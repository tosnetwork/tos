"""Offline controls for wc0 token-index message and RPC evidence."""

import asyncio
import ast
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
import urllib.error
from unittest.mock import AsyncMock, patch


SOURCE = Path(os.environ.get(
    "E14_SOURCE_PATH",
    Path(__file__).resolve().parents[2] / "scripts/wc0-token-index-e2e.py",
))
spec = importlib.util.spec_from_file_location("e14_wc0", SOURCE)
e14 = importlib.util.module_from_spec(spec)
stubs = {name: types.ModuleType(name) for name in (
    "tostester", "tostester.install", "tostester.network",
    "tostester.pq_initial_validator", "pytosiq_core", "contract",
)}
stubs["tostester.install"].Install = object
stubs["tostester.network"].Network = object
stubs["tostester.network"].StartOptions = object
stubs["tostester.pq_initial_validator"].make_deterministic_pq_initial_validator = object
stubs["contract"].tos = object
for name in ("Address", "Cell", "InternalMsgInfo", "MessageAny", "StateInit", "WalletMessage",
             "begin_cell"):
    setattr(stubs["pytosiq_core"], name, object)
with patch.dict(sys.modules, stubs):
    spec.loader.exec_module(e14)


def sender_tx(message_hash="edge"):
    return {"transaction_id": {"lt": "11"}, "aborted": False,
            "compute": {"success": True}, "action": {"success": True},
            "out_msgs": [{"destination": "target", "hash": message_hash}]}


def target_tx(message_hash="edge", aborted=False):
    return {"transaction_id": {"lt": "21"}, "aborted": aborted,
            "compute": {"success": not aborted}, "action": {"success": not aborted},
            "in_msg": {"source": "sender", "hash": message_hash}}


class Wc0EvidenceTests(unittest.TestCase):
    def edge(self, *, sent=None, received=None, success=False):
        with patch.object(e14, "transactions_after", side_effect=[
            [sent or sender_tx()], [received or target_tx()]
        ]), patch.object(e14, "same_addr", side_effect=lambda a, b: a == b), patch.object(
            e14, "record_jsonl"
        ) as record:
            tx = asyncio.run(e14.observe_edge(
                "forged", "sender", "target", 10, 20, success))
            return tx, record

    def test_exact_forged_edge_is_nonvacuous(self):
        tx, record = self.edge()
        self.assertEqual(tx["in_msg"]["hash"], "edge")
        record.assert_called_once()

    def test_mint_requires_successful_target(self):
        with self.assertRaisesRegex(RuntimeError, "did not succeed"):
            self.edge(received=target_tx(aborted=True), success=True)

    def test_wrong_message_hash_is_not_target_delivery(self):
        with self.assertRaisesRegex(RuntimeError, "did not match"):
            self.edge(received=target_tx(message_hash="unrelated"))

    def test_sender_failure_is_not_target_delivery(self):
        with self.assertRaisesRegex(RuntimeError, "did not match"):
            self.edge(sent=dict(sender_tx(), aborted=True))

    def test_missing_transaction_fails_after_bounded_wait(self):
        clock = types.SimpleNamespace(monotonic=iter([0, 46]).__next__)
        with patch.object(e14, "transactions_after", side_effect=[[], []]), patch.object(
            e14, "time", clock
        ):
            with self.assertRaisesRegex(RuntimeError, "not observed"):
                asyncio.run(e14.observe_edge("forged", "sender", "target", 10, 20, False))

    def test_final_heads_must_advance(self):
        before = {"id": {"seqno": 10}}
        with patch.object(e14, "finalized_mc_header", side_effect=[
            {"id": {"seqno": 11}}, {"id": {"seqno": 12}}
        ]):
            self.assertEqual(len(asyncio.run(e14.later_final_heads(before))), 2)
        clock = types.SimpleNamespace(monotonic=iter([0, 1, 46]).__next__)
        with patch.object(e14, "finalized_mc_header", return_value={"id": {"seqno": 10}}), patch.object(
            e14, "time", clock
        ), patch.object(e14.asyncio, "sleep", new=AsyncMock()):
            with self.assertRaisesRegex(RuntimeError, "did not advance"):
                asyncio.run(e14.later_final_heads(before))

    def test_json_rpc_error_is_rejected(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def read(self):
                return b'{"error":{"code":-32603}}'

        with patch.object(e14.urllib.request, "urlopen", return_value=Response()), patch.object(
            e14, "record_jsonl"
        ):
            with self.assertRaisesRegex(RuntimeError, "RPC failed"):
                e14.rpc_call("getAccountJettons", address="victim")

    def test_getter_method_is_a_parameter_not_the_rpc_name(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def read(self):
                return b'{"result":{"exit_code":0,"stack":[]}}'

        with patch.object(e14.urllib.request, "urlopen", return_value=Response()) as send, patch.object(
            e14, "record_jsonl"
        ):
            self.assertEqual(e14.getter_stack("wallet", "get_wallet_data", []), [])
        request = json.loads(send.call_args.args[0].data)
        self.assertEqual(request["method"], "runGetMethodStd")
        self.assertEqual(request["params"]["method"], "get_wallet_data")

    def test_raw_http_error_is_retained_and_rejected(self):
        raw = b'{"error":{"code":-32603}}'
        error = urllib.error.HTTPError("http://127.0.0.1/", 503, "unavailable", {},
                                      io.BytesIO(raw))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rpc.jsonl"
            with patch.object(e14, "RPC_TRANSCRIPT", path), patch.object(
                e14.urllib.request, "urlopen", side_effect=error
            ):
                with self.assertRaises(urllib.error.HTTPError):
                    e14.rpc_call("getAccountJettons", address="victim")
            row = json.loads(path.read_text().splitlines()[0])
        error.close()
        self.assertEqual(row["status"], 503)
        self.assertEqual(base64.b64decode(row["response_base64"]), raw)

    def test_provenance_refuses_dirty_source(self):
        with patch.object(e14.subprocess, "check_output", side_effect=["fixed-head\n", " M script.py\n"]):
            with self.assertRaisesRegex(RuntimeError, "uncommitted tracked changes"):
                e14.record_provenance()

    def test_provenance_records_exact_runtime_artifact_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(e14, "WORKDIR", Path(directory)), patch.object(
                e14.subprocess, "check_output", side_effect=["fixed-head\n", ""]
            ), patch.object(e14.subprocess, "run", return_value=types.SimpleNamespace(
                returncode=0, stdout=b"build ok", stderr=b"")) as built, patch.object(
                e14, "sha256_file", return_value="a" * 64
            ) as hashed:
                e14.record_provenance()
            manifest = json.loads((Path(directory) / "provenance.json").read_text())
            build_report = json.loads((Path(directory) / "boc-build.json").read_text())
        self.assertEqual(manifest["source_head"], "fixed-head")
        self.assertEqual(len(manifest["sha256"]), 9)
        self.assertEqual(hashed.call_count, 9)
        built.assert_called_once()
        self.assertEqual(manifest["build_command"][-1], "slice1_gas_parity_contracts")
        self.assertEqual(build_report["exit_code"], 0)

    def test_boc_build_failure_is_retained_and_stops_route(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(e14, "WORKDIR", Path(directory)), patch.object(
                e14.subprocess, "check_output", side_effect=["fixed-head\n", ""]
            ), patch.object(e14.subprocess, "run", return_value=types.SimpleNamespace(
                returncode=1, stdout=b"", stderr=b"compiler failed")):
                with self.assertRaisesRegex(RuntimeError, "BOC build failed"):
                    e14.record_provenance()
            report = json.loads((Path(directory) / "boc-build.json").read_text())
            self.assertEqual(report["exit_code"], 1)
            self.assertEqual(base64.b64decode(report["stderr_base64"]), b"compiler failed")

    def test_indexed_row_requires_live_observed_jetton_wallet(self):
        valid = {"jetton_master": "0:" + "1" * 64,
                 "jetton_wallet": "0:" + "2" * 64, "last_lt": "10"}
        with patch.object(e14, "get_jettons", return_value=[valid]), patch.object(
            e14, "rpc_call", return_value={"result": "active"}
        ), patch.object(e14, "verify_indexed_wallet") as verify:
            self.assertEqual(e14.indexed_entry("owner", valid["jetton_master"]), valid)
            verify.assert_called_once_with(valid["jetton_wallet"], "owner", valid["jetton_master"])
        with patch.object(e14, "get_jettons", return_value=[dict(valid, last_lt="0")]):
            with self.assertRaisesRegex(RuntimeError, "observed wallet transaction"):
                e14.indexed_entry("owner", valid["jetton_master"])
        with patch.object(e14, "get_jettons", return_value=[valid]), patch.object(
            e14, "rpc_call", return_value={"result": "uninit"}
        ):
            with self.assertRaisesRegex(RuntimeError, "not active"):
                e14.indexed_entry("owner", valid["jetton_master"])

    def test_negative_index_check_has_post_forgery_canary_gate(self):
        tree = ast.parse(SOURCE.read_text())
        main = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
                    and node.name == "main")
        text = ast.get_source_segment(SOURCE.read_text(), main)
        self.assertLess(text.index('"forged notification"'),
                        text.index('observe_edge(\n                "post-forgery canary mint"'))
        self.assertLess(text.index('"post-forgery canary mint"'),
                        text.index('victim_index_after_canary('))
        self.assertLess(text.index('victim_index_after_canary('),
                        text.index('require_forged_block_indexed(victim_raw, forged_target_tx)'))
        self.assertLess(text.index('require_forged_block_indexed(victim_raw, forged_target_tx)'),
                        text.index('if victim_js:'))
        with patch.object(e14, "poll", new=AsyncMock(return_value=None)), patch.object(
            e14, "get_jettons"
        ) as victim_query:
            with self.assertRaisesRegex(RuntimeError, "canary mint was not indexed"):
                asyncio.run(e14.victim_index_after_canary("victim", "canary", "master"))
            victim_query.assert_not_called()
        with patch.object(e14, "poll", new=AsyncMock(return_value={"jetton_wallet": "wallet"})), patch.object(
            e14, "get_jettons", return_value=[]
        ) as victim_query:
            canary, victim = asyncio.run(
                e14.victim_index_after_canary("victim", "canary", "master"))
            self.assertEqual(canary["jetton_wallet"], "wallet")
            self.assertEqual(victim, [])
            victim_query.assert_called_once_with("victim")

    def test_canary_must_follow_forgery_in_same_shard(self):
        block = lambda seqno, shard="-9223372036854775808": {
            "block_id": {"workchain": 0, "shard": shard, "seqno": seqno,
                         "root_hash": "root", "file_hash": "file"}}
        e14.require_later_same_shard(block(10), block(11))
        for later in (block(10), block(11, "other"), {"block_id": None}):
            with self.subTest(later=later), self.assertRaisesRegex(RuntimeError, "later block"):
                e14.require_later_same_shard(block(10), later)

    def test_exact_forged_block_index_receipt(self):
        tx_hash = bytes(range(32))
        tx = {"transaction_id": {"lt": "49000003", "hash": base64.b64encode(tx_hash).decode()},
              "block_id": {"workchain": 0, "shard": "-9223372036854775808",
                           "seqno": 48, "root_hash": "root", "file_hash": "file"}}
        event_id = f"49000003:{tx_hash.hex()}"
        event = {"@type": "wallet.accountEvent", "event_id": event_id.upper(),
                 "lt": "49000003", "hash": tx_hash.hex(),
                 "raw_transaction": base64.b64encode(b"tx-boc").decode()}
        fake_cell = types.SimpleNamespace(hash=tx_hash)
        fake_cell_class = types.SimpleNamespace(one_from_boc=lambda raw: fake_cell)
        with patch.object(e14, "rpc_call", return_value={"result": event}) as rpc, patch.object(
            e14, "Cell", fake_cell_class
        ), patch.object(e14, "record_jsonl") as record:
            self.assertEqual(e14.require_forged_block_indexed("victim", tx), event)
            rpc.assert_called_once_with("getAccountEvent", address="victim", event_id=event_id)
            self.assertEqual(record.call_args.args[1]["block_id"]["seqno"], 48)
        # Skipping only the forged block leaves later canary rows intact, but
        # the exact event lookup must fail rather than infer completion from them.
        with patch.object(e14, "rpc_call", side_effect=RuntimeError("Account event not found")):
            with self.assertRaisesRegex(RuntimeError, "Account event not found"):
                e14.require_forged_block_indexed("victim", tx)
        with patch.object(e14, "rpc_call", return_value={"result": dict(event, hash="00" * 32)}):
            with self.assertRaisesRegex(RuntimeError, "receipt differs"):
                e14.require_forged_block_indexed("victim", tx)

    def test_indexed_wallet_getter_binds_owner_master_and_roundtrip(self):
        data = [["cell", {}], ["slice", {"id": "master"}],
                ["slice", {"id": "owner"}], ["num", "1000"]]
        resolved = [["slice", {"id": "wallet"}]]

        class Builder:
            def store_address(self, _):
                return self

            def end_cell(self):
                return self

            def to_boc(self):
                return b"owner-address"

        with patch.object(e14, "getter_stack", side_effect=[data, resolved]) as getter, patch.object(
            e14, "stack_address", side_effect=lambda entry: entry[1]["id"]
        ), patch.object(e14, "same_addr", side_effect=lambda a, b: a == b), patch.object(
            e14, "begin_cell", return_value=Builder()
        ), patch.object(e14, "Address", side_effect=lambda value: value):
            e14.verify_indexed_wallet("wallet", "owner", "master")
            self.assertEqual(getter.call_args_list[0].args[:2], ("wallet", "get_wallet_data"))
            self.assertEqual(getter.call_args_list[1].args[:2], ("master", "get_wallet_address"))

        bad_owner = [["cell", {}], ["slice", {"id": "master"}],
                     ["slice", {"id": "unrelated"}], ["num", "1000"]]
        with patch.object(e14, "getter_stack", side_effect=[bad_owner, resolved]), patch.object(
            e14, "stack_address", side_effect=lambda entry: entry[1]["id"]
        ), patch.object(e14, "same_addr", side_effect=lambda a, b: a == b), patch.object(
            e14, "begin_cell", return_value=Builder()
        ), patch.object(e14, "Address", side_effect=lambda value: value):
            with self.assertRaisesRegex(RuntimeError, "owner/master differs"):
                e14.verify_indexed_wallet("wallet", "owner", "master")

        with patch.object(e14, "getter_stack", side_effect=[data, [["slice", {"id": "other"}]]]), patch.object(
            e14, "stack_address", side_effect=lambda entry: entry[1]["id"]
        ), patch.object(e14, "same_addr", side_effect=lambda a, b: a == b), patch.object(
            e14, "begin_cell", return_value=Builder()
        ), patch.object(e14, "Address", side_effect=lambda value: value):
            with self.assertRaisesRegex(RuntimeError, "does not resolve back"):
                e14.verify_indexed_wallet("wallet", "owner", "master")

    def test_getter_address_stack_encodings_and_vm_failure(self):
        class FakeCell:
            @staticmethod
            def one_from_boc(raw):
                self = FakeCell()
                self.raw = raw
                return self

            def begin_parse(self):
                return self

            def load_address(self):
                return self

            def to_str(self, **_):
                return self.raw.decode()

        encoded = base64.b64encode(b"0:wallet").decode()
        with patch.object(e14, "Cell", FakeCell):
            self.assertEqual(e14.stack_address(["slice", {"bytes": encoded}]), "0:wallet")
            self.assertEqual(e14.stack_address({"@type": "tvm.stackEntrySlice",
                                                "slice": {"bytes": encoded}}), "0:wallet")
        with patch.object(e14, "rpc_call", return_value={"result": {
            "exit_code": 9, "stack": []}}):
            with self.assertRaisesRegex(RuntimeError, "did not succeed"):
                e14.getter_stack("wallet", "get_wallet_data", [])

    def test_attacker_self_claim_is_a_failure(self):
        failures = []
        with patch.object(e14, "get_jettons", return_value=[{"jetton_master": "forged"}]), patch.object(
            e14, "record_jsonl"
        ) as record:
            e14.check_attacker_self_index("attacker", failures)
            self.assertEqual(failures, ["attacker self-claim was indexed"])
            self.assertEqual(record.call_args.args[1]["jettons"], [{"jetton_master": "forged"}])
        failures.clear()
        with patch.object(e14, "get_jettons", return_value=[]), patch.object(e14, "record_jsonl"):
            e14.check_attacker_self_index("attacker", failures)
            self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
