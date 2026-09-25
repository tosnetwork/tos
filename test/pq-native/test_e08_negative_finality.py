"""Fail-closed control-flow checks for attestation negative evidence."""

import asyncio
import base64
import hashlib
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


SCRIPT = Path(os.environ.get(
    "E08_SOURCE_PATH",
    Path(__file__).resolve().parents[2] / "scripts/proof-attestation-e2e.py",
))
SPEC = importlib.util.spec_from_file_location("e08_attestation", SCRIPT)
e08 = importlib.util.module_from_spec(SPEC)
stubs = {name: types.ModuleType(name) for name in (
    "tostester", "tostester.install", "tostester.network",
    "tostester.pq_initial_validator", "pytosiq_core",
)}
stubs["tostester.install"].Install = object
stubs["tostester.network"].Network = object
stubs["tostester.network"].StartOptions = object
stubs["tostester.pq_initial_validator"].make_deterministic_pq_initial_validator = object
for name in ("Address", "Cell", "InternalMsgInfo", "MessageAny", "WalletMessage"):
    setattr(stubs["pytosiq_core"], name, object)
with patch.dict(sys.modules, stubs):
    SPEC.loader.exec_module(e08)


STATE = {"address": "0:abc", "public_key": "11", "revoked": False,
         "has_attestation": True, "attested_hash": "22"}


def head(seqno: int) -> dict:
    return {"id": {"seqno": seqno}, "gen_utime": seqno + 100}


def wallet_tx() -> dict:
    return {"transaction_id": {"lt": "11"}, "aborted": False,
            "compute": {"success": True}, "action": {"success": True},
            "out_msgs": [{"destination": "0:abc", "hash": "message-hash"}]}


def contract_tx(exit_code: int = 2101) -> dict:
    return {"transaction_id": {"lt": "21"}, "aborted": True,
            "compute": {"success": False, "exit_code": exit_code},
            "in_msg": {"source": "0:payer", "hash": "message-hash"}}


class NegativeFinalityTests(unittest.TestCase):
    def test_manifest_binds_source_binaries_and_refuses_dirty_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            validator = root / "validator-engine/validator-engine"
            dht = root / "dht-server/dht-server"
            validator.parent.mkdir()
            dht.parent.mkdir()
            validator.write_bytes(b"validator")
            dht.write_bytes(b"dht")
            tosctl = root / "tosctl"
            tosctl.write_bytes(b"tosctl")
            manifest_path = root / "manifest.json"
            with patch.object(e08, "BUILD_DIR", root), patch.object(
                e08, "TOSCTL", str(tosctl)
            ), patch.object(e08, "MANIFEST", manifest_path), patch.object(
                e08.subprocess, "check_output", return_value="fixed-sha\n"
            ), patch.object(e08.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)):
                e08.write_manifest()
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["source_commit"], "fixed-sha")
            self.assertFalse(manifest["source_tracked_dirty"])
            self.assertEqual(manifest["binaries"]["tosctl"]["sha256"],
                             hashlib.sha256(b"tosctl").hexdigest())
            with patch.object(e08, "BUILD_DIR", root), patch.object(
                e08, "TOSCTL", str(tosctl)
            ), patch.object(e08, "MANIFEST", manifest_path), patch.object(
                e08.subprocess, "check_output", return_value="fixed-sha\n"
            ), patch.object(e08.subprocess, "run", return_value=types.SimpleNamespace(returncode=1)):
                with self.assertRaisesRegex(RuntimeError, "clean tracked source tree"):
                    e08.write_manifest()
            self.assertTrue(json.loads(manifest_path.read_text())["source_tracked_dirty"])

    def test_bounced_refund_does_not_count_as_second_wallet_send(self):
        bounce = {"transaction_id": {"lt": "15"}, "out_msgs": [],
                  "in_msg": {"source": "0:abc", "bounced": True}}
        with patch.object(e08, "same_addr", side_effect=lambda left, right: left == right):
            self.assertEqual(e08.unique_attestation_send([bounce, wallet_tx()], "0:abc")["out_msgs"][0]["hash"],
                             wallet_tx()["out_msgs"][0]["hash"])

    def test_duplicate_send_and_unrelated_wallet_transaction_are_refused(self):
        duplicate = dict(wallet_tx(), transaction_id={"lt": "15"})
        unrelated = {"transaction_id": {"lt": "15"}, "out_msgs": [],
                     "in_msg": {"source": "0:other", "bounced": True}}
        with patch.object(e08, "same_addr", side_effect=lambda left, right: left == right):
            with self.assertRaisesRegex(RuntimeError, "multiple wallet sends"):
                e08.unique_attestation_send([duplicate, wallet_tx()], "0:abc")
            with self.assertRaisesRegex(RuntimeError, "unrelated wallet transaction"):
                e08.unique_attestation_send([unrelated, wallet_tx()], "0:abc")

    def test_bounce_must_match_this_attestation_transaction(self):
        send = wallet_tx()
        bounce = {"out_msgs": [], "in_msg": {
            "source": "0:abc", "destination": "0:payer",
            "bounced": True, "hash": "exact-bounce",
        }}
        contract = contract_tx()
        contract["out_msgs"] = [{"source": "0:abc", "destination": "0:payer",
                                 "bounced": True, "hash": "exact-bounce"}]
        with patch.object(e08, "same_addr", side_effect=lambda left, right: left == right):
            e08.validate_attestation_bounces([bounce, send], send, contract,
                                             "0:payer", "0:abc")
            wrong = dict(bounce, in_msg=dict(bounce["in_msg"], hash="wrong-bounce"))
            with self.assertRaisesRegex(RuntimeError, "not this attestation's bounce"):
                e08.validate_attestation_bounces([wrong, send], send, contract,
                                                 "0:payer", "0:abc")
            with self.assertRaisesRegex(RuntimeError, "not this attestation's bounce"):
                e08.validate_attestation_bounces([bounce, dict(bounce), send], send, contract,
                                                 "0:payer", "0:abc")
            send["out_msgs"].append({"destination": "0:other", "hash": "other"})
            with self.assertRaisesRegex(RuntimeError, "extra outbound"):
                e08.validate_attestation_bounces([bounce, send], send, contract,
                                                 "0:payer", "0:abc")

    def test_full_transaction_page_without_baseline_is_refused(self):
        rows = [{"transaction_id": {"lt": str(20 - index)}} for index in range(10)]
        with patch.object(e08, "rpc_call", return_value={"result": rows}):
            with self.assertRaisesRegex(RuntimeError, "did not cover baseline"):
                e08.transactions_after("0:payer", 10)

    def run_case(self, *, transaction=None, send_error=None, states=None, heads=None):
        send = AsyncMock(side_effect=send_error, return_value="submitted")
        snapshots = states or [STATE, STATE, STATE]
        with patch.object(e08, "attestation_show", new=AsyncMock(side_effect=snapshots)), patch.object(
            e08, "finalized_mc_header", side_effect=heads or [head(10), head(11), head(12)]
        ), patch.object(e08, "last_lt", side_effect=[10, 20]), patch.object(
            e08, "transactions_after", side_effect=[[wallet_tx()], [transaction or contract_tx()]]
        ), patch.object(e08, "same_addr", return_value=True), patch.object(
            e08, "send_op", send
        ), patch.object(e08, "record_jsonl") as record, patch.object(e08, "check") as check:
            asyncio.run(e08.rejected_operation(
                "wrong-key", "0:abc", "0:payer", 2101,
                "attest", "case-1", "outsider", "--signer-vault-key", "wrong-key"))
            return send, record, check

    def test_exact_aborted_vm_exit_and_two_final_heads_pass(self):
        send, record, check = self.run_case()
        send.assert_awaited_once()
        record.assert_called_once()
        check.assert_called_once_with("wrong-key", True)

    def test_generic_submission_error_is_not_rejection(self):
        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            self.run_case(send_error=RuntimeError("HTTP 503"))

    def test_wrong_vm_exit_is_not_expected_rejection(self):
        with self.assertRaisesRegex(RuntimeError, "expected VM exit 2101"):
            self.run_case(transaction=contract_tx(42))

    def test_state_change_after_execution_is_not_rejection(self):
        changed = dict(STATE, attested_hash="33")
        with self.assertRaisesRegex(RuntimeError, "state changed"):
            self.run_case(states=[STATE, changed])

    def test_raw_rpc_success_and_http_error_are_retained(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def read(self):
                return b'{"result":[]}'

        error_body = b'{"error":"unavailable"}\n'
        error = urllib.error.HTTPError("http://127.0.0.1/", 503, "unavailable", {},
                                      io.BytesIO(error_body))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rpc.jsonl"
            with patch.object(e08, "RPC_TRANSCRIPT", path), patch.object(
                e08.urllib.request, "urlopen", side_effect=[Response(), error]
            ):
                self.assertEqual(e08.rpc_call("getTransactions", address="0:abc"),
                                 {"result": []})
                with self.assertRaises(urllib.error.HTTPError):
                    e08.rpc_call("getTransactions", address="0:abc")
            rows = [json.loads(line) for line in path.read_text().splitlines()]
        error.close()
        self.assertEqual([row["status"] for row in rows], [200, 503])
        self.assertEqual([base64.b64decode(row["response_base64"]) for row in rows],
                         [b'{"result":[]}', error_body])


if __name__ == "__main__":
    unittest.main()
