"""Offline controls for Service Actor positive wallet, contract and payment edges."""

import asyncio
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch


SOURCE = Path(os.environ.get(
    "E13_SOURCE_PATH",
    Path(__file__).resolve().parents[2] / "scripts/service-actor-e2e.py",
))
spec = importlib.util.spec_from_file_location("e13_positive", SOURCE)
e13 = importlib.util.module_from_spec(spec)
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
    spec.loader.exec_module(e13)


PAYER = "0:wallet"
SERVICE = "0:service"


def head(height):
    return {"id": {"seqno": height, "root_hash": f"root-{height}",
                   "file_hash": f"file-{height}"}}


def rows(*, service_hash="send-hash", service_ok=True, action_ok=True,
         payout_hash="refund-hash", payout_value=50_000_000,
         received_value=50_000_000, service_inbound=270_000_000):
    wallet = {"aborted": False, "compute": {"success": True},
              "action": {"success": True},
              "out_msgs": [{"destination": SERVICE, "hash": "send-hash",
                            "value": "270000000"}]}
    service = {"aborted": False, "compute": {"success": service_ok},
               "action": {"success": action_ok},
               "in_msg": {"source": PAYER, "hash": service_hash,
                          "value": str(service_inbound)},
               "out_msgs": [{"destination": PAYER, "hash": payout_hash,
                             "value": str(payout_value)}]}
    receiver = {"aborted": False,
                "in_msg": {"source": SERVICE, "hash": "refund-hash",
                           "value": str(received_value)}, "out_msgs": []}
    return wallet, service, receiver


class ServicePositiveEdgesTests(unittest.TestCase):
    def test_http_state_poll_requires_later_200_after_504(self):
        unavailable = {"ok": False, "error": {"code": 504, "kind": "timeout"}}
        pending = {"ok": True, "result": {"status": "pending"}}
        with (patch.object(e13, "http_get", side_effect=[(504, unavailable),
                                                       (200, pending)]) as get,
              patch.object(e13.asyncio, "sleep", new=AsyncMock())):
            ready, body = asyncio.run(e13.poll_http_predicate(
                "/services/0:service/requests/0",
                lambda result: result.get("result", {}).get("status") == "pending"))
        self.assertTrue(ready)
        self.assertEqual(body, pending)
        self.assertEqual(get.call_count, 2)

    def test_http_state_poll_persistent_504_fails_closed(self):
        unavailable = {"ok": False, "error": {"code": 504, "kind": "timeout"}}
        with (patch.object(e13, "http_get", return_value=(504, unavailable)),
              patch.object(e13.asyncio, "sleep", new=AsyncMock())):
            ready, body = asyncio.run(e13.poll_http_predicate(
                "/services/0:service/requests/0", lambda _: True, timeout=0.001))
        self.assertFalse(ready)
        self.assertEqual(body, unavailable)

    def test_http_state_poll_retries_transport_timeout_not_business_error(self):
        pending = {"ok": True, "result": {"status": "pending"}}
        with (patch.object(e13, "http_get", side_effect=[TimeoutError("slow"),
                                                       (200, pending)]) as get,
              patch.object(e13.asyncio, "sleep", new=AsyncMock())):
            ready, _ = asyncio.run(e13.poll_http_predicate(
                "/services/0:service/requests/0",
                lambda result: result.get("result", {}).get("status") == "pending"))
        self.assertTrue(ready)
        self.assertEqual(get.call_count, 2)

    def test_indexer_barrier_uses_indexed_cursor_not_live_head(self):
        behind = {"ok": True, "result": {
            "masterchain_head": 90, "masterchain_indexed": 44}}
        covered = {"ok": True, "result": {
            "masterchain_head": 91, "masterchain_indexed": 47}}
        with (patch.object(e13, "http_get", side_effect=[(200, behind), (200, covered)]) as get,
              patch.object(e13.asyncio, "sleep", new=AsyncMock()),
              patch.object(e13, "record_jsonl") as record):
            ready, result = asyncio.run(e13.wait_indexer_through("deploy", 46))
        self.assertTrue(ready)
        self.assertEqual(result["body"]["result"]["masterchain_indexed"], 47)
        self.assertEqual(get.call_count, 2)
        self.assertEqual(record.call_args.args[1]["target_mc_seqno"], 46)

    def test_indexer_barrier_refuses_bad_status_or_missing_cursor(self):
        for status, body in ((500, {"ok": True, "result": {"masterchain_indexed": 99}}),
                             (200, {"ok": True, "result": {"masterchain_head": 99}})):
            with self.subTest(status=status, body=body), patch.object(
                e13, "http_get", return_value=(status, body)
            ), patch.object(e13, "record_jsonl") as record:
                ready, _ = asyncio.run(e13.wait_indexer_through("deploy", 46, timeout=0.001))
                self.assertFalse(ready)
                self.assertTrue(record.call_args.args[1]["timed_out"])

    def test_indexer_barrier_retries_transport_timeout_within_same_deadline(self):
        covered = {"ok": True, "result": {"masterchain_indexed": 47}}
        with (patch.object(e13, "http_get", side_effect=[TimeoutError("slow indexer"),
                                                       (200, covered)]) as get,
              patch.object(e13.asyncio, "sleep", new=AsyncMock()),
              patch.object(e13, "record_jsonl") as record):
            ready, _ = asyncio.run(e13.wait_indexer_through("deploy", 46))
        self.assertTrue(ready)
        self.assertEqual(get.call_count, 2)
        self.assertEqual(record.call_args_list[0].args[1]["label"], "deploy")
        self.assertTrue(record.call_args_list[0].args[1]["poll_error"])
        self.assertEqual(record.call_args.args[1]["target_mc_seqno"], 46)

    def test_indexer_barrier_persistent_timeout_fails_closed(self):
        with (patch.object(e13, "http_get", side_effect=TimeoutError("still slow")),
              patch.object(e13.asyncio, "sleep", new=AsyncMock()),
              patch.object(e13, "record_jsonl") as record):
            ready, last = asyncio.run(e13.wait_indexer_through("deploy", 46, timeout=0.001))
        self.assertFalse(ready)
        self.assertEqual(last["transport_error"], "TimeoutError")
        self.assertTrue(record.call_args.args[1]["timed_out"])

    def test_http_timeout_is_retained_before_raising(self):
        with patch.object(e13.urllib.request, "urlopen", side_effect=TimeoutError("slow")), \
                patch.object(e13, "record_jsonl") as record:
            with self.assertRaisesRegex(TimeoutError, "slow"):
                e13.http_get("/explorer/status")
        self.assertEqual(record.call_args.args[1]["transport_error"], "TimeoutError")

    def run_edge(self, *, wallet=None, service=None, receiver=None,
                 expected=50_000_000, expected_inbound=None, heads=None):
        usual = rows()
        wallet = wallet or usual[0]
        service = service or usual[1]
        receiver = receiver or usual[2]

        def transactions(address, baseline):
            self.assertEqual(baseline, 10 if address == PAYER else 20)
            return [wallet, receiver] if address == PAYER else [service]

        with patch.object(e13, "transactions_after", side_effect=transactions), patch.object(
            e13, "same_addr", side_effect=lambda actual, want: actual == want
        ), patch.object(e13, "finalized_mc_header", side_effect=heads or [head(11), head(12)]), patch.object(
            e13, "record_jsonl"
        ) as record:
            asyncio.run(e13.observe_successful_edge(
                "call-refund", SERVICE, PAYER, 10, 20, head(10), "submitted",
                expected, expected_inbound,
            ))
            return record

    def test_exact_wallet_contract_refund_and_final_heads(self):
        record = self.run_edge()
        self.assertEqual(record.call_count, 1)
        evidence = record.call_args.args[1]
        self.assertEqual(evidence["recipient_tx"]["in_msg"]["hash"], "refund-hash")
        self.assertEqual([row["id"]["seqno"] for row in evidence["final_heads"]], [11, 12])

    def test_wrong_wallet_to_contract_hash_fails(self):
        service = rows(service_hash="unrelated")[1]
        with self.assertRaisesRegex(RuntimeError, "wallet outbound and Service Actor inbound"):
            self.run_edge(service=service)

    def test_observed_inbound_value_matches_wallet_and_command(self):
        self.run_edge(expected_inbound=270_000_000)
        with self.assertRaisesRegex(RuntimeError, "inbound value differs"):
            self.run_edge(service=rows(service_inbound=269_000_000)[1])
        with self.assertRaisesRegex(RuntimeError, "inbound value differs"):
            self.run_edge(expected_inbound=269_000_000)

    def test_failed_service_compute_or_action_fails(self):
        for service in (rows(service_ok=False)[1], rows(action_ok=False)[1]):
            with self.subTest(service=service), self.assertRaisesRegex(RuntimeError, "execution did not succeed"):
                self.run_edge(service=service)

    def test_refund_amount_and_recipient_inbound_are_exact(self):
        with self.assertRaisesRegex(RuntimeError, "payment amount or recipient"):
            self.run_edge(service=rows(payout_value=49_000_000)[1])
        with self.assertRaisesRegex(RuntimeError, "recipient inbound hash differs"):
            self.run_edge(service=rows(payout_hash="unrelated")[1])
        with self.assertRaisesRegex(RuntimeError, "recipient inbound amount or source"):
            self.run_edge(receiver=rows(received_value=49_000_000)[2])

    def test_missing_later_final_heads_fails(self):
        clock = [0]

        async def advance_clock(_):
            clock[0] = 61

        with patch.object(e13.time, "monotonic", side_effect=lambda: clock[0]), patch.object(
            e13.asyncio, "sleep", new=advance_clock
        ):
            with self.assertRaisesRegex(RuntimeError, "later finalized masterchain heads"):
                self.run_edge(heads=[head(10)])

    def test_withdraw_amount_is_derived_from_command_and_requires_edge(self):
        before = {"address": SERVICE, "price_per_call": "0.02", "storage_fee": "0.2"}
        with patch.object(e13, "service_show", new=AsyncMock(return_value=before)), patch.object(
            e13, "wallet_address", new=AsyncMock(return_value=PAYER)
        ), patch.object(e13, "finalized_mc_header", return_value=head(10)), patch.object(
            e13, "last_lt", side_effect=[10, 20, 10, 20]
        ), patch.object(e13, "send_op", new=AsyncMock(return_value="submitted")), patch.object(
            e13, "observe_successful_edge", new=AsyncMock()
        ) as observe:
            asyncio.run(e13.successful_operation(
                "withdraw-revenue", "svc-1", "owner", "--withdraw-amount", "0.15",
            ))
            self.assertEqual(observe.await_args.args[-2], 150_000_000)
            self.assertIsNone(observe.await_args.args[-1])
            asyncio.run(e13.successful_operation(
                "call", "svc-1", "owner", "--amount", "0.5",
            ))
            self.assertEqual(observe.await_args.args[-2], 280_000_000)
            self.assertEqual(observe.await_args.args[-1], 500_000_000)

    def test_all_positive_sends_and_deploy_use_exact_edge(self):
        tree = ast.parse(SOURCE.read_text())
        functions = {node.name: node for node in tree.body
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        calls = lambda fn, name: sum(
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == name for node in ast.walk(functions[fn])
        )
        self.assertEqual(calls("run_checks", "successful_operation"), 21)
        self.assertEqual(calls("run_checks", "send_op"), 0)
        self.assertEqual(calls("deploy_service", "observe_successful_edge"), 1)
        self.assertEqual(calls("rejected_operation", "send_op"), 1)
        self.assertEqual(calls("main", "write_provenance"), 1)

    def test_provenance_hashes_exact_sources_and_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            paths = [
                root / "scripts/check-service-actor-bytecode.py",
                root / "crypto/smartcont/service-actor-code.fc",
                root / "tosctl/src/node-control/contracts/src/service_actor.rs",
                build / "crypto/func", build / "crypto/fift",
                build / "validator-engine/validator-engine",
                build / "dht-server/dht-server", root / "tosctl-bin",
            ]
            for index, path in enumerate(paths):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(bytes([index + 1]))
            manifest = root / "provenance.json"
            bytecode = "Service Actor bytecode synchronized (repr_hash=" + str(2**255) + ")"
            run = [Mock(returncode=0), Mock(stdout=bytecode + "\n")] * 2
            with patch.object(e13, "REPO", root), patch.object(e13, "BUILD_DIR", build), patch.object(
                e13, "TOSCTL", str(paths[-1])
            ), patch.object(e13, "PROVENANCE", manifest), patch.object(
                e13.subprocess, "check_output", return_value="a" * 40
            ), patch.object(e13.subprocess, "run", side_effect=run):
                e13.write_provenance()
            report = json.loads(manifest.read_text())
            self.assertEqual(report["source_commit"], "a" * 40)
            self.assertEqual(report["service_bytecode_check"], bytecode)
            self.assertEqual(report["artifacts"]["tosctl"]["sha256"],
                             hashlib.sha256(paths[-1].read_bytes()).hexdigest())
            with patch.object(e13, "REPO", root), patch.object(
                e13.subprocess, "check_output", return_value="a" * 40
            ), patch.object(e13.subprocess, "run", side_effect=[
                Mock(returncode=0), Mock(stdout="stale bytecode")
            ]):
                with self.assertRaisesRegex(RuntimeError, "bytecode identity missing"):
                    e13.write_provenance()
            with patch.object(e13, "REPO", root), patch.object(
                e13.subprocess, "check_output", return_value="a" * 40
            ), patch.object(e13.subprocess, "run", side_effect=[
                Mock(returncode=0), Mock(stdout="Service Actor bytecode synchronized (repr_hash=0)")
            ]):
                with self.assertRaisesRegex(RuntimeError, "bytecode identity missing"):
                    e13.write_provenance()
            paths[-1].unlink()
            with patch.object(e13, "REPO", root), patch.object(e13, "BUILD_DIR", build), patch.object(
                e13, "TOSCTL", str(paths[-1])
            ), patch.object(e13, "PROVENANCE", manifest), patch.object(
                e13.subprocess, "check_output", return_value="a" * 40
            ), patch.object(e13.subprocess, "run", side_effect=run):
                with self.assertRaises(FileNotFoundError):
                    e13.write_provenance()


if __name__ == "__main__":
    unittest.main()
