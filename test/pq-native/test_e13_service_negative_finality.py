"""Offline fail-closed controls for Service Actor negative route evidence."""

import asyncio
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
import urllib.error
from unittest.mock import AsyncMock, patch


SOURCE = Path(os.environ.get(
    "E13_SOURCE_PATH",
    Path(__file__).resolve().parents[2] / "scripts/service-actor-e2e.py",
))
spec = importlib.util.spec_from_file_location("e13_service", SOURCE)
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


STATE = {"calls_today": 0, "pending_count": 0, "next_request_id": 1}


def head(seqno):
    return {"id": {"seqno": seqno}, "gen_utime": seqno + 100}


def wallet_tx():
    return {"transaction_id": {"lt": "11"}, "aborted": False,
            "compute": {"success": True}, "action": {"success": True},
            "out_msgs": [{"destination": "0:service", "hash": "message-hash"}]}


def service_tx(code=1923, message_hash="message-hash"):
    return {"transaction_id": {"lt": "21"}, "aborted": True,
            "compute": {"success": False, "exit_code": code},
            "in_msg": {"hash": message_hash, "source": "0:payer"},
            "out_msgs": [{"hash": "bounce-hash", "source": "0:service",
                          "destination": "0:payer", "bounced": True}]}


def bounce_tx(message_hash="bounce-hash"):
    return {"transaction_id": {"lt": "12"}, "in_msg": {
        "hash": message_hash, "source": "0:service", "destination": "0:payer",
        "bounced": True}, "out_msgs": []}


class ServiceNegativeTests(unittest.TestCase):
    def run_case(self, *, expected=1923, transaction=None, send_error=None,
                 wallet=None, bounce=None, extra=None, states=None, operation="call"):
        with patch.object(e13, "service_show", new=AsyncMock(
            side_effect=states or [STATE, STATE, STATE]
        )), patch.object(e13, "finalized_mc_header",
                         side_effect=[head(10), head(11), head(12)]), patch.object(
            e13, "last_lt", side_effect=[10, 20]
        ), patch.object(e13, "transactions_after", side_effect=[
            [wallet or wallet_tx(), bounce or bounce_tx(), *(extra or [])],
            [transaction or service_tx()]
        ]), patch.object(e13, "same_addr", side_effect=lambda a, b: a == b), patch.object(
            e13, "send_op", new=AsyncMock(side_effect=send_error, return_value="submitted")
        ), patch.object(e13, "record_jsonl") as record, patch.object(e13, "check") as check:
            asyncio.run(e13.rejected_operation(
                "outsider call", "0:service", "0:payer", expected,
                "svc-1", "outsider", operation, "--request-hash", "aa" * 32))
            return record, check

    def test_exact_vm_exit_and_two_final_heads(self):
        record, check = self.run_case()
        record.assert_called_once()
        self.assertEqual(record.call_args.args[1]["bounce_tx"]["in_msg"]["hash"],
                         "bounce-hash")
        check.assert_called_once_with("outsider call", True)

    def test_wrong_bounce_hash_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "not the Service Actor's exact bounce"):
            self.run_case(bounce=bounce_tx("unrelated"))

    def test_duplicate_bounce_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "unrelated or duplicate"):
            self.run_case(extra=[bounce_tx()])

    def test_extra_wallet_outbound_is_refused(self):
        extra = {"transaction_id": {"lt": "13"}, "out_msgs": [
            {"destination": "0:other", "hash": "other-send"}]}
        with self.assertRaisesRegex(RuntimeError, "unrelated or duplicate"):
            self.run_case(extra=[extra])

    def test_full_page_without_baseline_is_inconclusive(self):
        rows = [{"transaction_id": {"lt": str(11 + i)}} for i in range(10)]
        with patch.object(e13, "rpc_call", return_value={"result": rows}):
            with self.assertRaisesRegex(RuntimeError, "did not cover"):
                e13.transactions_after("0:service", 10)

    def test_cli_http_error_does_not_count(self):
        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            self.run_case(send_error=RuntimeError("HTTP 503"))

    def test_exact_post_submit_call_timeout_can_reach_chain_vm_proof(self):
        timeout = RuntimeError(
            "tosctl agent service send failed:\n"
            "OK Service Actor call message submitted to 0:service\n"
            "Error: timed out waiting for the Service Actor call to land")
        record, check = self.run_case(send_error=timeout)
        self.assertTrue(record.call_args.args[1]["cli_post_submit_timeout"])
        self.assertIn("message submitted to", record.call_args.args[1]["receipt"])
        check.assert_called_once_with("outsider call", True)
        with self.assertRaisesRegex(RuntimeError, "expected VM exit 1923"):
            self.run_case(send_error=timeout, transaction=service_tx(1902))
        with self.assertRaisesRegex(RuntimeError, "timed out waiting"):
            self.run_case(send_error=timeout, operation="respond")

    def test_timeout_without_submit_marker_is_transport_failure(self):
        with self.assertRaisesRegex(RuntimeError, "timed out waiting"):
            self.run_case(send_error=RuntimeError(
                "Error: timed out waiting for the Service Actor call to land"))

    def test_wrong_vm_code_does_not_count(self):
        with self.assertRaisesRegex(RuntimeError, "expected VM exit 1923"):
            self.run_case(transaction=service_tx(1902))

    def test_unsigned_response_vm9_is_distinct(self):
        self.run_case(expected=9, transaction=service_tx(9))
        with self.assertRaisesRegex(RuntimeError, "expected VM exit 9"):
            self.run_case(expected=9, transaction=service_tx(1911))

    def test_wrong_inbound_hash_does_not_count(self):
        with self.assertRaisesRegex(RuntimeError, "inbound hash differs"):
            self.run_case(transaction=service_tx(message_hash="unrelated"))

    def test_wallet_failure_does_not_count(self):
        with self.assertRaisesRegex(RuntimeError, "wallet did not send"):
            self.run_case(wallet=dict(wallet_tx(), aborted=True))

    def test_state_change_does_not_count(self):
        with self.assertRaisesRegex(RuntimeError, "state changed"):
            self.run_case(states=[STATE, dict(STATE, calls_today=1)])

    def test_http_error_body_and_status_are_retained(self):
        error_body = b'{"result":{"status":"pending"}}'
        error = urllib.error.HTTPError("http://127.0.0.1/", 503, "unavailable", {},
                                      io.BytesIO(error_body))
        with patch.object(e13.urllib.request, "urlopen", side_effect=error), patch.object(
            e13, "record_jsonl"
        ) as record:
            status, body = e13.http_get("/services/0:service/requests/1")
        error.close()
        self.assertEqual(status, 503)
        self.assertEqual(body, json.loads(error_body))
        row = record.call_args.args[1]
        self.assertEqual(row["status"], 503)
        self.assertEqual(base64.b64decode(row["response_base64"]), error_body)


if __name__ == "__main__":
    unittest.main()
