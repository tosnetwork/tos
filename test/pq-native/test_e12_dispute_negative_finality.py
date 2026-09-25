"""Fail-closed offline controls for Dispute negative transaction evidence."""

import asyncio
import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch


SCRIPT = Path(os.environ.get(
    "E12_SOURCE_PATH",
    Path(__file__).resolve().parents[2] / "scripts/dispute-e2e.py",
))
SPEC = importlib.util.spec_from_file_location("e12_dispute", SCRIPT)
e12 = importlib.util.module_from_spec(SPEC)
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
    SPEC.loader.exec_module(e12)


STATE = {"status": "open", "ruling": "none", "attestor_pubkey": "cc" * 32}


def head(seqno):
    return {"id": {"seqno": seqno}, "gen_utime": seqno + 100}


def wallet_tx():
    return {"transaction_id": {"lt": "11"}, "aborted": False,
            "compute": {"success": True}, "action": {"success": True},
            "out_msgs": [{"destination": "0:abc", "hash": "message-hash"}]}


def contract_tx(exit_code=2007):
    return {"transaction_id": {"lt": "21"}, "aborted": True,
            "compute": {"success": False, "exit_code": exit_code},
            "in_msg": {"hash": "message-hash", "source": "0:payer"},
            "out_msgs": [{"hash": "bounce-hash", "source": "0:abc",
                          "destination": "0:payer", "bounced": True}]}


def bounce_tx(message_hash="bounce-hash"):
    return {"transaction_id": {"lt": "12"}, "in_msg": {
        "hash": message_hash, "source": "0:abc", "destination": "0:payer",
        "bounced": True}, "out_msgs": []}


class DisputeNegativeTests(unittest.TestCase):
    def test_full_page_without_baseline_is_inconclusive(self):
        rows = [{"transaction_id": {"lt": str(11 + i)}} for i in range(10)]
        with patch.object(e12, "rpc_call", return_value={"result": rows}):
            with self.assertRaisesRegex(RuntimeError, "did not cover"):
                e12.transactions_after("0:abc", 10)

    def test_full_page_crossing_baseline_is_covered(self):
        rows = [{"transaction_id": {"lt": str(20 - i)}} for i in range(10)]
        with patch.object(e12, "rpc_call", return_value={"result": rows}):
            self.assertEqual(len(e12.transactions_after("0:abc", 15)), 5)

    def run_case(self, *, expected=2007, transaction=None, send_error=None,
                 wallet=None, bounce=None, extra=None, states=None, rows=None):
        send = AsyncMock(side_effect=send_error, return_value="submitted")
        with patch.object(e12, "dispute_show", new=AsyncMock(
            side_effect=states or [STATE, STATE, STATE]
        )), patch.object(e12, "finalized_mc_header",
                         side_effect=[head(10), head(11), head(12)]), patch.object(
            e12, "last_lt", side_effect=[10, 20]
        ), patch.object(e12, "transactions_after", side_effect=rows or [
            [wallet or wallet_tx(), bounce or bounce_tx(), *(extra or [])],
            [transaction or contract_tx()]
        ]), patch.object(e12, "same_addr", side_effect=lambda a, b: a == b), patch.object(
            e12, "send_op", send
        ), patch.object(e12, "record_jsonl") as record, patch.object(e12, "check") as check:
            asyncio.run(e12.rejected_operation(
                "frozen", "0:abc", "0:payer", expected,
                "rotate-attestor-key", "case-5", "reviewer",
                "--new-attestor-pubkey", "dd" * 32))
            return record, check

    def test_exact_vm_exit_with_two_final_heads_passes(self):
        record, check = self.run_case()
        record.assert_called_once()
        check.assert_called_once_with("frozen", True)

    def test_cell_underflow_has_distinct_exact_code(self):
        self.run_case(expected=9, transaction=contract_tx(9))
        with self.assertRaisesRegex(RuntimeError, "expected VM exit 9"):
            self.run_case(expected=9, transaction=contract_tx(2006))

    def test_cli_error_is_not_contract_rejection(self):
        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            self.run_case(send_error=RuntimeError("HTTP 503"))

    def test_wrong_vm_code_is_not_expected_rejection(self):
        with self.assertRaisesRegex(RuntimeError, "expected VM exit 2007"):
            self.run_case(transaction=contract_tx(2001))

    def test_wallet_failure_is_not_contract_rejection(self):
        bad = dict(wallet_tx(), aborted=True)
        with self.assertRaisesRegex(RuntimeError, "wallet transaction did not send"):
            self.run_case(wallet=bad)

    def test_wrong_contract_message_is_not_rejection(self):
        bad = dict(contract_tx(), in_msg={"hash": "unrelated", "source": "0:payer"})
        with self.assertRaisesRegex(RuntimeError, "inbound hash differs"):
            self.run_case(transaction=bad)

    def test_changed_state_is_not_rejection(self):
        with self.assertRaisesRegex(RuntimeError, "state changed"):
            self.run_case(states=[STATE, dict(STATE, status="resolved")])

    def test_exact_bounce_is_not_second_wallet_send(self):
        record, check = self.run_case()
        self.assertEqual(record.call_args.args[1]["bounce_transaction"]["in_msg"]["hash"],
                         "bounce-hash")
        check.assert_called_once_with("frozen", True)

    def test_wrong_bounce_hash_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "not the dispute's exact bounce"):
            self.run_case(bounce=bounce_tx("unrelated"))

    def test_duplicate_bounce_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "unrelated or duplicate"):
            self.run_case(extra=[bounce_tx()])

    def test_additional_wallet_outbound_is_refused(self):
        unrelated = {"transaction_id": {"lt": "13"}, "out_msgs": [
            {"destination": "0:other", "hash": "other-send"}]}
        with self.assertRaisesRegex(RuntimeError, "unrelated or duplicate"):
            self.run_case(extra=[unrelated])


if __name__ == "__main__":
    unittest.main()
