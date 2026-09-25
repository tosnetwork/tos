"""Fail-closed controls for the retained Agent Account negative windows."""

import base64
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from pytosiq_core import Cell


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/agent-wallet-account-e2e.py"
SPEC = importlib.util.spec_from_file_location("e04_agent_wallet_account", SCRIPT)
e04 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(e04)


class NegativeWindowTests(unittest.IsolatedAsyncioTestCase):
    async def test_later_rpc_error_does_not_certify_absence(self):
        calls = 0

        def predicate():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("observer read failed")
            return True

        heads = iter(({"node": {"seqno": 1}},
                      *({"node": {"seqno": 2}} for _ in range(100))))
        with patch.object(e04, "finalized_views", side_effect=lambda: next(heads)):
            self.assertFalse(await e04.predicate_stays_true(
                predicate, duration=0.05, poll_interval=0.001))
        self.assertEqual(calls, 2)

    async def test_async_later_rpc_error_does_not_certify_absence(self):
        calls = 0

        async def predicate():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("account read failed")
            return True

        heads = iter(({"node": {"seqno": 1}},
                      *({"node": {"seqno": 2}} for _ in range(100))))
        with patch.object(e04, "finalized_views", side_effect=lambda: next(heads)):
            self.assertFalse(await e04.async_predicate_stays_true(
                predicate, duration=0.05, poll_interval=0.001))
        self.assertEqual(calls, 2)

    async def test_success_requires_repeated_samples_and_finalized_progress(self):
        views = iter(({"node": {"seqno": 1}},
                      *({"node": {"seqno": 1}} for _ in range(100)),
                      {"node": {"seqno": 2}}))
        with patch.object(e04, "finalized_views", side_effect=lambda: next(views)):
            self.assertFalse(await e04.predicate_stays_true(
                lambda: True, duration=0.004, poll_interval=0.001))


class ExactCancellationTests(unittest.TestCase):
    def test_winner_is_bound_to_exact_boc_and_baseline(self):
        boc = base64.b64encode(Cell.empty().to_boc()).decode()
        inbound_hash = base64.b64encode(Cell.empty().hash).decode()
        winner = {"transaction_id": {"lt": "2"},
                  "in_msg": {"hash": inbound_hash}, "aborted": False,
                  "compute": {"success": True}, "action": {"success": True}}
        baseline = {"transaction_id": {"lt": "1"}}

        def rpc(_method, **_params):
            return {"result": [winner, baseline]}

        with patch.object(e04, "rpc_call", side_effect=rpc):
            self.assertTrue(e04.exact_account_winner("account", boc, 1))
            winner["in_msg"]["hash"] = "wrong"
            self.assertFalse(e04.exact_account_winner("account", boc, 1))
            winner["in_msg"]["hash"] = inbound_hash
            winner["action"]["success"] = False
            self.assertFalse(e04.exact_account_winner("account", boc, 1))
        with patch.object(e04, "rpc_call", return_value={"result": [winner]}):
            with self.assertRaisesRegex(RuntimeError, "did not cover"):
                e04.exact_account_winner("account", boc, 1)

    def test_expiry_uses_header_for_the_exact_finalized_block(self):
        block = {"workchain": -1, "shard": "-9223372036854775808",
                 "seqno": 7, "root_hash": "root", "file_hash": "file"}
        header = {"id": dict(block), "gen_utime": 123}
        with patch.object(e04, "finalized_views", return_value={e04.RPC: block}), \
             patch.object(e04, "rpc_call", return_value={"result": header}):
            self.assertEqual(e04.finalized_mc_header()["gen_utime"], 123)
            header["id"]["root_hash"] = "other"
            with self.assertRaisesRegex(RuntimeError, "did not bind"):
                e04.finalized_mc_header()


if __name__ == "__main__":
    unittest.main()
