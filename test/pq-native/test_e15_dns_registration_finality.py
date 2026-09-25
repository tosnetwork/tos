"""Offline controls for DNS registration delivery and launch-gate evidence."""

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, patch


SOURCE = Path(os.environ.get(
    "E15_SOURCE_PATH",
    Path(__file__).resolve().parents[2] / "scripts/dns-e2e.py",
))
spec = importlib.util.spec_from_file_location("e15_dns", SOURCE)
e15 = importlib.util.module_from_spec(spec)
stubs = {name: types.ModuleType(name) for name in (
    "pytosiq_core", "pytosiq_core.boc", "pytosiq_core.tlb",
    "pytosiq_core.tlb.account", "tosapi", "tostester", "tostester.install",
    "tostester.network", "tostester.pq_initial_validator",
)}
for name in ("Address", "Cell", "CurrencyCollection", "InternalMsgInfo", "MessageAny",
             "WalletMessage"):
    setattr(stubs["pytosiq_core"], name, object)
stubs["pytosiq_core.boc"].begin_cell = object
stubs["pytosiq_core.tlb.account"].StateInit = object
stubs["tosapi"].tos_api = object
stubs["tostester.install"].Install = object
stubs["tostester.network"].Network = object
stubs["tostester.network"].StartOptions = object
stubs["tostester.pq_initial_validator"].make_deterministic_pq_initial_validator = object
with patch.dict(sys.modules, stubs):
    spec.loader.exec_module(e15)


def wallet_tx(message_hash="edge"):
    return {"transaction_id": {"lt": "11"}, "aborted": False,
            "compute": {"success": True}, "action": {"success": True},
            "out_msgs": [{"destination": "collection", "hash": message_hash}]}


def collection_tx(code=199, timestamp=100, message_hash="edge"):
    rejected = code != 0
    return {"transaction_id": {"lt": "21"}, "utime": timestamp, "aborted": rejected,
            "compute": {"success": not rejected, "exit_code": code},
            "action": {"success": not rejected},
            "in_msg": {"source": "faucet", "hash": message_hash}}


class DnsRegistrationTests(unittest.TestCase):
    def run_case(self, *, wallet=None, collection=None):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(e15, "transactions_after", side_effect=[
                [wallet or wallet_tx()], [collection or collection_tx()]
            ]), patch.object(e15, "same_addr", side_effect=lambda a, b: a == b), patch.object(
                e15, "finalized_mc_header", side_effect=[
                    {"id": {"seqno": 11}}, {"id": {"seqno": 12}}
                ]
            ), patch.object(e15, "REGISTRATION_EVIDENCE", Path(directory) / "receipt.json"):
                result = asyncio.run(e15.registration_receipt(
                    "faucet", "collection", 10, 20, {"id": {"seqno": 10}}, 200))
                receipt = json.loads((Path(directory) / "receipt.json").read_text())
        return result, receipt

    def test_prelaunch_exact_vm199_and_two_heads(self):
        result, receipt = self.run_case()
        self.assertTrue(result)
        self.assertEqual(len(receipt["after_heads"]), 2)

    def test_wrong_vm_code_is_not_rejection(self):
        with self.assertRaisesRegex(RuntimeError, "expected Collection VM 199"):
            self.run_case(collection=collection_tx(code=200))

    def test_wrong_message_hash_is_not_delivery(self):
        with self.assertRaisesRegex(RuntimeError, "did not match"):
            self.run_case(collection=collection_tx(message_hash="unrelated"))

    def test_wallet_failure_is_not_delivery(self):
        with self.assertRaisesRegex(RuntimeError, "did not match"):
            self.run_case(wallet=dict(wallet_tx(), aborted=True))

    def test_postlaunch_success_uses_transaction_time(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(e15, "transactions_after", side_effect=[
                [wallet_tx()], [collection_tx(code=0, timestamp=300)]
            ]), patch.object(e15, "same_addr", side_effect=lambda a, b: a == b), patch.object(
                e15, "finalized_mc_header", side_effect=[
                    {"id": {"seqno": 11}}, {"id": {"seqno": 12}}
                ]
            ), patch.object(e15, "REGISTRATION_EVIDENCE", Path(directory) / "receipt.json"):
                result = asyncio.run(e15.registration_receipt(
                    "faucet", "collection", 10, 20, {"id": {"seqno": 10}}, 200))
        self.assertFalse(result)

    def test_missing_transaction_cannot_pass(self):
        clock = types.SimpleNamespace(monotonic=iter([0, 46]).__next__)
        with patch.object(e15, "transactions_after", side_effect=[[], []]), patch.object(
            e15, "time", clock
        ), patch.object(e15.asyncio, "sleep", new=AsyncMock()):
            with self.assertRaisesRegex(RuntimeError, "not observed"):
                asyncio.run(e15.registration_receipt(
                    "faucet", "collection", 10, 20, {"id": {"seqno": 10}}, 200))


if __name__ == "__main__":
    unittest.main()
