"""Offline controls for DNS registration delivery and launch-gate evidence."""

import asyncio
import base64
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
    "pytosiq_core.tlb.account", "pytosiq_core.tlb.transaction",
    "tosapi", "tostester", "tostester.install",
    "tostester.network", "tostester.pq_initial_validator",
)}
for name in ("Address", "Cell", "CurrencyCollection", "InternalMsgInfo", "MessageAny",
             "WalletMessage"):
    setattr(stubs["pytosiq_core"], name, object)
stubs["pytosiq_core.boc"].begin_cell = object
stubs["pytosiq_core.tlb.account"].StateInit = object
stubs["pytosiq_core.tlb.transaction"].Transaction = object
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


class DnsGovernanceReceiptTests(unittest.TestCase):
    class FakeCell:
        hash = b"v" * 32

        @classmethod
        def one_from_boc(cls, _data):
            return cls()

    def test_raw_config_transaction_binds_tx_message_and_body(self):
        tx_hash, msg_hash, body_hash = b"t" * 32, b"m" * 32, b"b" * 32
        tx_id = {"lt": "21", "hash": base64.b64encode(tx_hash).decode()}
        config = {"transaction_id": tx_id,
                  "in_msg": {"hash": base64.b64encode(msg_hash).decode()}}
        parsed = types.SimpleNamespace(
            cell=types.SimpleNamespace(hash=tx_hash),
            in_msg=types.SimpleNamespace(cell=types.SimpleNamespace(hash=msg_hash),
                                         body=types.SimpleNamespace(hash=body_hash)))
        cell_class = types.SimpleNamespace(one_from_boc=lambda _: types.SimpleNamespace(
            begin_parse=lambda: object()))
        parser = types.SimpleNamespace(deserialize=lambda _: parsed)
        page = {"result": {"transactions": [{"transaction_id": tx_id,
                                               "data": base64.b64encode(b"raw BOC").decode()}]}}
        with patch.object(e15, "rpc_call", return_value=page) as rpc, patch.object(
            e15, "Cell", cell_class
        ), patch.object(e15, "Transaction", parser):
            self.assertEqual(e15.exact_config_incoming_body("config", config).hash, body_hash)
            rpc.assert_called_once_with("getTransactionsStd", address="config", limit=1,
                                        lt="21", hash=tx_id["hash"])
            parsed.in_msg.cell.hash = b"x" * 32
            with self.assertRaisesRegex(RuntimeError, "inbound message hash differs"):
                e15.exact_config_incoming_body("config", config)
            parsed.in_msg.cell.hash = msg_hash
            parsed.cell.hash = b"x" * 32
            with self.assertRaisesRegex(RuntimeError, "raw transaction or inbound message hash differs"):
                e15.exact_config_incoming_body("config", config)

    def run_case(self, *, config_hash="edge", config_aborted=False,
                 body_hash=None, incoming_source="faucet", extra_wallet=None,
                 transient_timeout=False):
        wallet = wallet_tx()
        wallet["out_msgs"][0]["destination"] = "config"
        config = collection_tx(code=0, message_hash=config_hash)
        config["aborted"] = config_aborted
        config["in_msg"]["source"] = incoming_source
        config["out_msgs"] = [{"destination": "faucet", "hash": "return"}]

        class ParsedCell(self.FakeCell):
            hash = body_hash or b"v" * 32

        reads = ([TimeoutError("temporary socket stall")] if transient_timeout else [])
        reads += [[wallet] + (extra_wallet or []), [config]]
        with tempfile.TemporaryDirectory() as directory, patch.object(
            e15, "transactions_after", side_effect=reads
        ), patch.object(e15, "same_addr", side_effect=lambda a, b: a == b), patch.object(
            e15, "finalized_mc_header", side_effect=[
                {"id": {"seqno": 11}}, {"id": {"seqno": 12}}
            ]
        ), patch.object(e15.asyncio, "sleep", new=AsyncMock()), patch.object(
            e15, "exact_config_incoming_body", return_value=ParsedCell()), patch.object(
            e15, "GOVERNANCE_EVIDENCE", Path(directory) / "receipts.jsonl"
        ) as evidence_path:
            receipt = asyncio.run(e15.governance_receipt(
                "PQ vote", "faucet", "config", 10, 20,
                {"id": {"seqno": 10}}, self.FakeCell()))
            stored = json.loads(evidence_path.read_text().splitlines()[0])
        return receipt, stored

    def test_vote_exact_wallet_config_body_and_two_heads(self):
        receipt, stored = self.run_case()
        self.assertEqual(receipt["outgoing"]["hash"], "edge")
        self.assertEqual(receipt["config_tx"]["in_msg"]["hash"], "edge")
        self.assertEqual([h["id"]["seqno"] for h in stored["after_heads"]], [11, 12])
        self.assertEqual(stored["body_hash"], (b"v" * 32).hex())

    def test_wrong_incoming_message_hash_is_not_a_vote_receipt(self):
        clock = types.SimpleNamespace(monotonic=iter([0, 0, 0, 0, 61]).__next__)
        with patch.object(e15, "time", clock), patch.object(
            e15.asyncio, "sleep", new=AsyncMock()
        ):
            with self.assertRaisesRegex(RuntimeError, "exact Config receipt not observed"):
                self.run_case(config_hash="other")

    def test_wrong_body_cannot_substitute_for_node_vote(self):
        with self.assertRaisesRegex(RuntimeError, "body differs"):
            self.run_case(body_hash=b"x" * 32)

    def test_config_abort_is_not_success(self):
        with self.assertRaisesRegex(RuntimeError, "receipt or body differs"):
            self.run_case(config_aborted=True)

    def test_wrong_sender_is_not_delivery(self):
        with self.assertRaisesRegex(RuntimeError, "receipt or body differs"):
            self.run_case(incoming_source="other")

    def test_config_return_credit_is_not_a_second_faucet_send(self):
        credit = {"transaction_id": {"lt": "12"},
                  "in_msg": {"source": "config", "hash": "return"}, "out_msgs": []}
        receipt, _ = self.run_case(extra_wallet=[credit])
        self.assertEqual(receipt["scanned_wallet"], 2)
        with self.assertRaisesRegex(RuntimeError, "unrelated faucet transaction"):
            self.run_case(extra_wallet=[dict(credit, in_msg={"source": "other", "hash": "return"})])
        with self.assertRaisesRegex(RuntimeError, "unrelated faucet transaction"):
            self.run_case(extra_wallet=[dict(credit, out_msgs=[{"destination": "other"}])])
        with self.assertRaisesRegex(RuntimeError, "multiple faucet sends"):
            self.run_case(extra_wallet=[dict(credit, out_msgs=[{"destination": "config"}])])

    def test_one_transport_timeout_retries_without_resending(self):
        receipt, _ = self.run_case(transient_timeout=True)
        self.assertEqual(receipt["outgoing"]["hash"], "edge")

    def test_persistent_transport_timeout_does_not_pass(self):
        clock = types.SimpleNamespace(monotonic=iter([0, 0, 0, 61]).__next__)
        with patch.object(e15, "time", clock), patch.object(
            e15, "transactions_after", side_effect=TimeoutError("socket stalled")
        ), patch.object(e15.asyncio, "sleep", new=AsyncMock()):
            with self.assertRaisesRegex(RuntimeError, "exact Config receipt not observed"):
                asyncio.run(e15.governance_receipt(
                    "PQ vote", "faucet", "config", 10, 20,
                    {"id": {"seqno": 10}}, self.FakeCell()))


if __name__ == "__main__":
    unittest.main()
