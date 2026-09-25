"""Offline fail-closed controls for composed workflow rejection and payout edges."""

import asyncio
import hashlib
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
    "E10_SOURCE_PATH",
    Path(__file__).resolve().parents[2] / "scripts/agent-economy-composed-e2e.py",
))
spec = importlib.util.spec_from_file_location("e10_composed", SOURCE)
e10 = importlib.util.module_from_spec(spec)
stubs = {name: types.ModuleType(name) for name in (
    "tostester", "tostester.install", "tostester.network",
    "tostester.pq_initial_validator", "pytosiq_core", "contract",
)}
stubs["tostester.install"].Install = object
stubs["tostester.network"].Network = object
stubs["tostester.network"].StartOptions = object
stubs["tostester.pq_initial_validator"].make_deterministic_pq_initial_validator = object
stubs["contract"].tos = object
for name in ("Address", "Cell", "InternalMsgInfo", "MessageAny", "WalletMessage"):
    setattr(stubs["pytosiq_core"], name, object)
with patch.dict(sys.modules, stubs):
    spec.loader.exec_module(e10)


STATE = {"status": "result_submitted", "attestor_pubkey": "aa" * 32}


def head(seqno):
    return {"id": {"seqno": seqno}, "gen_utime": seqno + 100}


def wallet_tx():
    return {"transaction_id": {"lt": "11"}, "aborted": False,
            "compute": {"success": True}, "action": {"success": True},
            "out_msgs": [{"destination": "0:target", "hash": "wallet-edge"}]}


def rejected_tx(code=9):
    return {"transaction_id": {"lt": "21"}, "aborted": True,
            "compute": {"success": False, "exit_code": code},
            "in_msg": {"hash": "wallet-edge"}}


def escrow_tx(value=2_600_000_000):
    return {"transaction_id": {"lt": "31"}, "aborted": False,
            "compute": {"success": True}, "action": {"success": True},
            "out_msgs": [{"destination": "0:worker", "value": str(value),
                          "hash": "payout-edge"}]}


def worker_tx(value=2_600_000_000, message_hash="payout-edge"):
    return {"transaction_id": {"lt": "41"}, "aborted": False,
            "in_msg": {"source": "0:target", "value": str(value),
                       "hash": message_hash}}


class ComposedEvidenceTests(unittest.TestCase):
    def test_manifest_binds_clean_source_and_three_binary_hashes(self):
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
            path = root / "manifest.json"
            with patch.object(e10, "BUILD_DIR", root), patch.object(e10, "TOSCTL", str(tosctl)), patch.object(
                e10, "MANIFEST", path
            ), patch.object(e10.subprocess, "check_output", return_value="fixed-sha\n"), patch.object(
                e10.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)
            ):
                e10.write_manifest()
            manifest = json.loads(path.read_text())
            self.assertEqual(manifest["source_commit"], "fixed-sha")
            self.assertFalse(manifest["source_tracked_dirty"])
            self.assertEqual(manifest["binaries"]["tosctl"]["sha256"],
                             hashlib.sha256(b"tosctl").hexdigest())
            with patch.object(e10, "BUILD_DIR", root), patch.object(e10, "TOSCTL", str(tosctl)), patch.object(
                e10, "MANIFEST", path
            ), patch.object(e10.subprocess, "check_output", return_value="fixed-sha\n"), patch.object(
                e10.subprocess, "run", return_value=types.SimpleNamespace(returncode=1)
            ):
                with self.assertRaisesRegex(RuntimeError, "clean tracked source tree"):
                    e10.write_manifest()

    def test_full_transaction_page_without_baseline_is_refused(self):
        rows = [{"transaction_id": {"lt": str(20 - index)}} for index in range(10)]
        with patch.object(e10, "rpc_call", return_value={"result": rows}):
            with self.assertRaisesRegex(RuntimeError, "did not cover baseline"):
                e10.transactions_after("0:payer", 10)

    def negative(self, *, code=9, send_error=None, target=None, wallet=None):
        with patch.object(e10, "finalized_mc_header",
                          side_effect=[head(10), head(11), head(12)]), patch.object(
            e10, "last_lt", side_effect=[10, 20]
        ), patch.object(e10, "transactions_after", side_effect=[
            [wallet or wallet_tx()], [target or rejected_tx(code)]
        ]), patch.object(e10, "same_addr", return_value=True), patch.object(
            e10, "record_jsonl"
        ) as record, patch.object(e10, "check") as check:
            asyncio.run(e10.rejected_operation(
                "no signature", "0:target", "0:payer", 9,
                AsyncMock(side_effect=[STATE, STATE, STATE]),
                AsyncMock(side_effect=send_error, return_value="submitted")))
            return record, check

    def payout(self, *, source=None, recipient=None):
        with patch.object(e10, "transactions_after", side_effect=[
            [source or escrow_tx()], [recipient or worker_tx()]
        ]), patch.object(e10, "same_addr", return_value=True), patch.object(
            e10, "finalized_mc_header", side_effect=[head(11), head(12)]
        ), patch.object(e10, "record_jsonl") as record, patch.object(e10, "check") as check:
            asyncio.run(e10.verify_payout_edge(
                "payout", "0:target", "0:worker", 30, 40, 2_600_000_000, head(10)))
            return record, check

    def test_exact_vm9_and_final_heads(self):
        record, check = self.negative()
        record.assert_called_once()
        check.assert_called_once_with("no signature", True)

    def test_cli_error_is_not_rejection(self):
        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            self.negative(send_error=RuntimeError("HTTP 503"))

    def test_wrong_vm_code_is_not_rejection(self):
        with self.assertRaisesRegex(RuntimeError, "expected VM exit 9"):
            self.negative(target=rejected_tx(127))

    def test_wallet_failure_is_not_rejection(self):
        with self.assertRaisesRegex(RuntimeError, "wallet did not submit"):
            self.negative(wallet=dict(wallet_tx(), aborted=True))

    def test_exact_payout_message_passes(self):
        record, check = self.payout()
        record.assert_called_once()
        check.assert_called_once_with("payout", True)

    def test_unrelated_credit_is_not_payout(self):
        with self.assertRaisesRegex(RuntimeError, "inbound hash did not match"):
            self.payout(recipient=worker_tx(message_hash="unrelated"))

    def test_wrong_amount_is_not_payout(self):
        with self.assertRaisesRegex(RuntimeError, "exact payout message and amount"):
            self.payout(source=escrow_tx(value=2_500_000_000))


if __name__ == "__main__":
    unittest.main()
