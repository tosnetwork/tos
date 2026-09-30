#!/usr/bin/env python3
"""Offline controls for the private functional window stop receipt."""

from contextlib import redirect_stdout
import datetime as dt
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name("write-c09-functional-stop-receipt.py")
spec = importlib.util.spec_from_file_location("functional_stop_receipt", SOURCE)
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)


class StopReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.directory.chmod(0o700)
        self.q = self.directory / "q.db"
        self.q.write_bytes(b"fixture")
        self.q.chmod(0o600)
        self.baseline = self.directory / "baseline.private.json"
        self.baseline.write_text(json.dumps({"q_device": str(self.q.stat().st_dev),
                                             "q_inode": str(self.q.stat().st_ino)}))
        self.baseline.chmod(0o600)
        self.log = self.directory / "samples.private.jsonl"
        row = {"slot": 1, "slot_highwater": 1, "status": "failed", "cleanup_confirmed": False,
               "wall_utc": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=73)).isoformat(),
               "secret": "must-not-appear"}
        self.log.write_text(json.dumps(row) + "\n")
        self.log.chmod(0o600)
        self.marker = self.directory / "samples.private.jsonl.inflight"
        self.marker.write_bytes(b"private marker")
        self.marker.chmod(0o600)

    def call(self, end, timer_active="inactive", first_deadline=None):
        argv = [str(SOURCE), "--runtime-dir", str(self.directory), "--q-ledger", str(self.q),
                "--baseline-file", str(self.baseline), "--expected-baseline-sha256",
                hashlib.sha256(self.baseline.read_bytes()).hexdigest(),
                "--window-end-utc", end, "--first-pass-not-after-utc", first_deadline or end]
        def state(unit):
            return {"LoadState": "loaded", "ActiveState": timer_active if unit.endswith(".timer") else "inactive",
                    "SubState": "dead"}
        with patch.object(sys, "argv", argv), patch.object(receipt, "unit_state", side_effect=state), \
             redirect_stdout(io.StringIO()):
            receipt.main()

    def test_receipt_requires_window_end_and_inactive_timer(self):
        future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat()
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)).isoformat()
        with self.assertRaisesRegex(RuntimeError, "window not ended"):
            self.call(future)
        with self.assertRaisesRegex(RuntimeError, "still active"):
            self.call(past, timer_active="active")
        self.assertFalse((self.directory / "stop-receipt.private.json").exists())

    def test_receipt_is_private_bounded_and_single_write(self):
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)).isoformat()
        self.call(past)
        path = self.directory / "stop-receipt.private.json"
        raw = path.read_bytes()
        value = json.loads(raw)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(value["acceptance_claim"])
        self.assertIsNone(value["first_successful_sample_wall_utc"])
        self.assertFalse(value["functional_elapsed_gate_met"])
        self.assertTrue(value["q_identity_match"])
        self.assertEqual(value["last_sample"]["status"], "failed")
        self.assertEqual(value["inflight_sha256"], hashlib.sha256(self.marker.read_bytes()).hexdigest())
        self.assertNotIn(b"must-not-appear", raw)
        self.assertNotIn(b"private marker", raw)
        with self.assertRaises(FileExistsError):
            self.call(past)
        self.assertEqual(path.read_bytes(), raw)

    def test_replaced_q_ledger_is_recorded_without_acceptance_claim(self):
        self.q.rename(self.directory / "q.db.old")
        self.q.write_bytes(b"replacement")
        self.q.chmod(0o600)
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)).isoformat()
        self.call(past)
        value = json.loads((self.directory / "stop-receipt.private.json").read_bytes())
        self.assertFalse(value["q_identity_match"])
        self.assertFalse(value["acceptance_claim"])

    def test_actual_first_success_controls_elapsed_gate(self):
        wall = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=72, minutes=10)
        self.log.write_text(json.dumps({"slot": 1, "slot_highwater": 1, "status": "pass",
                                        "cleanup_confirmed": True, "fixed_grant_query_status": "pass",
                                        "boot_id": "test-boot", "boottime_ns": 1_000_000_000,
                                        "wall_utc": wall.isoformat()}) + "\n")
        self.log.chmod(0o600)
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat()
        with patch.object(receipt, "boot_domain", return_value=("test-boot", 1_000_000_000 + receipt.MIN_ELAPSED_NS)):
            self.call(past, first_deadline=(wall + dt.timedelta(minutes=1)).isoformat())
        value = json.loads((self.directory / "stop-receipt.private.json").read_bytes())
        self.assertEqual(value["first_successful_sample_wall_utc"], wall.isoformat())
        self.assertTrue(value["first_success_within_deadline"])
        self.assertTrue(value["functional_elapsed_gate_met"])
        self.assertFalse(value["acceptance_claim"])

    def test_boot_change_cannot_satisfy_elapsed_gate(self):
        wall = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=73)
        self.log.write_text(json.dumps({"slot": 1, "slot_highwater": 1, "status": "pass",
                                        "cleanup_confirmed": True, "fixed_grant_query_status": "pass",
                                        "boot_id": "prior-boot", "boottime_ns": 1_000_000_000,
                                        "wall_utc": wall.isoformat()}) + "\n")
        self.log.chmod(0o600)
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat()
        with patch.object(receipt, "boot_domain", return_value=("new-boot", receipt.MIN_ELAPSED_NS * 2)):
            self.call(past, first_deadline=(wall + dt.timedelta(minutes=1)).isoformat())
        value = json.loads((self.directory / "stop-receipt.private.json").read_bytes())
        self.assertIsNone(value["monotonic_elapsed_ns"])
        self.assertFalse(value["functional_elapsed_gate_met"])


if __name__ == "__main__":
    unittest.main()
