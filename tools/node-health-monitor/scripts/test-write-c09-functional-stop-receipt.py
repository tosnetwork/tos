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
               "secret": "must-not-appear"}
        self.log.write_text(json.dumps(row) + "\n")
        self.log.chmod(0o600)
        self.marker = self.directory / "samples.private.jsonl.inflight"
        self.marker.write_bytes(b"private marker")
        self.marker.chmod(0o600)

    def call(self, end, timer_active="inactive"):
        argv = [str(SOURCE), "--runtime-dir", str(self.directory), "--q-ledger", str(self.q),
                "--baseline-file", str(self.baseline), "--expected-baseline-sha256",
                hashlib.sha256(self.baseline.read_bytes()).hexdigest(),
                "--window-end-utc", end]
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


if __name__ == "__main__":
    unittest.main()
