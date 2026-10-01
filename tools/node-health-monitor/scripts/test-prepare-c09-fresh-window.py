#!/usr/bin/env python3
"""Disposable Q and private-artifact controls for fresh-window preparation."""

import datetime as dt
import importlib.util
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

SOURCE = Path(__file__).with_name("prepare-c09-fresh-window.py")
spec = importlib.util.spec_from_file_location("fresh_window", SOURCE)
fresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fresh)


class FreshWindowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.d = Path(self.temp.name)
        self.d.chmod(0o700)
        self.q = self.d / "q.db"
        with sqlite3.connect(self.q) as db:
            db.executescript(
                "CREATE TABLE query_grants(run_id TEXT,boot_id TEXT,revoked INTEGER,expires_ms INTEGER,body BLOB);"
                "CREATE TABLE query_attempts(id INTEGER);"
            )
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            for i in range(3):
                db.execute(
                    "INSERT INTO query_grants VALUES(?,?,?,?,?)",
                    (str(i), boot + "|test", 1, 1, b"{}"),
                )
            db.execute("INSERT INTO query_attempts VALUES(1)")
        self.q.chmod(0o600)
        self.log = self.d / "old.jsonl"
        self.log.write_text(
            json.dumps({"status": "failed", "cleanup_confirmed": False, "slot_highwater": 10})
            + "\n"
        )
        self.log.chmod(0o600)
        self.marker = self.d / "old.inflight"
        self.marker.write_text('{"slot":10}')
        self.marker.chmod(0o600)
        self.frozen_log = self.d / "old.frozen"
        self.frozen_log.write_bytes(self.log.read_bytes())
        self.frozen_log.chmod(0o600)
        self.frozen_marker = self.d / "marker.frozen"
        self.frozen_marker.write_bytes(self.marker.read_bytes())
        self.frozen_marker.chmod(0o600)
        self.audit = self.d / "AUDIT.json"
        audit = {
            "observed_utc": (
                dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=2)
            ).isoformat(),
            "sample_log": {
                "source": str(self.log),
                "frozen": str(self.frozen_log),
                "sha256": fresh.digest(self.log.read_bytes()),
            },
            "inflight_marker": {
                "source": str(self.marker),
                "frozen": str(self.frozen_marker),
                "sha256": fresh.digest(self.marker.read_bytes()),
            },
            "q_ledger": {
                "device": self.q.stat().st_dev,
                "inode": self.q.stat().st_ino,
                "grant_count": 3,
                "attempt_count": 1,
                "new_rows": [{"ordinal": 3}],
            },
        }
        self.audit.write_text(json.dumps(audit))
        self.audit.chmod(0o600)
        self.resolution = self.d / "resolution.json"
        value = {
            "schema_version": 1,
            "decision": "resolved_new_window",
            "audit_sha256": fresh.digest(self.audit.read_bytes()),
            "old_log_sha256": audit["sample_log"]["sha256"],
            "old_marker_sha256": audit["inflight_marker"]["sha256"],
            "q_device": audit["q_ledger"]["device"],
            "q_inode": audit["q_ledger"]["inode"],
            "failed_slot_highwater": 10,
            "reviewer": "operator",
            "reviewed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "candidate_grants_accounted_for": True,
            "original_marker_preserved": True,
        }
        self.resolution.write_text(json.dumps(value))
        self.resolution.chmod(0o600)

    def prepare(self, name="new"):
        return fresh.prepare(self.audit, self.resolution, self.q, self.d / name, "a" * 64)

    def test_new_baseline_has_distinct_window_and_old_artifacts_remain(self):
        old_log, old_marker = self.log.read_bytes(), self.marker.read_bytes()
        window, digest = self.prepare()
        baseline_path = self.d / "new/baseline.private.json"
        baseline = json.loads(baseline_path.read_bytes())
        self.assertEqual((self.d / "new").stat().st_mode & 0o777, 0o700)
        self.assertEqual(baseline_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(window, fresh.digest(self.resolution.read_bytes()))
        self.assertEqual(digest, fresh.digest(baseline_path.read_bytes()))
        self.assertEqual((baseline["grants"], baseline["attempts"]), (3, 1))
        self.assertEqual(self.log.read_bytes(), old_log)
        self.assertEqual(self.marker.read_bytes(), old_marker)
        self.assertFalse((self.d / "new/samples.private.jsonl").exists())

    def test_resolution_or_q_change_fails_before_new_directory(self):
        value = json.loads(self.resolution.read_bytes())
        value["old_marker_sha256"] = "0" * 64
        self.resolution.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError, "manual resolution mismatch"):
            self.prepare()
        self.assertFalse((self.d / "new").exists())
        value["old_marker_sha256"] = fresh.digest(self.marker.read_bytes())
        self.resolution.write_text(json.dumps(value))
        self.q.rename(self.d / "q-old.db")
        with sqlite3.connect(self.q) as db:
            db.executescript(
                "CREATE TABLE query_grants(run_id TEXT,boot_id TEXT,revoked INTEGER,expires_ms INTEGER,body BLOB);"
                "CREATE TABLE query_attempts(id INTEGER);"
            )
        self.q.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "Q ledger replacement"):
            self.prepare()
        self.assertFalse((self.d / "new").exists())

    def test_unresolved_live_grant_fails_before_new_directory(self):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        now_ms = int(time.clock_gettime(time.CLOCK_BOOTTIME) * 1000)
        with sqlite3.connect(self.q) as db:
            db.execute(
                "INSERT INTO query_grants VALUES(?,?,?,?,?)",
                ("live", boot + "|test", 0, now_ms + 200_000, b"{}"),
            )
        with self.assertRaisesRegex(RuntimeError, "Q grant state unresolved"):
            self.prepare()
        self.assertFalse((self.d / "new").exists())


if __name__ == "__main__":
    unittest.main()
