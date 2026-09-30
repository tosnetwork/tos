#!/usr/bin/env python3
"""Disposable SQLite controls for the advisory retention inventory."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

SOURCE = Path(__file__).with_name("plan-c09-retention-dry-run.py")
spec = importlib.util.spec_from_file_location("retention_dry_run", SOURCE)
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


class DryRunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="c09-retention-dry-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.m, self.q, self.control = (root / name for name in ("m.db", "q.db", "control.db"))
        self.network = "a" * 64
        with sqlite3.connect(self.m) as db:
            db.executescript("CREATE TABLE database_identity(singleton INTEGER PRIMARY KEY,network TEXT);"
                             "CREATE TABLE observations(store_seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                             "source TEXT,content_hash TEXT,body TEXT);")
            db.execute("INSERT INTO database_identity VALUES(1,?)", (self.network,))
            for source in ("process", "mystery", "diagnostic"):
                db.execute("INSERT INTO observations(source,content_hash,body) VALUES(?,?,?)",
                           (source, "b" * 64, "{}"))
        self.m.chmod(0o600)
        meta = self.m.stat()
        with sqlite3.connect(self.q) as db:
            db.executescript("CREATE TABLE query_manager_cursor(singleton INTEGER PRIMARY KEY,network TEXT,"
                             "device TEXT,inode TEXT,watermark INTEGER,anchor_seq INTEGER,anchor_hash TEXT);"
                             "CREATE TABLE query_origins(origin_id TEXT PRIMARY KEY,manager_seq INTEGER);")
            db.execute("INSERT INTO query_manager_cursor VALUES(1,?,?,?,?,?,?)",
                       (self.network, str(meta.st_dev), str(meta.st_ino), 3, 3, "b" * 64))
            db.execute("INSERT INTO query_origins VALUES(?,?)", ("c" * 64, 2))
        self.q.chmod(0o600)
        with sqlite3.connect(self.control) as db:
            db.executescript("CREATE TABLE database_identity(singleton INTEGER PRIMARY KEY,network TEXT);"
                             "CREATE TABLE source_state(store_seq INTEGER);"
                             "CREATE TABLE incidents(body TEXT);"
                             "CREATE TABLE outbox(delivered INTEGER);")
            db.execute("INSERT INTO database_identity VALUES(1,?)", (self.network,))
            db.execute("INSERT INTO source_state VALUES(1)")
            db.execute("INSERT INTO incidents VALUES('{}')")
            db.execute("INSERT INTO outbox VALUES(0)")
        self.control.chmod(0o600)

    def inspect(self, after=0):
        return planner.inspect(self.m, self.q, self.control, self.network, after)

    def test_pins_unknown_class_and_no_mutation(self):
        before = [hashlib.sha256(path.read_bytes()).digest() for path in (self.m, self.q, self.control)]
        result = self.inspect()
        after = [hashlib.sha256(path.read_bytes()).digest() for path in (self.m, self.q, self.control)]
        self.assertEqual(after, before)
        self.assertTrue(result["advisory_only"])
        self.assertEqual(result["pin_view"], "provisional_cross_database_snapshot")
        self.assertEqual(result["pin_integrity"], "not_verified")
        self.assertEqual(result["deletion_candidates"], 0)
        self.assertEqual(result["age_eligibility"], "not_evaluated_unknown_class_or_clock")
        self.assertEqual(result["page_rows"], 3)
        self.assertEqual(result["page_process_rows"], 1)
        self.assertEqual(result["page_unclassified_rows"], 2)
        self.assertEqual(result["page_q_pinned_rows"], 2)  # retained seq 2 and non-process anchor 3
        self.assertEqual(result["page_control_pinned_rows"], 1)
        self.assertEqual(result["control_pending_outbox_count"], 1)
        self.assertEqual(self.inspect(2)["page_last_seq"], "3")

    def test_missing_or_mutated_anchor_refuses(self):
        with sqlite3.connect(self.m) as db:
            db.execute("UPDATE observations SET content_hash=? WHERE store_seq=3", ("d" * 64,))
        with self.assertRaisesRegex(planner.Refused, "q_anchor_missing"):
            self.inspect()

    def test_old_anchor_below_global_watermark_refuses(self):
        with sqlite3.connect(self.q) as db:
            db.execute("UPDATE query_manager_cursor SET anchor_seq=1,anchor_hash=?", ("b" * 64,))
        before = [hashlib.sha256(path.read_bytes()).digest() for path in (self.m, self.q, self.control)]
        with self.assertRaisesRegex(planner.Refused, "q_anchor"):
            self.inspect()
        self.assertEqual(before, [hashlib.sha256(path.read_bytes()).digest()
                                  for path in (self.m, self.q, self.control)])

    def test_replaced_q_identity_and_excess_origins_refuse(self):
        with sqlite3.connect(self.q) as db:
            db.execute("UPDATE query_manager_cursor SET inode='1'")
        with self.assertRaisesRegex(planner.Refused, "q_cursor_identity"):
            self.inspect()
        with sqlite3.connect(self.q) as db:
            db.execute("UPDATE query_manager_cursor SET inode=?", (str(self.m.stat().st_ino),))
            db.executemany("INSERT INTO query_origins VALUES(?,2)",
                           ((f"{i:064x}",) for i in range(4097)))
        with self.assertRaisesRegex(planner.Refused, "q_origin_bound"):
            self.inspect()

    def test_private_files_required_and_no_delete_sql(self):
        self.m.chmod(0o644)
        with self.assertRaisesRegex(planner.Refused, "file_identity"):
            self.inspect()
        self.assertNotIn("DELETE FROM", SOURCE.read_text().upper())
        self.assertNotIn("UPDATE ", SOURCE.read_text().upper())


if __name__ == "__main__":
    unittest.main()
