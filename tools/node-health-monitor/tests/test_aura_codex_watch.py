"""AURA model output must stay tied to the six verified process parents."""

import importlib.util
import datetime as dt
import json
import os
import hashlib
import sqlite3
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).parents[1] / "scripts" / "run-aura-process-watch.py"
SCHEMA = Path(__file__).parents[1] / "contracts" / "diagnosis.schema.json"
spec = importlib.util.spec_from_file_location("aura_process_watch", SCRIPT)
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)


class CodexWatchTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        fake = Path(self.temp.name) / "fake-aura"
        fake.write_text("#!/usr/bin/env python3\nimport os\nprint(os.environ['FAKE_ANSWER'])\n")
        fake.chmod(0o700)
        self.args = types.SimpleNamespace(
            diagnosis_schema=str(SCHEMA), codex_bin=str(fake),
            codex_socket="/unused", codex_thread_file="/unused",
        )
        self.sources = {
            node: {"pid": index + 1, "evidence_id": f"{index + 1:064x}"}
            for index, node in enumerate(sorted(watch.NODES))
        }

    def answer(self, evidence_id, status="insufficient_evidence"):
        return {
            "status": status,
            "summary": "Six process sources are partial; validator health is unknown.",
            "findings": [{"claim": "A process source was observed", "basis": "observed",
                          "evidence_ids": [evidence_id]}],
            "missing_evidence": ["consensus", "duty"],
            "recommended_runbooks": ["inspect_consensus_queues"],
        }

    def test_bound_partial_answer_passes(self):
        answer = json.dumps(self.answer(next(iter(self.sources.values()))["evidence_id"]))
        with patch.dict(os.environ, {"FAKE_ANSWER": answer}):
            result = watch.analyze(self.args, self.sources, "2026-09-30T00:00:00+00:00")
        self.assertEqual(result["status"], "insufficient_evidence")

    def test_fabricated_parent_and_healthy_status_refuse(self):
        for answer in (self.answer("f" * 64),
                       self.answer(next(iter(self.sources.values()))["evidence_id"], "analysis")):
            with patch.dict(os.environ, {"FAKE_ANSWER": json.dumps(answer)}):
                with self.assertRaises(ValueError):
                    watch.analyze(self.args, self.sources, "2026-09-30T00:00:00+00:00")

    def test_local_facts_require_fresh_private_matching_source(self):
        path = Path(self.temp.name) / "health.json"
        database = Path(self.temp.name) / "evidence.db"
        network = "a" * 64
        native_payload = {"network_id": network}
        native_hash = hashlib.sha256(json.dumps(native_payload, sort_keys=True,
                                                separators=(",", ":")).encode()).hexdigest()
        with sqlite3.connect(database) as db:
            db.executescript("CREATE TABLE observations(store_seq INTEGER PRIMARY KEY,"
                             "node TEXT,scope TEXT,source TEXT,content_hash TEXT,body TEXT);"
                             "CREATE TABLE quarantined(node TEXT,scope TEXT,process_epoch TEXT,"
                             "source_epoch TEXT,source TEXT);")
            for index, node in enumerate(sorted(watch.NODES)):
                native = {"content_hash": native_hash, "generation": "1", "source_epoch": "epoch",
                          "payload": native_payload}
                value = {"source_epoch": "epoch", "record": {
                    "node_id": node, "source_id": "native_core", "source_record_id": "epoch:1",
                    "process_epoch": "epoch", "received_at_ms": 1,
                    "payload": {"source": native}}}
                canonical = json.loads(json.dumps(value))
                canonical["record"]["received_at_ms"] = 0
                parent = hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()
                db.execute("INSERT INTO observations VALUES(?,?,?,?,?,?)",
                           (index + 1, node, "node", "native_core", parent,
                            json.dumps(value, separators=(",", ":"))))
        value = {
            "schema_version": 1,
            "scope": "local_development_validator_sources",
            "network_id": network,
            "whole_validator_health": "unknown",
            "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "samples": {node: {"pid": source["pid"], "native_hash": native_hash,
                               "native_epoch": "epoch", "native_generation": 1}
                        for node, source in self.sources.items()},
            "verdicts": {node: {"status": "unknown", "reasons": ["unverified"],
                               "facts": {"native_hash": native_hash}}
                         for node in self.sources},
        }
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        actual = watch.read_local_health(path, self.sources, network, database)
        self.assertEqual(len(actual), 6)
        self.assertTrue(all(len(item["native_archive_parent"]) == 64 for item in actual.values()))
        value["samples"]["validator1"]["pid"] += 1
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "local_health_identity"):
            watch.read_local_health(path, self.sources, network, database)
        value["samples"]["validator1"]["pid"] -= 1
        path.write_text(json.dumps(value))
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "local_health_permissions"):
            watch.read_local_health(path, self.sources, network, database)
        path.chmod(0o600)
        with sqlite3.connect(database) as db:
            db.execute("INSERT INTO quarantined VALUES(?,?,?,?,?)",
                       ("validator1", "node", "epoch", "epoch", "native_core"))
        with self.assertRaisesRegex(ValueError, "local_health_archive_quarantined"):
            watch.read_local_health(path, self.sources, network, database)
        with sqlite3.connect(database) as db:
            db.execute("DELETE FROM quarantined")
            db.execute("UPDATE observations SET content_hash=? WHERE node='validator1'", ("f" * 64,))
        with self.assertRaisesRegex(ValueError, "local_health_archive_mismatch"):
            watch.read_local_health(path, self.sources, network, database)


if __name__ == "__main__":
    unittest.main()
