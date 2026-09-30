#!/usr/bin/env python3
"""Offline controls for the bounded functional witness; never use live tokens."""

import importlib.util
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SOURCE = Path(__file__).with_name("sample-query-functional.py")
spec = importlib.util.spec_from_file_location("functional_witness", SOURCE)
witness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(witness)


class FunctionalWitnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db = str(Path(self.temporary.name) / "m.db")
        conn = sqlite3.connect(self.db)
        conn.execute("CREATE TABLE observations(content_hash TEXT,node TEXT,source TEXT,body TEXT)")
        self.parent = {"source_epoch": "source-1", "record": {"node_id": "validator1", "source_id": "process",
                                  "process_epoch": "epoch-1", "observed_at_ms": 100000, "received_at_ms": 123456,
                                  "payload": {"component": "process", "source": {
                                      "payload": {"kind": "process", "pid": 42}}}}}
        canonical = json.loads(json.dumps(self.parent))
        canonical["record"]["received_at_ms"] = 0
        self.parent_id = hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()
        conn.execute("INSERT INTO observations VALUES(?,?,?,?)",
                     (self.parent_id, "validator1", "process", json.dumps(self.parent)))
        conn.commit()
        conn.close()
        self.envelope = {"run_id": "run", "status": "partial", "data": {
            "node_id": "validator1", "process_epoch": "epoch-1", "components": [
                {"kind": "process", "sources": ["process"], "value": {"kind": "process", "pid": 42}}]},
            "evidence": [{"node_id": "validator1", "source_id": "process", "kind": "derived",
                          "process_epoch": "epoch-1", "clock_quality": "valid", "redacted": True,
                          "source_version": "m-observation-projection-v1",
                          "derivation_version": "m-observation-projection-v1",
                          "observed_at": "1970-01-01T00:01:40.000Z",
                          "source_record_id": "m-" + self.parent_id,
                          "parent_evidence_ids": [self.parent_id],
                          "payload": {"kind": "process", "pid": 42}}]}

    def test_exact_parent_and_age(self):
        self.assertEqual(witness.validate_process(self.envelope, "run", "validator1", 180000, self.db), 100000)
        with self.assertRaisesRegex(witness.WitnessError, "parent_age"):
            witness.validate_process(self.envelope, "run", "validator1", 280001, self.db)
        with self.assertRaisesRegex(witness.WitnessError, "parent_payload"):
            changed = json.loads(json.dumps(self.parent))
            changed["record"]["payload"]["source"]["payload"]["pid"] = 43
            with patch.object(witness, "parent_from_m", return_value=changed):
                witness.validate_process(self.envelope, "run", "validator1", 180000, self.db)
        with self.assertRaisesRegex(witness.WitnessError, "parent_hash"):
            conn = sqlite3.connect(self.db)
            conn.execute("UPDATE observations SET body=?", (json.dumps(changed),))
            conn.commit()
            conn.close()
            witness.validate_process(self.envelope, "run", "validator1", 180000, self.db)

    def test_negative_controls_require_exact_error_and_unknown(self):
        for code in ("CACHE_MISS", "OUT_OF_SCOPE"):
            value = {"run_id": "run", "status": "error", "error": {"code": code},
                     "coverage": {"status": "unknown"}, "data": None, "evidence": []}
            witness.validate_negative(value, code, "run")
            value["coverage"]["status"] = "partial"
            with self.assertRaises(witness.WitnessError):
                witness.validate_negative(value, code, "run")

    def test_successful_grant_with_bad_token_still_needs_revoke(self):
        run = "11111111-1111-4111-8111-111111111111"
        with patch.object(witness, "control", return_value=(200, {"content-type": "application/json"}, json.dumps({
                "run_id": run, "run_token": "bad"}).encode())):
            leases = []
            with self.assertRaisesRegex(witness.WitnessError, "grant_shape"):
                witness.issue("socket", "token", "validator1", "start", "end", leases)
            self.assertEqual(leases, [run])

    def test_ledger_growth_refuses_before_next_grant(self):
        path = str(Path(self.temporary.name) / "q.db")
        conn = sqlite3.connect(path)
        conn.executescript("CREATE TABLE query_grants(body BLOB); CREATE TABLE query_attempts(id INTEGER);")
        conn.execute("INSERT INTO query_grants VALUES(?)", (b"small",))
        conn.commit()
        conn.close()
        self.assertEqual(witness.ledger_growth(path, (0, 0, 0)), 1)
        with self.assertRaisesRegex(witness.WitnessError, "ledger_growth"):
            witness.ledger_growth(path, (0, 0, -4000))

    def test_mcp_session_initializes_before_call_and_binds_run(self):
        calls = []
        def fake_request(_conn, _method, path, body, headers, _cap=witness.LIMIT):
            calls.append((path, body, headers))
            if body["method"] == "initialize":
                return 200, {"content-type": "application/json", "mcp-session-id": "session1"}, json.dumps({
                    "jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18"}}).encode()
            if body["method"] == "notifications/initialized":
                return 202, {}, b""
            return 200, {"content-type": "application/json"}, json.dumps({
                "jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": json.dumps(self.envelope)}]}}).encode()
        with patch.object(witness, "request", side_effect=fake_request):
            session = witness.McpSession("socket", "service", "run", "a" * 64)
            session.initialize()
            self.assertEqual(session.snapshot("run", "validator1", "time", "process")["status"], "partial")
            session.close()
        self.assertEqual([item[1]["method"] for item in calls],
                         ["initialize", "notifications/initialized", "tools/call"])
        self.assertEqual(calls[-1][2]["mcp-session-id"], "session1")
        self.assertEqual(calls[-1][1]["params"]["arguments"]["run_id"], "run")

    def test_timeout_after_grant_attempts_revoke_and_logs_failure(self):
        log = Path(self.temporary.name) / "samples.jsonl"
        args = SimpleNamespace(log_file=str(log), operator_token_file="operator", service_token_file="service",
                               query_unit="query", expected_query_sha256="a" * 64, control_socket="control",
                               mcp_socket="mcp", m_db=self.db, q_ledger="q",
                               baseline_grants=0, baseline_grant_bytes=0, baseline_attempts=0)
        run = "11111111-1111-4111-8111-111111111111"
        def timeout_issue(_socket, _token, _node, _start, _end, leases):
            leases.append(run)
            raise TimeoutError("injected")
        with patch.object(witness, "private_token", return_value="secret"), \
             patch.object(witness, "bound_service", return_value=123), \
             patch.object(witness, "ledger_growth", return_value=1), \
             patch.object(witness, "issue", side_effect=timeout_issue), \
             patch.object(witness, "revoke", return_value=True) as revoke:
            self.assertEqual(witness.run(args), 1)
        revoke.assert_called_once_with("control", "secret", run)
        row = json.loads(log.read_text().strip())
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["error_kind"], "TimeoutError")
        self.assertTrue(row["cleanup_confirmed"])
        self.assertNotIn(run, log.read_text())


if __name__ == "__main__":
    unittest.main()
