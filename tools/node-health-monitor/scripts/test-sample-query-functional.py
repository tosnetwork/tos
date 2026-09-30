#!/usr/bin/env python3
"""Offline controls for the bounded functional witness; never use live tokens."""

import importlib.util
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import socket
import tempfile
import threading
import time
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
        conn.execute("CREATE TABLE observations(store_seq INTEGER PRIMARY KEY,content_hash TEXT,node TEXT,scope TEXT,process_epoch TEXT,source_epoch TEXT,source TEXT,body TEXT)")
        conn.execute("CREATE TABLE database_identity(singleton INTEGER,network TEXT)")
        conn.execute("CREATE TABLE quarantined(node TEXT,scope TEXT,process_epoch TEXT,source_epoch TEXT,source TEXT)")
        conn.execute("INSERT INTO database_identity VALUES(1,'network')")
        self.parent = {"source_epoch": "source-1", "record": {"node_id": "validator1", "scope_id": "node", "source_id": "process",
                                  "process_epoch": "epoch-1", "observed_at_ms": 100000, "received_at_ms": 123456,
                                  "payload": {"component": "process", "source": {
                                      "payload": {"kind": "process", "pid": 42}}}}}
        canonical = json.loads(json.dumps(self.parent))
        canonical["record"]["received_at_ms"] = 0
        self.parent_id = hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()
        conn.execute("INSERT INTO observations VALUES(?,?,?,?,?,?,?,?)",
                     (1, self.parent_id, "validator1", "node", "epoch-1", "source-1", "process", json.dumps(self.parent)))
        conn.commit()
        conn.close()
        self.envelope = {"run_id": "run", "status": "partial", "data": {
            "node_id": "validator1", "process_epoch": "epoch-1", "components": [
                {"kind": "process", "sources": ["process"], "value": {"kind": "process", "pid": 42}}]},
            "evidence": [{"node_id": "validator1", "source_id": "process", "kind": "derived",
                          "evidence_id": "b" * 64,
                          "process_epoch": "epoch-1", "clock_quality": "valid", "redacted": True,
                          "source_version": "m-observation-projection-v1",
                          "derivation_version": "m-observation-projection-v1",
                          "observed_at": "1970-01-01T00:01:40.000Z",
                          "source_record_id": "m-" + self.parent_id,
                          "parent_evidence_ids": [self.parent_id],
                          "payload": {"kind": "process", "pid": 42}}]}

    def test_exact_parent_and_age(self):
        self.assertEqual(witness.validate_process(self.envelope, "run", "validator1", 180000, self.parent), 100000)
        with self.assertRaisesRegex(witness.WitnessError, "parent_age"):
            witness.validate_process(self.envelope, "run", "validator1", 280001, self.parent)
        with self.assertRaisesRegex(witness.WitnessError, "parent_payload"):
            changed = json.loads(json.dumps(self.parent))
            changed["record"]["payload"]["source"]["payload"]["pid"] = 43
            witness.validate_process(self.envelope, "run", "validator1", 180000, changed)

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
                "run_id": run, "run_token": "bad", "expires_in_seconds": 200}).encode())):
            leases = []
            with self.assertRaisesRegex(witness.WitnessError, "grant_shape"):
                witness.issue("socket", "token", "validator1", "start", "end", leases)
            self.assertEqual(leases, [run])
        with patch.object(witness, "control", return_value=(200, {"content-type": "application/json"}, json.dumps({
                "run_id": run, "run_token": "a" * 64, "expires_in_seconds": 201}).encode())):
            leases = []
            with self.assertRaisesRegex(witness.WitnessError, "grant_expiry"):
                witness.issue("socket", "token", "validator1", "start", "end", leases)
            self.assertEqual(leases, [run])
        with patch.object(witness, "control", side_effect=TimeoutError("after commit")):
            leases = []
            with self.assertRaises(TimeoutError):
                witness.issue("socket", "token", "validator1", "start", "end", leases)
            self.assertEqual(leases, [None])
        with patch.object(witness, "control", return_value=(503, {}, b"")):
            leases = []
            with self.assertRaisesRegex(witness.WitnessError, "grant_refused"):
                witness.issue("socket", "token", "validator1", "start", "end", leases)
            self.assertEqual(leases, [None])

    def test_whole_run_timeout_in_head_probe_never_issues_grant(self):
        log = str(Path(self.temporary.name) / "sample.jsonl")
        args = SimpleNamespace(log_file=log, operator_token_file="operator", service_token_file="service",
                               baseline_file="baseline", expected_baseline_sha256="a" * 64,
                               expected_query_sha256="b" * 64, query_unit="isolated-query",
                               control_socket="control", mcp_socket="mcp", m_db="m", q_ledger="q")
        with (patch.object(witness, "private_token", return_value="a" * 64),
              patch.object(witness, "frozen_baseline", return_value={}),
              patch.object(witness, "bound_service", return_value=123),
              patch.object(witness, "ledger_growth", return_value=0),
              patch.object(witness, "projection_head", side_effect=witness.WholeRunTimeout("whole run")),
              patch.object(witness, "issue") as issue):
            self.assertEqual(witness.run(args), 1)
            issue.assert_not_called()
        row = json.loads(Path(log).read_text().strip())
        self.assertEqual((row["status"], row["error_kind"], row["grants_created"]),
                         ("failed", "WholeRunTimeout", 0))

    def _assert_real_socket_grant_commit_failure(self, response_status):
        suffix = str(response_status or "disconnect")
        path = str(Path(self.temporary.name) / ("control-" + suffix + ".sock"))
        side_effect_db = str(Path(self.temporary.name) / ("committed-" + suffix + ".db"))
        with closing(sqlite3.connect(side_effect_db)) as db:
            db.execute("CREATE TABLE issued(id INTEGER PRIMARY KEY)")
            db.commit()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(1)
        committed = threading.Event()
        def complete_with_ambiguous_response():
            conn, _ = listener.accept()
            with conn:
                raw = b""
                while b"\r\n\r\n" not in raw:
                    part = conn.recv(4096)
                    if not part:
                        return
                    raw += part
                header, body = raw.split(b"\r\n\r\n", 1)
                length = next(int(line.split(b":", 1)[1].strip()) for line in header.split(b"\r\n")
                              if line.lower().startswith(b"content-length:"))
                while len(body) < length:
                    body += conn.recv(length - len(body))
                self.assertIn(b"POST /v1/control/grants HTTP/1.1", header)
                with closing(sqlite3.connect(side_effect_db)) as db:
                    db.execute("INSERT INTO issued VALUES(1)")
                    db.commit()
                committed.set()  # Durable side effect precedes response loss or 503.
                if response_status == 503:
                    conn.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            listener.close()
        server = threading.Thread(target=complete_with_ambiguous_response, daemon=True)
        server.start()
        log = str(Path(self.temporary.name) / ("response-" + suffix + ".jsonl"))
        args = SimpleNamespace(log_file=log, operator_token_file="operator", service_token_file="service",
                               baseline_file="baseline", expected_baseline_sha256="a" * 64,
                               expected_query_sha256="b" * 64, query_unit="isolated-query",
                               control_socket=path, mcp_socket="mcp", m_db="m", q_ledger="q")
        try:
            with (patch.object(witness, "private_token", return_value="a" * 64),
                  patch.object(witness, "frozen_baseline", return_value={}),
                  patch.object(witness, "bound_service", return_value=123),
                  patch.object(witness, "ledger_growth", return_value=0),
                  patch.object(witness, "projection_head", return_value="caught_up")):
                self.assertEqual(witness.run(args), 1)
            self.assertTrue(committed.wait(1))
            with closing(sqlite3.connect(side_effect_db)) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM issued").fetchone(), (1,))
            row = json.loads(Path(log).read_text().strip())
            self.assertEqual((row["status"], row["error_kind"], row["grants_created"],
                              row["cleanup_confirmed"]),
                             ("failed", "cleanup_unconfirmed", 1, False))
        finally:
            listener.close()
            server.join(timeout=1)

    def test_real_socket_grant_commit_with_lost_response_is_unconfirmed(self):
        self._assert_real_socket_grant_commit_failure(None)

    def test_real_socket_grant_commit_with_503_is_unconfirmed(self):
        self._assert_real_socket_grant_commit_failure(503)

    def test_ledger_growth_refuses_before_next_grant(self):
        path = str(Path(self.temporary.name) / "q.db")
        conn = sqlite3.connect(path)
        conn.executescript("CREATE TABLE query_grants(body BLOB); CREATE TABLE query_attempts(id INTEGER);")
        conn.execute("INSERT INTO query_grants VALUES(?)", (b"small",))
        conn.commit()
        conn.close()
        meta = os.stat(path)
        baseline = {"q_device": str(meta.st_dev), "q_inode": str(meta.st_ino),
                    "grants": 0, "grant_body_bytes": 0, "attempts": 0}
        self.assertEqual(witness.ledger_growth(path, baseline), 1)
        with self.assertRaisesRegex(witness.WitnessError, "ledger_growth"):
            witness.ledger_growth(path, {**baseline, "attempts": -4000})
        with patch.object(witness, "MAX_NEW_GRANTS", 2):
            with self.assertRaisesRegex(witness.WitnessError, "ledger_growth"):
                witness.ledger_growth(path, baseline, reserve_grants=2)
        with patch.object(witness, "MAX_NEW_GRANT_BODY_BYTES", 32768):
            with self.assertRaisesRegex(witness.WitnessError, "ledger_growth"):
                witness.ledger_growth(path, baseline, reserve_grants=1)

    def test_cleanup_requires_durable_revoked_row(self):
        path = str(Path(self.temporary.name) / "revocation.db")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE query_grants(run_id TEXT,revoked INTEGER)")
        conn.execute("INSERT INTO query_grants VALUES('run',0)")
        conn.commit()
        meta = os.stat(path)
        baseline = {"q_device": str(meta.st_dev), "q_inode": str(meta.st_ino)}
        self.assertFalse(witness.ledger_revoked(path, baseline, ["run"]))
        conn.execute("UPDATE query_grants SET revoked=1")
        conn.commit()
        self.assertTrue(witness.ledger_revoked(path, baseline, ["run"]))
        self.assertFalse(witness.ledger_revoked(path, baseline, ["missing"]))
        conn.close()

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

    def test_exact_q_retention_and_running_m_identity(self):
        qpath = str(Path(self.temporary.name) / "q-binding.db")
        q = sqlite3.connect(qpath)
        q.executescript("CREATE TABLE query_manager_cursor(singleton INTEGER,network TEXT,device TEXT,inode TEXT,watermark INTEGER);"
                        "CREATE TABLE query_evidence(evidence_id TEXT,store_seq INTEGER);"
                        "CREATE TABLE query_grants(run_id TEXT,body BLOB);"
                        "CREATE TABLE query_origins(origin_id TEXT,manager_seq INTEGER,body BLOB);"
                        "CREATE TABLE query_projection_origin(query_evidence_id TEXT,origin_id TEXT);")
        m_meta = os.stat(self.db)
        q_meta = os.stat(qpath)
        q.execute("INSERT INTO query_manager_cursor VALUES(1,?,?,?,1)",
                  ("network", str(m_meta.st_dev), str(m_meta.st_ino)))
        q.execute("INSERT INTO query_evidence VALUES(?,1)", ("b" * 64,))
        q.execute("INSERT INTO query_grants VALUES(?,?)", ("run", json.dumps({
            "run_id": "run", "network_id": "network", "nodes": ["validator1"],
            "scopes": ["node"], "watermark": 1, "manager_watermark": 1}).encode()))
        q.execute("INSERT INTO query_origins VALUES(?,?,?)", (self.parent_id, 1, json.dumps({
            "store_seq": "1", "evidence_id": self.parent_id, "evidence": self.parent},
            separators=(",", ":")).encode()))
        q.execute("INSERT INTO query_projection_origin VALUES(?,?)", ("b" * 64, self.parent_id))
        q.commit()
        baseline = {"q_device": str(q_meta.st_dev), "q_inode": str(q_meta.st_ino)}
        with patch.object(witness, "process_owns_db"):
            witness.verify_retained_binding(self.envelope, "run", qpath, self.db, baseline, 123)
            wrong_run = {**self.envelope, "run_id": "different-run"}
            with self.assertRaisesRegex(witness.WitnessError, "frozen_grant_binding"):
                witness.verify_retained_binding(wrong_run, "run", qpath, self.db, baseline, 123)
            q.execute("UPDATE query_grants SET body=json_set(body,'$.manager_watermark',0)")
            q.commit()
            with self.assertRaisesRegex(witness.WitnessError, "frozen_grant_binding"):
                witness.verify_retained_binding(self.envelope, "run", qpath, self.db, baseline, 123)
            q.execute("UPDATE query_grants SET body=json_set(body,'$.manager_watermark',1)")
            q.execute("UPDATE query_evidence SET store_seq=2")
            q.commit()
            with self.assertRaisesRegex(witness.WitnessError, "retained_source_identity"):
                witness.verify_retained_binding(self.envelope, "run", qpath, self.db, baseline, 123)
            q.execute("UPDATE query_evidence SET store_seq=1")
            q.commit()
            with closing(sqlite3.connect(self.db)) as m_above:
                m_above.execute("INSERT INTO observations SELECT 2,content_hash,node,scope,process_epoch,"
                                "source_epoch,source,body FROM observations WHERE store_seq=1")
                m_above.commit()
            q.execute("UPDATE query_origins SET manager_seq=2,body=?", (json.dumps({
                "store_seq": "2", "evidence_id": self.parent_id, "evidence": self.parent},
                separators=(",", ":")).encode(),))
            q.execute("UPDATE query_manager_cursor SET watermark=2")
            q.commit()
            with self.assertRaisesRegex(witness.WitnessError, "retained_source_identity"):
                witness.verify_retained_binding(self.envelope, "run", qpath, self.db, baseline, 123)
            q.execute("UPDATE query_origins SET manager_seq=1,body=?", (json.dumps({
                "store_seq": "1", "evidence_id": self.parent_id, "evidence": self.parent},
                separators=(",", ":")).encode(),))
            q.execute("DELETE FROM query_projection_origin")
            q.commit()
            with self.assertRaisesRegex(witness.WitnessError, "retained_binding_missing"):
                witness.verify_retained_binding(self.envelope, "run", qpath, self.db, baseline, 123)
            q.execute("INSERT INTO query_projection_origin VALUES(?,?)", ("b" * 64, self.parent_id))
            q.commit()
            q.execute("UPDATE query_origins SET body=?", (b"{}",))
            q.commit()
            with self.assertRaisesRegex(witness.WitnessError, "retained_parent_changed"):
                witness.verify_retained_binding(self.envelope, "run", qpath, self.db, baseline, 123)
            q.execute("UPDATE query_origins SET body=?", (json.dumps({
                "store_seq": "1", "evidence_id": self.parent_id, "evidence": self.parent},
                separators=(",", ":")).encode(),))
            q.commit()
            m = sqlite3.connect(self.db)
            m.execute("UPDATE observations SET process_epoch='other'")
            m.commit()
            with self.assertRaisesRegex(witness.WitnessError, "retained_source_tuple"):
                witness.verify_retained_binding(self.envelope, "run", qpath, self.db, baseline, 123)
            m.execute("UPDATE observations SET process_epoch='epoch-1'")
            changed = json.loads(json.dumps(self.parent))
            changed["record"]["payload"]["source"]["payload"]["pid"] = 43
            m.execute("UPDATE observations SET body=?", (json.dumps(changed),))
            m.commit()
            with self.assertRaisesRegex(witness.WitnessError, "parent_hash"):
                witness.verify_retained_binding(self.envelope, "run", qpath, self.db, baseline, 123)
            m.execute("UPDATE observations SET body=?", (json.dumps(self.parent),))
            m.execute("INSERT INTO quarantined VALUES(?,?,?,?,?)",
                      ("validator1", "node", "epoch-1", "source-1", "process"))
            m.commit()
            with self.assertRaisesRegex(witness.WitnessError, "retained_parent_quarantined"):
                witness.verify_retained_binding(self.envelope, "run", qpath, self.db, baseline, 123)
            m.execute("DELETE FROM quarantined")
            m.commit()
            m.close()
            q.execute("UPDATE query_manager_cursor SET inode='0'")
            q.commit()
            with self.assertRaisesRegex(witness.WitnessError, "retained_source_identity"):
                witness.verify_retained_binding(self.envelope, "run", qpath, self.db, baseline, 123)
        q.close()

    def test_frozen_baseline_digest_and_budget(self):
        path = Path(self.temporary.name) / "baseline.json"
        value = {"schema_version": 1, "q_device": "1", "q_inode": "2", "grants": 3,
                 "grant_body_bytes": 100, "attempts": 5, "query_sha256": "a" * 64,
                 "max_new_grants": witness.MAX_NEW_GRANTS,
                 "max_new_grant_body_bytes": witness.MAX_NEW_GRANT_BODY_BYTES,
                 "max_new_attempts": witness.MAX_NEW_ATTEMPTS}
        raw = json.dumps(value).encode()
        path.write_bytes(raw)
        path.chmod(0o600)
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(witness.frozen_baseline(path, digest, "a" * 64)["grants"], 3)
        with self.assertRaisesRegex(witness.WitnessError, "baseline_digest"):
            witness.frozen_baseline(path, "0" * 64, "a" * 64)

    def test_projection_head_is_independent_and_rejects_false_caught_up(self):
        value = {"schema_version": 1, "projection_status": "lagging",
                 "manager_conflicted": False, "caught_up_at_last_import": True,
                 "source_identity_match": True, "cursor_global_m_seq": "10",
                 "source_global_m_seq": "11", "lag_global_m_seq": "1"}
        with patch.object(witness, "control", return_value=(200, {"content-type": "application/json"},
                                                             json.dumps(value).encode())):
            self.assertEqual(witness.projection_head("socket", "service"), "lagging")
        value["projection_status"] = "caught_up"
        with patch.object(witness, "control", return_value=(200, {"content-type": "application/json"},
                                                             json.dumps(value).encode())):
            with self.assertRaisesRegex(witness.WitnessError, "projection_false_caught_up"):
                witness.projection_head("socket", "service")

    def test_fixed_query_success_recorded_separately_from_lagging_head(self):
        log = Path(self.temporary.name) / "separate.jsonl"
        args = SimpleNamespace(log_file=str(log), operator_token_file="operator", service_token_file="service",
                               query_unit="query", expected_query_sha256="a" * 64, control_socket="control",
                               mcp_socket="mcp", m_db=self.db, q_ledger="q",
                               baseline_file="baseline", expected_baseline_sha256="c" * 64)
        run = "11111111-1111-4111-8111-111111111111"
        def fake_issue(_socket, _token, _node, _start, _end, leases):
            leases.append(run)
            return run, "a" * 64
        class FakeSession:
            def __init__(self, *_args): pass
            def initialize(self): pass
            def snapshot(self, *_args): return self_envelope
            def close(self): pass
        self_envelope = self.envelope
        with patch.object(witness.time, "time", return_value=301), \
             patch.object(witness, "private_token", return_value="secret"), \
             patch.object(witness, "bound_service", return_value=123), \
             patch.object(witness, "frozen_baseline", return_value={}), \
             patch.object(witness, "ledger_growth", return_value=1), \
             patch.object(witness, "projection_head", return_value="lagging") as head_probe, \
             patch.object(witness, "issue", side_effect=fake_issue), \
             patch.object(witness, "McpSession", FakeSession), \
             patch.object(witness, "validate_process"), \
             patch.object(witness, "verify_retained_binding"), \
             patch.object(witness, "ledger_revoked", return_value=True), \
             patch.object(witness, "revoke", return_value=True):
            self.assertEqual(witness.run(args), 0)
            args.log_file = str(Path(self.temporary.name) / "probe-timeout.jsonl")
            head_probe.side_effect = TimeoutError("head call deadline")
            self.assertEqual(witness.run(args), 1)
        timeout_row = json.loads(Path(args.log_file).read_text().strip())
        self.assertEqual(timeout_row["fixed_grant_query_status"], "pass")
        self.assertEqual(timeout_row["projection_head_status"], "probe_failed")
        row = json.loads(log.read_text().strip())
        self.assertEqual(row["fixed_grant_query_status"], "pass")
        self.assertEqual(row["projection_head_status"], "lagging")
        self.assertEqual(row["status"], "pass")

    def test_timeout_after_grant_attempts_revoke_and_logs_failure(self):
        log = Path(self.temporary.name) / "samples.jsonl"
        args = SimpleNamespace(log_file=str(log), operator_token_file="operator", service_token_file="service",
                               query_unit="query", expected_query_sha256="a" * 64, control_socket="control",
                               mcp_socket="mcp", m_db=self.db, q_ledger="q",
                               baseline_file="baseline", expected_baseline_sha256="c" * 64)
        run = "11111111-1111-4111-8111-111111111111"
        def timeout_issue(_socket, _token, _node, _start, _end, leases):
            leases.append(run)
            raise TimeoutError("injected")
        with patch.object(witness, "private_token", return_value="secret"), \
             patch.object(witness, "bound_service", return_value=123), \
             patch.object(witness, "frozen_baseline", return_value={}), \
             patch.object(witness, "ledger_growth", return_value=1), \
             patch.object(witness, "projection_head", return_value="caught_up"), \
             patch.object(witness, "issue", side_effect=timeout_issue), \
             patch.object(witness, "ledger_revoked", return_value=True), \
             patch.object(witness, "revoke", return_value=True) as revoke:
            self.assertEqual(witness.run(args), 1)
        revoke.assert_called_once_with("control", "secret", run)
        row = json.loads(log.read_text().strip())
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["error_kind"], "TimeoutError")
        self.assertTrue(row["cleanup_confirmed"])
        self.assertNotIn(run, log.read_text())

    def test_unconfirmed_cleanup_is_failed(self):
        log = Path(self.temporary.name) / "cleanup.jsonl"
        args = SimpleNamespace(log_file=str(log), operator_token_file="operator", service_token_file="service",
                               query_unit="query", expected_query_sha256="a" * 64, control_socket="control",
                               mcp_socket="mcp", m_db=self.db, q_ledger="q",
                               baseline_file="baseline", expected_baseline_sha256="c" * 64)
        def timeout_issue(_socket, _token, _node, _start, _end, leases):
            leases.append("11111111-1111-4111-8111-111111111111")
            raise TimeoutError("injected")
        with patch.object(witness, "private_token", return_value="secret"), \
             patch.object(witness, "bound_service", return_value=123), \
             patch.object(witness, "frozen_baseline", return_value={}), \
             patch.object(witness, "ledger_growth", return_value=1), \
             patch.object(witness, "projection_head", return_value="caught_up"), \
             patch.object(witness, "issue", side_effect=timeout_issue), \
             patch.object(witness, "revoke", return_value=False):
            self.assertEqual(witness.run(args), 1)
        row = json.loads(log.read_text().strip())
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["error_kind"], "cleanup_unconfirmed")
        self.assertFalse(row["cleanup_confirmed"])

    def test_boottime_spacing_refuses_new_grant(self):
        log = Path(self.temporary.name) / "spacing.jsonl"
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        slot = int(time.time()) // witness.SLOT_SECONDS
        log.write_text(json.dumps({"slot": slot - 1, "boot_id": boot,
                                   "boottime_ns": time.clock_gettime_ns(time.CLOCK_BOOTTIME) - 100_000_000_000}) + "\n")
        log.chmod(0o600)
        args = SimpleNamespace(log_file=str(log), control_socket="control")
        with patch.object(witness, "issue") as issue:
            self.assertEqual(witness.run(args), 1)
        issue.assert_not_called()
        self.assertEqual(json.loads(log.read_text().splitlines()[-1])["error_kind"], "sample_too_soon")

    def test_wall_slot_rollback_refuses_new_grant(self):
        log = Path(self.temporary.name) / "rollback.jsonl"
        slot = int(time.time()) // witness.SLOT_SECONDS
        log.write_text(json.dumps({"slot": slot + 1, "boot_id": "previous-boot", "boottime_ns": 0}) + "\n")
        log.chmod(0o600)
        with patch.object(witness, "issue") as issue:
            self.assertEqual(witness.run(SimpleNamespace(log_file=str(log))), 1)
        issue.assert_not_called()
        first = json.loads(log.read_text().splitlines()[-1])
        self.assertEqual((first["error_kind"], first["slot_highwater"]), ("slot_not_advanced", slot + 1))
        with patch.object(witness, "issue") as issue:
            self.assertEqual(witness.run(SimpleNamespace(log_file=str(log))), 1)
        issue.assert_not_called()
        self.assertEqual(json.loads(log.read_text().splitlines()[-1])["slot_highwater"], slot + 1)


if __name__ == "__main__":
    unittest.main()
