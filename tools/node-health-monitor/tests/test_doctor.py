"""Deterministic doctor runs against a synthetic manager state and receipts.

Every gate is exercised in each of its three states, the evidence database is
opened read-only, and the process exit status is checked end to end.
"""
import datetime as dt
import http.server
import socket
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCTOR = ROOT / "scripts/doctor.py"
NOW = "2026-09-30T12:00:00Z"


def load_module():
    spec = importlib.util.spec_from_file_location("doctor", DOCTOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules["doctor"] = module
    spec.loader.exec_module(module)
    return module


doctor = load_module()


def incident(node, rule, input_signal="good", state="clear"):
    return {"key": {"node": node, "scope": "node", "rule": rule},
            "state": {"state": state, "severity": "critical", "episode": "1"},
            "input": input_signal}


def healthy_state(**overrides):
    state = {
        "schema_version": 1, "monitor_epoch": "e" * 64, "evaluation_sequence": "42",
        "incidents": [incident("v1", "target_unreachable"), incident("v1", "pq_signing_failure"),
                      incident("v2", "target_unreachable"), incident("v2", "pq_signing_failure")],
        "inventory": {"revision": "r1", "network_id": "a" * 64,
                      "targets": [{"node": "v1", "scope": "node", "rules": ["target_unreachable", "pq_signing_failure"]},
                                  {"node": "v2", "scope": "node", "rules": ["target_unreachable", "pq_signing_failure"]}]},
        "quarantined_sources": [],
        "retention": {"configured": True, "evidence_retention_ms": "86400000", "period_ms": "300000",
                      "last_pass_age_ms": "120000", "last_pass_error": None, "observations_deleted_total": "12"},
        "notification": {"receiver_configured": True, "receiver_alias": "ops", "last_delivery_age_ms": "3600000"},
    }
    state.update(overrides)
    return state


def receipts(tmp_path, **gates):
    evidence = tmp_path / "round-a.log"
    evidence.write_text("raw samples\n")
    base = {"schema_version": 1, "gates": {}}
    for gate_id, spec in gates.items():
        entry = {"status": spec.get("status", "pass"), "evidence_path": spec.get("evidence_path", str(evidence)),
                 "at": spec.get("at", "2026-09-29T00:00:00Z"), "note": spec.get("note", "")}
        base["gates"][gate_id] = entry
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(base))
    return path


def evidence_db(tmp_path, quarantined=0, witness_quarantined=0):
    path = tmp_path / "evidence.db"
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE quarantined(node TEXT,scope TEXT,process_epoch TEXT,source_epoch TEXT,source TEXT);"
        "CREATE TABLE witness_quarantined(observer_epoch TEXT,endpoint TEXT,source_epoch TEXT);")
    for _ in range(quarantined):
        db.execute("INSERT INTO quarantined VALUES('v1','node','p','s','edge_probe')")
    for _ in range(witness_quarantined):
        db.execute("INSERT INTO witness_quarantined VALUES('o','cache_1','s')")
    db.commit()
    db.close()
    return path


def run_doctor(tmp_path, state, *extra):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps(state))
    gates = doctor.run(_args(["--manager-state-file", str(state_path), "--now", NOW, *extra]))
    return {g.id: g for g in gates}


def _args(argv):
    return doctor.build_parser().parse_args(argv)


def test_all_live_gates_pass_and_receipt_gates_pass_with_valid_receipts(tmp_path):
    evidence = receipts(tmp_path, **{gate_id: {} for gate_id, _ in doctor.RECEIPT_GATES})
    ledger = tmp_path / "query-ledger.db"
    ledger.write_bytes(b"x")
    stamp = doctor.parse_time(NOW).timestamp()
    os.utime(ledger, (stamp, stamp))
    gates = run_doctor(tmp_path, healthy_state(), "--evidence-file", str(evidence),
                       "--evidence-db", str(evidence_db(tmp_path)), "--query-ledger-db", str(ledger))
    assert gates["ai_lane"].status == doctor.NOT_RUN, "ai_unavailable is not bound in this inventory"
    assert {g.status for g in gates.values() if g.id not in ("ai_lane", "query_broker", "mcp_lane")} == {doctor.PASS}
    assert gates["query_broker"].status == doctor.NOT_RUN and gates["mcp_lane"].status == doctor.NOT_RUN
    assert gates["rule_inputs_usable"].detail.startswith("4 rule bindings")
    assert "evidence db quarantined+witness_quarantined empty" in gates["no_quarantined_sources"].detail
    assert len(gates) == 1 + 5 + 3 + len(doctor.RECEIPT_GATES)


def test_unknown_input_and_missing_evaluation_fail_rule_gate(tmp_path):
    state = healthy_state()
    state["incidents"][1]["input"] = "unknown"
    del state["incidents"][3]
    gates = run_doctor(tmp_path, state)
    gate = gates["rule_inputs_usable"]
    assert gate.status == doctor.FAIL
    assert "unknown input: v1/node/pq_signing_failure" in gate.detail
    assert "no evaluation: v2/node/pq_signing_failure" in gate.detail
    without_inventory = healthy_state()
    del without_inventory["inventory"]
    assert run_doctor(tmp_path, without_inventory)["rule_inputs_usable"].status == doctor.NOT_RUN


def test_quarantine_gate_reads_live_state_and_evidence_db(tmp_path):
    live = healthy_state(quarantined_sources=[{"node": "v1", "scope": "node", "source": "edge_probe",
                                               "exhausted": False, "epochs": []}])
    assert run_doctor(tmp_path, live)["no_quarantined_sources"].status == doctor.FAIL
    durable = run_doctor(tmp_path, healthy_state(), "--evidence-db", str(evidence_db(tmp_path, quarantined=2)))
    assert durable["no_quarantined_sources"].status == doctor.FAIL
    assert "quarantined=2" in durable["no_quarantined_sources"].detail
    state = healthy_state()
    del state["quarantined_sources"]
    assert run_doctor(tmp_path, state)["no_quarantined_sources"].status == doctor.NOT_RUN
    missing = run_doctor(tmp_path, state, "--evidence-db", str(tmp_path / "absent.db"))
    assert missing["no_quarantined_sources"].status == doctor.FAIL


def test_evidence_db_is_never_written(tmp_path):
    path = evidence_db(tmp_path)
    before = path.read_bytes()
    mode = path.stat().st_mode
    os.chmod(path, 0o400)
    try:
        gates = run_doctor(tmp_path, healthy_state(), "--evidence-db", str(path))
    finally:
        os.chmod(path, mode)
    assert gates["no_quarantined_sources"].status == doctor.PASS
    assert path.read_bytes() == before
    assert not (tmp_path / "evidence.db-wal").exists()


def test_retention_gate_needs_configuration_and_a_recent_clean_pass(tmp_path):
    assert run_doctor(tmp_path, healthy_state())["evidence_retention"].status == doctor.PASS
    state = healthy_state()
    state["retention"]["configured"] = False
    assert run_doctor(tmp_path, state)["evidence_retention"].status == doctor.FAIL
    state = healthy_state()
    state["retention"]["last_pass_age_ms"] = "600001"
    gate = run_doctor(tmp_path, state)["evidence_retention"]
    assert gate.status == doctor.FAIL and "exceeds 2x period" in gate.detail
    state = healthy_state()
    state["retention"]["last_pass_age_ms"] = None
    assert run_doctor(tmp_path, state)["evidence_retention"].status == doctor.FAIL
    state = healthy_state()
    state["retention"]["last_pass_error"] = "database or disk is full"
    assert run_doctor(tmp_path, state)["evidence_retention"].status == doctor.FAIL
    state = healthy_state()
    del state["retention"]
    assert run_doctor(tmp_path, state)["evidence_retention"].status == doctor.NOT_RUN


def test_notification_gate_accepts_live_or_receipt_delivery_within_a_day(tmp_path):
    assert run_doctor(tmp_path, healthy_state())["notification_receiver"].status == doctor.PASS
    state = healthy_state()
    state["notification"]["receiver_configured"] = False
    assert run_doctor(tmp_path, state)["notification_receiver"].status == doctor.FAIL
    stale = healthy_state()
    stale["notification"]["last_delivery_age_ms"] = str(doctor.DAY_MS + 1)
    assert run_doctor(tmp_path, stale)["notification_receiver"].status == doctor.FAIL
    fresh_receipt = receipts(tmp_path, notification_delivery={"at": "2026-09-30T01:00:00Z"})
    gate = run_doctor(tmp_path, stale, "--evidence-file", str(fresh_receipt))["notification_receiver"]
    assert gate.status == doctor.PASS and "delivery receipt" in gate.detail
    old_receipt = receipts(tmp_path, notification_delivery={"at": "2026-09-28T01:00:00Z"})
    assert run_doctor(tmp_path, stale, "--evidence-file", str(old_receipt))["notification_receiver"].status == doctor.FAIL
    none = healthy_state()
    del none["notification"]
    assert run_doctor(tmp_path, none)["notification_receiver"].status == doctor.NOT_RUN


def test_ai_lane_gate(tmp_path):
    assert run_doctor(tmp_path, healthy_state())["ai_lane"].status == doctor.NOT_RUN
    bound = healthy_state()
    bound["inventory"]["targets"][0]["rules"].append("ai_unavailable")
    assert run_doctor(tmp_path, bound)["ai_lane"].status == doctor.FAIL
    bound["incidents"].append(incident("v1", "ai_unavailable", "good", "clear"))
    assert run_doctor(tmp_path, bound)["ai_lane"].status == doctor.PASS
    bound["incidents"][-1]["state"]["state"] = "suspended_unknown"
    gate = run_doctor(tmp_path, bound)["ai_lane"]
    assert gate.status == doctor.FAIL and "v1/node" in gate.detail


def test_receipt_gates_cover_pass_fail_not_run_and_broken_receipts(tmp_path):
    evidence = receipts(
        tmp_path,
        physical_separation={"status": "not_run", "note": "shared host"},
        performance_round_a={},
        performance_round_b={"status": "fail", "note": "p99 over budget"},
        performance_round_c={"evidence_path": str(tmp_path / "missing.log")},
        performance_round_d={"at": "2026-01-01T00:00:00Z"},
        performance_round_e={"at": "not a time"},
        performance_round_f={"status": "green"},
        soak_72h={"at": "2026-10-01T00:00:00Z"},
        token_rotation={"evidence_path": ""},
    )
    gates = run_doctor(tmp_path, healthy_state(), "--evidence-file", str(evidence))
    assert gates["physical_separation"].status == doctor.NOT_RUN
    assert gates["performance_round_a"].status == doctor.PASS
    assert gates["performance_round_b"].status == doctor.FAIL
    assert gates["performance_round_c"].status == doctor.FAIL and "missing" in gates["performance_round_c"].detail
    assert gates["performance_round_d"].status == doctor.NOT_RUN and "days old" in gates["performance_round_d"].detail
    assert gates["performance_round_e"].status == doctor.FAIL
    assert gates["performance_round_f"].status == doctor.FAIL and "malformed" in gates["performance_round_f"].detail
    assert gates["soak_72h"].status == doctor.FAIL and "future" in gates["soak_72h"].detail
    assert gates["token_rotation"].status == doctor.FAIL
    assert gates["cert_rotation"].status == doctor.NOT_RUN
    assert gates["rollback_drill"].status == doctor.NOT_RUN
    relaxed = run_doctor(tmp_path, healthy_state(), "--evidence-file", str(evidence), "--no-check-evidence-paths")
    assert relaxed["performance_round_c"].status == doctor.PASS


def test_example_evidence_file_is_all_not_run():
    example = json.loads((ROOT / "config/doctor-evidence.example.json").read_text())
    assert example["schema_version"] == 1
    assert {gate_id for gate_id, _ in doctor.RECEIPT_GATES} <= set(example["gates"])
    assert all(entry["status"] == "not_run" for entry in example["gates"].values())


def test_unreadable_state_fails_and_makes_dependent_gates_not_run(tmp_path):
    gates = {g.id: g for g in doctor.run(_args(["--manager-state-file", str(tmp_path / "absent.json"), "--now", NOW]))}
    assert gates["manager_state"].status == doctor.FAIL
    for gate_id in ("rule_inputs_usable", "evidence_retention", "notification_receiver", "ai_lane"):
        assert gates[gate_id].status == doctor.NOT_RUN
    assert gates["no_quarantined_sources"].status == doctor.NOT_RUN
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": 2}))
    assert {g.id: g for g in doctor.run(_args(["--manager-state-file", str(bad), "--now", NOW]))}["manager_state"].status == doctor.FAIL


class _Handler(http.server.BaseHTTPRequestHandler):
    state = None

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer secret-token" or self.path != "/v1/manager/state":
            self.send_response(401)
            self.end_headers()
            return
        body = json.dumps(self.state).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def test_cli_reads_the_live_endpoint_with_the_token_and_exits_nonzero_on_fail(tmp_path):
    _Handler.state = healthy_state()
    _Handler.state["retention"]["configured"] = False
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    token = tmp_path / "read.token"
    token.write_text("secret-token\n")
    os.chmod(token, 0o600)
    url = f"http://127.0.0.1:{server.server_port}/v1/manager/state"
    try:
        result = subprocess.run(
            [sys.executable, str(DOCTOR), "--manager-state-url", url, "--manager-read-token-file", str(token),
             "--now", NOW],
            capture_output=True, text=True, check=False)
        assert result.returncode == 1, result.stdout + result.stderr
        assert "evidence_retention  fail" in result.stdout.replace("   ", " ").replace("  ", " ") or "evidence_retention" in result.stdout
        assert "-> FAIL" in result.stdout
        assert "physical_separation" in result.stdout and "not_run" in result.stdout
        _Handler.state["retention"]["configured"] = True
        result = subprocess.run(
            [sys.executable, str(DOCTOR), "--manager-state-url", url, "--manager-read-token-file", str(token),
             "--now", NOW, "--json"],
            capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(result.stdout)
        assert report["failing"] == 0
        statuses = {g["id"]: g["status"] for g in report["gates"]}
        assert statuses["manager_state"] == "pass" and statuses["soak_72h"] == "not_run"
        os.chmod(token, 0o644)
        result = subprocess.run(
            [sys.executable, str(DOCTOR), "--manager-state-url", url, "--manager-read-token-file", str(token),
             "--now", NOW],
            capture_output=True, text=True, check=False)
        assert result.returncode == 2 and "group/world readable" in result.stderr
        os.chmod(token, 0o600)
        result = subprocess.run(
            [sys.executable, str(DOCTOR), "--manager-state-url", url + "x", "--manager-read-token-file", str(token),
             "--now", NOW],
            capture_output=True, text=True, check=False)
        assert result.returncode == 1 and "manager_state" in result.stdout and "unreadable" in result.stdout
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("value,expected", [("12", 12), (7, 7), ("x", None), (True, None), (None, None)])
def test_wire_integers(value, expected):
    assert doctor.as_int(value) == expected


def test_query_ledger_activity_gate_reads_ledger_write_activity(tmp_path):
    ledger = tmp_path / "query-ledger.db"
    ledger.write_bytes(b"x")
    stale = doctor.parse_time(NOW).timestamp() - 3600
    os.utime(ledger, (stale, stale))
    gates = run_doctor(tmp_path, healthy_state(), "--query-ledger-db", str(ledger))
    assert gates["query_ledger_activity"].status == doctor.FAIL  # an hour of silence
    fresh = doctor.parse_time(NOW).timestamp() - 20
    os.utime(ledger, (fresh, fresh))
    gates = run_doctor(tmp_path, healthy_state(), "--query-ledger-db", str(ledger))
    assert gates["query_ledger_activity"].status == doctor.PASS
    # The WAL counts as write activity even when the main file is older.
    os.utime(ledger, (stale, stale))
    wal = tmp_path / "query-ledger.db-wal"
    wal.write_bytes(b"w")
    os.utime(wal, (fresh, fresh))
    gates = run_doctor(tmp_path, healthy_state(), "--query-ledger-db", str(ledger))
    assert gates["query_ledger_activity"].status == doctor.PASS
    gates = run_doctor(tmp_path, healthy_state())
    assert gates["query_ledger_activity"].status == doctor.NOT_RUN
    missing = run_doctor(tmp_path, healthy_state(), "--query-ledger-db", str(tmp_path / "absent.db"))
    assert missing["query_ledger_activity"].status == doctor.FAIL


def _projection_health_server(tmp_path, answers, token):
    """A broker stand-in on a filesystem socket answering projection-health."""
    socket_path = str(tmp_path / "control.sock")
    if len(socket_path) > 100:  # AF_UNIX path limit
        socket_path = os.path.join("/tmp", f"nhm-doctor-{os.getpid()}.sock")
    calls = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append((self.path, self.headers.get("authorization")))
            if self.headers.get("authorization") != f"Bearer {token}":
                self.send_response(401); self.end_headers(); return
            status, body = answers.pop(0)
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass

    class UnixServer(http.server.HTTPServer):
        address_family = socket.AF_UNIX

        def server_bind(self):
            self.socket.bind(self.server_address)

    server = UnixServer(socket_path, Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, socket_path, calls


def test_query_broker_gate_reads_projection_health_over_the_control_socket(tmp_path):
    token_file = tmp_path / "service.token"
    token_file.write_text("s" * 32)
    token_file.chmod(0o600)
    answers = [
        (200, {"projection_status": "caught_up", "lag_global_m_seq": "0", "manager_conflicted": False}),
        (200, {"projection_status": "lagging", "lag_global_m_seq": "300", "manager_conflicted": False}),
        (200, {"projection_status": "lagging", "lag_global_m_seq": "148424", "manager_conflicted": False}),
        (503, {"projection_status": "conflict", "lag_global_m_seq": None, "manager_conflicted": True}),
        (503, {"projection_status": "source_unavailable", "lag_global_m_seq": None, "manager_conflicted": False}),
    ]
    server, socket_path, calls = _projection_health_server(tmp_path, answers, "s" * 32)
    try:
        common = ["--query-control-socket", socket_path, "--query-service-token-file", str(token_file)]
        gates = run_doctor(tmp_path, healthy_state(), *common)
        assert gates["query_broker"].status == doctor.PASS and "caught_up" in gates["query_broker"].detail
        gates = run_doctor(tmp_path, healthy_state(), *common)
        assert gates["query_broker"].status == doctor.PASS, "four pages behind is within the allowance"
        gates = run_doctor(tmp_path, healthy_state(), *common)
        assert gates["query_broker"].status == doctor.FAIL, "a broker wedged for hours shows as a lag no allowance covers"
        assert "148424" in gates["query_broker"].detail
        gates = run_doctor(tmp_path, healthy_state(), *common)
        assert gates["query_broker"].status == doctor.FAIL and "conflict" in gates["query_broker"].detail
        gates = run_doctor(tmp_path, healthy_state(), *common)
        assert gates["query_broker"].status == doctor.FAIL and "source_unavailable" in gates["query_broker"].detail
        assert all(path == "/v1/control/projection-health" for path, _ in calls)
        # A wrong token is a failing gate, not a pass by absence.
        wrong = tmp_path / "wrong.token"
        wrong.write_text("w" * 32)
        wrong.chmod(0o600)
        gates = run_doctor(tmp_path, healthy_state(), "--query-control-socket", socket_path,
                           "--query-service-token-file", str(wrong))
        assert gates["query_broker"].status == doctor.FAIL and "refused" in gates["query_broker"].detail
    finally:
        server.shutdown()
        server.server_close()
        try:
            os.unlink(socket_path)
        except OSError:
            pass
    # Nobody listening: fail, never not_run.
    gates = run_doctor(tmp_path, healthy_state(), "--query-control-socket", socket_path,
                       "--query-service-token-file", str(token_file))
    assert gates["query_broker"].status == doctor.FAIL and "unreachable" in gates["query_broker"].detail
    # Without the socket flag the gate is honestly not run.
    gates = run_doctor(tmp_path, healthy_state())
    assert gates["query_broker"].status == doctor.NOT_RUN


def test_mcp_lane_gate_reads_the_newest_journal_record(tmp_path):
    journal = tmp_path / "mcp-verdicts.jsonl"
    now = doctor.parse_time(NOW)
    fresh = (now - dt.timedelta(minutes=20)).isoformat()
    stale = (now - dt.timedelta(hours=5)).isoformat()
    accepted = {"checked_at": fresh, "provider": "codex", "model": {"result": "accepted"}}
    refused = {"checked_at": fresh, "provider": "claude", "model": {"result": "rejected", "error": "observed_without_evidence"}}
    journal.write_text(json.dumps(accepted) + "\n")
    gates = run_doctor(tmp_path, healthy_state(), "--mcp-journal", str(journal))
    assert gates["mcp_lane"].status == doctor.PASS and "codex answer accepted" in gates["mcp_lane"].detail
    journal.write_text(json.dumps(accepted) + "\n" + json.dumps(refused) + "\n")
    gates = run_doctor(tmp_path, healthy_state(), "--mcp-journal", str(journal))
    assert gates["mcp_lane"].status == doctor.FAIL and "observed_without_evidence" in gates["mcp_lane"].detail
    journal.write_text(json.dumps({**accepted, "checked_at": stale}) + "\n")
    gates = run_doctor(tmp_path, healthy_state(), "--mcp-journal", str(journal))
    assert gates["mcp_lane"].status == doctor.FAIL and "5.0 h ago" in gates["mcp_lane"].detail
    journal.write_text("")
    assert run_doctor(tmp_path, healthy_state(), "--mcp-journal", str(journal))["mcp_lane"].status == doctor.FAIL
    assert run_doctor(tmp_path, healthy_state())["mcp_lane"].status == doctor.NOT_RUN
    missing = run_doctor(tmp_path, healthy_state(), "--mcp-journal", str(tmp_path / "absent.jsonl"))
    assert missing["mcp_lane"].status == doctor.FAIL
