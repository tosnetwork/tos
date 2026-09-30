"""Deterministic verdict of judge-validator-health.py against a synthetic M state.

The archived native body is the real validator1 loopback fixture wrapped in the
M archive envelope; the parent hash is recomputed the way M stores it.
"""
import hashlib
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "crates/health-core/tests/fixtures/native-core-v2.validator1.live.json"
NET = "b7fba4bda348db54717b7930da7b874289d88642a4d3990fb41d03e0cb006004"


def load_module():
    spec = importlib.util.spec_from_file_location("judge", ROOT / "scripts/judge-validator-health.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["judge"] = module
    spec.loader.exec_module(module)
    return module


def archive_row(native, observed_ms, received_ms):
    record = {
        "node_id": native["node_id"], "scope_id": "node", "source_id": "native_core",
        "source_record_id": f"{native['process_epoch']}:{native['generation']}",
        "process_epoch": native["process_epoch"], "observed_at_ms": observed_ms,
        "received_at_ms": received_ms,
        "quality": {"availability": "available", "coverage": "partial", "observed_at_ms": observed_ms,
                    "last_success_at_ms": observed_ms, "clock_valid": True,
                    "process_epoch": native["process_epoch"], "source_sequence": native["generation"]},
        "payload": {"component": "native", "source": native}, "redacted": True,
    }
    body = {"source_epoch": native["source_epoch"], "record": record}
    hashed = json.loads(json.dumps(body))
    hashed["record"]["received_at_ms"] = 0
    parent = hashlib.sha256(json.dumps(hashed, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return json.dumps(body, separators=(",", ":")), parent


def make_db(path, rows):
    Path(path).unlink(missing_ok=True)
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE observations(store_seq INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT, scope TEXT,"
        " process_epoch TEXT, source_epoch TEXT, source TEXT, source_record TEXT, content_hash TEXT, body BLOB);"
        "CREATE TABLE quarantined(node TEXT, scope TEXT, process_epoch TEXT, source_epoch TEXT, source TEXT);")
    for node, native, body, parent in rows:
        db.execute("INSERT INTO observations(node,scope,process_epoch,source_epoch,source,source_record,content_hash,body)"
                   " VALUES(?,?,?,?,?,?,?,?)",
                   (node, "node", native["process_epoch"], native["source_epoch"], "native_core",
                    f"{native['process_epoch']}:{native['generation']}", parent, body))
    db.commit()
    db.close()


def incident(node, rule, input_, state, severity):
    return {"input": input_, "key": {"node": node, "rule": rule, "scope": "node"},
            "state": {"acknowledged": False, "episode": "1" if state == "open" else "0", "good_count": 0,
                      "good_since": None, "last_good": {}, "last_now": 1, "severity": severity, "state": state}}


def all_good(node, role="validator"):
    rules = list(judge.REACH_RULES) + list(judge.NATIVE_RULES[:4])
    if role == "validator":
        rules += list(judge.NATIVE_RULES[4:])
    return [incident(node, r, "good", "clear", "unknown") for r in rules]


judge = load_module()


def run_judge(tmp_path, incidents, rows, monkeypatch, nodes=None):
    db = tmp_path / "evidence.db"
    make_db(db, rows)
    nodes_file = tmp_path / "nodes.json"
    nodes_file.write_text(json.dumps(nodes or {"validator1": "validator"}))
    token = tmp_path / "read.token"
    token.write_text("t" * 32)
    token.chmod(0o600)
    monkeypatch.setattr(judge, "manager_state", lambda url, tok: {"evaluation_sequence": "7", "incidents": incidents})

    class Args:
        network_id = NET
        manager_state_url = "http://127.0.0.1:1/v1/manager/state"
        manager_read_token_file = str(token)
        evidence_db = str(db)
    Args.nodes_file = str(nodes_file)
    return judge.judge(Args)


def fresh_native(observed_ms):
    native = json.loads(FIXTURE.read_text())
    native["observed_at"] = judge.dt.datetime.fromtimestamp(observed_ms / 1000, judge.dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return native


def test_all_rules_good_and_fresh_native_is_healthy(tmp_path, monkeypatch):
    now_ms = int(judge.utc_now().timestamp() * 1000)
    native = fresh_native(now_ms - 10_000)
    body, parent = archive_row(native, now_ms - 10_000, now_ms - 9_000)
    report = run_judge(tmp_path, all_good("validator1"), [("validator1", native, body, parent)], monkeypatch)
    node = report["nodes"]["validator1"]
    assert node["verdict"] == "healthy", node["reasons"]
    assert node["native"]["archive_parent"] == parent
    assert node["native"]["sessions_active"] == 4
    assert report["evidence_ids"] == [parent]
    assert report["summary"]["healthy"] == ["validator1"]


def test_open_critical_incident_is_unhealthy_and_named(tmp_path, monkeypatch):
    now_ms = int(judge.utc_now().timestamp() * 1000)
    native = fresh_native(now_ms - 10_000)
    body, parent = archive_row(native, now_ms - 10_000, now_ms - 9_000)
    incidents = [i for i in all_good("validator1") if i["key"]["rule"] != "local_chain_stalled"]
    incidents.append(incident("validator1", "local_chain_stalled", "bad", "open", "critical"))
    report = run_judge(tmp_path, incidents, [("validator1", native, body, parent)], monkeypatch)
    node = report["nodes"]["validator1"]
    assert node["verdict"] == "unhealthy"
    assert node["reasons"] == ["local_chain_stalled"]


def test_open_warning_is_degraded_but_critical_wins(tmp_path, monkeypatch):
    now_ms = int(judge.utc_now().timestamp() * 1000)
    native = fresh_native(now_ms - 10_000)
    body, parent = archive_row(native, now_ms - 10_000, now_ms - 9_000)
    incidents = [i for i in all_good("validator1") if i["key"]["rule"] != "local_action_overdue"]
    incidents.append(incident("validator1", "local_action_overdue", "bad", "open", "warning"))
    report = run_judge(tmp_path, incidents, [("validator1", native, body, parent)], monkeypatch)
    assert report["nodes"]["validator1"]["verdict"] == "degraded"
    incidents = [i for i in incidents if i["key"]["rule"] != "pq_signing_failure"]
    incidents.append(incident("validator1", "pq_signing_failure", "bad", "open", "critical"))
    report = run_judge(tmp_path, incidents, [("validator1", native, body, parent)], monkeypatch)
    assert report["nodes"]["validator1"]["verdict"] == "unhealthy"


def test_unknown_input_missing_rule_or_stale_native_is_unknown(tmp_path, monkeypatch):
    now_ms = int(judge.utc_now().timestamp() * 1000)
    native = fresh_native(now_ms - 10_000)
    body, parent = archive_row(native, now_ms - 10_000, now_ms - 9_000)
    incidents = [i for i in all_good("validator1") if i["key"]["rule"] != "storage_ack_failure"]
    incidents.append(incident("validator1", "storage_ack_failure", "unknown", "clear", "unknown"))
    report = run_judge(tmp_path, incidents, [("validator1", native, body, parent)], monkeypatch)
    assert report["nodes"]["validator1"]["verdict"] == "unknown"
    assert "rule_input_unknown:storage_ack_failure" in report["nodes"]["validator1"]["reasons"]
    incidents = [i for i in all_good("validator1") if i["key"]["rule"] != "local_action_failure"]
    report = run_judge(tmp_path, incidents, [("validator1", native, body, parent)], monkeypatch)
    assert "rule_not_in_inventory:local_action_failure" in report["nodes"]["validator1"]["reasons"]
    stale = fresh_native(now_ms - 600_000)
    body, parent = archive_row(stale, now_ms - 600_000, now_ms - 599_000)
    report = run_judge(tmp_path, all_good("validator1"), [("validator1", stale, body, parent)], monkeypatch)
    assert report["nodes"]["validator1"]["verdict"] == "unknown"
    assert "native_sample_stale" in report["nodes"]["validator1"]["reasons"]


def test_missing_archive_row_and_tampered_parent_are_refused(tmp_path, monkeypatch):
    report = run_judge(tmp_path, all_good("validator1"), [], monkeypatch)
    assert report["nodes"]["validator1"]["verdict"] == "unknown"
    assert report["nodes"]["validator1"]["reasons"] == ["no_archived_native_sample"]
    now_ms = int(judge.utc_now().timestamp() * 1000)
    native = fresh_native(now_ms - 10_000)
    body, parent = archive_row(native, now_ms - 10_000, now_ms - 9_000)
    tampered = body.replace('"sessions_active"', '"sessions_active"').replace('"active":"4"', '"active":"3"')
    assert tampered != body
    try:
        run_judge(tmp_path, all_good("validator1"), [("validator1", native, tampered, parent)], monkeypatch)
    except ValueError as error:
        assert "parent hash" in str(error)
    else:
        raise AssertionError("tampered archive body accepted")


def test_model_answer_cannot_upgrade_a_verdict(tmp_path, monkeypatch):
    now_ms = int(judge.utc_now().timestamp() * 1000)
    native = fresh_native(now_ms - 10_000)
    body, parent = archive_row(native, now_ms - 10_000, now_ms - 9_000)
    incidents = [i for i in all_good("validator1") if i["key"]["rule"] != "local_chain_stalled"]
    incidents.append(incident("validator1", "local_chain_stalled", "bad", "open", "critical"))
    report = run_judge(tmp_path, incidents, [("validator1", native, body, parent)], monkeypatch)
    schema = ROOT / "contracts/diagnosis.schema.json"

    def fake_run(command, **kwargs):
        class R:
            returncode = 0
            stderr = b""
            stdout = json.dumps({"status": "analysis", "summary": "all good",
                                 "findings": [], "missing_evidence": [], "recommended_runbooks": []}).encode()
        return R()
    monkeypatch.setattr(judge.subprocess, "run", fake_run)

    class Args:
        diagnosis_schema = str(schema)
        codex_bin = "aura"
        codex_socket = "sock"
        codex_workdir = str(tmp_path)
        codex_thread_file = str(tmp_path / "thread")
        model_timeout = 5
    outcome = judge.model_explanation(Args, report)
    assert outcome["result"] == "rejected"
    assert outcome["error"] == "unexplained_non_healthy_nodes"

    def fake_run_cites(command, **kwargs):
        class R:
            returncode = 0
            stderr = b""
            stdout = json.dumps({"status": "analysis", "summary": "validator1 chain stalled",
                                 "findings": [{"claim": "finalized slot has not advanced", "basis": "observed",
                                               "evidence_ids": [parent]}],
                                 "missing_evidence": [], "recommended_runbooks": ["inspect_consensus_queues"]}).encode()
        return R()
    monkeypatch.setattr(judge.subprocess, "run", fake_run_cites)
    assert judge.model_explanation(Args, report)["result"] == "accepted"

    def fake_run_foreign(command, **kwargs):
        class R:
            returncode = 0
            stderr = b""
            stdout = json.dumps({"status": "analysis", "summary": "x",
                                 "findings": [{"claim": "c", "basis": "observed", "evidence_ids": ["f" * 64]}],
                                 "missing_evidence": [], "recommended_runbooks": []}).encode()
        return R()
    monkeypatch.setattr(judge.subprocess, "run", fake_run_foreign)
    assert judge.model_explanation(Args, report)["error"] == "unbound_evidence_id"
