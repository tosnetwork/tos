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
    for row in rows:
        node, native, body, parent = row[:4]
        source = row[4] if len(row) > 4 else "native_core"
        db.execute("INSERT INTO observations(node,scope,process_epoch,source_epoch,source,source_record,content_hash,body)"
                   " VALUES(?,?,?,?,?,?,?,?)",
                   (node, "node", native["process_epoch"], native["source_epoch"], source,
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


def fact_frame_row(native, observed_ms):
    """A rule fact frame archived under the same source id; it is not snapshot evidence."""
    body = {"source_epoch": native["source_epoch"], "record": {
        "node_id": native["node_id"], "scope_id": "node", "source_id": "native_core",
        "source_record_id": f"{native['process_epoch']}:999", "process_epoch": native["process_epoch"],
        "observed_at_ms": observed_ms, "received_at_ms": observed_ms,
        "quality": {"availability": "available", "coverage": "complete", "observed_at_ms": observed_ms,
                    "last_success_at_ms": observed_ms, "clock_valid": True,
                    "process_epoch": native["process_epoch"], "source_sequence": "999"},
        "payload": {"facts": [{"id": "pq_signing_failures", "value": "0"}]}, "redacted": True}}
    hashed = json.loads(json.dumps(body))
    hashed["record"]["received_at_ms"] = 0
    parent = hashlib.sha256(json.dumps(hashed, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return json.dumps(body, separators=(",", ":")), parent


def test_all_rules_good_and_fresh_native_is_healthy(tmp_path, monkeypatch):
    now_ms = int(judge.utc_now().timestamp() * 1000)
    native = fresh_native(now_ms - 10_000)
    body, parent = archive_row(native, now_ms - 10_000, now_ms - 9_000)
    frame_body, frame_parent = fact_frame_row(native, now_ms - 5_000)
    # The newer fact-frame row must be skipped in favour of the archived snapshot.
    report = run_judge(tmp_path, all_good("validator1"),
                       [("validator1", native, body, parent), ("validator1", native, frame_body, frame_parent)], monkeypatch)
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
    # Stale native sample while the process source is still fresh: unknown,
    # not unhealthy (the node is observable, only the native lane is behind).
    stale = fresh_native(now_ms - 600_000)
    body, parent = archive_row(stale, now_ms - 600_000, now_ms - 599_000)
    process_body = json.dumps({"source_epoch": stale["source_epoch"], "record": {
        "node_id": "validator1", "scope_id": "node", "source_id": "process",
        "source_record_id": "p:1", "process_epoch": stale["process_epoch"],
        "observed_at_ms": now_ms - 5_000, "received_at_ms": now_ms - 4_000, "quality": {},
        "payload": {"component": "process", "source": {"payload": {"pid": 1}}}, "redacted": True}})
    report = run_judge(tmp_path, all_good("validator1"),
                       [("validator1", stale, body, parent), ("validator1", stale, process_body, "0" * 64, "process")],
                       monkeypatch)
    assert report["nodes"]["validator1"]["verdict"] == "unknown"
    assert "native_sample_stale" in report["nodes"]["validator1"]["reasons"]


def test_suspended_unknown_keeps_incident_active_and_unobservable_node_is_unhealthy(tmp_path, monkeypatch):
    now_ms = int(judge.utc_now().timestamp() * 1000)
    native = fresh_native(now_ms - 10_000)
    body, parent = archive_row(native, now_ms - 10_000, now_ms - 9_000)
    incidents = [i for i in all_good("validator1") if i["key"]["rule"] != "telemetry_unavailable"]
    incidents.append(incident("validator1", "telemetry_unavailable", "unknown", "suspended_unknown", "warning"))
    report = run_judge(tmp_path, incidents, [("validator1", native, body, parent)], monkeypatch)
    assert report["nodes"]["validator1"]["verdict"] == "degraded"
    assert report["nodes"]["validator1"]["rules"]["telemetry_unavailable"]["state"] == "suspended_unknown"
    # Edge reachable, but no native or process sample for longer than the
    # unobservable bound: the node process is gone, which is unhealthy.
    stale = fresh_native(now_ms - 400_000)
    body, parent = archive_row(stale, now_ms - 400_000, now_ms - 399_000)
    report = run_judge(tmp_path, all_good("validator1"), [("validator1", stale, body, parent)], monkeypatch)
    assert report["nodes"]["validator1"]["verdict"] == "unhealthy"
    assert report["nodes"]["validator1"]["reasons"][0] == "node_process_unobservable"
    # Same staleness while the edge itself is unreachable stays unknown/critical by rule.
    incidents = [i for i in all_good("validator1") if i["key"]["rule"] != "target_unreachable"]
    incidents.append(incident("validator1", "target_unreachable", "bad", "open", "critical"))
    report = run_judge(tmp_path, incidents, [("validator1", stale, body, parent)], monkeypatch)
    assert report["nodes"]["validator1"]["verdict"] == "unhealthy"
    assert report["nodes"]["validator1"]["reasons"][0] == "target_unreachable"


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
    monkeypatch.setattr(judge, "run_bounded", lambda command, stdin, timeout: fake_run(command))

    class Args:
        provider = "codex"
        diagnosis_schema = str(schema)
        codex_bin = "aura"
        codex_socket = "sock"
        codex_home = None
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
    monkeypatch.setattr(judge, "run_bounded", lambda command, stdin, timeout: fake_run_cites(command))
    assert judge.model_explanation(Args, report)["result"] == "accepted"

    def fake_run_foreign(command, **kwargs):
        class R:
            returncode = 0
            stderr = b""
            stdout = json.dumps({"status": "analysis", "summary": "x",
                                 "findings": [{"claim": "c", "basis": "observed", "evidence_ids": ["f" * 64]}],
                                 "missing_evidence": [], "recommended_runbooks": []}).encode()
        return R()
    monkeypatch.setattr(judge, "run_bounded", lambda command, stdin, timeout: fake_run_foreign(command))
    assert judge.model_explanation(Args, report)["error"] == "unbound_evidence_id"


def test_anthropic_provider_sends_key_only_in_header_and_refuses_redirects(tmp_path, monkeypatch):
    now_ms = int(judge.utc_now().timestamp() * 1000)
    native = fresh_native(now_ms - 10_000)
    body, parent = archive_row(native, now_ms - 10_000, now_ms - 9_000)
    report = run_judge(tmp_path, all_good("validator1"), [("validator1", native, body, parent)], monkeypatch)
    key_file = tmp_path / "key"
    key_file.write_text("sk-test-secret-value\n")
    key_file.chmod(0o600)
    seen = {}

    class Response:
        def __init__(self, payload):
            self.payload = payload
        def read(self, n):
            return self.payload
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    class Opener:
        def open(self, request, timeout):
            seen["url"] = request.full_url
            seen["headers"] = dict(request.header_items())
            seen["body"] = request.data.decode()
            answer = {"status": "analysis", "summary": "all six healthy", "findings": [
                {"claim": "validator1 rules good", "basis": "observed", "evidence_ids": [parent]}],
                "missing_evidence": [], "recommended_runbooks": []}
            return Response(json.dumps({"content": [{"type": "text", "text": json.dumps(answer)}],
                                        "stop_reason": "end_turn", "model": "m", "usage": {"input_tokens": 1, "output_tokens": 2}}).encode())
    monkeypatch.setattr(judge.urllib.request, "build_opener", lambda *handlers: Opener())

    class Args:
        provider = "anthropic"
        diagnosis_schema = str(ROOT / "contracts/diagnosis.schema.json")
        api_key_file = str(key_file)
        model = "m"
        egress_host = "api.anthropic.com"
        model_timeout = 5
    outcome = judge.model_explanation(Args, report)
    assert outcome["result"] == "accepted", outcome
    assert seen["url"] == "https://api.anthropic.com/v1/messages"
    assert seen["headers"]["X-api-key"] == "sk-test-secret-value"
    assert "sk-test-secret-value" not in seen["body"]
    assert "sk-test-secret-value" not in json.dumps(outcome)
    # A world-readable key file is refused before any request.
    key_file.chmod(0o644)
    assert judge.model_explanation(Args, report)["error"] == "api_key_file_permissions"
    key_file.chmod(0o600)
    # A redirect from the approved host is refused, never followed.
    class Redirecting:
        def open(self, request, timeout):
            raise judge.urllib.error.HTTPError(request.full_url, 302, "redirect refused", {}, None)
    monkeypatch.setattr(judge.urllib.request, "build_opener", lambda *handlers: Redirecting())
    assert judge.model_explanation(Args, report)["error"] == "http_302"


def test_ai_availability_from_the_model_journal(tmp_path):
    import datetime as dt
    pass
    now = dt.datetime(2026, 9, 30, 18, 0, tzinfo=dt.timezone.utc)
    journal = tmp_path / "model.jsonl"
    assert judge.ai_available_from_journal(journal, 900, now) is False  # missing
    journal.write_text("")
    assert judge.ai_available_from_journal(journal, 900, now) is False  # empty
    fresh = {"checked_at": "2026-09-30T17:55:00+00:00", "model": {"result": "accepted"}}
    stale = {"checked_at": "2026-09-30T17:30:00+00:00", "model": {"result": "accepted"}}
    refused = {"checked_at": "2026-09-30T17:59:00+00:00", "model": {"result": "refused"}}
    journal.write_text(json.dumps(stale) + "\n" + json.dumps(fresh) + "\n")
    assert judge.ai_available_from_journal(journal, 900, now) is True
    journal.write_text(json.dumps(fresh) + "\n" + json.dumps(stale) + "\n")
    assert judge.ai_available_from_journal(journal, 900, now) is False  # last line rules
    journal.write_text(json.dumps(refused) + "\n")
    assert judge.ai_available_from_journal(journal, 900, now) is False
    journal.write_text("not json\n")
    assert judge.ai_available_from_journal(journal, 900, now) is False
    future = {"checked_at": "2026-09-30T18:05:00+00:00", "model": {"result": "accepted"}}
    journal.write_text(json.dumps(future) + "\n")
    assert judge.ai_available_from_journal(journal, 900, now) is False  # a future clock is not fresh


def test_journal_rotates_once_before_the_size_cap(tmp_path):
    judge = load_module()
    path = tmp_path / "verdicts.jsonl"
    judge.append_journal(path, "a" * 40, 100)
    judge.append_journal(path, "b" * 40, 100)
    assert not (tmp_path / "verdicts.jsonl.1").exists()
    judge.append_journal(path, "c" * 40, 100)  # 82 + 41 > 100 -> rotate first
    assert (tmp_path / "verdicts.jsonl.1").read_text() == "a" * 40 + "\n" + "b" * 40 + "\n"
    assert path.read_text() == "c" * 40 + "\n"
    judge.append_journal(path, "d" * 70, 100)  # 41 + 71 > 100 -> rotate again, one generation kept
    assert (tmp_path / "verdicts.jsonl.1").read_text() == "c" * 40 + "\n"
    judge.append_journal(path, "e", 0)  # 0 disables rotation
    assert path.read_text().endswith("e\n")


def test_bounded_child_output_is_capped_and_the_child_killed():
    import sys as _sys
    judge = load_module()
    quick = judge.run_bounded([_sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read()); sys.stderr.write('e')"],
                              b"hello", 10)
    assert quick is not None and quick.returncode == 0 and quick.stdout == b"hello" and quick.stderr == b"e"
    flood = judge.run_bounded([_sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x' * 65536); sys.stdout.flush()"],
                              b"", 10, stdout_cap=100_000)
    assert flood is None  # overflow: killed, nothing beyond the cap buffered
    slow = judge.run_bounded([_sys.executable, "-c", "import time; time.sleep(30)"], b"", 1)
    assert slow is None  # deadline: killed
