"""The MCP lane's acceptance rules: a model answer counts only when it cites
evidence the tools actually returned, for the node it claims to explain."""
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location("mcp_judge", ROOT / "scripts/mcp-judge.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["mcp_judge"] = module
    spec.loader.exec_module(module)
    return module


mcp = load_module()
SCHEMA = json.loads((ROOT / "contracts/diagnosis.schema.json").read_text())
V1 = "1" * 64
V2 = "2" * 64
PARENT1 = "a" * 64
FOREIGN = "f" * 64


def calls(*items):
    return [{"tool": "tos_get_node_snapshot", "request_id": "r1", "status": "partial", "evidence": list(items)}]


def item(evidence_id, node, parents=()):
    return {"evidence_id": evidence_id, "node_id": node, "source_id": "native_core", "kind": "derived",
            "content_hash": "c" * 64, "parent_evidence_ids": list(parents)}


def report(**verdicts):
    return {"nodes": {node: {"verdict": verdict} for node, verdict in verdicts.items()}}


def diagnosis(findings, status="analysis"):
    return {"status": status, "summary": "s", "findings": findings, "missing_evidence": [], "recommended_runbooks": []}


def test_observed_finding_must_cite_tool_returned_evidence_for_that_node():
    log = calls(item(V1, "validator1", [PARENT1]), item(V2, "validator2"))
    verdict = report(validator1="degraded", validator2="healthy")
    ok = diagnosis([{"claim": "gc lag", "basis": "observed", "evidence_ids": [V1]}])
    assert mcp.validate_mcp_diagnosis(SCHEMA, ok, verdict, log)["result"] == "accepted"
    # A parent id the tool returned also binds.
    via_parent = diagnosis([{"claim": "gc lag", "basis": "observed", "evidence_ids": [PARENT1]}])
    assert mcp.validate_mcp_diagnosis(SCHEMA, via_parent, verdict, log)["result"] == "accepted"
    # An id no tool returned is refused even if it looks like a hash.
    foreign = diagnosis([{"claim": "gc lag", "basis": "observed", "evidence_ids": [FOREIGN]}])
    out = mcp.validate_mcp_diagnosis(SCHEMA, foreign, verdict, log)
    assert out["result"] == "rejected" and out["error"] == "unbound_evidence_id"
    # Explaining the degraded node with another node's evidence does not count.
    wrong_node = diagnosis([{"claim": "gc lag", "basis": "observed", "evidence_ids": [V2]}])
    out = mcp.validate_mcp_diagnosis(SCHEMA, wrong_node, verdict, log)
    assert out["result"] == "rejected" and out["error"] == "unexplained_non_healthy_nodes"
    assert out["nodes"] == ["validator1"]
    # No tool call at all: an analysis cannot be grounded.
    out = mcp.validate_mcp_diagnosis(SCHEMA, ok, verdict, [])
    assert out["result"] == "rejected" and out["error"] == "no_tool_calls"
    # A hypothesis needs no citation, but a degraded node still needs an observed one.
    hypo = diagnosis([{"claim": "maybe disk", "basis": "hypothesis", "evidence_ids": []}])
    out = mcp.validate_mcp_diagnosis(SCHEMA, hypo, verdict, log)
    assert out["result"] == "rejected" and out["error"] == "unexplained_non_healthy_nodes"
    # Contract violations are caught before binding.
    bad = diagnosis([{"claim": "x", "basis": "guess", "evidence_ids": [V1]}])
    assert mcp.validate_mcp_diagnosis(SCHEMA, bad, verdict, log)["error"].startswith("schema:")
    # All-unknown verdicts cannot be an analysis.
    out = mcp.validate_mcp_diagnosis(SCHEMA, ok, report(validator1="unknown"), log)
    assert out["error"] == "analysis_without_known_verdict"
    # Known verdicts, seven calls that all failed, nothing retrieved: a failed
    # session, not an "insufficient evidence" judgement (a real Codex run did this
    # with malformed arguments and would otherwise have been accepted).
    failed = [{"tool": "tos_get_node_snapshot", "status": "error", "error": True, "error_code": "INVALID_ARGUMENT",
               "argument_keys": ["run_id", "node_id"], "evidence": []}] * 7
    nothing = diagnosis([], status="insufficient_evidence")
    out = mcp.validate_mcp_diagnosis(SCHEMA, nothing, verdict, failed)
    assert out["result"] == "rejected" and out["error"] == "no_evidence_retrieved"
    assert out["tool_errors"] == ["INVALID_ARGUMENT"]
    # When every verdict is unknown, insufficient evidence is the honest answer.
    assert mcp.validate_mcp_diagnosis(SCHEMA, nothing, report(validator1="unknown"), failed)["result"] == "accepted"


def test_evidence_log_is_read_defensively_and_indexed_by_node():
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "evidence.jsonl"
        path.write_text(json.dumps(calls(item(V1, "validator1", [PARENT1]))[0]) + "\nnot json\n\n[1,2]\n")
        read = mcp.read_evidence_log(path)
        assert len(read) == 1
        index = mcp.evidence_index(read)
        assert index[V1] == "validator1" and index[PARENT1] == "validator1" and index["c" * 64] == "validator1"
        assert mcp.read_evidence_log(Path(directory) / "absent.jsonl") == []


def test_credentials_are_private_and_the_claude_command_names_exactly_one_server(tmp_path, monkeypatch):
    run_dir = mcp.private_run_dir(tmp_path / "runs")
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
    grant = {"run_id": "6357ee64-202f-4e53-9fd2-7f69d9dfcdab", "run_token": "t" * 64}
    credentials = mcp.write_credentials(run_dir, grant, "s" * 40)
    assert stat.S_IMODE(credentials.stat().st_mode) == 0o600
    assert json.loads(credentials.read_text())["service_token"] == "s" * 40
    server = mcp.mcp_server_config("/usr/bin/adapter", "/run/mcp.sock", credentials, run_dir / "evidence.jsonl")
    assert server == {"command": "/usr/bin/adapter",
                      "args": ["/run/mcp.sock", str(credentials), str(run_dir / "evidence.jsonl")]}
    servers = {"nhm_a": server, "nhm_b": dict(server)}
    # Seven nodes need two grants of at most four nodes each, in sorted order.
    assert mcp.node_groups(["validator7", "validator1", "observer5", "validator2", "validator3", "validator4", "observer6"]) == [
        ["observer5", "observer6", "validator1", "validator2"], ["validator3", "validator4", "validator7"]]
    assert [mcp.server_name(i) for i in range(3)] == ["nhm_a", "nhm_b", "nhm_c"]
    seen = {}

    class Result:
        returncode = 0
        stderr = b""
        stdout = json.dumps({"is_error": False, "num_turns": 3, "total_cost_usd": 0.1,
                             "modelUsage": {"claude-sonnet-5-5": {}},
                             "structured_output": diagnosis([])}).encode()

    def fake_run_bounded(command, stdin_bytes, timeout_s, **kwargs):
        seen["command"] = command
        return Result()
    judge = mcp.load_judge()
    monkeypatch.setattr(mcp, "load_judge", lambda: type("J", (), {"run_bounded": staticmethod(fake_run_bounded)}))

    class Args:
        claude_bin = "claude"
        max_turns = 7
        model = "sonnet"
        model_timeout = 30
    out = mcp.run_claude(Args, {"nodes": {}}, SCHEMA, servers)
    assert out["result"] == "answered" and out["model"] == "claude-sonnet-5-5" and out["num_turns"] == 3
    command = seen["command"]
    assert command[:3] == ["claude", "-p", "--strict-mcp-config"]
    config = json.loads(command[command.index("--mcp-config") + 1])
    assert list(config["mcpServers"]) == ["nhm_a", "nhm_b"] and config["mcpServers"]["nhm_a"] == server
    assert "--restricted" in command and command[command.index("--allowedTools") + 1] == "mcp__nhm_a mcp__nhm_b"
    # Tokens never travel on the command line.
    assert "t" * 64 not in " ".join(command) and "s" * 40 not in " ".join(command)
    assert judge is not None


def test_codex_home_for_the_mcp_lane_is_private_and_names_only_the_adapter(tmp_path):
    source = tmp_path / "auth.json"
    source.write_text("{}")
    os.chmod(source, 0o600)

    class Args:
        codex_home = str(tmp_path / "codex-home-mcp")
        codex_auth_source = str(source)
    server = {"command": "/usr/bin/adapter", "args": ["/run/mcp.sock", "/private/cred", "/private/log"]}
    mcp.write_codex_home(Args, {"nhm_a": server, "nhm_b": server})
    home = Path(Args.codex_home)
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    config = (home / "config.toml").read_text()
    assert '[mcp_servers.nhm_a]' in config and '[mcp_servers.nhm_b]' in config and 'command = "/usr/bin/adapter"' in config
    assert config.count("[mcp_servers.") == 2
    assert stat.S_IMODE((home / "auth.json").stat().st_mode) == 0o600
