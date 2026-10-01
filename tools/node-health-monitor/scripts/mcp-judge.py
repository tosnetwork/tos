#!/usr/bin/env python3
"""Judge validator health through the private MCP lane with a real model.

The deterministic judgement (the same rules and native evidence the minute
judge uses) is computed first. Then one grant is issued on the query
broker's control socket for every inventory node, a one-use credential file
is written for the stdio adapter, and a model session (Claude Code in print
mode, or `codex exec` in a private home) is started whose only MCP servers
are adapter instances, one per grant. A grant covers at most four nodes, so
seven nodes need two. The model reads retained evidence through the six
read-only tools and answers the diagnosis contract. The adapter records
every evidence item the tools returned; the answer is accepted only when it
validates against the contract, cites only evidence the tools returned, and
explains every non-healthy node with evidence that belongs to that node. The
model never sees a token, never issues a grant, and cannot change a verdict.
"""

import argparse
import datetime as dt
import http.client
import importlib.util
import json
import os
import secrets
import shutil
import socket
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAX_MODEL_OUTPUT_BYTES = 65536
GRANT_WINDOW_MINUTES = 10
TOOL_PREFIX = "mcp__nhm__"
TOOLS = (
    "tos_get_capabilities",
    "tos_get_node_snapshot",
    "tos_get_metric_window",
    "tos_get_event_window",
    "tos_get_change_history",
    "tos_get_block_evidence",
)

MCP_INSTRUCTION = (
    "You are the read-only TOS validator health investigator. Your MCP servers (named nhm_a, nhm_b, ...) "
    "each expose six read-only tools over retained evidence for the nodes listed under that server in "
    "the input's `grants`, and every call must pass that server's run_id. Input: a deterministic rule "
    "verdict per node from the health-state engine. For every node call tos_get_node_snapshot on the "
    "server that covers it with exactly these arguments: run_id = that server's run_id, node_id, "
    "as_of = the input's as_of value verbatim (it is the grant window's end; any other timestamp is "
    'out of scope), max_age_seconds = 120, components = ["consensus", "chain", "storage", '
    '"process"]. Use the returned evidence. If a tool result is truncated in your view so that you '
    'cannot read its evidence ids, call the same tool again for that node with components = ["chain"] '
    "and cite the ids from that shorter result; never cite an id you did not read from a tool result. "
    "Return exactly one JSON object matching the diagnosis contract. Use status 'analysis' when verdicts "
    "are healthy/degraded/unhealthy and explain each non-healthy node with an observed finding citing "
    "evidence_id values taken only from tool results for that node; use 'insufficient_evidence' only when "
    "every node is unknown or the tools returned no evidence. Never claim a node is healthier than its "
    "verdict, never claim remediation was done, never ask for other tools. Hypotheses must list what "
    "evidence is missing. Do not include run_id or tokens in the answer."
)


def load_judge():
    spec = importlib.util.spec_from_file_location(
        "judge_validator_health", HERE / "judge-validator-health.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


def control(socket_path, token, method, path, body=None, timeout=10):
    connection = UnixHTTPConnection(socket_path, timeout)
    try:
        headers = {"Authorization": f"Bearer {token}"}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["content-type"] = "application/json"
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        raw = response.read(65536)
    finally:
        connection.close()
    return response.status, raw


def rfc3339(moment):
    return moment.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def issue_grant(socket_path, operator_token, nodes, now):
    """One grant over every judged node for the last GRANT_WINDOW_MINUTES; the
    end must not be in the future, so it is the judgement time itself."""
    start = rfc3339(now - dt.timedelta(minutes=GRANT_WINDOW_MINUTES))
    end = rfc3339(now)
    status, raw = control(
        socket_path,
        operator_token,
        "POST",
        "/v1/control/grants",
        {"node_ids": sorted(nodes), "scope_ids": ["node"], "start": start, "end": end},
    )
    if status != 200:
        raise RuntimeError(f"grant refused: http {status} {raw[:200]!r}")
    grant = json.loads(raw)
    for key in ("run_id", "run_token"):
        if not isinstance(grant.get(key), str) or not grant[key]:
            raise RuntimeError("grant response malformed")
    return grant


def revoke_grant(socket_path, operator_token, run_id):
    try:
        control(socket_path, operator_token, "POST", f"/v1/control/grants/{run_id}/revoke")
    except (OSError, http.client.HTTPException):
        pass


def private_run_dir(base):
    """A fresh 0700 directory for this run's one-use credential and evidence log."""
    base = Path(base)
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    run_dir = base / f"run-{secrets.token_hex(8)}"
    run_dir.mkdir(mode=0o700)
    return run_dir


def write_credentials(run_dir, grant, service_token, name="nhm"):
    path = run_dir / f"credentials-{name}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(
            {
                "run_id": grant["run_id"],
                "run_token": grant["run_token"],
                "service_token": service_token,
            },
            stream,
        )
    return path


def read_evidence_log(path):
    """The adapter's record of what the tools returned: calls, and per call the
    evidence items (id, node, parents, content hash). Missing log = no calls."""
    calls = []
    try:
        text = Path(path).read_text()
    except OSError:
        return calls
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            calls.append(record)
    return calls


def evidence_index(calls):
    """Map every id a tool returned (evidence id, parent id, content hash) to
    the node it belongs to. A citation must resolve here to count as observed."""
    index = {}
    for call in calls:
        for item in call.get("evidence") or []:
            if not isinstance(item, dict):
                continue
            node = item.get("node_id")
            for key in ("evidence_id", "content_hash"):
                value = item.get(key)
                if isinstance(value, str) and value:
                    index.setdefault(value, node)
            for parent in item.get("parent_evidence_ids") or []:
                if isinstance(parent, str) and parent:
                    index.setdefault(parent, node)
    return index


def strip_unsupported(schema):
    unsupported = {
        "$schema",
        "$defs",
        "maxItems",
        "minItems",
        "maxLength",
        "minLength",
        "uniqueItems",
    }
    if isinstance(schema, dict):
        return {k: strip_unsupported(v) for k, v in schema.items() if k not in unsupported}
    if isinstance(schema, list):
        return [strip_unsupported(v) for v in schema]
    return schema


def validate_mcp_diagnosis(schema, diagnosis, report, calls):
    """Contract first, then evidence binding against what the tools returned,
    then the same non-upgrade rule the push lane enforces."""
    from jsonschema import Draft202012Validator

    if not isinstance(diagnosis, dict):
        return {"result": "rejected", "error": "schema: not an object"}
    error = next(Draft202012Validator(schema).iter_errors(diagnosis), None)
    if error is not None:
        return {"result": "rejected", "error": f"schema: {error.message[:200]}"}
    index = evidence_index(calls)
    if not calls:
        return {"result": "rejected", "error": "no_tool_calls"}
    for finding in diagnosis["findings"]:
        unknown = [e for e in finding["evidence_ids"] if e not in index]
        if unknown:
            return {"result": "rejected", "error": "unbound_evidence_id", "ids": unknown[:4]}
        if finding["basis"] == "observed" and not finding["evidence_ids"]:
            return {"result": "rejected", "error": "observed_without_evidence"}
    all_unknown = all(n["verdict"] == "unknown" for n in report["nodes"].values())
    if diagnosis["status"] == "analysis" and all_unknown:
        return {"result": "rejected", "error": "analysis_without_known_verdict"}
    # Verdicts were known and the tools exist, yet the model retrieved nothing:
    # that is a failed session (usually malformed tool arguments), not a
    # judgement. The call log says which arguments it used and why they failed.
    if diagnosis["status"] == "insufficient_evidence" and not all_unknown and not index:
        failures = sorted({str(c.get("error_code")) for c in calls if c.get("error")})
        return {"result": "rejected", "error": "no_evidence_retrieved", "tool_errors": failures[:4]}
    explained = set()
    for finding in diagnosis["findings"]:
        if finding["basis"] != "observed":
            continue
        for evidence_id in finding["evidence_ids"]:
            node = index.get(evidence_id)
            if node:
                explained.add(node)
    unexplained = [
        n
        for n, r in report["nodes"].items()
        if r["verdict"] in ("degraded", "unhealthy") and n not in explained
    ]
    if diagnosis["status"] == "analysis" and unexplained:
        return {
            "result": "rejected",
            "error": "unexplained_non_healthy_nodes",
            "nodes": unexplained,
        }
    return {"result": "accepted"}


GRANT_NODE_LIMIT = 4


def node_groups(nodes):
    """Grants cover at most four nodes; group sorted nodes accordingly."""
    nodes = sorted(nodes)
    return [nodes[i : i + GRANT_NODE_LIMIT] for i in range(0, len(nodes), GRANT_NODE_LIMIT)]


def server_name(index):
    return f"nhm_{chr(ord('a') + index)}"


def mcp_server_config(adapter, mcp_socket, credentials, evidence_log):
    return {"command": str(adapter), "args": [str(mcp_socket), str(credentials), str(evidence_log)]}


def run_claude(args, prompt, schema, servers):
    """Claude Code in print mode with only the adapter servers and no built-in
    tools; the structured output is validated by the caller, not trusted."""
    judge = load_judge()
    config = json.dumps({"mcpServers": servers})
    allowed = " ".join(f"mcp__{name}" for name in servers)
    command = [
        args.claude_bin,
        "-p",
        "--strict-mcp-config",
        "--mcp-config",
        config,
        "--restricted",
        "--allowedTools",
        allowed,
        "--permission-mode",
        "dontAsk",
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(strip_unsupported(schema)),
        "--max-turns",
        str(args.max_turns),
        "--model",
        args.model,
        "--system-prompt",
        MCP_INSTRUCTION,
        json.dumps(prompt),
    ]
    result = judge.run_bounded(
        command, b"", args.model_timeout, stdout_cap=MAX_MODEL_OUTPUT_BYTES + 1
    )
    if result is None:
        return {"result": "unavailable", "error": "model process exceeded its output or time bound"}
    if result.returncode != 0:
        return {
            "result": "unavailable",
            "error": result.stderr.decode(errors="replace")[-400:] or f"exit {result.returncode}",
        }
    try:
        envelope = json.loads(result.stdout)
    except ValueError:
        return {"result": "unavailable", "error": "model_output_not_json"}
    if not isinstance(envelope, dict) or envelope.get("is_error"):
        return {"result": "unavailable", "error": "model_session_error"}
    diagnosis = envelope.get("structured_output")
    if diagnosis is None:
        try:
            diagnosis = json.loads(envelope.get("result") or "")
        except ValueError:
            return {"result": "unavailable", "error": "model_output_not_json"}
    meta = {
        "model": next(iter((envelope.get("modelUsage") or {}).keys()), args.model),
        "num_turns": envelope.get("num_turns"),
        "cost_usd": envelope.get("total_cost_usd"),
    }
    return {"result": "answered", "diagnosis": diagnosis, **meta}


def write_codex_home(args, servers):
    """A private Codex home for the MCP lane: the model lane's home carries
    no MCP servers by design, so this one is separate. Only the configuration
    is rewritten per run; the sign-in material is the owner's existing private
    copy, copied here once."""
    home = Path(args.codex_home)
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    auth = home / "auth.json"
    if not auth.exists():
        source = Path(args.codex_auth_source)
        shutil.copyfile(source, auth)
        os.chmod(auth, 0o600)
    config = "[features]\napps = false\n"
    for name, server in servers.items():
        quoted_args = ", ".join(json.dumps(a) for a in server["args"])
        config += f"\n[mcp_servers.{name}]\ncommand = {json.dumps(server['command'])}\nargs = [{quoted_args}]\n"
    (home / "config.toml").write_text(config)
    os.chmod(home / "config.toml", 0o600)


def run_codex(args, prompt, schema, servers):
    """One `codex exec` turn in a private Codex home whose configuration names
    exactly one MCP server: the adapter. The AURA bridge is not used here: it
    refuses an app-server that has any MCP server, by design, because the
    push lane must stay tool-free. Read-only sandbox, ephemeral thread, the
    final message captured to a private file."""
    judge = load_judge()
    write_codex_home(args, servers)
    home = Path(args.codex_home)
    with tempfile.TemporaryDirectory(dir=home, prefix="run-") as scratch:
        wire = Path(scratch) / "schema.json"
        wire.write_text(json.dumps(strip_unsupported(schema)))
        last = Path(scratch) / "last-message.json"
        command = [
            args.codex_bin,
            "exec",
            "--json",
            "--skip-git-repo-check",
            "--ephemeral",
            "--sandbox",
            "read-only",
            "-C",
            args.codex_workdir,
            "--output-schema",
            str(wire),
            "-o",
            str(last),
            json.dumps({"instruction": MCP_INSTRUCTION, "verdict": prompt}),
        ]
        if args.codex_model:
            command[2:2] = ["-m", args.codex_model]
        previous = os.environ.get("CODEX_HOME")
        os.environ["CODEX_HOME"] = str(home)
        try:
            result = judge.run_bounded(
                command, b"", args.model_timeout + 10, stdout_cap=4 * 1024 * 1024
            )
        finally:
            if previous is None:
                os.environ.pop("CODEX_HOME", None)
            else:
                os.environ["CODEX_HOME"] = previous
        if result is None:
            return {
                "result": "unavailable",
                "error": "model process exceeded its output or time bound",
            }
        if result.returncode != 0:
            return {
                "result": "unavailable",
                "error": result.stderr.decode(errors="replace")[-400:]
                or f"exit {result.returncode}",
            }
        try:
            text = last.read_text().strip()
        except OSError:
            return {"result": "unavailable", "error": "model_output_missing"}
        if text.startswith("```"):
            text = text.strip("`")
            text = text[text.find("{") : text.rfind("}") + 1]
        try:
            diagnosis = json.loads(text)
        except ValueError:
            return {"result": "unavailable", "error": "model_output_not_json"}
        events_text = result.stdout.decode(errors="replace")
        events = events_text.count("\n")
        # The event stream (tool calls, arguments, errors) is kept privately for
        # diagnosis of a refused run; it carries no tokens.
        events_path = home / "last-run-events.jsonl"
        fd = os.open(events_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(events_text)
    return {
        "result": "answered",
        "diagnosis": diagnosis,
        "model": args.codex_model or "codex-default",
        "events": events,
    }


PROVIDERS = {"claude": run_claude, "codex": run_codex}


def judge_through_mcp(args, now=None):
    judge = load_judge()
    now = now or judge.utc_now()
    report = judge.judge(args)
    schema = json.loads(Path(args.diagnosis_schema).read_text())
    nodes = list(report["nodes"].keys())
    operator = judge.read_secret(args.operator_token_file)
    service = judge.read_secret(args.service_token_file)
    run_dir = private_run_dir(args.run_dir)
    grants = []
    servers = {}
    logs = []
    for index, group in enumerate(node_groups(nodes)):
        grant = issue_grant(args.control_socket, operator, group, now)
        name = server_name(index)
        credentials = write_credentials(run_dir, grant, service, name)
        evidence_log = run_dir / f"evidence-{name}.jsonl"
        servers[name] = mcp_server_config(
            args.adapter_bin, args.mcp_socket, credentials, evidence_log
        )
        grants.append(
            {"server": name, "run_id": grant["run_id"], "nodes": group, "credentials": credentials}
        )
        logs.append(evidence_log)
    # The grant window ends at `now` to the second; that exact value is the
    # only as_of every tool accepts, so the model is given it verbatim.
    prompt = {
        "checked_at": report["checked_at"],
        "as_of": rfc3339(now),
        "network_id": report["network_id"],
        "evaluation_sequence": report["evaluation_sequence"],
        "grants": {g["server"]: {"run_id": g["run_id"], "nodes": g["nodes"]} for g in grants},
        "nodes": {
            n: {
                "role": r["role"],
                "verdict": r["verdict"],
                "reasons": r["reasons"],
                "rules": r["rules"],
            }
            for n, r in report["nodes"].items()
        },
        "summary": report["summary"],
    }
    started = time.monotonic()
    try:
        outcome = PROVIDERS[args.provider](args, prompt, schema, servers)
    finally:
        for g in grants:
            revoke_grant(args.control_socket, operator, g["run_id"])
            try:
                g["credentials"].unlink()
            except OSError:
                pass
    calls = [call for log in logs for call in read_evidence_log(log)]
    if outcome["result"] == "answered":
        verdict = validate_mcp_diagnosis(schema, outcome["diagnosis"], report, calls)
        outcome = {**outcome, **verdict}
    record = {
        "schema_version": 1,
        "checked_at": now.isoformat(),
        "lane": "mcp",
        "provider": args.provider,
        "grants": [
            {"server": g["server"], "run_id": g["run_id"], "nodes": g["nodes"]} for g in grants
        ],
        "tool_calls": len(calls),
        "tools_used": sorted({c.get("tool") for c in calls if isinstance(c.get("tool"), str)}),
        "evidence_items": sum(len(c.get("evidence") or []) for c in calls),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "summary": report["summary"],
        "model": outcome,
    }
    if args.journal:
        judge.append_journal(
            Path(args.journal), json.dumps(record, ensure_ascii=False), args.journal_max_bytes
        )
    if not args.keep_run_dir:
        shutil.rmtree(run_dir, ignore_errors=True)
    return record


def build_parser():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--network-id", required=True)
    parser.add_argument("--manager-state-url", required=True)
    parser.add_argument("--manager-read-token-file", required=True)
    parser.add_argument("--evidence-db", required=True)
    parser.add_argument("--nodes-file", required=True)
    parser.add_argument("--control-socket", required=True, help="query broker control socket")
    parser.add_argument("--mcp-socket", required=True, help="query broker MCP socket")
    parser.add_argument("--operator-token-file", required=True)
    parser.add_argument("--service-token-file", required=True)
    parser.add_argument("--adapter-bin", required=True, help="tos-nhm-aura-stdio binary")
    parser.add_argument("--diagnosis-schema", required=True)
    parser.add_argument(
        "--run-dir",
        required=True,
        help="private directory for one-use credentials and evidence logs",
    )
    parser.add_argument(
        "--keep-run-dir",
        action="store_true",
        help="keep the run directory (evidence log) after the run",
    )
    parser.add_argument("--provider", choices=sorted(PROVIDERS), required=True)
    parser.add_argument("--model-timeout", type=int, default=240)
    parser.add_argument("--max-turns", type=int, default=24)
    parser.add_argument("--claude-bin", default="claude")
    parser.add_argument("--model", default="sonnet", help="Claude model alias or name")
    parser.add_argument("--codex-bin", default="codex", help="Codex CLI binary")
    parser.add_argument("--codex-model", help="Codex model override")
    parser.add_argument(
        "--codex-home", help="private Codex home for the MCP lane (separate from the model lane's)"
    )
    parser.add_argument(
        "--codex-auth-source", help="existing private auth.json to copy into --codex-home once"
    )
    parser.add_argument("--codex-workdir")
    parser.add_argument("--journal", help="append one JSON line per run")
    parser.add_argument("--journal-max-bytes", type=int, default=64 * 1024 * 1024)
    return parser


def main():
    args = build_parser().parse_args()
    # The model client may run with any working directory (Codex runs in its
    # own private one), so the adapter path must be absolute.
    args.adapter_bin = str(Path(args.adapter_bin).resolve())
    if not os.access(args.adapter_bin, os.X_OK):
        raise SystemExit(f"adapter binary not executable: {args.adapter_bin}")
    if args.provider == "codex":
        for field in ("codex_home", "codex_auth_source", "codex_workdir"):
            if not getattr(args, field):
                raise SystemExit(f"--provider codex requires --{field.replace('_', '-')}")
    record = judge_through_mcp(args)
    print(json.dumps(record, ensure_ascii=False))
    return 0 if record["model"].get("result") == "accepted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
