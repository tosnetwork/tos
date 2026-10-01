#!/usr/bin/env python3
"""Validator health judgement: deterministic verdict first, model explanation second.

The verdict comes only from the health-state rule incidents (M control state)
and the archived native evidence rows in M. The optional AURA step receives
that verdict together with the exact archive parent hashes as evidence IDs and
must return the repository diagnosis JSON; a model answer can explain or
declare insufficient evidence, but it can never upgrade a node's verdict.

Read-only against M; no node, edge, key or validator control access.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

HEX = re.compile(r"[0-9a-f]{64}\Z")
NATIVE_RULES = ("local_chain_stalled", "pq_signing_failure", "local_action_failure",
                "storage_ack_failure", "local_action_overdue", "session_stop_pending")
REACH_RULES = ("target_unreachable", "telemetry_unavailable")
MAX_STATE_BYTES = 1 << 20
MAX_ARCHIVE_BODY = 32_768
NATIVE_FRESH_SECONDS = 90
UNOBSERVABLE_SECONDS = 180
ACTIVE_STATES = ("open", "suspended_unknown", "recovering")


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def read_secret(path):
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise SystemExit(f"{path}: token file must not be group/world readable")
    return Path(path).read_text().strip()


def manager_state(url, token):
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=5) as response:
        raw = response.read(MAX_STATE_BYTES + 1)
    if len(raw) > MAX_STATE_BYTES:
        raise SystemExit("manager state oversize")
    return json.loads(raw)


def incidents_by_node(state, nodes):
    """Map node -> rule -> (input, open?, severity, episode)."""
    result = {node: {} for node in nodes}
    for incident in state.get("incidents", []):
        key = incident["key"]
        if key.get("scope") != "node" or key.get("node") not in result:
            continue
        s = incident["state"]
        # An incident stays active while suspended on unknown input or while
        # recovering inside its hold; only clear/closed_recovered end it.
        active = s["state"] in ACTIVE_STATES
        result[key["node"]][key["rule"]] = {
            "input": incident["input"],
            "open": active,
            "state": s["state"],
            "severity": s["severity"] if active else None,
            "episode": s["episode"],
        }
    return result


def latest_native(db_path, node, now_ms):
    """Latest archived native row for a node with its exact parent hash."""
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2) as db:
        # The native source has two row kinds in M: archived edge snapshots
        # (payload.component/source) and rule fact frames. Only the archived
        # snapshot is evidence for the judgement; fact frames are skipped.
        rows = db.execute(
            "SELECT store_seq, process_epoch, source_epoch, source_record, content_hash, body "
            "FROM observations WHERE node=? AND scope='node' AND source='native_core' "
            "ORDER BY store_seq DESC LIMIT 16", (node,)).fetchall()
        chosen = None
        for row in rows:
            body = row[5]
            if len(body) > MAX_ARCHIVE_BODY or HEX.match(row[4]) is None:
                raise ValueError("archive row out of contract")
            payload = json.loads(body).get("record", {}).get("payload")
            if isinstance(payload, dict) and "source" in payload:
                chosen = row
                break
        if chosen is None:
            return None
        store_seq, process_epoch, source_epoch, source_record, parent_hash, body = chosen
        quarantined = db.execute(
            "SELECT 1 FROM quarantined WHERE node=? AND scope='node' AND source='native_core' "
            "AND process_epoch=? AND source_epoch=? LIMIT 1", (node, process_epoch, source_epoch)).fetchone()
    value = json.loads(body)
    recomputed = json.loads(body)
    recomputed["record"]["received_at_ms"] = 0
    if hashlib.sha256(json.dumps(recomputed, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest() != parent_hash:
        raise ValueError("archive parent hash mismatch")
    record = value["record"]
    native = record["payload"]["source"]
    payload = native["payload"]
    consensus = payload.get("consensus") or {}
    contexts = [c for c in consensus.get("contexts", [])
                if c.get("scope", {}).get("scope_id") == "masterchain" and c.get("lifecycle") == "active"]
    failures = {}
    for action in consensus.get("actions", []):
        for reason, count in action.get("live", {}).get("failures", {}).items():
            if reason in ("missing_signer", "sign_backend", "intent_storage", "signed_storage", "journal_unusable"):
                failures[reason] = failures.get(reason, 0) + int(count)
    chain = payload.get("chain")
    age_s = max(0, (now_ms - record["observed_at_ms"]) // 1000)
    return {
        "archive_parent": parent_hash,
        "store_seq": store_seq,
        "source_version": native["source_version"],
        "process_epoch": process_epoch,
        "generation": native["generation"],
        "observed_at": native["observed_at"],
        "age_seconds": age_s,
        "quarantined": bool(quarantined),
        "instrumentation_complete": native["quality"]["instrumentation_complete"],
        "incomplete_reasons": list(consensus.get("incomplete_reasons", [])) if consensus else [],
        "coverage_missing": native["coverage"]["missing_fields"],
        "sessions_active": int(consensus["sessions"]["active"]) if consensus else None,
        "finalized_slot": max((c["last_finalized_slot"] for c in contexts if c.get("last_finalized_slot") is not None), default=None),
        "current_slot": max((c["current_slot"] for c in contexts if c.get("current_slot") is not None), default=None),
        "local_execution_failures": failures,
        "pq_sign_failed": int(payload["pq_sign"]["failed"]) if payload.get("pq_sign") else None,
        "pq_sign_succeeded": int(payload["pq_sign"]["succeeded"]) if payload.get("pq_sign") else None,
        "chain_applied_seqno": chain["applied"]["seqno"] if chain else None,
        "chain_applied_advanced_age_seconds": (int(chain["observed_unix_seconds"]) - int(chain["applied_advanced_unix_seconds"])) if chain else None,
    }


def latest_process_age(db_path, node, now_ms):
    """Age in seconds of the latest archived process snapshot row, or None."""
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2) as db:
        rows = db.execute(
            "SELECT body FROM observations WHERE node=? AND scope='node' AND source='process' "
            "ORDER BY store_seq DESC LIMIT 8", (node,)).fetchall()
    for (body,) in rows:
        if len(body) > MAX_ARCHIVE_BODY:
            continue
        record = json.loads(body).get("record", {})
        if isinstance(record.get("payload"), dict) and "source" in record["payload"]:
            return max(0, (now_ms - record["observed_at_ms"]) // 1000)
    return None


def verdict_for(node, rules, native, role, process_age=None):
    """Deterministic verdict. unknown beats healthy; any open critical is unhealthy."""
    reasons = []
    if native is None:
        return "unknown", ["no_archived_native_sample"]
    if native["quarantined"]:
        return "unknown", ["native_source_quarantined"]
    if native["age_seconds"] > NATIVE_FRESH_SECONDS:
        reasons.append("native_sample_stale")
    # The management edge answers but neither the process nor the native
    # source has produced a sample for a long time: the node process itself is
    # gone or wedged. That is delivered evidence, not absence of evidence.
    reachable = rules.get("target_unreachable", {}).get("input") == "good"
    if (reachable and native["age_seconds"] > UNOBSERVABLE_SECONDS
            and (process_age is None or process_age > UNOBSERVABLE_SECONDS)):
        return "unhealthy", ["node_process_unobservable"] + reasons
    open_critical = [r for r, s in rules.items() if s["open"] and s["severity"] == "critical"]
    open_warning = [r for r, s in rules.items() if s["open"] and s["severity"] == "warning"]
    expected = list(REACH_RULES) + list(NATIVE_RULES[:4]) + (list(NATIVE_RULES[4:]) if role == "validator" else [])
    missing = [r for r in expected if r not in rules]
    unknown_inputs = [r for r in expected if r in rules and rules[r]["input"] == "unknown"]
    if open_critical:
        return "unhealthy", sorted(open_critical) + reasons
    if open_warning:
        return "degraded", sorted(open_warning) + reasons
    if missing or unknown_inputs or reasons:
        return "unknown", sorted(set(["rule_not_in_inventory:" + r for r in missing]
                                     + ["rule_input_unknown:" + r for r in unknown_inputs] + reasons))
    if role == "validator" and (native["sessions_active"] or 0) == 0:
        return "degraded", ["no_active_consensus_session"]
    return "healthy", []


def judge(args):
    nodes = json.loads(Path(args.nodes_file).read_text()) if args.nodes_file else {
        f"validator{i}": "validator" for i in range(1, 5)} | {"observer5": "observer", "observer6": "observer"}
    now = utc_now()
    now_ms = int(now.timestamp() * 1000)
    state = manager_state(args.manager_state_url, read_secret(args.manager_read_token_file))
    incidents = incidents_by_node(state, nodes)
    report = {"schema_version": 1, "checked_at": now.isoformat(), "network_id": args.network_id,
              "evaluation_sequence": state.get("evaluation_sequence"), "nodes": {}, "evidence_ids": []}
    for node, role in sorted(nodes.items()):
        native = latest_native(args.evidence_db, node, now_ms)
        process_age = latest_process_age(args.evidence_db, node, now_ms)
        verdict, reasons = verdict_for(node, incidents[node], native, role, process_age)
        report["nodes"][node] = {
            "role": role, "verdict": verdict, "reasons": reasons,
            "rules": {r: {"input": s["input"], "open": s["open"], "state": s["state"], "severity": s["severity"]}
                      for r, s in sorted(incidents[node].items())},
            "native": native,
            "process_age_seconds": process_age,
        }
        if native:
            report["evidence_ids"].append(native["archive_parent"])
    report["summary"] = {v: sorted(n for n, r in report["nodes"].items() if r["verdict"] == v)
                         for v in ("healthy", "degraded", "unhealthy", "unknown")}
    return report


DIAGNOSIS_INSTRUCTION = (
    "You are the read-only TOS validator health investigator. Input: a deterministic rule verdict per "
    "node computed by the health-state engine, plus the latest archived native evidence row per node "
    "(its archive_parent is the evidence ID). Return exactly one JSON object matching the diagnosis "
    "contract. Use status 'analysis' when the verdicts are healthy/degraded/unhealthy and explain each "
    "non-healthy node with an observed finding citing that node's archive_parent; use status "
    "'insufficient_evidence' only when every node is unknown. Never claim a node is healthier than its "
    "verdict, never claim remediation was done, never request tools. Findings with basis 'observed' "
    "must cite only supplied evidence IDs; hypotheses must list what evidence is missing. "
    "Each native row carries instrumentation_complete with incomplete_reasons: "
    "'session_lifecycle_unverified' means no session has yet been observed through its drain boundary "
    "since the process started (observers never run one); capacity and saturation reasons mean a "
    "counter table overflowed and the affected counters are lower bounds. coverage_missing lists what "
    "this publisher does not cover: 'shard_consensus_progress' means the node validates a shard whose "
    "typed consensus progress is not an approved input (masterchain facts are unaffected); "
    "'local_duties', 'queue_state' and 'storage_state' mean the node-state section is absent. An "
    "empty list means everything is covered. Name the reason instead of calling coverage unspecified. "
    "Nodes that share one cause may be explained by one finding citing each of their evidence IDs."
)


MAX_MODEL_OUTPUT_BYTES = 16384


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would move the evidence to a host that was never approved."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def run_codex(args, prompt, schema):
    """One turn through the local Codex bridge; returns raw output bytes or an error dict."""
    unsupported = {"$schema", "$defs", "maxItems", "minItems", "maxLength", "minLength", "uniqueItems"}

    def strip(value):
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if k not in unsupported}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as wire:
        json.dump(strip(schema), wire)
        wire.flush()
        # A dedicated private app-server (own CODEX_HOME, no MCP servers) or a
        # dedicated socket; never the operator's own Codex session.
        endpoint = (["--spawn-app-server", "--codex-home", args.codex_home] if args.codex_home
                    else ["--socket", args.codex_socket])
        # One turn per thread: a reused thread accumulates every earlier
        # evidence package and its turns grew from ~2 to over 5 minutes.
        command = [args.codex_bin, "codex", *endpoint, "--workdir", args.codex_workdir,
                   "--thread-file", args.codex_thread_file, "--max-thread-turns", "1",
                   "--output-schema", wire.name, "--timeout-seconds", str(args.model_timeout)]
        result = run_bounded(command, json.dumps(prompt).encode(), args.model_timeout + 10)
    if result is None or result.returncode != 0 or len(result.stdout) > MAX_MODEL_OUTPUT_BYTES:
        error = (result.stderr if result else b"model process exceeded its output or time bound")
        return {"result": "unavailable", "error": error.decode(errors="replace")[-400:]}
    return result.stdout


class BoundedResult:
    def __init__(self, returncode, stdout, stderr):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def run_bounded(command, stdin_bytes, timeout_s, stdout_cap=MAX_MODEL_OUTPUT_BYTES + 1, stderr_cap=16384):
    """Run a child with streamed, capped output under one deadline that
    starts before the spawn and covers the stdin write as well: the input is
    pumped in chunks from the same selector loop, so a child that never reads
    cannot hold this process on a full pipe. stdout is read up to one byte past
    the accepted maximum and stderr up to `stderr_cap`; a child that exceeds
    either, or the deadline, is killed together with its whole process group,
    so the helpers it spawned do not outlive it. Nothing beyond the caps is
    ever buffered."""
    import selectors
    import signal
    import time as _time
    deadline = _time.monotonic() + timeout_s
    try:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
    except OSError as error:
        return BoundedResult(127, b"", str(error).encode())

    def kill_group():
        try:
            os.killpg(os.getpgid(child.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            child.kill()
        except (ProcessLookupError, OSError):
            pass
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    def close_streams():
        for stream in (child.stdin, child.stdout, child.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass

    out, err = bytearray(), bytearray()
    caps = {child.stdout: (out, stdout_cap), child.stderr: (err, stderr_cap)}
    pending = memoryview(stdin_bytes)
    selector = selectors.DefaultSelector()
    for stream in caps:
        selector.register(stream, selectors.EVENT_READ)
    stdin_open = True
    if pending.nbytes == 0:
        child.stdin.close()
        stdin_open = False
    else:
        selector.register(child.stdin, selectors.EVENT_WRITE)
    overflow = False
    while caps and not overflow:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            break
        for key, events in selector.select(timeout=min(remaining, 1.0)):
            if key.fileobj is child.stdin:
                # Write what the pipe accepts right now, never more than one
                # chunk per wake-up, and stop at the first error: a child
                # that closed its input gets no more of it.
                try:
                    written = os.write(child.stdin.fileno(), pending[:65536])
                    pending = pending[written:]
                except (BrokenPipeError, OSError):
                    pending = pending[:0]
                if pending.nbytes == 0:
                    selector.unregister(child.stdin)
                    try:
                        child.stdin.close()
                    except OSError:
                        pass
                    stdin_open = False
                continue
            chunk = os.read(key.fileobj.fileno(), 65536)
            buffer, cap = caps[key.fileobj]
            if not chunk:
                selector.unregister(key.fileobj)
                del caps[key.fileobj]
                continue
            buffer.extend(chunk[: max(0, cap - len(buffer))])
            if len(buffer) >= cap and len(chunk) > 0 and (len(buffer) + len(chunk)) > cap:
                overflow = True
                break
    selector.close()
    # A child that closed its outputs is finished even if it left input
    # unread; only outputs still open at the deadline mean a timeout.
    timed_out = bool(caps)
    if overflow or timed_out:
        kill_group()
        close_streams()
        return None
    remaining = max(0.0, deadline - _time.monotonic())
    try:
        child.wait(timeout=min(5.0, max(remaining, 0.05)))
    except subprocess.TimeoutExpired:
        kill_group()
        close_streams()
        return None
    close_streams()
    return BoundedResult(child.returncode, bytes(out), bytes(err))


def run_anthropic(args, prompt, schema):
    """One Messages API turn. The key is read at call time, sent only in the
    request header to the configured host, and never written anywhere."""
    host = args.egress_host
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
        return {"result": "unavailable", "error": "egress_host_invalid"}
    key_path = Path(args.api_key_file)
    if key_path.stat().st_mode & 0o077:
        return {"result": "unavailable", "error": "api_key_file_permissions"}
    key = key_path.read_text().strip()
    if not key or any(c.isspace() for c in key):
        return {"result": "unavailable", "error": "api_key_file_shape"}
    body = {
        "model": args.model,
        "max_tokens": 1536,
        "system": DIAGNOSIS_INSTRUCTION + " The JSON schema of the required answer is: "
                  + json.dumps(schema, separators=(",", ":"))
                  + " Output only the JSON object, no prose, no code fences.",
        "messages": [{"role": "user", "content": json.dumps(prompt, separators=(",", ":"))}],
    }
    encoded = json.dumps(body).encode()
    if len(encoded) > 65536:
        return {"result": "unavailable", "error": "prompt_oversize"}
    request = urllib.request.Request(
        f"https://{host}/v1/messages", data=encoded, method="POST",
        headers={"content-type": "application/json", "anthropic-version": "2023-06-01",
                 "x-api-key": key, "accept": "application/json"})
    del key
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=args.model_timeout) as response:
            raw = response.read(MAX_MODEL_OUTPUT_BYTES * 4 + 1)
    except urllib.error.HTTPError as error:
        # The provider's error body names the refused field; it never echoes
        # the credential. Bounded, and only for non-redirect statuses.
        detail = ""
        if error.code not in (301, 302, 303, 307, 308) and error.fp is not None:
            detail = error.fp.read(512).decode(errors="replace")
        return {"result": "unavailable", "error": f"http_{error.code}", "detail": detail}
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return {"result": "unavailable", "error": f"transport: {str(error)[:120]}"}
    if len(raw) > MAX_MODEL_OUTPUT_BYTES * 4:
        return {"result": "unavailable", "error": "response_oversize"}
    try:
        envelope = json.loads(raw)
        text = "".join(block.get("text", "") for block in envelope.get("content", [])
                       if isinstance(block, dict) and block.get("type") == "text")
    except (json.JSONDecodeError, AttributeError):
        return {"result": "unavailable", "error": "provider_envelope_invalid"}
    if envelope.get("stop_reason") not in ("end_turn", "stop_sequence"):
        return {"result": "unavailable", "error": f"stop_reason_{envelope.get('stop_reason')}"}
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):text.rfind("}") + 1]
    usage = envelope.get("usage") or {}
    return {"text": text.encode(), "usage": {"input_tokens": usage.get("input_tokens"),
                                              "output_tokens": usage.get("output_tokens")},
            "model": envelope.get("model")}


def model_explanation(args, report):
    """Optional model turn. Output is validated and never changes verdicts."""
    from jsonschema import Draft202012Validator
    schema = json.loads(Path(args.diagnosis_schema).read_text())
    Draft202012Validator.check_schema(schema)
    prompt = {"instruction": DIAGNOSIS_INSTRUCTION, "verdict": report}
    provider_meta = {"provider": args.provider}
    # Every non-healthy node needs an observed finding, so a contract that
    # cannot hold one finding per node would reject every correct answer.
    # Refuse the turn as unavailable instead of blaming the model for it.
    findings_cap = schema["properties"]["findings"].get("maxItems")
    if findings_cap is not None and len(report["nodes"]) > findings_cap:
        return {"result": "unavailable", "error": "diagnosis_contract_capacity",
                "nodes": len(report["nodes"]), "findings_max_items": findings_cap, **provider_meta}
    if args.provider == "anthropic":
        outcome = run_anthropic(args, prompt, schema)
        if isinstance(outcome, dict) and "text" in outcome:
            provider_meta.update({"model": outcome["model"], "usage": outcome["usage"]})
            outcome = outcome["text"]
    else:
        outcome = run_codex(args, prompt, schema)
    if isinstance(outcome, dict):
        return {**outcome, **provider_meta}
    if len(outcome) > MAX_MODEL_OUTPUT_BYTES:
        return {"result": "unavailable", "error": "model_output_oversize", **provider_meta}
    try:
        diagnosis = json.loads(outcome)
    except json.JSONDecodeError:
        return {"result": "unavailable", "error": "model_output_not_json", **provider_meta}
    verdict = validate_diagnosis(schema, diagnosis, report)
    return {**verdict, **provider_meta}


def validate_diagnosis(schema, diagnosis, report):
    from jsonschema import Draft202012Validator
    if not isinstance(diagnosis, dict):
        return {"result": "rejected", "error": "schema: not an object"}
    error = next(Draft202012Validator(schema).iter_errors(diagnosis), None)
    if error is not None:
        return {"result": "rejected", "error": f"schema: {error.message[:200]}"}
    delivered = set(report["evidence_ids"])
    for finding in diagnosis["findings"]:
        if set(finding["evidence_ids"]) - delivered:
            return {"result": "rejected", "error": "unbound_evidence_id"}
        if finding["basis"] == "observed" and not finding["evidence_ids"]:
            return {"result": "rejected", "error": "observed_without_evidence"}
    all_unknown = all(n["verdict"] == "unknown" for n in report["nodes"].values())
    if diagnosis["status"] == "analysis" and all_unknown:
        return {"result": "rejected", "error": "analysis_without_known_verdict", "diagnosis": diagnosis}
    # Every non-healthy node must be explained by an observed finding citing its evidence.
    cited = {e for f in diagnosis["findings"] if f["basis"] == "observed" for e in f["evidence_ids"]}
    unexplained = [n for n, r in report["nodes"].items()
                   if r["verdict"] in ("degraded", "unhealthy") and r["native"]
                   and r["native"]["archive_parent"] not in cited]
    if diagnosis["status"] == "analysis" and unexplained:
        return {"result": "rejected", "error": "unexplained_non_healthy_nodes", "nodes": unexplained,
                "diagnosis": diagnosis}
    return {"result": "accepted", "diagnosis": diagnosis}


AI_FACT_EPOCH_MAX = 128


def ai_available_from_journal(path, max_age_s, now):
    """Whether the model lane produced an accepted explanation recently: the
    last line of the model journal must be an accepted result younger than
    `max_age_s`. Missing, unreadable or malformed journals mean unavailable.
    The judge posts this every minute, so the fact's freshness follows the
    minute timer while the model turn keeps its own bounded period."""
    try:
        with open(path, "rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - 65536))
            lines = stream.read().splitlines()
    except OSError:
        return False
    if not lines:
        return False
    try:
        record = json.loads(lines[-1])
        checked = dt.datetime.fromisoformat(record["checked_at"])
        if checked.tzinfo is None:
            return False
        result = record.get("model", {}).get("result")
    except (ValueError, KeyError, AttributeError, TypeError):
        return False
    age = (now - checked).total_seconds()
    return result == "accepted" and 0 <= age <= max_age_s


def post_ai_fact(args, available):
    """One `ai_optional` fact frame per run: 1 when the model turn was accepted,
    0 otherwise. Epoch and generation persist in a private state file so the
    rule engine sees a monotonic source; a lost state file starts a new epoch."""
    import secrets
    state_path = Path(args.ai_fact_state)
    state = {"epoch": None, "generation": 0}
    try:
        loaded = json.loads(state_path.read_text())
        if isinstance(loaded.get("epoch"), str) and 0 < len(loaded["epoch"]) <= AI_FACT_EPOCH_MAX \
                and isinstance(loaded.get("generation"), int) and loaded["generation"] >= 0:
            state = loaded
    except (OSError, ValueError):
        pass
    if not state["epoch"]:
        state["epoch"] = secrets.token_hex(16)
    state["generation"] += 1
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(state_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(state, stream)
    frame = {
        "schema_version": 1, "network_id": args.network_id, "node_id": args.ai_fact_node, "scope_id": "node",
        "source_id": "ai_optional", "process_epoch": state["epoch"], "source_epoch": state["epoch"],
        "generation": str(state["generation"]), "source_age_ms": "0", "request_duration_ms": "0",
        "observed_at": utc_now().isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "clock_valid": True, "complete": True,
        "facts": [{"id": "ai_available", "value": "1" if available else "0"}],
    }
    token = read_secret(args.ai_fact_token_file)
    request = urllib.request.Request(args.ai_fact_url, data=json.dumps(frame).encode(), method="POST",
                                     headers={"content-type": "application/json",
                                              "authorization": f"Bearer {token}"})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=5) as response:
            return {"posted": True, "status": response.status, "available": available,
                    "generation": state["generation"]}
    except urllib.error.HTTPError as error:
        return {"posted": False, "status": error.code, "available": available}
    except (urllib.error.URLError, OSError) as error:
        return {"posted": False, "error": str(error)[:120], "available": available}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--network-id", required=True)
    parser.add_argument("--manager-state-url", required=True)
    parser.add_argument("--manager-read-token-file", required=True)
    parser.add_argument("--evidence-db", required=True)
    parser.add_argument("--nodes-file", help="JSON object node -> role (validator|observer)")
    parser.add_argument("--journal", help="append one JSON line per run to this private file")
    parser.add_argument("--journal-max-bytes", type=int, default=JOURNAL_MAX_BYTES_DEFAULT,
                        help="rotate the journal to <name>.1 before it passes this size (0 = never)")
    parser.add_argument("--codex-bin")
    parser.add_argument("--codex-socket")
    parser.add_argument("--codex-home", help="private CODEX_HOME for a spawned app-server")
    parser.add_argument("--codex-workdir")
    parser.add_argument("--codex-thread-file")
    parser.add_argument("--diagnosis-schema")
    parser.add_argument("--model-timeout", type=int, default=90)
    parser.add_argument("--provider", choices=("codex", "anthropic"), default="codex")
    parser.add_argument("--api-key-file", help="private file holding the provider API key (never logged)")
    parser.add_argument("--model", default="claude-sonnet-5-5")
    parser.add_argument("--egress-host", default="api.anthropic.com",
                        help="the only host the model request may go to")
    parser.add_argument("--ai-fact-url", help="M facts ingest URL for the ai_optional availability fact")
    parser.add_argument("--ai-fact-token-file", help="M ingest token for --ai-fact-url")
    parser.add_argument("--ai-fact-state", help="private file holding the ai_optional epoch and generation")
    parser.add_argument("--ai-fact-node", default="monitor", help="node alias the ai_optional fact is filed under")
    parser.add_argument("--ai-fact-journal", help="model journal the availability fact is judged from when this run has no model turn")
    parser.add_argument("--ai-fact-max-age", type=int, default=900,
                        help="seconds an accepted model explanation counts as available (default 900)")
    args = parser.parse_args()
    if not HEX.match(args.network_id):
        parser.error("network id must be 64 lowercase hex characters")
    if args.provider == "anthropic":
        model_args = (args.api_key_file, args.diagnosis_schema)
    else:
        model_args = (args.codex_bin, args.codex_socket or args.codex_home, args.codex_workdir,
                      args.codex_thread_file, args.diagnosis_schema)
    if any(model_args) and not all(model_args):
        parser.error("model options must be given together")
    ai_args = (args.ai_fact_url, args.ai_fact_token_file, args.ai_fact_state)
    if any(ai_args) and not all(ai_args):
        parser.error("--ai-fact-url, --ai-fact-token-file and --ai-fact-state go together")
    if args.ai_fact_journal and all(model_args):
        parser.error("--ai-fact-journal is for the run without a model turn; the model run posts its own result")
    if args.ai_fact_max_age <= 0:
        parser.error("--ai-fact-max-age must be positive")
    report = judge(args)
    if all(model_args):
        report["model"] = model_explanation(args, report)
        if args.ai_fact_url:
            report["ai_fact"] = post_ai_fact(args, report["model"].get("result") == "accepted")
    elif args.ai_fact_url and args.ai_fact_journal:
        available = ai_available_from_journal(args.ai_fact_journal, args.ai_fact_max_age, utc_now())
        report["ai_fact"] = post_ai_fact(args, available)
    line = canonical(report)
    if args.journal:
        append_journal(Path(args.journal), line, args.journal_max_bytes)
        # The journal holds the record; stdout (and so journald) gets one line.
        print(canonical({"checked_at": report["checked_at"], "summary": report["summary"],
                         "model": (report.get("model") or {}).get("result"),
                         "ai_fact": (report.get("ai_fact") or {}).get("posted")}))
    else:
        print(line)
    return 0 if report["summary"]["unhealthy"] == [] else 3


JOURNAL_MAX_BYTES_DEFAULT = 64 * 1024 * 1024


def append_journal(path, line, max_bytes):
    """Append one record; when the file would pass `max_bytes`, rotate it to
    `<name>.1` first (one generation kept), so a minute timer cannot grow a
    journal without bound."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        size = 0
    if max_bytes > 0 and size + len(line) + 1 > max_bytes:
        os.replace(path, path.with_name(path.name + ".1"))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as stream:
        stream.write(line + "\n")


if __name__ == "__main__":
    sys.exit(main())
