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
    "must cite only supplied evidence IDs; hypotheses must list what evidence is missing."
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
        command = [args.codex_bin, "codex", "--socket", args.codex_socket, "--workdir", args.codex_workdir,
                   "--thread-file", args.codex_thread_file, "--output-schema", wire.name,
                   "--timeout-seconds", str(args.model_timeout)]
        result = subprocess.run(command, input=json.dumps(prompt).encode(), capture_output=True,
                                timeout=args.model_timeout + 10)
    if result.returncode != 0 or len(result.stdout) > MAX_MODEL_OUTPUT_BYTES:
        return {"result": "unavailable", "error": result.stderr.decode(errors="replace")[-400:]}
    return result.stdout


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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--network-id", required=True)
    parser.add_argument("--manager-state-url", required=True)
    parser.add_argument("--manager-read-token-file", required=True)
    parser.add_argument("--evidence-db", required=True)
    parser.add_argument("--nodes-file", help="JSON object node -> role (validator|observer)")
    parser.add_argument("--journal", help="append one JSON line per run to this private file")
    parser.add_argument("--codex-bin")
    parser.add_argument("--codex-socket")
    parser.add_argument("--codex-workdir")
    parser.add_argument("--codex-thread-file")
    parser.add_argument("--diagnosis-schema")
    parser.add_argument("--model-timeout", type=int, default=90)
    parser.add_argument("--provider", choices=("codex", "anthropic"), default="codex")
    parser.add_argument("--api-key-file", help="private file holding the provider API key (never logged)")
    parser.add_argument("--model", default="claude-sonnet-5-5")
    parser.add_argument("--egress-host", default="api.anthropic.com",
                        help="the only host the model request may go to")
    args = parser.parse_args()
    if not HEX.match(args.network_id):
        parser.error("network id must be 64 lowercase hex characters")
    if args.provider == "anthropic":
        model_args = (args.api_key_file, args.diagnosis_schema)
    else:
        model_args = (args.codex_bin, args.codex_socket, args.codex_workdir, args.codex_thread_file,
                      args.diagnosis_schema)
    if any(model_args) and not all(model_args):
        parser.error("model options must be given together")
    report = judge(args)
    if all(model_args):
        report["model"] = model_explanation(args, report)
    line = canonical(report)
    if args.journal:
        path = Path(args.journal)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as stream:
            stream.write(line + "\n")
    print(line)
    return 0 if report["summary"]["unhealthy"] == [] else 3


if __name__ == "__main__":
    sys.exit(main())
