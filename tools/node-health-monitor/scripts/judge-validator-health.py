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
import urllib.request
from pathlib import Path

HEX = re.compile(r"[0-9a-f]{64}\Z")
NATIVE_RULES = ("local_chain_stalled", "pq_signing_failure", "local_action_failure",
                "storage_ack_failure", "local_action_overdue", "session_stop_pending")
REACH_RULES = ("target_unreachable", "telemetry_unavailable")
MAX_STATE_BYTES = 1 << 20
MAX_ARCHIVE_BODY = 32_768
NATIVE_FRESH_SECONDS = 90


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
        result[key["node"]][key["rule"]] = {
            "input": incident["input"],
            "open": s["state"] == "open",
            "severity": s["severity"] if s["state"] == "open" else None,
            "episode": s["episode"],
        }
    return result


def latest_native(db_path, node, now_ms):
    """Latest archived native row for a node with its exact parent hash."""
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2) as db:
        rows = db.execute(
            "SELECT store_seq, process_epoch, source_epoch, source_record, content_hash, body "
            "FROM observations WHERE node=? AND scope='node' AND source='native_core' "
            "ORDER BY store_seq DESC LIMIT 1", (node,)).fetchall()
        if not rows:
            return None
        store_seq, process_epoch, source_epoch, source_record, parent_hash, body = rows[0]
        if len(body) > MAX_ARCHIVE_BODY or HEX.match(parent_hash) is None:
            raise ValueError("archive row out of contract")
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


def verdict_for(node, rules, native, role):
    """Deterministic verdict. unknown beats healthy; any open critical is unhealthy."""
    reasons = []
    if native is None:
        return "unknown", ["no_archived_native_sample"]
    if native["quarantined"]:
        return "unknown", ["native_source_quarantined"]
    if native["age_seconds"] > NATIVE_FRESH_SECONDS:
        reasons.append("native_sample_stale")
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
        verdict, reasons = verdict_for(node, incidents[node], native, role)
        report["nodes"][node] = {
            "role": role, "verdict": verdict, "reasons": reasons,
            "rules": {r: {"input": s["input"], "open": s["open"], "severity": s["severity"]}
                      for r, s in sorted(incidents[node].items())},
            "native": native,
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


def model_explanation(args, report):
    """Optional AURA turn through the Codex bridge. Output is validated and never changes verdicts."""
    from jsonschema import Draft202012Validator
    schema = json.loads(Path(args.diagnosis_schema).read_text())
    Draft202012Validator.check_schema(schema)
    unsupported = {"$schema", "$defs", "maxItems", "minItems", "maxLength", "minLength", "uniqueItems"}

    def strip(value):
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if k not in unsupported}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value
    prompt = {"instruction": DIAGNOSIS_INSTRUCTION, "verdict": report}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as wire:
        json.dump(strip(schema), wire)
        wire.flush()
        command = [args.codex_bin, "codex", "--socket", args.codex_socket, "--workdir", args.codex_workdir,
                   "--thread-file", args.codex_thread_file, "--output-schema", wire.name,
                   "--timeout-seconds", str(args.model_timeout)]
        result = subprocess.run(command, input=json.dumps(prompt).encode(), capture_output=True,
                                timeout=args.model_timeout + 10)
    if result.returncode != 0 or len(result.stdout) > 16384:
        return {"result": "unavailable", "error": result.stderr.decode(errors="replace")[-400:]}
    try:
        diagnosis = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"result": "unavailable", "error": "model_output_not_json"}
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
    args = parser.parse_args()
    if not HEX.match(args.network_id):
        parser.error("network id must be 64 lowercase hex characters")
    model_args = (args.codex_bin, args.codex_socket, args.codex_workdir, args.codex_thread_file, args.diagnosis_schema)
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
