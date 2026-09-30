#!/usr/bin/env python3
"""Run one bounded pinned-AURA process check against the local private broker.

This uses AURA's McpManager through the already compiled, source-bound host
check. It reports process-source availability, not whole-node health or model
judgment. The caller schedules invocations and retains the JSON status.
"""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile


NODES = frozenset(("validator1", "validator2", "validator3", "validator4", "observer5", "observer6"))
PROCESS_LINE = re.compile(
    r'^AURA_C09_REAL_PROCESS (validator[1-4]|observer[56]) "partial" '
    r'pid=([1-9][0-9]*) parent=([0-9a-f]{64})$'
)
TEST_NAME = "pinned_aura_reads_six_real_m_process_sources_without_model"


def digest(path):
    sha = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            sha.update(block)
    return sha.hexdigest()


def unit_pid(unit):
    result = subprocess.run(
        ["systemctl", "--user", "show", "--property=MainPID", "--value", unit],
        capture_output=True, text=True, timeout=3, check=True,
    )
    value = result.stdout.strip()
    if not value.isdecimal() or int(value) <= 0:
        raise ValueError("unit_unavailable")
    return value


def evaluate(output):
    seen = {}
    for line in output.splitlines():
        match = PROCESS_LINE.fullmatch(line)
        if match:
            node = match.group(1)
            if node in seen:
                raise ValueError("duplicate_node")
            seen[node] = {"pid": int(match.group(2)), "evidence_id": match.group(3)}
    if set(seen) != NODES:
        raise ValueError("missing_node")
    if (output.count("C09_GRANT_REVOKED group=0") != 1
            or output.count("C09_GRANT_REVOKED group=1") != 1
            or output.count("AURA_C09_REAL_UNKNOWN consensus=error") != 1
            or output.count("AURA_C09_REAL_SCOPE cross_run=error") != 1
            or f"test {TEST_NAME} ... ok" not in output):
        raise ValueError("missing_control")
    return seen


def run(args):
    test = Path(args.test_binary)
    adapter = Path(args.adapter_binary)
    manifest = Path(args.manifest)
    for path, expected in ((test, args.test_sha256), (adapter, args.adapter_sha256)):
        if digest(path) != expected:
            raise ValueError("binary_changed")
    manifest_sha = digest(manifest)
    env = {
        "NHM_C09_LIVE_M_EVIDENCE_DB": args.manager_db,
        "NHM_C09_DEPLOYMENT_MANIFEST": str(manifest),
        "NHM_C09_EXPECTED_MANIFEST_SHA256": manifest_sha,
        "NHM_C09_MANAGER_PID": unit_pid(args.manager_unit),
        "NHM_C09_BROKER_PID": unit_pid(args.broker_unit),
        "NHM_C09_BROKER_CONTROL_SOCKET": args.control_socket,
        "NHM_C09_BROKER_MCP_SOCKET": args.mcp_socket,
        "NHM_C09_BROKER_OPERATOR_TOKEN_FILE": args.operator_token_file,
        "NHM_C09_BROKER_SERVICE_TOKEN_FILE": args.service_token_file,
        "NHM_AURA_STDIO_BIN": str(adapter),
    }
    # The child needs its ordinary runtime environment, but no token value is
    # placed in argv, env, stdout, or the status row.
    import os
    child_env = os.environ.copy()
    child_env.update(env)
    result = subprocess.run(
        [str(test), "--exact", TEST_NAME, "--nocapture"],
        capture_output=True, timeout=45, env=child_env,
    )
    output = result.stdout + result.stderr
    if len(output) > 32768:
        raise ValueError("child_output_oversize")
    if result.returncode != 0:
        raise ValueError("aura_check_failed")
    return evaluate(output.decode("utf-8", errors="replace"))


def archived_native_parents(manager_db, samples, network_id):
    """Bind each transient native sample to an exact, unquarantined M row."""
    parents = {}
    try:
        with sqlite3.connect(f"file:{Path(manager_db)}?mode=ro", uri=True, timeout=1) as db:
            db.execute("BEGIN")
            for node in sorted(samples):
                sample = samples[node]
                for store_seq, process_epoch, source_epoch, source_record, parent_hash, body in db.execute(
                    "SELECT store_seq,process_epoch,source_epoch,source_record,content_hash,body "
                    "FROM observations WHERE node=? AND scope='node' AND source='native_core' "
                    "ORDER BY store_seq DESC LIMIT 32", (node,)
                ):
                    if (type(store_seq) is not int or store_seq <= 0
                            or process_epoch != sample["native_epoch"]
                            or source_epoch != sample["native_epoch"]
                            or source_record != f"{sample['native_epoch']}:{sample['native_generation']}"):
                        continue
                    if len(body) > 32_768:
                        raise ValueError("local_health_archive_oversize")
                    value = json.loads(body)
                    record = value["record"]
                    native = record["payload"]["source"]
                    if native["content_hash"] != sample["native_hash"]:
                        continue
                    observed_at = native["observed_at"]
                    if not isinstance(observed_at, str) or not observed_at.endswith("Z"):
                        raise ValueError("local_health_archive_mismatch")
                    observed_ms = int(dt.datetime.fromisoformat(observed_at).timestamp() * 1000)
                    canonical = json.loads(body)
                    canonical["record"]["received_at_ms"] = 0
                    if (re.fullmatch(r"[0-9a-f]{64}", parent_hash) is None
                            or hashlib.sha256(json.dumps(canonical, separators=(",", ":"),
                                                         ensure_ascii=False).encode()).hexdigest() != parent_hash
                            or record["node_id"] != node
                            or record["source_id"] != "native_core"
                            or record["source_record_id"] != f"{sample['native_epoch']}:{sample['native_generation']}"
                            or record["process_epoch"] != sample["native_epoch"]
                            or value["source_epoch"] != sample["native_epoch"]
                            or native["node_id"] != node
                            or native["scope_id"] != "node"
                            or native["source_id"] != "native_core"
                            or native["source_version"] != "native-core-v2"
                            or native["process_epoch"] != sample["native_epoch"]
                            or native["source_epoch"] != sample["native_epoch"]
                            or native["generation"] != str(sample["native_generation"])
                            or native["availability"] != "available"
                            or native["clock_quality"] != "valid"
                            or native["quality"]["instrumentation_complete"] != sample["native_complete"]
                            or record["observed_at_ms"] != observed_ms
                            or record["quality"]["observed_at_ms"] != observed_ms
                            or record["quality"]["availability"] != native["availability"]
                            or record["quality"]["clock_valid"] is not True
                            or record["quality"]["coverage"] != native["coverage"]["status"]
                            or native["coverage"]["missing_fields"] != sample["native_missing"]
                            or native["payload"]["consensus"]["instrumentation_complete"]
                            != sample["native_complete"]
                            or native["payload"]["network_id"] != network_id
                            or hashlib.sha256(json.dumps(native["payload"], sort_keys=True,
                                                         separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
                            != sample["native_hash"]):
                        raise ValueError("local_health_archive_mismatch")
                    quarantined = db.execute(
                        "SELECT 1 FROM quarantined WHERE node=? AND scope='node' "
                        "AND process_epoch=? AND source_epoch=? AND source='native_core' LIMIT 1",
                        (node, sample["native_epoch"], sample["native_epoch"]),
                    ).fetchone()
                    if quarantined:
                        raise ValueError("local_health_archive_quarantined")
                    parents[node] = parent_hash
                    break
                if node not in parents:
                    raise ValueError("local_health_archive_missing")
    except (KeyError, TypeError, sqlite3.DatabaseError, json.JSONDecodeError) as error:
        raise ValueError("local_health_archive_invalid") from error
    return parents


def read_local_health(path, sources, network_id, manager_db):
    """Read the independent local sampler cache; never contact a node here."""
    import os
    import stat

    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077):
            raise ValueError("local_health_permissions")
        raw = os.read(fd, 16_385)
    finally:
        os.close(fd)
    if len(raw) > 16_384:
        raise ValueError("local_health_oversize")
    value = json.loads(raw)
    at = dt.datetime.fromisoformat(value["checked_at"])
    age = (dt.datetime.now(dt.timezone.utc) - at).total_seconds()
    if (value.get("schema_version") != 1
            or value.get("scope") != "local_development_validator_sources"
            or value.get("network_id") != network_id
            or value.get("whole_validator_health") != "unknown"
            or at.tzinfo is None or not 0 <= age <= 90
            or not set(value.get("samples", {})) <= NODES
            or set(value.get("verdicts", {})) != NODES):
        raise ValueError("local_health_stale_or_mismatched")
    compact = {}
    for node in sorted(NODES):
        verdict = value["verdicts"][node]
        if node not in value["samples"]:
            if verdict.get("status") != "unknown" or verdict.get("facts") != {}:
                raise ValueError("local_health_missing_source_state")
            compact[node] = {"status": "unknown", "reasons": verdict["reasons"], "facts": {}}
            continue
        sample = value["samples"][node]
        native_hash = sample.get("native_hash")
        if (sample.get("pid") != sources[node]["pid"]
                or not isinstance(native_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", native_hash) is None
                or not isinstance(sample.get("native_epoch"), str)
                or type(sample.get("native_generation")) is not int
                or verdict.get("status") not in ("unknown", "degraded")
                or verdict.get("facts", {}).get("native_hash") != native_hash):
            raise ValueError("local_health_identity")
        compact[node] = {"status": verdict["status"],
                         "reasons": verdict["reasons"],
                         "facts": verdict["facts"]}
    parents = archived_native_parents(manager_db, value["samples"], network_id)
    for node, parent in parents.items():
        compact[node]["native_archive_parent"] = parent
    return compact


def analyze(args, sources, checked_at, local_health=None):
    from jsonschema import Draft202012Validator

    schema = json.loads(Path(args.diagnosis_schema).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    evidence_ids = {item["evidence_id"] for item in sources.values()}
    if local_health:
        evidence_ids.update(item["native_archive_parent"] for item in local_health.values()
                            if "native_archive_parent" in item)
    prompt = {
        "instruction": (
            "Analyze only this AURA process-source receipt. Return one JSON object matching "
            "the diagnosis contract. The six process snapshots are partial; consensus, duty, "
            "persistence and whole-validator health are unknown. Local development "
            "facts, if present, may show sync or local action progress or degradation; "
            "they do not prove full duty or finality health. Use status "
            "insufficient_evidence. Do not infer healthy or safe. Cite only supplied "
            "M process parent IDs or M native archive parent IDs for observed findings. "
            "Do not request tools or remediation."
        ),
        "checked_at": checked_at,
        "source": "pinned_aura_mcp",
        "consensus": "unknown",
        "process_sources": [
            {"node_id": node, **sources[node]} for node in sorted(sources)
        ],
        "local_development_facts": local_health,
    }
    # The app-server accepts a subset of JSON Schema. It constrains the shape;
    # the complete repository contract is checked after the turn.
    unsupported = {"$schema", "$defs", "maxItems", "minItems", "maxLength",
                   "minLength", "uniqueItems"}

    def output_schema(value):
        if isinstance(value, dict):
            return {key: output_schema(item) for key, item in value.items()
                    if key not in unsupported}
        if isinstance(value, list):
            return [output_schema(item) for item in value]
        return value

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as wire:
        json.dump(output_schema(schema), wire)
        wire.flush()
        command = [args.codex_bin, "codex", "--socket", args.codex_socket,
                   "--thread-file", args.codex_thread_file,
                   "--output-schema", wire.name, "--timeout-seconds", "60"]
        result = subprocess.run(command, input=json.dumps(prompt).encode(),
                                capture_output=True, timeout=65)
    if result.returncode != 0 or len(result.stdout) > 16384:
        kind = "codex_turn_timeout" if b"timed out" in result.stderr else "codex_turn_failed"
        raise ValueError(kind)
    diagnosis = json.loads(result.stdout)
    if next(Draft202012Validator(schema).iter_errors(diagnosis), None) is not None:
        raise ValueError("diagnosis_schema_invalid")
    if diagnosis["status"] != "insufficient_evidence":
        raise ValueError("unsupported_health_conclusion")
    for finding in diagnosis["findings"]:
        if set(finding["evidence_ids"]) - evidence_ids:
            raise ValueError("unbound_evidence_id")
        if finding["basis"] == "observed" and not finding["evidence_ids"]:
            raise ValueError("observed_without_evidence")
    return diagnosis


def main():
    parser = argparse.ArgumentParser()
    for name in (
        "test-binary", "test-sha256", "adapter-binary", "adapter-sha256",
        "manifest", "manager-db", "manager-unit", "broker-unit",
        "control-socket", "mcp-socket", "operator-token-file", "service-token-file",
    ):
        parser.add_argument("--" + name, required=True)
    for name in ("codex-bin", "codex-socket", "codex-thread-file", "diagnosis-schema"):
        parser.add_argument("--" + name)
    parser.add_argument("--local-health-file")
    args = parser.parse_args()
    codex_options = (args.codex_bin, args.codex_socket, args.codex_thread_file,
                     args.diagnosis_schema)
    if any(codex_options) and not all(codex_options):
        parser.error("all Codex options are required together")
    status = {"schema_version": 1, "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "source": "pinned_aura_mcp", "scope": "process_source_only"}
    try:
        sources = run(args)
        status["nodes"] = sorted(sources)
        status["result"] = "observed_partial"
        if args.codex_bin:
            try:
                local_health = None
                if args.local_health_file:
                    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
                    local_health = read_local_health(
                        args.local_health_file, sources, manifest["network_id"], args.manager_db
                    )
                    status["local_validator_facts"] = local_health
                status["diagnosis"] = analyze(args, sources, status["checked_at"], local_health)
                status["ai_result"] = "insufficient_evidence"
            except (ImportError, OSError, ValueError, subprocess.SubprocessError) as error:
                status["ai_result"] = "unavailable"
                status["ai_error_kind"] = (str(error) if isinstance(error, ValueError)
                                           else type(error).__name__)
                code = 1
            else:
                code = 0
        else:
            code = 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        status["result"] = "unavailable"
        status["error_kind"] = str(error) if isinstance(error, ValueError) else type(error).__name__
        code = 1
    print(json.dumps(status, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
