#!/usr/bin/env python3
"""Bounded, read-only local development sampler. AURA consumes its saved result.

The result describes observed sync and local action progress. It cannot certify
whole-validator health while the native source declares required capabilities
unverified. This process has no validator control credential.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.error
import urllib.request

from jsonschema import Draft202012Validator


NODES = tuple([f"validator{i}" for i in range(1, 5)] + ["observer5", "observer6"])
HEX = re.compile(r"[0-9a-f]{64}\Z")
U64 = (1 << 64) - 1
MAX_BODY = 65_536
MAX_STATE = 16_384


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def exact_u64(value):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        raise ValueError("invalid_u64")
    result = int(value)
    if result > U64:
        raise ValueError("overflow_u64")
    return result


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise ValueError("state_permissions")
        raw = os.read(fd, MAX_STATE + 1)
        if len(raw) > MAX_STATE:
            raise ValueError("state_oversize")
        return json.loads(raw)
    finally:
        os.close(fd)


def write_private(path, value):
    raw = canonical(value)
    if len(raw) > MAX_STATE:
        raise ValueError("state_oversize")
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".{os.getpid()}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def get_json(port, route):
    request = urllib.request.Request(f"http://127.0.0.1:{port}{route}", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            if response.status != 200:
                raise ValueError("source_http_status")
            raw = response.read(MAX_BODY + 1)
    except urllib.error.HTTPError as error:
        if route != "/readyz" or error.code != 503:
            raise ValueError(f"source_http_{error.code}") from None
        raw = error.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY:
        raise ValueError("source_oversize")
    return json.loads(raw)


def check_readiness_clock(readiness, now):
    if abs(now - readiness["node_time"]) > 30 or readiness["last_block_utime"] > now + 30:
        raise ValueError("readiness_clock")


def node_sample(node, manifest, validator):
    index = int(node[-1])
    native = get_json(9010 + index, "/health-snapshot")
    readiness = get_json(8010 + index, "/readyz")
    if next(validator.iter_errors(native), None) is not None:
        raise ValueError("native_schema")
    if (native.get("source_id") != "native_core" or native.get("node_id") != node
            or native.get("source_version") != "native-core-v2"
            or native.get("availability") != "available"
            or native.get("clock_quality") != "valid"
            or native.get("payload", {}).get("network_id") != manifest["network_id"]
            or native.get("payload", {}).get("generation") != native.get("generation")
            or native.get("source_epoch") != native.get("process_epoch")):
        raise ValueError("native_identity")
    payload = native["payload"]
    if hashlib.sha256(canonical(payload)).hexdigest() != native.get("content_hash"):
        raise ValueError("native_hash")
    age = native.get("source_age_ms")
    if type(age) is not int or not 0 <= age <= 30_000:
        raise ValueError("native_age")
    pid = manifest["nodes"][node]["pid"]
    if type(pid) is not int or pid <= 0:
        raise ValueError("process_identity")
    command = Path(f"/proc/{pid}/cmdline").read_bytes()[:8192].split(b"\0")
    if (b"--health-node-id" not in command
            or command[command.index(b"--health-node-id") + 1:][:1] != [node.encode()]
            or f"127.0.0.1:{9010 + index}".encode() not in command
            or f"127.0.0.1:{8010 + index}".encode() not in command):
        raise ValueError("process_identity")
    if (type(readiness) is not dict or type(readiness.get("ready")) is not bool
            or type(readiness.get("sync_lag_seconds")) is not int
            or type(readiness.get("node_time")) is not int
            or type(readiness.get("last_block_utime")) is not int
            or type(readiness.get("last_block")) is not dict
            or type(readiness["last_block"].get("seqno")) is not int):
        raise ValueError("readiness_contract")
    now = int(time.time())
    check_readiness_clock(readiness, now)
    consensus = payload.get("consensus")
    if type(consensus) is not dict:
        raise ValueError("missing_consensus")
    actions = {}
    for action in consensus.get("actions", []):
        name = action.get("action")
        if name in actions or name not in ("proposal", "notarize_vote", "finalize_vote", "skip_vote"):
            raise ValueError("action_identity")
        live = action["live"]
        actions[name] = {
            "requested": exact_u64(live["phases"]["requested"]),
            "committed": exact_u64(live["phases"].get("signed_committed", "0")),
            "failed": exact_u64(live["outcomes"]["failed"]),
            "pending": exact_u64(live["pending"]),
        }
    if len(actions) != 4:
        raise ValueError("action_coverage")
    return {
        "pid": pid,
        "native_epoch": native["process_epoch"],
        "native_generation": exact_u64(native["generation"]),
        "native_hash": native["content_hash"],
        "native_complete": consensus["instrumentation_complete"],
        "native_missing": native["coverage"]["missing_fields"],
        "ready": readiness["ready"],
        "sync_lag_seconds": readiness["sync_lag_seconds"],
        "block_seqno": readiness["last_block"]["seqno"],
        "block_utime": readiness["last_block_utime"],
        "actions": actions,
        "pq_sign_failed": exact_u64(payload["pq_sign"]["failed"]),
    }


def evaluate(current, previous, elapsed_ms):
    if not current["ready"]:
        return "degraded", ["sync_not_ready"]
    if previous is None or elapsed_ms is None or elapsed_ms < 30_000:
        return "unknown", ["needs_independent_sample"]
    if current["pid"] != previous.get("pid") or current["native_epoch"] != previous.get("native_epoch"):
        return "unknown", ["epoch_changed"]
    if current["native_generation"] <= previous.get("native_generation", -1):
        return "unknown", ["native_not_advanced"]
    if current["block_seqno"] < previous.get("block_seqno", -1):
        return "unknown", ["chain_reorg_or_source_reset"]
    if current["block_seqno"] == previous.get("block_seqno") and elapsed_ms >= 60_000:
        return "degraded", ["chain_not_progressing"]
    if current["pq_sign_failed"] > previous.get("pq_sign_failed", U64):
        return "degraded", ["pq_sign_failure"]
    for name, now in current["actions"].items():
        old = previous.get("actions", {}).get(name)
        if not old:
            return "unknown", ["action_baseline_missing"]
        if any(now[field] < old.get(field, U64) for field in ("requested", "committed", "failed")):
            return "unknown", ["action_counter_reset"]
        if now["failed"] > old["failed"]:
            return "degraded", ["local_action_failure"]
    if not current["native_complete"] or current["native_missing"]:
        return "unknown", ["unverified_validator_dimensions"]
    return "unknown", ["validator_duty_and_finality_unverified"]


def facts(current, previous):
    old = previous if isinstance(previous, dict) else {}
    result = {"sync_lag_seconds": current["sync_lag_seconds"],
              "block_seqno": current["block_seqno"],
              "native_generation": current["native_generation"],
              "native_hash": current["native_hash"],
              "native_complete": current["native_complete"]}
    if old.get("native_epoch") == current["native_epoch"]:
        for label, new, prior in (
            ("block_delta", current["block_seqno"], old.get("block_seqno")),
            ("local_requests_delta", sum(v["requested"] for v in current["actions"].values()),
             sum(v["requested"] for v in old.get("actions", {}).values())),
            ("storage_ack_delta", sum(v["committed"] for v in current["actions"].values()),
             sum(v["committed"] for v in old.get("actions", {}).values())),
        ):
            if type(prior) is int and new >= prior:
                result[label] = new - prior
    return result


def run(manifest, schema, previous, fetch=node_sample):
    if not HEX.fullmatch(manifest.get("network_id", "")) or set(manifest.get("nodes", {})) != set(NODES):
        raise ValueError("manifest_identity")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    namespace = os.stat("/proc/self/ns/time").st_ino
    tick = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    domain = f"{boot}:{namespace}"
    prior_tick = previous.get("boottime_ns") if previous.get("domain") == domain else None
    elapsed = (tick - prior_tick) // 1_000_000 if type(prior_tick) is int and tick >= prior_tick else None
    validator = Draft202012Validator(schema)
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {node: pool.submit(fetch, node, manifest, validator) for node in NODES}
        samples = {}
        verdicts = {}
        for node, future in futures.items():
            try:
                sample = future.result(timeout=8)
                samples[node] = sample
                prior = previous.get("samples", {}).get(node)
                status, reasons = evaluate(sample, prior, elapsed)
                checked = facts(sample, prior)
            except (OSError, ValueError, KeyError, TypeError, TimeoutError) as error:
                status, reasons = "unknown", [type(error).__name__ if not isinstance(error, ValueError) else str(error)]
                checked = {}
            verdicts[node] = {"status": status, "reasons": reasons, "facts": checked}
    return {
        "schema_version": 1,
        "scope": "local_development_validator_sources",
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "network_id": manifest["network_id"],
        "domain": domain,
        "boottime_ns": tick,
        "samples": samples,
        "verdicts": verdicts,
        "whole_validator_health": "unknown",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--source-schema", required=True)
    parser.add_argument("--state-file", required=True)
    args = parser.parse_args()
    manifest = json.loads(Path(args.manifest).read_text())
    schema = json.loads(Path(args.source_schema).read_text())
    try:
        previous = read_private(args.state_file)
    except FileNotFoundError:
        previous = {}
    result = run(manifest, schema, previous)
    write_private(args.state_file, result)
    print(json.dumps({key: value for key, value in result.items() if key not in ("samples", "domain", "boottime_ns")}, sort_keys=True))
    return int(any(value["status"] == "degraded" or not value["facts"]
                   for value in result["verdicts"].values()))


if __name__ == "__main__":
    sys.exit(main())
