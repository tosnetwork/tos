#!/usr/bin/env python3
"""One bounded, low-rate private QueryService functional witness. No model calls."""

import argparse
import datetime as dt
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time

NODES = ("validator1", "validator2", "validator3", "validator4", "observer5", "observer6")
LIMIT = 32768
SLOT_SECONDS = 300
LOG_LIMIT = 4 * 1024 * 1024


class WitnessError(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=3):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def private_token(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077 or meta.st_size > 256:
            raise WitnessError("credential_ownership")
        raw = os.read(fd, 257)
        if len(raw) != meta.st_size:
            raise WitnessError("credential_changed")
        token = raw.decode("ascii").strip()
        if not 32 <= len(token) <= 128 or not token.isascii() or not token.isprintable():
            raise WitnessError("credential_format")
        return token
    finally:
        os.close(fd)


def checked_json(raw, cap=LIMIT):
    if len(raw) > cap:
        raise WitnessError("response_oversize")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise WitnessError("response_json") from exc
    if not isinstance(value, dict):
        raise WitnessError("response_shape")
    return value


def request(conn, method, path, body=None, headers=None, cap=LIMIT):
    encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    if encoded is not None and len(encoded) > 4096:
        raise WitnessError("request_oversize")
    conn.request(method, path, body=encoded, headers={"Accept": "application/json", "Connection": "keep-alive",
                                                    **({"Content-Type": "application/json"} if encoded is not None else {}),
                                                    **(headers or {})})
    response = conn.getresponse()
    raw = response.read(cap + 1)
    if len(raw) > cap:
        raise WitnessError("response_oversize")
    return response.status, {key.lower(): value for key, value in response.getheaders()}, raw


def control(socket_path, token, method, path, body=None):
    conn = UnixHTTP(socket_path, timeout=3)
    try:
        return request(conn, method, path, body, {"Authorization": "Bearer " + token}, 4096)
    finally:
        conn.close()


def issue(socket_path, token, node, start, end, leases):
    status, headers, raw = control(socket_path, token, "POST", "/v1/control/grants",
                             {"node_ids": [node], "scope_ids": ["node"], "start": start, "end": end})
    if status != 200:
        raise WitnessError("grant_refused")
    # A 200 may have created a grant even if its response cannot be decoded.
    # Keep that uncertainty visible instead of reporting successful cleanup.
    leases.append(None)
    if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise WitnessError("grant_content_type")
    value = checked_json(raw, 4096)
    run, secret = value.get("run_id"), value.get("run_token")
    if not isinstance(run, str) or re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", run) is None:
        raise WitnessError("grant_shape")
    leases[-1] = run
    if not isinstance(secret, str) or len(secret) != 64 or any(c not in "0123456789abcdef" for c in secret):
        raise WitnessError("grant_shape")
    return run, secret


def revoke(socket_path, token, run):
    try:
        status, headers, raw = control(socket_path, token, "POST", "/v1/control/grants/" + run + "/revoke")
        return (status == 200 and headers.get("content-type", "").split(";", 1)[0].strip().lower() == "application/json"
                and checked_json(raw, 4096).get("revoked") is True)
    except (OSError, TimeoutError, WitnessError, http.client.HTTPException):
        return False


class McpSession:
    def __init__(self, socket_path, service_token, run, run_token):
        self.conn = UnixHTTP(socket_path, timeout=5)
        self.headers = {"Authorization": "Bearer " + service_token, "x-tos-run-id": run,
                        "x-tos-run-token": run_token, "mcp-protocol-version": "2025-06-18",
                        "Accept": "application/json, text/event-stream"}
        self.session = None
        self.sequence = 0

    def call(self, method, params):
        self.sequence += 1
        headers = dict(self.headers)
        if self.session:
            headers["mcp-session-id"] = self.session
        status, reply_headers, raw = request(self.conn, "POST", "/mcp",
                                              {"jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params},
                                              headers)
        if status != 200 or reply_headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise WitnessError("mcp_http")
        session = reply_headers.get("mcp-session-id")
        if session is not None:
            if not 1 <= len(session) <= 128 or not session.isascii() or not session.isprintable():
                raise WitnessError("mcp_session")
            self.session = session
        reply = checked_json(raw)
        if reply.get("id") != self.sequence or reply.get("jsonrpc") != "2.0" or "error" in reply:
            raise WitnessError("mcp_rpc")
        return reply.get("result")

    def initialize(self):
        result = self.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                           "clientInfo": {"name": "c09-functional-witness", "version": "1"}})
        if not isinstance(result, dict) or result.get("protocolVersion") != "2025-06-18":
            raise WitnessError("mcp_initialize")
        headers = dict(self.headers)
        if self.session:
            headers["mcp-session-id"] = self.session
        status, _, raw = request(self.conn, "POST", "/mcp",
                                 {"jsonrpc": "2.0", "method": "notifications/initialized"}, headers)
        if status not in (200, 202, 204) or raw:
            raise WitnessError("mcp_initialized")

    def snapshot(self, run, node, as_of, component):
        result = self.call("tools/call", {"name": "tos_get_node_snapshot", "arguments": {
            "run_id": run, "node_id": node, "as_of": as_of, "max_age_seconds": 180,
            "components": [component]}})
        if not isinstance(result, dict) or not isinstance(result.get("content"), list) or len(result["content"]) != 1:
            raise WitnessError("mcp_content")
        item = result["content"][0]
        if not isinstance(item, dict) or item.get("type") != "text" or not isinstance(item.get("text"), str):
            raise WitnessError("mcp_content")
        return checked_json(item["text"].encode())

    def close(self):
        self.conn.close()


def parent_from_m(path, evidence_id, node):
    if len(evidence_id) != 64 or any(c not in "0123456789abcdef" for c in evidence_id):
        raise WitnessError("parent_id")
    meta = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(meta.st_mode):
        raise WitnessError("m_path")
    uri = "file:" + str(Path(path).resolve()) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=0.5)
    try:
        conn.execute("PRAGMA query_only=ON")
        rows = conn.execute("SELECT body FROM observations WHERE content_hash=? AND node=? AND source='process' LIMIT 2",
                            (evidence_id, node)).fetchall()
        if len(rows) != 1:
            raise WitnessError("parent_missing_or_duplicate")
        if len(rows[0][0]) > 32768:
            raise WitnessError("parent_oversize")
        parent = checked_json(rows[0][0].encode(), 32768)
        if not isinstance(parent.get("record"), dict):
            raise WitnessError("parent_shape")
        canonical = json.loads(json.dumps(parent))
        canonical["record"]["received_at_ms"] = 0
        digest = hashlib.sha256(json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        if digest != evidence_id:
            raise WitnessError("parent_hash")
        return parent
    finally:
        conn.close()


def validate_process(envelope, run, node, as_of_ms, m_path):
    if envelope.get("run_id") != run or envelope.get("status") not in ("ok", "partial"):
        raise WitnessError("process_status")
    data, evidence = envelope.get("data"), envelope.get("evidence")
    if not isinstance(data, dict) or data.get("node_id") != node or not isinstance(evidence, list) or len(evidence) != 1:
        raise WitnessError("process_shape")
    components = data.get("components")
    if not isinstance(components, list) or len(components) != 1 or not isinstance(components[0], dict) or components[0].get("kind") != "process":
        raise WitnessError("process_component")
    component, derived = components[0], evidence[0]
    if not isinstance(derived, dict) or derived.get("node_id") != node or derived.get("source_id") != "process" or derived.get("kind") != "derived":
        raise WitnessError("derived_identity")
    if (component.get("sources") != ["process"] or derived.get("source_version") != "m-observation-projection-v1"
            or derived.get("derivation_version") != "m-observation-projection-v1" or derived.get("redacted") is not True):
        raise WitnessError("derived_contract")
    parents = derived.get("parent_evidence_ids")
    if not isinstance(parents, list) or len(parents) != 1 or derived.get("source_record_id") != "m-" + str(parents[0]):
        raise WitnessError("derived_parent")
    parent = parent_from_m(m_path, parents[0], node)
    original = parent.get("record")
    if not isinstance(original, dict) or original.get("node_id") != node or original.get("source_id") != "process":
        raise WitnessError("parent_identity")
    outer_payload = original.get("payload")
    source = outer_payload.get("source") if isinstance(outer_payload, dict) else None
    if not isinstance(source, dict) or source.get("payload") != component.get("value") or derived.get("payload") != component.get("value"):
        raise WitnessError("parent_payload")
    if original.get("process_epoch") != derived.get("process_epoch") or data.get("process_epoch") != derived.get("process_epoch"):
        raise WitnessError("parent_epoch")
    observed = original.get("observed_at_ms")
    if type(observed) is not int or not 0 <= as_of_ms - observed <= 180000:
        raise WitnessError("parent_age")
    observed_text = dt.datetime.fromtimestamp(observed / 1000, dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if derived.get("observed_at") != observed_text:
        raise WitnessError("parent_time")
    source_payload = source.get("payload")
    if not isinstance(source_payload, dict) or type(source_payload.get("pid")) is not int or source_payload["pid"] <= 0 or derived.get("clock_quality") != "valid":
        raise WitnessError("parent_clock_or_pid")
    return observed


def validate_negative(envelope, code, run):
    if (envelope.get("run_id") != run or envelope.get("status") != "error"
            or envelope.get("error", {}).get("code") != code
            or envelope.get("coverage", {}).get("status") != "unknown"
            or envelope.get("data") is not None or envelope.get("evidence") != []):
        raise WitnessError("negative_" + code.lower())


def ledger_growth(path, baseline):
    uri = "file:" + str(Path(path).resolve()) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=0.5)
    try:
        conn.execute("PRAGMA query_only=ON")
        count, body = conn.execute("SELECT count(*),coalesce(sum(length(body)),0) FROM query_grants").fetchone()
        attempts = conn.execute("SELECT count(*) FROM query_attempts").fetchone()[0]
    finally:
        conn.close()
    if count < baseline[0] or body < baseline[1] or attempts < baseline[2]:
        raise WitnessError("ledger_regression")
    if count > baseline[0] + 1024 or body > baseline[1] + 32 * 1024 * 1024 or attempts > baseline[2] + 3072:
        raise WitnessError("ledger_growth")
    return count - baseline[0]


def bound_service(unit, expected_sha, control_path, mcp_path, m_path):
    output = subprocess.check_output(["systemctl", "--user", "show", unit, "-p", "MainPID", "--value"], timeout=2)
    pid = int(output.strip())
    if pid <= 1:
        raise WitnessError("query_pid")
    with open(f"/proc/{pid}/exe", "rb") as executable:
        digest = hashlib.file_digest(executable, "sha256").hexdigest()
    if digest != expected_sha:
        raise WitnessError("query_binary")
    args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    for path in (control_path, mcp_path, m_path):
        if os.fsencode(path) not in args:
            raise WitnessError("query_binding")
    return pid


def open_log(path):
    parent = os.stat(Path(path).parent, follow_symlinks=False)
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise WitnessError("log_directory")
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    meta = os.fstat(fd)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077 or meta.st_nlink != 1:
        os.close(fd)
        raise WitnessError("log_file")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if meta.st_size > LOG_LIMIT:
        os.close(fd)
        raise WitnessError("log_full")
    return fd


def append_log(fd, sample):
    body = (json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(body) > 1024 or os.fstat(fd).st_size + len(body) > LOG_LIMIT:
        raise WitnessError("log_full")
    if os.write(fd, body) != len(body):
        raise WitnessError("log_short_write")
    os.fsync(fd)


def run(args):
    slot = int(time.time()) // SLOT_SECONDS
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    boottime_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    fd = open_log(args.log_file)
    leases = []
    operator = None
    phase = "preflight"
    status = "failed"
    error_kind = None
    cleanup_ok = True
    ledger_delta = None
    started = time.monotonic_ns()
    try:
        size = os.fstat(fd).st_size
        if size:
            os.lseek(fd, max(0, size - 2048), os.SEEK_SET)
            last = os.read(fd, min(size, 2048)).splitlines()[-1]
            previous = checked_json(last, 1024)
            if previous.get("slot") == slot:
                raise WitnessError("duplicate_slot")
            if previous.get("boot_id") == boot_id:
                prior = previous.get("boottime_ns")
                if type(prior) is not int or boottime_ns < prior or boottime_ns - prior < SLOT_SECONDS * 1_000_000_000:
                    raise WitnessError("sample_too_soon")
        operator = private_token(args.operator_token_file)
        service = private_token(args.service_token_file)
        bound_service(args.query_unit, args.expected_query_sha256, args.control_socket, args.mcp_socket, args.m_db)
        ledger_delta = ledger_growth(args.q_ledger, (args.baseline_grants, args.baseline_grant_bytes, args.baseline_attempts))
        now = dt.datetime.now(dt.timezone.utc)
        end = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        start = (now - dt.timedelta(minutes=4)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        node = NODES[slot % len(NODES)]
        phase = "grant"
        run_id, run_token = issue(args.control_socket, operator, node, start, end, leases)
        phase = "process"
        session = McpSession(args.mcp_socket, service, run_id, run_token)
        try:
            session.initialize()
            envelope = session.snapshot(run_id, node, end, "process")
            validate_process(envelope, run_id, node, int(now.timestamp() * 1000), args.m_db)
            if slot % 12 == 0:
                phase = "consensus_negative"
                validate_negative(session.snapshot(run_id, node, end, "consensus"), "CACHE_MISS", run_id)
        finally:
            session.close()
        if slot % 12 == 0:
            phase = "scope_grant"
            other = NODES[(slot + 1) % len(NODES)]
            other_run, other_token = issue(args.control_socket, operator, other, start, end, leases)
            phase = "scope_negative"
            session = McpSession(args.mcp_socket, service, other_run, other_token)
            try:
                session.initialize()
                validate_negative(session.snapshot(other_run, node, end, "process"), "OUT_OF_SCOPE", other_run)
            finally:
                session.close()
        status = "pass"
    except WitnessError as exc:
        error_kind = exc.kind
    except Exception as exc:
        error_kind = type(exc).__name__
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for run_id in reversed(leases):
            cleanup_ok = bool(operator and run_id) and revoke(args.control_socket, operator, run_id) and cleanup_ok
        if not cleanup_ok:
            status = "failed"
            error_kind = "cleanup_unconfirmed"
        sample = {"schema_version": 1, "slot": slot, "boot_id": boot_id, "boottime_ns": boottime_ns,
                  "wall_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                  "status": status, "phase": phase, "error_kind": error_kind,
                  "negative_controls": slot % 12 == 0, "grants_created": len(leases),
                  "cleanup_confirmed": cleanup_ok, "q_grants_since_baseline": ledger_delta,
                  "elapsed_ms": (time.monotonic_ns() - started) // 1_000_000}
        append_log(fd, sample)
        os.close(fd)
    return 0 if status == "pass" else 1


def main():
    parser = argparse.ArgumentParser()
    for name in ("control-socket", "mcp-socket", "operator-token-file", "service-token-file", "m-db",
                 "q-ledger", "log-file", "query-unit", "expected-query-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("baseline-grants", "baseline-grant-bytes", "baseline-attempts"):
        parser.add_argument("--" + name, required=True, type=int)
    args = parser.parse_args()
    if any(getattr(args, name) < 0 for name in ("baseline_grants", "baseline_grant_bytes", "baseline_attempts")) or len(args.expected_query_sha256) != 64:
        parser.error("invalid pinned baseline or binary digest")
    def expired(_signum, _frame):
        raise TimeoutError("functional witness deadline")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 22)
    try:
        code = run(args)
        error_kind = None
    except Exception as exc:
        code = 1
        error_kind = exc.kind if isinstance(exc, WitnessError) else type(exc).__name__
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps({"witness_ok": code == 0, "status": "pass" if code == 0 else "failed",
                      "instrument_error": error_kind}, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
