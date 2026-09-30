#!/usr/bin/env python3
"""One bounded, low-rate private QueryService functional witness. No model calls."""

import argparse
from contextlib import contextmanager
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
CONTROL_TIMEOUT_S = 3
MCP_TIMEOUT_S = 5
SQLITE_TIMEOUT_S = 0.5
WHOLE_RUN_TIMEOUT_S = 22
SERVICE_GRANT_EXPIRY_S = 200
MAX_REQUEST_BYTES = 4096
MAX_CONTROL_BYTES = 4096
LIMIT = 32768
MAX_LOG_ROW_BYTES = 1024
MAX_REVIEW_BYTES = 1024
SLOT_SECONDS = 300
LOG_LIMIT = 4 * 1024 * 1024
MAX_NEW_GRANTS = 1024
MAX_NEW_GRANT_BODY_BYTES = 32 * 1024 * 1024
MAX_NEW_ATTEMPTS = 3072


class WitnessError(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


class WholeRunTimeout(TimeoutError):
    pass


@contextmanager
def call_deadline(seconds):
    """Preserve the shorter whole-run alarm around one blocking socket call."""
    remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    signal.setitimer(signal.ITIMER_REAL, min(seconds, remaining) if remaining > 0 else seconds)
    try:
        yield
    finally:
        if remaining > 0:
            signal.setitimer(signal.ITIMER_REAL, max(0.000001, remaining - (time.monotonic() - started)), interval)
        else:
            signal.setitimer(signal.ITIMER_REAL, 0)


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
    if encoded is not None and len(encoded) > MAX_REQUEST_BYTES:
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
    conn = UnixHTTP(socket_path, timeout=CONTROL_TIMEOUT_S)
    try:
        with call_deadline(CONTROL_TIMEOUT_S):
            return request(conn, method, path, body, {"Authorization": "Bearer " + token}, MAX_CONTROL_BYTES)
    finally:
        conn.close()


def projection_head(socket_path, service_token):
    status, headers, raw = control(socket_path, service_token, "GET", "/v1/control/projection-health")
    if status not in (200, 503) or headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise WitnessError("projection_http")
    value = checked_json(raw, MAX_CONTROL_BYTES)
    name = value.get("projection_status")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1 or name not in (
            "caught_up", "lagging", "conflict", "source_unavailable", "uninitialized",
            "identity_or_watermark_mismatch"):
        raise WitnessError("projection_shape")
    conflicted = value.get("manager_conflicted")
    caught = value.get("caught_up_at_last_import")
    identity = value.get("source_identity_match")
    cursor = value.get("cursor_global_m_seq")
    source = value.get("source_global_m_seq")
    lag = value.get("lag_global_m_seq")
    if type(conflicted) is not bool or type(caught) is not bool or not (type(identity) is bool or identity is None):
        raise WitnessError("projection_shape")
    for number in (cursor, source, lag):
        if number is not None and (not isinstance(number, str) or re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", number) is None
                                   or int(number) > 2**64 - 1):
            raise WitnessError("projection_counter")
    if cursor is not None and source is not None and lag is not None:
        if int(source) < int(cursor) or int(source) - int(cursor) != int(lag):
            raise WitnessError("projection_lag")
    if name == "caught_up" and not (status == 200 and not conflicted and caught and identity is True
                                    and isinstance(cursor, str) and source == cursor and lag == "0"):
        raise WitnessError("projection_false_caught_up")
    if name == "lagging" and not (status == 200 and not conflicted and identity is True
                                  and isinstance(lag, str) and (not caught or lag != "0")):
        raise WitnessError("projection_false_lagging")
    if name == "conflict" and not (status == 503 and conflicted):
        raise WitnessError("projection_false_conflict")
    return name


def issue(socket_path, token, node, start, end, leases):
    # A transport timeout can occur after Q commits a grant but before its
    # run ID reaches us. The unknown side effect must fail cleanup confirmation.
    leases.append(None)
    status, headers, raw = control(socket_path, token, "POST", "/v1/control/grants",
                             {"node_ids": [node], "scope_ids": ["node"], "start": start, "end": end})
    if status != 200:
        # A non-200 reply is not proof that no durable side effect occurred.
        # Without a returned run ID, cleanup cannot be confirmed.
        raise WitnessError("grant_refused")
    # A 200 may have created a grant even if its response cannot be decoded.
    if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise WitnessError("grant_content_type")
    value = checked_json(raw, MAX_CONTROL_BYTES)
    run, secret = value.get("run_id"), value.get("run_token")
    if not isinstance(run, str) or re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", run) is None:
        raise WitnessError("grant_shape")
    leases[-1] = run
    if value.get("expires_in_seconds") != SERVICE_GRANT_EXPIRY_S:
        raise WitnessError("grant_expiry")
    if not isinstance(secret, str) or len(secret) != 64 or any(c not in "0123456789abcdef" for c in secret):
        raise WitnessError("grant_shape")
    return run, secret


def revoke(socket_path, token, run):
    try:
        status, headers, raw = control(socket_path, token, "POST", "/v1/control/grants/" + run + "/revoke")
        return (status == 200 and headers.get("content-type", "").split(";", 1)[0].strip().lower() == "application/json"
                and checked_json(raw, MAX_CONTROL_BYTES).get("revoked") is True)
    except (OSError, TimeoutError, WitnessError, http.client.HTTPException):
        return False


class McpSession:
    def __init__(self, socket_path, service_token, run, run_token):
        self.conn = UnixHTTP(socket_path, timeout=MCP_TIMEOUT_S)
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
        with call_deadline(MCP_TIMEOUT_S):
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
        with call_deadline(MCP_TIMEOUT_S):
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


def validate_process(envelope, run, node, as_of_ms, parent):
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


def frozen_baseline(path, expected_digest, expected_query_sha, window_id=None):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or meta.st_mode & 0o077 or meta.st_nlink != 1 or meta.st_size > 2048):
            raise WitnessError("baseline_file")
        raw = os.read(fd, 2049)
        if len(raw) != meta.st_size or hashlib.sha256(raw).hexdigest() != expected_digest:
            raise WitnessError("baseline_digest")
    finally:
        os.close(fd)
    value = checked_json(raw, 2048)
    required = {"schema_version", "q_device", "q_inode", "grants", "grant_body_bytes", "attempts",
                "query_sha256", "max_new_grants", "max_new_grant_body_bytes", "max_new_attempts"}
    if window_id is not None:
        required |= {"window_id", "prior_log_sha256", "prior_marker_sha256", "boot_id", "time_namespace"}
    if (set(value) != required or type(value["schema_version"]) is not int
            or value["schema_version"] != (2 if window_id is not None else 1)
            or value["query_sha256"] != expected_query_sha):
        raise WitnessError("baseline_schema")
    if window_id is not None and (value["window_id"] != window_id
                               or any(re.fullmatch(r"[0-9a-f]{64}", value[key]) is None
                                      for key in ("prior_log_sha256", "prior_marker_sha256"))
                               or value["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                               or value["time_namespace"] != os.readlink("/proc/self/ns/time")):
        raise WitnessError("baseline_window")
    for key in ("q_device", "q_inode"):
        if not isinstance(value[key], str) or not value[key].isascii() or not value[key].isdecimal():
            raise WitnessError("baseline_schema")
    for key in ("grants", "grant_body_bytes", "attempts"):
        if type(value[key]) is not int or value[key] < 0:
            raise WitnessError("baseline_schema")
    if (value["max_new_grants"] != MAX_NEW_GRANTS
            or value["max_new_grant_body_bytes"] != MAX_NEW_GRANT_BODY_BYTES
            or value["max_new_attempts"] != MAX_NEW_ATTEMPTS):
        raise WitnessError("baseline_budget")
    return value


def ledger_growth(path, baseline, reserve_grants=0, reserve_attempts=0):
    meta = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(meta.st_mode) or str(meta.st_dev) != baseline["q_device"] or str(meta.st_ino) != baseline["q_inode"]:
        raise WitnessError("q_ledger_identity")
    uri = "file:" + str(Path(path).resolve()) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=SQLITE_TIMEOUT_S)
    try:
        conn.execute("PRAGMA query_only=ON")
        count, body = conn.execute("SELECT count(*),coalesce(sum(length(body)),0) FROM query_grants").fetchone()
        attempts = conn.execute("SELECT count(*) FROM query_attempts").fetchone()[0]
    finally:
        conn.close()
    end_meta = os.stat(path, follow_symlinks=False)
    if end_meta.st_dev != meta.st_dev or end_meta.st_ino != meta.st_ino:
        raise WitnessError("q_ledger_identity")
    if count < baseline["grants"] or body < baseline["grant_body_bytes"] or attempts < baseline["attempts"]:
        raise WitnessError("ledger_regression")
    if (count + reserve_grants > baseline["grants"] + MAX_NEW_GRANTS
            or body + reserve_grants * 32768 > baseline["grant_body_bytes"] + MAX_NEW_GRANT_BODY_BYTES
            or attempts + reserve_attempts > baseline["attempts"] + MAX_NEW_ATTEMPTS):
        raise WitnessError("ledger_growth")
    return count - baseline["grants"]


def ledger_revoked(path, baseline, runs):
    meta = os.stat(path, follow_symlinks=False)
    if str(meta.st_dev) != baseline["q_device"] or str(meta.st_ino) != baseline["q_inode"]:
        return False
    conn = sqlite3.connect("file:" + str(Path(path).resolve()) + "?mode=ro", uri=True, timeout=SQLITE_TIMEOUT_S)
    try:
        conn.execute("PRAGMA query_only=ON")
        for run in runs:
            if conn.execute("SELECT revoked FROM query_grants WHERE run_id=?", (run,)).fetchone() != (1,):
                return False
    finally:
        conn.close()
    end = os.stat(path, follow_symlinks=False)
    return (end.st_dev, end.st_ino) == (meta.st_dev, meta.st_ino)


def process_owns_db(pid, path):
    expected = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(expected.st_mode):
        raise WitnessError("q_ledger_identity")
    with os.scandir(f"/proc/{pid}/fd") as entries:
        for count, entry in enumerate(entries):
            if count >= 256:
                raise WitnessError("query_fds")
            try:
                opened = os.stat(entry.path)
            except OSError:
                continue
            if opened.st_dev == expected.st_dev and opened.st_ino == expected.st_ino:
                return
    raise WitnessError("query_ledger_not_open")


def verify_retained_binding(envelope, run, q_path, m_path, baseline, pid):
    if envelope.get("run_id") != run:
        raise WitnessError("frozen_grant_binding")
    evidence = envelope["evidence"][0]
    query_id = evidence.get("evidence_id")
    parent_id = evidence["parent_evidence_ids"][0]
    if (not isinstance(query_id, str) or len(query_id) != 64
            or any(c not in "0123456789abcdef" for c in query_id)
            or not isinstance(parent_id, str) or len(parent_id) != 64
            or any(c not in "0123456789abcdef" for c in parent_id)):
        raise WitnessError("derived_id")
    m_meta = os.stat(m_path, follow_symlinks=False)
    q_meta = os.stat(q_path, follow_symlinks=False)
    if not stat.S_ISREG(m_meta.st_mode) or not stat.S_ISREG(q_meta.st_mode):
        raise WitnessError("database_identity")
    if str(q_meta.st_dev) != baseline["q_device"] or str(q_meta.st_ino) != baseline["q_inode"]:
        raise WitnessError("q_ledger_identity")
    process_owns_db(pid, q_path)
    m = sqlite3.connect("file:" + str(Path(m_path).resolve()) + "?mode=ro", uri=True, timeout=SQLITE_TIMEOUT_S)
    q = sqlite3.connect("file:" + str(Path(q_path).resolve()) + "?mode=ro", uri=True, timeout=SQLITE_TIMEOUT_S)
    try:
        m.execute("PRAGMA query_only=ON")
        q.execute("PRAGMA query_only=ON")
        m.execute("BEGIN TRANSACTION")
        q.execute("BEGIN TRANSACTION")
        cursor = q.execute("SELECT network,device,inode,watermark FROM query_manager_cursor WHERE singleton=1").fetchone()
        if not cursor:
            raise WitnessError("retained_binding_missing")
        frozen = q.execute("SELECT body FROM query_grants WHERE run_id=?", (run,)).fetchone()
        if not frozen:
            raise WitnessError("frozen_grant_missing")
        grant = checked_json(frozen[0], 32768)
        q_limit, m_limit = grant.get("watermark"), grant.get("manager_watermark")
        if (grant.get("run_id") != run or grant.get("network_id") != cursor[0]
                or type(q_limit) is not int or type(m_limit) is not int
                or q_limit <= 0 or m_limit <= 0
                or envelope["data"]["node_id"] not in grant.get("nodes", [])
                or "node" not in grant.get("scopes", [])):
            raise WitnessError("frozen_grant_binding")
        binding = q.execute("SELECT o.manager_seq,o.body,e.store_seq FROM query_projection_origin p "
                            "JOIN query_origins o ON o.origin_id=p.origin_id "
                            "JOIN query_evidence e ON e.evidence_id=p.query_evidence_id "
                            "WHERE p.query_evidence_id=? AND p.origin_id=? LIMIT 2",
                            (query_id, parent_id)).fetchall()
        if not cursor or len(binding) != 1:
            raise WitnessError("retained_binding_missing")
        manager_seq, q_body, q_seq = binding[0]
        if (type(manager_seq) is not int or manager_seq <= 0 or manager_seq > m_limit
                or type(q_seq) is not int or q_seq <= 0 or q_seq > q_limit):
            raise WitnessError("retained_source_identity")
        network = m.execute("SELECT network FROM database_identity WHERE singleton=1").fetchone()
        source = m.execute("SELECT content_hash,node,scope,process_epoch,source_epoch,source,body "
                           "FROM observations WHERE store_seq=?", (manager_seq,)).fetchone()
        if not network or not source:
            raise WitnessError("retained_binding_missing")
        content_hash, node, scope, process_epoch, source_epoch, source_name, m_body = source
        if (cursor[0] != network[0] or cursor[1] != str(m_meta.st_dev)
                or cursor[2] != str(m_meta.st_ino) or manager_seq > cursor[3]
                or content_hash != parent_id or node != envelope["data"]["node_id"]
                or source_name != "process"):
            raise WitnessError("retained_source_identity")
        parent = checked_json(m_body.encode(), 32768)
        original = parent.get("record")
        if not isinstance(original, dict):
            raise WitnessError("parent_shape")
        if (node != original.get("node_id") or scope != original.get("scope_id")
                or process_epoch != original.get("process_epoch")
                or source_epoch != parent.get("source_epoch") or source_name != original.get("source_id")):
            raise WitnessError("retained_source_tuple")
        quarantined = m.execute("SELECT 1 FROM quarantined WHERE node=? AND scope=? AND process_epoch=? "
                                "AND source_epoch=? AND source=? LIMIT 1",
                                (node, scope, process_epoch, source_epoch, source_name)).fetchone()
        if quarantined:
            raise WitnessError("retained_parent_quarantined")
        canonical = json.loads(json.dumps(parent))
        canonical["record"]["received_at_ms"] = 0
        digest = hashlib.sha256(json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        if digest != parent_id:
            raise WitnessError("parent_hash")
        expected = json.dumps({"store_seq": str(manager_seq), "evidence_id": parent_id,
                               "evidence": parent},
                              ensure_ascii=False, separators=(",", ":")).encode()
        if q_body != expected:
            raise WitnessError("retained_parent_changed")
    finally:
        m.close()
        q.close()
    m_end = os.stat(m_path, follow_symlinks=False)
    q_end = os.stat(q_path, follow_symlinks=False)
    if (m_end.st_dev, m_end.st_ino) != (m_meta.st_dev, m_meta.st_ino) or (q_end.st_dev, q_end.st_ino) != (q_meta.st_dev, q_meta.st_ino):
        raise WitnessError("database_replaced")
    return parent


def bound_service(unit, expected_sha, control_path, mcp_path, m_path, q_path):
    output = subprocess.check_output(["systemctl", "--user", "show", unit, "-p", "MainPID", "--value"], timeout=2)
    pid = int(output.strip())
    if pid <= 1:
        raise WitnessError("query_pid")
    with open(f"/proc/{pid}/exe", "rb") as executable:
        digest_state = hashlib.sha256()
        for block in iter(lambda: executable.read(1024 * 1024), b""):
            digest_state.update(block)
        digest = digest_state.hexdigest()
    if digest != expected_sha:
        raise WitnessError("query_binary")
    args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    for path in (control_path, mcp_path, m_path, q_path):
        if os.fsencode(path) not in args:
            raise WitnessError("query_binding")
    process_owns_db(pid, q_path)
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
    # Leave room for a complete failure row before any grant can be issued.
    if meta.st_size + MAX_LOG_ROW_BYTES > LOG_LIMIT:
        os.close(fd)
        raise WitnessError("log_full")
    return fd


def reviewed_failure(path, failed_row, highwater):
    if not path:
        return None
    directory = os.stat(Path(path).parent, follow_symlinks=False)
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or directory.st_mode & 0o077:
        raise WitnessError("review_directory")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or meta.st_mode & 0o077 or meta.st_nlink != 1 or meta.st_size > MAX_REVIEW_BYTES):
            raise WitnessError("review_file")
        raw = os.read(fd, MAX_REVIEW_BYTES + 1)
        if len(raw) != meta.st_size:
            raise WitnessError("review_file")
    finally:
        os.close(fd)
    value = checked_json(raw, MAX_REVIEW_BYTES)
    if (set(value) != {"schema_version", "failed_row_sha256", "slot_highwater", "reviewer", "reviewed_at_utc"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["slot_highwater"]) is not int
            or value["slot_highwater"] != highwater
            or value["failed_row_sha256"] != hashlib.sha256(failed_row).hexdigest()
            or not isinstance(value["reviewer"], str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value["reviewer"]) is None):
        raise WitnessError("review_mismatch")
    try:
        reviewed = dt.datetime.fromisoformat(value["reviewed_at_utc"].replace("Z", "+00:00"))
        if reviewed.utcoffset() != dt.timedelta(0) or reviewed > dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=60):
            raise ValueError("review time")
        failed = dt.datetime.fromisoformat(checked_json(failed_row, MAX_LOG_ROW_BYTES)["wall_utc"].replace("Z", "+00:00"))
        if failed.utcoffset() != dt.timedelta(0) or reviewed <= failed:
            raise ValueError("review time")
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise WitnessError("review_time") from exc
    return hashlib.sha256(raw).hexdigest()


def inflight_path(log_path):
    return log_path + ".inflight"


def sync_parent(path):
    fd = os.open(str(Path(path).parent), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def start_inflight(log_path, slot, boot_id):
    path = inflight_path(log_path)
    raw = json.dumps({"schema_version": 1, "slot": slot, "boot_id": boot_id,
                      "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat()}, separators=(",", ":")).encode()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except FileExistsError as exc:
        raise WitnessError("inflight_review_required") from exc
    try:
        if os.write(fd, raw) != len(raw):
            raise WitnessError("inflight_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_parent(path)


def finish_inflight(log_path):
    path = inflight_path(log_path)
    os.unlink(path)
    sync_parent(path)


def append_log(fd, sample):
    body = (json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(body) > MAX_LOG_ROW_BYTES or os.fstat(fd).st_size + len(body) > LOG_LIMIT:
        raise WitnessError("log_full")
    if os.write(fd, body) != len(body):
        raise WitnessError("log_short_write")
    os.fsync(fd)


def first_successful_sample(fd, size):
    if not size:
        return None
    os.lseek(fd, 0, os.SEEK_SET)
    raw = os.read(fd, size)
    if len(raw) != size or not raw.endswith(b"\n"):
        raise WitnessError("log_incomplete")
    first = None
    for line in raw.splitlines():
        row = checked_json(line, MAX_LOG_ROW_BYTES)
        if (row.get("status") == "pass" and row.get("cleanup_confirmed") is True
                and row.get("fixed_grant_query_status") == "pass" and first is None):
            first = row
    return first


def run(args):
    slot = int(time.time()) // SLOT_SECONDS
    slot_highwater = slot
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    boottime_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    fd = open_log(args.log_file)
    leases = []
    operator = None
    phase = "preflight"
    status = "failed"
    error_kind = None
    primary_error_kind = None
    cleanup_ok = True
    ledger_delta = None
    baseline = None
    fixed_grant_query_status = "not_run"
    head_status = "not_run"
    head_probe_error = None
    review_ack_sha256 = None
    latch_refused = False
    inflight_started = False
    started = time.monotonic_ns()
    try:
        window_id = getattr(args, "window_id", None)
        if window_id is not None and re.fullmatch(r"[0-9a-f]{64}", window_id) is None:
            raise WitnessError("window_id")
        if os.path.lexists(inflight_path(args.log_file)):
            latch_refused = True
            raise WitnessError("inflight_review_required")
        size = os.fstat(fd).st_size
        if size:
            os.lseek(fd, max(0, size - 2048), os.SEEK_SET)
            last = os.read(fd, min(size, 2048)).splitlines()[-1]
            previous = checked_json(last, 1024)
            if window_id is not None and previous.get("window_id") != window_id:
                raise WitnessError("window_mismatch")
            prior_slot = previous.get("slot")
            prior_highwater = previous.get("slot_highwater", prior_slot)
            if (type(prior_slot) is not int or type(prior_highwater) is not int
                    or prior_highwater < prior_slot):
                raise WitnessError("log_slot_invalid")
            slot_highwater = max(slot, prior_highwater)
            if previous.get("status") != "pass" or previous.get("cleanup_confirmed") is not True:
                try:
                    review_ack_sha256 = reviewed_failure(getattr(args, "review_file", None), last, prior_highwater)
                except (OSError, WitnessError):
                    review_ack_sha256 = None
                if review_ack_sha256 is None:
                    latch_refused = True
                    raise WitnessError("operator_review_required")
            if slot <= prior_highwater:
                raise WitnessError("slot_not_advanced")
            if previous.get("boot_id") == boot_id:
                prior = previous.get("boottime_ns")
                if type(prior) is not int or boottime_ns < prior or boottime_ns - prior < SLOT_SECONDS * 1_000_000_000:
                    raise WitnessError("sample_too_soon")
        if getattr(args, "first_pass_not_after_utc", None):
            try:
                first_deadline = dt.datetime.fromisoformat(args.first_pass_not_after_utc.replace("Z", "+00:00"))
            except ValueError as exc:
                raise WitnessError("first_sample_window_config") from exc
            if first_deadline.utcoffset() != dt.timedelta(0):
                raise WitnessError("first_sample_window_config")
            first = first_successful_sample(fd, size)
            if first is None:
                # Leave a full systemd service deadline before the latest
                # valid first-pass row.
                if dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=35) > first_deadline:
                    raise WitnessError("first_sample_window_closed")
            else:
                try:
                    first_wall = dt.datetime.fromisoformat(first["wall_utc"].replace("Z", "+00:00"))
                except (AttributeError, KeyError, TypeError, ValueError) as exc:
                    raise WitnessError("first_sample_clock") from exc
                if (first_wall.utcoffset() != dt.timedelta(0) or first_wall > first_deadline
                        or first.get("boot_id") != boot_id
                        or type(first.get("boottime_ns")) is not int
                        or first["boottime_ns"] > boottime_ns):
                    raise WitnessError("first_sample_window_closed")
        if getattr(args, "not_after_utc", None):
            try:
                end_of_window = dt.datetime.fromisoformat(args.not_after_utc.replace("Z", "+00:00"))
            except ValueError as exc:
                raise WitnessError("window_config") from exc
            if end_of_window.utcoffset() != dt.timedelta(0):
                raise WitnessError("window_config")
            if dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=45) >= end_of_window:
                raise WitnessError("window_closed")
        operator = private_token(args.operator_token_file)
        service = private_token(args.service_token_file)
        baseline = frozen_baseline(args.baseline_file, args.expected_baseline_sha256,
                                   args.expected_query_sha256, window_id)
        pid = bound_service(args.query_unit, args.expected_query_sha256, args.control_socket, args.mcp_socket, args.m_db, args.q_ledger)
        if window_id is not None and os.readlink("/proc/" + str(pid) + "/ns/time") != baseline["time_namespace"]:
            raise WitnessError("q_clock_domain")
        hourly = slot % 12 == 0
        # Reserve the full worst-case cost before any side-effect: each grant
        # body is capped at 32768 bytes by QueryLedger::encoded.
        ledger_delta = ledger_growth(args.q_ledger, baseline, 2 if hourly else 1,
                                     3 if hourly else 1)
        try:
            head_status = projection_head(args.control_socket, service)
        except WholeRunTimeout:
            # The outer 22-second alarm is a whole-run failure, even when it
            # fires during the independent head probe. Never issue a grant.
            raise
        except Exception as exc:
            head_probe_error = exc.kind if isinstance(exc, WitnessError) else type(exc).__name__
            head_status = "probe_failed"
        now = dt.datetime.now(dt.timezone.utc)
        end = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        start = (now - dt.timedelta(minutes=4)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        node = NODES[slot % len(NODES)]
        phase = "grant"
        start_inflight(args.log_file, slot, boot_id)
        inflight_started = True
        run_id, run_token = issue(args.control_socket, operator, node, start, end, leases)
        phase = "process"
        session = McpSession(args.mcp_socket, service, run_id, run_token)
        try:
            session.initialize()
            envelope = session.snapshot(run_id, node, end, "process")
            parent = verify_retained_binding(envelope, run_id, args.q_ledger, args.m_db, baseline, pid)
            validate_process(envelope, run_id, node, int(now.timestamp() * 1000), parent)
            fixed_grant_query_status = "pass"
            if hourly:
                phase = "consensus_negative"
                validate_negative(session.snapshot(run_id, node, end, "consensus"), "CACHE_MISS", run_id)
        finally:
            session.close()
        if hourly:
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
        status = "pass" if head_probe_error is None else "failed"
        if head_probe_error is not None:
            error_kind = "projection_probe_failed"
            primary_error_kind = error_kind
    except WitnessError as exc:
        if latch_refused:
            raise
        error_kind = exc.kind
        primary_error_kind = error_kind
    except Exception as exc:
        error_kind = type(exc).__name__
        primary_error_kind = error_kind
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for run_id in reversed(leases):
            cleanup_ok = bool(operator and run_id) and revoke(args.control_socket, operator, run_id) and cleanup_ok
        if cleanup_ok and leases:
            try:
                cleanup_ok = baseline is not None and ledger_revoked(args.q_ledger, baseline, leases)
            except (OSError, sqlite3.Error, WitnessError):
                cleanup_ok = False
        if not cleanup_ok:
            status = "failed"
            error_kind = "cleanup_unconfirmed"
        try:
            if not latch_refused:
                sample = {"schema_version": 1, "slot": slot, "slot_highwater": slot_highwater,
                          "boot_id": boot_id, "boottime_ns": boottime_ns,
                          "wall_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                          "status": status, "phase": phase, "error_kind": error_kind,
                          "primary_error_kind": primary_error_kind,
                          "cleanup_error_kind": "cleanup_unconfirmed" if not cleanup_ok else None,
                          "negative_controls": slot % 12 == 0, "grants_created": len(leases),
                          "cleanup_confirmed": cleanup_ok, "q_grants_since_baseline": ledger_delta,
                          "fixed_grant_query_status": fixed_grant_query_status,
                          "projection_head_status": head_status, "projection_probe_error": head_probe_error,
                          "review_ack_sha256": review_ack_sha256,
                          "elapsed_ms": (time.monotonic_ns() - started) // 1_000_000}
                if window_id is not None:
                    sample["window_id"] = window_id
                    # The pre-POST unknown lease is an attempted request, not
                    # evidence that Q durably created a grant.
                    sample.pop("grants_created")
                    sample["grant_requests_attempted"] = len(leases)
                    sample["known_run_ids"] = sum(run_id is not None for run_id in leases)
                append_log(fd, sample)
                if status == "pass" and inflight_started:
                    finish_inflight(args.log_file)
        finally:
            os.close(fd)
    return 0 if status == "pass" else 1


def main():
    parser = argparse.ArgumentParser()
    for name in ("control-socket", "mcp-socket", "operator-token-file", "service-token-file", "m-db",
                 "q-ledger", "log-file", "query-unit", "expected-query-sha256", "baseline-file",
                 "expected-baseline-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--review-file")
    parser.add_argument("--not-after-utc")
    parser.add_argument("--first-pass-not-after-utc")
    parser.add_argument("--window-id", required=True)
    args = parser.parse_args()
    if (re.fullmatch(r"[0-9a-f]{64}", args.expected_query_sha256) is None
            or re.fullmatch(r"[0-9a-f]{64}", args.expected_baseline_sha256) is None):
        parser.error("invalid pinned baseline or binary digest")
    def expired(_signum, _frame):
        raise WholeRunTimeout("functional witness deadline")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, WHOLE_RUN_TIMEOUT_S)
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
