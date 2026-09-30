"""Bounded C09 external HTTP first-byte samples; no native-stage or acceptance claim."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from c09_profiles import freeze_plan, MAX_PLAN_BYTES, NATIVE_STAGES

CLOCK_NAME = "CLOCK_MONOTONIC_RAW"
POPULATION = "external_http_first_byte"
OPERATION = "http_get_first_byte"
MAX_RECORDS = 65536
MAX_BYTES = 16 * 1024 * 1024
MAX_ROW_BYTES = 512
MAX_DURATION_NS = 3600 * 1_000_000_000
ROLES = ("V", "edge", "M", "O", "A")
OUTCOMES = {"ok", "http_error", "error", "timeout"}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def decimal(value: Any) -> int:
    if type(value) is not str or not value or (len(value) > 1 and value[0] == "0") or any(c not in "0123456789" for c in value):
        raise ValueError("noncanonical decimal timestamp")
    return int(value)


def _identity() -> tuple[str, str]:
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    ns = os.stat("/proc/self/ns/time")
    stat = Path("/proc/self/stat").read_text()
    start_ticks = stat.rsplit(")", 1)[1].split()[19]
    domain = hashlib.sha256(f"{CLOCK_NAME}:{boot}:{ns.st_dev}:{ns.st_ino}".encode()).hexdigest()
    epoch = hashlib.sha256(f"{domain}:{os.getpid()}:{start_ticks}".encode()).hexdigest()
    return domain, epoch


@dataclass(frozen=True)
class Point:
    process_epoch: str
    clock_domain_id: str
    clock_name: str
    monotonic_ns: str


def duration_ns(start: Point, finish: Point) -> str:
    if (start.process_epoch != finish.process_epoch or not start.process_epoch or
            start.clock_domain_id != finish.clock_domain_id or not start.clock_domain_id or
            start.clock_name != CLOCK_NAME or finish.clock_name != CLOCK_NAME):
        raise ValueError("process or clock domain mismatch")
    a, b = decimal(start.monotonic_ns), decimal(finish.monotonic_ns)
    if b < a or b - a > MAX_DURATION_NS:
        raise ValueError("reversed or unbounded duration")
    return str(b - a)


def _sample(domain: str, epoch: str) -> Point:
    return Point(epoch, domain, CLOCK_NAME, str(time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)))


def _open_new(path: Path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "wb")


def resource_ledger() -> dict[str, dict[str, str]]:
    return {role: {"status": "not_run"} for role in ROLES}


def _validate_ledger(ledger: dict[str, Any]) -> None:
    if type(ledger) is not dict or set(ledger) != set(ROLES):
        raise ValueError("incomplete resource ledger")
    for entry in ledger.values():
        if entry != {"status": "not_run"}:
            raise ValueError("resource measurements are not wired")


class Capture:
    def __init__(self, path: Path, *, plan_sha256: str, profile: str, workload: str,
                 round_index: int, requested: int, max_records: int = MAX_RECORDS,
                 max_bytes: int = MAX_BYTES):
        if (type(requested) is not int or not 0 < requested <= MAX_RECORDS or
                type(max_records) is not int or not 0 < max_records <= MAX_RECORDS or
                type(max_bytes) is not int or not 0 < max_bytes <= MAX_BYTES):
            raise ValueError("invalid capture bound")
        if type(plan_sha256) is not str or len(plan_sha256) != 64 or any(c not in "0123456789abcdef" for c in plan_sha256):
            raise ValueError("invalid plan hash")
        if profile not in "ABCDEF" or len(profile) != 1 or workload not in ("normal", "high", "maximum_approved") or type(round_index) is not int or round_index < 0:
            raise ValueError("invalid frozen run identity")
        self.path = Path(path)
        self.plan_sha256, self.profile, self.workload, self.round_index = plan_sha256, profile, workload, round_index
        self.requested, self.max_records, self.max_bytes = requested, max_records, max_bytes
        self.clock_domain_id, self.process_epoch = _identity()
        self.clock_resolution_ns = math.ceil(time.clock_getres(time.CLOCK_MONOTONIC_RAW) * 1_000_000_000)
        self.attempted = self.retained = self.dropped = self.invalid = self.bytes_used = 0
        self._hash = hashlib.sha256()
        self._closed = False
        self._out = _open_new(self.path)

    def start(self) -> Point:
        if self._closed:
            raise ValueError("capture closed")
        if self.attempted >= self.requested:
            raise ValueError("requested count exceeded")
        if _identity() != (self.clock_domain_id, self.process_epoch):
            raise ValueError("process or domain changed")
        point = _sample(self.clock_domain_id, self.process_epoch)
        if _identity() != (self.clock_domain_id, self.process_epoch):
            raise ValueError("process or domain changed during start")
        return point

    def finish(self, start: Point, outcome: str) -> bool:
        if self._closed or self.attempted >= self.requested:
            raise ValueError("capture closed or request bound exceeded")
        self.attempted += 1
        try:
            if outcome not in OUTCOMES or _identity() != (self.clock_domain_id, self.process_epoch):
                raise ValueError("invalid outcome or changed process/domain")
            finish = _sample(self.clock_domain_id, self.process_epoch)
            if _identity() != (self.clock_domain_id, self.process_epoch):
                raise ValueError("process or domain changed during finish")
            delta = duration_ns(start, finish)
            if start.process_epoch != self.process_epoch or start.clock_domain_id != self.clock_domain_id:
                raise ValueError("foreign capture point")
            row = canonical({"seq": self.attempted, "profile": self.profile, "round": self.round_index,
                             "workload": self.workload, "population": POPULATION, "operation": OPERATION,
                             "outcome": outcome, "start_ns": start.monotonic_ns,
                             "finish_ns": finish.monotonic_ns, "duration_ns": delta,
                             "process_epoch": self.process_epoch, "clock_domain_id": self.clock_domain_id,
                             "clock_name": CLOCK_NAME})
            if len(row) > MAX_ROW_BYTES:
                raise ValueError("raw row exceeds bound")
        except (ValueError, TypeError):
            self.invalid += 1
            raise
        if self.retained >= self.max_records or self.bytes_used + len(row) > self.max_bytes:
            self.dropped += 1
            return False
        self._out.write(row)
        self._hash.update(row)
        self.retained += 1
        self.bytes_used += len(row)
        return True

    def close(self, *, stopped_early: bool = False, ledger: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._closed:
            raise ValueError("capture closed")
        ledger = resource_ledger() if ledger is None else ledger
        _validate_ledger(ledger)
        self._out.flush()
        os.fsync(self._out.fileno())
        self._out.close()
        self._closed = True
        manifest = {"schema_version": 1, "kind": "c09_raw_capture", "population": POPULATION,
                    "operation": OPERATION, "plan_sha256": self.plan_sha256, "profile": self.profile,
                    "workload": self.workload, "round": self.round_index,
                    "clock_name": CLOCK_NAME, "clock_domain_id": self.clock_domain_id,
                    "process_epoch": self.process_epoch, "clock_resolution_ns": self.clock_resolution_ns,
                    "requested": self.requested, "attempted": self.attempted, "retained": self.retained,
                    "dropped": self.dropped, "invalid": self.invalid, "stopped_early": bool(stopped_early),
                    "capacity_records": self.max_records, "capacity_bytes": self.max_bytes,
                    "retained_bytes": self.bytes_used, "raw_sha256": self._hash.hexdigest(),
                    "resource_ledger": ledger,
                    "native_stages": {stage: "not_run" for stage in NATIVE_STAGES},
                    "complete": self.attempted == self.requested and self.dropped == 0 and self.invalid == 0 and not stopped_early}
        with _open_new(self.path.with_name(self.path.name + ".manifest.json")) as out:
            out.write(canonical(manifest))
            out.flush()
            os.fsync(out.fileno())
        return manifest


def verify_capture(path: Path, *, require_complete: bool = True) -> dict[str, Any]:
    path = Path(path)
    manifest_path = path.with_name(path.name + ".manifest.json")
    if not manifest_path.is_file() or manifest_path.stat().st_size > 8192:
        raise ValueError("missing or unbounded completion manifest")
    encoded = manifest_path.read_bytes()
    manifest = json.loads(encoded)
    if encoded != canonical(manifest):
        raise ValueError("noncanonical manifest")
    if (manifest.get("kind") != "c09_raw_capture" or manifest.get("schema_version") != 1 or
            manifest.get("population") != POPULATION or manifest.get("operation") != OPERATION or
            manifest.get("clock_name") != CLOCK_NAME or
            manifest.get("native_stages") != {stage: "not_run" for stage in NATIVE_STAGES}):
        raise ValueError("invalid capture identity")
    _validate_ledger(manifest.get("resource_ledger"))
    if any(type(manifest.get(k)) is not int or manifest[k] < 0 for k in
           ("requested", "attempted", "retained", "dropped", "invalid", "capacity_records", "capacity_bytes", "retained_bytes", "clock_resolution_ns", "round")):
        raise ValueError("invalid manifest count")
    if not (0 < manifest["requested"] <= MAX_RECORDS and 0 < manifest["capacity_records"] <= MAX_RECORDS and
            0 < manifest["capacity_bytes"] <= MAX_BYTES and manifest["attempted"] <= manifest["requested"] and
            manifest["retained"] <= manifest["capacity_records"] and
            manifest["attempted"] == manifest["retained"] + manifest["dropped"] + manifest["invalid"] and
            manifest["retained_bytes"] <= manifest["capacity_bytes"]):
        raise ValueError("inconsistent capture counts")
    complete = manifest["attempted"] == manifest["requested"] and manifest["dropped"] == 0 and manifest["invalid"] == 0 and not manifest.get("stopped_early")
    if type(manifest.get("complete")) is not bool or manifest["complete"] != complete or (require_complete and not complete):
        raise ValueError("incomplete capture")
    if path.stat().st_size > MAX_BYTES or path.stat().st_size != manifest["retained_bytes"]:
        raise ValueError("raw size mismatch")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest.get("raw_sha256"):
        raise ValueError("raw hash mismatch")
    rows = raw.splitlines(keepends=True)
    if len(rows) != manifest["retained"]:
        raise ValueError("raw count mismatch")
    prior_seq = 0
    for index, line in enumerate(rows, 1):
        if len(line) > MAX_ROW_BYTES:
            raise ValueError("row too large")
        row = json.loads(line)
        if line != canonical(row) or set(row) != {"seq", "profile", "round", "workload", "population", "operation", "outcome", "start_ns", "finish_ns", "duration_ns", "process_epoch", "clock_domain_id", "clock_name"}:
            raise ValueError("invalid raw row")
        if (type(row["seq"]) is not int or not prior_seq < row["seq"] <= manifest["attempted"] or
                (complete and row["seq"] != index) or row["population"] != POPULATION or
                row["operation"] != OPERATION or row["outcome"] not in OUTCOMES or
                any(row[key] != manifest[key] for key in ("profile", "round", "workload"))):
            raise ValueError("wrong sequence or population")
        prior_seq = row["seq"]
        start = Point(row["process_epoch"], row["clock_domain_id"], row["clock_name"], row["start_ns"])
        finish = Point(row["process_epoch"], row["clock_domain_id"], row["clock_name"], row["finish_ns"])
        if (start.process_epoch != manifest["process_epoch"] or
                start.clock_domain_id != manifest["clock_domain_id"] or
                duration_ns(start, finish) != row["duration_ns"]):
            raise ValueError("invalid duration identity")
    return manifest


def _loopback_target(url: str, fixed_path: str) -> tuple[str, int]:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or parsed.path != fixed_path:
        raise ValueError("only fixed-path local HTTP is allowed")
    try:
        host = parsed.hostname
        address = ipaddress.ip_address(host or "")
        port = parsed.port
    except ValueError:
        raise ValueError("numeric loopback address and port required") from None
    if not address.is_loopback or port is None or not 0 < port <= 65535 or parsed.netloc != (f"[{host}]:{port}" if address.version == 6 else f"{host}:{port}"):
        raise ValueError("numeric loopback address and port required")
    return host, port


def _probe(host: str, port: int, path: str, timeout: float) -> str:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Host": host, "Connection": "close"})
        response = connection.getresponse()
        response.read(1)
        return "ok" if response.status == 200 else "http_error"
    except (socket.timeout, TimeoutError):
        return "timeout"
    except (OSError, http.client.HTTPException):
        return "error"
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="C09 local external first-byte preparation")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--workload", required=True)
    parser.add_argument("--round", type=int, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--deadline-seconds", type=int, default=3600)
    args = parser.parse_args()
    if args.plan.stat().st_size > MAX_PLAN_BYTES or not 0 < args.timeout <= 30 or not 0 < args.deadline_seconds <= 3600:
        parser.error("plan, timeout or deadline exceeds bound")
    frozen = freeze_plan(json.loads(args.plan.read_bytes()))
    plan = frozen["plan"]
    if not any(row == {"profile": args.profile, "workload": args.workload, "round": args.round} for row in plan["order"]):
        parser.error("run identity absent from frozen order")
    host, port = _loopback_target(args.url, plan["cache_only_path"])
    capture = Capture(args.output, plan_sha256=frozen["plan_sha256"], profile=args.profile,
                      workload=args.workload, round_index=args.round, requested=args.count)
    deadline_ns = time.monotonic_ns() + int(args.deadline_seconds * 1_000_000_000)
    stopped_early = False
    try:
        for _ in range(args.count):
            remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                stopped_early = True
                break
            start = capture.start()
            outcome = _probe(host, port, plan["cache_only_path"], min(args.timeout, remaining))
            capture.finish(start, outcome)
    finally:
        capture.close(stopped_early=stopped_early or capture.attempted < args.count)


if __name__ == "__main__":
    main()
