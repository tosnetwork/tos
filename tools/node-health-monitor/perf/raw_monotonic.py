"""Bounded, same-process raw duration capture for C09 development runs.

This module does not claim native consensus-stage coverage. Callers must name
the measured operation and keep its start and finish in this process.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


CLOCK_ID = "linux:CLOCK_MONOTONIC_RAW"
MAX_RECORDS = 100_000
MAX_BYTES = 16 * 1024 * 1024
MAX_DURATION_NS = 60 * 60 * 1_000_000_000


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def process_epoch() -> str:
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    stat = Path("/proc/self/stat").read_text()
    # comm may contain spaces and parentheses; field 22 is index 19 after it.
    start_ticks = stat.rsplit(")", 1)[1].split()[19]
    return hashlib.sha256(f"{boot}:{os.getpid()}:{start_ticks}".encode()).hexdigest()


@dataclass(frozen=True)
class Point:
    process_epoch: str
    clock_domain: str
    monotonic_ns: int


def duration_ns(start: Point, finish: Point) -> int:
    if not start.process_epoch or start.process_epoch != finish.process_epoch:
        raise ValueError("process epoch mismatch")
    if start.clock_domain != CLOCK_ID or finish.clock_domain != CLOCK_ID:
        raise ValueError("clock domain mismatch or unsupported")
    if not isinstance(start.monotonic_ns, int) or isinstance(start.monotonic_ns, bool):
        raise ValueError("invalid start timestamp")
    if not isinstance(finish.monotonic_ns, int) or isinstance(finish.monotonic_ns, bool):
        raise ValueError("invalid finish timestamp")
    delta = finish.monotonic_ns - start.monotonic_ns
    if start.monotonic_ns < 0 or delta < 0 or delta > MAX_DURATION_NS:
        raise ValueError("invalid duration")
    return delta


def sample(epoch: str) -> Point:
    return Point(epoch, CLOCK_ID, time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW))


class Capture:
    def __init__(self, population: str, max_records: int = MAX_RECORDS, max_bytes: int = MAX_BYTES):
        if not population or len(population) > 128 or not population.isascii():
            raise ValueError("invalid population")
        if not 0 < max_records <= MAX_RECORDS or not 0 < max_bytes <= MAX_BYTES:
            raise ValueError("invalid capture capacity")
        self.population = population
        self.epoch = process_epoch()
        self.max_records = max_records
        self.max_bytes = max_bytes
        self.records: list[bytes] = []
        self.bytes_used = 0
        self.attempted = 0
        self.dropped = 0
        self.invalid = 0

    def start(self) -> Point:
        return sample(self.epoch)

    def finish(self, operation: str, start: Point, outcome: str = "ok") -> bool:
        self.attempted += 1
        if process_epoch() != self.epoch:
            self.invalid += 1
            raise ValueError("capture process changed")
        if not operation or len(operation) > 96 or not operation.isascii() or outcome not in {"ok", "error", "timeout"}:
            self.invalid += 1
            raise ValueError("invalid operation or outcome")
        end = sample(self.epoch)
        try:
            delta = duration_ns(start, end)
        except ValueError:
            self.invalid += 1
            raise
        record = canonical({"operation": operation, "population": self.population,
                            "outcome": outcome, "start": asdict(start), "finish": asdict(end),
                            "duration_ns": delta})
        if len(self.records) >= self.max_records or self.bytes_used + len(record) > self.max_bytes:
            self.dropped += 1
            return False
        self.records.append(record)
        self.bytes_used += len(record)
        return True

    def write(self, path: Path, resource_ledger: dict[str, Any]) -> dict[str, Any]:
        if self.attempted != len(self.records) + self.dropped + self.invalid:
            raise ValueError("capture accounting mismatch")
        if not isinstance(resource_ledger, dict) or set(resource_ledger) != {"V", "edge", "M", "O", "A"}:
            raise ValueError("incomplete resource ledger")
        for role, entry in resource_ledger.items():
            if not isinstance(entry, dict) or entry.get("status") not in {"measured", "not_run"}:
                raise ValueError(f"invalid resource ledger: {role}")
            if entry["status"] == "measured":
                required = {"cpu_seconds", "rss_peak_bytes", "io_read_bytes", "io_write_bytes", "network_rx_bytes", "network_tx_bytes"}
                if not required.issubset(entry) or any(type(entry[key]) not in {int, float} or not math.isfinite(entry[key]) or entry[key] < 0 for key in required):
                    raise ValueError(f"incomplete measured resources: {role}")
        digest = hashlib.sha256(b"".join(self.records)).hexdigest()
        with path.open("xb") as out:
            for record in self.records:
                out.write(record)
        return {"schema_version": 1, "kind": "c09_raw_capture", "population": self.population,
                "process_epoch": self.epoch, "clock_domain": CLOCK_ID,
                "clock_resolution_ns": int(time.clock_getres(time.CLOCK_MONOTONIC_RAW) * 1_000_000_000),
                "attempted": self.attempted, "retained": len(self.records), "dropped": self.dropped,
                "invalid": self.invalid, "capacity_records": self.max_records,
                "capacity_bytes": self.max_bytes, "retained_bytes": self.bytes_used,
                "evidence_sha256": digest, "resource_ledger": resource_ledger}


def verify_capture(path: Path, manifest: dict[str, Any]) -> None:
    if manifest.get("clock_domain") != CLOCK_ID or not 0 <= manifest.get("capacity_records", -1) <= MAX_RECORDS or not 0 <= manifest.get("capacity_bytes", -1) <= MAX_BYTES:
        raise ValueError("invalid manifest clock or capacity")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("evidence exceeds global bound")
    raw = path.read_bytes()
    if len(raw) > manifest["capacity_bytes"] or len(raw) != manifest["retained_bytes"]:
        raise ValueError("evidence size mismatch")
    if hashlib.sha256(raw).hexdigest() != manifest["evidence_sha256"]:
        raise ValueError("evidence hash mismatch")
    lines = raw.splitlines(keepends=True)
    if len(lines) != manifest["retained"] or manifest["attempted"] != manifest["retained"] + manifest["dropped"] + manifest["invalid"]:
        raise ValueError("evidence count mismatch")
    for line in lines:
        record = json.loads(line)
        if canonical(record) != line or record["population"] != manifest["population"]:
            raise ValueError("noncanonical or wrong population")
        start, finish = Point(**record["start"]), Point(**record["finish"])
        if start.process_epoch != manifest["process_epoch"] or duration_ns(start, finish) != record["duration_ns"]:
            raise ValueError("invalid raw duration")


def main() -> None:
    import argparse
    import urllib.error
    import urllib.request

    parser = argparse.ArgumentParser(description="C09 bounded external HTTP RTT capture; not a native stage measurement")
    parser.add_argument("url", help="approved cache-only GET endpoint")
    parser.add_argument("output", type=Path, help="new raw JSONL path")
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--deadline-seconds", type=int, default=3600)
    args = parser.parse_args()
    if (not args.url.startswith(("http://", "https://")) or not 0 < args.count <= MAX_RECORDS
            or not 0 < args.timeout <= 30 or not 0 < args.deadline_seconds <= 3600):
        parser.error("invalid endpoint, count, timeout or deadline")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None

    client = urllib.request.build_opener(NoRedirect)
    capture = Capture("external_request_rtt")
    deadline_ns = time.monotonic_ns() + args.deadline_seconds * 1_000_000_000
    for _ in range(args.count):
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            break
        start = capture.start()
        outcome = "ok"
        try:
            with client.open(urllib.request.Request(args.url, method="GET"), timeout=min(args.timeout, remaining)) as response:
                response.read(1)
                if response.status != 200:
                    outcome = "error"
        except (TimeoutError, urllib.error.URLError) as error:
            outcome = "timeout" if isinstance(error, TimeoutError) else "error"
        except Exception:
            outcome = "error"
        capture.finish("http_get_first_byte", start, outcome)
    ledger = {role: {"status": "not_run"} for role in ("V", "edge", "M", "O", "A")}
    manifest = capture.write(args.output, ledger)
    manifest["requested"] = args.count
    manifest["stopped_early"] = capture.attempted < args.count
    manifest_path = args.output.with_suffix(args.output.suffix + ".manifest.json")
    with manifest_path.open("x", encoding="utf-8") as out:
        json.dump(manifest, out, sort_keys=True, indent=2, allow_nan=False)
        out.write("\n")


if __name__ == "__main__":
    main()
