#!/usr/bin/env python3
"""Bounded local-node acceptance instrument, separate from the monitoring owner.

RPC RTT is an instrument metric, not a consensus-stage latency measurement.
This sampler reads public RPC answers and fixed proc/cgroup fields only.
"""

import argparse
import base64
import concurrent.futures
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

CAPTURE_CAP = 128 * 1024 * 1024
UNITS = ["tos-pq-dht.service"] + [
    f"tos-pq-{'validator' if i <= 4 else 'observer'}@{i}.service" for i in range(1, 7)
]


def bounded_text(path, cap=65536):
    with open(path, "rb") as stream:
        raw = stream.read(cap + 1)
    if len(raw) > cap:
        raise ValueError("instrument file overflow")
    return raw.decode("ascii")


def digest_field(value):
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32:
        raise ValueError("block digest length")
    return raw.hex()


def block_id(row):
    if row.get("workchain") != -1:
        raise ValueError("not masterchain")
    shard = int(row["shard"])
    if shard not in (-9223372036854775808, 9223372036854775808):
        raise ValueError("masterchain shard")
    seqno = row["seqno"]
    if type(seqno) is not int or not 0 <= seqno <= 0xFFFFFFFF:
        raise ValueError("block seqno")
    return {
        "workchain": -1,
        "shard": "9223372036854775808",
        "seqno": seqno,
        "root_hash": digest_field(row["root_hash"]),
        "file_hash": digest_field(row["file_hash"]),
    }


def rpc_sample(node):
    start = time.monotonic_ns()
    request = urllib.request.Request(
        f"http://127.0.0.1:{8010 + node}",
        data=json.dumps(
            {"jsonrpc": "2.0", "id": node, "method": "getMasterchainInfo", "params": {}}
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    # Explicitly bypass proxy environment even for loopback.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=3) as response:
            raw = response.read(16385)
        if len(raw) > 16384:
            raise ValueError("RPC body overflow")
        value = json.loads(raw)
        if value.get("ok") is not True or value.get("id") != node:
            raise ValueError("RPC refused or wrong receipt")
        result = value["result"]
        return {
            "node": node,
            "start_monotonic_ns": start,
            "rtt_ns": time.monotonic_ns() - start,
            "last": block_id(result["last"]),
            "init": block_id(result["init"]),
        }
    except Exception as error:
        return {
            "node": node,
            "start_monotonic_ns": start,
            "rtt_ns": time.monotonic_ns() - start,
            "error": f"{type(error).__name__}: {str(error)[:256]}",
        }


def systemd_sample():
    command = [
        "systemctl",
        "show",
        *UNITS,
        "-p",
        "Id",
        "-p",
        "ActiveState",
        "-p",
        "MainPID",
        "-p",
        "ControlGroup",
        "-p",
        "MemoryCurrent",
        "-p",
        "MemoryMax",
        "-p",
        "CPUUsageNSec",
        "-p",
        "CPUQuotaPerSecUSec",
    ]
    result = subprocess.run(command, capture_output=True, timeout=5, check=True)
    if len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise ValueError("systemctl capture overflow")
    rows = []
    for group in result.stdout.decode("ascii").strip().split("\n\n"):
        row = dict(line.split("=", 1) for line in group.splitlines())
        if row["Id"] not in UNITS:
            raise ValueError("unexpected unit")
        pid = int(row["MainPID"])
        if pid:
            status = bounded_text(f"/proc/{pid}/status")
            row["proc_status"] = {
                key: value.strip()
                for key, value in (
                    line.split(":", 1) for line in status.splitlines() if ":" in line
                )
                if key in ("VmRSS", "RssAnon", "VmSwap", "Threads")
            }
            row["proc_io"] = bounded_text(f"/proc/{pid}/io")
        cgroup = row["ControlGroup"]
        if not cgroup.startswith("/") or ".." in Path(cgroup).parts:
            raise ValueError("invalid cgroup path")
        if cgroup:
            root = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
            row["cgroup"] = {
                name: bounded_text(root / name)
                for name in ("cpu.stat", "memory.events", "io.stat", "pids.current")
            }
        rows.append(row)
    if len(rows) != len(UNITS) or len({row["Id"] for row in rows}) != len(UNITS):
        raise ValueError("unit inventory incomplete")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seconds", type=int, required=True)
    parser.add_argument("--interval", type=int, default=30)
    args = parser.parse_args()
    if not 60 <= args.seconds <= 259200 or not 5 <= args.interval <= 60:
        parser.error("duration 60..259200; interval 5..60")
    args.out.mkdir(mode=0o700)
    network = json.loads(bounded_text("/data/network.json"))
    expected_root = network["zerostate_root"]
    expected_file = network["zerostate_file"]
    start = time.monotonic_ns()
    deadline = start + args.seconds * 1_000_000_000
    next_tick = start
    count = 0
    written = 0
    errors = 0
    previous = None
    advances = 0
    with (args.out / "samples.jsonl").open("xb", buffering=0) as stream:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            while time.monotonic_ns() < deadline:
                now = time.monotonic_ns()
                if now < next_tick:
                    time.sleep(min((next_tick - now) / 1e9, 1))
                    continue
                record = {
                    "sample": count,
                    "monotonic_ns": now,
                    "unix_ns": time.time_ns(),
                    "scope": "local_development",
                    "rpc_is_finality_proof": False,
                    "rpc_rtt_is_consensus_latency": False,
                }
                try:
                    record["units"] = systemd_sample()
                except Exception as error:
                    record["instrument_error"] = f"{type(error).__name__}: {str(error)[:256]}"
                    errors += 1
                record["rpc"] = list(pool.map(rpc_sample, range(1, 7)))
                good = [row for row in record["rpc"] if "last" in row]
                record["genesis_matches_prepared_manifest"] = len(good) == 6 and all(
                    row["init"]["root_hash"] == expected_root
                    and row["init"]["file_hash"] == expected_file
                    for row in good
                )
                record["reported_same_id"] = len(good) == 6 and all(
                    row["last"] == good[0]["last"] and row["init"] == good[0]["init"]
                    for row in good
                )
                if len(good) != 6:
                    errors += 1
                if not record["genesis_matches_prepared_manifest"]:
                    errors += 1
                if record["reported_same_id"]:
                    height = good[0]["last"]["seqno"]
                    if previous is not None and height > previous:
                        advances += 1
                    previous = height
                filesystem = os.statvfs("/data")
                record["filesystem_available_bytes"] = filesystem.f_bavail * filesystem.f_frsize
                raw = json.dumps(record, separators=(",", ":"), sort_keys=True).encode() + b"\n"
                if written + len(raw) > CAPTURE_CAP:
                    raise RuntimeError("instrument capture cap reached")
                stream.write(raw)
                written += len(raw)
                count += 1
                # Skip missed ticks; no burst to catch up on work.
                next_tick += args.interval * 1_000_000_000
                if next_tick <= time.monotonic_ns():
                    next_tick = time.monotonic_ns() + args.interval * 1_000_000_000
    terminal = {
        "elapsed_monotonic_ns": time.monotonic_ns() - start,
        "requested_seconds": args.seconds,
        "samples": count,
        "instrument_or_rpc_errors": errors,
        "agreeing_height_advances": advances,
        "bytes": written,
        "completed_duration": True,
        "c09_accepted": False,
        "production_accepted": False,
    }
    (args.out / "terminal.json").write_text(json.dumps(terminal, indent=2) + "\n")
    if errors or count < 2 or not advances:
        raise SystemExit("instrument/chain observation refused; retained terminal is not a pass")


if __name__ == "__main__":
    main()
