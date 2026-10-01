#!/usr/bin/env python3
"""Private, bounded receipt after the supervised functional timer is stopped."""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_ROW_BYTES = 1024
MAX_MARKER_BYTES = 256
MIN_ELAPSED_NS = (72 * 60 + 5) * 60 * 1_000_000_000
MAX_SAMPLE_GAP_NS = 360 * 1_000_000_000
MIN_SAMPLE_GAP_NS = 300 * 1_000_000_000


def boot_domain():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def private_file(path, limit):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or meta.st_mode & 0o077 or meta.st_nlink != 1 or meta.st_size > limit):
            raise RuntimeError("private file identity or size")
        raw = os.read(fd, limit + 1)
        if len(raw) != meta.st_size:
            raise RuntimeError("private file changed")
        return raw
    finally:
        os.close(fd)


def unit_state(unit):
    result = subprocess.run(["/usr/bin/systemctl", "--user", "show", unit,
                             "-p", "LoadState", "-p", "ActiveState", "-p", "SubState"],
                            capture_output=True, text=True, timeout=3, check=True)
    if len(result.stdout) > 512:
        raise RuntimeError("unit state too large")
    state = dict(line.split("=", 1) for line in result.stdout.splitlines())
    if set(state) != {"LoadState", "ActiveState", "SubState"} or state["LoadState"] != "loaded":
        raise RuntimeError("unit state unavailable")
    return state


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--q-ledger", required=True)
    parser.add_argument("--baseline-file", required=True)
    parser.add_argument("--expected-baseline-sha256", required=True)
    parser.add_argument("--window-end-utc", required=True)
    parser.add_argument("--first-pass-not-after-utc", required=True)
    parser.add_argument("--window-id", required=True)
    parser.add_argument("--timer-unit", required=True)
    parser.add_argument("--service-unit", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{64}", args.window_id) is None:
        raise RuntimeError("window ID")
    directory = Path(args.runtime_dir)
    meta = directory.stat(follow_symlinks=False)
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
        raise RuntimeError("runtime directory")
    window_end = dt.datetime.fromisoformat(args.window_end_utc.replace("Z", "+00:00"))
    first_deadline = dt.datetime.fromisoformat(args.first_pass_not_after_utc.replace("Z", "+00:00"))
    now = dt.datetime.now(dt.timezone.utc)
    if (window_end.utcoffset() != dt.timedelta(0) or first_deadline.utcoffset() != dt.timedelta(0)
            or now < window_end):
        raise RuntimeError("window not ended")
    timer = unit_state(args.timer_unit)
    service = unit_state(args.service_unit)
    if timer["ActiveState"] != "inactive" or service["ActiveState"] not in {"inactive", "failed"}:
        raise RuntimeError("functional unit still active")
    q_meta = Path(args.q_ledger).stat(follow_symlinks=False)
    if (not stat.S_ISREG(q_meta.st_mode) or q_meta.st_uid != os.getuid()
            or q_meta.st_mode & 0o077):
        raise RuntimeError("Q ledger identity")
    baseline_raw = private_file(args.baseline_file, 1024)
    if baseline_raw is None or hashlib.sha256(baseline_raw).hexdigest() != args.expected_baseline_sha256:
        raise RuntimeError("baseline digest")
    baseline = json.loads(baseline_raw)
    if baseline.get("schema_version") != 2 or baseline.get("window_id") != args.window_id:
        raise RuntimeError("baseline window mismatch")
    if (baseline.get("boot_id") != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            or baseline.get("time_namespace") != os.readlink("/proc/self/ns/time")):
        raise RuntimeError("baseline clock domain mismatch")
    anchor_raw = private_file(str(directory / "window-anchor.private.json"), 1024)
    if anchor_raw is None:
        raise RuntimeError("window anchor missing")
    anchor = json.loads(anchor_raw)
    if (anchor.get("schema_version") != 1 or anchor.get("window_id") != args.window_id
            or anchor.get("manual_resolution_sha256") != args.window_id
            or anchor.get("baseline_sha256") != hashlib.sha256(baseline_raw).hexdigest()
            or anchor.get("old_log_sha256") != baseline.get("prior_log_sha256")
            or anchor.get("old_marker_sha256") != baseline.get("prior_marker_sha256")):
        raise RuntimeError("window anchor mismatch")
    q_identity_match = (baseline.get("q_device") == str(q_meta.st_dev)
                        and baseline.get("q_inode") == str(q_meta.st_ino))
    log = private_file(str(directory / "samples.private.jsonl"), MAX_LOG_BYTES)
    marker = private_file(str(directory / "samples.private.jsonl.inflight"), MAX_MARKER_BYTES)
    last = None
    first_sample = None
    first_pass = None
    first_pass_boot = None
    first_pass_boottime = None
    last_boottime = None
    last_boot = None
    all_rows_pass = True
    sample_gaps_bounded = True
    sample_count = 0
    previous_slot = None
    previous_highwater = None
    if log:
        if not log.endswith(b"\n"):
            raise RuntimeError("incomplete sample row")
        for line in log.splitlines():
            if len(line) > MAX_ROW_BYTES:
                raise RuntimeError("sample row too large")
            row = json.loads(line)
            if row.get("window_id") != args.window_id:
                raise RuntimeError("window log mismatch")
            sample_count += 1
            slot = row.get("slot")
            highwater = row.get("slot_highwater")
            if (type(slot) is not int or type(highwater) is not int or slot < 0 or highwater < slot
                    or (previous_slot is not None and slot <= previous_slot)
                    or (previous_highwater is not None and highwater <= previous_highwater)):
                all_rows_pass = False
            previous_slot, previous_highwater = slot, highwater
            sample_boot = row.get("boot_id")
            sample_boottime = row.get("boottime_ns")
            if type(sample_boottime) is not int or sample_boottime < 0 or not isinstance(sample_boot, str):
                raise RuntimeError("sample monotonic clock")
            if last_boottime is not None and (sample_boot != last_boot or sample_boottime <= last_boottime
                                             or not MIN_SAMPLE_GAP_NS <= sample_boottime - last_boottime <= MAX_SAMPLE_GAP_NS):
                sample_gaps_bounded = False
            last_boottime, last_boot = sample_boottime, sample_boot
            if (row.get("status") != "pass" or row.get("cleanup_confirmed") is not True
                    or row.get("fixed_grant_query_status") != "pass"
                    or row.get("error_kind") is not None
                    or row.get("primary_error_kind") is not None
                    or row.get("cleanup_error_kind") is not None
                    or row.get("negative_controls") is not (type(slot) is int and slot % 12 == 0)):
                all_rows_pass = False
            wall = dt.datetime.fromisoformat(row["wall_utc"].replace("Z", "+00:00"))
            if wall.utcoffset() != dt.timedelta(0):
                raise RuntimeError("sample clock domain")
            if first_sample is None:
                first_sample = wall
            if (first_pass is None and row.get("status") == "pass"
                    and row.get("cleanup_confirmed") is True
                    and row.get("fixed_grant_query_status") == "pass"):
                first_pass = wall
                first_pass_boot = row.get("boot_id")
                first_pass_boottime = row.get("boottime_ns")
        last = {"sha256": hashlib.sha256(line).hexdigest(), "slot": row["slot"],
                "slot_highwater": row["slot_highwater"], "status": row["status"],
                "cleanup_confirmed": row["cleanup_confirmed"]}
    minimum_end = first_pass + dt.timedelta(hours=72, minutes=5) if first_pass else None
    stop_boot, stop_boottime = boot_domain()
    same_boot = (first_pass_boot == stop_boot and type(first_pass_boottime) is int
                 and 0 <= first_pass_boottime <= stop_boottime)
    elapsed_ns = stop_boottime - first_pass_boottime if same_boot else None
    last_to_stop_bounded = (last_boot == stop_boot and last_boottime is not None
                            and 0 <= stop_boottime - last_boottime <= MAX_SAMPLE_GAP_NS)
    receipt = {"schema_version": 1, "kind": "c09_functional_window_stop",
               "window_id": args.window_id,
               "window_end_utc": args.window_end_utc, "recorded_at_utc": now.isoformat(),
               "first_pass_deadline_utc": args.first_pass_not_after_utc,
               "first_sample_wall_utc": first_sample.isoformat() if first_sample else None,
               "first_successful_sample_wall_utc": first_pass.isoformat() if first_pass else None,
               "first_success_within_deadline": first_pass is not None and first_pass <= first_deadline,
               "minimum_72h_plus_tick_end_utc": minimum_end.isoformat() if minimum_end else None,
               "first_success_boot_id": first_pass_boot, "first_success_boottime_ns": first_pass_boottime,
               "stop_boot_id": stop_boot, "stop_boottime_ns": stop_boottime,
               "monotonic_elapsed_ns": elapsed_ns,
               "sample_count": sample_count, "all_rows_pass": all_rows_pass,
               "sample_gaps_bounded": sample_gaps_bounded,
               "last_to_stop_bounded": last_to_stop_bounded,
               "functional_elapsed_gate_met": (first_pass is not None and first_pass <= first_deadline
                                               and elapsed_ns is not None and elapsed_ns >= MIN_ELAPSED_NS
                                               and all_rows_pass and sample_gaps_bounded and last_to_stop_bounded
                                               and q_identity_match and marker is None),
               "timer": timer, "service": service,
               "q_ledger_device": q_meta.st_dev, "q_ledger_inode": q_meta.st_ino,
               "q_identity_match": q_identity_match,
               "sample_log_bytes": len(log) if log is not None else None,
               "sample_log_sha256": hashlib.sha256(log).hexdigest() if log is not None else None,
               "last_sample": last, "inflight_present": marker is not None,
               "inflight_sha256": hashlib.sha256(marker).hexdigest() if marker is not None else None,
               "acceptance_claim": False}
    path = directory / "stop-receipt.private.json"
    body = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, body) != len(body):
            raise RuntimeError("receipt short write")
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    print(json.dumps({"receipt_written": True, "timer_inactive": True, "inflight_present": marker is not None}))


if __name__ == "__main__":
    main()
