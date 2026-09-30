#!/usr/bin/env python3
"""Private, bounded receipt after the supervised functional timer is stopped."""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_ROW_BYTES = 1024
MAX_MARKER_BYTES = 256


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
    args = parser.parse_args()
    directory = Path(args.runtime_dir)
    meta = directory.stat(follow_symlinks=False)
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
        raise RuntimeError("runtime directory")
    window_end = dt.datetime.fromisoformat(args.window_end_utc.replace("Z", "+00:00"))
    now = dt.datetime.now(dt.timezone.utc)
    if window_end.utcoffset() != dt.timedelta(0) or now < window_end:
        raise RuntimeError("window not ended")
    timer = unit_state("nhm-c09-functional.timer")
    service = unit_state("nhm-c09-functional.service")
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
    q_identity_match = (baseline.get("q_device") == str(q_meta.st_dev)
                        and baseline.get("q_inode") == str(q_meta.st_ino))
    log = private_file(str(directory / "samples.private.jsonl"), MAX_LOG_BYTES)
    marker = private_file(str(directory / "samples.private.jsonl.inflight"), MAX_MARKER_BYTES)
    last = None
    if log:
        if not log.endswith(b"\n"):
            raise RuntimeError("incomplete sample row")
        line = log.splitlines()[-1]
        if len(line) > MAX_ROW_BYTES:
            raise RuntimeError("sample row too large")
        row = json.loads(line)
        last = {"sha256": hashlib.sha256(line).hexdigest(), "slot": row["slot"],
                "slot_highwater": row["slot_highwater"], "status": row["status"],
                "cleanup_confirmed": row["cleanup_confirmed"]}
    receipt = {"schema_version": 1, "kind": "c09_functional_window_stop",
               "window_end_utc": args.window_end_utc, "recorded_at_utc": now.isoformat(),
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
