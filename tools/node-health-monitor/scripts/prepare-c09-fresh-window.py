#!/usr/bin/env python3
"""Create a new private C09 functional-window baseline after manual review."""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

MAX_PRIVATE = 4096
BASELINE_LIMITS = (1024, 32 * 1024 * 1024, 3072)


def private_bytes(path, limit=MAX_PRIVATE):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or meta.st_mode & 0o077 or meta.st_nlink != 1 or meta.st_size > limit):
            raise RuntimeError("private source identity")
        raw = os.read(fd, limit + 1)
        if len(raw) != meta.st_size:
            raise RuntimeError("private source changed")
        return raw
    finally:
        os.close(fd)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def prepare(audit_path, resolution_path, q_path, target, query_sha):
    audit_raw = private_bytes(audit_path)
    resolution_raw = private_bytes(resolution_path)
    audit, resolution = json.loads(audit_raw), json.loads(resolution_raw)
    log_info, marker_info, q_info = audit["sample_log"], audit["inflight_marker"], audit["q_ledger"]
    failed_line = private_bytes(log_info["source"], 4 * 1024 * 1024).splitlines()[-1]
    failed = json.loads(failed_line)
    marker_raw = private_bytes(marker_info["source"], 256)
    log_raw = private_bytes(log_info["source"], 4 * 1024 * 1024)
    if (digest(log_raw) != log_info["sha256"] or digest(marker_raw) != marker_info["sha256"]
            or digest(private_bytes(log_info["frozen"], 4 * 1024 * 1024)) != log_info["sha256"]
            or digest(private_bytes(marker_info["frozen"], 256)) != marker_info["sha256"]
            or failed.get("status") == "pass" or failed.get("cleanup_confirmed") is True):
        raise RuntimeError("failed window artifacts changed")
    prior_grant_floor = min(row["ordinal"] for row in q_info["new_rows"]) - 1
    if prior_grant_floor < 0 or q_info["grant_count"] < prior_grant_floor:
        raise RuntimeError("audit grant boundary")
    required = {"schema_version", "decision", "audit_sha256", "old_log_sha256", "old_marker_sha256",
                "q_device", "q_inode", "failed_slot_highwater", "reviewer", "reviewed_at_utc",
                "candidate_grants_accounted_for", "original_marker_preserved"}
    if (set(resolution) != required or resolution["schema_version"] != 1
            or resolution["decision"] != "resolved_new_window"
            or resolution["audit_sha256"] != digest(audit_raw)
            or resolution["old_log_sha256"] != log_info["sha256"]
            or resolution["old_marker_sha256"] != marker_info["sha256"]
            or resolution["q_device"] != q_info["device"] or resolution["q_inode"] != q_info["inode"]
            or resolution["failed_slot_highwater"] != failed.get("slot_highwater")
            or resolution["candidate_grants_accounted_for"] is not True
            or resolution["original_marker_preserved"] is not True
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", resolution["reviewer"]) is None):
        raise RuntimeError("manual resolution mismatch")
    reviewed = dt.datetime.fromisoformat(resolution["reviewed_at_utc"].replace("Z", "+00:00"))
    if reviewed.utcoffset() != dt.timedelta(0) or reviewed <= dt.datetime.fromisoformat(audit["observed_utc"].replace("Z", "+00:00")):
        raise RuntimeError("manual resolution time")
    if re.fullmatch(r"[0-9a-f]{64}", query_sha) is None:
        raise RuntimeError("Q binary digest")
    meta = os.stat(q_path, follow_symlinks=False)
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077
            or meta.st_dev != q_info["device"] or meta.st_ino != q_info["inode"]):
        raise RuntimeError("Q ledger replacement")
    now_ms = int(time.clock_gettime(time.CLOCK_BOOTTIME) * 1000)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    with sqlite3.connect("file:" + str(Path(q_path).resolve()) + "?mode=ro", uri=True, timeout=0.5) as db:
        db.execute("PRAGMA query_only=ON")
        if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise RuntimeError("Q quick_check")
        grants, body = db.execute("SELECT count(*),coalesce(sum(length(body)),0) FROM query_grants").fetchone()
        attempts = db.execute("SELECT count(*) FROM query_attempts").fetchone()[0]
        unresolved = db.execute("SELECT count(*) FROM query_grants WHERE rowid>? AND boot_id LIKE ? AND revoked=0 AND expires_ms>?",
                                (prior_grant_floor, boot + "|%", now_ms)).fetchone()[0]
    after = os.stat(q_path, follow_symlinks=False)
    if ((after.st_dev, after.st_ino) != (meta.st_dev, meta.st_ino)
            or grants < q_info["grant_count"] or attempts < q_info["attempt_count"] or unresolved):
        raise RuntimeError("Q grant state unresolved")
    window_id = digest(resolution_raw)
    baseline = {"schema_version": 2, "window_id": window_id,
                "prior_log_sha256": log_info["sha256"], "prior_marker_sha256": marker_info["sha256"],
                "boot_id": boot, "time_namespace": os.readlink("/proc/self/ns/time"),
                "q_device": str(meta.st_dev), "q_inode": str(meta.st_ino),
                "grants": grants, "grant_body_bytes": body, "attempts": attempts,
                "query_sha256": query_sha, "max_new_grants": BASELINE_LIMITS[0],
                "max_new_grant_body_bytes": BASELINE_LIMITS[1], "max_new_attempts": BASELINE_LIMITS[2]}
    target = Path(target)
    target.mkdir(mode=0o700)
    try:
        for name, value in (("baseline.private.json", baseline),
                            ("window-anchor.private.json", {"schema_version": 1, "window_id": window_id,
                              "manual_resolution_sha256": window_id, "old_log_sha256": log_info["sha256"],
                              "old_marker_sha256": marker_info["sha256"],
                              "baseline_sha256": digest(json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()),
                              "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat()})):
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            fd = os.open(target / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            try:
                if os.write(fd, raw) != len(raw):
                    raise RuntimeError("short write")
                os.fsync(fd)
            finally:
                os.close(fd)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try: os.fsync(fd)
        finally: os.close(fd)
    except Exception:
        # Leave partial private files for explicit operator inspection; do not
        # pretend preparation was atomic after an I/O failure.
        raise
    return window_id, digest((target / "baseline.private.json").read_bytes())


def main():
    parser = argparse.ArgumentParser()
    for name in ("audit", "resolution", "q-ledger", "target-dir", "query-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    window_id, baseline_sha = prepare(args.audit, args.resolution, args.q_ledger,
                                      args.target_dir, args.query_sha256)
    print(json.dumps({"window_id": window_id, "baseline_sha256": baseline_sha}, separators=(",", ":")))


if __name__ == "__main__":
    main()
