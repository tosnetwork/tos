#!/usr/bin/env python3
"""Verify a fixed first batch of A03 source and raw evidence without closing units."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

EXPECTED_IDS = {"E16", "F01", "X01"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def local(item, label, errors):
    if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("sha256"), str):
        errors.append(f"{label}: malformed path/SHA")
        return None
    path = Path(item["path"])
    if not path.is_absolute() or not path.is_file() or sha(path.read_bytes()) != item["sha256"]:
        errors.append(f"{label}: missing or SHA mismatch")
        return None
    return path.read_bytes()


def git_blob(repo, commit, path, expected, label, errors):
    obj = f"{commit}:{path}"
    kind = subprocess.run(["git", "cat-file", "-t", obj], cwd=repo, capture_output=True, text=True)
    raw = subprocess.run(["git", "show", obj], cwd=repo, capture_output=True)
    if kind.returncode or kind.stdout.strip() != "blob" or raw.returncode or sha(raw.stdout) != expected:
        errors.append(f"{label}: fixed Git blob missing or SHA mismatch")
        return None
    return raw.stdout


def validate(batch, snapshot, snapshot_bytes, source_repo, memo_repo):
    errors = []
    if batch.get("schema") != 1 or batch.get("snapshot_sha256") != sha(snapshot_bytes):
        errors.append("batch: snapshot identity mismatch")
    entries = batch.get("entries")
    if not isinstance(entries, dict) or set(entries) != EXPECTED_IDS:
        return errors + ["batch: exact first-batch IDs required"]
    tasks = {row["id"]: row for row in snapshot["tasks"]}
    for tid in sorted(EXPECTED_IDS):
        entry = entries[tid]
        label = tid
        if not isinstance(entry, dict):
            errors.append(f"{label}: malformed entry")
            continue
        if entry.get("task_status") != tasks[tid]["status"] or entry.get("accepted") is not False:
            errors.append(f"{label}: status/acceptance differs from frozen task table")
        if not isinstance(entry.get("scope"), str) or not entry["scope"].strip():
            errors.append(f"{label}: applicability scope missing")
        invalidating = entry.get("invalidating_changes")
        if not isinstance(invalidating, list) or not invalidating or not all(isinstance(x, str) and x.strip() for x in invalidating):
            errors.append(f"{label}: invalidating changes missing")
        if tid == "F01" and entry.get("task_status") != "✅":
            errors.append(f"{label}: signed local F01 row missing")
        if tid == "X01" and entry.get("task_status") != "▶":
            errors.append(f"{label}: open unit cannot be promoted")
        gaps = entry.get("gaps")
        if not isinstance(gaps, list) or not gaps or not all(isinstance(x, str) and x.strip() for x in gaps):
            errors.append(f"{label}: explicit unresolved gaps required")
        sources = entry.get("source_blobs")
        if not isinstance(sources, list) or not sources:
            errors.append(f"{label}: source blobs missing")
            sources = []
        for n, item in enumerate(sources):
            if not isinstance(item, dict) or not all(isinstance(item.get(x), str) for x in ("commit", "path", "sha256")):
                errors.append(f"{label}:source:{n}: malformed")
            else:
                git_blob(source_repo, item["commit"], item["path"], item["sha256"], f"{label}:source:{n}", errors)
        raw_items = entry.get("raw")
        if not isinstance(raw_items, list) or not raw_items:
            errors.append(f"{label}: original raw evidence missing")
            raw_items = []
        raw_bytes = [local(item, f"{label}:raw:{n}", errors) for n, item in enumerate(raw_items)]
        binaries = entry.get("binaries")
        if not isinstance(binaries, list):
            errors.append(f"{label}: binary inventory missing")
            binaries = []
        if tid != "X01" and not binaries:
            errors.append(f"{label}: exact binary snapshots missing")
        for n, item in enumerate(binaries):
            local(item, f"{label}:binary:{n}", errors)
        review = entry.get("review")
        if not isinstance(review, dict) or not all(isinstance(review.get(x), str) for x in ("memo_commit", "path", "sha256")):
            errors.append(f"{label}: fixed independent review missing")
        else:
            git_blob(memo_repo, review["memo_commit"], review["path"], review["sha256"], f"{label}:review", errors)
        ci_items = entry.get("ci")
        if not isinstance(ci_items, list):
            errors.append(f"{label}: CI disposition list missing")
            ci_items = []
        if tid == "E16" and len(ci_items) != 3:
            errors.append(f"{label}: three fixed CI dispositions required")
        if tid == "F01":
            query = local(entry.get("ci_query"), f"{label}:ci-query", errors)
            if ci_items or query is None or query.strip() != b"[]":
                errors.append(f"{label}: exact-source no-CI query missing or contradicted")
        source_commit = sources[0].get("commit") if sources else None
        for n, item in enumerate(ci_items):
            raw = local(item.get("raw"), f"{label}:ci:{n}", errors) if isinstance(item, dict) else None
            if raw is None:
                continue
            try:
                run = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                errors.append(f"{label}:ci:{n}: malformed run JSON")
                continue
            if (run.get("databaseId") != item.get("run_id") or run.get("headSha") != item.get("head_sha")
                    or run.get("headSha") != source_commit or run.get("name") != item.get("name")
                    or run.get("conclusion") != item.get("conclusion") or run.get("status") != "completed"):
                errors.append(f"{label}:ci:{n}: run identity/outcome mismatch")
        command = entry.get("command")
        if (not isinstance(command, dict) or type(command.get("reported_exit")) is not int
                or (tid != "F01" and (not isinstance(command.get("argv"), list) or not command["argv"]
                                      or not all(isinstance(x, str) for x in command["argv"])))
                or (tid == "F01" and command.get("argv") is not None)):
            errors.append(f"{label}: documented command and exact reported exit missing")
        elif tid in {"E16", "F01"}:
            marker = command.get("exit_raw_marker")
            if command.get("kind") != "real_chain" or command.get("exit_raw_role") != "console" or not isinstance(marker, str) or not raw_bytes or raw_bytes[0] is None or marker.encode() not in raw_bytes[0]:
                errors.append(f"{label}: natural command exit not in original console")
        elif tid == "X01" and command.get("kind") != "offline_unit":
            errors.append(f"{label}: offline candidate misclassified")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--memo-repo", type=Path, required=True)
    parser.add_argument("--inventory-only", action="store_true")
    args = parser.parse_args()
    snapshot_bytes = args.snapshot.read_bytes()
    batch = json.loads(args.batch.read_bytes())
    errors = validate(batch, json.loads(snapshot_bytes), snapshot_bytes, args.source_repo, args.memo_repo)
    print(json.dumps({"integrity_passed": not errors, "development_gate_passed": False,
                      "accepted_ids": [], "indexed_ids": sorted(EXPECTED_IDS), "errors": errors}, indent=2))
    return bool(errors) if args.inventory_only else 1


if __name__ == "__main__":
    raise SystemExit(main())
