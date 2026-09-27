#!/usr/bin/env python3
"""Verify a fixed first batch of A03 source and raw evidence without closing units."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

EXPECTED_IDS = {"E16", "F01", "X01"}
# Completed runs that each signed task-table row names for its fixed source.
EXPECTED_CI_RUNS = {"E16": 3, "F01": 3, "X01": 3}
SIGNED = "✅"
_SPEC = importlib.util.spec_from_file_location("a03_development_ledger", Path(__file__).with_name("a03_development_ledger.py"))
ledger = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ledger)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def console_exit_code(raw):
    """Return the sole terminal `script` exit marker, never a log-body mention."""
    matches = re.findall(rb'(?m)^Script done on [^\r\n]* \[COMMAND_EXIT_CODE="(-?[0-9]+)"\]\r?$', raw)
    return int(matches[0]) if len(matches) == 1 else None


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


def docs_only_descendant(repo, source, head):
    """True when head descends from source and changes nothing outside doc/."""
    if not isinstance(source, str) or not isinstance(head, str):
        return False
    ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", source, head], cwd=repo, capture_output=True)
    names = subprocess.run(["git", "diff", "--name-only", "--no-renames", source, head], cwd=repo, capture_output=True, text=True)
    if ancestor.returncode or names.returncode:
        return False
    changed = [line for line in names.stdout.splitlines() if line]
    return bool(changed) and all(name.startswith("doc/") for name in changed)


def validate(batch, snapshot, snapshot_bytes, source_repo, memo_repo):
    errors = []
    if batch.get("schema") != 1 or batch.get("snapshot_sha256") != sha(snapshot_bytes):
        errors.append("batch: snapshot identity mismatch")
    table = subprocess.run(["git", "show", f"{snapshot.get('memo_commit')}:{snapshot.get('task_table_path')}"],
                           cwd=memo_repo, capture_output=True)
    if table.returncode or sha(table.stdout) != snapshot.get("task_table_sha256"):
        errors.append("snapshot: fixed memo task table missing or SHA mismatch")
    else:
        errors.extend(ledger.snapshot_table_errors(snapshot, table.stdout))
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
        signed = tasks[tid]["status"] == SIGNED
        kind = entry.get("command", {}).get("kind") if isinstance(entry.get("command"), dict) else None
        if not signed and kind != "offline_unit":
            errors.append(f"{label}: open unit cannot be promoted")
        if signed and kind != "real_chain":
            errors.append(f"{label}: signed row must index its signed real-chain run")
        if not isinstance(entry.get("scope"), str) or not entry["scope"].strip():
            errors.append(f"{label}: applicability scope missing")
        invalidating = entry.get("invalidating_changes")
        if not isinstance(invalidating, list) or not invalidating or not all(isinstance(x, str) and x.strip() for x in invalidating):
            errors.append(f"{label}: invalidating changes missing")
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
        if signed and not binaries:
            errors.append(f"{label}: exact binary snapshots missing")
        for n, item in enumerate(binaries):
            local(item, f"{label}:binary:{n}", errors)
        review = entry.get("review")
        review_bytes = None
        if not isinstance(review, dict) or not all(isinstance(review.get(x), str) for x in ("memo_commit", "path", "sha256")):
            errors.append(f"{label}: fixed independent review missing")
        else:
            review_bytes = git_blob(memo_repo, review["memo_commit"], review["path"], review["sha256"], f"{label}:review", errors)
        ci_items = entry.get("ci")
        if not isinstance(ci_items, list):
            errors.append(f"{label}: CI disposition list missing")
            ci_items = []
        if signed and len(ci_items) != EXPECTED_CI_RUNS[tid]:
            errors.append(f"{label}: {EXPECTED_CI_RUNS[tid]} fixed CI dispositions required")
        source_commit = sources[0].get("commit") if sources else None
        if tid == "F01":
            query = local(entry.get("ci_query"), f"{label}:ci-query", errors)
            if query is None or query.strip() != b"[]":
                errors.append(f"{label}: exact-source no-CI query missing or contradicted")
            if any(isinstance(item, dict) and item.get("head_sha") == source_commit for item in ci_items):
                errors.append(f"{label}: exact-source no-CI query missing or contradicted")
        for n, item in enumerate(ci_items):
            raw = local(item.get("raw"), f"{label}:ci:{n}", errors) if isinstance(item, dict) else None
            if raw is None:
                continue
            try:
                run = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                errors.append(f"{label}:ci:{n}: malformed run JSON")
                continue
            equivalent = run.get("headSha") == source_commit or (
                item.get("source_equivalence") == "docs_only_descendant"
                and docs_only_descendant(source_repo, source_commit, run.get("headSha")))
            if (run.get("databaseId") != item.get("run_id") or run.get("headSha") != item.get("head_sha")
                    or not equivalent or run.get("name") != item.get("name")
                    or run.get("conclusion") != item.get("conclusion") or run.get("status") != "completed"):
                errors.append(f"{label}:ci:{n}: run identity/outcome mismatch")
        command = entry.get("command")
        argv = command.get("argv") if isinstance(command, dict) else None
        argv_ok = (isinstance(argv, list) and argv and all(isinstance(x, str) for x in argv)) or (
            argv is None and isinstance(command.get("argv_gap"), str) and command["argv_gap"].strip())
        if not isinstance(command, dict) or type(command.get("reported_exit")) is not int or not argv_ok:
            errors.append(f"{label}: documented command and exact reported exit missing")
        elif signed:
            marker = command.get("exit_raw_marker")
            natural_exit = console_exit_code(raw_bytes[0]) if raw_bytes and raw_bytes[0] is not None else None
            expected_marker = f'COMMAND_EXIT_CODE="{command["reported_exit"]}"'
            if (command.get("exit_raw_role") != "console" or marker != expected_marker
                    or natural_exit is None or natural_exit != command["reported_exit"]):
                errors.append(f"{label}: natural command exit not in original console")
            reported = command.get("reported_argv_text")
            if reported is not None and (not isinstance(reported, str) or review_bytes is None or reported.encode() not in review_bytes):
                errors.append(f"{label}: reported argv absent from fixed independent review")
        elif command.get("exit_raw_marker") is not None:
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
