#!/usr/bin/env python3
"""Check per-unit development evidence without running tests or a node."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

HEX = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SIGNED = "✅"
TESTNET = "◇"
OPEN = {"□", "▶"}
EXPECTED_SNAPSHOT_SHA = "f9e5875793c50a136938cfc693d4450681fb71469cc6fec0a48083328059d86b"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def task_table_rows(table_bytes):
    """Return (id, lane, owner, status) for every task row, in table order."""
    rows = []
    for line in table_bytes.decode("utf-8").splitlines():
        if re.match(r"^\| [A-Z][0-9]{2} \|", line):
            cells = [cell.strip() for cell in line.split("|")[1:5]]
            rows.append(tuple(cells) if len(cells) == 4 else (cells[0], None, None, None))
    return rows


def snapshot_table_errors(snapshot, table_bytes):
    """The snapshot must restate the table exactly; a matching SHA alone is not enough."""
    rows = task_table_rows(table_bytes)
    tasks = snapshot.get("tasks") if isinstance(snapshot.get("tasks"), list) else []
    ids = [row[0] for row in rows]
    if len(ids) != len(set(ids)):
        return ["snapshot: task table has duplicate IDs"]
    if ids != [t.get("id") if isinstance(t, dict) else None for t in tasks]:
        return ["snapshot: task IDs or order differ from task table"]
    errors = []
    for task, (tid, lane, owner, status) in zip(tasks, rows):
        for key, wanted in (("lane", lane), ("owner", owner), ("status", status)):
            if task.get(key) != wanted:
                errors.append(f"{tid}: snapshot {key} {task.get(key)} differs from task table {wanted}")
    return errors


def unit_counts(snapshot, ledger):
    """Separate accepted rows from signed-but-unreconciled, open and deferred rows."""
    units = ledger.get("units") if isinstance(ledger.get("units"), dict) else {}
    counts = {"accepted": 0, "signed_unreconciled": 0, "open": 0, "deferred_testnet": 0}
    for task in snapshot.get("tasks", []):
        status = task.get("status")
        if status == TESTNET:
            counts["deferred_testnet"] += 1
        elif status in OPEN:
            counts["open"] += 1
        elif units.get(task.get("id"), {}).get("accepted") is True:
            counts["accepted"] += 1
        else:
            counts["signed_unreconciled"] += 1
    return counts


def artifact(item, evidence_root, errors, label):
    if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not HEX.fullmatch(str(item.get("sha256", ""))):
        errors.append(f"{label}: path and 64-hex sha256 required")
        return None
    root = evidence_root.resolve()
    path = (root / item["path"]).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        errors.append(f"{label}: missing or escaped evidence file")
        return None
    if digest(path.read_bytes()) != item["sha256"]:
        errors.append(f"{label}: raw SHA mismatch")
        return None
    return str(path)


def run_receipt(item, evidence_root, errors, label, expected):
    path = artifact(item, evidence_root, errors, f"{label}:receipt")
    if not path:
        return
    try:
        receipt = json.loads(Path(path).read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError):
        errors.append(f"{label}: invalid run receipt JSON")
        return
    if (not isinstance(receipt, dict) or type(receipt.get("schema")) is not int
            or type(receipt.get("exit")) is not int or receipt != expected):
        errors.append(f"{label}: run receipt does not bind unit/role/source/argv/exit/raw")


def source_file(item, repo, commit, errors, label):
    if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not HEX.fullmatch(str(item.get("sha256", ""))):
        errors.append(f"{label}: source path and SHA required")
        return
    name = item["path"]
    if name.startswith("/") or ".." in Path(name).parts:
        errors.append(f"{label}: invalid source path")
        return
    kind = subprocess.run(["git", "cat-file", "-t", f"{commit}:{name}"], cwd=repo, capture_output=True, text=True)
    if kind.returncode or kind.stdout.strip() != "blob":
        errors.append(f"{label}: fixed source is not a blob")
        return
    result = subprocess.run(["git", "show", f"{commit}:{name}"], cwd=repo, capture_output=True)
    if result.returncode or digest(result.stdout) != item["sha256"]:
        errors.append(f"{label}: fixed-commit source SHA mismatch")


def validate(snapshot, ledger, snapshot_bytes, repo, evidence_root, current_task_table_bytes, memo_repo):
    errors = []
    if digest(current_task_table_bytes) != snapshot.get("task_table_sha256"):
        errors.append("snapshot: current memo task table differs")
    errors.extend(snapshot_table_errors(snapshot, current_task_table_bytes))
    tasks = snapshot.get("tasks")
    if snapshot.get("schema") != 1 or not isinstance(tasks, list) or len(tasks) != 72:
        return ["snapshot: expected 72 task rows"]
    ids = [t.get("id") for t in tasks if isinstance(t, dict)]
    if len(ids) != 72 or len(set(ids)) != 72 or any(not re.fullmatch(r"[A-Z][0-9]{2}", str(x)) for x in ids):
        return ["snapshot: duplicate or invalid task ID"]
    if ledger.get("schema") != 1 or ledger.get("snapshot_sha256") != digest(snapshot_bytes):
        errors.append("ledger: snapshot SHA mismatch")
    units = ledger.get("units")
    if not isinstance(units, dict) or set(units) != set(ids):
        return errors + ["ledger: missing or extra task IDs"]
    if not COMMIT.fullmatch(str(ledger.get("source_commit", ""))):
        errors.append("ledger: fixed source commit required")
    else:
        result = subprocess.run(["git", "cat-file", "-e", ledger["source_commit"] + "^{commit}"], cwd=repo, capture_output=True)
        if result.returncode:
            errors.append("ledger: fixed source commit unavailable")
    used_raw = {}
    used_raw_hash = {}
    table_rows = {}
    for line in current_task_table_bytes.decode("utf-8").splitlines():
        match = re.match(r"^\| ([A-Z][0-9]{2}) \|", line)
        if match:
            table_rows[match.group(1)] = line + "\n"
    for task in tasks:
        tid = task["id"]
        unit = units[tid]
        if not isinstance(unit, dict):
            errors.append(f"{tid}: invalid row")
            continue
        status = task.get("status")
        if status not in OPEN | {SIGNED, TESTNET} or unit.get("status") != status or unit.get("scope") != task.get("lane"):
            errors.append(f"{tid}: task-table status/scope mismatch")
            continue
        if status == TESTNET:
            if unit.get("accepted") is True:
                errors.append(f"{tid}: testnet item cannot close development gate")
            continue
        if status in OPEN:
            if unit.get("accepted") is True:
                errors.append(f"{tid}: open item marked accepted")
            else:
                errors.append(f"{tid}: development unit open")
            continue
        ev = unit.get("evidence")
        if not isinstance(ev, dict):
            partial = unit.get("partial_evidence")
            if not isinstance(partial, dict):
                errors.append(f"{tid}: partial evidence inventory missing")
            else:
                row = table_rows.get(tid, "")
                if digest(row.encode()) != partial.get("task_table_row_sha256"):
                    errors.append(f"{tid}: task-table row SHA mismatch")
                for kind in ("review_reports", "memo_raw_artifacts"):
                    refs = partial.get(kind)
                    if not isinstance(refs, list):
                        errors.append(f"{tid}: {kind} inventory missing")
                        continue
                    for n, item in enumerate(refs):
                        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not item["path"].startswith("pq-native/") or not HEX.fullmatch(str(item.get("sha256", ""))):
                            errors.append(f"{tid}: {kind}:{n} malformed")
                            continue
                        result = subprocess.run(["git", "show", f"{snapshot['memo_commit']}:{item['path']}"], cwd=memo_repo, capture_output=True)
                        if result.returncode or digest(result.stdout) != item["sha256"]:
                            errors.append(f"{tid}: {kind}:{n} fixed memo SHA mismatch")
                refs = partial.get("local_raw_artifacts")
                if not isinstance(refs, list):
                    errors.append(f"{tid}: local raw inventory missing")
                else:
                    for n, item in enumerate(refs):
                        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not Path(item["path"]).is_absolute() or not HEX.fullmatch(str(item.get("sha256", ""))):
                            errors.append(f"{tid}: local raw:{n} malformed")
                            continue
                        path = Path(item["path"])
                        if not path.is_file() or digest(path.read_bytes()) != item["sha256"]:
                            errors.append(f"{tid}: local raw:{n} SHA mismatch or missing")
                refs = partial.get("source_references")
                if not isinstance(refs, list):
                    errors.append(f"{tid}: source reference inventory missing")
                else:
                    for n, item in enumerate(refs):
                        if not isinstance(item, dict) or not COMMIT.fullmatch(str(item.get("commit", ""))):
                            errors.append(f"{tid}: source reference:{n} malformed")
                        else:
                            source_file(item, repo, item["commit"], errors, f"{tid}:source reference:{n}")
                            if item.get("sha_origin") not in {"sha_literal_present_in_report", "computed_from_cited_path"}:
                                errors.append(f"{tid}: source reference:{n} SHA origin missing")
                            cited = item.get("cited_by")
                            if not isinstance(cited, str) or not cited.startswith("pq-native/"):
                                errors.append(f"{tid}: source reference:{n} report citation missing")
                            else:
                                report = subprocess.run(["git", "show", f"{snapshot['memo_commit']}:{cited}"], cwd=memo_repo, capture_output=True)
                                if report.returncode or item["path"].encode() not in report.stdout:
                                    errors.append(f"{tid}: source reference:{n} path absent from fixed report")
                                elif item["sha_origin"] == "sha_literal_present_in_report" and item["sha256"].encode() not in report.stdout:
                                    errors.append(f"{tid}: source reference:{n} SHA literal absent from fixed report")
                gaps = partial.get("missing_required_fields")
                if not isinstance(gaps, list) or not gaps or not all(isinstance(x, str) and x.strip() for x in gaps):
                    errors.append(f"{tid}: explicit per-row gaps missing")
            errors.append(f"{tid}: signed row lacks machine evidence")
            continue
        if ev.get("unit_id") != tid or not COMMIT.fullmatch(str(ev.get("source_commit", ""))):
            errors.append(f"{tid}: fixed source identity missing")
            continue
        files = ev.get("source_files")
        if not isinstance(files, list) or not files:
            errors.append(f"{tid}: source files missing")
        else:
            for n, file in enumerate(files):
                source_file(file, repo, ev["source_commit"], errors, f"{tid}:source:{n}")
        command = ev.get("command")
        if not isinstance(command, dict) or not isinstance(command.get("argv"), list) or not command["argv"] or not all(isinstance(x, str) for x in command["argv"]) or type(command.get("exit")) is not int:
            errors.append(f"{tid}: command and exact exit required")
        raw = ev.get("raw")
        def unique_raw(item, label):
            actual = artifact(item, evidence_root, errors, label)
            if actual:
                if actual in used_raw:
                    errors.append(f"{tid}: raw reused from {used_raw[actual]}")
                used_raw[actual] = label
                raw_hash = item["sha256"]
                if raw_hash in used_raw_hash:
                    errors.append(f"{tid}: raw content reused from {used_raw_hash[raw_hash]}")
                used_raw_hash[raw_hash] = label

        unique_raw(raw, f"{tid}:raw")
        if isinstance(command, dict) and isinstance(command.get("argv"), list) and type(command.get("exit")) is int and isinstance(raw, dict):
            run_receipt(ev.get("receipt"), evidence_root, errors, f"{tid}:main", {
                "schema": 1, "unit_id": tid, "role": "main", "source_commit": ev["source_commit"],
                "argv": command["argv"], "exit": command["exit"], "raw_sha256": raw.get("sha256"),
            })
        controls = ev.get("controls")
        if not isinstance(controls, dict):
            errors.append(f"{tid}: old-red/new-green/mutant controls required")
        else:
            for kind, wanted in (("old_red", False), ("new_green", True), ("mutant_red", False)):
                control = controls.get(kind)
                if not isinstance(control, dict) or not isinstance(control.get("argv"), list) or not control["argv"] or not all(isinstance(x, str) for x in control["argv"]) or type(control.get("exit")) is not int or (control["exit"] == 0) != wanted:
                    errors.append(f"{tid}:{kind}: wrong or missing exit")
                else:
                    control_commit = control.get("source_commit")
                    if not COMMIT.fullmatch(str(control_commit)):
                        errors.append(f"{tid}:{kind}: independent executed source identity missing")
                        continue
                    control_files = control.get("source_files")
                    if not isinstance(control_files, list) or not control_files:
                        errors.append(f"{tid}:{kind}: executed source files missing")
                    else:
                        for n, file in enumerate(control_files):
                            source_file(file, repo, control_commit, errors, f"{tid}:{kind}:source:{n}")
                    unique_raw(control.get("raw"), f"{tid}:{kind}")
                    if isinstance(control.get("raw"), dict):
                        run_receipt(control.get("receipt"), evidence_root, errors, f"{tid}:{kind}", {
                            "schema": 1, "unit_id": tid, "role": kind, "source_commit": control_commit,
                            "argv": control["argv"], "exit": control["exit"],
                            "raw_sha256": control["raw"].get("sha256"),
                        })
        binary = ev.get("binary")
        if isinstance(binary, dict) and binary.get("gap"):
            if not isinstance(binary["gap"], str) or len(binary["gap"].strip()) < 8:
                errors.append(f"{tid}: unexplained binary gap")
        else:
            artifact(binary, evidence_root, errors, f"{tid}:binary")
        artifact(ev.get("independent_review"), evidence_root, errors, f"{tid}:review")
        if not isinstance(ev.get("applicability"), str) or not ev["applicability"].strip():
            errors.append(f"{tid}: applicability missing")
        if not isinstance(ev.get("invalidating_changes"), list) or not ev["invalidating_changes"] or not all(isinstance(x, str) and x.strip() for x in ev["invalidating_changes"]):
            errors.append(f"{tid}: invalidating changes missing")
        ci = ev.get("ci")
        if not isinstance(ci, dict) or ci.get("state") not in {"passed", "pending", "not_applicable"} or not isinstance(ci.get("reason"), str) or not ci["reason"].strip():
            errors.append(f"{tid}: CI status/reason missing or failed")
        if unit.get("accepted") is not True:
            errors.append(f"{tid}: evidence not reconciled/accepted")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--memo-repo", type=Path, required=True)
    parser.add_argument("--memo-ref", default="origin/main")
    args = parser.parse_args()
    raw = args.snapshot.read_bytes()
    if digest(raw) != EXPECTED_SNAPSHOT_SHA:
        print(json.dumps({"passed": False, "errors": ["task snapshot differs from frozen memo/main table"]}))
        return 1
    snapshot = json.loads(raw)
    ledger = json.loads(args.ledger.read_bytes())
    table = subprocess.run(["git", "show", f"{args.memo_ref}:{snapshot['task_table_path']}"], cwd=args.memo_repo, capture_output=True)
    if table.returncode:
        print(json.dumps({"passed": False, "errors": ["current memo task table unavailable"]}))
        return 1
    errors = validate(snapshot, ledger, raw, args.repo, args.evidence_root, table.stdout, args.memo_repo)
    print(json.dumps({"passed": not errors, "task_count": len(snapshot.get("tasks", [])),
                      "counts": unit_counts(snapshot, ledger), "errors": errors}, ensure_ascii=False, indent=2))
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
