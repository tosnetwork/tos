#!/usr/bin/env python3
"""Read-only replay of the retained d4d X02 snapshots against both parsers.

The d4d run contains eight complete snapshots and an incomplete first recovery
snapshot. This checks each complete raw snapshot, without treating the old run
as a successful X02 fault-window verdict.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import types

import x02_fault_evidence as current


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def old_parser(commit: str) -> types.ModuleType:
    source = subprocess.check_output(
        ["git", "show", f"{commit}:scripts/x02_fault_evidence.py"])
    module = types.ModuleType("x02_d4d_old")
    module.__file__ = "scripts/x02_fault_evidence.py"
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def replay(root: Path, old_commit: str) -> dict:
    policy_path = root / "x02-policy.json"
    policy = json.loads(policy_path.read_bytes())
    samples = root / "x02-directed"
    old = old_parser(old_commit)
    names = [node["name"] for node in policy["nodes"]]
    seen = {name: {} for name in names}
    journals = {name: {} for name in names}
    global_ids = {}
    generations = {}
    tips = {}
    previous = None
    complete = []
    old_header_red = None
    for index in range(9):
        paths = list(samples.glob(f"sample-{index:02d}-*.json"))
        if len(paths) != 1:
            raise ValueError(f"sample-{index:02d} is absent or ambiguous")
        snapshot = json.loads(paths[0].read_bytes())
        if index == 1:
            try:
                old.validate_tc_surface(snapshot, policy)
            except ValueError as exc:
                old_header_red = str(exc)
            if old_header_red != "unaccounted tc filter shares the validator peer interface":
                raise ValueError("old parser did not reject the first real flower header")
        if index == 8:
            if (snapshot.get("capture_error") !=
                    "ValueError('common height regressed below anchor')"
                    or snapshot.get("common_seqno") != 42
                    or snapshot.get("anchor_common_seqno") != 47
                    or snapshot["rpc"].get("range_headers") != {}):
                raise ValueError("sample-08 is not the retained incomplete recovery record")
            try:
                current.verify_snapshot(
                    snapshot, policy, snapshot["policy_sha256"], seen, journals,
                    global_ids, generations, tips, previous["post_journals"])
            except ValueError as exc:
                if str(exc) != "range-header node set differs from live phase":
                    raise
                incomplete_error = str(exc)
            else:
                raise ValueError("incomplete sample-08 unexpectedly verified")
            return {"passed": True, "old_commit": old_commit,
                    "old_first_header_red": old_header_red,
                    "complete_snapshots": complete,
                    "sample_08": {"sha256": sha256(paths[0]),
                                  "incomplete_error": incomplete_error},
                    "policy_sha256": sha256(policy_path),
                    "current_parser_sha256": sha256(Path(current.__file__)),
                    "replay_source_sha256": sha256(Path(__file__))}
        if snapshot.get("capture_error"):
            raise ValueError(f"sample-{index:02d} has a capture error")
        parsed = current.verify_snapshot(
            snapshot, policy, snapshot["policy_sha256"], seen, journals,
            global_ids, generations, tips,
            previous["post_journals"] if previous else None)
        complete.append({"sample": index, "sha256": sha256(paths[0]),
                         "common_seqno": parsed["common"][2]})
        previous = snapshot
    raise AssertionError("unreachable")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--old-commit", default="d4d12eb74")
    args = parser.parse_args()
    try:
        result = replay(args.run_root, args.old_commit)
    except Exception as exc:
        print(json.dumps({"passed": False, "error": f"{type(exc).__name__}: {exc}"},
                         sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
