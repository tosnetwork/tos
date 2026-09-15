#!/usr/bin/env python3
"""Compile real selector mutants; accept only the named assertion as evidence."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def named_failure(result: subprocess.CompletedProcess[str], case: str) -> bool:
    return (
        result.returncode == 1
        and f"SETUP_OK {case}" in result.stdout.splitlines()
        and result.stderr.splitlines() == [f"ASSERTION_FAILED {case}"]
        and not any(line.startswith("ASSERTION_FAILED") for line in result.stdout.splitlines())
    )


def invoke(command: list[str], log: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    log.write_text(
        "$ " + " ".join(command) + "\n"
        + "exit_code=" + str(result.returncode) + "\n"
        + "--- stdout ---\n" + result.stdout
        + "--- stderr ---\n" + result.stderr
    )
    return result


def compiled(command: list[str], artifact: Path, log: Path) -> bool:
    artifact.unlink(missing_ok=True)
    result = invoke(command, log)
    return result.returncode == 0 and artifact.is_file() and artifact.stat().st_size > 0 and os.access(artifact, os.X_OK)


def passing_suite(result: subprocess.CompletedProcess[str], expected: int) -> bool:
    return (
        result.returncode == 0
        and len(re.findall(r"^CASE_PASS ", result.stdout, re.MULTILINE)) == expected
        and result.stdout.splitlines()[-1:] == [f"SUMMARY cases={expected} passed={expected}"]
        and not result.stderr
    )


def mutations() -> list[tuple[str, str, str, str, str]]:
    # guard name, named case, mutation kind, original source, replacement source
    return [
        ("block-seqno", "maximum_coordinate", "guard-disable",
         "block.seqno != std::numeric_limits<std::uint32_t>::max()", "true"),
        ("block-root", "zero_root", "guard-disable", "block.root != Hash{}", "true"),
        ("block-file", "zero_file", "guard-disable", "block.file != Hash{}", "true"),
        ("block-state", "zero_state", "guard-disable", "block.state != Hash{}", "true"),
        ("epoch-native-id", "zero_native_id", "guard-disable", "epoch.native_session_id != Hash{}", "true"),
        ("epoch-election", "zero_election_hash", "guard-disable", "epoch.election_cell_hash != Hash{}", "true"),
        ("epoch-options", "zero_options_hash", "guard-disable", "epoch.native_options_hash != Hash{}", "true"),
        ("history-budget", "budget_exceeded", "guard-disable",
         "if (history.size() > observation_limit || history.size() > max_observations)",
         "if (false && (history.size() > observation_limit || history.size() > max_observations))"),
        ("history-link", "wrong_link", "guard-disable", "if (observation.block != expected_block)",
         "if (false && observation.block != expected_block)"),
        ("epoch-match", "future_not_current", "guard-disable", "if (!current || *current != expected_epoch)",
         "if (false && (!current || *current != expected_epoch))"),
        ("complete-parent", "missing_parent_is_not_birth", "guard-disable",
         "if (observation.block.seqno != 0 || observation.parent)",
         "if (false && (observation.block.seqno != 0 || observation.parent))"),
        ("parent-step", "parent_step_no_gaps", "guard-disable",
         "if (observation.parent->seqno != observation.block.seqno - 1)",
         "if (false && observation.parent->seqno != observation.block.seqno - 1)"),
        ("incomplete-history-fallback", "truncated_history", "semantic-fault",
         '  return Error{"session-birth-history-incomplete"};',
         '  if (candidate)\n    return SessionBirthResult{*candidate, expected_epoch, used};\n'
         '  return Error{"session-birth-history-incomplete"};'),
        ("lookup-error-as-boundary", "source_error_is_not_boundary", "semantic-fault",
         "    if (!observation.current.ok())\n      return observation.current.error();",
         "    if (!observation.current.ok()) {\n"
         "      if (candidate)\n        return SessionBirthResult{*candidate, expected_epoch, used};\n"
         "      return observation.current.error();\n    }"),
        ("local-tip-as-birth", "first_current_state", "semantic-fault",
         "      return SessionBirthResult{*candidate, expected_epoch, used};\n    }\n    candidate = observation.block;",
         "      return SessionBirthResult{trusted_tip, expected_epoch, used};\n    }\n    candidate = observation.block;"),
        ("genesis-tip-fallback", "genesis_birth", "semantic-fault",
         "      return SessionBirthResult{*candidate, expected_epoch, used};\n    }\n    if (observation.parent->seqno",
         "      return SessionBirthResult{trusted_tip, expected_epoch, used};\n    }\n    if (observation.parent->seqno"),
        ("empty-history-accepted", "empty_history", "semantic-fault",
         '  return Error{"session-birth-history-incomplete"};',
         '  if (history.empty())\n    return SessionBirthResult{trusted_tip, expected_epoch, used};\n'
         '  return Error{"session-birth-history-incomplete"};'),
        ("input-write", "read_only_and_owned_result", "semantic-fault",
         "      return SessionBirthResult{*candidate, expected_epoch, used};\n    }\n    candidate = observation.block;",
         "      const_cast<SessionBirthObservation&>(history.front()).block = {};\n"
         "      return SessionBirthResult{*candidate, expected_epoch, used};\n    }\n    candidate = observation.block;"),
        ("native-epoch-alias", "boundary_conflict_election", "guard-disable",
         "if (current && current->native_session_id == expected_epoch.native_session_id)",
         "if (false && current && current->native_session_id == expected_epoch.native_session_id)"),
        ("first-observation-conflict-order", "epoch_election", "semantic-fault",
         "      if (current && current->native_session_id == expected_epoch.native_session_id)\n"
         "        return Error{\"session-birth-epoch-conflict\"};\n"
         "      if (!candidate)\n"
         "        return Error{\"session-birth-not-current\"};",
         "      if (!candidate)\n"
         "        return Error{\"session-birth-not-current\"};\n"
         "      if (current && current->native_session_id == expected_epoch.native_session_id)\n"
         "        return Error{\"session-birth-epoch-conflict\"};"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", default=os.environ.get("CXX", "c++"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--stop", type=int)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / "validator/auth/session-birth.h"
    codec = root / "validator/auth/codec.h"
    driver = Path(__file__).with_name("session-birth-test.cpp")
    original = source.read_text()
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    args.out.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which(args.cxx)
    if compiler is None:
        raise RuntimeError("compiler not found")
    invoke([compiler, "--version"], args.out / "compiler.log")
    flags = ["-std=c++20", "-O0", "-Wall", "-Wextra", "-Werror", "-pedantic"]
    overlay = args.out / "overlay"
    include_dir = overlay / "validator/auth"
    include_dir.mkdir(parents=True, exist_ok=True)
    mutant_source = include_dir / source.name
    mutant_source.write_text(original)
    shutil.copyfile(codec, include_dir / codec.name)
    baseline = args.out / "baseline"
    command = [compiler, *flags, "-I", str(overlay), str(driver), "-o", str(baseline)]
    if not compiled(command, baseline, args.out / "baseline-build.log"):
        raise RuntimeError("baseline did not produce an executable")
    listed = invoke([str(baseline), "--list"], args.out / "cases.log")
    expected = len(listed.stdout.splitlines())
    if listed.returncode != 0 or expected == 0:
        raise RuntimeError("case inventory failed")
    if not passing_suite(invoke([str(baseline)], args.out / "baseline.log"), expected):
        raise RuntimeError("baseline tests failed")
    baseline_digest = hashlib.sha256(baseline.read_bytes()).hexdigest()
    records: list[dict[str, object]] = []
    selected = mutations()[args.start:args.stop]
    if not selected:
        raise RuntimeError("no mutations selected")
    for guard, case, kind, old, new in selected:
        if original.count(old) != 1:
            raise RuntimeError(f"source anchor is not unique: {guard}")
        changed = original.replace(old, new, 1)
        mutant_source.write_text(changed)
        (args.out / f"{guard}.diff").write_text("".join(difflib.unified_diff(
            original.splitlines(True), changed.splitlines(True), fromfile=str(source), tofile=str(mutant_source))))
        binary = args.out / f"mutant-{guard}"
        ok = compiled([compiler, *flags, "-I", str(overlay), str(driver), "-o", str(binary)],
                      binary, args.out / f"{guard}-build.log")
        record: dict[str, object] = {
            "guard": guard, "case": case, "kind": kind, "compiled": ok,
            "assertion_name": case, "assertion_failed": False, "restored_baseline": False,
        }
        if ok:
            actual = invoke([str(binary), case], args.out / f"{guard}-run.log")
            record["assertion_failed"] = named_failure(actual, case)
            record["mutant_exit_code"] = actual.returncode
        mutant_source.write_text(original)
        # The baseline has its own executable, never overwritten by a mutant.
        # Restore exactly the bytes that produced it, then rerun that baseline.
        restored_source = mutant_source.read_bytes() == source.read_bytes()
        restored_binary = hashlib.sha256(baseline.read_bytes()).hexdigest() == baseline_digest
        restored_ok = restored_source and restored_binary and passing_suite(
            invoke([str(baseline)], args.out / f"{guard}-restored.log"), expected)
        record["restored_source_matches"] = restored_source
        record["baseline_binary_unchanged"] = restored_binary
        record["restored_method"] = "restored-source-and-rerun-original-baseline"
        record["restored_baseline"] = restored_ok
        record["restored_cases"] = expected if restored_ok else 0
        record["source_unchanged"] = hashlib.sha256(source.read_bytes()).hexdigest() == source_digest
        records.append(record)
        (args.out / "mutations.json").write_text(json.dumps(records, indent=2) + "\n")
        print(json.dumps(record), flush=True)
        if not (ok and record["assertion_failed"] and restored_ok and record["source_unchanged"]):
            raise RuntimeError(f"mutation did not establish its named assertion: {guard}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_FAILURE: {error}", file=sys.stderr)
        sys.exit(2)
