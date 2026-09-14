#!/usr/bin/env python3
"""Compile admission mutants; accept only the named assertion as evidence."""
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
        ("reader-error", "reader_error_is_not_boundary", "semantic-fault",
         "    if (!observation.ok())\n      return observation.error();",
         "    if (!observation.ok())\n      return Error{\"session-birth-budget\"};"),
        ("budget-local-tip-fallback", "budget_never_falls_back", "semantic-fault",
         "  }\n  return Error{\"session-birth-budget\"};\n}\n\n// The native session ID",
         "  }\n  return AuthenticatedSessionBirth{trusted_tip, "
         "SessionBirthResult{history.back().block, expected_epoch, history.size()}};\n}\n\n// The native session ID"),
        ("hard-budget", "hard_budget", "guard-disable",
         "if (observation_limit == 0 || observation_limit > max_observations)",
         "if (observation_limit == 0 || (false && observation_limit > max_observations))"),
        ("options-hash", "zero_options_are_refused", "guard-disable",
         "if (input.native_options_hash == Hash{})",
         "if (false && input.native_options_hash == Hash{})"),
        ("legacy-key-coordinate", "legacy_key_coordinate_is_normalized", "semantic-fault",
         "input.new_catchain_ids ? input.last_key_block_seqno : 0",
         "input.last_key_block_seqno"),
        ("admission-epoch-conflict", "same_id_metadata_conflict_is_refused", "guard-disable",
         "if (held.epoch != incoming.epoch)",
         "if (false && held.epoch != incoming.epoch)"),
        ("admission-birth-conflict", "same_id_birth_conflict_is_refused", "guard-disable",
         "if (held.block != incoming.block)",
         "if (false && held.block != incoming.block)"),
        ("derive-at-tip", "derive_uses_birth_not_detection_tip", "semantic-fault",
         "std::invoke(std::forward<Derive>(derive), birth.selected().block)",
         "std::invoke(std::forward<Derive>(derive), birth.trusted_tip())"),
        ("derive-error-fallback", "derive_error_has_no_fallback", "semantic-fault",
         "  if (!committee.ok())\n    return committee.error();\n  using Context = SessionCommitteeContext<Committee>;",
         "  using Context = SessionCommitteeContext<Committee>;\n"
         "  if (!committee.ok())\n"
         "    return std::shared_ptr<const Context>(new Context(std::move(birth), Committee{}));"),
        ("reuse-derives-again", "same_session_reuses_owned_context", "guard-disable",
         "if (decision.value() == SessionAdmissionDecision::reuse_existing)",
         "if (false && decision.value() == SessionAdmissionDecision::reuse_existing)"),
        ("different-id-reuse", "new_native_id_creates_new_context", "semantic-fault",
         "if (held.epoch.native_session_id != incoming.epoch.native_session_id)\n    return SessionAdmissionDecision::create_new;",
         "if (held.epoch.native_session_id != incoming.epoch.native_session_id)\n"
         "    return SessionAdmissionDecision::reuse_existing;"),
        ("walk-parent-coordinate", "walks_exact_authenticated_chain", "semantic-fault",
         "    expected = *history.back().parent;",
         "    expected = trusted_tip;"),
        ("read-past-boundary", "stops_after_authenticated_boundary", "semantic-fault",
         "    if (selected.ok())\n      return AuthenticatedSessionBirth{trusted_tip, selected.value()};",
         "    if (selected.ok()) {\n"
         "      (void)read(selected.value().block);\n"
         "      return AuthenticatedSessionBirth{trusted_tip, selected.value()};\n"
         "    }"),
        ("empty-reader-error", "empty_reader_is_unavailable", "semantic-fault",
         '    return Error{"session-birth-history-unavailable"};',
         '    return Error{"session-birth-budget"};'),
        ("zero-budget-error", "zero_budget", "semantic-fault",
         "  if (observation_limit == 0 || observation_limit > max_observations)\n"
         '    return Error{"session-birth-budget"};',
         "  if (observation_limit > max_observations)\n"
         '    return Error{"session-birth-budget"};\n'
         "  if (observation_limit == 0)\n"
         '    return Error{"session-birth-history-unavailable"};'),
        ("drop-owned-committee", "owned_committee_is_immutable", "semantic-fault",
         "new Context(std::move(birth), std::move(committee.value()))",
         "new Context(std::move(birth), Committee{})"),
        ("drop-new-key-coordinate", "new_id_key_coordinate_is_preserved", "semantic-fault",
         "input.new_catchain_ids ? input.last_key_block_seqno : 0",
         "0"),
        ("shard-coordinate", "split_merge_shards_are_not_aliased", "semantic-fault",
         "                           input.shard,\n                           input.catchain,",
         "                           std::uint64_t{1} << 63,\n                           input.catchain,"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", default=os.environ.get("CXX", "c++"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--stop", type=int)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / "validator/auth/session-admission.h"
    selector = root / "validator/auth/session-birth.h"
    codec = root / "validator/auth/codec.h"
    driver = Path(__file__).with_name("session-admission-test.cpp")
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
    shutil.copyfile(selector, include_dir / selector.name)
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
