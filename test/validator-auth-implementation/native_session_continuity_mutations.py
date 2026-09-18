#!/usr/bin/env python3
"""Compile session-continuity mutants and require the named assertion."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/validator-auth-session-birth"))
from admission_mutations import compiled, invoke, named_failure, passing_suite  # noqa: E402


def mutations() -> list[tuple[str, str, str, str, str]]:
    return [
        (
            "restart-verify",
            "restart_commitment_conflict_refused",
            "guard-disable",
            "  if (!verified.ok())\n    return verified.error();",
            "  if (false && !verified.ok())\n    return verified.error();",
        ),
        (
            "restart-missing",
            "restart_missing_refused",
            "semantic-fault",
            "  if (!verified.ok())\n    return verified.error();",
            "  if (!verified.ok() && "
            "verified.error().code != \"session-commitment-missing\")\n"
            "    return verified.error();",
        ),
        (
            "committee-commitment",
            "committee_commitment_checked",
            "guard-disable",
            "  if (recorded.value() != commitment)\n"
            "    return Error{\"session-commitment-conflict\"};",
            "  if (recorded.value() != commitment &&\n"
            "      recorded.value().committee_hash == "
            "commitment.committee_hash)\n"
            "    return Error{\"session-commitment-conflict\"};",
        ),
        (
            "record-before-use",
            "new_session_recorded_before_use",
            "semantic-fault",
            "  auto recorded = store.record_new(commitment.value());\n"
            "  if (!recorded.ok())\n"
            "    return recorded.error();",
            "  Result<bool> recorded{true};\n"
            "  if (!recorded.ok())\n"
            "    return recorded.error();",
        ),
        (
            "frontier-binding",
            "frontier_rollback_refused",
            "guard-disable",
            "  if (disk_frontier.value().first != sequence ||\n"
            "      disk_frontier.value().second != previous)\n"
            "    return Error{\"session-commitment-frontier\"};",
            "  if (false && "
            "(disk_frontier.value().first != sequence ||\n"
            "                disk_frontier.value().second != previous))\n"
            "    return Error{\"session-commitment-frontier\"};",
        ),
        (
            "nonmember-fallback",
            "member_authority_only_for_member",
            "guard-disable",
            "  if (identity == Hash{} || found == members.end())\n"
            "    return Error{\"session-member-nonmember\"};",
            "  if (identity == Hash{})\n"
            "    return Error{\"session-member-nonmember\"};\n"
            "  if (found == members.end())\n"
            "    found = members.begin();",
        ),
        (
            "same-session-release",
            "same_session_not_terminated",
            "guard-disable",
            "  if (current.value() &&\n"
            "      current.value()->native_session_id == native_session_id_) {",
            "  if (false && current.value() &&\n"
            "      current.value()->native_session_id == native_session_id_) {",
        ),
        (
            # The duty a member signs must carry the canonical P0 session id, not
            # the native ValidatorSessionId. Substituting the native id here is
            # exactly the frozen-WIRE deviation the split corrects.
            "member-duty-p0-session",
            "member_authority_only_for_member",
            "semantic-fault",
            "      chain_, snapshot, p0_session_id_, role, position, payload);",
            "      chain_, snapshot, native_session_id_, role, position, payload);",
        ),
        (
            "termination-release",
            "authenticated_termination_releases",
            "semantic-fault",
            "  context_.reset();\n"
            "  ++release_count_;",
            "  (void)context_;\n"
            "  ++release_count_;",
        ),
        (
            "release-counter",
            "authenticated_termination_releases",
            "semantic-fault",
            "  context_.reset();\n"
            "  ++release_count_;",
            "  context_.reset();\n"
            "  release_count_ += 0;",
        ),
    ]


def invoke_with_env(command: list[str], log: Path, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    merged = dict(os.environ)
    merged.update(environment)
    result = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False, env=merged)
    log.write_text(
        "$ " + " ".join(command) + "\n"
        + "exit_code=" + str(result.returncode) + "\n"
        + "--- stdout ---\n" + result.stdout
        + "--- stderr ---\n" + result.stderr
    )
    return result


def run_provider_validation(args: argparse.Namespace, build: Path) -> None:
    provider = build / "validator/auth/test-p0-native-session-provider"
    if not compiled(
        ["cmake", "--build", str(build), "--target", "test-p0-native-session-provider", "-j2"],
        provider, args.out / "provider-build.log"):
        raise RuntimeError("session provider target did not compile")

    listed = invoke(
        [str(provider), str(args.owner.resolve()), str(args.committee.resolve()),
         str((args.work / "provider-list").resolve()), "--list"],
        args.out / "provider-cases.log")
    provider_cases = len(listed.stdout.splitlines())
    if listed.returncode != 0 or provider_cases == 0:
        raise RuntimeError("session provider case inventory failed")

    normal_work = args.work / "provider-normal"
    shutil.rmtree(normal_work, ignore_errors=True)
    normal = invoke(
        [str(provider), str(args.owner.resolve()), str(args.committee.resolve()), str(normal_work.resolve())],
        args.out / "provider-baseline.log")
    if not passing_suite(normal, provider_cases):
        raise RuntimeError("session provider baseline failed")

    sanitized_build = ROOT / "build-p0-sanitized"
    if sanitized_build.is_dir():
        sanitized = sanitized_build / "validator/auth/test-p0-native-session-provider"
        if not compiled(
            ["cmake", "--build", str(sanitized_build), "--target", "test-p0-native-session-provider", "-j2"],
            sanitized, args.out / "provider-sanitized-build.log"):
            raise RuntimeError("sanitized session provider target did not compile")
        committee_sanitized = args.committee.parent / (args.committee.name + "-sanitized")
        sanitized_work = args.work / "provider-sanitized"
        shutil.rmtree(sanitized_work, ignore_errors=True)
        run = invoke_with_env(
            [str(sanitized), str(args.owner.resolve()), str(committee_sanitized.resolve()),
             str(sanitized_work.resolve())],
            args.out / "provider-sanitized.log",
            {"ASAN_OPTIONS": "detect_leaks=1:detect_stack_use_after_return=1",
             "UBSAN_OPTIONS": "halt_on_error=1"})
        if not passing_suite(run, provider_cases):
            raise RuntimeError("sanitized session provider baseline failed")

    provider_out = args.out / "provider-mutations"
    command = [
        sys.executable,
        str(ROOT / "test/validator-auth-implementation/native_session_provider_mutations.py"),
        "--build", str(build),
        "--owner", str(args.owner.resolve()),
        "--committee", str(args.committee.resolve()),
        "--work", str((args.work / "provider-mutations").resolve()),
        "--out", str(provider_out.resolve()),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False)
    (args.out / "provider-mutations.log").write_text(
        "$ " + " ".join(command) + "\n"
        + "exit_code=" + str(result.returncode) + "\n"
        + "--- stdout ---\n" + result.stdout
        + "--- stderr ---\n" + result.stderr)
    if result.returncode != 0:
        raise RuntimeError("session provider mutations failed")
    shutil.copyfile(provider_out / "mutations.json", args.out / "provider-mutations.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--committee", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--stop", type=int)
    args = parser.parse_args()

    source = ROOT / "validator/auth/native-session-continuity.cpp"
    build = args.build.resolve()
    mutant_source = build / "validator/auth/mutated-native-session-continuity.cpp"
    binary = build / "validator/auth/test-p0-native-session-continuity-mutant"
    original = source.read_text()
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    args.out.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)
    mutant_source.write_text(original)

    build_command = [
        "cmake", "--build", str(build), "--target",
        "test-p0-native-session-continuity-mutant", "-j2",
    ]
    if not compiled(build_command, binary, args.out / "baseline-build.log"):
        raise RuntimeError("baseline did not produce an executable")

    listed = invoke(
        [str(binary), str(args.owner.resolve()), str(args.committee.resolve()),
         str((args.work / "list").resolve()), "--list"],
        args.out / "cases.log")
    expected = len(listed.stdout.splitlines())
    if listed.returncode != 0 or expected == 0:
        raise RuntimeError("case inventory failed")

    baseline_work = args.work / "baseline"
    shutil.rmtree(baseline_work, ignore_errors=True)
    baseline = invoke(
        [str(binary), str(args.owner.resolve()), str(args.committee.resolve()), str(baseline_work.resolve())],
        args.out / "baseline.log")
    if not passing_suite(baseline, expected):
        raise RuntimeError("baseline tests failed")

    records: list[dict[str, object]] = []
    selected = mutations()[args.start:args.stop]
    if not selected:
        raise RuntimeError("no mutations selected")

    try:
        for guard, case, kind, old, new in selected:
            if original.count(old) != 1:
                raise RuntimeError(f"source anchor is not unique: {guard}")
            changed = original.replace(old, new, 1)
            if changed == original:
                raise RuntimeError(f"mutation did not reach source: {guard}")
            mutant_source.write_text(changed)
            if mutant_source.read_text() != changed:
                raise RuntimeError(f"mutated source write mismatch: {guard}")
            (args.out / f"{guard}.diff").write_text(
                "".join(difflib.unified_diff(
                    original.splitlines(True), changed.splitlines(True),
                    fromfile=str(source), tofile=str(mutant_source))))

            ok = compiled(build_command, binary, args.out / f"{guard}-build.log")
            record: dict[str, object] = {
                "guard": guard, "case": case, "kind": kind,
                "edit_reached_source": True, "compiled": ok,
                "assertion_name": case, "assertion_failed": False,
                "restored_baseline": False,
            }
            if ok:
                mutant_work = args.work / f"mutant-{guard}"
                shutil.rmtree(mutant_work, ignore_errors=True)
                actual = invoke(
                    [str(binary), str(args.owner.resolve()), str(args.committee.resolve()),
                     str(mutant_work.resolve()), case],
                    args.out / f"{guard}-run.log")
                record["assertion_failed"] = named_failure(actual, case)
                record["mutant_exit_code"] = actual.returncode

            mutant_source.write_text(original)
            restored_compiled = compiled(
                build_command, binary, args.out / f"{guard}-restored-build.log")
            restored_work = args.work / f"restored-{guard}"
            shutil.rmtree(restored_work, ignore_errors=True)
            restored = invoke(
                [str(binary), str(args.owner.resolve()), str(args.committee.resolve()), str(restored_work.resolve())],
                args.out / f"{guard}-restored.log")
            restored_ok = restored_compiled and passing_suite(restored, expected)
            record["restored_source_matches"] = mutant_source.read_bytes() == source.read_bytes()
            record["restored_method"] = "restore-source-copy-rebuild-and-rerun"
            record["restored_baseline"] = restored_ok
            record["restored_cases"] = expected if restored_ok else 0
            record["source_unchanged"] = hashlib.sha256(source.read_bytes()).hexdigest() == source_digest
            records.append(record)
            (args.out / "mutations.json").write_text(json.dumps(records, indent=2) + "\n")
            print(json.dumps(record), flush=True)

            if not (ok and record["assertion_failed"] and restored_ok and
                    record["restored_source_matches"] and record["source_unchanged"]):
                raise RuntimeError("mutation did not establish its named assertion: " + guard)
    finally:
        mutant_source.write_text(original)

    run_provider_validation(args, build)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_FAILURE: {error}", file=sys.stderr)
        sys.exit(2)
