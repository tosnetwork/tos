#!/usr/bin/env python3
"""Compile node-history adapter mutants and require isolated named failures."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "validator/auth/native-node-history.cpp"


def mutations() -> list[tuple[str, str, str, str, str]]:
    return [
        (
            "missing-coordinate",
            "missing_coordinate_refuses_substitution",
            "guard-disable",
            "  auto authenticated = history_.finalized_anchor(request.seqno_);\n"
            "  if (!authenticated.ok())\n"
            "    return authenticated.error();",
            "  auto authenticated = history_.finalized_anchor(request.seqno_);\n"
            "  if (!authenticated.ok())\n"
            "    return request;",
        ),
        (
            "exact-anchor",
            "exact_anchor_binding",
            "guard-disable",
            "  if (authenticated.value() != request)\n"
            "    return Error{\"node-history-anchor-conflict\"};",
            "  if (false && authenticated.value() != request)\n"
            "    return Error{\"node-history-anchor-conflict\"};",
        ),
        (
            "state-binding",
            "exact_anchor_binding",
            "guard-disable",
            "  auto bound = native_session_history_detail::bind_state(\n"
            "      loaded.value(), anchor, chain_);\n"
            "  if (!bound.ok())\n"
            "    return bound.error();",
            "  Result<bool> bound(true);\n"
            "  if (!bound.ok())\n"
            "    return bound.error();",
        ),
        (
            "outage-provenance",
            "outage_provenance",
            "semantic-fault",
            "Error preserve_source(const Error& error) {\n"
            "  return error;\n"
            "}",
            "Error preserve_source(const Error&) {\n"
            "  return Error{\"history-unavailable\"};\n"
            "}",
        ),
        (
            "cumulative-budget",
            "budget_not_refreshed",
            "guard-disable",
            "  --remaining;\n"
            "  return true;",
            "  (void)remaining;\n"
            "  return true;",
        ),
        (
            "retained-history",
            "retained_history",
            "semantic-fault",
            "Result<td::Ref<vm::Cell>> NativeNodeHistoryAdapter::state(\n"
            "    const Anchor& request) const {\n"
            "  auto authenticated = authenticate(request);",
            "Result<td::Ref<vm::Cell>> NativeNodeHistoryAdapter::state(\n"
            "    const Anchor& request) const {\n"
            "  if (request.seqno_ != head_.seqno_)\n"
            "    return Error{\"finalized-anchor-unavailable\"};\n"
            "  auto authenticated = authenticate(request);",
        ),
    ]


def invoke(
    command: list[str], log: Path, timeout: int = 600
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, capture_output=True, text=True,
        timeout=timeout, check=False
    )
    log.write_text(
        "$ " + " ".join(command)
        + f"\nexit_code={result.returncode}\n--- stdout ---\n"
        + result.stdout
        + "--- stderr ---\n"
        + result.stderr
    )
    return result


def compiled(
    command: list[str], binary: Path, log: Path
) -> bool:
    binary.unlink(missing_ok=True)
    result = invoke(command, log)
    return (
        result.returncode == 0
        and binary.is_file()
        and binary.stat().st_size > 0
        and os.access(binary, os.X_OK)
    )


def passing(
    result: subprocess.CompletedProcess[str], expected: int
) -> bool:
    return (
        result.returncode == 0
        and result.stderr == ""
        and result.stdout.splitlines()[-1:]
        == [f"SUMMARY cases={expected} passed={expected}"]
        and sum(
            line.startswith("CASE_PASS ")
            for line in result.stdout.splitlines()
        )
        == expected
    )


def named_failure(
    result: subprocess.CompletedProcess[str], case: str
) -> bool:
    return (
        result.returncode == 1
        and result.stdout.splitlines() == [f"SETUP_OK {case}"]
        and result.stderr.splitlines()
        == [f"ASSERTION_FAILED {case}"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--committee", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    build = args.build.resolve()
    mutant_source = (
        build / "test/validator-auth-implementation/"
        "mutated-native-node-history.cpp"
    )
    binary = (
        build / "test/validator-auth-implementation/"
        "test-p0-node-history-adapter-mutant"
    )
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    original_digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    mutant_source.parent.mkdir(parents=True, exist_ok=True)
    mutant_source.write_text(original)

    build_command = [
        "cmake", "--build", str(build), "--target",
        "test-p0-node-history-adapter-mutant", "-j2",
    ]
    if not compiled(
        build_command, binary, args.out / "baseline-build.log"
    ):
        raise RuntimeError(
            "baseline mutant target did not produce an executable"
        )

    listed = invoke(
        [
            str(binary),
            str(args.owner.resolve()),
            str(args.committee.resolve()),
            "--list",
        ],
        args.out / "cases.log",
    )
    case_names = listed.stdout.splitlines()
    if listed.returncode != 0 or not case_names:
        raise RuntimeError("case inventory failed")
    expected = len(case_names)

    baseline = invoke(
        [
            str(binary),
            str(args.owner.resolve()),
            str(args.committee.resolve()),
        ],
        args.out / "baseline.log",
    )
    if not passing(baseline, expected):
        raise RuntimeError("baseline tests failed")

    records: list[dict[str, object]] = []
    try:
        for guard, case, kind, old, new in mutations():
            if original.count(old) != 1:
                raise RuntimeError(
                    f"source anchor is not unique: {guard}"
                )
            changed = original.replace(old, new, 1)
            if changed == original:
                raise RuntimeError(
                    f"mutation did not reach source: {guard}"
                )
            mutant_source.write_text(changed)
            if mutant_source.read_text() != changed:
                raise RuntimeError(
                    f"mutated source write mismatch: {guard}"
                )

            (args.out / f"{guard}.diff").write_text(
                "".join(
                    difflib.unified_diff(
                        original.splitlines(True),
                        changed.splitlines(True),
                        fromfile=str(SOURCE),
                        tofile=str(mutant_source),
                    )
                )
            )

            did_compile = compiled(
                build_command, binary,
                args.out / f"{guard}-build.log",
            )
            named = False
            isolated = False
            if did_compile:
                targeted = invoke(
                    [
                        str(binary),
                        str(args.owner.resolve()),
                        str(args.committee.resolve()),
                        case,
                    ],
                    args.out / f"{guard}-named.log",
                )
                named = named_failure(targeted, case)

                others = invoke(
                    [
                        str(binary),
                        str(args.owner.resolve()),
                        str(args.committee.resolve()),
                        f"--exclude={case}",
                    ],
                    args.out / f"{guard}-others.log",
                )
                isolated = passing(others, expected - 1)

            mutant_source.write_text(original)
            restored_compile = compiled(
                build_command, binary,
                args.out / f"{guard}-restored-build.log",
            )
            restored = invoke(
                [
                    str(binary),
                    str(args.owner.resolve()),
                    str(args.committee.resolve()),
                ],
                args.out / f"{guard}-restored.log",
            )
            restored_ok = (
                restored_compile and passing(restored, expected)
            )
            record = {
                "guard": guard,
                "case": case,
                "kind": kind,
                "edit_reached_source": True,
                "compiled": did_compile,
                "named_assertion_failed": named,
                "other_cases_passed": isolated,
                "restored_source_matches":
                    mutant_source.read_text() == original,
                "restored_baseline": restored_ok,
                "source_unchanged":
                    hashlib.sha256(SOURCE.read_bytes()).hexdigest()
                    == original_digest,
            }
            records.append(record)
            (args.out / "mutations.json").write_text(
                json.dumps(records, indent=2) + "\n"
            )
            print(json.dumps(record), flush=True)

            if not (
                did_compile
                and named
                and isolated
                and restored_ok
                and record["restored_source_matches"]
                and record["source_unchanged"]
            ):
                raise RuntimeError(
                    "mutation did not establish only its "
                    f"named assertion: {guard}"
                )
    finally:
        mutant_source.write_text(original)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_FAILURE {error}", file=sys.stderr)
        sys.exit(2)
