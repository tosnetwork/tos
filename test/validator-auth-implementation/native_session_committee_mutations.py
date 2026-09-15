#!/usr/bin/env python3
"""Compile session-committee mutants and require each named assertion."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/validator-auth-session-birth"))
from admission_mutations import compiled, invoke, named_failure, passing_suite  # noqa: E402


def mutations() -> list[tuple[str, str, str, str, str]]:
    return [
        (
            "birth-anchor",
            "committee_at_birth",
            "semantic-fault",
            "  const auto anchor = anchor_from_session_block(selected.block);",
            "  const auto anchor = "
            "anchor_from_session_block(birth.birth().trusted_tip());",
        ),
        (
            "reuse-owned-context",
            "same_session_reuses_owned_context",
            "semantic-fault",
            "      existing, birth.birth(),",
            "      std::shared_ptr<const NativeSessionCommitteeContext>{}, "
            "birth.birth(),",
        ),
        (
            "block-response-binding",
            "wrong_response_refused",
            "guard-disable",
            "  if (!(request.id == id))\n"
            "    return Error{\"session-handoff-response-mismatch\"};",
            "  if (false && !(request.id == id))\n"
            "    return Error{\"session-handoff-response-mismatch\"};",
        ),
        (
            "identity-response-binding",
            "wrong_identity_response_refused",
            "guard-disable",
            "  if (request.anchor != anchor || !same_target(request.target, target))\n"
            "    return Error{\"session-handoff-response-mismatch\"};",
            "  if (false && (request.anchor != anchor || "
            "!same_target(request.target, target)))\n"
            "    return Error{\"session-handoff-response-mismatch\"};",
        ),
        (
            "block-bound",
            "oversize_response_refused",
            "guard-disable",
            "  if (bytes.empty() || bytes.size() > request.maximum_bytes)\n"
            "    return Error{\"session-handoff-block-bound\"};",
            "  if (false && (bytes.empty() || "
            "bytes.size() > request.maximum_bytes))\n"
            "    return Error{\"session-handoff-block-bound\"};",
        ),
        (
            "history-budget",
            "history_budget_preserved",
            "semantic-fault",
            "      std::move(state_reader), std::move(identity_reader), history_budget_);",
            "      std::move(state_reader), std::move(identity_reader), "
            "NativeSessionHistoryBudget{});",
        ),
        (
            "committee-budget",
            "committee_budget_preserved",
            "semantic-fault",
            "      existing_, birth.value(), chain_, committee_budget_);",
            "      existing_, birth.value(), chain_, StateReadBudget{});",
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--committee", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--stop", type=int)
    args = parser.parse_args()

    source = ROOT / "validator/auth/native-session-committee.cpp"
    build = args.build.resolve()
    mutant_source = (
        build / "validator/auth/mutated-native-session-committee.cpp"
    )
    binary = build / "validator/auth/test-p0-native-session-committee-mutant"
    original = source.read_text()
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    args.out.mkdir(parents=True, exist_ok=True)
    mutant_source.write_text(original)

    build_command = [
        "cmake",
        "--build",
        str(build),
        "--target",
        "test-p0-native-session-committee-mutant",
        "-j2",
    ]
    if not compiled(
        build_command, binary, args.out / "baseline-build.log"
    ):
        raise RuntimeError("baseline did not produce an executable")

    listed = invoke(
        [
            str(binary),
            str(args.owner.resolve()),
            str(args.committee.resolve()),
            "--list",
        ],
        args.out / "cases.log",
    )
    expected = len(listed.stdout.splitlines())
    if listed.returncode != 0 or expected == 0:
        raise RuntimeError("case inventory failed")

    baseline = invoke(
        [
            str(binary),
            str(args.owner.resolve()),
            str(args.committee.resolve()),
        ],
        args.out / "baseline.log",
    )
    if not passing_suite(baseline, expected):
        raise RuntimeError("baseline tests failed")

    records: list[dict[str, object]] = []
    selected = mutations()[args.start : args.stop]
    if not selected:
        raise RuntimeError("no mutations selected")

    try:
        for guard, case, kind, old, new in selected:
            if original.count(old) != 1:
                raise RuntimeError(
                    f"source anchor is not unique: {guard}"
                )
            changed = original.replace(old, new, 1)
            mutant_source.write_text(changed)
            (args.out / f"{guard}.diff").write_text(
                "".join(
                    difflib.unified_diff(
                        original.splitlines(True),
                        changed.splitlines(True),
                        fromfile=str(source),
                        tofile=str(mutant_source),
                    )
                )
            )
            ok = compiled(
                build_command,
                binary,
                args.out / f"{guard}-build.log",
            )
            record: dict[str, object] = {
                "guard": guard,
                "case": case,
                "kind": kind,
                "compiled": ok,
                "assertion_name": case,
                "assertion_failed": False,
                "restored_baseline": False,
            }
            if ok:
                actual = invoke(
                    [
                        str(binary),
                        str(args.owner.resolve()),
                        str(args.committee.resolve()),
                        case,
                    ],
                    args.out / f"{guard}-run.log",
                )
                record["assertion_failed"] = named_failure(
                    actual, case
                )
                record["mutant_exit_code"] = actual.returncode

            mutant_source.write_text(original)
            restored_compiled = compiled(
                build_command,
                binary,
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
            restored_ok = restored_compiled and passing_suite(
                restored, expected
            )
            record["restored_source_matches"] = (
                mutant_source.read_bytes() == source.read_bytes()
            )
            record["restored_method"] = (
                "restore-source-copy-rebuild-and-rerun"
            )
            record["restored_baseline"] = restored_ok
            record["restored_cases"] = expected if restored_ok else 0
            record["source_unchanged"] = (
                hashlib.sha256(source.read_bytes()).hexdigest()
                == source_digest
            )
            records.append(record)
            (args.out / "mutations.json").write_text(
                json.dumps(records, indent=2) + "\n"
            )
            print(json.dumps(record), flush=True)
            if not (
                ok
                and record["assertion_failed"]
                and restored_ok
                and record["restored_source_matches"]
                and record["source_unchanged"]
            ):
                raise RuntimeError(
                    "mutation did not establish its named assertion: "
                    + guard
                )
    finally:
        mutant_source.write_text(original)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_FAILURE: {error}", file=sys.stderr)
        sys.exit(2)
