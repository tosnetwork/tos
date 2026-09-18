#!/usr/bin/env python3
"""Compile finalized-head mutants and require isolated named failures."""
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
SOURCE = ROOT / "validator/auth/native-finality.cpp"

MUTATIONS = [
    (
        "genesis-zero-coordinate",
        "configured_genesis_must_name_exact_zero_block",
        "guard-disable",
        "        genesis.block.id.seqno != 0 ||\n",
        "",
    ),
    (
        "genesis-chain-coordinate",
        "configured_genesis_must_match_chain_coordinates",
        "guard-disable",
        "        genesis.block.file_hash != file)\n",
        "        false)\n",
    ),
    (
        "genesis-state-binding",
        "configured_genesis_must_match_state_root",
        "guard-disable",
        "        state_hash != chain_.genesis_root)\n",
        "        false)\n",
    ),
    (
        "final-signature-kind",
        "final_signature_set_required",
        "guard-disable",
        "  if (verified.value().kind !=\n"
        "      NativeSignatureSetKind::final)\n"
        '    return Error{"finalized-head-approval-only"};',
        "  if (false && verified.value().kind !=\n"
        "      NativeSignatureSetKind::final)\n"
        '    return Error{"finalized-head-approval-only"};',
    ),
    (
        "peer-claim",
        "peer_claim_refused",
        "guard-disable",
        "  if (observed.value().peer_claim)\n"
        '    return Error{"finalized-head-peer-claim"};',
        "  if (false && observed.value().peer_claim)\n"
        '    return Error{"finalized-head-peer-claim"};',
    ),
    (
        "state-binding",
        "complete_anchor_state_binding",
        "guard-disable",
        "      resulting_hash != anchor.value().state_)",
        "      false)",
    ),
    (
        "monotonic-head",
        "head_regression_refused",
        "guard-disable",
        "    if (anchor.value().seqno_ < current_->seqno_)\n"
        '      return Error{"finalized-head-regression"};',
        "    if (false && anchor.value().seqno_ < current_->seqno_)\n"
        '      return Error{"finalized-head-regression"};',
    ),
    (
        "latest-fallback",
        "no_latest_fallback",
        "semantic-fault",
        "  if (observed.value().finality_candidate)\n"
        "    candidate = &*observed.value().finality_candidate;\n"
        "  else\n"
        '    return Error{"finalized-head-unavailable"};',
        "  if (observed.value().finality_candidate)\n"
        "    candidate = &*observed.value().finality_candidate;\n"
        "  else if (observed.value().latest_candidate)\n"
        "    candidate = &*observed.value().latest_candidate;\n"
        "  else\n"
        '    return Error{"finalized-head-unavailable"};',
    ),
]


def invoke(command: list[str], log: Path, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, check=False
    )
    log.write_text(
        "$ " + " ".join(command)
        + f"\nexit_code={result.returncode}\n--- stdout ---\n"
        + result.stdout + "--- stderr ---\n" + result.stderr
    )
    return result


def built(command: list[str], binary: Path, log: Path) -> bool:
    binary.unlink(missing_ok=True)
    result = invoke(command, log)
    return (
        result.returncode == 0
        and binary.is_file()
        and binary.stat().st_size > 0
        and os.access(binary, os.X_OK)
    )


def passing(result: subprocess.CompletedProcess[str], expected: int) -> bool:
    lines = result.stdout.splitlines()
    return (
        result.returncode == 0
        and result.stderr == ""
        and lines[-1:] == [f"SUMMARY cases={expected} passed={expected}"]
        and sum(line.startswith("CASE_PASS ") for line in lines) == expected
    )


def named_failure(result: subprocess.CompletedProcess[str], case: str) -> bool:
    return (
        result.returncode == 1
        and result.stdout.splitlines() == [f"SETUP_OK {case}"]
        and result.stderr.splitlines() == [f"ASSERTION_FAILED {case}"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--committee", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    build = args.build.resolve()
    folder = build / "test/validator-auth-implementation"
    mutant_source = folder / "mutated-native-finality.cpp"
    binary = folder / "test-p0-native-finality-mutant"
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    mutant_source.write_text(original)

    build_command = [
        "cmake", "--build", str(build), "--target",
        "test-p0-native-finality-mutant", "-j2",
    ]
    if not built(build_command, binary, args.out / "baseline-build.log"):
        raise RuntimeError("baseline mutant target did not compile")

    listed = invoke(
        [str(binary), str(args.owner.resolve()), str(args.committee.resolve()), "--list"],
        args.out / "cases.log",
    )
    cases = listed.stdout.splitlines()
    if listed.returncode != 0 or not cases:
        raise RuntimeError("case inventory failed")
    expected = len(cases)

    baseline = invoke(
        [str(binary), str(args.owner.resolve()), str(args.committee.resolve())],
        args.out / "baseline.log",
    )
    if not passing(baseline, expected):
        raise RuntimeError("baseline suite failed")

    records: list[dict[str, object]] = []
    try:
        for guard, case, kind, old, new in MUTATIONS:
            if original.count(old) != 1:
                raise RuntimeError(f"source anchor is not unique: {guard}")
            changed = original.replace(old, new, 1)
            if changed == original:
                raise RuntimeError(f"mutation did not reach source: {guard}")

            mutant_source.write_text(changed)
            if mutant_source.read_text() != changed:
                raise RuntimeError(f"mutated source write mismatch: {guard}")

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

            compiled = built(
                build_command, binary, args.out / f"{guard}-build.log"
            )
            named = False
            isolated = False
            if compiled:
                target = invoke(
                    [str(binary), str(args.owner.resolve()),
                     str(args.committee.resolve()), case],
                    args.out / f"{guard}-named.log",
                )
                named = named_failure(target, case)

                others = invoke(
                    [str(binary), str(args.owner.resolve()),
                     str(args.committee.resolve()), f"--exclude={case}"],
                    args.out / f"{guard}-others.log",
                )
                isolated = passing(others, expected - 1)

            mutant_source.write_text(original)
            restored_compile = built(
                build_command, binary,
                args.out / f"{guard}-restored-build.log",
            )
            restored = invoke(
                [str(binary), str(args.owner.resolve()),
                 str(args.committee.resolve())],
                args.out / f"{guard}-restored.log",
            )
            restored_ok = restored_compile and passing(restored, expected)

            record = {
                "guard": guard,
                "case": case,
                "kind": kind,
                "edit_reached_source": True,
                "compiled": compiled,
                "named_assertion_failed": named,
                "other_cases_passed": isolated,
                "restored_source_matches": mutant_source.read_text() == original,
                "restored_baseline": restored_ok,
                "production_source_unchanged":
                    hashlib.sha256(SOURCE.read_bytes()).hexdigest() == digest,
            }
            records.append(record)
            (args.out / "mutations.json").write_text(
                json.dumps(records, indent=2) + "\n"
            )
            print(json.dumps(record), flush=True)

            if not (
                compiled and named and isolated
                and record["restored_source_matches"]
                and restored_ok and record["production_source_unchanged"]
            ):
                raise RuntimeError(
                    f"mutation did not establish only its named case: {guard}"
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
