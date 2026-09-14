#!/usr/bin/env python3
"""Compile signer-provisioning mutants and require isolated named failures."""
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
SOURCE = ROOT / "validator/auth/node-provisioning.cpp"

MUTATIONS = [
    (
        "provider-missing",
        "provider_missing_active_refused",
        "guard-disable",
        '    if (!seen.contains(wanted.key_id_))\n'
        '      return Error{"provider-inventory-missing"};',
        '    if (false && !seen.contains(wanted.key_id_))\n'
        '      return Error{"provider-inventory-missing"};',
    ),
    (
        "provider-extra",
        "provider_extra_handle_refused",
        "guard-disable",
        '    if (!seen.insert(reference.value().key_id_).second)\n'
        '      return Error{"provider-inventory-extra"};',
        '    seen.insert(reference.value().key_id_);',
    ),
    (
        "provider-descriptor",
        "provider_descriptor_binding",
        "guard-disable",
        '    if (resolved.value() != local.descriptor)\n'
        '      return Error{"provider-inventory-descriptor"};',
        '    if (false && resolved.value() != local.descriptor)\n'
        '      return Error{"provider-inventory-descriptor"};',
    ),
    (
        "provider-route",
        "provider_routing_reconciled_only",
        "semantic-fault",
        '  return Error{"provider-route-unreconciled"};',
        '  return routes_.front().handle;',
    ),
    (
        "local-trust-required",
        "local_trust_required",
        "guard-disable",
        '  if (records.value().empty())\n'
        '    return Error{"service-trust-unavailable"};',
        '  if (false && records.value().empty())\n'
        '    return Error{"service-trust-unavailable"};',
    ),
    (
        "trust-rotation-history",
        "local_trust_rotation_history",
        "semantic-fault",
        '  auto selected = records.value();',
        '  auto selected = records.value();\n'
        '  if (selected.size() > 1)\n'
        '    selected.pop_back();',
    ),
    (
        "permit-missing",
        "permit_missing_refused",
        "guard-disable",
        '  if (!permit.ok())\n'
        '    return permit.error();',
        '  if (!permit.ok())\n'
        '    return VerifiedNodePermit(Permit{}, expectation);',
    ),
    (
        "permit-signature",
        "permit_signature_refused",
        "guard-disable",
        '  if (!trusted.ok())\n'
        '    return trusted.error();',
        '  if (!trusted.ok())\n'
        '    return VerifiedNodePermit(std::move(permit.value()), expectation);',
    ),
    (
        "permit-context",
        "permit_context_refused",
        "guard-disable",
        '  if (permit.value().body_ != expectation.body)\n'
        '    return Error{"permit-context"};',
        '  if (false && permit.value().body_ != expectation.body)\n'
        '    return Error{"permit-context"};',
    ),
    (
        "permit-expiry",
        "expired_permit_not_renewed",
        "semantic-fault",
        '      expectation.current_coordinate,\n'
        '      expectation.fence,',
        '      permit.value().body_.anchor_.seqno_,\n'
        '      expectation.fence,',
    ),
]


def invoke(
    command: list[str], log: Path, timeout: int = 900
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    log.write_text(
        "$ "
        + " ".join(command)
        + f"\nexit_code={result.returncode}\n"
        + "--- stdout ---\n"
        + result.stdout
        + "--- stderr ---\n"
        + result.stderr
    )
    return result


def built(
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
    lines = result.stdout.splitlines()
    return (
        result.returncode == 0
        and result.stderr == ""
        and lines[-1:]
        == [f"SUMMARY cases={expected} passed={expected}"]
        and sum(line.startswith("CASE_PASS ") for line in lines)
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
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    build = args.build.resolve()
    folder = build / "test/validator-auth-implementation"
    mutant_source = folder / "mutated-node-provisioning.cpp"
    binary = folder / "test-p0-node-provisioning-mutant"
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    production_digest = hashlib.sha256(
        SOURCE.read_bytes()
    ).hexdigest()
    mutant_source.write_text(original)

    build_command = [
        "cmake",
        "--build",
        str(build),
        "--target",
        "test-p0-node-provisioning-mutant",
        "-j2",
    ]

    if not built(
        build_command, binary, args.out / "baseline-build.log"
    ):
        raise RuntimeError(
            "baseline mutant target did not compile"
        )

    listed = invoke(
        [str(binary), "--list"],
        args.out / "cases.log",
    )
    case_names = listed.stdout.splitlines()
    if listed.returncode != 0 or not case_names:
        raise RuntimeError("case inventory failed")
    expected = len(case_names)

    baseline = invoke(
        [str(binary)],
        args.out / "baseline.log",
    )
    if not passing(baseline, expected):
        raise RuntimeError("baseline suite failed")

    records: list[dict[str, object]] = []
    try:
        for guard, case, kind, old, new in MUTATIONS:
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

            compiled = built(
                build_command,
                binary,
                args.out / f"{guard}-build.log",
            )

            named = False
            isolated = False
            if compiled:
                target = invoke(
                    [str(binary), case],
                    args.out / f"{guard}-named.log",
                )
                named = named_failure(target, case)

                others = invoke(
                    [str(binary), f"--exclude={case}"],
                    args.out / f"{guard}-others.log",
                )
                isolated = passing(others, expected - 1)

            mutant_source.write_text(original)
            restored_compile = built(
                build_command,
                binary,
                args.out / f"{guard}-restored-build.log",
            )
            restored = invoke(
                [str(binary)],
                args.out / f"{guard}-restored.log",
            )
            restored_ok = (
                restored_compile
                and passing(restored, expected)
            )

            record = {
                "guard": guard,
                "case": case,
                "kind": kind,
                "edit_reached_source": True,
                "compiled": compiled,
                "named_assertion_failed": named,
                "other_cases_passed": isolated,
                "restored_source_matches":
                    mutant_source.read_text() == original,
                "restored_baseline": restored_ok,
                "production_source_unchanged":
                    hashlib.sha256(
                        SOURCE.read_bytes()
                    ).hexdigest()
                    == production_digest,
            }
            records.append(record)
            (args.out / "mutations.json").write_text(
                json.dumps(records, indent=2) + "\n"
            )
            print(json.dumps(record), flush=True)

            if not (
                compiled
                and named
                and isolated
                and record["restored_source_matches"]
                and restored_ok
                and record["production_source_unchanged"]
            ):
                raise RuntimeError(
                    "mutation did not establish only its "
                    f"named case: {guard}"
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
