#!/usr/bin/env python3
"""Compile public-RPC mutants and require isolated named failures."""
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

SOURCES = {
    "public": ROOT / "validator/auth/public-rpc.cpp",
    "common": ROOT / "validator/auth/client-api-common.h",
    "transfer": ROOT / "validator/auth/transfer.cpp",
    "store": ROOT / "validator/auth/object-store.cpp",
}


def mutations() -> list[tuple[str, str, str, str, str, str]]:
    return [
        (
            "transport-principal",
            "transport_principal_only",
            "public",
            "guard-disable",
            "        return handler(principal_, request);",
            "        return handler(Hash{}, request);",
        ),
        (
            "client-surface",
            "client_only_methods",
            "public",
            "guard-disable",
            "  if (!public_client_method(route->method))\n"
            "    return api_failure_response(route->method, frame.request_id, 2, 4);",
            "  if (false && !public_client_method(route->method))\n"
            "    return api_failure_response(route->method, frame.request_id, 2, 4);",
        ),
        (
            "operation-reader-budget",
            "reader_operation_budget",
            "transfer",
            "semantic-fault",
            "  remaining_ -= size;",
            "  remaining_ -= 0;",
        ),
        (
            "source-error-class",
            "source_outage_provenance",
            "common",
            "semantic-fault",
            '      e == "global-storage-quota" || '
            'e == "storage-clock-regression" ||',
            '      e == "global-storage-quota" || false ||',
        ),
        (
            "quota-error-class",
            "quota_classification_and_expiry",
            "common",
            "semantic-fault",
            '      e == "witness-unavailable" || '
            'e == "principal-storage-quota" ||',
            '      e == "witness-unavailable" || false ||',
        ),
        (
            "expiry-reclamation",
            "quota_classification_and_expiry",
            "store",
            "guard-disable",
            "    if (it->second.expires > now) {",
            "    if (true) {",
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
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--committee", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    build = args.build.resolve()
    folder = build / "test/validator-auth-implementation"
    mutant_root = folder / "public-rpc-mutant-root"
    copies = {
        "public": folder / "mutated-public-rpc.cpp",
        "common":
            mutant_root / "validator/auth/client-api-common.h",
        "transfer": folder / "mutated-public-rpc-transfer.cpp",
        "store": folder / "mutated-public-rpc-object-store.cpp",
    }
    binary = folder / "test-p0-public-rpc-mutant"

    args.out.mkdir(parents=True, exist_ok=True)
    mutant_root.joinpath("validator/auth").mkdir(
        parents=True, exist_ok=True
    )

    originals = {
        key: source.read_text()
        for key, source in SOURCES.items()
    }
    source_digests = {
        key: hashlib.sha256(source.read_bytes()).hexdigest()
        for key, source in SOURCES.items()
    }

    for key, copy in copies.items():
        copy.write_text(originals[key])

    build_command = [
        "cmake",
        "--build",
        str(build),
        "--target",
        "test-p0-public-rpc-mutant",
        "-j2",
    ]

    if not compiled(
        build_command, binary, args.out / "baseline-build.log"
    ):
        raise RuntimeError(
            "baseline mutant target did not compile"
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
        raise RuntimeError("baseline suite failed")

    records: list[dict[str, object]] = []

    for guard, case, source_key, kind, old, new in mutations():
        original = originals[source_key]
        if original.count(old) != 1:
            raise RuntimeError(
                f"source anchor is not unique: {guard}"
            )

        changed = original.replace(old, new, 1)
        if changed == original:
            raise RuntimeError(
                f"mutation did not reach source: {guard}"
            )

        # Restore every copy first so each mutation changes one source only.
        for key, copy in copies.items():
            copy.write_text(originals[key])

        copies[source_key].write_text(changed)
        if copies[source_key].read_text() != changed:
            raise RuntimeError(
                f"mutated source write mismatch: {guard}"
            )

        (args.out / f"{guard}.diff").write_text(
            "".join(
                difflib.unified_diff(
                    original.splitlines(True),
                    changed.splitlines(True),
                    fromfile=str(SOURCES[source_key]),
                    tofile=str(copies[source_key]),
                )
            )
        )

        did_compile = compiled(
            build_command,
            binary,
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

        for key, copy in copies.items():
            copy.write_text(originals[key])

        restored_compile = compiled(
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
        restored_ok = (
            restored_compile and passing(restored, expected)
        )

        sources_unchanged = all(
            hashlib.sha256(source.read_bytes()).hexdigest()
            == source_digests[key]
            for key, source in SOURCES.items()
        )
        copies_restored = all(
            copies[key].read_text() == originals[key]
            for key in copies
        )

        record = {
            "guard": guard,
            "case": case,
            "source": source_key,
            "kind": kind,
            "edit_reached_source": True,
            "compiled": did_compile,
            "named_assertion_failed": named,
            "other_cases_passed": isolated,
            "restored_copies_match": copies_restored,
            "restored_baseline": restored_ok,
            "production_sources_unchanged": sources_unchanged,
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
            and copies_restored
            and restored_ok
            and sources_unchanged
        ):
            raise RuntimeError(
                "mutation did not establish only its "
                f"named case: {guard}"
            )

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_FAILURE {error}", file=sys.stderr)
        sys.exit(2)
