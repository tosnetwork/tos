#!/usr/bin/env python3
"""Compile Rust scoped-object-store mutants and require isolated named failures."""
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
SOURCE = ROOT / "tosctl/src/validator-auth/src/transfer.rs"
CHECK = ROOT / "test/validator-auth-implementation/check_object_store.py"
MANIFEST = ROOT / "tosctl/src/Cargo.toml"
RUST = ROOT / "tosctl/src/target/debug/conformance"

MUTATIONS = [
    (
        "principal-object-quota",
        "principal-object-quota",
        "guard-disable",
        "        if usage.objects >= PRINCIPAL_OBJECT_LIMIT {\n"
        "            return Err(Error(\"principal-storage-quota\"));\n"
        "        }",
        "        if false {\n"
        "            return Err(Error(\"principal-storage-quota\"));\n"
        "        }",
    ),
    (
        "principal-byte-quota",
        "principal-byte-quota",
        "guard-disable",
        "        let principal_bytes_exhausted =\n"
        "            usage.bytes > PRINCIPAL_BYTE_LIMIT || length > principal_remaining;",
        "        let principal_bytes_exhausted = false;",
    ),
    (
        "global-byte-quota",
        "global-byte-quota",
        "guard-disable",
        "        let global_bytes_exhausted = self.used > self.limit || length > global_remaining;",
        "        let global_bytes_exhausted = false;",
    ),
    (
        "principal-table-bound",
        "principal-table-bound",
        "guard-disable",
        "        let principal_table_exhausted =\n"
        "            current.is_none() && self.principals.len() >= PRINCIPAL_TABLE_LIMIT;",
        "        let principal_table_exhausted = false;",
    ),
    (
        "expiry-bytes",
        "expiry-releases-all",
        "semantic-fault",
        "            let next_used = self.used.checked_sub(length).ok_or(Error(\"storage-accounting\"))?;",
        "            let next_used = self.used;",
    ),
    (
        "expiry-object-slot",
        "expiry-releases-all",
        "semantic-fault",
        "            let next_objects = "
        "usage.objects.checked_sub(1).ok_or(Error(\"storage-accounting\"))?;",
        "            let next_objects = usage.objects;",
    ),
    (
        "expiry-principal-table",
        "expiry-releases-all",
        "guard-disable",
        "            if next_objects == 0 {",
        "            if false {",
    ),
]


def invoke(command: list[str], log: Path, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, check=False
    )
    log.write_text(
        "$ " + " ".join(command)
        + f"\nexit_code={result.returncode}\n--- stdout ---\n"
        + result.stdout
        + "--- stderr ---\n"
        + result.stderr
    )
    return result


def build(log: Path) -> bool:
    result = invoke(
        [
            "cargo",
            "build",
            "--locked",
            "--manifest-path",
            str(MANIFEST),
            "-p",
            "tos-validator-auth",
            "--bin",
            "conformance",
        ],
        log,
    )
    return (
        result.returncode == 0
        and RUST.is_file()
        and RUST.stat().st_size > 0
        and os.access(RUST, os.X_OK)
    )


def check(cpp: Path, out: Path, case: str | None = None, exclude: str | None = None):
    command = [
        sys.executable,
        str(CHECK),
        "--cpp",
        str(cpp),
        "--rust",
        str(RUST),
    ]
    if case:
        command.extend(["--case", case])
    if exclude:
        command.extend(["--exclude", exclude])
    return invoke(command, out, timeout=600)


def named_failure(result: subprocess.CompletedProcess[str], case: str) -> bool:
    return (
        result.returncode == 1
        and result.stderr.splitlines() == [f"ASSERTION_FAILED {case}"]
        and result.stdout.splitlines() == [f"SETUP_OK {case}"]
    )


def passing(result: subprocess.CompletedProcess[str]) -> bool:
    return (
        result.returncode == 0
        and result.stderr == ""
        and result.stdout.splitlines()[-1:] == ["SUMMARY cases=9 passed=9"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpp", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    original_digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    if not build(args.out / "baseline-build.log"):
        raise RuntimeError("baseline Rust binary did not compile")
    baseline = check(args.cpp.resolve(), args.out / "baseline.log")
    if not passing(baseline):
        raise RuntimeError("baseline differential did not pass")

    records: list[dict[str, object]] = []
    try:
        for guard, case, kind, old, new in MUTATIONS:
            if original.count(old) != 1:
                raise RuntimeError(f"source anchor is not unique: {guard}")
            changed = original.replace(old, new, 1)
            if changed == original:
                raise RuntimeError(f"mutation did not reach source: {guard}")
            SOURCE.write_text(changed)
            if SOURCE.read_text() != changed:
                raise RuntimeError(f"mutated source write mismatch: {guard}")

            (args.out / f"{guard}.diff").write_text(
                "".join(
                    difflib.unified_diff(
                        original.splitlines(True),
                        changed.splitlines(True),
                        fromfile=str(SOURCE),
                        tofile=f"{SOURCE}.mutant",
                    )
                )
            )

            compiled = build(args.out / f"{guard}-build.log")
            named = False
            isolated = False
            if compiled:
                target = check(
                    args.cpp.resolve(),
                    args.out / f"{guard}-named.log",
                    case=case,
                )
                named = named_failure(target, case)
                others = check(
                    args.cpp.resolve(),
                    args.out / f"{guard}-others.log",
                    exclude=case,
                )
                isolated = (
                    others.returncode == 0
                    and others.stderr == ""
                    and others.stdout.splitlines()[-1:]
                    == ["SUMMARY cases=8 passed=8"]
                )

            SOURCE.write_text(original)
            restored_compiled = build(args.out / f"{guard}-restored-build.log")
            restored = check(
                args.cpp.resolve(),
                args.out / f"{guard}-restored.log",
            )
            restored_ok = restored_compiled and passing(restored)
            record = {
                "guard": guard,
                "case": case,
                "kind": kind,
                "edit_reached_source": True,
                "compiled": compiled,
                "named_assertion_failed": named,
                "other_cases_passed": isolated,
                "restored_source_matches": SOURCE.read_text() == original,
                "restored_baseline": restored_ok,
                "source_unchanged": hashlib.sha256(SOURCE.read_bytes()).hexdigest()
                == original_digest,
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
                and restored_ok
                and record["restored_source_matches"]
                and record["source_unchanged"]
            ):
                raise RuntimeError(
                    f"mutation did not establish only its named case: {guard}"
                )
    finally:
        SOURCE.write_text(original)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_FAILURE {error}", file=sys.stderr)
        sys.exit(2)
