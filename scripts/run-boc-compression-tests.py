#!/usr/bin/env python3
"""Run BOC compression regressions, refusing empty, incomplete or ignored selections."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE_REQUIRED = {
    "Test_BocCompression_DuplicateEdgesUseFullMultiplicity",
    "Test_BocCompression_OnlyExactlyReconstructibleBalanceEncodingIsElided",
}
RUST_REQUIRED = {
    "boc_compression::tests::per_edge_balance::duplicate_edges_use_full_multiplicity",
    "boc_compression::tests::per_edge_balance::noncanonical_balance_encoding_is_not_elided",
    "boc_compression::tests::per_edge_balance::only_the_block_root_merkle_update_is_elided",
    "boc_compression::tests::per_edge_balance::native_noncanonical_child_uses_canonical_deltas",
    "boc_compression::tests::per_edge_balance::mixed_balance_encodings_do_not_change_parent_elision",
}


def run(command: list[str], timeout: int) -> str:
    result = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode:
        raise RuntimeError(f"test command exited {result.returncode}: {command}")
    return result.stdout + "\n" + result.stderr


def require_cases(observed: list[str], required: set[str]) -> set[str]:
    names = set(observed)
    if not names or len(names) != len(observed) or not required <= names:
        raise RuntimeError(
            f"test selection incomplete: observed={len(observed)}, missing={sorted(required - names)}"
        )
    return names


def run_native(binary: Path) -> None:
    output = run([str(binary.resolve()), "--filter", "+BocCompression"], 120)
    observed = re.findall(r"Running test (Test_BocCompression_\w+)\.\.\.", output)
    names = require_cases(observed, NATIVE_REQUIRED)
    passed = re.findall(r"(?m)^(\d+) test\(s\) passed\s*$", output)
    if passed != [str(len(names))]:
        raise RuntimeError(
            f"native compression pass summary does not match {len(names)} executed cases"
        )


def run_rust() -> None:
    command = [
        "cargo",
        "test",
        "--manifest-path",
        str(ROOT / "tosctl/src/Cargo.toml"),
        "--locked",
        "--color",
        "never",
        "-p",
        "chain_block",
        "--lib",
        "boc_compression::tests",
    ]
    listed = run([*command, "--", "--list"], 1800)
    expected = require_cases(re.findall(r"(?m)^(\S+): test$", listed), RUST_REQUIRED)
    # Captured output keeps concurrent tests from splitting the "test ... ok" lines.
    output = run(command, 1800)
    passed = require_cases(re.findall(r"(?m)^test (\S+) \.\.\. ok$", output), expected)
    summaries = re.findall(r"test result: ok\. (\d+) passed; 0 failed; 0 ignored;", output)
    if passed != expected or summaries != [str(len(expected))]:
        raise RuntimeError(
            "Rust compression execution does not match the discovered test inventory"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--native-binary", type=Path)
    mode.add_argument("--rust", action="store_true")
    args = parser.parse_args()
    try:
        if args.rust:
            run_rust()
        else:
            run_native(args.native_binary)
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"BOC_COMPRESSION_TEST_FAILURE: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
