#!/usr/bin/env python3
"""Run the complete CTest registry with a small audited parallel unit-test phase."""

import argparse
import json
import subprocess
from pathlib import Path

# These programs have no source mutations or network listeners. DB and tdutils
# use distinct file names, and regression caches are already per executable.
PARALLEL_UNITS = ("test-db", "test-tdutils", "test-bigint", "test-vm", "test-cells")


def registry(build):
    result = subprocess.run(
        ["ctest", "--test-dir", str(build), "--show-only=json-v1"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)["tests"]


def plan(tests):
    names = [test["name"] for test in tests]
    if not names or len(names) != len(set(names)):
        raise ValueError("CTest registry must be nonempty and unique")
    if not set(PARALLEL_UNITS) <= set(names):
        raise ValueError("Audited native unit tests missing from full registry")
    for test in tests:
        if test["name"] in PARALLEL_UNITS:
            properties = {p["name"]: p["value"] for p in test.get("properties", [])}
            if any(
                properties.get(p)
                for p in ["DEPENDS", "FIXTURES_REQUIRED", "FIXTURES_SETUP", "FIXTURES_CLEANUP"]
            ):
                raise ValueError("Parallel unit acquired an unaudited fixture dependency")
    parallel = [name for name in names if name in PARALLEL_UNITS]
    serial = [name for name in names if name not in PARALLEL_UNITS]
    if not serial or set(parallel) & set(serial) or set(parallel + serial) != set(names):
        raise ValueError("CTest plan must retain every registered test exactly once")
    return parallel, serial


def run(build):
    tests = registry(build)
    parallel, serial = plan(tests)
    pattern = "^(" + "|".join(PARALLEL_UNITS) + ")$"
    common = [
        "ctest",
        "--test-dir",
        str(build),
        "--output-on-failure",
        "--timeout",
        "1800",
        "--no-tests=error",
    ]
    print(
        f"CTEST_COMPLETE_PLAN: {len(parallel)} audited units at -j2; {len(serial)} tests at -j1",
        flush=True,
    )
    codes = []
    # Do not stop after a test failure: the original complete run collected the
    # remaining results as well. Any failed phase still fails the overall job.
    for arguments in [["-j2", "-R", pattern], ["-j1", "-E", pattern]]:
        codes.append(subprocess.run(common + arguments).returncode)
    if registry(build) != tests:
        raise ValueError("CTest registry changed during execution")
    return 1 if any(codes) else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.build_dir.resolve()))


if __name__ == "__main__":
    main()
