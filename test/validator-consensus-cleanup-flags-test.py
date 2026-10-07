#!/usr/bin/env python3
"""Validator consensus-DB cleanup switch, on the real engine binary.

Deleting retired validator consensus databases is on by default: without it a
validator keeps one RocksDB directory per validator-set session forever. The
engine reports the effective setting once it has loaded the global config, so
these cases are decided on a node that has no chain yet:

  - no flag: the engine reports cleanup enabled;
  - --enable-validator-consensus-cleanup: enabled;
  - --disable-validator-consensus-cleanup: disabled, as a warning;
  - both flags: the engine exits with code 2 and names the conflict.

Usage: validator-consensus-cleanup-flags-test.py <validator-engine>
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from importlib import import_module  # noqa: E402

startup = import_module("full-node-master-startup-test")

ENABLED = "validator consensus cleanup: enabled"
DISABLED = "validator consensus cleanup: disabled"
CONFLICT = "are mutually exclusive"
REPORT_TIMEOUT_S = 30.0


def fail(message: str) -> None:
    print(f"VALIDATOR_CONSENSUS_CLEANUP_FLAGS_FAILURE: {message}", file=sys.stderr)
    sys.exit(1)


def expect_report(node, extra: list[str], expected: str, case: str) -> None:
    log_path = os.path.join(node.root, f"{case}.log")
    output = ""
    with open(log_path, "w") as log:
        process = subprocess.Popen(
            node.command(["-v", "3", *extra]), stdout=log, stderr=subprocess.STDOUT
        )
        try:
            deadline = time.monotonic() + REPORT_TIMEOUT_S
            while time.monotonic() < deadline:
                with open(log_path, errors="replace") as f:
                    output = f.read()
                if ENABLED in output or DISABLED in output or process.poll() is not None:
                    break
                time.sleep(0.2)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
    with open(log_path, errors="replace") as f:
        output = f.read()
    reported = [line for line in (ENABLED, DISABLED) if line in output]
    if reported != [expected]:
        fail(f"{case}: expected only '{expected}', saw {reported}: {output[-2000:]}")
    print(
        f"VALIDATOR_CONSENSUS_CLEANUP_FLAGS {case}={'enabled' if expected == ENABLED else 'disabled'}"
    )


def expect_conflict(node, case: str) -> None:
    try:
        result = subprocess.run(
            node.command(
                ["--enable-validator-consensus-cleanup", "--disable-validator-consensus-cleanup"]
            ),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=REPORT_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        fail(f"{case}: the engine did not refuse conflicting flags within {REPORT_TIMEOUT_S} s")
    output = result.stdout + result.stderr
    if result.returncode != 2 or CONFLICT not in output:
        fail(
            f"{case}: expected exit 2 naming the conflict, got {result.returncode}: {output[-2000:]}"
        )
    print(f"VALIDATOR_CONSENSUS_CLEANUP_FLAGS {case}=refused exit=2")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validator-consensus-cleanup-flags-test.py <validator-engine>")
    engine = os.path.abspath(sys.argv[1])
    if not os.access(engine, os.X_OK):
        fail(f"not an executable: {engine}")
    root = tempfile.mkdtemp(prefix="tos-validator-consensus-cleanup-flags-")
    try:
        node = startup.Node(engine, root)
        node.create_config()
        expect_report(node, [], ENABLED, "default")
        expect_report(node, ["--enable-validator-consensus-cleanup"], ENABLED, "explicit_enable")
        expect_report(node, ["--disable-validator-consensus-cleanup"], DISABLED, "disable")
        expect_conflict(node, "both_flags")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
