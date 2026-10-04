#!/usr/bin/env python3
"""Check that validator-engine refuses an unsafe JSON-RPC listener at startup.

A write-enabled plaintext JSON-RPC listener may bind loopback only. The engine
must exit with status 2 before it starts any actor when asked to bind such a
listener elsewhere, and must not refuse the safe configurations.

The safe cases cannot be allowed to start a node, so each one also passes
--measurement-jsonl without --measurement-node-id. That is rejected by the
next startup check, which runs only after the listener check has passed: its
message proves the listener check was reached and let the configuration
through.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

REFUSAL = "refusing to bind write-enabled plaintext listener to non-loopback address"
NEXT_CHECK = "--measurement-jsonl and --measurement-node-id must be supplied together"
TIMEOUT_SECONDS = 60

UNSAFE = (
    ("ipv4-any-write", ["--json-rpc-address", "0.0.0.0:1"]),
    ("ipv4-private-write", ["--json-rpc-address", "10.0.0.5:1"]),
    ("ipv6-any-write", ["--json-rpc-address", "[::]:1"]),
    # The last --json-rpc-address is the one the engine serves.
    ("last-address-wins", ["--json-rpc-address", "127.0.0.1:1", "--json-rpc-address", "0.0.0.0:1"]),
)

SAFE = (
    ("ipv4-loopback-write", ["--json-rpc-address", "127.0.0.1:1"]),
    ("ipv6-loopback-write", ["--json-rpc-address", "[::1]:1"]),
    ("ipv4-any-readonly", ["--json-rpc-address", "0.0.0.0:1", "--json-rpc-readonly"]),
    ("readonly-before-address", ["--json-rpc-readonly", "--json-rpc-address", "0.0.0.0:1"]),
)


def run(binary: Path, args: list[str], workdir: Path) -> tuple[int, str]:
    completed = subprocess.run(
        [str(binary), *args],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )
    return completed.returncode, completed.stdout + completed.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    if not args.binary.is_file():
        print(f"JSON_RPC_STARTUP_REFUSAL_FAILURE: missing binary {args.binary}", file=sys.stderr)
        return 1

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="json-rpc-startup-") as tmp:
        workdir = Path(tmp)
        for name, case_args in UNSAFE:
            code, output = run(args.binary, case_args, workdir)
            if code != 2 or REFUSAL not in output:
                failures.append(
                    f"{name}: expected exit 2 with the listener refusal, got exit {code}"
                )
            elif NEXT_CHECK in output:
                failures.append(f"{name}: the refusal did not stop startup")
        sink = str(workdir / "measurement.jsonl")
        for name, case_args in SAFE:
            code, output = run(args.binary, [*case_args, "--measurement-jsonl", sink], workdir)
            if REFUSAL in output:
                failures.append(f"{name}: a safe listener configuration was refused")
            elif code != 2 or NEXT_CHECK not in output:
                failures.append(
                    f"{name}: startup did not reach the check after the listener check (exit {code})"
                )

    if failures:
        for failure in failures:
            print(f"JSON_RPC_STARTUP_REFUSAL_FAILURE: {failure}", file=sys.stderr)
        return 1
    print(f"json-rpc startup refusal: {len(UNSAFE)} unsafe refused, {len(SAFE)} safe admitted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
