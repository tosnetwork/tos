#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""The canonical text of a result value is bounded: a tuple nested 512 deep is reported, one nested 513 deep
is refused (harness_error), never a crash. Usage: depth_limit.py <target> (a line-protocol vm target)."""

from __future__ import annotations

import base64
import json
import subprocess
import sys


def boc(data: bytes) -> str:
    """A bag of cells holding one ordinary cell with whole bytes of data and no references."""
    cell = bytes([0, 2 * len(data)]) + data
    return base64.b64encode(
        bytes.fromhex("b5ee9c72") + bytes([1, 1, 1, 1, 0, len(cell), 0]) + cell
    ).decode()


def context(depth: int) -> str:
    # NULL; PUSHINT depth; PUSHCONT { 1 TUPLE }; REPEAT -> a null wrapped in `depth` one-element tuples.
    code = bytes([0x6D, 0x81]) + depth.to_bytes(2, "big") + bytes([0x92, 0x6F, 0x01, 0xE4])
    ctx = {
        "code": boc(code),
        "global_version": 16,
        "gas": {"limit": 1000000, "max": 1000000},
        "stack": [],
    }
    return json.dumps(ctx)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    done = subprocess.run(
        [argv[0], "vm"],
        input=context(512) + "\n" + context(513) + "\n",
        capture_output=True,
        text=True,
        timeout=120,
    )
    lines = done.stdout.splitlines()
    if done.returncode != 0 or len(lines) != 2:
        print(
            f"target failed: rc {done.returncode}, {len(lines)} lines, {done.stderr.strip()[-500:]}"
        )
        return 1
    at_limit, past_limit = json.loads(lines[0]), json.loads(lines[1])
    ok = (
        at_limit.get("exit_code") == 0
        and len(at_limit.get("stack", [])) == 1
        and set(past_limit) == {"harness_error"}
    )
    print(f"depth 512: {lines[0][:80]}\ndepth 513: {lines[1][:80]}\n{'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
