#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""The canonical text of a result value is bounded in depth and in size, never a crash: a tuple nested 512
deep is reported and one nested 513 deep is refused (harness_error); a shared tuple built by k rounds of
DUP; 2 TUPLE renders 2^(k+1) - 1 values, so k = 19 (1,048,575 values) is reported and k = 20 and k = 30
(2^31 - 1 values of text from a 91-byte program) are refused at the 2^20-value budget.
Usage: depth_limit.py <target> (a line-protocol vm target)."""

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
    return vm_context(code)


def shared(rounds: int) -> str:
    # NULL, then `rounds` times DUP; 2 TUPLE: a value of depth `rounds` whose text has 2^(rounds+1) - 1 values.
    return vm_context(bytes([0x6D]) + bytes([0x20, 0x6F, 0x02]) * rounds)


def vm_context(code: bytes) -> str:
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
    try:
        done = subprocess.run(
            [argv[0], "vm"],
            input="".join(
                c + "\n" for c in (context(512), context(513), shared(19), shared(20), shared(30))
            ),
            capture_output=True,
            text=True,
            timeout=240,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print("target failed: no answer within 240 s (unbounded result text)")
        return 1
    lines = done.stdout.splitlines()
    if done.returncode != 0 or len(lines) != 5:
        print(
            f"target failed: rc {done.returncode}, {len(lines)} lines, {done.stderr.strip()[-500:]}"
        )
        return 1
    answers = [json.loads(line) for line in lines]

    def reported(answer: dict[str, object]) -> bool:
        stack = answer.get("stack")
        return answer.get("exit_code") == 0 and isinstance(stack, list) and len(stack) == 1

    def refused(answer: dict[str, object]) -> bool:
        return set(answer) == {"harness_error"}

    ok = (
        reported(answers[0])
        and refused(answers[1])
        and reported(answers[2])
        and refused(answers[3])
        and refused(answers[4])
    )
    for name, line in zip(("depth 512", "depth 513", "shared 19", "shared 20", "shared 30"), lines):
        print(f"{name}: {line[:80]}")
    print("OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
