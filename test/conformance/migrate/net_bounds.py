#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Out-of-bound net contexts are refused (harness_error), never a crash: a zero symbol size for every FEC
code; an overlay broadcast at a time before 1970; overlay broadcasts among more than two members whose send would leave the two-step path (a simple
send, a FEC send with the no-two-step flag) or that also receive a message, since those paths pick
neighbours at random; then one valid context that must still be answered by the same process.
Usage: net_bounds.py <target> (a line-protocol net target)."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

ALGORITHMS = ("raptorq", "online", "round_robin")
FIXTURES = Path(__file__).resolve().parent.parent / "vectors" / "net" / "fixtures"
NO_TWOSTEP = 256


def frozen_context(family: str, fixture_id: str) -> dict[str, Any]:
    for line in (FIXTURES / f"{family}.jsonl").read_text().splitlines():
        fixture = cast(dict[str, Any], json.loads(line))
        if fixture["metadata"]["fixture_id"] == fixture_id:
            return cast(dict[str, Any], fixture["context"])
    raise SystemExit(f"{family}/{fixture_id}: no such fixture")


def multi_member_contexts() -> list[dict[str, object]]:
    """Variants of a six-member two-step FEC send (600 bytes, within every size bound) that leave it."""
    base = frozen_context("overlay-broadcast", "twostep/fec-6")
    inbound = frozen_context("overlay-broadcast-inbound", "simple/replay")["inbound"]
    simple = copy.deepcopy(base)
    simple["broadcast"]["fec"] = False
    old_fec = copy.deepcopy(base)
    old_fec["broadcast"]["flags"] = old_fec["broadcast"]["flags"] | NO_TWOSTEP
    receiving = copy.deepcopy(base)
    receiving["inbound"] = copy.deepcopy(inbound)
    late = copy.deepcopy(base)
    late["now"] = -5
    return [simple, old_fec, receiving, late]


def refused_contexts() -> list[dict[str, object]]:
    contexts: list[dict[str, object]] = []
    for algorithm in ALGORITHMS:
        contexts.append(
            {
                "op": "fec_encode",
                "algorithm": algorithm,
                "data": "00",
                "symbol_size": 0,
                "symbol_ids": [0],
            }
        )
        contexts.append(
            {
                "op": "fec_decode",
                "algorithm": algorithm,
                "data_size": 1,
                "symbol_size": 0,
                "symbols_count": 1,
                "symbols": [],
            }
        )
    contexts.extend(multi_member_contexts())
    return contexts


def valid_context() -> dict[str, object]:
    return {
        "op": "fec_encode",
        "algorithm": "raptorq",
        "data": "00",
        "symbol_size": 1,
        "symbol_ids": [0],
    }


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    contexts = [*refused_contexts(), valid_context()]
    done = subprocess.run(
        [argv[0], "net"],
        input="".join(json.dumps(c) + "\n" for c in contexts),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    lines = done.stdout.splitlines()
    if done.returncode != 0 or len(lines) != len(contexts):
        print(
            f"target exited {done.returncode} after {len(lines)} of {len(contexts)} answers: "
            f"{done.stderr.strip()[-500:]}",
            file=sys.stderr,
        )
        return 1
    failures = 0
    for ctx, line in zip(contexts[:-1], lines[:-1]):
        answer = json.loads(line)
        if "harness_error" not in answer:
            print(f"not refused: {json.dumps(ctx)[:200]} -> {line[:200]}", file=sys.stderr)
            failures += 1
    last = json.loads(lines[-1])
    if "harness_error" in last or last.get("outcome") != "encoded":
        print(f"valid context after the refusals not answered: {lines[-1]}", file=sys.stderr)
        failures += 1
    print(
        f"{len(contexts) - 1} out-of-bound contexts refused, valid context answered; {failures} failures"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
