#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Oversize validate contexts are refused by their encoded length (harness_error naming the bound),
never decoded or run; a context at a bound is still run; then a frozen context must still be answered
with its frozen effect by the same process.
Usage: validate_bounds.py <target> <vectors dir> (a line-protocol validate target)."""

from __future__ import annotations

import base64
import importlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "runner"))
c: Any = importlib.import_module("conformance")

Json = dict[str, Any]
MIB = 1 << 20
# The bounds of ref/harness-validate.cpp, in decoded bytes.
BLOCK_BYTES = 4 * MIB
COLLATED_BYTES = 4 * MIB
STATE_BYTES = 4 * MIB
STATES_BYTES = 8 * MIB
# A frozen context that the oversize ones are derived from, and that must be answered afterwards.
FAMILY = "rel02-negative"
FIXTURE = "mc-117752:candidate_file_hash"


def b64(size: int) -> str:
    return base64.b64encode(bytes(size)).decode()


def frozen(vectors: Path) -> tuple[Json, Json]:
    fam = c.load_family(vectors / "validate" / "fixtures" / f"{FAMILY}.jsonl")
    for fixture, ctx in zip(fam.fixtures, fam.contexts(), strict=True):
        if fixture["metadata"]["fixture_id"] == FIXTURE:
            return cast(Json, ctx), cast(Json, fixture["effects"])
    raise SystemExit(f"{FAMILY}/{FIXTURE} not found")


def cases(base: Json) -> list[tuple[str, Json, str | None]]:
    """(name, context, the bound its refusal must name, or None when the context must run)."""

    def changed(**fields: Any) -> Json:
        return {**base, **fields}

    state = base["states"][0]
    return [
        ("block one byte over", changed(block=b64(BLOCK_BYTES + 1)), "block: larger than"),
        (
            "collated data one byte over",
            changed(collated_data=b64(COLLATED_BYTES + 1)),
            "collated_data: larger than",
        ),
        (
            "one state one byte over",
            changed(states=[{**state, "state": b64(STATE_BYTES + 1)}]),
            "states[0].state: larger than",
        ),
        (
            "states over in total",
            changed(states=[{**state, "state": b64(3 * MIB)} for _ in range(3)]),
            f"states: larger than {STATES_BYTES} bytes in total",
        ),
        # At the bound the block is decoded and validated: its file hash is not the candidate's.
        ("block at the bound", changed(block=b64(BLOCK_BYTES)), None),
    ]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    base, base_effects = frozen(Path(argv[1]))
    checks = cases(base)
    contexts = [ctx for _, ctx, _ in checks] + [base]
    done = subprocess.run(
        [argv[0], "validate"],
        input="".join(json.dumps(ctx, separators=(",", ":")) + "\n" for ctx in contexts),
        capture_output=True,
        text=True,
        timeout=600,
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
    for (name, _, bound), line in zip(checks, lines, strict=False):
        answer = cast(Json, json.loads(line))
        error = answer.get("harness_error")
        if bound is None:
            if error is not None or answer.get("reason") != "candidate_id_mismatch":
                print(f"{name}: not run: {line[:300]}", file=sys.stderr)
                failures += 1
        elif not isinstance(error, str) or bound not in error:
            print(f"{name}: not refused by its bound ({bound!r}): {line[:300]}", file=sys.stderr)
            failures += 1
    last = cast(Json, json.loads(lines[-1]))
    if last != base_effects:
        print(f"frozen context after the refusals: {lines[-1]} != {base_effects}", file=sys.stderr)
        failures += 1
    print(
        f"{len(checks) - 1} oversize contexts refused, one at the bound run, frozen context answered; "
        f"{failures} failures"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
