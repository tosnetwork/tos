#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Controls of the tosctl conformance target (../docs/tosvm.md): the comparison must be able to fail.

    tosvm_controls.py <conformance-target> <vectors dir>

1. The adapter's output with one field corrupted (gas_used of the first vm response plus one) must
   be reported as exactly one mismatch, the other fixtures staying equal.
2. A context the adapter refuses (gas limit plus credit past 63 bits) must be counted as refused,
   never as equal.
"""

from __future__ import annotations

import json
import shlex
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance as c  # noqa: E402

CORRUPTING_WRAPPER = r"""
import json, subprocess, sys
target = sys.argv[1]
args = sys.argv[2:]
stdin = "" if args == ["--info"] else sys.stdin.read()
done = subprocess.run([target, *args], input=stdin, capture_output=True, text=True)
lines = done.stdout.splitlines()
if args == ["vm"] and lines:
    first = json.loads(lines[0])
    first["gas_used"] += 1
    lines[0] = json.dumps(first)
sys.stdout.write("".join(line + "\n" for line in lines))
sys.stderr.write(done.stderr)
sys.exit(done.returncode)
"""


def corrupted_field(target: str, vectors: Path, work: Path) -> list[str]:
    wrapper = work / "corrupting-target"
    wrapper.write_text(
        "#!/bin/sh\nexec "
        + " ".join(shlex.quote(part) for part in (sys.executable, str(work / "wrapper.py"), target))
        + ' "$@"\n'
    )
    (work / "wrapper.py").write_text(CORRUPTING_WRAPPER)
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    tally = c.command_run(str(wrapper), [vectors / "vm"])
    print(f"corrupted gas_used: {tally.line()}")
    failures: list[str] = []
    if tally.ok() or tally.mismatched != 1 or tally.equal != tally.compared - 1:
        failures.append("a corrupted field was not reported as exactly one mismatch")
    if not any("gas_used" in line for line in tally.details):
        failures.append("the mismatch does not name gas_used")
    return failures


def refused_context(target: str, vectors: Path, work: Path) -> list[str]:
    source = next(iter(sorted((vectors / "vm" / "fixtures").glob("*.jsonl"))))
    fixture = json.loads(source.read_text().splitlines()[0])
    fixture["metadata"]["family"] = "tosvm-refusal"
    fixture["metadata"]["fixture_id"] = "gas-sum-overflow"
    limit = (1 << 63) - 1
    fixture["context"]["gas"] = {"limit": limit, "max": limit, "credit": 1}
    family = work / "vectors" / "vm" / "fixtures" / "tosvm-refusal.jsonl"
    family.parent.mkdir(parents=True)
    family.write_text(json.dumps(fixture) + "\n")
    tally = c.command_run(target, [work / "vectors"])
    print(f"refused context: {tally.line()}")
    if tally.ok() or tally.refused != 1 or tally.equal != 0:
        return ["a refused context was not counted as refused"]
    return []


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    target, vectors = str(Path(argv[0]).resolve()), Path(argv[1])
    with tempfile.TemporaryDirectory(prefix="conformance-tosvm-") as directory:
        work = Path(directory)
        failures = corrupted_field(target, vectors, work) + refused_context(target, vectors, work)
    for failure in failures:
        print(f"CONTROL FAILED: {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
