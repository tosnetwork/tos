"""Require the admission path to open an arriving container once.

Recognition opens the evidence container under the admission allowance, and
what follows it -- owner authentication, then the transaction assembler -- is
handed the value it produced. Opening the root a second time establishes no
boundary recognition has not already established: the cell is immutable and the
parse is a function of it, so the second answer can only agree with the first.
What it does do is repeat an expansion whose size the sender chose, which is the
thing the allowance exists to bound.

So the count is held here. A guard against work that is merely redundant does
not fail any test when it is removed -- everything still passes, twice as
slowly -- which is exactly the kind of property that regresses quietly.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADMISSION = ROOT / "validator/auth/native-registry-admission.cpp"
OPEN = re.compile(r"NativeEvidence::open\s*\(")


def main() -> int:
    source = ADMISSION.read_text()
    openings = OPEN.findall(source)
    if len(openings) != 1:
        print(
            f"FAIL: the admission path opens an arriving container {len(openings)} times; "
            "recognition's opening is the only one that establishes anything",
            file=sys.stderr,
        )
        return 1
    if "admission_evidence_budget()" not in source:
        print("FAIL: the opening is not made under the admission allowance", file=sys.stderr)
        return 1
    print("PASS: one opening, under the admission allowance")
    return 0


if __name__ == "__main__":
    sys.exit(main())
