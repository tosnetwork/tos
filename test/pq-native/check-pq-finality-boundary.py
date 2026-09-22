#!/usr/bin/env python3
"""Keep the carried-session PQ verifier out of production proof consumers."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NEEDLE = "check_pq_signatures_under_carried_session_for_test"
PRODUCTION = [ROOT / "validator", ROOT / "crypto" / "block"]
DEFINITION_FILES = {"signature-set.cpp", "signature-set.h"}


def main() -> int:
    offenders = []
    scanned = 0
    for entry in PRODUCTION:
        paths = entry.rglob("*") if entry.is_dir() else [entry]
        for path in paths:
            if path.is_dir() or path.suffix not in (".cpp", ".h", ".hpp"):
                continue
            if path.name in DEFINITION_FILES:
                continue
            scanned += 1
            for line_no, line in enumerate(path.read_text().splitlines(), start=1):
                if NEEDLE in line:
                    offenders.append(f"{path.relative_to(ROOT)}:{line_no}: {line.strip()}")
    if scanned == 0:
        sys.exit("PQ_FINALITY_BOUNDARY_SCANNED_NO_PRODUCTION_SOURCES")
    if offenders:
        print("PQ_FINALITY_CARRIED_SESSION_HELPER_REACHED_PRODUCTION", file=sys.stderr)
        for offender in offenders:
            print(offender, file=sys.stderr)
        return 1
    print(f"PQ_FINALITY_BOUNDARY_SOURCE_OK scanned={scanned}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
