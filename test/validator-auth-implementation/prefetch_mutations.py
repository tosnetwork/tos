"""Remove one guard of the prefetch boundary at a time.

Each mutation must compile, reach the file, and fail its own named case for the
reason it was written for. A failure for a different reason is not a kill.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-prefetch.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-prefetch")

MUTATIONS = [
    ("future-anchor", "same-block-anchor-refused",
     '    if (at >= inclusion)\n      return Error{"owner-finality-coordinate"};',
     ''),
    ("breadth-bound", "unbounded-history-refused",
     '  if (coordinates.size() > 64)\n    return Error{"owner-finality-breadth"};',
     ''),
    ("prefetch-miss", "unfetched-coordinate-refused",
     '  auto found = anchors_.find(at);\n'
     '  if (found == anchors_.end())\n'
     '    return Error{"finalized-anchor-unavailable"};',
     '  auto found = anchors_.find(at);\n'
     '  if (found == anchors_.end())\n'
     '    return Anchor{at, {}, {}, {}};'),
    ("misfiled-entry", "misfiled-anchor-refused",
     '  if (found->second.seqno_ != at)\n    return Error{"finalized-anchor-binding"};',
     ''),
    ("duplicate-collapse", "duplicates-collapse-and-sort",
     '  coordinates.erase(std::unique(coordinates.begin(), coordinates.end()), coordinates.end());',
     ''),
]


def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-prefetch", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def run() -> subprocess.CompletedProcess:
    return subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    if run().returncode != 0:
        print("BASELINE-NOT-PASSING")
        return 1

    records, failures = [], 0
    for guard, case, before, after in MUTATIONS:
        if original.count(before) != 1:
            print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})")
            failures += 1
            continue
        SOURCE.write_text(original.replace(before, after, 1))
        reached = before not in SOURCE.read_text()
        compiled = build()
        named = False
        if compiled:
            result = run()
            named = result.returncode != 0 and case in (result.stderr + result.stdout)
        SOURCE.write_text(original)
        restored = build() and run().returncode == 0
        record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                  "named_assertion_failed": named, "restored_baseline": restored,
                  "source_unchanged": SOURCE.read_text() == original}
        records.append(record)
        print(json.dumps(record))
        if not all(record[k] for k in ("edit_reached_source", "compiled", "named_assertion_failed",
                                       "restored_baseline", "source_unchanged")):
            failures += 1

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
