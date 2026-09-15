"""Remove one guard of history resolution at a time.

The cache is consulted instead of the archive after this runs, so anything
admitted wrongly here is never looked at again. Each case below has to be the
only one that fails when its own guard is gone.

One guard is deliberately absent from this list. Removing the check for an
absent reader does not make the named case fail; it makes the call abort inside
std::function. The guard is necessary and is not independently observable, so it
is recorded here rather than counted as covered.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-anchor-cache.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-history-resolve")

MUTATIONS = [
    ("declaration-bound", "oversized-declaration-is-refused",
     '  if (coordinates.size() > budget.coordinates)\n    return Error{"anchor-resolve-budget"};',
     ''),
    ("admission-checked", "block-under-another-coordinate-is-refused",
     '    auto admitted = cache.admit(at, anchor.value());\n'
     '    if (!admitted.ok())\n'
     '      return admitted.error();',
     '    cache.admit(at, anchor.value());'),
    ("parse-checked", "unparsable-bytes-are-refused",
     '    auto anchor = native_masterchain_block_anchor(raw.value(), expected_network);\n'
     '    if (!anchor.ok())\n'
     '      return anchor.error();',
     '    auto anchor = native_masterchain_block_anchor(raw.value(), expected_network);\n'
     '    if (!anchor.ok())\n'
     '      continue;'),
    ("miss-is-not-a-refusal", "missing-block-is-reported-not-refused",
     '      resolution.unavailable.push_back(at);\n      continue;',
     '      return raw.error();'),
    ("admitted-counted", "declared-history-becomes-a-source",
     '    ++resolution.admitted;',
     ''),
]


def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-history-resolve", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def run(inputs: Path) -> subprocess.CompletedProcess:
    return subprocess.run([str(BINARY), str(inputs)], capture_output=True, text=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    baseline = run(args.inputs)
    if baseline.returncode != 0:
        print("BASELINE-NOT-PASSING")
        return 1
    cases = [line.split()[1] for line in baseline.stdout.splitlines() if line.startswith("CASE_PASS")]

    records, failures = [], 0
    for guard, case, before, after in MUTATIONS:
        if original.count(before) != 1:
            print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})")
            failures += 1
            continue
        SOURCE.write_text(original.replace(before, after, 1))
        reached = before not in SOURCE.read_text()
        compiled = build()
        named, others = False, False
        if compiled:
            result = run(args.inputs)
            output = result.stdout + result.stderr
            named = result.returncode != 0 and case in output
            # The test stops at its first failure, so what can be checked is
            # that no case ahead of this one failed first. A mutation that kills
            # an earlier case is killing something other than what it names.
            expected = cases[:cases.index(case)]
            others = all(f"CASE_PASS {name}" in output for name in expected)
        SOURCE.write_text(original)
        restored = build() and run(args.inputs).returncode == 0
        record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                  "named_assertion_failed": named, "no_earlier_case_failed": others,
                  "restored_baseline": restored, "source_unchanged": SOURCE.read_text() == original}
        records.append(record)
        print(json.dumps(record))
        if not all(record[k] for k in record if k != "guard" and k != "case"):
            failures += 1

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
