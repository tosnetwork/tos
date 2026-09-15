"""Remove the attestation requirement and require the named case to fail.

The guard exists because policy_at() selects by coordinate alone: without it a
policy governs from its boundary onward and nothing records that the change
happened. That is invisible in every other test, which is why this one exists.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/state.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-activation")

MUTATIONS = [
    ("attestation-required", "an-unattested-policy-is-refused",
     '  for (const auto& [at, p] : policies_) {\n'
     '    (void)at;\n'
     '    if (p.effective_from_ == 0)\n'
     '      continue;\n'
     '    if (!activations_.contains(p.effective_from_))\n'
     '      return Error{"policy-activation"};\n'
     '  }',
     ''),
]


def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-activation", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def run() -> subprocess.CompletedProcess:
    return subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    baseline = run()
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
        named, earlier = False, False
        if compiled:
            result = run()
            output = result.stdout + result.stderr
            named = result.returncode != 0 and case in output
            earlier = all(f"CASE_PASS {name}" in output for name in cases[:cases.index(case)])
        SOURCE.write_text(original)
        restored = build() and run().returncode == 0
        record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                  "named_assertion_failed": named, "no_earlier_case_failed": earlier,
                  "restored_baseline": restored, "source_unchanged": SOURCE.read_text() == original}
        records.append(record)
        print(json.dumps(record))
        if not all(v for k, v in record.items() if k not in ("guard", "case")):
            failures += 1

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
