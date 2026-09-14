"""Remove one shape check of the registry-message recognizer at a time.

The recognizer is a place where an attacker chooses the input, so a check that
can be removed without a named case failing is a check nothing depends on. Each
mutation must compile, reach the file, and fail its own named case.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-config-message.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-config-message")

MUTATIONS = [
    ("action-tag", "other-action-refused",
     '    if (cs.fetch_ulong(32) != native_registry_action)\n      return Error{"registry-message-action"};',
     '    cs.fetch_ulong(32);'),
    ("missing-reference", "missing-reference-refused",
     '    if (update.is_null() || evidence.is_null())\n      return Error{"registry-message-shape"};',
     ''),
    # Now that the redundant count check is gone, this is what refuses an extra
    # reference as well as trailing bits; it is named for the case it stops
    # first.
    ("exact-parse-end", "extra-reference-refused",
     '    if (cs.size() != 0 || cs.size_refs() != 0)\n      return Error{"registry-message-shape"};',
     ''),
    # The null-body guard is deliberately absent from this list: removing it
    # dereferences a null reference and aborts rather than answering
    # differently, and a failure for the wrong reason is not a kill.
]


def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-config-message", "-j48"],
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
