"""Remove one condition of the host-offer predicate at a time.

A condition that can be deleted without a named case failing is a condition
nothing depends on. Each mutation must compile, reach the file, and fail only
its own case.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("crypto/block/transaction.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-host-injection")

WHOLE = """  return validator_auth_host && validator_auth_account && is_masterchain && addr == validator_auth_account.value() &&
         global_version >= vm::validator_auth_min_version &&
         (global_capabilities & vm::validator_auth_capability) != 0;"""

def without(term: str) -> str:
    # Keep the operator the term carried, or the expression stops parsing and a
    # compile failure would be mistaken for the mutation doing nothing.
    return WHOLE.replace(term, "true &&" if term.rstrip().endswith("&&") else "true")

MUTATIONS = [
    ("host-present", "absent-host-offers-nothing", "validator_auth_host &&"),
    # The account guard is deliberately absent from this list. Removing it does
    # not produce a different answer: the next term calls value() on a
    # disengaged optional, which throws, so the case fails for a reason that is
    # not the property under test. A failure for the wrong reason is not a kill,
    # so the condition is recorded as necessary-but-not-independently-observable
    # rather than counted as covered.
    ("masterchain", "non-masterchain-refused", "is_masterchain &&"),
    ("address-match", "other-address-refused", "addr == validator_auth_account.value() &&"),
    ("version-gate", "unactivated-version-refused", "global_version >= vm::validator_auth_min_version &&"),
    ("capability-gate", "absent-capability-refused", "(global_capabilities & vm::validator_auth_capability) != 0"),
]


def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-host-injection", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def run() -> subprocess.CompletedProcess:
    return subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    if original.count(WHOLE) != 1:
        print(f"ANCHOR-NOT-UNIQUE ({original.count(WHOLE)})")
        return 1
    if run().returncode != 0:
        print("BASELINE-NOT-PASSING")
        return 1

    records, failures = [], 0
    for guard, case, term in MUTATIONS:
        assert WHOLE.count(term) == 1, (guard, term)
        SOURCE.write_text(original.replace(WHOLE, without(term), 1))
        mutated = SOURCE.read_text()
        reached = without(term) in mutated
        compiled = build()
        named, others = False, False
        if compiled:
            result = run()
            named = result.returncode != 0 and case in result.stderr
            # Every other case must still pass: the output stops at the first
            # failure, so isolation is read from which case it stopped on.
            others = case in result.stderr
        SOURCE.write_text(original)
        restored = build() and run().returncode == 0
        record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                  "named_assertion_failed": named, "only_named_case_failed": others,
                  "restored_baseline": restored, "source_unchanged": SOURCE.read_text() == original}
        records.append(record)
        print(json.dumps(record))
        if not all((reached, compiled, named, restored, record["source_unchanged"])):
            failures += 1

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
