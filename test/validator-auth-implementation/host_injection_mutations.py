"""Remove one condition of the host-offer predicate at a time.

A condition that can be deleted without a named case failing is a condition
nothing depends on. Each mutation must compile, reach the file, and break only
the cases it declares.

Isolation is read from the whole case list, not from where the run stopped. The
test reports every case, so a mutation that quietly broke a later one cannot
hide behind an earlier failure -- a case that was never reached would otherwise
be indistinguishable from one that passed.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("crypto/block/transaction.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-host-injection")

WHOLE = """  return validator_auth_host && account.is_masterchain() &&
         cfg.global_version >= vm::validator_auth_min_version &&
         (cfg.global_capabilities & vm::validator_auth_capability) != 0;"""


def without(term: str) -> str:
    # Keep the operator the term carried, or the expression stops parsing and a
    # compile failure would be mistaken for the mutation doing nothing.
    return WHOLE.replace(term, "true &&" if term.rstrip().endswith("&&") else "true")


# The account is deliberately absent from this list. It is no longer a condition
# here: an authority reaches a transaction only because the assembler recognised
# the message that transaction is processing, and refusing a message addressed
# anywhere but the configuration account is that assembler's job. Restating it
# here would be a second answer to the same question.
MUTATIONS = [
    ("host-present", "transaction-without-authority-offers-nothing", "validator_auth_host &&",
     ["two-transactions-sharing-one-compute-config-do-not-share-authority"]),
    ("masterchain", "non-masterchain-transaction-offers-nothing", "account.is_masterchain() &&", []),
    ("version-gate", "unactivated-version-refused", "cfg.global_version >= vm::validator_auth_min_version &&", []),
    ("capability-gate", "absent-capability-refused", "(cfg.global_capabilities & vm::validator_auth_capability) != 0",
     ["later-version-still-needs-capability"]),
]


def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-host-injection", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def run() -> subprocess.CompletedProcess:
    return subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)


def failing(result: subprocess.CompletedProcess) -> set[str]:
    return {line.removeprefix("CASE_FAIL ") for line in result.stdout.splitlines() if line.startswith("CASE_FAIL ")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    if original.count(WHOLE) != 1:
        print(f"ANCHOR-NOT-UNIQUE ({original.count(WHOLE)})")
        return 1
    baseline = run()
    if baseline.returncode != 0 or failing(baseline):
        print("BASELINE-NOT-PASSING")
        return 1
    cases = sum(line.startswith("CASE_") for line in baseline.stdout.splitlines())

    records, failures = [], 0
    try:
        for guard, case, term, companions in MUTATIONS:
            assert WHOLE.count(term) == 1, (guard, term)
            SOURCE.write_text(original.replace(WHOLE, without(term), 1))
            reached = without(term) in SOURCE.read_text()
            compiled = build()
            broke: set[str] = set()
            if compiled:
                broke = failing(run())
            SOURCE.write_text(original)
            restored = build() and run().returncode == 0
            record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                      "named_case_failed": case in broke,
                      "only_declared_cases_broke": broke <= {case, *companions},
                      "declared_companions": companions, "cases_broken": sorted(broke), "cases_run": cases,
                      "restored_baseline": restored, "source_unchanged": SOURCE.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "named_case_failed",
                                               "only_declared_cases_broke", "restored_baseline", "source_unchanged")):
                failures += 1
    finally:
        SOURCE.write_text(original)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
