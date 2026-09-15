"""Remove one guard of the chain-context establisher at a time.

A guard whose removal breaks no named case is a guard nothing depends on. Each
mutation must compile, reach the file, and fail only its own case.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-chain-context.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-chain-context")

MUTATIONS = [
    ("zero-binding", "substituted-state-refused",
     '  if (zero_state->get_hash().as_slice() != zero_block_id.root_hash.as_slice())\n'
     '    return Error{"chain-context-zero-binding"};',
     ''),
    ("zero-coordinates", "non-zero-seqno-refused",
     '  if (zero_block_id.id.workchain != tos::masterchainId || zero_block_id.id.seqno != 0)\n'
     '    return Error{"chain-context-zero-id"};',
     ''),
    ("network-agreement", "network-disagreement-refused",
     '  if (!tlb::unpack_cell(zero_state, state) || state.global_id != expected_network)\n'
     '    return Error{"chain-context-network"};',
     '  if (!tlb::unpack_cell(zero_state, state))\n'
     '    return Error{"chain-context-network"};'),
    # The null-state guard is deliberately absent from this list. Removing it
    # does not produce a different answer: the next line dereferences a null
    # reference and the process aborts, so the case fails for a reason that is
    # not the property under test. A failure for the wrong reason is not a kill,
    # so this condition is recorded as necessary-but-not-independently-
    # observable rather than counted as covered.
]


def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-chain-context", "-j48"],
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
