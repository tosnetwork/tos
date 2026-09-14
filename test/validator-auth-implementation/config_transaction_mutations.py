"""Remove one guard of the config-transaction assembler at a time.

A guard whose removal breaks no named case is a guard nothing depends on. Each
mutation must compile, reach the file, and fail its own named case for the
reason it was written for.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-config-transaction.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-config-transaction")

MUTATIONS = [
    ("coordinate-advance", "coordinate-must-advance",
     '  if (inputs.inclusion <= inputs.parent.seqno_)\n'
     '    return Error{"native-config-transaction-coordinate"};',
     ''),
    ("chain-established", "unestablished-chain-refused",
     '  if (inputs.chain.genesis_root == Hash{} || inputs.chain.genesis_file == Hash{} ||\n'
     '      inputs.chain.chain_domain == Hash{} || inputs.chain.network == 0)\n'
     '    return Error{"native-config-transaction-chain"};',
     ''),
]


def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-config-transaction", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def run(owner: Path) -> subprocess.CompletedProcess:
    return subprocess.run([str(BINARY), "verify", str(owner)], capture_output=True, text=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    if run(args.owner).returncode != 0:
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
            result = run(args.owner)
            named = result.returncode != 0 and case in (result.stderr + result.stdout)
        SOURCE.write_text(original)
        restored = build() and run(args.owner).returncode == 0
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
