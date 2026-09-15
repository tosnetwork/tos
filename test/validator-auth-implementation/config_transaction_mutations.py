"""Compile config-transaction mutants and require isolated named failures."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-config-transaction.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-config-transaction")

MUTATIONS = [
    ("exact-successor", "coordinate-must-be-immediate-successor",
     '  if (inputs.parent.seqno_ == std::numeric_limits<std::uint32_t>::max() ||\n'
     '      inputs.inclusion != inputs.parent.seqno_ + 1)\n'
     '    return Error{"native-config-transaction-coordinate"};',
     '  if (inputs.inclusion <= inputs.parent.seqno_)\n'
     '    return Error{"native-config-transaction-coordinate"};'),
    ("chain-established", "unestablished-chain-refused",
     '  if (inputs.chain.genesis_root == Hash{} || inputs.chain.genesis_file == Hash{} ||\n'
     '      inputs.chain.chain_domain == Hash{} || inputs.chain.network == 0)\n'
     '    return Error{"native-config-transaction-chain"};', ''),
    ("history-owned", "history-owned-for-authority-lifetime",
     '    , history_(std::move(history))',
     '    , history_(std::shared_ptr<const FinalizedAnchorSource>(history.get(), [](const FinalizedAnchorSource*) {}))'),
]


def invoke(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def build() -> bool:
    return invoke(["cmake", "--build", "build-p0", "--target", "test-p0-config-transaction", "-j48"]).returncode == 0


def run(owner: Path, selector: str | None = None) -> subprocess.CompletedProcess[str]:
    command = [str(BINARY), "verify", str(owner)]
    if selector:
        command.append(selector)
    return invoke(command)


def passing(result: subprocess.CompletedProcess[str], expected: int) -> bool:
    lines = result.stdout.splitlines()
    return (result.returncode == 0 and result.stderr == "" and
            lines[-1:] == [f"SUMMARY cases={expected} passed={expected}"] and
            sum(line.startswith("CASE_PASS ") for line in lines) == expected)


def named_failure(result: subprocess.CompletedProcess[str], case: str) -> bool:
    return (result.returncode == 1 and result.stdout.splitlines() == [f"SETUP_OK {case}"] and
            result.stderr.splitlines() == [f"ASSERTION_FAILED {case}"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    if not build():
        print("BASELINE-BUILD-FAILED", file=sys.stderr)
        return 1
    listed = run(args.owner, "--list")
    cases = listed.stdout.splitlines()
    if listed.returncode != 0 or listed.stderr != "" or not cases:
        print("CASE-INVENTORY-FAILED", file=sys.stderr)
        return 1
    if not passing(run(args.owner), len(cases)):
        print("BASELINE-NOT-PASSING", file=sys.stderr)
        return 1

    records = []
    failures = 0
    try:
        for guard, case, before, after in MUTATIONS:
            if original.count(before) != 1:
                print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})", file=sys.stderr)
                failures += 1
                continue
            changed = original.replace(before, after, 1)
            SOURCE.write_text(changed)
            reached = SOURCE.read_text() == changed
            compiled = build()
            named = False
            isolated = False
            if compiled:
                named = named_failure(run(args.owner, case), case)
                isolated = passing(run(args.owner, f"--exclude={case}"), len(cases) - 1)
            SOURCE.write_text(original)
            restored = build() and passing(run(args.owner), len(cases))
            record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                      "named_assertion_failed": named, "other_cases_passed": isolated,
                      "restored_baseline": restored, "source_unchanged": SOURCE.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "named_assertion_failed",
                                                "other_cases_passed", "restored_baseline", "source_unchanged")):
                failures += 1
    finally:
        SOURCE.write_text(original)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
