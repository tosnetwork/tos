"""Compile registry-admission mutants and require isolated named failures."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-registry-admission.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-registry-admission")

MUTATIONS = [
    ("destination-account", "other-account-not-admitted",
     '  if (recognized.value().destination != declared.value())\n'
     '    return Error{"registry-admission-not-configuration"};', ''),
    ("account-supplied", "missing-account-is-an-input-error",
     '  if (inputs.configuration_account == Hash{} || inputs.transaction.masterchain_state.is_null())\n'
     '    return Error{"registry-admission-input"};',
     '  if (inputs.transaction.masterchain_state.is_null())\n'
     '    return Error{"registry-admission-input"};'),
    ("account-bound-to-state", "gathered-account-must-match-parent-state",
     '  if (declared.value() != inputs.configuration_account)\n'
     '    return Error{"registry-admission-configuration-input"};', ''),
    ("masterchain-only", "non-masterchain-not-admitted",
     '  if (destination.fetch_long(8) != tos::masterchainId)\n'
     '    return Error{"registry-admission-not-configuration"};',
     '  destination.fetch_long(8);'),
    ("deferral", "unresolved-history-defers",
     '  auto history = cache.source(required.value());\n'
     '  if (!history.ok())\n'
     '    return Error{"registry-admission-deferred"};',
     '  auto history = cache.source(required.value());\n'
     '  if (!history.ok())\n'
     '    return Error{"registry-admission-not-registry"};'),
    ("authority-returned", "complete-input-produces-an-authority",
     '  return NativeConfigTransaction::open(inputs.transaction, recognized.value().message.evidence,\n'
     '                                       std::move(owned_history), uncharged);',
     '  return Error{"registry-admission-not-registry"};'),
]


def invoke(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def build() -> bool:
    return invoke(["cmake", "--build", "build-p0", "--target", "test-p0-registry-admission", "-j48"]).returncode == 0


def run(fixtures: Path, selector: str | None = None) -> subprocess.CompletedProcess[str]:
    command = [str(BINARY), str(fixtures)]
    if selector:
        command.append(selector)
    return invoke(command)


def passing(result: subprocess.CompletedProcess[str], expected: int) -> bool:
    lines = result.stdout.splitlines()
    return (result.returncode == 0 and result.stderr == "" and
            lines[-1:] == [f"SUMMARY cases={expected} passed={expected}"] and
            sum(line.startswith("CASE_PASS ") for line in lines) == expected)


def named_failure(result: subprocess.CompletedProcess[str], case: str) -> bool:
    if result.returncode != 1 or result.stdout.splitlines() != [f"SETUP_OK {case}"]:
        return False
    errors = result.stderr.splitlines()
    if errors == [f"ASSERTION_FAILED {case}"]:
        return True
    return (len(errors) == 2 and errors[0].startswith(f"DETAIL {case} expected=") and
            errors[1] == f"ASSERTION_FAILED {case}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    if not build():
        print("BASELINE-BUILD-FAILED", file=sys.stderr)
        return 1
    listed = run(args.fixtures, "--list")
    cases = listed.stdout.splitlines()
    if listed.returncode != 0 or listed.stderr != "" or not cases:
        print("CASE-INVENTORY-FAILED", file=sys.stderr)
        return 1
    if not passing(run(args.fixtures), len(cases)):
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
                named = named_failure(run(args.fixtures, case), case)
                isolated = passing(run(args.fixtures, f"--exclude={case}"), len(cases) - 1)
            SOURCE.write_text(original)
            restored = build() and passing(run(args.fixtures), len(cases))
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
