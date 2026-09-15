"""Remove one condition of registry admission at a time.

This exists because the first attempt at this decision compiled, ran, and was
dead: it never built the authority, so the answer was always no and nothing
failed. The case that must stay killable is the one where a complete input
produces an authority.
"""
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
     '    return Error{"registry-admission-not-configuration"};',
     ''),
    ("account-supplied", "missing-account-is-an-input-error",
     '  if (inputs.configuration_account == Hash{} || inputs.transaction.masterchain_state.is_null())\n'
     '    return Error{"registry-admission-input"};',
     '  if (inputs.transaction.masterchain_state.is_null())\n'
     '    return Error{"registry-admission-input"};'),
    ("account-bound-to-state", "gathered-account-must-match-parent-state",
     '  if (declared.value() != inputs.configuration_account)\n'
     '    return Error{"registry-admission-configuration-input"};',
     ''),
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


def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-registry-admission", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def run(fixtures: Path) -> subprocess.CompletedProcess:
    return subprocess.run([str(BINARY), str(fixtures)], capture_output=True, text=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    if run(args.fixtures).returncode != 0:
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
            result = run(args.fixtures)
            named = result.returncode != 0 and case in (result.stderr + result.stdout)
        SOURCE.write_text(original)
        restored = build() and run(args.fixtures).returncode == 0
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
