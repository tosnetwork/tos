"""Compile registry-admission mutants and require isolated named failures."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-registry-admission.cpp")
# One property spans two files. Whether the caller promotes the prefetched
# source into ownership lives here; whether the authority then keeps it lives in
# the assembler. Both are removed from this one case, each in its own file,
# because either one alone leaves the history dangling.
ASSEMBLER = Path("validator/auth/native-config-transaction.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-registry-admission")
SANITIZED = Path("build-p0-sanitized/test/validator-auth-implementation/test-p0-registry-admission")

# One property is not observable as a wrong answer. A history the authority does
# not own is read after the call that built it returned, and reading freed memory
# usually still returns the bytes that were there. The detector for that is the
# sanitizer, so the mutation that removes ownership is built and run under it.
SANITIZER_ENVIRONMENT = {
    "ASAN_OPTIONS": "detect_leaks=1:detect_stack_use_after_return=1",
    "UBSAN_OPTIONS": "halt_on_error=1",
}

MUTATIONS = [
    ("history-promoted", "history-outlives-the-call-that-assembled-it",
     '  auto owned_history = std::make_shared<PrefetchedAnchorSource>(std::move(history.value()));',
     '  std::shared_ptr<PrefetchedAnchorSource> owned_history(&history.value(), [](PrefetchedAnchorSource*) {});',
     True, [], SOURCE),
    ("history-retained", "history-outlives-the-call-that-assembled-it",
     '    , history_(std::move(history))',
     '    , history_(std::shared_ptr<const FinalizedAnchorSource>(history.get(), [](const FinalizedAnchorSource*) {}))',
     True, [], ASSEMBLER),

    # The collator supplies these facts. Mutating the copy step simulates the
    # integration bug this seam exists to expose: admission must refuse rather
    # than execute under a value different from the one the collator held.
    ("collator-catchain-copy", "collator-gathering-produces-an-authority",
     '  inputs.transaction.catchain = catchain;',
     '  inputs.transaction.catchain = catchain ^ 1u;'),
    ("collator-parent-root-copy", "collator-gathering-produces-an-authority",
     '  inputs.transaction.parent = anchor_of(parent_block, masterchain_state);',
     '  inputs.transaction.parent = anchor_of(parent_block, masterchain_state);\n'
     '  inputs.transaction.parent.root_[0] ^= 1;'),
    ("collator-parent-file-copy", "collator-gathering-produces-an-authority",
     '  inputs.transaction.parent = anchor_of(parent_block, masterchain_state);',
     '  inputs.transaction.parent = anchor_of(parent_block, masterchain_state);\n'
     '  inputs.transaction.parent.file_[0] ^= 1;'),

    # The bindings are independently observable by changing only the preserved
    # source while leaving the transaction copy valid. Removing either guard
    # must therefore make the refusal case unexpectedly assemble an authority.
    ("catchain-source-bound", "gathered-catchain-must-match-source",
     '  if (inputs.transaction.catchain != inputs.catchain_source)\n'
     '    return Error{"registry-admission-catchain-input"};', ''),
    ("parent-source-bound", "gathered-parent-root-must-match-source",
     '  const auto parent = anchor_of(inputs.parent_block, inputs.transaction.masterchain_state);\n'
     '  if (inputs.transaction.parent != parent)\n'
     '    return Error{"registry-admission-parent-input"};', '',
     False, ["gathered-parent-file-must-match-source"]),

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
    # Removing the returned authority breaks every case that needs one. The
    # companions are declared rather than the rule relaxed: a mutation that
    # breaks something it did not name is a mutation nobody understood.
    ("authority-returned", "complete-input-produces-an-authority",
     '  return NativeConfigTransaction::open(inputs.transaction, recognized.value().message.evidence,\n'
     '                                       std::move(owned_history), uncharged);',
     '  return Error{"registry-admission-not-registry"};',
     False, ["collator-gathering-produces-an-authority",
             "history-outlives-the-call-that-assembled-it", "resolved-history-admits"]),
]


def invoke(command: list[str], environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = None
    if environment:
        merged = dict(os.environ)
        merged.update(environment)
    return subprocess.run(command, capture_output=True, text=True, check=False, env=merged)


def build(sanitized: bool = False) -> bool:
    tree = "build-p0-sanitized" if sanitized else "build-p0"
    return invoke(["cmake", "--build", tree, "--target", "test-p0-registry-admission", "-j48"]).returncode == 0


def run(fixtures: Path, selector: str | None = None,
        sanitized: bool = False) -> subprocess.CompletedProcess[str]:
    command = [str(SANITIZED if sanitized else BINARY), str(fixtures)]
    if selector:
        command.append(selector)
    return invoke(command, SANITIZER_ENVIRONMENT if sanitized else None)


def passing(result: subprocess.CompletedProcess[str], expected: int) -> bool:
    lines = result.stdout.splitlines()
    return (result.returncode == 0 and result.stderr == "" and
            lines[-1:] == [f"SUMMARY cases={expected} passed={expected}"] and
            sum(line.startswith("CASE_PASS ") for line in lines) == expected)


def named_failure(result: subprocess.CompletedProcess[str], case: str, sanitized: bool = False) -> bool:
    if result.stdout.splitlines() != [f"SETUP_OK {case}"]:
        return False
    # Under the sanitizer the case does not fail an assertion; the process is
    # aborted at the read. Requiring only a clean exit code here would accept a
    # mutant that answered wrongly instead of one that read freed memory.
    if sanitized:
        return result.returncode != 0 and "AddressSanitizer" in result.stderr
    if result.returncode != 1:
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
    # Every file this run may edit, captured before anything is touched, so an
    # interruption restores all of them rather than the one that happened to be
    # last.
    pristine = {path: path.read_text() for path in {SOURCE, ASSEMBLER}}
    try:
        for guard, case, before, after, *rest in MUTATIONS:
            sanitized = bool(rest and rest[0])
            companions = list(rest[1]) if len(rest) > 1 else []
            source = rest[2] if len(rest) > 2 else SOURCE
            original = source.read_text()
            if original.count(before) != 1:
                print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})", file=sys.stderr)
                failures += 1
                continue
            changed = original.replace(before, after, 1)
            source.write_text(changed)
            reached = source.read_text() == changed
            compiled = build(sanitized)
            named = False
            isolated = False
            if compiled:
                named = named_failure(run(args.fixtures, case, sanitized), case, sanitized)
                # Every other case run on its own. Running them together stops at
                # the first failure, which hides whether the ones after it still
                # hold -- and that is the question isolation is asking.
                spared = [name for name in cases if name != case and name not in companions]
                isolated = all(passing(run(args.fixtures, name, sanitized), 1) for name in spared)
            source.write_text(original)
            restored = build(sanitized) and passing(run(args.fixtures, sanitized=sanitized), len(cases))
            record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                      "named_assertion_failed": named, "only_declared_cases_broke": isolated,
                      "declared_companions": companions,
                      "source": str(source), "restored_baseline": restored,
                      "source_unchanged": source.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "named_assertion_failed",
                                                "only_declared_cases_broke", "restored_baseline", "source_unchanged")):
                failures += 1
    finally:
        for path, text in pristine.items():
            path.write_text(text)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
