#!/usr/bin/env python3
"""Red/green controls for the tosctl ML-DSA-44 Agent Account route.

Usage (from a clean checkout, FUNC_PATH and FIFT_PATH set, cargo on PATH):
    python3 test/mldsa-auth/cli_route_mutations.py <results.json>

Starts from a green baseline, applies one mutation at a time, runs the test
that must catch it, requires it to fail naming that test, and restores every
mutated file before the next control:

- module-verifier-removed: the module's PQCHECKSIG refusal is deleted and the
  embedded module bytecode regenerated; the sandbox's wrong-key case must fail.
- context-changed: the SDK signs and verifies under another context; the
  module refuses and the sandbox's positive send must fail.
- staged-module-check-dropped: the CLI precondition that the account names
  this controller's module is removed; its unit test must fail.
- classifier-ignores-source: the resolver accepts the envelope from any
  sender; its unit test must fail.
- custody-ignores-account: the journal accepts a submission for another
  account; its unit test must fail.
- epoch-change-fence-ignored: the journal admits claims while install has
  fenced the account; its unit test must fail.
- already-staged-lifts-any-fence: an install that finds its module already
  staged lifts a fence started at the current counters (a second install
  about to replace the module); its unit test must fail.
- classifier-ignores-action-rollback: a delivery whose action phase failed
  is counted as committed; the resolver's unit test must fail.

Exits nonzero when any control behaves otherwise.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CARGO_DIR = ROOT / "tosctl/src"
OUTPUT = Path(sys.argv[1])
MODULE_SOURCE = "crypto/smartcont/mldsa44-auth-module.fc"
SDK = "tosctl/src/node-control/contracts/src/agent_account_auth.rs"
CLI = "tosctl/src/node-control/commands/src/commands/nodectl/agent_cmd/mldsa44.rs"
CUSTODY = "tosctl/src/node-control/contracts/src/agent_account_custody.rs"
SANDBOX = ["cargo", "test", "-p", "contracts", "--test", "agent_account_mldsa44_sandbox", "--"]
CONTRACTS_LIB = ["cargo", "test", "-p", "contracts", "--lib", "--"]
COMMANDS_LIB = ["cargo", "test", "-p", "commands", "--lib", "--no-default-features", "--"]
REGENERATE = ["python3", "scripts/update-auth-contract-code.py"]

results = []
mismatches = []


def run(command, cwd):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def check(control, command, cwd, expect_failure, marker):
    status, output = run(command, cwd)
    failed = status != 0
    matched = failed == expect_failure and (marker in output if marker else True)
    results.append(
        {
            "control": control,
            "command": " ".join(command),
            "exit": status,
            "expected": "red" if expect_failure else "green",
            "marker": marker,
            "matched": matched,
        }
    )
    if not matched:
        mismatches.append(
            f"{control}: exit {status}; marker {marker!r} present: {marker in output}"
        )


def replace_once(path, old, new):
    target = ROOT / path
    text = target.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"{path}: the mutation anchor must occur exactly once")
    target.write_text(text.replace(old, new, 1))


def mutation(name, edits, steps):
    originals = {path: (ROOT / path).read_bytes() for path, _, _ in edits}
    originals[SDK] = (ROOT / SDK).read_bytes()
    try:
        for path, old, new in edits:
            replace_once(path, old, new)
        for command, cwd, expect_failure, marker in steps:
            check(name, command, cwd, expect_failure, marker)
    finally:
        for path, content in originals.items():
            (ROOT / path).write_bytes(content)


for command in (SANDBOX, CONTRACTS_LIB + ["agent_account"], COMMANDS_LIB + ["mldsa44"]):
    check("baseline", command, CARGO_DIR, False, None)

mutation(
    "module-verifier-removed",
    [
        (
            MODULE_SOURCE,
            "  throw_unless(auth::bad_signature, pq_check_mldsa44(message, context, signature, public_key));\n",
            "",
        )
    ],
    [
        (REGENERATE, ROOT, False, "Updated: " + SDK),
        (
            SANDBOX + ["the_module_refuses_another_key_another_context_and_too_little_funding"],
            CARGO_DIR,
            True,
            "another key",
        ),
    ],
)
mutation(
    "context-changed",
    [(SDK, 'b"TOS-AUTH-ML-DSA-44-v1"', 'b"TOS-AUTH-ML-DSA-44-v2"')],
    [
        (
            SANDBOX + ["a_staged_module_executes_one_native_send_and_refuses_its_replay"],
            CARGO_DIR,
            True,
            "the module must accept before anything is forwarded",
        )
    ],
)
mutation(
    "staged-module-check-dropped",
    [
        (
            SDK,
            "    ensure!(\n        expected.as_ref() == Some(module),",
            "    ensure!(\n        true || expected.as_ref() == Some(module),",
        )
    ],
    [
        (
            CONTRACTS_LIB + ["the_window_and_the_staged_module_are_checked_before_signing"],
            CARGO_DIR,
            True,
            "the_window_and_the_staged_module_are_checked_before_signing",
        )
    ],
)
mutation(
    "classifier-ignores-source",
    [(CLI, "if header.bounced || header.src_ref() != Some(module) {", "if header.bounced {")],
    [
        (
            COMMANDS_LIB + ["account_transactions_are_classified_by_module_envelope"],
            CARGO_DIR,
            True,
            "account_transactions_are_classified_by_module_envelope_commit_and_transfer",
        )
    ],
)
mutation(
    "custody-ignores-account",
    [(CUSTODY, "            || request.account.to_string() != claim.account\n", "")],
    [
        (
            CONTRACTS_LIB
            + ["an_mldsa_submission_is_journaled_only_when_every_layer_matches_the_claim"],
            CARGO_DIR,
            True,
            "an_mldsa_submission_is_journaled_only_when_every_layer_matches_the_claim",
        )
    ],
)
mutation(
    "epoch-change-fence-ignored",
    [
        (
            CUSTODY,
            "\n    if document.epoch_change_fences.contains_key(&generation) {",
            "\n    if false && document.epoch_change_fences.contains_key(&generation) {",
        )
    ],
    [
        (
            CONTRACTS_LIB + ["an_epoch_change_fence_excludes_claims_until_it_is_lifted"],
            CARGO_DIR,
            True,
            "an_epoch_change_fence_excludes_claims_until_it_is_lifted",
        )
    ],
)
mutation(
    "already-staged-lifts-any-fence",
    [
        (
            CUSTODY,
            "            if finalized <= (start.controller_epoch, start.seqno) {",
            "            if false && finalized <= (start.controller_epoch, start.seqno) {",
        )
    ],
    [
        (
            CONTRACTS_LIB + ["an_already_staged_install_leaves_a_second_installs_fence_held"],
            CARGO_DIR,
            True,
            "an_already_staged_install_leaves_a_second_installs_fence_held",
        )
    ],
)
mutation(
    "classifier-ignores-action-rollback",
    [
        (
            CLI,
            "    let committed = !description.aborted\n        && matches!",
            "    let committed = matches!",
        )
    ],
    [
        (
            COMMANDS_LIB + ["account_transactions_are_classified_by_module_envelope"],
            CARGO_DIR,
            True,
            "account_transactions_are_classified_by_module_envelope_commit_and_transfer",
        )
    ],
)
for command in (SANDBOX, CONTRACTS_LIB + ["agent_account"], COMMANDS_LIB + ["mldsa44"]):
    check("restored", command, CARGO_DIR, False, None)

OUTPUT.write_text(json.dumps(results, indent=1) + "\n")
print(json.dumps(results, indent=1))
if mismatches:
    print("controls did not behave as expected:", *mismatches, sep="\n  ", file=sys.stderr)
    sys.exit(1)
if subprocess.run(["git", "diff", "--quiet"], cwd=ROOT).returncode != 0:
    sys.exit("the checkout was not restored")
print("MLDSA44_CLI_ROUTE_CONTROLS_OK")
