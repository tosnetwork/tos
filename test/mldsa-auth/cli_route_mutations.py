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
- fence-lifted-on-counters-alone: a fence is lifted when the controller
  counters move without its own auth transition (another install pending,
  an owner rotate-controller); its unit test must fail.
- supersession-ignores-auth-nonce: moved counters alone count as
  supersession; the committed-refusal sandbox case and the resolver's unit
  test must fail.
- resolver-ignores-supersession-proof: the resolver settles moved counters
  without the snapshot proof; its unit test must fail.
- rebroadcast-ignores-chain-identity: a journaled submission is relayed to a
  chain with the same global id but another zero state; its test must fail.
- legacy-fence-undecodable: a fence journaled without its stage identity no
  longer decodes; its unit test must fail.
- install-skips-interrupted-recovery: --recover-interrupted no longer lifts
  an interrupted fence; the install path's unit test must fail.
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
    "fence-lifted-on-counters-alone",
    [
        (
            CUSTODY,
            "            let landed = auth.mode == crate::agent_account_auth::AUTH_MODE_STAGED",
            "            let landed = true || auth.mode == crate::agent_account_auth::AUTH_MODE_STAGED",
        ),
        (
            CUSTODY,
            '                anyhow::bail!("the stage landed but the controller counters did not advance");',
            "                return Ok(false);",
        ),
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
    "supersession-ignores-auth-nonce",
    [(SDK, "        && state.auth.nonce == auth_nonce\n", "")],
    [
        (
            SANDBOX + ["a_refusal_after_acceptance_consumes_the_counters_without_a_transfer"],
            CARGO_DIR,
            True,
            "a_refusal_after_acceptance_consumes_the_counters_without_a_transfer",
        ),
        (
            COMMANDS_LIB + ["a_request_whose_sequence_another_action_took_settles_as_superseded"],
            CARGO_DIR,
            True,
            "a_request_whose_sequence_another_action_took_settles_as_superseded",
        ),
    ],
)
mutation(
    "resolver-ignores-supersession-proof",
    [
        (
            CLI,
            "            anyhow::ensure!(\n                observation.superseded,",
            "            anyhow::ensure!(\n                true || observation.superseded,",
        )
    ],
    [
        (
            COMMANDS_LIB + ["a_request_whose_sequence_another_action_took_settles_as_superseded"],
            CARGO_DIR,
            True,
            "a_request_whose_sequence_another_action_took_settles_as_superseded",
        )
    ],
)
mutation(
    "rebroadcast-ignores-chain-identity",
    [
        (
            CLI,
            "        claim.network_domain.as_ref() == Some(network),",
            "        true || claim.network_domain.as_ref() == Some(network),",
        )
    ],
    [
        (
            COMMANDS_LIB + ["a_retry_is_never_relayed_to_another_chain_with_the_same_global_id"],
            CARGO_DIR,
            True,
            "a_retry_is_never_relayed_to_another_chain_with_the_same_global_id",
        )
    ],
)
mutation(
    "legacy-fence-undecodable",
    [
        (
            CUSTODY,
            "    #[serde(default)]\n    start_auth_epoch: u64,",
            "    start_auth_epoch: u64,",
        ),
        (
            CUSTODY,
            "    #[serde(default)]\n    staged_module_hash: String,",
            "    staged_module_hash: String,",
        ),
    ],
    [
        (
            CONTRACTS_LIB + ["a_fence_without_its_stage_identity_is_never_lifted_automatically"],
            CARGO_DIR,
            True,
            "a_fence_without_its_stage_identity_is_never_lifted_automatically",
        )
    ],
)
mutation(
    "install-skips-interrupted-recovery",
    [(CLI, "    if !recover {", "    if true || !recover {")],
    [
        (
            COMMANDS_LIB + ["an_interrupted_install_is_recovered_after_a_rotation"],
            CARGO_DIR,
            True,
            "an_interrupted_install_is_recovered_after_a_rotation_and_the_next_send_claims",
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
