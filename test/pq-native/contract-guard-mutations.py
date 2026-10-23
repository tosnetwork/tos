#!/usr/bin/env python3
"""A guard nothing reaches is decoration, whatever its comment says.

Each mutation below removes one rule the post-quantum elector, configuration contract
and their library add or rely on, and requires a test to go red for it. A mutation that survives is reported as a failure: either the rule
is unreachable, or nothing is holding it.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SMARTCONT = ROOT / "crypto/smartcont"
MANIFEST = ROOT / "tosctl/src/Cargo.toml"

# name, file, the text a rule lives in, what removing it looks like, test binary, filter
MUTANTS = [
    # A stake registers only under a signature by the key it carries.
    (
        "stake-signature",
        "elector-code.fc",
        "  ifnot (pq_check_mldsa44(pq::stake_preimage(stake_at, max_factor, src_addr, adnl_addr),",
        "  ifnot (true | pq_check_mldsa44(pq::stake_preimage(stake_at, max_factor, src_addr, adnl_addr),",
        "elector_sandbox",
        "a_post_quantum_stake_signed_by_another_key_is_returned",
    ),
    # The signature names the account the stake comes from, which is the validator id.
    (
        "stake-bound-to-its-sender",
        "pq-validator.fc",
        "    .store_uint(src_addr, 256)\n    .store_uint(adnl_addr, 256)",
        "    .store_uint(0, 256)\n    .store_uint(adnl_addr, 256)",
        "elector_sandbox",
        "every_signed_field_of_a_stake_is_covered_by_its_signature",
    ),
    (
        "stake-factor-at-least-one",
        "elector-code.fc",
        "  if (max_factor < 0x10000) {",
        "  if (false) {",
        "elector_sandbox",
        "a_stake_stating_a_factor_below_one_is_returned",
    ),
    # A post-quantum descriptor needs a transport address; a zero one is refused here
    # rather than by the configuration, which would refuse the whole set.
    (
        "stake-needs-a-transport-address",
        "elector-code.fc",
        "  if (adnl_addr == 0) {",
        "  if (false) {",
        "elector_sandbox",
        "a_post_quantum_stake_without_a_transport_address_is_returned",
    ),
    # Two members with one key would make the configuration refuse the whole set.
    (
        "stake-key-held-by-another-member",
        "elector-code.fc",
        "  if (conflict == 1) {",
        "  if (false) {",
        "elector_sandbox",
        "a_key_already_registered_by_another_member_is_returned",
    ),
    # A member restating its own key and address is a top-up, not a conflict with itself.
    (
        "stake-member-scan-skips-itself",
        "elector-code.fc",
        "      if (id != validator_id) {",
        "      if (true) {",
        "elector_sandbox",
        "a_member_may_restate_its_own_address_and_nobody_else_may",
    ),
    (
        "stake-address-stated-by-another-candidate",
        "elector-code.fc",
        "  if (conflict == 2) {",
        "  if (false) {",
        "elector_sandbox",
        "a_stake_restating_another_candidates_address_is_refused_at_registration",
    ),
    (
        "stake-address-held-by-an-incumbent",
        "elector-code.fc",
        "  if (address_held_by_another_validator(validator_id, adnl_addr)) {",
        "  if (false) {",
        "elector_sandbox",
        "a_stake_restating_an_incumbents_address_is_refused_at_registration",
    ),
    # Every member carries a full post-quantum key, so the member count is bounded.
    (
        "stake-participant-limit",
        "elector-code.fc",
        "    if (bounded_participant_count(members) >= participant_limit) {",
        "    if (false) {",
        "elector_sandbox",
        "an_additional_identity_is_refused_at_the_participant_bound_before_state_changes",
    ),
    # The principal owed back is what was placed, not the stake capped at max_stake.
    (
        "selection-refunds-placed-principal",
        "elector-code.fc",
        "      placed -= true_stake;",
        "      placed = stake - true_stake;",
        "elector_sandbox",
        "over_cap_principal_is_conserved_for_winners_and_losers",
    ),
    # ---------------------------------------------------------------------------
    # The post-quantum authority cutover
    #
    # Each of these is a rule that, if it stopped holding, would leave the chain
    # authorising validators with something other than the current post-quantum set.
    # None of them announces itself when it breaks: a vote counted for the wrong
    # validator, a set installed that the node cannot read, an operation that quietly
    # comes back.
    # ---------------------------------------------------------------------------
    (
        "vote-signature",
        "config-code.fc",
        "    throw_unless(34, pq_check_mldsa44(\n      pq::config_vote_preimage(vset.cell_hash(), validator_id, idx, phash),",
        "    throw_unless(34, true | pq_check_mldsa44(\n      pq::config_vote_preimage(vset.cell_hash(), validator_id, idx, phash),",
        "elector_sandbox",
        "a_vote_signed_by_a_key_that_is_not_at_that_index_is_refused",
    ),
    (
        "vote-identity-from-the-set",
        "pq-validator.fc",
        "    .store_uint(validator_set_id, 256)\n    .store_uint(validator_id, 256)\n    .store_uint(idx, 16)\n    .store_uint(proposal_hash, 256)",
        "    .store_uint(validator_set_id, 256)\n    .store_uint(idx, 16)\n    .store_uint(proposal_hash, 256)",
        "elector_sandbox",
        "a_validator_votes_for_a_proposal_with_the_key_in_the_current_set",
    ),
    (
        "vote-bound-to-its-set",
        "pq-validator.fc",
        "    .store_uint(pq::tag::config_vote_sign, 32)\n    .store_int(pq::global_id(), 32)\n    .store_uint(validator_set_id, 256)",
        "    .store_uint(pq::tag::config_vote_sign, 32)\n    .store_int(pq::global_id(), 32)\n    .store_uint(0, 256)",
        "elector_sandbox",
        "a_validator_votes_for_a_proposal_with_the_key_in_the_current_set",
    ),
    (
        "vote-funding",
        "config-code.fc",
        "    throw_unless(47, msg_value >= pq::verification_value(-1));\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "    throw_unless(47, true);\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "elector_sandbox",
        "an_underfunded_configuration_vote_is_refused_before_the_verification",
    ),
    (
        "vote-minimum-value",
        "config-code.fc",
        "    throw_unless(47, msg_value >= pq::verification_value(-1));\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "    throw_unless(47, true);\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "elector_sandbox",
        "the_minimum_value_a_configuration_vote_must_carry",
    ),
    (
        "complaint-vote-signature",
        "elector-code.fc",
        "    throw_unless(34, pq_check_mldsa44(\n      pq::complaint_vote_preimage(vset.cell_hash(), validator_id, idx, elect_id, chash),",
        "    throw_unless(34, true | pq_check_mldsa44(\n      pq::complaint_vote_preimage(vset.cell_hash(), validator_id, idx, elect_id, chash),",
        "elector_sandbox",
        "a_complaint_vote_signed_by_another_validator_is_refused",
    ),
    (
        "complaint-vote-identity",
        "pq-validator.fc",
        "    .store_uint(validator_set_id, 256)\n    .store_uint(validator_id, 256)\n    .store_uint(idx, 16)\n    .store_uint(election_id, 32)",
        "    .store_uint(validator_set_id, 256)\n    .store_uint(idx, 16)\n    .store_uint(election_id, 32)",
        "elector_sandbox",
        "a_validator_votes_to_punish_a_validator_of_a_past_election",
    ),
    (
        "set-duplicate-validator",
        "config-code.fc",
        "      (_, int duplicate_validator) = seen_validators.udict_get?(256, validator_id);\n      throw_if(9, duplicate_validator);",
        "      (_, int duplicate_validator) = seen_validators.udict_get?(256, validator_id);\n      throw_if(9, false);",
        "elector_sandbox",
        "a_set_the_node_would_refuse_is_refused_before_it_is_installed",
    ),
    (
        "set-duplicate-key",
        "config-code.fc",
        "      (_, int duplicate_key) = seen_keys.udict_get?(256, key_id);\n      throw_if(9, duplicate_key);",
        "      (_, int duplicate_key) = seen_keys.udict_get?(256, key_id);\n      throw_if(9, false);",
        "elector_sandbox",
        "a_set_the_node_would_refuse_is_refused_before_it_is_installed",
    ),
    (
        "set-weight-sum",
        "config-code.fc",
        "  throw_unless(9, weight_sum == total_weight);",
        "  throw_unless(9, true);",
        "elector_sandbox",
        "a_set_the_node_would_refuse_is_refused_before_it_is_installed",
    ),
    (
        "set-count-agreement",
        "config-code.fc",
        "  throw_unless(9, counted == total);",
        "  throw_unless(9, true);",
        "elector_sandbox",
        "a_set_the_node_would_refuse_is_refused_before_it_is_installed",
    ),
    (
        "no-administrator-appointment",
        "config-code.fc",
        "  if (param_id == config::appoint_administrator_param) {\n    return (cfg_dict, false);\n  }",
        "  if (false) {\n    return (cfg_dict, false);\n  }",
        "elector_sandbox",
        "governance_cannot_vote_itself_an_administrator",
    ),
    (
        "no-external-authority",
        "config-code.fc",
        "() recv_external(slice in_msg) impure {\n  throw(32);\n}",
        "() recv_external(slice in_msg) impure {\n  accept_message();\n}",
        "elector_sandbox",
        "an_external_validator_vote_has_no_authorization_path",
    ),
]


def build():
    subprocess.run(
        ["cmake", "--build", "build", "--target", "gen_fif", "-j4"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )


def run(binary, filter_, log):
    completed = subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(MANIFEST),
            "-p",
            "contracts",
            "--locked",
            "--test",
            binary,
            filter_,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "TOS_ROOT": str(ROOT),
            "CARGO_TARGET_DIR": os.environ.get("CARGO_TARGET_DIR", str(ROOT / "tosctl/src/target")),
        },
    )
    raw = completed.stdout + completed.stderr
    log.write_text(raw)
    return (
        completed.returncode,
        raw,
        {
            "path": str(log),
            "bytes": log.stat().st_size,
            "sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--only", default=None, help="run one mutation by name")
    args = parser.parse_args()

    mutants = [m for m in MUTANTS if m[2] is not None]
    if args.only:
        mutants = [m for m in mutants if m[0] == args.only]
    if not mutants:
        parser.error("no matching mutations")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    logs = args.out.parent / (args.out.stem + "-logs")
    logs.mkdir(exist_ok=True)

    # Every anchor is checked before anything is built, and all the broken ones are
    # reported together.
    #
    # This used to be checked inside the loop, one rule at a time, after a build. So a stale
    # anchor stopped the run at the first one it reached and said nothing about the rest --
    # and since a run takes the better part of an hour, and this harness only runs where
    # nothing before it has failed, two rules sat broken for weeks: one whose guard had been
    # written a second time elsewhere in the contract, and one naming a variable that had
    # been renamed. Nothing was measured in all that time, and nothing said so.
    stale = []
    for name, filename, before, _after, _binary, _filter in mutants:
        found = (SMARTCONT / filename).read_text().count(before)
        if found != 1:
            stale.append(
                f"  {name}: matches {found} places in {filename}, and must match exactly one"
            )
    if stale:
        raise ValueError(
            "these rules no longer name one place in the contract they guard:\n" + "\n".join(stale)
        )

    build()
    reports, survivors = [], []
    for name, filename, before, after, binary, filter_ in mutants:
        source = SMARTCONT / filename
        original = source.read_text()
        baseline, _, baseline_receipt = run(binary, filter_, logs / (name + "-baseline.log"))
        if baseline:
            raise RuntimeError(f"{name}: baseline must execute and pass before mutation")
        try:
            source.write_text(original.replace(before, after))
            build()  # A contract that no longer compiles is not a killed mutation.
            exit_code, raw, receipt = run(binary, filter_, logs / (name + "-mutant.log"))
            # A missing fixture, a compilation error or a zero-test filter must
            # never count as a guard exercised by a compiled failing test.
            killed = (
                exit_code == 101
                and "could not compile" not in raw
                and "test result: FAILED" in raw
                and "running 0 tests" not in raw
                and any(filter_ in line and "FAILED" in line for line in raw.splitlines())
            )
        finally:
            source.write_text(original)
        build()
        restored, _, restored_receipt = run(binary, filter_, logs / (name + "-restored.log"))
        if restored:
            raise RuntimeError(f"{name}: restored source must pass")
        reports.append(
            {
                "guard": name,
                "killed": killed,
                "exit": exit_code,
                "test": f"{binary}::{filter_}",
                "baseline": baseline_receipt,
                "mutant": receipt,
                "restored": restored_receipt,
            }
        )
        if not killed:
            survivors.append(name)
        print(f"{'killed  ' if killed else 'SURVIVED'} {name}", flush=True)

    build()
    args.out.write_text(json.dumps(reports, indent=2, sort_keys=True) + "\n")
    if survivors:
        print("surviving mutations: " + ", ".join(survivors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
