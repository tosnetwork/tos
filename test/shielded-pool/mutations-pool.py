#!/usr/bin/env python3
"""Remove one rule at a time from the pool contract's deposit path and require
the sandbox suite to report it, by name.

A mutation that turns the wrong test red is not evidence for the one it was
aimed at, so each case names the test that must fail. A mutation that fails to
compile is not evidence at all: every replacement below still compiles and
still runs, it is simply wrong.

Usage: mutations-pool.py [--only NAME ...]
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import sys

# This repository, never another checkout: TOS_ROOT points at the built
# toolchain, which may live somewhere else entirely.
from toolchain import toolchain_root

ROOT = Path(__file__).resolve().parents[2]

POOL = ROOT / 'crypto/smartcont/tos-shielded-pool-v1.fc'
ANCHORS = ROOT / 'crypto/smartcont/shielded/anchors.fc'
# Not a contract. The recovery path's authentication rests on the executor
# refusing to let a contract set the bounced flag, and gate 16 is about that.
EXECUTOR = ROOT / 'tosctl/src/executor/src/transaction_executor.rs'
RECOVERY = ROOT / 'crypto/smartcont/shielded/recovery.fc'
CONTRACTS = ROOT / 'tosctl/src/node-control/contracts'
# The ceilings have to hold for a pool that has been running, and only the
# crosscheck crate can age one: it owns the probes that build a worn frontier
# and full anchor rings.
CROSSCHECK = ROOT / 'tools/shielded-pool-circuit/crosscheck'
SUITE = 'shielded_pool_sandbox'
TRANSACT_SUITE = 'shielded_pool_transact_sandbox'
MATURE_DEPOSIT_SUITE = 'deposit_in_a_mature_pool'
MATURE_TRANSACT_SUITE = 'transact_in_a_mature_pool'

LEDGER_TEST = 'a_deposit_is_the_note_the_contract_computed_at_the_index_it_assigned'
NOTE_TEST = 'the_depositor_cannot_choose_its_note'
STARVED_TEST = 'a_message_that_cannot_pay_for_its_own_gas_never_reaches_the_pools_balance'
FUNDING_TEST = 'a_deposit_must_fund_its_principal_and_its_execution'
SHAPE_TEST = 'only_a_configured_denomination_and_the_frozen_body_shape_are_accepted'
TOPUP_TEST = 'a_plain_top_up_and_a_bounce_change_no_shielded_state'
RESERVE_TEST = 'a_reserve_top_up_adds_balance_and_nothing_else'
ORDER_TEST = 'each_step_fails_with_its_own_code_and_in_its_own_place'
ATOMIC_TEST = 'a_failure_at_any_step_changes_nothing'
COST_TEST = 'a_transact_fits_its_ceiling_and_the_gas_this_chain_grants'
WITHDRAWAL_TEST = 'a_well_formed_withdrawal_reaches_the_proof_like_a_transfer_does'
PROOF_TEST = 'a_proof_that_does_not_verify_stops_the_transaction'
MATURE_DEPOSIT_TEST = 'a_deposit_fits_its_ceiling_at_every_age'
TRAFFIC_SUITE = 'anchor_traffic'
DEPOSIT_TRAFFIC_TEST = 'pure_deposit_traffic_writes_every_consecutive_slot'
MIXED_TRAFFIC_TEST = 'mixed_traffic_leaves_the_skipped_slots_alone'
RING_SIZE_TEST = 'a_version_half_a_ring_away_lands_on_its_own_slot'
RECENT_LIVE_TEST = 'a_recent_root_is_accepted_until_its_slot_is_overwritten'
RECENT_DEAD_TEST = 'a_recent_root_is_refused_once_its_slot_is_overwritten'
FORGED_SUITE = 'forged_bounce'
FORGED_TEST = 'a_contract_cannot_send_the_pool_a_message_that_arrives_bounced'
RECORD_BINDING_TEST = 'a_record_naming_another_address_is_refused_from_any_sender'
ATOMICITY_SUITE = 'atomicity_beyond_a_throw'
OOG_DEPOSIT_TEST = 'a_deposit_that_runs_out_of_gas_changes_nothing'
OOG_TRANSACT_TEST = 'a_transact_that_runs_out_of_gas_changes_nothing'
ACTION_FAILURE_TEST = 'a_withdrawal_whose_payout_cannot_be_sent_changes_nothing'
STATE_LIMIT_TEST = 'a_deposit_refused_by_the_state_limit_changes_nothing'
MATURE_TRANSACT_TEST = 'a_withdrawal_and_its_bounce_in_a_pool_with_history'


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str
    # The deposit path and the transact path have suites of their own; a
    # mutation is only evidence against the suite that can see it.
    suite: str = SUITE
    crate: Path = CONTRACTS


CASES = [
    # The rule the whole backing argument rests on. Inserted where the threat
    # actually is -- after the operation is known and before any work -- so the
    # message is carried past the gas it paid for.
    Case('accept', 'the contract accepts the message before looking at it', POOL,
         '() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {\n',
         '() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {\n  accept_message();\n',
         STARVED_TEST),

    # Section 14.1: message-local funding.
    Case('funding-compute', 'the message need not pay for its own execution', POOL,
         '    msg_value >= deposit_amount + get_compute_fee(0, deposit_gas_ceiling()));',
         '    msg_value >= deposit_amount);', FUNDING_TEST),
    Case('funding-principal', 'the message need not carry its own principal', POOL,
         '    msg_value >= deposit_amount + get_compute_fee(0, deposit_gas_ceiling()));',
         '    msg_value >= get_compute_fee(0, deposit_gas_ceiling()));', FUNDING_TEST),
    Case('gas-ceiling-live', 'the ceiling is below what the path needs', POOL,
         'int deposit_gas_ceiling() asm "230000 PUSHINT";',
         'int deposit_gas_ceiling() asm "5000 PUSHINT";', LEDGER_TEST),
    # A ceiling that covers a pool with empty anchor rings and refuses one
    # whose rings are full. The rings are worth about 14,000 gas a mutation
    # and they fill once and stay full, so this is the age a harness that
    # deploys and sends three messages cannot see. The frontier used to be a
    # second such age; it is not any more, because the store is no longer a
    # dictionary whose reads grow with the leaf index.
    Case('gas-ceiling-fresh-pool', 'the deposit ceiling covers only a new pool', POOL,
         'int deposit_gas_ceiling() asm "230000 PUSHINT";',
         'int deposit_gas_ceiling() asm "160000 PUSHINT";',
         MATURE_DEPOSIT_TEST, MATURE_DEPOSIT_SUITE, CROSSCHECK),
    Case('bounce-ceiling-fresh-pool', 'the bounce ceiling covers only a new pool', POOL,
         'int bounce_gas_ceiling() asm "240000 PUSHINT";',
         'int bounce_gas_ceiling() asm "170000 PUSHINT";',
         MATURE_TRANSACT_TEST, MATURE_TRANSACT_SUITE, CROSSCHECK),
    # The corner the two ends of a pool's life do not contain. Full anchor
    # rings make a transact dearer and a higher leaf index makes it slightly
    # cheaper, so the dearest *reachable* state is full rings on the youngest
    # tree that can have them. 1,465,000 clears the rule against a fresh pool
    # and against the worst leaf index, and fails it only there -- so only the
    # measurement taken at that corner can kill it. The ceiling itself no
    # longer comes from that corner, or from any other reachable one:
    # `gas_ceiling_bound` derives it. This case stays because the corner is
    # still what a sampled maximum misses.
    Case('transact-ceiling-misses-the-corner',
         'the transact ceiling is set from the two ends of a pool\'s life', POOL,
         'int transact_gas_ceiling() asm "1510000 PUSHINT";',
         'int transact_gas_ceiling() asm "1465000 PUSHINT";',
         MATURE_TRANSACT_TEST, MATURE_TRANSACT_SUITE, CROSSCHECK),
    # A ceiling that is not the rule's, but is still above the path at every
    # age, so nothing stops working and no cost test notices. The only thing
    # wrong with 180,000 is that the rule gives 230,000, and a sender under it
    # would be charged for a budget nobody derived. This is what a suite
    # holding its own copy of the ceiling could never catch: until 2026-09-21
    # the check compared the ceiling written in the test against the same
    # number computed in the test, and passed whatever the contract said.
    Case('gas-ceiling-off-the-rule',
         'the deposit ceiling is not the one the production rule gives', POOL,
         'int deposit_gas_ceiling() asm "230000 PUSHINT";',
         'int deposit_gas_ceiling() asm "180000 PUSHINT";',
         'the_gas_ceiling_does_not_depend_on_how_much_money_arrived', SUITE, CONTRACTS),

    # Section 19 gate 17, over runs rather than single messages. These four
    # are aimed at the traffic tests in the crosscheck crate, which are the
    # only place a mutation that is correct for one message and wrong for a
    # sequence can show itself.
    Case('anchor-version', 'a root is preserved under the wrong version', ANCHORS,
         '  int root_version = commitment_next_index;',
         '  int root_version = commitment_next_index + 1;',
         DEPOSIT_TRAFFIC_TEST, TRAFFIC_SUITE, CROSSCHECK),
    Case('anchor-after-append', 'the root preserved is the one after the append', POOL,
         "  ;; 8. the pre-mutation root is preserved once, before the append.\n  (anchors, last_anchor_epoch) =\n    anchors_preserve(anchors, commitment_next_index, commitment_root, now(),\n                     last_anchor_epoch);\n\n  ;; 9. the leaf index is the contract's, not the sender's.\n  int leaf_index = commitment_next_index;\n  int leaf = note_commitment(note_body, leaf_index);\n  (frontier, commitment_root) = frontier_append(frontier, leaf_index, leaf);",
         "  ;; 9. the leaf index is the contract's, not the sender's.\n  int leaf_index = commitment_next_index;\n  int leaf = note_commitment(note_body, leaf_index);\n  (frontier, commitment_root) = frontier_append(frontier, leaf_index, leaf);\n\n  ;; 8. the pre-mutation root is preserved once, before the append.\n  (anchors, last_anchor_epoch) =\n    anchors_preserve(anchors, commitment_next_index, commitment_root, now(),\n                     last_anchor_epoch);",
         RECENT_LIVE_TEST, TRAFFIC_SUITE, CROSSCHECK),
    Case('anchor-slot-modulus', 'the ring is addressed by a modulus that is not its size',
         ANCHORS,
         '                                    root_version % recent_root_slots(),',
         '                                    root_version % 2048,',
         RING_SIZE_TEST, TRAFFIC_SUITE, CROSSCHECK),
    Case('anchor-occupancy', 'a slot that is occupied is treated as a match', ANCHORS,
         '    throw_unless(153, (stored_id == id) & (stored_root == root));',
         '    throw_unless(153, found);',
         RECENT_DEAD_TEST, TRAFFIC_SUITE, CROSSCHECK),
    # Section 19 gate 16. The first of these is not a contract mutation: it
    # removes the executor's guarantee that a contract cannot send a message
    # that arrives bounced, which is the only thing standing between the
    # address a payout was sent to and a free mint.
    Case('bounced-flag-kept', 'a contract may send a message that arrives bounced', EXECUTOR,
         '        int_header.bounced = false;\n    }',
         '    }',
         FORGED_TEST, FORGED_SUITE, CROSSCHECK),
    Case('recovery-address-binding', 'a record is recovered by whoever presents it', RECOVERY,
         '  throw_unless(267, recipient_hash == public_recipient_hash(sender));',
         '  throw_unless(267, recipient_hash == recipient_hash);',
         RECORD_BINDING_TEST, FORGED_SUITE, CROSSCHECK),
    # Section 19 gate 11, for the failures a throw does not reach. One is a
    # contract mutation and one is not: whether a state the chain refuses to
    # store is rolled back is the executor's answer, and the pool's atomicity
    # rests on it either way. The out-of-gas half has no mutation at all --
    # a compute phase that throws hands back no data, so nothing in this
    # repository can make a half-finished deposit persist. The tests carry
    # controls instead.
    Case('payout-reserve-omits-liability', 'the payout may be paid out of what the pool owes',
         POOL,
         '    raw_reserve(native_liability + reserve_floor, 0);',
         '    raw_reserve(reserve_floor, 0);',
         ACTION_FAILURE_TEST, ATOMICITY_SUITE, CROSSCHECK),
    Case('state-limit-unchecked', 'a state above the chain\'s limit is stored anyway', EXECUTOR,
         '        if !is_special && !check_account_size_limits(limits, &mut acc_copy)? {',
         '        if false {',
         STATE_LIMIT_TEST, ATOMICITY_SUITE, CROSSCHECK),
    # Section 12.1: the body, and what may be deposited.
    Case('body-refs', 'a deposit body with no payload is not refused here', POOL,
         '  throw_unless(200, body.slice_refs() == 1);',
         '  throw_unless(200, body.slice_refs() >= 0);', SHAPE_TEST),
    Case('body-trailing', 'trailing bits after the deposit fields are ignored', POOL,
         '  cell output_data = body~load_ref();\n  throw_unless(200, body.slice_empty?());',
         '  cell output_data = body~load_ref();', SHAPE_TEST),
    Case('denomination', 'any amount is a denomination', POOL,
         '  throw_unless(202, config_has_denomination(config, deposit_amount));',
         '  throw_unless(202, deposit_amount > 0);', SHAPE_TEST),
    Case('unknown-op', 'an unknown operation is ignored instead of refused', POOL,
         '  throw(201);\n}\n\n() recv_external', '  return ();\n}\n\n() recv_external',
         SHAPE_TEST),

    # Section 16.1: the note is the contract's, and so is the index.
    Case('note-amount', 'the note is built for an amount the contract did not admit', POOL,
         '  int note_body = note_body_commitment(owner_commitment, deposit_amount, data_hash);',
         '  int note_body = note_body_commitment(owner_commitment, 0, data_hash);', NOTE_TEST),
    Case('note-payload', 'the payload does not reach the note', POOL,
         '  int note_body = note_body_commitment(owner_commitment, deposit_amount, data_hash);',
         '  int note_body = note_body_commitment(owner_commitment, deposit_amount, 0);', NOTE_TEST),
    # Both handlers assign a leaf index the same way, so this anchor carries
    # the deposit path's own comment with it.
    Case('leaf-index', 'the leaf is committed at the wrong index', POOL,
         """;; 9. the leaf index is the contract's, not the sender's.
  int leaf_index = commitment_next_index;""",
         """;; 9. the leaf index is the contract's, not the sender's.
  int leaf_index = commitment_next_index + 1;""", LEDGER_TEST),
    # The recovery handler writes the counter the same way, so this anchor
    # carries the deposit path's own comment with it.
    Case('leaf-counter', 'the counter does not advance with the tree', POOL,
         ';; 10, 11. one write, at the end. No COMMIT and no outbound action.\n'
         '  set_data(state_build(commitment_root, leaf_index + 1,',
         ';; 10, 11. one write, at the end. No COMMIT and no outbound action.\n'
         '  set_data(state_build(commitment_root, leaf_index,', LEDGER_TEST),

    # Section 12.1 step 8: liability is the principal, and nothing else.
    Case('liability-value', 'liability grows by what arrived, not by what was admitted', POOL,
         '  int new_liability = native_liability + deposit_amount;',
         '  int new_liability = native_liability + msg_value;', LEDGER_TEST),
    Case('liability-none', 'a deposit adds no liability at all', POOL,
         '  int new_liability = native_liability + deposit_amount;',
         '  int new_liability = native_liability;', LEDGER_TEST),

    # Sections 12.3 and 16.4: reserve without a note.
    Case('topup-leftover', 'anything left over after the query id is ignored', POOL,
         '  int query_id = body~load_uint(64);\n  throw_unless(200, body.slice_empty?());',
         '  int query_id = body~load_uint(64);', RESERVE_TEST),
    Case('topup-funding', 'a top-up need not pay for its own compute', POOL,
         '  throw_unless(203, msg_value >= get_compute_fee(0, topup_gas_ceiling()));',
         '  throw_unless(203, msg_value >= 0);', RESERVE_TEST),
    Case('topup-op', 'a top-up is dispatched to the deposit handler', POOL,
         '  if (op == op_reserve_topup()) {\n    handle_reserve_topup(msg_value, in_msg_body);',
         '  if (op == op_reserve_topup()) {\n    handle_deposit(msg_value, in_msg_body);',
         RESERVE_TEST),

    # Section 16.2: the transact handler's order and its rules.
    Case('transact-funding', 'a transact need not pay for its own compute', POOL,
         '  throw_unless(203, msg_value >= get_compute_fee(0, transact_gas_ceiling()));',
         '  throw_unless(203, msg_value >= 0);', ORDER_TEST, TRANSACT_SUITE),
    Case('transact-withdrawal-refused', 'the withdrawal path is refused outright', POOL,
         '  check_intent_validity(valid_until, now());\n',
         '  check_intent_validity(valid_until, now());\n  throw_unless(206, public_amount_out == 0);\n',
         WITHDRAWAL_TEST, TRANSACT_SUITE),
    Case('transact-denomination', 'a withdrawal may name any amount it likes', POOL,
         '    throw_unless(202, config_has_denomination(config, public_amount_out));\n', '',
         ORDER_TEST, TRANSACT_SUITE),
    Case('transact-denomination-transfer', 'a transfer is held to the denomination list too', POOL,
         '  if (public_amount_out > 0) {\n    throw_unless(202, config_has_denomination(config, public_amount_out));\n  }',
         '  throw_unless(202, config_has_denomination(config, public_amount_out));',
         ORDER_TEST, TRANSACT_SUITE),
    Case('transact-validity', 'the intent has no window', POOL,
         '  check_intent_validity(valid_until, now());\n', '', ORDER_TEST, TRANSACT_SUITE),
    Case('transact-anchor', 'any anchor is accepted', POOL,
         '  anchor_require_valid(anchors, anchor_kind, anchor_id, anchor_root,\n                       commitment_root, now());\n',
         '', ORDER_TEST, TRANSACT_SUITE),
    Case('transact-authorize', 'the signatures are never checked', POOL,
         '  (int key_hash_0, int key_hash_1) =\n    authorize_intent(public_key_0, signature_0, public_key_1, signature_1, intent_digest);\n',
         '', ORDER_TEST, TRANSACT_SUITE),
    Case('transact-nullifier-sequence', 'the second witness is judged against the first tree', POOL,
         '  (temp_nullifier_root, temp_nullifier_next) =\n    imt_insert(temp_nullifier_root, temp_nullifier_next, nullifier_1, witness_1);',
         '  (temp_nullifier_root, temp_nullifier_next) =\n    imt_insert(nullifier_root, nullifier_next_index, nullifier_1, witness_1);',
         ORDER_TEST, TRANSACT_SUITE),
    Case('transact-proof', 'the proof is never verified', POOL,
         '  groth16_require_valid(vk, proof_a, proof_b, proof_c, inputs);\n', '',
         PROOF_TEST, TRANSACT_SUITE),
    Case('transact-gas-ceiling', 'the ceiling is below what the path needs', POOL,
         'int transact_gas_ceiling() asm "1510000 PUSHINT";',
         'int transact_gas_ceiling() asm "5000 PUSHINT";', ORDER_TEST, TRANSACT_SUITE),

    # A message with no operation must not be mistaken for one.
    Case('empty-body', 'a body too short to hold an operation is parsed anyway', POOL,
         '  if (in_msg_body.slice_bits() < 32) {\n    return ();\n  }\n', '', TOPUP_TEST),
]


def run_suite(suite: str = SUITE, crate: Path = CONTRACTS) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env['PATH'] = str(Path.home() / '.cargo/bin') + os.pathsep + env.get('PATH', '')
    env['CARGO_TERM_COLOR'] = 'never'
    # TOS_ROOT only locates the built func/fift toolchain and stdlib.fc; the
    # library under test is found from the crate manifest, inside this tree.
    env.setdefault('TOS_ROOT', str(toolchain_root(ROOT)))
    return subprocess.run(['cargo', 'test', '--release', '--test', suite, '--',
                           '--test-threads=1'],
                          cwd=crate, capture_output=True, text=True, timeout=3600, env=env)


def failed_tests(output: str) -> set[str]:
    return set(re.findall(r'^test (\S+) \.\.\. FAILED$', output, flags=re.M))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--only', nargs='*', default=None)
    options = parser.parse_args()
    cases = CASES if options.only is None else [c for c in CASES if c.name in options.only]
    if options.only and len(cases) != len(options.only):
        raise SystemExit(f'unknown case name in {options.only}')

    baseline_suites = sorted({(c.suite, c.crate) for c in cases})
    for suite, crate in baseline_suites:
        baseline = run_suite(suite, crate)
        if baseline.returncode:
            raise SystemExit(f'{suite} is not green before any mutation:\n'
                             + baseline.stdout + baseline.stderr)
    print('baseline green', flush=True)

    survivors = []
    for case in cases:
        original = case.path.read_text()
        count = original.count(case.before)
        if count != 1:
            raise SystemExit(f'{case.name}: anchor appears {count} times, expected once')
        try:
            case.path.write_text(original.replace(case.before, case.after))
            result = run_suite(case.suite, case.crate)
            failures = failed_tests(result.stdout + result.stderr)
            if result.returncode == 0:
                survivors.append(f'{case.name}: the suite stayed green')
                verdict = 'SURVIVED'
            elif 'error[' in result.stderr or 'could not compile' in result.stderr:
                survivors.append(f'{case.name}: no longer compiles, which is not evidence')
                verdict = 'UNCOMPILED'
            elif case.expect not in failures:
                survivors.append(f'{case.name}: failed as {sorted(failures)}, not {case.expect}')
                verdict = 'WRONG-TEST'
            else:
                verdict = 'killed'
            print(f'{case.name:20} {case.why:58} {verdict}', flush=True)
        finally:
            case.path.write_text(original)

    for suite, crate in baseline_suites:
        again = run_suite(suite, crate)
        if again.returncode:
            raise SystemExit(f'{suite} did not come back green:\n'
                             + again.stdout + again.stderr)
    print('green again', flush=True)

    if survivors:
        print('\nSURVIVORS:', file=sys.stderr)
        for line in survivors:
            print('  ' + line, file=sys.stderr)
        return 1
    print(f'\n{len(cases)} mutations, all killed by the test they were aimed at')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
