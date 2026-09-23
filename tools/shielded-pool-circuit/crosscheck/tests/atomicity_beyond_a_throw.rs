/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 19 gate 11, for the three failures a throw does not cover.
//!
//! A `throw` is the easy case: the handler writes its state once, at the end,
//! so nothing reached `set_data`. The three the gate also names can all
//! happen *after* the compute phase has decided what the new state is:
//!
//!   * out of gas, which ends the compute phase wherever it happens to be;
//!   * an action-phase failure, after `set_data` has already run;
//!   * a state-limit failure, which is the action phase refusing the state
//!     the compute phase produced.
//!
//! Each one is reached here by changing the world around the contract rather
//! than the contract: the gas the chain grants, the balance the pool holds,
//! and the size a state may be. A test that reached them by editing the
//! contract would be testing the edit.

use ark_ff::PrimeField;
use chain_block::SizeLimitsConfig;
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::wire;
use shielded_pool_circuit_crosscheck::pool::{Pool, PoolState, DENOMINATION, WITHDRAWAL_FEE};
use shielded_pool_circuit_crosscheck::wire::byte_chain;

mod support;
use support::{Perturbation, Withdrawal};

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;

/// Out of gas.
const OUT_OF_GAS: i32 = -14;

/// The action phase could not pay for what the compute phase asked it to send.
const NOT_ENOUGH_FUNDS: i32 = 37;

/// The action phase refused the account state the compute phase produced.
const EXCEEDED_LIMITS: i32 = 50;

/// A deposit that would fit its ceiling, with plenty of funding.
fn deposit_body(seed: u8) -> chain_block::Cell {
    let payload: Vec<u8> =
        (0..wire::OUTPUT_DATA_BYTES as u32).map(|index| (index as u8) ^ seed).collect();
    Pool::deposit_body(
        DENOMINATION,
        Fr::from(0x4321_0000u64 + u64::from(seed)),
        byte_chain(&payload).expect("payload"),
    )
    .expect("deposit body")
}

/// A pool with one deposit already in it, so every persistent field has
/// something in it that a half-finished transaction could disturb.
fn pool_with_history() -> (Pool, PoolState) {
    let mut pool = Pool::deploy().expect("deploy the pool");
    pool.send(DENOMINATION + COMPUTE_FEE, deposit_body(0x11))
        .expect("first deposit")
        .expect_success();
    let state = pool.state_snapshot().expect("the state");
    (pool, state)
}

/// Out of gas part-way through a deposit.
///
/// The chain is made to grant less than the path needs, which is the one
/// thing a contract cannot work around: `SETGASLIMIT` may lower the limit it
/// was given and never raise it. This is not a hypothetical configuration --
/// it is what a basechain granting a million gas would do to this contract.
///
/// What holds here is not the contract's write-once discipline. A compute
/// phase that ends in an exception hands back no new data at all, so there is
/// nothing for the action phase to commit even when it is made to run. That
/// was established by removing the `phase.success` guard in
/// `ordinary_transaction.rs` and watching this stay green, which is why there
/// is no mutation aimed at it: the guarantee is the VM's and no line of this
/// repository's contract or executor flow can take it away. The control below
/// is what keeps the test from passing because the deposit never ran.
#[test]
fn a_deposit_that_runs_out_of_gas_changes_nothing() {
    // The control: the same deposit, given the gas it needs, does change the
    // state. Without this the assertion below would hold for a message that
    // was rejected before it started.
    let (mut control, before_control) = pool_with_history();
    let (exit, _) =
        control.run(DENOMINATION + COMPUTE_FEE, deposit_body(0x22)).expect("control deposit");
    assert_eq!(exit, 0, "the control deposit was refused");
    assert_ne!(
        control.state_snapshot().expect("the state"),
        before_control,
        "the control deposit changed nothing, so this test cannot tell a rollback from a no-op"
    );

    let (mut pool, before) = pool_with_history();
    // Comfortably past the parsing and into the tree work, and comfortably
    // short of the 147,595 a deposit needs.
    pool.bc.set_workchain_gas_limit(80_000);

    let (exit, gas) = pool.run(DENOMINATION + COMPUTE_FEE, deposit_body(0x22)).expect("deposit");
    assert_eq!(exit, OUT_OF_GAS, "the deposit did not run out of gas: exit {exit} at {gas} gas");
    assert_eq!(
        pool.state_snapshot().expect("the state"),
        before,
        "a deposit that ran out of gas left the state changed"
    );
}

/// The same for a transact, which is the path with something to lose: it
/// preserves an anchor, appends three leaves and inserts two nullifiers
/// before it writes anything.
#[test]
fn a_transact_that_runs_out_of_gas_changes_nothing() {
    let outcome = support::run(&Withdrawal {
        denominations: &[DENOMINATION],
        amount: DENOMINATION,
        destination_name: "oog_refuser",
        destination_source: support::REFUSER,
        age: None,
        before_transact: Perturbation { gas_limit: Some(900_000), ..Default::default() },
    });
    assert_eq!(
        outcome.exit, OUT_OF_GAS,
        "the withdrawal did not run out of gas: exit {}",
        outcome.exit
    );
    assert_eq!(
        outcome.state_after, outcome.state_before,
        "a transact that ran out of gas left the state changed"
    );

    // The same control as the deposit's: the path does change the state when
    // it is allowed to finish.
    let control = support::run(&Withdrawal {
        denominations: &[DENOMINATION],
        amount: DENOMINATION,
        destination_name: "oog_refuser",
        destination_source: support::REFUSER,
        age: None,
        before_transact: Default::default(),
    });
    assert_eq!(control.exit, 0, "the control withdrawal was refused");
    assert_ne!(
        control.state_after, control.state_before,
        "the control withdrawal changed nothing, so this test proves nothing about a rollback"
    );
}

/// The action phase failing after the compute phase has written the state.
///
/// A withdrawal reserves what the pool still owes and then sends the payout,
/// so the action phase needs the reserve *and* the payout. The compute phase
/// checks only the reserve, because the reserve is what it is responsible
/// for. A pool holding enough for the first and not the second gets all the
/// way through compute -- anchor preserved, three leaves appended, two
/// nullifiers inserted, `set_data` run -- and then cannot pay.
///
/// Which of the two actions fails is not reported by the transaction, so it
/// is established by bracketing instead: the two runs below differ only in
/// the balance, the reserve they ask for is identical, and one of them pays.
#[test]
fn a_withdrawal_whose_payout_cannot_be_sent_changes_nothing() {
    // Two deposits of one denomination, one withdrawn, the fee kept: what the
    // pool still owes once the payout leaves, which is what it reserves.
    // The floor comes from the deployment parameters rather than a literal:
    // this line said `+ 5 * TOS` until the floor was re-derived, and the
    // control run then held less than the reserve it was meant to prove
    // sufficient.
    let floor = u64::try_from(shielded_pool_genesis::RESERVE_FLOOR).expect("the floor fits");
    let reserved = 2 * DENOMINATION - DENOMINATION - WITHDRAWAL_FEE + floor;
    // The transact brings its own value, credited before compute reads the
    // balance, so the account is set to the difference.
    let sent = 1_000_000_000u64;

    let drained = |at_compute: u64| {
        support::run(&Withdrawal {
            denominations: &[DENOMINATION],
            amount: DENOMINATION,
            destination_name: "drained_accepter",
            destination_source: support::ACCEPTER,
            age: None,
            before_transact: Perturbation {
                balance: Some(at_compute - sent),
                value: Some(sent),
                gas_limit: None,
            },
        })
    };

    // Enough for the reserve and the payout both.
    let paid = drained(reserved + DENOMINATION + TOS);
    assert_eq!(paid.exit, 0, "the control withdrawal was refused in compute");
    assert!(
        !paid.aborted,
        "a pool holding the reserve and the payout still could not pay: action {:?}",
        paid.action
    );

    // Enough for the reserve and the payout to the nanoton, and therefore not
    // enough, because the gas the compute phase burned has to come out of the
    // same balance. Whatever that gas costs, the payout is short by exactly
    // it.
    //
    // This used to be a round 7 TOS, which worked only while the gas happened
    // to cost more than the 50 millitos of slack that left. It stopped
    // working the moment the basechain gas price was cut, and a test that
    // depends on the price to express "not quite enough" is measuring the
    // price. Written this way there is no window to fall out of.
    let unpaid = drained(reserved + DENOMINATION);
    assert_eq!(
        unpaid.exit, 0,
        "the compute phase did not get through, so this is not the action-phase failure it was \
         meant to be"
    );
    assert_eq!(
        unpaid.action,
        Some(NOT_ENOUGH_FUNDS),
        "the action phase failed for some reason other than the money: {:?}",
        unpaid.action
    );
    assert!(unpaid.aborted, "the transaction was not rolled back");
    assert_eq!(
        unpaid.state_after, unpaid.state_before,
        "a withdrawal whose payout could not be sent left the state changed: the pool spent \
         two notes and never paid anybody"
    );
    assert_eq!(
        unpaid.pool_liability_after, unpaid.pool_liability_before,
        "the liability moved although nothing left the pool"
    );
}

/// The action phase refusing the state the compute phase produced.
///
/// Nothing the contract does can keep its state under a limit the chain
/// lowers underneath it, so this is the one failure the compute phase cannot
/// see coming: it succeeds, writes, and is overruled.
#[test]
fn a_deposit_refused_by_the_state_limit_changes_nothing() {
    // The control first. Without it, a test that ends with "the state did not
    // change" would pass just as well if the deposit had never been sent.
    let (mut control, before_control) = pool_with_history();
    let phases = control.run_phases(DENOMINATION + COMPUTE_FEE, deposit_body(0x33)).expect("run");
    assert_eq!(phases.compute, 0, "the control deposit did not get through the compute phase");
    assert!(!phases.aborted, "the control deposit was rolled back");
    assert_ne!(
        control.state_snapshot().expect("the state"),
        before_control,
        "the control deposit changed nothing, so this test cannot tell a rollback from a no-op"
    );

    let (mut pool, before) = pool_with_history();
    let mut limits = SizeLimitsConfig::default();
    limits.max_acc_state_cells = 1;
    pool.bc.set_size_limits_config(limits).expect("lower the state limit");

    let phases = pool.run_phases(DENOMINATION + COMPUTE_FEE, deposit_body(0x33)).expect("run");
    assert_eq!(
        phases.compute, 0,
        "the compute phase did not finish, so the state limit is not what refused this"
    );
    assert_eq!(
        phases.action,
        Some(EXCEEDED_LIMITS),
        "the action phase failed for some reason other than the state limit: {:?}",
        phases.action
    );
    assert!(phases.aborted, "a state the chain refused to store was kept anyway");
    assert_eq!(
        pool.state_snapshot().expect("the state"),
        before,
        "a deposit the chain refused to store left the state changed"
    );
}
