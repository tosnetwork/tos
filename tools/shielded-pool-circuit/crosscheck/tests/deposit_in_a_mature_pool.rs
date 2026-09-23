/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! A deposit fits its gas ceiling at every age a pool can reach.
//!
//! The ceilings were first set from measurements taken against a pool that
//! had just been deployed, and that is the cheapest the contract will ever
//! be. Three of its costs grew with history:
//!
//!   * `frontier_append` read `digit + 1` slots at level `l`, and the digits
//!     are the leaf index in base seven -- twelve reads in total near
//!     genesis, seventy-nine at the worst index. This one is gone: since
//!     2026-09-21 the store is a level chain that reads all seven slots of
//!     every level whatever the index, and costs slightly *less* as the index
//!     grows. The term is still measured below, because a term that has gone
//!     to zero is a claim like any other;
//!   * `anchors_preserve` writes into a 4,096-slot ring that is empty at
//!     genesis and full after an hour of traffic;
//!   * a proof against a recent root reads that ring, which a harness proving
//!     against the current root never does.
//!
//! Against the first set of ceilings a pool refused its thirty-fifth deposit.
//! This test deploys the shipping contract, moves its state to where a pool
//! with history would be, and sends the same deposit message -- so that a
//! ceiling can never again be set from the best case alone.

use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit_crosscheck::anchor_probe::{AnchorProbe, EPOCH_SLOTS, RECENT_SLOTS};
use shielded_pool_circuit_crosscheck::frontier_probe::FrontierProbe;
use shielded_pool_circuit_crosscheck::pool::{Pool, DENOMINATION};

/// The ceiling frozen into the contract for a deposit, read from it rather
/// than copied: a test that keeps its own copy checks the copy.
fn deposit_gas_ceiling() -> i64 {
    shielded_pool_circuit_crosscheck::pool::contract_gas_ceiling("deposit_gas_ceiling")
        .expect("the contract's deposit ceiling")
}

/// Far more than the deposit may spend, so the ceiling is what stops it and
/// not the message's own gas credit.
const COMPUTE_FEE: u64 = 2_000_000_000;

/// The index with the largest digit sum any pool can reach: one, then eleven
/// sixes in base seven.
const WORST_INDEX: u64 = 2 * 1_977_326_743 - 1;

/// How far the scan for a refused deposit goes.
const SCAN_LIMIT: u64 = 400;

/// The exit code and gas of one deposit into a pool at that age.
fn deposit(index: u64, recent: u64, epoch: u64) -> (i32, i64) {
    let frontier = FrontierProbe::deploy().expect("frontier probe").fill(index).expect("frontier");
    let anchors = AnchorProbe::deploy().expect("anchor probe").fill(recent, epoch).expect("anchors");
    deposit_against(index, frontier, anchors)
}

/// The same deposit, against a frontier and an anchor store already built.
/// Filling a ring takes more than a hundred calls, so a scan that rebuilt it
/// every step would be measuring the harness.
fn deposit_against(index: u64, frontier: chain_block::Cell, anchors: chain_block::Cell) -> (i32, i64) {
    // The deployed denomination list, not the one denomination most tests
    // use: the contract walks the list to validate the amount, so a maximum
    // measured against a shorter list is a maximum for a pool nobody deploys.
    let mut pool = Pool::deploy_with_denominations(
        &shielded_pool_circuit_crosscheck::pool::DEPLOYED_DENOMINATIONS,
    )
    .expect("deploy the pool");
    pool.age_to(index, frontier, anchors).expect("age the pool");

    let body = Pool::deposit_body(
        DENOMINATION,
        Fr::from(0x1234_5678u64),
        shielded_pool_circuit_crosscheck::wire::byte_chain(&vec![
            0x5eu8;
            shielded_pool_circuit::wire::OUTPUT_DATA_BYTES
        ])
        .expect("a payload"),
    )
    .expect("deposit body");
    pool.run(DENOMINATION + COMPUTE_FEE, body).expect("send the deposit")
}

#[test]
fn a_deposit_fits_its_ceiling_at_every_age() {
    let ceiling = deposit_gas_ceiling();
    let (exit, fresh) = deposit(1, 0, 0);
    eprintln!("index 1, empty rings: exit {exit}, {fresh} gas");
    assert_eq!(exit, 0, "the deposit a fresh pool takes is the baseline and it has to succeed");

    let mut worst = fresh;
    for (name, index) in [
        ("fresh frontier, full rings", 1),
        ("a thousand notes", 1_000),
        ("ten thousand notes", 10_000),
        ("a million notes", 1_000_000),
        ("the worst index", WORST_INDEX),
    ] {
        let (exit, gas) = deposit(index, RECENT_SLOTS, EPOCH_SLOTS);
        eprintln!("{name} (index {index}): exit {exit}, {gas} gas");
        assert_eq!(
            exit, 0,
            "a deposit at index {index} was refused with exit {exit}: the ceiling of {ceiling} \
             does not cover this pool's age"
        );
        worst = worst.max(gas);
    }

    eprintln!("the worst deposit measured: {worst} gas, ceiling {ceiling}");
    assert!(
        worst * 5 <= ceiling * 4,
        "the worst deposit is {worst} gas and the ceiling {ceiling}, which is less than the \
         quarter above the maximum that section 14 asks for"
    );
}

/// No pool size refuses a deposit.
///
/// The cost used to follow the base-seven digit sum of the leaf index, which
/// is not monotone, so this scans rather than bisects. It is the test that
/// went red first when the ceilings were set from a fresh pool: the
/// thirty-fifth deposit was refused. The scan is kept now that the store no
/// longer grows, because what it asserts -- that no reachable size is
/// refused -- is the claim, and the shape of the cost curve is an argument
/// about why, not a substitute for it.
#[test]
fn no_pool_size_refuses_a_deposit() {
    let frontier_probe = FrontierProbe::deploy().expect("frontier probe");
    let anchors = AnchorProbe::deploy()
        .expect("anchor probe")
        .fill(RECENT_SLOTS, EPOCH_SLOTS)
        .expect("full rings");

    for index in 1..=SCAN_LIMIT {
        let frontier = frontier_probe.fill(index).expect("frontier");
        let (exit, gas) = deposit_against(index, frontier, anchors.clone());
        assert_eq!(
            exit, 0,
            "a pool that has taken {index} notes cannot take another: exit {exit} at {gas} gas"
        );
    }
    eprintln!("every pool size up to {SCAN_LIMIT} notes takes another deposit");
}

/// The two causes, separated, and the arithmetic that adds them checked.
///
/// A ceiling cannot be repaired by guessing how much the unmeasured terms are
/// worth. This measures each one on its own and then checks that a deposit at
/// a given age really does cost the baseline plus both -- because that is
/// what makes a probe's number usable when an end-to-end run is too
/// expensive to build.
#[test]
fn the_two_causes_add_up() {
    let frontier_probe = FrontierProbe::deploy().expect("frontier probe");
    let anchor_probe = AnchorProbe::deploy().expect("anchor probe");
    let empty = anchor_probe.fill(0, 0).expect("empty rings");
    let full = anchor_probe.fill(RECENT_SLOTS, EPOCH_SLOTS).expect("full rings");

    let base = deposit_against(1, frontier_probe.fill(1).expect("frontier"), empty.clone()).1;
    let rings_only = deposit_against(1, frontier_probe.fill(1).expect("frontier"), full).1;
    eprintln!("the anchor rings alone add {} gas", rings_only - base);

    for index in [1u64, 34, 1_000, 100_000, WORST_INDEX] {
        let measured =
            deposit_against(index, frontier_probe.fill(index).expect("frontier"), empty.clone());
        let predicted = base
            + frontier_probe.append_gas(index).expect("append")
            - frontier_probe.append_gas(1).expect("append");
        eprintln!(
            "index {index} (digit sum {}): {} gas measured, {predicted} predicted, exit {}",
            frontier_probe.digit_sum(index).expect("digit sum"),
            measured.1,
            measured.0,
        );
        assert_eq!(measured.0, 0, "the empty-ring deposit at index {index} should fit");
        let error = (measured.1 - predicted).abs();
        assert!(
            error <= 600,
            "the frontier term does not account for the growth at index {index}: {} measured \
             against {predicted} predicted, {error} apart. Anything that rests on this addition \
             has to be redone from measurements at each age instead.",
            measured.1
        );
    }
}
