/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! How much of the pool's own tree work is Poseidon2 and how much is TVM.
//!
//! This is not a question about proof systems. Both of the pool's trees are
//! walked by FunC loops that hash with Poseidon2 and carry the result through
//! cells and dictionaries, and the measurement that showed a STARK's Merkle
//! path to be seven eighths bookkeeping applies here unchanged.
//!
//! The permutation counts are measured rather than read off the source, by
//! the method the Poseidon2 tariff work used: build the VM at a different
//! price, re-run, and divide the difference. Set `TOS_POSEIDON2_PRICE` to the
//! price the VM was built with.

use ark_ff::{BigInteger, PrimeField};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::imt;
use shielded_pool_circuit_crosscheck::frontier_probe::FrontierProbe;
use shielded_pool_circuit_crosscheck::imt_probe::ImtProbe;

/// Measured by re-running against a VM built at 4,500 and dividing the
/// difference by a thousand. Pinned so a change to either tree makes the
/// arithmetic below go red rather than quietly stale.
///
/// Unchanged by global version 18: POSEIDON2_PATH7 does the same permutations
/// the FunC loop did. What it removed is everything around them.
const IMT_PERMUTATIONS: i64 = 51;
const APPEND_PERMUTATIONS: i64 = 12;

/// Measured when the ceilings were set: a whole withdrawal, and the
/// permutations it executes.
const WITHDRAWAL_GAS: i64 = 1_175_034;
const WITHDRAWAL_PERMUTATIONS: i64 = 142;

fn poseidon2_price() -> i64 {
    std::env::var("TOS_POSEIDON2_PRICE").ok().and_then(|v| v.parse().ok()).unwrap_or(2_800)
}

fn dec(value: Fr) -> String {
    let digits = value.into_bigint().to_bytes_be();
    let mut n = 0u128;
    for byte in digits.iter().rev().take(16).rev() {
        n = n.wrapping_mul(256).wrapping_add(u128::from(*byte));
    }
    n.to_string()
}

fn percent(part: i64, whole: i64) -> i64 {
    part * 100 / whole
}

#[test]
fn what_the_pools_trees_spend_on_hashing() {
    let price = poseidon2_price();

    let probe = ImtProbe::deploy().expect("deploy the IMT probe");
    let mut state = imt::State::genesis();
    let root = probe.genesis_root().expect("the genesis root");
    let nullifier = Fr::from(0x7777_8888_9999_aaaau64);
    let (witness, _) = state.witness_for(&nullifier).expect("a witness");
    let insert = probe
        .insert_gas(&root, state.next_index, &dec(nullifier), &witness)
        .expect("one insert");

    let frontier = FrontierProbe::deploy().expect("deploy the frontier probe");
    let append_fresh = frontier.append_gas(2).expect("an append near genesis");
    let append_worst = frontier.append_gas(2 * 1_977_326_743 - 1).expect("the worst append");

    eprintln!("at a Poseidon2 price of {price}:");
    for (name, gas, permutations) in [
        ("one imt_insert", insert, IMT_PERMUTATIONS),
        ("one frontier_append, near genesis", append_fresh, APPEND_PERMUTATIONS),
        ("one frontier_append, worst index", append_worst, APPEND_PERMUTATIONS),
    ] {
        let hashing = permutations * price;
        eprintln!(
            "  {name:<34} {gas:>7} gas = {hashing:>6} hashing ({:>2}%) + {:>6} bookkeeping ({:>2}%)",
            percent(hashing, gas),
            gas - hashing,
            percent(gas - hashing, gas)
        );
    }

    // What one transaction spends on its two trees: two nullifier inserts
    // and three leaf appends.
    let tree_gas = 2 * insert + 3 * append_fresh;
    let tree_permutations = 2 * IMT_PERMUTATIONS + 3 * APPEND_PERMUTATIONS;
    let bookkeeping = tree_gas - tree_permutations * price;

    eprintln!();
    eprintln!("a transact walks both trees: two inserts and three appends.");
    eprintln!(
        "  {tree_gas} gas, {}% of a whole withdrawal",
        percent(tree_gas, WITHDRAWAL_GAS)
    );
    eprintln!("  hashing      {}", tree_permutations * price);
    eprintln!(
        "  bookkeeping  {bookkeeping}, {}% of a whole withdrawal",
        percent(bookkeeping, WITHDRAWAL_GAS)
    );
    eprintln!();
    eprintln!(
        "  the trees are {tree_permutations} of the transaction's {WITHDRAWAL_PERMUTATIONS} \
         permutations, so there is almost no hashing anywhere else"
    );

    // A cross-check between two measurements taken for different reasons: if
    // the trees claimed more permutations than the whole transaction
    // executes, one of them would be wrong.
    assert!(
        tree_permutations <= WITHDRAWAL_PERMUTATIONS,
        "the trees claim {tree_permutations} permutations against the transaction's \
         {WITHDRAWAL_PERMUTATIONS}, so one of the two measurements is wrong"
    );
    // This assertion used to read the other way. It said that if bookkeeping
    // ever fell below a quarter of the tree work, the case for a native path
    // instruction had weakened and should be re-argued. At global version 18
    // it did fall, because the instruction landed: an insert went from 52%
    // bookkeeping to 10%, and a withdrawal from 1,565,609 gas to 1,222,791.
    //
    // What is left is the commitment tree, whose overhead is dictionary work
    // that POSEIDON2_PATH7 does not touch. So the guard now points the other
    // way: if the nullifier tree ever goes back to spending most of its gas on
    // bookkeeping, something has undone the instruction.
    assert!(
        insert - IMT_PERMUTATIONS * price < insert / 4,
        "an imt_insert is back to spending {} of {insert} gas on bookkeeping, which is what \
         POSEIDON2_PATH7 was added to remove",
        insert - IMT_PERMUTATIONS * price
    );
}
