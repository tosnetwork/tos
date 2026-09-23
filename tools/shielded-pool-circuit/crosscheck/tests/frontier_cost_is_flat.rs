/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! An append costs about the same at every leaf index, and never more than at
//! genesis. The transact ceiling is set on the strength of that.
//!
//! It did not always. Under the HashmapE the frontier used to live in, level
//! `l` read slots `0..digit_l` and the digits were the leaf index in base
//! seven: one slot a level at index 2, seventy-nine slots in total at index
//! 3,954,653,485. A harness that deposits twice and withdraws once measured
//! the cheapest append the contract had and called the result a maximum, and
//! the pool that came out of it refused its thirty-fifth deposit.
//!
//! The level chain reads and rebuilds all seven slots of every level whatever
//! the digits are, so there is no age left to under-measure: measured, it
//! runs from 127,412 gas at genesis down to 123,544 at the worst index, where
//! the dictionary ran from 108,544 up to 172,192. That is a property a
//! ceiling now depends on, so it is asserted here rather than believed: the
//! dictionary is still in the probe, and this shows the probe can tell
//! indices apart on the container that does grow before concluding that the
//! one in the contract does not.

use shielded_pool_circuit_crosscheck::frontier_probe::FrontierProbe;

/// The largest digit sum any legal index has: one, then eleven sixes.
const WORST_INDEX: u64 = 2 * 1_977_326_743 - 1;

/// Indices the withdrawal harness actually appends at.
const HARNESS_INDEX: u64 = 2;

#[test]
fn an_append_costs_the_same_however_full_the_tree_is() {
    let probe = FrontierProbe::deploy().expect("deploy the frontier probe");

    assert_eq!(probe.digit_sum(0).expect("digit sum"), 0, "index zero has no digits set");
    assert_eq!(
        probe.digit_sum(WORST_INDEX).expect("digit sum"),
        67,
        "no legal index has a larger digit sum, so none read more slots"
    );

    for (name, index) in [
        ("genesis", 0u64),
        ("one", 1),
        ("harness", HARNESS_INDEX),
        ("million", 1_000_000),
        ("billion", 1_000_000_000),
        ("worst", WORST_INDEX),
    ] {
        eprintln!(
            "append at {name} (index {index}, digit sum {}): {} gas, dictionary {} gas",
            probe.digit_sum(index).expect("digit sum"),
            probe.append_gas(index).expect("append gas"),
            probe.dict_append_gas(index).expect("dictionary append gas"),
        );
    }

    // First that the probe can tell two indices apart at all. It can: the
    // dictionary it still carries costs measurably more at the worst index,
    // and that is the same probe, the same fill, the same call.
    let dict_harness = probe.dict_append_gas(HARNESS_INDEX).expect("dictionary append");
    let dict_worst = probe.dict_append_gas(WORST_INDEX).expect("dictionary append");
    assert!(
        dict_worst > dict_harness,
        "the probe reports the same dictionary cost at index {HARNESS_INDEX} and index \
         {WORST_INDEX} ({dict_harness} gas), so it is not measuring the append and the flatness \
         it reports below means nothing"
    );

    // Then that the contract's store does not move. Genesis is included
    // because it is the one state a deployed pool is guaranteed to pass
    // through, and the store it is deployed with is built by the contract,
    // not by the probe's fill.
    let at_genesis = probe.append_gas(0).expect("append at genesis");
    let at_harness = probe.append_gas(HARNESS_INDEX).expect("append where the harness measures");
    let at_worst = probe.append_gas(WORST_INDEX).expect("append at the worst index");
    let spread = (at_worst - at_genesis).abs() * 100 / at_genesis;
    eprintln!(
        "genesis {at_genesis}, harness {at_harness}, worst {at_worst}: {spread}% across the range"
    );
    // It is not quite flat, and it falls rather than rises: a high digit
    // takes a stored slot where a low one takes `empty_root_at`, and that is
    // an if-ladder. So the most expensive append a pool can ever do is its
    // first, which is the one every harness measures anyway. That is the
    // property the ceiling rests on -- not that the cost is constant, but
    // that the measurable end of the range is the dear one.
    assert!(
        at_worst <= at_genesis,
        "an append at the worst index ({at_worst}) now costs more than at genesis \
         ({at_genesis}): the transact ceiling is set from a measurement taken at genesis and \
         would have to carry an age margin again"
    );
    assert!(
        spread < 5,
        "the append's cost moved {spread}% across the index range ({at_genesis} at genesis, \
         {at_worst} at the worst index); it was three, so the store's shape has changed"
    );

    // And that the probe's fill is never cheaper than the store a pool is
    // really deployed with.
    //
    // It is not equal to it, and the difference is worth keeping in view. The
    // genesis store is all zeros, so its twelve tail cells are byte-identical
    // and the VM charges for loading one of them once; a filled store's tail
    // cells all differ. That is the whole of the gap -- the same fill with
    // its values zeroed costs what the deployed store costs -- and it means
    // the fill is the conservative side of the two, which is the side a
    // ceiling wants.
    let deployed = probe.genesis_append_gas().expect("the first append a pool ever does");
    let zeroed = probe.zeroed_append_gas(0).expect("the same append against a zeroed store");
    eprintln!(
        "the deployed store costs {deployed}, the same shape zeroed {zeroed}, the probe's fill \
         {at_genesis}"
    );
    assert_eq!(
        deployed, zeroed,
        "the store section 13.2 deploys ({deployed}) and a zeroed store of the probe's own \
         shape ({zeroed}) no longer cost the same, so the probe is not building the shape the \
         contract deploys"
    );
    assert!(
        at_genesis >= deployed,
        "the probe's fill ({at_genesis}) is now cheaper than the store a pool is deployed with \
         ({deployed}), so every ceiling derived from it is derived from the cheap side"
    );
}
