/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Why the commitment tree's store is a level chain and not a dictionary.
//!
//! An append writes one slot a level and reads the slots below it, walking
//! levels zero to eleven in order. Nothing about that wants a sparse
//! dictionary, and the dictionary was what it cost: a write was 5,233 gas
//! against 2,800 for the permutation it carried.
//!
//! The contract now carries a level-ordered chain of cells, read and rebuilt
//! in the order the fold walks. The dictionary survives in the probe, and
//! this measures the same fold against both. If the two ever stop differing
//! the way the argument said they do, this fails, because the argument was a
//! comparison and a comparison is only as good as its last run.

use shielded_pool_circuit_crosscheck::frontier_probe::FrontierProbe;

/// The index with the largest digit sum any pool can reach.
const WORST_INDEX: u64 = 2 * 1_977_326_743 - 1;
/// Section 5's twelve levels, and the frozen tariff.
const DEPTH: i64 = 12;
const POSEIDON2: i64 = 2_800;

#[test]
fn a_level_ordered_store_against_the_dictionary() {
    let probe = FrontierProbe::deploy().expect("deploy the frontier probe");

    eprintln!("{:<18}{:>12}{:>12}{:>12}", "index", "dictionary", "chain", "saved");
    for (name, index) in
        [("genesis", 0u64), ("harness", 2), ("a million", 1_000_000), ("worst", WORST_INDEX)]
    {
        let dict = probe.dict_append_gas(index).expect("dictionary append");
        let chain = probe.append_gas(index).expect("chain append");
        eprintln!("{name:<18}{dict:>12}{chain:>12}{:>12}", dict - chain);
    }

    // What the hashing costs, which neither layout can avoid: it is the floor
    // both are being measured against.
    eprintln!();
    eprintln!("the {DEPTH} permutations either way: {}", DEPTH * POSEIDON2);

    // The claim, and it is not the one the prototype was written to make.
    //
    // A level-ordered store is not simply cheaper. It is *constant* -- about
    // 115,000 gas whatever the leaf index -- where the dictionary ran from
    // 108,923 at genesis to 172,571 at the worst index. So it is dearer for a
    // young pool and much cheaper for an old one, and they cross somewhere
    // around a hundred thousand notes.
    //
    // What decided the question is that a sender pre-pays the ceiling, and a
    // ceiling has to cover the worst age the pool can reach. Under the
    // dictionary every sender paid for a maturity most of them will never
    // see. Under a constant store there is no maturity to pay for.
    let worst_dict = probe.dict_append_gas(WORST_INDEX).expect("dictionary append");
    let worst_chain = probe.append_gas(WORST_INDEX).expect("chain append");
    let young_dict = probe.dict_append_gas(2).expect("dictionary append");
    let young_chain = probe.append_gas(2).expect("chain append");

    assert!(
        worst_chain < worst_dict,
        "the level-ordered store no longer wins at the worst index ({worst_chain} against \
         {worst_dict}), which is the only place the ceilings are set from"
    );
    assert!(
        young_chain > young_dict,
        "the level-ordered store is now cheaper at index 2 as well ({young_chain} against \
         {young_dict}); it reads and writes all seven slots a level whatever the digit, so if \
         that has stopped costing anything the store under test is not the one described here"
    );
    // Constant to within a few per cent across the whole index range, which is
    // the property the ceiling rests on, not the average.
    let spread = (worst_chain - young_chain).abs() * 100 / young_chain;
    eprintln!("the level chain varies by {spread}% from genesis to the worst index");
    assert!(spread < 5, "the level chain is no longer constant: {spread}% across the range");
}
