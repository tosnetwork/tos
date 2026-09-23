/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The nullifier tree, modelled by the prover and enforced by the contract,
//! compared against each other in the VM.
//!
//! The circuit proves nothing about this tree -- section 7 is enforced on
//! chain. But a transaction cannot be submitted without two witnesses against
//! it, so the prover has to model it exactly, and a model that is only ever
//! checked against itself is not evidence. Here the contract is given the
//! witnesses the model built and asked whether they are good, and the roots
//! the two arrive at are compared.

use ark_ff::{BigInteger, PrimeField};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::imt;
use shielded_pool_circuit_crosscheck::imt_probe::ImtProbe;

fn dec(value: Fr) -> String {
    let bytes = value.into_bigint().to_bytes_be();
    let mut digits = vec![0u8];
    for byte in bytes {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let next = u32::from(*digit) * 256 + carry;
            *digit = (next % 10) as u8;
            carry = next / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

/// The empty ladder and the genesis root are the two constants everything
/// else is measured from, and the ladder is a different one from the
/// commitment tree's.
#[test]
fn the_empty_ladder_and_the_genesis_root_agree_with_the_vm() {
    let probe = ImtProbe::deploy().expect("deploy the IMT probe");
    let ladder = imt::empty_ladder();
    for (level, value) in ladder.iter().enumerate() {
        assert_eq!(dec(*value), probe.empty_at(level).expect("the vm"), "level {level}");
    }
    assert_eq!(
        dec(imt::State::genesis().root()),
        probe.genesis_root().expect("the vm"),
        "the genesis root is not the sentinel at leaf zero"
    );
}

/// Two nullifiers inserted in sequence, with the contract judging witnesses
/// the model built. The second witness is against the tree the first
/// insertion left, which is what section 16.2 step 10 means by sequential.
#[test]
fn the_contract_accepts_the_witnesses_this_model_builds() {
    let probe = ImtProbe::deploy().expect("deploy the IMT probe");
    let mut state = imt::State::genesis();
    let mut root = state.root();
    let mut next = state.next_index;

    for nullifier in [Fr::from(101u64), Fr::from(202u64), Fr::from(7u64), Fr::from(999u64)] {
        let (witness, after) = state.witness_for(&nullifier).expect("a witness");
        let (vm_root, vm_next) =
            probe.insert(&dec(root), next, &dec(nullifier), &witness).expect("the vm");
        state.apply(after);
        root = state.root();
        next = state.next_index;
        assert_eq!(
            vm_root,
            dec(root),
            "the contract and the model disagree on the root after inserting {}",
            dec(nullifier)
        );
        assert_eq!(vm_next, next, "the contract and the model disagree on the next index");
    }
}

/// The comparison can fail. A witness for the wrong nullifier is refused by
/// the contract rather than quietly folding to some other root.
#[test]
fn a_witness_the_model_did_not_build_for_this_nullifier_is_refused() {
    let probe = ImtProbe::deploy().expect("deploy the IMT probe");
    let state = imt::State::genesis();
    let root = dec(state.root());
    let (witness, _) = state.witness_for(&Fr::from(101u64)).expect("a witness");

    assert!(
        probe.insert(&root, state.next_index, &dec(Fr::from(101u64)), &witness).is_ok(),
        "the witness the model built for this nullifier was refused"
    );
    // The same witness, a different nullifier: the predecessor link no longer
    // brackets it.
    let refused = probe.insert(&root, state.next_index, &dec(Fr::from(5u64)), &witness);
    assert!(refused.is_err(), "a witness for another nullifier was accepted");
}

/// A nullifier already in the tree cannot be inserted twice, which is the
/// property the whole structure exists for.
#[test]
fn a_nullifier_already_in_the_tree_cannot_be_inserted_again() {
    let probe = ImtProbe::deploy().expect("deploy the IMT probe");
    let mut state = imt::State::genesis();
    let nullifier = Fr::from(101u64);
    let (witness, after) = state.witness_for(&nullifier).expect("a witness");
    probe.insert(&dec(state.root()), state.next_index, &dec(nullifier), &witness).expect("insert");
    state.apply(after);

    // The model cannot even build a witness that would pass: the predecessor
    // of a value already present is the leaf holding it, and its successor
    // link points at the value itself.
    let (again, _) = state.witness_for(&nullifier).expect("a witness");
    let refused = probe.insert(&dec(state.root()), state.next_index, &dec(nullifier), &again);
    assert!(refused.is_err(), "a nullifier was spent twice");
}
