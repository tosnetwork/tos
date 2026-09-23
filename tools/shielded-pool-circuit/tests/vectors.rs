/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The Poseidon2 gadget against the frozen known-answer vectors.
//!
//! The vectors were produced by executing the pinned upstream reference, which
//! is a third implementation: neither this crate nor the node wrote them. They
//! are the only thing standing behind the round structure. The parameter
//! manifest is not enough on its own: the permutation reads only the diagonal
//! of the internal matrix, so perturbing the rest of that matrix changes no
//! output, and dropping a partial round leaves the manifest untouched.
//!
//! Every table is checked twice: once out of circuit, and once with the
//! constraints actually generated and the system reported satisfied, so that a
//! gadget which computes the right value while constraining nothing is caught.

use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

use shielded_pool_circuit::field::{fr_from_be, fr_to_be, Fr};
use shielded_pool_circuit::gadgets::poseidon2 as gadget;
use shielded_pool_circuit::{domains, poseidon2, tree};

/// The frozen tables, read from the generated file in the tree rather than
/// copied here, so that a regenerated table is picked up automatically.
#[allow(dead_code)]
#[allow(clippy::all)]
mod kat {
    include!(concat!(env!("OUT_DIR"), "/poseidon2_kat_includable.rs"));
}

fn element(bytes: &[u8; 32]) -> Fr {
    match fr_from_be(bytes) {
        Ok(value) => value,
        Err(error) => panic!("frozen vector carries a non-canonical element: {error}"),
    }
}

fn new_cs() -> ConstraintSystemRef<Fr> {
    ConstraintSystem::<Fr>::new_ref()
}

fn witness(cs: &ConstraintSystemRef<Fr>, value: Fr) -> FpVar<Fr> {
    match FpVar::new_witness(cs.clone(), || Ok(value)) {
        Ok(var) => var,
        Err(error) => panic!("witness allocation failed: {error}"),
    }
}

fn satisfied(cs: &ConstraintSystemRef<Fr>) -> bool {
    match cs.is_satisfied() {
        Ok(state) => state,
        Err(error) => panic!("constraint system could not be evaluated: {error}"),
    }
}

#[test]
fn permutation_vectors_out_of_circuit() {
    let mut checked = 0usize;
    for (name, input, expected) in kat::PERM8.iter() {
        let state: [Fr; 8] = core::array::from_fn(|lane| element(&input[lane]));
        let produced = poseidon2::permute(&state);
        for lane in 0..8 {
            assert_eq!(
                fr_to_be(&produced[lane]),
                expected[lane],
                "permutation vector {name}, lane {lane}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 21, "the frozen table holds 21 permutation vectors");
    println!("out of circuit: {checked}/21 permutation vectors reproduced");
}

#[test]
fn hash_vectors_out_of_circuit() {
    let mut checked = 0usize;
    for (name, input, expected) in kat::HASH7.iter() {
        let domain = element(&input[0]);
        let inputs: [Fr; 7] = core::array::from_fn(|lane| element(&input[lane + 1]));
        let produced = poseidon2::hash7(domain, &inputs);
        assert_eq!(fr_to_be(&produced), *expected, "hash vector {name}");
        checked += 1;
    }
    assert_eq!(checked, 28, "the frozen table holds 28 hash vectors");
    println!("out of circuit: {checked}/28 hash vectors reproduced");
}

#[test]
fn permutation_vectors_in_circuit() {
    let mut checked = 0usize;
    for (name, input, expected) in kat::PERM8.iter() {
        let cs = new_cs();
        let state: [FpVar<Fr>; 8] =
            core::array::from_fn(|lane| witness(&cs, element(&input[lane])));
        let produced = match gadget::permute(&state) {
            Ok(produced) => produced,
            Err(error) => panic!("gadget failed on {name}: {error}"),
        };
        for lane in 0..8 {
            let target = witness(&cs, element(&expected[lane]));
            if let Err(error) = produced[lane].enforce_equal(&target) {
                panic!("equality constraint failed on {name}, lane {lane}: {error}");
            }
        }
        assert!(
            satisfied(&cs),
            "permutation vector {name} does not satisfy the generated constraints"
        );
        assert!(
            cs.num_constraints() > 0,
            "permutation vector {name} generated no constraints at all"
        );
        checked += 1;
    }
    assert_eq!(checked, 21);
    println!("in circuit: {checked}/21 permutation vectors satisfied the R1CS");
}

#[test]
fn hash_vectors_in_circuit() {
    let mut checked = 0usize;
    let mut constraints = 0usize;
    for (name, input, expected) in kat::HASH7.iter() {
        let cs = new_cs();
        let domain = witness(&cs, element(&input[0]));
        let inputs: [FpVar<Fr>; 7] =
            core::array::from_fn(|lane| witness(&cs, element(&input[lane + 1])));
        let produced = match gadget::hash7(&domain, &inputs) {
            Ok(produced) => produced,
            Err(error) => panic!("gadget failed on {name}: {error}"),
        };
        let target = witness(&cs, element(expected));
        if let Err(error) = produced.enforce_equal(&target) {
            panic!("equality constraint failed on {name}: {error}");
        }
        assert!(satisfied(&cs), "hash vector {name} does not satisfy the generated constraints");
        constraints = cs.num_constraints();
        checked += 1;
    }
    assert_eq!(checked, 28);
    println!(
        "in circuit: {checked}/28 hash vectors satisfied the R1CS ({constraints} constraints each)"
    );
}

/// The in-circuit permutation must reject a wrong claimed output, not merely
/// produce the right one. Without this the previous two tests would pass for a
/// gadget that allocates its answer as a free witness.
#[test]
fn a_wrong_claimed_output_is_unsatisfiable_in_circuit() {
    let (name, input, expected) = &kat::PERM8[0];
    let cs = new_cs();
    let state: [FpVar<Fr>; 8] = core::array::from_fn(|lane| witness(&cs, element(&input[lane])));
    let produced = match gadget::permute(&state) {
        Ok(produced) => produced,
        Err(error) => panic!("gadget failed on {name}: {error}"),
    };
    let mut wrong = *expected;
    wrong[0][31] ^= 0x01;
    let target = witness(&cs, element(&wrong[0]));
    if let Err(error) = produced[0].enforce_equal(&target) {
        panic!("equality constraint could not be added: {error}");
    }
    assert!(!satisfied(&cs), "a mutated expected output still satisfied the constraint system");
}

#[test]
fn domain_constants_match_the_frozen_table() {
    assert_eq!(kat::DOMAINS.len(), domains::LABELS.len());
    for (label, expected) in kat::DOMAINS.iter() {
        let derived = match domains::domain(label) {
            Some(value) => value,
            None => panic!("label {label} is not on the frozen list in this crate"),
        };
        assert_eq!(fr_to_be(&derived), *expected, "domain constant for {label}");
    }
    assert!(domains::no_domain_is_zero(), "a reserved domain constant reduced to zero");
}

#[test]
fn empty_roots_match_the_frozen_table() {
    let roots = tree::empty_roots();
    assert_eq!(roots.len(), kat::EMPTY_ROOTS.len());
    for (level, expected) in kat::EMPTY_ROOTS.iter().enumerate() {
        assert_eq!(
            fr_to_be(&roots[level]),
            *expected,
            "EMPTY_ROOT[{level}] of the 7-ary depth-12 tree"
        );
    }
}
