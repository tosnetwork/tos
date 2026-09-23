/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! What one Poseidon2 permutation costs in constraints, and therefore how
//! many of them the whole transaction circuit proves.
//!
//! The number matters outside this crate: a proof system is chosen partly by
//! how much work it is asked to do, and "18,107 constraints" says nothing
//! about that work until it is expressed in the primitive the circuit is
//! almost entirely made of.

use ark_r1cs_std::alloc::AllocVar;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::gadgets::poseidon2;

#[test]
fn one_permutation_and_the_whole_circuit() {
    let cs: ConstraintSystemRef<Fr> = ConstraintSystem::new_ref();
    let zero = ark_r1cs_std::fields::fp::FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64)))
        .expect("a witness");
    let state = core::array::from_fn(|_| zero.clone());
    let before = cs.num_constraints();
    let _ = poseidon2::permute(&state).expect("permute");
    let per_permutation = cs.num_constraints() - before;
    eprintln!("one Poseidon2 t=8 permutation: {per_permutation} constraints");
    assert!(per_permutation > 0, "the permutation generated no constraints");
    eprintln!(
        "the transaction circuit is 18107 constraints, which is about {} permutations",
        18107 / per_permutation.max(1)
    );
}
