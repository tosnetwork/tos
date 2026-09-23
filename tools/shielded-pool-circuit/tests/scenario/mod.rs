/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Test-side wrappers around the library's scenario builder: the constraint
//! system helpers, and `Result` unwrapped into a failure the runner reports.

#![allow(dead_code, unused_imports)]

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

use shielded_pool_circuit::circuit::{
    HeldNote, OutputNote, Relations, ShieldedTransactionCircuit, TransactionWitness,
};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::public_inputs::PublicInputs;
use shielded_pool_circuit::scenario;

pub use shielded_pool_circuit::scenario::{amount, execution_domain, reseal, Pool, PublicTerms};

pub fn deposit(pool: &mut Pool, value: Fr) -> (HeldNote, Fr) {
    match pool.deposit(value) {
        Ok(result) => result,
        Err(error) => panic!("deposit: {error}"),
    }
}

pub fn transaction(
    pool: &mut Pool,
    held: [HeldNote; 2],
    input_pq: [Fr; 2],
    outputs: [OutputNote; 3],
    terms: PublicTerms,
) -> (PublicInputs, TransactionWitness) {
    match scenario::transaction(pool, held, input_pq, outputs, terms) {
        Ok(pair) => pair,
        Err(error) => panic!("building the transaction: {error}"),
    }
}

pub fn valid_transfer() -> (Pool, PublicInputs, TransactionWitness) {
    match scenario::valid_transfer() {
        Ok(result) => result,
        Err(error) => panic!("valid transfer: {error}"),
    }
}

pub fn valid_withdrawal() -> (Pool, PublicInputs, TransactionWitness) {
    match scenario::valid_withdrawal() {
        Ok(result) => result,
        Err(error) => panic!("valid withdrawal: {error}"),
    }
}

/// Synthesises the circuit and reports whether the R1CS is satisfied.
pub fn satisfied(
    public: &PublicInputs,
    witness: &TransactionWitness,
    relations: Relations,
) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = ShieldedTransactionCircuit::for_removal_test(*public, witness.clone(), relations);
    if let Err(error) = circuit.generate_constraints(cs.clone()) {
        panic!("synthesis failed: {error}");
    }
    match cs.is_satisfied() {
        Ok(state) => state,
        Err(error) => panic!("constraint evaluation failed: {error}"),
    }
}

/// The number of constraints the full circuit generates.
pub fn constraint_count(public: &PublicInputs, witness: &TransactionWitness) -> usize {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = ShieldedTransactionCircuit::new(*public, witness.clone());
    if let Err(error) = circuit.generate_constraints(cs.clone()) {
        panic!("synthesis failed: {error}");
    }
    cs.num_constraints()
}
