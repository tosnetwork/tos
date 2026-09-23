/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Poseidon2 t=8 inside the constraint system.
//!
//! Every linear step of the permutation is a linear combination and costs no
//! constraint. Every S-box is `x^5` and costs three: `x2 = x*x`,
//! `x4 = x2*x2`, `x5 = x4*x`. The structure is written from profile sections
//! 1.2 and 1.3, the same text the out-of-circuit half is written from, and the
//! two are held together only by the known-answer vectors.

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::SynthesisError;

use crate::field::Fr;
use crate::params::{params, ROUNDS_F_BEGINNING, ROUNDS_P, ROUNDS_TOTAL, STATE_WIDTH};

/// A field element inside the constraint system.
pub type FrVar = FpVar<Fr>;

/// `x^5`. Three multiplication constraints, no shortcuts.
fn sbox(x: &FrVar) -> Result<FrVar, SynthesisError> {
    let squared = x * x;
    let quartic = &squared * &squared;
    Ok(&quartic * x)
}

fn matmul_m4(x: &mut [FrVar]) {
    let t0 = &x[0] + &x[1];
    let t1 = &x[2] + &x[3];
    let t2 = &x[1] + &x[1] + &t1;
    let t3 = &x[3] + &x[3] + &t0;
    let t1_double = &t1 + &t1;
    let t4 = &t1_double + &t1_double + &t3;
    let t0_double = &t0 + &t0;
    let t5 = &t0_double + &t0_double + &t2;
    let t6 = &t3 + &t5;
    let t7 = &t2 + &t4;
    x[0] = t6;
    x[1] = t5;
    x[2] = t7;
    x[3] = t4;
}

fn matmul_external(state: &mut [FrVar; STATE_WIDTH]) {
    let (first, second) = state.split_at_mut(4);
    matmul_m4(first);
    matmul_m4(second);
    let stored: Vec<FrVar> = (0..4).map(|lane| &state[lane] + &state[4 + lane]).collect();
    for (lane, slot) in state.iter_mut().enumerate() {
        *slot = &*slot + &stored[lane % 4];
    }
}

fn matmul_internal(state: &mut [FrVar; STATE_WIDTH]) {
    let diag = &params().diag;
    let mut sum = state[0].clone();
    for value in state.iter().skip(1) {
        sum = &sum + value;
    }
    for (lane, slot) in state.iter_mut().enumerate() {
        *slot = &(&*slot * &FrVar::Constant(diag[lane])) + &sum;
    }
}

/// The frozen permutation over eight in-circuit field elements.
pub fn permute(input: &[FrVar; STATE_WIDTH]) -> Result<[FrVar; STATE_WIDTH], SynthesisError> {
    let constants = &params().round_constants;
    let mut state = input.clone();

    matmul_external(&mut state);

    for round in constants.iter().take(ROUNDS_F_BEGINNING) {
        for (lane, slot) in state.iter_mut().enumerate() {
            *slot = sbox(&(&*slot + &FrVar::Constant(round[lane])))?;
        }
        matmul_external(&mut state);
    }

    let partial_end = ROUNDS_F_BEGINNING.saturating_add(ROUNDS_P);
    for round in constants.iter().take(partial_end).skip(ROUNDS_F_BEGINNING) {
        state[0] = sbox(&(&state[0] + &FrVar::Constant(round[0])))?;
        matmul_internal(&mut state);
    }

    for round in constants.iter().take(ROUNDS_TOTAL).skip(partial_end) {
        for (lane, slot) in state.iter_mut().enumerate() {
            *slot = sbox(&(&*slot + &FrVar::Constant(round[lane])))?;
        }
        matmul_external(&mut state);
    }

    Ok(state)
}

/// `POSEIDON2_HASH7` inside the constraint system.
pub fn hash7(domain: &FrVar, inputs: &[FrVar; 7]) -> Result<FrVar, SynthesisError> {
    let mut state: [FrVar; STATE_WIDTH] = core::array::from_fn(|_| FrVar::zero());
    state[0] = domain.clone();
    for (slot, value) in state.iter_mut().skip(1).zip(inputs.iter()) {
        *slot = value.clone();
    }
    let permuted = permute(&state)?;
    match permuted.into_iter().next() {
        Some(output) => Ok(output),
        None => Err(SynthesisError::Unsatisfiable),
    }
}

/// `H7(label, a0..a6)`: the domain is a circuit constant, never a witness, so
/// a proof cannot choose its own domain separator.
pub fn h7(label: &str, inputs: &[FrVar; 7]) -> Result<FrVar, SynthesisError> {
    let domain = crate::domains::domain(label).ok_or(SynthesisError::AssignmentMissing)?;
    hash7(&FrVar::Constant(domain), inputs)
}
