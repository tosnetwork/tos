/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Range, non-zero and distinctness constraints.
//!
//! These are the constraints that stop a field element from being read as a
//! small number when it is not one. A field addition wraps; an amount that is
//! not range-checked can be negative in every sense that matters, and
//! conservation then balances a theft.

use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::SynthesisError;

use crate::field::Fr;
use crate::gadgets::poseidon2::FrVar;

/// Constrains `0 <= value < 2^bits` by decomposing it into exactly `bits`
/// booleans and requiring the recomposition to be the value itself.
///
/// Returns the bits, least significant first, so a caller that needs them
/// again does not pay for a second decomposition.
pub fn enforce_bit_width(value: &FrVar, bits: usize) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    if bits == 0 || bits >= Fr::MODULUS_BIT_SIZE as usize {
        return Err(SynthesisError::Unsatisfiable);
    }
    let cs = value.cs();
    let mut allocated: Vec<Boolean<Fr>> = Vec::with_capacity(bits);
    for index in 0..bits {
        allocated.push(Boolean::new_witness(cs.clone(), || {
            let assigned = value.value()?;
            let repr = assigned.into_bigint();
            Ok(repr.get_bit(index))
        })?);
    }

    let mut recomposed = FrVar::zero();
    let mut weight = Fr::ONE;
    let two = Fr::from(2u64);
    for bit in allocated.iter() {
        recomposed = &recomposed + &(&FrVar::from(bit.clone()) * &FrVar::Constant(weight));
        weight *= two;
    }
    recomposed.enforce_equal(value)?;
    Ok(allocated)
}

/// Constrains `value != 0` by exhibiting its inverse.
pub fn enforce_non_zero(value: &FrVar) -> Result<(), SynthesisError> {
    let cs = value.cs();
    let inverse = FrVar::new_witness(cs, || {
        let assigned = value.value()?;
        // An unsatisfiable system is the right answer for a zero value; the
        // inverse is only a hint, and the constraint below is what decides.
        Ok(assigned.inverse().unwrap_or(Fr::ZERO))
    })?;
    (value * &inverse).enforce_equal(&FrVar::one())
}

/// Constrains `value != 0` exactly when `condition` holds, and says nothing
/// about `value` otherwise.
pub fn conditionally_enforce_non_zero(
    value: &FrVar,
    condition: &Boolean<Fr>,
) -> Result<(), SynthesisError> {
    let cs = value.cs();
    let inverse = FrVar::new_witness(cs, || {
        // The hint has to follow the condition. Offering the true inverse
        // while the condition is clear would make the constraint below
        // unsatisfiable for any non-zero value, which would turn this into an
        // unconditional "value is zero" check from the prover's side: honest
        // witnesses would fail to prove and the relation under test would
        // never be the thing that decided the verdict.
        if condition.value()? {
            let assigned = value.value()?;
            Ok(assigned.inverse().unwrap_or(Fr::ZERO))
        } else {
            Ok(Fr::ZERO)
        }
    })?;
    // value * inverse == condition. With the condition set this forces a real
    // inverse and so a non-zero value; with it clear, inverse = 0 satisfies it
    // for any value.
    (value * &inverse).enforce_equal(&FrVar::from(condition.clone()))
}

/// Constrains `left != right`.
pub fn enforce_not_equal(left: &FrVar, right: &FrVar) -> Result<(), SynthesisError> {
    enforce_non_zero(&(left - right))
}
