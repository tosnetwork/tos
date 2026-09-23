/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Phase 2, first stage: the parameters a ceremony starts from.
//!
//! A circuit-specific setup is a linear map from the phase-1 reference string
//! to a proving key, and everything in that map except two scalars is fixed by
//! the circuit. Those two are `gamma` and `delta`, and the multi-party
//! computation is entirely about `delta`. So the ceremony begins with a key
//! built at `gamma = delta = 1`, which has **no secrets at all** -- it is a
//! deterministic function of the slice and the R1CS, and two people who run it
//! must get identical bytes.
//!
//! That is what makes this stage checkable in a way the contribution step is
//! not, and it is why it is built first.
//!
//! # The map
//!
//! `ark-groth16`'s QAP reduction evaluates every Lagrange coefficient at tau
//! and calls the vector `u`, so `u[j] = L_j(tau)`. Our [`LagrangeSrs`] holds
//! exactly that in the exponent. Every key element is therefore a
//! multiexponentiation of the QAP's scalars against a section of the slice:
//!
//! ```text
//!   A_v(tau)*G1         = sum_j A[j][v] * coeffs_g1[j]
//!   beta*A_v(tau)*G1    = sum_j A[j][v] * beta_coeffs_g1[j]
//!   alpha*B_v(tau)*G1   = sum_j B[j][v] * alpha_coeffs_g1[j]
//!   tau^i*t(tau)*G1     = h[i]
//! ```
//!
//! with `alpha*G1` and `beta*G1` recovered as the **sums** of their sections,
//! because `sum_j L_j(X) = 1` identically, so summing `alpha*L_j(tau)` gives
//! `alpha`.
//!
//! # The row that is easy to miss
//!
//! The domain is `constraints + instance_variables`, and the extra rows are
//! not padding: `instance_map_with_evaluation` seeds `a[v] = u[constraints +
//! v]` for every instance variable *before* adding any constraint's
//! contribution. Those are the input-consistency rows. They apply to `a`
//! alone -- not to `b`, not to `c` -- and leaving them out yields a key that
//! is the right shape, parses, and proves nothing.

use std::collections::BTreeMap;

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Zero;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};

use crate::error::{Error, Result};
use crate::lagrange::LagrangeSrs;

/// One variable's column of an R1CS matrix: which rows it appears in, and with
/// what coefficient.
///
/// The matrices are stored by row and every key element is a sum over rows for
/// a fixed variable, so the transpose is taken once rather than searched
/// repeatedly.
type Columns = Vec<Vec<(usize, Fr)>>;

fn transpose(rows: &[Vec<(Fr, usize)>], variables: usize) -> Columns {
    let mut columns: Vec<Vec<(usize, Fr)>> = vec![Vec::new(); variables];
    for (row, entries) in rows.iter().enumerate() {
        for (coefficient, variable) in entries {
            if let Some(column) = columns.get_mut(*variable) {
                column.push((row, *coefficient));
            }
        }
    }
    columns
}

/// `sum_j column[j] * basis[j]`, with the seed added first where there is one.
///
/// The seed is the input-consistency row: for an instance variable it is
/// `basis[constraints + v]`, and for everything else there is none.
fn combine_g1(
    basis: &[G1Affine],
    column: &[(usize, Fr)],
    seed: Option<usize>,
) -> Result<G1Projective> {
    let mut points: Vec<G1Affine> = Vec::with_capacity(column.len() + 1);
    let mut scalars: Vec<Fr> = Vec::with_capacity(column.len() + 1);
    if let Some(row) = seed {
        points.push(*basis.get(row).ok_or_else(|| {
            Error::Structure(format!("the basis has no row {row} for an input-consistency term"))
        })?);
        scalars.push(Fr::from(1u64));
    }
    for (row, coefficient) in column {
        points.push(*basis.get(*row).ok_or_else(|| {
            Error::Structure(format!("the basis has no row {row}, so the domain is too small"))
        })?);
        scalars.push(*coefficient);
    }
    if points.is_empty() {
        return Ok(G1Projective::zero());
    }
    G1Projective::msm(&points, &scalars)
        .map_err(|_| Error::Structure("a multiexponentiation failed".into()))
}

fn combine_g2(basis: &[G2Affine], column: &[(usize, Fr)]) -> Result<G2Projective> {
    let mut points: Vec<G2Affine> = Vec::with_capacity(column.len());
    let mut scalars: Vec<Fr> = Vec::with_capacity(column.len());
    for (row, coefficient) in column {
        points.push(*basis.get(*row).ok_or_else(|| {
            Error::Structure(format!("the basis has no row {row}, so the domain is too small"))
        })?);
        scalars.push(*coefficient);
    }
    if points.is_empty() {
        return Ok(G2Projective::zero());
    }
    G2Projective::msm(&points, &scalars)
        .map_err(|_| Error::Structure("a multiexponentiation failed".into()))
}

/// The R1CS this key is for, synthesised the way the setup synthesises it.
///
/// Setup mode with the constraint optimisation goal, because a circuit can
/// generate a different system under different goals and the key has to be for
/// the one the setup would build.
pub fn matrices<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
) -> Result<(ConstraintMatrices<Fr>, usize, usize)> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .map_err(|error| Error::Structure(format!("synthesising the circuit: {error}")))?;
    cs.finalize();
    let instance = cs.num_instance_variables();
    let witness = cs.num_witness_variables();
    let matrices = cs
        .to_matrices()
        .ok_or_else(|| Error::Structure("the constraint system has no matrices".into()))?;
    Ok((matrices, instance, witness))
}

/// The key a phase-2 ceremony starts from: `gamma = delta = 1`.
///
/// Deterministic. Given the same slice and the same circuit this returns the
/// same bytes, which is what lets a participant check the starting point
/// rather than accept it.
pub fn initial<C: ConstraintSynthesizer<Fr>>(
    srs: &LagrangeSrs,
    circuit: C,
) -> Result<ProvingKey<Bls12_381>> {
    let (matrices, instance, witness) = matrices(circuit)?;
    let constraints = matrices.num_constraints;
    let variables = instance + witness;

    let domain = constraints + instance;
    if srs.degree() < domain {
        return Err(Error::Structure(format!(
            "this circuit's QAP domain is {domain} and the reference string covers {}; it was \
             taken at too small an exponent",
            srs.degree()
        )));
    }
    if srs.degree() != srs.coeffs_g2.len() || srs.h.len() + 1 != srs.degree() {
        return Err(Error::Structure("the reference string's sections disagree in length".into()));
    }

    let a_columns = transpose(&matrices.a, variables);
    let b_columns = transpose(&matrices.b, variables);
    let c_columns = transpose(&matrices.c, variables);

    // The input-consistency seed, for instance variables only and for `a`
    // only.
    let seed = |variable: usize| -> Option<usize> {
        (variable < instance).then_some(constraints + variable)
    };

    let mut a_query = Vec::with_capacity(variables);
    let mut b_g1_query = Vec::with_capacity(variables);
    let mut b_g2_query = Vec::with_capacity(variables);
    // `(beta*A_v + alpha*B_v + C_v)` at tau, which becomes the IC for an
    // instance variable and the L query for a witness variable. With gamma and
    // delta both one there is nothing to divide by.
    let mut combined = Vec::with_capacity(variables);

    for variable in 0..variables {
        let a = &a_columns[variable];
        let b = &b_columns[variable];
        let c = &c_columns[variable];

        a_query.push(combine_g1(&srs.coeffs_g1, a, seed(variable))?);
        b_g1_query.push(combine_g1(&srs.coeffs_g1, b, None)?);
        b_g2_query.push(combine_g2(&srs.coeffs_g2, b)?);

        // beta*A_v uses the beta section with A's own scalars -- including the
        // input-consistency seed, because it is part of A_v.
        let beta_a = combine_g1(&srs.beta_coeffs_g1, a, seed(variable))?;
        let alpha_b = combine_g1(&srs.alpha_coeffs_g1, b, None)?;
        let plain_c = combine_g1(&srs.coeffs_g1, c, None)?;
        combined.push(beta_a + alpha_b + plain_c);
    }

    // `sum_j L_j(X) = 1`, so summing a section recovers the scalar that scales
    // it. This is the only place alpha and beta appear on their own.
    let alpha_g1: G1Projective =
        srs.alpha_coeffs_g1.iter().fold(G1Projective::zero(), |total, point| total + point);
    let beta_g1: G1Projective =
        srs.beta_coeffs_g1.iter().fold(G1Projective::zero(), |total, point| total + point);

    let a_query = G1Projective::normalize_batch(&a_query);
    let b_g1_query = G1Projective::normalize_batch(&b_g1_query);
    let b_g2_query = G2Projective::normalize_batch(&b_g2_query);
    let combined = G1Projective::normalize_batch(&combined);
    let (gamma_abc_g1, l_query) = combined.split_at(instance);

    let vk = VerifyingKey::<Bls12_381> {
        alpha_g1: alpha_g1.into_affine(),
        beta_g2: srs.beta_g2,
        // gamma = 1 and delta = 1. The ceremony's whole job is to replace
        // delta with something nobody knows.
        gamma_g2: G2Affine::generator(),
        delta_g2: G2Affine::generator(),
        gamma_abc_g1: gamma_abc_g1.to_vec(),
    };

    Ok(ProvingKey {
        vk,
        beta_g1: beta_g1.into_affine(),
        delta_g1: G1Affine::generator(),
        a_query,
        b_g1_query,
        b_g2_query,
        h_query: srs.h[..domain_h(srs)].to_vec(),
        l_query: l_query.to_vec(),
    })
}

/// The h query is one short of the domain, and the slice's is already exactly
/// that length -- stated rather than assumed, because a silent truncation here
/// would produce a key that proves nothing and says nothing.
fn domain_h(srs: &LagrangeSrs) -> usize {
    srs.h.len()
}

/// Which variables a key's queries are indexed by, for error messages and for
/// the tests that compare two constructions.
pub fn dimensions(key: &ProvingKey<Bls12_381>) -> BTreeMap<&'static str, usize> {
    BTreeMap::from([
        ("a_query", key.a_query.len()),
        ("b_g1_query", key.b_g1_query.len()),
        ("b_g2_query", key.b_g2_query.len()),
        ("h_query", key.h_query.len()),
        ("l_query", key.l_query.len()),
        ("ic", key.vk.gamma_abc_g1.len()),
    ])
}
