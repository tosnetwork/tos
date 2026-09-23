/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The phase-2 audit, again, on a different pairing library.
//!
//! An auditor checking a ceremony runs [`crate::contribution::verify_chain`],
//! which is arkworks all the way down: the pairings, the group arithmetic and
//! the multiexponentiations are one library's, used one way, by one author.
//! The tests around it show that it accepts honest chains and refuses the
//! forgeries aimed at it -- but a pairing check that is *consistently* wrong
//! would do both. It would accept and refuse exactly the cases it was tested
//! on, and have a different meaning from the one written down.
//!
//! So the same four checks are implemented here against **blst**, the library
//! the chain itself verifies proofs with, and a test requires the two to agree
//! on every chain the suite can build -- honest and forged alike.
//!
//! # What this is independent of, and what it is not
//!
//! Independent: the pairing, the final exponentiation, the group law, the
//! scalar multiplication. Those are the parts where a convention can be got
//! wrong -- a missing negation, an argument order, a subgroup assumption --
//! and where "it passes its own tests" is not evidence.
//!
//! **Not** independent: the author, the repository, the protocol's meaning, or
//! the point encoding. Both sides read the same [`crate::points`] bytes, on
//! purpose, because that encoding is normative -- ruling A1 fixes it and the
//! chain reads the same bytes. An error in *what should be checked* is
//! reproduced here faithfully, and this cannot find it. That is the reason
//! `doc/shielded-pool-ceremony.md` still asks for a verifier outside this
//! repository: this narrows the gap and does not close it.
//!
//! # The checks
//!
//! Exactly the ones `verify_chain` makes, in the same order, with the same
//! meanings:
//!
//! 1. the proof of knowledge: `e(s, r_delta) == e(s_delta, h)`;
//! 2. `delta` agrees across the groups: `e(delta_g1, G2) == e(G1, delta_g2)`;
//! 3. the chain link: `e(delta_after, h) == e(delta_before, r_delta)`;
//! 4. the queries were divided by what `delta` was multiplied by, batched:
//!    `e(sum(rho_i * l_after_i), delta_after_g2) == e(sum(rho_i * l_before_i), delta_before_g2)`.
//!
//! The weights in 4 are a parameter rather than drawn inside, so a caller
//! decides where its own randomness comes from and this side never silently
//! answers a different question from the one it was asked.
//!
//! It does **not** follow that both implementations are given the same
//! weights, and an earlier version of this comment said it did.
//! `crosscheck_agrees.rs` lets each side draw its own, which is the stronger
//! arrangement: two implementations agreeing under independently drawn
//! weights says more than agreeing under one weighting, and a batched check
//! that only worked for particular weights would show up as a disagreement.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::ProvingKey;

use crate::contribution::{challenge_point, Contribution, Transcript};
use crate::error::{Error, Result};
use crate::points::{g1_to_uncompressed, g2_to_uncompressed};

/// An affine G1 point as blst holds it.
///
/// Through the normative uncompressed encoding, which puts every point through
/// blst's own curve and subgroup checks on the way in. A point arkworks
/// believes in and blst refuses would fail here rather than be waved past,
/// which is itself worth knowing.
fn g1(point: &G1Affine) -> Result<blst::blst_p1_affine> {
    let bytes = g1_to_uncompressed(point);
    let mut out = blst::blst_p1_affine::default();
    if point.is_zero() {
        // blst's deserialize accepts the infinity encoding and yields the
        // identity; the explicit branch is here because a pairing with the
        // identity is a case worth not discovering by accident.
        return Ok(out);
    }
    // SAFETY: `bytes` is the 96 blst reads for an uncompressed G1 and `out` is
    // a valid out-parameter.
    let status = unsafe { blst::blst_p1_deserialize(&mut out, bytes.as_ptr()) };
    if status != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(Error::Point(format!("blst refused a G1 point: {status:?}")));
    }
    Ok(out)
}

fn g2(point: &G2Affine) -> Result<blst::blst_p2_affine> {
    let bytes = g2_to_uncompressed(point);
    let mut out = blst::blst_p2_affine::default();
    if point.is_zero() {
        return Ok(out);
    }
    // SAFETY: `bytes` is the 192 blst reads for an uncompressed G2 and `out`
    // is a valid out-parameter.
    let status = unsafe { blst::blst_p2_deserialize(&mut out, bytes.as_ptr()) };
    if status != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(Error::Point(format!("blst refused a G2 point: {status:?}")));
    }
    Ok(out)
}

/// `e(a, b) == e(c, d)`, through blst's Miller loop and final verification.
///
/// Two Miller loops compared by `blst_fp12_finalverify`, which applies the
/// final exponentiation to both and compares -- rather than negating one input
/// and asking whether the product is one, which is how the arkworks side does
/// it. Two different routes to the same question is the point.
fn same_pairing(a: &G1Affine, b: &G2Affine, c: &G1Affine, d: &G2Affine) -> Result<bool> {
    let (a, b, c, d) = (g1(a)?, g2(b)?, g1(c)?, g2(d)?);
    let mut left = blst::blst_fp12::default();
    let mut right = blst::blst_fp12::default();
    // SAFETY: all four affine points were filled by a successful deserialize
    // or are the identity, and the outputs are valid out-parameters. blst's
    // Miller loop takes G2 first.
    unsafe {
        blst::blst_miller_loop(&mut left, &b, &a);
        blst::blst_miller_loop(&mut right, &d, &c);
        Ok(blst::blst_fp12_finalverify(&left, &right))
    }
}

/// `sum(scalars[i] * points[i])`, accumulated one point at a time.
///
/// Deliberately naive. The arkworks side uses Pippenger through
/// `VariableBaseMSM`; a second Pippenger would share the algorithm's
/// assumptions, and the sum is what has to agree, not the way of reaching it.
fn combine(points: &[G1Affine], scalars: &[Fr]) -> Result<G1Affine> {
    if points.len() != scalars.len() {
        return Err(Error::Structure(format!(
            "{} points against {} scalars",
            points.len(),
            scalars.len()
        )));
    }

    let mut total = blst::blst_p1::default();
    for (point, scalar) in points.iter().zip(scalars) {
        if point.is_zero() {
            continue;
        }
        let affine = g1(point)?;
        let mut term = blst::blst_p1::default();
        let mut base = blst::blst_p1::default();

        // Big-endian, 32 bytes, which is what `blst_scalar_from_bendian`
        // reads. `into_bigint().to_bytes_be()` can be shorter for a small
        // scalar, so it is left-padded rather than assumed full width.
        let digits = scalar.into_bigint().to_bytes_be();
        let mut padded = [0u8; 32];
        if digits.len() > 32 {
            return Err(Error::Structure("a scalar wider than 32 bytes".into()));
        }
        padded[32 - digits.len()..].copy_from_slice(&digits);
        let mut blst_scalar = blst::blst_scalar::default();

        // SAFETY: `padded` is 32 bytes, the width blst reads for a scalar;
        // `affine` came from a successful deserialize; every output is a valid
        // out-parameter.
        unsafe {
            blst::blst_scalar_from_bendian(&mut blst_scalar, padded.as_ptr());
            blst::blst_p1_from_affine(&mut base, &affine);
            blst::blst_p1_mult(&mut term, &base, blst_scalar.b.as_ptr(), 255);
            let previous = total;
            blst::blst_p1_add_or_double(&mut total, &previous, &term);
        }
    }

    let mut affine = blst::blst_p1_affine::default();
    // SAFETY: `total` is a valid projective point and `affine` a valid
    // out-parameter.
    unsafe { blst::blst_p1_to_affine(&mut affine, &total) };
    let mut bytes = [0u8; 96];
    // SAFETY: `bytes` is the 96 blst writes for an uncompressed G1.
    unsafe { blst::blst_p1_affine_serialize(bytes.as_mut_ptr(), &affine) };

    // Back through the same gate as every other point, so a sum blst computed
    // and arkworks cannot read is an error rather than a silent divergence.
    crate::points::g1_from_uncompressed(&bytes)
}

/// The chain audit, on blst.
///
/// Mirrors [`crate::contribution::verify_chain`]: same checks, same order,
/// same meanings. `weights` are the batching scalars, passed in so both
/// implementations answer the same question rather than two related ones.
///
/// Returns `Ok(())` when it accepts. Any refusal is an `Err`, and the message
/// says which check objected -- a disagreement between the two sides is only
/// useful if it can be located.
pub fn verify_chain_with_blst(
    initial: &ProvingKey<Bls12_381>,
    final_key: &ProvingKey<Bls12_381>,
    contributions: &[Contribution],
    weights: &Weights,
) -> Result<()> {
    if contributions.is_empty() {
        return Err(Error::Structure("a ceremony with no contributions".into()));
    }
    if initial.delta_g1 != G1Affine::generator() || initial.vk.delta_g2 != G2Affine::generator() {
        return Err(Error::Structure("the starting key's delta is not one".into()));
    }

    let generator_g1 = G1Affine::generator();
    let generator_g2 = G2Affine::generator();
    let mut transcript = Transcript::begin(initial)?;
    let mut previous_g1 = initial.delta_g1;

    for (index, contribution) in contributions.iter().enumerate() {
        let at =
            |what: &str| Error::Structure(format!("contribution {}: {what} (blst)", index + 1));
        let challenge = challenge_point(&transcript, &contribution.s, &contribution.s_delta)?;

        if contribution.s.is_zero() || contribution.s_delta.is_zero() {
            return Err(at("the proof of knowledge uses the identity"));
        }
        if !same_pairing(&contribution.s, &contribution.r_delta, &contribution.s_delta, &challenge)?
        {
            return Err(at("the proof of knowledge does not check out"));
        }
        if contribution.delta_g1 == previous_g1 {
            return Err(at("delta is unchanged"));
        }
        if !same_pairing(
            &contribution.delta_g1,
            &generator_g2,
            &generator_g1,
            &contribution.delta_g2,
        )? {
            return Err(at("delta in G1 and delta in G2 are different scalars"));
        }
        if !same_pairing(&contribution.delta_g1, &challenge, &previous_g1, &contribution.r_delta)? {
            return Err(at("this delta does not follow from the previous one"));
        }

        previous_g1 = contribution.delta_g1;
        transcript = transcript.extend(contribution);
    }

    let last = contributions
        .last()
        .ok_or_else(|| Error::Structure("the contribution list emptied itself".into()))?;
    if final_key.delta_g1 != last.delta_g1 || final_key.vk.delta_g2 != last.delta_g2 {
        return Err(Error::Structure("the final key's delta is not the chain's end (blst)".into()));
    }

    for (name, before, after, scalars) in [
        ("l_query", &initial.l_query, &final_key.l_query, &weights.l),
        ("h_query", &initial.h_query, &final_key.h_query, &weights.h),
    ] {
        if before.len() != after.len() {
            return Err(Error::Structure(format!("{name} changed length (blst)")));
        }
        if before.is_empty() {
            continue;
        }
        let before_sum = combine(before, scalars)?;
        let after_sum = combine(after, scalars)?;
        if !same_pairing(&after_sum, &final_key.vk.delta_g2, &before_sum, &initial.vk.delta_g2)? {
            return Err(Error::Structure(format!(
                "{name} was not divided by the scalar delta was multiplied by (blst)"
            )));
        }
    }

    the_rest_is_untouched(initial, final_key)
}

/// The batching weights, shared between the two implementations.
///
/// Held in a struct rather than drawn inside, because a disagreement is only
/// evidence when both sides were asked the same question. In production each
/// verifier draws its own; the tests draw once and hand the same scalars to
/// both.
pub struct Weights {
    pub l: Vec<Fr>,
    pub h: Vec<Fr>,
}

impl Weights {
    /// Weights for a key's query lengths, drawn from an entropy source.
    pub fn draw(
        key: &ProvingKey<Bls12_381>,
        entropy: &mut dyn crate::entropy::Entropy,
    ) -> Result<Self> {
        use ark_ff::UniformRand;
        use rand::SeedableRng;
        let mut seed = [0u8; 32];
        entropy.fill(&mut seed)?;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        Ok(Self {
            l: (0..key.l_query.len()).map(|_| Fr::rand(&mut rng)).collect(),
            h: (0..key.h_query.len()).map(|_| Fr::rand(&mut rng)).collect(),
        })
    }
}

/// Byte comparison, the same sections the arkworks side compares.
///
/// Not a pairing, so not independent of anything -- it is here so the two
/// implementations refuse the same set of chains rather than differing on a
/// case neither side's pairings look at.
fn the_rest_is_untouched(
    before: &ProvingKey<Bls12_381>,
    after: &ProvingKey<Bls12_381>,
) -> Result<()> {
    let mismatch = |what: &str| Error::Structure(format!("{what} changed (blst)"));
    if before.vk.alpha_g1 != after.vk.alpha_g1 {
        return Err(mismatch("alpha_g1"));
    }
    if before.vk.beta_g2 != after.vk.beta_g2 {
        return Err(mismatch("beta_g2"));
    }
    if before.vk.gamma_g2 != after.vk.gamma_g2 {
        return Err(mismatch("gamma_g2"));
    }
    if before.vk.gamma_abc_g1 != after.vk.gamma_abc_g1 {
        return Err(mismatch("the input-consistency points"));
    }
    if before.beta_g1 != after.beta_g1 {
        return Err(mismatch("beta_g1"));
    }
    if before.a_query != after.a_query {
        return Err(mismatch("a_query"));
    }
    if before.b_g1_query != after.b_g1_query {
        return Err(mismatch("b_g1_query"));
    }
    if before.b_g2_query != after.b_g2_query {
        return Err(mismatch("b_g2_query"));
    }
    Ok(())
}
