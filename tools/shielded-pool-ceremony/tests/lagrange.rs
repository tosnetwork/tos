/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Is the basis change the basis change?
//!
//! A wrong FFT produces a vector of perfectly good curve points, in the right
//! number, in the right groups. Nothing about the output announces that it is
//! the wrong polynomial basis, and everything downstream would go on working
//! until a proof failed to verify for no visible reason.
//!
//! So the first test here does not check the transform against another run of
//! the same machinery. It builds a slice from a tau it chose, computes
//! `L_j(tau)` **from the closed form in the field** -- no FFT, no domain object
//! doing the work -- and requires every element of the output to equal it.
//! That is the test that catches a wrong domain, a forward transform where an
//! inverse was meant, or a missing `1/n`.
//!
//! The rest break the output one way at a time and require `verify` to say so.

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use shielded_pool_ceremony::lagrange::{self, LagrangeSrs};
use shielded_pool_ceremony::verify::{slice_from_known_secrets, Phase1Slice};

const SEED: [u8; 32] = *b"tos-shielded-pool-lagrange-check";
const DEGREE: usize = 16;

fn secrets() -> (Fr, Fr, Fr) {
    let mut rng = ChaCha20Rng::from_seed([23u8; 32]);
    (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng))
}

fn slice() -> Phase1Slice {
    let (tau, alpha, beta) = secrets();
    slice_from_known_secrets(DEGREE, tau, alpha, beta)
}

fn transformed() -> (Phase1Slice, LagrangeSrs) {
    let slice = slice();
    let srs = lagrange::transform(&slice).expect("the transform");
    (slice, srs)
}

/// The one that is not a restatement: every output element against the
/// definition of a Lagrange basis polynomial, computed in the field.
#[test]
fn every_element_is_the_lagrange_basis_from_its_closed_form() {
    let (tau, alpha, beta) = secrets();
    let (_slice, srs) = transformed();
    let g1 = G1Affine::generator().into_group();
    let g2 = G2Affine::generator().into_group();

    for j in 0..DEGREE {
        let expected = lagrange::lagrange_at(tau, DEGREE, j).expect("L_j(tau)");
        assert_eq!(
            srs.coeffs_g1[j],
            (g1 * expected).into_affine(),
            "coeffs_g1[{j}] is not L_{j}(tau) * G1"
        );
        assert_eq!(
            srs.coeffs_g2[j],
            (g2 * expected).into_affine(),
            "coeffs_g2[{j}] is not L_{j}(tau) * G2"
        );
        assert_eq!(
            srs.alpha_coeffs_g1[j],
            (g1 * (alpha * expected)).into_affine(),
            "alpha_coeffs_g1[{j}] is not alpha * L_{j}(tau) * G1"
        );
        assert_eq!(
            srs.beta_coeffs_g1[j],
            (g1 * (beta * expected)).into_affine(),
            "beta_coeffs_g1[{j}] is not beta * L_{j}(tau) * G1"
        );
    }
}

/// And the h query, likewise from the definition: `t(X) = X^n - 1`.
#[test]
fn the_h_query_is_the_vanishing_polynomial_times_the_powers() {
    let (tau, _, _) = secrets();
    let (_slice, srs) = transformed();
    let g1 = G1Affine::generator().into_group();
    let vanishing = {
        let mut power = Fr::from(1u64);
        for _ in 0..DEGREE {
            power *= tau;
        }
        power - Fr::from(1u64)
    };
    assert_eq!(srs.h.len(), DEGREE - 1, "the h query is the wrong length");

    let mut power = Fr::from(1u64);
    for (i, point) in srs.h.iter().enumerate() {
        assert_eq!(
            *point,
            (g1 * (power * vanishing)).into_affine(),
            "h[{i}] is not tau^{i} * t(tau) * G1"
        );
        power *= tau;
    }
}

/// The instrument speaks.
#[test]
fn the_transform_verifies_against_the_slice_it_came_from() {
    let (slice, srs) = transformed();
    lagrange::verify(&slice, &srs, SEED).expect("a correct transform must verify");
}

/// The identity that holds for no other vector of points: the basis
/// interpolates the constant one.
#[test]
fn a_basis_that_does_not_sum_to_the_generator_is_refused() {
    let (slice, mut srs) = transformed();
    // Move one element and compensate in another, so the *sum* is the only
    // thing that changes... it is not: pairing checks would also see it. The
    // point of this case is that the sum check fires first and names itself.
    srs.coeffs_g1[3] = (srs.coeffs_g1[3].into_group() + G1Affine::generator()).into_affine();
    let error = lagrange::verify(&slice, &srs, SEED).expect_err("a broken basis must be refused");
    assert!(format!("{error}").contains("sum to the generator"), "wrong check: {error}");
}

/// The case nothing but the cross-basis check can see.
///
/// Two elements swapped **in both groups at once**. The sum is unchanged, so
/// the identity check passes. G1 and G2 still carry the same polynomials as
/// each other, so the pairing check passes. Every point is genuine and in the
/// right group. What is wrong is only visible by going back to the powers the
/// basis was built from -- which is what the random-polynomial check does, and
/// the reason it is worth its cost.
///
/// A swap in G1 alone is a weaker case: the pairing check catches that one
/// first, because the two groups stop agreeing.
#[test]
fn two_basis_elements_swapped_in_both_groups_are_refused() {
    let (slice, mut srs) = transformed();
    srs.coeffs_g1.swap(5, 9);
    srs.coeffs_g2.swap(5, 9);

    let sum: G1Projective =
        srs.coeffs_g1.iter().fold(G1Projective::default(), |total, point| total + point);
    assert_eq!(
        sum.into_affine(),
        G1Affine::generator(),
        "the swap changed the sum, so this is not the case it was meant to be"
    );

    let error = lagrange::verify(&slice, &srs, SEED).expect_err("a permuted basis must be refused");
    assert!(
        format!("{error}").contains("disagrees with the powers it was built from"),
        "wrong check: {error}"
    );
}

/// The two groups have to carry the same polynomials, or the setup's pairing
/// equation closes over two different statements.
#[test]
fn a_g2_basis_for_a_different_tau_is_refused() {
    let (tau, alpha, beta) = secrets();
    let slice = slice();
    let mut srs = lagrange::transform(&slice).expect("the transform");
    let other = slice_from_known_secrets(DEGREE, tau + Fr::from(1u64), alpha, beta);
    let other_srs = lagrange::transform(&other).expect("the other transform");
    srs.coeffs_g2 = other_srs.coeffs_g2;
    let error = lagrange::verify(&slice, &srs, SEED).expect_err("two taus must be refused");
    assert!(format!("{error}").contains("not the same polynomials at tau"), "wrong check: {error}");
}

#[test]
fn an_h_query_that_is_not_the_vanishing_polynomial_is_refused() {
    let (slice, mut srs) = transformed();
    srs.h[0] = (srs.h[0].into_group() + G1Affine::generator()).into_affine();
    let error = lagrange::verify(&slice, &srs, SEED).expect_err("a broken h query must be refused");
    assert!(format!("{error}").contains("not t(tau)"), "wrong check: {error}");
}

/// Past the first element, where only the batched ratio can see it.
#[test]
fn an_h_query_that_stops_being_consecutive_is_refused() {
    let (slice, mut srs) = transformed();
    let middle = srs.h.len() / 2;
    srs.h[middle] = (srs.h[middle].into_group() + G1Affine::generator()).into_affine();
    let error = lagrange::verify(&slice, &srs, SEED).expect_err("a broken h query must be refused");
    assert!(format!("{error}").contains("not consecutive powers of tau"), "wrong check: {error}");
}

/// A transform is a function of its input, so the same slice twice is the same
/// SRS twice -- and the digest is what a phase-2 transcript would record.
#[test]
fn the_transform_is_deterministic() {
    let slice = slice();
    let first = lagrange::transform(&slice).expect("first");
    let second = lagrange::transform(&slice).expect("second");
    assert_eq!(first, second);
    assert_eq!(lagrange::digest(&first), lagrange::digest(&second));

    // And a different slice is a different digest, or the digest names
    // nothing.
    let (tau, alpha, beta) = secrets();
    let other = slice_from_known_secrets(DEGREE, tau + Fr::from(1u64), alpha, beta);
    let other_srs = lagrange::transform(&other).expect("other");
    assert_ne!(lagrange::digest(&first), lagrange::digest(&other_srs));
}

/// A slice too short for the h query is refused rather than silently giving a
/// shorter one.
#[test]
fn a_slice_without_the_upper_powers_is_refused() {
    let mut slice = slice();
    slice.tau_g1.truncate(DEGREE);
    let error = lagrange::transform(&slice).expect_err("a short slice must be refused");
    assert!(format!("{error}").contains("the h query needs"), "wrong check: {error}");
}
