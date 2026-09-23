/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Can the phase-1 verification fail?
//!
//! A verifier that returns `Ok` on a correct string has proved nothing about
//! itself. Every check in `verify` is a defence against one way a transcript
//! can be wrong, and each one is reached here by building a string that is
//! wrong in exactly that way and requiring the named check to catch it.
//!
//! The strings are built from secrets this file chose, which is what makes
//! them breakable. A slice built this way must never reach a deployment; the
//! point of it is that a tampered slice is indistinguishable from a real one
//! until the pairing checks run, so this is the only way to find out whether
//! they run.

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use shielded_pool_ceremony::verify::{slice_from_known_secrets, verify, Phase1Slice};

const SEED: [u8; 32] = *b"tos-shielded-pool-phase1-checks!";

/// Small enough to run in a moment, large enough that the batched checks have
/// more than one pair to batch.
const DEGREE: usize = 16;

fn secrets() -> (Fr, Fr, Fr) {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng))
}

fn good() -> Phase1Slice {
    let (tau, alpha, beta) = secrets();
    slice_from_known_secrets(DEGREE, tau, alpha, beta)
}

/// The instrument speaks: a correct string passes. Without this every test
/// below could be passing because the verifier rejects everything.
#[test]
fn a_correct_powers_of_tau_string_verifies() {
    verify(&good(), SEED).expect("a correctly built slice must verify");
}

#[test]
fn a_string_that_does_not_start_at_the_generator_is_refused() {
    let mut slice = good();
    let (tau, _, _) = secrets();
    // Scale the whole G1 section by tau: still consistent powers, of the
    // wrong base point. Every ratio check still holds, so only the generator
    // check can catch this.
    for point in &mut slice.tau_g1 {
        *point = (point.into_group() * tau).into_affine();
    }
    let error = verify(&slice, SEED).expect_err("a string of the wrong generator must be refused");
    assert!(
        format!("{error}").contains("not the G1 generator"),
        "caught by the wrong check: {error}"
    );
}

#[test]
fn two_different_taus_in_the_two_groups_are_refused() {
    let (tau, alpha, beta) = secrets();
    let mut slice = slice_from_known_secrets(DEGREE, tau, alpha, beta);
    // Rebuild G2 under a different tau. On its own the G2 section is a
    // perfectly good powers-of-tau string; it is only wrong relative to G1.
    let other = slice_from_known_secrets(DEGREE, tau + Fr::from(1u64), alpha, beta);
    slice.tau_g2 = other.tau_g2;
    let error = verify(&slice, SEED).expect_err("two taus must be refused");
    assert!(format!("{error}").contains("not the same tau"), "caught by the wrong check: {error}");
}

#[test]
fn a_single_wrong_power_deep_in_the_g1_section_is_refused() {
    let mut slice = good();
    // Not the first pair -- that one has its own check. This lands in the
    // middle, where only the batched check can see it.
    let middle = slice.tau_g1.len() / 2;
    slice.tau_g1[middle] =
        (slice.tau_g1[middle].into_group() + G1Affine::generator()).into_affine();
    let error = verify(&slice, SEED).expect_err("a corrupted power must be refused");
    assert!(
        format!("{error}").contains("not consecutive powers"),
        "caught by the wrong check: {error}"
    );
}

#[test]
fn a_single_wrong_power_deep_in_the_g2_section_is_refused() {
    let mut slice = good();
    let middle = slice.tau_g2.len() / 2;
    slice.tau_g2[middle] =
        (slice.tau_g2[middle].into_group() + G2Affine::generator()).into_affine();
    let error = verify(&slice, SEED).expect_err("a corrupted G2 power must be refused");
    assert!(
        format!("{error}").contains("G2 powers of tau are not consecutive"),
        "caught by the wrong check: {error}"
    );
}

#[test]
fn an_alpha_section_that_is_not_alpha_times_the_powers_is_refused() {
    let mut slice = good();
    let last = slice.alpha_tau_g1.len() - 1;
    slice.alpha_tau_g1[last] =
        (slice.alpha_tau_g1[last].into_group() + G1Affine::generator()).into_affine();
    let error = verify(&slice, SEED).expect_err("a corrupted alpha section must be refused");
    assert!(
        format!("{error}").contains("alpha powers are not consecutive"),
        "caught by the wrong check: {error}"
    );
}

#[test]
fn a_beta_in_g2_that_is_not_the_beta_in_g1_is_refused() {
    let (tau, alpha, beta) = secrets();
    let mut slice = slice_from_known_secrets(DEGREE, tau, alpha, beta);
    // beta_g2 is the only appearance of beta in the second group, so a
    // mismatch here is invisible to every other check.
    slice.beta_g2 = (G2Affine::generator().into_group() * (beta + Fr::from(1u64))).into_affine();
    let error = verify(&slice, SEED).expect_err("a mismatched beta must be refused");
    assert!(format!("{error}").contains("different scalars"), "caught by the wrong check: {error}");
}

#[test]
fn sections_in_the_wrong_order_are_refused() {
    // The failure mode the layout module cannot catch: right sizes, right
    // points, read in the wrong order. Swapping alpha and beta leaves two
    // sections that are each internally consistent.
    let (tau, alpha, beta) = secrets();
    let mut slice = slice_from_known_secrets(DEGREE, tau, alpha, beta);
    std::mem::swap(&mut slice.alpha_tau_g1, &mut slice.beta_tau_g1);
    // Both are alpha/beta times consecutive powers, so the ratio checks still
    // pass -- what fails is the tie between beta_tau_g1[0] and beta_g2.
    let error = verify(&slice, SEED).expect_err("swapped sections must be refused");
    assert!(format!("{error}").contains("different scalars"), "caught by the wrong check: {error}");
}

#[test]
fn a_truncated_section_is_refused() {
    let mut slice = good();
    slice.tau_g1.pop();
    let error = verify(&slice, SEED).expect_err("a short section must be refused");
    assert!(format!("{error}").contains("tau_g1 holds"), "caught by the wrong check: {error}");
}
