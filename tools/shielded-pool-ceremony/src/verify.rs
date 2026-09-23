/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Is this string really the powers of one tau?
//!
//! A phase-1 slice arrives as several million bytes that parse into valid
//! curve points. That says almost nothing: any list of points parses. What
//! has to hold is that the list *is* `tau^0, tau^1, tau^2, ...` for a single
//! unknown tau, in both groups, with alpha and beta consistent -- because
//! everything phase 2 builds is a linear combination of these, and a slice
//! whose powers do not advance by a constant ratio yields a proving key that
//! proves statements nobody wrote.
//!
//! **What this establishes and what it does not.** These checks establish the
//! *structure* of the string: that it is a well-formed powers-of-tau over the
//! degree we need. They say nothing about *who knows tau*. That property
//! comes from the contribution chain -- 2017 onwards, many participants, each
//! multiplying in their own secret and proving they did -- and re-verifying
//! that chain means replaying every response file in the transcript, not
//! reading the final accumulator. A slice cannot carry it, and no amount of
//! pairing arithmetic on the slice will produce it. Section 20 has to say
//! which of those two the deployment is relying on, and the honest answer is
//! both: structure checked here, custody inherited from the published
//! ceremony.
//!
//! The checks are the ones `Accumulator::verify` performs, restricted to a
//! prefix, which is sound because every one of them is a statement about
//! consecutive elements.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, UniformRand};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::error::{Error, Result};

/// A phase-1 slice, parsed.
#[derive(Debug)]
pub struct Phase1Slice {
    /// `tau^i * G1` for i in 0..=2n-2.
    pub tau_g1: Vec<G1Affine>,
    /// `tau^i * G2` for i in 0..n.
    pub tau_g2: Vec<G2Affine>,
    /// `alpha * tau^i * G1` for i in 0..n.
    pub alpha_tau_g1: Vec<G1Affine>,
    /// `beta * tau^i * G1` for i in 0..n.
    pub beta_tau_g1: Vec<G1Affine>,
    /// `beta * G2`.
    pub beta_g2: G2Affine,
}

impl Phase1Slice {
    /// The QAP degree this slice supports.
    pub fn degree(&self) -> usize {
        self.tau_g2.len()
    }
}

/// `e(a, d) == e(b, c)`, which for `b = x*a` and `d = x*c` is the statement
/// that the two pairs share a ratio.
///
/// Written as one multi-pairing with `a` negated rather than two pairings
/// compared, so a slice that is wrong fails on the equation rather than on
/// floating comparisons of target-group elements.
pub(crate) fn same_ratio((a, b): (G1Affine, G1Affine), (c, d): (G2Affine, G2Affine)) -> bool {
    // e(a, d) * e(-b, c) == 1
    let minus_b = -b;
    Bls12_381::multi_pairing([a, minus_b], [d, c]).0 == <Bls12_381 as Pairing>::TargetField::one()
}

/// Collapses a whole vector of consecutive pairs into one, so that a single
/// `same_ratio` decides all of them.
///
/// With random `s_i`, `l = sum s_i * v[i]` and `r = sum s_i * v[i+1]`. If
/// every `v[i+1] = tau * v[i]` then `r = tau * l`. If any one of them is
/// wrong, the equality survives only with probability about `1/|Fr|` over the
/// choice of `s`, so this is a proof and not a sample.
///
/// The randomness is drawn from the caller's generator. It must not be
/// derived from the slice: scalars a malicious transcript could predict are
/// scalars it could cancel against.
pub(crate) fn merge_consecutive<R: rand::Rng>(
    points: &[G1Affine],
    rng: &mut R,
) -> Result<(G1Affine, G1Affine)> {
    if points.len() < 2 {
        return Err(Error::Structure("a section with fewer than two points has no ratio".into()));
    }
    let scalars: Vec<Fr> = (0..points.len() - 1).map(|_| Fr::rand(rng)).collect();
    let left = G1Projective::msm(&points[..points.len() - 1], &scalars)
        .map_err(|_| Error::Structure("the left multiexponentiation failed".into()))?;
    let right = G1Projective::msm(&points[1..], &scalars)
        .map_err(|_| Error::Structure("the right multiexponentiation failed".into()))?;
    Ok((left.into_affine(), right.into_affine()))
}

fn merge_consecutive_g2<R: rand::Rng>(
    points: &[G2Affine],
    rng: &mut R,
) -> Result<(G2Affine, G2Affine)> {
    if points.len() < 2 {
        return Err(Error::Structure("a section with fewer than two points has no ratio".into()));
    }
    let scalars: Vec<Fr> = (0..points.len() - 1).map(|_| Fr::rand(rng)).collect();
    let left = G2Projective::msm(&points[..points.len() - 1], &scalars)
        .map_err(|_| Error::Structure("the left multiexponentiation failed".into()))?;
    let right = G2Projective::msm(&points[1..], &scalars)
        .map_err(|_| Error::Structure("the right multiexponentiation failed".into()))?;
    Ok((left.into_affine(), right.into_affine()))
}

/// Every structural check, in order, with the first failure named.
///
/// `seed` chooses the batching randomness. Production callers pass entropy
/// from the operating system; the tests pass a fixed seed so that a failure is
/// reproducible.
pub fn verify(slice: &Phase1Slice, seed: [u8; 32]) -> Result<()> {
    let mut rng = ChaCha20Rng::from_seed(seed);

    let n = slice.tau_g2.len();
    if n < 2 {
        return Err(Error::Structure("a slice of fewer than two powers is not one".into()));
    }
    if slice.tau_g1.len() != 2 * n - 1 {
        return Err(Error::Structure(format!(
            "tau_g1 holds {} points; a degree-{n} slice needs {} of them",
            slice.tau_g1.len(),
            2 * n - 1
        )));
    }
    if slice.alpha_tau_g1.len() != n || slice.beta_tau_g1.len() != n {
        return Err(Error::Structure(format!(
            "alpha and beta sections hold {} and {} points, not {n} each",
            slice.alpha_tau_g1.len(),
            slice.beta_tau_g1.len()
        )));
    }

    // 1. The zeroth power is the generator, in both groups. Without this the
    //    whole string could be a consistent powers-of-tau of some *other*
    //    generator, which is a different and useless SRS.
    if slice.tau_g1[0] != G1Affine::generator() {
        return Err(Error::Structure("tau_g1[0] is not the G1 generator".into()));
    }
    if slice.tau_g2[0] != G2Affine::generator() {
        return Err(Error::Structure("tau_g2[0] is not the G2 generator".into()));
    }

    // 2. The same tau in both groups. Everything downstream pairs a G1 power
    //    against a G2 power, so two different taus would go unnoticed here and
    //    produce a proving key nothing verifies against.
    if !same_ratio((slice.tau_g1[0], slice.tau_g1[1]), (slice.tau_g2[0], slice.tau_g2[1])) {
        return Err(Error::Structure(
            "the first power of tau in G1 and in G2 are not the same tau".into(),
        ));
    }

    // 3. alpha and beta advance by that same tau.
    if !same_ratio(
        (slice.alpha_tau_g1[0], slice.alpha_tau_g1[1]),
        (slice.tau_g2[0], slice.tau_g2[1]),
    ) {
        return Err(Error::Structure("the alpha powers do not advance by tau".into()));
    }
    if !same_ratio((slice.beta_tau_g1[0], slice.beta_tau_g1[1]), (slice.tau_g2[0], slice.tau_g2[1]))
    {
        return Err(Error::Structure("the beta powers do not advance by tau".into()));
    }

    // 4. The beta in G1 is the beta in G2. beta_g2 is the only place beta
    //    appears in the second group and phase 2 uses both, so a mismatch here
    //    is a proving key whose pairing equation cannot close.
    if !same_ratio((slice.beta_tau_g1[0], slice.tau_g1[0]), (slice.beta_g2, slice.tau_g2[0])) {
        return Err(Error::Structure("beta in G1 and beta in G2 are different scalars".into()));
    }

    // 5. And now every remaining power, batched. Steps 2 and 3 only looked at
    //    the first pair of each section; these cover all of them at once.
    let (left, right) = merge_consecutive(&slice.tau_g1, &mut rng)?;
    if !same_ratio((left, right), (slice.tau_g2[0], slice.tau_g2[1])) {
        return Err(Error::Structure(
            "the G1 powers of tau are not consecutive powers of one tau".into(),
        ));
    }

    let (left, right) = merge_consecutive_g2(&slice.tau_g2, &mut rng)?;
    if !same_ratio((slice.tau_g1[0], slice.tau_g1[1]), (left, right)) {
        return Err(Error::Structure(
            "the G2 powers of tau are not consecutive powers of one tau".into(),
        ));
    }

    let (left, right) = merge_consecutive(&slice.alpha_tau_g1, &mut rng)?;
    if !same_ratio((left, right), (slice.tau_g2[0], slice.tau_g2[1])) {
        return Err(Error::Structure("the alpha powers are not consecutive".into()));
    }

    let (left, right) = merge_consecutive(&slice.beta_tau_g1, &mut rng)?;
    if !same_ratio((left, right), (slice.tau_g2[0], slice.tau_g2[1])) {
        return Err(Error::Structure("the beta powers are not consecutive".into()));
    }

    Ok(())
}

/// A slice built from a known tau, alpha and beta.
///
/// Not a substitute for the real transcript and never to be used as one: the
/// secrets are the caller's, so a proving key derived from it proves anything.
/// It exists so that the checks above can be run against a string that is
/// correct by construction, and against strings broken one way at a time --
/// which is the only way to find out whether they can fail at all.
pub fn slice_from_known_secrets(degree: usize, tau: Fr, alpha: Fr, beta: Fr) -> Phase1Slice {
    let g1 = G1Projective::from(G1Affine::generator());
    let g2 = G2Projective::from(G2Affine::generator());

    let mut powers = Vec::with_capacity(2 * degree - 1);
    let mut current = Fr::from(1u64);
    for _ in 0..2 * degree - 1 {
        powers.push(current);
        current *= tau;
    }

    let tau_g1 = powers.iter().map(|power| (g1 * power).into_affine()).collect();
    let tau_g2 = powers[..degree].iter().map(|power| (g2 * power).into_affine()).collect();
    let alpha_tau_g1 =
        powers[..degree].iter().map(|power| (g1 * (alpha * power)).into_affine()).collect();
    let beta_tau_g1 =
        powers[..degree].iter().map(|power| (g1 * (beta * power)).into_affine()).collect();

    Phase1Slice { tau_g1, tau_g2, alpha_tau_g1, beta_tau_g1, beta_g2: (g2 * beta).into_affine() }
}
