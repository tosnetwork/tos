/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Phase 1.5: the monomial basis into the Lagrange basis.
//!
//! A verified slice is not yet something a setup can use. The transcript
//! stores `tau^0, tau^1, tau^2, ...` in the exponent; Groth16's setup needs
//! `L_0(tau), L_1(tau), ...`, where `L_j` is the polynomial that is one at
//! `omega^j` and zero at every other root of unity. It needs that because the
//! QAP polynomials are defined by their values on the evaluation domain, so
//! `A_i(tau)` is a combination of `L_j(tau)` and not of `tau^j`.
//!
//! The two bases are one inverse DFT apart, in the exponent:
//!
//! ```text
//! L_j(X) = (1/n) * sum_i omega^(-ji) * X^i
//! L_j(tau)*G = (1/n) * sum_i omega^(-ji) * (tau^i*G)
//! ```
//!
//! which is `ifft` applied to group elements. Filecoin runs this as its own
//! stage and publishes the results as `phase1radix2m{k}` -- but only for
//! `k = 19` and `k = 27`, and a Lagrange basis belongs to one evaluation
//! domain. The 2^19 basis is not a prefix of the 2^15 one; it is a different
//! set of polynomials over a different set of roots. So this circuit's basis is
//! computed here.
//!
//! **The reason this is safe in a way phase 2 is not: the transform has no
//! secrets.** It is a fixed linear map from a known input to a known output, so
//! nothing has to be trusted and everything can be checked. [`verify`] checks
//! it four ways, and the tests break it four ways to show the checks bite.
//!
//! The same stage builds the **`h` query**, which is the other thing the
//! monomial basis is for. The prover divides by the vanishing polynomial
//! `t(X) = X^n - 1`, so the setup needs `tau^i * t(tau)` for `i` up to `n-2`:
//!
//! ```text
//! tau^i * t(tau) = tau^(i+n) - tau^i
//! ```
//!
//! That subtraction is the only reason the transcript's G1 section runs to
//! `2n-2` rather than `n-1`, and therefore the reason the slice's longest
//! range is as long as it is.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::points;
use crate::verify::{merge_consecutive, same_ratio, Phase1Slice};

/// The structured reference string a circuit-specific setup consumes.
///
/// Every element is a linear combination of the slice's, so this carries
/// exactly the trust the slice carries and no more -- and exactly as much, so
/// a deployment's custody argument is still about the published ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LagrangeSrs {
    /// `L_j(tau) * G1` for j in 0..n.
    pub coeffs_g1: Vec<G1Affine>,
    /// `L_j(tau) * G2`.
    pub coeffs_g2: Vec<G2Affine>,
    /// `alpha * L_j(tau) * G1`.
    pub alpha_coeffs_g1: Vec<G1Affine>,
    /// `beta * L_j(tau) * G1`.
    pub beta_coeffs_g1: Vec<G1Affine>,
    /// `tau^i * t(tau) * G1` for i in 0..n-1, with `t(X) = X^n - 1`.
    pub h: Vec<G1Affine>,
    /// Carried through unchanged; the setup needs beta in the second group.
    pub beta_g2: G2Affine,
}

impl LagrangeSrs {
    pub fn degree(&self) -> usize {
        self.coeffs_g1.len()
    }
}

fn domain(n: usize) -> Result<Radix2EvaluationDomain<Fr>> {
    Radix2EvaluationDomain::<Fr>::new(n).ok_or_else(|| {
        Error::Structure(format!("no radix-2 evaluation domain of size {n} over this field"))
    })
}

/// The transform.
///
/// Takes the first `n` powers of each section -- the slice carries `2n-1` in
/// G1 because the `h` query needs them, and the basis change does not.
pub fn transform(slice: &Phase1Slice) -> Result<LagrangeSrs> {
    let n = slice.degree();
    if n < 2 {
        return Err(Error::Structure("a slice of fewer than two powers has no domain".into()));
    }
    if slice.tau_g1.len() != 2 * n - 1 {
        return Err(Error::Structure(format!(
            "tau_g1 holds {} points; the h query needs {}",
            slice.tau_g1.len(),
            2 * n - 1
        )));
    }
    let domain = domain(n)?;

    // The inverse DFT, in the exponent. `ifft` carries the 1/n itself.
    let mut coeffs_g1: Vec<G1Projective> =
        slice.tau_g1[..n].iter().map(|point| point.into_group()).collect();
    domain.ifft_in_place(&mut coeffs_g1);

    let mut coeffs_g2: Vec<G2Projective> =
        slice.tau_g2.iter().map(|point| point.into_group()).collect();
    domain.ifft_in_place(&mut coeffs_g2);

    let mut alpha_coeffs_g1: Vec<G1Projective> =
        slice.alpha_tau_g1.iter().map(|point| point.into_group()).collect();
    domain.ifft_in_place(&mut alpha_coeffs_g1);

    let mut beta_coeffs_g1: Vec<G1Projective> =
        slice.beta_tau_g1.iter().map(|point| point.into_group()).collect();
    domain.ifft_in_place(&mut beta_coeffs_g1);

    // The h query. `t(X) = X^n - 1` for a multiplicative subgroup of order n,
    // so `tau^i * t(tau)` is one subtraction of two powers already in hand.
    let h: Vec<G1Projective> = (0..n - 1)
        .map(|i| slice.tau_g1[i + n].into_group() - slice.tau_g1[i].into_group())
        .collect();

    Ok(LagrangeSrs {
        coeffs_g1: G1Projective::normalize_batch(&coeffs_g1),
        coeffs_g2: G2Projective::normalize_batch(&coeffs_g2),
        alpha_coeffs_g1: G1Projective::normalize_batch(&alpha_coeffs_g1),
        beta_coeffs_g1: G1Projective::normalize_batch(&beta_coeffs_g1),
        h: G1Projective::normalize_batch(&h),
        beta_g2: slice.beta_g2,
    })
}

/// One polynomial, evaluated at tau by two different routes.
///
/// Values `e_j` on the domain define a polynomial. Going through the Lagrange
/// output, `P(tau) = sum_j e_j * L_j(tau)`. Going through the monomial input,
/// `P(tau) = sum_i c_i * tau^i` where `c = ifft(e)` **in the field**. Both
/// land on the same point, and they get there through different arithmetic:
/// one transforms group elements, the other scalars.
fn agrees_on_a_random_polynomial<R: rand::Rng>(
    lagrange: &[G1Affine],
    monomial: &[G1Affine],
    domain: &Radix2EvaluationDomain<Fr>,
    rng: &mut R,
) -> Result<bool> {
    let n = lagrange.len();
    let values: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
    let coefficients = domain.ifft(&values);

    let through_lagrange = G1Projective::msm(lagrange, &values)
        .map_err(|_| Error::Structure("the Lagrange multiexponentiation failed".into()))?;
    let through_monomial = G1Projective::msm(&monomial[..n], &coefficients)
        .map_err(|_| Error::Structure("the monomial multiexponentiation failed".into()))?;
    Ok(through_lagrange == through_monomial)
}

/// Checks the transform against its input, four ways.
///
/// `slice` is what it came from. Nothing here trusts [`transform`]; every
/// check is a statement relating the output to the input or to an identity the
/// Lagrange basis satisfies.
pub fn verify(slice: &Phase1Slice, srs: &LagrangeSrs, seed: [u8; 32]) -> Result<()> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let n = slice.degree();

    if srs.coeffs_g1.len() != n
        || srs.coeffs_g2.len() != n
        || srs.alpha_coeffs_g1.len() != n
        || srs.beta_coeffs_g1.len() != n
    {
        return Err(Error::Structure(format!(
            "the basis sections are {}, {}, {}, {} long, not {n} each",
            srs.coeffs_g1.len(),
            srs.coeffs_g2.len(),
            srs.alpha_coeffs_g1.len(),
            srs.beta_coeffs_g1.len()
        )));
    }
    if srs.h.len() != n - 1 {
        return Err(Error::Structure(format!(
            "the h query is {} long, not {}",
            srs.h.len(),
            n - 1
        )));
    }
    let domain = domain(n)?;

    // 1. The basis sums to one. `sum_j L_j(X) = 1` identically -- it is the
    //    interpolation of the constant one -- so the sum of the output is the
    //    generator exactly. Cheap, and independent of everything below.
    let sum_g1: G1Projective =
        srs.coeffs_g1.iter().fold(G1Projective::zero(), |total, point| total + point);
    if sum_g1.into_affine() != G1Affine::generator() {
        return Err(Error::Structure(
            "the G1 Lagrange basis does not sum to the generator, so it is not a basis for this \
             domain"
                .into(),
        ));
    }
    let sum_g2: G2Projective =
        srs.coeffs_g2.iter().fold(G2Projective::zero(), |total, point| total + point);
    if sum_g2.into_affine() != G2Affine::generator() {
        return Err(Error::Structure("the G2 Lagrange basis does not sum to the generator".into()));
    }

    // 2. The two groups carry the same basis. Batched: with random s_j,
    //    e(sum s_j L_j G1, G2) == e(G1, sum s_j L_j G2).
    let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    let left = G1Projective::msm(&srs.coeffs_g1, &scalars)
        .map_err(|_| Error::Structure("the G1 multiexponentiation failed".into()))?
        .into_affine();
    let right = G2Projective::msm(&srs.coeffs_g2, &scalars)
        .map_err(|_| Error::Structure("the G2 multiexponentiation failed".into()))?
        .into_affine();
    let paired =
        Bls12_381::multi_pairing([left, -G1Affine::generator()], [G2Affine::generator(), right]);
    if paired.0 != <Bls12_381 as Pairing>::TargetField::one() {
        return Err(Error::Structure(
            "the G1 and G2 Lagrange bases are not the same polynomials at tau".into(),
        ));
    }

    // 3. A random polynomial, evaluated through the new basis and through the
    //    old one. This is the check that would catch a wrong domain, a forward
    //    transform where an inverse was meant, or a missing 1/n.
    for (what, lagrange, monomial) in [
        ("the basis", &srs.coeffs_g1, &slice.tau_g1),
        ("the alpha basis", &srs.alpha_coeffs_g1, &slice.alpha_tau_g1),
        ("the beta basis", &srs.beta_coeffs_g1, &slice.beta_tau_g1),
    ] {
        if !agrees_on_a_random_polynomial(lagrange, monomial, &domain, &mut rng)? {
            return Err(Error::Structure(format!(
                "{what} disagrees with the powers it was built from: a polynomial evaluated at \
                 tau through the Lagrange basis is not the one evaluated through the monomial \
                 basis"
            )));
        }
    }

    // 4. The h query. Its first element pins it to the vanishing polynomial,
    //    and the batched ratio covers the rest: h[i] = tau^i * t(tau), so
    //    consecutive elements differ by tau.
    let expected_first =
        (slice.tau_g1[n].into_group() - slice.tau_g1[0].into_group()).into_affine();
    if srs.h[0] != expected_first {
        return Err(Error::Structure(
            "h[0] is not t(tau) = tau^n - 1, so the h query is not for this domain".into(),
        ));
    }
    if srs.h.len() >= 2 {
        let (left, right) = merge_consecutive(&srs.h, &mut rng)?;
        if !same_ratio((left, right), (slice.tau_g2[0], slice.tau_g2[1])) {
            return Err(Error::Structure(
                "the h query is not consecutive powers of tau times t(tau)".into(),
            ));
        }
    }

    Ok(())
}

/// The SRS as bytes, in the canonical uncompressed encoding, section by
/// section in the order of the struct.
///
/// Not a file format anybody else reads -- in particular **not** Filecoin's
/// `phase1radix2m{k}`, which this deliberately does not try to be. It exists
/// so the transform's output has a name: a phase-2 transcript can record which
/// SRS it started from without carrying twenty megabytes of it.
pub fn digest(srs: &LagrangeSrs) -> String {
    let mut hasher = Sha256::new();
    for section in [&srs.coeffs_g1, &srs.alpha_coeffs_g1, &srs.beta_coeffs_g1, &srs.h] {
        for point in section {
            hasher.update(points::g1_to_uncompressed(point));
        }
    }
    for point in &srs.coeffs_g2 {
        hasher.update(points::g2_to_uncompressed(point));
    }
    hasher.update(points::g2_to_uncompressed(&srs.beta_g2));
    hex::encode(hasher.finalize())
}

/// `L_j(tau)` from the definition, for a tau the caller knows.
///
/// The closed form for a multiplicative subgroup:
/// `L_j(X) = omega^j * (X^n - 1) / (n * (X - omega^j))`.
///
/// No FFT, no domain object doing the work -- only the field. Tests use it to
/// check [`transform`] against what a Lagrange basis *is*, rather than against
/// a second run of the same machinery.
pub fn lagrange_at(tau: Fr, n: usize, j: usize) -> Result<Fr> {
    let domain = domain(n)?;
    let omega_j = domain.element(j);
    let numerator = tau.pow([n as u64]) - Fr::one();
    let denominator = Fr::from(n as u64) * (tau - omega_j);
    let inverse = denominator.inverse().ok_or_else(|| {
        Error::Structure("tau is a root of unity, which a transcript's is not".into())
    })?;
    Ok(omega_j * numerator * inverse)
}
