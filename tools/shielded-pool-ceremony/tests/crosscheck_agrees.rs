/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Do two pairing libraries agree about what a valid ceremony is?
//!
//! `phase2_contribution.rs` shows that the arkworks audit accepts honest
//! chains and refuses the forgeries aimed at it. That is necessary and it is
//! not sufficient: a pairing check that is *consistently* wrong -- an argument
//! the wrong way round, a missing negation, a subgroup assumption that happens
//! to hold for every point a test builds -- accepts and refuses exactly those
//! cases too, while meaning something other than what is written down.
//!
//! So every chain below is put to **both** implementations, and the assertion
//! is not "it was refused" but **"they agreed"**. A disagreement is a defect
//! wherever it lives, and there is no version of it that is fine.
//!
//! What this establishes is narrow and worth stating exactly: the pairing, the
//! final exponentiation, the group law and the scalar multiplication are not
//! one library's convention. The author, the repository, the point encoding
//! and the *meaning* of the checks are shared, so an error in what ought to be
//! checked is reproduced faithfully on both sides and passes here.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_groth16::ProvingKey;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::ConstraintSynthesizer;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use shielded_pool_ceremony::contribution::{
    challenge_point, contribute, finalise, verify_chain, Contribution, Transcript,
};
use shielded_pool_ceremony::crosscheck::{verify_chain_with_blst, Weights};
use shielded_pool_ceremony::entropy::{Entropy, OperatingSystem};
use shielded_pool_ceremony::verify::slice_from_known_secrets;
use shielded_pool_ceremony::{lagrange, phase2, Result};

/// A repeatable source, test-only. The library has none, by design.
struct Repeatable(ChaCha20Rng);

impl Repeatable {
    fn from(label: &[u8; 32]) -> Self {
        Self(ChaCha20Rng::from_seed(*label))
    }
}

impl Entropy for Repeatable {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        self.0.fill_bytes(out);
        Ok(())
    }
}

#[derive(Clone)]
struct Tiny;

impl ConstraintSynthesizer<Fr> for Tiny {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        use ark_r1cs_std::alloc::AllocVar;
        use ark_r1cs_std::eq::EqGadget;
        use ark_r1cs_std::fields::fp::FpVar;

        let a = FpVar::new_input(cs.clone(), || Ok(Fr::from(3u64)))?;
        let b = FpVar::new_input(cs.clone(), || Ok(Fr::from(5u64)))?;
        let product = FpVar::new_input(cs.clone(), || Ok(Fr::from(15u64)))?;
        (&a * &b).enforce_equal(&product)?;

        let mut running = a;
        for i in 0..5 {
            let next = FpVar::new_witness(cs.clone(), || Ok(Fr::from(i as u64 + 2)))?;
            running = &running * &next;
        }
        let target = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64)))?;
        (&running * &target).enforce_equal(&running)?;
        Ok(())
    }
}

fn starting_key() -> ProvingKey<Bls12_381> {
    let (matrices, instance, _) = phase2::matrices(Tiny).expect("the circuit's matrices");
    let size = Radix2EvaluationDomain::<Fr>::new(matrices.num_constraints + instance)
        .expect("a domain")
        .size();
    let mut secrets = ChaCha20Rng::from_seed(*b"test-only-crosscheck-phase1-001!");
    let tau = Fr::rand(&mut secrets);
    let alpha = Fr::rand(&mut secrets);
    let beta = Fr::rand(&mut secrets);
    let srs = lagrange::transform(&slice_from_known_secrets(size, tau, alpha, beta))
        .expect("the Lagrange basis");
    phase2::initial(&srs, Tiny).expect("the starting key")
}

/// Both verdicts, for the same chain.
///
/// Each side draws or is given its own batching weights. That is deliberate:
/// two implementations agreeing under *independently drawn* weights is
/// stronger than agreeing under one weighting, and a batched check that only
/// worked for particular weights would show up as a disagreement.
fn both(
    initial: &ProvingKey<Bls12_381>,
    final_key: &ProvingKey<Bls12_381>,
    contributions: &[Contribution],
) -> (bool, bool) {
    let arkworks = verify_chain(initial, final_key, contributions, &mut OperatingSystem).is_ok();
    let weights = Weights::draw(final_key, &mut OperatingSystem).expect("weights");
    let blst = verify_chain_with_blst(initial, final_key, contributions, &weights).is_ok();
    (arkworks, blst)
}

/// Asserts agreement, and says what the expected verdict was so a failure
/// distinguishes "they disagree" from "both are wrong".
#[track_caller]
fn agree(
    what: &str,
    expected: bool,
    initial: &ProvingKey<Bls12_381>,
    final_key: &ProvingKey<Bls12_381>,
    contributions: &[Contribution],
) {
    let (arkworks, blst) = both(initial, final_key, contributions);
    assert_eq!(
        arkworks, blst,
        "{what}: arkworks says {arkworks} and blst says {blst}; one of the two pairing \
         implementations is wrong"
    );
    assert_eq!(arkworks, expected, "{what}: both agreed on {arkworks}, and {expected} was right");
}

/// A 32-byte test seed from a readable name, zero-padded.
///
/// Every seed in this file is the test's own and is meant to be legible: a
/// failure names the chain it came from. The library has no seeded entropy at
/// all, so nothing here is reachable from anything that ships.
fn label(name: &str) -> [u8; 32] {
    let mut out = [b'-'; 32];
    let bytes = name.as_bytes();
    assert!(bytes.len() <= 32, "a test label longer than a seed: {name}");
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

fn run(count: usize, label: &[u8; 32]) -> (ProvingKey<Bls12_381>, Vec<Contribution>) {
    let mut key = starting_key();
    let mut transcript = Transcript::begin(&key).expect("a transcript");
    let mut source = Repeatable::from(label);
    let mut published = Vec::new();
    for _ in 0..count {
        let contribution = contribute(&mut key, &transcript, &mut source).expect("a contribution");
        transcript = transcript.extend(&contribution);
        published.push(contribution);
    }
    (key, published)
}

// ------------------------------------------------------------- the honest side

/// Without this the refusals below would all agree for two implementations
/// that refuse everything.
#[test]
fn both_accept_an_honest_chain() {
    for count in 1..=3 {
        let (key, published) = run(count, &label(&format!("cross-honest-{count}")));
        agree(&format!("an honest chain of {count}"), true, &starting_key(), &key, &published);
    }
}

#[test]
fn both_accept_a_chain_that_ends_in_a_beacon() {
    let initial = starting_key();
    let mut key = initial.clone();
    let mut transcript = Transcript::begin(&key).expect("a transcript");
    let first = contribute(
        &mut key,
        &transcript,
        &mut Repeatable::from(b"cross-beacon-0000000000000000001"),
    )
    .expect("a contribution");
    transcript = transcript.extend(&first);
    let ending = finalise(
        &mut key,
        &transcript,
        b"a stand-in beacon output, long enough to clear the floor",
    )
    .expect("the beacon step");
    agree("a chain ending in a beacon", true, &initial, &key, &[first, ending]);
}

// ---------------------------------------------------------------- the forgeries

/// Each of these is a chain the audit has to refuse, and the assertion is that
/// **both** refuse it. A forgery one library catches and the other does not is
/// the finding this file exists for.
#[test]
fn both_refuse_every_forgery() {
    let initial = starting_key();

    // An empty chain: delta is one and known to everyone.
    agree("an empty chain", false, &initial, &initial.clone(), &[]);

    let (key, published) = run(3, b"cross-forgery-000000000000000001");

    // Reordered.
    let reordered = vec![published[1].clone(), published[0].clone(), published[2].clone()];
    agree("a reordered chain", false, &initial, &key, &reordered);

    // One dropped.
    let dropped = vec![published[0].clone(), published[2].clone()];
    agree("a chain with its middle removed", false, &initial, &key, &dropped);

    // A final key that is not the chain's end.
    let (other, _) = run(3, b"cross-forgery-000000000000000002");
    agree("a final key from elsewhere", false, &initial, &other, &published);

    // A query divided by something else.
    let mut mangled = key.clone();
    let mut rng = ChaCha20Rng::from_seed(*b"cross-forgery-scalar-00000000001");
    mangled.l_query[0] = (mangled.l_query[0] * Fr::rand(&mut rng)).into_affine();
    agree("a mis-divided L query", false, &initial, &mangled, &published);

    let mut mangled = key.clone();
    mangled.h_query[3] = (mangled.h_query[3] * Fr::rand(&mut rng)).into_affine();
    agree("a mis-divided H query", false, &initial, &mangled, &published);

    // A section a contribution may not touch.
    let mut mangled = key.clone();
    mangled.a_query[1] = (mangled.a_query[1] + mangled.a_query[1]).into_affine();
    agree("a moved A query", false, &initial, &mangled, &published);

    // A starting key that is not the ceremony's start.
    agree("an anchor part-way through", false, &key, &key.clone(), &published);
}

/// The hand-built forgeries: one knob turned at a time, so each reaches a
/// single check. Both implementations have to refuse each of them, which is
/// what says the two agree about *which* check objects rather than only about
/// the verdict.
#[test]
fn both_refuse_a_forgery_aimed_at_each_check() {
    let initial = starting_key();
    let transcript = Transcript::begin(&initial).expect("a transcript");
    let mut rng = ChaCha20Rng::from_seed(*b"cross-knobs-00000000000000000001");

    let forge = |delta_g1: Fr, delta_g2: Fr, pok_g1: Fr, pok_g2: Fr, blind: Fr| -> Contribution {
        let s = (G1Affine::generator() * blind).into_affine();
        let s_delta = (s * pok_g1).into_affine();
        let challenge = challenge_point(&transcript, &s, &s_delta).expect("a challenge");
        Contribution {
            delta_g1: (initial.delta_g1 * delta_g1).into_affine(),
            delta_g2: (initial.vk.delta_g2 * delta_g2).into_affine(),
            s,
            s_delta,
            r_delta: (challenge * pok_g2).into_affine(),
        }
    };
    let key_for = |contribution: &Contribution, divisor: Fr| -> ProvingKey<Bls12_381> {
        use ark_ff::Field;
        let inverse = divisor.inverse().expect("a non-zero divisor");
        let mut key = initial.clone();
        key.l_query = key.l_query.iter().map(|p| (*p * inverse).into_affine()).collect();
        key.h_query = key.h_query.iter().map(|p| (*p * inverse).into_affine()).collect();
        key.delta_g1 = contribution.delta_g1;
        key.vk.delta_g2 = contribution.delta_g2;
        key
    };

    let one = Fr::rand(&mut rng);
    let other = Fr::rand(&mut rng);
    let blind = Fr::rand(&mut rng);
    assert_ne!(one, other);

    // Honest, hand-built. The baseline: without it the three below would agree
    // for two implementations that refuse anything hand-built.
    let honest = forge(one, one, one, one, blind);
    agree("an honest hand-built chain", true, &initial, &key_for(&honest, one), &[honest]);

    // The chain link: delta moved by a scalar the proof is not about.
    let mismatched = forge(one, one, other, other, blind);
    agree(
        "a delta the proof is not about",
        false,
        &initial,
        &key_for(&mismatched, one),
        &[mismatched],
    );

    // The proof of knowledge: one scalar in G1, another in G2.
    let split_proof = forge(other, other, one, other, blind);
    agree(
        "a proof that disagrees between the groups",
        false,
        &initial,
        &key_for(&split_proof, other),
        &[split_proof],
    );

    // The cross-group check: delta differs between the groups, with the
    // queries matching G2 so the batched check passes.
    let split_delta = forge(one, other, one, one, blind);
    agree(
        "a delta that differs between the groups",
        false,
        &initial,
        &key_for(&split_delta, other),
        &[split_delta],
    );
}

/// Differential, over many perturbations of one honest chain.
///
/// The cases above are the ones somebody thought of. This one changes a point
/// at a time, in places nobody reasoned about, and requires the two
/// implementations to agree on every single verdict. Most of these are
/// refused for dull reasons; what matters is that they are refused by both.
#[test]
fn the_two_agree_on_every_perturbation() {
    let initial = starting_key();
    let (key, published) = run(2, b"cross-differential-0000000000001");
    agree("the chain being perturbed", true, &initial, &key, &published);

    let mut rng = ChaCha20Rng::from_seed(*b"cross-differential-scalars-00001");
    let mut checked = 0usize;

    for round in 0..6 {
        let factor = Fr::rand(&mut rng);

        // Each field of each contribution, scaled.
        for index in 0..published.len() {
            for field in 0..5 {
                let mut forged = published.clone();
                let target = &mut forged[index];
                match field {
                    0 => target.delta_g1 = (target.delta_g1 * factor).into_affine(),
                    1 => target.delta_g2 = (target.delta_g2 * factor).into_affine(),
                    2 => target.s = (target.s * factor).into_affine(),
                    3 => target.s_delta = (target.s_delta * factor).into_affine(),
                    _ => target.r_delta = (target.r_delta * factor).into_affine(),
                }
                agree(
                    &format!("round {round}, contribution {index}, field {field}"),
                    false,
                    &initial,
                    &key,
                    &forged,
                );
                checked += 1;
            }
        }

        // And the key's own sections.
        let mut mangled = key.clone();
        let position = round % mangled.l_query.len();
        mangled.l_query[position] = (mangled.l_query[position] * factor).into_affine();
        agree(&format!("round {round}, an L query"), false, &initial, &mangled, &published);
        checked += 1;

        let mut mangled = key.clone();
        mangled.vk.delta_g2 = (mangled.vk.delta_g2 * factor).into_affine();
        agree(&format!("round {round}, the key's delta_g2"), false, &initial, &mangled, &published);
        checked += 1;
    }

    assert_eq!(checked, 6 * (2 * 5 + 2), "the sweep did not cover what it claims");
    eprintln!("{checked} perturbations, two implementations, no disagreement");
}

/// The batching weights are what makes the query check a check.
///
/// Every other forgery in this file scales a single query point, and an
/// **unweighted** sum catches those just as well -- which is why dropping the
/// scalar multiplication from the blst implementation left the whole suite
/// green, and why nothing here had ever shown the weights doing anything.
///
/// A compensating pair is the case they exist for: add a point to one query
/// entry and subtract it from another. The plain sum is unchanged, so a check
/// that summed without weights would accept a key whose entries are wrong.
/// Weighted, the two sides differ by `(rho_i - rho_j) * v`, which is zero only
/// if the verifier happened to draw `rho_i == rho_j`.
///
/// This is also the reason the weights must be drawn *after* the key exists.
/// A forger who knew them would scale the second term by `rho_i / rho_j` and
/// pass.
#[test]
fn the_weights_are_what_catches_a_compensating_pair() {
    use ark_bls12_381::G1Projective;
    use ark_ff::Zero;

    let initial = starting_key();
    let (key, published) = run(2, b"cross-compensating-pair-00000001");
    agree("the chain being perturbed", true, &initial, &key, &published);

    let mut rng = ChaCha20Rng::from_seed(*b"cross-compensating-scalar-000001");
    let shift = (G1Affine::generator() * Fr::rand(&mut rng)).into_affine();

    let mut mangled = key.clone();
    assert!(mangled.l_query.len() >= 2, "this circuit has too few L query points to pair up");
    mangled.l_query[0] = (mangled.l_query[0] + shift).into_affine();
    mangled.l_query[1] = (mangled.l_query[1].into_group() - shift).into_affine();

    // The forgery really is invisible to an unweighted sum, which is what
    // makes it evidence about the weights rather than about anything else.
    let plain = |query: &[G1Affine]| {
        query.iter().fold(G1Projective::zero(), |total, point| total + point).into_affine()
    };
    assert_eq!(
        plain(&key.l_query),
        plain(&mangled.l_query),
        "the compensating pair did not compensate, so this tests nothing about weights"
    );
    assert_ne!(key.l_query, mangled.l_query, "nothing was actually changed");

    agree("a compensating pair in the L query", false, &initial, &mangled, &published);

    // And the same in the H query, which is a separate batched check.
    let mut mangled = key.clone();
    mangled.h_query[0] = (mangled.h_query[0] + shift).into_affine();
    mangled.h_query[1] = (mangled.h_query[1].into_group() - shift).into_affine();
    assert_eq!(plain(&key.h_query), plain(&mangled.h_query), "the H pair did not compensate");
    agree("a compensating pair in the H query", false, &initial, &mangled, &published);
}

/// The identity is the point most likely to be handled differently by two
/// libraries, and a pairing against it is trivially satisfied.
#[test]
fn both_refuse_a_contribution_built_from_the_identity() {
    let initial = starting_key();
    let (key, published) = run(1, b"cross-identity-00000000000000001");

    for field in 0..5 {
        let mut forged = published.clone();
        match field {
            0 => forged[0].delta_g1 = G1Affine::identity(),
            1 => forged[0].delta_g2 = G2Affine::identity(),
            2 => forged[0].s = G1Affine::identity(),
            3 => forged[0].s_delta = G1Affine::identity(),
            _ => forged[0].r_delta = G2Affine::identity(),
        }
        agree(&format!("the identity in field {field}"), false, &initial, &key, &forged);
    }
}
