/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Does a contribution do what it claims, and does the verifier catch one that
//! does not?
//!
//! The first stage of phase 2 could be checked by equality against
//! `ark-groth16`. This one cannot: arkworks has no multi-party setup, so there
//! is nothing to agree with. What can be checked is the pair of properties the
//! construction exists for, and both are testable:
//!
//! * **liveness** -- after contributions the key still proves, and proofs
//!   still verify, over the circuit it was built for;
//! * **soundness of the verifier** -- every way of cheating that does not
//!   require breaking a discrete log is tried here, one mutation at a time,
//!   and has to be refused.
//!
//! The second list is the one worth reading. Each case below is an attack a
//! participant could actually mount with nothing but the public state: keep
//! the secret instead of destroying it (not detectable, and not claimed),
//! scale `delta` but divide the queries by something else, take somebody
//! else's proof, use a proof at the wrong position, alter a part of the key
//! that is not `delta`. A verifier that passes all of these still proves
//! nothing about how the secret was drawn -- that is stated in the library and
//! not testable anywhere.
//!
//! # Every secret in this file is a test secret
//!
//! The [`Repeatable`] source below exists so failures are reproducible. It is
//! defined *here*, in the test crate, because the library deliberately has no
//! seeded entropy source: there is no way to reach this from a shipped binary.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, ProvingKey};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_snark::SNARK;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use shielded_pool_ceremony::contribution::{
    challenge_point, contribute, finalise, verify_beacon_step, verify_chain, verify_step,
    Contribution, Transcript, CONTRIBUTION_BYTES, MINIMUM_BEACON_BYTES,
};
use shielded_pool_ceremony::entropy::Entropy;
use shielded_pool_ceremony::verify::slice_from_known_secrets;
use shielded_pool_ceremony::{lagrange, phase2, Result};

/// A repeatable entropy source, for tests only.
///
/// The library has nothing like this on purpose. A ceremony run from a seed
/// has a secret anybody holding the seed can recompute, which is the exact
/// failure the whole of `entropy` and `secret` is arranged to prevent -- so
/// the seeded path lives in the test crate, where it cannot be called by
/// mistake from anything that ships.
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

/// Small enough to set up and prove in a second, with public inputs, because
/// the input-consistency points are among the things a contribution must not
/// touch.
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
        for i in 0..6 {
            let next = FpVar::new_witness(cs.clone(), || Ok(Fr::from(i as u64 + 2)))?;
            running = &running * &next;
        }
        let target = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64)))?;
        (&running * &target).enforce_equal(&running)?;
        Ok(())
    }
}

const PUBLIC_INPUTS: [u64; 3] = [3, 5, 15];

/// Publicly rescaling both proof points must invalidate their challenge.
/// The transformation uses only a published contribution, not its secret.
/// This demonstrates proof malleability if the points are omitted from the
/// challenge; it does not demonstrate recovery of the contribution scalar.
#[test]
fn publicly_rerandomizing_the_proof_points_is_rejected() {
    let initial = starting_key();
    let (key, contributions) = run(1, b"test-only-auditor-randomness-01!");
    verify_chain(&initial, &key, &contributions, &mut auditor())
        .expect("the unchanged published contribution must audit");
    let mut changed = contributions[0].clone();
    changed.s = (changed.s * Fr::from(2u64)).into_affine();
    changed.s_delta = (changed.s_delta * Fr::from(2u64)).into_affine();
    assert!(changed.to_bytes() != contributions[0].to_bytes());
    let transcript = Transcript::begin(&initial).expect("the opening transcript");
    let error = verify_step(&initial, &key, &changed, &transcript, &mut auditor())
        .expect_err("a publicly rerandomized proof was accepted");
    assert!(format!("{error}").contains("proof of knowledge"), "{error}");
    let error = verify_chain(&initial, &key, &[changed], &mut auditor())
        .expect_err("the audit accepted a publicly rerandomized proof");
    assert!(format!("{error}").contains("proof of knowledge"), "{error}");
}

/// The key a ceremony over [`Tiny`] starts from.
///
/// Built through the real path -- a reference string, the Lagrange transform,
/// then [`phase2::initial`] -- because a contribution applied to a hand-made
/// key would not be evidence about the one a ceremony would use.
fn starting_key() -> ProvingKey<Bls12_381> {
    let (matrices, instance, _) = phase2::matrices(Tiny).expect("the circuit's matrices");
    let wanted = matrices.num_constraints + instance;
    let size = Radix2EvaluationDomain::<Fr>::new(wanted).expect("a domain").size();

    let mut secrets = ChaCha20Rng::from_seed(*b"test-only-phase1-secrets-000001!");
    let tau = Fr::rand(&mut secrets);
    let alpha = Fr::rand(&mut secrets);
    let beta = Fr::rand(&mut secrets);
    let srs = lagrange::transform(&slice_from_known_secrets(size, tau, alpha, beta))
        .expect("the Lagrange basis");
    phase2::initial(&srs, Tiny).expect("the starting key")
}

/// Does this key prove, and does the proof verify?
fn the_key_works(key: &ProvingKey<Bls12_381>) -> bool {
    let mut rng = ChaCha20Rng::from_seed(*b"test-only-proving-randomness-01!");
    let Ok(proof) = Groth16::<Bls12_381>::prove(key, Tiny, &mut rng) else {
        return false;
    };
    let inputs: Vec<Fr> = PUBLIC_INPUTS.iter().map(|value| Fr::from(*value)).collect();
    Groth16::<Bls12_381>::verify(&key.vk, &inputs, &proof).unwrap_or(false)
}

/// A ceremony of `count` contributions, returning the finished key and the
/// published record.
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

fn auditor() -> Repeatable {
    Repeatable::from(b"test-only-auditor-randomness-01!")
}

/// An entropy source that records how much was asked of it.
///
/// A verifier that batches against weights it did not draw is verifying
/// against weights the key's author could have known, which is not a check at
/// all. Nothing else in this file can observe that, so it is observed here.
struct Counting {
    inner: Repeatable,
    bytes: usize,
}

impl Entropy for Counting {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        self.bytes += out.len();
        self.inner.fill(out)
    }
}

// ---------------------------------------------------------------- liveness

/// The starting key proves, so a later failure is about the contribution and
/// not about the key it was applied to.
#[test]
fn the_starting_key_already_proves() {
    assert!(the_key_works(&starting_key()), "the key a ceremony starts from does not prove");
}

#[test]
fn a_key_still_proves_after_one_contribution() {
    let (key, _) = run(1, b"test-only-ceremony-liveness-01!!");
    assert!(the_key_works(&key), "the key stopped proving after a contribution");
}

/// Three participants, which is where an error in the order of multiplication
/// or division would show and a single step would not.
#[test]
fn and_after_three() {
    let (key, _) = run(3, b"test-only-ceremony-liveness-03!!");
    assert!(the_key_works(&key), "the key stopped proving after three contributions");
}

/// `delta` actually moved, and moved again. Without this the liveness tests
/// above would pass for a `contribute` that did nothing at all.
#[test]
fn each_contribution_moves_delta() {
    let (_, published) = run(3, b"test-only-ceremony-deltas-0003!!");
    assert_ne!(published[0].delta_g1, G1Affine::generator(), "the first contribution did nothing");
    assert_ne!(published[0].delta_g1, published[1].delta_g1, "the second repeated the first");
    assert_ne!(published[1].delta_g1, published[2].delta_g1, "the third repeated the second");
}

// ---------------------------------------------------------------- the audit

#[test]
fn an_honest_step_verifies() {
    let mut key = starting_key();
    let before = key.clone();
    let transcript = Transcript::begin(&key).expect("a transcript");
    let mut source = Repeatable::from(b"test-only-ceremony-one-step-01!!");
    let contribution = contribute(&mut key, &transcript, &mut source).expect("a contribution");
    verify_step(&before, &key, &contribution, &transcript, &mut auditor())
        .expect("an honest step was rejected");
}

/// The audit a later reader runs: the starting key they rebuilt themselves,
/// the published contributions, and the key in use. No intermediate keys.
#[test]
fn a_whole_chain_verifies_without_the_intermediate_keys() {
    let (key, published) = run(4, b"test-only-ceremony-chain-0004!!!");
    verify_chain(&starting_key(), &key, &published, &mut auditor())
        .expect("an honest chain was rejected");
}

#[test]
fn a_ceremony_with_no_contributions_is_refused() {
    let key = starting_key();
    assert!(
        verify_chain(&key, &key, &[], &mut auditor()).is_err(),
        "a chain of nothing was accepted, and its delta is one"
    );
}

// ------------------------------------------------------------ the mutations

/// Every one of these is a cheat available to a participant from public data
/// alone.
fn rejected(what: &str, result: Result<()>) {
    match result {
        Ok(()) => panic!("{what} was accepted"),
        Err(error) => {
            let message = format!("{error}");
            assert!(!message.is_empty(), "{what} was rejected without saying why");
        }
    }
}

/// Scale `delta` honestly, divide the queries by something else. This is the
/// cheat that matters most: it leaves a key of the right shape, with a `delta`
/// that chains correctly, and it is why the batched query check exists.
#[test]
fn queries_divided_by_a_different_scalar_are_caught() {
    let mut key = starting_key();
    let before = key.clone();
    let transcript = Transcript::begin(&key).expect("a transcript");
    let mut source = Repeatable::from(b"test-only-attack-wrong-divisor1!");
    let contribution = contribute(&mut key, &transcript, &mut source).expect("a contribution");

    // The honest key is the baseline, so the rejection below is about the
    // mutation and not about the setup.
    verify_step(&before, &key, &contribution, &transcript, &mut auditor())
        .expect("the honest step should verify");

    let mut rng = ChaCha20Rng::from_seed(*b"test-only-attack-scalar-00000001");
    let other = Fr::rand(&mut rng);
    key.l_query[0] = (key.l_query[0] * other).into_affine();
    rejected(
        "a key with one L query scaled by an unrelated factor",
        verify_step(&before, &key, &contribution, &transcript, &mut auditor()),
    );
}

/// And the same mutation is not merely detected -- it breaks the key, which is
/// why detecting it is worth the pairings.
#[test]
fn a_key_with_a_mis_divided_query_does_not_prove() {
    let (mut key, _) = run(1, b"test-only-attack-broken-key-01!!");
    assert!(the_key_works(&key), "the honest key should prove");
    let mut rng = ChaCha20Rng::from_seed(*b"test-only-attack-scalar-00000002");
    key.l_query[0] = (key.l_query[0] * Fr::rand(&mut rng)).into_affine();
    assert!(!the_key_works(&key), "a key with a mis-divided L query still produced a valid proof");
}

#[test]
fn the_h_query_is_checked_too() {
    let mut key = starting_key();
    let before = key.clone();
    let transcript = Transcript::begin(&key).expect("a transcript");
    let mut source = Repeatable::from(b"test-only-attack-h-query-00001!!");
    let contribution = contribute(&mut key, &transcript, &mut source).expect("a contribution");
    let mut rng = ChaCha20Rng::from_seed(*b"test-only-attack-scalar-00000003");
    key.h_query[7] = (key.h_query[7] * Fr::rand(&mut rng)).into_affine();
    rejected(
        "a key with one H query scaled",
        verify_step(&before, &key, &contribution, &transcript, &mut auditor()),
    );
}

/// `delta` in the two groups must be the same scalar. A participant who scales
/// G1 by one factor and G2 by another gets a key nobody can use and a proof of
/// knowledge that still passes on its own.
#[test]
fn a_delta_that_disagrees_between_the_groups_is_caught() {
    let mut key = starting_key();
    let before = key.clone();
    let transcript = Transcript::begin(&key).expect("a transcript");
    let mut source = Repeatable::from(b"test-only-attack-split-delta-01!");
    let mut contribution = contribute(&mut key, &transcript, &mut source).expect("a contribution");

    let mut rng = ChaCha20Rng::from_seed(*b"test-only-attack-scalar-00000004");
    let other = Fr::rand(&mut rng);
    key.vk.delta_g2 = (key.vk.delta_g2 * other).into_affine();
    contribution.delta_g2 = key.vk.delta_g2;
    rejected(
        "a delta scaled differently in G1 and G2",
        verify_step(&before, &key, &contribution, &transcript, &mut auditor()),
    );
}

/// The proof of knowledge is about a scalar; the key must have moved by *that*
/// scalar. Here the participant proves knowledge of one factor and applies
/// another.
#[test]
fn a_proof_about_a_different_scalar_is_caught() {
    let mut first = starting_key();
    let before = first.clone();
    let transcript = Transcript::begin(&first).expect("a transcript");

    let honest = contribute(
        &mut first,
        &transcript,
        &mut Repeatable::from(b"test-only-attack-swapped-pok-01!"),
    )
    .expect("a contribution");

    // A second, independent contribution to the same starting key: its proof
    // is internally valid and about a different secret.
    let mut second = before.clone();
    let elsewhere = contribute(
        &mut second,
        &transcript,
        &mut Repeatable::from(b"test-only-attack-swapped-pok-02!"),
    )
    .expect("a contribution");

    let forged = Contribution {
        s: elsewhere.s,
        s_delta: elsewhere.s_delta,
        r_delta: elsewhere.r_delta,
        ..honest
    };
    rejected(
        "a key moved by one scalar with a proof of knowledge about another",
        verify_step(&before, &first, &forged, &transcript, &mut auditor()),
    );
}

/// A proof is bound to its position. Contribution two's proof, presented as
/// contribution one's, hashes to a different challenge point and fails -- this
/// is what stops a chain being reordered or an entry being dropped.
#[test]
fn a_proof_from_another_position_is_caught() {
    let (_, published) = run(2, b"test-only-attack-reorder-0002!!!");
    let initial = starting_key();
    let swapped = vec![published[1].clone(), published[0].clone()];
    rejected(
        "a reordered chain",
        verify_chain(&initial, &starting_key(), &swapped, &mut auditor()),
    );
}

#[test]
fn a_dropped_contribution_is_caught() {
    let (key, published) = run(3, b"test-only-attack-dropped-0003!!!");
    let missing_middle = vec![published[0].clone(), published[2].clone()];
    rejected(
        "a chain with its middle removed",
        verify_chain(&starting_key(), &key, &missing_middle, &mut auditor()),
    );
}

/// A contribution lifted from a ceremony over a *different* starting key --
/// another circuit, or the same circuit over a different phase-1 slice. The
/// transcript opens on the starting key, so the challenge differs and the
/// proof does not transfer.
#[test]
fn a_contribution_from_another_ceremony_is_caught() {
    let (_, elsewhere) = run(1, b"test-only-attack-other-chain-01!");

    // A different starting key: same circuit, different phase-1 secrets.
    let different = {
        let (matrices, instance, _) = phase2::matrices(Tiny).expect("matrices");
        let size = Radix2EvaluationDomain::<Fr>::new(matrices.num_constraints + instance)
            .expect("a domain")
            .size();
        let mut secrets = ChaCha20Rng::from_seed(*b"test-only-phase1-secrets-000002!");
        let tau = Fr::rand(&mut secrets);
        let alpha = Fr::rand(&mut secrets);
        let beta = Fr::rand(&mut secrets);
        let srs = lagrange::transform(&slice_from_known_secrets(size, tau, alpha, beta))
            .expect("a basis");
        phase2::initial(&srs, Tiny).expect("another starting key")
    };
    assert_ne!(different.l_query, starting_key().l_query, "the two ceremonies share a key");

    rejected(
        "a contribution carried over from a ceremony with a different starting key",
        verify_chain(&different, &different, &elsewhere, &mut auditor()),
    );
}

/// A participant who changes something that is not `delta` is substituting a
/// different circuit, however valid their proof of knowledge is.
#[test]
fn touching_anything_but_delta_is_caught() {
    let base = starting_key();
    let transcript = Transcript::begin(&base).expect("a transcript");

    let mutations: Vec<(&str, fn(&mut ProvingKey<Bls12_381>))> = vec![
        ("alpha_g1", |key| key.vk.alpha_g1 = (key.vk.alpha_g1 + key.vk.alpha_g1).into_affine()),
        ("beta_g2", |key| key.vk.beta_g2 = (key.vk.beta_g2 + key.vk.beta_g2).into_affine()),
        ("gamma_g2", |key| key.vk.gamma_g2 = (key.vk.gamma_g2 + key.vk.gamma_g2).into_affine()),
        ("an input-consistency point", |key| {
            key.vk.gamma_abc_g1[1] = (key.vk.gamma_abc_g1[1] + key.vk.gamma_abc_g1[1]).into_affine()
        }),
        ("beta_g1", |key| key.beta_g1 = (key.beta_g1 + key.beta_g1).into_affine()),
        ("a_query", |key| key.a_query[2] = (key.a_query[2] + key.a_query[2]).into_affine()),
        ("b_g1_query", |key| {
            key.b_g1_query[2] = (key.b_g1_query[2] + key.b_g1_query[2]).into_affine()
        }),
        ("b_g2_query", |key| {
            key.b_g2_query[2] = (key.b_g2_query[2] + key.b_g2_query[2]).into_affine()
        }),
    ];

    for (name, mutate) in mutations {
        let mut key = base.clone();
        let contribution = contribute(
            &mut key,
            &transcript,
            &mut Repeatable::from(b"test-only-attack-other-field-01!"),
        )
        .expect("a contribution");
        mutate(&mut key);
        rejected(
            &format!("a contribution that also changed {name}"),
            verify_step(&base, &key, &contribution, &transcript, &mut auditor()),
        );
    }
}

/// A "contribution" that left `delta` where it was. Harmless to everyone else,
/// but it is a participant appearing in the record who added nothing, and a
/// drawn secret cannot produce it.
#[test]
fn a_contribution_that_changed_nothing_is_refused() {
    let key = starting_key();
    let transcript = Transcript::begin(&key).expect("a transcript");
    let idle = Contribution {
        delta_g1: key.delta_g1,
        delta_g2: key.vk.delta_g2,
        s: G1Affine::generator(),
        s_delta: G1Affine::generator(),
        r_delta: G2Affine::generator(),
    };
    rejected(
        "a contribution that left delta alone",
        verify_step(&key, &key.clone(), &idle, &transcript, &mut auditor()),
    );
}

/// The final key has to be the one the chain ends at, not merely a key that
/// passes the query check.
#[test]
fn a_final_key_that_is_not_the_chains_is_caught() {
    let (key, published) = run(2, b"test-only-attack-wrong-final-1!!");
    let (other, _) = run(2, b"test-only-attack-wrong-final-2!!");
    assert_ne!(key.delta_g1, other.delta_g1, "the two ceremonies produced one delta");
    rejected(
        "a key from a different ceremony presented as this chain's result",
        verify_chain(&starting_key(), &other, &published, &mut auditor()),
    );
}

// --------------------------------------------------------- the wire format

#[test]
fn a_contribution_round_trips() {
    let (_, published) = run(1, b"test-only-wire-format-roundtrip!");
    let bytes = published[0].to_bytes();
    assert_eq!(bytes.len(), CONTRIBUTION_BYTES);
    assert_eq!(CONTRIBUTION_BYTES, 672, "the published width moved");
    let read = Contribution::from_bytes(&bytes).expect("the bytes parse");
    assert_eq!(read, published[0], "a contribution did not survive its own encoding");
}

#[test]
fn a_corrupt_contribution_is_refused_rather_than_misread() {
    let (_, published) = run(1, b"test-only-wire-format-corrupt-1!");
    let mut bytes = published[0].to_bytes();
    bytes[10] ^= 0x01;
    assert!(Contribution::from_bytes(&bytes).is_err(), "a point off the curve was read as a point");
    assert!(
        Contribution::from_bytes(&bytes[..CONTRIBUTION_BYTES - 1]).is_err(),
        "a truncated contribution was accepted"
    );
}

/// The transcript is the thing two implementations have to agree on, so it is
/// a function of the published bytes and nothing else.
#[test]
fn the_transcript_is_determined_by_what_is_published() {
    let (_, published) = run(2, b"test-only-transcript-determined!");
    let initial = starting_key();

    let replay = |list: &[Contribution]| {
        let mut transcript = Transcript::begin(&initial).expect("a transcript");
        for contribution in list {
            transcript = transcript.extend(contribution);
        }
        transcript.digest()
    };

    assert_eq!(replay(&published), replay(&published), "the transcript is not a function");
    assert_ne!(
        replay(&published[..1]),
        replay(&published),
        "absorbing a second contribution left the transcript where it was"
    );

    let reversed = vec![published[1].clone(), published[0].clone()];
    assert_ne!(replay(&reversed), replay(&published), "the transcript does not depend on order");

    // And it depends on the whole prefix, not only on the newest entry. A
    // transcript that hashed just the last contribution would give these two
    // the same digest, and every assertion above would still pass.
    let prefixed = vec![published[1].clone(), published[0].clone()];
    assert_ne!(
        replay(&published[..1]),
        replay(&prefixed[..2]),
        "the transcript forgets what came before its newest entry"
    );
}

// ------------------------------------------- checks that others would shadow
//
// Each test below exists because a mutation of the library survived the tests
// above: the attack was caught, but by a different check than the one being
// tested. A check nothing can fail is not a check, so these are built to reach
// exactly one of them, with everything else about the contribution honest.

/// The transcript is what binds a proof to its position. Everything here is a
/// genuine contribution; only the record it is checked against is the wrong
/// one.
///
/// The reorder and other-ceremony tests above do not establish this. Both are
/// caught by the delta chain before the transcript is consulted, so a build
/// whose challenge ignored the transcript entirely still passed them.
#[test]
fn a_step_checked_against_the_wrong_transcript_is_rejected() {
    let mut key = starting_key();
    let before = key.clone();
    let transcript = Transcript::begin(&key).expect("a transcript");
    let contribution = contribute(
        &mut key,
        &transcript,
        &mut Repeatable::from(b"test-only-transcript-binding-01!"),
    )
    .expect("a contribution");

    verify_step(&before, &key, &contribution, &transcript, &mut auditor())
        .expect("the honest step should verify against its own transcript");

    // The same contribution, the same keys, a transcript from one entry later.
    let later = transcript.extend(&contribution);
    rejected(
        "an honest contribution checked against a transcript it was not made against",
        verify_step(&before, &key, &contribution, &later, &mut auditor()),
    );
}

/// A contribution whose secret is one: the key is untouched, and the proof of
/// knowledge is **genuine** -- `s_delta = s` and `r_delta = h` is what a
/// contribution with `d = 1` looks like, and it satisfies every pairing in the
/// verifier.
///
/// [`contribute`] cannot produce this, because [`Secret`] refuses a scalar of
/// one. It is built by hand here because that is the only way to reach the
/// check that catches it: a participant in the record who added nothing.
#[test]
fn a_genuine_contribution_of_one_is_refused() {
    let key = starting_key();
    let transcript = Transcript::begin(&key).expect("a transcript");

    let mut rng = ChaCha20Rng::from_seed(*b"test-only-identity-contribution1");
    let s = (G1Affine::generator() * Fr::rand(&mut rng)).into_affine();
    let idle = Contribution {
        delta_g1: key.delta_g1,
        delta_g2: key.vk.delta_g2,
        s,
        // d = 1: the scaled point is the point.
        s_delta: s,
        r_delta: challenge_point(&transcript, &s, &s).expect("a challenge"),
    };

    rejected(
        "a contribution whose secret is one, with a proof of knowledge that genuinely verifies",
        verify_step(&key, &key.clone(), &idle, &transcript, &mut auditor()),
    );
    rejected(
        "the same, presented as a whole ceremony",
        verify_chain(&key, &key.clone(), &[idle], &mut auditor()),
    );
}

/// The batched query check is only a check if its weights are unpredictable to
/// whoever built the key. A verifier that derived them from the key, or from a
/// constant, could be passed by a key crafted with two compensating errors.
///
/// Nothing observable distinguishes good weights from bad ones, so what is
/// asserted is the thing that can be: the verifier asks its caller for
/// randomness.
#[test]
fn verification_draws_its_weights_from_the_caller() {
    let mut key = starting_key();
    let before = key.clone();
    let transcript = Transcript::begin(&key).expect("a transcript");
    let contribution = contribute(
        &mut key,
        &transcript,
        &mut Repeatable::from(b"test-only-weights-are-drawn-001!"),
    )
    .expect("a contribution");

    let mut counted =
        Counting { inner: Repeatable::from(b"test-only-weights-auditor-0001!!"), bytes: 0 };
    verify_step(&before, &key, &contribution, &transcript, &mut counted)
        .expect("the honest step should verify");
    assert!(
        counted.bytes >= 32,
        "the verifier batched against weights it did not draw ({} bytes asked for)",
        counted.bytes
    );

    let mut counted =
        Counting { inner: Repeatable::from(b"test-only-weights-auditor-0002!!"), bytes: 0 };
    verify_chain(&before, &key, &[contribution], &mut counted).expect("the chain should verify");
    assert!(counted.bytes >= 32, "the chain audit batched against weights it did not draw");
}

// -------------------------------------------------- one thing wrong at a time
//
// The tests above all go through `contribute`, which means every contribution
// in them is internally consistent and a mutation can only be reached if no
// earlier check happens to catch the same thing first. Several did not survive
// that: removing the chain link, the proof-of-knowledge pairing or the
// cross-group check left every test above green, because the transcript or the
// query check caught the attack instead.
//
// So these build a contribution by hand, with a separate knob for each
// quantity that a check compares, and turn exactly one of them. The secrets
// here are the test's own and are chosen, not drawn -- which is precisely what
// `contribute` must never do, and precisely what is needed to reach a single
// check in isolation.

/// A contribution assembled from chosen scalars.
///
/// An honest contribution has all four factors equal. Each one that differs
/// breaks exactly one comparison in the verifier:
///
/// * `delta_g1` -- the scalar the published `delta` claims in G1, compared
///   against `pok_g2` by the chain link;
/// * `delta_g2` -- the same in G2, compared against `delta_g1` by the
///   cross-group check;
/// * `pok_g1` and `pok_g2` -- the scalars the proof of knowledge exhibits in
///   each group, compared against each other by the proof's own pairing.
struct Knobs {
    delta_g1: Fr,
    delta_g2: Fr,
    pok_g1: Fr,
    pok_g2: Fr,
}

impl Knobs {
    fn honest(factor: Fr) -> Self {
        Self { delta_g1: factor, delta_g2: factor, pok_g1: factor, pok_g2: factor }
    }
}

fn forge(
    transcript: &Transcript,
    previous_g1: G1Affine,
    previous_g2: G2Affine,
    knobs: &Knobs,
    label: &[u8; 32],
) -> Contribution {
    let mut rng = ChaCha20Rng::from_seed(*label);
    let s = (G1Affine::generator() * Fr::rand(&mut rng)).into_affine();
    let s_delta = (s * knobs.pok_g1).into_affine();
    let challenge = challenge_point(transcript, &s, &s_delta).expect("a challenge");
    Contribution {
        delta_g1: (previous_g1 * knobs.delta_g1).into_affine(),
        delta_g2: (previous_g2 * knobs.delta_g2).into_affine(),
        s,
        s_delta,
        r_delta: (challenge * knobs.pok_g2).into_affine(),
    }
}

/// The key that goes with a forged contribution: queries divided by
/// `divisor`, deltas taken from the contribution.
///
/// `divisor` is separate from the contribution's own factors because the query
/// check reads `delta` in G2 while the chain link reads it in G1, and a forgery
/// that keeps one of them satisfied has to divide by the matching scalar.
fn key_for(
    base: &ProvingKey<Bls12_381>,
    contribution: &Contribution,
    divisor: Fr,
) -> ProvingKey<Bls12_381> {
    use ark_ff::Field;
    let inverse = divisor.inverse().expect("a non-zero divisor");
    let mut key = base.clone();
    key.l_query = key.l_query.iter().map(|point| (*point * inverse).into_affine()).collect();
    key.h_query = key.h_query.iter().map(|point| (*point * inverse).into_affine()).collect();
    key.delta_g1 = contribution.delta_g1;
    key.vk.delta_g2 = contribution.delta_g2;
    key
}

fn two_scalars(label: &[u8; 32]) -> (Fr, Fr) {
    let mut rng = ChaCha20Rng::from_seed(*label);
    let first = Fr::rand(&mut rng);
    let mut second = Fr::rand(&mut rng);
    while second == first {
        second = Fr::rand(&mut rng);
    }
    (first, second)
}

/// The hand-built machinery agrees with the real one: an honest forgery is
/// accepted, and it proves.
///
/// Without this the four tests below would be evidence of nothing -- a forgery
/// rejected for a reason unrelated to the knob being turned looks exactly like
/// a check working.
#[test]
fn an_honest_hand_built_contribution_is_accepted() {
    let initial = starting_key();
    let transcript = Transcript::begin(&initial).expect("a transcript");
    let (factor, _) = two_scalars(b"test-only-handbuilt-honest-0001!");
    let contribution = forge(
        &transcript,
        initial.delta_g1,
        initial.vk.delta_g2,
        &Knobs::honest(factor),
        b"test-only-handbuilt-honest-0002!",
    );
    let key = key_for(&initial, &contribution, factor);

    verify_step(&initial, &key, &contribution, &transcript, &mut auditor())
        .expect("an honest hand-built step was rejected");
    verify_chain(&initial, &key, &[contribution], &mut auditor())
        .expect("an honest hand-built chain was rejected");
    assert!(the_key_works(&key), "the hand-built key does not prove");
}

/// `delta` moved by one scalar while the proof of knowledge is about another.
///
/// Everything else is consistent: the proof verifies on its own terms, the two
/// groups agree, the queries are divided by the scalar `delta` was multiplied
/// by, and the transcript is the right one. Only the link between the proof
/// and the key is broken -- which is the difference between a participant who
/// knows their secret and one who copied a `delta` from somewhere.
#[test]
fn a_delta_that_does_not_follow_from_the_proof_is_caught() {
    let initial = starting_key();
    let transcript = Transcript::begin(&initial).expect("a transcript");
    let (applied, proven) = two_scalars(b"test-only-handbuilt-chainlink01!");
    let knobs = Knobs { delta_g1: applied, delta_g2: applied, pok_g1: proven, pok_g2: proven };
    let contribution = forge(
        &transcript,
        initial.delta_g1,
        initial.vk.delta_g2,
        &knobs,
        b"test-only-handbuilt-chainlink02!",
    );
    let key = key_for(&initial, &contribution, applied);

    rejected(
        "a delta scaled by a scalar the proof of knowledge is not about",
        verify_step(&initial, &key, &contribution, &transcript, &mut auditor()),
    );
    rejected(
        "the same, audited as a chain",
        verify_chain(&initial, &key, &[contribution], &mut auditor()),
    );
}

/// The proof of knowledge is inconsistent between the groups, and nothing else
/// is wrong.
///
/// `delta` follows from `r_delta` exactly as it should, so the chain link
/// passes; the queries match; the groups agree. What is missing is the G1 half
/// of the proof -- the participant never demonstrates the scalar in the group
/// the extractor reads it from.
#[test]
fn a_proof_that_disagrees_between_the_groups_is_caught() {
    let initial = starting_key();
    let transcript = Transcript::begin(&initial).expect("a transcript");
    let (in_g1, in_g2) = two_scalars(b"test-only-handbuilt-pok-split01!");
    let knobs = Knobs { delta_g1: in_g2, delta_g2: in_g2, pok_g1: in_g1, pok_g2: in_g2 };
    let contribution = forge(
        &transcript,
        initial.delta_g1,
        initial.vk.delta_g2,
        &knobs,
        b"test-only-handbuilt-pok-split02!",
    );
    let key = key_for(&initial, &contribution, in_g2);

    rejected(
        "a proof of knowledge exhibiting one scalar in G1 and another in G2",
        verify_step(&initial, &key, &contribution, &transcript, &mut auditor()),
    );
    rejected(
        "the same, audited as a chain",
        verify_chain(&initial, &key, &[contribution], &mut auditor()),
    );
}

/// `delta` is one scalar in G1 and another in G2.
///
/// The chain link reads G1 and passes; the query check reads G2 and passes,
/// because the queries are divided by the G2 scalar. The key is nonetheless
/// useless -- a prover works from `delta_g1` and a verifier from `delta_g2` --
/// and the only thing that says so is the check that pairs one against the
/// other.
#[test]
fn a_delta_that_differs_between_the_groups_is_caught() {
    let initial = starting_key();
    let transcript = Transcript::begin(&initial).expect("a transcript");
    let (in_g1, in_g2) = two_scalars(b"test-only-handbuilt-delta-split!");
    let knobs = Knobs { delta_g1: in_g1, delta_g2: in_g2, pok_g1: in_g1, pok_g2: in_g1 };
    let contribution = forge(
        &transcript,
        initial.delta_g1,
        initial.vk.delta_g2,
        &knobs,
        b"test-only-handbuilt-delta-spli2!",
    );
    let key = key_for(&initial, &contribution, in_g2);

    rejected(
        "a delta scaled differently in the two groups, with the queries matching G2",
        verify_step(&initial, &key, &contribution, &transcript, &mut auditor()),
    );
    rejected(
        "the same, audited as a chain",
        verify_chain(&initial, &key, &[contribution], &mut auditor()),
    );
    assert!(!the_key_works(&key), "a key whose two deltas differ still proved");
}

/// An audit anchored part-way through a ceremony.
///
/// The chain presented here is internally perfect -- built against its own
/// anchor, with a valid proof and matching queries -- and it is still refused,
/// because the anchor's `delta` is not one. Accepting it would let somebody
/// present the tail of a ceremony as the whole of it: every contribution
/// before the anchor would go unexamined while the audit reported success.
#[test]
fn an_audit_anchored_after_the_start_is_refused() {
    let (midway, _) = run(1, b"test-only-anchored-after-start1!");
    assert_ne!(midway.delta_g1, G1Affine::generator(), "the anchor is still the starting key");

    let transcript = Transcript::begin(&midway).expect("a transcript");
    let (factor, _) = two_scalars(b"test-only-anchored-after-start2!");
    let contribution = forge(
        &transcript,
        midway.delta_g1,
        midway.vk.delta_g2,
        &Knobs::honest(factor),
        b"test-only-anchored-after-start3!",
    );
    let key = key_for(&midway, &contribution, factor);

    // It is a perfectly good *step* -- that is the point.
    verify_step(&midway, &key, &contribution, &transcript, &mut auditor())
        .expect("the step itself is honest");

    rejected(
        "an audit that treats a mid-ceremony key as the ceremony's start",
        verify_chain(&midway, &key, &[contribution], &mut auditor()),
    );
}

// --------------------------------------------------------------- the ending

/// A ceremony has to end somewhere, and the beacon is where.
///
/// Its scalar is public, so it adds no secrecy -- every test here is about the
/// one thing it does add, which is that the final `delta` depends on a value
/// no participant could have known while contributing. That property is
/// procedural: it holds only if the beacon was named before the ceremony
/// began, which no test can check and the documentation has to say.

const BEACON: &[u8] = b"a published beacon output, at least thirty-two bytes long";

#[test]
fn a_beacon_finishes_a_ceremony_and_the_key_still_proves() {
    let initial = starting_key();
    let mut key = initial.clone();
    let mut transcript = Transcript::begin(&key).expect("a transcript");
    let mut source = Repeatable::from(b"test-only-beacon-ceremony-0001!!");

    let mut published = Vec::new();
    for _ in 0..2 {
        let contribution = contribute(&mut key, &transcript, &mut source).expect("a contribution");
        transcript = transcript.extend(&contribution);
        published.push(contribution);
    }

    let before_the_beacon = key.clone();
    let ending = finalise(&mut key, &transcript, BEACON).expect("the beacon step");
    published.push(ending.clone());

    verify_beacon_step(
        before_the_beacon.delta_g1,
        before_the_beacon.vk.delta_g2,
        &transcript,
        BEACON,
        &ending,
    )
    .expect("the beacon step is not the one this beacon determines");
    verify_chain(&initial, &key, &published, &mut auditor())
        .expect("a ceremony ending in a beacon was rejected");
    assert!(the_key_works(&key), "the key stopped proving after the beacon");
}

/// Everything about the beacon step is a function of the transcript and the
/// beacon, the blinding scalar included. Two people running it must get
/// identical bytes, because comparing bytes is how it is checked.
#[test]
fn the_beacon_step_is_the_same_for_everyone() {
    let mut first = starting_key();
    let mut second = starting_key();
    let transcript = Transcript::begin(&first).expect("a transcript");
    let one = finalise(&mut first, &transcript, BEACON).expect("the beacon step");
    let other = finalise(&mut second, &transcript, BEACON).expect("the beacon step");
    assert_eq!(one.to_bytes(), other.to_bytes(), "two runs of the beacon step disagree");
    assert_eq!(first.l_query, second.l_query, "two runs produced different keys");
}

/// The beacon's *content* decides the result.
///
/// The two outputs below are deliberately the same length. An earlier version
/// of this test used beacons of different lengths and passed for a build whose
/// scalar depended only on how long the beacon was -- the mutation battery is
/// what found that, and the equal lengths are what fix it.
#[test]
fn a_different_beacon_gives_a_different_ending() {
    let mut first = starting_key();
    let mut second = starting_key();
    let other_beacon = b"A published beacon output, at least thirty-two bytes long";
    assert_eq!(other_beacon.len(), BEACON.len(), "the two beacons must differ only in content");
    assert_ne!(&other_beacon[..], BEACON);

    let transcript = Transcript::begin(&first).expect("a transcript");
    let one = finalise(&mut first, &transcript, BEACON).expect("the beacon step");
    let other = finalise(&mut second, &transcript, other_beacon).expect("the beacon step");
    assert_ne!(one.delta_g1, other.delta_g1, "the beacon's content did not decide the result");
}

/// The check the beacon exists for: a step that verifies perfectly well as an
/// ordinary contribution, but whose scalar was chosen rather than derived.
///
/// `verify_chain` accepts it, and should -- from the chain's point of view it
/// is a participant like any other. What refuses it is the recomputation, and
/// a ceremony that published a beacon and did not run that check has the
/// beacon's name without its property.
#[test]
fn a_chosen_scalar_wearing_the_beacons_name_is_caught() {
    let initial = starting_key();
    let mut key = initial.clone();
    let transcript = Transcript::begin(&key).expect("a transcript");
    let chosen = contribute(
        &mut key,
        &transcript,
        &mut Repeatable::from(b"test-only-beacon-impersonation1!"),
    )
    .expect("a contribution");

    verify_chain(&initial, &key, &[chosen.clone()], &mut auditor())
        .expect("as a chain entry it is perfectly valid, which is the point");
    rejected(
        "a participant-chosen scalar presented as the beacon's",
        verify_beacon_step(initial.delta_g1, initial.vk.delta_g2, &transcript, BEACON, &chosen),
    );
}

/// A beacon short enough to be ground out in advance defeats the only thing a
/// beacon is for.
#[test]
fn a_beacon_too_short_to_be_unpredictable_is_refused() {
    let mut key = starting_key();
    let transcript = Transcript::begin(&key).expect("a transcript");
    assert!(
        finalise(&mut key, &transcript, b"too short").is_err(),
        "a nine-byte beacon was accepted"
    );
    assert!(finalise(&mut key, &transcript, b"").is_err(), "an empty beacon was accepted");
    assert!(
        finalise(&mut key, &transcript, &[0x5au8; MINIMUM_BEACON_BYTES]).is_ok(),
        "the stated minimum is not actually accepted"
    );
}

/// The beacon step is bound to its position like any other, because it goes
/// through the same transcript.
#[test]
fn the_beacon_step_is_bound_to_where_it_sits() {
    let mut key = starting_key();
    let transcript = Transcript::begin(&key).expect("a transcript");
    let before = key.clone();
    let ending = finalise(&mut key, &transcript, BEACON).expect("the beacon step");
    let elsewhere = transcript.extend(&ending);
    rejected(
        "a beacon step checked at a different position",
        verify_beacon_step(before.delta_g1, before.vk.delta_g2, &elsewhere, BEACON, &ending),
    );
}

/// The beacon step is checkable from the **published record alone**.
///
/// This is the property the signature is shaped for. An auditor arriving years
/// later has the starting key they rebuilt, the contributions, and the
/// finished key -- and no intermediate keys, because a ceremony keeps none. So
/// the recomputation takes the previous step's *published* delta, which is in
/// the record, and never a key.
///
/// Nothing after the setup below touches a `ProvingKey`. If
/// `verify_beacon_step` ever needs one again this stops compiling, which is
/// the intended alarm.
#[test]
fn the_beacon_step_checks_out_against_the_record_and_nothing_else() {
    let initial = starting_key();
    let mut key = initial.clone();
    let mut transcript = Transcript::begin(&key).expect("a transcript");
    let first = contribute(
        &mut key,
        &transcript,
        &mut Repeatable::from(b"test-only-record-only-audit-01!!"),
    )
    .expect("a contribution");
    transcript = transcript.extend(&first);
    let ending = finalise(&mut key, &transcript, BEACON).expect("the beacon step");

    // From here, only what a record carries: two 672-byte blobs, the beacon's
    // bytes, and the transcript replayed from the starting key.
    let published = [first, ending];
    let replayed = Transcript::begin(&initial).expect("a transcript").extend(&published[0]);

    verify_beacon_step(
        published[0].delta_g1,
        published[0].delta_g2,
        &replayed,
        BEACON,
        &published[1],
    )
    .expect("the beacon step did not check out from the record");

    // And it still refuses the wrong thing when read this way, so the check
    // survived losing its key.
    rejected(
        "a participant's contribution presented as the beacon's, checked from the record",
        verify_beacon_step(
            initial.delta_g1,
            initial.vk.delta_g2,
            &Transcript::begin(&initial).expect("a transcript"),
            BEACON,
            &published[0],
        ),
    );
}

// ----------------------------------------------------- the circuit that ships

/// A contribution on the real circuit, end to end.
///
/// Everything above runs on a circuit of a few dozen constraints. This one is
/// the 18,107-constraint shielded transaction, whose `L` query is three orders
/// of magnitude longer and whose `H` query is 32,767 points -- the shape a
/// ceremony actually hands round. It also reports the two numbers a ceremony
/// has to be planned against: what a participant waits for, and what an
/// auditor does.
///
/// Slow, so it is behind `--ignored`.
#[test]
#[ignore = "the full 18,107-constraint circuit; run when contribution.rs changes"]
fn the_shielded_circuit_takes_a_contribution() {
    use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
    use shielded_pool_circuit::scenario;
    use std::time::Instant;

    let (_pool, public, witness) = scenario::valid_withdrawal().expect("a withdrawal");
    let circuit = ShieldedTransactionCircuit::new(public.clone(), witness);

    let (matrices, instance, _) = phase2::matrices(circuit.clone()).expect("the matrices");
    let size = Radix2EvaluationDomain::<Fr>::new(matrices.num_constraints + instance)
        .expect("a domain")
        .size();
    let mut secrets = ChaCha20Rng::from_seed(*b"test-only-phase1-secrets-real01!");
    let tau = Fr::rand(&mut secrets);
    let alpha = Fr::rand(&mut secrets);
    let beta = Fr::rand(&mut secrets);
    let srs = lagrange::transform(&slice_from_known_secrets(size, tau, alpha, beta))
        .expect("the Lagrange basis");

    let initial = phase2::initial(&srs, circuit.clone()).expect("the starting key");
    let mut key = initial.clone();
    let transcript = Transcript::begin(&key).expect("a transcript");

    let started = Instant::now();
    let contribution = contribute(
        &mut key,
        &transcript,
        &mut Repeatable::from(b"test-only-real-circuit-contrib1!"),
    )
    .expect("a contribution");
    let contributing = started.elapsed();

    let started = Instant::now();
    verify_chain(&initial, &key, &[contribution], &mut auditor()).expect("the chain should verify");
    let auditing = started.elapsed();

    // The build profile is part of the measurement. A ceremony planned around
    // a debug figure would budget an order of magnitude too much of a
    // participant's time, and a reader seeing a bare number has no way to tell
    // which they are looking at.
    println!(
        "{} build: constraints {}, L {}, H {} -- contributing {:.1}s, auditing {:.1}s",
        if cfg!(debug_assertions) { "debug" } else { "release" },
        matrices.num_constraints,
        key.l_query.len(),
        key.h_query.len(),
        contributing.as_secs_f64(),
        auditing.as_secs_f64()
    );

    // And the key still proves -- the only claim here that is not about time.
    let mut rng = ChaCha20Rng::from_seed(*b"test-only-real-circuit-proving1!");
    let proof = Groth16::<Bls12_381>::prove(&key, circuit, &mut rng).expect("a proof");
    assert!(
        Groth16::<Bls12_381>::verify(&key.vk, &public.to_vec(), &proof).expect("verification ran"),
        "the real circuit stopped proving after a contribution"
    );
}
