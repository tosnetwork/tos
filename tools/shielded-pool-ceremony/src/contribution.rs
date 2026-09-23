/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Phase 2, second stage: one participant's contribution, and the checks that
//! make it worth something.
//!
//! The starting key from [`crate::phase2::initial`] has `delta = 1`, which
//! everybody knows. A contribution replaces `delta` with `delta * d` for a
//! scalar `d` the participant draws and destroys. Do that `n` times and the
//! final `delta` is a product no single participant knows; forging a proof
//! needs all `n` of them, so the parameters are sound if **one** participant
//! was honest. That is the whole argument, and it is why a ceremony wants many
//! participants rather than trustworthy ones.
//!
//! # What changes, and what must not
//!
//! ```text
//!   delta_g1  <- delta_g1 * d          h_query[i] <- h_query[i] / d
//!   delta_g2  <- delta_g2 * d          l_query[i] <- l_query[i] / d
//! ```
//!
//! Everything else -- `alpha`, `beta`, `gamma`, the `A` and `B` queries, and
//! the input-consistency points -- is fixed by the circuit and the phase-1
//! string, and a contribution that touched any of it would be substituting a
//! different circuit. [`verify_step`] compares those element for element, not
//! by a digest of the whole key, so a rejection says which section moved.
//!
//! # Why the verifier believes it
//!
//! A participant could multiply `delta_g1` by `d` and the queries by some
//! other `d'`, or copy a previous participant's `delta` and claim it, or
//! replay somebody's contribution from another ceremony. Three things rule
//! those out, and none of them need the secret:
//!
//! 1. **A proof of knowledge.** The participant publishes `s` and `s*d` in G1
//!    and `h*d` in G2, where `h` is a curve point *derived by hashing the
//!    transcript together with `s` and `s*d`*. Pairing `s` against `h*d` and
//!    `s*d` against `h` gives the same value only if the same `d` scales both,
//!    which no one can arrange without knowing `d`. Because `h` comes out of
//!    the transcript, the same proof is worthless in any other ceremony, at
//!    any other position in this one, and after any earlier contribution has
//!    been altered -- that is the replay defence, and it is why
//!    [`Transcript`] chains.
//! 2. **The same `d` moved `delta`.** Pairing the new `delta_g1` against `h`
//!    and the old one against `h*d` agrees only for the `d` the proof is
//!    about.
//! 3. **The same `d` divided the queries.** Pairing a query after against
//!    `delta` after, and before against before, cancels only when the
//!    multiplication and the division used one scalar. Batched with random
//!    weights the verifier draws *after* seeing the key, so a key built to
//!    pass a known weighting cannot be.
//!
//! # `gamma` stays at one
//!
//! Only `delta` is randomised. This is the established shape of a phase 2 and
//! not an economy: in the Groth16 setup `gamma` separates the public-input
//! terms from the rest, and its secrecy is not what soundness rests on --
//! being non-zero is. The multi-party literature this follows sets it to one
//! for exactly that reason. It is stated here because it is the kind of thing
//! a reader assumes is an oversight, and because it is a claim resting on a
//! proof in a paper rather than on anything in this file.
//!
//! # These checks shadow each other, and that mattered
//!
//! Worth knowing before changing any of them: the three above overlap heavily,
//! and most concrete attacks are caught by whichever comes first rather than
//! by the one aimed at them. A build with the chain link removed, a build with
//! the proof-of-knowledge pairing removed and a build with the cross-group
//! comparison removed each passed the whole suite as first written -- the
//! transcript binding or the query check caught the forgery on the way past.
//!
//! So the tests that cover them build a contribution **by hand from chosen
//! scalars**, with a separate knob for `delta` in each group and for the proof
//! in each group, and turn exactly one. `test/shielded-pool/mutations-ceremony.py`
//! keeps them honest by naming, per mutation, the test that has to go red; a
//! suite that goes red somewhere else counts as a survivor.
//!
//! # Finishing
//!
//! [`finalise`] applies a last contribution whose scalar is a hash of a public
//! random beacon. It adds no secrecy -- everybody can recompute it -- and its
//! only property is that no participant could have predicted it while
//! contributing, which holds only if the beacon was **named before the
//! ceremony began**. No code can check that.
//!
//! **It does not rescue a ceremony whose participants all colluded.** The
//! final `delta` is `d_1 * ... * d_n * d_beacon`, and `d_beacon` is a hash of
//! published bytes that anyone can compute -- so a coalition holding every
//! `d_i` holds the product. Security rests on one participant having
//! destroyed their scalar, beacon or no beacon. What [`verify_beacon_step`] does
//! check is that the step really is the one those bytes determine, by
//! recomputing it and comparing bytes: a participant-chosen scalar wearing the
//! beacon's name passes [`verify_chain`] perfectly well.
//!
//! # What is not checked here
//!
//! That `d` was drawn well, and that it was destroyed. Neither is observable
//! -- a contribution from a scalar the participant published verifies exactly
//! as well as one from a scalar they burned. [`crate::entropy`] and
//! [`crate::secret`] are the whole of the answer, and they are a discipline
//! rather than a proof.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand, Zero};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalSerialize;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::entropy::Entropy;
use crate::error::{Error, Result};
use crate::points::{g1_to_uncompressed, g2_from_uncompressed, g2_to_uncompressed};
use crate::secret::Secret;

/// Hash-to-curve domain separation for the proof of knowledge.
///
/// Carries the protocol, the phase and the suite, per the IETF hash-to-curve
/// recommendation. Changing it invalidates every proof ever produced, which is
/// the intended effect if the construction ever changes.
const POK_DST: &[u8] = b"TOS-SHIELDED-POOL-V1-PHASE2-POK_XMD:SHA-256_SSWU_RO_";

/// Domain separation for the transcript hash, distinct from the one above so
/// no transcript digest can ever be read as a hash-to-curve message.
const TRANSCRIPT_DOMAIN: &[u8] = b"TOS-SHIELDED-POOL-V1-PHASE2-TRANSCRIPT";

/// Domain separation for the verifier's batching weights.
const BATCH_DOMAIN: &[u8] = b"TOS-SHIELDED-POOL-V1-PHASE2-BATCH";

/// The public half of one participant's contribution.
///
/// Everything a verifier needs and nothing a forger could use. There is no
/// secret in this struct -- that is the point of it -- so it is the artifact a
/// ceremony publishes, and it is small: 672 bytes, whatever the circuit's
/// size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contribution {
    /// `delta` in G1 after this contribution.
    pub delta_g1: G1Affine,
    /// The same `delta` in G2. Both are published so the chain can be checked
    /// without the intermediate keys.
    pub delta_g2: G2Affine,
    /// A point the participant chose, and the same point scaled by `d`.
    pub s: G1Affine,
    pub s_delta: G1Affine,
    /// The transcript-derived challenge point, scaled by `d`.
    pub r_delta: G2Affine,
}

/// The serialized width of a contribution: two G1 for the proof, one G1 for
/// `delta`, and two G2.
pub const CONTRIBUTION_BYTES: usize = 96 * 3 + 192 * 2;

impl Contribution {
    /// Canonical bytes, in this chain's own point encoding.
    ///
    /// The transcript hashes these, so the encoding is part of the protocol:
    /// two implementations that agreed on the points and disagreed on their
    /// bytes would compute different challenges and reject each other.
    pub fn to_bytes(&self) -> [u8; CONTRIBUTION_BYTES] {
        let mut out = [0u8; CONTRIBUTION_BYTES];
        out[..96].copy_from_slice(&g1_to_uncompressed(&self.delta_g1));
        out[96..288].copy_from_slice(&g2_to_uncompressed(&self.delta_g2));
        out[288..384].copy_from_slice(&g1_to_uncompressed(&self.s));
        out[384..480].copy_from_slice(&g1_to_uncompressed(&self.s_delta));
        out[480..].copy_from_slice(&g2_to_uncompressed(&self.r_delta));
        out
    }

    /// Reads a contribution, with every point put through the subgroup check.
    ///
    /// A point outside the prime-order subgroup is the classic way to make a
    /// pairing check pass without knowing anything, so this is a security
    /// boundary and not a parsing convenience.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use crate::points::g1_from_uncompressed;
        if bytes.len() != CONTRIBUTION_BYTES {
            return Err(Error::Structure(format!(
                "a contribution is {CONTRIBUTION_BYTES} bytes and this is {}",
                bytes.len()
            )));
        }
        Ok(Self {
            delta_g1: g1_from_uncompressed(&bytes[..96])?,
            delta_g2: g2_from_uncompressed(&bytes[96..288])?,
            s: g1_from_uncompressed(&bytes[288..384])?,
            s_delta: g1_from_uncompressed(&bytes[384..480])?,
            r_delta: g2_from_uncompressed(&bytes[480..])?,
        })
    }
}

/// The running record a contribution is bound to.
///
/// It starts from a digest of the key the ceremony began at -- which fixes the
/// circuit *and* the phase-1 string it was built from -- and absorbs each
/// contribution in order. Because the challenge point of contribution `k` is
/// hashed from the transcript as it stood before it, a published contribution
/// is valid at exactly one position of exactly one ceremony. Reordering,
/// dropping, substituting or replaying any of them changes a later challenge
/// and the proof stops verifying.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    digest: [u8; 32],
}

impl Transcript {
    /// Opens a transcript over the key a ceremony starts from.
    pub fn begin(initial: &ProvingKey<Bls12_381>) -> Result<Self> {
        use sha2::{Digest, Sha256};
        let mut serialized = Vec::new();
        initial
            .serialize_compressed(&mut serialized)
            .map_err(|error| Error::Structure(format!("serializing the initial key: {error}")))?;
        let mut hasher = Sha256::new();
        hasher.update(TRANSCRIPT_DOMAIN);
        hasher.update(b"initial");
        hasher.update(&serialized);
        Ok(Self { digest: hasher.finalize().into() })
    }

    /// Absorbs a contribution, giving the transcript the next one is bound to.
    pub fn extend(&self, contribution: &Contribution) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(TRANSCRIPT_DOMAIN);
        hasher.update(b"step");
        hasher.update(self.digest);
        hasher.update(contribution.to_bytes());
        Self { digest: hasher.finalize().into() }
    }

    /// The transcript's digest, for publishing and for comparing two records.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// The challenge point for a contribution, hashed from the transcript and the
/// participant's own `s` and `s*d`.
///
/// Public because an independent verifier has to reproduce it exactly, and
/// because the mutation battery needs to build a contribution by hand to reach
/// checks that other checks would otherwise shadow.
///
/// Both inputs are here for a reason, and only one of them is backed by a test
/// in this repository:
///
/// * the **transcript** is what stops a proof being valid anywhere but its own
///   position in its own ceremony, and
///   `a_step_checked_against_the_wrong_transcript_is_rejected` fails without
///   it;
/// * **`s` and `s_delta`** are here because the construction this follows puts
///   them here: hashing the participant's own points means the challenge is
///   fixed only after they have committed to a scalar, which is what the
///   knowledge extractor in the security proof needs. No mutation in this
///   repository's battery distinguishes a version that omits them, and that is
///   recorded rather than hidden -- it is a claim resting on the paper, like
///   `gamma = 1` above.
pub fn challenge_point(
    transcript: &Transcript,
    s: &G1Affine,
    s_delta: &G1Affine,
) -> Result<G2Affine> {
    let mut message = Vec::with_capacity(32 + 96 * 2);
    message.extend_from_slice(&transcript.digest);
    message.extend_from_slice(&g1_to_uncompressed(s));
    message.extend_from_slice(&g1_to_uncompressed(s_delta));

    let mut point = blst::blst_p2::default();
    // SAFETY: all four pointer/length pairs describe live slices, the
    // augmentation is the documented null/zero, and `point` is a valid
    // out-parameter. blst's hash-to-curve always returns a subgroup element.
    unsafe {
        blst::blst_hash_to_g2(
            &mut point,
            message.as_ptr(),
            message.len(),
            POK_DST.as_ptr(),
            POK_DST.len(),
            std::ptr::null(),
            0,
        );
    }
    let mut bytes = [0u8; 192];
    // SAFETY: `bytes` is the 192 blst writes for an uncompressed G2 and
    // `point` was filled above.
    unsafe { blst::blst_p2_serialize(bytes.as_mut_ptr(), &point) };

    // Back through the same gate every other point in this crate goes
    // through, so the challenge is a point arkworks and blst agree on rather
    // than one this function asserts.
    g2_from_uncompressed(&bytes)
}

/// Adds one contribution to `key`, in place.
///
/// The secret is drawn here, used here and destroyed here. It is not a
/// parameter, not a return value and not a field of [`Contribution`]: there is
/// no expression in this crate's public interface that evaluates to it, which
/// is the only reliable way to guarantee it is never printed or stored.
///
/// `transcript` must be the record as it stands *before* this contribution;
/// the caller extends it with the returned contribution afterwards.
pub fn contribute(
    key: &mut ProvingKey<Bls12_381>,
    transcript: &Transcript,
    entropy: &mut dyn Entropy,
) -> Result<Contribution> {
    let delta = Secret::draw(entropy)?;
    // The proof's blinding scalar. Drawn from the same source: it is not the
    // thing whose secrecy matters, but there is no reason to make anyone argue
    // about that.
    let blind = Secret::draw(entropy)?;
    apply(key, transcript, delta.value(), blind.value())
    // `delta` and `blind` go out of scope here and wipe themselves. Nothing
    // after this line can reach either.
}

/// The arithmetic of a contribution, for a scalar the caller already has.
///
/// Private, and the only place `delta` is multiplied into anything. Both the
/// participant path and the beacon path go through it so there is one piece of
/// arithmetic to get right rather than two -- and so a reader comparing them
/// sees only the difference that matters, which is where the scalar came from.
fn apply(
    key: &mut ProvingKey<Bls12_381>,
    transcript: &Transcript,
    delta: &Fr,
    blind: &Fr,
) -> Result<Contribution> {
    let contribution = build(key.delta_g1, key.vk.delta_g2, transcript, delta, blind)?;

    // Knowing this is knowing the secret, so it is wiped before the function
    // returns rather than left on the stack for the next frame to inherit.
    let mut inverse = delta
        .inverse()
        .ok_or_else(|| Error::Structure("the contribution scalar has no inverse".into()))?;

    let divide = |points: &[G1Affine]| -> Vec<G1Affine> {
        let scaled: Vec<G1Projective> = points.iter().map(|point| *point * inverse).collect();
        G1Projective::normalize_batch(&scaled)
    };
    key.l_query = divide(&key.l_query);
    key.h_query = divide(&key.h_query);
    key.delta_g1 = contribution.delta_g1;
    key.vk.delta_g2 = contribution.delta_g2;

    zeroize::Zeroize::zeroize(&mut inverse);
    Ok(contribution)
}

/// A contribution's five published points, from the previous `delta` and a
/// scalar.
///
/// **The only place these are computed.** It takes the previous `delta` rather
/// than the key it came from, because that is all the points depend on -- and
/// because an auditor recomputing a beacon step has the published `delta` of
/// every step and none of the intermediate keys. A version of this that needed
/// a key would quietly make the audit depend on artifacts nobody keeps.
fn build(
    previous_g1: G1Affine,
    previous_g2: G2Affine,
    transcript: &Transcript,
    delta: &Fr,
    blind: &Fr,
) -> Result<Contribution> {
    let s = (G1Affine::generator() * blind).into_affine();
    let s_delta = (s * delta).into_affine();
    let challenge = challenge_point(transcript, &s, &s_delta)?;
    let r_delta = (challenge * delta).into_affine();

    let delta_g1 = (previous_g1 * delta).into_affine();
    let delta_g2 = (previous_g2 * delta).into_affine();
    if delta_g1.is_zero() || delta_g2.is_zero() || s.is_zero() || s_delta.is_zero() {
        return Err(Error::Structure(
            "scaling produced the identity; either the scalar was zero or the delta this was \
             applied to was already degenerate"
                .into(),
        ));
    }
    Ok(Contribution { delta_g1, delta_g2, s, s_delta, r_delta })
}

/// Domain separation for the scalars a beacon determines.
const BEACON_DOMAIN: &[u8] = b"TOS-SHIELDED-POOL-V1-PHASE2-BEACON";

/// The shortest beacon output this will accept.
///
/// A ceremony whose finalising value is a handful of bytes is one whose
/// finalising value can be ground out in advance, which is the single thing
/// the beacon exists to prevent. Thirty-two bytes is a block hash, a drand
/// round, a hash of several sources -- anything worth using is at least this
/// long, so the bound costs nothing and refuses the obviously wrong.
pub const MINIMUM_BEACON_BYTES: usize = 32;

/// A scalar determined by public bytes, reduced from a wide hash.
///
/// Public by construction. There is no [`Secret`] here and there must not be:
/// wrapping a value everyone can recompute in the type whose promise is that
/// nobody can read it would be a lie told by the code itself.
fn beacon_scalar(beacon: &[u8], purpose: &[u8]) -> Result<Fr> {
    use ark_ff::PrimeField;
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(BEACON_DOMAIN);
    hasher.update(purpose);
    hasher.update((beacon.len() as u64).to_le_bytes());
    hasher.update(beacon);
    let wide = hasher.finalize();
    let value = Fr::from_le_bytes_mod_order(&wide);
    if value.is_zero() || value == Fr::ONE {
        return Err(Error::Structure(
            "this beacon hashes to a degenerate scalar; pick another round".into(),
        ));
    }
    Ok(value)
}

/// The finalising step: a contribution whose scalar comes from a public random
/// beacon rather than from a participant.
///
/// # What it adds, and what it does not
///
/// It adds **no secrecy at all**. The scalar is a hash of published bytes and
/// anybody can recompute it, so a ceremony consisting only of this step is
/// worth nothing.
///
/// It also does **not** rescue a ceremony whose participants all colluded.
/// The final `delta` is `d_1 * ... * d_n * d_beacon`; a coalition holding
/// every `d_i` can compute `d_beacon` like anyone else, so it holds the
/// product. **Security rests entirely on one participant having destroyed
/// their scalar**, and nothing here changes that.
///
/// What it does add is that the finished parameters depend on a value nobody
/// could have predicted while contributing, so no participant could steer
/// `delta` towards something prepared in advance. That property holds only if
/// the beacon was **named and fixed before the ceremony started**; one chosen
/// afterwards is decoration, and no code can check which happened.
///
/// # Deterministic, and that is the check
///
/// Everything here is a function of the transcript and the beacon, including
/// the proof's blinding scalar. A verifier does not check this step with
/// pairings; they recompute it and compare bytes, which
/// [`verify_beacon_step`] does. That is a stronger check than any contribution
/// from a participant can be given.
pub fn finalise(
    key: &mut ProvingKey<Bls12_381>,
    transcript: &Transcript,
    beacon: &[u8],
) -> Result<Contribution> {
    let (delta, blind) = beacon_scalars(beacon)?;
    apply(key, transcript, &delta, &blind)
}

/// The two scalars a beacon determines, with the length floor enforced once.
fn beacon_scalars(beacon: &[u8]) -> Result<(Fr, Fr)> {
    if beacon.len() < MINIMUM_BEACON_BYTES {
        return Err(Error::Structure(format!(
            "a beacon of {} bytes is too short to be unpredictable; {MINIMUM_BEACON_BYTES} is the \
             minimum",
            beacon.len()
        )));
    }
    Ok((beacon_scalar(beacon, b"delta")?, beacon_scalar(beacon, b"blind")?))
}

/// The finalising contribution a beacon determines, from published data alone.
///
/// Takes the previous step's published `delta` -- which is in the record --
/// rather than the key before the beacon, which nobody keeps. This is what
/// lets the whole ceremony, beacon included, be audited from the record and
/// the finished key.
pub fn beacon_contribution(
    previous_g1: G1Affine,
    previous_g2: G2Affine,
    transcript: &Transcript,
    beacon: &[u8],
) -> Result<Contribution> {
    let (delta, blind) = beacon_scalars(beacon)?;
    build(previous_g1, previous_g2, transcript, &delta, &blind)
}

/// Is this contribution the one the announced beacon determines?
///
/// Recomputed and compared, not merely checked for internal consistency: a
/// contribution that verifies as an ordinary step but is not this beacon's is
/// a participant-chosen scalar wearing the beacon's name, and it would defeat
/// the only thing the beacon is for.
///
/// `previous_g1`/`previous_g2` are the `delta` the step before published --
/// the starting key's generators when the beacon is the only step.
pub fn verify_beacon_step(
    previous_g1: G1Affine,
    previous_g2: G2Affine,
    transcript: &Transcript,
    beacon: &[u8],
    contribution: &Contribution,
) -> Result<()> {
    let expected = beacon_contribution(previous_g1, previous_g2, transcript, beacon)?;
    if expected.to_bytes() != contribution.to_bytes() {
        return Err(Error::Structure(
            "the finalising contribution is not the one this beacon determines; its scalar came \
             from somewhere else"
                .into(),
        ));
    }
    Ok(())
}

/// `e(a, b) == e(c, d)`, as a single multi-pairing.
///
/// One pairing with a negated input rather than two compared, because the
/// final exponentiation is the expensive part and this pays for it once.
fn same_pairing(a: G1Affine, b: G2Affine, c: G1Affine, d: G2Affine) -> bool {
    Bls12_381::multi_pairing([a, -c], [b, d]).is_zero()
}

/// The weights a batched check uses, drawn from entropy the key's author could
/// not have seen.
///
/// A fixed or derived weighting is a cheat: a forger who knows the weights can
/// craft a set of points whose weighted sum passes while no individual element
/// is right. These are drawn after the key exists, from the verifier's own
/// generator.
fn weights(count: usize, entropy: &mut dyn Entropy) -> Result<Vec<Fr>> {
    let mut seed = [0u8; 32];
    entropy.fill(&mut seed)?;
    // Domain-separated so a seed drawn here can never coincide with one drawn
    // for another purpose from the same source.
    let seed = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(BATCH_DOMAIN);
        hasher.update(seed);
        let out: [u8; 32] = hasher.finalize().into();
        out
    };
    let mut rng = ChaCha20Rng::from_seed(seed);
    Ok((0..count).map(|_| Fr::rand(&mut rng)).collect())
}

fn combine(points: &[G1Affine], scalars: &[Fr]) -> Result<G1Affine> {
    G1Projective::msm(points, scalars)
        .map(|point| point.into_affine())
        .map_err(|_| Error::Structure("a batching multiexponentiation failed".into()))
}

/// The proof of knowledge on its own: `s_delta/s` and `r_delta/h` are the same
/// scalar, and `h` is the one this transcript demands.
fn verify_proof(contribution: &Contribution, transcript: &Transcript) -> Result<G2Affine> {
    if contribution.s.is_zero() || contribution.s_delta.is_zero() {
        return Err(Error::Structure(
            "the proof of knowledge uses the identity, which proves nothing".into(),
        ));
    }
    let challenge = challenge_point(transcript, &contribution.s, &contribution.s_delta)?;
    if !same_pairing(contribution.s, contribution.r_delta, contribution.s_delta, challenge) {
        return Err(Error::Structure(
            "the proof of knowledge does not check out: either it is for a different transcript \
             -- a replay from elsewhere in this ceremony or from another one -- or the two groups \
             were scaled by different secrets"
                .into(),
        ));
    }
    Ok(challenge)
}

/// `delta_g1` and `delta_g2` describe the same scalar.
fn delta_agrees_across_groups(delta_g1: G1Affine, delta_g2: G2Affine) -> bool {
    same_pairing(delta_g1, G2Affine::generator(), G1Affine::generator(), delta_g2)
}

/// One participant's step: `after` is `before` with this contribution applied.
///
/// This is what a participant runs on the state handed to them before adding
/// their own, and what a coordinator runs on receipt. The chain-level audit,
/// [`verify_chain`], needs no intermediate keys and is the one a later auditor
/// uses.
pub fn verify_step(
    before: &ProvingKey<Bls12_381>,
    after: &ProvingKey<Bls12_381>,
    contribution: &Contribution,
    transcript: &Transcript,
    entropy: &mut dyn Entropy,
) -> Result<()> {
    let challenge = verify_proof(contribution, transcript)?;

    if contribution.delta_g1 != after.delta_g1 || contribution.delta_g2 != after.vk.delta_g2 {
        return Err(Error::Structure(
            "the contribution claims a delta the key does not carry".into(),
        ));
    }
    if before.delta_g1 == after.delta_g1 {
        return Err(Error::Structure(
            "delta is unchanged, so this contribution added nothing; a drawn secret reaches this \
             about once in 2^254 times, so the generator is broken or the step was skipped"
                .into(),
        ));
    }
    if !delta_agrees_across_groups(after.delta_g1, after.vk.delta_g2) {
        return Err(Error::Structure("delta in G1 and delta in G2 are different scalars".into()));
    }

    // The scalar the proof is about is the one that moved delta.
    if !same_pairing(after.delta_g1, challenge, before.delta_g1, contribution.r_delta) {
        return Err(Error::Structure(
            "delta was multiplied by a scalar other than the one the proof of knowledge is about"
                .into(),
        ));
    }

    queries_were_divided_by_the_same_scalar(before, after, entropy)?;
    the_rest_is_untouched(before, after)
}

/// `e(after[i], delta_after) == e(before[i], delta_before)`, batched.
///
/// This is the check that catches a participant who scales `delta` honestly
/// and divides the queries by something else -- the alteration that would
/// leave the key looking correct and proving nothing.
fn queries_were_divided_by_the_same_scalar(
    before: &ProvingKey<Bls12_381>,
    after: &ProvingKey<Bls12_381>,
    entropy: &mut dyn Entropy,
) -> Result<()> {
    for (name, b, a) in
        [("l_query", &before.l_query, &after.l_query), ("h_query", &before.h_query, &after.h_query)]
    {
        if b.len() != a.len() {
            return Err(Error::Structure(format!(
                "{name} changed length, from {} to {}",
                b.len(),
                a.len()
            )));
        }
        if b.is_empty() {
            continue;
        }
        let scalars = weights(b.len(), entropy)?;
        let before_sum = combine(b, &scalars)?;
        let after_sum = combine(a, &scalars)?;
        if !same_pairing(after_sum, after.vk.delta_g2, before_sum, before.vk.delta_g2) {
            return Err(Error::Structure(format!(
                "{name} was not divided by the scalar delta was multiplied by"
            )));
        }
    }
    Ok(())
}

/// Every section a contribution has no business touching, compared element for
/// element.
fn the_rest_is_untouched(
    before: &ProvingKey<Bls12_381>,
    after: &ProvingKey<Bls12_381>,
) -> Result<()> {
    let mismatch =
        |what: &str| Error::Structure(format!("{what} changed, and nothing but delta may"));
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

/// The standalone audit: does this final key follow from this starting key and
/// this list of contributions?
///
/// The property that makes a ceremony auditable years later is that this needs
/// **no intermediate keys**. The starting key is rebuildable by anyone from
/// the phase-1 slice and the circuit; the contributions are 672 bytes each;
/// and the final key is the artifact in use. Nothing else has to have been
/// kept, and nothing that was kept has to be trusted.
///
/// It works because the starting key has `delta = 1`, so the queries in the
/// final key are the starting ones divided by the whole product, and the final
/// `delta` *is* that product. Pairing one against the other cancels it without
/// anyone knowing it.
pub fn verify_chain(
    initial: &ProvingKey<Bls12_381>,
    final_key: &ProvingKey<Bls12_381>,
    contributions: &[Contribution],
    entropy: &mut dyn Entropy,
) -> Result<()> {
    if contributions.is_empty() {
        return Err(Error::Structure(
            "a ceremony with no contributions; the starting key's delta is one and known to \
             everyone"
                .into(),
        ));
    }
    if initial.delta_g1 != G1Affine::generator() || initial.vk.delta_g2 != G2Affine::generator() {
        return Err(Error::Structure(
            "the starting key's delta is not one, so it is not the key a ceremony starts from"
                .into(),
        ));
    }

    let mut transcript = Transcript::begin(initial)?;
    let mut previous_g1 = initial.delta_g1;

    for (index, contribution) in contributions.iter().enumerate() {
        let at = |error: Error| match error {
            Error::Structure(message) => {
                Error::Structure(format!("contribution {}: {message}", index + 1))
            }
            other => other,
        };
        let challenge = verify_proof(contribution, &transcript).map_err(at)?;

        if contribution.delta_g1 == previous_g1 {
            return Err(at(Error::Structure("delta is unchanged, so this added nothing".into())));
        }
        if !delta_agrees_across_groups(contribution.delta_g1, contribution.delta_g2) {
            return Err(at(Error::Structure(
                "delta in G1 and delta in G2 are different scalars".into(),
            )));
        }
        if !same_pairing(contribution.delta_g1, challenge, previous_g1, contribution.r_delta) {
            return Err(at(Error::Structure(
                "this delta does not follow from the previous one by the scalar the proof is \
                 about, so the chain is broken here"
                    .into(),
            )));
        }

        previous_g1 = contribution.delta_g1;
        transcript = transcript.extend(contribution);
    }

    let last = contributions.last().ok_or_else(|| {
        Error::Structure("the contribution list emptied itself, which cannot happen".into())
    })?;
    if final_key.delta_g1 != last.delta_g1 || final_key.vk.delta_g2 != last.delta_g2 {
        return Err(Error::Structure(
            "the final key's delta is not the one the last contribution produced".into(),
        ));
    }

    // The starting delta is one, so this is the same check `verify_step` makes
    // pairwise, collapsed over the whole chain.
    queries_were_divided_by_the_same_scalar(initial, final_key, entropy)?;
    the_rest_is_untouched(initial, final_key)
}

/// The key a ceremony finished at, as a digest to publish alongside the
/// transcript.
pub fn key_digest(key: &ProvingKey<Bls12_381>) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut serialized = Vec::new();
    key.serialize_compressed(&mut serialized)
        .map_err(|error| Error::Structure(format!("serializing a key: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(TRANSCRIPT_DOMAIN);
    hasher.update(b"key");
    hasher.update(&serialized);
    Ok(hasher.finalize().into())
}
