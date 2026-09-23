/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Profile section 10.1: the Groth16 proof and verifying key, and the
//! development fixture.
//!
//! Two things are deliberately not taken on trust here.
//!
//! The pairing equation's sign and operand order are **measured**, not
//! recalled: [`pairing_equation_report`] evaluates a list of candidate forms
//! against one valid proof and four mutated ones, and reports which forms hold
//! for the valid proof and fail for every mutation. Section 10.1 requires that
//! cross-check before the equation is frozen, and a remembered sign would not
//! be evidence.
//!
//! The keys below come from a fixed seed. That makes the development fixture
//! reproducible and is exactly what section 17 and section 20 call a
//! development artifact: the toxic waste is known, so **no key produced here
//! may ever verify a real transaction**. Production keys come from a Phase-2
//! ceremony.

use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::circuit::ShieldedTransactionCircuit;
use crate::error::{Error, Result};
use crate::field::Fr;
use crate::public_inputs::{PublicInputs, PUBLIC_INPUT_COUNT};

/// The seed the development keys are drawn from. Fixed on purpose.
pub const DEVELOPMENT_SEED: [u8; 32] = *b"tos-shielded-pool-v1-devkeys-001";

/// A development proving/verifying key pair.
pub struct DevelopmentKeys {
    pub proving: ProvingKey<Bls12_381>,
    pub verifying: VerifyingKey<Bls12_381>,
}

/// Runs the circuit-specific setup over the section 11 circuit.
pub fn development_keys(shape: ShieldedTransactionCircuit) -> Result<DevelopmentKeys> {
    keys_from_seed(shape, DEVELOPMENT_SEED)
}

/// The same setup under a caller-chosen seed.
///
/// Still a single-party setup and still not a ceremony: whoever holds the seed
/// holds the toxic waste. It exists so that a *second* key pair can be
/// produced, which is what the ceremony acceptance gate needs -- a gate that
/// only ever sees one key cannot show that it binds a proof to the key the
/// pool was deployed with rather than merely to some valid key.
pub fn keys_from_seed(
    shape: ShieldedTransactionCircuit,
    seed: [u8; 32],
) -> Result<DevelopmentKeys> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (proving, verifying) = Groth16::<Bls12_381>::circuit_specific_setup(shape, &mut rng)
        .map_err(|error| Error::Backend(format!("setup: {error}")))?;
    if verifying.gamma_abc_g1.len() != PUBLIC_INPUT_COUNT + 1 {
        return Err(Error::Backend(format!(
            "the verifying key has {} IC points, not the {} that 18 public inputs require",
            verifying.gamma_abc_g1.len(),
            PUBLIC_INPUT_COUNT + 1
        )));
    }
    Ok(DevelopmentKeys { proving, verifying })
}

/// Produces one proof.
pub fn prove(
    keys: &DevelopmentKeys,
    circuit: ShieldedTransactionCircuit,
    nonce: u8,
) -> Result<Proof<Bls12_381>> {
    let mut seed = DEVELOPMENT_SEED;
    seed[31] = nonce;
    let mut rng = ChaCha20Rng::from_seed(seed);
    Groth16::<Bls12_381>::prove(&keys.proving, circuit, &mut rng)
        .map_err(|error| Error::Backend(format!("prove: {error}")))
}

/// The library's own verifier.
pub fn verify(
    verifying: &VerifyingKey<Bls12_381>,
    public: &PublicInputs,
    proof: &Proof<Bls12_381>,
) -> Result<bool> {
    Groth16::<Bls12_381>::verify(verifying, &public.to_vec(), proof)
        .map_err(|error| Error::Backend(format!("verify: {error}")))
}

/// `vk_x = IC[0] + sum(public_input[i] * IC[i+1])`, computed exactly as
/// section 10.1 writes it.
pub fn vk_x(verifying: &VerifyingKey<Bls12_381>, public: &PublicInputs) -> Result<G1Affine> {
    let ic = &verifying.gamma_abc_g1;
    let base = ic
        .first()
        .ok_or_else(|| Error::Backend("the verifying key has no IC points".to_string()))?;
    let mut accumulator = G1Projective::from(*base);
    for (index, value) in public.to_vec().iter().enumerate() {
        let point = ic
            .get(index.saturating_add(1))
            .ok_or_else(|| Error::Backend(format!("IC[{}] is missing", index + 1)))?;
        accumulator += point.mul_bigint(value.into_bigint());
    }
    Ok(accumulator.into_affine())
}

/// One candidate form of the four-pair check, written as a multi-pairing whose
/// result must be the target-group identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EquationForm {
    /// How the name reads once the signs are put back into `e(..)` form.
    pub name: &'static str,
    /// Sign of each of the four G1 operands, in the order
    /// `A, alpha, vk_x, C`. `true` means the point is negated.
    pub negate: [bool; 4],
}

/// The forms evaluated. The list is deliberately wider than the one that can
/// be right, so a form that happens to hold is distinguished from one that
/// holds because it is the equation.
pub const CANDIDATE_FORMS: [EquationForm; 6] = [
    EquationForm {
        name: "e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1",
        negate: [true, false, false, false],
    },
    EquationForm {
        name: "e(A,B) * e(-alpha,beta) * e(-vk_x,gamma) * e(-C,delta) == 1",
        negate: [false, true, true, true],
    },
    EquationForm {
        name: "e(A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1",
        negate: [false, false, false, false],
    },
    EquationForm {
        name: "e(-A,B) * e(-alpha,beta) * e(-vk_x,gamma) * e(-C,delta) == 1",
        negate: [true, true, true, true],
    },
    EquationForm {
        name: "e(A,B) * e(-alpha,beta) * e(vk_x,gamma) * e(-C,delta) == 1",
        negate: [false, true, false, true],
    },
    EquationForm {
        name: "e(-A,B) * e(alpha,beta) * e(-vk_x,gamma) * e(C,delta) == 1",
        negate: [true, false, true, false],
    },
];

fn maybe_negate_g1(point: G1Affine, negate: bool) -> G1Affine {
    if negate {
        (-G1Projective::from(point)).into_affine()
    } else {
        point
    }
}

/// Evaluates one candidate form and says whether it holds.
pub fn form_holds(
    form: EquationForm,
    verifying: &VerifyingKey<Bls12_381>,
    public: &PublicInputs,
    proof: &Proof<Bls12_381>,
) -> Result<bool> {
    let x = vk_x(verifying, public)?;
    let g1 = [
        maybe_negate_g1(proof.a, form.negate[0]),
        maybe_negate_g1(verifying.alpha_g1, form.negate[1]),
        maybe_negate_g1(x, form.negate[2]),
        maybe_negate_g1(proof.c, form.negate[3]),
    ];
    let g2: [G2Affine; 4] = [proof.b, verifying.beta_g2, verifying.gamma_g2, verifying.delta_g2];
    let result: PairingOutput<Bls12_381> = Bls12_381::multi_pairing(g1, g2);
    Ok(result.is_zero())
}

/// Mutates a proof's `A` by adding the G1 generator: still a valid, in-subgroup
/// point, and a different one.
pub fn mutate_a(proof: &Proof<Bls12_381>) -> Proof<Bls12_381> {
    let mut mutated = proof.clone();
    mutated.a =
        (G1Projective::from(proof.a) + G1Projective::from(G1Affine::generator())).into_affine();
    mutated
}

/// The same for `B`.
pub fn mutate_b(proof: &Proof<Bls12_381>) -> Proof<Bls12_381> {
    let mut mutated = proof.clone();
    mutated.b =
        (G2Projective::from(proof.b) + G2Projective::from(G2Affine::generator())).into_affine();
    mutated
}

/// The same for `C`.
pub fn mutate_c(proof: &Proof<Bls12_381>) -> Proof<Bls12_381> {
    let mut mutated = proof.clone();
    mutated.c =
        (G1Projective::from(proof.c) + G1Projective::from(G1Affine::generator())).into_affine();
    mutated
}

/// The result of the section 10.1 cross-check for one candidate form.
#[derive(Clone, Debug)]
pub struct FormVerdict {
    pub name: &'static str,
    pub holds_for_valid: bool,
    /// One entry per mutated vector, in the order
    /// `A mutated, B mutated, C mutated, public input mutated`.
    pub holds_for_mutations: [bool; 4],
}

impl FormVerdict {
    /// A form is usable only if it accepts the valid vector and rejects every
    /// mutation.
    pub fn is_the_equation(&self) -> bool {
        self.holds_for_valid && self.holds_for_mutations.iter().all(|held| !held)
    }
}

/// Runs every candidate form against one valid proof and four mutations.
pub fn pairing_equation_report(
    verifying: &VerifyingKey<Bls12_381>,
    public: &PublicInputs,
    proof: &Proof<Bls12_381>,
    mutated_public: &PublicInputs,
) -> Result<Vec<FormVerdict>> {
    let a = mutate_a(proof);
    let b = mutate_b(proof);
    let c = mutate_c(proof);
    let mut verdicts = Vec::with_capacity(CANDIDATE_FORMS.len());
    for form in CANDIDATE_FORMS {
        verdicts.push(FormVerdict {
            name: form.name,
            holds_for_valid: form_holds(form, verifying, public, proof)?,
            holds_for_mutations: [
                form_holds(form, verifying, public, &a)?,
                form_holds(form, verifying, public, &b)?,
                form_holds(form, verifying, public, &c)?,
                form_holds(form, verifying, mutated_public, proof)?,
            ],
        });
    }
    Ok(verdicts)
}

/// The canonical proof bytes of section 10.1: `A || C` in the root cell and
/// `B` in the referenced cell, 192 bytes in total.
///
/// The compressed point encoding is the blst/IETF one ruled in A1: 48 bytes for
/// G1 and 96 for G2, big-endian x with the flags in the first byte, produced
/// and checked by blst rather than by the proving library's serializer.
pub struct CanonicalProof {
    pub a: [u8; 48],
    pub b: [u8; 96],
    pub c: [u8; 48],
}

/// A field element as the 48 big-endian bytes the IETF encoding uses. The
/// modulus is 381 bits, so the top three bits of the first byte are free and
/// carry the compression, infinity and sort flags.
fn fp_be(value: &ark_bls12_381::Fq) -> [u8; 48] {
    let digits = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 48];
    out[48 - digits.len()..].copy_from_slice(&digits);
    out
}

/// The uncompressed IETF serialization blst accepts: big-endian x then y, with
/// the flag bits clear, or the infinity bit alone for the point at infinity.
fn uncompressed_g1(point: &G1Affine) -> [u8; 96] {
    let mut out = [0u8; 96];
    if point.infinity {
        out[0] = 0x40;
        return out;
    }
    out[..48].copy_from_slice(&fp_be(&point.x));
    out[48..].copy_from_slice(&fp_be(&point.y));
    out
}

fn uncompressed_g2(point: &G2Affine) -> [u8; 192] {
    let mut out = [0u8; 192];
    if point.infinity {
        out[0] = 0x40;
        return out;
    }
    // An Fp2 coordinate is serialized with its c1 part first.
    out[..48].copy_from_slice(&fp_be(&point.x.c1));
    out[48..96].copy_from_slice(&fp_be(&point.x.c0));
    out[96..144].copy_from_slice(&fp_be(&point.y.c1));
    out[144..].copy_from_slice(&fp_be(&point.y.c0));
    out
}

/// Ruling A1: V1 wire bytes are what this chain's blst primitives accept and
/// produce, not what the proving library happens to emit. arkworks stays the
/// curve implementation; this is the only place its points become bytes.
///
/// The bytes are defined by a round trip rather than by a description of the
/// layout: deserialize them with blst, compress the result, and the same bytes
/// must come back. Anything that survives that is canonical by construction.
fn compress_g1(point: &G1Affine) -> Result<[u8; 48]> {
    let uncompressed = uncompressed_g1(point);
    let mut affine = blst::blst_p1_affine::default();
    // SAFETY: a 96-byte buffer, which is the width blst reads for an
    // uncompressed G1, and an initialised output.
    let status = unsafe { blst::blst_p1_deserialize(&mut affine, uncompressed.as_ptr()) };
    if status != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(Error::Backend(format!("blst refused a G1 point: {status:?}")));
    }
    let mut out = [0u8; 48];
    // SAFETY: a 48-byte output, the width blst writes for a compressed G1.
    unsafe { blst::blst_p1_affine_compress(out.as_mut_ptr(), &affine) };
    round_trip_g1(&out)?;
    Ok(out)
}

fn compress_g2(point: &G2Affine) -> Result<[u8; 96]> {
    let uncompressed = uncompressed_g2(point);
    let mut affine = blst::blst_p2_affine::default();
    // SAFETY: a 192-byte buffer, the width blst reads for an uncompressed G2.
    let status = unsafe { blst::blst_p2_deserialize(&mut affine, uncompressed.as_ptr()) };
    if status != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(Error::Backend(format!("blst refused a G2 point: {status:?}")));
    }
    let mut out = [0u8; 96];
    // SAFETY: a 96-byte output, the width blst writes for a compressed G2.
    unsafe { blst::blst_p2_affine_compress(out.as_mut_ptr(), &affine) };
    round_trip_g2(&out)?;
    Ok(out)
}

/// The definition of canonical: bytes that blst reads back and re-emits
/// unchanged. Checked at the moment of encoding, so a point can never reach a
/// fixture or a digest without having passed it.
pub fn round_trip_g1(bytes: &[u8; 48]) -> Result<()> {
    let mut affine = blst::blst_p1_affine::default();
    // SAFETY: a 48-byte compressed input and an initialised output.
    let status = unsafe { blst::blst_p1_uncompress(&mut affine, bytes.as_ptr()) };
    if status != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(Error::Backend(format!("blst refused compressed G1 bytes: {status:?}")));
    }
    let mut again = [0u8; 48];
    // SAFETY: as above, in the other direction.
    unsafe { blst::blst_p1_affine_compress(again.as_mut_ptr(), &affine) };
    if again != *bytes {
        return Err(Error::Backend("a compressed G1 point did not round trip".to_string()));
    }
    Ok(())
}

pub fn round_trip_g2(bytes: &[u8; 96]) -> Result<()> {
    let mut affine = blst::blst_p2_affine::default();
    // SAFETY: a 96-byte compressed input and an initialised output.
    let status = unsafe { blst::blst_p2_uncompress(&mut affine, bytes.as_ptr()) };
    if status != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(Error::Backend(format!("blst refused compressed G2 bytes: {status:?}")));
    }
    let mut again = [0u8; 96];
    // SAFETY: as above, in the other direction.
    unsafe { blst::blst_p2_affine_compress(again.as_mut_ptr(), &affine) };
    if again != *bytes {
        return Err(Error::Backend("a compressed G2 point did not round trip".to_string()));
    }
    Ok(())
}

impl CanonicalProof {
    pub fn from_proof(proof: &Proof<Bls12_381>) -> Result<Self> {
        Ok(Self { a: compress_g1(&proof.a)?, b: compress_g2(&proof.b)?, c: compress_g1(&proof.c)? })
    }

    /// The 192 bytes in the order section 10.1 lays the cells out.
    pub fn flat(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(192);
        out.extend_from_slice(&self.a);
        out.extend_from_slice(&self.c);
        out.extend_from_slice(&self.b);
        out
    }
}

/// The canonical verifying key encoding of section 10.1, and its digest.
pub struct CanonicalVerifyingKey {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub ic_count: usize,
}

pub fn canonical_verifying_key(
    verifying: &VerifyingKey<Bls12_381>,
) -> Result<CanonicalVerifyingKey> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&compress_g1(&verifying.alpha_g1)?);
    bytes.extend_from_slice(&compress_g2(&verifying.beta_g2)?);
    bytes.extend_from_slice(&compress_g2(&verifying.gamma_g2)?);
    bytes.extend_from_slice(&compress_g2(&verifying.delta_g2)?);
    for point in verifying.gamma_abc_g1.iter() {
        bytes.extend_from_slice(&compress_g1(point)?);
    }
    let expected = 48 + 96 * 3 + 48 * verifying.gamma_abc_g1.len();
    if bytes.len() != expected {
        return Err(Error::Backend(format!(
            "the canonical verifying key is {} bytes, not {expected}",
            bytes.len()
        )));
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(CanonicalVerifyingKey { bytes, sha256, ic_count: verifying.gamma_abc_g1.len() })
}

/// Public inputs rendered as decimal strings, in the section 10 order.
pub fn public_decimals(public: &PublicInputs) -> Vec<String> {
    public.to_vec().iter().map(crate::field::fr_to_decimal).collect()
}

/// A trivial mutation of one public input, for the fixture.
pub fn mutate_public(public: &PublicInputs, position: usize) -> Result<PublicInputs> {
    let current = public
        .to_vec()
        .get(position)
        .copied()
        .ok_or_else(|| Error::Backend(format!("public input {position} does not exist")))?;
    public
        .with_mutated(position, current + Fr::from(1u64))
        .ok_or_else(|| Error::Backend(format!("public input {position} does not exist")))
}
