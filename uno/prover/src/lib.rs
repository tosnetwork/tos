//! Wallet-only proof generation. This crate is never a node dependency or C ABI.
//! Authentication, nonce allocation, witness construction and submission belong
//! to the wallet transaction builder, not to this cryptographic primitive.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use chacha20::ChaCha12Rng;
use curve25519_dalek::{RistrettoPoint, Scalar, traits::MultiscalarMul};
use rand::{CryptoRng, SeedableRng, TryCryptoRng, rngs::SysRng};
use tos_uno_crypto_prototype::{ffi::{AbiStatus, KernelLimits}, statement::PreparedStatement};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Public data must match the authenticated statement used by the receiver.
pub struct Statement<'a> {
    pub kind: u32,
    pub limits: &'a KernelLimits,
    pub domain: &'a [u8; 80],
    pub fee: u64,
    pub context: &'a [u8],
    pub points: &'a [[u8; 32]],
    pub receipt_ids: &'a [[u8; 32]],
}

/// Shared scalar witnesses and openings in specification order. Range openings
/// include zero padding. Borrowed secrets remain the caller's erasure obligation.
/// This type deliberately implements neither Debug nor Clone.
pub struct Witness<'a> {
    pub scalars: &'a [Scalar],
    pub range_values: &'a [u64],
    pub range_blindings: &'a [Scalar],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Proof {
    pub commitments: Vec<[u8; 32]>,
    pub responses: Vec<[u8; 32]>,
    pub range_proof: Vec<u8>,
}

/// Wallet-local outcomes. Embedded ABI statuses describe primitive failures,
/// not authenticated provenance or a verdict on a network candidate.
#[derive(Debug, PartialEq, Eq)]
pub enum ProverError {
    Statement(AbiStatus),
    WitnessShape,
    WitnessEquation,
    RangeOpening,
    EntropyUnavailable,
    RangeProver,
    GeneratedProof(AbiStatus),
}

/// Fresh operating-system entropy is acquired for every invocation. There is no
/// public seeded or caller-supplied generator API that a wallet can accidentally
/// reuse. No partial proof is returned on failure.
pub fn prove(statement: &Statement<'_>, witness: &Witness<'_>) -> Result<Proof, ProverError> {
    prove_from_entropy(statement, witness, &mut SysRng)
}

fn prove_from_entropy<R: TryCryptoRng>(statement: &Statement<'_>, witness: &Witness<'_>,
    entropy: &mut R) -> Result<Proof, ProverError> {
    let prepared = prepare(statement, witness)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    entropy.try_fill_bytes(seed.as_mut()).map_err(|_| ProverError::EntropyUnavailable)?;
    let mut rng = ChaCha12Rng::from_seed(*seed);
    generate(statement, witness, &prepared, &mut rng)
}

fn prepare(statement: &Statement<'_>, witness: &Witness<'_>) -> Result<PreparedStatement, ProverError> {
    let prepared = PreparedStatement::new(statement.kind, statement.limits, statement.domain,
        statement.fee, statement.context, statement.points, statement.receipt_ids)
        .map_err(ProverError::Statement)?;
    if prepared.rows().iter().any(|row| row.len() != witness.scalars.len())
        || prepared.ranges().len() != witness.range_values.len()
        || prepared.ranges().len() != witness.range_blindings.len() {
        return Err(ProverError::WitnessShape);
    }
    for (row, target) in prepared.rows().iter().zip(prepared.targets()) {
        // Witness scalars are secret: do not use the verifier's variable-time MSM.
        if RistrettoPoint::multiscalar_mul(witness.scalars, row) != *target {
            return Err(ProverError::WitnessEquation);
        }
    }
    let pc = PedersenGens::default();
    for ((value, blinding), expected) in witness.range_values.iter()
        .zip(witness.range_blindings).zip(prepared.ranges()) {
        if pc.commit(Scalar::from(*value), *blinding).compress() != *expected {
            return Err(ProverError::RangeOpening);
        }
    }
    Ok(prepared)
}

fn generate<R: CryptoRng + ZeroizeOnDrop>(statement: &Statement<'_>, witness: &Witness<'_>,
    prepared: &PreparedStatement, rng: &mut R) -> Result<Proof, ProverError> {
    let masks = Zeroizing::new(witness.scalars.iter().map(|_| Scalar::random(rng)).collect::<Vec<_>>());
    let commitments: Vec<_> = prepared.rows().iter().map(|row|
        RistrettoPoint::multiscalar_mul(masks.iter(), row).compress().to_bytes()).collect();
    let challenge = prepared.sigma_challenge(&commitments);
    // These are scalar-field operations, not monetary integer arithmetic.
    let responses = masks.iter().zip(witness.scalars)
        .map(|(mask, secret)| (mask + challenge * secret).to_bytes()).collect();
    let generators = BulletproofGens::new(64, prepared.ranges().len());
    // Shapes, generator capacity and opening counts are already checked. The
    // pinned backend's normal parameter errors are unreachable here; retain
    // propagation for an unexpected backend failure, not a caller diagnosis.
    let (range, openings) = RangeProof::prove_multiple_with_rng(&generators, &PedersenGens::default(),
        &mut prepared.range_transcript(), witness.range_values, witness.range_blindings, 64, rng)
        .map_err(|_| ProverError::RangeProver)?;
    // A disagreement after prepare is an internal backend inconsistency.
    if openings != prepared.ranges() { return Err(ProverError::RangeProver); }
    let proof = Proof { commitments, responses, range_proof: range.to_bytes() };
    tos_uno_crypto_prototype::verify_relation(statement.kind, statement.limits, statement.domain,
        statement.fee, statement.context, statement.points, statement.receipt_ids,
        &proof.commitments, &proof.responses, &proof.range_proof).map_err(ProverError::GeneratedProof)?;
    Ok(proof)
}

#[cfg(test)]
mod tests;
