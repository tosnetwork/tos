//! D64 specialization of the existing SEND relation, not a new relation.
//!
//! The dedicated v2 ABI requires matching D78 host reconstruction. Authentication of the context,
//! fee components, identities and state is a host obligation. Success neither
//! authorizes a payout nor permits installing a pending receipt.
use bulletproofs::PedersenGens;
use curve25519_dalek::{Scalar, ristretto::CompressedRistretto, traits::IsIdentity};
use merlin::Transcript;

use crate::{ffi::{AbiStatus, KernelLimits, UNO_RELATION_SEND}, relation};

/// Separate public destinations of value. Only operation_fee belongs to D32 F.
#[derive(Clone, Copy)]
pub struct WithdrawalAmounts {
    pub principal: u64,
    pub outward_fee: u64,
    pub operation_fee: u64,
}

impl WithdrawalAmounts {
    pub fn total(&self) -> Result<u64, AbiStatus> {
        if self.principal == 0 { return Err(AbiStatus::UNO_CRYPTO_DECODE); }
        self.principal.checked_add(self.outward_fee)
            .ok_or(AbiStatus::UNO_CRYPTO_DECODE)
    }
}

/// Public, transient opening scalar: never a stored state or wire field.
/// These event labels are the explicit D64 implementation encoding; the host
/// must not substitute a Deposit identity or the system-encryption domain.
pub fn public_opening(domain: &[u8; 80], withdrawal: &[u8; 32], attempt: &[u8; 32],
    owner: &[u8; 32], total: u64) -> Result<Scalar, AbiStatus> {
    let p = CompressedRistretto(*owner).decompress().ok_or(AbiStatus::UNO_CRYPTO_DECODE)?;
    if p.is_identity() || total == 0 { return Err(AbiStatus::UNO_CRYPTO_DECODE); }
    let mut transcript = Transcript::new(b"uno-v2/withdrawal-opening");
    transcript.append_message(b"protocol-domain", domain);
    transcript.append_message(b"withdrawal-id", withdrawal);
    transcript.append_message(b"attempt-id", attempt);
    transcript.append_message(b"owner-P", owner);
    transcript.append_message(b"amount", &total.to_le_bytes());
    let mut wide = [0; 64];
    transcript.challenge_bytes(b"r", &mut wide);
    nonzero_opening(&wide)
}

fn nonzero_opening(wide: &[u8; 64]) -> Result<Scalar, AbiStatus> {
    let r = Scalar::from_bytes_mod_order_wide(wide);
    if r == Scalar::ZERO { return Err(AbiStatus::UNO_CRYPTO_DECODE); }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zero_opening_is_rejected_without_resampling() {
        assert_eq!(nonzero_opening(&[0; 64]), Err(AbiStatus::UNO_CRYPTO_DECODE));
    }
}

/// P_A, old C/D, new C/D, J. No P_B or transfer C/D input exists.
pub struct WithdrawalStatement {
    domain: [u8; 80],
    fee: u64,
    context: Vec<u8>,
    points: [[u8; 32]; 10],
}

impl WithdrawalStatement {
    pub fn new(limits: &KernelLimits, domain: [u8; 80], withdrawal: [u8; 32],
        attempt: [u8; 32], amounts: WithdrawalAmounts, authenticated_context: &[u8],
        balance_points: [[u8; 32]; 6]) -> Result<Self, AbiStatus> {
        relation::validate_limits(limits)?;
        let total = amounts.total()?;
        // D66: checked total above links the public payout amounts before any
        // scalar conversion. T <= V_max belongs to the existing range proof,
        // not a second construction/admission gate.
        if authenticated_context.is_empty() {
            return Err(AbiStatus::UNO_CRYPTO_DECODE);
        }
        // Bound allocation before copying caller bytes. Context includes a
        // fixed explicit operation domain, two IDs and three public u64 amounts.
        const TAG: &[u8] = b"uno-v2/withdrawal-statement/v2";
        let size = TAG.len().checked_add(88)
            .and_then(|n| n.checked_add(authenticated_context.len()))
            .ok_or(AbiStatus::UNO_CRYPTO_DECODE)?;
        if size > limits.max_context_bytes { return Err(AbiStatus::UNO_CRYPTO_DECODE); }
        let r = public_opening(&domain, &withdrawal, &attempt, &balance_points[0], total)?;
        let p = CompressedRistretto(balance_points[0]).decompress().ok_or(AbiStatus::UNO_CRYPTO_DECODE)?;
        let generators = PedersenGens::default();
        let commitment = (Scalar::from(total) * generators.B + r * generators.B_blinding).compress().to_bytes();
        let handle = (r * p).compress().to_bytes();
        let points = [balance_points[0], balance_points[0], balance_points[1], balance_points[2],
            balance_points[3], balance_points[4], commitment, handle, handle, balance_points[5]];
        let mut context = Vec::with_capacity(size);
        context.extend_from_slice(TAG);
        context.extend_from_slice(&withdrawal);
        context.extend_from_slice(&attempt);
        for value in [amounts.principal, amounts.outward_fee, amounts.operation_fee] {
            context.extend_from_slice(&value.to_le_bytes());
        }
        context.extend_from_slice(authenticated_context);
        relation::prepare(UNO_RELATION_SEND, limits, &domain, amounts.operation_fee, &context, &points, &[])?;
        Ok(Self { domain, fee: amounts.operation_fee, context, points })
    }

    pub fn domain(&self) -> &[u8; 80] { &self.domain }
    pub fn fee(&self) -> u64 { self.fee }
    pub fn context(&self) -> &[u8] { &self.context }
    pub fn points(&self) -> &[[u8; 32]; 10] { &self.points }

    pub fn verify(&self, limits: &KernelLimits, commitments: &[[u8; 32]], responses: &[[u8; 32]],
        range_proof: &[u8]) -> Result<(), AbiStatus> {
        relation::verify_relation(UNO_RELATION_SEND, limits, &self.domain, self.fee, &self.context,
            &self.points, &[], commitments, responses, range_proof)
    }
}
