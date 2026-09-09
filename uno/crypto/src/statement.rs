//! Public statement preparation shared with independently built wallet code.
//!
//! This module accepts no secret witnesses and performs no proof generation.
//! Preparation does not authenticate the domain, context, state or receipt IDs.
//! A wallet must obtain those from its authenticated view before proving.

use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use merlin::Transcript;

use crate::{ffi::{AbiStatus, KernelLimits}, relation};

/// Read-only view of the same statement used by the node verifier.
/// Mutating a returned transcript clone cannot change this statement.
pub struct PreparedStatement(relation::Relation);

impl PreparedStatement {
    pub fn new(
        kind: u32, limits: &KernelLimits, domain: &[u8; 80], fee: u64,
        context: &[u8], points: &[[u8; 32]], receipt_ids: &[[u8; 32]],
    ) -> Result<Self, AbiStatus> {
        relation::prepare(kind, limits, domain, fee, context, points, receipt_ids).map(Self)
    }

    /// Each column denotes a shared witness, not an independent response per row.
    /// Wallet operations on secret witnesses must use constant-time group methods.
    pub fn rows(&self) -> &[Vec<RistrettoPoint>] { &self.0.rows }

    pub fn targets(&self) -> &[RistrettoPoint] { &self.0.targets }

    /// Includes the identity padding required by the aggregated range proof.
    pub fn ranges(&self) -> &[CompressedRistretto] { &self.0.ranges }

    /// All prover first messages must be supplied in equation order. Encoding
    /// and arity are checked by final verification; this is not an admission API.
    pub fn sigma_challenge(&self, commitments: &[[u8; 32]]) -> Scalar {
        relation::sigma_transcript(self.0.transcript.clone(), commitments).1
    }

    pub fn range_transcript(&self) -> Transcript {
        relation::range_transcript(self.0.transcript.clone())
    }
}
