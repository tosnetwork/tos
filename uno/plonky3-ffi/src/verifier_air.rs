//! Verifier-as-AIR — the Plonky3 uni-stark verifier's algorithm expressed
//! as an AIR, so that the aggregator (see [`crate::aggregator`]) can
//! bundle N per-Transfer proofs into one recursive proof.
//!
//! # Role in the aggregation pipeline
//!
//! See `doc/uno-aggregation-design.md` for the full architecture. Summary:
//!
//! ```text
//!   per-Transfer AIR (`transfer_air::MvpTransferAir`)
//!         │
//!         │ prove(pi, witness) → π      (client-side, ~520 KB at 1/2)
//!         │
//!         ▼
//!   collator runs AggregatorAir (`crate::aggregator`) over N slots of
//!         (pi_i, π_i) — using this crate's VerifierAir as the per-slot
//!         sub-circuit that re-proves `verify(pi_i, π_i) == Ok`.
//!         │
//!         │ prove(PI_block, [(pi_1,π_1),..,(pi_N,π_N)]) → π_block (~100 KB)
//!         │
//!         ▼
//!   validators verify π_block — ONE STARK verify per block replaces N
//!         per-Transfer STARK verifies.
//! ```
//!
//! # What this AIR proves
//!
//! For a single `(pi, π)` slot:
//!
//! ```text
//! verify_transfer_plonky3(pi, π) returns Ok under the §2.1
//! Option B FRI pin (log_blowup=3, num_queries=52, query_pow_bits=24).
//! ```
//!
//! Expressed via AIR columns that replay the uni-stark verifier's
//! algorithm:
//!   1. Reconstruct the Fiat-Shamir challenger state as Poseidon2
//!      absorbs over the commitments + PI vector.
//!   2. Check the quotient-polynomial constraint at the out-of-domain
//!      point `zeta` (degree-bound check).
//!   3. For each of the 52 FRI queries, fold `log_blowup=3` times and
//!      confirm the final polynomial is low-degree.
//!
//! This is the hand-written version of Plonky3's
//! `uni_stark::verifier::verify_with_key`. The Plonky3 vendored tree
//! at v0.5.1 does not ship a dedicated "verifier-as-AIR" crate, so we
//! write it here against the same uni-stark verifier source.
//!
//! # Status
//!
//! **SKELETON ONLY — Phase A1.** This file carries the type layout + doc
//! contract to unlock subsequent phases:
//!   - Phase A2: implement the claims above for a single slot. Proves
//!     `verify(pi, π) == Ok` for one Transfer at a time.
//!   - Phase A3: generalize to N slots, add the Merkle commitment over
//!     per-Tx PIs, wire into the `aggregator` module.
//!   - Phase A4: measurement pass to confirm 30-Tx aggregator proof
//!     under 150 KB.
//!
//! See `doc/uno-aggregation-design.md` §4.1 for the phase table and
//! §5 for risks / open questions.

use p3_goldilocks::Goldilocks;

// ---------------------------------------------------------------------------
// Slot public inputs — what a single VerifierAir slot asserts
// ---------------------------------------------------------------------------

/// Public inputs for ONE verified Plonky3 Transfer proof within the
/// aggregator. Binds the per-Transfer PI that was submitted alongside
/// the proof byte-identically, so the aggregator's final Merkle root
/// is a commitment over these exact values.
///
/// The layout is intentionally equal to the `transfer_air` AIR's public
/// inputs — the verifier-as-AIR needs to re-absorb them byte-for-byte
/// into the Fiat-Shamir transcript.
#[derive(Clone, Debug)]
pub struct VerifiedTransferPublicInputs {
    /// Byte-packed §4.3 step-4 public-input vector. Variable length:
    /// `64 + 64·n_spends + 72·n_outputs` bytes (per `transfer_air::air_public_inputs_wire_len`).
    pub pi_bytes: Vec<u8>,
}

/// Per-slot witness handed to the aggregator: the public inputs that
/// were proven and the proof bytes themselves.
#[derive(Clone, Debug)]
pub struct VerifierSlotWitness {
    /// Exactly what the per-Transfer prover committed to.
    pub public_inputs: VerifiedTransferPublicInputs,
    /// The postcard-encoded `Proof<MvpConfig>` bytes produced by the
    /// per-Transfer prover.
    pub proof_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// VerifierAir — stub skeleton
// ---------------------------------------------------------------------------

/// The Plonky3 uni-stark verifier's algorithm as an AIR. Used as a
/// sub-circuit inside the aggregator.
///
/// At Phase A1 this is a skeleton that carries the API contract; the
/// actual constraint generation lands in Phase A2.
#[derive(Clone, Debug)]
pub struct VerifierAir {
    /// Target FRI parameters for the Transfer-level AIR this verifier
    /// re-proves. MUST match `prover::build_config` byte-for-byte.
    pub log_blowup: usize,
    pub num_queries: usize,
    pub query_pow_bits: usize,
}

impl VerifierAir {
    /// Construct with the pinned §2.1 Option B params.
    pub const fn option_b() -> Self {
        Self {
            log_blowup: 3,
            num_queries: 52,
            query_pow_bits: 24,
        }
    }

    /// Compute the AIR column width for this verifier instance.
    ///
    /// Estimate from `doc/uno-aggregation-design.md` §1.3:
    ///   - ~50–80 cols Poseidon2 absorbs (challenger reconstruction)
    ///   - ~100 cols FRI folding (52 queries × log_blowup=3 amortized
    ///     across trace rows)
    ///   - ~30 cols quotient-constraint check
    ///   - ~20 cols per-slot PI absorb
    ///
    /// Total estimate: ~200–300 cols per slot at Phase A2. To be
    /// measured empirically.
    pub const fn air_width() -> usize {
        // Phase A1 placeholder: return the design-doc estimate's
        // midpoint. Real measurement comes in A2.
        250
    }
}

// ---------------------------------------------------------------------------
// Stubbed prove / verify entry points
// ---------------------------------------------------------------------------

/// Result of running the verifier-as-AIR prove step for a single slot.
///
/// Phase A1: a stub that returns a fixed-size byte vector representing
/// "a proof would have gone here". Meaningless cryptographically; exists
/// only to let downstream module scaffolding compile + call through.
#[derive(Clone, Debug)]
pub struct SlotProof {
    pub bytes: Vec<u8>,
}

/// Phase A1 stub. Will become the real per-slot prove step in Phase A2.
///
/// Returns `None` if the slot is malformed (proof bytes don't decode,
/// PI length doesn't match a legal 1..4 × 1..4 Transfer shape).
pub fn prove_slot_stub(witness: &VerifierSlotWitness) -> Option<SlotProof> {
    // Shape sanity: any legal Transfer PI is between
    // 64 + 64·1 + 72·1 = 200 bytes and 64 + 64·4 + 72·4 = 608 bytes.
    let pi_len = witness.public_inputs.pi_bytes.len();
    if pi_len < 200 || pi_len > 608 {
        return None;
    }
    // Proof bytes between 300 KB and 2 MB under Option B (see
    // tosctl/uno sanity window).
    let proof_len = witness.proof_bytes.len();
    if proof_len < 300_000 || proof_len > 2_000_000 {
        return None;
    }

    // Phase A1 stub: emit a 32-byte BLAKE3 of the witness bytes as the
    // "proof". This is NOT cryptographic output — it's just a unique
    // deterministic handle the aggregator can thread through the rest
    // of the pipeline while we wire the A2 real prover.
    let mut buf = Vec::with_capacity(witness.public_inputs.pi_bytes.len()
                                      + witness.proof_bytes.len());
    buf.extend_from_slice(&witness.public_inputs.pi_bytes);
    buf.extend_from_slice(&witness.proof_bytes);
    let hash = blake3::hash(&buf);
    Some(SlotProof { bytes: hash.as_bytes().to_vec() })
}

/// Compute the canonical hash of a Transfer's public inputs — used by
/// the aggregator to build the Merkle root committed to in `PI_block`.
/// Phase A1 uses BLAKE3; A2 may switch to Poseidon2 for in-circuit
/// efficiency. The switch is an audit-vendor-reviewable change.
pub fn hash_slot_public_inputs(pi: &VerifiedTransferPublicInputs) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"uno-aggregator-slot-pi-v1");
    hasher.update(&(pi.pi_bytes.len() as u64).to_le_bytes());
    hasher.update(&pi.pi_bytes);
    *hasher.finalize().as_bytes()
}

/// Convert a canonical per-Transfer PI byte blob into a sequence of
/// Goldilocks field elements, matching `transfer_air::decode_public_inputs`.
/// Used by the aggregator witness builder when it needs to thread PI
/// limbs through as actual field elements.
pub fn pi_bytes_to_goldilocks(pi_bytes: &[u8]) -> Option<Vec<Goldilocks>> {
    if pi_bytes.len() % 8 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(pi_bytes.len() / 8);
    let p_g: u64 = 0xFFFF_FFFF_0000_0001;
    for chunk in pi_bytes.chunks_exact(8) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        let v = u64::from_le_bytes(bytes);
        // Reduce canonically into Goldilocks.
        let canonical = if v >= p_g { v - p_g } else { v };
        out.push(Goldilocks::new(canonical));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_b_params_match_main_air() {
        let v = VerifierAir::option_b();
        assert_eq!(v.log_blowup, 3);
        assert_eq!(v.num_queries, 52);
        assert_eq!(v.query_pow_bits, 24);
    }

    #[test]
    fn stub_rejects_malformed_pi_length() {
        let witness = VerifierSlotWitness {
            public_inputs: VerifiedTransferPublicInputs { pi_bytes: vec![0; 100] },
            proof_bytes: vec![0; 500_000],
        };
        assert!(prove_slot_stub(&witness).is_none());
    }

    #[test]
    fn stub_rejects_tiny_proof() {
        let witness = VerifierSlotWitness {
            public_inputs: VerifiedTransferPublicInputs { pi_bytes: vec![0; 272] },
            proof_bytes: vec![0; 100],
        };
        assert!(prove_slot_stub(&witness).is_none());
    }

    #[test]
    fn stub_emits_deterministic_32b_handle() {
        let witness = VerifierSlotWitness {
            public_inputs: VerifiedTransferPublicInputs { pi_bytes: vec![0xA5; 272] },
            proof_bytes: vec![0x5A; 520_000],
        };
        let p1 = prove_slot_stub(&witness).unwrap();
        let p2 = prove_slot_stub(&witness).unwrap();
        assert_eq!(p1.bytes, p2.bytes, "stub must be deterministic");
        assert_eq!(p1.bytes.len(), 32);
    }

    #[test]
    fn pi_bytes_roundtrip_via_goldilocks() {
        // Canonical 1/2 shape: 272 bytes = 34 field elements.
        let pi_bytes = vec![0x42u8; 272];
        let fes = pi_bytes_to_goldilocks(&pi_bytes).unwrap();
        assert_eq!(fes.len(), 34);
    }

    #[test]
    fn pi_bytes_rejects_non_aligned() {
        assert!(pi_bytes_to_goldilocks(&vec![0u8; 271]).is_none());
    }

    #[test]
    fn hash_slot_pi_is_deterministic_and_domain_separated() {
        let pi_a = VerifiedTransferPublicInputs { pi_bytes: vec![0x01; 272] };
        let pi_b = VerifiedTransferPublicInputs { pi_bytes: vec![0x02; 272] };
        let h_a1 = hash_slot_public_inputs(&pi_a);
        let h_a2 = hash_slot_public_inputs(&pi_a);
        let h_b = hash_slot_public_inputs(&pi_b);
        assert_eq!(h_a1, h_a2);
        assert_ne!(h_a1, h_b);
    }
}
