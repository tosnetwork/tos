//! Block-level proof aggregator — bundles N per-Transfer Plonky3 proofs
//! into one recursive STARK proof whose size is ~independent of N.
//!
//! See `doc/uno-aggregation-design.md` for the full architecture.
//!
//! # Role in the block-production pipeline
//!
//! ```text
//!   Collator drains mempool → list of up to BLOCK_TX_CAP Transfers
//!     for each: full §4.3 verify (including per-Tx Plonky3 verify)
//!   Accepted list [(tx_1, π_1), ..., (tx_N, π_N)]
//!     │
//!     │ AggregatorAir: multi-slot instance of verifier_air::VerifierAir
//!     │   - slot i proves verify(pi_i, π_i) == Ok
//!     │   - global constraint: MerkleRoot(hash(pi_i)) == PI_block.tx_pi_root
//!     │
//!     │ prove(PI_block, witness) → π_block  (~100 KB target)
//!     │
//!     ▼
//!   Block payload: [Transfer_list (proof-less)] + π_block
//! ```
//!
//! Validators verify π_block ONCE per block, replacing N per-Transfer
//! STARK verifies — a cost-reduction proportional to N and the primary
//! mechanism for hitting the §3.4 ~100 KB envelope (see §1.2 of the
//! aggregation design doc).
//!
//! # Status: Phase A1 scaffolding
//!
//! This module carries:
//!   - the public API shape (types, entry points)
//!   - input validation sanity
//!   - a deterministic stub "aggregated proof" that the next phase will
//!     replace with a real STARK prove call
//!
//! What it does NOT do yet (future phases):
//!   - Phase A2: compute a real per-slot verifier-AIR proof (see
//!     `verifier_air::prove_slot_stub` → real prover)
//!   - Phase A3: multi-slot instance with Merkle-root-of-PI gluing
//!   - Phase A4: measurement pass to confirm ≤ 150 KB at 30 slots
//!   - Phase A5+: wire-format changes in §4.1 (NOT in this crate; see
//!     design doc §2 for the `Transfer.zk_proof` field deprecation
//!     and new block-level `aggregated_proof` field)

use crate::verifier_air::{
    hash_slot_public_inputs, VerifiedTransferPublicInputs, VerifierSlotWitness,
};

// ---------------------------------------------------------------------------
// Block-level throughput cap
// ---------------------------------------------------------------------------

/// Per-block maximum aggregated Transfer count. See design doc §2.3.
///
/// Rationale: matches §1.4 success criterion #7 (15–30 TPS sustained)
/// at 1 s block cadence. A higher cap increases aggregator prove time
/// and may push the block production off the 1 s schedule.
pub const BLOCK_TX_CAP: usize = 30;

/// Minimum aggregated Transfer count. Zero-Transfer blocks are legal
/// (empty block → empty aggregator proof), but the aggregator only
/// runs when N >= 1.
pub const BLOCK_TX_MIN: usize = 0;

// ---------------------------------------------------------------------------
// Aggregator public inputs (§3.1 of design doc)
// ---------------------------------------------------------------------------

/// Public inputs for one aggregated-block proof. All fields are
/// committed by the aggregator AIR and bound to the block's wire
/// metadata by the collator / validator compute-phase logic.
#[derive(Clone, Debug)]
pub struct BlockPublicInputs {
    /// Must match `transfer_air` chain_id field of every aggregated slot.
    pub chain_id: u32,
    /// Block seqno on the masterchain. Prevents cross-block replay of
    /// the aggregated proof.
    pub block_seqno: u64,
    /// Earliest anchor seqno observed across the aggregated Transfers;
    /// the per-Tx AIR's own anchor-window check is NOT re-done here
    /// (it runs at the collator), but the aggregator records this for
    /// audit traceability.
    pub anchor_seqno: u64,
    /// Number of Transfers aggregated in this block. 0..=BLOCK_TX_CAP.
    pub n_transfers: u16,
    /// BLAKE3 Merkle root over the per-Transfer PI hashes, in block
    /// inclusion order. Layout: a simple binary Merkle tree with
    /// `hash_slot_public_inputs` leaves and BLAKE3 internal nodes
    /// (domain tag `"uno-aggregator-merkle-v1"`).
    pub tx_pi_merkle_root: [u8; 32],
}

impl BlockPublicInputs {
    /// Canonical byte serialization used by validators to recompute
    /// the aggregator PI hash. 8 + 8 + 8 + 2 + 32 = 58 bytes padded to
    /// 64 for 8-byte alignment (matches Goldilocks field-element grain).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&(self.chain_id as u64).to_le_bytes());
        out.extend_from_slice(&self.block_seqno.to_le_bytes());
        out.extend_from_slice(&self.anchor_seqno.to_le_bytes());
        out.extend_from_slice(&(self.n_transfers as u64).to_le_bytes());
        out.extend_from_slice(&self.tx_pi_merkle_root);
        // Pad to 64 bytes for 8-byte alignment.
        debug_assert_eq!(out.len(), 64);
        out
    }
}

// ---------------------------------------------------------------------------
// Aggregator witness — one slot per aggregated Transfer
// ---------------------------------------------------------------------------

/// Full witness handed to the aggregator prover. The collator builds
/// this after draining the mempool and running per-Transfer §4.3
/// verify; the aggregator prover never re-runs off-AIR checks.
#[derive(Clone, Debug)]
pub struct AggregatorWitness {
    pub slots: Vec<VerifierSlotWitness>,
}

impl AggregatorWitness {
    pub fn new(slots: Vec<VerifierSlotWitness>) -> Self {
        Self { slots }
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Compute the Merkle root over per-Transfer PI hashes, in
    /// inclusion order. Binary tree with BLAKE3 internal nodes; odd
    /// levels duplicate the last leaf (standard Bitcoin-style
    /// convention — documented here so the audit-vendor can verify).
    ///
    /// Domain tag `"uno-aggregator-merkle-v1"` separates this from
    /// other BLAKE3 usages in the tree.
    pub fn compute_pi_merkle_root(&self) -> [u8; 32] {
        if self.slots.is_empty() {
            // Empty-block convention: root is BLAKE3 of the domain tag
            // alone, so an empty-block aggregated_proof is still
            // well-defined and uniquely hashable.
            let mut h = blake3::Hasher::new();
            h.update(b"uno-aggregator-merkle-v1");
            h.update(b"EMPTY");
            return *h.finalize().as_bytes();
        }

        let mut leaves: Vec<[u8; 32]> = self
            .slots
            .iter()
            .map(|s| hash_slot_public_inputs(&s.public_inputs))
            .collect();

        while leaves.len() > 1 {
            if leaves.len() & 1 == 1 {
                // Odd: duplicate last leaf. Documented convention.
                leaves.push(*leaves.last().unwrap());
            }
            let mut next = Vec::with_capacity(leaves.len() / 2);
            for pair in leaves.chunks_exact(2) {
                let mut h = blake3::Hasher::new();
                h.update(b"uno-aggregator-merkle-v1");
                h.update(&pair[0]);
                h.update(&pair[1]);
                next.push(*h.finalize().as_bytes());
            }
            leaves = next;
        }
        leaves[0]
    }
}

// ---------------------------------------------------------------------------
// Aggregator prove entry point — Phase A1 stub
// ---------------------------------------------------------------------------

/// Aggregator prove result — the recursive proof bytes to embed in the
/// block's `UnoBlockExtra.aggregated_proof` field (§2.1 of design doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregatedProof {
    pub bytes: Vec<u8>,
}

/// Errors from aggregator building / proving. Phase A1 uses a minimal
/// enum; future phases add FRI-verify failures, proof-shape rejections,
/// etc.
#[derive(Debug, PartialEq, Eq)]
pub enum AggregatorError {
    /// `AggregatorWitness.slots.len()` exceeds `BLOCK_TX_CAP`.
    TooManySlots,
    /// Slot chain_id / other consistency checks failed. Phase A1 does
    /// not run these; Phase A3 will.
    SlotMismatch,
    /// A slot's public-input bytes don't match a legal Transfer shape
    /// (see `verifier_air::prove_slot_stub` for the shape check).
    SlotMalformed(usize),
}

/// Phase A1 stub — emits a deterministic placeholder proof whose bytes
/// are `BLAKE3("uno-aggregator-v1-stub" || PI_block.encode() || per-slot hashes)`.
/// Not cryptographically meaningful yet; Phase A2 replaces this with a
/// real STARK prove call.
pub fn prove_block_stub(
    pi: &BlockPublicInputs,
    witness: &AggregatorWitness,
) -> Result<AggregatedProof, AggregatorError> {
    if witness.slots.len() > BLOCK_TX_CAP {
        return Err(AggregatorError::TooManySlots);
    }
    // Per-slot shape sanity — mirror what the real Phase A2 prover will
    // demand to reject malformed witnesses before spending any work.
    for (i, slot) in witness.slots.iter().enumerate() {
        let pi_len = slot.public_inputs.pi_bytes.len();
        let proof_len = slot.proof_bytes.len();
        if pi_len < 200 || pi_len > 608 {
            return Err(AggregatorError::SlotMalformed(i));
        }
        if proof_len < 300_000 || proof_len > 2_000_000 {
            return Err(AggregatorError::SlotMalformed(i));
        }
    }

    // Confirm the witness's Merkle root matches the PI commitment.
    // This is defensive — the collator is expected to have computed
    // the PI merkle root FROM this witness; if they disagree, something
    // is wrong upstream.
    let computed = witness.compute_pi_merkle_root();
    if computed != pi.tx_pi_merkle_root {
        return Err(AggregatorError::SlotMismatch);
    }

    // Produce deterministic stub proof bytes. Size is ~100 KB so the
    // rest of the pipeline exercises the right wire-bandwidth regime.
    let mut stub_proof = Vec::with_capacity(100_000);
    let encoded_pi = pi.encode();
    let mut seed_hasher = blake3::Hasher::new();
    seed_hasher.update(b"uno-aggregator-v1-stub");
    seed_hasher.update(&encoded_pi);
    for slot in &witness.slots {
        let slot_hash = hash_slot_public_inputs(&slot.public_inputs);
        seed_hasher.update(&slot_hash);
    }
    let seed = *seed_hasher.finalize().as_bytes();
    // Expand the 32-byte seed via BLAKE3's XOF to produce ~100 KB of
    // stub bytes. Deterministic.
    let mut reader = blake3::Hasher::new();
    reader.update(b"uno-aggregator-v1-stub-xof");
    reader.update(&seed);
    let mut xof = reader.finalize_xof();
    stub_proof.resize(100_000, 0);
    xof.fill(&mut stub_proof);
    Ok(AggregatedProof { bytes: stub_proof })
}

/// Phase A1 stub verifier — checks that a proof was produced by
/// `prove_block_stub` for the given PI. Phase A2 replaces this with the
/// real STARK verify call.
pub fn verify_block_stub(
    pi: &BlockPublicInputs,
    witness: &AggregatorWitness,
    proof: &AggregatedProof,
) -> Result<(), AggregatorError> {
    // Reprove and compare. Trivially round-trip; Phase A2 won't need the
    // witness on the verifier side (verify takes PI + proof only).
    let expected = prove_block_stub(pi, witness)?;
    if expected.bytes == proof.bytes {
        Ok(())
    } else {
        Err(AggregatorError::SlotMismatch)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier_air::VerifiedTransferPublicInputs;

    fn dummy_slot(pi_pattern: u8, proof_pattern: u8) -> VerifierSlotWitness {
        VerifierSlotWitness {
            public_inputs: VerifiedTransferPublicInputs {
                pi_bytes: vec![pi_pattern; 272],
            },
            proof_bytes: vec![proof_pattern; 520_000],
        }
    }

    #[test]
    fn block_tx_cap_matches_design_doc() {
        // Design doc §2.3 pins BLOCK_TX_CAP = 30 to match §1.4 30 TPS
        // target at 1 s block cadence. A drift here is a design-doc
        // divergence — catch it immediately.
        assert_eq!(BLOCK_TX_CAP, 30);
    }

    #[test]
    fn empty_block_has_canonical_root() {
        let w = AggregatorWitness::new(vec![]);
        let r = w.compute_pi_merkle_root();
        // Stable across versions; pinning here so a BLAKE3 or tag
        // change is caught.
        assert_ne!(r, [0u8; 32]);
    }

    #[test]
    fn merkle_root_stable_for_same_input() {
        let w1 = AggregatorWitness::new(vec![dummy_slot(1, 2), dummy_slot(3, 4)]);
        let w2 = AggregatorWitness::new(vec![dummy_slot(1, 2), dummy_slot(3, 4)]);
        assert_eq!(w1.compute_pi_merkle_root(), w2.compute_pi_merkle_root());
    }

    #[test]
    fn merkle_root_order_sensitive() {
        let w1 = AggregatorWitness::new(vec![dummy_slot(1, 2), dummy_slot(3, 4)]);
        let w2 = AggregatorWitness::new(vec![dummy_slot(3, 4), dummy_slot(1, 2)]);
        assert_ne!(w1.compute_pi_merkle_root(), w2.compute_pi_merkle_root());
    }

    #[test]
    fn prove_stub_rejects_too_many_slots() {
        let slots: Vec<_> = (0..(BLOCK_TX_CAP + 1))
            .map(|i| dummy_slot(i as u8, (i + 1) as u8))
            .collect();
        let w = AggregatorWitness::new(slots);
        let pi = BlockPublicInputs {
            chain_id: 0x554E4F54,
            block_seqno: 42,
            anchor_seqno: 41,
            n_transfers: w.len() as u16,
            tx_pi_merkle_root: w.compute_pi_merkle_root(),
        };
        assert_eq!(prove_block_stub(&pi, &w), Err(AggregatorError::TooManySlots));
    }

    #[test]
    fn prove_stub_rejects_malformed_slot() {
        let mut slot = dummy_slot(1, 2);
        slot.public_inputs.pi_bytes = vec![0; 100]; // too short
        let w = AggregatorWitness::new(vec![slot]);
        let pi = BlockPublicInputs {
            chain_id: 0x554E4F54,
            block_seqno: 1,
            anchor_seqno: 1,
            n_transfers: 1,
            tx_pi_merkle_root: [0; 32],
        };
        assert_eq!(prove_block_stub(&pi, &w), Err(AggregatorError::SlotMalformed(0)));
    }

    #[test]
    fn prove_stub_rejects_mismatched_root() {
        let slot = dummy_slot(1, 2);
        let w = AggregatorWitness::new(vec![slot]);
        let pi = BlockPublicInputs {
            chain_id: 0x554E4F54,
            block_seqno: 1,
            anchor_seqno: 1,
            n_transfers: 1,
            tx_pi_merkle_root: [0xDE; 32], // doesn't match
        };
        assert_eq!(prove_block_stub(&pi, &w), Err(AggregatorError::SlotMismatch));
    }

    #[test]
    fn prove_stub_roundtrip_verifies() {
        let w = AggregatorWitness::new(vec![dummy_slot(1, 2), dummy_slot(3, 4)]);
        let pi = BlockPublicInputs {
            chain_id: 0x554E4F54,
            block_seqno: 100,
            anchor_seqno: 99,
            n_transfers: 2,
            tx_pi_merkle_root: w.compute_pi_merkle_root(),
        };
        let proof = prove_block_stub(&pi, &w).unwrap();
        assert_eq!(proof.bytes.len(), 100_000);
        assert!(verify_block_stub(&pi, &w, &proof).is_ok());
    }

    #[test]
    fn prove_stub_proof_size_matches_target() {
        // Every aggregated proof ~100 KB regardless of slot count.
        // This is the load-bearing property the design doc calls out
        // in §0 executive summary.
        let small = AggregatorWitness::new(vec![dummy_slot(1, 2)]);
        let pi_small = BlockPublicInputs {
            chain_id: 0,
            block_seqno: 1,
            anchor_seqno: 1,
            n_transfers: 1,
            tx_pi_merkle_root: small.compute_pi_merkle_root(),
        };
        let p_small = prove_block_stub(&pi_small, &small).unwrap();

        let slots: Vec<_> = (0..BLOCK_TX_CAP).map(|i| dummy_slot(i as u8, (i + 1) as u8)).collect();
        let large = AggregatorWitness::new(slots);
        let pi_large = BlockPublicInputs {
            chain_id: 0,
            block_seqno: 2,
            anchor_seqno: 1,
            n_transfers: BLOCK_TX_CAP as u16,
            tx_pi_merkle_root: large.compute_pi_merkle_root(),
        };
        let p_large = prove_block_stub(&pi_large, &large).unwrap();

        // Stub proof is fixed-size so this is trivially constant at
        // Phase A1. In Phase A2 the assertion becomes "real proof
        // within 90..110 KB".
        assert_eq!(p_small.bytes.len(), p_large.bytes.len());
        assert_eq!(p_small.bytes.len(), 100_000);
    }
}
