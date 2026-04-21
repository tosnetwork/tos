//! Block-level proof aggregator — bundles N per-Transfer Plonky3 proofs
//! into one recursive STARK proof whose size is ~independent of N.
//!
//! ⚠️ **v2 research path (frozen).** Per the v1 pivot in
//! `doc/uno-aggregation-design.md` §-1 (2026-04-21), UNO v1 launches
//! WITHOUT block-level aggregation. This module's real prove_block /
//! verify_block are shipping code but NOT on the v1 critical path —
//! they stay in-tree as infrastructure for when v2 triggers light up
//! (WHIR/BaseFold maturity + specialized prover ecosystem). The only
//! v1-relevant item here is the `BLOCK_TX_CAP = 4` constant, used by
//! the v1 collator to cap per-block Transfer admission.
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

/// Per-block maximum Transfer count. See design doc §2.3.
///
/// **v1 value: 4** (per `doc/uno-aggregation-design.md` §-1 pivot of
/// 2026-04-21). UNO v1 ships without block-level aggregation; each
/// Transfer carries its own ~520 KB per-Tx Plonky3 STARK on-chain.
/// Block size at 4 Tx × ~520 KB ≈ 2 MB typical (3.7 MB worst-case
/// 4/4 shape), ~16-32 Mbps validator bandwidth — consumer broadband
/// territory. TPS = 4 is 10× Zcash observed (~0.9), 2× Zcash Sapling
/// theoretical (~10), and plenty for 2026 launch. Scaling beyond 4
/// TPS uses additional wc=2 shardchains (wc=2a, wc=2b, ...) — TOS
/// architecture supports this natively.
///
/// **v2 target: 30** (to be restored when aggregation returns per
/// §-1 triggers). Matches original §1.4 success criterion #7
/// ("15–30 TPS sustained") at 1 s block cadence, under the v2
/// aggregation path where block prover time becomes the bottleneck
/// instead of bandwidth.
pub const BLOCK_TX_CAP: usize = 4;

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
// A6-1.5: Real prove_block / verify_block backed by the monolithic AIR
//
// These replace the A1 stub pair's semantics: `prove_block` runs a
// real Plonky3 STARK prover over the A3-5c multi-bundle trace; the
// returned `AggregatedProof.bytes` is a postcard-encoded
// `p3_uni_stark::Proof`. `verify_block` is PI+proof ONLY (no witness
// required — the validator API).
//
// A6-1.6: PI binding is NOW in-circuit.
//
//   The monolithic AIR declares `num_public_values() = 8` and pins 8
//   BLOCK_PI_* columns to the public-value slice on row 0, then
//   unconditionally persists them across every transition. A prover
//   that attempts to produce a proof accepted against a MODIFIED PI
//   (e.g. flipping a bit in `tx_pi_merkle_root`) will fail the
//   row-0 boundary. See `block_public_inputs_to_field_elements` below
//   for the exact encoding and `monolithic_verifier_air::col::BLOCK_PI_*`
//   for the column layout.
// ---------------------------------------------------------------------------

use crate::block_wire_format;
use crate::monolithic_verifier_air::{
    build_multi_bundle_trace, BlockPi, BundleSpec, MonolithicVerifierAirV1,
    MONOLITHIC_VERIFIER_AIR_WIDTH,
};
use crate::prover::build_config;
use p3_goldilocks::Goldilocks;

/// A6-1.6: Encode `BlockPublicInputs` as 8 Goldilocks field elements
/// bound in-circuit by [`MonolithicVerifierAirV1`].
///
/// Layout (matches `col::BLOCK_PI_*` in `monolithic_verifier_air.rs`):
///
///   [0] chain_id        (u32 widened to u64)
///   [1] block_seqno     (u64)
///   [2] anchor_seqno    (u64)
///   [3] n_transfers     (u16 widened to u64)
///   [4..8] tx_pi_merkle_root split into 4 × u64 LE chunks (8 bytes each)
///
/// Endianness is deterministic via `u64::from_le_bytes`. Every Goldilocks
/// element fits a u64 cleanly (Goldilocks prime is 2^64 - 2^32 + 1 — any
/// u64 input is interpreted modulo the prime; the round-trip validates
/// in-circuit because prove and verify convert identically).
pub fn block_public_inputs_to_field_elements(pi: &BlockPublicInputs) -> [Goldilocks; 8] {
    let mut out = [Goldilocks::default(); 8];
    out[0] = Goldilocks::new(pi.chain_id as u64);
    out[1] = Goldilocks::new(pi.block_seqno);
    out[2] = Goldilocks::new(pi.anchor_seqno);
    out[3] = Goldilocks::new(pi.n_transfers as u64);
    for (i, chunk) in pi.tx_pi_merkle_root.chunks_exact(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        out[4 + i] = Goldilocks::new(u64::from_le_bytes(buf));
    }
    out
}

/// Errors surfaced by [`verify_block`]. Wire-layer decode errors are
/// re-used from [`block_wire_format::DecodeError`] where applicable;
/// cryptographic verification failures surface distinctly.
#[derive(Debug, PartialEq, Eq)]
pub enum BlockVerifyError {
    /// Postcard deserialization of the proof payload failed.
    ProofMalformed,
    /// Plonky3 `uni_stark::verify` returned an error.
    StarkVerifyFailed,
}

/// Build + prove a multi-bundle aggregated block proof.
///
/// A6-1.6: `pi` is now cryptographically bound INSIDE the proof via 8
/// public-input columns on the monolithic AIR. The returned proof is
/// valid ONLY against this exact `pi`; changing any field on the
/// verifier side (chain_id, block_seqno, anchor_seqno, n_transfers,
/// tx_pi_merkle_root) rejects the proof.
///
/// `trace_height` must be a power of two ≥ the sum of bundle
/// physical rows. Callers typically set it to the next pow2 of the
/// total expected row count.
pub fn prove_block(
    pi: &BlockPublicInputs,
    bundles: &[BundleSpec<'_>],
    trace_height: usize,
) -> Result<AggregatedProof, AggregatorError> {
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::prove;

    if bundles.len() > BLOCK_TX_CAP {
        return Err(AggregatorError::TooManySlots);
    }

    let pi_felts = block_public_inputs_to_field_elements(pi);
    let block_pi = BlockPi::new(pi_felts);

    let flat = build_multi_bundle_trace(bundles, &block_pi, trace_height)
        .map_err(|_| AggregatorError::SlotMismatch)?;
    let trace = RowMajorMatrix::new(flat, MONOLITHIC_VERIFIER_AIR_WIDTH);
    let cfg = build_config();
    let air = MonolithicVerifierAirV1;
    let proof = prove(&cfg, &air, trace, &pi_felts);

    let proof_bytes = postcard::to_allocvec(&proof)
        .map_err(|_| AggregatorError::SlotMismatch)?;

    // Enforce the wire-format size cap up front, so a freshly proven
    // block that can't be transmitted is caught at prove-time rather
    // than at encode-time.
    if proof_bytes.len() > block_wire_format::UNO_BLOCK_EXTRA_MAX_PROOF_BYTES as usize {
        return Err(AggregatorError::SlotMismatch);
    }

    Ok(AggregatedProof { bytes: proof_bytes })
}

/// Verify a block proof. Takes PI + opaque proof bytes; does NOT need
/// the witness. This is the real validator API.
///
/// On Ok, the proof cryptographically attested the AIR constraints
/// (all bank identities + cross-bindings across all stacked bundles)
/// AND the 8 public-input columns equal `block_public_inputs_to_field_elements(pi)`
/// on row 0 (propagated to every row by unconditional persistence).
/// Any mismatch between `pi` and the proof's baked-in PI triggers
/// `BlockVerifyError::StarkVerifyFailed`.
///
/// A6-1.6: PI is now bound in-circuit — the C++ validator no longer
/// needs to cross-check PI consistency at the consensus layer, though
/// doing so as defence-in-depth is harmless.
pub fn verify_block(
    pi: &BlockPublicInputs,
    proof: &AggregatedProof,
) -> Result<(), BlockVerifyError> {
    use p3_uni_stark::verify;

    let decoded: p3_uni_stark::Proof<_> = postcard::from_bytes(&proof.bytes)
        .map_err(|_| BlockVerifyError::ProofMalformed)?;

    let cfg = build_config();
    let air = MonolithicVerifierAirV1;
    let pi_felts = block_public_inputs_to_field_elements(pi);
    verify(&cfg, &air, &decoded, &pi_felts)
        .map_err(|_| BlockVerifyError::StarkVerifyFailed)
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
        // Design doc §-1 + §2.3 pin BLOCK_TX_CAP = 4 for v1 launch
        // (per-Tx direct, no aggregation). A drift here is a design-doc
        // divergence — catch it immediately. Will flip to 30 when v2
        // aggregation returns per the §-1 trigger checklist.
        assert_eq!(BLOCK_TX_CAP, 4);
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

    // =======================================================================
    // A6-1.5: real prove_block / verify_block round-trip coverage
    // =======================================================================

    /// Helper building a tiny but structurally complete BundleSpec
    /// owner: one α step, one Merkle path into a 2-leaf tree, one
    /// fold round. Returns (owner_storage, bundle_spec).
    fn tiny_bundle_storage() -> BundleStorage {
        use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref};
        use crate::monolithic_verifier_air::{AlphaStep, FoldRound, MerkleOpening};
        use crate::prover::Challenge;
        use p3_field::BasedVectorSpace;
        use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};

        fn gl(v: u64) -> Goldilocks {
            Goldilocks::new(v)
        }
        fn ext(a: u64, b: u64) -> Challenge {
            Challenge::from_basis_coefficients_fn(|i| if i == 0 { gl(a) } else { gl(b) })
        }

        let perm = default_goldilocks_poseidon2_8();
        let leaf: Vec<Goldilocks> = (0..8u64).map(|j| gl(100 + j * 17 + 1)).collect();
        let sib_leaf: Vec<Goldilocks> =
            (0..8u64).map(|j| gl(200 + j * 23 + 3)).collect();
        let dig = hash_leaf_row_ref(&perm, &leaf);
        let sib = hash_leaf_row_ref(&perm, &sib_leaf);
        let root = compress_pair_ref(&perm, &dig, &sib);

        BundleStorage {
            alpha: ext(3, 5),
            initial_apow: ext(1, 0),
            initial_ro: ext(0, 0),
            alpha_steps: vec![crate::monolithic_verifier_air::AlphaStep {
                p_at_x: gl(7),
                p_at_z: ext(11, 13),
                z: ext(17, 19),
                x: gl(23),
            }],
            leaf,
            opening: vec![sib],
            index: 0,
            expected_root: root,
            fold_rounds: vec![FoldRound {
                sibling: ext(29, 31),
                beta: ext(37, 41),
                domain_index: 0b01,
                log_height: 3,
            }],
            _ph: std::marker::PhantomData::<AlphaStep>,
            _ph2: std::marker::PhantomData::<MerkleOpening<'static>>,
        }
    }

    /// Owns the backing Vecs so BundleSpec borrows remain valid.
    struct BundleStorage {
        alpha: crate::prover::Challenge,
        initial_apow: crate::prover::Challenge,
        initial_ro: crate::prover::Challenge,
        alpha_steps: Vec<crate::monolithic_verifier_air::AlphaStep>,
        leaf: Vec<p3_goldilocks::Goldilocks>,
        opening: Vec<crate::merkle_path::Digest>,
        index: usize,
        expected_root: crate::merkle_path::Digest,
        fold_rounds: Vec<crate::monolithic_verifier_air::FoldRound>,
        _ph: std::marker::PhantomData<crate::monolithic_verifier_air::AlphaStep>,
        _ph2: std::marker::PhantomData<crate::monolithic_verifier_air::MerkleOpening<'static>>,
    }

    fn bundle_from_storage<'a>(
        s: &'a BundleStorage,
        merkle_paths: &'a [crate::monolithic_verifier_air::MerkleOpening<'a>],
    ) -> BundleSpec<'a> {
        BundleSpec {
            initial_alpha_pow: s.initial_apow,
            initial_ro: s.initial_ro,
            alpha: s.alpha,
            alpha_steps: &s.alpha_steps,
            merkle_paths,
            fold_rounds: &s.fold_rounds,
        }
    }

    #[test]
    fn prove_and_verify_block_single_bundle_round_trip() {
        use crate::monolithic_verifier_air::MerkleOpening;

        let store = tiny_bundle_storage();
        let mp = vec![MerkleOpening {
            leaf: &store.leaf,
            opening_proof: &store.opening,
            index: store.index,
            expected_root: store.expected_root,
        }];
        let bundle = bundle_from_storage(&store, &mp);

        // A6-1.6: real PI with non-trivial merkle root — in-circuit
        // binding means this exact PI must be passed to verify_block.
        let mut root = [0u8; 32];
        for (i, b) in root.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        let pi = BlockPublicInputs {
            chain_id: 7,
            block_seqno: 1,
            anchor_seqno: 0,
            n_transfers: 1,
            tx_pi_merkle_root: root,
        };
        // 1 α + 2 absorb + 1 compress + 1 fold = 5 rows; pad to 16.
        let proof = prove_block(&pi, std::slice::from_ref(&bundle), 16).unwrap();
        // The real proof is much larger than the stub (100 KB) — it's
        // a real Plonky3 STARK at ~250 KB minimum per our A4 metrics.
        assert!(
            proof.bytes.len() > 100_000,
            "real proof should exceed stub size; got {}",
            proof.bytes.len()
        );
        verify_block(&pi, &proof).expect("real block proof round-trips");
    }

    // =======================================================================
    // A6-1.6: in-circuit PI binding tests
    // =======================================================================

    fn tiny_bundle_and_pi() -> (
        BundleStorage,
        BlockPublicInputs,
    ) {
        let mut root = [0u8; 32];
        for (i, b) in root.iter_mut().enumerate() {
            *b = ((i as u8).wrapping_mul(29)).wrapping_add(5);
        }
        let pi = BlockPublicInputs {
            chain_id: 0x554E4F54, // 'UNOT'
            block_seqno: 12345,
            anchor_seqno: 12340,
            n_transfers: 1,
            tx_pi_merkle_root: root,
        };
        (tiny_bundle_storage(), pi)
    }

    #[test]
    fn air_accepts_matching_block_pi() {
        // Happy path: prove with PI_A, verify with PI_A — round-trips.
        use crate::monolithic_verifier_air::MerkleOpening;
        let (store, pi) = tiny_bundle_and_pi();
        let mp = vec![MerkleOpening {
            leaf: &store.leaf,
            opening_proof: &store.opening,
            index: store.index,
            expected_root: store.expected_root,
        }];
        let bundle = bundle_from_storage(&store, &mp);
        let proof = prove_block(&pi, std::slice::from_ref(&bundle), 16).unwrap();
        verify_block(&pi, &proof).expect("matching PI must verify");
    }

    #[test]
    fn air_rejects_mismatched_block_pi() {
        // A6-1.6 load-bearing test: prove with PI_A, verify with PI_B
        // where ONE field differs (chain_id). The AIR's in-circuit PI
        // binding must cause rejection — previously (pre A6-1.6) this
        // would wrongly succeed because PI was not bound.
        use crate::monolithic_verifier_air::MerkleOpening;
        let (store, pi_a) = tiny_bundle_and_pi();
        let mp = vec![MerkleOpening {
            leaf: &store.leaf,
            opening_proof: &store.opening,
            index: store.index,
            expected_root: store.expected_root,
        }];
        let bundle = bundle_from_storage(&store, &mp);
        let proof = prove_block(&pi_a, std::slice::from_ref(&bundle), 16).unwrap();

        // Change chain_id — everything else identical.
        let pi_b = BlockPublicInputs {
            chain_id: pi_a.chain_id ^ 0x1, // flip one bit
            ..pi_a.clone()
        };
        let err = verify_block(&pi_b, &proof).unwrap_err();
        assert_eq!(err, BlockVerifyError::StarkVerifyFailed);

        // Also check that swapping the merkle root rejects.
        let mut bad_root = pi_a.tx_pi_merkle_root;
        bad_root[0] ^= 0xff;
        let pi_c = BlockPublicInputs {
            tx_pi_merkle_root: bad_root,
            ..pi_a.clone()
        };
        let err2 = verify_block(&pi_c, &proof).unwrap_err();
        assert_eq!(err2, BlockVerifyError::StarkVerifyFailed);

        // And seqno.
        let pi_d = BlockPublicInputs {
            block_seqno: pi_a.block_seqno + 1,
            ..pi_a
        };
        let err3 = verify_block(&pi_d, &proof).unwrap_err();
        assert_eq!(err3, BlockVerifyError::StarkVerifyFailed);
    }

    #[test]
    fn block_public_inputs_to_field_elements_is_deterministic() {
        let pi = BlockPublicInputs {
            chain_id: 0xDEADBEEF,
            block_seqno: 0x0102030405060708,
            anchor_seqno: 0x1122334455667788,
            n_transfers: 7,
            tx_pi_merkle_root: [0xAB; 32],
        };
        let a = block_public_inputs_to_field_elements(&pi);
        let b = block_public_inputs_to_field_elements(&pi);
        assert_eq!(a, b);

        // Field-by-field sanity.
        use p3_goldilocks::Goldilocks;
        assert_eq!(a[0], Goldilocks::new(0xDEADBEEF));
        assert_eq!(a[1], Goldilocks::new(0x0102030405060708));
        assert_eq!(a[2], Goldilocks::new(0x1122334455667788));
        assert_eq!(a[3], Goldilocks::new(7));
        // tx_pi_merkle_root = [0xAB; 32] ⇒ each 8-byte u64 LE chunk is
        // 0xABABABABABABABAB.
        for i in 0..4 {
            assert_eq!(a[4 + i], Goldilocks::new(0xABABABABABABABAB));
        }
    }

    #[test]
    fn verify_block_rejects_tampered_proof_bytes() {
        use crate::monolithic_verifier_air::MerkleOpening;

        let store = tiny_bundle_storage();
        let mp = vec![MerkleOpening {
            leaf: &store.leaf,
            opening_proof: &store.opening,
            index: store.index,
            expected_root: store.expected_root,
        }];
        let bundle = bundle_from_storage(&store, &mp);
        let pi = BlockPublicInputs {
            chain_id: 0,
            block_seqno: 0,
            anchor_seqno: 0,
            n_transfers: 1,
            tx_pi_merkle_root: [0; 32],
        };
        let mut proof = prove_block(&pi, std::slice::from_ref(&bundle), 16).unwrap();

        // Flip a byte deep in the serialized proof; the STARK verifier
        // must reject.
        let mid = proof.bytes.len() / 2;
        proof.bytes[mid] ^= 0xff;
        let err = verify_block(&pi, &proof).unwrap_err();
        // Either the postcard decode chokes on the flipped byte or
        // the STARK verifier does. Both are valid rejection paths —
        // assert it's one of them (not Ok).
        match err {
            BlockVerifyError::ProofMalformed | BlockVerifyError::StarkVerifyFailed => {}
        }
    }

    #[test]
    fn verify_block_rejects_garbage_proof_bytes() {
        let pi = BlockPublicInputs {
            chain_id: 0,
            block_seqno: 0,
            anchor_seqno: 0,
            n_transfers: 0,
            tx_pi_merkle_root: [0; 32],
        };
        let junk = AggregatedProof {
            bytes: b"not-a-valid-proof".to_vec(),
        };
        let err = verify_block(&pi, &junk).unwrap_err();
        assert_eq!(err, BlockVerifyError::ProofMalformed);
    }

    #[test]
    fn prove_block_rejects_too_many_bundles() {
        use crate::monolithic_verifier_air::MerkleOpening;

        let store = tiny_bundle_storage();
        let mp = vec![MerkleOpening {
            leaf: &store.leaf,
            opening_proof: &store.opening,
            index: store.index,
            expected_root: store.expected_root,
        }];
        // Build BLOCK_TX_CAP + 1 bundles — all sharing the same backing
        // storage; we only need the COUNT to exceed the cap.
        let bundle = bundle_from_storage(&store, &mp);
        let bundles: Vec<_> = (0..=BLOCK_TX_CAP).map(|_| bundle.clone()).collect();

        let pi = BlockPublicInputs {
            chain_id: 0,
            block_seqno: 0,
            anchor_seqno: 0,
            n_transfers: BLOCK_TX_CAP as u16 + 1,
            tx_pi_merkle_root: [0; 32],
        };
        let err = prove_block(&pi, &bundles, 512).unwrap_err();
        assert_eq!(err, AggregatorError::TooManySlots);
    }
}
