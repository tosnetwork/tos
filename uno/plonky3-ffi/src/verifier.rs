//! Verifier entry point for the Uno Transfer AIR — consensus-critical path.
//!
//! This function is called from the validator's compute phase (via the
//! C++ `Plonky3Verifier::verify` wrapper). Every validator in the
//! catchain runs this function with byte-identical inputs and must agree
//! bit-identically on accept/reject.
//!
//! # Shape dispatch (P.2 scale-to-envelope)
//!
//! The Uno Transfer envelope allows 1..4 spends × 1..4 outputs (§4.1 /
//! ConfigParam 84). The AIR column-count and public-input length both
//! scale with the shape. Instead of embedding the shape in the proof
//! bytes (which would be either a consensus side-channel or wasted bytes
//! on the hot path), we derive it from the **public-input byte length**:
//!
//! ```text
//! pi_len = 64 + 64·n_spends + 72·n_outputs
//! ```
//!
//! The 16 legal shapes produce 16 distinct `pi_len` values (proven in
//! `transfer_air::derive_shape_from_public_inputs_len`). The verifier:
//!
//! 1. Decodes `pi_len` into `(n_spends, n_outputs)` — rejects with
//!    `PublicInputLengthMismatch` if no legal shape matches.
//! 2. Decodes the bytes into `Vec<Goldilocks>` — rejects with
//!    `PublicInputDecodeFailed` on non-canonical limbs.
//! 3. Instantiates `MvpTransferAir::new(n_spends, n_outputs)`.
//! 4. Calls `p3_uni_stark::verify`.
//!
//! A malicious prover who tries to pass a 4/4-shape proof with a
//! 1/2-shape public-input vector is caught at step 1 (wrong length) or
//! step 4 (wrong `num_public_values` / wrong trace width). Either way:
//! `VerifyFailed`.
//!
//! # Determinism constraints (design doc §4.3 + §7.4)
//!
//! - No wall clock, OS entropy, HashMap iteration, floating point, or
//!   thread-local mutation. Plonky3's `verify` is pure over its inputs;
//!   we add one layer (byte-level decode + shape dispatch) that is
//!   equally pure.

use p3_batch_stark::{verify_batch, BatchProof, CommonData};
use p3_uni_stark::{verify, Proof};

use crate::prover::{build_config, MvpConfig};
use crate::transfer_air::{
    decode_public_inputs, derive_shape_from_public_inputs_len, MvpTransferAir,
};
use crate::Plonky3Status;

/// Verifier handle holding the config.
///
/// The AIR is instantiated per-verify-call from the dispatched shape, so
/// a single handle serves all 16 envelope shapes.
pub struct MvpVerifier {
    config: MvpConfig,
}

impl Default for MvpVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl MvpVerifier {
    /// Build a verifier with the canonical config. The config matches the
    /// prover's byte-for-byte (same Poseidon2 round constants, same FRI).
    pub fn new() -> Self {
        Self {
            config: build_config(),
        }
    }

    /// Verify a serialized proof against its public-input vector.
    ///
    /// Shape-aware: decodes `(n_spends, n_outputs)` from the PI byte
    /// length and dispatches to the matching AIR instance.
    pub fn verify(&self, proof_bytes: &[u8], public_inputs_bytes: &[u8]) -> Plonky3Status {
        // Step 1: shape from PI length.
        let (n_s, n_o) = match derive_shape_from_public_inputs_len(public_inputs_bytes.len()) {
            Ok(shape) => shape,
            Err(e) => return e,
        };

        // Step 2: decode PI bytes into Goldilocks elements.
        let public_inputs = match decode_public_inputs(public_inputs_bytes) {
            Ok(v) => v,
            Err(e) => return e,
        };

        // Step 3: deserialize proof.
        let proof: Proof<MvpConfig> = match postcard::from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(_) => return Plonky3Status::ProofDecodeFailed,
        };

        // Step 4: instantiate AIR for the dispatched shape and run verify.
        let air = MvpTransferAir::new(n_s, n_o);
        match verify(&self.config, &air, &proof, &public_inputs) {
            Ok(()) => Plonky3Status::Ok,
            Err(_) => Plonky3Status::VerifyFailed,
        }
    }
}

/// Batch-STARK verifier for the Path (iii) single-instance feasibility path.
///
/// This intentionally runs beside [`MvpVerifier`] until the shipped opaque
/// proof format is switched from `p3_uni_stark::Proof` to
/// `p3_batch_stark::BatchProof`. AIR shape dispatch and public-input decoding
/// are identical to the shipped verifier.
pub struct MvpBatchVerifier {
    config: MvpConfig,
}

impl Default for MvpBatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl MvpBatchVerifier {
    /// Build a verifier with the canonical Option B config.
    pub fn new() -> Self {
        Self {
            config: build_config(),
        }
    }

    /// Verify a postcard-encoded `BatchProof<MvpConfig>` against PI bytes.
    pub fn verify(&self, proof_bytes: &[u8], public_inputs_bytes: &[u8]) -> Plonky3Status {
        let (n_s, n_o) = match derive_shape_from_public_inputs_len(public_inputs_bytes.len()) {
            Ok(shape) => shape,
            Err(e) => return e,
        };

        let public_inputs = match decode_public_inputs(public_inputs_bytes) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let proof: BatchProof<MvpConfig> = match postcard::from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(_) => return Plonky3Status::ProofDecodeFailed,
        };

        let air = MvpTransferAir::new(n_s, n_o);
        let common = CommonData::empty(1);
        match verify_batch(&self.config, &[air], &proof, &[public_inputs], &common) {
            Ok(()) => Plonky3Status::Ok,
            Err(_) => Plonky3Status::VerifyFailed,
        }
    }

    /// Verify a postcard-encoded `BatchProof<MvpConfig>` that was
    /// produced by `MvpBatchProver::prove_with_range_check`.
    ///
    /// The two-AIR cross-global `Kind::Global("u16_range")` LogUp
    /// requires the verifier to reconstruct the same `common_data`
    /// (preprocessed commitment + lookup declarations) the prover
    /// used. `ProverData::from_airs_and_degrees` is deterministic
    /// given identical inputs, so re-running it on the verifier side
    /// yields the identical commitment — the prover and verifier
    /// never transmit it on the wire.
    ///
    /// Returns `Plonky3Status::Ok` iff both (a) the Transfer AIR
    /// constraints hold AND (b) the cross-AIR cumulative LogUp sum
    /// is zero (i.e. every u16 limb read by MvpTransferAir is
    /// accounted for by the Range16Air multiplicity column).
    pub fn verify_with_range_check(
        &self,
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Plonky3Status {
        use crate::prover::MvpAirUnion;
        use crate::range16_air::{Range16Air, LOG_RANGE_TABLE_HEIGHT};
        use crate::transfer_air::LOG_TRACE_HEIGHT;
        use p3_batch_stark::ProverData;

        let (n_s, n_o) = match derive_shape_from_public_inputs_len(public_inputs_bytes.len()) {
            Ok(shape) => shape,
            Err(e) => return e,
        };

        let public_inputs = match decode_public_inputs(public_inputs_bytes) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let proof: BatchProof<MvpConfig> = match postcard::from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(_) => return Plonky3Status::ProofDecodeFailed,
        };

        // Reconstruct the two-AIR heterogeneous-height batch + common_data
        // exactly as the prover built it. `from_airs_and_degrees` is
        // deterministic, so this is byte-identical to the prover side.
        let mut airs = [
            MvpAirUnion::Transfer(MvpTransferAir::new(n_s, n_o)),
            MvpAirUnion::Range16(Range16Air::new()),
        ];
        let zk = p3_uni_stark::StarkGenericConfig::is_zk(&self.config);
        let log_ext_degrees = [LOG_TRACE_HEIGHT + zk, LOG_RANGE_TABLE_HEIGHT + zk];
        let prover_data: ProverData<MvpConfig> =
            ProverData::from_airs_and_degrees(&self.config, &mut airs, &log_ext_degrees);
        let common = &prover_data.common;

        let pvs = [public_inputs, Vec::new()];
        match verify_batch(&self.config, &airs, &proof, &pvs, common) {
            Ok(()) => Plonky3Status::Ok,
            Err(_) => Plonky3Status::VerifyFailed,
        }
    }
}

// Static Send+Sync check so `Arc<MvpVerifier>` in the FFI handle is sound
// for parallel verify across `num_cores` threads (§13 P.3).
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MvpVerifier>();
    assert_send_sync::<MvpBatchVerifier>();
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{MvpBatchProver, MvpProver};
    use crate::transfer_air::MvpWitness;

    fn valid_proof(n_s: usize, n_o: usize, seed: u64) -> (Vec<u8>, Vec<u8>) {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(n_s, n_o, seed);
        prover.prove(&w.encode()).expect("prove succeeds")
    }

    #[test]
    fn verify_valid_1_1() {
        let (proof, pis) = valid_proof(1, 1, 0x1111_0001);
        assert_eq!(MvpVerifier::new().verify(&proof, &pis), Plonky3Status::Ok);
    }

    fn valid_batch_proof(n_s: usize, n_o: usize, seed: u64) -> (Vec<u8>, Vec<u8>) {
        let prover = MvpBatchProver::new();
        let w = MvpWitness::deterministic_valid(n_s, n_o, seed);
        prover.prove(&w.encode()).expect("batch prove succeeds")
    }

    #[test]
    fn batch_verify_valid_1_2() {
        let (proof, pis) = valid_batch_proof(1, 2, 0xBADD_1200);
        assert_eq!(
            MvpBatchVerifier::new().verify(&proof, &pis),
            Plonky3Status::Ok
        );
    }

    #[test]
    fn batch_verify_rejects_tampered_public_inputs() {
        let (proof, mut pis) = valid_batch_proof(1, 2, 0xBADD_1201);
        pis[8] ^= 0x01; // tamper chain_id limb.
        assert_eq!(
            MvpBatchVerifier::new().verify(&proof, &pis),
            Plonky3Status::VerifyFailed
        );
    }

    #[test]
    fn verify_valid_1_2() {
        let (proof, pis) = valid_proof(1, 2, 0x1212_0001);
        assert_eq!(MvpVerifier::new().verify(&proof, &pis), Plonky3Status::Ok);
    }

    #[test]
    fn verify_valid_2_2() {
        let (proof, pis) = valid_proof(2, 2, 0x2222_0002);
        assert_eq!(MvpVerifier::new().verify(&proof, &pis), Plonky3Status::Ok);
    }

    #[test]
    fn verify_valid_4_4_worst_case() {
        let (proof, pis) = valid_proof(4, 4, 0x4444_0004);
        assert_eq!(MvpVerifier::new().verify(&proof, &pis), Plonky3Status::Ok);
    }

    /// PI-byte-length truncation to a non-legal byte count (i.e. not a
    /// multiple of 8, or not matching any of the 16 legal shapes) is
    /// rejected with `PublicInputLengthMismatch`. NOTE: truncating by
    /// one FE from a legal length can still land on another legal shape
    /// (e.g. 272 B = (1,2), 264 B = (2,1)). In that case the verifier
    /// reaches step 4 and returns `VerifyFailed` from the AIR-width
    /// mismatch. Either way the proof is rejected.
    #[test]
    fn verify_rejects_short_public_inputs() {
        let (proof, mut pis) = valid_proof(1, 2, 0x99);
        pis.truncate(pis.len() - 1); // drop one byte → non-multiple-of-8.
        let rc = MvpVerifier::new().verify(&proof, &pis);
        assert_eq!(rc, Plonky3Status::PublicInputLengthMismatch);
    }

    /// PI-byte length that's a multiple of 8 but doesn't match any of
    /// the 16 legal (n_s, n_o) shapes must also be rejected with
    /// `PublicInputLengthMismatch`.
    #[test]
    fn verify_rejects_bogus_shape_length() {
        let (proof, _) = valid_proof(1, 1, 0xDD);
        // 40 bytes = 5 FE; no legal shape has 5 FE.
        let bogus_pis = vec![0u8; 40];
        let rc = MvpVerifier::new().verify(&proof, &bogus_pis);
        assert_eq!(rc, Plonky3Status::PublicInputLengthMismatch);
    }

    /// Flipping a byte in the public-input vector is rejected at verify.
    #[test]
    fn verify_rejects_tampered_public_inputs() {
        let (proof, mut pis) = valid_proof(1, 1, 0x77);
        pis[8] ^= 0x01; // tamper chain_id limb.
        let rc = MvpVerifier::new().verify(&proof, &pis);
        assert_eq!(rc, Plonky3Status::VerifyFailed);
    }

    /// A malformed proof buffer is rejected at decode.
    #[test]
    fn verify_rejects_malformed_proof() {
        let (_, pis) = valid_proof(1, 1, 0x66);
        let bad = vec![0xffu8; 10];
        let rc = MvpVerifier::new().verify(&bad, &pis);
        assert_eq!(rc, Plonky3Status::ProofDecodeFailed);
    }

    /// Cross-shape attack: present a 1/1 proof but with a 4/4 PI byte
    /// length. Shape derivation succeeds (pi_len=608 is legal for 4/4),
    /// but the 4/4 AIR width doesn't match the 1/1-shaped proof → reject.
    #[test]
    fn verify_rejects_shape_confusion_attack() {
        let (proof_1_1, _) = valid_proof(1, 1, 0xAB);
        let (_, pis_4_4) = valid_proof(4, 4, 0xCD);
        let rc = MvpVerifier::new().verify(&proof_1_1, &pis_4_4);
        assert_ne!(
            rc,
            Plonky3Status::Ok,
            "verifier MUST reject a proof-vs-PI shape mismatch"
        );
    }

    /// Adversarial: the prover tampers with a private witness field while
    /// keeping the honest PI. Cross-check against honest PI must reject.
    #[test]
    fn verify_rejects_adversarial_ivk_mutation() {
        let prover = MvpProver::new();
        let honest = MvpWitness::deterministic_valid(2, 2, 0xFEED_0001);
        let honest_pi_bytes = honest.public_inputs_bytes();

        let mut bad = honest.clone();
        // Phase 4b-step3-step0: widened ivk to [u8; 32]; poke the low
        // byte to trip the same u64-proxy value the AIR derives via
        // first_u64_proxy(&ivk).
        bad.spends[0].ivk[0] = bad.spends[0].ivk[0].wrapping_add(1);

        match prover.prove(&bad.encode()) {
            Err(_) => {} // pre-check caught it
            Ok((proof_bytes, _bad_pi_bytes)) => {
                let verifier = MvpVerifier::new();
                assert_ne!(
                    verifier.verify(&proof_bytes, &honest_pi_bytes),
                    Plonky3Status::Ok,
                    "verifier MUST NOT accept a tampered-ivk proof against honest PI"
                );
            }
        }
    }

    /// Adversarial: tamper `pos` — should change the derived nullifier PI.
    #[test]
    fn verify_rejects_adversarial_pos_mutation() {
        let prover = MvpProver::new();
        let honest = MvpWitness::deterministic_valid(4, 4, 0xCAFE_0044);
        let honest_pi_bytes = honest.public_inputs_bytes();

        let mut bad = honest.clone();
        bad.spends[2].pos = bad.spends[2].pos.wrapping_add(0x100);

        match prover.prove(&bad.encode()) {
            Err(_) => {}
            Ok((proof_bytes, _bad_pi_bytes)) => {
                let verifier = MvpVerifier::new();
                assert_ne!(
                    verifier.verify(&proof_bytes, &honest_pi_bytes),
                    Plonky3Status::Ok,
                    "verifier MUST NOT accept a tampered-pos proof against honest PI"
                );
            }
        }
    }

    /// Adversarial: tamper the anchor bytes (i.e. lie about which tree
    /// root the spend was proven against). Cross-verify against honest
    /// PI must reject.
    ///
    /// Phase 4b-step3-step3a: pre-step-3a this test mutated
    /// `anchor_proxy` (the legacy single-u64 AIR-bound anchor). Post
    /// step-3a the AIR no longer reads `anchor_proxy` — all 4 anchor
    /// PI limbs derive from `witness.anchor_bytes` via the Merkle-walk
    /// 4-fe digest. Flipping a byte of `anchor_bytes[0..8]` changes
    /// `PI[PI_ANCHOR + 0]` and thus decouples the bad witness's PI
    /// from the honest PI — cross-verify MUST reject.
    #[test]
    fn verify_rejects_adversarial_wrong_anchor() {
        let prover = MvpProver::new();
        let honest = MvpWitness::deterministic_valid(1, 1, 0xBAAD_F00D);
        let honest_pi_bytes = honest.public_inputs_bytes();

        let mut bad = honest.clone();
        // Flip a bit inside `anchor_bytes[0..8]` so PI limb 0 differs
        // while the Merkle walk on the honest path still produces the
        // honest anchor (prover_side_check won't catch this; the AIR
        // verify must).
        bad.anchor_bytes[0] ^= 0x01;

        match prover.prove(&bad.encode()) {
            Err(_) => {}
            Ok((proof_bytes, bad_pi_bytes)) => {
                let verifier = MvpVerifier::new();
                assert_ne!(bad_pi_bytes, honest_pi_bytes);
                assert_ne!(
                    verifier.verify(&proof_bytes, &honest_pi_bytes),
                    Plonky3Status::Ok,
                    "verifier MUST NOT accept a wrong-anchor proof against honest PI"
                );
            }
        }
    }

    /// Balance inflation adversary. The pre-check MUST catch.
    #[test]
    fn prover_rejects_inflation_adversary_4_4() {
        let prover = MvpProver::new();
        let mut w = MvpWitness::deterministic_valid(4, 4, 0xBEEF_0000);
        w.outputs[0].value = w.outputs[0].value.saturating_add(1_000);
        assert_eq!(
            prover.prove(&w.encode()).unwrap_err(),
            Plonky3Status::WitnessInvalid
        );
    }
}
