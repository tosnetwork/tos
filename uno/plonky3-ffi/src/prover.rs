//! Reference prover for the Uno Transfer AIR (P.2 scale-to-envelope).
//!
//! This is NOT a production prover — it uses Plonky3's canonical default
//! `FriParameters::new_testing(...)` shape with a low `log_blowup`, so
//! proofs are small but security is below the production bar. P.2 swaps
//! this for a FriParameters configured to the §2.1 soundness target.
//!
//! Consumed by:
//! - the `uno_plonky3_prove` FFI entry point;
//! - Rust-side integration tests.
//!
//! NOT consumed by:
//! - the validator compute phase (which only ever calls the verifier);
//! - any consensus-critical path.

use std::sync::Arc;

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_8};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove};

use crate::transfer_air::{MvpTransferAir, MvpWitness};
use crate::Plonky3Status;

// ---------------------------------------------------------------------------
// Type aliases pinning our concrete config.
// ---------------------------------------------------------------------------

pub(crate) type Val = Goldilocks;
pub(crate) type Challenge = BinomialExtensionField<Val, 2>;

pub(crate) type Perm8 = Poseidon2Goldilocks<8>;

pub(crate) type MvpHash = PaddingFreeSponge<Perm8, 8, 4, 4>;
pub(crate) type MvpCompress = TruncatedPermutation<Perm8, 2, 4, 8>;

pub(crate) type MvpValMmcs = MerkleTreeMmcs<
    <Val as p3_field::Field>::Packing,
    <Val as p3_field::Field>::Packing,
    MvpHash,
    MvpCompress,
    2,
    4,
>;

pub(crate) type MvpChallengeMmcs = ExtensionMmcs<Val, Challenge, MvpValMmcs>;
pub(crate) type MvpChallenger = DuplexChallenger<Val, Perm8, 8, 4>;
pub(crate) type MvpDft = Radix2DitParallel<Val>;
pub(crate) type MvpPcs = TwoAdicFriPcs<Val, MvpDft, MvpValMmcs, MvpChallengeMmcs>;
pub(crate) type MvpConfig = StarkConfig<MvpPcs, Challenge, MvpChallenger>;

// ---------------------------------------------------------------------------
// Config builder
// ---------------------------------------------------------------------------

/// Build the canonical Transfer `StarkConfig`.
///
/// `log_blowup = 2` + `FriParameters::new_testing(...)` are test-grade
/// parameters; production P.2 will target `log_blowup = 1` + soundness-
/// target `num_queries` per §2.1. Tagged `TODO(uno-p2-soundness)`.
pub(crate) fn build_config() -> MvpConfig {
    let perm: Perm8 = default_goldilocks_poseidon2_8();
    let hash = MvpHash::new(perm.clone());
    let compress = MvpCompress::new(perm.clone());
    let val_mmcs = MvpValMmcs::new(hash, compress, 0);
    let challenge_mmcs = MvpChallengeMmcs::new(val_mmcs.clone());
    let dft = MvpDft::default();
    // TODO(uno-p2-soundness): switch to production FRI parameters.
    let fri_params = FriParameters::new_testing(challenge_mmcs, 2);
    let pcs = MvpPcs::new(dft, val_mmcs, fri_params);
    let challenger = MvpChallenger::new(perm);
    MvpConfig::new(pcs, challenger)
}

// ---------------------------------------------------------------------------
// Prover handle
// ---------------------------------------------------------------------------

/// Reference prover. The AIR shape is selected per-prove-call from the
/// decoded witness, so a single prover handle serves all 16 legal shapes.
pub struct MvpProver {
    config: MvpConfig,
}

impl Default for MvpProver {
    fn default() -> Self {
        Self::new()
    }
}

impl MvpProver {
    /// Build a prover with the canonical config.
    pub fn new() -> Self {
        Self {
            config: build_config(),
        }
    }

    /// Prove a witness. Returns `(proof_bytes, public_inputs_bytes)`.
    pub fn prove(&self, witness_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Plonky3Status> {
        let witness = MvpWitness::decode(witness_bytes)?;
        self.pre_check_witness(&witness)?;

        let (n_s, n_o) = witness.shape();
        let air = MvpTransferAir::new(n_s, n_o);
        let trace = witness.generate_trace();
        let public_inputs = witness.public_inputs();

        let proof = prove(&self.config, &air, trace, &public_inputs);
        let proof_bytes =
            postcard::to_allocvec(&proof).map_err(|_| Plonky3Status::InternalError)?;
        let pi_bytes = witness.public_inputs_bytes();
        Ok((proof_bytes, pi_bytes))
    }

    /// Cheap sanity checks mirroring the hardest AIR constraints. Short-
    /// circuits adversarial witnesses with `WitnessInvalid` before Plonky3
    /// sees them, keeping the FFI error code stable across debug/release
    /// profiles and preventing debug-build `DebugConstraintBuilder` panics
    /// on malformed witnesses.
    ///
    /// The witness is inconsistent iff any of the following is true:
    ///   (a) `fee` or any proxy is non-canonical mod Goldilocks.
    ///   (b) Claim 8 balance: `Σ spend.value ≠ Σ output.value + fee`.
    ///   (c) Claim 2 leaf derivation: for any spend,
    ///       `leaf_i ≠ Poseidon2("uno-cm-v1", d_i, pk_d_i, ivk_commitment_i,
    ///                            value_i, rcm_i)`.
    ///   (d) Claim 1 anchor consistency: for any spend,
    ///       `Poseidon2(leaf_i, sibling_i) ≠ anchor_proxy`.
    fn pre_check_witness(&self, w: &MvpWitness) -> Result<(), Plonky3Status> {
        use crate::transfer_air::{witness_claim1_anchor_consistent, witness_claim2_leaf_consistent};

        if w.fee >= crate::transfer_air::GOLDILOCKS_P {
            return Err(Plonky3Status::WitnessInvalid);
        }
        if !w.balance_holds() {
            return Err(Plonky3Status::WitnessInvalid);
        }
        if !witness_claim2_leaf_consistent(w) {
            return Err(Plonky3Status::WitnessInvalid);
        }
        if !witness_claim1_anchor_consistent(w) {
            return Err(Plonky3Status::WitnessInvalid);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Thread-safety marker
// ---------------------------------------------------------------------------
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MvpProver>();
    assert_send_sync::<Arc<MvpProver>>();
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer_air::{air_public_inputs_wire_len, MvpWitness};

    #[test]
    fn prove_succeeds_on_valid_1_1() {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(1, 1, 0x4242_4242_4242_4242);
        let (proof, pis) = prover.prove(&w.encode()).expect("prove 1/1");
        assert!(!proof.is_empty());
        assert_eq!(pis.len(), air_public_inputs_wire_len(1, 1));
    }

    #[test]
    fn prove_succeeds_on_valid_1_2() {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(1, 2, 0xAAAA_0001);
        let (proof, pis) = prover.prove(&w.encode()).expect("prove 1/2");
        assert!(!proof.is_empty());
        assert_eq!(pis.len(), air_public_inputs_wire_len(1, 2));
    }

    #[test]
    fn prove_succeeds_on_valid_2_2() {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(2, 2, 0xBBBB_0002);
        let (proof, pis) = prover.prove(&w.encode()).expect("prove 2/2");
        assert!(!proof.is_empty());
        assert_eq!(pis.len(), air_public_inputs_wire_len(2, 2));
    }

    #[test]
    fn prove_succeeds_on_valid_4_4_worst_case() {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(4, 4, 0xCCCC_0004);
        let (proof, pis) = prover.prove(&w.encode()).expect("prove 4/4");
        assert!(!proof.is_empty());
        assert_eq!(pis.len(), air_public_inputs_wire_len(4, 4));
    }

    #[test]
    fn prove_rejects_malformed_witness() {
        let prover = MvpProver::new();
        let short = vec![0u8; 5];
        let err = prover.prove(&short).unwrap_err();
        assert_eq!(err, Plonky3Status::WitnessInvalid);
    }

    /// Inflation attempt: bump an output value so `output_sum > spend_sum + fee`.
    /// Must reject with `WitnessInvalid` (balance pre-check).
    #[test]
    fn prove_rejects_inflation_attempt() {
        let prover = MvpProver::new();
        let mut w = MvpWitness::deterministic_valid(2, 2, 0x1234);
        w.outputs[0].value = w.outputs[0].value.saturating_add(1);
        let err = prover.prove(&w.encode()).unwrap_err();
        assert_eq!(err, Plonky3Status::WitnessInvalid);
    }

    /// Under-claim output: also breaks balance. Must reject.
    #[test]
    fn prove_rejects_under_claim() {
        let prover = MvpProver::new();
        let mut w = MvpWitness::deterministic_valid(2, 2, 0x2345);
        w.outputs[0].value = w.outputs[0].value.saturating_sub(1);
        let err = prover.prove(&w.encode()).unwrap_err();
        assert_eq!(err, Plonky3Status::WitnessInvalid);
    }

    /// Record proof / witness / public-input byte sizes at (4, 4).
    /// Not a consensus-binding assertion — just a visible regression floor.
    #[test]
    fn sizes_at_4_4_worst_case_recorded() {
        use crate::transfer_air::MERKLE_DEPTH;
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(4, 4, 0x1111_2222_3333_4444);
        let witness_wire = w.encode();
        let (proof, pi) = prover.prove(&witness_wire).expect("prove 4/4");
        println!(
            "[sizes 4/4] witness={}B proof={}B public_inputs={}B air_cols={}",
            witness_wire.len(),
            proof.len(),
            pi.len(),
            crate::transfer_air::air_width(4, 4),
        );
        // Per-spend wire: 64 B leading + 8·MERKLE_DEPTH path siblings.
        let per_spend = 64 + 8 * MERKLE_DEPTH;
        assert_eq!(witness_wire.len(), 18 + per_spend * 4 + 40 * 4);
        assert_eq!(pi.len(), 608);
    }
}
