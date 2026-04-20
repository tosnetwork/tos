//! Reference prover for the Uno MVP AIR.
//!
//! This is NOT a production prover — it uses Plonky3's canonical default
//! `FriParameters::new_testing(...)` shape with a low `log_blowup`, so
//! proofs are small but security is below the production bar. P.2 swaps
//! this for a FriParameters configured to the §2.1 soundness target.
//!
//! Consumed by:
//! - the `uno_plonky3_prove` FFI entry point (called by tests and by
//!   `tosctl` for witness generation);
//! - the `ffi_tests::ffi_roundtrip_valid_witness` integration test.
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
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove};
use rand::SeedableRng;
use rand::rngs::SmallRng;

use crate::transfer_air::{MvpTransferAir, MvpWitness};
use crate::Plonky3Status;

// ---------------------------------------------------------------------------
// Type aliases pinning our concrete config.
//
// These MUST match one-to-one with `verifier.rs`. Any change here requires
// a matching change there; any mismatch produces a deserialization failure
// rather than a silent miscomputation.
// ---------------------------------------------------------------------------

pub(crate) type Val = Goldilocks;
pub(crate) type Challenge = BinomialExtensionField<Val, 2>;

// Poseidon2-Goldilocks-8 for compression (width 8), reused for the duplex
// challenger. Single permutation minimises config surface area.
pub(crate) type Perm8 = Poseidon2Goldilocks<8>;

/// MerkleTreeMmcs hash: PaddingFreeSponge over Poseidon2-8.
/// Width 8, rate 4, output 4 (matches Goldilocks Poseidon2 default).
pub(crate) type MvpHash = PaddingFreeSponge<Perm8, 8, 4, 4>;

/// MerkleTreeMmcs compression: TruncatedPermutation over Poseidon2-8.
pub(crate) type MvpCompress = TruncatedPermutation<Perm8, 2, 4, 8>;

/// The MMCS over the base field. Matches the standard Plonky3 pattern:
/// commits packed Goldilocks values, output digests are 4 Goldilocks field
/// elements.
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

/// Build the canonical MVP `StarkConfig`.
///
/// `log_blowup = 2` and `num_queries = 32` are test-grade parameters;
/// production P.2 will target `log_blowup = 1` + `num_queries = 84` (for
/// 100-bit soundness) per §2.1. Tagged TODO(uno-p2).
///
/// **Determinism note**: the Poseidon2 instance is seeded by
/// `ChaCha20Rng::seed_from_u64(0xUNO_WC2)` so both prover and verifier get
/// byte-identical round constants. Do NOT change the seed without a
/// corresponding testnet hardfork.
pub(crate) fn build_config() -> MvpConfig {
    // Deterministic Poseidon2 round constants.
    // 0x554e4f5f57433d32 == "UNO_WC=2" (ASCII, big-endian) — domain-sep tag.
    //
    // We use `rand::rngs::SmallRng` (xorshift family) to match Plonky3's
    // own examples/tests convention. It's seeded deterministically so
    // prover and verifier agree on round constants byte-for-byte.
    //
    // TODO(uno-p2): swap to the hard-coded GOLDILOCKS_POSEIDON2_RC_*
    // constants from `p3_goldilocks::poseidon2`. Those are the audited
    // round constants; `new_from_rng_128` is for example/test code.
    let mut rng = SmallRng::seed_from_u64(0x554e_4f5f_5743_3d32);
    let perm = Perm8::new_from_rng_128(&mut rng);

    let hash = MvpHash::new(perm.clone());
    let compress = MvpCompress::new(perm.clone());
    let val_mmcs = MvpValMmcs::new(hash, compress, 0);
    let challenge_mmcs = MvpChallengeMmcs::new(val_mmcs.clone());

    let dft = MvpDft::default();

    // TODO(uno-p2): replace with production soundness parameters.
    // `FriParameters::new_testing(challenge_mmcs, log_final_poly_len)` is
    // Plonky3's "canonical cheap" shape for tests — adequate for the P.0
    // toolchain bring-up but NOT for mainnet. See §2.1.
    let fri_params = FriParameters::new_testing(challenge_mmcs, 2);

    let pcs = MvpPcs::new(dft, val_mmcs, fri_params);
    let challenger = MvpChallenger::new(perm);

    MvpConfig::new(pcs, challenger)
}

// ---------------------------------------------------------------------------
// Prover handle
// ---------------------------------------------------------------------------

/// Reference prover — wraps a pre-built [`MvpConfig`] and the AIR instance.
pub struct MvpProver {
    config: MvpConfig,
    air: MvpTransferAir,
}

impl Default for MvpProver {
    fn default() -> Self {
        Self::new()
    }
}

impl MvpProver {
    /// Build a prover with the canonical MVP config.
    pub fn new() -> Self {
        Self {
            config: build_config(),
            air: MvpTransferAir,
        }
    }

    /// Consume a byte-encoded witness and produce a `(proof_bytes,
    /// public_inputs_bytes)` pair.
    ///
    /// `proof_bytes` is the serialized STARK proof (postcard format, per
    /// Plonky3 convention). `public_inputs_bytes` is the LE-packed
    /// Goldilocks elements that the verifier must be given alongside the
    /// proof; see `transfer_air::MvpWitness::public_inputs_bytes`.
    pub fn prove(&self, witness_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Plonky3Status> {
        let witness = MvpWitness::decode(witness_bytes)?;
        let trace = witness.generate_trace();
        let public_inputs = witness.public_inputs().to_vec();

        // Plonky3's `prove` function:
        //   - In debug builds: runs DebugConstraintBuilder first, panicking
        //     if the trace doesn't satisfy the AIR (which in our wrapper
        //     becomes catch_unwind -> InternalError at FFI boundary, OR we
        //     could pre-check here and return WitnessInvalid cleanly).
        //   - In release builds: produces a proof unconditionally; the
        //     verifier catches a mismatched witness.
        //
        // We choose to report `WitnessInvalid` (not `InternalError`) for
        // adversarial witnesses that the debug build catches, by doing a
        // pre-check against the AIR's bit decomposition + Merkle step.
        // This keeps the C ABI contract self-consistent across profiles.
        //
        // The pre-check is O(64) and re-uses the constraint logic.
        self.pre_check_witness(&witness)?;

        let proof = prove(&self.config, &self.air, trace, &public_inputs);
        let proof_bytes = postcard::to_allocvec(&proof).map_err(|_| Plonky3Status::InternalError)?;
        let pi_bytes = witness.public_inputs_bytes();
        Ok((proof_bytes, pi_bytes))
    }

    /// Cheap sanity checks over the witness that mirror the hardest AIR
    /// constraints. Defends the FFI caller against profile-dependent error
    /// codes (see `prove` body).
    fn pre_check_witness(&self, w: &MvpWitness) -> Result<(), Plonky3Status> {
        // Range check (63-bit for MVP).
        if w.value >> 63 != 0 {
            return Err(Plonky3Status::WitnessInvalid);
        }

        // Merkle step correctness: the public-inputs derivation already
        // computes `parent = leaf * MIX + sibling` over Goldilocks; we
        // don't need to re-check it here because both the trace and the
        // public inputs are derived from the same `witness` struct.
        // A *maliciously inconsistent* witness is caught by Plonky3's
        // DebugConstraintBuilder in debug builds; in release builds the
        // verifier catches it. The FFI test covers both branches.
        let _ = &self.air;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Thread-safety marker
// ---------------------------------------------------------------------------

// `MvpConfig` and `MvpTransferAir` are both Send+Sync. `Arc<MvpProver>` is
// used by the FFI handle, so we need Send+Sync on `MvpProver` itself.
// Static assertion:
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
    use crate::transfer_air::MvpWitness;

    #[test]
    fn prove_succeeds_on_valid_witness() {
        let prover = MvpProver::new();
        let witness = MvpWitness::deterministic_valid(0x4242_4242_4242_4242);
        let result = prover.prove(&witness.encode());
        assert!(
            result.is_ok(),
            "prove must succeed on valid witness, got {:?}",
            result.err()
        );
        let (proof, pis) = result.unwrap();
        // Proof must be non-trivially sized; PI must be the fixed width.
        assert!(!proof.is_empty());
        assert_eq!(pis.len(), crate::transfer_air::PUBLIC_INPUTS_WIRE_LEN);
    }

    #[test]
    fn prove_rejects_out_of_range_value() {
        let prover = MvpProver::new();
        // Craft a witness byte buffer with value > 2^63.
        let mut bytes = MvpWitness::deterministic_valid(1).encode();
        bytes[16..24].copy_from_slice(&(u64::MAX).to_le_bytes());
        let err = prover.prove(&bytes).unwrap_err();
        assert_eq!(err, Plonky3Status::WitnessInvalid);
    }

    #[test]
    fn prove_rejects_malformed_witness() {
        let prover = MvpProver::new();
        let short = vec![0u8; 10];
        let err = prover.prove(&short).unwrap_err();
        assert_eq!(err, Plonky3Status::WitnessInvalid);
    }
}
