//! Verifier entry point for the Uno MVP AIR — consensus-critical path.
//!
//! This function is called from the validator's compute phase (via the
//! C++ `Plonky3Verifier::verify` wrapper in `uno/crypto/plonky3-verifier.cpp`).
//! Every validator in the catchain runs this function with byte-identical
//! inputs and must agree bit-identically on accept/reject.
//!
//! # Determinism constraints (design doc §4.3 + §7.4)
//!
//! - No wall clock.
//! - No OS entropy.
//! - No HashMap iteration.
//! - No floating point.
//! - No thread-local mutation (pool allocators, TLS counters, etc.).
//!
//! We inherit Plonky3's own determinism story here — `p3_uni_stark::verify`
//! is pure over its inputs. We add one layer: the byte-level decode of
//! proof + public inputs. The decoder is linear-scan, rejects non-
//! canonical encodings (see `transfer_air::decode_public_inputs`), and
//! does not allocate beyond `O(len)`.

use p3_uni_stark::{Proof, verify};

use crate::prover::{MvpConfig, build_config};
use crate::transfer_air::{decode_public_inputs, MvpTransferAir};
use crate::Plonky3Status;

/// Verifier handle holding the config and AIR reference.
pub struct MvpVerifier {
    config: MvpConfig,
    air: MvpTransferAir,
}

impl Default for MvpVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl MvpVerifier {
    /// Build a verifier with the canonical MVP config. The config must
    /// match the prover's byte-for-byte (same Poseidon2 round constants,
    /// same FRI parameters) — we enforce this by reusing `build_config`.
    pub fn new() -> Self {
        Self {
            config: build_config(),
            air: MvpTransferAir,
        }
    }

    /// Verify a serialized proof against a serialized public-input vector.
    ///
    /// Returns [`Plonky3Status::Ok`] iff the proof is valid, otherwise a
    /// specific error code (see the [`Plonky3Status`] docs).
    pub fn verify(&self, proof_bytes: &[u8], public_inputs_bytes: &[u8]) -> Plonky3Status {
        // Step 1: decode public inputs first (cheap; catches
        // canonical-form violations).
        let public_inputs = match decode_public_inputs(public_inputs_bytes) {
            Ok(v) => v,
            Err(e) => return e,
        };

        // Step 2: deserialize proof (may fail on truncated/malformed bytes).
        let proof: Proof<MvpConfig> = match postcard::from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(_) => return Plonky3Status::ProofDecodeFailed,
        };

        // Step 3: run Plonky3 STARK verify. Any verification error is
        // mapped to `VerifyFailed`; specific error kinds are not exposed
        // to C++ to keep the ABI stable across upstream Plonky3 refactors.
        match verify(&self.config, &self.air, &proof, &public_inputs) {
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
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::MvpProver;
    use crate::transfer_air::MvpWitness;

    fn valid_proof() -> (Vec<u8>, Vec<u8>) {
        let prover = MvpProver::new();
        let witness = MvpWitness::deterministic_valid(0x11_22_33_44_55_66_77_88);
        prover.prove(&witness.encode()).expect("prove succeeds")
    }

    /// Valid proof must verify.
    #[test]
    fn verify_valid_proof() {
        let (proof, pis) = valid_proof();
        let verifier = MvpVerifier::new();
        assert_eq!(verifier.verify(&proof, &pis), Plonky3Status::Ok);
    }

    /// Public-input truncation is rejected with a structured status.
    #[test]
    fn verify_rejects_short_public_inputs() {
        let (proof, mut pis) = valid_proof();
        pis.truncate(pis.len() - 1);
        let verifier = MvpVerifier::new();
        assert_eq!(
            verifier.verify(&proof, &pis),
            Plonky3Status::PublicInputLengthMismatch
        );
    }

    /// Flipping a byte in the public-input vector is rejected at verify.
    #[test]
    fn verify_rejects_tampered_public_inputs() {
        let (proof, mut pis) = valid_proof();
        // Flip a bit in element 0 (declared parent) but keep the value
        // inside canonical range so `decode_public_inputs` accepts. XOR
        // on a middle byte does that.
        pis[3] ^= 0x01;
        let verifier = MvpVerifier::new();
        assert_eq!(verifier.verify(&proof, &pis), Plonky3Status::VerifyFailed);
    }

    /// A malformed proof buffer is rejected at decode.
    #[test]
    fn verify_rejects_malformed_proof() {
        let (_, pis) = valid_proof();
        let bad = vec![0xffu8; 10];
        let verifier = MvpVerifier::new();
        assert_eq!(
            verifier.verify(&bad, &pis),
            Plonky3Status::ProofDecodeFailed
        );
    }

    /// Adversarial witness (decision #1, §4.2 claim 3 scaffold): the
    /// prover tampers with their private-witness `ivk` but claims the
    /// honest `ivk_commitment` in the public inputs. Because the AIR's
    /// first-row constraint is `ivk_commitment_claim = ivk * MIX +
    /// sibling`, a different `ivk` produces a different
    /// `ivk_commitment_claim`, which then mismatches the public input.
    /// The verifier MUST reject.
    #[test]
    fn verify_rejects_adversarial_ivk_witness() {
        let prover = MvpProver::new();
        let honest = MvpWitness::deterministic_valid(0x5678_5678_5678_5678);
        let honest_pi_bytes = honest.public_inputs_bytes();

        // Tamper with the private `ivk` while keeping the honest PI.
        let mut bad = honest.clone();
        bad.ivk = bad.ivk.wrapping_add(1);

        match prover.prove(&bad.encode()) {
            Err(Plonky3Status::WitnessInvalid) => {
                // Debug-build constraint check pre-filter caught it.
            }
            Err(other) => panic!("unexpected prove error: {:?}", other),
            Ok((proof_bytes, bad_pi_bytes)) => {
                let verifier = MvpVerifier::new();
                // Self-consistent under the adversary's own PI is allowed.
                let _ = verifier.verify(&proof_bytes, &bad_pi_bytes);
                // But same proof against HONEST PI must reject.
                assert_ne!(
                    verifier.verify(&proof_bytes, &honest_pi_bytes),
                    Plonky3Status::Ok,
                    "verifier MUST reject when prover's `ivk` does not satisfy \
                     the public ivk_commitment binding"
                );
            }
        }
    }

    /// Adversarial witness: flip the sibling, keep the public input "parent"
    /// as before (unchanged from the valid case). The AIR's first-row
    /// Merkle-step constraint says `parent_claim = leaf * MIX + sibling`,
    /// and the first-row binding says `parent_claim = public_input[0]`.
    /// So if sibling is perturbed the prover's trace will have
    /// `parent_claim_trace != public_input[0]`, and the verifier rejects.
    #[test]
    fn verify_rejects_adversarial_sibling_witness() {
        let prover = MvpProver::new();
        let witness = MvpWitness::deterministic_valid(0xf00d_d00d_cafe_babe);

        // Derive the "honest" public inputs.
        let honest_pi_bytes = witness.public_inputs_bytes();

        // Now mutate the sibling to produce an inconsistent trace.
        let mut bad_witness = witness.clone();
        bad_witness.merkle_sibling[0] ^= 0xff;

        // In debug builds the debug-constraint-builder inside `prove`
        // panics; our wrapper catches it and returns WitnessInvalid.
        // In release builds the prover succeeds but the verifier fails.
        let result = prover.prove(&bad_witness.encode());

        match result {
            Err(Plonky3Status::WitnessInvalid) => {
                // Outcome A (debug build, constraint-check pre-filter).
                // Acceptable — the negative was caught early.
            }
            Err(other) => {
                panic!("unexpected prove error: {:?}", other);
            }
            Ok((proof_bytes, bad_pi_bytes)) => {
                // Outcome B (release build path): prover produced a proof.
                // The proof may verify under the bad_witness's OWN public
                // inputs (self-consistency) — that's fine; the interesting
                // check is whether it verifies against the HONEST public
                // inputs (the adversary's claim of what was proved).
                let verifier = MvpVerifier::new();

                // (1) Self-consistent: proof matches the tampered PI.
                // Plonky3 MUST accept this — the prover produced a valid
                // proof for that witness. Our job is to show it FAILS
                // against the CLAIM the adversary wants to make.
                let _self_consistent = verifier.verify(&proof_bytes, &bad_pi_bytes);

                // (2) Adversarial claim: same proof, but public inputs
                // asserting the original `parent` digest. MUST REJECT.
                assert_ne!(
                    verifier.verify(&proof_bytes, &honest_pi_bytes),
                    Plonky3Status::Ok,
                    "verifier MUST NOT accept a proof that contradicts its declared parent"
                );
            }
        }
    }
}
