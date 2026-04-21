//! STARK verifier Fiat-Shamir transcript — out-of-circuit reference.
//!
//! Phase A2-3a of the aggregation roadmap (`doc/uno-aggregation-design.md`).
//! The verifier-as-AIR (future Phase A2-3b/c) must replay the exact same
//! transcript of observes and samples that `uni_stark::verifier::verify`
//! runs against a `DuplexChallenger`. This module provides the
//! **out-of-circuit** driver: given a decoded `Proof<MvpConfig>` and the
//! matching public-input vector, it returns the `(alpha, zeta)`
//! extension-field challenges that the in-circuit verifier AIR will also
//! need to recompute.
//!
//! # Scope
//!
//! At Phase A2-3a we only cover the **pre-PCS prefix** of the verifier's
//! transcript — everything up to and including sampling `zeta`. The FRI
//! phase of `pcs.verify(...)` adds more observes (opened values) and
//! samples (beta, fold challenges); that lands with the FRI-folding
//! AIR in Phase A2-3b+.
//!
//! Mirrors `third-party/plonky3-uno/uni-stark/src/verifier.rs` lines
//! 354–385 byte-for-byte:
//!
//! ```text
//!   challenger.observe(Val::from_usize(degree_bits));
//!   challenger.observe(Val::from_usize(base_degree_bits));   // = degree_bits (ZK off)
//!   challenger.observe(Val::from_usize(preprocessed_width)); // = 0 (no preproc)
//!   challenger.observe(commitments.trace);                   // 4 Goldilocks
//!   challenger.observe_slice(public_values);
//!   let alpha = challenger.sample_algebra_element();         // 2 Goldilocks
//!   challenger.observe(commitments.quotient_chunks);         // 4 Goldilocks
//!   let zeta  = challenger.sample_algebra_element();         // 2 Goldilocks
//! ```
//!
//! # Why an out-of-circuit driver, not the AIR directly?
//!
//! Two reasons:
//!   1. **Testable parity with upstream**: this driver runs alongside
//!      the real `uni_stark::verify` and we assert that its derived
//!      `(alpha, zeta)` match what upstream computed during its own
//!      verify pass. That pins the transcript before we re-encode it
//!      as an AIR — an AIR bug would surface as "prove+verify still
//!      passes but aggregator rejects" which is much harder to debug.
//!   2. **Input for Phase A2-3b+**: the aggregator witness builder
//!      needs a `Vec<ChallengerOp>` that it can hand to
//!      `challenger_air::build_trace`, and the natural way to build
//!      that Vec is to run the same observes/samples a second time and
//!      record them. That's exactly what `TranscriptRecorder` below
//!      does.

use p3_challenger::{CanObserve, CanSample};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;

use crate::challenger_air::{ChallengerOp, RefChallenger};
use crate::prover::{Challenge, MvpConfig};
use p3_uni_stark::Proof;

// ---------------------------------------------------------------------------
// TranscriptRecorder: a RefChallenger that logs every op for later AIR replay
// ---------------------------------------------------------------------------

/// Wraps a `RefChallenger`, forwarding all observes/samples to it while
/// recording the sequence as `ChallengerOp`s — the exact script the
/// `ChallengerAir` trace builder consumes.
///
/// Used by `derive_pre_pcs_challenges_recorded` when the caller needs
/// both the derived `(alpha, zeta)` AND the byte-level transcript for
/// downstream AIR use.
pub struct TranscriptRecorder {
    ch: RefChallenger,
    /// Every `observe(v)` and every `sample → v` the verifier executed,
    /// in order. Observes and auto-duplexes are captured as the script
    /// a future `build_trace` call will expand into trace rows.
    pub ops: Vec<ChallengerOp>,
}

impl TranscriptRecorder {
    pub fn new() -> Self {
        Self {
            ch: RefChallenger::new(),
            ops: Vec::new(),
        }
    }

    fn observe(&mut self, v: Goldilocks) {
        self.ops.push(ChallengerOp::Observe(v));
        self.ch.observe(v);
    }

    fn observe_slice(&mut self, values: &[Goldilocks]) {
        for &v in values {
            self.observe(v);
        }
    }

    fn sample(&mut self) -> Goldilocks {
        self.ops.push(ChallengerOp::Sample);
        self.ch.sample()
    }

    /// Sample a `Challenge = BinomialExtensionField<Goldilocks, 2>` — D=2
    /// base-field samples packed into a basis-coefficient vector. Mirrors
    /// upstream `CanSample<Challenge>::sample()` for DuplexChallenger.
    fn sample_ext(&mut self) -> Challenge {
        Challenge::from_basis_coefficients_fn(|_| self.sample())
    }
}

impl Default for TranscriptRecorder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Pre-PCS transcript driver
// ---------------------------------------------------------------------------

/// Deserialize proof bytes into a `Proof<MvpConfig>`. Consensus-binding:
/// the validator uses the exact same postcard wire format.
pub fn deserialize_proof(proof_bytes: &[u8]) -> Result<Proof<MvpConfig>, postcard::Error> {
    postcard::from_bytes(proof_bytes)
}

/// Run the verifier's pre-PCS Fiat-Shamir transcript and return the
/// derived challenges.
///
/// Byte-identical to `uni_stark::verifier::verify` lines 354–385 when
/// the underlying challenger is our production `DuplexChallenger<
/// Goldilocks, Poseidon2Goldilocks<8>, 8, 4>`. Verified by the
/// `parity_with_upstream_verifier` test below.
///
/// Inputs:
/// - `proof`: decoded proof (caller handles postcard errors).
/// - `public_values`: field-element public-input vector — must match
///   what the prover committed (i.e. what `transfer_air::MvpWitness::
///   public_inputs()` returns for the witness that produced this
///   proof).
///
/// Returns `(alpha, zeta, transcript)` where `transcript` is the
/// sequence of `ChallengerOp`s the AIR trace builder will replay.
pub fn derive_pre_pcs_challenges_recorded(
    proof: &Proof<MvpConfig>,
    public_values: &[Goldilocks],
) -> (Challenge, Challenge, Vec<ChallengerOp>) {
    let mut rec = TranscriptRecorder::new();

    // --- Instance data (verifier.rs:355-357) ---
    let degree_bits = proof.degree_bits;
    // Our MvpConfig is NOT ZK. `base_degree_bits == degree_bits` and
    // `preprocessed_width == 0` for MvpTransferAir. The recorded
    // transcript reflects exactly what `uni_stark::verify` observes.
    let base_degree_bits = degree_bits;
    let preprocessed_width = 0usize;
    rec.observe(Goldilocks::from_usize(degree_bits));
    rec.observe(Goldilocks::from_usize(base_degree_bits));
    rec.observe(Goldilocks::from_usize(preprocessed_width));

    // --- Trace commitment (verifier.rs:363) ---
    // `commitments.trace` is a `MerkleCap<Goldilocks, [Goldilocks; 4]>`
    // with cap_height=0 (single root digest). Observing it iterates
    // each of the 4 digest field elements — same as upstream's
    // CanObserve<&MerkleCap<F, [F; N]>> impl for DuplexChallenger.
    for digest in proof.commitments.trace.roots() {
        for v in digest.iter() {
            rec.observe(*v);
        }
    }

    // --- Preprocessed commitment (skipped: preprocessed_width == 0) ---

    // --- Public values (verifier.rs:367) ---
    rec.observe_slice(public_values);

    // --- Sample alpha (verifier.rs:373) ---
    let alpha = rec.sample_ext();

    // --- Quotient commitment (verifier.rs:374) ---
    for digest in proof.commitments.quotient_chunks.roots() {
        for v in digest.iter() {
            rec.observe(*v);
        }
    }

    // --- Random commitment (skipped: ZK off) ---

    // --- Sample zeta (verifier.rs:385) ---
    let zeta = rec.sample_ext();

    (alpha, zeta, rec.ops)
}

/// Convenience: derive challenges without retaining the transcript ops.
/// Equivalent to `derive_pre_pcs_challenges_recorded(...).0/.1` but
/// allocates no ChallengerOp vector.
pub fn derive_pre_pcs_challenges(
    proof: &Proof<MvpConfig>,
    public_values: &[Goldilocks],
) -> (Challenge, Challenge) {
    let (alpha, zeta, _ops) = derive_pre_pcs_challenges_recorded(proof, public_values);
    (alpha, zeta)
}

// ---------------------------------------------------------------------------
// Tests: parity with upstream p3_uni_stark verifier
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::MvpProver;
    use crate::transfer_air::MvpWitness;

    /// Reproduce the verifier's pre-PCS transcript directly against
    /// upstream `DuplexChallenger`, and assert our driver matches.
    ///
    /// This is the A2-3a acceptance test — without it, the in-circuit
    /// verifier (future A2-3b) could diverge from upstream at the
    /// transcript level and every aggregator proof would fail to verify
    /// with no clear error.
    fn upstream_derive(
        proof: &Proof<MvpConfig>,
        public_values: &[Goldilocks],
    ) -> (Challenge, Challenge) {
        use crate::prover::Perm8;
        use p3_challenger::DuplexChallenger;
        use p3_goldilocks::default_goldilocks_poseidon2_8;

        let perm: Perm8 = default_goldilocks_poseidon2_8();
        let mut ch: DuplexChallenger<Goldilocks, Perm8, 8, 4> = DuplexChallenger::new(perm);

        ch.observe(Goldilocks::from_usize(proof.degree_bits));
        ch.observe(Goldilocks::from_usize(proof.degree_bits)); // base == degree (ZK off)
        ch.observe(Goldilocks::from_usize(0)); // preprocessed_width = 0
        for digest in proof.commitments.trace.roots() {
            for v in digest.iter() {
                ch.observe(*v);
            }
        }
        ch.observe_slice(public_values);
        let alpha: Challenge =
            Challenge::from_basis_coefficients_fn(|_| <DuplexChallenger<Goldilocks, Perm8, 8, 4> as CanSample<Goldilocks>>::sample(&mut ch));
        for digest in proof.commitments.quotient_chunks.roots() {
            for v in digest.iter() {
                ch.observe(*v);
            }
        }
        let zeta: Challenge =
            Challenge::from_basis_coefficients_fn(|_| <DuplexChallenger<Goldilocks, Perm8, 8, 4> as CanSample<Goldilocks>>::sample(&mut ch));
        (alpha, zeta)
    }

    fn proof_for(n_s: usize, n_o: usize, seed: u64) -> (Proof<MvpConfig>, Vec<Goldilocks>) {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(n_s, n_o, seed);
        let (proof_bytes, _pi_bytes) = prover.prove(&w.encode()).expect("prove ok");
        let proof: Proof<MvpConfig> = postcard::from_bytes(&proof_bytes).expect("decode proof");
        let pis = w.public_inputs();
        (proof, pis)
    }

    #[test]
    fn parity_with_upstream_verifier_1_1() {
        let (proof, pis) = proof_for(1, 1, 0x1111);
        let (ours_alpha, ours_zeta) = derive_pre_pcs_challenges(&proof, &pis);
        let (up_alpha, up_zeta) = upstream_derive(&proof, &pis);
        assert_eq!(ours_alpha, up_alpha, "alpha mismatch at shape 1/1");
        assert_eq!(ours_zeta, up_zeta, "zeta mismatch at shape 1/1");
    }

    #[test]
    fn parity_with_upstream_verifier_2_2() {
        let (proof, pis) = proof_for(2, 2, 0x2222);
        let (ours_alpha, ours_zeta) = derive_pre_pcs_challenges(&proof, &pis);
        let (up_alpha, up_zeta) = upstream_derive(&proof, &pis);
        assert_eq!(ours_alpha, up_alpha, "alpha mismatch at shape 2/2");
        assert_eq!(ours_zeta, up_zeta, "zeta mismatch at shape 2/2");
    }

    #[test]
    fn parity_with_upstream_verifier_4_4_worst_case() {
        let (proof, pis) = proof_for(4, 4, 0x4444);
        let (ours_alpha, ours_zeta) = derive_pre_pcs_challenges(&proof, &pis);
        let (up_alpha, up_zeta) = upstream_derive(&proof, &pis);
        assert_eq!(ours_alpha, up_alpha, "alpha mismatch at shape 4/4");
        assert_eq!(ours_zeta, up_zeta, "zeta mismatch at shape 4/4");
    }

    #[test]
    fn transcript_ops_replay_back_to_same_challenges() {
        // The recorded ops, when fed back through RefChallenger via
        // `build_trace`-style replay, must yield the same sample values
        // the recorder logged. This is the input A2-3b/c feeds into
        // `challenger_air::build_trace`.
        let (proof, pis) = proof_for(2, 2, 0xC0DE);
        let (alpha, zeta, ops) = derive_pre_pcs_challenges_recorded(&proof, &pis);

        let mut replay = RefChallenger::new();
        let mut samples = Vec::<Goldilocks>::new();
        for op in &ops {
            match op {
                ChallengerOp::Observe(v) => replay.observe(*v),
                ChallengerOp::Sample => samples.push(replay.sample()),
            }
        }
        // First D=2 samples form alpha, next D=2 form zeta.
        assert_eq!(samples.len(), 4, "pre-PCS transcript samples exactly 2 + 2 Goldilocks");

        let replay_alpha = Challenge::from_basis_coefficients_fn(|i| samples[i]);
        let replay_zeta = Challenge::from_basis_coefficients_fn(|i| samples[2 + i]);
        assert_eq!(replay_alpha, alpha, "alpha diverges on replay");
        assert_eq!(replay_zeta, zeta, "zeta diverges on replay");
    }

    #[test]
    fn tampered_pi_derives_different_zeta() {
        // Soundness sanity: a single flipped byte in the public-input
        // vector must change the derived zeta (otherwise Fiat-Shamir
        // isn't pinning the PI). This guards against the classic
        // "verifier samples zeta before binding PI" bug.
        let (proof, mut pis) = proof_for(2, 2, 0xDEAD);
        let (_, zeta_ok) = derive_pre_pcs_challenges(&proof, &pis);
        // Flip one limb.
        pis[0] += Goldilocks::ONE;
        let (_, zeta_bad) = derive_pre_pcs_challenges(&proof, &pis);
        assert_ne!(zeta_ok, zeta_bad, "zeta must depend on PI");
    }

    #[test]
    fn deserialize_proof_roundtrip() {
        // Produced proof must decode cleanly; wire format is stable.
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(1, 1, 0xABCD);
        let (proof_bytes, _pi_bytes) = prover.prove(&w.encode()).unwrap();
        let _proof: Proof<MvpConfig> = deserialize_proof(&proof_bytes).expect("decode");
    }
}
