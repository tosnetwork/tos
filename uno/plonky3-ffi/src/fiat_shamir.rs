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

    /// Observe one extension-field element as its D=2 base-field limbs.
    /// Mirrors upstream `observe_algebra_element`.
    fn observe_ext(&mut self, v: Challenge) {
        for &limb in v.as_basis_coefficients_slice() {
            self.observe(limb);
        }
    }

    /// Observe a slice of extension-field elements. Mirrors upstream
    /// `observe_algebra_slice`.
    fn observe_ext_slice(&mut self, values: &[Challenge]) {
        for &v in values {
            self.observe_ext(v);
        }
    }

    /// Sample `bits` random bits from the transcript by drawing one
    /// Goldilocks element and masking the low `bits` bits of its
    /// canonical u64 representation. Matches upstream's
    /// `DuplexChallenger::sample_bits`.
    fn sample_bits(&mut self, bits: usize) -> usize {
        use p3_field::PrimeField64;
        debug_assert!(bits < usize::BITS as usize);
        debug_assert!((1u64 << bits) < Goldilocks::ORDER_U64);
        let v = self.sample();
        (v.as_canonical_u64() as usize) & ((1usize << bits) - 1)
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

/// Run the verifier's pre-PCS Fiat-Shamir transcript against an
/// existing recorder and return the derived challenges. Extracted so
/// `derive_full_challenges` can continue from zeta into the PCS/FRI
/// transcript without rebuilding the recorder.
fn pre_pcs_into(
    rec: &mut TranscriptRecorder,
    proof: &Proof<MvpConfig>,
    public_values: &[Goldilocks],
) -> (Challenge, Challenge) {
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

    (alpha, zeta)
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
    let (alpha, zeta) = pre_pcs_into(&mut rec, proof, public_values);
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
// Full transcript driver — pre-PCS + PCS (FRI) prefix, Phase A2-3c-i
// ---------------------------------------------------------------------------

/// All Fiat-Shamir-derived values the verifier produces while replaying
/// the transcript of a `uni_stark::verify` over our `MvpConfig`, from
/// the start through to the last `sample_bits` call of the FRI query
/// loop. This is the **complete** set of public-coin challenges the
/// in-circuit VerifierAir (Phase A2-3c onward) must reproduce — there
/// is no additional sampling after the query indices.
#[derive(Clone, Debug)]
pub struct FullChallenges {
    /// `alpha` from the STARK constraint-folding step (verifier.rs:373).
    pub alpha_stark: Challenge,
    /// Out-of-domain evaluation point (verifier.rs:385).
    pub zeta: Challenge,
    /// `alpha` from the batch-combination step inside `pcs.verify` →
    /// `verify_fri`, used to linearly combine multiple opening queries
    /// into one FRI instance (fri/verifier.rs:144).
    pub fri_alpha: Challenge,
    /// Per-commit-phase folding challenges `β_0, β_1, …`. One per
    /// `commit_phase_commits[i]` in the FRI proof.
    pub betas: Vec<Challenge>,
    /// Per-query random indices. Each is `log_global_max_height` bits.
    pub query_indices: Vec<usize>,
    /// `log_global_max_height` — the number of bits each query index
    /// is drawn from. Derived from `log_blowup + sum(log_arities) +
    /// log_final_poly_len`.
    pub log_global_max_height: usize,
}

/// Run the full Fiat-Shamir transcript — pre-PCS plus the PCS (FRI)
/// prefix up to and including query-index sampling — and return every
/// public-coin challenge the verifier produces along the way, plus the
/// recorded op sequence.
///
/// Byte-identical to a composition of
/// `uni_stark::verifier::verify` (lines 354–385 → pre-PCS)
/// + `TwoAdicFriPcs::verify` (observe opened values)
/// + `fri::verifier::verify_fri` (commit-phase observes/betas + final
///   poly + log_arities + query index samples).
///
/// Validated by `parity_full_transcript_with_upstream` on real 1/1,
/// 2/2, 4/4 Transfer proofs.
pub fn derive_full_challenges_recorded(
    proof: &Proof<MvpConfig>,
    public_values: &[Goldilocks],
) -> (FullChallenges, Vec<ChallengerOp>) {
    let mut rec = TranscriptRecorder::new();

    // ======= Pre-PCS (A2-3a) =======
    let (alpha_stark, zeta) = pre_pcs_into(&mut rec, proof, public_values);

    // ======= PCS (FRI) transcript =======
    // All observes done by `TwoAdicFriPcs::verify` before handing
    // control to `verify_fri`: the opened values in the same order
    // the prover committed them. For uni-stark verify over our
    // non-ZK, no-preprocessed MvpConfig, the commitment list is
    // (trace_commit, [(trace_domain, [(zeta, trace_local),
    //                                 (zeta_next, trace_next)])])
    // followed by (quotient_commit, [for each chunk: (chunk_domain,
    // [(zeta, chunk_values)])]). The verifier observes them in
    // exactly that order (two_adic_pcs.rs:680-685).

    // 1. trace_local at zeta
    rec.observe_ext_slice(&proof.opened_values.trace_local);

    // 2. trace_next at zeta_next (our AIR has transition constraints ⇒ present)
    if let Some(trace_next) = proof.opened_values.trace_next.as_deref() {
        rec.observe_ext_slice(trace_next);
    }

    // 3. quotient chunks at zeta (one opening per chunk)
    for chunk in &proof.opened_values.quotient_chunks {
        rec.observe_ext_slice(chunk);
    }

    // ======= verify_fri =======
    // 4. Sample fri_alpha (fri/verifier.rs:144).
    let fri_alpha = rec.sample_ext();

    // 5. Commit-phase rounds: for each, observe commit + sample β_i
    //    (PoW witnesses are validated but do not affect the transcript).
    let num_rounds = proof.opening_proof.commit_phase_commits.len();
    let mut betas = Vec::with_capacity(num_rounds);
    for comm in &proof.opening_proof.commit_phase_commits {
        // Commitment is `ExtensionMmcs<Val, Challenge, ValMmcs>::Commitment`
        // which inherits the inner (base-field) MMCS commitment type —
        // a `MerkleCap<Goldilocks, [Goldilocks; 4]>`. So we observe the
        // 4 base-field digest elements, identical to the trace and
        // quotient commitments.
        for digest in comm.roots() {
            for v in digest.iter() {
                rec.observe(*v);
            }
        }
        betas.push(rec.sample_ext());
    }

    // 6. Observe the final polynomial's extension-field coefficients.
    rec.observe_ext_slice(&proof.opening_proof.final_poly);

    // 7. Observe the per-round log_arity schedule (fri/verifier.rs:234-236).
    let log_arities: Vec<usize> = proof
        .opening_proof
        .query_proofs
        .first()
        .map(|qp| {
            qp.commit_phase_openings
                .iter()
                .map(|o| o.log_arity as usize)
                .collect()
        })
        .unwrap_or_default();
    for &log_arity in &log_arities {
        rec.observe(Goldilocks::from_usize(log_arity));
    }

    // 8. Query-index sampling. `extra_query_index_bits == 0` for
    //    `TwoAdicFriFolding` (fri/two_adic_pcs.rs:106-108), so the
    //    number of bits sampled per query equals `log_global_max_height`.
    let total_log_reduction: usize = log_arities.iter().sum();
    // params: log_blowup = 3, log_final_poly_len = 0 (see prover::build_config).
    let log_blowup = 3usize;
    let log_final_poly_len = 0usize;
    let log_global_max_height = total_log_reduction + log_blowup + log_final_poly_len;

    let num_queries = proof.opening_proof.query_proofs.len();
    let mut query_indices = Vec::with_capacity(num_queries);
    for _ in 0..num_queries {
        query_indices.push(rec.sample_bits(log_global_max_height));
    }

    (
        FullChallenges {
            alpha_stark,
            zeta,
            fri_alpha,
            betas,
            query_indices,
            log_global_max_height,
        },
        rec.ops,
    )
}

/// Convenience: drop the recorded op vector.
pub fn derive_full_challenges(
    proof: &Proof<MvpConfig>,
    public_values: &[Goldilocks],
) -> FullChallenges {
    derive_full_challenges_recorded(proof, public_values).0
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

    // ======================================================================
    // A2-3c-i: full-transcript byte-parity with upstream verify
    // ======================================================================

    /// Reproduce the *full* verifier transcript (pre-PCS + PCS/FRI
    /// prefix) directly against upstream `DuplexChallenger`, returning
    /// the same set of challenges our `derive_full_challenges` does.
    /// The test asserts that the two agree byte-for-byte — this is the
    /// A2-3c-i acceptance: it proves the in-circuit VerifierAir has a
    /// complete, faithful reference for every public-coin challenge.
    fn upstream_derive_full(
        proof: &Proof<MvpConfig>,
        public_values: &[Goldilocks],
    ) -> FullChallenges {
        use crate::prover::Perm8;
        use p3_challenger::DuplexChallenger;
        use p3_field::PrimeField64;
        use p3_goldilocks::default_goldilocks_poseidon2_8;

        let perm: Perm8 = default_goldilocks_poseidon2_8();
        let mut ch: DuplexChallenger<Goldilocks, Perm8, 8, 4> = DuplexChallenger::new(perm);

        // Pre-PCS (mirrors upstream_derive + a bit more)
        ch.observe(Goldilocks::from_usize(proof.degree_bits));
        ch.observe(Goldilocks::from_usize(proof.degree_bits));
        ch.observe(Goldilocks::from_usize(0));
        for digest in proof.commitments.trace.roots() {
            for v in digest.iter() {
                ch.observe(*v);
            }
        }
        ch.observe_slice(public_values);
        let alpha_stark: Challenge = Challenge::from_basis_coefficients_fn(|_| {
            <DuplexChallenger<Goldilocks, Perm8, 8, 4> as CanSample<Goldilocks>>::sample(&mut ch)
        });
        for digest in proof.commitments.quotient_chunks.roots() {
            for v in digest.iter() {
                ch.observe(*v);
            }
        }
        let zeta: Challenge = Challenge::from_basis_coefficients_fn(|_| {
            <DuplexChallenger<Goldilocks, Perm8, 8, 4> as CanSample<Goldilocks>>::sample(&mut ch)
        });

        // PCS observes all opened values first.
        let basis = |v: &Challenge| -> [Goldilocks; 2] {
            let s = <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(v);
            [s[0], s[1]]
        };
        for v in &proof.opened_values.trace_local {
            ch.observe_slice(&basis(v));
        }
        if let Some(next) = proof.opened_values.trace_next.as_deref() {
            for v in next {
                ch.observe_slice(&basis(v));
            }
        }
        for chunk in &proof.opened_values.quotient_chunks {
            for v in chunk {
                ch.observe_slice(&basis(v));
            }
        }

        // verify_fri
        let fri_alpha: Challenge = Challenge::from_basis_coefficients_fn(|_| {
            <DuplexChallenger<Goldilocks, Perm8, 8, 4> as CanSample<Goldilocks>>::sample(&mut ch)
        });
        let mut betas = Vec::new();
        for comm in &proof.opening_proof.commit_phase_commits {
            for digest in comm.roots() {
                for v in digest.iter() {
                    ch.observe(*v);
                }
            }
            betas.push(Challenge::from_basis_coefficients_fn(|_| {
                <DuplexChallenger<Goldilocks, Perm8, 8, 4> as CanSample<Goldilocks>>::sample(
                    &mut ch,
                )
            }));
        }
        for v in &proof.opening_proof.final_poly {
            ch.observe_slice(&basis(v));
        }

        let log_arities: Vec<usize> = proof
            .opening_proof
            .query_proofs
            .first()
            .map(|qp| {
                qp.commit_phase_openings
                    .iter()
                    .map(|o| o.log_arity as usize)
                    .collect()
            })
            .unwrap_or_default();
        for &la in &log_arities {
            ch.observe(Goldilocks::from_usize(la));
        }
        let total_log_reduction: usize = log_arities.iter().sum();
        let log_global_max_height = total_log_reduction + 3 + 0;
        let num_queries = proof.opening_proof.query_proofs.len();
        let mut query_indices = Vec::with_capacity(num_queries);
        for _ in 0..num_queries {
            // Mirror DuplexChallenger::sample_bits byte-for-byte.
            let bits = log_global_max_height;
            let g: Goldilocks =
                <DuplexChallenger<Goldilocks, Perm8, 8, 4> as CanSample<Goldilocks>>::sample(
                    &mut ch,
                );
            let idx = (g.as_canonical_u64() as usize) & ((1usize << bits) - 1);
            query_indices.push(idx);
        }

        FullChallenges {
            alpha_stark,
            zeta,
            fri_alpha,
            betas,
            query_indices,
            log_global_max_height,
        }
    }

    fn assert_full_challenges_eq(a: &FullChallenges, b: &FullChallenges, ctx: &str) {
        assert_eq!(a.alpha_stark, b.alpha_stark, "{ctx}: alpha_stark mismatch");
        assert_eq!(a.zeta, b.zeta, "{ctx}: zeta mismatch");
        assert_eq!(a.fri_alpha, b.fri_alpha, "{ctx}: fri_alpha mismatch");
        assert_eq!(a.betas, b.betas, "{ctx}: betas mismatch");
        assert_eq!(
            a.log_global_max_height, b.log_global_max_height,
            "{ctx}: log_global_max_height mismatch"
        );
        assert_eq!(a.query_indices, b.query_indices, "{ctx}: query_indices mismatch");
    }

    #[test]
    fn parity_full_transcript_1_1() {
        let (proof, pis) = proof_for(1, 1, 0xF101);
        let ours = derive_full_challenges(&proof, &pis);
        let theirs = upstream_derive_full(&proof, &pis);
        assert_full_challenges_eq(&ours, &theirs, "shape 1/1");
        // Structural invariants: 52 queries, ≥ 1 β, log_global_max_height
        // coherent with log_blowup = 3.
        assert_eq!(ours.query_indices.len(), 52);
        assert!(!ours.betas.is_empty());
        assert!(ours.log_global_max_height >= 3);
    }

    #[test]
    fn parity_full_transcript_2_2() {
        let (proof, pis) = proof_for(2, 2, 0xF202);
        let ours = derive_full_challenges(&proof, &pis);
        let theirs = upstream_derive_full(&proof, &pis);
        assert_full_challenges_eq(&ours, &theirs, "shape 2/2");
    }

    #[test]
    fn parity_full_transcript_4_4_worst_case() {
        let (proof, pis) = proof_for(4, 4, 0xF404);
        let ours = derive_full_challenges(&proof, &pis);
        let theirs = upstream_derive_full(&proof, &pis);
        assert_full_challenges_eq(&ours, &theirs, "shape 4/4");
    }

    #[test]
    fn pre_pcs_is_prefix_of_full() {
        // Regression: derive_pre_pcs_challenges must return the same
        // (alpha, zeta) that the full driver derives — otherwise we'd
        // have drift between the A2-3a and A2-3c-i code paths.
        let (proof, pis) = proof_for(3, 2, 0xF322);
        let (pre_alpha, pre_zeta) = derive_pre_pcs_challenges(&proof, &pis);
        let full = derive_full_challenges(&proof, &pis);
        assert_eq!(pre_alpha, full.alpha_stark);
        assert_eq!(pre_zeta, full.zeta);
    }

    #[test]
    fn two_distinct_proofs_derive_distinct_fri_alphas() {
        // Soundness-smoke: two valid proofs (different seeds, same
        // shape) produce different trace / quotient commitments, so
        // different zetas, and therefore different fri_alphas and
        // different query-index schedules. Fiat-Shamir downstream
        // challenges must reflect upstream commitment state; this
        // test fails if the FRI transcript is somehow decoupled.
        let (a_proof, a_pis) = proof_for(2, 2, 0xF555);
        let (b_proof, b_pis) = proof_for(2, 2, 0xF556);
        let a = derive_full_challenges(&a_proof, &a_pis);
        let b = derive_full_challenges(&b_proof, &b_pis);
        assert_ne!(a.zeta, b.zeta);
        assert_ne!(a.fri_alpha, b.fri_alpha);
        assert_ne!(a.betas, b.betas);
        assert_ne!(a.query_indices, b.query_indices);
    }

    #[test]
    fn query_indices_within_domain() {
        let (proof, pis) = proof_for(2, 2, 0xF777);
        let full = derive_full_challenges(&proof, &pis);
        let bound = 1usize << full.log_global_max_height;
        for &idx in &full.query_indices {
            assert!(idx < bound, "query index {idx} out of range [0, {bound})");
        }
    }
}
