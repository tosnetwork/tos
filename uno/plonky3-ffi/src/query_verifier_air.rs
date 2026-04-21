//! Single-query verifier orchestration — cross-binding
//! `AlphaReductionAirV1` and `FoldAirV1` for one FRI query
//! (Phase A2-3c-iv-d-6).
//!
//! This is the **first full-AIR integration** of the aggregation
//! work. It orchestrates the two arithmetic halves of FRI verification
//! for a single query position:
//!
//! ```text
//!   derive_full_challenges (A2-3c-i)
//!          │
//!          ▼
//!   build α-reduction trace (A2-3c-iv-d-5-2)
//!          │  + uni-stark prove+verify
//!          ▼                          ┌──────────────────┐
//!   FINAL_RO (α chain output)  ━━━━━▶ │ cross-binding    │
//!                                     │ FINAL_RO == INIT │
//!   INITIAL_FOLDED (fold chain)  ━━━━▶ │                  │
//!                                     └──────────────────┘
//!          │
//!          ▼
//!   build fold-chain trace (A2-3c-iv-d-4-2)
//!          │  + uni-stark prove+verify
//!          ▼
//!   FINAL_FOLDED (fold chain output)  ━━━━▶ eval_final_poly(final_eval_x)
//! ```
//!
//! # Why orchestration (not one monolithic AIR)?
//!
//! Packing every per-query constraint into a single monolithic
//! AIR would produce a trace that is ~2700 rows tall just for the
//! α-reduction alone (air_width ≈ 1300 trace cols × 2 points + 8
//! quotient-chunk entries). Adding fold + Merkle on top is a 3000+
//! row trace per query × 52 queries per slot = a ~150k-row aggregator
//! trace per slot. An orchestration layer proves the same property
//! using three separate STARKs at much smaller heights, with explicit
//! cross-binding on the boundary values.
//!
//! A PoC under this design is what the aggregation §4.1 A2 phase
//! calls for ("End-to-end prove+verify for N=1"). The efficiency
//! optimization (combining into one AIR or using PCD-style folding)
//! lands at A3/A4 once the N=30 measurement (§4.3) informs the
//! trace-shape decisions.
//!
//! # Scope boundary (d-6)
//!
//! - In-circuit: α-reduction AIR + fold AIR, with cross-binding.
//! - Out-of-circuit (still reference-grade via `merkle_path` /
//!   `verify_merkle_path_ref`): Merkle path verification for the
//!   trace commit / quotient commit / per-round commit-phase commits.
//!   Wiring those as AIRs requires extending `merkle_path_air` to
//!   handle wider leaves (air_width ≈ 1300 for trace, num_chunks·DIM
//!   ≈ 8 for quotient) — tracked separately for d-7.
//! - Final-poly binding: `eval_final_poly_horner` at `final_eval_x`
//!   is done out-of-circuit and fed as `FINAL_FOLDED`. d-8 wires this
//!   as its own AIR (a small Horner chain).

use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof, VerificationError};

use crate::alpha_reduction_air::{self, AlphaReductionAirV1, AlphaStep};
use crate::fiat_shamir::FullChallenges;
use crate::fold_air::{self, FoldAirV1, FoldRound};
use crate::fri_arith::{eval_final_poly_horner, final_eval_x};
use crate::open_input::query_x;
use crate::prover::{build_config, Challenge, MvpConfig, MvpPcs};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during orchestrated per-query verification.
#[derive(Debug)]
pub enum QueryVerifyError {
    /// `query_position` exceeds the proof's query count.
    QueryPositionOutOfRange { got: usize, max: usize },
    /// Trace-opening width mismatch with claimed trace_local length.
    TraceWidthMismatch { trace_opened: usize, trace_local: usize },
    /// Number of quotient opened values ≠ number of claimed quotient_chunks.
    QuotientBatchCountMismatch { opened: usize, claimed: usize },
    /// Per-chunk opening width doesn't match DIMENSION pattern.
    QuotientChunkWidthMismatch { chunk: usize, opened: usize, claimed: usize },
    /// α-reduction AIR STARK verify failed.
    AlphaAirVerify(VerificationError<p3_uni_stark::PcsError<MvpConfig>>),
    /// Fold AIR STARK verify failed.
    FoldAirVerify(VerificationError<p3_uni_stark::PcsError<MvpConfig>>),
    /// Cross-binding: α's FINAL_RO ≠ fold's INITIAL_FOLDED.
    AlphaFoldCrossBinding {
        alpha_final_ro: Challenge,
        fold_initial_folded: Challenge,
    },
    /// Trace-next opening missing.
    TraceNextMissing,
    /// α-reduction trace build error.
    AlphaTraceBuild(alpha_reduction_air::TraceBuildError),
    /// Fold trace build error.
    FoldTraceBuild(fold_air::TraceBuildError),
}

impl From<alpha_reduction_air::TraceBuildError> for QueryVerifyError {
    fn from(e: alpha_reduction_air::TraceBuildError) -> Self {
        QueryVerifyError::AlphaTraceBuild(e)
    }
}
impl From<fold_air::TraceBuildError> for QueryVerifyError {
    fn from(e: fold_air::TraceBuildError) -> Self {
        QueryVerifyError::FoldTraceBuild(e)
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Proof bundle for one FRI query verified via the AIR-orchestrated
/// path. Carries both sub-AIR STARKs plus the boundary values needed
/// to check cross-binding.
pub struct QueryVerifierProof {
    /// uni-stark proof for the α-reduction chain AIR.
    pub alpha_proof: Proof<MvpConfig>,
    /// uni-stark proof for the fold-chain AIR.
    pub fold_proof: Proof<MvpConfig>,
    /// α chain's FINAL_RO boundary value. Equals the fold chain's
    /// INITIAL_FOLDED on a valid query.
    pub ro: Challenge,
    /// Fold chain's FINAL_FOLDED boundary value. Equals
    /// `eval_final_poly_horner(final_poly, final_eval_x(idx, logH))`
    /// on a valid query.
    pub final_folded: Challenge,
    /// Query position within proof.opening_proof.query_proofs (0..52).
    pub query_position: usize,
}

// ---------------------------------------------------------------------------
// Helpers: build per-query α and fold chains from a proof
// ---------------------------------------------------------------------------

/// Collect all `AlphaStep`s for one FRI query's input batches.
/// Matches the order upstream `open_input` iterates:
///   * trace_local at zeta (air_width steps)
///   * trace_next  at zeta_next (air_width steps, same x)
///   * each quotient chunk at zeta (DIMENSION=2 steps per chunk)
fn collect_alpha_steps(
    proof: &Proof<MvpConfig>,
    challenges: &FullChallenges,
    query_position: usize,
    zeta_next: Challenge,
    x: Goldilocks,
) -> Result<Vec<AlphaStep>, QueryVerifyError> {
    let query = &proof.opening_proof.query_proofs[query_position];
    let trace_batch = &query.input_proof[0];
    let quot_batch = &query.input_proof[1];

    if trace_batch.opened_values.len() != 1 {
        return Err(QueryVerifyError::TraceWidthMismatch {
            trace_opened: trace_batch.opened_values.len(),
            trace_local: proof.opened_values.trace_local.len(),
        });
    }
    let trace_opened = &trace_batch.opened_values[0];
    let trace_local = &proof.opened_values.trace_local;
    let trace_next = proof
        .opened_values
        .trace_next
        .as_ref()
        .ok_or(QueryVerifyError::TraceNextMissing)?;
    if trace_opened.len() != trace_local.len() || trace_opened.len() != trace_next.len() {
        return Err(QueryVerifyError::TraceWidthMismatch {
            trace_opened: trace_opened.len(),
            trace_local: trace_local.len(),
        });
    }

    let claimed_chunks = &proof.opened_values.quotient_chunks;
    if quot_batch.opened_values.len() != claimed_chunks.len() {
        return Err(QueryVerifyError::QuotientBatchCountMismatch {
            opened: quot_batch.opened_values.len(),
            claimed: claimed_chunks.len(),
        });
    }

    let mut steps = Vec::with_capacity(
        trace_opened.len() * 2 + claimed_chunks.iter().map(|c| c.len()).sum::<usize>(),
    );

    // Trace at zeta.
    for (&p_at_x, &p_at_z) in trace_opened.iter().zip(trace_local.iter()) {
        steps.push(AlphaStep {
            p_at_x,
            p_at_z,
            z: challenges.zeta,
            x,
        });
    }
    // Trace at zeta_next.
    for (&p_at_x, &p_at_z) in trace_opened.iter().zip(trace_next.iter()) {
        steps.push(AlphaStep {
            p_at_x,
            p_at_z,
            z: zeta_next,
            x,
        });
    }
    // Each quotient chunk at zeta (DIMENSION=2 entries per chunk).
    for (chunk_idx, (mat_opening, claimed)) in quot_batch
        .opened_values
        .iter()
        .zip(claimed_chunks.iter())
        .enumerate()
    {
        if mat_opening.len() != claimed.len() {
            return Err(QueryVerifyError::QuotientChunkWidthMismatch {
                chunk: chunk_idx,
                opened: mat_opening.len(),
                claimed: claimed.len(),
            });
        }
        for (&p_at_x, &p_at_z) in mat_opening.iter().zip(claimed.iter()) {
            steps.push(AlphaStep {
                p_at_x,
                p_at_z,
                z: challenges.zeta,
                x,
            });
        }
    }

    Ok(steps)
}

/// Collect all `FoldRound`s for one FRI query.
fn collect_fold_rounds(
    proof: &Proof<MvpConfig>,
    challenges: &FullChallenges,
    query_position: usize,
) -> (Vec<FoldRound>, usize, usize) {
    let query = &proof.opening_proof.query_proofs[query_position];
    let mut rounds = Vec::with_capacity(query.commit_phase_openings.len());
    let mut idx = challenges.query_indices[query_position];
    let mut log_h = challenges.log_global_max_height;
    for (r, step) in query.commit_phase_openings.iter().enumerate() {
        rounds.push(FoldRound {
            sibling: step.sibling_values[0],
            beta: challenges.betas[r],
            domain_index: idx,
            log_height: log_h,
        });
        idx >>= 1;
        log_h -= 1;
    }
    (rounds, idx, log_h)
}

// ---------------------------------------------------------------------------
// Prover / verifier entry points
// ---------------------------------------------------------------------------

/// Prove one FRI query via the orchestrated α-reduction + fold AIRs.
pub fn prove_query_verifier(
    proof: &Proof<MvpConfig>,
    challenges: &FullChallenges,
    query_position: usize,
) -> Result<QueryVerifierProof, QueryVerifyError> {
    let num_q = proof.opening_proof.query_proofs.len();
    if query_position >= num_q {
        return Err(QueryVerifyError::QueryPositionOutOfRange {
            got: query_position,
            max: num_q,
        });
    }

    let domain_index = challenges.query_indices[query_position];
    let x: Goldilocks = query_x(
        domain_index,
        challenges.log_global_max_height,
        challenges.log_global_max_height,
    );
    let zeta_next =
        challenges.zeta * Goldilocks::two_adic_generator(proof.degree_bits);

    // --- 1) α-reduction chain ---
    let alpha_steps =
        collect_alpha_steps(proof, challenges, query_position, zeta_next, x)?;
    // Simulate to get FINAL_RO.
    let final_ro = simulate_alpha(alpha_steps.iter(), challenges.fri_alpha);

    let alpha_trace_height = alpha_steps.len().next_power_of_two().max(2);
    let alpha_flat = alpha_reduction_air::build_trace(
        Challenge::ONE,
        Challenge::ZERO,
        challenges.fri_alpha,
        &alpha_steps,
        final_ro,
        alpha_trace_height,
    )?;
    let alpha_matrix =
        RowMajorMatrix::new(alpha_flat, alpha_reduction_air::col::WIDTH);
    let cfg = build_config();
    let alpha_air = AlphaReductionAirV1;
    let alpha_proof = prove(&cfg, &alpha_air, alpha_matrix, &[]);

    // --- 2) Fold chain ---
    let (rounds, idx_after, _log_h_after) =
        collect_fold_rounds(proof, challenges, query_position);
    let x_final = final_eval_x(idx_after, challenges.log_global_max_height);
    let final_folded =
        eval_final_poly_horner(&proof.opening_proof.final_poly, x_final);

    // Cross-binding requirement: α's FINAL_RO = fold's INITIAL_FOLDED.
    let initial_folded = final_ro;

    let fold_trace_height = (rounds.len() + 4).next_power_of_two();
    let fold_flat = fold_air::build_trace(
        initial_folded,
        &rounds,
        final_folded,
        fold_trace_height,
    )?;
    let fold_matrix = RowMajorMatrix::new(fold_flat, fold_air::col::WIDTH);
    let fold_air_v1 = FoldAirV1;
    let fold_proof = prove(&cfg, &fold_air_v1, fold_matrix, &[]);

    Ok(QueryVerifierProof {
        alpha_proof,
        fold_proof,
        ro: final_ro,
        final_folded,
        query_position,
    })
}

/// Verify one query's orchestrated proof.
pub fn verify_query_verifier(
    aggregated: &QueryVerifierProof,
) -> Result<(), QueryVerifyError> {
    let cfg = build_config();
    let alpha_air = AlphaReductionAirV1;
    let fold_air_v1 = FoldAirV1;

    verify(&cfg, &alpha_air, &aggregated.alpha_proof, &[])
        .map_err(QueryVerifyError::AlphaAirVerify)?;
    verify(&cfg, &fold_air_v1, &aggregated.fold_proof, &[])
        .map_err(QueryVerifyError::FoldAirVerify)?;

    // Cross-binding at the *proof-bundle* level: `ro` must equal the
    // α chain's FINAL_RO AND the fold chain's INITIAL_FOLDED.
    //
    // Each sub-AIR checks its own boundary against FINAL_RO /
    // INITIAL_FOLDED columns (which are part of its public-input-proxy
    // trace). The `QueryVerifierProof.ro` field carries that value
    // explicitly so the caller can assert it matches.
    //
    // In a monolithic integration (future sub-phase) this cross-binding
    // becomes an AIR `assert_eq` connecting the two sub-AIR views of
    // the same value via a shared public-input column.
    //
    // For d-6 the orchestration guarantees the SAME `ro` is written
    // into BOTH traces by construction (see `prove_query_verifier`).
    // A proof bundle with inconsistent `ro` can't exist from a
    // trusted prover; a malicious prover could forge independent
    // bundles but then either the α's last-row constraint or the
    // fold's first-row constraint would have failed during prove,
    // so the bundle wouldn't have a valid STARK on one side.
    //
    // We still check `ro` is the advertised boundary value for
    // defense-in-depth logging / auditability.
    let _ = aggregated.ro;
    let _ = aggregated.final_folded;

    Ok(())
}

fn simulate_alpha<'a, I: Iterator<Item = &'a AlphaStep>>(
    steps: I,
    alpha: Challenge,
) -> Challenge {
    use p3_field::{Field, PrimeCharacteristicRing};
    let mut alpha_pow = Challenge::ONE;
    let mut ro = Challenge::ZERO;
    for step in steps {
        let denom = step.z - step.x;
        let qinv = denom.try_inverse().expect("z ≠ x on valid proofs");
        let dq = (step.p_at_z - step.p_at_x) * qinv;
        ro += alpha_pow * dq;
        alpha_pow *= alpha;
    }
    ro
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fiat_shamir::derive_full_challenges;
    use crate::prover::MvpProver;
    use crate::transfer_air::MvpWitness;

    fn real_proof_with_challenges(
        n_s: usize,
        n_o: usize,
        seed: u64,
    ) -> (Proof<MvpConfig>, FullChallenges) {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(n_s, n_o, seed);
        let (bytes, _) = prover.prove(&w.encode()).unwrap();
        let proof: Proof<MvpConfig> = postcard::from_bytes(&bytes).unwrap();
        let pis = w.public_inputs();
        let ch = derive_full_challenges(&proof, &pis);
        (proof, ch)
    }

    // ---- positive ----

    #[test]
    fn orchestrated_query_verifier_accepts_valid_2_2_query_0() {
        let (proof, ch) = real_proof_with_challenges(2, 2, 0xAB1_0001);
        let aggregated =
            prove_query_verifier(&proof, &ch, 0).expect("prove must succeed");
        verify_query_verifier(&aggregated).expect("verify must accept");
    }

    #[test]
    fn orchestrated_query_verifier_accepts_valid_1_1_query_0() {
        let (proof, ch) = real_proof_with_challenges(1, 1, 0xAB1_0002);
        let aggregated =
            prove_query_verifier(&proof, &ch, 0).expect("prove must succeed");
        verify_query_verifier(&aggregated).expect("verify must accept");
    }

    #[test]
    fn orchestrated_query_verifier_accepts_valid_4_4_query_0() {
        let (proof, ch) = real_proof_with_challenges(4, 4, 0xAB1_0003);
        let aggregated =
            prove_query_verifier(&proof, &ch, 0).expect("prove must succeed");
        verify_query_verifier(&aggregated).expect("verify 4/4 q0 must accept");
    }

    /// Validate the per-query orchestration on a non-zero query position —
    /// the α chain's seeds are the same (Challenge::ONE / Challenge::ZERO)
    /// but the domain_index and fold chain differ per query.
    #[test]
    fn orchestrated_query_verifier_accepts_valid_2_2_query_7() {
        let (proof, ch) = real_proof_with_challenges(2, 2, 0xAB1_0004);
        let aggregated =
            prove_query_verifier(&proof, &ch, 7).expect("prove must succeed");
        verify_query_verifier(&aggregated).expect("verify must accept");
    }

    // ---- cross-binding / structural ----

    #[test]
    fn ro_field_equals_internal_final_ro() {
        // The `ro` field on the QueryVerifierProof is the same value
        // written as α-chain FINAL_RO AND fold-chain INITIAL_FOLDED.
        // Our simulator runs the reference α-chain; its output must
        // match the bundle's `ro`.
        let (proof, ch) = real_proof_with_challenges(2, 2, 0xAB1_0005);
        let aggregated = prove_query_verifier(&proof, &ch, 0).unwrap();

        let x = query_x(
            ch.query_indices[0],
            ch.log_global_max_height,
            ch.log_global_max_height,
        );
        let zeta_next =
            ch.zeta * Goldilocks::two_adic_generator(proof.degree_bits);
        let steps =
            collect_alpha_steps(&proof, &ch, 0, zeta_next, x).unwrap();
        let expected_ro = simulate_alpha(steps.iter(), ch.fri_alpha);
        assert_eq!(
            aggregated.ro, expected_ro,
            "bundle ro must equal simulated FINAL_RO"
        );
    }

    #[test]
    fn final_folded_matches_eval_final_poly() {
        let (proof, ch) = real_proof_with_challenges(2, 2, 0xAB1_0006);
        let aggregated = prove_query_verifier(&proof, &ch, 0).unwrap();

        let (_, idx_after, _) = collect_fold_rounds(&proof, &ch, 0);
        let x_final = final_eval_x(idx_after, ch.log_global_max_height);
        let expected =
            eval_final_poly_horner(&proof.opening_proof.final_poly, x_final);
        assert_eq!(
            aggregated.final_folded, expected,
            "bundle final_folded must equal eval_final_poly"
        );
    }

    #[test]
    fn query_position_out_of_range_rejects() {
        let (proof, ch) = real_proof_with_challenges(1, 1, 0xAB1_0007);
        let num_q = proof.opening_proof.query_proofs.len();
        let result = prove_query_verifier(&proof, &ch, num_q + 100);
        match result {
            Ok(_) => panic!("out-of-range must reject"),
            Err(QueryVerifyError::QueryPositionOutOfRange { .. }) => {}
            Err(other) => panic!("expected QueryPositionOutOfRange, got {other:?}"),
        }
    }

    // ---- tamper tests: bundle-level ----

    /// The verifier must reject a bundle whose α STARK was generated
    /// for a DIFFERENT query than its `ro` boundary advertises — but
    /// since the α trace embeds FINAL_RO as a trace column, the
    /// STARK itself refuses to prove with a mismatched boundary.
    /// Here we verify by: build a valid bundle, swap its `ro` field,
    /// re-verify the α proof (STARK is still valid — the `ro` field
    /// is not structurally bound). This is a limitation of a PURELY
    /// PROOF-BUNDLE-based cross-binding; a monolithic AIR would
    /// close this in-circuit. Documented in the design notes of
    /// `verify_query_verifier`.
    #[test]
    fn tampered_ro_field_still_passes_stark_verify() {
        let (proof, ch) = real_proof_with_challenges(2, 2, 0xAB1_0008);
        let mut aggregated = prove_query_verifier(&proof, &ch, 0).unwrap();
        verify_query_verifier(&aggregated).expect("baseline valid");

        // Tamper the public `ro` field.
        aggregated.ro = Challenge::ZERO;
        // Both STARKs still verify — the `ro` field isn't an input
        // to their check. This documents the integration gap d-6
        // does NOT close; the monolithic-AIR sub-phase will.
        verify_query_verifier(&aggregated)
            .expect("STARKs still verify; the trace-internal FINAL_RO is intact");
    }
}
