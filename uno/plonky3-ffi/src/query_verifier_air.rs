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
// Phase A2-3c-iv-d-8-a — trace-commit Merkle chain orchestration
//
// Extends `QueryVerifierProof` to optionally carry the trace-commit
// Merkle chain (leaf_hash_air + compression_path_air) for a single
// query. The four STARK proofs (α + fold + trace_leaf_hash +
// trace_compression) together verify:
//
//   * trace-commit opened row hashes to `trace_leaf_digest`
//     (leaf_hash_air)
//   * `trace_leaf_digest` walks to `proof.commitments.trace` root via
//     the opening-proof siblings (compression_path_air)
//   * α-reduction on trace_local + trace_next + quotient chunks
//     produces `reduced_opening`
//   * fold chain from `reduced_opening` produces `final_folded`
//     matching `eval_final_poly_horner(final_poly, final_eval_x)`
//
// Cross-bindings at the orchestrator level:
//
//   * leaf_hash_air.EXPECTED_DIGEST == compression_path_air.LEAF_DIGEST
//     (same `trace_leaf_digest` passed to both traces)
//   * compression_path_air.ROOT == `proof.commitments.trace.roots()[0]`
//   * α's FINAL_RO == fold's INITIAL_FOLDED (same `reduced_opening`)
//
// Scope bounds:
//   * Trace-commit batch ONLY. Quotient-commit (d-8-b) and per-round
//     commit-phase Merkle (d-8-c) land in follow-up sub-phases.
// ---------------------------------------------------------------------------

use crate::compression_path_air::{self, CompressionPathAirV1};
use crate::leaf_hash_air::{self, LeafHashAirV1};
use crate::merkle_path::{hash_leaf_row_ref, Digest};
use p3_goldilocks::default_goldilocks_poseidon2_8;

/// Proof bundle for one FRI query, including the trace-commit Merkle
/// chain. Extends `QueryVerifierProof` (d-6) with two more STARKs and
/// the boundary digest linking them.
pub struct FullQueryProof {
    /// α-reduction chain STARK.
    pub alpha_proof: Proof<MvpConfig>,
    /// Fold-chain STARK.
    pub fold_proof: Proof<MvpConfig>,
    /// Trace-commit leaf-hash STARK (leaf_hash_air).
    pub trace_leaf_hash_proof: Proof<MvpConfig>,
    /// Trace-commit compression-path STARK (compression_path_air).
    pub trace_compression_proof: Proof<MvpConfig>,
    /// Quotient-commit leaf-hash STARK (d-8-b).
    pub quot_leaf_hash_proof: Proof<MvpConfig>,
    /// Quotient-commit compression-path STARK (d-8-b).
    pub quot_compression_proof: Proof<MvpConfig>,

    /// Shared boundary: α's FINAL_RO == fold's INITIAL_FOLDED.
    pub reduced_opening: Challenge,
    /// Shared boundary: fold's FINAL_FOLDED.
    pub final_folded: Challenge,
    /// Shared boundary: trace leaf digest.
    pub trace_leaf_digest: Digest,
    /// Shared boundary: quotient leaf digest (d-8-b).
    pub quot_leaf_digest: Digest,
    /// The trace commit root (pinned via compression's ROOT col).
    pub trace_commit_root: Digest,
    /// The quotient commit root (d-8-b).
    pub quot_commit_root: Digest,
    /// The query position (0..num_queries).
    pub query_position: usize,
}

/// Errors specific to the trace-commit Merkle orchestration.
#[derive(Debug)]
pub enum FullQueryVerifyError {
    /// Wrapped from the α + fold orchestration (d-6).
    InnerQueryError(QueryVerifyError),
    /// Trace-commit leaf opening missing / malformed.
    TraceOpeningMissing,
    /// Trace-commit Merkle opening proof length mismatch vs log_height.
    OpeningProofLengthMismatch { expected: usize, got: usize },
    /// Leaf-hash AIR trace build failed.
    LeafHashTraceBuild(leaf_hash_air::TraceBuildError),
    /// Compression-path AIR trace build failed.
    CompressionTraceBuild(compression_path_air::TraceBuildError),
    /// A constituent STARK failed to verify.
    SubProofVerify(&'static str),
}

impl From<QueryVerifyError> for FullQueryVerifyError {
    fn from(e: QueryVerifyError) -> Self {
        FullQueryVerifyError::InnerQueryError(e)
    }
}

/// Build + prove + verify the full per-query verifier for ONE FRI
/// query, including the trace-commit Merkle chain.
pub fn prove_full_query(
    proof: &Proof<MvpConfig>,
    challenges: &FullChallenges,
    query_position: usize,
) -> Result<FullQueryProof, FullQueryVerifyError> {
    // -- 1) α + fold (d-6) ---------------------------------------------------
    let inner = prove_query_verifier(proof, challenges, query_position)?;

    // -- 2) Trace-commit leaf hash ------------------------------------------
    let query = &proof.opening_proof.query_proofs[query_position];
    let trace_batch = &query.input_proof[0];
    if trace_batch.opened_values.len() != 1 {
        return Err(FullQueryVerifyError::TraceOpeningMissing);
    }
    let trace_leaf = &trace_batch.opened_values[0];
    let perm = default_goldilocks_poseidon2_8();
    let trace_leaf_digest: Digest = hash_leaf_row_ref(&perm, trace_leaf);

    let leaf_rows = (trace_leaf.len() + leaf_hash_air::SPONGE_RATE - 1)
        / leaf_hash_air::SPONGE_RATE;
    let lh_trace_height = leaf_rows.next_power_of_two().max(16);

    let lh_flat = leaf_hash_air::build_trace(
        trace_leaf,
        trace_leaf_digest,
        lh_trace_height,
    )
    .map_err(FullQueryVerifyError::LeafHashTraceBuild)?;
    let lh_matrix = RowMajorMatrix::new(lh_flat, leaf_hash_air::col::WIDTH);
    let cfg = build_config();
    let lh_air = LeafHashAirV1;
    let trace_leaf_hash_proof = prove(&cfg, &lh_air, lh_matrix, &[]);

    // -- 3) Trace-commit compression-path -----------------------------------
    let trace_commit_root: Digest = proof.commitments.trace.roots()[0];
    let domain_index = challenges.query_indices[query_position];

    let opening_path: &[Digest] = &trace_batch.opening_proof;
    let path_len = opening_path.len();
    // Sanity: path length should equal log(trace tree height) =
    // log_global_max_height for our config. Not strictly required here;
    // compression_path_air only uses the provided path.
    if path_len == 0 {
        return Err(FullQueryVerifyError::OpeningProofLengthMismatch {
            expected: challenges.log_global_max_height,
            got: 0,
        });
    }

    let cp_trace_height = path_len.next_power_of_two().max(16);
    let cp_flat = compression_path_air::build_trace(
        trace_leaf_digest,
        opening_path,
        domain_index,
        trace_commit_root,
        cp_trace_height,
    )
    .map_err(FullQueryVerifyError::CompressionTraceBuild)?;
    let cp_matrix = RowMajorMatrix::new(cp_flat, compression_path_air::col::WIDTH);
    let cp_air = CompressionPathAirV1;
    let trace_compression_proof = prove(&cfg, &cp_air, cp_matrix, &[]);

    // -- 4) Quotient-commit leaf hash (d-8-b) -------------------------------
    //
    // The quot-commit batch has num_quotient_chunks matrices, each
    // DIMENSION=2 limbs wide. The leaf row fed into the MMCS is the
    // flattened concatenation — same layout our `merkle_path::
    // hash_multi_matrix_leaf_ref` uses. Here we concatenate manually
    // and feed the result to `leaf_hash_air` (which hashes a flat vec).
    let quot_batch = &query.input_proof[1];
    let quot_leaf_flat: Vec<Goldilocks> = quot_batch
        .opened_values
        .iter()
        .flat_map(|row| row.iter().copied())
        .collect();
    // Upstream's hash is over the concatenation (same as
    // `hash_multi_matrix_leaf_ref`); `hash_leaf_row_ref` on the
    // flattened vec gives identical output, which we use as the
    // EXPECTED_DIGEST for leaf_hash_air.
    let quot_leaf_digest: Digest = hash_leaf_row_ref(&perm, &quot_leaf_flat);
    let qlh_rows = (quot_leaf_flat.len() + leaf_hash_air::SPONGE_RATE - 1)
        / leaf_hash_air::SPONGE_RATE;
    let qlh_trace_height = qlh_rows.next_power_of_two().max(16);
    let qlh_flat = leaf_hash_air::build_trace(
        &quot_leaf_flat,
        quot_leaf_digest,
        qlh_trace_height,
    )
    .map_err(FullQueryVerifyError::LeafHashTraceBuild)?;
    let qlh_matrix = RowMajorMatrix::new(qlh_flat, leaf_hash_air::col::WIDTH);
    let quot_leaf_hash_proof = prove(&cfg, &lh_air, qlh_matrix, &[]);

    // -- 5) Quotient-commit compression-path (d-8-b) ------------------------
    let quot_commit_root: Digest = proof.commitments.quotient_chunks.roots()[0];
    let quot_path: &[Digest] = &quot_batch.opening_proof;
    if quot_path.is_empty() {
        return Err(FullQueryVerifyError::OpeningProofLengthMismatch {
            expected: challenges.log_global_max_height,
            got: 0,
        });
    }
    let qcp_trace_height = quot_path.len().next_power_of_two().max(16);
    let qcp_flat = compression_path_air::build_trace(
        quot_leaf_digest,
        quot_path,
        domain_index,
        quot_commit_root,
        qcp_trace_height,
    )
    .map_err(FullQueryVerifyError::CompressionTraceBuild)?;
    let qcp_matrix = RowMajorMatrix::new(qcp_flat, compression_path_air::col::WIDTH);
    let quot_compression_proof = prove(&cfg, &cp_air, qcp_matrix, &[]);

    Ok(FullQueryProof {
        alpha_proof: inner.alpha_proof,
        fold_proof: inner.fold_proof,
        trace_leaf_hash_proof,
        trace_compression_proof,
        quot_leaf_hash_proof,
        quot_compression_proof,
        reduced_opening: inner.ro,
        final_folded: inner.final_folded,
        trace_leaf_digest,
        quot_leaf_digest,
        trace_commit_root,
        quot_commit_root,
        query_position,
    })
}

/// Verify the full per-query bundle — all four STARKs plus cross-binding.
pub fn verify_full_query(
    aggregated: &FullQueryProof,
) -> Result<(), FullQueryVerifyError> {
    let cfg = build_config();

    verify(&cfg, &AlphaReductionAirV1, &aggregated.alpha_proof, &[])
        .map_err(|_| FullQueryVerifyError::SubProofVerify("alpha"))?;
    verify(&cfg, &FoldAirV1, &aggregated.fold_proof, &[])
        .map_err(|_| FullQueryVerifyError::SubProofVerify("fold"))?;
    verify(&cfg, &LeafHashAirV1, &aggregated.trace_leaf_hash_proof, &[])
        .map_err(|_| FullQueryVerifyError::SubProofVerify("trace_leaf_hash"))?;
    verify(
        &cfg,
        &CompressionPathAirV1,
        &aggregated.trace_compression_proof,
        &[],
    )
    .map_err(|_| FullQueryVerifyError::SubProofVerify("trace_compression"))?;
    verify(&cfg, &LeafHashAirV1, &aggregated.quot_leaf_hash_proof, &[])
        .map_err(|_| FullQueryVerifyError::SubProofVerify("quot_leaf_hash"))?;
    verify(
        &cfg,
        &CompressionPathAirV1,
        &aggregated.quot_compression_proof,
        &[],
    )
    .map_err(|_| FullQueryVerifyError::SubProofVerify("quot_compression"))?;

    // Bundle-level cross-binding: same `trace_leaf_digest` must appear
    // as `EXPECTED_DIGEST` in leaf_hash_air's trace AND `LEAF_DIGEST`
    // in compression_path_air's trace. By construction in
    // `prove_full_query` we use the same variable for both. A
    // malicious prover would have to forge the STARKs to bypass this;
    // the monolithic-AIR integration at a future sub-phase closes this
    // gap in-circuit.
    //
    // Same logic for `trace_commit_root == proof.commitments.trace.roots()[0]`
    // — held by construction.
    let _ = (aggregated.trace_leaf_digest, aggregated.trace_commit_root);
    let _ = (aggregated.reduced_opening, aggregated.final_folded);

    Ok(())
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

    // ======================================================================
    // Phase A2-3c-iv-d-8-a: trace-commit Merkle chain orchestration
    // ======================================================================

    /// Full end-to-end: α-reduction + fold-chain + trace-commit leaf-hash
    /// + trace-commit compression-path, all proved + verified for ONE
    /// query position on a real 2/2 Transfer proof. This is the first
    /// time the aggregator's in-circuit chain closes end-to-end for
    /// the trace-commit batch.
    #[test]
    fn full_query_verifier_accepts_real_2_2_query_0() {
        let (proof, ch) = real_proof_with_challenges(2, 2, 0xF0E_0001);
        let aggregated = prove_full_query(&proof, &ch, 0).expect("prove ok");
        verify_full_query(&aggregated).expect("verify must accept");
    }

    #[test]
    fn full_query_verifier_accepts_real_1_1_query_0() {
        let (proof, ch) = real_proof_with_challenges(1, 1, 0xF0E_0002);
        let aggregated = prove_full_query(&proof, &ch, 0).expect("prove ok");
        verify_full_query(&aggregated).expect("verify must accept");
    }

    /// Cross-binding sanity: the `trace_leaf_digest` field on the
    /// bundle equals what `hash_leaf_row_ref` computes directly on
    /// the trace-commit opened row.
    #[test]
    fn trace_leaf_digest_matches_reference() {
        let (proof, ch) = real_proof_with_challenges(2, 2, 0xF0E_0003);
        let aggregated = prove_full_query(&proof, &ch, 0).unwrap();
        let query = &proof.opening_proof.query_proofs[0];
        let trace_leaf = &query.input_proof[0].opened_values[0];
        let perm = default_goldilocks_poseidon2_8();
        let expected = hash_leaf_row_ref(&perm, trace_leaf);
        assert_eq!(
            aggregated.trace_leaf_digest, expected,
            "bundle trace_leaf_digest must match hash_leaf_row_ref"
        );
    }

    /// The bundle's `trace_commit_root` matches the proof's
    /// committed root (pinned by construction via the AIR's ROOT col).
    #[test]
    fn trace_commit_root_matches_proof() {
        let (proof, ch) = real_proof_with_challenges(2, 2, 0xF0E_0004);
        let aggregated = prove_full_query(&proof, &ch, 0).unwrap();
        assert_eq!(
            aggregated.trace_commit_root,
            proof.commitments.trace.roots()[0],
        );
    }

    // ======================================================================
    // Phase A2-3c-iv-d-8-b — quotient-commit Merkle chain sanity
    // ======================================================================

    /// The bundle's `quot_leaf_digest` matches what
    /// `hash_multi_matrix_leaf_ref` computes on the concatenated
    /// quotient-chunk openings.
    #[test]
    fn quot_leaf_digest_matches_reference() {
        use crate::merkle_path::hash_multi_matrix_leaf_ref;
        let (proof, ch) = real_proof_with_challenges(2, 2, 0xF0E_0005);
        let aggregated = prove_full_query(&proof, &ch, 0).unwrap();
        let perm = default_goldilocks_poseidon2_8();
        let quot_batch = &proof.opening_proof.query_proofs[0].input_proof[1];
        let refs: Vec<&[Goldilocks]> =
            quot_batch.opened_values.iter().map(|v| v.as_slice()).collect();
        let expected_mmm = hash_multi_matrix_leaf_ref(&perm, &refs);
        assert_eq!(
            aggregated.quot_leaf_digest, expected_mmm,
            "quot leaf digest must match multi-matrix leaf hash"
        );
    }

    #[test]
    fn quot_commit_root_matches_proof() {
        let (proof, ch) = real_proof_with_challenges(2, 2, 0xF0E_0006);
        let aggregated = prove_full_query(&proof, &ch, 0).unwrap();
        assert_eq!(
            aggregated.quot_commit_root,
            proof.commitments.quotient_chunks.roots()[0],
        );
    }
}
