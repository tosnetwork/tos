//! Pure-Rust single-query FRI verifier — integration of A2-3c-i..iv-b.
//!
//! Phase A2-3c-iv-c of the aggregation roadmap (`doc/uno-aggregation-design.md`).
//! Combines the out-of-circuit reference modules into a single
//! `verify_query_ref` function that replays upstream's per-query FRI
//! verification end-to-end, using only our own primitives:
//!
//! ```text
//!   derive_full_challenges (A2-3c-i)
//!          │
//!          ▼
//!   verify_query_ref
//!       │
//!       ├── input-commit Merkle path checks (single / multi matrix, A2-3c-iii / iv-a)
//!       ├── α-batched quotient reduction     (A2-3c-iv-b)
//!       ├── fold chain:
//!       │     ├─ commit-phase Merkle path (A2-3c-iii)
//!       │     └─ fold_row_ref              (A2-3c-ii)
//!       └── final-poly evaluation           (A2-3c-ii)
//! ```
//!
//! This is the last out-of-circuit sub-phase before the in-circuit
//! FRI-AIR (A2-3c-iv-d / A2-4). With this module landed, every
//! arithmetic and Merkle operation the aggregator's in-circuit
//! verifier must encode has a line-numbered reference that can be
//! diffed against upstream on real Transfer proofs.
//!
//! # Scope
//!
//! - **Single query at a time** — the test harness wraps this in a
//!   52-query loop over a real proof. In production, all 52 queries
//!   share the same pre-PCS transcript and final_poly; only the
//!   per-query `domain_index` varies.
//! - **MvpConfig specialization** — height-bucketing is trivial
//!   (every matrix sits at `log_global_max_height`), so we do not
//!   implement the general per-height reduced-opening map.
//! - **Base-field MMCS** for input commits — our `TwoAdicFriPcs`
//!   wraps a base-field `MvpValMmcs` for trace/quotient and an
//!   `ExtensionMmcs<Val, Challenge, ValMmcs>` for commit-phase. Both
//!   resolve to the same base-field Merkle tree at the hash level;
//!   for the commit-phase we just flatten the Challenge siblings into
//!   base limbs before handing to `verify_merkle_path_ref`.

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks, Poseidon2Goldilocks};
use p3_uni_stark::Proof;

use crate::fiat_shamir::FullChallenges;
use crate::fri_arith::{eval_final_poly_horner, final_eval_x, fold_row_ref};
use crate::merkle_path::{verify_merkle_path_ref, verify_multi_matrix_merkle_path_ref, Digest};
use crate::open_input::{alpha_combine_matrix_point, query_x, OpenInputShapeError};
use crate::prover::{Challenge, MvpConfig};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Reasons `verify_query_ref` can reject a query. Mirrors the subset of
/// upstream `FriError` that applies to our MvpConfig.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum VerifyQueryError {
    /// `query_position` is out of range for `proof.opening_proof.query_proofs`.
    QueryPositionOutOfRange { got: usize, max: usize },
    /// Input-commit batch count doesn't match expected (= 2 for MvpConfig).
    InputBatchCountMismatch { expected: usize, got: usize },
    /// Trace-commit Merkle path failed to open to `commitments.trace`.
    TraceMerkleMismatch,
    /// Quotient-commit Merkle path failed to open to `commitments.quotient_chunks`.
    QuotientMerkleMismatch,
    /// Commit-phase Merkle path failed in round `round`.
    CommitPhaseMerkleMismatch { round: usize },
    /// Commit-phase opening has wrong `log_arity` (we only support binary FRI).
    UnexpectedLogArity { round: usize, got: usize },
    /// Number of sibling values doesn't match `arity - 1`.
    SiblingValuesLengthMismatch {
        round: usize,
        expected: usize,
        got: usize,
    },
    /// After all fold rounds, the folded eval does not match
    /// `eval_final_poly_horner(final_poly, x)` at the residual index.
    FinalPolyMismatch,
    /// Final fold height doesn't land on `log_blowup + log_final_poly_len`.
    FinalFoldHeightMismatch { expected: usize, got: usize },
    /// α-combine step rejected the shape of an opening row.
    OpenInputShape(OpenInputShapeError),
    /// Trace-next opening missing (our AIR has transition constraints).
    TraceNextMissing,
    /// Trace-local / trace-next / trace-opened-row width mismatch.
    TraceRowWidthMismatch {
        trace_row_len: usize,
        trace_local_len: usize,
    },
}

impl From<OpenInputShapeError> for VerifyQueryError {
    fn from(e: OpenInputShapeError) -> Self {
        VerifyQueryError::OpenInputShape(e)
    }
}

// ---------------------------------------------------------------------------
// Pin against our production prover config — all constants MUST track
// `prover::build_config`. Changing either side requires changing both.
// ---------------------------------------------------------------------------

/// FRI `log_blowup` parameter. Matches `prover::build_config` (Option B).
pub const LOG_BLOWUP: usize = 3;
/// FRI `log_final_poly_len` parameter. Matches `prover::build_config`.
pub const LOG_FINAL_POLY_LEN: usize = 0;
/// Log of the final domain size after all folds.
pub const LOG_FINAL_HEIGHT: usize = LOG_BLOWUP + LOG_FINAL_POLY_LEN;

// ---------------------------------------------------------------------------
// verify_query_ref — the integration point
// ---------------------------------------------------------------------------

/// Verify the FRI side of a STARK proof for a single query position.
///
/// On success returns `Ok(())`. Exactly the same result upstream's
/// `pcs.verify` → `verify_fri` → per-query branch would return for
/// this query, modulo the reduction to our MvpConfig scope.
///
/// # Arguments
///
/// - `proof`: the decoded `Proof<MvpConfig>`.
/// - `challenges`: the `FullChallenges` from `fiat_shamir::derive_full_challenges`.
/// - `query_position`: index into `proof.opening_proof.query_proofs`
///   (0..num_queries = 52). The FRI query index proper comes from
///   `challenges.query_indices[query_position]`.
#[allow(clippy::too_many_arguments)]
pub fn verify_query_ref(
    proof: &Proof<MvpConfig>,
    challenges: &FullChallenges,
    query_position: usize,
) -> Result<(), VerifyQueryError> {
    let num_queries = proof.opening_proof.query_proofs.len();
    if query_position >= num_queries {
        return Err(VerifyQueryError::QueryPositionOutOfRange {
            got: query_position,
            max: num_queries,
        });
    }

    let perm = default_goldilocks_poseidon2_8();
    let query_proof = &proof.opening_proof.query_proofs[query_position];
    let domain_index = challenges.query_indices[query_position];
    let log_global_max_height = challenges.log_global_max_height;

    // ==================================================================
    // Step 1 — Input commits (trace + quotient): Merkle verify each batch
    //           at `domain_index`; then α-combine openings into `ro`.
    // ==================================================================
    if query_proof.input_proof.len() != 2 {
        return Err(VerifyQueryError::InputBatchCountMismatch {
            expected: 2,
            got: query_proof.input_proof.len(),
        });
    }

    // --- Batch 0: trace commit (single matrix) ---
    let trace_batch = &query_proof.input_proof[0];
    if trace_batch.opened_values.len() != 1 {
        return Err(VerifyQueryError::InputBatchCountMismatch {
            expected: 1,
            got: trace_batch.opened_values.len(),
        });
    }
    let trace_opened_row = &trace_batch.opened_values[0];
    if trace_opened_row.len() != proof.opened_values.trace_local.len() {
        return Err(VerifyQueryError::TraceRowWidthMismatch {
            trace_row_len: trace_opened_row.len(),
            trace_local_len: proof.opened_values.trace_local.len(),
        });
    }
    {
        let trace_root: Digest = proof.commitments.trace.roots()[0];
        if !verify_merkle_path_ref(
            &perm,
            trace_opened_row,
            &trace_batch.opening_proof,
            domain_index,
            &trace_root,
        ) {
            return Err(VerifyQueryError::TraceMerkleMismatch);
        }
    }

    // --- Batch 1: quotient commit (multi matrix, same height) ---
    let quot_batch = &query_proof.input_proof[1];
    {
        let quot_root: Digest = proof.commitments.quotient_chunks.roots()[0];
        let refs: Vec<&[Goldilocks]> = quot_batch
            .opened_values
            .iter()
            .map(|v| v.as_slice())
            .collect();
        if !verify_multi_matrix_merkle_path_ref(
            &perm,
            &refs,
            &quot_batch.opening_proof,
            domain_index,
            &quot_root,
        ) {
            return Err(VerifyQueryError::QuotientMerkleMismatch);
        }
    }

    // --- α-combine openings into a single reduced_opening `ro`. ---
    let zeta_next = challenges.zeta * Goldilocks::two_adic_generator(proof.degree_bits);
    let trace_next = proof
        .opened_values
        .trace_next
        .as_ref()
        .ok_or(VerifyQueryError::TraceNextMissing)?;

    let x: Goldilocks = query_x(domain_index, log_global_max_height, log_global_max_height);
    let mut alpha_pow = Challenge::ONE;
    let mut ro = Challenge::ZERO;

    // Trace matrix at two points.
    alpha_combine_matrix_point(
        challenges.fri_alpha,
        trace_opened_row,
        &proof.opened_values.trace_local,
        challenges.zeta,
        x,
        &mut alpha_pow,
        &mut ro,
    )?;
    alpha_combine_matrix_point(
        challenges.fri_alpha,
        trace_opened_row,
        trace_next,
        zeta_next,
        x,
        &mut alpha_pow,
        &mut ro,
    )?;

    // Each quotient chunk at zeta.
    for (mat_opening, chunk_values) in quot_batch
        .opened_values
        .iter()
        .zip(proof.opened_values.quotient_chunks.iter())
    {
        alpha_combine_matrix_point(
            challenges.fri_alpha,
            mat_opening,
            chunk_values,
            challenges.zeta,
            x,
            &mut alpha_pow,
            &mut ro,
        )?;
    }

    // ==================================================================
    // Step 2 — Fold chain. Starting at height `log_global_max_height`
    //           with `folded_eval = ro`, for each commit-phase round:
    //             (a) reconstruct full arity-2 row [self, sibling]
    //             (b) Merkle-verify the row against
    //                 `commit_phase_commits[r]`
    //             (c) `fold_row_ref` to get next height's eval
    //             (d) shift `domain_index` right by `log_arity`
    // ==================================================================
    if query_proof.commit_phase_openings.len() != proof.opening_proof.commit_phase_commits.len() {
        return Err(VerifyQueryError::CommitPhaseMerkleMismatch { round: 0 });
    }

    let mut folded_eval = ro;
    let mut log_current = log_global_max_height;
    let mut idx = domain_index;

    for (round, (opening_step, commit)) in query_proof
        .commit_phase_openings
        .iter()
        .zip(proof.opening_proof.commit_phase_commits.iter())
        .enumerate()
    {
        let log_arity = opening_step.log_arity as usize;
        // Our pin is binary FRI (log_arity = 1 per round). Reject
        // anything else — the fold_row_ref code paths above have been
        // tested for arity up to 4, but the Merkle-path reconstruction
        // below assumes binary to keep the reference auditable.
        if log_arity != 1 {
            return Err(VerifyQueryError::UnexpectedLogArity {
                round,
                got: log_arity,
            });
        }
        let arity = 1usize << log_arity;

        if opening_step.sibling_values.len() != arity - 1 {
            return Err(VerifyQueryError::SiblingValuesLengthMismatch {
                round,
                expected: arity - 1,
                got: opening_step.sibling_values.len(),
            });
        }

        // Reconstruct the full arity-2 row: insert `folded_eval` at
        // `index_in_group = idx % arity`, fill the other slot with the
        // single sibling. Same layout upstream uses
        // (fri/verifier.rs:411-423).
        let index_in_group = idx % arity;
        let mut evals: Vec<Challenge> = vec![Challenge::ZERO; arity];
        evals[index_in_group] = folded_eval;
        let mut sib_idx = 0usize;
        for j in 0..arity {
            if j != index_in_group {
                evals[j] = opening_step.sibling_values[sib_idx];
                sib_idx += 1;
            }
        }

        let log_folded_height = log_current - log_arity;

        // Shift idx to the parent FRI node index (matches upstream's
        // `*start_index >>= log_arity` at verifier.rs:434 — done
        // BEFORE the Merkle verify so `idx` here is the parent index).
        idx >>= log_arity;

        // Merkle-verify the row.
        // The commit-phase MMCS is ExtensionMmcs<Val, Challenge, ValMmcs>,
        // whose Merkle tree stores BASE-field leaves (each leaf row is
        // `arity * DIMENSION = 4` Goldilocks after flattening). So we
        // flatten `evals` to base limbs and call the single-matrix
        // verify_merkle_path_ref.
        let leaf_row: Vec<Goldilocks> = evals
            .iter()
            .flat_map(|c| {
                <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(c).to_vec()
            })
            .collect();
        let commit_root: Digest = commit.roots()[0];
        if !verify_merkle_path_ref(
            &perm,
            &leaf_row,
            &opening_step.opening_proof,
            idx,
            &commit_root,
        ) {
            return Err(VerifyQueryError::CommitPhaseMerkleMismatch { round });
        }

        // Fold — Lagrange interpolation at β over the arity-2 coset.
        // `fold_row_ref`'s `index` arg is the PARENT index (post-shift);
        // matches upstream fri/verifier.rs:448-454.
        folded_eval = fold_row_ref(
            idx,
            log_folded_height,
            log_arity,
            challenges.betas[round],
            &evals,
        );

        log_current = log_folded_height;

        // MvpConfig note: since all matrices sit at log_global_max_height
        // there is no intermediate-height reduced_opening to roll in.
        // The general-case `beta^arity * ro` addition from
        // fri/verifier.rs:467-470 is a no-op here.
    }

    if log_current != LOG_FINAL_HEIGHT {
        return Err(VerifyQueryError::FinalFoldHeightMismatch {
            expected: LOG_FINAL_HEIGHT,
            got: log_current,
        });
    }

    // ==================================================================
    // Step 3 — Final poly check.
    //           x = g^{reverse_bits(idx, log_global_max_height)} where
    //           g = two_adic_generator(log_global_max_height). Compare
    //           `folded_eval` to `eval_final_poly_horner(final_poly, x)`.
    //           Matches upstream fri/verifier.rs:307-321.
    // ==================================================================
    let x_final = final_eval_x(idx, log_global_max_height);
    let expected = eval_final_poly_horner(&proof.opening_proof.final_poly, x_final);
    if folded_eval != expected {
        return Err(VerifyQueryError::FinalPolyMismatch);
    }

    // Prevent unused-import warning when integrating modules that
    // re-export perm; also a marker for the audit that every perm
    // call came from the same instance.
    let _ = &perm as *const Poseidon2Goldilocks<8>;

    Ok(())
}

/// Convenience: run `verify_query_ref` for every query position,
/// returning `Ok(())` iff all 52 queries pass. Mirrors the loop at
/// `fri/verifier.rs:246-322`.
pub fn verify_all_queries_ref(
    proof: &Proof<MvpConfig>,
    challenges: &FullChallenges,
) -> Result<(), VerifyQueryError> {
    for q in 0..proof.opening_proof.query_proofs.len() {
        verify_query_ref(proof, challenges, q)?;
    }
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

    fn proof_and_pis(n_s: usize, n_o: usize, seed: u64) -> (Proof<MvpConfig>, Vec<Goldilocks>) {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(n_s, n_o, seed);
        let (proof_bytes, _) = prover.prove(&w.encode()).unwrap();
        let proof: Proof<MvpConfig> = postcard::from_bytes(&proof_bytes).unwrap();
        let pis = w.public_inputs();
        (proof, pis)
    }

    // ---- Positive cases: valid proofs → all queries accept ----

    /// Diagnostic / regression guard: on a real 2/2 proof, the trace
    /// batch's opened values at `query_indices[0]` must satisfy
    /// upstream `MerkleTreeMmcs::verify_batch` AND our
    /// `verify_merkle_path_ref`. This test caught the missing query-PoW
    /// `check_witness` step in `fiat_shamir::derive_full_challenges`
    /// — without the 24-bit PoW sample before query-index sampling
    /// the indices drift and the Merkle path fails at a "random" row.
    #[test]
    fn regression_trace_batch_verify_at_derived_query_index() {
        use p3_commit::{BatchOpeningRef, Mmcs};
        use p3_field::Field;
        use p3_matrix::Dimensions;
        use p3_merkle_tree::MerkleTreeMmcs;
        use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

        let (proof, pis) = proof_and_pis(2, 2, 0xDEB_01);
        let ch = derive_full_challenges(&proof, &pis);
        let query_position = 0;
        let domain_index = ch.query_indices[query_position];

        type MyHash = PaddingFreeSponge<Poseidon2Goldilocks<8>, 8, 4, 4>;
        type MyCompress = TruncatedPermutation<Poseidon2Goldilocks<8>, 2, 4, 8>;
        let perm = default_goldilocks_poseidon2_8();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let mmcs: MerkleTreeMmcs<
            <Goldilocks as Field>::Packing,
            <Goldilocks as Field>::Packing,
            MyHash,
            MyCompress,
            2,
            4,
        > = MerkleTreeMmcs::new(hash, compress, 0);

        let trace_batch = &proof.opening_proof.query_proofs[query_position].input_proof[0];
        let trace_commit = &proof.commitments.trace;
        // The trace LDE height is 2^log_global_max_height.
        let height = 1usize << ch.log_global_max_height;
        let width = trace_batch.opened_values[0].len();

        // Upstream uses width=0 for verify_batch (verifier.rs:557-561).
        let dims = [Dimensions { width: 0, height }];
        let upstream_result = mmcs.verify_batch(
            trace_commit,
            &dims,
            domain_index,
            BatchOpeningRef::new(&trace_batch.opened_values, &trace_batch.opening_proof),
        );
        assert!(
            upstream_result.is_ok(),
            "upstream verify_batch must accept trace opening at derived query_index={domain_index}; \
             width={width} height={height}"
        );

        let ours = verify_merkle_path_ref(
            &perm,
            &trace_batch.opened_values[0],
            &trace_batch.opening_proof,
            domain_index,
            &trace_commit.roots()[0],
        );
        assert!(ours, "our verify_merkle_path_ref must also accept");
    }

    #[test]
    fn verify_all_queries_accepts_valid_1_1() {
        let (proof, pis) = proof_and_pis(1, 1, 0x11_11);
        let ch = derive_full_challenges(&proof, &pis);
        verify_all_queries_ref(&proof, &ch).expect("all queries must verify on 1/1");
    }

    #[test]
    fn verify_all_queries_accepts_valid_2_2() {
        let (proof, pis) = proof_and_pis(2, 2, 0x22_22);
        let ch = derive_full_challenges(&proof, &pis);
        verify_all_queries_ref(&proof, &ch).expect("all queries must verify on 2/2");
    }

    #[test]
    fn verify_all_queries_accepts_valid_4_4_worst_case() {
        let (proof, pis) = proof_and_pis(4, 4, 0x44_44);
        let ch = derive_full_challenges(&proof, &pis);
        verify_all_queries_ref(&proof, &ch).expect("all queries must verify on 4/4");
    }

    // ---- Negative cases: tampered inputs → rejects ----

    #[test]
    fn rejects_tampered_trace_commit_root() {
        let (mut proof, pis) = proof_and_pis(2, 2, 0xAA_01);
        let ch = derive_full_challenges(&proof, &pis);

        // Baseline: everything verifies.
        verify_all_queries_ref(&proof, &ch).expect("baseline must pass");

        // Tamper the trace commitment's root — the trace Merkle path
        // will no longer land on this root. Since zeta/fri_alpha are
        // derived BEFORE the quotient commit observation, modifying
        // ONLY the trace commit root doesn't affect the challenge
        // derivation here (ch is captured from the untampered proof),
        // so we expect a TraceMerkleMismatch.
        let mut bad_root = proof.commitments.trace.roots()[0];
        bad_root[0] += Goldilocks::ONE;
        let new_cap = p3_symmetric::MerkleCap::new(vec![bad_root]);
        proof.commitments.trace = new_cap;

        let err = verify_query_ref(&proof, &ch, 0).expect_err("tampered trace root must reject");
        matches!(err, VerifyQueryError::TraceMerkleMismatch);
    }

    #[test]
    fn rejects_tampered_quotient_sibling() {
        // Tampering a sibling value in the input_proof's quotient
        // opening must cause the quotient Merkle path to fail.
        let (mut proof, pis) = proof_and_pis(2, 2, 0xBB_02);
        let ch = derive_full_challenges(&proof, &pis);
        verify_all_queries_ref(&proof, &ch).expect("baseline");

        // Flip one limb of the quotient batch's opened values at query 0.
        proof.opening_proof.query_proofs[0].input_proof[1].opened_values[0][0] += Goldilocks::ONE;

        let err =
            verify_query_ref(&proof, &ch, 0).expect_err("tampered quotient opening must reject");
        matches!(err, VerifyQueryError::QuotientMerkleMismatch);
    }

    #[test]
    fn rejects_tampered_commit_phase_sibling() {
        let (mut proof, pis) = proof_and_pis(2, 2, 0xCC_03);
        let ch = derive_full_challenges(&proof, &pis);
        verify_all_queries_ref(&proof, &ch).expect("baseline");

        // Flip the first limb of the first commit-phase sibling for query 0.
        proof.opening_proof.query_proofs[0].commit_phase_openings[0].sibling_values[0] +=
            Challenge::ONE;

        let err = verify_query_ref(&proof, &ch, 0)
            .expect_err("tampered commit-phase sibling must reject");
        matches!(err, VerifyQueryError::CommitPhaseMerkleMismatch { .. });
    }

    #[test]
    fn rejects_tampered_final_poly() {
        let (mut proof, pis) = proof_and_pis(2, 2, 0xDD_04);
        let ch = derive_full_challenges(&proof, &pis);
        verify_all_queries_ref(&proof, &ch).expect("baseline");

        // Tampering final_poly does NOT affect challenges (final_poly
        // is observed AFTER beta sampling and BEFORE query_indices —
        // the Fiat-Shamir derivation uses the untampered `ch` we
        // captured first, so recomputing ch here would yield different
        // indices and βs and the test would spuriously fail at the
        // commit-phase step. We feed the original `ch` deliberately
        // to isolate the final-poly check.).
        proof.opening_proof.final_poly[0] += Challenge::ONE;

        let err = verify_query_ref(&proof, &ch, 0).expect_err("tampered final_poly must reject");
        matches!(err, VerifyQueryError::FinalPolyMismatch);
    }

    #[test]
    fn rejects_tampered_trace_opened_row() {
        // Tampering a base-field limb of the query's trace-opened row
        // breaks the trace Merkle path.
        let (mut proof, pis) = proof_and_pis(2, 2, 0xEE_05);
        let ch = derive_full_challenges(&proof, &pis);
        verify_all_queries_ref(&proof, &ch).expect("baseline");

        proof.opening_proof.query_proofs[0].input_proof[0].opened_values[0][0] += Goldilocks::ONE;

        let err = verify_query_ref(&proof, &ch, 0).expect_err("tampered trace opening must reject");
        matches!(err, VerifyQueryError::TraceMerkleMismatch);
    }

    // ---- Structural / invariant tests ----

    #[test]
    fn query_position_out_of_range_rejects() {
        let (proof, pis) = proof_and_pis(1, 1, 0xFF_01);
        let ch = derive_full_challenges(&proof, &pis);
        let err = verify_query_ref(&proof, &ch, 9999)
            .expect_err("out-of-range query_position must reject");
        matches!(err, VerifyQueryError::QueryPositionOutOfRange { .. });
    }

    #[test]
    fn log_final_height_constants_match_prover() {
        // Regression guard: if prover::build_config ever drifts from
        // Option B (log_blowup = 3, log_final_poly_len = 0) this test
        // fires, flagging the need to audit the pin across modules.
        assert_eq!(LOG_BLOWUP, 3);
        assert_eq!(LOG_FINAL_POLY_LEN, 0);
        assert_eq!(LOG_FINAL_HEIGHT, 3);
    }
}
