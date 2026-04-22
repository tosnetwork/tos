//! FRI input-opening — α-batched quotient reduction.
//!
//! Phase A2-3c-iv-b of the aggregation roadmap (`doc/uno-aggregation-design.md`).
//! Implements the arithmetic half of upstream
//! `p3_fri::verifier::open_input` (`fri/src/verifier.rs:513-650`): given
//! a query index, the opened polynomial values at the query-domain
//! point `x`, and the claimed openings at the out-of-domain points `z`
//! (= zeta, zeta_next), combine them into a single reduced opening
//! ```text
//!   RO = Σ α^k · (p_k(z) − p_k(x)) / (z − x)
//! ```
//! across every (matrix, point) pair at the same height. This is what
//! feeds into the FRI fold chain as the `reduced_openings` sequence
//! — one entry per distinct height.
//!
//! # Scope
//!
//! This module covers the **arithmetic** portion of `open_input`. The
//! Merkle-batch-verification step (`input_mmcs.verify_batch(...)`
//! immediately preceding the arithmetic) is handled by
//! `merkle_path::verify_multi_matrix_merkle_path_ref` (A2-3c-iv-a) —
//! when the full FRI verifier (A2-3c-iv-c) is wired together, both
//! live inside the same query-loop iteration.
//!
//! # Specialization to MvpConfig
//!
//! For our production config:
//!   * `is_zk = 0` ⇒ every batch matrix has height `1 << (degree_bits
//!     + log_blowup)` = `log_global_max_height`.
//!   * `commitments_with_opening_points` has length 2:
//!       - trace batch: 1 matrix at `trace_domain`, opened at
//!         (zeta, trace_local) and (zeta_next, trace_next).
//!       - quotient batch: `num_quotient_chunks` matrices each at
//!         their randomized-chunk domain, each opened at
//!         (zeta, chunk_values).
//!
//! All matrices share the same `log_height`, so every query emits a
//! single `(log_height, reduced_opening)` entry — not the general
//! per-height map that upstream builds.
//!
//! # Constraint-system view
//!
//! The in-circuit FRI-AIR will encode each α-combine update as:
//!   1. one extension-field inverse (`quotient = (z − x)^{-1}`)
//!   2. one multiply-accumulate per opened polynomial value
//!      (`ro += alpha_pow · (p_at_z − p_at_x) · quotient`)
//!   3. one α-power advance per opened value (`alpha_pow *= alpha`)
//! Having a line-numbered reference locked against upstream lets the
//! AIR encoder diff constraint-by-constraint during A2-3c-iv-c.

use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_util::reverse_bits_len;

use crate::prover::{Challenge, MvpConfig};
use p3_uni_stark::Proof;

// ---------------------------------------------------------------------------
// Primitive 1: query_x — the base-field point an opened matrix is at
// ---------------------------------------------------------------------------

/// Compute the query-domain base-field point `x` at which a matrix of
/// log-height `log_height` is opened for a given top-level `index`.
/// Line-matches upstream `fri/src/verifier.rs:596-605`.
///
/// Formula:
///   bits_reduced = log_global_max_height − log_height
///   k = reverse_bits(index >> bits_reduced, log_height)
///   x = GENERATOR · g^k,  where g = two_adic_generator(log_height).
///
/// `GENERATOR` is the coset shift — for Goldilocks it is `7`. It lifts
/// the query domain off the subgroup of roots of unity so that `z` (an
/// out-of-domain extension point) cannot accidentally coincide with
/// `x`.
pub fn query_x(index: usize, log_height: usize, log_global_max_height: usize) -> Goldilocks {
    assert!(
        log_height <= log_global_max_height,
        "log_height {log_height} > log_global_max_height {log_global_max_height}"
    );
    let bits_reduced = log_global_max_height - log_height;
    let reduced_index = index >> bits_reduced;
    let k = reverse_bits_len(reduced_index, log_height);
    let g = Goldilocks::two_adic_generator(log_height);
    Goldilocks::GENERATOR * g.exp_u64(k as u64)
}

// ---------------------------------------------------------------------------
// Primitive 2: alpha_combine_matrix_point — per-point α-batched update
// ---------------------------------------------------------------------------

/// Update `(alpha_pow, ro)` by folding one `(z, ps_at_z)` opening of a
/// single matrix into the running reduced opening.
///
/// Line-matches upstream `fri/src/verifier.rs:613-631`. For each opened
/// polynomial value `p_k` at the matrix: consume its value-at-x and
/// value-at-z, accumulate `α^k · (p_k(z) − p_k(x)) / (z − x)` into
/// `ro`, and advance `alpha_pow`.
///
/// Returns `Err(BadShape)` if `mat_opening.len() != ps_at_z.len()` —
/// the per-matrix opening must have the same width as the claimed
/// evaluation vector.
pub fn alpha_combine_matrix_point(
    alpha: Challenge,
    mat_opening: &[Goldilocks],
    ps_at_z: &[Challenge],
    z: Challenge,
    x: Goldilocks,
    alpha_pow: &mut Challenge,
    ro: &mut Challenge,
) -> Result<(), OpenInputShapeError> {
    if mat_opening.len() != ps_at_z.len() {
        return Err(OpenInputShapeError::PointValueLengthMismatch {
            mat_opening_len: mat_opening.len(),
            ps_at_z_len: ps_at_z.len(),
        });
    }
    // `(z − x)` is an extension element; `x` is in the base field,
    // `z` in the extension. Extension − base is supported by
    // `ExtensionField<Val>`.
    let denom = z - x;
    let quotient = denom
        .try_inverse()
        .expect("z != x with overwhelming probability — zeta is sampled off the query domain");
    for (&p_at_x, &p_at_z) in mat_opening.iter().zip(ps_at_z.iter()) {
        // p_at_x is base-field (an opened matrix row value), p_at_z
        // is extension (the claimed out-of-domain evaluation).
        *ro += *alpha_pow * (p_at_z - p_at_x) * quotient;
        *alpha_pow *= alpha;
    }
    Ok(())
}

/// Shape mismatch between a matrix's opened row and the claimed point
/// evaluation vector.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum OpenInputShapeError {
    /// Matrix opening width doesn't match the length of the claimed
    /// point-evaluation vector.
    PointValueLengthMismatch {
        mat_opening_len: usize,
        ps_at_z_len: usize,
    },
}

// ---------------------------------------------------------------------------
// Composite: compute_reduced_openings_for_query — MvpConfig specialization
// ---------------------------------------------------------------------------

/// Per-query reduced opening, paired with the log-height it sits at.
/// For our MvpConfig every query produces a single entry (all matrices
/// share the same height). For the fully-general FRI verifier an entry
/// exists per distinct height, sorted descending.
#[derive(Debug, Clone)]
pub struct ReducedOpening {
    pub log_height: usize,
    pub value: Challenge,
}

/// Compute the reduced-opening contribution of a single query in the
/// MvpConfig setting. Mirrors upstream `open_input` minus the Merkle
/// batch-verification step.
///
/// # Arguments
/// - `proof`: the STARK proof whose opened values define the per-query
///   openings-at-x.
/// - `zeta`: the out-of-domain evaluation point (from A2-3a Fiat-Shamir).
/// - `zeta_next`: `zeta · g` where `g = two_adic_generator(degree_bits)`
///   — the "next point" on the trace domain.
/// - `fri_alpha`: the batch-combining α challenge (from A2-3c-i).
/// - `log_global_max_height`: from the full challenges (also equals
///   `degree_bits + log_blowup` for our config).
/// - `query_position`: index into `proof.opening_proof.query_proofs`
///   (0..num_queries = 52) — NOT the sampled domain index.
/// - `domain_index`: the Fiat-Shamir-sampled query index from
///   `FullChallenges::query_indices[query_position]`. Drives the
///   query-domain point `x`.
///
/// # Returns
///
/// A single-element `ReducedOpening` at `log_height = log_global_max_height`.
/// All (trace_local at zeta, trace_next at zeta_next, each
/// quotient chunk at zeta) point/matrix contributions are α-combined
/// into `value`.
pub fn compute_reduced_openings_for_query(
    proof: &Proof<MvpConfig>,
    zeta: Challenge,
    zeta_next: Challenge,
    fri_alpha: Challenge,
    log_global_max_height: usize,
    query_position: usize,
    domain_index: usize,
) -> Result<ReducedOpening, OpenInputShapeError> {
    // Every matrix (trace + all quotient chunks) sits at the same
    // log_height in our config — there is no per-height bucketing.
    let log_height = log_global_max_height;
    let x: Goldilocks = query_x(domain_index, log_height, log_global_max_height);

    let mut alpha_pow = Challenge::ONE;
    let mut ro = Challenge::ZERO;

    // Trace batch input_proof (one BatchOpening): the input proof
    // carries `opened_values_at_x` — in our config exactly one matrix
    // (the trace) whose opened row has `air_width` base-field values
    // (extension-flattened).
    let input_proofs = &proof.opening_proof.query_proofs[query_position].input_proof;
    if input_proofs.len() != 2 {
        return Err(OpenInputShapeError::PointValueLengthMismatch {
            mat_opening_len: input_proofs.len(),
            ps_at_z_len: 2,
        });
    }

    // -----------------------------------------------------------------
    // Batch 0 — trace commitment: 1 matrix, opened at two points.
    //
    // mat_opening: the base-field row of the trace matrix at index
    //              `query_index`. Length = air_width (the trace's
    //              column count).
    // points:      [(zeta,      trace_local),
    //               (zeta_next, trace_next)]
    //
    // The opened values for the claimed evaluations are stored as
    // Challenge extension elements (air_width entries each). For the
    // α-combine we pass them straight through; `alpha_combine_matrix_point`
    // handles Challenge - base_field subtraction.
    // -----------------------------------------------------------------
    let trace_batch = &input_proofs[0];
    if trace_batch.opened_values.len() != 1 {
        return Err(OpenInputShapeError::PointValueLengthMismatch {
            mat_opening_len: trace_batch.opened_values.len(),
            ps_at_z_len: 1,
        });
    }
    let trace_mat_opening = &trace_batch.opened_values[0];

    let trace_local = &proof.opened_values.trace_local;
    let trace_next = proof
        .opened_values
        .trace_next
        .as_ref()
        .expect("MvpTransferAir has transition constraints ⇒ trace_next present");
    if trace_mat_opening.len() != trace_local.len() || trace_mat_opening.len() != trace_next.len() {
        return Err(OpenInputShapeError::PointValueLengthMismatch {
            mat_opening_len: trace_mat_opening.len(),
            ps_at_z_len: trace_local.len(),
        });
    }

    alpha_combine_matrix_point(
        fri_alpha,
        trace_mat_opening,
        trace_local,
        zeta,
        x,
        &mut alpha_pow,
        &mut ro,
    )?;
    alpha_combine_matrix_point(
        fri_alpha,
        trace_mat_opening,
        trace_next,
        zeta_next,
        x,
        &mut alpha_pow,
        &mut ro,
    )?;

    // -----------------------------------------------------------------
    // Batch 1 — quotient commitment: `num_quotient_chunks` matrices,
    //           each opened at a single point (zeta).
    //
    // For each chunk, mat_opening is a DIMENSION (= 2) × 1 = 2 base-
    // field row (extension-flattened from the row-width-1 matrix), and
    // ps_at_z is the 2-element quotient_chunks[i] from opened_values.
    // -----------------------------------------------------------------
    let quot_batch = &input_proofs[1];
    if quot_batch.opened_values.len() != proof.opened_values.quotient_chunks.len() {
        return Err(OpenInputShapeError::PointValueLengthMismatch {
            mat_opening_len: quot_batch.opened_values.len(),
            ps_at_z_len: proof.opened_values.quotient_chunks.len(),
        });
    }
    // Upstream `flatten_to_base` decomposes the quotient polynomial
    // evaluation vector (Vec<Challenge>) into DIMENSION=2 base-field
    // COLUMNS. `split_evals` then keeps width=DIMENSION per chunk matrix.
    // Each base column is an INDEPENDENT Val-valued polynomial over the
    // chunk's domain: evaluating at the query index gives 1 Goldilocks
    // per column (mat_opening[j] at row_idx), and evaluating at zeta
    // gives 1 Challenge per column (chunk_values[j]).
    //
    // So every (chunk, column) pair contributes one α-term:
    //   ro += alpha_pow · (chunk_values[j] − mat_opening[j]) / (zeta − x)
    //   alpha_pow *= α
    // `alpha_combine_matrix_point` handles this directly for the whole
    // column vector.
    for (mat_opening, chunk_values) in quot_batch
        .opened_values
        .iter()
        .zip(proof.opened_values.quotient_chunks.iter())
    {
        alpha_combine_matrix_point(
            fri_alpha,
            mat_opening,
            chunk_values,
            zeta,
            x,
            &mut alpha_pow,
            &mut ro,
        )?;
    }

    Ok(ReducedOpening {
        log_height,
        value: ro,
    })
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
    use p3_field::BasedVectorSpace;

    fn ch(a: u64, b: u64) -> Challenge {
        Challenge::from_basis_coefficients_fn(|i| {
            if i == 0 {
                Goldilocks::new(a)
            } else {
                Goldilocks::new(b)
            }
        })
    }

    // ---- query_x primitive ----

    #[test]
    fn query_x_matches_upstream_formula() {
        // Brute-force: for a range of indices and heights, compute x
        // via our function and via the literal formula from
        // fri/src/verifier.rs:604.
        for log_global in [3usize, 5, 10, 16] {
            for index in [
                0usize,
                1,
                2,
                7,
                (1 << log_global) - 1,
                1 << (log_global - 1),
            ] {
                for log_height in 1..=log_global {
                    let ours = query_x(index, log_height, log_global);
                    let bits_reduced = log_global - log_height;
                    let k = reverse_bits_len(index >> bits_reduced, log_height);
                    let g = Goldilocks::two_adic_generator(log_height);
                    let theirs = Goldilocks::GENERATOR * g.exp_u64(k as u64);
                    assert_eq!(
                        ours, theirs,
                        "query_x disagrees at log_global={log_global}, index={index}, log_height={log_height}",
                    );
                }
            }
        }
    }

    #[test]
    fn query_x_index_zero_is_generator_times_one() {
        // reverse_bits(0, *) = 0 ⇒ g^0 = 1 ⇒ x = GENERATOR.
        for log_global in [1usize, 4, 12] {
            assert_eq!(query_x(0, log_global, log_global), Goldilocks::GENERATOR);
        }
    }

    #[test]
    fn query_x_equals_coset_shift_independent_of_log_height_at_index_0() {
        // Regardless of log_height, at index=0 the result is GENERATOR.
        // This is the domain shift — guarantees x ≠ 0 and x ∉ subgroup.
        for log_global in [5usize, 10] {
            for log_h in [1usize, 2, 3, log_global - 1, log_global] {
                assert_eq!(query_x(0, log_h, log_global), Goldilocks::GENERATOR);
            }
        }
    }

    // ---- alpha_combine primitive ----

    #[test]
    fn alpha_combine_single_value_unit() {
        // Single-value opening: ro_out = α^k · (p_z − p_x) / (z − x)
        // with p_x base-field, p_z extension.
        let alpha = ch(3, 0);
        let z = ch(10, 1);
        let x = Goldilocks::new(2);

        let p_x = Goldilocks::new(5);
        let p_z = ch(7, 3);

        let mut alpha_pow = Challenge::ONE;
        let mut ro = Challenge::ZERO;
        alpha_combine_matrix_point(alpha, &[p_x], &[p_z], z, x, &mut alpha_pow, &mut ro).unwrap();

        // Expected: alpha_pow becomes α (one advance), ro = 1 · (p_z − p_x) / (z − x).
        let expected = (p_z - p_x) * (z - x).try_inverse().unwrap();
        assert_eq!(ro, expected);
        assert_eq!(alpha_pow, alpha);
    }

    #[test]
    fn alpha_combine_multi_value_unit() {
        // Three values: alpha_pow advances 3 times, ro accumulates.
        let alpha = ch(11, 5);
        let z = ch(100, 7);
        let x = Goldilocks::new(42);

        let p_x = vec![Goldilocks::new(1), Goldilocks::new(2), Goldilocks::new(3)];
        let p_z = vec![ch(10, 1), ch(20, 2), ch(30, 3)];

        let mut alpha_pow = Challenge::ONE;
        let mut ro = Challenge::ZERO;
        alpha_combine_matrix_point(alpha, &p_x, &p_z, z, x, &mut alpha_pow, &mut ro).unwrap();

        let denom_inv = (z - x).try_inverse().unwrap();
        let mut expected_ro = Challenge::ZERO;
        let mut expected_alpha_pow = Challenge::ONE;
        for (&px, &pz) in p_x.iter().zip(p_z.iter()) {
            expected_ro += expected_alpha_pow * (pz - px) * denom_inv;
            expected_alpha_pow *= alpha;
        }
        assert_eq!(ro, expected_ro);
        assert_eq!(alpha_pow, expected_alpha_pow);
    }

    #[test]
    fn alpha_combine_empty_opening_is_noop() {
        // Zero-length opening: no accumulation, α unchanged.
        let alpha = ch(3, 0);
        let z = ch(10, 1);
        let x = Goldilocks::new(2);
        let mut alpha_pow = ch(42, 7);
        let saved_pow = alpha_pow;
        let mut ro = ch(99, 1);
        let saved_ro = ro;
        alpha_combine_matrix_point(alpha, &[], &[], z, x, &mut alpha_pow, &mut ro).unwrap();
        assert_eq!(alpha_pow, saved_pow);
        assert_eq!(ro, saved_ro);
    }

    #[test]
    fn alpha_combine_shape_mismatch_rejects() {
        let alpha = ch(3, 0);
        let z = ch(10, 1);
        let x = Goldilocks::new(2);
        let mut alpha_pow = Challenge::ONE;
        let mut ro = Challenge::ZERO;
        let p_x = vec![Goldilocks::new(1), Goldilocks::new(2)];
        let p_z = vec![ch(1, 1)]; // wrong length
        let err = alpha_combine_matrix_point(alpha, &p_x, &p_z, z, x, &mut alpha_pow, &mut ro)
            .expect_err("shape mismatch must be rejected");
        assert_eq!(
            err,
            OpenInputShapeError::PointValueLengthMismatch {
                mat_opening_len: 2,
                ps_at_z_len: 1,
            },
        );
    }

    // ---- compute_reduced_openings_for_query on real proofs ----

    fn proof_and_pis(n_s: usize, n_o: usize, seed: u64) -> (Proof<MvpConfig>, Vec<Goldilocks>) {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(n_s, n_o, seed);
        let (proof_bytes, _pi_bytes) = prover.prove(&w.encode()).unwrap();
        let proof: Proof<MvpConfig> = postcard::from_bytes(&proof_bytes).unwrap();
        let pis = w.public_inputs();
        (proof, pis)
    }

    #[test]
    fn compute_reduced_openings_on_real_proof_smoke() {
        // Build a real 2/2 proof, compute reduced_openings for query 0.
        // Structural sanity: single entry at log_global_max_height.
        let (proof, pis) = proof_and_pis(2, 2, 0xAA_0001);
        let challenges = derive_full_challenges(&proof, &pis);

        let degree_bits = proof.degree_bits;
        let g_trace = Goldilocks::two_adic_generator(degree_bits);
        let zeta_next = challenges.zeta * g_trace;

        let ro = compute_reduced_openings_for_query(
            &proof,
            challenges.zeta,
            zeta_next,
            challenges.fri_alpha,
            challenges.log_global_max_height,
            0,
            challenges.query_indices[0],
        )
        .expect("reduced opening computation must succeed");

        assert_eq!(
            ro.log_height, challenges.log_global_max_height,
            "single-height invariant (all matrices at global max)"
        );
        // The reduced opening is a random extension element; we can't
        // assert a specific value without reimplementing upstream. We
        // verify it is non-zero with overwhelming probability and that
        // a tampered input changes it (next test).
        assert_ne!(ro.value, Challenge::ZERO);
    }

    #[test]
    fn compute_reduced_openings_deterministic_across_runs() {
        // Same proof + same challenges ⇒ same RO. Rules out UB /
        // uninit-state bugs in the α-batching loop.
        let (proof, pis) = proof_and_pis(2, 2, 0xDD_0002);
        let challenges = derive_full_challenges(&proof, &pis);
        let zeta_next = challenges.zeta * Goldilocks::two_adic_generator(proof.degree_bits);
        for q_pos in 0..4 {
            let q = challenges.query_indices[q_pos];
            let a = compute_reduced_openings_for_query(
                &proof,
                challenges.zeta,
                zeta_next,
                challenges.fri_alpha,
                challenges.log_global_max_height,
                q_pos,
                q,
            )
            .unwrap();
            let b = compute_reduced_openings_for_query(
                &proof,
                challenges.zeta,
                zeta_next,
                challenges.fri_alpha,
                challenges.log_global_max_height,
                q_pos,
                q,
            )
            .unwrap();
            assert_eq!(a.log_height, b.log_height);
            assert_eq!(a.value, b.value);
        }
    }

    #[test]
    fn tampered_trace_local_changes_reduced_opening() {
        // Flip one limb of trace_local → RO should change. Guards that
        // trace_local is actually part of the α-batching input.
        let (mut proof, pis) = proof_and_pis(2, 2, 0xEE_0003);
        let challenges = derive_full_challenges(&proof, &pis);
        let zeta_next = challenges.zeta * Goldilocks::two_adic_generator(proof.degree_bits);
        let q_pos = 0;
        let q = challenges.query_indices[q_pos];

        let ok = compute_reduced_openings_for_query(
            &proof,
            challenges.zeta,
            zeta_next,
            challenges.fri_alpha,
            challenges.log_global_max_height,
            q_pos,
            q,
        )
        .unwrap();

        proof.opened_values.trace_local[0] += Challenge::ONE;

        let bad = compute_reduced_openings_for_query(
            &proof,
            challenges.zeta,
            zeta_next,
            challenges.fri_alpha,
            challenges.log_global_max_height,
            q_pos,
            q,
        )
        .unwrap();

        assert_ne!(
            ok.value, bad.value,
            "RO must change on tampered trace_local"
        );
    }

    #[test]
    fn tampered_quotient_chunk_changes_reduced_opening() {
        // Same invariant for quotient chunks.
        let (mut proof, pis) = proof_and_pis(2, 2, 0xFF_0004);
        let challenges = derive_full_challenges(&proof, &pis);
        let zeta_next = challenges.zeta * Goldilocks::two_adic_generator(proof.degree_bits);
        let q_pos = 0;
        let q = challenges.query_indices[q_pos];

        let ok = compute_reduced_openings_for_query(
            &proof,
            challenges.zeta,
            zeta_next,
            challenges.fri_alpha,
            challenges.log_global_max_height,
            q_pos,
            q,
        )
        .unwrap();

        proof.opened_values.quotient_chunks[0][0] += Challenge::ONE;

        let bad = compute_reduced_openings_for_query(
            &proof,
            challenges.zeta,
            zeta_next,
            challenges.fri_alpha,
            challenges.log_global_max_height,
            q_pos,
            q,
        )
        .unwrap();

        assert_ne!(
            ok.value, bad.value,
            "RO must change on tampered chunk value"
        );
    }

    #[test]
    fn distinct_queries_yield_distinct_ros_with_high_probability() {
        // Different query indices produce different x → different RO.
        // Catches bugs where the x is constant or the loop aliases.
        let (proof, pis) = proof_and_pis(2, 2, 0xA1_0005);
        let challenges = derive_full_challenges(&proof, &pis);
        let zeta_next = challenges.zeta * Goldilocks::two_adic_generator(proof.degree_bits);

        let q0 = challenges.query_indices[0];
        let q1 = challenges.query_indices[1];
        if q0 == q1 {
            // Extremely unlikely but possible — skip this iteration.
            return;
        }
        let ro0 = compute_reduced_openings_for_query(
            &proof,
            challenges.zeta,
            zeta_next,
            challenges.fri_alpha,
            challenges.log_global_max_height,
            0,
            q0,
        )
        .unwrap();
        let ro1 = compute_reduced_openings_for_query(
            &proof,
            challenges.zeta,
            zeta_next,
            challenges.fri_alpha,
            challenges.log_global_max_height,
            1,
            q1,
        )
        .unwrap();
        assert_ne!(ro0.value, ro1.value);
    }
}
