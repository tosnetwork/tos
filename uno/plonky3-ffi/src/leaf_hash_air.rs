//! Wide-leaf Merkle-leaf hash AIR — trace + pure-Rust checker
//! (Phase A2-3c-iv-d-7-a).
//!
//! Encodes the `PaddingFreeSponge<Poseidon2Goldilocks<8>, 8, 4, 4>`
//! multi-block absorption (from `merkle_path::hash_leaf_row_ref`) as
//! an AIR. Each trace row represents ONE absorption step — a single
//! Poseidon2 permutation call. A leaf of width `W` (multiple of
//! `RATE = 4`) unfolds into `W / 4` consecutive ABSORB rows; the last
//! row's P2 post-state truncated to 4 is the leaf digest.
//!
//! # Column layout (28 framing cols; +180 Poseidon2 block in d-7-b)
//!
//! ```text
//! -------- Selectors --------------------------------------------
//!   KIND[0..3]              one-hot {ABSORB, IDLE}   (1 extra slot
//!                           reserved for future "non-absorb" kinds;
//!                           unused at d-7-a)
//!   IS_FIRST                1 on the first ABSORB row of a chain
//!   IS_LAST                 1 on the last ABSORB row of a chain
//!
//! -------- Per-row data -----------------------------------------
//!   BLOCK[0..4]             this row's absorption block
//!   STATE_IN[0..8]          sponge state entering P2 this row
//!                           (after overwriting state[0..4] with BLOCK
//!                            and preserving state[4..8] from the prior
//!                            row's STATE_OUT)
//!   STATE_OUT[0..8]         P2 post-state (wired to the Poseidon2
//!                           witness block in d-7-b)
//!
//! -------- Public-input proxy -----------------------------------
//!   EXPECTED_DIGEST[0..4]   expected leaf hash; the IS_LAST row's
//!                           STATE_OUT[0..4] is asserted to equal this.
//! ```
//!
//! Total framing: 3 + 1 + 1 + 4 + 8 + 8 + 4 = **29 cols**. The 180-col
//! Poseidon2-w8 block that binds `STATE_OUT = P2(STATE_IN)` arrives
//! in d-7-b.
//!
//! # Scope boundary
//!
//! - **Widths supported**: `W ∈ {4, 8, 12, 16, …}` — multiples of
//!   RATE = 4. This covers the FRI quot-commit batch (leaf width =
//!   num_chunks·DIMENSION = 4·2 = 8) and the commit-phase Merkle
//!   branches (leaf width = arity·DIMENSION = 4).
//! - **Partial-final-block widths** (W = 4k + r, r ∈ {1, 2, 3}) —
//!   needed for the trace commit (air_width ≈ 1300-1500 Goldilocks,
//!   typically not a multiple of 4) — land in a follow-up sub-phase
//!   d-7-c. That adds a per-row BLOCK_LEN + one-hot flags and
//!   branches the overwrite rule on BLOCK_LEN.
//! - **Air<AB> port**: d-7-b.
//! - **Integration with compression chain**: `merkle_path_air` already
//!   handles the binary-tree compression side; a future sub-phase ties
//!   `leaf_hash_air.DIGEST` to a compression-chain AIR's starting
//!   CURRENT via cross-binding (same pattern as d-6 uses for α ↔ fold).

use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};
use p3_symmetric::Permutation;

use crate::merkle_path::{hash_leaf_row_ref, Digest};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Sponge rate. Must match `merkle_path::SPONGE_RATE`.
pub const SPONGE_RATE: usize = 4;
/// Sponge width.
pub const SPONGE_WIDTH: usize = 8;
/// Digest width (= OUT of `PaddingFreeSponge<_, 8, 4, 4>`).
pub const DIGEST_WIDTH: usize = 4;

// ---------------------------------------------------------------------------
// Op-kind selectors
// ---------------------------------------------------------------------------

pub const OP_KIND_ABSORB: u8 = 0;
pub const OP_KIND_IDLE: u8 = 1;
/// Reserved slot for a future non-absorb / non-idle kind (e.g.
/// COMPRESS once we re-unify with merkle_path_air).
pub const OP_KIND_RESERVED: u8 = 2;
pub const NUM_OP_KINDS: usize = 3;

// ---------------------------------------------------------------------------
// Column offsets
// ---------------------------------------------------------------------------

pub mod col {
    use super::*;

    pub const KIND0: usize = 0;
    pub const KIND_END: usize = KIND0 + NUM_OP_KINDS;

    pub const IS_FIRST: usize = KIND_END;
    pub const IS_LAST: usize = IS_FIRST + 1;

    pub const BLOCK0: usize = IS_LAST + 1;
    pub const BLOCK_END: usize = BLOCK0 + SPONGE_RATE;

    pub const STATE_IN0: usize = BLOCK_END;
    pub const STATE_IN_END: usize = STATE_IN0 + SPONGE_WIDTH;

    pub const STATE_OUT0: usize = STATE_IN_END;
    pub const STATE_OUT_END: usize = STATE_OUT0 + SPONGE_WIDTH;

    pub const EXPECTED_DIGEST0: usize = STATE_OUT_END;
    pub const EXPECTED_DIGEST_END: usize = EXPECTED_DIGEST0 + DIGEST_WIDTH;

    pub const WIDTH: usize = EXPECTED_DIGEST_END;
}

pub const LEAF_HASH_AIR_FRAMING_WIDTH: usize = col::WIDTH;

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TraceBuildError {
    LeafWidthNotMultipleOfRate { got: usize },
    LeafWidthZero,
    TraceHeightNotPow2 { got: usize },
    TraceHeightTooSmall { physical_rows: usize, trace_height: usize },
}

/// Build a row-major trace for absorbing a leaf of width `W` (multiple
/// of `RATE = 4`) via the `PaddingFreeSponge<_, 8, 4, 4>` algorithm.
///
/// - `leaf`: the base-field leaf values. Length MUST be a multiple of
///   RATE and ≥ RATE.
/// - `expected_digest`: the leaf hash `hash_leaf_row_ref(perm, leaf)`.
///   The AIR asserts the last absorb row's STATE_OUT[0..4] matches.
/// - `trace_height`: power-of-two total trace rows; extra rows past
///   the physical ABSORB chain are padded with IDLE.
pub fn build_trace(
    leaf: &[Goldilocks],
    expected_digest: Digest,
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    if leaf.is_empty() {
        return Err(TraceBuildError::LeafWidthZero);
    }
    if leaf.len() % SPONGE_RATE != 0 {
        return Err(TraceBuildError::LeafWidthNotMultipleOfRate { got: leaf.len() });
    }
    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let num_absorb_rows = leaf.len() / SPONGE_RATE;
    if num_absorb_rows > trace_height {
        return Err(TraceBuildError::TraceHeightTooSmall {
            physical_rows: num_absorb_rows,
            trace_height,
        });
    }

    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];
    let zero_g = Goldilocks::default();
    let perm = default_goldilocks_poseidon2_8();

    let write_kind = |out: &mut [Goldilocks], kind: u8| {
        for k in 0..NUM_OP_KINDS {
            out[col::KIND0 + k] = if k as u8 == kind { Goldilocks::new(1) } else { zero_g };
        }
    };
    let write_digest_expected = |out: &mut [Goldilocks]| {
        for i in 0..DIGEST_WIDTH {
            out[col::EXPECTED_DIGEST0 + i] = expected_digest[i];
        }
    };

    // Run the sponge to populate STATE_IN / STATE_OUT per row.
    let mut state: [Goldilocks; SPONGE_WIDTH] = [zero_g; SPONGE_WIDTH];

    for r in 0..num_absorb_rows {
        let base = r * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_ABSORB);

        let is_first = r == 0;
        let is_last = r + 1 == num_absorb_rows;
        row[col::IS_FIRST] = if is_first { Goldilocks::new(1) } else { zero_g };
        row[col::IS_LAST] = if is_last { Goldilocks::new(1) } else { zero_g };

        // BLOCK = next 4 leaf elements.
        let block_start = r * SPONGE_RATE;
        for i in 0..SPONGE_RATE {
            row[col::BLOCK0 + i] = leaf[block_start + i];
        }

        // STATE_IN: overwrite state[0..RATE] with BLOCK; keep state[RATE..] as-is.
        for i in 0..SPONGE_RATE {
            state[i] = leaf[block_start + i];
        }
        for i in 0..SPONGE_WIDTH {
            row[col::STATE_IN0 + i] = state[i];
        }

        // Permute.
        perm.permute_mut(&mut state);
        for i in 0..SPONGE_WIDTH {
            row[col::STATE_OUT0 + i] = state[i];
        }

        write_digest_expected(row);
    }

    // Pad with IDLE rows — copy previous row's non-KIND, non-IS_FIRST,
    // non-IS_LAST data.
    for r in num_absorb_rows..trace_height {
        let prev_base = (r - 1) * width;
        let prev_row = flat[prev_base..prev_base + width].to_vec();
        let base = r * width;
        let row = &mut flat[base..base + width];
        // Copy BLOCK, STATE_IN, STATE_OUT, EXPECTED_DIGEST from previous.
        for c in col::BLOCK0..col::WIDTH {
            row[c] = prev_row[c];
        }
        // KIND = IDLE; IS_FIRST / IS_LAST = 0.
        write_kind(row, OP_KIND_IDLE);
        row[col::IS_FIRST] = zero_g;
        row[col::IS_LAST] = zero_g;
    }

    Ok(flat)
}

// ---------------------------------------------------------------------------
// Pure-Rust constraint checker
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CheckError {
    TraceLengthMismatch { expected: usize, got: usize },
    KindFlagNotBoolean { row: usize, kind: usize },
    KindNotOneHot { row: usize },
    IsFirstNotBoolean { row: usize },
    IsLastNotBoolean { row: usize },
    StateInFirstRowNotOverwrite { row: usize, col: usize },
    StateInCarryMismatch { row: usize, col: usize },
    StateInBlockOverwriteMismatch { row: usize, col: usize },
    StateOutNotPermutation { row: usize, col: usize },
    IdlePersistenceMismatch { row: usize, col: usize },
    ExpectedDigestDrift { row: usize, col: usize },
    FirstRowNotIsFirst,
    LastAbsorbNotIsLast,
    DigestMismatch { col: usize },
    UnexpectedIsFirstBeyondRow0,
    UnexpectedIsLastOnNonLastAbsorbRow { row: usize },
}

/// Verify every constraint on a pre-built trace.
pub fn check_all_transitions(
    trace: &[Goldilocks],
    trace_height: usize,
) -> Result<(), CheckError> {
    let width = col::WIDTH;
    if trace.len() != trace_height * width {
        return Err(CheckError::TraceLengthMismatch {
            expected: trace_height * width,
            got: trace.len(),
        });
    }
    let row = |r: usize| &trace[r * width..(r + 1) * width];
    let zero = Goldilocks::default();
    let one = Goldilocks::new(1);
    let perm = default_goldilocks_poseidon2_8();

    // Find the last ABSORB row.
    let mut last_absorb: Option<usize> = None;

    for r in 0..trace_height {
        let local = row(r);

        // One-hot selector.
        let mut sum = zero;
        for k in 0..NUM_OP_KINDS {
            let v = local[col::KIND0 + k];
            if v != zero && v != one {
                return Err(CheckError::KindFlagNotBoolean { row: r, kind: k });
            }
            sum += v;
        }
        if sum != one {
            return Err(CheckError::KindNotOneHot { row: r });
        }

        // IS_FIRST / IS_LAST boolean.
        if local[col::IS_FIRST] != zero && local[col::IS_FIRST] != one {
            return Err(CheckError::IsFirstNotBoolean { row: r });
        }
        if local[col::IS_LAST] != zero && local[col::IS_LAST] != one {
            return Err(CheckError::IsLastNotBoolean { row: r });
        }

        let is_absorb = local[col::KIND0 + OP_KIND_ABSORB as usize] == one;
        let is_idle = local[col::KIND0 + OP_KIND_IDLE as usize] == one;
        let is_first = local[col::IS_FIRST] == one;
        let is_last = local[col::IS_LAST] == one;

        // IS_FIRST may only be set on row 0.
        if is_first && r != 0 {
            return Err(CheckError::UnexpectedIsFirstBeyondRow0);
        }
        // Row 0 (if ABSORB) must be IS_FIRST.
        if r == 0 && is_absorb && !is_first {
            return Err(CheckError::FirstRowNotIsFirst);
        }

        if is_absorb {
            // STATE_IN[0..RATE] == BLOCK (overwrite rule).
            for i in 0..SPONGE_RATE {
                if local[col::STATE_IN0 + i] != local[col::BLOCK0 + i] {
                    return Err(CheckError::StateInBlockOverwriteMismatch {
                        row: r,
                        col: i,
                    });
                }
            }
            // STATE_IN[RATE..WIDTH]: if IS_FIRST, must be 0; else
            // must equal previous row's STATE_OUT[RATE..WIDTH].
            if is_first {
                for i in SPONGE_RATE..SPONGE_WIDTH {
                    if local[col::STATE_IN0 + i] != zero {
                        return Err(CheckError::StateInFirstRowNotOverwrite {
                            row: r,
                            col: i,
                        });
                    }
                }
            } else {
                let prev = row(r - 1);
                for i in SPONGE_RATE..SPONGE_WIDTH {
                    if local[col::STATE_IN0 + i] != prev[col::STATE_OUT0 + i] {
                        return Err(CheckError::StateInCarryMismatch { row: r, col: i });
                    }
                }
            }
            // STATE_OUT == P2(STATE_IN).
            let mut state_in: [Goldilocks; SPONGE_WIDTH] = [zero; SPONGE_WIDTH];
            for i in 0..SPONGE_WIDTH {
                state_in[i] = local[col::STATE_IN0 + i];
            }
            let state_out_expected = perm.permute(state_in);
            for i in 0..SPONGE_WIDTH {
                if local[col::STATE_OUT0 + i] != state_out_expected[i] {
                    return Err(CheckError::StateOutNotPermutation { row: r, col: i });
                }
            }
            if is_last {
                last_absorb = Some(r);
            }
        }

        // IDLE persistence.
        if is_idle && r > 0 {
            let prev = row(r - 1);
            // BLOCK, STATE_IN, STATE_OUT, EXPECTED_DIGEST preserved.
            for c in col::BLOCK0..col::WIDTH {
                if local[c] != prev[c] {
                    return Err(CheckError::IdlePersistenceMismatch { row: r, col: c });
                }
            }
            // IS_FIRST / IS_LAST on IDLE must be 0 (not an ABSORB row).
            if local[col::IS_FIRST] != zero || local[col::IS_LAST] != zero {
                return Err(CheckError::UnexpectedIsLastOnNonLastAbsorbRow { row: r });
            }
        }

        // EXPECTED_DIGEST persists across all rows.
        if r > 0 {
            let prev = row(r - 1);
            for i in 0..DIGEST_WIDTH {
                if local[col::EXPECTED_DIGEST0 + i] != prev[col::EXPECTED_DIGEST0 + i] {
                    return Err(CheckError::ExpectedDigestDrift { row: r, col: i });
                }
            }
        }
    }

    // Require a last-absorb row exists; assert its STATE_OUT[0..4]
    // equals EXPECTED_DIGEST.
    let last_r = last_absorb.ok_or(CheckError::LastAbsorbNotIsLast)?;
    let last = row(last_r);
    for i in 0..DIGEST_WIDTH {
        if last[col::STATE_OUT0 + i] != last[col::EXPECTED_DIGEST0 + i] {
            return Err(CheckError::DigestMismatch { col: i });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn gl(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    fn compute_digest(leaf: &[Goldilocks]) -> Digest {
        let perm = default_goldilocks_poseidon2_8();
        hash_leaf_row_ref(&perm, leaf)
    }

    // ---- builder sanity ----

    #[test]
    fn build_rejects_empty_leaf() {
        let err = build_trace(&[], [gl(0); 4], 4).unwrap_err();
        assert_eq!(err, TraceBuildError::LeafWidthZero);
    }

    #[test]
    fn build_rejects_non_multiple_of_rate() {
        let leaf = vec![gl(1), gl(2), gl(3), gl(4), gl(5)];
        let err = build_trace(&leaf, [gl(0); 4], 4).unwrap_err();
        assert_eq!(
            err,
            TraceBuildError::LeafWidthNotMultipleOfRate { got: 5 }
        );
    }

    #[test]
    fn build_rejects_non_pow2_height() {
        let leaf = vec![gl(1); 8];
        let digest = compute_digest(&leaf);
        let err = build_trace(&leaf, digest, 7).unwrap_err();
        assert_eq!(err, TraceBuildError::TraceHeightNotPow2 { got: 7 });
    }

    #[test]
    fn build_rejects_insufficient_height() {
        let leaf = vec![gl(1); 16];
        let digest = compute_digest(&leaf);
        // 16/4 = 4 absorb rows; trace_height=2 is too small.
        let err = build_trace(&leaf, digest, 2).unwrap_err();
        assert_eq!(
            err,
            TraceBuildError::TraceHeightTooSmall {
                physical_rows: 4,
                trace_height: 2
            }
        );
    }

    // ---- positive: valid traces for widths 4, 8, 16 ----

    #[test]
    fn trace_and_check_accept_width_4() {
        let leaf = vec![gl(7), gl(11), gl(13), gl(17)];
        let digest = compute_digest(&leaf);
        let trace = build_trace(&leaf, digest, 4).unwrap();
        assert_eq!(trace.len(), 4 * col::WIDTH);
        check_all_transitions(&trace, 4).expect("width-4 leaf must check");
    }

    #[test]
    fn trace_and_check_accept_width_8() {
        let leaf: Vec<Goldilocks> = (1..=8).map(|i| gl(i * 100)).collect();
        let digest = compute_digest(&leaf);
        let trace = build_trace(&leaf, digest, 8).unwrap();
        check_all_transitions(&trace, 8).expect("width-8 leaf must check");
    }

    #[test]
    fn trace_and_check_accept_width_16() {
        let leaf: Vec<Goldilocks> = (1..=16).map(|i| gl(i * 7 + 3)).collect();
        let digest = compute_digest(&leaf);
        let trace = build_trace(&leaf, digest, 8).unwrap();
        check_all_transitions(&trace, 8).expect("width-16 leaf must check");
    }

    /// Width that exercises multiple absorb rows.
    #[test]
    fn trace_and_check_accept_width_64() {
        let leaf: Vec<Goldilocks> = (0..64).map(|i| gl(i + 1000)).collect();
        let digest = compute_digest(&leaf);
        // 64/4 = 16 absorb rows; trace_height = 16.
        let trace = build_trace(&leaf, digest, 16).unwrap();
        check_all_transitions(&trace, 16).expect("width-64 leaf must check");
    }

    // ---- negatives ----

    #[test]
    fn checker_rejects_tampered_block() {
        let leaf = vec![gl(1), gl(2), gl(3), gl(4), gl(5), gl(6), gl(7), gl(8)];
        let digest = compute_digest(&leaf);
        let mut trace = build_trace(&leaf, digest, 8).unwrap();
        // Corrupt row 0 BLOCK[0] — STATE_IN[0] still matches (since both
        // overwrite from BLOCK), but the permutation input changes so
        // STATE_OUT won't match the expected P2(BLOCK) ⇒
        // StateOutNotPermutation catches it.
        trace[col::BLOCK0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_wrong_overwrite() {
        let leaf = vec![gl(1); 8];
        let digest = compute_digest(&leaf);
        let mut trace = build_trace(&leaf, digest, 8).unwrap();
        // Set STATE_IN[0] != BLOCK[0] → overwrite rule fires.
        trace[col::STATE_IN0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_first_row_non_zero_capacity() {
        let leaf = vec![gl(1); 8];
        let digest = compute_digest(&leaf);
        let mut trace = build_trace(&leaf, digest, 8).unwrap();
        // Row 0 is IS_FIRST. STATE_IN[4..8] should be 0 → set one to non-zero.
        trace[col::STATE_IN0 + 4] = gl(999);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_broken_state_carry() {
        let leaf = vec![gl(1); 8];
        let digest = compute_digest(&leaf);
        let mut trace = build_trace(&leaf, digest, 8).unwrap();
        // Row 1 STATE_IN[4] should equal row 0 STATE_OUT[4]. Break it.
        let row1 = col::WIDTH;
        trace[row1 + col::STATE_IN0 + 4] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_tampered_state_out() {
        let leaf = vec![gl(1); 8];
        let digest = compute_digest(&leaf);
        let mut trace = build_trace(&leaf, digest, 8).unwrap();
        // Corrupt STATE_OUT[0] on row 0 — P2(STATE_IN) computed check fires.
        trace[col::STATE_OUT0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_wrong_expected_digest() {
        let leaf = vec![gl(1); 8];
        let digest = compute_digest(&leaf);
        let mut bad = digest;
        bad[0] += gl(1);
        // Build with wrong expected digest — last row's STATE_OUT[0..4]
        // matches real digest, not the expected one ⇒ DigestMismatch fires.
        let trace = build_trace(&leaf, bad, 8).unwrap();
        let err = check_all_transitions(&trace, 8).unwrap_err();
        assert!(matches!(err, CheckError::DigestMismatch { .. }));
    }

    #[test]
    fn checker_rejects_idle_mutation() {
        let leaf = vec![gl(1); 8];
        let digest = compute_digest(&leaf);
        let mut trace = build_trace(&leaf, digest, 8).unwrap();
        // Row 3 is IDLE. Tamper a data col.
        let row3 = 3 * col::WIDTH;
        trace[row3 + col::STATE_OUT0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_expected_digest_drift() {
        let leaf = vec![gl(1); 8];
        let digest = compute_digest(&leaf);
        let mut trace = build_trace(&leaf, digest, 8).unwrap();
        // Flip EXPECTED_DIGEST[0] on row 1 — persistence transition catches.
        let row1 = col::WIDTH;
        trace[row1 + col::EXPECTED_DIGEST0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    // ---- column layout regression ----

    #[test]
    fn column_layout_constants() {
        assert_eq!(col::KIND0, 0);
        assert_eq!(col::KIND_END, 3);
        assert_eq!(col::WIDTH, 29);
        assert_eq!(LEAF_HASH_AIR_FRAMING_WIDTH, col::WIDTH);
    }

    // ---- end-to-end: hash a real FRI quotient-commit leaf ----

    /// On a real 2/2 Transfer proof, build the leaf-hash trace for
    /// the quot-commit leaf at query 0 and check it round-trips to
    /// the Merkle-tree's expected leaf digest.
    #[test]
    fn leaf_hash_air_on_real_quot_commit_leaf() {
        use crate::fiat_shamir::derive_full_challenges;
        use crate::merkle_path::hash_multi_matrix_leaf_ref;
        use crate::prover::{MvpConfig, MvpProver};
        use crate::transfer_air::MvpWitness;
        use p3_uni_stark::Proof;

        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(2, 2, 0x1EA_F001);
        let (bytes, _) = prover.prove(&w.encode()).unwrap();
        let proof: Proof<MvpConfig> = postcard::from_bytes(&bytes).unwrap();
        let pis = w.public_inputs();
        let _ch = derive_full_challenges(&proof, &pis);

        // Quot-commit batch at query 0: concatenate each chunk's
        // opened row into one 8-Goldilocks leaf (num_chunks = 4,
        // each chunk is DIMENSION = 2 Goldilocks).
        let quot_batch = &proof.opening_proof.query_proofs[0].input_proof[1];
        let refs: Vec<&[Goldilocks]> =
            quot_batch.opened_values.iter().map(|v| v.as_slice()).collect();
        let flat_leaf: Vec<Goldilocks> =
            refs.iter().flat_map(|r| r.iter().copied()).collect();

        // Upstream's multi-matrix leaf hash.
        let perm = default_goldilocks_poseidon2_8();
        let expected = hash_multi_matrix_leaf_ref(&perm, &refs);

        // Our AIR trace.
        let trace_height = (flat_leaf.len() / SPONGE_RATE).next_power_of_two().max(2);
        let trace = build_trace(&flat_leaf, expected, trace_height)
            .expect("trace build");
        check_all_transitions(&trace, trace_height)
            .expect("real quot-commit leaf must check");
    }
}
