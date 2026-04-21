//! Monolithic VerifierAir — Phase A3-PRE scaffolding.
//!
//! This module implements the **merged, single-STARK** per-Tx verifier
//! AIR that Phase A3+ will use to collapse the A2 orchestration's
//! 6+N per-query STARK bundle into ONE proof. See
//! `doc/uno-aggregation-path-decision.md` for the decision rationale.
//!
//! # Design (K-air-col-share pattern)
//!
//! Every row represents one "step" in the verifier's execution. A
//! per-row one-hot `KIND` selector picks which constraint bank applies:
//!
//! ```text
//!   KIND ∈ { ABSORB, COMPRESS, FOLD, ALPHA, IDLE }
//!
//!     ABSORB   : one PaddingFreeSponge absorb block (leaf hash for a
//!                Merkle leaf). Uses the shared Poseidon2-w8 block.
//!     COMPRESS : one binary Merkle compression step. Uses the shared
//!                Poseidon2-w8 block with [LEFT ∥ RIGHT] input.
//!     FOLD     : one FRI fold round (binary Lagrange interpolation at β).
//!                Uses the shared extension-mult lane, no P2 needed.
//!     ALPHA    : one α-batched quotient update. Uses the shared
//!                extension-mult lane (and INV witness column).
//!     IDLE     : no-op padding; all data cols carry previous row.
//! ```
//!
//! One shared **Poseidon2-w8 witness block** (180 cols) is populated
//! on every row. On ABSORB/COMPRESS rows the row-gated binding forces
//! `p2.inputs` and `p2.post[0..8]` to specific framing columns. On
//! FOLD/ALPHA/IDLE rows the block carries a dummy zero-input witness
//! (unconstrained relative to the framing).
//!
//! One shared **extension-multiplication lane** (4 output limbs + 2
//! input limbs × 3 factors = ~14 cols) is populated on every row. On
//! FOLD/ALPHA rows it's row-gated to carry the round's ext-mult result;
//! on ABSORB/COMPRESS/IDLE rows it's unconstrained.
//!
//! # Layout pinning (A3-PRE; stable from here)
//!
//! The column offsets below are PINNED so follow-up sub-phases (A3-1
//! ABSORB+COMPRESS, A3-2 FOLD+ALPHA, A3-3 cross-bindings) can reference
//! them without renumbering.
//!
//! # Status
//!
//! **A3-PRE — scaffolding only.** The `Air<AB>::eval` at this sub-phase
//! asserts:
//!   * KIND one-hot (5-way selector).
//!   * KIND boolean per flag.
//!
//! No operation-specific banks are wired yet; the trace builder
//! emits only IDLE rows. This is enough to prove the skeleton
//! round-trips through `uni_stark::prove + verify` and to lock in
//! the column layout contract.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};
use p3_symmetric::Permutation;

// ---------------------------------------------------------------------------
// Shared / imported constants
// ---------------------------------------------------------------------------

use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref, Digest};
use crate::transfer_air::{
    eval_poseidon2, P2Cols, POSEIDON2_COLS_PER_INSTANCE, POSEIDON2_HALF_FULL_ROUNDS,
};

/// Extension field DIMENSION. Mirrors the other AIRs' constant.
pub const CHALLENGE_DIM: usize = 2;
/// Sponge rate (matches `PaddingFreeSponge<_, 8, 4, 4>`).
pub const SPONGE_RATE: usize = 4;
/// Sponge width.
pub const SPONGE_WIDTH: usize = 8;
/// Digest width (sponge OUT).
pub const DIGEST_WIDTH: usize = 4;

// ---------------------------------------------------------------------------
// One-hot row-kind selectors
// ---------------------------------------------------------------------------

pub const OP_KIND_ABSORB: u8 = 0;
pub const OP_KIND_COMPRESS: u8 = 1;
pub const OP_KIND_FOLD: u8 = 2;
pub const OP_KIND_ALPHA: u8 = 3;
pub const OP_KIND_IDLE: u8 = 4;
pub const NUM_OP_KINDS: usize = 5;

// ---------------------------------------------------------------------------
// Column layout (PINNED; A3-1+ fill in the bank-specific constraints)
// ---------------------------------------------------------------------------

pub mod col {
    use super::*;

    // ---- Selectors ------------------------------------------------------
    pub const KIND0: usize = 0;
    pub const KIND_END: usize = KIND0 + NUM_OP_KINDS;

    // ---- ABSORB bank (shape mirrors leaf_hash_air framing) --------------
    /// Per-row absorption block (4 Goldilocks).
    pub const ABSORB_BLOCK0: usize = KIND_END;
    pub const ABSORB_BLOCK_END: usize = ABSORB_BLOCK0 + SPONGE_RATE;
    /// Per-row BLOCK_LEN (1..=RATE on ABSORB, 0 elsewhere).
    pub const ABSORB_BLOCK_LEN: usize = ABSORB_BLOCK_END;
    /// One-hot over {0, 1, 2, 3, 4}.
    pub const ABSORB_BLOCK_LEN_FLAG0: usize = ABSORB_BLOCK_LEN + 1;
    pub const ABSORB_BLOCK_LEN_FLAG_END: usize =
        ABSORB_BLOCK_LEN_FLAG0 + (SPONGE_RATE + 1);
    /// 1 on the FIRST ABSORB row of a leaf's chain.
    pub const ABSORB_IS_FIRST: usize = ABSORB_BLOCK_LEN_FLAG_END;
    /// 1 on the LAST ABSORB row of a leaf's chain.
    pub const ABSORB_IS_LAST: usize = ABSORB_IS_FIRST + 1;

    // ---- COMPRESS bank (shape mirrors compression_path_air framing) -----
    /// Digest at the start of a COMPRESS row (from prior DIGEST, or
    /// from the LEAF_DIGEST at the first COMPRESS of a path).
    pub const COMPRESS_CURRENT0: usize = ABSORB_IS_LAST + 1;
    pub const COMPRESS_CURRENT_END: usize = COMPRESS_CURRENT0 + DIGEST_WIDTH;
    pub const COMPRESS_SIBLING0: usize = COMPRESS_CURRENT_END;
    pub const COMPRESS_SIBLING_END: usize = COMPRESS_SIBLING0 + DIGEST_WIDTH;
    pub const COMPRESS_INDEX_BIT: usize = COMPRESS_SIBLING_END;

    // ---- Shared P2 I/O cols (both ABSORB and COMPRESS bind these) -------
    /// Sponge state fed into the Poseidon2 block on this row.
    /// ABSORB: state[0..RATE] = BLOCK; state[RATE..WIDTH] = carry.
    /// COMPRESS: state = [LEFT ∥ RIGHT].
    pub const STATE_IN0: usize = COMPRESS_INDEX_BIT + 1;
    pub const STATE_IN_END: usize = STATE_IN0 + SPONGE_WIDTH;
    /// Sponge state output of the Poseidon2 block (equals p2.post[0..8]).
    pub const STATE_OUT0: usize = STATE_IN_END;
    pub const STATE_OUT_END: usize = STATE_OUT0 + SPONGE_WIDTH;
    /// DIGEST = STATE_OUT[0..4] on ABSORB IS_LAST rows and on COMPRESS rows.
    pub const DIGEST0: usize = STATE_OUT_END;
    pub const DIGEST_END: usize = DIGEST0 + DIGEST_WIDTH;

    // ---- FOLD bank (shape mirrors fold_air framing) --------------------
    pub const FOLD_BETA0: usize = DIGEST_END;
    pub const FOLD_BETA_END: usize = FOLD_BETA0 + CHALLENGE_DIM;
    pub const FOLD_S: usize = FOLD_BETA_END;
    pub const FOLD_INV_2S: usize = FOLD_S + 1;
    /// Folded-eval in/out (Challenge). IN carries from the prior FOLD row.
    pub const FOLD_IN0: usize = FOLD_INV_2S + 1;
    pub const FOLD_IN_END: usize = FOLD_IN0 + CHALLENGE_DIM;
    pub const FOLD_OUT0: usize = FOLD_IN_END;
    pub const FOLD_OUT_END: usize = FOLD_OUT0 + CHALLENGE_DIM;

    // ---- ALPHA bank (shape mirrors alpha_reduction_air framing) --------
    pub const ALPHA_CHALLENGE0: usize = FOLD_OUT_END;
    pub const ALPHA_CHALLENGE_END: usize = ALPHA_CHALLENGE0 + CHALLENGE_DIM;
    pub const ALPHA_POW_IN0: usize = ALPHA_CHALLENGE_END;
    pub const ALPHA_POW_IN_END: usize = ALPHA_POW_IN0 + CHALLENGE_DIM;
    pub const ALPHA_POW_OUT0: usize = ALPHA_POW_IN_END;
    pub const ALPHA_POW_OUT_END: usize = ALPHA_POW_OUT0 + CHALLENGE_DIM;
    pub const ALPHA_P_AT_X: usize = ALPHA_POW_OUT_END;
    pub const ALPHA_P_AT_Z0: usize = ALPHA_P_AT_X + 1;
    pub const ALPHA_P_AT_Z_END: usize = ALPHA_P_AT_Z0 + CHALLENGE_DIM;
    pub const ALPHA_Z0: usize = ALPHA_P_AT_Z_END;
    pub const ALPHA_Z_END: usize = ALPHA_Z0 + CHALLENGE_DIM;
    pub const ALPHA_X: usize = ALPHA_Z_END;
    pub const ALPHA_QUOT_INV0: usize = ALPHA_X + 1;
    pub const ALPHA_QUOT_INV_END: usize = ALPHA_QUOT_INV0 + CHALLENGE_DIM;
    pub const ALPHA_DIFF_QUOT0: usize = ALPHA_QUOT_INV_END;
    pub const ALPHA_DIFF_QUOT_END: usize = ALPHA_DIFF_QUOT0 + CHALLENGE_DIM;
    pub const ALPHA_RO_IN0: usize = ALPHA_DIFF_QUOT_END;
    pub const ALPHA_RO_IN_END: usize = ALPHA_RO_IN0 + CHALLENGE_DIM;
    pub const ALPHA_RO_OUT0: usize = ALPHA_RO_IN_END;
    pub const ALPHA_RO_OUT_END: usize = ALPHA_RO_OUT0 + CHALLENGE_DIM;

    // ---- Public-input proxies (persist across all rows, asserted
    // consistent with proof data at the aggregator boundary) -----------
    /// Trace-commit root; all COMPRESS rows of the trace-Merkle walk
    /// have this as their "ROOT" target.
    pub const TRACE_COMMIT_ROOT0: usize = ALPHA_RO_OUT_END;
    pub const TRACE_COMMIT_ROOT_END: usize = TRACE_COMMIT_ROOT0 + DIGEST_WIDTH;
    /// Quotient-commit root (analogous).
    pub const QUOT_COMMIT_ROOT0: usize = TRACE_COMMIT_ROOT_END;
    pub const QUOT_COMMIT_ROOT_END: usize = QUOT_COMMIT_ROOT0 + DIGEST_WIDTH;
    /// Initial α-chain seeds (ALPHA_POW = 1, RO = 0). Normally pinned
    /// by first-row boundary constraint; stored explicitly for audit.
    pub const INITIAL_ALPHA_POW0: usize = QUOT_COMMIT_ROOT_END;
    pub const INITIAL_ALPHA_POW_END: usize = INITIAL_ALPHA_POW0 + CHALLENGE_DIM;
    pub const INITIAL_RO0: usize = INITIAL_ALPHA_POW_END;
    pub const INITIAL_RO_END: usize = INITIAL_RO0 + CHALLENGE_DIM;
    /// Expected FINAL_FOLDED (= eval_final_poly_horner(x_final)).
    pub const FINAL_FOLDED0: usize = INITIAL_RO_END;
    pub const FINAL_FOLDED_END: usize = FINAL_FOLDED0 + CHALLENGE_DIM;

    /// Base offset of the shared Poseidon2-w8 sub-AIR witness block.
    pub const P2_BLOCK: usize = FINAL_FOLDED_END;

    /// Total column width. 180-col Poseidon2 block added on top of
    /// framing cols. Final number fixed at A3-PRE to pin the layout.
    pub const WIDTH: usize = P2_BLOCK + POSEIDON2_COLS_PER_INSTANCE;
}

/// Canonical width constant mirroring `col::WIDTH`.
pub const MONOLITHIC_VERIFIER_AIR_WIDTH: usize = col::WIDTH;

// ---------------------------------------------------------------------------
// Trace builder (A3-PRE: emits IDLE-only rows for scaffold validation)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TraceBuildError {
    TraceHeightNotPow2 { got: usize },
    EmptyLeaf,
    EmptyPath,
    TraceHeightTooSmall {
        physical_rows: usize,
        trace_height: usize,
    },
}

/// Build a trivial all-IDLE trace of the requested height. Real
/// operation-specific rows land in A3-1+ as each bank migrates in.
pub fn build_trivial_trace(trace_height: usize) -> Result<Vec<Goldilocks>, TraceBuildError> {
    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];

    // Populate KIND = IDLE on every row + BLOCK_LEN_FLAG[0] = 1 (A3-1
    // requires BLOCK_LEN flags be a valid one-hot on every row).
    for r in 0..trace_height {
        let base = r * width;
        flat[base + col::KIND0 + OP_KIND_IDLE as usize] = Goldilocks::new(1);
        flat[base + col::ABSORB_BLOCK_LEN_FLAG0] = Goldilocks::new(1);
    }

    // Populate the shared Poseidon2-w8 block on every row with the
    // zero-input witness. Reuses the same helper pattern as
    // `leaf_hash_air` / `compression_path_air` / `merkle_path_air`.
    let p2_witness = gen_p2_witness_zero();
    for r in 0..trace_height {
        let base = r * width;
        for (i, v) in p2_witness.iter().enumerate() {
            flat[base + col::P2_BLOCK + i] = *v;
        }
    }

    Ok(flat)
}

/// Generate the Poseidon2-w8 witness for a zero input state. Shared
/// across all IDLE rows (and all current-phase non-wire-binding rows
/// at A3-PRE).
pub(crate) fn gen_p2_witness_zero() -> Vec<Goldilocks> {
    gen_p2_witness([Goldilocks::default(); 8])
}

/// View the Poseidon2-w8 sub-block as `&P2Cols<T>` for
/// `eval_poseidon2` consumption.
#[inline]
pub(crate) fn p2_group<T>(row: &[T]) -> &P2Cols<T> {
    let group: &[T] = &row[col::P2_BLOCK..col::P2_BLOCK + POSEIDON2_COLS_PER_INSTANCE];
    <[T] as Borrow<P2Cols<T>>>::borrow(group)
}

// ---------------------------------------------------------------------------
// A3-1 trace builder: "wide leaf → Merkle root" via ABSORB + COMPRESS banks
// ---------------------------------------------------------------------------

/// Build a trace that verifies a single Merkle-path opening end-to-end:
///
///   * Rows 0..ceil(W/4)   : ABSORB rows (leaf hash over `leaf`).
///   * Next `path.len()` rows: COMPRESS rows (walking up the Merkle tree).
///   * Remaining rows       : IDLE padding.
///
/// Public-input proxies `trace_commit_root` are pinned on every row.
///
/// In-circuit, at the ABSORB→COMPRESS transition the AIR enforces
/// `next.CURRENT = local.STATE_OUT[0..4]` on is_last_absorb rows —
/// this is the leaf-digest bridge that A2's orchestration did by
/// CONSTRUCTION; A3-1 now does it with a real constraint.
pub fn build_leaf_to_root_trace(
    leaf: &[Goldilocks],
    opening_proof: &[Digest],
    index: usize,
    expected_root: Digest,
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    if leaf.is_empty() {
        return Err(TraceBuildError::EmptyLeaf);
    }
    if opening_proof.is_empty() {
        return Err(TraceBuildError::EmptyPath);
    }
    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let n_absorb = (leaf.len() + SPONGE_RATE - 1) / SPONGE_RATE;
    let n_compress = opening_proof.len();
    let physical_rows = n_absorb + n_compress;
    if physical_rows > trace_height {
        return Err(TraceBuildError::TraceHeightTooSmall {
            physical_rows,
            trace_height,
        });
    }

    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];
    let zero_g = Goldilocks::default();
    let perm = default_goldilocks_poseidon2_8();

    let write_kind = |out: &mut [Goldilocks], kind: u8| {
        for k in 0..NUM_OP_KINDS {
            out[col::KIND0 + k] =
                if k as u8 == kind { Goldilocks::new(1) } else { zero_g };
        }
    };
    let write_root_pi = |out: &mut [Goldilocks], root: &Digest| {
        for i in 0..DIGEST_WIDTH {
            out[col::TRACE_COMMIT_ROOT0 + i] = root[i];
        }
    };
    let write_block_len_flags = |out: &mut [Goldilocks], len: usize| {
        debug_assert!(len <= SPONGE_RATE);
        out[col::ABSORB_BLOCK_LEN] = Goldilocks::new(len as u64);
        for k in 0..=SPONGE_RATE {
            out[col::ABSORB_BLOCK_LEN_FLAG0 + k] =
                if k == len { Goldilocks::new(1) } else { zero_g };
        }
    };

    // ======================================================================
    // Phase A: ABSORB rows (leaf hash).
    // ======================================================================
    let mut state: [Goldilocks; SPONGE_WIDTH] = [zero_g; SPONGE_WIDTH];
    for r in 0..n_absorb {
        let base = r * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_ABSORB);

        let is_first = r == 0;
        let is_last = r + 1 == n_absorb;
        row[col::ABSORB_IS_FIRST] = if is_first { Goldilocks::new(1) } else { zero_g };
        row[col::ABSORB_IS_LAST] = if is_last { Goldilocks::new(1) } else { zero_g };

        let block_start = r * SPONGE_RATE;
        let block_len = core::cmp::min(SPONGE_RATE, leaf.len() - block_start);
        write_block_len_flags(row, block_len);
        for i in 0..block_len {
            row[col::ABSORB_BLOCK0 + i] = leaf[block_start + i];
        }
        // Positions [block_len..RATE] of BLOCK: pad with zero (unused).

        // Overwrite state[0..block_len]; keep the rest.
        for i in 0..block_len {
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
        // DIGEST column: on is_last, write the leaf digest; otherwise
        // write 0 (nothing consumes DIGEST until is_last).
        if is_last {
            for i in 0..DIGEST_WIDTH {
                row[col::DIGEST0 + i] = state[i];
            }
        }

        write_root_pi(row, &expected_root);

        // Populate the shared Poseidon2-w8 block.
        let p2_witness = gen_p2_witness({
            let mut s: [Goldilocks; SPONGE_WIDTH] = [zero_g; SPONGE_WIDTH];
            for i in 0..SPONGE_WIDTH {
                s[i] = row[col::STATE_IN0 + i];
            }
            s
        });
        for (i, v) in p2_witness.into_iter().enumerate() {
            row[col::P2_BLOCK + i] = v;
        }
    }

    // Simulate the Merkle walk off-circuit to compute per-level digests
    // (used to populate COMPRESS row state).
    let mut digests_per_row: Vec<Digest> = Vec::with_capacity(n_compress);
    let mut current: Digest = {
        let mut d = [zero_g; DIGEST_WIDTH];
        for i in 0..DIGEST_WIDTH {
            // State[0..4] at the end of the last ABSORB row.
            let last_absorb_base = (n_absorb - 1) * width;
            d[i] = flat[last_absorb_base + col::STATE_OUT0 + i];
        }
        d
    };
    let mut idx = index;
    for sibling in opening_proof {
        let (left, right) = if idx & 1 == 0 {
            (current, *sibling)
        } else {
            (*sibling, current)
        };
        current = compress_pair_ref(&perm, &left, &right);
        digests_per_row.push(current);
        idx >>= 1;
    }

    // ======================================================================
    // Phase B: COMPRESS rows.
    // ======================================================================
    let mut running: Digest = digests_per_row.first().copied().unwrap_or([zero_g; 4]);
    // Start with leaf_digest (STATE_OUT[0..4] of last ABSORB row).
    running = {
        let last_absorb_base = (n_absorb - 1) * width;
        let mut d = [zero_g; DIGEST_WIDTH];
        for i in 0..DIGEST_WIDTH {
            d[i] = flat[last_absorb_base + col::STATE_OUT0 + i];
        }
        d
    };
    let mut idx = index;
    for (r, sibling) in opening_proof.iter().enumerate() {
        let row_idx = n_absorb + r;
        let base = row_idx * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_COMPRESS);
        // COMPRESS rows have BLOCK_LEN = 0 (flag[0] = 1). The ABSORB
        // bank's flag-one-hot + weighted-sum constraints fire on
        // EVERY row, so this is mandatory even though the COMPRESS
        // bank ignores BLOCK_LEN.
        write_block_len_flags(row, 0);

        let bit = (idx & 1) as u64;
        let (left, right) = if bit == 0 {
            (running, *sibling)
        } else {
            (*sibling, running)
        };
        for i in 0..DIGEST_WIDTH {
            row[col::COMPRESS_CURRENT0 + i] = running[i];
            row[col::COMPRESS_SIBLING0 + i] = sibling[i];
        }
        row[col::COMPRESS_INDEX_BIT] = Goldilocks::new(bit);

        // STATE_IN = [LEFT ∥ RIGHT]; populates shared P2 input.
        for i in 0..DIGEST_WIDTH {
            row[col::STATE_IN0 + i] = left[i];
            row[col::STATE_IN0 + DIGEST_WIDTH + i] = right[i];
        }
        // Permute.
        let mut s: [Goldilocks; SPONGE_WIDTH] = [zero_g; SPONGE_WIDTH];
        for i in 0..SPONGE_WIDTH {
            s[i] = row[col::STATE_IN0 + i];
        }
        perm.permute_mut(&mut s);
        for i in 0..SPONGE_WIDTH {
            row[col::STATE_OUT0 + i] = s[i];
        }
        let new_digest = digests_per_row[r];
        debug_assert_eq!(&s[..DIGEST_WIDTH], &new_digest[..]);
        for i in 0..DIGEST_WIDTH {
            row[col::DIGEST0 + i] = new_digest[i];
        }

        write_root_pi(row, &expected_root);

        let p2_witness = gen_p2_witness(s);
        let _ = &perm; // the permutation was used above
        for (i, v) in p2_witness.into_iter().enumerate() {
            row[col::P2_BLOCK + i] = v;
        }
        // Recompute via helper for witness generation (overwrites above).
        let state_in_witness: [Goldilocks; SPONGE_WIDTH] = {
            let mut a = [zero_g; SPONGE_WIDTH];
            for i in 0..SPONGE_WIDTH {
                a[i] = row[col::STATE_IN0 + i];
            }
            a
        };
        let p2_witness2 = gen_p2_witness(state_in_witness);
        for (i, v) in p2_witness2.into_iter().enumerate() {
            row[col::P2_BLOCK + i] = v;
        }

        running = new_digest;
        idx >>= 1;
    }

    // ======================================================================
    // Phase C: IDLE padding rows.
    // ======================================================================
    let p2_zero_witness = gen_p2_witness_zero();
    for r in physical_rows..trace_height {
        let prev_base = (r - 1) * width;
        let prev_row = flat[prev_base..prev_base + width].to_vec();
        let base = r * width;
        let row = &mut flat[base..base + width];
        // Carry everything except KIND + ABSORB bank flags +
        // COMPRESS INDEX_BIT (these are row-specific selectors).
        for c in col::STATE_IN0..col::P2_BLOCK {
            row[c] = prev_row[c];
        }
        // Carry DIGEST for last-row==ROOT boundary propagation.
        // (Already included in STATE_IN0..P2_BLOCK range above.)
        write_kind(row, OP_KIND_IDLE);
        // Per-bank selectors that would contradict IDLE: reset.
        row[col::ABSORB_IS_FIRST] = zero_g;
        row[col::ABSORB_IS_LAST] = zero_g;
        // BLOCK_LEN flag = 0 on IDLE (marks BLOCK_LEN = 0).
        write_block_len_flags(row, 0);
        // P2 block gets the zero-input witness.
        for (i, v) in p2_zero_witness.iter().enumerate() {
            row[col::P2_BLOCK + i] = *v;
        }
    }

    Ok(flat)
}

// ---------------------------------------------------------------------------
// Boilerplate — the existing gen_p2_witness fn follows.
// ---------------------------------------------------------------------------

pub(crate) fn gen_p2_witness(input: [Goldilocks; 8]) -> Vec<Goldilocks> {
    use p3_goldilocks::{
        GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8, GenericPoseidon2LinearLayersGoldilocks,
    };
    use p3_poseidon2_air::{RoundConstants, generate_trace_rows};

    let constants: RoundConstants<
        Goldilocks,
        8,
        { p3_goldilocks::GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS },
        GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
    > = RoundConstants::new(
        p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
        p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
        p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    );
    let mat = generate_trace_rows::<
        Goldilocks,
        GenericPoseidon2LinearLayersGoldilocks,
        8,
        7,
        1,
        { p3_goldilocks::GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS },
        GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
    >(vec![input], &constants, 0);
    debug_assert_eq!(mat.values.len(), POSEIDON2_COLS_PER_INSTANCE);
    mat.values
}

// ---------------------------------------------------------------------------
// Plonky3 AIR (A3-PRE: skeleton that enforces KIND one-hot only)
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Default)]
pub struct MonolithicVerifierAirV1;

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for MonolithicVerifierAirV1 {
    #[inline]
    fn width(&self) -> usize {
        MONOLITHIC_VERIFIER_AIR_WIDTH
    }

    #[inline]
    fn num_public_values(&self) -> usize {
        0
    }

    #[inline]
    fn max_constraint_degree(&self) -> Option<usize> {
        // Once A3-1 wires in Poseidon2 + per-bank banks, S-box degree
        // 7 dominates. Use None for auto-compute to match the other
        // hash AIRs.
        None
    }
}

impl<AB> Air<AB> for MonolithicVerifierAirV1
where
    AB: AirBuilder<F = Goldilocks>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &[AB::Var] = main.current_slice();
        let next: &[AB::Var] = main.next_slice();

        let fe = |v: u64| AB::Expr::from(AB::F::from_u64(v));
        let zero = || fe(0);
        let one = || fe(1);

        let is_absorb: AB::Expr = local[col::KIND0 + OP_KIND_ABSORB as usize].into();
        let is_compress: AB::Expr =
            local[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        let is_fold: AB::Expr = local[col::KIND0 + OP_KIND_FOLD as usize].into();
        let is_alpha: AB::Expr = local[col::KIND0 + OP_KIND_ALPHA as usize].into();
        let is_idle: AB::Expr = local[col::KIND0 + OP_KIND_IDLE as usize].into();

        // =================================================================
        // KIND one-hot.
        // =================================================================
        let mut sum = zero();
        for k in 0..NUM_OP_KINDS {
            let flag: AB::Expr = local[col::KIND0 + k].into();
            builder.assert_zero(flag.clone() * (flag.clone() - one()));
            sum = sum + flag;
        }
        builder.assert_eq(sum, one());

        // =================================================================
        // A3-1: ABSORB bank (leaf-hash multi-block with partial-tail).
        // Ported from leaf_hash_air (d-7-a/b/c).
        // =================================================================

        // IS_FIRST / IS_LAST boolean; gated to ABSORB rows only.
        let is_first: AB::Expr = local[col::ABSORB_IS_FIRST].into();
        let is_last: AB::Expr = local[col::ABSORB_IS_LAST].into();
        builder.assert_zero(is_first.clone() * (is_first.clone() - one()));
        builder.assert_zero(is_last.clone() * (is_last.clone() - one()));
        builder.assert_zero((one() - is_absorb.clone()) * is_first.clone());
        builder.assert_zero((one() - is_absorb.clone()) * is_last.clone());

        // BLOCK_LEN flags: boolean + one-hot + weighted-sum match.
        let mut flag_sum = zero();
        let mut weighted = zero();
        for k in 0..=SPONGE_RATE {
            let f: AB::Expr = local[col::ABSORB_BLOCK_LEN_FLAG0 + k].into();
            builder.assert_zero(f.clone() * (f.clone() - one()));
            flag_sum = flag_sum + f.clone();
            weighted = weighted + fe(k as u64) * f;
        }
        builder.assert_eq(flag_sum, one());
        builder.assert_eq(weighted, AB::Expr::from(local[col::ABSORB_BLOCK_LEN]));

        // ABSORB rows: BLOCK_LEN ≥ 1 (flag[0] == 0).
        let flag0: AB::Expr = local[col::ABSORB_BLOCK_LEN_FLAG0].into();
        builder.assert_zero(is_absorb.clone() * flag0.clone());
        // IDLE rows: BLOCK_LEN == 0 (flag[0] == 1).
        builder.assert_zero(is_idle.clone() * (one() - flag0.clone()));
        // Non-last ABSORB rows: BLOCK_LEN == RATE (flag[RATE] == 1).
        let flag_rate: AB::Expr =
            local[col::ABSORB_BLOCK_LEN_FLAG0 + SPONGE_RATE].into();
        builder.assert_zero(
            is_absorb.clone() * (one() - is_last.clone()) * (one() - flag_rate),
        );

        // ABSORB first-row rule:
        //   STATE_IN[i] = cond_block_use[i] · BLOCK[i] for i in 0..RATE
        //              = 0                    for i in RATE..WIDTH
        //
        // where cond_block_use[i] = sum_{k > i} BLOCK_LEN_FLAG[k].
        for i in 0..SPONGE_WIDTH {
            let state_in_i: AB::Expr = local[col::STATE_IN0 + i].into();
            let mut cond_block = zero();
            for k in (i + 1)..=SPONGE_RATE {
                let f: AB::Expr = local[col::ABSORB_BLOCK_LEN_FLAG0 + k].into();
                cond_block = cond_block + f;
            }
            let block_term: AB::Expr = if i < SPONGE_RATE {
                cond_block * AB::Expr::from(local[col::ABSORB_BLOCK0 + i])
            } else {
                zero()
            };
            builder.assert_zero(is_first.clone() * (state_in_i - block_term));
        }

        // ABSORB is_last: DIGEST[0..4] == STATE_OUT[0..4].
        for i in 0..DIGEST_WIDTH {
            let dg: AB::Expr = local[col::DIGEST0 + i].into();
            let so: AB::Expr = local[col::STATE_OUT0 + i].into();
            builder.assert_zero(is_last.clone() * (dg - so));
        }

        // =================================================================
        // A3-1: COMPRESS bank (ported from compression_path_air).
        // =================================================================
        let bit: AB::Expr = local[col::COMPRESS_INDEX_BIT].into();
        builder.assert_zero(is_compress.clone() * bit.clone() * (bit.clone() - one()));

        // STATE_IN[0..4] = LEFT = (1 − bit)·CURRENT + bit·SIBLING
        // STATE_IN[4..8] = RIGHT = bit·CURRENT + (1 − bit)·SIBLING
        for i in 0..DIGEST_WIDTH {
            let cur: AB::Expr = local[col::COMPRESS_CURRENT0 + i].into();
            let sib: AB::Expr = local[col::COMPRESS_SIBLING0 + i].into();
            let s_l: AB::Expr = local[col::STATE_IN0 + i].into();
            let s_r: AB::Expr = local[col::STATE_IN0 + DIGEST_WIDTH + i].into();
            let expected_left =
                (one() - bit.clone()) * cur.clone() + bit.clone() * sib.clone();
            let expected_right =
                bit.clone() * cur + (one() - bit.clone()) * sib;
            builder.assert_zero(is_compress.clone() * (s_l - expected_left));
            builder.assert_zero(is_compress.clone() * (s_r - expected_right));
        }
        // DIGEST == STATE_OUT[0..4] on COMPRESS rows.
        for i in 0..DIGEST_WIDTH {
            let dg: AB::Expr = local[col::DIGEST0 + i].into();
            let so: AB::Expr = local[col::STATE_OUT0 + i].into();
            builder.assert_zero(is_compress.clone() * (dg - so));
        }

        // =================================================================
        // Shared Poseidon2-w8 sub-AIR: binds STATE_OUT = P2(STATE_IN) on
        // both ABSORB and COMPRESS rows.
        // =================================================================
        let p2_local = p2_group::<AB::Var>(local);
        eval_poseidon2(builder, p2_local);

        let hash_row = is_absorb.clone() + is_compress.clone();
        for i in 0..SPONGE_WIDTH {
            let p2_in: AB::Expr = p2_local.inputs[i].into();
            let s_in: AB::Expr = local[col::STATE_IN0 + i].into();
            builder.assert_zero(hash_row.clone() * (p2_in - s_in));
        }
        let p2_post = &p2_local.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
        for i in 0..SPONGE_WIDTH {
            let p2_out: AB::Expr = p2_post[i].into();
            let s_out: AB::Expr = local[col::STATE_OUT0 + i].into();
            builder.assert_zero(hash_row.clone() * (p2_out - s_out));
        }

        // =================================================================
        // Transition constraints.
        // =================================================================
        let mut trans = builder.when_transition();

        // TRACE_COMMIT_ROOT persists across all rows.
        for i in 0..DIGEST_WIDTH {
            let l_r: AB::Expr = local[col::TRACE_COMMIT_ROOT0 + i].into();
            let n_r: AB::Expr = next[col::TRACE_COMMIT_ROOT0 + i].into();
            trans.assert_zero(n_r - l_r);
        }

        // Leaf-digest bridge: when local is is_last ABSORB and next is
        // COMPRESS, next.CURRENT == local.STATE_OUT[0..4]. This closes
        // the A2 trusted-construction gap.
        let next_is_compress: AB::Expr =
            next[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        for i in 0..DIGEST_WIDTH {
            let n_cur: AB::Expr = next[col::COMPRESS_CURRENT0 + i].into();
            let l_out: AB::Expr = local[col::STATE_OUT0 + i].into();
            trans.assert_zero(
                is_last.clone() * next_is_compress.clone() * (n_cur - l_out),
            );
        }

        // COMPRESS → COMPRESS: next.CURRENT = local.DIGEST.
        let next_is_compress_prop: AB::Expr =
            next[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        for i in 0..DIGEST_WIDTH {
            let n_cur: AB::Expr = next[col::COMPRESS_CURRENT0 + i].into();
            let l_dg: AB::Expr = local[col::DIGEST0 + i].into();
            trans.assert_zero(
                is_compress.clone() * next_is_compress_prop.clone() * (n_cur - l_dg),
            );
        }

        // IDLE persistence — all shared-state + public-input cols
        // preserved across IDLE transitions. Bounded to [STATE_IN0,
        // P2_BLOCK) to avoid flagging the P2 block (which is re-generated
        // with the zero-input witness on IDLE rows).
        let next_is_idle: AB::Expr = next[col::KIND0 + OP_KIND_IDLE as usize].into();
        for c in col::STATE_IN0..col::P2_BLOCK {
            let l_c: AB::Expr = local[c].into();
            let n_c: AB::Expr = next[c].into();
            trans.assert_zero(next_is_idle.clone() * (n_c - l_c));
        }

        // ABSORB capacity carry on ABSORB-after-ABSORB:
        //   next.STATE_IN[i] =
        //       next.cond_block_use[i] · next.BLOCK[i]
        //     + next.cond_carry[i]   · local.STATE_OUT[i]
        //
        // Gated by (next_is_absorb · (1 − next_is_first)).
        let next_is_absorb: AB::Expr =
            next[col::KIND0 + OP_KIND_ABSORB as usize].into();
        let next_is_first: AB::Expr = next[col::ABSORB_IS_FIRST].into();
        let carry_gate = next_is_absorb * (one() - next_is_first);
        for i in 0..SPONGE_WIDTH {
            let n_in: AB::Expr = next[col::STATE_IN0 + i].into();
            let l_out: AB::Expr = local[col::STATE_OUT0 + i].into();
            let mut cond_block = zero();
            for k in (i + 1)..=SPONGE_RATE {
                let f: AB::Expr = next[col::ABSORB_BLOCK_LEN_FLAG0 + k].into();
                cond_block = cond_block + f;
            }
            let mut cond_carry = zero();
            for k in 0..=i.min(SPONGE_RATE) {
                let f: AB::Expr = next[col::ABSORB_BLOCK_LEN_FLAG0 + k].into();
                cond_carry = cond_carry + f;
            }
            let block_term: AB::Expr = if i < SPONGE_RATE {
                cond_block * AB::Expr::from(next[col::ABSORB_BLOCK0 + i])
            } else {
                zero()
            };
            let carry_term = cond_carry * l_out;
            trans.assert_zero(carry_gate.clone() * (n_in - block_term - carry_term));
        }

        drop(trans);

        // =================================================================
        // Boundary: last row's DIGEST (propagated via IDLE persistence)
        // equals TRACE_COMMIT_ROOT.
        //
        // IDLE persistence: STATE_IN0..P2_BLOCK range includes DIGEST,
        // so the last compression's DIGEST propagates forward to the
        // trace's last row.
        // =================================================================
        let mut last = builder.when_last_row();
        for i in 0..DIGEST_WIDTH {
            let dg: AB::Expr = local[col::DIGEST0 + i].into();
            let r: AB::Expr = local[col::TRACE_COMMIT_ROOT0 + i].into();
            last.assert_zero(dg - r);
        }

        // Silence unused warnings for FOLD/ALPHA banks (A3-2).
        let _ = (is_fold, is_alpha);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_layout_is_stable() {
        // Pin the layout at A3-PRE. Follow-up sub-phases must NOT change
        // these offsets, or downstream column-share logic breaks.
        //
        // If you land a legitimate refactor that shifts offsets, update
        // this test AND doc/uno-aggregation-path-decision.md §A3-PRE.
        assert_eq!(col::KIND0, 0);
        assert_eq!(col::KIND_END, 5);
        assert_eq!(col::ABSORB_BLOCK0, 5);
        assert_eq!(col::P2_BLOCK % 1, 0); // just a syntactic no-op
        assert_eq!(col::WIDTH, col::P2_BLOCK + POSEIDON2_COLS_PER_INSTANCE);
    }

    #[test]
    fn trivial_trace_builds_any_pow2_height() {
        for h in [4, 8, 16, 32] {
            let flat = build_trivial_trace(h).expect("build");
            assert_eq!(flat.len(), h * col::WIDTH);
        }
    }

    #[test]
    fn trivial_trace_rejects_non_pow2() {
        let err = build_trivial_trace(7).unwrap_err();
        assert_eq!(err, TraceBuildError::TraceHeightNotPow2 { got: 7 });
    }

    /// The A3-PRE acceptance test: a trivial all-IDLE trace prove+verifies.
    /// Proves the scaffolding round-trips cleanly and the Poseidon2
    /// witness block populates correctly.
    #[test]
    fn air_prove_and_verify_trivial_idle_trace() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let flat = build_trivial_trace(16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[]).expect("trivial IDLE trace must verify");
    }

    #[test]
    fn air_rejects_broken_kind_onehot() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let mut flat = build_trivial_trace(16).unwrap();
        // Set KIND_ABSORB = 1 on row 0 (which already has KIND_IDLE = 1).
        flat[col::KIND0 + OP_KIND_ABSORB as usize] = Goldilocks::new(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &[])
        }));
        match outcome {
            Err(_) => {} // debug-builder panic on broken one-hot
            Ok(p) => {
                verify(&cfg, &air, &p, &[])
                    .expect_err("broken KIND one-hot must reject");
            }
        }
    }

    /// Report the column width to stdout — useful for A3-1 planning.
    #[test]
    fn print_column_layout() {
        eprintln!("MonolithicVerifierAir layout (A3-PRE):");
        eprintln!("  KIND           : 0 .. {}  ({} cols)", col::KIND_END, col::KIND_END);
        eprintln!(
            "  ABSORB bank    : {} .. {}",
            col::ABSORB_BLOCK0, col::ABSORB_IS_LAST + 1
        );
        eprintln!(
            "  COMPRESS bank  : {} .. {}",
            col::COMPRESS_CURRENT0, col::COMPRESS_INDEX_BIT + 1
        );
        eprintln!(
            "  STATE (shared) : {} .. {}",
            col::STATE_IN0, col::DIGEST_END
        );
        eprintln!("  FOLD bank      : {} .. {}", col::FOLD_BETA0, col::FOLD_OUT_END);
        eprintln!("  ALPHA bank     : {} .. {}", col::ALPHA_CHALLENGE0, col::ALPHA_RO_OUT_END);
        eprintln!(
            "  Public-input   : {} .. {}",
            col::TRACE_COMMIT_ROOT0, col::FINAL_FOLDED_END
        );
        eprintln!(
            "  P2 block       : {} .. {}  ({} cols)",
            col::P2_BLOCK, col::WIDTH, POSEIDON2_COLS_PER_INSTANCE
        );
        eprintln!("  TOTAL WIDTH    : {}", col::WIDTH);
    }

    // ======================================================================
    // A3-1: ABSORB + COMPRESS banks — "wide leaf → root" single STARK
    // ======================================================================

    fn gl(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    /// Hand-built tiny Merkle tree over 4 width-8 leaves.
    /// Returns (leaves, openings_per_leaf, root).
    #[allow(clippy::type_complexity)]
    fn tiny_tree_wide_leaves() -> (
        Vec<Vec<Goldilocks>>,
        Vec<(Digest, Vec<Digest>, usize)>,
        Digest,
    ) {
        let perm = default_goldilocks_poseidon2_8();
        let leaves: Vec<Vec<Goldilocks>> = (0..4u64)
            .map(|i| (0..8u64).map(|j| gl(i * 100 + j * 13 + 1)).collect())
            .collect();
        let leaf_digests: Vec<Digest> =
            leaves.iter().map(|l| hash_leaf_row_ref(&perm, l)).collect();
        let level1 = vec![
            compress_pair_ref(&perm, &leaf_digests[0], &leaf_digests[1]),
            compress_pair_ref(&perm, &leaf_digests[2], &leaf_digests[3]),
        ];
        let root = compress_pair_ref(&perm, &level1[0], &level1[1]);

        let mut openings = Vec::with_capacity(4);
        for idx in 0..4usize {
            let sib0 = leaf_digests[idx ^ 1];
            let sib1 = if (idx >> 1) & 1 == 0 {
                level1[1]
            } else {
                level1[0]
            };
            openings.push((leaf_digests[idx], vec![sib0, sib1], idx));
        }
        (leaves, openings, root)
    }

    #[test]
    fn air_prove_and_verify_leaf_to_root_width_8_leaf_0() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[0].clone();
        // 2 absorb (W=8 / RATE=4) + 2 compress = 4 physical rows; pad to 16.
        let flat = build_leaf_to_root_trace(&leaves[0], &path, idx, root, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[])
            .expect("width-8 leaf → root must verify end-to-end in ONE STARK");
    }

    #[test]
    fn air_prove_and_verify_leaf_to_root_all_tiny_leaves() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        for (leaf_idx, (_, path, idx)) in openings.iter().enumerate() {
            let flat = build_leaf_to_root_trace(&leaves[leaf_idx], path, *idx, root, 16)
                .expect("build");
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &[]);
            verify(&cfg, &air, &proof, &[])
                .unwrap_or_else(|e| panic!("leaf {leaf_idx}: {e:?}"));
        }
    }

    #[test]
    fn air_rejects_tampered_wide_leaf() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[0].clone();
        let mut flat = build_leaf_to_root_trace(&leaves[0], &path, idx, root, 16).unwrap();
        // Corrupt the first ABSORB row's BLOCK[0]: the P2 chain breaks,
        // the leaf digest differs, the bridge fails, and ultimately the
        // last-row DIGEST ≠ ROOT.
        flat[col::ABSORB_BLOCK0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &[])
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &[])
                    .expect_err("tampered wide leaf must reject");
            }
        }
    }

    #[test]
    fn air_rejects_wrong_expected_root() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[0].clone();
        let mut bad_root = root;
        bad_root[0] += gl(1);
        // Build with bad root pinned on every row; last-row DIGEST is
        // the REAL root, which differs — last-row boundary fires.
        let flat = build_leaf_to_root_trace(&leaves[0], &path, idx, bad_root, 16)
            .expect("build");
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &[])
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &[])
                    .expect_err("wrong root must reject at last-row boundary");
            }
        }
    }

    /// A3-1 acceptance: the bridge between last-absorb DIGEST and
    /// first-compress CURRENT is an in-circuit constraint, not a
    /// trusted-by-construction assertion. Directly tampering the
    /// first COMPRESS row's CURRENT must cause rejection via the
    /// `is_last · next_is_compress · (next.CURRENT − local.STATE_OUT)`
    /// transition bank.
    #[test]
    fn air_rejects_forged_bridge_between_absorb_and_compress() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[0].clone();
        let mut flat = build_leaf_to_root_trace(&leaves[0], &path, idx, root, 16).unwrap();
        // Row 0, 1: ABSORB (W=8, 2 blocks). Row 2: first COMPRESS.
        // Tamper row 2's CURRENT[0] so it doesn't equal row 1's
        // STATE_OUT[0]. The bridge constraint is
        // is_last · next_is_compress · (next.CURRENT − local.STATE_OUT)
        // on the (row1, row2) transition — this fires.
        let row2 = 2 * col::WIDTH;
        flat[row2 + col::COMPRESS_CURRENT0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &[])
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &[]).expect_err(
                    "forged leaf-digest bridge must reject — A3-1 closes A2's construction gap",
                );
            }
        }
    }
}
