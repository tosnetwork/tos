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

use crate::fri_arith::fold_row_ref;
use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref, Digest};
use crate::prover::Challenge;
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
/// Binomial-extension norm constant for Goldilocks D = 2.
/// Must match `<Goldilocks as BinomiallyExtendable<2>>::W`.
pub const EXT_W_U64: u64 = 7;

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
    /// Fold chain's initial running folded value. A3-3 binds this to
    /// the α-chain's FINAL_RO via an in-circuit `assert_eq`.
    pub const INITIAL_FOLDED0: usize = FINAL_FOLDED_END;
    pub const INITIAL_FOLDED_END: usize = INITIAL_FOLDED0 + CHALLENGE_DIM;
    /// Expected final RO from the α-reduction chain.
    pub const FINAL_RO0: usize = INITIAL_FOLDED_END;
    pub const FINAL_RO_END: usize = FINAL_RO0 + CHALLENGE_DIM;

    /// Base offset of the shared Poseidon2-w8 sub-AIR witness block.
    pub const P2_BLOCK: usize = FINAL_RO_END;

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
// A3-5a trace builder: multiple independent Merkle paths in ONE trace.
//
// Each path is a (leaf, opening_proof, index, expected_root) tuple. The
// trace emits each path's ABSORB rows (leaf hash) + COMPRESS rows
// (Merkle walk), then pads with IDLE.
//
// Constraint model (A3-5a):
//   - TRACE_COMMIT_ROOT persists within a COMPRESS run but is FREE
//     at ABSORB rows (between paths). The builder writes the current
//     path's expected_root on every COMPRESS row of that path.
//   - The per-path root check fires at each path's COMPRESS → non-
//     COMPRESS transition: local.DIGEST == local.TRACE_COMMIT_ROOT.
//   - The last-row boundary fires only if is_compress; otherwise IDLE
//     persistence carries the last path's root through to the last row.
// ---------------------------------------------------------------------------

/// A single Merkle opening for the multi-path builder.
#[derive(Clone, Debug)]
pub struct MerkleOpening<'a> {
    /// Leaf row (base-field values).
    pub leaf: &'a [Goldilocks],
    /// Sibling digests, least-significant-level first.
    pub opening_proof: &'a [Digest],
    /// Leaf index (low bits drive INDEX_BIT orientation).
    pub index: usize,
    /// Expected root at the end of this path.
    pub expected_root: Digest,
}

/// Build a trace that verifies multiple independent Merkle openings in
/// ONE monolithic STARK. Each opening runs its ABSORB rows then its
/// COMPRESS rows; IDLE padding fills the remainder.
pub fn build_multi_path_leaf_to_root_trace(
    paths: &[MerkleOpening<'_>],
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    if paths.is_empty() {
        return Err(TraceBuildError::EmptyPath);
    }
    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    // Sum physical rows across all paths.
    let mut physical_rows = 0usize;
    for p in paths {
        if p.leaf.is_empty() {
            return Err(TraceBuildError::EmptyLeaf);
        }
        if p.opening_proof.is_empty() {
            return Err(TraceBuildError::EmptyPath);
        }
        let n_absorb = (p.leaf.len() + SPONGE_RATE - 1) / SPONGE_RATE;
        let n_compress = p.opening_proof.len();
        physical_rows += n_absorb + n_compress;
    }
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

    let mut row_cursor: usize = 0;

    for path in paths {
        let n_absorb = (path.leaf.len() + SPONGE_RATE - 1) / SPONGE_RATE;
        let n_compress = path.opening_proof.len();

        // === ABSORB rows ===
        let mut state: [Goldilocks; SPONGE_WIDTH] = [zero_g; SPONGE_WIDTH];
        for r in 0..n_absorb {
            let base = (row_cursor + r) * width;
            let row = &mut flat[base..base + width];
            write_kind(row, OP_KIND_ABSORB);

            let is_first = r == 0;
            let is_last = r + 1 == n_absorb;
            row[col::ABSORB_IS_FIRST] = if is_first { Goldilocks::new(1) } else { zero_g };
            row[col::ABSORB_IS_LAST] = if is_last { Goldilocks::new(1) } else { zero_g };

            let block_start = r * SPONGE_RATE;
            let block_len = core::cmp::min(SPONGE_RATE, path.leaf.len() - block_start);
            write_block_len_flags(row, block_len);
            for i in 0..block_len {
                row[col::ABSORB_BLOCK0 + i] = path.leaf[block_start + i];
            }

            if is_first {
                // Reset state at the start of each path.
                state = [zero_g; SPONGE_WIDTH];
            }
            for i in 0..block_len {
                state[i] = path.leaf[block_start + i];
            }
            for i in 0..SPONGE_WIDTH {
                row[col::STATE_IN0 + i] = state[i];
            }
            perm.permute_mut(&mut state);
            for i in 0..SPONGE_WIDTH {
                row[col::STATE_OUT0 + i] = state[i];
            }
            if is_last {
                for i in 0..DIGEST_WIDTH {
                    row[col::DIGEST0 + i] = state[i];
                }
            }
            // TRACE_COMMIT_ROOT on ABSORB rows is free, but writing the
            // path's expected root here gives a clean audit trail.
            write_root_pi(row, &path.expected_root);

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

        // === COMPRESS rows ===
        let mut running: Digest = {
            let last_absorb_base = (row_cursor + n_absorb - 1) * width;
            let mut d = [zero_g; DIGEST_WIDTH];
            for i in 0..DIGEST_WIDTH {
                d[i] = flat[last_absorb_base + col::STATE_OUT0 + i];
            }
            d
        };
        let mut idx = path.index;
        for (r, sibling) in path.opening_proof.iter().enumerate() {
            let row_idx = row_cursor + n_absorb + r;
            let base = row_idx * width;
            let row = &mut flat[base..base + width];
            write_kind(row, OP_KIND_COMPRESS);
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
            for i in 0..DIGEST_WIDTH {
                row[col::STATE_IN0 + i] = left[i];
                row[col::STATE_IN0 + DIGEST_WIDTH + i] = right[i];
            }
            let mut s: [Goldilocks; SPONGE_WIDTH] = [zero_g; SPONGE_WIDTH];
            for i in 0..SPONGE_WIDTH {
                s[i] = row[col::STATE_IN0 + i];
            }
            // Capture pre-permute state for the P2 witness; `gen_p2_witness`
            // needs the input, not the output.
            let state_in_values = s;
            perm.permute_mut(&mut s);
            for i in 0..SPONGE_WIDTH {
                row[col::STATE_OUT0 + i] = s[i];
            }
            let new_digest: Digest = {
                let mut d = [zero_g; DIGEST_WIDTH];
                for i in 0..DIGEST_WIDTH {
                    d[i] = s[i];
                }
                d
            };
            for i in 0..DIGEST_WIDTH {
                row[col::DIGEST0 + i] = new_digest[i];
            }
            write_root_pi(row, &path.expected_root);

            let p2_witness = gen_p2_witness(state_in_values);
            for (i, v) in p2_witness.into_iter().enumerate() {
                row[col::P2_BLOCK + i] = v;
            }

            running = new_digest;
            idx >>= 1;
        }

        // Sanity: final digest equals the path's expected root.
        debug_assert_eq!(
            running, path.expected_root,
            "multi-path builder: path digest doesn't match expected_root",
        );

        row_cursor += n_absorb + n_compress;
    }

    // === IDLE padding ===
    let p2_zero_witness = gen_p2_witness_zero();
    for r in physical_rows..trace_height {
        let prev_base = (r - 1) * width;
        let prev_row = flat[prev_base..prev_base + width].to_vec();
        let base = r * width;
        let row = &mut flat[base..base + width];
        for c in col::STATE_IN0..col::P2_BLOCK {
            row[c] = prev_row[c];
        }
        write_kind(row, OP_KIND_IDLE);
        row[col::ABSORB_IS_FIRST] = zero_g;
        row[col::ABSORB_IS_LAST] = zero_g;
        write_block_len_flags(row, 0);
        for (i, v) in p2_zero_witness.iter().enumerate() {
            row[col::P2_BLOCK + i] = *v;
        }
    }

    Ok(flat)
}

// ---------------------------------------------------------------------------
// A3-2 trace builders: ALPHA-only and FOLD-only chains.
//
// These are standalone test traces — they exercise the ALPHA / FOLD
// banks in isolation. Row 0..N is the chain; the rest is IDLE padding.
// Non-bank cols are set to values that satisfy the "foreign" boundary
// constraints trivially (e.g. TRACE_COMMIT_ROOT = DIGEST = 0 ensures
// the ABSORB/COMPRESS boundary `DIGEST == ROOT` at last row holds; the
// fold-only trace sets ALPHA_RO_OUT = FINAL_RO = 0 on every row so the
// α-chain last-row boundary holds trivially; analogous for α-only).
// A3-3 wires cross-bindings between the chains.
// ---------------------------------------------------------------------------

/// One step of the α-reduction chain.
#[derive(Clone, Debug)]
pub struct AlphaStep {
    /// Base-field opening at query-domain point `x`.
    pub p_at_x: Goldilocks,
    /// Extension opening at point `z`.
    pub p_at_z: Challenge,
    /// Evaluation point `z`.
    pub z: Challenge,
    /// Query-domain base-field point `x`.
    pub x: Goldilocks,
}

/// Build a monolithic-AIR trace that verifies a single α-reduction
/// chain of `steps.len()` ALPHA rows, padded with IDLE.
///
/// * `initial_alpha_pow`, `initial_ro` : seed values for row 0.
/// * `alpha`                            : persistent FRI α challenge.
/// * `steps`                            : per-row claimed evaluations.
/// * `final_ro`                         : expected RO after last step.
///
/// Non-α data cols are kept at zero on every row so the other banks'
/// boundary constraints hold trivially.
pub fn build_alpha_chain_trace(
    initial_alpha_pow: Challenge,
    initial_ro: Challenge,
    alpha: Challenge,
    steps: &[AlphaStep],
    final_ro: Challenge,
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    use p3_field::{BasedVectorSpace, Field};

    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let physical_rows = steps.len();
    if physical_rows == 0 {
        return Err(TraceBuildError::EmptyPath);
    }
    if physical_rows > trace_height {
        return Err(TraceBuildError::TraceHeightTooSmall {
            physical_rows,
            trace_height,
        });
    }

    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];
    let zero_g = Goldilocks::default();

    let write_ext = |out: &mut [Goldilocks], base: usize, v: Challenge| {
        let limbs =
            <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&v);
        for i in 0..CHALLENGE_DIM {
            out[base + i] = limbs[i];
        }
    };
    let write_kind = |out: &mut [Goldilocks], kind: u8| {
        for k in 0..NUM_OP_KINDS {
            out[col::KIND0 + k] =
                if k as u8 == kind { Goldilocks::new(1) } else { zero_g };
        }
    };
    // Flag[0] = 1 on every non-ABSORB row (BLOCK_LEN = 0).
    let zero_block_len_flag = |out: &mut [Goldilocks]| {
        out[col::ABSORB_BLOCK_LEN_FLAG0] = Goldilocks::new(1);
    };

    let mut alpha_pow = initial_alpha_pow;
    let mut ro = initial_ro;
    let p2_zero_witness = gen_p2_witness_zero();

    for (r, step) in steps.iter().enumerate() {
        let base = r * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_ALPHA);
        zero_block_len_flag(row);

        // Per-step claimed values.
        row[col::ALPHA_P_AT_X] = step.p_at_x;
        write_ext(row, col::ALPHA_P_AT_Z0, step.p_at_z);
        write_ext(row, col::ALPHA_Z0, step.z);
        row[col::ALPHA_X] = step.x;

        // Witness: (z − x)^{-1}.
        let denom = step.z - step.x;
        if denom.is_zero() {
            return Err(TraceBuildError::TraceHeightTooSmall {
                physical_rows: r,
                trace_height,
            });
        }
        let quot_inv = denom
            .try_inverse()
            .expect("denom ≠ 0 ⇒ invertible");
        write_ext(row, col::ALPHA_QUOT_INV0, quot_inv);

        // Intermediate: DIFF_QUOT = (p_z − p_x) · quot_inv.
        let diff = step.p_at_z - step.p_at_x;
        let diff_quot = diff * quot_inv;
        write_ext(row, col::ALPHA_DIFF_QUOT0, diff_quot);

        // Chain state.
        write_ext(row, col::ALPHA_CHALLENGE0, alpha);
        write_ext(row, col::ALPHA_POW_IN0, alpha_pow);
        let new_alpha_pow = alpha_pow * alpha;
        write_ext(row, col::ALPHA_POW_OUT0, new_alpha_pow);
        write_ext(row, col::ALPHA_RO_IN0, ro);
        let new_ro = ro + alpha_pow * diff_quot;
        write_ext(row, col::ALPHA_RO_OUT0, new_ro);

        // PI proxies.
        write_ext(row, col::INITIAL_ALPHA_POW0, initial_alpha_pow);
        write_ext(row, col::INITIAL_RO0, initial_ro);
        write_ext(row, col::FINAL_RO0, final_ro);
        // FOLD/FINAL_FOLDED/INITIAL_FOLDED remain zero (boundary holds
        // trivially since FOLD_OUT = FINAL_FOLDED = 0).

        // Zero-input P2 witness; P2 block is unconstrained on ALPHA.
        for (i, v) in p2_zero_witness.iter().enumerate() {
            row[col::P2_BLOCK + i] = *v;
        }

        alpha_pow = new_alpha_pow;
        ro = new_ro;
    }

    // Pad with IDLE.
    for row_idx in physical_rows..trace_height {
        let prev_base = (row_idx - 1) * width;
        let prev_row = flat[prev_base..prev_base + width].to_vec();
        let base = row_idx * width;
        let row = &mut flat[base..base + width];
        for c in col::STATE_IN0..col::P2_BLOCK {
            row[c] = prev_row[c];
        }
        write_kind(row, OP_KIND_IDLE);
        zero_block_len_flag(row);
        row[col::ABSORB_IS_FIRST] = zero_g;
        row[col::ABSORB_IS_LAST] = zero_g;
        for (i, v) in p2_zero_witness.iter().enumerate() {
            row[col::P2_BLOCK + i] = *v;
        }
    }

    Ok(flat)
}

/// One round of the FRI fold chain.
#[derive(Clone, Debug)]
pub struct FoldRound {
    /// Sibling opening at this round (Challenge).
    pub sibling: Challenge,
    /// FRI fold challenge β_r (Challenge).
    pub beta: Challenge,
    /// Domain index at the START of this round (low bit → INDEX_BIT).
    pub domain_index: usize,
    /// Log-height of the FRI codeword BEFORE this fold.
    pub log_height: usize,
}

/// Build a monolithic-AIR trace that verifies a fold chain of
/// `rounds.len()` FOLD rows, padded with IDLE.
///
/// Non-FOLD data cols are kept at zero so other banks' boundaries hold.
pub fn build_fold_chain_trace(
    initial_folded: Challenge,
    rounds: &[FoldRound],
    final_folded: Challenge,
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    use p3_field::{BasedVectorSpace, Field, TwoAdicField};
    use p3_util::reverse_bits_len;

    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let physical_rows = rounds.len();
    if physical_rows == 0 {
        return Err(TraceBuildError::EmptyPath);
    }
    if physical_rows > trace_height {
        return Err(TraceBuildError::TraceHeightTooSmall {
            physical_rows,
            trace_height,
        });
    }

    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];
    let zero_g = Goldilocks::default();
    let write_ext = |out: &mut [Goldilocks], base: usize, v: Challenge| {
        let limbs =
            <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&v);
        for i in 0..CHALLENGE_DIM {
            out[base + i] = limbs[i];
        }
    };
    let write_kind = |out: &mut [Goldilocks], kind: u8| {
        for k in 0..NUM_OP_KINDS {
            out[col::KIND0 + k] =
                if k as u8 == kind { Goldilocks::new(1) } else { zero_g };
        }
    };
    let zero_block_len_flag = |out: &mut [Goldilocks]| {
        out[col::ABSORB_BLOCK_LEN_FLAG0] = Goldilocks::new(1);
    };

    let p2_zero_witness = gen_p2_witness_zero();

    let mut current = initial_folded;
    for (r, round) in rounds.iter().enumerate() {
        let base = r * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_FOLD);
        zero_block_len_flag(row);

        let bit = (round.domain_index & 1) as u64;
        let child_log_h = round.log_height - 1;
        let parent_idx = round.domain_index >> 1;
        let g_outer = Goldilocks::two_adic_generator(child_log_h + 1);
        let rev = reverse_bits_len(parent_idx, child_log_h);
        let s = g_outer.exp_u64(rev as u64);
        if s == zero_g {
            return Err(TraceBuildError::TraceHeightTooSmall {
                physical_rows: r,
                trace_height,
            });
        }
        let two_s = s * Goldilocks::new(2);
        let inv_2s = two_s
            .try_inverse()
            .expect("2s ≠ 0 ⇒ invertible in Goldilocks");

        let (pair_left, pair_right) = if bit == 0 {
            (current, round.sibling)
        } else {
            (round.sibling, current)
        };
        let folded = fold_row_ref(
            parent_idx,
            child_log_h,
            1, // log_arity = 1 (binary FRI)
            round.beta,
            &[pair_left, pair_right],
        );

        // Write FOLD-bank cols.
        write_ext(row, col::FOLD_IN0, current);
        write_ext(row, col::FOLD_OUT0, folded);
        write_ext(row, col::FOLD_BETA0, round.beta);
        row[col::FOLD_S] = s;
        row[col::FOLD_INV_2S] = inv_2s;

        // Shared cols:
        //   COMPRESS_SIBLING[0..2] ← sibling (2 of 4)
        //   COMPRESS_INDEX_BIT     ← bit
        //   STATE_IN[0..2]         ← PAIR_LEFT
        //   STATE_IN[2..4]         ← PAIR_RIGHT
        write_ext(row, col::COMPRESS_SIBLING0, round.sibling);
        row[col::COMPRESS_INDEX_BIT] = Goldilocks::new(bit);
        write_ext(row, col::STATE_IN0, pair_left);
        write_ext(row, col::STATE_IN0 + CHALLENGE_DIM, pair_right);

        // PI proxies.
        write_ext(row, col::INITIAL_FOLDED0, initial_folded);
        write_ext(row, col::FINAL_FOLDED0, final_folded);

        for (i, v) in p2_zero_witness.iter().enumerate() {
            row[col::P2_BLOCK + i] = *v;
        }

        current = folded;
    }

    // Pad with IDLE.
    for row_idx in physical_rows..trace_height {
        let prev_base = (row_idx - 1) * width;
        let prev_row = flat[prev_base..prev_base + width].to_vec();
        let base = row_idx * width;
        let row = &mut flat[base..base + width];
        for c in col::STATE_IN0..col::P2_BLOCK {
            row[c] = prev_row[c];
        }
        write_kind(row, OP_KIND_IDLE);
        zero_block_len_flag(row);
        row[col::ABSORB_IS_FIRST] = zero_g;
        row[col::ABSORB_IS_LAST] = zero_g;
        for (i, v) in p2_zero_witness.iter().enumerate() {
            row[col::P2_BLOCK + i] = *v;
        }
    }

    Ok(flat)
}

// ---------------------------------------------------------------------------
// A3-3 trace builder: unified ALPHA + FOLD chain
//
// Layout:
//   rows 0..N_alpha            : ALPHA rows (α-reduction chain)
//   rows N_alpha..N_alpha+N_fd : FOLD  rows (fold chain, seeded by α's ρ)
//   rows N_alpha+N_fd..height  : IDLE  padding
//
// Cross-binding invariants populated off-circuit:
//   - Last α row's ALPHA_RO_OUT = ρ_final.
//   - First FOLD row's FOLD_IN  = ρ_final (enforced by the A3-3 α→FOLD
//     bridge; the trace builder sets it this way so the bridge holds).
//   - On every α row, FOLD_OUT = ρ_final (so A3-3 non-fold persistence
//     holds on α→α transitions; the FOLD threading on α→FOLD then
//     reads local.FOLD_OUT = ρ_final, agreeing with the bridge).
//   - ALPHA_RO_OUT persists at ρ_final through FOLD + IDLE rows (so
//     the unconditional last-row `ALPHA_RO_OUT == FINAL_RO` holds).
// ---------------------------------------------------------------------------

/// Build a trace that verifies α-reduction followed by FRI fold as
/// ONE monolithic STARK. This is the A3-3 acceptance trace.
pub fn build_alpha_to_fold_unified_trace(
    initial_alpha_pow: Challenge,
    initial_ro: Challenge,
    alpha: Challenge,
    alpha_steps: &[AlphaStep],
    fold_rounds: &[FoldRound],
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    use p3_field::{BasedVectorSpace, Field, TwoAdicField};
    use p3_util::reverse_bits_len;

    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let n_alpha = alpha_steps.len();
    let n_fold = fold_rounds.len();
    if n_alpha == 0 || n_fold == 0 {
        return Err(TraceBuildError::EmptyPath);
    }
    let physical_rows = n_alpha + n_fold;
    if physical_rows > trace_height {
        return Err(TraceBuildError::TraceHeightTooSmall {
            physical_rows,
            trace_height,
        });
    }

    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];
    let zero_g = Goldilocks::default();
    let write_ext = |out: &mut [Goldilocks], base: usize, v: Challenge| {
        let limbs =
            <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&v);
        for i in 0..CHALLENGE_DIM {
            out[base + i] = limbs[i];
        }
    };
    let write_kind = |out: &mut [Goldilocks], kind: u8| {
        for k in 0..NUM_OP_KINDS {
            out[col::KIND0 + k] =
                if k as u8 == kind { Goldilocks::new(1) } else { zero_g };
        }
    };
    let zero_block_len_flag = |out: &mut [Goldilocks]| {
        out[col::ABSORB_BLOCK_LEN_FLAG0] = Goldilocks::new(1);
    };

    let p2_zero_witness = gen_p2_witness_zero();

    // --- Pass 1: run α chain off-circuit to compute ρ_final. ---
    let mut apow = initial_alpha_pow;
    let mut ro = initial_ro;
    let mut step_records: Vec<(Challenge, Challenge, Challenge, Challenge)> =
        Vec::with_capacity(n_alpha);
    for step in alpha_steps {
        let denom = step.z - step.x;
        if denom.is_zero() {
            return Err(TraceBuildError::TraceHeightTooSmall {
                physical_rows,
                trace_height,
            });
        }
        let qi = denom.try_inverse().expect("denom ≠ 0");
        let diff = step.p_at_z - step.p_at_x;
        let dq = diff * qi;
        let ro_in = ro;
        let apow_in = apow;
        ro = ro_in + apow_in * dq;
        apow = apow_in * alpha;
        step_records.push((qi, dq, apow_in, ro_in));
    }
    let rho_final = ro;
    let alpha_final_pow = apow;

    // --- Pass 2: run fold chain off-circuit to compute FINAL_FOLDED. ---
    let mut current = rho_final;
    let mut fold_witness: Vec<(Goldilocks, Goldilocks, Challenge, Challenge, Challenge)> =
        Vec::with_capacity(n_fold);
    for round in fold_rounds {
        let bit = (round.domain_index & 1) as u64;
        let child_log_h = round.log_height - 1;
        let parent_idx = round.domain_index >> 1;
        let g_outer = Goldilocks::two_adic_generator(child_log_h + 1);
        let rev = reverse_bits_len(parent_idx, child_log_h);
        let s = g_outer.exp_u64(rev as u64);
        if s == zero_g {
            return Err(TraceBuildError::TraceHeightTooSmall {
                physical_rows,
                trace_height,
            });
        }
        let two_s = s * Goldilocks::new(2);
        let inv_2s = two_s.try_inverse().expect("2s ≠ 0");
        let (pair_left, pair_right) = if bit == 0 {
            (current, round.sibling)
        } else {
            (round.sibling, current)
        };
        let folded = fold_row_ref(
            parent_idx,
            child_log_h,
            1,
            round.beta,
            &[pair_left, pair_right],
        );
        fold_witness.push((s, inv_2s, pair_left, pair_right, folded));
        current = folded;
    }
    let final_folded = current;

    // --- Pass 3: emit ALPHA rows. ---
    for (r, (step, record)) in alpha_steps.iter().zip(step_records.iter()).enumerate() {
        let (qi, dq, apow_in, ro_in) = *record;
        let base = r * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_ALPHA);
        zero_block_len_flag(row);

        row[col::ALPHA_P_AT_X] = step.p_at_x;
        write_ext(row, col::ALPHA_P_AT_Z0, step.p_at_z);
        write_ext(row, col::ALPHA_Z0, step.z);
        row[col::ALPHA_X] = step.x;

        write_ext(row, col::ALPHA_QUOT_INV0, qi);
        write_ext(row, col::ALPHA_DIFF_QUOT0, dq);
        write_ext(row, col::ALPHA_CHALLENGE0, alpha);
        write_ext(row, col::ALPHA_POW_IN0, apow_in);
        write_ext(row, col::ALPHA_POW_OUT0, apow_in * alpha);
        write_ext(row, col::ALPHA_RO_IN0, ro_in);
        let new_ro = ro_in + apow_in * dq;
        write_ext(row, col::ALPHA_RO_OUT0, new_ro);

        // A3-3 cross-bind setup: FOLD_OUT on α rows = ρ_final.
        // This satisfies non-fold persistence across α→α (FOLD_OUT
        // constant across α rows) AND agrees with the α→FOLD bridge
        // (which requires next.FOLD_IN = local.ALPHA_RO_OUT on the
        // last α row, i.e. = ρ_final).
        write_ext(row, col::FOLD_OUT0, rho_final);

        // PI proxies.
        write_ext(row, col::INITIAL_ALPHA_POW0, initial_alpha_pow);
        write_ext(row, col::INITIAL_RO0, initial_ro);
        write_ext(row, col::FINAL_FOLDED0, final_folded);
        write_ext(row, col::INITIAL_FOLDED0, rho_final);
        write_ext(row, col::FINAL_RO0, rho_final);

        for (i, v) in p2_zero_witness.iter().enumerate() {
            row[col::P2_BLOCK + i] = *v;
        }
    }

    // --- Pass 4: emit FOLD rows. ---
    let mut fold_current = rho_final;
    for (r, (round, record)) in fold_rounds.iter().zip(fold_witness.iter()).enumerate() {
        let (s, inv_2s, pair_left, pair_right, folded) = *record;
        let row_idx = n_alpha + r;
        let base = row_idx * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_FOLD);
        zero_block_len_flag(row);

        let bit = (round.domain_index & 1) as u64;
        write_ext(row, col::FOLD_IN0, fold_current);
        write_ext(row, col::FOLD_OUT0, folded);
        write_ext(row, col::FOLD_BETA0, round.beta);
        row[col::FOLD_S] = s;
        row[col::FOLD_INV_2S] = inv_2s;

        write_ext(row, col::COMPRESS_SIBLING0, round.sibling);
        row[col::COMPRESS_INDEX_BIT] = Goldilocks::new(bit);
        write_ext(row, col::STATE_IN0, pair_left);
        write_ext(row, col::STATE_IN0 + CHALLENGE_DIM, pair_right);

        // A3-3: ALPHA_RO_OUT persists at ρ_final through FOLD rows.
        write_ext(row, col::ALPHA_RO_OUT0, rho_final);
        // ALPHA_POW_OUT, ALPHA_POW_IN, ALPHA_RO_IN keep α-chain's last
        // values so their transition threading stays consistent (the α
        // threading gate is zero on FOLD→FOLD so they're free, but we
        // populate to avoid IDLE-persistence mismatches downstream).
        write_ext(row, col::ALPHA_POW_IN0, alpha_final_pow);
        write_ext(row, col::ALPHA_POW_OUT0, alpha_final_pow);
        write_ext(row, col::ALPHA_RO_IN0, rho_final);

        // PI proxies.
        write_ext(row, col::INITIAL_ALPHA_POW0, initial_alpha_pow);
        write_ext(row, col::INITIAL_RO0, initial_ro);
        write_ext(row, col::FINAL_FOLDED0, final_folded);
        write_ext(row, col::INITIAL_FOLDED0, rho_final);
        write_ext(row, col::FINAL_RO0, rho_final);

        for (i, v) in p2_zero_witness.iter().enumerate() {
            row[col::P2_BLOCK + i] = *v;
        }

        fold_current = folded;
    }

    // --- Pass 5: IDLE padding. ---
    for row_idx in physical_rows..trace_height {
        let prev_base = (row_idx - 1) * width;
        let prev_row = flat[prev_base..prev_base + width].to_vec();
        let base = row_idx * width;
        let row = &mut flat[base..base + width];
        for c in col::STATE_IN0..col::P2_BLOCK {
            row[c] = prev_row[c];
        }
        write_kind(row, OP_KIND_IDLE);
        zero_block_len_flag(row);
        row[col::ABSORB_IS_FIRST] = zero_g;
        row[col::ABSORB_IS_LAST] = zero_g;
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

        // A3-5a: TRACE_COMMIT_ROOT persists WITHIN a compression run
        // only (COMPRESS → COMPRESS). Between runs, the prover sets a
        // fresh TCR for the new path's expected root. The IDLE
        // persistence (later in this fn) still carries TCR into IDLE
        // padding, which is correct — IDLE inherits the preceding run's
        // last TCR. At ABSORB → COMPRESS, TCR is free, letting multi-
        // path traces hold independent roots.
        //
        // NOTE: this replaces A3-1's unconditional TCR persistence,
        // which made one-root-per-trace the only supported shape.
        let next_is_compress_tcr: AB::Expr =
            next[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        for i in 0..DIGEST_WIDTH {
            let l_r: AB::Expr = local[col::TRACE_COMMIT_ROOT0 + i].into();
            let n_r: AB::Expr = next[col::TRACE_COMMIT_ROOT0 + i].into();
            trans.assert_zero(
                is_compress.clone() * next_is_compress_tcr.clone() * (n_r - l_r),
            );
        }

        // A3-5a: Per-path root check.
        // At every COMPRESS → non-COMPRESS transition, the last
        // COMPRESS row's DIGEST must equal its TRACE_COMMIT_ROOT. This
        // lets the trace hold MULTIPLE independent Merkle paths, each
        // with its own root. The check fires once per path, at the
        // path's terminal row.
        //
        // For a trace whose last row itself is COMPRESS (no IDLE
        // padding), the `when_last_row` boundary at the bottom of this
        // fn takes over — `when_transition` excludes the final row in
        // uni-stark's formulation.
        for i in 0..DIGEST_WIDTH {
            let dg: AB::Expr = local[col::DIGEST0 + i].into();
            let tcr: AB::Expr = local[col::TRACE_COMMIT_ROOT0 + i].into();
            trans.assert_zero(
                is_compress.clone()
                    * (one() - next_is_compress_tcr.clone())
                    * (dg - tcr),
            );
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
        // A3-5a: Last-row root check, gated on is_compress.
        //
        // When the trace's final row is a COMPRESS row (no IDLE
        // padding), the `when_transition` per-path check above doesn't
        // fire (it excludes the last row). This boundary catches that
        // case. For IDLE-padded traces the last row has is_compress=0
        // and this boundary is a no-op — the path's root check fired
        // at the COMPRESS → IDLE transition.
        //
        // For non-COMPRESS traces (α-only, fold-only, all-IDLE), the
        // gate is 0 and no constraint fires.
        // =================================================================
        let mut last = builder.when_last_row();
        let last_is_compress: AB::Expr =
            local[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        for i in 0..DIGEST_WIDTH {
            let dg: AB::Expr = local[col::DIGEST0 + i].into();
            let r: AB::Expr = local[col::TRACE_COMMIT_ROOT0 + i].into();
            last.assert_zero(last_is_compress.clone() * (dg - r));
        }

        // =================================================================
        // A3-2: FOLD bank (binary FRI Lagrange fold).
        //
        // Column sharing (K-air-col-share): FOLD rows reuse
        //   COMPRESS_SIBLING[0..2] → FRI SIBLING (Challenge; 2 of 4 cols)
        //   COMPRESS_INDEX_BIT    → FRI INDEX_BIT (low bit of domain idx)
        //   STATE_IN[0..2]        → PAIR_LEFT  (Challenge)
        //   STATE_IN[2..4]        → PAIR_RIGHT (Challenge)
        //
        // The shared-col binding is safe because FOLD / COMPRESS are
        // one-hot disjoint — each row's gate zeroes out any cross-bank
        // constraint from the other bank.
        // =================================================================
        let w = || fe(EXT_W_U64);

        // FOLD row: INDEX_BIT boolean (shared col with COMPRESS, but
        // gated separately for FOLD). Re-assert here rather than gating
        // through is_compress.
        let fold_bit: AB::Expr = local[col::COMPRESS_INDEX_BIT].into();
        builder.assert_zero(
            is_fold.clone() * fold_bit.clone() * (fold_bit.clone() - one()),
        );

        // FOLD row: PAIR_LEFT / PAIR_RIGHT orientation — STATE_IN cols
        // repurposed via K-air-col-share.
        //   STATE_IN[0..2] = PAIR_LEFT  = (1 − bit)·FOLD_IN + bit·SIBLING
        //   STATE_IN[2..4] = PAIR_RIGHT = bit·FOLD_IN + (1 − bit)·SIBLING
        for i in 0..CHALLENGE_DIM {
            let fin: AB::Expr = local[col::FOLD_IN0 + i].into();
            let sib: AB::Expr = local[col::COMPRESS_SIBLING0 + i].into();
            let pl: AB::Expr = local[col::STATE_IN0 + i].into();
            let pr: AB::Expr = local[col::STATE_IN0 + CHALLENGE_DIM + i].into();
            let expected_left =
                (one() - fold_bit.clone()) * fin.clone() + fold_bit.clone() * sib.clone();
            let expected_right =
                fold_bit.clone() * fin + (one() - fold_bit.clone()) * sib;
            builder.assert_zero(is_fold.clone() * (pl - expected_left));
            builder.assert_zero(is_fold.clone() * (pr - expected_right));
        }

        // FOLD row: INV_2S witness 2·S·INV_2S = 1.
        {
            let s: AB::Expr = local[col::FOLD_S].into();
            let inv2s: AB::Expr = local[col::FOLD_INV_2S].into();
            builder.assert_zero(
                is_fold.clone() * (fe(2) * s * inv2s - one()),
            );
        }

        // FOLD row: fold identity per limb (degree 3 when gated).
        //   folded_0 · 2s = s·(pl_0 + pr_0) + β_0·d_0 + W·β_1·d_1
        //   folded_1 · 2s = s·(pl_1 + pr_1) + β_0·d_1 +     β_1·d_0
        {
            let s: AB::Expr = local[col::FOLD_S].into();
            let pl0: AB::Expr = local[col::STATE_IN0].into();
            let pl1: AB::Expr = local[col::STATE_IN0 + 1].into();
            let pr0: AB::Expr = local[col::STATE_IN0 + CHALLENGE_DIM].into();
            let pr1: AB::Expr = local[col::STATE_IN0 + CHALLENGE_DIM + 1].into();
            let b0: AB::Expr = local[col::FOLD_BETA0].into();
            let b1: AB::Expr = local[col::FOLD_BETA0 + 1].into();
            let f0: AB::Expr = local[col::FOLD_OUT0].into();
            let f1: AB::Expr = local[col::FOLD_OUT0 + 1].into();

            let two_s = fe(2) * s.clone();
            let d0 = pl0.clone() - pr0.clone();
            let d1 = pl1.clone() - pr1.clone();

            let lhs0 = f0 * two_s.clone();
            let rhs0 = s.clone() * (pl0 + pr0)
                + b0.clone() * d0.clone()
                + w() * b1.clone() * d1.clone();
            builder.assert_zero(is_fold.clone() * (lhs0 - rhs0));

            let lhs1 = f1 * two_s;
            let rhs1 = s * (pl1 + pr1) + b0 * d1 + b1 * d0;
            builder.assert_zero(is_fold.clone() * (lhs1 - rhs1));
        }

        // =================================================================
        // A3-2: ALPHA bank (α-batched quotient combination).
        //
        // Self-contained in the ALPHA_* columns: four degree-2 extension
        // multiplications, each gated by is_alpha → degree 3 overall.
        // =================================================================
        let ext_mul = |a0: AB::Expr, a1: AB::Expr, b0: AB::Expr, b1: AB::Expr|
            -> (AB::Expr, AB::Expr) {
            let p0 = a0.clone() * b0.clone() + w() * a1.clone() * b1.clone();
            let p1 = a0 * b1 + a1 * b0;
            (p0, p1)
        };

        // (1) ALPHA — QUOT_INV · (Z − X) == 1.
        {
            let qi0: AB::Expr = local[col::ALPHA_QUOT_INV0].into();
            let qi1: AB::Expr = local[col::ALPHA_QUOT_INV0 + 1].into();
            let z0: AB::Expr = local[col::ALPHA_Z0].into();
            let z1: AB::Expr = local[col::ALPHA_Z0 + 1].into();
            let x: AB::Expr = local[col::ALPHA_X].into();
            let d0 = z0 - x;
            let d1 = z1;
            let (p0, p1) = ext_mul(qi0, qi1, d0, d1);
            builder.assert_zero(is_alpha.clone() * (p0 - one()));
            builder.assert_zero(is_alpha.clone() * p1);
        }

        // (2) ALPHA — DIFF_QUOT == (P_AT_Z − P_AT_X) · QUOT_INV.
        {
            let pz0: AB::Expr = local[col::ALPHA_P_AT_Z0].into();
            let pz1: AB::Expr = local[col::ALPHA_P_AT_Z0 + 1].into();
            let px: AB::Expr = local[col::ALPHA_P_AT_X].into();
            let qi0: AB::Expr = local[col::ALPHA_QUOT_INV0].into();
            let qi1: AB::Expr = local[col::ALPHA_QUOT_INV0 + 1].into();
            let diff0 = pz0 - px;
            let diff1 = pz1;
            let (dq0_exp, dq1_exp) = ext_mul(diff0, diff1, qi0, qi1);
            let dq0: AB::Expr = local[col::ALPHA_DIFF_QUOT0].into();
            let dq1: AB::Expr = local[col::ALPHA_DIFF_QUOT0 + 1].into();
            builder.assert_zero(is_alpha.clone() * (dq0 - dq0_exp));
            builder.assert_zero(is_alpha.clone() * (dq1 - dq1_exp));
        }

        // (3) ALPHA — ALPHA_POW_OUT == ALPHA_POW_IN · ALPHA.
        {
            let api0: AB::Expr = local[col::ALPHA_POW_IN0].into();
            let api1: AB::Expr = local[col::ALPHA_POW_IN0 + 1].into();
            let a0: AB::Expr = local[col::ALPHA_CHALLENGE0].into();
            let a1: AB::Expr = local[col::ALPHA_CHALLENGE0 + 1].into();
            let (exp0, exp1) = ext_mul(api0, api1, a0, a1);
            let apo0: AB::Expr = local[col::ALPHA_POW_OUT0].into();
            let apo1: AB::Expr = local[col::ALPHA_POW_OUT0 + 1].into();
            builder.assert_zero(is_alpha.clone() * (apo0 - exp0));
            builder.assert_zero(is_alpha.clone() * (apo1 - exp1));
        }

        // (4) ALPHA — RO_OUT == RO_IN + ALPHA_POW_IN · DIFF_QUOT.
        {
            let api0: AB::Expr = local[col::ALPHA_POW_IN0].into();
            let api1: AB::Expr = local[col::ALPHA_POW_IN0 + 1].into();
            let dq0: AB::Expr = local[col::ALPHA_DIFF_QUOT0].into();
            let dq1: AB::Expr = local[col::ALPHA_DIFF_QUOT0 + 1].into();
            let (add0, add1) = ext_mul(api0, api1, dq0, dq1);
            let ri0: AB::Expr = local[col::ALPHA_RO_IN0].into();
            let ri1: AB::Expr = local[col::ALPHA_RO_IN0 + 1].into();
            let ro0: AB::Expr = local[col::ALPHA_RO_OUT0].into();
            let ro1: AB::Expr = local[col::ALPHA_RO_OUT0 + 1].into();
            builder.assert_zero(is_alpha.clone() * (ro0 - (ri0 + add0)));
            builder.assert_zero(is_alpha.clone() * (ro1 - (ri1 + add1)));
        }

        // =================================================================
        // A3-2: FOLD / ALPHA transitions (threading + PI persistence).
        // =================================================================
        let mut trans2 = builder.when_transition();

        // FOLD threading: next.FOLD_IN = local.FOLD_OUT when next is FOLD.
        let next_is_fold: AB::Expr = next[col::KIND0 + OP_KIND_FOLD as usize].into();
        for i in 0..CHALLENGE_DIM {
            let n_in: AB::Expr = next[col::FOLD_IN0 + i].into();
            let l_out: AB::Expr = local[col::FOLD_OUT0 + i].into();
            trans2.assert_zero(next_is_fold.clone() * (n_in - l_out));
        }

        // ALPHA threading:
        //   next.ALPHA_POW_IN = local.ALPHA_POW_OUT when next is ALPHA
        //   next.ALPHA_RO_IN  = local.ALPHA_RO_OUT  when next is ALPHA
        let next_is_alpha: AB::Expr = next[col::KIND0 + OP_KIND_ALPHA as usize].into();
        for i in 0..CHALLENGE_DIM {
            let n_api: AB::Expr = next[col::ALPHA_POW_IN0 + i].into();
            let l_apo: AB::Expr = local[col::ALPHA_POW_OUT0 + i].into();
            trans2.assert_zero(next_is_alpha.clone() * (n_api - l_apo));

            let n_ri: AB::Expr = next[col::ALPHA_RO_IN0 + i].into();
            let l_ro: AB::Expr = local[col::ALPHA_RO_OUT0 + i].into();
            trans2.assert_zero(next_is_alpha.clone() * (n_ri - l_ro));
        }

        // PI-proxy persistence (unconditional across all rows):
        //   INITIAL_ALPHA_POW, INITIAL_RO, FINAL_FOLDED, INITIAL_FOLDED, FINAL_RO.
        for c in col::INITIAL_ALPHA_POW0..col::FINAL_RO_END {
            let l_c: AB::Expr = local[c].into();
            let n_c: AB::Expr = next[c].into();
            trans2.assert_zero(n_c - l_c);
        }

        // =================================================================
        // A3-3: Cross-binding constraints.
        //
        // Close the A2 "trusted-by-construction" gap at the α↔fold seam.
        // The aggregator pipeline is: α-reduction chain computes ρ (the
        // reduced opening at the query point); ρ then seeds the fold
        // chain's initial running value. In A2 this was threaded at
        // orchestrator level without in-circuit binding. A3-3 enforces
        // it with three constraints:
        //
        //   (i)  Direct α→FOLD bridge: when a FOLD row follows an ALPHA
        //        row, the fold's FOLD_IN must equal the α's ALPHA_RO_OUT.
        //   (ii) ALPHA_RO_OUT persistence on non-α transitions, so the
        //        α chain's last output propagates through fold/IDLE rows
        //        to the last-row boundary `ALPHA_RO_OUT == FINAL_RO`.
        //   (iii) FOLD_OUT persistence on non-fold transitions, so the
        //        fold chain's last output propagates to the last-row
        //        boundary `FOLD_OUT == FINAL_FOLDED`.
        //
        // Together, a unified α+fold+IDLE trace verifies in ONE STARK.
        // =================================================================

        // (i) α→FOLD bridge: is_alpha · next_is_fold · (next.FOLD_IN − local.ALPHA_RO_OUT) = 0.
        for i in 0..CHALLENGE_DIM {
            let n_fin: AB::Expr = next[col::FOLD_IN0 + i].into();
            let l_ro: AB::Expr = local[col::ALPHA_RO_OUT0 + i].into();
            trans2.assert_zero(
                is_alpha.clone() * next_is_fold.clone() * (n_fin - l_ro),
            );
        }

        // (ii) ALPHA_RO_OUT persistence on non-α transitions.
        //      (1 − next_is_alpha) · (next.ALPHA_RO_OUT − local.ALPHA_RO_OUT) = 0.
        for i in 0..CHALLENGE_DIM {
            let l_ro: AB::Expr = local[col::ALPHA_RO_OUT0 + i].into();
            let n_ro: AB::Expr = next[col::ALPHA_RO_OUT0 + i].into();
            trans2.assert_zero(
                (one() - next_is_alpha.clone()) * (n_ro - l_ro),
            );
        }

        // (iii) FOLD_OUT persistence on non-fold transitions.
        //       (1 − next_is_fold) · (next.FOLD_OUT − local.FOLD_OUT) = 0.
        for i in 0..CHALLENGE_DIM {
            let l_fo: AB::Expr = local[col::FOLD_OUT0 + i].into();
            let n_fo: AB::Expr = next[col::FOLD_OUT0 + i].into();
            trans2.assert_zero(
                (one() - next_is_fold.clone()) * (n_fo - l_fo),
            );
        }

        drop(trans2);

        // =================================================================
        // A3-2: Row-0 boundaries for FOLD and ALPHA chains.
        //
        // Each boundary is gated by the row-0 kind so it only fires when
        // the chain is present. Leaf-to-root traces (row 0 = ABSORB) are
        // unaffected: is_fold = is_alpha = 0 on an ABSORB row.
        // =================================================================
        let mut first = builder.when_first_row();
        // FOLD row-0: FOLD_IN == INITIAL_FOLDED.
        for i in 0..CHALLENGE_DIM {
            let fin: AB::Expr = local[col::FOLD_IN0 + i].into();
            let init: AB::Expr = local[col::INITIAL_FOLDED0 + i].into();
            first.assert_zero(is_fold.clone() * (fin - init));
        }
        // ALPHA row-0:
        //   ALPHA_POW_IN == INITIAL_ALPHA_POW
        //   ALPHA_RO_IN  == INITIAL_RO
        for i in 0..CHALLENGE_DIM {
            let api: AB::Expr = local[col::ALPHA_POW_IN0 + i].into();
            let iap: AB::Expr = local[col::INITIAL_ALPHA_POW0 + i].into();
            first.assert_zero(is_alpha.clone() * (api - iap));

            let ri: AB::Expr = local[col::ALPHA_RO_IN0 + i].into();
            let ir: AB::Expr = local[col::INITIAL_RO0 + i].into();
            first.assert_zero(is_alpha.clone() * (ri - ir));
        }
        drop(first);

        // =================================================================
        // A3-2: Last-row boundaries.
        //
        // FOLD chain: last row's FOLD_OUT == FINAL_FOLDED.
        // ALPHA chain: last row's ALPHA_RO_OUT == FINAL_RO.
        //
        // For fold-only / α-only traces, IDLE persistence carries these
        // cols from the last physical row through to the last trace row.
        // For non-FOLD / non-ALPHA traces (e.g. leaf-to-root), the trace
        // builder sets FOLD_OUT = FINAL_FOLDED = 0 and ALPHA_RO_OUT =
        // FINAL_RO = 0 on every row, so both boundaries hold trivially.
        // =================================================================
        let mut last2 = builder.when_last_row();
        for i in 0..CHALLENGE_DIM {
            let f: AB::Expr = local[col::FOLD_OUT0 + i].into();
            let expected: AB::Expr = local[col::FINAL_FOLDED0 + i].into();
            last2.assert_zero(f - expected);

            let ro: AB::Expr = local[col::ALPHA_RO_OUT0 + i].into();
            let fr: AB::Expr = local[col::FINAL_RO0 + i].into();
            last2.assert_zero(ro - fr);
        }

        // Silence the unused-var warning for is_idle (used implicitly
        // via one-hot sum).
        let _ = is_idle;
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

    // ======================================================================
    // A3-2: ALPHA + FOLD banks — standalone chains
    // ======================================================================

    use p3_field::BasedVectorSpace;

    fn ext(a: u64, b: u64) -> Challenge {
        Challenge::from_basis_coefficients_fn(|i| if i == 0 { gl(a) } else { gl(b) })
    }

    /// Run the α-chain out-of-circuit to compute the expected FINAL_RO.
    fn expected_final_ro(
        initial_alpha_pow: Challenge,
        initial_ro: Challenge,
        alpha: Challenge,
        steps: &[AlphaStep],
    ) -> Challenge {
        let mut apow = initial_alpha_pow;
        let mut ro = initial_ro;
        for step in steps {
            let denom = step.z - step.x;
            use p3_field::Field;
            let qi = denom.try_inverse().expect("denom ≠ 0");
            let diff = step.p_at_z - step.p_at_x;
            let dq = diff * qi;
            ro = ro + apow * dq;
            apow = apow * alpha;
        }
        ro
    }

    /// Run the fold chain out-of-circuit to compute the expected FINAL_FOLDED.
    fn expected_final_folded(initial_folded: Challenge, rounds: &[FoldRound]) -> Challenge {
        let mut current = initial_folded;
        for round in rounds {
            let bit = (round.domain_index & 1) as u64;
            let child_log_h = round.log_height - 1;
            let parent_idx = round.domain_index >> 1;
            let (pair_left, pair_right) = if bit == 0 {
                (current, round.sibling)
            } else {
                (round.sibling, current)
            };
            current = fold_row_ref(
                parent_idx,
                child_log_h,
                1,
                round.beta,
                &[pair_left, pair_right],
            );
        }
        current
    }

    #[test]
    fn air_prove_and_verify_alpha_chain_3_steps() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let steps = vec![
            AlphaStep { p_at_x: gl(7), p_at_z: ext(11, 13), z: ext(17, 19), x: gl(23) },
            AlphaStep { p_at_x: gl(29), p_at_z: ext(31, 37), z: ext(41, 43), x: gl(47) },
            AlphaStep { p_at_x: gl(53), p_at_z: ext(59, 61), z: ext(67, 71), x: gl(73) },
        ];
        let final_ro = expected_final_ro(initial_apow, initial_ro, alpha, &steps);
        let flat = build_alpha_chain_trace(
            initial_apow, initial_ro, alpha, &steps, final_ro, 16,
        )
        .unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[])
            .expect("α-chain (3 steps) must verify in ONE monolithic STARK");
    }

    #[test]
    fn air_prove_and_verify_alpha_chain_single_step() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(2, 0);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let steps = vec![AlphaStep {
            p_at_x: gl(1),
            p_at_z: ext(2, 3),
            z: ext(5, 7),
            x: gl(11),
        }];
        let final_ro = expected_final_ro(initial_apow, initial_ro, alpha, &steps);
        let flat = build_alpha_chain_trace(
            initial_apow, initial_ro, alpha, &steps, final_ro, 8,
        )
        .unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[]).expect("α-chain (1 step) must verify");
    }

    #[test]
    fn air_rejects_alpha_chain_wrong_final_ro() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let steps = vec![
            AlphaStep { p_at_x: gl(7), p_at_z: ext(11, 13), z: ext(17, 19), x: gl(23) },
            AlphaStep { p_at_x: gl(29), p_at_z: ext(31, 37), z: ext(41, 43), x: gl(47) },
        ];
        let real_final = expected_final_ro(initial_apow, initial_ro, alpha, &steps);
        let bad_final = real_final + ext(1, 0);
        let flat = build_alpha_chain_trace(
            initial_apow, initial_ro, alpha, &steps, bad_final, 8,
        )
        .unwrap();
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
                    .expect_err("wrong FINAL_RO must reject at last-row boundary");
            }
        }
    }

    #[test]
    fn air_rejects_alpha_chain_tampered_p_at_x() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let steps = vec![
            AlphaStep { p_at_x: gl(7), p_at_z: ext(11, 13), z: ext(17, 19), x: gl(23) },
            AlphaStep { p_at_x: gl(29), p_at_z: ext(31, 37), z: ext(41, 43), x: gl(47) },
        ];
        let final_ro = expected_final_ro(initial_apow, initial_ro, alpha, &steps);
        let mut flat = build_alpha_chain_trace(
            initial_apow, initial_ro, alpha, &steps, final_ro, 8,
        )
        .unwrap();
        // Tamper P_AT_X on row 0 — breaks DIFF_QUOT and RO_OUT.
        flat[col::ALPHA_P_AT_X] += gl(1);
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
                    .expect_err("tampered P_AT_X must reject via DIFF_QUOT bank");
            }
        }
    }

    #[test]
    fn air_prove_and_verify_fold_chain_3_rounds() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let initial_folded = ext(5, 7);
        let rounds = vec![
            FoldRound {
                sibling: ext(11, 13),
                beta: ext(17, 19),
                domain_index: 0b101,
                log_height: 5,
            },
            FoldRound {
                sibling: ext(23, 29),
                beta: ext(31, 37),
                domain_index: 0b010,
                log_height: 4,
            },
            FoldRound {
                sibling: ext(41, 43),
                beta: ext(47, 53),
                domain_index: 0b001,
                log_height: 3,
            },
        ];
        let final_folded = expected_final_folded(initial_folded, &rounds);
        let flat =
            build_fold_chain_trace(initial_folded, &rounds, final_folded, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[])
            .expect("fold chain (3 rounds) must verify in ONE monolithic STARK");
    }

    #[test]
    fn air_prove_and_verify_fold_chain_bit_orientation_cases() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let cfg = build_config();
        let air = MonolithicVerifierAirV1;

        // Exercise both INDEX_BIT = 0 and INDEX_BIT = 1 on round 0.
        for bit in 0..2usize {
            let initial_folded = ext(9, 11);
            let rounds = vec![FoldRound {
                sibling: ext(13, 17),
                beta: ext(19, 23),
                domain_index: bit,
                log_height: 3,
            }];
            let final_folded = expected_final_folded(initial_folded, &rounds);
            let flat =
                build_fold_chain_trace(initial_folded, &rounds, final_folded, 8).unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &[]);
            verify(&cfg, &air, &proof, &[])
                .unwrap_or_else(|e| panic!("bit={bit}: {e:?}"));
        }
    }

    #[test]
    fn air_rejects_fold_chain_wrong_final_folded() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let initial_folded = ext(5, 7);
        let rounds = vec![FoldRound {
            sibling: ext(11, 13),
            beta: ext(17, 19),
            domain_index: 0b01,
            log_height: 4,
        }];
        let real_final = expected_final_folded(initial_folded, &rounds);
        let bad_final = real_final + ext(1, 0);
        let flat = build_fold_chain_trace(initial_folded, &rounds, bad_final, 8).unwrap();
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
                    "wrong FINAL_FOLDED must reject at last-row boundary",
                );
            }
        }
    }

    #[test]
    fn air_rejects_fold_chain_tampered_sibling() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let initial_folded = ext(5, 7);
        let rounds = vec![
            FoldRound {
                sibling: ext(11, 13),
                beta: ext(17, 19),
                domain_index: 0b010,
                log_height: 4,
            },
            FoldRound {
                sibling: ext(23, 29),
                beta: ext(31, 37),
                domain_index: 0b001,
                log_height: 3,
            },
        ];
        let final_folded = expected_final_folded(initial_folded, &rounds);
        let mut flat =
            build_fold_chain_trace(initial_folded, &rounds, final_folded, 8).unwrap();
        // Tamper SIBLING[0] on row 0 — breaks PAIR_LEFT/RIGHT orientation
        // (STATE_IN cols are the prover's "claimed" LEFT/RIGHT; flipping
        // SIBLING without recomputing them fires the orientation bank).
        flat[col::COMPRESS_SIBLING0] += gl(1);
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
                    .expect_err("tampered SIBLING must reject via orientation bank");
            }
        }
    }

    #[test]
    fn air_rejects_fold_chain_broken_inv_2s_witness() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let initial_folded = ext(5, 7);
        let rounds = vec![FoldRound {
            sibling: ext(11, 13),
            beta: ext(17, 19),
            domain_index: 0b01,
            log_height: 3,
        }];
        let final_folded = expected_final_folded(initial_folded, &rounds);
        let mut flat =
            build_fold_chain_trace(initial_folded, &rounds, final_folded, 8).unwrap();
        // Corrupt INV_2S witness on row 0.
        flat[col::FOLD_INV_2S] += gl(1);
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
                    .expect_err("broken INV_2S witness must reject via 2s·INV_2S=1 bank");
            }
        }
    }

    /// Regression guard: after A3-2, the A3-1 leaf-to-root test still
    /// passes — the new FOLD/ALPHA banks are gated off and don't fire
    /// on ABSORB/COMPRESS/IDLE rows.
    #[test]
    fn a3_1_leaf_to_root_still_verifies_after_a3_2() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[2].clone();
        let flat = build_leaf_to_root_trace(&leaves[2], &path, idx, root, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[])
            .expect("A3-1 leaf-to-root must still verify post-A3-2");
    }

    // ======================================================================
    // A3-3: Cross-bindings — unified α + fold chain in ONE STARK
    // ======================================================================

    /// A3-3 acceptance: the α chain's ρ_final THREADS in-circuit into
    /// the fold chain's seed via:
    ///   (i)  bridge: is_alpha · next_is_fold · (next.FOLD_IN − local.ALPHA_RO_OUT)
    ///   (ii) ALPHA_RO_OUT non-α persistence → last-row ALPHA_RO_OUT == FINAL_RO
    ///   (iii) FOLD_OUT non-fold persistence → last-row FOLD_OUT == FINAL_FOLDED
    /// One STARK proof covers both chains.
    #[test]
    fn air_prove_and_verify_unified_alpha_to_fold_chain() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let alpha_steps = vec![
            AlphaStep { p_at_x: gl(7), p_at_z: ext(11, 13), z: ext(17, 19), x: gl(23) },
            AlphaStep { p_at_x: gl(29), p_at_z: ext(31, 37), z: ext(41, 43), x: gl(47) },
        ];
        let fold_rounds = vec![
            FoldRound {
                sibling: ext(53, 59),
                beta: ext(61, 67),
                domain_index: 0b10,
                log_height: 4,
            },
            FoldRound {
                sibling: ext(71, 73),
                beta: ext(79, 83),
                domain_index: 0b01,
                log_height: 3,
            },
        ];
        let flat = build_alpha_to_fold_unified_trace(
            initial_apow, initial_ro, alpha, &alpha_steps, &fold_rounds, 16,
        )
        .unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[])
            .expect("unified α+fold must verify in ONE monolithic STARK");
    }

    /// A3-3 adversarial test #1: directly tamper the first FOLD row's
    /// FOLD_IN so it doesn't match the α chain's last ALPHA_RO_OUT.
    /// The bridge constraint
    ///   is_alpha · next_is_fold · (next.FOLD_IN − local.ALPHA_RO_OUT) = 0
    /// fires at the α→FOLD transition — rejection.
    ///
    /// This CLOSES A2's "trusted-by-construction" gap at the α/fold
    /// seam. Before A3-3, the prover could forge a fold chain starting
    /// from an arbitrary ρ' ≠ ρ_final and the verifier wouldn't catch it.
    #[test]
    fn air_rejects_unified_tampered_alpha_to_fold_bridge() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(29, 31),
            beta: ext(37, 41),
            domain_index: 0b01,
            log_height: 3,
        }];
        let mut flat = build_alpha_to_fold_unified_trace(
            initial_apow, initial_ro, alpha, &alpha_steps, &fold_rounds, 8,
        )
        .unwrap();
        // Row 0 = ALPHA; row 1 = first FOLD. Tamper FOLD_IN on row 1
        // so it no longer equals row 0's ALPHA_RO_OUT.
        let row1 = 1 * col::WIDTH;
        flat[row1 + col::FOLD_IN0] += gl(1);
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
                    "forged α→FOLD seam must reject — A3-3 closes A2's cross-binding gap",
                );
            }
        }
    }

    /// A3-3 adversarial test #2: tamper the α chain's last RO_OUT on
    /// its last row. The direct bridge still sees local.ALPHA_RO_OUT
    /// (unchanged in this case, since we tamper via P_AT_X), so the
    /// rejection path is the DIFF_QUOT / RO update constraint, not the
    /// bridge. Confirms α-chain tampering cascades through.
    #[test]
    fn air_rejects_unified_tampered_alpha_chain() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(29, 31),
            beta: ext(37, 41),
            domain_index: 0b01,
            log_height: 3,
        }];
        let mut flat = build_alpha_to_fold_unified_trace(
            initial_apow, initial_ro, alpha, &alpha_steps, &fold_rounds, 8,
        )
        .unwrap();
        // Tamper α row 0's P_AT_X — breaks DIFF_QUOT → RO update.
        flat[col::ALPHA_P_AT_X] += gl(1);
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
                    .expect_err("tampered α chain in unified trace must reject");
            }
        }
    }

    /// A3-3 adversarial test #3: forge ALPHA_RO_OUT on a FOLD row to
    /// break the non-α persistence chain. If the prover tries to set
    /// FINAL_RO = forged ρ' while keeping the real α chain → the
    /// last-row boundary holds only if ALPHA_RO_OUT propagates from
    /// last α row. Tampering mid-propagation fires persistence.
    #[test]
    fn air_rejects_unified_tampered_alpha_ro_out_on_fold_row() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![
            FoldRound {
                sibling: ext(29, 31),
                beta: ext(37, 41),
                domain_index: 0b10,
                log_height: 4,
            },
            FoldRound {
                sibling: ext(43, 47),
                beta: ext(53, 59),
                domain_index: 0b01,
                log_height: 3,
            },
        ];
        let mut flat = build_alpha_to_fold_unified_trace(
            initial_apow, initial_ro, alpha, &alpha_steps, &fold_rounds, 8,
        )
        .unwrap();
        // Row 0 = ALPHA, rows 1,2 = FOLD. Tamper ALPHA_RO_OUT on row 1.
        // Non-α persistence fires on row0→row1 (fold) or row1→row2 (fold).
        let row1 = 1 * col::WIDTH;
        flat[row1 + col::ALPHA_RO_OUT0] += gl(1);
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
                    .expect_err("tampered ALPHA_RO_OUT on FOLD row must reject via non-α persistence");
            }
        }
    }

    /// A3-3 regression: all A3-1 and A3-2 tests still pass under the
    /// new cross-binding constraints. Covers leaf-to-root, α-only, and
    /// fold-only traces in a single test.
    #[test]
    fn a3_1_and_a3_2_still_verify_after_a3_3() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let cfg = build_config();
        let air = MonolithicVerifierAirV1;

        // Leaf-to-root (A3-1).
        {
            let (leaves, openings, root) = tiny_tree_wide_leaves();
            let (_, path, idx) = openings[1].clone();
            let flat = build_leaf_to_root_trace(&leaves[1], &path, idx, root, 16).unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &[]);
            verify(&cfg, &air, &proof, &[])
                .expect("A3-1 leaf-to-root must still verify post-A3-3");
        }

        // α-only (A3-2).
        {
            let alpha = ext(2, 3);
            let steps = vec![AlphaStep {
                p_at_x: gl(5), p_at_z: ext(7, 11), z: ext(13, 17), x: gl(19),
            }];
            let final_ro = expected_final_ro(ext(1, 0), ext(0, 0), alpha, &steps);
            let flat = build_alpha_chain_trace(
                ext(1, 0), ext(0, 0), alpha, &steps, final_ro, 8,
            )
            .unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &[]);
            verify(&cfg, &air, &proof, &[])
                .expect("A3-2 α-only must still verify post-A3-3");
        }

        // Fold-only (A3-2).
        {
            let initial_folded = ext(5, 7);
            let rounds = vec![FoldRound {
                sibling: ext(11, 13),
                beta: ext(17, 19),
                domain_index: 0b01,
                log_height: 3,
            }];
            let final_folded = expected_final_folded(initial_folded, &rounds);
            let flat =
                build_fold_chain_trace(initial_folded, &rounds, final_folded, 8).unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &[]);
            verify(&cfg, &air, &proof, &[])
                .expect("A3-2 fold-only must still verify post-A3-3");
        }
    }

    // ======================================================================
    // A3-4: Scaling measurements — prover time + proof size sweep.
    //
    // These tests exercise the monolithic AIR at progressively larger
    // trace heights and record:
    //   - trace (height, width, cells)
    //   - prover time (ms)
    //   - postcard-serialized proof size (bytes)
    //
    // The measurements feed into `doc/uno-aggregation-metrics.md` §A3-4
    // and validate the §3.4 feasibility path before A4 scales to N=30.
    //
    // Reliability: these are #[ignore]'d by default to keep the default
    // test suite fast. Run them explicitly with
    //   cargo test -j 128 --release --lib monolithic_verifier_air::tests::measure \
    //     -- --ignored --test-threads 1 --nocapture
    // to capture fresh measurements. The `--test-threads 1` keeps the
    // timing measurements un-contended.
    // ======================================================================

    /// Deterministically sample α-chain steps for measurement traces.
    fn sample_alpha_steps(n: usize) -> Vec<AlphaStep> {
        // Use low-entropy-but-distinct values so steps don't degenerate
        // (z ≠ x is required for (z − x)^{−1} to exist).
        (0..n as u64)
            .map(|i| AlphaStep {
                p_at_x: gl(7 * i + 1),
                p_at_z: ext(11 * i + 3, 13 * i + 5),
                z: ext(17 * i + 7, 19 * i + 11),
                x: gl(23 * i + 2),
            })
            .collect()
    }

    /// Deterministically sample fold rounds. `log_height_start` is the
    /// log-height of the codeword BEFORE the first fold; log_height
    /// halves each round.
    fn sample_fold_rounds(n: usize, log_height_start: usize) -> Vec<FoldRound> {
        assert!(
            log_height_start >= n,
            "fold chain needs log_height_start ≥ n_rounds (each round halves log_h)"
        );
        (0..n)
            .map(|r| FoldRound {
                sibling: ext(53 + r as u64 * 7, 59 + r as u64 * 11),
                beta: ext(61 + r as u64 * 13, 67 + r as u64 * 17),
                domain_index: (0b1010_0101 ^ r) & ((1 << log_height_start) - 1),
                log_height: log_height_start - r,
            })
            .collect()
    }

    /// Single measurement record emitted to stderr.
    fn report(tag: &str, trace_h: usize, prove_ms: u128, proof_bytes: usize) {
        let cells = trace_h * col::WIDTH;
        eprintln!(
            "  [{tag}] height={trace_h:>6}  width={w}  cells={cells:>12}  \
             prove={prove_ms:>6} ms  proof={proof_bytes:>7} B",
            w = col::WIDTH,
            prove_ms = prove_ms,
            proof_bytes = proof_bytes,
        );
    }

    /// A3-4 acceptance: a realistic-scale unified α+fold trace at 2/2
    /// shape dimensions verifies in ONE monolithic STARK.
    ///
    /// Dimensions (mirrors §`doc/uno-aggregation-metrics.md` 2/2 row):
    ///   air_width   ≈ 1305 → α-chain length ≈ air_width · 2 + 2
    ///                                       = 2612 steps ≈ next_pow2 = 4096.
    ///   num_rounds  = 6
    ///   trace_height = 4096
    ///
    /// For this test we use a smaller but still-representative
    /// α_steps = 400 to keep runtime under ~1 min.
    #[test]
    #[ignore = "A3-4 measurement test — run explicitly to capture scaling data"]
    fn measure_unified_alpha_fold_realistic_scale() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};
        use std::time::Instant;

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let alpha_steps = sample_alpha_steps(400);
        let fold_rounds = sample_fold_rounds(9, 12);
        let trace_height = 512;
        let flat = build_alpha_to_fold_unified_trace(
            initial_apow,
            initial_ro,
            alpha,
            &alpha_steps,
            &fold_rounds,
            trace_height,
        )
        .unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;

        let t0 = Instant::now();
        let proof = prove(&cfg, &air, trace, &[]);
        let prove_ms = t0.elapsed().as_millis();
        verify(&cfg, &air, &proof, &[]).expect("realistic-scale unified trace must verify");

        let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
        eprintln!();
        eprintln!("A3-4 unified realistic-scale (α_steps=400, fold_rounds=9):");
        report("unified@512", trace_height, prove_ms, proof_bytes);
    }

    /// A3-4 scaling sweep: α-only chain at trace heights ∈ {64, 256, 1024, 4096}.
    /// Confirms prover time scales ~linearly with trace area.
    #[test]
    #[ignore = "A3-4 measurement test — run explicitly to capture scaling data"]
    fn measure_alpha_chain_scaling_sweep() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};
        use std::time::Instant;

        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);

        eprintln!();
        eprintln!("A3-4 α-chain scaling sweep:");
        for trace_height in [64usize, 256, 1024, 4096] {
            let steps = sample_alpha_steps(trace_height / 2);
            let final_ro = expected_final_ro(initial_apow, initial_ro, alpha, &steps);
            let flat = build_alpha_chain_trace(
                initial_apow, initial_ro, alpha, &steps, final_ro, trace_height,
            )
            .unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);

            let t0 = Instant::now();
            let proof = prove(&cfg, &air, trace, &[]);
            let prove_ms = t0.elapsed().as_millis();
            verify(&cfg, &air, &proof, &[]).unwrap();

            let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
            report(&format!("α@{trace_height}"), trace_height, prove_ms, proof_bytes);
        }
    }

    /// A3-4 scaling sweep: fold-only chain at log_height_start up to 16
    /// (15 rounds matches the 4/4 shape's `num_rounds = 9` with headroom).
    #[test]
    #[ignore = "A3-4 measurement test — run explicitly to capture scaling data"]
    fn measure_fold_chain_scaling_sweep() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};
        use std::time::Instant;

        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let initial_folded = ext(5, 7);

        eprintln!();
        eprintln!("A3-4 fold-chain scaling sweep:");
        // Each row of the fold bank is one round. num_rounds ∈ {3,6,9,12,15}
        // covers the 1/1 (3), 2/2 (6), 4/4 (9), and beyond.
        for (n_rounds, log_h_start) in [(3usize, 5usize), (6, 8), (9, 12), (15, 18)] {
            let rounds = sample_fold_rounds(n_rounds, log_h_start);
            let final_folded = expected_final_folded(initial_folded, &rounds);
            let trace_height = n_rounds.next_power_of_two().max(16);
            let flat = build_fold_chain_trace(
                initial_folded,
                &rounds,
                final_folded,
                trace_height,
            )
            .unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);

            let t0 = Instant::now();
            let proof = prove(&cfg, &air, trace, &[]);
            let prove_ms = t0.elapsed().as_millis();
            verify(&cfg, &air, &proof, &[]).unwrap();

            let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
            report(
                &format!("fold@{n_rounds}rnd"),
                trace_height,
                prove_ms,
                proof_bytes,
            );
        }
    }

    /// A3-4 composite: unified α+fold sweep at trace heights that match
    /// the 1/1, 2/2, and (scaled) 4/4 per-query shape.
    #[test]
    #[ignore = "A3-4 measurement test — run explicitly to capture scaling data"]
    fn measure_unified_alpha_fold_scaling_sweep() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};
        use std::time::Instant;

        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);

        eprintln!();
        eprintln!("A3-4 unified α+fold scaling sweep:");
        // (α_steps, fold_rounds, log_h_start, trace_height) — sized so
        // α_steps + fold_rounds < trace_height.
        let scenarios = [
            ("1/1 shape", 40usize, 3usize, 5usize, 64usize),
            ("2/2 shape", 180, 6, 10, 256),
            ("4/4 shape", 500, 9, 14, 1024),
            ("stretch", 2000, 12, 16, 4096),
        ];
        for (tag, n_alpha, n_fold, log_h_start, trace_height) in scenarios {
            let alpha_steps = sample_alpha_steps(n_alpha);
            let fold_rounds = sample_fold_rounds(n_fold, log_h_start);
            let flat = build_alpha_to_fold_unified_trace(
                initial_apow,
                initial_ro,
                alpha,
                &alpha_steps,
                &fold_rounds,
                trace_height,
            )
            .unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);

            let t0 = Instant::now();
            let proof = prove(&cfg, &air, trace, &[]);
            let prove_ms = t0.elapsed().as_millis();
            verify(&cfg, &air, &proof, &[]).unwrap();

            let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
            report(tag, trace_height, prove_ms, proof_bytes);
        }
    }

    // ======================================================================
    // A3-5a: multi-path Merkle in ONE monolithic STARK
    // ======================================================================

    /// Build two independent Merkle paths (from the same tiny tree) and
    /// prove them both in ONE STARK via the multi-path trace builder.
    /// This exercises the A3-5a per-path root check across two paths
    /// with the SAME root (the tiny tree has one shared root).
    #[test]
    fn air_prove_and_verify_two_paths_same_tree() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path0, idx0) = openings[0].clone();
        let (_, path2, idx2) = openings[2].clone();
        let paths = vec![
            MerkleOpening {
                leaf: &leaves[0],
                opening_proof: &path0,
                index: idx0,
                expected_root: root,
            },
            MerkleOpening {
                leaf: &leaves[2],
                opening_proof: &path2,
                index: idx2,
                expected_root: root,
            },
        ];
        // Each path: 2 absorb (W=8/RATE=4) + 2 compress = 4 rows. Two
        // paths = 8 physical rows; pad to 16.
        let flat = build_multi_path_leaf_to_root_trace(&paths, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[])
            .expect("two Merkle paths must verify in ONE monolithic STARK");
    }

    /// Build two Merkle paths from DIFFERENT trees (with different
    /// roots). Verifies the relaxed TRACE_COMMIT_ROOT persistence lets
    /// each path hold its own root. This is the critical A3-5a
    /// capability that A3-1's one-root model couldn't express.
    #[test]
    fn air_prove_and_verify_two_paths_different_roots() {
        use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref};
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let perm = default_goldilocks_poseidon2_8();

        // Tree A: 2 wide leaves → 1 compression → root_A.
        let leaf_a0: Vec<Goldilocks> =
            (0..8u64).map(|j| gl(100 + j * 17 + 1)).collect();
        let leaf_a1: Vec<Goldilocks> =
            (0..8u64).map(|j| gl(200 + j * 23 + 3)).collect();
        let dig_a0 = hash_leaf_row_ref(&perm, &leaf_a0);
        let dig_a1 = hash_leaf_row_ref(&perm, &leaf_a1);
        let root_a = compress_pair_ref(&perm, &dig_a0, &dig_a1);

        // Tree B: 2 wide leaves → 1 compression → root_B (≠ root_A).
        let leaf_b0: Vec<Goldilocks> =
            (0..8u64).map(|j| gl(300 + j * 29 + 5)).collect();
        let leaf_b1: Vec<Goldilocks> =
            (0..8u64).map(|j| gl(400 + j * 31 + 7)).collect();
        let dig_b0 = hash_leaf_row_ref(&perm, &leaf_b0);
        let dig_b1 = hash_leaf_row_ref(&perm, &leaf_b1);
        let root_b = compress_pair_ref(&perm, &dig_b0, &dig_b1);

        assert_ne!(root_a, root_b, "tree A and B must differ");

        // Path 0 in tree A: leaf_a0, sibling = dig_a1, index 0.
        // Path 0 in tree B: leaf_b0, sibling = dig_b1, index 0.
        let path_a_siblings = vec![dig_a1];
        let path_b_siblings = vec![dig_b1];
        let paths = vec![
            MerkleOpening {
                leaf: &leaf_a0,
                opening_proof: &path_a_siblings,
                index: 0,
                expected_root: root_a,
            },
            MerkleOpening {
                leaf: &leaf_b0,
                opening_proof: &path_b_siblings,
                index: 0,
                expected_root: root_b,
            },
        ];
        // 2 absorb + 1 compress = 3 rows per path; two paths = 6
        // physical rows. Pad to 8.
        let flat = build_multi_path_leaf_to_root_trace(&paths, 8).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[])
            .expect("two paths with different roots must verify in ONE STARK");
    }

    /// A3-5a adversarial test: swap path A's expected root with path
    /// B's. Path A's last COMPRESS row now claims root_B but DIGEST_A
    /// = real root_A ≠ root_B. The per-path root check
    ///   is_compress · (1 − next_is_compress) · (DIGEST − TCR) = 0
    /// fires at path A's COMPRESS → ABSORB_B transition — reject.
    #[test]
    fn air_rejects_multi_path_with_swapped_root() {
        use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref};
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let perm = default_goldilocks_poseidon2_8();
        let leaf_a0: Vec<Goldilocks> = (0..8u64).map(|j| gl(j * 17 + 1)).collect();
        let leaf_a1: Vec<Goldilocks> = (0..8u64).map(|j| gl(j * 23 + 3)).collect();
        let dig_a0 = hash_leaf_row_ref(&perm, &leaf_a0);
        let dig_a1 = hash_leaf_row_ref(&perm, &leaf_a1);
        let root_a = compress_pair_ref(&perm, &dig_a0, &dig_a1);

        let leaf_b0: Vec<Goldilocks> = (0..8u64).map(|j| gl(j * 29 + 5)).collect();
        let leaf_b1: Vec<Goldilocks> = (0..8u64).map(|j| gl(j * 31 + 7)).collect();
        let dig_b0 = hash_leaf_row_ref(&perm, &leaf_b0);
        let dig_b1 = hash_leaf_row_ref(&perm, &leaf_b1);
        let root_b = compress_pair_ref(&perm, &dig_b0, &dig_b1);

        let path_a_siblings = vec![dig_a1];
        let path_b_siblings = vec![dig_b1];
        // Deliberately swap: claim path_a leads to root_b (a lie).
        let paths = vec![
            MerkleOpening {
                leaf: &leaf_a0,
                opening_proof: &path_a_siblings,
                index: 0,
                expected_root: root_b, // wrong root
            },
            MerkleOpening {
                leaf: &leaf_b0,
                opening_proof: &path_b_siblings,
                index: 0,
                expected_root: root_a, // wrong root
            },
        ];
        // build_multi_path_leaf_to_root_trace debug-asserts that the
        // final digest matches expected_root; bypass that by building
        // with correct roots first, then tampering TCR post-hoc.
        let real_paths = vec![
            MerkleOpening {
                leaf: &leaf_a0,
                opening_proof: &path_a_siblings,
                index: 0,
                expected_root: root_a,
            },
            MerkleOpening {
                leaf: &leaf_b0,
                opening_proof: &path_b_siblings,
                index: 0,
                expected_root: root_b,
            },
        ];
        let mut flat = build_multi_path_leaf_to_root_trace(&real_paths, 8).unwrap();
        // Swap TCR on BOTH paths' compression rows. Each path has 2
        // absorb + 1 compress; path_A's compress is row 2, path_B's is
        // row 5 (after 2 absorb + 1 compress + 2 absorb).
        for i in 0..DIGEST_WIDTH {
            let row2 = 2 * col::WIDTH;
            flat[row2 + col::TRACE_COMMIT_ROOT0 + i] = root_b[i];
            let row5 = 5 * col::WIDTH;
            flat[row5 + col::TRACE_COMMIT_ROOT0 + i] = root_a[i];
        }
        // Suppress unused-var warning; `paths` built for docs only.
        let _ = paths;
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
                    "swapped multi-path roots must reject via per-path check",
                );
            }
        }
    }

    /// A3-5a adversarial test: within path A's compression run, change
    /// TCR on an intermediate COMPRESS row (not the last). The in-run
    /// persistence `is_compress · next_is_compress · (next.TCR −
    /// local.TCR) = 0` fires and rejects.
    #[test]
    fn air_rejects_multi_path_tcr_drifts_mid_run() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path0, idx0) = openings[0].clone();
        let paths = vec![MerkleOpening {
            leaf: &leaves[0],
            opening_proof: &path0,
            index: idx0,
            expected_root: root,
        }];
        let mut flat = build_multi_path_leaf_to_root_trace(&paths, 8).unwrap();
        // Rows 0,1 = ABSORB; rows 2,3 = COMPRESS; row 4+ = IDLE.
        // Tamper TCR on row 2 (first COMPRESS). Row 3's TCR still
        // equals real root. In-run persistence row2→row3 fires:
        // is_compress(row2)·next_is_compress(row3)·(row3.TCR − row2.TCR) ≠ 0.
        let row2 = 2 * col::WIDTH;
        flat[row2 + col::TRACE_COMMIT_ROOT0] += gl(1);
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
                    "TCR drift within a compression run must reject",
                );
            }
        }
    }
}
