//! Column-layout constants for the Monolithic Verifier AIR.
//!
//! Extracted from `monolithic_verifier_air` to keep the main file focused on
//! the AIR `eval` and trace builders. All symbols are re-exported from
//! `monolithic_verifier_air` for backward compatibility.

use crate::transfer_air::POSEIDON2_COLS_PER_INSTANCE;

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
    pub const ABSORB_BLOCK_LEN_FLAG_END: usize = ABSORB_BLOCK_LEN_FLAG0 + (SPONGE_RATE + 1);
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

    // ---- A6-1.6: Block-level PI columns (in-circuit PI binding) --------
    //
    // These 8 columns hold the 8 Goldilocks elements that encode the
    // block's `BlockPublicInputs`:
    //
    //   [0] chain_id          (u32 as u64)
    //   [1] block_seqno       (u64)
    //   [2] anchor_seqno      (u64)
    //   [3] n_transfers       (u16 as u64)
    //   [4..8] tx_pi_merkle_root, 4 × u64 LE chunks of the 32-byte root
    //
    // UNCONDITIONALLY persisted across every transition (block-level,
    // not bundle-scoped, so they do NOT change at bundle boundaries).
    // `when_first_row` pins them to `builder.public_values()[0..8]`,
    // cryptographically binding the aggregated proof to its PI.
    pub const BLOCK_PI_CHAIN_ID: usize = FINAL_RO_END;
    pub const BLOCK_PI_BLOCK_SEQNO: usize = BLOCK_PI_CHAIN_ID + 1;
    pub const BLOCK_PI_ANCHOR_SEQNO: usize = BLOCK_PI_BLOCK_SEQNO + 1;
    pub const BLOCK_PI_N_TRANSFERS: usize = BLOCK_PI_ANCHOR_SEQNO + 1;
    pub const BLOCK_PI_ROOT0: usize = BLOCK_PI_N_TRANSFERS + 1;
    pub const BLOCK_PI_ROOT_END: usize = BLOCK_PI_ROOT0 + 4;
    /// Total number of public-input Goldilocks elements bound in-circuit.
    pub const NUM_BLOCK_PI_ELEMS: usize = 8;

    /// Base offset of the shared Poseidon2-w8 sub-AIR witness block.
    pub const P2_BLOCK: usize = BLOCK_PI_ROOT_END;

    /// Total column width. 180-col Poseidon2 block added on top of
    /// framing cols. Final number fixed at A3-PRE to pin the layout.
    pub const WIDTH: usize = P2_BLOCK + POSEIDON2_COLS_PER_INSTANCE;
}

/// Canonical width constant mirroring `col::WIDTH`.
pub const MONOLITHIC_VERIFIER_AIR_WIDTH: usize = col::WIDTH;
