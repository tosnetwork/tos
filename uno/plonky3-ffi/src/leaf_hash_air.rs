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
use p3_poseidon2_air::RoundConstants;
use p3_symmetric::Permutation;

use crate::merkle_path::Digest;
use crate::transfer_air::{
    eval_poseidon2, P2Cols, POSEIDON2_COLS_PER_INSTANCE, POSEIDON2_HALF_FULL_ROUNDS,
};
use core::borrow::Borrow;

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

    /// Number of Goldilocks limbs absorbed on this row (1..=RATE on
    /// ABSORB rows; 0 on IDLE rows). Used by Phase A2-3c-iv-d-7-c to
    /// support partial-last-block leaf widths (W = 4k + r).
    pub const BLOCK_LEN: usize = IS_LAST + 1;
    /// One-hot flags over {0,1,2,3,4}. Flag k is 1 iff BLOCK_LEN == k.
    /// Flag 0 is 1 only on IDLE rows; on ABSORB rows BLOCK_LEN ∈ 1..=4.
    pub const BLOCK_LEN_FLAG0: usize = BLOCK_LEN + 1;
    pub const BLOCK_LEN_FLAG_END: usize = BLOCK_LEN_FLAG0 + (SPONGE_RATE + 1);

    pub const BLOCK0: usize = BLOCK_LEN_FLAG_END;
    pub const BLOCK_END: usize = BLOCK0 + SPONGE_RATE;

    pub const STATE_IN0: usize = BLOCK_END;
    pub const STATE_IN_END: usize = STATE_IN0 + SPONGE_WIDTH;

    pub const STATE_OUT0: usize = STATE_IN_END;
    pub const STATE_OUT_END: usize = STATE_OUT0 + SPONGE_WIDTH;

    pub const EXPECTED_DIGEST0: usize = STATE_OUT_END;
    pub const EXPECTED_DIGEST_END: usize = EXPECTED_DIGEST0 + DIGEST_WIDTH;

    /// Base offset of the shared Poseidon2-w8 sub-AIR witness block.
    /// The block is populated on EVERY row; its input is bound to
    /// STATE_IN and its output's first 4 limbs are bound to STATE_OUT
    /// on ABSORB rows only (IDLE rows carry a zero-input permutation
    /// witness, unconstrained relative to STATE_IN/OUT).
    pub const P2_BLOCK: usize = EXPECTED_DIGEST_END;

    /// Total column width = 29 framing cols + 180 Poseidon2-w8 block.
    pub const WIDTH: usize = P2_BLOCK + crate::transfer_air::POSEIDON2_COLS_PER_INSTANCE;
}

pub const LEAF_HASH_AIR_FRAMING_WIDTH: usize = col::WIDTH;

// ---------------------------------------------------------------------------
// Shared Poseidon2-w8 sub-AIR helpers (A2-3c-iv-d-7-b)
// ---------------------------------------------------------------------------

/// Generate a full Poseidon2-w8 witness row for a given 8-element
/// input state. Mirrors `challenger_air::gen_p2_witness` and
/// `merkle_path_air::gen_p2_witness`.
pub(crate) fn gen_p2_witness(input: [Goldilocks; 8]) -> Vec<Goldilocks> {
    use p3_goldilocks::{
        GenericPoseidon2LinearLayersGoldilocks, GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
    };
    use p3_poseidon2_air::generate_trace_rows;

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

/// View the Poseidon2-w8 sub-block at `col::P2_BLOCK` as `&P2Cols<T>`.
#[inline]
pub(crate) fn p2_group<T>(row: &[T]) -> &P2Cols<T> {
    let group: &[T] = &row[col::P2_BLOCK..col::P2_BLOCK + POSEIDON2_COLS_PER_INSTANCE];
    <[T] as Borrow<P2Cols<T>>>::borrow(group)
}

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TraceBuildError {
    LeafWidthZero,
    TraceHeightNotPow2 {
        got: usize,
    },
    TraceHeightTooSmall {
        physical_rows: usize,
        trace_height: usize,
    },
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
    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    // Phase A2-3c-iv-d-7-c: accept any non-zero width via partial-block
    // last absorb. num_absorb_rows = ceil(leaf.len() / RATE).
    let num_absorb_rows = (leaf.len() + SPONGE_RATE - 1) / SPONGE_RATE;
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
            out[col::KIND0 + k] = if k as u8 == kind {
                Goldilocks::new(1)
            } else {
                zero_g
            };
        }
    };
    let write_digest_expected = |out: &mut [Goldilocks]| {
        for i in 0..DIGEST_WIDTH {
            out[col::EXPECTED_DIGEST0 + i] = expected_digest[i];
        }
    };

    let write_block_len = |out: &mut [Goldilocks], block_len: usize| {
        debug_assert!(block_len <= SPONGE_RATE);
        out[col::BLOCK_LEN] = Goldilocks::new(block_len as u64);
        for k in 0..=SPONGE_RATE {
            out[col::BLOCK_LEN_FLAG0 + k] = if k == block_len {
                Goldilocks::new(1)
            } else {
                zero_g
            };
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

        // Per-row block length: full RATE unless this is the last row
        // of a partial-tail leaf.
        let block_start = r * SPONGE_RATE;
        let block_len = core::cmp::min(SPONGE_RATE, leaf.len() - block_start);
        write_block_len(row, block_len);

        // BLOCK[0..block_len] = next elements; BLOCK[block_len..RATE] = 0
        // (padded — not used by STATE_IN, but pin deterministically
        // so the checker / AIR can verify state consistency).
        for i in 0..block_len {
            row[col::BLOCK0 + i] = leaf[block_start + i];
        }
        for i in block_len..SPONGE_RATE {
            row[col::BLOCK0 + i] = zero_g;
        }

        // STATE_IN: overwrite state[0..block_len] with BLOCK; KEEP
        // state[block_len..RATE] AND state[RATE..WIDTH] as they are
        // (from the prior permute output, or zero if first row). This
        // matches `PaddingFreeSponge::hash_iter`'s overwrite-then-
        // permute semantics for partial blocks.
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

        write_digest_expected(row);
    }

    // Pad with IDLE rows — copy previous row's non-KIND, non-IS_FIRST,
    // non-IS_LAST data; IDLE carries BLOCK_LEN = 0.
    for r in num_absorb_rows..trace_height {
        let prev_base = (r - 1) * width;
        let prev_row = flat[prev_base..prev_base + width].to_vec();
        let base = r * width;
        let row = &mut flat[base..base + width];
        // Copy BLOCK, BLOCK_LEN + flags, STATE_IN, STATE_OUT, EXPECTED_DIGEST
        // from previous.
        for c in col::BLOCK_LEN..col::P2_BLOCK {
            row[c] = prev_row[c];
        }
        // KIND = IDLE; IS_FIRST / IS_LAST = 0; BLOCK_LEN = 0 (IDLE flag).
        write_kind(row, OP_KIND_IDLE);
        row[col::IS_FIRST] = zero_g;
        row[col::IS_LAST] = zero_g;
        write_block_len(row, 0);
    }

    // --- Populate the shared Poseidon2-w8 block on every row (d-7-b) ---
    //
    // ABSORB rows: input = STATE_IN[0..8]; the P2 sub-AIR enforces
    //   p2.inputs == STATE_IN and p2.post[0..4] == STATE_OUT[0..4]
    //   (the other post limbs are the permutation output but only the
    //    first 4 are truncated to the digest; STATE_OUT[4..8] is
    //    forwarded to the next row's STATE_IN[4..8]).
    //
    //   Since STATE_OUT[0..8] = full post-state and p2.post[0..8] is
    //   also the full post-state, we additionally bind p2.post[4..8]
    //   == STATE_OUT[4..8] on ABSORB rows so downstream carry is
    //   cryptographically pinned.
    //
    // IDLE rows: input = [0; 8] — canonical dummy permutation witness.
    //   The AIR's output binding is gated by is_absorb, so IDLE rows'
    //   P2 block is unconstrained relative to STATE_IN/OUT.
    for r in 0..trace_height {
        let base = r * width;
        let is_absorb = flat[base + col::KIND0 + OP_KIND_ABSORB as usize] == Goldilocks::new(1);
        let input: [Goldilocks; 8] = if is_absorb {
            let mut s = [zero_g; 8];
            for i in 0..SPONGE_WIDTH {
                s[i] = flat[base + col::STATE_IN0 + i];
            }
            s
        } else {
            [zero_g; 8]
        };
        let p2_witness = gen_p2_witness(input);
        debug_assert_eq!(p2_witness.len(), POSEIDON2_COLS_PER_INSTANCE);
        for (i, v) in p2_witness.into_iter().enumerate() {
            flat[base + col::P2_BLOCK + i] = v;
        }
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
    // d-7-c additions
    BlockLenFlagNotBoolean { row: usize, k: usize },
    BlockLenFlagNotOneHot { row: usize },
    BlockLenNotMatchFlag { row: usize },
    AbsorbBlockLenZero { row: usize },
    IdleBlockLenNonZero { row: usize },
    NonLastAbsorbBlockLenNotRate { row: usize },
}

/// Verify every constraint on a pre-built trace.
pub fn check_all_transitions(trace: &[Goldilocks], trace_height: usize) -> Result<(), CheckError> {
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

        // BLOCK_LEN flags: boolean, one-hot, sum==1, weighted-sum == BLOCK_LEN.
        let mut flag_sum = zero;
        let mut weighted = zero;
        for k in 0..=SPONGE_RATE {
            let v = local[col::BLOCK_LEN_FLAG0 + k];
            if v != zero && v != one {
                return Err(CheckError::BlockLenFlagNotBoolean { row: r, k });
            }
            flag_sum += v;
            weighted += Goldilocks::new(k as u64) * v;
        }
        if flag_sum != one {
            return Err(CheckError::BlockLenFlagNotOneHot { row: r });
        }
        if weighted != local[col::BLOCK_LEN] {
            return Err(CheckError::BlockLenNotMatchFlag { row: r });
        }

        // ABSORB rows: BLOCK_LEN ∈ 1..=RATE (flag[0] must be 0).
        if is_absorb && local[col::BLOCK_LEN_FLAG0] != zero {
            return Err(CheckError::AbsorbBlockLenZero { row: r });
        }
        // IDLE rows: BLOCK_LEN == 0 (flag[0] == 1).
        if is_idle && local[col::BLOCK_LEN_FLAG0] != one {
            return Err(CheckError::IdleBlockLenNonZero { row: r });
        }
        // Non-last ABSORB rows: BLOCK_LEN == RATE (flag[RATE] == 1).
        if is_absorb && !is_last && local[col::BLOCK_LEN_FLAG0 + SPONGE_RATE] != one {
            return Err(CheckError::NonLastAbsorbBlockLenNotRate { row: r });
        }

        if is_absorb {
            // Decode block_len from flags (equiv. to the integer col).
            let mut block_len = 0usize;
            for k in 0..=SPONGE_RATE {
                if local[col::BLOCK_LEN_FLAG0 + k] == one {
                    block_len = k;
                    break;
                }
            }
            // STATE_IN[0..block_len] == BLOCK[0..block_len] (overwrite).
            for i in 0..block_len {
                if local[col::STATE_IN0 + i] != local[col::BLOCK0 + i] {
                    return Err(CheckError::StateInBlockOverwriteMismatch { row: r, col: i });
                }
            }
            // STATE_IN[block_len..WIDTH]: carry from prev STATE_OUT
            // (or zero on IS_FIRST).
            if is_first {
                for i in block_len..SPONGE_WIDTH {
                    if local[col::STATE_IN0 + i] != zero {
                        return Err(CheckError::StateInFirstRowNotOverwrite { row: r, col: i });
                    }
                }
            } else {
                let prev = row(r - 1);
                for i in block_len..SPONGE_WIDTH {
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

        // IDLE persistence — framing data cols preserved (P2 block may
        // differ: IDLE rows carry a zero-input P2 witness).
        if is_idle && r > 0 {
            let prev = row(r - 1);
            for c in col::BLOCK0..col::P2_BLOCK {
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
// Plonky3 AIR trait implementation (Phase A2-3c-iv-d-7-b)
//
// Combined d-2 + d-3 style commit: port the checker to `Air<AB>` AND
// wire in the shared Poseidon2-w8 block in one sub-phase, since
// `leaf_hash_air` has only ONE hashing operation per row (no
// compression chain like `merkle_path_air` has).
// ---------------------------------------------------------------------------

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

#[derive(Copy, Clone, Debug, Default)]
pub struct LeafHashAirV1;

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for LeafHashAirV1 {
    #[inline]
    fn width(&self) -> usize {
        LEAF_HASH_AIR_FRAMING_WIDTH
    }

    #[inline]
    fn num_public_values(&self) -> usize {
        0
    }

    #[inline]
    fn max_constraint_degree(&self) -> Option<usize> {
        // Poseidon2 S-box dominates (degree 7). Auto-compute.
        None
    }
}

impl<AB> Air<AB> for LeafHashAirV1
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
        let is_idle: AB::Expr = local[col::KIND0 + OP_KIND_IDLE as usize].into();
        let is_first: AB::Expr = local[col::IS_FIRST].into();
        let is_last: AB::Expr = local[col::IS_LAST].into();

        // =============================================================
        // One-hot selector over {ABSORB, IDLE, RESERVED}.
        // =============================================================
        let mut kind_sum = zero();
        for k in 0..NUM_OP_KINDS {
            let flag: AB::Expr = local[col::KIND0 + k].into();
            builder.assert_zero(flag.clone() * (flag.clone() - one()));
            kind_sum = kind_sum + flag;
        }
        builder.assert_eq(kind_sum, one());

        // IS_FIRST / IS_LAST boolean; only meaningful on ABSORB rows,
        // so gate both to is_absorb · (flag · (flag − 1)) = 0. We also
        // force them to 0 on non-ABSORB rows via (1 − is_absorb) · flag = 0.
        builder.assert_zero(is_first.clone() * (is_first.clone() - one()));
        builder.assert_zero(is_last.clone() * (is_last.clone() - one()));
        builder.assert_zero((one() - is_absorb.clone()) * is_first.clone());
        builder.assert_zero((one() - is_absorb.clone()) * is_last.clone());

        // =============================================================
        // BLOCK_LEN flags (A2-3c-iv-d-7-c).
        //
        //   * each flag[k] for k in 0..=RATE is boolean;
        //   * sum_k flag[k] == 1 (one-hot);
        //   * weighted sum == BLOCK_LEN integer col;
        //   * on ABSORB rows: flag[0] == 0 (BLOCK_LEN ≥ 1);
        //   * on IDLE rows:   flag[0] == 1 (BLOCK_LEN == 0);
        //   * on non-last ABSORB rows: flag[RATE] == 1 (full block).
        // =============================================================
        let mut flag_sum = zero();
        let mut weighted = zero();
        for k in 0..=SPONGE_RATE {
            let flag: AB::Expr = local[col::BLOCK_LEN_FLAG0 + k].into();
            builder.assert_zero(flag.clone() * (flag.clone() - one()));
            flag_sum = flag_sum + flag.clone();
            weighted = weighted + fe(k as u64) * flag;
        }
        builder.assert_eq(flag_sum, one());
        builder.assert_eq(weighted, AB::Expr::from(local[col::BLOCK_LEN]));

        let flag0: AB::Expr = local[col::BLOCK_LEN_FLAG0].into();
        let flag_rate: AB::Expr = local[col::BLOCK_LEN_FLAG0 + SPONGE_RATE].into();
        builder.assert_zero(is_absorb.clone() * flag0.clone());
        builder.assert_zero(is_idle.clone() * (one() - flag0.clone()));
        builder.assert_zero(is_absorb.clone() * (one() - is_last.clone()) * (one() - flag_rate));

        // =============================================================
        // ABSORB row: STATE_IN[i] = cond_block_use[i] · BLOCK[i]
        //                         + cond_carry[i]   · carry_source[i]
        //
        //   cond_block_use[i] = sum_{k > i} flag[k]    ( = [BLOCK_LEN > i] )
        //   cond_carry[i]     = sum_{k ≤ i} flag[k]    ( = [BLOCK_LEN ≤ i] )
        //   carry_source[i]   = 0 on IS_FIRST rows,
        //                       prev.STATE_OUT[i] on non-first ABSORB rows.
        //
        // The "carry from prev" half is a transition constraint (added
        // below inside `when_transition`); the per-row constraint here
        // covers is_absorb AND is_first — where carry_source == 0 so
        // the rule collapses to
        //       STATE_IN[i] = cond_block_use[i] · BLOCK[i].
        //
        // On non-first ABSORB rows the per-row constraint is vacuous
        // (is_first = 0); the transition bank below handles those.
        // =============================================================
        for i in 0..SPONGE_WIDTH {
            let state_in_i: AB::Expr = local[col::STATE_IN0 + i].into();
            let mut cond_block = zero();
            for k in (i + 1)..=SPONGE_RATE {
                let f: AB::Expr = local[col::BLOCK_LEN_FLAG0 + k].into();
                cond_block = cond_block + f;
            }
            // Positions i >= RATE have cond_block = 0 (block never
            // overwrites capacity); the expression below simplifies
            // to state_in == 0 on first rows, matching the old rule.
            let block_term: AB::Expr = if i < SPONGE_RATE {
                cond_block * AB::Expr::from(local[col::BLOCK0 + i])
            } else {
                zero()
            };
            builder.assert_zero(is_first.clone() * (state_in_i - block_term));
        }

        // =============================================================
        // IS_LAST ABSORB row: STATE_OUT[0..DIGEST] == EXPECTED_DIGEST.
        // =============================================================
        for i in 0..DIGEST_WIDTH {
            let state_out_i: AB::Expr = local[col::STATE_OUT0 + i].into();
            let ed_i: AB::Expr = local[col::EXPECTED_DIGEST0 + i].into();
            builder.assert_zero(is_last.clone() * (state_out_i - ed_i));
        }

        // =============================================================
        // IS_LAST ABSORB row: STATE_OUT[0..DIGEST] == EXPECTED_DIGEST.
        // =============================================================
        for i in 0..DIGEST_WIDTH {
            let state_out_i: AB::Expr = local[col::STATE_OUT0 + i].into();
            let ed_i: AB::Expr = local[col::EXPECTED_DIGEST0 + i].into();
            builder.assert_zero(is_last.clone() * (state_out_i - ed_i));
        }

        // =============================================================
        // Transition constraints.
        //
        //   * EXPECTED_DIGEST persists.
        //   * On a NON-FIRST ABSORB row (i.e. carry-in row): STATE_IN
        //     capacity equals the PREVIOUS row's STATE_OUT capacity.
        //   * IDLE row persistence: all non-KIND, non-IS_FIRST,
        //     non-IS_LAST cols match the previous row.
        // =============================================================
        let mut trans = builder.when_transition();

        for i in 0..DIGEST_WIDTH {
            let l_ed: AB::Expr = local[col::EXPECTED_DIGEST0 + i].into();
            let n_ed: AB::Expr = next[col::EXPECTED_DIGEST0 + i].into();
            trans.assert_zero(n_ed - l_ed);
        }

        // Partial-block-aware carry on ABSORB-after-ABSORB transitions.
        //
        // For any ABSORB row that is NOT the first, per-limb:
        //   STATE_IN[i] == cond_block_use[i] · BLOCK[i]
        //               + cond_carry[i]   · local.STATE_OUT[i]
        //
        // Gate by (next_is_absorb · (1 - next_is_first)).
        let next_is_absorb: AB::Expr = next[col::KIND0 + OP_KIND_ABSORB as usize].into();
        let next_is_first: AB::Expr = next[col::IS_FIRST].into();
        let carry_gate = next_is_absorb * (one() - next_is_first);

        for i in 0..SPONGE_WIDTH {
            let n_in: AB::Expr = next[col::STATE_IN0 + i].into();
            let l_out: AB::Expr = local[col::STATE_OUT0 + i].into();
            // cond_block_use[i] = sum_{k > i} next.flag[k]
            // cond_carry[i]     = sum_{k ≤ i} next.flag[k]
            let mut cond_block = zero();
            for k in (i + 1)..=SPONGE_RATE {
                let f: AB::Expr = next[col::BLOCK_LEN_FLAG0 + k].into();
                cond_block = cond_block + f;
            }
            let mut cond_carry = zero();
            for k in 0..=i.min(SPONGE_RATE) {
                let f: AB::Expr = next[col::BLOCK_LEN_FLAG0 + k].into();
                cond_carry = cond_carry + f;
            }
            let block_term: AB::Expr = if i < SPONGE_RATE {
                cond_block * AB::Expr::from(next[col::BLOCK0 + i])
            } else {
                zero()
            };
            let carry_term = cond_carry * l_out;
            trans.assert_zero(carry_gate.clone() * (n_in - block_term - carry_term));
        }

        // IDLE persistence: all non-KIND, non-IS_FIRST, non-IS_LAST
        // columns unchanged.
        let next_is_idle: AB::Expr = next[col::KIND0 + OP_KIND_IDLE as usize].into();
        for c in col::BLOCK0..col::P2_BLOCK {
            let l_c: AB::Expr = local[c].into();
            let n_c: AB::Expr = next[c].into();
            trans.assert_zero(next_is_idle.clone() * (n_c - l_c));
        }

        drop(trans);

        // =============================================================
        // Shared Poseidon2-w8 sub-AIR.
        //
        // Run on every row; tie its input to STATE_IN and its first
        // 8 limbs of the final post to STATE_OUT[0..8], gated by
        // is_absorb. On IDLE rows the P2 block runs against [0;8]
        // (the builder wrote that witness) but no input/output
        // constraints tie it to STATE_IN/OUT.
        // =============================================================
        let p2_local = p2_group::<AB::Var>(local);
        eval_poseidon2(builder, p2_local);

        // P2 input == STATE_IN on ABSORB rows.
        for i in 0..SPONGE_WIDTH {
            let p2_in: AB::Expr = p2_local.inputs[i].into();
            let s_in: AB::Expr = local[col::STATE_IN0 + i].into();
            builder.assert_zero(is_absorb.clone() * (p2_in - s_in));
        }

        // P2 post == STATE_OUT on ABSORB rows (full 8 limbs).
        let p2_post = &p2_local.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
        for i in 0..SPONGE_WIDTH {
            let p2_out: AB::Expr = p2_post[i].into();
            let s_out: AB::Expr = local[col::STATE_OUT0 + i].into();
            builder.assert_zero(is_absorb.clone() * (p2_out - s_out));
        }

        let _ = is_idle;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_path::hash_leaf_row_ref;

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
    fn build_accepts_partial_last_block_widths_d7c() {
        // Phase A2-3c-iv-d-7-c: all widths ≥ 1 are legal, with the
        // last absorb row taking a partial block of size 1..=RATE.
        for width in [1, 2, 3, 5, 6, 7, 9, 13, 15, 17] {
            let leaf: Vec<Goldilocks> = (0..width as u64).map(|i| gl(i + 11)).collect();
            let digest = compute_digest(&leaf);
            let num_rows = (width + SPONGE_RATE - 1) / SPONGE_RATE;
            let trace_height = num_rows.next_power_of_two().max(2);
            let trace = build_trace(&leaf, digest, trace_height)
                .unwrap_or_else(|e| panic!("width {width} must build: {e:?}"));
            check_all_transitions(&trace, trace_height)
                .unwrap_or_else(|e| panic!("width {width} must check: {e:?}"));
        }
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
        // After d-7-c: 35 framing cols (+ BLOCK_LEN + 5 flag cols) + 180 P2.
        assert_eq!(col::P2_BLOCK, 35);
        assert_eq!(col::WIDTH, 35 + POSEIDON2_COLS_PER_INSTANCE);
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
        let refs: Vec<&[Goldilocks]> = quot_batch
            .opened_values
            .iter()
            .map(|v| v.as_slice())
            .collect();
        let flat_leaf: Vec<Goldilocks> = refs.iter().flat_map(|r| r.iter().copied()).collect();

        // Upstream's multi-matrix leaf hash.
        let perm = default_goldilocks_poseidon2_8();
        let expected = hash_multi_matrix_leaf_ref(&perm, &refs);

        // Our AIR trace.
        let trace_height = (flat_leaf.len() / SPONGE_RATE).next_power_of_two().max(2);
        let trace = build_trace(&flat_leaf, expected, trace_height).expect("trace build");
        check_all_transitions(&trace, trace_height).expect("real quot-commit leaf must check");
    }

    // ======================================================================
    // Phase A2-3c-iv-d-7-b: real STARK prove + verify via uni-stark
    // ======================================================================

    use crate::prover::build_config;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{prove, verify};

    fn trace_matrix(
        leaf: &[Goldilocks],
        expected: Digest,
        trace_height: usize,
    ) -> RowMajorMatrix<Goldilocks> {
        let flat = build_trace(leaf, expected, trace_height).expect("trace");
        RowMajorMatrix::new(flat, col::WIDTH)
    }

    #[test]
    fn air_prove_and_verify_width_4() {
        let leaf = vec![gl(7), gl(11), gl(13), gl(17)];
        let digest = compute_digest(&leaf);
        let trace = trace_matrix(&leaf, digest, 16);
        let cfg = build_config();
        let air = LeafHashAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[]).expect("width-4 leaf-hash must verify");
    }

    #[test]
    fn air_prove_and_verify_width_8() {
        let leaf: Vec<Goldilocks> = (1..=8).map(|i| gl(i * 100)).collect();
        let digest = compute_digest(&leaf);
        let trace = trace_matrix(&leaf, digest, 16);
        let cfg = build_config();
        let air = LeafHashAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[]).expect("width-8 leaf-hash must verify");
    }

    #[test]
    fn air_prove_and_verify_width_16() {
        let leaf: Vec<Goldilocks> = (1..=16).map(|i| gl(i * 7 + 3)).collect();
        let digest = compute_digest(&leaf);
        let trace = trace_matrix(&leaf, digest, 16);
        let cfg = build_config();
        let air = LeafHashAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[]).expect("width-16 leaf-hash must verify");
    }

    #[test]
    fn air_prove_and_verify_real_quot_commit_leaf() {
        use crate::merkle_path::hash_multi_matrix_leaf_ref;
        use crate::prover::{MvpConfig, MvpProver};
        use crate::transfer_air::MvpWitness;
        use p3_uni_stark::Proof;

        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(2, 2, 0x7E57_FED0);
        let (bytes, _) = prover.prove(&w.encode()).unwrap();
        let proof: Proof<MvpConfig> = postcard::from_bytes(&bytes).unwrap();

        let quot_batch = &proof.opening_proof.query_proofs[0].input_proof[1];
        let refs: Vec<&[Goldilocks]> = quot_batch
            .opened_values
            .iter()
            .map(|v| v.as_slice())
            .collect();
        let flat_leaf: Vec<Goldilocks> = refs.iter().flat_map(|r| r.iter().copied()).collect();
        let perm = default_goldilocks_poseidon2_8();
        let expected = hash_multi_matrix_leaf_ref(&perm, &refs);

        let trace_height = (flat_leaf.len() / SPONGE_RATE).next_power_of_two().max(2) * 2;
        let trace = trace_matrix(&flat_leaf, expected, trace_height);
        let cfg = build_config();
        let air = LeafHashAirV1;
        let proof_s = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof_s, &[])
            .expect("real quot-commit leaf-hash must verify via STARK");
    }

    /// Helper: adversarially prove+verify a tampered trace.
    fn air_rejects(trace: RowMajorMatrix<Goldilocks>) -> bool {
        let cfg = build_config();
        let air = LeafHashAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &[])
        }));
        match outcome {
            Err(_) => true,
            Ok(p) => verify(&cfg, &air, &p, &[]).is_err(),
        }
    }

    #[test]
    fn air_rejects_tampered_block() {
        let leaf: Vec<Goldilocks> = (1..=8).map(|i| gl(i)).collect();
        let digest = compute_digest(&leaf);
        let mut flat = build_trace(&leaf, digest, 16).unwrap();
        // Tamper row 0 BLOCK[0]. STATE_IN[0..RATE] = BLOCK enforced,
        // so STATE_IN[0] also mismatches → P2(STATE_IN) != STATE_OUT.
        flat[col::BLOCK0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "tampered BLOCK must reject");
    }

    #[test]
    fn air_rejects_first_row_non_zero_capacity() {
        let leaf = vec![gl(1); 4];
        let digest = compute_digest(&leaf);
        let mut flat = build_trace(&leaf, digest, 16).unwrap();
        // Row 0 is IS_FIRST. STATE_IN[4] should be 0 → set non-zero.
        flat[col::STATE_IN0 + 4] = gl(42);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "non-zero first-row capacity must reject"
        );
    }

    #[test]
    fn air_rejects_broken_capacity_carry() {
        let leaf: Vec<Goldilocks> = (1..=8).map(|i| gl(i)).collect();
        let digest = compute_digest(&leaf);
        let mut flat = build_trace(&leaf, digest, 16).unwrap();
        // Row 1 STATE_IN[4] should carry from row 0 STATE_OUT[4]. Break.
        let row1 = col::WIDTH;
        flat[row1 + col::STATE_IN0 + 4] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "broken capacity carry must reject");
    }

    #[test]
    fn air_rejects_wrong_expected_digest() {
        let leaf = vec![gl(1); 4];
        let digest = compute_digest(&leaf);
        let mut bad = digest;
        bad[0] += gl(1);
        // Builder fills EXPECTED_DIGEST = bad; last row STATE_OUT[0..4]
        // is the REAL digest → IS_LAST · (STATE_OUT − ED) ≠ 0.
        let flat = build_trace(&leaf, bad, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "wrong EXPECTED_DIGEST must reject at IS_LAST boundary"
        );
    }

    #[test]
    fn air_rejects_forged_state_out() {
        // Forge STATE_OUT to a value that satisfies DIGEST but not P2
        // (set STATE_OUT to something random). The P2 output binding
        // (p2.post == STATE_OUT on ABSORB rows) must catch it.
        //
        // To isolate the P2 binding, we also propagate the forged
        // STATE_OUT into EXPECTED_DIGEST so the IS_LAST boundary
        // doesn't fire first.
        let leaf = vec![gl(1); 4];
        let digest = compute_digest(&leaf);
        let mut flat = build_trace(&leaf, digest, 16).unwrap();
        // Corrupt row 0 STATE_OUT[0] and also row 0 EXPECTED_DIGEST[0]
        // (and all downstream EXPECTED_DIGEST for persistence).
        let forged = flat[col::STATE_OUT0] + gl(1);
        flat[col::STATE_OUT0] = forged;
        for r in 0..16 {
            flat[r * col::WIDTH + col::EXPECTED_DIGEST0] = forged;
        }
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "forged STATE_OUT must fail P2 output binding"
        );
    }

    #[test]
    fn air_rejects_idle_mutation() {
        let leaf = vec![gl(1); 4];
        let digest = compute_digest(&leaf);
        let mut flat = build_trace(&leaf, digest, 16).unwrap();
        // Row 5 is IDLE. Mutate STATE_OUT[0]. IDLE persistence fires.
        let row5 = 5 * col::WIDTH;
        flat[row5 + col::STATE_OUT0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "IDLE mutation must reject");
    }

    #[test]
    fn air_width_matches_layout_constant() {
        assert_eq!(
            <LeafHashAirV1 as BaseAir<Goldilocks>>::width(&LeafHashAirV1),
            LEAF_HASH_AIR_FRAMING_WIDTH,
        );
    }

    // ======================================================================
    // Phase A2-3c-iv-d-7-c — partial-block STARK prove+verify
    // ======================================================================

    /// STARK prove+verify a partial-block leaf (W = 4k + r, r ∈ {1,2,3}).
    /// This is the d-7-c acceptance test — the flag-based conditional
    /// overwrite/carry rule in `Air<AB>` must correctly express the
    /// partial-last-block semantics.
    #[test]
    fn air_prove_and_verify_partial_block_widths() {
        for width in [1, 2, 3, 5, 6, 7, 9, 13] {
            let leaf: Vec<Goldilocks> = (0..width as u64).map(|i| gl(i * 17 + 3)).collect();
            let digest = compute_digest(&leaf);
            let num_rows = (width + SPONGE_RATE - 1) / SPONGE_RATE;
            let trace_height = num_rows.next_power_of_two().max(2);
            // Pad the trace to at least 16 so FRI has headroom at
            // log_blowup = 3.
            let trace_height = trace_height.max(16);
            let trace = trace_matrix(&leaf, digest, trace_height);
            let cfg = build_config();
            let air = LeafHashAirV1;
            let proof = prove(&cfg, &air, trace, &[]);
            verify(&cfg, &air, &proof, &[])
                .unwrap_or_else(|e| panic!("width {width} STARK verify: {e:?}"));
        }
    }

    /// Real trace-commit leaf end-to-end at the partial-tail edge
    /// case. On a 1/1 Transfer proof the trace-matrix width is NOT a
    /// multiple of `SPONGE_RATE = 4`, so the final absorbed block has
    /// fewer than 4 lanes. We hash the real trace-commit leaf and
    /// verify the STARK proves correctly over this layout.
    ///
    /// The exact `W mod 4` tail-size changes when the AIR adds proxy
    /// columns (Phase 4a shifted 2/2 from mod-4=1 to mod-4=3; Phase
    /// 4b-step1 shifted 2/2 to mod-4=0 so partial-tail moved to 1/2;
    /// Phase 4b-step2a added 1 col/output so 1/2 is now full-tail,
    /// 1/1 at W=813 (mod 4 = 1) carries the test). Shape choice is
    /// whichever deterministic shape currently lands on
    /// `W mod 4 != 0`; the assertion below just requires a non-zero
    /// tail so partial-tail coverage is preserved across column-
    /// layout edits without coupling this test to the absolute column
    /// count.
    #[test]
    fn air_prove_and_verify_real_trace_commit_leaf_partial_tail() {
        use crate::prover::{MvpConfig, MvpProver};
        use crate::transfer_air::MvpWitness;
        use p3_uni_stark::Proof;

        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(1, 1, 0x7E57_D7C0);
        let (bytes, _) = prover.prove(&w.encode()).unwrap();
        let proof: Proof<MvpConfig> = postcard::from_bytes(&bytes).unwrap();

        // Trace-commit batch: one matrix of width = air_width(2,2).
        let trace_batch = &proof.opening_proof.query_proofs[0].input_proof[0];
        assert_eq!(trace_batch.opened_values.len(), 1);
        let leaf = &trace_batch.opened_values[0];
        assert_ne!(
            leaf.len() % SPONGE_RATE,
            0,
            "1/1 air_width should land on a partial-tail sponge block \
             (W mod 4 != 0); if this starts failing, find a different \
             shape whose air_width has W mod 4 != 0 so this test keeps \
             covering the partial tail case (leaf.len() = {})",
            leaf.len(),
        );

        let digest = compute_digest(leaf);
        let num_rows = (leaf.len() + SPONGE_RATE - 1) / SPONGE_RATE;
        let trace_height = num_rows.next_power_of_two().max(16);
        let trace = trace_matrix(leaf, digest, trace_height);
        let cfg = build_config();
        let air = LeafHashAirV1;
        let proof_s = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof_s, &[])
            .expect("real trace-commit leaf (W=1305) STARK must verify");
    }

    /// Tampering the LAST block's value on a partial-tail width
    /// (W=5 → block_len=1 on row 1). P2 input binding fires.
    #[test]
    fn air_rejects_tampered_partial_tail_block() {
        let width = 5; // 4+1
        let leaf: Vec<Goldilocks> = (0..width as u64).map(|i| gl(i + 100)).collect();
        let digest = compute_digest(&leaf);
        let mut flat = build_trace(&leaf, digest, 16).unwrap();
        // Row 1 is the last ABSORB row (partial, block_len=1).
        // Tamper its BLOCK[0]. STATE_IN[0] was = BLOCK[0] (overwrite),
        // so changing BLOCK[0] alone would also violate the overwrite
        // constraint. Mutate both to isolate the P2 input binding.
        let row1 = col::WIDTH;
        flat[row1 + col::BLOCK0] += gl(1);
        flat[row1 + col::STATE_IN0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "tampered partial-tail BLOCK must reject via STATE_OUT ≠ P2(STATE_IN)"
        );
    }

    /// Tampering BLOCK_LEN_FLAG breaks one-hot / BLOCK_LEN consistency.
    #[test]
    fn air_rejects_wrong_block_len_flag() {
        let width = 5;
        let leaf: Vec<Goldilocks> = (0..width as u64).map(|i| gl(i + 200)).collect();
        let digest = compute_digest(&leaf);
        let mut flat = build_trace(&leaf, digest, 16).unwrap();
        // Row 1's BLOCK_LEN_FLAG should have flag[1] = 1, others 0.
        // Clear flag[1] and set flag[4] = 1 instead → inconsistent with
        // block_len = 1 (and violates "last row carries real partial").
        let row1 = col::WIDTH;
        flat[row1 + col::BLOCK_LEN_FLAG0 + 1] = Goldilocks::default();
        flat[row1 + col::BLOCK_LEN_FLAG0 + SPONGE_RATE] = Goldilocks::new(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "wrong BLOCK_LEN_FLAG must reject via weighted-sum or carry-rule check"
        );
    }
}
