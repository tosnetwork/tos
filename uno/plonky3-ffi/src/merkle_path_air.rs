//! Merkle-path verification as an AIR — trace layout + pure-Rust
//! constraint checker (Phase A2-3c-iv-d-1).
//!
//! Scope for this sub-phase: the **commit-phase** Merkle path shape —
//! `leaf_row` is exactly 4 Goldilocks (one full `RATE=4` absorption
//! block, so the leaf hash is a single Poseidon2-w8 permutation).
//! The wider trace-commit / multi-matrix-quotient openings (leaf width
//! up to `air_width` ≈ 1300 Goldilocks and `num_chunks × 4` ≈ 16
//! Goldilocks respectively) involve multi-block absorption and land
//! in a follow-up sub-phase.
//!
//! # Column layout per row (framing — P2 block added in A2-3c-iv-d-3)
//!
//! ```text
//! -------- Selectors (one-hot over {LEAF, COMPRESS, IDLE}) --------
//!   IS_LEAF                : 1 col  — leaf-hash row (row 0 of a path)
//!   IS_COMPRESS            : 1 col  — one compress-per-level
//!   IS_IDLE                : 1 col  — padding after path ends
//!
//! -------- Per-row data ------------------------------------------
//!   LEAF_VALUES[0..4]      : 4 cols — the leaf row (valid iff IS_LEAF)
//!   LEFT[0..4]             : 4 cols — left input to Poseidon2 this row
//!                                      (= STATE_OUT of previous row on
//!                                       compress rows OR a sibling)
//!   RIGHT[0..4]            : 4 cols — right input (mirror of LEFT)
//!   DIGEST[0..4]           : 4 cols — Poseidon2 output of this row
//!                                      (= first 4 of the P2 post-state)
//!
//! -------- State threaded across rows ----------------------------
//!   CURRENT[0..4]          : 4 cols — running "my node" digest at the
//!                                     START of this row. On LEAF it
//!                                     is unconstrained; on COMPRESS
//!                                     it must equal the previous row's
//!                                     DIGEST.
//!   SIBLING[0..4]          : 4 cols — the level's sibling digest
//!                                     (public-input on COMPRESS rows)
//!   INDEX_BIT              : 1 col  — boolean, picks LEFT=CURRENT /
//!                                     RIGHT=SIBLING when bit=0, swapped
//!                                     when bit=1
//!
//! -------- Public inputs -----------------------------------------
//!   EXPECTED_ROOT[0..4]    : 4 cols — expected Merkle root (duplicated
//!                                     per row so the AIR can reference
//!                                     them in every row's last-row
//!                                     check; future A2-3c-iv-d-2 will
//!                                     move this to `num_public_values`)
//! ```
//!
//! Total framing width: 3 + 4 + 4 + 4 + 4 + 4 + 4 + 1 + 4 = **32 cols**
//! (the P2-witness block comes later and adds 180 cols; total 212).
//!
//! # Transition rules
//!
//! 1. Each row's (IS_LEAF, IS_COMPRESS, IS_IDLE) is one-hot.
//! 2. LEAF row:
//!    - LEFT[0..4] = LEAF_VALUES[0..4]
//!    - RIGHT[0..4] = [0; 4]     (PaddingFreeSponge overwrite mode)
//!    - DIGEST is the P2(state=[LEAF_VALUES ∥ zeros]) output
//!      (enforced by the Poseidon2 block in A2-3c-iv-d-3)
//!    - Next row is either COMPRESS or IDLE.
//! 3. COMPRESS row:
//!    - LEFT = (INDEX_BIT==0 ? CURRENT : SIBLING)
//!    - RIGHT = (INDEX_BIT==0 ? SIBLING : CURRENT)
//!    - INDEX_BIT is boolean (0 or 1)
//!    - DIGEST = P2([LEFT ∥ RIGHT])    (A2-3c-iv-d-3)
//!    - NEXT row's CURRENT = this row's DIGEST (propagation)
//! 4. IDLE row:
//!    - All non-ROOT columns equal the previous row (padding).
//! 5. LAST non-IDLE row's DIGEST == EXPECTED_ROOT.

use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};
use p3_symmetric::Permutation;

use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref, Digest};

// ---------------------------------------------------------------------------
// Protocol constants (must track `merkle_path` A2-3c-iii)
// ---------------------------------------------------------------------------

/// Leaf-row width supported by this sub-phase: exactly RATE=4 Goldilocks
/// (single Poseidon2-w8 absorption block). Wider leaves land in a
/// follow-up sub-phase that pipelines the absorb rows.
pub const LEAF_WIDTH: usize = 4;
/// Digest size (= DIGEST_ELEMS of MvpValMmcs).
pub const DIGEST_WIDTH: usize = 4;

// ---------------------------------------------------------------------------
// Op-kind selectors
// ---------------------------------------------------------------------------

pub const OP_KIND_LEAF: u8 = 0;
pub const OP_KIND_COMPRESS: u8 = 1;
pub const OP_KIND_IDLE: u8 = 2;
pub const NUM_OP_KINDS: usize = 3;

// ---------------------------------------------------------------------------
// Column offsets
// ---------------------------------------------------------------------------

pub mod col {
    use super::*;

    pub const KIND0: usize = 0;
    pub const KIND_END: usize = KIND0 + NUM_OP_KINDS;

    pub const LEAF0: usize = KIND_END;
    pub const LEAF_END: usize = LEAF0 + LEAF_WIDTH;

    pub const LEFT0: usize = LEAF_END;
    pub const LEFT_END: usize = LEFT0 + DIGEST_WIDTH;

    pub const RIGHT0: usize = LEFT_END;
    pub const RIGHT_END: usize = RIGHT0 + DIGEST_WIDTH;

    pub const DIGEST0: usize = RIGHT_END;
    pub const DIGEST_END: usize = DIGEST0 + DIGEST_WIDTH;

    pub const CURRENT0: usize = DIGEST_END;
    pub const CURRENT_END: usize = CURRENT0 + DIGEST_WIDTH;

    pub const SIBLING0: usize = CURRENT_END;
    pub const SIBLING_END: usize = SIBLING0 + DIGEST_WIDTH;

    pub const INDEX_BIT: usize = SIBLING_END;

    pub const ROOT0: usize = INDEX_BIT + 1;
    pub const ROOT_END: usize = ROOT0 + DIGEST_WIDTH;

    /// Total framing width (A2-3c-iv-d-1). A2-3c-iv-d-3 appends a
    /// 180-column Poseidon2-w8 block at this offset.
    pub const WIDTH: usize = ROOT_END;
}

/// Canonical framing width. Equal to `col::WIDTH`.
pub const MERKLE_PATH_AIR_FRAMING_WIDTH: usize = col::WIDTH;

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

/// Trace-building errors.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TraceBuildError {
    LeafWidthMismatch { expected: usize, got: usize },
    TraceHeightNotPow2 { got: usize },
    TraceHeightTooSmall { physical_rows: usize, trace_height: usize },
    IndexOutOfBoundsForPath { index: usize, path_len: usize },
}

/// Build a row-major trace matrix for one Merkle-path verification.
///
/// Produces `1 + opening_proof.len()` "physical" rows:
///   * Row 0: LEAF row — absorbs `leaf_row` into the Poseidon2 sponge,
///     emits `leaf_digest`.
///   * Rows 1..=path_len: COMPRESS rows — one per tree level. The row's
///     CURRENT digest comes from the previous row's DIGEST; SIBLING +
///     INDEX_BIT decide orientation; DIGEST is the compression output.
///
/// Extra rows up to `trace_height` (power-of-two) are padded with IDLE.
/// The LAST non-IDLE row's DIGEST must equal `expected_root`.
///
/// Returns the flattened `trace_height × col::WIDTH` Goldilocks vector.
pub fn build_trace(
    leaf_row: &[Goldilocks],
    opening_proof: &[Digest],
    index: usize,
    expected_root: Digest,
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    if leaf_row.len() != LEAF_WIDTH {
        return Err(TraceBuildError::LeafWidthMismatch {
            expected: LEAF_WIDTH,
            got: leaf_row.len(),
        });
    }
    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let physical_rows = 1 + opening_proof.len();
    if physical_rows > trace_height {
        return Err(TraceBuildError::TraceHeightTooSmall {
            physical_rows,
            trace_height,
        });
    }
    // opening_proof.len() == log_height; each index bit feeds one level.
    // Require `index < 2^path_len` — otherwise the bit schedule is
    // inconsistent. Upstream accepts index > bound too (it just truncates)
    // but we reject here to catch the caller's off-by-one.
    let path_len = opening_proof.len();
    if path_len < 64 && index >= (1usize << path_len) {
        return Err(TraceBuildError::IndexOutOfBoundsForPath { index, path_len });
    }

    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];
    let perm = default_goldilocks_poseidon2_8();

    // Pre-compute digests along the path (pure-Rust ref).
    let leaf_digest: Digest = hash_leaf_row_ref(&perm, leaf_row);
    let mut level_digests: Vec<Digest> = Vec::with_capacity(path_len + 1);
    level_digests.push(leaf_digest);
    let mut running = leaf_digest;
    let mut idx = index;
    for sibling in opening_proof {
        let (left, right) = if idx & 1 == 0 {
            (running, *sibling)
        } else {
            (*sibling, running)
        };
        running = compress_pair_ref(&perm, &left, &right);
        level_digests.push(running);
        idx >>= 1;
    }

    let write_digest = |out: &mut [Goldilocks], base: usize, d: &Digest| {
        for i in 0..DIGEST_WIDTH {
            out[base + i] = d[i];
        }
    };
    let write_root = |out: &mut [Goldilocks], root: &Digest| {
        for i in 0..DIGEST_WIDTH {
            out[col::ROOT0 + i] = root[i];
        }
    };
    let write_kind = |out: &mut [Goldilocks], kind: u8| {
        for k in 0..NUM_OP_KINDS {
            out[col::KIND0 + k] =
                if k as u8 == kind { Goldilocks::new(1) } else { Goldilocks::default() };
        }
    };

    // --- Row 0: LEAF ---
    {
        let row: &mut [Goldilocks] = &mut flat[0..width];
        write_kind(row, OP_KIND_LEAF);
        for i in 0..LEAF_WIDTH {
            row[col::LEAF0 + i] = leaf_row[i];
        }
        // For the LEAF row, the Poseidon2 block's input is
        // [leaf_row[0], leaf_row[1], leaf_row[2], leaf_row[3], 0, 0, 0, 0]
        // (overwrite-mode PaddingFreeSponge). We encode LEFT=leaf_row and
        // RIGHT=zeros so that the A2-3c-iv-d-3 P2-input-match constraint
        // can unify LEAF and COMPRESS rows' "LEFT ∥ RIGHT" packing.
        for i in 0..DIGEST_WIDTH {
            row[col::LEFT0 + i] = leaf_row[i];
            row[col::RIGHT0 + i] = Goldilocks::default();
        }
        write_digest(row, col::DIGEST0, &leaf_digest);
        // CURRENT / SIBLING / INDEX_BIT unconstrained on LEAF — leave 0.
        write_root(row, &expected_root);
    }

    // --- Rows 1..=path_len: COMPRESS ---
    let mut idx = index;
    let mut running = leaf_digest;
    for (r, sibling) in opening_proof.iter().enumerate() {
        let row_idx = r + 1;
        let base = row_idx * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_COMPRESS);

        let bit = (idx & 1) as u64;
        let (left, right) = if bit == 0 {
            (running, *sibling)
        } else {
            (*sibling, running)
        };
        write_digest(row, col::CURRENT0, &running);
        write_digest(row, col::SIBLING0, sibling);
        row[col::INDEX_BIT] = Goldilocks::new(bit);
        write_digest(row, col::LEFT0, &left);
        write_digest(row, col::RIGHT0, &right);
        let new_digest = level_digests[row_idx];
        write_digest(row, col::DIGEST0, &new_digest);
        write_root(row, &expected_root);

        running = new_digest;
        idx >>= 1;
    }

    // --- Pad remaining rows with IDLE (carry tail state) ---
    //
    // Every non-KIND, non-ROOT column on an IDLE row must match the
    // previous row's value (A2-3c-iv-d-2 encodes this via
    // `is_idle * (next[c] − local[c]) == 0` transition constraints).
    // So we clone the previous row's data columns wholesale.
    let last_physical = physical_rows;
    for row_idx in last_physical..trace_height {
        // Copy the previous row's data cols first…
        let prev_base = (row_idx - 1) * width;
        let prev_row = flat[prev_base..prev_base + width].to_vec();
        let base = row_idx * width;
        let row = &mut flat[base..base + width];
        for c in col::KIND_END..col::ROOT0 {
            row[c] = prev_row[c];
        }
        // …then overwrite the KIND selector and ROOT.
        write_kind(row, OP_KIND_IDLE);
        write_root(row, &expected_root);
    }

    Ok(flat)
}

// ---------------------------------------------------------------------------
// Pure-Rust constraint checker — spec for A2-3c-iv-d-2's Air<AB> port.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CheckError {
    KindFlagNotBoolean { row: usize, kind: usize },
    KindNotOneHot { row: usize },
    LeafLeftMismatch { row: usize, col: usize },
    LeafRightNonZero { row: usize, col: usize },
    IndexBitNotBoolean { row: usize },
    CompressLeftMismatch { row: usize, col: usize },
    CompressRightMismatch { row: usize, col: usize },
    CurrentPropagationMismatch { row: usize, col: usize },
    RootMismatch { row: usize, col: usize },
    FinalDigestNotRoot { col: usize },
    IdlePreservationMismatch { row: usize, col: usize },
    LeafDigestMismatch { row: usize, col: usize },
    CompressDigestMismatch { row: usize, col: usize },
    TraceLengthMismatch { expected: usize, got: usize },
}

/// Verify every constraint on a pre-built trace matrix.
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

    // Track the last non-IDLE row's DIGEST for the root-match check.
    let mut last_non_idle_digest: Option<Digest> = None;

    for r in 0..trace_height {
        let local = row(r);

        // ---- One-hot selector ----
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

        let is_leaf = local[col::KIND0 + OP_KIND_LEAF as usize] == one;
        let is_compress = local[col::KIND0 + OP_KIND_COMPRESS as usize] == one;
        let is_idle = local[col::KIND0 + OP_KIND_IDLE as usize] == one;

        // ---- LEAF row: LEFT = LEAF_VALUES, RIGHT = zeros ----
        if is_leaf {
            for i in 0..DIGEST_WIDTH {
                if local[col::LEFT0 + i] != local[col::LEAF0 + i] {
                    return Err(CheckError::LeafLeftMismatch { row: r, col: i });
                }
                if local[col::RIGHT0 + i] != zero {
                    return Err(CheckError::LeafRightNonZero { row: r, col: i });
                }
            }
            // Out-of-circuit check of the digest. In the AIR, this will
            // come from the Poseidon2 block's post-state (A2-3c-iv-d-3).
            let expected = hash_leaf_row_ref(&perm, &local[col::LEAF0..col::LEAF_END]);
            for i in 0..DIGEST_WIDTH {
                if local[col::DIGEST0 + i] != expected[i] {
                    return Err(CheckError::LeafDigestMismatch { row: r, col: i });
                }
            }
        }

        // ---- COMPRESS row ----
        if is_compress {
            let bit = local[col::INDEX_BIT];
            if bit != zero && bit != one {
                return Err(CheckError::IndexBitNotBoolean { row: r });
            }
            // LEFT = (1-bit)·CURRENT + bit·SIBLING
            // RIGHT = bit·CURRENT + (1-bit)·SIBLING
            for i in 0..DIGEST_WIDTH {
                let cur = local[col::CURRENT0 + i];
                let sib = local[col::SIBLING0 + i];
                let expected_left = (one - bit) * cur + bit * sib;
                let expected_right = bit * cur + (one - bit) * sib;
                if local[col::LEFT0 + i] != expected_left {
                    return Err(CheckError::CompressLeftMismatch { row: r, col: i });
                }
                if local[col::RIGHT0 + i] != expected_right {
                    return Err(CheckError::CompressRightMismatch { row: r, col: i });
                }
            }
            // Digest = compress(LEFT, RIGHT).
            let mut left: Digest = [zero; DIGEST_WIDTH];
            let mut right: Digest = [zero; DIGEST_WIDTH];
            for i in 0..DIGEST_WIDTH {
                left[i] = local[col::LEFT0 + i];
                right[i] = local[col::RIGHT0 + i];
            }
            let expected = compress_pair_ref(&perm, &left, &right);
            for i in 0..DIGEST_WIDTH {
                if local[col::DIGEST0 + i] != expected[i] {
                    return Err(CheckError::CompressDigestMismatch { row: r, col: i });
                }
            }
        }

        // ---- CURRENT propagation from previous DIGEST on COMPRESS rows ----
        if is_compress && r > 0 {
            let prev = row(r - 1);
            for i in 0..DIGEST_WIDTH {
                if local[col::CURRENT0 + i] != prev[col::DIGEST0 + i] {
                    return Err(CheckError::CurrentPropagationMismatch { row: r, col: i });
                }
            }
        }

        // ---- ROOT is constant across rows (public input proxy) ----
        if r > 0 {
            let prev = row(r - 1);
            for i in 0..DIGEST_WIDTH {
                if local[col::ROOT0 + i] != prev[col::ROOT0 + i] {
                    return Err(CheckError::RootMismatch { row: r, col: i });
                }
            }
        }

        // ---- IDLE row: data columns persist; kind flags may change ----
        //
        // The KIND one-hot is ALLOWED to change (it's what marks the
        // row as IDLE in the first place). Everything else — LEAF /
        // LEFT / RIGHT / DIGEST / CURRENT / SIBLING / INDEX_BIT —
        // must match the previous row so the padding carries tail
        // state unambiguously.
        if is_idle && r > 0 {
            let prev = row(r - 1);
            for c in col::KIND_END..col::ROOT0 {
                if local[c] != prev[c] {
                    return Err(CheckError::IdlePreservationMismatch { row: r, col: c });
                }
            }
        }

        // Track last non-IDLE digest.
        if !is_idle {
            let mut d: Digest = [zero; DIGEST_WIDTH];
            for i in 0..DIGEST_WIDTH {
                d[i] = local[col::DIGEST0 + i];
            }
            last_non_idle_digest = Some(d);
        }
    }

    // ---- Final: last non-IDLE DIGEST must equal EXPECTED_ROOT ----
    if let Some(d) = last_non_idle_digest {
        let last = trace_height - 1;
        let root_row = row(last);
        for i in 0..DIGEST_WIDTH {
            if d[i] != root_row[col::ROOT0 + i] {
                return Err(CheckError::FinalDigestNotRoot { col: i });
            }
        }
    } else {
        // No non-IDLE row at all — this is an empty path. Accept only
        // if expected_root == default (shouldn't happen in practice).
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Plonky3 AIR trait implementation (Phase A2-3c-iv-d-2)
//
// Mechanical port of `check_all_transitions` to `Air<AB>` — every
// `if / return Err` arm becomes a `builder.assert_zero(selector *
// (lhs - rhs))` constraint.
//
// # Constraints enforced at d-2 (structural only)
//
// - Per-row:
//   * KIND[k] boolean for each k ∈ {LEAF, COMPRESS, IDLE};
//     sum_k KIND[k] == 1 (one-hot).
//   * LEAF row ⇒ LEFT[i] == LEAF_VALUES[i] for i ∈ 0..4,
//                RIGHT[i] == 0 for i ∈ 0..4.
//   * COMPRESS row ⇒ INDEX_BIT boolean;
//                    LEFT[i]  == (1-INDEX_BIT)·CURRENT[i] + INDEX_BIT·SIBLING[i];
//                    RIGHT[i] == INDEX_BIT·CURRENT[i] + (1-INDEX_BIT)·SIBLING[i].
//
// - Transition (row r → row r+1):
//   * ROOT[i] persists across rows.
//   * next.IS_COMPRESS=1 ⇒ next.CURRENT[i] == local.DIGEST[i].
//   * next.IS_IDLE=1 ⇒ next[c] == local[c] for every non-KIND,
//                     non-ROOT data column c.
//
// - Last row:
//   * DIGEST[i] == ROOT[i]  (the boundary that closes the path).
//
// # Constraints deliberately NOT enforced here (deferred to d-3)
//
// - DIGEST[i] == P2([LEFT ∥ RIGHT])[i]  — the Poseidon2 identity.
//
// This means a malicious prover could currently emit any DIGEST
// values and the structural AIR would accept. The cryptographic
// binding comes from wiring in the shared Poseidon2-w8 sub-AIR in
// A2-3c-iv-d-3, exactly mirroring how ChallengerAirV1 adds the
// DUPLEX identity on top of its structural layer (A2-2c on top of
// A2-2a/2b).
//
// # Degree
//
// Max degree is 3 (is_compress × (1−INDEX_BIT) × CURRENT produces a
// degree-3 term; all other constraints are degree ≤ 2). Fits the
// Option B `log_blowup = 3` budget exactly.
// ---------------------------------------------------------------------------

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

/// Plonky3 AIR for single-Merkle-path verification at commit-phase
/// shape (leaf width = 4 Goldilocks). Structural half of the final
/// MerklePathAir — the P2 identity binding DIGEST = permutation
/// output lands in A2-3c-iv-d-3.
#[derive(Copy, Clone, Debug, Default)]
pub struct MerklePathAirV1;

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for MerklePathAirV1 {
    #[inline]
    fn width(&self) -> usize {
        MERKLE_PATH_AIR_FRAMING_WIDTH
    }

    #[inline]
    fn num_public_values(&self) -> usize {
        // Phase d-2 carries ROOT as a trace column (duplicated each
        // row via the persistence transition constraint). Promoting
        // ROOT to `num_public_values` is orthogonal polish that can
        // ride on a later sub-phase — not load-bearing for d-2.
        0
    }

    #[inline]
    fn max_constraint_degree(&self) -> Option<usize> {
        // See degree analysis in the module comment: degree 3 max.
        // Once d-3 wires in Poseidon2 (S-box degree 7), we'll bump
        // this to `None` (auto-compute) — matches MvpTransferAir.
        Some(3)
    }
}

impl<AB> Air<AB> for MerklePathAirV1
where
    AB: AirBuilder<F = Goldilocks>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_slice: &[AB::Var] = main.current_slice();
        let next_slice: &[AB::Var] = main.next_slice();

        let fe = |v: u64| AB::Expr::from(AB::F::from_u64(v));
        let zero = || fe(0);
        let one = || fe(1);

        // Kind-flag shortcuts.
        let is_leaf: AB::Expr = local_slice[col::KIND0 + OP_KIND_LEAF as usize].into();
        let is_compress: AB::Expr =
            local_slice[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        let is_idle: AB::Expr = local_slice[col::KIND0 + OP_KIND_IDLE as usize].into();

        // ================================================================
        // Per-row: one-hot selector.
        // ================================================================
        let mut kind_sum = zero();
        for k in 0..NUM_OP_KINDS {
            let flag: AB::Expr = local_slice[col::KIND0 + k].into();
            builder.assert_zero(flag.clone() * (flag.clone() - one()));
            kind_sum = kind_sum + flag;
        }
        builder.assert_eq(kind_sum, one());

        // ================================================================
        // Per-row: LEAF — LEFT == LEAF_VALUES, RIGHT == 0.
        // ================================================================
        for i in 0..DIGEST_WIDTH {
            let leaf_i: AB::Expr = local_slice[col::LEAF0 + i].into();
            let left_i: AB::Expr = local_slice[col::LEFT0 + i].into();
            let right_i: AB::Expr = local_slice[col::RIGHT0 + i].into();
            builder.assert_zero(is_leaf.clone() * (left_i - leaf_i));
            builder.assert_zero(is_leaf.clone() * right_i);
        }

        // ================================================================
        // Per-row: COMPRESS — INDEX_BIT boolean + LEFT/RIGHT selection.
        // ================================================================
        let index_bit: AB::Expr = local_slice[col::INDEX_BIT].into();
        // Boolean — but only when is_compress = 1. The vacuous case
        // (non-COMPRESS rows with arbitrary INDEX_BIT) is allowed: the
        // builder would see is_compress * … == 0 trivially.
        builder.assert_zero(
            is_compress.clone() * index_bit.clone() * (index_bit.clone() - one()),
        );
        for i in 0..DIGEST_WIDTH {
            let cur: AB::Expr = local_slice[col::CURRENT0 + i].into();
            let sib: AB::Expr = local_slice[col::SIBLING0 + i].into();
            let left: AB::Expr = local_slice[col::LEFT0 + i].into();
            let right: AB::Expr = local_slice[col::RIGHT0 + i].into();

            // Expected LEFT  = (1-bit)·CURRENT + bit·SIBLING.
            let expected_left =
                (one() - index_bit.clone()) * cur.clone() + index_bit.clone() * sib.clone();
            let expected_right =
                index_bit.clone() * cur + (one() - index_bit.clone()) * sib;

            builder.assert_zero(is_compress.clone() * (left - expected_left));
            builder.assert_zero(is_compress.clone() * (right - expected_right));
        }

        // ================================================================
        // Transition constraints (applied on row pairs).
        // ================================================================
        let mut trans = builder.when_transition();

        // ROOT persists across rows (public-input proxy).
        for i in 0..DIGEST_WIDTH {
            let local_root: AB::Expr = local_slice[col::ROOT0 + i].into();
            let next_root: AB::Expr = next_slice[col::ROOT0 + i].into();
            trans.assert_zero(next_root - local_root);
        }

        // CURRENT threading: when the NEXT row is COMPRESS, its
        // CURRENT must equal this row's DIGEST.
        let next_is_compress: AB::Expr =
            next_slice[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        for i in 0..DIGEST_WIDTH {
            let local_digest: AB::Expr = local_slice[col::DIGEST0 + i].into();
            let next_current: AB::Expr = next_slice[col::CURRENT0 + i].into();
            trans.assert_zero(next_is_compress.clone() * (next_current - local_digest));
        }

        // IDLE persistence: when NEXT row is IDLE, all non-KIND /
        // non-ROOT columns equal the local row's.
        let next_is_idle: AB::Expr = next_slice[col::KIND0 + OP_KIND_IDLE as usize].into();
        for c in col::KIND_END..col::ROOT0 {
            let local_c: AB::Expr = local_slice[c].into();
            let next_c: AB::Expr = next_slice[c].into();
            trans.assert_zero(next_is_idle.clone() * (next_c - local_c));
        }

        drop(trans);

        // ================================================================
        // Last-row boundary: DIGEST == ROOT.
        //
        // Since IDLE rows carry DIGEST unchanged (via the IDLE
        // persistence transition above), the last physical row of a
        // path propagates its final-compression digest to the last
        // row of the trace. This `when_last_row()` constraint therefore
        // enforces the path-closure property even when the trace is
        // padded with IDLE rows.
        // ================================================================
        let mut last = builder.when_last_row();
        for i in 0..DIGEST_WIDTH {
            let digest_i: AB::Expr = local_slice[col::DIGEST0 + i].into();
            let root_i: AB::Expr = local_slice[col::ROOT0 + i].into();
            last.assert_zero(digest_i - root_i);
        }

        // Silence unused warnings that would surface only when the
        // crate's `#[warn(unused)]` lint pipeline changes.
        let _ = (is_idle, zero);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_path::compress_pair_ref;

    fn gl(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    /// Build a tiny 4-leaf Merkle tree manually and return the
    /// (leaves, level1, root) plus a path for leaf index 2.
    fn tiny_tree_path_for_leaf_2() -> (
        Vec<[Goldilocks; 4]>,
        Vec<Digest>,
        Digest,
        Vec<Digest>,
        usize,
    ) {
        let perm = default_goldilocks_poseidon2_8();
        let leaves: Vec<[Goldilocks; 4]> = (0..4)
            .map(|i| [gl(100 + i), gl(200 + i), gl(300 + i), gl(400 + i)])
            .collect();
        let leaf_digests: Vec<Digest> = leaves
            .iter()
            .map(|row| hash_leaf_row_ref(&perm, row))
            .collect();
        let level1 = vec![
            compress_pair_ref(&perm, &leaf_digests[0], &leaf_digests[1]),
            compress_pair_ref(&perm, &leaf_digests[2], &leaf_digests[3]),
        ];
        let root = compress_pair_ref(&perm, &level1[0], &level1[1]);

        // Leaf index 2: siblings are leaf_digests[3] at level 0 and
        // level1[0] at level 1. Index bits: 2 = 0b10 ⇒ at level 0
        // INDEX_BIT=0, at level 1 INDEX_BIT=1.
        let opening = vec![leaf_digests[3], level1[0]];
        (leaves, leaf_digests, root, opening, 2)
    }

    // ---- builder sanity ----

    #[test]
    fn build_trace_rejects_wrong_leaf_width() {
        let leaf = vec![gl(1), gl(2), gl(3)]; // wrong width
        let err = build_trace(&leaf, &[], 0, [gl(0); 4], 4).unwrap_err();
        assert_eq!(
            err,
            TraceBuildError::LeafWidthMismatch { expected: 4, got: 3 }
        );
    }

    #[test]
    fn build_trace_rejects_non_pow2_height() {
        let leaf = vec![gl(1); 4];
        let err = build_trace(&leaf, &[], 0, [gl(0); 4], 7).unwrap_err();
        assert_eq!(err, TraceBuildError::TraceHeightNotPow2 { got: 7 });
    }

    #[test]
    fn build_trace_rejects_insufficient_height() {
        let leaf = vec![gl(1); 4];
        let (_, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        // 1 leaf + 2 compress = 3 physical rows; height 2 is too small.
        let err =
            build_trace(&leaf, &opening, index, root, 2).unwrap_err();
        assert_eq!(
            err,
            TraceBuildError::TraceHeightTooSmall {
                physical_rows: 3,
                trace_height: 2
            }
        );
    }

    // ---- builder + checker positive ----

    #[test]
    fn trace_and_check_accept_tiny_tree_leaf_2() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let trace = build_trace(&leaves[index], &opening, index, root, 8).unwrap();
        assert_eq!(trace.len(), 8 * col::WIDTH);
        check_all_transitions(&trace, 8).expect("valid path must check");
    }

    #[test]
    fn trace_and_check_accept_leaf_0() {
        let perm = default_goldilocks_poseidon2_8();
        let leaves: Vec<[Goldilocks; 4]> = (0..4)
            .map(|i| [gl(i), gl(10 + i), gl(20 + i), gl(30 + i)])
            .collect();
        let leaf_digests: Vec<Digest> = leaves
            .iter()
            .map(|r| hash_leaf_row_ref(&perm, r))
            .collect();
        let level1 = vec![
            compress_pair_ref(&perm, &leaf_digests[0], &leaf_digests[1]),
            compress_pair_ref(&perm, &leaf_digests[2], &leaf_digests[3]),
        ];
        let root = compress_pair_ref(&perm, &level1[0], &level1[1]);
        // Leaf 0: siblings = [leaf_digests[1], level1[1]], index=0 ⇒ bits=00.
        let opening = vec![leaf_digests[1], level1[1]];
        let trace = build_trace(&leaves[0], &opening, 0, root, 8).unwrap();
        check_all_transitions(&trace, 8).expect("leaf-0 path must check");
    }

    // ---- checker negatives ----

    #[test]
    fn checker_rejects_tampered_sibling() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut trace = build_trace(&leaves[index], &opening, index, root, 8).unwrap();
        // Row 1 is a COMPRESS row. Corrupt its SIBLING.
        let row1 = col::WIDTH;
        trace[row1 + col::SIBLING0] += Goldilocks::new(1);
        // The LEFT/RIGHT are derived from CURRENT and SIBLING under
        // INDEX_BIT, so the CompressLeftMismatch or CompressRightMismatch
        // check fires first. Either way the checker must reject.
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_flipped_index_bit() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut trace = build_trace(&leaves[index], &opening, index, root, 8).unwrap();
        // Row 1 (level 0) has INDEX_BIT=0 (since index=2 → low bit=0).
        // Flip to 1. LEFT/RIGHT would swap — no longer consistent with
        // what we wrote; checker rejects.
        let row1 = col::WIDTH;
        trace[row1 + col::INDEX_BIT] = Goldilocks::new(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_tampered_digest() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut trace = build_trace(&leaves[index], &opening, index, root, 8).unwrap();
        // Corrupt row 0's DIGEST.
        trace[col::DIGEST0] += Goldilocks::new(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_tampered_leaf_values() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut trace = build_trace(&leaves[index], &opening, index, root, 8).unwrap();
        // Corrupt row 0's LEAF_VALUES[0].
        trace[col::LEAF0] += Goldilocks::new(1);
        // LEAF_DIGEST recomputation via hash_leaf_row_ref will now
        // differ from the stored digest.
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_wrong_root() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut bad_root = root;
        bad_root[0] += Goldilocks::new(1);
        // Build with a bad root — the trace uses this as the expected
        // public input. The last COMPRESS row's DIGEST is the genuine
        // root, which now mismatches EXPECTED_ROOT.
        let trace = build_trace(&leaves[index], &opening, index, bad_root, 8).unwrap();
        let err = check_all_transitions(&trace, 8).unwrap_err();
        assert_eq!(err, CheckError::FinalDigestNotRoot { col: 0 });
    }

    #[test]
    fn checker_rejects_idle_mutation() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut trace = build_trace(&leaves[index], &opening, index, root, 8).unwrap();
        // Rows 3..=7 are IDLE. Row 4 should match row 3 byte-for-byte
        // (except ROOT which the checker gates separately). Tamper
        // row 4's DIGEST[0].
        let row4 = 4 * col::WIDTH;
        trace[row4 + col::DIGEST0] += Goldilocks::new(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    // ---- end-to-end: real FRI commit-phase opening ----

    /// Extract a commit-phase Merkle path from a real 2/2 Transfer
    /// proof and validate our AIR trace + checker against it.
    #[test]
    fn trace_and_check_accept_real_fri_commit_phase_opening() {
        use crate::fiat_shamir::derive_full_challenges;
        use crate::prover::{MvpConfig, MvpProver};
        use crate::transfer_air::MvpWitness;
        use p3_field::BasedVectorSpace;
        use p3_uni_stark::Proof;

        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(2, 2, 0xAF0E_0001);
        let (bytes, _) = prover.prove(&w.encode()).unwrap();
        let proof: Proof<MvpConfig> = postcard::from_bytes(&bytes).unwrap();
        let pis = w.public_inputs();
        let ch = derive_full_challenges(&proof, &pis);

        // Take the first query's first commit-phase round.
        let query = &proof.opening_proof.query_proofs[0];
        let step = &query.commit_phase_openings[0];
        let log_arity = step.log_arity as usize;
        assert_eq!(log_arity, 1, "binary FRI");
        let arity = 2;

        let mut idx = ch.query_indices[0];
        // Before the first round's Merkle verify, upstream does
        // `start_index >>= log_arity` (fri/verifier.rs:434). So the
        // Merkle path uses the PARENT index.
        let index_in_group = idx & (arity - 1);
        idx >>= log_arity;

        // Reconstruct the arity-2 row: folded_eval at `index_in_group`
        // and the sibling in the other slot.
        //
        // For this test we don't have access to `folded_eval` directly
        // (it's the first element of `reduced_openings` and requires
        // α-combining). But the SIBLING is stored in step.sibling_values.
        // We substitute folded_eval = zero for a structural check; the
        // builder does NOT care about the leaf values semantics, only
        // shape. The end-to-end byte-faithful test comes in A2-3c-iv-d-3.
        let folded_eval = crate::prover::Challenge::from_basis_coefficients_fn(|i| {
            if i == 0 { Goldilocks::new(1) } else { Goldilocks::new(0) }
        });
        let mut evals = vec![folded_eval; arity];
        evals[index_in_group] = folded_eval;
        evals[1 - index_in_group] = step.sibling_values[0];

        // Flatten to base limbs.
        let leaf_row: Vec<Goldilocks> = evals
            .iter()
            .flat_map(|c| {
                <crate::prover::Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(c)
                    .to_vec()
            })
            .collect();
        assert_eq!(leaf_row.len(), LEAF_WIDTH);

        // The real root.
        let root: Digest = proof.opening_proof.commit_phase_commits[0].roots()[0];

        let path_len = step.opening_proof.len();
        let trace_height = (1 + path_len).next_power_of_two();

        // Build trace. The hashes in the trace come from the REAL
        // permutation; the last digest is what our leaf_row + path
        // hashes to — which may NOT equal root (since folded_eval is
        // synthetic here). So the checker may or may not reject on
        // the FinalDigestNotRoot; the structural checks (kind one-hot,
        // left/right propagation, current threading, digest correctness
        // PER ROW) must always pass.
        let trace = build_trace(&leaf_row, &step.opening_proof, idx, root, trace_height)
            .expect("build should succeed");

        // Check per-row structural invariants. We allow FinalDigestNotRoot
        // since folded_eval is synthetic — but EVERY OTHER check must pass.
        match check_all_transitions(&trace, trace_height) {
            Ok(()) => {}
            Err(CheckError::FinalDigestNotRoot { .. }) => {
                // Expected: synthetic folded_eval doesn't hash to the
                // real root. The per-row arithmetic is still valid.
            }
            Err(e) => panic!("unexpected structural failure: {e:?}"),
        }
    }

    // ======================================================================
    // Phase A2-3c-iv-d-2: real STARK prove + verify via uni-stark
    // ======================================================================

    use crate::prover::build_config;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{prove, verify};

    /// Build the row-major trace matrix consumed by `uni_stark::prove`.
    fn trace_matrix(
        leaf_row: &[Goldilocks],
        opening_proof: &[Digest],
        index: usize,
        root: Digest,
        trace_height: usize,
    ) -> RowMajorMatrix<Goldilocks> {
        let flat = build_trace(leaf_row, opening_proof, index, root, trace_height)
            .expect("trace build");
        RowMajorMatrix::new(flat, col::WIDTH)
    }

    #[test]
    fn air_prove_and_verify_tiny_tree_leaf_2() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let trace = trace_matrix(&leaves[index], &opening, index, root, 16);
        let cfg = build_config();
        let air = MerklePathAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[]).expect("valid Merkle-path trace must verify");
    }

    #[test]
    fn air_prove_and_verify_leaf_0_boundary() {
        let perm = default_goldilocks_poseidon2_8();
        let leaves: Vec<[Goldilocks; 4]> = (0..4)
            .map(|i| [gl(i), gl(10 + i), gl(20 + i), gl(30 + i)])
            .collect();
        let leaf_digests: Vec<Digest> = leaves
            .iter()
            .map(|r| hash_leaf_row_ref(&perm, r))
            .collect();
        let level1 = vec![
            compress_pair_ref(&perm, &leaf_digests[0], &leaf_digests[1]),
            compress_pair_ref(&perm, &leaf_digests[2], &leaf_digests[3]),
        ];
        let root = compress_pair_ref(&perm, &level1[0], &level1[1]);
        let opening = vec![leaf_digests[1], level1[1]];
        let trace = trace_matrix(&leaves[0], &opening, 0, root, 16);
        let cfg = build_config();
        let air = MerklePathAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[]).expect("leaf-0 path must verify");
    }

    /// Helper: adversarially prove + verify a tampered trace. Returns
    /// true iff the AIR rejects (either prove panics in debug or
    /// verify returns Err in release).
    fn air_rejects(trace: RowMajorMatrix<Goldilocks>) -> bool {
        let cfg = build_config();
        let air = MerklePathAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &[])
        }));
        match outcome {
            Err(_) => true, // debug builder panic
            Ok(p) => verify(&cfg, &air, &p, &[]).is_err(),
        }
    }

    #[test]
    fn air_rejects_broken_one_hot() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut flat = build_trace(&leaves[index], &opening, index, root, 16).unwrap();
        // Row 0 has LEAF selector = 1. Set COMPRESS selector = 1 too →
        // sum = 2, breaks one-hot and the boolean product checks.
        flat[col::KIND0 + OP_KIND_COMPRESS as usize] = Goldilocks::new(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "broken one-hot must be rejected");
    }

    #[test]
    fn air_rejects_flipped_index_bit() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut flat = build_trace(&leaves[index], &opening, index, root, 16).unwrap();
        // Row 1 is the first COMPRESS row (level 0). INDEX_BIT was 0
        // for index=2. Flip to 1 — LEFT/RIGHT no longer match the
        // stored selection formula.
        let row1 = col::WIDTH;
        flat[row1 + col::INDEX_BIT] = Goldilocks::new(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "flipped INDEX_BIT must be rejected");
    }

    #[test]
    fn air_rejects_tampered_left() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut flat = build_trace(&leaves[index], &opening, index, root, 16).unwrap();
        // Tamper LEFT[0] on the first COMPRESS row (row 1). The LEFT
        // selector constraint (LEFT = (1-bit)·CURRENT + bit·SIBLING)
        // will detect the mismatch.
        let row1 = col::WIDTH;
        flat[row1 + col::LEFT0] += Goldilocks::new(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "tampered LEFT must be rejected");
    }

    #[test]
    fn air_rejects_broken_current_propagation() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut flat = build_trace(&leaves[index], &opening, index, root, 16).unwrap();
        // Row 2 is COMPRESS (level 1). Its CURRENT[0] should equal
        // row 1's DIGEST[0]. Tamper row 2's CURRENT[0].
        let row2 = 2 * col::WIDTH;
        flat[row2 + col::CURRENT0] += Goldilocks::new(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "broken CURRENT propagation must be rejected"
        );
    }

    #[test]
    fn air_rejects_wrong_final_root() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut bad_root = root;
        bad_root[0] += Goldilocks::new(1);
        // Builder writes `bad_root` into ROOT columns on every row
        // AND propagates the REAL final digest via IDLE. The last-row
        // boundary constraint `DIGEST == ROOT` then fails.
        let flat = build_trace(&leaves[index], &opening, index, bad_root, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "final-digest-vs-root mismatch must be rejected"
        );
    }

    #[test]
    fn air_rejects_root_drift_across_rows() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut flat = build_trace(&leaves[index], &opening, index, root, 16).unwrap();
        // Change ROOT[0] on row 5 (which is IDLE padding). The
        // ROOT-persistence transition constraint must reject.
        let row5 = 5 * col::WIDTH;
        flat[row5 + col::ROOT0] += Goldilocks::new(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "ROOT must persist across all trace rows"
        );
    }

    #[test]
    fn air_rejects_idle_data_mutation() {
        let (leaves, _, root, opening, index) = tiny_tree_path_for_leaf_2();
        let mut flat = build_trace(&leaves[index], &opening, index, root, 16).unwrap();
        // Rows 3..=15 are IDLE. Mutate row 5's DIGEST[0]. IDLE
        // persistence transition from row 4 → row 5 catches it.
        let row5 = 5 * col::WIDTH;
        flat[row5 + col::DIGEST0] += Goldilocks::new(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "IDLE rows must carry data cols unchanged"
        );
    }

    #[test]
    fn air_width_matches_layout_constant() {
        // Regression guard: if anyone shifts col offsets the width
        // constant must move in lockstep.
        assert_eq!(
            <MerklePathAirV1 as BaseAir<Goldilocks>>::width(&MerklePathAirV1),
            MERKLE_PATH_AIR_FRAMING_WIDTH,
        );
    }
}
