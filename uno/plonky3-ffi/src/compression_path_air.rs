//! Compression-only Merkle-path AIR — digest-to-root path verification
//! (Phase A2-3c-iv-d-7-d).
//!
//! Takes a pre-computed `LEAF_DIGEST` as input and walks the Merkle
//! path via binary compress steps (`Poseidon2-w8` truncated
//! permutation) to a target `ROOT`. Designed to compose with
//! `leaf_hash_air` (A2-3c-iv-d-7-a/b/c) via cross-AIR orchestration:
//!
//! ```text
//!   wide leaf  ──leaf_hash_air──▶ DIGEST  ══╗
//!                                           ║ cross-binding
//!                                           ╚═▶ LEAF_DIGEST  ──compression_path_air──▶ ROOT
//! ```
//!
//! Unlike `merkle_path_air` (which bakes the 4-Goldilocks leaf hash
//! into its first row), this AIR skips the leaf-hash phase entirely,
//! letting the caller supply the digest via a public-input proxy.
//! That's what makes the "wide leaf → root" chain expressible.
//!
//! # Column layout (32 framing cols + 180-col P2 block = 212 cols)
//!
//! ```text
//!   KIND[0..3]            one-hot {COMPRESS, IDLE, RESERVED}
//!   CURRENT[0..4]         digest at row start (first COMPRESS row: = LEAF_DIGEST)
//!   SIBLING[0..4]         this level's sibling digest
//!   LEFT[0..4]            P2 left-input (= INDEX_BIT == 0 ? CURRENT : SIBLING)
//!   RIGHT[0..4]           P2 right-input (= INDEX_BIT == 0 ? SIBLING : CURRENT)
//!   INDEX_BIT             level-orientation bit (boolean)
//!   DIGEST[0..4]          P2 post-state truncated to first 4 (this row's output)
//!   LEAF_DIGEST[0..4]     public-input proxy: starting digest
//!   ROOT[0..4]            public-input proxy: expected Merkle root
//!   P2_BLOCK              180-col Poseidon2-w8 witness (row-gated by is_compress)
//! ```
//!
//! # Transition rules
//!
//! - KIND one-hot (degree 1) with flag boolean checks.
//! - COMPRESS row:
//!   * INDEX_BIT boolean (gated by is_compress).
//!   * LEFT  = (1 − INDEX_BIT)·CURRENT + INDEX_BIT·SIBLING.
//!   * RIGHT = INDEX_BIT·CURRENT + (1 − INDEX_BIT)·SIBLING.
//!   * P2(LEFT ∥ RIGHT)[0..4] == DIGEST   (Poseidon2 block binding).
//! - Transition: next.IS_COMPRESS ⇒ next.CURRENT = local.DIGEST.
//! - Transition: LEAF_DIGEST, ROOT persist across rows.
//! - Transition: next.IS_IDLE ⇒ all non-KIND framing cols preserved.
//! - Boundary (first row, if COMPRESS): CURRENT = LEAF_DIGEST.
//! - Boundary (last row): DIGEST = ROOT.
//!
//! # Comparison with `merkle_path_air`
//!
//! - `merkle_path_air`: leaf_hash + compression chain in one AIR. Leaf
//!   width restricted to 4 Goldilocks (narrow leaf).
//! - `compression_path_air` (this module): compression chain only,
//!   leaf digest supplied externally. Enables wide-leaf Merkle paths
//!   by cross-binding `leaf_hash_air.DIGEST` = `LEAF_DIGEST`.
//! - Both are sound; they coexist. Future integration may deprecate
//!   `merkle_path_air`'s leaf-hash row in favor of always using
//!   `leaf_hash_air` + `compression_path_air`.

use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};
use p3_poseidon2_air::RoundConstants;

use crate::merkle_path::{compress_pair_ref, Digest};
use crate::transfer_air::{
    eval_poseidon2, P2Cols, POSEIDON2_COLS_PER_INSTANCE, POSEIDON2_HALF_FULL_ROUNDS,
};
use core::borrow::Borrow;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const DIGEST_WIDTH: usize = 4;

pub const OP_KIND_COMPRESS: u8 = 0;
pub const OP_KIND_IDLE: u8 = 1;
/// Reserved slot; unused at d-7-d but kept for forward compatibility.
pub const OP_KIND_RESERVED: u8 = 2;
pub const NUM_OP_KINDS: usize = 3;

// ---------------------------------------------------------------------------
// Column offsets
// ---------------------------------------------------------------------------

pub mod col {
    use super::*;

    pub const KIND0: usize = 0;
    pub const KIND_END: usize = KIND0 + NUM_OP_KINDS;

    pub const CURRENT0: usize = KIND_END;
    pub const CURRENT_END: usize = CURRENT0 + DIGEST_WIDTH;

    pub const SIBLING0: usize = CURRENT_END;
    pub const SIBLING_END: usize = SIBLING0 + DIGEST_WIDTH;

    pub const LEFT0: usize = SIBLING_END;
    pub const LEFT_END: usize = LEFT0 + DIGEST_WIDTH;

    pub const RIGHT0: usize = LEFT_END;
    pub const RIGHT_END: usize = RIGHT0 + DIGEST_WIDTH;

    pub const INDEX_BIT: usize = RIGHT_END;

    pub const DIGEST0: usize = INDEX_BIT + 1;
    pub const DIGEST_END: usize = DIGEST0 + DIGEST_WIDTH;

    pub const LEAF_DIGEST0: usize = DIGEST_END;
    pub const LEAF_DIGEST_END: usize = LEAF_DIGEST0 + DIGEST_WIDTH;

    pub const ROOT0: usize = LEAF_DIGEST_END;
    pub const ROOT_END: usize = ROOT0 + DIGEST_WIDTH;

    pub const P2_BLOCK: usize = ROOT_END;

    pub const WIDTH: usize = P2_BLOCK + crate::transfer_air::POSEIDON2_COLS_PER_INSTANCE;
}

pub const COMPRESSION_PATH_AIR_FRAMING_WIDTH: usize = col::WIDTH;

// ---------------------------------------------------------------------------
// Shared Poseidon2-w8 helpers
// ---------------------------------------------------------------------------

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
    TraceHeightNotPow2 {
        got: usize,
    },
    TraceHeightTooSmall {
        physical_rows: usize,
        trace_height: usize,
    },
    IndexOutOfBoundsForPath {
        index: usize,
        path_len: usize,
    },
    EmptyPath,
}

/// Build a row-major trace that verifies the Merkle path from
/// `leaf_digest` to `expected_root` via `opening_proof.len()`
/// compression rows.
pub fn build_trace(
    leaf_digest: Digest,
    opening_proof: &[Digest],
    index: usize,
    expected_root: Digest,
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    if opening_proof.is_empty() {
        return Err(TraceBuildError::EmptyPath);
    }
    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let path_len = opening_proof.len();
    if path_len > trace_height {
        return Err(TraceBuildError::TraceHeightTooSmall {
            physical_rows: path_len,
            trace_height,
        });
    }
    if path_len < 64 && index >= (1usize << path_len) {
        return Err(TraceBuildError::IndexOutOfBoundsForPath { index, path_len });
    }

    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];
    let perm = default_goldilocks_poseidon2_8();

    // Pre-compute the compression chain.
    let mut current = leaf_digest;
    let mut idx = index;
    let mut digests_per_row: Vec<Digest> = Vec::with_capacity(path_len);
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

    let zero_g = Goldilocks::default();
    let write_digest = |out: &mut [Goldilocks], base: usize, d: &Digest| {
        for i in 0..DIGEST_WIDTH {
            out[base + i] = d[i];
        }
    };
    let write_kind = |out: &mut [Goldilocks], kind: u8| {
        for k in 0..NUM_OP_KINDS {
            out[col::KIND0 + k] = if k as u8 == kind {
                Goldilocks::new(1)
            } else {
                zero_g
            };
        }
    };

    let mut running = leaf_digest;
    let mut idx = index;
    for (r, sibling) in opening_proof.iter().enumerate() {
        let base = r * width;
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
        let new_digest = digests_per_row[r];
        write_digest(row, col::DIGEST0, &new_digest);
        write_digest(row, col::LEAF_DIGEST0, &leaf_digest);
        write_digest(row, col::ROOT0, &expected_root);

        running = new_digest;
        idx >>= 1;
    }

    // Pad with IDLE rows.
    for row_idx in path_len..trace_height {
        let prev_base = (row_idx - 1) * width;
        let prev_row = flat[prev_base..prev_base + width].to_vec();
        let base = row_idx * width;
        let row = &mut flat[base..base + width];
        for c in col::KIND_END..col::P2_BLOCK {
            row[c] = prev_row[c];
        }
        write_kind(row, OP_KIND_IDLE);
    }

    // Populate the P2 block on every row.
    for row_idx in 0..trace_height {
        let base = row_idx * width;
        let is_compress = flat[base + col::KIND0 + OP_KIND_COMPRESS as usize] == Goldilocks::new(1);
        let input: [Goldilocks; 8] = if is_compress {
            let mut s = [zero_g; 8];
            for i in 0..DIGEST_WIDTH {
                s[i] = flat[base + col::LEFT0 + i];
                s[DIGEST_WIDTH + i] = flat[base + col::RIGHT0 + i];
            }
            s
        } else {
            [zero_g; 8]
        };
        let p2_witness = gen_p2_witness(input);
        for (i, v) in p2_witness.into_iter().enumerate() {
            flat[base + col::P2_BLOCK + i] = v;
        }
    }

    Ok(flat)
}

// ---------------------------------------------------------------------------
// Pure-Rust checker
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CheckError {
    TraceLengthMismatch { expected: usize, got: usize },
    KindFlagNotBoolean { row: usize, kind: usize },
    KindNotOneHot { row: usize },
    IndexBitNotBoolean { row: usize },
    CompressLeftMismatch { row: usize, col: usize },
    CompressRightMismatch { row: usize, col: usize },
    CompressDigestMismatch { row: usize, col: usize },
    CurrentPropagationMismatch { row: usize, col: usize },
    LeafDigestDrift { row: usize, col: usize },
    RootDrift { row: usize, col: usize },
    IdlePersistenceMismatch { row: usize, col: usize },
    Row0CurrentNotLeafDigest { col: usize },
    LastRowDigestNotRoot { col: usize },
}

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

    let mut last_non_idle_digest: Option<Digest> = None;

    for r in 0..trace_height {
        let local = row(r);

        // KIND one-hot + boolean.
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
        let is_compress = local[col::KIND0 + OP_KIND_COMPRESS as usize] == one;
        let is_idle = local[col::KIND0 + OP_KIND_IDLE as usize] == one;

        if is_compress {
            let bit = local[col::INDEX_BIT];
            if bit != zero && bit != one {
                return Err(CheckError::IndexBitNotBoolean { row: r });
            }
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
            // DIGEST = compress(LEFT, RIGHT).
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

        // CURRENT propagation on COMPRESS-after-COMPRESS (r ≥ 1).
        if is_compress && r > 0 {
            let prev = row(r - 1);
            for i in 0..DIGEST_WIDTH {
                if local[col::CURRENT0 + i] != prev[col::DIGEST0 + i] {
                    return Err(CheckError::CurrentPropagationMismatch { row: r, col: i });
                }
            }
        }

        // LEAF_DIGEST / ROOT persistence.
        if r > 0 {
            let prev = row(r - 1);
            for i in 0..DIGEST_WIDTH {
                if local[col::LEAF_DIGEST0 + i] != prev[col::LEAF_DIGEST0 + i] {
                    return Err(CheckError::LeafDigestDrift { row: r, col: i });
                }
                if local[col::ROOT0 + i] != prev[col::ROOT0 + i] {
                    return Err(CheckError::RootDrift { row: r, col: i });
                }
            }
        }

        // IDLE persistence.
        if is_idle && r > 0 {
            let prev = row(r - 1);
            for c in col::KIND_END..col::P2_BLOCK {
                if local[c] != prev[c] {
                    return Err(CheckError::IdlePersistenceMismatch { row: r, col: c });
                }
            }
        }

        if !is_idle {
            let mut d: Digest = [zero; DIGEST_WIDTH];
            for i in 0..DIGEST_WIDTH {
                d[i] = local[col::DIGEST0 + i];
            }
            last_non_idle_digest = Some(d);
        }
    }

    // Row-0 boundary: CURRENT == LEAF_DIGEST (if COMPRESS).
    {
        let row0 = row(0);
        let is_compress_0 = row0[col::KIND0 + OP_KIND_COMPRESS as usize] == one;
        if is_compress_0 {
            for i in 0..DIGEST_WIDTH {
                if row0[col::CURRENT0 + i] != row0[col::LEAF_DIGEST0 + i] {
                    return Err(CheckError::Row0CurrentNotLeafDigest { col: i });
                }
            }
        }
    }

    // Last-non-IDLE DIGEST == ROOT (via IDLE-persistence propagation
    // to the literal last row).
    if let Some(_d) = last_non_idle_digest {
        let last = row(trace_height - 1);
        for i in 0..DIGEST_WIDTH {
            if last[col::DIGEST0 + i] != last[col::ROOT0 + i] {
                return Err(CheckError::LastRowDigestNotRoot { col: i });
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Plonky3 AIR — mechanical port of the checker
// ---------------------------------------------------------------------------

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

#[derive(Copy, Clone, Debug, Default)]
pub struct CompressionPathAirV1;

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for CompressionPathAirV1 {
    #[inline]
    fn width(&self) -> usize {
        COMPRESSION_PATH_AIR_FRAMING_WIDTH
    }
    #[inline]
    fn num_public_values(&self) -> usize {
        0
    }
    #[inline]
    fn max_constraint_degree(&self) -> Option<usize> {
        None
    }
}

impl<AB> Air<AB> for CompressionPathAirV1
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

        let is_compress: AB::Expr = local[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        let is_idle: AB::Expr = local[col::KIND0 + OP_KIND_IDLE as usize].into();

        // KIND one-hot.
        let mut kind_sum = zero();
        for k in 0..NUM_OP_KINDS {
            let flag: AB::Expr = local[col::KIND0 + k].into();
            builder.assert_zero(flag.clone() * (flag.clone() - one()));
            kind_sum = kind_sum + flag;
        }
        builder.assert_eq(kind_sum, one());

        // COMPRESS row: INDEX_BIT boolean + LEFT/RIGHT selection.
        let bit: AB::Expr = local[col::INDEX_BIT].into();
        builder.assert_zero(is_compress.clone() * bit.clone() * (bit.clone() - one()));
        for i in 0..DIGEST_WIDTH {
            let cur: AB::Expr = local[col::CURRENT0 + i].into();
            let sib: AB::Expr = local[col::SIBLING0 + i].into();
            let left: AB::Expr = local[col::LEFT0 + i].into();
            let right: AB::Expr = local[col::RIGHT0 + i].into();
            let expected_left = (one() - bit.clone()) * cur.clone() + bit.clone() * sib.clone();
            let expected_right = bit.clone() * cur + (one() - bit.clone()) * sib;
            builder.assert_zero(is_compress.clone() * (left - expected_left));
            builder.assert_zero(is_compress.clone() * (right - expected_right));
        }

        // Transition.
        let mut trans = builder.when_transition();

        // LEAF_DIGEST / ROOT persistence.
        for i in 0..DIGEST_WIDTH {
            let l_ld: AB::Expr = local[col::LEAF_DIGEST0 + i].into();
            let n_ld: AB::Expr = next[col::LEAF_DIGEST0 + i].into();
            trans.assert_zero(n_ld - l_ld);
            let l_r: AB::Expr = local[col::ROOT0 + i].into();
            let n_r: AB::Expr = next[col::ROOT0 + i].into();
            trans.assert_zero(n_r - l_r);
        }

        // CURRENT threading on COMPRESS transitions.
        let next_is_compress: AB::Expr = next[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        for i in 0..DIGEST_WIDTH {
            let n_cur: AB::Expr = next[col::CURRENT0 + i].into();
            let l_dg: AB::Expr = local[col::DIGEST0 + i].into();
            trans.assert_zero(next_is_compress.clone() * (n_cur - l_dg));
        }

        // IDLE persistence.
        let next_is_idle: AB::Expr = next[col::KIND0 + OP_KIND_IDLE as usize].into();
        for c in col::KIND_END..col::P2_BLOCK {
            let l_c: AB::Expr = local[c].into();
            let n_c: AB::Expr = next[c].into();
            trans.assert_zero(next_is_idle.clone() * (n_c - l_c));
        }

        drop(trans);

        // Boundary: row 0's CURRENT == LEAF_DIGEST on a COMPRESS row.
        // (If row 0 happens to be IDLE, this is vacuous.)
        let mut first = builder.when_first_row();
        for i in 0..DIGEST_WIDTH {
            let cur: AB::Expr = local[col::CURRENT0 + i].into();
            let ld: AB::Expr = local[col::LEAF_DIGEST0 + i].into();
            first.assert_zero(is_compress.clone() * (cur - ld));
        }
        drop(first);

        // Boundary: last row's DIGEST == ROOT.
        let mut last = builder.when_last_row();
        for i in 0..DIGEST_WIDTH {
            let dg: AB::Expr = local[col::DIGEST0 + i].into();
            let r: AB::Expr = local[col::ROOT0 + i].into();
            last.assert_zero(dg - r);
        }

        // Poseidon2 binding: is_compress · (p2.inputs − [LEFT ∥ RIGHT]) = 0
        //                    is_compress · (p2.post[0..4] − DIGEST) = 0
        let p2_local = p2_group::<AB::Var>(local);
        eval_poseidon2(builder, p2_local);

        for i in 0..DIGEST_WIDTH {
            let p2_in_l: AB::Expr = p2_local.inputs[i].into();
            let left_i: AB::Expr = local[col::LEFT0 + i].into();
            builder.assert_zero(is_compress.clone() * (p2_in_l - left_i));
            let p2_in_r: AB::Expr = p2_local.inputs[DIGEST_WIDTH + i].into();
            let right_i: AB::Expr = local[col::RIGHT0 + i].into();
            builder.assert_zero(is_compress.clone() * (p2_in_r - right_i));
        }
        let p2_post = &p2_local.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
        for i in 0..DIGEST_WIDTH {
            let p2_out: AB::Expr = p2_post[i].into();
            let dg: AB::Expr = local[col::DIGEST0 + i].into();
            builder.assert_zero(is_compress.clone() * (p2_out - dg));
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
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{prove, verify};

    use crate::merkle_path::hash_leaf_row_ref;
    use crate::prover::build_config;

    fn gl(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    /// Build a 4-leaf tiny tree; return (leaves, openings-for-each-leaf, root).
    fn tiny_tree_4_leaves() -> (Vec<Digest>, Vec<(Digest, Vec<Digest>, usize)>, Digest) {
        let perm = default_goldilocks_poseidon2_8();
        let leaves: Vec<[Goldilocks; 4]> = (0..4)
            .map(|i| [gl(100 + i), gl(200 + i), gl(300 + i), gl(400 + i)])
            .collect();
        let leaf_digests: Vec<Digest> =
            leaves.iter().map(|r| hash_leaf_row_ref(&perm, r)).collect();
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
        (leaf_digests, openings, root)
    }

    fn trace_matrix(
        leaf_digest: Digest,
        path: &[Digest],
        index: usize,
        root: Digest,
        trace_height: usize,
    ) -> RowMajorMatrix<Goldilocks> {
        let flat = build_trace(leaf_digest, path, index, root, trace_height).expect("trace");
        RowMajorMatrix::new(flat, col::WIDTH)
    }

    fn air_rejects(trace: RowMajorMatrix<Goldilocks>) -> bool {
        let cfg = build_config();
        let air = CompressionPathAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &[])
        }));
        match outcome {
            Err(_) => true,
            Ok(p) => verify(&cfg, &air, &p, &[]).is_err(),
        }
    }

    // ---- builder sanity ----

    #[test]
    fn build_rejects_empty_path() {
        let err = build_trace([gl(0); 4], &[], 0, [gl(0); 4], 4).unwrap_err();
        assert_eq!(err, TraceBuildError::EmptyPath);
    }

    #[test]
    fn build_rejects_non_pow2_height() {
        let (_, openings, root) = tiny_tree_4_leaves();
        let (ld, path, idx) = openings[0].clone();
        let err = build_trace(ld, &path, idx, root, 7).unwrap_err();
        assert_eq!(err, TraceBuildError::TraceHeightNotPow2 { got: 7 });
    }

    // ---- positive + real STARK prove+verify ----

    #[test]
    fn trace_and_check_accept_all_leaves() {
        let (_, openings, root) = tiny_tree_4_leaves();
        for (ld, path, idx) in &openings {
            let trace = build_trace(*ld, path, *idx, root, 8).unwrap();
            check_all_transitions(&trace, 8).expect("valid path must check");
        }
    }

    #[test]
    fn air_prove_and_verify_all_leaves() {
        let (_, openings, root) = tiny_tree_4_leaves();
        let cfg = build_config();
        let air = CompressionPathAirV1;
        for (ld, path, idx) in &openings {
            let trace = trace_matrix(*ld, path, *idx, root, 16);
            let proof = prove(&cfg, &air, trace, &[]);
            verify(&cfg, &air, &proof, &[]).expect("valid compression path must verify");
        }
    }

    // ---- adversarial ----

    #[test]
    fn air_rejects_tampered_sibling() {
        let (_, openings, root) = tiny_tree_4_leaves();
        let (ld, mut path, idx) = openings[0].clone();
        path[0][0] += gl(1);
        // After tampering the path (but not rebuilding the trace), the
        // trace builder would compute a different final digest — it
        // won't match root, so last-row boundary fires. Alternative:
        // build with real path, then post-tamper SIBLING column.
        let mut flat = build_trace(ld, &openings[0].1, idx, root, 16).unwrap();
        flat[col::SIBLING0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "tampered sibling must reject");
    }

    #[test]
    fn air_rejects_tampered_leaf_digest_breaks_row0_boundary() {
        let (_, openings, root) = tiny_tree_4_leaves();
        let (ld, path, idx) = openings[0].clone();
        let mut flat = build_trace(ld, &path, idx, root, 16).unwrap();
        // Corrupt row 0 LEAF_DIGEST[0]; the first-row boundary
        // (CURRENT == LEAF_DIGEST) fires.
        flat[col::LEAF_DIGEST0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "tampered LEAF_DIGEST must reject at row-0 boundary"
        );
    }

    #[test]
    fn air_rejects_wrong_root() {
        let (_, openings, root) = tiny_tree_4_leaves();
        let (ld, path, idx) = openings[0].clone();
        let mut bad_root = root;
        bad_root[0] += gl(1);
        let flat = build_trace(ld, &path, idx, bad_root, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "wrong ROOT must reject at last-row boundary"
        );
    }

    #[test]
    fn air_rejects_flipped_index_bit() {
        let (_, openings, root) = tiny_tree_4_leaves();
        let (ld, path, idx) = openings[0].clone();
        let mut flat = build_trace(ld, &path, idx, root, 16).unwrap();
        // Flip INDEX_BIT on row 0 → LEFT/RIGHT selection constraint fires.
        flat[col::INDEX_BIT] = if flat[col::INDEX_BIT] == gl(0) {
            gl(1)
        } else {
            gl(0)
        };
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "flipped INDEX_BIT must reject");
    }

    #[test]
    fn air_width_matches_layout_constant() {
        assert_eq!(
            <CompressionPathAirV1 as BaseAir<Goldilocks>>::width(&CompressionPathAirV1),
            COMPRESSION_PATH_AIR_FRAMING_WIDTH,
        );
    }

    // ---- cross-AIR composition: leaf_hash_air + compression_path_air ----

    /// Full "wide leaf → root" path: hash a width-W leaf via
    /// `leaf_hash_air` (producing a digest), then walk the Merkle path
    /// via this compression AIR. The cross-binding is:
    /// leaf_hash.EXPECTED_DIGEST == compression.LEAF_DIGEST.
    #[test]
    fn wide_leaf_to_root_via_leaf_hash_plus_compression() {
        use crate::leaf_hash_air;
        use p3_matrix::dense::RowMajorMatrix;

        // Build a tiny 4-leaf tree where each leaf is width 8 (two
        // absorb rows in leaf_hash_air).
        let perm = default_goldilocks_poseidon2_8();
        let leaves: Vec<Vec<Goldilocks>> = (0..4)
            .map(|i| (0..8).map(|j| gl((i * 100 + j * 13 + 1) as u64)).collect())
            .collect();
        let leaf_digests: Vec<Digest> =
            leaves.iter().map(|l| hash_leaf_row_ref(&perm, l)).collect();
        let level1 = vec![
            compress_pair_ref(&perm, &leaf_digests[0], &leaf_digests[1]),
            compress_pair_ref(&perm, &leaf_digests[2], &leaf_digests[3]),
        ];
        let root = compress_pair_ref(&perm, &level1[0], &level1[1]);

        // Open leaf index 2: siblings = [leaf_digests[3], level1[0]].
        let leaf_idx = 2;
        let opening_path = vec![leaf_digests[3], level1[0]];

        let cfg = build_config();

        // Step 1: leaf_hash_air proves the width-8 leaf hashes to leaf_digest.
        let lh_flat = leaf_hash_air::build_trace(&leaves[leaf_idx], leaf_digests[leaf_idx], 8)
            .expect("leaf_hash trace");
        let lh_trace = RowMajorMatrix::new(lh_flat, leaf_hash_air::col::WIDTH);
        let lh_air = leaf_hash_air::LeafHashAirV1;
        let lh_proof = prove(&cfg, &lh_air, lh_trace, &[]);
        verify(&cfg, &lh_air, &lh_proof, &[]).expect("leaf_hash must verify");

        // Step 2: compression_path_air proves leaf_digest walks to root.
        let cp_flat = build_trace(leaf_digests[leaf_idx], &opening_path, leaf_idx, root, 8)
            .expect("compression trace");
        let cp_trace = RowMajorMatrix::new(cp_flat, col::WIDTH);
        let cp_air = CompressionPathAirV1;
        let cp_proof = prove(&cfg, &cp_air, cp_trace, &[]);
        verify(&cfg, &cp_air, &cp_proof, &[]).expect("compression path must verify");

        // Cross-binding: leaf_hash's EXPECTED_DIGEST == compression's
        // LEAF_DIGEST. Since we built both traces using the same
        // `leaf_digests[leaf_idx]`, this holds by construction. An
        // orchestration layer (like query_verifier_air for the α+fold
        // chain) would explicitly assert this at the bundle level and
        // close the PoC-style cross-binding gap.
        //
        // For d-7-d this is the acceptance test: both AIRs verify
        // independently and carry the same digest on the boundary.
    }
}
