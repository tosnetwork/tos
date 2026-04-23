//! Trace-builder helpers for the Monolithic Verifier AIR.
//!
//! Extracted from `monolithic_verifier_air` to keep the main file focused on
//! the AIR `eval`. All public symbols are re-exported from
//! `monolithic_verifier_air` for backward compatibility.

use core::borrow::Borrow;

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};
use p3_symmetric::Permutation;

use crate::fri_arith::fold_row_ref;
use crate::merkle_path::{compress_pair_ref, Digest};
use crate::monolithic_verifier_columns::col;
use crate::prover::Challenge;
use crate::transfer_air::{P2Cols, POSEIDON2_COLS_PER_INSTANCE};

// Re-import all column-layout constants + the col module (wildcard).
#[allow(unused_imports)]
use crate::monolithic_verifier_columns::*;

// ---------------------------------------------------------------------------
// Trace builder (A3-PRE: emits IDLE-only rows for scaffold validation)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TraceBuildError {
    TraceHeightNotPow2 {
        got: usize,
    },
    EmptyLeaf,
    EmptyPath,
    TraceHeightTooSmall {
        physical_rows: usize,
        trace_height: usize,
    },
}

// ---------------------------------------------------------------------------
// A6-1.6: Block-level public inputs bound in-circuit.
//
// `BlockPi` is the 8-element Goldilocks encoding of the block's public
// inputs. The monolithic AIR declares `num_public_values() = 8`; the
// trace builder populates `BLOCK_PI_*` columns with this data on every
// row; `when_first_row` pins row 0 to `builder.public_values()`;
// unconditional persistence propagates the values to every other row.
// This cryptographically binds the proof to its PI.
//
// For test-only builders that don't care about PI binding,
// [`block_pi_zero`] returns an all-zero PI. Production call sites
// (currently only `build_multi_bundle_trace` via `aggregator::prove_block`)
// take an explicit `BlockPi`.
// ---------------------------------------------------------------------------

/// 8-element Goldilocks encoding of the block's public inputs, bound
/// in-circuit by the AIR's public-value check. See
/// `aggregator::block_public_inputs_to_field_elements` for the encoding.
#[derive(Copy, Clone, Debug, Default)]
pub struct BlockPi {
    pub values: [Goldilocks; col::NUM_BLOCK_PI_ELEMS],
}

impl BlockPi {
    pub fn new(values: [Goldilocks; col::NUM_BLOCK_PI_ELEMS]) -> Self {
        Self { values }
    }
}

/// Zero-PI helper for test-only builders. In production, `prove_block`
/// derives a real `BlockPi` from `BlockPublicInputs` via
/// `aggregator::block_public_inputs_to_field_elements`.
pub fn block_pi_zero() -> BlockPi {
    BlockPi {
        values: [Goldilocks::default(); col::NUM_BLOCK_PI_ELEMS],
    }
}

/// Write the 8 BLOCK_PI columns on a single row.
#[inline]
fn write_block_pi(row: &mut [Goldilocks], pi: &BlockPi) {
    row[col::BLOCK_PI_CHAIN_ID] = pi.values[0];
    row[col::BLOCK_PI_BLOCK_SEQNO] = pi.values[1];
    row[col::BLOCK_PI_ANCHOR_SEQNO] = pi.values[2];
    row[col::BLOCK_PI_N_TRANSFERS] = pi.values[3];
    for i in 0..4 {
        row[col::BLOCK_PI_ROOT0 + i] = pi.values[4 + i];
    }
}

/// Build a trivial all-IDLE trace of the requested height. Real
/// operation-specific rows land in A3-1+ as each bank migrates in.
///
/// A6-1.6: this test builder populates BLOCK_PI columns with zeros so
/// the in-circuit PI binding trivially passes when callers invoke
/// `prove(&cfg, &air, trace, &[Goldilocks::default(); 8])`.
pub fn build_trivial_trace(trace_height: usize) -> Result<Vec<Goldilocks>, TraceBuildError> {
    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];
    let pi_zero = block_pi_zero();

    // Populate KIND = IDLE on every row + BLOCK_LEN_FLAG[0] = 1 (A3-1
    // requires BLOCK_LEN flags be a valid one-hot on every row).
    for r in 0..trace_height {
        let base = r * width;
        flat[base + col::KIND0 + OP_KIND_IDLE as usize] = Goldilocks::new(1);
        flat[base + col::ABSORB_BLOCK_LEN_FLAG0] = Goldilocks::new(1);
        write_block_pi(&mut flat[base..base + width], &pi_zero);
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
    let pi_zero = block_pi_zero();

    let write_kind = |out: &mut [Goldilocks], kind: u8| {
        for k in 0..NUM_OP_KINDS {
            out[col::KIND0 + k] = if k as u8 == kind {
                Goldilocks::new(1)
            } else {
                zero_g
            };
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
        write_block_pi(row, &pi_zero);

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
    // Start with leaf_digest (STATE_OUT[0..4] of last ABSORB row).
    let mut running: Digest = {
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
        write_block_pi(row, &pi_zero);
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
    let pi_zero = block_pi_zero();

    let write_kind = |out: &mut [Goldilocks], kind: u8| {
        for k in 0..NUM_OP_KINDS {
            out[col::KIND0 + k] = if k as u8 == kind {
                Goldilocks::new(1)
            } else {
                zero_g
            };
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
            write_block_pi(row, &pi_zero);

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
            write_block_pi(row, &pi_zero);
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
        let limbs = <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&v);
        for i in 0..CHALLENGE_DIM {
            out[base + i] = limbs[i];
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
    // Flag[0] = 1 on every non-ABSORB row (BLOCK_LEN = 0).
    let zero_block_len_flag = |out: &mut [Goldilocks]| {
        out[col::ABSORB_BLOCK_LEN_FLAG0] = Goldilocks::new(1);
    };

    let mut alpha_pow = initial_alpha_pow;
    let mut ro = initial_ro;
    let p2_zero_witness = gen_p2_witness_zero();
    let pi_zero = block_pi_zero();

    for (r, step) in steps.iter().enumerate() {
        let base = r * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_ALPHA);
        write_block_pi(row, &pi_zero);
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
        let quot_inv = denom.try_inverse().expect("denom ≠ 0 ⇒ invertible");
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
        let limbs = <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&v);
        for i in 0..CHALLENGE_DIM {
            out[base + i] = limbs[i];
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
    let zero_block_len_flag = |out: &mut [Goldilocks]| {
        out[col::ABSORB_BLOCK_LEN_FLAG0] = Goldilocks::new(1);
    };

    let p2_zero_witness = gen_p2_witness_zero();
    let pi_zero = block_pi_zero();

    let mut current = initial_folded;
    for (r, round) in rounds.iter().enumerate() {
        let base = r * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_FOLD);
        write_block_pi(row, &pi_zero);
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
        let limbs = <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&v);
        for i in 0..CHALLENGE_DIM {
            out[base + i] = limbs[i];
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
    let zero_block_len_flag = |out: &mut [Goldilocks]| {
        out[col::ABSORB_BLOCK_LEN_FLAG0] = Goldilocks::new(1);
    };

    let p2_zero_witness = gen_p2_witness_zero();
    let pi_zero = block_pi_zero();

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
        write_block_pi(row, &pi_zero);
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
        write_block_pi(row, &pi_zero);
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
// A3-5b trace builder: full per-query bundle — α + Merkle paths + fold
//
// Composes in ONE monolithic AIR trace:
//   rows 0..N_α              : ALPHA rows   (α-reduction chain; produces ρ_final)
//   rows N_α..P              : Merkle paths (ABSORB + COMPRESS per path)
//   rows P..P+N_fold         : FOLD rows    (fold chain seeded by ρ_final)
//   rows P+N_fold..height    : IDLE padding
//
// No new constraints are needed — A3-3's non-α ALPHA_RO_OUT persistence
// and non-fold FOLD_OUT persistence thread ρ_final from the last α row
// through all Merkle rows to the last-non-FOLD row's FOLD_OUT. The FOLD
// threading transition then reads that FOLD_OUT into first-FOLD's
// FOLD_IN, seeding the fold chain.
//
// Concretely:
//   - Last α row:           ALPHA_RO_OUT = ρ_final, FOLD_OUT = ρ_final.
//   - Merkle rows:          ALPHA_RO_OUT = ρ_final (non-α persistence),
//                           FOLD_OUT = ρ_final (non-fold persistence).
//   - Last Merkle COMPRESS: FOLD_OUT = ρ_final.
//   - FOLD → threads:       next.FOLD_IN = local.FOLD_OUT = ρ_final.
//   - Last FOLD row:        FOLD_OUT = FINAL_FOLDED (boundary),
//                           ALPHA_RO_OUT = ρ_final = FINAL_RO (boundary).
// ---------------------------------------------------------------------------

/// Build a trace that composes α-reduction + N Merkle path openings +
/// FRI fold chain into ONE monolithic STARK.
///
/// `alpha_steps` seeds the α chain. `merkle_paths` is processed in
/// order; each path's ABSORB+COMPRESS rows land between the α chain
/// and the fold chain. `fold_rounds` seeded by the α chain's ρ_final.
pub fn build_alpha_merkle_fold_bundle_trace(
    initial_alpha_pow: Challenge,
    initial_ro: Challenge,
    alpha: Challenge,
    alpha_steps: &[AlphaStep],
    merkle_paths: &[MerkleOpening<'_>],
    fold_rounds: &[FoldRound],
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    use p3_field::{BasedVectorSpace, Field, TwoAdicField};
    use p3_util::reverse_bits_len;

    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    if alpha_steps.is_empty() || fold_rounds.is_empty() {
        return Err(TraceBuildError::EmptyPath);
    }
    // Bundle requires at least one Merkle path; otherwise use
    // build_alpha_to_fold_unified_trace directly.
    if merkle_paths.is_empty() {
        return Err(TraceBuildError::EmptyPath);
    }

    let n_alpha = alpha_steps.len();
    let n_fold = fold_rounds.len();
    let mut n_merkle = 0usize;
    for p in merkle_paths {
        if p.leaf.is_empty() {
            return Err(TraceBuildError::EmptyLeaf);
        }
        if p.opening_proof.is_empty() {
            return Err(TraceBuildError::EmptyPath);
        }
        n_merkle += (p.leaf.len() + SPONGE_RATE - 1) / SPONGE_RATE + p.opening_proof.len();
    }
    let physical_rows = n_alpha + n_merkle + n_fold;
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

    let write_ext = |out: &mut [Goldilocks], base: usize, v: Challenge| {
        let limbs = <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&v);
        for i in 0..CHALLENGE_DIM {
            out[base + i] = limbs[i];
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
    let write_block_len_flags = |out: &mut [Goldilocks], len: usize| {
        debug_assert!(len <= SPONGE_RATE);
        out[col::ABSORB_BLOCK_LEN] = Goldilocks::new(len as u64);
        for k in 0..=SPONGE_RATE {
            out[col::ABSORB_BLOCK_LEN_FLAG0 + k] =
                if k == len { Goldilocks::new(1) } else { zero_g };
        }
    };
    let write_root = |out: &mut [Goldilocks], root: &Digest| {
        for i in 0..DIGEST_WIDTH {
            out[col::TRACE_COMMIT_ROOT0 + i] = root[i];
        }
    };

    // --- Pass 1: run α chain off-circuit. ---
    let mut apow = initial_alpha_pow;
    let mut ro = initial_ro;
    let mut alpha_records: Vec<(Challenge, Challenge, Challenge, Challenge)> =
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
        alpha_records.push((qi, dq, apow_in, ro_in));
    }
    let rho_final = ro;
    let alpha_final_pow = apow;

    // --- Pass 2: run fold chain off-circuit. ---
    let mut fold_current = rho_final;
    let mut fold_records: Vec<(Goldilocks, Goldilocks, Challenge, Challenge, Challenge)> =
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
            (fold_current, round.sibling)
        } else {
            (round.sibling, fold_current)
        };
        let folded = fold_row_ref(
            parent_idx,
            child_log_h,
            1,
            round.beta,
            &[pair_left, pair_right],
        );
        fold_records.push((s, inv_2s, pair_left, pair_right, folded));
        fold_current = folded;
    }
    let final_folded = fold_current;

    let p2_zero_witness = gen_p2_witness_zero();
    let pi_zero = block_pi_zero();

    // Helper: populate PI proxies + α-persistence cols on non-α rows.
    // rho_final threads through via A3-3's non-α persistence.
    let populate_shared = |row: &mut [Goldilocks]| {
        write_ext(row, col::INITIAL_ALPHA_POW0, initial_alpha_pow);
        write_ext(row, col::INITIAL_RO0, initial_ro);
        write_ext(row, col::FINAL_FOLDED0, final_folded);
        write_ext(row, col::INITIAL_FOLDED0, rho_final);
        write_ext(row, col::FINAL_RO0, rho_final);
        // ALPHA_RO_OUT = rho_final (non-α persistence requires this).
        write_ext(row, col::ALPHA_RO_OUT0, rho_final);
        // FOLD_OUT = rho_final (non-fold persistence requires this on
        // α + Merkle rows; FOLD rows overwrite with the fold result).
        write_ext(row, col::FOLD_OUT0, rho_final);
        // Keep ALPHA_* persistence cols consistent (not constrained on
        // non-α rows; populate for audit clarity).
        write_ext(row, col::ALPHA_POW_IN0, alpha_final_pow);
        write_ext(row, col::ALPHA_POW_OUT0, alpha_final_pow);
        write_ext(row, col::ALPHA_RO_IN0, rho_final);
        // A6-1.6: block-level PI columns (zero for this test builder).
        write_block_pi(row, &pi_zero);
    };

    // --- Pass 3: emit ALPHA rows. ---
    for (r, (step, record)) in alpha_steps.iter().zip(alpha_records.iter()).enumerate() {
        let (qi, dq, apow_in, ro_in) = *record;
        let base = r * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_ALPHA);
        write_block_pi(row, &pi_zero);
        write_block_len_flags(row, 0);

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

        // FOLD_OUT = ρ_final on α rows (A3-3 convention, so non-fold
        // persistence holds across α→α and α→Merkle transitions).
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

    // --- Pass 4: emit Merkle path rows. ---
    let mut row_cursor = n_alpha;
    for path in merkle_paths {
        let n_absorb = (path.leaf.len() + SPONGE_RATE - 1) / SPONGE_RATE;
        let n_compress = path.opening_proof.len();

        // ABSORB rows of this path.
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
                state = [zero_g; SPONGE_WIDTH];
            }
            for i in 0..block_len {
                state[i] = path.leaf[block_start + i];
            }
            for i in 0..SPONGE_WIDTH {
                row[col::STATE_IN0 + i] = state[i];
            }
            let state_in_values = state;
            perm.permute_mut(&mut state);
            for i in 0..SPONGE_WIDTH {
                row[col::STATE_OUT0 + i] = state[i];
            }
            if is_last {
                for i in 0..DIGEST_WIDTH {
                    row[col::DIGEST0 + i] = state[i];
                }
            }
            write_root(row, &path.expected_root);

            let p2_witness = gen_p2_witness(state_in_values);
            for (i, v) in p2_witness.into_iter().enumerate() {
                row[col::P2_BLOCK + i] = v;
            }

            populate_shared(row);
        }

        // COMPRESS rows of this path.
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
            write_root(row, &path.expected_root);

            let p2_witness = gen_p2_witness(state_in_values);
            for (i, v) in p2_witness.into_iter().enumerate() {
                row[col::P2_BLOCK + i] = v;
            }

            populate_shared(row);

            running = new_digest;
            idx >>= 1;
        }
        debug_assert_eq!(
            running, path.expected_root,
            "bundle builder: Merkle path digest mismatch",
        );

        row_cursor += n_absorb + n_compress;
    }

    // --- Pass 5: emit FOLD rows. ---
    let mut fold_current = rho_final;
    for (r, (round, record)) in fold_rounds.iter().zip(fold_records.iter()).enumerate() {
        let (s, inv_2s, pair_left, pair_right, folded) = *record;
        let row_idx = row_cursor + r;
        let base = row_idx * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_FOLD);
        write_block_pi(row, &pi_zero);
        write_block_len_flags(row, 0);

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

        // ALPHA persistence cols.
        write_ext(row, col::ALPHA_RO_OUT0, rho_final);
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
    row_cursor += n_fold;

    // --- Pass 6: IDLE padding. ---
    for r in row_cursor..trace_height {
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
// A3-5c trace builder: multi-bundle — stack N per-Tx-query bundles
//
// Each bundle is one (α-reduction, Merkle paths, fold) triple with its
// OWN α challenge, own openings, own ρ_final, own FINAL_FOLDED. The
// builder stacks them back-to-back in one monolithic trace:
//
//   rows of bundle 0 (α + Merkle + fold)
//   rows of bundle 1 (α + Merkle + fold)
//   ...
//   rows of bundle N-1
//   IDLE padding
//
// Cross-bundle invariants enforced by A3-5c constraints:
//   - PI proxies (INITIAL_ALPHA_POW, INITIAL_RO, FINAL_FOLDED,
//     INITIAL_FOLDED, FINAL_RO) persist within a bundle, change
//     freely at bundle boundaries (non-α → α transitions).
//   - At each bundle boundary: prev bundle's ALPHA_RO_OUT and
//     FOLD_OUT are checked against its FINAL_RO / FINAL_FOLDED; new
//     bundle's ALPHA_POW_IN / ALPHA_RO_IN are seeded from its
//     INITIAL_ALPHA_POW / INITIAL_RO.
//   - Trace last-row boundaries check the LAST bundle's close.
// ---------------------------------------------------------------------------

/// A single per-query bundle specification.
#[derive(Clone, Debug)]
pub struct BundleSpec<'a> {
    /// α-chain seed.
    pub initial_alpha_pow: Challenge,
    pub initial_ro: Challenge,
    /// Per-bundle α challenge.
    pub alpha: Challenge,
    /// α-reduction steps.
    pub alpha_steps: &'a [AlphaStep],
    /// Merkle paths to open (trace-commit, quot-commit, etc.).
    pub merkle_paths: &'a [MerkleOpening<'a>],
    /// FRI fold rounds, seeded by this bundle's ρ_final.
    pub fold_rounds: &'a [FoldRound],
}

/// Build a trace that stacks `bundles` back-to-back, each verified
/// in-circuit with its own α/ρ/final-folded via A3-5c bundle-boundary
/// constraints.
///
/// A6-1.6: `block_pi` is the 8-element Goldilocks encoding of the
/// block's [`BlockPublicInputs`]. Every row has BLOCK_PI columns set to
/// these values; the AIR's `when_first_row` boundary pins row 0 to
/// `builder.public_values()`, cryptographically binding the proof to
/// its declared PI.
pub fn build_multi_bundle_trace(
    bundles: &[BundleSpec<'_>],
    block_pi: &BlockPi,
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    use p3_field::{BasedVectorSpace, Field, TwoAdicField};
    use p3_util::reverse_bits_len;

    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    if bundles.is_empty() {
        return Err(TraceBuildError::EmptyPath);
    }

    // Validate + count rows.
    let mut physical_rows = 0usize;
    for b in bundles {
        if b.alpha_steps.is_empty() || b.fold_rounds.is_empty() {
            return Err(TraceBuildError::EmptyPath);
        }
        if b.merkle_paths.is_empty() {
            return Err(TraceBuildError::EmptyPath);
        }
        let mut merkle_rows = 0usize;
        for p in b.merkle_paths {
            if p.leaf.is_empty() {
                return Err(TraceBuildError::EmptyLeaf);
            }
            if p.opening_proof.is_empty() {
                return Err(TraceBuildError::EmptyPath);
            }
            merkle_rows += (p.leaf.len() + SPONGE_RATE - 1) / SPONGE_RATE + p.opening_proof.len();
        }
        physical_rows += b.alpha_steps.len() + merkle_rows + b.fold_rounds.len();
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

    let write_ext = |out: &mut [Goldilocks], base: usize, v: Challenge| {
        let limbs = <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&v);
        for i in 0..CHALLENGE_DIM {
            out[base + i] = limbs[i];
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
    let write_block_len_flags = |out: &mut [Goldilocks], len: usize| {
        debug_assert!(len <= SPONGE_RATE);
        out[col::ABSORB_BLOCK_LEN] = Goldilocks::new(len as u64);
        for k in 0..=SPONGE_RATE {
            out[col::ABSORB_BLOCK_LEN_FLAG0 + k] =
                if k == len { Goldilocks::new(1) } else { zero_g };
        }
    };
    let write_root = |out: &mut [Goldilocks], root: &Digest| {
        for i in 0..DIGEST_WIDTH {
            out[col::TRACE_COMMIT_ROOT0 + i] = root[i];
        }
    };

    let p2_zero_witness = gen_p2_witness_zero();

    let mut row_cursor: usize = 0;

    for bundle in bundles {
        // === Compute bundle's ρ_final and final_folded off-circuit. ===
        let mut apow = bundle.initial_alpha_pow;
        let mut ro = bundle.initial_ro;
        let mut alpha_records: Vec<(Challenge, Challenge, Challenge, Challenge)> =
            Vec::with_capacity(bundle.alpha_steps.len());
        for step in bundle.alpha_steps {
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
            apow = apow_in * bundle.alpha;
            alpha_records.push((qi, dq, apow_in, ro_in));
        }
        let rho_final = ro;
        let alpha_final_pow = apow;

        let mut fold_current = rho_final;
        let mut fold_records: Vec<(Goldilocks, Goldilocks, Challenge, Challenge, Challenge)> =
            Vec::with_capacity(bundle.fold_rounds.len());
        for round in bundle.fold_rounds {
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
                (fold_current, round.sibling)
            } else {
                (round.sibling, fold_current)
            };
            let folded = fold_row_ref(
                parent_idx,
                child_log_h,
                1,
                round.beta,
                &[pair_left, pair_right],
            );
            fold_records.push((s, inv_2s, pair_left, pair_right, folded));
            fold_current = folded;
        }
        let final_folded = fold_current;

        // Helper: write this bundle's PI proxies (all rows in bundle
        // carry them; A3-5c PI persistence allows cross-bundle change).
        let populate_pi = |row: &mut [Goldilocks]| {
            write_ext(row, col::INITIAL_ALPHA_POW0, bundle.initial_alpha_pow);
            write_ext(row, col::INITIAL_RO0, bundle.initial_ro);
            write_ext(row, col::FINAL_FOLDED0, final_folded);
            write_ext(row, col::INITIAL_FOLDED0, rho_final);
            write_ext(row, col::FINAL_RO0, rho_final);
        };

        // === ALPHA rows ===
        for (r, (step, record)) in bundle
            .alpha_steps
            .iter()
            .zip(alpha_records.iter())
            .enumerate()
        {
            let (qi, dq, apow_in, ro_in) = *record;
            let base = (row_cursor + r) * width;
            let row = &mut flat[base..base + width];
            write_kind(row, OP_KIND_ALPHA);
            write_block_pi(row, block_pi);
            write_block_len_flags(row, 0);

            row[col::ALPHA_P_AT_X] = step.p_at_x;
            write_ext(row, col::ALPHA_P_AT_Z0, step.p_at_z);
            write_ext(row, col::ALPHA_Z0, step.z);
            row[col::ALPHA_X] = step.x;

            write_ext(row, col::ALPHA_QUOT_INV0, qi);
            write_ext(row, col::ALPHA_DIFF_QUOT0, dq);
            write_ext(row, col::ALPHA_CHALLENGE0, bundle.alpha);
            write_ext(row, col::ALPHA_POW_IN0, apow_in);
            write_ext(row, col::ALPHA_POW_OUT0, apow_in * bundle.alpha);
            write_ext(row, col::ALPHA_RO_IN0, ro_in);
            let new_ro = ro_in + apow_in * dq;
            write_ext(row, col::ALPHA_RO_OUT0, new_ro);

            // FOLD_OUT = ρ_final so A3-3 non-fold persistence holds
            // across α→α and α→Merkle transitions (within bundle).
            write_ext(row, col::FOLD_OUT0, rho_final);

            populate_pi(row);
            for (i, v) in p2_zero_witness.iter().enumerate() {
                row[col::P2_BLOCK + i] = *v;
            }
        }
        let mut inner_cursor = row_cursor + bundle.alpha_steps.len();

        // === Merkle paths ===
        for path in bundle.merkle_paths {
            let n_absorb = (path.leaf.len() + SPONGE_RATE - 1) / SPONGE_RATE;
            let n_compress = path.opening_proof.len();

            // ABSORB rows.
            let mut state: [Goldilocks; SPONGE_WIDTH] = [zero_g; SPONGE_WIDTH];
            for r in 0..n_absorb {
                let base = (inner_cursor + r) * width;
                let row = &mut flat[base..base + width];
                write_kind(row, OP_KIND_ABSORB);
                write_block_pi(row, block_pi);

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
                    state = [zero_g; SPONGE_WIDTH];
                }
                for i in 0..block_len {
                    state[i] = path.leaf[block_start + i];
                }
                for i in 0..SPONGE_WIDTH {
                    row[col::STATE_IN0 + i] = state[i];
                }
                let state_in_values = state;
                perm.permute_mut(&mut state);
                for i in 0..SPONGE_WIDTH {
                    row[col::STATE_OUT0 + i] = state[i];
                }
                if is_last {
                    for i in 0..DIGEST_WIDTH {
                        row[col::DIGEST0 + i] = state[i];
                    }
                }
                write_root(row, &path.expected_root);

                // Persistence cols (ρ_final propagated by A3-3 non-α/
                // non-fold persistence).
                write_ext(row, col::ALPHA_RO_OUT0, rho_final);
                write_ext(row, col::FOLD_OUT0, rho_final);
                // α cols (free on Merkle rows; populate for consistency).
                write_ext(row, col::ALPHA_POW_IN0, alpha_final_pow);
                write_ext(row, col::ALPHA_POW_OUT0, alpha_final_pow);
                write_ext(row, col::ALPHA_RO_IN0, rho_final);

                populate_pi(row);

                let p2_witness = gen_p2_witness(state_in_values);
                for (i, v) in p2_witness.into_iter().enumerate() {
                    row[col::P2_BLOCK + i] = v;
                }
            }

            // COMPRESS rows.
            let mut running: Digest = {
                let last_absorb_base = (inner_cursor + n_absorb - 1) * width;
                let mut d = [zero_g; DIGEST_WIDTH];
                for i in 0..DIGEST_WIDTH {
                    d[i] = flat[last_absorb_base + col::STATE_OUT0 + i];
                }
                d
            };
            let mut idx = path.index;
            for (r, sibling) in path.opening_proof.iter().enumerate() {
                let row_idx = inner_cursor + n_absorb + r;
                let base = row_idx * width;
                let row = &mut flat[base..base + width];
                write_kind(row, OP_KIND_COMPRESS);
                write_block_pi(row, block_pi);
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
                write_root(row, &path.expected_root);

                write_ext(row, col::ALPHA_RO_OUT0, rho_final);
                write_ext(row, col::FOLD_OUT0, rho_final);
                write_ext(row, col::ALPHA_POW_IN0, alpha_final_pow);
                write_ext(row, col::ALPHA_POW_OUT0, alpha_final_pow);
                write_ext(row, col::ALPHA_RO_IN0, rho_final);

                populate_pi(row);

                let p2_witness = gen_p2_witness(state_in_values);
                for (i, v) in p2_witness.into_iter().enumerate() {
                    row[col::P2_BLOCK + i] = v;
                }

                running = new_digest;
                idx >>= 1;
            }
            debug_assert_eq!(
                running, path.expected_root,
                "multi-bundle: Merkle path digest mismatch",
            );

            inner_cursor += n_absorb + n_compress;
        }

        // === FOLD rows ===
        let mut cur = rho_final;
        for (r, (round, record)) in bundle
            .fold_rounds
            .iter()
            .zip(fold_records.iter())
            .enumerate()
        {
            let (s, inv_2s, pair_left, pair_right, folded) = *record;
            let row_idx = inner_cursor + r;
            let base = row_idx * width;
            let row = &mut flat[base..base + width];
            write_kind(row, OP_KIND_FOLD);
            write_block_pi(row, block_pi);
            write_block_len_flags(row, 0);

            let bit = (round.domain_index & 1) as u64;
            write_ext(row, col::FOLD_IN0, cur);
            write_ext(row, col::FOLD_OUT0, folded);
            write_ext(row, col::FOLD_BETA0, round.beta);
            row[col::FOLD_S] = s;
            row[col::FOLD_INV_2S] = inv_2s;

            write_ext(row, col::COMPRESS_SIBLING0, round.sibling);
            row[col::COMPRESS_INDEX_BIT] = Goldilocks::new(bit);
            write_ext(row, col::STATE_IN0, pair_left);
            write_ext(row, col::STATE_IN0 + CHALLENGE_DIM, pair_right);

            write_ext(row, col::ALPHA_RO_OUT0, rho_final);
            write_ext(row, col::ALPHA_POW_IN0, alpha_final_pow);
            write_ext(row, col::ALPHA_POW_OUT0, alpha_final_pow);
            write_ext(row, col::ALPHA_RO_IN0, rho_final);

            populate_pi(row);

            for (i, v) in p2_zero_witness.iter().enumerate() {
                row[col::P2_BLOCK + i] = *v;
            }

            cur = folded;
        }
        inner_cursor += bundle.fold_rounds.len();

        row_cursor = inner_cursor;
    }

    // === IDLE padding ===
    for r in row_cursor..trace_height {
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
// Boilerplate — the existing gen_p2_witness fn follows.
// ---------------------------------------------------------------------------

pub(crate) fn gen_p2_witness(input: [Goldilocks; 8]) -> Vec<Goldilocks> {
    use p3_goldilocks::{
        GenericPoseidon2LinearLayersGoldilocks, GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
    };
    use p3_poseidon2_air::{generate_trace_rows, RoundConstants};

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
