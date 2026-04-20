//! Transfer AIR for the Uno workchain — P.2 full §4.1 envelope (1..4 spends
//! × 1..4 outputs) with real Poseidon2 compression and in-circuit balance.
//!
//! # What this file proves
//!
//! The AIR is now parameterized by `(n_spends, n_outputs)` with
//! `1 ≤ n_spends, n_outputs ≤ 4` (ConfigParam 84 cap, §4.1). Prior slices
//! (A4 MVP, I-B ivk-commitment, N-P2 real Poseidon2) landed the four
//! Poseidon2 compressions for claims 1/2/3/4 at fixed (1, 1). This slice
//! (M-P2 scale-to-envelope) replicates claims 1/2/3/4 across all spends,
//! adds claims 6/7 per output, and adds the §4.2 claim-8 in-circuit
//! balance constraint `Σ value_i = Σ value_j + fee`.
//!
//! # Claims enforced (row-0 bindings; Poseidon2 constraints on ALL rows)
//!
//! **Per spend `i` (for `i ∈ [0, n_spends)`)**:
//!
//! - **Claim 1 — Merkle path (32 levels, §2.3)**: prover opens
//!   `cm_i → anchor` across 32 Poseidon2-Goldilocks-8 compressions. At
//!   level `k`, a path-bit `b_k ∈ {0, 1}` selects ordering: `b_k = 0`
//!   → `parent = Poseidon2(current, sibling_k)`; `b_k = 1` →
//!   `parent = Poseidon2(sibling_k, current)`. `current` starts as the
//!   leaf (= `cm_i`) and is replaced by each level's `parent`. The
//!   final `current` at level 31's output must equal the tx-level
//!   anchor PI. Position low→high bit order matches the
//!   C++ `commitment-tree.{h,cpp}` append-walk convention (`pos >> k & 1`).
//!   Row-0 binding: `current_final_i == public_inputs[anchor][0]`.
//!
//! - **Claim 2 — Note opening**: `cm_i = Poseidon2("uno-cm-v1", d_i, pk_d_i,
//!   ivk_commitment_i, value_i, rcm_i)`. Row-0 binding: `cm_i == leaf_i`.
//!
//! - **Claim 3 — Ownership via ivk-commitment**: `ivk_commitment_i =
//!   Poseidon2("uno-ivk-cm-v1", ivk_i, d_i)`. Row-0 binding:
//!   `ivk_commitment_claim_i == ` claim-2 input slot.
//!
//! - **Claim 4 — Nullifier**: `nf_i = Poseidon2("uno-nf-v1", nk_i, cm_i,
//!   pos_i)`. Row-0 binding: `nf_i == public_inputs[nf_i][0]`.
//!
//! - **Claim 5 — Range `value_i < 2^64`**: trivially enforced by
//!   Goldilocks field arithmetic (§4.2 claim 5); flagged
//!   `TODO(uno-p2-u64-range-explicit)` in case the base field widens.
//!
//! **Per output `j`**:
//!
//! - **Claim 6 — Output commitment**: `cm_j = Poseidon2("uno-cm-v1", d_j,
//!   pk_d_j, ivk_commitment_j, value_j, rcm_j)` — identical Poseidon2 shape
//!   to claim 2 over sender-chosen witnesses. Row-0 binding: `cm_j ==
//!   public_inputs[cm_j][0]`.
//!
//! - **Claim 7 — Range `value_j < 2^64`**: same as claim 5.
//!
//! **Whole-tx**:
//!
//! - **Claim 8 — Balance**: `Σ_i value_i = Σ_j value_j + fee`. Single
//!   degree-1 field-element equality on row 0 over value proxies and the
//!   `fee` PI.
//!
//! # Column layout
//!
//! ```text
//! width(n_s, n_o) = GLOBAL_COLS + n_s·per_spend_cols() + n_o·per_output_cols()
//!
//! per_spend_cols()  = SPEND_PROXY_COLS
//!                   + 32·POSEIDON2_COLS_PER_INSTANCE   // 32-level Merkle (w=8)
//!                   +  1·POSEIDON2_COLS_PER_INSTANCE   // claim 3 IvkCm  (w=8)
//!                   +  1·POSEIDON2_COLS_PER_INSTANCE_16 // claim 2 Cm    (w=16)
//!                   +  1·POSEIDON2_COLS_PER_INSTANCE   // claim 4 Nf     (w=8)
//! per_output_cols() = OUTPUT_PROXY_COLS + 1·POSEIDON2_COLS_PER_INSTANCE_16
//! ```
//!
//! Trace height stays at `2^6 = 64` rows. See [`air_width`] for current
//! cols-per-shape; exact numbers are tracked by the
//! `width_grows_with_shape` test.
//!
//! # Public-input vector (§4.3 step 4, decision #5)
//!
//! Length: `8 + 8·n_s + 9·n_o` Goldilocks elements.
//! Byte length: `64 + 64·n_s + 72·n_o` bytes.
//!
//! Verifier derives `(n_spends, n_outputs)` from the wire-byte length
//! (see [`derive_shape_from_public_inputs_len`]) and picks the matching
//! AIR instance.
//!
//! # Poseidon2 (unchanged from N-P2)
//!
//! Width-8 Poseidon2-Goldilocks with audited `GOLDILOCKS_POSEIDON2_RC_8_*`
//! constants (decision #42). Full-width Poseidon2-16 for claim 2/6's
//! 15-field-element absorb is `TODO(uno-p2-wide)`.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Dup, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS, GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_16,
    GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8, Goldilocks,
    GenericPoseidon2LinearLayersGoldilocks, default_goldilocks_poseidon2_16,
    default_goldilocks_poseidon2_8,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{
    FullRound, PartialRound, Poseidon2Cols, RoundConstants, SBox, num_cols as p2_num_cols,
};
use p3_symmetric::Permutation;

use crate::Plonky3Status;

// ---------------------------------------------------------------------------
// Shape caps (§4.1 ConfigParam 84)
// ---------------------------------------------------------------------------

/// Maximum spend count (§4.1 ConfigParam 84).
pub const MAX_SPENDS: usize = 4;

/// Maximum output count (§4.1 ConfigParam 84).
pub const MAX_OUTPUTS: usize = 4;

/// Minimum spend count — at least one spend is required for a Transfer.
pub const MIN_SPENDS: usize = 1;

/// Minimum output count — at least one output is required.
pub const MIN_OUTPUTS: usize = 1;

// ---------------------------------------------------------------------------
// Poseidon2 parameters (unchanged from N-P2 slice)
// ---------------------------------------------------------------------------

/// Width of the narrow Poseidon2 permutation (Merkle / IvkCm / Nf).
pub const POSEIDON2_WIDTH: usize = 8;

/// Width of the wide Poseidon2 permutation (claim 2 / claim 6 note-
/// commitment absorb; §3.2). The 15-fe input (`domain_tag, d, pk_d,
/// ivk_commitment, value, rcm`) needs a width-16 sponge.
pub const POSEIDON2_WIDTH_16: usize = 16;

/// S-box degree (α=7 on Goldilocks).
pub const POSEIDON2_SBOX_DEGREE: u64 = 7;

/// Number of committed intermediate registers per S-box at degree 7.
pub const POSEIDON2_SBOX_REGISTERS: usize = 1;

/// Number of full rounds per half. Total `R_F = 8`. Same for widths 8 / 16.
pub const POSEIDON2_HALF_FULL_ROUNDS: usize = GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS;

/// Number of partial rounds. `R_P = 22` for width-8 Goldilocks (§16 #42).
pub const POSEIDON2_PARTIAL_ROUNDS: usize = GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8;

/// Number of partial rounds for width-16 Goldilocks. Also 22.
pub const POSEIDON2_PARTIAL_ROUNDS_16: usize = GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_16;

/// Trace columns per width-8 Poseidon2 permutation witness = 180.
pub const POSEIDON2_COLS_PER_INSTANCE: usize = p2_num_cols::<
    POSEIDON2_WIDTH,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS,
>();

/// Trace columns per width-16 Poseidon2 permutation witness = 316.
pub const POSEIDON2_COLS_PER_INSTANCE_16: usize = p2_num_cols::<
    POSEIDON2_WIDTH_16,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS_16,
>();

/// Alias: one width-8 Poseidon2 column-set specialized to our parameters.
type P2Cols<T> = Poseidon2Cols<
    T,
    POSEIDON2_WIDTH,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS,
>;

/// Alias: one width-16 Poseidon2 column-set specialized to our parameters.
type P2Cols16<T> = Poseidon2Cols<
    T,
    POSEIDON2_WIDTH_16,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS_16,
>;

// ---------------------------------------------------------------------------
// Domain separation tags
// ---------------------------------------------------------------------------

/// Domain tag for the IVK-commitment Poseidon2.
pub const TAG_IVK_CM: u64 = 0x01_75_6E_6F_69_76_6B_63;

/// Domain tag for the note-commitment Poseidon2.
pub const TAG_CM: u64 = 0x01_75_6E_6F_63_6D_76_31;

/// Domain tag for the nullifier Poseidon2.
pub const TAG_NF: u64 = 0x01_75_6E_6F_6E_66_76_31;

// ---------------------------------------------------------------------------
// Column layout
// ---------------------------------------------------------------------------

/// Global (tx-level) proxy columns: `[fee]`.
pub const GLOBAL_COLS: usize = 1;
const GCOL_FEE: usize = 0;

/// Depth of the note-commitment Merkle tree (§2.3 / §10.2 ConfigParam 84).
pub const MERKLE_DEPTH: usize = 32;

/// Width in bits of the bit-decomposition range check for `value_i` /
/// `value_j` (§4.2 claims 5 & 7). Each value is committed as 64 bit
/// columns so the AIR constrains `value < 2^64`; since
/// `p_Goldilocks = 2^64 − 2^32 + 1`, the additional 32 high-bit
/// combinations in `[2^64 − 2^32 + 1, 2^64)` are unreachable by a single
/// field element, so the bit decomposition is exact on canonical inputs.
pub const VALUE_BITS: usize = 64;

/// Per-spend proxy columns: leaf, d, value, ivk, ivk_commitment_claim,
/// pk_d, rcm, nk, pos (9 leading fields), plus 32 path-bit proxies, 32
/// sibling-hash proxies for the 32-level Merkle path (§2.3), and
/// VALUE_BITS bit columns for the explicit u64 range-check on `value_i`
/// (§4.2 claim 5).
pub const SPEND_PROXY_COLS: usize =
    9 + MERKLE_DEPTH + MERKLE_DEPTH + VALUE_BITS;

/// Per-output proxy columns: cm_claim, d, pk_d, ivk_commitment, value,
/// rcm (6 leading fields), plus VALUE_BITS bit columns for the explicit
/// u64 range-check on `value_j` (§4.2 claim 7).
pub const OUTPUT_PROXY_COLS: usize = 6 + VALUE_BITS;

/// Narrow (width-8) Poseidon2 instances per spend (Merkle×32 + IvkCm + Nf).
/// The Cm slot is width-16 and counted separately.
pub const POSEIDON2_NARROW_PER_SPEND: usize = MERKLE_DEPTH + 2;

/// Wide (width-16) Poseidon2 instances per spend (Cm only).
pub const POSEIDON2_WIDE_PER_SPEND: usize = 1;

/// Wide (width-16) Poseidon2 instances per output (Cm only).
pub const POSEIDON2_WIDE_PER_OUTPUT: usize = 1;

/// Trace height log2. 64 rows; Poseidon2 sub-AIR runs on every row.
pub const LOG_TRACE_HEIGHT: usize = 6;

/// Trace height = 64 rows.
pub const TRACE_HEIGHT: usize = 1 << LOG_TRACE_HEIGHT;

// ---- Per-spend column indices (within a spend proxy block) ----
const S_LEAF: usize = 0;
const S_D: usize = 1; // diversifier proxy (was overloaded onto S_SIBLING pre-merkle32)
const S_VALUE: usize = 2;
const S_IVK: usize = 3;
const S_IVK_COMMITMENT_CLAIM: usize = 4;
const S_PK_D: usize = 5;
const S_RCM: usize = 6;
const S_NK: usize = 7;
const S_POS: usize = 8;
// Merkle path: MERKLE_DEPTH path-bit proxies, then MERKLE_DEPTH sibling
// proxies. Path bit `k` is `(pos >> k) & 1` (low→high bit order).
const S_PATH_BIT0: usize = 9;
const S_SIBLING0: usize = S_PATH_BIT0 + MERKLE_DEPTH;
/// Base index of the 64-bit range-check columns for `value_i` (claim 5).
const S_VALUE_BIT0: usize = S_SIBLING0 + MERKLE_DEPTH;

// ---- Per-output column indices (within an output proxy block) ----
const O_CM_CLAIM: usize = 0;
const O_D: usize = 1;
const O_PK_D: usize = 2;
const O_IVK_COMMITMENT: usize = 3;
const O_VALUE: usize = 4;
const O_RCM: usize = 5;
/// Base index of the 64-bit range-check columns for `value_j` (claim 7).
const O_VALUE_BIT0: usize = 6;

// ---------------------------------------------------------------------------
// Shape-aware helpers
// ---------------------------------------------------------------------------

/// Per-spend block width: proxies + 32 width-8 Merkle levels + width-8
/// IvkCm + width-16 Cm + width-8 Nf.
#[inline]
pub const fn per_spend_cols() -> usize {
    SPEND_PROXY_COLS
        + MERKLE_DEPTH * POSEIDON2_COLS_PER_INSTANCE
        + POSEIDON2_COLS_PER_INSTANCE
        + POSEIDON2_COLS_PER_INSTANCE_16
        + POSEIDON2_COLS_PER_INSTANCE
}

/// Per-output block width: proxies + 1 width-16 Cm slot.
#[inline]
pub const fn per_output_cols() -> usize {
    OUTPUT_PROXY_COLS + POSEIDON2_COLS_PER_INSTANCE_16
}

/// Column width for a given `(n_spends, n_outputs)` shape.
#[inline]
pub const fn air_width(n_spends: usize, n_outputs: usize) -> usize {
    GLOBAL_COLS + n_spends * per_spend_cols() + n_outputs * per_output_cols()
}

/// Public-input vector length (field elements) per §4.3 step 4.
#[inline]
pub const fn air_num_public_values(n_spends: usize, n_outputs: usize) -> usize {
    8 + 8 * n_spends + 9 * n_outputs
}

/// Public-input wire byte length: `8 · num_public_values`.
#[inline]
pub const fn air_public_inputs_wire_len(n_spends: usize, n_outputs: usize) -> usize {
    8 * air_num_public_values(n_spends, n_outputs)
}

/// Derive `(n_spends, n_outputs)` from the public-input wire byte length.
///
/// Linearly searches the 16 legal shapes (§4.1 cap of 4×4). Each shape
/// has a distinct byte length because `8·n_s + 9·n_o` is unique in the
/// `[1,4]²` envelope.
pub fn derive_shape_from_public_inputs_len(
    byte_len: usize,
) -> Result<(usize, usize), Plonky3Status> {
    for n_s in MIN_SPENDS..=MAX_SPENDS {
        for n_o in MIN_OUTPUTS..=MAX_OUTPUTS {
            if air_public_inputs_wire_len(n_s, n_o) == byte_len {
                return Ok((n_s, n_o));
            }
        }
    }
    Err(Plonky3Status::PublicInputLengthMismatch)
}

// --- Column offsets -------------------------------------------------------
//
// Spend block layout (contiguous within the spend-i region):
//     [SPEND_PROXY_COLS] | [Merkle level 0..32 : 180 each]
//                        | [IvkCm : 180]
//                        | [Cm (width-16) : 316]
//                        | [Nf : 180]
//
// Output block layout:
//     [OUTPUT_PROXY_COLS] | [Cm (width-16) : 316]

#[inline]
const fn spend_proxy_offset(i: usize) -> usize {
    GLOBAL_COLS + i * per_spend_cols()
}

#[inline]
const fn spend_p2_offset(i: usize) -> usize {
    spend_proxy_offset(i) + SPEND_PROXY_COLS
}

/// Offset of the IvkCm width-8 P2 slot within spend `i`.
#[inline]
const fn spend_p2_ivkcm_offset(i: usize) -> usize {
    spend_p2_offset(i) + MERKLE_DEPTH * POSEIDON2_COLS_PER_INSTANCE
}

/// Offset of the Cm width-16 P2 slot within spend `i`.
#[inline]
const fn spend_p2_cm_offset(i: usize) -> usize {
    spend_p2_ivkcm_offset(i) + POSEIDON2_COLS_PER_INSTANCE
}

/// Offset of the Nf width-8 P2 slot within spend `i`.
#[inline]
const fn spend_p2_nf_offset(i: usize) -> usize {
    spend_p2_cm_offset(i) + POSEIDON2_COLS_PER_INSTANCE_16
}

#[inline]
const fn output_proxy_offset(n_spends: usize, j: usize) -> usize {
    GLOBAL_COLS + n_spends * per_spend_cols() + j * per_output_cols()
}

#[inline]
const fn output_p2_offset(n_spends: usize, j: usize) -> usize {
    output_proxy_offset(n_spends, j) + OUTPUT_PROXY_COLS
}

/// Enumerated narrow (width-8) spend Poseidon2 slot. The Cm slot is
/// width-16 and reached via `spend_p2_cm_group`.
#[derive(Copy, Clone)]
enum SpendP2 {
    /// Merkle path level `k`, for `k ∈ [0, MERKLE_DEPTH)`.
    MerkleLevel(usize),
    /// Claim-3 IVK-commitment Poseidon2 (width-8).
    IvkCm,
    /// Claim-4 nullifier Poseidon2 (width-8).
    Nf,
}

#[inline]
fn spend_p2_group<T>(row: &[T], i: usize, s: SpendP2) -> &P2Cols<T> {
    let off = match s {
        SpendP2::MerkleLevel(k) => {
            spend_p2_offset(i) + k * POSEIDON2_COLS_PER_INSTANCE
        }
        SpendP2::IvkCm => spend_p2_ivkcm_offset(i),
        SpendP2::Nf => spend_p2_nf_offset(i),
    };
    let group: &[T] = &row[off..off + POSEIDON2_COLS_PER_INSTANCE];
    <[T] as Borrow<P2Cols<T>>>::borrow(group)
}

#[inline]
fn spend_p2_cm_group<T>(row: &[T], i: usize) -> &P2Cols16<T> {
    let off = spend_p2_cm_offset(i);
    let group: &[T] = &row[off..off + POSEIDON2_COLS_PER_INSTANCE_16];
    <[T] as Borrow<P2Cols16<T>>>::borrow(group)
}

#[inline]
fn output_p2_group<T>(row: &[T], n_spends: usize, j: usize) -> &P2Cols16<T> {
    let off = output_p2_offset(n_spends, j);
    let group: &[T] = &row[off..off + POSEIDON2_COLS_PER_INSTANCE_16];
    <[T] as Borrow<P2Cols16<T>>>::borrow(group)
}

#[inline]
fn spend_col<T: Copy>(row: &[T], i: usize, local_idx: usize) -> T {
    row[spend_proxy_offset(i) + local_idx]
}

#[inline]
fn output_col<T: Copy>(row: &[T], n_spends: usize, j: usize, local_idx: usize) -> T {
    row[output_proxy_offset(n_spends, j) + local_idx]
}

// ---------------------------------------------------------------------------
// Public-input indices
// ---------------------------------------------------------------------------

const PI_SCHEME: usize = 0;
const PI_CHAIN: usize = 1;
const PI_EXPIRY: usize = 2;
const PI_FEE: usize = 3;
const PI_ANCHOR: usize = 4; // limb 0 of 4-limb anchor
#[inline]
const fn pi_nf(i: usize) -> usize {
    8 + i * 8
}
#[inline]
const fn pi_rk(i: usize) -> usize {
    8 + i * 8 + 4
}
#[inline]
const fn pi_cm(n_spends: usize, j: usize) -> usize {
    8 + n_spends * 8 + j * 9
}
#[inline]
const fn pi_epk(n_spends: usize, j: usize) -> usize {
    8 + n_spends * 8 + j * 9 + 4
}
#[inline]
const fn pi_filter_tag(n_spends: usize, j: usize) -> usize {
    8 + n_spends * 8 + j * 9 + 8
}

// Silence unused warnings for field-tag indices that the proxy-shape AIR
// does not constrain today (reserved for future slices).
#[allow(dead_code)]
const _UNUSED_PI: (usize, usize, usize, fn(usize) -> usize, fn(usize, usize) -> usize, fn(usize, usize) -> usize) =
    (PI_SCHEME, PI_CHAIN, PI_EXPIRY, pi_rk, pi_epk, pi_filter_tag);

// ---------------------------------------------------------------------------
// AIR definition
// ---------------------------------------------------------------------------

/// The Transfer AIR, parameterized at runtime by `(n_spends, n_outputs)`.
///
/// Prover and verifier each select a matching instance via
/// [`derive_shape_from_public_inputs_len`].
#[derive(Debug, Clone, Copy)]
pub struct MvpTransferAir {
    /// Number of spends (1..=4).
    pub n_spends: usize,
    /// Number of outputs (1..=4).
    pub n_outputs: usize,
}

impl Default for MvpTransferAir {
    /// Default shape is 1-spend / 1-output.
    fn default() -> Self {
        Self::new(1, 1)
    }
}

impl MvpTransferAir {
    /// Build the AIR for a given shape. Panics if out of §4.1 envelope.
    pub const fn new(n_spends: usize, n_outputs: usize) -> Self {
        assert!(n_spends >= MIN_SPENDS && n_spends <= MAX_SPENDS);
        assert!(n_outputs >= MIN_OUTPUTS && n_outputs <= MAX_OUTPUTS);
        Self {
            n_spends,
            n_outputs,
        }
    }

    /// AIR column width for this shape.
    #[inline]
    pub const fn width(&self) -> usize {
        air_width(self.n_spends, self.n_outputs)
    }

    /// Public-input vector length (field elements) for this shape.
    #[inline]
    pub const fn num_public_values(&self) -> usize {
        air_num_public_values(self.n_spends, self.n_outputs)
    }
}

#[inline]
fn beginning_full_round_constant_8<F: PrimeCharacteristicRing>(round: usize) -> [F; POSEIDON2_WIDTH] {
    let src = &p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL[round];
    core::array::from_fn(|i| F::from_u64(src[i].as_canonical_u64()))
}

#[inline]
fn beginning_full_round_constant_16<F: PrimeCharacteristicRing>(
    round: usize,
) -> [F; POSEIDON2_WIDTH_16] {
    let src = &p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_INITIAL[round];
    core::array::from_fn(|i| F::from_u64(src[i].as_canonical_u64()))
}

#[inline]
fn ending_full_round_constant_8<F: PrimeCharacteristicRing>(round: usize) -> [F; POSEIDON2_WIDTH] {
    let src = &p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL[round];
    core::array::from_fn(|i| F::from_u64(src[i].as_canonical_u64()))
}

#[inline]
fn ending_full_round_constant_16<F: PrimeCharacteristicRing>(
    round: usize,
) -> [F; POSEIDON2_WIDTH_16] {
    let src = &p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_FINAL[round];
    core::array::from_fn(|i| F::from_u64(src[i].as_canonical_u64()))
}

#[inline]
fn partial_round_constant_8<F: PrimeCharacteristicRing>(round: usize) -> F {
    F::from_u64(p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_INTERNAL[round].as_canonical_u64())
}

#[inline]
fn partial_round_constant_16<F: PrimeCharacteristicRing>(round: usize) -> F {
    F::from_u64(p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_INTERNAL[round].as_canonical_u64())
}

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for MvpTransferAir {
    #[inline]
    fn width(&self) -> usize {
        MvpTransferAir::width(self)
    }

    #[inline]
    fn num_public_values(&self) -> usize {
        MvpTransferAir::num_public_values(self)
    }

    #[inline]
    fn max_constraint_degree(&self) -> Option<usize> {
        None
    }
}

impl<AB> Air<AB> for MvpTransferAir
where
    AB: AirBuilder<F = Goldilocks>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_slice = main.current_slice();
        let next_slice = main.next_slice();

        // Snapshot the PI vars we'll reference later. `PublicVar: Copy`,
        // so copying out dodges the aliasing-borrow conflict with the
        // later `builder.when_*_row()` mutable borrows.
        let pis_vec: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let pi_fee = pis_vec[PI_FEE];
        let pi_anchor0 = pis_vec[PI_ANCHOR];
        let pi_nfs: Vec<AB::PublicVar> =
            (0..self.n_spends).map(|i| pis_vec[pi_nf(i)]).collect();
        let pi_cms: Vec<AB::PublicVar> = (0..self.n_outputs)
            .map(|j| pis_vec[pi_cm(self.n_spends, j)])
            .collect();

        // ---- Poseidon2 sub-AIR on every row -----------------------------
        for i in 0..self.n_spends {
            for k in 0..MERKLE_DEPTH {
                eval_poseidon2(
                    builder,
                    spend_p2_group(local_slice, i, SpendP2::MerkleLevel(k)),
                );
            }
            eval_poseidon2(builder, spend_p2_group(local_slice, i, SpendP2::IvkCm));
            eval_poseidon2_16(builder, spend_p2_cm_group(local_slice, i));
            eval_poseidon2(builder, spend_p2_group(local_slice, i, SpendP2::Nf));
        }
        for j in 0..self.n_outputs {
            eval_poseidon2_16(builder, output_p2_group(local_slice, self.n_spends, j));
        }

        // ---- First-row bindings ----------------------------------------
        {
            let mut first = builder.when_first_row();

            // Global: fee proxy bound to PI.
            first.assert_eq(local_slice[GCOL_FEE], pi_fee);

            // Per-spend claims 1/2/3/4.
            for i in 0..self.n_spends {
                let leaf = spend_col(local_slice, i, S_LEAF);
                let d = spend_col(local_slice, i, S_D);
                let value = spend_col(local_slice, i, S_VALUE);
                let ivk = spend_col(local_slice, i, S_IVK);
                let ivk_commitment_claim =
                    spend_col(local_slice, i, S_IVK_COMMITMENT_CLAIM);
                let pk_d = spend_col(local_slice, i, S_PK_D);
                let rcm = spend_col(local_slice, i, S_RCM);
                let nk = spend_col(local_slice, i, S_NK);
                let pos = spend_col(local_slice, i, S_POS);

                // Claim 1: 32-level Merkle path (§2.3). Each level k takes
                // the running `current` (starts at leaf), combines with
                // `sibling_k` under path-bit `b_k` ordering, and outputs
                // the next `current` via Poseidon2(., .).
                //
                // Conservation invariants enforced on row 0:
                //  (a) `b_k ∈ {0,1}` (bit constraint).
                //  (b) Poseidon2 inputs: inputs[0] = (1-b)·cur + b·sib,
                //                        inputs[1] = b·cur + (1-b)·sib.
                //  (c) inputs[2..8] == 0 (padding).
                //  (d) output[0] feeds `current` of level k+1.
                //  (e) After level MERKLE_DEPTH-1, current[0] == anchor.
                //  (f) `pos = Σ_k b_k · 2^k` (bit decomposition of pos).
                let mut current_expr: AB::Expr = leaf.into();
                for k in 0..MERKLE_DEPTH {
                    let b: AB::Var =
                        spend_col(local_slice, i, S_PATH_BIT0 + k);
                    let sibling: AB::Var =
                        spend_col(local_slice, i, S_SIBLING0 + k);
                    // Bit constraint: b·(1-b) == 0.
                    let b_expr: AB::Expr = b.into();
                    let one_minus_b: AB::Expr =
                        AB::Expr::from(AB::F::from_u64(1)) - b_expr.clone();
                    first.assert_zero(b_expr.clone() * one_minus_b.clone());

                    let level =
                        spend_p2_group::<AB::Var>(local_slice, i, SpendP2::MerkleLevel(k));
                    // inputs[0] = (1-b)·current + b·sibling
                    let sibling_expr: AB::Expr = sibling.into();
                    let left_sel: AB::Expr = one_minus_b.clone() * current_expr.clone()
                        + b_expr.clone() * sibling_expr.clone();
                    let right_sel: AB::Expr = b_expr.clone() * current_expr.clone()
                        + one_minus_b.clone() * sibling_expr.clone();
                    first.assert_eq(level.inputs[0].into(), left_sel);
                    first.assert_eq(level.inputs[1].into(), right_sel);
                    for pad in 2..POSEIDON2_WIDTH {
                        first.assert_zero(level.inputs[pad].into());
                    }
                    // current_expr <- output[0] of this level's Poseidon2.
                    let level_out =
                        &level.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
                    current_expr = level_out[0].into();
                }
                // Final root equals the tx-level anchor.
                first.assert_eq(current_expr, pi_anchor0.into());

                // Pos bit-decomposition: `pos == Σ_k b_k · 2^k`.
                let mut pos_recon: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                for k in 0..MERKLE_DEPTH {
                    let b: AB::Var =
                        spend_col(local_slice, i, S_PATH_BIT0 + k);
                    let weight = AB::F::from_u64(1u64 << k);
                    pos_recon = pos_recon + AB::Expr::from(weight) * b.into();
                }
                first.assert_eq(pos.into(), pos_recon);

                // Claim 5: explicit u64 range-check on `value_i` via
                // 64-bit decomposition. Bit columns V_0..V_63 live at
                // S_VALUE_BIT0. Constraints: each bit is Boolean and the
                // weighted sum reconstructs `value`.
                let mut value_recon: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                for k in 0..VALUE_BITS {
                    let b: AB::Var =
                        spend_col(local_slice, i, S_VALUE_BIT0 + k);
                    let b_expr: AB::Expr = b.into();
                    // b·(1-b) == 0.
                    let one_minus_b =
                        AB::Expr::from(AB::F::from_u64(1)) - b_expr.clone();
                    first.assert_zero(b_expr.clone() * one_minus_b);
                    // 2^k · b_k. k < 64 so `1u64 << k` fits in u64 for
                    // k ≤ 63; for k = 64 it would overflow but we stop
                    // at 63.
                    let weight = if k == 63 {
                        AB::F::from_u64(1u64 << 63)
                    } else {
                        AB::F::from_u64(1u64 << k)
                    };
                    value_recon = value_recon + AB::Expr::from(weight) * b_expr;
                }
                first.assert_eq(value.into(), value_recon);

                // Claim 3: IVK-commitment.
                let ivkcm = spend_p2_group::<AB::Var>(local_slice, i, SpendP2::IvkCm);
                first.assert_eq(
                    ivkcm.inputs[0].into(),
                    AB::Expr::from(AB::F::from_u64(TAG_IVK_CM)),
                );
                first.assert_eq(ivkcm.inputs[1], ivk);
                first.assert_eq(ivkcm.inputs[2], d); // d_i proxy
                for k in 3..POSEIDON2_WIDTH {
                    first.assert_zero(ivkcm.inputs[k].into());
                }
                let ivkcm_out =
                    &ivkcm.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
                first.assert_eq(ivkcm_out[0], ivk_commitment_claim);

                // Claim 2: Note opening — wide-sponge Poseidon2-16 over the
                // 15-fe input `(TAG_CM, d, pk_d, ivk_commitment, value, rcm)`
                // per §3.2. Proxy-AIR keeps each field as a single fe slot;
                // unused slots 6..16 are pinned to zero.
                let cm = spend_p2_cm_group::<AB::Var>(local_slice, i);
                first.assert_eq(
                    cm.inputs[0].into(),
                    AB::Expr::from(AB::F::from_u64(TAG_CM)),
                );
                first.assert_eq(cm.inputs[1], d);
                first.assert_eq(cm.inputs[2], pk_d);
                first.assert_eq(cm.inputs[3], ivk_commitment_claim);
                first.assert_eq(cm.inputs[4], value);
                first.assert_eq(cm.inputs[5], rcm);
                for k in 6..POSEIDON2_WIDTH_16 {
                    first.assert_zero(cm.inputs[k].into());
                }
                let cm_out = &cm.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
                first.assert_eq(cm_out[0], leaf); // cm_i == leaf_i

                // Claim 4: Nullifier.
                let nf = spend_p2_group::<AB::Var>(local_slice, i, SpendP2::Nf);
                first.assert_eq(
                    nf.inputs[0].into(),
                    AB::Expr::from(AB::F::from_u64(TAG_NF)),
                );
                first.assert_eq(nf.inputs[1], nk);
                first.assert_eq(nf.inputs[2], leaf); // cm_i
                first.assert_eq(nf.inputs[3], pos);
                for k in 4..POSEIDON2_WIDTH {
                    first.assert_zero(nf.inputs[k].into());
                }
                let nf_out = &nf.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
                // Bind nf_i to limb 0 of the per-spend nullifier PI.
                // TODO(uno-p2-nf-fullwidth): bind all 4 limbs once the
                // wide-Poseidon2 slice lands.
                first.assert_eq(nf_out[0], pi_nfs[i]);
            }

            // Per-output claims 6/7.
            for j in 0..self.n_outputs {
                let cm_claim = output_col(local_slice, self.n_spends, j, O_CM_CLAIM);
                let d_out = output_col(local_slice, self.n_spends, j, O_D);
                let pk_d_out = output_col(local_slice, self.n_spends, j, O_PK_D);
                let ivk_cm_out =
                    output_col(local_slice, self.n_spends, j, O_IVK_COMMITMENT);
                let value_out = output_col(local_slice, self.n_spends, j, O_VALUE);
                let rcm_out = output_col(local_slice, self.n_spends, j, O_RCM);

                // Claim 6: wide-sponge Poseidon2-16, same shape as claim 2.
                let cm_p2 = output_p2_group::<AB::Var>(local_slice, self.n_spends, j);
                first.assert_eq(
                    cm_p2.inputs[0].into(),
                    AB::Expr::from(AB::F::from_u64(TAG_CM)),
                );
                first.assert_eq(cm_p2.inputs[1], d_out);
                first.assert_eq(cm_p2.inputs[2], pk_d_out);
                first.assert_eq(cm_p2.inputs[3], ivk_cm_out);
                first.assert_eq(cm_p2.inputs[4], value_out);
                first.assert_eq(cm_p2.inputs[5], rcm_out);
                for k in 6..POSEIDON2_WIDTH_16 {
                    first.assert_zero(cm_p2.inputs[k].into());
                }
                let cm_p2_out =
                    &cm_p2.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
                first.assert_eq(cm_p2_out[0], cm_claim);
                // Bind cm_j to limb 0 of the output-commitment PI.
                first.assert_eq(cm_claim, pi_cms[j]);

                // Claim 7: explicit u64 range-check on `value_j`.
                let mut value_recon: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                for k in 0..VALUE_BITS {
                    let b: AB::Var = output_col(
                        local_slice,
                        self.n_spends,
                        j,
                        O_VALUE_BIT0 + k,
                    );
                    let b_expr: AB::Expr = b.into();
                    let one_minus_b =
                        AB::Expr::from(AB::F::from_u64(1)) - b_expr.clone();
                    first.assert_zero(b_expr.clone() * one_minus_b);
                    let weight = if k == 63 {
                        AB::F::from_u64(1u64 << 63)
                    } else {
                        AB::F::from_u64(1u64 << k)
                    };
                    value_recon = value_recon + AB::Expr::from(weight) * b_expr;
                }
                first.assert_eq(value_out.into(), value_recon);
            }

            // Claim 8: balance. `Σ value_i - Σ value_j - fee == 0`.
            let mut sum: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
            for i in 0..self.n_spends {
                sum = sum + spend_col::<AB::Var>(local_slice, i, S_VALUE).into();
            }
            for j in 0..self.n_outputs {
                sum = sum
                    - output_col::<AB::Var>(local_slice, self.n_spends, j, O_VALUE)
                        .into();
            }
            sum = sum - local_slice[GCOL_FEE].into();
            first.assert_zero(sum);
        }

        // ---- Per-row replica checks: proxies constant across rows ------
        {
            let mut t = builder.when_transition();
            t.assert_eq(next_slice[GCOL_FEE], local_slice[GCOL_FEE]);
            for i in 0..self.n_spends {
                for k in 0..SPEND_PROXY_COLS {
                    t.assert_eq(
                        next_slice[spend_proxy_offset(i) + k],
                        local_slice[spend_proxy_offset(i) + k],
                    );
                }
            }
            for j in 0..self.n_outputs {
                for k in 0..OUTPUT_PROXY_COLS {
                    t.assert_eq(
                        next_slice[output_proxy_offset(self.n_spends, j) + k],
                        local_slice[output_proxy_offset(self.n_spends, j) + k],
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Poseidon2 constraint evaluation (reimplemented here because the upstream
// `p3_poseidon2_air::eval` is pub(crate); logic mirrors upstream byte-for-byte).
// ---------------------------------------------------------------------------

fn eval_poseidon2<AB>(builder: &mut AB, local: &P2Cols<AB::Var>)
where
    AB: AirBuilder,
{
    let mut state: [AB::Expr; POSEIDON2_WIDTH] = local.inputs.map(|x| x.into());

    <GenericPoseidon2LinearLayersGoldilocks as GenericPoseidon2LinearLayers<
        POSEIDON2_WIDTH,
    >>::external_linear_layer(&mut state);

    for round in 0..POSEIDON2_HALF_FULL_ROUNDS {
        eval_full_round::<AB, POSEIDON2_WIDTH>(
            &mut state,
            &local.beginning_full_rounds[round],
            &beginning_full_round_constant_8::<AB::F>(round),
            builder,
        );
    }

    for round in 0..POSEIDON2_PARTIAL_ROUNDS {
        eval_partial_round::<AB, POSEIDON2_WIDTH>(
            &mut state,
            &local.partial_rounds[round],
            &partial_round_constant_8::<AB::F>(round),
            builder,
        );
    }

    for round in 0..POSEIDON2_HALF_FULL_ROUNDS {
        eval_full_round::<AB, POSEIDON2_WIDTH>(
            &mut state,
            &local.ending_full_rounds[round],
            &ending_full_round_constant_8::<AB::F>(round),
            builder,
        );
    }
}

fn eval_poseidon2_16<AB>(builder: &mut AB, local: &P2Cols16<AB::Var>)
where
    AB: AirBuilder,
{
    let mut state: [AB::Expr; POSEIDON2_WIDTH_16] = local.inputs.map(|x| x.into());

    <GenericPoseidon2LinearLayersGoldilocks as GenericPoseidon2LinearLayers<
        POSEIDON2_WIDTH_16,
    >>::external_linear_layer(&mut state);

    for round in 0..POSEIDON2_HALF_FULL_ROUNDS {
        eval_full_round_16::<AB>(
            &mut state,
            &local.beginning_full_rounds[round],
            &beginning_full_round_constant_16::<AB::F>(round),
            builder,
        );
    }

    for round in 0..POSEIDON2_PARTIAL_ROUNDS_16 {
        eval_partial_round_16::<AB>(
            &mut state,
            &local.partial_rounds[round],
            &partial_round_constant_16::<AB::F>(round),
            builder,
        );
    }

    for round in 0..POSEIDON2_HALF_FULL_ROUNDS {
        eval_full_round_16::<AB>(
            &mut state,
            &local.ending_full_rounds[round],
            &ending_full_round_constant_16::<AB::F>(round),
            builder,
        );
    }
}

#[inline]
fn eval_full_round<AB: AirBuilder, const WIDTH: usize>(
    state: &mut [AB::Expr; WIDTH],
    full_round: &FullRound<
        AB::Var,
        WIDTH,
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
    >,
    round_constants: &[AB::F; WIDTH],
    builder: &mut AB,
) where
    GenericPoseidon2LinearLayersGoldilocks: GenericPoseidon2LinearLayers<WIDTH>,
{
    for (i, (s, r)) in state.iter_mut().zip(round_constants.iter()).enumerate() {
        *s += r.dup();
        eval_sbox(&full_round.sbox[i], s, builder);
    }
    <GenericPoseidon2LinearLayersGoldilocks as GenericPoseidon2LinearLayers<
        WIDTH,
    >>::external_linear_layer(state);
    for (state_i, post_i) in state.iter_mut().zip(full_round.post) {
        builder.assert_eq(state_i.clone(), post_i);
        *state_i = post_i.into();
    }
}

#[inline]
fn eval_partial_round<AB: AirBuilder, const WIDTH: usize>(
    state: &mut [AB::Expr; WIDTH],
    partial_round: &PartialRound<
        AB::Var,
        WIDTH,
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
    >,
    round_constant: &AB::F,
    builder: &mut AB,
) where
    GenericPoseidon2LinearLayersGoldilocks: GenericPoseidon2LinearLayers<WIDTH>,
{
    state[0] += round_constant.dup();
    eval_sbox(&partial_round.sbox, &mut state[0], builder);
    builder.assert_eq(state[0].dup(), partial_round.post_sbox);
    state[0] = partial_round.post_sbox.into();
    <GenericPoseidon2LinearLayersGoldilocks as GenericPoseidon2LinearLayers<
        WIDTH,
    >>::internal_linear_layer(state);
}

#[inline]
fn eval_full_round_16<AB: AirBuilder>(
    state: &mut [AB::Expr; POSEIDON2_WIDTH_16],
    full_round: &FullRound<
        AB::Var,
        POSEIDON2_WIDTH_16,
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
    >,
    round_constants: &[AB::F; POSEIDON2_WIDTH_16],
    builder: &mut AB,
) {
    eval_full_round::<AB, POSEIDON2_WIDTH_16>(state, full_round, round_constants, builder)
}

#[inline]
fn eval_partial_round_16<AB: AirBuilder>(
    state: &mut [AB::Expr; POSEIDON2_WIDTH_16],
    partial_round: &PartialRound<
        AB::Var,
        POSEIDON2_WIDTH_16,
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
    >,
    round_constant: &AB::F,
    builder: &mut AB,
) {
    eval_partial_round::<AB, POSEIDON2_WIDTH_16>(state, partial_round, round_constant, builder)
}

#[inline]
fn eval_sbox<AB: AirBuilder>(
    sbox: &SBox<AB::Var, POSEIDON2_SBOX_DEGREE, POSEIDON2_SBOX_REGISTERS>,
    x: &mut AB::Expr,
    builder: &mut AB,
) {
    let committed_x3: AB::Expr = sbox.0[0].into();
    builder.assert_eq(committed_x3.dup(), x.cube());
    *x = committed_x3.square() * x.dup();
}

// ---------------------------------------------------------------------------
// Witness + trace generation
// ---------------------------------------------------------------------------

/// Single-spend witness.
#[derive(Debug, Clone)]
pub struct SpendWitness {
    /// Single-fe proxy for the spent note commitment `cm` (= Merkle leaf).
    pub leaf: u64,
    /// Diversifier `d` proxy (8 B LE).
    pub d: [u8; 8],
    /// Value being spent. Must be `< p_Goldilocks`.
    pub value: u64,
    /// Private-witness `ivk` proxy.
    pub ivk: u64,
    /// Proxy for `pk_d.bytes`.
    pub pk_d: u64,
    /// Proxy for the note randomness `rcm`.
    pub rcm: u64,
    /// Proxy for the nullifier key `nk`.
    pub nk: u64,
    /// Leaf position within the depth-32 commitment tree. Low bit is the
    /// level-0 path bit (§2.3, matching `commitment-tree.{h,cpp}`). Must
    /// satisfy `pos < 2^MERKLE_DEPTH` (upper bits in `pos` are discarded
    /// when the witness is encoded because only 32 path bits are stored).
    pub pos: u64,
    /// 32-level Merkle path: each entry is the sibling hash proxy
    /// (single Goldilocks fe) at level `k`. Level 0 is the first layer
    /// above the leaf.
    pub merkle_path: [u64; MERKLE_DEPTH],
}

/// Single-output witness.
#[derive(Debug, Clone)]
pub struct OutputWitness {
    /// Diversifier `d_j` proxy.
    pub d: u64,
    /// `pk_d_j` proxy.
    pub pk_d: u64,
    /// Recipient `ivk_commitment_j` proxy.
    pub ivk_commitment: u64,
    /// Output value (u64, Goldilocks-fits).
    pub value: u64,
    /// `rcm_j` proxy.
    pub rcm: u64,
}

/// Full Transfer witness for 1..4 spends × 1..4 outputs + fee.
#[derive(Debug, Clone)]
pub struct MvpWitness {
    /// Transaction fee, public input.
    pub fee: u64,
    /// Spend descriptions (len ∈ [1, 4]).
    pub spends: Vec<SpendWitness>,
    /// Output descriptions (len ∈ [1, 4]).
    pub outputs: Vec<OutputWitness>,
    /// Shared anchor proxy (limb 0 of the 256-bit anchor). Derived by the
    /// constructor from the first spend's Merkle step so honest witnesses
    /// are self-consistent.
    pub anchor_proxy: u64,
}

impl MvpWitness {
    /// `(n_spends, n_outputs)` for this witness.
    #[inline]
    pub fn shape(&self) -> (usize, usize) {
        (self.spends.len(), self.outputs.len())
    }

    /// Build a deterministic valid witness of the given shape.
    ///
    /// All spends share `(leaf, sibling, value, ivk, pk_d, rcm)` so the
    /// per-spend Merkle step produces the same anchor by construction
    /// (single-step Merkle can only produce anchor-equivalence if all
    /// `(leaf, sibling)` pairs are equal). Only `(nk, pos)` differ
    /// per-spend to produce distinct nullifiers. This is a test-fixture
    /// construction — real wallets produce distinct leaves per spend
    /// over a 32-level Merkle chain (`TODO(uno-p2-merkle32)`).
    ///
    /// Balance construction: `value_i = v` constant per spend; total in
    /// is `n_s · v`; `fee` is chosen small; output values split
    /// `n_s·v - fee` evenly across `n_o` outputs (last output absorbs
    /// the remainder).
    pub fn deterministic_valid(n_spends: usize, n_outputs: usize, seed: u64) -> Self {
        assert!(n_spends >= MIN_SPENDS && n_spends <= MAX_SPENDS);
        assert!(n_outputs >= MIN_OUTPUTS && n_outputs <= MAX_OUTPUTS);

        let perm = default_goldilocks_poseidon2_8();
        let perm16 = default_goldilocks_poseidon2_16();

        // Derive shared spend witness fields.
        let d_word = seed
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(0x1234_0000_0000_0000)
            & ((1u64 << 62) - 1);
        let shared_ivk = seed.wrapping_mul(0xc2b2_ae3d_27d4_eb4f) ^ 0x1efb_e1ed;
        let shared_pk_d = seed.wrapping_mul(0x1656_67b1_9e37_79f9) ^ 0xdeca_d0de;
        let shared_rcm = seed.wrapping_mul(0xd6e8_feb8_6659_fd93) ^ 0xfade_cafe;

        // Shared per-spend value (small u32-ish so n_s·v never overflows u64).
        let v_per_spend: u64 = 0x0001_0000 + (seed & 0xFF_FFFF);
        let fee: u64 = 0x100 + (seed & 0xFFF);

        // Derived shared leaf via claim-2 Poseidon2-16 (wide sponge).
        let ivkcm = poseidon2_ivk_commitment(&perm, shared_ivk, d_word);
        let shared_leaf = poseidon2_cm(
            &perm16,
            d_word,
            shared_pk_d,
            ivkcm.as_canonical_u64(),
            v_per_spend,
            shared_rcm,
        );

        // Shared 32-level Merkle path: siblings fixed per seed; position
        // fixed per seed. All spends share `(leaf, path, pos)` so that the
        // resulting anchor is the same by construction (the AIR only
        // enforces anchor equality, not distinct leaves — test-fixture
        // convention, see struct-doc).
        let shared_pos: u64 = (seed & ((1u64 << MERKLE_DEPTH) - 1)) as u64;
        let mut shared_path = [0u64; MERKLE_DEPTH];
        for k in 0..MERKLE_DEPTH {
            // Distinct per-level siblings, bounded to 62 bits to stay
            // canonical after Goldilocks reduction.
            let mix = seed
                .wrapping_mul(0xBF58_476D_1CE4_E5B9)
                .wrapping_add((k as u64).wrapping_mul(0x94D0_49BB_1331_11EB));
            shared_path[k] = mix & ((1u64 << 62) - 1);
        }
        let shared_anchor = poseidon2_merkle_path_root(
            &perm,
            shared_leaf,
            shared_pos,
            &shared_path,
        )
        .as_canonical_u64();

        // Build spends; all share the path so the anchor is identical per
        // spend. Only `nk` differs for distinct nullifiers.
        let mut spends = Vec::with_capacity(n_spends);
        for i in 0..n_spends {
            let s = seed
                .wrapping_mul(0x517c_c1b7_2722_0a95)
                .wrapping_add((i as u64) * 0xC0FF_EE00);
            let nk = s.wrapping_mul(0xcbf2_9ce4_8422_2325) ^ 0xba11_00ba;
            spends.push(SpendWitness {
                leaf: shared_leaf,
                d: d_word.to_le_bytes(),
                value: v_per_spend,
                ivk: shared_ivk,
                pk_d: shared_pk_d,
                rcm: shared_rcm,
                nk,
                pos: shared_pos,
                merkle_path: shared_path,
            });
        }

        // Balance: Σ spends = n_s · v_per_spend; distribute across outputs.
        let total_in: u128 = (n_spends as u128) * (v_per_spend as u128);
        assert!(total_in > fee as u128, "test seed produced unpayable fee");
        let total_out: u128 = total_in - (fee as u128);
        let v_per_out_base: u64 = (total_out / (n_outputs as u128)) as u64;
        let remainder: u64 = (total_out - (v_per_out_base as u128) * (n_outputs as u128)) as u64;

        let mut outputs = Vec::with_capacity(n_outputs);
        for j in 0..n_outputs {
            let s = seed
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add((j as u64) * 0xDEAD_BEEF);
            let d = s.wrapping_mul(0xc2b2_ae3d_27d4_eb4f) ^ 0x1efb_e1ed;
            let pk_d = s.wrapping_mul(0x1656_67b1_9e37_79f9) ^ 0xdeca_d0de;
            let rcm = s.wrapping_mul(0xd6e8_feb8_6659_fd93) ^ 0xfade_cafe;
            let ivk_commitment = s.wrapping_mul(0xcbf2_9ce4_8422_2325) ^ 0xba11_00ba;
            let value = if j + 1 == n_outputs {
                v_per_out_base + remainder
            } else {
                v_per_out_base
            };
            outputs.push(OutputWitness {
                d,
                pk_d,
                ivk_commitment,
                value,
                rcm,
            });
        }

        Self {
            fee,
            spends,
            outputs,
            anchor_proxy: shared_anchor,
        }
    }

    /// Wire-encode for FFI.
    ///
    /// Layout: `u8 n_s || u8 n_o || u64 fee || (u64 leaf || [8 B] d
    /// || u64 value || u64 ivk || u64 pk_d || u64 rcm || u64 nk || u64 pos
    /// || u64 path[0..32]) × n_s || (u64 d || u64 pk_d || u64 ivk_commitment
    /// || u64 value || u64 rcm) × n_o || u64 anchor_proxy`.
    ///
    /// Per-spend bytes: `64 + 8·MERKLE_DEPTH = 320 bytes` (8 leading fields
    /// at 8 B each, then 32 path siblings at 8 B each).
    ///
    /// Byte length: `18 + (64 + 8·MERKLE_DEPTH)·n_s + 40·n_o`.
    pub fn encode(&self) -> Vec<u8> {
        let per_spend = 64 + 8 * MERKLE_DEPTH;
        let mut out = Vec::with_capacity(18 + per_spend * self.spends.len() + 40 * self.outputs.len());
        out.push(self.spends.len() as u8);
        out.push(self.outputs.len() as u8);
        out.extend_from_slice(&self.fee.to_le_bytes());
        for s in &self.spends {
            out.extend_from_slice(&s.leaf.to_le_bytes());
            out.extend_from_slice(&s.d);
            out.extend_from_slice(&s.value.to_le_bytes());
            out.extend_from_slice(&s.ivk.to_le_bytes());
            out.extend_from_slice(&s.pk_d.to_le_bytes());
            out.extend_from_slice(&s.rcm.to_le_bytes());
            out.extend_from_slice(&s.nk.to_le_bytes());
            out.extend_from_slice(&s.pos.to_le_bytes());
            for sib in &s.merkle_path {
                out.extend_from_slice(&sib.to_le_bytes());
            }
        }
        for o in &self.outputs {
            out.extend_from_slice(&o.d.to_le_bytes());
            out.extend_from_slice(&o.pk_d.to_le_bytes());
            out.extend_from_slice(&o.ivk_commitment.to_le_bytes());
            out.extend_from_slice(&o.value.to_le_bytes());
            out.extend_from_slice(&o.rcm.to_le_bytes());
        }
        out.extend_from_slice(&self.anchor_proxy.to_le_bytes());
        out
    }

    /// Decode a witness from the wire format.
    pub fn decode(bytes: &[u8]) -> Result<Self, Plonky3Status> {
        if bytes.len() < 18 {
            return Err(Plonky3Status::WitnessInvalid);
        }
        let n_s = bytes[0] as usize;
        let n_o = bytes[1] as usize;
        if n_s < MIN_SPENDS || n_s > MAX_SPENDS || n_o < MIN_OUTPUTS || n_o > MAX_OUTPUTS {
            return Err(Plonky3Status::WitnessInvalid);
        }
        let per_spend = 64 + 8 * MERKLE_DEPTH;
        let want = 18 + per_spend * n_s + 40 * n_o;
        if bytes.len() != want {
            return Err(Plonky3Status::WitnessInvalid);
        }
        let fee = u64::from_le_bytes(bytes[2..10].try_into().unwrap());
        if fee >= GOLDILOCKS_P {
            return Err(Plonky3Status::WitnessInvalid);
        }

        let mut off = 10;
        let mut spends = Vec::with_capacity(n_s);
        for _ in 0..n_s {
            let leaf = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            let mut d = [0u8; 8];
            d.copy_from_slice(&bytes[off..off + 8]);
            off += 8;
            let value = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            if value >= GOLDILOCKS_P {
                return Err(Plonky3Status::WitnessInvalid);
            }
            let ivk = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            let pk_d = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            let rcm = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            let nk = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            let pos = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            // `pos` must fit in MERKLE_DEPTH bits for the AIR's bit
            // decomposition to hold.
            if pos >= (1u64 << MERKLE_DEPTH) {
                return Err(Plonky3Status::WitnessInvalid);
            }
            let mut merkle_path = [0u64; MERKLE_DEPTH];
            for sib in merkle_path.iter_mut() {
                *sib = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
                off += 8;
                if *sib >= GOLDILOCKS_P {
                    return Err(Plonky3Status::WitnessInvalid);
                }
            }
            spends.push(SpendWitness {
                leaf,
                d,
                value,
                ivk,
                pk_d,
                rcm,
                nk,
                pos,
                merkle_path,
            });
        }
        let mut outputs = Vec::with_capacity(n_o);
        for _ in 0..n_o {
            let d = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            let pk_d = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            let ivk_commitment =
                u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            let value = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            if value >= GOLDILOCKS_P {
                return Err(Plonky3Status::WitnessInvalid);
            }
            let rcm = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            outputs.push(OutputWitness {
                d,
                pk_d,
                ivk_commitment,
                value,
                rcm,
            });
        }
        let anchor_proxy = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        debug_assert_eq!(off, bytes.len());

        Ok(Self {
            fee,
            spends,
            outputs,
            anchor_proxy,
        })
    }

    /// Balance pre-check. Runs in u128 to dodge u64 overflow on sums of
    /// up to 4 u64 summands.
    pub fn balance_holds(&self) -> bool {
        let sin: u128 = self.spends.iter().map(|s| s.value as u128).sum();
        let sout: u128 = self.outputs.iter().map(|o| o.value as u128).sum();
        sin == sout + (self.fee as u128)
    }

    /// Derive public inputs per §4.3 step 4.
    ///
    /// See the struct doc for field layout. The 3 higher limbs of
    /// anchor / nf / rk / cm / epk, and `epk` / `filter_tag` fields are
    /// emitted as zero in this proxy-shape derivation — real wallet PIs
    /// come from `uno_workchain::build_plonky3_public_inputs` and carry
    /// non-zero limbs. The AIR does not constrain the zero limbs.
    pub fn public_inputs(&self) -> Vec<Goldilocks> {
        let n_s = self.spends.len();
        let n_o = self.outputs.len();
        let mut out = Vec::with_capacity(air_num_public_values(n_s, n_o));

        out.push(Goldilocks::from_u64(0x01));
        out.push(Goldilocks::from_u64(CHAIN_ID_TEST as u64));
        out.push(Goldilocks::from_u64(EXPIRY_BLOCK_TEST));
        out.push(Goldilocks::from_u64(self.fee));

        // anchor: limb 0 = anchor_proxy; limbs 1..3 = 0.
        out.push(Goldilocks::from_u64(reduce_to_goldilocks(self.anchor_proxy)));
        for _ in 1..4 {
            out.push(Goldilocks::ZERO);
        }

        let perm = default_goldilocks_poseidon2_8();
        let perm16 = default_goldilocks_poseidon2_16();

        for s in &self.spends {
            // nf_i = Poseidon2(TAG_NF, nk, leaf(=cm), pos).
            let nf = poseidon2_nf(&perm, s.nk, s.leaf, s.pos);
            out.push(nf);
            for _ in 1..4 {
                out.push(Goldilocks::ZERO);
            }
            // rk_i: 4 × 0.
            for _ in 0..4 {
                out.push(Goldilocks::ZERO);
            }
        }

        for o in &self.outputs {
            let cm =
                poseidon2_cm_fe(&perm16, o.d, o.pk_d, o.ivk_commitment, o.value, o.rcm);
            out.push(cm);
            for _ in 1..4 {
                out.push(Goldilocks::ZERO);
            }
            // epk_j: 4 × 0.
            for _ in 0..4 {
                out.push(Goldilocks::ZERO);
            }
            // filter_tag_j: 0.
            out.push(Goldilocks::ZERO);
        }

        debug_assert_eq!(out.len(), air_num_public_values(n_s, n_o));
        out
    }

    /// Serialize `public_inputs()` to the wire-byte format (8 B LE per FE).
    pub fn public_inputs_bytes(&self) -> Vec<u8> {
        let pis = self.public_inputs();
        let mut out = Vec::with_capacity(pis.len() * 8);
        for fe in pis {
            out.extend_from_slice(&fe.as_canonical_u64().to_le_bytes());
        }
        out
    }

    /// Generate the full trace matrix.
    pub fn generate_trace(&self) -> RowMajorMatrix<Goldilocks> {
        let n_s = self.spends.len();
        let n_o = self.outputs.len();
        let width = air_width(n_s, n_o);

        let perm = default_goldilocks_poseidon2_8();
        let perm16 = default_goldilocks_poseidon2_16();
        let constants_8 = RoundConstants::new(
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
        );
        let constants_16 = RoundConstants::new(
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_INITIAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_INTERNAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_FINAL,
        );
        let gen_p2_row = |input: [Goldilocks; POSEIDON2_WIDTH]| -> Vec<Goldilocks> {
            use p3_poseidon2_air::generate_trace_rows;
            let mat = generate_trace_rows::<
                Goldilocks,
                GenericPoseidon2LinearLayersGoldilocks,
                POSEIDON2_WIDTH,
                POSEIDON2_SBOX_DEGREE,
                POSEIDON2_SBOX_REGISTERS,
                POSEIDON2_HALF_FULL_ROUNDS,
                POSEIDON2_PARTIAL_ROUNDS,
            >(vec![input], &constants_8, 0);
            debug_assert_eq!(mat.values.len(), POSEIDON2_COLS_PER_INSTANCE);
            mat.values
        };
        let gen_p2_row_16 = |input: [Goldilocks; POSEIDON2_WIDTH_16]| -> Vec<Goldilocks> {
            use p3_poseidon2_air::generate_trace_rows;
            let mat = generate_trace_rows::<
                Goldilocks,
                GenericPoseidon2LinearLayersGoldilocks,
                POSEIDON2_WIDTH_16,
                POSEIDON2_SBOX_DEGREE,
                POSEIDON2_SBOX_REGISTERS,
                POSEIDON2_HALF_FULL_ROUNDS,
                POSEIDON2_PARTIAL_ROUNDS_16,
            >(vec![input], &constants_16, 0);
            debug_assert_eq!(mat.values.len(), POSEIDON2_COLS_PER_INSTANCE_16);
            mat.values
        };
        let padding_p2 = gen_p2_row([Goldilocks::ZERO; POSEIDON2_WIDTH]);
        let padding_p2_16 = gen_p2_row_16([Goldilocks::ZERO; POSEIDON2_WIDTH_16]);

        // Row-0 Poseidon2 trace cells, per spend + output.
        // Per spend we generate MERKLE_DEPTH Merkle-level rows, then
        // IvkCm, Cm, Nf — matching the column layout from `SpendP2::slot`.
        let mut row0_spend_merkle: Vec<Vec<Vec<Goldilocks>>> = Vec::with_capacity(n_s);
        let mut row0_spend_ivkcm = Vec::with_capacity(n_s);
        let mut row0_spend_cm = Vec::with_capacity(n_s);
        let mut row0_spend_nf = Vec::with_capacity(n_s);
        for s in &self.spends {
            let d_word = u64::from_le_bytes(s.d);
            let d_f = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
            let leaf_f = Goldilocks::from_u64(reduce_to_goldilocks(s.leaf));
            let pk_d_f = Goldilocks::from_u64(reduce_to_goldilocks(s.pk_d));
            let rcm_f = Goldilocks::from_u64(reduce_to_goldilocks(s.rcm));
            let ivk_f = Goldilocks::from_u64(reduce_to_goldilocks(s.ivk));
            let nk_f = Goldilocks::from_u64(reduce_to_goldilocks(s.nk));
            let pos_f = Goldilocks::from_u64(reduce_to_goldilocks(s.pos));
            let value_f = Goldilocks::from_u64(reduce_to_goldilocks(s.value));
            let ivkcm_fe = poseidon2_ivk_commitment(&perm, s.ivk, d_word);

            // Merkle path rows: at each level, run the permutation with
            // inputs ordered by the path bit.
            let mut levels_rows = Vec::with_capacity(MERKLE_DEPTH);
            let mut current = reduce_to_goldilocks(s.leaf);
            for k in 0..MERKLE_DEPTH {
                let bit = (s.pos >> k) & 1;
                let sib = reduce_to_goldilocks(s.merkle_path[k]);
                let (left, right) = if bit == 0 { (current, sib) } else { (sib, current) };
                let mut input = [Goldilocks::ZERO; POSEIDON2_WIDTH];
                input[0] = Goldilocks::from_u64(left);
                input[1] = Goldilocks::from_u64(right);
                // Compute output for next-level current.
                let mut state = input;
                perm.permute_mut(&mut state);
                let row = gen_p2_row(input);
                levels_rows.push(row);
                current = state[0].as_canonical_u64();
            }
            row0_spend_merkle.push(levels_rows);

            let mut ivkcm_in = [Goldilocks::ZERO; POSEIDON2_WIDTH];
            ivkcm_in[0] = Goldilocks::from_u64(TAG_IVK_CM);
            ivkcm_in[1] = ivk_f;
            ivkcm_in[2] = d_f;
            row0_spend_ivkcm.push(gen_p2_row(ivkcm_in));

            let mut cm_in = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
            cm_in[0] = Goldilocks::from_u64(TAG_CM);
            cm_in[1] = d_f;
            cm_in[2] = pk_d_f;
            cm_in[3] = ivkcm_fe;
            cm_in[4] = value_f;
            cm_in[5] = rcm_f;
            row0_spend_cm.push(gen_p2_row_16(cm_in));

            let mut nf_in = [Goldilocks::ZERO; POSEIDON2_WIDTH];
            nf_in[0] = Goldilocks::from_u64(TAG_NF);
            nf_in[1] = nk_f;
            nf_in[2] = leaf_f;
            nf_in[3] = pos_f;
            row0_spend_nf.push(gen_p2_row(nf_in));
        }

        let mut row0_out_cm = Vec::with_capacity(n_o);
        for o in &self.outputs {
            let d_f = Goldilocks::from_u64(reduce_to_goldilocks(o.d));
            let pk_d_f = Goldilocks::from_u64(reduce_to_goldilocks(o.pk_d));
            let ivk_cm_f = Goldilocks::from_u64(reduce_to_goldilocks(o.ivk_commitment));
            let rcm_f = Goldilocks::from_u64(reduce_to_goldilocks(o.rcm));
            let value_f = Goldilocks::from_u64(reduce_to_goldilocks(o.value));
            let mut cm_in = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
            cm_in[0] = Goldilocks::from_u64(TAG_CM);
            cm_in[1] = d_f;
            cm_in[2] = pk_d_f;
            cm_in[3] = ivk_cm_f;
            cm_in[4] = value_f;
            cm_in[5] = rcm_f;
            row0_out_cm.push(gen_p2_row_16(cm_in));
        }

        // Per-spend proxy vector: [leaf, d, value, ivk, ivk_cm_claim, pk_d,
        // rcm, nk, pos, path_bits[0..32], siblings[0..32],
        // value_bits[0..64]].
        let spend_proxies: Vec<Vec<Goldilocks>> = self
            .spends
            .iter()
            .map(|s| {
                let d_word = u64::from_le_bytes(s.d);
                let d_f = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
                let ivkcm_fe = poseidon2_ivk_commitment(&perm, s.ivk, d_word);
                let mut v = Vec::with_capacity(SPEND_PROXY_COLS);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.leaf)));
                v.push(d_f);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.value)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.ivk)));
                v.push(ivkcm_fe);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.pk_d)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.rcm)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.nk)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.pos)));
                for k in 0..MERKLE_DEPTH {
                    let bit = (s.pos >> k) & 1;
                    v.push(Goldilocks::from_u64(bit));
                }
                for k in 0..MERKLE_DEPTH {
                    v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.merkle_path[k])));
                }
                // Bit-decompose value into VALUE_BITS = 64 bits.
                let value_canon = reduce_to_goldilocks(s.value);
                for k in 0..VALUE_BITS {
                    let bit = (value_canon >> k) & 1;
                    v.push(Goldilocks::from_u64(bit));
                }
                debug_assert_eq!(v.len(), SPEND_PROXY_COLS);
                v
            })
            .collect();

        let output_proxies: Vec<Vec<Goldilocks>> = self
            .outputs
            .iter()
            .map(|o| {
                let cm_fe =
                    poseidon2_cm_fe(&perm16, o.d, o.pk_d, o.ivk_commitment, o.value, o.rcm);
                let mut v = Vec::with_capacity(OUTPUT_PROXY_COLS);
                v.push(cm_fe);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(o.d)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(o.pk_d)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(o.ivk_commitment)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(o.value)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(o.rcm)));
                let value_canon = reduce_to_goldilocks(o.value);
                for k in 0..VALUE_BITS {
                    let bit = (value_canon >> k) & 1;
                    v.push(Goldilocks::from_u64(bit));
                }
                debug_assert_eq!(v.len(), OUTPUT_PROXY_COLS);
                v
            })
            .collect();

        let fee_f = Goldilocks::from_u64(self.fee);

        let mut values = Vec::<Goldilocks>::with_capacity(TRACE_HEIGHT * width);
        for row_idx in 0..TRACE_HEIGHT {
            values.push(fee_f);
            for i in 0..n_s {
                values.extend_from_slice(&spend_proxies[i]);
                if row_idx == 0 {
                    for k in 0..MERKLE_DEPTH {
                        values.extend_from_slice(&row0_spend_merkle[i][k]);
                    }
                    values.extend_from_slice(&row0_spend_ivkcm[i]);
                    values.extend_from_slice(&row0_spend_cm[i]);
                    values.extend_from_slice(&row0_spend_nf[i]);
                } else {
                    for _ in 0..MERKLE_DEPTH {
                        values.extend_from_slice(&padding_p2);
                    }
                    values.extend_from_slice(&padding_p2); // IvkCm (w=8)
                    values.extend_from_slice(&padding_p2_16); // Cm (w=16)
                    values.extend_from_slice(&padding_p2); // Nf (w=8)
                }
            }
            for j in 0..n_o {
                values.extend_from_slice(&output_proxies[j]);
                if row_idx == 0 {
                    values.extend_from_slice(&row0_out_cm[j]);
                } else {
                    values.extend_from_slice(&padding_p2_16);
                }
            }
        }

        debug_assert_eq!(values.len(), TRACE_HEIGHT * width);
        RowMajorMatrix::new(values, width)
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Goldilocks prime.
pub(crate) const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

/// Reduce a `u64` into a canonical Goldilocks residue.
#[inline]
pub(crate) fn reduce_to_goldilocks(x: u64) -> u64 {
    if x >= GOLDILOCKS_P {
        x.wrapping_sub(GOLDILOCKS_P)
    } else {
        x
    }
}

/// Default test chain_id ("UNOT" LE).
pub const CHAIN_ID_TEST: u32 = 0x544F4E55;

/// Default test expiry_block for witness-derived public inputs.
pub const EXPIRY_BLOCK_TEST: u64 = 100_000;

/// Decode a public-input byte buffer into Goldilocks field elements. The
/// decoder is length-agnostic; callers pair it with
/// [`derive_shape_from_public_inputs_len`] to detect the shape first.
pub fn decode_public_inputs(bytes: &[u8]) -> Result<Vec<Goldilocks>, Plonky3Status> {
    if bytes.len() % 8 != 0 {
        return Err(Plonky3Status::PublicInputLengthMismatch);
    }
    let mut out = Vec::with_capacity(bytes.len() / 8);
    for chunk in bytes.chunks_exact(8) {
        let v = u64::from_le_bytes(chunk.try_into().unwrap());
        if v >= GOLDILOCKS_P {
            return Err(Plonky3Status::PublicInputDecodeFailed);
        }
        out.push(Goldilocks::from_u64(v));
    }
    Ok(out)
}

// Small Poseidon2 wrappers.

fn poseidon2_merkle_step(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    left: u64,
    right: u64,
) -> Goldilocks {
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
    state[0] = Goldilocks::from_u64(reduce_to_goldilocks(left));
    state[1] = Goldilocks::from_u64(reduce_to_goldilocks(right));
    perm.permute_mut(&mut state);
    state[0]
}

/// Compute the Merkle root for a 32-level path: at each level `k`, combine
/// `current` with `path[k]` under the bit `(pos >> k) & 1` ordering.
fn poseidon2_merkle_path_root(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    leaf: u64,
    pos: u64,
    path: &[u64; MERKLE_DEPTH],
) -> Goldilocks {
    let mut current = reduce_to_goldilocks(leaf);
    for k in 0..MERKLE_DEPTH {
        let bit = (pos >> k) & 1;
        let sib = reduce_to_goldilocks(path[k]);
        let (left, right) = if bit == 0 { (current, sib) } else { (sib, current) };
        current = poseidon2_merkle_step(perm, left, right).as_canonical_u64();
    }
    Goldilocks::from_u64(current)
}

fn poseidon2_ivk_commitment(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    ivk: u64,
    d: u64,
) -> Goldilocks {
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
    state[0] = Goldilocks::from_u64(TAG_IVK_CM);
    state[1] = Goldilocks::from_u64(reduce_to_goldilocks(ivk));
    state[2] = Goldilocks::from_u64(reduce_to_goldilocks(d));
    perm.permute_mut(&mut state);
    state[0]
}

fn poseidon2_cm(
    perm16: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH_16]>,
    d: u64,
    pk_d: u64,
    ivk_cm: u64,
    value: u64,
    rcm: u64,
) -> u64 {
    poseidon2_cm_fe(perm16, d, pk_d, ivk_cm, value, rcm).as_canonical_u64()
}

/// Wide-sponge Poseidon2-16 for the 15-fe note-commitment input per §3.2.
fn poseidon2_cm_fe(
    perm16: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH_16]>,
    d: u64,
    pk_d: u64,
    ivk_cm: u64,
    value: u64,
    rcm: u64,
) -> Goldilocks {
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
    state[0] = Goldilocks::from_u64(TAG_CM);
    state[1] = Goldilocks::from_u64(reduce_to_goldilocks(d));
    state[2] = Goldilocks::from_u64(reduce_to_goldilocks(pk_d));
    state[3] = Goldilocks::from_u64(reduce_to_goldilocks(ivk_cm));
    state[4] = Goldilocks::from_u64(reduce_to_goldilocks(value));
    state[5] = Goldilocks::from_u64(reduce_to_goldilocks(rcm));
    perm16.permute_mut(&mut state);
    state[0]
}

fn poseidon2_nf(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    nk: u64,
    cm: u64,
    pos: u64,
) -> Goldilocks {
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
    state[0] = Goldilocks::from_u64(TAG_NF);
    state[1] = Goldilocks::from_u64(reduce_to_goldilocks(nk));
    state[2] = Goldilocks::from_u64(reduce_to_goldilocks(cm));
    state[3] = Goldilocks::from_u64(reduce_to_goldilocks(pos));
    perm.permute_mut(&mut state);
    state[0]
}

// ---------------------------------------------------------------------------
// Pre-check helpers (prover-side)
// ---------------------------------------------------------------------------
//
// Plonky3's `DebugConstraintBuilder` panics on inconsistent traces in
// debug builds. These helpers run the hard claim checks in plain Rust so
// the prover can reject with a structured `WitnessInvalid` status before
// ever invoking Plonky3. Identical checks as the AIR row-0 bindings —
// drift here silently accepts constraint-violating witnesses at debug
// build time, but release builds catch them at verify.

/// True iff for every spend, `leaf_i == Poseidon2-16("uno-cm-v1", d_i,
/// pk_d_i, ivk_commitment_i, value_i, rcm_i)` (wide sponge per §3.2).
pub fn witness_claim2_leaf_consistent(w: &MvpWitness) -> bool {
    let perm = default_goldilocks_poseidon2_8();
    let perm16 = default_goldilocks_poseidon2_16();
    for s in &w.spends {
        let d_word = u64::from_le_bytes(s.d);
        let ivkcm = poseidon2_ivk_commitment(&perm, s.ivk, d_word);
        let derived = poseidon2_cm(
            &perm16,
            d_word,
            s.pk_d,
            ivkcm.as_canonical_u64(),
            s.value,
            s.rcm,
        );
        if derived != reduce_to_goldilocks(s.leaf) {
            return false;
        }
    }
    true
}

/// True iff for every spend, folding the 32-level Merkle path reproduces
/// `anchor_proxy`.
pub fn witness_claim1_anchor_consistent(w: &MvpWitness) -> bool {
    let perm = default_goldilocks_poseidon2_8();
    let want = reduce_to_goldilocks(w.anchor_proxy);
    for s in &w.spends {
        let derived =
            poseidon2_merkle_path_root(&perm, s.leaf, s.pos, &s.merkle_path)
                .as_canonical_u64();
        if derived != want {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_math_matches_envelope() {
        assert_eq!(air_num_public_values(1, 1), 25);
        assert_eq!(air_num_public_values(1, 2), 34);
        assert_eq!(air_num_public_values(4, 4), 76);
        assert_eq!(air_public_inputs_wire_len(1, 2), 272);
        assert_eq!(air_public_inputs_wire_len(4, 4), 608);
    }

    #[test]
    fn shape_derivation_roundtrip() {
        for n_s in MIN_SPENDS..=MAX_SPENDS {
            for n_o in MIN_OUTPUTS..=MAX_OUTPUTS {
                let len = air_public_inputs_wire_len(n_s, n_o);
                assert_eq!(derive_shape_from_public_inputs_len(len).unwrap(), (n_s, n_o));
            }
        }
    }

    #[test]
    fn shape_derivation_rejects_bogus_length() {
        assert!(derive_shape_from_public_inputs_len(0).is_err());
        assert!(derive_shape_from_public_inputs_len(40).is_err());
        assert!(derive_shape_from_public_inputs_len(273).is_err());
    }

    #[test]
    fn width_grows_with_shape() {
        let w11 = air_width(1, 1);
        let w12 = air_width(1, 2);
        let w22 = air_width(2, 2);
        let w44 = air_width(4, 4);
        assert!(w11 < w12 && w12 < w22 && w22 < w44);
        assert_eq!(w44, GLOBAL_COLS + 4 * per_spend_cols() + 4 * per_output_cols());
    }

    #[test]
    fn witness_encode_decode_roundtrip_all_shapes() {
        for n_s in MIN_SPENDS..=MAX_SPENDS {
            for n_o in MIN_OUTPUTS..=MAX_OUTPUTS {
                let w = MvpWitness::deterministic_valid(n_s, n_o, 0xA5A5_0000 + n_s as u64);
                let bytes = w.encode();
                let w2 = MvpWitness::decode(&bytes).unwrap();
                assert_eq!(w.shape(), w2.shape());
                assert_eq!(w.fee, w2.fee);
                assert_eq!(w.anchor_proxy, w2.anchor_proxy);
                assert_eq!(w.spends.len(), w2.spends.len());
                assert_eq!(w.outputs.len(), w2.outputs.len());
            }
        }
    }

    #[test]
    fn witness_balance_holds_for_deterministic_valid() {
        for n_s in MIN_SPENDS..=MAX_SPENDS {
            for n_o in MIN_OUTPUTS..=MAX_OUTPUTS {
                let w = MvpWitness::deterministic_valid(n_s, n_o, 0xDEAD_0000 + n_o as u64);
                assert!(
                    w.balance_holds(),
                    "balance must hold for deterministic_valid({}, {})",
                    n_s,
                    n_o
                );
            }
        }
    }

    #[test]
    fn public_inputs_length_per_shape() {
        for n_s in MIN_SPENDS..=MAX_SPENDS {
            for n_o in MIN_OUTPUTS..=MAX_OUTPUTS {
                let w = MvpWitness::deterministic_valid(n_s, n_o, 1);
                let pis = w.public_inputs();
                assert_eq!(pis.len(), air_num_public_values(n_s, n_o));
                let pib = w.public_inputs_bytes();
                assert_eq!(pib.len(), air_public_inputs_wire_len(n_s, n_o));
            }
        }
    }

    #[test]
    fn trace_shape_matches_air_width() {
        use p3_matrix::Matrix;
        for (n_s, n_o) in [(1, 1), (1, 2), (2, 2), (4, 4)].iter().copied() {
            let w = MvpWitness::deterministic_valid(n_s, n_o, 42);
            let trace = w.generate_trace();
            assert_eq!(trace.height(), TRACE_HEIGHT);
            assert_eq!(trace.width(), air_width(n_s, n_o));
        }
    }

    #[test]
    fn witness_decode_rejects_short_buffer() {
        let bytes = vec![0u8; 5];
        assert!(matches!(
            MvpWitness::decode(&bytes),
            Err(Plonky3Status::WitnessInvalid)
        ));
    }

    #[test]
    fn witness_decode_rejects_out_of_envelope_shape() {
        let mut bytes = vec![0u8; 18];
        bytes[0] = 0; // n_spends = 0
        bytes[1] = 1;
        assert!(matches!(
            MvpWitness::decode(&bytes),
            Err(Plonky3Status::WitnessInvalid)
        ));
        let mut bytes = vec![0u8; 18];
        bytes[0] = 1;
        bytes[1] = 5; // n_outputs = 5 (out of cap)
        assert!(matches!(
            MvpWitness::decode(&bytes),
            Err(Plonky3Status::WitnessInvalid)
        ));
    }

    #[test]
    fn public_input_decode_rejects_non_canonical() {
        let mut bytes = vec![0u8; 8];
        bytes[0..8].copy_from_slice(&GOLDILOCKS_P.to_le_bytes());
        assert!(matches!(
            decode_public_inputs(&bytes),
            Err(Plonky3Status::PublicInputDecodeFailed)
        ));
    }
}
