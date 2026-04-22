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
//! # Column layout (K-air-col-step2: wide-Cm + narrow-IvkCm/Nf row-loops)
//!
//! ```text
//! width(n_s, n_o) = GLOBAL_COLS + n_s·per_spend_cols() + n_o·per_output_cols()
//!
//! GLOBAL_COLS       = 1 + MERKLE_DEPTH                 // fee + 32 row selectors
//!                   + 1·POSEIDON2_COLS_PER_INSTANCE_16 // SHARED claim 2/6 Cm (w=16)
//!                   + 1·POSEIDON2_COLS_PER_INSTANCE    // SHARED claim 3/4 IvkCm/Nf (w=8)
//!
//! per_spend_cols()  = SPEND_PROXY_COLS
//!                   + 1                                // S_CURRENT (Merkle running val)
//!                   + 1·POSEIDON2_COLS_PER_INSTANCE    // SHARED Merkle (w=8, row-loop)
//! per_output_cols() = OUTPUT_PROXY_COLS
//! ```
//!
//! Three row-looped shared Poseidon2 blocks fold all per-spend /
//! per-output compressions across trace rows:
//!
//! - **Merkle (w=8, shared per spend)**: rows 0..31 carry the 32 Merkle
//!   levels of that spend via a running-digest column `S_CURRENT`.
//! - **Cm/OutCm (w=16, shared globally — K-air-col-step2 strategy b)**:
//!   rows 0..3 carry spend `i`'s claim-2 Cm compression, rows 4..7 carry
//!   output `j`'s claim-6 Cm compression. Row-0 bindings check `cm ==
//!   leaf` (claim 2) or `cm == public_inputs[cm_j]` (claim 6) via
//!   selector-gated equalities on rows 0..7.
//! - **IvkCm/Nf (w=8, shared globally — K-air-col-step2 strategy c)**:
//!   rows 0..3 carry spend `i`'s claim-3 IVK-commitment compression,
//!   rows 4..7 carry spend `i`'s claim-4 nullifier compression. Row-4+i
//!   binds the 4 nullifier limbs to `public_inputs[nf_i]`.
//!
//! All three blocks reuse the existing `GS_ROW_SEL[0..32]` one-hot row
//! selector bank (which is `1` on row `k`, `0` elsewhere) — no new
//! selector columns are added for the step-2 pass. The Poseidon2 sub-AIR
//! still runs on every row; trace height stays at 64 rows.
//!
//! Width at (4, 4) after step 2 drops from 5,553 cols to 2,081 cols (a
//! ~62.5 % additional reduction on top of the 80 % step-1 savings, for
//! a cumulative ~92.5 % vs the pre-K-air-col-share baseline of 27,837
//! cols). See [`air_width`] for the exact cols-per-shape; numbers are
//! tracked by `width_grows_with_shape`.
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
    default_goldilocks_poseidon2_16, default_goldilocks_poseidon2_8,
    GenericPoseidon2LinearLayersGoldilocks, Goldilocks, GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS,
    GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_16, GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{
    num_cols as p2_num_cols, FullRound, PartialRound, Poseidon2Cols, RoundConstants, SBox,
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
pub(crate) type P2Cols<T> = Poseidon2Cols<
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

/// Depth of the note-commitment Merkle tree (§2.3 / §10.2 ConfigParam 84).
pub const MERKLE_DEPTH: usize = 32;

/// Global (tx-level) columns:
///
/// ```text
///   [fee]                                            (1 col)
///   [GS_ROW_SEL[0..MERKLE_DEPTH]]                    (32 cols, one-hot bank)
///   [shared Cm/OutCm Poseidon2-16 block]             (316 cols, claim 2/6)
///   [shared IvkCm/Nf Poseidon2-8 block]              (180 cols, claim 3/4)
/// ```
///
/// The 32 row selectors are the AIR's clock for all three shared
/// Poseidon2 blocks: `GS_ROW_SEL[k]` is `1` exactly on trace row `k` for
/// `k ∈ 0..32`, `0` on rows 32..63. Step 1 (K-air-col-share) introduced
/// them for the Merkle row-loop; step 2 (K-air-col-step2) reuses the
/// same bank for the Cm/IvkCm/Nf row-loops — no extra selector columns.
pub const GLOBAL_COLS: usize = 1
    + MERKLE_DEPTH
    + POSEIDON2_COLS_PER_INSTANCE_16 // shared Cm / OutCm (w=16) — claim 2/6
    + POSEIDON2_COLS_PER_INSTANCE; // shared IvkCm / Nf (w=8) — claim 3/4
const GCOL_FEE: usize = 0;
/// Base index of the 32 one-hot Merkle row-selector columns (§claim 1).
const GS_ROW_SEL0: usize = 1;
/// Base index of the shared Cm/OutCm width-16 Poseidon2 block
/// (K-air-col-step2 strategy b — claim 2/6 row-loop on rows 0..7).
const G_CM_SHARED_P2_16: usize = GS_ROW_SEL0 + MERKLE_DEPTH;
/// Base index of the shared IvkCm/Nf width-8 Poseidon2 block
/// (K-air-col-step2 strategy c — claim 3/4 row-loop on rows 0..7).
const G_IVKCM_NF_SHARED_P2_8: usize = G_CM_SHARED_P2_16 + POSEIDON2_COLS_PER_INSTANCE_16;

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
pub const SPEND_PROXY_COLS: usize = 9 + MERKLE_DEPTH + MERKLE_DEPTH + VALUE_BITS;

/// Per-output proxy columns: cm_claim, d, pk_d, ivk_commitment, value,
/// rcm (6 leading fields), plus VALUE_BITS bit columns for the explicit
/// u64 range-check on `value_j` (§4.2 claim 7).
pub const OUTPUT_PROXY_COLS: usize = 6 + VALUE_BITS;

/// Narrow (width-8) Poseidon2 instances per spend after K-air-col-step2:
/// only the shared-Merkle slot remains. IvkCm + Nf are folded into a
/// single globally-shared row-looped block on rows 0..7.
pub const POSEIDON2_NARROW_PER_SPEND: usize = 1;

/// Per-spend variable columns that are NOT constant across rows (i.e., not
/// included in the transition "proxies are constant" equality). Currently:
/// `S_CURRENT` (running Merkle digest).
pub const SPEND_VAR_COLS: usize = 1;
/// Offset of `S_CURRENT` within the per-spend variable block.
const S_CURRENT: usize = 0;

/// Wide (width-16) Poseidon2 instances per spend after K-air-col-step2:
/// zero (the claim-2 Cm compression is folded into the global shared
/// w=16 block on trace rows 0..3).
pub const POSEIDON2_WIDE_PER_SPEND: usize = 0;

/// Wide (width-16) Poseidon2 instances per output after K-air-col-step2:
/// zero (the claim-6 Cm compression is folded into the global shared
/// w=16 block on trace rows 4..7).
pub const POSEIDON2_WIDE_PER_OUTPUT: usize = 0;

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

/// Per-spend block width after K-air-col-step2: proxies + `S_CURRENT` +
/// the shared Merkle Poseidon2-w8 slot. IvkCm (w=8), Cm (w=16), Nf (w=8)
/// are globally shared (row-looped on rows 0..7) and live in `GLOBAL_COLS`.
#[inline]
pub const fn per_spend_cols() -> usize {
    SPEND_PROXY_COLS + SPEND_VAR_COLS + POSEIDON2_COLS_PER_INSTANCE // shared Merkle (row-loop)
}

/// Per-output block width after K-air-col-step2: proxies only; the
/// claim-6 Cm compression is globally shared (row-looped on rows 4..7)
/// and lives in `GLOBAL_COLS`.
#[inline]
pub const fn per_output_cols() -> usize {
    OUTPUT_PROXY_COLS
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
// Global block layout (K-air-col-step2):
//     [GCOL_FEE : 1]                                (constant across rows)
//   | [GS_ROW_SEL[0..32] : 32]                      (one-hot, rows 0..31)
//   | [shared Cm/OutCm P2 (w=16) : 316]             (rows 0..3 = spends,
//                                                    rows 4..7 = outputs)
//   | [shared IvkCm/Nf P2 (w=8) : 180]              (rows 0..3 = IvkCm,
//                                                    rows 4..7 = Nf)
//
// Spend block layout (contiguous within the spend-i region):
//     [SPEND_PROXY_COLS]                            (constant across rows)
//   | [SPEND_VAR_COLS: S_CURRENT]                   (running Merkle digest)
//   | [shared Merkle P2 (w=8) : 180]                (rows 0..31 = 32 levels)
//
// Output block layout:
//     [OUTPUT_PROXY_COLS]                           (constant across rows)

#[inline]
const fn spend_proxy_offset(i: usize) -> usize {
    GLOBAL_COLS + i * per_spend_cols()
}

/// Offset of `S_CURRENT` (running Merkle digest) within spend `i`. Placed
/// immediately after the constant-across-rows proxies.
#[inline]
const fn spend_var_offset(i: usize) -> usize {
    spend_proxy_offset(i) + SPEND_PROXY_COLS
}

/// Offset of the shared Merkle width-8 Poseidon2 column block within
/// spend `i` (K-air-col-share step 1 — row-loop over the 32 levels).
#[inline]
const fn spend_p2_offset(i: usize) -> usize {
    spend_var_offset(i) + SPEND_VAR_COLS
}

#[inline]
const fn output_proxy_offset(n_spends: usize, j: usize) -> usize {
    GLOBAL_COLS + n_spends * per_spend_cols() + j * per_output_cols()
}

/// Enumerated narrow (width-8) per-spend Poseidon2 slot.
///
/// After K-air-col-step2 the per-spend narrow block holds only the shared
/// Merkle row-loop; IvkCm and Nf moved to the globally-shared
/// `G_IVKCM_NF_SHARED_P2_8` block on rows 0..3 and 4..7 respectively.
#[derive(Copy, Clone)]
enum SpendP2 {
    /// Shared Merkle-path width-8 Poseidon2 slot (row-loop — level `k` is
    /// on trace row `k`).
    Merkle,
}

#[inline]
fn spend_p2_group<T>(row: &[T], i: usize, s: SpendP2) -> &P2Cols<T> {
    let off = match s {
        SpendP2::Merkle => spend_p2_offset(i),
    };
    let group: &[T] = &row[off..off + POSEIDON2_COLS_PER_INSTANCE];
    <[T] as Borrow<P2Cols<T>>>::borrow(group)
}

/// Globally-shared width-16 Poseidon2 block for claim 2 (spend Cm) on
/// rows 0..3 and claim 6 (output Cm) on rows 4..7.
#[inline]
fn shared_cm_p2_group<T>(row: &[T]) -> &P2Cols16<T> {
    let group: &[T] = &row[G_CM_SHARED_P2_16..G_CM_SHARED_P2_16 + POSEIDON2_COLS_PER_INSTANCE_16];
    <[T] as Borrow<P2Cols16<T>>>::borrow(group)
}

/// Globally-shared width-8 Poseidon2 block for claim 3 (IvkCm) on rows
/// 0..3 and claim 4 (Nf) on rows 4..7.
#[inline]
fn shared_ivkcm_nf_p2_group<T>(row: &[T]) -> &P2Cols<T> {
    let group: &[T] =
        &row[G_IVKCM_NF_SHARED_P2_8..G_IVKCM_NF_SHARED_P2_8 + POSEIDON2_COLS_PER_INSTANCE];
    <[T] as Borrow<P2Cols<T>>>::borrow(group)
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
const _UNUSED_PI: (
    usize,
    usize,
    usize,
    fn(usize) -> usize,
    fn(usize, usize) -> usize,
    fn(usize, usize) -> usize,
) = (PI_SCHEME, PI_CHAIN, PI_EXPIRY, pi_rk, pi_epk, pi_filter_tag);

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
fn beginning_full_round_constant_8<F: PrimeCharacteristicRing>(
    round: usize,
) -> [F; POSEIDON2_WIDTH] {
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
        // Full-width nullifier PI: `nf_i` occupies 4 Goldilocks slots
        // starting at `pi_nf(i)` per §4.3 step 4. Snapshot all 4 limbs.
        let pi_nfs: Vec<[AB::PublicVar; 4]> = (0..self.n_spends)
            .map(|i| {
                let base = pi_nf(i);
                [
                    pis_vec[base],
                    pis_vec[base + 1],
                    pis_vec[base + 2],
                    pis_vec[base + 3],
                ]
            })
            .collect();
        let pi_cms: Vec<AB::PublicVar> = (0..self.n_outputs)
            .map(|j| pis_vec[pi_cm(self.n_spends, j)])
            .collect();

        // ---- Poseidon2 sub-AIR on every row -----------------------------
        //
        // After K-air-col-step2 the three shared Poseidon2 blocks are:
        //   * Per-spend shared Merkle (w=8): runs 32 levels on rows 0..31.
        //   * Globally-shared Cm/OutCm (w=16): runs claim 2 on rows 0..3
        //     (spend i on row i) and claim 6 on rows 4..7 (output j on
        //     row 4+j). One physical column block, row-selector picks
        //     which instance's input/output binding applies.
        //   * Globally-shared IvkCm/Nf (w=8): runs claim 3 on rows 0..3
        //     (spend i on row i) and claim 4 on rows 4..7 (spend i on
        //     row 4+i). One physical column block, same gating story.
        //
        // The Poseidon2 sub-AIR runs on every row regardless of row
        // selector; non-bound rows carry zero-input permutation witness.
        for i in 0..self.n_spends {
            eval_poseidon2(builder, spend_p2_group(local_slice, i, SpendP2::Merkle));
        }
        eval_poseidon2_16(builder, shared_cm_p2_group(local_slice));
        eval_poseidon2(builder, shared_ivkcm_nf_p2_group(local_slice));

        // ---- Global row-selector boot, shift, and tail constraints -----
        //
        // `GS_ROW_SEL[k]` is 1 iff the current row is Merkle level `k`
        // (i.e., row index `k`). They are a one-hot pulse that starts at
        // position 0 on row 0 and shifts by +1 each row; after 32 rows
        // the pulse falls off the end of the bank and the selectors are
        // all 0 on rows 32..63.
        //
        // Row 0:    GS_ROW_SEL[0] = 1, GS_ROW_SEL[1..32] = 0.
        // Transition: next[0] = 0, next[k+1] = local[k]  (k = 0..30).
        //              local[31] has no next-row target (pulse expires).
        //
        // `is_merkle = Σ_k GS_ROW_SEL[k]` is 1 on rows 0..31, 0 on 32..63.
        {
            let mut first = builder.when_first_row();
            first.assert_eq(
                local_slice[GS_ROW_SEL0 + 0].into(),
                AB::Expr::from(AB::F::from_u64(1)),
            );
            for k in 1..MERKLE_DEPTH {
                first.assert_zero(local_slice[GS_ROW_SEL0 + k].into());
            }
        }
        {
            let mut t = builder.when_transition();
            // next[0] = 0.
            t.assert_zero(next_slice[GS_ROW_SEL0 + 0].into());
            // next[k+1] = local[k], for k ∈ 0..MERKLE_DEPTH-1.
            for k in 0..MERKLE_DEPTH - 1 {
                t.assert_eq(
                    next_slice[GS_ROW_SEL0 + k + 1].into(),
                    local_slice[GS_ROW_SEL0 + k].into(),
                );
            }
        }
        // Boolean each selector on every row (catches a malicious prover
        // committing non-boolean values that sum to 1).
        for k in 0..MERKLE_DEPTH {
            let s: AB::Expr = local_slice[GS_ROW_SEL0 + k].into();
            let one_minus_s: AB::Expr = AB::Expr::from(AB::F::from_u64(1)) - s.clone();
            builder.assert_zero(s * one_minus_s);
        }

        // ---- First-row bindings ----------------------------------------
        {
            let mut first = builder.when_first_row();

            // Global: fee proxy bound to PI.
            first.assert_eq(local_slice[GCOL_FEE], pi_fee);

            // Per-spend row-0 bindings (claims 1 / 5 seeds; bit-decomp of
            // path-bits, pos, value). Claims 2 / 3 / 4 are now row-gated
            // on rows 0..7 via the K-air-col-step2 shared blocks and live
            // in the separate "Row-gated shared-block bindings" section
            // below.
            for i in 0..self.n_spends {
                let value = spend_col(local_slice, i, S_VALUE);
                let pos = spend_col(local_slice, i, S_POS);
                let leaf = spend_col(local_slice, i, S_LEAF);

                // Claim 1 seed: `S_CURRENT` on row 0 starts at `leaf`.
                let s_current_row0 = local_slice[spend_var_offset(i) + S_CURRENT];
                first.assert_eq(s_current_row0.into(), leaf.into());

                // Row-0 bit booleanity for 32 path-bit proxies (they are
                // constant across rows by the transition "proxies are
                // constant" check, so booleanity on row 0 propagates).
                for k in 0..MERKLE_DEPTH {
                    let b: AB::Var = spend_col(local_slice, i, S_PATH_BIT0 + k);
                    let b_expr: AB::Expr = b.into();
                    let one_minus_b: AB::Expr = AB::Expr::from(AB::F::from_u64(1)) - b_expr.clone();
                    first.assert_zero(b_expr * one_minus_b);
                }

                // Pos bit-decomposition: `pos == Σ_k b_k · 2^k`.
                let mut pos_recon: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                for k in 0..MERKLE_DEPTH {
                    let b: AB::Var = spend_col(local_slice, i, S_PATH_BIT0 + k);
                    let weight = AB::F::from_u64(1u64 << k);
                    pos_recon = pos_recon + AB::Expr::from(weight) * b.into();
                }
                first.assert_eq(pos.into(), pos_recon);

                // Claim 5: explicit u64 range-check on `value_i`.
                let mut value_recon: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                for k in 0..VALUE_BITS {
                    let b: AB::Var = spend_col(local_slice, i, S_VALUE_BIT0 + k);
                    let b_expr: AB::Expr = b.into();
                    let one_minus_b = AB::Expr::from(AB::F::from_u64(1)) - b_expr.clone();
                    first.assert_zero(b_expr.clone() * one_minus_b);
                    let weight = if k == 63 {
                        AB::F::from_u64(1u64 << 63)
                    } else {
                        AB::F::from_u64(1u64 << k)
                    };
                    value_recon = value_recon + AB::Expr::from(weight) * b_expr;
                }
                first.assert_eq(value.into(), value_recon);
            }

            // Per-output row-0 bindings (claim 7 bit-decomp of value_j,
            // and the `cm_claim == pi_cms[j]` equality — proxies are
            // constant across rows, so row-0 suffices for these).
            for j in 0..self.n_outputs {
                let cm_claim = output_col(local_slice, self.n_spends, j, O_CM_CLAIM);
                let value_out = output_col(local_slice, self.n_spends, j, O_VALUE);

                // Claim 6 (output half): bind the per-output `cm_claim`
                // proxy to PI. The `cm_claim = Poseidon2(...)` half of
                // claim 6 is gated on row 4+j via the shared wide block.
                first.assert_eq(cm_claim, pi_cms[j]);

                // Claim 7: explicit u64 range-check on `value_j`.
                let mut value_recon: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                for k in 0..VALUE_BITS {
                    let b: AB::Var = output_col(local_slice, self.n_spends, j, O_VALUE_BIT0 + k);
                    let b_expr: AB::Expr = b.into();
                    let one_minus_b = AB::Expr::from(AB::F::from_u64(1)) - b_expr.clone();
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
                sum = sum - output_col::<AB::Var>(local_slice, self.n_spends, j, O_VALUE).into();
            }
            sum = sum - local_slice[GCOL_FEE].into();
            first.assert_zero(sum);
        }

        // ---- Row-gated shared-block bindings (K-air-col-step2) ---------
        //
        // The two globally-shared Poseidon2 blocks (wide Cm + narrow
        // IvkCm/Nf) host up to 4 + 4 = 8 distinct instances on the first
        // 8 trace rows. On row `r`, `GS_ROW_SEL[r] == 1` and we want:
        //
        //   Wide Cm block (w=16):
        //     row i (i ∈ 0..n_spends): inputs = (TAG_CM, d_i, pk_d_i,
        //       ivk_commitment_claim_i, value_i, rcm_i, 0*10); output[0]
        //       == leaf_i (claim 2 half — `cm == leaf`).
        //     row 4+j (j ∈ 0..n_outputs): inputs = (TAG_CM, d_j, pk_d_j,
        //       ivk_commitment_j, value_j, rcm_j, 0*10); output[0] ==
        //       cm_claim_j (claim 6 half — `cm == Poseidon2(...)`).
        //
        //   Narrow IvkCm/Nf block (w=8):
        //     row i (i ∈ 0..n_spends): inputs = (TAG_IVK_CM, ivk_i, d_i,
        //       0*5); output[0] == ivk_commitment_claim_i (claim 3).
        //     row 4+i (i ∈ 0..n_spends): inputs = (TAG_NF, nk_i, leaf_i,
        //       pos_i, 0*4); output[0..4] == pi_nfs[i] (claim 4, full
        //       256-bit nullifier).
        //
        // For rows that are NOT bound to any instance (e.g., row 4+i for
        // i ≥ n_spends, or rows 8..63), we emit no constraint — the
        // prover fills a zero-input permutation witness which satisfies
        // the Poseidon2 sub-AIR trivially.
        //
        // `GS_ROW_SEL` is one-hot with exactly one `1` on rows 0..31 (see
        // the row-selector shift-register constraint). Each row-gated
        // equality `sel_r · (a - b) == 0` is degree 2.
        {
            let shared_cm = shared_cm_p2_group::<AB::Var>(local_slice);
            let shared_cm_out = &shared_cm.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
            let shared_ivkcm_nf = shared_ivkcm_nf_p2_group::<AB::Var>(local_slice);
            let shared_ivkcm_nf_out =
                &shared_ivkcm_nf.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;

            // --- Wide Cm block: spend row-0..(n_spends-1) bindings ------
            for i in 0..self.n_spends {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + i].into();
                let leaf = spend_col::<AB::Var>(local_slice, i, S_LEAF);
                let d = spend_col::<AB::Var>(local_slice, i, S_D);
                let pk_d = spend_col::<AB::Var>(local_slice, i, S_PK_D);
                let ivk_commitment_claim =
                    spend_col::<AB::Var>(local_slice, i, S_IVK_COMMITMENT_CLAIM);
                let value = spend_col::<AB::Var>(local_slice, i, S_VALUE);
                let rcm = spend_col::<AB::Var>(local_slice, i, S_RCM);

                // inputs[0] = TAG_CM
                builder.assert_zero(
                    sel.clone()
                        * (AB::Expr::from(shared_cm.inputs[0])
                            - AB::Expr::from(AB::F::from_u64(TAG_CM))),
                );
                // inputs[1..6] = d, pk_d, ivk_commitment_claim, value, rcm
                builder.assert_zero(sel.clone() * (AB::Expr::from(shared_cm.inputs[1]) - d.into()));
                builder
                    .assert_zero(sel.clone() * (AB::Expr::from(shared_cm.inputs[2]) - pk_d.into()));
                builder.assert_zero(
                    sel.clone()
                        * (AB::Expr::from(shared_cm.inputs[3]) - ivk_commitment_claim.into()),
                );
                builder.assert_zero(
                    sel.clone() * (AB::Expr::from(shared_cm.inputs[4]) - value.into()),
                );
                builder
                    .assert_zero(sel.clone() * (AB::Expr::from(shared_cm.inputs[5]) - rcm.into()));
                for k in 6..POSEIDON2_WIDTH_16 {
                    builder.assert_zero(sel.clone() * AB::Expr::from(shared_cm.inputs[k]));
                }
                // Claim 2 output binding: `cm == leaf_i`.
                builder.assert_zero(sel * (AB::Expr::from(shared_cm_out[0]) - leaf.into()));
            }

            // --- Wide Cm block: output rows 4..(4+n_outputs-1) bindings -
            for j in 0..self.n_outputs {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 4 + j].into();
                let cm_claim = output_col::<AB::Var>(local_slice, self.n_spends, j, O_CM_CLAIM);
                let d = output_col::<AB::Var>(local_slice, self.n_spends, j, O_D);
                let pk_d = output_col::<AB::Var>(local_slice, self.n_spends, j, O_PK_D);
                let ivk_cm = output_col::<AB::Var>(local_slice, self.n_spends, j, O_IVK_COMMITMENT);
                let value_out = output_col::<AB::Var>(local_slice, self.n_spends, j, O_VALUE);
                let rcm = output_col::<AB::Var>(local_slice, self.n_spends, j, O_RCM);

                builder.assert_zero(
                    sel.clone()
                        * (AB::Expr::from(shared_cm.inputs[0])
                            - AB::Expr::from(AB::F::from_u64(TAG_CM))),
                );
                builder.assert_zero(sel.clone() * (AB::Expr::from(shared_cm.inputs[1]) - d.into()));
                builder
                    .assert_zero(sel.clone() * (AB::Expr::from(shared_cm.inputs[2]) - pk_d.into()));
                builder.assert_zero(
                    sel.clone() * (AB::Expr::from(shared_cm.inputs[3]) - ivk_cm.into()),
                );
                builder.assert_zero(
                    sel.clone() * (AB::Expr::from(shared_cm.inputs[4]) - value_out.into()),
                );
                builder
                    .assert_zero(sel.clone() * (AB::Expr::from(shared_cm.inputs[5]) - rcm.into()));
                for k in 6..POSEIDON2_WIDTH_16 {
                    builder.assert_zero(sel.clone() * AB::Expr::from(shared_cm.inputs[k]));
                }
                // Claim 6 output binding: `cm_claim == Poseidon2(...)`.
                builder.assert_zero(sel * (AB::Expr::from(shared_cm_out[0]) - cm_claim.into()));
            }

            // --- Narrow IvkCm block: rows 0..(n_spends-1) --------------
            for i in 0..self.n_spends {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + i].into();
                let ivk = spend_col::<AB::Var>(local_slice, i, S_IVK);
                let d = spend_col::<AB::Var>(local_slice, i, S_D);
                let ivk_commitment_claim =
                    spend_col::<AB::Var>(local_slice, i, S_IVK_COMMITMENT_CLAIM);

                builder.assert_zero(
                    sel.clone()
                        * (AB::Expr::from(shared_ivkcm_nf.inputs[0])
                            - AB::Expr::from(AB::F::from_u64(TAG_IVK_CM))),
                );
                builder.assert_zero(
                    sel.clone() * (AB::Expr::from(shared_ivkcm_nf.inputs[1]) - ivk.into()),
                );
                builder.assert_zero(
                    sel.clone() * (AB::Expr::from(shared_ivkcm_nf.inputs[2]) - d.into()),
                );
                for k in 3..POSEIDON2_WIDTH {
                    builder.assert_zero(sel.clone() * AB::Expr::from(shared_ivkcm_nf.inputs[k]));
                }
                // Claim 3 output binding: `ivk_commitment_claim == ...`.
                builder.assert_zero(
                    sel * (AB::Expr::from(shared_ivkcm_nf_out[0]) - ivk_commitment_claim.into()),
                );
            }

            // --- Narrow Nf block: rows 4..(4+n_spends-1) ---------------
            for i in 0..self.n_spends {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 4 + i].into();
                let nk = spend_col::<AB::Var>(local_slice, i, S_NK);
                let leaf = spend_col::<AB::Var>(local_slice, i, S_LEAF);
                let pos = spend_col::<AB::Var>(local_slice, i, S_POS);

                builder.assert_zero(
                    sel.clone()
                        * (AB::Expr::from(shared_ivkcm_nf.inputs[0])
                            - AB::Expr::from(AB::F::from_u64(TAG_NF))),
                );
                builder.assert_zero(
                    sel.clone() * (AB::Expr::from(shared_ivkcm_nf.inputs[1]) - nk.into()),
                );
                builder.assert_zero(
                    sel.clone() * (AB::Expr::from(shared_ivkcm_nf.inputs[2]) - leaf.into()),
                );
                builder.assert_zero(
                    sel.clone() * (AB::Expr::from(shared_ivkcm_nf.inputs[3]) - pos.into()),
                );
                for k in 4..POSEIDON2_WIDTH {
                    builder.assert_zero(sel.clone() * AB::Expr::from(shared_ivkcm_nf.inputs[k]));
                }
                // Claim 4: bind all 4 limbs of `nf_i` to the PI.
                for limb in 0..4 {
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_ivkcm_nf_out[limb]) - pi_nfs[i][limb].into()),
                    );
                }
            }
        }

        // ---- Per-row Merkle row-loop constraints (K-air-col-share #1) ---
        //
        // Let `is_merkle = Σ_k GS_ROW_SEL[k]`. On Merkle rows (0..31)
        // `is_merkle = 1`; on padding rows (32..63) `is_merkle = 0`.
        //
        // Selected bit/sibling: `b = Σ_k sel[k] · bit_k`, similarly `sib`.
        //
        // Active rows: bind P2.inputs to (left, right, 0*6); assert
        //   next.S_CURRENT = P2.output[0].
        // Inactive rows: latch next.S_CURRENT = S_CURRENT. P2.inputs are
        //   unconstrained (prover fills zero-input permutation witness).
        {
            // is_merkle as a reusable expression (sum of selectors on the
            // current row).
            let mut is_merkle: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
            for k in 0..MERKLE_DEPTH {
                is_merkle = is_merkle + AB::Expr::from(local_slice[GS_ROW_SEL0 + k]);
            }

            for i in 0..self.n_spends {
                // Selected bit/sibling at this row.
                let mut b_sel: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                let mut sib_sel: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                for k in 0..MERKLE_DEPTH {
                    let sel: AB::Expr = local_slice[GS_ROW_SEL0 + k].into();
                    let bit_k: AB::Var = spend_col(local_slice, i, S_PATH_BIT0 + k);
                    let sib_k: AB::Var = spend_col(local_slice, i, S_SIBLING0 + k);
                    b_sel = b_sel + sel.clone() * bit_k.into();
                    sib_sel = sib_sel + sel * sib_k.into();
                }
                let one_minus_b_sel: AB::Expr = AB::Expr::from(AB::F::from_u64(1)) - b_sel.clone();
                let cur: AB::Expr = local_slice[spend_var_offset(i) + S_CURRENT].into();

                let left_sel: AB::Expr =
                    one_minus_b_sel.clone() * cur.clone() + b_sel.clone() * sib_sel.clone();
                let right_sel: AB::Expr = b_sel * cur.clone() + one_minus_b_sel * sib_sel;

                let merkle = spend_p2_group::<AB::Var>(local_slice, i, SpendP2::Merkle);
                // Active-row input bindings (gated by is_merkle).
                builder
                    .assert_zero(is_merkle.clone() * (AB::Expr::from(merkle.inputs[0]) - left_sel));
                builder.assert_zero(
                    is_merkle.clone() * (AB::Expr::from(merkle.inputs[1]) - right_sel),
                );
                for pad in 2..POSEIDON2_WIDTH {
                    builder.assert_zero(is_merkle.clone() * AB::Expr::from(merkle.inputs[pad]));
                }

                // Transition: advance (active) or latch (inactive).
                let next_cur: AB::Expr = next_slice[spend_var_offset(i) + S_CURRENT].into();
                let merkle_out_0: AB::Expr = AB::Expr::from(
                    merkle.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[0],
                );
                let mut t = builder.when_transition();
                // Active: next.S_CURRENT == P2.output[0].
                t.assert_zero(is_merkle.clone() * (next_cur.clone() - merkle_out_0));
                // Inactive: next.S_CURRENT == S_CURRENT.
                let one_minus_is_merkle: AB::Expr =
                    AB::Expr::from(AB::F::from_u64(1)) - is_merkle.clone();
                t.assert_zero(one_minus_is_merkle * (next_cur - cur));
            }

            // Last-row anchor binding: after 32 active rows + latching on
            // rows 32..63, `S_CURRENT` on the last row is the final
            // Merkle root, which must equal the tx-level anchor PI.
            let mut last = builder.when_last_row();
            for i in 0..self.n_spends {
                last.assert_eq(local_slice[spend_var_offset(i) + S_CURRENT], pi_anchor0);
            }
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

pub(crate) fn eval_poseidon2<AB>(builder: &mut AB, local: &P2Cols<AB::Var>)
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
    full_round: &FullRound<AB::Var, WIDTH, POSEIDON2_SBOX_DEGREE, POSEIDON2_SBOX_REGISTERS>,
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
    partial_round: &PartialRound<AB::Var, WIDTH, POSEIDON2_SBOX_DEGREE, POSEIDON2_SBOX_REGISTERS>,
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
        let shared_anchor =
            poseidon2_merkle_path_root(&perm, shared_leaf, shared_pos, &shared_path)
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
        let mut out =
            Vec::with_capacity(18 + per_spend * self.spends.len() + 40 * self.outputs.len());
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
            let ivk_commitment = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
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
        out.push(Goldilocks::from_u64(reduce_to_goldilocks(
            self.anchor_proxy,
        )));
        for _ in 1..4 {
            out.push(Goldilocks::ZERO);
        }

        let perm = default_goldilocks_poseidon2_8();
        let perm16 = default_goldilocks_poseidon2_16();

        for s in &self.spends {
            // nf_i = first 4 limbs of Poseidon2(TAG_NF, nk, leaf(=cm), pos, 0, ...).
            // Full-width binding per §4.3 step 4.
            let nf_limbs = poseidon2_nf_full(&perm, s.nk, s.leaf, s.pos);
            for limb in nf_limbs {
                out.push(limb);
            }
            // rk_i: 4 × 0.
            for _ in 0..4 {
                out.push(Goldilocks::ZERO);
            }
        }

        for o in &self.outputs {
            let cm = poseidon2_cm_fe(&perm16, o.d, o.pk_d, o.ivk_commitment, o.value, o.rcm);
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

        // K-air-col-share step 1: the 32 Merkle levels now share one
        // Poseidon2 column block per spend, placed on rows 0..31. We
        // pre-compute:
        //   - `merkle_rows[i][k]` (k ∈ 0..32): the permutation witness for
        //     spend `i`'s level-k compression (placed at trace row `k`).
        //   - `s_current_vals[i][row]` (row ∈ 0..TRACE_HEIGHT): the per-row
        //     running Merkle digest (row 0 = leaf; row k+1 = permutation
        //     output of level k; rows 32..63 latch the final value = anchor).
        //   - `row0_spend_ivkcm / _cm / _nf`: the single-row permutation
        //     witnesses for claims 3/2/4 (placed on trace row 0 only).
        let mut merkle_rows: Vec<Vec<Vec<Goldilocks>>> = Vec::with_capacity(n_s);
        let mut s_current_vals: Vec<Vec<Goldilocks>> = Vec::with_capacity(n_s);
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

            // Merkle-row-loop: level k goes on trace row k. The P2 witness
            // at rows 32..63 is the zero-input permutation (padding_p2).
            let mut per_spend_merkle = Vec::with_capacity(TRACE_HEIGHT);
            let mut per_spend_current = Vec::with_capacity(TRACE_HEIGHT);
            per_spend_current.push(Goldilocks::from_u64(reduce_to_goldilocks(s.leaf)));
            let mut current = reduce_to_goldilocks(s.leaf);
            for k in 0..MERKLE_DEPTH {
                let bit = (s.pos >> k) & 1;
                let sib = reduce_to_goldilocks(s.merkle_path[k]);
                let (left, right) = if bit == 0 {
                    (current, sib)
                } else {
                    (sib, current)
                };
                let mut input = [Goldilocks::ZERO; POSEIDON2_WIDTH];
                input[0] = Goldilocks::from_u64(left);
                input[1] = Goldilocks::from_u64(right);
                let mut state = input;
                perm.permute_mut(&mut state);
                per_spend_merkle.push(gen_p2_row(input));
                current = state[0].as_canonical_u64();
                per_spend_current.push(Goldilocks::from_u64(current));
            }
            // Latch rows 32..63: pad P2 with zero-input permutation, and
            // hold S_CURRENT at the final anchor value.
            let anchor_f = Goldilocks::from_u64(current);
            while per_spend_merkle.len() < TRACE_HEIGHT {
                per_spend_merkle.push(padding_p2.clone());
            }
            while per_spend_current.len() < TRACE_HEIGHT {
                per_spend_current.push(anchor_f);
            }
            debug_assert_eq!(per_spend_merkle.len(), TRACE_HEIGHT);
            debug_assert_eq!(per_spend_current.len(), TRACE_HEIGHT);
            merkle_rows.push(per_spend_merkle);
            s_current_vals.push(per_spend_current);

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
                let cm_fe = poseidon2_cm_fe(&perm16, o.d, o.pk_d, o.ivk_commitment, o.value, o.rcm);
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
            // Global cols: fee + 32 one-hot Merkle row selectors.
            values.push(fee_f);
            for k in 0..MERKLE_DEPTH {
                let bit = if row_idx < MERKLE_DEPTH && row_idx == k {
                    1
                } else {
                    0
                };
                values.push(Goldilocks::from_u64(bit));
            }

            // Globally-shared Cm/OutCm (w=16) block:
            //   row i (i ∈ 0..n_s): spend i's claim-2 witness
            //   row 4+j (j ∈ 0..n_o): output j's claim-6 witness
            //   else: zero-input permutation
            if row_idx < n_s {
                values.extend_from_slice(&row0_spend_cm[row_idx]);
            } else if (4..4 + n_o).contains(&row_idx) {
                values.extend_from_slice(&row0_out_cm[row_idx - 4]);
            } else {
                values.extend_from_slice(&padding_p2_16);
            }

            // Globally-shared IvkCm/Nf (w=8) block:
            //   row i (i ∈ 0..n_s): spend i's claim-3 (IvkCm) witness
            //   row 4+i (i ∈ 0..n_s): spend i's claim-4 (Nf) witness
            //   else: zero-input permutation
            if row_idx < n_s {
                values.extend_from_slice(&row0_spend_ivkcm[row_idx]);
            } else if (4..4 + n_s).contains(&row_idx) {
                values.extend_from_slice(&row0_spend_nf[row_idx - 4]);
            } else {
                values.extend_from_slice(&padding_p2);
            }

            // Per-spend block: proxies + S_CURRENT + per-spend shared
            // Merkle P2 row-loop.
            for i in 0..n_s {
                values.extend_from_slice(&spend_proxies[i]);
                values.push(s_current_vals[i][row_idx]);
                values.extend_from_slice(&merkle_rows[i][row_idx]);
            }
            // Per-output block: proxies only (Cm moved to global block).
            for j in 0..n_o {
                values.extend_from_slice(&output_proxies[j]);
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
        let (left, right) = if bit == 0 {
            (current, sib)
        } else {
            (sib, current)
        };
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

/// Full-width nullifier computation per §4.3 step 4: `nf_i` occupies 4
/// Goldilocks elements (the first 4 limbs of the post-permutation state).
fn poseidon2_nf_full(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    nk: u64,
    cm: u64,
    pos: u64,
) -> [Goldilocks; 4] {
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
    state[0] = Goldilocks::from_u64(TAG_NF);
    state[1] = Goldilocks::from_u64(reduce_to_goldilocks(nk));
    state[2] = Goldilocks::from_u64(reduce_to_goldilocks(cm));
    state[3] = Goldilocks::from_u64(reduce_to_goldilocks(pos));
    perm.permute_mut(&mut state);
    [state[0], state[1], state[2], state[3]]
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
            poseidon2_merkle_path_root(&perm, s.leaf, s.pos, &s.merkle_path).as_canonical_u64();
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
                assert_eq!(
                    derive_shape_from_public_inputs_len(len).unwrap(),
                    (n_s, n_o)
                );
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
        assert_eq!(
            w44,
            GLOBAL_COLS + 4 * per_spend_cols() + 4 * per_output_cols()
        );
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
