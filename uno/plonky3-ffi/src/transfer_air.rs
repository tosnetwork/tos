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
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    default_goldilocks_poseidon2_16, default_goldilocks_poseidon2_8,
    GenericPoseidon2LinearLayersGoldilocks, Goldilocks, GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS,
    GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_16, GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{num_cols as p2_num_cols, Poseidon2Cols, RoundConstants};
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
    + POSEIDON2_COLS_PER_INSTANCE  // shared IvkCm / Nf (w=8) — claim 3/4
    + 3                              // anchor limbs 1..3 (Phase 4b-step1)
    + 1                              // anchor_proxy (Phase 4b-step2b)
    + 1;                             // anchor_limb0_real (Phase 4b-step2b)
const GCOL_FEE: usize = 0;
/// Base index of the 32 one-hot Merkle row-selector columns (§claim 1).
const GS_ROW_SEL0: usize = 1;
/// Base index of the shared Cm/OutCm width-16 Poseidon2 block
/// (K-air-col-step2 strategy b — claim 2/6 row-loop on rows 0..7).
const G_CM_SHARED_P2_16: usize = GS_ROW_SEL0 + MERKLE_DEPTH;
/// Base index of the shared IvkCm/Nf width-8 Poseidon2 block
/// (K-air-col-step2 strategy c — claim 3/4 row-loop on rows 0..7).
const G_IVKCM_NF_SHARED_P2_8: usize = G_CM_SHARED_P2_16 + POSEIDON2_COLS_PER_INSTANCE_16;
/// Phase 4b-step1: base index of anchor limbs 1..3 (3 global cols).
/// Holds the upper three u64 limbs of `witness.anchor_bytes[8..32]`,
/// bound via row-0 copy constraint to `PI[PI_ANCHOR + 1..4]`. Same
/// pattern as the rk / epk / filter_tag bindings in Phase 4a.
const G_ANCHOR_LIMB1: usize = G_IVKCM_NF_SHARED_P2_8 + POSEIDON2_COLS_PER_INSTANCE;
/// Phase 4b-step2b: global col holding `anchor_proxy` (the Merkle-walk
/// output from witness). The last-row Merkle-walk constraint
/// `S_CURRENT == AG_ANCHOR_PROXY_col` now binds the walk to this
/// trace-internal col instead of directly to `PI[PI_ANCHOR + 0]` —
/// decouples the Merkle derivation from the PI value, same pattern
/// as Phase 4b-step2a decoupled `O_CM_CLAIM` from `PI[cm + 0]`.
const G_ANCHOR_PROXY: usize = G_ANCHOR_LIMB1 + 3;
/// Phase 4b-step2b: global col holding `witness.anchor_bytes[0..8]`
/// as a u64 limb (mod p). Bound via row-0 copy constraint to
/// `PI[PI_ANCHOR + 0]`, matching C++'s
/// `pack_bits256_as_4_limbs(anchor)[0]`.
const G_ANCHOR_LIMB0_REAL: usize = G_ANCHOR_PROXY + 1;

/// u16-limb decomposition width for `value_i` / `value_j` (§4.2 claims
/// 5 & 7). Each value is committed as 4 × u16 limbs with the AIR
/// enforcing `value == Σ_k limb_k · 2^{16k}`; the per-limb range-check
/// `limb_k < 2^16` is discharged by a LogUp lookup against a preprocessed
/// 16-bit range table (M-P2 Phase 3b). Since
/// `p_Goldilocks = 2^64 − 2^32 + 1`, the extra high-bit combinations in
/// `[2^64 − 2^32 + 1, 2^64)` are unreachable by a single field element,
/// so 4×u16 decomp is exact on canonical inputs.
///
/// Phase 3b-step2 (this commit): swap 64 bit columns → 4 u16 limb columns.
/// The per-bit `b·(1−b) == 0` constraints are deleted here; the per-limb
/// `limb_k < 2^16` range-check is NOT enforced by this AIR yet — it lands
/// in Phase 3b-step3 via LogUp. Callers therefore see a temporarily
/// weaker soundness surface (values can violate u64 range and still
/// verify) until step3 is committed.
pub const VALUE_LIMBS_U16: usize = 4;

/// u64-limb decomposition width for `rk` / `epk` (Phase 4a field-
/// material binding). Each 32-byte Ristretto255 compressed pubkey is
/// split into 4 little-endian u64 limbs matching the C++ validator's
/// `encode_256` encoding used at `build_plonky3_public_inputs`.
/// Limbs are constant across trace rows (proxies-are-constant invariant).
pub const RK_EPK_LIMBS: usize = 4;

/// Per-spend proxy columns: leaf, d, value, ivk, ivk_commitment_claim,
/// pk_d, rcm, nk, pos (9 leading fields), plus 32 path-bit proxies, 32
/// sibling-hash proxies for the 32-level Merkle path (§2.3),
/// VALUE_LIMBS_U16 u16-limb columns for the u64 range-check on `value_i`
/// (§4.2 claim 5), and RK_EPK_LIMBS columns holding the 4-limb
/// decomposition of the spend's `rk_bytes` for the PI binding added in
/// Phase 4a.
pub const SPEND_PROXY_COLS: usize =
    9 + MERKLE_DEPTH + MERKLE_DEPTH + VALUE_LIMBS_U16 + RK_EPK_LIMBS;

/// Per-output proxy columns: cm_claim (Poseidon2-w=16 output, trace-
/// only after Phase 4b-step2a), d, pk_d, ivk_commitment, value, rcm (6
/// leading fields), VALUE_LIMBS_U16 u16-limb columns for the u64
/// range-check on `value_j` (§4.2 claim 7), RK_EPK_LIMBS columns
/// holding `epk_bytes` limbs, 1 column holding the u16 `filter_tag`
/// (Phase 4a), 3 columns for `cm_bytes[8..32]` upper limbs (Phase 4b-
/// step1), and 1 column for `cm_bytes[0..8]` limb 0 (Phase 4b-step2a)
/// — bound to `PI[pi_cm(j) + 0]` via row-0 copy-constraint, replacing
/// the previous `cm_claim == pi_cms[j]` binding.
pub const OUTPUT_PROXY_COLS: usize = 6 + VALUE_LIMBS_U16 + RK_EPK_LIMBS + 1 + 3 + 1;

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
/// Base index of the 4×u16 limb-decomposition columns for `value_i`
/// (claim 5). Phase 3b-step2: was `S_VALUE_BIT0` (64 bit columns).
const S_VALUE_LIMB0: usize = S_SIBLING0 + MERKLE_DEPTH;
/// Base index of the 4 u64-limb columns holding `rk_bytes` (Phase 4a).
const S_RK_LIMB0: usize = S_VALUE_LIMB0 + VALUE_LIMBS_U16;

// ---- Per-output column indices (within an output proxy block) ----
const O_CM_CLAIM: usize = 0;
const O_D: usize = 1;
const O_PK_D: usize = 2;
const O_IVK_COMMITMENT: usize = 3;
const O_VALUE: usize = 4;
const O_RCM: usize = 5;
/// Base index of the 4×u16 limb-decomposition columns for `value_j`
/// (claim 7). Phase 3b-step2: was `O_VALUE_BIT0` (64 bit columns).
const O_VALUE_LIMB0: usize = 6;
/// Base index of the 4 u64-limb columns holding `epk_bytes` (Phase 4a).
const O_EPK_LIMB0: usize = O_VALUE_LIMB0 + VALUE_LIMBS_U16;
/// Single column holding the u16 `filter_tag` (Phase 4a).
const O_FILTER_TAG: usize = O_EPK_LIMB0 + RK_EPK_LIMBS;
/// Base index of the 3 u64-limb columns holding `cm_bytes[8..32]`
/// (Phase 4b-step1). Bound to PI limbs 1..3 via row-0 copy-constraint.
const O_CM_LIMB1: usize = O_FILTER_TAG + 1;
/// Single column holding `cm_bytes[0..8]` as a u64 limb (Phase 4b-
/// step2a). Bound to `PI[pi_cm(j) + 0]` via row-0 copy-constraint,
/// replacing the prior `O_CM_CLAIM`-to-PI binding. `O_CM_CLAIM` still
/// exists and is still constrained to the Poseidon2-w=16 output via
/// the shared wide block on rows 0..7, but it no longer directly
/// drives the PI value — this decoupling is what achieves byte parity
/// with C++'s `encode_256(cm_bytes)[0]`, at the documented cost of
/// weakening claim-2's on-PI soundness.
const O_CM_LIMB0_REAL: usize = O_CM_LIMB1 + 3;

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

// `PI_SCHEME` / `PI_CHAIN` / `PI_EXPIRY` are populated by
// `public_inputs()` but not individually referenced by the AIR today
// (the proxy AIR does not bind header scalars — they are consensus-
// checked at the block-level tx_hash). Silence the unused-const lint.
#[allow(dead_code)]
const _UNUSED_PI: (usize, usize, usize) = (PI_SCHEME, PI_CHAIN, PI_EXPIRY);

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
    /// Per-AIR-local counter for `LookupAir::add_lookup_columns` column
    /// allocations. Always starts at 0 in `new()` / `default()`; mutated
    /// only when `LookupAir::get_lookups` calls register_lookup. The
    /// field is not part of the AIR's semantic identity — two values
    /// that differ only in `num_lookups` represent the same AIR.
    num_lookups: usize,
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
            num_lookups: 0,
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

// (round-constant adapter fns removed in M-P2 Phase 2 — see note above on
//  the handwritten Poseidon2 eval helpers that were deleted together with
//  them. Round constants now flow through upstream `Poseidon2Air`'s
//  `RoundConstants` via the `p2_air_8` / `p2_air_16` OnceLock singletons.
//  `RoundConstants::new` consumes `p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_*`
//  directly — the per-round `from_u64` adapter is no longer needed.)

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

    /// Declare all main-trace columns as next-row-accessed. The AIR's
    /// `eval` reads `main.next_slice()` for the §4.2 "proxies are
    /// constant across rows" transition constraint (every proxy col is
    /// checked against the next row). In the pre-batch-stark uni-stark
    /// pipeline the trace was always opened at both zeta and zeta*g, so
    /// this declaration was implicit. `p3_batch_stark` gates next-row
    /// opening on this method's non-empty return — returning `vec![]`
    /// (the default) means the verifier sees zeroed-out next-row data
    /// while the prover's quotient used the real values, causing an
    /// `OodEvaluationMismatch`. Declaring every column keeps the
    /// behavior honest for both provers.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..air_width(self.n_spends, self.n_outputs)).collect()
    }
}

/// `LookupAir` impl — M-P2 Phase 3b-step3 reader side.
///
/// Registers a single `Kind::Global("u16_range")` lookup whose
/// `Direction::Receive` input list holds **all** u16 limb columns from
/// the per-spend and per-output proxy blocks (4 limbs/value × n_spends
/// spends × 1 value-per-spend  +  4 limbs/value × n_outputs outputs ×
/// 1 value-per-output = 4·(n_spends + n_outputs) receives at
/// multiplicity 1).
///
/// The matching `Direction::Send` side lives in `range16_air` under the
/// identical interaction name
/// [`range16_air::U16_RANGE_LOOKUP_NAME`].
///
/// NB on trace rows: the LogUp gadget evaluates each `Lookup` on every
/// row of this AIR's main trace (64 rows). Because the u16 limb columns
/// are "constant across rows" per the §4.2 proxies-are-constant
/// transition invariant, each limb value is received 64× per prove.
/// `MvpBatchProver::prove` bakes this row-count into the multiplicity
/// column it feeds to `Range16Air::build_main_trace` so the global sum
/// balances out to zero in the cross-AIR cumulative check.
impl<F: p3_field::Field> p3_lookup::LookupAir<F> for MvpTransferAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let idx = self.num_lookups;
        self.num_lookups += 1;
        vec![idx]
    }

    fn get_lookups(&mut self) -> Vec<p3_lookup::lookup_traits::Lookup<F>> {
        self.num_lookups = 0;

        let width = air_width(self.n_spends, self.n_outputs);
        let num_pvs = air_num_public_values(self.n_spends, self.n_outputs);

        let symbolic = p3_air::symbolic::SymbolicAirBuilder::<F>::new(
            p3_air::symbolic::AirLayout {
                main_width: width,
                num_public_values: num_pvs,
                ..Default::default()
            },
        );
        let main_window = symbolic.main();
        let main_local = main_window.current_slice();

        // Register 4·(n_s + n_o) SEPARATE Kind::Global lookups — one per
        // u16 limb column, each with a single-element single-input tuple.
        //
        // Why not one lookup with 4·(n_s+n_o) input tuples? A bundled
        // single-lookup registration would compile and the prover would
        // produce a proof, but verify trips `OodEvaluationMismatch`:
        // bundling N tuples into one lookup raises the lookup
        // constraint's polynomial degree to N+ (denominator product of
        // N linear factors), which appears to mis-interact with the
        // shape-dependent symbolic-width computation in
        // `batch-stark::symbolic` for wide AIRs. Splitting into N
        // single-tuple lookups keeps each constraint at degree 2 —
        // the well-trodden LogUp case — at the cost of N aux cols in
        // the permutation trace.
        //
        // All N lookups share the same `Kind::Global("u16_range")`
        // name, so they all consume from the same Range16Air Send.
        let one = p3_air::symbolic::SymbolicExpression::Leaf(
            p3_air::BaseLeaf::Constant(F::ONE),
        );
        let mut lookups: Vec<p3_lookup::lookup_traits::Lookup<F>> =
            Vec::with_capacity(4 * (self.n_spends + self.n_outputs));

        let name = || {
            p3_lookup::lookup_traits::Kind::Global(String::from(
                crate::range16_air::U16_RANGE_LOOKUP_NAME,
            ))
        };

        for i in 0..self.n_spends {
            for k in 0..VALUE_LIMBS_U16 {
                let col = spend_proxy_offset(i) + S_VALUE_LIMB0 + k;
                let limb = main_local[col];
                let inputs = vec![(
                    vec![limb.into()],
                    one.clone(),
                    p3_lookup::lookup_traits::Direction::Receive,
                )];
                lookups.push(p3_lookup::LookupAir::register_lookup(self, name(), &inputs));
            }
        }
        for j in 0..self.n_outputs {
            for k in 0..VALUE_LIMBS_U16 {
                let col = output_proxy_offset(self.n_spends, j) + O_VALUE_LIMB0 + k;
                let limb = main_local[col];
                let inputs = vec![(
                    vec![limb.into()],
                    one.clone(),
                    p3_lookup::lookup_traits::Direction::Receive,
                )];
                lookups.push(p3_lookup::LookupAir::register_lookup(self, name(), &inputs));
            }
        }
        lookups
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
        // `pi_anchor0` removed in Phase 4b-step2b — the row-0 binding
        // for `PI[PI_ANCHOR]` now reads `pis_vec[PI_ANCHOR]` inline at
        // the anchor-limb block, and the last-row Merkle-walk binding
        // references `G_ANCHOR_PROXY` instead.
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

                // Claim 5: u64 range-check on `value_i` via 4×u16 limbs.
                // Phase 3b-step2: enforce `value = Σ_k limb_k · 2^{16k}`.
                // The per-limb `limb_k < 2^16` check lands in step3 via
                // LogUp against a preprocessed 16-bit range table — NOT
                // enforced by this AIR yet. (Temporary soundness gap.)
                let mut value_recon: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                for k in 0..VALUE_LIMBS_U16 {
                    let limb: AB::Var = spend_col(local_slice, i, S_VALUE_LIMB0 + k);
                    let weight = AB::F::from_u64(1u64 << (16 * k));
                    value_recon = value_recon + AB::Expr::from(weight) * limb.into();
                }
                first.assert_eq(value.into(), value_recon);
            }

            // Per-output row-0 bindings (claim 7 bit-decomp of value_j,
            // and the cm limb-0 PI binding).
            for j in 0..self.n_outputs {
                let value_out = output_col(local_slice, self.n_spends, j, O_VALUE);

                // Phase 4b-step2a: bind `PI[pi_cm(j) + 0]` to the new
                // witness-bytes col `O_CM_LIMB0_REAL` (= cm_bytes[0..8]
                // as u64 mod p) instead of the Poseidon2-derived
                // `O_CM_CLAIM`. `O_CM_CLAIM` still participates in the
                // shared-wide-block claim-6 `cm_claim = Poseidon2
                // (proxies)` constraint on row 4+j, so trace integrity
                // is preserved, but the PI value now comes from
                // `witness.cm_bytes[0..8]` — matching C++'s
                // `encode_256(cm_bytes)[0]`. See the module docstring
                // for the documented soundness trade-off.
                let cm_limb0_real: AB::Var =
                    output_col(local_slice, self.n_spends, j, O_CM_LIMB0_REAL);
                first.assert_eq(cm_limb0_real, pi_cms[j]);

                // Claim 7: u64 range-check on `value_j` via 4×u16 limbs.
                // Phase 3b-step2: see claim-5 comment above. Range-check
                // deferred to step3 LogUp.
                let mut value_recon: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                for k in 0..VALUE_LIMBS_U16 {
                    let limb: AB::Var =
                        output_col(local_slice, self.n_spends, j, O_VALUE_LIMB0 + k);
                    let weight = AB::F::from_u64(1u64 << (16 * k));
                    value_recon = value_recon + AB::Expr::from(weight) * limb.into();
                }
                first.assert_eq(value_out.into(), value_recon);
            }

            // Phase 4a: per-spend PI binding for `rk_bytes` (4 u64
            // limbs). Copy-constraint `PI[pi_rk(i) + k] == trace_col[
            // S_RK_LIMB0 + k]` for each spend i, limb k ∈ 0..4. Cols
            // are constant across rows (proxies-are-constant), so the
            // row-0 assertion suffices to bind PI for the full trace.
            for i in 0..self.n_spends {
                for k in 0..RK_EPK_LIMBS {
                    let rk_col: AB::Var = spend_col(local_slice, i, S_RK_LIMB0 + k);
                    let pi_rk_slot = pis_vec[pi_rk(i) + k];
                    first.assert_eq(rk_col, pi_rk_slot);
                }
            }

            // Phase 4a: per-output PI binding for `epk_bytes` (4 u64
            // limbs) + `filter_tag` (1 u16). Same rationale as the rk
            // binding above.
            for j in 0..self.n_outputs {
                for k in 0..RK_EPK_LIMBS {
                    let epk_col: AB::Var =
                        output_col(local_slice, self.n_spends, j, O_EPK_LIMB0 + k);
                    let pi_epk_slot = pis_vec[pi_epk(self.n_spends, j) + k];
                    first.assert_eq(epk_col, pi_epk_slot);
                }
                let ft_col: AB::Var = output_col(local_slice, self.n_spends, j, O_FILTER_TAG);
                let pi_ft_slot = pis_vec[pi_filter_tag(self.n_spends, j)];
                first.assert_eq(ft_col, pi_ft_slot);
            }

            // Phase 4b-step2b: anchor limb 0 PI binding from
            // witness bytes. Was indirectly bound via last-row
            // `S_CURRENT == pi_anchor0`; that binding now lands on
            // `G_ANCHOR_PROXY` (trace-only, see the `last.assert_eq`
            // in the row-gated section below). PI[PI_ANCHOR + 0] is
            // now bound to `G_ANCHOR_LIMB0_REAL = anchor_bytes[0..8]`.
            let anchor_limb0_real: AB::Var = local_slice[G_ANCHOR_LIMB0_REAL];
            first.assert_eq(anchor_limb0_real, pis_vec[PI_ANCHOR]);

            // Phase 4b-step1: anchor limbs 1..3 PI binding. The three
            // upper limbs live in global cols
            // `G_ANCHOR_LIMB1..G_ANCHOR_LIMB1+3` and are consensus-
            // bound to `witness.anchor_bytes[8..32]`.
            for k in 1..4 {
                let anchor_limb: AB::Var = local_slice[G_ANCHOR_LIMB1 + (k - 1)];
                let pi_anchor_slot = pis_vec[PI_ANCHOR + k];
                first.assert_eq(anchor_limb, pi_anchor_slot);
            }

            // Phase 4b-step1: cm limbs 1..3 PI binding per output. Limb
            // 0 is bound via `O_CM_CLAIM == pi_cms[j]` earlier in this
            // block (claim 6) and `cm_claim == Poseidon2-w=16(...)` via
            // the shared wide block on rows 0..7.
            for j in 0..self.n_outputs {
                for k in 1..4 {
                    let cm_upper: AB::Var = output_col(
                        local_slice,
                        self.n_spends,
                        j,
                        O_CM_LIMB1 + (k - 1),
                    );
                    let pi_cm_slot = pis_vec[pi_cm(self.n_spends, j) + k];
                    first.assert_eq(cm_upper, pi_cm_slot);
                }
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
            let anchor_proxy_col = local_slice[G_ANCHOR_PROXY];
            for i in 0..self.n_spends {
                // Phase 4b-step2b: Merkle walk output == anchor_proxy
                // trace col (was pi_anchor0). Decouples the Merkle
                // derivation from the PI value. `PI[PI_ANCHOR + 0]` is
                // bound separately below to
                // `G_ANCHOR_LIMB0_REAL = witness.anchor_bytes[0..8]`.
                last.assert_eq(
                    local_slice[spend_var_offset(i) + S_CURRENT],
                    anchor_proxy_col,
                );
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
// Poseidon2 constraint evaluation (M-P2 Phase 2 — delegated to upstream)
// ---------------------------------------------------------------------------
//
// **Phase 2 swap (2026-04-22)**: we used to carry ~180 LOC of handwritten
// round-eval helpers (`eval_full_round`, `eval_partial_round`, `eval_sbox`,
// plus round-constant adapter fns) that "mirrored upstream byte-for-byte"
// because `p3_poseidon2_air::eval` was `pub(crate)` at Plonky3 v0.5.1.
// The vendored `third-party/plonky3-uno` was patched to `pub`-export
// `eval` (1-char delta in `poseidon2-air/src/air.rs`); we now delegate
// to the upstream implementation directly. Round constants come from
// `p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_{8,16}_*` (decision #42)
// identically to before; the `Poseidon2Air` singletons cache the
// constructed `RoundConstants` once per process.

type Poseidon2Air8 = p3_poseidon2_air::Poseidon2Air<
    Goldilocks,
    GenericPoseidon2LinearLayersGoldilocks,
    POSEIDON2_WIDTH,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS,
>;

type Poseidon2Air16 = p3_poseidon2_air::Poseidon2Air<
    Goldilocks,
    GenericPoseidon2LinearLayersGoldilocks,
    POSEIDON2_WIDTH_16,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS_16,
>;

fn p2_air_8() -> &'static Poseidon2Air8 {
    use std::sync::OnceLock;
    static AIR: OnceLock<Poseidon2Air8> = OnceLock::new();
    AIR.get_or_init(|| {
        Poseidon2Air8::new(RoundConstants::new(
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
        ))
    })
}

fn p2_air_16() -> &'static Poseidon2Air16 {
    use std::sync::OnceLock;
    static AIR: OnceLock<Poseidon2Air16> = OnceLock::new();
    AIR.get_or_init(|| {
        Poseidon2Air16::new(RoundConstants::new(
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_INITIAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_INTERNAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_FINAL,
        ))
    })
}

pub(crate) fn eval_poseidon2<AB>(builder: &mut AB, local: &P2Cols<AB::Var>)
where
    AB: AirBuilder<F = Goldilocks>,
{
    p3_poseidon2_air::eval::<
        AB,
        GenericPoseidon2LinearLayersGoldilocks,
        POSEIDON2_WIDTH,
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
        POSEIDON2_HALF_FULL_ROUNDS,
        POSEIDON2_PARTIAL_ROUNDS,
    >(p2_air_8(), builder, local);
}

fn eval_poseidon2_16<AB>(builder: &mut AB, local: &P2Cols16<AB::Var>)
where
    AB: AirBuilder<F = Goldilocks>,
{
    p3_poseidon2_air::eval::<
        AB,
        GenericPoseidon2LinearLayersGoldilocks,
        POSEIDON2_WIDTH_16,
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
        POSEIDON2_HALF_FULL_ROUNDS,
        POSEIDON2_PARTIAL_ROUNDS_16,
    >(p2_air_16(), builder, local);
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
    /// Raw 32-byte `ivk` (Ristretto255 scalar). Phase 4b-step3-step0
    /// widened from `u64` proxy so tosctl can pass the real viewing
    /// key through. The AIR in its current (pre-step3) shape still
    /// derives a u64 proxy internally via
    /// `u64::from_le_bytes(ivk[0..8].try_into().unwrap())` — claim 2 /
    /// 3 semantics are unchanged until step 1+ lifts cm / nf to
    /// 4-fe output.
    pub ivk: [u8; 32],
    /// Raw 32-byte `pk_d` (Ristretto255 compressed point). See `ivk`
    /// doc for the same step0 widening note.
    pub pk_d: [u8; 32],
    /// Raw 32-byte note randomness `rcm`. Per-note value, not the
    /// whole address.
    pub rcm: [u8; 32],
    /// Raw 32-byte nullifier key `nk` (from the spender's FVK).
    pub nk: [u8; 32],
    /// Leaf position within the depth-32 commitment tree. Low bit is the
    /// level-0 path bit (§2.3, matching `commitment-tree.{h,cpp}`). Must
    /// satisfy `pos < 2^MERKLE_DEPTH` (upper bits in `pos` are discarded
    /// when the witness is encoded because only 32 path bits are stored).
    pub pos: u64,
    /// 32-level Merkle path: each entry is the sibling hash proxy
    /// (single Goldilocks fe) at level `k`. Level 0 is the first layer
    /// above the leaf.
    pub merkle_path: [u64; MERKLE_DEPTH],
    /// Raw 32-byte `rk` (compressed Ristretto255 spend-auth pubkey, §4.1).
    /// Consensus-binding: C++ `build_plonky3_public_inputs` encodes this
    /// via `encode_256` → 4 Goldilocks limbs. V1-3c-round-8 (档1) added
    /// this field so Rust-side PI bytes match the C++ build byte-for-byte
    /// (previously the 4 rk slots were all-zero, breaking STARK verify
    /// on a real validator). The AIR proxy claims do not bind these
    /// slots; the constraint is satisfied solely by consensus-level
    /// preimage equality via §4.1 tx_hash.
    pub rk_bytes: [u8; 32],
}

/// Single-output witness.
#[derive(Debug, Clone)]
pub struct OutputWitness {
    /// Raw diversifier `d_j` in 32-byte representation. The real
    /// diversifier is 11 bytes; tosctl pads `bytes[0..11]` with the
    /// real material and leaves `bytes[11..32]` zero. Phase 4b-step3-
    /// step0 widened from `u64` proxy so tosctl can pass real
    /// material through. The AIR (pre-step3) still derives a u64
    /// proxy internally via the first 8 bytes.
    pub d: [u8; 32],
    /// Raw 32-byte recipient `pk_d_j`.
    pub pk_d: [u8; 32],
    /// Raw 32-byte recipient `ivk_commitment_j`.
    pub ivk_commitment: [u8; 32],
    /// Output value (u64, Goldilocks-fits).
    pub value: u64,
    /// Raw 32-byte per-output randomness `rcm_j`.
    pub rcm: [u8; 32],
    /// Raw 32-byte `cm_j` (note commitment, §4.1). Used to populate all
    /// 4 PI limbs via `encode_256`; the current proxy AIR binds only the
    /// low-limb equality (`pi_cm[j] == cm_fe_computed_from_witness`).
    /// V1-3c-round-8 (档1) — see `rk_bytes` note on SpendWitness.
    pub cm_bytes: [u8; 32],
    /// Raw 32-byte `epk_j` (compressed Ristretto255 ephemeral pubkey, §4.1).
    pub epk_bytes: [u8; 32],
    /// 16-bit compact filter tag (§2.8). Becomes 1 PI element.
    pub filter_tag: u16,
}

/// Full Transfer witness for 1..4 spends × 1..4 outputs + fee.
#[derive(Debug, Clone)]
pub struct MvpWitness {
    /// `scheme_id` (§4.1, v1 = 0x01). Goes into PI position 0.
    pub scheme_id: u8,
    /// `chain_id` (§4.1, mainnet 0x554E4F4D "UNOM" / testnet 0x554E4F54
    /// "UNOT"). Goes into PI position 1.
    pub chain_id: u32,
    /// `expiry_block` (§4.1, §4.3 step 1.3). Goes into PI position 2.
    pub expiry_block: u64,
    /// Transaction fee, public input.
    pub fee: u64,
    /// Spend descriptions (len ∈ [1, 4]).
    pub spends: Vec<SpendWitness>,
    /// Output descriptions (len ∈ [1, 4]).
    pub outputs: Vec<OutputWitness>,
    /// Shared anchor proxy (limb 0 of the 256-bit anchor). Derived by the
    /// constructor from the first spend's Merkle step so honest witnesses
    /// are self-consistent. The AIR binds `pi_anchor[0] == anchor_proxy`.
    pub anchor_proxy: u64,
    /// Raw 32-byte anchor (§4.1). PI slots 4..7 are the 4 `encode_256`
    /// limbs of these bytes. For self-consistency callers should arrange
    /// `anchor_bytes[0..8]` = `anchor_proxy.to_le_bytes()`; the AIR only
    /// enforces the low-limb equality, so higher limbs are free.
    /// V1-3c-round-8 (档1) — see `rk_bytes` note on SpendWitness.
    pub anchor_bytes: [u8; 32],
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
            // Phase 4b-step3-step0: widened fields take `[u8; 32]`.
            // For this deterministic_valid test fixture, project the
            // legacy u64 proxy into `bytes[0..8]` with zero padding;
            // the AIR reads `first_u64_proxy(&field)` internally, so
            // the derived u64 is identical to pre-step0 behaviour.
            let mut ivk_bytes = [0u8; 32];
            ivk_bytes[0..8].copy_from_slice(&shared_ivk.to_le_bytes());
            let mut pk_d_bytes = [0u8; 32];
            pk_d_bytes[0..8].copy_from_slice(&shared_pk_d.to_le_bytes());
            let mut rcm_bytes = [0u8; 32];
            rcm_bytes[0..8].copy_from_slice(&shared_rcm.to_le_bytes());
            let mut nk_bytes = [0u8; 32];
            nk_bytes[0..8].copy_from_slice(&nk.to_le_bytes());
            spends.push(SpendWitness {
                leaf: shared_leaf,
                d: d_word.to_le_bytes(),
                value: v_per_spend,
                ivk: ivk_bytes,
                pk_d: pk_d_bytes,
                rcm: rcm_bytes,
                nk: nk_bytes,
                pos: shared_pos,
                merkle_path: shared_path,
                rk_bytes: [0u8; 32],
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
            // Synthesize cm_bytes from the Poseidon2 output so the AIR's
            // low-limb binding holds when `public_inputs()` re-derives
            // `cm_limb0` via `poseidon2_cm_fe`. `deterministic_valid` is a
            // test fixture; it doesn't carry real 32-byte cm material, so
            // we project `cm_limb0` into `cm_bytes[0..8]` and leave the
            // rest zero. Real production wallets populate all 32 bytes.
            let cm_limb0 =
                poseidon2_cm_fe(&perm16, d, pk_d, ivk_commitment, value, rcm).as_canonical_u64();
            let mut cm_bytes = [0u8; 32];
            cm_bytes[0..8].copy_from_slice(&cm_limb0.to_le_bytes());
            // Phase 4b-step3-step0: widen u64 proxies to [u8; 32] with
            // 8-byte low-limb projection + 24-byte zero padding (test
            // fixture convention; real tosctl witnesses carry full
            // 32-byte material).
            let mut d_bytes = [0u8; 32];
            d_bytes[0..8].copy_from_slice(&d.to_le_bytes());
            let mut pk_d_bytes = [0u8; 32];
            pk_d_bytes[0..8].copy_from_slice(&pk_d.to_le_bytes());
            let mut ivk_commitment_bytes = [0u8; 32];
            ivk_commitment_bytes[0..8].copy_from_slice(&ivk_commitment.to_le_bytes());
            let mut rcm_bytes = [0u8; 32];
            rcm_bytes[0..8].copy_from_slice(&rcm.to_le_bytes());
            outputs.push(OutputWitness {
                d: d_bytes,
                pk_d: pk_d_bytes,
                ivk_commitment: ivk_commitment_bytes,
                value,
                rcm: rcm_bytes,
                cm_bytes,
                epk_bytes: [0u8; 32],
                filter_tag: 0,
            });
        }

        // Same treatment for anchor_bytes: project `anchor_proxy` (= the
        // limb the AIR binds) into the low 8 bytes of anchor_bytes.
        let mut anchor_bytes = [0u8; 32];
        anchor_bytes[0..8].copy_from_slice(&shared_anchor.to_le_bytes());

        Self {
            scheme_id: 0x01,
            chain_id: CHAIN_ID_TEST,
            expiry_block: EXPIRY_BLOCK_TEST,
            fee,
            spends,
            outputs,
            anchor_proxy: shared_anchor,
            anchor_bytes,
        }
    }

    /// Wire-encode for FFI.
    ///
    /// Legacy layout (pre-档1):
    ///   `u8 n_s || u8 n_o || u64 fee ||`
    ///   `(u64 leaf || [8 B] d || u64 value || u64 ivk || u64 pk_d || u64 rcm
    ///    || u64 nk || u64 pos || u64 path[0..32]) × n_s ||`
    ///   `(u64 d || u64 pk_d || u64 ivk_commitment || u64 value || u64 rcm) × n_o ||`
    ///   `u64 anchor_proxy`.
    ///
    /// V1-3c-round-8 (档1) extended layout (this function):
    ///   `[32 B] anchor_bytes || u8 scheme_id || u32 chain_id || u64 expiry_block`  (trailer)
    ///   Each spend: `[32 B] rk_bytes` appended (stride +32).
    ///   Each output: `[32 B] cm_bytes || [32 B] epk_bytes || u16 filter_tag` appended (stride +66).
    ///
    /// M-P2 Phase 4b-step3-step0 widening (this revision): four spend
    /// fields (`ivk`, `pk_d`, `rcm`, `nk`) and four output fields (`d`,
    /// `pk_d`, `ivk_commitment`, `rcm`) move from `u64` (8 bytes each)
    /// to `[u8; 32]` (32 bytes each) so tosctl can pass real address
    /// material through instead of digest-reduced proxies. The AIR
    /// itself is unchanged in this commit — trace-gen extracts a u64
    /// proxy from `field[0..8]` (little-endian) at every existing
    /// Poseidon2 / Merkle call site.
    ///
    /// Per-spend bytes: `leaf(8) + d(8) + value(8) + pos(8) +
    ///   4·32 (ivk,pk_d,rcm,nk) + 8·MERKLE_DEPTH + 32 (rk_bytes) =
    ///   32 + 128 + 256 + 32 = 448 bytes` (was 352 pre-step0).
    /// Per-output bytes: `4·32 (d,pk_d,ivk_cm,rcm) + value(8) + cm(32)
    ///   + epk(32) + filter_tag(2) = 128 + 8 + 64 + 2 = 202 bytes`
    ///   (was 106 pre-step0).
    /// Trailer: `8 (anchor_proxy) + 32 (anchor_bytes) + 1 + 4 + 8 = 53 bytes`.
    /// Byte length: `10 (n_s+n_o+fee) + 448·n_s + 202·n_o + 53`.
    ///
    /// The extended layout is backwards-incompatible with the pre-step0
    /// callers; callers inside this crate and `tosctl/uno` are updated
    /// atomically. `decode()` enforces the new length. Wire blob is
    /// transient tosctl → Rust-prover FFI only (no C++ consumer;
    /// confirmed by the pre-commit Explore agent audit).
    pub fn encode(&self) -> Vec<u8> {
        // Per-spend: leaf(8) + d(8) + value(8) + ivk(32) + pk_d(32)
        //          + rcm(32) + nk(32) + pos(8) + path(8*MERKLE_DEPTH)
        //          + rk_bytes(32) = 40 + 128 + 8 + 256 + 32 = 464.
        const PER_SPEND: usize = 32 + 4 * 32 + 8 * MERKLE_DEPTH + 32;
        // Per-output: d(32) + pk_d(32) + ivk_cm(32) + value(8) + rcm(32)
        //           + cm(32) + epk(32) + filter_tag(2) = 202.
        const PER_OUTPUT: usize = 4 * 32 + 8 + 32 + 32 + 2;
        const HEAD: usize = 10;
        const TAIL: usize = 8 + 32 + 1 + 4 + 8;
        let mut out = Vec::with_capacity(
            HEAD + PER_SPEND * self.spends.len() + PER_OUTPUT * self.outputs.len() + TAIL,
        );
        out.push(self.spends.len() as u8);
        out.push(self.outputs.len() as u8);
        out.extend_from_slice(&self.fee.to_le_bytes());
        for s in &self.spends {
            out.extend_from_slice(&s.leaf.to_le_bytes());
            out.extend_from_slice(&s.d);
            out.extend_from_slice(&s.value.to_le_bytes());
            out.extend_from_slice(&s.ivk);
            out.extend_from_slice(&s.pk_d);
            out.extend_from_slice(&s.rcm);
            out.extend_from_slice(&s.nk);
            out.extend_from_slice(&s.pos.to_le_bytes());
            for sib in &s.merkle_path {
                out.extend_from_slice(&sib.to_le_bytes());
            }
            out.extend_from_slice(&s.rk_bytes);
        }
        for o in &self.outputs {
            out.extend_from_slice(&o.d);
            out.extend_from_slice(&o.pk_d);
            out.extend_from_slice(&o.ivk_commitment);
            out.extend_from_slice(&o.value.to_le_bytes());
            out.extend_from_slice(&o.rcm);
            out.extend_from_slice(&o.cm_bytes);
            out.extend_from_slice(&o.epk_bytes);
            out.extend_from_slice(&o.filter_tag.to_le_bytes());
        }
        out.extend_from_slice(&self.anchor_proxy.to_le_bytes());
        out.extend_from_slice(&self.anchor_bytes);
        out.push(self.scheme_id);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.expiry_block.to_le_bytes());
        out
    }

    /// Decode a witness from the wire format (档1 extended layout —
    /// see `encode()` doc for the field order).
    pub fn decode(bytes: &[u8]) -> Result<Self, Plonky3Status> {
        const HEAD: usize = 10;
        const TAIL: usize = 8 + 32 + 1 + 4 + 8;
        // Must match `encode()` — see step0 widening doc there.
        const PER_SPEND: usize = 32 + 4 * 32 + 8 * MERKLE_DEPTH + 32;
        const PER_OUTPUT: usize = 4 * 32 + 8 + 32 + 32 + 2;
        if bytes.len() < HEAD + TAIL {
            return Err(Plonky3Status::WitnessInvalid);
        }
        let n_s = bytes[0] as usize;
        let n_o = bytes[1] as usize;
        if n_s < MIN_SPENDS || n_s > MAX_SPENDS || n_o < MIN_OUTPUTS || n_o > MAX_OUTPUTS {
            return Err(Plonky3Status::WitnessInvalid);
        }
        let want = HEAD + PER_SPEND * n_s + PER_OUTPUT * n_o + TAIL;
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
            let mut ivk = [0u8; 32];
            ivk.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut pk_d = [0u8; 32];
            pk_d.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut rcm = [0u8; 32];
            rcm.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut nk = [0u8; 32];
            nk.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
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
            let mut rk_bytes = [0u8; 32];
            rk_bytes.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
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
                rk_bytes,
            });
        }
        let mut outputs = Vec::with_capacity(n_o);
        for _ in 0..n_o {
            let mut d = [0u8; 32];
            d.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut pk_d = [0u8; 32];
            pk_d.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut ivk_commitment = [0u8; 32];
            ivk_commitment.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let value = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            if value >= GOLDILOCKS_P {
                return Err(Plonky3Status::WitnessInvalid);
            }
            let mut rcm = [0u8; 32];
            rcm.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut cm_bytes = [0u8; 32];
            cm_bytes.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut epk_bytes = [0u8; 32];
            epk_bytes.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let filter_tag = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
            off += 2;
            outputs.push(OutputWitness {
                d,
                pk_d,
                ivk_commitment,
                value,
                rcm,
                cm_bytes,
                epk_bytes,
                filter_tag,
            });
        }
        let anchor_proxy = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let mut anchor_bytes = [0u8; 32];
        anchor_bytes.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let scheme_id = bytes[off];
        off += 1;
        let chain_id = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        let expiry_block = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        debug_assert_eq!(off, bytes.len());

        Ok(Self {
            scheme_id,
            chain_id,
            expiry_block,
            fee,
            spends,
            outputs,
            anchor_proxy,
            anchor_bytes,
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
    /// Layout (per-element 8 B LE Goldilocks):
    /// ```text
    ///   [scheme_id, chain_id, expiry_block, fee]          (4 header scalars)
    ///   [anchor as 4 limbs — limb 0 = anchor_proxy]       (4 anchor limbs)
    ///   for each spend i:
    ///     [nf_i via 4-limb Poseidon2 nullifier]           (4 nf limbs)
    ///     [rk_i as 4 limbs — all zero in proxy AIR]       (4 rk limbs)
    ///   for each output j:
    ///     [cm_j via 1-limb proxy + 3 zeros]               (4 cm limbs)
    ///     [epk_j as 4 limbs — all zero in proxy AIR]      (4 epk limbs)
    ///     [filter_tag_j as u16 → 1 limb — zero in proxy]  (1 filter_tag)
    /// ```
    ///
    /// **V1-3c-round-8 (档1, 2026-04-22)**: this is a partial fix. The
    /// header scalars `scheme_id` / `chain_id` / `expiry_block` are now
    /// threaded from the witness (no more hardcoded `CHAIN_ID_TEST` /
    /// `EXPIRY_BLOCK_TEST`), which is the subset of PI slots that the
    /// proxy AIR does not constrain and therefore can be safely pinned
    /// to real values. The 256-bit slots (anchor, nf, cm, rk, epk,
    /// filter_tag) remain proxy-derived:
    ///
    /// * `anchor[0]` is bound by the AIR to `anchor_proxy` (derived via
    ///   the depth-32 Merkle walk over the witness). Setting it to
    ///   `encode_256(real_anchor)[0]` would break the AIR constraint
    ///   (real anchor ≠ proxy anchor under the current u64-proxy AIR).
    /// * Same for `cm[0]` (AIR-bound to `poseidon2_cm_fe(witness)`) and
    ///   `nf[0..4]` (AIR-bound to `poseidon2_nf_full(witness)`).
    /// * `rk`, `epk`, `filter_tag` are not AIR-bound but stay at zero
    ///   in this pass to keep wallet↔validator PI alignment self-
    ///   consistent with the proxy anchor/cm/nf; C++ validator produces
    ///   real values at those slots, so full byte parity is still a
    ///   **M-P2** responsibility (real 32-byte field-material AIR).
    ///
    /// **档1 net effect for v1 launch**: closes the hardcoded-constant
    /// hazard for `scheme_id` / `chain_id` / `expiry_block`. Full
    /// Rust-prover ↔ C++ validator STARK verify parity still requires
    /// M-P2 (see `doc/uno-workchain.md §4.1` proxy-AIR notes).
    pub fn public_inputs(&self) -> Vec<Goldilocks> {
        let n_s = self.spends.len();
        let n_o = self.outputs.len();
        let mut out = Vec::with_capacity(air_num_public_values(n_s, n_o));

        out.push(Goldilocks::from_u64(self.scheme_id as u64));
        out.push(Goldilocks::from_u64(self.chain_id as u64));
        out.push(Goldilocks::from_u64(reduce_to_goldilocks(
            self.expiry_block,
        )));
        out.push(Goldilocks::from_u64(reduce_to_goldilocks(self.fee)));

        // anchor: Phase 4b-step2b — all 4 limbs now come from
        // witness.anchor_bytes[k*8..(k+1)*8] as u64 (mod p). The
        // Merkle-walk constraint (`last_row: S_CURRENT ==
        // G_ANCHOR_PROXY` per spend) still proves the walk lands on
        // `anchor_proxy` internally, but `PI[PI_ANCHOR + k]` is now
        // bound via row-0 copy-constraint to
        // `G_ANCHOR_LIMB{0_REAL,1,2,3}`. Matches C++'s
        // `pack_bits256_as_4_limbs(anchor)` / `encode_256` byte-for-
        // byte. See the module-level Phase 4b-step2 comments for the
        // documented soundness trade-off (Merkle consistency is now a
        // trace-only claim; the AIR no longer reveals the derived
        // anchor proxy on the PI wire).
        for k in 0..4 {
            let limb = u64::from_le_bytes(
                self.anchor_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
            );
            out.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
        }

        let perm = default_goldilocks_poseidon2_8();

        for s in &self.spends {
            // nf_i: 4-limb Poseidon2 nullifier (AIR-bound).
            // Phase 4b-step3-step0: widened nk field → u64 proxy via
            // first_u64_proxy (AIR semantics unchanged).
            let nf_limbs =
                poseidon2_nf_full(&perm, first_u64_proxy(&s.nk), s.leaf, s.pos);
            for limb in nf_limbs {
                out.push(limb);
            }
            // rk_i: 4 u64 limbs of rk_bytes (LE), reduced mod Goldilocks.
            // Phase 4a AIR-bound to spend's S_RK_LIMB0..S_RK_LIMB0+4
            // proxy cols. Matches C++ validator `encode_256`.
            for k in 0..RK_EPK_LIMBS {
                let limb = u64::from_le_bytes(
                    s.rk_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                );
                out.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
            }
        }

        for o in &self.outputs {
            // cm_j: Phase 4b-step2a — all 4 limbs now come from
            // witness.cm_bytes[k*8..(k+1)*8] as u64 (mod p). The
            // Poseidon2-w=16 proxy-derivation (poseidon2_cm_fe) still
            // constrains the `O_CM_CLAIM` trace column via the shared
            // wide block, but no longer drives PI. Matches C++'s
            // `pack_bits256_as_4_limbs(o.cm)` / `encode_256` output
            // byte-for-byte.
            for k in 0..4 {
                let limb = u64::from_le_bytes(
                    o.cm_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                );
                out.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
            }
            // epk_j: 4 u64 limbs of epk_bytes (LE), reduced mod
            // Goldilocks. Phase 4a AIR-bound to output's
            // O_EPK_LIMB0..O_EPK_LIMB0+4 proxy cols.
            for k in 0..RK_EPK_LIMBS {
                let limb = u64::from_le_bytes(
                    o.epk_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                );
                out.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
            }
            // filter_tag_j: 1 u16-wide field element. Phase 4a AIR-
            // bound to output's O_FILTER_TAG proxy col.
            out.push(Goldilocks::from_u64(o.filter_tag as u64));
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
            // Phase 4b-step3-step0: widened fields → u64 proxy via
            // first_u64_proxy; AIR inputs unchanged.
            let pk_d_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.pk_d)));
            let rcm_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.rcm)));
            let ivk_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.ivk)));
            let nk_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.nk)));
            let pos_f = Goldilocks::from_u64(reduce_to_goldilocks(s.pos));
            let value_f = Goldilocks::from_u64(reduce_to_goldilocks(s.value));
            let ivkcm_fe = poseidon2_ivk_commitment(&perm, first_u64_proxy(&s.ivk), d_word);

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
            // Phase 4b-step3-step0: widened output fields → u64 proxy.
            let d_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&o.d)));
            let pk_d_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&o.pk_d)));
            let ivk_cm_f =
                Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&o.ivk_commitment)));
            let rcm_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&o.rcm)));
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
                let ivkcm_fe = poseidon2_ivk_commitment(&perm, first_u64_proxy(&s.ivk), d_word);
                let mut v = Vec::with_capacity(SPEND_PROXY_COLS);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.leaf)));
                v.push(d_f);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.value)));
                // Phase 4b-step3-step0: widened u64 proxy extraction
                // from witness byte arrays.
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.ivk))));
                v.push(ivkcm_fe);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.pk_d))));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.rcm))));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.nk))));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.pos)));
                for k in 0..MERKLE_DEPTH {
                    let bit = (s.pos >> k) & 1;
                    v.push(Goldilocks::from_u64(bit));
                }
                for k in 0..MERKLE_DEPTH {
                    v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.merkle_path[k])));
                }
                // Decompose value into VALUE_LIMBS_U16 = 4 u16 limbs
                // (low-to-high). Phase 3b-step2: was 64 bit columns.
                let value_canon = reduce_to_goldilocks(s.value);
                for k in 0..VALUE_LIMBS_U16 {
                    let limb = (value_canon >> (16 * k)) & 0xffff;
                    v.push(Goldilocks::from_u64(limb));
                }
                // Phase 4a: 4 u64 limbs from rk_bytes (LE), each reduced
                // mod Goldilocks. Matches C++ `encode_256` — consensus-
                // binding byte-for-byte with validator PI.
                for k in 0..RK_EPK_LIMBS {
                    let limb = u64::from_le_bytes(
                        s.rk_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                    );
                    v.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
                }
                debug_assert_eq!(v.len(), SPEND_PROXY_COLS);
                v
            })
            .collect();

        let output_proxies: Vec<Vec<Goldilocks>> = self
            .outputs
            .iter()
            .map(|o| {
                // Phase 4b-step3-step0: widened output fields → u64
                // proxy for Poseidon2 input; cm derivation shape
                // unchanged.
                let d_p = first_u64_proxy(&o.d);
                let pk_d_p = first_u64_proxy(&o.pk_d);
                let ivkcm_p = first_u64_proxy(&o.ivk_commitment);
                let rcm_p = first_u64_proxy(&o.rcm);
                let cm_fe =
                    poseidon2_cm_fe(&perm16, d_p, pk_d_p, ivkcm_p, o.value, rcm_p);
                let mut v = Vec::with_capacity(OUTPUT_PROXY_COLS);
                v.push(cm_fe);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(d_p)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(pk_d_p)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(ivkcm_p)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(o.value)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(rcm_p)));
                // Phase 3b-step2: 4 u16 limbs (was 64 bit columns).
                let value_canon = reduce_to_goldilocks(o.value);
                for k in 0..VALUE_LIMBS_U16 {
                    let limb = (value_canon >> (16 * k)) & 0xffff;
                    v.push(Goldilocks::from_u64(limb));
                }
                // Phase 4a: 4 u64 limbs of epk_bytes (LE), + 1 filter_tag
                // column. All reduced mod Goldilocks; matches C++
                // `encode_256` + the u16 `filter_tag` PI encoding.
                for k in 0..RK_EPK_LIMBS {
                    let limb = u64::from_le_bytes(
                        o.epk_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                    );
                    v.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
                }
                v.push(Goldilocks::from_u64(o.filter_tag as u64));
                // Phase 4b-step1: 3 upper u64 limbs of cm_bytes[8..32]
                // (LE), reduced mod Goldilocks. Bound to PI[pi_cm(j)+k]
                // for k in 1..4 by row-0 copy-constraint.
                for k in 1..4 {
                    let limb = u64::from_le_bytes(
                        o.cm_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                    );
                    v.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
                }
                // Phase 4b-step2a: cm_bytes[0..8] as a single u64 limb,
                // reduced mod Goldilocks. This is the PI binding for
                // cm limb 0 — bound to `PI[pi_cm(j) + 0]` via row-0
                // copy-constraint. `O_CM_CLAIM` (col 0) stays on its
                // Poseidon2 derivation but no longer touches PI.
                let cm_limb0 = u64::from_le_bytes(
                    o.cm_bytes[0..8].try_into().unwrap(),
                );
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(cm_limb0)));
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

            // Phase 4b-step1: anchor limbs 1..3 (global cols, constant
            // across rows). Same invariant as other proxy cols: identical
            // value on every row; AIR eval binds row 0 only.
            for k in 1..4 {
                let limb = u64::from_le_bytes(
                    self.anchor_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                );
                values.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
            }
            // Phase 4b-step2b: anchor_proxy (Merkle-walk output from
            // witness, trace-only binding for `last.assert_eq`).
            values.push(Goldilocks::from_u64(reduce_to_goldilocks(self.anchor_proxy)));
            // Phase 4b-step2b: anchor_bytes[0..8] as u64 (mod p). PI-
            // binding col for `PI[PI_ANCHOR + 0]`.
            let anchor_limb0 = u64::from_le_bytes(
                self.anchor_bytes[0..8].try_into().unwrap(),
            );
            values.push(Goldilocks::from_u64(reduce_to_goldilocks(anchor_limb0)));

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

/// Phase 4b-step3-step0 shim: extract the u64 proxy from the first 8
/// bytes of a widened 32-byte witness field (little-endian). The AIR
/// in its current pre-step3 shape still processes Poseidon2 / Merkle
/// inputs as u64 proxies; lifting to full 4-fe inputs is Phase 4b-
/// step3-step1..3 per `doc/uno-p2-phase4b-step3-plan.md`. Callers
/// write `first_u64_proxy(&w.ivk)` etc. at every former
/// `w.ivk` (u64) reference site.
#[inline]
pub(crate) fn first_u64_proxy(bytes: &[u8; 32]) -> u64 {
    u64::from_le_bytes(bytes[0..8].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Phase 4b-step3-step1.0 helpers — 15-fe iterated-sponge
// Poseidon2-w=16 `cm` derivation, off-circuit reference
// ---------------------------------------------------------------------------
//
// These functions are the byte-for-byte Rust mirror of tosctl's
// `tosctl/uno/src/poseidon2.rs::hash_tagged` called with tag
// "uno-cm-v1" and 15 Goldilocks field elements in the order
// specified by `uno/core/poseidon2.cpp::compute_note_commitment`.
// They are NOT yet wired into the AIR; Phase 4b-step3-step1.1+
// will build trace-gen + constraints on top of them. Landing them
// here as a standalone commit lets us unit-test the off-circuit
// reference against tosctl / C++ before committing to the ~420 LOC
// of AIR structural change needed to express the sponge in a STARK
// constraint system.
//
// Layout per §3.2 of `doc/uno-workchain.md` and the iterated-sponge
// description recorded in `doc/uno-p2-phase4b-step3-plan.md` §4.1:
//
//   tag_block        = pack("uno-cm-v1" into 8 fes via 8-byte LE chunks)
//   fes[0..1]        = d   (11 B diversifier, zero-padded to 16 B,
//                           split as 2 × u64 LE mod p)
//   fes[2..5]        = pk_d            (32 B → 4 × u64 LE mod p)
//   fes[6..9]        = ivk_commitment  (32 B → 4 × u64 LE mod p)
//   fes[10]          = value           (u64 mod p)
//   fes[11..14]      = rcm             (32 B → 4 × u64 LE mod p)
//                      (15 fes total)
//
//   state[8..16]     = tag_block (capacity slots, pinned)
//
//   Permutation 1:   state[0..7] += fes[0..7]; permute.
//   Permutation 2:   state[0..6] += fes[8..14]; state[7] += ONE
//                    (10* padding, since rem=7 after block 1);
//                    permute.
//
//   Output:          state[0..4]  (4 fe = 32 B after LE-u64 packing)

/// Domain tag "uno-cm-v1" packed as 8 Goldilocks field elements in
/// the convention tosctl / C++ use for the capacity slots of the
/// width-16 sponge: 8-byte LE chunks of the UTF-8 tag string,
/// zero-padded. Only the first fe holds a non-zero u64 for this
/// 9-byte tag.
#[inline]
pub(crate) fn uno_cm_v1_tag_block() -> [Goldilocks; 8] {
    // Mirror of `tosctl/uno/src/poseidon2.rs::pack_tag_block` for
    // the specific tag "uno-cm-v1" (9 ASCII bytes). The tag fits
    // inside one 8-byte chunk + 1 trailing byte in the second
    // chunk; all remaining chunks are zero.
    let tag: &[u8] = b"uno-cm-v1";
    let mut out = [Goldilocks::ZERO; 8];
    let full = tag.len() / 8;
    for i in 0..full {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&tag[i * 8..(i + 1) * 8]);
        out[i] = Goldilocks::from_u64(u64::from_le_bytes(limb));
    }
    let rem = tag.len() - full * 8;
    if rem > 0 && full < 8 {
        let mut buf = [0u8; 8];
        buf[..rem].copy_from_slice(&tag[full * 8..full * 8 + rem]);
        out[full] = Goldilocks::from_u64(u64::from_le_bytes(buf));
    }
    out
}

/// 32 bytes → 4 Goldilocks field elements via 8-byte LE chunks,
/// each reduced mod p_Goldilocks (`reduce_to_goldilocks` if needed;
/// inputs from tosctl are already canonical). Byte-identical to
/// `tosctl/uno/src/poseidon2.rs::bytes_to_fes_wrapped` for a 32 B
/// input + C++ `pack_bytes32_as_4`.
#[inline]
pub(crate) fn pack_32b_as_4fe(bytes: &[u8; 32]) -> [Goldilocks; 4] {
    let mut out = [Goldilocks::ZERO; 4];
    for i in 0..4 {
        let limb = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        out[i] = Goldilocks::from_u64(reduce_to_goldilocks(limb));
    }
    out
}

/// 11-byte diversifier (passed as [u8; 32] with bytes[0..11] real +
/// bytes[11..32] zero-pad per the Phase 4b-step3-step0 witness wire
/// format) → 2 Goldilocks field elements. Consumes bytes[0..16] as
/// 2 × u64 LE mod p; bytes[16..32] are not looked at (they are
/// expected to be zero and play no role in the sponge).
#[inline]
pub(crate) fn pack_diversifier_as_2fe(d: &[u8; 32]) -> [Goldilocks; 2] {
    [
        Goldilocks::from_u64(reduce_to_goldilocks(
            u64::from_le_bytes(d[0..8].try_into().unwrap()),
        )),
        Goldilocks::from_u64(reduce_to_goldilocks(
            u64::from_le_bytes(d[8..16].try_into().unwrap()),
        )),
    ]
}

/// Off-circuit Rust mirror of tosctl `compute_note_commitment` /
/// C++ `compute_note_commitment`. Computes the 4-fe cm digest via
/// the 15-fe iterated Poseidon2-w=16 sponge with "uno-cm-v1" tag.
///
/// NOT yet wired into the AIR — step 1.1+ adds trace-gen + row-
/// gated constraints that verify this derivation in-circuit, at
/// which point `witness.cm_bytes` can be bound by the STARK to
/// match the output of this function (currently the AIR only
/// constrains the old single-permutation 6-input u64-proxy
/// `poseidon2_cm_fe`, which does NOT match tosctl's cm bytes).
///
/// Returns `[Goldilocks; 4]` — pack them with
/// `as_canonical_u64().to_le_bytes()` to get 32-byte cm.
#[allow(dead_code)]
pub(crate) fn poseidon2_cm_full_sponge(
    perm16: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH_16]>,
    d: &[u8; 32],
    pk_d: &[u8; 32],
    ivk_commitment: &[u8; 32],
    value: u64,
    rcm: &[u8; 32],
) -> [Goldilocks; 4] {
    // Assemble the 15 input field elements per §3.2.
    let d_fes = pack_diversifier_as_2fe(d);
    let pk_d_fes = pack_32b_as_4fe(pk_d);
    let ivk_cm_fes = pack_32b_as_4fe(ivk_commitment);
    let value_fe = Goldilocks::from_u64(reduce_to_goldilocks(value));
    let rcm_fes = pack_32b_as_4fe(rcm);

    let mut fes = [Goldilocks::ZERO; 15];
    fes[0] = d_fes[0];
    fes[1] = d_fes[1];
    fes[2..6].copy_from_slice(&pk_d_fes);
    fes[6..10].copy_from_slice(&ivk_cm_fes);
    fes[10] = value_fe;
    fes[11..15].copy_from_slice(&rcm_fes);

    // Initial sponge state: tag block pinned at capacity slots.
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
    let tag = uno_cm_v1_tag_block();
    state[8..16].copy_from_slice(&tag);

    // Permutation 1: absorb fes[0..8] into rate slots 0..7.
    for j in 0..8 {
        state[j] = state[j] + fes[j];
    }
    perm16.permute_mut(&mut state);

    // Permutation 2: absorb remaining 7 fes (rem = 15 - 8 = 7) into
    // rate slots 0..6; state[7] += ONE for 10* padding.
    for j in 0..7 {
        state[j] = state[j] + fes[8 + j];
    }
    state[7] = state[7] + Goldilocks::from_u64(1);
    perm16.permute_mut(&mut state);

    [state[0], state[1], state[2], state[3]]
}

/// 32-byte → 4 canonical-Goldilocks u64 limbs. Byte-identical mirror of
/// `uno/core/transaction.cpp::encode_256` (§4.3 step 4, decision #5):
///
/// * split into 4 consecutive u64 LE chunks,
/// * each chunk reduced via a single conditional subtract (safe for
///   `x ∈ [0, 2·p_Goldilocks)`, which covers any u64).
///
/// Used by `MvpWitness::public_inputs` (档1) to pack raw `anchor` / `rk`
/// / `cm` / `epk` bytes into the PI vector so Rust-prover PIs byte-match
/// C++ `build_plonky3_public_inputs(tx)` slot-for-slot.
#[inline]
pub fn encode_256_as_4_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for limb in 0..4 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[limb * 8..(limb + 1) * 8]);
        out[limb] = reduce_to_goldilocks(u64::from_le_bytes(chunk));
    }
    out
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
        // Phase 4b-step3-step0: widened fields → u64 proxy. Claim 2
        // derivation shape unchanged (still over u64 proxies; real
        // 32-byte derivation is step 1+).
        let ivkcm = poseidon2_ivk_commitment(&perm, first_u64_proxy(&s.ivk), d_word);
        let derived = poseidon2_cm(
            &perm16,
            d_word,
            first_u64_proxy(&s.pk_d),
            ivkcm.as_canonical_u64(),
            s.value,
            first_u64_proxy(&s.rcm),
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

/// Phase 4b-step1: true iff `witness.anchor_bytes[0..8] as u64 (mod p)
/// == anchor_proxy`. Enforced as a prover-side pre-check so C++ and
/// Rust emit byte-identical `PI[PI_ANCHOR + 0]`: C++ reads
/// `encode_256(anchor_bytes)[0] = anchor_bytes[0..8] as u64 (mod p)`;
/// Rust emits `anchor_proxy`; the AIR already binds `anchor_proxy ==
/// PI[PI_ANCHOR + 0]` via the last-row `S_CURRENT` check. If the
/// wallet populates `anchor_bytes[0..8]` from some other source, the
/// two sides would disagree on PI limb 0 and STARK verify would fail
/// downstream — better to reject at the structured-error boundary.
pub fn witness_anchor_bytes_consistent(w: &MvpWitness) -> bool {
    let anchor_limb0 = u64::from_le_bytes(w.anchor_bytes[0..8].try_into().unwrap());
    reduce_to_goldilocks(anchor_limb0) == reduce_to_goldilocks(w.anchor_proxy)
}

/// Phase 4b-step1: true iff for every output,
/// `witness.cm_bytes[0..8] as u64 (mod p) ==
/// poseidon2_cm_fe(d, pk_d, ivk_commitment, value, rcm)`. Same
/// rationale as `witness_anchor_bytes_consistent` but for the per-
/// output cm limb-0 binding. C++ side reads
/// `encode_256(cm_bytes)[0]`; Rust emits the Poseidon2-w=16 output.
/// Pre-check rejects witnesses where the two disagree on the low
/// 8 bytes.
pub fn witness_cm_bytes_consistent(w: &MvpWitness) -> bool {
    let perm16 = default_goldilocks_poseidon2_16();
    for o in &w.outputs {
        let derived = poseidon2_cm_fe(
            &perm16,
            first_u64_proxy(&o.d),
            first_u64_proxy(&o.pk_d),
            first_u64_proxy(&o.ivk_commitment),
            o.value,
            first_u64_proxy(&o.rcm),
        )
        .as_canonical_u64();
        let witness_limb0 =
            u64::from_le_bytes(o.cm_bytes[0..8].try_into().unwrap());
        if reduce_to_goldilocks(witness_limb0) != derived {
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

    /// Regression test for the Phase 3b-step3 N-bundled-tuple bug
    /// (task #130). The original wire-up registered a single
    /// `Kind::Global("u16_range")` lookup with 4·(n_s+n_o) input tuples
    /// bundled inside. That raised the LogUp per-row constraint
    /// polynomial degree to N+1 (denominator product of N linear
    /// factors), which mis-interacted with batch-stark's quotient
    /// sizing on wide AIRs and produced
    /// `OodEvaluationMismatch { index: Some(0) }` at verify time while
    /// prove succeeded. Fixed in dadc249ec by splitting into N
    /// separate single-tuple `Kind::Global("u16_range")` lookups —
    /// each a well-trodden degree-2 LogUp constraint.
    ///
    /// If someone accidentally re-bundles the tuples, this test fails
    /// BEFORE the slow prove+verify round-trip does, so the
    /// regression is caught at lint-level instead of during a CI
    /// STARK run.
    #[test]
    fn lookupair_must_stay_single_tuple_per_limb() {
        use p3_lookup::lookup_traits::{Kind, Lookup};
        use p3_lookup::LookupAir;

        for &(n_s, n_o) in &[(1, 1), (1, 2), (2, 2), (4, 4)] {
            let mut air = MvpTransferAir::new(n_s, n_o);
            let lookups: Vec<Lookup<Goldilocks>> = LookupAir::<Goldilocks>::get_lookups(&mut air);

            let expected_count = 4 * (n_s + n_o);
            assert_eq!(
                lookups.len(),
                expected_count,
                "shape {}/{} must register {} single-tuple Kind::Global lookups, got {}. \
                 Bundling into a single Lookup with multiple input tuples trips \
                 OodEvaluationMismatch on verify — see commit dadc249ec.",
                n_s,
                n_o,
                expected_count,
                lookups.len(),
            );

            for (i, lk) in lookups.iter().enumerate() {
                match &lk.kind {
                    Kind::Global(name) => assert_eq!(
                        name,
                        crate::range16_air::U16_RANGE_LOOKUP_NAME,
                        "shape {}/{} lookup {} must be Kind::Global(\"u16_range\"); got different name {:?}",
                        n_s, n_o, i, name,
                    ),
                    Kind::Local => panic!(
                        "shape {}/{} lookup {} must be Kind::Global, not Local",
                        n_s, n_o, i,
                    ),
                }
                assert_eq!(
                    lk.element_exprs.len(),
                    1,
                    "shape {}/{} lookup {} must have exactly one input tuple, got {}",
                    n_s, n_o, i, lk.element_exprs.len(),
                );
                assert_eq!(
                    lk.element_exprs[0].len(),
                    1,
                    "shape {}/{} lookup {} tuple must be single-element (just the u16 limb), got {}",
                    n_s, n_o, i, lk.element_exprs[0].len(),
                );
            }
        }
    }

    // --------------------------------------------------------------
    // Phase 4b-step3-step1.0 helper tests: off-circuit 15-fe sponge
    // --------------------------------------------------------------

    /// Tag-block packing matches a hand-derived expected for
    /// "uno-cm-v1" — the only non-zero slot is slot 0, holding the
    /// LE u64 of the first 8 ASCII bytes "uno-cm-v"; slot 1 holds
    /// the trailing "1" byte in its low byte; slots 2..7 are zero.
    #[test]
    fn uno_cm_v1_tag_block_expected_layout() {
        let got = uno_cm_v1_tag_block();

        // "uno-cm-v" = 0x75 0x6e 0x6f 0x2d 0x63 0x6d 0x2d 0x76
        let mut expect0 = [0u8; 8];
        expect0.copy_from_slice(b"uno-cm-v");
        let e0 = u64::from_le_bytes(expect0);
        assert_eq!(got[0].as_canonical_u64(), e0);

        // "1" at byte 0 of the second chunk, rest zero.
        let mut expect1 = [0u8; 8];
        expect1[0] = b'1';
        let e1 = u64::from_le_bytes(expect1);
        assert_eq!(got[1].as_canonical_u64(), e1);

        for k in 2..8 {
            assert_eq!(got[k].as_canonical_u64(), 0, "tag slot {} must be zero", k);
        }
    }

    /// Determinism: same inputs → same cm digest.
    #[test]
    fn poseidon2_cm_full_sponge_deterministic() {
        let perm16 = default_goldilocks_poseidon2_16();
        let d = [0x11u8; 32];
        let pk_d = [0x22u8; 32];
        let ivk_commitment = [0x33u8; 32];
        let value = 0xDEAD_BEEF_1234_5678u64 % GOLDILOCKS_P;
        let rcm = [0x44u8; 32];

        let a =
            poseidon2_cm_full_sponge(&perm16, &d, &pk_d, &ivk_commitment, value, &rcm);
        let b =
            poseidon2_cm_full_sponge(&perm16, &d, &pk_d, &ivk_commitment, value, &rcm);
        assert_eq!(a, b);

        // Perturb one byte → output changes.
        let mut rcm_alt = rcm;
        rcm_alt[0] ^= 0x01;
        let c = poseidon2_cm_full_sponge(
            &perm16,
            &d,
            &pk_d,
            &ivk_commitment,
            value,
            &rcm_alt,
        );
        assert_ne!(a, c, "cm digest must depend on every rcm byte");

        // Each of the 5 inputs contributes: confirm for d as well.
        let mut d_alt = d;
        d_alt[3] ^= 0x80;
        let e = poseidon2_cm_full_sponge(
            &perm16,
            &d_alt,
            &pk_d,
            &ivk_commitment,
            value,
            &rcm,
        );
        assert_ne!(a, e, "cm digest must depend on d bytes");
    }

    /// All four output limbs are typically non-zero for random inputs
    /// (sanity: sponge is actually producing 4-fe output, not just
    /// state[0]).
    #[test]
    fn poseidon2_cm_full_sponge_produces_4_distinct_limbs() {
        let perm16 = default_goldilocks_poseidon2_16();
        let d = [0x55u8; 32];
        let pk_d = [0x66u8; 32];
        let ivk_commitment = [0x77u8; 32];
        let value = 0xCAFE_F00Du64;
        let rcm = [0x88u8; 32];

        let digest =
            poseidon2_cm_full_sponge(&perm16, &d, &pk_d, &ivk_commitment, value, &rcm);

        // Sanity: at least 3 of 4 limbs are non-zero (extremely high
        // prob. given Poseidon2's avalanche). If this ever trips,
        // either the sponge is buggy or we got astronomically lucky.
        let non_zero = digest.iter().filter(|l| l.as_canonical_u64() != 0).count();
        assert!(
            non_zero >= 3,
            "poseidon2 cm output has too many zero limbs: {:?}",
            digest.map(|l| l.as_canonical_u64()),
        );

        // Sanity: all 4 limbs are distinct (ditto).
        use std::collections::HashSet;
        let distinct: HashSet<u64> =
            digest.iter().map(|l| l.as_canonical_u64()).collect();
        assert_eq!(
            distinct.len(),
            4,
            "poseidon2 cm output limbs collide unexpectedly: {:?}",
            digest.map(|l| l.as_canonical_u64()),
        );
    }
}
