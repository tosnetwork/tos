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
//!                   + 4                                // S_CURRENT_FE[0..4] (4-fe Merkle digest)
//!                   + 1·POSEIDON2_COLS_PER_INSTANCE    // SHARED Merkle (w=8, row-loop)
//! per_output_cols() = OUTPUT_PROXY_COLS
//! ```
//!
//! Three row-looped shared Poseidon2 blocks fold all per-spend /
//! per-output compressions across trace rows:
//!
//! - **Merkle (w=8, shared per spend)**: rows 0..31 carry the 32 Merkle
//!   levels of that spend via a 4-fe running-digest
//!   `S_CURRENT_FE[0..4]` (step 3a widening from the legacy single-fe
//!   `S_CURRENT`). Each level performs a
//!   `(left[4] ‖ right[4]) → out[4]` Poseidon2-w=8 compression.
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
///
/// Phase 4b-step3-step3a cleanup: the Phase 4b-step1 / Phase 4b-step2b
/// anchor-limb global cols (`G_ANCHOR_LIMB1..3`, `G_ANCHOR_PROXY`,
/// `G_ANCHOR_LIMB0_REAL`) are retired. Post step 3a the Merkle walk
/// carries a full 4-fe digest in `S_CURRENT_FE[0..4]` and the
/// last-row binding pins each of those cols directly to
/// `PI[PI_ANCHOR + 0..4]` — so the single-u64 anchor indirection is
/// no longer needed.
pub const GLOBAL_COLS: usize = 1
    + MERKLE_DEPTH
    + POSEIDON2_COLS_PER_INSTANCE_16 // shared Cm / OutCm (w=16) — claim 2/6
    + POSEIDON2_COLS_PER_INSTANCE;  // shared IvkCm / Nf (w=8) — claim 3/4
const GCOL_FEE: usize = 0;
/// Base index of the 32 one-hot Merkle row-selector columns (§claim 1).
const GS_ROW_SEL0: usize = 1;
/// Base index of the shared Cm/OutCm width-16 Poseidon2 block
/// (K-air-col-step2 strategy b — claim 2/6 row-loop on rows 0..7).
const G_CM_SHARED_P2_16: usize = GS_ROW_SEL0 + MERKLE_DEPTH;
/// Base index of the shared IvkCm/Nf width-8 Poseidon2 block
/// (K-air-col-step2 strategy c — claim 3/4 row-loop on rows 0..7).
const G_IVKCM_NF_SHARED_P2_8: usize = G_CM_SHARED_P2_16 + POSEIDON2_COLS_PER_INSTANCE_16;

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
/// × 4-fe sibling-hash proxy blocks for the 32-level Merkle path
/// (§2.3), VALUE_LIMBS_U16 u16-limb columns for the u64 range-check on
/// `value_i` (§4.2 claim 5), and RK_EPK_LIMBS columns holding the
/// 4-limb decomposition of the spend's `rk_bytes` for the PI binding
/// added in Phase 4a. Phase 4b-step3-step2b-decomp adds 38 additional
/// cols per spend (6 single-fe cols — upper 3 fes each of nk and leaf
/// — plus 32 u16 limb cols — 4 fes × 4 u16 each for nk and leaf) that
/// decompose the 32-byte `nk` and `leaf` witness fields into their
/// canonical 4-fe × 4×u16 LE form. Each u16 limb is range-checked via
/// the cross-AIR `u16_range` LogUp; each fe-limb col is AIR-bound to
/// `Σ_k limb_k · 2^{16k}`. Mirror of the output-side step 1.3-fields
/// block (`O_D_LIMB0`..`O_RCM_LIMB0`).
///
/// Phase 4b-step3-step3a widens sibling proxies from 1 fe/level to 4
/// fe/level (`SIBLING_FES_PER_LEVEL = 4`) so the Merkle walk runs a
/// full 4-fe Goldilocks digest through the 32 Poseidon2-w=8
/// compressions — matching the `pack_32b_as_4fe(sibling)` layout that
/// tosctl threads through. Net +96 cols/spend
/// (`MERKLE_DEPTH · (SIBLING_FES_PER_LEVEL - 1) = 32 · 3 = 96`).
pub const SPEND_PROXY_COLS: usize = 9
    + MERKLE_DEPTH
    + MERKLE_DEPTH * SIBLING_FES_PER_LEVEL
    + VALUE_LIMBS_U16
    + RK_EPK_LIMBS
    + 38
    + 16; // Phase 4b-step3-step2b-AIR-v2: S_NF_CARRY_{CAP,RATE}[0..8]

/// Per-output proxy columns: cm_claim (Poseidon2-w=16 output, trace-
/// only after Phase 4b-step2a), d, pk_d, ivk_commitment, value, rcm (6
/// leading fields), VALUE_LIMBS_U16 u16-limb columns for the u64
/// range-check on `value_j` (§4.2 claim 7), RK_EPK_LIMBS columns
/// holding `epk_bytes` limbs, 1 column holding the u16 `filter_tag`
/// (Phase 4a), 3 columns for `cm_bytes[8..32]` upper limbs (Phase 4b-
/// step1), and 1 column for `cm_bytes[0..8]` limb 0 (Phase 4b-step2a)
/// — bound to `PI[pi_cm(j) + 0]` via row-0 copy-constraint, replacing
/// the previous `cm_claim == pi_cms[j]` binding. Phase 4b-step3-
/// step1.3-fields adds 56 additional u16 limb cols per output (14 fe-
/// limbs × 4 u16 limbs) that decompose each of the d/pk_d/ivk_cm/rcm
/// fe-limb proxy cols into its canonical u64 → 4×u16 limb form. Each
/// limb is range-checked via the cross-AIR `u16_range` LogUp.
pub const OUTPUT_PROXY_COLS: usize =
    6 + VALUE_LIMBS_U16 + RK_EPK_LIMBS + 1 + 4 + 8 + 5 + 5 + 8 + 56;

/// Narrow (width-8) Poseidon2 instances per spend after K-air-col-step2:
/// only the shared-Merkle slot remains. IvkCm + Nf are folded into a
/// single globally-shared row-looped block on rows 0..7.
pub const POSEIDON2_NARROW_PER_SPEND: usize = 1;

/// Phase 4b-step3-step3a: number of Goldilocks field elements per
/// Merkle-path sibling. Step 3a widens from 1 (legacy single-u64
/// proxy) to 4 so the Merkle walk runs a full 4-fe digest through
/// each of the 32 Poseidon2-w=8 compressions
/// (`(left[4] ‖ right[4]) → out[4]`). Each sibling is the
/// `pack_32b_as_4fe(s.merkle_path[k])` decomposition.
pub const SIBLING_FES_PER_LEVEL: usize = 4;

/// Per-spend variable columns that are NOT constant across rows (i.e., not
/// included in the transition "proxies are constant" equality).
/// Phase 4b-step3-step3a: widened from 1 to 4 so the Merkle-walk
/// running digest `S_CURRENT_FE[0..4]` carries a full 4-fe state
/// through the 32 levels of `(left[4] ‖ right[4]) → out[4]`
/// Poseidon2-w=8 compressions.
pub const SPEND_VAR_COLS: usize = 4;
/// Offset of the low fe of the Merkle-walk running digest within the
/// per-spend variable block. The four digest cols live at
/// `S_CURRENT_FE0`..`S_CURRENT_FE3 = S_CURRENT_FE0 + 3`.
const S_CURRENT_FE0: usize = 0;
#[allow(dead_code)]
const S_CURRENT_FE1: usize = 1;
#[allow(dead_code)]
const S_CURRENT_FE2: usize = 2;
#[allow(dead_code)]
const S_CURRENT_FE3: usize = 3;

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
// Merkle path: MERKLE_DEPTH path-bit proxies, then
// `MERKLE_DEPTH * SIBLING_FES_PER_LEVEL` sibling-limb proxies (Phase
// 4b-step3-step3a: 4 fes per level). Path bit `k` is
// `(pos >> k) & 1` (low→high bit order); sibling limb `m` of level `k`
// lives at `S_SIBLING0 + k · SIBLING_FES_PER_LEVEL + m` and equals
// `pack_32b_as_4fe(s.merkle_path[k])[m]`.
const S_PATH_BIT0: usize = 9;
const S_SIBLING0: usize = S_PATH_BIT0 + MERKLE_DEPTH;
/// Base index of the 4×u16 limb-decomposition columns for `value_i`
/// (claim 5). Phase 3b-step2: was `S_VALUE_BIT0` (64 bit columns).
/// Phase 4b-step3-step3a: sibling block widened to 4 fe/level, so
/// this offset shifts by `MERKLE_DEPTH · (SIBLING_FES_PER_LEVEL - 1)
/// = 96` cols.
const S_VALUE_LIMB0: usize = S_SIBLING0 + MERKLE_DEPTH * SIBLING_FES_PER_LEVEL;
/// Base index of the 4 u64-limb columns holding `rk_bytes` (Phase 4a).
const S_RK_LIMB0: usize = S_VALUE_LIMB0 + VALUE_LIMBS_U16;

/// Phase 4b-step3-step2b-decomp: upper-fe-limb proxy columns holding
/// the 3 high Goldilocks field elements of `nk` (the low fe is the
/// existing `S_NK` col == `first_u64_proxy(&s.nk)`). Together these
/// 4 cols (S_NK, S_NK_FE1..3) hold `pack_32b_as_4fe(&s.nk)` — the
/// canonical 4-fe decomposition of the 32-byte witness `nk` field.
///
/// Populated trace-side from `pack_32b_as_4fe(&s.nk)[1..4]`; AIR-bound
/// by the new u16-limb decomposition block (step2b-decomp) to
/// `Σ_k S_NK_LIMB{fe·4+k} · 2^{16k}` for each fe. Consumed by
/// step 2b-AIR (nf Poseidon2 with real 4-fe inputs) — this commit
/// only adds the cols + decomposition constraints + LogUp receives;
/// the nf sponge absorb layout is unchanged (still uses `S_NK` as a
/// single u64 proxy).
const S_NK_FE1: usize = S_RK_LIMB0 + RK_EPK_LIMBS;
const S_NK_FE2: usize = S_NK_FE1 + 1;
const S_NK_FE3: usize = S_NK_FE2 + 1;
/// Phase 4b-step3-step2b-decomp: upper-fe-limb proxy columns for
/// `leaf` — same shape as `S_NK_FE{1..3}`. Low fe is the existing
/// `S_LEAF` col == `first_u64_proxy(&s.leaf)`.
const S_LEAF_FE1: usize = S_NK_FE3 + 1;
const S_LEAF_FE2: usize = S_LEAF_FE1 + 1;
const S_LEAF_FE3: usize = S_LEAF_FE2 + 1;
/// Phase 4b-step3-step2b-decomp: base index of the 16 u16 limb
/// columns decomposing the 4 fe-limbs of `nk` into their canonical
/// u64 → 4×u16 LE form (4 fes × 4 u16 = 16 cols). Mirrors
/// `O_RCM_LIMB0`/etc on the output side (step 1.3-fields).
///
/// Each fe-limb col `(S_NK, S_NK_FE1..3)` is AIR-bound to
/// `Σ_k limb_k · 2^{16k}` over its 4-col limb block, and each limb
/// col is range-checked via the cross-AIR `u16_range` LogUp. Together
/// these prove each `nk` fe-limb is the canonical u64 of the
/// corresponding 8-byte LE chunk of `s.nk` — what
/// `pack_32b_as_4fe(&s.nk)` emits off-circuit.
const S_NK_LIMB0: usize = S_LEAF_FE3 + 1;
/// Phase 4b-step3-step2b-decomp: base index of the 16 u16 limb
/// columns decomposing the 4 fe-limbs of `leaf` — same shape as
/// `S_NK_LIMB0`.
const S_LEAF_LIMB0: usize = S_NK_LIMB0 + 16;
/// Phase 4b-step3-step2b-AIR-v2: base index of the 8 "nf carry cap"
/// cols holding the bank-1 Poseidon2-w=16 output's capacity slots
/// (`state[8..16]` after perm-1) for the nf iterated sponge. Pinned
/// by AIR constraints to bank-1 post-permutation capacity on row
/// 16+i AND to bank-2 input capacity on row 20+i. The proxies-are-
/// constant transition invariant carries these across the 4-row gap.
/// Mirror of `O_SPONGE_CARRY_CAP` on the output side (step 1.2d).
const S_NF_CARRY_CAP0: usize = S_LEAF_LIMB0 + 16;
/// Phase 4b-step3-step2b-AIR-v2: base index of the 8 "nf carry rate"
/// cols holding the bank-1 Poseidon2-w=16 output's rate slots
/// (`state[0..8]` after perm-1) for the nf iterated sponge. Pinned
/// by AIR constraints to bank-1 post-permutation rate on row 16+i
/// AND used as the "bank1.out term" in bank-2's absorb addition on
/// row 20+i. Mirror of `O_SPONGE_CARRY_RATE` on the output side
/// (step 1.2f).
const S_NF_CARRY_RATE0: usize = S_NF_CARRY_CAP0 + 8;

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
/// Phase 4b-step3-step1.1: base index of the 4 trace columns holding
/// the output of the 15-fe iterated-sponge `poseidon2_cm_full_sponge`
/// over `witness.o.{d, pk_d, ivk_commitment, value, rcm}`. Bound by
/// step 1.2b-f in-circuit Poseidon2 AIR constraints to the sponge
/// derivation, and by step 1.3-pi to `PI[pi_cm(j) + 0..4]` via row-0
/// copy-constraint. Superseded the Phase 4b-step1 / Phase 4b-step2a
/// witness-bytes path (`O_CM_LIMB0_REAL` + `O_CM_LIMB1..3`) which
/// was trimmed out by step 1.3-cleanup.
const O_CM_SPONGE_OUT: usize = O_FILTER_TAG + 1;
/// Phase 4b-step3-step1.2d: base index of the 8 "carry capacity" cols
/// holding the bank-1 Poseidon2-w=16 output's capacity slots
/// (`state[8..16]` after perm-1). These are pinned by AIR constraints
/// to bank-1's post-permutation capacity on row 8+j, AND to bank-2's
/// input capacity on row 12+j. Because output proxy cols are "constant
/// across rows" per the §4.2 invariant (enforced by the existing
/// `OUTPUT_PROXY_COLS` transition loop), the two rows' constraints
/// ratify `bank-1.out.cap == bank-2.in.cap` — exactly the
/// sponge-absorb-doesn't-touch-capacity rule — without needing cross-
/// row AIR access.
const O_SPONGE_CARRY_CAP: usize = O_CM_SPONGE_OUT + 4;
/// Phase 4b-step3-step1.2c: upper-fe-limb output-proxy columns that
/// complete the bank-1 sponge absorb layout. Together with the existing
/// single-fe proxies (`O_D`, `O_PK_D`, `O_IVK_COMMITMENT`, whose values
/// coincide with the low-limb fe of each field via
/// `pack_*_as_*fe(...)[0]`), these 5 cols hold the remaining fes that
/// bank-1 absorbs into its rate slots on row 8+j:
///
///   shared_cm.inputs[0] = O_D             = d_fes[0]
///   shared_cm.inputs[1] = O_D_FE1         = d_fes[1]           (NEW)
///   shared_cm.inputs[2] = O_PK_D          = pk_d_fes[0]
///   shared_cm.inputs[3] = O_PK_D_FE1      = pk_d_fes[1]        (NEW)
///   shared_cm.inputs[4] = O_PK_D_FE2      = pk_d_fes[2]        (NEW)
///   shared_cm.inputs[5] = O_PK_D_FE3      = pk_d_fes[3]        (NEW)
///   shared_cm.inputs[6] = O_IVK_COMMITMENT = ivk_cm_fes[0]
///   shared_cm.inputs[7] = O_IVK_COMMITMENT_FE1 = ivk_cm_fes[1] (NEW)
///
/// The AIR constraint in §4.1 step 1.2c pins `shared_cm.inputs[0..8]`
/// on row 8+j to exactly this layout, so the prover can no longer put
/// arbitrary values in bank-1's rate slots.
///
/// Soundness caveat for this sub-step: these cols are currently
/// trace-populated from `pack_*_as_*fe(&witness.o.*)` but have NO AIR
/// constraint binding them to the underlying 32-byte witness fields.
/// Step 1.3-fields will add per-field byte→fe decomposition cols +
/// constraints so that `O_*_FE{k}` is provably the k-th LE u64 limb
/// of the witness bytes. Until then, a malicious prover could still
/// pick any fe-limb values — but the sponge output would then be
/// unable to match `O_CM_SPONGE_OUT`, which step 1.3 will wire to PI.
const O_D_FE1: usize = O_SPONGE_CARRY_CAP + 8;
const O_PK_D_FE1: usize = O_D_FE1 + 1;
const O_PK_D_FE2: usize = O_PK_D_FE1 + 1;
const O_PK_D_FE3: usize = O_PK_D_FE2 + 1;
const O_IVK_COMMITMENT_FE1: usize = O_PK_D_FE3 + 1;
/// Phase 4b-step3-step1.2f: upper-fe-limb output-proxy columns that
/// complete the bank-2 sponge absorb layout. Together with the existing
/// single-fe proxies (`O_VALUE`, `O_RCM`, which coincide with value_fe
/// and rcm_fes[0]) these 5 cols hold the remaining fes[8..14] that
/// bank-2 absorbs into its rate slots on row 12+j:
///
///   bank2.inputs[k] = bank1.out[k] + fes[8+k] for k ∈ 0..6
///   bank2.inputs[7] = bank1.out[7] + ONE      (10* padding)
///
/// fes[8..14] map onto ivk_cm_fes[2..=3], value_fe, rcm_fes[0..=3].
const O_IVK_COMMITMENT_FE2: usize = O_IVK_COMMITMENT_FE1 + 1;
const O_IVK_COMMITMENT_FE3: usize = O_IVK_COMMITMENT_FE2 + 1;
const O_RCM_FE1: usize = O_IVK_COMMITMENT_FE3 + 1;
const O_RCM_FE2: usize = O_RCM_FE1 + 1;
const O_RCM_FE3: usize = O_RCM_FE2 + 1;
/// Phase 4b-step3-step1.2f: base index of the 8 "carry rate" cols
/// holding bank-1's Poseidon2-w=16 output rate slots (`state[0..8]`
/// after perm-1). AIR constraint on row 8+j binds these to
/// `shared_cm_out[0..8]`; row 12+j uses them as the "bank-1 output rate
/// term" in bank-2's input-absorb addition. Together with the output-
/// proxy "constant across rows" invariant, this carries the rate slots
/// across the 4-row gap between the two sponge permutations.
const O_SPONGE_CARRY_RATE: usize = O_RCM_FE3 + 1;

/// Phase 4b-step3-step1.3-fields: base index of the 56 u16 limb
/// columns that decompose each output fe-limb proxy into its canonical
/// u64 → 4×u16 LE form. Layout (grouped by field, matching the 15-fe
/// sponge input order):
///
///   O_D_LIMB0..O_D_LIMB0+7      — 2 fe-limbs × 4 u16   (d)
///   O_PK_D_LIMB0..+15           — 4 fe-limbs × 4 u16   (pk_d)
///   O_IVK_COMMITMENT_LIMB0..+15 — 4 fe-limbs × 4 u16   (ivk_commitment)
///   O_RCM_LIMB0..+15            — 4 fe-limbs × 4 u16   (rcm)
///
/// Note `O_VALUE` already has its own 4-limb decomposition via the
/// existing `O_VALUE_LIMB0..3` cols (Phase 3b-step2), so the 15-fe
/// sponge input's single `value_fe` at fes[10] reuses those cols — no
/// new limb block is needed for value.
///
/// Each of the 14 fe-limb proxy cols is constrained in the AIR eval
/// to equal `Σ_k limb_k · 2^{16k}`, and each of the 56 new u16 cols
/// is range-checked via the cross-AIR `u16_range` LogUp (same `name`
/// as the existing value-limb receives). Together these close the
/// remaining soundness gap from step 1.2c/f: a malicious prover can
/// no longer pick arbitrary Goldilocks values in the fe-limb cols —
/// each must be the canonical u64 reduction of the corresponding
/// 8-byte LE chunk of the 32-byte witness field, matching what
/// `pack_*_as_*fe` emits off-circuit.
const O_D_LIMB0: usize = O_SPONGE_CARRY_RATE + 8;
const O_PK_D_LIMB0: usize = O_D_LIMB0 + 8;
const O_IVK_COMMITMENT_LIMB0: usize = O_PK_D_LIMB0 + 16;
const O_RCM_LIMB0: usize = O_IVK_COMMITMENT_LIMB0 + 16;

// ---------------------------------------------------------------------------
// Shape-aware helpers
// ---------------------------------------------------------------------------

/// Per-spend block width after K-air-col-step2: proxies +
/// `S_CURRENT_FE[0..4]` (4-fe Merkle digest, step 3a widening) +
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
//   | [SPEND_VAR_COLS: S_CURRENT_FE[0..4]]          (running Merkle 4-fe digest)
//   | [shared Merkle P2 (w=8) : 180]                (rows 0..31 = 32 levels)
//
// Output block layout:
//     [OUTPUT_PROXY_COLS]                           (constant across rows)

#[inline]
const fn spend_proxy_offset(i: usize) -> usize {
    GLOBAL_COLS + i * per_spend_cols()
}

/// Offset of `S_CURRENT_FE[0..4]` (running Merkle 4-fe digest) within
/// spend `i`. Placed immediately after the constant-across-rows proxies.
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
/// Registers `Kind::Global("u16_range")` lookups whose
/// `Direction::Receive` input lists hold all u16 limb columns from
/// the per-spend and per-output proxy blocks:
///
///   Phase 3b-step2 value cols:            4·(n_spends + n_outputs)
///   Phase 4b-step3-step1.3 output fe-limb:        56·n_outputs
///   Phase 4b-step3-step2b-decomp spend fe-limb:   32·n_spends
///
/// Total receives per row: 36·n_spends + 60·n_outputs.
/// All at multiplicity 1.
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
            Vec::with_capacity(36 * self.n_spends + 60 * self.n_outputs);

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
        // Phase 4b-step3-step1.3-fields: register `u16_range` receives
        // for the 56 new fe-limb u16 cols per output (14 fe-limbs × 4
        // u16 limbs). Each receive carries multiplicity 1; the matching
        // Send side in `Range16Air` is sized so the cross-AIR cumulative
        // sum balances out across all receive cols × TRACE_HEIGHT rows.
        for j in 0..self.n_outputs {
            let base = output_proxy_offset(self.n_spends, j);
            for limb_base in &[
                O_D_LIMB0,
                O_PK_D_LIMB0,
                O_IVK_COMMITMENT_LIMB0,
                O_RCM_LIMB0,
            ] {
                // Each fe-limb block has `n_fe_limbs * 4` u16 cols.
                let n_fe_limbs = match *limb_base {
                    x if x == O_D_LIMB0 => 2,
                    _ => 4,
                };
                for k in 0..(n_fe_limbs * 4) {
                    let col = base + limb_base + k;
                    let limb = main_local[col];
                    let inputs = vec![(
                        vec![limb.into()],
                        one.clone(),
                        p3_lookup::lookup_traits::Direction::Receive,
                    )];
                    lookups
                        .push(p3_lookup::LookupAir::register_lookup(self, name(), &inputs));
                }
            }
        }
        // Phase 4b-step3-step2b-decomp: register `u16_range` receives
        // for the 32 new fe-limb u16 cols per spend (2 fields × 4 fe-
        // limbs × 4 u16 limbs = 32). Mirror of the output-side block
        // above for the `nk` / `leaf` spend witness fields.
        for i in 0..self.n_spends {
            let base = spend_proxy_offset(i);
            for limb_base in &[S_NK_LIMB0, S_LEAF_LIMB0] {
                for k in 0..16 {
                    let col = base + *limb_base + k;
                    let limb = main_local[col];
                    let inputs = vec![(
                        vec![limb.into()],
                        one.clone(),
                        p3_lookup::lookup_traits::Direction::Receive,
                    )];
                    lookups
                        .push(p3_lookup::LookupAir::register_lookup(self, name(), &inputs));
                }
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

                // Phase 4b-step3-step3a: claim-1 seed — the 4-fe running
                // digest `S_CURRENT_FE[0..4]` on row 0 must equal the
                // 4-fe decomposition of `s.leaf` as bound by the
                // step2b-decomp cols. `S_CURRENT_FE0` matches the
                // existing single-fe `S_LEAF` proxy (low fe); the
                // upper three fes match `S_LEAF_FE{1..3}`.
                let leaf_fe_srcs = [S_LEAF, S_LEAF_FE1, S_LEAF_FE2, S_LEAF_FE3];
                for m in 0..4 {
                    let cur_fe_m: AB::Var =
                        local_slice[spend_var_offset(i) + S_CURRENT_FE0 + m];
                    let leaf_fe_m: AB::Var = spend_col(local_slice, i, leaf_fe_srcs[m]);
                    first.assert_eq(cur_fe_m, leaf_fe_m);
                }
                let _ = leaf; // silence unused-var: legacy single-fe proxy read

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

                // Phase 4b-step3-step1.3-pi: bind `PI[pi_cm(j) + 0]` to
                // the AIR-ratified 15-fe iterated-sponge output
                // `O_CM_SPONGE_OUT[0]`, superseding the Phase 4b-step2a
                // witness-bytes binding from `O_CM_LIMB0_REAL`. Step
                // 1.2b-f chained Poseidon2 constraints now prove that
                // `O_CM_SPONGE_OUT[0..4]` equals
                //   Poseidon2-w=16-wide-sponge(
                //       "uno-cm-v1",
                //       [d, pk_d, ivk_commitment, value, rcm]_fe15)
                // and step 1.1-tosctl ensures tosctl's witness uses
                // the REAL 32-byte (d, pk_d, ivk_commitment, rcm) +
                // real value, so the sponge output is byte-identical
                // to `witness.cm_bytes[0..8]` as a u64 LE mod p.
                //
                // Soundness delta: this closes the Phase 4b-step2a
                // decoupling gap — PI cm is no longer just "whatever
                // witness claims" but "the AIR-derived Poseidon2
                // output over (d, pk_d, ivk_commitment, value, rcm)".
                // Combined with the shared-wide-block claim-2 / claim-6
                // proxy-Poseidon2 bindings (which stay for now, as
                // they are part of the Merkle-leaf / nullifier chain),
                // the cm PI is end-to-end AIR-ratified.
                let cm_sponge_limb0: AB::Var =
                    output_col(local_slice, self.n_spends, j, O_CM_SPONGE_OUT);
                first.assert_eq(cm_sponge_limb0, pi_cms[j]);

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

            // Phase 4b-step3-step3a: anchor PI bindings retired from
            // row 0. All 4 anchor limbs are now bound on the last row
            // from the 4-fe Merkle-walk digest `S_CURRENT_FE[0..4]` —
            // see the last-row block below. The Phase 4b-step1 /
            // step2b `G_ANCHOR_LIMB1..3` + `G_ANCHOR_LIMB0_REAL` +
            // `G_ANCHOR_PROXY` global cols are deleted.

            // Phase 4b-step3-step1.3-pi: cm limbs 1..3 PI binding per
            // output, from the AIR-ratified sponge output cols
            // `O_CM_SPONGE_OUT[1..4]`, superseding the Phase 4b-step1
            // witness-bytes binding from `O_CM_LIMB1..3`. See the limb-0
            // block above for the full soundness argument.
            for j in 0..self.n_outputs {
                for k in 1..4 {
                    let cm_sponge_limb: AB::Var = output_col(
                        local_slice,
                        self.n_spends,
                        j,
                        O_CM_SPONGE_OUT + k,
                    );
                    let pi_cm_slot = pis_vec[pi_cm(self.n_spends, j) + k];
                    first.assert_eq(cm_sponge_limb, pi_cm_slot);
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

            // --- Phase 4b-step3-step1.2c: sponge bank-1 rate-slot pin --
            //
            // On row 8+j (j ∈ 0..n_outputs), bind the bank-1
            // permutation's rate-slot inputs (`shared_cm.inputs[0..8]`)
            // to the 8 fe-limbs that make up the first half of the
            // 15-fe absorb: d_fes[0..2], pk_d_fes[0..4], ivk_cm_fes[0..2].
            // The low-limb fes coincide with the existing single-fe
            // proxies (`O_D`, `O_PK_D`, `O_IVK_COMMITMENT`); the 5
            // upper-limb cols are new in step 1.2c
            // (`O_D_FE1`, `O_PK_D_FE1..3`, `O_IVK_COMMITMENT_FE1`).
            //
            // Soundness gain: with this + step 1.2b (tag pin) +
            // step 1.2d (capacity carry) + step 1.2e (bank-2 output
            // binding), the prover no longer has freedom in bank-1's
            // entire 16-slot input state — every slot is either a
            // pinned constant (tag) or a pinned column. Bank-2 rate
            // slots remain step 1.2f (absorb `bank1.out + fes[8..14]`
            // + ONE padding at slot 7).
            //
            // Caveat: `O_{D,PK_D,IVK_COMMITMENT,*_FE*}` cols are NOT yet
            // constrained to the 32-byte witness fields — they are
            // data-column proxies. Step 1.3-fields adds byte→fe
            // decomposition constraints. Until then, prover malleability
            // is bounded by: whatever (d, pk_d, ivk_cm) the prover
            // picks, the sponge output is uniquely determined, and
            // step 1.3 will bind that output to PI.
            for j in 0..self.n_outputs {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 8 + j].into();
                // Map bank-1 rate slot index -> output proxy col offset.
                let slot_to_col = [
                    O_D,               // inputs[0] = d_fes[0]
                    O_D_FE1,           // inputs[1] = d_fes[1]
                    O_PK_D,            // inputs[2] = pk_d_fes[0]
                    O_PK_D_FE1,        // inputs[3] = pk_d_fes[1]
                    O_PK_D_FE2,        // inputs[4] = pk_d_fes[2]
                    O_PK_D_FE3,        // inputs[5] = pk_d_fes[3]
                    O_IVK_COMMITMENT,  // inputs[6] = ivk_cm_fes[0]
                    O_IVK_COMMITMENT_FE1, // inputs[7] = ivk_cm_fes[1]
                ];
                for k in 0..8 {
                    let rate_col = output_col::<AB::Var>(
                        local_slice,
                        self.n_spends,
                        j,
                        slot_to_col[k],
                    );
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[k])
                                - rate_col.into()),
                    );
                }
            }

            // --- Phase 4b-step3-step1.2b: sponge bank-1 capacity pin ----
            //
            // On row 8+j (j ∈ 0..n_outputs), the shared_cm block hosts
            // output j's sponge perm-1 witness (see step 1.2a trace-gen).
            // This constraint block pins the capacity slots (state[8..15])
            // to the "uno-cm-v1" tag block — a fixed constant per §3.2.
            // Together with step 1.2c (rate-slot fe-limb bindings,
            // bank1→bank2 state carry, bank2-output binding to
            // O_CM_SPONGE_OUT), this ratifies the iterated sponge
            // derivation end-to-end.
            //
            // Soundness gain right now: a malicious prover can NO LONGER
            // put arbitrary values in `shared_cm.inputs[8..15]` on rows
            // 8+j for j ∈ 0..n_outputs — they must equal the tag block.
            // Without this pin, the sponge "domain separation" would not
            // be enforced. Rate-slot pinning remains a step-1.2c job.
            let tag = uno_cm_v1_tag_block();
            for j in 0..self.n_outputs {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 8 + j].into();
                for k in 0..8 {
                    let expected_tag_fe =
                        AB::F::from_u64(tag[k].as_canonical_u64());
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[8 + k])
                                - AB::Expr::from(expected_tag_fe)),
                    );
                }
            }

            // --- Phase 4b-step3-step1.2f-out: bank-1 rate → carry col --
            //
            // On row 8+j, bind the bank-1 permutation's post-state
            // rate slots (`state[0..8]` after perm-1) to output j's
            // `O_SPONGE_CARRY_RATE[0..8]` proxy columns. Paired with
            // the -in block below, this closes the sponge-rate carry
            // chain for bank-2's absorb addition.
            for j in 0..self.n_outputs {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 8 + j].into();
                for k in 0..8 {
                    let carry_col = output_col::<AB::Var>(
                        local_slice,
                        self.n_spends,
                        j,
                        O_SPONGE_CARRY_RATE + k,
                    );
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm_out[k])
                                - carry_col.into()),
                    );
                }
            }

            // --- Phase 4b-step3-step1.2d-out: bank-1 cap → carry col ----
            //
            // On row 8+j, bind the bank-1 permutation's post-state
            // capacity slots (`state[8..15]` after perm-1) to output j's
            // `O_SPONGE_CARRY_CAP[0..8]` proxy columns. Combined with
            // the proxies-are-constant transition invariant (enforced
            // by the trailing `OUTPUT_PROXY_COLS` loop), this lets us
            // "read" the same carry-cap values on row 12+j without a
            // cross-row AIR access, which the sub-AIR interface does
            // not provide for non-adjacent rows.
            for j in 0..self.n_outputs {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 8 + j].into();
                for k in 0..8 {
                    let carry_col = output_col::<AB::Var>(
                        local_slice,
                        self.n_spends,
                        j,
                        O_SPONGE_CARRY_CAP + k,
                    );
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm_out[8 + k])
                                - carry_col.into()),
                    );
                }
            }

            // --- Phase 4b-step3-step1.2d-in: carry col → bank-2 cap -----
            //
            // On row 12+j, bind the bank-2 permutation's input capacity
            // slots (`shared_cm.inputs[8..15]`) to output j's
            // `O_SPONGE_CARRY_CAP[0..8]` proxy columns. Paired with the
            // -out block above, this closes the sponge-capacity carry
            // chain: bank-1.out.cap == carry == bank-2.in.cap, matching
            // the iterated-sponge rule that absorb does not touch the
            // capacity portion. Without this, a malicious prover could
            // substitute arbitrary capacity in bank-2 and forge a cm
            // output.
            for j in 0..self.n_outputs {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 12 + j].into();
                for k in 0..8 {
                    let carry_col = output_col::<AB::Var>(
                        local_slice,
                        self.n_spends,
                        j,
                        O_SPONGE_CARRY_CAP + k,
                    );
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[8 + k])
                                - carry_col.into()),
                    );
                }
            }

            // --- Phase 4b-step3-step1.2f-in: bank-2 rate absorb --------
            //
            // On row 12+j, bind the bank-2 permutation's input rate
            // slots (`shared_cm.inputs[0..8]`) to
            // `bank1.out.rate + fes[8..14]` (with 10* padding at
            // slot 7), using the per-row carry cols populated by
            // step 1.2f-out above. fes[8..14] map onto the upper
            // fe limbs of ivk_commitment / value / rcm:
            //
            //   inputs[0] = carry_rate[0] + O_IVK_COMMITMENT_FE2
            //   inputs[1] = carry_rate[1] + O_IVK_COMMITMENT_FE3
            //   inputs[2] = carry_rate[2] + O_VALUE
            //   inputs[3] = carry_rate[3] + O_RCM
            //   inputs[4] = carry_rate[4] + O_RCM_FE1
            //   inputs[5] = carry_rate[5] + O_RCM_FE2
            //   inputs[6] = carry_rate[6] + O_RCM_FE3
            //   inputs[7] = carry_rate[7] + ONE  (10* padding)
            //
            // Soundness: combined with step 1.2c (bank-1 rate pin),
            // 1.2b (tag pin), 1.2d (capacity carry), 1.2e (bank-2
            // output), and 1.2f-out (bank-1 output rate carry), the
            // full iterated-sponge derivation is now AIR-ratified
            // end-to-end on the (d, pk_d, ivk_cm, value, rcm) fe-limb
            // proxies. The remaining gap before step 1.3 is the
            // byte→fe decomposition of these proxies (step 1.3-fields).
            for j in 0..self.n_outputs {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 12 + j].into();
                let fe_slot_cols = [
                    O_IVK_COMMITMENT_FE2, // fes[8]
                    O_IVK_COMMITMENT_FE3, // fes[9]
                    O_VALUE,              // fes[10]
                    O_RCM,                // fes[11]
                    O_RCM_FE1,            // fes[12]
                    O_RCM_FE2,            // fes[13]
                    O_RCM_FE3,            // fes[14]
                ];
                for k in 0..7 {
                    let carry_col = output_col::<AB::Var>(
                        local_slice,
                        self.n_spends,
                        j,
                        O_SPONGE_CARRY_RATE + k,
                    );
                    let fe_col = output_col::<AB::Var>(
                        local_slice,
                        self.n_spends,
                        j,
                        fe_slot_cols[k],
                    );
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[k])
                                - (AB::Expr::from(carry_col) + AB::Expr::from(fe_col))),
                    );
                }
                // Padding slot 7: inputs[7] = carry[7] + ONE.
                let carry_col_7 = output_col::<AB::Var>(
                    local_slice,
                    self.n_spends,
                    j,
                    O_SPONGE_CARRY_RATE + 7,
                );
                builder.assert_zero(
                    sel.clone()
                        * (AB::Expr::from(shared_cm.inputs[7])
                            - (AB::Expr::from(carry_col_7)
                                + AB::Expr::from(AB::F::from_u64(1)))),
                );
            }

            // --- Phase 4b-step3-step1.2e: sponge bank-2 output ↔ OUT ----
            //
            // On row 12+j (j ∈ 0..n_outputs), the shared_cm block hosts
            // output j's sponge perm-2 witness. Its post-permutation
            // state[0..4] is the final 4-fe cm digest. This constraint
            // binds that output to the `O_CM_SPONGE_OUT[0..4]` cols in
            // output j's proxy block — a 4-fe equality per output.
            //
            // Since output proxy cols are constant-across-rows, reading
            // `O_CM_SPONGE_OUT[k]` on row 12+j gives the same value as
            // row 0 where `trace_populates_o_cm_sponge_out_from_helper`
            // checks it against `poseidon2_cm_full_sponge(...)`. This
            // two-step equivalence (AIR proves bank2-output == proxy-
            // col on row 12+j, unit test proves proxy-col == helper
            // off-circuit) means the sponge digest is AIR-ratified
            // without a separate round-trip test needing to re-run the
            // permutation in-circuit.
            //
            // Still missing from step 1.2 (tracked as step 1.2c/f):
            //   - bank-1 rate-slot fe-limb absorption
            //   - bank-2 rate-slot fe-absorb (fes[8..14] + ONE padding)
            //
            // Those are independent incremental commits.
            for j in 0..self.n_outputs {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 12 + j].into();
                for k in 0..4 {
                    let sponge_out_col = output_col::<AB::Var>(
                        local_slice,
                        self.n_spends,
                        j,
                        O_CM_SPONGE_OUT + k,
                    );
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm_out[k])
                                - sponge_out_col.into()),
                    );
                }
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

            // --- Phase 4b-step3-step2b-AIR-v2: nf iterated sponge -------
            //
            // Nullifier binding now uses the 9-fe iterated Poseidon2-w=16
            // sponge with "uno-nf-v1" tag block, byte-identical to the
            // C++ validator's `derive_nullifier` and the codec-parity
            // test's `hash_tagged(b"uno-nf-v1", 9 fes)`. Replaces the
            // step-2b-AIR-v1 single-perm attempt (commits b92a6bdbb +
            // 0e23eef30) which used a u64-constant TAG_NF at slot 0 —
            // not consensus-compatible with C++.
            //
            // Layout per spend i (rows gated by GS_ROW_SEL):
            //
            //   Bank 1 — row 16+i:
            //     shared_cm.inputs[0..4]   == nk_fes[0..4]
            //                               (S_NK, S_NK_FE1..3)
            //     shared_cm.inputs[4..8]   == leaf_fes[0..4]
            //                               (S_LEAF, S_LEAF_FE1..3)
            //     shared_cm.inputs[8..16]  == uno_nf_v1_tag_block()
            //                               (constant, 8 fes)
            //     shared_cm_out[0..8]      == S_NF_CARRY_RATE[0..8]
            //                               (carry rate → row 20+i)
            //     shared_cm_out[8..16]     == S_NF_CARRY_CAP[0..8]
            //                               (carry cap  → row 20+i)
            //
            //   Bank 2 — row 20+i:
            //     shared_cm.inputs[0]      == S_NF_CARRY_RATE[0] + pos
            //                               (fes[8] absorb = pos)
            //     shared_cm.inputs[1]      == S_NF_CARRY_RATE[1] + 1
            //                               (10* padding bit)
            //     shared_cm.inputs[k]      == S_NF_CARRY_RATE[k]
            //                               for k ∈ 2..8 (rate carry, no absorb)
            //     shared_cm.inputs[8+k]    == S_NF_CARRY_CAP[k]
            //                               for k ∈ 0..8 (capacity carry)
            //     shared_cm_out[k]         == pi_nfs[i][k] for k ∈ 0..4
            //                               (output → PI)
            //
            // Carry cols are output-proxy-constant-across-rows per the
            // existing SPEND_PROXY_COLS transition loop, so bank-1 row
            // 16+i pins them and bank-2 row 20+i reads them — standard
            // cross-row-via-proxy trick, mirror of step 1.2d/f.
            //
            // Soundness: nf binding goes from 64-bit (narrow-nf u64
            // proxy) to 256-bit (real 32-byte nk + 32-byte cm absorbed
            // into the full 16-fe sponge state with domain-separated
            // tag).
            let nf_tag_block = uno_nf_v1_tag_block();

            // Bank-1 input pin + bank-1 output → carry cols (row 16+i).
            for i in 0..self.n_spends {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 16 + i].into();
                let nk_cols = [
                    spend_col::<AB::Var>(local_slice, i, S_NK),
                    spend_col::<AB::Var>(local_slice, i, S_NK_FE1),
                    spend_col::<AB::Var>(local_slice, i, S_NK_FE2),
                    spend_col::<AB::Var>(local_slice, i, S_NK_FE3),
                ];
                let leaf_cols = [
                    spend_col::<AB::Var>(local_slice, i, S_LEAF),
                    spend_col::<AB::Var>(local_slice, i, S_LEAF_FE1),
                    spend_col::<AB::Var>(local_slice, i, S_LEAF_FE2),
                    spend_col::<AB::Var>(local_slice, i, S_LEAF_FE3),
                ];
                // inputs[0..4] = nk_fes
                for (k, col) in nk_cols.iter().enumerate() {
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[k]) - (*col).into()),
                    );
                }
                // inputs[4..8] = leaf_fes
                for (k, col) in leaf_cols.iter().enumerate() {
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[4 + k]) - (*col).into()),
                    );
                }
                // inputs[8..16] = "uno-nf-v1" tag block (constant)
                for k in 0..8 {
                    let tag_fe = AB::F::from_u64(nf_tag_block[k].as_canonical_u64());
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[8 + k])
                                - AB::Expr::from(tag_fe)),
                    );
                }
                // shared_cm_out[0..8] (bank-1 rate) → S_NF_CARRY_RATE
                for k in 0..8 {
                    let carry_col = spend_col::<AB::Var>(local_slice, i, S_NF_CARRY_RATE0 + k);
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm_out[k]) - carry_col.into()),
                    );
                }
                // shared_cm_out[8..16] (bank-1 cap) → S_NF_CARRY_CAP
                for k in 0..8 {
                    let carry_col = spend_col::<AB::Var>(local_slice, i, S_NF_CARRY_CAP0 + k);
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm_out[8 + k]) - carry_col.into()),
                    );
                }
            }

            // Bank-2 input absorb + bank-2 output → PI (row 20+i).
            for i in 0..self.n_spends {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 20 + i].into();
                let pos = spend_col::<AB::Var>(local_slice, i, S_POS);
                // inputs[0] = carry_rate[0] + pos
                let carry_rate_0 = spend_col::<AB::Var>(local_slice, i, S_NF_CARRY_RATE0);
                builder.assert_zero(
                    sel.clone()
                        * (AB::Expr::from(shared_cm.inputs[0])
                            - (AB::Expr::from(carry_rate_0) + pos.into())),
                );
                // inputs[1] = carry_rate[1] + 1  (10* padding bit)
                let carry_rate_1 = spend_col::<AB::Var>(local_slice, i, S_NF_CARRY_RATE0 + 1);
                builder.assert_zero(
                    sel.clone()
                        * (AB::Expr::from(shared_cm.inputs[1])
                            - (AB::Expr::from(carry_rate_1)
                                + AB::Expr::from(AB::F::from_u64(1)))),
                );
                // inputs[2..8] = carry_rate[2..8]  (rate carry, no absorb)
                for k in 2..8 {
                    let carry_col = spend_col::<AB::Var>(local_slice, i, S_NF_CARRY_RATE0 + k);
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[k]) - carry_col.into()),
                    );
                }
                // inputs[8..16] = carry_cap[0..8]  (capacity carry)
                for k in 0..8 {
                    let carry_col = spend_col::<AB::Var>(local_slice, i, S_NF_CARRY_CAP0 + k);
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[8 + k]) - carry_col.into()),
                    );
                }
                // Claim 4: bind all 4 limbs of `nf_i` to the PI.
                for limb in 0..4 {
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm_out[limb]) - pi_nfs[i][limb].into()),
                    );
                }
            }

            // Silence "unused" warning on the narrow block's output
            // binding — kept in scope above for ivk_cm (claim 3) which
            // still runs on narrow rows 0..(n_spends-1).
            let _ = shared_ivkcm_nf_out;
        }

        // ---- Phase 4b-step3-step1.3-fields: fe-limb u16 decomposition ---
        //
        // For each of the 14 output fe-limb proxy cols (d_fes[0..2],
        // pk_d_fes[0..4], ivk_cm_fes[0..4], rcm_fes[0..4]), constrain
        // that the fe-limb col equals the u64 reconstruction of its 4
        // new u16 sub-limb cols:
        //
        //   fe_limb == Σ_{k=0..3} limb_k · 2^{16k}
        //
        // Combined with the cross-AIR `u16_range` LogUp that bounds
        // each `limb_k` to `0..=0xffff`, this proves the fe-limb is
        // the canonical u64 of the corresponding 8-byte LE chunk of
        // the 32-byte witness field — exactly what `pack_*_as_*fe`
        // emits off-circuit. Closes the step 1.2c/f decoupling gap:
        // a malicious prover can no longer put arbitrary Goldilocks
        // values in the sponge rate slots.
        //
        // Same decomposition pattern as the existing `O_VALUE_LIMB0`
        // constraint in the first-row block above. These constraints
        // are NOT row-gated — they hold on every row, which is sound
        // because both the fe-limb and limb cols are in the proxy
        // block (constant-across-rows per §4.2 transition invariant).
        //
        // Note: `O_VALUE` (fes[10]) is already covered by the existing
        // `O_VALUE_LIMB0..3` decomposition in the first-row block, so
        // it is NOT included here (no duplicate cols).
        {
            // (fe_col_offset, limb_base_offset) pairs for the 14
            // output fe-limbs that need decomposition.
            let fe_limb_pairs: [(usize, usize); 14] = [
                // d_fes[0..2] → O_D_LIMB0..O_D_LIMB0+8
                (O_D,                  O_D_LIMB0),
                (O_D_FE1,              O_D_LIMB0 + 4),
                // pk_d_fes[0..4] → O_PK_D_LIMB0..O_PK_D_LIMB0+16
                (O_PK_D,               O_PK_D_LIMB0),
                (O_PK_D_FE1,           O_PK_D_LIMB0 + 4),
                (O_PK_D_FE2,           O_PK_D_LIMB0 + 8),
                (O_PK_D_FE3,           O_PK_D_LIMB0 + 12),
                // ivk_cm_fes[0..4] → O_IVK_COMMITMENT_LIMB0..+16
                (O_IVK_COMMITMENT,     O_IVK_COMMITMENT_LIMB0),
                (O_IVK_COMMITMENT_FE1, O_IVK_COMMITMENT_LIMB0 + 4),
                (O_IVK_COMMITMENT_FE2, O_IVK_COMMITMENT_LIMB0 + 8),
                (O_IVK_COMMITMENT_FE3, O_IVK_COMMITMENT_LIMB0 + 12),
                // rcm_fes[0..4] → O_RCM_LIMB0..+16
                (O_RCM,                O_RCM_LIMB0),
                (O_RCM_FE1,            O_RCM_LIMB0 + 4),
                (O_RCM_FE2,            O_RCM_LIMB0 + 8),
                (O_RCM_FE3,            O_RCM_LIMB0 + 12),
            ];
            for j in 0..self.n_outputs {
                for (fe_col_offset, limb_base_offset) in &fe_limb_pairs {
                    let fe_col: AB::Var =
                        output_col(local_slice, self.n_spends, j, *fe_col_offset);
                    let mut recon: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                    for k in 0..4 {
                        let limb: AB::Var = output_col(
                            local_slice,
                            self.n_spends,
                            j,
                            *limb_base_offset + k,
                        );
                        let weight = AB::F::from_u64(1u64 << (16 * k));
                        recon = recon + AB::Expr::from(weight) * limb.into();
                    }
                    builder.assert_zero(fe_col.into() - recon);
                }
            }
        }

        // ---- Phase 4b-step3-step2b-decomp: spend fe-limb u16 decomp ----
        //
        // Spend-side mirror of the output-side step 1.3-fields block
        // above. For each of the 8 spend fe-limb proxy cols
        // (nk_fes[0..4], leaf_fes[0..4]), constrain that the fe-limb
        // col equals the u64 reconstruction of its 4 new u16 sub-limb
        // cols:
        //
        //   fe_limb == Σ_{k=0..3} limb_k · 2^{16k}
        //
        // Combined with the cross-AIR `u16_range` LogUp that bounds
        // each `limb_k` to `0..=0xffff`, this proves each spend fe-limb
        // is the canonical u64 of the corresponding 8-byte LE chunk of
        // the 32-byte `s.nk` / `s.leaf` witness field — exactly what
        // `pack_32b_as_4fe(...)` emits off-circuit.
        //
        // Unblocks step 2b-AIR (nf Poseidon2 with real 4-fe inputs):
        // that step will pin the nf sponge absorb layout to these
        // newly-ratified fe-limb cols, so the prover can no longer
        // pick non-canonical Goldilocks values for the nf input rate
        // slots. This commit adds only the cols + decomposition +
        // LogUp receives; the nf sponge still uses `S_NK` / `S_LEAF`
        // as single-u64 proxies until step 2b-AIR lands.
        //
        // Not row-gated — both fe-limb and limb cols live in the
        // proxy block (constant-across-rows per §4.2).
        {
            // (fe_col_offset, limb_base_offset) pairs for the 8 spend
            // fe-limbs that need decomposition.
            let fe_limb_pairs: [(usize, usize); 8] = [
                // nk_fes[0..4] → S_NK_LIMB0..S_NK_LIMB0+16
                (S_NK,         S_NK_LIMB0),
                (S_NK_FE1,     S_NK_LIMB0 + 4),
                (S_NK_FE2,     S_NK_LIMB0 + 8),
                (S_NK_FE3,     S_NK_LIMB0 + 12),
                // leaf_fes[0..4] → S_LEAF_LIMB0..S_LEAF_LIMB0+16
                (S_LEAF,       S_LEAF_LIMB0),
                (S_LEAF_FE1,   S_LEAF_LIMB0 + 4),
                (S_LEAF_FE2,   S_LEAF_LIMB0 + 8),
                (S_LEAF_FE3,   S_LEAF_LIMB0 + 12),
            ];
            for i in 0..self.n_spends {
                for (fe_col_offset, limb_base_offset) in &fe_limb_pairs {
                    let fe_col: AB::Var = spend_col(local_slice, i, *fe_col_offset);
                    let mut recon: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                    for k in 0..4 {
                        let limb: AB::Var =
                            spend_col(local_slice, i, *limb_base_offset + k);
                        let weight = AB::F::from_u64(1u64 << (16 * k));
                        recon = recon + AB::Expr::from(weight) * limb.into();
                    }
                    builder.assert_zero(fe_col.into() - recon);
                }
            }
        }

        // ---- Per-row Merkle row-loop constraints (step 3a: 4-fe) --------
        //
        // Let `is_merkle = Σ_k GS_ROW_SEL[k]`. On Merkle rows (0..31)
        // `is_merkle = 1`; on padding rows (32..63) `is_merkle = 0`.
        //
        // Per-row selected bit `b = Σ_k sel[k] · bit_k` and selected
        // 4-fe sibling `sib_sel_fes[m] = Σ_k sel[k] · sib[k][m]` for
        // `m ∈ 0..4`.
        //
        // Active rows: bind P2.inputs[0..4] to `left_fes[4]` and
        //   inputs[4..8] to `right_fes[4]`, where
        //     left_fes = (1-b)·cur_fes + b·sib_sel_fes
        //     right_fes = b·cur_fes + (1-b)·sib_sel_fes.
        //   Assert `next.S_CURRENT_FE[m] = P2.output[m]` for all 4 fes.
        //   NOTE: the previous `inputs[pad] == 0` zero-pad assertion for
        //   slots 2..8 is DELETED — post step 3a every slot 0..7 carries
        //   a pinned expression (left|right), not a zero pad.
        // Inactive rows: latch `next.S_CURRENT_FE[m] = S_CURRENT_FE[m]`.
        //   P2.inputs are unconstrained (prover fills zero-input
        //   permutation witness).
        //
        // Last row: all 4 digest fes must equal `PI[PI_ANCHOR + 0..4]`.
        // The Phase 4b-step1 / step2b `G_ANCHOR_LIMB*` global cols are
        // retired; the anchor is now end-to-end AIR-derived from the
        // 4-fe leaf + 4-fe siblings through 32 Poseidon2-w=8
        // `(left ‖ right) → out` compressions.
        {
            // is_merkle as a reusable expression (sum of selectors on the
            // current row).
            let mut is_merkle: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
            for k in 0..MERKLE_DEPTH {
                is_merkle = is_merkle + AB::Expr::from(local_slice[GS_ROW_SEL0 + k]);
            }

            for i in 0..self.n_spends {
                // Per-row selected bit `b_sel = Σ_k sel_k · bit_k`.
                let mut b_sel: AB::Expr = AB::Expr::from(AB::F::from_u64(0));
                for k in 0..MERKLE_DEPTH {
                    let sel: AB::Expr = local_slice[GS_ROW_SEL0 + k].into();
                    let bit_k: AB::Var = spend_col(local_slice, i, S_PATH_BIT0 + k);
                    b_sel = b_sel + sel * bit_k.into();
                }

                // Per-row selected 4-fe sibling `sib_sel_fes[m] = Σ_k sel_k
                // · sib[k][m]`.
                let mut sib_sel_fes: [AB::Expr; SIBLING_FES_PER_LEVEL] =
                    core::array::from_fn(|_| AB::Expr::from(AB::F::from_u64(0)));
                for k in 0..MERKLE_DEPTH {
                    let sel: AB::Expr = local_slice[GS_ROW_SEL0 + k].into();
                    for m in 0..SIBLING_FES_PER_LEVEL {
                        let sib_km: AB::Var = spend_col(
                            local_slice,
                            i,
                            S_SIBLING0 + SIBLING_FES_PER_LEVEL * k + m,
                        );
                        sib_sel_fes[m] = sib_sel_fes[m].clone() + sel.clone() * sib_km.into();
                    }
                }

                let one_minus_b: AB::Expr =
                    AB::Expr::from(AB::F::from_u64(1)) - b_sel.clone();
                let cur_fes: [AB::Expr; 4] = core::array::from_fn(|m| {
                    local_slice[spend_var_offset(i) + S_CURRENT_FE0 + m].into()
                });
                let left_fes: [AB::Expr; 4] = core::array::from_fn(|m| {
                    one_minus_b.clone() * cur_fes[m].clone()
                        + b_sel.clone() * sib_sel_fes[m].clone()
                });
                let right_fes: [AB::Expr; 4] = core::array::from_fn(|m| {
                    b_sel.clone() * cur_fes[m].clone()
                        + one_minus_b.clone() * sib_sel_fes[m].clone()
                });

                let merkle = spend_p2_group::<AB::Var>(local_slice, i, SpendP2::Merkle);
                // Active-row input bindings (gated by is_merkle): pin all
                // 8 rate slots to (left[4] ‖ right[4]). No zero-pad.
                for m in 0..4 {
                    builder.assert_zero(
                        is_merkle.clone()
                            * (AB::Expr::from(merkle.inputs[m]) - left_fes[m].clone()),
                    );
                    builder.assert_zero(
                        is_merkle.clone()
                            * (AB::Expr::from(merkle.inputs[4 + m]) - right_fes[m].clone()),
                    );
                }

                // Transition: advance (active) or latch (inactive) each
                // of the 4 running-digest cols.
                let one_minus_is_merkle: AB::Expr =
                    AB::Expr::from(AB::F::from_u64(1)) - is_merkle.clone();
                let mut t = builder.when_transition();
                for m in 0..4 {
                    let next_cur_m: AB::Expr =
                        next_slice[spend_var_offset(i) + S_CURRENT_FE0 + m].into();
                    let cur_m: AB::Expr = cur_fes[m].clone();
                    let p2_out_m: AB::Expr = AB::Expr::from(
                        merkle.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[m],
                    );
                    t.assert_zero(is_merkle.clone() * (next_cur_m.clone() - p2_out_m));
                    t.assert_zero(one_minus_is_merkle.clone() * (next_cur_m - cur_m));
                }
            }

            // Last-row anchor binding: after 32 active rows + latching on
            // rows 32..63, `S_CURRENT_FE[0..4]` on the last row is the
            // final Merkle root, which must equal the 4 limbs of the
            // tx-level anchor PI.
            let mut last = builder.when_last_row();
            for i in 0..self.n_spends {
                for m in 0..4 {
                    last.assert_eq(
                        local_slice[spend_var_offset(i) + S_CURRENT_FE0 + m],
                        pis_vec[PI_ANCHOR + m],
                    );
                }
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
    /// Raw 32-byte spent-note commitment `cm` (= Merkle leaf). Phase 4b-
    /// step3-step2a widened from `u64` single-fe proxy so tosctl can
    /// thread the real 32-byte note commitment through. The AIR in its
    /// current (pre-step2b) shape still derives a u64 proxy internally
    /// via `first_u64_proxy(&s.leaf)` — narrow-nf claim 4 and the
    /// per-spend Merkle walk both still use the low 8 bytes only.
    /// Step 2b will add 4-fe leaf decomposition cols + widen the nf
    /// derivation to consume them in-circuit.
    pub leaf: [u8; 32],
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
    /// 32-level Merkle path: each entry is the raw 32-byte sibling hash
    /// at level `k`. Level 0 is the first layer above the leaf. Phase
    /// 4b-step3-step3c widened from `u64` single-fe proxy (per-entry)
    /// to `[u8; 32]` so tosctl can thread the real 32-byte sibling
    /// digests through. The AIR in its current (pre-step3a) shape
    /// still derives a single-fe proxy via
    /// `first_u64_proxy(&s.merkle_path[k])` (low 8 bytes) for the
    /// legacy single-fe Merkle walk — no AIR logic changes here.
    /// Step 3a will lift the Merkle walk to a 4-fe state by
    /// decomposing each sibling via `pack_32b_as_4fe` for the
    /// `(left[4] ‖ right[4]) → out[4]` compression.
    pub merkle_path: [[u8; 32]; MERKLE_DEPTH],
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
    /// Legacy single-u64 anchor proxy (pre-step-3a Merkle-walk output).
    /// Phase 4b-step3-step3a: kept for wire-compat; AIR no longer reads.
    /// The post-step-3a AIR derives all 4 anchor limbs from the 4-fe
    /// Merkle walk and binds them directly to `PI[PI_ANCHOR + 0..4]`;
    /// this field plays no role in the constraint system. Full wire-
    /// field deletion is a follow-up.
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
        // Legacy single-fe anchor_proxy — kept for wire-compat with
        // the MvpWitness.anchor_proxy field (Phase 4b-step3-step3a
        // retired the AIR reader of this field but the wire layout
        // still carries it). NOT the anchor the AIR binds to PI —
        // see `anchor_bytes` below, which is the 4-fe walk output.
        let shared_anchor =
            poseidon2_merkle_path_root(&perm, shared_leaf, shared_pos, &shared_path)
                .as_canonical_u64();

        // Phase 4b-step3-step3c: widen siblings from `[u64; 32]` to
        // `[[u8; 32]; 32]`. Fixture projects each legacy u64 proxy into
        // bytes[0..8] with zero pad (same 8-byte-low-limb convention
        // as leaf / d / nk above); real tosctl witnesses now carry
        // full 32-byte sibling digests.
        let mut shared_path_bytes = [[0u8; 32]; MERKLE_DEPTH];
        for k in 0..MERKLE_DEPTH {
            shared_path_bytes[k][0..8].copy_from_slice(&shared_path[k].to_le_bytes());
        }

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
            // Phase 4b-step3-step2a: widen leaf from single-fe u64 to
            // [u8; 32]. Fixture projects the legacy u64 proxy into
            // bytes[0..8] with zero pad (same 8-byte-low-limb convention
            // as d/pk_d/ivk/rcm above); real tosctl witnesses now carry
            // the full 32-byte note commitment.
            let mut leaf_bytes = [0u8; 32];
            leaf_bytes[0..8].copy_from_slice(&shared_leaf.to_le_bytes());
            spends.push(SpendWitness {
                leaf: leaf_bytes,
                d: d_word.to_le_bytes(),
                value: v_per_spend,
                ivk: ivk_bytes,
                pk_d: pk_d_bytes,
                rcm: rcm_bytes,
                nk: nk_bytes,
                pos: shared_pos,
                merkle_path: shared_path_bytes,
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
            // Phase 4b-step3-step1.3-pi: synthesize cm_bytes from the
            // 15-fe iterated-sponge output so the AIR's new PI binding
            // (`O_CM_SPONGE_OUT[0..4] == PI[pi_cm(j) + 0..4]`) holds.
            // Pre-step-1.3 this fixture projected only `poseidon2_cm_fe`
            // (the OLD single-perm 6-input u64-proxy Poseidon2) into
            // cm_bytes[0..8], which diverges from the sponge output and
            // would break the round-trip here.
            let sponge_out = poseidon2_cm_full_sponge(
                &perm16,
                &d_bytes,
                &pk_d_bytes,
                &ivk_commitment_bytes,
                value,
                &rcm_bytes,
            );
            let mut cm_bytes = [0u8; 32];
            for k in 0..4 {
                cm_bytes[k * 8..(k + 1) * 8]
                    .copy_from_slice(&sponge_out[k].as_canonical_u64().to_le_bytes());
            }
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

        // Phase 4b-step3-step3a: compute `anchor_bytes` as the output
        // of the 4-fe Merkle walk (matching the AIR's post-step-3a
        // last-row binding `S_CURRENT_FE[0..4] == PI[PI_ANCHOR+0..4]`
        // where `PI[PI_ANCHOR+k] = encode_256(anchor_bytes)[k]`).
        // The low 8 bytes are no longer `shared_anchor.to_le_bytes()`
        // — that was the legacy single-u64-proxy walk, which is a
        // different digest; only the 4-fe walk matches the in-circuit
        // computation.
        //
        // We still pick a representative `s` from `spends` to thread
        // (leaf, pos, merkle_path) — all spends share the same path
        // per this fixture's convention.
        let leaf0_bytes = &spends[0].leaf;
        let path0 = &spends[0].merkle_path;
        let anchor_bytes = poseidon2_merkle_path_root_4fe_bytes(
            &perm,
            leaf0_bytes,
            shared_pos,
            path0,
        );

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
        // Per-spend: leaf(32) + d(8) + value(8) + pos(8)
        //          + ivk(32) + pk_d(32) + rcm(32) + nk(32)
        //          + path(32*MERKLE_DEPTH) + rk_bytes(32)
        //          = 32 + 24 + 4·32 + 1024 + 32 = 1240.
        // Phase 4b-step3-step2a widened leaf from u64 (8 B) to [u8;32]
        // (448 -> 472, +24 B/spend).
        // Phase 4b-step3-step3c widened per-level Merkle sibling from
        // u64 (8 B) to [u8;32] so tosctl can thread real 32-byte
        // sibling digests through. Net wire bump per spend:
        // (32-8)·MERKLE_DEPTH = 24·32 = +768 B (472 -> 1240).
        const PER_SPEND: usize = 32 + 3 * 8 + 4 * 32 + 32 * MERKLE_DEPTH + 32;
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
            out.extend_from_slice(&s.leaf);
            out.extend_from_slice(&s.d);
            out.extend_from_slice(&s.value.to_le_bytes());
            out.extend_from_slice(&s.ivk);
            out.extend_from_slice(&s.pk_d);
            out.extend_from_slice(&s.rcm);
            out.extend_from_slice(&s.nk);
            out.extend_from_slice(&s.pos.to_le_bytes());
            for sib in &s.merkle_path {
                out.extend_from_slice(sib);
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
        const PER_SPEND: usize = 32 + 3 * 8 + 4 * 32 + 32 * MERKLE_DEPTH + 32;
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
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
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
            let mut merkle_path = [[0u8; 32]; MERKLE_DEPTH];
            for sib in merkle_path.iter_mut() {
                sib.copy_from_slice(&bytes[off..off + 32]);
                off += 32;
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

        let perm16 = default_goldilocks_poseidon2_16();

        for s in &self.spends {
            // nf_i: 4-limb Poseidon2 nullifier (AIR-bound).
            // Phase 4b-step3-step2b-AIR: nf now derived from the real
            // 32-byte `nk` + 32-byte `leaf` (cm) + `pos` via a single
            // Poseidon2-w=16 permutation on shared-wide row 16+i, per
            // the AIR constraint block. Matches the C++ validator's
            // `derive_nullifier` which consumes the same 10-fe input.
            let nf_limbs = poseidon2_nf_full_wide(&perm16, &s.nk, &s.leaf, s.pos);
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
        // Phase 4b-step3-step3a: running Merkle digest is now 4-fe per
        // row. Previously `Vec<Vec<Goldilocks>>` (single-fe).
        let mut s_current_vals_fes: Vec<Vec<[Goldilocks; 4]>> = Vec::with_capacity(n_s);
        let mut row0_spend_ivkcm = Vec::with_capacity(n_s);
        let mut row0_spend_cm = Vec::with_capacity(n_s);
        for s in &self.spends {
            let d_word = u64::from_le_bytes(s.d);
            let d_f = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
            // Phase 4b-step3-step0: widened fields → u64 proxy via
            // first_u64_proxy; AIR inputs unchanged.
            let pk_d_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.pk_d)));
            let rcm_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.rcm)));
            let ivk_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.ivk)));
            let value_f = Goldilocks::from_u64(reduce_to_goldilocks(s.value));
            let ivkcm_fe = poseidon2_ivk_commitment(&perm, first_u64_proxy(&s.ivk), d_word);

            // Phase 4b-step3-step3a: 4-fe Merkle walk. Level k goes on
            // trace row k. Each level performs a Poseidon2-w=8
            // `(left[4] ‖ right[4]) → out[4]` compression with `left` /
            // `right` selected by path bit `(pos >> k) & 1`. State is
            // decomposed as `pack_32b_as_4fe` throughout.
            let leaf_fes: [Goldilocks; 4] = pack_32b_as_4fe(&s.leaf);
            let mut cur_state: [Goldilocks; 4] = leaf_fes;
            let mut per_spend_merkle = Vec::with_capacity(TRACE_HEIGHT);
            let mut per_spend_current_fes: Vec<[Goldilocks; 4]> =
                Vec::with_capacity(TRACE_HEIGHT);
            per_spend_current_fes.push(cur_state);
            for k in 0..MERKLE_DEPTH {
                let bit = (s.pos >> k) & 1;
                let sib_fes: [Goldilocks; 4] = pack_32b_as_4fe(&s.merkle_path[k]);
                let (left, right) = if bit == 0 {
                    (cur_state, sib_fes)
                } else {
                    (sib_fes, cur_state)
                };
                let mut input = [Goldilocks::ZERO; POSEIDON2_WIDTH];
                for m in 0..4 {
                    input[m] = left[m];
                }
                for m in 0..4 {
                    input[4 + m] = right[m];
                }
                let mut state = input;
                perm.permute_mut(&mut state);
                per_spend_merkle.push(gen_p2_row(input));
                cur_state = [state[0], state[1], state[2], state[3]];
                per_spend_current_fes.push(cur_state);
            }
            // Latch rows 32..63: pad P2 with zero-input permutation, and
            // hold the 4-fe running digest at the final anchor value.
            while per_spend_merkle.len() < TRACE_HEIGHT {
                per_spend_merkle.push(padding_p2.clone());
            }
            while per_spend_current_fes.len() < TRACE_HEIGHT {
                per_spend_current_fes.push(cur_state);
            }
            debug_assert_eq!(per_spend_merkle.len(), TRACE_HEIGHT);
            debug_assert_eq!(per_spend_current_fes.len(), TRACE_HEIGHT);
            merkle_rows.push(per_spend_merkle);
            s_current_vals_fes.push(per_spend_current_fes);

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

        }

        // Phase 4b-step3-step2b-AIR-v2: nf iterated-sponge witness per
        // spend. Bank-1 lives on shared_cm row 16+i, bank-2 on row
        // 20+i. Mirror of the cm sponge (step 1.2a) with 9-fe input
        // instead of 15-fe:
        //
        //   Bank 1: state[0..8]  = (nk_fes[0..4], cm_fes[0..4])
        //           state[8..16] = pack_tag_block("uno-nf-v1")
        //   Bank 2: state[0]     = bank1_out[0] + pos
        //           state[1]     = bank1_out[1] + 1 (10* padding)
        //           state[2..8]  = bank1_out[2..8]
        //           state[8..16] = bank1_out[8..16]
        //
        // Output bank2[0..4] → PI[pi_nf(i) + 0..4]. Byte-identical to
        // `uno/crypto/poseidon2.cpp::derive_nullifier` and the codec-
        // parity helper `hash_tagged(b"uno-nf-v1", 9 fes)`.
        //
        // Bank-1 output rate + capacity captured for the per-spend
        // `S_NF_CARRY_{CAP,RATE}[0..8]` proxy cols; AIR constraints
        // then bind bank-2 inputs to those carried values + 10*
        // padding + pos absorb.
        let nf_tag_block = uno_nf_v1_tag_block();
        let mut spend_nf_bank1: Vec<Vec<Goldilocks>> = Vec::with_capacity(n_s);
        let mut spend_nf_bank2: Vec<Vec<Goldilocks>> = Vec::with_capacity(n_s);
        let mut spend_nf_out_cap: Vec<[Goldilocks; 8]> = Vec::with_capacity(n_s);
        let mut spend_nf_out_rate: Vec<[Goldilocks; 8]> = Vec::with_capacity(n_s);
        for s in &self.spends {
            let nk_fes = pack_32b_as_4fe(&s.nk);
            let leaf_fes = pack_32b_as_4fe(&s.leaf);
            // Bank 1 input: (nk_fes, leaf_fes) into rate slots; tag
            // block into capacity slots.
            let mut bank1_in = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
            bank1_in[0..4].copy_from_slice(&nk_fes);
            bank1_in[4..8].copy_from_slice(&leaf_fes);
            bank1_in[8..16].copy_from_slice(&nf_tag_block);
            spend_nf_bank1.push(gen_p2_row_16(bank1_in));

            // Bank-1 post-permutation state (off-circuit; matches what
            // the Poseidon2-w=16 sub-AIR emits on row 16+i).
            let mut state_after_perm1 = bank1_in;
            perm16.permute_mut(&mut state_after_perm1);

            let mut out_cap = [Goldilocks::ZERO; 8];
            out_cap.copy_from_slice(&state_after_perm1[8..16]);
            spend_nf_out_cap.push(out_cap);
            let mut out_rate = [Goldilocks::ZERO; 8];
            out_rate.copy_from_slice(&state_after_perm1[0..8]);
            spend_nf_out_rate.push(out_rate);

            // Bank 2 input: absorb pos at slot 0, ONE padding at slot 1,
            // rest of rate carried from bank1, capacity carried from
            // bank1.
            let mut bank2_in = state_after_perm1;
            bank2_in[0] = bank2_in[0] + Goldilocks::from_u64(reduce_to_goldilocks(s.pos));
            bank2_in[1] = bank2_in[1] + Goldilocks::ONE;
            spend_nf_bank2.push(gen_p2_row_16(bank2_in));
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

        // Phase 4b-step3-step1.2a: pre-compute the Poseidon2-w=16
        // permutation witnesses for the 15-fe iterated sponge, one
        // per output. Each output j produces two permutations:
        //
        //   sponge_bank1_cm[j] — perm-1: state[0..7] = fes[0..8],
        //                        state[8..15] = tag_block. Placed on
        //                        trace row 8+j.
        //   sponge_bank2_cm[j] — perm-2: bank1.output with fes[8..14]
        //                        absorbed into slots 0..6 + ONE padding
        //                        at slot 7; state[8..15] unchanged from
        //                        bank1. Placed on trace row 12+j.
        //
        // These reuse the existing G_CM_SHARED_P2_16 column block (rows
        // 8..15 and 12..15 were `padding_p2_16` before this commit), so
        // no new global cols are added. The Poseidon2-w=16 AIR
        // constraints (`eval_poseidon2_16` on every row) apply uniformly
        // — any valid round-by-round witness satisfies them. Step
        // 1.2b+ will add row-gated constraints that bind bank1 inputs
        // to the 15-fe absorption layout and bank2 output to
        // `O_CM_SPONGE_OUT[0..4]`; today this commit just fills the
        // trace cells.
        let tag_block = uno_cm_v1_tag_block();
        let mut sponge_bank1_cm: Vec<Vec<Goldilocks>> = Vec::with_capacity(n_o);
        let mut sponge_bank2_cm: Vec<Vec<Goldilocks>> = Vec::with_capacity(n_o);
        // Phase 4b-step3-step1.2d: save bank-1 output capacity
        // (state[8..16] after perm-1) per output so the output proxy
        // block can carry it via `O_SPONGE_CARRY_CAP[0..8]`.
        let mut sponge_bank1_out_cap: Vec<[Goldilocks; 8]> = Vec::with_capacity(n_o);
        // Phase 4b-step3-step1.2f: save bank-1 output rate slots
        // (state[0..8] after perm-1) per output so the output proxy
        // block can carry them via `O_SPONGE_CARRY_RATE[0..8]`.
        let mut sponge_bank1_out_rate: Vec<[Goldilocks; 8]> = Vec::with_capacity(n_o);
        for o in &self.outputs {
            // Assemble the 15-fe input per §3.2.
            let d_fes = pack_diversifier_as_2fe(&o.d);
            let pk_d_fes = pack_32b_as_4fe(&o.pk_d);
            let ivk_cm_fes = pack_32b_as_4fe(&o.ivk_commitment);
            let value_fe = Goldilocks::from_u64(reduce_to_goldilocks(o.value));
            let rcm_fes = pack_32b_as_4fe(&o.rcm);
            let mut fes = [Goldilocks::ZERO; 15];
            fes[0] = d_fes[0];
            fes[1] = d_fes[1];
            fes[2..6].copy_from_slice(&pk_d_fes);
            fes[6..10].copy_from_slice(&ivk_cm_fes);
            fes[10] = value_fe;
            fes[11..15].copy_from_slice(&rcm_fes);

            // Bank 1 input: state[0..7] = fes[0..8], state[8..15] = tag_block.
            let mut bank1_in = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
            bank1_in[0..8].copy_from_slice(&fes[0..8]);
            bank1_in[8..16].copy_from_slice(&tag_block);
            sponge_bank1_cm.push(gen_p2_row_16(bank1_in));

            // Post-perm-1 state (off-circuit, matches the Poseidon2Cols
            // `ending_full_rounds[last].post` field in trace).
            let mut state_after_perm1 = bank1_in;
            perm16.permute_mut(&mut state_after_perm1);

            // Save bank-1 output capacity for carry-col population.
            let mut out_cap = [Goldilocks::ZERO; 8];
            out_cap.copy_from_slice(&state_after_perm1[8..16]);
            sponge_bank1_out_cap.push(out_cap);
            // Save bank-1 output rate slots for carry-col population
            // (step 1.2f).
            let mut out_rate = [Goldilocks::ZERO; 8];
            out_rate.copy_from_slice(&state_after_perm1[0..8]);
            sponge_bank1_out_rate.push(out_rate);

            // Bank 2 input: bank1_output[0..6] += fes[8..14];
            //               bank1_output[7] += ONE (padding, rem=7);
            //               bank1_output[8..15] unchanged.
            let mut bank2_in = state_after_perm1;
            for j in 0..7 {
                bank2_in[j] = bank2_in[j] + fes[8 + j];
            }
            bank2_in[7] = bank2_in[7] + Goldilocks::from_u64(1);
            sponge_bank2_cm.push(gen_p2_row_16(bank2_in));
        }

        // Per-spend proxy vector: [leaf, d, value, ivk, ivk_cm_claim, pk_d,
        // rcm, nk, pos, path_bits[0..32], siblings[0..32],
        // value_bits[0..64]].
        let spend_proxies: Vec<Vec<Goldilocks>> = self
            .spends
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let d_word = u64::from_le_bytes(s.d);
                let d_f = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
                let ivkcm_fe = poseidon2_ivk_commitment(&perm, first_u64_proxy(&s.ivk), d_word);
                let mut v = Vec::with_capacity(SPEND_PROXY_COLS);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.leaf))));
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
                // Phase 4b-step3-step3a: 4 fes per level via
                // `pack_32b_as_4fe(&s.merkle_path[k])`. Was 1 u64-proxy
                // per level pre-step-3a. Total sibling cols:
                // `MERKLE_DEPTH · SIBLING_FES_PER_LEVEL = 32 · 4 = 128`.
                for k in 0..MERKLE_DEPTH {
                    let sib_fes = pack_32b_as_4fe(&s.merkle_path[k]);
                    for m in 0..SIBLING_FES_PER_LEVEL {
                        v.push(sib_fes[m]);
                    }
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
                // Phase 4b-step3-step2b-decomp: 6 upper-fe proxy cols
                // (3 each for nk + leaf) + 32 u16 limb cols (4 fes ×
                // 4 u16 × 2 fields). Spend-side mirror of the output-
                // side step 1.3-fields block. Low fes (`S_NK`, `S_LEAF`)
                // are already pushed above at `S_NK` / `S_LEAF`
                // positions; only the upper 3 fes per field are pushed
                // here. The u16 limb blocks decompose ALL 4 fes per
                // field (so the AIR can bind the existing low-fe proxy
                // col to its limbs too).
                let nk_fes = pack_32b_as_4fe(&s.nk);
                let leaf_fes = pack_32b_as_4fe(&s.leaf);
                // S_NK_FE1..3 (upper 3 fes of nk).
                v.push(nk_fes[1]);
                v.push(nk_fes[2]);
                v.push(nk_fes[3]);
                // S_LEAF_FE1..3 (upper 3 fes of leaf).
                v.push(leaf_fes[1]);
                v.push(leaf_fes[2]);
                v.push(leaf_fes[3]);
                // S_NK_LIMB0..15: 4 fes × 4 u16 (LE, low→high).
                let push_u16_limbs = |v: &mut Vec<Goldilocks>, fe: Goldilocks| {
                    let u = fe.as_canonical_u64();
                    for k in 0..4 {
                        let limb = (u >> (16 * k)) & 0xffff;
                        v.push(Goldilocks::from_u64(limb));
                    }
                };
                for k in 0..4 {
                    push_u16_limbs(&mut v, nk_fes[k]);
                }
                // S_LEAF_LIMB0..15: 4 fes × 4 u16 (LE, low→high).
                for k in 0..4 {
                    push_u16_limbs(&mut v, leaf_fes[k]);
                }
                // Phase 4b-step3-step2b-AIR-v2: S_NF_CARRY_CAP[0..8] —
                // bank-1 Poseidon2-w=16 output capacity slots. AIR
                // constraint on row 16+i pins these to bank-1.post[8+k];
                // row 20+i pins bank-2.inputs[8+k] to them. Carries the
                // capacity across the 4-row gap between bank-1 (row
                // 16+i) and bank-2 (row 20+i).
                for fe in spend_nf_out_cap[i].iter() {
                    v.push(*fe);
                }
                // Phase 4b-step3-step2b-AIR-v2: S_NF_CARRY_RATE[0..8] —
                // bank-1 post-permutation rate slots, carried so bank-2
                // inputs[0..8] can be constrained as
                //   bank-2.inputs[k] = carry_rate[k] + absorb_term_k
                // where absorb_term is (pos, ONE, 0*6).
                for fe in spend_nf_out_rate[i].iter() {
                    v.push(*fe);
                }
                debug_assert_eq!(v.len(), SPEND_PROXY_COLS);
                v
            })
            .collect();

        let output_proxies: Vec<Vec<Goldilocks>> = self
            .outputs
            .iter()
            .enumerate()
            .map(|(j, o)| {
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
                // Phase 4b-step3-step1.1: O_CM_SPONGE_OUT[0..4] — the
                // 4-fe digest produced by the 15-fe iterated Poseidon2
                // sponge over the widened witness fields. AIR-bound
                // by step1.2e to bank-2 output on row 12+j.
                let sponge_out =
                    poseidon2_cm_full_sponge(&perm16, &o.d, &o.pk_d, &o.ivk_commitment, o.value, &o.rcm);
                for fe in &sponge_out {
                    v.push(*fe);
                }
                // Phase 4b-step3-step1.2d: O_SPONGE_CARRY_CAP[0..8] —
                // bank-1 Poseidon2-w=16 output capacity (state[8..16]
                // after perm-1). AIR constraint on row 8+j pins this
                // col to bank-1.post[8+k]; row 12+j pins bank-2.inputs
                // [8+k] to this col. Together with the output-proxy
                // "constant across rows" transition invariant, this
                // carries the capacity across the 4-row gap between
                // the two sponge permutations without cross-row AIR
                // access.
                for fe in sponge_bank1_out_cap[j].iter() {
                    v.push(*fe);
                }
                // Phase 4b-step3-step1.2c: upper fe limbs of d, pk_d,
                // and ivk_commitment that bank-1 absorbs into its rate
                // slots 1, 3, 4, 5, 7 on row 8+j. These 5 cols
                // complement the existing single-fe proxies
                // (`O_D`, `O_PK_D`, `O_IVK_COMMITMENT`) so that the
                // full 8-fe bank-1 input matches the iterated-sponge
                // layout per §4.1:
                //   inputs[0..=1] = d_fes[0..=1]
                //   inputs[2..=5] = pk_d_fes[0..=3]
                //   inputs[6..=7] = ivk_cm_fes[0..=1]
                // Trace-gen uses the same `pack_*_as_*fe` helpers as
                // `poseidon2_cm_full_sponge`, so the column values are
                // byte-identical to what bank-1 absorbs on row 8+j.
                let d_fes = pack_diversifier_as_2fe(&o.d);
                let pk_d_fes = pack_32b_as_4fe(&o.pk_d);
                let ivk_cm_fes = pack_32b_as_4fe(&o.ivk_commitment);
                let rcm_fes = pack_32b_as_4fe(&o.rcm);
                v.push(d_fes[1]);
                v.push(pk_d_fes[1]);
                v.push(pk_d_fes[2]);
                v.push(pk_d_fes[3]);
                v.push(ivk_cm_fes[1]);
                // Phase 4b-step3-step1.2f: upper fe limbs of
                // ivk_commitment and rcm that bank-2 absorbs into its
                // rate slots on row 12+j. Combined with `O_VALUE` and
                // `O_RCM` (== rcm_fes[0]), these complete the
                // bank-2 absorb layout fes[8..=14].
                v.push(ivk_cm_fes[2]);
                v.push(ivk_cm_fes[3]);
                v.push(rcm_fes[1]);
                v.push(rcm_fes[2]);
                v.push(rcm_fes[3]);
                // Phase 4b-step3-step1.2f: bank-1 output rate slots
                // (state[0..8] after perm-1) carried forward to row
                // 12+j as the "bank-1 output term" in bank-2's input
                // absorb addition.
                for fe in sponge_bank1_out_rate[j].iter() {
                    v.push(*fe);
                }
                // Phase 4b-step3-step1.3-fields: decompose each of the
                // 14 output fe-limb proxy cols (d[0..2], pk_d[0..4],
                // ivk_cm[0..4], rcm[0..4]) into 4 u16 limbs (LE,
                // low-to-high). The AIR eval binds each fe-limb col to
                // `Σ_k limb_k · 2^{16k}` and the cross-AIR `u16_range`
                // LogUp bounds each limb to `0..=0xffff`, closing the
                // step 1.2c/f decoupling gap: the prover can no longer
                // pick non-canonical Goldilocks values for the sponge
                // rate slots — each fe-limb must be the canonical
                // u64 of the corresponding 8-byte LE chunk.
                //
                // Note `O_VALUE` already has its own 4-limb
                // decomposition at `O_VALUE_LIMB0..3` (Phase 3b-step2),
                // so fes[10] (== `O_VALUE`) is NOT duplicated here.
                let push_u16_limbs = |v: &mut Vec<Goldilocks>, fe: Goldilocks| {
                    let u = fe.as_canonical_u64();
                    for k in 0..4 {
                        let limb = (u >> (16 * k)) & 0xffff;
                        v.push(Goldilocks::from_u64(limb));
                    }
                };
                // d_fes[0..2]  (2 fe-limbs × 4 u16 = 8 cols)
                push_u16_limbs(&mut v, d_fes[0]);
                push_u16_limbs(&mut v, d_fes[1]);
                // pk_d_fes[0..4]  (4 fe-limbs × 4 u16 = 16 cols)
                for k in 0..4 {
                    push_u16_limbs(&mut v, pk_d_fes[k]);
                }
                // ivk_cm_fes[0..4]  (4 fe-limbs × 4 u16 = 16 cols)
                for k in 0..4 {
                    push_u16_limbs(&mut v, ivk_cm_fes[k]);
                }
                // rcm_fes[0..4]  (4 fe-limbs × 4 u16 = 16 cols)
                for k in 0..4 {
                    push_u16_limbs(&mut v, rcm_fes[k]);
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
            //   row 8+j (j ∈ 0..n_o): output j's sponge perm-1 (step 1.2a)
            //   row 12+j (j ∈ 0..n_o): output j's sponge perm-2 (step 1.2a)
            //   row 16+i (i ∈ 0..n_s): spend i's nf sponge bank-1 (step 2b-AIR-v2)
            //   row 20+i (i ∈ 0..n_s): spend i's nf sponge bank-2 (step 2b-AIR-v2)
            //   else: zero-input permutation
            if row_idx < n_s {
                values.extend_from_slice(&row0_spend_cm[row_idx]);
            } else if (4..4 + n_o).contains(&row_idx) {
                values.extend_from_slice(&row0_out_cm[row_idx - 4]);
            } else if (8..8 + n_o).contains(&row_idx) {
                values.extend_from_slice(&sponge_bank1_cm[row_idx - 8]);
            } else if (12..12 + n_o).contains(&row_idx) {
                values.extend_from_slice(&sponge_bank2_cm[row_idx - 12]);
            } else if (16..16 + n_s).contains(&row_idx) {
                values.extend_from_slice(&spend_nf_bank1[row_idx - 16]);
            } else if (20..20 + n_s).contains(&row_idx) {
                values.extend_from_slice(&spend_nf_bank2[row_idx - 20]);
            } else {
                values.extend_from_slice(&padding_p2_16);
            }

            // Globally-shared IvkCm/Nf (w=8) block:
            //   row i (i ∈ 0..n_s): spend i's claim-3 (IvkCm) witness
            //   else: zero-input permutation (padding_p2)
            //
            // Phase 4b-step3-step2b-AIR: rows 4..(4+n_s-1) used to host
            // the narrow-nf (claim 4) witness; that derivation moved to
            // the wide-w=16 block on rows 16..(15+n_s) with real 4-fe
            // nk + 4-fe cm + pos inputs. Narrow rows 4+i now just carry
            // a zero-input Poseidon2 permutation witness which satisfies
            // the narrow sub-AIR trivially — the old constraint block
            // is deleted and `row0_spend_nf` (narrow) is no longer built.
            if row_idx < n_s {
                values.extend_from_slice(&row0_spend_ivkcm[row_idx]);
            } else {
                values.extend_from_slice(&padding_p2);
            }

            // Phase 4b-step3-step3a cleanup: Phase 4b-step1 / step2b
            // anchor-limb global cols (`G_ANCHOR_LIMB1..3`,
            // `G_ANCHOR_PROXY`, `G_ANCHOR_LIMB0_REAL`) retired. All 4
            // anchor-limb PI slots are now last-row-bound from the
            // 4-fe Merkle-walk digest `S_CURRENT_FE[0..4]`.

            // Per-spend block: proxies + S_CURRENT_FE[0..4] +
            // per-spend shared Merkle P2 row-loop.
            for i in 0..n_s {
                values.extend_from_slice(&spend_proxies[i]);
                let cur_fes = s_current_vals_fes[i][row_idx];
                for m in 0..4 {
                    values.push(cur_fes[m]);
                }
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

/// Phase 4b-step3-step2b-AIR-v2: generic tag-block packer — mirror
/// of `tosctl/uno/src/poseidon2.rs::pack_tag_block` and
/// `uno/crypto/poseidon2.cpp::pack_domain_tag`. Packs the UTF-8
/// bytes of a ≤ 64-byte domain tag into 8 Goldilocks field elements
/// via 8-byte LE chunks + zero-pad in the trailing slot. Used to
/// materialize the capacity slots of the width-16 iterated sponge
/// for any tagged Uno derivation ("uno-cm-v1", "uno-nf-v1",
/// "uno-ivk-cm-v1", etc).
#[inline]
pub fn pack_tag_block(tag: &[u8]) -> [Goldilocks; 8] {
    let mut out = [Goldilocks::ZERO; 8];
    let n = tag.len().min(64);
    let full = (n / 8).min(8);
    for i in 0..full {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&tag[i * 8..(i + 1) * 8]);
        out[i] = Goldilocks::from_u64(u64::from_le_bytes(limb));
    }
    let rem = n - full * 8;
    if rem > 0 && full < 8 {
        let mut buf = [0u8; 8];
        buf[..rem].copy_from_slice(&tag[full * 8..full * 8 + rem]);
        out[full] = Goldilocks::from_u64(u64::from_le_bytes(buf));
    }
    out
}

/// Phase 4b-step3-step2b-AIR-v2: tag block for "uno-nf-v1" used by
/// the 9-fe iterated-sponge nullifier derivation. Shape matches
/// `uno_cm_v1_tag_block` exactly (9-byte tag: first fe = 8 bytes
/// of "uno-nf-v", second fe = "1" + 7 zero-pad, rest zero).
#[inline]
pub fn uno_nf_v1_tag_block() -> [Goldilocks; 8] {
    pack_tag_block(b"uno-nf-v1")
}

/// Domain tag "uno-cm-v1" packed as 8 Goldilocks field elements in
/// the convention tosctl / C++ use for the capacity slots of the
/// width-16 sponge: 8-byte LE chunks of the UTF-8 tag string,
/// zero-padded. Only the first fe holds a non-zero u64 for this
/// 9-byte tag.
#[inline]
pub fn uno_cm_v1_tag_block() -> [Goldilocks; 8] {
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
pub fn pack_32b_as_4fe(bytes: &[u8; 32]) -> [Goldilocks; 4] {
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
pub fn pack_diversifier_as_2fe(d: &[u8; 32]) -> [Goldilocks; 2] {
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
/// Cross-crate byte-parity wrapper around `poseidon2_cm_full_sponge`:
/// constructs its own default `Poseidon2Goldilocks<16>` (so callers
/// don't need to import the vendored `p3-goldilocks`) and packs the
/// 4-fe digest into 32 LE bytes per Goldilocks limb.
///
/// Designed for `tosctl/uno` integration tests that cannot directly
/// reference the vendored-path `Goldilocks` type (Cargo resolves
/// `p3-field` / `p3-goldilocks` to two distinct crates for the
/// vendored vs. git-pathed consumers).
///
/// Output format matches `tosctl::poseidon2::hash_tagged(b"uno-cm-v1",
/// fes_15)` byte-for-byte for equivalent inputs — see
/// `tosctl/uno/tests/phase4b_step3_sponge_parity.rs`.
#[allow(dead_code)]
pub fn poseidon2_cm_full_sponge_bytes(
    d: &[u8; 32],
    pk_d: &[u8; 32],
    ivk_commitment: &[u8; 32],
    value: u64,
    rcm: &[u8; 32],
) -> [u8; 32] {
    let perm16 = default_goldilocks_poseidon2_16();
    let digest = poseidon2_cm_full_sponge(&perm16, d, pk_d, ivk_commitment, value, rcm);
    let mut out = [0u8; 32];
    for (i, fe) in digest.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&fe.as_canonical_u64().to_le_bytes());
    }
    out
}

/// Cross-crate byte-equivalent of `uno_cm_v1_tag_block()`: packs the
/// 8-fe tag block into 64 LE bytes (8 B per fe). Enables byte-level
/// parity checks from crates that cannot directly see the vendored
/// `Goldilocks` type.
#[allow(dead_code)]
pub fn uno_cm_v1_tag_block_bytes() -> [u8; 64] {
    let tag_fes = uno_cm_v1_tag_block();
    let mut out = [0u8; 64];
    for (i, fe) in tag_fes.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&fe.as_canonical_u64().to_le_bytes());
    }
    out
}

#[allow(dead_code)]
pub fn poseidon2_cm_full_sponge(
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
#[allow(dead_code)]
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

/// Phase 4b-step3-step3a: 4-fe Merkle root via Poseidon2-w=8
/// `(left[4] ‖ right[4]) → out[4]` compression. Mirror of the AIR's
/// post-step-3a last-row binding; callers pass raw 32-byte leaf +
/// sibling bytes (each decomposed by `pack_32b_as_4fe`), this
/// function applies the 32-level walk off-circuit and returns the
/// 4-fe anchor digest.
pub(crate) fn poseidon2_merkle_path_root_4fe(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    leaf_bytes: &[u8; 32],
    pos: u64,
    path_bytes: &[[u8; 32]; MERKLE_DEPTH],
) -> [Goldilocks; 4] {
    let mut cur: [Goldilocks; 4] = pack_32b_as_4fe(leaf_bytes);
    for k in 0..MERKLE_DEPTH {
        let bit = (pos >> k) & 1;
        let sib: [Goldilocks; 4] = pack_32b_as_4fe(&path_bytes[k]);
        let (left, right) = if bit == 0 { (cur, sib) } else { (sib, cur) };
        let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
        for m in 0..4 {
            state[m] = left[m];
        }
        for m in 0..4 {
            state[4 + m] = right[m];
        }
        perm.permute_mut(&mut state);
        cur = [state[0], state[1], state[2], state[3]];
    }
    cur
}

/// Bytes wrapper around `poseidon2_merkle_path_root_4fe`: packs the
/// 4-fe digest into 32 LE bytes (8 B per Goldilocks limb). Useful for
/// test fixtures that need to round-trip anchor-bytes through the
/// 4-fe walk.
pub(crate) fn poseidon2_merkle_path_root_4fe_bytes(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    leaf_bytes: &[u8; 32],
    pos: u64,
    path_bytes: &[[u8; 32]; MERKLE_DEPTH],
) -> [u8; 32] {
    let fes = poseidon2_merkle_path_root_4fe(perm, leaf_bytes, pos, path_bytes);
    let mut out = [0u8; 32];
    for (i, fe) in fes.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&fe.as_canonical_u64().to_le_bytes());
    }
    out
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

/// Phase 4b-step3-step2b-AIR-v2: nullifier computation via the 9-fe
/// iterated Poseidon2-w=16 sponge with "uno-nf-v1" tag block —
/// byte-identical to `uno/crypto/poseidon2.cpp::derive_nullifier` and
/// the codec-parity test helper `hash_tagged(b"uno-nf-v1", 9 fes)`.
///
/// Layout:
///   tag_block = pack_tag_block("uno-nf-v1")   — 8 fes, constant
///   fes[0..8] = (nk_fes[0..4], cm_fes[0..4])  — 8 fes (rate-8 absorb)
///   fes[8]    = pos                           — final fe
///
///   Bank 1:
///     state[0..8]   = fes[0..8]
///     state[8..16]  = tag_block              (capacity)
///     permute → bank1_out
///
///   Bank 2:
///     state[0]      = bank1_out[0] + pos     (fes[8] absorb)
///     state[1]      = bank1_out[1] + 1       (10* padding)
///     state[2..8]   = bank1_out[2..8]        (rate carry, no absorb)
///     state[8..16]  = bank1_out[8..16]       (capacity carry)
///     permute → bank2_out
///
///   Return bank2_out[0..4] — the 4-fe nf digest → PI[pi_nf(i) + 0..4].
///
/// Supersedes the Phase 4b-step3-step2b-AIR-v1 single-perm attempt
/// (commits b92a6bdbb + 0e23eef30) which pinned `state[0] = TAG_NF`
/// (a u64 constant) and bypassed the proper tag-block capacity
/// mechanism — not spec-compliant against C++
/// `build_plonky3_public_inputs` / `derive_nullifier`.
pub fn poseidon2_nf_full_wide(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH_16]>,
    nk_bytes: &[u8; 32],
    cm_bytes: &[u8; 32],
    pos: u64,
) -> [Goldilocks; 4] {
    let nk_fes = pack_32b_as_4fe(nk_bytes);
    let cm_fes = pack_32b_as_4fe(cm_bytes);
    let tag_block = uno_nf_v1_tag_block();
    // Bank 1: rate absorb of 8 fes, tag pinned at capacity.
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
    state[0..4].copy_from_slice(&nk_fes);
    state[4..8].copy_from_slice(&cm_fes);
    state[8..16].copy_from_slice(&tag_block);
    perm.permute_mut(&mut state);
    // Bank 2: partial absorb of the 1 remaining fe + 10* padding.
    state[0] = state[0] + Goldilocks::from_u64(reduce_to_goldilocks(pos));
    state[1] = state[1] + Goldilocks::ONE;
    perm.permute_mut(&mut state);
    [state[0], state[1], state[2], state[3]]
}

/// Phase 4b-step3-step2b-AIR-v2: cross-crate byte-parity wrapper around
/// `poseidon2_nf_full_wide`. Constructs its own default
/// `Poseidon2Goldilocks<16>` (so callers don't need the vendored
/// `p3-goldilocks`) and packs the 4-fe digest into 32 LE bytes per
/// Goldilocks limb. Designed for `tosctl/uno` integration tests that
/// cannot directly reference the vendored-path `Goldilocks` type.
pub fn poseidon2_nf_full_wide_bytes(
    nk_bytes: &[u8; 32],
    cm_bytes: &[u8; 32],
    pos: u64,
) -> [u8; 32] {
    let perm16 = default_goldilocks_poseidon2_16();
    let fes = poseidon2_nf_full_wide(&perm16, nk_bytes, cm_bytes, pos);
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8]
            .copy_from_slice(&fes[i].as_canonical_u64().to_le_bytes());
    }
    out
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
        if derived != reduce_to_goldilocks(first_u64_proxy(&s.leaf)) {
            return false;
        }
    }
    true
}

/// True iff for every spend, folding the 32-level Merkle path with a
/// 4-fe Poseidon2-w=8 walk reproduces the 4-fe decomposition of
/// `witness.anchor_bytes`.
///
/// Phase 4b-step3-step3a rewrote the reference from the legacy single-
/// u64-proxy walk (`anchor_proxy`) to the full 4-fe walk: both the
/// leaf and every sibling feed in as `pack_32b_as_4fe(&field)`, and
/// the target is `pack_32b_as_4fe(&w.anchor_bytes)`. This matches the
/// AIR's last-row binding after step 3a.
pub fn witness_claim1_anchor_consistent(w: &MvpWitness) -> bool {
    let perm = default_goldilocks_poseidon2_8();
    let want: [Goldilocks; 4] = pack_32b_as_4fe(&w.anchor_bytes);
    for s in &w.spends {
        let derived =
            poseidon2_merkle_path_root_4fe(&perm, &s.leaf, s.pos, &s.merkle_path);
        if derived != want {
            return false;
        }
    }
    true
}

/// Phase 4b-step3-step3a: no-op — the pre-step-3a invariant
/// `anchor_bytes[0..8] == anchor_proxy` is no longer meaningful.
/// `anchor_bytes` is now the 4-fe Merkle walk output (matches the
/// AIR's last-row binding to `PI[PI_ANCHOR + 0..4]`), while
/// `anchor_proxy` is the legacy single-fe walk output kept only for
/// wire-compat. Callers that need the fresh consistency check should
/// use [`witness_claim1_anchor_consistent`], which derives the 4-fe
/// walk off-circuit and compares against `pack_32b_as_4fe(anchor_bytes)`.
///
/// This stub is retained so downstream callers that previously ran
/// the check do not break at the type-signature level; it always
/// returns true. Real soundness lives in `witness_claim1_anchor_consistent`.
pub fn witness_anchor_bytes_consistent(_w: &MvpWitness) -> bool {
    true
}

/// Phase 4b-step3-step1.3-pi: true iff for every output, all 4 LE
/// u64 limbs of `witness.cm_bytes` (reduced mod Goldilocks) equal the
/// 4-fe output of the 15-fe iterated Poseidon2-w=16 sponge over
/// (d, pk_d, ivk_commitment, value, rcm). Post-step-1.3-pi, the AIR
/// binds `PI[pi_cm(j) + k]` to `O_CM_SPONGE_OUT[k]` — so a mismatch
/// here guarantees verify-time rejection. Surfacing the error at the
/// wallet pre-check boundary is friendlier than an opaque FFI
/// `VerifyFailed`.
///
/// Supersedes the Phase 4b-step1 single-limb check that tested
/// `encode_256(cm_bytes)[0] == poseidon2_cm_fe(...)`; the full 32 B
/// are now consensus-bound.
pub fn witness_cm_bytes_consistent(w: &MvpWitness) -> bool {
    let perm16 = default_goldilocks_poseidon2_16();
    for o in &w.outputs {
        let derived = poseidon2_cm_full_sponge(
            &perm16,
            &o.d,
            &o.pk_d,
            &o.ivk_commitment,
            o.value,
            &o.rcm,
        );
        for k in 0..4 {
            let witness_limb =
                u64::from_le_bytes(o.cm_bytes[k * 8..(k + 1) * 8].try_into().unwrap());
            if reduce_to_goldilocks(witness_limb) != derived[k].as_canonical_u64() {
                return false;
            }
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

            // Phase 4b-step3-step2b-decomp: 4·(n_s + n_o) value-limb
            // receives + 56·n_o output fe-limb receives (14 fe-limbs ×
            // 4 u16 limbs per output: d×2 + pk_d×4 + ivk_cm×4 + rcm×4)
            // + 32·n_s spend fe-limb receives (8 fe-limbs × 4 u16 limbs
            // per spend: nk×4 + leaf×4).
            let expected_count = 4 * (n_s + n_o) + 56 * n_o + 32 * n_s;
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

    /// Phase 4b-step3-step1.1: verify that `generate_trace` populates
    /// the new `O_CM_SPONGE_OUT[0..4]` output-proxy columns with the
    /// same 4-fe digest that `poseidon2_cm_full_sponge` would produce
    /// on the witness's (d, pk_d, ivk_commitment, value, rcm) tuple.
    ///
    /// This test pins the trace-gen contract for the new columns —
    /// step 1.2's in-circuit Poseidon2 AIR constraints will ratify
    /// the same values, and step 1.3 will re-couple PI to them.
    #[test]
    fn trace_populates_o_cm_sponge_out_from_helper() {
        use p3_matrix::Matrix;

        let w = MvpWitness::deterministic_valid(1, 2, 0xC05_5_1100);
        let perm16 = default_goldilocks_poseidon2_16();
        let trace = w.generate_trace();

        let n_s = 1usize;
        let width = air_width(n_s, 2);
        // The output_proxy block starts at
        //   GLOBAL_COLS + n_s*per_spend_cols() + j*per_output_cols()
        // for output j; see `output_proxy_offset` in the module.
        let output_block_0_start = GLOBAL_COLS + n_s * per_spend_cols();

        // On row 0, read the O_CM_SPONGE_OUT[0..4] slice from output 0.
        let row0: Vec<Goldilocks> = trace.row(0).unwrap().into_iter().collect();
        let sponge_col_base = output_block_0_start + O_CM_SPONGE_OUT;
        let trace_fes: [Goldilocks; 4] = [
            row0[sponge_col_base],
            row0[sponge_col_base + 1],
            row0[sponge_col_base + 2],
            row0[sponge_col_base + 3],
        ];

        // Reference: directly call the helper on output 0's witness
        // fields.
        let o = &w.outputs[0];
        let expected =
            poseidon2_cm_full_sponge(&perm16, &o.d, &o.pk_d, &o.ivk_commitment, o.value, &o.rcm);

        assert_eq!(
            trace_fes, expected,
            "trace-gen O_CM_SPONGE_OUT must match poseidon2_cm_full_sponge on (d, pk_d, ivk_commitment, value, rcm) tuple"
        );

        // Sanity: column is inside the trace-row width bounds.
        assert!(
            sponge_col_base + 3 < width,
            "O_CM_SPONGE_OUT cols must fit inside air_width({},{})={}",
            n_s,
            2,
            width,
        );

        // Sanity: the same column on any later row should hold the
        // same values (output proxies are constant across rows per
        // the §4.2 invariant).
        let row_last: Vec<Goldilocks> = trace
            .row(crate::transfer_air::TRACE_HEIGHT - 1)
            .unwrap()
            .into_iter()
            .collect();
        let trace_fes_last: [Goldilocks; 4] = [
            row_last[sponge_col_base],
            row_last[sponge_col_base + 1],
            row_last[sponge_col_base + 2],
            row_last[sponge_col_base + 3],
        ];
        assert_eq!(
            trace_fes, trace_fes_last,
            "O_CM_SPONGE_OUT must be constant across trace rows (proxies-are-constant invariant)"
        );
    }

    /// Phase 4b-step3-step1.2a: the shared `G_CM_SHARED_P2_16` block
    /// now hosts two additional row-cohorts — the sponge bank-1 perm
    /// witnesses on rows 8..8+n_o and bank-2 perm witnesses on rows
    /// 12..12+n_o. This test extracts the `inputs` field of both
    /// cohorts, reconstructs the expected bank-1 input layout
    /// (state[0..7] = fes[0..8], state[8..15] = tag_block), applies
    /// the Poseidon2-w=16 permutation off-circuit to get the expected
    /// bank-2 input, and asserts trace matches.
    ///
    /// Crucially, this test also confirms the CHAIN: the 4-fe output
    /// of bank-2's permutation, extracted from the `Poseidon2Cols::
    /// ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS-1].post[0..4]`
    /// field, must equal `O_CM_SPONGE_OUT[0..4]` in the output proxy
    /// block — i.e. the trace-gen produces a self-consistent sponge
    /// computation that step 1.2b+ AIR constraints can ratify.
    #[test]
    fn trace_populates_sponge_bank_rows_chained_to_o_cm_sponge_out() {
        use p3_matrix::Matrix;

        let w = MvpWitness::deterministic_valid(1, 2, 0x5B71_0000);
        let perm16 = default_goldilocks_poseidon2_16();
        let trace = w.generate_trace();

        let n_s = 1usize;
        let n_o = 2usize;
        let width = air_width(n_s, n_o);

        // Sanity: all widths line up.
        assert!(G_CM_SHARED_P2_16 + POSEIDON2_COLS_PER_INSTANCE_16 < width);

        for j in 0..n_o {
            let o = &w.outputs[j];

            // --- Expected bank-1 input (reconstructed off-circuit) ---
            let d_fes = pack_diversifier_as_2fe(&o.d);
            let pk_d_fes = pack_32b_as_4fe(&o.pk_d);
            let ivk_cm_fes = pack_32b_as_4fe(&o.ivk_commitment);
            let value_fe = Goldilocks::from_u64(reduce_to_goldilocks(o.value));
            let rcm_fes = pack_32b_as_4fe(&o.rcm);
            let mut fes = [Goldilocks::ZERO; 15];
            fes[0] = d_fes[0];
            fes[1] = d_fes[1];
            fes[2..6].copy_from_slice(&pk_d_fes);
            fes[6..10].copy_from_slice(&ivk_cm_fes);
            fes[10] = value_fe;
            fes[11..15].copy_from_slice(&rcm_fes);
            let tag_block = uno_cm_v1_tag_block();

            let mut expected_bank1_in =
                [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
            expected_bank1_in[0..8].copy_from_slice(&fes[0..8]);
            expected_bank1_in[8..16].copy_from_slice(&tag_block);

            // --- Extract trace row 8+j bank-1 input (first WIDTH cols
            //     of the shared block are Poseidon2Cols::inputs) ---
            let row_bank1: Vec<Goldilocks> =
                trace.row(8 + j).unwrap().into_iter().collect();
            let bank1_inputs_slice = &row_bank1[G_CM_SHARED_P2_16
                ..G_CM_SHARED_P2_16 + POSEIDON2_WIDTH_16];
            assert_eq!(
                bank1_inputs_slice,
                &expected_bank1_in[..],
                "bank-1 inputs on row 8+{} must match expected fes-at-rate + tag-at-capacity layout",
                j,
            );

            // --- Compute expected bank-2 input from post-perm-1 state ---
            let mut state = expected_bank1_in;
            perm16.permute_mut(&mut state);
            let mut expected_bank2_in = state;
            for k in 0..7 {
                expected_bank2_in[k] = expected_bank2_in[k] + fes[8 + k];
            }
            expected_bank2_in[7] = expected_bank2_in[7] + Goldilocks::from_u64(1);

            // --- Extract trace row 12+j bank-2 input ---
            let row_bank2: Vec<Goldilocks> =
                trace.row(12 + j).unwrap().into_iter().collect();
            let bank2_inputs_slice = &row_bank2[G_CM_SHARED_P2_16
                ..G_CM_SHARED_P2_16 + POSEIDON2_WIDTH_16];
            assert_eq!(
                bank2_inputs_slice,
                &expected_bank2_in[..],
                "bank-2 inputs on row 12+{} must absorb fes[8..14] into slots 0..6 + padding at slot 7 + tag unchanged",
                j,
            );

            // --- Post-perm-2 state[0..4] should equal O_CM_SPONGE_OUT ---
            let mut state_final = expected_bank2_in;
            perm16.permute_mut(&mut state_final);
            let sponge_out_expected: [Goldilocks; 4] = [
                state_final[0],
                state_final[1],
                state_final[2],
                state_final[3],
            ];

            // Read O_CM_SPONGE_OUT from output-j proxy block on any row
            // (proxies are constant; use row 0 since it's guaranteed
            // populated on all shapes).
            let row0: Vec<Goldilocks> =
                trace.row(0).unwrap().into_iter().collect();
            let output_block_j_start = GLOBAL_COLS + n_s * per_spend_cols() + j * per_output_cols();
            let sponge_col_base = output_block_j_start + O_CM_SPONGE_OUT;
            let o_cm_sponge_out: [Goldilocks; 4] = [
                row0[sponge_col_base],
                row0[sponge_col_base + 1],
                row0[sponge_col_base + 2],
                row0[sponge_col_base + 3],
            ];

            assert_eq!(
                sponge_out_expected,
                o_cm_sponge_out,
                "bank-2 permutation output state[0..4] must chain to O_CM_SPONGE_OUT for output {}",
                j,
            );
        }
    }

    /// Phase 4b-step3-step3a: verify that the trace-gen 4-fe Merkle
    /// walk output — read from `S_CURRENT_FE[0..4]` on the last trace
    /// row — matches `pack_32b_as_4fe(&w.anchor_bytes)` off-circuit.
    /// This pins the trace-gen contract for the new `S_CURRENT_FE`
    /// cols (step 3a's replacement for the legacy single-fe
    /// `S_CURRENT`) and closes the AIR's last-row anchor binding.
    #[test]
    fn merkle_walk_4fe_matches_reference_fixture() {
        use p3_matrix::Matrix;

        let w = MvpWitness::deterministic_valid(1, 1, 0x4FE_0_ABCD);
        let trace = w.generate_trace();
        let n_s = 1usize;

        // Read S_CURRENT_FE[0..4] on last row of spend 0's var block.
        let last_row_idx = TRACE_HEIGHT - 1;
        let last_row: Vec<Goldilocks> =
            trace.row(last_row_idx).unwrap().into_iter().collect();
        let var_base = GLOBAL_COLS
            + 0 * per_spend_cols()
            + SPEND_PROXY_COLS; // `spend_var_offset(0)` inline
        let trace_fes: [Goldilocks; 4] = [
            last_row[var_base + S_CURRENT_FE0],
            last_row[var_base + S_CURRENT_FE0 + 1],
            last_row[var_base + S_CURRENT_FE0 + 2],
            last_row[var_base + S_CURRENT_FE0 + 3],
        ];

        let expected = pack_32b_as_4fe(&w.anchor_bytes);
        assert_eq!(
            trace_fes, expected,
            "last-row S_CURRENT_FE[0..4] must equal pack_32b_as_4fe(anchor_bytes)"
        );

        // Also cross-check against the off-circuit 4-fe walk helper.
        let perm = default_goldilocks_poseidon2_8();
        let s = &w.spends[0];
        let helper_out =
            poseidon2_merkle_path_root_4fe(&perm, &s.leaf, s.pos, &s.merkle_path);
        assert_eq!(
            trace_fes, helper_out,
            "trace-gen 4-fe walk must match poseidon2_merkle_path_root_4fe helper"
        );

        // Unused n_s silencer (the GLOBAL_COLS arithmetic above uses
        // index 0 inline; keep the let-binding for readers).
        let _ = n_s;
    }
}
