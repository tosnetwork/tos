//! Column-layout constants, type aliases, and column-accessor helpers for the
//! Transfer AIR. Extracted from `transfer_air.rs` so the 5000-line file can
//! be split into focused sibling modules while preserving the external API.
//!
//! All items that were `pub` in `transfer_air.rs` remain `pub` here and are
//! re-exported from `transfer_air` via `pub use crate::transfer_columns::*`.

use core::borrow::Borrow;

use p3_goldilocks::{
    GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS,
    GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_16, GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
};
use p3_poseidon2_air::{num_cols as p2_num_cols, Poseidon2Cols};

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
pub(crate) type P2Cols16<T> = Poseidon2Cols<
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
pub(crate) const GCOL_FEE: usize = 0;
/// Base index of the 32 one-hot Merkle row-selector columns (§claim 1).
pub(crate) const GS_ROW_SEL0: usize = 1;
/// Base index of the shared Cm/OutCm width-16 Poseidon2 block
/// (K-air-col-step2 strategy b — claim 2/6 row-loop on rows 0..7).
pub(crate) const G_CM_SHARED_P2_16: usize = GS_ROW_SEL0 + MERKLE_DEPTH;
/// Base index of the shared IvkCm/Nf width-8 Poseidon2 block
/// (K-air-col-step2 strategy c — claim 3/4 row-loop on rows 0..7).
pub(crate) const G_IVKCM_NF_SHARED_P2_8: usize = G_CM_SHARED_P2_16 + POSEIDON2_COLS_PER_INSTANCE_16;

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
///
/// Phase 4b-step3-step5b-decomp adds 67 additional cols per spend (11
/// fe-limb cols — `S_D_FE1`, `S_PK_D_FE1..3`, `S_IVK_COMMITMENT_FE0..3`,
/// `S_RCM_FE1..3` — plus 56 u16 limb cols for the 14 fe-limb × 4 u16
/// decomposition: d×2 + pk_d×4 + ivk_cm×4 + rcm×4) that prepare the
/// spend cm sponge input layout. Mirror of the output-side step
/// 1.2c/f + step 1.3-fields block, on the spend side.
pub const SPEND_PROXY_COLS: usize = 9
    + MERKLE_DEPTH
    + MERKLE_DEPTH * SIBLING_FES_PER_LEVEL
    + VALUE_LIMBS_U16
    + RK_EPK_LIMBS
    + 38
    + 16  // Phase 4b-step3-step2b-AIR-v2: S_NF_CARRY_{CAP,RATE}[0..8]
    + 67  // Phase 4b-step3-step5b-decomp: 11 spend cm fe-limb proxy cols
          //   (S_D_FE1, S_PK_D_FE1..3, S_IVK_COMMITMENT_FE0..3, S_RCM_FE1..3)
          // + 56 u16 cols (d×2 + pk_d×4 + ivk_cm×4 + rcm×4 = 14 fe-limbs
          //   × 4 u16 limbs; NOTE value already has S_VALUE_LIMB0..3 from
          //   Phase 3b-step2, not duplicated).
    + 16; // Phase 4b-step3-step5c-sponge: S_CM_CARRY_{CAP,RATE}[0..8]
          // bank-1 → bank-2 carry cols for the spend cm iterated sponge.

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
pub(crate) const S_CURRENT_FE0: usize = 0;
#[allow(dead_code)]
pub(crate) const S_CURRENT_FE1: usize = 1;
#[allow(dead_code)]
pub(crate) const S_CURRENT_FE2: usize = 2;
#[allow(dead_code)]
pub(crate) const S_CURRENT_FE3: usize = 3;

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
pub(crate) const S_LEAF: usize = 0;
pub(crate) const S_D: usize = 1; // diversifier proxy (was overloaded onto S_SIBLING pre-merkle32)
pub(crate) const S_VALUE: usize = 2;
pub(crate) const S_IVK: usize = 3;
pub(crate) const S_IVK_COMMITMENT_CLAIM: usize = 4;
pub(crate) const S_PK_D: usize = 5;
pub(crate) const S_RCM: usize = 6;
pub(crate) const S_NK: usize = 7;
pub(crate) const S_POS: usize = 8;
// Merkle path: MERKLE_DEPTH path-bit proxies, then
// `MERKLE_DEPTH * SIBLING_FES_PER_LEVEL` sibling-limb proxies (Phase
// 4b-step3-step3a: 4 fes per level). Path bit `k` is
// `(pos >> k) & 1` (low→high bit order); sibling limb `m` of level `k`
// lives at `S_SIBLING0 + k · SIBLING_FES_PER_LEVEL + m` and equals
// `pack_32b_as_4fe(s.merkle_path[k])[m]`.
pub(crate) const S_PATH_BIT0: usize = 9;
pub(crate) const S_SIBLING0: usize = S_PATH_BIT0 + MERKLE_DEPTH;
/// Base index of the 4×u16 limb-decomposition columns for `value_i`
/// (claim 5). Phase 3b-step2: was `S_VALUE_BIT0` (64 bit columns).
/// Phase 4b-step3-step3a: sibling block widened to 4 fe/level, so
/// this offset shifts by `MERKLE_DEPTH · (SIBLING_FES_PER_LEVEL - 1)
/// = 96` cols.
pub(crate) const S_VALUE_LIMB0: usize = S_SIBLING0 + MERKLE_DEPTH * SIBLING_FES_PER_LEVEL;
/// Base index of the 4 u64-limb columns holding `rk_bytes` (Phase 4a).
pub(crate) const S_RK_LIMB0: usize = S_VALUE_LIMB0 + VALUE_LIMBS_U16;

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
pub(crate) const S_NK_FE1: usize = S_RK_LIMB0 + RK_EPK_LIMBS;
pub(crate) const S_NK_FE2: usize = S_NK_FE1 + 1;
pub(crate) const S_NK_FE3: usize = S_NK_FE2 + 1;
/// Phase 4b-step3-step2b-decomp: upper-fe-limb proxy columns for
/// `leaf` — same shape as `S_NK_FE{1..3}`. Low fe is the existing
/// `S_LEAF` col == `first_u64_proxy(&s.leaf)`.
pub(crate) const S_LEAF_FE1: usize = S_NK_FE3 + 1;
pub(crate) const S_LEAF_FE2: usize = S_LEAF_FE1 + 1;
pub(crate) const S_LEAF_FE3: usize = S_LEAF_FE2 + 1;
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
pub(crate) const S_NK_LIMB0: usize = S_LEAF_FE3 + 1;
/// Phase 4b-step3-step2b-decomp: base index of the 16 u16 limb
/// columns decomposing the 4 fe-limbs of `leaf` — same shape as
/// `S_NK_LIMB0`.
pub(crate) const S_LEAF_LIMB0: usize = S_NK_LIMB0 + 16;
/// Phase 4b-step3-step2b-AIR-v2: base index of the 8 "nf carry cap"
/// cols holding the bank-1 Poseidon2-w=16 output's capacity slots
/// (`state[8..16]` after perm-1) for the nf iterated sponge. Pinned
/// by AIR constraints to bank-1 post-permutation capacity on row
/// 16+i AND to bank-2 input capacity on row 20+i. The proxies-are-
/// constant transition invariant carries these across the 4-row gap.
/// Mirror of `O_SPONGE_CARRY_CAP` on the output side (step 1.2d).
pub(crate) const S_NF_CARRY_CAP0: usize = S_LEAF_LIMB0 + 16;
/// Phase 4b-step3-step2b-AIR-v2: base index of the 8 "nf carry rate"
/// cols holding the bank-1 Poseidon2-w=16 output's rate slots
/// (`state[0..8]` after perm-1) for the nf iterated sponge. Pinned
/// by AIR constraints to bank-1 post-permutation rate on row 16+i
/// AND used as the "bank1.out term" in bank-2's absorb addition on
/// row 20+i. Mirror of `O_SPONGE_CARRY_RATE` on the output side
/// (step 1.2f).
pub(crate) const S_NF_CARRY_RATE0: usize = S_NF_CARRY_CAP0 + 8;

// --- Phase 4b-step3-step5b-decomp: spend cm sponge fe-limb proxies ---
//
// Mirror of the output-side `O_D_FE1` / `O_PK_D_FE1..3` /
// `O_IVK_COMMITMENT_FE1..3` / `O_RCM_FE1..3` cols (step 1.2c/f) on
// the spend side. These hold the remaining Goldilocks field elements
// of each 32-byte witness field that the cm sponge needs to absorb,
// complementing the low-fe single-u64 proxies (`S_D`, `S_PK_D`,
// `S_RCM`) that already exist. `ivk_commitment` is a NEW 32-byte
// witness field (added in step 5a-wire): all 4 fes are added here
// — `S_IVK_COMMITMENT_FE0` is the low fe, distinct from the
// legacy claim-3 narrow-w=8 output `S_IVK_COMMITMENT_CLAIM`.
//
// Populated trace-side from `pack_diversifier_as_2fe(&s.d)` (d) /
// `pack_32b_as_4fe(&s.{pk_d,ivk_commitment,rcm})`; AIR-bound by the
// step 5b-decomp u16-limb decomposition block to
// `Σ_k limb_k · 2^{16k}` for each fe, closing the "fe is canonical
// u64 of 8-byte LE witness chunk" soundness gap. Consumed by step
// 5c-sponge to wire the bank-1 / bank-2 iterated sponge.
pub(crate) const S_D_FE1: usize = S_NF_CARRY_RATE0 + 8;
pub(crate) const S_PK_D_FE1: usize = S_D_FE1 + 1;
pub(crate) const S_PK_D_FE2: usize = S_PK_D_FE1 + 1;
pub(crate) const S_PK_D_FE3: usize = S_PK_D_FE2 + 1;
pub(crate) const S_IVK_COMMITMENT_FE0: usize = S_PK_D_FE3 + 1;
pub(crate) const S_IVK_COMMITMENT_FE1: usize = S_IVK_COMMITMENT_FE0 + 1;
pub(crate) const S_IVK_COMMITMENT_FE2: usize = S_IVK_COMMITMENT_FE1 + 1;
pub(crate) const S_IVK_COMMITMENT_FE3: usize = S_IVK_COMMITMENT_FE2 + 1;
pub(crate) const S_RCM_FE1: usize = S_IVK_COMMITMENT_FE3 + 1;
pub(crate) const S_RCM_FE2: usize = S_RCM_FE1 + 1;
pub(crate) const S_RCM_FE3: usize = S_RCM_FE2 + 1;
/// Phase 4b-step3-step5b-decomp: base index of the 8 u16 limb cols
/// decomposing the 2 fe-limbs of `d` (via `pack_diversifier_as_2fe`)
/// into u16 LE limbs. Fes[0..2] each → 4 u16 = 8 cols.
pub(crate) const S_D_LIMB0: usize = S_RCM_FE3 + 1;
/// Phase 4b-step3-step5b-decomp: base index of the 16 u16 limb cols
/// decomposing the 4 fe-limbs of `pk_d` — same shape as `O_PK_D_LIMB0`.
pub(crate) const S_PK_D_LIMB0: usize = S_D_LIMB0 + 8;
/// Phase 4b-step3-step5b-decomp: base index of the 16 u16 limb cols
/// decomposing the 4 fe-limbs of `ivk_commitment`.
pub(crate) const S_IVK_COMMITMENT_LIMB0: usize = S_PK_D_LIMB0 + 16;
/// Phase 4b-step3-step5b-decomp: base index of the 16 u16 limb cols
/// decomposing the 4 fe-limbs of `rcm`.
pub(crate) const S_RCM_LIMB0: usize = S_IVK_COMMITMENT_LIMB0 + 16;
/// Phase 4b-step3-step5c-sponge: base index of the 8 "spend cm carry
/// cap" cols holding the bank-1 Poseidon2-w=16 output's capacity
/// slots (`state[8..16]` after perm-1) for the spend cm iterated
/// sponge. Pinned by AIR constraints to bank-1 post-permutation
/// capacity on row i AND to bank-2 input capacity on row 24+i. The
/// proxies-are-constant transition invariant carries these across
/// the 24-row gap. Mirror of `O_SPONGE_CARRY_CAP` on the output side
/// (step 1.2d) and `S_NF_CARRY_CAP0` for the nf sponge (step 2b-AIR-v2).
pub(crate) const S_CM_CARRY_CAP0: usize = S_RCM_LIMB0 + 16;
/// Phase 4b-step3-step5c-sponge: base index of the 8 "spend cm carry
/// rate" cols holding the bank-1 Poseidon2-w=16 output's rate slots
/// (`state[0..8]` after perm-1) for the spend cm iterated sponge.
/// Pinned by AIR constraints to bank-1 post-permutation rate on row
/// i AND used as the "bank-1 out term" in bank-2's absorb addition
/// on row 24+i. Mirror of `O_SPONGE_CARRY_RATE` (step 1.2f) and
/// `S_NF_CARRY_RATE0` (step 2b-AIR-v2).
pub(crate) const S_CM_CARRY_RATE0: usize = S_CM_CARRY_CAP0 + 8;

// ---- Per-output column indices (within an output proxy block) ----
pub(crate) const O_CM_CLAIM: usize = 0;
pub(crate) const O_D: usize = 1;
pub(crate) const O_PK_D: usize = 2;
pub(crate) const O_IVK_COMMITMENT: usize = 3;
pub(crate) const O_VALUE: usize = 4;
pub(crate) const O_RCM: usize = 5;
/// Base index of the 4×u16 limb-decomposition columns for `value_j`
/// (claim 7). Phase 3b-step2: was `O_VALUE_BIT0` (64 bit columns).
pub(crate) const O_VALUE_LIMB0: usize = 6;
/// Base index of the 4 u64-limb columns holding `epk_bytes` (Phase 4a).
pub(crate) const O_EPK_LIMB0: usize = O_VALUE_LIMB0 + VALUE_LIMBS_U16;
/// Single column holding the u16 `filter_tag` (Phase 4a).
pub(crate) const O_FILTER_TAG: usize = O_EPK_LIMB0 + RK_EPK_LIMBS;
/// Phase 4b-step3-step1.1: base index of the 4 trace columns holding
/// the output of the 15-fe iterated-sponge `poseidon2_cm_full_sponge`
/// over `witness.o.{d, pk_d, ivk_commitment, value, rcm}`. Bound by
/// step 1.2b-f in-circuit Poseidon2 AIR constraints to the sponge
/// derivation, and by step 1.3-pi to `PI[pi_cm(j) + 0..4]` via row-0
/// copy-constraint. Superseded the Phase 4b-step1 / Phase 4b-step2a
/// witness-bytes path (`O_CM_LIMB0_REAL` + `O_CM_LIMB1..3`) which
/// was trimmed out by step 1.3-cleanup.
pub(crate) const O_CM_SPONGE_OUT: usize = O_FILTER_TAG + 1;
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
pub(crate) const O_SPONGE_CARRY_CAP: usize = O_CM_SPONGE_OUT + 4;
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
pub(crate) const O_D_FE1: usize = O_SPONGE_CARRY_CAP + 8;
pub(crate) const O_PK_D_FE1: usize = O_D_FE1 + 1;
pub(crate) const O_PK_D_FE2: usize = O_PK_D_FE1 + 1;
pub(crate) const O_PK_D_FE3: usize = O_PK_D_FE2 + 1;
pub(crate) const O_IVK_COMMITMENT_FE1: usize = O_PK_D_FE3 + 1;
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
pub(crate) const O_IVK_COMMITMENT_FE2: usize = O_IVK_COMMITMENT_FE1 + 1;
pub(crate) const O_IVK_COMMITMENT_FE3: usize = O_IVK_COMMITMENT_FE2 + 1;
pub(crate) const O_RCM_FE1: usize = O_IVK_COMMITMENT_FE3 + 1;
pub(crate) const O_RCM_FE2: usize = O_RCM_FE1 + 1;
pub(crate) const O_RCM_FE3: usize = O_RCM_FE2 + 1;
/// Phase 4b-step3-step1.2f: base index of the 8 "carry rate" cols
/// holding bank-1's Poseidon2-w=16 output rate slots (`state[0..8]`
/// after perm-1). AIR constraint on row 8+j binds these to
/// `shared_cm_out[0..8]`; row 12+j uses them as the "bank-1 output rate
/// term" in bank-2's input-absorb addition. Together with the output-
/// proxy "constant across rows" invariant, this carries the rate slots
/// across the 4-row gap between the two sponge permutations.
pub(crate) const O_SPONGE_CARRY_RATE: usize = O_RCM_FE3 + 1;

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
pub(crate) const O_D_LIMB0: usize = O_SPONGE_CARRY_RATE + 8;
pub(crate) const O_PK_D_LIMB0: usize = O_D_LIMB0 + 8;
pub(crate) const O_IVK_COMMITMENT_LIMB0: usize = O_PK_D_LIMB0 + 16;
pub(crate) const O_RCM_LIMB0: usize = O_IVK_COMMITMENT_LIMB0 + 16;

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
pub(crate) const fn spend_proxy_offset(i: usize) -> usize {
    GLOBAL_COLS + i * per_spend_cols()
}

/// Offset of `S_CURRENT_FE[0..4]` (running Merkle 4-fe digest) within
/// spend `i`. Placed immediately after the constant-across-rows proxies.
#[inline]
pub(crate) const fn spend_var_offset(i: usize) -> usize {
    spend_proxy_offset(i) + SPEND_PROXY_COLS
}

/// Offset of the shared Merkle width-8 Poseidon2 column block within
/// spend `i` (K-air-col-share step 1 — row-loop over the 32 levels).
#[inline]
pub(crate) const fn spend_p2_offset(i: usize) -> usize {
    spend_var_offset(i) + SPEND_VAR_COLS
}

#[inline]
pub(crate) const fn output_proxy_offset(n_spends: usize, j: usize) -> usize {
    GLOBAL_COLS + n_spends * per_spend_cols() + j * per_output_cols()
}

/// Enumerated narrow (width-8) per-spend Poseidon2 slot.
///
/// After K-air-col-step2 the per-spend narrow block holds only the shared
/// Merkle row-loop; IvkCm and Nf moved to the globally-shared
/// `G_IVKCM_NF_SHARED_P2_8` block on rows 0..3 and 4..7 respectively.
#[derive(Copy, Clone)]
pub(crate) enum SpendP2 {
    /// Shared Merkle-path width-8 Poseidon2 slot (row-loop — level `k` is
    /// on trace row `k`).
    Merkle,
}

#[inline]
pub(crate) fn spend_p2_group<T>(row: &[T], i: usize, s: SpendP2) -> &P2Cols<T> {
    let off = match s {
        SpendP2::Merkle => spend_p2_offset(i),
    };
    let group: &[T] = &row[off..off + POSEIDON2_COLS_PER_INSTANCE];
    <[T] as Borrow<P2Cols<T>>>::borrow(group)
}

/// Globally-shared width-16 Poseidon2 block for claim 2 (spend Cm) on
/// rows 0..3 and claim 6 (output Cm) on rows 4..7.
#[inline]
pub(crate) fn shared_cm_p2_group<T>(row: &[T]) -> &P2Cols16<T> {
    let group: &[T] = &row[G_CM_SHARED_P2_16..G_CM_SHARED_P2_16 + POSEIDON2_COLS_PER_INSTANCE_16];
    <[T] as Borrow<P2Cols16<T>>>::borrow(group)
}

/// Globally-shared width-8 Poseidon2 block for claim 3 (IvkCm) on rows
/// 0..3 and claim 4 (Nf) on rows 4..7.
#[inline]
pub(crate) fn shared_ivkcm_nf_p2_group<T>(row: &[T]) -> &P2Cols<T> {
    let group: &[T] =
        &row[G_IVKCM_NF_SHARED_P2_8..G_IVKCM_NF_SHARED_P2_8 + POSEIDON2_COLS_PER_INSTANCE];
    <[T] as Borrow<P2Cols<T>>>::borrow(group)
}

#[inline]
pub(crate) fn spend_col<T: Copy>(row: &[T], i: usize, local_idx: usize) -> T {
    row[spend_proxy_offset(i) + local_idx]
}

#[inline]
pub(crate) fn output_col<T: Copy>(row: &[T], n_spends: usize, j: usize, local_idx: usize) -> T {
    row[output_proxy_offset(n_spends, j) + local_idx]
}
