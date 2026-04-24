//! Column-layout constants for the MineUno AIR (Phase 3).
//!
//! MineUno is the wc=2 PoW mining transaction kind: a miner finds a
//! `nonce` such that
//!
//! ```text
//!   Poseidon2("uno-mine-v1" ‖ epoch ‖ nonce ‖ output_cm) < target
//! ```
//!
//! and submits a STARK proof showing the hash was computed honestly and
//! that `output_cm` is a well-formed commitment to a new note paying
//! `value` UNO to the miner's address. Bitcoin-style halving + 600s
//! target_delta + 21 M cap (see `doc/Mining-Design.md` §UNO Mining and
//! `doc/uno-mine-air-constraints.md`).
//!
//! ## Trace layout (single shared Poseidon2-w16 block, 4 active rows)
//!
//! The AIR uses TWO Poseidon2-width-16 sponges in-circuit:
//!
//! - **cm sponge** (15-fe iterated sponge, 2 permutations): produces
//!   `output_cm = Poseidon2("uno-cm-v1", d, pk_d, ivk_commitment, value, rcm)`.
//! - **PoW sponge** (9-fe iterated sponge, 2 permutations): produces
//!   `pow_hash = Poseidon2("uno-mine-v1", epoch, nonce[0..4], output_cm[0..4])`.
//!
//! Both share the same Poseidon2-w16 column block via row-selectors. Trace
//! height = 8 (4 active rows + 4 padding rows; padding carries a zero-input
//! permutation so the sub-AIR constraints are consistent on every row).
//!
//! ```text
//!   row 0: cm sponge perm 1   (absorb d_fe + pk_d_fe + ivk_cm_fe[0..2])
//!   row 1: cm sponge perm 2   (absorb ivk_cm_fe[2..4] + value + rcm_fe + pad)
//!   row 2: pow sponge perm 1  (absorb tag + epoch + nonce_fe[0..4] + cm_fe[0..2])
//!   row 3: pow sponge perm 2  (absorb cm_fe[2..4] + pad)
//!   rows 4-7: padding (zero-input permutation)
//! ```
//!
//! ## Public-input vector (12 Goldilocks elements = 96 bytes)
//!
//! ```text
//!   PI[0]      = epoch                  (u32 zero-extended)
//!   PI[1]      = value_nano             (u64 mint reward)
//!   PI[2..6]   = output_cm[0..4]        (4 limbs of 256-bit commitment, BE order)
//!   PI[6..10]  = pow_hash[0..4]         (4 limbs of 256-bit PoW hash, BE order)
//!   PI[10]     = remaining_pre          (u64; chain state at proof time)
//!   PI[11]     = remaining_post         (u64; = remaining_pre - value_nano)
//! ```
//!
//! Note: `target` is intentionally NOT in the PI. Target is a function of
//! `epoch` via the halving table + retargeting schedule, and the chain
//! already holds it in `UnoShardState::mine_target`. Including it in PI
//! would be redundant (and would let a malicious prover attempt to bait
//! the verifier with an inconsistent target).
//!
//! Off-circuit chain checks (in `compute-phase.cpp`):
//!
//! - `pow_hash < chain_state.mine_target` (the actual PoW threshold comparison)
//! - `value_nano = mine_reward_for_era(epoch / kEraSize)` (halving table)
//! - `remaining_post = remaining_pre - value_nano` (conservation)
//! - `remaining_post >= 0` (cap; arithmetic underflow check)
//! - `remaining_pre = chain_state.mine_remaining` (race protection)
//! - `epoch = chain_state.mine_epoch` (race protection)
//!
//! On-circuit (cryptographic) checks enforced by this AIR:
//!
//! 1. `output_cm = Poseidon2_full_sponge_15fe(...)` (cm well-form)
//! 2. `pow_hash = Poseidon2_iterated_sponge_9fe(...)` (PoW hash correctness)
//! 3. `output_cm` matches PI[6..10] (binding witness to public output_cm)
//! 4. `pow_hash` matches a witness column that the chain reads as `pow_hash`
//!    (see §AIR ↔ chain handoff below)
//! 5. Witness fields are field-element-canonical (no sub-canonical limbs)

use p3_goldilocks::Goldilocks;
use p3_poseidon2_air::{num_cols as p2_num_cols, Poseidon2Cols};

use crate::transfer_columns::{
    POSEIDON2_HALF_FULL_ROUNDS, POSEIDON2_PARTIAL_ROUNDS_16, POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS, POSEIDON2_WIDTH_16,
};

// ---------------------------------------------------------------------------
// Domain-separation tags
// ---------------------------------------------------------------------------

/// Domain tag for the MineUno PoW hash sponge.
/// ASCII: `0x01_75_6E_6F_6D_69_6E_65` = `"uno-mine"` with version-flag MSB.
/// First byte 0x01 is the scheme version flag (matches TAG_CM, TAG_NF
/// convention in `transfer_columns.rs`).
pub const TAG_MINE: u64 = 0x01_75_6E_6F_6D_69_6E_65;

// ---------------------------------------------------------------------------
// Trace dimensions
// ---------------------------------------------------------------------------

/// log2(trace height). 8 rows is enough for 4 Poseidon2 permutations + 4
/// padding rows, with comfortable headroom for the FRI low-degree extension.
pub const LOG_MINE_TRACE_HEIGHT: usize = 3;

/// Trace height (= 2^LOG_MINE_TRACE_HEIGHT = 8 rows).
pub const MINE_TRACE_HEIGHT: usize = 1 << LOG_MINE_TRACE_HEIGHT;

/// Trace columns per width-16 Poseidon2 permutation witness (= 316).
/// Re-exposes the `transfer_columns::POSEIDON2_COLS_PER_INSTANCE_16` value
/// for MineUno call sites without forcing a transitive import.
pub const MINE_POSEIDON2_COLS_16: usize = p2_num_cols::<
    POSEIDON2_WIDTH_16,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS_16,
>();

/// Alias for one width-16 Poseidon2 column-set, specialized to our params.
pub(crate) type MineP2Cols<T> = Poseidon2Cols<
    T,
    POSEIDON2_WIDTH_16,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS_16,
>;

// ---------------------------------------------------------------------------
// Row selectors
// ---------------------------------------------------------------------------
//
// Four one-hot row selectors gate which logical Poseidon2 instance the
// shared sub-AIR is currently evaluating. On any active row exactly one
// selector is 1 and the other three are 0; on padding rows all four are 0
// (the sub-AIR runs a zero-input permutation that satisfies the constraint
// trivially).

/// Row 0: row-selector for the cm sponge's first permutation
/// (absorb diversifier + pk_d + ivk_commitment partial).
pub const COL_SEL_CM_P1: usize = 0;

/// Row 1: row-selector for the cm sponge's second permutation
/// (absorb ivk_commitment continuation + value + rcm).
pub const COL_SEL_CM_P2: usize = 1;

/// Row 2: row-selector for the PoW sponge's first permutation.
pub const COL_SEL_POW_P1: usize = 2;

/// Row 3: row-selector for the PoW sponge's second permutation.
pub const COL_SEL_POW_P2: usize = 3;

/// Total row-selector columns (the shared P2 block follows immediately).
pub const N_ROW_SELECTORS: usize = 4;

// ---------------------------------------------------------------------------
// Witness proxy columns
// ---------------------------------------------------------------------------
//
// Witness proxies are columns that hold a witness value verbatim and are
// constrained to be CONSTANT across all 8 trace rows (transition constraint
// `local == next` applied per column). The AIR enforces that the proxies
// equal the corresponding Poseidon2 sponge inputs/outputs on the active
// row, and the Air-level row-0 binding ties the public-output proxies
// (output_cm, pow_hash) to the public-input vector.

/// Base index of the witness proxy block (immediately after row selectors
/// and the shared P2 column block).
pub const WITNESS_PROXY_BASE: usize = N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16;

/// `epoch` (1 fe). Equals `PI[0]`.
pub const COL_W_EPOCH: usize = WITNESS_PROXY_BASE;

/// `value_nano` (1 fe). Equals `PI[5]`.
pub const COL_W_VALUE: usize = WITNESS_PROXY_BASE + 1;

/// Diversifier `d` packed into 2 fes via `pack_diversifier_as_2fe`
/// (16-byte zero-padded preimage). Mirrors the output side of Transfer.
pub const COL_W_D_FE0: usize = WITNESS_PROXY_BASE + 2;
pub const COL_W_D_FE1: usize = WITNESS_PROXY_BASE + 3;

/// `pk_d` packed as 4 fes via `pack_32b_as_4fe`.
pub const COL_W_PK_D_FE0: usize = WITNESS_PROXY_BASE + 4;
pub const COL_W_PK_D_FE3: usize = WITNESS_PROXY_BASE + 7;

/// `ivk_commitment` packed as 4 fes via `pack_32b_as_4fe`.
pub const COL_W_IVK_CM_FE0: usize = WITNESS_PROXY_BASE + 8;
pub const COL_W_IVK_CM_FE3: usize = WITNESS_PROXY_BASE + 11;

/// `rcm` packed as 4 fes (= Poseidon2("uno-rcm-v1", rseed); off-circuit).
pub const COL_W_RCM_FE0: usize = WITNESS_PROXY_BASE + 12;
pub const COL_W_RCM_FE3: usize = WITNESS_PROXY_BASE + 15;

/// `nonce` packed as 4 fes via `pack_32b_as_4fe`.
pub const COL_W_NONCE_FE0: usize = WITNESS_PROXY_BASE + 16;
pub const COL_W_NONCE_FE3: usize = WITNESS_PROXY_BASE + 19;

/// `output_cm` packed as 4 fes (the cm sponge's output, also PI[6..10]).
pub const COL_W_OUTPUT_CM_FE0: usize = WITNESS_PROXY_BASE + 20;
pub const COL_W_OUTPUT_CM_FE3: usize = WITNESS_PROXY_BASE + 23;

/// `pow_hash` packed as 4 fes (the pow sponge's output; chain checks
/// against target off-circuit).
pub const COL_W_POW_HASH_FE0: usize = WITNESS_PROXY_BASE + 24;
pub const COL_W_POW_HASH_FE3: usize = WITNESS_PROXY_BASE + 27;

/// Total witness proxy columns.
pub const N_WITNESS_PROXY: usize = 28;

// ---------------------------------------------------------------------------
// Total AIR width
// ---------------------------------------------------------------------------

/// Total column count for the MineUno AIR.
pub const MINE_AIR_WIDTH: usize =
    N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16 + N_WITNESS_PROXY;

// ---------------------------------------------------------------------------
// Public-input layout
// ---------------------------------------------------------------------------

/// Public-input index for `epoch`.
pub const PI_EPOCH: usize = 0;

/// Public-input index for `value_nano`.
pub const PI_VALUE: usize = 1;

/// Public-input base index for `output_cm` (4 limbs follow at PI[2..6]).
pub const PI_OUTPUT_CM_BASE: usize = 2;

/// Public-input base index for `pow_hash` (4 limbs follow at PI[6..10]).
pub const PI_POW_HASH_BASE: usize = 6;

/// Public-input index for `remaining_pre`.
pub const PI_REMAINING_PRE: usize = 10;

/// Public-input index for `remaining_post`.
pub const PI_REMAINING_POST: usize = 11;

/// Total public-input vector length (Goldilocks elements).
pub const N_PUBLIC_INPUTS: usize = 12;

/// Total public-input wire byte length (`N_PUBLIC_INPUTS * 8`).
pub const PUBLIC_INPUT_BYTES: usize = N_PUBLIC_INPUTS * 8;

// ---------------------------------------------------------------------------
// Sanity asserts
// ---------------------------------------------------------------------------

const _: () = assert!(
    COL_W_PK_D_FE3 - COL_W_PK_D_FE0 == 3,
    "pk_d must occupy exactly 4 fe-limb columns"
);
const _: () = assert!(
    COL_W_IVK_CM_FE3 - COL_W_IVK_CM_FE0 == 3,
    "ivk_commitment must occupy exactly 4 fe-limb columns"
);
const _: () = assert!(
    COL_W_RCM_FE3 - COL_W_RCM_FE0 == 3,
    "rcm must occupy exactly 4 fe-limb columns"
);
const _: () = assert!(
    COL_W_NONCE_FE3 - COL_W_NONCE_FE0 == 3,
    "nonce must occupy exactly 4 fe-limb columns"
);
const _: () = assert!(
    COL_W_OUTPUT_CM_FE3 - COL_W_OUTPUT_CM_FE0 == 3,
    "output_cm must occupy exactly 4 fe-limb columns"
);
const _: () = assert!(
    COL_W_POW_HASH_FE3 - COL_W_POW_HASH_FE0 == 3,
    "pow_hash must occupy exactly 4 fe-limb columns"
);
const _: () = assert!(MINE_TRACE_HEIGHT == 8, "MineUno trace must be 8 rows");
const _: () = assert!(
    LOG_MINE_TRACE_HEIGHT == 3 && (1 << LOG_MINE_TRACE_HEIGHT) == MINE_TRACE_HEIGHT,
    "log2 trace height must match MINE_TRACE_HEIGHT"
);

// ---------------------------------------------------------------------------
// Helper: trace cell type alias
// ---------------------------------------------------------------------------

/// Convenience alias for Goldilocks trace cells.
pub(crate) type Val = Goldilocks;
