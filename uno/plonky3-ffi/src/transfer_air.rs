//! Transfer AIR for the Uno workchain — P.2 foundation (real Poseidon2
//! compression).
//!
//! # What this file proves
//!
//! This AIR is still MVP-shaped (one proxy field element per semantic
//! value) but it has been upgraded away from linear `MIX_COEF` stand-ins
//! to **real Poseidon2-over-Goldilocks compression** for four of the
//! §4.2 Transfer claims:
//!
//! - **Claim 1 (Merkle step)**: `parent = Poseidon2(leaf, sibling)`.
//!   Single-step (32-level scale-out is P.2 follow-up).
//!
//! - **Claim 2 (Note opening)**: `cm = Poseidon2("uno-cm-v1", d,
//!   pk_d.bytes, ivk_commitment, value, rcm)`. The five non-tag inputs
//!   are single-field-element proxies for the full-width Transfer AIR's
//!   multi-element fields (per §3.2, the real circuit packs 15 field
//!   elements into a wide-sponge Poseidon2-16; the single-proxy shape
//!   here keeps the constraint family honest while the Poseidon2 width
//!   stays at 8).
//!
//! - **Claim 3 (Ownership via ivk-commitment binding)**:
//!   `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)`. Real
//!   Poseidon2 replaces the `IVK_CM_MIX_COEF` placeholder.
//!
//! - **Claim 4 (Nullifier derivation)**: `nf = Poseidon2("uno-nf-v1",
//!   nk, cm, pos)`. Real Poseidon2-8 compression; `cm` is taken from
//!   the note-opening output column (i.e. `cm == leaf`, matching how
//!   the Merkle step sees the spent note).
//!
//! Claims 5, 6, 7, 8, 9 (value range, spend-auth, per-output opening,
//! output range, balance) are OUT OF SCOPE for this agent and remain
//! either placeholder (claim 5: the MVP's 63-bit bit-decomposition is
//! kept for now) or unimplemented.
//!
//! # Poseidon2 choice: width 8 everywhere (§16 decision tracking)
//!
//! All four compressions use `Poseidon2Goldilocks<8>` with the audited
//! round constants from `p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_*`
//! (decision #42). Width 8 is sufficient here because:
//!
//! - Merkle step has 2 inputs + 6 padding/capacity slots.
//! - IVK-CM has domain-tag + 2 inputs + 5 padding slots.
//! - CM has domain-tag + 5 proxy inputs + 2 padding slots. The real
//!   Transfer AIR needs Poseidon2-16 here (15 field elements); the
//!   proxy-shape MVP does not.
//! - NF has domain-tag + 3 inputs + 4 padding slots.
//!
//! Follow-up P.2 work: widen CM's Poseidon2 to t=16 and expand
//! proxies to their real-AIR multi-element shapes. Same audited
//! constants, different width.
//!
//! # AIR structure
//!
//! The trace has width
//!
//! ```text
//! NUM_COLS = MVP_PROXY_COLS + 4 * POSEIDON2_COLS_PER_INSTANCE
//!          = 11 + 4 * 180 = 731
//! ```
//!
//! (plus the existing range-check scaffold).  `MVP_PROXY_COLS` now
//! carries, in addition to the original 7, the four new single-element
//! witness proxies (`pk_d`, `rcm`, `nk`, `pos`) needed for claims 2 / 4.
//! The 180 comes from `num_cols::<8, 7, 1, 4, 22>()` of the upstream
//! `p3_poseidon2_air` crate.
//!
//! Trace height stays at `2^6 = 64` rows (range-check holdover). The
//! Poseidon2 constraints hold on every row (the prover fills rows 1..63
//! with honest permutations of arbitrary inputs — see trace generation);
//! only row 0 binds the Poseidon2 inputs/outputs to the MVP proxy
//! columns and public inputs.
//!
//! # Public inputs (unchanged from MVP — decision #5)
//!
//! Layout (Goldilocks elements):
//!   - `[0]`: declared parent digest (Merkle step output)
//!   - `[1]`: declared leaf digest  (= `cm`; Merkle step input; also
//!     claim-2 output)
//!   - `[2]`: declared range-checked value
//!   - `[3]`: declared ivk_commitment (= claim-3 output; also
//!     claim-2 input)
//!
//! `nf` is NOT a public input at this stage; the constraint guarantees
//! consistency but exposing it is a follow-up P.2 scope item.
//!
//! # Witness
//!
//! Wire length grew from **32 B** (MVP) to **64 B** (P.2 upgrade), to
//! carry the four new proxies: `pk_d`, `rcm`, `nk`, `pos`. See
//! [`MvpWitness::encode`] for the exact layout.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Dup, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS, GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8, Goldilocks,
    GenericPoseidon2LinearLayersGoldilocks, default_goldilocks_poseidon2_8,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{
    FullRound, PartialRound, Poseidon2Cols, RoundConstants, SBox, num_cols as p2_num_cols,
};
use p3_symmetric::Permutation;

use crate::Plonky3Status;

// ---------------------------------------------------------------------------
// Poseidon2 parameters
// ---------------------------------------------------------------------------

/// Width of the Poseidon2 permutation used throughout this AIR.
///
/// Width 8 matches the Goldilocks `Poseidon2Goldilocks<8>` default; it is
/// big enough for every compression in the MVP proxy shape (§ module doc).
pub const POSEIDON2_WIDTH: usize = 8;

/// S-box degree (α=7 on Goldilocks per Plonky3's `GOLDILOCKS_S_BOX_DEGREE`).
pub const POSEIDON2_SBOX_DEGREE: u64 = 7;

/// Number of committed intermediate registers per S-box at degree 7. Exactly
/// one (for `x^3`) is optimal per the Poseidon2 paper Appendix C.
pub const POSEIDON2_SBOX_REGISTERS: usize = 1;

/// Number of full rounds per half (beginning and ending). Total `R_F = 8`.
pub const POSEIDON2_HALF_FULL_ROUNDS: usize = GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS;

/// Number of partial rounds. `R_P = 22` for width-8 Goldilocks per §16
/// decision #42's audited parameter set.
pub const POSEIDON2_PARTIAL_ROUNDS: usize = GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8;

/// Number of trace columns occupied by one Poseidon2 permutation witness.
///
/// Concretely `8 + 4·(8·1 + 8) + 22·(1 + 1) + 4·(8·1 + 8) = 180` columns.
pub const POSEIDON2_COLS_PER_INSTANCE: usize = p2_num_cols::<
    POSEIDON2_WIDTH,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS,
>();

/// Alias: one Poseidon2 column-set specialized to our parameters.
type P2Cols<T> = Poseidon2Cols<
    T,
    POSEIDON2_WIDTH,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS,
>;

// ---------------------------------------------------------------------------
// Domain separation tags for Poseidon2 compressions
// ---------------------------------------------------------------------------
//
// These are single-field-element proxies for the full ASCII labels
// specified in §2.2/§3.2 of the design doc (e.g. `"uno-ivk-cm-v1"`).
// In the real Transfer AIR the tag occupies one Goldilocks element and
// is the first absorb slot; here we keep the same shape but pack the
// label into a u64 with the top byte = 0x01 as a version marker.

/// Domain tag for the IVK-commitment Poseidon2. `"uno-ivk-cm" || 0x01`.
pub const TAG_IVK_CM: u64 = 0x01_75_6E_6F_69_76_6B_63; // top byte = version 1

/// Domain tag for the note-commitment Poseidon2. `"uno-cm-v1"` proxy.
pub const TAG_CM: u64 = 0x01_75_6E_6F_63_6D_76_31;

/// Domain tag for the nullifier Poseidon2. `"uno-nf-v1"` proxy.
pub const TAG_NF: u64 = 0x01_75_6E_6F_6E_66_76_31;

/// Merkle-step compression does NOT use a domain tag in §2.3
/// (`parent = Poseidon2(left, right)` is plain 2-to-1 compression).

// ---------------------------------------------------------------------------
// Column layout
// ---------------------------------------------------------------------------

/// MVP proxy columns (semantic, all single field elements per MVP-proxy
/// convention). See [`MvpRow`] for field-by-field documentation.
pub const MVP_PROXY_COLS: usize = 11;

/// Index (in the raw row slice) where the four Poseidon2 column groups
/// begin. Groups are laid out in order: Merkle, IVK-CM, CM, NF.
const POSEIDON2_GROUP_OFFSETS: [usize; 4] = [
    MVP_PROXY_COLS,
    MVP_PROXY_COLS + POSEIDON2_COLS_PER_INSTANCE,
    MVP_PROXY_COLS + 2 * POSEIDON2_COLS_PER_INSTANCE,
    MVP_PROXY_COLS + 3 * POSEIDON2_COLS_PER_INSTANCE,
];

/// Slot enum for readability when addressing a Poseidon2 group.
#[derive(Copy, Clone)]
#[allow(clippy::upper_case_acronyms)]
enum P2Slot {
    Merkle = 0,
    IvkCm = 1,
    Cm = 2,
    Nf = 3,
}

/// Total number of trace columns. See module-level doc.
///
/// = `MVP_PROXY_COLS + 4 * POSEIDON2_COLS_PER_INSTANCE` = 11 + 720 = 731.
pub const NUM_COLS: usize = MVP_PROXY_COLS + 4 * POSEIDON2_COLS_PER_INSTANCE;

/// Column indices — kept for documentation / debug-trace tooling. The AIR
/// itself reads through the typed [`MvpRow`] view; these are not exported
/// across the FFI.
#[allow(dead_code)]
#[doc(hidden)]
pub(crate) mod col {
    pub const LEAF: usize = 0;
    pub const SIBLING: usize = 1;
    pub const PARENT_CLAIM: usize = 2;
    pub const VALUE_ACC: usize = 3;
    pub const VALUE_BIT: usize = 4;
    pub const IVK: usize = 5;
    pub const IVK_COMMITMENT_CLAIM: usize = 6;
    pub const PK_D: usize = 7;
    pub const RCM: usize = 8;
    pub const NK: usize = 9;
    pub const POS: usize = 10;
}

/// Log2 of the trace height. 64 rows = 2^6.
///
/// Chosen so that the bit-decomposition column accumulates 64 bits over 64
/// transitions — covers values up to 2^63. Real Transfer AIR uses the same
/// structure with a sign-bit extension to cover the full u64 range.
pub const LOG_TRACE_HEIGHT: usize = 6;

/// Trace height = 2^LOG_TRACE_HEIGHT.
pub const TRACE_HEIGHT: usize = 1 << LOG_TRACE_HEIGHT;

/// Number of public inputs.
///
/// Layout (Goldilocks elements, indexed):
/// - `[0]`: declared parent digest (Merkle step output)
/// - `[1]`: declared leaf digest  (Merkle step input; also claim-2 cm)
/// - `[2]`: declared range-checked value
/// - `[3]`: declared ivk_commitment (claim-3 output; claim-2 input)
pub const NUM_PUBLIC_INPUTS: usize = 4;

/// Byte length of the public-input wire encoding. Each Goldilocks element
/// is serialized as 8 little-endian bytes.
pub const PUBLIC_INPUTS_WIRE_LEN: usize = NUM_PUBLIC_INPUTS * 8;

// ---------------------------------------------------------------------------
// Row view
// ---------------------------------------------------------------------------

/// Typed view of one MVP trace row (PROXY columns only; Poseidon2 column
/// groups sit after these in the raw row slice and are viewed via
/// [`poseidon2_group`]).
#[repr(C)]
pub struct MvpRow<F> {
    /// `col::LEAF` — single-fe proxy for the spent note commitment `cm`.
    pub leaf: F,
    /// `col::SIBLING` — Merkle sibling (single-fe proxy). Also reused as
    /// the diversifier `d` proxy in claims 2 and 3.
    pub sibling: F,
    /// `col::PARENT_CLAIM` — trace-visible copy of the Merkle-step output.
    pub parent_claim: F,
    /// `col::VALUE_ACC`
    pub value_acc: F,
    /// `col::VALUE_BIT`
    pub value_bit: F,
    /// `col::IVK` — private-witness `ivk` proxy (§4.2 claim 3).
    pub ivk: F,
    /// `col::IVK_COMMITMENT_CLAIM` — trace-visible copy of the IVK-CM
    /// Poseidon2 output, bound to `public_inputs[3]` on row 0.
    pub ivk_commitment_claim: F,
    /// `col::PK_D` — proxy for `pk_d.bytes` (claim 2).
    pub pk_d: F,
    /// `col::RCM` — proxy for the randomness `rcm` (claim 2).
    pub rcm: F,
    /// `col::NK` — proxy for the nullifier key (claim 4).
    pub nk: F,
    /// `col::POS` — proxy for the leaf position (claim 4).
    pub pos: F,
}

impl<F> Borrow<MvpRow<F>> for [F] {
    #[inline]
    fn borrow(&self) -> &MvpRow<F> {
        debug_assert!(self.len() >= MVP_PROXY_COLS);
        // SAFETY: the leading `MVP_PROXY_COLS` cells of a trace row are
        // laid out as `MvpRow` (repr(C), identically-typed fields).
        let head: &[F] = &self[..MVP_PROXY_COLS];
        let (prefix, shorts, suffix) = unsafe { head.align_to::<MvpRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

/// Borrow one of the four Poseidon2 column groups from a raw row slice.
#[inline]
fn poseidon2_group<T>(row: &[T], slot: P2Slot) -> &P2Cols<T> {
    let off = POSEIDON2_GROUP_OFFSETS[slot as usize];
    let group: &[T] = &row[off..off + POSEIDON2_COLS_PER_INSTANCE];
    <[T] as Borrow<P2Cols<T>>>::borrow(group)
}

// ---------------------------------------------------------------------------
// AIR definition
// ---------------------------------------------------------------------------

/// The Transfer AIR (claims 1, 2, 3, 4 — single-step / single-spend
/// / single-output — with range check retained from MVP).
///
/// Uses real Poseidon2-Goldilocks-8 compression in-circuit, with the
/// audited round constants sourced via `GOLDILOCKS_POSEIDON2_RC_8_*`
/// (§16 decision #42). See module-level doc for the constraint system.
#[derive(Debug, Clone, Copy, Default)]
pub struct MvpTransferAir;

impl MvpTransferAir {
    /// Build the AIR. All Poseidon2 round constants are compile-time
    /// constants from `p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_*`;
    /// prover and verifier both read them through this type.
    pub const fn new() -> Self {
        Self
    }
}

/// Audited Goldilocks Poseidon2-8 round constants, typed so both the AIR
/// (symbolic builder) and the trace generator (concrete Goldilocks) can
/// read from the same source.
#[inline]
fn beginning_full_round_constant<F: PrimeCharacteristicRing>(round: usize) -> [F; POSEIDON2_WIDTH] {
    let src = &p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL[round];
    core::array::from_fn(|i| F::from_u64(src[i].as_canonical_u64()))
}

#[inline]
fn ending_full_round_constant<F: PrimeCharacteristicRing>(round: usize) -> [F; POSEIDON2_WIDTH] {
    let src = &p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL[round];
    core::array::from_fn(|i| F::from_u64(src[i].as_canonical_u64()))
}

#[inline]
fn partial_round_constant<F: PrimeCharacteristicRing>(round: usize) -> F {
    F::from_u64(p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_INTERNAL[round].as_canonical_u64())
}

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for MvpTransferAir {
    #[inline]
    fn width(&self) -> usize {
        NUM_COLS
    }

    #[inline]
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_INPUTS
    }

    #[inline]
    fn max_constraint_degree(&self) -> Option<usize> {
        // Let the symbolic evaluator compute the actual degree. A
        // conservative hint is fine in principle, but an under-hint
        // silently produces a wrong-size quotient polynomial; returning
        // `None` avoids the trap without noticeable prove-cost impact
        // (the symbolic walk runs once at prove/verify startup).
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

        let local: &MvpRow<AB::Var> = local_slice.borrow();
        let next: &MvpRow<AB::Var> = next_slice.borrow();

        let pis = builder.public_values();
        let declared_parent = pis[0];
        let declared_leaf = pis[1];
        let declared_value = pis[2];
        let declared_ivk_commitment = pis[3];

        // ---- Poseidon2 sub-AIR constraints on EVERY row ----------------
        //
        // Each of the four Poseidon2 column groups must represent a valid
        // permutation of its `inputs` to its `ending_full_rounds` final
        // `post` state. The prover fills rows 1..=TRACE_HEIGHT-1 with
        // honest permutations over arbitrary inputs (see
        // `MvpWitness::generate_trace`); the binding constraints below
        // only check row 0.
        eval_poseidon2(builder, poseidon2_group::<AB::Var>(local_slice, P2Slot::Merkle));
        eval_poseidon2(builder, poseidon2_group::<AB::Var>(local_slice, P2Slot::IvkCm));
        eval_poseidon2(builder, poseidon2_group::<AB::Var>(local_slice, P2Slot::Cm));
        eval_poseidon2(builder, poseidon2_group::<AB::Var>(local_slice, P2Slot::Nf));

        // ---- First-row: wire Poseidon2 inputs + outputs to MVP proxies
        {
            let mut first = builder.when_first_row();

            // --- Claim 1: Merkle step ---
            // inputs = [leaf, sibling, 0, 0, 0, 0, 0, 0]
            // output = inputs_after_perm[0]  → must equal parent_claim
            //
            // `ending_full_rounds[last].post[0]` is the degree-1 final
            // state slot. See `p3_poseidon2_air::eval` for where the
            // permutation places its output.
            let merkle = poseidon2_group::<AB::Var>(local_slice, P2Slot::Merkle);
            first.assert_eq(merkle.inputs[0], local.leaf);
            first.assert_eq(merkle.inputs[1], local.sibling);
            // Pad remaining input slots to zero so a malicious prover
            // cannot smuggle extra entropy.
            for i in 2..POSEIDON2_WIDTH {
                first.assert_zero(merkle.inputs[i].into());
            }
            // Output of the permutation: final `post[0]` after the last
            // external round. Bind to `parent_claim`.
            let merkle_out = &merkle.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
            first.assert_eq(merkle_out[0], local.parent_claim);

            // Bind `parent_claim` and `leaf` to public inputs. `leaf`
            // is ALSO the claim-2 `cm` anchor — hence the note-opening
            // binding below ties `cm = Poseidon2(...) == declared_leaf`.
            first.assert_eq(local.parent_claim, declared_parent);
            first.assert_eq(local.leaf, declared_leaf);

            // --- Claim 3: IVK-commitment binding ---
            // inputs = [TAG_IVK_CM, ivk, sibling(=d), 0, 0, 0, 0, 0]
            // output[0] → must equal ivk_commitment_claim
            let ivkcm = poseidon2_group::<AB::Var>(local_slice, P2Slot::IvkCm);
            first.assert_eq(
                ivkcm.inputs[0].into(),
                AB::Expr::from(AB::F::from_u64(TAG_IVK_CM)),
            );
            first.assert_eq(ivkcm.inputs[1], local.ivk);
            first.assert_eq(ivkcm.inputs[2], local.sibling);
            for i in 3..POSEIDON2_WIDTH {
                first.assert_zero(ivkcm.inputs[i].into());
            }
            let ivkcm_out = &ivkcm.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
            first.assert_eq(ivkcm_out[0], local.ivk_commitment_claim);
            first.assert_eq(local.ivk_commitment_claim, declared_ivk_commitment);

            // --- Claim 2: Note opening (cm) ---
            // inputs = [TAG_CM, d(=sibling), pk_d, ivk_commitment,
            //           value, rcm, 0, 0]
            // output[0] → must equal leaf (i.e. cm == declared_leaf)
            let cm = poseidon2_group::<AB::Var>(local_slice, P2Slot::Cm);
            first.assert_eq(
                cm.inputs[0].into(),
                AB::Expr::from(AB::F::from_u64(TAG_CM)),
            );
            first.assert_eq(cm.inputs[1], local.sibling);
            first.assert_eq(cm.inputs[2], local.pk_d);
            first.assert_eq(cm.inputs[3], local.ivk_commitment_claim);
            // value enters as a single field element (u64 fits in
            // Goldilocks). The AIR's range-check chain is separate
            // (claim 5, out of scope here) but still wires the same
            // public input.
            first.assert_eq(cm.inputs[4].into(), declared_value);
            first.assert_eq(cm.inputs[5], local.rcm);
            for i in 6..POSEIDON2_WIDTH {
                first.assert_zero(cm.inputs[i].into());
            }
            let cm_out = &cm.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
            // Bind the computed cm to the publicly-declared leaf (= cm).
            first.assert_eq(cm_out[0], local.leaf);

            // --- Claim 4: Nullifier ---
            // inputs = [TAG_NF, nk, cm(=leaf), pos, 0, 0, 0, 0]
            // output[0] is the nullifier — kept as a free witness at
            // this stage (no PI binding; follow-up P.2 agent adds it).
            let nf = poseidon2_group::<AB::Var>(local_slice, P2Slot::Nf);
            first.assert_eq(
                nf.inputs[0].into(),
                AB::Expr::from(AB::F::from_u64(TAG_NF)),
            );
            first.assert_eq(nf.inputs[1], local.nk);
            // Bind the nullifier's `cm` input to the leaf (i.e. the
            // claim-1 Merkle-step input, which equals claim-2 cm output).
            first.assert_eq(nf.inputs[2], local.leaf);
            first.assert_eq(nf.inputs[3], local.pos);
            for i in 4..POSEIDON2_WIDTH {
                first.assert_zero(nf.inputs[i].into());
            }

            // Range-check accumulator starts at value_bit[row 0] (the MSB).
            first.assert_eq(local.value_acc, local.value_bit);
        }

        // ---- Per-row bit-ness check (claim 5 scaffold, kept from MVP) --
        builder.assert_bool(local.value_bit);

        // ---- Per-row replica checks for MVP proxy columns --------------
        //
        // The leaf/sibling/parent/ivk/ivk_commitment/pk_d/rcm/nk/pos
        // columns are single-row witnesses; replicate across the 64-row
        // trace so a prover cannot silently change them mid-trace (which
        // would produce different Poseidon2 inputs on other rows). We
        // do NOT replicate value_acc/value_bit — they carry distinct
        // per-row data for the bit decomposition.
        {
            let mut t = builder.when_transition();
            t.assert_eq(next.leaf, local.leaf);
            t.assert_eq(next.sibling, local.sibling);
            t.assert_eq(next.parent_claim, local.parent_claim);
            t.assert_eq(next.ivk, local.ivk);
            t.assert_eq(next.ivk_commitment_claim, local.ivk_commitment_claim);
            t.assert_eq(next.pk_d, local.pk_d);
            t.assert_eq(next.rcm, local.rcm);
            t.assert_eq(next.nk, local.nk);
            t.assert_eq(next.pos, local.pos);

            // Range-check accumulator transition:
            //   value_acc_next = value_acc_curr * 2 + value_bit_next
            let two = AB::Expr::from(AB::F::from_u64(2));
            t.assert_eq(
                next.value_acc.into(),
                local.value_acc.into() * two + next.value_bit.into(),
            );
        }

        // ---- Last-row: range check public binding ----------------------
        {
            let mut last = builder.when_last_row();
            last.assert_eq(local.value_acc, declared_value);
        }
    }
}

// ---------------------------------------------------------------------------
// Local Poseidon2 constraint evaluation
// ---------------------------------------------------------------------------
//
// Upstream `p3_poseidon2_air::eval` is `pub(crate)`, so we reimplement
// the round-by-round constraint walk here using the public fields of
// `Poseidon2Cols` / `FullRound` / `PartialRound` / `SBox`. The logic
// mirrors `poseidon2-air/src/air.rs` byte-for-byte; only the privacy
// boundary differs. A mismatch with upstream would show up as a failing
// prove/verify round-trip on the very first test — byte-identical round
// constants (via `beginning_full_round_constant` etc.) and the same
// `GenericPoseidon2LinearLayersGoldilocks` linear-layer definition
// ensure identity.

fn eval_poseidon2<AB>(builder: &mut AB, local: &P2Cols<AB::Var>)
where
    AB: AirBuilder,
{
    let mut state: [AB::Expr; POSEIDON2_WIDTH] = local.inputs.map(|x| x.into());

    <GenericPoseidon2LinearLayersGoldilocks as GenericPoseidon2LinearLayers<
        POSEIDON2_WIDTH,
    >>::external_linear_layer(&mut state);

    for round in 0..POSEIDON2_HALF_FULL_ROUNDS {
        eval_full_round::<AB>(
            &mut state,
            &local.beginning_full_rounds[round],
            &beginning_full_round_constant::<AB::F>(round),
            builder,
        );
    }

    for round in 0..POSEIDON2_PARTIAL_ROUNDS {
        eval_partial_round::<AB>(
            &mut state,
            &local.partial_rounds[round],
            &partial_round_constant::<AB::F>(round),
            builder,
        );
    }

    for round in 0..POSEIDON2_HALF_FULL_ROUNDS {
        eval_full_round::<AB>(
            &mut state,
            &local.ending_full_rounds[round],
            &ending_full_round_constant::<AB::F>(round),
            builder,
        );
    }
}

#[inline]
fn eval_full_round<AB: AirBuilder>(
    state: &mut [AB::Expr; POSEIDON2_WIDTH],
    full_round: &FullRound<
        AB::Var,
        POSEIDON2_WIDTH,
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
    >,
    round_constants: &[AB::F; POSEIDON2_WIDTH],
    builder: &mut AB,
) {
    for (i, (s, r)) in state
        .iter_mut()
        .zip(round_constants.iter())
        .enumerate()
    {
        *s += r.dup();
        eval_sbox(&full_round.sbox[i], s, builder);
    }
    <GenericPoseidon2LinearLayersGoldilocks as GenericPoseidon2LinearLayers<
        POSEIDON2_WIDTH,
    >>::external_linear_layer(state);
    for (state_i, post_i) in state.iter_mut().zip(full_round.post) {
        builder.assert_eq(state_i.clone(), post_i);
        *state_i = post_i.into();
    }
}

#[inline]
fn eval_partial_round<AB: AirBuilder>(
    state: &mut [AB::Expr; POSEIDON2_WIDTH],
    partial_round: &PartialRound<
        AB::Var,
        POSEIDON2_WIDTH,
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
    >,
    round_constant: &AB::F,
    builder: &mut AB,
) {
    state[0] += round_constant.dup();
    eval_sbox(&partial_round.sbox, &mut state[0], builder);
    builder.assert_eq(state[0].dup(), partial_round.post_sbox);
    state[0] = partial_round.post_sbox.into();
    <GenericPoseidon2LinearLayersGoldilocks as GenericPoseidon2LinearLayers<
        POSEIDON2_WIDTH,
    >>::internal_linear_layer(state);
}

#[inline]
fn eval_sbox<AB: AirBuilder>(
    sbox: &SBox<AB::Var, POSEIDON2_SBOX_DEGREE, POSEIDON2_SBOX_REGISTERS>,
    x: &mut AB::Expr,
    builder: &mut AB,
) {
    // DEGREE=7, REGISTERS=1: commit x^3, assert committed = x^3, return
    // committed^2 * x = x^6 * x = x^7.
    let committed_x3: AB::Expr = sbox.0[0].into();
    builder.assert_eq(committed_x3.dup(), x.cube());
    *x = committed_x3.square() * x.dup();
}

// ---------------------------------------------------------------------------
// Witness struct + trace generation
// ---------------------------------------------------------------------------

/// A witness to the MVP AIR, in a form callable from tests and the FFI
/// prover entry point.
///
/// P.2 upgrade: the witness now carries four additional single-fe
/// proxies required for claims 2 (`pk_d`, `rcm`) and 4 (`nk`, `pos`).
#[derive(Debug, Clone)]
pub struct MvpWitness {
    /// Single-fe proxy for the note commitment `cm`. The leaf column is
    /// bound to public input `[1]` and — via the claim-2 Poseidon2 —
    /// must equal `Poseidon2("uno-cm-v1", d, pk_d, ivk_commitment,
    /// value, rcm)`. The honest prover therefore derives `leaf` from
    /// the other witness fields.
    pub leaf: u64,
    /// Merkle sibling at the step being proved (single-fe proxy). Also
    /// reused as the `d` proxy in claims 2 and 3.
    pub merkle_sibling: [u8; 8],
    /// The u64 value being range-checked. Also enters the claim-2
    /// Poseidon2 as a single field element (u64 < p_Goldilocks).
    pub value: u64,
    /// Private-witness `ivk` proxy (§4.2 claim 3).
    pub ivk: u64,
    /// Proxy for `pk_d.bytes` (§4.2 claim 2). In the real AIR this is
    /// 4 field elements (32-byte compressed Ristretto); here it is one
    /// field element for witness-shape symmetry with the other proxies.
    pub pk_d: u64,
    /// Proxy for the note randomness `rcm` (§4.2 claim 2).
    pub rcm: u64,
    /// Proxy for the nullifier key `nk` (§4.2 claim 4).
    pub nk: u64,
    /// Proxy for the leaf position `pos` (§4.2 claim 4).
    pub pos: u64,
}

impl MvpWitness {
    /// Build a deterministic valid witness, seeded by `seed`.
    ///
    /// The witness is self-consistent: `leaf` is computed as the
    /// Poseidon2 output of the note-opening inputs, so claim 2 holds.
    /// The other derived public inputs (`parent`, `ivk_commitment`)
    /// follow from this `leaf` + sibling + ivk via the same honest
    /// Poseidon2 permutation the AIR constrains.
    pub fn deterministic_valid(seed: u64) -> Self {
        let sibling_word = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x1234_0000_0000_0000;
        let value = (seed ^ 0xbabe_cafe_dead_f00d) & ((1u64 << 63) - 1); // 63-bit range
        let ivk = seed.wrapping_mul(0xc2b2_ae3d_27d4_eb4f) ^ 0x1efbe1edu64;
        let pk_d = seed.wrapping_mul(0x165667b1_9e37_79f9) ^ 0xdeca_d0de;
        let rcm = seed.wrapping_mul(0xd6e8_feb8_6659_fd93) ^ 0xfade_cafe;
        let nk = seed.wrapping_mul(0xcbf2_9ce4_8422_2325) ^ 0xba11_00ba;
        let pos = seed.wrapping_mul(0x100_0000_0001) & 0x00FF_FFFF_FFFF_FFFF;

        // Derive `ivk_commitment` = Poseidon2(TAG_IVK_CM, ivk, d, 0…).
        let perm = default_goldilocks_poseidon2_8();
        let d_word = u64::from_le_bytes(sibling_word.to_le_bytes());

        let mut ivkcm_state = [Goldilocks::default(); POSEIDON2_WIDTH];
        ivkcm_state[0] = Goldilocks::from_u64(TAG_IVK_CM);
        ivkcm_state[1] = Goldilocks::from_u64(reduce_to_goldilocks(ivk));
        ivkcm_state[2] = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
        perm.permute_mut(&mut ivkcm_state);
        let ivk_commitment_fe = ivkcm_state[0];
        let ivk_commitment_u = ivk_commitment_fe.as_canonical_u64();

        // Derive `cm` (= `leaf`) = Poseidon2(TAG_CM, d, pk_d,
        // ivk_commitment, value, rcm, 0, 0).
        let mut cm_state = [Goldilocks::default(); POSEIDON2_WIDTH];
        cm_state[0] = Goldilocks::from_u64(TAG_CM);
        cm_state[1] = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
        cm_state[2] = Goldilocks::from_u64(reduce_to_goldilocks(pk_d));
        cm_state[3] = ivk_commitment_fe;
        cm_state[4] = Goldilocks::from_u64(value);
        cm_state[5] = Goldilocks::from_u64(reduce_to_goldilocks(rcm));
        perm.permute_mut(&mut cm_state);
        let leaf_fe = cm_state[0];
        let leaf = leaf_fe.as_canonical_u64();

        // `ivk_commitment_u` is retained inside the PI derivation;
        // `leaf` becomes both the Merkle-step input and the claim-2
        // output. The sibling stays as-is (prover's free choice).
        let _ = ivk_commitment_u;

        Self {
            leaf,
            merkle_sibling: sibling_word.to_le_bytes(),
            value,
            ivk,
            pk_d,
            rcm,
            nk,
            pos,
        }
    }

    /// Serialize the witness to a byte buffer for the FFI path.
    ///
    /// Layout (64 B total, all u64 little-endian):
    /// `leaf(8) || sibling(8) || value(8) || ivk(8) || pk_d(8) ||
    ///  rcm(8) || nk(8) || pos(8)`
    ///
    /// P.2 upgrade: witness wire grew from 32 B (MVP) to 64 B; callers
    /// must size buffers accordingly. Consensus-binding: this is a
    /// prover-only wire format and does not affect the public-input
    /// encoding (which is unchanged — decision #5).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.leaf.to_le_bytes());
        out.extend_from_slice(&self.merkle_sibling);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&self.ivk.to_le_bytes());
        out.extend_from_slice(&self.pk_d.to_le_bytes());
        out.extend_from_slice(&self.rcm.to_le_bytes());
        out.extend_from_slice(&self.nk.to_le_bytes());
        out.extend_from_slice(&self.pos.to_le_bytes());
        out
    }

    /// Decode from wire bytes produced by [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, Plonky3Status> {
        if bytes.len() != 64 {
            return Err(Plonky3Status::WitnessInvalid);
        }
        let leaf = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let merkle_sibling: [u8; 8] = bytes[8..16].try_into().unwrap();
        let value = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let ivk = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let pk_d = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let rcm = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let nk = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
        let pos = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
        if value >> 63 != 0 {
            return Err(Plonky3Status::WitnessInvalid);
        }
        Ok(Self {
            leaf,
            merkle_sibling,
            value,
            ivk,
            pk_d,
            rcm,
            nk,
            pos,
        })
    }

    /// Verify the claim-2 relation: `leaf == Poseidon2("uno-cm-v1",
    /// d, pk_d, ivk_commitment, value, rcm)` holds under the canonical
    /// field reductions.
    ///
    /// Returns `true` for honest witnesses and `false` for any witness
    /// where the note-opening relation is violated (e.g. tampered
    /// `ivk`, tampered `sibling`, stale `leaf`). The prover's
    /// pre-check calls this to short-circuit a Plonky3-level panic
    /// into a structured `WitnessInvalid` status.
    pub fn claim2_cm_consistent(&self) -> bool {
        let perm = default_goldilocks_poseidon2_8();
        let d_word = u64::from_le_bytes(self.merkle_sibling);
        let ivkcm = self.compute_ivk_commitment();
        let mut state = [Goldilocks::default(); POSEIDON2_WIDTH];
        state[0] = Goldilocks::from_u64(TAG_CM);
        state[1] = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
        state[2] = Goldilocks::from_u64(reduce_to_goldilocks(self.pk_d));
        state[3] = ivkcm;
        state[4] = Goldilocks::from_u64(self.value);
        state[5] = Goldilocks::from_u64(reduce_to_goldilocks(self.rcm));
        perm.permute_mut(&mut state);
        state[0] == Goldilocks::from_u64(reduce_to_goldilocks(self.leaf))
    }

    /// Compute the `ivk_commitment` Goldilocks element from the
    /// witness, matching the claim-3 Poseidon2 formula.
    fn compute_ivk_commitment(&self) -> Goldilocks {
        let perm = default_goldilocks_poseidon2_8();
        let d_word = u64::from_le_bytes(self.merkle_sibling);
        let mut state = [Goldilocks::default(); POSEIDON2_WIDTH];
        state[0] = Goldilocks::from_u64(TAG_IVK_CM);
        state[1] = Goldilocks::from_u64(reduce_to_goldilocks(self.ivk));
        state[2] = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
        perm.permute_mut(&mut state);
        state[0]
    }

    /// Compute the Merkle-step parent from the witness.
    fn compute_parent(&self) -> Goldilocks {
        let perm = default_goldilocks_poseidon2_8();
        let d_word = u64::from_le_bytes(self.merkle_sibling);
        let mut state = [Goldilocks::default(); POSEIDON2_WIDTH];
        state[0] = Goldilocks::from_u64(reduce_to_goldilocks(self.leaf));
        state[1] = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
        perm.permute_mut(&mut state);
        state[0]
    }

    /// Derive the 4 public-input field elements from the witness.
    pub fn public_inputs(&self) -> [Goldilocks; NUM_PUBLIC_INPUTS] {
        let leaf_f = Goldilocks::from_u64(reduce_to_goldilocks(self.leaf));
        let parent_f = self.compute_parent();
        let value_f = Goldilocks::from_u64(self.value);
        let ivk_commitment_f = self.compute_ivk_commitment();
        [parent_f, leaf_f, value_f, ivk_commitment_f]
    }

    /// Encode the public inputs as the verifier wire format.
    pub fn public_inputs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_INPUTS_WIRE_LEN);
        for elem in self.public_inputs() {
            out.extend_from_slice(&elem.as_canonical_u64().to_le_bytes());
        }
        out
    }

    /// Generate the full trace matrix for this witness.
    ///
    /// Trace layout per row:
    ///   [MvpRow (11 cols)] ++ [Poseidon2Cols (180) × 4 groups]
    pub fn generate_trace(&self) -> RowMajorMatrix<Goldilocks> {
        let pis = self.public_inputs();
        let declared_leaf = pis[1];
        let declared_parent = pis[0];
        let declared_ivk_commitment = pis[3];

        let d_word = u64::from_le_bytes(self.merkle_sibling);
        let sibling_f = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
        let ivk_f = Goldilocks::from_u64(reduce_to_goldilocks(self.ivk));
        let pk_d_f = Goldilocks::from_u64(reduce_to_goldilocks(self.pk_d));
        let rcm_f = Goldilocks::from_u64(reduce_to_goldilocks(self.rcm));
        let nk_f = Goldilocks::from_u64(reduce_to_goldilocks(self.nk));
        let pos_f = Goldilocks::from_u64(reduce_to_goldilocks(self.pos));

        // Helper to generate a Poseidon2 row given the input state.
        // Returns the 180-column slice.
        let constants = RoundConstants::new(
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
        );
        let gen_p2_row = |input: [Goldilocks; POSEIDON2_WIDTH]| -> Vec<Goldilocks> {
            use p3_poseidon2_air::generate_trace_rows;
            // generate_trace_rows wants a power-of-two count; we generate
            // 1 permutation in a length-1 batch via its exact API.
            let mat = generate_trace_rows::<
                Goldilocks,
                GenericPoseidon2LinearLayersGoldilocks,
                POSEIDON2_WIDTH,
                POSEIDON2_SBOX_DEGREE,
                POSEIDON2_SBOX_REGISTERS,
                POSEIDON2_HALF_FULL_ROUNDS,
                POSEIDON2_PARTIAL_ROUNDS,
            >(vec![input], &constants, 0);
            debug_assert_eq!(mat.values.len(), POSEIDON2_COLS_PER_INSTANCE);
            mat.values
        };

        // Inputs for the four slots (row 0).
        let merkle_in: [Goldilocks; POSEIDON2_WIDTH] = {
            let mut s = [Goldilocks::default(); POSEIDON2_WIDTH];
            s[0] = declared_leaf;
            s[1] = sibling_f;
            s
        };
        let ivkcm_in: [Goldilocks; POSEIDON2_WIDTH] = {
            let mut s = [Goldilocks::default(); POSEIDON2_WIDTH];
            s[0] = Goldilocks::from_u64(TAG_IVK_CM);
            s[1] = ivk_f;
            s[2] = sibling_f;
            s
        };
        let cm_in: [Goldilocks; POSEIDON2_WIDTH] = {
            let mut s = [Goldilocks::default(); POSEIDON2_WIDTH];
            s[0] = Goldilocks::from_u64(TAG_CM);
            s[1] = sibling_f;
            s[2] = pk_d_f;
            s[3] = declared_ivk_commitment;
            s[4] = Goldilocks::from_u64(self.value);
            s[5] = rcm_f;
            s
        };
        let nf_in: [Goldilocks; POSEIDON2_WIDTH] = {
            let mut s = [Goldilocks::default(); POSEIDON2_WIDTH];
            s[0] = Goldilocks::from_u64(TAG_NF);
            s[1] = nk_f;
            s[2] = declared_leaf;
            s[3] = pos_f;
            s
        };

        // Row-0 Poseidon2 trace cells (real permutations on real inputs).
        let row0_merkle = gen_p2_row(merkle_in);
        let row0_ivkcm = gen_p2_row(ivkcm_in);
        let row0_cm = gen_p2_row(cm_in);
        let row0_nf = gen_p2_row(nf_in);

        // Note: for honest witnesses `extract_p2_output_zero` of each
        // row-0 group equals the respective public input. For ADVERSARIAL
        // witnesses (e.g. tampered ivk / sibling, used in negative tests)
        // the outputs will diverge — that is the desired behaviour, and
        // the AIR's first-row `assert_eq` bindings catch it either at
        // the DebugConstraintBuilder layer (returning WitnessInvalid)
        // or at verify time (returning VerifyFailed). We therefore do
        // NOT `debug_assert` consistency here; doing so would panic in
        // the negative test path before the guarded FFI boundary could
        // translate it to a status code.
        let _ = declared_parent;
        let _ = declared_ivk_commitment;
        let _ = declared_leaf;

        // For rows 1..TRACE_HEIGHT-1 we pick arbitrary (zero) inputs and
        // fill honestly. The AIR does not bind these Poseidon2 instances
        // to any public input, so they are free — but they MUST satisfy
        // the Poseidon2 constraints (every row of the sub-AIR is
        // enforced). Using the same zero input for all pads is OK.
        let padding_merkle = gen_p2_row([Goldilocks::default(); POSEIDON2_WIDTH]);
        let padding_ivkcm = padding_merkle.clone();
        let padding_cm = padding_merkle.clone();
        let padding_nf = padding_merkle.clone();

        // Pre-compute the 64 bits of `value`, MSB first, for the range
        // check scaffold carried from MVP.
        let mut bits_msb_first = [0u64; TRACE_HEIGHT];
        for i in 0..TRACE_HEIGHT {
            let bit_index_from_lsb = (TRACE_HEIGHT - 1) - i;
            bits_msb_first[i] = (self.value >> bit_index_from_lsb) & 1;
        }

        let mut values = Vec::<Goldilocks>::with_capacity(TRACE_HEIGHT * NUM_COLS);
        let mut acc: u64 = 0;
        for (row_idx, &bit) in bits_msb_first.iter().enumerate() {
            // Proxy columns (replicated across rows, except value_acc /
            // value_bit which carry the bit decomposition).
            values.push(declared_leaf); // 0 leaf
            values.push(sibling_f); // 1 sibling
            values.push(declared_parent); // 2 parent_claim

            if row_idx == 0 {
                acc = bit;
            } else {
                acc = acc.wrapping_mul(2).wrapping_add(bit);
            }
            values.push(Goldilocks::from_u64(acc)); // 3 value_acc
            values.push(Goldilocks::from_u64(bit)); // 4 value_bit

            values.push(ivk_f); // 5 ivk
            values.push(declared_ivk_commitment); // 6 ivk_commitment_claim
            values.push(pk_d_f); // 7 pk_d
            values.push(rcm_f); // 8 rcm
            values.push(nk_f); // 9 nk
            values.push(pos_f); // 10 pos

            // Poseidon2 column groups.
            let (merkle_src, ivkcm_src, cm_src, nf_src) = if row_idx == 0 {
                (&row0_merkle, &row0_ivkcm, &row0_cm, &row0_nf)
            } else {
                (&padding_merkle, &padding_ivkcm, &padding_cm, &padding_nf)
            };
            values.extend_from_slice(merkle_src);
            values.extend_from_slice(ivkcm_src);
            values.extend_from_slice(cm_src);
            values.extend_from_slice(nf_src);
        }

        debug_assert_eq!(values.len(), TRACE_HEIGHT * NUM_COLS);
        RowMajorMatrix::new(values, NUM_COLS)
    }
}

// (Helper `extract_p2_output_zero` was used by an earlier debug
// cross-check in `generate_trace`; see git history. Removed when
// adversarial-witness tests — which construct deliberately inconsistent
// traces — started panicking on the sanity assertion. Consistency is
// now enforced at three other layers: (1) the prover's
// `pre_check_witness` short-circuit, (2) Plonky3's
// DebugConstraintBuilder in debug builds, (3) the verifier in release
// builds.)

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Reduce a `u64` into a canonical Goldilocks residue.
#[inline]
pub(crate) fn reduce_to_goldilocks(x: u64) -> u64 {
    const P: u64 = 0xFFFF_FFFF_0000_0001;
    if x >= P {
        x.wrapping_sub(P)
    } else {
        x
    }
}

/// Decode a public-input byte buffer into Goldilocks field elements.
pub fn decode_public_inputs(bytes: &[u8]) -> Result<Vec<Goldilocks>, Plonky3Status> {
    if bytes.len() != PUBLIC_INPUTS_WIRE_LEN {
        return Err(Plonky3Status::PublicInputLengthMismatch);
    }
    const P: u64 = 0xFFFF_FFFF_0000_0001;
    let mut out = Vec::with_capacity(NUM_PUBLIC_INPUTS);
    for chunk in bytes.chunks_exact(8) {
        let v = u64::from_le_bytes(chunk.try_into().unwrap());
        if v >= P {
            return Err(Plonky3Status::PublicInputDecodeFailed);
        }
        out.push(Goldilocks::from_u64(v));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_inputs_are_four_elements() {
        assert_eq!(NUM_PUBLIC_INPUTS, 4);
        assert_eq!(
            <MvpTransferAir as BaseAir<Goldilocks>>::num_public_values(&MvpTransferAir::new()),
            NUM_PUBLIC_INPUTS
        );
    }

    #[test]
    fn num_cols_matches_layout() {
        // 11 proxy cols + 4 × 180 Poseidon2 cols = 731.
        assert_eq!(POSEIDON2_COLS_PER_INSTANCE, 180);
        assert_eq!(NUM_COLS, MVP_PROXY_COLS + 4 * POSEIDON2_COLS_PER_INSTANCE);
        assert_eq!(NUM_COLS, 731);
    }

    #[test]
    fn witness_encode_decode_roundtrip() {
        let w = MvpWitness::deterministic_valid(42);
        let bytes = w.encode();
        assert_eq!(bytes.len(), 64, "P.2 upgrade: witness wire is 64 B");
        let w2 = MvpWitness::decode(&bytes).unwrap();
        assert_eq!(w.leaf, w2.leaf);
        assert_eq!(w.merkle_sibling, w2.merkle_sibling);
        assert_eq!(w.value, w2.value);
        assert_eq!(w.ivk, w2.ivk);
        assert_eq!(w.pk_d, w2.pk_d);
        assert_eq!(w.rcm, w2.rcm);
        assert_eq!(w.nk, w2.nk);
        assert_eq!(w.pos, w2.pos);
    }

    #[test]
    fn witness_decode_rejects_out_of_range_value() {
        let mut bytes = MvpWitness::deterministic_valid(0).encode();
        bytes[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            MvpWitness::decode(&bytes),
            Err(Plonky3Status::WitnessInvalid)
        ));
    }

    #[test]
    fn witness_decode_rejects_short_length() {
        // A 32-byte buffer (pre-P.2 shape) must be rejected now.
        let short = vec![0u8; 32];
        assert!(matches!(
            MvpWitness::decode(&short),
            Err(Plonky3Status::WitnessInvalid)
        ));
    }

    #[test]
    fn public_inputs_bytes_are_expected_length() {
        let w = MvpWitness::deterministic_valid(7);
        assert_eq!(w.public_inputs_bytes().len(), PUBLIC_INPUTS_WIRE_LEN);
    }

    #[test]
    fn public_input_decode_round_trip() {
        let w = MvpWitness::deterministic_valid(99);
        let bytes = w.public_inputs_bytes();
        let pis = decode_public_inputs(&bytes).unwrap();
        assert_eq!(pis.len(), NUM_PUBLIC_INPUTS);
        let expected = w.public_inputs();
        assert_eq!(pis[0], expected[0]);
        assert_eq!(pis[1], expected[1]);
        assert_eq!(pis[2], expected[2]);
        assert_eq!(pis[3], expected[3]);
    }

    /// Tamper with `ivk` and confirm the derived `ivk_commitment` PI
    /// changes. Real-Poseidon2 version of the MVP's claim-3 soundness
    /// test.
    #[test]
    fn ivk_commitment_binding_changes_with_ivk() {
        let honest = MvpWitness::deterministic_valid(0xcafe_f00d_0001);
        let honest_pis = honest.public_inputs();
        let mut tampered = honest.clone();
        tampered.ivk ^= 0xffff_ffff_ffff_ffff;
        let tampered_pis = tampered.public_inputs();
        // `leaf` (cm) and `parent` depend on `ivk_commitment`, so they
        // change too — this is the expected cascading-hash behaviour
        // once the linear stand-in is gone.
        assert_ne!(
            honest_pis[3], tampered_pis[3],
            "ivk_commitment must change when ivk changes"
        );
    }

    #[test]
    fn public_input_decode_rejects_non_canonical() {
        let mut bytes = vec![0u8; PUBLIC_INPUTS_WIRE_LEN];
        let p = 0xFFFF_FFFF_0000_0001u64;
        bytes[0..8].copy_from_slice(&p.to_le_bytes());
        assert!(matches!(
            decode_public_inputs(&bytes),
            Err(Plonky3Status::PublicInputDecodeFailed)
        ));
    }

    #[test]
    fn public_input_decode_rejects_wrong_length() {
        let bytes = vec![0u8; PUBLIC_INPUTS_WIRE_LEN - 1];
        assert!(matches!(
            decode_public_inputs(&bytes),
            Err(Plonky3Status::PublicInputLengthMismatch)
        ));
    }

    #[test]
    fn trace_shape() {
        use p3_matrix::Matrix;
        let w = MvpWitness::deterministic_valid(11);
        let trace = w.generate_trace();
        assert_eq!(trace.height(), TRACE_HEIGHT);
        assert_eq!(trace.width(), NUM_COLS);
    }

    /// End-to-end Poseidon2 cross-check: the witness's `leaf` must be
    /// the Poseidon2-8 output of the note-opening inputs. If the
    /// constants drift from the audited tables, this test fires.
    #[test]
    fn claim2_note_opening_poseidon2_matches_witness_leaf() {
        let w = MvpWitness::deterministic_valid(0xfeed_face_cafe_b00b);
        let perm = default_goldilocks_poseidon2_8();
        let d_word = u64::from_le_bytes(w.merkle_sibling);
        let ivkcm = w.compute_ivk_commitment();
        let mut state = [Goldilocks::default(); POSEIDON2_WIDTH];
        state[0] = Goldilocks::from_u64(TAG_CM);
        state[1] = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
        state[2] = Goldilocks::from_u64(reduce_to_goldilocks(w.pk_d));
        state[3] = ivkcm;
        state[4] = Goldilocks::from_u64(w.value);
        state[5] = Goldilocks::from_u64(reduce_to_goldilocks(w.rcm));
        perm.permute_mut(&mut state);
        assert_eq!(
            state[0],
            Goldilocks::from_u64(reduce_to_goldilocks(w.leaf)),
            "claim-2 Poseidon2 output must match the witness `leaf`"
        );
    }
}
