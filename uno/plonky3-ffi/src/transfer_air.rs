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
//! - **Claim 5 — Range `value_i < 2^64`**: M-P2 Phase 3b-step3 enforces
//!   this explicitly via cross-AIR LogUp range-check — `MvpTransferAir`
//!   sends 4 × u16 limb decomposition of `value_i` into `Range16Air`
//!   (height 2^16, preprocessed range-table) per the `Kind::Global
//!   ("u16_range")` contract. See `S_VALUE_LIMB0..3` and
//!   `prover::collect_u16_reads_for_range16`.
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
//! 15-field-element iterated-sponge absorb LANDED in M-P2 Phase 4b-step3
//! (step 1.2, commits `81d30c246` → `5cf965204`): bank-1 on shared-wide
//! rows 8+j + bank-2 on rows 12+j, with `uno_cm_v1_tag_block` pinned at
//! capacity and `O_SPONGE_CARRY_{CAP,RATE}` cols threading the 4-row
//! gap between permutations. Same iterated pattern is used for nf
//! (9 fes, step 2b-AIR-v2 `9add1ad0f`, rows 16+i / 20+i).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

/// Re-export all column-layout symbols so external callers that import
/// `crate::transfer_air::MAX_SPENDS` etc. continue to work unchanged.
pub use crate::transfer_columns::*;
/// Re-export byte-packing / PI-decode helpers so callers referencing
/// `crate::transfer_air::decode_public_inputs` etc. continue to work.
pub use crate::transfer_preimage::*;
/// Re-export Poseidon2 sponge helpers so callers referencing
/// `crate::transfer_air::poseidon2_cm_full_sponge` etc. continue to work.
pub use crate::transfer_sponge::*;
/// Re-export witness types + trace-gen so callers referencing
/// `crate::transfer_air::MvpWitness` etc. continue to work unchanged.
pub use crate::transfer_witness::*;

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
///   Phase 4b-step3-step2b-decomp spend fe-limb:   32·n_spends (nk + leaf)
///   Phase 4b-step3-step5b-decomp spend fe-limb:   56·n_spends (d + pk_d
///                                                  + ivk_commitment + rcm)
///
/// Total receives per row: 4·(n_spends + n_outputs) + 56·n_outputs
///                        + 88·n_spends.
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
        // Phase 4b-step3-step5e: capacity reflects the post-step-5b
        // formula `4·(n_s+n_o) + 56·n_o + 88·n_s`; the earlier
        // `36·n_s + 60·n_o` wrote off the Phase 3b-step2 value cols
        // (4 per spend + 4 per output, which are the `4·(n_s+n_o)`
        // term). Full breakdown in the block-doc above.
        let mut lookups: Vec<p3_lookup::lookup_traits::Lookup<F>> =
            Vec::with_capacity(
                4 * (self.n_spends + self.n_outputs)
                    + 56 * self.n_outputs
                    + 88 * self.n_spends,
            );

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
        // Phase 4b-step3-step5b-decomp: register `u16_range` receives
        // for the 56 new fe-limb u16 cols per spend (d×8 + pk_d×16 +
        // ivk_cm×16 + rcm×16 = 56; value is covered by the
        // `S_VALUE_LIMB0..3` registration above). Mirror of the
        // output-side step 1.3-fields block.
        for i in 0..self.n_spends {
            let base = spend_proxy_offset(i);
            for limb_base in &[
                S_D_LIMB0,
                S_PK_D_LIMB0,
                S_IVK_COMMITMENT_LIMB0,
                S_RCM_LIMB0,
            ] {
                // d has 2 fes (8 u16 limbs); others have 4 fes (16 u16 limbs).
                let n_fe_limbs = match *limb_base {
                    x if x == S_D_LIMB0 => 2,
                    _ => 4,
                };
                for k in 0..(n_fe_limbs * 4) {
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

            // --- Phase 4b-step3-step5c-sponge: spend cm bank-1 (row i) ---
            //
            // Replaces the pre-step-5c single-perm u64-proxy claim-2
            // block (which had `inputs = (TAG_CM, d, pk_d, ivkcm_claim,
            // value, rcm, 0·10)` and `output[0] == S_LEAF`) with bank-1
            // of the iterated Poseidon2-w=16 sponge that matches the
            // output-side step 1.2c layout byte-for-byte. Closes Codex
            // audit finding 1 (doc/uno-phase4b-step3-codex-audit.md):
            // the spend-side claim 2 now absorbs the FULL 15-fe input
            // (d_fes(2) + pk_d_fes(4) + ivk_commitment_fes(4) + value(1)
            // + rcm_fes(4)) and binds the sponge's final 4-fe digest to
            // `pack_32b_as_4fe(&s.leaf)` — the cryptographic equivalent
            // of `compute_note_commitment` on the spend side.
            //
            // On row i (i ∈ 0..n_spends):
            //   shared_cm.inputs[0..=1] = d_fes[0..=1]
            //                            (S_D, S_D_FE1)
            //   shared_cm.inputs[2..=5] = pk_d_fes[0..=3]
            //                            (S_PK_D, S_PK_D_FE1..3)
            //   shared_cm.inputs[6..=7] = ivk_commitment_fes[0..=1]
            //                            (S_IVK_COMMITMENT_FE0,
            //                             S_IVK_COMMITMENT_FE1)
            //   shared_cm.inputs[8..16] = uno_cm_v1_tag_block()
            //                            (capacity, constant)
            //   shared_cm_out[0..8]     == S_CM_CARRY_RATE[0..8]
            //                            (bank-1 rate carry)
            //   shared_cm_out[8..16]    == S_CM_CARRY_CAP[0..8]
            //                            (bank-1 capacity carry)
            let cm_tag_block = uno_cm_v1_tag_block();
            for i in 0..self.n_spends {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + i].into();
                // inputs[0..8] pinned to the 8 low fes (d_fes[0..2] +
                // pk_d_fes[0..4] + ivk_commitment_fes[0..2]).
                let slot_to_col = [
                    S_D,                   // inputs[0] = d_fes[0]
                    S_D_FE1,               // inputs[1] = d_fes[1]
                    S_PK_D,                // inputs[2] = pk_d_fes[0]
                    S_PK_D_FE1,            // inputs[3] = pk_d_fes[1]
                    S_PK_D_FE2,            // inputs[4] = pk_d_fes[2]
                    S_PK_D_FE3,            // inputs[5] = pk_d_fes[3]
                    S_IVK_COMMITMENT_FE0,  // inputs[6] = ivk_cm_fes[0]
                    S_IVK_COMMITMENT_FE1,  // inputs[7] = ivk_cm_fes[1]
                ];
                for k in 0..8 {
                    let rate_col = spend_col::<AB::Var>(local_slice, i, slot_to_col[k]);
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[k]) - rate_col.into()),
                    );
                }
                // inputs[8..16] pinned to "uno-cm-v1" tag block (constant).
                for k in 0..8 {
                    let tag_fe = AB::F::from_u64(cm_tag_block[k].as_canonical_u64());
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[8 + k])
                                - AB::Expr::from(tag_fe)),
                    );
                }
                // shared_cm_out[0..8] (bank-1 rate) → S_CM_CARRY_RATE[0..8].
                for k in 0..8 {
                    let carry_col = spend_col::<AB::Var>(local_slice, i, S_CM_CARRY_RATE0 + k);
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm_out[k]) - carry_col.into()),
                    );
                }
                // shared_cm_out[8..16] (bank-1 cap) → S_CM_CARRY_CAP[0..8].
                for k in 0..8 {
                    let carry_col = spend_col::<AB::Var>(local_slice, i, S_CM_CARRY_CAP0 + k);
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm_out[8 + k]) - carry_col.into()),
                    );
                }
            }

            // --- Phase 4b-step3-step5c-sponge: spend cm bank-2 (row 24+i) ---
            //
            // Bank-2 absorbs fes[8..=14] into rate slots 0..6 + ONE
            // padding at slot 7 (10* padding bit since rem=7 after
            // bank-1's 8-fe absorb), with rate[0..8] + capacity[8..16]
            // coming from bank-1's carry cols (same constant-across-rows
            // trick used by step 1.2f-in / step 2b-AIR-v2). The post-
            // permutation state[0..4] is the final 4-fe cm digest — THE
            // closure of claim 2: bank-2.out[0..4] == leaf_fes[0..4].
            //
            // Layout per spend i (row 24+i):
            //   shared_cm.inputs[0]      == S_CM_CARRY_RATE[0] + S_IVK_COMMITMENT_FE2
            //                               (fes[8] absorb = ivk_cm_fes[2])
            //   shared_cm.inputs[1]      == S_CM_CARRY_RATE[1] + S_IVK_COMMITMENT_FE3
            //                               (fes[9] absorb = ivk_cm_fes[3])
            //   shared_cm.inputs[2]      == S_CM_CARRY_RATE[2] + S_VALUE
            //                               (fes[10] absorb = value)
            //   shared_cm.inputs[3]      == S_CM_CARRY_RATE[3] + S_RCM
            //                               (fes[11] absorb = rcm_fes[0])
            //   shared_cm.inputs[4]      == S_CM_CARRY_RATE[4] + S_RCM_FE1
            //                               (fes[12] absorb = rcm_fes[1])
            //   shared_cm.inputs[5]      == S_CM_CARRY_RATE[5] + S_RCM_FE2
            //                               (fes[13] absorb = rcm_fes[2])
            //   shared_cm.inputs[6]      == S_CM_CARRY_RATE[6] + S_RCM_FE3
            //                               (fes[14] absorb = rcm_fes[3])
            //   shared_cm.inputs[7]      == S_CM_CARRY_RATE[7] + 1
            //                               (10* padding bit)
            //   shared_cm.inputs[8+k]    == S_CM_CARRY_CAP[k]
            //                               for k ∈ 0..8 (capacity carry)
            //   shared_cm_out[0]         == S_LEAF        (= leaf_fes[0])
            //   shared_cm_out[1]         == S_LEAF_FE1    (= leaf_fes[1])
            //   shared_cm_out[2]         == S_LEAF_FE2    (= leaf_fes[2])
            //   shared_cm_out[3]         == S_LEAF_FE3    (= leaf_fes[3])
            //
            // This final 4-fe equality is the CLAIM-2 CLOSURE: leaf ==
            // Poseidon2("uno-cm-v1", full 15-fe input), bit-identical
            // to the output-side step 1.2e+f bindings. Combined with
            // step 5b-decomp's u16-range-checked limb decomposition of
            // each input fe-limb, the prover can no longer forge a
            // leaf for arbitrary field-element inputs — the leaf must
            // be the canonical sponge output of the real 32-byte
            // witness bytes for d / pk_d / ivk_commitment / rcm.
            for i in 0..self.n_spends {
                let sel: AB::Expr = local_slice[GS_ROW_SEL0 + 24 + i].into();
                // inputs[0..7] = carry_rate[k] + absorb_term_k for
                // k ∈ 0..7 (absorb fes[8..14], no absorb on k=7 —
                // padding bit lives there).
                let fe_slot_cols = [
                    S_IVK_COMMITMENT_FE2, // fes[8]
                    S_IVK_COMMITMENT_FE3, // fes[9]
                    S_VALUE,              // fes[10]
                    S_RCM,                // fes[11]
                    S_RCM_FE1,            // fes[12]
                    S_RCM_FE2,            // fes[13]
                    S_RCM_FE3,            // fes[14]
                ];
                for k in 0..7 {
                    let carry_col =
                        spend_col::<AB::Var>(local_slice, i, S_CM_CARRY_RATE0 + k);
                    let fe_col =
                        spend_col::<AB::Var>(local_slice, i, fe_slot_cols[k]);
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[k])
                                - (AB::Expr::from(carry_col) + AB::Expr::from(fe_col))),
                    );
                }
                // Padding slot 7: inputs[7] = carry[7] + ONE.
                let carry_col_7 =
                    spend_col::<AB::Var>(local_slice, i, S_CM_CARRY_RATE0 + 7);
                builder.assert_zero(
                    sel.clone()
                        * (AB::Expr::from(shared_cm.inputs[7])
                            - (AB::Expr::from(carry_col_7)
                                + AB::Expr::from(AB::F::from_u64(1)))),
                );
                // inputs[8..16] = carry_cap[0..8] (capacity carry).
                for k in 0..8 {
                    let carry_col =
                        spend_col::<AB::Var>(local_slice, i, S_CM_CARRY_CAP0 + k);
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm.inputs[8 + k]) - carry_col.into()),
                    );
                }
                // Claim 2 closure: bank-2 output rate slots 0..4 bind
                // all 4 limbs of `leaf_i`. S_LEAF holds fe[0], the
                // upper fes live in S_LEAF_FE1..3 (from step 2b-decomp).
                let leaf_cols = [S_LEAF, S_LEAF_FE1, S_LEAF_FE2, S_LEAF_FE3];
                for (k, col_offset) in leaf_cols.iter().enumerate() {
                    let leaf_col = spend_col::<AB::Var>(local_slice, i, *col_offset);
                    builder.assert_zero(
                        sel.clone()
                            * (AB::Expr::from(shared_cm_out[k]) - leaf_col.into()),
                    );
                }
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

        // ---- Phase 4b-step3-step5b-decomp: spend cm sponge fe-limb u16 ---
        //
        // Mirror of the output-side step 1.3-fields block on the spend
        // side for the 15-fe cm sponge input (d×2 + pk_d×4 + ivk_cm×4
        // + value×1 + rcm×4 = 15 fe-limbs). 14 fe-limbs decompose into
        // 4 u16 limbs each here (the 15th, `value`, already has its own
        // 4-limb decomposition at `S_VALUE_LIMB0..3` from Phase 3b-
        // step2 — do NOT duplicate).
        //
        //   fe_limb == Σ_{k=0..3} limb_k · 2^{16k}
        //
        // Combined with the cross-AIR `u16_range` LogUp that bounds
        // each `limb_k` to `0..=0xffff`, this proves the fe-limb is
        // the canonical u64 of the corresponding 8-byte LE chunk of
        // the 32-byte witness field — exactly what
        // `pack_diversifier_as_2fe(&s.d)` and
        // `pack_32b_as_4fe(&s.{pk_d,ivk_commitment,rcm})` emit off-
        // circuit. Unblocks step 5c-sponge: the prover can no longer
        // put arbitrary Goldilocks values in the spend cm sponge rate
        // slots.
        //
        // Not row-gated — both fe-limb and limb cols live in the
        // proxy block (constant-across-rows per §4.2).
        {
            let fe_limb_pairs: [(usize, usize); 14] = [
                // d_fes[0..2] → S_D_LIMB0..S_D_LIMB0+8
                // Note: fe[0] is the existing `S_D` single-u64 proxy,
                // which coincides with `pack_diversifier_as_2fe(&s.d)[0]`
                // (first 8 bytes of d). fe[1] is the new `S_D_FE1`.
                (S_D,                    S_D_LIMB0),
                (S_D_FE1,                S_D_LIMB0 + 4),
                // pk_d_fes[0..4] → S_PK_D_LIMB0..S_PK_D_LIMB0+16
                (S_PK_D,                 S_PK_D_LIMB0),
                (S_PK_D_FE1,             S_PK_D_LIMB0 + 4),
                (S_PK_D_FE2,             S_PK_D_LIMB0 + 8),
                (S_PK_D_FE3,             S_PK_D_LIMB0 + 12),
                // ivk_commitment_fes[0..4] → S_IVK_COMMITMENT_LIMB0..+16
                // All 4 fes are new (S_IVK_COMMITMENT_CLAIM is the
                // legacy claim-3 narrow output, a different field).
                (S_IVK_COMMITMENT_FE0,   S_IVK_COMMITMENT_LIMB0),
                (S_IVK_COMMITMENT_FE1,   S_IVK_COMMITMENT_LIMB0 + 4),
                (S_IVK_COMMITMENT_FE2,   S_IVK_COMMITMENT_LIMB0 + 8),
                (S_IVK_COMMITMENT_FE3,   S_IVK_COMMITMENT_LIMB0 + 12),
                // rcm_fes[0..4] → S_RCM_LIMB0..S_RCM_LIMB0+16
                (S_RCM,                  S_RCM_LIMB0),
                (S_RCM_FE1,              S_RCM_LIMB0 + 4),
                (S_RCM_FE2,              S_RCM_LIMB0 + 8),
                (S_RCM_FE3,              S_RCM_LIMB0 + 12),
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
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Plonky3Status;
    use p3_goldilocks::{default_goldilocks_poseidon2_16, default_goldilocks_poseidon2_8};
    use p3_symmetric::Permutation;

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
                assert_eq!(w.anchor_bytes, w2.anchor_bytes);
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

    /// Phase 4b-step3-step4c: guards against Codex audit finding 2
    /// (`doc/uno-phase4b-step3-codex-audit.md`). A witness with any
    /// non-zero byte in `OutputWitness.d[11..32]` does not correspond
    /// to a valid 11-byte diversifier under the C++ / spec preimage
    /// domain; the decoder must reject.
    #[test]
    fn witness_decode_rejects_non_canonical_diversifier_padding() {
        // Honest 1/1 witness first.
        let w = MvpWitness::deterministic_valid(1, 1, 0xD1FF_0001);
        let good = w.encode();
        MvpWitness::decode(&good).expect("honest witness must decode");

        // Locate and mutate output 0's `d[11]` (first non-canonical byte).
        // Wire layout from encode(): HEAD(10) + PER_SPEND·n_s + [output 0 starts:
        // d(32) + pk_d(32) + ...]. PER_SPEND post-step-5a-wire = 32 + 32 + 8 + 32 + 4·32 + 8 + 32·32 + 32 = 1296.
        let output0_d_off = 10 + 1296 * 1; // n_s = 1
        for offset_in_d in 11..32 {
            let mut bad = good.clone();
            bad[output0_d_off + offset_in_d] = 0xAB;
            assert!(
                matches!(
                    MvpWitness::decode(&bad),
                    Err(Plonky3Status::WitnessInvalid)
                ),
                "decode must reject non-zero d[{}]",
                offset_in_d
            );
        }
    }

    /// Phase 4b-step3-step5e: mirror of
    /// `witness_decode_rejects_non_canonical_diversifier_padding` on
    /// the spend side. Step 5a-wire added a decoder rejection for
    /// `SpendWitness.d[11..32] != 0` (same rationale as the output-side
    /// check: `pack_diversifier_as_2fe` absorbs `d[0..16]`, so
    /// `d[11..15]` would change the proven cm and `d[16..31]` would be
    /// unconstrained garbage). Codex follow-up audit finding 1
    /// (`doc/uno-phase4b-step5-codex-audit.md`) flagged that without
    /// this regression, a later refactor could silently weaken the
    /// check.
    #[test]
    fn witness_decode_rejects_non_canonical_spend_diversifier_padding() {
        let w = MvpWitness::deterministic_valid(1, 1, 0xD1FF_5005);
        let good = w.encode();
        MvpWitness::decode(&good).expect("honest witness must decode");

        // Spend 0's d starts at: HEAD(10) + leaf(32) = offset 42.
        // Wire layout per `encode()`: leaf(32) + d(32) + value(8) +
        // ivk(32) + pk_d(32) + ivk_commitment(32) + rcm(32) + nk(32)
        // + pos(8) + merkle_path(32·MERKLE_DEPTH) + rk_bytes(32).
        let spend0_d_off = 10 + 32;
        for offset_in_d in 11..32 {
            let mut bad = good.clone();
            bad[spend0_d_off + offset_in_d] = 0xAB;
            assert!(
                matches!(
                    MvpWitness::decode(&bad),
                    Err(Plonky3Status::WitnessInvalid)
                ),
                "decode must reject non-zero spend0.d[{}]",
                offset_in_d
            );
        }
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

            // Phase 4b-step3-step5b-decomp: 4·(n_s + n_o) value-limb
            // receives + 56·n_o output fe-limb receives (14 fe-limbs ×
            // 4 u16 limbs per output: d×2 + pk_d×4 + ivk_cm×4 + rcm×4)
            // + 88·n_s spend fe-limb receives (22 fe-limbs × 4 u16 limbs
            // per spend: nk×4 + leaf×4 from step 2b-decomp (32) +
            // d×2 + pk_d×4 + ivk_cm×4 + rcm×4 from step 5b-decomp (56)).
            let expected_count = 4 * (n_s + n_o) + 56 * n_o + 88 * n_s;
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
