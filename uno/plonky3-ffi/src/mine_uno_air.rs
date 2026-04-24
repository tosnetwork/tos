//! MineUno AIR — Phase 3a shell (+ Phase 3b Poseidon2 sub-AIR wiring TODO).
//!
//! The MineUno STARK proves (cryptographically) that the prover knows a
//! witness `(nonce, recipient, rseed, value)` such that
//!
//! ```text
//!     output_cm = Poseidon2("uno-cm-v1", d, pk_d, ivk_commitment, value, rcm)
//!     pow_hash  = Poseidon2("uno-mine-v1", epoch, nonce, output_cm)
//! ```
//!
//! and that `(output_cm, pow_hash, epoch, value, remaining_pre, remaining_post)`
//! match the public inputs. Off-circuit chain logic enforces the remaining
//! checks: `pow_hash < target`, `value` matches halving table, `remaining_post
//! = remaining_pre - value`, `remaining_pre = chain_state.mine_remaining`,
//! `epoch = chain_state.mine_epoch`.
//!
//! # Current scope (Phase 3a — this file)
//!
//! - `BaseAir` + `Air<AB>` impls with width/PI metadata correct
//! - Row-selector one-hot constraints (4 active rows, 4 padding rows)
//! - Witness-proxy "constant-across-rows" transition constraints
//! - Row-0 public-input bindings for epoch, value, output_cm, pow_hash,
//!   remaining_pre, remaining_post
//!
//! # Deferred to Phase 3b
//!
//! - Poseidon2-w16 sub-AIR evaluation (`eval_poseidon2_16`) wired to the
//!   shared column block
//! - Per-row rate-slot input pinning:
//!   - row 0 (cm perm 1): inputs = [d_fe0, d_fe1, pk_d_fe0..3, ivk_cm_fe0..1]
//!   - row 1 (cm perm 2): inputs = carry + [ivk_cm_fe2..3, value, rcm_fe0..3]
//!   - row 2 (pow perm 1): inputs = [epoch, nonce_fe0..3, output_cm_fe0..2]
//!   - row 3 (pow perm 2): inputs = carry + [output_cm_fe3, ONE padding]
//! - Per-row output-digest binding:
//!   - row 1 post[0..4] = output_cm_fe0..3
//!   - row 3 post[0..4] = pow_hash_fe0..3
//! - Capacity-slot tag-block pinning (uno-cm-v1 for rows 0-1, uno-mine-v1
//!   for rows 2-3)
//!
//! # Why Phase 3a alone is not soundness-complete
//!
//! Without the Phase 3b Poseidon2 wiring, a malicious prover could fabricate
//! arbitrary `output_cm` and `pow_hash` values in the witness-proxy columns,
//! satisfy all Phase 3a constraints (PI binding + proxy consistency), and
//! produce a proof that passes verification. The cryptographic soundness of
//! MineUno relies on the Poseidon2 sub-AIR enforcing that these values are
//! correctly derived from the private witness. Phase 3b closes this gap.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

pub use crate::mine_uno_columns::*;
pub use crate::mine_uno_witness::*;
use crate::transfer_columns::POSEIDON2_HALF_FULL_ROUNDS;
use crate::transfer_sponge::{eval_poseidon2_16, uno_cm_v1_tag_block};

// ---------------------------------------------------------------------------
// AIR struct
// ---------------------------------------------------------------------------

/// The MineUno AIR. There is only ONE shape (unlike Transfer's 16 shapes),
/// so no shape parameters are needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct MineUnoAir;

impl MineUnoAir {
    /// Build the AIR. Const-fn for consistency with `MvpTransferAir::new`.
    pub const fn new() -> Self {
        Self
    }

    /// AIR column width.
    #[inline]
    pub const fn width(&self) -> usize {
        MINE_AIR_WIDTH
    }

    /// Public-input vector length (field elements).
    #[inline]
    pub const fn num_public_values(&self) -> usize {
        N_PUBLIC_INPUTS
    }
}

// ---------------------------------------------------------------------------
// BaseAir
// ---------------------------------------------------------------------------

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for MineUnoAir {
    #[inline]
    fn width(&self) -> usize {
        MineUnoAir::width(self)
    }

    #[inline]
    fn num_public_values(&self) -> usize {
        MineUnoAir::num_public_values(self)
    }

    #[inline]
    fn max_constraint_degree(&self) -> Option<usize> {
        None
    }

    /// Declare every column as next-row-accessed so the batch-stark verifier
    /// opens both zeta and zeta·g. Required because our transition
    /// constraints (witness-proxy constant-across-rows) read `main.next`.
    /// See the detailed note in `transfer_air.rs::main_next_row_columns`
    /// for the rationale — same argument applies here verbatim.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..MINE_AIR_WIDTH).collect()
    }
}

// ---------------------------------------------------------------------------
// Air trait — constraint evaluation
// ---------------------------------------------------------------------------

impl<AB> Air<AB> for MineUnoAir
where
    AB: AirBuilder<F = Val>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_slice = main.current_slice();
        let next_slice = main.next_slice();

        // Snapshot public values (AB::PublicVar: Copy) before taking mutable
        // subbuilders — same Rust-borrow-checker dance as `MvpTransferAir::eval`.
        let pis_vec: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let pi_epoch = pis_vec[PI_EPOCH];
        let pi_value = pis_vec[PI_VALUE];
        let pi_output_cm: [AB::PublicVar; 4] = [
            pis_vec[PI_OUTPUT_CM_BASE],
            pis_vec[PI_OUTPUT_CM_BASE + 1],
            pis_vec[PI_OUTPUT_CM_BASE + 2],
            pis_vec[PI_OUTPUT_CM_BASE + 3],
        ];
        let pi_pow_hash: [AB::PublicVar; 4] = [
            pis_vec[PI_POW_HASH_BASE],
            pis_vec[PI_POW_HASH_BASE + 1],
            pis_vec[PI_POW_HASH_BASE + 2],
            pis_vec[PI_POW_HASH_BASE + 3],
        ];
        let pi_rem_pre = pis_vec[PI_REMAINING_PRE];
        let pi_rem_post = pis_vec[PI_REMAINING_POST];

        // -------------------------------------------------------------------
        // Constraint 1 — Row-selector booleanity
        // -------------------------------------------------------------------
        //
        // Every row selector must be 0 or 1. Expressed as `s · (1 - s) = 0`.
        for sel_col in [COL_SEL_CM_P1, COL_SEL_CM_P2, COL_SEL_POW_P1, COL_SEL_POW_P2] {
            let s: AB::Expr = local_slice[sel_col].into();
            let one_minus_s: AB::Expr =
                AB::Expr::from(AB::F::from_u64(1)) - s.clone();
            builder.assert_zero(s * one_minus_s);
        }

        // -------------------------------------------------------------------
        // Constraint 2 — Row-selector "at most one active"
        // -------------------------------------------------------------------
        //
        // Sum of the four row selectors must be 0 or 1 (never ≥ 2). Because
        // each is already booleanity-constrained, pairwise products must be
        // zero. We constrain each distinct pair.
        let sel_cols = [COL_SEL_CM_P1, COL_SEL_CM_P2, COL_SEL_POW_P1, COL_SEL_POW_P2];
        for i in 0..sel_cols.len() {
            for j in (i + 1)..sel_cols.len() {
                let si: AB::Expr = local_slice[sel_cols[i]].into();
                let sj: AB::Expr = local_slice[sel_cols[j]].into();
                builder.assert_zero(si * sj);
            }
        }

        // -------------------------------------------------------------------
        // Constraint 3 — Witness proxy columns are constant across rows
        // -------------------------------------------------------------------
        //
        // The witness-proxy block carries the private witness values and
        // must be identical on every row so the per-row P2 constraints can
        // reference the same inputs. Transition constraint: for every
        // proxy column c, `local[c] == next[c]`.
        // Phase 3b: all 28 witness proxies plus the 32 carry proxies
        // must be row-constant (propagates via transition closure so
        // perm-1 rows write the carry and perm-2 rows read it).
        let mut proxy_cols: Vec<usize> = vec![
            COL_W_EPOCH,
            COL_W_VALUE,
            COL_W_D_FE0,
            COL_W_D_FE1,
            COL_W_PK_D_FE0,
            COL_W_PK_D_FE0 + 1,
            COL_W_PK_D_FE0 + 2,
            COL_W_PK_D_FE0 + 3,
            COL_W_IVK_CM_FE0,
            COL_W_IVK_CM_FE0 + 1,
            COL_W_IVK_CM_FE0 + 2,
            COL_W_IVK_CM_FE0 + 3,
            COL_W_RCM_FE0,
            COL_W_RCM_FE0 + 1,
            COL_W_RCM_FE0 + 2,
            COL_W_RCM_FE0 + 3,
            COL_W_NONCE_FE0,
            COL_W_NONCE_FE0 + 1,
            COL_W_NONCE_FE0 + 2,
            COL_W_NONCE_FE0 + 3,
            COL_W_OUTPUT_CM_FE0,
            COL_W_OUTPUT_CM_FE0 + 1,
            COL_W_OUTPUT_CM_FE0 + 2,
            COL_W_OUTPUT_CM_FE0 + 3,
            COL_W_POW_HASH_FE0,
            COL_W_POW_HASH_FE0 + 1,
            COL_W_POW_HASH_FE0 + 2,
            COL_W_POW_HASH_FE0 + 3,
        ];
        for k in 0..N_CAP_CARRY_PROXY {
            proxy_cols.push(COL_CAP_CARRY_BASE + k);
        }
        {
            let mut trans = builder.when_transition();
            for &c in proxy_cols.iter() {
                let l: AB::Expr = local_slice[c].into();
                let n: AB::Expr = next_slice[c].into();
                trans.assert_zero(l - n);
            }
        }

        // -------------------------------------------------------------------
        // Constraint 4 — Row-0 public-input bindings
        // -------------------------------------------------------------------
        //
        // On the first row, the witness-proxy values must equal the public
        // inputs. Because Constraint 3 propagates values to every row, this
        // single row-0 equality transitively ties ALL rows' proxy cells to
        // the PI vector.
        {
            let mut first = builder.when_first_row();

            first.assert_eq(local_slice[COL_W_EPOCH], pi_epoch);
            first.assert_eq(local_slice[COL_W_VALUE], pi_value);

            for k in 0..4 {
                first.assert_eq(
                    local_slice[COL_W_OUTPUT_CM_FE0 + k],
                    pi_output_cm[k],
                );
                first.assert_eq(
                    local_slice[COL_W_POW_HASH_FE0 + k],
                    pi_pow_hash[k],
                );
            }
        }

        // -------------------------------------------------------------------
        // Constraint 5 — Conservation (remaining_post = remaining_pre - value)
        // -------------------------------------------------------------------
        //
        // Whole-tx invariant bound into the AIR on row 0. Off-circuit chain
        // logic redundantly checks this; doing it in-circuit too guarantees
        // the proof itself cannot claim a false conservation even if chain
        // logic had a bug.
        {
            let mut first = builder.when_first_row();
            // remaining_post + value == remaining_pre
            let lhs: AB::Expr = pi_rem_post.into() + pi_value.into();
            let rhs: AB::Expr = pi_rem_pre.into();
            first.assert_zero(lhs - rhs);
        }

        // -------------------------------------------------------------------
        // Phase 3b — Poseidon2 sub-AIR wiring
        // -------------------------------------------------------------------
        //
        // The shared width-16 Poseidon2 column block lives at offset
        // N_ROW_SELECTORS and spans MINE_POSEIDON2_COLS_16 cells. We first
        // cast it as a `MineP2Cols` view, then:
        //   1. Delegate the full Poseidon2-w16 round-by-round constraint
        //      system to `eval_poseidon2_16` so every row's 316 cells must
        //      encode a valid Poseidon2 permutation.
        //   2. Per-row-selector gate the input state (rate + capacity)
        //      against the witness proxies / tag blocks / capacity-carry
        //      proxies.
        //   3. Per-row-selector gate the output digest (post[0..4]) against
        //      `COL_W_OUTPUT_CM_FE` (row 1) or `COL_W_POW_HASH_FE` (row 3).
        //   4. On perm-1 rows, pin the post-permutation capacity
        //      (post[8..16]) into the capacity-carry proxy so the next
        //      active row (perm-2) can re-absorb it without a cross-row
        //      read. Mirrors the transfer_air.rs output-sponge pattern at
        //      lines 1072-1259.
        let shared_p2: &MineP2Cols<AB::Var> = {
            let group: &[AB::Var] = &local_slice
                [N_ROW_SELECTORS..N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16];
            <[AB::Var] as Borrow<MineP2Cols<AB::Var>>>::borrow(group)
        };
        let shared_p2_out =
            &shared_p2.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;

        // 3b.0: round-constraint delegation — runs on every row. Padding
        // rows (4..7) carry a zero-input-zero-tag permutation witness that
        // trivially satisfies this constraint without any input pinning.
        eval_poseidon2_16(builder, shared_p2);

        // Carry-proxy layout helpers (deviation from Phase 3b spec §A):
        // spec wanted 8 columns, but soundness needs 32 (8 rate + 8 cap
        // per chain × 2 chains). See `mine_uno_columns.rs` for the
        // rationale.
        let cm_carry_rate =
            |k: usize| local_slice[COL_CAP_CARRY_BASE + CARRY_CM_BASE + k];
        let cm_carry_cap =
            |k: usize| local_slice[COL_CAP_CARRY_BASE + CARRY_CM_BASE + 8 + k];
        let pow_carry_rate =
            |k: usize| local_slice[COL_CAP_CARRY_BASE + CARRY_POW_BASE + k];
        let pow_carry_cap =
            |k: usize| local_slice[COL_CAP_CARRY_BASE + CARRY_POW_BASE + 8 + k];

        // -------------------------------------------------------------------
        // Row-0 (CM perm-1, gated by COL_SEL_CM_P1)
        // -------------------------------------------------------------------
        //   inputs[0..2]   = d_fe[0..2]              (rate, 2 fes)
        //   inputs[2..6]   = pk_d_fe[0..4]           (rate, 4 fes)
        //   inputs[6..8]   = ivk_cm_fe[0..2]         (rate, 2 fes)
        //   inputs[8..16]  = uno_cm_v1_tag_block()   (capacity)
        //   post[0..8]     → carry_rate[0..8]        (rate carry to row 1)
        //   post[8..16]    → carry_cap[0..8]         (cap carry to row 1)
        {
            let sel: AB::Expr = local_slice[COL_SEL_CM_P1].into();

            // inputs[0..2] = d_fe
            for k in 0..2 {
                let input_k: AB::Expr = shared_p2.inputs[k].into();
                let proxy: AB::Expr = local_slice[COL_W_D_FE0 + k].into();
                builder.assert_zero(sel.clone() * (input_k - proxy));
            }
            // inputs[2..6] = pk_d_fe
            for k in 0..4 {
                let input_k: AB::Expr = shared_p2.inputs[2 + k].into();
                let proxy: AB::Expr = local_slice[COL_W_PK_D_FE0 + k].into();
                builder.assert_zero(sel.clone() * (input_k - proxy));
            }
            // inputs[6..8] = ivk_cm_fe[0..2]
            for k in 0..2 {
                let input_k: AB::Expr = shared_p2.inputs[6 + k].into();
                let proxy: AB::Expr = local_slice[COL_W_IVK_CM_FE0 + k].into();
                builder.assert_zero(sel.clone() * (input_k - proxy));
            }
            // inputs[8..16] = uno_cm_v1_tag_block() (capacity)
            let tag = uno_cm_v1_tag_block();
            for k in 0..8 {
                let tag_fe = AB::F::from_u64(tag[k].as_canonical_u64());
                let input_cap: AB::Expr = shared_p2.inputs[8 + k].into();
                builder.assert_zero(
                    sel.clone() * (input_cap - AB::Expr::from(tag_fe)),
                );
            }
            // post[0..8] → cm_carry_rate
            for k in 0..8 {
                let post_rate: AB::Expr = shared_p2_out[k].into();
                let cr: AB::Expr = cm_carry_rate(k).into();
                builder.assert_zero(sel.clone() * (post_rate - cr));
            }
            // post[8..16] → cm_carry_cap
            for k in 0..8 {
                let post_cap: AB::Expr = shared_p2_out[8 + k].into();
                let cc: AB::Expr = cm_carry_cap(k).into();
                builder.assert_zero(sel.clone() * (post_cap - cc));
            }
        }

        // -------------------------------------------------------------------
        // Row-1 (CM perm-2, gated by COL_SEL_CM_P2)
        // -------------------------------------------------------------------
        //
        // Off-circuit reference (`poseidon2_cm_full_sponge`,
        // transfer_sponge.rs:210-253): for the second permutation the
        // rate absorbs 7 fresh fes + ONE padding on top of the carried
        // rate; the capacity is untouched. So:
        //
        //   inputs[0] = carry_rate[0] + ivk_cm_fe[2]
        //   inputs[1] = carry_rate[1] + ivk_cm_fe[3]
        //   inputs[2] = carry_rate[2] + value
        //   inputs[3] = carry_rate[3] + rcm_fe[0]
        //   inputs[4] = carry_rate[4] + rcm_fe[1]
        //   inputs[5] = carry_rate[5] + rcm_fe[2]
        //   inputs[6] = carry_rate[6] + rcm_fe[3]
        //   inputs[7] = carry_rate[7] + ONE          (10* padding)
        //   inputs[8..16] = carry_cap[0..8]
        //   post[0..4] = COL_W_OUTPUT_CM_FE[0..4]    (CM sponge digest)
        {
            let sel: AB::Expr = local_slice[COL_SEL_CM_P2].into();
            let one_e: AB::Expr = AB::Expr::from(AB::F::from_u64(1));

            // rate-slot fe-limb absorbs into slots 0..7.
            let absorb_fe_cols = [
                COL_W_IVK_CM_FE0 + 2, // ivk_cm[2]
                COL_W_IVK_CM_FE0 + 3, // ivk_cm[3]
                COL_W_VALUE,          // value
                COL_W_RCM_FE0,        // rcm[0]
                COL_W_RCM_FE0 + 1,    // rcm[1]
                COL_W_RCM_FE0 + 2,    // rcm[2]
                COL_W_RCM_FE0 + 3,    // rcm[3]
            ];
            for k in 0..7 {
                let input_k: AB::Expr = shared_p2.inputs[k].into();
                let cr: AB::Expr = cm_carry_rate(k).into();
                let fe: AB::Expr = local_slice[absorb_fe_cols[k]].into();
                builder.assert_zero(sel.clone() * (input_k - (cr + fe)));
            }
            // inputs[7] = cm_carry_rate[7] + ONE (10* padding)
            {
                let input_7: AB::Expr = shared_p2.inputs[7].into();
                let cr_7: AB::Expr = cm_carry_rate(7).into();
                builder.assert_zero(
                    sel.clone() * (input_7 - (cr_7 + one_e.clone())),
                );
            }
            // inputs[8..16] = cm_carry_cap
            for k in 0..8 {
                let input_cap: AB::Expr = shared_p2.inputs[8 + k].into();
                let cc: AB::Expr = cm_carry_cap(k).into();
                builder.assert_zero(sel.clone() * (input_cap - cc));
            }
            // post[0..4] = COL_W_OUTPUT_CM_FE[0..4] (CM sponge digest).
            for k in 0..4 {
                let post_k: AB::Expr = shared_p2_out[k].into();
                let proxy: AB::Expr =
                    local_slice[COL_W_OUTPUT_CM_FE0 + k].into();
                builder.assert_zero(sel.clone() * (post_k - proxy));
            }
        }

        // -------------------------------------------------------------------
        // Row-2 (PoW perm-1, gated by COL_SEL_POW_P1)
        // -------------------------------------------------------------------
        //   inputs[0]      = epoch
        //   inputs[1..5]   = nonce_fe[0..4]
        //   inputs[5..8]   = output_cm_fe[0..3]
        //   inputs[8..16]  = uno_mine_v1_tag_block()
        //   post[0..8]     → pow_carry_rate  (PoW-chain-specific block)
        //   post[8..16]    → pow_carry_cap
        {
            let sel: AB::Expr = local_slice[COL_SEL_POW_P1].into();

            // inputs[0] = epoch
            {
                let input_0: AB::Expr = shared_p2.inputs[0].into();
                let proxy: AB::Expr = local_slice[COL_W_EPOCH].into();
                builder.assert_zero(sel.clone() * (input_0 - proxy));
            }
            // inputs[1..5] = nonce_fe[0..4]
            for k in 0..4 {
                let input_k: AB::Expr = shared_p2.inputs[1 + k].into();
                let proxy: AB::Expr = local_slice[COL_W_NONCE_FE0 + k].into();
                builder.assert_zero(sel.clone() * (input_k - proxy));
            }
            // inputs[5..8] = output_cm_fe[0..3]
            for k in 0..3 {
                let input_k: AB::Expr = shared_p2.inputs[5 + k].into();
                let proxy: AB::Expr = local_slice[COL_W_OUTPUT_CM_FE0 + k].into();
                builder.assert_zero(sel.clone() * (input_k - proxy));
            }
            // inputs[8..16] = uno_mine_v1_tag_block()
            let tag = uno_mine_v1_tag_block();
            for k in 0..8 {
                let tag_fe = AB::F::from_u64(tag[k].as_canonical_u64());
                let input_cap: AB::Expr = shared_p2.inputs[8 + k].into();
                builder.assert_zero(
                    sel.clone() * (input_cap - AB::Expr::from(tag_fe)),
                );
            }
            // post[0..8] → pow_carry_rate
            for k in 0..8 {
                let post_rate: AB::Expr = shared_p2_out[k].into();
                let cr: AB::Expr = pow_carry_rate(k).into();
                builder.assert_zero(sel.clone() * (post_rate - cr));
            }
            // post[8..16] → pow_carry_cap
            for k in 0..8 {
                let post_cap: AB::Expr = shared_p2_out[8 + k].into();
                let cc: AB::Expr = pow_carry_cap(k).into();
                builder.assert_zero(sel.clone() * (post_cap - cc));
            }
        }

        // -------------------------------------------------------------------
        // Row-3 (PoW perm-2, gated by COL_SEL_POW_P2)
        // -------------------------------------------------------------------
        //
        // Off-circuit reference (`poseidon2_mine_pow_hash`,
        // mine_uno_witness.rs:423-447): for perm-2 the rate absorbs the
        // final fe + ONE padding; slots 2..8 are untouched (the off-
        // circuit helper does NOT zero them — it carries bank-1's post
        // rate verbatim). So:
        //
        //   inputs[0]      = carry_rate[0] + output_cm_fe[3]
        //   inputs[1]      = carry_rate[1] + ONE           (10* padding)
        //   inputs[2..8]   = carry_rate[2..8]
        //   inputs[8..16]  = carry_cap[0..8]
        //   post[0..4]     = COL_W_POW_HASH_FE[0..4]       (PoW digest)
        {
            let sel: AB::Expr = local_slice[COL_SEL_POW_P2].into();
            let one_e: AB::Expr = AB::Expr::from(AB::F::from_u64(1));

            // inputs[0] = pow_carry_rate[0] + output_cm_fe[3]
            {
                let input_0: AB::Expr = shared_p2.inputs[0].into();
                let cr_0: AB::Expr = pow_carry_rate(0).into();
                let fe: AB::Expr = local_slice[COL_W_OUTPUT_CM_FE0 + 3].into();
                builder.assert_zero(sel.clone() * (input_0 - (cr_0 + fe)));
            }
            // inputs[1] = pow_carry_rate[1] + ONE (10* padding)
            {
                let input_1: AB::Expr = shared_p2.inputs[1].into();
                let cr_1: AB::Expr = pow_carry_rate(1).into();
                builder.assert_zero(
                    sel.clone() * (input_1 - (cr_1 + one_e.clone())),
                );
            }
            // inputs[2..8] = pow_carry_rate[2..8] (unchanged)
            for k in 2..8 {
                let input_k: AB::Expr = shared_p2.inputs[k].into();
                let cr: AB::Expr = pow_carry_rate(k).into();
                builder.assert_zero(sel.clone() * (input_k - cr));
            }
            // inputs[8..16] = pow_carry_cap[0..8]
            for k in 0..8 {
                let input_cap: AB::Expr = shared_p2.inputs[8 + k].into();
                let cc: AB::Expr = pow_carry_cap(k).into();
                builder.assert_zero(sel.clone() * (input_cap - cc));
            }
            // post[0..4] = COL_W_POW_HASH_FE[0..4] (PoW digest).
            for k in 0..4 {
                let post_k: AB::Expr = shared_p2_out[k].into();
                let proxy: AB::Expr =
                    local_slice[COL_W_POW_HASH_FE0 + k].into();
                builder.assert_zero(sel.clone() * (post_k - proxy));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p3_goldilocks::Goldilocks;

    #[test]
    fn base_air_dimensions_match_columns() {
        let air = MineUnoAir::new();
        assert_eq!(
            <MineUnoAir as BaseAir<Goldilocks>>::width(&air),
            MINE_AIR_WIDTH
        );
        assert_eq!(
            <MineUnoAir as BaseAir<Goldilocks>>::num_public_values(&air),
            N_PUBLIC_INPUTS
        );
    }

    #[test]
    fn next_row_columns_covers_all() {
        let air = MineUnoAir::new();
        let cols = <MineUnoAir as BaseAir<Goldilocks>>::main_next_row_columns(&air);
        assert_eq!(cols.len(), MINE_AIR_WIDTH);
        assert_eq!(cols[0], 0);
        assert_eq!(*cols.last().unwrap(), MINE_AIR_WIDTH - 1);
    }

    #[test]
    fn air_constants_are_sane() {
        // Row selectors are contiguous at offset 0.
        assert_eq!(COL_SEL_CM_P1, 0);
        assert_eq!(COL_SEL_POW_P2, 3);
        // Witness proxy block starts after selectors + P2 block.
        assert_eq!(
            WITNESS_PROXY_BASE,
            N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16
        );
        // Carry proxy block follows the witness proxy block.
        assert_eq!(
            COL_CAP_CARRY_BASE,
            WITNESS_PROXY_BASE + N_WITNESS_PROXY
        );
        // Total width = selectors + P2 + witness proxies + carry proxies.
        assert_eq!(
            MINE_AIR_WIDTH,
            N_ROW_SELECTORS
                + MINE_POSEIDON2_COLS_16
                + N_WITNESS_PROXY
                + N_CAP_CARRY_PROXY
        );
    }
}
