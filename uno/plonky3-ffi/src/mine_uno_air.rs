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

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

pub use crate::mine_uno_columns::*;
pub use crate::mine_uno_witness::*;

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
        let proxy_cols: [usize; 28] = [
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
        // Phase 3b TODO — Poseidon2 sub-AIR wiring
        // -------------------------------------------------------------------
        //
        // The shared width-16 Poseidon2 column block (at offset
        // N_ROW_SELECTORS, size MINE_POSEIDON2_COLS_16) must be constrained
        // as a valid Poseidon2 permutation on every row via
        // `eval_poseidon2_16(builder, &shared_p2)`. Further row-gated
        // constraints must then pin:
        //
        //   row 0 (COL_SEL_CM_P1): shared_p2.inputs[0..8] = expected rate
        //     absorb from (d_fe, pk_d_fe, ivk_cm_fe[0..2]); shared_p2.inputs
        //     [8..16] = uno_cm_v1_tag_block()
        //
        //   row 1 (COL_SEL_CM_P2): shared_p2.inputs[0..8] = ivk_cm_fe[2..4]
        //     + value + rcm_fe[0..3] + ONE padding, with capacity carried
        //     from row 0's shared_p2.post[8..16]
        //
        //   row 1 post[0..4] = output_cm_fe[0..4]  (the cm sponge digest)
        //
        //   row 2 (COL_SEL_POW_P1): shared_p2.inputs[0..8] = (epoch,
        //     nonce_fe[0..4], output_cm_fe[0..3]); shared_p2.inputs[8..16]
        //     = uno_mine_v1_tag_block()
        //
        //   row 3 (COL_SEL_POW_P2): shared_p2.inputs[0..8] = output_cm_fe[3]
        //     + ONE padding + 6 zeros; capacity carried from row 2
        //
        //   row 3 post[0..4] = pow_hash_fe[0..4]  (the PoW digest)
        //
        // The "capacity carry" between perm 1 and perm 2 of each sponge is
        // non-trivial to express as a transition constraint because it
        // crosses a row boundary. The cleanest pattern (used by Transfer's
        // cm-sponge at `transfer_air.rs` lines ~1663-1830) introduces
        // per-carry proxy columns so the row-local constraint can reference
        // both perm outputs consistently.
        //
        // Until this wiring lands, the Poseidon2 cells in the shared block
        // remain unconstrained (AIR eval does not reference them), and the
        // witness-side `generate_trace` leaves them zero. This means a
        // malicious prover could substitute any output_cm/pow_hash into
        // the proxy columns — soundness is not achieved until Phase 3b.
        //
        // Do not ship the AIR to mainnet until this constraint closes.
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        // Total width = selectors + P2 + proxies.
        assert_eq!(
            MINE_AIR_WIDTH,
            N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16 + N_WITNESS_PROXY
        );
    }
}

use p3_goldilocks::Goldilocks;
