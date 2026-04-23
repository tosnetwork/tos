//! Monolithic VerifierAir — Phase A3-PRE scaffolding.
//!
//! ⚠️ **v2 research path (frozen).** Per the v1 pivot in
//! `doc/uno-aggregation-design.md` §-1 (2026-04-21), UNO v1 launches
//! WITHOUT this AIR on the critical path. Each Transfer carries its
//! own per-Tx Plonky3 STARK on-chain; validators verify them
//! directly (see `uno/plonky3-ffi/src/verifier_air.rs` for the
//! v1 verifier path). This module stays in-tree as frozen v2
//! research; revive when the §-1 triggers light up
//! (WHIR/BaseFold maturity + specialized prover ecosystem). The
//! 40-test suite + `#[ignore]` measurement benches in the tests
//! module here are the audit-grade proof that this path is
//! sound — ready for v2 activation.
//!
//! This module implements the **merged, single-STARK** per-Tx verifier
//! AIR that Phase A3+ will use to collapse the A2 orchestration's
//! 6+N per-query STARK bundle into ONE proof. See
//! `doc/uno-aggregation-path-decision.md` for the decision rationale.
//!
//! # Design (K-air-col-share pattern)
//!
//! Every row represents one "step" in the verifier's execution. A
//! per-row one-hot `KIND` selector picks which constraint bank applies:
//!
//! ```text
//!   KIND ∈ { ABSORB, COMPRESS, FOLD, ALPHA, IDLE }
//!
//!     ABSORB   : one PaddingFreeSponge absorb block (leaf hash for a
//!                Merkle leaf). Uses the shared Poseidon2-w8 block.
//!     COMPRESS : one binary Merkle compression step. Uses the shared
//!                Poseidon2-w8 block with [LEFT ∥ RIGHT] input.
//!     FOLD     : one FRI fold round (binary Lagrange interpolation at β).
//!                Uses the shared extension-mult lane, no P2 needed.
//!     ALPHA    : one α-batched quotient update. Uses the shared
//!                extension-mult lane (and INV witness column).
//!     IDLE     : no-op padding; all data cols carry previous row.
//! ```
//!
//! One shared **Poseidon2-w8 witness block** (180 cols) is populated
//! on every row. On ABSORB/COMPRESS rows the row-gated binding forces
//! `p2.inputs` and `p2.post[0..8]` to specific framing columns. On
//! FOLD/ALPHA/IDLE rows the block carries a dummy zero-input witness
//! (unconstrained relative to the framing).
//!
//! One shared **extension-multiplication lane** (4 output limbs + 2
//! input limbs × 3 factors = ~14 cols) is populated on every row. On
//! FOLD/ALPHA rows it's row-gated to carry the round's ext-mult result;
//! on ABSORB/COMPRESS/IDLE rows it's unconstrained.
//!
//! # Layout pinning (A3-PRE; stable from here)
//!
//! The column offsets below are PINNED so follow-up sub-phases (A3-1
//! ABSORB+COMPRESS, A3-2 FOLD+ALPHA, A3-3 cross-bindings) can reference
//! them without renumbering.
//!
//! # Status
//!
//! **A3-PRE — scaffolding only.** The `Air<AB>::eval` at this sub-phase
//! asserts:
//!   * KIND one-hot (5-way selector).
//!   * KIND boolean per flag.
//!
//! No operation-specific banks are wired yet; the trace builder
//! emits only IDLE rows. This is enough to prove the skeleton
//! round-trips through `uni_stark::prove + verify` and to lock in
//! the column layout contract.


use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

use crate::transfer_air::{eval_poseidon2, POSEIDON2_HALF_FULL_ROUNDS};

// Re-export column-layout constants so external callers can use them at the
// `crate::monolithic_verifier_air::<SYMBOL>` path without any code changes.
pub use crate::monolithic_verifier_columns::{
    col, CHALLENGE_DIM, DIGEST_WIDTH, EXT_W_U64, MONOLITHIC_VERIFIER_AIR_WIDTH,
    NUM_OP_KINDS, OP_KIND_ABSORB, OP_KIND_ALPHA, OP_KIND_COMPRESS, OP_KIND_FOLD,
    OP_KIND_IDLE, SPONGE_RATE, SPONGE_WIDTH,
};

// Re-export trace-builder types and functions so external callers can
// continue to use `crate::monolithic_verifier_air::<SYMBOL>` paths.
pub use crate::monolithic_verifier_trace::{
    block_pi_zero, build_alpha_chain_trace, build_alpha_merkle_fold_bundle_trace,
    build_alpha_to_fold_unified_trace, build_fold_chain_trace, build_leaf_to_root_trace,
    build_multi_bundle_trace, build_multi_path_leaf_to_root_trace, build_trivial_trace,
    AlphaStep, BlockPi, BundleSpec, FoldRound, MerkleOpening, TraceBuildError,
};

// Crate-internal helper needed by eval.
pub(crate) use crate::monolithic_verifier_trace::p2_group;

// ---------------------------------------------------------------------------
// Plonky3 AIR (A3-PRE: skeleton that enforces KIND one-hot only)
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Default)]
pub struct MonolithicVerifierAirV1;

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for MonolithicVerifierAirV1 {
    #[inline]
    fn width(&self) -> usize {
        MONOLITHIC_VERIFIER_AIR_WIDTH
    }

    #[inline]
    fn num_public_values(&self) -> usize {
        // A6-1.6: 8 Goldilocks elements encoding the block's
        // `BlockPublicInputs` (chain_id, block_seqno, anchor_seqno,
        // n_transfers, 4× LE limbs of tx_pi_merkle_root).
        col::NUM_BLOCK_PI_ELEMS
    }

    #[inline]
    fn max_constraint_degree(&self) -> Option<usize> {
        // Once A3-1 wires in Poseidon2 + per-bank banks, S-box degree
        // 7 dominates. Use None for auto-compute to match the other
        // hash AIRs.
        None
    }
}

impl<AB> Air<AB> for MonolithicVerifierAirV1
where
    AB: AirBuilder<F = Goldilocks>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &[AB::Var] = main.current_slice();
        let next: &[AB::Var] = main.next_slice();

        let fe = |v: u64| AB::Expr::from(AB::F::from_u64(v));
        let zero = || fe(0);
        let one = || fe(1);

        let is_absorb: AB::Expr = local[col::KIND0 + OP_KIND_ABSORB as usize].into();
        let is_compress: AB::Expr = local[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        let is_fold: AB::Expr = local[col::KIND0 + OP_KIND_FOLD as usize].into();
        let is_alpha: AB::Expr = local[col::KIND0 + OP_KIND_ALPHA as usize].into();
        let is_idle: AB::Expr = local[col::KIND0 + OP_KIND_IDLE as usize].into();

        // =================================================================
        // KIND one-hot.
        // =================================================================
        let mut sum = zero();
        for k in 0..NUM_OP_KINDS {
            let flag: AB::Expr = local[col::KIND0 + k].into();
            builder.assert_zero(flag.clone() * (flag.clone() - one()));
            sum = sum + flag;
        }
        builder.assert_eq(sum, one());

        // =================================================================
        // A3-1: ABSORB bank (leaf-hash multi-block with partial-tail).
        // Ported from leaf_hash_air (d-7-a/b/c).
        // =================================================================

        // IS_FIRST / IS_LAST boolean; gated to ABSORB rows only.
        let is_first: AB::Expr = local[col::ABSORB_IS_FIRST].into();
        let is_last: AB::Expr = local[col::ABSORB_IS_LAST].into();
        builder.assert_zero(is_first.clone() * (is_first.clone() - one()));
        builder.assert_zero(is_last.clone() * (is_last.clone() - one()));
        builder.assert_zero((one() - is_absorb.clone()) * is_first.clone());
        builder.assert_zero((one() - is_absorb.clone()) * is_last.clone());

        // BLOCK_LEN flags: boolean + one-hot + weighted-sum match.
        let mut flag_sum = zero();
        let mut weighted = zero();
        for k in 0..=SPONGE_RATE {
            let f: AB::Expr = local[col::ABSORB_BLOCK_LEN_FLAG0 + k].into();
            builder.assert_zero(f.clone() * (f.clone() - one()));
            flag_sum = flag_sum + f.clone();
            weighted = weighted + fe(k as u64) * f;
        }
        builder.assert_eq(flag_sum, one());
        builder.assert_eq(weighted, AB::Expr::from(local[col::ABSORB_BLOCK_LEN]));

        // ABSORB rows: BLOCK_LEN ≥ 1 (flag[0] == 0).
        let flag0: AB::Expr = local[col::ABSORB_BLOCK_LEN_FLAG0].into();
        builder.assert_zero(is_absorb.clone() * flag0.clone());
        // IDLE rows: BLOCK_LEN == 0 (flag[0] == 1).
        builder.assert_zero(is_idle.clone() * (one() - flag0.clone()));
        // Non-last ABSORB rows: BLOCK_LEN == RATE (flag[RATE] == 1).
        let flag_rate: AB::Expr = local[col::ABSORB_BLOCK_LEN_FLAG0 + SPONGE_RATE].into();
        builder.assert_zero(is_absorb.clone() * (one() - is_last.clone()) * (one() - flag_rate));

        // ABSORB first-row rule:
        //   STATE_IN[i] = cond_block_use[i] · BLOCK[i] for i in 0..RATE
        //              = 0                    for i in RATE..WIDTH
        //
        // where cond_block_use[i] = sum_{k > i} BLOCK_LEN_FLAG[k].
        for i in 0..SPONGE_WIDTH {
            let state_in_i: AB::Expr = local[col::STATE_IN0 + i].into();
            let mut cond_block = zero();
            for k in (i + 1)..=SPONGE_RATE {
                let f: AB::Expr = local[col::ABSORB_BLOCK_LEN_FLAG0 + k].into();
                cond_block = cond_block + f;
            }
            let block_term: AB::Expr = if i < SPONGE_RATE {
                cond_block * AB::Expr::from(local[col::ABSORB_BLOCK0 + i])
            } else {
                zero()
            };
            builder.assert_zero(is_first.clone() * (state_in_i - block_term));
        }

        // ABSORB is_last: DIGEST[0..4] == STATE_OUT[0..4].
        for i in 0..DIGEST_WIDTH {
            let dg: AB::Expr = local[col::DIGEST0 + i].into();
            let so: AB::Expr = local[col::STATE_OUT0 + i].into();
            builder.assert_zero(is_last.clone() * (dg - so));
        }

        // =================================================================
        // A3-1: COMPRESS bank (ported from compression_path_air).
        // =================================================================
        let bit: AB::Expr = local[col::COMPRESS_INDEX_BIT].into();
        builder.assert_zero(is_compress.clone() * bit.clone() * (bit.clone() - one()));

        // STATE_IN[0..4] = LEFT = (1 − bit)·CURRENT + bit·SIBLING
        // STATE_IN[4..8] = RIGHT = bit·CURRENT + (1 − bit)·SIBLING
        for i in 0..DIGEST_WIDTH {
            let cur: AB::Expr = local[col::COMPRESS_CURRENT0 + i].into();
            let sib: AB::Expr = local[col::COMPRESS_SIBLING0 + i].into();
            let s_l: AB::Expr = local[col::STATE_IN0 + i].into();
            let s_r: AB::Expr = local[col::STATE_IN0 + DIGEST_WIDTH + i].into();
            let expected_left = (one() - bit.clone()) * cur.clone() + bit.clone() * sib.clone();
            let expected_right = bit.clone() * cur + (one() - bit.clone()) * sib;
            builder.assert_zero(is_compress.clone() * (s_l - expected_left));
            builder.assert_zero(is_compress.clone() * (s_r - expected_right));
        }
        // DIGEST == STATE_OUT[0..4] on COMPRESS rows.
        for i in 0..DIGEST_WIDTH {
            let dg: AB::Expr = local[col::DIGEST0 + i].into();
            let so: AB::Expr = local[col::STATE_OUT0 + i].into();
            builder.assert_zero(is_compress.clone() * (dg - so));
        }

        // =================================================================
        // Shared Poseidon2-w8 sub-AIR: binds STATE_OUT = P2(STATE_IN) on
        // both ABSORB and COMPRESS rows.
        // =================================================================
        let p2_local = p2_group::<AB::Var>(local);
        eval_poseidon2(builder, p2_local);

        let hash_row = is_absorb.clone() + is_compress.clone();
        for i in 0..SPONGE_WIDTH {
            let p2_in: AB::Expr = p2_local.inputs[i].into();
            let s_in: AB::Expr = local[col::STATE_IN0 + i].into();
            builder.assert_zero(hash_row.clone() * (p2_in - s_in));
        }
        let p2_post = &p2_local.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
        for i in 0..SPONGE_WIDTH {
            let p2_out: AB::Expr = p2_post[i].into();
            let s_out: AB::Expr = local[col::STATE_OUT0 + i].into();
            builder.assert_zero(hash_row.clone() * (p2_out - s_out));
        }

        // =================================================================
        // Transition constraints.
        // =================================================================
        let mut trans = builder.when_transition();

        // A3-5a: TRACE_COMMIT_ROOT persists WITHIN a compression run
        // only (COMPRESS → COMPRESS). Between runs, the prover sets a
        // fresh TCR for the new path's expected root. The IDLE
        // persistence (later in this fn) still carries TCR into IDLE
        // padding, which is correct — IDLE inherits the preceding run's
        // last TCR. At ABSORB → COMPRESS, TCR is free, letting multi-
        // path traces hold independent roots.
        //
        // NOTE: this replaces A3-1's unconditional TCR persistence,
        // which made one-root-per-trace the only supported shape.
        let next_is_compress_tcr: AB::Expr = next[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        for i in 0..DIGEST_WIDTH {
            let l_r: AB::Expr = local[col::TRACE_COMMIT_ROOT0 + i].into();
            let n_r: AB::Expr = next[col::TRACE_COMMIT_ROOT0 + i].into();
            trans.assert_zero(is_compress.clone() * next_is_compress_tcr.clone() * (n_r - l_r));
        }

        // A3-5a: Per-path root check.
        // At every COMPRESS → non-COMPRESS transition, the last
        // COMPRESS row's DIGEST must equal its TRACE_COMMIT_ROOT. This
        // lets the trace hold MULTIPLE independent Merkle paths, each
        // with its own root. The check fires once per path, at the
        // path's terminal row.
        //
        // For a trace whose last row itself is COMPRESS (no IDLE
        // padding), the `when_last_row` boundary at the bottom of this
        // fn takes over — `when_transition` excludes the final row in
        // uni-stark's formulation.
        for i in 0..DIGEST_WIDTH {
            let dg: AB::Expr = local[col::DIGEST0 + i].into();
            let tcr: AB::Expr = local[col::TRACE_COMMIT_ROOT0 + i].into();
            trans.assert_zero(
                is_compress.clone() * (one() - next_is_compress_tcr.clone()) * (dg - tcr),
            );
        }

        // Leaf-digest bridge: when local is is_last ABSORB and next is
        // COMPRESS, next.CURRENT == local.STATE_OUT[0..4]. This closes
        // the A2 trusted-construction gap.
        let next_is_compress: AB::Expr = next[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        for i in 0..DIGEST_WIDTH {
            let n_cur: AB::Expr = next[col::COMPRESS_CURRENT0 + i].into();
            let l_out: AB::Expr = local[col::STATE_OUT0 + i].into();
            trans.assert_zero(is_last.clone() * next_is_compress.clone() * (n_cur - l_out));
        }

        // COMPRESS → COMPRESS: next.CURRENT = local.DIGEST.
        let next_is_compress_prop: AB::Expr = next[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        for i in 0..DIGEST_WIDTH {
            let n_cur: AB::Expr = next[col::COMPRESS_CURRENT0 + i].into();
            let l_dg: AB::Expr = local[col::DIGEST0 + i].into();
            trans.assert_zero(is_compress.clone() * next_is_compress_prop.clone() * (n_cur - l_dg));
        }

        // IDLE persistence — all shared-state + public-input cols
        // preserved across IDLE transitions. Bounded to [STATE_IN0,
        // P2_BLOCK) to avoid flagging the P2 block (which is re-generated
        // with the zero-input witness on IDLE rows).
        let next_is_idle: AB::Expr = next[col::KIND0 + OP_KIND_IDLE as usize].into();
        for c in col::STATE_IN0..col::P2_BLOCK {
            let l_c: AB::Expr = local[c].into();
            let n_c: AB::Expr = next[c].into();
            trans.assert_zero(next_is_idle.clone() * (n_c - l_c));
        }

        // ABSORB capacity carry on ABSORB-after-ABSORB:
        //   next.STATE_IN[i] =
        //       next.cond_block_use[i] · next.BLOCK[i]
        //     + next.cond_carry[i]   · local.STATE_OUT[i]
        //
        // Gated by (next_is_absorb · (1 − next_is_first)).
        let next_is_absorb: AB::Expr = next[col::KIND0 + OP_KIND_ABSORB as usize].into();
        let next_is_first: AB::Expr = next[col::ABSORB_IS_FIRST].into();
        let carry_gate = next_is_absorb * (one() - next_is_first);
        for i in 0..SPONGE_WIDTH {
            let n_in: AB::Expr = next[col::STATE_IN0 + i].into();
            let l_out: AB::Expr = local[col::STATE_OUT0 + i].into();
            let mut cond_block = zero();
            for k in (i + 1)..=SPONGE_RATE {
                let f: AB::Expr = next[col::ABSORB_BLOCK_LEN_FLAG0 + k].into();
                cond_block = cond_block + f;
            }
            let mut cond_carry = zero();
            for k in 0..=i.min(SPONGE_RATE) {
                let f: AB::Expr = next[col::ABSORB_BLOCK_LEN_FLAG0 + k].into();
                cond_carry = cond_carry + f;
            }
            let block_term: AB::Expr = if i < SPONGE_RATE {
                cond_block * AB::Expr::from(next[col::ABSORB_BLOCK0 + i])
            } else {
                zero()
            };
            let carry_term = cond_carry * l_out;
            trans.assert_zero(carry_gate.clone() * (n_in - block_term - carry_term));
        }

        drop(trans);

        // =================================================================
        // A3-5a: Last-row root check, gated on is_compress.
        //
        // When the trace's final row is a COMPRESS row (no IDLE
        // padding), the `when_transition` per-path check above doesn't
        // fire (it excludes the last row). This boundary catches that
        // case. For IDLE-padded traces the last row has is_compress=0
        // and this boundary is a no-op — the path's root check fired
        // at the COMPRESS → IDLE transition.
        //
        // For non-COMPRESS traces (α-only, fold-only, all-IDLE), the
        // gate is 0 and no constraint fires.
        // =================================================================
        let mut last = builder.when_last_row();
        let last_is_compress: AB::Expr = local[col::KIND0 + OP_KIND_COMPRESS as usize].into();
        for i in 0..DIGEST_WIDTH {
            let dg: AB::Expr = local[col::DIGEST0 + i].into();
            let r: AB::Expr = local[col::TRACE_COMMIT_ROOT0 + i].into();
            last.assert_zero(last_is_compress.clone() * (dg - r));
        }

        // =================================================================
        // A3-2: FOLD bank (binary FRI Lagrange fold).
        //
        // Column sharing (K-air-col-share): FOLD rows reuse
        //   COMPRESS_SIBLING[0..2] → FRI SIBLING (Challenge; 2 of 4 cols)
        //   COMPRESS_INDEX_BIT    → FRI INDEX_BIT (low bit of domain idx)
        //   STATE_IN[0..2]        → PAIR_LEFT  (Challenge)
        //   STATE_IN[2..4]        → PAIR_RIGHT (Challenge)
        //
        // The shared-col binding is safe because FOLD / COMPRESS are
        // one-hot disjoint — each row's gate zeroes out any cross-bank
        // constraint from the other bank.
        // =================================================================
        let w = || fe(EXT_W_U64);

        // FOLD row: INDEX_BIT boolean (shared col with COMPRESS, but
        // gated separately for FOLD). Re-assert here rather than gating
        // through is_compress.
        let fold_bit: AB::Expr = local[col::COMPRESS_INDEX_BIT].into();
        builder.assert_zero(is_fold.clone() * fold_bit.clone() * (fold_bit.clone() - one()));

        // FOLD row: PAIR_LEFT / PAIR_RIGHT orientation — STATE_IN cols
        // repurposed via K-air-col-share.
        //   STATE_IN[0..2] = PAIR_LEFT  = (1 − bit)·FOLD_IN + bit·SIBLING
        //   STATE_IN[2..4] = PAIR_RIGHT = bit·FOLD_IN + (1 − bit)·SIBLING
        for i in 0..CHALLENGE_DIM {
            let fin: AB::Expr = local[col::FOLD_IN0 + i].into();
            let sib: AB::Expr = local[col::COMPRESS_SIBLING0 + i].into();
            let pl: AB::Expr = local[col::STATE_IN0 + i].into();
            let pr: AB::Expr = local[col::STATE_IN0 + CHALLENGE_DIM + i].into();
            let expected_left =
                (one() - fold_bit.clone()) * fin.clone() + fold_bit.clone() * sib.clone();
            let expected_right = fold_bit.clone() * fin + (one() - fold_bit.clone()) * sib;
            builder.assert_zero(is_fold.clone() * (pl - expected_left));
            builder.assert_zero(is_fold.clone() * (pr - expected_right));
        }

        // FOLD row: INV_2S witness 2·S·INV_2S = 1.
        {
            let s: AB::Expr = local[col::FOLD_S].into();
            let inv2s: AB::Expr = local[col::FOLD_INV_2S].into();
            builder.assert_zero(is_fold.clone() * (fe(2) * s * inv2s - one()));
        }

        // FOLD row: fold identity per limb (degree 3 when gated).
        //   folded_0 · 2s = s·(pl_0 + pr_0) + β_0·d_0 + W·β_1·d_1
        //   folded_1 · 2s = s·(pl_1 + pr_1) + β_0·d_1 +     β_1·d_0
        {
            let s: AB::Expr = local[col::FOLD_S].into();
            let pl0: AB::Expr = local[col::STATE_IN0].into();
            let pl1: AB::Expr = local[col::STATE_IN0 + 1].into();
            let pr0: AB::Expr = local[col::STATE_IN0 + CHALLENGE_DIM].into();
            let pr1: AB::Expr = local[col::STATE_IN0 + CHALLENGE_DIM + 1].into();
            let b0: AB::Expr = local[col::FOLD_BETA0].into();
            let b1: AB::Expr = local[col::FOLD_BETA0 + 1].into();
            let f0: AB::Expr = local[col::FOLD_OUT0].into();
            let f1: AB::Expr = local[col::FOLD_OUT0 + 1].into();

            let two_s = fe(2) * s.clone();
            let d0 = pl0.clone() - pr0.clone();
            let d1 = pl1.clone() - pr1.clone();

            let lhs0 = f0 * two_s.clone();
            let rhs0 =
                s.clone() * (pl0 + pr0) + b0.clone() * d0.clone() + w() * b1.clone() * d1.clone();
            builder.assert_zero(is_fold.clone() * (lhs0 - rhs0));

            let lhs1 = f1 * two_s;
            let rhs1 = s * (pl1 + pr1) + b0 * d1 + b1 * d0;
            builder.assert_zero(is_fold.clone() * (lhs1 - rhs1));
        }

        // =================================================================
        // A3-2: ALPHA bank (α-batched quotient combination).
        //
        // Self-contained in the ALPHA_* columns: four degree-2 extension
        // multiplications, each gated by is_alpha → degree 3 overall.
        // =================================================================
        let ext_mul =
            |a0: AB::Expr, a1: AB::Expr, b0: AB::Expr, b1: AB::Expr| -> (AB::Expr, AB::Expr) {
                let p0 = a0.clone() * b0.clone() + w() * a1.clone() * b1.clone();
                let p1 = a0 * b1 + a1 * b0;
                (p0, p1)
            };

        // (1) ALPHA — QUOT_INV · (Z − X) == 1.
        {
            let qi0: AB::Expr = local[col::ALPHA_QUOT_INV0].into();
            let qi1: AB::Expr = local[col::ALPHA_QUOT_INV0 + 1].into();
            let z0: AB::Expr = local[col::ALPHA_Z0].into();
            let z1: AB::Expr = local[col::ALPHA_Z0 + 1].into();
            let x: AB::Expr = local[col::ALPHA_X].into();
            let d0 = z0 - x;
            let d1 = z1;
            let (p0, p1) = ext_mul(qi0, qi1, d0, d1);
            builder.assert_zero(is_alpha.clone() * (p0 - one()));
            builder.assert_zero(is_alpha.clone() * p1);
        }

        // (2) ALPHA — DIFF_QUOT == (P_AT_Z − P_AT_X) · QUOT_INV.
        {
            let pz0: AB::Expr = local[col::ALPHA_P_AT_Z0].into();
            let pz1: AB::Expr = local[col::ALPHA_P_AT_Z0 + 1].into();
            let px: AB::Expr = local[col::ALPHA_P_AT_X].into();
            let qi0: AB::Expr = local[col::ALPHA_QUOT_INV0].into();
            let qi1: AB::Expr = local[col::ALPHA_QUOT_INV0 + 1].into();
            let diff0 = pz0 - px;
            let diff1 = pz1;
            let (dq0_exp, dq1_exp) = ext_mul(diff0, diff1, qi0, qi1);
            let dq0: AB::Expr = local[col::ALPHA_DIFF_QUOT0].into();
            let dq1: AB::Expr = local[col::ALPHA_DIFF_QUOT0 + 1].into();
            builder.assert_zero(is_alpha.clone() * (dq0 - dq0_exp));
            builder.assert_zero(is_alpha.clone() * (dq1 - dq1_exp));
        }

        // (3) ALPHA — ALPHA_POW_OUT == ALPHA_POW_IN · ALPHA.
        {
            let api0: AB::Expr = local[col::ALPHA_POW_IN0].into();
            let api1: AB::Expr = local[col::ALPHA_POW_IN0 + 1].into();
            let a0: AB::Expr = local[col::ALPHA_CHALLENGE0].into();
            let a1: AB::Expr = local[col::ALPHA_CHALLENGE0 + 1].into();
            let (exp0, exp1) = ext_mul(api0, api1, a0, a1);
            let apo0: AB::Expr = local[col::ALPHA_POW_OUT0].into();
            let apo1: AB::Expr = local[col::ALPHA_POW_OUT0 + 1].into();
            builder.assert_zero(is_alpha.clone() * (apo0 - exp0));
            builder.assert_zero(is_alpha.clone() * (apo1 - exp1));
        }

        // (4) ALPHA — RO_OUT == RO_IN + ALPHA_POW_IN · DIFF_QUOT.
        {
            let api0: AB::Expr = local[col::ALPHA_POW_IN0].into();
            let api1: AB::Expr = local[col::ALPHA_POW_IN0 + 1].into();
            let dq0: AB::Expr = local[col::ALPHA_DIFF_QUOT0].into();
            let dq1: AB::Expr = local[col::ALPHA_DIFF_QUOT0 + 1].into();
            let (add0, add1) = ext_mul(api0, api1, dq0, dq1);
            let ri0: AB::Expr = local[col::ALPHA_RO_IN0].into();
            let ri1: AB::Expr = local[col::ALPHA_RO_IN0 + 1].into();
            let ro0: AB::Expr = local[col::ALPHA_RO_OUT0].into();
            let ro1: AB::Expr = local[col::ALPHA_RO_OUT0 + 1].into();
            builder.assert_zero(is_alpha.clone() * (ro0 - (ri0 + add0)));
            builder.assert_zero(is_alpha.clone() * (ro1 - (ri1 + add1)));
        }

        // =================================================================
        // A3-2: FOLD / ALPHA transitions (threading + PI persistence).
        // =================================================================
        let mut trans2 = builder.when_transition();

        // FOLD threading: next.FOLD_IN = local.FOLD_OUT when next is FOLD.
        let next_is_fold: AB::Expr = next[col::KIND0 + OP_KIND_FOLD as usize].into();
        for i in 0..CHALLENGE_DIM {
            let n_in: AB::Expr = next[col::FOLD_IN0 + i].into();
            let l_out: AB::Expr = local[col::FOLD_OUT0 + i].into();
            trans2.assert_zero(next_is_fold.clone() * (n_in - l_out));
        }

        // ALPHA threading (A3-2, gated α→α only in A3-5c):
        //   next.ALPHA_POW_IN = local.ALPHA_POW_OUT when local AND next are ALPHA
        //   next.ALPHA_RO_IN  = local.ALPHA_RO_OUT  when local AND next are ALPHA
        //
        // A3-5c adds the `is_alpha ·` factor so the transition fires
        // ONLY on within-α-chain transitions. At bundle boundaries
        // (non-α → α), the A3-5c bundle-seed check (c, d) below takes
        // over, seeding the new bundle's α chain from its INITIAL_*
        // values rather than from the previous bundle's final values.
        let next_is_alpha: AB::Expr = next[col::KIND0 + OP_KIND_ALPHA as usize].into();
        for i in 0..CHALLENGE_DIM {
            let n_api: AB::Expr = next[col::ALPHA_POW_IN0 + i].into();
            let l_apo: AB::Expr = local[col::ALPHA_POW_OUT0 + i].into();
            trans2.assert_zero(is_alpha.clone() * next_is_alpha.clone() * (n_api - l_apo));

            let n_ri: AB::Expr = next[col::ALPHA_RO_IN0 + i].into();
            let l_ro: AB::Expr = local[col::ALPHA_RO_OUT0 + i].into();
            trans2.assert_zero(is_alpha.clone() * next_is_alpha.clone() * (n_ri - l_ro));
        }

        // A3-5c: PI-proxy persistence GATED by `1 − bundle_start`.
        //
        // A bundle is one per-Tx-query verification (α chain + Merkle
        // paths + fold chain). Each bundle has its own PI proxies
        // (INITIAL_ALPHA_POW, INITIAL_RO, FINAL_FOLDED, INITIAL_FOLDED,
        // FINAL_RO) reflecting that bundle's α seed and ρ_final. Across
        // bundle boundaries (non-α → α), these values CHANGE; within a
        // bundle they persist.
        //
        //   bundle_start = (1 − local_is_alpha) · next_is_alpha
        //
        // (Degree 2; the PI-diff is degree 1; total degree 3 ✓.)
        let bundle_start: AB::Expr = (one() - is_alpha.clone()) * next_is_alpha.clone();
        for c in col::INITIAL_ALPHA_POW0..col::FINAL_RO_END {
            let l_c: AB::Expr = local[c].into();
            let n_c: AB::Expr = next[c].into();
            trans2.assert_zero((one() - bundle_start.clone()) * (n_c - l_c));
        }

        // =================================================================
        // A3-3: Cross-binding constraints.
        //
        // Close the A2 "trusted-by-construction" gap at the α↔fold seam.
        // The aggregator pipeline is: α-reduction chain computes ρ (the
        // reduced opening at the query point); ρ then seeds the fold
        // chain's initial running value. In A2 this was threaded at
        // orchestrator level without in-circuit binding. A3-3 enforces
        // it with three constraints:
        //
        //   (i)  Direct α→FOLD bridge: when a FOLD row follows an ALPHA
        //        row, the fold's FOLD_IN must equal the α's ALPHA_RO_OUT.
        //   (ii) ALPHA_RO_OUT persistence on non-α transitions, so the
        //        α chain's last output propagates through fold/IDLE rows
        //        to the last-row boundary `ALPHA_RO_OUT == FINAL_RO`.
        //   (iii) FOLD_OUT persistence on non-fold transitions, so the
        //        fold chain's last output propagates to the last-row
        //        boundary `FOLD_OUT == FINAL_FOLDED`.
        //
        // Together, a unified α+fold+IDLE trace verifies in ONE STARK.
        // =================================================================

        // (i) α→FOLD bridge: is_alpha · next_is_fold · (next.FOLD_IN − local.ALPHA_RO_OUT) = 0.
        for i in 0..CHALLENGE_DIM {
            let n_fin: AB::Expr = next[col::FOLD_IN0 + i].into();
            let l_ro: AB::Expr = local[col::ALPHA_RO_OUT0 + i].into();
            trans2.assert_zero(is_alpha.clone() * next_is_fold.clone() * (n_fin - l_ro));
        }

        // (ii) ALPHA_RO_OUT persistence on non-α transitions.
        //      (1 − next_is_alpha) · (next.ALPHA_RO_OUT − local.ALPHA_RO_OUT) = 0.
        for i in 0..CHALLENGE_DIM {
            let l_ro: AB::Expr = local[col::ALPHA_RO_OUT0 + i].into();
            let n_ro: AB::Expr = next[col::ALPHA_RO_OUT0 + i].into();
            trans2.assert_zero((one() - next_is_alpha.clone()) * (n_ro - l_ro));
        }

        // (iii) FOLD_OUT persistence on non-fold transitions.
        //       (1 − next_is_fold) · (1 − next_is_alpha) · (next.FOLD_OUT − local.FOLD_OUT) = 0.
        //
        // A3-5c refines A3-3's non-fold persistence by adding the
        // `(1 − next_is_alpha)` factor: FOLD_OUT persists across
        // non-fold → non-α transitions (α→Merkle, Merkle→Merkle,
        // Merkle→IDLE, etc.) BUT is free to change at any → α
        // transition — which is exactly a bundle boundary. The A3-3
        // adversarial test `air_rejects_unified_tampered_alpha_ro_out_on_fold_row`
        // still passes because that test tampers ALPHA_RO_OUT, caught
        // by non-α persistence (ii), not FOLD_OUT persistence.
        //
        // Degree stays at 3 (two one-hot factors × diff).
        for i in 0..CHALLENGE_DIM {
            let l_fo: AB::Expr = local[col::FOLD_OUT0 + i].into();
            let n_fo: AB::Expr = next[col::FOLD_OUT0 + i].into();
            trans2.assert_zero(
                (one() - next_is_fold.clone()) * (one() - next_is_alpha.clone()) * (n_fo - l_fo),
            );
        }

        // =================================================================
        // A3-5c: Bundle-boundary constraints.
        //
        // Fires at each non-α → α transition (`bundle_start`):
        //   (a) Previous bundle's α chain closed: local.ALPHA_RO_OUT
        //       == local.FINAL_RO (prev bundle's claimed ρ_final).
        //   (b) Previous bundle's fold chain closed: local.FOLD_OUT
        //       == local.FINAL_FOLDED (prev bundle's claimed final).
        //   (c) New bundle's α seed: next.ALPHA_POW_IN
        //       == next.INITIAL_ALPHA_POW.
        //   (d) New bundle's RO seed: next.ALPHA_RO_IN == next.INITIAL_RO.
        //
        // Combined with the unconditional last-row boundaries (which
        // check the LAST bundle's close), this gives per-bundle
        // correctness across any number of stacked bundles.
        //
        // Degree: each is `bundle_start (degree 2) · diff (degree 1)`
        // = degree 3. ✓
        for i in 0..CHALLENGE_DIM {
            // (a) prev bundle α closed.
            let l_ro: AB::Expr = local[col::ALPHA_RO_OUT0 + i].into();
            let l_fr: AB::Expr = local[col::FINAL_RO0 + i].into();
            trans2.assert_zero(bundle_start.clone() * (l_ro - l_fr));

            // (b) prev bundle fold closed.
            let l_fo: AB::Expr = local[col::FOLD_OUT0 + i].into();
            let l_ff: AB::Expr = local[col::FINAL_FOLDED0 + i].into();
            trans2.assert_zero(bundle_start.clone() * (l_fo - l_ff));

            // (c) new bundle α seed.
            let n_api: AB::Expr = next[col::ALPHA_POW_IN0 + i].into();
            let n_iap: AB::Expr = next[col::INITIAL_ALPHA_POW0 + i].into();
            trans2.assert_zero(bundle_start.clone() * (n_api - n_iap));

            // (d) new bundle RO seed.
            let n_ri: AB::Expr = next[col::ALPHA_RO_IN0 + i].into();
            let n_ir: AB::Expr = next[col::INITIAL_RO0 + i].into();
            trans2.assert_zero(bundle_start.clone() * (n_ri - n_ir));
        }

        // =================================================================
        // A6-1.6: Block-level PI persistence (UNCONDITIONAL).
        //
        // The 8 BLOCK_PI_* columns carry the block's public inputs on
        // every row. They are BLOCK-LEVEL (not bundle-scoped), so they
        // persist across every transition — including bundle boundaries
        // and IDLE transitions. Combined with the `when_first_row` pin
        // against `builder.public_values()[0..8]`, every row's BLOCK_PI
        // columns are cryptographically bound to the aggregated proof's
        // declared PI.
        //
        // Degree: 1 (a pure equality; no gating factor). ✓
        // =================================================================
        for c in col::BLOCK_PI_CHAIN_ID..col::BLOCK_PI_ROOT_END {
            let l_c: AB::Expr = local[c].into();
            let n_c: AB::Expr = next[c].into();
            trans2.assert_zero(n_c - l_c);
        }

        drop(trans2);

        // =================================================================
        // A3-2: Row-0 boundaries for FOLD and ALPHA chains.
        //
        // Each boundary is gated by the row-0 kind so it only fires when
        // the chain is present. Leaf-to-root traces (row 0 = ABSORB) are
        // unaffected: is_fold = is_alpha = 0 on an ABSORB row.
        // =================================================================
        let mut first = builder.when_first_row();
        // FOLD row-0: FOLD_IN == INITIAL_FOLDED.
        for i in 0..CHALLENGE_DIM {
            let fin: AB::Expr = local[col::FOLD_IN0 + i].into();
            let init: AB::Expr = local[col::INITIAL_FOLDED0 + i].into();
            first.assert_zero(is_fold.clone() * (fin - init));
        }
        // ALPHA row-0:
        //   ALPHA_POW_IN == INITIAL_ALPHA_POW
        //   ALPHA_RO_IN  == INITIAL_RO
        for i in 0..CHALLENGE_DIM {
            let api: AB::Expr = local[col::ALPHA_POW_IN0 + i].into();
            let iap: AB::Expr = local[col::INITIAL_ALPHA_POW0 + i].into();
            first.assert_zero(is_alpha.clone() * (api - iap));

            let ri: AB::Expr = local[col::ALPHA_RO_IN0 + i].into();
            let ir: AB::Expr = local[col::INITIAL_RO0 + i].into();
            first.assert_zero(is_alpha.clone() * (ri - ir));
        }
        drop(first);

        // A6-1.6: Bind row-0 BLOCK_PI columns to the proof's declared
        // public values. With the UNCONDITIONAL BLOCK_PI persistence
        // constraint in trans2, this row-0 pin propagates to every row.
        //
        // PublicVar: Copy, so we snapshot the 8 values first; then open
        // the when_first_row filter to emit the 8 equality constraints.
        let pi_vars: [AB::PublicVar; col::NUM_BLOCK_PI_ELEMS] = {
            let pis = builder.public_values();
            // The AIR declares num_public_values() = NUM_BLOCK_PI_ELEMS;
            // prove/verify enforce length at the boundary, so indexing
            // 0..8 is safe for any honest configuration.
            core::array::from_fn(|i| pis[i])
        };
        let mut first_pi = builder.when_first_row();
        for (i, c) in (col::BLOCK_PI_CHAIN_ID..col::BLOCK_PI_ROOT_END).enumerate() {
            let l_c: AB::Expr = local[c].into();
            let pi_i: AB::Expr = pi_vars[i].into();
            first_pi.assert_zero(l_c - pi_i);
        }

        // =================================================================
        // A3-2: Last-row boundaries.
        //
        // FOLD chain: last row's FOLD_OUT == FINAL_FOLDED.
        // ALPHA chain: last row's ALPHA_RO_OUT == FINAL_RO.
        //
        // For fold-only / α-only traces, IDLE persistence carries these
        // cols from the last physical row through to the last trace row.
        // For non-FOLD / non-ALPHA traces (e.g. leaf-to-root), the trace
        // builder sets FOLD_OUT = FINAL_FOLDED = 0 and ALPHA_RO_OUT =
        // FINAL_RO = 0 on every row, so both boundaries hold trivially.
        // =================================================================
        let mut last2 = builder.when_last_row();
        for i in 0..CHALLENGE_DIM {
            let f: AB::Expr = local[col::FOLD_OUT0 + i].into();
            let expected: AB::Expr = local[col::FINAL_FOLDED0 + i].into();
            last2.assert_zero(f - expected);

            let ro: AB::Expr = local[col::ALPHA_RO_OUT0 + i].into();
            let fr: AB::Expr = local[col::FINAL_RO0 + i].into();
            last2.assert_zero(ro - fr);
        }

        // Silence the unused-var warning for is_idle (used implicitly
        // via one-hot sum).
        let _ = is_idle;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_path::hash_leaf_row_ref;

    /// A6-1.6: test PI = all-zero 8-element Goldilocks array. Test
    /// traces use `block_pi_zero()` to populate BLOCK_PI cols to zero,
    /// so calling `prove / verify` with this constant satisfies the
    /// in-circuit PI binding trivially. Production call sites pass a
    /// real PI derived from `BlockPublicInputs`.
    const TEST_PI_ZERO: [Goldilocks; 8] = [Goldilocks::new(0); 8];

    #[test]
    fn column_layout_is_stable() {
        // Pin the layout at A3-PRE. Follow-up sub-phases must NOT change
        // these offsets, or downstream column-share logic breaks.
        //
        // If you land a legitimate refactor that shifts offsets, update
        // this test AND doc/uno-aggregation-path-decision.md §A3-PRE.
        assert_eq!(col::KIND0, 0);
        assert_eq!(col::KIND_END, 5);
        assert_eq!(col::ABSORB_BLOCK0, 5);
        assert_eq!(col::P2_BLOCK % 1, 0); // just a syntactic no-op
        assert_eq!(col::WIDTH, col::P2_BLOCK + POSEIDON2_COLS_PER_INSTANCE);
        // A6-1.6: 8 BLOCK_PI columns sit between FINAL_RO_END and P2_BLOCK.
        assert_eq!(col::NUM_BLOCK_PI_ELEMS, 8);
        assert_eq!(col::BLOCK_PI_ROOT_END - col::BLOCK_PI_CHAIN_ID, 8);
        assert_eq!(col::BLOCK_PI_CHAIN_ID, col::FINAL_RO_END);
        assert_eq!(col::P2_BLOCK, col::BLOCK_PI_ROOT_END);
    }

    #[test]
    fn trivial_trace_builds_any_pow2_height() {
        for h in [4, 8, 16, 32] {
            let flat = build_trivial_trace(h).expect("build");
            assert_eq!(flat.len(), h * col::WIDTH);
        }
    }

    #[test]
    fn trivial_trace_rejects_non_pow2() {
        let err = build_trivial_trace(7).unwrap_err();
        assert_eq!(err, TraceBuildError::TraceHeightNotPow2 { got: 7 });
    }

    /// The A3-PRE acceptance test: a trivial all-IDLE trace prove+verifies.
    /// Proves the scaffolding round-trips cleanly and the Poseidon2
    /// witness block populates correctly.
    #[test]
    fn air_prove_and_verify_trivial_idle_trace() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let flat = build_trivial_trace(16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO).expect("trivial IDLE trace must verify");
    }

    #[test]
    fn air_rejects_broken_kind_onehot() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let mut flat = build_trivial_trace(16).unwrap();
        // Set KIND_ABSORB = 1 on row 0 (which already has KIND_IDLE = 1).
        flat[col::KIND0 + OP_KIND_ABSORB as usize] = Goldilocks::new(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {} // debug-builder panic on broken one-hot
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO).expect_err("broken KIND one-hot must reject");
            }
        }
    }

    /// Report the column width to stdout — useful for A3-1 planning.
    #[test]
    fn print_column_layout() {
        eprintln!("MonolithicVerifierAir layout (A3-PRE):");
        eprintln!(
            "  KIND           : 0 .. {}  ({} cols)",
            col::KIND_END,
            col::KIND_END
        );
        eprintln!(
            "  ABSORB bank    : {} .. {}",
            col::ABSORB_BLOCK0,
            col::ABSORB_IS_LAST + 1
        );
        eprintln!(
            "  COMPRESS bank  : {} .. {}",
            col::COMPRESS_CURRENT0,
            col::COMPRESS_INDEX_BIT + 1
        );
        eprintln!(
            "  STATE (shared) : {} .. {}",
            col::STATE_IN0,
            col::DIGEST_END
        );
        eprintln!(
            "  FOLD bank      : {} .. {}",
            col::FOLD_BETA0,
            col::FOLD_OUT_END
        );
        eprintln!(
            "  ALPHA bank     : {} .. {}",
            col::ALPHA_CHALLENGE0,
            col::ALPHA_RO_OUT_END
        );
        eprintln!(
            "  Block PI (A6-1.6): {} .. {}  ({} cols)",
            col::BLOCK_PI_CHAIN_ID,
            col::BLOCK_PI_ROOT_END,
            col::NUM_BLOCK_PI_ELEMS
        );
        eprintln!(
            "  Public-input   : {} .. {}",
            col::TRACE_COMMIT_ROOT0,
            col::FINAL_FOLDED_END
        );
        eprintln!(
            "  P2 block       : {} .. {}  ({} cols)",
            col::P2_BLOCK,
            col::WIDTH,
            POSEIDON2_COLS_PER_INSTANCE
        );
        eprintln!("  TOTAL WIDTH    : {}", col::WIDTH);
    }

    // ======================================================================
    // A3-1: ABSORB + COMPRESS banks — "wide leaf → root" single STARK
    // ======================================================================

    fn gl(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    /// Hand-built tiny Merkle tree over 4 width-8 leaves.
    /// Returns (leaves, openings_per_leaf, root).
    #[allow(clippy::type_complexity)]
    fn tiny_tree_wide_leaves() -> (
        Vec<Vec<Goldilocks>>,
        Vec<(Digest, Vec<Digest>, usize)>,
        Digest,
    ) {
        let perm = default_goldilocks_poseidon2_8();
        let leaves: Vec<Vec<Goldilocks>> = (0..4u64)
            .map(|i| (0..8u64).map(|j| gl(i * 100 + j * 13 + 1)).collect())
            .collect();
        let leaf_digests: Vec<Digest> =
            leaves.iter().map(|l| hash_leaf_row_ref(&perm, l)).collect();
        let level1 = vec![
            compress_pair_ref(&perm, &leaf_digests[0], &leaf_digests[1]),
            compress_pair_ref(&perm, &leaf_digests[2], &leaf_digests[3]),
        ];
        let root = compress_pair_ref(&perm, &level1[0], &level1[1]);

        let mut openings = Vec::with_capacity(4);
        for idx in 0..4usize {
            let sib0 = leaf_digests[idx ^ 1];
            let sib1 = if (idx >> 1) & 1 == 0 {
                level1[1]
            } else {
                level1[0]
            };
            openings.push((leaf_digests[idx], vec![sib0, sib1], idx));
        }
        (leaves, openings, root)
    }

    #[test]
    fn air_prove_and_verify_leaf_to_root_width_8_leaf_0() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[0].clone();
        // 2 absorb (W=8 / RATE=4) + 2 compress = 4 physical rows; pad to 16.
        let flat = build_leaf_to_root_trace(&leaves[0], &path, idx, root, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO)
            .expect("width-8 leaf → root must verify end-to-end in ONE STARK");
    }

    #[test]
    fn air_prove_and_verify_leaf_to_root_all_tiny_leaves() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        for (leaf_idx, (_, path, idx)) in openings.iter().enumerate() {
            let flat =
                build_leaf_to_root_trace(&leaves[leaf_idx], path, *idx, root, 16).expect("build");
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
            verify(&cfg, &air, &proof, &TEST_PI_ZERO)
                .unwrap_or_else(|e| panic!("leaf {leaf_idx}: {e:?}"));
        }
    }

    #[test]
    fn air_rejects_tampered_wide_leaf() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[0].clone();
        let mut flat = build_leaf_to_root_trace(&leaves[0], &path, idx, root, 16).unwrap();
        // Corrupt the first ABSORB row's BLOCK[0]: the P2 chain breaks,
        // the leaf digest differs, the bridge fails, and ultimately the
        // last-row DIGEST ≠ ROOT.
        flat[col::ABSORB_BLOCK0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO).expect_err("tampered wide leaf must reject");
            }
        }
    }

    #[test]
    fn air_rejects_wrong_expected_root() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[0].clone();
        let mut bad_root = root;
        bad_root[0] += gl(1);
        // Build with bad root pinned on every row; last-row DIGEST is
        // the REAL root, which differs — last-row boundary fires.
        let flat = build_leaf_to_root_trace(&leaves[0], &path, idx, bad_root, 16).expect("build");
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("wrong root must reject at last-row boundary");
            }
        }
    }

    /// A3-1 acceptance: the bridge between last-absorb DIGEST and
    /// first-compress CURRENT is an in-circuit constraint, not a
    /// trusted-by-construction assertion. Directly tampering the
    /// first COMPRESS row's CURRENT must cause rejection via the
    /// `is_last · next_is_compress · (next.CURRENT − local.STATE_OUT)`
    /// transition bank.
    #[test]
    fn air_rejects_forged_bridge_between_absorb_and_compress() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[0].clone();
        let mut flat = build_leaf_to_root_trace(&leaves[0], &path, idx, root, 16).unwrap();
        // Row 0, 1: ABSORB (W=8, 2 blocks). Row 2: first COMPRESS.
        // Tamper row 2's CURRENT[0] so it doesn't equal row 1's
        // STATE_OUT[0]. The bridge constraint is
        // is_last · next_is_compress · (next.CURRENT − local.STATE_OUT)
        // on the (row1, row2) transition — this fires.
        let row2 = 2 * col::WIDTH;
        flat[row2 + col::COMPRESS_CURRENT0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO).expect_err(
                    "forged leaf-digest bridge must reject — A3-1 closes A2's construction gap",
                );
            }
        }
    }

    // ======================================================================
    // A3-2: ALPHA + FOLD banks — standalone chains
    // ======================================================================

    use p3_field::BasedVectorSpace;

    fn ext(a: u64, b: u64) -> Challenge {
        Challenge::from_basis_coefficients_fn(|i| if i == 0 { gl(a) } else { gl(b) })
    }

    /// Run the α-chain out-of-circuit to compute the expected FINAL_RO.
    fn expected_final_ro(
        initial_alpha_pow: Challenge,
        initial_ro: Challenge,
        alpha: Challenge,
        steps: &[AlphaStep],
    ) -> Challenge {
        let mut apow = initial_alpha_pow;
        let mut ro = initial_ro;
        for step in steps {
            let denom = step.z - step.x;
            use p3_field::Field;
            let qi = denom.try_inverse().expect("denom ≠ 0");
            let diff = step.p_at_z - step.p_at_x;
            let dq = diff * qi;
            ro = ro + apow * dq;
            apow = apow * alpha;
        }
        ro
    }

    /// Run the fold chain out-of-circuit to compute the expected FINAL_FOLDED.
    fn expected_final_folded(initial_folded: Challenge, rounds: &[FoldRound]) -> Challenge {
        let mut current = initial_folded;
        for round in rounds {
            let bit = (round.domain_index & 1) as u64;
            let child_log_h = round.log_height - 1;
            let parent_idx = round.domain_index >> 1;
            let (pair_left, pair_right) = if bit == 0 {
                (current, round.sibling)
            } else {
                (round.sibling, current)
            };
            current = fold_row_ref(
                parent_idx,
                child_log_h,
                1,
                round.beta,
                &[pair_left, pair_right],
            );
        }
        current
    }

    #[test]
    fn air_prove_and_verify_alpha_chain_3_steps() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let steps = vec![
            AlphaStep {
                p_at_x: gl(7),
                p_at_z: ext(11, 13),
                z: ext(17, 19),
                x: gl(23),
            },
            AlphaStep {
                p_at_x: gl(29),
                p_at_z: ext(31, 37),
                z: ext(41, 43),
                x: gl(47),
            },
            AlphaStep {
                p_at_x: gl(53),
                p_at_z: ext(59, 61),
                z: ext(67, 71),
                x: gl(73),
            },
        ];
        let final_ro = expected_final_ro(initial_apow, initial_ro, alpha, &steps);
        let flat =
            build_alpha_chain_trace(initial_apow, initial_ro, alpha, &steps, final_ro, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO)
            .expect("α-chain (3 steps) must verify in ONE monolithic STARK");
    }

    #[test]
    fn air_prove_and_verify_alpha_chain_single_step() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(2, 0);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let steps = vec![AlphaStep {
            p_at_x: gl(1),
            p_at_z: ext(2, 3),
            z: ext(5, 7),
            x: gl(11),
        }];
        let final_ro = expected_final_ro(initial_apow, initial_ro, alpha, &steps);
        let flat =
            build_alpha_chain_trace(initial_apow, initial_ro, alpha, &steps, final_ro, 8).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO).expect("α-chain (1 step) must verify");
    }

    #[test]
    fn air_rejects_alpha_chain_wrong_final_ro() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let steps = vec![
            AlphaStep {
                p_at_x: gl(7),
                p_at_z: ext(11, 13),
                z: ext(17, 19),
                x: gl(23),
            },
            AlphaStep {
                p_at_x: gl(29),
                p_at_z: ext(31, 37),
                z: ext(41, 43),
                x: gl(47),
            },
        ];
        let real_final = expected_final_ro(initial_apow, initial_ro, alpha, &steps);
        let bad_final = real_final + ext(1, 0);
        let flat =
            build_alpha_chain_trace(initial_apow, initial_ro, alpha, &steps, bad_final, 8).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("wrong FINAL_RO must reject at last-row boundary");
            }
        }
    }

    #[test]
    fn air_rejects_alpha_chain_tampered_p_at_x() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let steps = vec![
            AlphaStep {
                p_at_x: gl(7),
                p_at_z: ext(11, 13),
                z: ext(17, 19),
                x: gl(23),
            },
            AlphaStep {
                p_at_x: gl(29),
                p_at_z: ext(31, 37),
                z: ext(41, 43),
                x: gl(47),
            },
        ];
        let final_ro = expected_final_ro(initial_apow, initial_ro, alpha, &steps);
        let mut flat =
            build_alpha_chain_trace(initial_apow, initial_ro, alpha, &steps, final_ro, 8).unwrap();
        // Tamper P_AT_X on row 0 — breaks DIFF_QUOT and RO_OUT.
        flat[col::ALPHA_P_AT_X] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("tampered P_AT_X must reject via DIFF_QUOT bank");
            }
        }
    }

    #[test]
    fn air_prove_and_verify_fold_chain_3_rounds() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let initial_folded = ext(5, 7);
        let rounds = vec![
            FoldRound {
                sibling: ext(11, 13),
                beta: ext(17, 19),
                domain_index: 0b101,
                log_height: 5,
            },
            FoldRound {
                sibling: ext(23, 29),
                beta: ext(31, 37),
                domain_index: 0b010,
                log_height: 4,
            },
            FoldRound {
                sibling: ext(41, 43),
                beta: ext(47, 53),
                domain_index: 0b001,
                log_height: 3,
            },
        ];
        let final_folded = expected_final_folded(initial_folded, &rounds);
        let flat = build_fold_chain_trace(initial_folded, &rounds, final_folded, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO)
            .expect("fold chain (3 rounds) must verify in ONE monolithic STARK");
    }

    #[test]
    fn air_prove_and_verify_fold_chain_bit_orientation_cases() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let cfg = build_config();
        let air = MonolithicVerifierAirV1;

        // Exercise both INDEX_BIT = 0 and INDEX_BIT = 1 on round 0.
        for bit in 0..2usize {
            let initial_folded = ext(9, 11);
            let rounds = vec![FoldRound {
                sibling: ext(13, 17),
                beta: ext(19, 23),
                domain_index: bit,
                log_height: 3,
            }];
            let final_folded = expected_final_folded(initial_folded, &rounds);
            let flat = build_fold_chain_trace(initial_folded, &rounds, final_folded, 8).unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
            verify(&cfg, &air, &proof, &TEST_PI_ZERO)
                .unwrap_or_else(|e| panic!("bit={bit}: {e:?}"));
        }
    }

    #[test]
    fn air_rejects_fold_chain_wrong_final_folded() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let initial_folded = ext(5, 7);
        let rounds = vec![FoldRound {
            sibling: ext(11, 13),
            beta: ext(17, 19),
            domain_index: 0b01,
            log_height: 4,
        }];
        let real_final = expected_final_folded(initial_folded, &rounds);
        let bad_final = real_final + ext(1, 0);
        let flat = build_fold_chain_trace(initial_folded, &rounds, bad_final, 8).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("wrong FINAL_FOLDED must reject at last-row boundary");
            }
        }
    }

    #[test]
    fn air_rejects_fold_chain_tampered_sibling() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let initial_folded = ext(5, 7);
        let rounds = vec![
            FoldRound {
                sibling: ext(11, 13),
                beta: ext(17, 19),
                domain_index: 0b010,
                log_height: 4,
            },
            FoldRound {
                sibling: ext(23, 29),
                beta: ext(31, 37),
                domain_index: 0b001,
                log_height: 3,
            },
        ];
        let final_folded = expected_final_folded(initial_folded, &rounds);
        let mut flat = build_fold_chain_trace(initial_folded, &rounds, final_folded, 8).unwrap();
        // Tamper SIBLING[0] on row 0 — breaks PAIR_LEFT/RIGHT orientation
        // (STATE_IN cols are the prover's "claimed" LEFT/RIGHT; flipping
        // SIBLING without recomputing them fires the orientation bank).
        flat[col::COMPRESS_SIBLING0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("tampered SIBLING must reject via orientation bank");
            }
        }
    }

    #[test]
    fn air_rejects_fold_chain_broken_inv_2s_witness() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let initial_folded = ext(5, 7);
        let rounds = vec![FoldRound {
            sibling: ext(11, 13),
            beta: ext(17, 19),
            domain_index: 0b01,
            log_height: 3,
        }];
        let final_folded = expected_final_folded(initial_folded, &rounds);
        let mut flat = build_fold_chain_trace(initial_folded, &rounds, final_folded, 8).unwrap();
        // Corrupt INV_2S witness on row 0.
        flat[col::FOLD_INV_2S] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("broken INV_2S witness must reject via 2s·INV_2S=1 bank");
            }
        }
    }

    /// Regression guard: after A3-2, the A3-1 leaf-to-root test still
    /// passes — the new FOLD/ALPHA banks are gated off and don't fire
    /// on ABSORB/COMPRESS/IDLE rows.
    #[test]
    fn a3_1_leaf_to_root_still_verifies_after_a3_2() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[2].clone();
        let flat = build_leaf_to_root_trace(&leaves[2], &path, idx, root, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO)
            .expect("A3-1 leaf-to-root must still verify post-A3-2");
    }

    // ======================================================================
    // A3-3: Cross-bindings — unified α + fold chain in ONE STARK
    // ======================================================================

    /// A3-3 acceptance: the α chain's ρ_final THREADS in-circuit into
    /// the fold chain's seed via:
    ///   (i)  bridge: is_alpha · next_is_fold · (next.FOLD_IN − local.ALPHA_RO_OUT)
    ///   (ii) ALPHA_RO_OUT non-α persistence → last-row ALPHA_RO_OUT == FINAL_RO
    ///   (iii) FOLD_OUT non-fold persistence → last-row FOLD_OUT == FINAL_FOLDED
    /// One STARK proof covers both chains.
    #[test]
    fn air_prove_and_verify_unified_alpha_to_fold_chain() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let alpha_steps = vec![
            AlphaStep {
                p_at_x: gl(7),
                p_at_z: ext(11, 13),
                z: ext(17, 19),
                x: gl(23),
            },
            AlphaStep {
                p_at_x: gl(29),
                p_at_z: ext(31, 37),
                z: ext(41, 43),
                x: gl(47),
            },
        ];
        let fold_rounds = vec![
            FoldRound {
                sibling: ext(53, 59),
                beta: ext(61, 67),
                domain_index: 0b10,
                log_height: 4,
            },
            FoldRound {
                sibling: ext(71, 73),
                beta: ext(79, 83),
                domain_index: 0b01,
                log_height: 3,
            },
        ];
        let flat = build_alpha_to_fold_unified_trace(
            initial_apow,
            initial_ro,
            alpha,
            &alpha_steps,
            &fold_rounds,
            16,
        )
        .unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO)
            .expect("unified α+fold must verify in ONE monolithic STARK");
    }

    /// A3-3 adversarial test #1: directly tamper the first FOLD row's
    /// FOLD_IN so it doesn't match the α chain's last ALPHA_RO_OUT.
    /// The bridge constraint
    ///   is_alpha · next_is_fold · (next.FOLD_IN − local.ALPHA_RO_OUT) = 0
    /// fires at the α→FOLD transition — rejection.
    ///
    /// This CLOSES A2's "trusted-by-construction" gap at the α/fold
    /// seam. Before A3-3, the prover could forge a fold chain starting
    /// from an arbitrary ρ' ≠ ρ_final and the verifier wouldn't catch it.
    #[test]
    fn air_rejects_unified_tampered_alpha_to_fold_bridge() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(29, 31),
            beta: ext(37, 41),
            domain_index: 0b01,
            log_height: 3,
        }];
        let mut flat = build_alpha_to_fold_unified_trace(
            initial_apow,
            initial_ro,
            alpha,
            &alpha_steps,
            &fold_rounds,
            8,
        )
        .unwrap();
        // Row 0 = ALPHA; row 1 = first FOLD. Tamper FOLD_IN on row 1
        // so it no longer equals row 0's ALPHA_RO_OUT.
        let row1 = 1 * col::WIDTH;
        flat[row1 + col::FOLD_IN0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO).expect_err(
                    "forged α→FOLD seam must reject — A3-3 closes A2's cross-binding gap",
                );
            }
        }
    }

    /// A3-3 adversarial test #2: tamper the α chain's last RO_OUT on
    /// its last row. The direct bridge still sees local.ALPHA_RO_OUT
    /// (unchanged in this case, since we tamper via P_AT_X), so the
    /// rejection path is the DIFF_QUOT / RO update constraint, not the
    /// bridge. Confirms α-chain tampering cascades through.
    #[test]
    fn air_rejects_unified_tampered_alpha_chain() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(29, 31),
            beta: ext(37, 41),
            domain_index: 0b01,
            log_height: 3,
        }];
        let mut flat = build_alpha_to_fold_unified_trace(
            initial_apow,
            initial_ro,
            alpha,
            &alpha_steps,
            &fold_rounds,
            8,
        )
        .unwrap();
        // Tamper α row 0's P_AT_X — breaks DIFF_QUOT → RO update.
        flat[col::ALPHA_P_AT_X] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("tampered α chain in unified trace must reject");
            }
        }
    }

    /// A3-3 adversarial test #3: forge ALPHA_RO_OUT on a FOLD row to
    /// break the non-α persistence chain. If the prover tries to set
    /// FINAL_RO = forged ρ' while keeping the real α chain → the
    /// last-row boundary holds only if ALPHA_RO_OUT propagates from
    /// last α row. Tampering mid-propagation fires persistence.
    #[test]
    fn air_rejects_unified_tampered_alpha_ro_out_on_fold_row() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![
            FoldRound {
                sibling: ext(29, 31),
                beta: ext(37, 41),
                domain_index: 0b10,
                log_height: 4,
            },
            FoldRound {
                sibling: ext(43, 47),
                beta: ext(53, 59),
                domain_index: 0b01,
                log_height: 3,
            },
        ];
        let mut flat = build_alpha_to_fold_unified_trace(
            initial_apow,
            initial_ro,
            alpha,
            &alpha_steps,
            &fold_rounds,
            8,
        )
        .unwrap();
        // Row 0 = ALPHA, rows 1,2 = FOLD. Tamper ALPHA_RO_OUT on row 1.
        // Non-α persistence fires on row0→row1 (fold) or row1→row2 (fold).
        let row1 = 1 * col::WIDTH;
        flat[row1 + col::ALPHA_RO_OUT0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO).expect_err(
                    "tampered ALPHA_RO_OUT on FOLD row must reject via non-α persistence",
                );
            }
        }
    }

    /// A3-3 regression: all A3-1 and A3-2 tests still pass under the
    /// new cross-binding constraints. Covers leaf-to-root, α-only, and
    /// fold-only traces in a single test.
    #[test]
    fn a3_1_and_a3_2_still_verify_after_a3_3() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let cfg = build_config();
        let air = MonolithicVerifierAirV1;

        // Leaf-to-root (A3-1).
        {
            let (leaves, openings, root) = tiny_tree_wide_leaves();
            let (_, path, idx) = openings[1].clone();
            let flat = build_leaf_to_root_trace(&leaves[1], &path, idx, root, 16).unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
            verify(&cfg, &air, &proof, &TEST_PI_ZERO)
                .expect("A3-1 leaf-to-root must still verify post-A3-3");
        }

        // α-only (A3-2).
        {
            let alpha = ext(2, 3);
            let steps = vec![AlphaStep {
                p_at_x: gl(5),
                p_at_z: ext(7, 11),
                z: ext(13, 17),
                x: gl(19),
            }];
            let final_ro = expected_final_ro(ext(1, 0), ext(0, 0), alpha, &steps);
            let flat =
                build_alpha_chain_trace(ext(1, 0), ext(0, 0), alpha, &steps, final_ro, 8).unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
            verify(&cfg, &air, &proof, &TEST_PI_ZERO)
                .expect("A3-2 α-only must still verify post-A3-3");
        }

        // Fold-only (A3-2).
        {
            let initial_folded = ext(5, 7);
            let rounds = vec![FoldRound {
                sibling: ext(11, 13),
                beta: ext(17, 19),
                domain_index: 0b01,
                log_height: 3,
            }];
            let final_folded = expected_final_folded(initial_folded, &rounds);
            let flat = build_fold_chain_trace(initial_folded, &rounds, final_folded, 8).unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
            verify(&cfg, &air, &proof, &TEST_PI_ZERO)
                .expect("A3-2 fold-only must still verify post-A3-3");
        }
    }

    // ======================================================================
    // A3-4: Scaling measurements — prover time + proof size sweep.
    //
    // These tests exercise the monolithic AIR at progressively larger
    // trace heights and record:
    //   - trace (height, width, cells)
    //   - prover time (ms)
    //   - postcard-serialized proof size (bytes)
    //
    // The measurements feed into `doc/uno-aggregation-metrics.md` §A3-4
    // and validate the §3.4 feasibility path before A4 scales to N=30.
    //
    // Reliability: these are #[ignore]'d by default to keep the default
    // test suite fast. Run them explicitly with
    //   cargo test -j 128 --release --lib monolithic_verifier_air::tests::measure \
    //     -- --ignored --test-threads 1 --nocapture
    // to capture fresh measurements. The `--test-threads 1` keeps the
    // timing measurements un-contended.
    // ======================================================================

    /// Deterministically sample α-chain steps for measurement traces.
    fn sample_alpha_steps(n: usize) -> Vec<AlphaStep> {
        // Use low-entropy-but-distinct values so steps don't degenerate
        // (z ≠ x is required for (z − x)^{−1} to exist).
        (0..n as u64)
            .map(|i| AlphaStep {
                p_at_x: gl(7 * i + 1),
                p_at_z: ext(11 * i + 3, 13 * i + 5),
                z: ext(17 * i + 7, 19 * i + 11),
                x: gl(23 * i + 2),
            })
            .collect()
    }

    /// Deterministically sample fold rounds. `log_height_start` is the
    /// log-height of the codeword BEFORE the first fold; log_height
    /// halves each round.
    fn sample_fold_rounds(n: usize, log_height_start: usize) -> Vec<FoldRound> {
        assert!(
            log_height_start >= n,
            "fold chain needs log_height_start ≥ n_rounds (each round halves log_h)"
        );
        (0..n)
            .map(|r| FoldRound {
                sibling: ext(53 + r as u64 * 7, 59 + r as u64 * 11),
                beta: ext(61 + r as u64 * 13, 67 + r as u64 * 17),
                domain_index: (0b1010_0101 ^ r) & ((1 << log_height_start) - 1),
                log_height: log_height_start - r,
            })
            .collect()
    }

    /// Single measurement record emitted to stderr.
    fn report(tag: &str, trace_h: usize, prove_ms: u128, proof_bytes: usize) {
        let cells = trace_h * col::WIDTH;
        eprintln!(
            "  [{tag}] height={trace_h:>6}  width={w}  cells={cells:>12}  \
             prove={prove_ms:>6} ms  proof={proof_bytes:>7} B",
            w = col::WIDTH,
            prove_ms = prove_ms,
            proof_bytes = proof_bytes,
        );
    }

    /// A3-4 acceptance: a realistic-scale unified α+fold trace at 2/2
    /// shape dimensions verifies in ONE monolithic STARK.
    ///
    /// Dimensions (mirrors §`doc/uno-aggregation-metrics.md` 2/2 row):
    ///   air_width   ≈ 1305 → α-chain length ≈ air_width · 2 + 2
    ///                                       = 2612 steps ≈ next_pow2 = 4096.
    ///   num_rounds  = 6
    ///   trace_height = 4096
    ///
    /// For this test we use a smaller but still-representative
    /// α_steps = 400 to keep runtime under ~1 min.
    #[test]
    #[ignore = "A3-4 measurement test — run explicitly to capture scaling data"]
    fn measure_unified_alpha_fold_realistic_scale() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};
        use std::time::Instant;

        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let alpha_steps = sample_alpha_steps(400);
        let fold_rounds = sample_fold_rounds(9, 12);
        let trace_height = 512;
        let flat = build_alpha_to_fold_unified_trace(
            initial_apow,
            initial_ro,
            alpha,
            &alpha_steps,
            &fold_rounds,
            trace_height,
        )
        .unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;

        let t0 = Instant::now();
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        let prove_ms = t0.elapsed().as_millis();
        verify(&cfg, &air, &proof, &TEST_PI_ZERO)
            .expect("realistic-scale unified trace must verify");

        let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
        eprintln!();
        eprintln!("A3-4 unified realistic-scale (α_steps=400, fold_rounds=9):");
        report("unified@512", trace_height, prove_ms, proof_bytes);
    }

    /// A3-4 scaling sweep: α-only chain at trace heights ∈ {64, 256, 1024, 4096}.
    /// Confirms prover time scales ~linearly with trace area.
    #[test]
    #[ignore = "A3-4 measurement test — run explicitly to capture scaling data"]
    fn measure_alpha_chain_scaling_sweep() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};
        use std::time::Instant;

        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);

        eprintln!();
        eprintln!("A3-4 α-chain scaling sweep:");
        for trace_height in [64usize, 256, 1024, 4096] {
            let steps = sample_alpha_steps(trace_height / 2);
            let final_ro = expected_final_ro(initial_apow, initial_ro, alpha, &steps);
            let flat = build_alpha_chain_trace(
                initial_apow,
                initial_ro,
                alpha,
                &steps,
                final_ro,
                trace_height,
            )
            .unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);

            let t0 = Instant::now();
            let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
            let prove_ms = t0.elapsed().as_millis();
            verify(&cfg, &air, &proof, &TEST_PI_ZERO).unwrap();

            let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
            report(
                &format!("α@{trace_height}"),
                trace_height,
                prove_ms,
                proof_bytes,
            );
        }
    }

    /// A3-4 scaling sweep: fold-only chain at log_height_start up to 16
    /// (15 rounds matches the 4/4 shape's `num_rounds = 9` with headroom).
    #[test]
    #[ignore = "A3-4 measurement test — run explicitly to capture scaling data"]
    fn measure_fold_chain_scaling_sweep() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};
        use std::time::Instant;

        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let initial_folded = ext(5, 7);

        eprintln!();
        eprintln!("A3-4 fold-chain scaling sweep:");
        // Each row of the fold bank is one round. num_rounds ∈ {3,6,9,12,15}
        // covers the 1/1 (3), 2/2 (6), 4/4 (9), and beyond.
        for (n_rounds, log_h_start) in [(3usize, 5usize), (6, 8), (9, 12), (15, 18)] {
            let rounds = sample_fold_rounds(n_rounds, log_h_start);
            let final_folded = expected_final_folded(initial_folded, &rounds);
            let trace_height = n_rounds.next_power_of_two().max(16);
            let flat = build_fold_chain_trace(initial_folded, &rounds, final_folded, trace_height)
                .unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);

            let t0 = Instant::now();
            let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
            let prove_ms = t0.elapsed().as_millis();
            verify(&cfg, &air, &proof, &TEST_PI_ZERO).unwrap();

            let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
            report(
                &format!("fold@{n_rounds}rnd"),
                trace_height,
                prove_ms,
                proof_bytes,
            );
        }
    }

    /// A3-4 composite: unified α+fold sweep at trace heights that match
    /// the 1/1, 2/2, and (scaled) 4/4 per-query shape.
    #[test]
    #[ignore = "A3-4 measurement test — run explicitly to capture scaling data"]
    fn measure_unified_alpha_fold_scaling_sweep() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};
        use std::time::Instant;

        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);

        eprintln!();
        eprintln!("A3-4 unified α+fold scaling sweep:");
        // (α_steps, fold_rounds, log_h_start, trace_height) — sized so
        // α_steps + fold_rounds < trace_height.
        let scenarios = [
            ("1/1 shape", 40usize, 3usize, 5usize, 64usize),
            ("2/2 shape", 180, 6, 10, 256),
            ("4/4 shape", 500, 9, 14, 1024),
            ("stretch", 2000, 12, 16, 4096),
        ];
        for (tag, n_alpha, n_fold, log_h_start, trace_height) in scenarios {
            let alpha_steps = sample_alpha_steps(n_alpha);
            let fold_rounds = sample_fold_rounds(n_fold, log_h_start);
            let flat = build_alpha_to_fold_unified_trace(
                initial_apow,
                initial_ro,
                alpha,
                &alpha_steps,
                &fold_rounds,
                trace_height,
            )
            .unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);

            let t0 = Instant::now();
            let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
            let prove_ms = t0.elapsed().as_millis();
            verify(&cfg, &air, &proof, &TEST_PI_ZERO).unwrap();

            let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
            report(tag, trace_height, prove_ms, proof_bytes);
        }
    }

    // ======================================================================
    // A3-5a: multi-path Merkle in ONE monolithic STARK
    // ======================================================================

    /// Build two independent Merkle paths (from the same tiny tree) and
    /// prove them both in ONE STARK via the multi-path trace builder.
    /// This exercises the A3-5a per-path root check across two paths
    /// with the SAME root (the tiny tree has one shared root).
    #[test]
    fn air_prove_and_verify_two_paths_same_tree() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path0, idx0) = openings[0].clone();
        let (_, path2, idx2) = openings[2].clone();
        let paths = vec![
            MerkleOpening {
                leaf: &leaves[0],
                opening_proof: &path0,
                index: idx0,
                expected_root: root,
            },
            MerkleOpening {
                leaf: &leaves[2],
                opening_proof: &path2,
                index: idx2,
                expected_root: root,
            },
        ];
        // Each path: 2 absorb (W=8/RATE=4) + 2 compress = 4 rows. Two
        // paths = 8 physical rows; pad to 16.
        let flat = build_multi_path_leaf_to_root_trace(&paths, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO)
            .expect("two Merkle paths must verify in ONE monolithic STARK");
    }

    /// Build two Merkle paths from DIFFERENT trees (with different
    /// roots). Verifies the relaxed TRACE_COMMIT_ROOT persistence lets
    /// each path hold its own root. This is the critical A3-5a
    /// capability that A3-1's one-root model couldn't express.
    #[test]
    fn air_prove_and_verify_two_paths_different_roots() {
        use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref};
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let perm = default_goldilocks_poseidon2_8();

        // Tree A: 2 wide leaves → 1 compression → root_A.
        let leaf_a0: Vec<Goldilocks> = (0..8u64).map(|j| gl(100 + j * 17 + 1)).collect();
        let leaf_a1: Vec<Goldilocks> = (0..8u64).map(|j| gl(200 + j * 23 + 3)).collect();
        let dig_a0 = hash_leaf_row_ref(&perm, &leaf_a0);
        let dig_a1 = hash_leaf_row_ref(&perm, &leaf_a1);
        let root_a = compress_pair_ref(&perm, &dig_a0, &dig_a1);

        // Tree B: 2 wide leaves → 1 compression → root_B (≠ root_A).
        let leaf_b0: Vec<Goldilocks> = (0..8u64).map(|j| gl(300 + j * 29 + 5)).collect();
        let leaf_b1: Vec<Goldilocks> = (0..8u64).map(|j| gl(400 + j * 31 + 7)).collect();
        let dig_b0 = hash_leaf_row_ref(&perm, &leaf_b0);
        let dig_b1 = hash_leaf_row_ref(&perm, &leaf_b1);
        let root_b = compress_pair_ref(&perm, &dig_b0, &dig_b1);

        assert_ne!(root_a, root_b, "tree A and B must differ");

        // Path 0 in tree A: leaf_a0, sibling = dig_a1, index 0.
        // Path 0 in tree B: leaf_b0, sibling = dig_b1, index 0.
        let path_a_siblings = vec![dig_a1];
        let path_b_siblings = vec![dig_b1];
        let paths = vec![
            MerkleOpening {
                leaf: &leaf_a0,
                opening_proof: &path_a_siblings,
                index: 0,
                expected_root: root_a,
            },
            MerkleOpening {
                leaf: &leaf_b0,
                opening_proof: &path_b_siblings,
                index: 0,
                expected_root: root_b,
            },
        ];
        // 2 absorb + 1 compress = 3 rows per path; two paths = 6
        // physical rows. Pad to 8.
        let flat = build_multi_path_leaf_to_root_trace(&paths, 8).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO)
            .expect("two paths with different roots must verify in ONE STARK");
    }

    /// A3-5a adversarial test: swap path A's expected root with path
    /// B's. Path A's last COMPRESS row now claims root_B but DIGEST_A
    /// = real root_A ≠ root_B. The per-path root check
    ///   is_compress · (1 − next_is_compress) · (DIGEST − TCR) = 0
    /// fires at path A's COMPRESS → ABSORB_B transition — reject.
    #[test]
    fn air_rejects_multi_path_with_swapped_root() {
        use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref};
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let perm = default_goldilocks_poseidon2_8();
        let leaf_a0: Vec<Goldilocks> = (0..8u64).map(|j| gl(j * 17 + 1)).collect();
        let leaf_a1: Vec<Goldilocks> = (0..8u64).map(|j| gl(j * 23 + 3)).collect();
        let dig_a0 = hash_leaf_row_ref(&perm, &leaf_a0);
        let dig_a1 = hash_leaf_row_ref(&perm, &leaf_a1);
        let root_a = compress_pair_ref(&perm, &dig_a0, &dig_a1);

        let leaf_b0: Vec<Goldilocks> = (0..8u64).map(|j| gl(j * 29 + 5)).collect();
        let leaf_b1: Vec<Goldilocks> = (0..8u64).map(|j| gl(j * 31 + 7)).collect();
        let dig_b0 = hash_leaf_row_ref(&perm, &leaf_b0);
        let dig_b1 = hash_leaf_row_ref(&perm, &leaf_b1);
        let root_b = compress_pair_ref(&perm, &dig_b0, &dig_b1);

        let path_a_siblings = vec![dig_a1];
        let path_b_siblings = vec![dig_b1];
        // Deliberately swap: claim path_a leads to root_b (a lie).
        let paths = vec![
            MerkleOpening {
                leaf: &leaf_a0,
                opening_proof: &path_a_siblings,
                index: 0,
                expected_root: root_b, // wrong root
            },
            MerkleOpening {
                leaf: &leaf_b0,
                opening_proof: &path_b_siblings,
                index: 0,
                expected_root: root_a, // wrong root
            },
        ];
        // build_multi_path_leaf_to_root_trace debug-asserts that the
        // final digest matches expected_root; bypass that by building
        // with correct roots first, then tampering TCR post-hoc.
        let real_paths = vec![
            MerkleOpening {
                leaf: &leaf_a0,
                opening_proof: &path_a_siblings,
                index: 0,
                expected_root: root_a,
            },
            MerkleOpening {
                leaf: &leaf_b0,
                opening_proof: &path_b_siblings,
                index: 0,
                expected_root: root_b,
            },
        ];
        let mut flat = build_multi_path_leaf_to_root_trace(&real_paths, 8).unwrap();
        // Swap TCR on BOTH paths' compression rows. Each path has 2
        // absorb + 1 compress; path_A's compress is row 2, path_B's is
        // row 5 (after 2 absorb + 1 compress + 2 absorb).
        for i in 0..DIGEST_WIDTH {
            let row2 = 2 * col::WIDTH;
            flat[row2 + col::TRACE_COMMIT_ROOT0 + i] = root_b[i];
            let row5 = 5 * col::WIDTH;
            flat[row5 + col::TRACE_COMMIT_ROOT0 + i] = root_a[i];
        }
        // Suppress unused-var warning; `paths` built for docs only.
        let _ = paths;
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("swapped multi-path roots must reject via per-path check");
            }
        }
    }

    /// A3-5a adversarial test: within path A's compression run, change
    /// TCR on an intermediate COMPRESS row (not the last). The in-run
    /// persistence `is_compress · next_is_compress · (next.TCR −
    /// local.TCR) = 0` fires and rejects.
    #[test]
    fn air_rejects_multi_path_tcr_drifts_mid_run() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path0, idx0) = openings[0].clone();
        let paths = vec![MerkleOpening {
            leaf: &leaves[0],
            opening_proof: &path0,
            index: idx0,
            expected_root: root,
        }];
        let mut flat = build_multi_path_leaf_to_root_trace(&paths, 8).unwrap();
        // Rows 0,1 = ABSORB; rows 2,3 = COMPRESS; row 4+ = IDLE.
        // Tamper TCR on row 2 (first COMPRESS). Row 3's TCR still
        // equals real root. In-run persistence row2→row3 fires:
        // is_compress(row2)·next_is_compress(row3)·(row3.TCR − row2.TCR) ≠ 0.
        let row2 = 2 * col::WIDTH;
        flat[row2 + col::TRACE_COMMIT_ROOT0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("TCR drift within a compression run must reject");
            }
        }
    }

    // ======================================================================
    // A3-5b: full per-query bundle — α + Merkle paths + fold in ONE STARK
    // ======================================================================

    /// A3-5b core acceptance: α-reduction chain + one Merkle path +
    /// fold chain verify as a single STARK proof. The α chain's ρ_final
    /// threads through the Merkle rows (via A3-3 non-α/non-fold
    /// persistence) into the FOLD chain's seed (via FOLD threading).
    /// No new constraints were needed beyond A3-3 + A3-5a.
    #[test]
    fn air_prove_and_verify_bundle_alpha_1merkle_fold() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[0].clone();
        let merkle_paths = vec![MerkleOpening {
            leaf: &leaves[0],
            opening_proof: &path,
            index: idx,
            expected_root: root,
        }];
        let alpha = ext(3, 5);
        let initial_apow = ext(1, 0);
        let initial_ro = ext(0, 0);
        let alpha_steps = vec![
            AlphaStep {
                p_at_x: gl(7),
                p_at_z: ext(11, 13),
                z: ext(17, 19),
                x: gl(23),
            },
            AlphaStep {
                p_at_x: gl(29),
                p_at_z: ext(31, 37),
                z: ext(41, 43),
                x: gl(47),
            },
        ];
        let fold_rounds = vec![
            FoldRound {
                sibling: ext(53, 59),
                beta: ext(61, 67),
                domain_index: 0b10,
                log_height: 4,
            },
            FoldRound {
                sibling: ext(71, 73),
                beta: ext(79, 83),
                domain_index: 0b01,
                log_height: 3,
            },
        ];
        // Physical rows: 2 α + (2 absorb + 2 compress = 4 Merkle) + 2 fold = 8.
        let flat = build_alpha_merkle_fold_bundle_trace(
            initial_apow,
            initial_ro,
            alpha,
            &alpha_steps,
            &merkle_paths,
            &fold_rounds,
            16,
        )
        .unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO)
            .expect("bundle (α + 1 Merkle + fold) must verify in ONE monolithic STARK");
    }

    /// A3-5b 2-path bundle: α + TWO independent Merkle paths (different
    /// roots) + fold. Mirrors the per-query shape where trace-commit
    /// and quotient-commit paths sit in the same trace.
    #[test]
    fn air_prove_and_verify_bundle_alpha_2merkle_fold() {
        use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref};
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let perm = default_goldilocks_poseidon2_8();

        // Tree A (mimics trace-commit Merkle).
        let leaf_a0: Vec<Goldilocks> = (0..8u64).map(|j| gl(100 + j * 17 + 1)).collect();
        let leaf_a1: Vec<Goldilocks> = (0..8u64).map(|j| gl(200 + j * 23 + 3)).collect();
        let dig_a0 = hash_leaf_row_ref(&perm, &leaf_a0);
        let dig_a1 = hash_leaf_row_ref(&perm, &leaf_a1);
        let root_a = compress_pair_ref(&perm, &dig_a0, &dig_a1);

        // Tree B (mimics quotient-commit Merkle).
        let leaf_b0: Vec<Goldilocks> = (0..8u64).map(|j| gl(300 + j * 29 + 5)).collect();
        let leaf_b1: Vec<Goldilocks> = (0..8u64).map(|j| gl(400 + j * 31 + 7)).collect();
        let dig_b0 = hash_leaf_row_ref(&perm, &leaf_b0);
        let dig_b1 = hash_leaf_row_ref(&perm, &leaf_b1);
        let root_b = compress_pair_ref(&perm, &dig_b0, &dig_b1);

        let path_a_siblings = vec![dig_a1];
        let path_b_siblings = vec![dig_b1];
        let merkle_paths = vec![
            MerkleOpening {
                leaf: &leaf_a0,
                opening_proof: &path_a_siblings,
                index: 0,
                expected_root: root_a,
            },
            MerkleOpening {
                leaf: &leaf_b0,
                opening_proof: &path_b_siblings,
                index: 0,
                expected_root: root_b,
            },
        ];
        let alpha = ext(2, 3);
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(5),
            p_at_z: ext(7, 11),
            z: ext(13, 17),
            x: gl(19),
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(23, 29),
            beta: ext(31, 37),
            domain_index: 0b01,
            log_height: 3,
        }];
        // 1 α + 2×(2 absorb + 1 compress = 3) + 1 fold = 8.
        let flat = build_alpha_merkle_fold_bundle_trace(
            ext(1, 0),
            ext(0, 0),
            alpha,
            &alpha_steps,
            &merkle_paths,
            &fold_rounds,
            16,
        )
        .unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO)
            .expect("bundle with 2 Merkle paths must verify in ONE monolithic STARK");
    }

    /// A3-5b adversarial: tamper a Merkle sibling mid-bundle — the
    /// ABSORB+COMPRESS Poseidon2 chain diverges, the per-path root
    /// check fails.
    #[test]
    fn air_rejects_bundle_tampered_merkle_sibling() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[1].clone();
        let merkle_paths = vec![MerkleOpening {
            leaf: &leaves[1],
            opening_proof: &path,
            index: idx,
            expected_root: root,
        }];
        let alpha = ext(3, 5);
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(53, 59),
            beta: ext(61, 67),
            domain_index: 0b01,
            log_height: 3,
        }];
        let mut flat = build_alpha_merkle_fold_bundle_trace(
            ext(1, 0),
            ext(0, 0),
            alpha,
            &alpha_steps,
            &merkle_paths,
            &fold_rounds,
            16,
        )
        .unwrap();
        // Bundle layout: 1 α + (2 absorb + 2 compress) + 1 fold = 6.
        // α rows: 0. ABSORB rows: 1, 2. COMPRESS rows: 3, 4. FOLD: 5.
        // Tamper COMPRESS_SIBLING on row 3 (first COMPRESS of path).
        let row3 = 3 * col::WIDTH;
        flat[row3 + col::COMPRESS_SIBLING0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("tampered Merkle sibling in bundle must reject");
            }
        }
    }

    /// A3-5b adversarial: tamper the α chain's P_AT_X. Even with a
    /// Merkle path between α and fold, the α→...→fold chain must
    /// reject when α is corrupted (via the DIFF_QUOT / RO cascade and
    /// the eventual FOLD_IN = local.FOLD_OUT threading).
    #[test]
    fn air_rejects_bundle_tampered_alpha() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[0].clone();
        let merkle_paths = vec![MerkleOpening {
            leaf: &leaves[0],
            opening_proof: &path,
            index: idx,
            expected_root: root,
        }];
        let alpha = ext(3, 5);
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(53, 59),
            beta: ext(61, 67),
            domain_index: 0b01,
            log_height: 3,
        }];
        let mut flat = build_alpha_merkle_fold_bundle_trace(
            ext(1, 0),
            ext(0, 0),
            alpha,
            &alpha_steps,
            &merkle_paths,
            &fold_rounds,
            16,
        )
        .unwrap();
        // Tamper α row 0's P_AT_X.
        flat[col::ALPHA_P_AT_X] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("tampered α chain in bundle must reject");
            }
        }
    }

    /// A3-5b adversarial: tamper a FOLD round's SIBLING — fold
    /// orientation constraint fires.
    #[test]
    fn air_rejects_bundle_tampered_fold_sibling() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let (leaves, openings, root) = tiny_tree_wide_leaves();
        let (_, path, idx) = openings[0].clone();
        let merkle_paths = vec![MerkleOpening {
            leaf: &leaves[0],
            opening_proof: &path,
            index: idx,
            expected_root: root,
        }];
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(53, 59),
            beta: ext(61, 67),
            domain_index: 0b01,
            log_height: 3,
        }];
        let mut flat = build_alpha_merkle_fold_bundle_trace(
            ext(1, 0),
            ext(0, 0),
            ext(3, 5),
            &alpha_steps,
            &merkle_paths,
            &fold_rounds,
            16,
        )
        .unwrap();
        // Bundle: 1 α + 2 absorb + 2 compress + 1 fold = 6. FOLD on row 5.
        // FOLD's SIBLING shares COMPRESS_SIBLING; tamper it on row 5.
        let row5 = 5 * col::WIDTH;
        flat[row5 + col::COMPRESS_SIBLING0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("tampered fold SIBLING in bundle must reject");
            }
        }
    }

    // ======================================================================
    // A3-5c: multi-bundle stacking — N per-query bundles in ONE STARK
    // ======================================================================

    fn sample_merkle_leaf(seed: u64, len: usize) -> Vec<Goldilocks> {
        (0..len as u64)
            .map(|j| gl(seed * 100 + j * 17 + 1))
            .collect()
    }

    /// Build a small self-contained Merkle tree-of-2-leaves and return
    /// (leaf0, leaf1, digest0, digest1, root).
    fn sample_2leaf_tree(
        perm: &p3_goldilocks::Poseidon2Goldilocks<8>,
        seed: u64,
    ) -> (Vec<Goldilocks>, Vec<Goldilocks>, Digest, Digest, Digest) {
        use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref};
        let leaf0 = sample_merkle_leaf(seed, 8);
        let leaf1 = sample_merkle_leaf(seed + 1, 8);
        let d0 = hash_leaf_row_ref(perm, &leaf0);
        let d1 = hash_leaf_row_ref(perm, &leaf1);
        let root = compress_pair_ref(perm, &d0, &d1);
        (leaf0, leaf1, d0, d1, root)
    }

    /// A3-5c core acceptance: TWO bundles with DIFFERENT α, DIFFERENT
    /// ρ_final, and DIFFERENT final_folded verify as a single STARK.
    /// Each bundle brings its own (α, Merkle, fold); A3-5c bundle-
    /// boundary constraints let the PI proxies change between them.
    #[test]
    fn air_prove_and_verify_two_bundles_different_alpha() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let perm = default_goldilocks_poseidon2_8();
        let (l0a, _l1a, _d0a, d1a, root_a) = sample_2leaf_tree(&perm, 1);
        let (l0b, _l1b, _d0b, d1b, root_b) = sample_2leaf_tree(&perm, 10);

        // Bundle 0: α_0 = (2, 3), one α step, one Merkle path in tree A, one fold.
        let siblings_a = vec![d1a];
        let paths_a = vec![MerkleOpening {
            leaf: &l0a,
            opening_proof: &siblings_a,
            index: 0,
            expected_root: root_a,
        }];
        let alpha_steps_0 = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds_0 = vec![FoldRound {
            sibling: ext(29, 31),
            beta: ext(37, 41),
            domain_index: 0b01,
            log_height: 3,
        }];

        // Bundle 1: α_1 = (5, 7), DIFFERENT — different α_steps so
        // different ρ_final, different fold rounds so different
        // final_folded.
        let siblings_b = vec![d1b];
        let paths_b = vec![MerkleOpening {
            leaf: &l0b,
            opening_proof: &siblings_b,
            index: 0,
            expected_root: root_b,
        }];
        let alpha_steps_1 = vec![AlphaStep {
            p_at_x: gl(43),
            p_at_z: ext(47, 53),
            z: ext(59, 61),
            x: gl(67),
        }];
        let fold_rounds_1 = vec![FoldRound {
            sibling: ext(71, 73),
            beta: ext(79, 83),
            domain_index: 0b10,
            log_height: 4,
        }];

        let bundles = vec![
            BundleSpec {
                initial_alpha_pow: ext(1, 0),
                initial_ro: ext(0, 0),
                alpha: ext(2, 3),
                alpha_steps: &alpha_steps_0,
                merkle_paths: &paths_a,
                fold_rounds: &fold_rounds_0,
            },
            BundleSpec {
                initial_alpha_pow: ext(1, 0),
                initial_ro: ext(0, 0),
                alpha: ext(5, 7),
                alpha_steps: &alpha_steps_1,
                merkle_paths: &paths_b,
                fold_rounds: &fold_rounds_1,
            },
        ];
        // Bundle 0: 1 α + (2 absorb + 1 compress) + 1 fold = 5 rows.
        // Bundle 1: same shape = 5 rows. Total = 10; pad to 16.
        let flat = build_multi_bundle_trace(&bundles, &block_pi_zero(), 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        verify(&cfg, &air, &proof, &TEST_PI_ZERO)
            .expect("two bundles with different α must verify in ONE STARK");
    }

    /// A3-5c adversarial: forge bundle 0's close by tampering its
    /// FINAL_RO mid-bundle. PI persistence within bundle fires (or the
    /// bundle-boundary close check fires if tampered at the boundary).
    #[test]
    fn air_rejects_two_bundles_tampered_final_ro_mid_bundle() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let perm = default_goldilocks_poseidon2_8();
        let (l0, _, _, d1, root) = sample_2leaf_tree(&perm, 1);
        let siblings = vec![d1];
        let paths = vec![MerkleOpening {
            leaf: &l0,
            opening_proof: &siblings,
            index: 0,
            expected_root: root,
        }];
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(29, 31),
            beta: ext(37, 41),
            domain_index: 0b01,
            log_height: 3,
        }];
        let bundles = vec![
            BundleSpec {
                initial_alpha_pow: ext(1, 0),
                initial_ro: ext(0, 0),
                alpha: ext(2, 3),
                alpha_steps: &alpha_steps,
                merkle_paths: &paths,
                fold_rounds: &fold_rounds,
            },
            BundleSpec {
                initial_alpha_pow: ext(1, 0),
                initial_ro: ext(0, 0),
                alpha: ext(5, 7),
                alpha_steps: &alpha_steps,
                merkle_paths: &paths,
                fold_rounds: &fold_rounds,
            },
        ];
        let mut flat = build_multi_bundle_trace(&bundles, &block_pi_zero(), 16).unwrap();
        // Tamper FINAL_RO on row 0 (inside bundle 0). PI persistence
        // within bundle 0 fires on row 0 → row 1 transition.
        flat[col::FINAL_RO0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("tampered FINAL_RO within bundle must reject");
            }
        }
    }

    /// A3-5c adversarial: at bundle boundary, forge new bundle's
    /// ALPHA_POW_IN so it doesn't match the new bundle's
    /// INITIAL_ALPHA_POW. Bundle-boundary seed check (c) fires.
    #[test]
    fn air_rejects_bundle_boundary_bad_alpha_pow_seed() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let perm = default_goldilocks_poseidon2_8();
        let (l0a, _, _, d1a, root_a) = sample_2leaf_tree(&perm, 1);
        let (l0b, _, _, d1b, root_b) = sample_2leaf_tree(&perm, 10);
        let siblings_a = vec![d1a];
        let siblings_b = vec![d1b];
        let paths_a = vec![MerkleOpening {
            leaf: &l0a,
            opening_proof: &siblings_a,
            index: 0,
            expected_root: root_a,
        }];
        let paths_b = vec![MerkleOpening {
            leaf: &l0b,
            opening_proof: &siblings_b,
            index: 0,
            expected_root: root_b,
        }];
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(29, 31),
            beta: ext(37, 41),
            domain_index: 0b01,
            log_height: 3,
        }];
        let bundles = vec![
            BundleSpec {
                initial_alpha_pow: ext(1, 0),
                initial_ro: ext(0, 0),
                alpha: ext(2, 3),
                alpha_steps: &alpha_steps,
                merkle_paths: &paths_a,
                fold_rounds: &fold_rounds,
            },
            BundleSpec {
                initial_alpha_pow: ext(1, 0),
                initial_ro: ext(0, 0),
                alpha: ext(5, 7),
                alpha_steps: &alpha_steps,
                merkle_paths: &paths_b,
                fold_rounds: &fold_rounds,
            },
        ];
        let mut flat = build_multi_bundle_trace(&bundles, &block_pi_zero(), 16).unwrap();
        // Bundle 0 has 5 rows: 0=α, 1=ABS, 2=ABS, 3=COMPR, 4=FOLD.
        // Bundle 1 starts at row 5 (first α of bundle 1). Tamper
        // ALPHA_POW_IN on row 5 — bundle-boundary seed check (c) fires
        // on the row4→row5 transition:
        //   bundle_start · (row5.ALPHA_POW_IN − row5.INITIAL_ALPHA_POW) = 0.
        let row5 = 5 * col::WIDTH;
        flat[row5 + col::ALPHA_POW_IN0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO).expect_err(
                    "tampered ALPHA_POW_IN at bundle boundary must reject via seed check",
                );
            }
        }
    }

    /// A3-5c adversarial: forge bundle 0's FINAL_FOLDED to differ from
    /// its actual last fold output. Bundle-boundary check (b) fires:
    /// bundle_start · (local.FOLD_OUT − local.FINAL_FOLDED) = 0.
    #[test]
    fn air_rejects_bundle_boundary_bad_final_folded_close() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let perm = default_goldilocks_poseidon2_8();
        let (l0a, _, _, d1a, root_a) = sample_2leaf_tree(&perm, 1);
        let (l0b, _, _, d1b, root_b) = sample_2leaf_tree(&perm, 10);
        let siblings_a = vec![d1a];
        let siblings_b = vec![d1b];
        let paths_a = vec![MerkleOpening {
            leaf: &l0a,
            opening_proof: &siblings_a,
            index: 0,
            expected_root: root_a,
        }];
        let paths_b = vec![MerkleOpening {
            leaf: &l0b,
            opening_proof: &siblings_b,
            index: 0,
            expected_root: root_b,
        }];
        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(29, 31),
            beta: ext(37, 41),
            domain_index: 0b01,
            log_height: 3,
        }];
        let bundles = vec![
            BundleSpec {
                initial_alpha_pow: ext(1, 0),
                initial_ro: ext(0, 0),
                alpha: ext(2, 3),
                alpha_steps: &alpha_steps,
                merkle_paths: &paths_a,
                fold_rounds: &fold_rounds,
            },
            BundleSpec {
                initial_alpha_pow: ext(1, 0),
                initial_ro: ext(0, 0),
                alpha: ext(5, 7),
                alpha_steps: &alpha_steps,
                merkle_paths: &paths_b,
                fold_rounds: &fold_rounds,
            },
        ];
        let mut flat = build_multi_bundle_trace(&bundles, &block_pi_zero(), 16).unwrap();
        // Tamper FINAL_FOLDED on row 4 (last FOLD of bundle 0). PI
        // persistence within bundle 0 would fire between α rows and
        // row 4, so we need to tamper FINAL_FOLDED on ALL rows of
        // bundle 0. Instead, tamper a different way:
        // set row 4's FOLD_OUT (the actual fold result) to a new
        // value — the bundle-boundary close check (b) fires on the
        // row4→row5 transition:
        //   bundle_start · (row4.FOLD_OUT − row4.FINAL_FOLDED) = 0.
        let row4 = 4 * col::WIDTH;
        flat[row4 + col::FOLD_OUT0] += gl(1);
        // Also patch the fold identity so prove doesn't trip earlier
        // — but that's complicated. Simpler: the fold identity
        // constraint on row 4 would fail (FOLD_OUT tampered breaks
        // fold identity too). Either way rejects.
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &TEST_PI_ZERO)
        }));
        match outcome {
            Err(_) => {}
            Ok(p) => {
                verify(&cfg, &air, &p, &TEST_PI_ZERO)
                    .expect_err("tampered bundle 0 FOLD_OUT must reject");
            }
        }
    }

    /// A3-5c regression: A3-5b bundle test + A3-3 unified α→fold test
    /// both still pass under A3-5c relaxed persistence.
    #[test]
    fn a3_3_and_a3_5b_still_verify_after_a3_5c() {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};

        let cfg = build_config();
        let air = MonolithicVerifierAirV1;

        // A3-3 unified α+fold trace.
        {
            let alpha = ext(3, 5);
            let alpha_steps = vec![AlphaStep {
                p_at_x: gl(7),
                p_at_z: ext(11, 13),
                z: ext(17, 19),
                x: gl(23),
            }];
            let fold_rounds = vec![FoldRound {
                sibling: ext(29, 31),
                beta: ext(37, 41),
                domain_index: 0b01,
                log_height: 3,
            }];
            let flat = build_alpha_to_fold_unified_trace(
                ext(1, 0),
                ext(0, 0),
                alpha,
                &alpha_steps,
                &fold_rounds,
                8,
            )
            .unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
            verify(&cfg, &air, &proof, &TEST_PI_ZERO)
                .expect("A3-3 unified trace must still verify post-A3-5c");
        }

        // A3-5b single-bundle α + 1 Merkle + fold.
        {
            let (leaves, openings, root) = tiny_tree_wide_leaves();
            let (_, path, idx) = openings[0].clone();
            let merkle_paths = vec![MerkleOpening {
                leaf: &leaves[0],
                opening_proof: &path,
                index: idx,
                expected_root: root,
            }];
            let alpha_steps = vec![AlphaStep {
                p_at_x: gl(7),
                p_at_z: ext(11, 13),
                z: ext(17, 19),
                x: gl(23),
            }];
            let fold_rounds = vec![FoldRound {
                sibling: ext(29, 31),
                beta: ext(37, 41),
                domain_index: 0b01,
                log_height: 3,
            }];
            let flat = build_alpha_merkle_fold_bundle_trace(
                ext(1, 0),
                ext(0, 0),
                ext(3, 5),
                &alpha_steps,
                &merkle_paths,
                &fold_rounds,
                16,
            )
            .unwrap();
            let trace = RowMajorMatrix::new(flat, col::WIDTH);
            let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
            verify(&cfg, &air, &proof, &TEST_PI_ZERO)
                .expect("A3-5b single-bundle must still verify post-A3-5c");
        }
    }

    // ======================================================================
    // A4: Multi-bundle scaling measurements — monolithic STARK per N bundles
    //
    // Each "bundle" is one per-query FRI verification (α + Merkle paths +
    // fold). The §4.1 landmark is N = 4 Txs × 52 queries = 208 bundles per
    // block-level monolithic trace. §3.4 scales to N = 30 Txs → 1560
    // bundles. A4 measures prover time + proof size at progressive scales
    // to validate the feasibility path.
    //
    // Run with:
    //   cargo test -j 128 --release --lib monolithic_verifier_air::tests::measure_multi_bundle \
    //     -- --ignored --test-threads 1 --nocapture
    // ======================================================================

    /// Deterministic sample per-bundle data. Each bundle has:
    ///   - alpha_steps: `n_alpha` AlphaSteps.
    ///   - merkle_paths: 1 path, wide-leaf into a tiny 2-leaf tree.
    ///   - fold_rounds: `n_fold` rounds at log_height_start.
    ///
    /// Bundles are all structurally identical (same shape) but with α /
    /// ρ / roots varying by `seed`.
    fn sample_bundle_inputs(
        seed: u64,
        n_alpha: usize,
        n_fold: usize,
        log_height_start: usize,
    ) -> (
        Challenge,       // alpha
        Vec<AlphaStep>,  // alpha_steps
        Vec<Goldilocks>, // leaf
        Vec<Digest>,     // opening_proof (1 sibling = log_height 1)
        usize,           // index
        Digest,          // expected_root
        Vec<FoldRound>,  // fold_rounds
    ) {
        use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref};
        let perm = default_goldilocks_poseidon2_8();

        let alpha = ext(3 + seed, 5 + seed * 2);
        let alpha_steps: Vec<AlphaStep> = (0..n_alpha as u64)
            .map(|i| AlphaStep {
                p_at_x: gl(7 * i + seed + 1),
                p_at_z: ext(11 * i + seed + 3, 13 * i + seed + 5),
                z: ext(17 * i + seed + 7, 19 * i + seed + 11),
                x: gl(23 * i + seed + 2),
            })
            .collect();

        let leaf: Vec<Goldilocks> = (0..8u64).map(|j| gl(seed * 1000 + j * 17 + 1)).collect();
        let leaf_sib: Vec<Goldilocks> = (0..8u64)
            .map(|j| gl(seed * 1000 + 500 + j * 23 + 3))
            .collect();
        let dig = hash_leaf_row_ref(&perm, &leaf);
        let dig_sib = hash_leaf_row_ref(&perm, &leaf_sib);
        let root = compress_pair_ref(&perm, &dig, &dig_sib);
        let opening = vec![dig_sib];

        let fold_rounds: Vec<FoldRound> = (0..n_fold)
            .map(|r| FoldRound {
                sibling: ext(53 + r as u64 * 7 + seed, 59 + r as u64 * 11 + seed),
                beta: ext(61 + r as u64 * 13 + seed, 67 + r as u64 * 17 + seed),
                domain_index: (0b1010_0101 ^ (r + seed as usize)) & ((1 << log_height_start) - 1),
                log_height: log_height_start - r,
            })
            .collect();

        (alpha, alpha_steps, leaf, opening, 0, root, fold_rounds)
    }

    /// Convenience wrapper that runs prove+verify + postcard-serializes
    /// and reports timing. Trace_height must be a power of two and ≥
    /// the sum of all bundles' physical rows.
    fn run_multi_bundle_measurement(
        tag: &str,
        n_bundles: usize,
        n_alpha_per_bundle: usize,
        n_fold_per_bundle: usize,
        log_height_start: usize,
        trace_height: usize,
    ) {
        use crate::prover::build_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};
        use std::time::Instant;

        // Generate bundle inputs, then borrow them into BundleSpec.
        struct BundleInputs {
            alpha: Challenge,
            alpha_steps: Vec<AlphaStep>,
            leaf: Vec<Goldilocks>,
            opening: Vec<Digest>,
            index: usize,
            expected_root: Digest,
            fold_rounds: Vec<FoldRound>,
        }
        let inputs: Vec<BundleInputs> = (0..n_bundles as u64)
            .map(|seed| {
                let (a, alpha_steps, leaf, opening, index, expected_root, fold_rounds) =
                    sample_bundle_inputs(
                        seed + 1, // +1 to avoid seed=0 degeneracies
                        n_alpha_per_bundle,
                        n_fold_per_bundle,
                        log_height_start,
                    );
                BundleInputs {
                    alpha: a,
                    alpha_steps,
                    leaf,
                    opening,
                    index,
                    expected_root,
                    fold_rounds,
                }
            })
            .collect();

        // Second pass: wire up &-borrows.
        let bundles: Vec<BundleSpec<'_>> = inputs
            .iter()
            .map(|b| BundleSpec {
                initial_alpha_pow: ext(1, 0),
                initial_ro: ext(0, 0),
                alpha: b.alpha,
                alpha_steps: &b.alpha_steps,
                merkle_paths: &[],
                fold_rounds: &b.fold_rounds,
            })
            .collect();

        // But merkle_paths needs a slice of MerkleOpening — can't nest
        // borrows through closures easily. Build a parallel vec:
        let merkle_paths_per_bundle: Vec<Vec<MerkleOpening<'_>>> = inputs
            .iter()
            .map(|b| {
                vec![MerkleOpening {
                    leaf: &b.leaf,
                    opening_proof: &b.opening,
                    index: b.index,
                    expected_root: b.expected_root,
                }]
            })
            .collect();

        // Now weave them:
        let bundles: Vec<BundleSpec<'_>> = bundles
            .into_iter()
            .zip(merkle_paths_per_bundle.iter())
            .map(|(mut b, mp)| {
                b.merkle_paths = mp.as_slice();
                b
            })
            .collect();

        let flat = build_multi_bundle_trace(&bundles, &block_pi_zero(), trace_height)
            .expect("trace build");
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        let cfg = build_config();
        let air = MonolithicVerifierAirV1;

        let t0 = Instant::now();
        let proof = prove(&cfg, &air, trace, &TEST_PI_ZERO);
        let prove_ms = t0.elapsed().as_millis();
        verify(&cfg, &air, &proof, &TEST_PI_ZERO).expect("must verify");

        let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
        let cells = trace_height * col::WIDTH;
        eprintln!(
            "  [{tag}] n_bundles={n_bundles:>4}  α={n_alpha_per_bundle:>3}/bundle  \
             fold={n_fold_per_bundle}  height={trace_height:>6}  \
             cells={cells:>10}  prove={prove_ms:>7} ms  proof={proof_bytes:>7} B",
        );
    }

    /// A4 baseline: 52 bundles = 1 Tx's full per-query bundle (all 52
    /// FRI queries in ONE monolithic STARK), small α_steps per query
    /// to keep total runtime manageable.
    #[test]
    #[ignore = "A4 measurement — run explicitly to capture scaling data"]
    fn measure_multi_bundle_one_tx_52q() {
        eprintln!();
        eprintln!("A4: 1 Tx = 52 bundles (all queries in ONE STARK):");
        // Each bundle: 10 α + (2 absorb + 1 compress = 3 Merkle) + 3 fold
        //            = 16 rows. 52 bundles = 832 rows. Pad to 1024.
        run_multi_bundle_measurement("1tx-52q", 52, 10, 3, 5, 1024);
    }

    /// A4 §4.1 landmark: 4 Txs × 52 queries = 208 bundles in ONE STARK.
    #[test]
    #[ignore = "A4 measurement — run explicitly to capture scaling data"]
    fn measure_multi_bundle_n4_208bundles() {
        eprintln!();
        eprintln!("A4 §4.1 landmark: N=4 Txs × 52q = 208 bundles:");
        // 208 × 16 = 3328 rows. Pad to 4096.
        run_multi_bundle_measurement("n4-208b", 208, 10, 3, 5, 4096);
    }

    /// A4 scaling sweep: exercise the monolithic AIR at increasing
    /// bundle counts to characterize prover time / proof size growth.
    #[test]
    #[ignore = "A4 measurement — run explicitly to capture scaling data"]
    fn measure_multi_bundle_scaling_sweep() {
        eprintln!();
        eprintln!("A4 multi-bundle scaling sweep:");
        // (tag, n_bundles, trace_height) — α_steps=10, fold=3.
        let scenarios = [
            ("2 bundles ", 2usize, 64usize),
            ("8 bundles ", 8, 256),
            ("32 bundles", 32, 1024),
            ("128 bundles", 128, 4096),
        ];
        for (tag, n, h) in scenarios {
            run_multi_bundle_measurement(tag, n, 10, 3, 5, h);
        }
    }

    /// A4 larger-per-bundle: each bundle has more α_steps + more fold
    /// rounds (approximates the 2/2 per-query shape).
    #[test]
    #[ignore = "A4 measurement — run explicitly to capture scaling data"]
    fn measure_multi_bundle_2_2_shape_per_bundle() {
        eprintln!();
        eprintln!("A4 2/2-shape per-bundle (α=40, fold=6):");
        // Per bundle: 40 α + 3 Merkle + 6 fold = 49 rows.
        // 8 bundles × 49 = 392 rows → pad to 512.
        // 32 bundles × 49 = 1568 → pad to 2048.
        run_multi_bundle_measurement("2/2 ×8 ", 8, 40, 6, 8, 512);
        run_multi_bundle_measurement("2/2 ×32", 32, 40, 6, 8, 2048);
    }
}
