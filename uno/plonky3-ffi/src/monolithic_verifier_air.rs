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
#[path = "monolithic_verifier_air_tests.rs"]
mod tests;
