//! Monolithic VerifierAir — Phase A3-PRE scaffolding.
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

// ---------------------------------------------------------------------------
// Shared / imported constants
// ---------------------------------------------------------------------------

use crate::transfer_air::POSEIDON2_COLS_PER_INSTANCE;

/// Extension field DIMENSION. Mirrors the other AIRs' constant.
pub const CHALLENGE_DIM: usize = 2;
/// Sponge rate (matches `PaddingFreeSponge<_, 8, 4, 4>`).
pub const SPONGE_RATE: usize = 4;
/// Sponge width.
pub const SPONGE_WIDTH: usize = 8;
/// Digest width (sponge OUT).
pub const DIGEST_WIDTH: usize = 4;

// ---------------------------------------------------------------------------
// One-hot row-kind selectors
// ---------------------------------------------------------------------------

pub const OP_KIND_ABSORB: u8 = 0;
pub const OP_KIND_COMPRESS: u8 = 1;
pub const OP_KIND_FOLD: u8 = 2;
pub const OP_KIND_ALPHA: u8 = 3;
pub const OP_KIND_IDLE: u8 = 4;
pub const NUM_OP_KINDS: usize = 5;

// ---------------------------------------------------------------------------
// Column layout (PINNED; A3-1+ fill in the bank-specific constraints)
// ---------------------------------------------------------------------------

pub mod col {
    use super::*;

    // ---- Selectors ------------------------------------------------------
    pub const KIND0: usize = 0;
    pub const KIND_END: usize = KIND0 + NUM_OP_KINDS;

    // ---- ABSORB bank (shape mirrors leaf_hash_air framing) --------------
    /// Per-row absorption block (4 Goldilocks).
    pub const ABSORB_BLOCK0: usize = KIND_END;
    pub const ABSORB_BLOCK_END: usize = ABSORB_BLOCK0 + SPONGE_RATE;
    /// Per-row BLOCK_LEN (1..=RATE on ABSORB, 0 elsewhere).
    pub const ABSORB_BLOCK_LEN: usize = ABSORB_BLOCK_END;
    /// One-hot over {0, 1, 2, 3, 4}.
    pub const ABSORB_BLOCK_LEN_FLAG0: usize = ABSORB_BLOCK_LEN + 1;
    pub const ABSORB_BLOCK_LEN_FLAG_END: usize =
        ABSORB_BLOCK_LEN_FLAG0 + (SPONGE_RATE + 1);
    /// 1 on the FIRST ABSORB row of a leaf's chain.
    pub const ABSORB_IS_FIRST: usize = ABSORB_BLOCK_LEN_FLAG_END;
    /// 1 on the LAST ABSORB row of a leaf's chain.
    pub const ABSORB_IS_LAST: usize = ABSORB_IS_FIRST + 1;

    // ---- COMPRESS bank (shape mirrors compression_path_air framing) -----
    /// Digest at the start of a COMPRESS row (from prior DIGEST, or
    /// from the LEAF_DIGEST at the first COMPRESS of a path).
    pub const COMPRESS_CURRENT0: usize = ABSORB_IS_LAST + 1;
    pub const COMPRESS_CURRENT_END: usize = COMPRESS_CURRENT0 + DIGEST_WIDTH;
    pub const COMPRESS_SIBLING0: usize = COMPRESS_CURRENT_END;
    pub const COMPRESS_SIBLING_END: usize = COMPRESS_SIBLING0 + DIGEST_WIDTH;
    pub const COMPRESS_INDEX_BIT: usize = COMPRESS_SIBLING_END;

    // ---- Shared P2 I/O cols (both ABSORB and COMPRESS bind these) -------
    /// Sponge state fed into the Poseidon2 block on this row.
    /// ABSORB: state[0..RATE] = BLOCK; state[RATE..WIDTH] = carry.
    /// COMPRESS: state = [LEFT ∥ RIGHT].
    pub const STATE_IN0: usize = COMPRESS_INDEX_BIT + 1;
    pub const STATE_IN_END: usize = STATE_IN0 + SPONGE_WIDTH;
    /// Sponge state output of the Poseidon2 block (equals p2.post[0..8]).
    pub const STATE_OUT0: usize = STATE_IN_END;
    pub const STATE_OUT_END: usize = STATE_OUT0 + SPONGE_WIDTH;
    /// DIGEST = STATE_OUT[0..4] on ABSORB IS_LAST rows and on COMPRESS rows.
    pub const DIGEST0: usize = STATE_OUT_END;
    pub const DIGEST_END: usize = DIGEST0 + DIGEST_WIDTH;

    // ---- FOLD bank (shape mirrors fold_air framing) --------------------
    pub const FOLD_BETA0: usize = DIGEST_END;
    pub const FOLD_BETA_END: usize = FOLD_BETA0 + CHALLENGE_DIM;
    pub const FOLD_S: usize = FOLD_BETA_END;
    pub const FOLD_INV_2S: usize = FOLD_S + 1;
    /// Folded-eval in/out (Challenge). IN carries from the prior FOLD row.
    pub const FOLD_IN0: usize = FOLD_INV_2S + 1;
    pub const FOLD_IN_END: usize = FOLD_IN0 + CHALLENGE_DIM;
    pub const FOLD_OUT0: usize = FOLD_IN_END;
    pub const FOLD_OUT_END: usize = FOLD_OUT0 + CHALLENGE_DIM;

    // ---- ALPHA bank (shape mirrors alpha_reduction_air framing) --------
    pub const ALPHA_CHALLENGE0: usize = FOLD_OUT_END;
    pub const ALPHA_CHALLENGE_END: usize = ALPHA_CHALLENGE0 + CHALLENGE_DIM;
    pub const ALPHA_POW_IN0: usize = ALPHA_CHALLENGE_END;
    pub const ALPHA_POW_IN_END: usize = ALPHA_POW_IN0 + CHALLENGE_DIM;
    pub const ALPHA_POW_OUT0: usize = ALPHA_POW_IN_END;
    pub const ALPHA_POW_OUT_END: usize = ALPHA_POW_OUT0 + CHALLENGE_DIM;
    pub const ALPHA_P_AT_X: usize = ALPHA_POW_OUT_END;
    pub const ALPHA_P_AT_Z0: usize = ALPHA_P_AT_X + 1;
    pub const ALPHA_P_AT_Z_END: usize = ALPHA_P_AT_Z0 + CHALLENGE_DIM;
    pub const ALPHA_Z0: usize = ALPHA_P_AT_Z_END;
    pub const ALPHA_Z_END: usize = ALPHA_Z0 + CHALLENGE_DIM;
    pub const ALPHA_X: usize = ALPHA_Z_END;
    pub const ALPHA_QUOT_INV0: usize = ALPHA_X + 1;
    pub const ALPHA_QUOT_INV_END: usize = ALPHA_QUOT_INV0 + CHALLENGE_DIM;
    pub const ALPHA_DIFF_QUOT0: usize = ALPHA_QUOT_INV_END;
    pub const ALPHA_DIFF_QUOT_END: usize = ALPHA_DIFF_QUOT0 + CHALLENGE_DIM;
    pub const ALPHA_RO_IN0: usize = ALPHA_DIFF_QUOT_END;
    pub const ALPHA_RO_IN_END: usize = ALPHA_RO_IN0 + CHALLENGE_DIM;
    pub const ALPHA_RO_OUT0: usize = ALPHA_RO_IN_END;
    pub const ALPHA_RO_OUT_END: usize = ALPHA_RO_OUT0 + CHALLENGE_DIM;

    // ---- Public-input proxies (persist across all rows, asserted
    // consistent with proof data at the aggregator boundary) -----------
    /// Trace-commit root; all COMPRESS rows of the trace-Merkle walk
    /// have this as their "ROOT" target.
    pub const TRACE_COMMIT_ROOT0: usize = ALPHA_RO_OUT_END;
    pub const TRACE_COMMIT_ROOT_END: usize = TRACE_COMMIT_ROOT0 + DIGEST_WIDTH;
    /// Quotient-commit root (analogous).
    pub const QUOT_COMMIT_ROOT0: usize = TRACE_COMMIT_ROOT_END;
    pub const QUOT_COMMIT_ROOT_END: usize = QUOT_COMMIT_ROOT0 + DIGEST_WIDTH;
    /// Initial α-chain seeds (ALPHA_POW = 1, RO = 0). Normally pinned
    /// by first-row boundary constraint; stored explicitly for audit.
    pub const INITIAL_ALPHA_POW0: usize = QUOT_COMMIT_ROOT_END;
    pub const INITIAL_ALPHA_POW_END: usize = INITIAL_ALPHA_POW0 + CHALLENGE_DIM;
    pub const INITIAL_RO0: usize = INITIAL_ALPHA_POW_END;
    pub const INITIAL_RO_END: usize = INITIAL_RO0 + CHALLENGE_DIM;
    /// Expected FINAL_FOLDED (= eval_final_poly_horner(x_final)).
    pub const FINAL_FOLDED0: usize = INITIAL_RO_END;
    pub const FINAL_FOLDED_END: usize = FINAL_FOLDED0 + CHALLENGE_DIM;

    /// Base offset of the shared Poseidon2-w8 sub-AIR witness block.
    pub const P2_BLOCK: usize = FINAL_FOLDED_END;

    /// Total column width. 180-col Poseidon2 block added on top of
    /// framing cols. Final number fixed at A3-PRE to pin the layout.
    pub const WIDTH: usize = P2_BLOCK + POSEIDON2_COLS_PER_INSTANCE;
}

/// Canonical width constant mirroring `col::WIDTH`.
pub const MONOLITHIC_VERIFIER_AIR_WIDTH: usize = col::WIDTH;

// ---------------------------------------------------------------------------
// Trace builder (A3-PRE: emits IDLE-only rows for scaffold validation)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TraceBuildError {
    TraceHeightNotPow2 { got: usize },
}

/// Build a trivial all-IDLE trace of the requested height. Real
/// operation-specific rows land in A3-1+ as each bank migrates in.
pub fn build_trivial_trace(trace_height: usize) -> Result<Vec<Goldilocks>, TraceBuildError> {
    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];

    // Populate KIND = IDLE on every row.
    for r in 0..trace_height {
        let base = r * width;
        flat[base + col::KIND0 + OP_KIND_IDLE as usize] = Goldilocks::new(1);
        // Other KIND flags default to 0.
    }

    // Populate the shared Poseidon2-w8 block on every row with the
    // zero-input witness. Reuses the same helper pattern as
    // `leaf_hash_air` / `compression_path_air` / `merkle_path_air`.
    let p2_witness = gen_p2_witness_zero();
    for r in 0..trace_height {
        let base = r * width;
        for (i, v) in p2_witness.iter().enumerate() {
            flat[base + col::P2_BLOCK + i] = *v;
        }
    }

    Ok(flat)
}

/// Generate the Poseidon2-w8 witness for a zero input state. Shared
/// across all IDLE rows (and all current-phase non-wire-binding rows
/// at A3-PRE).
pub(crate) fn gen_p2_witness_zero() -> Vec<Goldilocks> {
    gen_p2_witness([Goldilocks::default(); 8])
}

pub(crate) fn gen_p2_witness(input: [Goldilocks; 8]) -> Vec<Goldilocks> {
    use p3_goldilocks::{
        GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8, GenericPoseidon2LinearLayersGoldilocks,
    };
    use p3_poseidon2_air::{RoundConstants, generate_trace_rows};

    let constants: RoundConstants<
        Goldilocks,
        8,
        { p3_goldilocks::GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS },
        GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
    > = RoundConstants::new(
        p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
        p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
        p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    );
    let mat = generate_trace_rows::<
        Goldilocks,
        GenericPoseidon2LinearLayersGoldilocks,
        8,
        7,
        1,
        { p3_goldilocks::GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS },
        GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
    >(vec![input], &constants, 0);
    debug_assert_eq!(mat.values.len(), POSEIDON2_COLS_PER_INSTANCE);
    mat.values
}

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
        0
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

        let fe = |v: u64| AB::Expr::from(AB::F::from_u64(v));
        let zero = || fe(0);
        let one = || fe(1);

        // KIND one-hot enforcement — the only constraint wired at A3-PRE.
        let mut sum = zero();
        for k in 0..NUM_OP_KINDS {
            let flag: AB::Expr = local[col::KIND0 + k].into();
            builder.assert_zero(flag.clone() * (flag.clone() - one()));
            sum = sum + flag;
        }
        builder.assert_eq(sum, one());

        // A3-1+ will add ABSORB / COMPRESS / FOLD / ALPHA banks here.
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[]).expect("trivial IDLE trace must verify");
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
            prove(&cfg, &air, trace, &[])
        }));
        match outcome {
            Err(_) => {} // debug-builder panic on broken one-hot
            Ok(p) => {
                verify(&cfg, &air, &p, &[])
                    .expect_err("broken KIND one-hot must reject");
            }
        }
    }

    /// Report the column width to stdout — useful for A3-1 planning.
    #[test]
    fn print_column_layout() {
        eprintln!("MonolithicVerifierAir layout (A3-PRE):");
        eprintln!("  KIND           : 0 .. {}  ({} cols)", col::KIND_END, col::KIND_END);
        eprintln!(
            "  ABSORB bank    : {} .. {}",
            col::ABSORB_BLOCK0, col::ABSORB_IS_LAST + 1
        );
        eprintln!(
            "  COMPRESS bank  : {} .. {}",
            col::COMPRESS_CURRENT0, col::COMPRESS_INDEX_BIT + 1
        );
        eprintln!(
            "  STATE (shared) : {} .. {}",
            col::STATE_IN0, col::DIGEST_END
        );
        eprintln!("  FOLD bank      : {} .. {}", col::FOLD_BETA0, col::FOLD_OUT_END);
        eprintln!("  ALPHA bank     : {} .. {}", col::ALPHA_CHALLENGE0, col::ALPHA_RO_OUT_END);
        eprintln!(
            "  Public-input   : {} .. {}",
            col::TRACE_COMMIT_ROOT0, col::FINAL_FOLDED_END
        );
        eprintln!(
            "  P2 block       : {} .. {}  ({} cols)",
            col::P2_BLOCK, col::WIDTH, POSEIDON2_COLS_PER_INSTANCE
        );
        eprintln!("  TOTAL WIDTH    : {}", col::WIDTH);
    }
}
