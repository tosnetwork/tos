//! α-reduction AIR — trace layout + pure-Rust constraint checker
//! (Phase A2-3c-iv-d-5).
//!
//! Encodes the α-batched quotient combination from
//! `open_input::alpha_combine_matrix_point` (A2-3c-iv-b) as AIR
//! constraints. Each row is ONE `(P_AT_X, P_AT_Z, Z)` update:
//!
//! ```text
//!   ro_out       = ro_in + alpha_pow_in · (p_at_z − p_at_x) · (z − x)^{-1}
//!   alpha_pow_out = alpha_pow_in · alpha
//! ```
//!
//! A full `open_input` for one FRI query stitches many such rows
//! together: `air_width` rows for trace_local at zeta, `air_width`
//! rows for trace_next at zeta_next, then `num_chunks · DIMENSION`
//! rows for quotient chunks at zeta. Between batches, ALPHA_POW is
//! threaded through — there's no reset.
//!
//! # Why decompose as a chain?
//!
//! The native formula has a three-factor extension product
//! `α^k · (p_z − p_x) · quotient`. Expanding per-limb gives degree-4
//! terms before row-selector gating, which blows the `log_blowup = 3`
//! budget. To stay at degree 3 we introduce an intermediate
//! `DIFF_QUOT = (p_z − p_x) · quotient` column, split the product
//! into two extension-mult constraint banks (each degree 2 per limb,
//! degree 3 gated), and keep the final `α^k · DIFF_QUOT → ro_out`
//! as its own bank.
//!
//! # Column layout per row (44 framing cols, no Poseidon2 block)
//!
//! ```text
//! -------- Selectors (one-hot over {COMBINE, IDLE}) -------------
//!   IS_COMBINE             : 1 col
//!   IS_IDLE                : 1 col
//!
//! -------- Per-row claimed evaluations -------------------------
//!   P_AT_X                 : 1 col  — base-field opening at query point
//!   P_AT_Z[0..2]           : 2 cols — Challenge opening at z
//!   Z[0..2]                : 2 cols — Challenge: zeta or zeta_next (varies
//!                                     by which batch / point we're combining)
//!   X                      : 1 col  — query-domain base-field point
//!
//! -------- Witnesses + intermediates ---------------------------
//!   QUOT_INV[0..2]         : 2 cols — witness: (Z − X)^{−1} as Challenge
//!   DIFF_QUOT[0..2]        : 2 cols — intermediate: (P_AT_Z − P_AT_X) · QUOT_INV
//!
//! -------- Chain state -----------------------------------------
//!   ALPHA[0..2]            : 2 cols — persistent FRI α challenge
//!   ALPHA_POW_IN[0..2]     : 2 cols — α^k at row start
//!   ALPHA_POW_OUT[0..2]    : 2 cols — α^{k+1} = ALPHA_POW_IN · ALPHA
//!   RO_IN[0..2]            : 2 cols — reduced opening at row start
//!   RO_OUT[0..2]           : 2 cols — RO_IN + ALPHA_POW_IN · DIFF_QUOT
//!
//! -------- Public-input proxies -------------------------------
//!   INITIAL_ALPHA_POW[0..2]: 2 cols — typically Challenge::ONE
//!   INITIAL_RO[0..2]       : 2 cols — typically Challenge::ZERO
//!   FINAL_RO[0..2]         : 2 cols — expected RO after last row
//! ```
//!
//! Total: 2 + 1 + 2 + 2 + 1 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 2
//!      = **28 cols**.
//!
//! # Transition rules
//!
//! 1. `IS_COMBINE + IS_IDLE = 1`, each boolean.
//! 2. COMBINE row — inverse witness:
//!    `QUOT_INV · (Z − X) == 1` (extension identity, per limb).
//! 3. COMBINE row — diff-quot intermediate:
//!    `DIFF_QUOT == (P_AT_Z − P_AT_X) · QUOT_INV` (extension mult, per limb).
//! 4. COMBINE row — α advance:
//!    `ALPHA_POW_OUT == ALPHA_POW_IN · ALPHA` (extension mult, per limb).
//! 5. COMBINE row — RO update:
//!    `RO_OUT == RO_IN + ALPHA_POW_IN · DIFF_QUOT` (extension mult, per limb).
//! 6. Transition (local → next):
//!    `next.ALPHA_POW_IN == local.ALPHA_POW_OUT` (chain threading),
//!    `next.RO_IN       == local.RO_OUT`.
//! 7. ALPHA, INITIAL_*, FINAL_RO persist across all rows.
//! 8. IDLE rows preserve every non-KIND column.
//! 9. Row 0: ALPHA_POW_IN = INITIAL_ALPHA_POW, RO_IN = INITIAL_RO.
//! 10. Last non-IDLE row: RO_OUT = FINAL_RO.
//!
//! # Constraint degree
//!
//! Each of banks (2)/(3)/(4)/(5) is degree 2 per limb (an extension
//! multiplication). Gating by `is_combine` (degree 1) gives max
//! degree 3 overall — fits Option B's log_blowup = 3 budget.

use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;

use crate::prover::Challenge;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

pub const CHALLENGE_DIM: usize = 2;
/// Binomial extension norm constant. `<Goldilocks as BinomiallyExtendable<2>>::W`.
pub const EXT_W: u64 = 7;

pub const OP_KIND_COMBINE: u8 = 0;
pub const OP_KIND_IDLE: u8 = 1;
pub const NUM_OP_KINDS: usize = 2;

// ---------------------------------------------------------------------------
// Column offsets
// ---------------------------------------------------------------------------

pub mod col {
    use super::*;

    pub const KIND0: usize = 0;
    pub const KIND_END: usize = KIND0 + NUM_OP_KINDS;

    pub const P_AT_X: usize = KIND_END;
    pub const P_AT_Z0: usize = P_AT_X + 1;
    pub const P_AT_Z_END: usize = P_AT_Z0 + CHALLENGE_DIM;

    pub const Z0: usize = P_AT_Z_END;
    pub const Z_END: usize = Z0 + CHALLENGE_DIM;

    pub const X: usize = Z_END;
    pub const QUOT_INV0: usize = X + 1;
    pub const QUOT_INV_END: usize = QUOT_INV0 + CHALLENGE_DIM;

    pub const DIFF_QUOT0: usize = QUOT_INV_END;
    pub const DIFF_QUOT_END: usize = DIFF_QUOT0 + CHALLENGE_DIM;

    pub const ALPHA0: usize = DIFF_QUOT_END;
    pub const ALPHA_END: usize = ALPHA0 + CHALLENGE_DIM;

    pub const ALPHA_POW_IN0: usize = ALPHA_END;
    pub const ALPHA_POW_IN_END: usize = ALPHA_POW_IN0 + CHALLENGE_DIM;
    pub const ALPHA_POW_OUT0: usize = ALPHA_POW_IN_END;
    pub const ALPHA_POW_OUT_END: usize = ALPHA_POW_OUT0 + CHALLENGE_DIM;

    pub const RO_IN0: usize = ALPHA_POW_OUT_END;
    pub const RO_IN_END: usize = RO_IN0 + CHALLENGE_DIM;
    pub const RO_OUT0: usize = RO_IN_END;
    pub const RO_OUT_END: usize = RO_OUT0 + CHALLENGE_DIM;

    pub const INITIAL_ALPHA_POW0: usize = RO_OUT_END;
    pub const INITIAL_ALPHA_POW_END: usize = INITIAL_ALPHA_POW0 + CHALLENGE_DIM;
    pub const INITIAL_RO0: usize = INITIAL_ALPHA_POW_END;
    pub const INITIAL_RO_END: usize = INITIAL_RO0 + CHALLENGE_DIM;

    pub const FINAL_RO0: usize = INITIAL_RO_END;
    pub const FINAL_RO_END: usize = FINAL_RO0 + CHALLENGE_DIM;

    pub const WIDTH: usize = FINAL_RO_END;
}

pub const ALPHA_REDUCTION_AIR_FRAMING_WIDTH: usize = col::WIDTH;

// ---------------------------------------------------------------------------
// Per-row α-combine step description
// ---------------------------------------------------------------------------

/// One α-combine step: update (ALPHA_POW, RO) using `(p_at_x, p_at_z, z, x)`.
#[derive(Clone, Debug)]
pub struct AlphaStep {
    /// Base-field opening at query domain point `x`.
    pub p_at_x: Goldilocks,
    /// Extension opening at point `z`.
    pub p_at_z: Challenge,
    /// The evaluation point `z` (zeta or zeta_next per batch).
    pub z: Challenge,
    /// Query-domain base-field point `x`.
    pub x: Goldilocks,
}

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TraceBuildError {
    TraceHeightNotPow2 {
        got: usize,
    },
    TraceHeightTooSmall {
        physical_rows: usize,
        trace_height: usize,
    },
    ZequalsXAtStep {
        step: usize,
    },
}

/// Build a row-major trace for an α-combine chain of `steps.len()` rows.
///
/// `initial_ro` / `initial_alpha_pow` seed the chain (usually
/// `Challenge::ZERO` / `Challenge::ONE` but can be non-trivial when
/// the chain continues from a prior batch). `final_ro` is the
/// expected RO after all steps — asserted at the last non-IDLE row.
pub fn build_trace(
    initial_alpha_pow: Challenge,
    initial_ro: Challenge,
    alpha: Challenge,
    steps: &[AlphaStep],
    final_ro: Challenge,
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    use p3_field::BasedVectorSpace;

    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let physical_rows = steps.len();
    if physical_rows > trace_height {
        return Err(TraceBuildError::TraceHeightTooSmall {
            physical_rows,
            trace_height,
        });
    }

    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];
    let zero_g = Goldilocks::default();

    let write_ext = |out: &mut [Goldilocks], base: usize, v: Challenge| {
        let limbs = <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&v);
        for i in 0..CHALLENGE_DIM {
            out[base + i] = limbs[i];
        }
    };
    let write_kind = |out: &mut [Goldilocks], kind: u8| {
        for k in 0..NUM_OP_KINDS {
            out[col::KIND0 + k] = if k as u8 == kind {
                Goldilocks::new(1)
            } else {
                zero_g
            };
        }
    };

    // Run the chain for witness generation.
    let mut alpha_pow = initial_alpha_pow;
    let mut ro = initial_ro;

    for (r, step) in steps.iter().enumerate() {
        let base = r * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_COMBINE);

        // Per-step claimed values.
        row[col::P_AT_X] = step.p_at_x;
        write_ext(row, col::P_AT_Z0, step.p_at_z);
        write_ext(row, col::Z0, step.z);
        row[col::X] = step.x;

        // Witnesses.
        let denom = step.z - step.x;
        if denom.is_zero() {
            return Err(TraceBuildError::ZequalsXAtStep { step: r });
        }
        let quot_inv = denom.try_inverse().expect("denom ≠ 0 ⇒ invertible");
        write_ext(row, col::QUOT_INV0, quot_inv);

        let diff = step.p_at_z - step.p_at_x;
        let diff_quot = diff * quot_inv;
        write_ext(row, col::DIFF_QUOT0, diff_quot);

        // Chain state.
        write_ext(row, col::ALPHA0, alpha);
        write_ext(row, col::ALPHA_POW_IN0, alpha_pow);
        let new_alpha_pow = alpha_pow * alpha;
        write_ext(row, col::ALPHA_POW_OUT0, new_alpha_pow);
        write_ext(row, col::RO_IN0, ro);
        let new_ro = ro + alpha_pow * diff_quot;
        write_ext(row, col::RO_OUT0, new_ro);

        // Boundaries.
        write_ext(row, col::INITIAL_ALPHA_POW0, initial_alpha_pow);
        write_ext(row, col::INITIAL_RO0, initial_ro);
        write_ext(row, col::FINAL_RO0, final_ro);

        alpha_pow = new_alpha_pow;
        ro = new_ro;
    }

    // Pad with IDLE rows — copy previous row's non-KIND data.
    for row_idx in physical_rows..trace_height {
        let prev_base = (row_idx - 1) * width;
        let prev_row = flat[prev_base..prev_base + width].to_vec();
        let base = row_idx * width;
        let row = &mut flat[base..base + width];
        for c in col::KIND_END..col::WIDTH {
            row[c] = prev_row[c];
        }
        write_kind(row, OP_KIND_IDLE);
    }

    Ok(flat)
}

// ---------------------------------------------------------------------------
// Pure-Rust constraint checker
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CheckError {
    TraceLengthMismatch { expected: usize, got: usize },
    KindFlagNotBoolean { row: usize, kind: usize },
    KindNotOneHot { row: usize },
    QuotInvWitnessLimb0 { row: usize },
    QuotInvWitnessLimb1 { row: usize },
    DiffQuotLimb0 { row: usize },
    DiffQuotLimb1 { row: usize },
    AlphaPowAdvanceLimb0 { row: usize },
    AlphaPowAdvanceLimb1 { row: usize },
    RoUpdateLimb0 { row: usize },
    RoUpdateLimb1 { row: usize },
    ChainThreadingAlphaPow { row: usize, limb: usize },
    ChainThreadingRo { row: usize, limb: usize },
    AlphaDrift { row: usize, limb: usize },
    InitialAlphaPowDrift { row: usize, limb: usize },
    InitialRoDrift { row: usize, limb: usize },
    FinalRoDrift { row: usize, limb: usize },
    IdlePersistenceMismatch { row: usize, col: usize },
    Row0AlphaPowInMismatch { limb: usize },
    Row0RoInMismatch { limb: usize },
    LastRowFinalRoMismatch { limb: usize },
}

/// Compute extension multiplication (a0, a1) * (b0, b1) with the
/// binomial-extension norm W = EXT_W. Both limbs of the product
/// are returned as base-field values.
#[inline]
fn ext_mul_base(
    a0: Goldilocks,
    a1: Goldilocks,
    b0: Goldilocks,
    b1: Goldilocks,
) -> (Goldilocks, Goldilocks) {
    let w = Goldilocks::new(EXT_W);
    let out0 = a0 * b0 + w * a1 * b1;
    let out1 = a0 * b1 + a1 * b0;
    (out0, out1)
}

pub fn check_all_transitions(trace: &[Goldilocks], trace_height: usize) -> Result<(), CheckError> {
    let width = col::WIDTH;
    if trace.len() != trace_height * width {
        return Err(CheckError::TraceLengthMismatch {
            expected: trace_height * width,
            got: trace.len(),
        });
    }
    let row = |r: usize| &trace[r * width..(r + 1) * width];
    let zero_g = Goldilocks::default();
    let one_g = Goldilocks::new(1);

    let mut last_non_idle_ro: Option<(Goldilocks, Goldilocks)> = None;

    for r in 0..trace_height {
        let local = row(r);

        // ---- One-hot ----
        let mut sum = zero_g;
        for k in 0..NUM_OP_KINDS {
            let v = local[col::KIND0 + k];
            if v != zero_g && v != one_g {
                return Err(CheckError::KindFlagNotBoolean { row: r, kind: k });
            }
            sum += v;
        }
        if sum != one_g {
            return Err(CheckError::KindNotOneHot { row: r });
        }

        let is_combine = local[col::KIND0 + OP_KIND_COMBINE as usize] == one_g;
        let is_idle = local[col::KIND0 + OP_KIND_IDLE as usize] == one_g;

        // ---- COMBINE row constraints ----
        if is_combine {
            // (1) QUOT_INV · (Z − X) == 1
            //     Let d = (Z0 - X, Z1); e = QUOT_INV. Compute e · d per limb.
            let qi0 = local[col::QUOT_INV0];
            let qi1 = local[col::QUOT_INV0 + 1];
            let z0 = local[col::Z0];
            let z1 = local[col::Z0 + 1];
            let x = local[col::X];
            let d0 = z0 - x;
            let d1 = z1;
            let (prod0, prod1) = ext_mul_base(qi0, qi1, d0, d1);
            if prod0 != one_g {
                return Err(CheckError::QuotInvWitnessLimb0 { row: r });
            }
            if prod1 != zero_g {
                return Err(CheckError::QuotInvWitnessLimb1 { row: r });
            }

            // (2) DIFF_QUOT == (P_AT_Z − P_AT_X) · QUOT_INV
            let pz0 = local[col::P_AT_Z0];
            let pz1 = local[col::P_AT_Z0 + 1];
            let px = local[col::P_AT_X];
            let diff0 = pz0 - px;
            let diff1 = pz1;
            let (dq0_exp, dq1_exp) = ext_mul_base(diff0, diff1, qi0, qi1);
            if local[col::DIFF_QUOT0] != dq0_exp {
                return Err(CheckError::DiffQuotLimb0 { row: r });
            }
            if local[col::DIFF_QUOT0 + 1] != dq1_exp {
                return Err(CheckError::DiffQuotLimb1 { row: r });
            }

            // (3) ALPHA_POW_OUT == ALPHA_POW_IN · ALPHA
            let api0 = local[col::ALPHA_POW_IN0];
            let api1 = local[col::ALPHA_POW_IN0 + 1];
            let a0 = local[col::ALPHA0];
            let a1 = local[col::ALPHA0 + 1];
            let (apo0_exp, apo1_exp) = ext_mul_base(api0, api1, a0, a1);
            if local[col::ALPHA_POW_OUT0] != apo0_exp {
                return Err(CheckError::AlphaPowAdvanceLimb0 { row: r });
            }
            if local[col::ALPHA_POW_OUT0 + 1] != apo1_exp {
                return Err(CheckError::AlphaPowAdvanceLimb1 { row: r });
            }

            // (4) RO_OUT == RO_IN + ALPHA_POW_IN · DIFF_QUOT
            let dq0 = local[col::DIFF_QUOT0];
            let dq1 = local[col::DIFF_QUOT0 + 1];
            let (add0, add1) = ext_mul_base(api0, api1, dq0, dq1);
            let ri0 = local[col::RO_IN0];
            let ri1 = local[col::RO_IN0 + 1];
            if local[col::RO_OUT0] != ri0 + add0 {
                return Err(CheckError::RoUpdateLimb0 { row: r });
            }
            if local[col::RO_OUT0 + 1] != ri1 + add1 {
                return Err(CheckError::RoUpdateLimb1 { row: r });
            }
        }

        // ---- Transition: chain threading & persistence ----
        if r > 0 {
            let prev = row(r - 1);
            // ALPHA persists.
            for i in 0..CHALLENGE_DIM {
                if local[col::ALPHA0 + i] != prev[col::ALPHA0 + i] {
                    return Err(CheckError::AlphaDrift { row: r, limb: i });
                }
                if local[col::INITIAL_ALPHA_POW0 + i] != prev[col::INITIAL_ALPHA_POW0 + i] {
                    return Err(CheckError::InitialAlphaPowDrift { row: r, limb: i });
                }
                if local[col::INITIAL_RO0 + i] != prev[col::INITIAL_RO0 + i] {
                    return Err(CheckError::InitialRoDrift { row: r, limb: i });
                }
                if local[col::FINAL_RO0 + i] != prev[col::FINAL_RO0 + i] {
                    return Err(CheckError::FinalRoDrift { row: r, limb: i });
                }
            }
            // CURRENT (ALPHA_POW_IN / RO_IN) threading on COMBINE rows.
            if is_combine {
                for i in 0..CHALLENGE_DIM {
                    if local[col::ALPHA_POW_IN0 + i] != prev[col::ALPHA_POW_OUT0 + i] {
                        return Err(CheckError::ChainThreadingAlphaPow { row: r, limb: i });
                    }
                    if local[col::RO_IN0 + i] != prev[col::RO_OUT0 + i] {
                        return Err(CheckError::ChainThreadingRo { row: r, limb: i });
                    }
                }
            }
            // IDLE persistence.
            if is_idle {
                for c in col::KIND_END..col::WIDTH {
                    if local[c] != prev[c] {
                        return Err(CheckError::IdlePersistenceMismatch { row: r, col: c });
                    }
                }
            }
        }

        if !is_idle {
            last_non_idle_ro = Some((local[col::RO_OUT0], local[col::RO_OUT0 + 1]));
        }
    }

    // Row-0 boundary.
    {
        let row0 = row(0);
        for i in 0..CHALLENGE_DIM {
            if row0[col::ALPHA_POW_IN0 + i] != row0[col::INITIAL_ALPHA_POW0 + i] {
                return Err(CheckError::Row0AlphaPowInMismatch { limb: i });
            }
            if row0[col::RO_IN0 + i] != row0[col::INITIAL_RO0 + i] {
                return Err(CheckError::Row0RoInMismatch { limb: i });
            }
        }
    }

    // Last-non-IDLE boundary.
    if let Some((ro0, ro1)) = last_non_idle_ro {
        let last = row(trace_height - 1);
        let f0 = last[col::FINAL_RO0];
        let f1 = last[col::FINAL_RO0 + 1];
        if ro0 != f0 {
            return Err(CheckError::LastRowFinalRoMismatch { limb: 0 });
        }
        if ro1 != f1 {
            return Err(CheckError::LastRowFinalRoMismatch { limb: 1 });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Plonky3 AIR trait implementation (Phase A2-3c-iv-d-5-2)
//
// Mechanical port of `check_all_transitions` to Plonky3's `Air<AB>`.
// No Poseidon2 block — four extension-mult constraint banks handle
// the α-reduction identities. Max degree 3 (each ext-mult is degree
// 2; gated by is_combine adds 1).
// ---------------------------------------------------------------------------

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};

/// Plonky3 AIR for the α-reduction chain. One row per
/// `(p_at_x, p_at_z, z, x)` update; threads ALPHA_POW and RO across
/// rows.
#[derive(Copy, Clone, Debug, Default)]
pub struct AlphaReductionAirV1;

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for AlphaReductionAirV1 {
    #[inline]
    fn width(&self) -> usize {
        ALPHA_REDUCTION_AIR_FRAMING_WIDTH
    }

    #[inline]
    fn num_public_values(&self) -> usize {
        // INITIAL_* / FINAL_RO are trace columns with persistence
        // transitions. Integration (d-6) promotes them to public inputs.
        0
    }

    #[inline]
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB> Air<AB> for AlphaReductionAirV1
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
        let w = || fe(EXT_W);

        let is_combine: AB::Expr = local[col::KIND0 + OP_KIND_COMBINE as usize].into();
        let is_idle: AB::Expr = local[col::KIND0 + OP_KIND_IDLE as usize].into();

        // ============================================================
        // One-hot selector.
        // ============================================================
        let mut kind_sum = zero();
        for k in 0..NUM_OP_KINDS {
            let flag: AB::Expr = local[col::KIND0 + k].into();
            builder.assert_zero(flag.clone() * (flag.clone() - one()));
            kind_sum = kind_sum + flag;
        }
        builder.assert_eq(kind_sum, one());

        // Helper — extension multiplication expressed per-limb with W.
        let ext_mul =
            |a0: AB::Expr, a1: AB::Expr, b0: AB::Expr, b1: AB::Expr| -> (AB::Expr, AB::Expr) {
                // (a0 + a1·u) · (b0 + b1·u) = (a0·b0 + W·a1·b1) + (a0·b1 + a1·b0)·u
                let p0 = a0.clone() * b0.clone() + w() * a1.clone() * b1.clone();
                let p1 = a0 * b1 + a1 * b0;
                (p0, p1)
            };

        // ============================================================
        // (1) COMBINE — QUOT_INV · (Z − X) == 1.
        //     Here (Z − X) has limbs (Z0 − X, Z1) since X is base-field.
        // ============================================================
        {
            let qi0: AB::Expr = local[col::QUOT_INV0].into();
            let qi1: AB::Expr = local[col::QUOT_INV0 + 1].into();
            let z0: AB::Expr = local[col::Z0].into();
            let z1: AB::Expr = local[col::Z0 + 1].into();
            let x: AB::Expr = local[col::X].into();
            let d0 = z0 - x;
            let d1 = z1;
            let (p0, p1) = ext_mul(qi0, qi1, d0, d1);
            builder.assert_zero(is_combine.clone() * (p0 - one()));
            builder.assert_zero(is_combine.clone() * p1);
        }

        // ============================================================
        // (2) COMBINE — DIFF_QUOT == (P_AT_Z − P_AT_X) · QUOT_INV.
        //     (P_AT_Z − P_AT_X) limbs: (P_AT_Z0 − P_AT_X, P_AT_Z1).
        // ============================================================
        {
            let pz0: AB::Expr = local[col::P_AT_Z0].into();
            let pz1: AB::Expr = local[col::P_AT_Z0 + 1].into();
            let px: AB::Expr = local[col::P_AT_X].into();
            let qi0: AB::Expr = local[col::QUOT_INV0].into();
            let qi1: AB::Expr = local[col::QUOT_INV0 + 1].into();
            let diff0 = pz0 - px;
            let diff1 = pz1;
            let (dq0_exp, dq1_exp) = ext_mul(diff0, diff1, qi0, qi1);
            let dq0: AB::Expr = local[col::DIFF_QUOT0].into();
            let dq1: AB::Expr = local[col::DIFF_QUOT0 + 1].into();
            builder.assert_zero(is_combine.clone() * (dq0 - dq0_exp));
            builder.assert_zero(is_combine.clone() * (dq1 - dq1_exp));
        }

        // ============================================================
        // (3) COMBINE — ALPHA_POW_OUT == ALPHA_POW_IN · ALPHA.
        // ============================================================
        {
            let api0: AB::Expr = local[col::ALPHA_POW_IN0].into();
            let api1: AB::Expr = local[col::ALPHA_POW_IN0 + 1].into();
            let a0: AB::Expr = local[col::ALPHA0].into();
            let a1: AB::Expr = local[col::ALPHA0 + 1].into();
            let (exp0, exp1) = ext_mul(api0, api1, a0, a1);
            let apo0: AB::Expr = local[col::ALPHA_POW_OUT0].into();
            let apo1: AB::Expr = local[col::ALPHA_POW_OUT0 + 1].into();
            builder.assert_zero(is_combine.clone() * (apo0 - exp0));
            builder.assert_zero(is_combine.clone() * (apo1 - exp1));
        }

        // ============================================================
        // (4) COMBINE — RO_OUT == RO_IN + ALPHA_POW_IN · DIFF_QUOT.
        // ============================================================
        {
            let api0: AB::Expr = local[col::ALPHA_POW_IN0].into();
            let api1: AB::Expr = local[col::ALPHA_POW_IN0 + 1].into();
            let dq0: AB::Expr = local[col::DIFF_QUOT0].into();
            let dq1: AB::Expr = local[col::DIFF_QUOT0 + 1].into();
            let (add0, add1) = ext_mul(api0, api1, dq0, dq1);
            let ri0: AB::Expr = local[col::RO_IN0].into();
            let ri1: AB::Expr = local[col::RO_IN0 + 1].into();
            let ro0: AB::Expr = local[col::RO_OUT0].into();
            let ro1: AB::Expr = local[col::RO_OUT0 + 1].into();
            builder.assert_zero(is_combine.clone() * (ro0 - (ri0 + add0)));
            builder.assert_zero(is_combine.clone() * (ro1 - (ri1 + add1)));
        }

        // ============================================================
        // Transition constraints.
        // ============================================================
        let mut trans = builder.when_transition();

        // ALPHA / INITIAL_* / FINAL_RO persist across every row.
        for i in 0..CHALLENGE_DIM {
            let l_a: AB::Expr = local[col::ALPHA0 + i].into();
            let n_a: AB::Expr = next[col::ALPHA0 + i].into();
            trans.assert_zero(n_a - l_a);

            let l_iap: AB::Expr = local[col::INITIAL_ALPHA_POW0 + i].into();
            let n_iap: AB::Expr = next[col::INITIAL_ALPHA_POW0 + i].into();
            trans.assert_zero(n_iap - l_iap);

            let l_ir: AB::Expr = local[col::INITIAL_RO0 + i].into();
            let n_ir: AB::Expr = next[col::INITIAL_RO0 + i].into();
            trans.assert_zero(n_ir - l_ir);

            let l_fr: AB::Expr = local[col::FINAL_RO0 + i].into();
            let n_fr: AB::Expr = next[col::FINAL_RO0 + i].into();
            trans.assert_zero(n_fr - l_fr);
        }

        // CURRENT threading on COMBINE rows: next.ALPHA_POW_IN =
        // local.ALPHA_POW_OUT; next.RO_IN = local.RO_OUT.
        let next_is_combine: AB::Expr = next[col::KIND0 + OP_KIND_COMBINE as usize].into();
        for i in 0..CHALLENGE_DIM {
            let n_api: AB::Expr = next[col::ALPHA_POW_IN0 + i].into();
            let l_apo: AB::Expr = local[col::ALPHA_POW_OUT0 + i].into();
            trans.assert_zero(next_is_combine.clone() * (n_api - l_apo));

            let n_ri: AB::Expr = next[col::RO_IN0 + i].into();
            let l_ro: AB::Expr = local[col::RO_OUT0 + i].into();
            trans.assert_zero(next_is_combine.clone() * (n_ri - l_ro));
        }

        // IDLE persistence: all non-KIND cols stay put.
        let next_is_idle: AB::Expr = next[col::KIND0 + OP_KIND_IDLE as usize].into();
        for c in col::KIND_END..col::WIDTH {
            let l_c: AB::Expr = local[c].into();
            let n_c: AB::Expr = next[c].into();
            trans.assert_zero(next_is_idle.clone() * (n_c - l_c));
        }

        drop(trans);

        // ============================================================
        // Boundary: row 0 seeds from INITIAL_*.
        // ============================================================
        let mut first = builder.when_first_row();
        for i in 0..CHALLENGE_DIM {
            let api: AB::Expr = local[col::ALPHA_POW_IN0 + i].into();
            let iap: AB::Expr = local[col::INITIAL_ALPHA_POW0 + i].into();
            first.assert_zero(api - iap);

            let ri: AB::Expr = local[col::RO_IN0 + i].into();
            let ir: AB::Expr = local[col::INITIAL_RO0 + i].into();
            first.assert_zero(ri - ir);
        }
        drop(first);

        // ============================================================
        // Boundary: last row's RO_OUT == FINAL_RO.
        //
        // IDLE persistence carries RO_OUT unchanged so this closes
        // the chain even when the trace is padded.
        // ============================================================
        let mut last = builder.when_last_row();
        for i in 0..CHALLENGE_DIM {
            let ro: AB::Expr = local[col::RO_OUT0 + i].into();
            let fr: AB::Expr = local[col::FINAL_RO0 + i].into();
            last.assert_zero(ro - fr);
        }

        let _ = is_idle;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::BasedVectorSpace;

    fn gl(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    fn ext(a: u64, b: u64) -> Challenge {
        Challenge::from_basis_coefficients_fn(|i| if i == 0 { gl(a) } else { gl(b) })
    }

    /// Compute the expected FINAL_RO by running the chain out-of-circuit.
    fn simulate(
        initial_alpha_pow: Challenge,
        initial_ro: Challenge,
        alpha: Challenge,
        steps: &[AlphaStep],
    ) -> Challenge {
        let mut alpha_pow = initial_alpha_pow;
        let mut ro = initial_ro;
        for step in steps {
            let denom = step.z - step.x;
            let qinv = denom.try_inverse().unwrap();
            let dq = (step.p_at_z - step.p_at_x) * qinv;
            ro += alpha_pow * dq;
            alpha_pow *= alpha;
        }
        ro
    }

    fn sample_3_step() -> (Challenge, Challenge, Challenge, Vec<AlphaStep>, Challenge) {
        let alpha = ext(3, 5);
        let initial_alpha_pow = Challenge::ONE;
        let initial_ro = Challenge::ZERO;
        let steps = vec![
            AlphaStep {
                p_at_x: gl(11),
                p_at_z: ext(21, 31),
                z: ext(7, 1),
                x: gl(2),
            },
            AlphaStep {
                p_at_x: gl(12),
                p_at_z: ext(22, 32),
                z: ext(7, 1),
                x: gl(2),
            },
            AlphaStep {
                p_at_x: gl(13),
                p_at_z: ext(23, 33),
                z: ext(9, 4), // different z (e.g. zeta_next)
                x: gl(2),
            },
        ];
        let final_ro = simulate(initial_alpha_pow, initial_ro, alpha, &steps);
        (alpha, initial_alpha_pow, initial_ro, steps, final_ro)
    }

    // ---- positive ----

    #[test]
    fn build_and_check_accept_sample_chain() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let trace = build_trace(iap, ir, alpha, &steps, fr, 8).unwrap();
        assert_eq!(trace.len(), 8 * col::WIDTH);
        check_all_transitions(&trace, 8).expect("valid chain must check");
    }

    #[test]
    fn build_rejects_non_pow2_height() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let err = build_trace(iap, ir, alpha, &steps, fr, 7).unwrap_err();
        assert_eq!(err, TraceBuildError::TraceHeightNotPow2 { got: 7 });
    }

    #[test]
    fn build_rejects_insufficient_height() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let err = build_trace(iap, ir, alpha, &steps, fr, 2).unwrap_err();
        assert_eq!(
            err,
            TraceBuildError::TraceHeightTooSmall {
                physical_rows: 3,
                trace_height: 2
            }
        );
    }

    #[test]
    fn build_rejects_z_equals_x() {
        let alpha = ext(1, 1);
        // z.lo = x, z.hi = 0 → z == x (extension vs base).
        let steps = vec![AlphaStep {
            p_at_x: gl(3),
            p_at_z: ext(5, 5),
            z: ext(42, 0),
            x: gl(42),
        }];
        let fr = Challenge::ZERO;
        let err = build_trace(Challenge::ONE, Challenge::ZERO, alpha, &steps, fr, 4).unwrap_err();
        assert_eq!(err, TraceBuildError::ZequalsXAtStep { step: 0 });
    }

    // ---- negatives ----

    #[test]
    fn checker_rejects_tampered_quot_inv() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut trace = build_trace(iap, ir, alpha, &steps, fr, 8).unwrap();
        trace[col::QUOT_INV0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_tampered_diff_quot() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut trace = build_trace(iap, ir, alpha, &steps, fr, 8).unwrap();
        trace[col::DIFF_QUOT0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_tampered_alpha_pow_out() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut trace = build_trace(iap, ir, alpha, &steps, fr, 8).unwrap();
        trace[col::ALPHA_POW_OUT0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_tampered_ro_out() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut trace = build_trace(iap, ir, alpha, &steps, fr, 8).unwrap();
        trace[col::RO_OUT0 + 1] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_broken_alpha_pow_threading() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut trace = build_trace(iap, ir, alpha, &steps, fr, 8).unwrap();
        let row1 = col::WIDTH;
        trace[row1 + col::ALPHA_POW_IN0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_broken_ro_threading() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut trace = build_trace(iap, ir, alpha, &steps, fr, 8).unwrap();
        let row1 = col::WIDTH;
        trace[row1 + col::RO_IN0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_alpha_drift() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut trace = build_trace(iap, ir, alpha, &steps, fr, 8).unwrap();
        let row2 = 2 * col::WIDTH;
        trace[row2 + col::ALPHA0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_initial_alpha_pow_mismatch_row0() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut trace = build_trace(iap, ir, alpha, &steps, fr, 8).unwrap();
        trace[col::INITIAL_ALPHA_POW0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_initial_ro_mismatch_row0() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut trace = build_trace(iap, ir, alpha, &steps, fr, 8).unwrap();
        trace[col::INITIAL_RO0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_wrong_final_ro() {
        let (alpha, iap, ir, steps, _) = sample_3_step();
        let wrong_final = ext(9999, 8888);
        let trace = build_trace(iap, ir, alpha, &steps, wrong_final, 8).unwrap();
        let err = check_all_transitions(&trace, 8).unwrap_err();
        assert!(matches!(err, CheckError::LastRowFinalRoMismatch { .. }));
    }

    #[test]
    fn checker_rejects_idle_mutation() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut trace = build_trace(iap, ir, alpha, &steps, fr, 8).unwrap();
        // Row 5 is IDLE. Tamper.
        let row5 = 5 * col::WIDTH;
        trace[row5 + col::P_AT_X] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    // ---- column layout regression ----

    #[test]
    fn column_layout_constants() {
        assert_eq!(col::KIND0, 0);
        assert_eq!(col::KIND_END, 2);
        assert_eq!(col::WIDTH, 28);
        assert_eq!(ALPHA_REDUCTION_AIR_FRAMING_WIDTH, col::WIDTH);
    }

    // ---- end-to-end on a real trace_local α-combine batch ----

    /// On a real 2/2 Transfer proof, build an α-combine chain for the
    /// trace_local at zeta batch (one row per (trace_col base opening,
    /// trace_col claimed zeta opening)). Check the AIR accepts and
    /// that the last row's RO matches what
    /// `alpha_combine_matrix_point` computes.
    #[test]
    fn alpha_chain_matches_alpha_combine_on_real_trace_batch() {
        use crate::fiat_shamir::derive_full_challenges;
        use crate::open_input::{alpha_combine_matrix_point, query_x};
        use crate::prover::{MvpConfig, MvpProver};
        use crate::transfer_air::MvpWitness;
        use p3_uni_stark::Proof;

        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(2, 2, 0xA55A_0001);
        let (bytes, _) = prover.prove(&w.encode()).unwrap();
        let proof: Proof<MvpConfig> = postcard::from_bytes(&bytes).unwrap();
        let pis = w.public_inputs();
        let ch = derive_full_challenges(&proof, &pis);

        let q_pos = 0;
        let domain_index = ch.query_indices[q_pos];
        let x = query_x(
            domain_index,
            ch.log_global_max_height,
            ch.log_global_max_height,
        );

        // Build steps for the trace_local batch only (at zeta).
        let trace_batch = &proof.opening_proof.query_proofs[q_pos].input_proof[0];
        let trace_opening = &trace_batch.opened_values[0];
        let trace_local = &proof.opened_values.trace_local;
        assert_eq!(trace_opening.len(), trace_local.len());

        let steps: Vec<AlphaStep> = trace_opening
            .iter()
            .zip(trace_local.iter())
            .map(|(&p_at_x, &p_at_z)| AlphaStep {
                p_at_x,
                p_at_z,
                z: ch.zeta,
                x,
            })
            .collect();

        // Expected final RO: simulate via the reference (A2-3c-iv-b).
        let mut ref_alpha_pow = Challenge::ONE;
        let mut ref_ro = Challenge::ZERO;
        alpha_combine_matrix_point(
            ch.fri_alpha,
            trace_opening,
            trace_local,
            ch.zeta,
            x,
            &mut ref_alpha_pow,
            &mut ref_ro,
        )
        .expect("α-combine ref must succeed");
        let expected_final_ro = ref_ro;

        // Trace height: next pow-2 ≥ steps.len(). For 2/2 air_width ≈
        // 1305 ⇒ 2048 rows. That's a big trace but still tractable.
        let trace_height = steps.len().next_power_of_two().max(2);
        let trace = build_trace(
            Challenge::ONE,
            Challenge::ZERO,
            ch.fri_alpha,
            &steps,
            expected_final_ro,
            trace_height,
        )
        .expect("trace build");
        check_all_transitions(&trace, trace_height).expect("real α-combine chain must check");
    }

    // ======================================================================
    // Phase A2-3c-iv-d-5-2: real STARK prove + verify via uni-stark
    // ======================================================================

    use crate::prover::build_config;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{prove, verify};

    fn trace_matrix(
        initial_alpha_pow: Challenge,
        initial_ro: Challenge,
        alpha: Challenge,
        steps: &[AlphaStep],
        final_ro: Challenge,
        trace_height: usize,
    ) -> RowMajorMatrix<Goldilocks> {
        let flat = build_trace(
            initial_alpha_pow,
            initial_ro,
            alpha,
            steps,
            final_ro,
            trace_height,
        )
        .expect("trace build");
        RowMajorMatrix::new(flat, col::WIDTH)
    }

    #[test]
    fn air_prove_and_verify_sample_chain() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        // trace_height = 16 leaves enough FRI headroom with log_blowup = 3.
        let trace = trace_matrix(iap, ir, alpha, &steps, fr, 16);
        let cfg = build_config();
        let air = AlphaReductionAirV1;
        let proof = prove(&cfg, &air, trace, &[]);
        verify(&cfg, &air, &proof, &[]).expect("sample α-chain must verify");
    }

    /// Helper: adversarially prove+verify a tampered trace.
    fn air_rejects(trace: RowMajorMatrix<Goldilocks>) -> bool {
        let cfg = build_config();
        let air = AlphaReductionAirV1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, &air, trace, &[])
        }));
        match outcome {
            Err(_) => true,
            Ok(p) => verify(&cfg, &air, &p, &[]).is_err(),
        }
    }

    #[test]
    fn air_rejects_tampered_quot_inv() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut flat = build_trace(iap, ir, alpha, &steps, fr, 16).unwrap();
        flat[col::QUOT_INV0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "tampered QUOT_INV must reject");
    }

    #[test]
    fn air_rejects_tampered_diff_quot() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut flat = build_trace(iap, ir, alpha, &steps, fr, 16).unwrap();
        flat[col::DIFF_QUOT0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "tampered DIFF_QUOT must reject");
    }

    #[test]
    fn air_rejects_tampered_alpha_pow_out() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut flat = build_trace(iap, ir, alpha, &steps, fr, 16).unwrap();
        flat[col::ALPHA_POW_OUT0 + 1] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "tampered ALPHA_POW_OUT must reject");
    }

    #[test]
    fn air_rejects_tampered_ro_out() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut flat = build_trace(iap, ir, alpha, &steps, fr, 16).unwrap();
        flat[col::RO_OUT0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "tampered RO_OUT must reject");
    }

    #[test]
    fn air_rejects_broken_alpha_pow_threading() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut flat = build_trace(iap, ir, alpha, &steps, fr, 16).unwrap();
        let row1 = col::WIDTH;
        flat[row1 + col::ALPHA_POW_IN0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "broken ALPHA_POW threading must reject");
    }

    #[test]
    fn air_rejects_broken_ro_threading() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut flat = build_trace(iap, ir, alpha, &steps, fr, 16).unwrap();
        let row1 = col::WIDTH;
        flat[row1 + col::RO_IN0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "broken RO threading must reject");
    }

    #[test]
    fn air_rejects_alpha_drift() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut flat = build_trace(iap, ir, alpha, &steps, fr, 16).unwrap();
        let row2 = 2 * col::WIDTH;
        flat[row2 + col::ALPHA0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "ALPHA drift must reject");
    }

    #[test]
    fn air_rejects_initial_alpha_pow_mismatch_row0() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut flat = build_trace(iap, ir, alpha, &steps, fr, 16).unwrap();
        flat[col::INITIAL_ALPHA_POW0] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "INITIAL_ALPHA_POW mismatch at row 0 must reject"
        );
    }

    #[test]
    fn air_rejects_wrong_final_ro() {
        let (alpha, iap, ir, steps, _) = sample_3_step();
        let wrong = ext(9999, 8888);
        let flat = build_trace(iap, ir, alpha, &steps, wrong, 16).unwrap();
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(
            air_rejects(trace),
            "wrong FINAL_RO must reject at last-row boundary"
        );
    }

    #[test]
    fn air_rejects_idle_mutation() {
        let (alpha, iap, ir, steps, fr) = sample_3_step();
        let mut flat = build_trace(iap, ir, alpha, &steps, fr, 16).unwrap();
        let row5 = 5 * col::WIDTH;
        flat[row5 + col::P_AT_X] += gl(1);
        let trace = RowMajorMatrix::new(flat, col::WIDTH);
        assert!(air_rejects(trace), "IDLE mutation must reject");
    }

    #[test]
    fn air_width_matches_layout_constant() {
        assert_eq!(
            <AlphaReductionAirV1 as BaseAir<Goldilocks>>::width(&AlphaReductionAirV1),
            ALPHA_REDUCTION_AIR_FRAMING_WIDTH,
        );
        assert_eq!(col::WIDTH, 28);
    }
}
