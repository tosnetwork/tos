//! 16-bit range-table AIR — Phase 3b-step3 preparation.
//!
//! Scaffolds a standalone AIR whose preprocessed column is the
//! canonical 16-bit range table (`table[i] == i` for `i ∈ 0..2^16`).
//! This is the *table side* of the future cross-AIR `Kind::Global`
//! LogUp lookup that `MvpTransferAir` will eventually register from
//! its 4×u16 limb columns (§4.2 claims 5 & 7) per the
//! `doc/uno-p2-path-research.md` Path (iii)-step-2 plan.
//!
//! # Current scope (Phase 3b-step3-prep)
//!
//! This commit stops at the *module skeleton*:
//!
//!   * `Range16Air` type definition.
//!   * `BaseAir` / `Air` impls with no base constraints (LogUp is
//!     the entire soundness argument; the table AIR has no row-local
//!     relations).
//!   * Preprocessed table trace generator (`preprocessed_trace_values`)
//!     emitting a `RowMajorMatrix` of height `2^16` and width 1.
//!   * A unit test (`preprocessed_table_has_expected_shape`) that pins
//!     the shape + boundary values of the table so any future change
//!     trips CI before it trips a prover run.
//!
//! What is **NOT yet landed** here:
//!
//!   * `LookupAir::get_lookups` registering a `Kind::Global("u16_range")`
//!     send of the preprocessed column with the multiplicity column —
//!     that is Phase 3b-step3 proper.
//!   * Corresponding `Kind::Global("u16_range")` receive on
//!     `MvpTransferAir`'s `S_VALUE_LIMB0..` / `O_VALUE_LIMB0..`
//!     limb columns.
//!   * Wiring `Range16Air` into `MvpBatchProver::prove` as a second
//!     instance alongside `MvpTransferAir`.
//!   * Multiplicity column computation (counts how many times each
//!     table entry is read across the transfer instance).
//!
//! # Why separate from `MvpTransferAir`
//!
//! A 16-bit range table has `2^16 = 65 536` rows, vs. the
//! `MvpTransferAir` main trace height of `2^6 = 64`. The two AIRs
//! therefore cannot share a main trace. `p3-batch-stark` supports
//! heterogeneous trace heights across a batch, tied together by
//! `Kind::Global` LogUp cumulative-sum checks — that is the intended
//! wiring pattern. See `third-party/plonky3-uno/batch-stark/tests/
//! simple.rs::test_batch_stark_global_lookups_only` for a working
//! reference of the cross-AIR pattern.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

/// `log2` of the 16-bit range-table height.
pub const LOG_RANGE_TABLE_HEIGHT: usize = 16;

/// Height of the 16-bit range table (= `2^16`).
pub const RANGE_TABLE_HEIGHT: usize = 1 << LOG_RANGE_TABLE_HEIGHT;

/// Width of the `Range16Air` main trace: a single multiplicity column
/// `mult[i]` recording how many times the preprocessed table entry
/// `i` is read by other AIRs via `Kind::Global("u16_range")`. In the
/// Phase 3b-step3-prep skeleton the main trace is not yet generated;
/// the value is pinned here so callers wiring the full LogUp know the
/// expected width ahead of time.
pub const MAIN_TRACE_WIDTH: usize = 1;

/// Width of the `Range16Air` preprocessed trace: a single column
/// containing the canonical `table[i] == i` range table for
/// `i ∈ 0..2^16`.
pub const PREPROCESSED_TRACE_WIDTH: usize = 1;

/// Standalone 16-bit range-table AIR. Carries no state; the table is
/// derived on-the-fly from the row index.
#[derive(Debug, Clone, Copy, Default)]
pub struct Range16Air;

impl Range16Air {
    /// Construct a new `Range16Air` instance. The AIR is stateless —
    /// this is a no-arg constructor kept for parity with other AIR
    /// modules in this crate (e.g. `MvpTransferAir::new`).
    pub const fn new() -> Self {
        Self
    }

    /// Materialize the preprocessed 16-bit range table as a
    /// `RowMajorMatrix`. Column 0 row `i` contains `Goldilocks::from(i)`.
    ///
    /// Deterministic, no RNG, no allocation beyond the returned `Vec`.
    /// The caller is expected to hand this matrix to
    /// `p3_batch_stark::ProverData::from_airs_and_degrees` via the
    /// `BaseAir::preprocessed_trace` path once step3 proper is wired.
    pub fn preprocessed_trace_values() -> RowMajorMatrix<Goldilocks> {
        let values: Vec<Goldilocks> = (0..RANGE_TABLE_HEIGHT as u64)
            .map(Goldilocks::from_u64)
            .collect();
        RowMajorMatrix::new(values, PREPROCESSED_TRACE_WIDTH)
    }
}

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for Range16Air {
    fn width(&self) -> usize {
        MAIN_TRACE_WIDTH
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        // Range16 constraints are purely single-row (LogUp cumulative-
        // sum updates are handled by the permutation trace, not by an
        // Air::eval transition). No next-row columns are ever read.
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Degree-1 bound: the AIR has no base constraints, so the
        // effective degree over the main trace is trivially 1.
        Some(1)
    }
}

impl<AB> Air<AB> for Range16Air
where
    AB: AirBuilder<F = Goldilocks>,
{
    #[inline]
    fn eval(&self, _builder: &mut AB) {
        // No base-AIR constraints. All soundness comes from the
        // LogUp argument — which is NOT registered in this skeleton
        // (see module docstring). A later `LookupAir::get_lookups`
        // impl will send `(preprocessed[0], multiplicity)` pairs under
        // the `Kind::Global("u16_range")` name; receivers on
        // `MvpTransferAir` will consume each u16 limb value with
        // multiplicity 1.
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p3_matrix::Matrix;

    #[test]
    fn preprocessed_table_has_expected_shape() {
        let table = Range16Air::preprocessed_trace_values();
        assert_eq!(table.height(), RANGE_TABLE_HEIGHT);
        assert_eq!(table.width(), PREPROCESSED_TRACE_WIDTH);

        // Boundary pins: first row is 0, last row is 2^16 - 1. Interior
        // row sampled at u16::MAX / 2 to catch any off-by-one introduced
        // by a future optimization.
        let first: Vec<Goldilocks> = table.row(0).unwrap().into_iter().collect();
        assert_eq!(first[0], Goldilocks::from_u64(0));

        let mid_row = (u16::MAX as usize) / 2;
        let mid: Vec<Goldilocks> = table.row(mid_row).unwrap().into_iter().collect();
        assert_eq!(mid[0], Goldilocks::from_u64(mid_row as u64));

        let last: Vec<Goldilocks> = table
            .row(RANGE_TABLE_HEIGHT - 1)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(last[0], Goldilocks::from_u64(u16::MAX as u64));
    }

    #[test]
    fn range16_air_has_expected_widths() {
        let air = Range16Air::new();
        assert_eq!(<Range16Air as BaseAir<Goldilocks>>::width(&air), 1);
        assert_eq!(LOG_RANGE_TABLE_HEIGHT, 16);
        assert_eq!(RANGE_TABLE_HEIGHT, 65_536);
    }
}
