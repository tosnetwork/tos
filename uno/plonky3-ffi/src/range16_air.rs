//! 16-bit range-table AIR — Phase 3b-step3 table-side wire-up.
//!
//! Provides the *table side* of the cross-AIR `Kind::Global("u16_range")`
//! LogUp lookup that `MvpTransferAir` registers from its 4×u16 limb
//! columns (§4.2 claims 5 & 7). See `doc/uno-p2-path-research.md`
//! Path (iii)-step-2.
//!
//! # Shape
//!
//!   * Preprocessed trace: 2^16 rows × 1 column. Row `i` holds
//!     `Goldilocks::from(i)` — this is the canonical range table.
//!   * Main trace: 2^16 rows × 1 column. Row `i` holds `mult[i]` — the
//!     number of times table entry `i` is read by the *reader* AIR
//!     (`MvpTransferAir`) across all its u16 limb columns and all
//!     trace rows that contain limb data.
//!
//! # LogUp registration
//!
//!   * `Kind::Global("u16_range")`, `Direction::Send`
//!   * single-element tuple: `vec![preprocessed[0]]`
//!   * multiplicity expression: `main[0]` (the mult column)
//!
//! The matching `Direction::Receive` on `MvpTransferAir`'s limb columns
//! lands in a separate commit (see module docstring cross-reference
//! below).
//!
//! # Global cumulative sum
//!
//! Per Agent research report (confirmed at
//! `lookup/src/logup.rs::verify_global_final_value`): the batch-stark
//! prover/verifier check that the sum of per-instance cumulated values
//! across all AIRs participating in the interaction is zero. So the
//! Range16Air's Send running sum must cancel `MvpTransferAir`'s Receive
//! running sum for the proof to validate.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

extern crate alloc;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

/// `log2` of the 16-bit range-table height.
pub const LOG_RANGE_TABLE_HEIGHT: usize = 16;

/// Height of the 16-bit range table (= `2^16`).
pub const RANGE_TABLE_HEIGHT: usize = 1 << LOG_RANGE_TABLE_HEIGHT;

/// Width of the `Range16Air` main trace: a single multiplicity column.
pub const MAIN_TRACE_WIDTH: usize = 1;

/// Width of the `Range16Air` preprocessed trace: single range-table col.
pub const PREPROCESSED_TRACE_WIDTH: usize = 1;

/// Canonical `Kind::Global` interaction name for the u16 range lookup.
/// `MvpTransferAir`'s `Direction::Receive` MUST use this exact string.
pub const U16_RANGE_LOOKUP_NAME: &str = "u16_range";

/// Standalone 16-bit range-table AIR.
///
/// `num_lookups` tracks how many lookups have been registered on this
/// instance via `add_lookup_columns`; it's per-AIR local per the
/// `test_batch_stark_global_lookups_only` pattern in the vendored tree.
#[derive(Debug, Clone, Copy, Default)]
pub struct Range16Air {
    /// Per-AIR lookup-column allocation counter. Starts at 0; bumped by
    /// each `add_lookup_columns` call.
    num_lookups: usize,
}

impl Range16Air {
    /// Construct a fresh `Range16Air` with zero lookups registered yet.
    pub const fn new() -> Self {
        Self { num_lookups: 0 }
    }

    /// Materialize the preprocessed 16-bit range table.
    /// Column 0, row `i` = `Goldilocks::from(i)`.
    pub fn preprocessed_trace_values() -> RowMajorMatrix<Goldilocks> {
        let values: Vec<Goldilocks> = (0..RANGE_TABLE_HEIGHT as u64)
            .map(Goldilocks::from_u64)
            .collect();
        RowMajorMatrix::new(values, PREPROCESSED_TRACE_WIDTH)
    }

    /// Build the main trace (multiplicity column) given a slice of
    /// `u16` values that external AIRs will "receive" via the
    /// `Kind::Global("u16_range")` lookup.
    ///
    /// For each value `v` in `reads`, `mult[v]` is incremented.
    /// Entries not read have mult 0.
    ///
    /// Deterministic, no RNG.
    pub fn build_main_trace(reads: &[u16]) -> RowMajorMatrix<Goldilocks> {
        let mut mults = vec![0u64; RANGE_TABLE_HEIGHT];
        for &v in reads {
            mults[v as usize] += 1;
        }
        let values: Vec<Goldilocks> = mults.iter().copied().map(Goldilocks::from_u64).collect();
        RowMajorMatrix::new(values, MAIN_TRACE_WIDTH)
    }
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for Range16Air {
    fn width(&self) -> usize {
        MAIN_TRACE_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut values: Vec<F> = Vec::with_capacity(RANGE_TABLE_HEIGHT);
        for i in 0..RANGE_TABLE_HEIGHT as u64 {
            values.push(F::from_u64(i));
        }
        Some(RowMajorMatrix::new(values, PREPROCESSED_TRACE_WIDTH))
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(1)
    }
}

impl<AB> Air<AB> for Range16Air
where
    AB: AirBuilder<F = Goldilocks>,
{
    #[inline]
    fn eval(&self, _builder: &mut AB) {
        // No base-AIR constraints. All soundness lives in the LogUp
        // argument registered via `LookupAir::get_lookups` below.
    }
}

impl<F: Field> LookupAir<F> for Range16Air {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let idx = self.num_lookups;
        self.num_lookups += 1;
        vec![idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        self.num_lookups = 0;

        // Symbolic builder with a 1-col preprocessed + 1-col main layout.
        let symbolic = SymbolicAirBuilder::<F>::new(AirLayout {
            preprocessed_width: PREPROCESSED_TRACE_WIDTH,
            main_width: MAIN_TRACE_WIDTH,
            ..Default::default()
        });
        let main_window = symbolic.main();
        let main_local = main_window.current_slice();
        let prep_window = symbolic.preprocessed();
        let prep_local = prep_window.current_slice();

        // Element = preprocessed[0] (the table entry at this row).
        // Multiplicity = main[0] (the mult column).
        // Direction = Send.
        let table_entry = prep_local[0];
        let mult = main_local[0];

        let lookup_inputs = vec![(
            vec![table_entry.into()],
            mult.into(),
            Direction::Send,
        )];

        vec![LookupAir::register_lookup(
            self,
            Kind::Global(U16_RANGE_LOOKUP_NAME.to_string()),
            &lookup_inputs,
        )]
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

    #[test]
    fn build_main_trace_counts_reads_correctly() {
        // Three 42s, one 0, one 65535 — mult[0]=1, mult[42]=3, mult[65535]=1,
        // all others 0.
        let reads = [42u16, 42, 42, 0, u16::MAX];
        let trace = Range16Air::build_main_trace(&reads);
        assert_eq!(trace.height(), RANGE_TABLE_HEIGHT);
        assert_eq!(trace.width(), MAIN_TRACE_WIDTH);

        let get = |i: usize| -> Goldilocks {
            trace.row(i).unwrap().into_iter().next().unwrap()
        };
        assert_eq!(get(0), Goldilocks::from_u64(1));
        assert_eq!(get(42), Goldilocks::from_u64(3));
        assert_eq!(get(u16::MAX as usize), Goldilocks::from_u64(1));
        // A bystander entry should be zero.
        assert_eq!(get(1000), Goldilocks::from_u64(0));
    }

    #[test]
    fn lookup_air_registers_one_global_lookup() {
        let mut air = Range16Air::new();
        let lookups: Vec<Lookup<Goldilocks>> = LookupAir::<Goldilocks>::get_lookups(&mut air);
        assert_eq!(lookups.len(), 1);
        match &lookups[0].kind {
            Kind::Global(name) => assert_eq!(name, U16_RANGE_LOOKUP_NAME),
            Kind::Local => panic!("expected Kind::Global"),
        }
        assert_eq!(lookups[0].columns, vec![0]);
        assert_eq!(lookups[0].element_exprs.len(), 1);
        assert_eq!(lookups[0].element_exprs[0].len(), 1);
    }
}
