/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! `accrued_storage_fee` against the node. The vector file's expected values are
//! checked against the node's own `StoragePrices::compute_storage_fees` by
//! `test-storage-fee-vectors` (crypto/block), so agreeing with the file is
//! agreeing with the node.

use super::*;

pub(crate) const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../crypto/block/storage-fee-vectors.tsv"
));

pub(crate) struct Row {
    pub name: String,
    pub now: u32,
    pub last_paid: u32,
    pub cells: u64,
    pub bits: u64,
    pub special: bool,
    pub masterchain: bool,
    pub periods: Vec<StoragePrices>,
    pub expected: BigInt,
}

fn flag(text: &str) -> bool {
    match text {
        "0" => false,
        "1" => true,
        other => panic!("not a 0/1 flag: {other:?}"),
    }
}

fn periods(text: &str) -> Vec<StoragePrices> {
    if text == "-" {
        return Vec::new();
    }
    text.split(',')
        .map(|period| {
            let fields: Vec<&str> = period.split(':').collect();
            assert_eq!(fields.len(), 5, "a period needs five fields: {period:?}");
            StoragePrices {
                utime_since: fields[0].parse().expect("utime_since"),
                bit_price_ps: fields[1].parse().expect("bit_price_ps"),
                cell_price_ps: fields[2].parse().expect("cell_price_ps"),
                mc_bit_price_ps: fields[3].parse().expect("mc_bit_price_ps"),
                mc_cell_price_ps: fields[4].parse().expect("mc_cell_price_ps"),
            }
        })
        .collect()
}

pub(crate) fn rows(text: &str) -> Vec<Row> {
    let rows: Vec<Row> = text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 9, "a row needs nine fields: {line:?}");
            Row {
                name: fields[0].to_string(),
                now: fields[1].parse().expect("now"),
                last_paid: fields[2].parse().expect("last_paid"),
                cells: fields[3].parse().expect("cells"),
                bits: fields[4].parse().expect("bits"),
                special: flag(fields[5]),
                masterchain: flag(fields[6]),
                periods: periods(fields[7]),
                expected: fields[8].parse().expect("expected"),
            }
        })
        .collect();
    assert!(!rows.is_empty(), "the vector file has no rows");
    rows
}

#[test]
fn every_vector_row_matches_the_node() {
    let rows = rows(VECTORS);
    let mut wrong = Vec::new();
    for row in &rows {
        let fee = accrued_storage_fee(
            &row.periods,
            row.cells,
            row.bits,
            row.last_paid,
            row.now,
            row.special,
            row.masterchain,
        )
        .unwrap_or_else(|e| panic!("{}: {e}", row.name));
        if fee != row.expected {
            wrong.push(format!("{}: computed {fee}, the node charges {}", row.name, row.expected));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} rows disagree:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
}

fn period(since: u32, cell: u64, bit: u64, mc_cell: u64, mc_bit: u64) -> StoragePrices {
    StoragePrices {
        utime_since: since,
        bit_price_ps: bit,
        cell_price_ps: cell,
        mc_bit_price_ps: mc_bit,
        mc_cell_price_ps: mc_cell,
    }
}

/// A special account is never charged, even with storage that would be.
#[test]
fn a_special_account_accrues_nothing() {
    let prices = [period(0, 500, 1, 500_000, 1_000)];
    let charged = accrued_storage_fee(&prices, 10, 1_000, 100, 1_000, false, true).unwrap();
    assert!(charged > BigInt::default(), "the same storage is chargeable: {charged}");
    let special = accrued_storage_fee(&prices, 10, 1_000, 100, 1_000, true, true).unwrap();
    assert_eq!(special, BigInt::default());
}

/// The largest inputs: every product exceeds 128 bits before the final shift.
#[test]
fn the_largest_inputs_do_not_overflow() {
    let max = u64::MAX;
    let prices = [period(0, max, max, max, max)];
    let one_second = accrued_storage_fee(&prices, max, max, 1, 2, false, true).unwrap();
    let max_big = BigInt::from(max);
    let per_second: BigInt = &max_big * &max_big * 2;
    let expected = (per_second.clone() + 0xffff) >> 16u8;
    assert_eq!(one_second, expected);
    assert!(one_second > BigInt::from(u128::MAX >> 16), "beyond what a u128 product holds");

    let whole_range = accrued_storage_fee(&prices, max, max, 1, u32::MAX, false, false).unwrap();
    let expected = (per_second * BigInt::from(u32::MAX - 1) + 0xffff) >> 16u8;
    assert_eq!(whole_range, expected);
    assert!(whole_range > BigInt::from(u128::MAX), "past u128 itself");
}

fn refused(prices: &[StoragePrices], last_paid: u32, now: u32) -> String {
    match accrued_storage_fee(prices, 1, 1, last_paid, now, false, true) {
        Ok(fee) => panic!("an unordered price table was accepted: fee {fee}"),
        Err(e) => {
            let text = e.to_string();
            assert!(text.contains("strictly increasing"), "refused for its order, not {text}");
            text
        }
    }
}

/// A table the node would not load is refused, including in the cases that would
/// otherwise return zero before looking at the periods.
#[test]
fn an_unordered_price_table_is_refused() {
    let duplicate = [period(0, 1, 1, 1, 1), period(100, 1, 1, 1, 1), period(100, 2, 2, 2, 2)];
    let descending = [period(0, 1, 1, 1, 1), period(200, 1, 1, 1, 1), period(100, 2, 2, 2, 2)];
    for prices in [&duplicate[..], &descending[..]] {
        refused(prices, 10, 300);
        // now not after last_paid
        refused(prices, 300, 300);
        refused(prices, 300, 10);
        // never paid
        refused(prices, 0, 300);
    }
    // now not after the first period's start
    let starts_late = [period(500, 1, 1, 1, 1), period(200, 1, 1, 1, 1)];
    refused(&starts_late, 10, 300);
    // special accounts too
    assert!(accrued_storage_fee(&duplicate, 1, 1, 10, 300, true, true).is_err());
    // and an ordered table with the same periods is accepted
    let ordered = [period(0, 1, 1, 1, 1), period(100, 1, 1, 1, 1), period(200, 2, 2, 2, 2)];
    assert!(accrued_storage_fee(&ordered, 1, 1, 10, 300, false, true).is_ok());
}
