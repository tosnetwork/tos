/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The executor's storage fee against the node. Every expected value comes from
//! crypto/block/storage-fee-vectors.tsv, whose rows `test-storage-fee-vectors`
//! checks against the node's own `StoragePrices::compute_storage_fees`.

use super::*;
use crate::{ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use chain_block::{
    Account, AccountStorage, Cell, CurrencyCollection, Deserializable, InternalMessageHeader,
    Message, Serializable, StateInit, TransactionDescr,
};
use num::BigInt;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../crypto/block/storage-fee-vectors.tsv"
));

struct Row {
    name: String,
    now: u32,
    last_paid: u32,
    cells: u64,
    bits: u64,
    special: bool,
    masterchain: bool,
    periods: Vec<StoragePrices>,
    expected: u128,
}

fn row_periods(text: &str) -> Vec<StoragePrices> {
    if text == "-" {
        return Vec::new();
    }
    text.split(',')
        .map(|period| {
            let f: Vec<u64> =
                period.split(':').map(|v| v.parse().expect("a price field")).collect();
            assert_eq!(f.len(), 5, "a period needs five fields: {period:?}");
            StoragePrices {
                utime_since: u32::try_from(f[0]).expect("utime_since"),
                bit_price_ps: f[1],
                cell_price_ps: f[2],
                mc_bit_price_ps: f[3],
                mc_cell_price_ps: f[4],
            }
        })
        .collect()
}

fn rows() -> Vec<Row> {
    let rows: Vec<Row> = VECTORS
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 9, "a row needs nine fields: {line:?}");
            Row {
                name: f[0].to_string(),
                now: f[1].parse().expect("now"),
                last_paid: f[2].parse().expect("last_paid"),
                cells: f[3].parse().expect("cells"),
                bits: f[4].parse().expect("bits"),
                special: f[5] == "1",
                masterchain: f[6] == "1",
                periods: row_periods(f[7]),
                expected: f[8].parse().expect("expected"),
            }
        })
        .collect();
    assert!(!rows.is_empty(), "the vector file has no rows");
    rows
}

fn row(name: &str) -> Row {
    rows().into_iter().find(|row| row.name == name).unwrap_or_else(|| panic!("no row {name}"))
}

/// ConfigParam 18 keyed by each period's start, as the node requires.
fn config_with_prices(periods: &[StoragePrices]) -> ConfigParams {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/real_boc/default_config.boc");
    let mut params = ConfigParams::construct_from_file(path).expect("the fixture configuration");
    let mut param = ConfigParam18::default();
    for period in periods {
        param.map.set(&period.utime_since, period).expect("a period");
    }
    params.set_config(ConfigParamEnum::ConfigParam18(param)).expect("param 18");
    params
}

/// Every row the executor computes (it never charges a special account, so it
/// is never asked for one) through the storage price table it holds.
#[test]
fn the_executor_charges_what_the_node_charges() {
    let mut wrong = Vec::new();
    let mut checked = 0;
    for row in rows().iter().filter(|row| !row.special) {
        let prices = AccStoragePrices { prices: row.periods.clone() };
        let fee = prices
            .calc_storage_fees(row.cells, row.bits, row.last_paid, row.now, row.masterchain)
            .unwrap_or_else(|e| panic!("{}: {e}", row.name));
        if fee != row.expected {
            wrong.push(format!("{}: executor {fee}, node {}", row.name, row.expected));
        }
        checked += 1;
    }
    assert!(checked >= 10, "only {checked} rows reached the executor");
    assert!(wrong.is_empty(), "{} rows disagree:\n{}", wrong.len(), wrong.join("\n"));
}

/// A fee beyond u128 is an error, not a truncated or wrapped number.
#[test]
fn a_fee_beyond_u128_is_refused() {
    let max = u64::MAX;
    let prices = AccStoragePrices {
        prices: vec![StoragePrices {
            utime_since: 0,
            bit_price_ps: max,
            cell_price_ps: max,
            mc_bit_price_ps: max,
            mc_cell_price_ps: max,
        }],
    };
    let accrued =
        chain_block::accrued_storage_fee(&prices.prices, max, max, 1, u32::MAX, false, true)
            .expect("the helper computes it");
    assert!(accrued > BigInt::from(u128::MAX), "the case is beyond u128: {accrued}");
    assert!(prices.calc_storage_fees(max, max, 1, u32::MAX, true).is_err());
    // one second still fits
    let one_second = prices.calc_storage_fees(1, 1, 1, 2, true).expect("a small fee");
    assert_eq!(
        BigInt::from(one_second),
        chain_block::accrued_storage_fee(&prices.prices, 1, 1, 1, 2, false, true).unwrap()
    );
}

const DUE: u64 = 7;
const BALANCE: u64 = 10_000_000_000;

fn account_for(row: &Row, config: &BlockchainConfig) -> Account {
    let workchain = if row.masterchain { -1 } else { 0 };
    let address = MsgAddressInt::with_standart(None, workchain, [0x5a; 32].into()).unwrap();
    let mut account = Account::with_storage(
        &address,
        &StorageInfo::with_values(row.last_paid, Some(Coins::from(DUE))),
        &AccountStorage::active(0, CurrencyCollection::with_coins(BALANCE), StateInit::default()),
    );
    account.set_code(Cell::default());
    account.set_data(Cell::default());
    account
        .update_storage_stat(config.size_limits_config().acc_state_cells_for_storage_dict)
        .unwrap();
    account
}

/// A whole transaction under a multi-period table, by an account that already owes
/// storage: its storage phase collects the node's accrued fee plus the debt.
#[test]
fn a_transaction_collects_the_node_fee_and_the_existing_debt() {
    let row = row("transaction-account-mc");
    let config = BlockchainConfig::with_config(config_with_prices(&row.periods)).unwrap();
    let mut account = account_for(&row, &config);
    let used = account.storage_info().expect("storage").used();
    assert_eq!(
        (used.cells(), used.bits()),
        (row.cells, row.bits),
        "the row describes this account's storage"
    );
    assert_eq!(account.due_payment(), Some(&Coins::from(DUE)));
    // what the executor reads from the configuration, before anything runs
    let accrued = config
        .calc_storage_fees(account.storage_info().expect("storage"), row.masterchain, row.now)
        .unwrap();
    assert_eq!(accrued, Coins::try_from(row.expected).unwrap(), "accrued from the configuration");
    assert!(
        !config.is_special_account(row.masterchain, account.get_id().unwrap()).unwrap(),
        "the account pays storage"
    );

    let mut header = InternalMessageHeader::with_addresses(
        MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap(),
        account.get_addr().unwrap().clone(),
        CurrencyCollection::with_coins(1_000_000_000u64),
    );
    header.bounce = false;
    header.created_lt = 1_000;
    let message = Message::with_int_header(header);
    let params = ExecuteParams {
        block_unixtime: row.now,
        block_lt: 2_000_000_000,
        last_tr_lt: 2_000_000_001,
        ..ExecuteParams::default()
    };
    let executor = OrdinaryTransactionExecutor::new(config);
    let transaction = executor
        .execute_with_params(Some(message.serialize().unwrap()), &mut account, params)
        .expect("the transaction executes");
    let TransactionDescr::Ordinary(description) = transaction.read_description().unwrap() else {
        panic!("an ordinary transaction");
    };
    let storage = description.storage_ph.expect("a storage phase");
    let expected = row.expected + u128::from(DUE);
    assert_eq!(storage.storage_fees_collected, Coins::try_from(expected).unwrap());
    assert_eq!(storage.storage_fees_due, None);
    assert_eq!(account.due_payment(), None, "the debt is paid");
    assert_eq!(account.last_paid(), row.now);
}
