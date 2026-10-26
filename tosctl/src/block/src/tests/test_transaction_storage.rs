// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn account_with_counters(
    balance: u64,
    cells: u64,
    bits: u64,
    master: bool,
    hash: Option<UInt256>,
) -> Account {
    let address =
        MsgAddressInt::with_standart(None, if master { -1 } else { 0 }, [0x45; 32].into()).unwrap();
    let mut init = StateInit::default();
    init.set_code(BuilderData::with_raw(vec![0xf8, 0x00], 16).unwrap().into_cell().unwrap());
    init.set_data(Cell::default());
    let mut info = StorageInfo::with_values(1_780_000_000, None);
    info.used = StorageUsed::with_values_checked(cells, bits).unwrap();
    info.storage_extra.dict_hash = hash;
    Account::with_storage(
        &address,
        &info,
        &AccountStorage::active(0, CurrencyCollection::with_coins(balance), init),
    )
}

#[test]
fn transaction_storage_applies_only_the_final_net_bit_delta() {
    // Coin widths: 255 takes one byte, 256 two. The four-bit length field is fixed.
    for (before, after, old_bits, expected) in [
        (255, 255, 0, Some(0)),
        (255, 256, 0, Some(8)),
        (256, 255, 0, None),
        (256, 255, 16, Some(8)),
    ] {
        let mut account = account_with_counters(before, 1, old_bits, false, None);
        let snapshot = account.snapshot_transaction_storage(16).unwrap();
        account.set_balance(CurrencyCollection::with_coins(after));
        let result = account.finalize_transaction_storage(snapshot, 16, 26);
        match expected {
            Some(bits) => {
                result.unwrap();
                assert_eq!(account.storage_info().unwrap().used().bits(), bits);
                assert_eq!(account.storage_info().unwrap().used().cells(), 1);
            }
            None => {
                assert!(result.unwrap_err().to_string().contains("transaction storage bit delta"))
            }
        }
    }
}

#[test]
fn transaction_storage_retains_original_hash_and_checks_native_range() {
    let hash = UInt256::from([0x55; 32]);
    for master in [false, true] {
        let mut account = account_with_counters(255, 26, 1000, master, Some(hash.clone()));
        let snapshot = account.snapshot_transaction_storage(16).unwrap();
        account.finalize_transaction_storage(snapshot, 16, 1000).unwrap();
        assert_eq!(account.storage_info().unwrap().used().cells(), 26);
        assert_eq!(account.storage_info().unwrap().used().bits(), 1000);
        assert_eq!(account.dict_hash(), if master { None } else { Some(&hash) });
    }
    let mut account = account_with_counters(255, 1, 0xffff_ffff_ffff, false, None);
    let snapshot = account.snapshot_transaction_storage(16).unwrap();
    account.set_balance(CurrencyCollection::with_coins(256));
    assert!(account
        .finalize_transaction_storage(snapshot, 16, 26)
        .unwrap_err()
        .to_string()
        .contains("native VarUInteger7"));
    let snapshot = account.snapshot_transaction_storage(16).unwrap();
    assert!(account
        .finalize_transaction_storage(snapshot, 15, 26)
        .unwrap_err()
        .to_string()
        .contains("version mismatch"));
}
