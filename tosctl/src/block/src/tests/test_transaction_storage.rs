// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;

#[test]
fn transaction_storage_snapshot_matches_native_accepted_original_encodings() {
    use crate::{read_single_root_boc, ShardAccount};
    let mut lines = include_str!("data/storage_stat/storage-encoding.tsv").lines();
    assert_eq!(lines.next(), Some("#native-account-storage-v1"));
    let mut count = 0;
    for line in lines {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 5);
        let shard_cell = read_single_root_boc(hex::decode(fields[1]).unwrap()).unwrap();
        let shard = ShardAccount::construct_from_cell(shard_cell.clone()).unwrap();
        let account = shard.read_account().unwrap();
        assert_eq!(
            account.serialize().unwrap().repr_hash(),
            shard_cell.reference(0).unwrap().repr_hash(),
            "{}",
            fields[0]
        );
        let storage = account.stuff().unwrap().storage.serialize().unwrap();
        assert_eq!(storage.repr_hash().as_hex_string(), fields[3], "{}", fields[0]);
        let original = account.snapshot_transaction_storage(16).unwrap().original.unwrap();
        assert_eq!(original.root_bits, fields[2].parse::<usize>().unwrap(), "{}", fields[0]);
        let references: Vec<_> = original.references.iter().map(UInt256::as_hex_string).collect();
        let expected: Vec<_> = fields[4].split(',').filter(|value| *value != "-").collect();
        assert_eq!(references, expected, "{}", fields[0]);
        count += 1;
    }
    assert_eq!(count, 282);
}

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
fn transaction_option_normalization_preserves_original_and_nonzero_fields() {
    let mut account = account_with_counters(255, 1, 1000, false, None);
    let state = account.state_init_mut().unwrap();
    state.fixed_prefix_length = Some(crate::Number5::new(0).unwrap());
    state.special = Some(crate::TickTock { tick: false, tock: false });
    let raw_hash = state.hash().unwrap();
    let mut normalized = state.clone();
    normalized.fixed_prefix_length = None;
    normalized.special = None;
    let canonical_hash = normalized.hash().unwrap();
    assert_ne!(raw_hash, canonical_hash);
    let snapshot = account.snapshot_transaction_storage(16).unwrap();
    assert_eq!(snapshot.original.as_ref().unwrap().root_bits, 90);
    let mut explicit = account.clone();
    explicit.try_freeze().unwrap();
    assert_eq!(explicit.frozen_hash(), Some(&raw_hash));
    account.try_freeze_for_transaction().unwrap();
    assert_eq!(account.frozen_hash(), Some(&canonical_hash));
    assert_eq!(snapshot.original.as_ref().unwrap().root_bits, 90);
    account.finalize_transaction_storage(snapshot, 16, 26).unwrap();
    assert_eq!(account.storage_info().unwrap().used().cells(), 1);
    assert_eq!(account.storage_info().unwrap().used().bits(), 335);

    for flags in
        [crate::TickTock { tick: true, tock: false }, crate::TickTock { tick: false, tock: true }]
    {
        let mut account = account_with_counters(255, 1, 1000, false, None);
        let state = account.state_init_mut().unwrap();
        state.fixed_prefix_length = Some(crate::Number5::new(30).unwrap());
        state.special = Some(flags.clone());
        let original_hash = state.hash().unwrap();
        let snapshot = account.snapshot_transaction_storage(16).unwrap();
        account.finalize_transaction_storage(snapshot, 16, 26).unwrap();
        assert_eq!(account.state_init().unwrap().hash().unwrap(), original_hash);
        assert_eq!(account.storage_info().unwrap().used().bits(), 1000);
    }
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
                assert!(result.unwrap_err().to_string().contains("transaction storage bit delta"));
                assert_eq!(account.storage_info().unwrap().used().bits(), old_bits);
                assert_eq!(account.storage_info().unwrap().used().cells(), 1);
                // Failure leaves advertised metadata intact; the reconciled
                // actual cache remains usable after selecting another state.
                account.set_balance(CurrencyCollection::with_coins(before));
                let retry = account.snapshot_transaction_storage(16).unwrap();
                account.finalize_transaction_storage(retry, 16, 26).unwrap();
                assert_eq!(account.storage_info().unwrap().used().bits(), old_bits);
            }
        }
    }
}

#[test]
fn transaction_storage_excludes_extra_currencies_from_version_ten() {
    for version in [9, 10, 11, 16] {
        let mut account = account_with_counters(255, 25, 1000, false, None);
        let snapshot = account.snapshot_transaction_storage(version).unwrap();
        let mut balance = CurrencyCollection::with_coins(255);
        balance.set_other(17, 1234567).unwrap();
        account.set_balance(balance);
        let measured = account.measure_storage_stat(version).unwrap();
        // One ordinary dictionary leaf is added to root/code/empty-data.
        assert_eq!(measured.cells(), if version < 10 { 4 } else { 3 });
        assert_eq!(account.storage_info().unwrap().used().cells(), 25);
        account.finalize_transaction_storage(snapshot, version, 3).unwrap();
        assert_eq!(
            account.storage_info().unwrap().used().cells(),
            if version < 10 { 4 } else { 25 }
        );
        if version < 10 {
            // Independent unique graph walk of serialized AccountStorage,
            // including its currency dictionary. No production cache oracle.
            let root = account.stuff().unwrap().storage.serialize().unwrap();
            let mut pending = vec![root];
            let mut unique = std::collections::BTreeMap::new();
            while let Some(cell) = pending.pop() {
                if unique.insert(cell.repr_hash(), cell.bit_length() as u64).is_none() {
                    for index in 0..cell.references_count() {
                        pending.push(cell.reference(index).unwrap());
                    }
                }
            }
            assert_eq!(account.storage_info().unwrap().used().bits(), unique.values().sum::<u64>());
        } else {
            assert_eq!(account.storage_info().unwrap().used().bits(), 1000);
        }
        assert!(account.dict_hash().is_none());
    }
}

#[test]
fn transaction_storage_distinguishes_creation_deletion_and_uninit() {
    let mut absent = Account::default();
    let snapshot = absent.snapshot_transaction_storage(16).unwrap();
    absent.finalize_transaction_storage(snapshot, 16, 0).unwrap();
    assert!(absent.is_none());

    let snapshot = absent.snapshot_transaction_storage(16).unwrap();
    let mut created = account_with_counters(255, 0, 0, false, None);
    created.finalize_transaction_storage(snapshot, 16, 3).unwrap();
    assert_eq!(created.storage_info().unwrap().used().cells(), 3);
    assert!(created.dict_hash().is_some());

    let snapshot = created.snapshot_transaction_storage(16).unwrap();
    let mut deleted = Account::default();
    deleted.finalize_transaction_storage(snapshot, 16, 0).unwrap();
    assert!(deleted.is_none());

    let snapshot = created.snapshot_transaction_storage(16).unwrap();
    created.uninit_account();
    created.finalize_transaction_storage(snapshot, 16, 1).unwrap();
    assert!(created.is_uninit());
    assert_eq!(created.storage_info().unwrap().used().cells(), 1);
    assert_eq!(created.storage_stat().unwrap().total_cells(), 0);
    // Empty native StorageStatDict hash is zero, not the hash of an empty cell.
    assert_eq!(created.dict_hash(), Some(&UInt256::default()));
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
