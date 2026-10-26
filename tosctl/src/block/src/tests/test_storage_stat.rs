/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{Account, Deserializable, DICT_HASH_MIN_CELLS};

#[test]
fn test_storage_stat() {
    let acc_state1 = include_bytes!("data/storage_stat/acc.boc");
    let mut acc1 = Account::construct_from_bytes(acc_state1).unwrap();
    let storage_info1 = acc1.storage_info().unwrap().clone();

    // calc dictionary and check its hash
    let dict_root1 = acc1.update_storage_stat(DICT_HASH_MIN_CELLS).unwrap().unwrap();
    assert_eq!(&dict_root1.repr_hash(), storage_info1.dict_hash().unwrap());
    assert_eq!(storage_info1.used(), acc1.storage_info().unwrap().used());

    // import storage stat dict and check again
    let mut acc1 = Account::construct_from_bytes(acc_state1).unwrap();
    acc1.import_storage_stat_dict(dict_root1.clone()).unwrap();

    let dict_root1 = acc1.update_storage_stat(DICT_HASH_MIN_CELLS).unwrap().unwrap();
    assert_eq!(&dict_root1.repr_hash(), storage_info1.dict_hash().unwrap());
    assert_eq!(storage_info1.used(), acc1.storage_info().unwrap().used());

    // change account state and update dictionary
    let acc_state2 = include_bytes!("data/storage_stat/acc1.boc");
    let mut acc2 = Account::construct_from_bytes(acc_state2).unwrap();
    assert!(acc2.import_storage_stat_dict(dict_root1).is_err());
    let storage_info2 = acc2.storage_info().unwrap();

    *acc1.state_init_mut().unwrap() = acc2.state_init().unwrap().clone();

    let dict_root2 = acc1.update_storage_stat(DICT_HASH_MIN_CELLS).unwrap().unwrap();
    assert_eq!(&dict_root2.repr_hash(), storage_info2.dict_hash().unwrap());
    assert_eq!(storage_info2.used(), acc1.storage_info().unwrap().used());
}

#[test]
fn measured_cache_tracks_duplicate_root_multiplicity() {
    use crate::{
        AccountStorage, BuilderData, CurrencyCollection, MsgAddressInt, StateInit, StorageInfo,
    };
    let shared = BuilderData::with_raw(vec![0x42], 8).unwrap().into_cell().unwrap();
    let mut init = StateInit::default();
    init.set_code(shared.clone());
    init.set_data(shared);
    let address = MsgAddressInt::with_standart(None, 0, [0x45; 32].into()).unwrap();
    let mut account = Account::with_storage(
        &address,
        &StorageInfo::with_values(1_780_000_000, None),
        &AccountStorage::active(0, CurrencyCollection::with_coins(100_000_000_000), init),
    );
    account.measure_storage_stat(16).unwrap();
    assert_eq!(account.storage_stat().unwrap().total_cells(), 1);
    let data = BuilderData::with_raw(vec![0x43], 8).unwrap().into_cell().unwrap();
    assert!(account.set_data(data));
    account.measure_storage_stat(16).unwrap();
    assert_eq!(account.storage_stat().unwrap().total_cells(), 2);
    let code = BuilderData::with_raw(vec![0x44], 8).unwrap().into_cell().unwrap();
    assert!(account.set_code(code));
    account.measure_storage_stat(16).unwrap();
    // The original shared root has no remaining edge. Exactly two cells exist.
    assert_eq!(account.storage_stat().unwrap().total_cells(), 2);
}

#[test]
fn cached_root_changes_match_fresh_multiset_and_unique_graph() {
    use crate::{AccountStorageStat, BuilderData, Cell, IBitstring};
    use std::collections::BTreeMap;
    let a = BuilderData::with_raw(vec![0x41], 8).unwrap().into_cell().unwrap();
    let b = BuilderData::with_raw(vec![0x42], 8).unwrap().into_cell().unwrap();
    let mut builder = BuilderData::with_raw(vec![0x43], 8).unwrap();
    builder.checked_append_reference(a.clone()).unwrap();
    builder.checked_append_reference(b.clone()).unwrap();
    let c = builder.into_cell().unwrap();
    let mut builder = BuilderData::with_raw(vec![0x44], 8).unwrap();
    builder.checked_append_reference(c.clone()).unwrap();
    let d = builder.into_cell().unwrap();
    let sequence = [
        vec![a.clone(), a.clone()],
        vec![a.clone(), b.clone()],
        vec![c.clone(), b.clone()],
        vec![b.clone(), c.clone()],
        vec![a.clone(), b.clone()],
        vec![a.clone(), a.clone()],
        vec![a.clone(), a.clone(), a.clone()],
        vec![a.clone()],
        vec![a.clone(), c.clone()],
        vec![c.clone(), d.clone()],
        vec![],
        vec![d, a],
    ];
    let mut cache = AccountStorageStat::new();
    for roots in sequence {
        cache.replace_roots(roots.clone()).unwrap();
        let mut fresh = AccountStorageStat::new();
        fresh.replace_roots(roots.clone()).unwrap();
        let mut unique = BTreeMap::new();
        let mut pending: Vec<Cell> = roots.clone();
        while let Some(cell) = pending.pop() {
            if unique.insert(cell.repr_hash(), cell.bit_length()).is_none() {
                for index in 0..cell.references_count() {
                    pending.push(cell.reference(index).unwrap());
                }
            }
        }
        assert_eq!(cache.total_cells(), unique.len() as u64);
        assert_eq!(cache.total_bits(), unique.values().sum::<usize>() as u64);
        assert_eq!(cache.max_merkle_depth().unwrap(), fresh.max_merkle_depth().unwrap());
        assert_eq!(
            cache.dict_root().unwrap().map(Cell::repr_hash),
            fresh.dict_root().unwrap().map(Cell::repr_hash)
        );
        if roots.is_empty() {
            assert!(cache.cache.is_empty());
            assert!(cache.dict_root().unwrap().is_none());
            assert_eq!(cache.max_merkle_depth().unwrap(), 0);
        }
    }
}
