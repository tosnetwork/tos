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
    use crate::{AccountStorageStat, BuilderData, Cell};
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

#[test]
fn native_saturated_merkle_depth_survives_cache_and_dictionary_roundtrips() {
    use crate::{
        AccountStorage, AccountStorageStat, BuilderData, Cell, CurrencyCollection, MerkleProof,
        Serializable, StateInit, StorageUsed,
    };
    // Authored depths/cell counts/bits and acceptance were asserted by the
    // C++ AccountStorageStat probe before freezing these root/dictionary hashes.
    // Native permits depth2; its two-bit depth3 sentinel rejects all deeper trees.
    let cases = [
        (
            0usize,
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "e4b7c555acb5aaac7a147a57cdcdc188a1793e40e545d4439f02e1e8bf4c87b6",
        ),
        (
            1usize,
            "c4090e1912b84dabee7b62c4ea9ef268c0a198c81855aacb2ba458d59a2f9a88",
            "d0d88451f320b304fb4559c6021dd2c26af4e46f1a45cd0ecae15ee19f7cf696",
        ),
        (
            2usize,
            "ec8672e628b89bab7e102bf5d38277c346f1b967b43920a83e7c518260c87cb2",
            "2eb9f64e7f3233fa6f2b51f9462afde38b90a3b818dd1fa8f5c0e16ad0ef5db6",
        ),
        (
            3usize,
            "97b2d492cc85849a717a246c8bee531a759553c640755bc784c41641ccc4ec50",
            "e3de4ab31291b82449fc6a898983d302c62ddc7d7d83fdca2aba15ef5739cedb",
        ),
        (
            4usize,
            "5c28b014ffead37c6f2a78550273fbc789847fa6b8a79b517d62fd4d42397170",
            "74828a155558b8475cc4719321a2d86f221a3b161908647e824e6fc541eb1729",
        ),
        (
            255usize,
            "8ba0089638ea0ea06792e92ef6a731b24130dc57dfbaa35ee9a7eb66f7db5fc4",
            "4d6104f30d3185daa5600977c8c75ef6e0f2c7aa2ece89f5e8fbdd9d808bd958",
        ),
        (
            256usize,
            "1717e09208a11bd866faeb787f5df5b0e8d91528c4dcb5937e0cfe74319c533c",
            "b1cc22880e3556dc833145d2db0007138c43f74d232b32583a66ebfc80fe7b46",
        ),
        (
            257usize,
            "2cdee7b908c917182287cc9d59ddd711f1c3b59d27a70b0ed5b3de10689e6e29",
            "c609905b6964071413c92935d624b683ad44ece27d035c98a364797b283a0a35",
        ),
    ];
    let mut cache = AccountStorageStat::new();
    for (depth, root_hash, dict_hash) in cases {
        let mut root = Cell::default();
        for _ in 0..depth {
            root = MerkleProof::create(&root, |_| true).unwrap().serialize().unwrap();
        }
        assert_eq!(root.repr_hash().as_hex_string(), root_hash);
        cache.replace_roots(vec![root.clone()]).unwrap();
        assert_eq!(cache.total_cells(), depth as u64 + 1);
        assert_eq!(cache.total_bits(), depth as u64 * 280);
        assert_eq!(cache.max_merkle_depth().unwrap(), depth.min(3) as u8);
        let dict = cache.dict_root().unwrap().cloned().unwrap();
        assert_eq!(dict.repr_hash().as_hex_string(), dict_hash);
        let mut fresh = AccountStorageStat::new();
        fresh.replace_roots(vec![root.clone()]).unwrap();
        assert_eq!(fresh.dict_root().unwrap().unwrap().repr_hash(), dict.repr_hash());

        let mut init = StateInit::default();
        init.set_data(root.clone());
        let storage = AccountStorage::active(0, CurrencyCollection::with_coins(255), init);
        // AccountStorage root: LT64 + coin length4 + coin8 + extra1 + state6.
        let used =
            StorageUsed::with_values_checked(depth as u64 + 2, depth as u64 * 280 + 83).unwrap();
        let mut imported = AccountStorageStat::try_from_dict(dict, &storage, &used).unwrap();
        assert_eq!(imported.max_merkle_depth().unwrap(), depth.min(3) as u8);
        let mut builder = BuilderData::with_raw(vec![0x42], 8).unwrap();
        builder.checked_append_reference(root.clone()).unwrap();
        let plain_parent = builder.into_cell().unwrap();
        imported.replace_roots(vec![plain_parent]).unwrap();
        assert_eq!(imported.max_merkle_depth().unwrap(), depth.min(3) as u8);
        assert_eq!(imported.total_cells(), depth as u64 + 2);
        assert_eq!(imported.total_bits(), depth as u64 * 280 + 8);
        imported.replace_roots(vec![Cell::default()]).unwrap();
        assert_eq!(imported.max_merkle_depth().unwrap(), 0);
        assert_eq!(imported.total_cells(), 1);
        imported.replace_roots(vec![root]).unwrap();
        assert_eq!(imported.max_merkle_depth().unwrap(), depth.min(3) as u8);
        assert_eq!(imported.dict_root().unwrap().unwrap().repr_hash().as_hex_string(), dict_hash);
    }
}

#[test]
fn saturated_merkle_updates_use_the_deeper_child_without_counting_plain_parents() {
    use crate::{AccountStorageStat, BuilderData, Cell, MerkleProof, MerkleUpdate, Serializable};
    for proof_depth in [0usize, 1, 2, 3, 255, 256] {
        let mut deep = Cell::default();
        for _ in 0..proof_depth {
            deep = MerkleProof::create(&deep, |_| true).unwrap().serialize().unwrap();
        }
        for reverse in [false, true] {
            let (old, new) = if reverse {
                (deep.clone(), Cell::default())
            } else {
                (Cell::default(), deep.clone())
            };
            let update = MerkleUpdate {
                old_hash: old.repr_hash(),
                new_hash: new.repr_hash(),
                old_depth: old.repr_depth(),
                new_depth: new.repr_depth(),
                old,
                new,
            }
            .serialize()
            .unwrap();
            let mut builder = BuilderData::with_raw(vec![0x42], 8).unwrap();
            builder.checked_append_reference(update).unwrap();
            let parent = builder.into_cell().unwrap();
            let mut cache = AccountStorageStat::new();
            cache.replace_roots(vec![parent]).unwrap();
            assert_eq!(cache.max_merkle_depth().unwrap(), (proof_depth + 1).min(3) as u8);
            // Unique empty leaf + proof nodes + update + ordinary parent.
            assert_eq!(cache.total_cells(), proof_depth as u64 + 3);
            assert_eq!(cache.total_bits(), proof_depth as u64 * 280 + 552 + 8);
            assert!(cache.dict_root().unwrap().is_some());
        }
    }
}
