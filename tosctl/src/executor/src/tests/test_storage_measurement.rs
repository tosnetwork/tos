// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Size checks inspect the actual candidate graph without publishing its metadata.
use super::*;
use crate::OrdinaryTransactionExecutor;
use chain_block::{AccountStorage, BuilderData, ConfigParams, StateInit, StorageInfo};

#[test]
fn size_measurement_preserves_visible_storage_metadata() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/real_boc/default_config.boc");
    let config =
        BlockchainConfig::with_config(ConfigParams::construct_from_file(path).unwrap()).unwrap();
    for maximum in [1000, 4] {
        let address = MsgAddressInt::with_standart(None, 0, [0x45; 32].into()).unwrap();
        let mut init = StateInit::default();
        init.set_code(BuilderData::with_raw(vec![0xf8, 0x00], 16).unwrap().into_cell().unwrap());
        init.set_data(Cell::default());
        // Deliberately small advertised counters must never bypass real size checks.
        let mut account = Account::with_storage(
            &address,
            &StorageInfo::with_values(1_780_000_000, None),
            &AccountStorage::active(0, CurrencyCollection::with_coins(100_000_000_000), init),
        );
        let original = account.storage_info().unwrap().serialize().unwrap().repr_hash();
        let mut data = Cell::default();
        for depth in 0..12u8 {
            let mut builder = BuilderData::with_raw(vec![depth], 8).unwrap();
            builder.checked_append_reference(data).unwrap();
            data = builder.into_cell().unwrap();
        }
        assert!(account.set_data(data));
        let mut limits = config.size_limits_config().clone();
        limits.max_acc_state_cells = maximum;
        let fits = check_account_size_limits(&limits, 16, &mut account).unwrap();
        assert_eq!(fits, maximum == 1000);
        assert!(account.storage_stat().unwrap().total_cells() >= 13);
        assert_eq!(
            account.storage_info().unwrap().serialize().unwrap().repr_hash(),
            original,
            "candidate measurement must not publish storage metadata"
        );
        // Restoring the selected data must reconcile the same actual cache.
        assert!(account.set_data(Cell::default()));
        assert!(check_account_size_limits(&limits, 16, &mut account).unwrap());
        assert_eq!(account.storage_stat().unwrap().total_cells(), 2);
        assert_eq!(account.storage_info().unwrap().serialize().unwrap().repr_hash(), original);
    }
}

#[test]
fn size_measurement_checks_actual_merkle_depth_with_low_advertised_counters() {
    use chain_block::{MerkleProof, MAX_MERKLE_DEPTH};
    let config = BlockchainConfig::with_config(
        ConfigParams::construct_from_file(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/real_boc/default_config.boc"
        ))
        .unwrap(),
    )
    .unwrap();
    let address = MsgAddressInt::with_standart(None, 0, [0x45; 32].into()).unwrap();
    let mut account = Account::with_storage(
        &address,
        &StorageInfo::with_values(1_780_000_000, None),
        &AccountStorage::active(
            0,
            CurrencyCollection::with_coins(100_000_000_000),
            StateInit::default(),
        ),
    );
    let original = account.storage_info().unwrap().serialize().unwrap().repr_hash();
    let mut data = Cell::default();
    for depth in 1..=MAX_MERKLE_DEPTH + 1 {
        data = MerkleProof::create(&data, |_| true).unwrap().serialize().unwrap();
        assert!(account.set_data(data.clone()));
        assert_eq!(
            check_account_size_limits(config.size_limits_config(), 16, &mut account).unwrap(),
            depth <= MAX_MERKLE_DEPTH
        );
        assert_eq!(account.storage_stat().unwrap().max_merkle_depth().unwrap(), depth);
        assert_eq!(account.storage_info().unwrap().serialize().unwrap().repr_hash(), original);
    }
    assert!(account.set_data(Cell::default()));
    assert!(check_account_size_limits(config.size_limits_config(), 16, &mut account).unwrap());
    assert_eq!(account.storage_stat().unwrap().max_merkle_depth().unwrap(), 0);
    assert_eq!(account.storage_info().unwrap().serialize().unwrap().repr_hash(), original);
}

#[test]
fn deep_merkle_proofs_cannot_wrap_past_the_size_guard() {
    use chain_block::MerkleProof;
    let config = BlockchainConfig::with_config(
        ConfigParams::construct_from_file(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/real_boc/default_config.boc"
        ))
        .unwrap(),
    )
    .unwrap();
    let mut data = Cell::default();
    for _ in 0..256 {
        data = MerkleProof::create(&data, |_| true).unwrap().serialize().unwrap();
    }
    let mut init = StateInit::default();
    init.set_data(data);
    let mut account = Account::with_storage(
        &MsgAddressInt::with_standart(None, 0, [0x45; 32].into()).unwrap(),
        &StorageInfo::with_values(1_780_000_000, None),
        &AccountStorage::active(0, CurrencyCollection::with_coins(100_000_000_000), init),
    );
    assert!(
        !check_account_size_limits(config.size_limits_config(), 16, &mut account).unwrap(),
        "256 nested proofs must exceed the depth limit; measured depth {:?}",
        account.storage_stat().unwrap().max_merkle_depth().unwrap()
    );
}

#[test]
fn live_storage_cache_matches_native_after_duplicate_code_data_roots() {
    let fixture =
        serde_json::from_str(include_str!("../../tests/fixtures/storage-cache-carry.json"))
            .unwrap();
    assert_live_storage_cache(fixture);
}

#[test]
fn live_storage_cache_matches_native_after_oversize_rollback_and_successors() {
    let fixture =
        serde_json::from_str(include_str!("../../tests/fixtures/storage-rollback-carry.json"))
            .unwrap();
    assert_live_storage_cache(fixture);
}

#[test]
fn live_storage_cache_matches_native_across_tick_oog_tock_and_tick() {
    let fixture =
        serde_json::from_str(include_str!("../../tests/fixtures/storage-tick-carry.json")).unwrap();
    assert_live_storage_cache(fixture);
}

fn assert_live_storage_cache(fixture: serde_json::Value) {
    use crate::TickTockTransactionExecutor;
    use chain_block::{read_single_root_boc, HashUpdate, ShardAccount, TransactionTickTock};
    fn cell(value: &serde_json::Value) -> Cell {
        read_single_root_boc(hex::decode(value.as_str().unwrap()).unwrap()).unwrap()
    }
    let config = BlockchainConfig::with_config(
        ConfigParams::construct_from_cell(cell(&fixture["config_boc"])).unwrap(),
    )
    .unwrap();
    let executor = OrdinaryTransactionExecutor::new(config.clone());
    let rows = fixture["rows"].as_array().unwrap();
    for prewarm in [false, true] {
        let mut shard = ShardAccount::construct_from_cell(cell(&rows[0]["input_shard"])).unwrap();
        let mut account = shard.read_account().unwrap();
        if prewarm {
            account.measure_storage_stat(16).unwrap();
        }
        for row in rows {
            assert_eq!(
                shard.serialize().unwrap().repr_hash(),
                cell(&row["input_shard"]).repr_hash()
            );
            let old_hash = shard.account_hash();
            let lt = row["lt"].as_u64().unwrap();
            let params = ExecuteParams {
                block_unixtime: row["now"].as_u64().unwrap() as u32,
                block_lt: lt - lt % 1_000_000,
                last_tr_lt: lt,
                ..ExecuteParams::default()
            };
            let mut transaction = if let Some(is_tock) = row["is_tock"].as_bool() {
                TickTockTransactionExecutor::new(config.clone(), TransactionTickTock::new(is_tock))
                    .execute_with_params(None, &mut account, params)
            } else {
                executor.execute_with_params(Some(cell(&row["message"])), &mut account, params)
            }
            .unwrap();
            let description = transaction.read_description().unwrap();
            if let Some(aborted) = row["aborted"].as_bool() {
                assert_eq!(description.is_aborted(), aborted);
            }
            match description.compute_phase_ref() {
                Some(TrComputePhase::Vm(vm)) => {
                    assert_eq!(vm.gas_used.as_u64(), row["gas"].as_u64().unwrap());
                    if let Some(code) = row["exit_code"].as_i64() {
                        assert_eq!(vm.exit_code, code as i32);
                    }
                }
                _ => panic!("the authored contract must execute"),
            }
            if let Some(code) = row["action_code"].as_i64() {
                assert_eq!(description.action_phase_ref().unwrap().result_code, code as i32);
            }
            transaction.set_prev_trans_lt(shard.last_trans_lt());
            transaction.set_prev_trans_hash(shard.last_trans_hash().clone());
            shard.write_account(&account).unwrap();
            let new_hash = shard.account_hash();
            transaction
                .write_state_update(&HashUpdate::with_hashes(old_hash, new_hash.clone()))
                .unwrap();
            let tx_hash = transaction.serialize().unwrap().repr_hash();
            shard.set_last_trans_hash(tx_hash.clone());
            shard.set_last_trans_lt(transaction.logical_time());
            assert_eq!(hex::encode(tx_hash.as_slice()), row["transaction_hash"].as_str().unwrap());
            assert_eq!(hex::encode(new_hash.as_slice()), row["account_hash"].as_str().unwrap());
            assert_eq!(
                hex::encode(shard.serialize().unwrap().repr_hash().as_slice()),
                row["shard_hash"].as_str().unwrap()
            );
            // Keep the actual Account/cache for the next row. Never reconstruct
            // it from the native input or normalize its finalized metadata.
        }
    }
}
