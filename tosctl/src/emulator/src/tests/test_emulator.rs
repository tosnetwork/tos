/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::*;
use chain_block::{
    base64_decode, base64_encode, read_single_root_boc, write_boc, Serializable, Transaction,
};

fn cell_to_base64(cell: &Cell) -> String {
    base64_encode(write_boc(cell).unwrap())
}

#[test]
fn test_emulator() {
    let config = "../executor/real_boc/config.boc";
    let config_params = ConfigParams::construct_from_file(config).unwrap();
    let config_params_boc = cell_to_base64(config_params.root().unwrap());
    let account = "../executor/real_boc/two_messages_account_old.boc";
    let account_root = Cell::read_from_file(account);
    let shard_acc = ShardAccount::with_account_root(account_root, Default::default(), 0);
    let account = shard_acc.read_account().unwrap();
    let shard_account_boc = shard_acc.write_to_base64().unwrap();
    let transaction = "../executor/real_boc/two_messages_transaction.boc";
    let transaction = Transaction::construct_from_file(transaction).unwrap();
    let message_boc = cell_to_base64(&transaction.in_msg_cell().unwrap());

    let p = transaction_emulator_create(config_params_boc.as_ptr() as *const c_char, 0);
    transaction_emulator_set_unixtime(p, account.last_paid());
    let result = transaction_emulator_emulate_transaction(
        p,
        shard_account_boc.as_ptr() as *const c_char,
        message_boc.as_ptr() as *const c_char,
    );
    let result = unsafe { CString::from_raw(result as *mut c_char) };
    println!("Emulation result: {}", result.to_string_lossy());
    transaction_emulator_destroy(p);
    let result = emulator_version();
    let result = unsafe { CString::from_raw(result as *mut c_char) };
    println!("Emulator version: {}", result.to_string_lossy());
}

#[test]
fn test_transaction() {
    let json_path = "src/tests/4C90C139A5736F34EA3EEF62F0B06431719913835EA5A1B9173F20B2EF711583_66815326000001.json";
    let json_str = std::fs::read_to_string(json_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    // 1. Config params
    let config_params_boc = CString::new(json["config_params_boc"].as_str().unwrap()).unwrap();

    // 2. Shard account state (before transaction)
    let shard_account_boc = CString::new(json["shard_account_boc"].as_str().unwrap()).unwrap();

    // 3. Input message
    let message_boc = CString::new(json["message_boc"].as_str().unwrap()).unwrap();

    // 4. Prev blocks info
    let prev_blocks_info_boc =
        CString::new(json["prev_blocks_info_boc"].as_str().unwrap()).unwrap();
    let expected_tx_hash = json["tx_hash"].as_str().unwrap();

    // 5. Create emulator
    let p = transaction_emulator_create(config_params_boc.as_ptr(), 5);

    // 6. Set block parameters
    transaction_emulator_set_unixtime(p, 1770822950);
    transaction_emulator_set_lt(p, 66815326000001);

    // rand_seed
    let rand_seed_hex =
        CString::new("628d5512834b482d4982d69d445da5f63e79de5f45f7ac52b25a9efc9a0db11c").unwrap();
    transaction_emulator_set_rand_seed(p, rand_seed_hex.as_ptr());

    // 7. Set prev blocks info
    transaction_emulator_set_prev_blocks_info(p, prev_blocks_info_boc.as_ptr());

    // 8. Emulate transaction
    let result = transaction_emulator_emulate_transaction(
        p,
        shard_account_boc.as_ptr(),
        message_boc.as_ptr(),
    );

    let result_str = unsafe { CString::from_raw(result as *mut c_char) };
    let result_json: serde_json::Value = serde_json::from_slice(result_str.as_bytes()).unwrap();

    assert!(result_json["success"].as_bool().unwrap());
    let tx_boc = result_json["transaction"].as_str().unwrap();
    let tx_cell = read_single_root_boc(base64_decode(tx_boc).unwrap()).unwrap();
    let tx_hash = tx_cell.repr_hash().to_hex_string().to_uppercase();
    assert_eq!(tx_hash, expected_tx_hash, "Transaction hash mismatch!");

    transaction_emulator_destroy(p);
}

#[test]
fn external_compute_skips_are_unaccepted_without_outputs() {
    use chain_block::{
        Account, BuilderData, ConfigParamEnum, CurrencyCollection, ExternalInboundMessageHeader,
        Message, MsgAddressExt, MsgAddressInt, PrecompiledContractsList, StateInit,
    };
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../executor/real_boc/default_config.boc");
    let address = MsgAddressInt::with_standart(None, 0, [0x45; 32].into()).unwrap();
    let message = Message::with_ext_in_header(ExternalInboundMessageHeader::new(
        MsgAddressExt::AddrNone,
        address.clone(),
    ))
    .serialize()
    .unwrap();
    for missing_state in [false, true] {
        let mut config = ConfigParams::construct_from_file(path).unwrap();
        let account = if missing_state {
            Account::uninit(
                address.clone(),
                CurrencyCollection::with_coins(100_000_000_000),
                0,
                1_750_000_000,
            )
        } else {
            let code = BuilderData::with_raw(vec![0xf8, 0x00], 16).unwrap().into_cell().unwrap();
            let mut list = PrecompiledContractsList::default();
            list.add(&code.repr_hash(), u64::MAX).unwrap();
            config.set_config(ConfigParamEnum::ConfigParam45(list)).unwrap();
            let mut init = StateInit::default();
            init.set_code(code);
            init.set_data(Cell::default());
            Account::active(
                address.clone(),
                CurrencyCollection::with_coins(100_000_000_000),
                0,
                1_750_000_000,
                init,
                0,
            )
            .unwrap()
        };
        let shard = ShardAccount::with_params(&account, Default::default(), 0).unwrap();
        let emulator = Emulator { unixtime: 1_750_000_000, lt: 2_000_000, ..Emulator::new(config) };
        let text = emulator.emulate_transaction(shard, Some(message.clone()), false).unwrap();
        let result: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(result["success"], false);
        assert_eq!(result["external_not_accepted"], true, "{result}");
        assert_eq!(result["vm_exit_code"], 0);
        for field in ["transaction", "shard_account"] {
            assert!(result.get(field).is_none(), "{result}");
        }
    }
}
