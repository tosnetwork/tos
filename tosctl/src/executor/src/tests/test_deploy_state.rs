// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only

use super::*;
use crate::OrdinaryTransactionExecutor;
use chain_block::{
    ConfigParam8, ConfigParamEnum, ConfigParams, GlobalVersion, InternalMessageHeader,
};
use tos_assembler::compile_code_to_cell;

fn deployment(status: AccountStatus, program: &str) -> (TrComputePhaseVm, Account) {
    let mut raw = ConfigParams::construct_from_file(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/real_boc/default_config.boc"
    ))
    .expect("configuration");
    let capabilities = raw.get_global_version().expect("version").capabilities;
    raw.set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 {
        global_version: GlobalVersion { version: 16, capabilities },
    }))
    .expect("version 16");
    let config = BlockchainConfig::with_config(raw).expect("configuration");
    let mut init = StateInit::default();
    init.set_code(compile_code_to_cell(program).expect("program"));
    init.set_data(Cell::default());
    let address = MsgAddressInt::with_standart(
        None,
        0,
        if status == AccountStatus::AccStateFrozen {
            [0x12; 32].into()
        } else {
            init.hash().expect("state hash").into()
        },
    )
    .expect("address");
    let balance = CurrencyCollection::with_coins(100_000_000_000u64);
    let now = 1_750_000_000;
    let mut account = match status {
        AccountStatus::AccStateNonexist => Account::default(),
        AccountStatus::AccStateUninit => Account::uninit(address.clone(), balance, 0, now),
        AccountStatus::AccStateActive | AccountStatus::AccStateFrozen => {
            let mut account = Account::active(address.clone(), balance, 0, now, init.clone(), 0)
                .expect("active account");
            if status == AccountStatus::AccStateFrozen {
                account.try_freeze().expect("freeze");
            }
            account
        }
    };
    let sender = MsgAddressInt::with_standart(None, 0, [0x99; 32].into()).expect("sender");
    let header = InternalMessageHeader::with_addresses(
        sender,
        address,
        CurrencyCollection::with_coins(1_000_000_000u64),
    );
    let mut message = Message::with_int_header(header);
    message.set_state_init(init);
    let transaction = OrdinaryTransactionExecutor::new(config)
        .execute_with_params(
            Some(message.serialize().expect("message")),
            &mut account,
            ExecuteParams {
                block_unixtime: now,
                block_lt: 2_000_000,
                last_tr_lt: 2_000_000,
                ..ExecuteParams::default()
            },
        )
        .expect("transaction");
    let phase = match transaction.read_description().expect("description").compute_phase_ref() {
        Some(TrComputePhase::Vm(phase)) => phase.clone(),
        other => panic!("compute must run: {other:?}"),
    };
    (phase, account)
}

#[test]
fn deploy_state_success_sets_flags_for_each_initial_status() {
    for status in [
        AccountStatus::AccStateNonexist,
        AccountStatus::AccStateUninit,
        AccountStatus::AccStateFrozen,
        AccountStatus::AccStateActive,
    ] {
        let (phase, account) = deployment(status.clone(), "ACCEPT");
        assert_eq!(phase.exit_code, 0, "{status:?}");
        assert!(phase.success, "{status:?}");
        let used = status != AccountStatus::AccStateActive;
        assert_eq!(phase.msg_state_used, used, "{status:?}");
        assert_eq!(phase.account_activated, used, "{status:?}");
        assert_eq!(account.status(), AccountStatus::AccStateActive);
    }
}

#[test]
fn deploy_state_accepted_failure_does_not_activate() {
    for status in [
        AccountStatus::AccStateNonexist,
        AccountStatus::AccStateUninit,
        AccountStatus::AccStateFrozen,
        AccountStatus::AccStateActive,
    ] {
        let (phase, account) = deployment(status.clone(), "ACCEPT THROW 42");
        assert_eq!(phase.exit_code, 42, "{status:?}");
        assert!(!phase.success, "{status:?}");
        assert_eq!(phase.msg_state_used, status != AccountStatus::AccStateActive, "{status:?}");
        assert!(!phase.account_activated, "{status:?}");
        let expected = if status == AccountStatus::AccStateNonexist {
            AccountStatus::AccStateUninit
        } else {
            status.clone()
        };
        assert_eq!(account.status(), expected, "{status:?}");
        if expected == AccountStatus::AccStateUninit || expected == AccountStatus::AccStateFrozen {
            assert!(account.get_code().is_none(), "{status:?}");
            assert!(account.get_data().is_none(), "{status:?}");
        }
    }
}

#[test]
fn deploy_state_commit_then_throw_still_activates() {
    for status in [
        AccountStatus::AccStateNonexist,
        AccountStatus::AccStateUninit,
        AccountStatus::AccStateFrozen,
    ] {
        let (phase, account) = deployment(status.clone(), "ACCEPT COMMIT THROW 42");
        assert_eq!(phase.exit_code, 42, "{status:?}");
        assert!(phase.success, "{status:?}");
        assert!(phase.msg_state_used, "{status:?}");
        assert!(phase.account_activated, "{status:?}");
        assert_eq!(account.status(), AccountStatus::AccStateActive);
    }
}

#[test]
fn deploy_state_matches_frozen_native_roots() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/deploy-state.json"))
            .expect("native fixtures");
    let rows = rows.as_array().expect("fixture array");
    assert_eq!(rows.len(), 55);
    for row in rows {
        let name = row["name"].as_str().expect("name");
        let cell = |key: &str| {
            chain_block::read_single_root_boc(
                hex::decode(row[key].as_str().expect("hex field")).expect("hex"),
            )
            .expect("cell")
        };
        let config = BlockchainConfig::with_config(
            ConfigParams::with_root(cell("config")).expect("raw config"),
        )
        .expect("config");
        let storage_threshold = config.size_limits_config().acc_state_cells_for_storage_dict;
        let initial = cell("account");
        let mut account = Account::construct_from_cell(initial.clone()).expect("account");
        let lt = row["lt"].as_u64().expect("lt");
        let outcome = OrdinaryTransactionExecutor::new(config).execute_with_params(
            Some(cell("message")),
            &mut account,
            ExecuteParams {
                block_unixtime: row["now"].as_u64().expect("now") as u32,
                block_lt: lt - lt % 1_000_000,
                last_tr_lt: lt,
                ..ExecuteParams::default()
            },
        );
        if let Some(exit) = row["rejected_exit"].as_i64() {
            let error = outcome.expect_err(name);
            match error.downcast_ref::<crate::ExecutorError>() {
                Some(crate::ExecutorError::NoAcceptError(code, _)) => {
                    assert_eq!(i64::from(*code), exit, "{name}")
                }
                other => panic!("{name}: wrong rejection {other:?}"),
            }
            continue;
        }
        let mut transaction = outcome.expect(name);
        account.update_storage_stat(storage_threshold).expect("storage statistics");
        let account_hash = account.serialize().expect("account cell").repr_hash();
        transaction
            .write_state_update(&chain_block::HashUpdate::with_hashes(
                initial.repr_hash(),
                account_hash.clone(),
            ))
            .expect("state update");
        if hex::encode(account_hash.as_slice())
            != row["account_hash"].as_str().expect("account hash")
        {
            panic!(
                "{name}: actual {account:?}, expected {:?}",
                Account::construct_from_cell(cell("expected_account")).expect("expected account")
            );
        }
        assert_eq!(
            hex::encode(transaction.serialize().expect("transaction cell").repr_hash().as_slice()),
            row["tx_hash"].as_str().expect("tx hash"),
            "{name}"
        );
    }
}
