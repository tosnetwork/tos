// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Execute whole transactions so the action phase is compared, not only compute.
//!
//! The opcode driver stops at the compute phase, so RAWRESERVE and SENDRAWMSG
//! were only ever compared as an action-list hash. This runs the same account
//! and the same inbound message through the Rust executor and prints what the
//! transaction did, for the emulator's transcript to be compared against.
use std::{env, fs};

use chain_block::{
    read_single_root_boc, Account, ConfigParam8, ConfigParamEnum, ConfigParams, Deserializable,
    Serializable, Transaction,
};
use tos_executor::{
    BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor,
};

fn hex_cell(value: &str) -> anyhow::Result<chain_block::Cell> {
    Ok(read_single_root_boc(hex::decode(value)?)?)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = env::args().collect();
    anyhow::ensure!(args.len() == 3, "usage: pq-tx-parity config.boc scenarios.tsv");
    let mut config = ConfigParams::construct_from_file(&args[1])?;
    let version = config
        .get_global_version()
        .map_err(|e| anyhow::anyhow!("configuration without a global version: {e}"))?;
    anyhow::ensure!(version.version >= 16, "the scenarios need an activated instruction");
    config.set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 { global_version: version }))?;
    let blockchain = BlockchainConfig::with_config(config)?;

    let data = fs::read_to_string(&args[2])?;
    let mut count = 0;
    for line in data.lines() {
        let f: Vec<_> = line.split('\t').collect();
        anyhow::ensure!(f.len() == 6, "invalid transaction scenario");
        let now = f[1].parse::<u32>()?;
        let lt = f[2].parse::<u64>()?;
        let mut account = Account::construct_from_cell(hex_cell(f[3])?)?;
        let message = chain_block::Message::construct_from_cell(hex_cell(f[4])?)?;
        let executor = OrdinaryTransactionExecutor::new(blockchain.clone());
        let params = ExecuteParams {
            block_unixtime: now,
            block_lt: lt - lt % 1_000_000,
            last_tr_lt: lt,
            ..ExecuteParams::default()
        };
        let outcome =
            executor.execute_with_params(Some(message.serialize()?), &mut account, params);
        let (exit, action, messages, account_hash) = match outcome {
            Ok(transaction) => summarize(&transaction, &account)?,
            // A rejected transaction is a result, not a driver failure.
            Err(error) => (describe(&error), 0, String::from("-"), String::from("-")),
        };
        println!("{}\t{}\t{}\t{}\t{}", f[0], exit, action, messages, account_hash);
        count += 1;
    }
    anyhow::ensure!(count >= 4, "incomplete transaction scenario set");
    Ok(())
}

fn describe(error: &anyhow::Error) -> i32 {
    match error.downcast_ref::<tos_executor::ExecutorError>() {
        Some(tos_executor::ExecutorError::NoAcceptError(code, _)) => *code,
        _ => i32::MIN,
    }
}

fn summarize(
    transaction: &Transaction,
    account: &Account,
) -> anyhow::Result<(i32, i32, String, String)> {
    let description = transaction.read_description()?;
    // A skipped compute phase must not read as a clean exit 0: that is the one
    // way this transcript could report success for a transaction that never ran.
    let (mut exit, mut action) = (i32::MIN, 0);
    if let Some(compute) = description.compute_phase_ref() {
        if let chain_block::TrComputePhase::Vm(vm) = compute {
            exit = vm.exit_code;
        }
    }
    if let Some(phase) = description.action_phase_ref() {
        action = phase.result_code;
    }
    let mut digests = Vec::new();
    transaction.iterate_out_msgs(|message| {
        digests.push(hex::encode(message.serialize()?.repr_hash().as_slice()));
        Ok(true)
    })?;
    // The balance and the contract's own storage are what the two runs must
    // agree on. The whole account cell also carries storage bookkeeping, which
    // would turn any difference in due-payment accounting into a permanent
    // false difference in every scenario.
    let balance = account.balance().map(|g| g.coins.as_u128()).unwrap_or_default();
    let data = account
        .get_data()
        .map(|cell| hex::encode(cell.repr_hash().as_slice()))
        .unwrap_or_else(|| String::from("-"));
    Ok((
        exit,
        action,
        if digests.is_empty() { String::from("-") } else { digests.join(",") },
        format!("{balance}\t{data}"),
    ))
}
