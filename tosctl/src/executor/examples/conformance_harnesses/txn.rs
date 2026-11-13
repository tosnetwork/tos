// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! txn harness: one transaction through the Rust executor, executed the way the transaction
//! emulator library executes it (test/conformance/ref/harness-txn.cpp,
//! schema/harness/txn-v1.schema.json).
use chain_block::{
    ConfigParams, Deserializable, HashUpdate, HashmapE, Serializable, ShardAccount, SliceData,
    TransactionTickTock, UInt256,
};
use serde_json::{json, Value};
use tos_executor::{
    BlockchainConfig, ExecuteParams, ExecutorError, OrdinaryTransactionExecutor,
    TickTockTransactionExecutor, TransactionExecutor,
};
use tos_vm::{smart_contract_info::PrevBlocksInfo, stack::read_stack_item};

use super::common::{self, Object};

const REQUIRED: &[&str] = &["config", "shard_account", "now", "lt", "rand_seed"];
const ALLOWED: &[&str] = &[
    "config",
    "shard_account",
    "now",
    "lt",
    "rand_seed",
    "message",
    "tick_tock",
    "libraries",
    "prev_blocks",
];
/// The Rust executor is aligned with the C++ node at this global version only; a configuration
/// at another version is refused rather than run with semantics nobody compared.
const GLOBAL_VERSION: u32 = 16;
/// Logical times of one block are aligned to this, as in the emulator.
const LT_ALIGN: u64 = 1_000_000;

fn rejected(code: i32) -> Value {
    json!({"outcome": "rejected", "vm_exit_code": code})
}

pub fn run(ctx: &Object) -> anyhow::Result<Value> {
    common::check_keys(ctx, REQUIRED, ALLOWED, "txn context")?;
    let config_cell = common::required_boc(ctx, "config")?;
    let shard_account_cell = common::required_boc(ctx, "shard_account")?;
    let now = u32::try_from(common::required_integer(ctx, "now", 1, i64::from(u32::MAX))?)?;
    let lt = u64::try_from(common::required_integer(ctx, "lt", 1, i64::MAX)?)?;
    let seed =
        common::text(ctx, "rand_seed")?.ok_or_else(|| anyhow::anyhow!("missing rand_seed"))?;
    anyhow::ensure!(
        seed.len() == 64 && seed.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "rand_seed must be 64 lowercase hex digits"
    );
    let seed: UInt256 = seed.parse().map_err(|e| anyhow::anyhow!("rand_seed: {e}"))?;
    let message = common::optional_boc(ctx, "message")?;
    let tick_tock = match common::text(ctx, "tick_tock")? {
        None => None,
        Some("tick") => Some(TransactionTickTock::Tick),
        Some("tock") => Some(TransactionTickTock::Tock),
        Some(_) => anyhow::bail!("tick_tock must be tick or tock"),
    };
    anyhow::ensure!(
        message.is_some() != tick_tock.is_some(),
        "exactly one of message and tick_tock is required"
    );
    let libraries = common::optional_boc(ctx, "libraries")?;
    let prev_blocks = match common::optional_boc(ctx, "prev_blocks")? {
        None => PrevBlocksInfo::default(),
        Some(cell) => {
            let item = read_stack_item(&mut SliceData::load_cell(cell)?)
                .map_err(|e| anyhow::anyhow!("previous blocks: {e}"))?;
            anyhow::ensure!(
                item.is_null() || item.is_tuple(),
                "previous blocks must be a tuple or null"
            );
            PrevBlocksInfo::Tuple(item)
        }
    };

    let config = BlockchainConfig::with_config(ConfigParams::with_root(config_cell)?)
        .map_err(|e| anyhow::anyhow!("configuration refused: {e}"))?;
    anyhow::ensure!(
        config.global_version() == GLOBAL_VERSION,
        "configuration at global version {}, the adapter runs {GLOBAL_VERSION} only",
        config.global_version()
    );

    // From here on the context is accepted: what the executor makes of it is the effect.
    let Ok(mut shard_account) = ShardAccount::construct_from_cell(shard_account_cell) else {
        return Ok(json!({"outcome": "error"}));
    };
    let Ok(mut account) = shard_account.read_account() else {
        return Ok(json!({"outcome": "error"}));
    };
    let executor: Box<dyn TransactionExecutor> = match tick_tock {
        None => Box::new(OrdinaryTransactionExecutor::new(config)),
        Some(kind) => Box::new(TickTockTransactionExecutor::new(config, kind)),
    };
    let params = ExecuteParams {
        block_unixtime: now,
        block_lt: lt.saturating_sub(lt % LT_ALIGN),
        last_tr_lt: lt,
        seed_block: seed,
        state_libs: HashmapE::with_hashmap(256, libraries),
        prev_blocks_info: prev_blocks,
        ..ExecuteParams::default()
    };
    let old_hash = shard_account.account_hash();
    let mut transaction = match executor.execute_with_params(message, &mut account, params) {
        Ok(transaction) => transaction,
        Err(error) => {
            return Ok(match error.downcast_ref::<ExecutorError>() {
                Some(ExecutorError::NoAcceptError(code, _)) => rejected(*code),
                // A skipped compute phase leaves the exit code at its initial 0.
                Some(ExecutorError::ExtMsgComputeSkipped(_)) => rejected(0),
                _ => json!({"outcome": "error"}),
            });
        }
    };
    transaction.set_prev_trans_lt(shard_account.last_trans_lt());
    transaction.set_prev_trans_hash(shard_account.last_trans_hash().clone());
    shard_account.write_account(&account)?;
    let account_hash = shard_account.account_hash();
    transaction.write_state_update(&HashUpdate::with_hashes(old_hash, account_hash.clone()))?;
    let transaction_hash = transaction.serialize()?.repr_hash();
    shard_account.set_last_trans_hash(transaction_hash.clone());
    shard_account.set_last_trans_lt(transaction.logical_time());
    let shard_account_hash = shard_account.serialize()?.repr_hash();
    Ok(json!({
        "outcome": "accepted",
        "transaction_hash": format!("{transaction_hash:X}"),
        "account_hash": format!("{account_hash:X}"),
        "shard_account_hash": format!("{shard_account_hash:X}"),
    }))
}
