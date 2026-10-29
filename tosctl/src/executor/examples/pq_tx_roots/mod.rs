// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Explicit v16 fixture input: full original ShardAccount and execution context.
//! No expected output fields are inputs to this adapter.
use std::{collections::HashMap, fs::File, io::Read};

use anyhow::Context;
use chain_block::{
    read_single_root_boc, Account, Cell, CellType, ConfigParams, Deserializable, HashUpdate,
    HashmapE, Message, Serializable, ShardAccount, SliceData, UInt256,
};
use tos_executor::{
    BlockchainConfig, ExecuteParams, ExecutorError, OrdinaryTransactionExecutor,
    TransactionExecutor,
};
use tos_vm::{smart_contract_info::PrevBlocksInfo, stack::read_stack_item};

const MAX_FILE: usize = 64 * 1024 * 1024;
const MAX_CONFIG: usize = 8 * 1024 * 1024;
// The original basechain wallet state-bound fixtures carry 65,536 cells:
// their largest measured explicit-input row is 2,881,435 bytes.
const MAX_ROW: usize = 4 * 1024 * 1024;
const MAX_ROWS: usize = 10_000;
const MAX_VISITS: usize = 2_000_000;
const MAX_DEPTH: usize = 1024;

fn bounded(path: &str, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?.take((limit + 1) as u64).read_to_end(&mut data)?;
    anyhow::ensure!(data.len() <= limit, "root input byte limit exceeded");
    Ok(data)
}

fn complete(root: &Cell) -> anyhow::Result<()> {
    let mut visited = HashMap::new();
    let mut pending = vec![(root.clone(), 0usize)];
    let mut work = 0;
    while let Some((cell, depth)) = pending.pop() {
        work += 1;
        anyhow::ensure!(
            work <= MAX_VISITS && depth <= MAX_DEPTH,
            "root cell traversal limit exceeded"
        );
        anyhow::ensure!(
            matches!(cell.cell_type(), CellType::Ordinary | CellType::LibraryReference),
            "root fixtures require complete ordinary/library cells"
        );
        let key = cell.repr_hash();
        if visited.get(&key).is_some_and(|seen| *seen >= depth) {
            continue;
        }
        visited.insert(key, depth);
        for index in 0..cell.references_count() {
            pending.push((cell.reference(index)?, depth + 1));
        }
    }
    Ok(())
}

fn cell(value: &str) -> anyhow::Result<Cell> {
    let root = read_single_root_boc(hex::decode(value)?)?;
    complete(&root)?;
    Ok(root)
}

struct Row {
    name: String,
    shard: ShardAccount,
    account: Account,
    message: Cell,
    params: ExecuteParams,
}

fn parse(line: &str) -> anyhow::Result<Row> {
    anyhow::ensure!(line.len() <= MAX_ROW, "root row byte limit exceeded");
    let f: Vec<_> = line.split('\t').collect();
    anyhow::ensure!(f.len() == 9, "root scenario requires nine fields");
    anyhow::ensure!(
        !f[0].is_empty() && f[0].len() <= 256 && !f[0].chars().any(char::is_control),
        "invalid root scenario name"
    );
    let now = f[1].parse::<u32>()?;
    let lt = f[2].parse::<u64>()?;
    // Native zero values select wall time / inferred block LT. Do not make a
    // deterministic claim for those implicit modes.
    anyhow::ensure!(now > 0 && lt > 0, "root fixtures require explicit nonzero time and LT");
    let shard = ShardAccount::construct_from_cell(cell(f[3])?)?;
    let account = shard.read_account().context("invalid original Account during root preflight")?;
    let message = cell(f[4])?;
    Message::construct_from_cell(message.clone())
        .context("invalid original Message during root preflight")?;
    anyhow::ensure!(
        f[5].len() == 64 && f[5].bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid root seed"
    );
    let seed: UInt256 = f[5].parse().map_err(|e| anyhow::anyhow!("invalid root seed: {e}"))?;
    let libraries = if f[6] == "-" { None } else { Some(cell(f[6])?) };
    let previous = if f[7] == "-" {
        PrevBlocksInfo::default()
    } else {
        let item = read_stack_item(&mut SliceData::load_cell(cell(f[7])?)?)?;
        anyhow::ensure!(item.is_tuple(), "root previous blocks must be a tuple");
        PrevBlocksInfo::Tuple(item)
    };
    anyhow::ensure!(f[8] == "0", "root fixtures require signature verification");
    Ok(Row {
        name: f[0].to_owned(),
        shard,
        account,
        message,
        params: ExecuteParams {
            block_unixtime: now,
            block_lt: lt - lt % 1_000_000,
            last_tr_lt: lt,
            seed_block: seed,
            state_libs: HashmapE::with_hashmap(256, libraries),
            prev_blocks_info: previous,
            ..ExecuteParams::default()
        },
    })
}

pub fn run(config_path: &str, scenarios: &str) -> anyhow::Result<()> {
    let config_cell = read_single_root_boc(bounded(config_path, MAX_CONFIG)?)?;
    complete(&config_cell)?;
    let config = BlockchainConfig::with_config(ConfigParams::construct_from_cell(config_cell)?)?;
    anyhow::ensure!(config.global_version() == 16, "root mode requires exactly global version 16");
    let executor = OrdinaryTransactionExecutor::new(config);
    let text = String::from_utf8(bounded(scenarios, MAX_FILE)?)?;
    anyhow::ensure!(
        text.ends_with('\n') && !text.contains('\r'),
        "root input requires complete LF records"
    );
    let mut lines = text.lines();
    anyhow::ensure!(lines.next() == Some("#pq-tx-roots-v1"), "missing root schema header");
    let mut rows = Vec::new();
    // Preflight every record before executing any transaction. Duplicate names
    // remain separate ordered records (some fixtures intentionally repeat rows).
    for line in lines {
        anyhow::ensure!(rows.len() < MAX_ROWS, "root row count limit exceeded");
        let row =
            parse(line).with_context(|| format!("invalid root input record {}", rows.len()))?;
        rows.push(row);
    }
    anyhow::ensure!(!rows.is_empty(), "empty root fixture set");
    for row in rows {
        let mut shard = row.shard;
        let old_hash = shard.account_hash();
        let mut account = row.account;
        match executor.execute_with_params(Some(row.message), &mut account, row.params) {
            Ok(mut transaction) => {
                transaction.set_prev_trans_lt(shard.last_trans_lt());
                transaction.set_prev_trans_hash(shard.last_trans_hash().clone());
                shard.write_account(&account)?;
                let account_hash = shard.account_hash();
                transaction
                    .write_state_update(&HashUpdate::with_hashes(old_hash, account_hash.clone()))?;
                let transaction_hash = transaction.serialize()?.repr_hash();
                shard.set_last_trans_hash(transaction_hash.clone());
                shard.set_last_trans_lt(transaction.logical_time());
                println!(
                    "{}\taccepted\t{}\t{}\t{}",
                    row.name,
                    hex::encode(transaction_hash.as_slice()),
                    hex::encode(account_hash.as_slice()),
                    hex::encode(shard.serialize()?.repr_hash().as_slice())
                );
            }
            Err(error) => match error.downcast_ref::<ExecutorError>() {
                Some(ExecutorError::NoAcceptError(code, _)) => {
                    println!("{}\trejected\t{}\t-\t-", row.name, code);
                }
                Some(ExecutorError::ExtMsgComputeSkipped(_)) => {
                    println!("{}\trejected\t0\t-\t-", row.name);
                }
                Some(ExecutorError::PrecompiledComputeOutOfGas) => {
                    println!("{}\trefused\tprecompiled-compute-failed\t-\t-", row.name);
                }
                Some(ExecutorError::NoFundsToImportMsg) => {
                    println!("{}\trefused\timport-no-funds\t-\t-", row.name);
                }
                _ => anyhow::bail!("unexpected root execution error for {}: {error}", row.name),
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse, MAX_ROW};

    #[test]
    fn root_row_byte_boundary_precedes_typed_parsing() {
        let exact = "x".repeat(MAX_ROW);
        let Err(error) = parse(&exact) else { panic!("invalid typed row accepted") };
        assert!(error.to_string().contains("requires nine fields"));
        let oversized = "x".repeat(MAX_ROW + 1);
        let Err(error) = parse(&oversized) else { panic!("oversized row accepted") };
        assert!(error.to_string().contains("row byte limit exceeded"));
    }
}
