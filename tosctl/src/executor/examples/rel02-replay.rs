// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Replay recorded chain transactions through the Rust executor.
//!
//! The input is the transcript `test-epoch-replay --dump` writes while the C++
//! emulator re-executes the REL-02 blocks: for every transaction its exact
//! inputs (account, message, configuration, libraries, previous blocks, time,
//! logical time, seed) and the on-chain transaction and account hashes. Each
//! transaction is executed the way the emulator library executes it, and the
//! resulting transaction cell and account hash must equal the chain's.
use std::{env, fs};

use chain_block::{
    read_single_root_boc, Account, Cell, ConfigParams, Deserializable, HashUpdate, HashmapE,
    Serializable, ShardAccount, SliceData, Transaction, TransactionTickTock, UInt256,
};
use tos_executor::{
    BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TickTockTransactionExecutor,
    TransactionExecutor,
};
use tos_vm::{smart_contract_info::PrevBlocksInfo, stack::read_stack_item};

const ORDINARY: u32 = 1;
const TICK: u32 = 3;
const TOCK: u32 = 4;

/// State read from a block's Merkle update keeps the subtrees no transaction
/// touched as pruned branches, which raises the level of every cell above them.
/// The C++ replay reads that state virtualized at level 0; so must this one, or
/// hashes and the commit-time level checks see the proof instead of the state.
fn hex_cell(value: &str) -> anyhow::Result<Option<Cell>> {
    if value == "-" {
        return Ok(None);
    }
    let cell = read_single_root_boc(hex::decode(value)?)?;
    let level = cell.level();
    Ok(Some(if level > 0 { cell.virtualize(level) } else { cell }))
}

fn required(value: &str, what: &str) -> anyhow::Result<Cell> {
    hex_cell(value)?.ok_or_else(|| anyhow::anyhow!("missing {what}"))
}

struct Row {
    kind: u32,
    now: u32,
    lt: u64,
    seed: UInt256,
    shard_account: Cell,
    message: Option<Cell>,
    config: Cell,
    libraries: Option<Cell>,
    previous_blocks: Cell,
    transaction_hash: String,
    account_hash: String,
    original: Cell,
}

fn parse(line: &str) -> anyhow::Result<Row> {
    let f: Vec<_> = line.split('\t').collect();
    anyhow::ensure!(f.len() == 12, "a dump row has 12 fields, found {}", f.len());
    Ok(Row {
        kind: f[0].parse()?,
        now: f[1].parse()?,
        lt: f[2].parse()?,
        seed: f[3].parse().map_err(|e| anyhow::anyhow!("invalid seed: {e}"))?,
        shard_account: required(f[4], "shard account")?,
        message: hex_cell(f[5])?,
        config: required(f[6], "configuration")?,
        libraries: hex_cell(f[7])?,
        previous_blocks: required(f[8], "previous blocks")?,
        // The C++ transcript writes hashes in upper case.
        transaction_hash: f[9].to_ascii_lowercase(),
        account_hash: f[10].to_ascii_lowercase(),
        original: required(f[11], "original transaction")?,
    })
}

struct Outcome {
    transaction: Option<Cell>,
    account_hash: String,
    account: Option<Account>,
    error: String,
}

fn execute(row: &Row) -> anyhow::Result<Outcome> {
    let config = BlockchainConfig::with_config(ConfigParams::with_root(row.config.clone())?)?;
    let dict_hash_min_cells = config.size_limits_config().acc_state_cells_for_storage_dict;
    let executor: Box<dyn TransactionExecutor> = match row.kind {
        ORDINARY => Box::new(OrdinaryTransactionExecutor::new(config)),
        TICK | TOCK => Box::new(TickTockTransactionExecutor::new(
            config,
            TransactionTickTock::new(row.kind == TOCK),
        )),
        other => anyhow::bail!("unsupported transaction type {other}"),
    };
    let previous = read_stack_item(&mut SliceData::load_cell(row.previous_blocks.clone())?)?;
    anyhow::ensure!(previous.is_tuple(), "previous blocks are not a tuple");
    let params = ExecuteParams {
        block_lt: row.lt - row.lt % 1_000_000,
        last_tr_lt: row.lt,
        block_unixtime: row.now,
        seed_block: row.seed.clone(),
        state_libs: HashmapE::with_hashmap(256, row.libraries.clone()),
        prev_blocks_info: PrevBlocksInfo::Tuple(previous),
        ..ExecuteParams::default()
    };
    let mut shard_account = ShardAccount::construct_from_cell(row.shard_account.clone())?;
    let mut account = shard_account.read_account()?;
    let mut transaction =
        match executor.execute_with_params(row.message.clone(), &mut account, params) {
            Ok(transaction) => transaction,
            Err(error) => {
                return Ok(Outcome {
                    transaction: None,
                    account_hash: String::from("-"),
                    account: None,
                    error: error.to_string().replace(['\t', '\n'], " "),
                })
            }
        };
    account.update_storage_stat(dict_hash_min_cells)?;
    transaction.set_prev_trans_lt(shard_account.last_trans_lt());
    transaction.set_prev_trans_hash(shard_account.last_trans_hash().clone());
    let old_hash = shard_account.account_hash();
    let original = Transaction::construct_from_cell(row.original.clone())?;
    anyhow::ensure!(
        original.read_state_update()?.old_hash == old_hash,
        "input account {} differs from the chain's pre-state {}",
        old_hash.to_hex_string(),
        original.read_state_update()?.old_hash.to_hex_string()
    );
    shard_account.write_account(&account)?;
    let new_hash = shard_account.account_hash();
    transaction.write_state_update(&HashUpdate::with_hashes(old_hash, new_hash.clone()))?;
    Ok(Outcome {
        transaction: Some(transaction.serialize()?),
        account_hash: hex::encode(new_hash.as_slice()),
        account: Some(account),
        error: String::new(),
    })
}

/// The first field where the Rust transaction differs from the chain's, by
/// decoding both; `-` when the decoded records agree.
fn first_difference(actual: &Cell, original: &Cell) -> anyhow::Result<String> {
    let a = Transaction::construct_from_cell(actual.clone())?;
    let o = Transaction::construct_from_cell(original.clone())?;
    let (ad, od) = (a.read_description()?, o.read_description()?);
    let mut fields = Vec::new();
    let mut compare = |name: &str, x: String, y: String| {
        if x != y {
            fields.push(format!("{name}:{x}!={y}"));
        }
    };
    compare("total_fees", format!("{:?}", a.total_fees()), format!("{:?}", o.total_fees()));
    compare("orig_status", format!("{:?}", a.orig_status), format!("{:?}", o.orig_status));
    compare("end_status", format!("{:?}", a.end_status), format!("{:?}", o.end_status));
    compare("out_msgs", a.out_msgs.len()?.to_string(), o.out_msgs.len()?.to_string());
    compare("aborted", ad.is_aborted().to_string(), od.is_aborted().to_string());
    compare(
        "compute",
        format!("{:?}", ad.compute_phase_ref()),
        format!("{:?}", od.compute_phase_ref()),
    );
    compare(
        "action",
        format!("{:?}", ad.action_phase_ref()),
        format!("{:?}", od.action_phase_ref()),
    );
    compare("description", format!("{ad:?}"), format!("{od:?}"));
    compare(
        "state_update",
        format!("{:?}", a.read_state_update()?),
        format!("{:?}", o.read_state_update()?),
    );
    let mut out_a = Vec::new();
    a.iterate_out_msgs(|m| {
        out_a.push(hex::encode(m.serialize()?.repr_hash().as_slice()));
        Ok(true)
    })?;
    let mut out_o = Vec::new();
    o.iterate_out_msgs(|m| {
        out_o.push(hex::encode(m.serialize()?.repr_hash().as_slice()));
        Ok(true)
    })?;
    compare("out_msg_hashes", out_a.join(","), out_o.join(","));
    Ok(if fields.is_empty() { String::from("-") } else { fields.join(" | ") })
}

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = env::args().collect();
    anyhow::ensure!(args.len() == 2, "usage: rel02-replay dump.tsv");
    let data = fs::read_to_string(&args[1])?;
    let rows = data.lines().map(parse).collect::<anyhow::Result<Vec<_>>>()?;
    // The chain's account after a transaction is the input of the account's
    // next transaction in the corpus, keyed by its hash.
    let mut chain_accounts = std::collections::HashMap::new();
    for row in &rows {
        let input = ShardAccount::construct_from_cell(row.shard_account.clone())?;
        chain_accounts.insert(hex::encode(input.account_hash().as_slice()), input.read_account()?);
    }
    let (mut total, mut equal) = (0usize, 0usize);
    for (index, row) in rows.iter().enumerate() {
        let row = row;
        let outcome = execute(row)?;
        total += 1;
        let (tx_hash, detail) = match &outcome.transaction {
            Some(cell) => {
                let hash = hex::encode(cell.repr_hash().as_slice());
                let detail = if hash == row.transaction_hash {
                    String::from("-")
                } else {
                    first_difference(cell, &row.original)?
                };
                (hash, detail)
            }
            None => (String::from("-"), format!("executor refused: {}", outcome.error)),
        };
        let same = tx_hash == row.transaction_hash && outcome.account_hash == row.account_hash;
        if outcome.account_hash != row.account_hash {
            if let Some(actual) = &outcome.account {
                match chain_accounts.get(&row.account_hash) {
                    Some(chain) => eprintln!(
                        "{index}\taccount\t{}\tpruned_in_input={}",
                        account_difference(actual, chain),
                        pruned(&row.shard_account)
                    ),
                    None => eprintln!("{index}\taccount\tchain account not in the corpus"),
                }
            }
        }
        if same {
            equal += 1;
        }
        eprintln!("{index}\tinput\tpruned={}", pruned(&row.shard_account));
        println!(
            "{index}\t{}\t{}\t{}\t{}\t{detail}",
            row.kind,
            row.lt,
            if same { "EQUAL" } else { "DIFF" },
            if outcome.account_hash == row.account_hash { "account=" } else { "account!=" },
        );
    }
    eprintln!("{equal}/{total} transactions equal to the chain");
    anyhow::ensure!(total > 0, "empty dump");
    Ok(())
}

fn account_difference(actual: &Account, chain: &Account) -> String {
    let mut fields = Vec::new();
    let mut compare = |name: &str, x: String, y: String| {
        if x != y {
            fields.push(format!("{name}:{x}!={y}"));
        }
    };
    compare("balance", format!("{:?}", actual.balance()), format!("{:?}", chain.balance()));
    compare(
        "storage_info",
        format!("{:?}", actual.storage_info()),
        format!("{:?}", chain.storage_info()),
    );
    compare(
        "last_tr_lt",
        format!("{:?}", actual.last_tr_time()),
        format!("{:?}", chain.last_tr_time()),
    );
    compare("status", format!("{:?}", actual.status()), format!("{:?}", chain.status()));
    compare(
        "code",
        format!("{:?}", actual.get_code().map(|c| c.repr_hash())),
        format!("{:?}", chain.get_code().map(|c| c.repr_hash())),
    );
    compare(
        "data",
        format!("{:?}", actual.get_data().map(|c| c.repr_hash())),
        format!("{:?}", chain.get_data().map(|c| c.repr_hash())),
    );
    if fields.is_empty() {
        String::from("decoded fields agree")
    } else {
        fields.join(" | ")
    }
}

/// Pruned-branch cells under a root: subtrees the corpus does not hold.
fn pruned(root: &Cell) -> usize {
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![root.clone()];
    let mut count = 0;
    while let Some(cell) = stack.pop() {
        if !seen.insert(cell.repr_hash()) {
            continue;
        }
        if cell.cell_type() == chain_block::CellType::PrunedBranch {
            count += 1;
            continue;
        }
        for i in 0..cell.references_count() {
            if let Ok(child) = cell.reference(i) {
                stack.push(child);
            }
        }
    }
    count
}
