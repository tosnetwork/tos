// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Replay recorded chain transactions through the Rust executor.
//!
//! The input is the transcript `test-epoch-replay --dump` writes while the C++
//! emulator re-executes the REL-02 blocks: for every transaction its exact
//! inputs (account, message, configuration, libraries, previous blocks, time,
//! logical time, seed) and the on-chain transaction and account hashes. Each
//! transaction is executed the way the emulator library executes it, and the
//! resulting transaction cell and account hash must equal the chain's.
use std::{env, fs, io::Read};

use chain_block::{
    read_single_root_boc, Account, Cell, ConfigParams, Deserializable, HashUpdate, HashmapE,
    Serializable, ShardAccount, SliceData, Transaction, TransactionTickTock, UInt256,
};
use tos_executor::{
    BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TickTockTransactionExecutor,
    TransactionExecutor,
};
use tos_vm::{smart_contract_info::PrevBlocksInfo, stack::read_stack_item};

const MAX_DUMP_BYTES: usize = 64 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROW_BYTES: usize = 1024 * 1024;
const MAX_ROWS: usize = 10_000;
const MAX_CELL_VISITS: usize = 2_000_000;
const MAX_DEPTH: usize = 1024;

fn bounded_text(path: &str, limit: usize) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= limit, "input byte limit exceeded");
    Ok(String::from_utf8(bytes)?)
}

fn hash_text(value: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid hash field"
    );
    Ok(value.to_ascii_lowercase())
}

fn complete_account(root: &Cell) -> anyhow::Result<()> {
    let mut visited = std::collections::HashMap::new();
    let mut pending = vec![(root.clone(), 0usize)];
    let mut work = 0;
    while let Some((cell, depth)) = pending.pop() {
        work += 1;
        anyhow::ensure!(
            work <= MAX_CELL_VISITS && depth <= MAX_DEPTH,
            "account traversal limit exceeded"
        );
        anyhow::ensure!(
            cell.cell_type() != chain_block::CellType::PrunedBranch,
            "incomplete account input: pruned branch"
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
    source_wc: i64,
    source_shard: u64,
    source_seqno: u32,
    source_root: String,
    source_file: String,
    post_account_depth: u16,
}

fn parse(line: &str) -> anyhow::Result<Row> {
    anyhow::ensure!(line.len() < MAX_ROW_BYTES, "row byte limit exceeded");
    let f: Vec<_> = line.split('\t').collect();
    anyhow::ensure!(f.len() == 18, "a v2 dump row has 18 fields, found {}", f.len());
    let post_account_depth: u16 = f[17].parse()?;
    anyhow::ensure!(post_account_depth <= 1024, "invalid native Account depth");
    // Inspect the unvirtualized graph: virtualization must not hide a hole.
    let raw_account = read_single_root_boc(hex::decode(f[4])?)?;
    complete_account(&raw_account)?;
    Ok(Row {
        kind: f[0].parse()?,
        now: f[1].parse()?,
        lt: f[2].parse()?,
        seed: f[3].parse().map_err(|e| anyhow::anyhow!("invalid seed: {e}"))?,
        shard_account: raw_account,
        message: hex_cell(f[5])?,
        config: required(f[6], "configuration")?,
        libraries: hex_cell(f[7])?,
        previous_blocks: required(f[8], "previous blocks")?,
        // The C++ transcript writes hashes in upper case.
        transaction_hash: hash_text(f[9])?,
        account_hash: hash_text(f[10])?,
        original: required(f[11], "original transaction")?,
        source_wc: f[12].parse()?,
        source_shard: f[13].parse()?,
        source_seqno: f[14].parse()?,
        source_root: hash_text(f[15])?,
        source_file: hash_text(f[16])?,
        post_account_depth,
    })
}

struct Outcome {
    transaction: Option<Cell>,
    account_hash: String,
    account: Option<Account>,
    shard_account: Option<ShardAccount>,
    error: String,
}

fn execute(row: &Row, carried: Option<(ShardAccount, Account)>) -> anyhow::Result<Outcome> {
    let config = BlockchainConfig::with_config(ConfigParams::with_root(row.config.clone())?)?;
    anyhow::ensure!(config.global_version() == 16, "replay requires global version 16");
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
    let (mut shard_account, mut account) = match carried {
        Some((mut shard, account)) => {
            shard.write_account(&account)?;
            anyhow::ensure!(
                shard.serialize()?.repr_hash() == row.shard_account.repr_hash(),
                "carried ShardAccount differs from authenticated input at {}",
                row.lt
            );
            (shard, account)
        }
        None => {
            let shard = ShardAccount::construct_from_cell(row.shard_account.clone())?;
            let account = shard.read_account()?;
            (shard, account)
        }
    };
    let old_hash = shard_account.account_hash();
    let original = Transaction::construct_from_cell(row.original.clone())?;
    anyhow::ensure!(original.read_state_update()?.old_hash == old_hash, "input pre-state mismatch");
    let mut transaction =
        match executor.execute_with_params(row.message.clone(), &mut account, params) {
            Ok(transaction) => transaction,
            Err(error) => {
                return Ok(Outcome {
                    transaction: None,
                    account_hash: String::from("-"),
                    account: None,
                    shard_account: None,
                    error: error.to_string().replace(['\t', '\n'], " "),
                })
            }
        };
    account.update_storage_stat(dict_hash_min_cells)?;
    transaction.set_prev_trans_lt(shard_account.last_trans_lt());
    transaction.set_prev_trans_hash(shard_account.last_trans_hash().clone());
    shard_account.write_account(&account)?;
    let new_hash = shard_account.account_hash();
    transaction.write_state_update(&HashUpdate::with_hashes(old_hash, new_hash.clone()))?;
    let transaction_cell = transaction.serialize()?;
    shard_account.set_last_trans_hash(transaction_cell.repr_hash());
    shard_account.set_last_trans_lt(transaction.logical_time());
    Ok(Outcome {
        transaction: Some(transaction_cell),
        account_hash: hex::encode(new_hash.as_slice()),
        account: Some(account),
        shard_account: Some(shard_account),
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
    // Only the orchestrator can establish authenticated export provenance.
    // The digest binds this invocation to its successfully verified export.
    let args: Vec<_> = env::args().collect();
    anyhow::ensure!(
        args.len() == 5,
        "usage: rel02-replay dump.tsv manifest.json topology.json verified-dump-sha256"
    );
    let data = bounded_text(&args[1], MAX_DUMP_BYTES)?;
    anyhow::ensure!(
        UInt256::calc_file_hash(data.as_bytes()).to_hex_string().to_lowercase()
            == hash_text(&args[4])?,
        "dump digest differs from verified native export"
    );
    let mut lines = data.lines();
    anyhow::ensure!(lines.next() == Some("#rel02-v2"), "unsupported dump schema");
    anyhow::ensure!(data.ends_with('\n'), "truncated dump");
    let mut rows = Vec::new();
    for line in lines {
        anyhow::ensure!(rows.len() < MAX_ROWS, "row count limit exceeded");
        rows.push(parse(line)?);
    }
    let manifest: serde_json::Value =
        serde_json::from_str(&bounded_text(&args[2], MAX_METADATA_BYTES)?)?;
    let topology: serde_json::Value =
        serde_json::from_str(&bounded_text(&args[3], MAX_METADATA_BYTES)?)?;
    let records =
        manifest["expected"].as_array().ok_or_else(|| anyhow::anyhow!("expected records"))?;
    let mut expected = Vec::new();
    let mut source = None;
    for record in records {
        if record["kind"] == "block" {
            source = Some(record);
        } else {
            anyhow::ensure!(record["kind"] == "transaction", "unknown oracle record");
            let block = source.ok_or_else(|| anyhow::anyhow!("missing source block"))?;
            expected.push((
                block["workchain"].as_i64().ok_or_else(|| anyhow::anyhow!("missing workchain"))?,
                record,
                block,
            ));
        }
    }
    anyhow::ensure!(rows.len() == expected.len() && rows.len() == 576, "missing/extra rows");
    let mut originals = Vec::new();
    let mut identity = Vec::new();
    let mut by_hash = std::collections::HashMap::new();
    for (index, (row, (wc, record, source))) in rows.iter().zip(&expected).enumerate() {
        let tx = Transaction::construct_from_cell(row.original.clone())?;
        anyhow::ensure!(
            row.source_wc == *wc
                && Some(row.source_seqno as u64) == source["seqno"].as_u64()
                && row.source_shard.to_string() == source["shard"].as_str().unwrap_or("")
                && row.source_root.eq_ignore_ascii_case(source["root_hash"].as_str().unwrap_or(""))
                && row.source_file.eq_ignore_ascii_case(source["file_hash"].as_str().unwrap_or("")),
            "row {index} source block identity mismatch"
        );
        let actual_address = hex::encode(tx.account_id().get_bytestring(0));
        anyhow::ensure!(
            actual_address.eq_ignore_ascii_case(record["account"].as_str().unwrap_or("")),
            "row {index} account identity mismatch"
        );
        let expected_kind = match tx.read_description()? {
            chain_block::TransactionDescr::Ordinary(_) => ORDINARY,
            chain_block::TransactionDescr::TickTock(t) => {
                if t.tt == TransactionTickTock::Tock {
                    TOCK
                } else {
                    TICK
                }
            }
            _ => anyhow::bail!("unsupported original transaction description"),
        };
        anyhow::ensure!(row.kind == expected_kind, "row {index} transaction type mismatch");
        let original_message =
            if tx.in_msg.is_empty() { None } else { Some(tx.in_msg.cell().repr_hash()) };
        anyhow::ensure!(
            row.message.as_ref().map(|cell| cell.repr_hash()) == original_message,
            "row {index} inbound message mismatch"
        );
        anyhow::ensure!(
            BlockchainConfig::with_config(ConfigParams::with_root(row.config.clone())?)?
                .global_version()
                == 16,
            "row {index} global version is not 16"
        );
        anyhow::ensure!(
            row.transaction_hash.eq_ignore_ascii_case(record["result_hash"].as_str().unwrap_or(""))
                && row
                    .account_hash
                    .eq_ignore_ascii_case(record["account_hash"].as_str().unwrap_or("")),
            "row {index} differs from ordered manifest"
        );
        anyhow::ensure!(
            hex::encode(row.original.repr_hash().as_slice()) == row.transaction_hash,
            "row {index} original transaction hash mismatch"
        );
        anyhow::ensure!(
            tx.logical_time() == row.lt && tx.now() == row.now,
            "row {index} identity mismatch"
        );
        let shard = ShardAccount::construct_from_cell(row.shard_account.clone())?;
        anyhow::ensure!(
            shard.last_trans_hash() == tx.prev_trans_hash()
                && shard.last_trans_lt() == tx.prev_trans_lt(),
            "row {index} predecessor mismatch"
        );

        anyhow::ensure!(
            by_hash.insert(row.transaction_hash.clone(), index).is_none(),
            "duplicate transaction"
        );
        identity.push((*wc, hex::encode(tx.account_id().get_bytestring(0))));
        originals.push(tx);
    }
    let mut incoming = vec![None; rows.len()];
    let mut outgoing = vec![None; rows.len()];
    let mut last = std::collections::HashMap::new();
    let mut anchors = Vec::new();
    let mut edges = Vec::new();
    for (index, tx) in originals.iter().enumerate() {
        let previous = last.insert(identity[index].clone(), index);
        if let Some(prev) = previous {
            anyhow::ensure!(rows[prev].lt < rows[index].lt, "non-increasing account LT");
        }
        if let Some(&prev) = by_hash.get(&tx.prev_trans_hash().to_hex_string().to_lowercase()) {
            anyhow::ensure!(
                prev < index
                    && previous == Some(prev)
                    && identity[prev] == identity[index]
                    && rows[prev].lt == tx.prev_trans_lt(),
                "invalid predecessor edge at row {index}"
            );
            anyhow::ensure!(outgoing[prev].replace(index).is_none(), "forked predecessor");
            incoming[index] = Some(prev);
            edges.push(serde_json::json!([prev, index]));
        } else {
            anyhow::ensure!(tx.prev_trans_lt() < tx.logical_time(), "invalid anchor LT");
            if let Some(prev) = previous {
                anyhow::ensure!(rows[prev].lt < tx.prev_trans_lt(), "anchor resets known history");
            }
            anchors.push(index);
        }
    }
    anyhow::ensure!(serde_json::Value::Array(edges) == topology["edges"], "changed carry topology");
    let expected_anchors: Vec<_> = topology["anchors"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("anchors"))?
        .iter()
        .map(|a| a["index"].as_u64().map(|n| n as usize))
        .collect();
    anyhow::ensure!(
        anchors.iter().copied().map(Some).collect::<Vec<_>>() == expected_anchors,
        "changed segment anchors"
    );
    anyhow::ensure!(anchors.len() == 102, "unexpected anchors");
    for (index, anchor) in anchors
        .iter()
        .zip(topology["anchors"].as_array().ok_or_else(|| anyhow::anyhow!("anchors"))?)
    {
        let row = &rows[*index];
        let tx = &originals[*index];
        anyhow::ensure!(
            anchor["hash"].as_str() == Some(row.transaction_hash.as_str())
                && anchor["workchain"].as_i64() == Some(row.source_wc)
                && anchor["address"].as_str() == Some(identity[*index].1.as_str())
                && anchor["lt"].as_u64() == Some(row.lt)
                && anchor["prev_lt"].as_u64() == Some(tx.prev_trans_lt())
                && anchor["prev_hash"].as_str()
                    == Some(tx.prev_trans_hash().to_hex_string().to_lowercase().as_str()),
            "changed authenticated segment anchor"
        );
    }
    let mut states = std::collections::HashMap::new();
    let mut equal = 0;
    let mut carried_count = 0;
    for (index, row) in rows.iter().enumerate() {
        let carried = if incoming[index].is_some() {
            carried_count += 1;
            Some(
                states
                    .remove(&identity[index])
                    .ok_or_else(|| anyhow::anyhow!("missing carried state"))?,
            )
        } else {
            anyhow::ensure!(
                !states.contains_key(&identity[index]),
                "anchor discards pending carry"
            );
            None
        };
        let mut outcome = execute(row, carried)?;
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
        let shard_hash = match &outcome.shard_account {
            Some(shard) => hex::encode(shard.serialize()?.repr_hash().as_slice()),
            None => String::from("-"),
        };
        let actual_depth = outcome
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no resulting Account"))?
            .serialize()?
            .depth(0);
        anyhow::ensure!(
            actual_depth == row.post_account_depth,
            "row {index}: Account depth mismatch"
        );
        // ShardAccount is 320 ordinary bits and one Account reference. Use the
        // original transaction's start LT, never the Account's ending LT.
        let mut expected_shard = vec![1u8, 80u8];
        expected_shard.extend(hex::decode(&row.transaction_hash)?);
        expected_shard.extend(row.lt.to_be_bytes());
        expected_shard.extend(row.post_account_depth.to_be_bytes());
        expected_shard.extend(hex::decode(&row.account_hash)?);
        let expected_shard = hex::encode(UInt256::calc_file_hash(&expected_shard).as_slice());
        anyhow::ensure!(shard_hash == expected_shard, "row {index}: ShardAccount oracle mismatch");
        println!(
            "{index}\t{}\t{}\t{}\t{}\t{detail}\t{tx_hash}\t{}\t{shard_hash}",
            row.kind,
            row.lt,
            if same { "EQUAL" } else { "DIFF" },
            if outcome.account_hash == row.account_hash { "account=" } else { "account!=" },
            outcome.account_hash
        );
        anyhow::ensure!(same, "row {index}: full transaction/account root mismatch");
        equal += 1;
        if outgoing[index].is_some() {
            let account =
                outcome.account.take().ok_or_else(|| anyhow::anyhow!("no resulting Account"))?;
            let shard = outcome
                .shard_account
                .take()
                .ok_or_else(|| anyhow::anyhow!("no resulting ShardAccount"))?;
            anyhow::ensure!(
                states.insert(identity[index].clone(), (shard, account)).is_none(),
                "unconsumed carry"
            );
        }
    }
    anyhow::ensure!(
        states.is_empty() && equal == 576 && carried_count == 474,
        "incomplete carry replay"
    );
    eprintln!(
        "{equal}/576 equal; {carried_count} actual Account carries; {} anchors",
        anchors.len()
    );
    Ok(())
}
