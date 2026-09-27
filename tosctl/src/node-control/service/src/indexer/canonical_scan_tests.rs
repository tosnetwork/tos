/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Scenario tests for canonical traversal and publication, driven against a
//! scripted chain and a real SQLite store.

use super::*;
use chain_rpc_client::v2::data_models::{AccountState, ShortTxId, TransactionId};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use tl_api::tos::tvm::{
    List, Number, StackEntry, Tuple, list,
    numberdecimal::NumberDecimal,
    stackentry::{StackEntryList, StackEntryNumber, StackEntryTuple},
    tuple,
};

pub(super) type Key = (i32, i64, u32);

pub(super) const MC: i64 = i64::MIN;
pub(super) const ROOT: i64 = i64::MIN;
pub(super) const LEFT: i64 = 0x4000_0000_0000_0000;
pub(super) const RIGHT: i64 = 0xC000_0000_0000_0000_u64 as i64;

/// A deterministic identity: coordinates plus a fork tag, so the same
/// coordinate on two forks yields two different hashes.
pub(super) fn block_id(workchain: i32, shard: i64, seqno: u32, fork: u8) -> BlockIdExt {
    let mut root = [0u8; 32];
    root[0..4].copy_from_slice(&seqno.to_be_bytes());
    root[4..12].copy_from_slice(&shard.to_be_bytes());
    root[12..16].copy_from_slice(&workchain.to_be_bytes());
    root[16] = fork;
    let mut file = root;
    file[31] = 0xF1;
    BlockIdExt {
        r#type: "tos.blockIdExt".to_owned(),
        workchain,
        shard,
        seqno,
        root_hash: root.to_vec(),
        file_hash: file.to_vec(),
    }
}

fn key(id: &BlockIdExt) -> Key {
    (id.workchain, id.shard, id.seqno)
}

/// One pool state, effective from a masterchain seqno onwards.
#[derive(Clone, Debug)]
pub(super) struct PoolFixture {
    pub(super) state: i32,
    pub(super) nominators: Vec<([u8; 32], u64, u64)>,
}

#[derive(Default)]
pub(super) struct ChainState {
    pub(super) tip: u32,
    pub(super) blocks: HashMap<Key, (BlockIdExt, Vec<ShortTxId>)>,
    pub(super) parents: HashMap<Key, Vec<BlockIdExt>>,
    pub(super) shards: HashMap<u32, Vec<BlockIdExt>>,
    pub(super) pools: HashMap<String, BTreeMap<u32, PoolFixture>>,
    pub(super) historical_get_methods: bool,
    pub(super) wrong_identity_method: Option<String>,
    pub(super) fail_get_shards: bool,
    pub(super) fail_parents_of: HashSet<Key>,
    /// Fail the n-th (1-based) masterchain identity lookup.
    pub(super) fail_lookup_number: Option<usize>,
    pub(super) lookups: usize,
    pub(super) parent_calls: HashMap<Key, usize>,
    pub(super) scans: HashMap<Key, usize>,
    pub(super) scan_order: Vec<Key>,
    pub(super) pinned_reads: Vec<(String, u32)>,
}

pub(super) struct FakeChain {
    pub(super) state: Mutex<ChainState>,
}

impl FakeChain {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ChainState { historical_get_methods: true, ..Default::default() }),
        })
    }

    pub(super) fn with<R>(&self, f: impl FnOnce(&mut ChainState) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    pub(super) fn add_block(&self, workchain: i32, shard: i64, seqno: u32, fork: u8) -> BlockIdExt {
        let id = block_id(workchain, shard, seqno, fork);
        self.with(|s| s.blocks.insert(key(&id), (id.clone(), Vec::new())));
        id
    }

    pub(super) fn set_parents(&self, child: &BlockIdExt, parents: &[&BlockIdExt]) {
        let parents = parents.iter().map(|p| (*p).clone()).collect();
        self.with(|s| s.parents.insert(key(child), parents));
    }

    /// Masterchain block `seqno` on `fork`, referencing `heads`.
    pub(super) fn add_master(&self, seqno: u32, fork: u8, heads: &[&BlockIdExt]) -> BlockIdExt {
        let id = self.add_block(-1, MC, seqno, fork);
        let heads = heads.iter().map(|h| (*h).clone()).collect();
        self.with(|s| {
            s.shards.insert(seqno, heads);
            s.tip = s.tip.max(seqno);
        });
        id
    }

    pub(super) fn add_tx(&self, block: &BlockIdExt, account_hex: &str, hash: &str) {
        self.with(|s| {
            s.blocks.get_mut(&key(block)).unwrap().1.push(ShortTxId {
                r#type: None,
                account: account_hex.to_owned(),
                lt: 1_000,
                hash: hash.to_owned(),
            })
        });
    }

    /// A linear chain of `shard` blocks `from..=to`, each the parent of the
    /// next; block 1's parent is the zerostate.
    pub(super) fn shard_chain(&self, shard: i64, from: u32, to: u32, fork: u8) -> Vec<BlockIdExt> {
        let mut out = Vec::new();
        for seqno in from..=to {
            let id = self.add_block(0, shard, seqno, fork);
            let parent = if seqno == 1 {
                block_id(0, shard, 0, 0)
            } else {
                self.with(|s| s.blocks.get(&(0, shard, seqno - 1)).unwrap().0.clone())
            };
            self.set_parents(&id, &[&parent]);
            out.push(id);
        }
        out
    }

    pub(super) fn scans_of(&self, id: &BlockIdExt) -> usize {
        self.with(|s| s.scans.get(&key(id)).copied().unwrap_or(0))
    }

    pub(super) fn parent_calls_of(&self, id: &BlockIdExt) -> usize {
        self.with(|s| s.parent_calls.get(&key(id)).copied().unwrap_or(0))
    }

    pub(super) fn dyn_chain(self: &Arc<Self>) -> Arc<dyn ChainProvider> {
        self.clone()
    }
}

fn number(value: &str) -> StackEntry {
    StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
        number: Number::Tvm_NumberDecimal(NumberDecimal { number: value.to_owned() }),
    })
}

fn tuple_entry(elements: Vec<StackEntry>) -> StackEntry {
    StackEntry::Tvm_StackEntryTuple(StackEntryTuple {
        tuple: Tuple::Tvm_Tuple(tuple::Tuple { elements }),
    })
}

fn list_entry(elements: Vec<StackEntry>) -> StackEntry {
    StackEntry::Tvm_StackEntryList(StackEntryList { list: List::Tvm_List(list::List { elements }) })
}

fn pool_data_stack(fixture: &PoolFixture) -> common::tvm_stack_parser::TvmStackParser {
    common::tvm_stack_parser::TvmStackParser::new(vec![
        number(&fixture.state.to_string()),
        number(&fixture.nominators.len().to_string()),
        number("0"),
        number("2000"),
        number("0xabc"),
        number("0xdef"),
        number("4000"),
        number("40"),
        number("1000"),
        number("100"),
        list_entry(vec![]),
        list_entry(vec![]),
        number("999"),
        number("0x11"),
        number("0"),
        number("1234"),
        number("3600"),
        list_entry(vec![]),
    ])
}

fn nominators_stack(fixture: &PoolFixture) -> common::tvm_stack_parser::TvmStackParser {
    common::tvm_stack_parser::TvmStackParser::new(vec![list_entry(
        fixture
            .nominators
            .iter()
            .map(|(address, amount, pending)| {
                tuple_entry(vec![
                    number(&format!("0x{}", hex::encode(address))),
                    number(&amount.to_string()),
                    number(&pending.to_string()),
                    number("0"),
                ])
            })
            .collect(),
    )])
}

#[async_trait::async_trait]
impl ChainProvider for FakeChain {
    async fn run_get_method(
        &self,
        _address: String,
        _method: &str,
        _stack: Vec<StackEntry>,
    ) -> anyhow::Result<common::tvm_stack_parser::TvmStackParser> {
        anyhow::bail!("latest-state get-methods are not scripted")
    }

    async fn run_get_method_at(
        &self,
        address: String,
        method: &str,
        _stack: Vec<StackEntry>,
        checkpoint: &MasterchainCheckpoint,
    ) -> anyhow::Result<common::tvm_stack_parser::TvmStackParser> {
        let mut s = self.state.lock().unwrap();
        anyhow::ensure!(s.historical_get_methods, "historical state is unavailable");
        let master = s
            .blocks
            .get(&(-1, MC, checkpoint.seqno))
            .map(|(id, _)| id.clone())
            .ok_or_else(|| anyhow::anyhow!("no masterchain block {}", checkpoint.seqno))?;
        anyhow::ensure!(
            hex::encode(&master.root_hash) == checkpoint.root_hash
                && hex::encode(&master.file_hash) == checkpoint.file_hash
                && s.wrong_identity_method.as_deref() != Some(method),
            "checkpoint get-method returned another block"
        );
        s.pinned_reads.push((method.to_owned(), checkpoint.seqno));
        let fixture = s
            .pools
            .get(&address)
            .and_then(|history| history.range(..=checkpoint.seqno).next_back())
            .map(|(_, fixture)| fixture.clone())
            .ok_or_else(|| anyhow::anyhow!("account {address} is not active at the checkpoint"))?;
        match method {
            "get_pool_data" => Ok(pool_data_stack(&fixture)),
            "list_nominators" => Ok(nominators_stack(&fixture)),
            other => anyhow::bail!("unexpected get-method {other}"),
        }
    }

    async fn get_balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
        anyhow::bail!("not scripted")
    }
    async fn send_boc(&self, _boc: &[u8]) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }
    async fn get_config_param(
        &self,
        _param_id: u32,
    ) -> anyhow::Result<chain_block::ConfigParamEnum> {
        anyhow::bail!("not scripted")
    }
    async fn get_address_info(
        &self,
        address: &MsgAddressInt,
    ) -> anyhow::Result<contracts::chain_provider::AddressInfo> {
        let is_pool = self.with(|s| s.pools.contains_key(&address.to_string()));
        let code = if is_pool { Some(hex::decode(NOMINATOR_POOL_CODE)?) } else { None };
        Ok(contracts::chain_provider::AddressInfo {
            r#type: "raw.fullAccountState".to_owned(),
            balance: 0,
            code,
            data: None,
            last_transaction_id: TransactionId {
                r#type: "internal.transactionId".to_owned(),
                lt: 0,
                hash: vec![0; 32],
            },
            block_id: block_id(-1, MC, 0, 0),
            sync_utime: 0,
            extra_currencies: Vec::new(),
            state: AccountState::default(),
            frozen_hash: String::new(),
        })
    }
    async fn get_extended_address_info(
        &self,
        _address: &MsgAddressInt,
    ) -> anyhow::Result<contracts::chain_provider::ExtendedAddressInfo> {
        anyhow::bail!("not scripted")
    }
    async fn get_wallet_info(
        &self,
        _address: &MsgAddressInt,
    ) -> anyhow::Result<contracts::chain_provider::WalletInfo> {
        anyhow::bail!("not scripted")
    }
    async fn get_masterchain_info(
        &self,
    ) -> anyhow::Result<contracts::chain_provider::MasterchainInfo> {
        let s = self.state.lock().unwrap();
        let last = s
            .blocks
            .get(&(-1, MC, s.tip))
            .map(|(id, _)| id.clone())
            .ok_or_else(|| anyhow::anyhow!("no masterchain tip"))?;
        Ok(contracts::chain_provider::MasterchainInfo {
            r#type: None,
            last,
            state_root_hash: String::new(),
            init: None,
        })
    }
    async fn get_shards(
        &self,
        seqno: u32,
    ) -> anyhow::Result<contracts::chain_provider::ShardsInfo> {
        let s = self.state.lock().unwrap();
        anyhow::ensure!(!s.fail_get_shards, "simulated shard descriptor outage");
        let shards = s
            .shards
            .get(&seqno)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no shard descriptors for {seqno}"))?;
        Ok(contracts::chain_provider::ShardsInfo { r#type: None, shards })
    }
    async fn get_block_parents(&self, id: &BlockIdExt) -> anyhow::Result<Vec<BlockIdExt>> {
        let mut s = self.state.lock().unwrap();
        *s.parent_calls.entry(key(id)).or_insert(0) += 1;
        anyhow::ensure!(!s.fail_parents_of.contains(&key(id)), "simulated header outage");
        s.parents
            .get(&key(id))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no proof-derived predecessor for {:?}", key(id)))
    }
    async fn get_block_transactions_page(
        &self,
        workchain: i32,
        shard: i64,
        seqno: u32,
        _after_lt: Option<u64>,
        _after_account: Option<&str>,
        count: u32,
    ) -> anyhow::Result<contracts::chain_provider::BlockTransactionsPage> {
        let mut s = self.state.lock().unwrap();
        let k = (workchain, shard, seqno);
        if workchain == -1 && count == 1 {
            s.lookups += 1;
            if s.fail_lookup_number == Some(s.lookups) {
                anyhow::bail!("simulated masterchain lookup outage");
            }
        } else {
            *s.scans.entry(k).or_insert(0) += 1;
            s.scan_order.push(k);
        }
        let (id, txs) =
            s.blocks.get(&k).cloned().ok_or_else(|| anyhow::anyhow!("no block {k:?}"))?;
        Ok(contracts::chain_provider::BlockTransactionsPage {
            r#type: None,
            id: Some(id),
            req_count: None,
            incomplete: false,
            transactions: if count == 1 { Vec::new() } else { txs },
        })
    }
}

pub(super) fn limits(max_batches: u32, max_shard_work: usize) -> ScanLimits {
    ScanLimits { max_batches, max_shard_work, max_refresh: MAX_ADDRESS_REFRESH_PER_DRAIN }
}

pub(super) async fn run_tick(
    chain: &Arc<FakeChain>,
    store: &IndexerStore,
    limits: &ScanLimits,
) -> anyhow::Result<ScanOutcome> {
    scan_new_blocks(
        &chain.dyn_chain(),
        store,
        &KnownCodeHashes::compute()?,
        &ProbeBudget::new(),
        limits,
    )
    .await
}

/// Ticks until the published height reaches `target`, failing the test if
/// that takes more than `max_ticks`.
pub(super) async fn run_until(
    chain: &Arc<FakeChain>,
    store: &IndexerStore,
    limits: &ScanLimits,
    target: u32,
    max_ticks: usize,
) -> Vec<ScanOutcome> {
    let mut outcomes = Vec::new();
    for _ in 0..max_ticks {
        let outcome = run_tick(chain, store, limits).await.unwrap();
        outcomes.push(outcome.clone());
        if outcome.published_mc_seqno >= target {
            return outcomes;
        }
    }
    panic!("did not publish {target} within {max_ticks} ticks: {outcomes:?}");
}

/// Every durable fact of the canonical index except wall-clock stamps.
pub(super) fn snapshot(store: &IndexerStore) -> String {
    let (mut blocks, _) = store.list_explorer_blocks(0, 200).unwrap();
    for block in &mut blocks {
        block.indexed_at = 0;
    }
    blocks.sort_by_key(|b| (b.workchain, b.shard, b.seqno));
    let (mut txs, _) = store.list_explorer_transactions(None, 0, 200).unwrap();
    for tx in &mut txs {
        tx.indexed_at = 0;
    }
    txs.sort_by(|a, b| a.hash.cmp(&b.hash));
    format!(
        "{blocks:?}\n{txs:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}",
        store.canonical_state().unwrap(),
        store.canonical_shard_frontier().unwrap(),
        store.checkpoints().unwrap(),
        store.address_refresh_queue(200).unwrap(),
        store.pending_batch().unwrap(),
        store.raw_explorer_row_counts().unwrap(),
    )
}

pub(super) fn temp_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("indexer.sqlite");
    (dir, path)
}

fn hex_of(id: &BlockIdExt) -> String {
    hex::encode(&id.root_hash)
}

// ─── Explorer / traversal ─────────────────────────────────────────────────

/// Thirty masterchain heights, each moving the shard head three blocks.
fn thirty_heights(chain: &FakeChain) -> Vec<BlockIdExt> {
    let shard_blocks = chain.shard_chain(ROOT, 1, 90, 0);
    for mc in 1..=30u32 {
        let head = &shard_blocks[(mc * 3 - 1) as usize];
        chain.add_master(mc, 0, &[head]);
    }
    shard_blocks
}

#[tokio::test]
async fn fresh_database_reaches_the_tip_in_bounded_ticks_with_a_monotone_checkpoint() {
    let chain = FakeChain::new();
    let shard_blocks = thirty_heights(&chain);
    let store = IndexerStore::open_in_memory().unwrap();
    let bounded = limits(7, 20);
    let mut previous = 0;
    let mut ticks = 0;
    loop {
        let before = chain
            .with(|s| s.scans.values().sum::<usize>() + s.parent_calls.values().sum::<usize>());
        let outcome = run_tick(&chain, &store, &bounded).await.unwrap();
        let after = chain
            .with(|s| s.scans.values().sum::<usize>() + s.parent_calls.values().sum::<usize>());
        ticks += 1;
        assert!(after - before <= 20, "one tick did {} work units", after - before);
        assert!(outcome.published_mc_seqno >= previous, "checkpoint went backwards");
        assert!(outcome.published_mc_seqno - previous <= 7, "published more than the batch limit");
        assert_eq!(
            store.checkpoint("-1:-9223372036854775808").unwrap(),
            outcome.published_mc_seqno
        );
        previous = outcome.published_mc_seqno;
        if previous == 30 {
            break;
        }
        assert!(ticks < 40, "no progress: {outcome:?}");
    }
    assert!(ticks > 1, "the bound must actually have split the work");
    for block in &shard_blocks {
        assert_eq!(chain.scans_of(block), 1, "block {} scanned more than once", block.seqno);
        assert!(store.explorer_block_by_hash(&hex_of(block)).unwrap().is_some());
    }
    assert_eq!(store.canonical_shard_frontier().unwrap().len(), 1);
    assert_eq!(store.canonical_shard_frontier().unwrap()[0].seqno, 90);
}

/// Unindexed ancestry deeper than one tick's work budget is a normal
/// Pending, resumed across a process restart from durable state, never a
/// fatal error or a restart from zero.
#[tokio::test]
async fn deep_ancestry_yields_pending_and_resumes_across_a_restart() {
    let chain = FakeChain::new();
    let depth = 5_000u32;
    let blocks = chain.shard_chain(ROOT, 1, depth, 0);
    chain.add_master(1, 0, &[&blocks[0]]);
    chain.add_master(2, 0, &[&blocks[(depth - 1) as usize]]);
    let (_dir, path) = temp_db();
    let production = ScanLimits::production();
    let mut trace = Vec::new();
    let mut tick_number = 0;
    loop {
        // Each tick runs in a fresh process: the store is reopened from disk.
        let store = IndexerStore::open_for_tests(&path).unwrap();
        let outcome = run_tick(&chain, &store, &production).await.unwrap();
        tick_number += 1;
        let line = format!(
            "tick={tick_number} published_mc_seqno={} remote_tip={} pending_batch={:?} work={:?}",
            outcome.published_mc_seqno,
            outcome.remote_tip,
            store.pending_batch().unwrap().map(|b| b.anchor.seqno),
            store.pending_work_counts().unwrap()
        );
        println!("{line}");
        trace.push(line);
        if outcome.published_mc_seqno == 2 {
            break;
        }
        assert!(tick_number < 10, "no progress:\n{}", trace.join("\n"));
    }
    assert!(tick_number >= 3, "5000 blocks cannot fit one {MAX_SHARD_WORK_PER_TICK}-unit tick");
    let store = IndexerStore::open_for_tests(&path).unwrap();
    for block in &blocks {
        assert_eq!(chain.parent_calls_of(block), 1, "parents of {} refetched", block.seqno);
        assert_eq!(chain.scans_of(block), 1, "block {} rescanned", block.seqno);
    }
    assert_eq!(store.explorer_stats().unwrap().blocks, depth as usize + 2);
    if let Ok(dir) = std::env::var("INDEXER_TRACE_DIR") {
        std::fs::write(format!("{dir}/deep-ancestry-trace.txt"), trace.join("\n") + "\n").unwrap();
    }
}

#[tokio::test]
async fn split_and_merge_follow_full_identity_edges_ancestors_first() {
    let chain = FakeChain::new();
    let r1 = chain.add_block(0, ROOT, 1, 0);
    chain.set_parents(&r1, &[&block_id(0, ROOT, 0, 0)]);
    let r2 = chain.add_block(0, ROOT, 2, 0);
    chain.set_parents(&r2, &[&r1]);
    chain.add_master(1, 0, &[&r2]);
    // Split: one parent, two children.
    let l3 = chain.add_block(0, LEFT, 3, 0);
    let rr3 = chain.add_block(0, RIGHT, 3, 0);
    chain.set_parents(&l3, &[&r2]);
    chain.set_parents(&rr3, &[&r2]);
    let l4 = chain.add_block(0, LEFT, 4, 0);
    chain.set_parents(&l4, &[&l3]);
    chain.add_master(2, 0, &[&l4, &rr3]);
    // Merge: two parents, one child.
    let m5 = chain.add_block(0, ROOT, 5, 0);
    chain.set_parents(&m5, &[&l4, &rr3]);
    chain.add_master(3, 0, &[&m5]);
    let store = IndexerStore::open_in_memory().unwrap();

    run_until(&chain, &store, &limits(1, 100), 1, 3).await;
    assert_eq!(store.canonical_shard_frontier().unwrap().len(), 1);
    run_until(&chain, &store, &limits(1, 100), 2, 3).await;
    let frontier = store.canonical_shard_frontier().unwrap();
    // Ordered by (workchain, shard) as signed integers: RIGHT is negative.
    assert_eq!(
        frontier.iter().map(|f| (f.shard, f.seqno)).collect::<Vec<_>>(),
        vec![(RIGHT, 3), (LEFT, 4)]
    );
    run_until(&chain, &store, &limits(1, 100), 3, 3).await;
    assert_eq!(store.canonical_shard_frontier().unwrap()[0].seqno, 5);

    for block in [&r1, &r2, &l3, &rr3, &l4, &m5] {
        assert_eq!(chain.scans_of(block), 1);
        let row = store.explorer_block_by_hash(&hex_of(block)).unwrap().unwrap();
        assert_eq!(row.file_hash, hex::encode(&block.file_hash));
    }
    let order = chain.with(|s| s.scan_order.clone());
    let position = |id: &BlockIdExt| order.iter().position(|k| *k == key(id)).unwrap();
    for (child, parents) in
        [(&l3, vec![&r2]), (&rr3, vec![&r2]), (&l4, vec![&l3]), (&m5, vec![&l4, &rr3])]
    {
        for parent in parents {
            assert!(position(parent) < position(child), "{:?} before its parent", key(child));
        }
    }
    // Each block's parents were fetched exactly once, in the height that
    // introduced it; as a published frontier head it is never expanded again.
    for block in [&r1, &r2, &l3, &rr3, &l4, &m5] {
        assert_eq!(chain.parent_calls_of(block), 1, "{:?}", key(block));
    }
}

/// Publishes height 1 with head `(0, ROOT, 2)` and returns the chain.
async fn published_first_height() -> (Arc<FakeChain>, IndexerStore, Vec<BlockIdExt>) {
    let chain = FakeChain::new();
    let blocks = chain.shard_chain(ROOT, 1, 2, 0);
    chain.add_master(1, 0, &[&blocks[1]]);
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(10, 100), 1, 2).await;
    (chain, store, blocks)
}

async fn assert_height_two_fails_closed(
    chain: &Arc<FakeChain>,
    store: &IndexerStore,
    expect: &str,
) {
    let before = store.explorer_stats().unwrap();
    for _ in 0..2 {
        let error = run_tick(chain, store, &limits(10, 100)).await.unwrap_err();
        assert!(format!("{error:#}").contains(expect), "{error:#}");
        assert_eq!(store.published_mc_seqno().unwrap(), 1);
        assert_eq!(store.explorer_stats().unwrap(), before, "nothing of height 2 is public");
    }
}

#[tokio::test]
async fn a_missing_parent_fails_closed() {
    let (chain, store, _) = published_first_height().await;
    let orphan = chain.add_block(0, ROOT, 4, 0);
    chain.add_master(2, 0, &[&orphan]);
    assert_height_two_fails_closed(&chain, &store, "no proof-derived predecessor").await;
}

#[tokio::test]
async fn the_same_coordinate_with_a_different_hash_fails_closed() {
    let (chain, store, blocks) = published_first_height().await;
    // Head 3's parent is reported at the published coordinate (0, ROOT, 2)
    // but with another fork's hash.
    let impostor = block_id(0, ROOT, 2, 9);
    let head = chain.add_block(0, ROOT, 3, 0);
    chain.set_parents(&head, &[&impostor]);
    chain.add_master(2, 0, &[&head]);
    assert_height_two_fails_closed(&chain, &store, "published frontier holds").await;
    assert_eq!(store.canonical_shard_frontier().unwrap()[0].root_hash, hex_of(&blocks[1]));
}

#[tokio::test]
async fn a_forged_parent_fails_closed() {
    let (chain, store, _) = published_first_height().await;
    // The header names a parent whose own pages report a different block.
    let head = chain.add_block(0, ROOT, 4, 0);
    let claimed = block_id(0, ROOT, 3, 0);
    chain.set_parents(&head, &[&claimed]);
    let actual = chain.add_block(0, ROOT, 3, 7);
    chain.set_parents(&claimed, &[&chain.with(|s| s.blocks[&(0, ROOT, 2)].0.clone())]);
    let _ = actual;
    chain.add_master(2, 0, &[&head]);
    assert_height_two_fails_closed(&chain, &store, "reports a different block").await;
}

#[tokio::test]
async fn a_parent_that_does_not_precede_its_child_fails_closed() {
    let (chain, store, _) = published_first_height().await;
    let head = chain.add_block(0, ROOT, 4, 0);
    let later = block_id(0, ROOT, 4, 3);
    chain.set_parents(&head, &[&later]);
    chain.add_master(2, 0, &[&head]);
    assert_height_two_fails_closed(&chain, &store, "names an invalid parent").await;
}

#[tokio::test]
async fn parents_with_an_impossible_shard_shape_fail_closed() {
    let (chain, store, blocks) = published_first_height().await;
    // A root-shard block cannot descend from one half of a split alone.
    let half = chain.add_block(0, LEFT, 3, 0);
    chain.set_parents(&half, &[&blocks[1]]);
    let head = chain.add_block(0, ROOT, 4, 0);
    chain.set_parents(&head, &[&half]);
    chain.add_master(2, 0, &[&head]);
    assert_height_two_fails_closed(&chain, &store, "not a continuation, split or merge").await;
}

/// The same small history run cleanly, for the crash tests to compare with.
fn crash_scenario(chain: &FakeChain) -> Vec<BlockIdExt> {
    let a = chain.shard_chain(LEFT, 1, 6, 0);
    let b = chain.shard_chain(RIGHT, 1, 4, 0);
    chain.add_tx(&a[3], &"aa".repeat(32), "tx-left-4");
    chain.add_tx(&b[2], &"bb".repeat(32), "tx-right-3");
    chain.add_tx(&b[2], &"bb".repeat(32), "tx-right-3b");
    let m1 = chain.add_master(1, 0, &[&a[1], &b[0]]);
    chain.add_tx(&m1, &"cc".repeat(32), "tx-master-1");
    chain.add_master(2, 0, &[&a[5], &b[3]]);
    chain.add_master(3, 0, &[&a[5], &b[3]]);
    a.into_iter().chain(b).collect()
}

async fn clean_snapshot() -> String {
    let chain = FakeChain::new();
    crash_scenario(&chain);
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(10, 1_000), 3, 2).await;
    snapshot(&store)
}

/// Runs the scenario, injects one failure, "crashes" (drops the store),
/// restarts from disk, and requires the same final state as a clean run.
async fn crash_and_resume(inject: impl FnOnce(&FakeChain), clear: impl FnOnce(&FakeChain)) {
    let expected = clean_snapshot().await;
    let chain = FakeChain::new();
    crash_scenario(&chain);
    inject(&chain);
    let (_dir, path) = temp_db();
    {
        let store = IndexerStore::open_for_tests(&path).unwrap();
        let mut crashed = false;
        for _ in 0..4 {
            if run_tick(&chain, &store, &limits(10, 1_000)).await.is_err() {
                crashed = true;
                break;
            }
        }
        assert!(crashed, "the injected failure never fired");
    }
    clear(&chain);
    let store = IndexerStore::open_for_tests(&path).unwrap();
    run_until(&chain, &store, &limits(10, 1_000), 3, 3).await;
    assert_eq!(snapshot(&store), expected);
    let (blocks, txs) = store.raw_explorer_row_counts().unwrap();
    let stats = store.explorer_stats().unwrap();
    assert_eq!((blocks, txs), (stats.blocks as i64, stats.transactions as i64), "hidden leftovers");
}

#[tokio::test]
async fn crash_after_the_hidden_master_row_is_idempotent() {
    crash_and_resume(
        |c| c.with(|s| s.fail_get_shards = true),
        |c| c.with(|s| s.fail_get_shards = false),
    )
    .await;
}

#[tokio::test]
async fn crash_after_half_the_parents_are_expanded_is_idempotent() {
    crash_and_resume(
        |c| {
            c.with(|s| s.fail_parents_of.insert((0, RIGHT, 2)));
        },
        |c| c.with(|s| s.fail_parents_of.clear()),
    )
    .await;
}

#[tokio::test]
async fn crash_after_all_shard_rows_but_before_publish_is_idempotent() {
    // Lookups: open height 1, recheck before publishing it -> fail there.
    crash_and_resume(
        |c| c.with(|s| s.fail_lookup_number = Some(2)),
        |c| c.with(|s| s.fail_lookup_number = None),
    )
    .await;
}

#[tokio::test]
async fn crash_after_the_publish_commit_is_idempotent() {
    // Lookups: open 1, publish 1, open 2 -> fail right after the commit.
    crash_and_resume(
        |c| c.with(|s| s.fail_lookup_number = Some(3)),
        |c| c.with(|s| s.fail_lookup_number = None),
    )
    .await;
}

/// A pending batch whose masterchain block switches fork while the process
/// is down must not leak a single hidden row into the new fork's publish.
#[tokio::test]
async fn a_pending_anchor_that_switches_fork_leaks_no_hidden_rows() {
    let chain = FakeChain::new();
    let base = chain.shard_chain(ROOT, 1, 1, 0);
    chain.add_master(1, 0, &[&base[0]]);
    let a2 = chain.add_block(0, ROOT, 2, 0xA);
    chain.set_parents(&a2, &[&base[0]]);
    let a3 = chain.add_block(0, ROOT, 3, 0xA);
    chain.set_parents(&a3, &[&a2]);
    chain.add_tx(&a3, &"aa".repeat(32), "tx-fork-a");
    let a4 = chain.add_block(0, ROOT, 4, 0xA);
    chain.set_parents(&a4, &[&a3]);
    let a_master = chain.add_master(2, 0xA, &[&a4]);
    chain.add_tx(&a_master, &"ab".repeat(32), "tx-fork-a-master");
    let (_dir, path) = temp_db();
    {
        let store = IndexerStore::open_for_tests(&path).unwrap();
        run_until(&chain, &store, &limits(1, 100), 1, 2).await;
        // Height 2 on fork A: master, four resolutions, then two of its three
        // shard blocks scanned before the work budget runs out.
        let outcome = run_tick(&chain, &store, &limits(1, 7)).await.unwrap();
        assert_eq!(outcome.published_mc_seqno, 1);
        assert!(store.raw_transaction_exists("tx-fork-a").unwrap(), "fork A rows are durable");
        assert!(store.explorer_transaction("tx-fork-a").unwrap().is_none(), "but hidden");
    }
    // While down, height 2 is replaced by fork B with a shorter shard history.
    let b2 = chain.add_block(0, ROOT, 2, 0xB);
    chain.set_parents(&b2, &[&base[0]]);
    chain.add_tx(&b2, &"bb".repeat(32), "tx-fork-b");
    chain.with(|s| {
        s.blocks.remove(&(0, ROOT, 3));
        s.blocks.remove(&(0, ROOT, 4));
    });
    chain.add_master(2, 0xB, &[&b2]);

    let store = IndexerStore::open_for_tests(&path).unwrap();
    run_until(&chain, &store, &limits(1, 100), 2, 2).await;
    assert_eq!(
        store.canonical_state().unwrap().unwrap().root_hash,
        hex_of(&block_id(-1, MC, 2, 0xB))
    );
    assert!(store.explorer_transaction("tx-fork-b").unwrap().is_some());
    for gone in ["tx-fork-a", "tx-fork-a-master"] {
        assert!(!store.raw_transaction_exists(gone).unwrap(), "{gone} survived the discard");
    }
    assert!(store.explorer_block_by_hash(&hex_of(&a3)).unwrap().is_none());
    assert!(store.explorer_block_root(0, ROOT, 3).unwrap().is_none());
    let (blocks, txs) = store.raw_explorer_row_counts().unwrap();
    let stats = store.explorer_stats().unwrap();
    assert_eq!((blocks, txs), (stats.blocks as i64, stats.transactions as i64));
}

#[tokio::test]
async fn a_published_anchor_that_switches_fork_resets_and_replays() {
    let chain = FakeChain::new();
    let a = chain.shard_chain(ROOT, 1, 3, 0xA);
    chain.add_tx(&a[2], &"aa".repeat(32), "tx-a-3");
    for mc in 1..=3u32 {
        chain.add_master(mc, 0xA, &[&a[(mc - 1) as usize]]);
    }
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(10, 100), 3, 2).await;
    assert!(store.explorer_transaction("tx-a-3").unwrap().is_some());

    // Heights 2 and 3 are reorganized onto fork B.
    let b2 = chain.add_block(0, ROOT, 2, 0xB);
    chain.set_parents(&b2, &[&a[0]]);
    let b3 = chain.add_block(0, ROOT, 3, 0xB);
    chain.set_parents(&b3, &[&b2]);
    chain.add_tx(&b3, &"bb".repeat(32), "tx-b-3");
    chain.add_master(2, 0xB, &[&b2]);
    chain.add_master(3, 0xB, &[&b3]);

    // Detection resets everything; a one-height tick shows the replay has
    // restarted from genesis rather than patched the old state.
    let outcome = run_tick(&chain, &store, &limits(1, 100)).await.unwrap();
    assert_eq!(outcome.published_mc_seqno, 1);
    assert!(store.explorer_transaction("tx-a-3").unwrap().is_none());
    run_until(&chain, &store, &limits(10, 100), 3, 2).await;
    assert_eq!(
        store.canonical_state().unwrap().unwrap().root_hash,
        hex_of(&block_id(-1, MC, 3, 0xB))
    );
    assert!(!store.raw_transaction_exists("tx-a-3").unwrap());
    assert!(store.explorer_transaction("tx-b-3").unwrap().is_some());
    assert_eq!(store.canonical_shard_frontier().unwrap()[0].root_hash, hex_of(&b3));
}

#[tokio::test]
async fn public_reads_are_blind_to_a_pending_batch_until_it_publishes() {
    let chain = FakeChain::new();
    let blocks = chain.shard_chain(ROOT, 1, 8, 0);
    chain.add_master(1, 0, &[&blocks[0]]);
    chain.add_tx(&blocks[4], &"dd".repeat(32), "tx-pending-5");
    chain.add_master(2, 0, &[&blocks[7]]);
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(1, 100), 1, 2).await;
    let published = (store.explorer_stats().unwrap(), store.list_explorer_blocks(0, 50).unwrap().1);

    // Enough work to scan most of height 2's ancestry, not to finish it:
    // master, seven resolutions, the frontier, then blocks 2..=6.
    let outcome = run_tick(&chain, &store, &limits(1, 14)).await.unwrap();
    assert_eq!(outcome.published_mc_seqno, 1);
    assert!(store.raw_transaction_exists("tx-pending-5").unwrap(), "rows exist, hidden");
    assert_eq!(
        (store.explorer_stats().unwrap(), store.list_explorer_blocks(0, 50).unwrap().1),
        published
    );
    assert!(store.explorer_transaction("tx-pending-5").unwrap().is_none());
    assert!(store.explorer_block_by_hash(&hex_of(&blocks[4])).unwrap().is_none());
    assert!(store.masterchain_block(2).unwrap().is_none());
    assert_eq!(store.list_explorer_transactions(None, 0, 50).unwrap().1, 0);
    let account = MsgAddressInt::from_str(&format!("0:{}", "dd".repeat(32))).unwrap().to_string();
    assert_eq!(store.list_explorer_transactions(Some(&account), 0, 50).unwrap().1, 0);
    assert_eq!(store.list_explorer_block_transactions(0, ROOT, 5, 0, 50).unwrap().1, 0);

    run_until(&chain, &store, &limits(1, 100), 2, 2).await;
    assert!(store.explorer_transaction("tx-pending-5").unwrap().is_some());
    assert_eq!(store.list_explorer_transactions(Some(&account), 0, 50).unwrap().1, 1);
    assert_eq!(store.list_explorer_block_transactions(0, ROOT, 5, 0, 50).unwrap().1, 1);
    assert!(store.masterchain_block(2).unwrap().is_some());
    assert_eq!(store.explorer_stats().unwrap().blocks, 10);
}

/// Shard ancestry plus a small retention window and a far remote tip: the
/// frontier, not retained history, is the traversal boundary, so pruning
/// right behind the published watermark never forces a re-walk.
#[tokio::test]
async fn pruning_right_behind_the_watermark_never_costs_traversal_progress() {
    let chain = FakeChain::new();
    let tip = 450u32;
    let blocks = chain.shard_chain(ROOT, 1, tip, 0);
    for mc in 1..=tip {
        chain.add_master(mc, 0, &[&blocks[(mc - 1) as usize]]);
    }
    let store = IndexerStore::open_in_memory().unwrap();
    let known = KnownCodeHashes::compute().unwrap();
    let mut prune = PruneState::new(1);
    let mut previous = 0;
    for _ in 0..5 {
        let outcome = tick(
            &chain.dyn_chain(),
            &store,
            &known,
            &ProbeBudget::new(),
            &limits(200, MAX_SHARD_WORK_PER_TICK),
            10,
            &mut prune,
        )
        .await
        .unwrap();
        assert!(outcome.published_mc_seqno > previous || outcome.published_mc_seqno == tip);
        previous = outcome.published_mc_seqno;
        let window = store.list_explorer_blocks(0, 200).unwrap().1;
        assert!(window <= 2 * 11, "retention did not prune ({window} rows)");
        assert!(store.masterchain_block(previous).unwrap().is_some());
        if previous == tip {
            break;
        }
    }
    assert_eq!(previous, tip);
    for block in &blocks {
        assert_eq!(chain.scans_of(block), 1, "block {} re-walked after pruning", block.seqno);
    }
}
