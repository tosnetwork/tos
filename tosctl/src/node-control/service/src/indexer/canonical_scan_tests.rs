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
use contracts::NominatorPoolSnapshot;
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
    /// Pinned reads below this masterchain seqno fail, like a node that has
    /// pruned older state.
    pub(super) oldest_servable_seqno: u32,
    /// The snapshot source answers for a block other than the one asked for.
    pub(super) snapshot_for_another_block: bool,
    /// Pool get-method stacks the endpoint served. A dishonest endpoint
    /// answers with fabricated balances under the right block identity.
    pub(super) endpoint_pool_reads: usize,
    pub(super) fail_get_shards: bool,
    pub(super) fail_parents_of: HashSet<Key>,
    /// Fail the n-th (1-based) masterchain identity lookup.
    pub(super) fail_lookup_number: Option<usize>,
    pub(super) lookups: usize,
    /// Runs on every masterchain identity lookup, after counting it: lets a
    /// test reorganize the chain at an exact point inside one tick.
    #[allow(clippy::type_complexity)]
    pub(super) on_lookup: Option<Box<dyn FnMut(&mut ChainState, usize) + Send>>,
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
        self.add_master_with_id(block_id(-1, MC, seqno, fork), heads)
    }

    /// A masterchain block with an exact identity, such as one a proof
    /// verifier can authenticate.
    pub(super) fn add_master_with_id(&self, id: BlockIdExt, heads: &[&BlockIdExt]) -> BlockIdExt {
        let seqno = id.seqno;
        self.with(|s| s.blocks.insert(key(&id), (id.clone(), Vec::new())));
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

/// What the dishonest endpoint reports instead of the pool's real state.
fn fabricated(fixture: &PoolFixture) -> PoolFixture {
    PoolFixture {
        state: fixture.state,
        nominators: fixture
            .nominators
            .iter()
            .map(|(key, amount, pending)| (*key, amount.saturating_mul(1000), *pending))
            .collect(),
    }
}

fn snapshot_of(fixture: &PoolFixture, checkpoint: MasterchainCheckpoint) -> NominatorPoolSnapshot {
    NominatorPoolSnapshot {
        checkpoint,
        pool: contracts::NominatorPoolData {
            state: fixture.state,
            nominators_count: u32::try_from(fixture.nominators.len()).unwrap(),
            stake_amount_sent: 0,
            validator_amount: 2000,
            validator_address: [0xab; 32],
            controller_address: [0xcd; 32],
            validator_reward_share: 4000,
            max_nominators_count: 40,
            min_validator_stake: 1000,
            min_nominator_stake: 100,
            stake_at: 999,
            saved_validator_set_hash: [0x11; 32],
            validator_set_changes_count: 0,
            validator_set_change_time: 1234,
            stake_held_for: 3600,
        },
        nominators: fixture
            .nominators
            .iter()
            .map(|(key, amount, pending)| contracts::NominatorPosition {
                address: format!("0:{}", hex::encode(key)),
                amount: *amount,
                pending_deposit: *pending,
                withdraw_requested: false,
            })
            .collect(),
        proof: contracts::NominatorPoolSnapshotProof {
            live: false,
            block_gen_utime: 0,
            account_state_hash: "00".repeat(32),
            account_balance: "0".to_owned(),
            request_sha256: "00".repeat(32),
        },
    }
}

/// Stands in for the proof verifier: it answers only for the exact block the
/// scripted chain holds at the checkpoint, from the pool's real state.
#[async_trait::async_trait]
impl PoolSnapshotSource for FakeChain {
    async fn nominator_pool_snapshot(
        &self,
        address: &MsgAddressInt,
        policy: &ReadPolicy,
    ) -> anyhow::Result<NominatorPoolSnapshot> {
        let ReadPolicy::Historical(checkpoint) = policy else {
            anyhow::bail!("the indexer reads pools at an explicit historical block");
        };
        let mut s = self.state.lock().unwrap();
        anyhow::ensure!(
            s.historical_get_methods && checkpoint.seqno >= s.oldest_servable_seqno,
            "historical state is unavailable"
        );
        let master = s
            .blocks
            .get(&(-1, MC, checkpoint.seqno))
            .map(|(id, _)| id.clone())
            .ok_or_else(|| anyhow::anyhow!("no masterchain block {}", checkpoint.seqno))?;
        anyhow::ensure!(
            hex::encode(&master.root_hash) == checkpoint.root_hash
                && hex::encode(&master.file_hash) == checkpoint.file_hash,
            "the checkpoint is not the authenticated block at its height"
        );
        for method in contracts::NOMINATOR_POOL_SNAPSHOT_METHODS {
            s.pinned_reads.push((method.to_owned(), checkpoint.seqno));
        }
        let address = address.to_string();
        let fixture = s
            .pools
            .get(&address)
            .and_then(|history| history.range(..=checkpoint.seqno).next_back())
            .map(|(_, fixture)| fixture.clone())
            .ok_or_else(|| anyhow::anyhow!("account {address} is not active at the checkpoint"))?;
        let mut answered = checkpoint.clone();
        if s.snapshot_for_another_block {
            answered.root_hash = "ab".repeat(32);
        }
        Ok(snapshot_of(&fixture, answered))
    }
}

#[async_trait::async_trait]
impl ChainProvider for FakeChain {
    async fn run_get_method(
        &self,
        address: String,
        method: &str,
        _stack: Vec<StackEntry>,
    ) -> anyhow::Result<common::tvm_stack_parser::TvmStackParser> {
        let tip = self.with(|s| s.tip);
        let checkpoint = MasterchainCheckpoint {
            seqno: tip,
            root_hash: String::new(),
            file_hash: String::new(),
        };
        self.run_get_method_at_unverified(address, method, Vec::new(), &checkpoint).await
    }

    /// A dishonest endpoint: it reports the exact requested block and a
    /// stack that pays every depositor a thousand times what the pool holds.
    async fn run_get_method_at_unverified(
        &self,
        address: String,
        method: &str,
        _stack: Vec<StackEntry>,
        checkpoint: &MasterchainCheckpoint,
    ) -> anyhow::Result<common::tvm_stack_parser::TvmStackParser> {
        let mut s = self.state.lock().unwrap();
        let fixture = s
            .pools
            .get(&address)
            .and_then(|history| history.range(..=checkpoint.seqno).next_back())
            .map(|(_, fixture)| fixture.clone())
            .ok_or_else(|| anyhow::anyhow!("account {address} is not active at the checkpoint"))?;
        s.endpoint_pool_reads += 1;
        let fabricated = fabricated(&fixture);
        match method {
            "get_pool_data" => Ok(pool_data_stack(&fabricated)),
            "list_nominators" => Ok(nominators_stack(&fabricated)),
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
            if let Some(mut hook) = s.on_lookup.take() {
                let lookups = s.lookups;
                hook(&mut s, lookups);
                s.on_lookup = Some(hook);
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
    ScanLimits { max_batches, max_shard_work, refresh: RefreshBudget::production() }
}

pub(super) async fn run_tick(
    chain: &Arc<FakeChain>,
    store: &IndexerStore,
    limits: &ScanLimits,
) -> anyhow::Result<ScanOutcome> {
    run_tick_with(chain, chain.as_ref(), store, limits).await
}

/// One tick whose pool snapshots come from `pool_snapshots`.
pub(super) async fn run_tick_with(
    chain: &Arc<FakeChain>,
    pool_snapshots: &dyn PoolSnapshotSource,
    store: &IndexerStore,
    limits: &ScanLimits,
) -> anyhow::Result<ScanOutcome> {
    scan_new_blocks(
        &chain.dyn_chain(),
        pool_snapshots,
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

/// The masterchain block of the pending height is reorganized after its
/// batch was fully assembled but before it is published, inside one tick.
#[tokio::test]
async fn an_anchor_that_changes_just_before_publish_is_discarded_not_published() {
    let chain = FakeChain::new();
    let base = chain.shard_chain(ROOT, 1, 1, 0);
    chain.add_master(1, 0, &[&base[0]]);
    let a2 = chain.add_block(0, ROOT, 2, 0xA);
    chain.set_parents(&a2, &[&base[0]]);
    chain.add_tx(&a2, &"aa".repeat(32), "tx-pre-a");
    chain.add_master(2, 0xA, &[&a2]);
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(1, 100), 1, 2).await;
    let b2 = block_id(0, ROOT, 2, 0xB);
    let base_id = base[0].clone();
    // Lookups of the next tick: published recheck, open height 2, then the
    // pre-publish recheck -- where fork B replaces fork A.
    let switch_at = chain.with(|s| s.lookups) + 3;
    chain.with(|s| {
        s.on_lookup = Some(Box::new(move |state: &mut ChainState, lookups: usize| {
            if lookups != switch_at {
                return;
            }
            let master = block_id(-1, MC, 2, 0xB);
            state.blocks.insert((-1, MC, 2), (master, Vec::new()));
            state.shards.insert(2, vec![b2.clone()]);
            state.blocks.insert(
                (0, ROOT, 2),
                (
                    b2.clone(),
                    vec![ShortTxId {
                        r#type: None,
                        account: "bb".repeat(32),
                        lt: 1_000,
                        hash: "tx-pre-b".to_owned(),
                    }],
                ),
            );
            state.parents.insert((0, ROOT, 2), vec![base_id.clone()]);
        }))
    });
    let outcome = run_tick(&chain, &store, &limits(10, 100)).await.unwrap();
    assert_eq!(outcome.published_mc_seqno, 2);
    assert_eq!(
        store.canonical_state().unwrap().unwrap().root_hash,
        hex_of(&block_id(-1, MC, 2, 0xB))
    );
    assert!(store.explorer_transaction("tx-pre-b").unwrap().is_some());
    assert!(!store.raw_transaction_exists("tx-pre-a").unwrap(), "fork A was published or leaked");
    assert_eq!(chain.scans_of(&block_id(-1, MC, 2, 0)), 2, "height 2 was assembled twice");
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
            chain.as_ref(),
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

// ─── Nominator ledger ─────────────────────────────────────────────────────

const POOL_HEX: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const ALICE_KEY: [u8; 32] = [0xA1; 32];
const BOB_KEY: [u8; 32] = [0xB0; 32];
const IDLE: i32 = 0;
const STAKED: i32 = 2;

fn pool_address() -> String {
    format!("-1:{POOL_HEX}")
}

fn nominator(key: [u8; 32]) -> String {
    format!("0:{}", hex::encode(key))
}

/// Masterchain block `seqno` on `fork` in which the pool has `touches`
/// transactions and, from then on, the given state.
fn pool_height(
    chain: &FakeChain,
    seqno: u32,
    fork: u8,
    touches: usize,
    fixture: Option<PoolFixture>,
) -> BlockIdExt {
    let master = chain.add_master(seqno, fork, &[]);
    for touch in 0..touches {
        chain.add_tx(&master, POOL_HEX, &format!("tx-pool-{seqno}-{fork}-{touch}"));
    }
    if let Some(fixture) = fixture {
        chain.with(|s| s.pools.entry(pool_address()).or_default().insert(seqno, fixture));
    }
    master
}

fn fixture(state: i32, nominators: &[([u8; 32], u64, u64)]) -> Option<PoolFixture> {
    Some(PoolFixture { state, nominators: nominators.to_vec() })
}

/// The API's answer, as the JSON body a client would receive, with the
/// HTTP status.
fn api(store: &IndexerStore, who: [u8; 32]) -> (u16, serde_json::Value) {
    match crate::http::explorer_query_api::nominator_positions_response(store, nominator(who)) {
        Ok(response) => (200, serde_json::to_value(response).unwrap()),
        Err(error) => (
            error.status().as_u16(),
            serde_json::json!({"ok": false, "error": {"kind": error.kind(), "message": error.message()}}),
        ),
    }
}

fn record_response(name: &str, response: &(u16, serde_json::Value)) {
    if let Ok(dir) = std::env::var("INDEXER_TRACE_DIR") {
        let body = serde_json::to_string_pretty(&serde_json::json!({
            "http_status": response.0,
            "body": response.1,
        }))
        .unwrap();
        std::fs::write(format!("{dir}/{name}.json"), body + "\n").unwrap();
    }
}

#[tokio::test]
async fn a_ledger_fork_switch_is_unavailable_then_carries_only_the_new_fork() {
    let chain = FakeChain::new();
    pool_height(&chain, 1, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0)]));
    pool_height(&chain, 2, 0, 1, fixture(STAKED, &[(ALICE_KEY, 1_000, 0)]));
    // Fork A: the round pays Alice 100.
    pool_height(&chain, 3, 0xA, 1, fixture(IDLE, &[(ALICE_KEY, 1_100, 0)]));
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(10, 100), 3, 2).await;
    let on_a = api(&store, ALICE_KEY);
    record_response("ledger-fork-a-valid", &on_a);
    assert_eq!(on_a.0, 200, "{}", on_a.1);
    assert_eq!(on_a.1["rewarded_total"], "100");
    assert_eq!(on_a.1["attribution_complete"], true);
    assert_eq!(on_a.1["caught_up"], true);
    assert_eq!(on_a.1["as_of_mc_seqno"], 3);
    assert_eq!(on_a.1["as_of_mc_root_hash"], hex_of(&block_id(-1, MC, 3, 0xA)));

    // Height 3 is reorganized onto fork B, where the round paid nothing.
    pool_height(&chain, 3, 0xB, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0)]));
    pool_height(&chain, 4, 0xB, 0, None);
    let outcome = run_tick(&chain, &store, &limits(1, 100)).await.unwrap();
    assert_eq!(outcome.published_mc_seqno, 1, "the replay restarts from genesis");
    let during = api(&store, ALICE_KEY);
    record_response("ledger-fork-switch-unavailable", &during);
    assert_eq!(during.0, 503);
    assert_eq!(during.1["error"]["kind"], "nominator_ledger_rebuilding");

    run_until(&chain, &store, &limits(10, 100), 4, 2).await;
    let on_b = api(&store, ALICE_KEY);
    record_response("ledger-fork-b-valid", &on_b);
    assert_eq!(on_b.0, 200, "{}", on_b.1);
    assert_eq!(on_b.1["rewarded_total"], "0", "fork A's reward must not survive");
    assert_eq!(on_b.1["result"][0]["deposited_total"], "1000");
    assert_eq!(on_b.1["result"][0]["amount"], "1000");
    assert_eq!(on_b.1["result"][0]["last_mc_root_hash"], hex_of(&block_id(-1, MC, 3, 0xB)));
    assert_eq!(on_b.1["as_of_mc_seqno"], 4);
    assert_eq!(on_b.1["as_of_mc_root_hash"], hex_of(&block_id(-1, MC, 4, 0xB)));
    // Every pool read was pinned to the height that made its touch canonical.
    let reads = chain.with(|s| s.pinned_reads.clone());
    assert!(reads.iter().all(|(_, seqno)| (1..=3).contains(seqno)), "{reads:?}");
}

#[tokio::test]
async fn a_migrated_v10_ledger_is_not_complete_before_the_replay_finishes() {
    let chain = FakeChain::new();
    pool_height(&chain, 1, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0)]));
    pool_height(&chain, 2, 0, 0, None);
    pool_height(&chain, 3, 0, 0, None);
    let (_dir, path) = temp_db();
    crate::indexer::store::write_v10_database_for_tests(&path).unwrap();
    let store = IndexerStore::open_for_tests(&path).unwrap();
    let Err(before) =
        crate::http::explorer_query_api::nominator_positions_response(&store, "0:1111".to_owned())
    else {
        panic!("a migrated v10 ledger was served before any replay");
    };
    assert_eq!(before.kind(), "nominator_ledger_rebuild_required");
    run_tick(&chain, &store, &limits(1, 100)).await.unwrap();
    assert_eq!(api(&store, ALICE_KEY).1["error"]["kind"], "nominator_ledger_rebuilding");
    run_until(&chain, &store, &limits(10, 100), 3, 2).await;
    let after = api(&store, ALICE_KEY);
    assert_eq!(after.0, 200, "{}", after.1);
    assert_eq!(after.1["attribution_complete"], true);
    assert_eq!(after.1["result"][0]["deposited_total"], "1000");
    let old =
        crate::http::explorer_query_api::nominator_positions_response(&store, "0:1111".to_owned())
            .unwrap();
    assert!(old.result.is_empty(), "the unprovable v10 row is gone");
}

#[tokio::test]
async fn a_full_withdrawal_zeroes_the_position_and_a_redeposit_starts_from_zero() {
    let chain = FakeChain::new();
    pool_height(&chain, 1, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0), (BOB_KEY, 50, 0)]));
    pool_height(&chain, 2, 0, 1, fixture(IDLE, &[(BOB_KEY, 50, 0)]));
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(10, 100), 2, 2).await;
    let gone = api(&store, ALICE_KEY);
    assert_eq!(gone.0, 200, "{}", gone.1);
    assert_eq!(gone.1["result"][0]["amount"], "0", "a withdrawn position is not still held");
    assert_eq!(gone.1["result"][0]["deposited_total"], "1000");
    pool_height(&chain, 3, 0, 1, fixture(IDLE, &[(ALICE_KEY, 300, 0), (BOB_KEY, 50, 0)]));
    run_until(&chain, &store, &limits(10, 100), 3, 2).await;
    let back = api(&store, ALICE_KEY);
    assert_eq!(back.1["result"][0]["amount"], "300");
    assert_eq!(back.1["result"][0]["deposited_total"], "1300");
    assert_eq!(back.1["result"][0]["unattributed_total"], "0");
    assert_eq!(back.1["attribution_complete"], true);
}

#[tokio::test]
async fn several_touches_in_one_interval_make_attribution_incomplete() {
    let chain = FakeChain::new();
    pool_height(&chain, 1, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0)]));
    // A deposit and a second transaction land in one masterchain height.
    pool_height(&chain, 2, 0, 2, fixture(IDLE, &[(ALICE_KEY, 1_500, 0)]));
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(10, 100), 2, 2).await;
    let response = api(&store, ALICE_KEY);
    record_response("ledger-coverage-gap", &response);
    assert_eq!(response.0, 200);
    assert_eq!(response.1["result"][0]["coverage_gap_count"], 1);
    assert_eq!(response.1["result"][0]["unattributed_total"], "0");
    assert_eq!(response.1["result"][0]["attribution_complete"], false);
    assert_eq!(response.1["attribution_complete"], false);
}

#[tokio::test]
async fn unexplained_change_makes_attribution_incomplete() {
    let chain = FakeChain::new();
    pool_height(&chain, 1, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0)]));
    // Principal shrinks while idle with the dictionary entry still present:
    // no pool.fc rule explains it.
    pool_height(&chain, 2, 0, 1, fixture(IDLE, &[(ALICE_KEY, 800, 0)]));
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(10, 100), 2, 2).await;
    let response = api(&store, ALICE_KEY);
    assert_eq!(response.0, 200);
    assert_eq!(response.1["result"][0]["unattributed_total"], "200");
    assert_eq!(response.1["result"][0]["coverage_gap_count"], 0);
    assert_eq!(response.1["attribution_complete"], false);
}

async fn assert_ledger_stays_unavailable(chain: &Arc<FakeChain>) {
    pool_height(chain, 1, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0)]));
    pool_height(chain, 2, 0, 0, None);
    let store = IndexerStore::open_in_memory().unwrap();
    for _ in 0..3 {
        run_tick(chain, &store, &limits(10, 100)).await.unwrap();
    }
    assert_eq!(store.published_mc_seqno().unwrap(), 2, "the explorer is not held back");
    let response = api(&store, ALICE_KEY);
    record_response("ledger-historical-unavailable", &response);
    assert_eq!(response.0, 503);
    assert_eq!(response.1["error"]["kind"], "nominator_ledger_rebuilding");
    assert!(store.nominator_ledger_entries(&nominator(ALICE_KEY)).unwrap().is_empty());
    assert_eq!(store.address_refresh_queue(10).unwrap().len(), 1, "the observation is retried");
}

#[tokio::test]
async fn without_historical_state_the_ledger_stays_unavailable() {
    let chain = FakeChain::new();
    chain.with(|s| s.historical_get_methods = false);
    assert_ledger_stays_unavailable(&chain).await;
    assert!(chain.with(|s| s.pinned_reads.is_empty()));
}

#[tokio::test]
async fn a_snapshot_answering_for_another_block_is_never_folded_in() {
    let chain = FakeChain::new();
    chain.with(|s| s.snapshot_for_another_block = true);
    assert_ledger_stays_unavailable(&chain).await;
    assert!(chain.with(|s| !s.pinned_reads.is_empty()), "the snapshot was taken and refused");
}

#[tokio::test]
async fn an_unreadable_historical_height_keeps_the_ledger_unavailable() {
    let chain = FakeChain::new();
    // The node no longer serves height 1's state, only height 2 onwards.
    chain.with(|s| s.oldest_servable_seqno = 2);
    pool_height(&chain, 1, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0)]));
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(10, 100), 1, 2).await;
    assert_eq!(api(&store, ALICE_KEY).0, 503);
    // A later touch at a readable height does not stand in for height 1: the
    // pool is never observed at height 2 while height 1 is still owed.
    pool_height(&chain, 2, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_200, 0)]));
    run_until(&chain, &store, &limits(10, 100), 2, 2).await;
    for _ in 0..3 {
        run_tick(&chain, &store, &limits(10, 100)).await.unwrap();
    }
    let response = api(&store, ALICE_KEY);
    assert_eq!(response.0, 503, "{}", response.1);
    // Still replaying from genesis: the replay cannot finish past the owed height.
    let kind = response.1["error"]["kind"].as_str().unwrap_or_default().to_owned();
    assert!(
        kind == "nominator_ledger_rebuilding" || kind == "nominator_ledger_behind_index",
        "{kind}"
    );
    let reads = chain.with(|s| s.pinned_reads.clone());
    assert!(reads.iter().all(|(_, seqno)| *seqno == 1), "no observation skipped ahead: {reads:?}");
}

#[tokio::test]
async fn a_transient_read_failure_delays_but_skips_no_height() {
    let chain = FakeChain::new();
    chain.with(|s| s.oldest_servable_seqno = 2);
    pool_height(&chain, 1, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0)]));
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(10, 100), 1, 2).await;
    pool_height(&chain, 2, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_200, 0)]));
    run_until(&chain, &store, &limits(10, 100), 2, 2).await;
    assert_eq!(api(&store, ALICE_KEY).0, 503);
    // Height 1 becomes readable again: it is observed first, then height 2,
    // and the served amount is height 2's, not a stale height 1 value.
    chain.with(|s| s.oldest_servable_seqno = 0);
    for _ in 0..3 {
        run_tick(&chain, &store, &limits(10, 100)).await.unwrap();
    }
    let response = api(&store, ALICE_KEY);
    assert_eq!(response.0, 200, "{}", response.1);
    assert_eq!(response.1["result"][0]["amount"], "1200", "height 2's amount, not height 1's");
    assert_eq!(response.1["result"][0]["coverage_gap_count"], 0);
    let reads: Vec<u32> = chain.with(|s| {
        s.pinned_reads
            .iter()
            .filter(|(method, _)| method == "list_nominators")
            .map(|(_, seqno)| *seqno)
            .collect()
    });
    let first_two = reads.iter().position(|seqno| *seqno == 2).expect("height 2 observed");
    assert!(reads[..first_two].contains(&1), "height 1 observed before height 2: {reads:?}");
    assert!(!reads[first_two..].contains(&1), "no height observed out of order: {reads:?}");
}

#[tokio::test]
async fn a_pool_backlog_drains_while_the_pool_is_touched_every_block() {
    let chain = FakeChain::new();
    // Thirty heights are owed while the node cannot serve the first one.
    chain.with(|s| s.oldest_servable_seqno = 2);
    for seqno in 1..=30 {
        pool_height(&chain, seqno, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0)]));
    }
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(10, 100), 30, 5).await;
    let owed = |store: &IndexerStore| store.queued_heights_for_test(&pool_address()).unwrap().len();
    assert_eq!(owed(&store), 30);
    // The state is servable again, and every new block touches the pool.
    chain.with(|s| s.oldest_servable_seqno = 0);
    let mut backlog = Vec::new();
    for seqno in 31..=34 {
        pool_height(&chain, seqno, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0)]));
        run_tick(&chain, &store, &limits(1, 100)).await.unwrap();
        backlog.push(owed(&store));
    }
    assert_eq!(store.published_mc_seqno().unwrap(), 34);
    assert_eq!(backlog, vec![0, 0, 0, 0], "the backlog is gone within one block");
    let response = api(&store, ALICE_KEY);
    assert_eq!(response.0, 200, "{}", response.1);
    assert_eq!(response.1["result"][0]["coverage_gap_count"], 0);
    // Every height observed exactly once, in order: no read succeeded during
    // the outage, and none was skipped after it.
    let reads: Vec<u32> = chain.with(|s| {
        s.pinned_reads
            .iter()
            .filter(|(method, _)| method == "list_nominators")
            .map(|(_, seqno)| *seqno)
            .collect()
    });
    assert_eq!(reads, (1..=34).collect::<Vec<u32>>());
}

// ─── Pool snapshots never come from the endpoint ──────────────────────────

#[tokio::test]
async fn an_endpoint_stack_never_reaches_the_ledger() {
    let chain = FakeChain::new();
    pool_height(&chain, 1, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_000, 0)]));
    pool_height(&chain, 2, 0, 1, fixture(IDLE, &[(ALICE_KEY, 1_200, 0)]));
    let store = IndexerStore::open_in_memory().unwrap();
    run_until(&chain, &store, &limits(10, 100), 2, 2).await;
    let response = api(&store, ALICE_KEY);
    assert_eq!(response.0, 200, "{}", response.1);
    assert_eq!(response.1["result"][0]["amount"], "1200");
    assert_eq!(chain.with(|s| s.endpoint_pool_reads), 0, "no endpoint stack was read");
    // The endpoint is reachable and dishonest: asked, it reports the exact
    // block and a fabricated position.
    let pinned = MasterchainCheckpoint {
        seqno: 2,
        root_hash: hex_of(&block_id(-1, MC, 2, 0)),
        file_hash: hex::encode(&block_id(-1, MC, 2, 0).file_hash),
    };
    let stack = chain
        .run_get_method_at_unverified(pool_address(), "list_nominators", Vec::new(), &pinned)
        .await
        .unwrap();
    let positions = stack.list_or_empty(0).unwrap();
    assert_eq!(positions.tuple(0).unwrap().u64(1).unwrap(), 1_200_000);
}

fn fake_verifier_fixtures() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../contracts/tests/fixtures/proven-reads")
        .canonicalize()
        .unwrap()
}

fn on_path(program: &str) -> std::path::PathBuf {
    let path = std::env::var_os("PATH").expect("PATH");
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{program} is needed on PATH"))
}

/// Decimal of a 256-bit big-endian integer, as the verifier renders it.
fn decimal_of(bytes: [u8; 32]) -> String {
    let mut digits = Vec::new();
    let mut value = bytes.to_vec();
    while value.iter().any(|byte| *byte != 0) {
        let mut remainder = 0u32;
        for byte in value.iter_mut() {
            let current = (remainder << 8) | u32::from(*byte);
            *byte = u8::try_from(current / 10).unwrap();
            remainder = current % 10;
        }
        digits.push(char::from(b'0' + u8::try_from(remainder).unwrap()));
    }
    if digits.is_empty() {
        return "0".to_owned();
    }
    digits.iter().rev().collect()
}

/// The production provider, running a stand-in verifier whose every answer
/// says Alice holds `amount` in the pool.
fn verifier_backed_provider(
    dir: &std::path::Path,
    mutation: &str,
    amount: u64,
) -> contracts::ProvenGetterProvider {
    let int = |value: &str| serde_json::json!({"type": "int", "value": value});
    let nil = serde_json::json!({"type": "null"});
    let behaviour = serde_json::json!({
        "mutation": mutation,
        "gen_utime": 1_000,
        "log": dir.join("requests.jsonl").display().to_string(),
        "stacks": {
            "get_pool_data": [
                int("0"), int("1"), int("0"), int("2000"), int("171"), int("205"), int("4000"),
                int("40"), int("1000"), int("100"), nil.clone(), nil.clone(), int("999"),
                int("17"), int("0"), int("1234"), int("3600"), nil.clone(),
            ],
            "list_nominators": [{"type": "tuple", "items": [
                {"type": "tuple", "items": [
                    int(&decimal_of(ALICE_KEY)), int(&amount.to_string()), int("0"), int("0"),
                ]},
                nil,
            ]}],
        },
    });
    let behaviour_path = dir.join("behaviour.json");
    std::fs::write(&behaviour_path, behaviour.to_string()).unwrap();
    // Installed by another process, so no write descriptor of this one can
    // leak into a concurrently forked child and make the file busy.
    let source = dir.join("verifier.source");
    std::fs::write(
        &source,
        format!(
            "#!/bin/sh\nexec '{}' '{}' '{}' \"$@\"\n",
            on_path("python3").display(),
            fake_verifier_fixtures().join("fake_verifier.py").display(),
            behaviour_path.display()
        ),
    )
    .unwrap();
    let executable = dir.join("verifier");
    assert!(
        std::process::Command::new(on_path("install"))
            .args(["-m", "755"])
            .arg(&source)
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let material = dir.join("material");
    std::fs::create_dir_all(&material).unwrap();
    contracts::ProvenGetterProvider::new(&common::app_config::ProofVerifierConfig {
        executable,
        anchor_file: fake_verifier_fixtures().join("anchor.json"),
        liteserver_config: None,
        material_dir: Some(material),
        live_state_file: None,
        live_max_age_seconds: None,
        timeout_seconds: 60,
        min_interval_ms: 0,
    })
    .unwrap()
}

#[tokio::test]
async fn the_indexer_takes_pool_snapshots_only_from_the_proof_verifier() {
    let chain = FakeChain::new();
    // The chain's real state says 5; the endpoint reports 5000; the proof
    // verifier computed 1000.
    pool_height(&chain, 1, 0, 1, fixture(IDLE, &[(ALICE_KEY, 5, 0)]));
    pool_height(&chain, 2, 0, 0, None);
    let dir = tempfile::tempdir().unwrap();
    let provider = verifier_backed_provider(dir.path(), "none", 1_000);
    let store = IndexerStore::open_in_memory().unwrap();
    for _ in 0..3 {
        run_tick_with(&chain, &provider, &store, &limits(10, 100)).await.unwrap();
    }
    let response = api(&store, ALICE_KEY);
    assert_eq!(response.0, 200, "{}", response.1);
    assert_eq!(response.1["result"][0]["amount"], "1000", "the proven value, nothing else");
    assert_eq!(chain.with(|s| s.endpoint_pool_reads), 0, "no endpoint stack was read");
    // The verifier was asked for the pool at the exact canonical block.
    let requests = std::fs::read_to_string(dir.path().join("requests.jsonl")).unwrap();
    let first: serde_json::Value = serde_json::from_str(requests.lines().next().unwrap()).unwrap();
    assert_eq!(first["request"]["mode"], "historical");
    assert_eq!(first["request"]["account"], pool_address());
    assert_eq!(first["request"]["target"]["seqno"], 1);
    assert_eq!(first["request"]["target"]["root_hash"], hex_of(&block_id(-1, MC, 1, 0)));
}

#[tokio::test]
async fn an_unbound_verifier_answer_leaves_the_pool_pending_without_fallback() {
    let chain = FakeChain::new();
    pool_height(&chain, 1, 0, 1, fixture(IDLE, &[(ALICE_KEY, 5, 0)]));
    pool_height(&chain, 2, 0, 0, None);
    let dir = tempfile::tempdir().unwrap();
    let provider = verifier_backed_provider(dir.path(), "request_hash", 1_000);
    let store = IndexerStore::open_in_memory().unwrap();
    for _ in 0..3 {
        run_tick_with(&chain, &provider, &store, &limits(10, 100)).await.unwrap();
    }
    assert_eq!(store.published_mc_seqno().unwrap(), 2, "the explorer is not held back");
    let response = api(&store, ALICE_KEY);
    assert_eq!(response.0, 503, "{}", response.1);
    assert!(store.nominator_ledger_entries(&nominator(ALICE_KEY)).unwrap().is_empty());
    assert_eq!(store.address_refresh_queue(10).unwrap().len(), 1, "the observation is retried");
    assert_eq!(chain.with(|s| s.endpoint_pool_reads), 0, "no fallback to the endpoint");
}

/// The real proof verifier, with the signed synthetic chain whose target block
/// holds a pool running the current pool code. The scripted chain carries
/// that exact block at height 3 and a dishonest endpoint that reports the
/// pool's positions a thousand times larger.
#[tokio::test]
#[ignore = "needs the proof verifier: set TOS_PROOF_VERIFY (the contract-sandboxes job runs it)"]
async fn the_indexer_folds_a_current_code_pool_snapshot_proven_by_the_real_verifier() {
    let verifier = std::path::PathBuf::from(
        std::env::var_os("TOS_PROOF_VERIFY").expect("TOS_PROOF_VERIFY names the proof verifier"),
    );
    let fixtures = fake_verifier_fixtures().join("synthetic-pool");
    let target: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixtures.join("target.json")).unwrap()).unwrap();
    let hash = |field: &str| hex::decode(target[field].as_str().unwrap()).unwrap();
    const PROVEN_POOL_HEX: &str =
        "7777777777777777777777777777777777777777777777777777777777777777";
    let pool = format!("-1:{PROVEN_POOL_HEX}");

    let chain = FakeChain::new();
    chain.add_master(1, 0, &[]);
    chain.add_master(2, 0, &[]);
    let master = chain.add_master_with_id(
        BlockIdExt {
            r#type: "tos.blockIdExt".to_owned(),
            workchain: -1,
            shard: MC,
            seqno: 3,
            root_hash: hash("root_hash"),
            file_hash: hash("file_hash"),
        },
        &[],
    );
    chain.add_tx(&master, PROVEN_POOL_HEX, "tx-proven-pool");
    // What the endpoint believes; it reports a thousand times these.
    chain.with(|s| {
        s.pools.entry(pool.clone()).or_default().insert(
            3,
            PoolFixture { state: 1, nominators: vec![(ALICE_KEY, 7, 0), (BOB_KEY, 9, 0)] },
        )
    });

    let dir = tempfile::tempdir().unwrap();
    let material = dir.path().join("material");
    std::fs::create_dir_all(&material).unwrap();
    for (from, to) in [
        ("chain-0000.tl", "chain-0000.tl"),
        ("exec-config.tl", "exec-config.tl"),
        ("pool-account.tl", "account.tl"),
    ] {
        std::fs::copy(fixtures.join(from), material.join(to)).unwrap();
    }
    let provider = contracts::ProvenGetterProvider::new(&common::app_config::ProofVerifierConfig {
        executable: verifier,
        anchor_file: fixtures.join("anchor.json"),
        liteserver_config: None,
        material_dir: Some(material),
        live_state_file: None,
        live_max_age_seconds: None,
        timeout_seconds: 60,
        min_interval_ms: 0,
    })
    .unwrap();
    let store = IndexerStore::open_in_memory().unwrap();
    for _ in 0..3 {
        run_tick_with(&chain, &provider, &store, &limits(10, 100)).await.unwrap();
    }
    assert_eq!(chain.with(|s| s.endpoint_pool_reads), 0, "no endpoint stack was read");
    let alice = api(&store, ALICE_KEY);
    record_response("ledger-proven-current-code-pool", &alice);
    assert_eq!(alice.0, 200, "{}", alice.1);
    assert_eq!(alice.1["result"][0]["amount"], "1000000000000", "{}", alice.1);
    assert_eq!(alice.1["as_of_mc_seqno"], 3);
    assert_eq!(alice.1["as_of_mc_root_hash"], target["root_hash"]);
    let bob = api(&store, BOB_KEY);
    assert_eq!(bob.1["result"][0]["amount"], "250000000000", "{}", bob.1);
    assert_eq!(bob.1["result"][0]["pending_deposit"], "5000000000", "{}", bob.1);
}
