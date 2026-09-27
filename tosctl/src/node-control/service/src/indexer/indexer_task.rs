/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Chain-wide contract indexer background task.
//!
//! There is no chain primitive to "list every Task Escrow"; the only
//! enumeration primitive is per-block ("which accounts had a transaction in
//! this block"). This task walks masterchain blocks sequentially and follows
//! each referenced shard head's proof-derived predecessor IDs back to the
//! exact shard heads of the previously published masterchain block --
//! including split and merge branches. Each masterchain height is assembled
//! as a durable batch and published atomically; nothing it writes is public
//! before that. It covers the
//! masterchain itself (some actors deploy there directly)
//! plus every other workchain's current shard(s), since that is where
//! almost every contract actually lives -- and for every account it hasn't
//! seen before, checks its code hash against the recognized contract codes
//! (Agent Account, Task Escrow, Dispute, Service Actor and Capability Registry).
//! A match is
//! decoded via that contract's own `decode_data` -- no new decode logic --
//! and stored in [`IndexerStore`]. Every block/transaction identity is also
//! recorded for explorer search and pagination. An address already known to be one of
//! these kinds is *always* re-decoded when it reappears in a later block,
//! since that is exactly how a status change (accept/settle/rule/...)
//! becomes visible.
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use chain_block::{
    Cell, Deserializable, MsgAddressInt, SliceData, UInt256, read_single_root_boc, write_boc,
};
use chain_rpc_client::v2::data_models::BlockIdExt;
use common::{app_config::AppConfig, task_cancellation::CancellationCtx, time_format};
use contracts::contract_codes::NOMINATOR_POOL_CODE;
use contracts::{
    AgentAccountContract, CapabilityRegistryContract, ChainProvider, DisputeContract,
    MasterchainCheckpoint, ServiceActorContract, TaskEscrowContract,
    read_nominator_pool_snapshot_at,
};

const DNS_ITEM_CODE_HASH: &str = "e469483aa8a8e5018f46cdd9c374b60153025847a6d4997692cfdd9b15be1d78";
const DNS_COLLECTION_ADDRESS: &str =
    "0:cec242160fa821bc402586947649f25d4a0c1b02808d1dce93c893e98061bb8a";
const DNS_ITEM_CODE_DEPTH: u16 = 11;

use crate::indexer::store::{
    AddressRefresh, AddressTouch, BatchPhase, BlockFullId, DnsDomainHistoryRecord,
    ExplorerBlockRecord, ExplorerTransactionRecord, IndexedRecord, IndexerStore, LedgerStatus,
    ScannedTarget, ServiceRequestRecord, ShardStep,
};
use crate::runtime_config::RuntimeConfig;

/// Upper bound on how many masterchain blocks a single tick will publish, so
/// a long-idle indexer catching up on history doesn't stall the tick loop
/// indefinitely -- the next tick picks up where this one left off.
const MAX_BLOCKS_PER_TICK: u32 = 200;
/// Shard-ancestry work units (a parent lookup or an exact block scan) one
/// tick may spend. Reaching it is a normal yield: the pending batch resumes
/// from durable state next tick, however deep the unindexed ancestry is.
const MAX_SHARD_WORK_PER_TICK: usize = 4096;
/// Published addresses refreshed per drain.
const MAX_ADDRESS_REFRESH_PER_DRAIN: usize = 4096;
const NOMINATOR_POOL_KIND: &str = "contract.pool.nominator";
/// Max transactions requested per `getBlockTransactions` page.
const TRANSACTIONS_PAGE_SIZE: u32 = 256;
/// Upper bound on how many *new* service-request ids one visit to a Service
/// Actor may materialise. `next_request_id` is read from an arbitrary deployed
/// contract's own state, so it is untrusted input: without a cap a contract
/// reporting a huge counter would make the indexer allocate and probe the
/// whole id range in a single tick. Later visits resume from the stored
/// high-water mark, so progress stays monotonic while per-tick work is bounded.
const MAX_SERVICE_REQUEST_IDS_PER_TICK: u64 = 4096;

/// Hard bound on how many request rows one service contract may ever occupy
/// in the index. The per-tick cap alone only bounds each visit: a contract
/// reporting an absurd `next_request_id` would still grow the database by one
/// capped batch of not-found rows per visit, forever. Beyond this bound the
/// indexer stops extending into new ids for the service (already-stored rows
/// keep refreshing) and says so once per visit; a legitimate service that
/// outgrows it needs an operator decision, not silent unbounded disk growth.
const MAX_TRACKED_REQUESTS_PER_SERVICE: u64 = 65_536;

/// Process-wide budget for probing NEW service-request ids, refilled on a
/// time basis. Per-service and per-visit caps alone still let a third party
/// multiply the work by deploying many service contracts with fabricated
/// counters; every not-found probe costs two chain reads, so the total
/// probe rate must be bounded no matter how many contracts exist. Real,
/// already-stored requests are refreshed outside this budget: each of those
/// rows corresponds to a request somebody paid chain fees to create.
const GLOBAL_SERVICE_PROBE_BUDGET: u64 = 16_384;
const PROBE_BUDGET_REFILL_SECS: u64 = 60;

/// Token bucket for new-id probes, owned by the indexer run loop and passed
/// down the scan call chain (tests construct their own, so nothing is
/// process-global).
pub(crate) struct ProbeBudget {
    // One lock holds both the window stamp and the remaining tokens: with
    // two separate atomics, a concurrent taker between the window publish
    // and the refill store could drain leftover tokens that the refill then
    // overwrote, over-granting across the boundary. take() runs at most
    // once per service visit, so contention is irrelevant.
    state: std::sync::Mutex<ProbeBudgetState>,
}

struct ProbeBudgetState {
    remaining: u64,
    window_start: u64,
}

impl ProbeBudget {
    pub(crate) fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(ProbeBudgetState {
                remaining: GLOBAL_SERVICE_PROBE_BUDGET,
                window_start: 0,
            }),
        }
    }

    fn take(&self, want: u64, now: u64) -> u64 {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if now.saturating_sub(state.window_start) >= PROBE_BUDGET_REFILL_SECS {
            state.window_start = now;
            state.remaining = GLOBAL_SERVICE_PROBE_BUDGET;
        }
        let granted = state.remaining.min(want);
        state.remaining -= granted;
        granted
    }
}

/// Pure range computation for the new-id scan, so the bounds are unit
/// testable: resumes after the scanned high-water mark, takes at most one
/// per-visit batch, and never extends past the per-service row budget or
/// the granted share of the global probe budget.
fn new_service_request_id_range(
    max_indexed: Option<u64>,
    stored_rows: u64,
    claimed_next_request_id: u64,
    granted_probes: u64,
) -> std::ops::Range<u64> {
    let first_new = max_indexed.map_or(0, |id| id.saturating_add(1));
    let remaining_budget = MAX_TRACKED_REQUESTS_PER_SERVICE.saturating_sub(stored_rows);
    let batch = MAX_SERVICE_REQUEST_IDS_PER_TICK.min(remaining_budget).min(granted_probes);
    let new_end = claimed_next_request_id.min(first_new.saturating_add(batch));
    first_new..new_end
}

pub async fn run(
    cancellation_ctx: CancellationCtx,
    app_config: Arc<AppConfig>,
    runtime_cfg: Arc<dyn RuntimeConfig>,
    indexer_store: Arc<IndexerStore>,
) -> anyhow::Result<()> {
    let chain_provider = runtime_cfg.chain_provider();
    let known = KnownCodeHashes::compute()?;
    let probe_budget = ProbeBudget::new();
    let mut interval = tokio::time::interval(Duration::from_secs(app_config.tick_interval));
    let mut cancel = cancellation_ctx.subscribe();
    let retention_blocks = app_config.indexer_retention_blocks;
    // Only prune once the published watermark has advanced by this much past
    // the last prune, so the referential transaction sweep does not run every
    // tick.
    let mut prune = PruneState::new((retention_blocks / 10).max(1000));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = tick(
                    &chain_provider,
                    &indexer_store,
                    &known,
                    &probe_budget,
                    &ScanLimits::production(),
                    retention_blocks,
                    &mut prune,
                )
                .await
                {
                    tracing::error!(target: "indexer", "scan error: {:#}", e);
                }
            }
            _ = cancel.changed() => {
                tracing::info!(target: "indexer", "cancel received");
                return Ok(());
            }
        }
    }
}

/// The contract codes the indexer recognizes, keyed by their
/// representation hash (`Cell::repr_hash`, the same value `HASHCU` computes
/// on-chain).
struct KnownCodeHashes {
    by_hash: std::collections::HashMap<UInt256, &'static str>,
}

impl KnownCodeHashes {
    fn compute() -> anyhow::Result<Self> {
        let mut by_hash = std::collections::HashMap::new();
        by_hash.insert(TaskEscrowContract::code()?.repr_hash(), "task_escrow");
        by_hash.insert(AgentAccountContract::code()?.repr_hash(), "agent_account");
        by_hash.insert(DisputeContract::code()?.repr_hash(), "dispute");
        by_hash.insert(ServiceActorContract::code()?.repr_hash(), "service_actor");
        by_hash.insert(CapabilityRegistryContract::code()?.repr_hash(), "capability_registry");
        by_hash.insert(UInt256::from_slice(&hex::decode(DNS_ITEM_CODE_HASH)?), "dns_domain");
        let nominator_pool_code = read_single_root_boc(hex::decode(NOMINATOR_POOL_CODE)?)?;
        by_hash.insert(nominator_pool_code.repr_hash(), "contract.pool.nominator");
        Ok(Self { by_hash })
    }

    fn classify(&self, code: &Cell) -> Option<&'static str> {
        self.by_hash.get(&code.repr_hash()).copied()
    }
}

/// How much work one tick may do. Every bound yields a normal, resumable
/// return rather than an error: the next tick continues from durable state.
#[derive(Clone, Debug)]
struct ScanLimits {
    /// Masterchain heights published per tick.
    max_batches: u32,
    /// Shard-ancestry work units per tick.
    max_shard_work: usize,
    /// Published addresses refreshed per drain.
    max_refresh: usize,
}

impl ScanLimits {
    fn production() -> Self {
        Self {
            max_batches: MAX_BLOCKS_PER_TICK,
            max_shard_work: MAX_SHARD_WORK_PER_TICK,
            max_refresh: MAX_ADDRESS_REFRESH_PER_DRAIN,
        }
    }
}

/// What one scan pass achieved. `published_mc_seqno` is the only value any
/// retention decision may be derived from; `remote_tip` is informational.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ScanOutcome {
    remote_tip: u32,
    published_mc_seqno: u32,
}

/// Retention bookkeeping carried across ticks.
struct PruneState {
    last_prune_seqno: u32,
    step: u32,
}

impl PruneState {
    fn new(step: u32) -> Self {
        Self { last_prune_seqno: 0, step: step.max(1) }
    }
}

/// One indexer tick: scan, then prune strictly below the published
/// watermark.
async fn tick(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    known: &KnownCodeHashes,
    probe_budget: &ProbeBudget,
    limits: &ScanLimits,
    retention_blocks: u32,
    prune: &mut PruneState,
) -> anyhow::Result<ScanOutcome> {
    let outcome = scan_new_blocks(chain_provider, store, known, probe_budget, limits).await?;
    if let Err(e) = prune_after_scan(store, retention_blocks, outcome.published_mc_seqno, prune) {
        tracing::error!(target: "indexer", "prune error: {:#}", e);
    }
    Ok(outcome)
}

/// Retention is measured from what is published, never from the remote tip:
/// `keep_from = published - retention`.
fn prune_after_scan(
    store: &IndexerStore,
    retention_blocks: u32,
    published_mc_seqno: u32,
    prune: &mut PruneState,
) -> anyhow::Result<()> {
    if retention_blocks == 0 || published_mc_seqno <= retention_blocks {
        return Ok(());
    }
    let keep_from = published_mc_seqno.saturating_sub(retention_blocks);
    if keep_from < prune.last_prune_seqno.saturating_add(prune.step) {
        return Ok(());
    }
    let removed = store.prune_history(keep_from)?;
    prune.last_prune_seqno = keep_from;
    if removed > 0 {
        tracing::info!(
            target: "indexer",
            "pruned {removed} history rows older than published mc seqno {keep_from}"
        );
    }
    Ok(())
}

async fn scan_new_blocks(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    known: &KnownCodeHashes,
    probe_budget: &ProbeBudget,
    limits: &ScanLimits,
) -> anyhow::Result<ScanOutcome> {
    let mc_info = chain_provider.get_masterchain_info().await?;
    let master_shard = mc_info.last.shard;
    let target = mc_info.last.seqno;
    store.set_remote_mc_tip(target)?;

    // Published history is only trusted while the chain still reports the
    // exact published masterchain block; otherwise everything derived from
    // it is replayed.
    if let Some(published) = store.canonical_state()? {
        let actual = masterchain_block_id(chain_provider, master_shard, published.seqno).await?;
        if !is_anchor(&actual, &published) {
            tracing::warn!(
                target: "indexer",
                seqno = published.seqno,
                "published masterchain block changed; rebuilding canonical explorer index",
            );
            store.reset_canonical_index()?;
        }
    }
    // Lifetime ledger totals without canonical provenance are rebuilt by a
    // replay of the whole index from genesis; they stay unavailable until it
    // completes.
    if store.nominator_ledger_state()?.status == LedgerStatus::RebuildRequired {
        if store.canonical_state()?.is_some() || store.pending_batch()?.is_some() {
            tracing::warn!(
                target: "indexer",
                "nominator ledger lacks canonical provenance; replaying the index from genesis",
            );
            store.reset_canonical_index()?;
        }
        store.begin_nominator_ledger_rebuild()?;
    }
    // A batch left pending by an earlier tick or process is resumed only if
    // its anchor is still the chain's block at that height.
    if let Some(batch) = store.pending_batch()? {
        let expected = store.published_mc_seqno()?.saturating_add(1);
        let actual = masterchain_block_id(chain_provider, master_shard, batch.anchor.seqno).await?;
        if batch.anchor.seqno != expected || !is_anchor(&actual, &batch.anchor) {
            tracing::warn!(
                target: "indexer",
                seqno = batch.anchor.seqno,
                "pending masterchain block changed; discarding its hidden rows",
            );
            store.discard_pending_batch()?;
        }
    }
    // Touches published before an interruption are refreshed first.
    drain_address_refresh(chain_provider, store, known, probe_budget, limits.max_refresh).await?;

    let mut published_now = 0u32;
    let mut work_left = limits.max_shard_work;
    loop {
        let Some(batch) = store.pending_batch()? else {
            if published_now >= limits.max_batches {
                break;
            }
            let next = store.published_mc_seqno()?.saturating_add(1);
            if next > target {
                break;
            }
            let id = masterchain_block_id(chain_provider, master_shard, next).await?;
            store.begin_batch(&checkpoint_of(&id))?;
            continue;
        };
        match advance_batch(chain_provider, store, &batch.anchor, master_shard, &mut work_left)
            .await?
        {
            BatchProgress::Pending => break,
            BatchProgress::Assembled => {
                let actual =
                    masterchain_block_id(chain_provider, master_shard, batch.anchor.seqno).await?;
                if !is_anchor(&actual, &batch.anchor) {
                    tracing::warn!(
                        target: "indexer",
                        seqno = batch.anchor.seqno,
                        "masterchain block changed while its batch was assembled; discarding it",
                    );
                    store.discard_pending_batch()?;
                    continue;
                }
                store.publish_batch(master_shard, &batch.anchor)?;
                published_now = published_now.saturating_add(1);
                drain_address_refresh(
                    chain_provider,
                    store,
                    known,
                    probe_budget,
                    limits.max_refresh,
                )
                .await?;
            }
        }
    }
    Ok(ScanOutcome { remote_tip: target, published_mc_seqno: store.published_mc_seqno()? })
}

fn is_anchor(actual: &BlockFullId, anchor: &MasterchainCheckpoint) -> bool {
    actual.workchain == -1
        && actual.seqno == anchor.seqno
        && actual.root_hash == anchor.root_hash
        && actual.file_hash == anchor.file_hash
}

fn checkpoint_of(id: &BlockFullId) -> MasterchainCheckpoint {
    MasterchainCheckpoint {
        seqno: id.seqno,
        root_hash: id.root_hash.clone(),
        file_hash: id.file_hash.clone(),
    }
}

enum BatchProgress {
    /// The work budget ran out; the batch resumes from durable state.
    Pending,
    /// Every shard block the height references is indexed or at the frontier.
    Assembled,
}

/// Advances the pending batch as far as the work budget allows. Each unit
/// of work is one durable step, so stopping anywhere is safe.
async fn advance_batch(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    anchor: &MasterchainCheckpoint,
    master_shard: i64,
    work_left: &mut usize,
) -> anyhow::Result<BatchProgress> {
    loop {
        let batch = store
            .pending_batch()?
            .ok_or_else(|| anyhow::anyhow!("pending masterchain batch disappeared"))?;
        anyhow::ensure!(batch.anchor == *anchor, "pending masterchain batch was replaced");
        match batch.phase {
            BatchPhase::ScanMaster => {
                if *work_left == 0 {
                    return Ok(BatchProgress::Pending);
                }
                *work_left = work_left.saturating_sub(1);
                let id = BlockFullId {
                    workchain: -1,
                    shard: master_shard,
                    seqno: anchor.seqno,
                    root_hash: anchor.root_hash.clone(),
                    file_hash: anchor.file_hash.clone(),
                };
                let scanned = scan_exact_block(chain_provider, &id, anchor.seqno).await?;
                store.commit_scanned_block(
                    anchor.seqno,
                    &ScannedTarget::Master,
                    &scanned.block,
                    &scanned.transactions,
                    &scanned.touches,
                )?;
            }
            BatchPhase::SeedShards => {
                let shards = chain_provider.get_shards(anchor.seqno).await?.shards;
                let heads = shards.iter().map(full_id).collect::<anyhow::Result<Vec<_>>>()?;
                store.seed_batch_heads(anchor.seqno, &heads)?;
            }
            BatchPhase::Traverse => loop {
                let step = store.next_shard_step(anchor.seqno)?;
                if step == ShardStep::Done {
                    return Ok(BatchProgress::Assembled);
                }
                if *work_left == 0 {
                    return Ok(BatchProgress::Pending);
                }
                *work_left = work_left.saturating_sub(1);
                match step {
                    ShardStep::Resolve(id) => {
                        if store.resolve_at_frontier(anchor.seqno, &id)? {
                            continue;
                        }
                        let parents = chain_provider.get_block_parents(&rpc_block_id(&id)?).await?;
                        let parents = proof_parents(&id, &parents)?;
                        store.record_parents(anchor.seqno, &id, &parents)?;
                    }
                    ShardStep::Scan(id) => {
                        let scanned = scan_exact_block(chain_provider, &id, anchor.seqno).await?;
                        store.commit_scanned_block(
                            anchor.seqno,
                            &ScannedTarget::Shard(id),
                            &scanned.block,
                            &scanned.transactions,
                            &scanned.touches,
                        )?;
                    }
                    ShardStep::Done => return Ok(BatchProgress::Assembled),
                }
            },
        }
    }
}

fn rpc_block_id(id: &BlockFullId) -> anyhow::Result<BlockIdExt> {
    Ok(BlockIdExt {
        r#type: "tos.blockIdExt".to_owned(),
        workchain: id.workchain,
        shard: id.shard,
        seqno: id.seqno,
        root_hash: hex::decode(&id.root_hash)?,
        file_hash: hex::decode(&id.file_hash)?,
    })
}

/// Shard prefix one level up, if `shard` is not the whole workchain.
fn shard_parent(shard: i64) -> Option<i64> {
    let value = shard as u64;
    let low = value & value.wrapping_neg();
    if low == 0 || low == 1 << 63 {
        return None;
    }
    let parent = value.checked_sub(low)? | low.checked_shl(1)?;
    Some(parent as i64)
}

/// The two halves `shard` splits into, if it can split further.
fn shard_children(shard: i64) -> Option<(i64, i64)> {
    let value = shard as u64;
    let low = value & value.wrapping_neg();
    if low <= 1 {
        return None;
    }
    let half = low >> 1;
    Some((value.checked_sub(half)? as i64, value.checked_add(half)? as i64))
}

/// Validates proof-derived parents before they become durable edges: one or
/// two of them, full identities, same workchain, strictly lower seqno, and
/// the shard shape of a continuation, split or merge.
fn proof_parents(child: &BlockFullId, parents: &[BlockIdExt]) -> anyhow::Result<Vec<BlockFullId>> {
    anyhow::ensure!(
        !parents.is_empty() && parents.len() <= 2,
        "shard block {}:{}:{} has {} parents",
        child.workchain,
        child.shard,
        child.seqno,
        parents.len()
    );
    anyhow::ensure!(child.workchain != -1, "masterchain blocks are not shard ancestry");
    let parents = parents.iter().map(full_id).collect::<anyhow::Result<Vec<_>>>()?;
    for parent in &parents {
        anyhow::ensure!(
            parent.workchain == child.workchain && parent.shard != 0 && parent.seqno < child.seqno,
            "shard block {}:{}:{} names an invalid parent {}:{}:{}",
            child.workchain,
            child.shard,
            child.seqno,
            parent.workchain,
            parent.shard,
            parent.seqno
        );
    }
    let shape_ok = match parents.as_slice() {
        [only] => only.shard == child.shard || shard_parent(child.shard) == Some(only.shard),
        [left, right] => shard_children(child.shard).is_some_and(|(low, high)| {
            (left.shard == low && right.shard == high) || (left.shard == high && right.shard == low)
        }),
        _ => false,
    };
    anyhow::ensure!(
        shape_ok,
        "parents of shard block {}:{}:{} are not a continuation, split or merge",
        child.workchain,
        child.shard,
        child.seqno
    );
    Ok(parents)
}

/// One exact block's explorer rows and per-address touch counts.
struct ScannedBlock {
    block: ExplorerBlockRecord,
    transactions: Vec<ExplorerTransactionRecord>,
    touches: Vec<AddressTouch>,
}

/// Reads every transaction page of one exact block. Every page must report
/// exactly the requested identity; nothing is written here.
async fn scan_exact_block(
    chain_provider: &Arc<dyn ChainProvider>,
    id: &BlockFullId,
    observed_mc_seqno: u32,
) -> anyhow::Result<ScannedBlock> {
    let (workchain, shard, seqno) = (id.workchain, id.shard, id.seqno);
    let mut touches: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut explorer_transactions: Vec<ExplorerTransactionRecord> = Vec::new();
    let indexed_at = time_format::now();
    let mut observed_gen_utime = 0;
    let mut after_lt: Option<u64> = None;
    let mut after_account: Option<String> = None;
    loop {
        let extended = chain_provider
            .get_block_transactions_ext_page(
                workchain,
                shard,
                seqno,
                after_lt,
                after_account.as_deref(),
                TRANSACTIONS_PAGE_SIZE,
            )
            .await;
        let (page_id, incomplete, transactions) = match extended {
            Ok(page) => (
                page.id,
                page.incomplete,
                page.transactions
                    .into_iter()
                    .map(|tx| {
                        (
                            tx.account,
                            tx.lt,
                            tx.hash,
                            (!tx.fee.is_empty()).then_some(tx.fee),
                            (!tx.in_msg_hash.is_empty()).then_some(tx.in_msg_hash),
                            tx.utime,
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
            Err(error) => {
                tracing::debug!(
                    target: "indexer",
                    workchain,
                    shard,
                    seqno,
                    error = %error,
                    "extended transaction page unavailable; using identity-only page",
                );
                let page = chain_provider
                    .get_block_transactions_page(
                        workchain,
                        shard,
                        seqno,
                        after_lt,
                        after_account.as_deref(),
                        TRANSACTIONS_PAGE_SIZE,
                    )
                    .await?;
                (
                    page.id,
                    page.incomplete,
                    page.transactions
                        .into_iter()
                        .map(|tx| (tx.account, tx.lt, tx.hash, None, None, 0))
                        .collect::<Vec<_>>(),
                )
            }
        };
        let actual = page_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("block transaction page omitted exact block id"))?;
        anyhow::ensure!(
            full_id(actual)? == *id,
            "block transaction page for {workchain}:{shard}:{seqno} reports a different block"
        );
        for (account, lt, hash, fee, in_msg_hash, utime) in &transactions {
            if account.is_empty() {
                continue;
            }
            // Normalize through `MsgAddressInt` rather than storing the raw
            // (RPC-cased) hex string directly: `getBlockTransactions`
            // returns the account hash in whatever case the node chose,
            // which need not match `MsgAddressInt::to_string()`'s canonical
            // form -- and every other lookup (direct `/x/{address}` HTTP
            // routes, CLI address args) goes through that canonical form.
            let Ok(addr) = MsgAddressInt::from_str(&format!("{workchain}:{account}")) else {
                continue;
            };
            let address = addr.to_string();
            let count = touches.entry(address.clone()).or_insert(0);
            *count = count.saturating_add(1);
            if observed_gen_utime == 0 {
                observed_gen_utime = *utime;
            }
            if !hash.is_empty() {
                explorer_transactions.push(ExplorerTransactionRecord {
                    hash: hash.clone(),
                    account: address,
                    lt: *lt,
                    workchain,
                    shard,
                    seqno,
                    gen_utime: 0,
                    fee: fee.clone(),
                    in_msg_hash: in_msg_hash.clone(),
                    indexed_at,
                });
            }
        }
        if !incomplete {
            break;
        }
        let Some(last) = transactions.last() else { break };
        after_lt = Some(last.1);
        after_account = Some(last.0.clone());
    }

    let gen_utime = if observed_gen_utime > 0 {
        observed_gen_utime
    } else {
        chain_provider.get_block_timestamp(workchain, shard, seqno).await?
    };
    for transaction in &mut explorer_transactions {
        transaction.gen_utime = gen_utime;
    }
    let block = ExplorerBlockRecord {
        workchain,
        shard,
        seqno,
        root_hash: id.root_hash.clone(),
        file_hash: id.file_hash.clone(),
        gen_utime,
        tx_count: explorer_transactions.len(),
        indexed_at,
        observed_mc_seqno,
    };
    let touches = touches
        .into_iter()
        .map(|(address, count)| AddressTouch { address, count, block_seqno: seqno, gen_utime })
        .collect();
    Ok(ScannedBlock { block, transactions: explorer_transactions, touches })
}

/// Refreshes contract state for addresses touched by published history,
/// each bound to the exact published masterchain block that made its
/// touches canonical. A failure that could hide a nominator-pool
/// observation keeps the row for another attempt; other contract kinds are
/// best-effort, as before.
async fn drain_address_refresh(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    known: &KnownCodeHashes,
    probe_budget: &ProbeBudget,
    limit: usize,
) -> anyhow::Result<()> {
    for refresh in store.address_refresh_queue(limit)? {
        let kind_before = store.kind_of(&refresh.address)?;
        match visit_address(chain_provider, store, known, &refresh, probe_budget).await {
            Ok(()) => store.complete_address_refresh(&refresh)?,
            Err(e) => {
                let ledger_relevant = match kind_before.as_deref() {
                    None | Some("unclassified") => true,
                    Some(kind) => kind == NOMINATOR_POOL_KIND,
                };
                if ledger_relevant {
                    tracing::warn!(
                        target: "indexer",
                        address = %refresh.address,
                        mc_seqno = refresh.checkpoint.seqno,
                        error = %format!("{e:#}"),
                        "failed to index account; keeping it for another attempt"
                    );
                    store.defer_address_refresh(&refresh)?;
                } else {
                    tracing::warn!(
                        target: "indexer",
                        address = %refresh.address,
                        error = %format!("{e:#}"),
                        "failed to index account"
                    );
                    store.complete_address_refresh(&refresh)?;
                }
            }
        }
    }
    store.settle_nominator_ledger()?;
    Ok(())
}

async fn visit_address(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    known: &KnownCodeHashes,
    refresh: &AddressRefresh,
    probe_budget: &ProbeBudget,
) -> anyhow::Result<()> {
    let address = refresh.address.as_str();
    let seqno = refresh.last_block_seqno;
    let existing_kind = store.kind_of(address)?;
    let kind = match existing_kind {
        // A funded address can be observed while it is still uninitialized;
        // Nominator Pools intentionally use that fund-then-activate flow.
        // Re-check an unclassified address whenever later activity touches it
        // so StateInit activation can promote it to a known contract kind.
        Some(kind) if kind == "unclassified" => {
            let Some(kind) = classify_address(chain_provider, known, address).await? else {
                return Ok(());
            };
            kind
        }
        Some(kind) => kind,
        None => {
            let Some(kind) = classify_address(chain_provider, known, address).await? else {
                store.upsert(&IndexedRecord {
                    address: address.to_owned(),
                    kind: "unclassified".to_owned(),
                    creator: None,
                    counterparty: None,
                    status: None,
                    deadline: None,
                    last_seqno: seqno,
                    updated_at: time_format::now(),
                    dto_json: "{}".to_owned(),
                })?;
                return Ok(());
            };
            kind
        }
    };

    if kind == NOMINATOR_POOL_KIND {
        return refresh_nominator_pool(chain_provider, store, address, refresh).await;
    }
    if kind == "dns_domain" {
        return decode_dns_domain(
            chain_provider,
            store,
            address,
            seqno,
            refresh.checkpoint.seqno,
            u64::from(refresh.last_gen_utime),
            &refresh.checkpoint,
        )
        .await;
    }
    decode_and_store(chain_provider, store, address, &kind, seqno, time_format::now(), probe_budget)
        .await
}

/// Converts an RPC block id into a full identity, refusing ids whose hashes
/// are not 32 bytes: a truncated hash is not an identity.
fn full_id(id: &BlockIdExt) -> anyhow::Result<BlockFullId> {
    anyhow::ensure!(
        id.root_hash.len() == 32 && id.file_hash.len() == 32,
        "block id {}:{}:{} lacks full 32-byte hashes",
        id.workchain,
        id.shard,
        id.seqno
    );
    Ok(BlockFullId {
        workchain: id.workchain,
        shard: id.shard,
        seqno: id.seqno,
        root_hash: hex::encode(&id.root_hash),
        file_hash: hex::encode(&id.file_hash),
    })
}

/// The exact identity the chain currently reports for one masterchain seqno.
async fn masterchain_block_id(
    chain_provider: &Arc<dyn ChainProvider>,
    master_shard: i64,
    seqno: u32,
) -> anyhow::Result<BlockFullId> {
    let page =
        chain_provider.get_block_transactions_page(-1, master_shard, seqno, None, None, 1).await?;
    let id = page
        .id
        .ok_or_else(|| anyhow::anyhow!("masterchain block {seqno} lookup omitted its id"))?;
    let id = full_id(&id)?;
    anyhow::ensure!(
        id.workchain == -1 && id.shard == master_shard && id.seqno == seqno,
        "masterchain block lookup for {seqno} returned {}:{}:{}",
        id.workchain,
        id.shard,
        id.seqno
    );
    Ok(id)
}

async fn classify_address(
    chain_provider: &Arc<dyn ChainProvider>,
    known: &KnownCodeHashes,
    address: &str,
) -> anyhow::Result<Option<String>> {
    let addr = address.parse::<MsgAddressInt>()?;
    let info = chain_provider.get_address_info(&addr).await?;
    let Some(code_bytes) = info.code else {
        return Ok(None);
    };
    if code_bytes.is_empty() {
        return Ok(None);
    }
    let code = read_single_root_boc(code_bytes)?;
    Ok(known.classify(&code).map(str::to_owned))
}

async fn decode_and_store(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    address: &str,
    kind: &str,
    seqno: u32,
    now: u64,
    probe_budget: &ProbeBudget,
) -> anyhow::Result<()> {
    match kind {
        "agent_account" => {
            let stack = chain_provider
                .run_get_method(address.to_owned(), "get_agent_account_data", vec![])
                .await?;
            let data = AgentAccountContract::decode_data(&stack)?;
            store.upsert(&IndexedRecord {
                address: address.to_owned(),
                kind: kind.to_owned(),
                creator: Some(data.owner.to_string()),
                counterparty: None,
                status: Some("active".to_owned()),
                deadline: None,
                last_seqno: seqno,
                updated_at: now,
                dto_json: serde_json::to_string(&AgentAccountRecordDto::from(&data))?,
            })
        }
        "task_escrow" => {
            let stack =
                chain_provider.run_get_method(address.to_owned(), "get_task_data", vec![]).await?;
            let data = TaskEscrowContract::decode_data(&stack)?;
            store.upsert(&IndexedRecord {
                address: address.to_owned(),
                kind: kind.to_owned(),
                creator: Some(data.creator.to_string()),
                counterparty: data.assigned_agent.as_ref().map(|a| a.to_string()),
                status: Some(task_status_name(data.status).to_owned()),
                deadline: Some(data.deadline),
                last_seqno: seqno,
                updated_at: now,
                dto_json: serde_json::to_string(&TaskEscrowRecordDto::from(&data))?,
            })
        }
        "dispute" => {
            let stack = chain_provider
                .run_get_method(address.to_owned(), "get_dispute_data", vec![])
                .await?;
            let data = DisputeContract::decode_data(&stack)?;
            store.upsert(&IndexedRecord {
                address: address.to_owned(),
                kind: kind.to_owned(),
                creator: Some(data.claimant.to_string()),
                counterparty: Some(data.respondent.to_string()),
                status: Some(dispute_status_name(data.status).to_owned()),
                deadline: Some(data.deadline),
                last_seqno: seqno,
                updated_at: now,
                dto_json: serde_json::to_string(&DisputeRecordDto::from(&data))?,
            })
        }
        "service_actor" => {
            let stack = chain_provider
                .run_get_method(address.to_owned(), "get_service_data", vec![])
                .await?;
            let data = ServiceActorContract::decode_data(&stack)?;
            refresh_service_request_lifecycle(
                chain_provider,
                store,
                address,
                &data,
                now,
                probe_budget,
            )
            .await?;
            store.upsert(&IndexedRecord {
                address: address.to_owned(),
                kind: kind.to_owned(),
                creator: Some(data.owner.to_string()),
                counterparty: data.authorized_caller.as_ref().map(|a| a.to_string()),
                status: Some(if data.active { "active" } else { "inactive" }.to_owned()),
                deadline: None,
                last_seqno: seqno,
                updated_at: now,
                dto_json: serde_json::to_string(&ServiceActorRecordDto::from(&data))?,
            })
        }
        "capability_registry" => {
            let stack = chain_provider
                .run_get_method(address.to_owned(), "get_capability_registry_data", vec![])
                .await?;
            let data = CapabilityRegistryContract::decode_data(&stack)?;
            store.upsert(&IndexedRecord {
                address: address.to_owned(),
                kind: kind.to_owned(),
                creator: Some(data.owner.to_string()),
                counterparty: data.verifier.as_ref().map(|a| a.to_string()),
                status: Some(if data.active { "active" } else { "inactive" }.to_owned()),
                deadline: None,
                last_seqno: seqno,
                updated_at: now,
                dto_json: serde_json::to_string(&CapabilityRegistryRecordDto::from(&data))?,
            })
        }
        NOMINATOR_POOL_KIND => {
            anyhow::bail!("nominator pools are only refreshed at an exact published checkpoint")
        }
        other => anyhow::bail!("unknown indexed contract kind: {other}"),
    }
}

/// Refreshes one nominator pool from a snapshot pinned to the exact
/// published masterchain block its touches became canonical in, and folds
/// that snapshot into the lifetime ledger. Any failure -- including a node
/// that cannot serve the historical state -- leaves the refresh pending, so
/// the ledger never advances past an observation it could not make.
async fn refresh_nominator_pool(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    address: &str,
    refresh: &AddressRefresh,
) -> anyhow::Result<()> {
    let address_value = address.parse::<MsgAddressInt>()?;
    let snapshot = read_nominator_pool_snapshot_at(
        chain_provider.as_ref(),
        &address_value,
        &refresh.checkpoint,
    )
    .await?;
    let data = snapshot.pool;
    let nominators = snapshot.nominators;
    let nominator_stake = nominators.iter().fold(0u64, |total, position| {
        total.saturating_add(position.amount.saturating_add(position.pending_deposit))
    });

    // What guard 68 would compare against for the next new depositor:
    // the depth of the dictionary as it stands now, against the bound
    // derived from a count that has already been incremented.
    let addresses: Vec<[u8; 32]> = nominators
        .iter()
        .filter_map(|position| {
            let hex_part = position.address.split(':').nth(1)?;
            let bytes = hex::decode(hex_part).ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        })
        .collect();
    let depth_headroom = deposit_depth_bound(data.nominators_count.saturating_add(1))
        .saturating_sub(nominator_dictionary_depth(&addresses))
        .saturating_sub(1);
    let status = match data.state {
        0 => "idle",
        1 => "staking",
        2 => "staked",
        _ => "unknown",
    };
    let dto = NominatorPoolRecordDto {
        state: data.state,
        nominators_count: data.nominators_count,
        stake_amount_sent: data.stake_amount_sent.to_string(),
        validator_amount: data.validator_amount.to_string(),
        nominator_stake: nominator_stake.to_string(),
        total_balance_at_risk: data.validator_amount.saturating_add(nominator_stake).to_string(),
        validator_address: format!("0:{}", hex::encode(data.validator_address)),
        validator_reward_share_bps: data.validator_reward_share,
        max_nominators_count: data.max_nominators_count,
        min_validator_stake: data.min_validator_stake.to_string(),
        min_nominator_stake: data.min_nominator_stake.to_string(),
        stake_at: data.stake_at,
        saved_validator_set_hash: hex::encode(data.saved_validator_set_hash),
        validator_set_changes_count: data.validator_set_changes_count,
        validator_set_change_time: data.validator_set_change_time,
        stake_held_for: data.stake_held_for,
        capacity_headroom: data
            .max_nominators_count
            .saturating_sub(u16::try_from(data.nominators_count).unwrap_or(u16::MAX)),
        deposit_depth_headroom: depth_headroom,
        accepting_deposits: u32::from(data.max_nominators_count) > data.nominators_count
            && depth_headroom > 0,
        nominators,
    };

    // Attribute this observation before the record is overwritten: the
    // contract's ledger says what a depositor is owed now, and the
    // difference from the last observation is the only place the reason
    // for the change is still visible. A withdrawal deletes the entry
    // outright, so the ledger zeroes whoever is missing.
    let observed_positions: Vec<(String, u64, u64)> = dto
        .nominators
        .iter()
        .map(|position| (position.address.clone(), position.amount, position.pending_deposit))
        .collect();
    let now = time_format::now();
    store.observe_nominator_snapshot(
        address,
        dto.state,
        now,
        &observed_positions,
        &refresh.checkpoint,
        refresh.touch_count,
    )?;
    store.upsert(&IndexedRecord {
        address: address.to_owned(),
        kind: NOMINATOR_POOL_KIND.to_owned(),
        creator: Some(dto.validator_address.clone()),
        counterparty: None,
        status: Some(status.to_owned()),
        deadline: (data.stake_at > 0 && data.stake_held_for > 0)
            .then_some(u64::from(data.stake_at).saturating_add(data.stake_held_for)),
        last_seqno: refresh.last_block_seqno,
        updated_at: now,
        dto_json: serde_json::to_string(&dto)?,
    })
}

async fn decode_dns_domain(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    address: &str,
    account_seqno: u32,
    mc_seqno: u32,
    now: u64,
    checkpoint: &MasterchainCheckpoint,
) -> anyhow::Result<()> {
    anyhow::ensure!(mc_seqno > 0, "DNS observation lacks a masterchain checkpoint");
    anyhow::ensure!(checkpoint.seqno == mc_seqno, "DNS checkpoint seqno mismatch");
    let nft = chain_provider
        .run_get_method_at(address.to_owned(), "get_nft_data", vec![], checkpoint)
        .await?;
    anyhow::ensure!(nft.bool(0)?, "DNS Domain Item is not initialized");
    let index = nft.decimal_string(1)?.to_owned();
    let mut collection_slice = nft.slice(2)?;
    let collection = MsgAddressInt::construct_from(&mut collection_slice)?;
    anyhow::ensure!(
        collection.to_string() == DNS_COLLECTION_ADDRESS,
        "DNS Item belongs to a non-canonical Collection"
    );
    anyhow::ensure!(
        collection_slice.remaining_bits() == 0 && collection_slice.remaining_references() == 0,
        "trailing Collection address data"
    );
    let owner = parse_optional_dns_address(nft.slice(3)?)?.map(|value| value.to_string());
    let content = nft.cell(4)?;

    let domain_stack = chain_provider
        .run_get_method_at(address.to_owned(), "get_domain", vec![], checkpoint)
        .await?;
    let domain_slice = domain_stack.slice(0)?;
    anyhow::ensure!(
        domain_slice.remaining_bits() % 8 == 0 && domain_slice.remaining_references() == 0,
        "DNS label is not one refless byte string"
    );
    let domain_bytes = domain_slice.get_bytestring(0);
    let label = String::from_utf8(domain_bytes)?;
    anyhow::ensure!(
        contracts::dns::label_contract_error(&label).is_none(),
        "on-chain DNS label is invalid"
    );
    let expected_index = contracts::dns::label_slice_hash(&label)?;
    anyhow::ensure!(
        nft.number_bytes(1, 32)? == expected_index,
        "DNS Item index differs from label slice hash"
    );
    let item_hash: [u8; 32] =
        hex::decode(DNS_ITEM_CODE_HASH)?.try_into().expect("constant is 32 bytes");
    let derived = contracts::dns::derive_item_address(
        &contracts::dns::CollectionConfig {
            collection: collection.clone(),
            item_code_hash: item_hash,
            item_code_depth: DNS_ITEM_CODE_DEPTH,
            item_workchain: 0,
        },
        &label,
    )?;
    anyhow::ensure!(
        derived.to_string() == address,
        "DNS Item address is not canonical for its label"
    );

    let auction_stack = chain_provider
        .run_get_method_at(address.to_owned(), "get_auction_info", vec![], checkpoint)
        .await?;
    let auction_end_time = auction_stack.i64(2)?;
    let max_bid_amount = auction_stack.decimal_string(1)?.parse::<u128>()?;
    anyhow::ensure!(auction_end_time >= 0, "negative DNS auction end time");
    let max_bid_address =
        parse_optional_dns_address(auction_stack.slice(0)?)?.map(|value| value.to_string());
    let auction = (auction_end_time != 0).then_some(contracts::dns::AuctionInfo {
        max_bid_address: max_bid_address.as_deref().map(str::parse).transpose()?,
        max_bid_amount,
        auction_end_time,
    });
    let fill_stack = chain_provider
        .run_get_method_at(address.to_owned(), "get_last_fill_up_time", vec![], checkpoint)
        .await?;
    let last_fill_up_time = fill_stack.i64(0)?;
    anyhow::ensure!(last_fill_up_time > 0, "DNS Domain Item lacks a renewal clock");
    let lifecycle =
        contracts::dns::classify_domain(auction.as_ref(), last_fill_up_time, now as i64);
    let dto = DnsDomainRecordDto {
        name: format!("{label}.tos"),
        label,
        index,
        collection: collection.to_string(),
        owner,
        max_bid_address,
        max_bid_amount: max_bid_amount.to_string(),
        auction_end_time,
        last_fill_up_time,
        renewal_deadline: lifecycle.renewal_deadline,
        safe_to_resolve: lifecycle.safe_to_resolve,
        content_boc_base64: base64::engine::general_purpose::STANDARD.encode(write_boc(&content)?),
        content_hash: hex::encode(content.repr_hash()),
    };
    let dto_json = serde_json::to_string(&dto)?;
    store.record_dns_domain_history(&DnsDomainHistoryRecord {
        address: address.to_owned(),
        account_seqno,
        observed_mc_seqno: mc_seqno,
        observed_at: now,
        dto_json: dto_json.clone(),
        root_hash: Some(checkpoint.root_hash.clone()),
        file_hash: Some(checkpoint.file_hash.clone()),
    })?;
    store.upsert(&IndexedRecord {
        address: address.to_owned(),
        kind: "dns_domain".to_owned(),
        creator: dto.owner.clone(),
        counterparty: dto.max_bid_address.clone(),
        status: Some(lifecycle.state.as_str().to_owned()),
        deadline: lifecycle.renewal_deadline.and_then(|value| u64::try_from(value).ok()),
        last_seqno: account_seqno,
        updated_at: now,
        dto_json,
    })
}

fn parse_optional_dns_address(mut value: SliceData) -> anyhow::Result<Option<MsgAddressInt>> {
    let mut tag = value.clone();
    let prefix = tag.get_next_int(2)?;
    if prefix == 0 {
        anyhow::ensure!(
            value.remaining_bits() == 2 && value.remaining_references() == 0,
            "trailing data after addr_none"
        );
        return Ok(None);
    }
    let address = MsgAddressInt::construct_from(&mut value)?;
    anyhow::ensure!(
        value.remaining_bits() == 0 && value.remaining_references() == 0,
        "trailing internal-address data"
    );
    Ok(Some(address))
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct DnsDomainRecordDto {
    name: String,
    label: String,
    index: String,
    collection: String,
    owner: Option<String>,
    max_bid_address: Option<String>,
    max_bid_amount: String,
    auction_end_time: i64,
    last_fill_up_time: i64,
    renewal_deadline: Option<i64>,
    safe_to_resolve: bool,
    content_boc_base64: String,
    content_hash: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct NominatorPoolRecordDto {
    state: i32,
    nominators_count: u32,
    stake_amount_sent: String,
    validator_amount: String,
    nominator_stake: String,
    total_balance_at_risk: String,
    validator_address: String,
    validator_reward_share_bps: u16,
    max_nominators_count: u16,
    min_validator_stake: String,
    min_nominator_stake: String,
    stake_at: u32,
    saved_validator_set_hash: String,
    validator_set_changes_count: i32,
    validator_set_change_time: u64,
    stake_held_for: u64,
    /// Free slots under max_nominators_count.
    capacity_headroom: u16,
    /// Fork levels the nominator dictionary is below pool.fc's depth guard.
    ///
    /// Guard 68 refuses a deposit when the dictionary is already this deep,
    /// and the depositor is told nothing beyond a failed transaction. The
    /// bound grows with the logarithm of the depositor count while the depth
    /// grows with how the admitted addresses happen to branch, so a pool can
    /// stop accepting deposits well below its stated capacity. Zero here means
    /// the next new depositor is refused.
    deposit_depth_headroom: i32,
    /// Whether a new address can currently deposit at all: both limits clear.
    accepting_deposits: bool,
    nominators: Vec<contracts::NominatorPosition>,
}

/// Cell depth of the dictionary holding these nominator addresses.
///
/// A hashmap node is a leaf or a two-way fork, so depth is the number of fork
/// levels on the deepest path; a shared prefix is absorbed into a label and
/// costs nothing. Recomputed here rather than read from the contract because
/// what matters is whether the *next* deposit would be refused, which the
/// contract only reveals by refusing it.
fn nominator_dictionary_depth(addresses: &[[u8; 32]]) -> i32 {
    fn split(keys: &[&[u8; 32]], bit: i32) -> i32 {
        if keys.len() <= 1 || bit < 0 {
            return 0;
        }
        let index = (255 - bit) as usize / 8;
        let mask = 1u8 << (bit % 8);
        let (ones, zeros): (Vec<_>, Vec<_>) = keys.iter().partition(|key| key[index] & mask != 0);
        if ones.is_empty() || zeros.is_empty() {
            return split(keys, bit - 1);
        }
        1 + split(&ones, bit - 1).max(split(&zeros, bit - 1))
    }
    if addresses.len() <= 1 {
        return 0;
    }
    let refs: Vec<&[u8; 32]> = addresses.iter().collect();
    split(&refs, 255)
}

/// pool.fc's `max(5, binary_log_ceil(count) * 2)`, where binary_log_ceil is
/// TVM's UBITSIZE.
fn deposit_depth_bound(nominators_count: u32) -> i32 {
    let bits = 32 - nominators_count.leading_zeros() as i32;
    (bits * 2).max(5)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ServiceRequestLifecycleRecordDto {
    service_address: String,
    request_id: u64,
    status: String,
    caller: Option<String>,
    price: Option<u64>,
    storage_fee: Option<u64>,
    cleanup_bounty: Option<u64>,
    response_deadline: Option<u64>,
    refund_claim_deadline: Option<u64>,
    policy_version: Option<u32>,
    request_hash: Option<String>,
    terms_hash: Option<String>,
}

async fn refresh_service_request_lifecycle(
    provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    address: &str,
    data: &contracts::ServiceActorData,
    now: u64,
    probe_budget: &ProbeBudget,
) -> anyhow::Result<()> {
    let (max_indexed, stored_rows, active) = store.service_requests_for_refresh(address)?;
    // `active` is bounded by rows this indexer itself stored (non-terminal
    // statuses only); the contract cannot inflate it. The *new* id range, by
    // contrast, comes straight from the contract's own counter, so it is
    // capped per visit AND by a per-service row budget -- otherwise a
    // fabricated counter would still grow the database by one capped batch
    // of not-found rows per visit, forever.
    let mut ids: HashSet<u64> = active.into_iter().map(|r| r.request_id).collect();
    let first_new = max_indexed.map_or(0, |id| id.saturating_add(1));
    let want = MAX_SERVICE_REQUEST_IDS_PER_TICK
        .min(data.next_request_id.saturating_sub(first_new))
        .min(MAX_TRACKED_REQUESTS_PER_SERVICE.saturating_sub(stored_rows));
    let granted = if want > 0 { probe_budget.take(want, now) } else { 0 };
    let new_range =
        new_service_request_id_range(max_indexed, stored_rows, data.next_request_id, granted);
    if want > 0 && new_range.is_empty() {
        tracing::debug!(
            service = %address,
            stored_rows,
            claimed_next_request_id = data.next_request_id,
            "service request scan deferred: per-service or global probe budget exhausted"
        );
    }
    let scanned_high_water = if new_range.is_empty() { None } else { Some(new_range.end - 1) };
    ids.extend(new_range);
    for request_id in ids {
        let old = store.service_request(address, request_id)?;
        let arg = vec![contracts::stack_utils::u64_to_stack_entry(request_id)];
        let pending = ServiceActorContract::decode_request(
            &provider.run_get_method(address.to_owned(), "get_request", arg.clone()).await?,
        )?;
        let refund = if pending.is_none() {
            ServiceActorContract::decode_refund(
                &provider.run_get_method(address.to_owned(), "get_refund", arg).await?,
            )?
        } else {
            None
        };
        let dto = if let Some(r) = pending {
            ServiceRequestLifecycleRecordDto {
                service_address: address.to_owned(),
                request_id,
                status: "pending".into(),
                caller: Some(r.caller.to_string()),
                price: Some(r.price),
                storage_fee: Some(r.storage_fee),
                cleanup_bounty: Some(r.cleanup_bounty),
                response_deadline: Some(r.response_deadline),
                refund_claim_deadline: Some(r.refund_claim_deadline),
                policy_version: Some(r.policy_version),
                request_hash: Some(hex::encode(r.request_hash)),
                terms_hash: Some(hex::encode(r.terms_hash)),
            }
        } else if let Some(r) = refund {
            ServiceRequestLifecycleRecordDto {
                service_address: address.to_owned(),
                request_id,
                status: "refundable".into(),
                caller: Some(r.caller.to_string()),
                price: Some(r.price),
                storage_fee: Some(r.storage_fee),
                cleanup_bounty: Some(r.cleanup_bounty),
                response_deadline: None,
                refund_claim_deadline: Some(r.refund_claim_deadline),
                policy_version: None,
                request_hash: None,
                terms_hash: None,
            }
        } else if let Some(old) = old {
            // This is a snapshot diff, not an event log: `run_get_method`
            // always answers with *current* chain state, so an observation
            // gap of even one missed tick can hide an entire intermediate
            // transition (e.g. pending -> expire -> refundable -> claim_refund,
            // collapsed into a single "it's gone now" if the indexer never
            // caught the refundable state in between). The only sound
            // conclusions are the ones an unbroken observation window
            // actually supports:
            //  - a `pending` entry can only disappear via `respond` while
            //    `now() < response_deadline` on chain (expire requires
            //    `now() >= response_deadline`) -- so if *our* observation is
            //    still strictly before `response_deadline`, no expire could
            //    have happened yet and disappearing here can only be
            //    `respond`.
            //  - a `refundable` entry can only disappear via `claim_refund`
            //    while `now() < refund_claim_deadline` (sweep requires
            //    `now() >= refund_claim_deadline`) -- so if our observation is
            //    still strictly before that deadline, disappearing here can
            //    only be `claim_refund`.
            //  - past either respective deadline, or when the entry's last
            //    known status could have already transitioned again before we
            //    looked (e.g. `pending` observed, but `response_deadline` has
            //    since passed -- it may have quietly gone
            //    pending->expire->refundable->claim_refund entirely between
            //    ticks), the disappearance is ambiguous *unless* the last
            //    observation (`old.updated_at`) was already at or past
            //    `refund_claim_deadline`, which proves the entry survived to
            //    become sweepable and only `sweep_expired_request` remains.
            //  - otherwise: report `resolved_unknown` rather than guess.
            //    Disambiguating this for real needs per-transaction event
            //    indexing, not periodic full-state scans.
            let mut prior: ServiceRequestLifecycleRecordDto = serde_json::from_str(&old.dto_json)?;
            let claim_deadline = prior.refund_claim_deadline.unwrap_or(u64::MAX);
            let response_deadline = prior.response_deadline.unwrap_or(0);
            prior.status = match old.status.as_str() {
                "pending" if now < response_deadline => "responded",
                "refundable" if now < claim_deadline => "refunded",
                "pending" | "refundable" if old.updated_at >= claim_deadline => "swept",
                "pending" | "refundable" => "resolved_unknown",
                _ => "resolved_unknown",
            }
            .into();
            prior
        } else {
            // Never seen before and absent on chain: either it resolved
            // before we ever observed it, or the contract's counter is
            // fabricated. Either way a durable row records nothing useful,
            // and storing one per probed id would let a fabricated counter
            // grow the table without limit; the scan high-water mark alone
            // carries the resume position.
            continue;
        };
        store.upsert_service_request(&ServiceRequestRecord {
            service_address: address.to_owned(),
            request_id,
            status: dto.status.clone(),
            updated_at: now,
            dto_json: serde_json::to_string(&dto)?,
        })?;
    }
    if let Some(high_water) = scanned_high_water {
        store.set_service_scan_high_water(address, high_water)?;
    }
    Ok(())
}

#[cfg(test)]
mod new_id_range_tests {
    use super::*;

    #[test]
    fn resumes_after_the_high_water_mark_in_per_tick_batches() {
        assert_eq!(new_service_request_id_range(None, 0, 10, u64::MAX), 0..10);
        assert_eq!(
            new_service_request_id_range(None, 0, u64::MAX, u64::MAX),
            0..MAX_SERVICE_REQUEST_IDS_PER_TICK
        );
        assert_eq!(
            new_service_request_id_range(Some(4095), 4096, u64::MAX, u64::MAX),
            4096..4096 + MAX_SERVICE_REQUEST_IDS_PER_TICK
        );
    }

    #[test]
    fn a_fabricated_counter_cannot_grow_the_index_past_the_service_budget() {
        // At the budget: no new ids at all, however large the claim.
        let r = new_service_request_id_range(
            Some(MAX_TRACKED_REQUESTS_PER_SERVICE - 1),
            MAX_TRACKED_REQUESTS_PER_SERVICE,
            u64::MAX,
            u64::MAX,
        );
        assert!(r.is_empty());
        // Near the budget: only the remainder is scanned.
        let r = new_service_request_id_range(
            Some(MAX_TRACKED_REQUESTS_PER_SERVICE - 11),
            MAX_TRACKED_REQUESTS_PER_SERVICE - 10,
            u64::MAX,
            u64::MAX,
        );
        assert_eq!(r.end - r.start, 10);
    }

    #[test]
    fn the_granted_probe_share_caps_the_batch() {
        let r = new_service_request_id_range(None, 0, u64::MAX, 7);
        assert_eq!(r, 0..7);
        let r = new_service_request_id_range(None, 0, u64::MAX, 0);
        assert!(r.is_empty());
    }

    #[test]
    fn the_global_probe_bucket_grants_at_most_its_refill_per_window() {
        let bucket = ProbeBudget::new();
        let a = bucket.take(GLOBAL_SERVICE_PROBE_BUDGET - 100, 1_000_000);
        assert_eq!(a, GLOBAL_SERVICE_PROBE_BUDGET - 100);
        let b = bucket.take(4_096, 1_000_000);
        assert_eq!(b, 100);
        let c = bucket.take(4_096, 1_000_000);
        assert_eq!(c, 0);
        // A later window refills.
        let d = bucket.take(4_096, 1_000_000 + PROBE_BUDGET_REFILL_SECS);
        assert_eq!(d, 4_096);
    }

    #[test]
    fn high_water_at_max_yields_an_empty_range_instead_of_wrapping() {
        let r = new_service_request_id_range(Some(u64::MAX), 100, u64::MAX, u64::MAX);
        assert!(r.is_empty());
    }
}

fn task_status_name(status: u8) -> &'static str {
    match status {
        0 => "open",
        1 => "accepted",
        2 => "result_submitted",
        3 => "settled",
        4 => "cancelled",
        5 => "expired",
        6 => "rejected",
        7 => "disputed",
        _ => "unknown",
    }
}

fn dispute_status_name(status: u8) -> &'static str {
    match status {
        0 => "open",
        1 => "evidence_submitted",
        2 => "resolved",
        _ => "unknown",
    }
}

// ─── Minimal JSON shapes stored in `dto_json` ──────────────────────────────
//
// These mirror the HTTP query API's own DTOs (see `http::agent_query_api`)
// closely enough to be re-served directly; kept private to this module since
// they exist purely as the indexer's storage format.

#[derive(serde::Serialize, serde::Deserialize)]
struct AgentAccountRecordDto {
    owner: String,
    controller_pubkey: String,
    deployment_id: String,
    controller_epoch: u64,
    seqno: u32,
    spend_day: u32,
    spent_today: u64,
    max_per_tx: u64,
    daily_limit: u64,
    default_task_timeout_secs: u64,
    metadata_hash: Option<String>,
    service_endpoint_hash: Option<String>,
}

impl From<&contracts::AgentAccountData> for AgentAccountRecordDto {
    fn from(data: &contracts::AgentAccountData) -> Self {
        Self {
            owner: data.owner.to_string(),
            controller_pubkey: hex::encode(data.controller_pubkey),
            deployment_id: hex::encode(data.deployment_id),
            controller_epoch: data.controller_epoch,
            seqno: data.seqno,
            spend_day: data.spend_day,
            spent_today: data.spent_today,
            max_per_tx: data.max_per_tx,
            daily_limit: data.daily_limit,
            default_task_timeout_secs: data.default_task_timeout_secs,
            metadata_hash: data.metadata_hash.map(hex::encode),
            service_endpoint_hash: data.service_endpoint_hash.map(hex::encode),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TaskEscrowRecordDto {
    creator: String,
    assigned_agent: Option<String>,
    verifier: Option<String>,
    budget: u64,
    deadline: u64,
    review_period: u32,
    review_deadline: u64,
    status: String,
    result_hash: String,
    evidence_hash: String,
    settlement_policy_hash: String,
    permission_hash: String,
    dispute_hash: String,
}

impl From<&contracts::TaskEscrowData> for TaskEscrowRecordDto {
    fn from(data: &contracts::TaskEscrowData) -> Self {
        Self {
            creator: data.creator.to_string(),
            assigned_agent: data.assigned_agent.as_ref().map(|a| a.to_string()),
            verifier: data.verifier.as_ref().map(|a| a.to_string()),
            budget: data.budget,
            deadline: data.deadline,
            review_period: data.review_period,
            review_deadline: data.review_deadline,
            status: task_status_name(data.status).to_owned(),
            result_hash: hex::encode(data.result_hash),
            evidence_hash: hex::encode(data.evidence_hash),
            settlement_policy_hash: hex::encode(data.settlement_policy_hash),
            permission_hash: hex::encode(data.permission_hash),
            dispute_hash: hex::encode(data.dispute_hash),
        }
    }
}

#[derive(serde::Serialize)]
struct DisputeRecordDto {
    claimant: String,
    respondent: String,
    reviewer: String,
    status: String,
    ruling: u8,
    split_bps: u16,
    deadline: u64,
    subject_hash: String,
}

impl From<&contracts::DisputeData> for DisputeRecordDto {
    fn from(data: &contracts::DisputeData) -> Self {
        Self {
            claimant: data.claimant.to_string(),
            respondent: data.respondent.to_string(),
            reviewer: data.reviewer.to_string(),
            status: dispute_status_name(data.status).to_owned(),
            ruling: data.ruling,
            split_bps: data.split_bps,
            deadline: data.deadline,
            subject_hash: hex::encode(data.subject_hash),
        }
    }
}

#[derive(serde::Serialize)]
struct ServiceActorRecordDto {
    owner: String,
    authorized_caller: Option<String>,
    open_access: bool,
    // Field name (and "active"/"inactive" values) must match the HTTP
    // query API's `ServiceActorDto::status`, which this JSON blob is
    // deserialized directly into (see `agent_query_api::indexed_dto`).
    status: String,
    price_per_call: u64,
    rate_limit_per_day: u32,
    withdrawable_revenue: u64,
    pending_count: u32,
    live_count: u32,
}

impl From<&contracts::ServiceActorData> for ServiceActorRecordDto {
    fn from(data: &contracts::ServiceActorData) -> Self {
        Self {
            owner: data.owner.to_string(),
            authorized_caller: data.authorized_caller.as_ref().map(|a| a.to_string()),
            open_access: data.open_access,
            status: if data.active { "active" } else { "inactive" }.to_owned(),
            price_per_call: data.price_per_call,
            rate_limit_per_day: data.rate_limit_per_day,
            withdrawable_revenue: data.withdrawable_revenue,
            pending_count: data.pending_count,
            live_count: data.live_count,
        }
    }
}

#[derive(serde::Serialize)]
struct CapabilityRegistryRecordDto {
    owner: String,
    verifier: Option<String>,
    // Field name (and "active"/"inactive" values) must match the HTTP
    // query API's `RegistryDto::status`, which this JSON blob is
    // deserialized directly into (see `agent_query_api::indexed_dto`).
    status: String,
    registered_at: u64,
    bond: u64,
    reputation_score: i64,
}

impl From<&contracts::CapabilityRegistryData> for CapabilityRegistryRecordDto {
    fn from(data: &contracts::CapabilityRegistryData) -> Self {
        Self {
            owner: data.owner.to_string(),
            verifier: data.verifier.as_ref().map(|a| a.to_string()),
            status: if data.active { "active" } else { "inactive" }.to_owned(),
            registered_at: data.registered_at,
            bond: data.bond,
            reputation_score: data.reputation_score,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Each `*RecordDto` here is the storage format `IndexerStore` persists
    //! (see `decode_and_store`), and the HTTP query API (`agent_query_api`)
    //! deserializes it *directly* into its own public DTO type via
    //! `indexed_dto` -- no field-by-field mapping in between. These tests
    //! exist because that coupling is invisible to the type checker (it's a
    //! JSON-shape contract between two independently-defined struct types,
    //! not a shared type): a field renamed on one side but not the other
    //! compiles cleanly and fails only by silently dropping rows out of a
    //! list response at runtime (`filter_map` swallows the decode error).
    use super::*;
    use crate::http::agent_query_api::{
        AgentAccountDto, DisputeDto, RegistryDto, ServiceActorDto, TaskDto,
    };

    fn addr(byte: u8) -> MsgAddressInt {
        MsgAddressInt::with_standart(None, 0, [byte; 32].into()).unwrap()
    }

    #[test]
    fn canonical_dns_item_code_hash_is_classified() {
        let known = KnownCodeHashes::compute().expect("known code hashes");
        let hash = UInt256::from_slice(&hex::decode(DNS_ITEM_CODE_HASH).expect("DNS hash"));
        assert_eq!(known.by_hash.get(&hash), Some(&"dns_domain"));
    }

    #[test]
    fn agent_account_record_dto_deserializes_into_the_http_agent_dto() {
        let data = contracts::AgentAccountData {
            owner: addr(1),
            controller_pubkey: [2; 32],
            deployment_id: [11; 32],
            controller_epoch: 12,
            seqno: 3,
            spend_day: 4,
            spent_today: 5,
            max_per_tx: 6,
            daily_limit: 7,
            default_task_timeout_secs: 8,
            metadata_hash: Some([9; 32]),
            service_endpoint_hash: Some([10; 32]),
        };
        let stored = serde_json::to_string(&AgentAccountRecordDto::from(&data)).unwrap();
        let dto = crate::http::agent_query_api::indexed_dto::<AgentAccountDto>(
            &stored,
            &addr(11).to_string(),
            false,
        )
        .expect("agent storage and HTTP DTO shapes must remain compatible");
        assert_eq!(dto.owner, data.owner.to_string());
        assert_eq!(dto.controller_pubkey, hex::encode(data.controller_pubkey));
        assert_eq!(dto.spent_today, 5);
        assert_eq!(dto.daily_limit, 7);
    }

    #[test]
    fn task_escrow_record_dto_deserializes_into_the_http_task_dto() {
        let data = contracts::TaskEscrowData {
            creator: addr(1),
            assigned_agent: Some(addr(2)),
            verifier: Some(addr(3)),
            budget: 100,
            deadline: 200,
            review_period: 10,
            review_deadline: 210,
            status: 0,
            result_hash: [0; 32],
            evidence_hash: [0; 32],
            settlement_policy_hash: [0; 32],
            permission_hash: [0; 32],
            dispute_hash: [0; 32],
            attestor_pubkey: None,
        };
        let json = serde_json::to_string(&TaskEscrowRecordDto::from(&data)).unwrap();
        let dto = crate::http::agent_query_api::indexed_dto::<TaskDto>(&json, "0:aa", true);
        assert!(dto.is_some(), "TaskEscrowRecordDto JSON must decode into TaskDto: {json}");
    }

    #[test]
    fn dispute_record_dto_deserializes_into_the_http_dispute_dto() {
        let data = contracts::DisputeData {
            claimant: addr(1),
            respondent: addr(2),
            reviewer: addr(3),
            status: 0,
            ruling: 0,
            split_bps: 0,
            deadline: 100,
            subject_hash: [0; 32],
            claimant_evidence_hash: [0; 32],
            respondent_evidence_hash: [0; 32],
            ruling_hash: [0; 32],
            attestor_pubkey: None,
        };
        let json = serde_json::to_string(&DisputeRecordDto::from(&data)).unwrap();
        let dto = crate::http::agent_query_api::indexed_dto::<DisputeDto>(&json, "0:aa", false);
        assert!(dto.is_some(), "DisputeRecordDto JSON must decode into DisputeDto: {json}");
    }

    #[test]
    fn service_actor_record_dto_deserializes_into_the_http_service_actor_dto() {
        let data = contracts::ServiceActorData {
            owner: addr(1),
            active: true,
            policy_version: 0,
            price_per_call: 10,
            storage_fee: 100_000_000,
            cleanup_bounty: 100_000_000,
            response_sla: 3_600,
            refund_claim_window: 3_600,
            open_access: false,
            authorized_caller: Some(addr(2)),
            rate_limit_per_day: 100,
            metadata_hash: [0; 32],
            proof_scheme_hash: [0; 32],
            attestor_pubkey: None,
            next_request_id: 0,
            pending_count: 0,
            live_count: 0,
            withdrawable_revenue: 0,
            locked_storage_fees: 0,
            pending_liability: 0,
            refundable_liability: 0,
            call_day: 0,
            calls_today: 0,
        };
        let json = serde_json::to_string(&ServiceActorRecordDto::from(&data)).unwrap();
        let dto =
            crate::http::agent_query_api::indexed_dto::<ServiceActorDto>(&json, "0:aa", false);
        assert!(
            dto.is_some(),
            "ServiceActorRecordDto JSON must decode into ServiceActorDto: {json}"
        );
    }

    #[test]
    fn capability_registry_record_dto_deserializes_into_the_http_registry_dto() {
        let data = contracts::CapabilityRegistryData {
            owner: addr(1),
            verifier: Some(addr(2)),
            active: true,
            registered_at: 100,
            bond: 10,
            reputation_score: 0,
            verification_method_hash: [0; 32],
            task_categories_hash: [0; 32],
            pricing_hash: [0; 32],
            metadata_hash: [0; 32],
        };
        let json = serde_json::to_string(&CapabilityRegistryRecordDto::from(&data)).unwrap();
        let dto = crate::http::agent_query_api::indexed_dto::<RegistryDto>(&json, "0:aa", false);
        assert!(
            dto.is_some(),
            "CapabilityRegistryRecordDto JSON must decode into RegistryDto: {json}"
        );
    }

    // ─── Reorg detection ───────────────────────────────────────────────────

    /// A [`ChainProvider`] whose `get_block_transactions_page` answers are
    /// scripted per-seqno and can be mutated mid-test, so a reorg (the same
    /// seqno later reporting a different block hash) can be simulated
    /// without a real chain. Methods the scanner never calls are stubbed.
    struct ScriptedBlocksProvider {
        // Keyed by (workchain, shard, seqno): `scan_new_blocks` scans the
        // masterchain and every other shard in the same call, so a mock
        // keyed by seqno alone would silently hand one shard's block to
        // another shard's query whenever their seqnos happened to collide.
        by_seqno: std::sync::Mutex<
            std::collections::HashMap<
                (i32, i64, u32),
                contracts::chain_provider::BlockTransactionsPage,
            >,
        >,
        /// Total `get_block_transactions_page` calls made so far.
        call_count: std::sync::Mutex<usize>,
        masterchain_info: std::sync::Mutex<Option<contracts::chain_provider::MasterchainInfo>>,
        shards: std::sync::Mutex<Option<contracts::chain_provider::ShardsInfo>>,
        shards_by_mc:
            std::sync::Mutex<std::collections::HashMap<u32, contracts::chain_provider::ShardsInfo>>,
        parents: std::sync::Mutex<std::collections::HashMap<(i32, i64, u32), Vec<BlockIdExt>>>,
    }

    impl ScriptedBlocksProvider {
        fn new() -> Self {
            Self {
                by_seqno: std::sync::Mutex::new(std::collections::HashMap::new()),
                call_count: std::sync::Mutex::new(0),
                masterchain_info: std::sync::Mutex::new(None),
                shards: std::sync::Mutex::new(None),
                shards_by_mc: std::sync::Mutex::new(std::collections::HashMap::new()),
                parents: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }

        /// Scripts a block on an explicit (workchain, shard) -- needed once
        /// a test scans more than one shard in the same call (e.g. via
        /// `scan_new_blocks`, which walks the masterchain and every entry
        /// `get_shards` reports).
        fn set_on(&self, workchain: i32, shard: i64, seqno: u32, block_hash: &str) {
            let page = contracts::chain_provider::BlockTransactionsPage {
                r#type: None,
                id: Some(chain_rpc_client::v2::data_models::BlockIdExt {
                    r#type: "tos.blockIdExt".to_owned(),
                    workchain,
                    shard,
                    seqno,
                    root_hash: hex::decode(block_hash).unwrap(),
                    file_hash: vec![0; 32],
                }),
                req_count: Some(1),
                incomplete: false,
                transactions: vec![],
            };
            self.by_seqno.lock().unwrap().insert((workchain, shard, seqno), page);
        }

        fn calls_made(&self) -> usize {
            *self.call_count.lock().unwrap()
        }

        fn set_masterchain_info(&self, seqno: u32, shard: i64) {
            *self.masterchain_info.lock().unwrap() =
                Some(contracts::chain_provider::MasterchainInfo {
                    r#type: None,
                    last: chain_rpc_client::v2::data_models::BlockIdExt {
                        r#type: "tos.blockIdExt".to_owned(),
                        workchain: -1,
                        shard,
                        seqno,
                        root_hash: vec![0; 32],
                        file_hash: vec![0; 32],
                    },
                    state_root_hash: String::new(),
                    init: None,
                });
        }

        fn set_shards(&self, entries: &[(i32, i64, u32)]) {
            let blocks = self.by_seqno.lock().unwrap();
            *self.shards.lock().unwrap() = Some(contracts::chain_provider::ShardsInfo {
                r#type: None,
                shards: entries
                    .iter()
                    .map(|&(workchain, shard, seqno)| {
                        blocks
                            .get(&(workchain, shard, seqno))
                            .and_then(|page| page.id.clone())
                            .unwrap_or_else(|| BlockIdExt {
                                r#type: "tos.blockIdExt".to_owned(),
                                workchain,
                                shard,
                                seqno,
                                root_hash: vec![0; 32],
                                file_hash: vec![0; 32],
                            })
                    })
                    .collect(),
            });
        }

        fn set_shards_at(&self, mc_seqno: u32, entries: &[(i32, i64, u32)]) {
            self.set_shards(entries);
            self.shards_by_mc
                .lock()
                .unwrap()
                .insert(mc_seqno, self.shards.lock().unwrap().clone().unwrap());
        }

        fn set_transaction_on(&self, key: (i32, i64, u32), account: &str, hash: &str) {
            self.by_seqno.lock().unwrap().get_mut(&key).unwrap().transactions.push(
                chain_rpc_client::v2::data_models::ShortTxId {
                    r#type: None,
                    account: account.to_owned(),
                    lt: 4000003,
                    hash: hash.to_owned(),
                },
            );
        }

        fn set_parents(&self, id: (i32, i64, u32), parents: Vec<(i32, i64, u32)>) {
            let blocks = self.by_seqno.lock().unwrap();
            let ids = parents
                .into_iter()
                .map(|key| blocks.get(&key).unwrap().id.clone().unwrap())
                .collect();
            self.parents.lock().unwrap().insert(id, ids);
        }
    }

    #[async_trait::async_trait]
    impl ChainProvider for ScriptedBlocksProvider {
        async fn run_get_method(
            &self,
            _address: String,
            _method: &str,
            _stack: Vec<tl_api::tos::tvm::StackEntry>,
        ) -> anyhow::Result<common::tvm_stack_parser::TvmStackParser> {
            anyhow::bail!("not exercised by the scanner tests")
        }
        async fn get_balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
            anyhow::bail!("not exercised by the scanner tests")
        }
        async fn send_boc(&self, _boc: &[u8]) -> anyhow::Result<()> {
            anyhow::bail!("not exercised by the scanner tests")
        }
        async fn get_config_param(
            &self,
            _param_id: u32,
        ) -> anyhow::Result<chain_block::ConfigParamEnum> {
            anyhow::bail!("not exercised by the scanner tests")
        }
        async fn get_address_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::AddressInfo> {
            anyhow::bail!("no scripted account state")
        }
        async fn get_extended_address_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::ExtendedAddressInfo> {
            anyhow::bail!("not exercised by the scanner tests")
        }
        async fn get_wallet_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::WalletInfo> {
            anyhow::bail!("not exercised by the scanner tests")
        }
        async fn get_masterchain_info(
            &self,
        ) -> anyhow::Result<contracts::chain_provider::MasterchainInfo> {
            self.masterchain_info
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| anyhow::anyhow!("no scripted masterchain info"))
        }
        async fn get_shards(
            &self,
            seqno: u32,
        ) -> anyhow::Result<contracts::chain_provider::ShardsInfo> {
            if let Some(shards) = self.shards_by_mc.lock().unwrap().get(&seqno) {
                return Ok(shards.clone());
            }
            self.shards.lock().unwrap().clone().ok_or_else(|| anyhow::anyhow!("no scripted shards"))
        }
        async fn get_block_parents(&self, id: &BlockIdExt) -> anyhow::Result<Vec<BlockIdExt>> {
            if let Some(parents) =
                self.parents.lock().unwrap().get(&(id.workchain, id.shard, id.seqno))
            {
                return Ok(parents.clone());
            }
            if id.seqno == 1 {
                return Ok(vec![BlockIdExt {
                    r#type: "tos.blockIdExt".to_owned(),
                    workchain: id.workchain,
                    shard: id.shard,
                    seqno: 0,
                    root_hash: vec![0; 32],
                    file_hash: vec![0; 32],
                }]);
            }
            anyhow::bail!("no proof-derived predecessor for scripted block")
        }
        async fn get_block_transactions_page(
            &self,
            workchain: i32,
            shard: i64,
            seqno: u32,
            _after_lt: Option<u64>,
            _after_hash: Option<&str>,
            _count: u32,
        ) -> anyhow::Result<contracts::chain_provider::BlockTransactionsPage> {
            *self.call_count.lock().unwrap() += 1;
            self.by_seqno.lock().unwrap().get(&(workchain, shard, seqno)).cloned().ok_or_else(
                || anyhow::anyhow!("no scripted block for ({workchain}, {shard}, {seqno})"),
            )
        }
    }

    fn known_code_hashes_for_test() -> KnownCodeHashes {
        KnownCodeHashes::compute().unwrap()
    }

    #[tokio::test]
    async fn shard_set_changes_between_ticks_do_not_error_or_lose_the_new_shard() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        let mc_shard = -9223372036854775808i64;
        let shard_a: i64 = 4611686018427387904; // an arbitrary distinct shard id
        let shard_b: i64 = -4611686018427387904; // a different one entirely

        provider.set_on(-1, mc_shard, 1, &"aa".repeat(32));
        provider.set_masterchain_info(1, mc_shard);
        provider.set_on(0, shard_a, 1, &"bb".repeat(32));
        provider.set_shards(&[(0, shard_a, 1)]);

        let store = IndexerStore::open_in_memory().unwrap();
        let known = known_code_hashes_for_test();
        let dyn_provider: Arc<dyn ChainProvider> = provider.clone();

        scan_new_blocks(
            &dyn_provider,
            &store,
            &known,
            &ProbeBudget::new(),
            &ScanLimits::production(),
        )
        .await
        .unwrap();
        assert_eq!(store.checkpoint(&format!("0:{shard_a}")).unwrap(), 1);
        assert_eq!(store.checkpoint("-1:-9223372036854775808").unwrap(), 1);

        // Simulate a shard-set change (e.g. a split/merge): shard_a is
        // gone, shard_b appears instead (starting from its own seqno 1,
        // like a genuinely new shard), and the masterchain advances.
        provider.set_on(-1, mc_shard, 2, &"cc".repeat(32));
        provider.set_masterchain_info(2, mc_shard);
        provider.set_on(0, shard_b, 1, &"dd".repeat(32));
        provider.set_shards(&[(0, shard_b, 1)]);

        scan_new_blocks(
            &dyn_provider,
            &store,
            &known,
            &ProbeBudget::new(),
            &ScanLimits::production(),
        )
        .await
        .unwrap();

        // The new shard is scanned from its own reported head with no
        // prior checkpoint -- it starts fresh, exactly as a genuinely new
        // shard should.
        assert_eq!(store.checkpoint(&format!("0:{shard_b}")).unwrap(), 1);
        // The retired shard's checkpoint is simply never advanced again;
        // it is not an error for `get_shards` to stop reporting it.
        assert_eq!(store.checkpoint(&format!("0:{shard_a}")).unwrap(), 1);
        // The masterchain itself keeps advancing normally throughout.
        assert_eq!(store.checkpoint("-1:-9223372036854775808").unwrap(), 2);
    }

    #[tokio::test]
    async fn newly_reported_shard_is_indexed_from_its_exact_parent() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        let mc_shard = i64::MIN;
        let child_shard = 4_611_686_018_427_387_904i64;

        provider.set_on(-1, mc_shard, 1, &"aa".repeat(32));
        provider.set_on(0, child_shard, 1, &"bb".repeat(32));
        provider.set_masterchain_info(1, mc_shard);
        provider.set_shards(&[(0, child_shard, 1)]);

        let store = IndexerStore::open_in_memory().unwrap();
        let known = known_code_hashes_for_test();
        let dyn_provider: Arc<dyn ChainProvider> = provider.clone();
        scan_new_blocks(
            &dyn_provider,
            &store,
            &known,
            &ProbeBudget::new(),
            &ScanLimits::production(),
        )
        .await
        .unwrap();

        assert_eq!(store.checkpoint(&format!("0:{child_shard}")).unwrap(), 1);
        assert!(store.explorer_block_root(0, child_shard, 1).unwrap().is_some());
        assert_eq!(
            provider.calls_made(),
            4,
            "two exact-identity lookups of the masterchain block (open and pre-publish), \
             then one transaction page each for it and its child head"
        );
    }

    #[tokio::test]
    async fn masterchain_head_jump_indexes_intermediate_deployment_block() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        let shard = i64::MIN;
        provider.set_on(-1, shard, 1, &"a1".repeat(32));
        provider.set_on(-1, shard, 2, &"a2".repeat(32));
        for seqno in 1..=5 {
            provider.set_on(0, shard, seqno, &format!("{seqno:064x}"));
            if seqno > 1 {
                provider.set_parents((0, shard, seqno), vec![(0, shard, seqno - 1)]);
            }
        }
        let deployment = "de".repeat(32);
        provider.set_transaction_on((0, shard, 4), &"ab".repeat(32), &deployment);
        provider.set_shards_at(1, &[(0, shard, 2)]);
        provider.set_shards_at(2, &[(0, shard, 5)]);
        provider.set_masterchain_info(2, shard);
        let store = IndexerStore::open_in_memory().unwrap();
        let known = known_code_hashes_for_test();
        let dyn_provider: Arc<dyn ChainProvider> = provider;
        scan_new_blocks(
            &dyn_provider,
            &store,
            &known,
            &ProbeBudget::new(),
            &ScanLimits::production(),
        )
        .await
        .unwrap();
        assert_eq!(store.checkpoint(&format!("0:{shard}")).unwrap(), 5);
        assert!(store.explorer_block_root(0, shard, 3).unwrap().is_some());
        assert!(store.explorer_block_root(0, shard, 4).unwrap().is_some());
        assert_eq!(store.explorer_transaction(&deployment).unwrap().unwrap().seqno, 4);
    }

    #[tokio::test]
    async fn shard_ancestry_follows_split_and_both_merge_parents() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        let root = i64::MIN;
        let left = 4_611_686_018_427_387_904i64;
        let right = -4_611_686_018_427_387_904i64;
        provider.set_on(-1, root, 1, &"a1".repeat(32));
        for (shard, seqno, tag) in
            [(root, 1, "11"), (root, 2, "22"), (left, 3, "33"), (right, 3, "44"), (root, 4, "55")]
        {
            provider.set_on(0, shard, seqno, &tag.repeat(32));
        }
        provider.set_parents((0, root, 2), vec![(0, root, 1)]);
        provider.set_parents((0, left, 3), vec![(0, root, 2)]);
        provider.set_parents((0, right, 3), vec![(0, root, 2)]);
        provider.set_parents((0, root, 4), vec![(0, left, 3), (0, right, 3)]);
        provider.set_masterchain_info(1, root);
        provider.set_shards(&[(0, root, 4)]);
        let store = IndexerStore::open_in_memory().unwrap();
        let dyn_provider: Arc<dyn ChainProvider> = provider;
        scan_new_blocks(
            &dyn_provider,
            &store,
            &known_code_hashes_for_test(),
            &ProbeBudget::new(),
            &ScanLimits::production(),
        )
        .await
        .unwrap();
        for (shard, seqno) in [(root, 1), (root, 2), (left, 3), (right, 3), (root, 4)] {
            assert!(
                store.explorer_block_root(0, shard, seqno).unwrap().is_some(),
                "missing exact ancestor {shard}:{seqno}"
            );
        }
    }

    #[tokio::test]
    async fn changed_shard_head_at_a_published_coordinate_fails_closed() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        let shard = i64::MIN;
        provider.set_on(-1, shard, 1, &"a1".repeat(32));
        provider.set_on(0, shard, 1, &"11".repeat(32));
        provider.set_on(0, shard, 2, &"22".repeat(32));
        provider.set_parents((0, shard, 2), vec![(0, shard, 1)]);
        provider.set_masterchain_info(1, shard);
        provider.set_shards_at(1, &[(0, shard, 2)]);
        let store = IndexerStore::open_in_memory().unwrap();
        let dyn_provider: Arc<dyn ChainProvider> = provider.clone();
        scan_new_blocks(
            &dyn_provider,
            &store,
            &known_code_hashes_for_test(),
            &ProbeBudget::new(),
            &ScanLimits::production(),
        )
        .await
        .unwrap();
        provider.set_on(-1, shard, 2, &"a2".repeat(32));
        provider.set_on(0, shard, 2, &"99".repeat(32));
        provider.set_shards_at(2, &[(0, shard, 2)]);
        provider.set_masterchain_info(2, shard);
        let err = scan_new_blocks(
            &dyn_provider,
            &store,
            &known_code_hashes_for_test(),
            &ProbeBudget::new(),
            &ScanLimits::production(),
        )
        .await
        .unwrap_err();
        // Masterchain block 1 is unchanged, yet block 2 claims a different
        // block at the coordinate block 1 published. That is conflicting
        // evidence, not progress: nothing of height 2 may be published.
        assert!(err.to_string().contains("published frontier holds"), "{err}");
        assert_eq!(store.published_mc_seqno().unwrap(), 1);
        assert_eq!(store.explorer_block_root(0, shard, 2).unwrap(), Some("22".repeat(32)));
        assert_eq!(store.canonical_shard_frontier().unwrap()[0].root_hash, "22".repeat(32));
        assert!(store.masterchain_block(2).unwrap().is_none());
    }

    /// A remote tip far ahead of what is published, a small retention
    /// window, and a scanner that publishes a bounded number of heights per
    /// tick. Retention must be measured from the published watermark: the
    /// freshly published window stays, progress is monotone, and the scanner
    /// catches up.
    #[tokio::test]
    async fn retention_is_measured_from_the_published_watermark_not_the_remote_tip() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        let mc_shard = i64::MIN;
        let tip = 600u32;
        for seqno in 1..=tip {
            provider.set_on(-1, mc_shard, seqno, &format!("{seqno:064x}"));
        }
        provider.set_masterchain_info(tip, mc_shard);
        provider.set_shards(&[]);
        let store = IndexerStore::open_in_memory().unwrap();
        let known = known_code_hashes_for_test();
        let dyn_provider: Arc<dyn ChainProvider> = provider.clone();
        let retention = 50u32;
        let limits = ScanLimits { max_batches: 200, ..ScanLimits::production() };
        let mut prune = PruneState::new(1);
        let mut previous = 0u32;
        for _ in 0..4 {
            let outcome = tick(
                &dyn_provider,
                &store,
                &known,
                &ProbeBudget::new(),
                &limits,
                retention,
                &mut prune,
            )
            .await
            .unwrap();
            assert_eq!(outcome.remote_tip, tip);
            assert!(outcome.published_mc_seqno >= previous, "published watermark regressed");
            previous = outcome.published_mc_seqno;
            let keep_from = previous.saturating_sub(retention);
            for seqno in keep_from.max(1)..=previous {
                assert!(
                    store.masterchain_block(seqno).unwrap().is_some(),
                    "published height {seqno} inside the retention window was pruned \
                     (published {previous}, remote tip {tip})"
                );
            }
            if keep_from > 1 {
                assert!(store.explorer_block_root(-1, mc_shard, keep_from - 1).unwrap().is_none());
            }
        }
        assert_eq!(previous, tip, "the scanner must catch up to the remote tip");
    }

    #[tokio::test]
    async fn shard_zerostate_descriptors_are_not_fetched_as_blocks() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        let mc_shard = i64::MIN;
        provider.set_on(-1, mc_shard, 1, &"aa".repeat(32));
        provider.set_masterchain_info(1, mc_shard);
        provider.set_shards(&[(0, i64::MIN, 0)]);

        let store = IndexerStore::open_in_memory().unwrap();
        let known = known_code_hashes_for_test();
        let dyn_provider: Arc<dyn ChainProvider> = provider.clone();
        scan_new_blocks(
            &dyn_provider,
            &store,
            &known,
            &ProbeBudget::new(),
            &ScanLimits::production(),
        )
        .await
        .unwrap();

        assert_eq!(
            provider.calls_made(),
            3,
            "two identity lookups and one page of the masterchain block; the zerostate \
             descriptor is never fetched as a block"
        );
        assert_eq!(store.checkpoint(&format!("0:{}", i64::MIN)).unwrap(), 0);
        assert_eq!(store.checkpoint(&format!("-1:{mc_shard}")).unwrap(), 1);
    }

    // ─── Service Actor request-lifecycle classification (real sandbox contract) ───
    //
    // These drive `refresh_service_request_lifecycle` (via `decode_and_store`)
    // against a genuine, compiled Service Actor contract executing in
    // `tos_sandbox`, not a hand-crafted stack fixture -- the classification
    // logic only matters if it agrees with what the real contract's
    // get-methods actually return once a request has left `pending`/
    // `refundable`. `decode_and_store` takes `now` as an explicit parameter
    // (threaded through from `time_format::now()` in production) precisely so
    // these tests can supply a `now` that is consistent with the sandbox's
    // own virtual clock (`Blockchain::set_now`), instead of racing real wall
    // time against a deadline computed from the sandbox's fixed default
    // clock (1.7bn, i.e. already in the past relative to real time).

    use common::tvm_stack_parser::TvmStackParser;
    use contracts::ServiceActorInit;
    use std::sync::Mutex as StdMutex;
    use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

    struct SandboxChainProvider {
        bc: StdMutex<Blockchain>,
    }

    #[async_trait::async_trait]
    impl ChainProvider for SandboxChainProvider {
        async fn run_get_method(
            &self,
            address: String,
            method: &str,
            stack: Vec<tl_api::tos::tvm::StackEntry>,
        ) -> anyhow::Result<TvmStackParser> {
            let addr = MsgAddressInt::from_str(&address)?;
            let vm_stack = stack
                .into_iter()
                .map(|entry| match entry {
                    tl_api::tos::tvm::StackEntry::Tvm_StackEntryNumber(n) => {
                        let tl_api::tos::tvm::Number::Tvm_NumberDecimal(v) = n.number;
                        v.number
                            .parse::<u64>()
                            .map(tos_vm::stack::StackItem::int)
                            .map_err(Into::into)
                    }
                    _ => anyhow::bail!("unsupported sandbox input stack entry"),
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let result = {
                let bc = self.bc.lock().expect("sandbox lock poisoned");
                bc.run_get_method(&addr, method, vm_stack)
                    .map_err(|e| anyhow::anyhow!("get-method {method} error: {e}"))?
            };
            if result.exit_code != 0 {
                anyhow::bail!("get-method {method} error: exit_code={}", result.exit_code);
            }
            let entries = result
                .stack
                .iter()
                .map(lifecycle_stack_item_to_entry)
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(TvmStackParser::new(entries))
        }

        async fn get_balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
            anyhow::bail!("not supported by SandboxChainProvider")
        }

        async fn send_boc(&self, _boc: &[u8]) -> anyhow::Result<()> {
            anyhow::bail!("not supported by SandboxChainProvider")
        }

        async fn get_config_param(
            &self,
            _param_id: u32,
        ) -> anyhow::Result<chain_block::ConfigParamEnum> {
            anyhow::bail!("not supported by SandboxChainProvider")
        }

        async fn get_address_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::AddressInfo> {
            anyhow::bail!("not supported by SandboxChainProvider")
        }

        async fn get_extended_address_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::ExtendedAddressInfo> {
            anyhow::bail!("not supported by SandboxChainProvider")
        }

        async fn get_wallet_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::WalletInfo> {
            anyhow::bail!("not supported by SandboxChainProvider")
        }

        async fn get_masterchain_info(
            &self,
        ) -> anyhow::Result<contracts::chain_provider::MasterchainInfo> {
            anyhow::bail!("not supported by SandboxChainProvider")
        }

        async fn get_shards(
            &self,
            _seqno: u32,
        ) -> anyhow::Result<contracts::chain_provider::ShardsInfo> {
            anyhow::bail!("not supported by SandboxChainProvider")
        }

        async fn get_block_transactions_page(
            &self,
            _workchain: i32,
            _shard: i64,
            _seqno: u32,
            _after_lt: Option<u64>,
            _after_hash: Option<&str>,
            _count: u32,
        ) -> anyhow::Result<contracts::chain_provider::BlockTransactionsPage> {
            anyhow::bail!("not supported by SandboxChainProvider")
        }
    }

    fn lifecycle_stack_item_to_entry(
        item: &tos_vm::stack::StackItem,
    ) -> anyhow::Result<tl_api::tos::tvm::StackEntry> {
        use tl_api::tos::tvm::{
            Number, StackEntry,
            numberdecimal::NumberDecimal,
            slice,
            stackentry::{StackEntryNumber, StackEntrySlice},
        };
        if matches!(item, tos_vm::stack::StackItem::None) {
            // The "not found" branch of get_request/get_refund returns
            // null() for the caller slice; its value is never read
            // (decode_request/decode_refund check the `found` flag first),
            // but TvmStackParser still needs *some* entry here.
            return Ok(StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
                slice: slice::Slice { bytes: vec![] },
            }));
        }
        if let Ok(int) = item.as_integer() {
            return Ok(StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
                number: Number::Tvm_NumberDecimal(NumberDecimal { number: int.to_string() }),
            }));
        }
        if let Ok(slice) = item.as_slice() {
            let bytes = slice.clone().get_bytestring(0);
            return Ok(StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
                slice: slice::Slice { bytes },
            }));
        }
        if let Ok(cell) = item.as_cell() {
            let bytes = chain_block::SliceData::load_cell(cell.clone())?.get_bytestring(0);
            return Ok(StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
                slice: slice::Slice { bytes },
            }));
        }
        anyhow::bail!("unsupported sandbox stack item for lifecycle tests")
    }

    struct LifecycleFixture {
        provider: Arc<SandboxChainProvider>,
        provider_dyn: Arc<dyn ChainProvider>,
        owner: Treasury,
        caller: Treasury,
        service: MsgAddressInt,
        base_now: u64,
        response_sla: u32,
        refund_claim_window: u32,
    }

    impl LifecycleFixture {
        fn new() -> Self {
            let base_now = time_format::now();
            let mut bc = Blockchain::new().expect("blockchain");
            bc.set_workchain(-1);
            bc.set_now(base_now as u32);
            let owner = bc.treasury("lifecycle-owner", 100_000_000_000).expect("owner");
            let caller = bc.treasury("lifecycle-caller", 100_000_000_000).expect("caller");
            let response_sla = 3_600;
            let refund_claim_window = 3_600;
            let init = ServiceActorInit {
                owner: owner.address().clone(),
                authorized_caller: None,
                open_access: true,
                price_per_call: 100_000_000,
                storage_fee: 200_000_000,
                cleanup_bounty: 100_000_000,
                rate_limit_per_day: 0,
                response_sla,
                refund_claim_window,
                metadata_hash: [0x11; 32],
                proof_scheme_hash: [0x22; 32],
                attestor_pubkey: None,
            };
            let service = ServiceActorContract::calculate_address(-1, &init).expect("address");
            let deploy = MessageBuilder::internal(owner.address(), &service, 20_000_000_000)
                .bounce(false)
                .state_init(ServiceActorContract::build_state_init(&init).expect("state init"))
                .body(Cell::default())
                .build();
            bc.send_message(deploy).expect("deploy").expect_success();
            let provider = Arc::new(SandboxChainProvider { bc: StdMutex::new(bc) });
            Self {
                provider_dyn: provider.clone(),
                provider,
                owner,
                caller,
                service,
                base_now,
                response_sla,
                refund_claim_window,
            }
        }

        fn send(&self, from: &MsgAddressInt, body: chain_block::Cell) {
            let msg = MessageBuilder::internal(from, &self.service, 500_000_000).body(body).build();
            self.provider.bc.lock().unwrap().send_message(msg).unwrap().expect_success();
        }

        fn set_now(&self, t: u64) {
            self.provider.bc.lock().unwrap().set_now(t as u32);
        }

        async fn refresh(&self, store: &IndexerStore, now: u64) {
            decode_and_store(
                &self.provider_dyn,
                store,
                &self.service.to_string(),
                "service_actor",
                1,
                now,
                &ProbeBudget::new(),
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn indexer_classifies_a_responded_request_after_respond() {
        let f = LifecycleFixture::new();
        let store = IndexerStore::open_in_memory().unwrap();
        let caller = f.caller.address().clone();

        f.send(&caller, ServiceActorContract::call(1, [0xAA; 32]).unwrap());
        f.refresh(&store, f.base_now).await;
        let record = store.service_request(&f.service.to_string(), 0).unwrap().unwrap();
        assert_eq!(record.status, "pending");

        let owner = f.owner.address().clone();
        f.send(&owner, ServiceActorContract::respond(2, 0, [0xBB; 32]).unwrap());
        f.refresh(&store, f.base_now).await;
        let record = store.service_request(&f.service.to_string(), 0).unwrap().unwrap();
        assert_eq!(
            record.status, "responded",
            "a request answered before its deadline must be classified responded, not swept"
        );
    }

    #[tokio::test]
    async fn indexer_classifies_a_refunded_request_after_expire_and_claim() {
        let f = LifecycleFixture::new();
        let store = IndexerStore::open_in_memory().unwrap();
        let caller = f.caller.address().clone();

        f.send(&caller, ServiceActorContract::call(1, [0xCC; 32]).unwrap());
        f.refresh(&store, f.base_now).await;

        let past_response_deadline = f.base_now + f.response_sla as u64 + 1;
        f.set_now(past_response_deadline);
        f.send(&caller, ServiceActorContract::expire(2, 0).unwrap());
        f.refresh(&store, past_response_deadline).await;
        let record = store.service_request(&f.service.to_string(), 0).unwrap().unwrap();
        assert_eq!(record.status, "refundable");

        f.send(&caller, ServiceActorContract::claim_refund(3, 0, &caller).unwrap());
        f.refresh(&store, past_response_deadline).await;
        let record = store.service_request(&f.service.to_string(), 0).unwrap().unwrap();
        assert_eq!(
            record.status, "refunded",
            "a refund claimed before its claim window closes must be classified refunded, not swept"
        );
    }

    #[tokio::test]
    async fn indexer_reports_resolved_unknown_when_it_misses_the_refundable_transition() {
        // `run_get_method` always answers with *current* chain state, so an
        // indexer that is merely running one tick behind (not necessarily
        // down for a long outage) can miss the entire pending->refundable
        // window if expire and claim_refund land close together in real
        // time. The last stored status would then still be "pending" even
        // though the request was genuinely refunded, not responded to.
        let f = LifecycleFixture::new();
        let store = IndexerStore::open_in_memory().unwrap();
        let caller = f.caller.address().clone();

        f.send(&caller, ServiceActorContract::call(1, [0x12; 32]).unwrap());
        f.refresh(&store, f.base_now).await;
        let record = store.service_request(&f.service.to_string(), 0).unwrap().unwrap();
        assert_eq!(record.status, "pending");

        let past_response_deadline = f.base_now + f.response_sla as u64 + 1;
        f.set_now(past_response_deadline);
        f.send(&caller, ServiceActorContract::expire(2, 0).unwrap());
        f.send(&caller, ServiceActorContract::claim_refund(3, 0, &caller).unwrap());
        // No refresh between expire and claim_refund -- the indexer's stored
        // record for this id is still "pending" from the very first refresh.
        f.refresh(&store, past_response_deadline).await;
        let record = store.service_request(&f.service.to_string(), 0).unwrap().unwrap();
        assert_eq!(
            record.status, "resolved_unknown",
            "a genuinely refunded request must not be mislabeled responded just because the \
             indexer's only prior observation of it predates response_deadline and never saw \
             the intermediate refundable state"
        );
    }

    #[tokio::test]
    async fn indexer_classifies_a_swept_request() {
        let f = LifecycleFixture::new();
        let store = IndexerStore::open_in_memory().unwrap();
        let caller = f.caller.address().clone();

        f.send(&caller, ServiceActorContract::call(1, [0xDD; 32]).unwrap());
        f.refresh(&store, f.base_now).await;

        let past_claim_deadline =
            f.base_now + f.response_sla as u64 + f.refund_claim_window as u64 + 1;
        f.set_now(past_claim_deadline);
        // The indexer must observe the entry *still live at or past the
        // deadline* before the sweep -- only then is a subsequent
        // disappearance provably a sweep (see the classification comment
        // above `refresh_service_request_lifecycle`'s match arms). Without
        // this intermediate refresh, the indexer's last observation would
        // predate the deadline and the correct label would be
        // `resolved_unknown`, not `swept` -- exercised separately below.
        f.refresh(&store, past_claim_deadline).await;
        let record = store.service_request(&f.service.to_string(), 0).unwrap().unwrap();
        assert_eq!(record.status, "pending", "still live and unswept just past the deadline");

        // A third party (not the caller, not the owner) sweeps -- permissionless.
        let sweeper = {
            let mut bc = f.provider.bc.lock().unwrap();
            bc.treasury("lifecycle-sweeper", 10_000_000_000).unwrap()
        };
        f.send(
            &sweeper.address().clone(),
            ServiceActorContract::sweep_expired_request(4, 0).unwrap(),
        );
        f.refresh(&store, past_claim_deadline).await;
        let record = store.service_request(&f.service.to_string(), 0).unwrap().unwrap();
        assert_eq!(
            record.status, "swept",
            "a request only reclaimed via sweep_expired_request after its claim window closed must be classified swept"
        );
    }

    #[tokio::test]
    async fn indexer_reports_resolved_unknown_when_it_missed_the_deadline_crossing() {
        // If the indexer's last observation of a still-pending/refundable
        // entry predates the deadline, and the *next* observation is already
        // past the deadline with the entry gone, a periodic snapshot cannot
        // tell whether it resolved (respond/claim_refund, in the gap before
        // the deadline) or was swept (in the gap after it). It must not guess
        // either way.
        let f = LifecycleFixture::new();
        let store = IndexerStore::open_in_memory().unwrap();
        let caller = f.caller.address().clone();

        f.send(&caller, ServiceActorContract::call(1, [0xEE; 32]).unwrap());
        f.refresh(&store, f.base_now).await;
        let record = store.service_request(&f.service.to_string(), 0).unwrap().unwrap();
        assert_eq!(record.status, "pending");

        // Actually respond (a real, legitimate resolution before the
        // deadline) -- but the indexer's *next* observation only happens
        // after the deadline has passed, simulating a missed tick/outage.
        let owner = f.owner.address().clone();
        f.send(&owner, ServiceActorContract::respond(2, 0, [0xFF; 32]).unwrap());
        let past_claim_deadline =
            f.base_now + f.response_sla as u64 + f.refund_claim_window as u64 + 1;
        f.refresh(&store, past_claim_deadline).await;
        let record = store.service_request(&f.service.to_string(), 0).unwrap().unwrap();
        assert_eq!(
            record.status, "resolved_unknown",
            "a genuinely responded request must not be mislabeled swept just because the only \
             observation after it disappeared happened past the deadline"
        );
    }

    // ─── Hostile contract state must not translate into unbounded work ─────

    /// A [`ChainProvider`] whose `run_get_method` answers "not found" for
    /// every `get_request`/`get_refund` probe, counting the calls. The
    /// contract state itself (including `next_request_id`) is supplied
    /// directly to `refresh_service_request_lifecycle`, so this is enough to
    /// prove the refresh bounds its own work when the contract's counter is
    /// arbitrary.
    struct NotFoundLifecycleProvider {
        get_method_calls: StdMutex<usize>,
    }

    #[async_trait::async_trait]
    impl ChainProvider for NotFoundLifecycleProvider {
        async fn run_get_method(
            &self,
            _address: String,
            method: &str,
            _stack: Vec<tl_api::tos::tvm::StackEntry>,
        ) -> anyhow::Result<TvmStackParser> {
            anyhow::ensure!(
                matches!(method, "get_request" | "get_refund"),
                "unexpected get-method {method}"
            );
            *self.get_method_calls.lock().unwrap() += 1;
            use tl_api::tos::tvm::{
                Number, StackEntry, numberdecimal::NumberDecimal, stackentry::StackEntryNumber,
            };
            // `found = 0`: decode_request/decode_refund both stop at the flag.
            Ok(TvmStackParser::new(vec![StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
                number: Number::Tvm_NumberDecimal(NumberDecimal { number: "0".to_owned() }),
            })]))
        }
        async fn get_balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
            anyhow::bail!("not exercised")
        }
        async fn send_boc(&self, _boc: &[u8]) -> anyhow::Result<()> {
            anyhow::bail!("not exercised")
        }
        async fn get_config_param(
            &self,
            _param_id: u32,
        ) -> anyhow::Result<chain_block::ConfigParamEnum> {
            anyhow::bail!("not exercised")
        }
        async fn get_address_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::AddressInfo> {
            anyhow::bail!("not exercised")
        }
        async fn get_extended_address_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::ExtendedAddressInfo> {
            anyhow::bail!("not exercised")
        }
        async fn get_wallet_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::WalletInfo> {
            anyhow::bail!("not exercised")
        }
        async fn get_masterchain_info(
            &self,
        ) -> anyhow::Result<contracts::chain_provider::MasterchainInfo> {
            anyhow::bail!("not exercised")
        }
        async fn get_shards(
            &self,
            _seqno: u32,
        ) -> anyhow::Result<contracts::chain_provider::ShardsInfo> {
            anyhow::bail!("not exercised")
        }
        async fn get_block_transactions_page(
            &self,
            _workchain: i32,
            _shard: i64,
            _seqno: u32,
            _after_lt: Option<u64>,
            _after_hash: Option<&str>,
            _count: u32,
        ) -> anyhow::Result<contracts::chain_provider::BlockTransactionsPage> {
            anyhow::bail!("not exercised")
        }
    }

    fn service_actor_data_with_next_request_id(
        next_request_id: u64,
    ) -> contracts::ServiceActorData {
        contracts::ServiceActorData {
            owner: addr(1),
            active: true,
            policy_version: 0,
            price_per_call: 10,
            storage_fee: 100_000_000,
            cleanup_bounty: 100_000_000,
            response_sla: 3_600,
            refund_claim_window: 3_600,
            open_access: true,
            authorized_caller: None,
            rate_limit_per_day: 0,
            metadata_hash: [0; 32],
            proof_scheme_hash: [0; 32],
            attestor_pubkey: None,
            next_request_id,
            pending_count: 0,
            live_count: 0,
            withdrawable_revenue: 0,
            locked_storage_fees: 0,
            pending_liability: 0,
            refundable_liability: 0,
            call_day: 0,
            calls_today: 0,
        }
    }

    #[tokio::test]
    async fn a_hostile_next_request_id_only_materialises_a_bounded_batch_per_visit() {
        let provider = Arc::new(NotFoundLifecycleProvider { get_method_calls: StdMutex::new(0) });
        let provider_dyn: Arc<dyn ChainProvider> = provider.clone();
        let store = IndexerStore::open_in_memory().unwrap();
        // The counter is contract-controlled state: a deployer can report any
        // value, so the largest possible one must still yield a bounded tick.
        let data = service_actor_data_with_next_request_id(u64::MAX);

        let probe_budget = ProbeBudget::new();
        refresh_service_request_lifecycle(
            &provider_dyn,
            &store,
            "-1:service",
            &data,
            1_000,
            &probe_budget,
        )
        .await
        .unwrap();

        let cap = MAX_SERVICE_REQUEST_IDS_PER_TICK as usize;
        assert_eq!(
            *provider.get_method_calls.lock().unwrap(),
            cap * 2,
            "each id in the capped batch is probed once with get_request and once with \
             get_refund; nothing beyond the cap may be touched"
        );
        let (max_indexed, stored, active) =
            store.service_requests_for_refresh("-1:service").unwrap();
        assert_eq!(
            max_indexed,
            Some(MAX_SERVICE_REQUEST_IDS_PER_TICK - 1),
            "the scan high-water mark advances to the end of the capped batch"
        );
        assert_eq!(
            stored, 0,
            "ids probed and found absent must not become durable rows: a fabricated \
             counter would otherwise grow the table by one batch per visit forever"
        );
        assert!(active.is_empty());

        // A later visit resumes from the persisted high-water mark: progress
        // stays monotonic across capped batches, still without storing rows.
        refresh_service_request_lifecycle(
            &provider_dyn,
            &store,
            "-1:service",
            &data,
            1_001,
            &probe_budget,
        )
        .await
        .unwrap();
        let (max_indexed, stored, _) = store.service_requests_for_refresh("-1:service").unwrap();
        assert_eq!(max_indexed, Some(2 * MAX_SERVICE_REQUEST_IDS_PER_TICK - 1));
        assert_eq!(stored, 0);
        assert_eq!(*provider.get_method_calls.lock().unwrap(), cap * 4);

        // Once the global probe bucket is drained, further visits do no
        // chain reads at all until the next refill window.
        let _ = probe_budget.take(u64::MAX, 1_001);
        refresh_service_request_lifecycle(
            &provider_dyn,
            &store,
            "-1:service",
            &data,
            1_002,
            &probe_budget,
        )
        .await
        .unwrap();
        assert_eq!(*provider.get_method_calls.lock().unwrap(), cap * 4);
    }
}

#[cfg(test)]
#[path = "canonical_scan_tests.rs"]
mod canonical_scan_tests;

#[cfg(test)]
mod deposit_capacity_tests {
    use super::{deposit_depth_bound, nominator_dictionary_depth};

    /// pool.fc: max(5, binary_log_ceil(count) * 2), binary_log_ceil = UBITSIZE.
    #[test]
    fn bound_matches_the_contract_expression() {
        for (count, expected) in [(1, 5), (2, 5), (3, 5), (4, 6), (8, 8), (16, 10), (40, 12)] {
            assert_eq!(deposit_depth_bound(count), expected, "count {count}");
        }
    }

    #[test]
    fn an_empty_or_single_entry_dictionary_has_no_forks() {
        assert_eq!(nominator_dictionary_depth(&[]), 0);
        assert_eq!(nominator_dictionary_depth(&[[0xAB; 32]]), 0);
    }

    #[test]
    fn a_shared_prefix_costs_no_depth() {
        // Two keys differing only in the last bit fork once, however long the
        // prefix they share.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 0b0;
        b[31] = 0b1;
        assert_eq!(nominator_dictionary_depth(&[a, b]), 1);
    }

    #[test]
    fn keys_that_branch_early_fork_once_per_pair() {
        // Four keys splitting on the top two bits: two levels.
        let keys: Vec<[u8; 32]> = (0..4u8)
            .map(|i| {
                let mut key = [0u8; 32];
                key[0] = i << 6;
                key
            })
            .collect();
        assert_eq!(nominator_dictionary_depth(&keys), 2);
    }

    #[test]
    fn a_chain_of_prefixes_deepens_linearly() {
        // Each key extends the previous one's prefix by a bit, so every key
        // adds a level rather than sharing one. This is the shape the guard
        // exists to refuse.
        let keys: Vec<[u8; 32]> = (0..12usize)
            .map(|i| {
                let mut key = [0u8; 32];
                for bit in 0..i {
                    key[bit / 8] |= 1 << (7 - (bit % 8));
                }
                key
            })
            .collect();
        let depth = nominator_dictionary_depth(&keys);
        assert_eq!(depth, keys.len() as i32 - 1, "one fork level per key");
        // Depth grows linearly while the bound grows logarithmically, so they
        // cross -- which is what makes the guard reachable at all.
        assert!(
            depth >= deposit_depth_bound(keys.len() as u32 + 1),
            "depth {depth} should have passed bound {}",
            deposit_depth_bound(keys.len() as u32 + 1)
        );
    }
}
