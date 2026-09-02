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
//! this block"). This task walks every shard block by block from its own
//! checkpoint -- the masterchain itself (some actors deploy there directly)
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
use common::{app_config::AppConfig, task_cancellation::CancellationCtx, time_format};
use contracts::contract_codes::NOMINATOR_POOL_CODE;
use contracts::{
    AgentAccountContract, CapabilityRegistryContract, ChainProvider, DisputeContract,
    MasterchainCheckpoint, NominatorPoolWrapper, NominatorPoolWrapperImpl, ServiceActorContract,
    TaskEscrowContract, contract_provider_from,
};

const DNS_ITEM_CODE_HASH: &str = "e469483aa8a8e5018f46cdd9c374b60153025847a6d4997692cfdd9b15be1d78";
const DNS_COLLECTION_ADDRESS: &str =
    "0:cec242160fa821bc402586947649f25d4a0c1b02808d1dce93c893e98061bb8a";
const DNS_ITEM_CODE_DEPTH: u16 = 11;

use crate::indexer::store::{
    DnsDomainHistoryRecord, ExplorerBlockRecord, ExplorerTransactionRecord, IndexedRecord,
    IndexerStore, ServiceRequestRecord,
};
use crate::runtime_config::RuntimeConfig;

/// Upper bound on how many masterchain blocks a single tick will scan, so a
/// long-idle indexer catching up on history doesn't stall the tick loop
/// indefinitely -- the next tick picks up where this one left off.
const MAX_BLOCKS_PER_TICK: u32 = 200;
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

/// Pure range computation for the new-id scan, so the bounds are unit
/// testable: resumes after the stored high-water mark, takes at most one
/// per-tick batch, and never extends past the per-service row budget.
fn new_service_request_id_range(
    max_indexed: Option<u64>,
    stored_rows: u64,
    claimed_next_request_id: u64,
) -> std::ops::Range<u64> {
    let first_new = max_indexed.map_or(0, |id| id.saturating_add(1));
    let remaining_budget = MAX_TRACKED_REQUESTS_PER_SERVICE.saturating_sub(stored_rows);
    let batch = MAX_SERVICE_REQUEST_IDS_PER_TICK.min(remaining_budget);
    let new_end = claimed_next_request_id.min(first_new.saturating_add(batch));
    first_new..new_end
}
/// How far back to rewind and rescan when a reorg is detected at the
/// checkpoint boundary. Reorgs are a real, documented hazard on this chain
/// (see `https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-message-policy.md`'s replay-across-reorgs note), not a
/// theoretical one; this bounds how much already-indexed data can go stale
/// from a single detected divergence rather than only ever checking the one
/// block at the checkpoint itself.
#[cfg(test)]
const REORG_REWIND_BLOCKS: u32 = 5;

pub async fn run(
    cancellation_ctx: CancellationCtx,
    app_config: Arc<AppConfig>,
    runtime_cfg: Arc<dyn RuntimeConfig>,
    indexer_store: Arc<IndexerStore>,
) -> anyhow::Result<()> {
    let chain_provider = runtime_cfg.chain_provider();
    let known = KnownCodeHashes::compute()?;
    let mut interval = tokio::time::interval(Duration::from_secs(app_config.tick_interval));
    let mut cancel = cancellation_ctx.subscribe();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = scan_new_blocks(&chain_provider, &indexer_store, &known).await {
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

async fn scan_new_blocks(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    known: &KnownCodeHashes,
) -> anyhow::Result<()> {
    let mc_info = chain_provider.get_masterchain_info().await?;
    let mc_target = mc_info.last.seqno;

    scan_masterchain_history(chain_provider, store, known, mc_info.last.shard, mc_target).await
}

/// Advances the index from the masterchain timeline. For every masterchain
/// block, `shards(seqno)` supplies the exact canonical shard heads referenced
/// by that block. This avoids assuming a shard exists continuously from
/// seqno 1 to its current head, an assumption that fails after shard
/// split/merge topology changes.
async fn scan_masterchain_history(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    known: &KnownCodeHashes,
    master_shard: i64,
    target_seqno: u32,
) -> anyhow::Result<()> {
    let master_key = format!("-1:{master_shard}");
    let mut next = store.checkpoint(&master_key)?.saturating_add(1).max(1);
    let last_scanned = next.saturating_sub(1);

    if last_scanned > 0 {
        if let Some(expected_hash) = store.checkpoint_block_hash(&master_key)? {
            if let Ok(Some(actual_hash)) =
                fetch_block_hash(chain_provider, -1, master_shard, last_scanned).await
            {
                if actual_hash != expected_hash {
                    tracing::warn!(
                        target: "indexer",
                        seqno = last_scanned,
                        "masterchain reorg detected; rebuilding canonical explorer index",
                    );
                    store.reset_canonical_index()?;
                    next = 1;
                }
            }
        }
    }

    if next > target_seqno {
        return Ok(());
    }
    let end = next.saturating_add(MAX_BLOCKS_PER_TICK - 1).min(target_seqno);
    while next <= end {
        let block_hash =
            scan_one_seqno(chain_provider, store, known, -1, master_shard, next, next).await?;

        // Anchor non-masterchain history to this exact masterchain block.
        // Repeated descriptors are skipped by root hash; newly split shards
        // can start at any seqno without a fabricated numeric backfill.
        for shard in chain_provider.get_shards(next).await?.shards {
            // A shard's zerostate descriptor is not an ordinary block and
            // cannot be queried through getBlockTransactions. It only
            // anchors the chain before that shard produces seqno 1.
            if shard.seqno == 0 {
                continue;
            }
            let root_hash = hex::encode(&shard.root_hash);
            let stored = store.explorer_block_root(shard.workchain, shard.shard, shard.seqno)?;
            if stored.as_deref() != Some(root_hash.as_str()) {
                scan_one_seqno(
                    chain_provider,
                    store,
                    known,
                    shard.workchain,
                    shard.shard,
                    shard.seqno,
                    next,
                )
                .await?;
            }
            let shard_key = format!("{}:{}", shard.workchain, shard.shard);
            if shard.seqno >= store.checkpoint(&shard_key)? {
                store.set_checkpoint(&shard_key, shard.seqno)?;
                store.set_checkpoint_block_hash(&shard_key, &root_hash)?;
            }
        }

        // Commit the masterchain cursor only after all shard heads it
        // references are durable. A crash restarts this entire unit safely.
        store.set_checkpoint(&master_key, next)?;
        if let Some(hash) = block_hash {
            store.set_checkpoint_block_hash(&master_key, &hash)?;
        }
        next += 1;
    }
    Ok(())
}

#[cfg(test)]
async fn scan_shard(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    known: &KnownCodeHashes,
    workchain: i32,
    shard: i64,
    target_seqno: u32,
) -> anyhow::Result<()> {
    let shard_key = format!("{workchain}:{shard}");
    let mut next = store.checkpoint(&shard_key)?.saturating_add(1).max(1);

    // Reorg check: if a block has already been scanned here, verify the
    // hash recorded for it still matches what the chain reports now. A
    // mismatch means that block -- and everything already scanned after
    // it -- was reorganized out from under us; rewind by a safety margin
    // and rescan rather than silently trusting stale data forever.
    let last_scanned = next.saturating_sub(1);
    if last_scanned > 0 {
        if let Some(expected_hash) = store.checkpoint_block_hash(&shard_key)? {
            if let Ok(Some(actual_hash)) =
                fetch_block_hash(chain_provider, workchain, shard, last_scanned).await
            {
                if actual_hash != expected_hash {
                    tracing::warn!(
                        target: "indexer",
                        shard = %shard_key,
                        seqno = last_scanned,
                        "reorg detected (block hash changed since last scan), rewinding",
                    );
                    next =
                        last_scanned.saturating_sub(REORG_REWIND_BLOCKS).saturating_add(1).max(1);
                    store.rewind_explorer(workchain, shard, next)?;
                }
            }
        }
    }

    if next > target_seqno {
        return Ok(());
    }
    let end = next.saturating_add(MAX_BLOCKS_PER_TICK - 1).min(target_seqno);

    while next <= end {
        let block_hash =
            scan_one_seqno(chain_provider, store, known, workchain, shard, next, next).await?;
        store.set_checkpoint(&shard_key, next)?;
        if let Some(hash) = block_hash {
            store.set_checkpoint_block_hash(&shard_key, &hash)?;
        }
        next += 1;
    }
    Ok(())
}

/// Fetches just the block's own identity hash (a minimal, one-transaction
/// page is enough) -- used only for the reorg check above, never to walk
/// transactions.
async fn fetch_block_hash(
    chain_provider: &Arc<dyn ChainProvider>,
    workchain: i32,
    shard: i64,
    seqno: u32,
) -> anyhow::Result<Option<String>> {
    let page =
        chain_provider.get_block_transactions_page(workchain, shard, seqno, None, None, 1).await?;
    Ok(page.id.map(|id| hex::encode(&id.root_hash)))
}

async fn scan_one_seqno(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    known: &KnownCodeHashes,
    workchain: i32,
    shard: i64,
    seqno: u32,
    observed_mc_seqno: u32,
) -> anyhow::Result<Option<String>> {
    let mut addresses: HashSet<String> = HashSet::new();
    let mut block_hash: Option<String> = None;
    let mut explorer_block: Option<ExplorerBlockRecord> = None;
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
        let (id, incomplete, transactions) = match extended {
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
        if block_hash.is_none() {
            block_hash = id.as_ref().map(|id| hex::encode(&id.root_hash));
        }
        if explorer_block.is_none() {
            explorer_block = id.as_ref().map(|id| ExplorerBlockRecord {
                workchain: id.workchain,
                shard: id.shard,
                seqno: id.seqno,
                root_hash: hex::encode(&id.root_hash),
                file_hash: hex::encode(&id.file_hash),
                gen_utime: 0,
                tx_count: 0,
                indexed_at,
                observed_mc_seqno,
            });
        }
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
            // A mismatch here means list endpoints (which the test suite's
            // own comparison also re-normalizes) appear to work while
            // direct by-address lookups silently 404.
            let Ok(addr) = MsgAddressInt::from_str(&format!("{workchain}:{account}")) else {
                continue;
            };
            let address = addr.to_string();
            addresses.insert(address.clone());
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

    let block_gen_utime = if observed_gen_utime > 0 {
        observed_gen_utime
    } else {
        chain_provider.get_block_timestamp(workchain, shard, seqno).await?
    };
    if let Some(mut block) = explorer_block {
        block.gen_utime = block_gen_utime;
        for transaction in &mut explorer_transactions {
            transaction.gen_utime = block.gen_utime;
        }
        block.tx_count = explorer_transactions.len();
        store.index_explorer_block(&block, &explorer_transactions)?;
    }

    let dns_checkpoint =
        store.masterchain_block(observed_mc_seqno)?.map(|block| MasterchainCheckpoint {
            seqno: block.seqno,
            root_hash: block.root_hash,
            file_hash: block.file_hash,
        });

    for address in addresses {
        if let Err(e) = visit_address(
            chain_provider,
            store,
            known,
            &address,
            seqno,
            observed_mc_seqno,
            u64::from(block_gen_utime),
            dns_checkpoint.as_ref(),
        )
        .await
        {
            tracing::warn!(target: "indexer", address = %address, error = %format!("{e:#}"), "failed to index account");
        }
    }
    Ok(block_hash)
}

async fn visit_address(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    known: &KnownCodeHashes,
    address: &str,
    seqno: u32,
    observed_mc_seqno: u32,
    block_time: u64,
    dns_checkpoint: Option<&MasterchainCheckpoint>,
) -> anyhow::Result<()> {
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

    if kind == "dns_domain" {
        return decode_dns_domain(
            chain_provider,
            store,
            address,
            seqno,
            observed_mc_seqno,
            block_time,
            dns_checkpoint.ok_or_else(|| {
                anyhow::anyhow!("DNS observation lacks its canonical masterchain block")
            })?,
        )
        .await;
    }
    decode_and_store(chain_provider, store, address, &kind, seqno, time_format::now()).await
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
            refresh_service_request_lifecycle(chain_provider, store, address, &data, now).await?;
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
        "contract.pool.nominator" => {
            let address_value = address.parse::<MsgAddressInt>()?;
            let wrapper = NominatorPoolWrapperImpl::new(
                contract_provider_from(chain_provider.clone()),
                address_value,
            );
            let data = wrapper.get_pool_data().await?;
            let nominators = wrapper.list_nominators().await?;
            let nominator_stake = nominators
                .iter()
                .map(|position| position.amount.saturating_add(position.pending_deposit))
                .sum::<u64>();

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
                - nominator_dictionary_depth(&addresses)
                - 1;
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
                total_balance_at_risk: data
                    .validator_amount
                    .saturating_add(nominator_stake)
                    .to_string(),
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
                    .saturating_sub(data.nominators_count.min(u32::from(u16::MAX)) as u16),
                deposit_depth_headroom: depth_headroom,
                accepting_deposits: u32::from(data.max_nominators_count) > data.nominators_count
                    && depth_headroom > 0,
                nominators,
            };

            // Attribute this observation before the record is overwritten: the
            // contract's ledger says what a depositor is owed now, and the
            // difference from the last observation is the only place the reason
            // for the change is still visible. A withdrawal deletes the entry
            // outright, so nothing can be reconstructed after the fact.
            let observed_positions: Vec<(String, u64, u64)> = dto
                .nominators
                .iter()
                .map(|position| {
                    (position.address.clone(), position.amount, position.pending_deposit)
                })
                .collect();
            if let Err(error) = store.observe_nominator_positions(
                address,
                dto.state,
                common::time_format::now(),
                &observed_positions,
            ) {
                tracing::warn!(
                    target: "indexer",
                    pool = %address,
                    error = %format!("{error:#}"),
                    "could not attribute nominator positions"
                );
            }
            store.upsert(&IndexedRecord {
                address: address.to_owned(),
                kind: kind.to_owned(),
                creator: Some(dto.validator_address.clone()),
                counterparty: None,
                status: Some(status.to_owned()),
                deadline: (data.stake_at > 0 && data.stake_held_for > 0)
                    .then_some(u64::from(data.stake_at).saturating_add(data.stake_held_for)),
                last_seqno: seqno,
                updated_at: now,
                dto_json: serde_json::to_string(&dto)?,
            })
        }
        other => anyhow::bail!("unknown indexed contract kind: {other}"),
    }
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
) -> anyhow::Result<()> {
    let (max_indexed, stored_rows, active) = store.service_requests_for_refresh(address)?;
    // `active` is bounded by rows this indexer itself stored (non-terminal
    // statuses only); the contract cannot inflate it. The *new* id range, by
    // contrast, comes straight from the contract's own counter, so it is
    // capped per visit AND by a per-service row budget -- otherwise a
    // fabricated counter would still grow the database by one capped batch
    // of not-found rows per visit, forever.
    let mut ids: HashSet<u64> = active.into_iter().map(|r| r.request_id).collect();
    let new_range = new_service_request_id_range(max_indexed, stored_rows, data.next_request_id);
    if new_range.is_empty()
        && stored_rows >= MAX_TRACKED_REQUESTS_PER_SERVICE
        && data.next_request_id > max_indexed.map_or(0, |id| id.saturating_add(1))
    {
        tracing::warn!(
            service = %address,
            stored_rows,
            claimed_next_request_id = data.next_request_id,
            "service request index is at its per-service budget; not extending into new ids"
        );
    }
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
            ServiceRequestLifecycleRecordDto {
                service_address: address.to_owned(),
                request_id,
                status: "resolved_unknown".into(),
                caller: None,
                price: None,
                storage_fee: None,
                cleanup_bounty: None,
                response_deadline: None,
                refund_claim_deadline: None,
                policy_version: None,
                request_hash: None,
                terms_hash: None,
            }
        };
        store.upsert_service_request(&ServiceRequestRecord {
            service_address: address.to_owned(),
            request_id,
            status: dto.status.clone(),
            updated_at: now,
            dto_json: serde_json::to_string(&dto)?,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod new_id_range_tests {
    use super::*;

    #[test]
    fn resumes_after_the_high_water_mark_in_per_tick_batches() {
        assert_eq!(new_service_request_id_range(None, 0, 10), 0..10);
        assert_eq!(
            new_service_request_id_range(None, 0, u64::MAX),
            0..MAX_SERVICE_REQUEST_IDS_PER_TICK
        );
        assert_eq!(
            new_service_request_id_range(Some(4095), 4096, u64::MAX),
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
        );
        assert!(r.is_empty());
        // Near the budget: only the remainder is scanned.
        let r = new_service_request_id_range(
            Some(MAX_TRACKED_REQUESTS_PER_SERVICE - 11),
            MAX_TRACKED_REQUESTS_PER_SERVICE - 10,
            u64::MAX,
        );
        assert_eq!(r.end - r.start, 10);
    }

    #[test]
    fn high_water_at_max_yields_an_empty_range_instead_of_wrapping() {
        let r = new_service_request_id_range(Some(u64::MAX), 100, u64::MAX);
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
    /// without a real chain. Every other trait method is unreachable from
    /// `scan_shard` (only `scan_new_blocks` -- not exercised by these tests
    /// -- calls `get_masterchain_info`/`get_shards`), so they're stubbed.
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
        /// Total `get_block_transactions_page` calls made so far, and (if
        /// set) the call count after which every subsequent call fails --
        /// simulating an RPC disruption partway through a scan.
        call_count: std::sync::Mutex<usize>,
        fail_after_calls: std::sync::Mutex<Option<usize>>,
        masterchain_info: std::sync::Mutex<Option<contracts::chain_provider::MasterchainInfo>>,
        shards: std::sync::Mutex<Option<contracts::chain_provider::ShardsInfo>>,
    }

    /// Default (workchain, shard) pair most tests scan; matches the id
    /// baked into the `BlockIdExt`s `set` constructs.
    const TEST_WORKCHAIN: i32 = 0;
    const TEST_SHARD: i64 = -9223372036854775808;

    impl ScriptedBlocksProvider {
        fn new() -> Self {
            Self {
                by_seqno: std::sync::Mutex::new(std::collections::HashMap::new()),
                call_count: std::sync::Mutex::new(0),
                fail_after_calls: std::sync::Mutex::new(None),
                masterchain_info: std::sync::Mutex::new(None),
                shards: std::sync::Mutex::new(None),
            }
        }

        /// Scripts a block on the default test shard ([`TEST_WORKCHAIN`]/
        /// [`TEST_SHARD`]), the shard every pre-existing test scans.
        fn set(&self, seqno: u32, block_hash: &str) {
            self.set_on(TEST_WORKCHAIN, TEST_SHARD, seqno, block_hash);
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

        /// After this many `get_block_transactions_page` calls succeed,
        /// every subsequent call fails -- simulating an RPC disruption.
        fn fail_after(&self, n: usize) {
            *self.fail_after_calls.lock().unwrap() = Some(n);
        }

        fn calls_made(&self) -> usize {
            *self.call_count.lock().unwrap()
        }

        fn clear_failure(&self) {
            *self.fail_after_calls.lock().unwrap() = None;
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
            *self.shards.lock().unwrap() = Some(contracts::chain_provider::ShardsInfo {
                r#type: None,
                shards: entries
                    .iter()
                    .map(|&(workchain, shard, seqno)| {
                        chain_rpc_client::v2::data_models::BlockIdExt {
                            r#type: "tos.blockIdExt".to_owned(),
                            workchain,
                            shard,
                            seqno,
                            root_hash: vec![0; 32],
                            file_hash: vec![0; 32],
                        }
                    })
                    .collect(),
            });
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
            unimplemented!("not exercised by scan_shard reorg tests")
        }
        async fn get_balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn send_boc(&self, _boc: &[u8]) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn get_config_param(
            &self,
            _param_id: u32,
        ) -> anyhow::Result<chain_block::ConfigParamEnum> {
            unimplemented!()
        }
        async fn get_address_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::AddressInfo> {
            unimplemented!()
        }
        async fn get_extended_address_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::ExtendedAddressInfo> {
            unimplemented!()
        }
        async fn get_wallet_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::WalletInfo> {
            unimplemented!()
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
            _seqno: u32,
        ) -> anyhow::Result<contracts::chain_provider::ShardsInfo> {
            self.shards.lock().unwrap().clone().ok_or_else(|| anyhow::anyhow!("no scripted shards"))
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
            {
                let mut count = self.call_count.lock().unwrap();
                *count += 1;
                if let Some(fail_at) = *self.fail_after_calls.lock().unwrap() {
                    if *count > fail_at {
                        anyhow::bail!("simulated RPC disruption");
                    }
                }
            }
            self.by_seqno.lock().unwrap().get(&(workchain, shard, seqno)).cloned().ok_or_else(
                || anyhow::anyhow!("no scripted block for ({workchain}, {shard}, {seqno})"),
            )
        }
    }

    fn known_code_hashes_for_test() -> KnownCodeHashes {
        KnownCodeHashes::compute().unwrap()
    }

    #[tokio::test]
    async fn scan_shard_advances_the_checkpoint_and_records_the_block_hash() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        provider.set(1, &"11".repeat(32));
        provider.set(2, &"22".repeat(32));
        let store = IndexerStore::open_in_memory().unwrap();
        let known = known_code_hashes_for_test();
        let dyn_provider: Arc<dyn ChainProvider> = provider.clone();

        scan_shard(&dyn_provider, &store, &known, 0, -9223372036854775808, 2).await.unwrap();

        assert_eq!(store.checkpoint("0:-9223372036854775808").unwrap(), 2);
        assert_eq!(
            store.checkpoint_block_hash("0:-9223372036854775808").unwrap(),
            Some("22".repeat(32))
        );
    }

    #[tokio::test]
    async fn scan_shard_detects_a_reorg_and_rewinds_to_rescan() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        provider.set(1, &"11".repeat(32));
        provider.set(2, &"22".repeat(32));
        let store = IndexerStore::open_in_memory().unwrap();
        let known = known_code_hashes_for_test();
        let dyn_provider: Arc<dyn ChainProvider> = provider.clone();

        scan_shard(&dyn_provider, &store, &known, 0, -9223372036854775808, 2).await.unwrap();
        assert_eq!(store.checkpoint("0:-9223372036854775808").unwrap(), 2);
        assert_eq!(
            store.checkpoint_block_hash("0:-9223372036854775808").unwrap(),
            Some("22".repeat(32))
        );

        // Simulate a reorg: seqno 2 now has different content/hash, and a
        // new seqno 3 is available.
        provider.set(2, &"99".repeat(32));
        provider.set(3, &"33".repeat(32));

        scan_shard(&dyn_provider, &store, &known, 0, -9223372036854775808, 3).await.unwrap();

        // The checkpoint must reflect the corrected chain: re-scanned
        // through the reorged block up to the new head, with the *new*
        // hash recorded, not the stale pre-reorg one.
        assert_eq!(store.checkpoint("0:-9223372036854775808").unwrap(), 3);
        assert_eq!(
            store.checkpoint_block_hash("0:-9223372036854775808").unwrap(),
            Some("33".repeat(32))
        );
    }

    #[tokio::test]
    async fn rpc_disruption_mid_scan_leaves_the_checkpoint_at_the_last_successful_seqno() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        for seqno in 1..=5u32 {
            provider.set(seqno, &format!("{seqno:064x}"));
        }
        provider.fail_after(3); // seqnos 1-3 succeed; seqno 4's call fails
        let store = IndexerStore::open_in_memory().unwrap();
        let known = known_code_hashes_for_test();
        let dyn_provider: Arc<dyn ChainProvider> = provider.clone();

        let result = scan_shard(&dyn_provider, &store, &known, 0, -9223372036854775808, 5).await;
        assert!(result.is_err(), "the simulated RPC disruption must propagate as an error");
        assert_eq!(
            store.checkpoint("0:-9223372036854775808").unwrap(),
            3,
            "checkpoint must stop at the last seqno actually scanned, not skip ahead or corrupt"
        );

        // The RPC recovers; a subsequent call must resume from seqno 4, not
        // re-scan 1-3 or skip ahead.
        let calls_before_retry = provider.calls_made();
        provider.clear_failure();
        scan_shard(&dyn_provider, &store, &known, 0, -9223372036854775808, 5).await.unwrap();
        assert_eq!(store.checkpoint("0:-9223372036854775808").unwrap(), 5);
        assert_eq!(
            provider.calls_made() - calls_before_retry,
            3,
            "resuming must only make the reorg-check probe plus the 2 remaining calls \
             (seqno 4 and 5), not re-scan from genesis"
        );
    }

    #[tokio::test]
    async fn rescanning_an_unchanged_range_only_probes_for_a_reorg_once() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        provider.set(1, &"11".repeat(32));
        provider.set(2, &"22".repeat(32));
        let store = IndexerStore::open_in_memory().unwrap();
        let known = known_code_hashes_for_test();
        let dyn_provider: Arc<dyn ChainProvider> = provider.clone();

        scan_shard(&dyn_provider, &store, &known, 0, -9223372036854775808, 2).await.unwrap();
        let calls_after_first_scan = provider.calls_made();

        // Nothing changed on chain. Re-running against the same target
        // must make exactly one call -- the reorg-verification probe that
        // re-checks the checkpoint's block hash still matches -- not a
        // full rescan, and not zero calls either (skipping verification
        // once "done" would miss a reorg that happens afterward).
        scan_shard(&dyn_provider, &store, &known, 0, -9223372036854775808, 2).await.unwrap();
        assert_eq!(provider.calls_made(), calls_after_first_scan + 1);
        assert_eq!(store.checkpoint("0:-9223372036854775808").unwrap(), 2);
        assert_eq!(
            store.checkpoint_block_hash("0:-9223372036854775808").unwrap(),
            Some("22".repeat(32))
        );
    }

    #[tokio::test]
    async fn long_catch_up_advances_in_capped_steps_across_multiple_calls() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        for seqno in 1..=250u32 {
            provider.set(seqno, &format!("{seqno:064x}"));
        }
        let store = IndexerStore::open_in_memory().unwrap();
        let known = known_code_hashes_for_test();
        let dyn_provider: Arc<dyn ChainProvider> = provider.clone();

        // Far behind (250 available, checkpoint at 0): must cap at
        // MAX_BLOCKS_PER_TICK in a single call, not consume everything at
        // once and stall the tick loop.
        scan_shard(&dyn_provider, &store, &known, 0, -9223372036854775808, 250).await.unwrap();
        assert_eq!(store.checkpoint("0:-9223372036854775808").unwrap(), MAX_BLOCKS_PER_TICK);

        // A second call continues from exactly where it left off, without
        // gaps or re-scanning, until the real head is reached.
        scan_shard(&dyn_provider, &store, &known, 0, -9223372036854775808, 250).await.unwrap();
        assert_eq!(store.checkpoint("0:-9223372036854775808").unwrap(), 250);
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

        scan_new_blocks(&dyn_provider, &store, &known).await.unwrap();
        assert_eq!(store.checkpoint(&format!("0:{shard_a}")).unwrap(), 1);
        assert_eq!(store.checkpoint("-1:-9223372036854775808").unwrap(), 1);

        // Simulate a shard-set change (e.g. a split/merge): shard_a is
        // gone, shard_b appears instead (starting from its own seqno 1,
        // like a genuinely new shard), and the masterchain advances.
        provider.set_on(-1, mc_shard, 2, &"cc".repeat(32));
        provider.set_masterchain_info(2, mc_shard);
        provider.set_on(0, shard_b, 1, &"dd".repeat(32));
        provider.set_shards(&[(0, shard_b, 1)]);

        scan_new_blocks(&dyn_provider, &store, &known).await.unwrap();

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
    async fn newly_split_shard_is_indexed_from_its_masterchain_reported_head() {
        let provider = Arc::new(ScriptedBlocksProvider::new());
        let mc_shard = i64::MIN;
        let child_shard = 4_611_686_018_427_387_904i64;

        provider.set_on(-1, mc_shard, 1, &"aa".repeat(32));
        provider.set_on(0, child_shard, 900, &"bb".repeat(32));
        provider.set_masterchain_info(1, mc_shard);
        provider.set_shards(&[(0, child_shard, 900)]);

        let store = IndexerStore::open_in_memory().unwrap();
        let known = known_code_hashes_for_test();
        let dyn_provider: Arc<dyn ChainProvider> = provider.clone();
        scan_new_blocks(&dyn_provider, &store, &known).await.unwrap();

        assert_eq!(store.checkpoint(&format!("0:{child_shard}")).unwrap(), 900);
        assert!(store.explorer_block_root(0, child_shard, 900).unwrap().is_some());
        assert_eq!(
            provider.calls_made(),
            2,
            "only the masterchain block and the reported child head may be fetched"
        );
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
        scan_new_blocks(&dyn_provider, &store, &known).await.unwrap();

        assert_eq!(provider.calls_made(), 1, "only the masterchain block is queryable");
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

        refresh_service_request_lifecycle(&provider_dyn, &store, "-1:service", &data, 1_000)
            .await
            .unwrap();

        let cap = MAX_SERVICE_REQUEST_IDS_PER_TICK as usize;
        assert_eq!(
            *provider.get_method_calls.lock().unwrap(),
            cap * 2,
            "each id in the capped batch is probed once with get_request and once with \
             get_refund; nothing beyond the cap may be touched"
        );
        let (max_indexed, _stored, active) =
            store.service_requests_for_refresh("-1:service").unwrap();
        assert_eq!(
            max_indexed,
            Some(MAX_SERVICE_REQUEST_IDS_PER_TICK - 1),
            "the stored high-water mark advances to the end of the capped batch"
        );
        assert!(active.is_empty(), "not-found probes are stored as terminal, not active");

        // A later visit resumes from the stored high-water mark: progress
        // stays monotonic across capped batches.
        refresh_service_request_lifecycle(&provider_dyn, &store, "-1:service", &data, 1_001)
            .await
            .unwrap();
        let (max_indexed, _stored, _) = store.service_requests_for_refresh("-1:service").unwrap();
        assert_eq!(max_indexed, Some(2 * MAX_SERVICE_REQUEST_IDS_PER_TICK - 1));
        assert_eq!(*provider.get_method_calls.lock().unwrap(), cap * 4);
    }
}

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
