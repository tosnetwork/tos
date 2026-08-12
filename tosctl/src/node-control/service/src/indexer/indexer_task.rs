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
//! seen before, checks its code hash against the four known contract codes
//! (Task Escrow, Dispute, Service Actor, Capability Registry). A match is
//! decoded via that contract's own `decode_data` -- no new decode logic --
//! and stored in [`IndexerStore`]. An address already known to be one of
//! these kinds is *always* re-decoded when it reappears in a later block,
//! since that is exactly how a status change (accept/settle/rule/...)
//! becomes visible.
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chain_block::{Cell, MsgAddressInt, UInt256, read_single_root_boc};
use common::{app_config::AppConfig, task_cancellation::CancellationCtx, time_format};
use contracts::{
    AipowCommitmentContract, AipowDistributorContract, CapabilityRegistryContract, ChainProvider,
    DisputeContract, ServiceActorContract, TaskEscrowContract,
};

use crate::indexer::store::{
    IndexedRecord, IndexerStore, AipowSettlementRecord, ServiceRequestRecord,
};
use crate::runtime_config::RuntimeConfig;

/// Upper bound on how many masterchain blocks a single tick will scan, so a
/// long-idle indexer catching up on history doesn't stall the tick loop
/// indefinitely -- the next tick picks up where this one left off.
const MAX_BLOCKS_PER_TICK: u32 = 200;
/// Max transactions requested per `getBlockTransactions` page.
const TRANSACTIONS_PAGE_SIZE: u32 = 256;
/// How far back to rewind and rescan when a reorg is detected at the
/// checkpoint boundary. Reorgs are a real, documented hazard on this chain
/// (see `doc/tos-message-policy.md`'s replay-across-reorgs note), not a
/// theoretical one; this bounds how much already-indexed data can go stale
/// from a single detected divergence rather than only ever checking the one
/// block at the checkpoint itself.
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
        by_hash.insert(DisputeContract::code()?.repr_hash(), "dispute");
        by_hash.insert(ServiceActorContract::code()?.repr_hash(), "service_actor");
        by_hash.insert(CapabilityRegistryContract::code()?.repr_hash(), "capability_registry");
        by_hash.insert(AipowCommitmentContract::code()?.repr_hash(), "aipow_commitment");
        by_hash.insert(AipowDistributorContract::code()?.repr_hash(), "aipow_distributor");
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

    // The masterchain block itself -- some actors are deployed directly to
    // workchain -1 (e.g. Dispute/Capability Registry in some examples).
    scan_shard(chain_provider, store, known, -1, mc_info.last.shard, mc_target).await?;

    // Every other workchain's current shard block(s) -- this is where
    // almost every real contract actually lives (Task Escrow, Service
    // Actor, etc. are conventionally deployed to workchain 0). Shard block
    // seqnos advance independently of the masterchain's, so each shard is
    // walked (and checkpointed) on its own from its own reported head.
    let shards = chain_provider.get_shards(mc_target).await?;
    for shard in shards.shards {
        scan_shard(chain_provider, store, known, shard.workchain, shard.shard, shard.seqno).await?;
    }
    Ok(())
}

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
            scan_one_seqno(chain_provider, store, known, workchain, shard, next).await?;
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
) -> anyhow::Result<Option<String>> {
    let mut addresses: HashSet<String> = HashSet::new();
    let mut block_hash: Option<String> = None;
    let mut after_lt: Option<u64> = None;
    let mut after_hash: Option<String> = None;
    loop {
        let page = chain_provider
            .get_block_transactions_page(
                workchain,
                shard,
                seqno,
                after_lt,
                after_hash.as_deref(),
                TRANSACTIONS_PAGE_SIZE,
            )
            .await?;
        if block_hash.is_none() {
            block_hash = page.id.as_ref().map(|id| hex::encode(&id.root_hash));
        }
        for tx in &page.transactions {
            if tx.account.is_empty() {
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
            let Ok(addr) = MsgAddressInt::from_str(&format!("{workchain}:{}", tx.account)) else {
                continue;
            };
            addresses.insert(addr.to_string());
        }
        if !page.incomplete {
            break;
        }
        let Some(last) = page.transactions.last() else { break };
        after_lt = Some(last.lt);
        after_hash = Some(last.hash.clone());
    }

    for address in addresses {
        if let Err(e) = visit_address(chain_provider, store, known, &address, seqno).await {
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
) -> anyhow::Result<()> {
    let existing_kind = store.kind_of(address)?;
    let kind = match existing_kind {
        // Already known not to be one of the four contract kinds: nothing
        // further can ever change that (contract code never changes after
        // deploy in this actor model), so skip the code-hash lookup.
        Some(kind) if kind == "unclassified" => return Ok(()),
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
        "task_escrow" => {
            let stack =
                chain_provider.run_get_method(address.to_owned(), "get_task_data", vec![]).await?;
            let data = TaskEscrowContract::decode_data(&stack)?;
            if task_status_name(data.status) == "settled" {
                // Settlement drains the escrow, so the *current* budget
                // field is already zero by the time the settled status is
                // observable. The real budget comes from this indexer's
                // own pre-settlement observation of the same contract
                // (the not-yet-overwritten stored record). An indexer
                // that first sees an escrow only after settlement has no
                // such observation and records amount 0 -- the documented
                // snapshot-diff limitation, resolved for good by the
                // settlement-receipt schema.
                let amount = if data.budget > 0 {
                    data.budget
                } else {
                    store
                        .get(address)?
                        .and_then(|prior| {
                            serde_json::from_str::<TaskEscrowRecordDto>(&prior.dto_json).ok()
                        })
                        .map(|dto| dto.budget)
                        .unwrap_or(0)
                };
                // A settled escrow is terminal; `record_aipow_settlement`
                // keeps the first observation, so re-visits are no-ops.
                store.record_aipow_settlement(&AipowSettlementRecord {
                    address: address.to_owned(),
                    request_id: String::new(),
                    kind: "task_escrow".to_owned(),
                    earner: data.assigned_agent.as_ref().unwrap_or(&data.creator).to_string(),
                    payer: data.creator.to_string(),
                    amount,
                    attested: data.attestor_pubkey.is_some(),
                    seqno,
                    observed_at: now,
                })?;
            }
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
            refresh_service_request_lifecycle(chain_provider, store, address, &data, seqno, now)
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
        "aipow_commitment" => {
            let stack = chain_provider
                .run_get_method(address.to_owned(), "get_aipow_commitment_data", vec![])
                .await?;
            let data = AipowCommitmentContract::decode_data(&stack)?;
            store.upsert(&IndexedRecord {
                address: address.to_owned(),
                kind: kind.to_owned(),
                creator: Some(data.committer.to_string()),
                counterparty: Some(data.reviewer.to_string()),
                status: Some(aipow_commitment_status_name(data.status).to_owned()),
                deadline: Some(data.window_deadline),
                last_seqno: seqno,
                updated_at: now,
                dto_json: serde_json::to_string(&AipowCommitmentRecordDto::from(&data))?,
            })
        }
        "aipow_distributor" => {
            let stack = chain_provider
                .run_get_method(address.to_owned(), "get_aipow_distributor_data", vec![])
                .await?;
            let data = AipowDistributorContract::decode_data(&stack)?;
            store.upsert(&IndexedRecord {
                address: address.to_owned(),
                kind: kind.to_owned(),
                creator: Some(data.operator.to_string()),
                counterparty: None,
                // A distributor has no single lifecycle status; expose the
                // running claimed count in the status column so the list
                // endpoints have something to filter/show.
                status: Some(format!("claimed:{}", data.claimed_count)),
                deadline: None,
                last_seqno: seqno,
                updated_at: now,
                dto_json: serde_json::to_string(&AipowDistributorRecordDto::from(&data))?,
            })
        }
        other => anyhow::bail!("unknown indexed contract kind: {other}"),
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct AipowDistributorRecordDto {
    operator: String,
    epoch: u64,
    total_score: String,
    pool: u64,
    claimed_count: u32,
    claimed_score: String,
    score_root: String,
    commitment_ref: String,
}

impl From<&contracts::AipowDistributorData> for AipowDistributorRecordDto {
    fn from(data: &contracts::AipowDistributorData) -> Self {
        Self {
            operator: data.operator.to_string(),
            epoch: data.epoch,
            total_score: data.total_score.to_string(),
            pool: data.pool,
            claimed_count: data.claimed_count,
            claimed_score: data.claimed_score.to_string(),
            score_root: hex::encode(data.score_root),
            commitment_ref: hex::encode(data.commitment_ref),
        }
    }
}

fn aipow_commitment_status_name(status: u8) -> &'static str {
    match status {
        0 => "committed",
        1 => "challenged",
        2 => "final",
        3 => "rejected",
        _ => "unknown",
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct AipowCommitmentRecordDto {
    committer: String,
    reviewer: String,
    status: String,
    epoch: u64,
    window_deadline: u64,
    review_deadline: u64,
    commit_bond: u64,
    challenge_bond: u64,
    score_root: String,
    methodology_hash: String,
    challenger: String,
    challenge_evidence_hash: String,
}

impl From<&contracts::AipowCommitmentData> for AipowCommitmentRecordDto {
    fn from(data: &contracts::AipowCommitmentData) -> Self {
        Self {
            committer: data.committer.to_string(),
            reviewer: data.reviewer.to_string(),
            status: aipow_commitment_status_name(data.status).to_owned(),
            epoch: data.epoch,
            window_deadline: data.window_deadline,
            review_deadline: data.review_deadline,
            commit_bond: data.commit_bond,
            challenge_bond: data.challenge_bond,
            score_root: hex::encode(data.score_root),
            methodology_hash: hex::encode(data.methodology_hash),
            challenger: data.challenger.to_string(),
            challenge_evidence_hash: hex::encode(data.challenge_evidence_hash),
        }
    }
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
    seqno: u32,
    now: u64,
) -> anyhow::Result<()> {
    let (max_indexed, active) = store.service_requests_for_refresh(address)?;
    let mut ids: HashSet<u64> = active.into_iter().map(|r| r.request_id).collect();
    let first_new = max_indexed.and_then(|id| id.checked_add(1)).unwrap_or(0);
    ids.extend(first_new..data.next_request_id);
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
        // A `responded` conclusion is the only one this snapshot diff can
        // prove was a real, paid service completion (see the deadline
        // reasoning above); it is the Service Actor analog of a settled
        // Task Escrow for the AIPoW shadow-scoring data plane.
        if let ("responded", Some(caller), Some(price)) =
            (dto.status.as_str(), &dto.caller, dto.price)
        {
            store.record_aipow_settlement(&AipowSettlementRecord {
                address: address.to_owned(),
                request_id: request_id.to_string(),
                kind: "service_request".to_owned(),
                earner: data.owner.to_string(),
                payer: caller.clone(),
                amount: price,
                attested: data.attestor_pubkey.is_some(),
                seqno,
                observed_at: now,
            })?;
        }
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
    use crate::http::agent_query_api::{DisputeDto, RegistryDto, ServiceActorDto, TaskDto};

    fn addr(byte: u8) -> MsgAddressInt {
        MsgAddressInt::with_standart(None, 0, [byte; 32].into()).unwrap()
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
            let entries =
                result.stack.iter().map(lifecycle_stack_item_to_entry).collect::<anyhow::Result<Vec<_>>>()?;
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
            Number, StackEntry, numberdecimal::NumberDecimal, slice,
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

        // A responded request is a real, paid service completion: exactly
        // one AIPoW settlement event, attributed owner <- caller at the
        // service's per-call price, unattested (this fixture deploys with
        // no attestor key). A further refresh must not duplicate it.
        let (events, total) = store.list_aipow_settlements(0, u32::MAX, 0, 10).unwrap();
        assert_eq!(total, 1);
        assert_eq!(events[0].kind, "service_request");
        assert_eq!(events[0].request_id, "0");
        assert_eq!(events[0].earner, f.owner.address().to_string());
        assert_eq!(events[0].payer, caller.to_string());
        assert_eq!(events[0].amount, 100_000_000);
        assert!(!events[0].attested);
        f.refresh(&store, f.base_now).await;
        let (_, total_after) = store.list_aipow_settlements(0, u32::MAX, 0, 10).unwrap();
        assert_eq!(total_after, 1);
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

        // A refunded request is not a completed service: no AIPoW
        // settlement event may be recorded for it.
        let (_, total) = store.list_aipow_settlements(0, u32::MAX, 0, 10).unwrap();
        assert_eq!(total, 0);
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

    // ─── AIPoW score-commitment classification (real sandbox contract) ───

    #[tokio::test]
    async fn indexer_decodes_a_aipow_commitment_through_its_lifecycle() {
        use contracts::{AipowCommitmentContract, AipowCommitmentInit};

        let tos: u64 = 1_000_000_000;
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let base_now = time_format::now();
        bc.set_now(base_now as u32);
        let committer = bc.treasury("aipow-idx-committer", 1_000 * tos).expect("committer");
        let reviewer = bc.treasury("aipow-idx-reviewer", 1_000 * tos).expect("reviewer");
        let challenger = bc.treasury("aipow-idx-challenger", 1_000 * tos).expect("challenger");
        let window_deadline = base_now + 3_600;
        let init = AipowCommitmentInit {
            committer: committer.address().clone(),
            reviewer: reviewer.address().clone(),
            epoch: 42,
            window_deadline,
            commit_bond: 5 * tos,
            score_root: [0x33; 32],
            methodology_hash: [0x44; 32],
        };
        let commitment = AipowCommitmentContract::calculate_address(-1, &init).expect("address");
        let deploy = MessageBuilder::internal(committer.address(), &commitment, 6 * tos)
            .bounce(false)
            .state_init(AipowCommitmentContract::build_state_init(&init).expect("state init"))
            .body(chain_block::Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();

        let provider = Arc::new(SandboxChainProvider { bc: StdMutex::new(bc) });
        let provider_dyn: Arc<dyn ChainProvider> = provider.clone();
        let store = IndexerStore::open_in_memory().unwrap();
        let address = commitment.to_string();

        decode_and_store(&provider_dyn, &store, &address, "aipow_commitment", 1, base_now)
            .await
            .unwrap();
        let record = store.get(&address).unwrap().unwrap();
        assert_eq!(record.kind, "aipow_commitment");
        assert_eq!(record.status.as_deref(), Some("committed"));
        assert_eq!(record.creator.as_deref(), Some(committer.address().to_string().as_str()));
        assert_eq!(record.counterparty.as_deref(), Some(reviewer.address().to_string().as_str()));
        assert_eq!(record.deadline, Some(window_deadline));
        let dto: serde_json::Value = serde_json::from_str(&record.dto_json).unwrap();
        assert_eq!(dto["epoch"], 42);
        assert_eq!(dto["score_root"], hex::encode([0x33u8; 32]));
        assert_eq!(dto["commit_bond"], 5 * tos);

        // Drive a real challenge through the contract, then re-decode: the
        // stored record must follow the status transition.
        let challenge = MessageBuilder::internal(
            challenger.address(),
            &commitment,
            6 * tos,
        )
        .body(AipowCommitmentContract::challenge(1, [0xEE; 32]).unwrap())
        .build();
        provider.bc.lock().unwrap().send_message(challenge).unwrap().expect_success();
        decode_and_store(&provider_dyn, &store, &address, "aipow_commitment", 2, base_now)
            .await
            .unwrap();
        let record = store.get(&address).unwrap().unwrap();
        assert_eq!(record.status.as_deref(), Some("challenged"));
        let dto: serde_json::Value = serde_json::from_str(&record.dto_json).unwrap();
        assert_eq!(dto["challenger"], challenger.address().to_string());
        assert_eq!(dto["challenge_evidence_hash"], hex::encode([0xEEu8; 32]));
        // The bond is fixed at the commit bond; the 1 TOS overpayment is
        // refunded rather than recorded as a larger bond.
        assert_eq!(dto["challenge_bond"], 5 * tos);
        // The review deadline is set to the challenge time plus the 7-day
        // review window.
        assert_eq!(dto["review_deadline"], base_now + 604_800);
    }

    #[tokio::test]
    async fn indexer_decodes_an_aipow_distributor_and_follows_claims() {
        use contracts::aipow_merkle::{inclusion_proof, score_root, ScoreEntry};
        use contracts::{AipowDistributorContract, AipowDistributorInit};

        let tos: u64 = 1_000_000_000;
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let base_now = time_format::now();
        bc.set_now(base_now as u32);
        let operator = bc.treasury("aipow-dist-op", 1_000 * tos).expect("operator");
        let caller = bc.treasury("aipow-dist-caller", 1_000 * tos).expect("caller");
        let members = vec![
            ScoreEntry { identity: [0x11; 32], score: 400_000 },
            ScoreEntry { identity: [0x22; 32], score: 600_000 },
        ];
        let root = score_root(&members).unwrap();
        let init = AipowDistributorInit {
            operator: operator.address().clone(),
            epoch: 42,
            total_score: 1_000_000,
            pool: 10 * tos,
            score_root: root,
            commitment_ref: [0x99; 32],
        };
        let distributor = AipowDistributorContract::calculate_address(-1, &init).expect("address");
        let deploy = MessageBuilder::internal(operator.address(), &distributor, 2 * tos)
            .bounce(false)
            .state_init(AipowDistributorContract::build_state_init(&init).expect("state init"))
            .body(chain_block::Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();

        let provider = Arc::new(SandboxChainProvider { bc: StdMutex::new(bc) });
        let provider_dyn: Arc<dyn ChainProvider> = provider.clone();
        let store = IndexerStore::open_in_memory().unwrap();
        let address = distributor.to_string();

        decode_and_store(&provider_dyn, &store, &address, "aipow_distributor", 1, base_now)
            .await
            .unwrap();
        let record = store.get(&address).unwrap().unwrap();
        assert_eq!(record.kind, "aipow_distributor");
        assert_eq!(record.status.as_deref(), Some("claimed:0"));
        assert_eq!(record.creator.as_deref(), Some(operator.address().to_string().as_str()));
        let dto: serde_json::Value = serde_json::from_str(&record.dto_json).unwrap();
        assert_eq!(dto["epoch"], 42);
        assert_eq!(dto["total_score"], "1000000");
        assert_eq!(dto["pool"], 10 * tos);
        assert_eq!(dto["score_root"], hex::encode(root));

        // Drive a real claim through the contract, then re-decode: the
        // claimed count in the stored record must advance.
        let proof = inclusion_proof(&members, &[0x11; 32]).unwrap();
        let claim = MessageBuilder::internal(caller.address(), &distributor, tos / 2)
            .body(AipowDistributorContract::claim(1, [0x11; 32], 400_000, &proof).unwrap())
            .build();
        provider.bc.lock().unwrap().send_message(claim).unwrap().expect_success();
        decode_and_store(&provider_dyn, &store, &address, "aipow_distributor", 2, base_now)
            .await
            .unwrap();
        let record = store.get(&address).unwrap().unwrap();
        assert_eq!(record.status.as_deref(), Some("claimed:1"));
        let dto: serde_json::Value = serde_json::from_str(&record.dto_json).unwrap();
        assert_eq!(dto["claimed_count"], 1);
        // The running claimed_score advances by the claimed member's score.
        assert_eq!(dto["claimed_score"], "400000");
    }
}
