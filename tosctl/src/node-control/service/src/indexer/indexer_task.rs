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
    CapabilityRegistryContract, ChainProvider, DisputeContract, ServiceActorContract,
    TaskEscrowContract,
};

use crate::indexer::store::{IndexedRecord, IndexerStore};
use crate::runtime_config::RuntimeConfig;

/// Upper bound on how many masterchain blocks a single tick will scan, so a
/// long-idle indexer catching up on history doesn't stall the tick loop
/// indefinitely -- the next tick picks up where this one left off.
const MAX_BLOCKS_PER_TICK: u32 = 200;
/// Max transactions requested per `getBlockTransactions` page.
const TRANSACTIONS_PAGE_SIZE: u32 = 256;

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

/// The four contract codes the indexer recognizes, keyed by their
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
    if next > target_seqno {
        return Ok(());
    }
    let end = next.saturating_add(MAX_BLOCKS_PER_TICK - 1).min(target_seqno);

    while next <= end {
        scan_one_seqno(chain_provider, store, known, workchain, shard, next).await?;
        store.set_checkpoint(&shard_key, next)?;
        next += 1;
    }
    Ok(())
}

async fn scan_one_seqno(
    chain_provider: &Arc<dyn ChainProvider>,
    store: &IndexerStore,
    known: &KnownCodeHashes,
    workchain: i32,
    shard: i64,
    seqno: u32,
) -> anyhow::Result<()> {
    let mut addresses: HashSet<String> = HashSet::new();
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
    Ok(())
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

    decode_and_store(chain_provider, store, address, &kind, seqno).await
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
) -> anyhow::Result<()> {
    let now = time_format::now();
    match kind {
        "task_escrow" => {
            let stack = chain_provider.run_get_method(address.to_owned(), "get_task_data", vec![]).await?;
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
            let stack = chain_provider.run_get_method(address.to_owned(), "get_dispute_data", vec![]).await?;
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
            let stack =
                chain_provider.run_get_method(address.to_owned(), "get_service_actor_data", vec![]).await?;
            let data = ServiceActorContract::decode_data(&stack)?;
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
        other => anyhow::bail!("unknown indexed contract kind: {other}"),
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

#[derive(serde::Serialize)]
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
    total_revenue: u64,
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
            total_revenue: data.total_revenue,
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
            authorized_caller: Some(addr(2)),
            open_access: false,
            active: true,
            price_per_call: 10,
            rate_limit_per_day: 100,
            call_day: 0,
            calls_today: 0,
            total_revenue: 0,
            metadata_hash: [0; 32],
            proof_scheme_hash: [0; 32],
            last_request_hash: [0; 32],
            last_response_hash: [0; 32],
            attestor_pubkey: None,
        };
        let json = serde_json::to_string(&ServiceActorRecordDto::from(&data)).unwrap();
        let dto = crate::http::agent_query_api::indexed_dto::<ServiceActorDto>(&json, "0:aa", false);
        assert!(dto.is_some(), "ServiceActorRecordDto JSON must decode into ServiceActorDto: {json}");
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
        assert!(dto.is_some(), "CapabilityRegistryRecordDto JSON must decode into RegistryDto: {json}");
    }
}
