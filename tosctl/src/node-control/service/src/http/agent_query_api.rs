/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Read-only HTTP query API for Agent Accounts and Task Escrow contracts.
//!
//! `GET /tasks` enumerates tasks registered in this node's local
//! `tosctld` configuration (`agent_tasks`, populated by `tosctl agent task
//! create`/`claim` and friends). It is **not** a chain-wide contract index:
//! a Task Escrow deployed or discovered through any other channel will not
//! appear here unless this operator's config also tracks it. Chain-wide
//! discovery of every Task Escrow on the network requires a future indexer
//! (see `ROADMAP.md`, Phase 3) and is out of scope for this endpoint.
#[allow(unused_imports)]
use super::http_server_task::ApiErrorResponse;
use super::http_server_task::{AppError, AppState};
use crate::runtime_config::RuntimeConfig;
use axum::extract::{Path, Query, State};
use chain_block::MsgAddressInt;
use common::tvm_stack_parser::TvmStackParser;
use contracts::{AgentAccountContract, ServiceActorContract, TaskEscrowContract};
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// Upper bound on concurrent chain RPC requests issued by a single
/// `list_tasks` call, so a large local task registry cannot fan out an
/// unbounded number of simultaneous requests to the chain RPC endpoint.
const MAX_CONCURRENT_TASK_READS: usize = 8;

/// Per get-method call timeout. Applied individually to every chain read so
/// one slow or unreachable endpoint cannot stall a request indefinitely.
const CHAIN_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AgentAccountDto {
    pub address: String,
    pub owner: String,
    pub controller_pubkey: String,
    pub deployment_id: String,
    pub controller_epoch: u64,
    pub seqno: u32,
    pub spend_day: u32,
    pub spent_today: u64,
    pub max_per_tx: u64,
    pub daily_limit: u64,
    pub default_task_timeout_secs: u64,
    pub metadata_hash: Option<String>,
    pub service_endpoint_hash: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AgentAccountResponse {
    pub ok: bool,
    pub result: AgentAccountDto,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct TaskDto {
    pub name: Option<String>,
    pub address: String,
    pub creator: String,
    pub assigned_agent: Option<String>,
    pub verifier: Option<String>,
    pub budget: u64,
    pub deadline: u64,
    pub review_period: u32,
    pub review_deadline: u64,
    pub status: String,
    pub result_hash: String,
    pub evidence_hash: String,
    pub settlement_policy_hash: String,
    pub permission_hash: String,
    pub dispute_hash: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct TaskResponse {
    pub ok: bool,
    pub result: TaskDto,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct TaskListItem {
    pub name: String,
    pub address: String,
    pub task: Option<TaskDto>,
    /// Human-readable reason `task` is absent. Safe to display; never
    /// contains raw internal RPC error text (see `error_kind` for the
    /// stable machine-readable category).
    pub error: Option<String>,
    pub error_kind: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct TaskListResponse {
    pub ok: bool,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub result: Vec<TaskListItem>,
}

#[derive(Clone, Default, serde::Deserialize, utoipa::IntoParams)]
pub struct TaskListQuery {
    pub status: Option<String>,
    pub creator: Option<String>,
    pub agent: Option<String>,
    pub deadline_after: Option<u64>,
    pub deadline_before: Option<u64>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

fn parse_address(value: &str) -> Result<MsgAddressInt, AppError> {
    MsgAddressInt::from_str(value).map_err(|_| AppError::bad_request("invalid TOS address"))
}

// Mirrors the FunC contract's `status::*` constants exactly (see
// `crypto/smartcont/task-escrow-code.fc`): 0 open, 1 accepted,
// 2 result_submitted, 3 settled, 4 cancelled, 5 expired, 6 rejected,
// 7 disputed. Keep in sync with `indexer::indexer_task::task_status_name`,
// which decodes the same on-chain field for chain-wide-discovered tasks.
fn status_name(status: u8) -> &'static str {
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

fn task_dto(name: Option<String>, address: String, data: contracts::TaskEscrowData) -> TaskDto {
    TaskDto {
        name,
        address,
        creator: data.creator.to_string(),
        assigned_agent: data.assigned_agent.map(|v| v.to_string()),
        verifier: data.verifier.map(|v| v.to_string()),
        budget: data.budget,
        deadline: data.deadline,
        review_period: data.review_period,
        review_deadline: data.review_deadline,
        status: status_name(data.status).to_owned(),
        result_hash: hex::encode(data.result_hash),
        evidence_hash: hex::encode(data.evidence_hash),
        settlement_policy_hash: hex::encode(data.settlement_policy_hash),
        permission_hash: hex::encode(data.permission_hash),
        dispute_hash: hex::encode(data.dispute_hash),
    }
}

/// Runs a get-method against `address` with a bounded timeout, and classifies
/// the failure modes into stable API error kinds:
///
/// - the call exceeds [`CHAIN_QUERY_TIMEOUT`] -> `timeout`
/// - the RPC round-trip succeeds but the get-method itself reports a
///   non-zero exit code (the normal shape of "no such contract state at this
///   address", e.g. an inactive or wrong-code account) -> `not_found`
/// - the RPC round-trip itself fails (transport/connection error) ->
///   `rpc_unavailable`
///
/// The raw error is always preserved in the tracing logs; only a safe,
/// generic message reaches the HTTP client.
async fn run_get_method(
    state: &AppState,
    address: &MsgAddressInt,
    method: &'static str,
) -> Result<TvmStackParser, AppError> {
    run_get_method_with_args(state, address, method, vec![]).await
}

/// As [`run_get_method`], but for a get-method that takes stack arguments
/// (e.g. `get_request(request_id)`) rather than none.
async fn run_get_method_with_args(
    state: &AppState,
    address: &MsgAddressInt,
    method: &'static str,
    args: Vec<tl_api::tos::tvm::StackEntry>,
) -> Result<TvmStackParser, AppError> {
    let provider = state.runtime_cfg.chain_provider();
    let call = provider.run_get_method(address.to_string(), method, args);
    match tokio::time::timeout(CHAIN_QUERY_TIMEOUT, call).await {
        Ok(Ok(stack)) => Ok(stack),
        Ok(Err(e)) => {
            let detail = format!("{e:#}");
            tracing::warn!(
                target: "agent_query_api",
                address = %address,
                method,
                error = %detail,
                "chain get-method call failed"
            );
            // `DefaultChainProvider::run_get_method` formats a successful
            // RPC round-trip that exits non-zero as "...exit_code=N", and
            // wraps any other (transport-level) failure without that
            // marker. That is the only signal available to distinguish the
            // two cases without threading a structured error type through
            // the chain RPC client.
            if detail.contains("exit_code=") {
                Err(AppError::not_found(format!("no {method} state at this address")))
            } else {
                Err(AppError::rpc_unavailable("chain rpc endpoint unavailable"))
            }
        }
        Err(_) => {
            tracing::warn!(
                target: "agent_query_api",
                address = %address,
                method,
                "chain get-method call timed out"
            );
            Err(AppError::timeout(format!("{method} query timed out")))
        }
    }
}

async fn read_task(state: &AppState, address: &MsgAddressInt) -> Result<TaskDto, AppError> {
    let stack = run_get_method(state, address, "get_task_data").await?;
    let data = TaskEscrowContract::decode_data(&stack).map_err(|e| {
        tracing::warn!(
            target: "agent_query_api",
            address = %address,
            error = %format!("{e:#}"),
            "task escrow state decode failed"
        );
        AppError::invalid_contract_state("task escrow state could not be decoded")
    })?;
    Ok(task_dto(None, address.to_string(), data))
}

#[utoipa::path(get, path = "/agents/{address}", params(("address" = String, Path, description = "Agent Account address")), responses(
    (status = 200, body = AgentAccountResponse), (status = 400, body = ApiErrorResponse),
    (status = 404, body = ApiErrorResponse), (status = 422, body = ApiErrorResponse),
    (status = 503, body = ApiErrorResponse), (status = 504, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn get_agent(
    State(state): State<AppState>,
    Path(raw): Path<String>,
) -> Result<axum::Json<AgentAccountResponse>, AppError> {
    let address = parse_address(&raw)?;
    let stack = run_get_method(&state, &address, "get_agent_account_data").await?;
    let data = AgentAccountContract::decode_data(&stack).map_err(|e| {
        tracing::warn!(
            target: "agent_query_api",
            address = %address,
            error = %format!("{e:#}"),
            "agent account state decode failed"
        );
        AppError::invalid_contract_state("agent account state could not be decoded")
    })?;
    Ok(axum::Json(AgentAccountResponse {
        ok: true,
        result: AgentAccountDto {
            address: address.to_string(),
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
        },
    }))
}

#[utoipa::path(get, path = "/tasks/{address}", params(("address" = String, Path, description = "Task Escrow address")), responses(
    (status = 200, body = TaskResponse), (status = 400, body = ApiErrorResponse),
    (status = 404, body = ApiErrorResponse), (status = 422, body = ApiErrorResponse),
    (status = 503, body = ApiErrorResponse), (status = 504, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn get_task(
    State(state): State<AppState>,
    Path(raw): Path<String>,
) -> Result<axum::Json<TaskResponse>, AppError> {
    let address = parse_address(&raw)?;
    let task = read_task(&state, &address).await?;
    Ok(axum::Json(TaskResponse { ok: true, result: task }))
}

/// Fetches and decodes a single locally-registered task, never returning an
/// `Err`: any failure (invalid stored address, RPC failure, timeout, decode
/// failure) is captured on the `TaskListItem` itself so it cannot fail the
/// rest of the list.
async fn build_list_item(state: &AppState, name: String, raw: String) -> TaskListItem {
    match parse_address(&raw) {
        Ok(address) => match read_task(state, &address).await {
            Ok(mut task) => {
                task.name = Some(name.clone());
                TaskListItem { name, address: raw, task: Some(task), error: None, error_kind: None }
            }
            Err(e) => TaskListItem {
                name,
                address: raw,
                task: None,
                error: Some(e.message().to_owned()),
                error_kind: Some(e.kind().to_owned()),
            },
        },
        Err(_) => TaskListItem {
            name,
            address: raw,
            task: None,
            error: Some("invalid registered task address".to_owned()),
            error_kind: Some("invalid_request".to_owned()),
        },
    }
}

#[utoipa::path(get, path = "/tasks", params(TaskListQuery), responses(
    (status = 200, body = TaskListResponse), (status = 400, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn list_tasks(
    State(state): State<AppState>,
    Query(query): Query<TaskListQuery>,
) -> Result<axum::Json<TaskListResponse>, AppError> {
    if matches!((query.deadline_after, query.deadline_before), (Some(a), Some(b)) if a >= b) {
        return Err(AppError::bad_request("deadline_after must be less than deadline_before"));
    }
    if let Some(status) = query.status.as_deref() {
        if !matches!(
            status,
            "open"
                | "accepted"
                | "result_submitted"
                | "settled"
                | "cancelled"
                | "expired"
                | "rejected"
                | "disputed"
        ) {
            return Err(AppError::bad_request("invalid task status"));
        }
    }
    let creator = query.creator.as_deref().map(parse_address).transpose()?;
    let agent = query.agent.as_deref().map(parse_address).transpose()?;

    // Pre-filter on locally-recorded metadata (creator, deadline) before
    // touching the chain at all -- these fields are set at task creation and
    // never change, unlike status/assigned-agent which can change on-chain
    // (e.g. via `claim`) and are therefore filtered after the chain read below.
    let mut records = state
        .runtime_cfg
        .get()
        .agent_tasks
        .iter()
        .filter(|(_, v)| {
            creator
                .as_ref()
                .is_none_or(|x| v.creator.parse::<MsgAddressInt>().ok().as_ref() == Some(x))
        })
        .filter(|(_, v)| query.deadline_after.is_none_or(|x| v.deadline > x))
        .filter(|(_, v)| query.deadline_before.is_none_or(|x| v.deadline < x))
        .map(|(name, v)| (name.clone(), v.address.clone()))
        .collect::<Vec<_>>();
    records.sort_by(|a, b| a.0.cmp(&b.0));

    // Bounded-concurrency chain fan-out: at most MAX_CONCURRENT_TASK_READS
    // get-method calls in flight at once, each independently timed out, with
    // results written back into their original (deterministic, name-sorted)
    // slot regardless of completion order.
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TASK_READS));
    let mut handles = Vec::with_capacity(records.len());
    for (index, (name, raw)) in records.into_iter().enumerate() {
        let state = state.clone();
        let semaphore = Arc::clone(&semaphore);
        handles.push(tokio::spawn(async move {
            let _permit =
                semaphore.acquire_owned().await.expect("task-read semaphore never closed");
            (index, build_list_item(&state, name, raw).await)
        }));
    }
    let mut slots: Vec<Option<TaskListItem>> =
        std::iter::repeat_with(|| None).take(handles.len()).collect();
    for handle in handles {
        let (index, item) = handle.await.expect("task list read panicked");
        slots[index] = Some(item);
    }

    let mut result: Vec<TaskListItem> = slots
        .into_iter()
        .map(|item| item.expect("every dispatched slot is filled exactly once"))
        .collect();

    result.retain(|item| {
        let Some(task) = item.task.as_ref() else {
            // Keep chain-read failures visible in the listing rather than
            // silently dropping them; they still count toward pagination.
            return true;
        };
        if query.status.as_ref().is_some_and(|v| v != &task.status) {
            return false;
        }
        if agent.as_ref().is_some_and(|v| task.assigned_agent.as_deref() != Some(&v.to_string())) {
            return false;
        }
        true
    });

    // Merge in chain-wide discoveries the indexer knows about that this
    // operator's local config does not (e.g. a Task Escrow some other
    // operator deployed). Local-config entries always win on address
    // collision, since they carry a human-assigned `name`; this only adds
    // addresses not already present.
    let known_addrs: std::collections::HashSet<String> =
        result.iter().map(|item| item.address.clone()).collect();
    let creator_str = creator.as_ref().map(|a| a.to_string());
    let filters = crate::indexer::ListFilters {
        creator: creator_str.as_deref(),
        status: query.status.as_deref(),
        deadline_after: query.deadline_after,
        deadline_before: query.deadline_before,
    };
    if let Ok((indexed, _)) = state.indexer_store.list("task_escrow", &filters, 0, 10_000) {
        for rec in indexed {
            if known_addrs.contains(&rec.address) {
                continue;
            }
            if let Some(agent) = &agent {
                if rec.counterparty.as_deref() != Some(agent.to_string().as_str()) {
                    continue;
                }
            }
            let Some(task) = indexed_dto::<TaskDto>(&rec.dto_json, &rec.address, true) else {
                continue;
            };
            result.push(TaskListItem {
                name: rec.address.clone(),
                address: rec.address,
                task: Some(task),
                error: None,
                error_kind: None,
            });
        }
    }

    let total = result.len();
    let offset = query.offset.unwrap_or(0).min(total);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let result = result.into_iter().skip(offset).take(limit).collect();
    Ok(axum::Json(TaskListResponse { ok: true, total, offset, limit, result }))
}

/// Decodes an [`crate::indexer::IndexerStore`] record's `dto_json` into a
/// concrete DTO type, patching in the `address` field the indexer doesn't
/// store inline (and `name: null` when the DTO has a `name` field, for the
/// Task Escrow DTO shared with the local-config-backed listing path).
pub(crate) fn indexed_dto<T: serde::de::DeserializeOwned>(
    dto_json: &str,
    address: &str,
    has_name_field: bool,
) -> Option<T> {
    let mut value: serde_json::Value = serde_json::from_str(dto_json).ok()?;
    if has_name_field {
        value["name"] = serde_json::Value::Null;
    }
    value["address"] = serde_json::Value::String(address.to_owned());
    serde_json::from_value(value).ok()
}

// ─── Chain-wide indexer-backed listings: Dispute / Service Actor / ────────
// ─── Capability Registry ───────────────────────────────────────────────────
//
// Unlike `/tasks` (which predates the indexer and still primarily reads a
// local per-operator registry), these three endpoints are indexer-only from
// the start: there was no chain-wide way to enumerate any of these contract
// types before the indexer existed, so there is no legacy local-config path
// to preserve.

#[derive(Clone, Default, serde::Deserialize, utoipa::IntoParams)]
pub struct IndexedListQuery {
    pub status: Option<String>,
    pub creator: Option<String>,
    pub deadline_after: Option<u64>,
    pub deadline_before: Option<u64>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

fn validate_indexed_query(query: &IndexedListQuery) -> Result<(), AppError> {
    if matches!((query.deadline_after, query.deadline_before), (Some(a), Some(b)) if a >= b) {
        return Err(AppError::bad_request("deadline_after must be less than deadline_before"));
    }
    if let Some(creator) = query.creator.as_deref() {
        parse_address(creator)?;
    }
    Ok(())
}

fn indexed_list_filters(query: &IndexedListQuery) -> crate::indexer::ListFilters<'_> {
    crate::indexer::ListFilters {
        creator: query.creator.as_deref(),
        status: query.status.as_deref(),
        deadline_after: query.deadline_after,
        deadline_before: query.deadline_before,
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct DisputeDto {
    pub address: String,
    pub claimant: String,
    pub respondent: String,
    pub reviewer: String,
    pub status: String,
    pub ruling: u8,
    pub split_bps: u16,
    pub deadline: u64,
    pub subject_hash: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct DisputeResponse {
    pub ok: bool,
    pub result: DisputeDto,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct DisputeListResponse {
    pub ok: bool,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub result: Vec<DisputeDto>,
}

#[utoipa::path(get, path = "/disputes", params(IndexedListQuery), responses(
    (status = 200, body = DisputeListResponse), (status = 400, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn list_disputes(
    State(state): State<AppState>,
    Query(query): Query<IndexedListQuery>,
) -> Result<axum::Json<DisputeListResponse>, AppError> {
    validate_indexed_query(&query)?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let (rows, total) = state
        .indexer_store
        .list("dispute", &indexed_list_filters(&query), offset, limit)
        .map_err(|e| AppError::internal(format!("{e:#}")))?;
    let result = rows
        .into_iter()
        .filter_map(|r| indexed_dto::<DisputeDto>(&r.dto_json, &r.address, false))
        .collect();
    Ok(axum::Json(DisputeListResponse { ok: true, total, offset, limit, result }))
}

#[utoipa::path(get, path = "/disputes/{address}", params(("address" = String, Path, description = "Dispute address")), responses(
    (status = 200, body = DisputeResponse), (status = 400, body = ApiErrorResponse),
    (status = 404, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn get_dispute(
    State(state): State<AppState>,
    Path(raw): Path<String>,
) -> Result<axum::Json<DisputeResponse>, AppError> {
    let address = parse_address(&raw)?;
    let rec = state
        .indexer_store
        .get(&address.to_string())
        .map_err(|e| AppError::internal(format!("{e:#}")))?
        .filter(|r| r.kind == "dispute")
        .ok_or_else(|| AppError::not_found("no dispute indexed at this address"))?;
    let result =
        indexed_dto::<DisputeDto>(&rec.dto_json, &rec.address, false).ok_or_else(|| {
            AppError::invalid_contract_state("indexed dispute record could not be decoded")
        })?;
    Ok(axum::Json(DisputeResponse { ok: true, result }))
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ServiceActorDto {
    pub address: String,
    pub owner: String,
    pub authorized_caller: Option<String>,
    pub open_access: bool,
    pub status: String,
    pub price_per_call: u64,
    pub rate_limit_per_day: u32,
    /// Nominal earned-revenue counter (see the concurrent-escrow design doc's
    /// Financial Accounting section) -- the closest single-number analog to
    /// the single-slot contract's old `total_revenue`. The actual amount the
    /// owner can withdraw right now may be lower; this is a summary/
    /// monitoring signal, not a live balance query.
    pub withdrawable_revenue: u64,
    /// Outstanding, unanswered requests.
    pub pending_count: u32,
    /// Pending + refundable-but-unclaimed requests combined -- the quantity
    /// this contract's capacity limits actually cap.
    pub live_count: u32,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ServiceActorResponse {
    pub ok: bool,
    pub result: ServiceActorDto,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ServiceActorListResponse {
    pub ok: bool,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub result: Vec<ServiceActorDto>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ServiceRequestLifecycleDto {
    pub service_address: String,
    pub request_id: u64,
    pub status: String,
    pub caller: Option<String>,
    pub price: Option<u64>,
    pub storage_fee: Option<u64>,
    pub cleanup_bounty: Option<u64>,
    pub response_deadline: Option<u64>,
    pub refund_claim_deadline: Option<u64>,
    pub policy_version: Option<u32>,
    pub request_hash: Option<String>,
    pub terms_hash: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ServiceRequestLifecycleResponse {
    pub ok: bool,
    pub result: ServiceRequestLifecycleDto,
}

#[utoipa::path(get, path = "/services", params(IndexedListQuery), responses(
    (status = 200, body = ServiceActorListResponse), (status = 400, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn list_services(
    State(state): State<AppState>,
    Query(query): Query<IndexedListQuery>,
) -> Result<axum::Json<ServiceActorListResponse>, AppError> {
    validate_indexed_query(&query)?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let (rows, total) = state
        .indexer_store
        .list("service_actor", &indexed_list_filters(&query), offset, limit)
        .map_err(|e| AppError::internal(format!("{e:#}")))?;
    let result = rows
        .into_iter()
        .filter_map(|r| indexed_dto::<ServiceActorDto>(&r.dto_json, &r.address, false))
        .collect();
    Ok(axum::Json(ServiceActorListResponse { ok: true, total, offset, limit, result }))
}

#[utoipa::path(get, path = "/services/{address}", params(("address" = String, Path, description = "Service Actor address")), responses(
    (status = 200, body = ServiceActorResponse), (status = 400, body = ApiErrorResponse),
    (status = 404, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn get_service(
    State(state): State<AppState>,
    Path(raw): Path<String>,
) -> Result<axum::Json<ServiceActorResponse>, AppError> {
    let address = parse_address(&raw)?;
    let rec = state
        .indexer_store
        .get(&address.to_string())
        .map_err(|e| AppError::internal(format!("{e:#}")))?
        .filter(|r| r.kind == "service_actor")
        .ok_or_else(|| AppError::not_found("no service actor indexed at this address"))?;
    let result =
        indexed_dto::<ServiceActorDto>(&rec.dto_json, &rec.address, false).ok_or_else(|| {
            AppError::invalid_contract_state("indexed service actor record could not be decoded")
        })?;
    Ok(axum::Json(ServiceActorResponse { ok: true, result }))
}

/// Reads the authoritative live request/refund state. Terminal entries are
/// deliberately absent from contract storage, so `resolved_or_unknown`
/// means callers should consult the lifecycle index for its final outcome.
#[utoipa::path(
    get,
    path = "/services/{address}/requests/{request_id}",
    params(
        ("address" = String, Path, description = "Service Actor address"),
        ("request_id" = u64, Path, description = "Contract-assigned request ID")
    ),
    responses((status = 200, body = ServiceRequestLifecycleResponse),
        (status = 400, body = ApiErrorResponse)),
    security(("bearerAuth" = []))
)]
pub async fn get_service_request(
    State(state): State<AppState>,
    Path((raw, request_id)): Path<(String, u64)>,
) -> Result<axum::Json<ServiceRequestLifecycleResponse>, AppError> {
    let address = parse_address(&raw)?;
    if let Some(record) = state
        .indexer_store
        .service_request(&address.to_string(), request_id)
        .map_err(|e| AppError::internal(format!("{e:#}")))?
        .filter(|r| matches!(r.status.as_str(), "responded" | "refunded" | "swept"))
    {
        let result = serde_json::from_str(&record.dto_json)
            .map_err(|e| AppError::invalid_contract_state(format!("{e:#}")))?;
        return Ok(axum::Json(ServiceRequestLifecycleResponse { ok: true, result }));
    }
    let arg = vec![contracts::stack_utils::u64_to_stack_entry(request_id)];
    let request = ServiceActorContract::decode_request(
        &run_get_method_with_args(&state, &address, "get_request", arg.clone()).await?,
    )
    .map_err(|e| AppError::invalid_contract_state(format!("{e:#}")))?;
    let refund = if request.is_none() {
        ServiceActorContract::decode_refund(
            &run_get_method_with_args(&state, &address, "get_refund", arg).await?,
        )
        .map_err(|e| AppError::invalid_contract_state(format!("{e:#}")))?
    } else {
        None
    };
    let result = match (request, refund) {
        (Some(r), _) => ServiceRequestLifecycleDto {
            service_address: address.to_string(),
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
        },
        (_, Some(r)) => ServiceRequestLifecycleDto {
            service_address: address.to_string(),
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
        },
        _ => ServiceRequestLifecycleDto {
            service_address: address.to_string(),
            request_id,
            status: "resolved_or_unknown".into(),
            caller: None,
            price: None,
            storage_fee: None,
            cleanup_bounty: None,
            response_deadline: None,
            refund_claim_deadline: None,
            policy_version: None,
            request_hash: None,
            terms_hash: None,
        },
    };
    Ok(axum::Json(ServiceRequestLifecycleResponse { ok: true, result }))
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct RegistryDto {
    pub address: String,
    pub owner: String,
    pub verifier: Option<String>,
    pub status: String,
    pub registered_at: u64,
    pub bond: u64,
    pub reputation_score: i64,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct RegistryResponse {
    pub ok: bool,
    pub result: RegistryDto,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct RegistryListResponse {
    pub ok: bool,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub result: Vec<RegistryDto>,
}

#[utoipa::path(get, path = "/registry", params(IndexedListQuery), responses(
    (status = 200, body = RegistryListResponse), (status = 400, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn list_registry(
    State(state): State<AppState>,
    Query(query): Query<IndexedListQuery>,
) -> Result<axum::Json<RegistryListResponse>, AppError> {
    validate_indexed_query(&query)?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let (rows, total) = state
        .indexer_store
        .list("capability_registry", &indexed_list_filters(&query), offset, limit)
        .map_err(|e| AppError::internal(format!("{e:#}")))?;
    let result = rows
        .into_iter()
        .filter_map(|r| indexed_dto::<RegistryDto>(&r.dto_json, &r.address, false))
        .collect();
    Ok(axum::Json(RegistryListResponse { ok: true, total, offset, limit, result }))
}

#[utoipa::path(get, path = "/registry/{address}", params(("address" = String, Path, description = "Capability Registry address")), responses(
    (status = 200, body = RegistryResponse), (status = 400, body = ApiErrorResponse),
    (status = 404, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn get_registry(
    State(state): State<AppState>,
    Path(raw): Path<String>,
) -> Result<axum::Json<RegistryResponse>, AppError> {
    let address = parse_address(&raw)?;
    let rec = state
        .indexer_store
        .get(&address.to_string())
        .map_err(|e| AppError::internal(format!("{e:#}")))?
        .filter(|r| r.kind == "capability_registry")
        .ok_or_else(|| {
            AppError::not_found("no capability registry entry indexed at this address")
        })?;
    let result =
        indexed_dto::<RegistryDto>(&rec.dto_json, &rec.address, false).ok_or_else(|| {
            AppError::invalid_contract_state(
                "indexed capability registry record could not be decoded",
            )
        })?;
    Ok(axum::Json(RegistryResponse { ok: true, result }))
}

// --- AIPoW score commitments (chain-wide, indexer-backed) ---

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AipowCommitmentDto {
    pub address: String,
    pub committer: String,
    pub reviewer: String,
    /// `committed`, `challenged`, `final`, or `rejected`.
    pub status: String,
    pub epoch: u64,
    pub window_deadline: u64,
    /// Zero until challenged; then the challenge time plus the review window,
    /// after which the commitment can be failed safe permissionlessly.
    #[serde(default)]
    pub review_deadline: u64,
    pub commit_bond: u64,
    pub challenge_bond: u64,
    pub score_root: String,
    pub methodology_hash: String,
    /// The committed pro-rata denominator (decimal string, u128).
    #[serde(default)]
    pub total_score: String,
    /// The committed epoch organic settled value (decimal string, u128).
    #[serde(default)]
    pub organic_settled_value: String,
    /// The zero address until a challenge is recorded.
    pub challenger: String,
    pub challenge_evidence_hash: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AipowCommitmentListResponse {
    pub ok: bool,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub result: Vec<AipowCommitmentDto>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AipowCommitmentResponse {
    pub ok: bool,
    pub result: AipowCommitmentDto,
}

#[utoipa::path(get, path = "/aipow/commitments", params(IndexedListQuery), responses(
    (status = 200, body = AipowCommitmentListResponse), (status = 400, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn list_aipow_commitments(
    State(state): State<AppState>,
    Query(query): Query<IndexedListQuery>,
) -> Result<axum::Json<AipowCommitmentListResponse>, AppError> {
    validate_indexed_query(&query)?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let (rows, total) = state
        .indexer_store
        .list("aipow_commitment", &indexed_list_filters(&query), offset, limit)
        .map_err(|e| AppError::internal(format!("{e:#}")))?;
    let result = rows
        .into_iter()
        .filter_map(|r| indexed_dto::<AipowCommitmentDto>(&r.dto_json, &r.address, false))
        .collect();
    Ok(axum::Json(AipowCommitmentListResponse { ok: true, total, offset, limit, result }))
}

#[utoipa::path(get, path = "/aipow/commitments/{address}", params(("address" = String, Path, description = "AIPoW score-commitment address")), responses(
    (status = 200, body = AipowCommitmentResponse), (status = 400, body = ApiErrorResponse),
    (status = 404, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn get_aipow_commitment(
    State(state): State<AppState>,
    Path(raw): Path<String>,
) -> Result<axum::Json<AipowCommitmentResponse>, AppError> {
    let address = parse_address(&raw)?;
    let rec = state
        .indexer_store
        .get(&address.to_string())
        .map_err(|e| AppError::internal(format!("{e:#}")))?
        .filter(|r| r.kind == "aipow_commitment")
        .ok_or_else(|| AppError::not_found("no AIPoW score commitment indexed at this address"))?;
    let result =
        indexed_dto::<AipowCommitmentDto>(&rec.dto_json, &rec.address, false).ok_or_else(|| {
            AppError::invalid_contract_state(
                "indexed AIPoW score-commitment record could not be decoded",
            )
        })?;
    Ok(axum::Json(AipowCommitmentResponse { ok: true, result }))
}

// --- AIPoW reward distributors (chain-wide, indexer-backed) ---

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AipowDistributorDto {
    pub address: String,
    pub operator: String,
    pub epoch: u64,
    /// The epoch total score (pro-rata denominator), as a decimal string
    /// because it is a u128.
    pub total_score: String,
    pub pool: u64,
    pub claimed_count: u32,
    /// Running sum of claimed scores (decimal string, u128); held at or below
    /// `total_score` so the aggregate recorded amount cannot exceed `pool`.
    #[serde(default)]
    pub claimed_score: String,
    pub score_root: String,
    pub commitment_ref: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AipowDistributorListResponse {
    pub ok: bool,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub result: Vec<AipowDistributorDto>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AipowDistributorResponse {
    pub ok: bool,
    pub result: AipowDistributorDto,
}

#[utoipa::path(get, path = "/aipow/distributors", params(IndexedListQuery), responses(
    (status = 200, body = AipowDistributorListResponse), (status = 400, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn list_aipow_distributors(
    State(state): State<AppState>,
    Query(query): Query<IndexedListQuery>,
) -> Result<axum::Json<AipowDistributorListResponse>, AppError> {
    validate_indexed_query(&query)?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let (rows, total) = state
        .indexer_store
        .list("aipow_distributor", &indexed_list_filters(&query), offset, limit)
        .map_err(|e| AppError::internal(format!("{e:#}")))?;
    let result = rows
        .into_iter()
        .filter_map(|r| indexed_dto::<AipowDistributorDto>(&r.dto_json, &r.address, false))
        .collect();
    Ok(axum::Json(AipowDistributorListResponse { ok: true, total, offset, limit, result }))
}

#[utoipa::path(get, path = "/aipow/distributors/{address}", params(("address" = String, Path, description = "AIPoW distributor address")), responses(
    (status = 200, body = AipowDistributorResponse), (status = 400, body = ApiErrorResponse),
    (status = 404, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn get_aipow_distributor(
    State(state): State<AppState>,
    Path(raw): Path<String>,
) -> Result<axum::Json<AipowDistributorResponse>, AppError> {
    let address = parse_address(&raw)?;
    let rec = state
        .indexer_store
        .get(&address.to_string())
        .map_err(|e| AppError::internal(format!("{e:#}")))?
        .filter(|r| r.kind == "aipow_distributor")
        .ok_or_else(|| AppError::not_found("no AIPoW distributor indexed at this address"))?;
    let result = indexed_dto::<AipowDistributorDto>(&rec.dto_json, &rec.address, false)
        .ok_or_else(|| {
            AppError::invalid_contract_state(
                "indexed AIPoW distributor record could not be decoded",
            )
        })?;
    Ok(axum::Json(AipowDistributorResponse { ok: true, result }))
}

// --- AIPoW shadow-scoring data plane ---
//
// Settlement events observed by the chain indexer, exposed for the AIPoW
// scorer's phase-A shadow scoring. This is the interim, tosctld-served
// form of the settled-work surface; the node-side JSON-RPC method that
// eventually supersedes it must serve the same rows. The evidence field
// applies the published phase-A interim mapping: a settlement on a
// contract deployed with an attestor key is `Attested` (its settle/
// respond op carried a verified attestor signature), any other real
// settlement is `Observed`. Capability classes, measured work units, and
// rate-card values are not on chain yet, so consumers value work by the
// settled amount until the settlement-receipt schema lands.

#[derive(Clone, Default, serde::Deserialize, utoipa::IntoParams)]
pub struct AipowSettledWorkQuery {
    pub from_seqno: Option<u32>,
    pub to_seqno: Option<u32>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AipowSettledWorkDto {
    pub address: String,
    /// Empty for Task Escrow settlements; the request number for Service
    /// Actor responses.
    pub request_id: String,
    /// `task_escrow` or `service_request`.
    pub kind: String,
    pub earner: String,
    pub payer: String,
    /// Settled amount in nanotos.
    pub amount: u64,
    /// Phase-A interim evidence mapping: `Attested` or `Observed`.
    pub evidence: String,
    /// Block seqno at which the settlement was observed by the scan (an
    /// upper bound on the executing block).
    pub seqno: u32,
    pub observed_at: u64,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AipowSettledWorkResponse {
    pub ok: bool,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub result: Vec<AipowSettledWorkDto>,
}

#[utoipa::path(get, path = "/aipow/settled-work", params(AipowSettledWorkQuery), responses(
    (status = 200, body = AipowSettledWorkResponse), (status = 400, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn list_aipow_settled_work(
    State(state): State<AppState>,
    Query(query): Query<AipowSettledWorkQuery>,
) -> Result<axum::Json<AipowSettledWorkResponse>, AppError> {
    let from_seqno = query.from_seqno.unwrap_or(0);
    let to_seqno = query.to_seqno.unwrap_or(u32::MAX);
    if from_seqno > to_seqno {
        return Err(AppError::bad_request("from_seqno must not exceed to_seqno"));
    }
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let (rows, total) = state
        .indexer_store
        .list_aipow_settlements(from_seqno, to_seqno, offset, limit)
        .map_err(|e| AppError::internal(format!("{e:#}")))?;
    let result = rows
        .into_iter()
        .map(|r| AipowSettledWorkDto {
            address: r.address,
            request_id: r.request_id,
            kind: r.kind,
            earner: r.earner,
            payer: r.payer,
            amount: r.amount,
            evidence: if r.attested { "Attested" } else { "Observed" }.to_owned(),
            seqno: r.seqno,
            observed_at: r.observed_at,
        })
        .collect();
    Ok(axum::Json(AipowSettledWorkResponse { ok: true, total, offset, limit, result }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{jwt::JwtAuth, user_store::UserStore},
        http::{http_server_task::routes, login_rate_limiter::LoginRateLimiter},
        runtime_config::RuntimeConfigStore,
        task::task_manager::{ServiceTask, TaskController},
    };
    use axum::body::Body;
    use axum::http::Request;
    use base64::Engine;
    use chain_block::Cell;
    use common::{
        app_config::{AgentTaskConfig, AppConfig, ChainRpcConfig, HttpConfig},
        snapshot::SnapshotStore,
        task_cancellation::CancellationCtx,
    };
    use contracts::{
        AgentAccountContract, AgentAccountInit, ChainProvider, ServiceActorInit,
        TaskEscrowContract, TaskEscrowInit,
    };
    use std::sync::Mutex as StdMutex;
    use tos_sandbox::{Blockchain, MessageBuilder, Treasury};
    use tower::ServiceExt;

    struct NoopTask;

    #[async_trait::async_trait]
    impl ServiceTask for NoopTask {
        async fn run(
            &self,
            cancellation_ctx: CancellationCtx,
            _app_config: std::sync::Arc<AppConfig>,
        ) -> anyhow::Result<()> {
            let mut cancel = cancellation_ctx.subscribe();
            let _ = cancel.changed().await;
            Ok(())
        }
    }

    fn test_app_config() -> Arc<AppConfig> {
        Arc::new(AppConfig {
            nodes: Default::default(),
            wallets: Default::default(),
            agent_wallets: Default::default(),
            capability_registries: Default::default(),
            service_actors: Default::default(),
            disputes: Default::default(),
            proof_attestations: Default::default(),
            aipow_commitments: Default::default(),
            aipow_distributors: Default::default(),
            agent_tasks: Default::default(),
            pools: Default::default(),
            bindings: Default::default(),
            chain_rpc: ChainRpcConfig::default(),
            elections: None,
            voting: None,
            http: HttpConfig { auth: None, ..Default::default() },
            master_wallet: None,
            tick_interval: 30,
            log: None,
            bookmarks: Default::default(),
            alerts: Default::default(),
        })
    }

    async fn test_state_with_provider(
        app_config: Arc<AppConfig>,
        provider: Arc<dyn ChainProvider>,
    ) -> AppState {
        let store = Arc::new(SnapshotStore::new());
        let runtime_cfg =
            Arc::new(RuntimeConfigStore::from_app_config_with_chain_provider(app_config, provider));
        let elections_task = Arc::new(TaskController::new(
            "elections",
            NoopTask,
            runtime_cfg.clone() as Arc<dyn RuntimeConfig>,
        ));
        let user_store = Arc::new(UserStore::new(runtime_cfg.clone() as Arc<dyn RuntimeConfig>));
        let secret = base64::engine::general_purpose::STANDARD.encode([42u8; 32]);
        let jwt_auth = Arc::new(JwtAuth::new(None, Some(&secret)).await.unwrap());
        AppState {
            store,
            runtime_cfg,
            elections_task,
            jwt_auth,
            user_store,
            login_rate_limiter: Arc::new(tokio::sync::Mutex::new(LoginRateLimiter::default())),
            indexer_store: Arc::new(crate::indexer::IndexerStore::open_in_memory().unwrap()),
        }
    }

    async fn json_body(response: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn get(uri: impl Into<String>) -> Request<Body> {
        Request::builder().uri(uri.into()).body(Body::empty()).unwrap()
    }

    /// A [`ChainProvider`] backed by a real, in-process `tos_sandbox`
    /// blockchain: get-method calls execute the actual compiled contract
    /// bytecode against real (deployed) contract state, giving these
    /// HTTP-layer tests genuine on-chain semantics without a live
    /// multi-process localnet. Only address plumbing and RPC framing are
    /// stubbed; contract logic and state are real.
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
                result.stack.iter().map(stack_item_to_entry).collect::<anyhow::Result<Vec<_>>>()?;
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

    /// Converts one sandbox VM stack item into the wire `StackEntry` shape
    /// that `TvmStackParser` (and therefore `AgentAccountContract`/
    /// `TaskEscrowContract::decode_data`) expects, mirroring what a real
    /// JSON-RPC server does when serializing get-method results.
    fn stack_item_to_entry(
        item: &tos_vm::stack::StackItem,
    ) -> anyhow::Result<tl_api::tos::tvm::StackEntry> {
        use tl_api::tos::tvm::{
            Number, StackEntry,
            numberdecimal::NumberDecimal,
            slice,
            stackentry::{StackEntryNumber, StackEntrySlice},
        };
        if let Ok(int) = item.as_integer() {
            // Stack hashes are pushed as full 256-bit integers, which don't
            // fit in i128 -- go through `IntegerData`'s arbitrary-precision
            // decimal `Display` (matching `TvmStackParser::number_bytes`,
            // which parses this same decimal-string shape via `BigUint`)
            // instead of `as_integer_value`.
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
        anyhow::bail!("unsupported sandbox stack item for HTTP query API tests")
    }

    struct Fixture {
        provider: Arc<SandboxChainProvider>,
        creator: Treasury,
        agent: Treasury,
    }

    impl Fixture {
        fn new() -> Self {
            let mut bc = Blockchain::new().expect("blockchain");
            bc.set_workchain(-1);
            let creator = bc.treasury("creator", 1_000_000_000_000).expect("creator");
            let agent = bc.treasury("agent", 1_000_000_000_000).expect("agent");
            Fixture {
                provider: Arc::new(SandboxChainProvider { bc: StdMutex::new(bc) }),
                creator,
                agent,
            }
        }

        fn deploy_task(&self, budget: u64, deadline: u64, assigned: bool) -> MsgAddressInt {
            let init = TaskEscrowInit {
                creator: self.creator.address().clone(),
                assigned_agent: assigned.then(|| self.agent.address().clone()),
                verifier: None,
                budget,
                deadline,
                review_period: 3_600,
                settlement_policy_hash: [0x33; 32],
                permission_hash: [0x77; 32],
                attestor_pubkey: None,
            };
            let address = TaskEscrowContract::calculate_address(-1, &init).expect("address");
            let state_init = TaskEscrowContract::build_state_init(&init).expect("state init");
            let deploy =
                MessageBuilder::internal(self.creator.address(), &address, budget + 500_000_000)
                    .bounce(false)
                    .state_init(state_init)
                    .body(Cell::default())
                    .build();
            self.provider
                .bc
                .lock()
                .expect("lock")
                .send_message(deploy)
                .expect("deploy")
                .expect_success();
            address
        }

        fn deploy_service_with_request(&self) -> MsgAddressInt {
            let init = ServiceActorInit {
                owner: self.creator.address().clone(),
                authorized_caller: None,
                open_access: true,
                price_per_call: 100_000_000,
                storage_fee: 200_000_000,
                cleanup_bounty: 100_000_000,
                rate_limit_per_day: 0,
                response_sla: 3_600,
                refund_claim_window: 3_600,
                metadata_hash: [0x11; 32],
                proof_scheme_hash: [0x22; 32],
                attestor_pubkey: None,
            };
            let address = ServiceActorContract::calculate_address(-1, &init).unwrap();
            let deploy = MessageBuilder::internal(self.creator.address(), &address, 2_000_000_000)
                .bounce(false)
                .state_init(ServiceActorContract::build_state_init(&init).unwrap())
                .body(Cell::default())
                .build();
            let mut bc = self.provider.bc.lock().expect("lock");
            bc.send_message(deploy).unwrap().expect_success();
            let call = MessageBuilder::internal(self.agent.address(), &address, 500_000_000)
                .body(ServiceActorContract::call(7, [0xAB; 32]).unwrap())
                .build();
            bc.send_message(call).unwrap().expect_success();
            address
        }

        /// Sends `accept` from `self.agent`, transitioning the task from
        /// `open` to `accepted`. Deploying with `assigned: true` only fixes
        /// who *may* accept -- it does not itself change status.
        fn accept_task(&self, address: &MsgAddressInt) {
            let accept = MessageBuilder::internal(self.agent.address(), address, 100_000_000)
                .body(TaskEscrowContract::accept(1).expect("accept body"))
                .build();
            self.provider
                .bc
                .lock()
                .expect("lock")
                .send_message(accept)
                .expect("accept")
                .expect_success();
        }

        fn deploy_agent_account(&self) -> MsgAddressInt {
            let init = AgentAccountInit {
                owner: self.creator.address().clone(),
                controller_pubkey: [0x01; 32],
                deployment_id: [0x02; 32],
                max_per_tx: 1_000_000_000,
                daily_limit: 10_000_000_000,
                default_task_timeout_secs: 3_600,
                metadata_hash: None,
                service_endpoint_hash: None,
            };
            let address = AgentAccountContract::calculate_address(-1, &init).expect("address");
            let state_init = AgentAccountContract::build_state_init(&init).expect("state init");
            let deploy = MessageBuilder::internal(self.creator.address(), &address, 1_000_000_000)
                .bounce(false)
                .state_init(state_init)
                .body(Cell::default())
                .build();
            self.provider
                .bc
                .lock()
                .expect("lock")
                .send_message(deploy)
                .expect("deploy")
                .expect_success();
            address
        }
    }

    #[tokio::test]
    async fn get_task_returns_real_sandbox_state() {
        let f = Fixture::new();
        let address = f.deploy_task(5_000_000_000, 2_000_000_000, true);
        let state = test_state_with_provider(test_app_config(), f.provider.clone()).await;
        let response =
            routes(false, state).oneshot(get(format!("/tasks/{address}"))).await.unwrap();
        assert_eq!(response.status(), 200);
        let v = json_body(response).await;
        assert_eq!(v["result"]["status"], "open");
        assert_eq!(v["result"]["budget"], 5_000_000_000u64);
        assert_eq!(v["result"]["creator"], f.creator.address().to_string());
        assert_eq!(v["result"]["assigned_agent"], f.agent.address().to_string());
    }

    #[tokio::test]
    async fn get_service_request_returns_authoritative_pending_state() {
        let fixture = Fixture::new();
        let service = fixture.deploy_service_with_request();
        let state = test_state_with_provider(test_app_config(), fixture.provider.clone()).await;
        let response = routes(false, state)
            .oneshot(get(format!("/services/{service}/requests/0")))
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["result"]["status"], "pending");
        assert_eq!(body["result"]["request_id"], 0);
        assert_eq!(body["result"]["request_hash"], "ab".repeat(32));
    }

    #[tokio::test]
    async fn get_agent_returns_real_sandbox_state() {
        let f = Fixture::new();
        let address = f.deploy_agent_account();
        let state = test_state_with_provider(test_app_config(), f.provider.clone()).await;
        let response =
            routes(false, state).oneshot(get(format!("/agents/{address}"))).await.unwrap();
        assert_eq!(response.status(), 200);
        let v = json_body(response).await;
        assert_eq!(v["result"]["owner"], f.creator.address().to_string());
        assert_eq!(v["result"]["max_per_tx"], 1_000_000_000u64);
    }

    #[tokio::test]
    async fn malformed_address_is_rejected_before_touching_the_chain() {
        let f = Fixture::new();
        let state = test_state_with_provider(test_app_config(), f.provider.clone()).await;
        let app = routes(false, state);

        let response = app.clone().oneshot(get("/tasks/not-an-address")).await.unwrap();
        assert_eq!(response.status(), 400);
        assert_eq!(json_body(response).await["error"]["kind"], "invalid_request");

        let response = app.oneshot(get("/agents/not-an-address")).await.unwrap();
        assert_eq!(response.status(), 400);
    }

    #[tokio::test]
    async fn wrong_method_selector_on_real_contract_is_not_found() {
        // A real, deployed Agent Account has no `get_task_data` selector, so
        // asking the Task Escrow decoder to read it hits a genuine non-zero
        // VM exit code -- the real-chain shape of "no such state here".
        let f = Fixture::new();
        let address = f.deploy_agent_account();
        let state = test_state_with_provider(test_app_config(), f.provider.clone()).await;
        let response =
            routes(false, state).oneshot(get(format!("/tasks/{address}"))).await.unwrap();
        assert_eq!(response.status(), 404);
        assert_eq!(json_body(response).await["error"]["kind"], "not_found");
    }

    #[tokio::test]
    async fn list_tasks_isolates_failures_and_preserves_order() {
        let f = Fixture::new();
        let open = f.deploy_task(1_000_000_000, 2_000_000_000, false);
        let assigned = f.deploy_task(2_000_000_000, 2_100_000_000, true);

        let mut app_config = (*test_app_config()).clone();
        app_config.agent_tasks.insert(
            "a-open".to_owned(),
            AgentTaskConfig {
                address: open.to_string(),
                creator: f.creator.address().to_string(),
                assigned_agent: None,
                verifier: None,
                permission_id: None,
                budget: 1_000_000_000,
                deadline: 2_000_000_000,
                review_period: 600,
                policy_hash: "33".repeat(32),
                attestor_pubkey: None,
                created_at: None,
            },
        );
        app_config.agent_tasks.insert(
            "b-assigned".to_owned(),
            AgentTaskConfig {
                address: assigned.to_string(),
                creator: f.creator.address().to_string(),
                assigned_agent: Some(f.agent.address().to_string()),
                verifier: None,
                permission_id: None,
                budget: 2_000_000_000,
                deadline: 2_100_000_000,
                review_period: 600,
                policy_hash: "33".repeat(32),
                attestor_pubkey: None,
                created_at: None,
            },
        );
        app_config.agent_tasks.insert(
            "c-broken".to_owned(),
            AgentTaskConfig {
                address: "not-an-address".to_owned(),
                creator: f.creator.address().to_string(),
                assigned_agent: None,
                verifier: None,
                permission_id: None,
                budget: 0,
                deadline: 0,
                review_period: 600,
                policy_hash: "33".repeat(32),
                attestor_pubkey: None,
                created_at: None,
            },
        );

        let state = test_state_with_provider(Arc::new(app_config), f.provider.clone()).await;
        let response = routes(false, state).oneshot(get("/tasks")).await.unwrap();
        assert_eq!(response.status(), 200);
        let v = json_body(response).await;
        let names: Vec<&str> = v["result"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["name"].as_str().unwrap())
            .collect();
        // Deterministic, name-sorted order preserved despite concurrent reads.
        assert_eq!(names, vec!["a-open", "b-assigned", "c-broken"]);
        assert_eq!(v["result"][0]["task"]["status"], "open");
        assert_eq!(v["result"][1]["task"]["status"], "open");
        assert_eq!(v["result"][2]["task"], serde_json::Value::Null);
        assert_eq!(v["result"][2]["error_kind"], "invalid_request");
        assert_eq!(v["total"], 3);
    }

    #[tokio::test]
    async fn status_and_agent_filters_use_live_chain_state() {
        let f = Fixture::new();
        let open = f.deploy_task(1_000_000_000, 2_000_000_000, false);
        let assigned = f.deploy_task(2_000_000_000, 2_100_000_000, true);
        // Move the assigned task past "open" so the status filter has two
        // genuinely different live states to distinguish, not just two
        // tasks that both happen to still be open.
        f.accept_task(&assigned);

        let mut app_config = (*test_app_config()).clone();
        for (name, addr, assigned_agent) in [
            ("a-open", open.to_string(), None),
            ("b-assigned", assigned.to_string(), Some(f.agent.address().to_string())),
        ] {
            app_config.agent_tasks.insert(
                name.to_owned(),
                AgentTaskConfig {
                    address: addr,
                    creator: f.creator.address().to_string(),
                    assigned_agent,
                    verifier: None,
                    permission_id: None,
                    budget: 1_000_000_000,
                    deadline: 2_000_000_000,
                    review_period: 600,
                    policy_hash: "33".repeat(32),
                    attestor_pubkey: None,
                    created_at: None,
                },
            );
        }

        let state = test_state_with_provider(Arc::new(app_config), f.provider.clone()).await;
        let app = routes(false, state);

        let response = app.clone().oneshot(get("/tasks?status=open")).await.unwrap();
        let v = json_body(response).await;
        assert_eq!(v["total"], 1);
        assert_eq!(v["result"][0]["name"], "a-open");

        let agent_addr = f.agent.address().to_string();
        let response = app.oneshot(get(format!("/tasks?agent={agent_addr}"))).await.unwrap();
        let v = json_body(response).await;
        assert_eq!(v["total"], 1);
        assert_eq!(v["result"][0]["name"], "b-assigned");
    }

    /// A [`ChainProvider`] double with one fixed, injected behavior. Used to
    /// exercise error classification paths that a real (or sandboxed)
    /// contract cannot naturally produce: a malformed/undecodable stack, a
    /// transport-level failure, and a call that never returns.
    enum FakeBehavior {
        Stack(Vec<tl_api::tos::tvm::StackEntry>),
        TransportError,
        Hang,
    }

    struct FakeChainProvider(FakeBehavior);

    #[async_trait::async_trait]
    impl ChainProvider for FakeChainProvider {
        async fn run_get_method(
            &self,
            _address: String,
            _method: &str,
            _stack: Vec<tl_api::tos::tvm::StackEntry>,
        ) -> anyhow::Result<TvmStackParser> {
            match &self.0 {
                FakeBehavior::Stack(entries) => Ok(TvmStackParser::new(entries.clone())),
                FakeBehavior::TransportError => {
                    Err(anyhow::anyhow!("connection refused (os error 111)"))
                }
                FakeBehavior::Hang => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    unreachable!("test timeout should fire first")
                }
            }
        }

        async fn get_balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
            anyhow::bail!("not supported by FakeChainProvider")
        }

        async fn send_boc(&self, _boc: &[u8]) -> anyhow::Result<()> {
            anyhow::bail!("not supported by FakeChainProvider")
        }

        async fn get_config_param(
            &self,
            _param_id: u32,
        ) -> anyhow::Result<chain_block::ConfigParamEnum> {
            anyhow::bail!("not supported by FakeChainProvider")
        }

        async fn get_address_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::AddressInfo> {
            anyhow::bail!("not supported by FakeChainProvider")
        }

        async fn get_extended_address_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::ExtendedAddressInfo> {
            anyhow::bail!("not supported by FakeChainProvider")
        }

        async fn get_wallet_info(
            &self,
            _address: &MsgAddressInt,
        ) -> anyhow::Result<contracts::chain_provider::WalletInfo> {
            anyhow::bail!("not supported by FakeChainProvider")
        }

        async fn get_masterchain_info(
            &self,
        ) -> anyhow::Result<contracts::chain_provider::MasterchainInfo> {
            anyhow::bail!("not supported by FakeChainProvider")
        }

        async fn get_shards(
            &self,
            _seqno: u32,
        ) -> anyhow::Result<contracts::chain_provider::ShardsInfo> {
            anyhow::bail!("not supported by FakeChainProvider")
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
            anyhow::bail!("not supported by FakeChainProvider")
        }
    }

    fn filler_address() -> MsgAddressInt {
        MsgAddressInt::with_standart(None, -1, [0x01; 32].into()).unwrap()
    }

    #[tokio::test]
    async fn decode_failure_is_reported_as_invalid_contract_state() {
        let provider: Arc<dyn ChainProvider> =
            Arc::new(FakeChainProvider(FakeBehavior::Stack(vec![])));
        let state = test_state_with_provider(test_app_config(), provider).await;
        let response = routes(false, state)
            .oneshot(get(format!("/tasks/{}", filler_address())))
            .await
            .unwrap();
        assert_eq!(response.status(), 422);
        assert_eq!(json_body(response).await["error"]["kind"], "invalid_contract_state");
    }

    #[tokio::test]
    async fn transport_failure_is_reported_as_rpc_unavailable() {
        let provider: Arc<dyn ChainProvider> =
            Arc::new(FakeChainProvider(FakeBehavior::TransportError));
        let state = test_state_with_provider(test_app_config(), provider).await;
        let response = routes(false, state)
            .oneshot(get(format!("/tasks/{}", filler_address())))
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(json_body(response).await["error"]["kind"], "rpc_unavailable");
    }

    #[tokio::test(start_paused = true)]
    async fn slow_chain_query_is_reported_as_timeout() {
        let provider: Arc<dyn ChainProvider> = Arc::new(FakeChainProvider(FakeBehavior::Hang));
        let state = test_state_with_provider(test_app_config(), provider).await;
        let response = routes(false, state)
            .oneshot(get(format!("/tasks/{}", filler_address())))
            .await
            .unwrap();
        assert_eq!(response.status(), 504);
        assert_eq!(json_body(response).await["error"]["kind"], "timeout");
    }

    #[tokio::test]
    async fn aipow_settled_work_lists_events_with_interim_evidence_mapping() {
        let f = Fixture::new();
        let state = test_state_with_provider(test_app_config(), f.provider.clone()).await;
        let seed = |request_id: &str, kind: &str, seqno: u32, attested: bool| {
            crate::indexer::AipowSettlementRecord {
                address: "0:contract".to_owned(),
                request_id: request_id.to_owned(),
                kind: kind.to_owned(),
                earner: "0:agent".to_owned(),
                payer: "0:consumer".to_owned(),
                amount: 750,
                attested,
                seqno,
                observed_at: 1_234,
            }
        };
        state.indexer_store.record_aipow_settlement(&seed("", "task_escrow", 5, true)).unwrap();
        state
            .indexer_store
            .record_aipow_settlement(&seed("3", "service_request", 9, false))
            .unwrap();

        let response = routes(false, state.clone())
            .oneshot(get("/aipow/settled-work?from_seqno=1&to_seqno=100"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let v = json_body(response).await;
        assert_eq!(v["total"], 2);
        let result = v["result"].as_array().unwrap();
        assert_eq!(result[0]["kind"], "task_escrow");
        assert_eq!(result[0]["evidence"], "Attested");
        assert_eq!(result[0]["seqno"], 5);
        assert_eq!(result[1]["kind"], "service_request");
        assert_eq!(result[1]["request_id"], "3");
        assert_eq!(result[1]["evidence"], "Observed");
        assert_eq!(result[1]["amount"], 750);

        // A range excluding both events lists nothing.
        let response = routes(false, state)
            .oneshot(get("/aipow/settled-work?from_seqno=50&to_seqno=100"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(json_body(response).await["total"], 0);
    }

    #[tokio::test]
    async fn aipow_settled_work_rejects_an_inverted_seqno_range() {
        let f = Fixture::new();
        let state = test_state_with_provider(test_app_config(), f.provider.clone()).await;
        let response = routes(false, state)
            .oneshot(get("/aipow/settled-work?from_seqno=10&to_seqno=2"))
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        assert_eq!(json_body(response).await["error"]["kind"], "invalid_request");
    }

    #[tokio::test]
    async fn aipow_commitments_list_and_lookup_from_the_indexer() {
        let f = Fixture::new();
        let state = test_state_with_provider(test_app_config(), f.provider.clone()).await;
        let address = "-1:".to_owned() + &"7".repeat(64);
        let dto = serde_json::json!({
            "committer": "-1:".to_owned() + &"1".repeat(64),
            "reviewer": "-1:".to_owned() + &"2".repeat(64),
            "status": "committed",
            "epoch": 42,
            "window_deadline": 1_900_000_000u64,
            "commit_bond": 5_000_000_000u64,
            "challenge_bond": 0,
            "score_root": "33".repeat(32),
            "methodology_hash": "44".repeat(32),
            "challenger": "0:".to_owned() + &"0".repeat(64),
            "challenge_evidence_hash": "0".repeat(64),
        });
        state
            .indexer_store
            .upsert(&crate::indexer::IndexedRecord {
                address: address.clone(),
                kind: "aipow_commitment".to_owned(),
                creator: Some("-1:".to_owned() + &"1".repeat(64)),
                counterparty: Some("-1:".to_owned() + &"2".repeat(64)),
                status: Some("committed".to_owned()),
                deadline: Some(1_900_000_000),
                last_seqno: 5,
                updated_at: 1_234,
                dto_json: dto.to_string(),
            })
            .unwrap();

        let response = routes(false, state.clone())
            .oneshot(get("/aipow/commitments?status=committed"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let v = json_body(response).await;
        assert_eq!(v["total"], 1);
        assert_eq!(v["result"][0]["address"], address);
        assert_eq!(v["result"][0]["epoch"], 42);
        assert_eq!(v["result"][0]["score_root"], "33".repeat(32));

        let response = routes(false, state.clone())
            .oneshot(get(format!("/aipow/commitments/{address}")))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let v = json_body(response).await;
        assert_eq!(v["result"]["status"], "committed");
        assert_eq!(v["result"]["commit_bond"], 5_000_000_000u64);

        // A non-commitment address 404s rather than leaking another kind.
        let missing = "-1:".to_owned() + &"9".repeat(64);
        let response = routes(false, state)
            .oneshot(get(format!("/aipow/commitments/{missing}")))
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }

    #[tokio::test]
    async fn aipow_distributors_list_and_lookup_from_the_indexer() {
        let f = Fixture::new();
        let state = test_state_with_provider(test_app_config(), f.provider.clone()).await;
        let address = "-1:".to_owned() + &"6".repeat(64);
        let dto = serde_json::json!({
            "operator": "-1:".to_owned() + &"1".repeat(64),
            "epoch": 42,
            "total_score": "1000000",
            "pool": 10_000_000_000u64,
            "claimed_count": 3,
            "score_root": "33".repeat(32),
            "commitment_ref": "99".repeat(32),
        });
        state
            .indexer_store
            .upsert(&crate::indexer::IndexedRecord {
                address: address.clone(),
                kind: "aipow_distributor".to_owned(),
                creator: Some("-1:".to_owned() + &"1".repeat(64)),
                counterparty: None,
                status: Some("claimed:3".to_owned()),
                deadline: None,
                last_seqno: 5,
                updated_at: 1_234,
                dto_json: dto.to_string(),
            })
            .unwrap();

        let response =
            routes(false, state.clone()).oneshot(get("/aipow/distributors")).await.unwrap();
        assert_eq!(response.status(), 200);
        let v = json_body(response).await;
        assert_eq!(v["total"], 1);
        assert_eq!(v["result"][0]["address"], address);
        assert_eq!(v["result"][0]["epoch"], 42);
        assert_eq!(v["result"][0]["total_score"], "1000000");
        assert_eq!(v["result"][0]["claimed_count"], 3);

        let response = routes(false, state.clone())
            .oneshot(get(format!("/aipow/distributors/{address}")))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let v = json_body(response).await;
        assert_eq!(v["result"]["pool"], 10_000_000_000u64);
        assert_eq!(v["result"]["score_root"], "33".repeat(32));

        let missing = "-1:".to_owned() + &"8".repeat(64);
        let response = routes(false, state)
            .oneshot(get(format!("/aipow/distributors/{missing}")))
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }
}
