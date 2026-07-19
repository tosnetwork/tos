/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
#[allow(unused_imports)]
use super::http_server_task::ApiErrorResponse;
use super::http_server_task::{AppError, AppState};
use crate::runtime_config::RuntimeConfig;
use axum::extract::{Path, Query, State};
use chain_block::MsgAddressInt;
use contracts::{AgentAccountContract, TaskEscrowContract};
use std::str::FromStr;

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AgentAccountDto {
    pub address: String,
    pub owner: String,
    pub controller_pubkey: String,
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
    pub error: Option<String>,
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

fn status_name(status: u8) -> &'static str {
    match status {
        0 => "open",
        1 => "accepted",
        2 => "submitted",
        3 => "settled",
        4 => "cancelled",
        5 => "expired",
        6 => "disputed",
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

async fn read_task(state: &AppState, address: &MsgAddressInt) -> anyhow::Result<TaskDto> {
    let stack = state
        .runtime_cfg
        .chain_provider()
        .run_get_method(address.to_string(), "get_task_data", vec![])
        .await?;
    Ok(task_dto(None, address.to_string(), TaskEscrowContract::decode_data(&stack)?))
}

#[utoipa::path(get, path = "/agents/{address}", params(("address" = String, Path, description = "Agent Account address")), responses(
    (status = 200, body = AgentAccountResponse), (status = 400, body = ApiErrorResponse),
    (status = 404, body = ApiErrorResponse), (status = 500, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn get_agent(
    State(state): State<AppState>,
    Path(raw): Path<String>,
) -> Result<axum::Json<AgentAccountResponse>, AppError> {
    let address = parse_address(&raw)?;
    let stack = state
        .runtime_cfg
        .chain_provider()
        .run_get_method(address.to_string(), "get_agent_account_data", vec![])
        .await
        .map_err(|e| AppError::not_found(format!("agent account unavailable: {e:#}")))?;
    let data = AgentAccountContract::decode_data(&stack)
        .map_err(|e| AppError::internal(format!("invalid agent account state: {e:#}")))?;
    Ok(axum::Json(AgentAccountResponse {
        ok: true,
        result: AgentAccountDto {
            address: address.to_string(),
            owner: data.owner.to_string(),
            controller_pubkey: hex::encode(data.controller_pubkey),
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
    (status = 404, body = ApiErrorResponse)
), security(("bearerAuth" = [])))]
pub async fn get_task(
    State(state): State<AppState>,
    Path(raw): Path<String>,
) -> Result<axum::Json<TaskResponse>, AppError> {
    let address = parse_address(&raw)?;
    let task = read_task(&state, &address)
        .await
        .map_err(|e| AppError::not_found(format!("task unavailable: {e:#}")))?;
    Ok(axum::Json(TaskResponse { ok: true, result: task }))
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
            "open" | "accepted" | "submitted" | "settled" | "cancelled" | "expired" | "disputed"
        ) {
            return Err(AppError::bad_request("invalid task status"));
        }
    }
    let creator = query.creator.as_deref().map(parse_address).transpose()?;
    let agent = query.agent.as_deref().map(parse_address).transpose()?;
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
    let mut result = Vec::with_capacity(records.len());
    for (name, raw) in records {
        let item = match parse_address(&raw) {
            Ok(address) => match read_task(&state, &address).await {
                Ok(mut task) => {
                    task.name = Some(name.clone());
                    if query.status.as_ref().is_some_and(|v| v != &task.status)
                        || agent
                            .as_ref()
                            .is_some_and(|v| task.assigned_agent.as_deref() != Some(&v.to_string()))
                    {
                        continue;
                    }
                    TaskListItem { name, address: raw, task: Some(task), error: None }
                }
                Err(e) => {
                    TaskListItem { name, address: raw, task: None, error: Some(format!("{e:#}")) }
                }
            },
            Err(_) => TaskListItem {
                name,
                address: raw,
                task: None,
                error: Some("invalid registered task address".to_owned()),
            },
        };
        result.push(item);
    }
    let total = result.len();
    let offset = query.offset.unwrap_or(0).min(total);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let result = result.into_iter().skip(offset).take(limit).collect();
    Ok(axum::Json(TaskListResponse { ok: true, total, offset, limit, result }))
}
