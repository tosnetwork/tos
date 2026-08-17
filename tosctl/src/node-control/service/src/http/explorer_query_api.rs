/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Public, read-only query surface for TOSCAN and other explorers.
//!
//! The durable index resolves identities and provides pagination; the TOS
//! node remains authoritative for full block, transaction and account bodies.

#[allow(unused_imports)]
use super::http_server_task::{ApiErrorResponse, AppError, AppState};
use crate::indexer::{ExplorerBlockRecord, ExplorerTransactionRecord, IndexedRecord, ListFilters};
use crate::runtime_config::RuntimeConfig;
use axum::extract::{Path, Query, State};
use base64::Engine;
use chain_block::MsgAddressInt;
use serde_json::Value;
use std::str::FromStr;

const MAX_PAGE_SIZE: usize = 200;
const JAVASCRIPT_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const CONTRACT_KINDS: &[&str] = &[
    "agent_account",
    "task_escrow",
    "dispute",
    "service_actor",
    "capability_registry",
    "aipow_commitment",
    "aipow_distributor",
];

#[derive(Clone, Default, serde::Deserialize, utoipa::IntoParams)]
pub struct ExplorerPageQuery {
    pub account: Option<String>,
    pub workchain: Option<i32>,
    pub shard: Option<i64>,
    pub seqno: Option<u32>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Clone, Default, serde::Deserialize, utoipa::IntoParams)]
pub struct ExplorerContractQuery {
    pub creator: Option<String>,
    pub status: Option<String>,
    pub deadline_after: Option<u64>,
    pub deadline_before: Option<u64>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Clone, serde::Deserialize, utoipa::IntoParams)]
pub struct HashQuery {
    pub hash: String,
}

#[derive(Clone, serde::Deserialize, utoipa::IntoParams)]
pub struct SearchQuery {
    pub q: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerTransactionDto {
    pub hash: String,
    pub account: String,
    pub lt: String,
    pub workchain: i32,
    pub shard: String,
    pub seqno: u32,
    pub gen_utime: u32,
    pub fee: Option<String>,
    pub in_msg_hash: Option<String>,
    pub indexed_at: u64,
}

impl From<ExplorerTransactionRecord> for ExplorerTransactionDto {
    fn from(value: ExplorerTransactionRecord) -> Self {
        Self {
            hash: value.hash,
            account: value.account,
            lt: value.lt.to_string(),
            workchain: value.workchain,
            shard: value.shard.to_string(),
            seqno: value.seqno,
            gen_utime: value.gen_utime,
            fee: value.fee,
            in_msg_hash: value.in_msg_hash,
            indexed_at: value.indexed_at,
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerBlockDto {
    pub workchain: i32,
    pub shard: String,
    pub seqno: u32,
    pub root_hash: String,
    pub file_hash: String,
    pub gen_utime: u32,
    pub tx_count: usize,
    pub indexed_at: u64,
    pub observed_mc_seqno: u32,
}

impl From<ExplorerBlockRecord> for ExplorerBlockDto {
    fn from(value: ExplorerBlockRecord) -> Self {
        Self {
            workchain: value.workchain,
            shard: value.shard.to_string(),
            seqno: value.seqno,
            root_hash: value.root_hash,
            file_hash: value.file_hash,
            gen_utime: value.gen_utime,
            tx_count: value.tx_count,
            indexed_at: value.indexed_at,
            observed_mc_seqno: value.observed_mc_seqno,
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerContractDto {
    pub address: String,
    pub kind: String,
    pub creator: Option<String>,
    pub counterparty: Option<String>,
    pub status: Option<String>,
    pub deadline: Option<u64>,
    pub last_seqno: u32,
    pub updated_at: u64,
    pub data: Value,
}

impl From<IndexedRecord> for ExplorerContractDto {
    fn from(value: IndexedRecord) -> Self {
        let mut data = serde_json::from_str::<Value>(&value.dto_json)
            .unwrap_or_else(|_| Value::Object(Default::default()));
        if let Value::Object(object) = &mut data {
            object.insert("address".to_owned(), Value::String(value.address.clone()));
        }
        make_json_browser_safe(&mut data);
        Self {
            address: value.address,
            kind: value.kind,
            creator: value.creator,
            counterparty: value.counterparty,
            status: value.status,
            deadline: value.deadline,
            last_seqno: value.last_seqno,
            updated_at: value.updated_at,
            data,
        }
    }
}

/// JSON itself permits 64-bit integers, but JavaScript parses every JSON number
/// as an IEEE-754 double. Preserve exact on-chain balances and limits by
/// serializing only out-of-range integers as decimal strings at the explorer
/// boundary. Small counters and timestamps remain numbers for API ergonomics.
fn make_json_browser_safe(value: &mut Value) {
    match value {
        Value::Number(number) => {
            let outside_safe_range = number
                .as_u64()
                .map(|integer| integer > JAVASCRIPT_MAX_SAFE_INTEGER)
                .or_else(|| {
                    number
                        .as_i64()
                        .map(|integer| integer.unsigned_abs() > JAVASCRIPT_MAX_SAFE_INTEGER)
                })
                .unwrap_or(false);
            if outside_safe_range {
                *value = Value::String(number.to_string());
            }
        }
        Value::Array(items) => items.iter_mut().for_each(make_json_browser_safe),
        Value::Object(object) => object.values_mut().for_each(make_json_browser_safe),
        _ => {}
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerTransactionListResponse {
    pub ok: bool,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub result: Vec<ExplorerTransactionDto>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerBlockListResponse {
    pub ok: bool,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub result: Vec<ExplorerBlockDto>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerContractListResponse {
    pub ok: bool,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub result: Vec<ExplorerContractDto>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerTransactionResponse {
    pub ok: bool,
    pub result: ExplorerTransactionDto,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerBlockResponse {
    pub ok: bool,
    pub result: ExplorerBlockDto,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerContractResponse {
    pub ok: bool,
    pub result: ExplorerContractDto,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerCheckpointDto {
    pub shard: String,
    pub seqno: u32,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerStatusDto {
    pub blocks: usize,
    pub transactions: usize,
    pub contracts: usize,
    pub latest_indexed_at: Option<u64>,
    pub masterchain_head: Option<u32>,
    pub masterchain_indexed: Option<u32>,
    pub masterchain_lag: Option<u32>,
    pub checkpoints: Vec<ExplorerCheckpointDto>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerStatusResponse {
    pub ok: bool,
    pub result: ExplorerStatusDto,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", content = "result", rename_all = "snake_case")]
pub enum ExplorerSearchHit {
    Transaction(ExplorerTransactionDto),
    Block(ExplorerBlockDto),
    Contract(ExplorerContractDto),
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerSearchResponse {
    pub ok: bool,
    pub result: Option<ExplorerSearchHit>,
}

fn index_error(error: anyhow::Error) -> AppError {
    tracing::error!(target: "explorer_api", error = %format!("{error:#}"), "explorer index query failed");
    AppError::internal("explorer index unavailable")
}

fn page(offset: Option<usize>, limit: Option<usize>) -> (usize, usize) {
    (offset.unwrap_or(0), limit.unwrap_or(50).clamp(1, MAX_PAGE_SIZE))
}

fn validate_kind(kind: &str) -> Result<(), AppError> {
    if CONTRACT_KINDS.contains(&kind) {
        Ok(())
    } else {
        Err(AppError::bad_request("unsupported explorer contract kind"))
    }
}

fn block_hash_candidates(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    let mut candidates = vec![trimmed.to_ascii_lowercase()];
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        if decoded.len() == 32 {
            let hex = hex::encode(decoded);
            if !candidates.contains(&hex) {
                candidates.push(hex);
            }
        }
    }
    candidates
}

#[utoipa::path(get, path = "/explorer/status", responses(
    (status = 200, body = ExplorerStatusResponse), (status = 500, body = ApiErrorResponse)
))]
pub async fn status(
    State(state): State<AppState>,
) -> Result<axum::Json<ExplorerStatusResponse>, AppError> {
    let stats = state.indexer_store.explorer_stats().map_err(index_error)?;
    let checkpoints = state.indexer_store.checkpoints().map_err(index_error)?;
    let chain_head = state.runtime_cfg.chain_provider().get_masterchain_info().await.ok();
    let masterchain_head = chain_head.as_ref().map(|head| head.last.seqno);
    let masterchain_indexed = chain_head.as_ref().and_then(|head| {
        let key = format!("-1:{}", head.last.shard);
        checkpoints.iter().find(|checkpoint| checkpoint.shard_key == key).map(|value| value.seqno)
    });
    let masterchain_lag = masterchain_head
        .zip(masterchain_indexed)
        .map(|(head, indexed)| head.saturating_sub(indexed));
    Ok(axum::Json(ExplorerStatusResponse {
        ok: true,
        result: ExplorerStatusDto {
            blocks: stats.blocks,
            transactions: stats.transactions,
            contracts: stats.contracts,
            latest_indexed_at: stats.latest_indexed_at,
            masterchain_head,
            masterchain_indexed,
            masterchain_lag,
            checkpoints: checkpoints
                .into_iter()
                .map(|value| ExplorerCheckpointDto { shard: value.shard_key, seqno: value.seqno })
                .collect(),
        },
    }))
}

#[utoipa::path(get, path = "/explorer/transactions", params(ExplorerPageQuery), responses(
    (status = 200, body = ExplorerTransactionListResponse), (status = 400, body = ApiErrorResponse)
))]
pub async fn list_transactions(
    State(state): State<AppState>,
    Query(query): Query<ExplorerPageQuery>,
) -> Result<axum::Json<ExplorerTransactionListResponse>, AppError> {
    let account = query
        .account
        .as_deref()
        .map(MsgAddressInt::from_str)
        .transpose()
        .map_err(|_| AppError::bad_request("invalid TOS address"))?
        .map(|address| address.to_string());
    let (offset, limit) = page(query.offset, query.limit);
    let block_filter = match (query.workchain, query.shard, query.seqno) {
        (None, None, None) => None,
        (Some(workchain), Some(shard), Some(seqno)) if account.is_none() => {
            Some((workchain, shard, seqno))
        }
        (Some(_), Some(_), Some(_)) => {
            return Err(AppError::bad_request(
                "account and block transaction filters are mutually exclusive",
            ));
        }
        _ => {
            return Err(AppError::bad_request(
                "workchain, shard and seqno must be supplied together",
            ));
        }
    };
    let (rows, total) = if let Some((workchain, shard, seqno)) = block_filter {
        state
            .indexer_store
            .list_explorer_block_transactions(workchain, shard, seqno, offset, limit)
            .map_err(index_error)?
    } else {
        state
            .indexer_store
            .list_explorer_transactions(account.as_deref(), offset, limit)
            .map_err(index_error)?
    };
    Ok(axum::Json(ExplorerTransactionListResponse {
        ok: true,
        total,
        offset,
        limit,
        result: rows.into_iter().map(Into::into).collect(),
    }))
}

#[utoipa::path(get, path = "/explorer/blocks", params(ExplorerPageQuery), responses(
    (status = 200, body = ExplorerBlockListResponse)
))]
pub async fn list_blocks(
    State(state): State<AppState>,
    Query(query): Query<ExplorerPageQuery>,
) -> Result<axum::Json<ExplorerBlockListResponse>, AppError> {
    let (offset, limit) = page(query.offset, query.limit);
    let (rows, total) =
        state.indexer_store.list_explorer_blocks(offset, limit).map_err(index_error)?;
    Ok(axum::Json(ExplorerBlockListResponse {
        ok: true,
        total,
        offset,
        limit,
        result: rows.into_iter().map(Into::into).collect(),
    }))
}

#[utoipa::path(get, path = "/explorer/transaction", params(HashQuery), responses(
    (status = 200, body = ExplorerTransactionResponse), (status = 404, body = ApiErrorResponse)
))]
pub async fn get_transaction(
    State(state): State<AppState>,
    Query(query): Query<HashQuery>,
) -> Result<axum::Json<ExplorerTransactionResponse>, AppError> {
    let record = state
        .indexer_store
        .explorer_transaction(query.hash.trim())
        .map_err(index_error)?
        .ok_or_else(|| AppError::not_found("transaction hash is not indexed"))?;
    Ok(axum::Json(ExplorerTransactionResponse { ok: true, result: record.into() }))
}

#[utoipa::path(get, path = "/explorer/block", params(HashQuery), responses(
    (status = 200, body = ExplorerBlockResponse), (status = 404, body = ApiErrorResponse)
))]
pub async fn get_block(
    State(state): State<AppState>,
    Query(query): Query<HashQuery>,
) -> Result<axum::Json<ExplorerBlockResponse>, AppError> {
    let mut record = None;
    for candidate in block_hash_candidates(&query.hash) {
        record = state.indexer_store.explorer_block_by_hash(&candidate).map_err(index_error)?;
        if record.is_some() {
            break;
        }
    }
    let record = record.ok_or_else(|| AppError::not_found("block hash is not indexed"))?;
    Ok(axum::Json(ExplorerBlockResponse { ok: true, result: record.into() }))
}

#[utoipa::path(get, path = "/explorer/contracts/{kind}", params(
    ("kind" = String, Path, description = "Indexed contract kind"), ExplorerContractQuery
), responses((status = 200, body = ExplorerContractListResponse), (status = 400, body = ApiErrorResponse)))]
pub async fn list_contracts(
    State(state): State<AppState>,
    Path(kind): Path<String>,
    Query(query): Query<ExplorerContractQuery>,
) -> Result<axum::Json<ExplorerContractListResponse>, AppError> {
    validate_kind(&kind)?;
    if matches!((query.deadline_after, query.deadline_before), (Some(a), Some(b)) if a >= b) {
        return Err(AppError::bad_request("deadline_after must be less than deadline_before"));
    }
    let creator = query
        .creator
        .as_deref()
        .map(MsgAddressInt::from_str)
        .transpose()
        .map_err(|_| AppError::bad_request("invalid TOS address"))?
        .map(|address| address.to_string());
    let (offset, limit) = page(query.offset, query.limit);
    let filters = ListFilters {
        creator: creator.as_deref(),
        status: query.status.as_deref(),
        deadline_after: query.deadline_after,
        deadline_before: query.deadline_before,
    };
    let (rows, total) =
        state.indexer_store.list(&kind, &filters, offset, limit).map_err(index_error)?;
    Ok(axum::Json(ExplorerContractListResponse {
        ok: true,
        total,
        offset,
        limit,
        result: rows.into_iter().map(Into::into).collect(),
    }))
}

#[utoipa::path(get, path = "/explorer/contracts/{kind}/{address}", params(
    ("kind" = String, Path, description = "Indexed contract kind"),
    ("address" = String, Path, description = "TOS contract address")
), responses((status = 200, body = ExplorerContractResponse), (status = 404, body = ApiErrorResponse)))]
pub async fn get_contract(
    State(state): State<AppState>,
    Path((kind, raw_address)): Path<(String, String)>,
) -> Result<axum::Json<ExplorerContractResponse>, AppError> {
    validate_kind(&kind)?;
    let address = MsgAddressInt::from_str(&raw_address)
        .map_err(|_| AppError::bad_request("invalid TOS address"))?
        .to_string();
    let record = state
        .indexer_store
        .get(&address)
        .map_err(index_error)?
        .filter(|record| record.kind == kind)
        .ok_or_else(|| AppError::not_found("contract is not indexed under this kind"))?;
    Ok(axum::Json(ExplorerContractResponse { ok: true, result: record.into() }))
}

#[utoipa::path(get, path = "/explorer/search", params(SearchQuery), responses(
    (status = 200, body = ExplorerSearchResponse)
))]
pub async fn search(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<axum::Json<ExplorerSearchResponse>, AppError> {
    let q = query.q.trim();
    if q.is_empty() {
        return Err(AppError::bad_request("search query is required"));
    }
    if let Some(record) = state.indexer_store.explorer_transaction(q).map_err(index_error)? {
        return Ok(axum::Json(ExplorerSearchResponse {
            ok: true,
            result: Some(ExplorerSearchHit::Transaction(record.into())),
        }));
    }
    for candidate in block_hash_candidates(q) {
        if let Some(record) =
            state.indexer_store.explorer_block_by_hash(&candidate).map_err(index_error)?
        {
            return Ok(axum::Json(ExplorerSearchResponse {
                ok: true,
                result: Some(ExplorerSearchHit::Block(record.into())),
            }));
        }
    }
    if let Ok(address) = MsgAddressInt::from_str(q) {
        if let Some(record) = state.indexer_store.get(&address.to_string()).map_err(index_error)? {
            if record.kind != "unclassified" {
                return Ok(axum::Json(ExplorerSearchResponse {
                    ok: true,
                    result: Some(ExplorerSearchHit::Contract(record.into())),
                }));
            }
        }
    }
    Ok(axum::Json(ExplorerSearchResponse { ok: true, result: None }))
}

#[cfg(test)]
mod tests {
    use super::make_json_browser_safe;

    #[test]
    fn converts_only_integers_that_javascript_cannot_represent_exactly() {
        let mut value = serde_json::json!({
            "safe": 9_007_199_254_740_991_u64,
            "large": 18_446_744_073_709_551_615_u64,
            "negative": -9_007_199_254_740_992_i64,
            "nested": [42, 9_007_199_254_740_992_u64],
            "fraction": 1.5,
        });

        make_json_browser_safe(&mut value);

        assert_eq!(value["safe"], serde_json::json!(9_007_199_254_740_991_u64));
        assert_eq!(value["large"], "18446744073709551615");
        assert_eq!(value["negative"], "-9007199254740992");
        assert_eq!(value["nested"][0], 42);
        assert_eq!(value["nested"][1], "9007199254740992");
        assert_eq!(value["fraction"], serde_json::json!(1.5));
    }
}
