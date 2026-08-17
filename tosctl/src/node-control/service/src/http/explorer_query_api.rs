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
use contracts::{ElectionsInfo, ElectorWrapper, ElectorWrapperImpl, contract_provider_from};
use serde_json::Value;
use std::str::FromStr;

const MAX_PAGE_SIZE: usize = 200;
const JAVASCRIPT_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// ConfigParam 17 stores max_stake_factor in 1/65536 units.
const STAKE_FACTOR_SCALE: u32 = 1 << 16;
const STAKE_FACTOR_SHIFT: u32 = 16;

const CONTRACT_KINDS: &[&str] = &[
    "agent_account",
    "task_escrow",
    "dispute",
    "service_actor",
    "capability_registry",
    "aipow_commitment",
    "aipow_distributor",
    "contract.pool.nominator",
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
pub struct ExplorerStakingCycleDto {
    pub election_id: u64,
    pub unfreeze_at: u64,
    pub duration_seconds: u64,
    pub total_stake: String,
    pub rewards: String,
    pub reward_rate: f64,
    pub annualized_apr: Option<f64>,
    pub compounded_apy: Option<f64>,
    pub validator_count: usize,
    pub vset_hash: String,
}

/// What the Elector will actually pay a stake on.
///
/// Effective stake is capped: the Elector pays each elected validator on
/// `min(stake, max_stake_factor * smallest_elected_stake)` and refunds the
/// difference (elector-code.fc, try_elect). A page that shows a pool's size and
/// a network reward rate side by side implies the two multiply, and past the
/// cap they do not -- capital above it earns nothing while still carrying the
/// pool's risk. At a factor of one the cap equals the smallest elected stake,
/// so every validator carries identical weight no matter how much it gathered,
/// and aggregating capital buys nothing at all.
#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerEffectiveStakeDto {
    /// ConfigParam 17's max_stake_factor, in the 1/65536 units it is stored in.
    pub max_stake_factor_raw: Option<u32>,
    /// The same value as a plain multiplier.
    pub max_stake_factor: Option<f64>,
    /// Smallest stake among the validators elected in the most recent completed
    /// round: the quantity the cap is measured against.
    pub smallest_elected_stake: Option<String>,
    /// Absolute ceiling on one participant's effective stake, in nanotos.
    pub effective_stake_cap: Option<String>,
    /// Whether a validator staking above the cap is paid for the excess.
    /// False whenever the factor is at its floor of one.
    pub surplus_earns: Option<bool>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerStakingOverviewDto {
    pub current_election_available: bool,
    pub reward_history_available: bool,
    pub active_election_id: u64,
    pub election_closes_at: u64,
    pub current_election_stake: String,
    pub current_participants: usize,
    pub minimum_stake: String,
    pub election_failed: bool,
    pub election_finished: bool,
    pub pools: usize,
    pub active_pools: usize,
    pub nominators: u64,
    pub total_pool_stake: String,
    pub effective_stake: ExplorerEffectiveStakeDto,
    pub updated_at: u64,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExplorerStakingResponse {
    pub ok: bool,
    pub result: ExplorerStakingOverviewDto,
    pub cycles: Vec<ExplorerStakingCycleDto>,
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

/// Chain-derived staking state. Current election and historical rewards come
/// from Elector get-methods; pool totals come from code-hash-classified
/// Nominator Pool contracts in the canonical explorer index.
#[utoipa::path(get, path = "/explorer/staking", responses(
    (status = 200, body = ExplorerStakingResponse), (status = 503, body = ApiErrorResponse)
))]
pub async fn staking(
    State(state): State<AppState>,
) -> Result<axum::Json<ExplorerStakingResponse>, AppError> {
    let provider = contract_provider_from(state.runtime_cfg.chain_provider());
    let elector = ElectorWrapperImpl::new(provider);
    let (current_result, past_result) =
        tokio::join!(elector.elections_info(), elector.past_elections());
    let current_election_available = current_result.is_ok();
    let reward_history_available = past_result.is_ok();
    let current = current_result.unwrap_or_else(|error| {
        tracing::warn!(target: "explorer_api", error = %format!("{error:#}"), "current Elector election is unavailable");
        ElectionsInfo::default()
    });
    let mut past = past_result.unwrap_or_else(|error| {
        tracing::warn!(target: "explorer_api", error = %format!("{error:#}"), "Elector reward history is unavailable");
        Vec::new()
    });

    past.sort_by(|left, right| right.election_id.cmp(&left.election_id));

    // The cap the Elector applies is a multiple of the smallest stake it
    // actually elected, so it can only be stated against a completed round.
    let smallest_elected_stake =
        past.first().and_then(|cycle| cycle.frozen_map.values().map(|entry| entry.stake).min());
    let max_stake_factor_raw = match state.runtime_cfg.chain_provider().get_config_param(17).await {
        Ok(chain_block::ConfigParamEnum::ConfigParam17(param)) => Some(param.max_stake_factor),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(target: "explorer_api", error = %format!("{error:#}"), "stake limits are unavailable");
            None
        }
    };
    let effective_stake = ExplorerEffectiveStakeDto {
        max_stake_factor_raw,
        max_stake_factor: max_stake_factor_raw
            .map(|raw| f64::from(raw) / f64::from(STAKE_FACTOR_SCALE)),
        smallest_elected_stake: smallest_elected_stake.map(|stake| stake.to_string()),
        effective_stake_cap: max_stake_factor_raw.zip(smallest_elected_stake).map(
            |(raw, stake)| {
                ((u128::from(stake) * u128::from(raw)) >> STAKE_FACTOR_SHIFT).to_string()
            },
        ),
        // At the floor the cap equals the smallest elected stake, so no
        // validator is paid on more than the least-staked one put up.
        surplus_earns: max_stake_factor_raw.map(|raw| raw > STAKE_FACTOR_SCALE),
    };

    let seconds_per_year = 31_557_600_f64;
    let cycles = past
        .into_iter()
        .take(64)
        .map(|cycle| {
            let reward_rate = if cycle.total_stake > 0 {
                cycle.bonuses as f64 / cycle.total_stake as f64
            } else {
                0.0
            };
            let periods =
                if cycle.stake_held > 0 { seconds_per_year / cycle.stake_held as f64 } else { 0.0 };
            let apr = reward_rate * periods;
            let apy = if periods > 0.0 { (1.0 + reward_rate).powf(periods) - 1.0 } else { 0.0 };
            ExplorerStakingCycleDto {
                election_id: cycle.election_id,
                unfreeze_at: cycle.unfreeze_at,
                duration_seconds: cycle.stake_held,
                total_stake: cycle.total_stake.to_string(),
                rewards: cycle.bonuses.to_string(),
                reward_rate,
                annualized_apr: apr.is_finite().then_some(apr),
                compounded_apy: apy.is_finite().then_some(apy),
                validator_count: cycle.frozen_map.len(),
                vset_hash: hex::encode(cycle.vset_hash),
            }
        })
        .collect::<Vec<_>>();

    let (pools, _) = state
        .indexer_store
        .list("contract.pool.nominator", &ListFilters::default(), 0, 10_000)
        .map_err(index_error)?;
    let mut active_pools = 0usize;
    let mut nominators = 0u64;
    let mut total_pool_stake = 0u64;
    for pool in &pools {
        if matches!(pool.status.as_deref(), Some("staking" | "staked")) {
            active_pools += 1;
        }
        if let Ok(data) = serde_json::from_str::<Value>(&pool.dto_json) {
            nominators = nominators
                .saturating_add(data.get("nominators_count").and_then(Value::as_u64).unwrap_or(0));
            total_pool_stake = total_pool_stake.saturating_add(
                data.get("total_balance_at_risk")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0),
            );
        }
    }

    Ok(axum::Json(ExplorerStakingResponse {
        ok: true,
        result: ExplorerStakingOverviewDto {
            current_election_available,
            reward_history_available,
            active_election_id: current.election_id,
            election_closes_at: current.elect_close,
            current_election_stake: current.total_stake.to_string(),
            current_participants: current.participants.len(),
            minimum_stake: current.min_stake.to_string(),
            election_failed: current.failed,
            election_finished: current.finished,
            pools: pools.len(),
            active_pools,
            nominators,
            total_pool_stake: total_pool_stake.to_string(),
            effective_stake,
            updated_at: common::time_format::now(),
        },
        cycles,
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
