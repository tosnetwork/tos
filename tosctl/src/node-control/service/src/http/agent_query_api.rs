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
use contracts::{AgentAccountContract, TaskEscrowContract};
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
    let provider = state.runtime_cfg.chain_provider();
    let call = provider.run_get_method(address.to_string(), method, vec![]);
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
            "open" | "accepted" | "submitted" | "settled" | "cancelled" | "expired" | "disputed"
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

    let total = result.len();
    let offset = query.offset.unwrap_or(0).min(total);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let result = result.into_iter().skip(offset).take(limit).collect();
    Ok(axum::Json(TaskListResponse { ok: true, total, offset, limit, result }))
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
        AgentAccountContract, AgentAccountInit, ChainProvider, TaskEscrowContract, TaskEscrowInit,
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
            _stack: Vec<tl_api::tos::tvm::StackEntry>,
        ) -> anyhow::Result<TvmStackParser> {
            let addr = MsgAddressInt::from_str(&address)?;
            let result = {
                let bc = self.bc.lock().expect("sandbox lock poisoned");
                bc.run_get_method(&addr, method, vec![])
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
                review_period: 600,
                settlement_policy_hash: [0x33; 32],
                permission_hash: [0x77; 32],
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
}
