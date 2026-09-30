use crate::{
    authorized, decode_token, hex,
    query_ledger::{Attempt, QueryLedger},
    random_token, Inventory,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use tos_health_core::{
    evidence::{Evidence, EvidenceStore},
    query::{Grant, QueryService, TOOLS},
};

pub struct Data {
    pub store: EvidenceStore,
    pub grants: BTreeMap<String, Grant>,
    pub manager_conflicted: bool,
    pub manager_caught_up: bool,
    pub manager_validated_data_version: Option<u64>,
}
#[derive(Clone)]
pub struct ObservabilityState {
    pub data: Arc<Mutex<Data>>,
    pub inventory: Arc<Inventory>,
    pub operator_token: Arc<Vec<u8>>,
    pub ingest_token: Arc<Vec<u8>>,
    pub service_token: Arc<Vec<u8>>,
    pub metrics: Arc<BTreeSet<String>>,
    pub query_ledger: Option<Arc<Mutex<QueryLedger>>>,
    pub manager_evidence_db: Option<PathBuf>,
    /// One stable read-only SQLite connection observes changes to M even when
    /// its global row watermark does not move (for example, quarantine).
    pub manager_change_witness: Option<Arc<Mutex<Connection>>>,
    /// Serializes background imports without holding the query Data mutex
    /// across M's retained-parent validation and bounded page read.
    pub manager_import_gate: Arc<Mutex<()>>,
    /// Precise source-I/O phase witness: a control test can distinguish the
    /// slow M read from the short publication window without sleeping.
    pub manager_source_read_active: Arc<AtomicBool>,
    /// Counts actual broker-side M archive read attempts. Query handlers must
    /// not increment this witness even under a call storm or cache miss.
    pub manager_projection_reads: Arc<AtomicU64>,
    pub started: Instant,
    pub epoch: String,
}
impl ObservabilityState {
    pub fn new(
        inventory: Inventory,
        operator: Vec<u8>,
        ingest: Vec<u8>,
        service: Vec<u8>,
    ) -> Result<Self, String> {
        inventory.validate()?;
        if operator == ingest || operator == service || ingest == service {
            return Err("identities must use distinct credentials".into());
        }
        Ok(Self {
            data: Arc::new(Mutex::new(Data {
                store: EvidenceStore::new(8 * 1024 * 1024),
                grants: BTreeMap::new(),
                manager_conflicted: false,
                manager_caught_up: true,
                manager_validated_data_version: None,
            })),
            inventory: Arc::new(inventory),
            operator_token: Arc::new(operator),
            ingest_token: Arc::new(ingest),
            service_token: Arc::new(service),
            metrics: Arc::new(BTreeSet::new()),
            query_ledger: None,
            manager_evidence_db: None,
            manager_change_witness: None,
            manager_import_gate: Arc::new(Mutex::new(())),
            manager_source_read_active: Arc::new(AtomicBool::new(false)),
            manager_projection_reads: Arc::new(AtomicU64::new(0)),
            started: Instant::now(),
            epoch: hex(&random_token()?),
        })
    }
    fn now(&self) -> u64 {
        // Match the durable grant ledger's restart-stable clock domain.
        crate::query_ledger::boot_millis().unwrap_or(u64::MAX)
    }
    pub fn with_query_ledger(mut self, path: &std::path::Path) -> Result<Self, String> {
        let ledger = QueryLedger::open(path)?;
        let active = ledger.load_active_all(self.now())?;
        let mut data = self.data.lock().map_err(|_| "query state unavailable")?;
        let floor = active.iter().map(|g| g.watermark).max().unwrap_or(0);
        let mut restored = ledger.load_evidence(8 * 1024 * 1024)?;
        if restored.watermark() < floor && restored.entries().next().is_none() {
            restored.advance_watermark_floor(floor).map_err(str::to_owned)?;
        } else if restored.watermark() < floor {
            return Err("query evidence watermark behind active grants".into());
        }
        data.store = restored;
        data.grants = active.into_iter().map(|g| (g.run_id.clone(), g)).collect();
        drop(data);
        self.query_ledger = Some(Arc::new(Mutex::new(ledger)));
        Ok(self)
    }
    pub fn with_manager_evidence(mut self, path: PathBuf) -> Result<Self, String> {
        if self.query_ledger.is_none() {
            return Err("M projection requires durable query ledger".into());
        }
        let witness = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| error.to_string())?;
        witness
            .busy_timeout(std::time::Duration::from_millis(100))
            .map_err(|error| error.to_string())?;
        witness.execute_batch("PRAGMA query_only=ON").map_err(|error| error.to_string())?;
        self.manager_change_witness = Some(Arc::new(Mutex::new(witness)));
        self.manager_evidence_db = Some(path);
        match import_manager(&self) {
            Ok(_) => {}
            Err(_)
                if self
                    .data
                    .lock()
                    .is_ok_and(|data| !data.manager_conflicted && !data.manager_caught_up) =>
            {
                // A bounded-capacity pause leaves old fixed-W grants usable.
                // The 15-second owner retries; new grants stay 503.
            }
            Err(error) => return Err(error),
        }
        Ok(self)
    }
}
fn block_manager_queries(state: &ObservabilityState, data: &mut Data) -> Result<(), String> {
    // Set the in-memory refusal before touching SQLite. A partial I/O failure
    // must never leave an apparently usable run in this process.
    data.manager_conflicted = true;
    let ledger = state.query_ledger.as_ref().ok_or("query ledger unavailable")?;
    let mut ledger = ledger.lock().map_err(|_| "query ledger unavailable")?;
    for run in data.grants.keys() {
        ledger.revoke(run)?;
    }
    for grant in data.grants.values_mut() {
        grant.revoke();
    }
    Ok(())
}
fn projection_insert_can_pause(error: &str) -> bool {
    // Only these bounded-capacity refusals prove that already-retained evidence
    // and its fixed-W grants remain intact. Unknown source or SQLite failures
    // are not evidence of a recoverable pause.
    matches!(error, "active grant evidence retention" | "M parent retention full")
}
fn manager_data_version(state: &ObservabilityState, wait: bool) -> Result<u64, String> {
    let witness = state.manager_change_witness.as_ref().ok_or("M change witness unavailable")?;
    let guard = if wait {
        witness.lock().map_err(|_| "M change witness unavailable")?
    } else {
        witness.try_lock().map_err(|_| "M change witness busy")?
    };
    let version: i64 = guard
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    u64::try_from(version).map_err(|error| error.to_string())
}
fn block_import_error(state: &ObservabilityState, error: String) -> Result<(u64, usize), String> {
    let mut data = state.data.lock().map_err(|_| "query state unavailable")?;
    block_manager_queries(state, &mut data)?;
    Err(error)
}
struct SourceReadPhase(Arc<AtomicBool>);
impl SourceReadPhase {
    fn begin(flag: &Arc<AtomicBool>) -> Self {
        flag.store(true, Ordering::Release);
        Self(flag.clone())
    }
}
impl Drop for SourceReadPhase {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
/// This is a broker-control operation, not a query handler fallback. The M
/// snapshot and retained-parent read can take longer than the control socket's
/// deadline at peak retention, so neither Data nor QueryLedger is held across
/// that read. Only the short publication/commit phase takes both locks.
pub fn import_manager(state: &ObservabilityState) -> Result<(u64, usize), String> {
    let _import_gate = state.manager_import_gate.lock().map_err(|_| "M importer unavailable")?;
    let Some(path) = &state.manager_evidence_db else {
        return Ok((0, 0));
    };
    if state.data.lock().map_err(|_| "query state unavailable")?.manager_conflicted {
        return Err("M projection conflict requires operator review".into());
    }
    let version_before = match manager_data_version(state, true) {
        Ok(value) => value,
        Err(error) => return block_import_error(state, error),
    };
    let ledger = state.query_ledger.as_ref().ok_or("query ledger unavailable")?;
    state.manager_projection_reads.fetch_add(1, Ordering::Relaxed);
    let cursor_and_retained = {
        let guard = ledger.lock().map_err(|_| "query ledger unavailable")?;
        guard
            .manager_cursor()
            .and_then(|cursor| guard.retained_origin_rows().map(|retained| (cursor, retained)))
    };
    let (previous, retained) = match cursor_and_retained {
        Ok(value) => value,
        Err(error) => return block_import_error(state, error),
    };
    let source = {
        let _source_read = SourceReadPhase::begin(&state.manager_source_read_active);
        crate::manager_query_source::read_process_projection_page(
            path,
            &state.inventory.network_id,
            previous.as_ref(),
            &retained,
        )
    };
    let page = match source {
        Ok(value) => value,
        Err(error) => return block_import_error(state, error),
    };
    if !page.quarantined_retained.is_empty() {
        return block_import_error(state, "retained M parent was quarantined".into());
    }
    let count = page.records.len();
    for (_, record) in &page.records {
        if !state.inventory.nodes.contains(&record.node_id)
            || !state.inventory.scopes.contains(&record.scope_id)
        {
            return block_import_error(state, "M projection outside inventory".into());
        }
    }
    let mut data = state.data.lock().map_err(|_| "query state unavailable")?;
    if data.manager_conflicted {
        return Err("M projection conflict requires operator review".into());
    }
    let inserted = ledger
        .lock()
        .map_err(|_| "query ledger unavailable")?
        .insert_projection_page(&mut data.store, &page.records);
    if let Err(error) = inserted {
        if projection_insert_can_pause(&error) {
            // The bounded page was refused before publication. Existing grants
            // retain their fixed W, while new grants wait for catch-up.
            data.manager_caught_up = false;
        } else {
            block_manager_queries(state, &mut data)?;
        }
        return Err(error);
    }
    let committed = ledger.lock().map_err(|_| "query ledger unavailable")?.commit_manager_cursor(
        previous.as_ref(),
        &page.cursor,
        page.boundary_witness.as_ref(),
    );
    if let Err(error) = committed {
        // A failed cursor commit can be an invariant or SQLite integrity
        // failure. Do not infer recoverability from an unknown error string.
        block_manager_queries(state, &mut data)?;
        return Err(error);
    }
    let version_after = match manager_data_version(state, true) {
        Ok(value) => value,
        Err(error) => {
            block_manager_queries(state, &mut data)?;
            return Err(error);
        }
    };
    data.manager_caught_up = page.caught_up && version_before == version_after;
    data.manager_validated_data_version = data.manager_caught_up.then_some(version_after);
    Ok((page.cursor.watermark, count))
}
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get("authorization").and_then(|v| v.to_str().ok())
}
async fn monitor_heartbeat(
    State(state): State<ObservabilityState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(bearer(&headers), &state.service_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let epoch = &state.epoch;
    Ok(Json(
        json!({"schema_version":1,"sequence":(state.started.elapsed().as_secs()/15).to_string(),"process_epoch":epoch}),
    ))
}
async fn healthz() -> Json<Value> {
    Json(json!({"service":"available","validator_health":"unknown"}))
}
/// Authenticated, read-only control-socket witness. This is not a grant and
/// does not import M, so a failing projection cannot be hidden by the probe.
async fn projection_health(
    State(state): State<ObservabilityState>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    if !authorized(bearer(&headers), &state.service_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let ledger = state.query_ledger.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let path = state.manager_evidence_db.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    // Never park a control-socket Tokio worker behind a slow importer. Take
    // the flags and durable cursor together under non-waiting locks, then do
    // the SQLite source-head I/O on the blocking pool without either lock.
    let (manager_conflicted, caught_up_at_last_import, validated_version, query_watermark, cursor) = {
        let data = state.data.try_lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let cursor = ledger
            .try_lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .manager_cursor()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        (
            data.manager_conflicted,
            data.manager_caught_up,
            data.manager_validated_data_version,
            data.store.watermark(),
            cursor,
        )
    };
    let path = path.clone();
    let network = state.inventory.network_id.clone();
    let head = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::task::spawn_blocking(move || {
            crate::manager_query_source::read_projection_head(&path, &network)
        }),
    )
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let current_version = manager_data_version(&state, false);
    let (source_global_m_seq, source_identity_match, lag_global_m_seq) = match (&head, &cursor) {
        (Ok(head), Some(cursor)) => (
            Some(head.global_m_seq.to_string()),
            Some(
                cursor.network == state.inventory.network_id
                    && cursor.device == head.device
                    && cursor.inode == head.inode,
            ),
            head.global_m_seq.checked_sub(cursor.watermark).map(|lag| lag.to_string()),
        ),
        (Ok(head), None) => (Some(head.global_m_seq.to_string()), None, None),
        (Err(_), _) => (None, None, None),
    };
    let status = if manager_conflicted {
        "conflict"
    } else if head.is_err() || current_version.is_err() {
        "source_unavailable"
    } else if cursor.is_none() {
        "uninitialized"
    } else if source_identity_match != Some(true) || lag_global_m_seq.is_none() {
        "identity_or_watermark_mismatch"
    } else if !caught_up_at_last_import
        || validated_version != current_version.ok()
        || lag_global_m_seq.as_deref() != Some("0")
    {
        "lagging"
    } else {
        "caught_up"
    };
    let code =
        if matches!(status, "conflict" | "source_unavailable" | "identity_or_watermark_mismatch") {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        };
    let response = (
        code,
        Json(json!({
            "schema_version":1,
            "projection_status":status,
            "manager_conflicted":manager_conflicted,
            "caught_up_at_last_import":caught_up_at_last_import,
            "query_watermark":query_watermark.to_string(),
            "cursor_global_m_seq":cursor.map(|value| value.watermark.to_string()),
            "source_global_m_seq":source_global_m_seq,
            "lag_global_m_seq":lag_global_m_seq,
            "source_identity_match":source_identity_match,
        })),
    )
        .into_response();
    Ok(response)
}
async fn ingest(
    State(state): State<ObservabilityState>,
    headers: HeaderMap,
    Json(mut record): Json<Evidence>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(bearer(&headers), &state.ingest_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !state.inventory.nodes.contains(&record.node_id)
        || !state.inventory.scopes.contains(&record.scope_id)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut data = state.data.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    record.received_at_ms = chrono::Utc::now().timestamp_millis();
    let id = if let Some(ledger) = &state.query_ledger {
        ledger
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .insert_evidence(&mut data.store, record)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    } else {
        data.store.insert(record).map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?
    };
    Ok(Json(json!({"evidence_id":id,"watermark":data.store.watermark().to_string()})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    node_ids: BTreeSet<String>,
    scope_ids: BTreeSet<String>,
    start: String,
    end: String,
}
async fn grant(
    State(state): State<ObservabilityState>,
    headers: HeaderMap,
    Json(request): Json<GrantRequest>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(bearer(&headers), &state.operator_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !request.node_ids.is_subset(&state.inventory.nodes)
        || !request.scope_ids.is_subset(&state.inventory.scopes)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let start =
        tos_health_core::query::utc_ms(&request.start).map_err(|_| StatusCode::BAD_REQUEST)?;
    let end = tos_health_core::query::utc_ms(&request.end).map_err(|_| StatusCode::BAD_REQUEST)?;
    if end > chrono::Utc::now().timestamp_millis() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let token = random_token().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut identity = random_token().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    identity[6] = (identity[6] & 0x0f) | 0x40;
    identity[8] = (identity[8] & 0x3f) | 0x80;
    let value = hex(&identity[..16]);
    let run = format!(
        "{}-{}-{}-{}-{}",
        &value[..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..]
    );
    // A grant must never run a projection page, nor wait on the projection's
    // long-lived Data lock on a Tokio worker. This small source-head read is
    // isolated on the blocking pool and bounded below the control deadline.
    let source_head = if let Some(path) = state.manager_evidence_db.clone() {
        let network = state.inventory.network_id.clone();
        Some(
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio::task::spawn_blocking(move || {
                    crate::manager_query_source::read_projection_head(&path, &network)
                }),
            )
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        )
    } else {
        None
    };
    let mut data = state.data.try_lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if data.manager_conflicted {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    data.grants.retain(|_, g| g.expires_monotonic_ms > state.now());
    if data.grants.len() >= 32 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    // Keep this one non-waiting ledger guard through both cursor validation
    // and durable creation. Dropping it between the two admits an importer
    // that can turn a fast refusal into a blocking Tokio-worker mutex wait.
    let mut ledger = match &state.query_ledger {
        Some(ledger) => Some(ledger.try_lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?),
        None => None,
    };
    let manager_watermark = if let Some(head) = source_head {
        let current_version =
            manager_data_version(&state, false).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !data.manager_caught_up || data.manager_validated_data_version != Some(current_version) {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let cursor = ledger
            .as_mut()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
            .manager_cursor()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        if cursor.network != state.inventory.network_id
            || cursor.device != head.device
            || cursor.inode != head.inode
            || cursor.watermark != head.global_m_seq
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        Some(cursor.watermark)
    } else {
        None
    };
    let mut g = Grant::new(
        run.clone(),
        "aura".into(),
        state.inventory.network_id.clone(),
        &token,
        request.node_ids,
        request.scope_ids,
        start,
        end,
        state.now(),
        data.store.watermark(),
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    g.manager_watermark = manager_watermark;
    if let Some(ledger) = ledger.as_mut() {
        ledger.create(&g, state.now()).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    }
    data.grants.insert(run.clone(), g);
    Ok(Json(json!({"run_id":run,"run_token":hex(&token),"expires_in_seconds":200})))
}
async fn revoke(
    State(state): State<ObservabilityState>,
    headers: HeaderMap,
    Path(run): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(bearer(&headers), &state.operator_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut data = state.data.try_lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if let Some(ledger) = &state.query_ledger {
        ledger
            .try_lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .revoke(&run)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    }
    if let Some(mut grant) = data.grants.remove(&run) {
        grant.revoke();
    }
    Ok(Json(json!({"revoked":true})))
}
async fn ledger_view(
    State(state): State<ObservabilityState>,
    headers: HeaderMap,
    Path(run): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(bearer(&headers), &state.operator_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let ledger = state.query_ledger.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let row = ledger
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .inspect(&run)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(row))
}
async fn query(
    State(state): State<ObservabilityState>,
    headers: HeaderMap,
    Path(tool): Path<String>,
    Json(input): Json<Value>,
) -> Result<Response, StatusCode> {
    if !authorized(bearer(&headers), &state.service_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let token = headers
        .get("x-tos-run-token")
        .and_then(|v| v.to_str().ok())
        .and_then(decode_token)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let run =
        input.get("run_id").and_then(Value::as_str).ok_or(StatusCode::BAD_REQUEST)?.to_owned();
    let mut data = state.data.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if data.manager_conflicted {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let Data { store, grants, .. } = &mut *data;
    let grant = grants.get(&run).ok_or(StatusCode::UNAUTHORIZED)?;
    let name = match tool.as_str() {
        "capabilities" => TOOLS[0],
        "node-snapshot" => TOOLS[1],
        "metric-window" => TOOLS[2],
        "event-window" => TOOLS[3],
        "change-history" => TOOLS[4],
        "block-evidence" => TOOLS[5],
        _ => return Err(StatusCode::NOT_FOUND),
    };
    let mut next_grant = grant.clone();
    let prior_calls = grant.calls();
    let prior_bytes = grant.returned_bytes();
    let now = state.now();
    let result = QueryService { store, metrics: &state.metrics }.call(
        &mut next_grant,
        "aura",
        &token,
        now,
        name,
        input,
    );
    if next_grant.calls() > prior_calls {
        let commit_now = state.now();
        if commit_now >= next_grant.expires_monotonic_ms() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        if let Some(ledger) = &state.query_ledger {
            let code = result["error"]["code"].as_str().unwrap_or(if result.is_null() {
                "RUN_BUDGET_EXHAUSTED"
            } else {
                "ok"
            });
            ledger
                .lock()
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
                .advance(
                    &next_grant,
                    commit_now,
                    Attempt {
                        tool: name,
                        result_code: code,
                        returned_bytes: next_grant.returned_bytes().saturating_sub(prior_bytes),
                    },
                )
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        *grants.get_mut(&run).ok_or(StatusCode::SERVICE_UNAVAILABLE)? = next_grant;
    }
    if result.is_null() {
        return Ok(StatusCode::TOO_MANY_REQUESTS.into_response());
    }
    let status = match result["error"]["code"].as_str() {
        None => StatusCode::OK,
        Some("INVALID_ARGUMENT") => StatusCode::BAD_REQUEST,
        Some("UNAUTHENTICATED" | "RUN_TOKEN_EXPIRED") => StatusCode::UNAUTHORIZED,
        Some("OUT_OF_SCOPE") => StatusCode::FORBIDDEN,
        Some("UNKNOWN_NODE" | "UNKNOWN_REFERENCE" | "UNKNOWN_METRIC") => StatusCode::NOT_FOUND,
        Some("CURSOR_MISMATCH" | "SOURCE_CONFLICT") => StatusCode::CONFLICT,
        Some("CURSOR_EXPIRED" | "EVIDENCE_EXPIRED") => StatusCode::GONE,
        Some("RESULT_TOO_LARGE") => StatusCode::PAYLOAD_TOO_LARGE,
        Some("CAPABILITY_UNSUPPORTED" | "CAPABILITY_DISABLED" | "SCHEMA_MISMATCH") => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        Some("SERIES_LIMIT" | "RUN_BUDGET_EXHAUSTED" | "RATE_LIMITED") => {
            StatusCode::TOO_MANY_REQUESTS
        }
        Some("QUERY_TIMEOUT") => StatusCode::GATEWAY_TIMEOUT,
        Some(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    Ok((status, Json(result)).into_response())
}
pub fn router(state: ObservabilityState) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/monitor/heartbeat", get(monitor_heartbeat))
        .route("/v1/ingest", post(ingest))
        .route("/v1/query/{tool}", post(query));
    // Legacy in-memory test state retains the historical test routes. A
    // configured durable service cannot expose grant management on TCP.
    if state.query_ledger.is_none() {
        router = router
            .route("/v1/control/grants", post(grant))
            .route("/v1/control/grants/{run}/revoke", post(revoke));
    }
    router
        .layer(axum::extract::DefaultBodyLimit::max(16_384))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(8)),
            crate::limit_requests,
        ))
        .with_state(state)
}
/// Bind this router exclusively to a private Unix-domain socket. The HTTP
/// listener never exposes it when the durable ledger is configured.
pub fn control_router(state: ObservabilityState) -> Router {
    Router::new()
        .route("/v1/control/projection-health", get(projection_health))
        .route("/v1/control/grants", post(grant))
        .route("/v1/control/grants/{run}/revoke", post(revoke))
        .route("/v1/control/grants/{run}/ledger", get(ledger_view))
        .layer(axum::extract::DefaultBodyLimit::max(16_384))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(8)),
            crate::limit_requests,
        ))
        .with_state(state)
}
/// Offline cache import, bounded independently of JSON deserialization. Input
/// comes from the monitoring host, never from a live validator request.
pub fn import_cache(state: &ObservabilityState, path: PathBuf) -> Result<usize, String> {
    use std::io::{BufRead, BufReader};
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > 8 * 1024 * 1024 {
        return Err("cache import too large".into());
    }
    let mut data = state.data.lock().map_err(|_| "cache unavailable")?;
    let mut count = 0;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.len() > 32_768 {
            return Err("record too large".into());
        }
        let record: Evidence = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        if !state.inventory.nodes.contains(&record.node_id)
            || !state.inventory.scopes.contains(&record.scope_id)
        {
            return Err("record outside inventory".into());
        }
        if let Some(ledger) = &state.query_ledger {
            ledger
                .lock()
                .map_err(|_| "query ledger unavailable")?
                .insert_evidence(&mut data.store, record)?;
        } else {
            data.store.insert(record).map_err(str::to_owned)?;
        }
        count += 1;
    }
    Ok(count)
}
