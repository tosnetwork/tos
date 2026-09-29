use crate::{authorized, decode_token, hex, random_token, Inventory};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
use tos_health_core::{
    evidence::{Evidence, EvidenceStore},
    query::{Grant, QueryService, TOOLS},
};

pub struct Data {
    pub store: EvidenceStore,
    pub grants: BTreeMap<String, Grant>,
}
#[derive(Clone)]
pub struct ObservabilityState {
    pub data: Arc<Mutex<Data>>,
    pub inventory: Arc<Inventory>,
    pub operator_token: Arc<Vec<u8>>,
    pub ingest_token: Arc<Vec<u8>>,
    pub service_token: Arc<Vec<u8>>,
    pub metrics: Arc<BTreeSet<String>>,
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
            })),
            inventory: Arc::new(inventory),
            operator_token: Arc::new(operator),
            ingest_token: Arc::new(ingest),
            service_token: Arc::new(service),
            metrics: Arc::new(BTreeSet::new()),
            started: Instant::now(),
            epoch: hex(&random_token()?),
        })
    }
    fn now(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
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
    let id = data.store.insert(record).map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
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
    let mut data = state.data.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    data.grants.retain(|_, g| g.expires_monotonic_ms > state.now());
    if data.grants.len() >= 32 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let g = Grant::new(
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
    let mut data = state.data.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if let Some(mut grant) = data.grants.remove(&run) {
        grant.revoke();
    }
    Ok(Json(json!({"revoked":true})))
}
async fn query(
    State(state): State<ObservabilityState>,
    headers: HeaderMap,
    Path(tool): Path<String>,
    Json(input): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    if !authorized(bearer(&headers), &state.service_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let token = headers
        .get("x-tos-run-token")
        .and_then(|v| v.to_str().ok())
        .and_then(decode_token)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let run = input.get("run_id").and_then(Value::as_str).ok_or(StatusCode::BAD_REQUEST)?;
    let mut data = state.data.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let Data { store, grants } = &mut *data;
    let grant = grants.get_mut(run).ok_or(StatusCode::UNAUTHORIZED)?;
    let name = match tool.as_str() {
        "capabilities" => TOOLS[0],
        "node-snapshot" => TOOLS[1],
        "metric-window" => TOOLS[2],
        "event-window" => TOOLS[3],
        "change-history" => TOOLS[4],
        "block-evidence" => TOOLS[5],
        _ => return Err(StatusCode::NOT_FOUND),
    };
    let result = QueryService { store, metrics: &state.metrics }.call(
        grant,
        "aura",
        &token,
        state.now(),
        name,
        input,
    );
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
    Ok((status, Json(result)))
}
pub fn router(state: ObservabilityState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/monitor/heartbeat", get(monitor_heartbeat))
        .route("/v1/ingest", post(ingest))
        .route("/v1/control/grants", post(grant))
        .route("/v1/control/grants/{run}/revoke", post(revoke))
        .route("/v1/query/{tool}", post(query))
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
        data.store.insert(record).map_err(str::to_owned)?;
        count += 1;
    }
    Ok(count)
}
