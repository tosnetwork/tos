use crate::authorized;
use axum::{
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tos_health_core::{
    evidence::Evidence,
    source::{Availability, Coverage, SourceQuality},
};

#[derive(Clone)]
pub struct EdgeState {
    pub token: Arc<Vec<u8>>,
    pub node: String,
    pub cache: Arc<Mutex<Option<Evidence>>>,
    pub native: Arc<Mutex<crate::native_cache::NativeCache>>,
    pub started: Instant,
    pub limiter: Arc<Mutex<(Instant, u32)>>,
}
impl EdgeState {
    pub fn new(node: String, token: Vec<u8>) -> Self {
        Self {
            node,
            token: Arc::new(token),
            cache: Arc::new(Mutex::new(None)),
            native: crate::native_cache::cache(),
            started: Instant::now(),
            limiter: Arc::new(Mutex::new((Instant::now(), 4))),
        }
    }
}
fn permit(state: &EdgeState, headers: &HeaderMap, uri: &axum::http::Uri) -> Result<(), StatusCode> {
    if uri.query().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !authorized(headers.get("authorization").and_then(|h| h.to_str().ok()), &state.token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut limiter = state.limiter.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let elapsed = limiter.0.elapsed().as_secs();
    if elapsed > 0 {
        limiter.1 = limiter.1.saturating_add(elapsed.min(4) as u32).min(4);
        limiter.0 = Instant::now();
    }
    if limiter.1 == 0 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    limiter.1 -= 1;
    Ok(())
}
async fn heartbeat(
    State(state): State<EdgeState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, StatusCode> {
    permit(&state, &headers, &uri)?;
    let cache = state.cache.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(
        json!({"schema_version":1,"node_id":state.node,"edge_uptime_seconds":state.started.elapsed().as_secs(),"last_observed_at_ms":cache.as_ref().map(|e|e.observed_at_ms),"validator_consensus_health":"unknown"}),
    ))
}
async fn snapshot(
    State(state): State<EdgeState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Evidence>, StatusCode> {
    permit(&state, &headers, &uri)?;
    let cache = state.cache.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let Some(value) = cache.as_ref() else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    if !value.quality.usable(chrono::Utc::now().timestamp_millis(), 30_000, false) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(value.clone()))
}
async fn capabilities(
    State(state): State<EdgeState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, StatusCode> {
    permit(&state, &headers, &uri)?;
    Ok(Json(
        json!({"schema_version":1,"node_id":state.node,"cache_only":true,"available":["process"],"unsupported":["core_duty","core_persistence","core_queue","getstats_adapter"],"production_gate":"not_passed"}),
    ))
}
async fn metrics(
    State(state): State<EdgeState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<([(axum::http::header::HeaderName, &'static str); 1], String), StatusCode> {
    permit(&state, &headers, &uri)?;
    let body = state
        .native
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .read()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        body,
    ))
}
pub fn router(state: EdgeState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/v1/edge/heartbeat", get(heartbeat))
        .route("/v1/edge/snapshot", get(snapshot))
        .route("/v1/edge/capabilities", get(capabilities))
        .layer(axum::extract::DefaultBodyLimit::max(4096))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(8)),
            crate::limit_requests,
        ))
        .with_state(state)
}
fn bounded_read(path: &str, limit: u64) -> Result<String, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("local source too large".into());
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}
pub fn sample_process(node: &str, pid: u32, sequence: u64) -> Result<Evidence, String> {
    if pid == 0 || !crate::alias(node) {
        return Err("invalid process inventory".into());
    }
    let stat = bounded_read(&format!("/proc/{pid}/stat"), 16_384)?;
    let fields: Vec<_> =
        stat.rsplit_once(')').ok_or("malformed process stat")?.1.split_whitespace().collect();
    let start = fields
        .get(19)
        .ok_or("missing process start")?
        .parse::<u64>()
        .map_err(|_| "invalid process start")?;
    let boot = bounded_read("/proc/sys/kernel/random/boot_id", 128)?;
    let epoch = format!("{}:{pid}:{start}", boot.trim());
    let status = bounded_read(&format!("/proc/{pid}/status"), 65_536)?;
    let mut values = BTreeMap::new();
    for line in status.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if ["VmRSS", "RssAnon", "RssFile", "VmSwap"].contains(&key) {
                let mut words = value.split_whitespace();
                let count = words
                    .next()
                    .ok_or("missing value")?
                    .parse::<u64>()
                    .map_err(|_| "invalid memory value")?;
                if words.next() != Some("kB") {
                    return Err("unknown memory unit".into());
                }
                values.insert(
                    key.to_owned(),
                    count.checked_mul(1024).ok_or("memory overflow")?.to_string(),
                );
            }
        }
    }
    // Detect PID reuse between the two fixed reads.
    let second = bounded_read(&format!("/proc/{pid}/stat"), 16_384)?;
    if second
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|v| v.parse::<u64>().ok())
        != Some(start)
    {
        return Err("process epoch changed during sample".into());
    }
    let at = chrono::Utc::now().timestamp_millis();
    Ok(Evidence {
        node_id: node.into(),
        scope_id: "node".into(),
        source_id: "collector".into(),
        source_record_id: sequence.to_string(),
        process_epoch: epoch.clone(),
        observed_at_ms: at,
        received_at_ms: at,
        quality: SourceQuality {
            availability: Availability::Available,
            coverage: Coverage::Partial,
            observed_at_ms: Some(at),
            last_success_at_ms: Some(at),
            clock_valid: true,
            process_epoch: epoch,
            source_sequence: sequence.to_string(),
        },
        payload: json!({"component":"process","pid":pid,"memory_bytes":values,"cpu_user_ticks":fields.get(11),"cpu_system_ticks":fields.get(12),"missing_fields":["host_pressure","cgroup_effective","fd_usage","validator_core"]}),
        redacted: true,
    })
}
pub async fn sample_loop(state: EdgeState, pid: u32) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sequence = 0u64;
    loop {
        interval.tick().await;
        let Some(next) = sequence.checked_add(1) else {
            return;
        };
        sequence = next;
        let node = state.node.clone();
        // One blocking task is awaited to actual completion; no timeout creates a replacement.
        let result =
            tokio::task::spawn_blocking(move || sample_process(&node, pid, sequence)).await;
        if let Ok(Ok(sample)) = result {
            if let Ok(mut cache) = state.cache.lock() {
                *cache = Some(sample);
            }
        }
    }
}
