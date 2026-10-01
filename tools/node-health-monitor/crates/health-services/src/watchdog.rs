//! Independent observer-side dead-man receiver. Delivery replay never refreshes its clock.
use axum::{
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use tos_health_core::{
    observer::EpochDeadman,
    wire::{exact_u64, U64},
};
#[derive(Clone)]
pub struct WatchdogState {
    pub process: Arc<Mutex<EpochDeadman>>,
    pipeline: Arc<Mutex<EpochDeadman>>,
    token: Arc<Vec<u8>>,
    monitor_id: String,
    observer_id: String,
    own_epoch: String,
    own_sequence: Arc<AtomicU64>,
    notice_transport: Arc<Mutex<&'static str>>,
    started: Instant,
}
impl WatchdogState {
    pub fn new(monitor_id: String, token: Vec<u8>) -> Result<Self, String> {
        let epoch = crate::hex(&crate::random_token()?);
        Self::new_with_epoch(monitor_id.clone(), monitor_id, epoch, token)
    }
    pub fn new_with_epoch(
        monitor_id: String,
        observer_id: String,
        own_epoch: String,
        token: Vec<u8>,
    ) -> Result<Self, String> {
        if !crate::alias(&monitor_id)
            || !crate::alias(&observer_id)
            || own_epoch.is_empty()
            || own_epoch.len() > 128
            || token.len() < 32
        {
            return Err("invalid watchdog identity".into());
        }
        Ok(Self {
            process: Arc::new(Mutex::new(EpochDeadman::new(0, 45_000).map_err(str::to_owned)?)),
            pipeline: Arc::new(Mutex::new(EpochDeadman::new(0, 100_000).map_err(str::to_owned)?)),
            token: Arc::new(token),
            monitor_id,
            observer_id,
            own_epoch,
            own_sequence: Arc::new(AtomicU64::new(0)),
            notice_transport: Arc::new(Mutex::new("unknown")),
            started: Instant::now(),
        })
    }
    pub fn completed_tick(&self) -> Result<u64, String> {
        self.own_sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |previous| previous.checked_add(1))
            .map(|previous| previous + 1)
            .map_err(|_| "observer heartbeat sequence exhausted".into())
    }
    pub fn notice_result(&self, accepted: bool) -> Result<(), String> {
        *self.notice_transport.lock().map_err(|_| "observer notice state unavailable")? =
            if accepted { "accepted_by_receiver" } else { "delivery_failed" };
        Ok(())
    }
    pub fn now(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
    pub fn receive_process(&self, epoch: &str, sequence: u64) -> Result<bool, String> {
        self.process
            .lock()
            .map_err(|_| "watchdog unavailable")?
            .receive(self.now(), epoch, sequence)
            .map_err(str::to_owned)
    }
    pub fn unavailable(&self) -> Result<(bool, bool), String> {
        let now = self.now();
        Ok((
            self.process.lock().map_err(|_| "watchdog unavailable")?.unavailable(now),
            self.pipeline.lock().map_err(|_| "watchdog unavailable")?.unavailable(now),
        ))
    }
    pub fn accept_pipeline(&self, bytes: &[u8]) -> Result<usize, String> {
        if bytes.len() > 262_144 {
            return Err("webhook too large".into());
        }
        let body: Webhook = serde_json::from_slice(bytes).map_err(|_| "invalid webhook")?;
        if body.version != "4" || body.alerts.is_empty() || body.alerts.len() > 100 {
            return Err("invalid webhook version or size".into());
        }
        let mut accepted = 0;
        for alert in body.alerts {
            if alert.status != "firing"
                || alert.labels.alertname != "Watchdog"
                || alert.labels.monitor_id != self.monitor_id
            {
                continue;
            }
            if alert.annotations.monitor_epoch.len() > 128 || alert.fingerprint.len() > 128 {
                return Err("invalid heartbeat identity".into());
            }
            tos_health_core::query::utc_ms(&alert.starts_at).map_err(str::to_owned)?;
            let sequence =
                exact_u64(&alert.annotations.evaluation_sequence).map_err(str::to_owned)?;
            // The monitor process heartbeat is the authority for its current
            // epoch. A webhook cannot introduce a new epoch on its own.
            let approved_process = self.process.lock().map_err(|_| "watchdog unavailable")?;
            if approved_process.epoch() != Some(alert.annotations.monitor_epoch.as_str()) {
                return Err("unapproved monitor epoch".into());
            }
            // Hold the process guard through the pipeline update so a concurrent
            // process epoch switch cannot authorize an obsolete message.
            if self
                .pipeline
                .lock()
                .map_err(|_| "watchdog unavailable")?
                .receive(self.now(), &alert.annotations.monitor_epoch, sequence)
                .map_err(str::to_owned)?
            {
                eprintln!(
                    "watchdog pipeline advanced epoch={} sequence={} received_unix_ms={}",
                    alert.annotations.monitor_epoch,
                    sequence,
                    chrono::Utc::now().timestamp_millis()
                );
                accepted += 1;
            }
        }
        Ok(accepted)
    }
}
// Transport metadata can vary by the pinned Alertmanager release; arbitrary extra
// keys are ignored only outside the explicitly typed heartbeat identity.
#[derive(Deserialize)]
struct Webhook {
    version: String,
    alerts: Vec<Alert>,
}
#[derive(Deserialize)]
struct Alert {
    status: String,
    labels: Labels,
    annotations: Annotations,
    fingerprint: String,
    #[serde(rename = "startsAt")]
    starts_at: String,
}
#[derive(Deserialize)]
struct Labels {
    alertname: String,
    monitor_id: String,
}
#[derive(Deserialize)]
struct Annotations {
    monitor_epoch: String,
    evaluation_sequence: String,
}
async fn receive(
    State(state): State<WatchdogState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, StatusCode> {
    if !crate::authorized(headers.get("authorization").and_then(|h| h.to_str().ok()), &state.token)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let n = state.accept_pipeline(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(json!({"accepted_sequences":U64(n as u64)})))
}
async fn own_heartbeat(
    State(state): State<WatchdogState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: axum::body::Bytes,
) -> Result<Json<Value>, StatusCode> {
    if !crate::authorized(headers.get("authorization").and_then(|h| h.to_str().ok()), &state.token)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if uri.query().is_some() || !body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let notice = *state.notice_transport.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(json!({"schema_version":1,"observer_id":state.observer_id,
        "observer_epoch":state.own_epoch,
        "sequence":U64(state.own_sequence.load(Ordering::Acquire)),
        "notification_transport":notice})))
}
pub fn router(state: WatchdogState) -> Router {
    Router::new()
        .route("/v1/watchdog/pipeline", post(receive))
        .route("/v1/watchdog/heartbeat", get(own_heartbeat))
        .layer(axum::extract::DefaultBodyLimit::max(262_144))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(4)),
            crate::limit_requests,
        ))
        .with_state(state)
}

/// One stable notification identity and observation time per outage. Retry
/// attempts are spaced by the watchdog's 15-second tick and capped at 60s.
pub struct NoticeTracker {
    observer_id: String,
    epoch: String,
    episode: u64,
    current: Option<Notice>,
}
struct Notice {
    flags: (bool, bool),
    key: String,
    payload: Value,
    next_ms: u64,
    attempts: u32,
}
impl NoticeTracker {
    pub fn new(observer_id: String, epoch: String) -> Result<Self, String> {
        if !crate::alias(&observer_id) || epoch.is_empty() || epoch.len() > 128 {
            return Err("invalid notice identity".into());
        }
        Ok(Self { observer_id, epoch, episode: 0, current: None })
    }
    pub fn due(
        &mut self,
        now_ms: u64,
        process: bool,
        pipeline: bool,
    ) -> Result<Option<(String, Value)>, String> {
        if !process && !pipeline {
            self.current = None;
            return Ok(None);
        }
        let flags = (process, pipeline);
        if self.current.as_ref().is_none_or(|notice| notice.flags != flags) {
            self.episode = self.episode.checked_add(1).ok_or("notice episodes exhausted")?;
            let key = format!(
                "{:x}",
                Sha256::digest(
                    format!("watchdog-v1:{}:{}:{}", self.observer_id, self.epoch, self.episode)
                        .as_bytes()
                )
            );
            let payload = json!({"schema_version":1,"alert":"MonitoringUnavailable",
                "observer_id":self.observer_id,"severity":"critical","observed_at":chrono::Utc::now().to_rfc3339(),
                "scope":"monitor","process_unavailable":process,"pipeline_unavailable":pipeline,
                "idempotency_key":key});
            self.current = Some(Notice { flags, key, payload, next_ms: now_ms, attempts: 0 });
        }
        let notice = self.current.as_mut().ok_or("notice absent")?;
        if now_ms < notice.next_ms {
            return Ok(None);
        }
        notice.attempts = notice.attempts.saturating_add(1);
        // First three attempts at 15s, then one stable-key retry per 60s.
        let delay = if notice.attempts < 3 { 15_000 } else { 60_000 };
        notice.next_ms = now_ms.checked_add(delay).ok_or("notice deadline exhausted")?;
        Ok(Some((notice.key.clone(), notice.payload.clone())))
    }
}
/// A receiver success is an acceptance boundary, not an end-user receipt.
pub async fn send_notice(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    key: &str,
    payload: &Value,
) -> Result<(), String> {
    if !crate::alias(payload["observer_id"].as_str().ok_or("notice observer absent")?)
        || !tos_health_core::wire::hash(key)
        || payload["idempotency_key"] != key
    {
        return Err("invalid notice".into());
    }
    let body = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
    let hash = format!("{:x}", Sha256::digest(&body));
    let response = client
        .post(url)
        .bearer_auth(token)
        .header("Idempotency-Key", key)
        .header("X-Content-SHA256", hash)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    crate::bounded_body(response, 4096).await.map(|_| ())
}
