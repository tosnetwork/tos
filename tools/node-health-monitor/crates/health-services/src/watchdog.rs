//! Independent observer-side dead-man receiver. Delivery replay never refreshes its clock.
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
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
    started: Instant,
}
impl WatchdogState {
    pub fn new(monitor_id: String, token: Vec<u8>) -> Result<Self, String> {
        if !crate::alias(&monitor_id) || token.len() < 32 {
            return Err("invalid watchdog identity".into());
        }
        Ok(Self {
            process: Arc::new(Mutex::new(EpochDeadman::new(0, 45_000).map_err(str::to_owned)?)),
            pipeline: Arc::new(Mutex::new(EpochDeadman::new(0, 100_000).map_err(str::to_owned)?)),
            token: Arc::new(token),
            monitor_id,
            started: Instant::now(),
        })
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
            if self
                .pipeline
                .lock()
                .map_err(|_| "watchdog unavailable")?
                .receive(self.now(), &alert.annotations.monitor_epoch, sequence)
                .map_err(str::to_owned)?
            {
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
pub fn router(state: WatchdogState) -> Router {
    Router::new()
        .route("/v1/watchdog/pipeline", post(receive))
        .layer(axum::extract::DefaultBodyLimit::max(262_144))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(4)),
            crate::limit_requests,
        ))
        .with_state(state)
}
