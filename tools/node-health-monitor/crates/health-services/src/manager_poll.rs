//! Scheduled management-reachability probes. They do not assert consensus health.
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use tos_health_core::{
    rules::{Fact, FactFrame, FactId},
    wire::U64,
};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeConfig {
    pub network_id: String,
    pub node_id: String,
    pub scope_id: String,
    pub edge_url: String,
    pub manager_url: String,
    pub ca_file: PathBuf,
    pub identity_file: PathBuf,
    pub edge_token_file: PathBuf,
    pub manager_token_file: PathBuf,
}
fn fixed(url: &str, path: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|u| {
        u.scheme() == "https"
            && u.path() == path
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
    })
}
pub async fn run(config: ProbeConfig) -> Result<(), String> {
    if !tos_health_core::wire::hash(&config.network_id)
        || !crate::alias(&config.node_id)
        || !crate::alias(&config.scope_id)
        || !fixed(&config.edge_url, "/v1/edge/heartbeat")
        || !fixed(&config.manager_url, "/v1/manager/facts")
    {
        return Err("invalid fixed probe configuration".into());
    }
    let client = crate::client(&config.ca_file, &config.identity_file)?;
    let edge =
        String::from_utf8(crate::secret(&config.edge_token_file)?).map_err(|e| e.to_string())?;
    let manager =
        String::from_utf8(crate::secret(&config.manager_token_file)?).map_err(|e| e.to_string())?;
    if edge == manager {
        return Err("probe credentials must differ".into());
    }
    let epoch = crate::hex(&crate::random_token()?);
    let mut generation = 0u64;
    let mut timer = tokio::time::interval(Duration::from_secs(15));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        generation = generation.checked_add(1).ok_or("probe generation exhausted")?;
        let started = Instant::now();
        let (value, complete) = match client.get(&config.edge_url).bearer_auth(&edge).send().await {
            Ok(response) if response.status().is_success() => {
                match crate::bounded_body(response, 4096).await {
                    Ok(bytes) => {
                        let valid = serde_json::from_slice::<
                            tos_health_core::edge_snapshot::EdgeHeartbeat,
                        >(&bytes)
                        .is_ok_and(|v| v.validate(&config.node_id).is_ok());
                        (1, valid)
                    }
                    Err(_) => (0, false),
                }
            }
            Ok(_) => (0, false),
            Err(e) => (0, e.is_timeout() || e.is_connect()),
        };
        let frame = FactFrame {
            schema_version: 1,
            network_id: config.network_id.clone(),
            node_id: config.node_id.clone(),
            scope_id: config.scope_id.clone(),
            source_id: "edge_probe".into(),
            process_epoch: epoch.clone(),
            source_epoch: epoch.clone(),
            generation: U64(generation),
            source_age_ms: U64(0),
            request_duration_ms: U64(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
            observed_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            clock_valid: true,
            complete,
            facts: vec![Fact { id: FactId::Reachable, value: U64(value) }],
        };
        let sent = client.post(&config.manager_url).bearer_auth(&manager).json(&frame).send().await;
        if let Ok(response) = sent {
            let _ = crate::bounded_body(response, 4096).await;
        }
    }
}

pub fn native_frame(
    value: tos_health_core::native::NativeEnvelope,
    duration: u64,
) -> Result<FactFrame, String> {
    value.validate()?;
    let facts = value
        .payload
        .pq_sign
        .as_ref()
        .map(|pq| vec![Fact { id: FactId::PqSigningFailures, value: pq.failed }])
        .unwrap_or_default();
    Ok(FactFrame {
        schema_version: 1,
        network_id: value.payload.network_id,
        node_id: value.node_id,
        scope_id: value.scope_id,
        source_id: value.source_id,
        process_epoch: value.process_epoch,
        source_epoch: value.source_epoch,
        generation: value.generation,
        source_age_ms: U64(value.source_age_ms.ok_or("missing source age")?),
        request_duration_ms: U64(duration),
        observed_at: value.observed_at.ok_or("missing observation time")?,
        clock_valid: true,
        complete: value.quality.instrumentation_complete
            && value.quality.producer_dropped.0 == 0
            && value.quality.relay_dropped.0 == 0
            && value.quality.parse_errors.0 == 0,
        facts,
    })
}
pub fn native_frame_v2(
    value: tos_health_core::native::NativeEnvelopeV2,
    duration: u64,
) -> Result<FactFrame, String> {
    value.validate()?;
    // C04 rule adapters remain gated until scoped inventory and runtime gates
    // are accepted. Preserve the already-implemented PQ fact without deriving
    // a fake node-wide duty denominator from action request counts.
    let facts = value
        .payload
        .pq_sign
        .as_ref()
        .map(|pq| vec![Fact { id: FactId::PqSigningFailures, value: pq.failed }])
        .unwrap_or_default();
    Ok(FactFrame {
        schema_version: 1,
        network_id: value.payload.network_id,
        node_id: value.node_id,
        scope_id: value.scope_id,
        source_id: value.source_id,
        process_epoch: value.process_epoch,
        source_epoch: value.source_epoch,
        generation: value.generation,
        source_age_ms: U64(value.source_age_ms.ok_or("missing source age")?),
        request_duration_ms: U64(duration),
        observed_at: value.observed_at.ok_or("missing observation time")?,
        clock_valid: true,
        complete: value.quality.instrumentation_complete
            && value.quality.producer_dropped.0 == 0
            && value.quality.relay_dropped.0 == 0
            && value.quality.parse_errors.0 == 0,
        facts,
    })
}

/// Scheduled native facts use the edge cache; a missing source never becomes a zero counter.
pub async fn run_native(config: ProbeConfig) -> Result<(), String> {
    if !tos_health_core::wire::hash(&config.network_id)
        || !crate::alias(&config.node_id)
        || config.scope_id != "node"
        || !fixed(&config.edge_url, "/v1/edge/snapshot")
        || !fixed(&config.manager_url, "/v1/manager/facts")
    {
        return Err("invalid fixed native poll configuration".into());
    }
    let client = crate::client(&config.ca_file, &config.identity_file)?;
    let edge =
        String::from_utf8(crate::secret(&config.edge_token_file)?).map_err(|e| e.to_string())?;
    let manager =
        String::from_utf8(crate::secret(&config.manager_token_file)?).map_err(|e| e.to_string())?;
    if edge == manager {
        return Err("native poll credentials must differ".into());
    }
    let mut timer = tokio::time::interval(Duration::from_secs(15));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let started = Instant::now();
        let Ok(response) = client.get(&config.edge_url).bearer_auth(&edge).send().await else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(bytes) = crate::bounded_body(response, 262_144).await else {
            continue;
        };
        let Ok(snapshot) =
            serde_json::from_slice::<tos_health_core::edge_snapshot::EdgeSnapshot>(&bytes)
        else {
            continue;
        };
        if snapshot.validate(&config.node_id, &config.network_id).is_err() {
            continue;
        }
        let elapsed = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let frame = if let Some(native) = snapshot.native_v2() {
            native_frame_v2(native.clone(), elapsed)
        } else if let Some(native) = snapshot.native() {
            native_frame(native.clone(), elapsed)
        } else {
            continue;
        };
        let Ok(frame) = frame else {
            continue;
        };
        if let Ok(response) =
            client.post(&config.manager_url).bearer_auth(&manager).json(&frame).send().await
        {
            let _ = crate::bounded_body(response, 4096).await;
        }
    }
}
