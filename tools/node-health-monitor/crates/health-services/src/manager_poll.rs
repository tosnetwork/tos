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
    /// Separate client identity for the manager ingest lane; the edge reader
    /// role must not carry ingest rights. Defaults to `identity_file`.
    #[serde(default)]
    pub manager_identity_file: Option<PathBuf>,
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

/// Fixed native fact frame for any supported native version. Facts come from
/// `native_facts::derive`; a fact the sample cannot support is absent and the
/// frame is marked incomplete, never filled with zero.
pub fn native_fact_frame(
    record: &tos_health_core::native::NativeRecord,
    duration: u64,
    state: &mut tos_health_core::native_facts::NativeFactState,
) -> Result<FactFrame, String> {
    use tos_health_core::native::NativeRecord;
    let (validated, source_epoch, source_age, observed_at, quality) = match record {
        // The v1 publisher carries only the PQ counters; it keeps its fixed frame.
        NativeRecord::V1(v) => return native_frame(v.clone(), duration),
        NativeRecord::V2(v) => {
            (v.validate(), &v.source_epoch, v.source_age_ms, &v.observed_at, &v.quality)
        }
        NativeRecord::V3(v) => {
            (v.validate(), &v.source_epoch, v.source_age_ms, &v.observed_at, &v.quality)
        }
    };
    validated?;
    let observed_at = observed_at.clone().ok_or("missing observation time")?;
    let observed_ms = u64::try_from(tos_health_core::query::utc_ms(&observed_at)?)
        .map_err(|_| "observation time before epoch")?;
    let derived = tos_health_core::native_facts::derive(record, observed_ms, state)?;
    Ok(FactFrame {
        schema_version: 1,
        network_id: record.network_id().to_owned(),
        node_id: record.node_id().to_owned(),
        scope_id: "node".into(),
        // Derived facts are their own source: a change in the derivation must
        // never quarantine the archived native snapshots of the same epoch.
        source_id: "native_facts".into(),
        process_epoch: record.process_epoch().to_owned(),
        source_epoch: format!(
            "{source_epoch}:facts-v{}",
            tos_health_core::native_facts::CATALOG_VERSION
        ),
        generation: record.generation(),
        source_age_ms: U64(source_age.ok_or("missing source age")?),
        request_duration_ms: U64(duration),
        observed_at,
        clock_valid: quality.parse_errors.0 == 0,
        complete: derived.complete,
        facts: derived.facts,
    })
}

/// A one-fact frame derived from the same native sample under its own source
/// id (`native_chain`, `diagnostic`) so a fact that only some nodes can
/// support never blocks the main native catalog.
pub fn secondary_frame(native: &FactFrame, source_id: &str, fact: FactId, value: u64) -> FactFrame {
    FactFrame {
        source_id: source_id.into(),
        complete: true,
        facts: vec![Fact { id: fact, value: U64(value) }],
        ..native.clone()
    }
}

/// Process memory frame from the edge's process source: anonymous memory
/// growth over the trailing window, bound to the process epoch.
pub fn process_frame(
    process: &tos_health_core::edge_snapshot::ProcessEnvelope,
    network_id: &str,
    duration: u64,
    state: &mut tos_health_core::native_facts::NativeFactState,
) -> Result<FactFrame, String> {
    let observed_at = process.observed_at.clone().ok_or("missing process observation time")?;
    let observed_ms = u64::try_from(tos_health_core::query::utc_ms(&observed_at)?)
        .map_err(|_| "observation time before epoch")?;
    let anon = process.payload.anon_bytes.ok_or("process anon bytes unavailable")?.0;
    let growth = tos_health_core::native_facts::process_memory_growth(state, observed_ms, anon);
    Ok(FactFrame {
        schema_version: 1,
        network_id: network_id.to_owned(),
        node_id: process.node_id.clone(),
        scope_id: "node".into(),
        // Derived from the archived process source but its own source: the
        // archived snapshot rows of the same epoch must never be quarantined
        // by a change in this derivation.
        source_id: "process_facts".into(),
        process_epoch: process.process_epoch.clone(),
        source_epoch: format!(
            "{}:facts-v{}",
            process.source_epoch,
            tos_health_core::native_facts::CATALOG_VERSION
        ),
        generation: process.generation,
        source_age_ms: U64(process.source_age_ms.ok_or("missing source age")?),
        request_duration_ms: U64(duration),
        observed_at,
        clock_valid: process.quality.parse_errors.0 == 0,
        complete: true,
        facts: vec![Fact { id: FactId::UnexplainedMemoryBytes, value: U64(growth) }],
    })
}

/// Fixed gauges read from the edge's cached OpenMetrics body: the QUIC
/// backlog is unsent plus unacknowledged bytes. Only these two exact metric
/// names are read; any other line is ignored and a missing line yields no
/// fact rather than zero.
/// Storage write-stop gauge published by the engine (`1` while RocksDB reports
/// `rocksdb.is-write-stopped` on its last committed write). Absent on engines
/// that predate the gauge: then no fact, never zero.
pub fn storage_write_stopped(openmetrics: &str) -> Option<u64> {
    for line in openmetrics.lines() {
        let mut parts = line.split_whitespace();
        if let (Some("tos_health_storage_write_stopped"), Some(v)) = (parts.next(), parts.next()) {
            return match v {
                "0" | "0.0" => Some(0),
                "1" | "1.0" => Some(1),
                _ => None,
            };
        }
    }
    None
}

pub fn quic_backlog_bytes(openmetrics: &str) -> Option<u64> {
    let mut unsent = None;
    let mut unacked = None;
    for line in openmetrics.lines() {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("tos_quic_summary_unsent_bytes"), Some(v)) => unsent = v.parse::<f64>().ok(),
            (Some("tos_quic_summary_unacked_bytes"), Some(v)) => unacked = v.parse::<f64>().ok(),
            _ => {}
        }
    }
    let total = unsent? + unacked?;
    if !total.is_finite() || !(0.0..=9_007_199_254_740_992.0).contains(&total) {
        return None;
    }
    Some(total as u64)
}

/// Deterministic start offset inside the 15-second period, from the node alias.
pub fn stagger_ms(node_id: &str) -> u64 {
    let hash = node_id.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    hash % 12_000
}

async fn post_frame(client: &reqwest::Client, url: &str, token: &str, frame: &FactFrame) {
    // One bounded retry after admission shedding; anything else is reported
    // and dropped, never queued.
    for attempt in 0..2u8 {
        match client.post(url).bearer_auth(token).json(frame).send().await {
            Ok(response) => {
                let status = response.status();
                let body = crate::bounded_body(response, 4096).await.unwrap_or_default();
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS && attempt == 0 {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
                if !status.is_success() {
                    eprintln!(
                        "native poll: manager refused {} facts: {status} {}",
                        frame.source_id,
                        String::from_utf8_lossy(&body)
                    );
                }
                return;
            }
            Err(e) => {
                eprintln!("native poll: manager request failed: {e}");
                return;
            }
        }
    }
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
    let manager_client = match &config.manager_identity_file {
        Some(identity) => crate::client(&config.ca_file, identity)?,
        None => crate::client(&config.ca_file, &config.identity_file)?,
    };
    let edge =
        String::from_utf8(crate::secret(&config.edge_token_file)?).map_err(|e| e.to_string())?;
    let manager =
        String::from_utf8(crate::secret(&config.manager_token_file)?).map_err(|e| e.to_string())?;
    if edge == manager {
        return Err("native poll credentials must differ".into());
    }
    let mut timer = tokio::time::interval(Duration::from_secs(15));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut state = tos_health_core::native_facts::NativeFactState::default();
    let mut first = true;
    loop {
        timer.tick().await;
        let started = Instant::now();
        // Each skipped tick names its reason once; the loop never invents a
        // zero fact for a source it could not read.
        let response = match client.get(&config.edge_url).bearer_auth(&edge).send().await {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                eprintln!("native poll: edge status {}", response.status());
                continue;
            }
            Err(e) => {
                eprintln!("native poll: edge request failed: {e}");
                continue;
            }
        };
        let Ok(bytes) = crate::bounded_body(response, 262_144).await else {
            eprintln!("native poll: edge body exceeded bound");
            continue;
        };
        let snapshot =
            match serde_json::from_slice::<tos_health_core::edge_snapshot::EdgeSnapshot>(&bytes) {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    eprintln!("native poll: edge snapshot invalid: {e}");
                    continue;
                }
            };
        if let Err(e) = snapshot.validate(&config.node_id, &config.network_id) {
            eprintln!("native poll: edge snapshot refused: {e}");
            continue;
        }
        let elapsed = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let Some(record) = snapshot.native_record() else {
            eprintln!("native poll: no native source in edge snapshot");
            continue;
        };
        let frame = match native_fact_frame(&record, elapsed, &mut state) {
            Ok(frame) => frame,
            Err(e) => {
                eprintln!("native poll: fact frame refused: {e}");
                continue;
            }
        };
        post_frame(&manager_client, &config.manager_url, &manager, &frame).await;
        // Secondary sources from the same sample: only when the node supports them.
        if let Some(gap) = tos_health_core::native_facts::chain_gap(&record) {
            let chain = secondary_frame(&frame, "native_chain", FactId::AppliedServedGap, gap);
            post_frame(&manager_client, &config.manager_url, &manager, &chain).await;
        }
        let drops = tos_health_core::native_facts::diagnostic_drops(&record);
        let diagnostic = secondary_frame(&frame, "diagnostic", FactId::DiagnosticDrops, drops);
        post_frame(&manager_client, &config.manager_url, &manager, &diagnostic).await;
        // The edge serves the same completed generation's OpenMetrics from
        // its cache; two fixed gauge lines become the QUIC backlog fact.
        let metrics_url = config.edge_url.replace("/v1/edge/snapshot", "/metrics");
        if let Ok(response) = client.get(&metrics_url).bearer_auth(&edge).send().await {
            if response.status().is_success() {
                if let Ok(body) = crate::bounded_body(response, 2_097_152).await {
                    let text = String::from_utf8_lossy(&body);
                    let mut facts = Vec::with_capacity(2);
                    if let Some(backlog) = quic_backlog_bytes(&text) {
                        facts.push(Fact { id: FactId::QuicBacklogBytes, value: U64(backlog) });
                    }
                    if let Some(stopped) = storage_write_stopped(&text) {
                        facts.push(Fact { id: FactId::RocksdbWriteStopped, value: U64(stopped) });
                    }
                    if !facts.is_empty() {
                        // Both catalog gauges present = complete; an engine
                        // without the storage gauge yields an incomplete frame.
                        let complete = facts.len() == 2;
                        let gauges = FactFrame {
                            source_id: "native_gauges".into(),
                            complete,
                            facts,
                            ..frame.clone()
                        };
                        post_frame(&manager_client, &config.manager_url, &manager, &gauges).await;
                    }
                }
            }
        }
        if let Some(process) = snapshot.process() {
            match process_frame(process, &config.network_id, elapsed, &mut state) {
                Ok(memory) => {
                    post_frame(&manager_client, &config.manager_url, &manager, &memory).await
                }
                Err(e) => eprintln!("native poll: process frame skipped: {e}"),
            }
        }
        if first {
            // The first sample went out at once. A fixed per-node offset now
            // re-phases the periodic timer so the pollers of different nodes
            // spread over the period instead of hitting the manager's bounded
            // ingest admission as one synchronized burst after a deployment.
            first = false;
            tokio::time::sleep(Duration::from_millis(stagger_ms(&config.node_id))).await;
            timer = tokio::time::interval(Duration::from_secs(15));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        }
    }
}
