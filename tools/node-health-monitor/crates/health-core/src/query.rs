use crate::evidence::EvidenceStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const TOOLS: [&str; 6] = [
    "tos_get_capabilities",
    "tos_get_node_snapshot",
    "tos_get_metric_window",
    "tos_get_event_window",
    "tos_get_change_history",
    "tos_get_block_evidence",
];
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRequest {
    pub run_id: String,
    pub node_id: String,
    pub as_of: String,
    pub max_age_seconds: u32,
    pub components: Vec<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricRequest {
    pub run_id: String,
    pub node_ids: Vec<String>,
    pub metric_ids: Vec<String>,
    pub scope_id: String,
    pub start: String,
    pub end: String,
    pub step_seconds: u32,
    pub mode: String,
    pub max_points_per_series: u32,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventRequest {
    pub run_id: String,
    pub node_ids: Vec<String>,
    pub scope_id: String,
    pub start: String,
    pub end: String,
    pub sources: Vec<String>,
    pub kinds: Vec<String>,
    pub correlation_id: String,
    pub contains: String,
    pub limit: u32,
    pub cursor: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeRequest {
    pub run_id: String,
    pub node_ids: Vec<String>,
    pub start: String,
    pub end: String,
    pub kinds: Vec<String>,
    pub limit: u32,
    pub cursor: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockRequest {
    pub run_id: String,
    pub node_ids: Vec<String>,
    pub reference_id: String,
    pub ancestor_depth: u32,
    pub max_events: u32,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesRequest {
    pub run_id: String,
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub run_id: String,
    pub principal: String,
    pub network_id: String,
    pub nodes: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
    pub window_start_ms: i64,
    pub window_end_ms: i64,
    pub change_start_ms: i64,
    pub expires_monotonic_ms: u64,
    pub watermark: u64,
    pub references: BTreeSet<String>,
    token_hash: [u8; 32],
    calls: u32,
    bytes: usize,
    pub delivered_ids: BTreeSet<String>,
    revoked: bool,
}
impl Grant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: String,
        principal: String,
        network_id: String,
        token: &[u8; 32],
        nodes: BTreeSet<String>,
        scopes: BTreeSet<String>,
        start: i64,
        end: i64,
        now: u64,
        watermark: u64,
    ) -> Result<Self, &'static str> {
        if nodes.is_empty()
            || nodes.len() > 4
            || scopes.is_empty()
            || scopes.len() > 8
            || start >= end
            || end.checked_sub(start).is_none_or(|span| span > 3_600_000)
            || run_id.len() != 36
            || principal.is_empty()
            || network_id.is_empty()
        {
            return Err("invalid grant");
        }
        Ok(Self {
            run_id,
            principal,
            network_id,
            nodes,
            scopes,
            window_start_ms: start,
            window_end_ms: end,
            change_start_ms: end.checked_sub(86_400_000).ok_or("window overflow")?,
            expires_monotonic_ms: now.checked_add(200_000).ok_or("expiry overflow")?,
            watermark,
            references: BTreeSet::new(),
            token_hash: Sha256::digest(token).into(),
            calls: 0,
            bytes: 0,
            delivered_ids: BTreeSet::new(),
            revoked: false,
        })
    }
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
    pub fn authenticate(
        &self,
        principal: &str,
        token: &[u8; 32],
        now: u64,
    ) -> Result<(), &'static str> {
        let provided: [u8; 32] = Sha256::digest(token).into();
        let mut difference = 0u8;
        for (left, right) in provided.iter().zip(self.token_hash.iter()) {
            difference |= left ^ right;
        }
        if self.revoked || principal != self.principal || difference != 0 {
            return Err("UNAUTHENTICATED");
        }
        if now >= self.expires_monotonic_ms {
            return Err("RUN_TOKEN_EXPIRED");
        }
        Ok(())
    }
}

pub fn utc_ms(value: &str) -> Result<i64, &'static str> {
    if !value.ends_with('Z') {
        return Err("INVALID_ARGUMENT");
    }
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|v| v.timestamp_millis())
        .map_err(|_| "INVALID_ARGUMENT")
}
fn list(values: &[String], min: usize, max: usize, allowed: Option<&[&str]>) -> bool {
    values.len() >= min
        && values.len() <= max
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
        && values.iter().all(|v| {
            !v.is_empty() && v.len() <= 96 && allowed.is_none_or(|a| a.contains(&v.as_str()))
        })
}
fn nodes(grant: &Grant, values: &[String]) -> Result<(), &'static str> {
    if !list(values, 1, 4, None) {
        return Err("INVALID_ARGUMENT");
    }
    if values.iter().any(|v| !grant.nodes.contains(v)) {
        return Err("OUT_OF_SCOPE");
    }
    Ok(())
}
fn window(
    grant: &Grant,
    start: &str,
    end: &str,
    changes: bool,
) -> Result<(i64, i64), &'static str> {
    let (start, end) = (utc_ms(start)?, utc_ms(end)?);
    let minimum = if changes { grant.change_start_ms } else { grant.window_start_ms };
    if start >= end {
        return Err("INVALID_ARGUMENT");
    }
    if start < minimum || end > grant.window_end_ms {
        return Err("OUT_OF_SCOPE");
    }
    Ok((start, end))
}
fn parse<T: serde::de::DeserializeOwned>(input: &Value) -> Result<T, &'static str> {
    serde_json::from_value(input.clone()).map_err(|_| "INVALID_ARGUMENT")
}

/// Reads only an already populated store. This type cannot construct an upstream
/// client and has no callback for cache misses or background refresh.
pub struct QueryService<'a> {
    pub store: &'a EvidenceStore,
    pub metrics: &'a BTreeSet<String>,
}
impl QueryService<'_> {
    pub fn call(
        &self,
        grant: &mut Grant,
        principal: &str,
        token: &[u8; 32],
        now: u64,
        tool: &str,
        input: Value,
    ) -> Value {
        let result = self.execute(grant, principal, token, now, tool, input);
        match result {
            Ok((data, ids)) => {
                let response = json!({"schema_version":1,"request_id":format!("{}:{}",grant.run_id,grant.calls),"generated_at":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true),"run_id":grant.run_id,"network_id":grant.network_id,"status":"ok","data":data,"evidence":ids,"missing_evidence":[],"coverage":{"cache_only":true,"watermark":grant.watermark.to_string()},"pagination":{"next_cursor":null,"truncated":false,"scan_complete":true},"error":null,"budget":{"remaining_calls":16u32.saturating_sub(grant.calls)}});
                let size = match serde_json::to_vec(&response) {
                    Ok(bytes) => bytes.len(),
                    Err(_) => return error("SERIALIZATION_FAILED", grant),
                };
                if size > 32_768 || grant.bytes.saturating_add(size) > 131_072 {
                    return error("RUN_BUDGET_EXHAUSTED", grant);
                }
                grant.bytes += size;
                grant.delivered_ids.extend(ids);
                response
            }
            Err(code) => error(code, grant),
        }
    }
    fn execute(
        &self,
        grant: &mut Grant,
        principal: &str,
        token: &[u8; 32],
        now: u64,
        tool: &str,
        input: Value,
    ) -> Result<(Value, Vec<String>), &'static str> {
        grant.authenticate(principal, token, now)?;
        if grant.calls >= 16 {
            return Err("RUN_BUDGET_EXHAUSTED");
        }
        grant.calls += 1; // errors and duplicates count too
        if serde_json::to_vec(&input).map_err(|_| "INVALID_ARGUMENT")?.len() > 16_384 {
            return Err("INVALID_ARGUMENT");
        }
        if input.get("run_id").and_then(Value::as_str) != Some(grant.run_id.as_str()) {
            return Err("OUT_OF_SCOPE");
        }
        let visible = || {
            self.store.entries().filter(|e| {
                e.watermark <= grant.watermark
                    && grant.nodes.contains(&e.record.node_id)
                    && grant.scopes.contains(&e.record.scope_id)
            })
        };
        match tool {
            "tos_get_capabilities" => {
                let _: CapabilitiesRequest = parse(&input)?;
                Ok((
                    json!({"cache_only":true,"node_ids":grant.nodes,"scope_ids":grant.scopes,"metric_ids":self.metrics,"tools":TOOLS,"live_fallback":false}),
                    vec![],
                ))
            }
            "tos_get_node_snapshot" => {
                let q: SnapshotRequest = parse(&input)?;
                nodes(grant, std::slice::from_ref(&q.node_id))?;
                if !(1..=180).contains(&q.max_age_seconds)
                    || !list(
                        &q.components,
                        1,
                        10,
                        Some(&[
                            "process",
                            "host",
                            "chain",
                            "consensus",
                            "network",
                            "storage",
                            "index",
                            "gpu",
                            "telemetry",
                            "deployment",
                        ]),
                    )
                {
                    return Err("INVALID_ARGUMENT");
                }
                let at = utc_ms(&q.as_of)?;
                if at < grant.window_start_ms || at > grant.window_end_ms {
                    return Err("OUT_OF_SCOPE");
                }
                let mut values = BTreeMap::new();
                let mut ids = vec![];
                for component in q.components {
                    let entry = visible()
                        .filter(|e| {
                            e.record.node_id == q.node_id
                                && e.record.payload.get("component").and_then(Value::as_str)
                                    == Some(component.as_str())
                                && e.record.quality.usable(
                                    at,
                                    i64::from(q.max_age_seconds) * 1000,
                                    false,
                                )
                        })
                        .max_by_key(|e| e.record.observed_at_ms);
                    let Some(entry) = entry else {
                        return Err("CACHE_MISS");
                    };
                    values.insert(component, json!(entry));
                    ids.push(entry.evidence_id.clone());
                }
                Ok((json!(values), ids))
            }
            "tos_get_metric_window" => {
                let q: MetricRequest = parse(&input)?;
                nodes(grant, &q.node_ids)?;
                if !grant.scopes.contains(&q.scope_id) {
                    return Err("OUT_OF_SCOPE");
                }
                let (start, end) = window(grant, &q.start, &q.end, false)?;
                if !list(&q.metric_ids, 1, 6, None)
                    || ![15, 30, 60, 300].contains(&q.step_seconds)
                    || !(1..=240).contains(&q.max_points_per_series)
                    || !["series", "summary"].contains(&q.mode.as_str())
                {
                    return Err("INVALID_ARGUMENT");
                }
                if q.metric_ids.iter().any(|id| !self.metrics.contains(id)) {
                    return Err("UNKNOWN_METRIC");
                }
                // No interpolated zeros and no percentile calculations over raw values.
                let mut series: BTreeMap<String, Vec<Value>> = BTreeMap::new();
                let mut ids = vec![];
                for e in visible().filter(|e| {
                    q.node_ids.contains(&e.record.node_id)
                        && e.record.scope_id == q.scope_id
                        && e.record.observed_at_ms >= start
                        && e.record.observed_at_ms < end
                }) {
                    let Some(metric) = e.record.payload.get("metric_id").and_then(Value::as_str)
                    else {
                        continue;
                    };
                    if !q.metric_ids.iter().any(|m| m == metric) {
                        continue;
                    }
                    let key = format!("{}:{}", e.record.node_id, metric);
                    let points = series.entry(key).or_default();
                    if points.len() >= q.max_points_per_series as usize {
                        return Err("SERIES_LIMIT");
                    }
                    points.push(json!(e));
                    ids.push(e.evidence_id.clone());
                }
                if series.is_empty() {
                    return Err("CACHE_MISS");
                }
                if series.len() > 32 || ids.len() > 4096 {
                    return Err("SERIES_LIMIT");
                }
                if q.mode == "summary" {
                    return Err("CAPABILITY_UNSUPPORTED");
                }
                Ok((
                    json!({"series":series,"aggregation":"raw","requested_step_seconds":q.step_seconds}),
                    ids,
                ))
            }
            "tos_get_event_window" | "tos_get_change_history" => {
                let (
                    node_ids,
                    scope,
                    start,
                    end,
                    kinds,
                    sources,
                    contains,
                    correlation,
                    limit,
                    cursor,
                ) = if tool == "tos_get_event_window" {
                    let q: EventRequest = parse(&input)?;
                    if !list(
                        &q.sources,
                        1,
                        6,
                        Some(&[
                            "journal",
                            "consensus_trace",
                            "rocksdb",
                            "rpc_probe",
                            "collector",
                            "operator_change",
                        ]),
                    ) || !list(
                        &q.kinds,
                        1,
                        6,
                        Some(&[
                            "error",
                            "warning",
                            "consensus_stage",
                            "storage_sample",
                            "lifecycle",
                            "data_gap",
                        ]),
                    ) || q.contains.len() > 128
                        || q.correlation_id.len() > 160
                    {
                        return Err("INVALID_ARGUMENT");
                    }
                    (
                        q.node_ids,
                        Some(q.scope_id),
                        q.start,
                        q.end,
                        q.kinds,
                        q.sources,
                        q.contains,
                        q.correlation_id,
                        q.limit,
                        q.cursor,
                    )
                } else {
                    let q: ChangeRequest = parse(&input)?;
                    if !list(
                        &q.kinds,
                        1,
                        6,
                        Some(&[
                            "deploy",
                            "restart",
                            "config",
                            "maintenance",
                            "load_test",
                            "resource_limit",
                        ]),
                    ) {
                        return Err("INVALID_ARGUMENT");
                    }
                    (
                        q.node_ids,
                        None,
                        q.start,
                        q.end,
                        q.kinds,
                        vec!["operator_change".into()],
                        String::new(),
                        String::new(),
                        q.limit,
                        q.cursor,
                    )
                };
                nodes(grant, &node_ids)?;
                if scope.as_ref().is_some_and(|s| !grant.scopes.contains(s)) {
                    return Err("OUT_OF_SCOPE");
                }
                let (start, end) = window(grant, &start, &end, tool == "tos_get_change_history")?;
                if !(1..=100).contains(&limit) {
                    return Err("INVALID_ARGUMENT");
                }
                if !cursor.is_empty() {
                    return Err("CURSOR_MISMATCH");
                }
                let mut rows = vec![];
                let mut ids = vec![];
                let mut scanned = 0usize;
                for e in visible() {
                    scanned = scanned.saturating_add(
                        serde_json::to_vec(e).map_err(|_| "INVALID_ARGUMENT")?.len(),
                    );
                    if scanned > 8 * 1024 * 1024 {
                        return Err("QUERY_TIMEOUT");
                    }
                    if !node_ids.contains(&e.record.node_id)
                        || scope.as_ref().is_some_and(|s| *s != e.record.scope_id)
                        || e.record.observed_at_ms < start
                        || e.record.observed_at_ms >= end
                        || !sources.contains(&e.record.source_id)
                    {
                        continue;
                    }
                    if !e
                        .record
                        .payload
                        .get("kind")
                        .and_then(Value::as_str)
                        .is_some_and(|k| kinds.iter().any(|v| v == k))
                    {
                        continue;
                    }
                    if !correlation.is_empty()
                        && e.record.payload.get("correlation_id").and_then(Value::as_str)
                            != Some(&correlation)
                    {
                        continue;
                    }
                    if !contains.is_empty() && !e.record.payload.to_string().contains(&contains) {
                        continue;
                    }
                    if rows.len() >= limit as usize {
                        return Err("SERIES_LIMIT");
                    }
                    rows.push(json!(e));
                    ids.push(e.evidence_id.clone());
                }
                rows.sort_by_key(|e| {
                    (
                        e["record"]["observed_at_ms"].as_i64(),
                        e["record"]["node_id"].as_str().map(str::to_owned),
                        e["record"]["source_record_id"].as_str().map(str::to_owned),
                    )
                });
                Ok((json!(rows), ids))
            }
            "tos_get_block_evidence" => {
                let q: BlockRequest = parse(&input)?;
                nodes(grant, &q.node_ids)?;
                if q.ancestor_depth > 4 || !(1..=100).contains(&q.max_events) {
                    return Err("INVALID_ARGUMENT");
                }
                if !grant.references.contains(&q.reference_id) {
                    return Err("UNKNOWN_REFERENCE");
                }
                if q.ancestor_depth != 0 {
                    return Err("CAPABILITY_UNSUPPORTED");
                }
                let rows: Vec<_> = visible()
                    .filter(|e| {
                        q.node_ids.contains(&e.record.node_id)
                            && e.record.observed_at_ms >= grant.window_start_ms
                            && e.record.observed_at_ms < grant.window_end_ms
                            && e.record.payload.get("reference_id").and_then(Value::as_str)
                                == Some(&q.reference_id)
                    })
                    .collect();
                if rows.is_empty() {
                    return Err("CACHE_MISS");
                }
                if rows.len() > q.max_events as usize {
                    return Err("SERIES_LIMIT");
                }
                let ids = rows.iter().map(|e| e.evidence_id.clone()).collect();
                Ok((json!(rows), ids))
            }
            _ => Err("INVALID_ARGUMENT"),
        }
    }
}
fn error(code: &str, grant: &Grant) -> Value {
    json!({"schema_version":1,"request_id":format!("{}:{}",grant.run_id,grant.calls),"run_id":grant.run_id,"network_id":grant.network_id,"generated_at":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true),"status":"error","data":null,"evidence":[],"error":{"code":code,"message":code,"retryable":false,"retry_after_seconds":null},"missing_evidence":[],"coverage":{"cache_only":true},"pagination":{"next_cursor":null,"truncated":false,"scan_complete":false},"budget":{"remaining_calls":16u32.saturating_sub(grant.calls)}})
}
