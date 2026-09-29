use crate::{evidence::EvidenceStore, query_output::PaginationDto};
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
            || !crate::wire::uuid(&run_id)
            || nodes.iter().chain(scopes.iter()).any(|v| !crate::wire::alias(v))
            || principal.is_empty()
            || !crate::wire::hash(&network_id)
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
    /// The immutable authorization tuple. A durable ledger must reject an
    /// update that swaps scope or token while retaining the same run ID.
    pub fn same_binding(&self, other: &Self) -> bool {
        self.run_id == other.run_id
            && self.principal == other.principal
            && self.network_id == other.network_id
            && self.nodes == other.nodes
            && self.scopes == other.scopes
            && self.window_start_ms == other.window_start_ms
            && self.window_end_ms == other.window_end_ms
            && self.change_start_ms == other.change_start_ms
            && self.expires_monotonic_ms == other.expires_monotonic_ms
            && self.watermark == other.watermark
            && self.references == other.references
            && self.token_hash == other.token_hash
    }
    /// Calls, returned bytes and evidence delivery may only advance; a
    /// revoked grant cannot be resurrected by replaying an older snapshot.
    pub fn progress_follows(&self, previous: &Self) -> bool {
        self.same_binding(previous)
            && self.calls >= previous.calls
            && self.calls <= 16
            && self.bytes >= previous.bytes
            && self.bytes <= 131_072
            && self.delivered_ids.is_superset(&previous.delivered_ids)
            && (!previous.revoked || self.revoked)
    }
    pub fn returned_bytes(&self) -> usize {
        self.bytes
    }
    /// Charge bytes that will actually be returned, not just successful data.
    pub fn charge_returned(&mut self, size: usize) -> Result<(), &'static str> {
        if size > 32_768 || self.bytes.checked_add(size).is_none_or(|n| n > 131_072) {
            return Err("RUN_BUDGET_EXHAUSTED");
        }
        self.bytes += size;
        Ok(())
    }
    pub fn revoked(&self) -> bool {
        self.revoked
    }
    pub fn calls(&self) -> u32 {
        self.calls
    }
    pub(crate) fn remaining_calls(&self) -> u32 {
        16u32.saturating_sub(self.calls)
    }
    pub(crate) fn remaining_bytes(&self) -> u32 {
        u32::try_from(131_072usize.saturating_sub(self.bytes)).unwrap_or(0)
    }
    pub fn expires_monotonic_ms(&self) -> u64 {
        self.expires_monotonic_ms
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
    if value.len() > 40 || !value.ends_with('Z') {
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
    if !list(values, 1, 4, None) || values.iter().any(|v| !crate::wire::alias(v)) {
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

fn complete_page() -> PaginationDto {
    PaginationDto { next_cursor: None, truncated: false, scan_complete: true }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // Production passes Grant::token_hash (32 bytes); the vector uses 20.
    assert!(key.len() <= 64);
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn cursor_tag(
    grant: &Grant,
    tool: &str,
    input: &Value,
    expiry: u64,
    seq: u64,
    id: &str,
) -> Result<String, &'static str> {
    let mut filters = input.clone();
    filters.as_object_mut().ok_or("INVALID_ARGUMENT")?.insert("cursor".into(), json!(""));
    let message = serde_json::to_vec(&json!([
        "nhm-c08-cursor-v1",
        grant.principal,
        grant.run_id,
        tool,
        filters,
        grant.network_id,
        grant.nodes,
        grant.scopes,
        grant.window_start_ms,
        grant.window_end_ms,
        grant.change_start_ms,
        grant.watermark,
        expiry,
        seq,
        id,
    ]))
    .map_err(|_| "INVALID_ARGUMENT")?;
    // HMAC-SHA256 with the durable token hash as a private cursor key. The
    // token itself is never placed in a response, log, cursor or model input.
    Ok(format!("{:x}", Sha256Display(hmac_sha256(&grant.token_hash, &message))))
}

struct Sha256Display([u8; 32]);
impl std::fmt::LowerHex for Sha256Display {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn read_cursor(
    grant: &Grant,
    tool: &str,
    input: &Value,
    now: u64,
    cursor: &str,
) -> Result<Option<(u64, String)>, &'static str> {
    if cursor.is_empty() {
        return Ok(None);
    }
    let parts: Vec<_> = cursor.split('.').collect();
    if parts.len() != 5
        || parts[0] != "c1"
        || parts[3].len() != 64
        || !parts[3].bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || parts[4].len() != 64
        || !parts[4].bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("CURSOR_MISMATCH");
    }
    let expiry = parts[1].parse::<u64>().map_err(|_| "CURSOR_MISMATCH")?;
    let seq = parts[2].parse::<u64>().map_err(|_| "CURSOR_MISMATCH")?;
    if seq == 0
        || parts[1] != expiry.to_string()
        || parts[2] != seq.to_string()
        || seq > grant.watermark
        || expiry > grant.expires_monotonic_ms
    {
        return Err("CURSOR_MISMATCH");
    }
    let expected = cursor_tag(grant, tool, input, expiry, seq, parts[3])?;
    if expected.as_bytes().iter().zip(parts[4].as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b))
        != 0
    {
        return Err("CURSOR_MISMATCH");
    }
    if now >= expiry {
        return Err("CURSOR_EXPIRED");
    }
    Ok(Some((seq, parts[3].into())))
}

fn next_cursor(
    grant: &Grant,
    tool: &str,
    input: &Value,
    now: u64,
    seq: u64,
    id: &str,
) -> Result<String, &'static str> {
    const CURSOR_TTL_MS: u64 = 600_000;
    let expiry =
        now.checked_add(CURSOR_TTL_MS).ok_or("CURSOR_MISMATCH")?.min(grant.expires_monotonic_ms);
    let tag = cursor_tag(grant, tool, input, expiry, seq, id)?;
    Ok(format!("c1.{expiry}.{seq}.{id}.{tag}"))
}

#[cfg(test)]
mod cursor_tests {
    use super::{hmac_sha256, next_cursor, read_cursor, Grant, Sha256Display, TOOLS};
    use serde_json::json;
    use std::collections::BTreeSet;

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_one() {
        let tag = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            format!("{tag:x}", tag = Sha256Display(tag)),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn cursor_expiry_and_noncanonical_integer_lexemes_refuse() {
        let grant = Grant::new(
            "00000000-0000-4000-8000-000000000001".into(),
            "aura".into(),
            "a".repeat(64),
            &[7; 32],
            BTreeSet::from(["v1".into()]),
            BTreeSet::from(["node".into()]),
            0,
            60_000,
            0,
            1,
        )
        .unwrap();
        let input = json!({"run_id":grant.run_id,"cursor":""});
        let cursor = next_cursor(&grant, TOOLS[3], &input, 1, 1, &"b".repeat(64)).unwrap();
        assert_eq!(read_cursor(&grant, TOOLS[3], &input, 200_000, &cursor), Err("CURSOR_EXPIRED"));
        let noncanonical = cursor.replacen(".200000.1.", ".0200000.1.", 1);
        assert_eq!(read_cursor(&grant, TOOLS[3], &input, 2, &noncanonical), Err("CURSOR_MISMATCH"));
        let noncanonical_seq = cursor.replacen(".1.", ".+1.", 1);
        assert_eq!(
            read_cursor(&grant, TOOLS[3], &input, 2, &noncanonical_seq),
            Err("CURSOR_MISMATCH")
        );
    }
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
        let generated_ms = chrono::Utc::now().timestamp_millis();
        let saved_input = input.clone();
        let calls_before = grant.calls;
        let result = self.execute(grant, principal, token, now, tool, input);
        let (mut response, delivered) = match result {
            Ok((_legacy_data, ids, pagination)) => {
                let response = match crate::query_output::success(
                    tool,
                    &saved_input,
                    grant,
                    now,
                    generated_ms,
                    &ids,
                    self.store,
                    self.metrics,
                    pagination,
                ) {
                    Ok(response) => response,
                    Err(code) => crate::query_output::error(code, grant, now, generated_ms),
                };
                (response, ids)
            }
            Err(code) => (crate::query_output::error(code, grant, now, generated_ms), vec![]),
        };
        let admitted = grant.calls > calls_before;
        let mut size = if admitted {
            finalize_remaining_bytes(&mut response, grant.bytes)
        } else {
            serde_json::to_vec(&response).map(|bytes| bytes.len()).unwrap_or(usize::MAX)
        };
        if size > 32_768 || grant.bytes.checked_add(size).is_none_or(|n| n > 131_072) {
            response = crate::query_output::error("RUN_BUDGET_EXHAUSTED", grant, now, generated_ms);
            size = finalize_remaining_bytes(&mut response, grant.bytes);
        }
        // No valid envelope fits once the run byte budget is exhausted. The
        // HTTP/MCP adapters must send an empty 429/error, never an unmetered
        // JSON body. Authentication failures before admission are uncharged.
        if admitted && grant.charge_returned(size).is_err() {
            return Value::Null;
        }
        if response["error"].is_null() {
            grant.delivered_ids.extend(delivered);
        }
        response
    }
    fn execute(
        &self,
        grant: &mut Grant,
        principal: &str,
        token: &[u8; 32],
        now: u64,
        tool: &str,
        input: Value,
    ) -> Result<(Value, Vec<String>, PaginationDto), &'static str> {
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
                    complete_page(),
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
                Ok((json!(values), ids, complete_page()))
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
                    complete_page(),
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
                if !(1..=100).contains(&limit) || cursor.len() > 2048 {
                    return Err("INVALID_ARGUMENT");
                }
                let after = read_cursor(grant, tool, &input, now, &cursor)?;
                let mut rows = vec![];
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
                    rows.push(e);
                }
                rows.sort_by(|a, b| {
                    (a.watermark, &a.evidence_id).cmp(&(b.watermark, &b.evidence_id))
                });
                if let Some((seq, id)) = &after {
                    if !rows.iter().any(|row| row.watermark == *seq && row.evidence_id == *id) {
                        return Err("EVIDENCE_EXPIRED");
                    }
                    rows.retain(|row| (row.watermark, &row.evidence_id) > (*seq, id));
                }
                let truncated = rows.len() > limit as usize;
                rows.truncate(limit as usize);
                let next = if truncated {
                    let last = rows.last().ok_or("CURSOR_MISMATCH")?;
                    Some(next_cursor(grant, tool, &input, now, last.watermark, &last.evidence_id)?)
                } else {
                    None
                };
                let ids: Vec<_> = rows.iter().map(|row| row.evidence_id.clone()).collect();
                Ok((
                    json!(rows),
                    ids,
                    PaginationDto { next_cursor: next, truncated, scan_complete: !truncated },
                ))
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
                Ok((json!(rows), ids, complete_page()))
            }
            _ => Err("INVALID_ARGUMENT"),
        }
    }
}

/// Decimal width can make an exact post-return number impossible at a power
/// of ten. Select the greatest conservative value that fits the actual JSON
/// length; never advertise more bytes than remain after this response.
fn finalize_remaining_bytes(response: &mut Value, prior: usize) -> usize {
    let mut low = 0usize;
    let mut high = 131_072usize.saturating_sub(prior);
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        set_remaining_bytes(response, middle);
        let size = serde_json::to_vec(response).map(|bytes| bytes.len()).unwrap_or(usize::MAX);
        if prior
            .checked_add(size)
            .and_then(|used| used.checked_add(middle))
            .is_some_and(|used| used <= 131_072)
        {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    set_remaining_bytes(response, low);
    serde_json::to_vec(response).map(|bytes| bytes.len()).unwrap_or(usize::MAX)
}

fn set_remaining_bytes(response: &mut Value, remaining: usize) {
    response["budget"]["remaining_bytes"] = json!(remaining);
    if response["data"]["remaining_budget"].is_object() {
        response["data"]["remaining_budget"]["remaining_bytes"] = json!(remaining);
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn advertised_remaining_never_exceeds_actual_at_decimal_width_edges() {
        for prior in 129_800..130_300 {
            let mut response = json!({"budget":{"remaining_bytes":0},"data":{"remaining_budget":{"remaining_bytes":0}}});
            let size = finalize_remaining_bytes(&mut response, prior);
            let actual = 131_072usize.saturating_sub(prior + size);
            let advertised = response["budget"]["remaining_bytes"].as_u64().unwrap() as usize;
            assert!(
                advertised <= actual,
                "prior={prior}, actual={actual}, advertised={advertised}"
            );
            assert_eq!(response["data"]["remaining_budget"]["remaining_bytes"], advertised);
        }
    }
}
