//! Development-only, cache-only C07 package from verified M process projections.
//! This is not a model prompt or an assertion that other source classes exist.
use crate::{observability::ObservabilityState, query_ledger::boot_millis};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tos_health_core::{edge_snapshot::ProcessPayload, evidence::StoredEvidence, wire::U64};

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct Package {
    schema_version: u32,
    source_profile: &'static str,
    status: &'static str,
    run_id: String,
    network_id: String,
    query_watermark: U64,
    manager_watermark: U64,
    process: Vec<ProcessItem>,
    missing_process: Vec<NodeScope>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeScope {
    node_id: String,
    scope_id: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessItem {
    node_id: String,
    scope_id: String,
    evidence_id: String,
    parent_evidence_id: String,
    query_sequence: U64,
    manager_sequence: U64,
    observed_at_ms: String,
    process_epoch: String,
    value: ProcessPayload,
}

pub struct FrozenPackage {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

fn process_item(entry: &StoredEvidence, manager_watermark: u64) -> Result<ProcessItem, String> {
    let record = &entry.record;
    let payload = &record.payload;
    if record.source_id != "process"
        || !record.redacted
        || !record.quality.clock_valid
        || payload.get("component").and_then(serde_json::Value::as_str) != Some("process")
        || payload.get("evidence_kind").and_then(serde_json::Value::as_str) != Some("derived")
        || payload.get("derivation_version").and_then(serde_json::Value::as_str)
            != Some("m-observation-projection-v1")
    {
        return Err("unsupported package process projection".into());
    }
    let parents = payload
        .get("parent_evidence_ids")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing process parent")?;
    if parents.len() != 1 {
        return Err("invalid process parent count".into());
    }
    let parent = parents[0].as_str().ok_or("invalid process parent")?;
    if !tos_health_core::wire::hash(parent) {
        return Err("invalid process parent hash".into());
    }
    let origin_seq: U64 = serde_json::from_value(
        payload.get("origin_store_seq").ok_or("missing M sequence")?.clone(),
    )
    .map_err(|_| "invalid M sequence")?;
    if origin_seq.0 == 0 || origin_seq.0 > manager_watermark {
        return Err("process parent beyond fixed M watermark".into());
    }
    let process: ProcessPayload = serde_json::from_value(
        payload.get("contract_payload").ok_or("missing process payload")?.clone(),
    )
    .map_err(|_| "invalid process payload")?;
    if process.kind != "process" || process.pid == 0 {
        return Err("invalid process payload identity".into());
    }
    Ok(ProcessItem {
        node_id: record.node_id.clone(),
        scope_id: record.scope_id.clone(),
        evidence_id: entry.evidence_id.clone(),
        parent_evidence_id: parent.into(),
        query_sequence: U64(entry.watermark),
        manager_sequence: origin_seq,
        observed_at_ms: record.observed_at_ms.to_string(),
        process_epoch: record.process_epoch.clone(),
        value: process,
    })
}

/// Fix a small deterministic development package entirely from the durable
/// query cache. `load_evidence` revalidates each derived row against its
/// retained M original; this function never opens M or V/O endpoints.
pub fn freeze_process_package(
    state: &ObservabilityState,
    run_id: &str,
) -> Result<FrozenPackage, String> {
    if state.manager_evidence_db.is_none() {
        return Err("M-derived source unavailable".into());
    }
    let data = state.data.lock().map_err(|_| "query state unavailable")?;
    if data.manager_conflicted {
        return Err("M-derived source conflicted".into());
    }
    let ledger = state.query_ledger.as_ref().ok_or("durable query ledger unavailable")?;
    let ledger = ledger.lock().map_err(|_| "query ledger unavailable")?;
    let grant = ledger.load_active(run_id, boot_millis()?)?.ok_or("run grant inactive")?;
    if grant.network_id != state.inventory.network_id {
        return Err("package network mismatch".into());
    }
    let manager_watermark = grant.manager_watermark.ok_or("M watermark unavailable")?;
    let store = ledger.load_evidence(8 * 1024 * 1024)?;
    if store.watermark() < grant.watermark {
        return Err("query cache behind fixed watermark".into());
    }
    let mut newest: BTreeMap<(String, String), (i64, u64, ProcessItem)> = BTreeMap::new();
    for entry in store.entries() {
        let record = &entry.record;
        if entry.watermark > grant.watermark
            || !grant.nodes.contains(&record.node_id)
            || !grant.scopes.contains(&record.scope_id)
            || record.observed_at_ms < grant.window_start_ms
            || record.observed_at_ms >= grant.window_end_ms
            || record.payload.get("evidence_kind").and_then(serde_json::Value::as_str)
                != Some("derived")
        {
            continue;
        }
        let item = process_item(entry, manager_watermark)?;
        let key = (record.node_id.clone(), record.scope_id.clone());
        let order = (record.observed_at_ms, entry.watermark);
        if newest.get(&key).is_none_or(|(at, seq, _)| order > (*at, *seq)) {
            newest.insert(key, (order.0, order.1, item));
        }
    }
    let mut process = Vec::new();
    let mut missing_process = Vec::new();
    for node_id in &grant.nodes {
        for scope_id in &grant.scopes {
            if let Some((_, _, item)) = newest.remove(&(node_id.clone(), scope_id.clone())) {
                process.push(item);
            } else {
                missing_process
                    .push(NodeScope { node_id: node_id.clone(), scope_id: scope_id.clone() });
            }
        }
    }
    let body = Package {
        schema_version: 1,
        source_profile: "development_process_only",
        status: "partial",
        run_id: grant.run_id,
        network_id: grant.network_id,
        query_watermark: U64(grant.watermark),
        manager_watermark: U64(manager_watermark),
        process,
        missing_process,
    };
    let bytes = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
    if bytes.len() > 16_384 {
        return Err("fixed process package exceeds 16 KiB".into());
    }
    Ok(FrozenPackage { sha256: format!("{:x}", Sha256::digest(&bytes)), bytes })
}
