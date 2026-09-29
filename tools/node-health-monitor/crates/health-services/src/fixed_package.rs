//! Development-only, cache-only C07 package from verified M process projections.
//! This is not a model prompt or an assertion that other source classes exist.
use crate::{observability::ObservabilityState, query_ledger::boot_millis};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use tos_health_core::query::Grant;
use tos_health_core::{edge_snapshot::ProcessPayload, evidence::StoredEvidence, wire::U64};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Package {
    schema_version: u32,
    source_profile: String,
    status: String,
    run_id: String,
    network_id: String,
    query_watermark: U64,
    manager_watermark: U64,
    process: Vec<ProcessItem>,
    missing_process: Vec<NodeScope>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeScope {
    node_id: String,
    scope_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
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

/// Recheck the complete package after durable restoration, before it can be
/// presented to a model. The database digest alone does not certify that a
/// recomputed/tampered body still represents the frozen grant and source set.
pub(crate) fn validate_package_binding(body: &[u8], grant: &Grant) -> Result<(), String> {
    let package: Package = serde_json::from_slice(body).map_err(|_| "invalid broker package")?;
    let fixed_m = grant.manager_watermark.ok_or("broker package M watermark unavailable")?;
    if package.schema_version != 1
        || package.source_profile != "development_process_only"
        || package.status != "partial"
        || package.run_id != grant.run_id
        || package.network_id != grant.network_id
        || package.query_watermark.0 != grant.watermark
        || package.manager_watermark.0 != fixed_m
    {
        return Err("broker package grant binding mismatch".into());
    }
    let mut covered = BTreeSet::new();
    let mut evidence_ids = BTreeSet::new();
    for item in &package.process {
        if !grant.nodes.contains(&item.node_id)
            || !grant.scopes.contains(&item.scope_id)
            || !covered.insert((&item.node_id, &item.scope_id))
            || !tos_health_core::wire::hash(&item.evidence_id)
            || !tos_health_core::wire::hash(&item.parent_evidence_id)
            || !evidence_ids.insert(&item.evidence_id)
            || item.query_sequence.0 == 0
            || item.query_sequence.0 > grant.watermark
            || item.manager_sequence.0 == 0
            || item.manager_sequence.0 > fixed_m
            || item.process_epoch.is_empty()
            || item.process_epoch.len() > 128
            || item.value.kind != "process"
            || item.value.pid == 0
            || item.observed_at_ms.parse::<i64>().ok().is_none_or(|at| {
                at < grant.window_start_ms
                    || at >= grant.window_end_ms
                    || at.to_string() != item.observed_at_ms
            })
        {
            return Err("broker package process item invalid".into());
        }
    }
    for missing in &package.missing_process {
        if !grant.nodes.contains(&missing.node_id)
            || !grant.scopes.contains(&missing.scope_id)
            || !covered.insert((&missing.node_id, &missing.scope_id))
        {
            return Err("broker package missing-process item invalid".into());
        }
    }
    if covered.len() != grant.nodes.len().saturating_mul(grant.scopes.len()) {
        return Err("broker package source partition incomplete".into());
    }
    Ok(())
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

/// Fix and durably retain a small deterministic development package entirely
/// from the query cache. `load_evidence` revalidates every derived row against
/// its retained M original; this function never opens M or V/O endpoints.
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
    let mut ledger = ledger.lock().map_err(|_| "query ledger unavailable")?;
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
        source_profile: "development_process_only".into(),
        status: "partial".into(),
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
    let sha256 = ledger.save_package(run_id, &bytes, boot_millis()?)?;
    Ok(FrozenPackage { sha256, bytes })
}
