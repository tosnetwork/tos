//! Development-only, cache-only C07 package fixed at the grant's query watermark.
//! Version 3 carries, per node, the newest native consensus sample with its
//! fixed chain and storage views, the read-only health verdict copy and the
//! newest process and host samples per scope. Everything is read from the durable query
//! cache; nothing here opens M, a model or a V/O endpoint. When the 16 KiB
//! budget is exceeded, items are dropped in a fixed priority order and each
//! drop is listed explicitly so the model cannot mistake absence for health.
use crate::{
    manager_query_source::VERDICT_SOURCE, observability::ObservabilityState,
    query_ledger::boot_millis,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use tos_health_core::query::Grant;
use tos_health_core::{
    edge_snapshot::{CgroupPayload, ProcessPayload},
    evidence::StoredEvidence,
    query_output::{HealthVerdictDto, PayloadDto},
    wire::U64,
};

pub const PACKAGE_MAX_BYTES: usize = 16_384;
pub const PACKAGE_SCHEMA_VERSION: u32 = 3;
pub const PROFILE_V3: &str = "development_native_process_host_v3";
pub const BROKER_PACKAGE_SUPERSEDED: &str = "BROKER_PACKAGE_SUPERSEDED";
const TRUNCATION_REASON: &str = "package_budget_16kib";

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
    host: Vec<HostItem>,
    missing_host: Vec<NodeScope>,
    native: Vec<NativeItem>,
    missing_native: Vec<NodeScope>,
    health: Vec<VerdictItem>,
    missing_health: Vec<NodeScope>,
    truncated: Vec<Truncated>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostItem {
    node_id: String,
    scope_id: String,
    evidence_id: String,
    parent_evidence_id: String,
    query_sequence: U64,
    manager_sequence: U64,
    observed_at_ms: String,
    process_epoch: String,
    value: CgroupPayload,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeItem {
    node_id: String,
    scope_id: String,
    evidence_id: String,
    parent_evidence_id: String,
    query_sequence: U64,
    manager_sequence: U64,
    observed_at_ms: String,
    process_epoch: String,
    consensus: PayloadDto,
    chain: Option<PayloadDto>,
    storage: Option<PayloadDto>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerdictItem {
    node_id: String,
    scope_id: String,
    evidence_id: String,
    observed_at_ms: String,
    evaluation_sequence: U64,
    verdicts: Vec<HealthVerdictDto>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Truncated {
    node_id: String,
    scope_id: String,
    component: String,
    reason: String,
}

pub struct FrozenPackage {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

fn valid_time(value: &str, grant: &Grant, window_bound: bool) -> bool {
    value.parse::<i64>().ok().is_some_and(|at| {
        at.to_string() == value
            && at >= grant.window_start_ms
            && (!window_bound || at < grant.window_end_ms)
    })
}

fn validate_process_item(item: &ProcessItem, grant: &Grant, fixed_m: u64) -> bool {
    grant.nodes.contains(&item.node_id)
        && grant.scopes.contains(&item.scope_id)
        && tos_health_core::wire::hash(&item.evidence_id)
        && tos_health_core::wire::hash(&item.parent_evidence_id)
        && item.query_sequence.0 != 0
        && item.query_sequence.0 <= grant.watermark
        && item.manager_sequence.0 != 0
        && item.manager_sequence.0 <= fixed_m
        && !item.process_epoch.is_empty()
        && item.process_epoch.len() <= 128
        && item.value.kind == "process"
        && item.value.pid != 0
        && valid_time(&item.observed_at_ms, grant, true)
}

fn validate_host_item(item: &HostItem, grant: &Grant, fixed_m: u64) -> bool {
    grant.nodes.contains(&item.node_id)
        && grant.scopes.contains(&item.scope_id)
        && tos_health_core::wire::hash(&item.evidence_id)
        && tos_health_core::wire::hash(&item.parent_evidence_id)
        && item.query_sequence.0 != 0
        && item.query_sequence.0 <= grant.watermark
        && item.manager_sequence.0 != 0
        && item.manager_sequence.0 <= fixed_m
        && !item.process_epoch.is_empty()
        && item.process_epoch.len() <= 128
        && item.value.kind == "host_cgroup"
        && item.value.cpu_period_usec.0 != 0
        && valid_time(&item.observed_at_ms, grant, true)
}

// Read only the discriminator for superseded formats. Current bodies still
// require every field and the complete grant-bound source partition.
fn check_discriminator(body: &[u8]) -> Result<(), String> {
    if body.len() > PACKAGE_MAX_BYTES {
        return Err("broker package exceeds 16 KiB".into());
    }
    #[derive(Deserialize)]
    struct Discriminator {
        schema_version: u32,
        source_profile: String,
    }
    let discriminator: Discriminator =
        serde_json::from_slice(body).map_err(|_| "invalid broker package")?;
    match discriminator.schema_version {
        1 | 2 => Err(BROKER_PACKAGE_SUPERSEDED.into()),
        PACKAGE_SCHEMA_VERSION if discriminator.source_profile == PROFILE_V3 => Ok(()),
        PACKAGE_SCHEMA_VERSION => Err("broker package profile mismatch".into()),
        _ => Err("unsupported broker package version".into()),
    }
}

fn parse_package(body: &[u8]) -> Result<Package, String> {
    check_discriminator(body)?;
    serde_json::from_slice(body).map_err(|_| "invalid broker package".into())
}

fn validate_current(body: &[u8], grant: &Grant) -> Result<(), String> {
    let package = parse_package(body)?;
    let fixed_m = grant.manager_watermark.ok_or("broker package M watermark unavailable")?;
    if package.schema_version != PACKAGE_SCHEMA_VERSION
        || package.source_profile != PROFILE_V3
        || package.status != "partial"
        || package.run_id != grant.run_id
        || package.network_id != grant.network_id
        || package.query_watermark.0 != grant.watermark
        || package.manager_watermark.0 != fixed_m
    {
        return Err("broker package grant binding mismatch".into());
    }
    let mut evidence_ids = BTreeSet::new();
    let mut process_cover = BTreeSet::new();
    for item in &package.process {
        if !validate_process_item(item, grant, fixed_m)
            || !process_cover.insert((item.node_id.clone(), item.scope_id.clone()))
            || !evidence_ids.insert(item.evidence_id.clone())
        {
            return Err("broker package process item invalid".into());
        }
    }
    for missing in &package.missing_process {
        if !grant.nodes.contains(&missing.node_id)
            || !grant.scopes.contains(&missing.scope_id)
            || !process_cover.insert((missing.node_id.clone(), missing.scope_id.clone()))
        {
            return Err("broker package missing-process item invalid".into());
        }
    }
    let mut host_cover = BTreeSet::new();
    for item in &package.host {
        if !validate_host_item(item, grant, fixed_m)
            || !host_cover.insert((item.node_id.clone(), item.scope_id.clone()))
            || !evidence_ids.insert(item.evidence_id.clone())
        {
            return Err("broker package host item invalid".into());
        }
    }
    for missing in &package.missing_host {
        if !grant.nodes.contains(&missing.node_id)
            || !grant.scopes.contains(&missing.scope_id)
            || !host_cover.insert((missing.node_id.clone(), missing.scope_id.clone()))
        {
            return Err("broker package missing-host item invalid".into());
        }
    }
    let mut native_cover = BTreeSet::new();
    let mut chain_present = BTreeSet::new();
    let mut storage_present = BTreeSet::new();
    for item in &package.native {
        if !grant.nodes.contains(&item.node_id)
            || item.scope_id != "node"
            || !grant.scopes.contains(&item.scope_id)
            || !tos_health_core::wire::hash(&item.evidence_id)
            || !tos_health_core::wire::hash(&item.parent_evidence_id)
            || item.query_sequence.0 == 0
            || item.query_sequence.0 > grant.watermark
            || item.manager_sequence.0 == 0
            || item.manager_sequence.0 > fixed_m
            || item.process_epoch.is_empty()
            || item.process_epoch.len() > 128
            || !valid_time(&item.observed_at_ms, grant, true)
            || !matches!(item.consensus, PayloadDto::NativeConsensus { .. })
            || !item.chain.as_ref().is_none_or(|c| matches!(c, PayloadDto::ChainAnchors { .. }))
            || !item.storage.as_ref().is_none_or(|s| matches!(s, PayloadDto::StorageState { .. }))
            || !native_cover.insert(item.node_id.clone())
            || !evidence_ids.insert(item.evidence_id.clone())
        {
            return Err("broker package native item invalid".into());
        }
        if item.chain.is_some() {
            chain_present.insert(item.node_id.clone());
        }
        if item.storage.is_some() {
            storage_present.insert(item.node_id.clone());
        }
    }
    for missing in &package.missing_native {
        if !grant.nodes.contains(&missing.node_id)
            || missing.scope_id != "node"
            || !native_cover.insert(missing.node_id.clone())
        {
            return Err("broker package missing-native item invalid".into());
        }
    }
    let mut health_cover = BTreeSet::new();
    for item in &package.health {
        if !grant.nodes.contains(&item.node_id)
            || item.scope_id != "node"
            || !tos_health_core::wire::hash(&item.evidence_id)
            || !valid_time(&item.observed_at_ms, grant, false)
            || item.verdicts.len() > 64
            || item.verdicts.iter().any(|v| {
                !tos_health_core::wire::alias(&v.rule) || !tos_health_core::wire::alias(&v.scope_id)
            })
            || !health_cover.insert(item.node_id.clone())
            || !evidence_ids.insert(item.evidence_id.clone())
        {
            return Err("broker package health item invalid".into());
        }
    }
    for missing in &package.missing_health {
        if !grant.nodes.contains(&missing.node_id)
            || missing.scope_id != "node"
            || !health_cover.insert(missing.node_id.clone())
        {
            return Err("broker package missing-health item invalid".into());
        }
    }
    // A node whose whole consensus sample was dropped also lost its chain and
    // storage views earlier in the drop order; register consensus drops first
    // so those view entries validate against the complete native partition.
    for cut in &package.truncated {
        if cut.reason != TRUNCATION_REASON || !grant.nodes.contains(&cut.node_id) {
            return Err("broker package truncation entry invalid".into());
        }
        if cut.component == "consensus"
            && (cut.scope_id != "node" || !native_cover.insert(cut.node_id.clone()))
        {
            return Err("broker package truncation entry invalid".into());
        }
    }
    let mut chain_cut = BTreeSet::new();
    let mut storage_cut = BTreeSet::new();
    for cut in &package.truncated {
        let accepted = match cut.component.as_str() {
            "process" => {
                grant.scopes.contains(&cut.scope_id)
                    && process_cover.insert((cut.node_id.clone(), cut.scope_id.clone()))
            }
            "host" => {
                grant.scopes.contains(&cut.scope_id)
                    && host_cover.insert((cut.node_id.clone(), cut.scope_id.clone()))
            }
            "consensus" => true,
            "chain" => {
                cut.scope_id == "node"
                    && native_cover.contains(&cut.node_id)
                    && !chain_present.contains(&cut.node_id)
                    && chain_cut.insert(cut.node_id.clone())
            }
            "storage" => {
                cut.scope_id == "node"
                    && native_cover.contains(&cut.node_id)
                    && !storage_present.contains(&cut.node_id)
                    && storage_cut.insert(cut.node_id.clone())
            }
            _ => false,
        };
        if !accepted {
            return Err("broker package truncation entry invalid".into());
        }
    }
    if process_cover.len() != grant.nodes.len().saturating_mul(grant.scopes.len())
        || host_cover.len() != grant.nodes.len().saturating_mul(grant.scopes.len())
        || native_cover.len() != grant.nodes.len()
        || health_cover.len() != grant.nodes.len()
    {
        return Err("broker package source partition incomplete".into());
    }
    Ok(())
}

/// Recheck the complete package after durable restoration, before it can be
/// presented to a model. The database digest alone does not certify that a
/// recomputed/tampered body still represents the frozen grant and source set.
pub(crate) fn validate_package_binding(body: &[u8], grant: &Grant) -> Result<(), String> {
    validate_current(body, grant)
}

/// Every query-cache evidence id the package presents to a model. This is the
/// delivered set for a summary-only run without tool calls.
pub fn package_evidence_ids(body: &[u8]) -> Result<BTreeSet<String>, String> {
    let package = parse_package(body)?;
    Ok(package
        .process
        .iter()
        .map(|item| item.evidence_id.clone())
        .chain(package.host.iter().map(|item| item.evidence_id.clone()))
        .chain(package.native.iter().map(|item| item.evidence_id.clone()))
        .chain(package.health.iter().map(|item| item.evidence_id.clone()))
        .collect())
}

fn derived_parent(entry: &StoredEvidence, manager_watermark: u64) -> Result<(String, U64), String> {
    let payload = &entry.record.payload;
    if payload.get("evidence_kind").and_then(serde_json::Value::as_str) != Some("derived")
        || payload.get("derivation_version").and_then(serde_json::Value::as_str)
            != Some("m-observation-projection-v1")
        || !entry.record.redacted
        || !entry.record.quality.clock_valid
    {
        return Err("unsupported package projection".into());
    }
    let parents = payload
        .get("parent_evidence_ids")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing projection parent")?;
    if parents.len() != 1 {
        return Err("invalid projection parent count".into());
    }
    let parent = parents[0].as_str().ok_or("invalid projection parent")?;
    if !tos_health_core::wire::hash(parent) {
        return Err("invalid projection parent hash".into());
    }
    let origin_seq: U64 = serde_json::from_value(
        payload.get("origin_store_seq").ok_or("missing M sequence")?.clone(),
    )
    .map_err(|_| "invalid M sequence")?;
    if origin_seq.0 == 0 || origin_seq.0 > manager_watermark {
        return Err("projection parent beyond fixed M watermark".into());
    }
    Ok((parent.to_owned(), origin_seq))
}

fn process_item(entry: &StoredEvidence, manager_watermark: u64) -> Result<ProcessItem, String> {
    let record = &entry.record;
    let payload = &record.payload;
    if record.source_id != "process"
        || payload.get("component").and_then(serde_json::Value::as_str) != Some("process")
    {
        return Err("unsupported package process projection".into());
    }
    let (parent, origin_seq) = derived_parent(entry, manager_watermark)?;
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
        parent_evidence_id: parent,
        query_sequence: U64(entry.watermark),
        manager_sequence: origin_seq,
        observed_at_ms: record.observed_at_ms.to_string(),
        process_epoch: record.process_epoch.clone(),
        value: process,
    })
}

fn host_item(entry: &StoredEvidence, manager_watermark: u64) -> Result<HostItem, String> {
    let record = &entry.record;
    let payload = &record.payload;
    if record.source_id != "host_cgroup"
        || payload.get("component").and_then(serde_json::Value::as_str) != Some("host")
    {
        return Err("unsupported package host projection".into());
    }
    let (parent, origin_seq) = derived_parent(entry, manager_watermark)?;
    let process: CgroupPayload = serde_json::from_value(
        payload.get("contract_payload").ok_or("missing host payload")?.clone(),
    )
    .map_err(|_| "invalid host payload")?;
    if process.kind != "host_cgroup" || process.cpu_period_usec.0 == 0 {
        return Err("invalid host payload identity".into());
    }
    Ok(HostItem {
        node_id: record.node_id.clone(),
        scope_id: record.scope_id.clone(),
        evidence_id: entry.evidence_id.clone(),
        parent_evidence_id: parent,
        query_sequence: U64(entry.watermark),
        manager_sequence: origin_seq,
        observed_at_ms: record.observed_at_ms.to_string(),
        process_epoch: record.process_epoch.clone(),
        value: process,
    })
}

fn native_item(entry: &StoredEvidence, manager_watermark: u64) -> Result<NativeItem, String> {
    let record = &entry.record;
    let payload = &record.payload;
    if record.source_id != "native_core"
        || payload.get("component").and_then(serde_json::Value::as_str) != Some("consensus")
    {
        return Err("unsupported package native projection".into());
    }
    let (parent, origin_seq) = derived_parent(entry, manager_watermark)?;
    let consensus: PayloadDto = serde_json::from_value(
        payload.get("contract_payload").ok_or("missing native payload")?.clone(),
    )
    .map_err(|_| "invalid native payload")?;
    if !matches!(consensus, PayloadDto::NativeConsensus { .. }) {
        return Err("native sample without typed consensus is not packaged".into());
    }
    let view = |field: &str| -> Result<Option<PayloadDto>, String> {
        match payload.get(field) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(value) => serde_json::from_value(value.clone())
                .map(Some)
                .map_err(|_| format!("invalid native {field}")),
        }
    };
    Ok(NativeItem {
        node_id: record.node_id.clone(),
        scope_id: record.scope_id.clone(),
        evidence_id: entry.evidence_id.clone(),
        parent_evidence_id: parent,
        query_sequence: U64(entry.watermark),
        manager_sequence: origin_seq,
        observed_at_ms: record.observed_at_ms.to_string(),
        process_epoch: record.process_epoch.clone(),
        consensus,
        chain: view("chain_payload")?,
        storage: view("storage_payload")?,
    })
}

fn verdict_item(entry: &StoredEvidence) -> Result<VerdictItem, String> {
    let record = &entry.record;
    let payload: PayloadDto = serde_json::from_value(
        record.payload.get("contract_payload").ok_or("missing verdict payload")?.clone(),
    )
    .map_err(|_| "invalid verdict payload")?;
    let PayloadDto::HealthVerdicts { evaluation_sequence, verdicts, .. } = payload else {
        return Err("verdict row payload is not health_verdicts".into());
    };
    Ok(VerdictItem {
        node_id: record.node_id.clone(),
        scope_id: record.scope_id.clone(),
        evidence_id: entry.evidence_id.clone(),
        observed_at_ms: record.observed_at_ms.to_string(),
        evaluation_sequence,
        verdicts,
    })
}

/// Drop exactly one item in fixed priority order: process then host samples first,
/// then storage and chain views, then whole consensus samples, always from
/// the last node backwards. Verdict copies are never dropped.
fn truncate_one(package: &mut Package) -> bool {
    if let Some(item) = package.process.pop() {
        package.truncated.push(Truncated {
            node_id: item.node_id,
            scope_id: item.scope_id,
            component: "process".into(),
            reason: TRUNCATION_REASON.into(),
        });
        return true;
    }
    if let Some(item) = package.host.pop() {
        package.truncated.push(Truncated {
            node_id: item.node_id,
            scope_id: item.scope_id,
            component: "host".into(),
            reason: TRUNCATION_REASON.into(),
        });
        return true;
    }
    for component in ["storage", "chain"] {
        if let Some(item) = package.native.iter_mut().rev().find(|item| {
            if component == "storage" {
                item.storage.is_some()
            } else {
                item.chain.is_some()
            }
        }) {
            if component == "storage" {
                item.storage = None;
            } else {
                item.chain = None;
            }
            package.truncated.push(Truncated {
                node_id: item.node_id.clone(),
                scope_id: item.scope_id.clone(),
                component: component.into(),
                reason: TRUNCATION_REASON.into(),
            });
            return true;
        }
    }
    if let Some(item) = package.native.pop() {
        package.truncated.push(Truncated {
            node_id: item.node_id,
            scope_id: item.scope_id,
            component: "consensus".into(),
            reason: TRUNCATION_REASON.into(),
        });
        return true;
    }
    false
}

/// Fix and durably retain a bounded deterministic development package
/// entirely from the query cache. `load_evidence` revalidates every derived
/// row against its retained M original; this function never opens M or V/O.
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
    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut newest_process: BTreeMap<(String, String), (i64, u64, ProcessItem)> = BTreeMap::new();
    let mut newest_host: BTreeMap<(String, String), (i64, u64, HostItem)> = BTreeMap::new();
    let mut newest_native: BTreeMap<String, (i64, u64, NativeItem)> = BTreeMap::new();
    let mut newest_verdict: BTreeMap<String, (i64, u64, VerdictItem)> = BTreeMap::new();
    for entry in store.entries() {
        let record = &entry.record;
        if entry.watermark > grant.watermark
            || !grant.nodes.contains(&record.node_id)
            || !grant.scopes.contains(&record.scope_id)
        {
            continue;
        }
        let order = (record.observed_at_ms, entry.watermark);
        let kind = record.payload.get("evidence_kind").and_then(serde_json::Value::as_str);
        let component = record.payload.get("component").and_then(serde_json::Value::as_str);
        if record.source_id == VERDICT_SOURCE && kind == Some("observation") {
            if record.observed_at_ms > now_ms || record.observed_at_ms < grant.window_start_ms {
                continue;
            }
            let item = verdict_item(entry)?;
            if newest_verdict.get(&record.node_id).is_none_or(|(at, seq, _)| order > (*at, *seq)) {
                newest_verdict.insert(record.node_id.clone(), (order.0, order.1, item));
            }
            continue;
        }
        if kind != Some("derived")
            || record.observed_at_ms < grant.window_start_ms
            || record.observed_at_ms >= grant.window_end_ms
        {
            continue;
        }
        match component {
            Some("process") => {
                let item = process_item(entry, manager_watermark)?;
                let key = (record.node_id.clone(), record.scope_id.clone());
                if newest_process.get(&key).is_none_or(|(at, seq, _)| order > (*at, *seq)) {
                    newest_process.insert(key, (order.0, order.1, item));
                }
            }
            Some("host") => {
                let item = host_item(entry, manager_watermark)?;
                let key = (record.node_id.clone(), record.scope_id.clone());
                if newest_host.get(&key).is_none_or(|(at, seq, _)| order > (*at, *seq)) {
                    newest_host.insert(key, (order.0, order.1, item));
                }
            }
            Some("consensus") if record.source_id == "native_core" => {
                let item = native_item(entry, manager_watermark)?;
                if newest_native.get(&record.node_id).is_none_or(|(at, seq, _)| order > (*at, *seq))
                {
                    newest_native.insert(record.node_id.clone(), (order.0, order.1, item));
                }
            }
            _ => {}
        }
    }
    let mut package = Package {
        schema_version: PACKAGE_SCHEMA_VERSION,
        source_profile: PROFILE_V3.into(),
        status: "partial".into(),
        run_id: grant.run_id.clone(),
        network_id: grant.network_id.clone(),
        query_watermark: U64(grant.watermark),
        manager_watermark: U64(manager_watermark),
        process: Vec::new(),
        missing_process: Vec::new(),
        host: Vec::new(),
        missing_host: Vec::new(),
        native: Vec::new(),
        missing_native: Vec::new(),
        health: Vec::new(),
        missing_health: Vec::new(),
        truncated: Vec::new(),
    };
    for node_id in &grant.nodes {
        for scope_id in &grant.scopes {
            match newest_process.remove(&(node_id.clone(), scope_id.clone())) {
                Some((_, _, item)) => package.process.push(item),
                None => package
                    .missing_process
                    .push(NodeScope { node_id: node_id.clone(), scope_id: scope_id.clone() }),
            }
            match newest_host.remove(&(node_id.clone(), scope_id.clone())) {
                Some((_, _, item)) => package.host.push(item),
                None => package
                    .missing_host
                    .push(NodeScope { node_id: node_id.clone(), scope_id: scope_id.clone() }),
            }
        }
        match newest_native.remove(node_id) {
            Some((_, _, item)) => package.native.push(item),
            None => package
                .missing_native
                .push(NodeScope { node_id: node_id.clone(), scope_id: "node".into() }),
        }
        match newest_verdict.remove(node_id) {
            Some((_, _, item)) => package.health.push(item),
            None => package
                .missing_health
                .push(NodeScope { node_id: node_id.clone(), scope_id: "node".into() }),
        }
    }
    let bytes = loop {
        let bytes = serde_json::to_vec(&package).map_err(|error| error.to_string())?;
        if bytes.len() <= PACKAGE_MAX_BYTES {
            break bytes;
        }
        if !truncate_one(&mut package) {
            return Err(format!(
                "fixed package exceeds 16 KiB even after truncation ({} verdict rows)",
                package.health.len()
            ));
        }
    };
    let sha256 = ledger.save_package(run_id, &bytes, boot_millis()?)?;
    Ok(FrozenPackage { sha256, bytes })
}

/// Which components were dropped for budget, for reporting to the operator.
pub fn truncated_components(body: &[u8]) -> Result<Vec<(String, String)>, String> {
    let package = parse_package(body)?;
    Ok(package.truncated.into_iter().map(|cut| (cut.node_id, cut.component)).collect())
}

#[cfg(test)]
mod host_tests {
    use super::*;

    #[test]
    fn package_readers_share_the_format_discriminator() {
        let mut grant = Grant::new(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            "reader".into(),
            "a".repeat(64),
            &[7; 32],
            BTreeSet::from(["v1".into()]),
            BTreeSet::from(["node".into()]),
            1000,
            2000,
            100,
            17,
        )
        .unwrap();
        grant.manager_watermark = Some(3);
        let cases = [
            (
                include_bytes!("../tests/fixtures/broker-package-v2.json").to_vec(),
                BROKER_PACKAGE_SUPERSEDED,
            ),
            (
                br#"{"schema_version":1,"source_profile":"development_process_only"}"#.to_vec(),
                BROKER_PACKAGE_SUPERSEDED,
            ),
            (
                br#"{"schema_version":3,"source_profile":"development_native_process_host_v3"}"#
                    .to_vec(),
                "invalid broker package",
            ),
            (
                br#"{"schema_version":4,"source_profile":"unknown"}"#.to_vec(),
                "unsupported broker package version",
            ),
            (
                br#"{"schema_version":3,"source_profile":"development_native_process_v2"}"#
                    .to_vec(),
                "broker package profile mismatch",
            ),
            (b"not JSON".to_vec(), "invalid broker package"),
            (vec![b'x'; PACKAGE_MAX_BYTES + 1], "broker package exceeds 16 KiB"),
        ];
        for (body, expected) in cases {
            assert_eq!(validate_package_binding(&body, &grant).unwrap_err(), expected);
            assert_eq!(package_evidence_ids(&body).unwrap_err(), expected);
            assert_eq!(truncated_components(&body).unwrap_err(), expected);
        }
    }

    #[test]
    fn host_truncation_preserves_the_complete_source_partition() {
        let mut grant = Grant::new(
            "00000000-0000-4000-8000-000000000001".into(),
            "reader".into(),
            "a".repeat(64),
            &[7; 32],
            BTreeSet::from(["v1".into()]),
            BTreeSet::from(["node".into()]),
            0,
            60000,
            0,
            1,
        )
        .unwrap();
        grant.manager_watermark = Some(1);
        let node = NodeScope { node_id: "v1".into(), scope_id: "node".into() };
        let host = HostItem {
            node_id: "v1".into(),
            scope_id: "node".into(),
            evidence_id: "b".repeat(64),
            parent_evidence_id: "c".repeat(64),
            query_sequence: U64(1),
            manager_sequence: U64(1),
            observed_at_ms: "1000".into(),
            process_epoch: "epoch".into(),
            value: CgroupPayload {
                kind: "host_cgroup".into(),
                memory_current_bytes: U64(1),
                memory_max_bytes: U64(2),
                cpu_usage_usec: U64(3),
                cpu_quota_usec: U64(4),
                cpu_period_usec: U64(5),
                oom_events: U64(0),
            },
        };
        let mut package = Package {
            schema_version: PACKAGE_SCHEMA_VERSION,
            source_profile: PROFILE_V3.into(),
            status: "partial".into(),
            run_id: grant.run_id.clone(),
            network_id: grant.network_id.clone(),
            query_watermark: U64(1),
            manager_watermark: U64(1),
            process: vec![],
            missing_process: vec![node.clone()],
            host: vec![host],
            missing_host: vec![],
            native: vec![],
            missing_native: vec![node.clone()],
            health: vec![],
            missing_health: vec![node],
            truncated: vec![],
        };
        let bytes = serde_json::to_vec(&package).unwrap();
        validate_package_binding(&bytes, &grant).unwrap();
        let restored = parse_package(&bytes).unwrap();
        assert_eq!(restored.schema_version, 3);
        assert_eq!(restored.source_profile, "development_native_process_host_v3");
        assert_eq!(restored.host.len(), 1);
        assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
        assert_eq!(package_evidence_ids(&bytes).unwrap(), BTreeSet::from(["b".repeat(64)]));
        assert!(truncated_components(&bytes).unwrap().is_empty());
        assert!(truncate_one(&mut package));
        assert!(package.host.is_empty());
        assert_eq!(package.truncated[0].component, "host");
        let bytes = serde_json::to_vec(&package).unwrap();
        validate_package_binding(&bytes, &grant).unwrap();
        assert_eq!(truncated_components(&bytes).unwrap(), vec![("v1".into(), "host".into())]);
        package.truncated.clear();
        assert_eq!(
            validate_current(&serde_json::to_vec(&package).unwrap(), &grant).unwrap_err(),
            "broker package source partition incomplete"
        );
    }
}
