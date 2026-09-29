use crate::{
    evidence::{EvidenceStore, StoredEvidence},
    query::{utc_ms, Grant, TOOLS},
    source::Coverage as SourceCoverage,
    wire::U64,
};
use chrono::{SecondsFormat, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityDto {
    pub instrumentation_complete: bool,
    pub producer_dropped: U64,
    pub relay_dropped: U64,
    pub parse_errors: U64,
    pub shed_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PayloadDto {
    Process {
        pid: u32,
        rss_bytes: Option<U64>,
        anon_bytes: Option<U64>,
        file_bytes: Option<U64>,
        swap_bytes: Option<U64>,
        cpu_user_ticks: Option<U64>,
        cpu_system_ticks: Option<U64>,
    },
    Native {
        generation: U64,
        openmetrics_hash: String,
        bytes: u32,
    },
    NativeCore {
        generation: U64,
        network_id: String,
        openmetrics_hash: String,
        bytes: u32,
        pq_sign: Option<PqSnapshotDto>,
        pq_verify: Option<PqSnapshotDto>,
    },
    Unavailable {
        reason: String,
    },
    Scalar {
        metric_id: String,
        value: Option<f64>,
        unit: String,
    },
    #[serde(rename = "diagnostic_fixture")]
    DiagnosticFixture {
        record_type: u16,
        payload: String,
    },
    Block {
        network_id: String,
        scope_id: String,
        workchain: i32,
        shard: U64,
        seqno: u32,
        root_hash: String,
        file_hash: String,
        point: String,
    },
    Consensus {
        network_id: String,
        scope_id: String,
        session_id: String,
        slot: u32,
        candidate_id: Option<String>,
        phase: String,
    },
    StorageAck {
        operation: String,
        logical_reference: String,
        contract_id: String,
        source_epoch: String,
        completion_sequence: U64,
        durability: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqSnapshotDto {
    pub complete: bool,
    pub failed: U64,
    pub succeeded: U64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDto {
    pub evidence_id: String,
    pub kind: String,
    pub node_id: String,
    pub source_id: String,
    pub source_version: String,
    pub source_record_id: String,
    pub process_epoch: String,
    pub observed_at: Option<String>,
    pub received_at: String,
    pub clock_quality: String,
    pub scope_id: String,
    pub payload: PayloadDto,
    pub content_hash: String,
    pub quality: QualityDto,
    pub redacted: bool,
    pub parent_evidence_ids: Vec<String>,
    pub derivation_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingDto {
    pub source_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDto {
    pub status: String,
    pub missing_fields: Vec<String>,
    pub gaps: Vec<String>,
    pub sampling_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaginationDto {
    pub next_cursor: Option<String>,
    pub truncated: bool,
    pub scan_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorDto {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub retry_after_seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetDto {
    pub remaining_calls: u32,
    pub remaining_bytes: u32,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDto {
    pub supported: bool,
    pub enabled: bool,
    pub contract_valid: bool,
    pub performance_gate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedCapabilityDto {
    pub name: String,
    pub value: CapabilityDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCapabilitiesDto {
    pub node_id: String,
    pub capabilities: Vec<NamedCapabilityDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowDto {
    pub start: String,
    pub end: String,
    pub change_start: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateDto {
    pub name: String,
    pub status: String,
    pub evidence_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesData {
    pub contract_version: String,
    pub catalog_digest: String,
    pub inventory_revision: String,
    pub watermark: U64,
    pub network: String,
    pub node_capabilities: Vec<NodeCapabilitiesDto>,
    pub allowed_scopes: Vec<String>,
    pub metric_ids: Vec<String>,
    pub windows: WindowDto,
    pub query_mode: String,
    pub gates: Vec<GateDto>,
    pub remaining_budget: BudgetDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDto {
    pub kind: String,
    pub sources: Vec<String>,
    pub value: Option<PayloadDto>,
    pub quality: QualityDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotData {
    pub node_id: String,
    pub as_of: String,
    pub process_epoch: String,
    pub role: String,
    pub components: Vec<ComponentDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelDto {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointDto {
    pub at: String,
    pub value: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricSeriesDto {
    pub metric_id: String,
    pub node_id: String,
    pub scope_id: String,
    pub labels: Vec<LabelDto>,
    pub unit: String,
    pub semantic_type: String,
    pub population: String,
    pub clock: String,
    pub points: Option<Vec<PointDto>>,
    pub summary: Option<Value>,
    pub samples_count: U64,
    pub expected_samples: Option<U64>,
    pub coverage: CoverageDto,
    pub reset_count: U64,
    pub source_evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricData {
    pub series: Vec<MetricSeriesDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventDto {
    pub event_id: String,
    pub evidence_id: String,
    pub source_id: String,
    pub source_record_id: String,
    pub process_epoch: String,
    pub observed_at: Option<String>,
    pub scope_id: String,
    pub kind: String,
    pub stage: Option<String>,
    pub reason: Option<String>,
    pub correlation_id: Option<String>,
    pub excerpt: String,
    pub content_hash: String,
    pub quality: QualityDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventData {
    pub events: Vec<EventDto>,
    pub gaps: Vec<MissingDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeFieldDto {
    pub field: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeDto {
    pub change_id: String,
    pub evidence_id: String,
    pub node_id: String,
    pub kind: String,
    pub started: String,
    pub completed: Option<String>,
    pub actor_alias: String,
    pub before: Vec<ChangeFieldDto>,
    pub after: Vec<ChangeFieldDto>,
    pub reason: String,
    pub trusted_origin: bool,
    pub quality: QualityDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeData {
    pub changes: Vec<ChangeDto>,
    pub gaps: Vec<MissingDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionsDto {
    pub local_action: String,
    pub network_observation: String,
    pub certificate_membership: String,
    pub proof_verification: String,
    pub local_persistence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurationDto {
    pub stage: String,
    pub duration_ns: Option<U64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockNodeDto {
    pub node_id: String,
    pub identity: Option<PayloadDto>,
    pub stage_events: Vec<EventDto>,
    pub observed_durations: Vec<DurationDto>,
    pub ancestor_evidence: Vec<EvidenceDto>,
    pub dimensions: DimensionsDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockData {
    pub selector: String,
    pub per_node: Vec<BlockNodeDto>,
    pub comparison_status: String,
    pub missing_evidence: Vec<MissingDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolData {
    Capabilities(Box<CapabilitiesData>),
    Snapshot(SnapshotData),
    Metric(MetricData),
    Events(EventData),
    Changes(ChangeData),
    Block(BlockData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolEnvelope {
    pub schema_version: u32,
    pub request_id: String,
    pub run_id: String,
    pub network_id: String,
    pub generated_at: String,
    pub status: String,
    pub data: Option<ToolData>,
    pub evidence: Vec<EvidenceDto>,
    pub missing_evidence: Vec<MissingDto>,
    pub coverage: CoverageDto,
    pub pagination: PaginationDto,
    pub error: Option<ErrorDto>,
    pub budget: BudgetDto,
}

fn time(ms: i64) -> Result<String, &'static str> {
    Utc.timestamp_millis_opt(ms)
        .single()
        .map(|v| v.to_rfc3339_opts(SecondsFormat::Millis, true))
        .ok_or("SCHEMA_MISMATCH")
}

fn quality(record: &StoredEvidence) -> Result<QualityDto, &'static str> {
    let quality: QualityDto = serde_json::from_value(
        record.record.payload.get("contract_quality").ok_or("SCHEMA_MISMATCH")?.clone(),
    )
    .map_err(|_| "SCHEMA_MISMATCH")?;
    if quality.shed_reason.as_ref().is_some_and(|reason| reason.len() > 96) {
        return Err("SCHEMA_MISMATCH");
    }
    Ok(quality)
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max
}

fn optional_bounded(value: Option<&str>, max: usize) -> bool {
    value.is_none_or(|item| item.len() <= max)
}

fn merge_unique_bounded(
    target: &mut Vec<String>,
    incoming: Vec<String>,
    max: usize,
) -> Result<(), &'static str> {
    for value in incoming {
        if !target.contains(&value) {
            target.push(value);
        }
    }
    if target.len() > max {
        return Err("SCHEMA_MISMATCH");
    }
    Ok(())
}

fn coverage(record: &StoredEvidence) -> Result<CoverageDto, &'static str> {
    let mut coverage: CoverageDto = serde_json::from_value(
        record.record.payload.get("contract_coverage").ok_or("SCHEMA_MISMATCH")?.clone(),
    )
    .map_err(|_| "SCHEMA_MISMATCH")?;
    let expected = match record.record.quality.coverage {
        SourceCoverage::Complete => "complete",
        SourceCoverage::Partial => "partial",
        SourceCoverage::Unknown => "unknown",
    };
    if coverage.status != expected {
        return Err("SCHEMA_MISMATCH");
    }
    if !record.record.quality.clock_valid && coverage.status == "complete" {
        coverage.status = "partial".into();
        coverage.missing_fields.push("valid_clock".into());
    }
    if coverage.missing_fields.len() > 64
        || coverage.missing_fields.iter().any(|item| item.len() > 96)
        || coverage.gaps.len() > 32
        || coverage.gaps.iter().any(|item| item.len() > 256)
        || coverage.sampling_policy.len() > 128
    {
        return Err("SCHEMA_MISMATCH");
    }
    Ok(coverage)
}

fn payload(record: &StoredEvidence) -> Result<PayloadDto, &'static str> {
    let value =
        record.record.payload.get("contract_payload").unwrap_or(&record.record.payload).clone();
    let payload: PayloadDto = serde_json::from_value(value).map_err(|_| "SCHEMA_MISMATCH")?;
    let valid = match &payload {
        PayloadDto::Process { pid, .. } => *pid > 0,
        PayloadDto::Native { openmetrics_hash, bytes, .. } => {
            crate::wire::hash(openmetrics_hash) && *bytes <= 2_097_152
        }
        PayloadDto::NativeCore { network_id, openmetrics_hash, bytes, .. } => {
            crate::wire::hash(network_id)
                && crate::wire::hash(openmetrics_hash)
                && *bytes <= 2_097_152
        }
        PayloadDto::Unavailable { reason } => reason.len() <= 256,
        PayloadDto::Scalar { metric_id, value, unit } => {
            !metric_id.is_empty()
                && metric_id.len() <= 96
                && unit.len() <= 32
                && value.is_none_or(f64::is_finite)
        }
        PayloadDto::DiagnosticFixture { record_type, payload } => {
            *record_type == 1
                && payload.len() == 4
                && payload.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        PayloadDto::Block { network_id, scope_id, root_hash, file_hash, point, .. } => {
            crate::wire::hash(network_id)
                && crate::wire::alias(scope_id)
                && crate::wire::hash(root_hash)
                && crate::wire::hash(file_hash)
                && point.len() <= 64
        }
        PayloadDto::Consensus { network_id, scope_id, session_id, candidate_id, phase, .. } => {
            crate::wire::hash(network_id)
                && crate::wire::alias(scope_id)
                && crate::wire::hash(session_id)
                && candidate_id.as_ref().is_none_or(|v| v.len() <= 160)
                && phase.len() <= 64
        }
        PayloadDto::StorageAck {
            operation,
            logical_reference,
            contract_id,
            source_epoch,
            durability,
            ..
        } => {
            operation.len() <= 64
                && logical_reference.len() <= 160
                && crate::wire::alias(contract_id)
                && source_epoch.len() <= 128
                && ["commit_acknowledged", "restart_verified_in_test", "unknown"]
                    .contains(&durability.as_str())
        }
    };
    if !valid {
        return Err("SCHEMA_MISMATCH");
    }
    Ok(payload)
}

fn evidence(record: &StoredEvidence) -> Result<EvidenceDto, &'static str> {
    if !crate::wire::alias(&record.record.node_id)
        || !crate::wire::alias(&record.record.source_id)
        || !crate::wire::alias(&record.record.scope_id)
        || !bounded(&record.evidence_id, 128)
        || !bounded(&record.record.source_record_id, 256)
        || !bounded(&record.record.process_epoch, 128)
        || !record.record.redacted
    {
        return Err("SCHEMA_MISMATCH");
    }
    let source_version = record
        .record
        .payload
        .get("source_version")
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty() && version.len() <= 96)
        .ok_or("SCHEMA_MISMATCH")?;
    let kind = record
        .record
        .payload
        .get("evidence_kind")
        .and_then(Value::as_str)
        .filter(|kind| ["observation", "derived", "event", "change"].contains(kind))
        .ok_or("SCHEMA_MISMATCH")?;
    // Derived evidence requires actual parent IDs and a derivation version. The
    // current immutable store has no lineage columns, so fail closed instead of
    // emitting an invented empty lineage.
    if kind == "derived" {
        return Err("CAPABILITY_UNSUPPORTED");
    }
    let payload_value =
        record.record.payload.get("contract_payload").unwrap_or(&record.record.payload);
    let content_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(payload_value).map_err(|_| "SCHEMA_MISMATCH")?)
    );
    Ok(EvidenceDto {
        evidence_id: record.evidence_id.clone(),
        kind: kind.into(),
        node_id: record.record.node_id.clone(),
        source_id: record.record.source_id.clone(),
        source_version: source_version.into(),
        source_record_id: record.record.source_record_id.clone(),
        process_epoch: record.record.process_epoch.clone(),
        observed_at: Some(time(record.record.observed_at_ms)?),
        received_at: time(record.record.received_at_ms)?,
        clock_quality: if record.record.quality.clock_valid { "valid" } else { "invalid" }.into(),
        scope_id: record.record.scope_id.clone(),
        payload: payload(record)?,
        content_hash,
        quality: quality(record)?,
        redacted: record.record.redacted,
        parent_evidence_ids: vec![],
        derivation_version: None,
    })
}

fn event(record: &StoredEvidence) -> Result<EventDto, &'static str> {
    let meta = record.record.payload.get("event").ok_or("SCHEMA_MISMATCH")?;
    let kind = meta.get("kind").and_then(Value::as_str).ok_or("SCHEMA_MISMATCH")?;
    let stage = meta.get("stage").and_then(Value::as_str);
    let reason = meta.get("reason").and_then(Value::as_str);
    let correlation_id = meta.get("correlation_id").and_then(Value::as_str);
    let excerpt = meta.get("excerpt").and_then(Value::as_str).unwrap_or("");
    if !bounded(kind, 64)
        || !optional_bounded(stage, 64)
        || !optional_bounded(reason, 256)
        || !optional_bounded(correlation_id, 160)
        || excerpt.len() > 512
    {
        return Err("SCHEMA_MISMATCH");
    }
    Ok(EventDto {
        event_id: record.record.source_record_id.clone(),
        evidence_id: record.evidence_id.clone(),
        source_id: record.record.source_id.clone(),
        source_record_id: record.record.source_record_id.clone(),
        process_epoch: record.record.process_epoch.clone(),
        observed_at: Some(time(record.record.observed_at_ms)?),
        scope_id: record.record.scope_id.clone(),
        kind: kind.into(),
        stage: stage.map(str::to_owned),
        reason: reason.map(str::to_owned),
        correlation_id: correlation_id.map(str::to_owned),
        excerpt: excerpt.into(),
        content_hash: evidence(record)?.content_hash,
        quality: quality(record)?,
    })
}

fn records(store: &EvidenceStore, ids: &[String]) -> Result<Vec<StoredEvidence>, &'static str> {
    ids.iter()
        .map(|id| {
            store
                .entries()
                .find(|entry| &entry.evidence_id == id)
                .cloned()
                .ok_or("EVIDENCE_EXPIRED")
        })
        .collect()
}

fn contract_digest() -> String {
    format!("{:x}", Sha256::digest(b"tos-node-health-r4-c00-runtime-v1"))
}

fn budget(grant: &Grant, now: u64, generated_ms: i64) -> Result<BudgetDto, &'static str> {
    let remaining_ms = grant.expires_monotonic_ms().saturating_sub(now);
    let remaining_ms = i64::try_from(remaining_ms).map_err(|_| "SCHEMA_MISMATCH")?;
    Ok(BudgetDto {
        remaining_calls: grant.remaining_calls(),
        remaining_bytes: grant.remaining_bytes(),
        expires_at: time(generated_ms.checked_add(remaining_ms).ok_or("SCHEMA_MISMATCH")?)?,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn success(
    tool: &str,
    input: &Value,
    grant: &Grant,
    now: u64,
    generated_ms: i64,
    ids: &[String],
    store: &EvidenceStore,
    metrics: &std::collections::BTreeSet<String>,
    pagination: PaginationDto,
) -> Result<Value, &'static str> {
    let selected = records(store, ids)?;
    let dto_evidence: Vec<_> = selected.iter().map(evidence).collect::<Result<_, _>>()?;
    let response_budget = budget(grant, now, generated_ms)?;
    let data = match tool {
        "tos_get_capabilities" => ToolData::Capabilities(Box::new(CapabilitiesData {
            contract_version: "R4-v1".into(),
            catalog_digest: contract_digest(),
            inventory_revision: "runtime-v1".into(),
            watermark: U64(grant.watermark),
            network: grant.network_id.clone(),
            node_capabilities: grant
                .nodes
                .iter()
                .map(|node_id| NodeCapabilitiesDto {
                    node_id: node_id.clone(),
                    capabilities: vec![NamedCapabilityDto {
                        name: "cache_query".into(),
                        value: CapabilityDto {
                            supported: true,
                            enabled: true,
                            contract_valid: true,
                            performance_gate: "not_run".into(),
                        },
                    }],
                })
                .collect(),
            allowed_scopes: grant.scopes.iter().cloned().collect(),
            metric_ids: metrics.iter().cloned().collect(),
            windows: WindowDto {
                start: time(grant.window_start_ms)?,
                end: time(grant.window_end_ms)?,
                change_start: time(grant.change_start_ms)?,
            },
            query_mode: "cache_only".into(),
            gates: vec![GateDto {
                name: "production_acceptance".into(),
                status: "not_run".into(),
                evidence_digest: None,
            }],
            remaining_budget: response_budget.clone(),
        })),
        "tos_get_node_snapshot" => {
            let node = input.get("node_id").and_then(Value::as_str).ok_or("SCHEMA_MISMATCH")?;
            let as_of = input.get("as_of").and_then(Value::as_str).ok_or("SCHEMA_MISMATCH")?;
            utc_ms(as_of)?;
            let requested =
                input.get("components").and_then(Value::as_array).ok_or("SCHEMA_MISMATCH")?;
            let mut components = vec![];
            for kind in requested.iter().filter_map(Value::as_str) {
                let record = selected
                    .iter()
                    .find(|r| {
                        r.record.payload.get("component").and_then(Value::as_str) == Some(kind)
                    })
                    .ok_or("SCHEMA_MISMATCH")?;
                components.push(ComponentDto {
                    kind: kind.into(),
                    sources: vec![record.record.source_id.clone()],
                    value: Some(payload(record)?),
                    quality: quality(record)?,
                });
            }
            ToolData::Snapshot(SnapshotData {
                node_id: node.into(),
                as_of: as_of.into(),
                process_epoch: selected
                    .first()
                    .map(|r| r.record.process_epoch.clone())
                    .ok_or("SCHEMA_MISMATCH")?,
                role: "unknown".into(),
                components,
            })
        }
        "tos_get_metric_window" => {
            let mut groups: BTreeMap<(String, String, String), Vec<&StoredEvidence>> =
                BTreeMap::new();
            for record in &selected {
                let p = payload(record)?;
                let PayloadDto::Scalar { metric_id, .. } = &p else {
                    return Err("SCHEMA_MISMATCH");
                };
                groups
                    .entry((
                        record.record.node_id.clone(),
                        record.record.scope_id.clone(),
                        metric_id.clone(),
                    ))
                    .or_default()
                    .push(record);
            }
            let mut series = vec![];
            for ((node_id, scope_id, metric_id), mut group) in groups {
                group.sort_by_key(|r| r.record.observed_at_ms);
                let mut points = vec![];
                let mut source_evidence_ids = vec![];
                let mut unit: Option<String> = None;
                let mut process_epoch: Option<&str> = None;
                let mut series_coverage: Option<CoverageDto> = None;
                let mut clock = "valid";
                let metric_meta = group
                    .first()
                    .and_then(|record| record.record.payload.get("metric"))
                    .cloned()
                    .ok_or("SCHEMA_MISMATCH")?;
                for record in &group {
                    let PayloadDto::Scalar { value, unit: item_unit, .. } = payload(record)? else {
                        return Err("SCHEMA_MISMATCH");
                    };
                    if unit.as_ref().is_some_and(|known| known != &item_unit)
                        || process_epoch.is_some_and(|known| known != record.record.process_epoch)
                    {
                        return Err("SCHEMA_MISMATCH");
                    }
                    unit = Some(item_unit);
                    process_epoch = Some(&record.record.process_epoch);
                    let item_coverage = coverage(record)?;
                    if record.record.payload.get("metric") != Some(&metric_meta)
                        || series_coverage.as_ref().is_some_and(|known| {
                            known.sampling_policy != item_coverage.sampling_policy
                        })
                    {
                        return Err("SCHEMA_MISMATCH");
                    }
                    if let Some(known) = &mut series_coverage {
                        known.status = if known.status == "unknown"
                            || item_coverage.status == "unknown"
                        {
                            "unknown".into()
                        } else if known.status == "partial" || item_coverage.status == "partial" {
                            "partial".into()
                        } else {
                            "complete".into()
                        };
                        merge_unique_bounded(
                            &mut known.missing_fields,
                            item_coverage.missing_fields,
                            64,
                        )?;
                        merge_unique_bounded(&mut known.gaps, item_coverage.gaps, 32)?;
                    } else {
                        series_coverage = Some(item_coverage);
                    }
                    if !record.record.quality.clock_valid {
                        clock = "invalid";
                    }
                    points.push(PointDto { at: time(record.record.observed_at_ms)?, value });
                    source_evidence_ids.push(record.evidence_id.clone());
                }
                let semantic_type = metric_meta
                    .get("semantic_type")
                    .and_then(Value::as_str)
                    .filter(|v| ["counter", "gauge", "histogram", "raw"].contains(v))
                    .ok_or("SCHEMA_MISMATCH")?;
                let population = metric_meta
                    .get("population")
                    .and_then(Value::as_str)
                    .filter(|v| v.len() <= 256)
                    .ok_or("SCHEMA_MISMATCH")?;
                let reset_count: U64 = serde_json::from_value(
                    metric_meta.get("reset_count").ok_or("SCHEMA_MISMATCH")?.clone(),
                )
                .map_err(|_| "SCHEMA_MISMATCH")?;
                let labels: Vec<LabelDto> = serde_json::from_value(
                    metric_meta.get("labels").ok_or("SCHEMA_MISMATCH")?.clone(),
                )
                .map_err(|_| "SCHEMA_MISMATCH")?;
                if labels.len() > 8
                    || labels
                        .iter()
                        .any(|label| !crate::wire::alias(&label.name) || label.value.len() > 96)
                {
                    return Err("SCHEMA_MISMATCH");
                }
                series.push(MetricSeriesDto {
                    metric_id,
                    node_id,
                    scope_id,
                    labels,
                    unit: unit.ok_or("SCHEMA_MISMATCH")?,
                    semantic_type: semantic_type.into(),
                    population: population.into(),
                    clock: clock.into(),
                    samples_count: U64(points.len() as u64),
                    points: Some(points),
                    summary: None,
                    expected_samples: None,
                    coverage: series_coverage.ok_or("SCHEMA_MISMATCH")?,
                    reset_count,
                    source_evidence_ids,
                });
            }
            ToolData::Metric(MetricData { series })
        }
        "tos_get_event_window" => ToolData::Events(EventData {
            events: selected.iter().map(event).collect::<Result<_, _>>()?,
            gaps: vec![],
        }),
        "tos_get_change_history" => {
            let mut changes = vec![];
            for record in &selected {
                let meta = record.record.payload.get("change").ok_or("SCHEMA_MISMATCH")?;
                let fields = |name: &str| -> Result<Vec<ChangeFieldDto>, &'static str> {
                    let values: Vec<_> = meta
                        .get(name)
                        .and_then(Value::as_object)
                        .ok_or("SCHEMA_MISMATCH")?
                        .iter()
                        .map(|(field, value)| {
                            if field.len() > 96
                                || value.as_str().is_some_and(|item| item.len() > 512)
                                || !(value.is_null() || value.is_string())
                            {
                                return Err("SCHEMA_MISMATCH");
                            }
                            Ok(ChangeFieldDto {
                                field: field.clone(),
                                value: value.as_str().map(str::to_owned),
                            })
                        })
                        .collect::<Result<_, _>>()?;
                    if values.len() > 32 {
                        return Err("SCHEMA_MISMATCH");
                    }
                    Ok(values)
                };
                let kind = meta.get("kind").and_then(Value::as_str).ok_or("SCHEMA_MISMATCH")?;
                let actor_alias =
                    meta.get("actor_alias").and_then(Value::as_str).ok_or("SCHEMA_MISMATCH")?;
                let completed = meta.get("completed").and_then(Value::as_str);
                let reason = meta.get("reason").and_then(Value::as_str).unwrap_or("");
                if !["deploy", "restart", "config", "maintenance", "load_test", "resource_limit"]
                    .contains(&kind)
                    || !crate::wire::alias(actor_alias)
                    || reason.len() > 512
                {
                    return Err("SCHEMA_MISMATCH");
                }
                if let Some(completed) = completed {
                    utc_ms(completed)?;
                }
                changes.push(ChangeDto {
                    change_id: record.record.source_record_id.clone(),
                    evidence_id: record.evidence_id.clone(),
                    node_id: record.record.node_id.clone(),
                    kind: kind.into(),
                    started: time(record.record.observed_at_ms)?,
                    completed: completed.map(str::to_owned),
                    actor_alias: actor_alias.into(),
                    before: fields("before")?,
                    after: fields("after")?,
                    reason: reason.into(),
                    trusted_origin: meta
                        .get("trusted_origin")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    quality: quality(record)?,
                });
            }
            ToolData::Changes(ChangeData { changes, gaps: vec![] })
        }
        "tos_get_block_evidence" => {
            let selector =
                input.get("reference_id").and_then(Value::as_str).ok_or("SCHEMA_MISMATCH")?;
            let mut per_node = vec![];
            for record in &selected {
                let identity = payload(record)?;
                if !matches!(
                    identity,
                    PayloadDto::Block { .. }
                        | PayloadDto::Consensus { .. }
                        | PayloadDto::StorageAck { .. }
                ) {
                    return Err("SCHEMA_MISMATCH");
                }
                per_node.push(BlockNodeDto {
                    node_id: record.record.node_id.clone(),
                    identity: Some(identity),
                    stage_events: vec![],
                    observed_durations: vec![],
                    ancestor_evidence: vec![],
                    dimensions: DimensionsDto {
                        local_action: "unknown".into(),
                        network_observation: "unavailable".into(),
                        certificate_membership: "not_checked".into(),
                        proof_verification: "not_checked".into(),
                        local_persistence: "unknown".into(),
                    },
                });
            }
            ToolData::Block(BlockData {
                selector: selector.into(),
                per_node,
                comparison_status: "unavailable".into(),
                missing_evidence: vec![],
            })
        }
        _ => return Err("INVALID_ARGUMENT"),
    };
    let response_coverage = if selected.is_empty() {
        CoverageDto {
            status: "complete".into(),
            missing_fields: vec![],
            gaps: vec![],
            sampling_policy: "cache_only_fixed_watermark".into(),
        }
    } else {
        let mut items = selected.iter().map(coverage).collect::<Result<Vec<_>, _>>()?;
        let status = if items.iter().any(|item| item.status == "unknown") {
            "unknown"
        } else if items.iter().any(|item| item.status == "partial") {
            "partial"
        } else {
            "complete"
        };
        let sampling_policy =
            items.first().map(|item| item.sampling_policy.clone()).ok_or("SCHEMA_MISMATCH")?;
        if items.iter().any(|item| item.sampling_policy != sampling_policy) {
            return Err("SCHEMA_MISMATCH");
        }
        let mut missing_fields = vec![];
        let mut gaps = vec![];
        for item in &mut items {
            merge_unique_bounded(&mut missing_fields, item.missing_fields.drain(..).collect(), 64)?;
            merge_unique_bounded(&mut gaps, item.gaps.drain(..).collect(), 32)?;
        }
        CoverageDto { status: status.into(), missing_fields, gaps, sampling_policy }
    };
    let mut missing_evidence = vec![];
    for record in &selected {
        let item = coverage(record)?;
        if item.status != "complete" {
            let reason = format!(
                "coverage {}; {} missing fields, {} gaps; see response coverage",
                item.status,
                item.missing_fields.len(),
                item.gaps.len()
            );
            if !missing_evidence
                .iter()
                .any(|missing: &MissingDto| missing.source_id == record.record.source_id)
            {
                missing_evidence
                    .push(MissingDto { source_id: record.record.source_id.clone(), reason });
            }
        }
    }
    let (status, data, error) = match response_coverage.status.as_str() {
        "complete" => ("ok", Some(data), None),
        "partial" => ("partial", Some(data), None),
        "unknown" => (
            "unavailable",
            None,
            Some(ErrorDto {
                code: "SOURCE_UNAVAILABLE".into(),
                message: "required cached evidence has unknown coverage".into(),
                retryable: false,
                retry_after_seconds: None,
            }),
        ),
        _ => return Err("SCHEMA_MISMATCH"),
    };
    let envelope = ToolEnvelope {
        schema_version: 1,
        request_id: format!("{}:{}", grant.run_id, grant.calls()),
        run_id: grant.run_id.clone(),
        network_id: grant.network_id.clone(),
        generated_at: time(generated_ms)?,
        status: status.into(),
        data,
        evidence: dto_evidence,
        missing_evidence,
        coverage: response_coverage,
        pagination,
        error,
        budget: response_budget,
    };
    serde_json::to_value(envelope).map_err(|_| "SERIALIZATION_FAILED")
}

pub fn error(code: &str, grant: &Grant, now: u64, generated_ms: i64) -> Value {
    let response_budget = budget(grant, now, generated_ms).unwrap_or(BudgetDto {
        remaining_calls: 0,
        remaining_bytes: 0,
        expires_at: time(generated_ms).unwrap_or_else(|_| "1970-01-01T00:00:00.000Z".into()),
    });
    serde_json::to_value(ToolEnvelope {
        schema_version: 1,
        request_id: format!("{}:{}", grant.run_id, grant.calls()),
        run_id: grant.run_id.clone(),
        network_id: grant.network_id.clone(),
        generated_at: time(generated_ms).unwrap_or_else(|_| "1970-01-01T00:00:00.000Z".into()),
        status: "error".into(),
        data: None,
        evidence: vec![],
        missing_evidence: vec![],
        coverage: CoverageDto {
            status: "unknown".into(),
            missing_fields: vec![],
            gaps: vec![],
            sampling_policy: "cache_only_fixed_watermark".into(),
        },
        pagination: PaginationDto { next_cursor: None, truncated: false, scan_complete: false },
        error: Some(ErrorDto {
            code: code.into(),
            message: code.into(),
            retryable: false,
            retry_after_seconds: None,
        }),
        budget: response_budget,
    })
    .unwrap_or(Value::Null)
}

pub fn tool_names() -> [&'static str; 6] {
    TOOLS
}
