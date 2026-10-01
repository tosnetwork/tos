//! Read-only, bounded M observation projection for the query process.
//! Only the exact archived process envelope is implemented. Unsupported
//! source classes are not silently recast as a complete query component.
use crate::durable::{DurableEvidence, EvidenceRow};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, os::unix::fs::MetadataExt, path::Path};
use tos_health_core::{
    consensus_v2::{Action, Consensus, IncompleteReason, Lifecycle},
    edge_snapshot::{ProcessEnvelope, ProcessPayload},
    evidence::Evidence,
    native::{canonical_hash, parse_native, BlockAnchor, ChainAnchors, NativeRecord, PqSnapshot},
    query::utc_ms,
    query_output::{
        ActionDto, BlockAnchorDto, ContextDto, CountDto, PayloadDto, PqSnapshotDto, SessionsDto,
        StorageCapabilityDto,
    },
    source::{Availability, Coverage},
    wire::U64,
};

const MAX_ROWS: usize = 4096;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const PAGE_ROWS: usize = 256;
const VERSION: &str = "m-observation-projection-v1";
pub type ProjectionScan = (u64, Vec<(EvidenceRow, Evidence)>, std::collections::BTreeSet<String>);
type RetainedSqlRow = (String, String, String, String, String, String, String, String, i64);

#[derive(Debug)]
pub struct ProjectionPage {
    pub cursor: crate::query_ledger::ManagerCursor,
    /// Same-snapshot global boundary that is not a projected process parent.
    pub boundary_witness: Option<(u64, String)>,
    pub records: Vec<(EvidenceRow, Evidence)>,
    pub quarantined_retained: BTreeSet<String>,
    /// Retained parents absent from M whose generation is covered by M's
    /// retention seal for their identity: expired by bounded age retention,
    /// not tampered. The caller evicts their derived rows instead of locking.
    pub expired_retained: BTreeSet<String>,
    pub caught_up: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ProjectionHead {
    pub global_m_seq: u64,
    pub device: u64,
    pub inode: u64,
}

fn failure(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Low-cost read-only broker witness: M's global observation high-water, not
/// the count of process rows. It never scans or projects source payloads.
pub fn read_projection_head(path: &Path, network: &str) -> Result<ProjectionHead, String> {
    if !tos_health_core::wire::hash(network) {
        return Err("invalid M network".into());
    }
    let meta = std::fs::symlink_metadata(path).map_err(failure)?;
    if !meta.file_type().is_file() {
        return Err("M evidence path is not a regular file".into());
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(failure)?;
    conn.busy_timeout(std::time::Duration::from_millis(100)).map_err(failure)?;
    conn.execute_batch("PRAGMA query_only=ON; BEGIN TRANSACTION").map_err(failure)?;
    let bound: String = conn
        .query_row("SELECT network FROM database_identity WHERE singleton=1", [], |row| row.get(0))
        .map_err(failure)?;
    if bound != network {
        return Err("M evidence network mismatch".into());
    }
    let watermark: Option<i64> = conn
        .query_row("SELECT seq FROM sqlite_sequence WHERE name='observations'", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(failure)?;
    let end_meta = std::fs::symlink_metadata(path).map_err(failure)?;
    if end_meta.dev() != meta.dev() || end_meta.ino() != meta.ino() {
        return Err("M projection database replaced during read".into());
    }
    Ok(ProjectionHead {
        global_m_seq: u64::try_from(watermark.unwrap_or(0)).map_err(failure)?,
        device: meta.dev(),
        inode: meta.ino(),
    })
}

/// SQL eligibility shared by every M scan: archived edge process rows and
/// archived native consensus rows. Collector fact frames also use the
/// `native_core` source id but carry no `component`, so they are never read.
const ELIGIBLE_SOURCE: &str = "(o.source='process' OR (o.source='native_core' \
     AND json_extract(o.body,'$.record.payload.component')='consensus'))";

/// Project one archived M row into the query cache. Process and native
/// consensus rows are supported; any other row yields `Ok(None)`.
pub fn project_origin(row: &EvidenceRow) -> Result<Option<Evidence>, String> {
    if row.store_seq.0 == 0 || !tos_health_core::wire::hash(&row.evidence_id) {
        return Err("invalid M evidence identity".into());
    }
    let mut original = row.evidence.clone();
    original.record.received_at_ms = 0;
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&original).map_err(failure)?));
    if digest != row.evidence_id {
        return Err("M evidence hash mismatch".into());
    }
    let record = &row.evidence.record;
    match record.payload.get("component").and_then(serde_json::Value::as_str) {
        Some("process") if record.source_id == "process" => project_process(row),
        Some("consensus") if record.source_id == "native_core" => project_native(row),
        _ => Ok(None),
    }
}

fn count_rows(map: &std::collections::BTreeMap<String, U64>) -> Vec<CountDto> {
    map.iter().map(|(name, count)| CountDto { name: name.clone(), count: *count }).collect()
}

fn nonzero_rows(map: &std::collections::BTreeMap<String, U64>) -> Vec<CountDto> {
    map.iter()
        .filter(|(_, count)| count.0 > 0)
        .map(|(name, count)| CountDto { name: name.clone(), count: *count })
        .collect()
}

fn action_dto(action: &Action) -> ActionDto {
    let (name, complete, reasons, live) = match action {
        Action::Proposal { accounting_complete, incomplete_reasons, live, .. } => {
            ("proposal", accounting_complete, incomplete_reasons, live)
        }
        Action::NotarizeVote { accounting_complete, incomplete_reasons, live, .. } => {
            ("notarize_vote", accounting_complete, incomplete_reasons, live)
        }
        Action::FinalizeVote { accounting_complete, incomplete_reasons, live, .. } => {
            ("finalize_vote", accounting_complete, incomplete_reasons, live)
        }
        Action::SkipVote { accounting_complete, incomplete_reasons, live, .. } => {
            ("skip_vote", accounting_complete, incomplete_reasons, live)
        }
    };
    ActionDto {
        action: name.into(),
        accounting_complete: *complete,
        incomplete_reasons: reasons.iter().map(reason_name).collect(),
        phases: count_rows(&live.phases),
        outcomes: count_rows(&live.outcomes),
        failures: nonzero_rows(&live.failures),
        pending: live.pending,
        oldest_age_ns: live.oldest_age_ns,
    }
}

fn reason_name(reason: &IncompleteReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn consensus_dto(
    source_version: &str,
    generation: U64,
    network_id: &str,
    consensus: &Consensus,
    pq_sign: Option<&PqSnapshot>,
    pq_verify: Option<&PqSnapshot>,
) -> PayloadDto {
    let pq = |snapshot: Option<&PqSnapshot>| {
        snapshot.map(|pq| PqSnapshotDto {
            complete: pq.complete,
            failed: pq.failed,
            succeeded: pq.succeeded,
        })
    };
    PayloadDto::NativeConsensus {
        source_version: source_version.into(),
        generation,
        network_id: network_id.into(),
        instrumentation_complete: consensus.instrumentation_complete,
        incomplete_reasons: consensus.incomplete_reasons.iter().map(reason_name).collect(),
        repeated_requests: consensus.repeated_requests,
        retired_requests: consensus.retired_requests,
        post_terminal_progress: consensus.post_terminal_progress,
        sessions: SessionsDto {
            active: consensus.sessions.active,
            started: consensus.sessions.started,
            stop_started: consensus.sessions.stop_started,
            stopped: consensus.sessions.stopped,
            stopping: consensus.sessions.stopping,
        },
        contexts: consensus
            .contexts
            .iter()
            .map(|context| ContextDto {
                session_id: context.session_id.clone(),
                scope_id: context.scope.scope_id.clone(),
                workchain: context.scope.workchain,
                shard: context.scope.shard,
                current_slot: context.current_slot,
                last_finalized_slot: context.last_finalized_slot,
                lifecycle: match context.lifecycle {
                    Lifecycle::Active => "active",
                    Lifecycle::Stopping => "stopping",
                }
                .into(),
                stop_started_monotonic_ns: context.stop_started_monotonic_ns,
            })
            .collect(),
        actions: consensus.actions.iter().map(action_dto).collect(),
        pq_sign: pq(pq_sign),
        pq_verify: pq(pq_verify),
    }
}

fn storage_dto(consensus: &Consensus) -> Result<PayloadDto, String> {
    let capability = |name: &str| consensus.capabilities.get(name);
    let ack = capability("storage_commit_ack").ok_or("native sample lacks storage capability")?;
    let mut sums = [0u64; 3];
    for action in &consensus.actions {
        let live = match action {
            Action::Proposal { live, .. }
            | Action::NotarizeVote { live, .. }
            | Action::FinalizeVote { live, .. }
            | Action::SkipVote { live, .. } => live,
        };
        for (index, key) in
            ["intent_storage", "signed_storage", "journal_unusable"].iter().enumerate()
        {
            if let Some(count) = live.failures.get(*key) {
                sums[index] = sums[index].checked_add(count.0).ok_or("storage failure overflow")?;
            }
        }
    }
    Ok(PayloadDto::StorageState {
        storage_commit_ack: StorageCapabilityDto {
            supported: ack.supported,
            enabled: ack.enabled,
            contract_valid: ack.contract_valid,
            reason: ack.reason.clone(),
        },
        durable_finality_reason: capability("durable_finality").and_then(|c| c.reason.clone()),
        intent_storage_failures: U64(sums[0]),
        signed_storage_failures: U64(sums[1]),
        journal_unusable_failures: U64(sums[2]),
    })
}

fn chain_dto(network_id: &str, chain: &ChainAnchors) -> Result<PayloadDto, String> {
    let anchor = |a: &BlockAnchor| BlockAnchorDto {
        workchain: a.workchain,
        shard: a.shard,
        seqno: a.seqno,
        root_hash: a.root_hash.clone(),
        file_hash: a.file_hash.clone(),
    };
    let time = |seconds: u64| -> Result<String, String> {
        let ms = i64::try_from(seconds.checked_mul(1000).ok_or("chain time overflow")?)
            .map_err(failure)?;
        chrono::TimeZone::timestamp_millis_opt(&chrono::Utc, ms)
            .single()
            .map(|v| v.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            .ok_or_else(|| "chain time out of range".into())
    };
    Ok(PayloadDto::ChainAnchors {
        network_id: network_id.into(),
        applied: anchor(&chain.applied),
        served: chain.served.as_ref().map(anchor),
        applied_advanced_at: time(chain.applied_advanced_unix_seconds.0)?,
        observed_at: time(chain.observed_unix_seconds.0)?,
        applied_age_seconds: U64(chain
            .observed_unix_seconds
            .0
            .saturating_sub(chain.applied_advanced_unix_seconds.0)),
        served_gap: chain
            .served
            .as_ref()
            .map(|served| U64(u64::from(chain.applied.seqno.saturating_sub(served.seqno)))),
    })
}

/// Archived native consensus rows (v1/v2/v3) become one derived query row
/// each: a compact typed consensus payload, fixed chain/storage views and the
/// exact origin payload. The row is a pure function of its retained parent.
fn project_native(row: &EvidenceRow) -> Result<Option<Evidence>, String> {
    let record = &row.evidence.record;
    let source_value = record.payload.get("source").ok_or("missing archived native source")?;
    let mut native = parse_native(&serde_json::to_vec(source_value).map_err(failure)?)?;
    // Relay age is not part of the immutable archive; validation checks the
    // frozen sample the same way `immutable_hash` does.
    native.set_source_age_ms(Some(0));
    let (source_version, generation, network_id, observed, success, coverage, quality, payload) =
        match &native {
            NativeRecord::V1(v) => {
                v.validate()?;
                (
                    v.source_version.as_str(),
                    v.generation,
                    v.payload.network_id.as_str(),
                    v.observed_at.as_deref(),
                    v.last_success_at.as_deref(),
                    &v.coverage,
                    &v.quality,
                    serde_json::to_value(&v.payload).map_err(failure)?,
                )
            }
            NativeRecord::V2(v) => {
                v.validate()?;
                (
                    v.source_version.as_str(),
                    v.generation,
                    v.payload.network_id.as_str(),
                    v.observed_at.as_deref(),
                    v.last_success_at.as_deref(),
                    &v.coverage,
                    &v.quality,
                    serde_json::to_value(&v.payload).map_err(failure)?,
                )
            }
            NativeRecord::V3(v) => {
                v.validate()?;
                (
                    v.source_version.as_str(),
                    v.generation,
                    v.payload.network_id.as_str(),
                    v.observed_at.as_deref(),
                    v.last_success_at.as_deref(),
                    &v.coverage,
                    &v.quality,
                    serde_json::to_value(&v.payload).map_err(failure)?,
                )
            }
        };
    let observed = utc_ms(observed.ok_or("missing native observed_at")?).map_err(str::to_owned)?;
    let success = utc_ms(success.ok_or("missing native success_at")?).map_err(str::to_owned)?;
    let envelope_matches = |node: &str, scope: &str, epoch: &str, source_epoch: &str| {
        node == record.node_id
            && scope == record.scope_id
            && epoch == record.process_epoch
            && source_epoch == row.evidence.source_epoch
    };
    let identity_ok = match &native {
        NativeRecord::V1(v) => {
            envelope_matches(&v.node_id, &v.scope_id, &v.process_epoch, &v.source_epoch)
        }
        NativeRecord::V2(v) => {
            envelope_matches(&v.node_id, &v.scope_id, &v.process_epoch, &v.source_epoch)
        }
        NativeRecord::V3(v) => {
            envelope_matches(&v.node_id, &v.scope_id, &v.process_epoch, &v.source_epoch)
        }
    };
    if !identity_ok
        || record.source_id != "native_core"
        || record.source_record_id != format!("{}:{}", row.evidence.source_epoch, generation.0)
        || record.observed_at_ms != observed
        || record.quality.observed_at_ms != Some(observed)
        || record.quality.last_success_at_ms != Some(success)
        || record.quality.process_epoch != record.process_epoch
        || record.quality.source_sequence != generation.0.to_string()
        || record.quality.availability != Availability::Available
        || record.quality.coverage != Coverage::Partial
        || !record.quality.clock_valid
        || !record.redacted
        || source_value.get("received_at").is_some_and(|v| !v.is_null())
    {
        return Err("archived native source mismatch".into());
    }
    let (contract_payload, chain_payload, storage_payload) = match &native {
        NativeRecord::V1(v) => (serde_json::to_value(&v.payload).map_err(failure)?, None, None),
        NativeRecord::V2(v) => match &v.payload.consensus {
            Some(consensus) => (
                serde_json::to_value(consensus_dto(
                    source_version,
                    generation,
                    network_id,
                    consensus,
                    v.payload.pq_sign.as_ref(),
                    v.payload.pq_verify.as_ref(),
                ))
                .map_err(failure)?,
                None,
                Some(serde_json::to_value(storage_dto(consensus)?).map_err(failure)?),
            ),
            None => return Err("native v2 sample without consensus is not projectable".into()),
        },
        NativeRecord::V3(v) => match &v.payload.consensus {
            Some(consensus) => (
                serde_json::to_value(consensus_dto(
                    source_version,
                    generation,
                    network_id,
                    consensus,
                    v.payload.pq_sign.as_ref(),
                    v.payload.pq_verify.as_ref(),
                ))
                .map_err(failure)?,
                v.payload
                    .chain
                    .as_ref()
                    .map(|chain| chain_dto(network_id, chain))
                    .transpose()?
                    .map(serde_json::to_value)
                    .transpose()
                    .map_err(failure)?,
                Some(serde_json::to_value(storage_dto(consensus)?).map_err(failure)?),
            ),
            None => return Err("native v3 sample without consensus is not projectable".into()),
        },
    };
    let query_payload = serde_json::json!({
        "component":"consensus",
        "source_version":VERSION,
        "origin_source_version":source_version,
        "origin_store_seq":U64(row.store_seq.0),
        "evidence_kind":"derived",
        "parent_evidence_ids":[row.evidence_id],
        "derivation_version":VERSION,
        "contract_quality":quality,
        "contract_coverage":coverage,
        "contract_payload":contract_payload,
        "chain_payload":chain_payload,
        "storage_payload":storage_payload,
        "origin_payload":payload,
    });
    let mut projected = record.clone();
    projected.source_record_id = format!("m-{}", row.evidence_id);
    projected.payload = query_payload;
    Ok(Some(projected))
}

pub fn project_process(row: &EvidenceRow) -> Result<Option<Evidence>, String> {
    if row.store_seq.0 == 0 || !tos_health_core::wire::hash(&row.evidence_id) {
        return Err("invalid M evidence identity".into());
    }
    let mut original = row.evidence.clone();
    original.record.received_at_ms = 0;
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&original).map_err(failure)?));
    if digest != row.evidence_id {
        return Err("M evidence hash mismatch".into());
    }
    let record = &row.evidence.record;
    match record.payload.get("component").and_then(serde_json::Value::as_str) {
        Some("process") => {}
        Some("consensus") if record.source_id == "native_core" => return project_native(row),
        _ => return Ok(None),
    }
    let source: ProcessEnvelope = serde_json::from_value(
        record.payload.get("source").ok_or("missing archived process source")?.clone(),
    )
    .map_err(failure)?;
    if source.availability != "available"
        || source.clock_quality != "valid"
        || source.observed_at.is_none()
        || source.last_success_at.is_none()
        || !record.quality.clock_valid
        || record.quality.observed_at_ms.is_none()
    {
        return Err(
            "M process source unavailable: source clock, time or availability unknown".into()
        );
    }
    let observed = utc_ms(source.observed_at.as_deref().ok_or("missing source observed_at")?)
        .map_err(str::to_owned)?;
    let success = utc_ms(source.last_success_at.as_deref().ok_or("missing source success_at")?)
        .map_err(str::to_owned)?;
    if source.schema_version != 1
        || source.source_id != "process"
        || source.source_version != "proc-v1"
        || source.payload.kind != "process"
        || source.payload.pid == 0
        || source.generation.0 == 0
        || source.availability != "available"
        || source.clock_quality != "valid"
        || source.coverage.status != "partial"
        || source.coverage.sampling_policy != "fixed_15s"
        || !source.coverage.gaps.is_empty()
        || source.coverage.missing_fields.len() > 64
        || source.coverage.missing_fields.iter().any(|field| field.len() > 96)
        || source.node_id != record.node_id
        || source.scope_id != record.scope_id
        || source.process_epoch != record.process_epoch
        || source.source_epoch != row.evidence.source_epoch
        || record.source_id != source.source_id
        || record.source_record_id != format!("{}:{}", source.source_epoch, source.generation.0)
        || record.observed_at_ms != observed
        || record.quality.observed_at_ms != Some(observed)
        || record.quality.last_success_at_ms != Some(success)
        || record.quality.process_epoch != source.process_epoch
        || record.quality.source_sequence != source.generation.0.to_string()
        || record.quality.availability != Availability::Available
        || record.quality.coverage != Coverage::Partial
        || !record.quality.clock_valid
        || !record.redacted
        || source.received_at.is_some()
        || canonical_hash(&source.payload)? != source.content_hash
    {
        return Err("archived process source mismatch".into());
    }
    let payload: ProcessPayload = source.payload;
    let query_payload = serde_json::json!({
        "component":"process",
        "source_version":VERSION,
        "origin_source_version":source.source_version,
        "origin_store_seq":U64(row.store_seq.0),
        "evidence_kind":"derived",
        "parent_evidence_ids":[row.evidence_id],
        "derivation_version":VERSION,
        "contract_quality":source.quality,
        "contract_coverage":source.coverage,
        "contract_payload":payload,
    });
    let mut projected = record.clone();
    projected.source_record_id = format!("m-{}", row.evidence_id);
    projected.payload = query_payload;
    Ok(Some(projected))
}

/// Fixed source identity of the read-only verdict copy in the query cache.
pub const VERDICT_SOURCE: &str = "health_state";
pub const VERDICT_EPOCH: &str = "m-control";
pub const VERDICT_VERSION: &str = "m-health-state-v1";
const MAX_VERDICT_RULES: usize = 64;

/// One node's deterministic rule verdicts as read from M's control database.
#[derive(Debug, Clone)]
pub struct NodeVerdicts {
    pub node_id: String,
    pub verdicts: Vec<tos_health_core::query_output::HealthVerdictDto>,
}

/// Read M's health-state incidents read-only in one snapshot. This copies
/// the deterministic verdict; it never evaluates a rule or opens M for write.
pub fn read_health_verdicts(
    path: &Path,
    network: &str,
    nodes: &BTreeSet<String>,
) -> Result<(u64, Vec<NodeVerdicts>), String> {
    use tos_health_core::{health_state::HealthState, query_output::HealthVerdictDto};
    if !tos_health_core::wire::hash(network) {
        return Err("invalid M network".into());
    }
    let meta = std::fs::symlink_metadata(path).map_err(failure)?;
    if !meta.file_type().is_file() {
        return Err("M control path is not a regular file".into());
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(failure)?;
    conn.busy_timeout(std::time::Duration::from_millis(100)).map_err(failure)?;
    conn.execute_batch("PRAGMA query_only=ON; BEGIN TRANSACTION").map_err(failure)?;
    let bound: String = conn
        .query_row("SELECT network FROM database_identity WHERE singleton=1", [], |row| row.get(0))
        .map_err(failure)?;
    if bound != network {
        return Err("M control network mismatch".into());
    }
    let sequence: i64 = conn
        .query_row("SELECT sequence FROM evaluation WHERE singleton=1", [], |row| row.get(0))
        .map_err(failure)?;
    let sequence = u64::try_from(sequence).map_err(failure)?;
    let mut query = conn
        .prepare("SELECT node,scope,rule,body FROM incidents ORDER BY node,scope,rule LIMIT ?1")
        .map_err(failure)?;
    let limit = i64::try_from(nodes.len().saturating_mul(MAX_VERDICT_RULES).saturating_add(1))
        .map_err(failure)?;
    let rows = query
        .query_map([limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(failure)?;
    let mut per_node: std::collections::BTreeMap<String, Vec<HealthVerdictDto>> =
        nodes.iter().map(|node| (node.clone(), Vec::new())).collect();
    for row in rows {
        let (node, scope, rule, body) = row.map_err(failure)?;
        let Some(list) = per_node.get_mut(&node) else { continue };
        if list.len() >= MAX_VERDICT_RULES {
            return Err("M control rule count exceeds verdict bound".into());
        }
        if !tos_health_core::wire::alias(&scope) || !tos_health_core::wire::alias(&rule) {
            return Err("M control rule key malformed".into());
        }
        let state: HealthState = serde_json::from_str(&body).map_err(failure)?;
        let state_name = serde_json::to_value(state.state)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or("M control state malformed")?;
        list.push(HealthVerdictDto {
            rule,
            scope_id: scope,
            state: state_name,
            severity: state.severity.clone(),
            episode: state.episode,
            acknowledged: state.acknowledged,
            active: state.active(),
        });
    }
    let end_meta = std::fs::symlink_metadata(path).map_err(failure)?;
    if end_meta.dev() != meta.dev() || end_meta.ino() != meta.ino() {
        return Err("M control database replaced during read".into());
    }
    Ok((
        sequence,
        per_node
            .into_iter()
            .map(|(node_id, verdicts)| NodeVerdicts { node_id, verdicts })
            .collect(),
    ))
}

/// Build the query-cache row for one node's verdict copy. `import_ms` is the
/// query layer's own wall clock at the read; it is the only time basis.
pub fn verdict_evidence(sequence: u64, node: &NodeVerdicts, import_ms: i64) -> Evidence {
    use tos_health_core::source::SourceQuality;
    let payload = PayloadDto::HealthVerdicts {
        source_id: VERDICT_SOURCE.into(),
        evaluation_sequence: U64(sequence),
        verdicts: node.verdicts.clone(),
    };
    Evidence {
        node_id: node.node_id.clone(),
        scope_id: "node".into(),
        source_id: VERDICT_SOURCE.into(),
        source_record_id: format!("{sequence}:{import_ms}"),
        process_epoch: VERDICT_EPOCH.into(),
        observed_at_ms: import_ms,
        received_at_ms: import_ms,
        quality: SourceQuality {
            availability: Availability::Available,
            coverage: Coverage::Complete,
            observed_at_ms: Some(import_ms),
            last_success_at_ms: Some(import_ms),
            clock_valid: true,
            process_epoch: VERDICT_EPOCH.into(),
            source_sequence: sequence.to_string(),
        },
        payload: serde_json::json!({
            "component":"health",
            "source_version":VERDICT_VERSION,
            "evidence_kind":"observation",
            "contract_quality":{"instrumentation_complete":true,"producer_dropped":"0","relay_dropped":"0","parse_errors":"0","shed_reason":null},
            "contract_coverage":{"status":"complete","missing_fields":[],"gaps":[],"sampling_policy":"m_control_incidents_read_at_import"},
            "contract_payload":payload,
        }),
        redacted: true,
    }
}

/// One read transaction fixes M's original observation watermark and excludes
/// quarantine. Query-memory W is separate and only advances after its own
/// durable import; the caller must not mistake the two sequence namespaces.
pub fn read_process_projection(
    path: &Path,
    network: &str,
) -> Result<(u64, Vec<(EvidenceRow, Evidence)>), String> {
    let (watermark, records, _) = read_process_projection_state(path, network)?;
    Ok((watermark, records))
}

/// One bounded incremental page from a single read transaction. The previous
/// cursor is persisted in QueryLedger, not inferred from the in-memory store:
/// evicted query rows must not cause old M history to be scanned again.
pub fn read_process_projection_page(
    path: &Path,
    network: &str,
    previous: Option<&crate::query_ledger::ManagerCursor>,
    retained: &[EvidenceRow],
) -> Result<ProjectionPage, String> {
    if !tos_health_core::wire::hash(network) || retained.len() > MAX_ROWS {
        return Err("invalid M projection source or retained set".into());
    }
    let meta = std::fs::symlink_metadata(path).map_err(failure)?;
    if !meta.file_type().is_file() {
        return Err("M evidence path is not a regular file".into());
    }
    if previous.is_some_and(|old| {
        old.network != network || old.device != meta.dev() || old.inode != meta.ino()
    }) {
        return Err("M projection database identity changed".into());
    }
    if previous.is_some_and(|old| match (old.watermark, old.anchor.as_ref()) {
        (0, None) => false,
        (watermark, Some((seq, hash))) => *seq != watermark || !tos_health_core::wire::hash(hash),
        _ => true,
    }) {
        return Err("invalid persisted M projection cursor".into());
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(failure)?;
    conn.busy_timeout(std::time::Duration::from_millis(100)).map_err(failure)?;
    conn.execute_batch("PRAGMA query_only=ON; BEGIN TRANSACTION").map_err(failure)?;
    let bound: String = conn
        .query_row("SELECT network FROM database_identity WHERE singleton=1", [], |row| row.get(0))
        .map_err(failure)?;
    if bound != network {
        return Err("M evidence network mismatch".into());
    }
    let watermark: Option<i64> = conn
        .query_row("SELECT seq FROM sqlite_sequence WHERE name='observations'", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(failure)?;
    let watermark = u64::try_from(watermark.unwrap_or(0)).map_err(failure)?;
    let after = previous.map_or(0, |old| old.watermark);
    if watermark < after {
        return Err("M projection watermark regressed".into());
    }
    // The cursor shape above binds seq to old W. This lookup and the later
    // page scan share one M read transaction, so a real boundary at W must
    // still have the original hash even when it is not a process row.
    if let Some((seq, expected)) = previous.and_then(|old| old.anchor.as_ref()) {
        let actual: Option<String> = conn
            .query_row(
                "SELECT content_hash FROM observations WHERE store_seq=?1",
                [i64::try_from(*seq).map_err(failure)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(failure)?;
        if actual.as_deref() != Some(expected) {
            return Err("M projection anchor changed".into());
        }
    }
    // A late quarantine or replacement may target a row older than `after`.
    // Revalidate exact retained parent seq/hash/body in this same M snapshot.
    let mut quarantined_retained = BTreeSet::new();
    let mut expired_retained = BTreeSet::new();
    let mut parent = conn
        .prepare(
            "SELECT o.content_hash,o.body,o.node,o.scope,o.process_epoch,
             o.source_epoch,o.source,o.source_record,
             EXISTS(SELECT 1 FROM quarantined q
             WHERE q.node=o.node AND q.scope=o.scope AND q.process_epoch=o.process_epoch
             AND q.source_epoch=o.source_epoch AND q.source=o.source)
             FROM observations o WHERE o.store_seq=?1 AND o.source IN ('process','native_core')",
        )
        .map_err(failure)?;
    for origin in retained {
        if origin.store_seq.0 == 0 || origin.store_seq.0 > watermark {
            return Err("retained M parent sequence outside snapshot".into());
        }
        let actual: Option<RetainedSqlRow> = parent
            .query_row([i64::try_from(origin.store_seq.0).map_err(failure)?], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            })
            .optional()
            .map_err(failure)?;
        let Some((
            id,
            body,
            node,
            scope,
            process_epoch,
            source_epoch,
            source,
            source_record,
            quarantined,
        )) = actual
        else {
            // M's age retention seals every identity it deletes from, in the
            // deleting transaction. A seal at or above this parent's
            // generation proves a bounded expiry; anything else is a missing
            // row the projection cannot explain.
            if retention_seal_covers(&conn, origin)? {
                expired_retained.insert(origin.evidence_id.clone());
                continue;
            }
            return Err("retained M parent missing".into());
        };
        let original = &origin.evidence.record;
        if id != origin.evidence_id
            || body.as_bytes() != serde_json::to_vec(&origin.evidence).map_err(failure)?
            || node != original.node_id
            || scope != original.scope_id
            || process_epoch != original.process_epoch
            || source_epoch != origin.evidence.source_epoch
            || source != original.source_id
            || source_record != original.source_record_id
        {
            return Err("retained M parent changed".into());
        }
        if quarantined != 0 {
            quarantined_retained.insert(id);
        }
    }
    drop(parent);
    let mut query = conn
        .prepare(&format!(
            "SELECT o.store_seq,
             CASE WHEN length(CAST(o.content_hash AS BLOB))=64 THEN o.content_hash ELSE NULL END,
             CASE WHEN {ELIGIBLE_SOURCE} AND q.source IS NULL THEN 1 ELSE 0 END,
             CASE WHEN {ELIGIBLE_SOURCE} AND q.source IS NULL THEN length(CAST(o.body AS BLOB)) ELSE 0 END,
             CASE WHEN {ELIGIBLE_SOURCE} AND q.source IS NULL
                  AND length(CAST(o.body AS BLOB))<=32768 THEN o.body ELSE NULL END
             FROM observations o LEFT JOIN quarantined q
             ON q.node=o.node AND q.scope=o.scope AND q.process_epoch=o.process_epoch
             AND q.source_epoch=o.source_epoch AND q.source=o.source
             WHERE o.store_seq>?1 AND o.store_seq<=?2
             ORDER BY o.store_seq LIMIT ?3"
        ))
        .map_err(failure)?;
    let rows = query
        .query_map(
            params![
                i64::try_from(after).map_err(failure)?,
                i64::try_from(watermark).map_err(failure)?,
                (PAGE_ROWS + 1) as i64
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .map_err(failure)?;
    let mut records = Vec::new();
    let mut process_bytes = 0usize;
    let mut last = after;
    let mut anchor = previous.and_then(|old| old.anchor.clone());
    let mut last_was_projected = false;
    let mut caught_up = true;
    for (count, row) in rows.enumerate() {
        if count == PAGE_ROWS {
            caught_up = false;
            break;
        }
        let (seq, id, eligible, length, body) = row.map_err(failure)?;
        let id = id.ok_or("M projection global row hash malformed")?;
        if !tos_health_core::wire::hash(&id) {
            return Err("M projection global row hash malformed".into());
        }
        last = u64::try_from(seq).map_err(failure)?;
        anchor = Some((last, id.clone()));
        last_was_projected = false;
        if eligible == 0 {
            continue;
        }
        if eligible != 1 {
            return Err("M projection eligibility malformed".into());
        }
        let length = usize::try_from(length).map_err(failure)?;
        process_bytes = process_bytes.checked_add(length).ok_or("M scan overflow")?;
        if process_bytes > MAX_BYTES || length > 32_768 {
            return Err("M projection page bound exceeded".into());
        }
        let row = EvidenceRow {
            store_seq: U64(last),
            evidence_id: id,
            evidence: serde_json::from_str::<DurableEvidence>(
                &body.ok_or("M projection body unavailable")?,
            )
            .map_err(failure)?,
        };
        let projected = project_origin(&row)?.ok_or("M eligible row is not projectable")?;
        records.push((row, projected));
        last_was_projected = true;
    }
    drop(query);
    let mut boundary_witness =
        if last > after && !last_was_projected { anchor.clone() } else { None };
    if caught_up && watermark > 0 {
        let boundary: Option<String> = conn
            .query_row(
                "SELECT content_hash FROM observations WHERE store_seq=?1",
                [i64::try_from(watermark).map_err(failure)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(failure)?;
        let digest = boundary.ok_or("M projection global boundary missing")?;
        if !tos_health_core::wire::hash(&digest) {
            return Err("M projection global boundary malformed".into());
        }
        let global = (watermark, digest);
        if anchor.as_ref() != Some(&global) {
            boundary_witness = Some(global.clone());
            anchor = Some(global);
        }
    }
    let end_meta = std::fs::symlink_metadata(path).map_err(failure)?;
    if end_meta.dev() != meta.dev() || end_meta.ino() != meta.ino() {
        return Err("M projection database replaced during read".into());
    }
    Ok(ProjectionPage {
        cursor: crate::query_ledger::ManagerCursor {
            network: network.to_owned(),
            device: meta.dev(),
            inode: meta.ino(),
            watermark: if caught_up { watermark } else { last },
            anchor,
        },
        boundary_witness,
        records,
        quarantined_retained,
        expired_retained,
        caught_up,
    })
}

/// True when M's retention seal for the parent's exact identity records a
/// highest deleted generation at or above the parent's own generation. Read
/// in the caller's M snapshot. A parent without a canonical generation can
/// never have been sealed, so it is never reported as expired.
fn retention_seal_covers(conn: &Connection, origin: &EvidenceRow) -> Result<bool, String> {
    let record = &origin.evidence.record;
    let Some(generation) = crate::retention::generation_of(&record.source_record_id) else {
        return Ok(false);
    };
    let sealed: Option<String> = conn
        .query_row(
            "SELECT max_generation FROM retention_seals WHERE node=?1 AND scope=?2
             AND process_epoch=?3 AND source_epoch=?4 AND source=?5",
            params![
                record.node_id,
                record.scope_id,
                record.process_epoch,
                origin.evidence.source_epoch,
                record.source_id
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(failure)?;
    match sealed {
        Some(value) => {
            let sealed = tos_health_core::wire::exact_u64(&value).map_err(str::to_owned)?;
            Ok(generation <= sealed)
        }
        None => Ok(false),
    }
}

/// The third value is a bounded set of M original IDs whose source tuple is
/// quarantined. It is read in the same SQLite snapshot as the projection.
pub fn read_process_projection_state(path: &Path, network: &str) -> Result<ProjectionScan, String> {
    if !tos_health_core::wire::hash(network) {
        return Err("invalid M network".into());
    }
    let meta = std::fs::symlink_metadata(path).map_err(failure)?;
    if !meta.file_type().is_file() {
        return Err("M evidence path is not a regular file".into());
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(failure)?;
    conn.busy_timeout(std::time::Duration::from_millis(100)).map_err(failure)?;
    conn.execute_batch("PRAGMA query_only=ON; BEGIN TRANSACTION").map_err(failure)?;
    let bound: String = conn
        .query_row("SELECT network FROM database_identity WHERE singleton=1", [], |row| row.get(0))
        .map_err(failure)?;
    if bound != network {
        return Err("M evidence network mismatch".into());
    }
    let watermark: Option<i64> = conn
        .query_row("SELECT seq FROM sqlite_sequence WHERE name='observations'", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(failure)?;
    let watermark = u64::try_from(watermark.unwrap_or(0)).map_err(failure)?;
    let mut query = conn
        .prepare(&format!(
            "SELECT o.store_seq,o.content_hash,length(CAST(o.body AS BLOB)),
             CASE WHEN length(CAST(o.body AS BLOB))<=32768 THEN o.body ELSE NULL END
             FROM observations o WHERE o.store_seq<=?1 AND {ELIGIBLE_SOURCE}
             AND NOT EXISTS(SELECT 1 FROM quarantined q WHERE q.node=o.node
             AND q.scope=o.scope AND q.process_epoch=o.process_epoch
             AND q.source_epoch=o.source_epoch AND q.source=o.source)
             ORDER BY o.store_seq LIMIT ?2"
        ))
        .map_err(failure)?;
    let rows = query
        .query_map(
            params![i64::try_from(watermark).map_err(failure)?, MAX_ROWS as i64 + 1],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .map_err(failure)?;
    let mut projected = Vec::new();
    let mut count = 0usize;
    let mut bytes = 0usize;
    for row in rows {
        let (seq, id, length, body) = row.map_err(failure)?;
        count += 1;
        let length = usize::try_from(length).map_err(failure)?;
        bytes = bytes.checked_add(length).ok_or("M scan overflow")?;
        if count > MAX_ROWS || bytes > MAX_BYTES || length > 32_768 {
            return Err("M projection scan bound exceeded".into());
        }
        let body = body.ok_or("M projection body unavailable")?;
        let row = EvidenceRow {
            store_seq: U64(u64::try_from(seq).map_err(failure)?),
            evidence_id: id,
            evidence: serde_json::from_str::<DurableEvidence>(&body).map_err(failure)?,
        };
        if let Some(record) = project_origin(&row)? {
            projected.push((row, record));
        }
    }
    let mut quarantined = std::collections::BTreeSet::new();
    let mut query = conn
        .prepare(
            "SELECT o.content_hash FROM observations o JOIN quarantined q
         ON q.node=o.node AND q.scope=o.scope AND q.process_epoch=o.process_epoch
         AND q.source_epoch=o.source_epoch AND q.source=o.source
             WHERE o.store_seq<=?1 AND o.source IN ('process','native_core')
             ORDER BY o.store_seq LIMIT ?2",
        )
        .map_err(failure)?;
    let rows = query
        .query_map(
            params![i64::try_from(watermark).map_err(failure)?, MAX_ROWS as i64 + 1],
            |row| row.get::<_, String>(0),
        )
        .map_err(failure)?;
    let mut count = 0usize;
    for row in rows {
        count += 1;
        if count > MAX_ROWS {
            return Err("M quarantine scan bound exceeded".into());
        }
        quarantined.insert(row.map_err(failure)?);
    }
    Ok((watermark, projected, quarantined))
}
