//! Independent control/evidence owners; handlers never execute database work.
use crate::durable::{
    ControlDb, ControlUpdate, DurableEvidence, Evaluation, EvidenceDb, EvidenceRow, RuleKey,
    WitnessArchiveRow,
};
use crate::retention::{RetentionPolicy, RetentionSchedule, RetentionStatus};
use crate::witness::{
    CacheResponse, RelativeAge, RemoteClock, RoleAtObserverReceipt, RowAge, RowQualification,
};
use axum::{
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        mpsc::{sync_channel, RecvTimeoutError, SyncSender},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use tos_health_core::{
    evidence::Evidence,
    rules::{FactFrame, RuleEngine, RuleInventory, Signal},
    source::{Availability, Coverage, SourceQuality},
    wire::U64,
};
const MAX_CURRENT_VIEW_BYTES: usize = 1_048_576;
const CURRENT_BODY_MAX: usize = 32_768;
// The current lane admits one writer and two body-lifetime readers. Reserve
// each simultaneously owned bounded object before charging retained views:
// six archive/request/duplicate/serialization bodies, two decoded source
// representations, two queued read bodies, and one read serialization body.
// Row structures include decoded Source, CacheResponse, qualification and
// read DTO vectors plus bounded target strings and allocator headroom.
// SQLite pages and concurrent history-only requests are separate quotas, not
// part of this volatile current-view budget.
const CURRENT_SCRATCH_RESERVE: usize = 6 * CURRENT_BODY_MAX
    + 2 * tos_health_core::witness::MAX_BODY
    + 3 * CURRENT_BODY_MAX
    + tos_health_core::witness::MAX_ROWS
        * (std::mem::size_of::<tos_health_core::witness::Row>()
            + std::mem::size_of::<RowAge>()
            + std::mem::size_of::<RowQualification>()
            + std::mem::size_of::<CurrentReadRow<'static>>()
            + 3 * 64
            + 512)
    + 32 * 1024;
const _: () = assert!(CURRENT_SCRATCH_RESERVE < MAX_CURRENT_VIEW_BYTES);
fn current_admissible(track_bytes: usize, retained_bytes: usize, candidate_bytes: usize) -> bool {
    CURRENT_SCRATCH_RESERVE
        .checked_add(track_bytes)
        .and_then(|total| total.checked_add(retained_bytes))
        .and_then(|total| total.checked_add(candidate_bytes))
        .is_some_and(|total| total <= MAX_CURRENT_VIEW_BYTES)
}
fn projected_current_entry_bytes(response: &CacheResponse) -> usize {
    // Before the durable current review mutates its row maps, reserve the
    // worst per-row ownership in both maps and the public view. IDs are
    // aliases (<=64 bytes), UTC is <=40 bytes, and rows are capped at 32 by
    // CacheResponse::decode. A new generation replaces the old entry; we
    // deliberately charge both until that replacement has completed.
    let track_row = 2 * (std::mem::size_of::<(String, Option<u64>)>() + 64 + 256);
    let view_row =
        std::mem::size_of::<(RowQualification, RowAge, Option<u64>)>() + 3 * 64 + 40 + 256;
    2048 + response.row_ages.len() * (track_row + view_row)
}

struct CurrentView {
    endpoint: String,
    observer_epoch: String,
    source_epoch: String,
    generation: u64,
    source_hash: String,
    first_received: Option<crate::transit::Stamp>,
    collector_to_m_ms: Option<u64>,
    rows: Vec<(RowQualification, RowAge, Option<u64>)>,
}
#[derive(Serialize)]
struct CurrentReadRow<'a> {
    qualification: RowQualification,
    first_received_at: &'a str,
    observer_clock_quality_at_first_receipt: tos_health_core::witness::ClockQuality,
    source_age_at_first_receipt_ms: Option<String>,
    effective_age_at_read_ms: Option<String>,
}
#[derive(Serialize)]
struct CurrentReadOutput<'a> {
    schema_version: u32,
    status: &'static str,
    production_usable: bool,
    endpoint_id: &'a str,
    observer_epoch: &'a str,
    source_epoch: &'a str,
    generation: String,
    source_hash: &'a str,
    m_elapsed_ms: Option<String>,
    collector_to_m_ms: Option<String>,
    rows: Vec<CurrentReadRow<'a>>,
}
struct CappedJson(Vec<u8>);
impl std::io::Write for CappedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > 32_768usize.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("witness current output overflow"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[cfg(test)]
mod current_output_tests {
    use super::CappedJson;
    use std::io::Write;
    #[test]
    fn serialization_buffer_accepts_exact_limit_and_refuses_next_byte() {
        let mut buffer = CappedJson(Vec::with_capacity(32_768));
        buffer.write_all(&vec![b'x'; 32_768]).unwrap();
        assert_eq!(buffer.0.len(), 32_768);
        assert_eq!(buffer.0.capacity(), 32_768);
        assert!(buffer.write_all(b"x").is_err());
        assert_eq!(buffer.0.len(), 32_768);
    }
    #[test]
    fn current_budget_structural_sizes_are_visible() {
        eprintln!("CurrentView={} RowQualification={} RowAge={} CacheResponse={} Source={} SourceRow={} CurrentReadRow={}",
            std::mem::size_of::<super::CurrentView>(),
            std::mem::size_of::<crate::witness::RowQualification>(),
            std::mem::size_of::<crate::witness::RowAge>(),
            std::mem::size_of::<crate::witness::CacheResponse>(),
            std::mem::size_of::<tos_health_core::witness::Source>(),
            std::mem::size_of::<tos_health_core::witness::Row>(),
            std::mem::size_of::<super::CurrentReadRow<'static>>());
        eprintln!(
            "current_scratch_reserve={} current_retained_room={}",
            super::CURRENT_SCRATCH_RESERVE,
            super::MAX_CURRENT_VIEW_BYTES - super::CURRENT_SCRATCH_RESERVE
        );
    }
    #[test]
    fn current_budget_accepts_exact_cap_and_refuses_overflow() {
        let room = super::MAX_CURRENT_VIEW_BYTES - super::CURRENT_SCRATCH_RESERVE;
        assert!(super::current_admissible(room / 2, room - room / 2, 0));
        assert!(!super::current_admissible(room / 2, room - room / 2, 1));
        assert!(!super::current_admissible(usize::MAX, 0, 0));
    }
    #[test]
    fn full_row_candidate_is_charged_before_current_mutation() {
        use crate::witness::{CacheReceipt, CacheResponse, RowAge};
        use tos_health_core::{wire::U64, witness::ClockQuality};
        let response = CacheResponse {
            receipt: CacheReceipt {
                schema_version: 1,
                observer_id: "observer_1".into(),
                observer_epoch: "observer-1".into(),
                plan_revision: "a".repeat(64),
                plan_hash: "a".repeat(64),
                endpoint_id: "cache_1".into(),
                source_epoch: "source-1".into(),
                generation: U64(1),
                source_hash: "a".repeat(64),
                raw_transport_hash: "a".repeat(64),
                observer_clock_quality: ClockQuality::Unknown,
                first_received_at: "2026-09-29T00:00:00Z".into(),
                request_duration_ms: U64(0),
                source_json: String::new(),
            },
            observer_elapsed_ms: U64(0),
            row_ages: (0..tos_health_core::witness::MAX_ROWS)
                .map(|i| RowAge {
                    target_id: format!("target_{i}"),
                    first_received_at: "2026-09-29T00:00:00Z".into(),
                    observer_clock_quality_at_first_receipt: ClockQuality::Unknown,
                    source_age_at_first_receipt_ms: None,
                    effective_age_ms: None,
                    fresh_relative_age: false,
                })
                .collect(),
        };
        let projected = super::projected_current_entry_bytes(&response);
        let room = super::MAX_CURRENT_VIEW_BYTES - super::CURRENT_SCRATCH_RESERVE;
        assert!(projected > 32 * 1024 && projected < room);
        assert!(super::current_admissible(room - projected, 0, projected));
        assert!(!super::current_admissible(room - projected + 1, 0, projected));
    }
    #[test]
    fn projected_full_row_entry_covers_decoded_track_and_view() {
        use crate::witness::{CacheReceipt, CacheResponse, RowAge};
        use serde_json::json;
        use sha2::{Digest, Sha256};
        use tos_health_core::{
            wire::U64,
            witness::{ClockQuality, Plan, Source},
        };
        let targets = (0..32)
            .map(|i| {
                json!({
                "target_id": format!("{}{:02}", "t".repeat(62), i),
                    "node_id": format!("node_{i}"), "role": "normal",
                    "valid_from": "2026-09-29T00:00:00Z",
                    "valid_until": "2026-09-30T00:00:00Z",
                    "scope_id": "masterchain", "workchain": -1,
                    "shard": "9223372036854775808", "endpoint_ids": ["cache_1"]
                })
            })
            .collect::<Vec<_>>();
        let plan_bytes = serde_json::to_vec(&json!({
            "schema_version": 1, "profile": "c05_development_cache_only",
            "revision": "a".repeat(64), "observer_id": "observer_1",
            "observer_epoch": "o".repeat(128), "network_id": "a".repeat(64),
            "genesis": "c".repeat(64), "clock_skew_allowance_ms": 5000,
            "endpoints": [{
                "endpoint_id": "cache_1",
                "fixed_url": "https://cache.example.test/witness",
                "failure_domain": "zone_a", "kind": "approved_cache_only_https",
                "current_source_epoch": "s".repeat(128)
            }], "targets": targets
        }))
        .unwrap();
        let plan = Plan::decode(&plan_bytes).unwrap();
        let rows = plan
            .targets
            .iter()
            .map(|target| {
                json!({
                    "target_id": target.target_id, "observed_at": null,
                    "source_age_ms": null, "anchor": null,
                    "network_observation": "unavailable",
                    "reported_certificate_membership": "not_checked",
                    "reported_proof": "not_checked",
                    "private_vote_visibility": "unavailable",
                    "coverage": "partial", "missing_fields": ["private_vote"]
                })
            })
            .collect::<Vec<_>>();
        let source_json = serde_json::to_string(&json!({
            "schema_version": 1, "endpoint_id": "cache_1",
            "source_epoch": "s".repeat(128), "generation": "1",
            "network_id": "a".repeat(64), "genesis": "c".repeat(64),
            "observed_at": null, "source_age_ms": null,
            "clock_quality": "unknown", "coverage": "partial", "rows": rows
        }))
        .unwrap();
        let source = Source::decode(source_json.as_bytes(), &plan, "cache_1").unwrap();
        let response = CacheResponse {
            receipt: CacheReceipt {
                schema_version: 1,
                observer_id: plan.observer_id.clone(),
                observer_epoch: plan.observer_epoch.clone(),
                plan_revision: plan.revision.clone(),
                plan_hash: tos_health_core::witness::canonical_plan_hash(&plan).unwrap(),
                endpoint_id: "cache_1".into(),
                source_epoch: "s".repeat(128),
                generation: U64(1),
                source_hash: tos_health_core::witness::canonical_source_hash(&source).unwrap(),
                raw_transport_hash: crate::hex(&Sha256::digest(source_json.as_bytes())),
                observer_clock_quality: ClockQuality::Unknown,
                first_received_at: "2026-09-29T00:00:00.123456789Z".into(),
                request_duration_ms: U64(0),
                source_json,
            },
            observer_elapsed_ms: U64(0),
            row_ages: source
                .rows
                .iter()
                .map(|row| RowAge {
                    target_id: row.target_id.clone(),
                    first_received_at: "2026-09-29T00:00:00.123456789Z".into(),
                    observer_clock_quality_at_first_receipt: ClockQuality::Unknown,
                    source_age_at_first_receipt_ms: None,
                    effective_age_ms: None,
                    fresh_relative_age: false,
                })
                .collect(),
        };
        let path = std::env::temp_dir().join(format!(
            "nhm-current-budget-{}-{}.db",
            std::process::id(),
            crate::hex(&crate::random_token().unwrap())
        ));
        let mut db = crate::durable::EvidenceDb::open(&path, 1_048_576).unwrap();
        db.activate_witness_current(&plan).unwrap();
        let stamp = crate::transit::Stamp::capture();
        let qualified =
            db.review_witness_current_at(&response, &plan, Some(0), stamp.clone()).unwrap();
        let view = super::CurrentView::new(&response, qualified, stamp, Some(0)).unwrap();
        let actual = db.witness_current_resident_bytes() + view.endpoint.capacity() + view.charge();
        let projected = super::projected_current_entry_bytes(&response);
        eprintln!("full_row_actual={actual} projected={projected}");
        assert!(actual <= projected, "preflight must dominate actual retained capacities");
    }
    #[tokio::test]
    async fn timed_out_queued_reads_keep_leases_until_command_drain() {
        let (tx, rx) = std::sync::mpsc::sync_channel(2);
        let reads = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        for _ in 0..2 {
            assert_eq!(
                super::read_queued_current(
                    &tx,
                    &reads,
                    "cache_1",
                    std::time::Duration::from_millis(10)
                )
                .await
                .err()
                .as_deref(),
                Some("evidence deadline")
            );
        }
        assert_eq!(reads.available_permits(), 0);
        assert_eq!(
            super::read_queued_current(
                &tx,
                &reads,
                "cache_1",
                std::time::Duration::from_millis(10)
            )
            .await
            .err()
            .as_deref(),
            Some("witness current read busy"),
            "caller timeout must not release a queued writer command's lease"
        );
        drop(rx);
        assert_eq!(reads.available_permits(), 2, "actual queue drain releases both leases");
    }
}
impl CurrentView {
    fn new(
        response: &CacheResponse,
        qualifications: Vec<RowQualification>,
        received: Option<crate::transit::Stamp>,
        extra_ms: Option<u64>,
    ) -> Option<Self> {
        let rows = qualifications
            .into_iter()
            .map(|q| {
                let original =
                    response.row_ages.iter().find(|age| age.target_id == q.target_id).cloned()?;
                let age = original
                    .effective_age_ms
                    .zip(extra_ms)
                    .and_then(|(age, extra)| age.0.checked_add(extra));
                Some((q, original, age))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            endpoint: response.receipt.endpoint_id.clone(),
            observer_epoch: response.receipt.observer_epoch.clone(),
            source_epoch: response.receipt.source_epoch.clone(),
            generation: response.receipt.generation.0,
            source_hash: response.receipt.source_hash.clone(),
            first_received: received,
            collector_to_m_ms: extra_ms,
            rows,
        })
    }
    fn charge(&self) -> usize {
        let strings = self.endpoint.capacity()
            + self.observer_epoch.capacity()
            + self.source_epoch.capacity()
            + self.source_hash.capacity();
        std::mem::size_of::<Self>()
            + strings
            + self.rows.capacity() * std::mem::size_of::<(RowQualification, RowAge, Option<u64>)>()
            + self
                .rows
                .iter()
                .map(|(row, age, _)| {
                    row.target_id.capacity()
                        + age.target_id.capacity()
                        + age.first_received_at.capacity()
                })
                .sum::<usize>()
            + self.first_received.as_ref().map_or(0, crate::transit::Stamp::resident_bytes)
            + 256 // BTreeMap node/index and allocator overhead, conservatively charged.
    }
    fn merge_same_generation(&mut self, other: &Self) {
        let elapsed = self.first_received.as_ref().and_then(|stamp| stamp.elapsed_ms_now());
        for ((existing, _, floor), (incoming, _, new_age)) in self.rows.iter_mut().zip(&other.rows)
        {
            if existing.target_id != incoming.target_id {
                continue;
            }
            *floor = match (*floor, elapsed, *new_age) {
                (Some(old), Some(elapsed), Some(new)) => {
                    old.checked_add(elapsed).map(|aged| aged.max(new).saturating_sub(elapsed))
                }
                _ => None,
            };
            if incoming.relative_age != RelativeAge::Fresh {
                existing.relative_age = incoming.relative_age;
            }
        }
    }
    fn read(&self) -> Result<Vec<u8>, String> {
        let elapsed = self.first_received.as_ref().and_then(|stamp| stamp.elapsed_ms_now());
        let rows = self
            .rows
            .iter()
            .map(|(row, original, floor)| {
                let mut row = row.clone();
                let effective = floor.and_then(|v| elapsed.and_then(|e| v.checked_add(e)));
                row.relative_age = match (row.relative_age, effective) {
                    (RelativeAge::Stale, _) => RelativeAge::Stale,
                    (RelativeAge::Unknown, _) | (_, None) => RelativeAge::Unknown,
                    (_, Some(age)) if age > tos_health_core::witness::USABLE_AGE_MS => {
                        RelativeAge::Stale
                    }
                    _ => RelativeAge::Fresh,
                };
                CurrentReadRow {
                    qualification: row,
                    first_received_at: &original.first_received_at,
                    observer_clock_quality_at_first_receipt: original
                        .observer_clock_quality_at_first_receipt,
                    source_age_at_first_receipt_ms: original
                        .source_age_at_first_receipt_ms
                        .map(|v| v.0.to_string()),
                    effective_age_at_read_ms: effective.map(|v| v.to_string()),
                }
            })
            .collect::<Vec<_>>();
        let status = if !rows.is_empty()
            && rows.iter().all(|entry| {
                let row = &entry.qualification;
                row.relative_age == RelativeAge::Fresh
                    && row.remote_clock == RemoteClock::Compatible
                    && matches!(
                        row.role_at_observer_receipt,
                        RoleAtObserverReceipt::Normal
                            | RoleAtObserverReceipt::ProbeOnly
                            | RoleAtObserverReceipt::NonVoting
                    )
            }) {
            "qualified"
        } else {
            "unknown"
        };
        let output = CurrentReadOutput {
            schema_version: 1,
            status,
            production_usable: false,
            endpoint_id: &self.endpoint,
            observer_epoch: &self.observer_epoch,
            source_epoch: &self.source_epoch,
            generation: self.generation.to_string(),
            source_hash: &self.source_hash,
            m_elapsed_ms: elapsed.map(|v| v.to_string()),
            collector_to_m_ms: self.collector_to_m_ms.map(|v| v.to_string()),
            rows,
        };
        let mut bytes = CappedJson(Vec::with_capacity(32_768));
        serde_json::to_writer(&mut bytes, &output).map_err(|e| e.to_string())?;
        Ok(bytes.0)
    }
}
async fn read_queued_current(
    evidence: &SyncSender<EvidenceCommand>,
    reads: &Arc<tokio::sync::Semaphore>,
    endpoint_id: &str,
    deadline: Duration,
) -> Result<(Vec<u8>, Arc<tokio::sync::OwnedSemaphorePermit>), String> {
    let lease =
        Arc::new(reads.clone().try_acquire_owned().map_err(|_| "witness current read busy")?);
    let (tx, rx) = oneshot::channel();
    evidence
        .try_send(EvidenceCommand::ReadWitness(endpoint_id.to_owned(), lease.clone(), tx))
        .map_err(|_| "evidence queue unavailable")?;
    let bytes = tokio::time::timeout(deadline, rx)
        .await
        .map_err(|_| "evidence deadline")?
        .map_err(|_| "evidence writer stopped")??;
    Ok((bytes, lease))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerConfig {
    pub inventory: RuleInventory,
    pub control_db: PathBuf,
    pub evidence_db: PathBuf,
    pub control_quota_bytes: U64,
    pub evidence_quota_bytes: U64,
    pub listen: String,
    pub ingest_token_file: PathBuf,
    pub read_token_file: PathBuf,
    pub receiver: Option<ReceiverConfig>,
    #[serde(default)]
    pub witness_plan_file: Option<PathBuf>,
    #[serde(default)]
    pub witness_current_token_file: Option<PathBuf>,
    #[serde(default)]
    pub witness_current_trusted_same_host: bool,
    #[serde(default)]
    pub diagnostic: Option<DiagnosticConfig>,
    /// Age after which ordinary observations may be deleted (1 h to 90 d).
    /// Absent keeps the store unbounded, as before.
    #[serde(default)]
    pub evidence_retention_ms: Option<U64>,
    /// Same bound for the historical witness archive.
    #[serde(default)]
    pub witness_retention_ms: Option<U64>,
}
impl ManagerConfig {
    pub fn retention_policy(&self) -> RetentionPolicy {
        RetentionPolicy {
            evidence_retention_ms: self.evidence_retention_ms.map(|value| value.0),
            witness_retention_ms: self.witness_retention_ms.map(|value| value.0),
        }
    }
}
/// Delivery facts the doctor reads: whether a receiver exists and when the
/// last authenticated receipt was accepted in this process lifetime.
#[derive(Debug, Clone, Default)]
pub struct NotificationStatus {
    pub receiver_configured: bool,
    pub receiver_alias: Option<String>,
    pub deliveries: u64,
    pub last_delivery_at_ms: Option<i64>,
}
impl NotificationStatus {
    fn json(&self, now_ms: i64) -> Value {
        json!({
            "receiver_configured": self.receiver_configured,
            "receiver_alias": self.receiver_alias,
            "deliveries": self.deliveries.to_string(),
            "last_delivery_at_ms": self.last_delivery_at_ms.map(|value| value.to_string()),
            "last_delivery_age_ms": self.last_delivery_at_ms
                .and_then(|value| now_ms.checked_sub(value))
                .map(|age| age.max(0).to_string()),
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticConfig {
    pub token_file: PathBuf,
    pub nodes: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverConfig {
    pub url: String,
    pub ca_file: PathBuf,
    pub identity_file: PathBuf,
    pub token_file: PathBuf,
    pub alias: String,
}
#[derive(Clone)]
pub struct Manager {
    control: SyncSender<ControlCommand>,
    evidence: SyncSender<EvidenceCommand>,
    cache: Arc<Mutex<Cached>>,
    pub epoch: String,
    started: Instant,
    ingest: Arc<Vec<u8>>,
    read: Arc<Vec<u8>>,
    pub inventory: Arc<RuleInventory>,
    quarantines: Quarantines,
    witness_plan: Option<Arc<tos_health_core::witness::Plan>>,
    witness_current_token: Option<Arc<Vec<u8>>>,
    witness_current_reads: Arc<tokio::sync::Semaphore>,
    witness_current_writes: Arc<tokio::sync::Semaphore>,
    diagnostic_token: Option<Arc<Vec<u8>>>,
    diagnostic_nodes: Arc<Vec<String>>,
    diagnostic_budget: Arc<crate::diagnostic_ingest::Budget>,
    retention: Arc<Mutex<RetentionStatus>>,
    notification: Arc<Mutex<NotificationStatus>>,
}
#[derive(Clone)]
struct Cached {
    json: Value,
    metrics: String,
    completed: Option<Instant>,
    failure: bool,
}
enum ControlCommand {
    Ingest(Box<FactFrame>, Box<EvidenceRow>, Instant, oneshot::Sender<Result<bool, String>>),
    Pending(oneshot::Sender<Result<OutboxRows, String>>),
    Due(i64, oneshot::Sender<Result<OutboxRows, String>>),
    BeginAttempt(i64, String, i64, oneshot::Sender<Result<String, String>>),
    Delivered(i64, oneshot::Sender<Result<(), String>>),
}
enum EvidenceCommand {
    Insert(Box<DurableEvidence>, oneshot::Sender<Result<EvidenceRow, String>>),
    Diagnostic(
        Box<tos_health_core::contracts::DiagnosticBatch>,
        crate::diagnostic_ingest::Lease,
        oneshot::Sender<Result<crate::diagnostic_ingest::Ack, String>>,
    ),
    InsertWitness(
        Box<crate::witness::CacheResponse>,
        Arc<tos_health_core::witness::Plan>,
        Option<crate::transit::Stamp>,
        Option<tokio::sync::OwnedSemaphorePermit>,
        oneshot::Sender<Result<WitnessArchiveRow, String>>,
    ),
    ReadWitness(
        String,
        Arc<tokio::sync::OwnedSemaphorePermit>,
        oneshot::Sender<Result<Vec<u8>, String>>,
    ),
}
fn evidence(frame: &FactFrame) -> Result<DurableEvidence, String> {
    let at = tos_health_core::query::utc_ms(&frame.observed_at).map_err(str::to_owned)?;
    Ok(DurableEvidence {
        source_epoch: frame.source_epoch.clone(),
        record: Evidence {
            node_id: frame.node_id.clone(),
            scope_id: frame.scope_id.clone(),
            source_id: frame.source_id.clone(),
            source_record_id: frame.generation.0.to_string(),
            process_epoch: frame.process_epoch.clone(),
            observed_at_ms: at,
            received_at_ms: chrono::Utc::now().timestamp_millis(),
            quality: SourceQuality {
                availability: Availability::Available,
                coverage: if frame.complete { Coverage::Complete } else { Coverage::Partial },
                observed_at_ms: Some(at),
                last_success_at_ms: Some(at),
                clock_valid: frame.clock_valid,
                process_epoch: frame.process_epoch.clone(),
                source_sequence: frame.generation.0.to_string(),
            },
            payload: serde_json::to_value(frame.immutable()).map_err(|e| e.to_string())?,
            redacted: true,
        },
    })
}
fn same_database(a: &std::path::Path, b: &std::path::Path) -> Result<bool, String> {
    fn resolved(path: &std::path::Path) -> Result<PathBuf, String> {
        if path.exists() {
            return path.canonicalize().map_err(|e| e.to_string());
        }
        let name = path.file_name().ok_or("database requires filename")?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        Ok(parent.canonicalize().map_err(|e| e.to_string())?.join(name))
    }
    if resolved(a)? == resolved(b)? {
        return Ok(true);
    }
    #[cfg(unix)]
    if let (Ok(a), Ok(b)) = (std::fs::metadata(a), std::fs::metadata(b)) {
        use std::os::unix::fs::MetadataExt;
        if a.dev() == b.dev() && a.ino() == b.ino() {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Queue residence is observation age, never extra freshness granted by a slow writer.
pub fn with_queue_age(mut frame: FactFrame, residence: Duration) -> Result<FactFrame, String> {
    let elapsed = u64::try_from(residence.as_millis()).map_err(|_| "queue age overflow")?;
    frame.request_duration_ms =
        U64(frame.request_duration_ms.0.checked_add(elapsed).ok_or("queue age overflow")?);
    Ok(frame)
}
impl Manager {
    pub fn start(config: &ManagerConfig) -> Result<Self, String> {
        config.inventory.validate().map_err(str::to_owned)?;
        for target in &config.inventory.targets {
            for rule in &target.rules {
                match (rule.id.as_str(), rule.source.as_str()) {
                    ("target_unreachable", "edge_probe")
                    | ("telemetry_unavailable", "inventory")
                    | (
                        "pq_signing_failure"
                        | "local_chain_stalled"
                        | "local_action_failure"
                        | "local_action_overdue"
                        | "storage_ack_failure"
                        | "session_stop_pending"
                        | "initialization_stalled",
                        "native_core" | "native_facts",
                    )
                    | ("applied_served_gap", "native_chain")
                    | ("key_block_stale", "native_key_block")
                    | ("duty_missed", "native_duties")
                    | ("queue_stall", "native_queues")
                    | ("storage_space_low" | "state_gc_lag", "native_storage")
                    | ("diagnostic_coverage_reduced", "diagnostic")
                    | ("memory_growth_unexplained", "process_facts")
                    | ("quic_pressure" | "rocksdb_write_stopped", "native_gauges")
                    | ("observer_disagreement", "witness")
                    | ("ai_unavailable", "ai_optional") => {}
                    _ => return Err(format!("rule adapter unavailable: {}", rule.id)),
                }
            }
        }
        if same_database(&config.control_db, &config.evidence_db)? {
            return Err("control and evidence must be separate databases".into());
        }
        let policy = config.retention_policy();
        policy.validate()?;
        crate::loopback(&config.listen)?;
        let ingest = crate::secret(&config.ingest_token_file)?;
        let read = crate::secret(&config.read_token_file)?;
        if ingest == read {
            return Err("manager credentials must differ".into());
        }
        if config.witness_current_trusted_same_host != config.witness_current_token_file.is_some()
            || (config.witness_current_token_file.is_some() && config.witness_plan_file.is_none())
        {
            return Err(
                "current witness requires development plan, same-host trust and token".into()
            );
        }
        let witness_current_token = config
            .witness_current_token_file
            .as_ref()
            .map(|path| crate::secret(path).map(Arc::new))
            .transpose()?;
        if witness_current_token
            .as_deref()
            .is_some_and(|token| token.as_slice() == ingest || token.as_slice() == read)
        {
            return Err("current witness credential must be distinct".into());
        }
        let diagnostic_token = config
            .diagnostic
            .as_ref()
            .map(|diagnostic| {
                crate::diagnostic_ipc::read_token(&diagnostic.token_file).map(Arc::new)
            })
            .transpose()?;
        let diagnostic_nodes =
            config.diagnostic.as_ref().map_or_else(Vec::new, |diagnostic| diagnostic.nodes.clone());
        if diagnostic_token.as_deref().is_some_and(|token| {
            token.as_slice() == ingest
                || token.as_slice() == read
                || witness_current_token
                    .as_deref()
                    .is_some_and(|witness| token.as_slice() == witness.as_slice())
        }) {
            return Err("diagnostic credential must be distinct".into());
        }
        if config.diagnostic.is_some()
            && (diagnostic_nodes.is_empty()
                || diagnostic_nodes.len() > 1024
                || diagnostic_nodes.iter().collect::<std::collections::BTreeSet<_>>().len()
                    != diagnostic_nodes.len()
                || diagnostic_nodes.iter().any(|node| {
                    !crate::alias(node)
                        || !config.inventory.targets.iter().any(|target| target.node == *node)
                }))
        {
            return Err("diagnostic node outside inventory".into());
        }
        let mut db = ControlDb::open(&config.control_db, config.control_quota_bytes.0, 2304, 4096)?;
        db.bind_network(&config.inventory.network_id)?;
        db.bind_inventory(
            &config.inventory.revision,
            &serde_json::to_string(&config.inventory).map_err(|e| e.to_string())?,
        )?;
        let mut evidence_db = EvidenceDb::open(&config.evidence_db, config.evidence_quota_bytes.0)?;
        evidence_db.bind_network(&config.inventory.network_id)?;
        let witness_plan = if let Some(path) = &config.witness_plan_file {
            let plan = tos_health_core::witness::Plan::read_file(path)?;
            if plan.network_id != config.inventory.network_id {
                return Err("witness plan network mismatch".into());
            }
            for target in &plan.targets {
                if !config
                    .inventory
                    .targets
                    .iter()
                    .any(|item| item.node == target.node_id && item.scope == target.scope_id)
                {
                    return Err("witness target outside manager inventory".into());
                }
            }
            Some(Arc::new(plan))
        } else {
            None
        };
        if let Some(plan) = &witness_plan {
            evidence_db.activate_witness_current(plan)?;
        }
        let epoch = crate::hex(&crate::random_token()?);
        let started = Instant::now();
        let engine = RuleEngine::new(config.inventory.clone(), 0).map_err(str::to_owned)?;
        let cache = Arc::new(Mutex::new(Cached {
            json: json!({"status":"unknown","incidents":[]}),
            metrics: String::new(),
            completed: None,
            failure: false,
        }));
        let (control, rx) = sync_channel(32);
        let (evidence_tx, erx) = sync_channel(32);
        let retention = Arc::new(Mutex::new(RetentionStatus::new(&policy)));
        let retention_writer = retention.clone();
        std::thread::Builder::new()
            .name("health-evidence-writer".into())
            .spawn(move || {
                let mut current_views = BTreeMap::<String, CurrentView>::new();
                let mut schedule = RetentionSchedule::new(policy);
                loop {
                    schedule.tick(&mut evidence_db, &retention_writer);
                    let command = match erx.recv_timeout(schedule.until_next()) {
                        Ok(command) => command,
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => break,
                    };
                    match command {
                        EvidenceCommand::Insert(value, reply) => {
                            let result = match evidence_db.insert((*value).clone()) {
                                Err(error)
                                    if schedule.recover(
                                        &mut evidence_db,
                                        &retention_writer,
                                        &error,
                                    ) =>
                                {
                                    evidence_db.insert(*value)
                                }
                                other => other,
                            };
                            let _ = reply.send(result);
                        }
                        EvidenceCommand::Diagnostic(batch, _lease, reply) => {
                            let result = match evidence_db.insert_diagnostic(&batch) {
                                Err(error)
                                    if schedule.recover(
                                        &mut evidence_db,
                                        &retention_writer,
                                        &error,
                                    ) =>
                                {
                                    evidence_db.insert_diagnostic(&batch)
                                }
                                other => other,
                            };
                            let _ = reply.send(result);
                        }
                        EvidenceCommand::InsertWitness(
                            value,
                            plan,
                            stamp,
                            _current_slot,
                            reply,
                        ) => {
                            // Duplicate archive ACKs return the original stored body.
                            // Current qualification must use this incoming validated
                            // body, which is bound to the transit digest.
                            let incoming = (*value).clone();
                            let archived = evidence_db.insert_witness(*value, &plan);
                            if archived.is_ok() {
                                // A current refusal cannot erase a valid historical commit.
                                if _current_slot.is_none() {
                                    // Historical-only delivery cannot advance or allocate the
                                    // current-order index. It also cannot leave a matching old
                                    // view qualified without a measured current receipt.
                                    let receipt = &incoming.receipt;
                                    if current_views.get(&receipt.endpoint_id).is_some_and(|view| {
                                        view.observer_epoch == receipt.observer_epoch
                                            && view.source_epoch == receipt.source_epoch
                                    }) {
                                        current_views.remove(&receipt.endpoint_id);
                                        evidence_db
                                            .forget_witness_current_track(&receipt.endpoint_id);
                                    }
                                } else {
                                    let retained_bytes = current_views
                                        .iter()
                                        .map(|(key, view)| key.capacity() + view.charge())
                                        .sum::<usize>();
                                    let same_generation = current_views
                                        .get(&incoming.receipt.endpoint_id)
                                        .is_some_and(|view| {
                                            view.generation == incoming.receipt.generation.0
                                                && view.source_hash == incoming.receipt.source_hash
                                        });
                                    let projected = if same_generation {
                                        0
                                    } else {
                                        projected_current_entry_bytes(&incoming)
                                    };
                                    if !current_admissible(
                                        evidence_db.witness_current_resident_bytes(),
                                        retained_bytes,
                                        projected,
                                    ) {
                                        let receipt = &incoming.receipt;
                                        if current_views.get(&receipt.endpoint_id).is_some_and(
                                            |view| {
                                                view.observer_epoch == receipt.observer_epoch
                                                    && view.source_epoch == receipt.source_epoch
                                            },
                                        ) {
                                            current_views.remove(&receipt.endpoint_id);
                                            evidence_db
                                                .forget_witness_current_track(&receipt.endpoint_id);
                                        }
                                        let _ = reply.send(archived);
                                        continue;
                                    }
                                    let received_at = crate::transit::Stamp::capture();
                                    let elapsed = stamp
                                        .as_ref()
                                        .zip(received_at.as_ref())
                                        .and_then(|(start, end)| start.elapsed_ms_at(end));
                                    match evidence_db.review_witness_current_at(
                                        &incoming,
                                        &plan,
                                        elapsed,
                                        received_at.clone(),
                                    ) {
                                        Ok(qualified) => {
                                            if let Some(candidate) = CurrentView::new(
                                                &incoming,
                                                qualified,
                                                received_at,
                                                elapsed,
                                            ) {
                                                let endpoint = candidate.endpoint.clone();
                                                if let Some(existing) =
                                                    current_views.get_mut(&endpoint)
                                                {
                                                    if existing.generation == candidate.generation
                                                        && existing.source_hash
                                                            == candidate.source_hash
                                                    {
                                                        existing.merge_same_generation(&candidate);
                                                    } else {
                                                        current_views.remove(&endpoint);
                                                    }
                                                }
                                                if !current_views.contains_key(&endpoint) {
                                                    let retained_bytes = current_views
                                                        .iter()
                                                        .map(|(key, view)| {
                                                            key.capacity() + view.charge()
                                                        })
                                                        .sum::<usize>();
                                                    if current_admissible(
                                                        evidence_db
                                                            .witness_current_resident_bytes(),
                                                        retained_bytes,
                                                        endpoint.capacity() + candidate.charge(),
                                                    ) && current_views.len() < 16
                                                    {
                                                        current_views.insert(endpoint, candidate);
                                                    }
                                                }
                                            }
                                            // Compare actual owned capacities after review as
                                            // well as the preflight projection. A rejected
                                            // candidate must not leave a hidden volatile track.
                                            let retained_bytes = current_views
                                                .iter()
                                                .map(|(key, view)| key.capacity() + view.charge())
                                                .sum::<usize>();
                                            if !current_views
                                                .contains_key(&incoming.receipt.endpoint_id)
                                                || !current_admissible(
                                                    evidence_db.witness_current_resident_bytes(),
                                                    retained_bytes,
                                                    0,
                                                )
                                            {
                                                current_views.remove(&incoming.receipt.endpoint_id);
                                                evidence_db.forget_witness_current_track(
                                                    &incoming.receipt.endpoint_id,
                                                );
                                            }
                                        }
                                        Err(error) if error == "WITNESS_CURRENT_CONFLICT" => {
                                            current_views.remove(&incoming.receipt.endpoint_id);
                                        }
                                        Err(_) => {} // An unrelated historical epoch cannot evict current.
                                    }
                                }
                            } else if archived
                                .as_ref()
                                .err()
                                .is_some_and(|e| e == "WITNESS_SOURCE_CONFLICT")
                            {
                                let receipt = &incoming.receipt;
                                if current_views.get(&receipt.endpoint_id).is_some_and(|view| {
                                    view.observer_epoch == receipt.observer_epoch
                                        && view.source_epoch == receipt.source_epoch
                                }) {
                                    current_views.remove(&receipt.endpoint_id);
                                }
                            }
                            let _ = reply.send(archived);
                        }
                        EvidenceCommand::ReadWitness(endpoint, _lease, reply) => {
                            let result = current_views
                                .get(&endpoint)
                                .ok_or_else(|| "witness current view unavailable".to_owned())
                                .and_then(CurrentView::read);
                            let _ = reply.send(result);
                        }
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        let output = cache.clone();
        let quarantines = Arc::new(Mutex::new(std::collections::BTreeMap::<
            (String, String, String),
            Quarantine,
        >::new()));
        let conflicts = quarantines.clone();
        let monitor_epoch = epoch.clone();
        std::thread::Builder::new()
            .name("health-control".into())
            .spawn(move || control_loop(db, engine, rx, output, conflicts, monitor_epoch, started))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            control,
            evidence: evidence_tx,
            cache,
            epoch,
            started,
            ingest: Arc::new(ingest),
            read: Arc::new(read),
            inventory: Arc::new(config.inventory.clone()),
            quarantines,
            witness_plan,
            witness_current_token,
            witness_current_reads: Arc::new(tokio::sync::Semaphore::new(2)),
            witness_current_writes: Arc::new(tokio::sync::Semaphore::new(1)),
            diagnostic_token,
            diagnostic_nodes: Arc::new(diagnostic_nodes),
            diagnostic_budget: Arc::new(crate::diagnostic_ingest::Budget::default()),
            retention,
            notification: Arc::new(Mutex::new(NotificationStatus {
                receiver_configured: config.receiver.is_some(),
                receiver_alias: config.receiver.as_ref().map(|receiver| receiver.alias.clone()),
                deliveries: 0,
                last_delivery_at_ms: None,
            })),
        })
    }
    /// Operator-facing facts beside the rule round: the inventory the doctor
    /// must see covered, quarantines, retention and delivery status.
    fn operator_facts(&self, now_ms: i64) -> Value {
        let inventory = json!({
            "revision": self.inventory.revision,
            "network_id": self.inventory.network_id,
            "targets": self.inventory.targets.iter().map(|target| json!({
                "node": target.node,
                "scope": target.scope,
                "rules": target.rules.iter().map(|rule| rule.id.clone()).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        });
        let quarantined = self.quarantines.lock().map_or_else(
            |_| json!(null),
            |entries| {
                json!(entries
                    .iter()
                    .map(|((node, scope, source), entry)| json!({
                        "node": node, "scope": scope, "source": source,
                        "exhausted": entry.exhausted,
                        "epochs": entry.epochs.iter().map(|(process, source_epoch)| json!({
                            "process_epoch": process, "source_epoch": source_epoch
                        })).collect::<Vec<_>>(),
                    }))
                    .collect::<Vec<_>>())
            },
        );
        let retention =
            self.retention.lock().map_or_else(|_| json!(null), |status| status.json(now_ms));
        let notification =
            self.notification.lock().map_or_else(|_| json!(null), |status| status.json(now_ms));
        json!({
            "inventory": inventory,
            "quarantined_sources": quarantined,
            "retention": retention,
            "notification": notification,
        })
    }
    pub async fn ingest(&self, frame: FactFrame) -> Result<String, String> {
        let admitted = Instant::now();
        frame.validate().map_err(str::to_owned)?;
        // Admission validates against the catalog before any disk write.
        let mut validator = RuleEngine::new((*self.inventory).clone(), 0).map_err(str::to_owned)?;
        validator.ingest(frame.clone(), 0).map_err(str::to_owned)?;
        let (tx, rx) = oneshot::channel();
        self.evidence
            .try_send(EvidenceCommand::Insert(Box::new(evidence(&frame)?), tx))
            .map_err(|_| "evidence queue unavailable")?;
        let result = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .map_err(|_| "evidence deadline")?
            .map_err(|_| "evidence writer stopped")?;
        let row = match result {
            Ok(row) => row,
            Err(error) => {
                if error == "SOURCE_CONFLICT" {
                    if let Ok(mut q) = self.quarantines.lock() {
                        let entry = q
                            .entry((
                                frame.node_id.clone(),
                                frame.scope_id.clone(),
                                frame.source_id.clone(),
                            ))
                            .or_default();
                        let epoch = (frame.process_epoch.clone(), frame.source_epoch.clone());
                        if entry.epochs.len() < 32 || entry.epochs.contains(&epoch) {
                            entry.epochs.insert(epoch);
                        } else {
                            entry.exhausted = true;
                        }
                    }
                }
                return Err(error);
            }
        };
        let (tx, rx) = oneshot::channel();
        self.control
            .try_send(ControlCommand::Ingest(Box::new(frame), Box::new(row.clone()), admitted, tx))
            .map_err(|_| "control queue unavailable")?;
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .map_err(|_| "control deadline")?
            .map_err(|_| "control stopped")??;
        Ok(row.evidence_id)
    }
    pub fn diagnostic_status(&self) -> Value {
        json!({"schema_version":1,"enabled":self.diagnostic_token.is_some(),"source_id":"consensus_diagnostic","budget":self.diagnostic_budget.status()})
    }
    /// Archive a fully validated C02 edge snapshot. This never synthesizes a
    /// health fact: missing, stale or unsupported sources remain unknown to
    /// the rule engine. Each returned reference names a committed evidence row.
    pub async fn archive_snapshot(&self, bytes: &[u8]) -> Result<Vec<EvidenceRow>, String> {
        use tos_health_core::edge_snapshot::{EdgeSnapshot, EdgeSource};
        if bytes.len() > 262_144 {
            return Err("edge body limit".into());
        }
        let snapshot: EdgeSnapshot = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let node = snapshot
            .sources
            .iter()
            .find_map(|source| match source {
                EdgeSource::Native(value) => Some(value.node_id.as_str()),
                EdgeSource::NativeV2(value) => Some(value.node_id.as_str()),
                EdgeSource::NativeV3(value) => Some(value.node_id.as_str()),
                _ => None,
            })
            .ok_or("native source absent")?;
        if !self
            .inventory
            .targets
            .iter()
            .any(|target| target.node == node && target.scope == "node")
        {
            return Err("node outside inventory".into());
        }
        let records =
            crate::collector::decode_records(bytes, node, Some(&self.inventory.network_id))?;
        let mut committed = Vec::with_capacity(records.len());
        for record in records {
            let epoch = record
                .payload
                .get("source")
                .and_then(|source| source.get("source_epoch"))
                .and_then(Value::as_str)
                .ok_or("missing source epoch")?;
            let (tx, rx) = oneshot::channel();
            self.evidence
                .try_send(EvidenceCommand::Insert(
                    Box::new(DurableEvidence { source_epoch: epoch.to_owned(), record }),
                    tx,
                ))
                .map_err(|_| "evidence queue unavailable")?;
            let row = tokio::time::timeout(Duration::from_secs(2), rx)
                .await
                .map_err(|_| "evidence deadline")?
                .map_err(|_| "evidence writer stopped")??;
            committed.push(row);
        }
        Ok(committed)
    }
    /// Separate retained-witness archive; it never enters the health rule
    /// engine as a verified local fact or creates an upstream request.
    pub async fn archive_witness(
        &self,
        endpoint_id: &str,
        bytes: &[u8],
    ) -> Result<WitnessArchiveRow, String> {
        self.archive_witness_with_stamp(endpoint_id, bytes, None).await
    }
    async fn current_witness(
        &self,
        endpoint_id: &str,
    ) -> Result<(Vec<u8>, Arc<tokio::sync::OwnedSemaphorePermit>), String> {
        if self.witness_current_token.is_none()
            || !self
                .witness_plan
                .as_ref()
                .is_some_and(|plan| plan.endpoints.iter().any(|v| v.endpoint_id == endpoint_id))
        {
            return Err("witness current development lane disabled".into());
        }
        read_queued_current(
            &self.evidence,
            &self.witness_current_reads,
            endpoint_id,
            Duration::from_secs(2),
        )
        .await
    }
    async fn archive_witness_with_stamp(
        &self,
        endpoint_id: &str,
        bytes: &[u8],
        stamp: Option<crate::transit::Stamp>,
    ) -> Result<WitnessArchiveRow, String> {
        let plan = self.witness_plan.as_ref().ok_or("witness development plan disabled")?;
        // Current qualification is singleflight through writer completion.
        // Saturation merely drops current timing; historical archive still runs.
        let current_slot = stamp
            .as_ref()
            .and_then(|_| self.witness_current_writes.clone().try_acquire_owned().ok());
        let stamp = stamp.filter(|_| current_slot.is_some());
        let (response, _) = crate::witness::CacheResponse::decode(bytes, plan, endpoint_id)
            .map_err(str::to_owned)?;
        let (tx, rx) = oneshot::channel();
        self.evidence
            .try_send(EvidenceCommand::InsertWitness(
                Box::new(response),
                plan.clone(),
                stamp,
                current_slot,
                tx,
            ))
            .map_err(|_| "evidence queue unavailable")?;
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .map_err(|_| "evidence deadline")?
            .map_err(|_| "evidence writer stopped")?
    }
    pub fn snapshot(&self) -> Result<Value, String> {
        let mut value = {
            let c = self.cache.lock().map_err(|_| "cache unavailable")?;
            if c.failure || c.completed.is_none_or(|t| t.elapsed() > Duration::from_secs(15)) {
                return Err("rule evaluation unavailable".into());
            }
            c.json.clone()
        };
        let facts = self.operator_facts(chrono::Utc::now().timestamp_millis());
        match (value.as_object_mut(), facts.as_object()) {
            (Some(target), Some(facts)) => {
                for (key, item) in facts {
                    target.insert(key.clone(), item.clone());
                }
            }
            _ => return Err("state shape unavailable".into()),
        }
        Ok(value)
    }
    pub fn metrics(&self) -> Result<String, String> {
        let round = {
            let c = self.cache.lock().map_err(|_| "cache unavailable")?;
            if c.failure || c.completed.is_none_or(|t| t.elapsed() > Duration::from_secs(15)) {
                return Err("rule evaluation unavailable".into());
            }
            c.metrics.clone()
        };
        let retention = self
            .retention
            .lock()
            .map_err(|_| "retention status unavailable")?
            .metrics(chrono::Utc::now().timestamp_millis());
        let body = round.strip_suffix("# EOF\n").ok_or("metrics shape unavailable")?;
        Ok(format!("{body}{retention}# EOF\n"))
    }
    pub async fn pending(&self) -> Result<Vec<(i64, String, String)>, String> {
        let (tx, rx) = oneshot::channel();
        self.control.try_send(ControlCommand::Pending(tx)).map_err(|_| "control busy")?;
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .map_err(|_| "control deadline")?
            .map_err(|_| "control stopped")?
    }
    pub async fn due(&self, now_ms: i64) -> Result<Vec<(i64, String, String)>, String> {
        let (tx, rx) = oneshot::channel();
        self.control.try_send(ControlCommand::Due(now_ms, tx)).map_err(|_| "control busy")?;
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .map_err(|_| "control deadline")?
            .map_err(|_| "control stopped")?
    }
    pub async fn begin_attempt(&self, id: i64, alias: &str, now_ms: i64) -> Result<String, String> {
        let (tx, rx) = oneshot::channel();
        self.control
            .try_send(ControlCommand::BeginAttempt(id, alias.into(), now_ms, tx))
            .map_err(|_| "control busy")?;
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .map_err(|_| "control deadline")?
            .map_err(|_| "control stopped")?
    }
    pub async fn delivered(&self, id: i64) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.control.try_send(ControlCommand::Delivered(id, tx)).map_err(|_| "control busy")?;
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .map_err(|_| "control deadline")?
            .map_err(|_| "control stopped")??;
        if let Ok(mut status) = self.notification.lock() {
            status.deliveries = status.deliveries.saturating_add(1);
            status.last_delivery_at_ms = Some(chrono::Utc::now().timestamp_millis());
        }
        Ok(())
    }
}
fn permit(headers: &HeaderMap, token: &[u8], uri: &axum::http::Uri) -> Result<(), StatusCode> {
    if uri.query().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !crate::authorized(headers.get("authorization").and_then(|h| h.to_str().ok()), token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}
async fn ingest(
    State(state): State<Manager>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Json(frame): Json<FactFrame>,
) -> Result<Json<Value>, StatusCode> {
    permit(&headers, &state.ingest, &uri)?;
    let id = state.ingest(frame).await.map_err(|e| {
        if e == "SOURCE_CONFLICT" {
            StatusCode::CONFLICT
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
    })?;
    Ok(Json(json!({"evidence_id":id,"accepted":true})))
}
async fn ingest_diagnostic(
    State(state): State<Manager>,
    request: axum::extract::Request,
) -> Result<Json<crate::diagnostic_ingest::Ack>, StatusCode> {
    let token = state.diagnostic_token.as_deref().ok_or(StatusCode::NOT_FOUND)?;
    permit(request.headers(), token, request.uri())?;
    let mut lease =
        state.diagnostic_budget.acquire_request().map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let bytes = tokio::time::timeout(
        Duration::from_secs(1),
        axum::body::to_bytes(request.into_body(), 262144),
    )
    .await
    .map_err(|_| StatusCode::BAD_REQUEST)?
    .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    let body = bytes.to_vec();
    drop(bytes);
    let batch = tos_health_core::contracts::DiagnosticBatch::decode(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if batch.source_id != "consensus_diagnostic"
        || !state.diagnostic_nodes.contains(&batch.node_id)
        || batch.content_id().map_err(|_| StatusCode::BAD_REQUEST)? != batch.batch_id
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    lease.narrow(body.capacity(), &batch).map_err(|error| {
        if error == "DIAGNOSTIC_BUSY" {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::PAYLOAD_TOO_LARGE
        }
    })?;
    let (tx, rx) = oneshot::channel();
    state
        .evidence
        .try_send(EvidenceCommand::Diagnostic(Box::new(batch), lease, tx))
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let ack = tokio::time::timeout(Duration::from_secs(2), rx)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|error| {
            if error == "SOURCE_CONFLICT" {
                StatusCode::CONFLICT
            } else if error == "DIAGNOSTIC_INVALID" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        })?;
    Ok(Json(ack))
}
async fn diagnostic_status(
    State(state): State<Manager>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, StatusCode> {
    permit(&headers, &state.read, &uri)?;
    Ok(Json(state.diagnostic_status()))
}
async fn archive_snapshot(
    State(state): State<Manager>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    bytes: axum::body::Bytes,
) -> Result<Json<Value>, StatusCode> {
    permit(&headers, &state.ingest, &uri)?;
    let rows = state.archive_snapshot(&bytes).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(
        json!({"accepted":true,"evidence":rows.iter().map(|row| json!({"evidence_id":row.evidence_id,"store_seq":row.store_seq})).collect::<Vec<_>>()}),
    ))
}
async fn archive_witness(
    State(state): State<Manager>,
    Path(endpoint_id): Path<String>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    bytes: axum::body::Bytes,
) -> Result<Json<Value>, StatusCode> {
    permit(&headers, &state.ingest, &uri)?;
    let stamp = state
        .witness_current_token
        .as_ref()
        .and_then(|token| crate::transit::Stamp::from_headers(&headers, &bytes, token));
    let row =
        state.archive_witness_with_stamp(&endpoint_id, &bytes, stamp).await.map_err(|error| {
            if error == "WITNESS_SOURCE_CONFLICT" {
                StatusCode::CONFLICT
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        })?;
    Ok(Json(json!({"accepted":true,"namespace":row.namespace,
        "evidence_id":row.evidence_id,"archive_seq":row.archive_seq})))
}
async fn read_witness_current(
    State(state): State<Manager>,
    Path(endpoint_id): Path<String>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<axum::response::Response, StatusCode> {
    permit(&headers, &state.read, &uri)?;
    match state.current_witness(&endpoint_id).await {
        Ok((bytes, lease)) => axum::response::Response::builder()
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(crate::witness::hold_permit(axum::body::Body::from(bytes), lease))
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE),
        Err(_) => axum::response::Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(br#"{"schema_version":1,"status":"unavailable","production_usable":false,"reason":"current_unavailable"}"#.to_vec()))
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE),
    }
}
async fn snapshot(
    State(state): State<Manager>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, StatusCode> {
    permit(&headers, &state.read, &uri)?;
    state.snapshot().map(Json).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
async fn metrics(
    State(state): State<Manager>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<([(axum::http::header::HeaderName, &'static str); 1], String), StatusCode> {
    permit(&headers, &state.read, &uri)?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        state.metrics().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
    ))
}
async fn heartbeat(
    State(state): State<Manager>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, StatusCode> {
    permit(&headers, &state.read, &uri)?;
    Ok(Json(
        json!({"schema_version":1,"process_epoch":state.epoch,"sequence":(state.started.elapsed().as_secs()/15).to_string()}),
    ))
}
pub fn router(state: Manager) -> Router {
    let writes = Router::new()
        .route(
            "/v1/manager/facts",
            post(ingest).layer(axum::extract::DefaultBodyLimit::max(16_384)),
        )
        .route(
            "/v1/manager/snapshot-evidence",
            post(archive_snapshot).layer(axum::extract::DefaultBodyLimit::max(262_144)),
        )
        .route(
            "/v1/manager/witness-evidence/{endpoint_id}",
            post(archive_witness).layer(axum::extract::DefaultBodyLimit::max(32_768)),
        )
        // Ingest admission: five fact lanes, a collector and a probe per node
        // share this; the single evidence writer behind it stays the real bound.
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(16)),
            crate::limit_requests,
        ));
    let reads = Router::new()
        .route("/v1/manager/state", get(snapshot))
        .route("/v1/manager/diagnostics", get(diagnostic_status))
        .route("/metrics", get(metrics))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(2)),
            crate::limit_requests,
        ));
    let current_reads =
        Router::new().route("/v1/manager/witness-current/{endpoint_id}", get(read_witness_current));
    Router::new()
        .merge(writes)
        .merge(reads)
        .merge(current_reads)
        .route("/v1/ingest/diagnostic-batches", post(ingest_diagnostic))
        .route("/v1/monitor/heartbeat", get(heartbeat))
        .with_state(state)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    accepted: bool,
    idempotency_key: String,
    payload_hash: String,
}
/// Outbox entries remain durable on timeout, wrong receipt or an HTTP-only acknowledgement.
pub async fn deliver_once(
    manager: &Manager,
    client: &reqwest::Client,
    config: &ReceiverConfig,
    token: &str,
) -> Result<usize, String> {
    deliver_once_at(manager, client, config, token, chrono::Utc::now().timestamp_millis()).await
}
/// Explicit clock only for deterministic retry tests; production uses UTC above.
pub async fn deliver_once_at(
    manager: &Manager,
    client: &reqwest::Client,
    config: &ReceiverConfig,
    token: &str,
    now_ms: i64,
) -> Result<usize, String> {
    use sha2::{Digest, Sha256};
    let mut delivered = 0;
    for (id, key, body) in manager.due(now_ms).await?.into_iter().take(4) {
        let committed_hash = manager.begin_attempt(id, &config.alias, now_ms).await?;
        let key = format!(
            "{:x}",
            Sha256::digest(
                format!("health-notification-v1:{}:{key}", manager.inventory.network_id).as_bytes()
            )
        );
        let hash = format!("{:x}", Sha256::digest(body.as_bytes()));
        if hash != committed_hash {
            return Err("outbox payload hash mismatch".into());
        }
        let incident: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        let response=client.post(&config.url).bearer_auth(token).header("Idempotency-Key",&key).json(&json!({"schema_version":1,"network_id":manager.inventory.network_id,"receiver_alias":config.alias,"idempotency_key":key,"payload_hash":hash,"incident":incident})).send().await.map_err(|e|e.to_string())?;
        let bytes = crate::bounded_body(response, 4096).await?;
        let receipt: Receipt =
            serde_json::from_slice(&bytes).map_err(|_| "invalid delivery receipt")?;
        if !receipt.accepted || receipt.idempotency_key != key || receipt.payload_hash != hash {
            return Err("delivery receipt mismatch".into());
        }
        manager.delivered(id).await?;
        delivered += 1;
    }
    Ok(delivered)
}
pub fn prepare_receiver(config: &ReceiverConfig) -> Result<(reqwest::Client, String), String> {
    let url = reqwest::Url::parse(&config.url).map_err(|e| e.to_string())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !crate::alias(&config.alias)
    {
        return Err("invalid receiver endpoint".into());
    }
    let client = crate::client(&config.ca_file, &config.identity_file)?;
    let token = String::from_utf8(crate::secret(&config.token_file)?).map_err(|e| e.to_string())?;
    Ok((client, token))
}
pub async fn notify_loop(
    manager: Manager,
    config: ReceiverConfig,
    client: reqwest::Client,
    token: String,
) -> Result<(), String> {
    let mut timer = tokio::time::interval(Duration::from_secs(15));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        if deliver_once(&manager, &client, &config, &token).await.is_err() {
            eprintln!("health-state notification attempt failed; durable outbox retained");
        }
    }
}
type OutboxRows = Vec<(i64, String, String)>;
#[derive(Default)]
struct Quarantine {
    epochs: std::collections::BTreeSet<(String, String)>,
    exhausted: bool,
}
type Quarantines = Arc<Mutex<std::collections::BTreeMap<(String, String, String), Quarantine>>>;
fn control_loop(
    mut db: ControlDb,
    mut engine: RuleEngine,
    rx: std::sync::mpsc::Receiver<ControlCommand>,
    output: Arc<Mutex<Cached>>,
    conflicts: Quarantines,
    epoch: String,
    started: Instant,
) {
    let mut due = Instant::now();
    loop {
        if Instant::now() >= due {
            due = Instant::now() + Duration::from_secs(5);
            let now = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            if let Ok(entries) = conflicts.lock() {
                for ((node, scope, source), entry) in entries.iter() {
                    if entry.exhausted {
                        engine.quarantine_source(node, scope, source);
                    }
                    for (process, source_epoch) in &entry.epochs {
                        engine.quarantine(node, scope, source, process, source_epoch);
                    }
                }
            }
            let results = engine.evaluate(now);
            let updates = results
                .iter()
                .map(|r| ControlUpdate {
                    key: RuleKey {
                        node: r.node.clone(),
                        scope: r.scope.clone(),
                        rule: r.rule.clone(),
                    },
                    signal: match r.signal {
                        Signal::Bad => Evaluation::Bad { severity: r.severity.clone() },
                        Signal::Good => Evaluation::Good { samples: r.samples.clone() },
                        Signal::Unknown => Evaluation::Unknown,
                    },
                    required: r.required.clone(),
                    hold: r.recovery_ms,
                })
                .collect();
            let evaluated = db
                .evaluate_round(updates, now)
                .and_then(|_| Ok((db.all_states()?, db.sequence()?)));
            match evaluated {
                Ok((states, sequence)) => {
                    let mut metrics=format!("# HELP tos_health_evaluation_sequence Completed persisted rule rounds.\n# TYPE tos_health_evaluation_sequence gauge\ntos_health_evaluation_sequence{{monitor_epoch=\"{epoch}\"}} {sequence}\n");
                    let (mut active_metrics, mut usable_metrics) = (String::new(), String::new());
                    let mut incidents = Vec::new();
                    for (key, state) in states {
                        let signal = results
                            .iter()
                            .find(|r| {
                                r.node == key.node && r.scope == key.scope && r.rule == key.rule
                            })
                            .map(|r| r.signal)
                            .unwrap_or(Signal::Unknown);
                        active_metrics.push_str(&format!("tos_health_incident_active{{node=\"{}\",scope=\"{}\",rule=\"{}\",severity=\"{}\"}} {}\n",key.node,key.scope,key.rule,state.severity,u8::from(state.active())));
                        usable_metrics.push_str(&format!("tos_health_rule_input_usable{{node=\"{}\",scope=\"{}\",rule=\"{}\"}} {}\n",key.node,key.scope,key.rule,u8::from(signal!=Signal::Unknown)));
                        incidents.push(json!({"key":key,"state":state,"input":signal}));
                    }
                    metrics.push_str("# HELP tos_health_incident_active Persisted unresolved incident; only the health-state transition closes it.\n# TYPE tos_health_incident_active gauge\n");
                    metrics.push_str(&active_metrics);
                    metrics.push_str("# HELP tos_health_rule_input_usable Complete current rule input is usable.\n# TYPE tos_health_rule_input_usable gauge\n");
                    metrics.push_str(&usable_metrics);
                    metrics.push_str("# EOF\n");
                    let response = json!({"schema_version":1,"monitor_epoch":epoch,"evaluation_sequence":sequence.to_string(),"incidents":incidents});
                    if let Ok(mut c) = output.lock() {
                        c.json = response;
                        c.metrics = metrics;
                        c.completed = Some(Instant::now());
                        c.failure = false;
                    }
                }
                Err(_) => {
                    if let Ok(mut c) = output.lock() {
                        c.failure = true;
                    }
                }
            }
        }
        match rx.recv_timeout(due.saturating_duration_since(Instant::now())) {
            Ok(ControlCommand::Ingest(frame, row, admitted, reply)) => {
                let now = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                let result = with_queue_age(*frame, admitted.elapsed()).and_then(|frame| {
                    let accepted = engine.ingest(frame.clone(), now).map_err(str::to_owned)?;
                    if accepted {
                        if let Err(error) = db.record_source_ref(&frame, &row) {
                            engine.quarantine_source(
                                &frame.node_id,
                                &frame.scope_id,
                                &frame.source_id,
                            );
                            if let Ok(mut cached) = output.lock() {
                                cached.failure = true;
                            }
                            return Err(error);
                        }
                    }
                    Ok(accepted)
                });
                let _ = reply.send(result);
            }
            Ok(ControlCommand::Pending(reply)) => {
                let _ = reply.send(db.pending());
            }
            Ok(ControlCommand::Due(now_ms, reply)) => {
                let _ = reply.send(db.due(now_ms));
            }
            Ok(ControlCommand::BeginAttempt(id, alias, now_ms, reply)) => {
                let _ = reply.send(db.begin_attempt(id, &alias, now_ms));
            }
            Ok(ControlCommand::Delivered(id, reply)) => {
                let _ = reply.send(db.delivered(id));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}
