//! Independent control/evidence owners; handlers never execute database work.
use crate::durable::{
    ControlDb, ControlUpdate, DurableEvidence, Evaluation, EvidenceDb, EvidenceRow, RuleKey,
    WitnessArchiveRow,
};
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
// Writer decode/qualification and two body-lifetime read permits are reserved
// before retained admission. Raw Source is archived on disk, not held here.
const CURRENT_SCRATCH_RESERVE: usize = 8 * 32_768;

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
    InsertWitness(
        Box<crate::witness::CacheResponse>,
        Arc<tos_health_core::witness::Plan>,
        Option<crate::transit::Stamp>,
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
                    | ("pq_signing_failure", "native_core") => {}
                    _ => return Err(format!("rule adapter unavailable: {}", rule.id)),
                }
            }
        }
        if same_database(&config.control_db, &config.evidence_db)? {
            return Err("control and evidence must be separate databases".into());
        }
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
        std::thread::Builder::new()
            .name("health-evidence-writer".into())
            .spawn(move || {
                let mut current_views = BTreeMap::<String, CurrentView>::new();
                while let Ok(command) = erx.recv() {
                    match command {
                        EvidenceCommand::Insert(value, reply) => {
                            let _ = reply.send(evidence_db.insert(*value));
                        }
                        EvidenceCommand::InsertWitness(value, plan, stamp, reply) => {
                            // Duplicate archive ACKs return the original stored body.
                            // Current qualification must use this incoming validated
                            // body, which is bound to the transit digest.
                            let incoming = (*value).clone();
                            let archived = evidence_db.insert_witness(*value, &plan);
                            if archived.is_ok() {
                                // A current refusal cannot erase a valid historical commit.
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
                                            if let Some(existing) = current_views.get_mut(&endpoint)
                                            {
                                                if existing.generation == candidate.generation
                                                    && existing.source_hash == candidate.source_hash
                                                {
                                                    existing.merge_same_generation(&candidate);
                                                } else {
                                                    current_views.remove(&endpoint);
                                                }
                                            }
                                            if !current_views.contains_key(&endpoint) {
                                                let charged = CURRENT_SCRATCH_RESERVE
                                                    + evidence_db.witness_current_resident_bytes()
                                                    + current_views
                                                        .iter()
                                                        .map(|(key, view)| {
                                                            key.capacity() + view.charge()
                                                        })
                                                        .sum::<usize>()
                                                    + endpoint.capacity()
                                                    + candidate.charge();
                                                if charged <= MAX_CURRENT_VIEW_BYTES
                                                    && current_views.len() < 16
                                                {
                                                    current_views.insert(endpoint, candidate);
                                                }
                                            }
                                        }
                                    }
                                    Err(error) if error == "WITNESS_CURRENT_CONFLICT" => {
                                        current_views.remove(&incoming.receipt.endpoint_id);
                                    }
                                    Err(_) => {} // An unrelated historical epoch cannot evict current.
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
        let lease = Arc::new(
            self.witness_current_reads
                .clone()
                .try_acquire_owned()
                .map_err(|_| "witness current read busy")?,
        );
        let (tx, rx) = oneshot::channel();
        self.evidence
            .try_send(EvidenceCommand::ReadWitness(endpoint_id.to_owned(), lease.clone(), tx))
            .map_err(|_| "evidence queue unavailable")?;
        let bytes = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .map_err(|_| "evidence deadline")?
            .map_err(|_| "evidence writer stopped")??;
        Ok((bytes, lease))
    }
    async fn archive_witness_with_stamp(
        &self,
        endpoint_id: &str,
        bytes: &[u8],
        stamp: Option<crate::transit::Stamp>,
    ) -> Result<WitnessArchiveRow, String> {
        let plan = self.witness_plan.as_ref().ok_or("witness development plan disabled")?;
        let (response, _) = crate::witness::CacheResponse::decode(bytes, plan, endpoint_id)
            .map_err(str::to_owned)?;
        let (tx, rx) = oneshot::channel();
        self.evidence
            .try_send(EvidenceCommand::InsertWitness(Box::new(response), plan.clone(), stamp, tx))
            .map_err(|_| "evidence queue unavailable")?;
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .map_err(|_| "evidence deadline")?
            .map_err(|_| "evidence writer stopped")?
    }
    pub fn snapshot(&self) -> Result<Value, String> {
        let c = self.cache.lock().map_err(|_| "cache unavailable")?;
        if c.failure || c.completed.is_none_or(|t| t.elapsed() > Duration::from_secs(15)) {
            return Err("rule evaluation unavailable".into());
        }
        Ok(c.json.clone())
    }
    pub fn metrics(&self) -> Result<String, String> {
        let c = self.cache.lock().map_err(|_| "cache unavailable")?;
        if c.failure || c.completed.is_none_or(|t| t.elapsed() > Duration::from_secs(15)) {
            return Err("rule evaluation unavailable".into());
        }
        Ok(c.metrics.clone())
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
            .map_err(|_| "control stopped")?
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
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(4)),
            crate::limit_requests,
        ));
    let reads = Router::new()
        .route("/v1/manager/state", get(snapshot))
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
