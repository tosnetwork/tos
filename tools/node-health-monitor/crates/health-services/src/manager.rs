//! Independent control/evidence owners; handlers never execute database work.
use crate::durable::{
    ControlDb, ControlUpdate, DurableEvidence, Evaluation, EvidenceDb, EvidenceRow, RuleKey,
    WitnessArchiveRow,
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
    Insert(DurableEvidence, oneshot::Sender<Result<EvidenceRow, String>>),
    InsertWitness(
        Box<crate::witness::CacheResponse>,
        Arc<tos_health_core::witness::Plan>,
        oneshot::Sender<Result<WitnessArchiveRow, String>>,
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
                while let Ok(command) = erx.recv() {
                    match command {
                        EvidenceCommand::Insert(value, reply) => {
                            let _ = reply.send(evidence_db.insert(value));
                        }
                        EvidenceCommand::InsertWitness(value, plan, reply) => {
                            let _ = reply.send(evidence_db.insert_witness(*value, &plan));
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
            .try_send(EvidenceCommand::Insert(evidence(&frame)?, tx))
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
                    DurableEvidence { source_epoch: epoch.to_owned(), record },
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
        let plan = self.witness_plan.as_ref().ok_or("witness development plan disabled")?;
        let (response, _) = crate::witness::CacheResponse::decode(bytes, plan, endpoint_id)
            .map_err(str::to_owned)?;
        let (tx, rx) = oneshot::channel();
        self.evidence
            .try_send(EvidenceCommand::InsertWitness(Box::new(response), plan.clone(), tx))
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
    let row = state.archive_witness(&endpoint_id, &bytes).await.map_err(|error| {
        if error == "WITNESS_SOURCE_CONFLICT" {
            StatusCode::CONFLICT
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
    })?;
    Ok(Json(json!({"accepted":true,"namespace":row.namespace,
        "evidence_id":row.evidence_id,"archive_seq":row.archive_seq})))
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
    Router::new()
        .merge(writes)
        .merge(reads)
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
