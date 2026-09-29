use crate::authorized;
use axum::{
    body::Body,
    extract::{OriginalUri, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tos_health_core::{
    edge_snapshot::{
        CapabilitySource, CapabilityValue, EdgeCapabilities, EdgeHeartbeat, HeartbeatSource,
        NamedCapability,
    },
    evidence::Evidence,
    source::{Availability, Coverage, SourceQuality},
    wire::U64,
};

struct Bucket {
    at: Instant,
    tokens: u32,
}
impl Bucket {
    fn new() -> Self {
        Self { at: Instant::now(), tokens: 4 }
    }
    fn take(&mut self, heartbeat: bool) -> bool {
        let elapsed = self.at.elapsed().as_secs();
        if elapsed > 0 {
            self.tokens = self.tokens.saturating_add(elapsed.min(4) as u32).min(4);
            self.at += Duration::from_secs(elapsed);
        }
        // One token remains available to either approved heartbeat route.
        if self.tokens <= u32::from(!heartbeat) {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[derive(Clone)]
pub struct EdgeState {
    pub token: Arc<Vec<u8>>,
    pub node: String,
    pub cache: Arc<Mutex<Option<Evidence>>>,
    pub native: Arc<Mutex<crate::native_cache::NativeCache>>,
    pub cgroup: Arc<Mutex<CgroupCache>>,
    cgroup_config: Arc<Mutex<Option<CgroupConfig>>>,
    cgroup_status: Arc<Mutex<String>>,
    pub started: Instant,
    pub source_epoch: Option<String>,
    pub diagnostic_stats:Arc<crate::diagnostic_relay::Stats>,
    limiter: Arc<Mutex<Bucket>>,
}
impl EdgeState {
    pub fn new(node: String, token: Vec<u8>) -> Self {
        Self {
            node,
            token: Arc::new(token),
            cache: Arc::new(Mutex::new(None)),
            native: crate::native_cache::cache(),
            cgroup: Arc::new(Mutex::new(CgroupCache::default())),
            cgroup_config: Arc::new(Mutex::new(None)),
            cgroup_status: Arc::new(Mutex::new("disabled".into())),
            started: Instant::now(),
            source_epoch: crate::random_token().ok().map(|bytes| crate::hex(&bytes)),
            diagnostic_stats:Arc::new(crate::diagnostic_relay::Stats::default()),
            limiter: Arc::new(Mutex::new(Bucket::new())),
        }
    }
    pub fn configure_cgroup(&self, config: CgroupConfig) -> Result<(), String> {
        let mut slot = self.cgroup_config.lock().map_err(|_| "cgroup config unavailable")?;
        if slot.is_some() {
            return Err("cgroup source already configured".into());
        }
        *slot = Some(config);
        *self.cgroup_status.lock().map_err(|_| "cgroup status unavailable")? = "unknown".into();
        Ok(())
    }
    pub fn record_cgroup_discovery_error(&self, reason: &str) -> Result<(), String> {
        let status = if reason.contains("cgroup v2 unavailable") { "unsupported" } else { "error" };
        *self.cgroup_status.lock().map_err(|_| "cgroup status unavailable")? = status.into();
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CgroupConfig {
    root: PathBuf,
    relative: PathBuf,
}
impl CgroupConfig {
    pub fn new(root: PathBuf, relative: PathBuf) -> Result<Self, String> {
        let depth = relative.components().count();
        if !root.is_absolute()
            || relative.is_absolute()
            || relative.as_os_str().is_empty()
            || depth > 16
            || relative.components().any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err("invalid cgroup inventory".into());
        }
        Ok(Self { root, relative })
    }
    pub fn discover(pid: u32) -> Result<Self, String> {
        Self::discover_from(Path::new("/proc"), PathBuf::from("/sys/fs/cgroup"), pid)
    }
    pub fn discover_from(proc_root: &Path, cgroup_root: PathBuf, pid: u32) -> Result<Self, String> {
        if pid == 0 {
            return Err("invalid process inventory".into());
        }
        let value = bounded_read(&proc_root.join(pid.to_string()).join("cgroup"), 4096)?;
        let mut unified = value.lines().filter_map(|line| line.strip_prefix("0::/"));
        let relative = PathBuf::from(unified.next().ok_or("cgroup v2 unavailable")?);
        if unified.next().is_some() {
            return Err("ambiguous cgroup v2 inventory".into());
        }
        let config = Self::new(cgroup_root, relative)?;
        config.require_effective_quotas()?;
        Ok(config)
    }
    fn levels(&self) -> Result<Vec<PathBuf>, String> {
        let root = std::fs::canonicalize(&self.root).map_err(|e| e.to_string())?;
        let mut levels = vec![root.clone()];
        let mut current = root.clone();
        for part in self.relative.components() {
            current.push(part.as_os_str());
            let level = std::fs::canonicalize(&current).map_err(|e| e.to_string())?;
            if !level.starts_with(&root) {
                return Err("cgroup path escaped root".into());
            }
            levels.push(level.clone());
            current = level;
        }
        Ok(levels)
    }
    fn effective_quotas(&self) -> Result<(u64, u64, u64, PathBuf), String> {
        let levels = self.levels()?;
        let leaf = levels.last().cloned().ok_or("cgroup hierarchy unavailable")?;
        let mut memory: Option<u64> = None;
        let mut cpu: Option<(u64, u64)> = None;
        // The cgroup-v2 mount root has no parent and commonly omits controller
        // quota files. Descendant cgroups must expose both fixed controller files.
        for level in levels.into_iter().skip(1) {
            for name in ["memory.max", "cpu.max"] {
                let meta =
                    std::fs::symlink_metadata(level.join(name)).map_err(|e| e.to_string())?;
                if !meta.file_type().is_file() || meta.file_type().is_symlink() {
                    return Err("cgroup quota source is not a fixed regular file".into());
                }
            }
            if let Some(limit) = cgroup_limit(&level.join("memory.max"))? {
                memory = Some(memory.map_or(limit, |old| old.min(limit)));
            }
            if let Some(candidate) = cgroup_cpu_limit(&level.join("cpu.max"))? {
                cpu = Some(match cpu {
                    Some(old)
                        if u128::from(old.0) * u128::from(candidate.1)
                            <= u128::from(candidate.0) * u128::from(old.1) =>
                    {
                        old
                    }
                    _ => candidate,
                });
            }
        }
        let memory = memory.ok_or("effective memory quota unavailable")?;
        let (quota, period) = cpu.ok_or("effective CPU quota unavailable")?;
        Ok((memory, quota, period, leaf))
    }
    fn require_effective_quotas(&self) -> Result<(), String> {
        self.effective_quotas().map(|_| ())
    }
}

#[derive(Debug, Default)]
pub struct CgroupCache {
    value: Option<(tos_health_core::edge_snapshot::CgroupEnvelope, Instant)>,
}
impl CgroupCache {
    pub fn publish(&mut self, value: tos_health_core::edge_snapshot::CgroupEnvelope) {
        self.value = Some((value, Instant::now()));
    }
    pub fn read(&self) -> Option<tos_health_core::edge_snapshot::CgroupEnvelope> {
        let (value, accepted) = self.value.as_ref()?;
        let mut value = value.clone();
        value.source_age_ms = value
            .source_age_ms?
            .checked_add(accepted.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
        (value.source_age_ms? <= 30_000).then_some(value)
    }
    pub fn age_ms(&self) -> Option<u64> {
        let (value, accepted) = self.value.as_ref()?;
        value
            .source_age_ms?
            .checked_add(accepted.elapsed().as_millis().min(u128::from(u64::MAX)) as u64)
    }
}
fn permit(state: &EdgeState, headers: &HeaderMap, uri: &axum::http::Uri) -> Result<(), StatusCode> {
    if uri.query().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !authorized(headers.get("authorization").and_then(|h| h.to_str().ok()), &state.token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut limiter = state.limiter.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !limiter.take(uri.path() == "/v1/edge/heartbeat") {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(())
}
fn bounded_json<T: Serialize>(value: &T, max: usize) -> Result<Response, StatusCode> {
    let body = serde_json::to_vec(value).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if body.len() > max {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
fn catalog_digest() -> &'static str {
    static DIGEST: OnceLock<String> = OnceLock::new();
    DIGEST.get_or_init(|| {
        format!("{:x}", Sha256::digest(include_bytes!("../../../contracts/source-manifest.json")))
    })
}
async fn heartbeat(
    State(state): State<EdgeState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, StatusCode> {
    permit(&state, &headers, &uri)?;
    let now = chrono::Utc::now().timestamp_millis();
    let cache = state.cache.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let process_age = cache
        .as_ref()
        .and_then(|sample| now.checked_sub(sample.observed_at_ms))
        .and_then(|age| u64::try_from(age).ok());
    let process_usable =
        cache.as_ref().is_some_and(|sample| sample.quality.usable(now, 30_000, false));
    let validator_epoch = cache.as_ref().map(|sample| sample.process_epoch.clone());
    drop(cache);
    let native = state.native.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let native_age = native.age_ms();
    let native_usable = native.usable();
    drop(native);
    let cgroup = state.cgroup.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let cgroup_age = cgroup.age_ms();
    let cgroup_usable = cgroup.read().is_some();
    let value = EdgeHeartbeat {
        schema_version: 1,
        node_id: state.node.clone(),
        edge_epoch: state.source_epoch.clone().ok_or(StatusCode::SERVICE_UNAVAILABLE)?,
        state: "available".into(),
        // Optional and higher-cost sources remain disabled, so the edge starts conservatively guarded.
        guard: "guarded".into(),
        validator_epoch,
        sources: vec![
            HeartbeatSource {
                source_id: "process".into(),
                age_ms: process_age.map(U64),
                usable: process_usable,
            },
            HeartbeatSource {
                source_id: "native_core".into(),
                age_ms: native_age.map(U64),
                usable: native_usable,
            },
            HeartbeatSource {
                source_id: "host_cgroup".into(),
                age_ms: cgroup_age.map(U64),
                usable: cgroup_usable,
            },
        ],
    };
    bounded_json(&value, 4096)
}
async fn snapshot(
    State(state): State<EdgeState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, StatusCode> {
    permit(&state, &headers, &uri)?;
    let value = r4_snapshot(&state).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    bounded_json(&value, 262_144)
}
async fn capabilities(
    State(state): State<EdgeState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, StatusCode> {
    permit(&state, &headers, &uri)?;
    let now = chrono::Utc::now().timestamp_millis();
    let process = state
        .cache
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .as_ref()
        .is_some_and(|sample| sample.quality.usable(now, 30_000, false));
    let native = state.native.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let native_enabled = native.configured();
    let native_available = native.usable();
    drop(native);
    let cgroup_enabled =
        state.cgroup_config.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?.is_some();
    let cgroup_status =
        state.cgroup_status.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?.clone();
    let cgroup_available =
        state.cgroup.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?.read().is_some();
    let capability = |supported, enabled, contract_valid| CapabilityValue {
        supported,
        enabled,
        contract_valid,
        performance_gate: "not_run".into(),
    };
    let value = EdgeCapabilities {
        schema_version: 1,
        node_id: state.node.clone(),
        catalog_digest: catalog_digest().into(),
        capabilities: vec![
            NamedCapability { name: "basic_edge".into(), value: capability(true, true, true) },
            NamedCapability {
                name: "native_core".into(),
                value: capability(true, native_enabled, true),
            },
            NamedCapability {
                name: "host_cgroup".into(),
                value: capability(true, cgroup_enabled, true),
            },
            NamedCapability { name: "readiness".into(), value: capability(false, false, false) },
            NamedCapability {
                name: "validator_stats".into(),
                value: capability(false, false, false),
            },
        ],
        sources: vec![
            CapabilitySource {
                source_id: "process".into(),
                status: if process { "available" } else { "unknown" }.into(),
            },
            CapabilitySource {
                source_id: "native_core".into(),
                status: if native_available {
                    "available"
                } else if native_enabled {
                    "unknown"
                } else {
                    "disabled"
                }
                .into(),
            },
            CapabilitySource {
                source_id: "host_cgroup".into(),
                status: if cgroup_available {
                    "available"
                } else if cgroup_enabled {
                    "unknown"
                } else {
                    &cgroup_status
                }
                .into(),
            },
            CapabilitySource { source_id: "readiness".into(), status: "unsupported".into() },
            CapabilitySource { source_id: "validator_stats".into(), status: "disabled".into() },
        ],
    };
    bounded_json(&value, 32_768)
}
async fn metrics(
    State(state): State<EdgeState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<([(axum::http::header::HeaderName, &'static str); 1], String), StatusCode> {
    permit(&state, &headers, &uri)?;
    let body = state
        .native
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .read()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        body,
    ))
}
pub fn router(state: EdgeState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/v1/edge/heartbeat", get(heartbeat))
        .route("/v1/edge/snapshot", get(snapshot))
        .route("/v1/edge/capabilities", get(capabilities))
        .route("/v1/edge/diagnostics",get(diagnostics))
        .layer(axum::extract::DefaultBodyLimit::max(4096))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(8)),
            crate::limit_requests,
        ))
        .with_state(state)
}
async fn diagnostics(State(state):State<EdgeState>,headers:HeaderMap,OriginalUri(uri):OriginalUri)
    ->Result<Response,StatusCode> {
    permit(&state,&headers,&uri)?;
    bounded_json(&state.diagnostic_stats.snapshot(),4096)
}
fn bounded_read(path: &Path, limit: u64) -> Result<String, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("local source too large".into());
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}
pub(crate) fn process_epoch_from(proc_root: &Path, pid: u32) -> Result<String, String> {
    let stat = bounded_read(&proc_root.join(pid.to_string()).join("stat"), 16_384)?;
    let start = stat
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .ok_or("missing process start")?
        .parse::<u64>()
        .map_err(|_| "invalid process start")?;
    let boot = bounded_read(&proc_root.join("sys/kernel/random/boot_id"), 128)?;
    let boot = boot.trim();
    if boot.is_empty() || boot.len() > 64 {
        return Err("invalid boot identity".into());
    }
    Ok(format!("{boot}:{pid}:{start}"))
}
pub fn sample_process(node: &str, pid: u32, sequence: u64) -> Result<Evidence, String> {
    sample_process_from(node, pid, sequence, Path::new("/proc"))
}
pub fn sample_process_from(
    node: &str,
    pid: u32,
    sequence: u64,
    proc_root: &Path,
) -> Result<Evidence, String> {
    if pid == 0 || !crate::alias(node) {
        return Err("invalid process inventory".into());
    }
    let directory = proc_root.join(pid.to_string());
    let stat = bounded_read(&directory.join("stat"), 16_384)?;
    let fields: Vec<_> =
        stat.rsplit_once(')').ok_or("malformed process stat")?.1.split_whitespace().collect();
    let start = fields
        .get(19)
        .ok_or("missing process start")?
        .parse::<u64>()
        .map_err(|_| "invalid process start")?;
    let epoch = process_epoch_from(proc_root, pid)?;
    let status = bounded_read(&directory.join("status"), 65_536)?;
    let mut values = BTreeMap::new();
    for line in status.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if ["VmRSS", "RssAnon", "RssFile", "VmSwap"].contains(&key) {
                let mut words = value.split_whitespace();
                let count = words
                    .next()
                    .ok_or("missing value")?
                    .parse::<u64>()
                    .map_err(|_| "invalid memory value")?;
                if words.next() != Some("kB") {
                    return Err("unknown memory unit".into());
                }
                values.insert(
                    key.to_owned(),
                    count.checked_mul(1024).ok_or("memory overflow")?.to_string(),
                );
            }
        }
    }
    // Detect PID reuse between the two fixed reads.
    let second = bounded_read(&directory.join("stat"), 16_384)?;
    if second
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|v| v.parse::<u64>().ok())
        != Some(start)
    {
        return Err("process epoch changed during sample".into());
    }
    let at = chrono::Utc::now().timestamp_millis();
    Ok(Evidence {
        node_id: node.into(),
        scope_id: "node".into(),
        source_id: "collector".into(),
        source_record_id: sequence.to_string(),
        process_epoch: epoch.clone(),
        observed_at_ms: at,
        received_at_ms: at,
        quality: SourceQuality {
            availability: Availability::Available,
            coverage: Coverage::Partial,
            observed_at_ms: Some(at),
            last_success_at_ms: Some(at),
            clock_valid: true,
            process_epoch: epoch,
            source_sequence: sequence.to_string(),
        },
        payload: json!({"component":"process","pid":pid,"memory_bytes":values,"cpu_user_ticks":fields.get(11),"cpu_system_ticks":fields.get(12),"missing_fields":["host_pressure","cgroup_effective","fd_usage","validator_core"]}),
        redacted: true,
    })
}
fn exact_file_u64(path: &Path) -> Result<u64, String> {
    let value = bounded_read(path, 4096)?;
    let value = value.trim();
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("invalid cgroup integer".into());
    }
    value.parse::<u64>().map_err(|_| "cgroup integer overflow".into())
}
fn cgroup_limit(path: &Path) -> Result<Option<u64>, String> {
    let value = bounded_read(path, 4096)?;
    let value = value.trim();
    if value == "max" {
        return Ok(None);
    }
    let value = exact_file_u64(path)?;
    (value != 0).then_some(value).map(Some).ok_or_else(|| "invalid cgroup limit".into())
}
fn cgroup_cpu_limit(path: &Path) -> Result<Option<(u64, u64)>, String> {
    let value = bounded_read(path, 4096)?;
    let fields: Vec<_> = value.split_whitespace().collect();
    if fields.len() != 2 {
        return Err("invalid CPU quota".into());
    }
    let period = fields[1].parse::<u64>().map_err(|_| "invalid CPU period")?;
    if period == 0 || (fields[1].len() > 1 && fields[1].starts_with('0')) {
        return Err("invalid CPU period".into());
    }
    if fields[0] == "max" {
        return Ok(None);
    }
    let quota = fields[0].parse::<u64>().map_err(|_| "invalid CPU quota")?;
    if quota == 0 || (fields[0].len() > 1 && fields[0].starts_with('0')) {
        return Err("invalid CPU quota".into());
    }
    Ok(Some((quota, period)))
}
fn keyed_u64(path: &Path, key: &str) -> Result<u64, String> {
    let value = bounded_read(path, 4096)?;
    let mut found = None;
    for line in value.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else { continue };
        let Some(raw) = fields.next() else { return Err("malformed cgroup keyed value".into()) };
        if fields.next().is_some() {
            return Err("malformed cgroup keyed value".into());
        }
        if name == key {
            if found.is_some() {
                return Err("duplicate cgroup keyed value".into());
            }
            found = Some(raw);
        }
    }
    let raw = found.ok_or_else(|| format!("missing cgroup {key}"))?;
    if raw.is_empty()
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("invalid cgroup keyed integer".into());
    }
    raw.parse::<u64>().map_err(|_| "cgroup keyed integer overflow".into())
}
pub fn sample_cgroup(
    node: &str,
    process_epoch: &str,
    edge_epoch: &str,
    generation: u64,
    config: &CgroupConfig,
) -> Result<tos_health_core::edge_snapshot::CgroupEnvelope, String> {
    use tos_health_core::{
        edge_snapshot::CgroupPayload,
        native::{canonical_hash, Coverage as NativeCoverage, Quality, SourceEnvelope},
    };
    if !crate::alias(node)
        || process_epoch.is_empty()
        || process_epoch.len() > 128
        || edge_epoch.is_empty()
        || edge_epoch.len() > 128
        || generation == 0
    {
        return Err("invalid cgroup source identity".into());
    }
    let (memory_max, cpu_quota, cpu_period, directory) = config.effective_quotas()?;
    for name in ["memory.current", "cpu.stat", "memory.events"] {
        let meta = std::fs::symlink_metadata(directory.join(name)).map_err(|e| e.to_string())?;
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            return Err("cgroup source is not a fixed regular file".into());
        }
    }
    let memory_current = exact_file_u64(&directory.join("memory.current"))?;
    let cpu_usage = keyed_u64(&directory.join("cpu.stat"), "usage_usec")?;
    let oom = keyed_u64(&directory.join("memory.events"), "oom")?;
    let payload = CgroupPayload {
        kind: "host_cgroup".into(),
        memory_current_bytes: U64(memory_current),
        memory_max_bytes: U64(memory_max),
        cpu_usage_usec: U64(cpu_usage),
        cpu_quota_usec: U64(cpu_quota),
        cpu_period_usec: U64(cpu_period),
        oom_events: U64(oom),
    };
    let at = chrono::Utc::now();
    let timestamp = at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    Ok(SourceEnvelope {
        schema_version: 1,
        source_id: "host_cgroup".into(),
        node_id: node.into(),
        scope_id: "node".into(),
        process_epoch: process_epoch.into(),
        source_epoch: edge_epoch.into(),
        source_version: "cgroup-v2-effective-v1".into(),
        generation: U64(generation),
        availability: "available".into(),
        observed_at: Some(timestamp.clone()),
        last_success_at: Some(timestamp),
        received_at: None,
        source_age_ms: Some(0),
        clock_quality: "valid".into(),
        coverage: NativeCoverage {
            status: "partial".into(),
            missing_fields: vec!["host_pressure".into(), "io_pressure".into(), "fd_usage".into()],
            gaps: vec![],
            sampling_policy: "fixed_cgroup_v2_15s".into(),
        },
        content_hash: canonical_hash(&payload)?,
        payload,
        quality: Quality {
            instrumentation_complete: true,
            producer_dropped: U64(0),
            relay_dropped: U64(0),
            parse_errors: U64(0),
            shed_reason: None,
        },
    })
}
pub async fn sample_loop(state: EdgeState, pid: u32) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sequence = 0u64;
    loop {
        interval.tick().await;
        let Some(next) = sequence.checked_add(1) else {
            return;
        };
        sequence = next;
        let node = state.node.clone();
        // One blocking task is awaited to actual completion; no timeout creates a replacement.
        let result =
            tokio::task::spawn_blocking(move || sample_process(&node, pid, sequence)).await;
        if let Ok(Ok(sample)) = result {
            let config = state.cgroup_config.lock().ok().and_then(|slot| slot.clone());
            if let (Some(config), Some(edge_epoch)) = (config, state.source_epoch.as_deref()) {
                if let Ok(value) =
                    sample_cgroup(&state.node, &sample.process_epoch, edge_epoch, sequence, &config)
                {
                    if process_epoch_from(Path::new("/proc"), pid).as_deref()
                        == Ok(sample.process_epoch.as_str())
                    {
                        if let Ok(mut cache) = state.cgroup.lock() {
                            cache.publish(value);
                        }
                    }
                }
            }
            if let Ok(mut cache) = state.cache.lock() {
                *cache = Some(sample);
            }
        }
    }
}

pub fn r4_snapshot(state: &EdgeState) -> Result<Value, String> {
    use tos_health_core::{
        edge_snapshot::{EdgeSnapshot, EdgeSource, ProcessPayload},
        native::{canonical_hash, Coverage as NativeCoverage, Quality, SourceEnvelope},
        wire::{exact_u64, U64},
    };
    let mut sources = Vec::new();
    let mut process_epoch = None;
    let now = chrono::Utc::now().timestamp_millis();
    {
        let cache = state.cache.lock().map_err(|_| "process cache unavailable")?;
        if let Some(e) = cache.as_ref().filter(|e| e.quality.usable(now, 30_000, false)) {
            process_epoch = Some(e.process_epoch.clone());
            let scalar = |v: &Value| -> Result<Option<U64>, String> {
                v.as_str().map(|v| exact_u64(v).map(U64).map_err(str::to_owned)).transpose()
            };
            let payload = ProcessPayload {
                kind: "process".into(),
                pid: e.payload["pid"]
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("invalid pid")?,
                rss_bytes: scalar(&e.payload["memory_bytes"]["VmRSS"])?,
                anon_bytes: scalar(&e.payload["memory_bytes"]["RssAnon"])?,
                file_bytes: scalar(&e.payload["memory_bytes"]["RssFile"])?,
                swap_bytes: scalar(&e.payload["memory_bytes"]["VmSwap"])?,
                cpu_user_ticks: scalar(&e.payload["cpu_user_ticks"])?,
                cpu_system_ticks: scalar(&e.payload["cpu_system_ticks"])?,
            };
            let observed = chrono::DateTime::from_timestamp_millis(e.observed_at_ms)
                .ok_or("invalid observation time")?
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let age = now
                .checked_sub(e.observed_at_ms)
                .and_then(|v| u64::try_from(v).ok())
                .ok_or("invalid process age")?;
            sources.push(EdgeSource::Process(SourceEnvelope {
                schema_version: 1,
                source_id: "process".into(),
                node_id: state.node.clone(),
                scope_id: "node".into(),
                process_epoch: e.process_epoch.clone(),
                source_epoch: state.source_epoch.clone().ok_or("edge epoch unavailable")?,
                source_version: "proc-v1".into(),
                generation: U64(exact_u64(&e.source_record_id).map_err(str::to_owned)?),
                availability: "available".into(),
                observed_at: Some(observed.clone()),
                last_success_at: Some(observed),
                received_at: None,
                source_age_ms: Some(age),
                clock_quality: "valid".into(),
                coverage: NativeCoverage {
                    status: "partial".into(),
                    missing_fields: vec![
                        "host_pressure".into(),
                        "cgroup_effective".into(),
                        "fd_usage".into(),
                    ],
                    gaps: vec![],
                    sampling_policy: "fixed_15s".into(),
                },
                content_hash: canonical_hash(&payload)?,
                payload,
                quality: Quality {
                    instrumentation_complete: false,
                    producer_dropped: U64(0),
                    relay_dropped: U64(0),
                    parse_errors: U64(0),
                    shed_reason: None,
                },
            }));
        }
    }
    if !sources.iter().any(|source| matches!(source, EdgeSource::Process(_))) {
        return Err("required process sample unavailable".into());
    }
    let cache = state.native.lock().map_err(|_| "native cache unavailable")?;
    let network = cache.network.clone().ok_or("native network not configured")?;
    let native = cache.read_record().ok_or("required native sample unavailable")?;
    let process_epoch = process_epoch.as_deref().ok_or("required process epoch unavailable")?;
    let binding = cache.read_binding().ok_or("required native process binding unavailable")?;
    if binding.process_epoch != process_epoch || binding.native_epoch != native.process_epoch() {
        return Err("native process binding mismatch".into());
    }
    // No source I/O on HTTP: the scheduled sampler alone verifies actual PID,
    // executable and listener ownership before/after its paired native read.
    sources.push(match native {
        tos_health_core::native::NativeRecord::V1(v) => EdgeSource::Native(v),
        tos_health_core::native::NativeRecord::V2(v) => EdgeSource::NativeV2(v),
    });
    drop(cache);
    let cgroup_required =
        state.cgroup_config.lock().map_err(|_| "cgroup config unavailable")?.is_some();
    let cgroup = state.cgroup.lock().map_err(|_| "cgroup cache unavailable")?.read();
    if cgroup_required && cgroup.is_none() {
        return Err("required cgroup sample unavailable".into());
    }
    if let Some(value) = cgroup {
        if value.process_epoch != process_epoch {
            return Err("cgroup process epoch mismatch".into());
        }
        sources.push(EdgeSource::Cgroup(value));
    }
    if state
        .cache
        .lock()
        .map_err(|_| "process cache unavailable")?
        .as_ref()
        .is_none_or(|sample| sample.process_epoch != process_epoch)
    {
        return Err("process epoch changed during edge snapshot".into());
    }
    let snapshot = EdgeSnapshot {
        schema_version: 1,
        status: "partial".into(),
        sources,
        anchors: vec![],
        native_process_binding: binding,
    };
    snapshot.validate(&state.node, &network)?;
    serde_json::to_value(snapshot).map_err(|e| e.to_string())
}
