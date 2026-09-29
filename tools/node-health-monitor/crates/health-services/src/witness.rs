//! C05 isolated observer cache slice. GET never polls a source or changes its age.
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, OriginalUri, Path, Request, State},
    http::{header::CONTENT_TYPE, HeaderMap, Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
    routing::get,
    Router,
};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path as FsPath,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tos_health_core::{
    wire::U64,
    witness::{
        canonical_plan_hash, canonical_source_hash, ClockQuality, NetworkObservation, Plan,
        ReportedMembership, ReportedProof, Role, Source, MAX_BODY, MAX_CACHE_RESIDENT,
        MAX_ENDPOINTS, MAX_INFLIGHT, MAX_RETAINED_PER_ENDPOINT, USABLE_AGE_MS,
    },
};
const MAX_ARCHIVE_BODY: usize = 32_768;
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheReceipt {
    pub schema_version: u32,
    pub observer_id: String,
    pub observer_epoch: String,
    pub plan_revision: String,
    pub plan_hash: String,
    pub endpoint_id: String,
    pub source_epoch: String,
    pub generation: U64,
    pub source_hash: String,
    pub raw_transport_hash: String,
    pub observer_clock_quality: ClockQuality,
    pub first_received_at: String,
    pub request_duration_ms: U64,
    /// Exact upstream JSON bytes encoded as a JSON string; its hash is over these bytes.
    pub source_json: String,
}
type CachedSnapshot = (CacheReceipt, u64, Vec<RowAge>);
pub fn archive_evidence_id(receipt: &CacheReceipt) -> Result<String, &'static str> {
    let bytes = serde_json::to_vec(&(
        &receipt.observer_epoch,
        &receipt.endpoint_id,
        &receipt.source_epoch,
        receipt.generation,
        &receipt.source_hash,
    ))
    .map_err(|_| "witness archive identity failed")?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}
struct Entry {
    receipt: CacheReceipt,
    received: Instant,
    rows: BTreeMap<String, RowTrack>,
}
#[derive(Clone)]
struct RowTrack {
    identity_hash: String,
    first_received: Instant,
    first_received_at: String,
    observer_clock_quality_at_first_receipt: ClockQuality,
    age_at_receipt_ms: Option<u64>,
}
#[derive(Clone, Default)]
struct CacheInner {
    entries: BTreeMap<String, VecDeque<Arc<Entry>>>,
    // One bounded lineage slot per planned endpoint/target, retained across
    // partial generations that omit that row.
    row_history: BTreeMap<(String, String), RowTrack>,
    quarantined: BTreeSet<String>,
}
fn accounted_bytes(plan: &Plan, token: &Vec<u8>, inner: &CacheInner) -> usize {
    // Charge capacities, container payloads, a per-node allocator margin and
    // the four concurrent parse/body reservations before admitting a sample.
    let mut charged = std::mem::size_of::<Plan>()
        + std::mem::size_of::<CacheInner>()
        + token.capacity()
        + 128
        + MAX_INFLIGHT * (5 * MAX_BODY + 4096)
        + 4 * (MAX_ARCHIVE_BODY + MAX_BODY + 4096)
        + 16 * 512;
    charged += plan.profile.capacity()
        + plan.revision.capacity()
        + plan.observer_id.capacity()
        + plan.observer_epoch.capacity()
        + plan.network_id.capacity()
        + plan.genesis.capacity()
        + plan.endpoints.capacity() * std::mem::size_of::<tos_health_core::witness::Endpoint>()
        + plan.targets.capacity() * std::mem::size_of::<tos_health_core::witness::Target>();
    for endpoint in &plan.endpoints {
        charged += endpoint.endpoint_id.capacity()
            + endpoint.fixed_url.capacity()
            + endpoint.failure_domain.capacity()
            + endpoint.kind.capacity()
            + endpoint.current_source_epoch.capacity()
            + 128;
    }
    for target in &plan.targets {
        charged += target.target_id.capacity()
            + target.node_id.capacity()
            + target.valid_from.capacity()
            + target.valid_until.capacity()
            + target.scope_id.capacity()
            + target.endpoint_ids.capacity() * std::mem::size_of::<String>()
            + target.endpoint_ids.iter().map(String::capacity).sum::<usize>()
            + 128;
    }
    for (endpoint, entries) in &inner.entries {
        charged += endpoint.capacity()
            + std::mem::size_of::<VecDeque<Arc<Entry>>>()
            + 2 * entries.capacity() * std::mem::size_of::<Arc<Entry>>()
            + 256;
        for entry in entries {
            let receipt = &entry.receipt;
            charged += std::mem::size_of::<Entry>()
                + std::mem::size_of::<CacheReceipt>()
                + receipt.source_json.capacity()
                + receipt.observer_id.capacity()
                + receipt.observer_epoch.capacity()
                + receipt.plan_revision.capacity()
                + receipt.plan_hash.capacity()
                + receipt.endpoint_id.capacity()
                + receipt.source_epoch.capacity()
                + receipt.source_hash.capacity()
                + receipt.raw_transport_hash.capacity()
                + receipt.first_received_at.capacity()
                + 256;
            for (target, row) in &entry.rows {
                charged += target.capacity()
                    + std::mem::size_of::<RowTrack>()
                    + row.identity_hash.capacity()
                    + row.first_received_at.capacity()
                    + 128;
            }
        }
    }
    for ((endpoint, target), row) in &inner.row_history {
        charged += 2
            * (endpoint.capacity()
                + target.capacity()
                + std::mem::size_of::<RowTrack>()
                + row.identity_hash.capacity()
                + row.first_received_at.capacity()
                + 128);
    }
    for endpoint in &inner.quarantined {
        charged += endpoint.capacity() + 128;
    }
    charged
}
#[derive(Clone)]
pub struct WitnessCache {
    plan: Arc<Plan>,
    token: Arc<Vec<u8>>,
    inner: Arc<Mutex<CacheInner>>,
    round_busy: Arc<AtomicBool>,
    round_pending: Arc<Mutex<BTreeSet<String>>>,
    local_slots: Arc<tokio::sync::Semaphore>,
    observer_clock_quality: ClockQuality,
}
impl WitnessCache {
    pub fn new(plan: Plan, token: Vec<u8>) -> Result<Self, &'static str> {
        Self::with_clock_quality(plan, token, ClockQuality::Unknown)
    }
    /// Synthetic fixture only. A production caller cannot assert clock quality
    /// until an independent local clock-quality source is validated.
    pub fn new_synthetic_valid_clock_fixture(
        plan: Plan,
        token: Vec<u8>,
    ) -> Result<Self, &'static str> {
        Self::with_clock_quality(plan, token, ClockQuality::Valid)
    }
    fn with_clock_quality(
        plan: Plan,
        token: Vec<u8>,
        quality: ClockQuality,
    ) -> Result<Self, &'static str> {
        plan.validate()?;
        if !(32..=4096).contains(&token.len()) {
            return Err("invalid witness cache token length");
        }
        if accounted_bytes(&plan, &token, &CacheInner::default()) > MAX_CACHE_RESIDENT {
            return Err("witness initial resident capacity");
        }
        Ok(Self {
            plan: Arc::new(plan),
            token: Arc::new(token),
            inner: Arc::new(Mutex::new(CacheInner::default())),
            round_busy: Arc::new(AtomicBool::new(false)),
            round_pending: Arc::new(Mutex::new(BTreeSet::new())),
            local_slots: Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT)),
            observer_clock_quality: quality,
        })
    }
    pub fn mark_timeout(&self, endpoint_id: &str) -> Result<(), &'static str> {
        if !self.plan.endpoints.iter().any(|e| e.endpoint_id == endpoint_id) {
            return Err("unapproved witness endpoint");
        }
        self.inner
            .lock()
            .map_err(|_| "witness cache unavailable")?
            .quarantined
            .insert(endpoint_id.to_owned());
        Ok(())
    }
    pub fn local_requests_inflight(&self) -> usize {
        MAX_INFLIGHT - self.local_slots.available_permits()
    }
    fn polling_allowed(&self, endpoint_id: &str) -> bool {
        self.inner.lock().is_ok_and(|inner| !inner.quarantined.contains(endpoint_id))
    }
    /// Called only by the fixed scheduler after a bounded response, never by a read handler.
    pub fn admit(
        &self,
        endpoint_id: &str,
        bytes: &[u8],
        request_duration_ms: u64,
    ) -> Result<bool, &'static str> {
        if bytes.len() > MAX_BODY || request_duration_ms > 3_000 {
            return Err("witness response exceeds local boundary");
        }
        let source = Source::decode(bytes, &self.plan, endpoint_id)?;
        let raw = std::str::from_utf8(bytes).map_err(|_| "witness response is not UTF-8")?;
        let source_hash = canonical_source_hash(&source)?;
        let raw_transport_hash = format!("{:x}", Sha256::digest(bytes));
        let mut inner = self.inner.lock().map_err(|_| "witness cache unavailable")?;
        if inner.quarantined.contains(endpoint_id) {
            return Err("witness endpoint quarantined");
        }
        if let Some(previous) = inner.entries.get(endpoint_id).and_then(VecDeque::back) {
            if previous.receipt.source_epoch != source.source_epoch {
                // A source-epoch transition needs a reviewed plan/observer epoch change.
                inner.quarantined.insert(endpoint_id.to_owned());
                return Err("unapproved witness source epoch");
            }
            if source.generation.0 < previous.receipt.generation.0 {
                return Err("regressed witness generation");
            }
            if source.generation.0 == previous.receipt.generation.0 {
                if source_hash == previous.receipt.source_hash {
                    return Ok(false);
                }
                inner.quarantined.insert(endpoint_id.to_owned());
                return Err("conflicted witness generation");
            }
        }
        if inner.entries.len() >= MAX_ENDPOINTS && !inner.entries.contains_key(endpoint_id) {
            return Err("witness cache capacity");
        }
        let now = Instant::now();
        let received_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut rows = BTreeMap::new();
        for row in &source.rows {
            let identity = serde_json::to_vec(&(&row.target_id, &row.observed_at, &row.anchor))
                .map_err(|_| "witness row identity failed")?;
            let identity_hash = format!("{:x}", Sha256::digest(&identity));
            let key = (endpoint_id.to_owned(), row.target_id.clone());
            let old = inner.row_history.get(&key);
            let track = if let Some(old) = old.filter(|old| old.identity_hash == identity_hash) {
                let mut retained = old.clone();
                retained.age_at_receipt_ms = match (
                    retained.age_at_receipt_ms,
                    row.source_age_ms.and_then(|age| age.0.checked_add(request_duration_ms)),
                ) {
                    (Some(previous), Some(reported)) => {
                        let elapsed =
                            retained.first_received.elapsed().as_millis().min(u128::from(u64::MAX))
                                as u64;
                        Some(previous.max(reported.saturating_sub(elapsed)))
                    }
                    _ => None,
                };
                retained
            } else {
                RowTrack {
                    identity_hash,
                    first_received: now,
                    first_received_at: received_at.clone(),
                    observer_clock_quality_at_first_receipt: self.observer_clock_quality,
                    age_at_receipt_ms: row
                        .source_age_ms
                        .and_then(|age| age.0.checked_add(request_duration_ms)),
                }
            };
            rows.insert(row.target_id.clone(), track);
        }
        let receipt = CacheReceipt {
            schema_version: 1,
            observer_id: self.plan.observer_id.clone(),
            observer_epoch: self.plan.observer_epoch.clone(),
            plan_revision: self.plan.revision.clone(),
            plan_hash: canonical_plan_hash(&self.plan)?,
            endpoint_id: endpoint_id.to_owned(),
            source_epoch: source.source_epoch,
            generation: source.generation,
            source_hash,
            raw_transport_hash,
            observer_clock_quality: self.observer_clock_quality,
            first_received_at: received_at,
            request_duration_ms: U64(request_duration_ms),
            source_json: raw.to_owned(),
        };
        let trial = CacheResponse {
            receipt: receipt.clone(),
            observer_elapsed_ms: U64(0),
            row_ages: age_rows(&rows),
        };
        if serde_json::to_vec(&trial).map_err(|_| "witness cache serialization failed")?.len()
            > MAX_ARCHIVE_BODY
        {
            return Err("witness cache response overflow");
        }
        let mut next = inner.clone();
        for (target, track) in &rows {
            next.row_history.insert((endpoint_id.to_owned(), target.clone()), track.clone());
        }
        let retained = next.entries.entry(endpoint_id.to_owned()).or_default();
        retained.push_back(Arc::new(Entry { receipt, received: now, rows }));
        if retained.len() > MAX_RETAINED_PER_ENDPOINT {
            retained.pop_front();
        }
        if accounted_bytes(&self.plan, &self.token, &next) > MAX_CACHE_RESIDENT {
            return Err("witness resident cache capacity");
        }
        *inner = next;
        Ok(true)
    }
    pub fn cached(&self, endpoint_id: &str) -> Result<Option<CachedSnapshot>, &'static str> {
        if !self.plan.endpoints.iter().any(|e| e.endpoint_id == endpoint_id) {
            return Err("unapproved witness endpoint");
        }
        let inner = self.inner.lock().map_err(|_| "witness cache unavailable")?;
        if inner.quarantined.contains(endpoint_id) {
            return Err("witness endpoint quarantined");
        }
        Ok(inner.entries.get(endpoint_id).and_then(VecDeque::back).map(|entry| {
            let elapsed = entry.received.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            let ages = age_rows(&entry.rows);
            (entry.receipt.clone(), elapsed, ages)
        }))
    }
    pub fn retained_generations(&self, endpoint_id: &str) -> Result<Vec<u64>, &'static str> {
        if !self.plan.endpoints.iter().any(|e| e.endpoint_id == endpoint_id) {
            return Err("unapproved witness endpoint");
        }
        let inner = self.inner.lock().map_err(|_| "witness cache unavailable")?;
        Ok(inner
            .entries
            .get(endpoint_id)
            .map(|entries| entries.iter().map(|entry| entry.receipt.generation.0).collect())
            .unwrap_or_default())
    }
}
fn age_rows(rows: &BTreeMap<String, RowTrack>) -> Vec<RowAge> {
    rows.iter()
        .map(|(target_id, track)| {
            let effective = track.age_at_receipt_ms.and_then(|age| {
                age.checked_add(
                    track.first_received.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                )
            });
            RowAge {
                target_id: target_id.clone(),
                first_received_at: track.first_received_at.clone(),
                observer_clock_quality_at_first_receipt: track
                    .observer_clock_quality_at_first_receipt,
                source_age_at_first_receipt_ms: track.age_at_receipt_ms.map(U64),
                effective_age_ms: effective.map(U64),
                fresh_relative_age: effective.is_some_and(|age| age <= USABLE_AGE_MS),
            }
        })
        .collect()
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RoundSummary {
    pub attempted: usize,
    pub skipped_local_busy: usize,
    pub admitted: usize,
    pub duplicate: usize,
    pub refused: usize,
    pub timed_out_or_uncertain: usize,
}
/// O can construct this only from the standard pinned mTLS/no-redirect client.
#[derive(Clone)]
pub struct WitnessClient(reqwest::Client);
impl WitnessClient {
    pub fn new(ca_file: &FsPath, identity_file: &FsPath) -> Result<Self, String> {
        crate::client(ca_file, identity_file).map(Self)
    }
}
struct RoundGuard(WitnessCache);
impl Drop for RoundGuard {
    fn drop(&mut self) {
        if let (Ok(mut pending), Ok(mut inner)) = (self.0.round_pending.lock(), self.0.inner.lock())
        {
            for id in pending.iter() {
                inner.quarantined.insert(id.clone());
            }
            pending.clear();
        }
        self.0.round_busy.store(false, Ordering::Release);
    }
}
/// Fixed-plan, cache-only GET round. Cancellation is a local cost boundary,
/// never a statement that an upstream server stopped working.
pub async fn poll_round(
    cache: WitnessCache,
    client: &WitnessClient,
) -> Result<RoundSummary, &'static str> {
    if cache.round_busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
    {
        return Err("witness round already active");
    }
    let _guard = RoundGuard(cache.clone());
    let mut summary = RoundSummary::default();
    for chunk in cache.plan.endpoints.chunks(MAX_INFLIGHT) {
        let mut tasks = tokio::task::JoinSet::new();
        for endpoint in chunk {
            if !cache.polling_allowed(&endpoint.endpoint_id) {
                continue;
            }
            let Ok(slot) = cache.local_slots.clone().try_acquire_owned() else {
                summary.skipped_local_busy += 1;
                continue;
            };
            summary.attempted += 1;
            let client = client.0.clone();
            let url = endpoint.fixed_url.clone();
            let id = endpoint.endpoint_id.clone();
            cache.round_pending.lock().map_err(|_| "witness round unavailable")?.insert(id.clone());
            tasks.spawn(async move {
                let _slot = slot;
                let started = Instant::now();
                let result = tokio::time::timeout(Duration::from_secs(3), async {
                    let response = client.get(&url).send().await.map_err(|error| {
                        eprintln!("witness transport error endpoint={id}: {error:?}");
                        "witness transport error"
                    })?;
                    if !response.status().is_success() {
                        return Err("witness upstream refused");
                    }
                    crate::bounded_body(response, MAX_BODY)
                        .await
                        .map_err(|_| "witness body refused")
                })
                .await;
                let elapsed = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                (id, result, elapsed)
            });
        }
        while let Some(result) = tasks.join_next().await {
            let (id, outcome, elapsed) = result.map_err(|_| "witness poll task failed")?;
            cache.round_pending.lock().map_err(|_| "witness round unavailable")?.remove(&id);
            match outcome {
                Ok(Ok(bytes)) => match cache.admit(&id, &bytes, elapsed) {
                    Ok(true) => summary.admitted += 1,
                    Ok(false) => summary.duplicate += 1,
                    Err(_) => summary.refused += 1,
                },
                Ok(Err(_)) => {
                    // The request may have reached the peer; do not retry until review.
                    cache.mark_timeout(&id)?;
                    summary.timed_out_or_uncertain += 1;
                }
                Err(_) => {
                    cache.mark_timeout(&id)?;
                    summary.timed_out_or_uncertain += 1;
                }
            }
        }
    }
    Ok(summary)
}
/// Fixed phase schedule: a round finishing after a missed boundary waits for
/// the next future boundary instead of immediately collecting again.
pub fn next_fixed_due_ms(elapsed_ms: u64) -> Result<u64, &'static str> {
    elapsed_ms
        .checked_div(15_000)
        .and_then(|slot| slot.checked_add(1))
        .and_then(|slot| slot.checked_mul(15_000))
        .ok_or("witness schedule overflow")
}
/// Development-only O source owner. Production activation/restore is not
/// supported until a real endpoint adapter and quarantine lifecycle are proven.
pub async fn run_fixed(cache: WitnessCache, client: WitnessClient) -> Result<(), &'static str> {
    let origin = tokio::time::Instant::now();
    let mut due = origin;
    loop {
        tokio::time::sleep_until(due).await;
        let summary = poll_round(cache.clone(), &client).await?;
        if summary.refused != 0 || summary.timed_out_or_uncertain != 0 {
            eprintln!(
                "witness development round incomplete refused={} uncertain={}",
                summary.refused, summary.timed_out_or_uncertain
            );
        }
        let elapsed_ms =
            u64::try_from(origin.elapsed().as_millis()).map_err(|_| "witness schedule overflow")?;
        due = origin
            .checked_add(Duration::from_millis(next_fixed_due_ms(elapsed_ms)?))
            .ok_or("witness schedule overflow")?;
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowAge {
    pub target_id: String,
    pub first_received_at: String,
    pub observer_clock_quality_at_first_receipt: ClockQuality,
    #[serde(deserialize_with = "required_nullable")]
    pub source_age_at_first_receipt_ms: Option<U64>,
    #[serde(deserialize_with = "required_nullable")]
    pub effective_age_ms: Option<U64>,
    /// Only a relative-age statement; not source coverage, role validity or proof.
    pub fresh_relative_age: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheResponse {
    pub receipt: CacheReceipt,
    pub observer_elapsed_ms: U64,
    pub row_ages: Vec<RowAge>,
}
impl CacheResponse {
    pub fn decode(
        bytes: &[u8],
        plan: &Plan,
        endpoint_id: &str,
    ) -> Result<(Self, Source), &'static str> {
        let valid_utc = |value: &str| {
            value.len() <= 40
                && value.ends_with('Z')
                && tos_health_core::query::utc_ms(value).is_ok()
        };
        if bytes.len() > MAX_ARCHIVE_BODY {
            return Err("witness archive body overflow");
        }
        let response: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid witness cache response")?;
        let receipt = &response.receipt;
        if receipt.schema_version != 1
            || receipt.observer_id != plan.observer_id
            || receipt.observer_epoch != plan.observer_epoch
            || receipt.plan_revision != plan.revision
            || receipt.plan_hash != canonical_plan_hash(plan)?
            || receipt.endpoint_id != endpoint_id
            || !tos_health_core::wire::hash(&receipt.source_hash)
            || !tos_health_core::wire::hash(&receipt.raw_transport_hash)
            || !valid_utc(&receipt.first_received_at)
            || receipt.request_duration_ms.0 > 3_000
            || receipt.source_json.len() > MAX_BODY
        {
            return Err("invalid witness cache identity");
        }
        let raw = receipt.source_json.as_bytes();
        if format!("{:x}", Sha256::digest(raw)) != receipt.raw_transport_hash {
            return Err("witness raw digest mismatch");
        }
        let source = Source::decode(raw, plan, endpoint_id)?;
        if source.source_epoch != receipt.source_epoch
            || source.generation != receipt.generation
            || canonical_source_hash(&source)? != receipt.source_hash
            || response.row_ages.len() != source.rows.len()
        {
            return Err("witness source identity mismatch");
        }
        let mut seen = BTreeSet::new();
        for age in &response.row_ages {
            let row = source
                .rows
                .iter()
                .find(|row| row.target_id == age.target_id)
                .ok_or("unknown witness row age target")?;
            let reported = row
                .source_age_ms
                .map(|value| value.0)
                .and_then(|value| value.checked_add(receipt.request_duration_ms.0))
                .and_then(|value| value.checked_add(response.observer_elapsed_ms.0));
            let historical = age
                .source_age_at_first_receipt_ms
                .map(|value| value.0)
                .and_then(|value| value.checked_add(response.observer_elapsed_ms.0));
            if !seen.insert(age.target_id.as_str())
                || !valid_utc(&age.first_received_at)
                || age.source_age_at_first_receipt_ms.is_none() && age.effective_age_ms.is_some()
                || age.effective_age_ms.is_some_and(|value| {
                    age.source_age_at_first_receipt_ms.is_some_and(|base| value.0 < base.0)
                })
                || match (reported, age.effective_age_ms) {
                    (Some(minimum), Some(actual)) => actual.0 < minimum,
                    (_, None) => false,
                    _ => true,
                }
                || match (historical, age.effective_age_ms) {
                    (Some(minimum), Some(actual)) => actual.0 < minimum,
                    (_, None) => false,
                    _ => true,
                }
                || age.fresh_relative_age
                    != age.effective_age_ms.is_some_and(|v| v.0 <= USABLE_AGE_MS)
            {
                return Err("invalid witness row age");
            }
        }
        Ok((response, source))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelativeAge {
    Fresh,
    Stale,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteClock {
    Compatible,
    Future,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleAtObserverReceipt {
    Normal,
    ProbeOnly,
    NonVoting,
    OutsideWindow,
    Unknown,
}
#[derive(Debug, Clone, Serialize)]
pub struct RowQualification {
    pub target_id: String,
    pub relative_age: RelativeAge,
    pub remote_clock: RemoteClock,
    /// Observer local receipt-window context, never proof of role at remote observation.
    pub role_at_observer_receipt: RoleAtObserverReceipt,
    pub reported_network_observation: NetworkObservation,
    pub reported_certificate_membership: ReportedMembership,
    pub reported_proof: ReportedProof,
    pub private_vote_visibility: NetworkObservation,
    pub local_action: &'static str,
    pub local_persistence: &'static str,
    pub verified_finality: bool,
    pub node_fault_from_witness_alone: bool,
}
/// Qualification uses relative age plus extra measured M transport/queue/elapsed time.
/// It never treats remote wall time, a reported quorum, or archive ACK as proof.
pub fn qualify_row_from_wire(
    bytes: &[u8],
    plan: &Plan,
    endpoint_id: &str,
    target_id: &str,
    extra_elapsed_ms: Option<u64>,
) -> Result<RowQualification, &'static str> {
    let (response, source) = CacheResponse::decode(bytes, plan, endpoint_id)?;
    qualify_validated_row(&response, &source, plan, target_id, extra_elapsed_ms)
}
pub(crate) fn qualify_validated_row(
    response: &CacheResponse,
    source: &Source,
    plan: &Plan,
    target_id: &str,
    extra_elapsed_ms: Option<u64>,
) -> Result<RowQualification, &'static str> {
    let row = source
        .rows
        .iter()
        .find(|row| row.target_id == target_id)
        .ok_or("unknown witness target row")?;
    let age = response
        .row_ages
        .iter()
        .find(|age| age.target_id == target_id)
        .ok_or("missing witness row age")?;
    let target = plan
        .targets_for(&source.endpoint_id)
        .find(|target| target.target_id == target_id)
        .ok_or("unapproved witness target")?;
    let relative_age = match (age.effective_age_ms, extra_elapsed_ms) {
        (Some(value), Some(extra)) => match value.0.checked_add(extra) {
            Some(total) if total <= USABLE_AGE_MS => RelativeAge::Fresh,
            Some(_) => RelativeAge::Stale,
            None => RelativeAge::Unknown,
        },
        _ => RelativeAge::Unknown,
    };
    let receipt_ms = tos_health_core::query::utc_ms(&age.first_received_at)
        .map_err(|_| "invalid observer receipt UTC")?;
    let remote_clock = if age.observer_clock_quality_at_first_receipt == ClockQuality::Valid
        && source.clock_quality == ClockQuality::Valid
    {
        match &row.observed_at {
            Some(remote) => {
                let remote_ms =
                    tos_health_core::query::utc_ms(remote).map_err(|_| "invalid remote UTC")?;
                if remote_ms > receipt_ms.saturating_add(i64::from(plan.clock_skew_allowance_ms)) {
                    RemoteClock::Future
                } else {
                    RemoteClock::Compatible
                }
            }
            None => RemoteClock::Unknown,
        }
    } else {
        RemoteClock::Unknown
    };
    let from =
        tos_health_core::query::utc_ms(&target.valid_from).map_err(|_| "invalid role UTC")?;
    let until =
        tos_health_core::query::utc_ms(&target.valid_until).map_err(|_| "invalid role UTC")?;
    let role_at_observer_receipt =
        if age.observer_clock_quality_at_first_receipt != ClockQuality::Valid {
            RoleAtObserverReceipt::Unknown
        } else if receipt_ms < from || receipt_ms >= until {
            RoleAtObserverReceipt::OutsideWindow
        } else {
            match target.role {
                Role::Normal => RoleAtObserverReceipt::Normal,
                Role::ProbeOnly => RoleAtObserverReceipt::ProbeOnly,
                Role::NonVoting => RoleAtObserverReceipt::NonVoting,
            }
        };
    Ok(RowQualification {
        target_id: target_id.to_owned(),
        relative_age,
        remote_clock,
        role_at_observer_receipt,
        reported_network_observation: row.network_observation,
        reported_certificate_membership: row.reported_certificate_membership,
        reported_proof: row.reported_proof,
        private_vote_visibility: row.private_vote_visibility,
        local_action: "unknown",
        local_persistence: "unknown",
        verified_finality: false,
        node_fault_from_witness_alone: false,
    })
}
async fn read_cache(
    State(state): State<WitnessCache>,
    Path(endpoint_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response<Body>, StatusCode> {
    if !crate::authorized(headers.get("authorization").and_then(|v| v.to_str().ok()), &state.token)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if uri.query().is_some() || !body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let result = state.cached(&endpoint_id).map_err(|reason| {
        if reason == "unapproved witness endpoint" {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
    })?;
    let (receipt, elapsed, row_ages) = result.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let output =
        serde_json::to_vec(&CacheResponse { receipt, observer_elapsed_ms: U64(elapsed), row_ages })
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if output.len() > MAX_ARCHIVE_BODY {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(output))
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
pub fn router(state: WitnessCache) -> Router {
    Router::new()
        .route("/v1/witness/cache/{endpoint_id}", get(read_cache))
        .layer(DefaultBodyLimit::max(0))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(4)),
            limit_cache_reads,
        ))
        .with_state(state)
}
struct PermitBody {
    inner: Pin<Box<Body>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl HttpBody for PermitBody {
    type Data = Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.inner.as_mut().poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
async fn limit_cache_reads(
    State(limit): State<Arc<tokio::sync::Semaphore>>,
    request: Request,
    next: Next,
) -> axum::response::Response {
    let Ok(permit) = limit.try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    next.run(request)
        .await
        .map(|body| Body::new(PermitBody { inner: Box::pin(body), _permit: permit }))
}
