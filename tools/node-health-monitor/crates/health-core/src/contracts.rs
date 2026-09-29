use crate::wire::{DiagnosticRecord, U64};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticItem {
    pub sequence: U64,
    pub monotonic_ns: U64,
    pub observed_at: Option<String>,
    pub record_type: u16,
    pub payload: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticQuality {
    pub dropped: U64,
    pub gaps: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticBatch {
    pub schema_version: u32,
    pub node_id: String,
    pub edge_epoch: String,
    pub process_epoch: String,
    pub source_id: String,
    pub batch_id: String,
    pub records: Vec<DiagnosticItem>,
    pub quality: DiagnosticQuality,
}
impl DiagnosticBatch {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > 262_144 {
            return Err("JSON body limit");
        }
        let batch: Self = serde_json::from_slice(bytes).map_err(|_| "invalid batch JSON")?;
        if batch.schema_version != 1
            || !crate::wire::alias(&batch.node_id)
            || !crate::wire::alias(&batch.source_id)
            || !crate::wire::hash(&batch.batch_id)
            || [&batch.edge_epoch, &batch.process_epoch]
                .iter()
                .any(|v| v.is_empty() || v.len() > 128)
            || batch.records.is_empty()
            || batch.records.len() > 128
        {
            return Err("invalid batch metadata");
        }
        let mut total = 0usize;
        let mut previous = None;
        for r in &batch.records {
            if r.payload.len() % 2 != 0
                || !r.payload.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("invalid payload encoding");
            }
            total = total.checked_add(r.payload.len() / 2).ok_or("payload overflow")?;
            if total > 65_536 {
                return Err("decoded payload limit");
            }
        }
        for r in &batch.records {
            if r.record_type != 1 || r.payload.len() != 4 {
                return Err("unsupported diagnostic catalog");
            }
            if previous.is_some_and(|s| r.sequence.0 <= s) {
                return Err("non-increasing sequence");
            }
            previous = Some(r.sequence.0);
            if r.observed_at.as_ref().is_some_and(|s| crate::query::utc_ms(s).is_err()) {
                return Err("invalid UTC");
            }
        }
        Ok(batch)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricFamily {
    pub name: String,
    pub semantic_type: String,
    pub label_names: Vec<String>,
    pub allowed_tuples: Vec<Vec<String>>,
    pub finite_buckets: Vec<f64>,
    pub bytes_per_tuple: u32,
}
pub fn metric_capacity(families: &[MetricFamily]) -> Result<(usize, usize), &'static str> {
    let mut names = BTreeSet::new();
    let (mut series, mut bytes) = (0usize, 0usize);
    for f in families {
        if !names.insert(&f.name)
            || f.label_names.len() > 8
            || f.allowed_tuples.is_empty()
            || f.label_names.iter().collect::<BTreeSet<_>>().len() != f.label_names.len()
            || f.allowed_tuples.iter().collect::<BTreeSet<_>>().len() != f.allowed_tuples.len()
            || f.allowed_tuples.iter().any(|t| t.len() != f.label_names.len())
            || f.bytes_per_tuple == 0
        {
            return Err("invalid metric tuples");
        }
        let per = match f.semantic_type.as_str() {
            "counter" | "gauge" if f.finite_buckets.is_empty() => 1,
            "histogram"
                if !f.finite_buckets.is_empty()
                    && f.finite_buckets.iter().all(|b| b.is_finite() && *b > 0.)
                    && f.finite_buckets.windows(2).all(|b| b[0] < b[1]) =>
            {
                f.finite_buckets.len().checked_add(3).ok_or("series overflow")?
            }
            _ => return Err("invalid metric type or buckets"),
        };
        series = series
            .checked_add(per.checked_mul(f.allowed_tuples.len()).ok_or("series overflow")?)
            .ok_or("series overflow")?;
        bytes = bytes
            .checked_add(
                (f.bytes_per_tuple as usize)
                    .checked_mul(f.allowed_tuples.len())
                    .ok_or("memory overflow")?,
            )
            .ok_or("memory overflow")?;
    }
    if series > 2048 || bytes > 4 * 1024 * 1024 {
        return Err("core capacity exceeded");
    }
    Ok((series, bytes))
}
/// Contract model, deliberately separate from production vote execution.
#[derive(Debug)]
pub struct VoteStages {
    phase: u8,
    replay: bool,
    terminal: bool,
}
impl VoteStages {
    pub fn new(action: &str, replay: bool) -> Result<Self, &'static str> {
        if !["notarize_vote", "finalize_vote", "skip_vote"].contains(&action) {
            return Err("not a vote");
        }
        Ok(Self { phase: 0, replay, terminal: false })
    }
    pub fn advance(&mut self, phase: u8) -> Result<(), &'static str> {
        if self.terminal || phase != self.phase + 1 || phase > 5 || (self.replay && phase == 5) {
            return Err("invalid vote stage");
        }
        self.phase = phase;
        if phase == 5 {
            self.terminal = true;
        }
        Ok(())
    }
    pub fn fail(&mut self) -> Result<(), &'static str> {
        if self.terminal {
            return Err("already terminal");
        }
        self.terminal = true;
        Ok(())
    }
    pub fn enqueued(&self) -> bool {
        !self.replay && self.phase == 5
    }
}
pub fn fixture_record() -> DiagnosticRecord {
    DiagnosticRecord {
        record_type: 1,
        source_catalog_id: 7,
        epoch: [0x11; 16],
        sequence: 9,
        monotonic_ns: 10,
        wall_unix_ns: None,
        payload: vec![1, 2],
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub schema_version: u32,
    pub placement: String,
    pub native_owner: String,
    pub remote_native_mode: String,
    pub native_interval_seconds: u32,
    pub native_actual_inflight: u32,
    pub native_source_budget_ms: u32,
    pub native_http_timeout_ms: u32,
    pub native_cache_max_age_seconds: u32,
    pub native_max_bytes: u32,
    pub native_build_per_path: bool,
    pub getstats_enabled: bool,
    pub skip_missed_ticks: bool,
    pub retry_on_timeout: bool,
    pub core_max_bytes: u32,
    pub core_max_series: u32,
    pub core_max_scopes: u32,
    pub diagnostics_enabled: bool,
    pub ai_enabled: bool,
    pub live_fallback: bool,
    pub max_contiguous_monitor_work_us: Option<U64>,
    pub network_id: Option<String>,
    pub binary_digest: Option<String>,
    pub performance_digest: Option<String>,
    pub failure_domains: Option<FailureDomains>,
    pub mtls_digest: Option<String>,
    pub receiver_digest: Option<String>,
    pub effective_resource_digest: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureDomains {
    pub validator: String,
    pub monitor: String,
    pub watchdog: String,
}
impl DeploymentConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || !["development_fixture", "production_off_validator"]
                .contains(&self.placement.as_str())
            || self.native_owner != "health_edge"
            || self.remote_native_mode != "cached_only"
            || self.native_interval_seconds != 15
            || self.native_actual_inflight != 1
            || self.native_source_budget_ms != 2000
            || self.native_http_timeout_ms != 3000
            || self.native_cache_max_age_seconds != 30
            || self.native_max_bytes != 2097152
            || self.native_build_per_path
            || self.getstats_enabled
            || !self.skip_missed_ticks
            || self.retry_on_timeout
            || self.core_max_bytes != 4194304
            || self.core_max_series != 2048
            || self.core_max_scopes != 8
            || self.diagnostics_enabled
            || self.ai_enabled
            || self.live_fallback
        {
            return Err("unsupported deployment contract");
        }
        for v in [
            &self.network_id,
            &self.binary_digest,
            &self.performance_digest,
            &self.mtls_digest,
            &self.receiver_digest,
            &self.effective_resource_digest,
        ]
        .into_iter()
        .flatten()
        {
            if !crate::wire::hash(v) {
                return Err("invalid digest");
            }
        }
        if let Some(d) = &self.failure_domains {
            if !crate::wire::alias(&d.validator)
                || !crate::wire::alias(&d.monitor)
                || !crate::wire::alias(&d.watchdog)
                || d.validator == d.monitor
                || d.validator == d.watchdog
                || d.monitor == d.watchdog
            {
                return Err("invalid failure domains");
            }
        }
        Ok(())
    }
    pub fn production_blockers(&self) -> Vec<&'static str> {
        let mut missing = vec![];
        if self.validate().is_err() {
            missing.push("config");
        }
        if self.placement != "production_off_validator" {
            missing.push("development_only");
        }
        for (ok, name) in [
            (self.network_id.is_some(), "network"),
            (self.binary_digest.is_some(), "binary"),
            (self.performance_digest.is_some(), "performance"),
            (self.failure_domains.is_some(), "failure_domains"),
            (self.mtls_digest.is_some(), "mtls"),
            (self.receiver_digest.is_some(), "receiver"),
            (self.effective_resource_digest.is_some(), "resources"),
            (self.max_contiguous_monitor_work_us.is_some_and(|n| n.0 > 0), "contiguous_work"),
        ] {
            if !ok {
                missing.push(name);
            }
        }
        // Digests identify claims; a future release gate must verify their actual evidence.
        missing.push("runtime_acceptance_not_verified");
        missing
    }
}
