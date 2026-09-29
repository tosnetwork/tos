//! Closed initial edge snapshot subset. Unsupported anchors cannot be fabricated.
use crate::{
    native::{canonical_hash, required_nullable, NativeEnvelope, NativeEnvelopeV2, SourceEnvelope},
    wire::U64,
};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessPayload {
    pub kind: String,
    pub pid: u32,
    #[serde(deserialize_with = "required_nullable")]
    pub rss_bytes: Option<U64>,
    #[serde(deserialize_with = "required_nullable")]
    pub anon_bytes: Option<U64>,
    #[serde(deserialize_with = "required_nullable")]
    pub file_bytes: Option<U64>,
    #[serde(deserialize_with = "required_nullable")]
    pub swap_bytes: Option<U64>,
    #[serde(deserialize_with = "required_nullable")]
    pub cpu_user_ticks: Option<U64>,
    #[serde(deserialize_with = "required_nullable")]
    pub cpu_system_ticks: Option<U64>,
}
pub type ProcessEnvelope = SourceEnvelope<ProcessPayload>;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupPayload {
    pub kind: String,
    pub memory_current_bytes: U64,
    pub memory_max_bytes: U64,
    pub cpu_usage_usec: U64,
    pub cpu_quota_usec: U64,
    pub cpu_period_usec: U64,
    pub oom_events: U64,
}
pub type CgroupEnvelope = SourceEnvelope<CgroupPayload>;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EdgeSource {
    Native(NativeEnvelope),
    NativeV2(NativeEnvelopeV2),
    Process(ProcessEnvelope),
    Cgroup(CgroupEnvelope),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnsupportedAnchor {}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeSnapshot {
    pub schema_version: u32,
    pub status: String,
    pub sources: Vec<EdgeSource>,
    pub anchors: Vec<UnsupportedAnchor>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatSource {
    pub source_id: String,
    pub age_ms: Option<U64>,
    pub usable: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeHeartbeat {
    pub schema_version: u32,
    pub node_id: String,
    pub edge_epoch: String,
    pub state: String,
    pub guard: String,
    pub validator_epoch: Option<String>,
    pub sources: Vec<HeartbeatSource>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityValue {
    pub supported: bool,
    pub enabled: bool,
    pub contract_valid: bool,
    pub performance_gate: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedCapability {
    pub name: String,
    pub value: CapabilityValue,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySource {
    pub source_id: String,
    pub status: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeCapabilities {
    pub schema_version: u32,
    pub node_id: String,
    pub catalog_digest: String,
    pub capabilities: Vec<NamedCapability>,
    pub sources: Vec<CapabilitySource>,
}
impl EdgeHeartbeat {
    pub fn validate(&self, node: &str) -> Result<(), String> {
        if self.schema_version != 1
            || self.node_id != node
            || !crate::wire::alias(&self.node_id)
            || self.edge_epoch.is_empty()
            || self.edge_epoch.len() > 128
            || !matches!(self.state.as_str(), "available" | "degraded" | "unknown")
            || !matches!(self.guard.as_str(), "normal" | "guarded" | "emergency" | "recovering")
            || self.validator_epoch.as_ref().is_some_and(|v| v.is_empty() || v.len() > 128)
            || self.sources.len() > 32
        {
            return Err("invalid edge heartbeat".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for source in &self.sources {
            if !crate::wire::alias(&source.source_id)
                || !seen.insert(source.source_id.as_str())
                || (source.usable && source.age_ms.is_none_or(|age| age.0 > 30_000))
            {
                return Err("invalid heartbeat source".into());
            }
        }
        Ok(())
    }
}
impl EdgeCapabilities {
    pub fn validate(&self, node: &str) -> Result<(), String> {
        if self.schema_version != 1
            || self.node_id != node
            || !crate::wire::alias(&self.node_id)
            || !crate::wire::hash(&self.catalog_digest)
            || self.capabilities.len() > 32
            || self.sources.len() > 32
        {
            return Err("invalid edge capabilities".into());
        }
        let mut capabilities = std::collections::BTreeSet::new();
        for capability in &self.capabilities {
            if !crate::wire::alias(&capability.name)
                || !capabilities.insert(capability.name.as_str())
                || (capability.value.enabled && !capability.value.supported)
                || capability.value.performance_gate != "not_run"
            {
                return Err("invalid capability".into());
            }
        }
        let mut sources = std::collections::BTreeSet::new();
        for source in &self.sources {
            if !crate::wire::alias(&source.source_id)
                || !sources.insert(source.source_id.as_str())
                || !matches!(
                    source.status.as_str(),
                    "available" | "disabled" | "unsupported" | "unauthorized" | "error" | "unknown"
                )
            {
                return Err("invalid capability source".into());
            }
        }
        Ok(())
    }
}
impl EdgeSnapshot {
    pub fn native(&self) -> Option<&NativeEnvelope> {
        self.sources.iter().find_map(|source| match source {
            EdgeSource::Native(value) => Some(value),
            _ => None,
        })
    }
    pub fn native_v2(&self) -> Option<&NativeEnvelopeV2> {
        self.sources.iter().find_map(|source| match source {
            EdgeSource::NativeV2(value) => Some(value),
            _ => None,
        })
    }
    pub fn validate(&self, node: &str, network: &str) -> Result<(), String> {
        if self.schema_version != 1
            || self.status != "partial"
            || self.sources.len() > 3
            || !self.anchors.is_empty()
        {
            return Err("unsupported edge snapshot".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut process_epoch: Option<&str> = None;
        for source in &self.sources {
            let (id, epoch) = match source {
                EdgeSource::Native(value) => {
                    value.validate()?;
                    if value.node_id != node || value.payload.network_id != network {
                        return Err("native inventory mismatch".into());
                    }
                    (value.source_id.as_str(), value.process_epoch.as_str())
                }
                EdgeSource::NativeV2(value) => {
                    value.validate()?;
                    if value.node_id != node || value.payload.network_id != network {
                        return Err("native inventory mismatch".into());
                    }
                    (value.source_id.as_str(), value.process_epoch.as_str())
                }
                EdgeSource::Process(value) => {
                    if value.schema_version != 1
                        || value.source_id != "process"
                        || value.node_id != node
                        || value.scope_id != "node"
                        || value.source_version != "proc-v1"
                        || value.payload.kind != "process"
                        || value.payload.pid == 0
                        || value.process_epoch.is_empty()
                        || value.process_epoch.len() > 128
                        || value.source_epoch.is_empty()
                        || value.source_epoch.len() > 128
                        || value.generation.0 == 0
                        || value.availability != "available"
                        || value.clock_quality != "valid"
                        || value.source_age_ms.is_none_or(|age| age > 30_000)
                        || value.coverage.status != "partial"
                        || value.coverage.sampling_policy != "fixed_15s"
                        || value.coverage.missing_fields.len() > 64
                        || value.coverage.missing_fields.iter().any(|v| v.len() > 96)
                        || !value.coverage.gaps.is_empty()
                        || canonical_hash(&value.payload)? != value.content_hash
                    {
                        return Err("invalid process snapshot".into());
                    }
                    for time in [&value.observed_at, &value.last_success_at] {
                        let time = time.as_ref().ok_or("missing process timestamp")?;
                        if !time.ends_with('Z') {
                            return Err("UTC timestamp required".into());
                        }
                        crate::query::utc_ms(time).map_err(str::to_owned)?;
                    }
                    if let Some(time) = &value.received_at {
                        if !time.ends_with('Z') {
                            return Err("UTC timestamp required".into());
                        }
                        crate::query::utc_ms(time).map_err(str::to_owned)?;
                    }
                    (value.source_id.as_str(), value.process_epoch.as_str())
                }
                EdgeSource::Cgroup(value) => {
                    if value.schema_version != 1
                        || value.source_id != "host_cgroup"
                        || value.node_id != node
                        || value.scope_id != "node"
                        || value.source_version != "cgroup-v2-effective-v1"
                        || value.payload.kind != "host_cgroup"
                        || value.process_epoch.is_empty()
                        || value.process_epoch.len() > 128
                        || value.source_epoch.is_empty()
                        || value.source_epoch.len() > 128
                        || value.generation.0 == 0
                        || value.availability != "available"
                        || value.clock_quality != "valid"
                        || value.source_age_ms.is_none_or(|age| age > 30_000)
                        || value.coverage.status != "partial"
                        || value.coverage.sampling_policy != "fixed_cgroup_v2_15s"
                        || value.coverage.missing_fields.len() > 64
                        || value.coverage.missing_fields.iter().any(|v| v.len() > 96)
                        || !value.coverage.gaps.is_empty()
                        || !value.quality.instrumentation_complete
                        || canonical_hash(&value.payload)? != value.content_hash
                    {
                        return Err("invalid cgroup snapshot".into());
                    }
                    for time in [&value.observed_at, &value.last_success_at] {
                        let time = time.as_ref().ok_or("missing cgroup timestamp")?;
                        if !time.ends_with('Z') {
                            return Err("UTC timestamp required".into());
                        }
                        crate::query::utc_ms(time).map_err(str::to_owned)?;
                    }
                    (value.source_id.as_str(), value.process_epoch.as_str())
                }
            };
            if process_epoch.is_some_and(|expected| expected != epoch) {
                return Err("mixed process epochs".into());
            }
            process_epoch = Some(epoch);
            if !seen.insert(id) {
                return Err("duplicate edge source".into());
            }
        }
        if !seen.contains("process") || !seen.contains("native_core") {
            return Err("required edge source missing".into());
        }
        Ok(())
    }
}
