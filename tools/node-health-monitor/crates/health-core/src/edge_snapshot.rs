//! Closed initial edge snapshot subset. Unsupported anchors cannot be fabricated.
use crate::{
    native::{canonical_hash, required_nullable, NativeEnvelope, SourceEnvelope},
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
#[serde(untagged)]
pub enum EdgeSource {
    Native(NativeEnvelope),
    Process(ProcessEnvelope),
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
impl EdgeSnapshot {
    pub fn native(&self) -> Option<&NativeEnvelope> {
        self.sources.iter().find_map(|source| match source {
            EdgeSource::Native(value) => Some(value),
            _ => None,
        })
    }
    pub fn validate(&self, node: &str, network: &str) -> Result<(), String> {
        if self.schema_version != 1
            || self.status != "partial"
            || self.sources.len() > 2
            || !self.anchors.is_empty()
        {
            return Err("unsupported edge snapshot".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for source in &self.sources {
            let id = match source {
                EdgeSource::Native(value) => {
                    value.validate()?;
                    if value.node_id != node || value.payload.network_id != network {
                        return Err("native inventory mismatch".into());
                    }
                    &value.source_id
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
                    &value.source_id
                }
            };
            if !seen.insert(id) {
                return Err("duplicate edge source".into());
            }
        }
        Ok(())
    }
}
