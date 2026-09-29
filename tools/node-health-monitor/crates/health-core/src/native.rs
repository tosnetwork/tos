//! Exact native snapshot contract and pairing with the frozen OpenMetrics generation.
use crate::wire::{alias, exact_u64, hash, U64};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

pub(crate) fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqSnapshot {
    pub complete: bool,
    pub failed: U64,
    pub succeeded: U64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePayload {
    pub bytes: u32,
    pub generation: U64,
    pub kind: String,
    pub network_id: String,
    pub openmetrics_hash: String,
    #[serde(deserialize_with = "required_nullable")]
    pub pq_sign: Option<PqSnapshot>,
    #[serde(deserialize_with = "required_nullable")]
    pub pq_verify: Option<PqSnapshot>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub status: String,
    pub missing_fields: Vec<String>,
    pub gaps: Vec<String>,
    pub sampling_policy: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quality {
    pub instrumentation_complete: bool,
    pub producer_dropped: U64,
    pub relay_dropped: U64,
    pub parse_errors: U64,
    #[serde(deserialize_with = "required_nullable")]
    pub shed_reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceEnvelope<T> {
    pub schema_version: u32,
    pub source_id: String,
    pub node_id: String,
    pub scope_id: String,
    pub process_epoch: String,
    pub source_epoch: String,
    pub source_version: String,
    pub generation: U64,
    pub availability: String,
    #[serde(deserialize_with = "required_nullable")]
    pub observed_at: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub last_success_at: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub received_at: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub source_age_ms: Option<u64>,
    pub clock_quality: String,
    pub coverage: Coverage,
    pub content_hash: String,
    pub payload: T,
    pub quality: Quality,
}
pub type NativeEnvelope = SourceEnvelope<NativePayload>;

pub fn canonical_hash<T: Serialize>(value: &T) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// C01 freezes the complete returned body, including exporter transport fields.
pub fn immutable_metrics(body: &str) -> String {
    body.to_owned()
}
impl NativeEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.source_id != "native_core"
            || !alias(&self.node_id)
            || self.scope_id != "node"
            || self.source_version != "native-core-v1"
            || self.availability != "available"
            || self.clock_quality != "valid"
            || self.process_epoch.is_empty()
            || self.process_epoch.len() > 128
            || self.source_epoch != self.process_epoch
            || self.generation.0 == 0
            || self.payload.generation != self.generation
            || self.payload.kind != "native_core"
            || !hash(&self.payload.network_id)
            || !hash(&self.payload.openmetrics_hash)
            || self.payload.bytes > 2_097_152
            || self.source_age_ms.is_none_or(|age| age > 30_000)
            || !hash(&self.content_hash)
            || self.coverage.status != "partial"
            || self.coverage.missing_fields.len() > 64
            || self.coverage.gaps.len() > 32
            || self.coverage.missing_fields.iter().any(|v| v.len() > 96)
            || self.coverage.gaps.iter().any(|v| v.len() > 256)
            || self.coverage.sampling_policy != "native_generation_approximate_pq"
            || self.quality.shed_reason.as_ref().is_some_and(|v| v.len() > 96)
        {
            return Err("invalid native snapshot contract".into());
        }
        for time in [&self.observed_at, &self.last_success_at] {
            let time = time.as_ref().ok_or("missing native timestamp")?;
            if !time.ends_with('Z') {
                return Err("UTC timestamp required".into());
            }
            crate::query::utc_ms(time).map_err(str::to_owned)?;
        }
        if let Some(time) = &self.received_at {
            if !time.ends_with('Z') {
                return Err("UTC timestamp required".into());
            }
            crate::query::utc_ms(time).map_err(str::to_owned)?;
        }
        if canonical_hash(&self.payload)? != self.content_hash {
            return Err("native content hash mismatch".into());
        }
        let complete = self.payload.pq_sign.as_ref().is_some_and(|p| p.complete)
            && self.payload.pq_verify.as_ref().is_some_and(|p| p.complete);
        if complete != self.quality.instrumentation_complete {
            return Err("native instrumentation quality mismatch".into());
        }
        Ok(())
    }
    pub fn paired(
        &self,
        node: &str,
        network: &str,
        generation: &str,
        epoch: &str,
        body: &str,
    ) -> Result<(), String> {
        self.validate()?;
        if self.node_id != node
            || self.payload.network_id != network
            || self.process_epoch != epoch
            || self.generation.0 != exact_u64(generation).map_err(str::to_owned)?
        {
            return Err("native identity or generation mismatch".into());
        }
        if body.len() > 2_097_152 || !body.ends_with("# EOF\n") {
            return Err("invalid OpenMetrics body".into());
        }
        let stable = immutable_metrics(body);
        if stable.len() != self.payload.bytes as usize
            || format!("{:x}", Sha256::digest(stable.as_bytes())) != self.payload.openmetrics_hash
        {
            return Err("native OpenMetrics pairing mismatch".into());
        }
        Ok(())
    }
    pub fn immutable_hash(&self) -> Result<String, String> {
        let mut value = self.clone();
        value.source_age_ms = Some(0);
        value.received_at = None;
        canonical_hash(&value)
    }
}
