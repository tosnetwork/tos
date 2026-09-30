//! Exact native snapshot contract and pairing with the frozen OpenMetrics generation.
use crate::consensus_v2::Consensus;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePayloadV2 {
    pub bytes: u32,
    pub generation: U64,
    pub kind: String,
    pub network_id: String,
    pub openmetrics_hash: String,
    #[serde(deserialize_with = "required_nullable")]
    pub pq_sign: Option<PqSnapshot>,
    #[serde(deserialize_with = "required_nullable")]
    pub pq_verify: Option<PqSnapshot>,
    #[serde(deserialize_with = "required_nullable")]
    pub consensus: Option<Consensus>,
}
pub type NativeEnvelopeV2 = SourceEnvelope<NativePayloadV2>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockAnchor {
    pub file_hash: String,
    pub kind: String,
    pub network_id: String,
    pub point: String,
    pub root_hash: String,
    pub scope_id: String,
    pub seqno: u32,
    pub shard: U64,
    pub workchain: i32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainAnchors {
    pub applied: BlockAnchor,
    pub applied_advanced_unix_seconds: U64,
    pub observed_unix_seconds: U64,
    #[serde(deserialize_with = "required_nullable")]
    pub served: Option<BlockAnchor>,
}
impl ChainAnchors {
    fn validate(&self, network: &str) -> Result<(), String> {
        let valid = |a: &BlockAnchor, point: &str| {
            a.kind == "block"
                && a.network_id == network
                && a.scope_id == "masterchain"
                && a.point == point
                && a.workchain == -1
                && a.shard.0 == (1u64 << 63)
                && hash(&a.root_hash)
                && hash(&a.file_hash)
                && a.root_hash.bytes().any(|b| b != b'0')
                && a.file_hash.bytes().any(|b| b != b'0')
        };
        if !valid(&self.applied, "applied")
            || self.observed_unix_seconds.0 == 0
            || self.applied_advanced_unix_seconds.0 > self.observed_unix_seconds.0
            || self
                .served
                .as_ref()
                .is_some_and(|s| !valid(s, "served") || s.seqno > self.applied.seqno)
        {
            return Err("invalid chain anchors".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePayloadV3 {
    pub bytes: u32,
    #[serde(deserialize_with = "required_nullable")]
    pub chain: Option<ChainAnchors>,
    #[serde(deserialize_with = "required_nullable")]
    pub consensus: Option<Consensus>,
    pub generation: U64,
    pub kind: String,
    pub network_id: String,
    pub openmetrics_hash: String,
    #[serde(deserialize_with = "required_nullable")]
    pub pq_sign: Option<PqSnapshot>,
    #[serde(deserialize_with = "required_nullable")]
    pub pq_verify: Option<PqSnapshot>,
}
pub type NativeEnvelopeV3 = SourceEnvelope<NativePayloadV3>;

pub fn parse_native(bytes: &[u8]) -> Result<NativeRecord, String> {
    if bytes.len() > 262_144 {
        return Err("native typed snapshot exceeds fixed bound".into());
    }
    // Version inspection is not validation: the selected strict DTO is parsed
    // again from original bytes, retaining Serde duplicate-field rejection.
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    match value.get("source_version").and_then(|v| v.as_str()) {
        Some("native-core-v1") => serde_json::from_slice::<NativeEnvelope>(bytes)
            .map(NativeRecord::V1)
            .map_err(|e| e.to_string()),
        Some("native-core-v2") => serde_json::from_slice::<NativeEnvelopeV2>(bytes)
            .map(NativeRecord::V2)
            .map_err(|e| e.to_string()),
        Some("native-core-v3") => serde_json::from_slice::<NativeEnvelopeV3>(bytes)
            .map(NativeRecord::V3)
            .map_err(|e| e.to_string()),
        _ => Err("unsupported native source version".into()),
    }
}
// Parsed once per 15-second sample; the size spread between versions is
// irrelevant next to the 256 KiB body it is decoded from.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum NativeRecord {
    V1(NativeEnvelope),
    V2(NativeEnvelopeV2),
    V3(NativeEnvelopeV3),
}
impl NativeRecord {
    pub fn node_id(&self) -> &str {
        match self {
            Self::V1(v) => &v.node_id,
            Self::V2(v) => &v.node_id,
            Self::V3(v) => &v.node_id,
        }
    }
    pub fn network_id(&self) -> &str {
        match self {
            Self::V1(v) => &v.payload.network_id,
            Self::V2(v) => &v.payload.network_id,
            Self::V3(v) => &v.payload.network_id,
        }
    }
    pub fn process_epoch(&self) -> &str {
        match self {
            Self::V1(v) => &v.process_epoch,
            Self::V2(v) => &v.process_epoch,
            Self::V3(v) => &v.process_epoch,
        }
    }
    pub fn generation(&self) -> U64 {
        match self {
            Self::V1(v) => v.generation,
            Self::V2(v) => v.generation,
            Self::V3(v) => v.generation,
        }
    }
    pub fn source_age_ms(&self) -> Option<u64> {
        match self {
            Self::V1(v) => v.source_age_ms,
            Self::V2(v) => v.source_age_ms,
            Self::V3(v) => v.source_age_ms,
        }
    }
    pub fn set_source_age_ms(&mut self, age: Option<u64>) {
        match self {
            Self::V1(v) => v.source_age_ms = age,
            Self::V2(v) => v.source_age_ms = age,
            Self::V3(v) => v.source_age_ms = age,
        }
    }
    pub fn set_received_at(&mut self, time: Option<String>) {
        match self {
            Self::V1(v) => v.received_at = time,
            Self::V2(v) => v.received_at = time,
            Self::V3(v) => v.received_at = time,
        }
    }
    pub fn paired(
        &self,
        node: &str,
        network: &str,
        generation: &str,
        epoch: &str,
        body: &str,
    ) -> Result<(), String> {
        match self {
            Self::V1(v) => v.paired(node, network, generation, epoch, body),
            Self::V2(v) => v.paired(node, network, generation, epoch, body),
            Self::V3(v) => v.paired(node, network, generation, epoch, body),
        }
    }
    pub fn immutable_hash(&self) -> Result<String, String> {
        match self {
            Self::V1(v) => v.immutable_hash(),
            Self::V2(v) => v.immutable_hash(),
            Self::V3(v) => v.immutable_hash(),
        }
    }
}

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

impl NativeEnvelopeV2 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.source_id != "native_core"
            || !alias(&self.node_id)
            || self.scope_id != "node"
            || self.source_version != "native-core-v2"
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
            || self.source_age_ms.is_none_or(|v| v > 30_000)
            || !hash(&self.content_hash)
            || self.coverage.status != "partial"
            || self.coverage.missing_fields.len() > 64
            || self.coverage.gaps.len() > 32
            || self.coverage.missing_fields.iter().any(|v| v.len() > 96)
            || self.coverage.gaps.iter().any(|v| v.len() > 256)
            || self.coverage.sampling_policy != "native-core-v2-concurrent-bounded"
            || self.quality.shed_reason.as_ref().is_some_and(|v| v.len() > 96)
        {
            return Err("invalid native v2 snapshot contract".into());
        }
        for time in [&self.observed_at, &self.last_success_at] {
            let time = time.as_ref().ok_or("missing native v2 timestamp")?;
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
            return Err("native v2 content hash mismatch".into());
        }
        let pq_complete = self.payload.pq_sign.as_ref().is_some_and(|v| v.complete)
            && self.payload.pq_verify.as_ref().is_some_and(|v| v.complete);
        let consensus_complete = match &self.payload.consensus {
            Some(v) => {
                v.validate(&self.payload.network_id)?;
                v.instrumentation_complete
            }
            None => false,
        };
        // Registry/publication degradation may make the whole source
        // incomplete even when these two component snapshots are complete.
        // The reverse promotion is never valid.
        if self.quality.instrumentation_complete
            && (!(pq_complete && consensus_complete)
                || self.quality.producer_dropped.0 != 0
                || self.quality.relay_dropped.0 != 0
                || self.quality.parse_errors.0 != 0
                || self.quality.shed_reason.is_some())
        {
            return Err("native v2 quality mismatch".into());
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
            return Err("native v2 identity or generation mismatch".into());
        }
        if body.len() > 2_097_152 || !body.ends_with("# EOF\n") {
            return Err("invalid OpenMetrics body".into());
        }
        if body.len() != self.payload.bytes as usize
            || format!("{:x}", Sha256::digest(body.as_bytes())) != self.payload.openmetrics_hash
        {
            return Err("native v2 OpenMetrics pairing mismatch".into());
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

impl NativeEnvelopeV3 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.source_id != "native_core"
            || !alias(&self.node_id)
            || self.scope_id != "node"
            || self.source_version != "native-core-v3"
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
            || self.coverage.sampling_policy != "native-core-v3-chain-partial"
            || self.coverage.missing_fields.len() > 64
            || self.coverage.gaps.len() > 32
            || self.coverage.missing_fields.iter().any(|v| v.len() > 96)
            || self.coverage.gaps.iter().any(|v| v.len() > 256)
            || self.quality.instrumentation_complete
            || self.quality.shed_reason.as_ref().is_some_and(|v| v.len() > 96)
        {
            return Err("invalid native v3 snapshot contract".into());
        }
        for time in [&self.observed_at, &self.last_success_at] {
            let time = time.as_ref().ok_or("missing native v3 timestamp")?;
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
        if let Some(chain) = &self.payload.chain {
            chain.validate(&self.payload.network_id)?;
            let sampled_ms = crate::query::utc_ms(
                self.observed_at.as_deref().ok_or("missing native v3 timestamp")?,
            )?;
            let anchor_ms =
                chain.observed_unix_seconds.0.checked_mul(1000).ok_or("chain time overflow")?;
            let advanced_ms = chain
                .applied_advanced_unix_seconds
                .0
                .checked_mul(1000)
                .ok_or("chain time overflow")?;
            let sampled_ms = sampled_ms.max(0) as u64;
            if advanced_ms == 0
                || anchor_ms > sampled_ms + 1000
                || advanced_ms > sampled_ms + 1000
                || sampled_ms.saturating_sub(anchor_ms) > 31_000
                || sampled_ms.saturating_sub(advanced_ms) > 31_000
            {
                return Err("stale or future chain anchor".into());
            }
            if self.coverage.missing_fields.iter().any(|field| field == "chain_anchors") {
                return Err("present chain marked missing".into());
            }
        } else if !self.coverage.missing_fields.iter().any(|field| field == "chain_anchors") {
            return Err("missing chain not covered".into());
        }
        if let Some(consensus) = &self.payload.consensus {
            consensus.validate(&self.payload.network_id)?;
        }
        if canonical_hash(&self.payload)? != self.content_hash {
            return Err("native v3 content hash mismatch".into());
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
            return Err("native v3 identity or generation mismatch".into());
        }
        if body.len() > 2_097_152
            || !body.ends_with("# EOF\n")
            || body.len() != self.payload.bytes as usize
            || format!("{:x}", Sha256::digest(body.as_bytes())) != self.payload.openmetrics_hash
        {
            return Err("native v3 OpenMetrics pairing mismatch".into());
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
