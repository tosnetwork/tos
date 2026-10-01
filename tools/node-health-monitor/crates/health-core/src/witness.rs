//! C05 development-only cache witness wire. Remote reports are never local proof.
use crate::{
    native::required_nullable,
    wire::{alias, hash, U64},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use url::Url;

pub const MAX_TARGETS: usize = 32;
pub const MAX_ENDPOINTS: usize = 16;
pub const MAX_TARGET_REFS: usize = 3;
pub const MAX_ROWS: usize = 32;
pub const MAX_BODY: usize = 16_384;
pub const MAX_ROUND_BODY: usize = 262_144;
pub const MAX_INFLIGHT: usize = 4;
pub const MAX_CACHE_RESIDENT: usize = 2_097_152;
pub const MAX_RETAINED_PER_ENDPOINT: usize = 4;
pub const MAX_RETIRED_EPOCHS: usize = 32;
pub const USABLE_AGE_MS: u64 = 45_000;

fn epoch(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_graphic())
}
fn utc(value: &str) -> bool {
    value.len() <= 40 && value.ends_with('Z') && crate::query::utc_ms(value).is_ok()
}
fn ordered_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Normal,
    ProbeOnly,
    NonVoting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub endpoint_id: String,
    pub fixed_url: String,
    pub failure_domain: String,
    pub kind: String,
    /// Explicit current-view activation; historical decode does not enforce it.
    pub current_source_epoch: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub target_id: String,
    pub node_id: String,
    pub role: Role,
    pub valid_from: String,
    pub valid_until: String,
    pub scope_id: String,
    pub workchain: i32,
    pub shard: U64,
    pub endpoint_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: u32,
    pub profile: String,
    pub revision: String,
    pub observer_id: String,
    pub observer_epoch: String,
    pub network_id: String,
    pub genesis: String,
    pub clock_skew_allowance_ms: u32,
    pub endpoints: Vec<Endpoint>,
    pub targets: Vec<Target>,
}
impl Plan {
    pub fn read_file(path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("witness plan must be a regular file".into());
        }
        let mut bytes = Vec::with_capacity(MAX_BODY + 1);
        file.take((MAX_BODY + 1) as u64).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        Self::decode(&bytes).map_err(str::to_owned)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_BODY {
            return Err("witness plan body overflow");
        }
        let plan: Self = serde_json::from_slice(bytes).map_err(|_| "invalid witness plan JSON")?;
        plan.validate()?;
        Ok(plan)
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || self.profile != "c05_development_cache_only"
            || !hash(&self.revision)
            || !alias(&self.observer_id)
            || !epoch(&self.observer_epoch)
            || !hash(&self.network_id)
            || !hash(&self.genesis)
            || self.clock_skew_allowance_ms != 5_000
            || self.endpoints.is_empty()
            || self.endpoints.len() > MAX_ENDPOINTS
            || self.targets.is_empty()
            || self.targets.len() > MAX_TARGETS
        {
            return Err("invalid witness plan bound or identity");
        }
        let mut endpoint_ids = BTreeSet::new();
        let mut urls = BTreeSet::new();
        for endpoint in &self.endpoints {
            let parsed =
                Url::parse(&endpoint.fixed_url).map_err(|_| "invalid fixed witness URL")?;
            if !alias(&endpoint.endpoint_id)
                || !alias(&endpoint.failure_domain)
                || endpoint.kind != "approved_cache_only_https"
                || !epoch(&endpoint.current_source_epoch)
                || endpoint.fixed_url.len() > 512
                || endpoint.fixed_url != parsed.as_str()
                || endpoint
                    .fixed_url
                    .strip_prefix("https://")
                    .and_then(|rest| rest.split('/').next())
                    .is_none_or(str::is_empty)
                || parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || endpoint.fixed_url.bytes().any(|b| b.is_ascii_control())
                || !endpoint_ids.insert(&endpoint.endpoint_id)
                || !urls.insert(parsed.as_str().to_string())
            {
                return Err("invalid fixed witness endpoint");
            }
        }
        let mut target_ids = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut scope_bindings = BTreeMap::new();
        let mut used = BTreeSet::new();
        for target in &self.targets {
            if !alias(&target.target_id)
                || !alias(&target.node_id)
                || !alias(&target.scope_id)
                || !utc(&target.valid_from)
                || !utc(&target.valid_until)
                || crate::query::utc_ms(&target.valid_from).ok()
                    >= crate::query::utc_ms(&target.valid_until).ok()
                || target.endpoint_ids.is_empty()
                || target.endpoint_ids.len() > MAX_TARGET_REFS
                || !ordered_unique(&target.endpoint_ids)
                || !target.endpoint_ids.iter().all(|id| endpoint_ids.contains(id))
                || target.scope_id == "masterchain"
                    && (target.workchain != -1 || target.shard.0 != 9_223_372_036_854_775_808)
                || target.workchain == -1 && target.shard.0 != 9_223_372_036_854_775_808
                || scope_bindings
                    .insert(&target.scope_id, (target.workchain, target.shard.0))
                    .is_some_and(|prior| prior != (target.workchain, target.shard.0))
                || !target_ids.insert(&target.target_id)
                || !identities.insert((&target.node_id, &target.scope_id))
            {
                return Err("invalid witness target or role window");
            }
            used.extend(target.endpoint_ids.iter());
        }
        if used.len() != endpoint_ids.len() {
            return Err("unused witness endpoint");
        }
        Ok(())
    }
    pub fn targets_for<'a>(
        &'a self,
        endpoint_id: &'a str,
    ) -> impl Iterator<Item = &'a Target> + 'a {
        self.targets
            .iter()
            .filter(move |target| target.endpoint_ids.iter().any(|id| id == endpoint_id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockQuality {
    Valid,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Complete,
    Partial,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkObservation {
    Observed,
    NotObservedInWindow,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportedMembership {
    Included,
    NotInThisCertificate,
    NotChecked,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportedProof {
    NotChecked,
    ReportedValid,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Missing {
    Anchor,
    Certificate,
    Clock,
    PrivateVote,
    Proof,
    Role,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockPoint {
    ReportedFinalized,
    ReportedApplied,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusPhase {
    ReportedCandidate,
    ReportedVote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Anchor {
    Block {
        network_id: String,
        genesis: String,
        scope_id: String,
        workchain: i32,
        shard: U64,
        seqno: u32,
        root_hash: String,
        file_hash: String,
        point: BlockPoint,
    },
    Consensus {
        network_id: String,
        genesis: String,
        scope_id: String,
        workchain: i32,
        shard: U64,
        session_id: String,
        slot: u32,
        #[serde(deserialize_with = "required_nullable")]
        candidate_id: Option<String>,
        phase: ConsensusPhase,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub target_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub observed_at: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub source_age_ms: Option<U64>,
    #[serde(deserialize_with = "required_nullable")]
    pub anchor: Option<Anchor>,
    pub network_observation: NetworkObservation,
    pub reported_certificate_membership: ReportedMembership,
    pub reported_proof: ReportedProof,
    pub private_vote_visibility: NetworkObservation,
    pub coverage: Coverage,
    pub missing_fields: Vec<Missing>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub schema_version: u32,
    pub endpoint_id: String,
    pub source_epoch: String,
    pub generation: U64,
    pub network_id: String,
    pub genesis: String,
    #[serde(deserialize_with = "required_nullable")]
    pub observed_at: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub source_age_ms: Option<U64>,
    pub clock_quality: ClockQuality,
    pub coverage: Coverage,
    pub rows: Vec<Row>,
}
impl Source {
    pub fn decode(bytes: &[u8], plan: &Plan, endpoint_id: &str) -> Result<Self, &'static str> {
        if bytes.len() > MAX_BODY {
            return Err("witness source body overflow");
        }
        let source: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid witness source JSON")?;
        source.validate(plan, endpoint_id)?;
        Ok(source)
    }
    pub fn validate(&self, plan: &Plan, endpoint_id: &str) -> Result<(), &'static str> {
        plan.validate()?;
        if self.schema_version != 1
            || self.endpoint_id != endpoint_id
            || !plan.endpoints.iter().any(|e| e.endpoint_id == endpoint_id)
            || !epoch(&self.source_epoch)
            || self.generation.0 == 0
            || self.network_id != plan.network_id
            || self.genesis != plan.genesis
            || self.observed_at.as_ref().is_some_and(|v| !utc(v))
            || (self.clock_quality == ClockQuality::Valid && self.observed_at.is_none())
            || self.rows.len() > MAX_ROWS
            || (self.coverage == Coverage::Complete && self.rows.is_empty())
        {
            return Err("invalid witness source identity");
        }
        let allowed: BTreeMap<_, _> =
            plan.targets_for(endpoint_id).map(|v| (&v.target_id, v)).collect();
        if self.coverage == Coverage::Complete && self.rows.len() != allowed.len() {
            return Err("complete witness source omits planned target");
        }
        let mut seen = BTreeSet::new();
        for row in &self.rows {
            let target = allowed.get(&row.target_id).ok_or("unapproved witness target")?;
            if !seen.insert(&row.target_id)
                || row.observed_at.as_ref().is_some_and(|v| !utc(v))
                || (self.clock_quality == ClockQuality::Valid && row.observed_at.is_none())
                || row.missing_fields.len() > 8
                || !ordered_unique(&row.missing_fields)
                || (row.coverage == Coverage::Complete && !row.missing_fields.is_empty())
                || (row.coverage != Coverage::Complete && row.missing_fields.is_empty())
                || (self.coverage == Coverage::Complete && row.coverage != Coverage::Complete)
                || (row.private_vote_visibility == NetworkObservation::Unavailable
                    && (row.coverage == Coverage::Complete
                        || !row.missing_fields.contains(&Missing::PrivateVote)))
                || (row.reported_certificate_membership == ReportedMembership::Unavailable
                    && (row.coverage == Coverage::Complete
                        || !row.missing_fields.contains(&Missing::Certificate)))
                || (row.reported_proof == ReportedProof::Unavailable
                    && (row.coverage == Coverage::Complete
                        || !row.missing_fields.contains(&Missing::Proof)))
                || (row.network_observation == NetworkObservation::Observed && row.anchor.is_none())
            {
                return Err("invalid witness row");
            }
            if let Some(anchor) = &row.anchor {
                let context_ok = match anchor {
                    Anchor::Block {
                        network_id,
                        genesis,
                        scope_id,
                        workchain,
                        shard,
                        root_hash,
                        file_hash,
                        ..
                    } => {
                        network_id == &plan.network_id
                            && genesis == &plan.genesis
                            && scope_id == &target.scope_id
                            && workchain == &target.workchain
                            && shard == &target.shard
                            && hash(root_hash)
                            && hash(file_hash)
                    }
                    Anchor::Consensus {
                        network_id,
                        genesis,
                        scope_id,
                        workchain,
                        shard,
                        session_id,
                        candidate_id,
                        ..
                    } => {
                        network_id == &plan.network_id
                            && genesis == &plan.genesis
                            && scope_id == &target.scope_id
                            && workchain == &target.workchain
                            && shard == &target.shard
                            && hash(session_id)
                            && candidate_id.as_ref().is_none_or(|v| hash(v))
                    }
                };
                if !context_ok {
                    return Err("witness anchor context mismatch");
                }
            }
        }
        Ok(())
    }
}

/// Reported observations may disagree; no result of this comparator is verified finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compared {
    Same,
    ObservedDisagreement,
    Incomparable,
}
pub fn compare(left: &Anchor, right: &Anchor) -> Compared {
    match (left, right) {
        (
            Anchor::Block {
                network_id: an,
                genesis: ag,
                scope_id: as_,
                workchain: aw,
                shard: ah,
                seqno: aq,
                root_hash: ar,
                file_hash: af,
                point: ap,
            },
            Anchor::Block {
                network_id: bn,
                genesis: bg,
                scope_id: bs,
                workchain: bw,
                shard: bh,
                seqno: bq,
                root_hash: br,
                file_hash: bf,
                point: bp,
            },
        ) if an == bn && ag == bg && as_ == bs && aw == bw && ah == bh && aq == bq && ap == bp => {
            if ar == br && af == bf {
                Compared::Same
            } else {
                Compared::ObservedDisagreement
            }
        }
        (
            Anchor::Consensus {
                network_id: an,
                genesis: ag,
                scope_id: as_,
                workchain: aw,
                shard: ah,
                session_id: ae,
                slot: aq,
                candidate_id: ac,
                phase: ap,
            },
            Anchor::Consensus {
                network_id: bn,
                genesis: bg,
                scope_id: bs,
                workchain: bw,
                shard: bh,
                session_id: be,
                slot: bq,
                candidate_id: bc,
                phase: bp,
            },
        ) if an == bn
            && ag == bg
            && as_ == bs
            && aw == bw
            && ah == bh
            && ae == be
            && aq == bq
            && ap == bp
            && ac.is_some()
            && bc.is_some() =>
        {
            if ac == bc {
                Compared::Same
            } else {
                Compared::ObservedDisagreement
            }
        }
        _ => Compared::Incomparable,
    }
}

/// Canonical semantic hash after strict DTO validation: object keys sorted,
/// array order retained. Exact transport bytes have a separate raw digest.
fn canonical_hash<T: Serialize>(typed: &T) -> Result<String, &'static str> {
    fn append(value: &Value, out: &mut Vec<u8>) -> Result<(), &'static str> {
        match value {
            Value::Object(map) => {
                out.push(b'{');
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(key).map_err(|_| "canonical key failed")?);
                    out.push(b':');
                    append(&map[key], out)?;
                }
                out.push(b'}');
            }
            Value::Array(items) => {
                out.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    append(item, out)?;
                }
                out.push(b']');
            }
            _ => out.extend(serde_json::to_vec(value).map_err(|_| "canonical scalar failed")?),
        }
        Ok(())
    }
    let value = serde_json::to_value(typed).map_err(|_| "canonical object failed")?;
    let mut bytes = Vec::with_capacity(MAX_BODY);
    append(&value, &mut bytes)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}
pub fn canonical_source_hash(source: &Source) -> Result<String, &'static str> {
    canonical_hash(source)
}
/// Binds every approved target, URL, role window and raw scope to a cache receipt;
/// the operator-facing revision alone is not a content hash.
pub fn canonical_plan_hash(plan: &Plan) -> Result<String, &'static str> {
    canonical_hash(plan)
}
