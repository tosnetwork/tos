//! Fixed deterministic rule catalog. Inputs are facts, never model conclusions.
use crate::{
    freshness::Freshness,
    health_state::Sample,
    wire::{alias, hash, U64},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactId {
    Reachable,
    InitializationPendingMs,
    ChainProgressAgeMs,
    AppliedServedGap,
    KeyBlockAgeMs,
    ActionFailures,
    ActionOldestMs,
    PqSigningFailures,
    QueueOldestMs,
    SessionStopPendingMs,
    StorageAckFailures,
    StorageUsable,
    RocksdbWriteStopped,
    UnexplainedMemoryBytes,
    QuicBacklogBytes,
    ObserverDisagreement,
    MonitorAvailable,
    DiagnosticDrops,
    AiAvailable,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub id: FactId,
    pub value: U64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactFrame {
    pub schema_version: u32,
    pub network_id: String,
    pub node_id: String,
    pub scope_id: String,
    pub source_id: String,
    pub process_epoch: String,
    pub source_epoch: String,
    pub generation: U64,
    pub source_age_ms: U64,
    pub request_duration_ms: U64,
    pub observed_at: String,
    pub clock_valid: bool,
    pub complete: bool,
    pub facts: Vec<Fact>,
}
impl FactFrame {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || !hash(&self.network_id)
            || [&self.node_id, &self.scope_id, &self.source_id].iter().any(|v| !alias(v))
            || [&self.process_epoch, &self.source_epoch]
                .iter()
                .any(|v| v.is_empty() || v.len() > 128)
            || crate::query::utc_ms(&self.observed_at).is_err()
            || self.facts.len() > 32
            || self.facts.iter().map(|f| f.id).collect::<BTreeSet<_>>().len() != self.facts.len()
        {
            return Err("invalid facts frame");
        }
        for f in &self.facts {
            if matches!(
                f.id,
                FactId::Reachable
                    | FactId::StorageUsable
                    | FactId::RocksdbWriteStopped
                    | FactId::ObserverDisagreement
                    | FactId::MonitorAvailable
                    | FactId::AiAvailable
            ) && f.value.0 > 1
            {
                return Err("boolean fact out of range");
            }
        }
        Ok(())
    }
    pub fn immutable(&self) -> Self {
        let mut copy = self.clone();
        copy.source_age_ms = U64(0);
        copy.request_duration_ms = U64(0);
        copy
    }
    pub fn digest(&self) -> Result<String, &'static str> {
        Ok(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&self.immutable()).map_err(|_| "serialization failed")?
            )
        ))
    }
    pub fn sample(&self) -> Sample {
        Sample {
            process_epoch: self.process_epoch.clone(),
            source_epoch: self.source_epoch.clone(),
            generation: self.generation,
        }
    }
    fn fact(&self, id: FactId) -> Option<u64> {
        self.facts.iter().find(|f| f.id == id).map(|f| f.value.0)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSpec {
    pub id: String,
    pub ttl_ms: U64,
    pub facts: Vec<FactId>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub node: String,
    pub scope: String,
    pub sources: Vec<SourceSpec>,
    pub rules: Vec<RuleSpec>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    pub source: String,
    pub threshold: U64,
    pub pending_ms: U64,
    pub recovery_ms: U64,
    pub minimum_bad_samples: u32,
    pub severity: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleInventory {
    pub schema_version: u32,
    pub revision: String,
    pub network_id: String,
    pub targets: Vec<Target>,
}
#[derive(Clone, Copy)]
enum Predicate {
    Zero,
    Positive,
    Above,
    Increase,
    Storage,
}
fn definition(id: &str) -> Option<(Option<FactId>, Predicate)> {
    use FactId::*;
    use Predicate::*;
    Some(match id {
        "target_unreachable" => (Some(Reachable), Zero),
        "telemetry_unavailable" => (None, Zero),
        "initialization_stalled" => (Some(InitializationPendingMs), Above),
        "local_chain_stalled" => (Some(ChainProgressAgeMs), Above),
        "applied_served_gap" => (Some(AppliedServedGap), Above),
        "key_block_stale" => (Some(KeyBlockAgeMs), Above),
        "local_action_failure" => (Some(ActionFailures), Increase),
        "local_action_overdue" => (Some(ActionOldestMs), Above),
        "pq_signing_failure" => (Some(PqSigningFailures), Increase),
        "queue_stall" => (Some(QueueOldestMs), Above),
        "session_stop_pending" => (Some(SessionStopPendingMs), Above),
        "storage_ack_failure" => (Some(StorageAckFailures), Storage),
        "rocksdb_write_stopped" => (Some(RocksdbWriteStopped), Positive),
        "memory_growth_unexplained" => (Some(UnexplainedMemoryBytes), Above),
        "quic_pressure" => (Some(QuicBacklogBytes), Above),
        "observer_disagreement" => (Some(ObserverDisagreement), Positive),
        "monitoring_unavailable" => (Some(MonitorAvailable), Zero),
        "diagnostic_coverage_reduced" => (Some(DiagnosticDrops), Increase),
        "ai_unavailable" => (Some(AiAvailable), Zero),
        _ => return None,
    })
}
impl RuleInventory {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || self.revision.is_empty()
            || self.revision.len() > 128
            || !hash(&self.network_id)
            || self.targets.is_empty()
            || self.targets.len() > 128
        {
            return Err("invalid rule inventory");
        }
        let mut keys = BTreeSet::new();
        for t in &self.targets {
            if !alias(&t.node)
                || !alias(&t.scope)
                || !keys.insert((&t.node, &t.scope))
                || t.sources.is_empty()
                || t.sources.len() > 32
                || t.rules.is_empty()
                || t.rules.len() > 18
            {
                return Err("invalid target");
            }
            let mut sources = BTreeSet::new();
            let mut rules = BTreeSet::new();
            for s in &t.sources {
                if !alias(&s.id)
                    || !sources.insert(&s.id)
                    || s.ttl_ms.0 == 0
                    || s.ttl_ms.0 > 180_000
                    || s.facts.is_empty()
                    || s.facts.len() > 32
                    || s.facts.iter().collect::<BTreeSet<_>>().len() != s.facts.len()
                {
                    return Err("invalid source catalog");
                }
            }
            for r in &t.rules {
                let Some((fact, _)) = definition(&r.id) else {
                    return Err("unknown rule");
                };
                if !rules.insert(&r.id)
                    || r.recovery_ms.0 == 0
                    || r.recovery_ms.0 > 3_600_000
                    || r.pending_ms.0 > 3_600_000
                    || !(1..=32).contains(&r.minimum_bad_samples)
                    || !["warning", "critical"].contains(&r.severity.as_str())
                {
                    return Err("invalid rule contract");
                }
                if let Some(f) = fact {
                    let s = t.sources.iter().find(|s| s.id == r.source).ok_or("missing source")?;
                    if !s.facts.contains(&f)
                        || (r.id == "storage_ack_failure"
                            && !s.facts.contains(&FactId::StorageUsable))
                    {
                        return Err("missing required fact");
                    }
                } else if r.source != "inventory" {
                    return Err("invalid inventory rule");
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    Bad,
    Good,
    Unknown,
}
#[derive(Debug, Clone)]
pub struct RuleResult {
    pub node: String,
    pub scope: String,
    pub rule: String,
    pub signal: Signal,
    pub severity: String,
    pub required: Vec<String>,
    pub samples: BTreeMap<String, Sample>,
    pub recovery_ms: u64,
}
struct Cached {
    freshness: Freshness,
    frame: FactFrame,
}
#[derive(Default)]
struct History {
    last_sample: Option<Sample>,
    counter: Option<u64>,
    last_decision: Option<bool>,
    bad_since: Option<u64>,
    bad_samples: u32,
}
pub struct RuleEngine {
    pub inventory: RuleInventory,
    cache: BTreeMap<(String, String, String), Cached>,
    history: BTreeMap<(String, String, String), History>,
    started: u64,
}
impl RuleEngine {
    pub fn new(inventory: RuleInventory, now: u64) -> Result<Self, &'static str> {
        inventory.validate()?;
        Ok(Self { inventory, cache: BTreeMap::new(), history: BTreeMap::new(), started: now })
    }
    pub fn ingest(&mut self, frame: FactFrame, now: u64) -> Result<bool, &'static str> {
        frame.validate()?;
        if frame.network_id != self.inventory.network_id {
            return Err("network mismatch");
        }
        let source = self
            .inventory
            .targets
            .iter()
            .find(|t| t.node == frame.node_id && t.scope == frame.scope_id)
            .and_then(|t| t.sources.iter().find(|s| s.id == frame.source_id))
            .ok_or("source outside inventory")?;
        if frame.facts.iter().any(|f| !source.facts.contains(&f.id))
            || (frame.complete && frame.facts.len() != source.facts.len())
        {
            return Err("fact outside source catalog");
        }
        let key = (frame.node_id.clone(), frame.scope_id.clone(), frame.source_id.clone());
        let hash = frame.digest()?;
        let cache = self
            .cache
            .entry(key)
            .or_insert_with(|| Cached { freshness: Freshness::default(), frame: frame.clone() });
        let accepted = cache.freshness.observe(
            &frame.process_epoch,
            &frame.source_epoch,
            frame.generation.0,
            &hash,
            now,
            frame.source_age_ms.0,
            frame.request_duration_ms.0,
        )?;
        if accepted {
            cache.frame = frame;
        }
        Ok(accepted)
    }
    pub fn quarantine_source(&mut self, node: &str, scope: &str, source: &str) {
        if let Some(c) = self.cache.get_mut(&(node.into(), scope.into(), source.into())) {
            c.freshness.conflicted = true;
        }
    }
    pub fn quarantine(
        &mut self,
        node: &str,
        scope: &str,
        source: &str,
        process_epoch: &str,
        source_epoch: &str,
    ) {
        if let Some(c) = self.cache.get_mut(&(node.into(), scope.into(), source.into())) {
            if c.frame.process_epoch == process_epoch && c.frame.source_epoch == source_epoch {
                c.freshness.conflicted = true;
            }
        }
    }
    pub fn evaluate(&mut self, now: u64) -> Vec<RuleResult> {
        let mut output = Vec::new();
        for t in &self.inventory.targets {
            for r in &t.rules {
                let h = self
                    .history
                    .entry((t.node.clone(), t.scope.clone(), r.id.clone()))
                    .or_default();
                let mut result = RuleResult {
                    node: t.node.clone(),
                    scope: t.scope.clone(),
                    rule: r.id.clone(),
                    signal: Signal::Unknown,
                    severity: r.severity.clone(),
                    required: vec![],
                    samples: BTreeMap::new(),
                    recovery_ms: r.recovery_ms.0,
                };
                let Some((fact, predicate)) = definition(&r.id) else {
                    output.push(result);
                    continue;
                };
                let required: Vec<_> = if fact.is_none() {
                    t.sources.iter().collect()
                } else {
                    t.sources.iter().filter(|s| s.id == r.source).collect()
                };
                let mut usable = true;
                for spec in &required {
                    result.required.push(spec.id.clone());
                    match self.cache.get(&(t.node.clone(), t.scope.clone(), spec.id.clone())) {
                        Some(c)
                            if c.freshness.usable(now, spec.ttl_ms.0)
                                && c.frame.complete
                                && c.frame.clock_valid =>
                        {
                            result.samples.insert(spec.id.clone(), c.frame.sample());
                        }
                        _ => usable = false,
                    }
                }
                let is_bad = if fact.is_none() {
                    if now < self.started {
                        None
                    } else {
                        Some(!usable)
                    }
                } else if !usable {
                    None
                } else {
                    let cache =
                        self.cache.get(&(t.node.clone(), t.scope.clone(), r.source.clone()));
                    cache
                        .and_then(|c| {
                            fact.and_then(|f| c.frame.fact(f)).map(|value| (&c.frame, value))
                        })
                        .and_then(|(frame, value)| {
                            let sample = frame.sample();
                            let changed = h.last_sample.as_ref() != Some(&sample);
                            if !changed {
                                return h.last_decision;
                            }
                            let same_epoch = h.last_sample.as_ref().is_some_and(|s| {
                                s.process_epoch == sample.process_epoch
                                    && s.source_epoch == sample.source_epoch
                            });
                            if !same_epoch {
                                h.bad_since = None;
                                h.bad_samples = 0;
                            }
                            let decision = match predicate {
                                Predicate::Zero => Some(value == 0),
                                Predicate::Positive => Some(value > 0),
                                Predicate::Above => Some(value > r.threshold.0),
                                Predicate::Increase | Predicate::Storage => {
                                    let increased = if same_epoch {
                                        h.counter.filter(|old| value >= *old).map(|old| value > old)
                                    } else {
                                        None
                                    };
                                    if matches!(predicate, Predicate::Storage) {
                                        match frame.fact(FactId::StorageUsable) {
                                            Some(0) => Some(true),
                                            Some(1) => increased,
                                            _ => None,
                                        }
                                    } else {
                                        increased
                                    }
                                }
                            };
                            if matches!(predicate, Predicate::Increase | Predicate::Storage) {
                                h.counter = Some(value);
                            }
                            h.last_sample = Some(sample);
                            h.last_decision = decision;
                            if decision == Some(true) {
                                h.bad_samples = h.bad_samples.saturating_add(1);
                            }
                            decision
                        })
                };
                match is_bad {
                    None => {
                        h.bad_since = None;
                        h.bad_samples = 0;
                    }
                    Some(false) => {
                        h.bad_since = None;
                        h.bad_samples = 0;
                        result.signal = Signal::Good;
                    }
                    Some(true) => {
                        let start = *h.bad_since.get_or_insert(now);
                        let count_ok = fact.is_none() || h.bad_samples >= r.minimum_bad_samples;
                        if now.checked_sub(start).is_some_and(|d| d >= r.pending_ms.0) && count_ok {
                            result.signal = Signal::Bad;
                        }
                    }
                }
                output.push(result);
            }
        }
        output
    }
}
