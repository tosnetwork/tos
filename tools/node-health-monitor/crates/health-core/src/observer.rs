use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockIdentity {
    pub genesis: String,
    pub workchain: i32,
    pub shard: String,
    pub seqno: u32,
    pub root_hash: String,
    pub file_hash: String,
}
impl BlockIdentity {
    pub fn valid(&self) -> bool {
        [&self.genesis, &self.root_hash, &self.file_hash].iter().all(|v| crate::wire::hash(v))
            && crate::wire::exact_u64(&self.shard).is_ok()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    Same,
    ObservedBlockDisagreement,
    Incomparable,
    InvalidIdentity,
}
/// RPC claims alone never become verified finality evidence.
pub fn compare(left: &BlockIdentity, right: &BlockIdentity) -> Comparison {
    if !left.valid() || !right.valid() {
        return Comparison::InvalidIdentity;
    }
    if left.genesis != right.genesis
        || left.workchain != right.workchain
        || left.shard != right.shard
        || left.seqno != right.seqno
    {
        return Comparison::Incomparable;
    }
    if left.root_hash == right.root_hash && left.file_hash == right.file_hash {
        Comparison::Same
    } else {
        Comparison::ObservedBlockDisagreement
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteObservation {
    Observed,
    NotObservedInWindow,
    Unavailable,
}
#[derive(Debug)]
pub struct Deadman {
    start_ms: u64,
    last_sequence: Option<u64>,
    last_received: Option<u64>,
}
impl Deadman {
    pub fn new(start_ms: u64) -> Self {
        Self { start_ms, last_sequence: None, last_received: None }
    }
    pub fn receive(&mut self, now: u64, sequence: u64) -> bool {
        if now < self.start_ms
            || self.last_received.is_some_and(|t| now < t)
            || self.last_sequence.is_some_and(|s| sequence <= s)
        {
            return false;
        }
        self.last_sequence = Some(sequence);
        self.last_received = Some(now);
        true
    }
    pub fn unavailable(&self, now: u64) -> bool {
        now.saturating_sub(self.last_received.unwrap_or(self.start_ms)) >= 45_000
    }
}
/// Process and pipeline heartbeats have separate deadlines and replay histories.
#[derive(Debug)]
pub struct EpochDeadman {
    epoch: Option<String>,
    retired: std::collections::BTreeSet<String>,
    sequence: Option<u64>,
    started: u64,
    last_received: Option<u64>,
    timeout_ms: u64,
}
impl EpochDeadman {
    pub fn new(now: u64, timeout_ms: u64) -> Result<Self, &'static str> {
        if timeout_ms == 0 {
            return Err("invalid deadline");
        }
        Ok(Self {
            epoch: None,
            retired: std::collections::BTreeSet::new(),
            sequence: None,
            started: now,
            last_received: None,
            timeout_ms,
        })
    }
    pub fn receive(&mut self, now: u64, epoch: &str, sequence: u64) -> Result<bool, &'static str> {
        if epoch.is_empty()
            || epoch.len() > 128
            || now < self.started
            || self.last_received.is_some_and(|t| now < t)
        {
            return Err("invalid heartbeat");
        }
        if self.epoch.as_deref() != Some(epoch) {
            if self.retired.contains(epoch) || self.retired.len() >= 32 {
                return Err("retired epoch or epoch budget");
            }
            if let Some(old) = self.epoch.replace(epoch.into()) {
                self.retired.insert(old);
            }
            self.sequence = Some(sequence);
            self.last_received = Some(now);
            return Ok(true);
        }
        if self.sequence.is_some_and(|s| sequence <= s) {
            return Ok(false);
        }
        self.sequence = Some(sequence);
        self.last_received = Some(now);
        Ok(true)
    }
    pub fn unavailable(&self, now: u64) -> bool {
        now.checked_sub(self.last_received.unwrap_or(self.started))
            .is_none_or(|age| age >= self.timeout_ms)
    }
}
