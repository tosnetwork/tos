use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Disabled,
    Unsupported,
    Unauthorized,
    Error,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Complete,
    Partial,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQuality {
    pub availability: Availability,
    pub coverage: Coverage,
    pub observed_at_ms: Option<i64>,
    pub last_success_at_ms: Option<i64>,
    pub clock_valid: bool,
    pub process_epoch: String,
    pub source_sequence: String,
}
impl SourceQuality {
    pub fn usable(&self, as_of_ms: i64, max_age_ms: i64, require_complete: bool) -> bool {
        if max_age_ms < 0
            || !self.clock_valid
            || self.availability != Availability::Available
            || self.coverage == Coverage::Unknown
            || (require_complete && self.coverage != Coverage::Complete)
        {
            return false;
        }
        match (self.observed_at_ms, self.last_success_at_ms) {
            (Some(observed), Some(success)) => {
                observed <= success
                    && success <= as_of_ms
                    && as_of_ms.checked_sub(observed).is_some_and(|age| age <= max_age_ms)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Started(u64),
    Busy,
    NotDue,
    Exhausted,
}
/// A client deadline does not release this token. `complete` is called only
/// after the underlying task, including all children, has actually ended.
#[derive(Debug)]
pub struct SourceGate {
    interval_ms: u64,
    budget_ms: u64,
    next_due: u64,
    active: Option<(u64, u64)>,
    sequence: u64,
}
impl SourceGate {
    pub fn new(interval_ms: u64, budget_ms: u64) -> Result<Self, &'static str> {
        if budget_ms == 0 || interval_ms <= budget_ms {
            return Err("invalid source budget");
        }
        Ok(Self { interval_ms, budget_ms, next_due: 0, active: None, sequence: 0 })
    }
    pub fn start(&mut self, now: u64) -> Admission {
        if self.active.is_some() {
            return Admission::Busy;
        }
        if now < self.next_due {
            return Admission::NotDue;
        }
        let (Some(id), Some(next)) =
            (self.sequence.checked_add(1), now.checked_add(self.interval_ms))
        else {
            return Admission::Exhausted;
        };
        self.sequence = id;
        self.next_due = next; // skip missed ticks; never schedule backlog
        self.active = Some((id, now));
        Admission::Started(id)
    }
    pub fn expired(&self, now: u64) -> bool {
        self.active.is_some_and(|(_, start)| now.saturating_sub(start) >= self.budget_ms)
    }
    pub fn complete(&mut self, token: u64, now: u64) -> Result<bool, &'static str> {
        let Some((id, started)) = self.active else {
            return Err("no active work");
        };
        if token != id {
            return Err("wrong work token");
        }
        if now < started {
            return Err("monotonic clock reversed");
        }
        let on_time = !self.expired(now);
        self.active = None;
        Ok(on_time)
    }
    pub fn inflight(&self) -> bool {
        self.active.is_some()
    }
}
