//! Deterministic incident authority; no model or notification callback can resolve it.
use crate::wire::U64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Clear,
    Open,
    SuspendedUnknown,
    Recovering,
    ClosedRecovered,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub process_epoch: String,
    pub source_epoch: String,
    pub generation: U64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthState {
    pub state: State,
    pub episode: U64,
    pub acknowledged: bool,
    pub severity: String,
    good_since: Option<u64>,
    last_good: BTreeMap<String, Sample>,
    good_count: u32,
    last_now: Option<u64>,
}
impl Default for HealthState {
    fn default() -> Self {
        Self {
            state: State::Clear,
            episode: U64(0),
            acknowledged: false,
            severity: "unknown".into(),
            good_since: None,
            last_good: BTreeMap::new(),
            good_count: 0,
            last_now: None,
        }
    }
}
impl HealthState {
    fn reset_recovery(&mut self) {
        self.good_since = None;
        self.last_good.clear();
        self.good_count = 0;
    }
    pub fn active(&self) -> bool {
        matches!(self.state, State::Open | State::SuspendedUnknown | State::Recovering)
    }
    pub fn unknown(&mut self) {
        if self.active() {
            self.state = State::SuspendedUnknown;
        }
        self.reset_recovery();
    }
    pub fn after_restart(&mut self) {
        self.unknown();
        self.last_now = None;
    }
    pub fn acknowledge(&mut self) {
        self.acknowledged = true;
    }
    pub fn bad(&mut self, severity: &str) -> Result<(), &'static str> {
        if !["warning", "critical"].contains(&severity) {
            return Err("invalid severity");
        }
        if !self.active() {
            self.episode = U64(self.episode.0.checked_add(1).ok_or("episode exhausted")?);
            self.acknowledged = false;
        }
        self.severity = severity.into();
        self.state = State::Open;
        self.reset_recovery();
        Ok(())
    }
    /// Caller supplies all required, usable source samples. An absent source is unknown.
    pub fn good(
        &mut self,
        now: u64,
        required: &[String],
        samples: BTreeMap<String, Sample>,
        hold_ms: u64,
        minimum: u32,
    ) -> Result<(), &'static str> {
        if required.is_empty() || required.len() > 32 || minimum < 2 || hold_ms == 0 {
            return Err("invalid recovery contract");
        }
        if self.last_now.is_some_and(|old| now < old) {
            self.unknown();
            return Err("monotonic clock reversed");
        }
        self.last_now = Some(now);
        if samples.len() != required.len() || required.iter().any(|k| !samples.contains_key(k)) {
            self.unknown();
            return Ok(());
        }
        if !self.active() {
            return Ok(());
        }
        let changed_epoch = samples.iter().any(|(k, v)| {
            self.last_good.get(k).is_some_and(|old| {
                old.process_epoch != v.process_epoch || old.source_epoch != v.source_epoch
            })
        });
        if self.good_since.is_none() || changed_epoch {
            self.good_since = Some(now);
            self.good_count = 1;
            self.last_good = samples;
            self.state = State::Recovering;
            return Ok(());
        }
        if samples
            .iter()
            .any(|(k, v)| self.last_good.get(k).is_none_or(|old| v.generation <= old.generation))
        {
            return Ok(());
        }
        self.good_count = self.good_count.saturating_add(1);
        self.last_good = samples;
        if self.good_count >= minimum
            && self.good_since.is_some_and(|t| now.saturating_sub(t) >= hold_ms)
        {
            self.state = State::ClosedRecovered;
            self.severity = "healthy".into();
        }
        Ok(())
    }
}
