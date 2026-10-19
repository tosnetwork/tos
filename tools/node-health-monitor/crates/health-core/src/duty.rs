use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    CompletedOnTime,
    CompletedLate,
    Failed,
    Cancelled,
    NotRequired,
    Unknown,
}
#[derive(Debug, Clone)]
struct Duty {
    assigned_ms: u64,
    started_ms: Option<u64>,
    deadline_ms: Option<u64>,
    overdue: bool,
    outcome: Option<Outcome>,
}
/// Closed cohorts remain until explicitly retired. At capacity, completeness
/// becomes false; no business operation depends on this accounting table.
#[derive(Debug)]
pub struct DutyLedger {
    duties: BTreeMap<String, Duty>,
    capacity: usize,
    pub complete: bool,
    pub overdue_total: u64,
}
impl DutyLedger {
    pub fn new(capacity: usize) -> Self {
        Self { duties: BTreeMap::new(), capacity, complete: true, overdue_total: 0 }
    }
    pub fn assign(&mut self, key: &str, now: u64, deadline_ms: Option<u64>) -> bool {
        if self.duties.contains_key(key) {
            return false;
        }
        if key.len() > 256
            || key.is_empty()
            || self.duties.len() >= self.capacity
            || deadline_ms.is_some_and(|v| v < now)
        {
            self.complete = false;
            return false;
        }
        self.duties.insert(
            key.into(),
            Duty { assigned_ms: now, started_ms: None, deadline_ms, overdue: false, outcome: None },
        );
        true
    }
    pub fn start(&mut self, key: &str, now: u64) -> bool {
        match self.duties.get_mut(key) {
            Some(duty)
                if duty.started_ms.is_none()
                    && duty.outcome.is_none()
                    && now >= duty.assigned_ms =>
            {
                duty.started_ms = Some(now);
                true
            }
            _ => false,
        }
    }
    pub fn finish(&mut self, key: &str, outcome: Outcome, protocol_not_required: bool) -> bool {
        match self.duties.get_mut(key) {
            Some(duty)
                if duty.outcome.is_none()
                    && (outcome != Outcome::NotRequired || protocol_not_required) =>
            {
                duty.outcome = Some(outcome);
                true
            }
            _ => false,
        }
    }
    pub fn tick(&mut self, now: u64) {
        for duty in self.duties.values_mut() {
            if duty.outcome.is_none() && !duty.overdue && duty.deadline_ms.is_some_and(|d| now > d)
            {
                duty.overdue = true;
                match self.overdue_total.checked_add(1) {
                    Some(total) => self.overdue_total = total,
                    None => self.complete = false,
                }
            }
        }
    }
    pub fn pending(&self) -> usize {
        self.duties.values().filter(|d| d.outcome.is_none()).count()
    }
    pub fn closed_cohort(&self, start: u64, end: u64) -> Option<(usize, usize)> {
        if !self.complete || start >= end {
            return None;
        }
        let cohort: Vec<_> = self
            .duties
            .values()
            .filter(|d| d.assigned_ms >= start && d.assigned_ms < end)
            .collect();
        if cohort.is_empty()
            || cohort.iter().any(|d| d.outcome.is_none() || d.outcome == Some(Outcome::Unknown))
        {
            return None;
        }
        Some((
            cohort.iter().filter(|d| d.outcome == Some(Outcome::CompletedOnTime)).count(),
            cohort
                .iter()
                .filter(|d| !matches!(d.outcome, Some(Outcome::Cancelled | Outcome::NotRequired)))
                .count(),
        ))
    }
}
