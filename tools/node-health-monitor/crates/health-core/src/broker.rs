use std::collections::{BTreeMap, VecDeque};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub incident: String,
    pub queued_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueue {
    Queued,
    Duplicate,
    Cooldown,
    Full,
    Invalid,
}
#[derive(Debug, Default)]
pub struct Broker {
    queue: VecDeque<Job>,
    active: Option<Job>,
    cancelling: bool,
    last_runs: BTreeMap<String, u64>,
}
impl Broker {
    pub fn enqueue(&mut self, incident: &str, now: u64) -> Enqueue {
        if incident.is_empty() || incident.len() > 128 {
            return Enqueue::Invalid;
        }
        if self.active.as_ref().is_some_and(|j| j.incident == incident)
            || self.queue.iter().any(|j| j.incident == incident)
        {
            return Enqueue::Duplicate;
        }
        self.last_runs.retain(|_, time| now.saturating_sub(*time) < 600_000);
        if self.last_runs.contains_key(incident) {
            return Enqueue::Cooldown;
        }
        if self.queue.len() >= 32 || self.last_runs.len() >= 1024 {
            return Enqueue::Full;
        }
        self.queue.push_back(Job { incident: incident.into(), queued_ms: now });
        Enqueue::Queued
    }
    pub fn start(&mut self, now: u64) -> Option<Job> {
        if self.active.is_some() {
            return None;
        }
        while let Some(job) = self.queue.pop_front() {
            if now < job.queued_ms || now - job.queued_ms >= 300_000 {
                continue;
            }
            self.last_runs.insert(job.incident.clone(), now);
            self.active = Some(job.clone());
            self.cancelling = false;
            return Some(job);
        }
        None
    }
    pub fn cancel(&mut self) -> bool {
        self.cancelling = self.active.is_some();
        self.cancelling
    }
    /// Call only after the model and all MCP child tasks have stopped.
    pub fn confirm_stopped(&mut self, incident: &str) -> bool {
        if self.active.as_ref().is_none_or(|j| j.incident != incident) {
            return false;
        }
        self.active = None;
        self.cancelling = false;
        true
    }
    pub fn cancelling(&self) -> bool {
        self.cancelling
    }
}
