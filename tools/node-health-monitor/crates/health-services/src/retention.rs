//! Bounded age retention for the local evidence database.
//!
//! An evidence store that can only grow eventually hits its quota, refuses
//! ingest and leaves the monitor blind; forgetting old immutable evidence is
//! the lesser harm. The policy here is deliberately narrow: only ordinary
//! observations and historical witness archive rows are eligible, only by
//! receipt age, never below a hard floor, never the newest rows of a source,
//! and never anything in the control database or a quarantine table.
//!
//! Deleting a row also removes the unique-identity witness that refused a
//! replay of that same source record. Every deletion therefore commits a
//! per-source seal (the highest deleted generation) in the same transaction;
//! a later insert at or below the seal is refused as `EVIDENCE_EXPIRED`
//! instead of minting a fresh sequence number for old data.
use crate::durable::{is_capacity_error, EvidenceDb};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Shortest configurable retention: one hour.
pub const RETENTION_MIN_MS: u64 = 3_600_000;
/// Longest configurable retention: ninety days.
pub const RETENTION_MAX_MS: u64 = 90 * 86_400_000;
/// Rows younger than this are never deleted regardless of configuration, so
/// the query service's retained parents and fixed-watermark grants stay valid.
pub const RETENTION_FLOOR_MS: u64 = 7_200_000;
/// The newest rows per (node, scope, source) / per witness endpoint that a
/// pass always keeps, so a silent source still has its last evidence.
pub const RETAINED_ROWS_PER_SOURCE: u32 = 8;
/// Scheduled pass period on the evidence writer thread.
pub const RETENTION_PERIOD_MS: u64 = 300_000;
/// Minimum spacing between quota-triggered recovery passes.
pub const RECOVERY_SPACING_MS: u64 = 30_000;
/// Rows scanned per page and pages per pass bound one pass's writer time.
pub const PAGE_ROWS: u32 = 512;
pub const MAX_PAGES_PER_PASS: u32 = 16;
pub const PASS_BUDGET_MS: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionPolicy {
    pub evidence_retention_ms: Option<u64>,
    pub witness_retention_ms: Option<u64>,
}
impl RetentionPolicy {
    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("evidence_retention_ms", self.evidence_retention_ms),
            ("witness_retention_ms", self.witness_retention_ms),
        ] {
            if let Some(value) = value {
                if !(RETENTION_MIN_MS..=RETENTION_MAX_MS).contains(&value) {
                    return Err(format!("{name} must be between one hour and ninety days"));
                }
            }
        }
        Ok(())
    }
    pub fn configured(&self) -> bool {
        self.evidence_retention_ms.is_some() || self.witness_retention_ms.is_some()
    }
    /// Receipt time below which an ordinary observation is eligible.
    pub fn evidence_cutoff_ms(&self, now_ms: i64) -> Option<i64> {
        self.evidence_retention_ms.and_then(|value| cutoff(now_ms, value))
    }
    /// Receipt time below which a historical witness row is eligible.
    pub fn witness_cutoff_ms(&self, now_ms: i64) -> Option<i64> {
        self.witness_retention_ms.and_then(|value| cutoff(now_ms, value))
    }
}
fn cutoff(now_ms: i64, retention_ms: u64) -> Option<i64> {
    let window = i64::try_from(retention_ms.max(RETENTION_FLOOR_MS)).ok()?;
    now_ms.checked_sub(window)
}
/// The generation a source record identifies: the canonical decimal after
/// the last `:` (archived `epoch:generation` records) or the whole record.
/// Records without a canonical generation are never deleted.
/// Deleted observations leave a (sequence, content hash) tombstone so a
/// reader holding that exact row as a cursor anchor or a retained parent can
/// prove retention removed it. Only the newest this many tombstones are
/// kept: a reader whose anchor is older than that window is refused and
/// must be re-anchored by an operator, which is the fail-closed outcome.
pub const RETENTION_TOMBSTONE_LIMIT: i64 = 262_144;
pub fn generation_of(source_record: &str) -> Option<u64> {
    let tail = source_record.rsplit(':').next().unwrap_or(source_record);
    tos_health_core::wire::exact_u64(tail).ok()
}
/// Result of one bounded pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPass {
    pub observations_deleted: u64,
    pub witness_deleted: u64,
    /// Eligible rows kept because their record carries no canonical generation.
    pub unsealable_kept: u64,
    pub pages: u32,
    /// False when the page or time budget ended the pass before the scan did.
    pub complete: bool,
    pub oldest_retained_received_at_ms: Option<i64>,
    pub observations_rows: u64,
    pub witness_rows: u64,
    /// `PRAGMA wal_checkpoint(PASSIVE)` result: busy, log frames, checkpointed.
    pub checkpoint: (i64, i64, i64),
}
/// Cumulative writer-thread view published through the manager state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionStatus {
    pub evidence_retention_ms: Option<u64>,
    pub witness_retention_ms: Option<u64>,
    pub passes: u64,
    pub failed_passes: u64,
    pub observations_deleted_total: u64,
    pub witness_deleted_total: u64,
    pub unsealable_kept_total: u64,
    pub last_pass_at_ms: Option<i64>,
    pub last_pass_complete: Option<bool>,
    pub last_pass_error: Option<String>,
    pub oldest_retained_received_at_ms: Option<i64>,
    pub observations_rows: Option<u64>,
    pub witness_rows: Option<u64>,
}
impl RetentionStatus {
    pub fn new(policy: &RetentionPolicy) -> Self {
        Self {
            evidence_retention_ms: policy.evidence_retention_ms,
            witness_retention_ms: policy.witness_retention_ms,
            ..Self::default()
        }
    }
    pub fn configured(&self) -> bool {
        self.evidence_retention_ms.is_some() || self.witness_retention_ms.is_some()
    }
    pub fn record(&mut self, now_ms: i64, outcome: &Result<RetentionPass, String>) {
        self.last_pass_at_ms = Some(now_ms);
        match outcome {
            Ok(pass) => {
                self.passes = self.passes.saturating_add(1);
                self.observations_deleted_total =
                    self.observations_deleted_total.saturating_add(pass.observations_deleted);
                self.witness_deleted_total =
                    self.witness_deleted_total.saturating_add(pass.witness_deleted);
                self.unsealable_kept_total =
                    self.unsealable_kept_total.saturating_add(pass.unsealable_kept);
                self.last_pass_complete = Some(pass.complete);
                self.last_pass_error = None;
                self.oldest_retained_received_at_ms = pass.oldest_retained_received_at_ms;
                self.observations_rows = Some(pass.observations_rows);
                self.witness_rows = Some(pass.witness_rows);
            }
            Err(error) => {
                self.failed_passes = self.failed_passes.saturating_add(1);
                self.last_pass_complete = Some(false);
                self.last_pass_error = Some(error.clone());
            }
        }
    }
    fn age_ms(at: Option<i64>, now_ms: i64) -> Option<i64> {
        at.and_then(|value| now_ms.checked_sub(value)).map(|age| age.max(0))
    }
    /// Wire form: u64 values are decimal strings, ages are computed against
    /// the caller's clock so the doctor never has to trust the writer's.
    pub fn json(&self, now_ms: i64) -> Value {
        let text = |value: Option<u64>| value.map(|value| value.to_string());
        json!({
            "configured": self.configured(),
            "evidence_retention_ms": text(self.evidence_retention_ms),
            "witness_retention_ms": text(self.witness_retention_ms),
            "floor_ms": RETENTION_FLOOR_MS.to_string(),
            "retained_rows_per_source": RETAINED_ROWS_PER_SOURCE,
            "period_ms": RETENTION_PERIOD_MS.to_string(),
            "passes": self.passes.to_string(),
            "failed_passes": self.failed_passes.to_string(),
            "observations_deleted_total": self.observations_deleted_total.to_string(),
            "witness_deleted_total": self.witness_deleted_total.to_string(),
            "unsealable_kept_total": self.unsealable_kept_total.to_string(),
            "last_pass_at_ms": self.last_pass_at_ms.map(|value| value.to_string()),
            "last_pass_age_ms": Self::age_ms(self.last_pass_at_ms, now_ms).map(|value| value.to_string()),
            "last_pass_complete": self.last_pass_complete,
            "last_pass_error": self.last_pass_error,
            "oldest_retained_received_at_ms": self.oldest_retained_received_at_ms.map(|value| value.to_string()),
            "oldest_retained_age_ms": Self::age_ms(self.oldest_retained_received_at_ms, now_ms).map(|value| value.to_string()),
            "observations_rows": text(self.observations_rows),
            "witness_rows": text(self.witness_rows),
        })
    }
    /// OpenMetrics lines without the trailing `# EOF`.
    pub fn metrics(&self, now_ms: i64) -> String {
        let seconds = |value: Option<i64>| {
            value.map_or_else(|| "NaN".to_owned(), |value| (value / 1000).to_string())
        };
        format!(
            "# HELP tos_health_evidence_retention_configured Evidence age retention is enabled.\n\
             # TYPE tos_health_evidence_retention_configured gauge\n\
             tos_health_evidence_retention_configured {}\n\
             # HELP tos_health_evidence_retention_passes_total Completed retention passes.\n\
             # TYPE tos_health_evidence_retention_passes_total counter\n\
             tos_health_evidence_retention_passes_total {}\n\
             # HELP tos_health_evidence_retention_failed_passes_total Retention passes that failed.\n\
             # TYPE tos_health_evidence_retention_failed_passes_total counter\n\
             tos_health_evidence_retention_failed_passes_total {}\n\
             # HELP tos_health_evidence_retention_rows_deleted_total Observation rows deleted by retention.\n\
             # TYPE tos_health_evidence_retention_rows_deleted_total counter\n\
             tos_health_evidence_retention_rows_deleted_total{{table=\"observations\"}} {}\n\
             tos_health_evidence_retention_rows_deleted_total{{table=\"witness_observations\"}} {}\n\
             # HELP tos_health_evidence_retention_last_pass_age_seconds Seconds since the last retention pass.\n\
             # TYPE tos_health_evidence_retention_last_pass_age_seconds gauge\n\
             tos_health_evidence_retention_last_pass_age_seconds {}\n\
             # HELP tos_health_evidence_oldest_retained_age_seconds Age of the oldest retained observation receipt.\n\
             # TYPE tos_health_evidence_oldest_retained_age_seconds gauge\n\
             tos_health_evidence_oldest_retained_age_seconds {}\n",
            u8::from(self.configured()),
            self.passes,
            self.failed_passes,
            self.observations_deleted_total,
            self.witness_deleted_total,
            seconds(Self::age_ms(self.last_pass_at_ms, now_ms)),
            seconds(Self::age_ms(self.oldest_retained_received_at_ms, now_ms)),
        )
    }
}
/// Writer-thread schedule: one pass per period, plus at most one recovery
/// pass per `RECOVERY_SPACING_MS` when a write was refused for space.
pub struct RetentionSchedule {
    policy: RetentionPolicy,
    next: Instant,
    last_recovery: Option<Instant>,
}
impl RetentionSchedule {
    pub fn new(policy: RetentionPolicy) -> Self {
        Self { policy, next: Instant::now(), last_recovery: None }
    }
    pub fn until_next(&self) -> Duration {
        if !self.policy.configured() {
            return Duration::from_secs(3600);
        }
        self.next.saturating_duration_since(Instant::now())
    }
    fn run(&mut self, db: &mut EvidenceDb, status: &Arc<Mutex<RetentionStatus>>) -> bool {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let outcome = db.retain(&self.policy, now_ms);
        let freed = outcome
            .as_ref()
            .is_ok_and(|pass| pass.observations_deleted > 0 || pass.witness_deleted > 0);
        if let Ok(mut status) = status.lock() {
            status.record(now_ms, &outcome);
        }
        freed
    }
    /// Scheduled pass when due; a no-op otherwise or when unconfigured.
    pub fn tick(&mut self, db: &mut EvidenceDb, status: &Arc<Mutex<RetentionStatus>>) {
        if !self.policy.configured() || Instant::now() < self.next {
            return;
        }
        self.run(db, status);
        self.next = Instant::now() + Duration::from_millis(RETENTION_PERIOD_MS);
    }
    /// After a capacity refusal, run one bounded pass and report whether it
    /// freed anything, so the caller can retry the refused write exactly once.
    pub fn recover(
        &mut self,
        db: &mut EvidenceDb,
        status: &Arc<Mutex<RetentionStatus>>,
        error: &str,
    ) -> bool {
        if !self.policy.configured() || !is_capacity_error(error) {
            return false;
        }
        let spacing = Duration::from_millis(RECOVERY_SPACING_MS);
        if self.last_recovery.is_some_and(|last| last.elapsed() < spacing) {
            return false;
        }
        self.last_recovery = Some(Instant::now());
        self.run(db, status)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_and_floor() {
        assert!(RetentionPolicy {
            evidence_retention_ms: Some(RETENTION_MIN_MS - 1),
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(RetentionPolicy {
            witness_retention_ms: Some(RETENTION_MAX_MS + 1),
            ..Default::default()
        }
        .validate()
        .is_err());
        let policy = RetentionPolicy {
            evidence_retention_ms: Some(RETENTION_MIN_MS),
            witness_retention_ms: None,
        };
        policy.validate().unwrap();
        assert_eq!(
            policy.evidence_cutoff_ms(10_000_000),
            Some(10_000_000 - RETENTION_FLOOR_MS as i64)
        );
        assert_eq!(policy.witness_cutoff_ms(10_000_000), None);
        assert!(!RetentionPolicy::default().configured());
    }
    #[test]
    fn generation_parsing() {
        assert_eq!(generation_of("42"), Some(42));
        assert_eq!(generation_of("abc:7"), Some(7));
        assert_eq!(generation_of("a:b:0"), Some(0));
        assert_eq!(generation_of("007"), None);
        assert_eq!(generation_of("abc:"), None);
        assert_eq!(generation_of(""), None);
    }
}
