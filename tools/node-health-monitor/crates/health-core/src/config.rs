use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProfile {
    pub records: u64,
    pub record_bytes: u64,
    pub payload_bytes: u64,
    pub resident_bytes: u64,
    pub batch_records: u64,
    pub batch_bytes: u64,
    pub source_budget_ms: u64,
    pub http_timeout_ms: u64,
    pub guard_interval_ms: u64,
    pub guard_stale_ms: u64,
    pub run_deadline_ms: u64,
    pub grant_ttl_ms: u64,
    pub max_contiguous_monitor_work_us: Option<u64>,
}
impl ResourceProfile {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.records == 0
            || self.record_bytes == 0
            || self.records.checked_mul(self.record_bytes).is_none_or(|n| n > self.payload_bytes)
            || self.payload_bytes > self.resident_bytes
            || self.resident_bytes > 4 * 1024 * 1024
            || self.batch_records == 0
            || self
                .batch_records
                .checked_mul(self.record_bytes)
                .is_none_or(|n| n > self.batch_bytes)
            || self.batch_bytes > 65_536
            || self.source_budget_ms == 0
            || self.source_budget_ms >= self.http_timeout_ms
            || self.guard_interval_ms == 0
            || self.guard_interval_ms.checked_mul(2).is_none_or(|n| n > self.guard_stale_ms)
            || self.run_deadline_ms == 0
            || self.grant_ttl_ms <= self.run_deadline_ms
        {
            return Err("invalid resource budget");
        }
        Ok(())
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionEvidence {
    pub source_admission_tested: bool,
    pub per_path_disabled_at_source: bool,
    pub independent_watchdog_receipt: bool,
    pub mtls_acl_tested: bool,
    pub cgroup_effective_verified: bool,
    pub validator_core_tested: bool,
    pub observer_coverage_tested: bool,
    pub performance_profile_passed: bool,
    pub ai_zero_upstream_tested: bool,
    pub host_domains_verified: bool,
}
pub fn production_doctor(
    profile: &ResourceProfile,
    evidence: &ProductionEvidence,
) -> Vec<&'static str> {
    let mut missing = vec![];
    if profile.validate().is_err() {
        missing.push("resource_budget");
    }
    if profile.max_contiguous_monitor_work_us.is_none_or(|n| n == 0) {
        missing.push("contiguous_work_budget");
    }
    for (ok, name) in [
        (evidence.source_admission_tested, "source_admission"),
        (evidence.per_path_disabled_at_source, "summary_only"),
        (evidence.independent_watchdog_receipt, "independent_watchdog"),
        (evidence.mtls_acl_tested, "mtls_acl"),
        (evidence.cgroup_effective_verified, "effective_resources"),
        (evidence.validator_core_tested, "validator_core"),
        (evidence.observer_coverage_tested, "observer_coverage"),
        (evidence.performance_profile_passed, "performance"),
        (evidence.ai_zero_upstream_tested, "zero_upstream"),
        (evidence.host_domains_verified, "failure_domains"),
    ] {
        if !ok {
            missing.push(name);
        }
    }
    missing
}
