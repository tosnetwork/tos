use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    Observed,
    Hypothesis,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub claim: String,
    pub basis: Basis,
    pub evidence_ids: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosisStatus {
    Analysis,
    InsufficientEvidence,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnosis {
    pub status: DiagnosisStatus,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub missing_evidence: Vec<String>,
    pub recommended_runbooks: Vec<String>,
}
impl Diagnosis {
    pub fn parse(bytes: &[u8], delivered: &BTreeSet<String>) -> Result<Self, &'static str> {
        if bytes.len() > 16_384 {
            return Err("diagnosis too large");
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| "invalid diagnosis JSON")?;
        if value.summary.len() > 2000
            || value.findings.len() > 6
            || value.missing_evidence.len() > 16
            || value.missing_evidence.iter().any(|v| v.len() > 256)
            || value.recommended_runbooks.len() > 6
        {
            return Err("diagnosis size limit");
        }
        let allowed = [
            "inspect_duty_accounting",
            "inspect_persistence_progress",
            "inspect_consensus_queues",
            "inspect_storage_pressure",
            "inspect_quic_backlog",
            "inspect_observer_coverage",
            "inspect_telemetry_unavailable",
            "inspect_ai_unavailable",
        ];
        if value.recommended_runbooks.iter().collect::<BTreeSet<_>>().len()
            != value.recommended_runbooks.len()
            || value.recommended_runbooks.iter().any(|r| !allowed.contains(&r.as_str()))
        {
            return Err("unapproved runbook");
        }
        for finding in &value.findings {
            if finding.claim.is_empty()
                || finding.claim.len() > 1000
                || finding.evidence_ids.len() > 8
                || finding.evidence_ids.iter().collect::<BTreeSet<_>>().len()
                    != finding.evidence_ids.len()
            {
                return Err("invalid finding");
            }
            if matches!(finding.basis, Basis::Observed) && finding.evidence_ids.is_empty() {
                return Err("observation without evidence");
            }
            if finding.evidence_ids.iter().any(|id| !delivered.contains(id)) {
                return Err("evidence not delivered in run");
            }
        }
        Ok(value)
    }
}
