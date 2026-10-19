use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Healthy,
    Warning,
    Critical,
    Unknown,
}
#[derive(Debug, Clone, Serialize)]
pub struct Incident {
    pub severity: Severity,
    pub last_known: Severity,
    pub evidence_missing: bool,
    pub active: bool,
}
impl Default for Incident {
    fn default() -> Self {
        Self {
            severity: Severity::Unknown,
            last_known: Severity::Unknown,
            evidence_missing: true,
            active: false,
        }
    }
}
impl Incident {
    pub fn observe(&mut self, observation: Severity, usable: bool) {
        if !usable || observation == Severity::Unknown {
            self.evidence_missing = true;
            self.severity = Severity::Unknown;
            return; // absence cannot resolve an active incident
        }
        self.evidence_missing = false;
        self.last_known = observation;
        self.severity = observation;
        self.active = observation != Severity::Healthy;
    }
}
