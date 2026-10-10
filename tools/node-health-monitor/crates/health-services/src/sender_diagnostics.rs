//! Bounded delivery diagnostics shared by the lanes of one scheduled sender.
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};
use tos_health_core::rules::FactFrame;

const REPORT_INTERVAL: Duration = Duration::from_secs(60);
const MAX_UNRESOLVED_LANES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryFailure {
    Http(u16),
    Timeout,
    Connect,
    Transport,
    Body,
}

impl DeliveryFailure {
    fn category(self) -> &'static str {
        match self {
            Self::Http(429) => "rate_limit",
            Self::Http(400..=499) => "http_client_error",
            Self::Http(500..=599) => "http_server_error",
            Self::Http(_) => "http_non_success",
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Transport => "transport",
            Self::Body => "response_body",
        }
    }
}

/// A success resolves only its own lane. Emission time is never reset by
/// recovery, so alternating success/failure cannot bypass the sender budget.
pub struct SenderDiagnostics {
    last_emission: Option<Instant>,
    unresolved: BTreeSet<(String, String)>,
    unresolved_overflow: bool,
    failures: u64,
    last_failure: Option<DeliveryFailure>,
    recovery_pending: bool,
}

impl Default for SenderDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

impl SenderDiagnostics {
    pub fn new() -> Self {
        Self {
            last_emission: None,
            unresolved: BTreeSet::new(),
            unresolved_overflow: false,
            failures: 0,
            last_failure: None,
            recovery_pending: false,
        }
    }

    pub fn observe(
        &mut self,
        node: &str,
        source: &str,
        outcome: Result<(), DeliveryFailure>,
        now: Instant,
    ) -> Option<String> {
        // The lane keys are aliases, not URLs, epochs, generations or errors.
        // If the lane bound is exceeded recovery becomes unknown rather than
        // claiming all deliveries recovered after discarding a failed lane.
        let key = if crate::alias(node) && crate::alias(source) {
            Some((node.to_owned(), source.to_owned()))
        } else {
            None
        };
        match outcome {
            Err(failure) => {
                self.failures = self.failures.saturating_add(1);
                self.last_failure = Some(failure);
                self.recovery_pending = false;
                if let Some(key) = key {
                    if self.unresolved.len() < MAX_UNRESOLVED_LANES
                        || self.unresolved.contains(&key)
                    {
                        self.unresolved.insert(key);
                    } else {
                        self.unresolved_overflow = true;
                    }
                } else {
                    self.unresolved_overflow = true;
                }
            }
            Ok(()) => {
                if let Some(key) = key {
                    let removed = self.unresolved.remove(&key);
                    if removed && self.unresolved.is_empty() && !self.unresolved_overflow {
                        self.recovery_pending = true;
                    }
                }
            }
        }
        if (self.failures == 0 && !self.recovery_pending)
            || self
                .last_emission
                .is_some_and(|last| now.saturating_duration_since(last) < REPORT_INTERVAL)
        {
            return None;
        }
        self.last_emission = Some(now);
        let category = self.last_failure.map(DeliveryFailure::category).unwrap_or("none");
        let status = match self.last_failure {
            Some(DeliveryFailure::Http(status)) => status.to_string(),
            _ => "none".into(),
        };
        let report = format!(
            "manager delivery: failures={} last_category={category} last_http_status={status} unresolved_lanes={} recovery={}",
            self.failures,
            self.unresolved.len(),
            if self.unresolved_overflow { "unknown" } else if self.unresolved.is_empty() { "complete" } else { "pending" },
        );
        self.failures = 0;
        self.recovery_pending = false;
        Some(report)
    }
}

pub async fn deliver_frame(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    frame: &FactFrame,
    retry_429: bool,
) -> Result<(), DeliveryFailure> {
    for attempt in 0..2u8 {
        let response =
            client.post(url).bearer_auth(token).json(frame).send().await.map_err(|error| {
                if error.is_timeout() {
                    DeliveryFailure::Timeout
                } else if error.is_connect() {
                    DeliveryFailure::Connect
                } else {
                    DeliveryFailure::Transport
                }
            })?;
        let status = response.status();
        let body = crate::bounded_body(response, 4096).await;
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS && retry_429 && attempt == 0 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        }
        if !status.is_success() {
            return Err(DeliveryFailure::Http(status.as_u16()));
        }
        return body.map(|_| ()).map_err(|_| DeliveryFailure::Body);
    }
    Err(DeliveryFailure::Transport)
}

pub async fn send_reported(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    frame: &FactFrame,
    retry_429: bool,
    diagnostics: &mut SenderDiagnostics,
    sender: &str,
) {
    let outcome = deliver_frame(client, url, token, frame, retry_429).await;
    if let Some(report) =
        diagnostics.observe(&frame.node_id, &frame.source_id, outcome, Instant::now())
    {
        eprintln!("{sender}: {report}");
    }
}
