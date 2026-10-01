//! Chat-completions-compatible model provider behind a configuration gate.
//! The adapter contacts only the configured private endpoint, never follows
//! a redirect, never retries a transport failure, repairs an invalid reply at
//! most once and reports every other failure as a rules-only outcome. An
//! HTTP 200, an SSE stream or a `[DONE]` marker is never taken as success on
//! its own; only a diagnosis that passes the closed validator is returned.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeSet, time::Duration};
use tos_health_core::diagnosis::Diagnosis;

pub const PROFILE_CHAT_COMPLETIONS: &str = "chat_completions";
pub const EGRESS_PRIVATE_ONLY: &str = "private_only";
const MAX_RESPONSE_BYTES: usize = 32_768;
const MAX_INPUT_BYTES: usize = 16_384 + 4_096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub enabled: bool,
    pub profile: String,
    pub base_url: String,
    pub model: String,
    pub egress: String,
    pub api_key_env: Option<String>,
    pub timeout_seconds: u32,
    pub max_output_tokens: u32,
}

impl ProviderConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.profile != PROFILE_CHAT_COMPLETIONS {
            return Err("unsupported provider profile".into());
        }
        if self.egress != EGRESS_PRIVATE_ONLY {
            return Err("only private_only egress is implemented".into());
        }
        if self.model.is_empty() || self.model.len() > 128 {
            return Err("invalid model id".into());
        }
        if !(1..=60).contains(&self.timeout_seconds) {
            return Err("timeout must be 1..60 seconds".into());
        }
        if !(1..=1536).contains(&self.max_output_tokens) {
            return Err("max_output_tokens must be 1..1536".into());
        }
        if self.api_key_env.as_ref().is_some_and(|name| {
            name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        }) {
            return Err("invalid api key environment name".into());
        }
        private_only_url(&self.base_url).map(|_| ())
    }
}

/// The endpoint must be a loopback, private or link-local IP literal or
/// `localhost`. Any public address or DNS name is refused before a socket
/// exists, so a misconfiguration cannot leak the evidence package.
pub fn private_only_url(base_url: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(base_url).map_err(|_| "invalid provider URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("provider URL must be http or https".into());
    }
    if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() {
        return Err("provider URL must not carry query, fragment or credentials".into());
    }
    let host = url.host_str().ok_or("provider URL has no host")?;
    let literal = host.trim_start_matches('[').trim_end_matches(']');
    let private = match literal.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Ok(std::net::IpAddr::V6(ip)) => {
            let first = ip.segments()[0];
            ip.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    };
    if !private {
        return Err("provider host is not a private or loopback address".into());
    }
    Ok(url)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Disabled,
    EgressRefused(String),
    /// Connection, timeout, redirect or stream error. Never retried.
    TransportFailed(String),
    HttpStatus(u16),
    Refusal,
    Incomplete,
    /// Still invalid after exactly one format-repair request.
    InvalidJson(String),
    Diagnosis(Diagnosis),
}

impl Outcome {
    /// Everything except a validated diagnosis leaves the run rules-only.
    pub fn rules_only(&self) -> bool {
        !matches!(self, Self::Diagnosis(_))
    }
}

pub struct Report {
    pub outcome: Outcome,
    pub requests: u32,
}

fn extract_json(body: &[u8]) -> Result<String, Outcome> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| Outcome::InvalidJson("provider body is not JSON".into()))?;
    if value.get("error").is_some() {
        return Err(Outcome::TransportFailed("provider error object".into()));
    }
    let choice = value.get("choices").and_then(Value::as_array).and_then(|c| c.first());
    let Some(choice) = choice else {
        return Err(Outcome::Incomplete);
    };
    let finish = choice.get("finish_reason").and_then(Value::as_str);
    let message = choice.get("message");
    if finish == Some("content_filter")
        || message.and_then(|m| m.get("refusal")).is_some_and(|r| !r.is_null())
    {
        return Err(Outcome::Refusal);
    }
    let content = message.and_then(|m| m.get("content")).and_then(Value::as_str).unwrap_or("");
    if finish == Some("length") || content.trim().is_empty() {
        return Err(Outcome::Incomplete);
    }
    Ok(content.to_owned())
}

fn extract_sse(body: &[u8]) -> Result<String, Outcome> {
    let text = std::str::from_utf8(body)
        .map_err(|_| Outcome::TransportFailed("stream is not UTF-8".into()))?;
    let mut content = String::new();
    let mut finish: Option<String> = None;
    let mut done = false;
    for line in text.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data == "[DONE]" {
            done = true;
            break;
        }
        let chunk: Value = serde_json::from_str(data)
            .map_err(|_| Outcome::TransportFailed("stream chunk is not JSON".into()))?;
        if chunk.get("error").is_some() {
            return Err(Outcome::TransportFailed("stream error event".into()));
        }
        let Some(choice) = chunk.get("choices").and_then(Value::as_array).and_then(|c| c.first())
        else {
            continue;
        };
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            finish = Some(reason.to_owned());
        }
        if let Some(delta) =
            choice.get("delta").and_then(|d| d.get("content")).and_then(Value::as_str)
        {
            content.push_str(delta);
        }
        if choice.get("delta").and_then(|d| d.get("refusal")).is_some_and(|r| !r.is_null()) {
            return Err(Outcome::Refusal);
        }
    }
    if finish.as_deref() == Some("content_filter") {
        return Err(Outcome::Refusal);
    }
    if !done || finish.as_deref() == Some("length") || content.trim().is_empty() {
        return Err(Outcome::Incomplete);
    }
    Ok(content)
}

/// One diagnosis attempt against the configured private endpoint. The
/// evidence package is the only user content; the delivered id set is what
/// the returned diagnosis may cite.
pub async fn diagnose(
    config: &ProviderConfig,
    system_prompt: &str,
    package: &[u8],
    delivered: &BTreeSet<String>,
) -> Report {
    if !config.enabled {
        return Report { outcome: Outcome::Disabled, requests: 0 };
    }
    if let Err(error) = config.validate() {
        return Report { outcome: Outcome::EgressRefused(error), requests: 0 };
    }
    let url = match private_only_url(&config.base_url) {
        Ok(url) => url,
        Err(error) => return Report { outcome: Outcome::EgressRefused(error), requests: 0 },
    };
    let Ok(endpoint) = url.join("v1/chat/completions") else {
        return Report {
            outcome: Outcome::EgressRefused("invalid endpoint path".into()),
            requests: 0,
        };
    };
    if package.len() > MAX_INPUT_BYTES || system_prompt.len() > 4_096 {
        return Report {
            outcome: Outcome::EgressRefused("prompt exceeds input bound".into()),
            requests: 0,
        };
    }
    let Ok(package_text) = std::str::from_utf8(package) else {
        return Report {
            outcome: Outcome::EgressRefused("package is not UTF-8".into()),
            requests: 0,
        };
    };
    let api_key = match &config.api_key_env {
        Some(name) => match std::env::var(name) {
            Ok(value) if !value.is_empty() => Some(value),
            _ => {
                return Report {
                    outcome: Outcome::TransportFailed("api key unavailable".into()),
                    requests: 0,
                }
            }
        },
        None => None,
    };
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(u64::from(config.timeout_seconds)))
        .pool_max_idle_per_host(1)
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return Report { outcome: Outcome::TransportFailed(error.to_string()), requests: 0 }
        }
    };
    let mut messages = vec![
        json!({"role":"system","content":system_prompt}),
        json!({"role":"user","content":package_text}),
    ];
    let mut requests = 0u32;
    loop {
        let body = json!({
            "model": config.model,
            "messages": messages,
            "max_tokens": config.max_output_tokens,
            "temperature": 0,
            "stream": false,
        });
        let mut request = client.post(endpoint.clone()).json(&body);
        if let Some(key) = &api_key {
            request = request.bearer_auth(key);
        }
        requests = requests.saturating_add(1);
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                let reason = if error.is_timeout() { "timeout" } else { "connection failed" };
                return Report { outcome: Outcome::TransportFailed(reason.into()), requests };
            }
        };
        let status = response.status();
        if status.is_redirection() {
            return Report { outcome: Outcome::HttpStatus(status.as_u16()), requests };
        }
        if !status.is_success() {
            return Report { outcome: Outcome::HttpStatus(status.as_u16()), requests };
        }
        let streamed = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().starts_with("text/event-stream"));
        let bytes = match crate::bounded_body(response, MAX_RESPONSE_BYTES).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return Report {
                    outcome: Outcome::TransportFailed("response exceeded 32 KiB or failed".into()),
                    requests,
                }
            }
        };
        let content = match if streamed { extract_sse(&bytes) } else { extract_json(&bytes) } {
            Ok(content) => content,
            Err(outcome) => return Report { outcome, requests },
        };
        match Diagnosis::parse(content.as_bytes(), delivered) {
            Ok(diagnosis) => return Report { outcome: Outcome::Diagnosis(diagnosis), requests },
            Err(reason) if requests == 1 => {
                // Exactly one format repair, without tools and within the
                // same run; the model sees only why its reply was refused.
                messages.push(json!({"role":"assistant","content":content}));
                messages.push(json!({"role":"user","content":format!(
                    "The previous reply was refused: {reason}. Reply with exactly one JSON object matching the approved diagnosis schema and nothing else."
                )}));
            }
            Err(reason) => {
                return Report { outcome: Outcome::InvalidJson(reason.into()), requests }
            }
        }
    }
}
