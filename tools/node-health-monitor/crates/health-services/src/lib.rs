use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Read, net::SocketAddr, path::Path, time::Duration};
use subtle::ConstantTimeEq;
pub mod collector;
pub mod edge;
pub mod manager_query_source;
#[cfg(feature = "mcp")]
pub mod mcp_bridge;
pub mod observability;
pub mod query_ledger;
pub mod transit;
pub mod witness;

pub fn secret(path: &Path) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || metadata.len() > 4096 {
        return Err("secret file must be a private regular file".into());
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| "secret must be ASCII")?.trim().as_bytes().to_vec();
    if text.len() < 32 || !text.iter().all(|b| b.is_ascii_graphic()) {
        return Err("secret must have at least 32 non-whitespace ASCII bytes".into());
    }
    Ok(text)
}
pub fn authorized(header: Option<&str>, expected: &[u8]) -> bool {
    let Some(value) = header.and_then(|v| v.strip_prefix("Bearer ")) else {
        return false;
    };
    Sha256::digest(value.as_bytes()).ct_eq(&Sha256::digest(expected)).into()
}
pub fn random_token() -> Result<[u8; 32], String> {
    let mut token = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut token))
        .map_err(|e| e.to_string())?;
    Ok(token)
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn decode_token(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut token = [0; 32];
    for (i, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(token)
}
pub fn alias(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(b))
}
pub fn loopback(value: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = value.parse().map_err(|_| "invalid listen address")?;
    if !addr.ip().is_loopback() {
        return Err("direct listeners must be loopback; use the approved mTLS ingress".into());
    }
    Ok(addr)
}
pub fn client(ca_file: &Path, identity_file: &Path) -> Result<reqwest::Client, String> {
    let ca = std::fs::read(ca_file).map_err(|e| e.to_string())?;
    let identity = std::fs::read(identity_file).map_err(|e| e.to_string())?;
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .pool_max_idle_per_host(1)
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).map_err(|e| e.to_string())?)
        .identity(reqwest::Identity::from_pem(&identity).map_err(|e| e.to_string())?)
        .build()
        .map_err(|e| e.to_string())
}
pub async fn bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, String> {
    if !response.status().is_success() {
        return Err(format!("upstream HTTP {}", response.status()));
    }
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err("upstream response too large".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err("upstream response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub network_id: String,
    pub nodes: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
}
impl Inventory {
    pub fn validate(&self) -> Result<(), String> {
        if self.network_id.len() != 64
            || !self.network_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.nodes.is_empty()
            || self.nodes.len() > 1024
            || self.scopes.is_empty()
            || self.scopes.len() > 8
            || !self.nodes.iter().all(|v| alias(v))
            || !self.scopes.iter().all(|v| alias(v))
        {
            return Err("invalid inventory".into());
        }
        Ok(())
    }
}

/// Reject excess work before handlers acquire cache locks; do not queue it.
pub async fn limit_requests(
    axum::extract::State(limit): axum::extract::State<std::sync::Arc<tokio::sync::Semaphore>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(_permit) = limit.try_acquire_owned() else {
        return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    next.run(request).await
}
pub mod diagnostic_ingest;
pub mod diagnostic_ipc;
pub mod diagnostic_relay;
pub mod diagnostic_transport;
pub mod durable;

pub mod ingress;
pub mod manager;
pub mod manager_poll;
pub mod native_cache;
pub mod watchdog;
