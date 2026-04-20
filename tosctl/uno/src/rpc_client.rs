//! Async JSON-RPC 2.0 client for the `uno_*` namespace (§9).
//!
//! Minimal shape — one `call(method, params)` entry point and typed wrappers
//! for the methods the wallet actually uses. Extends cleanly when a future
//! `send` command needs `uno_sendTransfer` / `uno_getTransactionStatus`.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

/// Default JSON-RPC endpoint path appended to the host URL.
pub const DEFAULT_ENDPOINT: &str = "/jsonrpc";

#[derive(Clone)]
pub struct RpcClient {
    base_url: String,
    http: reqwest::Client,
}

impl RpcClient {
    /// `base_url` should be e.g. `http://localhost:8080`; this client appends
    /// `DEFAULT_ENDPOINT` if the URL does not already contain a path.
    pub fn new(base_url: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("building reqwest client")?;
        let base_url = if base_url.contains("/jsonrpc") || base_url.ends_with('/') {
            base_url.trim_end_matches('/').to_string()
        } else {
            format!("{}{}", base_url.trim_end_matches('/'), DEFAULT_ENDPOINT)
        };
        Ok(Self { base_url, http })
    }

    /// Generic JSON-RPC call. Returns the raw `result` value on success.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp = self.http.post(&self.base_url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {}", self.base_url))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("HTTP {status} from {method}: {text}"));
        }
        let envelope: RpcEnvelope = resp.json().await
            .with_context(|| format!("decoding JSON-RPC response from {method}"))?;

        if let Some(err) = envelope.error {
            return Err(anyhow!("RPC error {}: {}", err.code, err.message));
        }
        envelope.result
            .ok_or_else(|| anyhow!("RPC response from {method} had neither result nor error"))
    }

    // -----------------------------------------------------------------------
    // Typed wrappers (subset used by foundation wallet)
    // -----------------------------------------------------------------------

    /// `uno_chainInfo()`.
    pub async fn chain_info(&self) -> Result<ChainInfo> {
        let v = self.call("uno_chainInfo", json!([])).await?;
        serde_json::from_value(v).context("decoding ChainInfo")
    }

    /// `uno_getBlockFilter(seqno)` — returns the raw GCS filter bytes.
    pub async fn get_block_filter(&self, seqno: u64) -> Result<Vec<u8>> {
        let v = self.call("uno_getBlockFilter", json!([seqno])).await?;
        let s: String = serde_json::from_value(v)
            .context("get_block_filter: expected hex string")?;
        hex::decode(s.trim_start_matches("0x"))
            .context("decoding filter hex")
    }

    /// `uno_getOutputsAtBlock(seqno, from_index, limit)`. Returns the raw
    /// wire bytes of each `OutputDescription` (hex-encoded in the envelope).
    pub async fn get_outputs_at_block(
        &self,
        seqno: u64,
        from_index: u64,
        limit: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let v = self.call(
            "uno_getOutputsAtBlock",
            json!([seqno, from_index, limit]),
        ).await?;
        let raw: Vec<String> = serde_json::from_value(v)
            .context("get_outputs_at_block: expected array of hex strings")?;
        raw.into_iter()
            .map(|s| hex::decode(s.trim_start_matches("0x"))
                .context("decoding output hex"))
            .collect()
    }

    /// `uno_getNullifierStatus(nf_hex)`.
    pub async fn get_nullifier_status(&self, nf: &[u8; 32]) -> Result<NullifierStatus> {
        let v = self.call(
            "uno_getNullifierStatus",
            json!([hex::encode(nf)]),
        ).await?;
        serde_json::from_value(v).context("decoding NullifierStatus")
    }
}

#[derive(Debug, Deserialize)]
struct RpcEnvelope {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError { code: i64, message: String }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChainInfo {
    pub chain_id: u32,
    pub workchain_id: u32,
    pub head_seqno: u64,
    #[serde(default)]
    pub executor: Option<String>,
    #[serde(default)]
    pub active_schemes: Vec<u32>,
    #[serde(default)]
    pub anchor_window_size: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NullifierStatus {
    pub spent: bool,
    #[serde(default)]
    pub block_seqno: Option<u64>,
}
