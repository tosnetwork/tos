/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::v2::data_models::{
    AccountAgentCapability, AccountCapabilityRes, AccountDelegationGrant, AccountSessionCapability,
    GetAddressInformationRes, GetBlockTransactionsRes, GetExtendedAddressInformationRes,
    GetMasterchainInfoRes, GetShardsRes, GetTransactionsRes, GetWalletInformationRes,
    LifecycleGrantRequest, LifecycleMutationResultRes, LifecycleRevokeRequest, RunGetMethodParams,
    RunGetMethodRes, SigningPayloadRes, SubmissionResultRes, TransactionIntentRes,
};
use anyhow::Context;
use base64::Engine;
use chain_block::{ConfigParamEnum, MsgAddressInt, read_boc};
use chain_rpc_rs::client::{ApiClientV2, ApiKey, Network};
use std::{
    collections::HashSet,
    sync::atomic::{AtomicUsize, Ordering},
};

struct EndpointClient {
    url: String,
    client: ApiClientV2,
}

pub struct ClientJsonRpc {
    api_key: Option<String>,
    endpoints: Vec<EndpointClient>,
    rr_cursor: AtomicUsize,
}

impl ClientJsonRpc {
    pub fn connect(url: String, api_key: Option<String>) -> anyhow::Result<Self> {
        Self::connect_many(vec![(url, None)], api_key)
    }

    /// Builds a failover client from one or more endpoint entries.
    ///
    /// Each entry is a `(url, per_endpoint_api_key)` pair. When the
    /// per-endpoint key is `None`, the `default_api_key` is used instead.
    ///
    /// This constructor is defensive: it trims inputs, drops empty values and
    /// deduplicates URLs while preserving order. Callers should normally pass
    /// pre-normalized values from `ChainRpcConfig::resolved_endpoints()`,
    /// but this method still tolerates duplicates for safety.
    pub fn connect_many(
        entries: Vec<(String, Option<String>)>,
        default_api_key: Option<String>,
    ) -> anyhow::Result<Self> {
        let mut seen = HashSet::with_capacity(entries.len());
        let mut unique: Vec<(String, Option<String>)> = Vec::with_capacity(entries.len());
        for (url, key) in entries {
            let url_trimmed = url.trim().to_string();
            if url_trimmed.is_empty() {
                continue;
            }
            if !seen.insert(url_trimmed.clone()) {
                continue;
            }
            unique.push((url_trimmed, key));
        }

        if unique.is_empty() {
            anyhow::bail!("No chain-rpc endpoints configured");
        }

        let endpoints = unique
            .into_iter()
            .map(|(url, per_key)| {
                let effective_key = per_key.as_ref().or(default_api_key.as_ref());
                EndpointClient {
                    client: ApiClientV2::new(
                        Network::Custom(url.clone()),
                        effective_key.map(|v| ApiKey::Header(v.to_string())),
                    ),
                    url,
                }
            })
            .collect::<Vec<_>>();

        Ok(ClientJsonRpc { api_key: default_api_key, endpoints, rr_cursor: AtomicUsize::new(0) })
    }

    pub fn api_key(&self) -> Option<String> {
        self.api_key.clone()
    }

    pub fn url(&self) -> &str {
        &self.endpoints[0].url
    }

    pub fn urls(&self) -> Vec<String> {
        self.endpoints.iter().map(|e| e.url.clone()).collect()
    }

    /// Executes a JSON-RPC call with round-robin failover across all endpoints.
    ///
    /// Algorithm:
    /// 1. An atomic cursor picks a per-request start endpoint so that
    ///    successive calls are spread across endpoints in round-robin order.
    /// 2. Starting from that endpoint, each endpoint is tried once in
    ///    cyclic order until one succeeds or all have been exhausted.
    /// 3. On success the response is returned immediately; on total failure
    ///    the last error is propagated.
    async fn json_rpc(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let total = self.endpoints.len();
        let start = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % total;
        let request_id = serde_json::json!(uuid::Uuid::new_v4().to_string());
        let mut last_error: Option<anyhow::Error> = None;

        for attempt in 0..total {
            let idx = (start + attempt) % total;
            let endpoint = &self.endpoints[idx];
            match endpoint.client.json_rpc(method, params.clone(), request_id.clone()).await {
                Ok(response) => {
                    if attempt > 0 {
                        tracing::debug!(
                            method,
                            used_endpoint = %endpoint.url,
                            attempt = attempt + 1,
                            "chain-rpc failover succeeded"
                        );
                    }
                    return Ok(response);
                }
                Err(err) => {
                    tracing::debug!(
                        method,
                        endpoint = %endpoint.url,
                        attempt = attempt + 1,
                        total_attempts = total,
                        error = %err,
                        "chain-rpc request failed"
                    );
                    last_error = Some(anyhow::Error::from(err));
                }
            }
        }

        if let Some(err) = last_error {
            Err(err.context(format!("all endpoints ({}) failed", total)))
        } else {
            anyhow::bail!("request failed")
        }
    }

    pub async fn get_config_param(&self, param_id: u32) -> anyhow::Result<ConfigParamEnum> {
        let json_params: serde_json::Value = serde_json::json!({
            "config_id": param_id,
        });

        let config_info = self
            .json_rpc("getConfigParam", json_params)
            .await
            .with_context(|| format!("getConfigParam({})", param_id))?;

        let b64 = config_info
            .get("config")
            .and_then(|c| c.get("bytes"))
            .or_else(|| {
                config_info.get("result").and_then(|r| r.get("config")).and_then(|c| c.get("bytes"))
            })
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!(r#"missing "config.bytes" string"#))?;

        let boc = base64::engine::general_purpose::STANDARD.decode(b64)?;
        let cell = read_boc(boc)?.withdraw_single_root()?;

        let config_param = ConfigParamEnum::construct_from_cell_and_number(cell, param_id)?;
        Ok(config_param)
    }

    pub async fn run_get_method(
        &self,
        args: &RunGetMethodParams,
    ) -> anyhow::Result<RunGetMethodRes> {
        let json_params = serde_json::json!(args);
        let json_params_str = json_params.to_string();
        let res = self.json_rpc("runGetMethodStd", json_params).await.map_err(|e| {
            anyhow::anyhow!("Request `runGetMethodStd({})` return error: {}", json_params_str, e)
        })?;

        let run_get_method_res = serde_json::from_value::<RunGetMethodRes>(res)?;

        Ok(run_get_method_res)
    }

    pub async fn send_boc(&self, boc: &Vec<u8>) -> anyhow::Result<()> {
        let json_params = serde_json::json!({
            "boc": base64::engine::general_purpose::STANDARD.encode(boc)
        });
        let json_params_str = json_params.to_string();
        let _ = self.json_rpc("sendBoc", json_params).await.map_err(|e| {
            anyhow::anyhow!("Request `sendBoc({})` return error: {}", json_params_str, e)
        })?;

        Ok(())
    }

    pub async fn get_extended_address_information(
        &self,
        address: &MsgAddressInt,
    ) -> anyhow::Result<GetExtendedAddressInformationRes> {
        let json_params = serde_json::json!({
            "address": address.to_string(),
        });
        let json_params_str = json_params.to_string();
        let res =
            self.json_rpc("getExtendedAddressInformation", json_params).await.map_err(|e| {
                anyhow::anyhow!(
                    "Request `getExtendedAddressInformation({})` return error: {}",
                    json_params_str,
                    e
                )
            })?;

        let get_extended_address_information_res =
            serde_json::from_value::<GetExtendedAddressInformationRes>(res)?;

        Ok(get_extended_address_information_res)
    }

    pub async fn get_address_information(
        &self,
        address: &MsgAddressInt,
    ) -> anyhow::Result<GetAddressInformationRes> {
        let json_params = serde_json::json!({
            "address": address.to_string(),
        });
        let json_params_str = json_params.to_string();
        let res = self.json_rpc("getAddressInformation", json_params).await.map_err(|e| {
            anyhow::anyhow!(
                "Request `getAddressInformation({})` return error: {}",
                json_params_str,
                e
            )
        })?;
        let address_info = serde_json::from_value::<GetAddressInformationRes>(res)?;
        Ok(address_info)
    }

    pub async fn get_account_capability(
        &self,
        address: &MsgAddressInt,
        seqno: Option<u32>,
        include_experimental: bool,
    ) -> anyhow::Result<AccountCapabilityRes> {
        let mut json_params = serde_json::json!({
            "address": address.to_string(),
        });
        if let Some(seqno) = seqno {
            json_params["seqno"] = serde_json::json!(seqno);
        }
        if include_experimental {
            json_params["include_experimental"] = serde_json::json!(true);
        }
        let json_params_str = json_params.to_string();
        let res = self.json_rpc("getAccountCapability", json_params).await.map_err(|e| {
            anyhow::anyhow!(
                "Request `getAccountCapability({})` return error: {}",
                json_params_str,
                e
            )
        })?;
        Ok(serde_json::from_value::<AccountCapabilityRes>(res)?)
    }

    pub async fn get_account_delegations(
        &self,
        address: &MsgAddressInt,
        include_inactive: bool,
        status: Option<&str>,
        source_tier: Option<&str>,
    ) -> anyhow::Result<Vec<AccountDelegationGrant>> {
        let mut json_params = serde_json::json!({
            "address": address.to_string(),
            "include_inactive": include_inactive,
        });
        if let Some(s) = status {
            json_params["status"] = serde_json::json!(s);
        }
        if let Some(t) = source_tier {
            json_params["source_tier"] = serde_json::json!(t);
        }
        let json_params_str = json_params.to_string();
        let res = self.json_rpc("getAccountDelegations", json_params).await.map_err(|e| {
            anyhow::anyhow!(
                "Request `getAccountDelegations({})` return error: {}",
                json_params_str,
                e
            )
        })?;
        Ok(serde_json::from_value::<Vec<AccountDelegationGrant>>(res)?)
    }

    pub async fn get_account_sessions(
        &self,
        address: &MsgAddressInt,
        include_inactive: bool,
        status: Option<&str>,
        source_tier: Option<&str>,
    ) -> anyhow::Result<Vec<AccountSessionCapability>> {
        let mut json_params = serde_json::json!({
            "address": address.to_string(),
            "include_inactive": include_inactive,
        });
        if let Some(s) = status {
            json_params["status"] = serde_json::json!(s);
        }
        if let Some(t) = source_tier {
            json_params["source_tier"] = serde_json::json!(t);
        }
        let json_params_str = json_params.to_string();
        let res = self.json_rpc("getAccountSessions", json_params).await.map_err(|e| {
            anyhow::anyhow!("Request `getAccountSessions({})` return error: {}", json_params_str, e)
        })?;
        Ok(serde_json::from_value::<Vec<AccountSessionCapability>>(res)?)
    }

    pub async fn get_account_agents(
        &self,
        address: &MsgAddressInt,
        include_inactive: bool,
        status: Option<&str>,
        source_tier: Option<&str>,
    ) -> anyhow::Result<Vec<AccountAgentCapability>> {
        let mut json_params = serde_json::json!({
            "address": address.to_string(),
            "include_inactive": include_inactive,
        });
        if let Some(s) = status {
            json_params["status"] = serde_json::json!(s);
        }
        if let Some(t) = source_tier {
            json_params["source_tier"] = serde_json::json!(t);
        }
        let json_params_str = json_params.to_string();
        let res = self.json_rpc("getAccountAgents", json_params).await.map_err(|e| {
            anyhow::anyhow!("Request `getAccountAgents({})` return error: {}", json_params_str, e)
        })?;
        Ok(serde_json::from_value::<Vec<AccountAgentCapability>>(res)?)
    }

    // ─── New methods for P0 operator commands ──────────────────────────

    pub async fn get_masterchain_info(&self) -> anyhow::Result<GetMasterchainInfoRes> {
        let res = self
            .json_rpc("getMasterchainInfo", serde_json::json!({}))
            .await
            .context("getMasterchainInfo")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        lt: u64,
        hash: &str,
        limit: u32,
    ) -> anyhow::Result<GetTransactionsRes> {
        let res = self
            .json_rpc(
                "getTransactions",
                serde_json::json!({
                    "address": address.to_string(),
                    "lt": lt.to_string(),
                    "hash": hash,
                    "limit": limit,
                }),
            )
            .await
            .context("getTransactions")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn get_address_balance(&self, address: &MsgAddressInt) -> anyhow::Result<String> {
        let res = self
            .json_rpc("getAddressBalance", serde_json::json!({"address": address.to_string()}))
            .await
            .context("getAddressBalance")?;
        // Response is just a quoted string like "1234567"
        res.as_str().map(|s| s.to_string()).ok_or_else(|| {
            anyhow::anyhow!("get_address_balance: expected string response, got: {}", res)
        })
    }

    pub async fn get_address_state(&self, address: &MsgAddressInt) -> anyhow::Result<String> {
        let res = self
            .json_rpc("getAddressState", serde_json::json!({"address": address.to_string()}))
            .await
            .context("getAddressState")?;
        res.as_str().map(|s| s.to_string()).ok_or_else(|| {
            anyhow::anyhow!("get_address_state: expected string response, got: {}", res)
        })
    }

    pub async fn get_shards(&self, seqno: u32) -> anyhow::Result<GetShardsRes> {
        let res =
            self.json_rpc("shards", serde_json::json!({"seqno": seqno})).await.context("shards")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn get_block_transactions(
        &self,
        workchain: i32,
        shard: &str,
        seqno: u32,
        count: u32,
    ) -> anyhow::Result<GetBlockTransactionsRes> {
        self.get_block_transactions_page(workchain, shard, seqno, None, None, count).await
    }

    /// Like [`Self::get_block_transactions`], but supports the `after_lt`/
    /// `after_hash` pagination cursor for blocks whose transaction count
    /// exceeds `count` (signalled by `incomplete: true` in the response).
    pub async fn get_block_transactions_page(
        &self,
        workchain: i32,
        shard: &str,
        seqno: u32,
        after_lt: Option<u64>,
        after_hash: Option<&str>,
        count: u32,
    ) -> anyhow::Result<GetBlockTransactionsRes> {
        let mut params = serde_json::json!({
            "workchain": workchain,
            "shard": shard,
            "seqno": seqno,
            "count": count,
        });
        if let Some(lt) = after_lt {
            params["after_lt"] = serde_json::json!(lt.to_string());
        }
        if let Some(hash) = after_hash {
            params["after_hash"] = serde_json::json!(hash);
        }
        let res =
            self.json_rpc("getBlockTransactions", params).await.context("getBlockTransactions")?;
        Ok(serde_json::from_value(res)?)
    }

    // ─── Transaction surface methods ────────────────────────────────

    pub async fn build_transaction_intent(
        &self,
        address: &str,
        body: &str,
        init_code: Option<&str>,
        init_data: Option<&str>,
    ) -> anyhow::Result<TransactionIntentRes> {
        let mut json_params = serde_json::json!({
            "address": address,
            "body": body,
        });
        if let Some(code) = init_code {
            json_params["init_code"] = serde_json::json!(code);
        }
        if let Some(data) = init_data {
            json_params["init_data"] = serde_json::json!(data);
        }
        let res = self
            .json_rpc("buildTransactionIntent", json_params)
            .await
            .context("buildTransactionIntent")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn get_signing_payload(
        &self,
        address: &str,
        body: &str,
        init_code: Option<&str>,
        init_data: Option<&str>,
    ) -> anyhow::Result<SigningPayloadRes> {
        let mut json_params = serde_json::json!({
            "address": address,
            "body": body,
        });
        if let Some(code) = init_code {
            json_params["init_code"] = serde_json::json!(code);
        }
        if let Some(data) = init_data {
            json_params["init_data"] = serde_json::json!(data);
        }
        let res =
            self.json_rpc("getSigningPayload", json_params).await.context("getSigningPayload")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn submit_signed_transaction(
        &self,
        boc: &str,
        signer: Option<&str>,
    ) -> anyhow::Result<SubmissionResultRes> {
        let mut json_params = serde_json::json!({
            "boc": boc,
        });
        if let Some(s) = signer {
            json_params["signer"] = serde_json::json!(s);
        }
        let res = self
            .json_rpc("submitSignedTransaction", json_params)
            .await
            .context("submitSignedTransaction")?;
        Ok(serde_json::from_value(res)?)
    }

    // ─── Lifecycle mutation methods ────────────────────────────────────

    pub async fn grant_account_delegation(
        &self,
        req: &LifecycleGrantRequest,
    ) -> anyhow::Result<LifecycleMutationResultRes> {
        let json_params = serde_json::to_value(req)?;
        let res = self
            .json_rpc("grantAccountDelegation", json_params)
            .await
            .context("grantAccountDelegation")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn revoke_account_delegation(
        &self,
        req: &LifecycleRevokeRequest,
    ) -> anyhow::Result<LifecycleMutationResultRes> {
        let json_params = serde_json::to_value(req)?;
        let res = self
            .json_rpc("revokeAccountDelegation", json_params)
            .await
            .context("revokeAccountDelegation")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn grant_account_session(
        &self,
        req: &LifecycleGrantRequest,
    ) -> anyhow::Result<LifecycleMutationResultRes> {
        let json_params = serde_json::to_value(req)?;
        let res = self
            .json_rpc("grantAccountSession", json_params)
            .await
            .context("grantAccountSession")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn revoke_account_session(
        &self,
        req: &LifecycleRevokeRequest,
    ) -> anyhow::Result<LifecycleMutationResultRes> {
        let json_params = serde_json::to_value(req)?;
        let res = self
            .json_rpc("revokeAccountSession", json_params)
            .await
            .context("revokeAccountSession")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn grant_account_agent(
        &self,
        req: &LifecycleGrantRequest,
    ) -> anyhow::Result<LifecycleMutationResultRes> {
        let json_params = serde_json::to_value(req)?;
        let res =
            self.json_rpc("grantAccountAgent", json_params).await.context("grantAccountAgent")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn revoke_account_agent(
        &self,
        req: &LifecycleRevokeRequest,
    ) -> anyhow::Result<LifecycleMutationResultRes> {
        let json_params = serde_json::to_value(req)?;
        let res =
            self.json_rpc("revokeAccountAgent", json_params).await.context("revokeAccountAgent")?;
        Ok(serde_json::from_value(res)?)
    }

    // ─── Existing methods ────────────────────────────────────────────

    pub async fn get_wallet_information(
        &self,
        address: &MsgAddressInt,
    ) -> anyhow::Result<GetWalletInformationRes> {
        let json_params = serde_json::json!({
            "address": address.to_string(),
        });
        let json_params_str = json_params.to_string();
        let res = self.json_rpc("getWalletInformation", json_params).await.map_err(|e| {
            anyhow::anyhow!(
                "Request `getWalletInformation({})` return error: {}",
                json_params_str,
                e
            )
        })?;
        let wallet_info = serde_json::from_value::<GetWalletInformationRes>(res)?;
        Ok(wallet_info)
    }
}

#[cfg(test)]
mod tests {
    use super::ClientJsonRpc;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn spawn_jsonrpc_ok_server(
        result: serde_json::Value,
        request_count: Arc<AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind async listener");
        let addr = listener.local_addr().expect("listener local addr");
        let response_body = serde_json::json!({
            "ok": true,
            "jsonrpc": "2.0",
            "result": result,
            "id": "1"
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );

        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept connection");
            request_count.fetch_add(1, Ordering::SeqCst);

            let mut buf = [0_u8; 4096];
            let mut acc = Vec::new();
            loop {
                let n = socket.read(&mut buf).await.expect("read request");
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }

            socket.write_all(response.as_bytes()).await.expect("write response");
            socket.shutdown().await.expect("shutdown socket");
        });

        (format!("http://{}", addr), handle)
    }

    async fn spawn_http_500_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind async listener");
        let addr = listener.local_addr().expect("listener local addr");
        let response_body = r#"{"ok":false,"error":"internal error"}"#;
        let response = format!(
            "HTTP/1.1 500 Internal Server Error\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );

        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept connection");

            let mut buf = [0_u8; 4096];
            let mut acc = Vec::new();
            loop {
                let n = socket.read(&mut buf).await.expect("read request");
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }

            socket.write_all(response.as_bytes()).await.expect("write response");
            socket.shutdown().await.expect("shutdown socket");
        });

        (format!("http://{}", addr), handle)
    }

    #[tokio::test]
    async fn json_rpc_failover_uses_second_url_when_first_is_broken() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let (bad_url, bad_server_handle) = spawn_http_500_server().await;
        let (good_url, server_handle) =
            spawn_jsonrpc_ok_server(serde_json::json!({"from":"fallback"}), request_count.clone())
                .await;

        let client = ClientJsonRpc::connect_many(vec![(bad_url, None), (good_url, None)], None)
            .expect("client");

        let response = client
            .json_rpc("getAddressInformation", serde_json::json!({"address":"x"}))
            .await
            .expect("json_rpc should fail over to healthy endpoint");

        assert_eq!(response["from"], "fallback");
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "healthy endpoint should receive one request"
        );
        bad_server_handle.await.expect("bad server task");
        server_handle.await.expect("server task");
    }

    #[tokio::test]
    async fn json_rpc_round_robin_starts_from_first_endpoint() {
        let first_count = Arc::new(AtomicUsize::new(0));
        let second_count = Arc::new(AtomicUsize::new(0));
        let (first_url, first_handle) =
            spawn_jsonrpc_ok_server(serde_json::json!({"from":"first"}), first_count.clone()).await;
        let (second_url, second_handle) =
            spawn_jsonrpc_ok_server(serde_json::json!({"from":"second"}), second_count.clone())
                .await;

        let client = ClientJsonRpc::connect_many(vec![(first_url, None), (second_url, None)], None)
            .expect("client");

        let first_response = client
            .json_rpc("getAddressInformation", serde_json::json!({"address":"x"}))
            .await
            .expect("first request should succeed");
        let second_response = client
            .json_rpc("getAddressInformation", serde_json::json!({"address":"x"}))
            .await
            .expect("second request should succeed");

        assert_eq!(first_response["from"], "first");
        assert_eq!(second_response["from"], "second");
        assert_eq!(first_count.load(Ordering::SeqCst), 1, "first endpoint request count");
        assert_eq!(second_count.load(Ordering::SeqCst), 1, "second endpoint request count");

        first_handle.await.expect("first server task");
        second_handle.await.expect("second server task");
    }

    #[tokio::test]
    async fn json_rpc_all_endpoints_failed_returns_last_error_only() {
        let (bad_1, bad_1_handle) = spawn_http_500_server().await;
        let (bad_2, bad_2_handle) = spawn_http_500_server().await;

        let client =
            ClientJsonRpc::connect_many(vec![(bad_1, None), (bad_2, None)], None).expect("client");

        let err = client
            .json_rpc("getAddressInformation", serde_json::json!({"address":"x"}))
            .await
            .expect_err("json_rpc should fail when all endpoints are down");
        let err_text = err.to_string();

        assert!(
            !err_text.contains("failed on all chain-rpc endpoints"),
            "error should not contain aggregated wrapper message"
        );
        assert!(
            !err_text.contains("Request `getAddressInformation`"),
            "error should not include method wrapper text"
        );

        bad_1_handle.await.expect("bad_1 server task");
        bad_2_handle.await.expect("bad_2 server task");
    }
}
