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
    ExactBocSubmissionResult, ExactBocSubmissionStatus, GetAddressInformationRes,
    GetBlockHeaderRes, GetBlockTransactionsExtRes, GetBlockTransactionsRes,
    GetExtendedAddressInformationRes, GetMasterchainInfoRes, GetShardsRes, GetTransactionsRes,
    GetWalletInformationRes, LifecycleGrantRequest, LifecycleMutationResultRes,
    LifecycleRevokeRequest, RelayNetworkDomainPin, RunGetMethodParams, RunGetMethodRes,
    SigningPayloadRes, SubmissionResultRes, TransactionIntentRes,
};
use anyhow::Context;
use base64::Engine;
use chain_block::{ConfigParamEnum, MsgAddressInt, read_boc, write_boc};
use chain_rpc_rs::client::{ApiClientV2, ApiKey, Network};
use std::{
    collections::HashSet,
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use url::Url;

struct EndpointClient {
    url: String,
    display_origin: String,
    client: ApiClientV2,
}

/// Collapse an untrusted transport/protocol error into a bounded diagnostic
/// category. HTTP client errors commonly retain the complete request URL,
/// including deployment-specific capability paths. Those errors must never
/// cross the chain-RPC client boundary or enter tracing fields verbatim.
fn bounded_rpc_error_category(error: &impl std::fmt::Display) -> &'static str {
    let rendered = error.to_string().to_ascii_lowercase();
    if rendered.contains("response id") || rendered.contains("request id") {
        "response_id_mismatch"
    } else if rendered.contains("timeout") || rendered.contains("timed out") {
        "timeout"
    } else if rendered.contains("connect")
        || rendered.contains("dns")
        || rendered.contains("request")
        || rendered.contains("transport")
    {
        "transport_unavailable"
    } else {
        "remote_or_protocol_error"
    }
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
    /// This constructor is defensive: it drops exactly empty values and
    /// deduplicates URLs while preserving order. Whitespace and non-ASCII
    /// aliases are rejected rather than normalized. Callers should normally pass
    /// pre-normalized values from `ChainRpcConfig::resolved_endpoints()`,
    /// but this method still tolerates duplicates for safety.
    pub fn connect_many(
        entries: Vec<(String, Option<String>)>,
        default_api_key: Option<String>,
    ) -> anyhow::Result<Self> {
        let mut seen = HashSet::with_capacity(entries.len());
        let mut unique: Vec<(String, Option<String>)> = Vec::with_capacity(entries.len());
        for (url, key) in entries {
            if url.is_empty() {
                continue;
            }
            let (canonical_url, _) = canonicalize_chain_rpc_endpoint(&url)?;
            if !seen.insert(canonical_url.clone()) {
                continue;
            }
            unique.push((canonical_url, key));
        }

        if unique.is_empty() {
            anyhow::bail!("No chain-rpc endpoints configured");
        }

        let endpoints = unique
            .into_iter()
            .map(|(url, per_key)| {
                let effective_key = per_key.as_ref().or(default_api_key.as_ref());
                let (_, display_origin) = canonicalize_chain_rpc_endpoint(&url)?;
                let client = ApiClientV2::try_new_direct(
                    Network::Custom(url.clone()),
                    effective_key.map(|v| ApiKey::Header(v.to_string())),
                )
                .map_err(|error| {
                    let category = bounded_rpc_error_category(&error);
                    anyhow::anyhow!(
                        "initialize chain-rpc client for {display_origin}; rpc_error_category={category}"
                    )
                })?;
                Ok(EndpointClient {
                    client,
                    url,
                    display_origin,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

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

    /// Executes a side-effect-free JSON-RPC read with round-robin failover.
    ///
    /// Algorithm:
    /// 1. An atomic cursor picks a per-request start endpoint so that
    ///    successive calls are spread across endpoints in round-robin order.
    /// 2. Starting from that endpoint, each endpoint is tried once in
    ///    cyclic order until one succeeds or all have been exhausted.
    /// 3. On success the response is returned immediately; on total failure
    ///    only a bounded category for the last failure is propagated.
    async fn json_rpc_read(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let total = self.endpoints.len();
        let start = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % total;
        let request_id = serde_json::json!(uuid::Uuid::new_v4().to_string());
        let mut last_error_category: Option<&'static str> = None;

        for attempt in 0..total {
            let idx = (start + attempt) % total;
            let endpoint = &self.endpoints[idx];
            match endpoint.client.json_rpc(method, params.clone(), request_id.clone()).await {
                Ok(response) => {
                    if attempt > 0 {
                        tracing::debug!(
                            method,
                            used_endpoint = %endpoint.display_origin,
                            attempt = attempt + 1,
                            "chain-rpc failover succeeded"
                        );
                    }
                    return Ok(response);
                }
                Err(err) => {
                    let error_category = bounded_rpc_error_category(&err);
                    tracing::debug!(
                        method,
                        endpoint = %endpoint.display_origin,
                        attempt = attempt + 1,
                        total_attempts = total,
                        error_category,
                        "chain-rpc request failed"
                    );
                    last_error_category = Some(error_category);
                }
            }
        }

        if let Some(category) = last_error_category {
            anyhow::bail!(
                "all chain-rpc endpoints failed; endpoint_count={total}; rpc_error_category={category}"
            )
        } else {
            anyhow::bail!("chain-rpc request failed; rpc_error_category=internal")
        }
    }

    /// Executes a state-changing JSON-RPC request against the configured
    /// primary endpoint exactly once.
    ///
    /// There is intentionally no endpoint failover here.  A connection can
    /// fail after the endpoint has received the request, so retrying the same
    /// write against another endpoint would turn an ambiguous result into an
    /// implicit rebroadcast.
    async fn json_rpc_write_once(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let endpoint = &self.endpoints[0];
        let request_id = serde_json::json!(uuid::Uuid::new_v4().to_string());
        endpoint.client.json_rpc(method, params, request_id).await.map_err(|error| {
            let category = bounded_rpc_error_category(&error);
            anyhow::anyhow!(
                "{method} write attempt against {} failed; rpc_error_category={category}",
                endpoint.display_origin
            )
        })
    }

    /// Executes a side-effect-free preflight against the primary endpoint.
    /// This deliberately bypasses round-robin selection and failover: a
    /// secondary endpoint is never allowed to authorize a write to primary.
    async fn json_rpc_primary_read(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let endpoint = &self.endpoints[0];
        let request_id = serde_json::json!(uuid::Uuid::new_v4().to_string());
        endpoint.client.json_rpc(method, params, request_id).await.map_err(|error| {
            let category = bounded_rpc_error_category(&error);
            anyhow::anyhow!(
                "{method} preflight against {} failed; rpc_error_category={category}",
                endpoint.display_origin
            )
        })
    }

    pub async fn get_config_param(&self, param_id: u32) -> anyhow::Result<ConfigParamEnum> {
        let json_params: serde_json::Value = serde_json::json!({
            "config_id": param_id,
        });

        let config_info = self
            .json_rpc_read("getConfigParam", json_params)
            .await
            .with_context(|| format!("getConfigParam({})", param_id))?;

        decode_config_param(config_info, param_id)
    }

    /// Reads the network identity (ConfigParam 19) that wallet contracts
    /// bind into every signed message. Signed writes go exclusively to the
    /// primary endpoint, so the identity is read from the primary as well:
    /// with a failover read, a misconfigured secondary on another network
    /// could hand back its own id, and the signature would then be valid on
    /// that other network instead of the one being written to.
    pub async fn get_global_id(&self) -> anyhow::Result<i32> {
        match self.get_primary_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => Ok(value as i32),
            other => anyhow::bail!("config parameter 19 is not a global ID: {other:?}"),
        }
    }

    async fn get_primary_config_param(&self, param_id: u32) -> anyhow::Result<ConfigParamEnum> {
        let config_info = self
            .json_rpc_primary_read("getConfigParam", serde_json::json!({"config_id": param_id}))
            .await
            .with_context(|| format!("primary getConfigParam({param_id})"))?;
        decode_config_param(config_info, param_id)
    }

    async fn get_primary_masterchain_info(&self) -> anyhow::Result<GetMasterchainInfoRes> {
        let value = self
            .json_rpc_primary_read("getMasterchainInfo", serde_json::json!({}))
            .await
            .context("primary getMasterchainInfo")?;
        serde_json::from_value(value).context("decode primary getMasterchainInfo")
    }

    async fn verify_primary_network_domain(
        &self,
        expected: &RelayNetworkDomainPin,
    ) -> anyhow::Result<RelayNetworkDomainPin> {
        validate_relay_network_domain_pin(expected)?;
        let global_id = match self.get_primary_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("primary config parameter 19 is not a global ID"),
        };
        let master = self.get_primary_masterchain_info().await?;
        let init = master.init.context("primary getMasterchainInfo omitted zero-state init")?;
        if init.workchain != -1 || init.shard != i64::MIN || init.seqno != 0 {
            anyhow::bail!("primary zero-state BlockIdExt has noncanonical masterchain coordinates");
        }
        let observed = RelayNetworkDomainPin {
            // This owner-controlled label is intentionally copied from the
            // pin; the RPC has no authority to select or reinterpret it.
            network_id: expected.network_id.clone(),
            global_id,
            zero_state_root_hash: hash_digest("zero-state root", &init.root_hash)?,
            zero_state_file_hash: hash_digest("zero-state file", &init.file_hash)?,
            // The endpoint cannot choose the transaction workchain. Custody
            // separately checks this owner-pinned value against the source.
            workchain_id: expected.workchain_id,
        };
        if &observed != expected {
            anyhow::bail!("primary RPC network domain does not match the owner pin");
        }
        Ok(observed)
    }

    /// Reads the immutable full network identity from the primary only and
    /// compares it with an explicit owner pin. This is diagnostic and does not
    /// itself authorize a later write; callers must use
    /// [`Self::submit_exact_boc_pinned`] for an adjacent preflight.
    pub async fn verify_pinned_primary_network(
        &self,
        expected: &RelayNetworkDomainPin,
    ) -> anyhow::Result<()> {
        self.verify_primary_network_domain(expected).await.map(|_| ())
    }

    /// Production relay entry point. The exact BOC is validated locally, then
    /// the configured primary alone must match the explicit full network pin.
    /// The next network operation is the one and only write to that primary.
    pub async fn submit_exact_boc_pinned(
        &self,
        boc: &[u8],
        expected_network: &RelayNetworkDomainPin,
    ) -> anyhow::Result<ExactBocSubmissionResult> {
        let validated = validate_exact_boc_inner(boc)?;
        let observed = self.verify_primary_network_domain(expected_network).await?;
        self.submit_validated_exact_boc(boc, validated, Some(observed)).await
    }

    pub async fn run_get_method(
        &self,
        args: &RunGetMethodParams,
    ) -> anyhow::Result<RunGetMethodRes> {
        let json_params = serde_json::json!(args);
        let json_params_str = json_params.to_string();
        let res = self.json_rpc_read("runGetMethodStd", json_params).await.map_err(|e| {
            anyhow::anyhow!("Request `runGetMethodStd({})` return error: {}", json_params_str, e)
        })?;

        let run_get_method_res = serde_json::from_value::<RunGetMethodRes>(res)?;

        Ok(run_get_method_res)
    }

    pub async fn send_boc(&self, boc: &Vec<u8>) -> anyhow::Result<()> {
        validate_exact_boc_before_broadcast(boc)?;
        let json_params = serde_json::json!({
            "boc": base64::engine::general_purpose::STANDARD.encode(boc)
        });
        let _ = self.json_rpc_write_once("sendBoc", json_params).await?;

        Ok(())
    }

    /// Submits one exact external-message BOC to one bound endpoint.
    ///
    /// A matching hash acknowledges that the endpoint completed its send
    /// request; it does not prove execution or finality. Transport and
    /// response-integrity failures are returned as `Unknown`, because the
    /// endpoint may already have accepted the bytes.
    /// Legacy/manual exact submission. This has no owner-pinned network-domain
    /// preflight and is therefore not a production Agent relay API.
    pub async fn submit_exact_boc_legacy_unpinned(
        &self,
        boc: &[u8],
    ) -> anyhow::Result<ExactBocSubmissionResult> {
        let validated = validate_exact_boc_inner(boc)?;
        self.submit_validated_exact_boc(boc, validated, None).await
    }

    async fn submit_validated_exact_boc(
        &self,
        boc: &[u8],
        validated: ValidatedExactBoc,
        network_domain: Option<RelayNetworkDomainPin>,
    ) -> anyhow::Result<ExactBocSubmissionResult> {
        let local_hash = validated.root_hash;
        let cell_hash = validated.cell_hash;
        // Submission results cross the CLI/API trust boundary.  Keep the
        // configured path private: it may contain a deployment-specific route
        // or capability token even though queries and fragments are rejected
        // by endpoint canonicalization.
        let endpoint = self.endpoints[0].display_origin.clone();
        let params = serde_json::json!({
            "boc": base64::engine::general_purpose::STANDARD.encode(boc),
        });

        let response = match self.json_rpc_write_once("sendBocReturnHash", params).await {
            Ok(response) => response,
            Err(err) => {
                let error_chain = format!("{err:#}").to_ascii_lowercase();
                let detail = if error_chain.contains("response_id_mismatch") {
                    "RPC response id did not match the exact write request"
                } else {
                    "RPC write outcome is unknown after a transport or protocol error"
                };
                tracing::debug!(
                    endpoint = %endpoint,
                    "exact BOC write outcome is unknown"
                );
                return Ok(ExactBocSubmissionResult {
                    status: ExactBocSubmissionStatus::Unknown,
                    cell_hash,
                    endpoint,
                    network_domain,
                    node_status: None,
                    node_cell_hash: None,
                    // Do not copy the transport error into a public result:
                    // HTTP clients commonly include the full request URL.
                    detail: Some(detail.to_owned()),
                });
            }
        };

        #[derive(serde::Deserialize)]
        struct SendBocReturnHashResponse {
            status: i32,
            hash: String,
        }

        let response = match serde_json::from_value::<SendBocReturnHashResponse>(response) {
            Ok(response) => response,
            Err(err) => {
                return Ok(ExactBocSubmissionResult {
                    status: ExactBocSubmissionStatus::Unknown,
                    cell_hash,
                    endpoint,
                    network_domain,
                    node_status: None,
                    node_cell_hash: None,
                    detail: Some(bounded_detail(&format!(
                        "invalid sendBocReturnHash response: {err}"
                    ))),
                });
            }
        };

        let node_hash = match base64::engine::general_purpose::STANDARD.decode(&response.hash) {
            Ok(hash) if hash.as_slice() == local_hash.as_slice() => Some(cell_hash.clone()),
            Ok(_) => {
                return Ok(ExactBocSubmissionResult {
                    status: ExactBocSubmissionStatus::Unknown,
                    cell_hash,
                    endpoint,
                    network_domain,
                    node_status: None,
                    node_cell_hash: None,
                    detail: Some("endpoint returned a different message hash".to_owned()),
                });
            }
            Err(err) => {
                return Ok(ExactBocSubmissionResult {
                    status: ExactBocSubmissionStatus::Unknown,
                    cell_hash,
                    endpoint,
                    network_domain,
                    node_status: None,
                    node_cell_hash: None,
                    detail: Some(bounded_detail(&format!(
                        "endpoint returned an invalid message hash: {err}"
                    ))),
                });
            }
        };

        let status = if response.status == 1 {
            ExactBocSubmissionStatus::Accepted
        } else {
            // sendBocReturnHash documents only status=1. Any other numeric
            // value is not a durable rejection proof and can follow admission.
            ExactBocSubmissionStatus::Unknown
        };

        Ok(ExactBocSubmissionResult {
            status,
            cell_hash,
            endpoint,
            network_domain,
            node_status: Some(response.status),
            node_cell_hash: node_hash,
            detail: None,
        })
    }

    pub async fn get_extended_address_information(
        &self,
        address: &MsgAddressInt,
    ) -> anyhow::Result<GetExtendedAddressInformationRes> {
        let json_params = serde_json::json!({
            "address": address.to_string(),
        });
        let json_params_str = json_params.to_string();
        let res = self.json_rpc_read("getExtendedAddressInformation", json_params).await.map_err(
            |e| {
                anyhow::anyhow!(
                    "Request `getExtendedAddressInformation({})` return error: {}",
                    json_params_str,
                    e
                )
            },
        )?;

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
        let res = self.json_rpc_read("getAddressInformation", json_params).await.map_err(|e| {
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
        let res = self.json_rpc_read("getAccountCapability", json_params).await.map_err(|e| {
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
        let res = self.json_rpc_read("getAccountDelegations", json_params).await.map_err(|e| {
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
        let res = self.json_rpc_read("getAccountSessions", json_params).await.map_err(|e| {
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
        let res = self.json_rpc_read("getAccountAgents", json_params).await.map_err(|e| {
            anyhow::anyhow!("Request `getAccountAgents({})` return error: {}", json_params_str, e)
        })?;
        Ok(serde_json::from_value::<Vec<AccountAgentCapability>>(res)?)
    }

    // ─── New methods for P0 operator commands ──────────────────────────

    pub async fn get_masterchain_info(&self) -> anyhow::Result<GetMasterchainInfoRes> {
        let res = self
            .json_rpc_read("getMasterchainInfo", serde_json::json!({}))
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
            .json_rpc_read(
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
        normalize_get_transactions(res)
    }

    pub async fn get_address_balance(&self, address: &MsgAddressInt) -> anyhow::Result<String> {
        let res = self
            .json_rpc_read("getAddressBalance", serde_json::json!({"address": address.to_string()}))
            .await
            .context("getAddressBalance")?;
        // Response is just a quoted string like "1234567"
        res.as_str().map(|s| s.to_string()).ok_or_else(|| {
            anyhow::anyhow!("get_address_balance: expected string response, got: {}", res)
        })
    }

    pub async fn get_address_state(&self, address: &MsgAddressInt) -> anyhow::Result<String> {
        let res = self
            .json_rpc_read("getAddressState", serde_json::json!({"address": address.to_string()}))
            .await
            .context("getAddressState")?;
        res.as_str().map(|s| s.to_string()).ok_or_else(|| {
            anyhow::anyhow!("get_address_state: expected string response, got: {}", res)
        })
    }

    pub async fn get_shards(&self, seqno: u32) -> anyhow::Result<GetShardsRes> {
        let res = self
            .json_rpc_read("shards", serde_json::json!({"seqno": seqno}))
            .await
            .context("shards")?;
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
    /// `after_account` pagination cursor for blocks whose transaction count
    /// exceeds `count` (signalled by `incomplete: true` in the response).
    pub async fn get_block_transactions_page(
        &self,
        workchain: i32,
        shard: &str,
        seqno: u32,
        after_lt: Option<u64>,
        after_account: Option<&str>,
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
        if let Some(account) = after_account {
            params["after_account"] = serde_json::json!(account);
        }
        let res = self
            .json_rpc_read("getBlockTransactions", params)
            .await
            .context("getBlockTransactions")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn get_block_transactions_ext_page(
        &self,
        workchain: i32,
        shard: &str,
        seqno: u32,
        after_lt: Option<u64>,
        after_account: Option<&str>,
        count: u32,
    ) -> anyhow::Result<GetBlockTransactionsExtRes> {
        let mut params = serde_json::json!({
            "workchain": workchain,
            "shard": shard,
            "seqno": seqno,
            "count": count,
        });
        if let Some(lt) = after_lt {
            params["after_lt"] = serde_json::json!(lt.to_string());
        }
        if let Some(account) = after_account {
            params["after_account"] = serde_json::json!(account);
        }
        let res = self
            .json_rpc_read("getBlockTransactionsExt", params)
            .await
            .context("getBlockTransactionsExt")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn get_block_header(
        &self,
        workchain: i32,
        shard: &str,
        seqno: u32,
    ) -> anyhow::Result<GetBlockHeaderRes> {
        let res = self
            .json_rpc_read(
                "getBlockHeader",
                serde_json::json!({
                    "workchain": workchain,
                    "shard": shard,
                    "seqno": seqno,
                }),
            )
            .await
            .context("getBlockHeader")?;
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
            .json_rpc_read("buildTransactionIntent", json_params)
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
        let res = self
            .json_rpc_read("getSigningPayload", json_params)
            .await
            .context("getSigningPayload")?;
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
            .json_rpc_write_once("submitSignedTransaction", json_params)
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
            .json_rpc_write_once("grantAccountDelegation", json_params)
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
            .json_rpc_write_once("revokeAccountDelegation", json_params)
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
            .json_rpc_write_once("grantAccountSession", json_params)
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
            .json_rpc_write_once("revokeAccountSession", json_params)
            .await
            .context("revokeAccountSession")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn grant_account_agent(
        &self,
        req: &LifecycleGrantRequest,
    ) -> anyhow::Result<LifecycleMutationResultRes> {
        let json_params = serde_json::to_value(req)?;
        let res = self
            .json_rpc_write_once("grantAccountAgent", json_params)
            .await
            .context("grantAccountAgent")?;
        Ok(serde_json::from_value(res)?)
    }

    pub async fn revoke_account_agent(
        &self,
        req: &LifecycleRevokeRequest,
    ) -> anyhow::Result<LifecycleMutationResultRes> {
        let json_params = serde_json::to_value(req)?;
        let res = self
            .json_rpc_write_once("revokeAccountAgent", json_params)
            .await
            .context("revokeAccountAgent")?;
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
        let res = self.json_rpc_read("getWalletInformation", json_params).await.map_err(|e| {
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

pub fn canonicalize_chain_rpc_endpoint(value: &str) -> anyhow::Result<(String, String)> {
    // The locator identity is reproduced by Go, Rust, and Python. Reject
    // parser-specific trimming and IDNA behavior before URL parsing so all
    // implementations hash the same ASCII byte string or fail closed.
    if !value.is_ascii()
        || value.trim() != value
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        anyhow::bail!(
            "chain-rpc endpoint must be strict printable ASCII without surrounding whitespace"
        );
    }
    let mut parsed = Url::parse(value).context("chain-rpc endpoint is not an absolute URL")?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        anyhow::bail!("chain-rpc endpoint must use HTTP or HTTPS");
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("chain-rpc endpoint must not contain credentials, query, or fragment");
    }
    let host = parsed.host_str().context("chain-rpc endpoint has no host")?.to_owned();
    let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized_host != host {
        parsed
            .set_host(Some(&normalized_host))
            .map_err(|_| anyhow::anyhow!("chain-rpc endpoint host is invalid"))?;
    }
    if parsed.path().contains('%') {
        anyhow::bail!("chain-rpc endpoint path must not contain percent encoding");
    }
    if (parsed.scheme() == "http" && parsed.port() == Some(80))
        || (parsed.scheme() == "https" && parsed.port() == Some(443))
    {
        parsed.set_port(None).map_err(|_| anyhow::anyhow!("chain-rpc endpoint port is invalid"))?;
    }
    let host = parsed.host_str().context("chain-rpc endpoint has no host")?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|address| address.is_loopback());
    if parsed.scheme() != "https" && !loopback {
        anyhow::bail!("remote chain-rpc endpoint must use HTTPS");
    }
    parsed.set_query(None);
    parsed.set_fragment(None);
    let display_origin = parsed.origin().ascii_serialization();
    let mut canonical = parsed.as_str().trim_end_matches('/').to_string();
    if canonical.ends_with(':') {
        canonical.push('/');
    }
    Ok((canonical, display_origin))
}

fn decode_config_param(
    config_info: serde_json::Value,
    param_id: u32,
) -> anyhow::Result<ConfigParamEnum> {
    let b64 = config_info
        .get("config")
        .and_then(|config| config.get("bytes"))
        .or_else(|| {
            config_info
                .get("result")
                .and_then(|result| result.get("config"))
                .and_then(|config| config.get("bytes"))
        })
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!(r#"missing "config.bytes" string"#))?;
    let boc = base64::engine::general_purpose::STANDARD.decode(b64)?;
    let cell = read_boc(boc)?.withdraw_single_root()?;
    ConfigParamEnum::construct_from_cell_and_number(cell, param_id).map_err(anyhow::Error::from)
}

/// Maximum exact external-message BOC accepted by custody and either relay
/// submission boundary. Keeping this public prevents the durable journal and
/// network writer from drifting to different byte budgets.
pub const MAX_EXACT_BOC_BYTES: usize = 64 * 1024;

struct ValidatedExactBoc {
    root_hash: chain_block::UInt256,
    cell_hash: String,
}

/// Shared local gate used before a durable `Broadcasting` transition and
/// repeated at the actual network boundary.
pub fn validate_exact_boc_before_broadcast(boc: &[u8]) -> anyhow::Result<()> {
    validate_exact_boc_inner(boc).map(|_| ())
}

fn validate_exact_boc_inner(boc: &[u8]) -> anyhow::Result<ValidatedExactBoc> {
    if boc.is_empty() || boc.len() > MAX_EXACT_BOC_BYTES {
        anyhow::bail!("exact BOC must contain 1..={MAX_EXACT_BOC_BYTES} bytes");
    }
    let message = read_boc(boc)?.withdraw_single_root()?;
    if write_boc(&message)?.as_slice() != boc {
        anyhow::bail!("exact BOC is not in the canonical single-root serialization");
    }
    let root_hash = message.repr_hash();
    Ok(ValidatedExactBoc { cell_hash: format!("tvm-cell-sha256:{root_hash:x}"), root_hash })
}

fn hash_digest(name: &str, value: &[u8]) -> anyhow::Result<String> {
    if value.len() != 32 {
        anyhow::bail!("{name} hash must contain exactly 32 bytes");
    }
    Ok(format!("sha256:{}", hex::encode(value)))
}

fn validate_relay_network_domain_pin(pin: &RelayNetworkDomainPin) -> anyhow::Result<()> {
    if pin.network_id.is_empty()
        || pin.network_id.len() > 128
        || !pin.network_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        anyhow::bail!("relay network_id must contain 1..=128 printable ASCII bytes");
    }
    if pin.global_id == 0 {
        anyhow::bail!("relay global_id must not be zero");
    }
    for (name, value) in [
        ("zero-state root", pin.zero_state_root_hash.as_str()),
        ("zero-state file", pin.zero_state_file_hash.as_str()),
    ] {
        if value.len() != 71
            || !value.starts_with("sha256:")
            || !value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            anyhow::bail!("{name} must be a canonical sha256 digest");
        }
    }
    Ok(())
}

fn bounded_detail(value: &str) -> String {
    const MAX_CHARS: usize = 512;
    value.chars().take(MAX_CHARS).collect()
}

fn normalize_get_transactions(res: serde_json::Value) -> anyhow::Result<GetTransactionsRes> {
    // The validator JSON-RPC surface returns the current toncenter-style array
    // with nested `transaction_id`, while older deployments used
    // `{transactions:[...]}` and top-level `lt`/`hash`.
    let values = if let Some(array) = res.as_array() {
        array.clone()
    } else {
        res.get("transactions").and_then(serde_json::Value::as_array).cloned().ok_or_else(|| {
            anyhow::anyhow!("getTransactions returned neither an array nor a transactions object")
        })?
    };
    let mut transactions = Vec::with_capacity(values.len());
    for value in values {
        if let Ok(transaction) =
            serde_json::from_value::<crate::v2::data_models::RawTransaction>(value.clone())
        {
            // A current response also has defaults for the legacy top-level
            // fields, so accept legacy only when those identity fields are
            // actually present. Otherwise the nested transaction ID would be
            // silently normalized to lt=0/hash="".
            if value.get("lt").is_some() && value.get("hash").is_some() {
                transactions.push(transaction);
                continue;
            }
        }
        #[derive(serde::Deserialize)]
        struct CurrentRawTransaction {
            #[serde(rename = "@type")]
            r#type: Option<String>,
            block_id: Option<crate::v2::data_models::BlockIdExt>,
            #[serde(default)]
            data: String,
            #[serde(default)]
            utime: u32,
            transaction_id: crate::v2::data_models::TransactionId,
        }
        let current: CurrentRawTransaction =
            serde_json::from_value(value).context("decode current getTransactions item")?;
        transactions.push(crate::v2::data_models::RawTransaction {
            r#type: current.r#type,
            block_id: current.block_id,
            data: current.data,
            lt: current.transaction_id.lt,
            utime: current.utime,
            hash: base64::engine::general_purpose::STANDARD.encode(current.transaction_id.hash),
        });
    }
    Ok(GetTransactionsRes { r#type: None, transactions })
}

#[cfg(test)]
mod get_transactions_tests {
    use super::normalize_get_transactions;

    #[test]
    fn normalizes_current_nested_transaction_identity() {
        let value = serde_json::json!([{
            "@type": "raw.transaction",
            "data": "dHgtYm9j",
            "utime": 2000000000,
            "transaction_id": {"@type":"internal.transactionId", "lt":"123", "hash":"AQIDBA=="}
        }]);
        let result = normalize_get_transactions(value).expect("current response");
        assert_eq!(result.transactions.len(), 1);
        assert_eq!(result.transactions[0].lt, 123);
        assert_eq!(result.transactions[0].hash, "AQIDBA==");
    }

    #[test]
    fn preserves_legacy_top_level_transaction_identity() {
        let value = serde_json::json!({"transactions":[{
            "@type":"raw.transaction", "data":"dHgtYm9j", "lt":"456", "utime":2000000001, "hash":"BQYHCA=="
        }]});
        let result = normalize_get_transactions(value).expect("legacy response");
        assert_eq!(result.transactions.len(), 1);
        assert_eq!(result.transactions[0].lt, 456);
        assert_eq!(result.transactions[0].hash, "BQYHCA==");
    }

    #[test]
    fn rejects_an_identity_free_transaction() {
        let value = serde_json::json!([{"data":"dHgtYm9j"}]);
        assert!(normalize_get_transactions(value).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientJsonRpc, canonicalize_chain_rpc_endpoint, validate_exact_boc_before_broadcast,
        validate_relay_network_domain_pin,
    };
    use crate::v2::data_models::{ExactBocSubmissionStatus, RelayNetworkDomainPin};
    use base64::Engine;
    use chain_block::{BocFlags, BocWriter, BuilderData, Cell, IBitstring, write_boc};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn chain_rpc_endpoint_policy_rejects_credential_leaks_and_cleartext_remote_hosts() {
        for endpoint in [
            "http://relay.example/api",
            "https://user:secret@relay.example/api",
            "https://relay.example/api?key=secret",
            "https://relay.example/api#fragment",
            "ftp://relay.example/api",
        ] {
            let error =
                canonicalize_chain_rpc_endpoint(endpoint).expect_err("unsafe endpoint accepted");
            assert!(!error.to_string().contains("secret"), "error leaked endpoint credentials");
        }
        let (loopback, loopback_display) =
            canonicalize_chain_rpc_endpoint("http://127.0.0.1:8011/api/")
                .expect("loopback development endpoint");
        assert_eq!(loopback, "http://127.0.0.1:8011/api");
        assert_eq!(loopback_display, "http://127.0.0.1:8011");
        let (remote, remote_display) =
            canonicalize_chain_rpc_endpoint("https://relay.example/private/path")
                .expect("remote HTTPS endpoint");
        assert_eq!(remote, "https://relay.example/private/path");
        assert_eq!(remote_display, "https://relay.example");
    }

    #[test]
    fn chain_rpc_endpoint_policy_rejects_cross_language_parser_aliases() {
        for endpoint in [
            " https://relay.example/api",
            "https://relay.example/api ",
            "https://relay.example/api\n",
            "https://rélay.example/api",
        ] {
            let error = canonicalize_chain_rpc_endpoint(endpoint)
                .expect_err("non-ASCII or parser-trimmed endpoint accepted");
            assert_eq!(
                error.to_string(),
                "chain-rpc endpoint must be strict printable ASCII without surrounding whitespace"
            );
        }
    }

    #[test]
    fn endpoint_identity_collapses_safe_url_variants_before_deduplication() {
        let client = ClientJsonRpc::connect_many(
            vec![
                ("https://RELAY.example:443/api/".to_owned(), None),
                ("https://relay.example/api".to_owned(), None),
                ("https://relay.example./api//".to_owned(), None),
            ],
            None,
        )
        .expect("canonical endpoint list");
        assert_eq!(client.urls(), vec!["https://relay.example/api"]);
    }

    async fn spawn_jsonrpc_ok_server(
        result: serde_json::Value,
        request_count: Arc<AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind async listener");
        let addr = listener.local_addr().expect("listener local addr");
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept connection");
            request_count.fetch_add(1, Ordering::SeqCst);
            let request = read_json_request(&mut socket).await;
            let response_body = serde_json::json!({
                "ok": true,
                "jsonrpc": "2.0",
                "result": result,
                "id": request.get("id").cloned().unwrap_or(serde_json::Value::Null),
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket.write_all(response.as_bytes()).await.expect("write response");
            socket.shutdown().await.expect("shutdown socket");
        });

        (format!("http://{}", addr), handle)
    }

    async fn read_json_request(socket: &mut tokio::net::TcpStream) -> serde_json::Value {
        let mut buf = [0_u8; 4096];
        let mut request = Vec::new();
        let mut body_start = None;
        let mut expected_len = None;
        loop {
            let n = socket.read(&mut buf).await.expect("read request");
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);
            if body_start.is_none()
                && let Some(header_end) =
                    request.windows(4).position(|window| window == b"\r\n\r\n")
            {
                let start = header_end + 4;
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_len = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                body_start = Some(start);
                expected_len = Some(start + content_len);
            }
            if expected_len.is_some_and(|length| request.len() >= length) {
                break;
            }
        }
        let start = body_start.expect("HTTP request headers");
        serde_json::from_slice(&request[start..expected_len.unwrap_or(request.len())])
            .expect("JSON request body")
    }

    async fn spawn_drop_response_server(
        request_count: Arc<AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind async listener");
        let addr = listener.local_addr().expect("listener local addr");
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept connection");
            request_count.fetch_add(1, Ordering::SeqCst);

            let mut buf = [0_u8; 4096];
            let mut request = Vec::new();
            let mut expected_len = None;
            loop {
                let n = socket.read(&mut buf).await.expect("read request");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if expected_len.is_none()
                    && let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n")
                {
                    let body_start = header_end + 4;
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_len = headers.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    });
                    expected_len = Some(body_start + content_len.unwrap_or(0));
                }
                if expected_len.is_some_and(|len| request.len() >= len) {
                    break;
                }
            }

            // Close only after receiving the full POST, but deliberately send
            // no HTTP response.  The client cannot know whether the endpoint
            // accepted the BOC.
            socket.shutdown().await.expect("shutdown socket");
        });

        (format!("http://{}", addr), handle)
    }

    async fn spawn_wrong_id_server(
        result: serde_json::Value,
        request_count: Arc<AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind async listener");
        let addr = listener.local_addr().expect("listener local addr");
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept connection");
            request_count.fetch_add(1, Ordering::SeqCst);
            let _ = read_json_request(&mut socket).await;
            let response_body = serde_json::json!({
                "ok": true,
                "jsonrpc": "2.0",
                "result": result,
                "id": "attacker-selected-id",
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket.write_all(response.as_bytes()).await.expect("write response");
            socket.shutdown().await.expect("shutdown socket");
        });
        (format!("http://{}", addr), handle)
    }

    fn exact_boc() -> (Vec<u8>, String) {
        let cell = Cell::default();
        let hash = base64::engine::general_purpose::STANDARD.encode(cell.repr_hash().as_slice());
        (write_boc(&cell).expect("write test BOC"), hash)
    }

    fn relay_network_pin(global_id: i32, root: [u8; 32], file: [u8; 32]) -> RelayNetworkDomainPin {
        RelayNetworkDomainPin {
            network_id: "tos:testnet".to_owned(),
            global_id,
            zero_state_root_hash: format!("sha256:{}", hex::encode(root)),
            zero_state_file_hash: format!("sha256:{}", hex::encode(file)),
            workchain_id: 0,
        }
    }

    async fn spawn_network_bound_server(
        global_id: i32,
        zero_root: [u8; 32],
        zero_file: [u8; 32],
        send_hash: String,
        expected_requests: usize,
        methods: Arc<std::sync::Mutex<Vec<String>>>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let mut config = BuilderData::new();
        config.append_i32(global_id).expect("serialize global id");
        let config_boc =
            write_boc(&config.into_cell().expect("global id cell")).expect("serialize config BOC");
        let config_b64 = base64::engine::general_purpose::STANDARD.encode(config_boc);
        let root_b64 = base64::engine::general_purpose::STANDARD.encode(zero_root);
        let file_b64 = base64::engine::general_purpose::STANDARD.encode(zero_file);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind network server");
        let address = listener.local_addr().expect("network server address");
        let handle = tokio::spawn(async move {
            for _ in 0..expected_requests {
                let (mut socket, _) = listener.accept().await.expect("accept network request");
                let request = read_json_request(&mut socket).await;
                let method = request
                    .get("method")
                    .and_then(serde_json::Value::as_str)
                    .expect("JSON-RPC method")
                    .to_owned();
                methods.lock().expect("methods lock").push(method.clone());
                let result = match method.as_str() {
                    "getConfigParam" => serde_json::json!({
                        "config": {"bytes": config_b64},
                    }),
                    "getMasterchainInfo" => serde_json::json!({
                        "last": {
                            "@type":"tos.blockIdExt", "workchain":-1,
                            "shard": i64::MIN.to_string(), "seqno":17,
                            "root_hash": root_b64, "file_hash": file_b64
                        },
                        "state_root_hash":"",
                        "init": {
                            "@type":"tos.blockIdExt", "workchain":-1,
                            "shard": i64::MIN.to_string(), "seqno":0,
                            "root_hash": root_b64, "file_hash": file_b64
                        }
                    }),
                    "sendBocReturnHash" => {
                        serde_json::json!({"status":1,"hash":send_hash})
                    }
                    other => panic!("unexpected method {other}"),
                };
                let response_body = serde_json::json!({
                    "ok":true,
                    "jsonrpc":"2.0",
                    "id":request.get("id").cloned().unwrap_or(serde_json::Value::Null),
                    "result":result,
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                socket.write_all(response.as_bytes()).await.expect("write network response");
                socket.shutdown().await.expect("shutdown network socket");
            }
        });
        (format!("http://{address}"), handle)
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
    async fn json_rpc_read_failover_uses_second_url_when_first_is_broken() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let (bad_url, bad_server_handle) = spawn_http_500_server().await;
        let (good_url, server_handle) =
            spawn_jsonrpc_ok_server(serde_json::json!({"from":"fallback"}), request_count.clone())
                .await;

        let client = ClientJsonRpc::connect_many(vec![(bad_url, None), (good_url, None)], None)
            .expect("client");

        let response = client
            .json_rpc_read("getAddressInformation", serde_json::json!({"address":"x"}))
            .await
            .expect("JSON-RPC read should fail over to healthy endpoint");

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
    async fn json_rpc_read_round_robin_starts_from_first_endpoint() {
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
            .json_rpc_read("getAddressInformation", serde_json::json!({"address":"x"}))
            .await
            .expect("first request should succeed");
        let second_response = client
            .json_rpc_read("getAddressInformation", serde_json::json!({"address":"x"}))
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
    async fn json_rpc_read_all_endpoints_failed_returns_last_error_only() {
        let (bad_1_origin, bad_1_handle) = spawn_http_500_server().await;
        let (bad_2_origin, bad_2_handle) = spawn_http_500_server().await;
        let private_path = "/tenant/secret-capability-token/jsonRPC";
        let bad_1 = format!("{bad_1_origin}{private_path}");
        let bad_2 = format!("{bad_2_origin}{private_path}");

        let client =
            ClientJsonRpc::connect_many(vec![(bad_1, None), (bad_2, None)], None).expect("client");

        let err = client
            .json_rpc_read("getAddressInformation", serde_json::json!({"address":"x"}))
            .await
            .expect_err("json_rpc should fail when all endpoints are down");
        let err_text = err.to_string();

        assert!(err_text.contains("rpc_error_category="));
        assert!(!err_text.contains(private_path));
        assert!(!err_text.contains("secret-capability-token"));
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

    #[tokio::test]
    async fn exact_boc_dropped_response_is_unknown_and_never_uses_endpoint_two() {
        let first_count = Arc::new(AtomicUsize::new(0));
        let (first_url, first_handle) = spawn_drop_response_server(first_count.clone()).await;
        let second_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind second endpoint");
        second_listener.set_nonblocking(true).expect("make second endpoint nonblocking");
        let second_url = format!("http://{}", second_listener.local_addr().expect("second addr"));
        let client =
            ClientJsonRpc::connect_many(vec![(first_url.clone(), None), (second_url, None)], None)
                .expect("client");
        let (boc, _) = exact_boc();

        let result =
            client.submit_exact_boc_legacy_unpinned(&boc).await.expect("typed submission result");

        assert_eq!(result.status, ExactBocSubmissionStatus::Unknown);
        assert_eq!(result.endpoint, first_url);
        assert_eq!(result.node_status, None);
        assert_eq!(first_count.load(Ordering::SeqCst), 1, "primary receives one write");
        assert!(
            matches!(second_listener.accept(), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock),
            "secondary endpoint must receive no implicit write"
        );
        first_handle.await.expect("dropped-response server task");
    }

    #[tokio::test]
    async fn exact_boc_public_result_never_exposes_the_configured_rpc_path() {
        let write_count = Arc::new(AtomicUsize::new(0));
        let (origin, server) = spawn_drop_response_server(write_count.clone()).await;
        let private_path = "/tenant/private-capability-token/jsonRPC";
        let configured = format!("{origin}{private_path}");
        let client = ClientJsonRpc::connect(configured, None).expect("path-bound client");
        let (boc, _) = exact_boc();

        let result =
            client.submit_exact_boc_legacy_unpinned(&boc).await.expect("typed unknown result");
        let public_json = serde_json::to_string(&result).expect("serialize public result");

        assert_eq!(result.status, ExactBocSubmissionStatus::Unknown);
        assert_eq!(result.endpoint, origin);
        assert!(!public_json.contains(private_path));
        assert!(!result.detail.as_deref().unwrap_or_default().contains(private_path));
        assert_eq!(write_count.load(Ordering::SeqCst), 1);
        server.await.expect("dropped-response server task");
    }

    #[tokio::test]
    async fn legacy_send_boc_dropped_response_never_uses_endpoint_two() {
        let first_count = Arc::new(AtomicUsize::new(0));
        let (first_url, first_handle) = spawn_drop_response_server(first_count.clone()).await;
        let second_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind second endpoint");
        second_listener.set_nonblocking(true).expect("make second endpoint nonblocking");
        let second_url = format!("http://{}", second_listener.local_addr().expect("second addr"));
        let client = ClientJsonRpc::connect_many(vec![(first_url, None), (second_url, None)], None)
            .expect("client");
        let (boc, _) = exact_boc();

        let error = client.send_boc(&boc).await.expect_err("dropped response is an error");

        assert!(error.to_string().contains("write attempt"));
        assert_eq!(first_count.load(Ordering::SeqCst), 1, "primary receives one write");
        assert!(
            matches!(second_listener.accept(), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock),
            "secondary endpoint must receive no implicit write"
        );
        first_handle.await.expect("dropped-response server task");
    }

    #[tokio::test]
    async fn exact_boc_rejects_hash_only_response_as_unknown() {
        let accepted_count = Arc::new(AtomicUsize::new(0));
        let (boc, hash) = exact_boc();
        let (url, handle) =
            spawn_jsonrpc_ok_server(serde_json::json!({"hash": hash}), accepted_count.clone())
                .await;
        let client = ClientJsonRpc::connect(url.clone(), None).expect("client");

        let result =
            client.submit_exact_boc_legacy_unpinned(&boc).await.expect("typed unknown result");

        assert_eq!(result.status, ExactBocSubmissionStatus::Unknown);
        assert_eq!(result.endpoint, url);
        assert_eq!(result.node_status, None);
        assert_eq!(result.node_cell_hash, None);
        assert_eq!(accepted_count.load(Ordering::SeqCst), 1);
        handle.await.expect("server task");
    }

    #[tokio::test]
    async fn exact_boc_post_write_response_id_mismatch_is_unknown() {
        let response_count = Arc::new(AtomicUsize::new(0));
        let (boc, hash) = exact_boc();
        let (url, handle) = spawn_wrong_id_server(
            serde_json::json!({"status": 1, "hash": hash}),
            response_count.clone(),
        )
        .await;
        let client = ClientJsonRpc::connect(url, None).expect("client");

        let result =
            client.submit_exact_boc_legacy_unpinned(&boc).await.expect("typed unknown result");

        assert_eq!(result.status, ExactBocSubmissionStatus::Unknown);
        assert!(result.detail.as_deref().is_some_and(|value| value.contains("response id")));
        assert_eq!(response_count.load(Ordering::SeqCst), 1);
        handle.await.expect("server task");
    }

    #[tokio::test]
    async fn exact_boc_binds_real_validator_status_and_hash() {
        let accepted_count = Arc::new(AtomicUsize::new(0));
        let (boc, hash) = exact_boc();
        let (url, handle) = spawn_jsonrpc_ok_server(
            serde_json::json!({
                "@type": "raw.extMessageInfo",
                "status": 1,
                "hash": hash,
            }),
            accepted_count.clone(),
        )
        .await;
        let client = ClientJsonRpc::connect(url, None).expect("client");

        let result = client.submit_exact_boc_legacy_unpinned(&boc).await.expect("accepted result");

        assert_eq!(result.status, ExactBocSubmissionStatus::Accepted);
        assert_eq!(result.node_status, Some(1));
        assert_eq!(accepted_count.load(Ordering::SeqCst), 1);
        handle.await.expect("server task");
    }

    #[tokio::test]
    async fn exact_boc_rejects_noncanonical_serialization_before_network_io() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind endpoint");
        listener.set_nonblocking(true).expect("make endpoint nonblocking");
        let url = format!("http://{}", listener.local_addr().expect("endpoint addr"));
        let client = ClientJsonRpc::connect(url, None).expect("client");
        let cell = Cell::default();
        let mut noncanonical_boc = Vec::new();
        BocWriter::with_flags([cell], BocFlags::Crc32)
            .expect("BOC writer")
            .write(&mut noncanonical_boc)
            .expect("write CRC32 BOC");

        let error = client
            .submit_exact_boc_legacy_unpinned(&noncanonical_boc)
            .await
            .expect_err("noncanonical BOC must be rejected");

        assert!(error.to_string().contains("not in the canonical single-root serialization"));
        assert!(
            matches!(listener.accept(), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock),
            "canonical validation must happen before network I/O"
        );
    }

    #[tokio::test]
    async fn exact_boc_mismatched_response_hash_is_unknown() {
        let response_count = Arc::new(AtomicUsize::new(0));
        let (boc, _) = exact_boc();
        let different_hash = base64::engine::general_purpose::STANDARD.encode([0x5a_u8; 32]);
        let (url, handle) = spawn_jsonrpc_ok_server(
            serde_json::json!({"status": 1, "hash": different_hash}),
            response_count.clone(),
        )
        .await;
        let client = ClientJsonRpc::connect(url, None).expect("client");

        let result = client.submit_exact_boc_legacy_unpinned(&boc).await.expect("unknown result");

        assert_eq!(result.status, ExactBocSubmissionStatus::Unknown);
        assert_eq!(result.node_status, None);
        assert_eq!(response_count.load(Ordering::SeqCst), 1);
        handle.await.expect("server task");
    }

    #[tokio::test]
    async fn exact_boc_treats_undocumented_validator_status_as_unknown() {
        let response_count = Arc::new(AtomicUsize::new(0));
        let (boc, hash) = exact_boc();
        let (url, handle) = spawn_jsonrpc_ok_server(
            serde_json::json!({"status": 0, "hash": hash}),
            response_count.clone(),
        )
        .await;
        let client = ClientJsonRpc::connect(url, None).expect("client");

        let result = client.submit_exact_boc_legacy_unpinned(&boc).await.expect("unknown result");

        assert_eq!(result.status, ExactBocSubmissionStatus::Unknown);
        assert_eq!(result.node_status, Some(0));
        assert_eq!(result.node_cell_hash.as_deref(), Some(result.cell_hash.as_str()));
        assert_eq!(response_count.load(Ordering::SeqCst), 1);
        handle.await.expect("server task");
    }

    #[test]
    fn exact_boc_size_gate_rejects_oversize_before_any_durable_transition() {
        let oversized = vec![0_u8; 64 * 1024 + 1];
        let error = validate_exact_boc_before_broadcast(&oversized)
            .expect_err("oversized exact BOC must fail locally");
        assert!(error.to_string().contains("65536"));
    }

    #[test]
    fn relay_network_domain_requires_a_canonical_zero_state_identity() {
        let mut pin = relay_network_pin(42, [0x11; 32], [0x22; 32]);
        pin.zero_state_root_hash = "sha256:ABC".to_owned();
        assert!(validate_relay_network_domain_pin(&pin).is_err());

        pin.zero_state_root_hash = format!("sha256:{}", "11".repeat(32));
        pin.network_id = "tos:testnet\nforged".to_owned();
        assert!(validate_relay_network_domain_pin(&pin).is_err());
    }

    #[tokio::test]
    async fn pinned_exact_write_preflights_full_domain_on_primary_then_writes_once() {
        let (boc, send_hash) = exact_boc();
        let zero_root = [0x11; 32];
        let zero_file = [0x22; 32];
        let methods = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (url, server) =
            spawn_network_bound_server(42, zero_root, zero_file, send_hash, 3, methods.clone())
                .await;
        let client = ClientJsonRpc::connect(url, None).expect("pinned client");
        let pin = relay_network_pin(42, zero_root, zero_file);

        let result = client.submit_exact_boc_pinned(&boc, &pin).await.expect("pinned exact write");

        assert_eq!(result.status, ExactBocSubmissionStatus::Accepted);
        assert_eq!(result.network_domain.as_ref(), Some(&pin));
        server.await.expect("network server");
        assert_eq!(
            *methods.lock().expect("methods lock"),
            vec!["getConfigParam", "getMasterchainInfo", "sendBocReturnHash"]
        );
    }

    #[tokio::test]
    async fn secondary_cannot_authorize_a_primary_with_the_wrong_zero_state() {
        let (boc, send_hash) = exact_boc();
        let expected_root = [0x31; 32];
        let expected_file = [0x32; 32];
        let methods = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (primary, primary_server) = spawn_network_bound_server(
            42,
            [0x41; 32],
            expected_file,
            send_hash,
            2,
            methods.clone(),
        )
        .await;
        let secondary = std::net::TcpListener::bind("127.0.0.1:0").expect("bind secondary");
        secondary.set_nonblocking(true).expect("nonblocking secondary");
        let secondary_url = format!("http://{}", secondary.local_addr().unwrap());
        let client =
            ClientJsonRpc::connect_many(vec![(primary, None), (secondary_url, None)], None)
                .expect("multi endpoint client");
        let pin = relay_network_pin(42, expected_root, expected_file);

        let error = client
            .submit_exact_boc_pinned(&boc, &pin)
            .await
            .expect_err("wrong primary genesis must block the write");

        assert!(error.to_string().contains("does not match the owner pin"));
        primary_server.await.expect("primary preflight server");
        assert_eq!(
            *methods.lock().expect("methods lock"),
            vec!["getConfigParam", "getMasterchainInfo"]
        );
        assert!(
            matches!(secondary.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "secondary must not participate in authorization or receive a write"
        );
    }
}
