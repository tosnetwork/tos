/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{WalletVersion, serde_utils, socket_utils::resolve_ip};
use adnl::{client::AdnlClientConfig, common::Timeouts};
use anyhow::Context;
use chain_block::Ed25519KeyOption;
use secrets_vault::{
    crypto::factory::{AutoCryptoFactory, CryptoFactory},
    types::{algorithm::Algorithm, metadata::Metadata, secret::Secret},
    vault::SecretVault,
};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs,
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

fn default_chain_rpc_url() -> String {
    "http://127.0.0.1:3301/".to_owned()
}

/// A single chain-rpc endpoint entry.
///
/// Plain strings use the global `api_key`; objects can override it per-endpoint.
/// ```json
/// "urls": ["http://a/", { "url": "http://b/", "api_key": "key-for-b" }]
/// ```
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum EndpointEntry {
    Url(String),
    WithKey { url: String, api_key: String },
}

impl EndpointEntry {
    pub fn url(&self) -> &str {
        match self {
            EndpointEntry::Url(u) => u,
            EndpointEntry::WithKey { url, .. } => url,
        }
    }

    pub fn api_key(&self) -> Option<&str> {
        match self {
            EndpointEntry::Url(_) => None,
            EndpointEntry::WithKey { api_key, .. } => Some(api_key),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ChainRpcConfig {
    /// Endpoint entries for the chain RPC service.
    /// The first entry is the primary endpoint; the rest are used for failover.
    /// Each entry is either a plain URL string (uses global `api_key`)
    /// or an object `{ "url": "...", "api_key": "..." }` with its own key.
    #[serde(default)]
    pub urls: Vec<EndpointEntry>,
    /// Legacy single-endpoint field. Merged into the head of `urls` by [`Self::endpoints`].
    /// Skipped on serialization so that re-saved configs migrate to `urls` automatically.
    #[serde(default, skip_serializing)]
    url: Option<String>,
    /// Global API key used for endpoints that don't specify their own.
    pub api_key: Option<String>,
    /// Owner-pinned operator identity used only when a single-endpoint config
    /// participates in independent evidence corroboration. An endpoint URL is
    /// not proof of operational independence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_provenance: Option<String>,
}

impl Default for ChainRpcConfig {
    fn default() -> Self {
        Self {
            urls: vec![EndpointEntry::Url(default_chain_rpc_url())],
            url: None,
            api_key: None,
            operator_provenance: None,
        }
    }
}

impl ChainRpcConfig {
    /// Migrates the legacy `url` field into `urls` so that re-saving the
    /// config is non-destructive. Should be called once after deserialization
    /// (e.g. in [`AppConfig::load`]).
    fn normalize(&mut self) {
        if let Some(legacy) = self.url.take() {
            // Preserve the exact configured bytes. Generic client resolution
            // remains backwards-compatible and trims for ordinary use, while
            // release-profile loaders can fail closed on parser aliases before
            // deriving a cross-language locator identity.
            if !legacy.trim().is_empty() && !self.urls.iter().any(|e| e.url() == legacy) {
                self.urls.insert(0, EndpointEntry::Url(legacy));
            }
        }
    }

    /// Returns deduplicated URL strings only (for display / logging).
    ///
    /// The legacy `url` field (if present) is prepended before `urls`.
    /// Falls back to the default endpoint when everything is empty.
    pub fn endpoints(&self) -> Vec<String> {
        self.resolved_endpoints().into_iter().map(|(url, _)| url).collect()
    }

    /// Returns deduplicated `(url, per_endpoint_api_key)` pairs.
    ///
    /// Per-endpoint key is `Some` only when the entry explicitly overrides
    /// the global `api_key`. Callers should fall back to the global key
    /// when the per-endpoint value is `None`.
    pub fn resolved_endpoints(&self) -> Vec<(String, Option<String>)> {
        let legacy = self.url.iter().map(|u| (u.as_str(), None));
        let entries = self.urls.iter().map(|e| (e.url(), e.api_key()));

        let mut seen = HashSet::with_capacity(self.urls.len() + 1);
        let mut result: Vec<(String, Option<String>)> = Vec::with_capacity(self.urls.len() + 1);
        for (url, key) in legacy.chain(entries) {
            let url = url.trim();
            if url.is_empty() {
                continue;
            }
            if seen.insert(url.to_string()) {
                result.push((url.to_string(), key.map(str::to_string)));
            }
        }
        if result.is_empty() {
            result.push((default_chain_rpc_url(), None));
        }
        result
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(untagged)]
pub enum KeyConfig {
    PrivateKey {
        type_id: i32,
        #[serde(with = "serde_utils::base64_key")]
        pvt_key: Vec<u8>,
    },
    PublicKey {
        type_id: i32,
        #[serde(with = "serde_utils::base64_key")]
        pub_key: Vec<u8>,
    },
    VaultKey {
        name: String,
    },
    #[serde(with = "serde_utils::hex_string")]
    KeyPair(Vec<u8>),
}

impl KeyConfig {
    pub async fn read_secret(&self, vault: Option<Arc<SecretVault>>) -> anyhow::Result<Secret> {
        match self {
            KeyConfig::PrivateKey { type_id: _, pvt_key } => {
                let metadata = Metadata::new(None, Algorithm::Ed25519, true);
                Secret::from_raw_data(&pvt_key, metadata, AutoCryptoFactory {}.new_crypto()?).await
            }
            KeyConfig::PublicKey { type_id: _, pub_key } => {
                let metadata = Metadata::new(None, Algorithm::None, true);
                Secret::from_raw_data(&pub_key, metadata, AutoCryptoFactory {}.new_crypto()?).await
            }
            KeyConfig::VaultKey { name } => {
                let vault =
                    vault.ok_or(anyhow::anyhow!("The secret vault is not set in the config"))?;
                let secret = vault.get(&name.into()).await?;
                let algo = secret.metadata().algorithm;

                if algo != Algorithm::Ed25519 {
                    anyhow::bail!(
                        "Invalid secret algorithm: expected Ed25519, got {}",
                        algo.as_str()
                    );
                }

                Ok(secret)
            }
            KeyConfig::KeyPair(data) => {
                let metadata = Metadata::new(None, Algorithm::Ed25519, true);

                Secret::from_raw_data(&data, metadata, AutoCryptoFactory {}.new_crypto()?).await
            }
        }
    }
}

fn default_http_bind() -> String {
    // Loopback by default: exposing the API on all interfaces is an explicit
    // operator decision and requires authentication to be configured.
    "127.0.0.1:8080".to_owned()
}

fn default_http_enable_swagger() -> bool {
    true
}

/// Default operator token lifetime: 24 hours. A bearer token's threat model
/// is theft, so the default stays short; a longer lifetime is an explicit
/// operator decision made in the config, not a default.
fn default_operator_ttl() -> u64 {
    86400 // 24 hours
}

fn default_nominator_ttl() -> u64 {
    86400 // 24 hours
}

fn default_min_password_length() -> usize {
    8
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Nominator = 0,
    Operator = 1,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Nominator => "nominator",
            Role::Operator => "operator",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Role {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "operator" => Ok(Role::Operator),
            "nominator" => Ok(Role::Nominator),
            other => anyhow::bail!("unknown role: {other}"),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct UserEntry {
    pub username: String,
    pub role: Role,
    /// Vault secret name where the password hash is stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_name: Option<String>,
    /// Inline Argon2 password hash (testing fallback when vault is unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    /// If set, JWTs with `iat` earlier than this unix timestamp are rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_after: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct AuthConfig {
    /// Operator token TTL in seconds.
    pub operator_token_ttl: u64,
    /// Nominator token TTL in seconds.
    pub nominator_token_ttl: u64,
    /// Minimum password length for new users. Defaults to 8.
    #[serde(default = "default_min_password_length")]
    pub min_password_length: usize,
    /// Base64-encoded 32-byte JWT signing key. Fallback when vault is not available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_secret: Option<String>,
    /// Registered users. Each entry points to a vault secret holding the password hash,
    /// or contains an inline `password_hash` for testing without vault.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<UserEntry>,
}

impl AuthConfig {
    /// Upper bound on a configured token TTL, in seconds (one year).
    ///
    /// A TTL is added to the current time to form the token's `exp`, so an
    /// unbounded value is both an arithmetic hazard and a security one: a
    /// token valid for centuries is a permanent credential that revocation by
    /// TTL expiry can never clear. Anything above this is a typo or an attempt
    /// to mint one, and is refused at config load rather than silently signed.
    pub const MAX_TOKEN_TTL: u64 = 365 * 24 * 60 * 60;

    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, ttl) in [
            ("operator_token_ttl", self.operator_token_ttl),
            ("nominator_token_ttl", self.nominator_token_ttl),
        ] {
            if ttl == 0 {
                anyhow::bail!("{name} must be greater than zero");
            }
            if ttl > Self::MAX_TOKEN_TTL {
                anyhow::bail!("{name} must not exceed {} seconds, got {ttl}", Self::MAX_TOKEN_TTL);
            }
        }
        Ok(())
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            operator_token_ttl: default_operator_ttl(),
            nominator_token_ttl: default_nominator_ttl(),
            min_password_length: default_min_password_length(),
            jwt_secret: None,
            users: Vec::new(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct HttpConfig {
    /// HTTP bind address, e.g. "127.0.0.1:8080" (the default) or "0.0.0.0:8080".
    /// Binding to a non-loopback address requires `auth` to be configured;
    /// the service refuses to start the HTTP server otherwise.
    #[serde(default = "default_http_bind")]
    pub bind: String,

    /// Expose Swagger UI endpoints.
    #[serde(default = "default_http_enable_swagger")]
    pub enable_swagger: bool,

    /// Peer IP addresses of trusted reverse proxies. Only when a request's
    /// TCP peer address is in this list is its `x-forwarded-for` header
    /// honored for client identification (e.g. login rate limiting). A direct
    /// client can put arbitrary text in that header, so it is ignored from
    /// any other peer. Default: empty (never trust `x-forwarded-for`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<std::net::IpAddr>,

    /// Authentication and authorization configuration.
    /// When `Some`, all protected routes require a valid JWT token.
    /// When `None`, all routes are open (auth explicitly disabled).
    /// Default: enabled with no users — all protected endpoints return 401
    /// until at least one user is created via `tosctl auth add`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthConfig>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: default_http_bind(),
            enable_swagger: default_http_enable_swagger(),
            trusted_proxies: Vec::new(),
            auth: Some(AuthConfig::default()),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct WalletConfig {
    pub key: KeyConfig,
    #[serde(with = "crate::wallet_version::version_serde")]
    pub version: WalletVersion,
    pub subwallet_id: u32,
    #[serde(default = "default_workchain")]
    pub workchain: i32,
}

fn default_agent_task_timeout_secs() -> u64 {
    3600
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AgentWalletPolicy {
    /// Maximum value the controller may spend in one action, in nano-TOS.
    pub max_per_tx: u64,
    /// Maximum value the controller may spend in one day, in nano-TOS.
    pub daily_limit: u64,
    /// Addresses or names of service actors the controller may pay or call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_service_actors: Vec<String>,
    /// Task categories this agent wallet may accept.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_task_categories: Vec<String>,
    /// Require owner approval when a single action is above this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_owner_approval_above: Option<u64>,
    /// Default task timeout used by off-chain runners and future task contracts.
    #[serde(default = "default_agent_task_timeout_secs")]
    pub default_task_timeout_secs: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct AgentRuntimeBinding {
    /// Stable operator-defined runtime identifier.
    pub runner_id: String,
    /// Runtime endpoint or local descriptor URI.
    pub endpoint: String,
    /// Optional hash of runtime attestation or deployment evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_hash: Option<String>,
    /// Owner-pinned OpenFox Economic Action Authority identity and Ed25519 key.
    /// Custody never accepts these values from a payment request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub economic_authority_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub economic_authority_public_key_hex: Option<String>,
    /// Owner-pinned, rollback-resistant custody journal location. Economic
    /// effect commands may not select another high-water domain at runtime.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub economic_custody_journal_directory: Option<String>,
    /// Unix timestamp when this local runtime binding was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct AgentWalletConfig {
    /// The underlying TOS wallet/account used to hold funds and sign owner actions.
    pub wallet: WalletConfig,
    /// Fixed native Agent Account address after successful deployment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_account_address: Option<String>,
    /// Immutable random ID committed to this Agent Account deployment's StateInit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_account_deployment_id: Option<String>,
    /// Controller key used by the agent runtime for bounded automated actions.
    pub controller_key: KeyConfig,
    /// Machine-readable spending and service-call policy.
    pub policy: AgentWalletPolicy,
    /// Optional content hash for agent metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<String>,
    /// Optional hash of the off-chain service endpoint descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_endpoint_hash: Option<String>,
    /// Capability labels advertised by the agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Optional off-chain runtime binding for this agent wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<AgentRuntimeBinding>,
    /// Unix timestamp when this local config entry was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

/// Locally tracked Task Escrow deployment record.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct AgentTaskConfig {
    /// Deployed Task Escrow contract address.
    pub address: String,
    /// Task creator (funding wallet) address.
    pub creator: String,
    /// Assigned agent address when fixed at deployment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_agent: Option<String>,
    /// Optional verifier allowed to settle the task.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
    /// Optional account-permission object linked to this task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_id: Option<String>,
    /// Escrow budget in nano-TOS.
    pub budget: u64,
    /// Unix deadline after which the escrow may be expired.
    pub deadline: u64,
    /// Result review window in seconds.
    #[serde(default)]
    pub review_period: u32,
    /// Hex-encoded 32-byte settlement policy hash.
    pub policy_hash: String,
    /// Optional hex-encoded ed25519 public key required to sign `settle`'s
    /// result_hash, on top of the existing creator/verifier authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestor_pubkey: Option<String>,
    /// Unix timestamp when this local record was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

/// Locally tracked Capability Registry deployment record.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct CapabilityRegistryConfig {
    /// Deployed Capability Registry contract address.
    pub address: String,
    /// Registry owner address.
    pub owner: String,
    /// Optional verifier allowed to adjust the reputation score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
    /// Hex-encoded 32-byte hash of the advertised task categories.
    pub task_categories_hash: String,
    /// Hex-encoded 32-byte hash of the advertised pricing model.
    pub pricing_hash: String,
    /// Hex-encoded 32-byte hash of general capability/service metadata.
    pub metadata_hash: String,
    /// Hex-encoded 32-byte hash identifying the supported verification method.
    pub verification_method_hash: String,
    /// Unix timestamp recorded as the registration time.
    pub registered_at: u64,
    /// Unix timestamp when this local record was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

/// Locally tracked Service Actor deployment record.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct ServiceActorConfig {
    /// Deployed Service Actor contract address.
    pub address: String,
    /// Service owner address.
    pub owner: String,
    /// Optional single authorized caller when access is not open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_caller: Option<String>,
    pub open_access: bool,
    /// Price per call, in nano-TOS.
    pub price_per_call: u64,
    /// Fixed, non-refundable fee collected alongside `price_per_call` at
    /// `call` time, in nano-TOS. See `https://github.com/tosnetwork/doc/blob/main/tos-blockchain/service-actor-concurrent-escrow-upgrade.md`.
    #[serde(default)]
    pub storage_fee: u64,
    /// Paid to whoever calls `sweep_expired_request` once a request's rights
    /// window has fully lapsed, in nano-TOS.
    #[serde(default)]
    pub cleanup_bounty: u64,
    /// Seconds a submitted call has to be `respond`ed to.
    #[serde(default)]
    pub response_sla: u32,
    /// Seconds after `response_deadline` an expired request's refund stays
    /// claimable.
    #[serde(default)]
    pub refund_claim_window: u32,
    /// Maximum calls accepted per day; `0` means unlimited.
    pub rate_limit_per_day: u32,
    /// Hex-encoded 32-byte hash of general service metadata.
    pub metadata_hash: String,
    /// Hex-encoded 32-byte hash identifying the supported proof/attestation scheme.
    pub proof_scheme_hash: String,
    /// Optional hex-encoded ed25519 public key required to sign `respond`'s
    /// response_hash, on top of the existing owner authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestor_pubkey: Option<String>,
    /// Unix timestamp when this local record was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

/// Locally tracked Dispute case record.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct DisputeConfig {
    /// Deployed Dispute contract address.
    pub address: String,
    pub claimant: String,
    pub respondent: String,
    pub reviewer: String,
    /// Unix timestamp: expected ruling deadline (informational only).
    pub deadline: u64,
    /// Hex-encoded 32-byte reference to the disputed subject (e.g. a Task
    /// Escrow address's hash).
    pub subject_hash: String,
    /// Hex-encoded 32-byte hash of the claimant's evidence.
    pub claimant_evidence_hash: String,
    /// Optional hex-encoded ed25519 public key required to sign `rule`'s
    /// ruling_hash, on top of the existing reviewer authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestor_pubkey: Option<String>,
    /// Unix timestamp when this local record was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

/// Locally tracked Proof Attestation record.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct ProofAttestationConfig {
    /// Deployed Proof Attestation contract address.
    pub address: String,
    pub owner: String,
    /// Hex-encoded 32-byte ed25519 public key registered to sign attestations.
    pub public_key: String,
    /// Hex-encoded 32-byte reference to what this attestation is about.
    pub subject_hash: String,
    /// Unix timestamp when this local record was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "kind")]
pub enum PoolConfig {
    #[serde(rename = "snp")]
    SNP {
        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        owner: Option<String>,
    },
    #[serde(rename = "core")]
    CorePool { addresses: [String; 2], validator_share: u64 },
    #[serde(rename = "nominator_pool")]
    NominatorPool {
        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        owner: Option<String>,
        validator_reward_share: u16,
        max_nominators: u16,
        min_validator_stake: u64,
        min_nominator_stake: u64,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(untagged)]
pub enum TimeoutVariant {
    Single(u64),
    Detailed(Timeouts),
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct AdnlConfig {
    pub server_address: String,
    pub server_key: KeyConfig,
    pub client_key: KeyConfig,
    pub timeouts: TimeoutVariant,
}

impl AdnlConfig {
    pub async fn to_node_adnl_config(
        &self,
        vault: Option<Arc<SecretVault>>,
    ) -> anyhow::Result<AdnlClientConfig> {
        let server_key = self.server_key.read_secret(vault.clone()).await?;
        let client_key = self.client_key.read_secret(vault.clone()).await?;
        let timeouts = match self.timeouts.clone() {
            TimeoutVariant::Single(secs) => Timeouts::with_duration(Duration::from_secs(secs)),
            TimeoutVariant::Detailed(timeouts) => timeouts,
        };

        let blob = match server_key {
            Secret::Blob { blob } => blob,
            _ => anyhow::bail!("Unsupported server key type"),
        };

        let client_keypair = match client_key {
            Secret::KeyPair { keypair } => keypair,
            _ => anyhow::bail!("Unsupported secret type"),
        };

        let client_pvt_key = client_keypair.private_key().await?;
        let pvt_key = client_pvt_key.lock().await?;
        if pvt_key.len() < 32 {
            anyhow::bail!("invalid client private key length");
        }
        let client_key_opt = Ed25519KeyOption::from_private_key(&pvt_key[..32].try_into()?)?;
        let server_pub_key = blob.data().await?;
        let server_key = Ed25519KeyOption::from_public_key(
            server_pub_key
                .lock()
                .await?
                .deref()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid public key length"))?,
        );

        Ok(AdnlClientConfig::new(
            Some(client_key_opt),
            resolve_ip(&self.server_address)?,
            server_key,
            timeouts,
        ))
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum StakePolicy {
    #[serde(rename = "fixed")]
    Fixed(u64),
    #[default]
    #[serde(rename = "split50")]
    Split50,
    #[serde(rename = "minimum")]
    Minimum,
}

impl std::fmt::Display for StakePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StakePolicy::Fixed(nanotos) => {
                let tos = crate::chain_utils::nanotos_to_tos(*nanotos);
                if tos.fract() == 0.0 {
                    write!(f, "fixed({} TOS)", tos as u64)
                } else {
                    write!(f, "fixed({} TOS)", tos)
                }
            }
            StakePolicy::Split50 => write!(f, "split50"),
            StakePolicy::Minimum => write!(f, "minimum"),
        }
    }
}

impl StakePolicy {
    pub fn calculate_stake(&self, min_stake: u64, available_stake: u64) -> anyhow::Result<u64> {
        if available_stake < min_stake {
            anyhow::bail!(
                "not enough balance: available={}, min_stake={}",
                available_stake,
                min_stake
            );
        }
        let stake = match self {
            StakePolicy::Fixed(v) => v.to_owned().max(min_stake).min(available_stake),
            StakePolicy::Minimum => min_stake,
            StakePolicy::Split50 => (available_stake / 2).max(min_stake),
        };
        Ok(stake)
    }
}

fn default_workchain() -> i32 {
    -1
}

fn default_max_factor() -> f32 {
    3.0
}

fn default_tick_interval() -> u64 {
    40
}
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ElectionsConfig {
    #[serde(default)]
    pub policy: StakePolicy,
    /// Per-node stake policy overrides.
    /// Key is the node name.
    /// When a node has an entry here, it takes precedence over the default `policy`.
    #[serde(default)]
    pub policy_overrides: HashMap<String, StakePolicy>,
    #[serde(default = "default_max_factor")]
    pub max_factor: f32,
    /// Interval for elections runner in seconds
    #[serde(default = "default_tick_interval")]
    pub tick_interval: u64,
}

impl ElectionsConfig {
    /// Returns the stake policy for a given node.
    /// If the node has an override, that is returned; otherwise the default policy.
    pub fn stake_policy(&self, node_id: &str) -> &StakePolicy {
        self.policy_overrides.get(node_id).unwrap_or(&self.policy)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !(1.0..=3.0).contains(&self.max_factor) {
            anyhow::bail!("max_factor must be in range [1.0..3.0]");
        }
        Ok(())
    }
}

impl Default for ElectionsConfig {
    fn default() -> Self {
        Self {
            policy: StakePolicy::default(),
            policy_overrides: HashMap::new(),
            max_factor: default_max_factor(),
            tick_interval: default_tick_interval(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct VotingConfig {
    #[serde(default)]
    pub proposals: Vec<String>,
    #[serde(default = "default_tick_interval")]
    pub tick_interval: u64,
}

/// Lifecycle status of a node binding.
///
/// Transitions:
/// - `idle` → `participating`: elections enabled and elections are open
/// - `participating` → `validating`: node appears in current validator set
/// - `validating` → `draining`: elections disabled or node left validator set with pending recovery
/// - `draining` → `idle`: recover stake reaches zero
/// - `validating` → `idle`: node left validator set and recover stake is zero
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum BindingStatus {
    #[default]
    Idle,
    Participating,
    Draining,
    Validating,
}

impl std::fmt::Display for BindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingStatus::Idle => write!(f, "idle"),
            BindingStatus::Participating => write!(f, "participating"),
            BindingStatus::Draining => write!(f, "draining"),
            BindingStatus::Validating => write!(f, "validating"),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct NodeBinding {
    pub wallet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
    /// Whether this binding participates in elections. Defaults to `false`.
    #[serde(default)]
    pub enable: bool,
    /// Current lifecycle status. Managed by the service at runtime.
    #[serde(default)]
    pub status: BindingStatus,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    Daily,
    Hourly,
    Never,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    Console,
    File,
    All,
}

fn default_max_size_mb() -> u64 {
    50
}

fn default_max_files() -> usize {
    10
}

fn default_rotation() -> LogRotation {
    LogRotation::Daily
}

fn default_output() -> LogOutput {
    LogOutput::Console
}

fn default_level() -> tracing::Level {
    tracing::Level::INFO
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct LogConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,
    #[serde(default = "default_max_files")]
    pub max_files: usize,
    #[serde(default = "default_rotation")]
    pub rotation: LogRotation,
    #[serde(with = "serde_utils::serde_level", default = "default_level")]
    pub level: tracing::Level,
    #[serde(default = "default_output")]
    pub output: LogOutput,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            path: None,
            max_size_mb: default_max_size_mb(),
            max_files: default_max_files(),
            rotation: default_rotation(),
            level: default_level(),
            output: default_output(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
pub struct AlertsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub channels: Vec<AlertChannel>,
    #[serde(default)]
    pub rules: Vec<AlertRule>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(tag = "type")]
pub enum AlertChannel {
    #[serde(rename = "telegram")]
    Telegram {
        /// Bot token stored directly in config (legacy / convenience).
        /// Prefer `bot_token_env` for production deployments.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bot_token: Option<String>,
        /// Name of an environment variable that holds the bot token.
        /// When set, the env var is read at runtime and takes precedence
        /// over `bot_token`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bot_token_env: Option<String>,
        chat_id: String,
    },
    #[serde(rename = "webhook")]
    Webhook { url: String },
}

impl AlertChannel {
    /// Resolve the Telegram bot token.
    ///
    /// Priority: `bot_token_env` (read from environment) > `bot_token` (inline).
    /// Returns an error when neither source provides a value.
    pub fn resolve_telegram_token(&self) -> anyhow::Result<String> {
        match self {
            AlertChannel::Telegram { bot_token, bot_token_env, .. } => {
                // Try env var first
                if let Some(env_name) = bot_token_env {
                    if let Ok(val) = std::env::var(env_name) {
                        if !val.is_empty() {
                            return Ok(val);
                        }
                    }
                    // Env var set in config but not in environment -- fall through
                }
                // Fall back to inline token
                if let Some(token) = bot_token {
                    if !token.is_empty() {
                        return Ok(token.clone());
                    }
                }
                anyhow::bail!(
                    "No Telegram bot token available. \
                     Set the token via `bot_token_env` (recommended) or `bot_token` in the config."
                )
            }
            _ => anyhow::bail!("resolve_telegram_token called on non-Telegram channel"),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(tag = "type")]
pub enum AlertRule {
    #[serde(rename = "sync_lag")]
    SyncLag { threshold_seconds: u32 },
    #[serde(rename = "balance_low")]
    BalanceLow { address: String, threshold_tos: f64 },
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct AppConfig {
    pub nodes: HashMap<String, AdnlConfig>,
    #[serde(default)]
    pub wallets: HashMap<String, WalletConfig>,
    #[serde(default)]
    pub agent_wallets: HashMap<String, AgentWalletConfig>,
    /// Task Escrow deployments tracked by this operator, keyed by local task name.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub agent_tasks: HashMap<String, AgentTaskConfig>,
    /// Capability Registry deployments tracked by this operator, keyed by local name.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub capability_registries: HashMap<String, CapabilityRegistryConfig>,
    /// Service Actor deployments tracked by this operator, keyed by local name.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub service_actors: HashMap<String, ServiceActorConfig>,
    /// Dispute cases tracked by this operator, keyed by local name.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub disputes: HashMap<String, DisputeConfig>,
    /// Proof Attestation actors tracked by this operator, keyed by local name.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub proof_attestations: HashMap<String, ProofAttestationConfig>,
    #[serde(default)]
    pub pools: HashMap<String, PoolConfig>,
    #[serde(default)]
    pub bindings: HashMap<String, NodeBinding>,
    pub chain_rpc: ChainRpcConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elections: Option<ElectionsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voting: Option<VotingConfig>,
    pub http: HttpConfig,
    pub master_wallet: Option<WalletConfig>,
    /// Default interval for all tasks in seconds
    #[serde(default = "default_tick_interval")]
    pub tick_interval: u64,
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub bookmarks: HashMap<String, String>,
    #[serde(default)]
    pub alerts: AlertsConfig,
}

impl AppConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            anyhow::bail!(
                "Configuration file '{:?}' not found. Generate it first with: tosctl config generate --output={:?}",
                path,
                path
            );
        }

        let data = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let file_ext = path.extension().and_then(OsStr::to_str).unwrap_or("").to_ascii_lowercase();

        Self::parse(&data, &file_ext, &path.display().to_string())
    }

    pub fn load_fd(fd: i32, format: &str) -> anyhow::Result<Self> {
        use std::io::Read;
        use std::os::fd::FromRawFd;
        if fd < 3 {
            anyhow::bail!("config fd must be at least 3");
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut data = String::new();
        file.read_to_string(&mut data).context("Failed to read config fd")?;
        Self::parse(&data, &format.to_ascii_lowercase(), &format!("fd {fd}"))
    }

    /// Parses an exact configuration byte snapshot without reopening a path.
    ///
    /// Callers that bind a configuration content digest must hash and pass the
    /// same byte slice here. Reopening a path after hashing it creates a
    /// check-to-use race in which credentials or transport settings can change
    /// while the endpoint identity remains unchanged.
    pub fn load_bytes(data: &[u8], format: &str, source: &str) -> anyhow::Result<Self> {
        let data = std::str::from_utf8(data)
            .with_context(|| format!("Configuration '{}' is not valid UTF-8", source))?;
        Self::parse(data, &format.to_ascii_lowercase(), source)
    }

    fn parse(data: &str, format: &str, source: &str) -> anyhow::Result<Self> {
        let mut config = match format {
            "yaml" | "yml" => serde_yaml2::from_str::<Self>(&data).map_err(|e| {
                anyhow::anyhow!("Failed to parse YAML config '{}'. Error: {}", source, e)
            })?,
            "json" => serde_json::from_str::<Self>(&data).map_err(|e| {
                anyhow::anyhow!("Failed to parse JSON config '{}'. Error: {}", source, e)
            })?,
            other => anyhow::bail!("Unsupported config extension: {other}"),
        };

        config.chain_rpc.normalize();
        config.validate()?;

        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        self.elections.as_ref().map(|e| e.validate()).transpose()?;
        self.http.auth.as_ref().map(|a| a.validate()).transpose()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_config_rejects_an_unbounded_token_ttl() {
        let auth =
            AuthConfig { operator_token_ttl: AuthConfig::MAX_TOKEN_TTL + 1, ..Default::default() };
        let err = auth.validate().expect_err("a ttl above the bound must be refused");
        assert!(err.to_string().contains("operator_token_ttl"), "got: {err}");

        let auth = AuthConfig { nominator_token_ttl: u64::MAX, ..Default::default() };
        let err = auth.validate().expect_err("u64::MAX must be refused");
        assert!(err.to_string().contains("nominator_token_ttl"), "got: {err}");
    }

    #[test]
    fn auth_config_rejects_a_zero_token_ttl() {
        // A token that is expired the moment it is signed locks every operator
        // out; refuse it rather than ship an unusable service.
        let auth = AuthConfig { operator_token_ttl: 0, ..Default::default() };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn auth_config_accepts_the_bound_and_the_defaults() {
        let auth = AuthConfig::default();
        auth.validate().expect("defaults must be valid");

        let auth = AuthConfig {
            operator_token_ttl: AuthConfig::MAX_TOKEN_TTL,
            nominator_token_ttl: AuthConfig::MAX_TOKEN_TTL,
            ..Default::default()
        };
        auth.validate().expect("the bound itself must be accepted");
    }

    #[test]
    fn loading_a_config_with_an_absurd_ttl_fails() {
        // The bound has to be enforced where configs actually enter, not only
        // when something remembers to call validate().
        let mut json = minimal_config_json();
        json["http"] = serde_json::json!({
            "auth": {"operator_token_ttl": u64::MAX, "nominator_token_ttl": 3600}
        });
        let err = match AppConfig::parse(&json.to_string(), "json", "test") {
            Ok(_) => panic!("a config with an absurd ttl must be refused at load"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("operator_token_ttl"), "got: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn load_json_from_inherited_fd_without_path_extension() {
        use std::io::{Seek, Write};
        use std::os::fd::IntoRawFd;
        let path = std::env::temp_dir().join(format!("tosctl-config-fd-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        serde_json::to_writer(&mut file, &minimal_config_json()).unwrap();
        file.flush().unwrap();
        file.rewind().unwrap();
        std::fs::remove_file(&path).unwrap();
        let config = AppConfig::load_fd(file.into_raw_fd(), "json").unwrap();
        assert_eq!(config.chain_rpc.endpoints(), vec!["http://127.0.0.1:3301/"]);
    }

    const ADDR: &'static str =
        "-1:bd313e9e1114bbbe7af6f28ef59be0ff3f02ac795423f10397a70dc16396c4ea";
    const OWNER: &'static str =
        "0:c5770dc489bef32419959c174b787ab95ff9109e0e43239c18059509819697fb";

    fn minimal_config_json() -> serde_json::Value {
        serde_json::json!({
            "nodes": {},
            "chain_rpc": {"urls": ["http://127.0.0.1:3301/"]},
            "http": {},
            "master_wallet": null,
            "log": null
        })
    }

    #[test]
    fn config_without_agent_tasks_loads_with_empty_map() {
        let config: AppConfig = serde_json::from_value(minimal_config_json()).unwrap();
        assert!(config.agent_tasks.is_empty());
    }

    #[test]
    fn default_token_ttls_are_24_hours() {
        // Bearer tokens are theft-prone: the defaults must stay short, and a
        // longer lifetime must be an explicit configuration choice.
        let auth = AuthConfig::default();
        assert_eq!(auth.operator_token_ttl, 86400, "operator tokens default to 24 hours");
        assert_eq!(auth.nominator_token_ttl, 86400, "nominator tokens default to 24 hours");
    }

    #[test]
    fn agent_task_records_roundtrip_and_stay_backward_compatible() {
        let mut json = minimal_config_json();
        json["agent_tasks"] = serde_json::json!({
            "task-1": {
                "address": "-1:1111111111111111111111111111111111111111111111111111111111111111",
                "creator": "0:2222222222222222222222222222222222222222222222222222222222222222",
                "budget": 1_000_000_000u64,
                "deadline": 1_800_000_000u64,
                "policy_hash": "33".repeat(32),
            }
        });
        let config: AppConfig = serde_json::from_value(json).unwrap();
        let record = &config.agent_tasks["task-1"];
        // Optional fields absent in older records must load as None.
        assert_eq!(record.assigned_agent, None);
        assert_eq!(record.created_at, None);
        assert_eq!(record.budget, 1_000_000_000);
        assert_eq!(record.review_period, 0);

        let serialized = serde_json::to_value(&config).unwrap();
        let reloaded: AppConfig = serde_json::from_value(serialized).unwrap();
        assert_eq!(reloaded.agent_tasks["task-1"], config.agent_tasks["task-1"]);

        // An empty map is skipped on serialization so untouched configs stay stable.
        let empty: AppConfig = serde_json::from_value(minimal_config_json()).unwrap();
        let empty_json = serde_json::to_value(&empty).unwrap();
        assert!(empty_json.get("agent_tasks").is_none());
    }

    #[test]
    fn test_calculate_stake_insufficient_balance() {
        let policy = StakePolicy::Minimum;
        let result = policy.calculate_stake(10, 9);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_stake_fixed_clamped_to_available() {
        let policy = StakePolicy::Fixed(100);
        let stake = policy.calculate_stake(50, 80).unwrap();
        assert_eq!(stake, 80);
    }

    #[test]
    fn test_calculate_stake_split50_respects_minimum() {
        let policy = StakePolicy::Split50;
        let stake = policy.calculate_stake(70, 100).unwrap();
        assert_eq!(stake, 70);
    }

    #[test]
    fn test_calculate_stake_minimum_ok() {
        let policy = StakePolicy::Minimum;
        let stake = policy.calculate_stake(10, 100).unwrap();
        assert_eq!(stake, 10);
    }

    #[test]
    fn test_calculate_stake_split50_ok() {
        let policy = StakePolicy::Split50;
        let stake = policy.calculate_stake(10, 100).unwrap();
        assert_eq!(stake, 50);
    }

    #[test]
    fn test_calculate_stake_fixed_within_range() {
        let policy = StakePolicy::Fixed(60);
        let stake = policy.calculate_stake(10, 100).unwrap();
        assert_eq!(stake, 60);
    }

    #[test]
    fn test_policy_for_node_returns_default_when_no_override() {
        let config = ElectionsConfig {
            policy: StakePolicy::Minimum,
            policy_overrides: HashMap::new(),
            ..Default::default()
        };
        assert!(matches!(config.stake_policy("node1"), StakePolicy::Minimum));
    }

    #[test]
    fn test_policy_for_node_returns_override_when_present() {
        let mut overrides = HashMap::new();
        overrides.insert("node1".to_string(), StakePolicy::Fixed(500));
        let config = ElectionsConfig {
            policy: StakePolicy::Minimum,
            policy_overrides: overrides,
            ..Default::default()
        };
        assert!(matches!(config.stake_policy("node1"), StakePolicy::Fixed(500)));
        // Other nodes still get the default
        assert!(matches!(config.stake_policy("node2"), StakePolicy::Minimum));
    }

    #[test]
    fn test_policy_for_node_override_split50() {
        let mut overrides = HashMap::new();
        overrides.insert("nodeA".to_string(), StakePolicy::Split50);
        let config = ElectionsConfig {
            policy: StakePolicy::Fixed(1000),
            policy_overrides: overrides,
            ..Default::default()
        };
        assert!(matches!(config.stake_policy("nodeA"), StakePolicy::Split50));
        assert!(matches!(config.stake_policy("nodeB"), StakePolicy::Fixed(1000)));
    }

    #[test]
    fn test_pool_config_serde_snp_with_owner() {
        let addr = ADDR;
        let owner = OWNER;
        let value = serde_json::json!({
            "kind": "snp",
            "address": addr,
            "owner": owner,
        });
        let cfg: PoolConfig = serde_json::from_value(value).unwrap();
        assert_eq!(
            cfg,
            PoolConfig::SNP { address: Some(addr.to_string()), owner: Some(owner.to_string()) }
        );

        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["kind"], "snp");
        assert_eq!(json["address"], addr);
        assert_eq!(json["owner"], owner);
    }

    #[test]
    fn test_pool_config_serde_snp_without_owner() {
        let addr = ADDR;
        let value = serde_json::json!({
            "kind": "snp",
            "address": addr,
        });
        let cfg: PoolConfig = serde_json::from_value(value).unwrap();
        assert_eq!(cfg, PoolConfig::SNP { address: Some(addr.to_string()), owner: None });

        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["kind"], "snp");
        assert_eq!(json["address"], addr.to_string());
        assert!(json.get("owner").is_none());
    }

    #[test]
    fn test_pool_config_serde_core() {
        let addr1 = ADDR;
        let addr2 = OWNER;
        let value = serde_json::json!({
            "kind": "core",
            "addresses": [addr1.to_string(), addr2.to_string()],
            "validator_share": 50,
        });
        let cfg: PoolConfig = serde_json::from_value(value).unwrap();
        assert_eq!(
            cfg,
            PoolConfig::CorePool {
                addresses: [addr1.to_string(), addr2.to_string()],
                validator_share: 50,
            }
        );

        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["kind"], "core");
        assert_eq!(json["validator_share"], 50);
    }

    #[test]
    fn test_binding_status_serde_roundtrip() {
        for status in [
            BindingStatus::Idle,
            BindingStatus::Participating,
            BindingStatus::Draining,
            BindingStatus::Validating,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: BindingStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn test_binding_status_display() {
        assert_eq!(BindingStatus::Idle.to_string(), "idle");
        assert_eq!(BindingStatus::Participating.to_string(), "participating");
        assert_eq!(BindingStatus::Draining.to_string(), "draining");
        assert_eq!(BindingStatus::Validating.to_string(), "validating");
    }

    #[test]
    fn test_binding_status_default_is_idle() {
        let status: BindingStatus = Default::default();
        assert_eq!(status, BindingStatus::Idle);
    }

    #[test]
    fn test_node_binding_serde_with_status() {
        let binding = NodeBinding {
            wallet: "w1".to_string(),
            pool: Some("p1".to_string()),
            enable: true,
            status: BindingStatus::Validating,
        };
        let json = serde_json::to_value(&binding).unwrap();
        assert_eq!(json["enable"], true);
        assert_eq!(json["status"], "validating");
        assert_eq!(json["wallet"], "w1");
        assert_eq!(json["pool"], "p1");

        let parsed: NodeBinding = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.status, BindingStatus::Validating);
        assert!(parsed.enable);
    }

    #[test]
    fn test_node_binding_serde_defaults() {
        let json = serde_json::json!({"wallet": "w1"});
        let binding: NodeBinding = serde_json::from_value(json).unwrap();
        assert!(!binding.enable);
        assert_eq!(binding.status, BindingStatus::Idle);
        assert!(binding.pool.is_none());
    }

    #[test]
    fn test_node_binding_serde_enable_and_status() {
        let json = serde_json::json!({"wallet": "w1", "enable": true, "status": "draining"});
        let binding: NodeBinding = serde_json::from_value(json).unwrap();
        assert!(binding.enable);
        assert_eq!(binding.status, BindingStatus::Draining);
    }

    #[test]
    fn test_chain_rpc_endpoints_dedup_and_order() {
        let cfg = ChainRpcConfig {
            urls: vec![
                EndpointEntry::Url("http://a/".into()),
                EndpointEntry::Url("http://b/".into()),
                EndpointEntry::Url("http://a/".into()),
            ],
            ..Default::default()
        };
        assert_eq!(cfg.endpoints(), vec!["http://a/", "http://b/"]);
    }

    #[test]
    fn test_chain_rpc_endpoints_single() {
        let cfg = ChainRpcConfig {
            urls: vec![EndpointEntry::Url("http://single/".into())],
            ..Default::default()
        };
        assert_eq!(cfg.endpoints(), vec!["http://single/"]);
    }

    #[test]
    fn test_chain_rpc_endpoints_empty_falls_back_to_default() {
        let cfg = ChainRpcConfig { urls: vec![], ..Default::default() };
        assert_eq!(cfg.endpoints(), vec!["http://127.0.0.1:3301/"]);
    }

    #[test]
    fn test_chain_rpc_compat_old_url_field() {
        // Old config format had "url" (singular string) instead of "urls"
        let old_json = r#"{"url": "http://custom:9999/", "api_key": "secret"}"#;
        let cfg: ChainRpcConfig = serde_json::from_str(old_json).unwrap();
        assert_eq!(cfg.endpoints(), vec!["http://custom:9999/"]);
    }

    #[test]
    fn test_chain_rpc_compat_old_url_merged_with_urls() {
        let json = r#"{"url": "http://primary/", "urls": ["http://fallback/"], "api_key": null}"#;
        let cfg: ChainRpcConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.endpoints(), vec!["http://primary/", "http://fallback/"]);
    }

    #[test]
    fn test_chain_rpc_compat_old_url_deduped_with_urls() {
        let json = r#"{"url": "http://same/", "urls": ["http://same/", "http://other/"], "api_key": null}"#;
        let cfg: ChainRpcConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.endpoints(), vec!["http://same/", "http://other/"]);
    }

    #[test]
    fn test_chain_rpc_legacy_url_migrated_on_normalize() {
        let json = r#"{"url": "http://legacy/", "api_key": null}"#;
        let mut cfg: ChainRpcConfig = serde_json::from_str(json).unwrap();
        cfg.normalize();
        let reserialized = serde_json::to_value(&cfg).unwrap();
        assert!(reserialized.get("url").is_none(), "legacy 'url' must not be serialized");
        assert_eq!(
            reserialized["urls"],
            serde_json::json!(["http://legacy/"]),
            "legacy url must be migrated into urls"
        );
    }

    #[test]
    fn test_chain_rpc_legacy_url_migration_preserves_raw_alias_bytes() {
        let json = r#"{"url": " https://rpc.example/jsonRPC ", "api_key": null}"#;
        let mut cfg: ChainRpcConfig = serde_json::from_str(json).unwrap();
        cfg.normalize();
        assert_eq!(cfg.urls[0].url(), " https://rpc.example/jsonRPC ");
        // Ordinary client resolution remains backwards compatible.
        assert_eq!(cfg.endpoints(), vec!["https://rpc.example/jsonRPC"]);
    }

    #[test]
    fn test_chain_rpc_per_endpoint_api_key() {
        let json = r#"{
            "urls": ["http://a/", {"url": "http://b/", "api_key": "key-b"}],
            "api_key": "global"
        }"#;
        let cfg: ChainRpcConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.endpoints(), vec!["http://a/", "http://b/"]);

        let resolved = cfg.resolved_endpoints();
        assert_eq!(resolved[0], ("http://a/".to_string(), None));
        assert_eq!(resolved[1], ("http://b/".to_string(), Some("key-b".to_string())));
    }

    #[test]
    fn test_chain_rpc_mixed_entries_serde_roundtrip() {
        let cfg = ChainRpcConfig {
            urls: vec![
                EndpointEntry::Url("http://a/".into()),
                EndpointEntry::WithKey { url: "http://b/".into(), api_key: "secret".into() },
            ],
            ..Default::default()
        };
        let json = serde_json::to_value(&cfg).unwrap();
        let parsed: ChainRpcConfig = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.endpoints(), vec!["http://a/", "http://b/"]);
        assert_eq!(parsed.resolved_endpoints()[1].1, Some("secret".to_string()));
    }

    #[test]
    fn test_chain_rpc_operator_provenance_roundtrip() {
        let provenance = format!("sha256:{}", "a".repeat(64));
        let cfg =
            ChainRpcConfig { operator_provenance: Some(provenance.clone()), ..Default::default() };

        let parsed: ChainRpcConfig =
            serde_json::from_value(serde_json::to_value(cfg).unwrap()).unwrap();

        assert_eq!(parsed.operator_provenance.as_deref(), Some(provenance.as_str()));
    }
}
