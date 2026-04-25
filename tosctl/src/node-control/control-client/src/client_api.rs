/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use common::serde_utils;
use chain_block::AccountStatus;

// --- Custom overlay types ---

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomOverlayNode {
    pub adnl_id: String,
    #[serde(default)]
    pub msg_sender: bool,
    #[serde(default)]
    pub msg_sender_priority: i32,
    #[serde(default)]
    pub block_sender: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomOverlayConfig {
    pub name: String,
    pub nodes: Vec<CustomOverlayNode>,
    #[serde(default)]
    pub sender_shards: Vec<ShardDescriptor>,
    #[serde(default)]
    pub skip_public_msg_send: bool,
    #[serde(default)]
    pub use_quic: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardDescriptor {
    pub workchain: i32,
    pub shard: i64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CustomOverlaysConfig {
    pub overlays: Vec<CustomOverlayConfig>,
}

// --- Collator management types ---

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CollatorEntry {
    #[serde(with = "serde_utils::hex_string")]
    pub adnl_id: Vec<u8>,
    pub workchain: i32,
    pub shard: i64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CollatorsListShard {
    pub workchain: i32,
    pub shard: i64,
    pub collators: Vec<CollatorEntry>,
    pub self_collate: bool,
    pub select_mode: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CollatorsList {
    pub shards: Vec<CollatorsListShard>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CollatorNodeWhitelist {
    pub enabled: bool,
    /// Each entry is a hex-encoded ADNL ID (256-bit).
    pub adnl_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NodeStats {
    pub stats: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AddCollatorRq {
    #[serde(with = "serde_utils::hex_string")]
    pub adnl_id: Vec<u8>,
    pub workchain: i32,
    pub shard: i64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AddLiteserverRq {
    #[serde(with = "serde_utils::hex_string")]
    pub key_hash: Vec<u8>,
    pub port: i32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CollatorNodeWhitelistRq {
    #[serde(with = "serde_utils::hex_string")]
    pub adnl_id: Vec<u8>,
    pub add: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ShardAccountState {
    #[serde(with = "serde_utils::account_status_as_str")]
    pub status: AccountStatus,
    pub balance: u128,
    pub last_paid: u32,
    pub last_trans: u64,
    #[serde(with = "serde_utils::hex_string")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Account {
    Nonexist,
    ShardAccountState(ShardAccountState),
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BlockchainConfigInfo {
    #[serde(with = "serde_utils::hex_string")]
    pub state_proof: Vec<u8>,
    #[serde(with = "serde_utils::hex_string")]
    pub config_proof: Vec<u8>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SignRq {
    #[serde(with = "serde_utils::hex_string")]
    pub key_hash: Vec<u8>,
    #[serde(with = "serde_utils::hex_string")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AddValidatorPermKeyRq {
    #[serde(with = "serde_utils::hex_string")]
    pub key_hash: Vec<u8>,
    pub election_date: i32,
    pub expire_at: i32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AddValidatorTempKeyRq {
    #[serde(with = "serde_utils::hex_string")]
    pub perm_key_hash: Vec<u8>,
    #[serde(with = "serde_utils::hex_string")]
    pub key_hash: Vec<u8>,
    pub expire_at: i32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AddAdnlAddressRq {
    #[serde(with = "serde_utils::hex_string")]
    pub key_hash: Vec<u8>,
    pub category: i32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AddValidatorAdnlAddrRq {
    #[serde(with = "serde_utils::hex_string")]
    pub perm_key_hash: Vec<u8>,
    #[serde(with = "serde_utils::hex_string")]
    pub key_hash: Vec<u8>,
    pub expire_at: i32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineValidatorConfig {
    #[serde(rename = "@type")]
    pub type_name: String, // "engine.validator.config"
    pub adnl: Vec<EngineAdnl>,
    pub dht: Vec<EngineDht>,
    pub validators: Vec<EngineValidator>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineAdnl {
    #[serde(rename = "@type")]
    pub type_name: String, // "engine.adnl"

    #[serde(with = "serde_utils::b64")]
    pub id: Vec<u8>,
    pub category: i32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineDht {
    #[serde(rename = "@type")]
    pub type_name: String, // "engine.dht"

    #[serde(with = "serde_utils::b64")]
    pub id: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineValidator {
    #[serde(rename = "@type")]
    pub type_name: String, // "engine.validator"

    #[serde(with = "serde_utils::b64")]
    pub id: Vec<u8>,
    pub temp_keys: Vec<EngineValidatorTempKey>,
    pub adnl_addrs: Vec<EngineValidatorAdnlAddress>,
    pub election_date: i64,
    pub expire_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineValidatorTempKey {
    #[serde(rename = "@type")]
    pub type_name: String, // "engine.validatorTempKey"

    #[serde(with = "serde_utils::b64")]
    pub key: Vec<u8>,
    pub expire_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineValidatorAdnlAddress {
    #[serde(rename = "@type")]
    pub type_name: String, // "engine.validatorAdnlAddress"
    #[serde(with = "serde_utils::b64")]
    pub id: Vec<u8>,
    pub expire_at: i64,
}

#[async_trait::async_trait]
pub trait ClientAPI: Send + Sync {
    async fn get_account_state(&mut self, address: &str) -> anyhow::Result<Account>;
    async fn get_blockchain_config(&mut self) -> anyhow::Result<BlockchainConfigInfo>;
    async fn get_validator_config(&mut self) -> anyhow::Result<EngineValidatorConfig>;
    async fn get_config_param(&mut self, id: u32) -> anyhow::Result<Vec<u8>>;

    async fn sign(&mut self, rq: &SignRq) -> anyhow::Result<Vec<u8>>;
    async fn generate_key_pair(&mut self) -> anyhow::Result<Vec<u8>>;
    async fn export_key_pub(&mut self, key_hash: &[u8]) -> anyhow::Result<Vec<u8>>;
    async fn add_validator_perm_key(&mut self, rq: &AddValidatorPermKeyRq) -> anyhow::Result<()>;
    async fn add_validator_temp_key(&mut self, rq: &AddValidatorTempKeyRq) -> anyhow::Result<()>;
    async fn add_adnl_address(&mut self, rq: &AddAdnlAddressRq) -> anyhow::Result<()>;
    async fn add_validator_adnl_addr(&mut self, rq: &AddValidatorAdnlAddrRq) -> anyhow::Result<()>;

    async fn send_boc(&mut self, boc: &[u8]) -> anyhow::Result<()>;

    // --- Collator management ---
    async fn show_collators_list(&mut self) -> anyhow::Result<CollatorsList>;
    async fn show_collator_node_whitelist(&mut self) -> anyhow::Result<CollatorNodeWhitelist>;
    async fn get_collator_options_json(&mut self) -> anyhow::Result<String>;
    async fn set_collator_options_json(&mut self, json: &str) -> anyhow::Result<()>;
    async fn add_collator(&mut self, rq: &AddCollatorRq) -> anyhow::Result<()>;
    async fn del_collator(&mut self, rq: &AddCollatorRq) -> anyhow::Result<()>;
    async fn clear_collators_list(&mut self) -> anyhow::Result<()>;
    async fn collator_node_set_whitelisted_validator(
        &mut self,
        rq: &CollatorNodeWhitelistRq,
    ) -> anyhow::Result<()>;
    async fn collator_node_set_whitelist_enabled(&mut self, enabled: bool) -> anyhow::Result<()>;
    async fn get_stats(&mut self) -> anyhow::Result<NodeStats>;
    async fn add_liteserver(&mut self, rq: &AddLiteserverRq) -> anyhow::Result<()>;
    async fn add_quic_addr(
        &mut self,
        ip: i32,
        port: i32,
        categories: Vec<i32>,
        priority_categories: Vec<i32>,
    ) -> anyhow::Result<()>;

    // --- Custom overlay management ---
    async fn add_custom_overlay(&mut self, config: &CustomOverlayConfig) -> anyhow::Result<()>;
    async fn del_custom_overlay(&mut self, name: &str) -> anyhow::Result<()>;
    async fn show_custom_overlays(&mut self) -> anyhow::Result<CustomOverlaysConfig>;
}

#[async_trait::async_trait]
pub trait Shutdown: Send + Sync {
    async fn shutdown(&mut self) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
pub trait ControlClient: ClientAPI + Shutdown {}

impl<T: ClientAPI + Shutdown> ControlClient for T {}
