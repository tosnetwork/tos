/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::v2::RPCStackEntry;
use chain_block::{AccountId, MsgAddrStd, MsgAddress};
use common::serde_utils;
use std::fmt::{Display, Formatter};

pub fn make_addr(account_id: &AccountId) -> anyhow::Result<MsgAddress> {
    let addr = MsgAddress::AddrStd(MsgAddrStd {
        anycast: None,
        workchain_id: -1,
        address: account_id.clone(),
    });

    Ok(addr)
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct RunGetMethodParams {
    pub address: String,
    #[serde(rename = "method")]
    pub method_id: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<Vec<RPCStackEntry>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seqno: Option<u32>,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct RunGetMethodRes {
    pub gas_used: i64,
    pub stack: Vec<RPCStackEntry>,
    pub exit_code: i32,
    pub last_transaction_id: Option<TransactionId>,
    pub block_id: Option<BlockIdExt>,
}

#[derive(Clone, Default, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountState {
    Active,
    #[default]
    Uninitialized,
    Frozen,
}

impl std::fmt::Display for AccountState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountState::Active => write!(f, "active"),
            AccountState::Uninitialized => write!(f, "uninit"),
            AccountState::Frozen => write!(f, "frozen"),
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct GetAddressInformationRes {
    #[serde(rename = "@type")]
    pub r#type: String,
    #[serde(with = "serde_utils::u64_as_str_or_num")]
    pub balance: u64,
    #[serde(default, with = "serde_utils::option_b64")]
    pub code: Option<Vec<u8>>,
    #[serde(default, with = "serde_utils::option_b64")]
    pub data: Option<Vec<u8>>,
    pub last_transaction_id: TransactionId,
    pub block_id: BlockIdExt,
    pub sync_utime: u64,
    #[serde(default)]
    pub extra_currencies: Vec<serde_json::Value>,
    pub state: AccountState,
    #[serde(default)]
    pub frozen_hash: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct GetExtendedAddressInformationRes {
    #[serde(rename = "@type")]
    pub r#type: String,

    pub address: AccountAddress,
    #[serde(with = "serde_utils::u64_as_str_or_num")]
    pub balance: u64,
    pub extra_currencies: Vec<serde_json::Value>,

    pub last_transaction_id: TransactionId,
    pub block_id: BlockIdExt,

    pub sync_utime: u64,
    pub account_state: RawAccountState,
    pub revision: i64,
    //#[serde(rename = "@extra")]
    //pub extra: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct AccountAddress {
    #[serde(rename = "@type")]
    pub r#type: String,
    pub account_address: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct TransactionId {
    #[serde(rename = "@type")]
    pub r#type: String,

    #[serde(with = "serde_utils::u64_as_str")]
    pub lt: u64,

    #[serde(with = "serde_utils::b64")]
    pub hash: Vec<u8>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct BlockIdExt {
    #[serde(rename = "@type")]
    pub r#type: String,
    pub workchain: i32,

    #[serde(with = "serde_utils::i64_as_str")]
    pub shard: i64,
    pub seqno: u32,

    #[serde(with = "serde_utils::b64")]
    pub root_hash: Vec<u8>,

    #[serde(with = "serde_utils::b64")]
    pub file_hash: Vec<u8>,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct RawAccountState {
    #[serde(rename = "@type")]
    pub r#type: String,

    #[serde(default, with = "serde_utils::option_b64")]
    pub code: Option<Vec<u8>>,

    #[serde(default, with = "serde_utils::option_b64")]
    pub data: Option<Vec<u8>>,

    #[serde(default, with = "serde_utils::option_b64")]
    pub frozen_hash: Option<Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum WalletType {
    #[serde(rename = "wallet simple r1")]
    SimpleR1,
    #[serde(rename = "wallet simple r2")]
    SimpleR2,
    #[serde(rename = "wallet simple r3")]
    SimpleR3,
    #[serde(rename = "wallet v2 r1")]
    V2R1,
    #[serde(rename = "wallet v2 r2")]
    V2R2,
    #[serde(rename = "wallet v3 r1")]
    V3R1,
    #[serde(rename = "wallet v3 r2")]
    V3R2,
    #[serde(rename = "wallet v4 r1")]
    V4R1,
    #[serde(rename = "wallet v4 r2")]
    V4R2,
    #[serde(rename = "wallet v5 r1")]
    V5R1,
    #[serde(untagged)]
    Other(String),
}

impl Display for WalletType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletType::SimpleR1 => write!(f, "SimpleR1"),
            WalletType::SimpleR2 => write!(f, "SimpleR2"),
            WalletType::SimpleR3 => write!(f, "SimpleR3"),
            WalletType::V2R1 => write!(f, "V2R1"),
            WalletType::V2R2 => write!(f, "V2R2"),
            WalletType::V3R1 => write!(f, "V3R1"),
            WalletType::V3R2 => write!(f, "V3R2"),
            WalletType::V4R1 => write!(f, "V4R1"),
            WalletType::V4R2 => write!(f, "V4R2"),
            WalletType::V5R1 => write!(f, "V5R1"),
            WalletType::Other(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GetWalletInformationRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    pub wallet: bool,
    #[serde(with = "serde_utils::u64_as_str_or_num")]
    pub balance: u64,
    pub account_state: AccountState,
    pub last_transaction_id: TransactionId,
    pub wallet_type: Option<WalletType>,
    pub seqno: Option<u32>,
    pub wallet_id: Option<u64>,
}

// ─── account capability / permission inspection responses ───────────

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct AccountCapabilityRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    pub address: String,
    pub account_model: String,
    pub authorization_version: String,
    pub supports_delegation: bool,
    pub supports_sessions: bool,
    pub supports_agents: bool,
    pub delegation_source: String,
    pub session_source: String,
    pub agent_source: String,
    pub capability_maturity: String,
    pub account_state: String,
    pub revision: i64,
    #[serde(default)]
    pub supports_sponsorship: Option<bool>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct AccountDelegationGrant {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
    pub id: String,
    pub grantor: String,
    pub grantee: String,
    pub scope: String,
    pub constraints: serde_json::Value,
    #[serde(default)]
    pub constraints_extensions: Option<serde_json::Value>,
    pub created_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub revocable: bool,
    pub revocation_reference: Option<String>,
    pub status: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct AccountSessionCapability {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
    pub session_id: String,
    pub principal: String,
    pub scope: String,
    pub constraints: serde_json::Value,
    #[serde(default)]
    pub constraints_extensions: Option<serde_json::Value>,
    pub created_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub revocable: bool,
    pub status: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct AccountAgentCapability {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
    pub agent_id: String,
    pub principal: String,
    pub scope: String,
    pub constraints: serde_json::Value,
    #[serde(default)]
    pub constraints_extensions: Option<serde_json::Value>,
    pub created_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub revocable: bool,
    pub status: String,
}

// ─── lifecycle mutation requests / responses ────────────────────────────

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct LifecycleGrantRequest {
    pub address: String,
    pub grantee: String,
    pub scope: String,
    #[serde(default)]
    pub constraints: serde_json::Value,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub revocable: bool,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct LifecycleRevokeRequest {
    pub address: String,
    pub permission_id: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct LifecycleMutationResultRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    pub method: String,
    pub account_model: String,
    pub accepted: bool,
    pub mutation_intent: serde_json::Value,
    pub affected_object_preview: serde_json::Value,
}

// ─── transaction surface responses ──────────────────────────────────────

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct TransactionIntentRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    pub from: String,
    pub account_model: String,
    pub authorization_version: String,
    pub action: serde_json::Value,
    pub authorization_roles: serde_json::Value,
    pub fee_intent: Option<serde_json::Value>,
    pub replay_protection: Option<serde_json::Value>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct SigningPayloadRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    pub payload_version: u32,
    pub payload_encoding: String,
    pub payload: String,
    pub chain_id: i64,
    pub replay_protection: Option<serde_json::Value>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct SubmissionResultRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    pub accepted: bool,
    pub transaction_hash: String,
    pub submission_id: String,
    #[serde(default)]
    pub status: Option<i32>,
    pub authorization_roles: Option<serde_json::Value>,
}

/// Outcome of one exact-BOC submission attempt against one bound RPC endpoint.
///
/// `Unknown` is deliberately distinct from `Rejected`: a transport failure or
/// malformed response may happen after the endpoint accepted the bytes.  A
/// caller must resolve the locally computed `cell_hash` before deciding to
/// submit those exact bytes again.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactBocSubmissionStatus {
    Accepted,
    Rejected,
    Unknown,
}

/// Explicit owner-pinned network domain for production exact relay writes.
///
/// `network_id` is the protocol-level owner label.  It is not learned from an
/// RPC endpoint and therefore cannot be used by an endpoint to authorize
/// itself.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct RelayNetworkDomainPin {
    pub network_id: String,
    pub global_id: i32,
    pub zero_state_root_hash: String,
    pub zero_state_file_hash: String,
    /// Workchain containing the authorized source/economic action. This is
    /// distinct from the masterchain coordinate of the zero-state BlockIdExt.
    pub workchain_id: i32,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ExactBocSubmissionResult {
    pub status: ExactBocSubmissionStatus,
    /// Hash of the exact root cell computed locally before any network I/O.
    pub cell_hash: String,
    /// The sole endpoint against which this attempt was made.
    pub endpoint: String,
    /// Present only for the production relay API, after a primary-only
    /// preflight matched the explicit owner pin immediately before the write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_domain: Option<RelayNetworkDomainPin>,
    /// Admission status returned by `sendBocReturnHash`; this is endpoint
    /// acknowledgement metadata, never execution or finality evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_status: Option<i32>,
    /// Endpoint-provided message hash, normalized to the same encoding as
    /// `cell_hash`, when it was valid and matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_cell_hash: Option<String>,
    /// Bounded diagnostic detail.  This is evidence about the attempt, not a
    /// signal that retrying against another endpoint is safe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

// ─── getMasterchainInfo response ─────────────────────────────────────

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GetMasterchainInfoRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    pub last: BlockIdExt,
    #[serde(default)]
    pub state_root_hash: String,
    pub init: Option<BlockIdExt>,
}

// ─── getTransactions response ────────────────────────────────────────

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GetTransactionsRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    #[serde(default)]
    pub transactions: Vec<RawTransaction>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct RawTransaction {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    pub block_id: Option<BlockIdExt>,
    /// Base64-encoded transaction BOC
    #[serde(default)]
    pub data: String,
    #[serde(default, with = "serde_utils::u64_as_str_or_num")]
    pub lt: u64,
    #[serde(default)]
    pub utime: u32,
    #[serde(default)]
    pub hash: String,
}

// ─── lookupBlock / shards responses ──────────────────────────────────

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GetShardsRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    #[serde(default)]
    pub shards: Vec<BlockIdExt>,
}

// ─── getBlockTransactions response ───────────────────────────────────

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GetBlockTransactionsRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    pub id: Option<BlockIdExt>,
    pub req_count: Option<u32>,
    #[serde(default)]
    pub incomplete: bool,
    #[serde(default)]
    pub transactions: Vec<ShortTxId>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GetBlockTransactionsExtRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    pub id: Option<BlockIdExt>,
    pub req_count: Option<u32>,
    #[serde(default)]
    pub incomplete: bool,
    #[serde(default)]
    pub transactions: Vec<BlockTransactionExt>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct BlockTransactionExt {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub account: String,
    #[serde(default, with = "serde_utils::u64_as_str_or_num")]
    pub lt: u64,
    #[serde(default)]
    pub utime: u32,
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub fee: String,
    #[serde(default)]
    pub in_msg_hash: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GetBlockHeaderRes {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    #[serde(default)]
    pub gen_utime: u32,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct ShortTxId {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,
    #[serde(default)]
    pub account: String,
    #[serde(default, with = "serde_utils::u64_as_str_or_num")]
    pub lt: u64,
    #[serde(default)]
    pub hash: String,
}
