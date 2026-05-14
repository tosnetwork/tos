/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
/*
 * Plain `serde::Deserialize` response shapes for the four wc=3 JVM
 * JSON-RPC endpoints (`jvm_deployContract`, `jvm_callContract`,
 * `jvm_getContractState`, `jvm_getReceipts`).
 *
 * The C++ producer is `jvm/core/rpc.cpp`. Field names below match
 * what the server emits literally; we use `#[serde(default)]` /
 * `Option<T>` for fields that are either absent on some responses
 * (e.g. `localResult` only present when `jvm_callContract` ran a
 * local simulation) or that the server omits when null.
 *
 * Unknown extra fields are tolerated by default; we never deny
 * future server-side additions.
 */
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JvmDeployResponse {
    /// 32-byte hex (no 0x prefix on the wire — the C++ side calls
    /// `hex_encode(contract_address)` which produces a plain hex
    /// string).
    pub contract_address: String,
    /// Hex BOC of the canonical `JvmDeployDescriptor` cell. Wallet
    /// callers should re-encode locally for byte-stability, but this
    /// value can be used as a cross-check during integration tests.
    pub deploy_descriptor_boc: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JvmCallResponse {
    /// 32-byte hex contract address the descriptor is bound to.
    pub contract_address: String,
    /// Hex BOC of the canonical `JvmCallDescriptor` cell.
    pub call_descriptor_boc: String,
    /// Present only when a local simulation ran (i.e. the caller
    /// supplied both `gasLimit` and `accountStateBoc` and the
    /// validator's runtime accepted them). Null otherwise.
    #[serde(default)]
    pub local_result: Option<JvmLocalResult>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JvmLocalResult {
    pub success: bool,
    #[serde(default)]
    pub out_of_gas: bool,
    #[serde(default)]
    pub out_of_memory: bool,
    #[serde(default)]
    pub gas_used: u64,
    #[serde(default)]
    pub vm_log: Option<String>,
    #[serde(default)]
    pub new_state_boc: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JvmContractStateView {
    pub contract_address: String,
    #[serde(default)]
    pub class_name: Option<String>,
    #[serde(default)]
    pub class_hash: Option<String>,
    #[serde(default)]
    pub storage_root_hash: Option<String>,
    #[serde(default)]
    pub storage_slots: Option<Vec<JvmStorageSlotView>>,
    #[serde(default)]
    pub storage_truncated: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JvmStorageSlotView {
    /// 32-byte hex (the keccak256 of `Wallet.<name>`).
    pub key: String,
    /// Hex of the raw storage value bytes.
    pub value: String,
}

/// One JVME event emitted from a wc=3 transaction's outbound message.
/// Matches the JSON shape `jvm_receipt_event_json` produces on the
/// validator side (`validator-engine/json-rpc-server-jvm.cpp:214`).
///
/// Topics are 32-byte hex strings; topic[0] follows Solidity
/// convention as `keccak256(event_signature)` so off-chain tooling
/// can grep for known events (e.g. `WalletExecuted(uint256,bytes32)`).
/// `data` is the ABI-encoded payload of the non-indexed args.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JvmReceiptEvent {
    pub block_seqno: u64,
    pub block_hash: String,
    pub transaction_lt: String,
    pub transaction_hash: String,
    pub log_index: u32,
    pub created_lt: String,
    pub created_at: u64,
    #[serde(default)]
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JvmReceiptsResponse {
    pub contract_address: String,
    #[serde(default)]
    pub receipts: Vec<JvmReceiptEvent>,
    /// True when the validator hit a per-call cap (kJvmReceiptMaxResults,
    /// kJvmReceiptMaxScannedTransactions, or the byte-budget) before
    /// finishing the requested block range.  Re-issue with a smaller
    /// range to fetch the remainder.
    #[serde(default)]
    pub truncated: bool,
    /// Number of transactions actually scanned (advisory).  Mainly for
    /// CLI debug output so operators can confirm the validator
    /// reached their requested range.
    #[serde(default)]
    pub scanned_transactions: u64,
}
