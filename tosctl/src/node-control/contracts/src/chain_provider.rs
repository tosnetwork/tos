/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

//! # Chain Provider Abstraction Layer
//!
//! This module defines the `ChainProvider` trait — a TOS-facing abstraction for
//! chain RPC access. It wraps the full set of RPC operations that the codebase
//! uses when interacting with the chain, going beyond the narrower
//! [`ContractProvider`](super::ContractProvider) trait (which only covers
//! `get_method` and `balance`).
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │  Higher-level code (elections,       │
//! │  commands, service)                  │
//! └────────────────┬────────────────────┘
//!                  │ uses
//!                  ▼
//! ┌─────────────────────────────────────┐
//! │  ChainProvider trait                 │  <-- this module
//! │  (TOS-neutral RPC abstraction)      │
//! └────────────────┬────────────────────┘
//!                  │ implemented by
//!                  ▼
//! ┌─────────────────────────────────────┐
//! │  DefaultChainProvider              │  <-- adapter in this module
//! │  (delegates to ClientJsonRpc)       │
//! └────────────────┬────────────────────┘
//!                  │ wraps
//!                  ▼
//! ┌─────────────────────────────────────┐
//! │  chain-rpc-client (unchanged)       │
//! └─────────────────────────────────────┘
//! ```
//!
//! ## Migration Path
//!
//! 1. **Current state**: `ClientJsonRpc` is used directly across the codebase.
//!    The `ContractProvider` trait only abstracts `get_method`/`balance`.
//!
//! 2. **This phase**: `ChainProvider` trait is introduced with a
//!    `DefaultChainProvider` implementation that delegates to `ClientJsonRpc`.
//!    Existing code continues to work unchanged.
//!
//! 3. **Future**: Higher-level code migrates to `ChainProvider`. When a
//!    TOS-native RPC backend is ready, it implements `ChainProvider` directly
//!    and the adapter can be swapped out transparently.
//!
//! ## Relationship to ContractProvider
//!
//! `ChainProvider` is a superset: it covers raw RPC methods (send_boc,
//! get_config_param, address/wallet info) that `ContractProvider` does not.
//! The existing `ContractProvider` trait remains in place — contract wrappers
//! (elector, nominator, wallet) continue to use it. A blanket implementation
//! bridges `ChainProvider` into `ContractProvider` so that adopters of the
//! new trait automatically satisfy the old one.

use std::sync::Arc;

use anyhow::Context;
use chain_block::{ConfigParamEnum, MsgAddressInt};
use chain_rpc_client::v2::{
    RPCStackEntry,
    client_json_rpc::ClientJsonRpc,
    data_models::{
        GetAddressInformationRes, GetBlockTransactionsExtRes, GetBlockTransactionsRes,
        GetExtendedAddressInformationRes, GetMasterchainInfoRes, GetShardsRes,
        GetWalletInformationRes, RunGetMethodParams,
    },
};
use tl_api::tos::tvm::StackEntry;

use common::tvm_stack_parser::TvmStackParser;

use crate::ContractProvider;

// ─── Re-exports for convenience ────────────────────────────────────────────

/// Type alias: address information response (TOS-facing name).
pub type AddressInfo = GetAddressInformationRes;

/// Type alias: extended address information response (TOS-facing name).
pub type ExtendedAddressInfo = GetExtendedAddressInformationRes;

/// Type alias: wallet information response (TOS-facing name).
pub type WalletInfo = GetWalletInformationRes;

/// Type alias: masterchain head information (last block, used to drive
/// block-scanning consumers such as the chain-wide contract indexer).
pub type MasterchainInfo = GetMasterchainInfoRes;

/// Type alias: one page of a block's transaction short-IDs (`account`/`lt`/
/// `hash`), used to enumerate every account touched by a block without a
/// full-state scan.
pub type BlockTransactionsPage = GetBlockTransactionsRes;

/// Full block transaction page used by explorers to retain fee and message
/// summary fields without one account-history RPC per transaction.
pub type BlockTransactionsExtPage = GetBlockTransactionsExtRes;

/// Type alias: the current shard block descriptors for non-masterchain
/// workchains, as of a given masterchain seqno. On this chain almost every
/// contract lives on workchain 0 (the masterchain is reserved for
/// system contracts and directly-deployed actors) -- a block-scanning
/// consumer that only walks the masterchain would miss nearly everything.
pub type ShardsInfo = GetShardsRes;

/// Exact masterchain identity used to bind checkpoint-sensitive reads.
/// A seqno alone is not an identity: after a same-height reorganization it
/// may name a different state, so both hashes are mandatory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MasterchainCheckpoint {
    pub seqno: u32,
    pub root_hash: String,
    pub file_hash: String,
}

// ─── Trait ─────────────────────────────────────────────────────────────────

/// TOS chain RPC provider trait.
///
/// This is the primary abstraction for all chain RPC access. Implementations
/// may target the current JSON-RPC HTTP API (via [`DefaultChainProvider`]) or,
/// in the future, a TOS-native RPC endpoint.
///
/// All methods are async and return `anyhow::Result` for uniform error handling.
#[async_trait::async_trait]
pub trait ChainProvider: Send + Sync {
    /// Execute a get-method on a smart contract, returning parsed TVM stack.
    async fn run_get_method(
        &self,
        address: String,
        method: &str,
        stack: Vec<StackEntry>,
    ) -> anyhow::Result<TvmStackParser>;

    /// Execute against one exact masterchain checkpoint. Implementations that
    /// cannot pin state must fail rather than silently substitute latest state.
    async fn run_get_method_at(
        &self,
        _address: String,
        _method: &str,
        _stack: Vec<StackEntry>,
        _checkpoint: &MasterchainCheckpoint,
    ) -> anyhow::Result<TvmStackParser> {
        anyhow::bail!("checkpoint-pinned get-method execution is unsupported")
    }

    /// Query the balance (in nanotos) of an address.
    async fn get_balance(&self, address: &MsgAddressInt) -> anyhow::Result<u64>;

    /// Broadcast a serialized BOC (bag-of-cells) message to the network.
    async fn send_boc(&self, boc: &[u8]) -> anyhow::Result<()>;

    /// Retrieve a blockchain configuration parameter by its numeric ID.
    async fn get_config_param(&self, param_id: u32) -> anyhow::Result<ConfigParamEnum>;

    /// Get basic address information (balance, state, code, data).
    async fn get_address_info(&self, address: &MsgAddressInt) -> anyhow::Result<AddressInfo>;

    /// Get extended address information (includes raw account state).
    async fn get_extended_address_info(
        &self,
        address: &MsgAddressInt,
    ) -> anyhow::Result<ExtendedAddressInfo>;

    /// Get wallet-specific information (wallet type, seqno, etc.).
    async fn get_wallet_info(&self, address: &MsgAddressInt) -> anyhow::Result<WalletInfo>;

    /// Get the current masterchain head (last block seqno/shard identity).
    /// The masterchain block's own `shard` value is constant across all its
    /// past seqnos too, so callers can reuse it to scan any earlier block.
    async fn get_masterchain_info(&self) -> anyhow::Result<MasterchainInfo>;

    /// Get the current shard block descriptors (for non-masterchain
    /// workchains) as of the given masterchain seqno.
    async fn get_shards(&self, seqno: u32) -> anyhow::Result<ShardsInfo>;

    /// List the accounts (as `account`/`lt`/`hash` short-IDs) that had a
    /// transaction in the given block, paginated via `after_lt`/`after_account`
    /// when `incomplete` comes back `true`. This is the primitive a
    /// chain-wide indexer walks block-by-block to discover every account
    /// without a full-state dump.
    async fn get_block_transactions_page(
        &self,
        workchain: i32,
        shard: i64,
        seqno: u32,
        after_lt: Option<u64>,
        after_account: Option<&str>,
        count: u32,
    ) -> anyhow::Result<BlockTransactionsPage>;

    /// Rich block transaction page. Alternate providers may leave this
    /// unsupported; the indexer falls back to short transaction identities.
    async fn get_block_transactions_ext_page(
        &self,
        _workchain: i32,
        _shard: i64,
        _seqno: u32,
        _after_lt: Option<u64>,
        _after_account: Option<&str>,
        _count: u32,
    ) -> anyhow::Result<BlockTransactionsExtPage> {
        anyhow::bail!("extended block transactions are not supported")
    }

    /// Returns the block's chain-authored Unix timestamp. The default keeps
    /// lightweight test providers source-compatible; production providers
    /// must override it to avoid publishing an invented explorer time.
    async fn get_block_timestamp(
        &self,
        _workchain: i32,
        _shard: i64,
        _seqno: u32,
    ) -> anyhow::Result<u32> {
        Ok(0)
    }
}

// ─── JSON-RPC adapter implementation ─────────────────────────────────────────

/// Adapter that implements [`ChainProvider`] by delegating to the existing
/// JSON-RPC HTTP API client (`ClientJsonRpc`).
///
/// This is the default (and currently only) backend. It preserves full
/// compatibility with the JSON-RPC HTTP API while exposing the TOS-neutral trait.
pub struct DefaultChainProvider {
    client: Arc<ClientJsonRpc>,
}

impl DefaultChainProvider {
    /// Create a new provider wrapping an existing `ClientJsonRpc` instance.
    pub fn new(client: Arc<ClientJsonRpc>) -> Self {
        Self { client }
    }

    /// Access the underlying `ClientJsonRpc` for operations not yet covered
    /// by the trait (escape hatch during migration).
    pub fn inner(&self) -> &Arc<ClientJsonRpc> {
        &self.client
    }
}

#[async_trait::async_trait]
impl ChainProvider for DefaultChainProvider {
    async fn run_get_method(
        &self,
        address: String,
        method: &str,
        stack: Vec<StackEntry>,
    ) -> anyhow::Result<TvmStackParser> {
        let result = self
            .client
            .run_get_method(&RunGetMethodParams {
                address,
                method_id: method.to_owned(),
                stack: Some(stack.into_iter().map(RPCStackEntry::from).collect::<Vec<_>>()),
                seqno: None,
            })
            .await
            .map_err(|e| anyhow::anyhow!("get-method {} error: {}", method, e))?;
        if result.exit_code != 0 {
            anyhow::bail!("get-method {} error: exit_code={}", method, result.exit_code);
        }
        // The JSON-RPC server serializes the TVM stack top-first (vm::Stack::at(0)
        // is the top). Decoders index entries in get-method return order, so
        // reverse to bottom-first at the RPC boundary.
        Ok(TvmStackParser::new(result.stack.into_iter().rev().map(Into::into).collect::<Vec<_>>()))
    }

    async fn run_get_method_at(
        &self,
        address: String,
        method: &str,
        stack: Vec<StackEntry>,
        checkpoint: &MasterchainCheckpoint,
    ) -> anyhow::Result<TvmStackParser> {
        anyhow::ensure!(checkpoint.seqno > 0, "get-method checkpoint must be non-zero");
        anyhow::ensure!(
            checkpoint.root_hash.len() == 64 && checkpoint.file_hash.len() == 64,
            "get-method checkpoint hashes must be 32-byte lowercase hex"
        );
        let result = self
            .client
            .run_get_method(&RunGetMethodParams {
                address,
                method_id: method.to_owned(),
                stack: Some(stack.into_iter().map(RPCStackEntry::from).collect::<Vec<_>>()),
                seqno: Some(checkpoint.seqno),
            })
            .await
            .map_err(|e| anyhow::anyhow!("checkpoint get-method {} error: {}", method, e))?;
        anyhow::ensure!(
            result.exit_code == 0,
            "checkpoint get-method {} exit_code={}",
            method,
            result.exit_code
        );
        let block = result
            .block_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("checkpoint get-method omitted block identity"))?;
        validate_masterchain_checkpoint(block, checkpoint)?;
        Ok(TvmStackParser::new(result.stack.into_iter().rev().map(Into::into).collect::<Vec<_>>()))
    }

    async fn get_balance(&self, address: &MsgAddressInt) -> anyhow::Result<u64> {
        let info = self
            .client
            .get_address_information(address)
            .await
            .context("Failed to get account info")?;
        Ok(info.balance)
    }

    async fn send_boc(&self, boc: &[u8]) -> anyhow::Result<()> {
        self.client.send_boc(&boc.to_vec()).await
    }

    async fn get_config_param(&self, param_id: u32) -> anyhow::Result<ConfigParamEnum> {
        self.client.get_config_param(param_id).await
    }

    async fn get_address_info(&self, address: &MsgAddressInt) -> anyhow::Result<AddressInfo> {
        self.client.get_address_information(address).await
    }

    async fn get_extended_address_info(
        &self,
        address: &MsgAddressInt,
    ) -> anyhow::Result<ExtendedAddressInfo> {
        self.client.get_extended_address_information(address).await
    }

    async fn get_wallet_info(&self, address: &MsgAddressInt) -> anyhow::Result<WalletInfo> {
        self.client.get_wallet_information(address).await
    }

    async fn get_masterchain_info(&self) -> anyhow::Result<MasterchainInfo> {
        self.client.get_masterchain_info().await
    }

    async fn get_shards(&self, seqno: u32) -> anyhow::Result<ShardsInfo> {
        self.client.get_shards(seqno).await
    }

    async fn get_block_transactions_page(
        &self,
        workchain: i32,
        shard: i64,
        seqno: u32,
        after_lt: Option<u64>,
        after_account: Option<&str>,
        count: u32,
    ) -> anyhow::Result<BlockTransactionsPage> {
        self.client
            .get_block_transactions_page(
                workchain,
                &shard.to_string(),
                seqno,
                after_lt,
                after_account,
                count,
            )
            .await
    }

    async fn get_block_transactions_ext_page(
        &self,
        workchain: i32,
        shard: i64,
        seqno: u32,
        after_lt: Option<u64>,
        after_account: Option<&str>,
        count: u32,
    ) -> anyhow::Result<BlockTransactionsExtPage> {
        self.client
            .get_block_transactions_ext_page(
                workchain,
                &shard.to_string(),
                seqno,
                after_lt,
                after_account,
                count,
            )
            .await
    }

    async fn get_block_timestamp(
        &self,
        workchain: i32,
        shard: i64,
        seqno: u32,
    ) -> anyhow::Result<u32> {
        Ok(self.client.get_block_header(workchain, &shard.to_string(), seqno).await?.gen_utime)
    }
}

fn validate_masterchain_checkpoint(
    block: &chain_rpc_client::v2::data_models::BlockIdExt,
    expected: &MasterchainCheckpoint,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        block.workchain == -1
            && block.seqno == expected.seqno
            && hex::encode(&block.root_hash) == expected.root_hash
            && hex::encode(&block.file_hash) == expected.file_hash,
        "checkpoint get-method returned another block"
    );
    Ok(())
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;
    use chain_rpc_client::v2::data_models::BlockIdExt;

    fn block(root: u8, file: u8) -> BlockIdExt {
        BlockIdExt {
            r#type: "tos.blockIdExt".to_owned(),
            workchain: -1,
            shard: i64::MIN,
            seqno: 42,
            root_hash: vec![root; 32],
            file_hash: vec![file; 32],
        }
    }

    #[test]
    fn checkpoint_rejects_same_height_reorganization() {
        let expected = MasterchainCheckpoint {
            seqno: 42,
            root_hash: hex::encode([1; 32]),
            file_hash: hex::encode([2; 32]),
        };
        assert!(validate_masterchain_checkpoint(&block(1, 2), &expected).is_ok());
        assert!(validate_masterchain_checkpoint(&block(9, 2), &expected).is_err());
        assert!(validate_masterchain_checkpoint(&block(1, 9), &expected).is_err());
    }
}

// ─── Bridge: ChainProvider → ContractProvider ──────────────────────────────

/// Blanket adapter that allows any `ChainProvider` to be used where a
/// `ContractProvider` is expected.
///
/// This means code that adopts `ChainProvider` automatically satisfies
/// contract wrapper requirements without additional glue.
#[async_trait::async_trait]
impl ContractProvider for DefaultChainProvider {
    async fn get_method(
        &self,
        address: String,
        method: &str,
        stack: Vec<StackEntry>,
    ) -> anyhow::Result<TvmStackParser> {
        self.run_get_method(address, method, stack).await
    }

    async fn balance(&self, address: &MsgAddressInt) -> anyhow::Result<u64> {
        self.get_balance(address).await
    }
}

// ─── Bridge: Arc<dyn ChainProvider> → Arc<dyn ContractProvider> ──────────

/// Adapter that wraps an `Arc<dyn ChainProvider>` to satisfy the narrower
/// [`ContractProvider`] trait. Use [`contract_provider_from`] to create one.
struct ContractProviderAdapter {
    inner: Arc<dyn ChainProvider>,
}

#[async_trait::async_trait]
impl ContractProvider for ContractProviderAdapter {
    async fn get_method(
        &self,
        address: String,
        method: &str,
        stack: Vec<StackEntry>,
    ) -> anyhow::Result<TvmStackParser> {
        self.inner.run_get_method(address, method, stack).await
    }

    async fn balance(&self, address: &MsgAddressInt) -> anyhow::Result<u64> {
        self.inner.get_balance(address).await
    }
}

/// Convert an `Arc<dyn ChainProvider>` into an `Arc<dyn ContractProvider>`.
///
/// This is the recommended bridge for code that needs the narrower
/// `ContractProvider` trait but receives a `ChainProvider`.
pub fn contract_provider_from(chain: Arc<dyn ChainProvider>) -> Arc<dyn ContractProvider> {
    Arc::new(ContractProviderAdapter { inner: chain })
}

// ─── Constructor macro ─────────────────────────────────────────────────────

/// Creates a new `DefaultChainProvider` wrapped in an `Arc<dyn ChainProvider>`.
///
/// # Example
/// ```ignore
/// let rpc_client = Arc::new(ClientJsonRpc::connect(...).unwrap());
/// let provider = chain_provider!(rpc_client);
/// ```
#[macro_export]
macro_rules! chain_provider {
    ($rpc_client:expr) => {
        std::sync::Arc::new($crate::chain_provider::DefaultChainProvider::new($rpc_client))
            as std::sync::Arc<dyn $crate::chain_provider::ChainProvider>
    };
}

/// Creates a `DefaultChainProvider` as an `Arc<dyn ContractProvider>`.
///
/// This is a convenience for code that still expects the narrower
/// [`ContractProvider`] trait but wants to use `DefaultChainProvider`
/// as the implementation.
///
/// # Example
/// ```ignore
/// let rpc_client = Arc::new(ClientJsonRpc::connect(...).unwrap());
/// let provider = chain_provider_as_contract!(rpc_client);
/// ```
#[macro_export]
macro_rules! chain_provider_as_contract {
    ($rpc_client:expr) => {
        std::sync::Arc::new($crate::chain_provider::DefaultChainProvider::new($rpc_client))
            as std::sync::Arc<dyn $crate::provider::ContractProvider>
    };
}
