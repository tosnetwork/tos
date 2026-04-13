/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use anyhow::Context;
use common::tvm_stack_parser::TvmStackParser;
use std::sync::Arc;
use tl_api::tos::tvm::StackEntry;
use chain_block::MsgAddressInt;
use chain_rpc_client::v2::{
    RPCStackEntry, client_json_rpc::ClientJsonRpc, data_models::RunGetMethodParams,
};

/// Creates a new `ContractProvider` instance backed by `ContractProviderImpl`.
///
/// This macro is the legacy constructor for the narrow `ContractProvider` trait.
/// For new code, consider using [`chain_provider!`](crate::chain_provider!) or
/// [`chain_provider_as_contract!`](crate::chain_provider_as_contract!) which
/// produce a [`DefaultChainProvider`](crate::chain_provider::DefaultChainProvider)
/// — it implements both `ChainProvider` (full RPC surface) and `ContractProvider`.
///
/// # Example
/// ```ignore
/// let rpc_client = Arc::new(ClientJsonRpc::connect(...).unwrap());
/// let provider = contract_provider!(rpc_client);
/// ```
#[macro_export]
macro_rules! contract_provider {
    ($rpc_client:expr) => {
        std::sync::Arc::new($crate::provider::ContractProviderImpl::new($rpc_client))
            as std::sync::Arc<dyn $crate::provider::ContractProvider>
    };
}

/// Trait for executing smart contract get-methods and querying balances.
///
/// This is the narrow interface used by contract wrappers (elector, nominator,
/// wallet, config). It abstracts only the operations needed for reading
/// contract state.
///
/// For a broader abstraction covering `send_boc`, `get_config_param`, and
/// address/wallet queries, see [`ChainProvider`](crate::chain_provider::ChainProvider).
///
/// `DefaultChainProvider` implements both traits, so code can progressively
/// migrate without breakage.
#[async_trait::async_trait]
pub trait ContractProvider: Send + Sync {
    /// Run a TVM get-method on a contract and return the parsed result stack.
    async fn get_method(
        &self,
        address: String,
        method: &str,
        stack: Vec<StackEntry>,
    ) -> anyhow::Result<TvmStackParser>;

    /// Query the balance (in nanotos) of the given address.
    async fn balance(&self, address: &MsgAddressInt) -> anyhow::Result<u64>;
}

pub struct ContractProviderImpl {
    rpc_client: Arc<ClientJsonRpc>,
}

impl ContractProviderImpl {
    pub fn new(rpc_client: Arc<ClientJsonRpc>) -> Self {
        Self { rpc_client }
    }
}

#[async_trait::async_trait]
impl ContractProvider for ContractProviderImpl {
    async fn get_method(
        &self,
        address: String,
        method: &str,
        stack: Vec<StackEntry>,
    ) -> anyhow::Result<TvmStackParser> {
        let result = self
            .rpc_client
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
        Ok(TvmStackParser::new(result.stack.into_iter().map(Into::into).collect::<Vec<_>>()))
    }
    async fn balance(&self, address: &MsgAddressInt) -> anyhow::Result<u64> {
        let info = self
            .rpc_client
            .get_address_information(&address)
            .await
            .context("Failed to get account info")?;
        Ok(info.balance)
    }
}
