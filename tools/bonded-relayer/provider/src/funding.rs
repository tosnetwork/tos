// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Reuse the network-bound V3 SDK; no read or broadcast is available to signing.
use crate::{config::Config, private_io};
use anyhow::{bail, ensure, Result};
use chain_block::MsgAddressInt;
use common::{signer::Signer, tvm_stack_parser::TvmStackParser, WalletVersion};
use ed25519_dalek::{Signer as _, SigningKey};
use node_contracts::{wallet::wallet_contract::WalletContract, ContractProvider};
use std::{path::Path, str::FromStr, sync::Arc};
use tl_api::tos::tvm::StackEntry;

struct FundingSigner(SigningKey);
#[async_trait::async_trait]
impl Signer for FundingSigner {
    async fn public_key(&self) -> Result<Vec<u8>> {
        Ok(self.0.verifying_key().to_bytes().to_vec())
    }
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}
struct NoChainAccess;
#[async_trait::async_trait]
impl ContractProvider for NoChainAccess {
    async fn get_method(
        &self,
        _address: String,
        _method: &str,
        _stack: Vec<StackEntry>,
    ) -> Result<TvmStackParser> {
        bail!("signing builder must use an independently proven sequence")
    }
    async fn balance(&self, _address: &MsgAddressInt) -> Result<u64> {
        bail!("signing builder cannot query balance")
    }
}

pub async fn wallet(config: &Config, directory: &Path) -> Result<WalletContract> {
    let seed = private_io::seed(&directory.join("funding.seed"))?;
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let subwallet = 3u32;
    let derived = WalletContract::calculate_address(WalletVersion::V3R2, 0, subwallet, &public)?;
    ensure!(
        derived == MsgAddressInt::from_str(&config.funding_wallet)?,
        "funding wallet key/address mismatch"
    );
    WalletContract::new(
        Box::new(FundingSigner(SigningKey::from_bytes(&seed))),
        WalletVersion::V3R2,
        subwallet,
        0,
        config.release.global_id,
        Arc::new(NoChainAccess),
    )
    .await
}
