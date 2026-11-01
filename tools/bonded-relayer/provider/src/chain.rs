// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Only the established native proof verifier can create account capabilities.
use crate::config::Config;
use anyhow::{ensure, Result};
use chain_block::{Deserializable, MsgAddressInt};
use node_contracts::{
    proven_getters::{ProvenAccountState, ProvenGetterProvider, ReadPolicy},
    relayer_bond::{BondState, RelayerBond},
};
use std::str::FromStr;

pub struct Chain {
    verifier: ProvenGetterProvider,
}
impl Chain {
    pub fn verifier(&self) -> &ProvenGetterProvider {
        &self.verifier
    }
    pub fn new(config: &Config) -> Result<Self> {
        // Operator-provisioned helper lives inside the same private custody
        // boundary. The digest pins the release, independently of RPC answers.
        use std::os::unix::fs::MetadataExt;
        let path = &config.proof_verifier.executable;
        let m = std::fs::symlink_metadata(path)?;
        ensure!(
            path.is_absolute()
                && path.canonicalize()? == *path
                && m.is_file()
                && m.nlink() == 1
                && m.mode() & 0o022 == 0,
            "unsafe proof verifier"
        );
        let uid = unsafe { libc::geteuid() };
        ensure!(m.uid() == 0 || m.uid() == uid, "proof verifier ownership");
        ensure!(m.len() > 0 && m.len() <= 128 * 1024 * 1024, "proof verifier byte bound");
        ensure!(
            crate::protocol::hash(&std::fs::read(path)?) == config.proof_verifier_sha256,
            "proof verifier release pin"
        );
        let anchor_bytes = crate::private_io::read(&config.proof_verifier.anchor_file, 64 * 1024)?;
        let anchor = crate::protocol::parse(&anchor_bytes)?;
        ensure!(
            anchor["kind"] == "zerostate"
                && anchor["root_hash"] == config.release.genesis_root
                && anchor["file_hash"] == config.release.genesis_file,
            "release proof anchor mismatch"
        );
        Ok(Self { verifier: ProvenGetterProvider::new(&config.proof_verifier)? })
    }
    pub async fn bond(&self, config: &Config) -> Result<(ProvenAccountState, BondState)> {
        let address = MsgAddressInt::from_str(&config.release.bond)?;
        let state =
            self.verifier.read_account_with_config(&address, &[8, 19], &ReadPolicy::Live).await?;
        ensure!(
            state.evidence().account.code_hash == config.release.bond_code_hash,
            "bond code pin"
        );
        ensure!(
            RelayerBond::code()?.repr_hash().to_hex_string() == config.release.bond_code_hash,
            "unsupported bond code"
        );
        let data = state.account().get_data().ok_or_else(|| anyhow::anyhow!("bond data absent"))?;
        let bond = RelayerBond::decode(&address, &data)?;
        ensure!(RelayerBond::address(&bond.init)? == address, "bond immutable identity");
        ensure!(
            RelayerBond::policy(&bond.init)?.repr_hash().to_hex_string()
                == config.release.policy_hash,
            "bond policy pin"
        );
        ensure!(
            bond.init.global_id == config.release.global_id
                && hex::encode(bond.init.genesis_root) == config.release.genesis_root
                && hex::encode(bond.init.genesis_file) == config.release.genesis_file,
            "bond network pin"
        );
        ensure!(
            crate::protocol::hash(&bond.init.worker_key) == config.release.worker_key_hash
                && bond.init.worker == MsgAddressInt::from_str(&config.funding_wallet)?,
            "bond worker pin"
        );
        ensure!(
            bond.eligible(state.evidence().account.balance.parse::<u128>()?),
            "bond is not live and backed"
        );
        let global = state.config_param(19).ok_or_else(|| anyhow::anyhow!("global id missing"))?;
        let mut global = chain_block::SliceData::load_cell(global.clone())?;
        ensure!(
            global.get_next_i32()? == config.release.global_id
                && global.remaining_bits() == 0
                && global.remaining_references() == 0,
            "chain global id"
        );
        let version = chain_block::ConfigParam8::construct_from_cell(
            state.config_param(8).ok_or_else(|| anyhow::anyhow!("global version missing"))?.clone(),
        )?;
        ensure!(version.global_version.version >= 16, "global version 16 required");
        Ok((state, bond))
    }
    pub async fn funding(&self, config: &Config) -> Result<(ProvenAccountState, u32)> {
        let address = MsgAddressInt::from_str(&config.funding_wallet)?;
        let state =
            self.verifier.read_account_with_config(&address, &[8, 19], &ReadPolicy::Live).await?;
        let seed = crate::private_io::seed(&std::env::current_dir()?.join("funding.seed"))?;
        let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let code = chain_block::read_single_root_boc(hex::decode(
            node_contracts::wallet::wallet_contract::V3R2_CODE,
        )?)?;
        ensure!(
            state.evidence().account.code_hash == code.repr_hash().to_hex_string(),
            "funding wallet code"
        );
        let mut data = chain_block::SliceData::load_cell(
            state.account().get_data().ok_or_else(|| anyhow::anyhow!("wallet data absent"))?,
        )?;
        let seq = data.get_next_u32()?;
        ensure!(
            data.get_next_u32()? == 3
                && data.get_next_bytes(32)? == public
                && data.remaining_bits() == 0
                && data.remaining_references() == 0,
            "funding wallet identity"
        );
        let mut global = chain_block::SliceData::load_cell(
            state.config_param(19).ok_or_else(|| anyhow::anyhow!("global id missing"))?.clone(),
        )?;
        ensure!(
            global.get_next_i32()? == config.release.global_id
                && global.remaining_bits() == 0
                && global.remaining_references() == 0,
            "funding chain global id"
        );
        let version = chain_block::ConfigParam8::construct_from_cell(
            state.config_param(8).ok_or_else(|| anyhow::anyhow!("global version missing"))?.clone(),
        )?;
        ensure!(version.global_version.version >= 16, "global version 16 required");
        Ok((state, seq))
    }
}
