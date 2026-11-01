// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
use crate::{private_io, protocol};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub global_id: i32,
    pub genesis_root: String,
    pub genesis_file: String,
    pub bond: String,
    pub bond_code_hash: String,
    pub policy_hash: String,
    pub worker_key_hash: String,
    pub pool: String,
    pub pool_code_hash: String,
    pub pool_config_hash: String,
}
impl Release {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.global_id == 3,
            "provider is restricted to isolated local development networks"
        );
        for s in [
            &self.genesis_root,
            &self.genesis_file,
            &self.bond_code_hash,
            &self.policy_hash,
            &self.worker_key_hash,
            &self.pool_code_hash,
            &self.pool_config_hash,
        ] {
            protocol::digest(&Value::String(s.clone()))?;
        }
        for s in [&self.bond, &self.pool] {
            ensure!(s.starts_with("0:") && s.len() == 66, "canonical basechain address");
            protocol::digest(&Value::String(s[2..].into()))?;
        }
        ensure!(self.bond != self.pool, "release account collision");
        Ok(())
    }
    pub fn scope(&self) -> Result<String> {
        let mut bytes = b"TOS-BR1-RELEASE\0".to_vec();
        bytes.extend(protocol::canonical(&serde_json::to_value(self)?)?);
        Ok(protocol::hash(&bytes))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    pub release: Release,
    pub execution_domain: String,
    pub fee: u64,
    pub funding_cap: u64,
    pub funding_wallet: String,
    pub rpc_url: String,
    pub proof_verifier: common::app_config::ProofVerifierConfig,
    pub proof_verifier_sha256: String,
}
impl Config {
    pub fn load(directory: &Path, payload: &Value) -> Result<Self> {
        let bytes = private_io::read(&directory.join("provider.json"), 64 * 1024)?;
        let value = protocol::parse(&bytes)?;
        let config: Self = serde_json::from_value(value)?;
        ensure!(config.schema == "tos.br1.provider.config.v1", "provider config schema");
        config.release.validate()?;
        ensure!(
            payload.get("release") == Some(&serde_json::to_value(&config.release)?),
            "operator release mismatch"
        );
        ensure!(
            config.fee > 0
                && config.fee <= i64::MAX as u64
                && config.funding_cap > 0
                && config.funding_cap <= i64::MAX as u64,
            "fee and funding bounds"
        );
        ensure!(
            config.proof_verifier.material_dir.is_none()
                && config.proof_verifier.liteserver_config.is_some()
                && config.proof_verifier.live_state_file.is_some()
                && config.proof_verifier.live_max_age_seconds.is_some_and(|age| age <= 60),
            "live proof policy required"
        );
        config.proof_verifier.validate()?;
        Ok(config)
    }
}
