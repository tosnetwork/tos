// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
use crate::{private_io, protocol};
use anyhow::{ensure, Result};
use serde::Deserialize;
use serde_json::Value;
use std::path::Path;

pub fn validate_global_id(global_id: i32) -> Result<()> {
    ensure!(
        global_id == 3 || (cfg!(feature = "public-testnet-pilot") && global_id == 2),
        "network requires an explicitly built public-testnet pilot provider"
    );
    Ok(())
}

/// The release pins, shared with the wallet. Network admission
/// ([`validate_global_id`]) is this provider's policy and is checked at every
/// path a release enters by.
pub use br1_client::release::Release;

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
        validate_global_id(config.release.global_id)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_testnet_requires_build_opt_in_and_other_networks_always_refuse() {
        assert!(validate_global_id(3).is_ok());
        assert_eq!(validate_global_id(2).is_ok(), cfg!(feature = "public-testnet-pilot"));
        for global_id in [i32::MIN, -1, 0, 1, 4, 16, i32::MAX] {
            assert!(validate_global_id(global_id).is_err());
        }
    }
}
