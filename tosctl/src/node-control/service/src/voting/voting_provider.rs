/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use adnl::client::AdnlClientConfig;
use chain_block::ValidatorSet;
use control_client::{
    client_adnl::ControlClientAdnl,
    client_api::{ControlClient, SignRq},
};
use std::collections::HashMap;

#[derive(Clone)]
pub struct ValidatorEntry {
    pub key_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub adnl_addrs: Vec<(Vec<u8>, u64)>,
    pub expired_at: u64,
}

pub struct ValidatorConfig {
    pub keys: HashMap<u64, ValidatorEntry>,
}

impl ValidatorConfig {
    pub fn from_map(keys: HashMap<u64, ValidatorEntry>) -> Self {
        Self { keys }
    }

    pub fn find_key(&self, public_key: &[u8]) -> Option<ValidatorEntry> {
        self.keys
            .iter()
            .find(|(_, entry)| entry.public_key == public_key)
            .map(|(_, entry)| entry.clone())
    }
}

#[async_trait::async_trait]
pub trait VotingProvider: Send + Sync {
    async fn setup(&mut self) -> anyhow::Result<()>;
    async fn shutdown(&mut self) -> anyhow::Result<()>;
    async fn send_boc(&mut self, boc: &[u8]) -> anyhow::Result<()>;
    async fn sign(&mut self, message: &[u8], key_id: Vec<u8>) -> anyhow::Result<Vec<u8>>;
    async fn validator_config(&mut self) -> anyhow::Result<ValidatorConfig>;
    async fn get_current_vset(&mut self) -> anyhow::Result<ValidatorSet>;
    async fn export_public_key(&mut self, key_id: &[u8]) -> anyhow::Result<Vec<u8>>;
}

pub struct VotingProviderImpl {
    client: Box<dyn ControlClient>,
}

impl VotingProviderImpl {
    pub fn new(config: AdnlClientConfig) -> Self {
        let client = ControlClientAdnl::new(config, 4);
        Self { client: Box::new(client) }
    }

    #[cfg(test)]
    pub fn with_client(client: Box<dyn ControlClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl VotingProvider for VotingProviderImpl {
    async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> anyhow::Result<()> {
        self.client.shutdown().await
    }

    async fn send_boc(&mut self, boc: &[u8]) -> anyhow::Result<()> {
        self.client.send_boc(boc).await
    }

    async fn sign(&mut self, message: &[u8], key_id: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        self.client.sign(&SignRq { key_hash: key_id, data: message.to_vec() }).await
    }

    async fn validator_config(&mut self) -> anyhow::Result<ValidatorConfig> {
        let remote = self.client.get_validator_config().await?;
        let keys = remote
            .validators
            .into_iter()
            .map(|validator| {
                let adnl_addrs: Vec<(Vec<u8>, u64)> = validator
                    .adnl_addrs
                    .iter()
                    .map(|entry| (entry.id.clone(), entry.expire_at as u64))
                    .collect();
                (
                    validator.election_date as u64,
                    ValidatorEntry {
                        key_id: validator.id,
                        public_key: vec![],
                        adnl_addrs,
                        expired_at: validator.expire_at as u64,
                    },
                )
            })
            .collect::<HashMap<u64, ValidatorEntry>>();
        Ok(ValidatorConfig::from_map(keys))
    }

    async fn get_current_vset(&mut self) -> anyhow::Result<ValidatorSet> {
        let bytes = self.client.get_config_param(34).await?;
        control_client::config_params::parse_config_param_34(&bytes)
    }

    async fn export_public_key(&mut self, key_id: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.client.export_key_pub(key_id).await
    }
}

#[cfg(test)]
#[path = "p0_provider_tests.rs"]
mod p0_provider_tests;
