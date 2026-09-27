/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::traits::ElectionsProvider;
use crate::providers::traits::{Account, ValidatorConfig, ValidatorEntry};
use adnl::client::AdnlClientConfig;
use anyhow::Context;
use chain_block::{Cell, ConfigParam15, ConfigParamEnum, MsgAddressInt, ValidatorSet};
use contracts::ChainProvider;
use control_client::{
    client_adnl::ControlClientAdnl,
    client_api::{
        AddAdnlAddressRq, AddValidatorAdnlAddrRq, AddValidatorPermKeyRq, AddValidatorTempKeyRq,
        ClientAPI, SignRq,
    },
};
use std::collections::HashMap;
use std::sync::Arc;

// Validator control and chain JSON-RPC are distinct protocols. Election
// parameters are read through the chain provider, not the control socket.
pub struct DefaultElectionsProvider {
    client: ControlClientAdnl,
    chain_provider: Arc<dyn ChainProvider>,
}

impl DefaultElectionsProvider {
    pub fn new(config: AdnlClientConfig, chain_provider: Arc<dyn ChainProvider>) -> Self {
        Self { client: ControlClientAdnl::new(config, 4), chain_provider }
    }
}

#[async_trait::async_trait]
impl ElectionsProvider for DefaultElectionsProvider {
    async fn setup(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn shutdown(&mut self) -> anyhow::Result<()> {
        self.client.shutdown().await
    }
    async fn new_validator_key(
        &mut self,
        since: u64,
        until: u64,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let key_id = self.client.generate_key_pair().await?;
        self.client
            .add_validator_perm_key(&AddValidatorPermKeyRq {
                key_hash: key_id.clone(),
                election_date: since as i32,
                expire_at: until as i32,
            })
            .await
            .context("add_validator_perm_key")?;
        self.client
            .add_validator_temp_key(&AddValidatorTempKeyRq {
                perm_key_hash: key_id.clone(),
                key_hash: key_id.clone(),
                expire_at: until as i32,
            })
            .await
            .context("add_validator_temp_key")?;
        let pub_key = self.client.export_key_pub(&key_id).await.context("export_key_pub")?;
        Ok((key_id, pub_key))
    }
    async fn new_adnl_addr(
        &mut self,
        validator_key_id: Vec<u8>,
        until: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let key_id = self.client.generate_key_pair().await?;
        self.client
            .add_adnl_address(&AddAdnlAddressRq { key_hash: key_id.clone(), category: 0 })
            .await
            .context("add_adnl_address")?;
        self.client
            .add_validator_adnl_addr(&AddValidatorAdnlAddrRq {
                perm_key_hash: validator_key_id,
                key_hash: key_id.clone(),
                expire_at: until as i32,
            })
            .await
            .context("add_validator_adnl_addr")?;
        Ok(key_id)
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
        Ok(ValidatorConfig { keys })
    }
    async fn election_parameters(&mut self) -> anyhow::Result<ConfigParam15> {
        election_parameters_from_live_config(self.chain_provider.get_config_param(15).await?)
    }
    async fn live_controller_policy(&mut self) -> anyhow::Result<Cell> {
        match self.chain_provider.get_config_param(47).await? {
            ConfigParamEnum::ConfigParamAny(47, cell) => Ok(cell),
            other => anyhow::bail!("live ConfigParam 47 has unexpected representation: {other:?}"),
        }
    }
    async fn send_boc(&mut self, msg_boc: &[u8]) -> anyhow::Result<()> {
        self.chain_provider.send_boc(msg_boc).await
    }
    async fn sign(&mut self, key_id: Vec<u8>, data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        self.client.sign(&SignRq { key_hash: key_id, data }).await
    }
    async fn create_pq_stake_authorization(
        &mut self,
        election_date: u32,
        max_factor: u32,
        adnl_addr: &[u8],
        stake_owner: &[u8],
    ) -> anyhow::Result<control_client::client_api::PqStakeAuthorization> {
        self.client
            .create_pq_stake_authorization(election_date, max_factor, adnl_addr, stake_owner)
            .await
    }
    async fn account(&mut self, address: &str) -> anyhow::Result<Account> {
        let address: MsgAddressInt = address.parse().context("parse election account address")?;
        Ok(Account::from_balance(self.chain_provider.get_balance(&address).await?))
    }
    async fn export_public_key(&mut self, key_id: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.client.export_key_pub(key_id).await
    }
    async fn get_current_vset(&mut self) -> anyhow::Result<ValidatorSet> {
        current_vset_from_live_config(self.chain_provider.get_config_param(34).await?)
    }
    async fn get_current_vset_hash(&mut self) -> anyhow::Result<Option<[u8; 32]>> {
        let cell = self.chain_provider.get_config_param_cell(34).await?;
        Ok(Some(cell.repr_hash().inner()))
    }

    async fn get_next_vset(&mut self) -> anyhow::Result<Option<ValidatorSet>> {
        self.chain_provider
            .get_optional_config_param(36)
            .await?
            .map(next_vset_from_live_config)
            .transpose()
    }
}

fn current_vset_from_live_config(param: ConfigParamEnum) -> anyhow::Result<ValidatorSet> {
    match param {
        ConfigParamEnum::ConfigParam34(value) => Ok(value.cur_validators),
        other => anyhow::bail!("live ConfigParam 34 has unexpected representation: {other:?}"),
    }
}

fn next_vset_from_live_config(param: ConfigParamEnum) -> anyhow::Result<ValidatorSet> {
    match param {
        ConfigParamEnum::ConfigParam36(value) => Ok(value.next_validators),
        other => anyhow::bail!("live ConfigParam 36 has unexpected representation: {other:?}"),
    }
}

fn election_parameters_from_live_config(param: ConfigParamEnum) -> anyhow::Result<ConfigParam15> {
    match param {
        ConfigParamEnum::ConfigParam15(value) => Ok(value),
        other => anyhow::bail!("live ConfigParam 15 has unexpected representation: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_validator_sets_use_the_matching_config_parameter() {
        let set = ValidatorSet::default();
        assert_eq!(
            current_vset_from_live_config(ConfigParamEnum::ConfigParam34(
                chain_block::ConfigParam34 { cur_validators: set.clone() }
            ))
            .unwrap(),
            set
        );
        assert_eq!(
            next_vset_from_live_config(ConfigParamEnum::ConfigParam36(
                chain_block::ConfigParam36 { next_validators: set.clone() }
            ))
            .unwrap(),
            set
        );
        assert!(
            current_vset_from_live_config(ConfigParamEnum::ConfigParam36(
                chain_block::ConfigParam36 { next_validators: set.clone() }
            ))
            .unwrap_err()
            .to_string()
            .contains("live ConfigParam 34")
        );
        assert!(
            next_vset_from_live_config(ConfigParamEnum::ConfigParam34(
                chain_block::ConfigParam34 { cur_validators: set }
            ))
            .unwrap_err()
            .to_string()
            .contains("live ConfigParam 36")
        );
    }

    #[test]
    fn chain_balance_preserves_nanotos_for_stake_budget() {
        assert_eq!(Account::from_balance(10_001_000_000_000).balance(), 10_001_000_000_000);
    }

    #[test]
    fn election_parameters_accept_only_live_param_15() {
        let expected = ConfigParam15 {
            validators_elected_for: 300,
            elections_start_before: 180,
            elections_end_before: 60,
            stake_held_for: 180,
        };
        assert_eq!(
            election_parameters_from_live_config(ConfigParamEnum::ConfigParam15(expected.clone()))
                .unwrap(),
            expected
        );
        let wrong = ConfigParamEnum::ConfigParamAny(47, Cell::default());
        assert!(
            election_parameters_from_live_config(wrong)
                .unwrap_err()
                .to_string()
                .contains("live ConfigParam 15 has unexpected representation")
        );
    }
}
