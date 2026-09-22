/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::{NominatorRoles, NominatorWrapper, PoolConfig, PoolData};
use crate::{ContractProvider, SmartContract};
use anyhow::Context;
use chain_block::{
    BuilderData, Deserializable, MsgAddressInt, Serializable, SliceData, StateInit,
    read_single_root_boc,
};
use std::sync::Arc;

/// Code for single-nominator contract v1.1
///
/// Compiled from crypto/smartcont/single-nominator-pool/single-nominator-code.fc against
/// crypto/smartcont/stdlib.fc, which is what the sandbox suite runs. A change to that
/// source that is not carried here deploys a different contract than the one the tests
/// exercise, and the address below would be derived from code nobody ran.
const CODE_V1_1: &'static str = "b5ee9c7241020d010001fb000114ff00f4a413f4bcf2c80b01020162020302c0d0ed44d0fa40fa40fa40d123c700925f07e004d0d3030171b0925f07e0fa403003d31f7022c000228b1778c705b022d74ac000b08e136c21830bc85387a182103b9aca00a1fa02c9d09430d33f12e25354c7059134e30d5243c705925f07e30d04050201200b0c01d021830bba8ea0fa005398a182103b9aca00a112b60881200421c200f2f452506d80188040db3cde21811001ba8e13fa40541557c85003cf1601cf1601cf16c9ed549134e220817702ba9803d307d402fb0003de2082009903ba9d03d4812002226ef2f201fb0403de0903f62182104e73744bba8f6003fa4430f828fa443081200302c0ff12f2f4830c01c0fff2f481200123f2f481200525821047868c00bef2f401fa0020db3c300681200406a182103b9aca00a15210bb15f2f482105051726cc8cb1f5220cb3f5005cf16c91380188040db3c019450565f05e2821047657424ba9130e30d0609070026d31fd31f31d3ff31d30f31d431d431f40431d1022c821047657424c8cb1fcb3fc9db3c705880188040db3c0809011671f833d0d70bff7f01db3c0a0048226eb32091719170e203c8cb055006cf165004fa02cb6a039358cc019130e201c901fb00001674c8cb0212ca07cbffc9d00027bdf8cb938b82a38002a380036b6aa39152988b6c0019bfe5076a2687d207d207d2068cec5ebf4e";
pub const NOMINATOR_POOL_WORKCHAIN: i32 = -1;
/// Implementation of the single-nominator contract wrapper
///
/// Single nominator contract
pub struct NominatorWrapperImpl {
    provider: Arc<dyn ContractProvider>,
    nominator_addr: MsgAddressInt,
    state_init: Option<StateInit>,
}

impl NominatorWrapperImpl {
    pub fn new(provider: Arc<dyn ContractProvider>, nominator_addr: MsgAddressInt) -> Self {
        Self { provider, nominator_addr, state_init: None }
    }

    pub fn from_init_data(
        provider: Arc<dyn ContractProvider>,
        owner_address: &MsgAddressInt,
        validator_address: &MsgAddressInt,
        controller_address: &MsgAddressInt,
        workchain: i32,
    ) -> anyhow::Result<Self> {
        let state_init =
            Some(Self::build_state_init(owner_address, validator_address, controller_address)?);
        let nominator_addr = Self::calculate_address(
            workchain,
            owner_address,
            validator_address,
            controller_address,
        )?;
        Ok(Self { provider, nominator_addr, state_init })
    }

    pub fn calculate_address(
        wc: i32,
        owner_address: &MsgAddressInt,
        validator_address: &MsgAddressInt,
        controller_address: &MsgAddressInt,
    ) -> anyhow::Result<MsgAddressInt> {
        let state_init =
            Self::build_state_init(owner_address, validator_address, controller_address)?
                .write_to_new_cell()?
                .into_cell()?;
        MsgAddressInt::with_params(wc, state_init.hash(0))
    }

    /// The contract's storage: three roles, in the order `get_roles` reports them. The
    /// third is the validator controller a stake is relayed through, which the contract
    /// reads on every message; a state init written without it underflows on the first
    /// one.
    pub fn build_state_init(
        owner_address: &MsgAddressInt,
        validator_address: &MsgAddressInt,
        controller_address: &MsgAddressInt,
    ) -> anyhow::Result<StateInit> {
        let mut data = BuilderData::new();
        owner_address.write_to(&mut data)?;
        validator_address.write_to(&mut data)?;
        controller_address.write_to(&mut data)?;
        let code =
            read_single_root_boc(hex::decode(CODE_V1_1).expect("CODE_V1_1 code hex is invalid"))?;
        let state_init = StateInit::with_code_and_data(code, data.into_cell()?);

        Ok(state_init)
    }
}

#[async_trait::async_trait]
impl SmartContract for NominatorWrapperImpl {
    async fn balance(&self) -> anyhow::Result<u64> {
        self.provider.balance(&self.nominator_addr).await
    }

    fn address(&self) -> MsgAddressInt {
        self.nominator_addr.clone()
    }
}

#[async_trait::async_trait]
impl NominatorWrapper for NominatorWrapperImpl {
    fn state_init(&self) -> Option<StateInit> {
        self.state_init.clone()
    }

    async fn get_roles(&self) -> anyhow::Result<NominatorRoles> {
        let stack =
            self.provider.get_method(self.nominator_addr.to_string(), "get_roles", vec![]).await?;
        let owner_address =
            MsgAddressInt::construct_from(&mut SliceData::load_cell(stack.cell(0)?)?)
                .map_err(|e| anyhow::anyhow!("parse owner address error: {}", e))?;
        let validator_address =
            MsgAddressInt::construct_from(&mut SliceData::load_cell(stack.cell(1)?)?)
                .map_err(|e| anyhow::anyhow!("parse validator address error: {}", e))?;
        let controller_address =
            MsgAddressInt::construct_from(&mut SliceData::load_cell(stack.cell(2)?)?)
                .map_err(|e| anyhow::anyhow!("parse controller address error: {}", e))?;

        Ok(NominatorRoles { owner_address, validator_address, controller_address })
    }

    async fn get_pool_data(&self) -> anyhow::Result<PoolData> {
        let stack = self
            .provider
            .get_method(self.nominator_addr.to_string(), "get_pool_data", vec![])
            .await?;
        let state = stack.i64(0).context("parse state")? as i32;
        let nominators_count = stack.i64(1).context("parse nominators_count")? as u32;
        let stake_amount_sent = stack.i64(2).context("parse stake_amount_sent")? as u64;
        let validator_amount = stack.i64(3).context("parse validator_amount")? as u64;
        // Parse pool config
        let validator_addr = {
            let mut array = [0u8; 32];
            array.copy_from_slice(&stack.number_bytes(4, 32).context("parse validator_addr")?);
            array
        };
        let validator_reward_share = stack.i64(5).context("parse validator_reward_share")? as u16;
        let max_nominators_count = stack.i64(6).context("parse max_nominators_count")? as u16;
        let min_validator_stake = stack.i64(7).context("parse min_validator_stake")? as u64;
        let max_nominators_stake = stack.i64(8).context("parse max_nominators_stake")? as u64;
        // skip indices 9-10 (nominators, withdraw_requests)
        let stake_at = stack.i64(11).context("parse stake_at")? as u32;
        let saved_validator_set_hash = {
            let bytes = stack.number_bytes(12, 32).context("parse saved_validator_set_hash")?;
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            array
        };
        let validator_set_changes_count =
            stack.i64(13).context("parse validator_set_changes_count")? as i32;
        let validator_set_change_time =
            stack.i64(14).context("parse validator_set_change_time")? as u64;
        let stake_held_for = stack.i64(11).context("parse stake_held_for")? as u64;

        Ok(PoolData {
            state,
            nominators_count,
            stake_amount_sent,
            validator_amount,
            pool_config: PoolConfig {
                validator_addr,
                validator_reward_share,
                max_nominators_count,
                min_validator_stake,
                max_nominators_stake,
            },
            stake_at,
            saved_validator_set_hash,
            validator_set_changes_count,
            validator_set_change_time,
            stake_held_for,
        })
    }
}

// Chain RPC integration tests for single nominator contract
#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract_provider;
    use chain_block::MsgAddressInt;
    use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
    use std::str::FromStr;

    fn open_nominator() -> Option<NominatorWrapperImpl> {
        let nominator_addr =
            MsgAddressInt::from_str("kf-d42Dwn_dzfdwlV_aEeX7WWnJ-bBU_eZp6CfKoMb4vQ3t0")
                .expect("Failed to parse nominator address");
        let url = match std::env::var("CHAIN_RPC_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping test: CHAIN_RPC_URL env variable not set");
                return None;
            }
        };

        let client = ClientJsonRpc::connect(url, None).expect("Failed to connect to chain RPC");
        Some(NominatorWrapperImpl::new(contract_provider!(Arc::new(client)), nominator_addr))
    }

    #[tokio::test]
    async fn test_get_roles() {
        // Enable logging to see debug logs from ClientJsonRpc
        //let _ = env_logger::init();
        let Some(nominator) = open_nominator() else {
            return;
        };
        let roles = nominator.get_roles().await.expect("Failed to get roles");
        assert_eq!(
            roles.owner_address,
            MsgAddressInt::from_str(
                "0:0f06dd725549dd60a6ca3743ac532db52789cb15af1f943fe96adbb4c1a86155"
            )
            .unwrap()
        );
        assert_eq!(
            roles.validator_address,
            MsgAddressInt::from_str(
                "0:308f9a48e5bf1c61bddcbd65dca41376877f845536f698eacfd5c7844d07c324"
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_pool_data() {
        // Enable logging to see debug logs from ClientJsonRpc
        //let _ = env_logger::init();
        let Some(nominator) = open_nominator() else {
            return;
        };
        let pool_data = nominator.get_pool_data().await.expect("Failed to get pool data");
        let expected = PoolData {
            state: 2,
            nominators_count: 1,
            validator_set_changes_count: 2,
            ..Default::default()
        };
        assert_eq!(pool_data, expected);
    }
}
