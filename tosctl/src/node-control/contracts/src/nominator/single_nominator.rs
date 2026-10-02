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
use common::tvm_stack_parser::TvmStackParser;
use std::sync::Arc;

/// Code for single-nominator contract v1.1
///
/// Compiled from crypto/smartcont/single-nominator-pool/single-nominator-code.fc against
/// crypto/smartcont/stdlib.fc, which is what the sandbox suite runs. A change to that
/// source that is not carried here deploys a different contract than the one the tests
/// exercise, and the address below would be derived from code nobody ran.
const CODE_V1_1: &'static str = "b5ee9c7241022401000864000114ff00f4a413f4bcf2c80b01020162020303ecd0ed44d0fa40fa40fa4020c700916d93f40401e2f861d123c700925f07e024d0d3030171b08f353004d0d30331fa4030db3c33335137c705b0505521d749810120b9925b709e01d31f01841fba01d3ff3058bab0e214b0925f06e30de03504fa403003d31f7022c000228b1778c705b022d74ac000b0110405020120222303dc5342bc8e2650420120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a120c2ff218377b9b0f2e0b493323370e28200c3507ff83678830b7ff8380120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b45210bc923033e30ddb3cf8611206070803728e136c21830bc85387a182103b9aca00a1fa02c9d09430d33f12e221821050516232ba5367c705b0e3025354c705e3005353c705925f09e30d090a0b01aaf841d0d33f31d3ff31fa0031d3ff31d30031f40431d430d050550120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a120c2ff218377b9b0f2e0b470fb0270821050517833c8cb1fc9102570db3c8306fb0020002ef841d0d33f31d3ff31fa0031d3ff31d30031f404d431d10024f841c85004cf1658cf1601cf16f400c9ed5403e8313403d3fffa00fa00d31fd300fa0031fa00d401d0fa40d101d151b1bef2e0b41b0120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a120c2ff218377b9b0f2e0b470fb02db3c3052a4ba5273ba12b05351bab0945f083330e30d70821050517833c8cb1f13cb3fc91270db3c8306fb00110c2001cc21830bba8ea0fa005398a182103b9aca00a112b60881200421c200f2f452506d80188040db3cde21811001ba8e17fa40525228f841c85004cf1658cf1601cf16f400c9ed54de21817702ba96d307d402fb00de2182009903ba9bd4812002226ef2f201fb04de1f03602182104e73744bba93306c62e30d821047657424ba8f16821047657424c8cb1fcb3fc9db3c705880188040db3c9130e20e0f1f029e2b8e2b0482103b9aca000120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a120c2ff218377b9b0f2e0b4923470e213baf2e0b409c00009c00019b1f2e0b4702551535435891056105cdb3c1c0d01ae8200c3507ff83678830b7ff8380120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b4c824cf16c9c882105051613254204802c8cb1fcb3fcbffc9d016cf1615ccc91470db3c73fb002004ec25fa4430f828fa443081200302c0ff12f2f4830c01c0fff2f481200123f2f481200528821047868c00bef2f4fa0020db3c3081200453a9a182103b9aca00a15230bbf2f4db3c6c3125833eb101c0005213bc12b0f2e0b4f828fa443129fa443171f833d0d3ffd120f2e0b4c85005cf16c95302db3c2510111213011671f833d0d70bff7f01db3c210026d31fd31f31d3ff31d30f31d431d431f40431d1003af8416e957054700020e0f841d0d33fd3fffa00d3ffd300f40431d431d1013a01d0db3c7104c8cb0f13cc16cb1f14cb1f12cbff13ccf400cb00cbffc91404e87f74c8cb02ca07cbffc9d05351db3c52807fdb3cdb3c82030d407ff83652100120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b48200c3507ff83678830b7ff8380120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b415201617001ad31fd31fd3ffd30fd4d4f404d1003220f900ab5f821050517332c8cb1f13cb3f12cb9f01d0cf16c901cc8307f9413082030d407ff836597ff8380120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b4728200c3507ff83678830b7ff8380120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b41804e20120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b452f0bef2e0b4251035542783516edb3c5233db3c21d0d70bff1314712604413a541b0d2ddb3c50870120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a120c2ff218377b9b0f2e0b4261a1b1c1d01f20120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a820c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b482030d407ff83678830b7ff8380120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b419009c0120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b4821005f5e1000120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b4015ec821cf16c9542640546449db3c821050517232c8cb1f15cb3f14cb9f0120c2ff218377b9b0f2e0b4fa02cbffccccc91e002a7f821050517332c8cb1fca1f13cbffcb3fccc9f900006ec801cf16c92492f841916de209c8cb3f18cbff5006fa0214cbff12cb0015f40013ccc9f861f841c85004cf1658cf1601cf16f400c9ed5402d60120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a120c2ff218377b9b0f2e0b470fb0250520120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b44304801871db3c70821050517833c8cb1f5230cb3fc970db3c8306fb00011f200052c801cf16c9821050517232c8cb1f15cbff13cbff0120c2ff218377b9b0f2e0b4fa02ccccc9f900ab5f0048226eb32091719170e203c8cb055006cf165004fa02cb6a039358cc019130e201c901fb000050717002928018928010e2c8cb055005cf160320c2ff218377b9b0f2e0b413fa0212cb6912cb00ccc9001674c8cb0212ca07cbffc9d00027bdf8cb938b82a38002a380036b6aa39152988b6c0031bfe5076a2687d207d207d2010638048b6c9fa0200f17c30e8c3734acff";
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
    /// FunC `get_roles()` returns three TVM slices, not cell references.
    /// A cell-only decoder refuses a live pool before any stake is submitted.
    fn decode_roles(stack: &TvmStackParser) -> anyhow::Result<NominatorRoles> {
        anyhow::ensure!(stack.stack.len() == 3, "get_roles returned an unexpected role count");
        let mut owner = stack.slice(0)?;
        let mut validator = stack.slice(1)?;
        let mut controller = stack.slice(2)?;
        Ok(NominatorRoles {
            owner_address: MsgAddressInt::construct_from(&mut owner)
                .context("parse owner address")?,
            validator_address: MsgAddressInt::construct_from(&mut validator)
                .context("parse validator address")?,
            controller_address: MsgAddressInt::construct_from(&mut controller)
                .context("parse controller address")?,
        })
    }

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
        Self::decode_roles(&stack)
    }

    async fn next_relay_query(&self) -> anyhow::Result<u64> {
        let controller = self.get_roles().await?.controller_address;
        let stack =
            self.provider.get_method(controller.to_string(), "next_relay_query", vec![]).await?;
        let query = stack.u64(0)?;
        anyhow::ensure!(query > (1_u64 << 63), "invalid relay query domain");
        Ok(query)
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
    use tl_api::tos::tvm::{StackEntry, slice, stackentry::StackEntrySlice};

    fn role_slice(address: &MsgAddressInt) -> StackEntry {
        let cell = address.write_to_new_cell().unwrap().into_cell().unwrap();
        let bytes = SliceData::load_cell(cell).unwrap().get_bytestring(0);
        StackEntry::Tvm_StackEntrySlice(StackEntrySlice { slice: slice::Slice { bytes } })
    }

    #[test]
    fn get_roles_decodes_three_ordered_slices_and_refuses_a_cell() {
        let owner = MsgAddressInt::standard(-1, [0x11; 32]);
        let operator = MsgAddressInt::standard(-1, [0x22; 32]);
        let controller = MsgAddressInt::standard(-1, [0x33; 32]);
        let entries = vec![role_slice(&owner), role_slice(&operator), role_slice(&controller)];
        let roles = NominatorWrapperImpl::decode_roles(&TvmStackParser::new(entries.clone()))
            .expect("the live getter's three slice entries must decode");
        assert_eq!(roles.owner_address, owner);
        assert_eq!(roles.validator_address, operator);
        assert_eq!(roles.controller_address, controller);

        let mut wrong_type = entries;
        let cell = owner.write_to_new_cell().unwrap().into_cell().unwrap();
        wrong_type[0] =
            StackEntry::Tvm_StackEntryCell(tl_api::tos::tvm::stackentry::StackEntryCell {
                cell: tl_api::tos::tvm::cell::Cell {
                    bytes: chain_block::write_boc(&cell).unwrap(),
                },
            });
        let error = NominatorWrapperImpl::decode_roles(&TvmStackParser::new(wrong_type))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a slice: index=0"), "wrong refusal: {error}");
    }

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
