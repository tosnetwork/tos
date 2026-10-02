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
const CODE_V1_1: &'static str = "b5ee9c72410220010006b6000114ff00f4a413f4bcf2c80b01020162020303f8d0ed44d0fa40fa40fa4020c700916d93f40401e2f861d123c700925f07e024d0d3030171b08f4e30353502d0d30331fa4030db3c6c22325125c705b05921d749810120b9925b709e01d31f01841fba01d3ff3058bab0e2b08e97db3cf86159f841c85004cf1658cf1601cf16f400c9ed54925f03e2e03504fa4030030d04050201201e1f002af841d0d33f31d3ff31fa0031d3ff31d30031f404d104d8d31f7022c000228b1778c705b022d74ac000b08e136c21830bc85387a182103b9aca00a1fa02c9d09430d33f12e221821050516232ba5367c705b08f243134353501d3fffa00fa00d31fd300d1db3c3052b4ba5283ba12b05361bab0925f0be30de05354c705e3005353c7050d06070802fe228e2b0582103b9aca000120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a120c2ff218377b9b0f2e0b4923570e214baf2e0b4c00001c000b1f2e0b4702651545197db3c8200c3507ff83678830b7ff8380120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b4821050516132190901cc21830bba8ea0fa005398a182103b9aca00a112b60881200421c200f2f452506d80188040db3cde21811001ba8e17fa40525228f841c85004cf1658cf1601cf16f400c9ed54de21817702ba96d307d402fb00de2182009903ba9bd4812002226ef2f201fb04de1c036c8fb02182104e73744bba93306c62e30d821047657424ba8f16821047657424c8cb1fcb3fc9db3c705880188040db3c9130e2925f09e20a0b1c0122403402c8cb1fcb3fcbffc970db3c73fb001204f005fa4430f828fa443081200302c0ff12f2f4830c01c0fff2f481200122f2f481200527821047868c00bef2f404fa0020db3c308120045198a182103b9aca00a15220bb19f2f4db3c6c3123833eb101c0005213bc12b0f2e0b4f828fa443127fa443171f833d0d3ffd120f2e0b4c8500ccf16c95302db3c2c0c0d0e0f011671f833d0d70bff7f01db3c1d0026d31fd31f31d3ff31d30f31d431d431f40431d10036f8416e957054700020e0f841d0d33fd3fffa00d3ffd300f40431d1013a01d0db3c7104c8cb0f13cc16cb1f14cb1f12cbff13ccf400cb00cbffc91004e87f74c8cb02ca07cbffc9d05351db3c52707fdb3cdb3c82030d407ff83652100120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b48200c3507ff83678830b7ff8380120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b411121314001ad31fd31fd3ffd30fd4d4f404d1003220f900ab5f821050517332c8cb1f13cb3f12cb9f01d0cf16c90050717002928018928010e2c8cb055005cf160320c2ff218377b9b0f2e0b413fa0212cb6912cb00ccc901cc8307f9413082030d407ff836597ff8380120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b4728200c3507ff83678830b7ff8380120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b41504e00120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b41dbef2e0b4241034542d63db3c522bdb3c29d0d70bff4430712204413754180adb3c040120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b450048018711718191a01f20120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a820c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b482030d407ff83678830b7ff8380120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b416009c0120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b4821005f5e1000120c2ff218377b9b0f2e0b40120c2ff218377b9b0f2e0b4a020c2ff218377b9b0f2e0b4015054342126db3c821050517232c8cb1f14cb3f13cb9f0220c2ff218377b9b0f2e0b412fa02cbffccc91b002a7f821050517332c8cb1fca1f13cbffcb3fccc9f90000602392f841916de208c8cb3f17cbff5005fa0213cbffcb0014f400c9f86101f841c85004cf1658cf1601cf16f400c9ed540106db3c011c0046821050517232c8cb1f14cbff12cbff0120c2ff218377b9b0f2e0b4fa02ccc9f900ab5f0048226eb32091719170e203c8cb055006cf165004fa02cb6a039358cc019130e201c901fb00001674c8cb0212ca07cbffc9d00027bdf8cb938b82a38002a380036b6aa39152988b6c0031bfe5076a2687d207d207d2010638048b6c9fa0200f17c30e8c12aaa1f2";
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
