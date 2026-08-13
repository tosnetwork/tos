/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::{NominatorData, NominatorPoolData, NominatorPoolWrapper};
use crate::contract_codes::NOMINATOR_POOL_CODE;
use crate::stack_utils::bytes_to_stack_entry;
use crate::{ContractProvider, SmartContract};
use anyhow::Context;
use chain_block::{
    BuilderData, Coins, IBitstring, MsgAddressInt, Serializable, StateInit, read_single_root_boc,
};
use std::sync::Arc;

/// Implementation of the multi-nominator pool contract wrapper
///
/// Multi-nominator pool contract
pub struct NominatorPoolWrapperImpl {
    provider: Arc<dyn ContractProvider>,
    pool_addr: MsgAddressInt,
}

impl NominatorPoolWrapperImpl {
    pub fn new(provider: Arc<dyn ContractProvider>, pool_addr: MsgAddressInt) -> Self {
        Self { provider, pool_addr }
    }

    /// Build the StateInit for a nominator pool contract.
    ///
    /// The data cell layout matches `save_data` in pool.fc:
    /// - state: uint8 (0 = idle)
    /// - nominators_count: uint16 (0)
    /// - stake_amount_sent: Coins (0)
    /// - validator_amount: Coins (0)
    /// - config: ref cell { validator_address: uint256, validator_reward_share: uint16,
    ///           max_nominators_count: uint16, min_validator_stake: Coins, min_nominator_stake: Coins }
    /// - nominators: dict (empty)
    /// - withdraw_requests: dict (empty)
    /// - stake_at: uint32 (0)
    /// - saved_validator_set_hash: uint256 (0)
    /// - validator_set_changes_count: uint8 (0)
    /// - validator_set_change_time: uint32 (0)
    /// - stake_held_for: uint32 (0)
    /// - config_proposal_votings: dict (empty)
    pub fn build_state_init(
        validator_address: &[u8; 32],
        validator_reward_share: u16,
        max_nominators_count: u16,
        min_validator_stake: u64,
        min_nominator_stake: u64,
    ) -> anyhow::Result<StateInit> {
        // Build config sub-cell
        let mut config_builder = BuilderData::new();
        config_builder.append_raw(validator_address, 256)?; // validator_address: uint256
        config_builder.append_u16(validator_reward_share)?; // validator_reward_share: uint16
        config_builder.append_u16(max_nominators_count)?; // max_nominators_count: uint16
        Coins::new(min_validator_stake).write_to(&mut config_builder)?; // min_validator_stake: Coins
        Coins::new(min_nominator_stake).write_to(&mut config_builder)?; // min_nominator_stake: Coins
        let config_cell = config_builder.into_cell()?;

        // Build main data cell
        let mut data = BuilderData::new();
        data.append_u8(0)?; // state: uint8 = 0 (idle)
        data.append_u16(0)?; // nominators_count: uint16 = 0
        Coins::new(0).write_to(&mut data)?; // stake_amount_sent: Coins = 0
        Coins::new(0).write_to(&mut data)?; // validator_amount: Coins = 0
        data.checked_append_reference(config_cell)?; // config: ref cell
        data.append_bit_zero()?; // nominators: empty dict
        data.append_bit_zero()?; // withdraw_requests: empty dict
        data.append_u32(0)?; // stake_at: uint32 = 0
        data.append_raw(&[0u8; 32], 256)?; // saved_validator_set_hash: uint256 = 0
        data.append_u8(0)?; // validator_set_changes_count: uint8 = 0
        data.append_u32(0)?; // validator_set_change_time: uint32 = 0
        data.append_u32(0)?; // stake_held_for: uint32 = 0
        data.append_bit_zero()?; // config_proposal_votings: empty dict

        let code = read_single_root_boc(
            hex::decode(NOMINATOR_POOL_CODE).expect("NOMINATOR_POOL_CODE hex is invalid"),
        )?;
        let state_init = StateInit::with_code_and_data(code, data.into_cell()?);

        Ok(state_init)
    }

    /// Calculate the pool address from the contract parameters.
    ///
    /// The pool address is derived from the StateInit hash, deployed to the
    /// masterchain (workchain -1).
    pub fn calculate_address(
        wc: i32,
        validator_address: &[u8; 32],
        validator_reward_share: u16,
        max_nominators_count: u16,
        min_validator_stake: u64,
        min_nominator_stake: u64,
    ) -> anyhow::Result<MsgAddressInt> {
        let state_init = Self::build_state_init(
            validator_address,
            validator_reward_share,
            max_nominators_count,
            min_validator_stake,
            min_nominator_stake,
        )?
        .write_to_new_cell()?
        .into_cell()?;
        MsgAddressInt::with_params(wc, state_init.hash(0))
    }
}

#[async_trait::async_trait]
impl SmartContract for NominatorPoolWrapperImpl {
    async fn balance(&self) -> anyhow::Result<u64> {
        self.provider.balance(&self.pool_addr).await
    }

    fn address(&self) -> MsgAddressInt {
        self.pool_addr.clone()
    }
}

#[async_trait::async_trait]
impl NominatorPoolWrapper for NominatorPoolWrapperImpl {
    async fn get_pool_data(&self) -> anyhow::Result<NominatorPoolData> {
        let stack =
            self.provider.get_method(self.pool_addr.to_string(), "get_pool_data", vec![]).await?;

        let state = stack.i64(0).context("parse state")? as i32;
        let nominators_count = stack.i64(1).context("parse nominators_count")? as u32;
        let stake_amount_sent = stack.i64(2).context("parse stake_amount_sent")? as u64;
        let validator_amount = stack.i64(3).context("parse validator_amount")? as u64;

        // Pool config fields
        let validator_address = {
            let mut array = [0u8; 32];
            array.copy_from_slice(&stack.number_bytes(4, 32).context("parse validator_address")?);
            array
        };
        let validator_reward_share = stack.i64(5).context("parse validator_reward_share")? as u16;
        let max_nominators_count = stack.i64(6).context("parse max_nominators_count")? as u16;
        let min_validator_stake = stack.i64(7).context("parse min_validator_stake")? as u64;
        let min_nominator_stake = stack.i64(8).context("parse min_nominator_stake")? as u64;

        // Skip indices 9-10 (nominators cell, withdraw_requests cell)
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
        let stake_held_for = stack.i64(15).context("parse stake_held_for")? as u64;

        Ok(NominatorPoolData {
            state,
            nominators_count,
            stake_amount_sent,
            validator_amount,
            validator_address,
            validator_reward_share,
            max_nominators_count,
            min_validator_stake,
            min_nominator_stake,
            stake_at,
            saved_validator_set_hash,
            validator_set_changes_count,
            validator_set_change_time,
            stake_held_for,
        })
    }

    async fn get_nominator_data(&self, nominator_addr: &[u8; 32]) -> anyhow::Result<NominatorData> {
        let stack_entry = bytes_to_stack_entry(nominator_addr);
        let stack = self
            .provider
            .get_method(self.pool_addr.to_string(), "get_nominator_data", vec![stack_entry])
            .await?;

        let amount = stack.i64(0).context("parse amount")? as u64;
        let pending_deposit = stack.i64(1).context("parse pending_deposit")? as u64;
        let withdraw_requested = stack.i64(2).context("parse withdraw_requested")? == -1;

        Ok(NominatorData { amount, pending_deposit, withdraw_requested })
    }

    async fn has_withdraw_requests(&self) -> anyhow::Result<bool> {
        let stack = self
            .provider
            .get_method(self.pool_addr.to_string(), "has_withdraw_requests", vec![])
            .await?;

        Ok(stack.i64(0).context("parse has_withdraw_requests")? == -1)
    }
}
