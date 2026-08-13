/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::{ControllerData, ControllerWrapper, LoanBalanceRequirement};
use crate::{ContractProvider, SmartContract, stack_utils::i64_to_stack_entry};
use anyhow::Context;
use chain_block::MsgAddressInt;
use std::sync::Arc;

/// Implementation of the liquid staking controller contract wrapper
///
/// Liquid staking controller contract
pub struct ControllerWrapperImpl {
    provider: Arc<dyn ContractProvider>,
    controller_addr: MsgAddressInt,
}

impl ControllerWrapperImpl {
    pub fn new(provider: Arc<dyn ContractProvider>, controller_addr: MsgAddressInt) -> Self {
        Self { provider, controller_addr }
    }
}

#[async_trait::async_trait]
impl SmartContract for ControllerWrapperImpl {
    async fn balance(&self) -> anyhow::Result<u64> {
        self.provider.balance(&self.controller_addr).await
    }

    fn address(&self) -> MsgAddressInt {
        self.controller_addr.clone()
    }
}

#[async_trait::async_trait]
impl ControllerWrapper for ControllerWrapperImpl {
    async fn get_controller_data(&self) -> anyhow::Result<ControllerData> {
        let stack = self
            .provider
            .get_method(self.controller_addr.to_string(), "get_validator_controller_data", vec![])
            .await?;

        let state = stack.i64(0).context("parse state")? as i32;
        let halted = stack.i64(1).context("parse halted")? == -1;
        let approved = stack.i64(2).context("parse approved")? == -1;
        let stake_amount_sent = stack.i64(3).context("parse stake_amount_sent")? as u64;
        let stake_at = stack.i64(4).context("parse stake_at")? as u32;
        let saved_validator_set_hash = {
            let bytes = stack.number_bytes(5, 32).context("parse saved_validator_set_hash")?;
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            array
        };
        let validator_set_changes_count =
            stack.i64(6).context("parse validator_set_changes_count")? as i32;
        let validator_set_change_time =
            stack.i64(7).context("parse validator_set_change_time")? as u64;
        let stake_held_for = stack.i64(8).context("parse stake_held_for")? as u64;
        let borrowed_amount = stack.i64(9).context("parse borrowed_amount")? as u64;
        let borrowing_time = stack.i64(10).context("parse borrowing_time")? as u64;

        Ok(ControllerData {
            state,
            halted,
            approved,
            stake_amount_sent,
            stake_at,
            saved_validator_set_hash,
            validator_set_changes_count,
            validator_set_change_time,
            stake_held_for,
            borrowed_amount,
            borrowing_time,
        })
    }

    async fn required_balance_for_loan(
        &self,
        credit: u64,
        interest: u64,
    ) -> anyhow::Result<LoanBalanceRequirement> {
        let stack = self
            .provider
            .get_method(
                self.controller_addr.to_string(),
                "required_balance_for_loan",
                vec![i64_to_stack_entry(credit as i64), i64_to_stack_entry(interest as i64)],
            )
            .await?;

        let required_balance = stack.i64(0).context("parse required_balance")? as u64;
        let validator_amount = stack.i64(1).context("parse validator_amount")? as u64;

        Ok(LoanBalanceRequirement { required_balance, validator_amount })
    }
}
