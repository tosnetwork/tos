/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::{NominatorData, NominatorPoolData, NominatorPoolWrapper, NominatorPosition};
use crate::contract_codes::NOMINATOR_POOL_CODE;
use crate::stack_utils::bytes_to_stack_entry;
use crate::{ContractProvider, SmartContract};
use anyhow::Context;
use chain_block::{
    BuilderData, Coins, IBitstring, MsgAddressInt, Serializable, StateInit, read_single_root_boc,
};
use common::tvm_stack_parser::TvmStackParser;
use std::sync::Arc;
use tl_api::tos::tvm::StackEntry;

fn flatten_tvm_list(entry: &StackEntry, result: &mut Vec<StackEntry>) -> anyhow::Result<()> {
    match entry {
        StackEntry::Tvm_StackEntryList(list) => {
            result.extend(list.list.elements().iter().cloned());
            Ok(())
        }
        StackEntry::Tvm_StackEntryTuple(tuple) => {
            let elements = tuple.tuple.elements();
            anyhow::ensure!(elements.len() == 2, "TVM cons-list tuple must contain head and tail");
            result.push(elements[0].clone());
            flatten_tvm_list(&elements[1], result)
        }
        StackEntry::Tvm_StackEntryUnsupported => Ok(()),
        _ => anyhow::bail!("stack entry is not a TVM list"),
    }
}

fn parse_nominator_positions(stack: &TvmStackParser) -> anyhow::Result<Vec<NominatorPosition>> {
    let root = stack.stack.first().context("missing nominators list")?;
    let mut entries = Vec::new();
    flatten_tvm_list(root, &mut entries).context("parse nominators list")?;
    let mut result = Vec::with_capacity(entries.len());
    for entry in entries {
        let item = TvmStackParser::new(vec![entry]).tuple(0).context("parse nominator tuple")?;
        result.push(NominatorPosition {
            address: format!("0:{}", hex::encode(item.number_bytes(0, 32)?)),
            amount: item.u64(1)?,
            pending_deposit: item.u64(2)?,
            withdraw_requested: item.bool(3)?,
        });
    }
    Ok(result)
}

fn parse_pool_data(stack: &TvmStackParser) -> anyhow::Result<NominatorPoolData> {
    // ChainProvider normalizes the raw TVM result stack into the get-method's
    // declaration order before contract wrappers receive it.
    let state = stack.i64(0).context("parse state")? as i32;
    let nominators_count = stack.i64(1).context("parse nominators_count")? as u32;
    let stake_amount_sent = stack.u64(2).context("parse stake_amount_sent")?;
    let validator_amount = stack.u64(3).context("parse validator_amount")?;
    let validator_address = {
        let mut array = [0u8; 32];
        array.copy_from_slice(&stack.number_bytes(4, 32).context("parse validator_address")?);
        array
    };
    let validator_reward_share = stack.u64(5).context("parse validator_reward_share")? as u16;
    let max_nominators_count = stack.u64(6).context("parse max_nominators_count")? as u16;
    let min_validator_stake = stack.u64(7).context("parse min_validator_stake")?;
    let min_nominator_stake = stack.u64(8).context("parse min_nominator_stake")?;
    let stake_at = stack.u64(11).context("parse stake_at")? as u32;
    let saved_validator_set_hash = {
        let bytes = stack.number_bytes(12, 32).context("parse saved_validator_set_hash")?;
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        array
    };
    let validator_set_changes_count =
        stack.i64(13).context("parse validator_set_changes_count")? as i32;
    let validator_set_change_time = stack.u64(14).context("parse validator_set_change_time")?;
    let stake_held_for = stack.u64(15).context("parse stake_held_for")?;

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

        parse_pool_data(&stack)
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

    async fn list_nominators(&self) -> anyhow::Result<Vec<NominatorPosition>> {
        let stack =
            self.provider.get_method(self.pool_addr.to_string(), "list_nominators", vec![]).await?;
        parse_nominator_positions(&stack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl_api::tos::tvm::{
        List, Number, Tuple, list,
        numberdecimal::NumberDecimal,
        stackentry::{StackEntryList, StackEntryNumber, StackEntryTuple},
        tuple,
    };

    fn number(value: &str) -> tl_api::tos::tvm::StackEntry {
        tl_api::tos::tvm::StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
            number: Number::Tvm_NumberDecimal(NumberDecimal { number: value.to_owned() }),
        })
    }

    fn tuple_entry(elements: Vec<tl_api::tos::tvm::StackEntry>) -> tl_api::tos::tvm::StackEntry {
        tl_api::tos::tvm::StackEntry::Tvm_StackEntryTuple(StackEntryTuple {
            tuple: Tuple::Tvm_Tuple(tuple::Tuple { elements }),
        })
    }

    fn list_entry(elements: Vec<tl_api::tos::tvm::StackEntry>) -> tl_api::tos::tvm::StackEntry {
        tl_api::tos::tvm::StackEntry::Tvm_StackEntryList(StackEntryList {
            list: List::Tvm_List(list::List { elements }),
        })
    }

    #[test]
    fn parses_pool_nominator_list_and_boolean_flags() {
        let position = tuple_entry(vec![
            number("0xabcd"),
            number("1000000000"),
            number("250000000"),
            number("-1"),
        ]);
        let list = list_entry(vec![position]);

        let parsed = parse_nominator_positions(&TvmStackParser::new(vec![list])).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].address, format!("0:{}abcd", "0".repeat(60)));
        assert_eq!(parsed[0].amount, 1_000_000_000);
        assert_eq!(parsed[0].pending_deposit, 250_000_000);
        assert!(parsed[0].withdraw_requested);
    }

    #[test]
    fn parses_cons_list_returned_by_real_pool_get_method() {
        let position =
            tuple_entry(vec![number("0xabcd"), number("100"), number("25"), number("0")]);
        let cons = tuple_entry(vec![position, list_entry(vec![])]);

        let parsed = parse_nominator_positions(&TvmStackParser::new(vec![cons])).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].amount, 100);
        assert_eq!(parsed[0].pending_deposit, 25);
        assert!(!parsed[0].withdraw_requested);
    }

    #[test]
    fn parses_get_pool_data_in_provider_normalized_order() {
        let stack = TvmStackParser::new(vec![
            number("0"),
            number("1"),
            number("3000"),
            number("2000"),
            number("0xabc"),
            number("4000"),
            number("40"),
            number("1000"),
            number("100"),
            list_entry(vec![]), // nominators dictionary
            list_entry(vec![]), // withdraw requests
            number("999"),
            number("0x11"),
            number("2"),
            number("1234"),
            number("3600"),
            list_entry(vec![]), // config proposal votings
        ]);

        let parsed = parse_pool_data(&stack).unwrap();
        assert_eq!(parsed.state, 0);
        assert_eq!(parsed.nominators_count, 1);
        assert_eq!(parsed.stake_amount_sent, 3000);
        assert_eq!(parsed.validator_amount, 2000);
        assert_eq!(parsed.validator_reward_share, 4000);
        assert_eq!(parsed.max_nominators_count, 40);
        assert_eq!(parsed.min_validator_stake, 1000);
        assert_eq!(parsed.min_nominator_stake, 100);
        assert_eq!(parsed.stake_at, 999);
        assert_eq!(parsed.saved_validator_set_hash[31], 0x11);
        assert_eq!(parsed.validator_set_changes_count, 2);
        assert_eq!(parsed.validator_set_change_time, 1234);
        assert_eq!(parsed.stake_held_for, 3600);
    }
}
