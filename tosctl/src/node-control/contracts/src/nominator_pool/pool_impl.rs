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
use crate::{ChainProvider, ContractProvider, MasterchainCheckpoint, SmartContract};
use anyhow::Context;
use chain_block::UnixTime;
use chain_block::{
    BuilderData, Coins, IBitstring, MsgAddressInt, Serializable, StateInit, read_single_root_boc,
};
use common::tvm_stack_parser::TvmStackParser;
use std::sync::Arc;
use tl_api::tos::tvm::StackEntry;

/// pool.fc stops counting validator set changes at three.
const MAX_VALIDATOR_SET_CHANGES: i32 = 3;
/// pool.fc state 0: funds are in the pool rather than with the Elector.
const POOL_STATE_IDLE: i32 = 0;
/// pool.fc's MIN_TOS_FOR_STORAGE: the balance it always keeps behind.
/// scripts/check-pool-storage-reserve.py reports how far this actually goes
/// against a given network's masterchain prices.
const MIN_TOS_FOR_STORAGE: u64 = 10_000_000_000;
/// Value attached to a maintenance call that only needs to pay its own way.
/// pool.fc returns the unspent remainder, so this only has to cover the
/// heaviest of them.
const MAINTENANCE_GAS: u64 = 200_000_000;
/// Headroom added on top of a shortfall so a pool is not topped up every tick.
/// Two TOS is roughly a dozen staking rounds of rent for a full pool.
const RENT_RUNWAY: u64 = 2_000_000_000;
/// Ceiling on a single top-up. Rent accrues at a fraction of a TOS per round,
/// so anything near this bound means the numbers are wrong rather than the
/// pool being expensive.
const MAX_TOP_UP_PER_TICK: u64 = 10_000_000_000;
/// Withdraw requests settled per message. The contract walks the queue until
/// the balance can no longer cover the next payout, so a bounded batch keeps
/// one message's gas predictable and the remainder is picked up next tick.
const WITHDRAW_REQUESTS_PER_MESSAGE: u8 = 8;

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
    // The config tuple carries two accounts now: who the pool validates for, and
    // the controller its stake is relayed through. Everything after it moved by
    // one slot, so reading the old positions would report a controller address
    // as a reward share.
    let controller_address = {
        let mut array = [0u8; 32];
        array.copy_from_slice(&stack.number_bytes(5, 32).context("parse controller_address")?);
        array
    };
    let validator_reward_share = stack.u64(6).context("parse validator_reward_share")? as u16;
    let max_nominators_count = stack.u64(7).context("parse max_nominators_count")? as u16;
    let min_validator_stake = stack.u64(8).context("parse min_validator_stake")?;
    let min_nominator_stake = stack.u64(9).context("parse min_nominator_stake")?;
    let stake_at = stack.u64(12).context("parse stake_at")? as u32;
    let saved_validator_set_hash = {
        let bytes = stack.number_bytes(13, 32).context("parse saved_validator_set_hash")?;
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        array
    };
    let validator_set_changes_count =
        stack.i64(14).context("parse validator_set_changes_count")? as i32;
    let validator_set_change_time = stack.u64(15).context("parse validator_set_change_time")?;
    let stake_held_for = stack.u64(16).context("parse stake_held_for")?;

    Ok(NominatorPoolData {
        state,
        nominators_count,
        stake_amount_sent,
        validator_amount,
        validator_address,
        controller_address,
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

/// A pool's state and depositor positions as of one exact masterchain block.
#[derive(Debug, Clone)]
pub struct NominatorPoolSnapshot {
    pub checkpoint: MasterchainCheckpoint,
    pub pool: NominatorPoolData,
    pub nominators: Vec<NominatorPosition>,
}

/// Reads `get_pool_data` and `list_nominators` against the same exact
/// masterchain block.
///
/// Both reads go through [`ChainProvider::run_get_method_at`], which binds
/// the request to `checkpoint.seqno` and rejects a response whose block
/// identity (workchain, seqno, root hash, file hash) differs from
/// `checkpoint`. The two halves of the snapshot are therefore provably from
/// one state: if either read resolves to another block, the whole
/// observation fails rather than mixing two states or falling back to the
/// latest one. Parsing reuses the wrapper's own decoders.
pub async fn read_nominator_pool_snapshot_at(
    chain: &dyn ChainProvider,
    address: &MsgAddressInt,
    checkpoint: &MasterchainCheckpoint,
) -> anyhow::Result<NominatorPoolSnapshot> {
    anyhow::ensure!(checkpoint.seqno > 0, "pool snapshot needs a non-zero masterchain checkpoint");
    let address = address.to_string();
    let pool_stack = chain
        .run_get_method_at(address.clone(), "get_pool_data", vec![], checkpoint)
        .await
        .with_context(|| format!("get_pool_data at masterchain {}", checkpoint.seqno))?;
    let nominators_stack = chain
        .run_get_method_at(address, "list_nominators", vec![], checkpoint)
        .await
        .with_context(|| format!("list_nominators at masterchain {}", checkpoint.seqno))?;
    Ok(NominatorPoolSnapshot {
        checkpoint: checkpoint.clone(),
        pool: parse_pool_data(&pool_stack)?,
        nominators: parse_nominator_positions(&nominators_stack)?,
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
    /// - config: ref cell { validator_address: uint256, controller_address: uint256,
    ///           validator_reward_share: uint16, max_nominators_count: uint16,
    ///           min_validator_stake: Coins, min_nominator_stake: Coins }
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
        controller_address: &[u8; 32],
        validator_reward_share: u16,
        max_nominators_count: u16,
        min_validator_stake: u64,
        min_nominator_stake: u64,
    ) -> anyhow::Result<StateInit> {
        // Build config sub-cell
        let mut config_builder = BuilderData::new();
        config_builder.append_raw(validator_address, 256)?; // validator_address: uint256
        config_builder.append_raw(controller_address, 256)?; // controller_address: uint256
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
        controller_address: &[u8; 32],
        validator_reward_share: u16,
        max_nominators_count: u16,
        min_validator_stake: u64,
        min_nominator_stake: u64,
    ) -> anyhow::Result<MsgAddressInt> {
        let state_init = Self::build_state_init(
            validator_address,
            controller_address,
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

/// The elections daemon drives every pool kind through `NominatorWrapper`.
///
/// That sharing is sound rather than merely convenient: the single-nominator
/// contract and pool.fc accept byte-identical `new_stake` and `recover_stake`
/// bodies, so the same election payloads reach the Elector either way. What
/// differs is the preconditions each contract enforces before forwarding, and
/// those live with the caller.
#[async_trait::async_trait]
impl crate::nominator::NominatorWrapper for NominatorPoolWrapperImpl {
    async fn next_relay_query(&self) -> anyhow::Result<u64> {
        let roles =
            self.provider.get_method(self.pool_addr.to_string(), "get_pool_data", vec![]).await?;
        let controller = MsgAddressInt::with_standart(
            None,
            -1,
            chain_block::UInt256::from_slice(&roles.number_bytes(5, 32)?).into(),
        )?;
        let stack =
            self.provider.get_method(controller.to_string(), "next_relay_query", vec![]).await?;
        let query = stack.u64(0)?;
        anyhow::ensure!(query > (1_u64 << 63), "invalid relay query domain");
        Ok(query)
    }

    async fn get_roles(&self) -> anyhow::Result<crate::nominator::NominatorRoles> {
        // pool.fc records a validator address but has no owner: the funds
        // belong to the nominators, and no single account can withdraw them.
        // Reporting some address as the owner would misstate who controls the
        // principal, so callers that need this concept have to ask for pool
        // data and decide what they actually mean.
        anyhow::bail!(
            "a multi-nominator pool has no owner role; read get_pool_data() for the validator"
        )
    }

    async fn maintenance(
        &self,
        current_validator_set_hash: &[u8; 32],
    ) -> anyhow::Result<Vec<crate::nominator::PoolMaintenance>> {
        let data = NominatorPoolWrapper::get_pool_data(self).await?;
        let mut actions = Vec::new();

        // pool.fc will not release stake until it has counted enough validator
        // set changes, and it only counts one when someone tells it the set
        // moved. Miss these and the recover path stays permanently blocked
        // behind its own guard, with every nominator's principal inside.
        if data.saved_validator_set_hash != *current_validator_set_hash
            && data.validator_set_changes_count < MAX_VALIDATOR_SET_CHANGES
        {
            actions.push(crate::nominator::PoolMaintenance {
                reason: "validator set changed; pool has not counted it yet",
                body: super::messages::update_validator_set(UnixTime::now())?,
                value: MAINTENANCE_GAS,
            });
        }

        // Masterchain rent is charged against the pool's balance, which is the
        // nominators' principal, and pool.fc books that drain against nobody:
        // its ledger keeps saying each nominator is owed what they deposited.
        // Once the balance no longer covers the ledger plus the reserve, the
        // withdrawal path stops paying out -- and it does so by returning
        // unchanged rather than throwing, so the request just sits in the queue
        // and nothing anywhere reports a problem. Say it out loud instead.
        if data.state == POOL_STATE_IDLE {
            let balance = self.balance().await?;
            let owed: u64 = self
                .list_nominators()
                .await?
                .iter()
                .map(|position| position.amount.saturating_add(position.pending_deposit))
                .sum();
            let required = owed.saturating_add(MIN_TOS_FOR_STORAGE);
            if balance < required {
                let shortfall = required - balance;
                // Rent is a cost of running the pool, and the validator is the
                // one paid a share of every round for running it. Booking the
                // top-up as a validator deposit rather than a bare transfer
                // keeps the ledger honest: the funds become the validator's own
                // stake in their own pool, count toward the minimum they must
                // post, and can be withdrawn again if the pool winds down.
                //
                // Bounded because a wrong balance or a garbled get-method must
                // not be able to drain a wallet in a loop. Falling short of the
                // cap is safe -- the next tick tops up again -- while exceeding
                // it never is.
                let top_up = shortfall.saturating_add(RENT_RUNWAY).min(MAX_TOP_UP_PER_TICK);
                tracing::warn!(
                    pool = %self.pool_addr,
                    balance,
                    owed,
                    shortfall,
                    top_up,
                    "pool holds less than it owes its nominators plus the storage reserve; \
                     depositing validator funds to cover it"
                );
                actions.push(crate::nominator::PoolMaintenance {
                    reason: "pool owes more than it holds; covering the shortfall",
                    body: super::messages::validator_deposit(UnixTime::now())?,
                    value: top_up,
                });
            }
        }

        // A queued withdrawal blocks the next stake outright, so one nominator
        // asking to leave takes the whole pool out of the round unless the
        // queue is drained first. Only worth attempting while the pool is idle:
        // in any other state the funds are with the Elector and the request
        // cannot be settled yet.
        if data.state == POOL_STATE_IDLE && self.has_withdraw_requests().await? {
            actions.push(crate::nominator::PoolMaintenance {
                reason: "queued withdrawals would block the next stake",
                body: super::messages::process_withdraw_requests(
                    UnixTime::now(),
                    WITHDRAW_REQUESTS_PER_MESSAGE,
                )?,
                value: MAINTENANCE_GAS,
            });
        }

        Ok(actions)
    }

    async fn get_pool_data(&self) -> anyhow::Result<crate::nominator::PoolData> {
        let data = NominatorPoolWrapper::get_pool_data(self).await?;
        Ok(crate::nominator::PoolData {
            state: data.state,
            nominators_count: data.nominators_count,
            stake_amount_sent: data.stake_amount_sent,
            validator_amount: data.validator_amount,
            pool_config: crate::nominator::PoolConfig {
                validator_addr: data.validator_address,
                validator_reward_share: data.validator_reward_share,
                max_nominators_count: data.max_nominators_count,
                min_validator_stake: data.min_validator_stake,
                // The shared shape calls this field a maximum; pool.fc stores
                // the per-nominator minimum in that slot.
                max_nominators_stake: data.min_nominator_stake,
            },
            stake_at: data.stake_at,
            saved_validator_set_hash: data.saved_validator_set_hash,
            validator_set_changes_count: data.validator_set_changes_count,
            validator_set_change_time: data.validator_set_change_time,
            stake_held_for: data.stake_held_for,
        })
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
    use std::str::FromStr;
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
            number("0xdef"), // the controller the stake is relayed through
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
        // Two accounts, read from two slots. Reading the old positions would take the
        // controller for a reward share and report every later field one slot early.
        assert_eq!(parsed.validator_address[31], 0xbc);
        assert_eq!(parsed.validator_address[30], 0x0a);
        assert_eq!(parsed.controller_address[31], 0xef);
        assert_eq!(parsed.controller_address[30], 0x0d);
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

    // ===== checkpoint-pinned snapshot =====

    use crate::chain_provider::DefaultChainProvider;
    use chain_rpc_client::v2::{RPCStackEntry, client_json_rpc::ClientJsonRpc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn checkpoint() -> MasterchainCheckpoint {
        MasterchainCheckpoint {
            seqno: 42,
            root_hash: hex::encode([0x11; 32]),
            file_hash: hex::encode([0x22; 32]),
        }
    }

    fn block(seqno: u32, root: u8, file: u8) -> chain_rpc_client::v2::data_models::BlockIdExt {
        chain_rpc_client::v2::data_models::BlockIdExt {
            r#type: "tos.blockIdExt".to_owned(),
            workchain: -1,
            shard: i64::MIN,
            seqno,
            root_hash: vec![root; 32],
            file_hash: vec![file; 32],
        }
    }

    fn pool_data_entries() -> Vec<StackEntry> {
        vec![
            number("2"),
            number("1"),
            number("3000"),
            number("2000"),
            number("0xabc"),
            number("0xdef"),
            number("4000"),
            number("40"),
            number("1000"),
            number("100"),
            list_entry(vec![]),
            list_entry(vec![]),
            number("999"),
            number("0x11"),
            number("2"),
            number("1234"),
            number("3600"),
            list_entry(vec![]),
        ]
    }

    /// The node's wire form of `list_nominators`: one list whose elements
    /// are typed stack entries.
    fn nominator_stack_json() -> serde_json::Value {
        let num = |value: &str| {
            serde_json::json!({
                "@type": "tvm.stackEntryNumber",
                "number": {"@type": "tvm.numberDecimal", "number": value}
            })
        };
        let position = serde_json::json!({
            "@type": "tvm.stackEntryTuple",
            "tuple": {
                "@type": "tvm.tuple",
                "elements": [num("0xabcd"), num("700"), num("50"), num("0")]
            }
        });
        serde_json::json!([["list", {"@type": "tvm.list", "elements": [position]}]])
    }

    /// Serves `runGetMethodStd` over loopback, answering each get-method with
    /// its declared stack (top-first, as the node does) and the block
    /// identity chosen for that method.
    async fn spawn_get_method_server(
        identities: std::collections::HashMap<
            &'static str,
            chain_rpc_client::v2::data_models::BlockIdExt,
        >,
        requests: usize,
    ) -> (String, tokio::task::JoinHandle<Vec<serde_json::Value>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..requests {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                let body = loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    request.extend_from_slice(&buf[..n]);
                    let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map(|value| value.trim().parse::<usize>().unwrap())
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break request[end + 4..end + 4 + length].to_vec();
                    }
                };
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let method = request["params"]["method"].as_str().unwrap().to_owned();
                let stack = match method.as_str() {
                    "get_pool_data" => serde_json::to_value(
                        pool_data_entries()
                            .into_iter()
                            .rev()
                            .map(RPCStackEntry::from)
                            .collect::<Vec<_>>(),
                    )
                    .unwrap(),
                    "list_nominators" => nominator_stack_json(),
                    other => panic!("unexpected get-method {other}"),
                };
                let result = serde_json::json!({
                    "gas_used": 0,
                    "stack": stack,
                    "exit_code": 0,
                    "last_transaction_id": null,
                    "block_id": identities.get(method.as_str()).cloned(),
                });
                let response = serde_json::json!({
                    "ok": true,
                    "jsonrpc": "2.0",
                    "id": request["id"].clone(),
                    "result": result,
                })
                .to_string();
                let http = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response.len(),
                    response
                );
                socket.write_all(http.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
                seen.push(request);
            }
            seen
        });
        (format!("http://{addr}"), handle)
    }

    fn pool_address() -> MsgAddressInt {
        MsgAddressInt::from_str(&format!("-1:{}", "5".repeat(64))).unwrap()
    }

    async fn snapshot_with(
        pool_identity: chain_rpc_client::v2::data_models::BlockIdExt,
        nominators_identity: chain_rpc_client::v2::data_models::BlockIdExt,
        requests: usize,
    ) -> (anyhow::Result<NominatorPoolSnapshot>, Vec<serde_json::Value>) {
        let identities = std::collections::HashMap::from([
            ("get_pool_data", pool_identity),
            ("list_nominators", nominators_identity),
        ]);
        let (url, server) = spawn_get_method_server(identities, requests).await;
        let provider =
            DefaultChainProvider::new(Arc::new(ClientJsonRpc::connect(url, None).unwrap()));
        let result =
            read_nominator_pool_snapshot_at(&provider, &pool_address(), &checkpoint()).await;
        (result, server.await.unwrap())
    }

    #[tokio::test]
    async fn a_pinned_snapshot_reads_both_get_methods_at_the_same_block() {
        let (result, requests) =
            snapshot_with(block(42, 0x11, 0x22), block(42, 0x11, 0x22), 2).await;
        let snapshot = result.unwrap();
        assert_eq!(snapshot.checkpoint, checkpoint());
        assert_eq!(snapshot.pool.state, 2);
        assert_eq!(snapshot.pool.stake_amount_sent, 3000);
        assert_eq!(snapshot.nominators.len(), 1);
        assert_eq!(snapshot.nominators[0].amount, 700);
        assert_eq!(snapshot.nominators[0].pending_deposit, 50);
        for request in &requests {
            assert_eq!(request["params"]["seqno"], 42, "every read is pinned: {request}");
        }
    }

    #[tokio::test]
    async fn a_pool_data_read_from_another_block_rejects_the_snapshot() {
        // Same height, different root hash: a same-seqno fork.
        let (result, _) = snapshot_with(block(42, 0x99, 0x22), block(42, 0x11, 0x22), 1).await;
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("get_pool_data") && error.contains("another block"), "{error}");
    }

    #[tokio::test]
    async fn a_nominator_list_read_from_another_block_rejects_the_snapshot() {
        // Right root hash, wrong file hash on the second read only.
        let (result, _) = snapshot_with(block(42, 0x11, 0x22), block(42, 0x11, 0x77), 2).await;
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("list_nominators") && error.contains("another block"), "{error}");
        let (result, _) = snapshot_with(block(42, 0x11, 0x22), block(43, 0x11, 0x22), 2).await;
        assert!(result.is_err(), "a different seqno is another block too");
    }

    /// A provider that cannot pin state must not be papered over with a
    /// latest-state read.
    #[tokio::test]
    async fn a_provider_without_historical_state_yields_no_snapshot() {
        struct LatestOnly;
        #[async_trait::async_trait]
        impl ChainProvider for LatestOnly {
            async fn run_get_method(
                &self,
                _address: String,
                _method: &str,
                _stack: Vec<StackEntry>,
            ) -> anyhow::Result<TvmStackParser> {
                panic!("a pinned snapshot must never fall back to latest state")
            }
            async fn get_balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
                anyhow::bail!("unused")
            }
            async fn send_boc(&self, _boc: &[u8]) -> anyhow::Result<()> {
                anyhow::bail!("unused")
            }
            async fn get_config_param(
                &self,
                _param_id: u32,
            ) -> anyhow::Result<chain_block::ConfigParamEnum> {
                anyhow::bail!("unused")
            }
            async fn get_address_info(
                &self,
                _address: &MsgAddressInt,
            ) -> anyhow::Result<crate::chain_provider::AddressInfo> {
                anyhow::bail!("unused")
            }
            async fn get_extended_address_info(
                &self,
                _address: &MsgAddressInt,
            ) -> anyhow::Result<crate::chain_provider::ExtendedAddressInfo> {
                anyhow::bail!("unused")
            }
            async fn get_wallet_info(
                &self,
                _address: &MsgAddressInt,
            ) -> anyhow::Result<crate::chain_provider::WalletInfo> {
                anyhow::bail!("unused")
            }
            async fn get_masterchain_info(
                &self,
            ) -> anyhow::Result<crate::chain_provider::MasterchainInfo> {
                anyhow::bail!("unused")
            }
            async fn get_shards(
                &self,
                _seqno: u32,
            ) -> anyhow::Result<crate::chain_provider::ShardsInfo> {
                anyhow::bail!("unused")
            }
            async fn get_block_transactions_page(
                &self,
                _workchain: i32,
                _shard: i64,
                _seqno: u32,
                _after_lt: Option<u64>,
                _after_account: Option<&str>,
                _count: u32,
            ) -> anyhow::Result<crate::chain_provider::BlockTransactionsPage> {
                anyhow::bail!("unused")
            }
        }
        let error = read_nominator_pool_snapshot_at(&LatestOnly, &pool_address(), &checkpoint())
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("unsupported"), "{error:#}");
    }

    // ===== pool maintenance =====

    /// A saved hash the pool is holding, distinct from any "current" set below.
    const SAVED_VSET_HASH: [u8; 32] = [0x11; 32];

    struct StubProvider {
        state: i32,
        changes_count: i32,
        saved_hash: [u8; 32],
        withdraw_requests: bool,
        /// What the pool actually holds.
        balance: u64,
        /// What its ledger says each nominator is owed.
        nominator_amounts: Vec<u64>,
    }

    impl StubProvider {
        /// A solvent, idle pool with one nominator and nothing to do.
        fn new() -> Self {
            Self {
                state: 0,
                changes_count: 0,
                saved_hash: SAVED_VSET_HASH,
                withdraw_requests: false,
                balance: 1_000_000_000_000,
                nominator_amounts: vec![100_000_000_000],
            }
        }
    }

    #[async_trait::async_trait]
    impl ContractProvider for StubProvider {
        async fn get_method(
            &self,
            _address: String,
            method: &str,
            _stack: Vec<tl_api::tos::tvm::StackEntry>,
        ) -> anyhow::Result<TvmStackParser> {
            match method {
                "get_pool_data" => Ok(TvmStackParser::new(vec![
                    number(&self.state.to_string()),
                    number("1"),
                    number("0"),
                    number("2000"),
                    number("0xabc"),
                    number("0xdef"),
                    number("4000"),
                    number("40"),
                    number("1000"),
                    number("100"),
                    list_entry(vec![]),
                    list_entry(vec![]),
                    number("999"),
                    number(&format!("0x{}", hex::encode(self.saved_hash))),
                    number(&self.changes_count.to_string()),
                    number("1234"),
                    number("3600"),
                    list_entry(vec![]),
                ])),
                "has_withdraw_requests" => {
                    Ok(TvmStackParser::new(vec![number(if self.withdraw_requests {
                        "-1"
                    } else {
                        "0"
                    })]))
                }
                "list_nominators" => Ok(TvmStackParser::new(vec![list_entry(
                    self.nominator_amounts
                        .iter()
                        .map(|amount| {
                            tuple_entry(vec![
                                number("0xabcd"),
                                number(&amount.to_string()),
                                number("0"),
                                number("0"),
                            ])
                        })
                        .collect(),
                )])),
                other => anyhow::bail!("unexpected get-method: {other}"),
            }
        }

        async fn balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
            Ok(self.balance)
        }
    }

    fn pool_with(stub: StubProvider) -> NominatorPoolWrapperImpl {
        NominatorPoolWrapperImpl::new(
            Arc::new(stub),
            MsgAddressInt::from_str(&format!("-1:{}", "0".repeat(64))).unwrap(),
        )
    }

    async fn maintenance_for(
        stub: StubProvider,
        current_hash: [u8; 32],
    ) -> Vec<crate::nominator::PoolMaintenance> {
        use crate::nominator::NominatorWrapper;
        pool_with(stub).maintenance(&current_hash).await.unwrap()
    }

    /// A pool's address is the hash of its code and its initial storage, so
    /// this value pins both. Two things derive it independently -- this crate
    /// when it deploys or resolves a pool, and the lifecycle end-to-end script
    /// when it drives one -- and a silent disagreement between them would send
    /// deposits to an address that holds no pool at all.
    #[test]
    fn pool_address_derivation_is_pinned() {
        let addr = NominatorPoolWrapperImpl::calculate_address(
            -1,
            &[0xAB; 32],
            &[0xCD; 32],
            4000,
            40,
            5_000_000_000_000,
            100_000_000_000,
        )
        .unwrap();
        assert_eq!(
            addr.to_string(),
            "-1:5f3cb76a7256a4bd9dbae1e362c87307d3821000d365bce6e3a04f154633bef4"
        );
    }

    #[tokio::test]
    async fn quiet_pool_needs_nothing() {
        let actions = maintenance_for(StubProvider::new(), SAVED_VSET_HASH).await;
        assert!(actions.is_empty());
    }

    #[tokio::test]
    async fn unnoticed_validator_set_change_is_reported_to_the_pool() {
        let actions = maintenance_for(StubProvider::new(), [0x22; 32]).await;
        assert_eq!(actions.len(), 1);
        assert!(actions[0].reason.contains("validator set"));

        let mut body = chain_block::SliceData::load_cell(actions[0].body.clone()).unwrap();
        assert_eq!(
            body.get_next_u32().unwrap(),
            super::super::messages::opcodes::UPDATE_VALIDATOR_SET
        );
    }

    #[tokio::test]
    async fn the_pool_stops_being_told_once_it_has_counted_enough_changes() {
        // pool.fc caps the counter, so past the cap another message would be
        // spent gas that changes nothing.
        let mut stub = StubProvider::new();
        stub.changes_count = MAX_VALIDATOR_SET_CHANGES;
        assert!(maintenance_for(stub, [0x22; 32]).await.is_empty());
    }

    #[tokio::test]
    async fn a_queued_withdrawal_is_drained_before_it_can_block_the_next_stake() {
        let mut stub = StubProvider::new();
        stub.withdraw_requests = true;
        let actions = maintenance_for(stub, SAVED_VSET_HASH).await;
        assert_eq!(actions.len(), 1);
        assert!(actions[0].reason.contains("block the next stake"));

        let mut body = chain_block::SliceData::load_cell(actions[0].body.clone()).unwrap();
        assert_eq!(
            body.get_next_u32().unwrap(),
            super::super::messages::opcodes::PROCESS_WITHDRAW_REQUESTS
        );
    }

    #[tokio::test]
    async fn withdrawals_are_left_alone_while_the_stake_sits_with_the_elector() {
        // The principal is not in the pool to pay out yet, so asking would only
        // burn gas until the round ends.
        let mut stub = StubProvider::new();
        stub.withdraw_requests = true;
        stub.state = 2;
        assert!(maintenance_for(stub, SAVED_VSET_HASH).await.is_empty());
    }

    #[tokio::test]
    async fn a_pool_that_owes_more_than_it_holds_is_topped_up_by_its_validator() {
        // Rent has eaten into what the ledger says the nominators are owed.
        let mut stub = StubProvider::new();
        stub.nominator_amounts = vec![100_000_000_000];
        stub.balance = 105_000_000_000; // 5 TOS short of owed + the 10 TOS reserve

        let actions = maintenance_for(stub, SAVED_VSET_HASH).await;
        assert_eq!(actions.len(), 1);
        assert!(actions[0].reason.contains("owes more than it holds"));
        // Shortfall plus runway, and booked as the validator's own stake so the
        // ledger stays honest about whose money it is.
        assert_eq!(actions[0].value, 5_000_000_000 + RENT_RUNWAY);

        let mut body = chain_block::SliceData::load_cell(actions[0].body.clone()).unwrap();
        assert_eq!(
            body.get_next_u32().unwrap(),
            super::super::messages::opcodes::VALIDATOR_DEPOSIT
        );
    }

    #[tokio::test]
    async fn a_nonsense_shortfall_cannot_drain_the_wallet() {
        // Whatever produced this, it is not a pool that owes ten million TOS.
        let mut stub = StubProvider::new();
        stub.nominator_amounts = vec![10_000_000_000_000_000];
        stub.balance = 0;

        let actions = maintenance_for(stub, SAVED_VSET_HASH).await;
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].value, MAX_TOP_UP_PER_TICK);
    }

    #[tokio::test]
    async fn a_solvent_pool_is_not_topped_up() {
        let mut stub = StubProvider::new();
        stub.nominator_amounts = vec![100_000_000_000];
        stub.balance = 110_000_000_000; // exactly owed plus the reserve
        assert!(maintenance_for(stub, SAVED_VSET_HASH).await.is_empty());
    }

    #[tokio::test]
    async fn solvency_is_not_judged_while_the_stake_sits_with_the_elector() {
        // Mid-round the balance is legitimately down to the reserve because the
        // principal is with the Elector. Reading that as insolvency would top
        // up the pool every round for no reason.
        let mut stub = StubProvider::new();
        stub.state = 2;
        stub.nominator_amounts = vec![100_000_000_000];
        stub.balance = 10_000_000_000;
        assert!(maintenance_for(stub, SAVED_VSET_HASH).await.is_empty());
    }

    #[tokio::test]
    async fn a_pool_can_need_both_nudges_at_once() {
        let mut stub = StubProvider::new();
        stub.withdraw_requests = true;
        let actions = maintenance_for(stub, [0x22; 32]).await;
        assert_eq!(actions.len(), 2);
    }
}
