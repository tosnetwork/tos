/*
 * Copyright (C) 2025-2026 TOS Network.
 * Licensed under the GNU General Public License v3.0.
 */

use anyhow::Context;
use chain_block::{
    BuilderData, Coins, Deserializable, HashmapE, IBitstring, MsgAddressInt, Serializable,
    SliceData, StateInit, base64_decode, read_single_root_boc,
};
use common::tvm_stack_parser::TvmStackParser;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const PREDICTION_MARKET_CODE_B64: &str =
    include_str!("../../../../../crypto/smartcont/prediction-market-v1.boc.base64");
pub const PREDICTION_MARKET_CODE_VERSION: u16 = 1;
pub const PREDICTION_PRICE_SCALE: u16 = 10_000;

pub const PM_ACTIVATE_OPCODE: u32 = 0x504d_0001;
pub const PM_REGISTER_DEPOSIT_OPCODE: u32 = 0x504d_0002;
pub const PM_DEPOSIT_OPCODE: u32 = 0x504d_0003;
pub const PM_SET_TRADING_KEY_OPCODE: u32 = 0x504d_0004;
pub const PM_RAISE_NONCE_FLOOR_OPCODE: u32 = 0x504d_0005;
pub const PM_CANCEL_EXACT_OPCODE: u32 = 0x504d_0006;
pub const PM_SPLIT_OPCODE: u32 = 0x504d_0007;
pub const PM_MERGE_OPCODE: u32 = 0x504d_0008;
pub const PM_MATCH_PAIR_OPCODE: u32 = 0x504d_0009;
pub const PM_REPORT_RESULT_OPCODE: u32 = 0x504d_000a;
pub const PM_CHALLENGE_RESULT_OPCODE: u32 = 0x504d_000b;
pub const PM_ADVANCE_PHASE_OPCODE: u32 = 0x504d_000c;
pub const PM_FINALIZE_UNCONTESTED_OPCODE: u32 = 0x504d_000d;
pub const PM_FINALIZE_REVIEW_TIMEOUT_OPCODE: u32 = 0x504d_000e;
pub const PM_CLAIM_OPCODE: u32 = 0x504d_000f;
pub const PM_WITHDRAW_OPCODE: u32 = 0x504d_0010;
pub const PM_WITHDRAW_CHALLENGE_BOND_OPCODE: u32 = 0x504d_0011;
pub const PM_FORCE_REFUND_CHALLENGE_BOND_OPCODE: u32 = 0x504d_0012;
pub const PM_PRUNE_ORDER_OPCODE: u32 = 0x504d_0013;
pub const PM_CLOSE_EMPTY_ACCOUNT_OPCODE: u32 = 0x504d_0014;
pub const PM_FORCE_CLOSE_ACCOUNT_OPCODE: u32 = 0x504d_0015;
pub const PM_COMPACT_TERMINAL_OPCODE: u32 = 0x504d_0016;
pub const PM_WITHDRAW_TERMINAL_SURPLUS_OPCODE: u32 = 0x504d_0017;
pub const PM_PRUNE_OWNER_ORDERS_OPCODE: u32 = 0x504d_0018;
pub const PM_TOP_UP_RESERVE_OPCODE: u32 = 0x504d_0019;

const ORDER_MAGIC: u32 = 0x504f_5231;
const SIGNED_ORDER_MAGIC: u32 = 0x5053_4f31;
const ORDER_AUTHORIZATION_MAGIC: u32 = 0x504f_4131;

const CONFIG_MAGIC: u32 = 0x504d_4331;
const IDENTITY_MAGIC: u32 = 0x504d_4931;
const RESERVE_RECIPIENT_MAGIC: u32 = 0x504d_5252;
const TIMES_MAGIC: u32 = 0x504d_5431;
const ECONOMICS_MAGIC: u32 = 0x504d_4531;
const FEES_MAGIC: u32 = 0x504d_4631;
const CHALLENGE_FEES_MAGIC: u32 = 0x504d_4643;
const POLICIES_MAGIC: u32 = 0x504d_5032;
const POLICY_MAGIC: u32 = 0x504d_5031;
const STATE_MAGIC: u32 = 0x504d_5331;
const ACCOUNTING_MAGIC: u32 = 0x504d_4131;
const LIABILITIES_MAGIC: u32 = 0x504d_4c31;
const RESOLUTION_MAGIC: u32 = 0x504d_5230;
const NORMAL_RUNTIME_MAGIC: u32 = 0x504d_524e;
const REVIEW_RUNTIME_MAGIC: u32 = 0x504d_5256;
const CHALLENGE_RUNTIME_MAGIC: u32 = 0x504d_4332;
const FINAL_RUNTIME_MAGIC: u32 = 0x504d_4632;
const OPTIONAL_HASH_NONE_MAGIC: u32 = 0x504d_4f30;
const DICTIONARIES_MAGIC: u32 = 0x504d_4431;
const MARKET_ID_DOMAIN: &[u8] = b"TOS_PREDICTION_MARKET_V1";
const ORDER_DOMAIN: &[u8] = b"TOS_PREDICTION_ORDER_V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PredictionOrderActionV1 {
    Buy = 0,
    Sell = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PredictionOrderOutcomeV1 {
    Yes = 0,
    No = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PredictionLiquidityRoleV1 {
    Maker = 0,
    Taker = 1,
}

#[derive(Clone, Debug)]
pub struct PredictionOrderV1 {
    pub global_id: i32,
    pub workchain_id: i8,
    pub market_address: MsgAddressInt,
    pub market_config_hash: [u8; 32],
    pub owner_address: MsgAddressInt,
    pub key_epoch: u32,
    pub nonce: u64,
    pub salt: [u8; 32],
    pub action: PredictionOrderActionV1,
    pub outcome: PredictionOrderOutcomeV1,
    pub liquidity_role: PredictionLiquidityRoleV1,
    pub quantity_lots: u64,
    pub min_fill_lots: u64,
    pub allow_partial: bool,
    pub limit_price_tick: u16,
    pub valid_after: u64,
    pub valid_until: u64,
    pub optional_counterparty: Option<MsgAddressInt>,
}

#[derive(Clone, Debug)]
pub struct PredictionOraclePolicyV1 {
    pub threshold: u8,
    pub reporters: Vec<MsgAddressInt>,
}

#[derive(Clone, Debug)]
pub struct PredictionMarketInitV1 {
    pub global_id: i32,
    pub workchain_id: i8,
    pub deployment_salt: [u8; 32],
    pub rules_hash: [u8; 32],
    pub metadata_hash: [u8; 32],
    pub reserve_recipient: MsgAddressInt,
    pub trade_close: u64,
    pub resolve_not_before: u64,
    pub oracle_vote_deadline: u64,
    pub challenge_period: u64,
    pub appeal_review_delay: u64,
    pub appeal_period: u64,
    pub claim_deadline: u64,
    pub lot_value: u64,
    pub min_price_tick: u16,
    pub min_fill_lots: u64,
    pub max_order_lots: u64,
    pub max_locked_collateral: u64,
    pub max_account_free_balance: u64,
    pub max_total_free_balance: u64,
    pub max_total_liability: u64,
    pub max_participants: u32,
    pub max_orders_per_participant: u32,
    pub max_live_order_records: u32,
    pub participant_entry_fee: u64,
    pub account_cleanup_bounty: u64,
    pub order_entry_fee: u64,
    pub order_cleanup_bounty: u64,
    pub operating_reserve_floor: u64,
    pub terminal_tombstone_reserve: u64,
    pub challenge_bond: u64,
    pub challenge_processing_fee: u64,
    pub normal_oracle_policy: PredictionOraclePolicyV1,
    pub appellate_oracle_policy: PredictionOraclePolicyV1,
}

pub struct PredictionMarketContractV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PredictionMarketStatusV1 {
    Trading = 0,
    Reporting = 1,
    Proposed = 2,
    Reviewing = 3,
    Finalized = 4,
    Terminal = 5,
}

impl TryFrom<u64> for PredictionMarketStatusV1 {
    type Error = anyhow::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Trading),
            1 => Ok(Self::Reporting),
            2 => Ok(Self::Proposed),
            3 => Ok(Self::Reviewing),
            4 => Ok(Self::Finalized),
            5 => Ok(Self::Terminal),
            _ => anyhow::bail!("unknown PredictionMarket status {value}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PredictionResolutionOutcomeV1 {
    Yes = 0,
    No = 1,
    Invalid = 2,
}

impl TryFrom<u64> for PredictionResolutionOutcomeV1 {
    type Error = anyhow::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Yes),
            1 => Ok(Self::No),
            2 => Ok(Self::Invalid),
            _ => anyhow::bail!("unknown PredictionMarket outcome {value}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredictionMarketStateV1 {
    pub activated: bool,
    pub activated_at: u64,
    pub status: PredictionMarketStatusV1,
    pub review_reason: u8,
    /// Meaningful only once `status >= Finalized`.
    pub final_outcome: PredictionResolutionOutcomeV1,
    pub market_config_hash: [u8; 32],
    pub market_id: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredictionMarketAccountingV1 {
    pub participants: u32,
    pub live_orders: u32,
    pub fill_count: u64,
    pub complete_sets: u64,
    pub total_free: u64,
    pub locked: u64,
    pub final_backing: u64,
    pub remaining_payout: u64,
    pub claimed: u64,
    pub challenge_bond: u64,
    pub cleanup_liability: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredictionMarketAccountV1 {
    pub owner: MsgAddressInt,
    pub trading_pubkey: [u8; 32],
    pub key_epoch: u32,
    pub nonce_floor: u64,
    pub free_balance: u64,
    pub yes_lots: u64,
    pub no_lots: u64,
    pub live_orders: u32,
    pub account_cleanup_credit: u64,
    pub order_cleanup_credit: u64,
    /// Opaque dictionary root. Use `get_prediction_order` for individual records.
    pub orders: chain_block::Cell,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredictionOrderStateV1 {
    pub digest: [u8; 32],
    pub quantity_lots: u64,
    pub filled_lots: u64,
    pub valid_until: u64,
    pub cancelled: bool,
    pub cleanup_credit: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredictionMarketPhaseV1 {
    pub status: PredictionMarketStatusV1,
    pub review_reason: u8,
    pub final_outcome: PredictionResolutionOutcomeV1,
    pub current_context_hash: [u8; 32],
    pub review_base_context_hash: [u8; 32],
    pub proposed_statement_hash: [u8; 32],
    pub next_deadline: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredictionResolutionContextsV1 {
    pub current: Option<chain_block::Cell>,
    pub review_base: Option<chain_block::Cell>,
}

impl PredictionMarketContractV1 {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(PREDICTION_MARKET_CODE_B64.trim())?).map_err(Into::into)
    }

    pub fn build_config(init: &PredictionMarketInitV1) -> anyhow::Result<chain_block::Cell> {
        validate_init(init)?;
        let mut reserve = BuilderData::new();
        reserve.append_u32(RESERVE_RECIPIENT_MAGIC)?;
        init.reserve_recipient.write_to(&mut reserve)?;

        let mut identity = BuilderData::new();
        identity
            .append_u32(IDENTITY_MAGIC)?
            .append_i32(init.global_id)?
            .append_i8(init.workchain_id)?
            .append_raw(&init.deployment_salt, 256)?
            .append_raw(&init.rules_hash, 256)?
            .append_raw(&init.metadata_hash, 256)?
            .checked_append_reference(reserve.into_cell()?)?;

        let mut times = BuilderData::new();
        times
            .append_u32(TIMES_MAGIC)?
            .append_u64(init.trade_close)?
            .append_u64(init.resolve_not_before)?
            .append_u64(init.oracle_vote_deadline)?
            .append_u64(init.challenge_period)?
            .append_u64(init.appeal_review_delay)?
            .append_u64(init.appeal_period)?
            .append_u64(init.claim_deadline)?;

        let mut challenge_fees = BuilderData::new();
        challenge_fees.append_u32(CHALLENGE_FEES_MAGIC)?;
        Coins::new(init.challenge_bond).write_to(&mut challenge_fees)?;
        Coins::new(init.challenge_processing_fee).write_to(&mut challenge_fees)?;
        let mut fees = BuilderData::new();
        fees.append_u32(FEES_MAGIC)?;
        for value in [
            init.participant_entry_fee,
            init.account_cleanup_bounty,
            init.order_entry_fee,
            init.order_cleanup_bounty,
            init.operating_reserve_floor,
            init.terminal_tombstone_reserve,
        ] {
            Coins::new(value).write_to(&mut fees)?;
        }
        fees.checked_append_reference(challenge_fees.into_cell()?)?;

        let mut economics = BuilderData::new();
        economics.append_u32(ECONOMICS_MAGIC)?;
        Coins::new(init.lot_value).write_to(&mut economics)?;
        economics
            .append_u16(init.min_price_tick)?
            .append_u64(init.min_fill_lots)?
            .append_u64(init.max_order_lots)?;
        for value in [
            init.max_locked_collateral,
            init.max_account_free_balance,
            init.max_total_free_balance,
            init.max_total_liability,
        ] {
            Coins::new(value).write_to(&mut economics)?;
        }
        economics
            .append_u32(init.max_participants)?
            .append_u32(init.max_orders_per_participant)?
            .append_u32(init.max_live_order_records)?
            .checked_append_reference(fees.into_cell()?)?;

        let normal = build_policy(&init.normal_oracle_policy)?;
        let appellate = build_policy(&init.appellate_oracle_policy)?;
        let mut policies = BuilderData::new();
        policies
            .append_u32(POLICIES_MAGIC)?
            .checked_append_reference(normal)?
            .checked_append_reference(appellate)?;

        let mut config = BuilderData::new();
        config
            .append_u32(CONFIG_MAGIC)?
            .checked_append_reference(identity.into_cell()?)?
            .checked_append_reference(times.into_cell()?)?
            .checked_append_reference(economics.into_cell()?)?
            .checked_append_reference(policies.into_cell()?)?;
        Ok(config.into_cell()?)
    }

    pub fn market_config_hash(init: &PredictionMarketInitV1) -> anyhow::Result<[u8; 32]> {
        Ok(*Self::build_config(init)?.repr_hash().as_array())
    }

    pub fn oracle_policy_hash(policy: &PredictionOraclePolicyV1) -> anyhow::Result<[u8; 32]> {
        Ok(*build_policy(policy)?.repr_hash().as_array())
    }

    pub fn market_id(init: &PredictionMarketInitV1) -> anyhow::Result<[u8; 32]> {
        let config_hash = Self::market_config_hash(init)?;
        let mut hasher = Sha256::new();
        hasher.update(MARKET_ID_DOMAIN);
        hasher.update(init.global_id.to_be_bytes());
        hasher.update(init.workchain_id.to_be_bytes());
        hasher.update(init.deployment_salt);
        hasher.update(config_hash);
        Ok(hasher.finalize().into())
    }

    pub fn build_data(init: &PredictionMarketInitV1) -> anyhow::Result<chain_block::Cell> {
        let config = Self::build_config(init)?;
        let config_hash = *config.repr_hash().as_array();
        let market_id = Self::market_id(init)?;

        let mut liabilities = BuilderData::new();
        liabilities.append_u32(LIABILITIES_MAGIC)?;
        for _ in 0..7 {
            Coins::new(0).write_to(&mut liabilities)?;
        }
        let mut accounting = BuilderData::new();
        accounting
            .append_u32(ACCOUNTING_MAGIC)?
            .append_u32(0)?
            .append_u32(0)?
            .append_u64(0)?
            .append_u64(0)?
            .checked_append_reference(liabilities.into_cell()?)?;

        let mut normal = BuilderData::new();
        normal
            .append_u32(NORMAL_RUNTIME_MAGIC)?
            .append_raw(&[0; 32], 256)?
            .append_u64(0)?
            .append_bit_zero()?
            .append_raw(&[0; 32], 256)?
            .append_raw(&[0], 2)?
            .append_raw(&[0; 32], 256)?
            .append_u64(0)?
            .append_u64(0)?;
        let mut review = BuilderData::new();
        review
            .append_u32(REVIEW_RUNTIME_MAGIC)?
            .append_bit_zero()?
            .append_raw(&[0; 32], 256)?
            .append_raw(&[0; 32], 256)?
            .append_u64(0)?
            .append_u64(0)?;
        let mut challenge = BuilderData::new();
        challenge.append_u32(CHALLENGE_RUNTIME_MAGIC)?;
        let mut absent_hash = BuilderData::new();
        absent_hash.append_u32(OPTIONAL_HASH_NONE_MAGIC)?;
        let absent_hash = absent_hash.into_cell()?;
        let mut final_state = BuilderData::new();
        final_state.append_u32(FINAL_RUNTIME_MAGIC)?.append_u8(0)?.append_u64(0)?;
        for _ in 0..4 {
            final_state.checked_append_reference(absent_hash.clone())?;
        }
        let mut resolution = BuilderData::new();
        resolution
            .append_u32(RESOLUTION_MAGIC)?
            .checked_append_reference(normal.into_cell()?)?
            .checked_append_reference(review.into_cell()?)?
            .checked_append_reference(challenge.into_cell()?)?
            .checked_append_reference(final_state.into_cell()?)?;

        let mut dictionaries = BuilderData::new();
        dictionaries.append_u32(DICTIONARIES_MAGIC)?;
        for _ in 0..4 {
            HashmapE::with_bit_len(256).write_to(&mut dictionaries)?;
        }

        let mut data = BuilderData::new();
        data.append_u32(STATE_MAGIC)?
            .append_u16(PREDICTION_MARKET_CODE_VERSION)?
            .append_bit_zero()?
            .append_u64(0)?
            .append_u8(0)?
            .append_raw(&[0], 2)?
            .append_raw(&[0], 2)?
            .append_raw(&config_hash, 256)?
            .append_raw(&market_id, 256)?
            .checked_append_reference(config)?
            .checked_append_reference(accounting.into_cell()?)?
            .checked_append_reference(resolution.into_cell()?)?
            .checked_append_reference(dictionaries.into_cell()?)?;
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &PredictionMarketInitV1) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(init: &PredictionMarketInitV1) -> anyhow::Result<MsgAddressInt> {
        let state = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(i32::from(init.workchain_id), state.hash(0))?)
    }

    pub fn decode_state(stack: &TvmStackParser) -> anyhow::Result<PredictionMarketStateV1> {
        require_stack_len(stack, 7, "get_prediction_state")?;
        Ok(PredictionMarketStateV1 {
            activated: stack.bool(0)?,
            activated_at: stack.u64(1)?,
            status: stack.u64(2)?.try_into()?,
            review_reason: narrow_u8(stack, 3, "review_reason")?,
            final_outcome: stack.u64(4)?.try_into()?,
            market_config_hash: parse_hash(stack, 5)?,
            market_id: parse_hash(stack, 6)?,
        })
    }

    pub fn decode_accounting(
        stack: &TvmStackParser,
    ) -> anyhow::Result<PredictionMarketAccountingV1> {
        require_stack_len(stack, 11, "get_prediction_accounting")?;
        Ok(PredictionMarketAccountingV1 {
            participants: narrow_u32(stack, 0, "participants")?,
            live_orders: narrow_u32(stack, 1, "live_orders")?,
            fill_count: stack.u64(2)?,
            complete_sets: stack.u64(3)?,
            total_free: stack.u64(4)?,
            locked: stack.u64(5)?,
            final_backing: stack.u64(6)?,
            remaining_payout: stack.u64(7)?,
            claimed: stack.u64(8)?,
            challenge_bond: stack.u64(9)?,
            cleanup_liability: stack.u64(10)?,
        })
    }

    pub fn decode_account(stack: &TvmStackParser) -> anyhow::Result<PredictionMarketAccountV1> {
        require_stack_len(stack, 11, "get_prediction_account")?;
        let mut owner = stack.slice(0)?;
        Ok(PredictionMarketAccountV1 {
            owner: MsgAddressInt::construct_from(&mut owner)?,
            trading_pubkey: parse_hash(stack, 1)?,
            key_epoch: narrow_u32(stack, 2, "key_epoch")?,
            nonce_floor: stack.u64(3)?,
            free_balance: stack.u64(4)?,
            yes_lots: stack.u64(5)?,
            no_lots: stack.u64(6)?,
            live_orders: narrow_u32(stack, 7, "live_orders")?,
            account_cleanup_credit: stack.u64(8)?,
            order_cleanup_credit: stack.u64(9)?,
            orders: stack.cell(10)?,
        })
    }

    pub fn decode_order_state(
        stack: &TvmStackParser,
    ) -> anyhow::Result<Option<PredictionOrderStateV1>> {
        require_stack_len(stack, 7, "get_prediction_order")?;
        if !stack.bool(0)? {
            return Ok(None);
        }
        let quantity_lots = stack.u64(2)?;
        let filled_lots = stack.u64(3)?;
        anyhow::ensure!(filled_lots <= quantity_lots, "order fill exceeds quantity");
        Ok(Some(PredictionOrderStateV1 {
            digest: parse_hash(stack, 1)?,
            quantity_lots,
            filled_lots,
            valid_until: stack.u64(4)?,
            cancelled: stack.bool(5)?,
            cleanup_credit: stack.u64(6)?,
        }))
    }

    pub fn decode_phase(stack: &TvmStackParser) -> anyhow::Result<PredictionMarketPhaseV1> {
        require_stack_len(stack, 7, "get_market_phase")?;
        Ok(PredictionMarketPhaseV1 {
            status: stack.u64(0)?.try_into()?,
            review_reason: narrow_u8(stack, 1, "review_reason")?,
            final_outcome: stack.u64(2)?.try_into()?,
            current_context_hash: parse_hash(stack, 3)?,
            review_base_context_hash: parse_hash(stack, 4)?,
            proposed_statement_hash: parse_hash(stack, 5)?,
            next_deadline: stack.u64(6)?,
        })
    }

    pub fn decode_resolution_contexts(
        stack: &TvmStackParser,
    ) -> anyhow::Result<PredictionResolutionContextsV1> {
        require_stack_len(stack, 4, "get_resolution_contexts")?;
        let current_present = stack.bool(0)?;
        let current = stack.cell(1)?;
        let review_present = stack.bool(2)?;
        let review_base = stack.cell(3)?;
        anyhow::ensure!(
            current_present || (current.bit_length() == 0 && current.references_count() == 0),
            "absent current resolution context must use the empty-cell sentinel"
        );
        anyhow::ensure!(
            review_present
                || (review_base.bit_length() == 0 && review_base.references_count() == 0),
            "absent review base context must use the empty-cell sentinel"
        );
        Ok(PredictionResolutionContextsV1 {
            current: current_present.then_some(current),
            review_base: review_present.then_some(review_base),
        })
    }

    pub fn activate(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message_header(PM_ACTIVATE_OPCODE, query_id)?.into_cell()
    }

    pub fn register_and_deposit(
        query_id: u64,
        credited: u64,
        trading_pubkey: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        validate_public_key(trading_pubkey)?;
        let mut body = message_header(PM_REGISTER_DEPOSIT_OPCODE, query_id)?;
        Coins::new(credited).write_to(&mut body)?;
        body.append_raw(&trading_pubkey, 256)?;
        Ok(body.into_cell()?)
    }

    pub fn deposit(query_id: u64, credited: u64) -> anyhow::Result<chain_block::Cell> {
        let mut body = message_header(PM_DEPOSIT_OPCODE, query_id)?;
        Coins::new(credited).write_to(&mut body)?;
        Ok(body.into_cell()?)
    }

    pub fn set_trading_key(
        query_id: u64,
        trading_pubkey: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        validate_public_key(trading_pubkey)?;
        let mut body = message_header(PM_SET_TRADING_KEY_OPCODE, query_id)?;
        body.append_raw(&trading_pubkey, 256)?;
        Ok(body.into_cell()?)
    }

    pub fn raise_nonce_floor(query_id: u64, floor: u64) -> anyhow::Result<chain_block::Cell> {
        let mut body = message_header(PM_RAISE_NONCE_FLOOR_OPCODE, query_id)?;
        body.append_u64(floor)?;
        Ok(body.into_cell()?)
    }

    pub fn split(query_id: u64, quantity: u64) -> anyhow::Result<chain_block::Cell> {
        let mut body = message_header(PM_SPLIT_OPCODE, query_id)?;
        body.append_u64(quantity)?;
        Ok(body.into_cell()?)
    }

    pub fn merge(query_id: u64, quantity: u64) -> anyhow::Result<chain_block::Cell> {
        let mut body = message_header(PM_MERGE_OPCODE, query_id)?;
        body.append_u64(quantity)?;
        Ok(body.into_cell()?)
    }

    pub fn claim(query_id: u64, owner: &MsgAddressInt) -> anyhow::Result<chain_block::Cell> {
        validate_address(owner, "claim owner")?;
        let mut body = message_header(PM_CLAIM_OPCODE, query_id)?;
        owner.write_to(&mut body)?;
        Ok(body.into_cell()?)
    }

    pub fn withdraw(query_id: u64, amount: u64) -> anyhow::Result<chain_block::Cell> {
        let mut body = message_header(PM_WITHDRAW_OPCODE, query_id)?;
        Coins::new(amount).write_to(&mut body)?;
        Ok(body.into_cell()?)
    }

    pub fn withdraw_challenge_bond(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message_header(PM_WITHDRAW_CHALLENGE_BOND_OPCODE, query_id)?.into_cell()
    }

    pub fn force_refund_challenge_bond(
        query_id: u64,
        challenger: &MsgAddressInt,
    ) -> anyhow::Result<chain_block::Cell> {
        validate_address(challenger, "challenge bond recipient")?;
        let mut body = message_header(PM_FORCE_REFUND_CHALLENGE_BOND_OPCODE, query_id)?;
        challenger.write_to(&mut body)?;
        Ok(body.into_cell()?)
    }

    pub fn prune_order(
        query_id: u64,
        owner: &MsgAddressInt,
        epoch: u32,
        nonce: u64,
        accept_reward: bool,
    ) -> anyhow::Result<chain_block::Cell> {
        validate_address(owner, "order owner")?;
        let mut body = message_header(PM_PRUNE_ORDER_OPCODE, query_id)?;
        owner.write_to(&mut body)?;
        body.append_u32(epoch)?.append_u64(nonce)?.append_bit_bool(accept_reward)?;
        Ok(body.into_cell()?)
    }

    pub fn prune_owner_orders(
        query_id: u64,
        owner: &MsgAddressInt,
        accept_reward: bool,
    ) -> anyhow::Result<chain_block::Cell> {
        validate_address(owner, "order owner")?;
        let mut body = message_header(PM_PRUNE_OWNER_ORDERS_OPCODE, query_id)?;
        owner.write_to(&mut body)?;
        body.append_bit_bool(accept_reward)?;
        Ok(body.into_cell()?)
    }

    pub fn close_empty_account(
        query_id: u64,
        owner: &MsgAddressInt,
        accept_reward: bool,
    ) -> anyhow::Result<chain_block::Cell> {
        validate_address(owner, "account owner")?;
        let mut body = message_header(PM_CLOSE_EMPTY_ACCOUNT_OPCODE, query_id)?;
        owner.write_to(&mut body)?;
        body.append_bit_bool(accept_reward)?;
        Ok(body.into_cell()?)
    }

    pub fn force_close_account(
        query_id: u64,
        owner: &MsgAddressInt,
        accept_reward: bool,
    ) -> anyhow::Result<chain_block::Cell> {
        validate_address(owner, "account owner")?;
        let mut body = message_header(PM_FORCE_CLOSE_ACCOUNT_OPCODE, query_id)?;
        owner.write_to(&mut body)?;
        body.append_bit_bool(accept_reward)?;
        Ok(body.into_cell()?)
    }

    pub fn compact_terminal(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message_header(PM_COMPACT_TERMINAL_OPCODE, query_id)?.into_cell()
    }

    pub fn withdraw_terminal_surplus(
        query_id: u64,
        amount: u64,
    ) -> anyhow::Result<chain_block::Cell> {
        if amount == 0 {
            anyhow::bail!("terminal surplus withdrawal must be nonzero");
        }
        let mut body = message_header(PM_WITHDRAW_TERMINAL_SURPLUS_OPCODE, query_id)?;
        Coins::new(amount).write_to(&mut body)?;
        Ok(body.into_cell()?)
    }

    /// Builds the typed reserve-donation body used by the Agent Account
    /// checked-contract-call v2 action. Direct wallets may continue to top up
    /// with an empty body.
    pub fn top_up_reserve(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message_header(PM_TOP_UP_RESERVE_OPCODE, query_id)?.into_cell()
    }

    pub fn report_result(
        query_id: u64,
        round: u8,
        expected_round_context_hash: [u8; 32],
        outcome: u8,
        evidence_root: [u8; 32],
        statement_created_at: u64,
        statement_expiry: u64,
    ) -> anyhow::Result<chain_block::Cell> {
        if round > 1
            || outcome > 2
            || expected_round_context_hash == [0; 32]
            || evidence_root == [0; 32]
            || statement_created_at >= statement_expiry
        {
            anyhow::bail!("invalid PredictionMarket resolution report");
        }
        let mut body = message_header(PM_REPORT_RESULT_OPCODE, query_id)?;
        body.append_u8(round)?
            .append_raw(&expected_round_context_hash, 256)?
            .append_u8(outcome)?
            .append_raw(&evidence_root, 256)?
            .append_u64(statement_created_at)?
            .append_u64(statement_expiry)?;
        Ok(body.into_cell()?)
    }

    pub fn challenge_result(
        query_id: u64,
        expected_proposed_statement_hash: [u8; 32],
        counter_outcome: u8,
        counter_evidence_root: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        if expected_proposed_statement_hash == [0; 32]
            || counter_outcome > 2
            || counter_evidence_root == [0; 32]
        {
            anyhow::bail!("invalid PredictionMarket challenge");
        }
        let mut body = message_header(PM_CHALLENGE_RESULT_OPCODE, query_id)?;
        body.append_raw(&expected_proposed_statement_hash, 256)?
            .append_u8(counter_outcome)?
            .append_raw(&counter_evidence_root, 256)?;
        Ok(body.into_cell()?)
    }

    pub fn advance_phase(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message_header(PM_ADVANCE_PHASE_OPCODE, query_id)?.into_cell()
    }

    pub fn finalize_uncontested(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message_header(PM_FINALIZE_UNCONTESTED_OPCODE, query_id)?.into_cell()
    }

    pub fn finalize_review_timeout(
        query_id: u64,
        expected_review_base_context_hash: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        if expected_review_base_context_hash == [0; 32] {
            anyhow::bail!("review base context hash must be nonzero");
        }
        let mut body = message_header(PM_FINALIZE_REVIEW_TIMEOUT_OPCODE, query_id)?;
        body.append_raw(&expected_review_base_context_hash, 256)?;
        Ok(body.into_cell()?)
    }

    pub fn build_order(order: &PredictionOrderV1) -> anyhow::Result<chain_block::Cell> {
        validate_order(order)?;
        let mut market = BuilderData::new();
        order.market_address.write_to(&mut market)?;
        market.append_raw(&order.market_config_hash, 256)?;
        let mut owner = BuilderData::new();
        order.owner_address.write_to(&mut owner)?;
        if let Some(counterparty) = &order.optional_counterparty {
            owner.append_bit_one()?;
            counterparty.write_to(&mut owner)?;
        } else {
            owner.append_bit_zero()?;
        }
        let mut root = BuilderData::new();
        root.append_u32(ORDER_MAGIC)?
            .append_u16(PREDICTION_MARKET_CODE_VERSION)?
            .append_i32(order.global_id)?
            .append_i8(order.workchain_id)?
            .append_u32(order.key_epoch)?
            .append_u64(order.nonce)?
            .append_raw(&order.salt, 256)?
            .append_u64(order.quantity_lots)?
            .append_u64(order.min_fill_lots)?
            .append_u16(order.limit_price_tick)?
            .append_u64(order.valid_after)?
            .append_u64(order.valid_until)?
            .append_u8(order.action as u8)?
            .append_u8(order.outcome as u8)?
            .append_u8(order.liquidity_role as u8)?;
        if order.allow_partial {
            root.append_bit_one()?;
        } else {
            root.append_bit_zero()?;
        }
        root.checked_append_reference(market.into_cell()?)?
            .checked_append_reference(owner.into_cell()?)?;
        Ok(root.into_cell()?)
    }

    pub fn order_digest(order: &PredictionOrderV1) -> anyhow::Result<[u8; 32]> {
        let order_cell = Self::build_order(order)?;
        let mut binding = BuilderData::new();
        order.market_address.write_to(&mut binding)?;
        binding
            .append_raw(&order.market_config_hash, 256)?
            .append_raw(order_cell.repr_hash().as_slice(), 256)?;
        let mut authorization = BuilderData::new();
        authorization
            .append_u32(ORDER_AUTHORIZATION_MAGIC)?
            .append_u16(PREDICTION_MARKET_CODE_VERSION)?
            .append_raw(Sha256::digest(ORDER_DOMAIN).as_slice(), 256)?
            .append_i32(order.global_id)?
            .append_i8(order.workchain_id)?
            .append_u16(PREDICTION_MARKET_CODE_VERSION)?
            .checked_append_reference(binding.into_cell()?)?;
        Ok(*authorization.into_cell()?.repr_hash().as_array())
    }

    pub fn build_signed_order(
        order: &PredictionOrderV1,
        public_key: [u8; 32],
        signature: [u8; 64],
    ) -> anyhow::Result<chain_block::Cell> {
        validate_public_key(public_key)?;
        let digest = Self::order_digest(order)?;
        let key = VerifyingKey::from_bytes(&public_key)?;
        key.verify_strict(&digest, &Signature::from_bytes(&signature))
            .context("invalid PredictionMarket order signature")?;
        let order_cell = Self::build_order(order)?;
        let mut signature_cell = BuilderData::new();
        signature_cell.append_raw(&signature, 512)?;
        let mut signed = BuilderData::new();
        signed
            .append_u32(SIGNED_ORDER_MAGIC)?
            .append_u16(PREDICTION_MARKET_CODE_VERSION)?
            .append_raw(&public_key, 256)?
            .checked_append_reference(order_cell)?
            .checked_append_reference(signature_cell.into_cell()?)?;
        Ok(signed.into_cell()?)
    }

    pub fn cancel_exact(
        query_id: u64,
        order: &PredictionOrderV1,
    ) -> anyhow::Result<chain_block::Cell> {
        let mut body = message_header(PM_CANCEL_EXACT_OPCODE, query_id)?;
        body.checked_append_reference(Self::build_order(order)?)?;
        Ok(body.into_cell()?)
    }

    pub fn match_pair(
        query_id: u64,
        quantity_lots: u64,
        left_signed_order: chain_block::Cell,
        right_signed_order: chain_block::Cell,
    ) -> anyhow::Result<chain_block::Cell> {
        if quantity_lots == 0 {
            anyhow::bail!("PredictionMarket match quantity must be nonzero");
        }
        let mut body = message_header(PM_MATCH_PAIR_OPCODE, query_id)?;
        body.append_u64(quantity_lots)?
            .checked_append_reference(left_signed_order)?
            .checked_append_reference(right_signed_order)?;
        Ok(body.into_cell()?)
    }
}

fn require_stack_len(stack: &TvmStackParser, expected: usize, method: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        stack.stack.len() == expected,
        "{method} returned {} entries, expected {expected}",
        stack.stack.len()
    );
    Ok(())
}

fn parse_hash(stack: &TvmStackParser, index: usize) -> anyhow::Result<[u8; 32]> {
    stack
        .number_bytes(index, 32)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stack entry {index} is not a 256-bit value"))
}

fn narrow_u32(stack: &TvmStackParser, index: usize, field: &str) -> anyhow::Result<u32> {
    u32::try_from(stack.u64(index)?).with_context(|| format!("{field} exceeds uint32"))
}

fn narrow_u8(stack: &TvmStackParser, index: usize, field: &str) -> anyhow::Result<u8> {
    u8::try_from(stack.u64(index)?).with_context(|| format!("{field} exceeds uint8"))
}

fn validate_order(order: &PredictionOrderV1) -> anyhow::Result<()> {
    validate_address(&order.market_address, "order market")?;
    validate_address(&order.owner_address, "order owner")?;
    if let Some(counterparty) = &order.optional_counterparty {
        validate_address(counterparty, "order counterparty")?;
    }
    if order.workchain_id != -1 && order.workchain_id != 0 {
        anyhow::bail!("unsupported PredictionMarket order workchain");
    }
    if order.market_address.workchain_id() != i32::from(order.workchain_id)
        || order.market_config_hash == [0; 32]
        || order.salt == [0; 32]
        || order.quantity_lots == 0
        || order.min_fill_lots == 0
        || order.min_fill_lots > order.quantity_lots
        || order.limit_price_tick == 0
        || order.limit_price_tick >= PREDICTION_PRICE_SCALE
        || order.valid_after >= order.valid_until
    {
        anyhow::bail!("invalid PredictionMarket order fields");
    }
    Ok(())
}

fn message_header(opcode: u32, query_id: u64) -> anyhow::Result<BuilderData> {
    let mut body = BuilderData::new();
    body.append_u32(opcode)?.append_u64(query_id)?;
    Ok(body)
}

fn build_policy(policy: &PredictionOraclePolicyV1) -> anyhow::Result<chain_block::Cell> {
    if policy.reporters.is_empty()
        || policy.reporters.len() > 7
        || policy.threshold == 0
        || usize::from(policy.threshold) > policy.reporters.len()
        || usize::from(policy.threshold) * 2 <= policy.reporters.len()
    {
        anyhow::bail!("invalid PredictionMarket oracle threshold policy");
    }
    let mut seen = HashSet::new();
    let mut reporters = HashmapE::with_bit_len(256);
    for address in &policy.reporters {
        validate_address(address, "oracle reporter")?;
        let identity = address.to_string();
        if !seen.insert(identity) {
            anyhow::bail!("PredictionMarket oracle reporters must be unique");
        }
        let mut address_cell = BuilderData::new();
        address.write_to(&mut address_cell)?;
        let address_cell = address_cell.into_cell()?;
        let key =
            SliceData::load_builder(BuilderData::with_bytes(address_cell.repr_hash().as_slice())?)?;
        let mut value = BuilderData::new();
        address.write_to(&mut value)?;
        reporters
            .set_builder(key, &value)
            .context("insert oracle reporter into canonical dictionary")?;
    }
    let mut result = BuilderData::new();
    result
        .append_u32(POLICY_MAGIC)?
        .append_u8(policy.threshold)?
        .append_u8(u8::try_from(policy.reporters.len())?)?;
    reporters.write_to(&mut result)?;
    Ok(result.into_cell()?)
}

fn validate_init(init: &PredictionMarketInitV1) -> anyhow::Result<()> {
    validate_address(&init.reserve_recipient, "reserve recipient")?;
    if init.workchain_id != -1 && init.workchain_id != 0 {
        anyhow::bail!("PredictionMarket workchain must be -1 or 0");
    }
    if init.reserve_recipient.workchain_id() != i32::from(init.workchain_id) {
        anyhow::bail!("reserve recipient must be in the market workchain");
    }
    if init.deployment_salt == [0; 32]
        || init.rules_hash == [0; 32]
        || init.metadata_hash == [0; 32]
    {
        anyhow::bail!("PredictionMarket immutable hashes must be nonzero");
    }
    let scheduled = init
        .oracle_vote_deadline
        .checked_add(init.challenge_period)
        .and_then(|value| value.checked_add(init.appeal_period))
        .context("PredictionMarket final deadline overflow")?;
    const MAX_RESOLUTION_DELAY: u64 = 2_592_000;
    const MAX_ORACLE_WINDOW: u64 = 2_592_000;
    const MAX_CHALLENGE_PERIOD: u64 = 604_800;
    const MAX_APPEAL_PERIOD: u64 = 1_209_600;
    const MAX_CLAIM_WINDOW: u64 = 15_552_000;
    let resolution_delay =
        init.resolve_not_before.checked_sub(init.trade_close).unwrap_or(u64::MAX);
    let oracle_window =
        init.oracle_vote_deadline.checked_sub(init.resolve_not_before).unwrap_or(u64::MAX);
    let claim_window = init.claim_deadline.checked_sub(scheduled).unwrap_or(u64::MAX);
    if init.trade_close > init.resolve_not_before
        || init.resolve_not_before.checked_add(60).unwrap_or(u64::MAX) > init.oracle_vote_deadline
        || init.challenge_period < 60
        || init.appeal_review_delay < 60
        || init.appeal_period.checked_sub(init.appeal_review_delay).unwrap_or(0) < 60
        || init.claim_deadline <= scheduled
        || resolution_delay > MAX_RESOLUTION_DELAY
        || oracle_window > MAX_ORACLE_WINDOW
        || init.challenge_period > MAX_CHALLENGE_PERIOD
        || init.appeal_period > MAX_APPEAL_PERIOD
        || claim_window > MAX_CLAIM_WINDOW
    {
        anyhow::bail!("invalid PredictionMarket time windows");
    }
    if init.lot_value == 0
        || init.lot_value % u64::from(PREDICTION_PRICE_SCALE) != 0
        || init.lot_value % 2 != 0
        || init.min_price_tick == 0
        || init.min_price_tick >= PREDICTION_PRICE_SCALE / 2
        || init.min_fill_lots == 0
        || init.min_fill_lots > init.max_order_lots
        || init.max_locked_collateral == 0
        || init.max_locked_collateral % init.lot_value != 0
        || init.max_order_lots > init.max_locked_collateral / init.lot_value
        || init.max_account_free_balance == 0
        || init.max_account_free_balance > init.max_total_free_balance
        || init.max_total_free_balance > init.max_total_liability
        || init.max_participants == 0
        || init.max_participants > 4096
        || init.max_orders_per_participant == 0
        || init.max_orders_per_participant > 256
        || init.max_live_order_records == 0
        || init.max_live_order_records > 16_384
    {
        anyhow::bail!("invalid PredictionMarket economic limits");
    }
    if init.participant_entry_fee < 1_000_000
        || init.account_cleanup_bounty < 1_000_000
        || init.order_entry_fee < 1_000_000
        || init.order_cleanup_bounty < 1_000_000
        || init.operating_reserve_floor < 100_000_000
        || init.terminal_tombstone_reserve == 0
        || init.terminal_tombstone_reserve > init.operating_reserve_floor
        || !(10_000_000..=1_000_000_000_000).contains(&init.challenge_bond)
        || !(1_000_000..=100_000_000_000).contains(&init.challenge_processing_fee)
    {
        anyhow::bail!("invalid PredictionMarket fee and reserve profile");
    }
    let cleanup = u128::from(init.max_participants)
        .checked_mul(u128::from(init.account_cleanup_bounty))
        .and_then(|value| {
            value.checked_add(
                u128::from(init.max_live_order_records) * u128::from(init.order_cleanup_bounty),
            )
        })
        .context("PredictionMarket cleanup liability overflow")?;
    let required = u128::from(init.max_total_free_balance)
        + u128::from(init.max_locked_collateral)
        + u128::from(init.challenge_bond)
        + cleanup;
    if required > u128::from(init.max_total_liability) {
        anyhow::bail!("max_total_liability does not cover configured worst-case liabilities");
    }
    let normal: HashSet<_> =
        init.normal_oracle_policy.reporters.iter().map(ToString::to_string).collect();
    if init
        .appellate_oracle_policy
        .reporters
        .iter()
        .any(|address| normal.contains(&address.to_string()))
    {
        anyhow::bail!("normal and appellate oracle sets must be disjoint");
    }
    build_policy(&init.normal_oracle_policy)?;
    build_policy(&init.appellate_oracle_policy)?;
    Ok(())
}

fn validate_address(address: &MsgAddressInt, label: &str) -> anyhow::Result<()> {
    let MsgAddressInt::AddrStd(value) = address else {
        anyhow::bail!("{label} must be a standard address");
    };
    if value.anycast.is_some() || (value.workchain_id != -1 && value.workchain_id != 0) {
        anyhow::bail!("{label} must be a canonical standard address in workchain -1 or 0");
    }
    Ok(())
}

fn validate_public_key(public_key: [u8; 32]) -> anyhow::Result<()> {
    const FIELD_MODULUS: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    let mut y = public_key;
    y[31] &= 0x7f;
    let canonical = y
        .iter()
        .rev()
        .zip(FIELD_MODULUS.iter().rev())
        .find_map(|(left, right)| (left != right).then_some(left < right))
        .unwrap_or(false);
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| anyhow::anyhow!("trading key is not a valid Ed25519 point"))?;
    if !canonical || key.is_weak() {
        anyhow::bail!("trading key is non-canonical or small-order");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::tvm_stack_parser::TvmStackParser;
    use tl_api::tos::tvm::{
        Number, StackEntry, cell,
        numberdecimal::NumberDecimal,
        stackentry::{StackEntryCell, StackEntryNumber},
    };

    fn number(value: impl Into<String>) -> StackEntry {
        StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
            number: Number::Tvm_NumberDecimal(NumberDecimal { number: value.into() }),
        })
    }

    fn hash_number(value: [u8; 32]) -> StackEntry {
        number(format!("0x{}", hex::encode(value)))
    }

    fn cell_entry(value: &chain_block::Cell) -> StackEntry {
        StackEntry::Tvm_StackEntryCell(StackEntryCell {
            cell: cell::Cell { bytes: chain_block::write_boc(value).unwrap() },
        })
    }

    fn addr(value: &str) -> MsgAddressInt {
        value.parse().expect("canonical address")
    }

    #[test]
    fn reserve_top_up_body_is_typed_and_exact() {
        let body = PredictionMarketContractV1::top_up_reserve(0x0102_0304_0506_0708).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), PM_TOP_UP_RESERVE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(slice.remaining_bits(), 0);
        assert_eq!(slice.remaining_references(), 0);
    }

    #[test]
    fn oracle_policy_hash_is_the_canonical_policy_cell_hash() {
        let policy = PredictionOraclePolicyV1 {
            threshold: 1,
            reporters: vec![addr(
                "0:1111111111111111111111111111111111111111111111111111111111111111",
            )],
        };
        let expected = *build_policy(&policy).unwrap().repr_hash().as_array();
        assert_eq!(PredictionMarketContractV1::oracle_policy_hash(&policy).unwrap(), expected);

        let mut changed = policy;
        changed.reporters[0] =
            addr("0:2222222222222222222222222222222222222222222222222222222222222222");
        assert_ne!(PredictionMarketContractV1::oracle_policy_hash(&changed).unwrap(), expected);
    }

    #[test]
    fn order_codec_matches_the_independent_protocol_golden_vector() {
        let order = PredictionOrderV1 {
            global_id: 42,
            workchain_id: 0,
            market_address: addr(
                "0:1111111111111111111111111111111111111111111111111111111111111111",
            ),
            market_config_hash: [0x44; 32],
            owner_address: addr(
                "0:2222222222222222222222222222222222222222222222222222222222222222",
            ),
            key_epoch: 7,
            nonce: 19,
            salt: [0x55; 32],
            action: PredictionOrderActionV1::Buy,
            outcome: PredictionOrderOutcomeV1::Yes,
            liquidity_role: PredictionLiquidityRoleV1::Maker,
            quantity_lots: 100,
            min_fill_lots: 10,
            allow_partial: true,
            limit_price_tick: 6_250,
            valid_after: 1_700_000_000,
            valid_until: 1_700_003_600,
            optional_counterparty: Some(addr(
                "0:3333333333333333333333333333333333333333333333333333333333333333",
            )),
        };
        let order_cell = PredictionMarketContractV1::build_order(&order).unwrap();
        assert_eq!(
            hex::encode(order_cell.repr_hash().as_slice()),
            "522c29e58e110437cae43bf8b45467da2836283d573a813a015851ac64fcf950"
        );
        assert_eq!(
            hex::encode(PredictionMarketContractV1::order_digest(&order).unwrap()),
            "f6ed4e0395a1787d27b90daad080b6977de5ff1ceb95a9386f792e0b3291fa09"
        );
        let public_key: [u8; 32] =
            hex::decode("8b237d788e8eaaef550c6d125823fa45f1fd5fc29b2c88bdf871119471fc1312")
                .unwrap()
                .try_into()
                .unwrap();
        let signature: [u8; 64] = hex::decode(
            "2330df8f78c3dbce994ef979823f78dbea32165fbe9f502130d6bbbf31030ab705664ba5ce58a4aece4b5b86648cd471436c66518ec0360d321851423fe80709",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let signed =
            PredictionMarketContractV1::build_signed_order(&order, public_key, signature).unwrap();
        assert_eq!(
            hex::encode(signed.repr_hash().as_slice()),
            "870e05091bd091a61296b6226a51f795a49abb6113e21ac794e8fb60a9ee5f97"
        );
    }

    #[test]
    fn decodes_strict_market_state_accounting_order_and_phase_stacks() {
        let state = PredictionMarketContractV1::decode_state(&TvmStackParser::new(vec![
            number("-1"),
            number("1700000000"),
            number("4"),
            number("1"),
            number("2"),
            hash_number([0x11; 32]),
            hash_number([0x22; 32]),
        ]))
        .unwrap();
        assert!(state.activated);
        assert_eq!(state.status, PredictionMarketStatusV1::Finalized);
        assert_eq!(state.final_outcome, PredictionResolutionOutcomeV1::Invalid);

        let accounting = PredictionMarketContractV1::decode_accounting(&TvmStackParser::new(
            (1u64..=11).map(|value| number(value.to_string())).collect(),
        ))
        .unwrap();
        assert_eq!(accounting.participants, 1);
        assert_eq!(accounting.complete_sets, 4);
        assert_eq!(accounting.cleanup_liability, 11);

        let order = PredictionMarketContractV1::decode_order_state(&TvmStackParser::new(vec![
            number("1"),
            hash_number([0x33; 32]),
            number("10"),
            number("6"),
            number("1700003600"),
            number("-1"),
            number("1000000"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(order.filled_lots, 6);
        assert!(order.cancelled);
        assert_eq!(order.cleanup_credit, 1_000_000);

        let absent = PredictionMarketContractV1::decode_order_state(&TvmStackParser::new(vec![
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
        ]))
        .unwrap();
        assert_eq!(absent, None);

        let phase = PredictionMarketContractV1::decode_phase(&TvmStackParser::new(vec![
            number("3"),
            number("1"),
            number("0"),
            hash_number([0x44; 32]),
            hash_number([0x55; 32]),
            hash_number([0x66; 32]),
            number("1700007200"),
        ]))
        .unwrap();
        assert_eq!(phase.status, PredictionMarketStatusV1::Reviewing);
        assert_eq!(phase.current_context_hash, [0x44; 32]);

        let current = BuilderData::with_raw(vec![0x80], 1).unwrap().into_cell().unwrap();
        let empty = chain_block::Cell::default();
        let contexts =
            PredictionMarketContractV1::decode_resolution_contexts(&TvmStackParser::new(vec![
                number("-1"),
                cell_entry(&current),
                number("0"),
                cell_entry(&empty),
            ]))
            .unwrap();
        assert_eq!(contexts.current, Some(current));
        assert_eq!(contexts.review_base, None);

        assert!(
            PredictionMarketContractV1::decode_resolution_contexts(&TvmStackParser::new(vec![
                number("0"),
                cell_entry(&BuilderData::with_raw(vec![0x80], 1).unwrap().into_cell().unwrap()),
                number("0"),
                cell_entry(&empty),
            ]))
            .is_err()
        );
    }

    #[test]
    fn rejects_abi_drift_and_impossible_order_state() {
        let short = TvmStackParser::new(vec![number("0")]);
        assert!(PredictionMarketContractV1::decode_state(&short).is_err());

        let overfilled = TvmStackParser::new(vec![
            number("1"),
            hash_number([0x33; 32]),
            number("5"),
            number("6"),
            number("1700003600"),
            number("0"),
            number("1000000"),
        ]);
        assert!(PredictionMarketContractV1::decode_order_state(&overfilled).is_err());

        let unknown_status = TvmStackParser::new(vec![
            number("1"),
            number("1700000000"),
            number("6"),
            number("0"),
            number("0"),
            hash_number([0x11; 32]),
            hash_number([0x22; 32]),
        ]);
        assert!(PredictionMarketContractV1::decode_state(&unknown_status).is_err());
    }
}
