/*
 * Copyright (C) 2025-2026 TOS Network.
 * Licensed under the GNU General Public License v3.0.
 */

use anyhow::Context;
use chain_block::{
    BuilderData, Coins, HashmapE, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
    base64_decode, read_single_root_boc,
};
use ed25519_dalek::VerifyingKey;
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
const DICTIONARIES_MAGIC: u32 = 0x504d_4431;
const MARKET_ID_DOMAIN: &[u8] = b"TOS_PREDICTION_MARKET_V1";

#[derive(Clone, Debug)]
pub struct PredictionOraclePolicyV1 {
    pub threshold: u8,
    pub policy_hash: [u8; 32],
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

        let empty = BuilderData::new().into_cell()?;
        let mut normal = BuilderData::new();
        normal
            .append_u32(NORMAL_RUNTIME_MAGIC)?
            .append_raw(&[0; 32], 256)?
            .append_u64(0)?
            .checked_append_reference(empty.clone())?
            .append_raw(&[0; 32], 256)?
            .append_u8(0)?
            .append_raw(&[0; 32], 256)?
            .append_u64(0)?
            .append_u64(0)?;
        let mut review = BuilderData::new();
        review
            .append_u32(REVIEW_RUNTIME_MAGIC)?
            .checked_append_reference(empty)?
            .append_raw(&[0; 32], 256)?
            .append_raw(&[0; 32], 256)?
            .append_u64(0)?
            .append_u64(0)?;
        let mut challenge = BuilderData::new();
        challenge.append_u32(CHALLENGE_RUNTIME_MAGIC)?.append_bit_zero()?;
        init.reserve_recipient.write_to(&mut challenge)?;
        challenge.append_u8(0)?.append_raw(&[0; 32], 256)?;
        Coins::new(0).write_to(&mut challenge)?;
        let mut final_state = BuilderData::new();
        final_state.append_u32(FINAL_RUNTIME_MAGIC)?.append_u8(0)?.append_u64(0)?;
        for _ in 0..4 {
            final_state.append_raw(&[0; 32], 256)?;
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
        || policy.policy_hash == [0; 32]
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
        .append_u8(u8::try_from(policy.reporters.len())?)?
        .append_raw(&policy.policy_hash, 256)?;
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
    if init.trade_close > init.resolve_not_before
        || init.resolve_not_before.checked_add(60) > Some(init.oracle_vote_deadline)
        || init.challenge_period < 60
        || init.appeal_review_delay < 60
        || init.appeal_period.checked_sub(init.appeal_review_delay).unwrap_or(0) < 60
        || init.claim_deadline <= scheduled
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
        || init.challenge_bond == 0
        || init.challenge_processing_fee == 0
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
