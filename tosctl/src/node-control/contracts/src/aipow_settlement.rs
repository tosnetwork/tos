/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
use chain_block::Deserializable;
use chain_block::{
    base64_decode, read_single_root_boc, BuilderData, Cell, Coins, IBitstring, MsgAddressInt,
    Serializable, StateInit,
};
use common::tvm_stack_parser::TvmStackParser;

pub const AIPOW_SETTLEMENT_CODE_B64: &str = "te6cckECDgEAA2IAART/APSkE/S88sgLAQIBYgIDA+LQAdDTAwFxsJJfA+D6QDDtRNDTD9Mf0x/TH9IH0w/TD9Mf+gD6ANT0BNEtxwCOnz1wf3TIywLKB8v/ydAcxwWzkl8N4FR4xVR3ZVYQVhLgPgzTH9M/MSGCEEFQUwG64wI8ghBBUFMCuuMCXw2BCQPy8AQFBgIBIAgJAvxScIAg9A9vocAAjmvQ+kDT/9N/MALTAjHSBzHT/zD4KAkQihB6EDYFEEpZcALIy//L/8lTEXHIyw9QDM8WGss/GMoHFst/UAT6AhfLHxXLfxTLDxTLDxLLH8zLAMlwcVRwEcjLAMsAywAUzBPLAMzLAMlxIfkAEuMNgQkCUAMLBwDqMdMf0//Tf9N/0YEI/VNNvvL0gQj/IsIA8vQjVhGAIPQPb6GBCP4y8vIQPvgjyFAFzxYTy//Lf8t/yx/JQL2AIPQXEIsQehBpEFgQRxA2RUAQIwvIyw8ayx8Yyx8Wyx8UygcSyw/LD8sfAfoCAfoCzPQAye1UAKYK0VN7gCD0D2+hgQkBMvLyJ6QnqCaggQkA+CNYvvL0B6QQiwoQaRBYEEcQNkUEQxMLyMsPGssfGMsfFssfFMoHEssPyw/LHwH6AgH6Asz0AMntVADK8vRQPqCBCQRTErzy8gmkUZZQPRwLyMsPGssfGMsfFssfFMoHEssPyw/LHwH6AgH6Asz0AMntVFh0yMsCE8oHy//J0HBxUwGAEMjLBVAFzxYj+gIUy2gTywASywASzMsAyYBA+wABW78hv2omhph+mP6Y/pj+kD6Yfph+mP/QB9AGp6AmicHC2bGxCIPAg0KCKIHCAMQKAgEgDA0B9lJwgCD0D2+hwACOa9D6QNP/038wAtMCMdIHMdP/MPgoCRCKEHoQNgUQSllwAsjL/8v/yVMRccjLD1AMzxYayz8YygcWy39QBPoCF8sfFct/FMsPFMsPEssfzMsAyXBxVHARyMsAywDLABTME8sAzMsAyXEh+QAS4w0xEgsACl8IcG0hAD251+7UTQ0w/TH9Mf0x/SB9MP0w/TH/oA+gDU9ATRW4AIO7OG7UTQ0w/TH9Mf0x/SB9MP0w/TH/oA+gDU9ATRbLGAIPQPb6HAAJkwcMjJ0FRxESDg0PpA0//Tf9N/0x8wcVVAgKwWN1";

pub const AIPOW_SETTLEMENT_REGISTER_OPCODE: u32 = 0x4150_5301;
pub const AIPOW_SETTLEMENT_SKIP_OPCODE: u32 = 0x4150_5302;

/// The settlement layout version this SDK writes and the contract understands.
pub const AIPOW_SETTLEMENT_VERSION: u16 = 1;

/// Deployment parameters for the AIPoW settlement account.
///
/// The single governance-registered masterchain account named by ConfigParam
/// 93. It owns the epoch cursor and the cumulative supply cap so the
/// once-per-epoch and 4.5B-cap invariants live in one place; it forwards each
/// epoch pool to the canonical per-epoch distributor. Inert until capAipow is
/// activated and this address is registered.
#[derive(Clone, Debug)]
pub struct AipowSettlementInit {
    /// The first epoch the cursor will settle.
    pub next_epoch: u32,
    /// Epoch length in seconds (fixes the skip deadline).
    pub epoch_seconds: u32,
    /// Seconds after an epoch ends before it may be skipped with zero mint.
    pub register_grace: u32,
    /// The workchain the per-epoch distributors are deployed on and pay
    /// identities on (e.g. 0 for basechain, where agent wallets live).
    pub earner_workchain: i8,
    /// The maturation snapshot every per-epoch distributor is deployed with.
    pub maturation: crate::aipow_distributor::AipowMaturation,
    /// The AIPoW supply cap (nanotos), e.g. 4.5B TOS.
    pub total_cap: u64,
    /// The audited distributor code used to derive canonical distributor
    /// addresses in the settle path.
    pub distributor_code: Cell,
}

pub struct AipowSettlementContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AipowSettlementData {
    pub version: u16,
    pub next_epoch: u32,
    pub epoch_seconds: u32,
    pub register_grace: u32,
    pub earner_workchain: i8,
    pub maturation: crate::aipow_distributor::AipowMaturation,
    pub minted_total: u64,
    pub total_cap: u64,
}

/// A recorded epoch → commitment nomination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AipowRegistration {
    pub commitment_addr: MsgAddressInt,
    pub score_root: [u8; 32],
    pub total_score: u128,
    pub organic_settled_value: u128,
    pub registered_at: u32,
}

impl AipowSettlementContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(AIPOW_SETTLEMENT_CODE_B64)?).map_err(Into::into)
    }

    pub fn build_data(init: &AipowSettlementInit) -> anyhow::Result<chain_block::Cell> {
        if init.epoch_seconds == 0 {
            anyhow::bail!("epoch_seconds must be positive");
        }
        if init.maturation.epoch_seconds == 0 || init.maturation.stream_epochs == 0 {
            anyhow::bail!("maturation epoch_seconds and stream_epochs must be positive");
        }
        if init.maturation.immediate_bps > 10_000 {
            anyhow::bail!("maturation immediate_bps must not exceed 10000");
        }
        let mut data = BuilderData::new();
        data.append_u16(AIPOW_SETTLEMENT_VERSION)?;
        data.append_u32(init.next_epoch)?;
        data.append_u32(init.epoch_seconds)?;
        data.append_u32(init.register_grace)?;
        data.append_i8(init.earner_workchain)?;
        data.append_u16(init.maturation.immediate_bps)?;
        data.append_u16(init.maturation.stream_epochs)?;
        data.append_u32(init.maturation.epoch_seconds)?;
        append_tomis(&mut data, 0)?; // minted_total starts at zero
        append_tomis(&mut data, init.total_cap)?;
        data.checked_append_reference(init.distributor_code.clone())?;
        data.append_bit_zero()?; // empty registrations dictionary
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &AipowSettlementInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(wc: i32, init: &AipowSettlementInit) -> anyhow::Result<MsgAddressInt> {
        let cell = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(wc, cell.hash(0))?)
    }

    /// Decode `get_aipow_settlement_data`.
    pub fn decode_data(stack: &TvmStackParser) -> anyhow::Result<AipowSettlementData> {
        Ok(AipowSettlementData {
            version: stack.u64(0)? as u16,
            next_epoch: stack.u64(1)? as u32,
            epoch_seconds: stack.u64(2)? as u32,
            register_grace: stack.u64(3)? as u32,
            earner_workchain: stack.i64(4)? as i8,
            maturation: crate::aipow_distributor::AipowMaturation {
                immediate_bps: stack.u64(5)? as u16,
                stream_epochs: stack.u64(6)? as u16,
                epoch_seconds: stack.u64(7)? as u32,
            },
            minted_total: stack.u64(8)?,
            total_cap: stack.u64(9)?,
        })
    }

    /// Decode `get_distributor_address(epoch, pool)`:
    /// `(found, workchain, address_hash)`. Returns the canonical distributor
    /// address the settle path would deploy, or `None` if `epoch` is not
    /// registered.
    pub fn decode_distributor_address(
        stack: &TvmStackParser,
    ) -> anyhow::Result<Option<MsgAddressInt>> {
        let found = stack.u64(0)? != 0;
        if !found {
            return Ok(None);
        }
        let workchain = stack.i64(1)? as i8;
        let hash = parse_hash(stack, 2)?;
        Ok(Some(MsgAddressInt::with_standart(None, workchain, hash.into())?))
    }

    /// Decode `get_registration`:
    /// `(found, commitment_addr, score_root, total_score, organic_settled_value, registered_at)`.
    pub fn decode_registration(stack: &TvmStackParser) -> anyhow::Result<Option<AipowRegistration>> {
        let found = stack.u64(0)? != 0;
        if !found {
            return Ok(None);
        }
        let mut addr_slice = stack.slice(1)?;
        Ok(Some(AipowRegistration {
            commitment_addr: MsgAddressInt::construct_from(&mut addr_slice)?,
            score_root: parse_hash(stack, 2)?,
            total_score: parse_u128(stack, 3)?,
            organic_settled_value: parse_u128(stack, 4)?,
            registered_at: stack.u64(5)? as u32,
        }))
    }

    /// A commitment nominates itself as the authoritative source for `epoch`,
    /// carrying its committed tuple. Sent with `sender == the commitment`.
    pub fn register(
        query_id: u64,
        epoch: u32,
        score_root: [u8; 32],
        total_score: u128,
        organic_settled_value: u128,
    ) -> anyhow::Result<chain_block::Cell> {
        let mut body = BuilderData::new();
        body.append_u32(AIPOW_SETTLEMENT_REGISTER_OPCODE)?;
        body.append_u64(query_id)?;
        body.append_u32(epoch)?;
        body.append_u256(&score_root)?;
        append_u128(&mut body, total_score)?;
        append_u128(&mut body, organic_settled_value)?;
        Ok(body.into_cell()?)
    }

    /// Permissionless: advance the cursor with zero mint once the epoch at the
    /// cursor has passed its grace deadline with no registration.
    pub fn skip(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        let mut body = BuilderData::new();
        body.append_u32(AIPOW_SETTLEMENT_SKIP_OPCODE)?;
        body.append_u64(query_id)?;
        Ok(body.into_cell()?)
    }
}

fn append_tomis(builder: &mut BuilderData, amount: u64) -> anyhow::Result<()> {
    Coins::new(amount).write_to(builder)?;
    Ok(())
}

fn append_u128(builder: &mut BuilderData, value: u128) -> anyhow::Result<()> {
    builder.append_raw(&value.to_be_bytes(), 128)?;
    Ok(())
}

fn parse_u128(stack: &TvmStackParser, index: usize) -> anyhow::Result<u128> {
    let bytes = stack.number_bytes(index, 16)?;
    let array: [u8; 16] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("stack entry {} is not a 128-bit value", index))?;
    Ok(u128::from_be_bytes(array))
}

fn parse_hash(stack: &TvmStackParser, index: usize) -> anyhow::Result<[u8; 32]> {
    stack
        .number_bytes(index, 32)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stack entry {} is not a 256-bit value", index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::SliceData;

    fn dummy_distributor_code() -> Cell {
        BuilderData::with_raw(vec![0xD1], 8).unwrap().into_cell().unwrap()
    }

    fn init() -> AipowSettlementInit {
        AipowSettlementInit {
            next_epoch: 27_260,
            epoch_seconds: 65_536,
            register_grace: 3600,
            earner_workchain: 0,
            maturation: crate::aipow_distributor::AipowMaturation::methodology_v0(),
            total_cap: 4_500_000_000_000_000_000,
            distributor_code: dummy_distributor_code(),
        }
    }

    #[test]
    fn state_init_and_address_are_deterministic() {
        let i = init();
        let a = AipowSettlementContract::build_state_init(&i)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        let b = AipowSettlementContract::build_state_init(&i)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        assert_eq!(a.hash(0), b.hash(0));
    }

    #[test]
    fn build_data_rejects_zero_epoch_seconds() {
        let mut bad = init();
        bad.epoch_seconds = 0;
        assert!(AipowSettlementContract::build_data(&bad).is_err());
    }

    #[test]
    fn encodes_register_and_skip_messages() {
        let body = AipowSettlementContract::register(1, 42, [0xAB; 32], 1000, 2000).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), AIPOW_SETTLEMENT_REGISTER_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 1);
        assert_eq!(slice.get_next_u32().unwrap(), 42);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xAB; 32]);
        assert_eq!(slice.get_next_bytes(16).unwrap(), 1000u128.to_be_bytes().to_vec());
        assert_eq!(slice.get_next_bytes(16).unwrap(), 2000u128.to_be_bytes().to_vec());
        assert_eq!(slice.remaining_bits(), 0);

        let body = AipowSettlementContract::skip(9).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), AIPOW_SETTLEMENT_SKIP_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 9);
        assert_eq!(slice.remaining_bits(), 0);
    }
}
