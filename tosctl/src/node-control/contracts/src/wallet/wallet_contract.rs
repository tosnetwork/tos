/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{ContractProvider, Wallet, smart_contract::SmartContract};
use chain_block::{
    BuilderData, Cell, CurrencyCollection, ExternalInboundMessageHeader, IBitstring,
    InternalMessageHeader, Message, MsgAddressExt, MsgAddressInt, OutAction, OutActions,
    Serializable, SliceData, StateInit, base64_decode, read_single_root_boc,
};
use common::{WalletVersion, signer::Signer, time_format};
use std::sync::Arc;

// The v1 wallet has no network-bound variant: its signed body carries no
// global_id, so a message signed for one network replays on any other network
// where the same key deployed the same code. Only kept for reading legacy
// accounts; new operator wallets must use v3, v4 or v5.
pub const V1R3_CODE: &str = "b5ee9c7241010101005f0000baff0020dd2082014c97ba218201339cbab19c71b0ed44d0d31fd70bffe304e0a4f260810200d71820d70b1fed44d0d31fd3ffd15112baf2a122f901541044f910f2a2f80001d31f3120d74a96d307d402fb00ded1a4c8cb1fcbffc9ed54b5b86e42";

// The three network-bound wallets below are compiled from
// crypto/smartcont/{wallet3-code,wallet-v4-code,wallet-v5-code}.fc. Each one
// reads the network's global_id (ConfigParam 19, GLOBALID opcode) and rejects
// a signed body whose leading int32 does not match it, so a transfer signed
// for one network cannot be replayed on another. The sandbox test
// `source_compiles_to_the_embedded_wallet_code` fails whenever these constants
// drift from the FunC sources.
pub const V3R2_CODE: &str = "b5ee9c7241020a0100014e000114ff00f4a413f4bcf2c80b010201200203020148040501b0f28308d71820d21ff83512baf2a4d31fd31fd31f02f823bbf263ed44d0d31fd31fd3ffd15132baf2a15144baf2a221db3cf26304f901541055f910f2a3f8009320d74a96d307d402fb00e83001a4c8cb1fcb1fcbffc9ed54080004d03002014806070017bb39ced44d0d33f31d70bff80011b8c97ed44d0d70b1f801d820abf78100ecbe8e1020ab0784efb084efba01807fb0c07fb0e08306b120843fb0208306bd218230b13802886d53fc85bdb00182304ec7fd7792ac03fabdb0923070e0208306ba2182e900000000000000000000000000000000000000000000000000000000000080bab12109009282f026e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85bab10182f0c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fabab107fcf873";
pub const V4R2_CODE_B64: &str = "te6cckECEQEAAloAART/APSkE/S88sgLAQIBIAIDAgFIBAUD+PKDCNcYINIf+DUSuvKk0x/TH9Mf0wcD+CO78mPtRNDTH9Mf0//0BDBRU7ryoVFhuvKiJds88mMG+QFUEHX5EPKj+AAgwACeApMg10qW0wfUAvsA6ALeIMABjhcC0gfT/1kByMoHy//J0MhAE4EBCPRBWN7AApEx4w0DpAMNDg8BnNAg10nBIJJfA+AB0NMDAXGwkl8D4PpAMAHTHwGCEHBsdWe9kl8D4O1E0NMf0x/T//QEMGwxIvpEAcjKB8v/ydABgQEI9ApvoTGSXwPjDQYCAUgHCABm0z/6ADD4J28iMFAEoSO+8uBQghDwbHVncIAYyMsFUATPFlAE+gISy2oSyx/LP8mAQPsAAgFYCQoAEbjJftRNDXCx+ABFsp37UTQ0x/TH9P/9AQwbDFZAcjKB8v/ydABgQEI9ApvoTGACASALDAAXrc52omhpn5jrhf/AABevHfaiaGmPmOuFj8AB2CCr94EA7L6OECCrB4TvsITvugGAf7DAf7DggwaxIIQ/sCCDBr0hgjCxOAKIbVP8hb2wAYIwTsf9d5KsA/q9sJIwcOAggwa6IYLpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgLqxIRAAKgHSB9P/MAHIygfL/8nQAYEBCPRZMAAcA8jLHxLLH8v/9ADJ7VQAkoLwJuiVj8KyJ7BFw/SJ8u+Y8NXfrAXTxjM5sTgCiG1T/IW6sQGC8McXanA9TdhPujwLdg0QZw8qIFP6LDnMxk7H/XeSrAP6urFdDUaB";
pub const V5R1_CODE_B64: &str = "te6cckECKAEACPMAART/APSkE/S88sgLAQIBIAIDAgFIBAUBJPIg1wsfghBzaWduuvLgin+K2B0CAssGBwIBIBMUArXQh0NMDAXGwkl8Dj00h10nBIJJfA+Ah1wsfIIIQQVVUSLqZMGwS+kAwAfAQ4DEgghBleHRuvSGCEHNpbnS9sJJfA+CCEGV4dG664wIxINdJgQKguZEw4HCK2OKCB0E99O1E0IBB1yHXC//tRNCBAUHXIfQEMSDXSpHUkm0B4tFUEyOBDhDbPCHAAY9NMds8INDXCwHAA46DAds8kTHif+1E0NIA0x+BASDXGPQEMASaIYQfuvLXEgGkAd4k0NcLAcIBlmwicG1BM94CyMoAyx8Bzxb0AMzJ7VTgM4JCg0LAZrtRNCBAUHXIfQEMSDXSpHUkm0B4tFu8ucPgCDXIQHQdNch+kAw+kT4KPpEMFi9kVvg7UTQgQFB1yH0BYMH9A5voTGRMOGAQNchcH/bPCEB9AQgbpUwcFRwAI4U0NMB0z/TP9P/0SPCACTBBLDy5w7iI8MA8ucIBiDXSYEBC7oh10rAALDy5xEg1wsCwATy5xH6RPgo+kRQM7pSE70SsPLnESa68ucIBNMfAYIQQVVUSLry5xPU9ATRIdDSH/g1Erry5wn6QPgoEscFDAHkASBulTBwVHAAjhTQ0wHTP9M/0//RI8IAJMEEsPLnDuJbAtDTAfpA0SHCACLBBLDy5w4CwgEhwAGw8tcOIoQ/uvLXEgKkcAIg10mBAQu6IddKwACw8ucRINcLAsAE8ucR+kT4KPpEUDO6UhO9ErDy5xESDwH8wADy5xMBfyHXOTBwlCHHALOOLQHXKCB2HkNsINdJwAjy4JMg10rAAvLgkyDXHQbHEsIAUjCw8tCJ10zXOTABpOhsEoQHu/Lgk9dKwADy4JMg0JQgxwCzjiHXKCB2HkNs0wchgCywwwDy1xMBgQDAsIEAwLry1xPUMNDoMAF/EgLs8ucK0z9RFLry5wvTP1EXuvLnDCaEP7ry1xLTHyH4I7z4I1ALoBK7GbDy5w0H0wfU0STAA46yJds8KG7y1xAI0CDXSYMIuiHXSsAAsPLnEAKCMFRPUy1BVVRIyMs/zMn5AEAF+RDy5xCXMjQGbvLnEOIDpEMDBA0OAfQghAewgH+wIasHhO+wIqv3AsB/AYTvurABgQDtvrDy1xAgg/e68tcQIILwxxdqcD1N2E+6PAt2DRBnDyogU/osOczGTsf9d5KsA3q68tcQIIMGuvLXECCC8CbolY/CsiewRcP0ifLvmPDV36wF08YzObE4AohtU/wFuhAAGgPIywESyz/LP8v/yQIAGAPIywESyz/LP8v/yQH+8tcQIILw7P///////////////////////////////////////3+68tcQIILwJuiVj8KyJ7BFw/SJ8u+Y8NXfrAXTxjM5sTgCiG1T/IW68tcQIMAA8tcQIILwxxdqcD1N2E+6PAt2DRBnDyogU/osOczGTsf9d5KsA/q68tcQIBEAloLpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgLry1xCC8Oz/////////////////////////////////////////uvLXEAB47UTQ0gDTH4EBINcY9AQwBJohhB+68tcSAaQB3iTQ1wsBwgGWbCJwbUEz3gLIygDLHwHPFvQAzMntVO1VAgEgFRYAGb5fD2omhAgKDrkPoCwCASAXGAIBSBscAG239d2omhAgKDrkPoCGJBrpUjqSTaA8WiQN0qYOCo4AEcKaGmA6Z/pn+n/6JHhABJgglh5c4dxQAgFYGRoAGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAv7tou377UTQgQFB1yH0BDEg10qR1JJtAeLRIG6RMJnQ1wsBwgHy1w/iIYMI1yICgwjXIyCAINch0h/4NRK68uCU0x/TH9Mf7UTQ0gDTHyDTH9P/1woAIds88tCHCvkBQMz5EJoolF8K2zHh8sCH3wKzUAew8tCEUSW68uCFUDa6Hh8B2CCr94EA7L6OECCrB4TvsITvugGAf7DAf7DggwaxIIQ/sCCDBr0hgjCxOAKIbVP8hb2wAYIwTsf9d5KsA/q9sJIwcOAggwa6IYLpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgLqxISABVvLghvgju/LQiCGEH7ry0IUikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zwhAJKC8CbolY/CsiewRcP0ifLvmPDV36wF08YzObE4AohtU/yFurEBgvDHF2pwPU3YT7o8C3YNEGcPKiBT+iw5zMZOx/13kqwD+rqxA/btou37AvQEIW6RMo5NUhMh1zkwcJQhxwCzji0B1yggdh5DbCDXScAI8uCTINdKwALy4JMg1x0GxxLCAFIwsPLQiddM1zkwAaTobBKEB7vy4JPXSsAA8uCT7VXiAdIAAcAAkl8D4CDXCwfABeMCMevXLAgUIJFw4w5SELEiIyQBTAFusxKx8tcTeNch0z/6QNHtRNCBAUHXIfQEMSDXSpHUkm0B4tFZJQAMAdcsCBwSAZCOOTDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4uMNINdKk1vbMeHXTNAnAeICIG6VMHBUcACOFNDTAdM/0z/T/9EjwgAkwQSw8ucO4lsBwgHy1w9muvLnCyCEP7ry1xJxAaRwAyDXSYEBC7oh10rAALDy5xEg1wsCwATy5xH6RPgo+kRQM7pSE70SsPLnEUEwA8jLARLLP8s/y//JcCYAdO1E0NIA0x+BASDXGPQEMASaIYQfuvLXEgGkAd4k0NcLAcIBlmwicG1BM94CyMoAyx8Bzxb0AMzJ7VQAmAH6QAH6RPgo+kQwWLry4JHtRNCBAUHXGPQEBZ1/yMoAQDODB/RT8uCLjhQSgwf0W/LgjCHXCgAhbgGzsPLQkOLIWM8W9ABYzxbJ7VSg8zus";

const SEND_MODE: u8 = 3;
const V4_OP_SIMPLE_SEND: u8 = 0;

pub struct WalletContract {
    signer: Box<dyn Signer>,
    subwallet_id: u32,
    provider: Arc<dyn ContractProvider>,
    address: MsgAddressInt,
    version: WalletVersion,
    /// Network identity (ConfigParam 19) bound into every signed body. The
    /// wallet code compares it with the GLOBALID opcode, so a body signed
    /// with the wrong value is rejected on-chain rather than replayed.
    global_id: i32,
}

impl WalletContract {
    const LIFETIME: u32 = 120; // 2 minutes
    const V5_PREFIX_SIGNED_EXTERNAL: u32 = 0x7369_676e;

    /// `global_id` must be the value the target chain publishes in
    /// ConfigParam 19; there is deliberately no default, because a wallet
    /// signing for the wrong network produces messages that either fail
    /// on-chain or, worse, are accepted by a different network.
    pub async fn new(
        signer: Box<dyn Signer>,
        version: WalletVersion,
        subwallet_id: u32,
        workchain_id: i32,
        global_id: i32,
        provider: Arc<dyn ContractProvider>,
    ) -> anyhow::Result<Self> {
        let address = WalletContract::calculate_address(
            version,
            workchain_id,
            subwallet_id,
            &signer.public_key().await?,
        )?;
        Ok(Self { signer, address, subwallet_id, provider, version, global_id })
    }

    pub fn global_id(&self) -> i32 {
        self.global_id
    }

    pub fn calculate_address(
        version: WalletVersion,
        wc: i32,
        subwallet_id: u32,
        public_key: &[u8],
    ) -> anyhow::Result<MsgAddressInt> {
        let wallet_id = subwallet_id;
        match version {
            WalletVersion::V1R3 => {
                let v1r3_code = read_single_root_boc(
                    hex::decode(V1R3_CODE).expect("V1R3 code hex is invalid"),
                )?;
                let mut b = BuilderData::new();
                b.append_u32(0)?.append_raw(public_key, 256)?;
                let state = StateInit::with_code_and_data(v1r3_code, b.into_cell()?);
                let state_hash = state.write_to_new_cell()?.into_cell()?.hash(0);
                Ok(MsgAddressInt::with_params(wc, state_hash.as_slice())?)
            }
            WalletVersion::V3R2 => {
                let v3r2_code = read_single_root_boc(
                    hex::decode(V3R2_CODE).expect("V3R2 code hex is invalid"),
                )?;
                let mut b = BuilderData::new();
                b.append_u32(0)?.append_u32(wallet_id)?.append_raw(public_key, 256)?;
                let state = StateInit::with_code_and_data(v3r2_code, b.into_cell()?);
                let state_hash = state.write_to_new_cell()?.into_cell()?.hash(0);
                Ok(MsgAddressInt::with_params(wc, state_hash.as_slice())?)
            }
            WalletVersion::V4R2 => {
                let v4r2_code = read_single_root_boc(base64_decode(V4R2_CODE_B64)?)?;
                let mut b = BuilderData::new();
                b.append_u32(0)?.append_u32(wallet_id)?.append_raw(public_key, 256)?;
                b.append_bit_zero()?;
                let state = StateInit::with_code_and_data(v4r2_code, b.into_cell()?);
                let state_hash = state.write_to_new_cell()?.into_cell()?.hash(0);
                Ok(MsgAddressInt::with_params(wc, state_hash.as_slice())?)
            }
            WalletVersion::V5R1 => {
                let v5r1_code = read_single_root_boc(base64_decode(V5R1_CODE_B64)?)?;
                let mut b = BuilderData::new();
                b.append_bit_one()?;
                b.append_u32(0)?.append_u32(wallet_id)?.append_raw(public_key, 256)?;
                b.append_bit_zero()?;
                let state = StateInit::with_code_and_data(v5r1_code, b.into_cell()?);
                let state_hash = state.write_to_new_cell()?.into_cell()?.hash(0);
                Ok(MsgAddressInt::with_params(wc, state_hash.as_slice())?)
            }
        }
    }

    fn signing_body(
        &self,
        seqno: u32,
        dest: MsgAddressInt,
        value: u64,
        payload: Cell,
        bounce: bool,
        state_init: Option<StateInit>,
    ) -> anyhow::Result<Cell> {
        match self.version {
            WalletVersion::V1R3 | WalletVersion::V3R2 | WalletVersion::V4R2 => {
                let header = InternalMessageHeader {
                    bounce,
                    dst: dest,
                    value: CurrencyCollection::with_coins(value),
                    ..Default::default()
                };
                let mut internal_message =
                    Message::with_int_header_and_body(header, SliceData::load_cell(payload)?);

                if let Some(state) = state_init {
                    internal_message.set_state_init(state);
                }

                let message_cell = internal_message.serialize_as_is()?.0.into_cell()?;
                const SEND_MODE: u8 = 1 + 2; // pay fees separately + ignore errors
                let expire = time_format::now() as u32 + Self::LIFETIME;
                let mut builder = BuilderData::new();
                match self.version {
                    WalletVersion::V1R3 => {
                        // V1R3 body layout: seqno(32) + mode(8) + [ref: msg]
                        builder
                            .append_u32(seqno)
                            .and_then(|b| b.append_u8(SEND_MODE))
                            .and_then(|b| b.checked_append_reference(message_cell))?;
                    }
                    WalletVersion::V3R2 => {
                        // V3R2 body layout: global_id(int32) + subwallet_id(32) + expire(32)
                        // + seqno(32) + mode(8) + [ref: msg]
                        builder
                            .append_i32(self.global_id)
                            .and_then(|b| b.append_u32(self.subwallet_id))
                            .and_then(|b| b.append_u32(expire))
                            .and_then(|b| b.append_u32(seqno))
                            .and_then(|b| b.append_u8(SEND_MODE))
                            .and_then(|b| b.checked_append_reference(message_cell))?;
                    }
                    WalletVersion::V4R2 => {
                        // V4R2 body layout: global_id(int32) + subwallet_id(32) + expire(32)
                        // + seqno(32) + op(8) + mode(8) + [ref: msg]
                        builder
                            .append_i32(self.global_id)
                            .and_then(|b| b.append_u32(self.subwallet_id))
                            .and_then(|b| b.append_u32(expire))
                            .and_then(|b| b.append_u32(seqno))
                            .and_then(|b| b.append_u8(V4_OP_SIMPLE_SEND)) // wallet-v4 simple transfer opcode
                            .and_then(|b| b.checked_append_reference(message_cell))
                            .and_then(|b| b.append_u8(SEND_MODE))?;
                    }
                    _ => anyhow::bail!("unreachable wallet version"),
                };
                builder.into_cell()
            }
            WalletVersion::V5R1 => {
                let actions =
                    Self::build_v5_single_send_actions(dest, value, payload, bounce, state_init)?;
                self.signing_body_v5(seqno, actions)
            }
        }
    }

    fn signing_body_v5(&self, seqno: u32, actions: Cell) -> anyhow::Result<Cell> {
        let wallet_id = self.subwallet_id;
        let mut builder = BuilderData::new();
        // V5R1 signed layout: prefix(32) + global_id(int32) + wallet_id(32)
        // + valid_until(32) + seqno(32) + actions
        builder
            .append_u32(Self::V5_PREFIX_SIGNED_EXTERNAL)?
            .append_i32(self.global_id)?
            .append_u32(wallet_id)?
            .append_u32(time_format::now() as u32 + Self::LIFETIME)?
            .append_u32(seqno)?
            .append_bit_one()? // has_actions = true
            .checked_append_reference(actions)?
            .append_bit_zero()?; // has_other_actions = false
        builder.into_cell()
    }

    async fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.signer.sign(message).await
    }

    fn build_v5_single_send_actions(
        dest: MsgAddressInt,
        value: u64,
        payload: Cell,
        bounce: bool,
        state_init: Option<StateInit>,
    ) -> anyhow::Result<Cell> {
        let header = InternalMessageHeader {
            bounce,
            dst: dest,
            value: CurrencyCollection::with_coins(value),
            ..Default::default()
        };
        let mut internal_message =
            Message::with_int_header_and_body(header, SliceData::load_cell(payload)?);
        if let Some(state) = state_init {
            internal_message.set_state_init(state);
        }

        let mut actions = OutActions::new();
        actions.push_back(OutAction::new_send(SEND_MODE, internal_message));
        let mut actions_builder = BuilderData::new();
        actions.write_to(&mut actions_builder)?;
        actions_builder.into_cell()
    }

    async fn build_state_init(&self) -> anyhow::Result<StateInit> {
        let pub_key = self.signer.public_key().await?;
        let wallet_id = self.subwallet_id;

        match self.version {
            WalletVersion::V1R3 => {
                let mut builder = BuilderData::new();
                builder.append_u32(0)?; // 32 bits: seqno = 0
                builder.append_raw(&pub_key, 256)?;
                let initial_data = builder.into_cell()?;
                let v1r3_code = read_single_root_boc(
                    hex::decode(V1R3_CODE).expect("V1R3 code hex is invalid"),
                )?;
                Ok(StateInit::with_code_and_data(v1r3_code, initial_data))
            }
            WalletVersion::V3R2 => {
                let mut builder = BuilderData::new();
                builder.append_u32(0)?; // seqno = 0
                builder.append_u32(wallet_id)?;
                builder.append_raw(&pub_key, 256)?;
                let initial_data = builder.into_cell()?;

                let v3r2_code = read_single_root_boc(
                    hex::decode(V3R2_CODE).expect("V3R2 code hex is invalid"),
                )?;

                Ok(StateInit::with_code_and_data(v3r2_code, initial_data))
            }
            WalletVersion::V4R2 => {
                let bytes = base64_decode(V4R2_CODE_B64)?;
                let v4r2_code = read_single_root_boc(bytes)?;
                let mut b = BuilderData::new();
                b.append_u32(0)?.append_u32(wallet_id)?.append_raw(&pub_key, 256)?;
                b.append_bit_zero()?; // empty plugins dict
                Ok(StateInit::with_code_and_data(v4r2_code, b.into_cell()?))
            }
            WalletVersion::V5R1 => {
                let bytes = base64_decode(V5R1_CODE_B64)?;
                let v5r1_code = read_single_root_boc(bytes)?;
                let mut b = BuilderData::new();
                b.append_bit_one()?; // is_signature_allowed = true
                b.append_u32(0)?.append_u32(wallet_id)?.append_raw(&pub_key, 256)?;
                b.append_bit_zero()?; // empty extensions dict
                Ok(StateInit::with_code_and_data(v5r1_code, b.into_cell()?))
            }
        }
    }
}

impl WalletContract {
    pub async fn seqno(&self) -> anyhow::Result<u32> {
        let stack = self.provider.get_method(self.address.to_string(), "seqno", vec![]).await?;
        stack.i64(0).map(|s| s as u32).map_err(|e| anyhow::anyhow!("seqno error: {}", e))
    }
}

#[async_trait::async_trait]
impl Wallet for WalletContract {
    async fn message(
        &self,
        dest: MsgAddressInt,
        value: u64,
        payload: Cell,
    ) -> anyhow::Result<Cell> {
        self.build_message(dest, value, payload, true, None, None, None).await
    }

    async fn deploy_message(&self, value: u64, payload: Cell) -> anyhow::Result<Cell> {
        let state_init = self.build_state_init().await?;
        self.build_message(self.address(), value, payload, false, Some(0), Some(state_init), None)
            .await
    }

    async fn state_init(&self) -> anyhow::Result<StateInit> {
        self.build_state_init().await
    }

    async fn build_message(
        &self,
        dest: MsgAddressInt,
        value: u64,
        payload: Cell,
        bounce: bool,
        seqno: Option<u32>,
        state_init_external: Option<StateInit>,
        state_init_internal: Option<StateInit>,
    ) -> anyhow::Result<Cell> {
        let seqno = match seqno {
            Some(seqno) => seqno,
            None => self.seqno().await.map_err(|e| anyhow::anyhow!("get seqno error: {}", e))?,
        };

        let body_slice = match self.version {
            WalletVersion::V5R1 => {
                // V5: signature at end, uses OutActions
                let actions_cell = Self::build_v5_single_send_actions(
                    dest,
                    value,
                    payload,
                    bounce,
                    state_init_internal,
                )?;

                let signing_cell = self.signing_body_v5(seqno, actions_cell)?;
                let signature = self.sign(signing_cell.hash(0).as_slice()).await?;

                // V5: body first, then signature
                let mut builder = BuilderData::from_cell(&signing_cell)?;
                builder.append_raw(&signature, 512)?;
                SliceData::load_builder(builder)?
            }
            WalletVersion::V1R3 | WalletVersion::V3R2 | WalletVersion::V4R2 => {
                // signature first, then body
                let signing_cell =
                    self.signing_body(seqno, dest, value, payload, bounce, state_init_internal)?;
                let signature = self.sign(signing_cell.hash(0).as_slice()).await?;

                let mut builder = BuilderData::new();
                builder.append_raw(&signature, 512)?;
                builder.append_builder(&BuilderData::from_cell(&signing_cell)?)?;
                SliceData::load_builder(builder)?
            }
        };

        let mut message = Message::with_ext_in_header_and_body(
            ExternalInboundMessageHeader::new(MsgAddressExt::AddrNone, self.address()),
            body_slice,
        );

        if let Some(state) = state_init_external {
            message.set_state_init(state);
        }

        let (builder, _, _) = message
            .serialize_as_is()
            .map_err(|e| anyhow::anyhow!("external message serialization error: {:?}", e))?;

        builder.into_cell()
    }
}

#[async_trait::async_trait]
impl SmartContract for WalletContract {
    fn address(&self) -> MsgAddressInt {
        self.address.clone()
    }
    async fn balance(&self) -> anyhow::Result<u64> {
        self.provider.balance(&self.address).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Pins the embedded wallet code to the hashes of the network-bound
    /// contracts compiled from crypto/smartcont. The node's account
    /// recognition table carries the same values.
    #[test]
    fn test_wallet_code_hashes() {
        let v1r3 = read_single_root_boc(hex::decode(V1R3_CODE).unwrap()).unwrap();
        let v3r2 = read_single_root_boc(hex::decode(V3R2_CODE).unwrap()).unwrap();
        let v4r2 = read_single_root_boc(base64_decode(V4R2_CODE_B64).unwrap()).unwrap();
        let v5r1 = read_single_root_boc(base64_decode(V5R1_CODE_B64).unwrap()).unwrap();

        assert_eq!(
            format!("{:x}", v1r3.repr_hash()),
            "587cc789eff1c84f46ec3797e45fc809a14ff5ae24f1e0c7a6a99cc9dc9061ff"
        );
        assert_eq!(
            format!("{:x}", v3r2.repr_hash()),
            "5829bd66ea5884eef70788d0609acad76af5c418aed2fc17709def2224cf9164"
        );
        assert_eq!(
            format!("{:x}", v4r2.repr_hash()),
            "056032cd4c32691b32eb043baa4495e6225590597ca458641975a7ed9de2bd6d"
        );
        assert_eq!(
            format!("{:x}", v5r1.repr_hash()),
            "76e73ca966098806708d7fcf977f61ee65cc9a55dca2a1723753f37b1117f3a7"
        );
    }

    /// Pins address derivation for a fixed key: the address depends only on
    /// code and initial data, not on global_id, so it is stable across
    /// networks while signed messages are not.
    #[test]
    fn test_address_calculation() {
        let public_key =
            hex::decode("72c9ed6b62a6e2eba14a93b90462e7a367777beb8a38fb15b9f33844d22ce2ff")
                .unwrap();

        let v3r2 =
            WalletContract::calculate_address(WalletVersion::V3R2, 0, 698983191, &public_key)
                .unwrap();
        assert_eq!(
            v3r2,
            MsgAddressInt::from_str(
                "0:0c8f77db9d7cb91eb5ae3654c45a34b47b01db344ef001ac632c2b9b6e79d8c9"
            )
            .unwrap()
        );

        let v4r2 =
            WalletContract::calculate_address(WalletVersion::V4R2, 0, 698983191, &public_key)
                .unwrap();
        assert_eq!(
            v4r2,
            MsgAddressInt::from_str(
                "0:9f108b7f52928a8ccee2461d51428bdf7b595feebaf9bfac528053555fef2c9c"
            )
            .unwrap()
        );

        let v5r1 =
            WalletContract::calculate_address(WalletVersion::V5R1, 0, 698983191, &public_key)
                .unwrap();
        assert_eq!(
            v5r1,
            MsgAddressInt::from_str(
                "0:35c5bb64e0a320beced9c33371eb26ccf1522cac89378eae6d1997333dec329e"
            )
            .unwrap()
        );
    }
}
