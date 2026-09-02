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
pub const V3R2_CODE: &str = "b5ee9c7241010801008e000114ff00f4a413f4bcf2c80b010201200203020148040500a6f28308d71820d21ff83512baf2a4d31fd31fd31f02f823bbf263ed44d0d31fd31fd3ffd15132baf2a15144baf2a204f901541055f910f2a3f8009320d74a96d307d402fb00e83001a4c8cb1fcb1fcbffc9ed540004d03002014806070017bb39ced44d0d33f31d70bff80011b8c97ed44d0d70b1f82805832c";
pub const V4R2_CODE_B64: &str = "te6cckECDwEAAZoAART/APSkE/S88sgLAQIBIAIDAgFIBAUC7vKDCNcYINIf+DUSuvKk0x/TH9\
    Mf0wcD+CO78mPtRNDTH9Mf0//0BDBRU7ryoVFhuvKiBvkBVBB1+RDyo/gAIMAAngKTINdKltMH1\
    AL7AOgC3iDAAY4XAtIH0/9ZAcjKB8v/ydDIQBOBAQj0QVjewAKRMeMNA6QDDQ4BnNAg10nBIJJf\
    A+AB0NMDAXGwkl8D4PpAMAHTHwGCEHBsdWe9kl8D4O1E0NMf0x/T//QEMGwxIvpEAcjKB8v/ydA\
    BgQEI9ApvoTGSXwPjDQYCAUgHCABm0z/6ADD4J28iMFAEoSO+8uBQghDwbHVncIAYyMsFUATPFl\
    AE+gISy2oSyx/LP8mAQPsAAgFYCQoAEbjJftRNDXCx+ABFsp37UTQ0x/TH9P/9AQwbDFZAcjKB8\
    v/ydABgQEI9ApvoTGACASALDAAXrc52omhpn5jrhf/AABevHfaiaGmPmOuFj8AAKgHSB9P/MAHI\
    ygfL/8nQAYEBCPRZMAAcA8jLHxLLH8v/9ADJ7VSSOBf9";
pub const V5R1_CODE_B64: &str = "te6cckECFAEAAo4AART/APSkE/S88sgLAQIBIAIDAgFIBAUBJPIg1wsfghBzaWduuvLgin/bPA\
    4C4NAg10nBIJFbj2Ug1wsfIIIQZXh0br0hghBzaW50vbCSXwPgghBleHRuuo60gCDXIQHQdNch+\
    kAw+kT4KPpEMFi9kVvg7UTQgQFB1yH0BYMH9A5voTGRMOGAQNchcH/bPOAxINdJgQKguZEw4HDb\
    POIPDgIBIAYHAgEgCAkAGb5fD2omhAgKDrkPoCwCAW4KCwIBSAwNABmtznaiaEAg65Drhf/AABm\
    vHfaiaEAQ65DrhY/AABezJftRNBx1yHXCx+AAEbJi+1E0NcKAIAL2jvntou37IYMI1yICgwjXIy\
    CAINch0h/4NRK68uCU0x/TH9Mf7UTQ0gDTHyDTH9P/1woACvkBQMz5EJoolF8K2zHh8sCH3wKzU\
    Aew8tCEUSW68uCFUDa68uCG+CO78tCIIpL4AN4BpH/IygDLHwHPFsntVCCS+A/ecNs8DxAD9u2i\
    7fsC9AQhbpJsIY5MAiHXOTBwlCHHALOOLQHXKCB2HkNsINdJwAjy4JMg10rAAvLgkyDXHQbHEsI\
    AUjCw8tCJ10zXOTABpOhsEoQHu/Lgk9dKwADy4JPtVeLSAAHAAJFb4OvXLAgUIJFwlgHXLAgcEu\
    JSELHjDyDXShESEwAC2ACWAfpAAfpE+Cj6RDBYuvLgke1E0IEBQdcY9AUEnX/IygBABIMH9FPy4\
    IuOFAODB/Rb8uCMItcKACFuAbOw8tCQ4shQA88WEvQAye1UAHIw1ywIJI4tIfLgktIA7UTQ0gBR\
    E7ry0I9UUDCRMZwBgQFA1yHXCgDy4I7iyMoAWM8Wye1Uk/LAjeIAEJNb2zHh10zQNLcyQw==";

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
        let v3r2 = read_single_root_boc(hex::decode(V3R2_CODE).unwrap()).unwrap();
        let v4r2 = read_single_root_boc(base64_decode(V4R2_CODE_B64).unwrap()).unwrap();
        let v5r1 = read_single_root_boc(base64_decode(V5R1_CODE_B64).unwrap()).unwrap();

        assert_eq!(
            format!("{:x}", v3r2.repr_hash()),
            "6c6caaf194af3660e7ae4c584785c1bda0d85fafd80e947d725105947cd11d7d"
        );
        assert_eq!(
            format!("{:x}", v4r2.repr_hash()),
            "f15bc24cbc229a1b72cab39345db191e761ef913e6d066e76d3836cf1600cb47"
        );
        assert_eq!(
            format!("{:x}", v5r1.repr_hash()),
            "e6c006f19fbabccd0d4852c1cc4ca3c6410914dc86f6611ccf8165cdcaafc6e0"
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
                "0:771555ef9b48db2f8c269ab3ad2d30b36360681f4dc1fefc03142564813fae8f"
            )
            .unwrap()
        );

        let v4r2 =
            WalletContract::calculate_address(WalletVersion::V4R2, 0, 698983191, &public_key)
                .unwrap();
        assert_eq!(
            v4r2,
            MsgAddressInt::from_str(
                "0:89664bd10cff3d946e3a54f6319542488740eda2102fd1173e83b716d1c75c9d"
            )
            .unwrap()
        );

        let v5r1 =
            WalletContract::calculate_address(WalletVersion::V5R1, 0, 698983191, &public_key)
                .unwrap();
        assert_eq!(
            v5r1,
            MsgAddressInt::from_str(
                "0:008d8e5221f7983fca6259ad68388e9201672254ac8944d35d8a616c1863aa3d"
            )
            .unwrap()
        );
    }
}
