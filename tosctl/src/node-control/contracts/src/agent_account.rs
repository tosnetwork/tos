/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use chain_block::{
    base64_decode, read_single_root_boc, BuilderData, Coins, Deserializable,
    ExternalInboundMessageHeader, IBitstring, Message, MsgAddressExt, MsgAddressInt, Serializable,
    SliceData, StateInit,
};

use crate::ContractProvider;

pub const AGENT_ACCOUNT_CODE_B64: &str = "te6ccgECEAEAA0wAART/APSkE/S88sgLAQIBIAIDAgFIBAUB+PKDCNcY7UTQ+kDT/9Mf0x/6ANTR0PoA+gDTP38B0wABkzHT/95/AdMAAZMx0//e0VUkKvkBVBDJ+RDy5qgJ0x8BghBBR1ADuvLmp9Mf0x9RI7ry5qn4I7zy5qr6QPoA1NFTGLvy5qv4I4IBUYCpBFMMvZM8cD2RMOJTwaAPArbQMiHHAJFb4NDTAzH6QDDtRND6QNP/0x/TH/oA1NHQ+gD6ANM/fwHTAAGTMdP/3n8B0wABkzHT/97RVSQL0x/TPzEhghBBR1ABuuMCOYIQQUdQArrjAl8L8sanBgcCASAJCgFuMWwzMzNRVMcF8uam+gD6ANM/INMAAZPT/zCSMH/iIdMAAZPT/zCSMH/iAtH4ABB5EGgQZxBWAQgAzFGYxwXy5qYG0//R+AAQeQgGB1VAJMEA8talUzS58talIsEB8talyFAF+gJQA/oCyz8hwQCUcDLLAJZxAcsAy//iIcEAlHAyywCWcQHLAMv/4snIUAbPFhTL/xLLH8sfAfoCzMntVACkJMEA8talUzS58talIsEB8talyFAF+gJQA/oCyz8hwQCUcDLLAJZxAcsAy//iIcEAlHAyywCWcQHLAMv/4snIUAbPFhTL/xLLH8sfAfoCzMntVAIBSAsMAgEgDQ4AZ7YlvaiaH0gaf/pj+mP/QBqaOh9AH0AaZ+/gOmAAMmY6f/vP4DpgADJmOn/72iqki+BthLAAY7c0vaiaH0gaf/pj+mP/QBqaOh9AH0AaZ+/gOmAAMmY6f/vP4DpgADJmOn/72iqki+EwAF+5rr7UTQ+kDT/9Mf0x/6ANTR0PoA+gDTP38B0wABkzHT/95/AdMAAZMx0//e0VUkgAZ7nk/tRND6QNP/0x/TH/oA1NHQ+gD6ANM/fwHTAAGTMdP/3n8B0wABkzHT/97RVSQQiV8JgA/Ci78uar+ABxcIAQyMsFUAXPFiP6AhTLaRPLABLMyXH7AAGkUKqgEHkQaFVAJMEA8talUzS58talIsEB8talyFAF+gJQA/oCyz8hwQCUcDLLAJZxAcsAy//iIcEAlHAyywCWcQHLAMv/4snIUAbPFhTL/xLLH8sfAfoCzMntVA==";

pub const AGENT_UPDATE_POLICY_OPCODE: u32 = 0x4147_5001;
pub const AGENT_ROTATE_CONTROLLER_OPCODE: u32 = 0x4147_5002;
pub const AGENT_TASK_SEND_OPCODE: u32 = 0x4147_5003;

#[derive(Clone, Debug)]
pub struct AgentAccountInit {
    pub owner: MsgAddressInt,
    pub controller_pubkey: [u8; 32],
    pub max_per_tx: u64,
    pub daily_limit: u64,
    pub default_task_timeout_secs: u64,
    pub metadata_hash: Option<[u8; 32]>,
    pub service_endpoint_hash: Option<[u8; 32]>,
}

pub struct AgentAccountContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAccountData {
    pub owner: MsgAddressInt,
    pub controller_pubkey: [u8; 32],
    pub seqno: u32,
    pub spend_day: u32,
    pub spent_today: u64,
    pub max_per_tx: u64,
    pub daily_limit: u64,
    pub default_task_timeout_secs: u64,
    pub metadata_hash: Option<[u8; 32]>,
    pub service_endpoint_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAccountPolicyUpdate {
    pub max_per_tx: u64,
    pub daily_limit: u64,
    pub default_task_timeout_secs: u64,
    pub metadata_hash: Option<[u8; 32]>,
    pub service_endpoint_hash: Option<[u8; 32]>,
}

impl AgentAccountContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(AGENT_ACCOUNT_CODE_B64)?).map_err(Into::into)
    }

    pub fn build_data(init: &AgentAccountInit) -> anyhow::Result<chain_block::Cell> {
        validate_policy(init.max_per_tx, init.daily_limit, init.default_task_timeout_secs)?;

        let mut policy = BuilderData::new();
        Coins::new(init.max_per_tx).write_to(&mut policy)?;
        Coins::new(init.daily_limit).write_to(&mut policy)?;
        policy.append_u64(init.default_task_timeout_secs)?;
        append_maybe_hash(&mut policy, init.metadata_hash)?;
        append_maybe_hash(&mut policy, init.service_endpoint_hash)?;

        let mut data = BuilderData::new();
        init.owner.write_to(&mut data)?;
        data.append_raw(&init.controller_pubkey, 256)?;
        data.append_u32(0)?;
        data.append_u32(0)?;
        Coins::new(0).write_to(&mut data)?;
        data.checked_append_reference(policy.into_cell()?)?;
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &AgentAccountInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(wc: i32, init: &AgentAccountInit) -> anyhow::Result<MsgAddressInt> {
        let state_cell = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(wc, state_cell.hash(0))?)
    }

    pub async fn get_data(
        provider: &dyn ContractProvider,
        address: &MsgAddressInt,
    ) -> anyhow::Result<AgentAccountData> {
        let stack =
            provider.get_method(address.to_string(), "get_agent_account_data", vec![]).await?;
        Self::decode_data(&stack)
    }

    /// Decode `get_agent_account_data`; transport concerns stay outside this module.
    pub fn decode_data(
        stack: &common::tvm_stack_parser::TvmStackParser,
    ) -> anyhow::Result<AgentAccountData> {
        let mut owner_slice = stack.slice(0)?;
        let owner = MsgAddressInt::construct_from(&mut owner_slice)?;

        Ok(AgentAccountData {
            owner,
            controller_pubkey: parse_hash(&stack, 1)?,
            max_per_tx: stack.u64(2)?,
            daily_limit: stack.u64(3)?,
            default_task_timeout_secs: stack.u64(4)?,
            metadata_hash: parse_maybe_hash(&stack, 5)?,
            service_endpoint_hash: parse_maybe_hash(&stack, 6)?,
            seqno: stack.u64(7)? as u32,
            spend_day: stack.u64(8)? as u32,
            spent_today: stack.u64(9)?,
        })
    }

    pub fn build_update_policy_message(
        query_id: u64,
        policy: &AgentAccountPolicyUpdate,
    ) -> anyhow::Result<chain_block::Cell> {
        validate_policy(policy.max_per_tx, policy.daily_limit, policy.default_task_timeout_secs)?;
        let mut body = BuilderData::new();
        body.append_u32(AGENT_UPDATE_POLICY_OPCODE)?.append_u64(query_id)?;
        Coins::new(policy.max_per_tx).write_to(&mut body)?;
        Coins::new(policy.daily_limit).write_to(&mut body)?;
        body.append_u64(policy.default_task_timeout_secs)?;
        append_maybe_hash(&mut body, policy.metadata_hash)?;
        append_maybe_hash(&mut body, policy.service_endpoint_hash)?;
        Ok(body.into_cell()?)
    }

    pub fn build_rotate_controller_message(
        query_id: u64,
        controller_pubkey: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        let mut body = BuilderData::new();
        body.append_u32(AGENT_ROTATE_CONTROLLER_OPCODE)?
            .append_u64(query_id)?
            .append_raw(&controller_pubkey, 256)?;
        Ok(body.into_cell()?)
    }

    /// Build the controller-signed payload. The controller signs the cell hash
    /// returned by this method; `build_signed_task_send_message` prepends the
    /// resulting 512-bit signature for external delivery.
    pub fn build_task_send_payload(
        seqno: u32,
        valid_until: u32,
        target: &MsgAddressInt,
        value: u64,
        body: chain_block::Cell,
    ) -> anyhow::Result<chain_block::Cell> {
        let mut payload = BuilderData::new();
        payload.append_u32(AGENT_TASK_SEND_OPCODE)?.append_u32(seqno)?.append_u32(valid_until)?;
        target.write_to(&mut payload)?;
        Coins::new(value).write_to(&mut payload)?;
        payload.checked_append_reference(body)?;
        Ok(payload.into_cell()?)
    }

    pub fn build_signed_task_send_message(
        payload: chain_block::Cell,
        signature: &[u8; 64],
    ) -> anyhow::Result<chain_block::Cell> {
        let mut message = BuilderData::new();
        message.append_raw(signature, 512)?;
        message.append_builder(&BuilderData::from_cell(&payload)?)?;
        Ok(message.into_cell()?)
    }

    pub fn build_external_task_send_message(
        account: MsgAddressInt,
        signed_body: chain_block::Cell,
    ) -> anyhow::Result<chain_block::Cell> {
        let body = SliceData::load_cell(signed_body)?;
        let message = Message::with_ext_in_header_and_body(
            ExternalInboundMessageHeader::new(MsgAddressExt::AddrNone, account),
            body,
        );
        let (builder, _, _) = message
            .serialize_as_is()
            .map_err(|e| anyhow::anyhow!("external message serialization error: {:?}", e))?;
        Ok(builder.into_cell()?)
    }
}

fn validate_policy(
    max_per_tx: u64,
    daily_limit: u64,
    default_task_timeout_secs: u64,
) -> anyhow::Result<()> {
    if daily_limit < max_per_tx {
        anyhow::bail!("daily_limit must be greater than or equal to max_per_tx");
    }
    if default_task_timeout_secs == 0 {
        anyhow::bail!("default_task_timeout_secs must be greater than zero");
    }
    Ok(())
}

fn parse_hash(
    stack: &common::tvm_stack_parser::TvmStackParser,
    index: usize,
) -> anyhow::Result<[u8; 32]> {
    stack
        .number_bytes(index, 32)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stack entry {} is not a 256-bit value", index))
}

fn parse_maybe_hash(
    stack: &common::tvm_stack_parser::TvmStackParser,
    index: usize,
) -> anyhow::Result<Option<[u8; 32]>> {
    if stack.decimal_string(index)? == "-1" {
        return Ok(None);
    }
    Ok(Some(parse_hash(stack, index)?))
}

fn append_maybe_hash(builder: &mut BuilderData, hash: Option<[u8; 32]>) -> anyhow::Result<()> {
    if let Some(hash) = hash {
        builder.append_bit_one()?.append_raw(&hash, 256)?;
    } else {
        builder.append_bit_zero()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::tvm_stack_parser::TvmStackParser;
    use tl_api::tos::tvm::{
        numberdecimal::NumberDecimal,
        slice,
        stackentry::{StackEntryNumber, StackEntrySlice},
        Number, StackEntry,
    };

    struct MockProvider {
        stack: Vec<StackEntry>,
    }

    #[async_trait::async_trait]
    impl ContractProvider for MockProvider {
        async fn get_method(
            &self,
            _address: String,
            method: &str,
            args: Vec<StackEntry>,
        ) -> anyhow::Result<TvmStackParser> {
            assert_eq!(method, "get_agent_account_data");
            assert!(args.is_empty());
            Ok(TvmStackParser::new(self.stack.clone()))
        }

        async fn balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
            Ok(0)
        }
    }

    fn number(value: impl Into<String>) -> StackEntry {
        StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
            number: Number::Tvm_NumberDecimal(NumberDecimal { number: value.into() }),
        })
    }

    fn hash_number(value: [u8; 32]) -> StackEntry {
        number(format!("0x{}", hex::encode(value)))
    }

    fn valid_init() -> AgentAccountInit {
        AgentAccountInit {
            owner: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap(),
            controller_pubkey: [0x22; 32],
            max_per_tx: 500_000_000,
            daily_limit: 5_000_000_000,
            default_task_timeout_secs: 3_600,
            metadata_hash: Some([0x33; 32]),
            service_endpoint_hash: Some([0x44; 32]),
        }
    }

    #[test]
    fn state_init_and_address_are_deterministic() {
        let init = valid_init();
        let first_state = AgentAccountContract::build_state_init(&init).unwrap();
        let second_state = AgentAccountContract::build_state_init(&init).unwrap();
        let first_cell = first_state.write_to_new_cell().unwrap().into_cell().unwrap();
        let second_cell = second_state.write_to_new_cell().unwrap().into_cell().unwrap();

        assert_eq!(first_cell.hash(0), second_cell.hash(0));
        assert_eq!(
            AgentAccountContract::calculate_address(-1, &init).unwrap(),
            AgentAccountContract::calculate_address(-1, &init).unwrap()
        );
        assert_eq!(AgentAccountContract::build_data(&init).unwrap().references_count(), 1);
    }

    #[test]
    fn rejects_daily_limit_below_per_action_limit() {
        let mut init = valid_init();
        init.daily_limit = init.max_per_tx - 1;

        let error = AgentAccountContract::build_data(&init).unwrap_err();
        assert!(error.to_string().contains("daily_limit"));
    }

    #[test]
    fn rejects_zero_task_timeout() {
        let mut init = valid_init();
        init.default_task_timeout_secs = 0;

        let error = AgentAccountContract::build_data(&init).unwrap_err();
        assert!(error.to_string().contains("default_task_timeout_secs"));
    }

    #[tokio::test]
    async fn decodes_agent_account_get_method() {
        let init = valid_init();
        let owner_cell = init.owner.write_to_new_cell().unwrap().into_cell().unwrap();
        let owner_bytes = chain_block::SliceData::load_cell(owner_cell).unwrap().get_bytestring(0);
        let provider = MockProvider {
            stack: vec![
                StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
                    slice: slice::Slice { bytes: owner_bytes },
                }),
                hash_number(init.controller_pubkey),
                number(init.max_per_tx.to_string()),
                number(init.daily_limit.to_string()),
                number(init.default_task_timeout_secs.to_string()),
                hash_number(init.metadata_hash.unwrap()),
                number("-1"),
                number("17"),
                number("20"),
                number("123456789"),
            ],
        };

        let data = AgentAccountContract::get_data(&provider, &init.owner).await.unwrap();

        assert_eq!(data.owner, init.owner);
        assert_eq!(data.controller_pubkey, init.controller_pubkey);
        assert_eq!(data.seqno, 17);
        assert_eq!(data.spend_day, 20);
        assert_eq!(data.spent_today, 123_456_789);
        assert_eq!(data.max_per_tx, init.max_per_tx);
        assert_eq!(data.daily_limit, init.daily_limit);
        assert_eq!(data.default_task_timeout_secs, init.default_task_timeout_secs);
        assert_eq!(data.metadata_hash, init.metadata_hash);
        assert_eq!(data.service_endpoint_hash, None);
    }

    #[test]
    fn builds_update_policy_message() {
        let policy = AgentAccountPolicyUpdate {
            max_per_tx: 700_000_000,
            daily_limit: 9_000_000_000,
            default_task_timeout_secs: 7_200,
            metadata_hash: Some([0x55; 32]),
            service_endpoint_hash: None,
        };
        let body = AgentAccountContract::build_update_policy_message(42, &policy).unwrap();
        let mut slice = chain_block::SliceData::load_cell(body).unwrap();

        assert_eq!(slice.get_next_u32().unwrap(), AGENT_UPDATE_POLICY_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 42);
        assert_eq!(Coins::construct_from(&mut slice).unwrap().as_u128(), 700_000_000);
        assert_eq!(Coins::construct_from(&mut slice).unwrap().as_u128(), 9_000_000_000);
        assert_eq!(slice.get_next_u64().unwrap(), 7_200);
        assert!(slice.get_next_bit().unwrap());
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0x55; 32]);
        assert!(!slice.get_next_bit().unwrap());
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn builds_rotate_controller_message() {
        let body = AgentAccountContract::build_rotate_controller_message(43, [0x66; 32]).unwrap();
        let mut slice = chain_block::SliceData::load_cell(body).unwrap();

        assert_eq!(slice.get_next_u32().unwrap(), AGENT_ROTATE_CONTROLLER_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 43);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0x66; 32]);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn builds_controller_signed_task_payload() {
        let target = MsgAddressInt::with_standart(None, -1, [0x66; 32].into()).unwrap();
        let task_body = BuilderData::new().into_cell().unwrap();
        let payload = AgentAccountContract::build_task_send_payload(
            7,
            1_900_000_000,
            &target,
            123_000_000,
            task_body,
        )
        .unwrap();
        let signed =
            AgentAccountContract::build_signed_task_send_message(payload, &[0xAA; 64]).unwrap();
        let external = AgentAccountContract::build_external_task_send_message(
            MsgAddressInt::with_standart(None, -1, [0x77; 32].into()).unwrap(),
            signed,
        )
        .unwrap();

        assert!(external.references_count() >= 1);
    }
}
