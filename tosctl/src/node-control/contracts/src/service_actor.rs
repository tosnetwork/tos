/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
use chain_block::{
    base64_decode, read_single_root_boc, BuilderData, Coins, Deserializable, IBitstring,
    MsgAddressInt, Serializable, StateInit,
};
use common::tvm_stack_parser::TvmStackParser;

pub const SERVICE_ACTOR_CODE_B64: &str = "te6cckECDQEABFQAART/APSkE/S88sgLAQIBYgIDBObQIMcAkl8D4NMf0z8xAtB01yH6QDDtRND6QNMA+kDTANMA+gDTH9Mf0x/6ANQB0NP/0//RAtQB0NP/0//TANP/0QTREEVVAlYRghBTVkMBuuMCVxNWEIIQU1ZDArrjAlYQghBTVkMDuuMCVhCCEFNWQwS6BAUGBwBpoDpT2omh9IGmAfSBpgGmAfQBpj+mP6Y/9AGoA6Gn/6f/ogWoA6Gn/6f/pgGn/6IJoiCKqgUBrjNXECnAAfLnbirAAVH8xwVS0LAfsfLnbVYQKL7y53H4I4IBUYCpBFMGvZM2cDWRMOImwABTV7mx8udwBKQREBOgDtP/0RC/EK4QnRCMEHsQahBZEEhEUwgA1jE/UdzHBfLnbA7T/y6dgwjXGFIiVhL5EPLndd7REL8QrhCdEIwQexBqEFkQSBA3QBYEUFMDyMv/Esv/ywDL/8kCyMv/y//JyFAMzxYaywBQCM8WFssAFMsAWPoCyx/LH8sfAfoCEszMye1UAO4zMzY2Nzc3OVF2xwXy52whwAHy524I+gDTH9MA0wD6QNQB0NP/0//RAtEQvxA+EC0QTBB7EGoQWRAoEGcFUEYTA8jL/xLL/8sAy//JAsjL/8v/ychQDM8WGssAUAjPFhbLABTLAFj6Assfyx/LHwH6AhLMzMntVATmjtFXEFHtxwXy52wP+gDRUwO78udy+CdvEFIQu/LncyDCAI4XU8BxcIAQyMsFUATPFlj6AhLLaskB+wDeE6EQvxCuEJ0QjBB7EGoQWRBIEDdeUAPgVhCCEFNWQwW64wJWEIIQU1ZDBrrjAjAvghBTVkMHuggJCgsAbgPIy/8Sy//LAMv/yQLIy//L/8nIUAzPFhrLAFAIzxYWywAUywBY+gLLH8sfyx8B+gISzMzJ7VQA7DU/P1HLxwXy52wGwAHy524pcIMGcIAQyMsFUATPFlj6AhLLaskB+wBwIBC/EK4QnRCMGxBqEFkQSBA3BgNFVQPIy/8Sy//LAMv/yQLIy//L/8nIUAzPFhrLAFAIzxYWywAUywBY+gLLH8sfyx8B+gISzMzJ7VQAvFcQVxBR3McF8udsB8AA8udvEK4QnRCMEHtxCxBqEFkQSBA3RlAQNAPIy/8Sy//LAMv/yQLIy//L/8nIUAzPFhrLAFAIzxYWywAUywBY+gLLH8sfyx8B+gISzMzJ7VQB3o5aP1cQUcvHBfLnbA3T/zAQrhCdEIwQexBqEFkQSBA3RlAUcQEDyMv/Esv/ywDL/8kCyMv/y//JyFAMzxYaywBQCM8WFssAFMsAWPoCyx/LH8sfAfoCEszMye1U4FcQDoIQU1ZDCLrjAl8PMPLHdAwAqFHLxwXy52wQrhCdEIwQexBqEFkQSBA3RhRQUnABA8jL/xLL/8sAy//JAsjL/8v/ychQDM8WGssAUAjPFhbLABTLAFj6Assfyx/LHwH6AhLMzMntVOcoCaQ=";
pub const SVC_CALL_OPCODE: u32 = 0x5356_4301;
pub const SVC_RESPOND_OPCODE: u32 = 0x5356_4302;
pub const SVC_UPDATE_POLICY_OPCODE: u32 = 0x5356_4303;
pub const SVC_WITHDRAW_REVENUE_OPCODE: u32 = 0x5356_4304;
pub const SVC_DEACTIVATE_OPCODE: u32 = 0x5356_4305;
pub const SVC_REACTIVATE_OPCODE: u32 = 0x5356_4306;
pub const SVC_ROTATE_ATTESTOR_KEY_OPCODE: u32 = 0x5356_4307;
pub const SVC_REVOKE_ATTESTOR_OPCODE: u32 = 0x5356_4308;

/// Deployment parameters for a Service Actor.
///
/// One instance is deployed per registered service (model, data, or tool
/// provider) -- the same per-actor pattern as `AgentAccountContract` /
/// `TaskEscrowContract` / `CapabilityRegistryContract`.
#[derive(Clone, Debug)]
pub struct ServiceActorInit {
    pub owner: MsgAddressInt,
    /// Optional single authorized caller when `open_access` is `false`.
    pub authorized_caller: Option<MsgAddressInt>,
    /// When `true`, any caller may send `call`; otherwise only
    /// `authorized_caller` may.
    pub open_access: bool,
    pub price_per_call: u64,
    /// Maximum `call`s accepted per UTC day; `0` means unlimited.
    pub rate_limit_per_day: u32,
    pub metadata_hash: [u8; 32],
    pub proof_scheme_hash: [u8; 32],
    /// Optional ed25519 public key. When set, `respond` additionally
    /// requires a signature over the new `response_hash` under this key --
    /// on top of, never instead of, the existing owner sender authorization.
    pub attestor_pubkey: Option<[u8; 32]>,
}

pub struct ServiceActorContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceActorData {
    pub owner: MsgAddressInt,
    pub authorized_caller: Option<MsgAddressInt>,
    pub open_access: bool,
    pub active: bool,
    pub price_per_call: u64,
    pub rate_limit_per_day: u32,
    pub call_day: u32,
    pub calls_today: u32,
    pub total_revenue: u64,
    pub metadata_hash: [u8; 32],
    pub proof_scheme_hash: [u8; 32],
    pub last_request_hash: [u8; 32],
    pub last_response_hash: [u8; 32],
    pub attestor_pubkey: Option<[u8; 32]>,
}

impl ServiceActorContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(SERVICE_ACTOR_CODE_B64)?).map_err(Into::into)
    }

    pub fn build_data(init: &ServiceActorInit) -> anyhow::Result<chain_block::Cell> {
        let authorized_caller = init.authorized_caller.as_ref().unwrap_or(&init.owner);
        let mut data = BuilderData::new();
        init.owner.write_to(&mut data)?;
        if init.authorized_caller.is_some() {
            data.append_bit_one()?;
        } else {
            data.append_bit_zero()?;
        }
        authorized_caller.write_to(&mut data)?;
        if init.open_access {
            data.append_bit_one()?;
        } else {
            data.append_bit_zero()?;
        }
        data.append_bit_one()?; // active = 1 at deploy
        Coins::new(init.price_per_call).write_to(&mut data)?;
        data.append_u32(init.rate_limit_per_day)?;
        data.append_u32(0)?; // call_day
        data.append_u32(0)?; // calls_today
        Coins::new(0).write_to(&mut data)?; // total_revenue
        let mut meta = BuilderData::new();
        meta.append_u256(&init.metadata_hash)?.append_u256(&init.proof_scheme_hash)?;
        data.checked_append_reference(meta.into_cell()?)?;
        let mut last = BuilderData::new();
        last.append_u256(&[0; 32])?.append_u256(&[0; 32])?;
        match init.attestor_pubkey {
            Some(pubkey) => {
                last.append_bit_one()?.append_raw(&pubkey, 256)?;
            }
            None => {
                last.append_bit_zero()?.append_raw(&[0; 32], 256)?;
            }
        }
        data.checked_append_reference(last.into_cell()?)?;
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &ServiceActorInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(wc: i32, init: &ServiceActorInit) -> anyhow::Result<MsgAddressInt> {
        let cell = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(wc, cell.hash(0))?)
    }

    /// Decode the result of `get_service_actor_data`; transport and RPC
    /// concerns stay outside this module.
    pub fn decode_data(stack: &TvmStackParser) -> anyhow::Result<ServiceActorData> {
        let mut owner_slice = stack.slice(0)?;
        let owner = MsgAddressInt::construct_from(&mut owner_slice)?;
        let mut caller_slice = stack.slice(2)?;
        let authorized_caller = if stack.u64(1)? == 0 {
            None
        } else {
            Some(MsgAddressInt::construct_from(&mut caller_slice)?)
        };
        Ok(ServiceActorData {
            owner,
            authorized_caller,
            open_access: stack.u64(3)? != 0,
            active: stack.u64(4)? != 0,
            price_per_call: stack.u64(5)?,
            rate_limit_per_day: stack.u64(6)? as u32,
            call_day: stack.u64(7)? as u32,
            calls_today: stack.u64(8)? as u32,
            total_revenue: stack.u64(9)?,
            metadata_hash: parse_hash(stack, 10)?,
            proof_scheme_hash: parse_hash(stack, 11)?,
            last_request_hash: parse_hash(stack, 12)?,
            last_response_hash: parse_hash(stack, 13)?,
            attestor_pubkey: if stack.u64(14)? == 0 { None } else { Some(parse_hash(stack, 15)?) },
        })
    }

    pub fn call(query_id: u64, request_hash: [u8; 32]) -> anyhow::Result<chain_block::Cell> {
        message(SVC_CALL_OPCODE, query_id, |b| b.append_u256(&request_hash).map(|_| ()))
    }

    pub fn respond(query_id: u64, response_hash: [u8; 32]) -> anyhow::Result<chain_block::Cell> {
        message(SVC_RESPOND_OPCODE, query_id, |b| b.append_u256(&response_hash).map(|_| ()))
    }

    /// Respond on a Service Actor deployed with an `attestor_pubkey`:
    /// `signature` must be a valid ed25519 signature over `response_hash`
    /// under that key, or the contract rejects the message.
    pub fn respond_signed(
        query_id: u64,
        response_hash: [u8; 32],
        signature: &[u8; 64],
    ) -> anyhow::Result<chain_block::Cell> {
        message(SVC_RESPOND_OPCODE, query_id, |b| {
            b.append_u256(&response_hash)?;
            b.append_raw(signature, 512).map(|_| ())
        })
    }

    /// `filler` is written in the authorized-caller slot when
    /// `authorized_caller` is `None` (mirroring how `ServiceActorInit`
    /// always carries a concrete address).
    #[allow(clippy::too_many_arguments)]
    pub fn update_policy(
        query_id: u64,
        price_per_call: u64,
        rate_limit_per_day: u32,
        open_access: bool,
        authorized_caller: Option<&MsgAddressInt>,
        filler: &MsgAddressInt,
        metadata_hash: [u8; 32],
        proof_scheme_hash: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(SVC_UPDATE_POLICY_OPCODE, query_id, |b| {
            Coins::new(price_per_call).write_to(b)?;
            b.append_u32(rate_limit_per_day)?;
            if open_access {
                b.append_bit_one()?;
            } else {
                b.append_bit_zero()?;
            }
            if authorized_caller.is_some() {
                b.append_bit_one()?;
            } else {
                b.append_bit_zero()?;
            }
            authorized_caller.unwrap_or(filler).write_to(b)?;
            let mut meta = BuilderData::new();
            meta.append_u256(&metadata_hash)?.append_u256(&proof_scheme_hash)?;
            b.checked_append_reference(meta.into_cell()?)?;
            Ok(())
        })
    }

    pub fn withdraw_revenue(query_id: u64, amount: u64) -> anyhow::Result<chain_block::Cell> {
        message(SVC_WITHDRAW_REVENUE_OPCODE, query_id, |b| Coins::new(amount).write_to(b))
    }

    pub fn deactivate(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(SVC_DEACTIVATE_OPCODE, query_id, |_| Ok(()))
    }

    pub fn reactivate(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(SVC_REACTIVATE_OPCODE, query_id, |_| Ok(()))
    }

    /// Owner-only: set or replace the `attestor_pubkey` `respond` checks
    /// against. Purely local state -- no cross-contract messaging.
    pub fn rotate_attestor_key(
        query_id: u64,
        new_attestor_pubkey: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(SVC_ROTATE_ATTESTOR_KEY_OPCODE, query_id, |b| {
            b.append_raw(&new_attestor_pubkey, 256).map(|_| ())
        })
    }

    /// Owner-only: drop the attestation requirement -- `respond` reverts to
    /// sender-authorization-only until `rotate_attestor_key` is called again.
    pub fn revoke_attestor(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(SVC_REVOKE_ATTESTOR_OPCODE, query_id, |_| Ok(()))
    }
}

fn parse_hash(stack: &TvmStackParser, index: usize) -> anyhow::Result<[u8; 32]> {
    stack
        .number_bytes(index, 32)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stack entry {} is not a 256-bit value", index))
}

fn message<F>(opcode: u32, query_id: u64, append: F) -> anyhow::Result<chain_block::Cell>
where
    F: FnOnce(&mut BuilderData) -> anyhow::Result<()>,
{
    let mut body = BuilderData::new();
    body.append_u32(opcode)?.append_u64(query_id)?;
    append(&mut body)?;
    Ok(body.into_cell()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::{Deserializable, Serializable, SliceData};
    use common::tvm_stack_parser::TvmStackParser;
    use tl_api::tos::tvm::{
        numberdecimal::NumberDecimal,
        slice,
        stackentry::{StackEntryNumber, StackEntrySlice},
        Number, StackEntry,
    };

    fn number(value: impl Into<String>) -> StackEntry {
        StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
            number: Number::Tvm_NumberDecimal(NumberDecimal { number: value.into() }),
        })
    }

    fn hash_number(value: [u8; 32]) -> StackEntry {
        number(format!("0x{}", hex::encode(value)))
    }

    fn address_slice_entry(address: &MsgAddressInt) -> StackEntry {
        let cell = address.write_to_new_cell().unwrap().into_cell().unwrap();
        let bytes = SliceData::load_cell(cell).unwrap().get_bytestring(0);
        StackEntry::Tvm_StackEntrySlice(StackEntrySlice { slice: slice::Slice { bytes } })
    }

    fn init() -> ServiceActorInit {
        ServiceActorInit {
            owner: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap(),
            authorized_caller: Some(MsgAddressInt::with_standart(None, -1, [0x22; 32].into()).unwrap()),
            open_access: false,
            price_per_call: 100_000_000,
            rate_limit_per_day: 1_000,
            metadata_hash: [0x33; 32],
            proof_scheme_hash: [0x44; 32],
            attestor_pubkey: None,
        }
    }

    #[test]
    fn state_init_and_address_are_deterministic() {
        let svc = init();
        let first = ServiceActorContract::build_state_init(&svc)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        let second = ServiceActorContract::build_state_init(&svc)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        assert_eq!(first.hash(0), second.hash(0));
    }

    #[test]
    fn encodes_call_and_respond_messages() {
        let call = ServiceActorContract::call(1, [0xAA; 32]).unwrap();
        let mut slice = SliceData::load_cell(call).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_CALL_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 1);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xAA; 32]);
        assert_eq!(slice.remaining_bits(), 0);

        let respond = ServiceActorContract::respond(2, [0xBB; 32]).unwrap();
        let mut slice = SliceData::load_cell(respond).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_RESPOND_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 2);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xBB; 32]);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn encodes_update_policy_message() {
        let svc = init();
        let body = ServiceActorContract::update_policy(
            3,
            200_000_000,
            50,
            true,
            svc.authorized_caller.as_ref(),
            &svc.owner,
            [0xCC; 32],
            [0xDD; 32],
        )
        .unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_UPDATE_POLICY_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 3);
        assert_eq!(Coins::construct_from(&mut slice).unwrap().as_u128(), 200_000_000);
        assert_eq!(slice.get_next_u32().unwrap(), 50);
        assert_eq!(slice.get_next_bit().unwrap(), true);
        assert_eq!(slice.get_next_bit().unwrap(), true);
        assert_eq!(MsgAddressInt::construct_from(&mut slice).unwrap(), svc.authorized_caller.unwrap());
        assert_eq!(slice.remaining_bits(), 0);
        assert_eq!(slice.remaining_references(), 1);
        let mut meta_slice = SliceData::load_cell(slice.reference(0).unwrap()).unwrap();
        assert_eq!(meta_slice.get_next_bytes(32).unwrap(), vec![0xCC; 32]);
        assert_eq!(meta_slice.get_next_bytes(32).unwrap(), vec![0xDD; 32]);
    }

    #[test]
    fn encodes_withdraw_and_lifecycle_messages() {
        let withdraw = ServiceActorContract::withdraw_revenue(4, 500_000_000).unwrap();
        let mut slice = SliceData::load_cell(withdraw).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_WITHDRAW_REVENUE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 4);
        assert_eq!(Coins::construct_from(&mut slice).unwrap().as_u128(), 500_000_000);
        assert_eq!(slice.remaining_bits(), 0);

        let deactivate = ServiceActorContract::deactivate(5).unwrap();
        let mut slice = SliceData::load_cell(deactivate).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_DEACTIVATE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 5);

        let reactivate = ServiceActorContract::reactivate(6).unwrap();
        let mut slice = SliceData::load_cell(reactivate).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_REACTIVATE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 6);
    }

    #[test]
    fn decodes_service_actor_data_stack() {
        let svc = init();
        let stack = TvmStackParser::new(vec![
            address_slice_entry(&svc.owner),
            number("1"),
            address_slice_entry(svc.authorized_caller.as_ref().unwrap()),
            number("0"),
            number("1"),
            number(svc.price_per_call.to_string()),
            number(svc.rate_limit_per_day.to_string()),
            number("19700"),
            number("3"),
            number("1500000000"),
            hash_number(svc.metadata_hash),
            hash_number(svc.proof_scheme_hash),
            hash_number([0xEE; 32]),
            hash_number([0xFF; 32]),
            number("1"),
            hash_number([0x99; 32]),
        ]);
        let data = ServiceActorContract::decode_data(&stack).unwrap();
        assert_eq!(data.owner, svc.owner);
        assert_eq!(data.authorized_caller, svc.authorized_caller);
        assert!(!data.open_access);
        assert!(data.active);
        assert_eq!(data.price_per_call, svc.price_per_call);
        assert_eq!(data.rate_limit_per_day, svc.rate_limit_per_day);
        assert_eq!(data.call_day, 19700);
        assert_eq!(data.calls_today, 3);
        assert_eq!(data.total_revenue, 1_500_000_000);
        assert_eq!(data.metadata_hash, svc.metadata_hash);
        assert_eq!(data.proof_scheme_hash, svc.proof_scheme_hash);
        assert_eq!(data.last_request_hash, [0xEE; 32]);
        assert_eq!(data.last_response_hash, [0xFF; 32]);
        assert_eq!(data.attestor_pubkey, Some([0x99; 32]));
    }

    #[test]
    fn decodes_service_actor_data_without_authorized_caller() {
        let svc = init();
        let stack = TvmStackParser::new(vec![
            address_slice_entry(&svc.owner),
            number("0"),
            address_slice_entry(&svc.owner),
            number("1"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            hash_number([0; 32]),
            hash_number([0; 32]),
            hash_number([0; 32]),
            hash_number([0; 32]),
            number("0"),
            hash_number([0; 32]),
        ]);
        let data = ServiceActorContract::decode_data(&stack).unwrap();
        assert_eq!(data.authorized_caller, None);
        assert!(data.open_access);
        assert!(!data.active);
        assert_eq!(data.attestor_pubkey, None);
    }
}
