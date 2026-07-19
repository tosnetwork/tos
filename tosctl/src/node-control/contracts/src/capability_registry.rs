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

pub const CAPABILITY_REGISTRY_CODE_B64: &str = "te6cckECCgEAAuIAART/APSkE/S88sgLAQIBYgIDAfTQIMcAkl8D4NMf0z8xAtB01yH6QDDtRND6QNMA+kDTANM/+gDSH9P/1AHQ0//T/9P/BNED0VgsghBDQVADuo43Ozs7UCugEGoQWRBIEDdGFUBDAsjL/8v/y//JyFAJzxYXywBQBc8WE8sAyz8B+gLKH8v/zMntVOA+KwQAR6Aix9qJofSBpgH0gaYBpn/0AaQ/p/+oA6Gn/6f/p/4JogeisQT+ghBDQVABuo5PXwM4OVFUxwXy5wggwAHy5wsG0//T/9P/1AHQ0//RAdEQahBZXjQQVlUgAsjL/8v/y//JyFAJzxYXywBQBc8WE8sAyz8B+gLKH8v/zMntVOArghBDQVACuuMCK4IQQ0FQBLrjAiuCEENBUAW64wI8KoIQQ0FQBgUGBwgAgjc3OVF2xwXy5wgI0wD6QNEQalCYEDdGE1BERRUCyMv/y//L/8nIUAnPFhfLAFAFzxYTywDLPwH6Asofy//Mye1UANg7UZjHBfLnCAr6ANFTArvy5w34J28QUhC78ucOIMIAjhdTcHFwgBDIywVQBM8WWPoCEstqyQH7AN4SoRBqEFkQSBA3RhVDQwLIy//L/8v/ychQCc8WF8sAUAXPFhPLAMs/AfoCyh/L/8zJ7VQAijsnwAHy5wpRlscF8ucJCtIf0aAQahBZEEgQN0ZEBUMTAsjL/8v/y//JyFAJzxYXywBQBc8WE8sAyz8B+gLKH8v/zMntVAHauo5aMzlRdscF8ucIAsAB8ucLJHCDBnCAEMjLBVAEzxZY+gISy2rJAfsAcCAQahBZEEhGdVAEQxMCyMv/y//L/8nIUAnPFhfLAFAFzxYTywDLPwH6Asofy//Mye1U4AqCEENBUAe64wJfDPLHDwkAfFGHxwXy5wgDwADy5wwQWRBIEDdxRhcDRFQCyMv/y//L/8nIUAnPFhfLAFAFzxYTywDLPwH6Asofy//Mye1UQ2HQ6Q==";
pub const CAP_UPDATE_METADATA_OPCODE: u32 = 0x4341_5001;
pub const CAP_UPDATE_VERIFIER_OPCODE: u32 = 0x4341_5002;
pub const CAP_STAKE_OPCODE: u32 = 0x4341_5003;
pub const CAP_WITHDRAW_BOND_OPCODE: u32 = 0x4341_5004;
pub const CAP_UPDATE_REPUTATION_OPCODE: u32 = 0x4341_5005;
pub const CAP_DEACTIVATE_OPCODE: u32 = 0x4341_5006;
pub const CAP_REACTIVATE_OPCODE: u32 = 0x4341_5007;

/// Deployment parameters for a Capability Registry entry.
///
/// One instance is deployed per registered agent/service (the same
/// per-actor pattern as `AgentAccountContract`/`TaskEscrowContract`); this
/// is not a shared, chain-wide dictionary contract.
#[derive(Clone, Debug)]
pub struct CapabilityRegistryInit {
    pub owner: MsgAddressInt,
    /// Optional authority allowed to adjust `reputation_score` post-deploy.
    pub verifier: Option<MsgAddressInt>,
    pub task_categories_hash: [u8; 32],
    pub pricing_hash: [u8; 32],
    pub metadata_hash: [u8; 32],
    pub verification_method_hash: [u8; 32],
    /// Initial bond, in nano-TOS. The deploy message's value should cover at
    /// least this amount plus gas.
    pub initial_bond: u64,
    /// Unix timestamp recorded as the registration time.
    pub registered_at: u64,
}

pub struct CapabilityRegistryContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRegistryData {
    pub owner: MsgAddressInt,
    pub verifier: Option<MsgAddressInt>,
    pub active: bool,
    pub registered_at: u64,
    pub bond: u64,
    pub reputation_score: i64,
    pub verification_method_hash: [u8; 32],
    pub task_categories_hash: [u8; 32],
    pub pricing_hash: [u8; 32],
    pub metadata_hash: [u8; 32],
}

impl CapabilityRegistryContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(CAPABILITY_REGISTRY_CODE_B64)?).map_err(Into::into)
    }

    pub fn build_data(init: &CapabilityRegistryInit) -> anyhow::Result<chain_block::Cell> {
        let verifier = init.verifier.as_ref().unwrap_or(&init.owner);
        let mut data = BuilderData::new();
        init.owner.write_to(&mut data)?;
        if init.verifier.is_some() {
            data.append_bit_one()?;
        } else {
            data.append_bit_zero()?;
        }
        verifier.write_to(&mut data)?;
        data.append_bit_one()?; // active = 1 at deploy
        data.append_u64(init.registered_at)?;
        Coins::new(init.initial_bond).write_to(&mut data)?;
        data.append_i32(0)?; // reputation_score starts at 0
        data.append_u256(&init.verification_method_hash)?;
        let mut meta = BuilderData::new();
        meta.append_u256(&init.task_categories_hash)?
            .append_u256(&init.pricing_hash)?
            .append_u256(&init.metadata_hash)?;
        data.checked_append_reference(meta.into_cell()?)?;
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &CapabilityRegistryInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(wc: i32, init: &CapabilityRegistryInit) -> anyhow::Result<MsgAddressInt> {
        let cell = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(wc, cell.hash(0))?)
    }

    /// Decode the result of `get_capability_registry_data`; transport and RPC
    /// concerns stay outside this module.
    pub fn decode_data(stack: &TvmStackParser) -> anyhow::Result<CapabilityRegistryData> {
        let mut owner_slice = stack.slice(0)?;
        let owner = MsgAddressInt::construct_from(&mut owner_slice)?;
        let mut verifier_slice = stack.slice(2)?;
        let verifier = if stack.u64(1)? == 0 {
            None
        } else {
            Some(MsgAddressInt::construct_from(&mut verifier_slice)?)
        };
        Ok(CapabilityRegistryData {
            owner,
            verifier,
            active: stack.u64(3)? != 0,
            registered_at: stack.u64(4)?,
            bond: stack.u64(5)?,
            reputation_score: stack.i64(6)?,
            verification_method_hash: parse_hash(stack, 7)?,
            task_categories_hash: parse_hash(stack, 8)?,
            pricing_hash: parse_hash(stack, 9)?,
            metadata_hash: parse_hash(stack, 10)?,
        })
    }

    /// `verification_method_hash` is carried in a separate cell reference:
    /// four inline 256-bit hashes plus the 32-bit op and 64-bit query_id
    /// would exceed the 1023-bit single-cell limit.
    pub fn update_metadata(
        query_id: u64,
        task_categories_hash: [u8; 32],
        pricing_hash: [u8; 32],
        metadata_hash: [u8; 32],
        verification_method_hash: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(CAP_UPDATE_METADATA_OPCODE, query_id, |b| {
            b.append_u256(&task_categories_hash)?
                .append_u256(&pricing_hash)?
                .append_u256(&metadata_hash)?;
            let mut vmh = BuilderData::new();
            vmh.append_u256(&verification_method_hash)?;
            b.checked_append_reference(vmh.into_cell()?)?;
            Ok(())
        })
    }

    /// `filler` is written in the address slot when `verifier` is `None`
    /// (mirroring how `TaskEscrowInit` always carries a concrete address).
    pub fn update_verifier(
        query_id: u64,
        verifier: Option<&MsgAddressInt>,
        filler: &MsgAddressInt,
    ) -> anyhow::Result<chain_block::Cell> {
        message(CAP_UPDATE_VERIFIER_OPCODE, query_id, |b| {
            if verifier.is_some() {
                b.append_bit_one()?;
            } else {
                b.append_bit_zero()?;
            }
            verifier.unwrap_or(filler).write_to(b)?;
            Ok(())
        })
    }

    pub fn stake(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(CAP_STAKE_OPCODE, query_id, |_| Ok(()))
    }

    pub fn withdraw_bond(query_id: u64, amount: u64) -> anyhow::Result<chain_block::Cell> {
        message(CAP_WITHDRAW_BOND_OPCODE, query_id, |b| Coins::new(amount).write_to(b))
    }

    pub fn update_reputation(query_id: u64, delta: i32) -> anyhow::Result<chain_block::Cell> {
        message(CAP_UPDATE_REPUTATION_OPCODE, query_id, |b| b.append_i32(delta).map(|_| ()))
    }

    pub fn deactivate(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(CAP_DEACTIVATE_OPCODE, query_id, |_| Ok(()))
    }

    pub fn reactivate(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(CAP_REACTIVATE_OPCODE, query_id, |_| Ok(()))
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

    fn init() -> CapabilityRegistryInit {
        CapabilityRegistryInit {
            owner: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap(),
            verifier: Some(MsgAddressInt::with_standart(None, -1, [0x22; 32].into()).unwrap()),
            task_categories_hash: [0x33; 32],
            pricing_hash: [0x44; 32],
            metadata_hash: [0x55; 32],
            verification_method_hash: [0x66; 32],
            initial_bond: 1_000_000_000,
            registered_at: 1_700_000_000,
        }
    }

    #[test]
    fn state_init_and_address_are_deterministic() {
        let cap = init();
        let first = CapabilityRegistryContract::build_state_init(&cap)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        let second = CapabilityRegistryContract::build_state_init(&cap)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        assert_eq!(first.hash(0), second.hash(0));
        assert_eq!(
            CapabilityRegistryContract::calculate_address(-1, &cap).unwrap(),
            CapabilityRegistryContract::calculate_address(-1, &cap).unwrap()
        );
    }

    #[test]
    fn encodes_update_metadata_message() {
        let body = CapabilityRegistryContract::update_metadata(
            1,
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            [0xDD; 32],
        )
        .unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), CAP_UPDATE_METADATA_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 1);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xAA; 32]);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xBB; 32]);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xCC; 32]);
        assert_eq!(slice.remaining_bits(), 0);
        assert_eq!(slice.remaining_references(), 1);
        let mut vmh_slice = SliceData::load_cell(slice.reference(0).unwrap()).unwrap();
        assert_eq!(vmh_slice.get_next_bytes(32).unwrap(), vec![0xDD; 32]);
        assert_eq!(vmh_slice.remaining_bits(), 0);
    }

    #[test]
    fn encodes_stake_and_withdraw_messages() {
        let stake = CapabilityRegistryContract::stake(2).unwrap();
        let mut slice = SliceData::load_cell(stake).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), CAP_STAKE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 2);
        assert_eq!(slice.remaining_bits(), 0);

        let withdraw = CapabilityRegistryContract::withdraw_bond(3, 500_000_000).unwrap();
        let mut slice = SliceData::load_cell(withdraw).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), CAP_WITHDRAW_BOND_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 3);
        assert_eq!(Coins::construct_from(&mut slice).unwrap().as_u128(), 500_000_000);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn encodes_reputation_and_lifecycle_messages() {
        let rep = CapabilityRegistryContract::update_reputation(4, -7).unwrap();
        let mut slice = SliceData::load_cell(rep).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), CAP_UPDATE_REPUTATION_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 4);
        assert_eq!(slice.get_next_int(32).unwrap() as i32, -7);
        assert_eq!(slice.remaining_bits(), 0);

        let deactivate = CapabilityRegistryContract::deactivate(5).unwrap();
        let mut slice = SliceData::load_cell(deactivate).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), CAP_DEACTIVATE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 5);
        assert_eq!(slice.remaining_bits(), 0);

        let reactivate = CapabilityRegistryContract::reactivate(6).unwrap();
        let mut slice = SliceData::load_cell(reactivate).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), CAP_REACTIVATE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 6);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn encodes_update_verifier_message_with_and_without_verifier() {
        let cap = init();
        let with_verifier =
            CapabilityRegistryContract::update_verifier(7, cap.verifier.as_ref(), &cap.owner)
                .unwrap();
        let mut slice = SliceData::load_cell(with_verifier).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), CAP_UPDATE_VERIFIER_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 7);
        assert_eq!(slice.get_next_bit().unwrap(), true);
        assert_eq!(MsgAddressInt::construct_from(&mut slice).unwrap(), cap.verifier.unwrap());

        let without_verifier =
            CapabilityRegistryContract::update_verifier(8, None, &cap.owner).unwrap();
        let mut slice = SliceData::load_cell(without_verifier).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), CAP_UPDATE_VERIFIER_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 8);
        assert_eq!(slice.get_next_bit().unwrap(), false);
        assert_eq!(MsgAddressInt::construct_from(&mut slice).unwrap(), cap.owner);
    }

    #[test]
    fn decodes_capability_registry_data_stack() {
        let cap = init();
        let stack = TvmStackParser::new(vec![
            address_slice_entry(&cap.owner),
            number("1"),
            address_slice_entry(cap.verifier.as_ref().unwrap()),
            number("1"),
            number(cap.registered_at.to_string()),
            number(cap.initial_bond.to_string()),
            number("-3"),
            hash_number(cap.verification_method_hash),
            hash_number(cap.task_categories_hash),
            hash_number(cap.pricing_hash),
            hash_number(cap.metadata_hash),
        ]);
        let data = CapabilityRegistryContract::decode_data(&stack).unwrap();
        assert_eq!(data.owner, cap.owner);
        assert_eq!(data.verifier, cap.verifier);
        assert!(data.active);
        assert_eq!(data.registered_at, cap.registered_at);
        assert_eq!(data.bond, cap.initial_bond);
        assert_eq!(data.reputation_score, -3);
        assert_eq!(data.verification_method_hash, cap.verification_method_hash);
        assert_eq!(data.task_categories_hash, cap.task_categories_hash);
        assert_eq!(data.pricing_hash, cap.pricing_hash);
        assert_eq!(data.metadata_hash, cap.metadata_hash);
    }

    #[test]
    fn decodes_capability_registry_data_without_verifier() {
        let cap = init();
        let stack = TvmStackParser::new(vec![
            address_slice_entry(&cap.owner),
            number("0"),
            address_slice_entry(&cap.owner),
            number("0"),
            number(cap.registered_at.to_string()),
            number("0"),
            number("0"),
            hash_number([0; 32]),
            hash_number([0; 32]),
            hash_number([0; 32]),
            hash_number([0; 32]),
        ]);
        let data = CapabilityRegistryContract::decode_data(&stack).unwrap();
        assert_eq!(data.verifier, None);
        assert!(!data.active);
        assert_eq!(data.bond, 0);
        assert_eq!(data.reputation_score, 0);
    }
}
