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

pub const TASK_ESCROW_CODE_B64: &str = "te6ccgECCwEAAzgAART/APSkE/S88sgLAQIBYgIDBMTQMiHHAJFb4AHTH9M/Me1E0PpA0wD6QNMA+kD6ANM/0wfUAdDT/9P/0//UMNDT/zAE0Q7QdNch+kAwLYIQVEFTAbrjAi2CEFRBUwK64wItghBUQVMDuuMCNjsrghBUQVMEugQFBgcAUaEhbdqJofSBpgH0gaYB9IH0AaZ/pg+oYaGn/6f/p/+oYaGn/mAhNCDxAJw8PALAAPLgZAfAAFKXxwUWsfLgZXEgEIsZGl40EDZFRALIy//JA8jL/xLL/8v/zMnIUAnPFhbLAFAGzxYSywBYzxYB+gISyz/LB8zJ7VQAoj1bAcAB8uBmUZXHBVJgsPLgZwfT/9P/MBB6XjVeMxAlckFEA8jL/8kDyMv/Esv/y//MychQCc8WFssAUAbPFhLLAFjPFgH6AhLLP8sHzMntVAHgPQPAAvLgaFO5xwVRxscFUnCwHLHy4GkJ+gAwUgS78uBq+CdvEFIwu/LgcCLCAI4XUlNxcIAQyMsFUATPFlj6AhLLaskB+wCRMuImcIMGcIAQyMsFUATPFlj6AhLLaskB+wAQaV40XjJwUEVzUERDEwgC+o5gOwHAAPLga1EnxwXy4GwmcIMGcIAQyMsFUATPFlj6AhLLaskB+wAQaV40XjJwUEV0UEQDyMv/yQPIy/8Sy//L/8zJyFAJzxYWywBQBs8WEssAWM8WAfoCEss/ywfMye1U4CuCEFRBUwa64wI0CoIQVEFTBbrjAl8L8sBvCQoAWsjL/8kDyMv/Esv/y//MychQCc8WFssAUAbPFhLLAFjPFgH6AhLLP8sHzMntVADGOwHAAPLgcVElxwVSYLDy4HImcIMGcIAQyMsFUATPFlj6AhLLaskB+wAQaV40XjJwUEV2UEQDyMv/yQPIy/8Sy//L/8zJyFAJzxYWywBQBs8WEssAWM8WAfoCEss/ywfMye1UAMwh+CO78uBtIMAAIcABsQHAArHy4G4mcIMGcIAQyMsFUATPFlj6AhLLaskB+wAQaV40XjJwUEV1UETIy//JA8jL/xLL/8v/zMnIUAnPFhbLAFAGzxYSywBYzxYB+gISyz/LB8zJ7VQ=";
pub const TASK_ACCEPT_OPCODE: u32 = 0x5441_5301;
pub const TASK_RESULT_OPCODE: u32 = 0x5441_5302;
pub const TASK_SETTLE_OPCODE: u32 = 0x5441_5303;
pub const TASK_CANCEL_OPCODE: u32 = 0x5441_5304;
pub const TASK_TIMEOUT_OPCODE: u32 = 0x5441_5305;
pub const TASK_REJECT_OPCODE: u32 = 0x5441_5306;

#[derive(Clone, Debug)]
pub struct TaskEscrowInit {
    pub creator: MsgAddressInt,
    pub assigned_agent: Option<MsgAddressInt>,
    /// Optional settlement authority allowed to settle alongside the creator.
    pub verifier: Option<MsgAddressInt>,
    pub budget: u64,
    pub deadline: u64,
    pub settlement_policy_hash: [u8; 32],
    pub permission_hash: [u8; 32],
}

pub struct TaskEscrowContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskEscrowData {
    pub creator: MsgAddressInt,
    pub assigned_agent: Option<MsgAddressInt>,
    pub verifier: Option<MsgAddressInt>,
    pub budget: u64,
    pub deadline: u64,
    pub status: u8,
    pub result_hash: [u8; 32],
    pub evidence_hash: [u8; 32],
    pub settlement_policy_hash: [u8; 32],
    pub permission_hash: [u8; 32],
}

impl TaskEscrowContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(TASK_ESCROW_CODE_B64)?).map_err(Into::into)
    }

    pub fn build_data(init: &TaskEscrowInit) -> anyhow::Result<chain_block::Cell> {
        let agent = init.assigned_agent.as_ref().unwrap_or(&init.creator);
        let verifier = init.verifier.as_ref().unwrap_or(&init.creator);
        let mut data = BuilderData::new();
        init.creator.write_to(&mut data)?;
        if init.assigned_agent.is_some() {
            data.append_bit_one()?;
        } else {
            data.append_bit_zero()?;
        }
        agent.write_to(&mut data)?;
        if init.verifier.is_some() {
            data.append_bit_one()?;
        } else {
            data.append_bit_zero()?;
        }
        verifier.write_to(&mut data)?;
        Coins::new(init.budget).write_to(&mut data)?;
        data.append_u64(init.deadline)?.append_u8(0)?;
        let mut hashes = BuilderData::new();
        let mut permission = BuilderData::new();
        permission.append_u256(&init.permission_hash)?;
        hashes
            .append_u256(&[0; 32])?
            .append_u256(&[0; 32])?
            .append_u256(&init.settlement_policy_hash)?
            .checked_append_reference(permission.into_cell()?)?;
        data.checked_append_reference(hashes.into_cell()?)?;
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &TaskEscrowInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(wc: i32, init: &TaskEscrowInit) -> anyhow::Result<MsgAddressInt> {
        let cell = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(wc, cell.hash(0))?)
    }

    /// Decode the result of `get_task_data`; transport and RPC concerns stay outside this module.
    pub fn decode_data(stack: &TvmStackParser) -> anyhow::Result<TaskEscrowData> {
        let mut creator_slice = stack.slice(0)?;
        let creator = MsgAddressInt::construct_from(&mut creator_slice)?;
        let mut agent_slice = stack.slice(1)?;
        let assigned_agent = if stack.u64(2)? == 0 {
            None
        } else {
            Some(MsgAddressInt::construct_from(&mut agent_slice)?)
        };
        let mut verifier_slice = stack.slice(3)?;
        let verifier = if stack.u64(4)? == 0 {
            None
        } else {
            Some(MsgAddressInt::construct_from(&mut verifier_slice)?)
        };
        Ok(TaskEscrowData {
            creator,
            assigned_agent,
            verifier,
            budget: stack.u64(5)?,
            deadline: stack.u64(6)?,
            status: stack.u64(7)? as u8,
            result_hash: parse_hash(stack, 8)?,
            evidence_hash: parse_hash(stack, 9)?,
            settlement_policy_hash: parse_hash(stack, 10)?,
            permission_hash: parse_hash(stack, 11)?,
        })
    }

    pub fn accept(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(TASK_ACCEPT_OPCODE, query_id, |_| Ok(()))
    }

    pub fn result(
        query_id: u64,
        result_hash: [u8; 32],
        evidence_hash: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(TASK_RESULT_OPCODE, query_id, |b| {
            b.append_raw(&result_hash, 256)?.append_raw(&evidence_hash, 256).map(|_| ())
        })
    }

    pub fn settle(query_id: u64, payout: u64) -> anyhow::Result<chain_block::Cell> {
        message(TASK_SETTLE_OPCODE, query_id, |b| Coins::new(payout).write_to(b))
    }

    pub fn cancel(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(TASK_CANCEL_OPCODE, query_id, |_| Ok(()))
    }

    pub fn timeout(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(TASK_TIMEOUT_OPCODE, query_id, |_| Ok(()))
    }

    pub fn reject(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(TASK_REJECT_OPCODE, query_id, |_| Ok(()))
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

    fn init() -> TaskEscrowInit {
        TaskEscrowInit {
            creator: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap(),
            assigned_agent: Some(
                MsgAddressInt::with_standart(None, -1, [0x22; 32].into()).unwrap(),
            ),
            verifier: Some(MsgAddressInt::with_standart(None, -1, [0x66; 32].into()).unwrap()),
            budget: 1_000_000_000,
            deadline: 1_800_000_000,
            settlement_policy_hash: [0x33; 32],
            permission_hash: [0x77; 32],
        }
    }

    #[test]
    fn state_init_and_address_are_deterministic() {
        let task = init();
        let first = TaskEscrowContract::build_state_init(&task)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        let second = TaskEscrowContract::build_state_init(&task)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        assert_eq!(first.hash(0), second.hash(0));
        assert_eq!(
            TaskEscrowContract::calculate_address(-1, &task).unwrap(),
            TaskEscrowContract::calculate_address(-1, &task).unwrap()
        );
    }

    #[test]
    fn encodes_result_message() {
        let body = TaskEscrowContract::result(7, [0x44; 32], [0x55; 32]).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), TASK_RESULT_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 7);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0x44; 32]);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0x55; 32]);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn encodes_settlement_amount() {
        let body = TaskEscrowContract::settle(8, 123_456).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), TASK_SETTLE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 8);
        assert_eq!(Coins::construct_from(&mut slice).unwrap().as_u128(), 123_456);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn encodes_reject_message() {
        let body = TaskEscrowContract::reject(9).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), TASK_REJECT_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 9);
        assert_eq!(slice.remaining_bits(), 0);
    }

    fn address_slice_entry(address: &MsgAddressInt) -> StackEntry {
        let cell = address.write_to_new_cell().unwrap().into_cell().unwrap();
        let bytes = SliceData::load_cell(cell).unwrap().get_bytestring(0);
        StackEntry::Tvm_StackEntrySlice(StackEntrySlice { slice: slice::Slice { bytes } })
    }

    #[test]
    fn decodes_task_data_stack() {
        let task = init();
        let stack = TvmStackParser::new(vec![
            address_slice_entry(&task.creator),
            address_slice_entry(task.assigned_agent.as_ref().unwrap()),
            number("1"),
            address_slice_entry(task.verifier.as_ref().unwrap()),
            number("1"),
            number(task.budget.to_string()),
            number(task.deadline.to_string()),
            number("2"),
            hash_number([0x44; 32]),
            hash_number([0x55; 32]),
            hash_number(task.settlement_policy_hash),
            hash_number(task.permission_hash),
        ]);
        let data = TaskEscrowContract::decode_data(&stack).unwrap();
        assert_eq!(data.creator, task.creator);
        assert_eq!(data.assigned_agent, task.assigned_agent);
        assert_eq!(data.verifier, task.verifier);
        assert_eq!(data.budget, task.budget);
        assert_eq!(data.deadline, task.deadline);
        assert_eq!(data.status, 2);
        assert_eq!(data.result_hash, [0x44; 32]);
        assert_eq!(data.evidence_hash, [0x55; 32]);
        assert_eq!(data.settlement_policy_hash, task.settlement_policy_hash);
        assert_eq!(data.permission_hash, task.permission_hash);
    }

    #[test]
    fn decodes_task_data_without_verifier() {
        let task = init();
        let stack = TvmStackParser::new(vec![
            address_slice_entry(&task.creator),
            address_slice_entry(&task.creator),
            number("0"),
            address_slice_entry(&task.creator),
            number("0"),
            number(task.budget.to_string()),
            number(task.deadline.to_string()),
            number("0"),
            hash_number([0; 32]),
            hash_number([0; 32]),
            hash_number(task.settlement_policy_hash),
            hash_number(task.permission_hash),
        ]);
        let data = TaskEscrowContract::decode_data(&stack).unwrap();
        assert_eq!(data.assigned_agent, None);
        assert_eq!(data.verifier, None);
        assert_eq!(data.status, 0);
    }
}
