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

pub const TASK_ESCROW_CODE_B64: &str = "te6ccgECCAEAAk8AART/APSkE/S88sgLAQIBYgIDAfbQMiHHAJFb4AHTH9M/Me1E0PpA0wD6QPoA0z/TB9QB0NP/0//T/zAD0QvQdNch+kAwKoIQVEFTAbqOPjk5AcAA8uBkBMAAUmTHBROx8uBlcSAQWBZFc1AkAsjL/8v/y//JyFAHzxYUywBQBM8WAfoCEss/ywfMye1U4CoEADuhIW3aiaH0gaYB9IH0AaZ/pg+oYaGn/6f/p/5gIM8D5oIQVEFTArqOQzE5OcAB8uBmUWLHBVIwsPLgZwTT/9P/MBBHXjIQNBAjcgMCyMv/y//L/8nIUAfPFhTLAFAEzxYB+gISyz/LB8zJ7VTgKoIQVEFTA7rjAjU4KIIQVEFTBLrjAjMHghBUQVMFuuMCXwjywG8FBgcA8joCwALy4GhRhscF8uBpBvoAMFIDu/LgaiHCAI4XUiJxcIAQyMsFUATPFlj6AhLLaskB+wCRMeIjcIMGcIAQyMsFUATPFlj6AhLLaskB+wAQNl4xcFA0cwMCyMv/y//L/8nIUAfPFhTLAFAEzxYB+gISyz/LB8zJ7VQAnjjAAPLga1EUxwXy4GwjcIMGcIAQyMsFUATPFlj6AhLLaskB+wAQNl4xcFA0dAMCyMv/y//L/8nIUAfPFhTLAFAEzxYB+gISyz/LB8zJ7VQAsiD4I7vy4G0mwAAnwAGxB8ACF7Hy4G4jcIMGcIAQyMsFUATPFlj6AhLLaskB+wAQNl4xcEMUdUMTAsjL/8v/y//JyFAHzxYUywBQBM8WAfoCEss/ywfMye1U";
pub const TASK_ACCEPT_OPCODE: u32 = 0x5441_5301;
pub const TASK_RESULT_OPCODE: u32 = 0x5441_5302;
pub const TASK_SETTLE_OPCODE: u32 = 0x5441_5303;
pub const TASK_CANCEL_OPCODE: u32 = 0x5441_5304;
pub const TASK_TIMEOUT_OPCODE: u32 = 0x5441_5305;

#[derive(Clone, Debug)]
pub struct TaskEscrowInit {
    pub creator: MsgAddressInt,
    pub assigned_agent: Option<MsgAddressInt>,
    pub budget: u64,
    pub deadline: u64,
    pub settlement_policy_hash: [u8; 32],
}

pub struct TaskEscrowContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskEscrowData {
    pub creator: MsgAddressInt,
    pub assigned_agent: Option<MsgAddressInt>,
    pub budget: u64,
    pub deadline: u64,
    pub status: u8,
    pub result_hash: [u8; 32],
    pub evidence_hash: [u8; 32],
    pub settlement_policy_hash: [u8; 32],
}

impl TaskEscrowContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(TASK_ESCROW_CODE_B64)?).map_err(Into::into)
    }

    pub fn build_data(init: &TaskEscrowInit) -> anyhow::Result<chain_block::Cell> {
        let agent = init.assigned_agent.as_ref().unwrap_or(&init.creator);
        let mut data = BuilderData::new();
        init.creator.write_to(&mut data)?;
        if init.assigned_agent.is_some() {
            data.append_bit_one()?;
        } else {
            data.append_bit_zero()?;
        }
        agent.write_to(&mut data)?;
        Coins::new(init.budget).write_to(&mut data)?;
        data.append_u64(init.deadline)?.append_u8(0)?;
        let mut hashes = BuilderData::new();
        hashes
            .append_u256(&[0; 32])?
            .append_u256(&[0; 32])?
            .append_u256(&init.settlement_policy_hash)?;
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
        Ok(TaskEscrowData {
            creator,
            assigned_agent,
            budget: stack.u64(3)?,
            deadline: stack.u64(4)?,
            status: stack.u64(5)? as u8,
            result_hash: parse_hash(stack, 6)?,
            evidence_hash: parse_hash(stack, 7)?,
            settlement_policy_hash: parse_hash(stack, 8)?,
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
            budget: 1_000_000_000,
            deadline: 1_800_000_000,
            settlement_policy_hash: [0x33; 32],
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
    fn decodes_task_data_stack() {
        let task = init();
        let creator_cell = task.creator.write_to_new_cell().unwrap().into_cell().unwrap();
        let creator_bytes = SliceData::load_cell(creator_cell).unwrap().get_bytestring(0);
        let agent = task.assigned_agent.as_ref().unwrap();
        let agent_cell = agent.write_to_new_cell().unwrap().into_cell().unwrap();
        let agent_bytes = SliceData::load_cell(agent_cell).unwrap().get_bytestring(0);
        let stack = TvmStackParser::new(vec![
            StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
                slice: slice::Slice { bytes: creator_bytes },
            }),
            StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
                slice: slice::Slice { bytes: agent_bytes },
            }),
            number("1"),
            number(task.budget.to_string()),
            number(task.deadline.to_string()),
            number("2"),
            hash_number([0x44; 32]),
            hash_number([0x55; 32]),
            hash_number(task.settlement_policy_hash),
        ]);
        let data = TaskEscrowContract::decode_data(&stack).unwrap();
        assert_eq!(data.creator, task.creator);
        assert_eq!(data.assigned_agent, task.assigned_agent);
        assert_eq!(data.budget, task.budget);
        assert_eq!(data.deadline, task.deadline);
        assert_eq!(data.status, 2);
        assert_eq!(data.result_hash, [0x44; 32]);
        assert_eq!(data.evidence_hash, [0x55; 32]);
        assert_eq!(data.settlement_policy_hash, task.settlement_policy_hash);
    }
}
