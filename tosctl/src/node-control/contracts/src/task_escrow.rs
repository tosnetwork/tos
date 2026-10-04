/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
use chain_block::{
    BuilderData, Coins, Deserializable, GasLimitsPrices, IBitstring, MsgAddressInt,
    MsgForwardPrices, Serializable, StateInit, base64_decode, read_single_root_boc,
};
use common::tvm_stack_parser::TvmStackParser;

pub const TASK_ESCROW_CODE_B64: &str = "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";
pub const TASK_ACCEPT_OPCODE: u32 = 0x5441_5301;
pub const TASK_RESULT_OPCODE: u32 = 0x5441_5302;
pub const TASK_SETTLE_OPCODE: u32 = 0x5441_5303;
pub const TASK_CANCEL_OPCODE: u32 = 0x5441_5304;
pub const TASK_TIMEOUT_OPCODE: u32 = 0x5441_5305;
pub const TASK_REJECT_OPCODE: u32 = 0x5441_5306;
pub const TASK_CLAIM_OPCODE: u32 = 0x5441_5307;
pub const TASK_DISPUTE_OPCODE: u32 = 0x5441_5308;
pub const TASK_RESOLVE_OPCODE: u32 = 0x5441_5309;
pub const TASK_ROTATE_ATTESTOR_KEY_OPCODE: u32 = 0x5441_530a;
pub const TASK_REVOKE_ATTESTOR_OPCODE: u32 = 0x5441_530b;
pub const TASK_DISPUTE_TIMEOUT_OPCODE: u32 = 0x5441_530c;

#[derive(Clone, Debug)]
pub struct TaskEscrowInit {
    pub creator: MsgAddressInt,
    pub assigned_agent: Option<MsgAddressInt>,
    /// Optional settlement authority allowed to settle alongside the creator.
    pub verifier: Option<MsgAddressInt>,
    pub budget: u64,
    pub deadline: u64,
    pub review_period: u32,
    pub settlement_policy_hash: [u8; 32],
    pub permission_hash: [u8; 32],
    /// Optional ed25519 public key. When set, `settle` additionally requires
    /// a signature over `result_hash` under this key -- on top of, never
    /// instead of, the existing creator/verifier sender authorization.
    pub attestor_pubkey: Option<[u8; 32]>,
    /// The agent's share, in basis points of the budget, when a dispute is
    /// still unresolved at its deadline; the creator receives the rest. Fixed
    /// before the agent claims or accepts the task.
    pub dispute_fallback_agent_bps: u16,
}

pub struct TaskEscrowContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskEscrowData {
    pub creator: MsgAddressInt,
    pub assigned_agent: Option<MsgAddressInt>,
    pub verifier: Option<MsgAddressInt>,
    pub budget: u64,
    pub deadline: u64,
    pub review_period: u32,
    pub review_deadline: u64,
    pub status: u8,
    pub result_hash: [u8; 32],
    pub evidence_hash: [u8; 32],
    pub settlement_policy_hash: [u8; 32],
    pub permission_hash: [u8; 32],
    pub dispute_hash: [u8; 32],
    pub attestor_pubkey: Option<[u8; 32]>,
    pub dispute_fallback_agent_bps: u16,
    /// When the fallback may end an open dispute; zero until one is raised.
    pub dispute_deadline: u64,
}

impl TaskEscrowContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(TASK_ESCROW_CODE_B64)?).map_err(Into::into)
    }

    /// The contract itself rejects `op::result` once a result is submitted
    /// against a shorter review window (see `err::review_period_too_short`)
    /// -- this mirrors that floor here so misconfigured deploys fail fast
    /// instead of only failing once the agent has already done the work.
    pub const MIN_REVIEW_PERIOD_SECS: u32 = 3_600;

    /// The fallback split a task carries unless its creator chooses another.
    pub const DEFAULT_DISPUTE_FALLBACK_AGENT_BPS: u16 = 5_000;
    /// The contract's `bps_denominator`.
    pub const BPS_DENOMINATOR: u16 = 10_000;
    /// How long after a dispute is raised the verifier alone may resolve it;
    /// the contract's `dispute_window`.
    pub const DISPUTE_WINDOW_SECS: u64 = 604_800;
    /// Gas any Task Escrow action may use at its widest valid inputs, with
    /// margin. `dispute_timeout` charges its caller for exactly this much
    /// (the contract's `dispute_timeout_gas`, which must stay equal).
    pub const MAX_ACTION_GAS: u64 = 20_000;

    /// The message value that pays for any Task Escrow action under these
    /// prices: [`Self::MAX_ACTION_GAS`] at the escrow's own gas price plus
    /// forwarding for the two value transfers a terminal action sends.
    /// tosctl attaches this unless told otherwise, and it covers what
    /// `dispute_timeout` requires.
    ///
    /// A transfer is priced at masterchain rates when either end is in the
    /// masterchain, and an escrow cannot know in advance where its payees
    /// live, so each transfer is priced at the dearest of the schedules
    /// given: pass the escrow's own workchain schedule and the masterchain's.
    pub fn action_value(
        gas: &GasLimitsPrices,
        transfer_schedules: &[&MsgForwardPrices],
    ) -> anyhow::Result<u64> {
        let transfer = transfer_schedules
            .iter()
            .map(|prices| prices.calc_fwd_fee(0, 0))
            .max()
            .ok_or_else(|| anyhow::anyhow!("no forwarding schedule to price a transfer"))?;
        let value = gas
            .calc_gas_fee(Self::MAX_ACTION_GAS)
            .checked_add(transfer)
            .and_then(|value| value.checked_add(transfer))
            .ok_or_else(|| anyhow::anyhow!("Task Escrow action value overflowed"))?;
        u64::try_from(value).map_err(|_| anyhow::anyhow!("Task Escrow action value exceeds uint64"))
    }

    pub fn build_data(init: &TaskEscrowInit) -> anyhow::Result<chain_block::Cell> {
        if init.review_period < Self::MIN_REVIEW_PERIOD_SECS {
            anyhow::bail!(
                "review_period must be at least {} seconds",
                Self::MIN_REVIEW_PERIOD_SECS
            );
        }
        if init.dispute_fallback_agent_bps > Self::BPS_DENOMINATOR {
            anyhow::bail!("dispute_fallback_agent_bps must be at most {}", Self::BPS_DENOMINATOR);
        }
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
        permission
            .append_u256(&init.permission_hash)?
            .append_u256(&[0; 32])?
            .append_u16(init.dispute_fallback_agent_bps)?
            .append_u64(0)?;
        hashes
            .append_u256(&[0; 32])?
            .append_u256(&[0; 32])?
            .append_u256(&init.settlement_policy_hash)?
            .append_u32(init.review_period)?
            .append_u64(0)?
            .checked_append_reference(permission.into_cell()?)?;
        let mut attestor = BuilderData::new();
        match init.attestor_pubkey {
            Some(pubkey) => {
                attestor.append_bit_one()?.append_raw(&pubkey, 256)?;
            }
            None => {
                attestor.append_bit_zero()?.append_raw(&[0; 32], 256)?;
            }
        }
        hashes.checked_append_reference(attestor.into_cell()?)?;
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
            review_period: stack.u64(12)? as u32,
            review_deadline: stack.u64(13)?,
            dispute_hash: parse_hash(stack, 14)?,
            attestor_pubkey: if stack.u64(15)? == 0 { None } else { Some(parse_hash(stack, 16)?) },
            dispute_fallback_agent_bps: u16::try_from(stack.u64(17)?)
                .map_err(|_| anyhow::anyhow!("dispute fallback share does not fit 16 bits"))?,
            dispute_deadline: stack.u64(18)?,
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

    /// Settle a task deployed with an `attestor_pubkey`: `signature` must be a
    /// valid ed25519 signature over the task's current `result_hash` under
    /// that key, or the contract rejects the message.
    pub fn settle_signed(
        query_id: u64,
        payout: u64,
        signature: &[u8; 64],
    ) -> anyhow::Result<chain_block::Cell> {
        message(TASK_SETTLE_OPCODE, query_id, |b| {
            Coins::new(payout).write_to(b)?;
            b.append_raw(signature, 512).map(|_| ())
        })
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

    pub fn claim(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(TASK_CLAIM_OPCODE, query_id, |_| Ok(()))
    }

    pub fn dispute(query_id: u64, dispute_hash: [u8; 32]) -> anyhow::Result<chain_block::Cell> {
        message(TASK_DISPUTE_OPCODE, query_id, |b| b.append_raw(&dispute_hash, 256).map(|_| ()))
    }

    pub fn resolve(query_id: u64, payout: u64) -> anyhow::Result<chain_block::Cell> {
        message(TASK_RESOLVE_OPCODE, query_id, |b| Coins::new(payout).write_to(b))
    }

    /// Resolve a disputed task deployed with an `attestor_pubkey`: `signature`
    /// must be a valid ed25519 signature over
    /// `attestation::resolve_domain_hash(contract_address, result_hash,
    /// dispute_hash, payout)` under that key, or the contract rejects the
    /// message.
    pub fn resolve_signed(
        query_id: u64,
        payout: u64,
        signature: &[u8; 64],
    ) -> anyhow::Result<chain_block::Cell> {
        message(TASK_RESOLVE_OPCODE, query_id, |b| {
            Coins::new(payout).write_to(b)?;
            b.append_raw(signature, 512).map(|_| ())
        })
    }

    /// Creator-only: set or replace the `attestor_pubkey` `settle` checks
    /// against. Purely local state -- no cross-contract messaging.
    pub fn rotate_attestor_key(
        query_id: u64,
        new_attestor_pubkey: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(TASK_ROTATE_ATTESTOR_KEY_OPCODE, query_id, |b| {
            b.append_raw(&new_attestor_pubkey, 256).map(|_| ())
        })
    }

    /// Creator-only: drop the attestation requirement -- `settle` reverts to
    /// sender-authorization-only until `rotate_attestor_key` is called again.
    pub fn revoke_attestor(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(TASK_REVOKE_ATTESTOR_OPCODE, query_id, |_| Ok(()))
    }

    /// Ends a dispute left unresolved past its deadline with the fallback
    /// split. Anyone may send it; the message value must cover the call's
    /// gas and the two payouts' forwarding fees.
    pub fn dispute_timeout(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(TASK_DISPUTE_TIMEOUT_OPCODE, query_id, |_| Ok(()))
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
        Number, StackEntry,
        numberdecimal::NumberDecimal,
        slice,
        stackentry::{StackEntryNumber, StackEntrySlice},
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
            review_period: 3_600,
            settlement_policy_hash: [0x33; 32],
            permission_hash: [0x77; 32],
            attestor_pubkey: None,
            dispute_fallback_agent_bps: TaskEscrowContract::DEFAULT_DISPUTE_FALLBACK_AGENT_BPS,
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
    fn rejects_zero_review_period() {
        let mut task = init();
        task.review_period = 0;
        let error = TaskEscrowContract::build_data(&task).unwrap_err();
        assert!(error.to_string().contains("review_period"));
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

    #[test]
    fn encodes_claim_message() {
        let body = TaskEscrowContract::claim(10).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), TASK_CLAIM_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 10);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn encodes_dispute_and_resolution_messages() {
        let dispute = TaskEscrowContract::dispute(11, [0x99; 32]).unwrap();
        let mut slice = SliceData::load_cell(dispute).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), TASK_DISPUTE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 11);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0x99; 32]);

        let resolve = TaskEscrowContract::resolve(12, 456_000).unwrap();
        let mut slice = SliceData::load_cell(resolve).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), TASK_RESOLVE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 12);
        assert_eq!(Coins::construct_from(&mut slice).unwrap().as_u128(), 456_000);
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
            number(task.review_period.to_string()),
            number("1234567890"),
            hash_number([0x88; 32]),
            number("1"),
            hash_number([0x99; 32]),
            number("3333"),
            number("1234999999"),
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
        assert_eq!(data.review_period, task.review_period);
        assert_eq!(data.review_deadline, 1_234_567_890);
        assert_eq!(data.dispute_hash, [0x88; 32]);
        assert_eq!(data.attestor_pubkey, Some([0x99; 32]));
        assert_eq!(data.dispute_fallback_agent_bps, 3_333);
        assert_eq!(data.dispute_deadline, 1_234_999_999);
    }

    #[test]
    fn a_fallback_share_above_the_budget_is_refused() {
        let mut task = init();
        task.dispute_fallback_agent_bps = TaskEscrowContract::BPS_DENOMINATOR;
        assert!(TaskEscrowContract::build_data(&task).is_ok());
        task.dispute_fallback_agent_bps = TaskEscrowContract::BPS_DENOMINATOR + 1;
        assert!(TaskEscrowContract::build_data(&task).is_err());
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
            number(task.review_period.to_string()),
            number("0"),
            hash_number([0; 32]),
            number("0"),
            hash_number([0; 32]),
            number("5000"),
            number("0"),
        ]);
        let data = TaskEscrowContract::decode_data(&stack).unwrap();
        assert_eq!(data.assigned_agent, None);
        assert_eq!(data.verifier, None);
        assert_eq!(data.status, 0);
        assert_eq!(data.review_deadline, 0);
        assert_eq!(data.attestor_pubkey, None);
    }
}
