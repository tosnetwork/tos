/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
use chain_block::{
    base64_decode, read_single_root_boc, BuilderData, Coins, IBitstring, MsgAddressInt,
    Serializable, StateInit,
};

pub const TASK_ESCROW_CODE_B64: &str = "te6ccgECCAEAAioAART/APSkE/S88sgLAQIBYgIDAvjQMiHHAJFb4AHTH9M/Me1E0PpA0wD6QPoA0z/TB9P/0//T/9EL0HTXIfpAMCqCEFRBUwG6jjs5OQHAAPLgZATAAFJkxwUTsfLgZRA2fwVDRnFDE8hQCc8WFsoAUAbPFlAD+gLLP8sHEsv/y//L/8ntVOAqghBUQVMCuuMCBAUAMaEhbdqJofSB9IGmAfQBpn+mD6f/p/+n/mEAfjpbwAHy4GZRYscFUjCw8uBnBNP/0/8wEEdeMhA0ECNyA8hQCc8WFsoAUAbPFlAD+gLLP8sHEsv/y//L/8ntVAH2KoIQVEFTA7qObjoCwALy4GhRhscF8uBpBvoAMFMCu/LgalMwcIAQyMsFUAPPFgH6AstqyYMG+wASoVJAcIAQyMsFUAPPFgH6AstqyYMG+wAQNl4xcFA0c1UgyFAJzxYWygBQBs8WUAP6Ass/ywcSy//L/8v/ye1U4DkpBgHMghBUQVMEuo5MOQHAAPLga1FlxwXy4GxSQnCAEMjLBVADzxYB+gLLasmDBvsAEDZeMXBQNHRQM8hQCc8WFsoAUAbPFlAD+gLLP8sHEsv/y//L/8ntVOA4CIIQVEFTBbrjAl8J8sBvBwCmIfgju/LgbSDAACHAAbEBwAKx8uBuUkJwgBDIywVQA88WAfoCy2rJgwb7ABA2XjFwUDR1VSDIUAnPFhbKAFAGzxZQA/oCyz/LBxLL/8v/y//J7VQ=";
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
        data.append_u64(init.deadline)?
            .append_u8(0)?
            .append_u256(&[0; 32])?
            .append_u256(&[0; 32])?
            .append_raw(&init.settlement_policy_hash, 256)?;
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &TaskEscrowInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(wc: i32, init: &TaskEscrowInit) -> anyhow::Result<MsgAddressInt> {
        let cell = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(wc, cell.hash(0))?)
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

fn message<F>(opcode: u32, query_id: u64, append: F) -> anyhow::Result<chain_block::Cell>
where
    F: FnOnce(&mut BuilderData) -> anyhow::Result<()>,
{
    let mut body = BuilderData::new();
    body.append_u32(opcode)?.append_u64(query_id)?;
    append(&mut body)?;
    Ok(body.into_cell()?)
}
