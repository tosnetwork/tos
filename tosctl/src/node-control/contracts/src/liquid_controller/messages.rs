/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use chain_block::{BuilderData, Cell, IBitstring};

/// Opcodes for liquid staking controller contract messages
///
/// Source of truth: crypto/smartcont/liquid-staking/op-codes.func
pub mod opcodes {
    /// Top-up controller balance (controller::top_up)
    pub const TOP_UP: u32 = 0xd372158c;
    /// Withdraw funds from the controller (controller::withdraw_validator)
    pub const WITHDRAW: u32 = 0x8efed779;
    /// Update validator set hash (controller::update_validator_hash)
    pub const UPDATE_VALIDATOR_HASH: u32 = 0xf0fd2250;
    /// Recover stake from the elector (controller::recover_stake)
    pub const RECOVER_STAKE: u32 = 0xeb373a05;
    /// Return unused loan to pool (controller::return_unused_loan)
    pub const RETURN_UNUSED_LOAN: u32 = 0xed7378a6;
}

/// Build top-up message body
///
/// Sends coins to the controller. The controller accepts any incoming
/// transfer with op=0 as a simple top-up.
pub fn top_up(query_id: u64) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(opcodes::TOP_UP)?.append_u64(query_id)?;
    Ok(b.into_cell()?)
}

/// Build withdraw message body
///
/// Withdraws the specified amount from the controller back to the caller.
pub fn withdraw(query_id: u64, amount: u64) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(opcodes::WITHDRAW)?.append_u64(query_id)?.append_u64(amount)?;
    Ok(b.into_cell()?)
}

/// Build update validator hash message body
///
/// Triggers the controller to update its saved validator set hash,
/// advancing its election cycle state machine.
pub fn update_validator_hash(query_id: u64) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(opcodes::UPDATE_VALIDATOR_HASH)?.append_u64(query_id)?;
    Ok(b.into_cell()?)
}

/// Build recover stake message body
///
/// Recovers stake from the elector after a validation cycle ends.
pub fn recover_stake(query_id: u64) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(opcodes::RECOVER_STAKE)?.append_u64(query_id)?;
    Ok(b.into_cell()?)
}

/// Build return_unused_loan message body
///
/// Returns an unused loan (borrowed funds) back to the liquid staking pool.
/// Can only be called when the controller is in REST state with an outstanding
/// loan, and the borrowing round has ended (current validator set changed).
pub fn return_unused_loan(query_id: u64) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(opcodes::RETURN_UNUSED_LOAN)?.append_u64(query_id)?;
    Ok(b.into_cell()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::SliceData;

    #[test]
    fn test_build_top_up() {
        let query_id = 12345u64;

        let cell = top_up(query_id).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::TOP_UP);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn test_build_withdraw() {
        let query_id = 67890u64;
        let amount = 5_000_000_000u64;

        let cell = withdraw(query_id, amount).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::WITHDRAW);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        let parsed_amount = slice.get_next_u64().unwrap();
        assert_eq!(parsed_amount, amount);

        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn test_build_update_validator_hash() {
        let query_id = 11111u64;

        let cell = update_validator_hash(query_id).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::UPDATE_VALIDATOR_HASH);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn test_build_recover_stake() {
        let query_id = 33333u64;

        let cell = recover_stake(query_id).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::RECOVER_STAKE);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn test_build_return_unused_loan() {
        let query_id = 44444u64;

        let cell = return_unused_loan(query_id).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::RETURN_UNUSED_LOAN);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        assert_eq!(slice.remaining_bits(), 0);
    }
}
