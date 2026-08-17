/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use chain_block::{BuilderData, Cell, IBitstring};

/// Opcodes for multi-nominator pool contract messages
pub mod opcodes {
    /// Accept an inbound transfer without changing pool accounting.
    pub const ACCEPT_COINS: u32 = 0x01;
    /// Process pending withdraw requests
    pub const PROCESS_WITHDRAW_REQUESTS: u32 = 0x02;
    /// Validator deposit (add validator's own stake)
    pub const VALIDATOR_DEPOSIT: u32 = 0x04;
    /// Withdraw validator funds from the pool
    pub const VALIDATOR_WITHDRAW: u32 = 0x05;
    /// Update validator set (trigger election cycle processing)
    pub const UPDATE_VALIDATOR_SET: u32 = 0x06;
    /// Recover stake from the elector
    pub const RECOVER_STAKE: u32 = 0x47657424;
}

/// Build the canonical no-op transfer body used while deploying a pool.
///
/// The pool contract always reads an opcode and query id.  An empty body
/// aborts with a cell-underflow error and leaves the account uninitialized.
pub fn accept_coins(query_id: u64) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(opcodes::ACCEPT_COINS)?.append_u64(query_id)?;
    Ok(b.into_cell()?)
}

/// Build validator deposit message body
///
/// Allows the validator to deposit their own stake into the pool.
pub fn validator_deposit(query_id: u64) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(opcodes::VALIDATOR_DEPOSIT)?.append_u64(query_id)?;
    Ok(b.into_cell()?)
}

/// Build validator withdraw message body
///
/// Allows the validator to withdraw their funds from the pool.
pub fn validator_withdraw(query_id: u64, amount: u64) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(opcodes::VALIDATOR_WITHDRAW)?.append_u64(query_id)?.append_u64(amount)?;
    Ok(b.into_cell()?)
}

/// Build update validator set message body
///
/// Triggers the pool to process a validator set change, advancing the
/// election cycle state machine.
pub fn update_validator_set(query_id: u64) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(opcodes::UPDATE_VALIDATOR_SET)?.append_u64(query_id)?;
    Ok(b.into_cell()?)
}

/// Build process withdraw requests message body
///
/// Processes up to `limit` pending withdraw requests from nominators.
pub fn process_withdraw_requests(query_id: u64, limit: u8) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(opcodes::PROCESS_WITHDRAW_REQUESTS)?.append_u64(query_id)?.append_u8(limit)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::SliceData;

    #[test]
    fn test_build_accept_coins() {
        let cell = accept_coins(42).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        assert_eq!(slice.get_next_u32().unwrap(), opcodes::ACCEPT_COINS);
        assert_eq!(slice.get_next_u64().unwrap(), 42);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn test_build_validator_deposit() {
        let query_id = 12345u64;

        let cell = validator_deposit(query_id).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::VALIDATOR_DEPOSIT);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn test_build_validator_withdraw() {
        let query_id = 67890u64;
        let amount = 5_000_000_000u64;

        let cell = validator_withdraw(query_id, amount).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::VALIDATOR_WITHDRAW);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        let parsed_amount = slice.get_next_u64().unwrap();
        assert_eq!(parsed_amount, amount);

        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn test_build_update_validator_set() {
        let query_id = 11111u64;

        let cell = update_validator_set(query_id).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::UPDATE_VALIDATOR_SET);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn test_build_process_withdraw_requests() {
        let query_id = 22222u64;
        let limit = 10u8;

        let cell = process_withdraw_requests(query_id, limit).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::PROCESS_WITHDRAW_REQUESTS);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        let parsed_limit = slice.get_next_byte().unwrap();
        assert_eq!(parsed_limit, limit);

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
}
