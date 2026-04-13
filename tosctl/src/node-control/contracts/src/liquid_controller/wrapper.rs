/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::SmartContract;

/// Trait for interacting with a liquid staking controller smart contract
///
/// Liquid staking controller wrapper
///
/// The controller contract manages a validator's participation in a liquid
/// staking pool. Two controllers (even/odd) are used in rotation across
/// election cycles.
#[async_trait::async_trait]
pub trait ControllerWrapper: SmartContract + Send + Sync {
    /// Get the full controller data (parsed persistent storage)
    async fn get_controller_data(&self) -> anyhow::Result<ControllerData>;

    /// Query required_balance_for_loan(credit, interest) get-method
    ///
    /// Returns (required_balance, validator_amount) in nanotos.
    /// - `credit`: desired loan amount in nanotos
    /// - `interest`: interest rate in basis points (SHARE_BASIS = 65536)
    async fn required_balance_for_loan(
        &self,
        credit: u64,
        interest: u64,
    ) -> anyhow::Result<LoanBalanceRequirement>;
}

/// Result of the `required_balance_for_loan` get-method
#[derive(Debug, Clone, Default)]
pub struct LoanBalanceRequirement {
    /// Minimum balance required (storage + fines + elector fine + interest payment)
    pub required_balance: u64,
    /// Validator's own funds (balance minus borrowed_amount)
    pub validator_amount: u64,
}

/// Controller-wide data returned by get_validator_controller_data()
#[derive(Debug, Clone, Default)]
pub struct ControllerData {
    /// Controller state: 0=ready, 1=staking, 2=staked
    pub state: i32,
    /// Whether the controller is halted
    pub halted: bool,
    /// Whether the controller is approved by the pool
    pub approved: bool,
    /// Stake amount sent to the elector
    pub stake_amount_sent: u64,
    /// Elections id (stake_at from elector)
    pub stake_at: u32,
    /// Saved validator set hash from config 34
    pub saved_validator_set_hash: [u8; 32],
    /// Validator set changes count
    pub validator_set_changes_count: i32,
    /// Validator set change time
    pub validator_set_change_time: u64,
    /// Duration that stake is held for
    pub stake_held_for: u64,
    /// Amount borrowed from the liquid pool
    pub borrowed_amount: u64,
    /// Timestamp when the borrow was made
    pub borrowing_time: u64,
}
