/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::SmartContract;

/// Trait for interacting with multi-nominator pool smart contract
///
/// Multi-nominator pool wrapper
///
/// The multi-nominator pool contract allows multiple nominators to delegate
/// stake to a single validator. The validator earns a configurable reward share
/// (in basis points) from all nominator stakes.
#[async_trait::async_trait]
pub trait NominatorPoolWrapper: SmartContract + Send + Sync {
    /// Get the full pool data (parsed persistent storage)
    async fn get_pool_data(&self) -> anyhow::Result<NominatorPoolData>;
    /// Get data for a specific nominator by their 256-bit address
    async fn get_nominator_data(&self, nominator_addr: &[u8; 32]) -> anyhow::Result<NominatorData>;
    /// Check whether there are pending withdraw requests
    async fn has_withdraw_requests(&self) -> anyhow::Result<bool>;
}

/// Pool-wide data returned by get_pool_data()
#[derive(Debug, Clone, Default)]
pub struct NominatorPoolData {
    /// Pool state: 0=idle, 1=staking, 2=staked
    pub state: i32,
    /// Number of nominators currently in the pool
    pub nominators_count: u32,
    /// Stake amount sent to the elector
    pub stake_amount_sent: u64,
    /// Validator's own stake amount
    pub validator_amount: u64,
    /// Validator address (256-bit)
    pub validator_address: [u8; 32],
    /// Validator reward share in basis points (0-10000)
    pub validator_reward_share: u16,
    /// Maximum number of nominators allowed
    pub max_nominators_count: u16,
    /// Minimum stake required from the validator
    pub min_validator_stake: u64,
    /// Minimum stake required from each nominator
    pub min_nominator_stake: u64,
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
}

/// Data for a single nominator within the pool
#[derive(Debug, Clone, Default)]
pub struct NominatorData {
    /// Currently staked amount (in nanotos)
    pub amount: u64,
    /// Pending deposit not yet included in active stake
    pub pending_deposit: u64,
    /// Whether this nominator has a pending withdraw request
    pub withdraw_requested: bool,
}
