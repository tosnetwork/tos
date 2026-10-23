/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::SmartContract;
use chain_block::{Cell, MsgAddressInt, StateInit};

/// A message the elections driver has to send to a pool so the pool can make
/// progress, together with the reason it is needed.
///
/// These are not optimizations. A contract that tracks its own view of the
/// validator set, or that refuses to stake while a withdrawal is queued, will
/// simply sit still until something external nudges it, and a pool that sits
/// still is a pool whose depositors cannot get their principal back.
#[derive(Debug, Clone)]
pub struct PoolMaintenance {
    /// Why the message is required, for operator-facing logs.
    pub reason: &'static str,
    /// Message body to send to the pool address.
    pub body: Cell,
    /// Value to attach, in nanotos. Most of these only need gas, which the
    /// pool refunds; a top-up carries the funds themselves.
    pub value: u64,
}

/// Trait for interacting with single-nominator smart contract
///
/// Single nominator pool wrapper
///
/// The single-nominator contract provides secure validation for the blockchain
/// by separating the owner role (cold wallet) from the validator role (hot wallet).
#[async_trait::async_trait]
pub trait NominatorWrapper: SmartContract + Send + Sync {
    /// Get the owner and validator addresses stored in the contract
    async fn get_roles(&self) -> anyhow::Result<NominatorRoles>;
    /// Get pool data (parsed persistent storage of nominator)
    async fn get_pool_data(&self) -> anyhow::Result<PoolData>;
    /// Return the state_init used for deploying this contract (if available).
    fn state_init(&self) -> Option<StateInit> {
        None
    }

    /// Messages this contract needs before it can stake or recover, given the
    /// hash of the currently installed validator set.
    ///
    /// The single-nominator contract keeps no election bookkeeping of its own
    /// and needs none, which is why the default is empty.
    async fn maintenance(
        &self,
        current_validator_set_hash: &[u8; 32],
    ) -> anyhow::Result<Vec<PoolMaintenance>> {
        let _ = current_validator_set_hash;
        Ok(Vec::new())
    }
}

/// Roles stored in the single nominator contract
#[derive(Debug, Clone)]
pub struct NominatorRoles {
    /// Owner address (can add or withdraw funds to/from nominator)
    pub owner_address: MsgAddressInt,
    /// Validator address (can stake or recover funds to/from elector)
    pub validator_address: MsgAddressInt,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PoolConfig {
    pub validator_addr: [u8; 32],
    pub validator_reward_share: u16,
    pub max_nominators_count: u16,
    pub min_validator_stake: u64,
    pub max_nominators_stake: u64,
}
/// Pool data returned by get_pool_data()
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PoolData {
    /// Pool state (2 = funds staked at elector)
    pub state: i32,
    /// Number of nominators (always 1 for single nominator)
    pub nominators_count: u32,
    /// Stake amount sent (always 0 for single nominator)
    pub stake_amount_sent: u64,
    /// Validator amount (always 0 for single nominator)
    pub validator_amount: u64,
    /// Pool config
    pub pool_config: PoolConfig,
    /// Elections Id
    pub stake_at: u32,
    /// Saved validator set hash from config 34
    pub saved_validator_set_hash: [u8; 32],
    /// Validator set changes count (2 = funds staked at elector)
    pub validator_set_changes_count: i32,
    /// Validator set change time
    pub validator_set_change_time: u64,
    /// Stake held for duration
    pub stake_held_for: u64,
}
