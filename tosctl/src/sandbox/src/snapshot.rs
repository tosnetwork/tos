/*
 * Copyright (C) 2025-2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! Blockchain state snapshots for save/restore in tests.

use chain_block::{Account, MsgAddressInt, Transaction};
use std::collections::HashMap;

/// A snapshot of the entire blockchain state that can be saved and restored.
///
/// # Example
/// ```ignore
/// let snap = bc.snapshot();
/// // ... do work ...
/// bc.restore(snap);  // roll back to saved state
/// ```
#[derive(Clone)]
pub struct BlockchainSnapshot {
    pub(crate) accounts: HashMap<String, Account>,
    pub(crate) next_lt: u64,
    pub(crate) block_unixtime: u32,
    pub(crate) transaction_log: Vec<(MsgAddressInt, Transaction)>,
}
