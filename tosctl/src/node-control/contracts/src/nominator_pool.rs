/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
/// Internal messages for multi-nominator pool contract
mod messages;
/// Multi-nominator pool contract implementation
mod pool_impl;
/// Trait for multi-nominator pool contract
mod wrapper;

pub use pool_impl::NominatorPoolWrapperImpl;
pub use wrapper::*;

/// Message builders for multi-nominator pool operations
pub mod pool_messages {
    pub use super::messages::*;
}
