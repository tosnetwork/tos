/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
/// Internal messages for liquid staking controller contract
mod messages;
/// Liquid staking controller contract implementation
mod controller_impl;
/// Trait for liquid staking controller contract
mod wrapper;

pub use controller_impl::ControllerWrapperImpl;
pub use wrapper::*;

/// Message builders for liquid staking controller operations
pub mod controller_messages {
    pub use super::messages::*;
}
