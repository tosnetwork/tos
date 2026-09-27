/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
/// Verified birth witness for a controller's first PQ stake.
mod controller_birth;
/// Internal messages for single nominator contract
mod messages;
/// Single nominator contract implementation
mod single_nominator;
/// Trait for single nominator contract
mod wrapper;

pub use controller_birth::{
    new_stake_from_birth_artifact, new_stake_with_verified_controller_birth,
    require_live_controller_admission, verified_controller_birth_witness,
};
pub use messages::*;
pub use single_nominator::{NOMINATOR_POOL_WORKCHAIN, NominatorWrapperImpl};
pub use wrapper::*;
