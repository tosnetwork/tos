/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
pub mod election_task;
pub mod providers;
mod registration;
pub(crate) mod runner;

/// Registration deadline covering a postponed election and its full duty.
pub use registration::pending_until as pending_registration_until;
