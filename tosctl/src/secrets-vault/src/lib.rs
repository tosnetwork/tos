/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
// SecretsVault - Cryptographic Key/Secrets Management Library

pub mod crypto;
pub mod errors;
pub mod events;
pub mod memory;
pub mod secret_input;
pub mod storage;
pub mod types;
pub mod utils;
pub mod vault;
pub mod vault_builder;

#[cfg(test)]
mod tests;

/// Held for their whole run by every test that spawns a child process or
/// relies on a Vault lock being released when its owner is dropped.
///
/// The Vault lock is flock on a sidecar file, and flock belongs to the open
/// file description. A child forked by one test duplicates every descriptor
/// of the test process until it execs, close-on-exec ones included, so a
/// Vault another test opened before that fork stays locked past its drop and
/// an immediate reopen fails. Serialising these tests closes that window; the
/// Vault's own locking is unchanged.
#[cfg(test)]
pub(crate) fn process_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
    GUARD.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub mod private_file;
