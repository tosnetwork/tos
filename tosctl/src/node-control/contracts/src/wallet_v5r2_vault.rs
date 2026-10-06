// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Vault-backed signing through authenticated V5R2 state gates. This does not
//! approve actions, reserve counters, submit messages or establish finality.
use crate::{
    proven_getters::ProvenAccountState, wallet_v5r2::AuthAction,
    wallet_v5r2_wallet_state::ProvenWalletState,
};
use chain_block::Cell;
use secrets_vault::{types::secret_id::SecretId, vault::SecretVault};
use wallet_pq_signer::{Role, vault::load_bound};

/// Borrow an authenticated encrypted custody session and its chosen record ID.
/// PRIMARY and RESCUE device separation remains the application's responsibility.
pub struct VaultKey<'a> {
    pub vault: &'a SecretVault,
    pub id: &'a SecretId,
}

fn checked_time(before: u32, after: u32) -> anyhow::Result<u32> {
    anyhow::ensure!(after >= before, "clock regressed while loading PQ custody");
    Ok(after)
}

impl VaultKey<'_> {
    /// Caller approves actions and provides a trusted current-time source. The
    /// clock is sampled before and after the asynchronous secret load. Both
    /// validation passes use the same immutable authenticated state snapshot.
    pub async fn sign_primary(
        &self,
        view: &ProvenWalletState,
        policy: &ProvenAccountState,
        mut clock: impl FnMut() -> anyhow::Result<u32>,
        valid_until: u32,
        actions: Cell,
    ) -> anyhow::Result<Cell> {
        let before = clock()?;
        view.primary_request(policy, before, valid_until, actions.clone())?;
        let mut signer =
            load_bound(self.vault, self.id, Role::Primary, view.primary_public_key()).await?;
        let after = checked_time(before, clock()?)?;
        view.sign_primary_submission(policy, after, valid_until, actions, &mut signer)
    }

    /// Ordinary rescue AUTH only. Migration must use the funded dual-POP gate;
    /// this convenience API cannot authorize migration from a seed record alone.
    pub async fn sign_rescue(
        &self,
        view: &ProvenWalletState,
        mut clock: impl FnMut() -> anyhow::Result<u32>,
        valid_until: u32,
        action: AuthAction,
    ) -> anyhow::Result<Cell> {
        anyhow::ensure!(
            !matches!(action, AuthAction::Migrate { .. }),
            "migration signing requires both funded POPs"
        );
        let before = clock()?;
        view.rescue_request(before, valid_until, action.clone())?;
        let mut signer =
            load_bound(self.vault, self.id, Role::Rescue, view.rescue_public_key()).await?;
        let after = checked_time(before, clock()?)?;
        view.sign_rescue_submission(after, valid_until, action, &mut signer)
    }
}
