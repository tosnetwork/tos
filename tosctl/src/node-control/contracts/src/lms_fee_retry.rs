// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Re-export an existing signature after checking current proof-bound delivery gates.
use super::{FeeJournal, SignedFeeMessage};
use crate::{
    lms_fee_schedule::{LEAVES_PER_SLOT, SLOT_SECONDS},
    wallet_v5r2_fee::FeeIntent,
    wallet_v5r2_state::ProvenFeeVault,
};

impl FeeJournal {
    /// Return exactly the cached body, without loading a secret or reserving a
    /// leaf. A restart barrier forbids new signatures, not immutable retries.
    /// Current proof, route, expiry and chain consumption are checked here;
    /// callers still check funding/admission, current inner authorization and
    /// authenticated delivery. Rejection is not proof of failed delivery.
    pub fn retry_proven_fee(
        &mut self,
        view: &ProvenFeeVault,
        now: u32,
        intent: &FeeIntent,
    ) -> anyhow::Result<SignedFeeMessage> {
        view.validate_freshness(now)?;
        anyhow::ensure!(self.route == view.route(), "retry fee route mismatch");
        anyhow::ensure!(
            view.proven_time() >= self.state.last_proven_time,
            "retry proof regressed behind journal"
        );
        let binding = intent.binding();
        anyhow::ensure!(
            binding.vault == self.route.vault
                && binding.config_hash == *view.config_hash()
                && binding.epoch0 == self.route.epoch0,
            "retry fee intent enrollment mismatch"
        );
        let ttl = binding
            .valid_until
            .checked_sub(now)
            .ok_or_else(|| anyhow::anyhow!("retry fee deadline expired"))?;
        anyhow::ensure!((1..=SLOT_SECONDS).contains(&ttl), "retry fee deadline expired");
        let slot = now
            .checked_sub(self.route.epoch0)
            .ok_or_else(|| anyhow::anyhow!("retry before fee epoch"))?
            / SLOT_SECONDS;
        let age = slot
            .checked_sub(binding.leaf / LEAVES_PER_SLOT)
            .ok_or_else(|| anyhow::anyhow!("retry fee leaf is in future slot"))?;
        anyhow::ensure!(age <= 1, "retry fee leaf outside delivery slots");
        anyhow::ensure!(
            binding.leaf >= view.next_leaf(),
            "retry fee leaf already consumed on chain"
        );
        let signature =
            self.cached_signature_verified(view.fee_public_key(), binding.leaf, *intent.digest())?;
        let body = intent.encode_external(&signature)?;
        Ok(SignedFeeMessage { vault: self.route.vault, intent: intent.clone(), body })
    }
}
