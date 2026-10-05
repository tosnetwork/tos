// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Bind an authenticated fee vault to locally trusted initial or recovery enrollment.
//!
//! Genesis code pins and keys must come from the reviewed release and local
//! enrollment. This does not prove deployment of the wallet/module, successful
//! POP, transaction delivery, fee affordability or possession of signing keys.
use crate::lms_fee_schedule::{
    Continuity, FeeRoute, LEAF_COUNT, ReservationPlan, SLOT_SECONDS, plan_reservation,
};
use crate::proven_getters::ProvenAccountState;
use crate::wallet_v5r2_genesis::{SuccessorDeployment, WalletGenesis};
use chain_block::{Cell, CellType, SliceData};

/// A bounded observation, not permission to reuse a signature or reserve a leaf.
/// Construct again with fresh proofs/time before starting a signing operation.
pub struct ProvenFeeVault {
    route: FeeRoute,
    next_leaf: u32,
    proven_time: u32,
    config_hash: [u8; 32],
    master_time: u32,
    max_age: u32,
    fee_public_key: [u8; 60],
}

/// Compatibility name for callers binding initial enrollment.
pub type ProvenInitialFeeVault = ProvenFeeVault;

struct Enrollment<'a> {
    module_data: &'a Cell,
    metadata: &'a Cell,
    vault_data: &'a Cell,
    vault_init: &'a Cell,
    config_hash: &'a [u8; 32],
}

impl ProvenFeeVault {
    /// `now` is the trusted local clock, not endpoint-provided time. Both the
    /// masterchain and shard observation must be recent, and in the local
    /// current slot. Only live proofs may be used to start new signatures.
    /// `max_age` is local policy, strictly less than one fee slot.
    pub fn bind(
        state: &ProvenAccountState,
        genesis: &WalletGenesis,
        now: u32,
        max_age: u32,
    ) -> anyhow::Result<Self> {
        Self::bind_enrollment(
            state,
            Enrollment {
                module_data: genesis.module_data(),
                metadata: genesis.metadata(),
                vault_data: genesis.vault_data(),
                vault_init: genesis.vault_init(),
                config_hash: genesis.config_hash(),
            },
            now,
            max_age,
        )
    }

    /// Bind the proven successor vault to locally enrolled recovery witnesses.
    /// This proves vault identity/state, not preparation delivery, module POP,
    /// or installation in the wallet. Verify those separately before migration.
    pub fn bind_successor(
        state: &ProvenAccountState,
        successor: &SuccessorDeployment,
        now: u32,
        max_age: u32,
    ) -> anyhow::Result<Self> {
        Self::bind_enrollment(
            state,
            Enrollment {
                module_data: successor.module_data(),
                metadata: successor.metadata(),
                vault_data: successor.vault_data(),
                vault_init: successor.vault_init(),
                config_hash: successor.config_hash(),
            },
            now,
            max_age,
        )
    }

    fn bind_enrollment(
        state: &ProvenAccountState,
        genesis: Enrollment<'_>,
        now: u32,
        max_age: u32,
    ) -> anyhow::Result<Self> {
        let evidence = state.evidence();
        anyhow::ensure!(evidence.live, "fee signing requires a live proof");
        let vault = *genesis.vault_init.repr_hash().as_array();
        anyhow::ensure!(
            evidence.account.address == format!("0:{}", hex::encode(vault)),
            "proven vault address does not match enrollment"
        );
        let mut init = SliceData::load_cell(genesis.vault_init.clone())?;
        let code = init.checked_drain_reference()?;
        anyhow::ensure!(
            evidence.account.code_hash == code.repr_hash().to_hex_string(),
            "proven vault code does not match enrollment"
        );
        let data =
            state.account().get_data().ok_or_else(|| anyhow::anyhow!("vault has no data"))?;
        let next_leaf = checked_counter(&data, genesis.vault_data)?;
        let mut module = SliceData::load_cell(genesis.module_data.clone())?;
        module.get_next_byte()?;
        let global_id = i32::from_be_bytes(module.get_next_u32()?.to_be_bytes());
        let network = *module.get_next_hash()?.as_array();
        let mut metadata = SliceData::load_cell(genesis.metadata.clone())?;
        metadata.move_by(16)?;
        let tree_id = *metadata.get_next_hash()?.as_array();
        let epoch0 = metadata.get_next_u32()?;
        let key = metadata.checked_drain_reference()?;
        let mut key = SliceData::load_cell(key)?;
        let mut fee_public_key = [0; 60];
        key.get_next_bytes_to_slice(&mut fee_public_key)?;
        check_time(evidence.block_gen_utime, evidence.account.gen_utime, now, max_age, epoch0)?;
        Ok(Self {
            route: FeeRoute { global_id, network, vault, tree_id, epoch0 },
            next_leaf,
            proven_time: evidence.account.gen_utime,
            config_hash: *genesis.config_hash,
            master_time: evidence.block_gen_utime,
            max_age,
            fee_public_key,
        })
    }

    pub fn route(&self) -> FeeRoute {
        self.route
    }
    pub fn next_leaf(&self) -> u32 {
        self.next_leaf
    }
    pub fn proven_time(&self) -> u32 {
        self.proven_time
    }
    pub fn config_hash(&self) -> &[u8; 32] {
        &self.config_hash
    }

    pub fn fee_public_key(&self) -> &[u8; 60] {
        &self.fee_public_key
    }

    pub(crate) fn validate_freshness(&self, now: u32) -> anyhow::Result<()> {
        check_time(self.master_time, self.proven_time, now, self.max_age, self.route.epoch0)
    }

    /// Read-only proposal. The custody journal must still durably reserve the
    /// leaf before invoking a signing backend, including after failed sends.
    pub fn plan(&self, now: u32, continuity: Continuity) -> anyhow::Result<ReservationPlan> {
        self.validate_freshness(now)?;
        plan_reservation(self.route, self.proven_time, self.next_leaf, continuity)
            .map_err(|error| anyhow::anyhow!("fee reservation: {error:?}"))
    }
}

fn checked_counter(data: &Cell, expected: &Cell) -> anyhow::Result<u32> {
    anyhow::ensure!(
        data.cell_type() == CellType::Ordinary && data.level() == 0,
        "ordinary vault state required"
    );
    let mut actual = SliceData::load_cell(data.clone())?;
    let mut expected = SliceData::load_cell(expected.clone())?;
    anyhow::ensure!(actual.get_next_byte()? == 3, "vault state version");
    expected.move_by(8)?;
    let next = actual.get_next_u32()?;
    expected.move_by(32)?;
    anyhow::ensure!(next <= LEAF_COUNT, "invalid vault leaf counter");
    anyhow::ensure!(
        actual.into_cell()?.repr_hash() == expected.into_cell()?.repr_hash(),
        "vault immutable configuration mismatch"
    );
    Ok(next)
}

fn check_time(master: u32, shard: u32, now: u32, max_age: u32, epoch0: u32) -> anyhow::Result<()> {
    anyhow::ensure!((1..SLOT_SECONDS).contains(&max_age), "fee proof age policy out of range");
    let local_slot =
        now.checked_sub(epoch0).ok_or_else(|| anyhow::anyhow!("before fee epoch"))? / SLOT_SECONDS;
    for time in [master, shard] {
        let age = now
            .checked_sub(time)
            .ok_or_else(|| anyhow::anyhow!("fee proof time is in the future"))?;
        anyhow::ensure!(age <= max_age, "stale fee proof time");
        let slot =
            time.checked_sub(epoch0).ok_or_else(|| anyhow::anyhow!("proof before fee epoch"))?
                / SLOT_SECONDS;
        anyhow::ensure!(slot == local_slot, "fee proof is from another slot");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fee_time_policy() {
        assert!(check_time(4610, 4600, 4620, 30, 1000).is_ok());
        for (master, shard, now, age, reason) in [
            (4610, 4599, 4620, 30, "another slot"),
            (4599, 4610, 4620, 30, "another slot"),
            (4610, 4600, 4631, 30, "stale"),
            (4600, 4610, 4631, 30, "stale"),
            (4621, 4610, 4620, 30, "future"),
            (4610, 4621, 4620, 30, "future"),
            (4620, 4620, 4620, 0, "policy"),
            (4610, 4600, 4620, 3600, "policy"),
            (999, 999, 999, 30, "before fee epoch"),
        ] {
            let error =
                check_time(master, shard, now, age, 1000).expect_err("unsafe time accepted");
            assert!(error.to_string().contains(reason), "{error}");
        }
    }
}
