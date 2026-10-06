// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! SLH-only successor preparation. Encoding is not witness or fee approval.
//!
//! The caller must verify the exact module/metadata/vault pairing, current
//! deployment fee bounds, and both resulting deployments before migration.
//! Preparation has no wallet authority and grants no withdrawal of prior funds.
use crate::wallet_v5r2::{AuthRole, encode_pq_submission};
use chain_block::{BuilderData, Cell, Coins, IBitstring, Serializable};

pub struct PreparationBinding {
    pub global_id: i32,
    pub network: [u8; 32],
    pub wallet: [u8; 32],
    pub source_module: [u8; 32],
    pub valid_until: u32,
}

pub struct PreparationPlan {
    pub module_amount: u128,
    pub vault_amount: u128,
    pub module_init: Cell,
    pub metadata: Cell,
    pub vault_init: Cell,
}

/// Deployment amounts only; network compute/forwarding fees are additional.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparationAmounts {
    pub module: u128,
    pub vault: u128,
}

pub struct PreparationRequest {
    cell: Cell,
    digest: [u8; 32],
    deployment_value: u128,
}

impl PreparationRequest {
    /// Time is supplied from a fresh verified chain view. Positive canonical
    /// amounts are checked here; network-dependent fee floors/caps are not.
    pub fn new(
        binding: PreparationBinding,
        plan: PreparationPlan,
        proven_time: u32,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            binding.wallet != binding.source_module,
            "wallet and source module must differ"
        );
        let ttl = binding
            .valid_until
            .checked_sub(proven_time)
            .ok_or_else(|| anyhow::anyhow!("expired preparation deadline"))?;
        anyhow::ensure!((1..=3600).contains(&ttl), "preparation TTL must be 1..=3600 seconds");
        anyhow::ensure!(
            plan.module_amount > 0 && plan.vault_amount > 0,
            "deployment amounts must be positive"
        );
        let deployment_value = plan
            .module_amount
            .checked_add(plan.vault_amount)
            .ok_or_else(|| anyhow::anyhow!("deployment sum overflow"))?;
        let mut targets = BuilderData::new();
        plan.module_amount.to_string().parse::<Coins>()?.write_to(&mut targets)?;
        plan.vault_amount.to_string().parse::<Coins>()?.write_to(&mut targets)?;
        targets.checked_append_reference(plan.module_init)?;
        targets.checked_append_reference(plan.metadata)?;
        targets.checked_append_reference(plan.vault_init)?;
        let mut b = BuilderData::new();
        b.append_u32(0x50525033)?;
        b.append_i32(binding.global_id)?;
        b.append_u256(&binding.network)?;
        b.append_raw(&[0x80, 0], 11)?;
        b.append_u256(&binding.wallet)?;
        b.append_u256(&binding.source_module)?;
        b.append_u32(binding.valid_until)?;
        b.checked_append_reference(targets.into_cell()?)?;
        let cell = b.into_cell()?;
        let digest = *cell.repr_hash().as_array();
        Ok(Self { cell, digest, deployment_value })
    }
    pub fn cell(&self) -> &Cell {
        &self.cell
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn signing_context(&self) -> &'static [u8] {
        b"TOS-RESCUE-FEE-PREP-v1"
    }
    /// Sum of signed deployment amounts only; excludes compute/forwarding fees.
    pub fn deployment_value(&self) -> u128 {
        self.deployment_value
    }
    /// Exact SLH framing only, not cryptographic signature verification.
    pub fn encode_submission(&self, signature: &[u8]) -> anyhow::Result<Cell> {
        encode_pq_submission(0x46505233, &self.cell, AuthRole::Rescue, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hash(v: u8) -> [u8; 32] {
        let mut h = [0; 32];
        h[31] = v;
        h
    }
    fn binding() -> PreparationBinding {
        PreparationBinding {
            global_id: 42,
            network: hash(123),
            wallet: hash(100),
            source_module: hash(101),
            valid_until: 1_780_000_600,
        }
    }
    fn byte(v: u8) -> Cell {
        let mut b = BuilderData::new();
        b.append_u8(v).expect("byte");
        b.into_cell().expect("cell")
    }
    fn plan(a: u128, b: u128) -> PreparationPlan {
        PreparationPlan {
            module_amount: a,
            vault_amount: b,
            module_init: byte(1),
            metadata: byte(2),
            vault_init: byte(3),
        }
    }
    #[test]
    fn independent_preparation_vectors() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/v5r2/prepare-wire.json"))
                .expect("vectors");
        for c in cases.as_array().expect("array") {
            let a = c["module_amount"].as_str().expect("amount").parse::<u128>().expect("number");
            let b = c["vault_amount"].as_str().expect("amount").parse::<u128>().expect("number");
            let req =
                PreparationRequest::new(binding(), plan(a, b), 1_780_000_000).expect("request");
            assert_eq!(hex::encode(req.cell().repr_hash().as_array()), c["request_hash"]);
            assert_eq!(hex::encode(req.digest()), c["request_hash"]);
            assert_eq!(req.deployment_value(), a.checked_add(b).expect("sum"));
            assert_eq!(req.signing_context(), b"TOS-RESCUE-FEE-PREP-v1");
            let sub = req.encode_submission(&vec![0xa5; 7856]).expect("framing");
            assert_eq!(hex::encode(sub.repr_hash().as_array()), c["submission_hash"]);
            for len in [64, 2420, 7855, 7857] {
                assert!(req.encode_submission(&vec![0; len]).is_err());
            }
        }
    }
    #[test]
    fn distinct_parties_and_deadline() {
        let mut b = binding();
        b.source_module = b.wallet;
        assert!(PreparationRequest::new(b, plan(1, 1), 1_780_000_000).is_err());
        for delta in [-1i64, 0, 1, 3600, 3601] {
            let mut b = binding();
            b.valid_until = u32::try_from(1_780_000_000i64 + delta).expect("time");
            assert_eq!(
                PreparationRequest::new(b, plan(1, 1), 1_780_000_000).is_ok(),
                delta > 0 && delta <= 3600
            );
        }
    }
    #[test]
    fn amount_encoding_has_no_truncation_or_zero_deployment() {
        for (a, b) in [(0, 1), (1, 0), (1u128 << 120, 1), (1, 1u128 << 120), (u128::MAX, 1)] {
            assert!(PreparationRequest::new(binding(), plan(a, b), 1_780_000_000).is_err());
        }
    }
}
