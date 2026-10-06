// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Initial recovery metadata, never current chain authority or fee signing state.
//! Reconstruct with independently pinned release code and the independently known
//! wallet address. Live authenticated state and funded POP are separate gates.
use crate::{
    wallet_v5r2_genesis::{CodeBundle, GenesisParameters, WalletGenesis},
    wallet_v5r2_pop::RescuePolicy,
};
use serde::{Deserialize, Serialize};

const SCHEMA: &str = "TOS-WALLET-V5R2-INITIAL-RECOVERY-v1";
const KDF: &str = "TOS-WALLET-DUALROOT-KDF-v1";
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024;

/// These are declared master-input formats, not proof of backup possession.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SeedProfile {
    #[serde(rename = "tos-native-mnemonic-v1")]
    NativeMnemonic,
    #[serde(rename = "raw-master-32-v1")]
    RawMaster32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDerivation {
    pub account_index: u32,
    pub key_generation: u32,
    pub primary_seed_profile: SeedProfile,
    pub rescue_seed_profile: SeedProfile,
    pub fee_seed_profile: SeedProfile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema: String,
    kdf: String,
    derivation: RecoveryDerivation,
    workchain: i32,
    global_id: i32,
    network: String,
    wallet_id: u32,
    primary_key: String,
    rescue_key: String,
    policy: String,
    fee_profile: String,
    fee_tree_id: String,
    fee_public_key: String,
    fee_epoch0: u32,
    wallet_code: String,
    module_code: String,
    vault_code: String,
    wallet_state_init: String,
    module_state_init: String,
    vault_state_init: String,
    fee_config_hash: String,
    // A display hint only. No request, signature or readiness decision uses it.
    last_observed_epoch: Option<u64>,
}

pub struct InitialRecoveryManifest {
    wire: Wire,
}

fn bytes<const N: usize>(value: &str) -> anyhow::Result<[u8; N]> {
    let decoded: [u8; N] =
        hex::decode(value)?.try_into().map_err(|_| anyhow::anyhow!("manifest field width"))?;
    anyhow::ensure!(hex::encode(decoded) == value, "manifest hex must be canonical lowercase");
    Ok(decoded)
}

impl InitialRecoveryManifest {
    /// Prepare public metadata without asserting possession, deployment or current
    /// authority. Callers retain these declared KDF inputs in authenticated backup.
    pub fn prepare(
        code: CodeBundle,
        parameters: GenesisParameters,
        derivation: RecoveryDerivation,
    ) -> anyhow::Result<(Self, WalletGenesis)> {
        let hashes = code.hashes();
        let g = WalletGenesis::new(code, parameters.clone())?;
        let wire = Wire {
            schema: SCHEMA.into(),
            kdf: KDF.into(),
            derivation,
            workchain: 0,
            global_id: parameters.global_id,
            network: hex::encode(parameters.network),
            wallet_id: parameters.wallet_id,
            primary_key: hex::encode(parameters.primary_key),
            rescue_key: hex::encode(parameters.rescue_key),
            policy: match parameters.policy {
                RescuePolicy::Ready => "RESCUE_READY",
                RescuePolicy::Required => "SLH_REQUIRED",
            }
            .into(),
            fee_profile: "HSS-L1-LMS-SHA256-M32-H20-LMOTS-SHA256-N32-W4".into(),
            fee_tree_id: hex::encode(parameters.fee_tree_id),
            fee_public_key: hex::encode(parameters.fee_public_key),
            fee_epoch0: parameters.epoch0,
            wallet_code: hex::encode(hashes.wallet),
            module_code: hex::encode(hashes.module),
            vault_code: hex::encode(hashes.vault),
            wallet_state_init: hex::encode(g.wallet_init().repr_hash().as_array()),
            module_state_init: hex::encode(g.module_init().repr_hash().as_array()),
            vault_state_init: hex::encode(g.vault_init().repr_hash().as_array()),
            fee_config_hash: hex::encode(g.config_hash()),
            last_observed_epoch: None,
        };
        Ok((Self { wire }, g))
    }

    pub fn to_json(&self) -> anyhow::Result<Vec<u8>> {
        let encoded = serde_json::to_vec(&self.wire)?;
        anyhow::ensure!(encoded.len() <= MAX_MANIFEST_BYTES, "manifest size limit");
        Ok(encoded)
    }

    pub fn derivation(&self) -> &RecoveryDerivation {
        &self.wire.derivation
    }

    /// Validate bounded strict metadata and reconstruct the initial identities.
    /// CodeBundle pins and expected_basechain_wallet must be independently trusted,
    /// not read from this same manifest. This does not validate an epoch hint or
    /// authorize restoring an old root after rotation; re-read authenticated state.
    pub fn parse_and_reconstruct(
        encoded: &[u8],
        code: CodeBundle,
        expected_basechain_wallet: [u8; 32],
    ) -> anyhow::Result<(Self, WalletGenesis)> {
        anyhow::ensure!(encoded.len() <= MAX_MANIFEST_BYTES, "manifest size limit");
        let wire: Wire = serde_json::from_slice(encoded)
            .map_err(|_| anyhow::anyhow!("invalid recovery manifest encoding"))?;
        anyhow::ensure!(wire.schema == SCHEMA && wire.kdf == KDF, "unsupported manifest profile");
        anyhow::ensure!(wire.workchain == 0, "manifest requires basechain");
        anyhow::ensure!(
            wire.fee_profile == "HSS-L1-LMS-SHA256-M32-H20-LMOTS-SHA256-N32-W4",
            "unsupported manifest fee profile"
        );
        let hashes = code.hashes();
        anyhow::ensure!(
            bytes::<32>(&wire.wallet_code)? == hashes.wallet
                && bytes::<32>(&wire.module_code)? == hashes.module
                && bytes::<32>(&wire.vault_code)? == hashes.vault,
            "manifest release code mismatch"
        );
        let policy = match wire.policy.as_str() {
            "RESCUE_READY" => RescuePolicy::Ready,
            "SLH_REQUIRED" => RescuePolicy::Required,
            _ => anyhow::bail!("unsupported manifest rescue policy"),
        };
        let g = WalletGenesis::new(
            code,
            GenesisParameters {
                global_id: wire.global_id,
                network: bytes(&wire.network)?,
                wallet_id: wire.wallet_id,
                primary_key: bytes(&wire.primary_key)?,
                rescue_key: bytes(&wire.rescue_key)?,
                policy,
                fee_tree_id: bytes(&wire.fee_tree_id)?,
                fee_public_key: bytes(&wire.fee_public_key)?,
                epoch0: wire.fee_epoch0,
            },
        )?;
        anyhow::ensure!(
            *g.wallet_init().repr_hash().as_array() == expected_basechain_wallet,
            "manifest wallet differs from trusted enrollment"
        );
        anyhow::ensure!(
            bytes::<32>(&wire.wallet_state_init)? == *g.wallet_init().repr_hash().as_array()
                && bytes::<32>(&wire.module_state_init)? == *g.module_init().repr_hash().as_array()
                && bytes::<32>(&wire.vault_state_init)? == *g.vault_init().repr_hash().as_array()
                && bytes::<32>(&wire.fee_config_hash)? == *g.config_hash(),
            "manifest reconstructed identity mismatch"
        );
        Ok((Self { wire }, g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_v5r2_genesis::tests::{bundle, parameters};
    fn fixture() -> (InitialRecoveryManifest, WalletGenesis) {
        InitialRecoveryManifest::prepare(
            bundle(),
            parameters(),
            RecoveryDerivation {
                account_index: 5,
                key_generation: 7,
                primary_seed_profile: SeedProfile::NativeMnemonic,
                rescue_seed_profile: SeedProfile::RawMaster32,
                fee_seed_profile: SeedProfile::NativeMnemonic,
            },
        )
        .unwrap()
    }
    #[test]
    fn manifest_roundtrip_reconstructs_genesis_without_trusting_observations() {
        let (manifest, genesis) = fixture();
        let expected = *genesis.wallet_init().repr_hash().as_array();
        let encoded = manifest.to_json().unwrap();
        let (decoded, rebuilt) =
            InitialRecoveryManifest::parse_and_reconstruct(&encoded, bundle(), expected).unwrap();
        assert_eq!(decoded.to_json().unwrap(), encoded);
        assert_eq!(decoded.derivation(), manifest.derivation());
        assert_eq!(rebuilt.wallet_init().repr_hash(), genesis.wallet_init().repr_hash());
        assert_eq!(rebuilt.module_init().repr_hash(), genesis.module_init().repr_hash());
        assert_eq!(rebuilt.vault_init().repr_hash(), genesis.vault_init().repr_hash());
        let mut hint: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        hint["last_observed_epoch"] = u64::MAX.into();
        let (_, unchanged) = InitialRecoveryManifest::parse_and_reconstruct(
            &serde_json::to_vec(&hint).unwrap(),
            bundle(),
            expected,
        )
        .unwrap();
        assert_eq!(unchanged.wallet_data().repr_hash(), genesis.wallet_data().repr_hash());
        assert_eq!(unchanged.vault_data().repr_hash(), genesis.vault_data().repr_hash());
        let mut required = parameters();
        required.policy = RescuePolicy::Required;
        let (manifest, genesis) =
            InitialRecoveryManifest::prepare(bundle(), required, manifest.derivation().clone())
                .unwrap();
        InitialRecoveryManifest::parse_and_reconstruct(
            &manifest.to_json().unwrap(),
            bundle(),
            *genesis.wallet_init().repr_hash().as_array(),
        )
        .unwrap();
    }

    #[test]
    fn manifest_rejects_profile_code_identity_and_trusted_wallet_changes() {
        let (manifest, genesis) = fixture();
        let expected = *genesis.wallet_init().repr_hash().as_array();
        let encoded = manifest.to_json().unwrap();
        let original: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        for field in ["schema", "kdf", "fee_profile", "policy"] {
            let mut changed = original.clone();
            changed[field] = "unsupported".into();
            assert!(
                InitialRecoveryManifest::parse_and_reconstruct(
                    &serde_json::to_vec(&changed).unwrap(),
                    bundle(),
                    expected
                )
                .is_err(),
                "manifest accepted changed {field}"
            );
        }
        let mut changed = original.clone();
        changed["workchain"] = (-1).into();
        assert!(
            InitialRecoveryManifest::parse_and_reconstruct(
                &serde_json::to_vec(&changed).unwrap(),
                bundle(),
                expected
            )
            .is_err(),
            "manifest accepted wrong workchain"
        );
        for field in [
            "wallet_code",
            "module_code",
            "vault_code",
            "wallet_state_init",
            "module_state_init",
            "vault_state_init",
            "fee_config_hash",
            "network",
            "rescue_key",
            "fee_tree_id",
        ] {
            let mut changed = original.clone();
            changed[field] = "ff".repeat(32).into();
            assert!(
                InitialRecoveryManifest::parse_and_reconstruct(
                    &serde_json::to_vec(&changed).unwrap(),
                    bundle(),
                    expected
                )
                .is_err(),
                "manifest accepted changed {field}"
            );
        }
        let mut other = expected;
        other[0] ^= 1;
        assert!(
            InitialRecoveryManifest::parse_and_reconstruct(&encoded, bundle(), other).is_err(),
            "manifest ignored trusted wallet"
        );
    }

    #[test]
    fn manifest_rejects_unknown_duplicate_oversized_and_noncanonical_inputs() {
        let (manifest, genesis) = fixture();
        let expected = *genesis.wallet_init().repr_hash().as_array();
        let encoded = manifest.to_json().unwrap();
        let original: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        for field in ["private_seed", "next_leaf", "ready"] {
            let mut changed = original.clone();
            changed[field] = true.into();
            assert!(
                InitialRecoveryManifest::parse_and_reconstruct(
                    &serde_json::to_vec(&changed).unwrap(),
                    bundle(),
                    expected
                )
                .is_err(),
                "manifest accepted unknown field"
            );
        }
        let mut changed = original.clone();
        changed["derivation"]["secret_seed"] = true.into();
        assert!(
            InitialRecoveryManifest::parse_and_reconstruct(
                &serde_json::to_vec(&changed).unwrap(),
                bundle(),
                expected
            )
            .is_err(),
            "manifest accepted unknown derivation field"
        );
        let mut changed = original.clone();
        changed["derivation"]["primary_seed_profile"] = "ed25519".into();
        assert!(
            InitialRecoveryManifest::parse_and_reconstruct(
                &serde_json::to_vec(&changed).unwrap(),
                bundle(),
                expected
            )
            .is_err()
        );
        let mut changed = original.clone();
        changed["primary_key"] = "00".into();
        assert!(
            InitialRecoveryManifest::parse_and_reconstruct(
                &serde_json::to_vec(&changed).unwrap(),
                bundle(),
                expected
            )
            .is_err()
        );
        let mut changed = original.clone();
        changed["wallet_code"] = changed["wallet_code"].as_str().unwrap().to_uppercase().into();
        assert!(
            InitialRecoveryManifest::parse_and_reconstruct(
                &serde_json::to_vec(&changed).unwrap(),
                bundle(),
                expected
            )
            .is_err(),
            "manifest accepted noncanonical hex"
        );
        let duplicate =
            String::from_utf8(encoded.clone()).unwrap().replacen('{', "{\"workchain\":0,", 1);
        assert!(
            InitialRecoveryManifest::parse_and_reconstruct(
                duplicate.as_bytes(),
                bundle(),
                expected
            )
            .is_err()
        );
        let mut oversized = encoded;
        oversized.resize(MAX_MANIFEST_BYTES + 1, b' ');
        assert!(
            InitialRecoveryManifest::parse_and_reconstruct(&oversized, bundle(), expected).is_err(),
            "manifest accepted oversized input"
        );
    }
}
