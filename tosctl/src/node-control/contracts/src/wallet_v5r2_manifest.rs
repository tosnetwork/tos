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
#[cfg(feature = "native-wallet-signer")]
#[path = "wallet_v5r2_manifest_fee.rs"]
mod fee_recovery;

fn bytes<const N: usize>(value: &str) -> anyhow::Result<[u8; N]> {
    let decoded: [u8; N] =
        hex::decode(value)?.try_into().map_err(|_| anyhow::anyhow!("manifest field width"))?;
    anyhow::ensure!(hex::encode(decoded) == value, "manifest hex must be canonical lowercase");
    Ok(decoded)
}

#[cfg(feature = "native-wallet-signer")]
struct Wipe<'a>(&'a mut [u8]);
#[cfg(feature = "native-wallet-signer")]
impl Drop for Wipe<'_> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
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

    /// Check a resolved master against the initial enrolled role, wiping it on
    /// every return. Native mnemonic validation must precede this call when that
    /// input profile is selected. Success proves only the initial key binding;
    /// it neither returns a signer nor authorizes a retired key or fee-tree reuse.
    #[cfg(feature = "native-wallet-signer")]
    pub fn verify_initial_master_and_wipe(
        &self,
        master: &mut [u8],
        role: wallet_pq_signer::Role,
        input_profile: SeedProfile,
    ) -> anyhow::Result<()> {
        use wallet_pq_signer::{
            Role,
            kdf::{DerivationContext, derive_signer_and_wipe},
        };
        let master = Wipe(master);
        let (profile, expected) = match role {
            Role::Primary => (self.wire.derivation.primary_seed_profile, &self.wire.primary_key),
            Role::Rescue => (self.wire.derivation.rescue_seed_profile, &self.wire.rescue_key),
        };
        anyhow::ensure!(profile == input_profile, "recovery input profile mismatch");
        let context = DerivationContext {
            network: bytes(&self.wire.network)?,
            global_id: self.wire.global_id,
            account_index: self.wire.derivation.account_index,
            key_generation: self.wire.derivation.key_generation,
        };
        let signer = derive_signer_and_wipe(master.0, context, role)?;
        anyhow::ensure!(
            hex::encode(signer.public_key()) == *expected,
            "recovered key differs from initial enrollment"
        );
        Ok(())
    }

    /// Persist a recovered initial role in an already authenticated, exclusively
    /// owned encrypted Vault. No signing handle or current-authority claim is
    /// returned. The guard is installed synchronously, including unpolled Drop.
    /// Uncertain writes must be preserved; no overwrite or automatic cleanup.
    #[cfg(feature = "native-wallet-vault")]
    pub fn restore_initial_master_to_vault<'a>(
        &'a self,
        vault: &'a secrets_vault::vault::SecretVault,
        id: &'a secrets_vault::types::secret_id::SecretId,
        master: &'a mut [u8],
        role: wallet_pq_signer::Role,
        input_profile: SeedProfile,
    ) -> impl std::future::Future<Output = anyhow::Result<Vec<u8>>> + 'a {
        let master = Wipe(master);
        async move {
            use wallet_pq_signer::{Role, kdf::DerivationContext, vault::restore_derived_and_wipe};
            let d = &self.wire.derivation;
            let (declared, key) = match role {
                Role::Primary => (d.primary_seed_profile, &self.wire.primary_key),
                Role::Rescue => (d.rescue_seed_profile, &self.wire.rescue_key),
            };
            anyhow::ensure!(declared == input_profile, "vault recovery input profile mismatch");
            let context = DerivationContext {
                network: bytes(&self.wire.network)?,
                global_id: self.wire.global_id,
                account_index: d.account_index,
                key_generation: d.key_generation,
            };
            let expected = hex::decode(key)?;
            let signer =
                restore_derived_and_wipe(vault, id, role, master.0, context, &expected).await?;
            Ok(signer.public_key().to_vec())
        }
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
    fn mobile_public_manifest_matches_rust_wire_and_initial_identities() {
        let encoded = include_bytes!("../tests/fixtures/v5r2/initial-recovery-mobile.json");
        let expected =
            bytes::<32>("017b4078cbfce4b21954669c79ed5f9785176eae6518e8f3bb9448ed2ab12b46")
                .expect("independently frozen wallet identity");
        let (parsed, genesis) =
            InitialRecoveryManifest::parse_and_reconstruct(encoded, bundle(), expected)
                .expect("mobile public manifest");
        assert_eq!(genesis.wallet_init().repr_hash().as_array(), &expected);
        assert_eq!(parsed.wire.last_observed_epoch, Some(u64::MAX));
        let original: serde_json::Value =
            serde_json::from_slice(encoded).expect("public fixture JSON");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&parsed.to_json().expect("export"))
                .expect("JSON"),
            original
        );
        let (prepared, _) = InitialRecoveryManifest::prepare(
            bundle(),
            parameters(),
            RecoveryDerivation {
                account_index: 0,
                key_generation: 0,
                primary_seed_profile: SeedProfile::RawMaster32,
                rescue_seed_profile: SeedProfile::RawMaster32,
                fee_seed_profile: SeedProfile::RawMaster32,
            },
        )
        .expect("Rust public preparation");
        let mut no_hint = original;
        no_hint["last_observed_epoch"] = serde_json::Value::Null;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&prepared.to_json().expect("export"))
                .expect("JSON"),
            no_hint
        );
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

#[cfg(all(test, feature = "native-wallet-signer"))]
mod recovery_tests {
    use super::*;
    use crate::wallet_v5r2_genesis::tests::{bundle, parameters};
    use wallet_pq_signer::{
        Role,
        kdf::{DerivationContext, derive_signer_and_wipe},
    };

    #[test]
    fn recovered_master_matches_initial_enrollment_and_is_wiped() {
        let mut p = parameters();
        let context = DerivationContext {
            network: p.network,
            global_id: p.global_id,
            account_index: 5,
            key_generation: 7,
        };
        let primary = derive_signer_and_wipe(&mut [11; 32], context, Role::Primary).unwrap();
        let rescue = derive_signer_and_wipe(&mut [22; 32], context, Role::Rescue).unwrap();
        p.primary_key.copy_from_slice(primary.public_key());
        p.rescue_key.copy_from_slice(rescue.public_key());
        let (manifest, g) = InitialRecoveryManifest::prepare(
            bundle(),
            p,
            RecoveryDerivation {
                account_index: 5,
                key_generation: 7,
                primary_seed_profile: SeedProfile::RawMaster32,
                rescue_seed_profile: SeedProfile::NativeMnemonic,
                fee_seed_profile: SeedProfile::RawMaster32,
            },
        )
        .unwrap();
        let encoded = manifest.to_json().unwrap();
        let expected = *g.wallet_init().repr_hash().as_array();
        let (manifest, _) =
            InitialRecoveryManifest::parse_and_reconstruct(&encoded, bundle(), expected).unwrap();
        for (role, seed, profile, wrong_profile) in [
            (Role::Primary, 11, SeedProfile::RawMaster32, SeedProfile::NativeMnemonic),
            (Role::Rescue, 22, SeedProfile::NativeMnemonic, SeedProfile::RawMaster32),
        ] {
            let mut master = [seed; 32];
            manifest.verify_initial_master_and_wipe(&mut master, role, profile).unwrap();
            assert_eq!(master, [0; 32], "successful recovery retained master");
            let mut wrong = [33; 32];
            assert!(
                manifest.verify_initial_master_and_wipe(&mut wrong, role, profile).is_err(),
                "recovery accepted wrong master"
            );
            assert_eq!(wrong, [0; 32]);
            let mut wrong = [seed; 32];
            assert!(
                manifest.verify_initial_master_and_wipe(&mut wrong, role, wrong_profile).is_err(),
                "recovery accepted wrong input profile"
            );
            assert_eq!(wrong, [0; 32], "preflight failure retained master");
            let mut short = [seed; 31];
            assert!(manifest.verify_initial_master_and_wipe(&mut short, role, profile).is_err());
            assert_eq!(short, [0; 31]);
            for field in ["account_index", "key_generation"] {
                let mut changed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
                changed["derivation"][field] = 0.into();
                // Address reconstruction cannot authenticate declared derivation metadata.
                let (changed, _) = InitialRecoveryManifest::parse_and_reconstruct(
                    &serde_json::to_vec(&changed).unwrap(),
                    bundle(),
                    expected,
                )
                .unwrap();
                let mut master = [seed; 32];
                assert!(
                    changed.verify_initial_master_and_wipe(&mut master, role, profile).is_err(),
                    "recovery accepted changed {field}"
                );
                assert_eq!(master, [0; 32]);
            }
        }
    }
}

#[cfg(all(test, feature = "native-wallet-vault"))]
mod vault_recovery_tests {
    use super::*;
    use crate::wallet_v5r2_genesis::tests::{bundle, parameters};
    use secrets_vault::{
        crypto::{factory::AutoCryptoFactory, key_material::KeyMaterial, master_key::MasterKey},
        events::null_handler::NullEventHandler,
        memory::protected_memory::ProtectedMemory,
        storage::file_json::FileJsonStorage,
        types::secret_id::SecretId,
        vault::SecretVault,
    };
    use std::{path::Path, sync::Arc};
    use wallet_pq_signer::{
        Role,
        kdf::{DerivationContext, derive_signer_and_wipe},
        vault::load_bound,
    };
    async fn open(path: &Path) -> SecretVault {
        let key = ProtectedMemory::from_slice(&[0x77; 32]).await.unwrap();
        let master =
            MasterKey::from_key_material(KeyMaterial::new_symmetric_key(key).await.unwrap())
                .await
                .unwrap();
        let storage = FileJsonStorage::new(master, path, Box::new(AutoCryptoFactory {}), false)
            .await
            .unwrap();
        SecretVault::new(Arc::new(storage), Arc::new(NullEventHandler {}))
    }
    #[tokio::test]
    async fn manifest_vault_restores_only_bound_keys_without_overwrite() {
        let mut p = parameters();
        let context = DerivationContext {
            network: p.network,
            global_id: p.global_id,
            account_index: 5,
            key_generation: 7,
        };
        let primary = derive_signer_and_wipe(&mut [11; 32], context, Role::Primary).unwrap();
        let rescue = derive_signer_and_wipe(&mut [22; 32], context, Role::Rescue).unwrap();
        p.primary_key.copy_from_slice(primary.public_key());
        p.rescue_key.copy_from_slice(rescue.public_key());
        let (m, g) = InitialRecoveryManifest::prepare(
            bundle(),
            p,
            RecoveryDerivation {
                account_index: 5,
                key_generation: 7,
                primary_seed_profile: SeedProfile::RawMaster32,
                rescue_seed_profile: SeedProfile::NativeMnemonic,
                fee_seed_profile: SeedProfile::RawMaster32,
            },
        )
        .unwrap();
        let encoded = m.to_json().unwrap();
        let expected_wallet = *g.wallet_init().repr_hash().as_array();
        let (m, _) =
            InitialRecoveryManifest::parse_and_reconstruct(&encoded, bundle(), expected_wallet)
                .unwrap();
        for (role, seed, profile, other, key) in [
            (
                Role::Primary,
                11,
                SeedProfile::RawMaster32,
                SeedProfile::NativeMnemonic,
                primary.public_key(),
            ),
            (
                Role::Rescue,
                22,
                SeedProfile::NativeMnemonic,
                SeedProfile::RawMaster32,
                rescue.public_key(),
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.json");
            let v = open(&path).await;
            let id = SecretId::new("recovered.initial");
            let mut master = [seed; 32];
            drop(m.restore_initial_master_to_vault(&v, &id, &mut master, role, profile));
            assert_eq!(master, [0; 32], "unpolled manifest restore retained master");
            assert!(!v.exists(&id).await.unwrap());
            let mut master = [seed; 32];
            assert!(
                m.restore_initial_master_to_vault(&v, &id, &mut master, role, other).await.is_err(),
                "vault accepted wrong input profile"
            );
            assert_eq!(master, [0; 32]);
            assert!(!v.exists(&id).await.unwrap());
            let mut master = [33; 32];
            assert!(
                m.restore_initial_master_to_vault(&v, &id, &mut master, role, profile)
                    .await
                    .is_err(),
                "vault accepted wrong master"
            );
            assert_eq!(master, [0; 32]);
            assert!(!v.exists(&id).await.unwrap());
            for field in ["account_index", "key_generation"] {
                let mut changed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
                changed["derivation"][field] = 0.into();
                let (changed, _) = InitialRecoveryManifest::parse_and_reconstruct(
                    &serde_json::to_vec(&changed).unwrap(),
                    bundle(),
                    expected_wallet,
                )
                .unwrap();
                let mut master = [seed; 32];
                assert!(
                    changed
                        .restore_initial_master_to_vault(&v, &id, &mut master, role, profile)
                        .await
                        .is_err(),
                    "vault accepted changed {field}"
                );
                assert_eq!(master, [0; 32]);
                assert!(!v.exists(&id).await.unwrap());
            }
            let mut master = [seed; 32];
            assert_eq!(
                m.restore_initial_master_to_vault(&v, &id, &mut master, role, profile)
                    .await
                    .unwrap(),
                key
            );
            assert_eq!(master, [0; 32]);
            let before = std::fs::read(&path).unwrap();
            let mut master = [seed; 32];
            assert!(
                m.restore_initial_master_to_vault(&v, &id, &mut master, role, profile)
                    .await
                    .is_err(),
                "vault overwrote recovered key"
            );
            assert_eq!(master, [0; 32]);
            assert_eq!(std::fs::read(&path).unwrap(), before);
            drop(v);
            let reopened = open(&path).await;
            assert_eq!(load_bound(&reopened, &id, role, key).await.unwrap().public_key(), key);
        }
    }
}
