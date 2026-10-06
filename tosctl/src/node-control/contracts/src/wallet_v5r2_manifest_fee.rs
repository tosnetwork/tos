// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Initial fee enrollment binding, never current signing authority.
use super::{InitialRecoveryManifest, SeedProfile, Wipe, bytes};
use wallet_pq_signer::kdf::{DerivationContext, Material, derive_seed_and_wipe};

impl InitialRecoveryManifest {
    /// Initial public enrollment only; callers still require current chain proofs.
    pub fn initial_fee_public_key(&self) -> anyhow::Result<[u8; 60]> {
        bytes(&self.wire.fee_public_key)
    }

    /// Reconstruct a missing public tree on a blocking worker and bind it to
    /// initial enrollment. Wipe the resolved master on every return. No custody
    /// record, journal or signature is created by this CPU-heavy operation.
    pub fn rebuild_initial_fee_tree_and_wipe(
        &self,
        master: &mut [u8],
        input_profile: SeedProfile,
    ) -> anyhow::Result<wallet_pq_signer::fee::FeeTree> {
        let master = Wipe(master);
        let (context, tree_id, key) = self.initial_fee_context(input_profile)?;
        let mut seed = zeroize::Zeroizing::new([0; 48]);
        derive_seed_and_wipe(master.0, context, Material::Fee { tree_id }, &mut *seed)?;
        let tree = wallet_pq_signer::fee::FeeTree::generate_and_wipe(&mut *seed)?;
        anyhow::ensure!(
            tree.public_key() == &key,
            "rebuilt fee tree differs from initial enrollment"
        );
        Ok(tree)
    }

    fn initial_fee_context(
        &self,
        input_profile: SeedProfile,
    ) -> anyhow::Result<(DerivationContext, [u8; 32], [u8; 60])> {
        let d = &self.wire.derivation;
        anyhow::ensure!(d.fee_seed_profile == input_profile, "fee recovery input profile mismatch");
        Ok((
            DerivationContext {
                network: bytes(&self.wire.network)?,
                global_id: self.wire.global_id,
                account_index: d.account_index,
                key_generation: d.key_generation,
            },
            bytes(&self.wire.fee_tree_id)?,
            bytes(&self.wire.fee_public_key)?,
        ))
    }

    /// Verify a resolved master against initial fee enrollment before opening
    /// custody storage. Native phrase validation must precede a NativeMnemonic
    /// call. Wipe master on every return. The public path may use a spent leaf;
    /// this read-only check neither signs nor authorizes old fee-tree reuse.
    pub fn verify_initial_fee_master_and_wipe(
        &self,
        master: &mut [u8],
        input_profile: SeedProfile,
        leaf: u32,
        path: &[u8; 640],
    ) -> anyhow::Result<()> {
        let master = Wipe(master);
        let (context, tree_id, key) = self.initial_fee_context(input_profile)?;
        let mut seed = zeroize::Zeroizing::new([0; 48]);
        derive_seed_and_wipe(master.0, context, Material::Fee { tree_id }, &mut *seed)?;
        wallet_pq_signer::fee::verify_seed_and_wipe(&mut *seed, &key, leaf, path)?;
        Ok(())
    }

    /// Restore initial fee enrollment into an authenticated, exclusively owned
    /// encrypted Vault using only this manifest's KDF namespace and tree identity.
    /// Return its public key only after new-only storage, flush and bound readback.
    /// Even unpolled cancellation wipes master. Current proofs, device takeover,
    /// journal restore barriers and funded rescue remain separate requirements.
    #[cfg(feature = "native-wallet-vault")]
    pub fn restore_initial_fee_master_to_vault<'a>(
        &'a self,
        vault: &'a secrets_vault::vault::SecretVault,
        id: &'a secrets_vault::types::secret_id::SecretId,
        master: &'a mut [u8],
        input_profile: SeedProfile,
        leaf: u32,
        path: &'a [u8; 640],
    ) -> impl std::future::Future<Output = anyhow::Result<[u8; 60]>> + 'a {
        let master = Wipe(master);
        async move {
            let (context, tree_id, key) = self.initial_fee_context(input_profile)?;
            crate::lms_fee_vault::restore_derived_and_wipe(
                vault, id, master.0, context, tree_id, &key, leaf, path,
            )
            .await?;
            Ok(key)
        }
    }
}

#[cfg(all(test, feature = "native-wallet-vault"))]
mod tests {
    use super::*;
    use crate::wallet_v5r2_genesis::tests::{bundle, parameters};
    use crate::wallet_v5r2_manifest::RecoveryDerivation;
    use secrets_vault::types::secret_id::SecretId;

    #[tokio::test]
    async fn initial_fee_manifest_binds_profile_namespace_and_enrollment() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../wallet-pq-signer/tests/fixtures/native-fee-recovery.json"
        ))
        .unwrap();
        let original = hex::decode(v["master_hex"].as_str().unwrap()).unwrap();
        let key: [u8; 60] =
            hex::decode(v["public_key_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let path: [u8; 640] =
            hex::decode(v["path_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let mut p = parameters();
        p.network = [1; 32];
        p.global_id = 42;
        p.fee_tree_id = [0xa5; 32];
        p.fee_public_key = key;
        let (m, g) = InitialRecoveryManifest::prepare(
            bundle(),
            p.clone(),
            RecoveryDerivation {
                account_index: 5,
                key_generation: 7,
                primary_seed_profile: SeedProfile::RawMaster32,
                rescue_seed_profile: SeedProfile::RawMaster32,
                fee_seed_profile: SeedProfile::NativeMnemonic,
            },
        )
        .unwrap();
        let wallet = *g.wallet_init().repr_hash().as_array();
        let encoded = m.to_json().unwrap();
        let (m, _) =
            InitialRecoveryManifest::parse_and_reconstruct(&encoded, bundle(), wallet).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("vault.json");
        let vault = crate::lms_fee_vault::tests::open(&file).await;
        let id = SecretId::new("manifest.fee");
        let mut master = original.clone();
        drop(m.restore_initial_fee_master_to_vault(
            &vault,
            &id,
            &mut master,
            SeedProfile::NativeMnemonic,
            0,
            &path,
        ));
        assert!(master.iter().all(|b| *b == 0), "fee manifest unpolled restore retained master");
        for case in 0..8 {
            let mut changed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            let mut master = original.clone();
            let profile =
                if case == 0 { SeedProfile::RawMaster32 } else { SeedProfile::NativeMnemonic };
            match case {
                1 => changed["derivation"]["account_index"] = 6.into(),
                2 => changed["derivation"]["key_generation"] = 8.into(),
                3 => master[0] ^= 1,
                4 => {
                    master.pop();
                }
                _ => {}
            }
            // Declared derivation fields do not alter reconstructed addresses;
            // secret-to-public-key binding must independently detect changes.
            let (changed, _) = if case >= 5 {
                // An enrolled initial identity can contain a public KDF context
                // incompatible with this master; still refuse private recovery.
                let mut other = p.clone();
                match case {
                    5 => other.fee_tree_id[0] ^= 1,
                    6 => other.network[0] ^= 1,
                    _ => other.global_id += 1,
                }
                let (other, g) =
                    InitialRecoveryManifest::prepare(bundle(), other, m.derivation().clone())
                        .unwrap();
                InitialRecoveryManifest::parse_and_reconstruct(
                    &other.to_json().unwrap(),
                    bundle(),
                    *g.wallet_init().repr_hash().as_array(),
                )
                .unwrap()
            } else {
                InitialRecoveryManifest::parse_and_reconstruct(
                    &serde_json::to_vec(&changed).unwrap(),
                    bundle(),
                    wallet,
                )
                .unwrap()
            };
            let mut check = master.clone();
            assert!(
                changed.verify_initial_fee_master_and_wipe(&mut check, profile, 0, &path).is_err(),
                "fee manifest preflight accepted input {case}"
            );
            assert!(check.iter().all(|b| *b == 0), "fee manifest preflight retained master");
            assert!(
                changed
                    .restore_initial_fee_master_to_vault(
                        &vault,
                        &id,
                        &mut master,
                        profile,
                        0,
                        &path
                    )
                    .await
                    .is_err(),
                "fee manifest restore accepted input {case}"
            );
            assert!(master.iter().all(|b| *b == 0));
            assert!(!vault.exists(&id).await.unwrap(), "fee manifest persisted wrong key");
        }
        master = original.clone();
        m.verify_initial_fee_master_and_wipe(&mut master, SeedProfile::NativeMnemonic, 0, &path)
            .unwrap();
        assert!(master.iter().all(|b| *b == 0));
        master = original.clone();
        let public = m
            .restore_initial_fee_master_to_vault(
                &vault,
                &id,
                &mut master,
                SeedProfile::NativeMnemonic,
                0,
                &path,
            )
            .await
            .unwrap();
        assert_eq!(public, key);
        assert!(master.iter().all(|b| *b == 0));
        let before = std::fs::read(&file).unwrap();
        master = original.clone();
        assert!(
            m.restore_initial_fee_master_to_vault(
                &vault,
                &id,
                &mut master,
                SeedProfile::NativeMnemonic,
                0,
                &path
            )
            .await
            .is_err()
        );
        assert!(master.iter().all(|b| *b == 0));
        assert_eq!(std::fs::read(&file).unwrap(), before);
    }

    #[test]
    #[ignore = "full H20 reconstruction against mismatched initial enrollment"]
    fn initial_fee_rebuild_refuses_different_enrolled_root() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../wallet-pq-signer/tests/fixtures/native-fee-recovery.json"
        ))
        .unwrap();
        let mut master = hex::decode(v["master_hex"].as_str().unwrap()).unwrap();
        let mut p = parameters();
        p.network = [1; 32];
        p.global_id = 42;
        p.fee_tree_id = [0xa5; 32];
        p.fee_public_key =
            hex::decode(v["public_key_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        p.fee_public_key[28] ^= 1;
        let (manifest, _) = InitialRecoveryManifest::prepare(
            bundle(),
            p,
            RecoveryDerivation {
                account_index: 5,
                key_generation: 7,
                primary_seed_profile: SeedProfile::RawMaster32,
                rescue_seed_profile: SeedProfile::RawMaster32,
                fee_seed_profile: SeedProfile::NativeMnemonic,
            },
        )
        .unwrap();
        assert!(
            manifest
                .rebuild_initial_fee_tree_and_wipe(&mut master, SeedProfile::NativeMnemonic)
                .is_err(),
            "fee rebuild accepted different enrolled root"
        );
        assert!(master.iter().all(|b| *b == 0), "fee rebuild retained rejected master");
    }
}
