// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Restore fee custody from the fixed wallet KDF; never restore signing state.
use super::{ProtectedMemory, Rejected, SecretId, SecretVault, Wipe, restore_seed_and_wipe};
use wallet_pq_signer::kdf::{DerivationContext, Material, derive_seed_and_wipe};

/// Derive a fee seed from a resolved 32-byte wallet master and restore it to a
/// new encrypted record only after enrollment binding. Public KDF context/tree
/// identity must come from authenticated recovery metadata, not guesses. The
/// authentication path is public and may belong to an already used leaf.
/// Wipes the master even when the returned future is never polled. This neither
/// opens nor resets a journal; the next-slot restore barrier remains mandatory.
pub fn restore_derived_and_wipe<'a>(
    vault: &'a SecretVault,
    id: &'a SecretId,
    master: &'a mut [u8],
    context: DerivationContext,
    tree_id: [u8; 32],
    key: &'a [u8; 60],
    leaf: u32,
    path: &'a [u8; 640],
) -> impl std::future::Future<Output = Result<(), Rejected>> + 'a {
    let master = Wipe(master);
    async move {
        let mut seed = ProtectedMemory::new(48).map_err(|_| Rejected)?;
        let mut locked = seed.lock_mut().await.map_err(|_| Rejected)?;
        derive_seed_and_wipe(master.0, context, Material::Fee { tree_id }, &mut locked)?;
        drop(master);
        restore_seed_and_wipe(vault, id, &mut locked, key, leaf, path).await
    }
}

/// Validate a native mnemonic and its exact password before fee derivation.
/// Phrase/password are borrowed; callers protect and clear their own input.
/// No classical signing key is derived. Wrong phrase/password or public context
/// must fail enrollment binding before any new fee record is written.
pub async fn restore_mnemonic(
    vault: &SecretVault,
    id: &SecretId,
    phrase: &str,
    password: &str,
    context: DerivationContext,
    tree_id: [u8; 32],
    key: &[u8; 60],
    leaf: u32,
    path: &[u8; 640],
) -> Result<(), Rejected> {
    let mut master = zeroize::Zeroizing::new(
        tos_native_mnemonic::private_seed(phrase, password).map_err(|_| Rejected)?,
    );
    restore_derived_and_wipe(vault, id, &mut *master, context, tree_id, key, leaf, path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn fee_master_and_mnemonic_restore_bind_context_and_wipe() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../wallet-pq-signer/tests/fixtures/native-fee-recovery.json"
        ))
        .unwrap();
        let key: [u8; 60] =
            hex::decode(v["public_key_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let path: [u8; 640] =
            hex::decode(v["path_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let original = hex::decode(v["master_hex"].as_str().unwrap()).unwrap();
        let context = DerivationContext {
            network: [1; 32],
            global_id: 42,
            account_index: 5,
            key_generation: 7,
        };
        let tree_id = [0xa5; 32];
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("vault.json");
        let vault = super::super::tests::open(&file).await;
        let id = SecretId::new("restored.fee");
        let mut master = original.clone();
        drop(restore_derived_and_wipe(&vault, &id, &mut master, context, tree_id, &key, 0, &path));
        assert!(master.iter().all(|b| *b == 0), "unpolled fee master restore retained input");
        for case in 0..9 {
            let mut master = original.clone();
            let mut context = context;
            let mut tree_id = tree_id;
            let mut key = key;
            let mut path = path;
            match case {
                0 => master[0] ^= 1,
                1 => context.network[0] ^= 1,
                2 => context.global_id += 1,
                3 => context.account_index += 1,
                4 => context.key_generation += 1,
                5 => tree_id[0] ^= 1,
                6 => {
                    master.pop();
                }
                7 => key[28] ^= 1,
                _ => path[0] ^= 1,
            }
            assert!(
                restore_derived_and_wipe(
                    &vault,
                    &id,
                    &mut master,
                    context,
                    tree_id,
                    &key,
                    0,
                    &path
                )
                .await
                .is_err(),
                "fee master restore accepted wrong input {case}"
            );
            assert!(master.iter().all(|b| *b == 0), "fee master restore retained rejected input");
            assert!(
                !vault.exists(&id).await.unwrap(),
                "fee master restore persisted wrong input {case}"
            );
        }
        let phrase = v["phrase"].as_str().unwrap();
        let password = v["password"].as_str().unwrap();
        for (phrase, password) in [("invalid mnemonic", password), (phrase, password.trim())] {
            assert!(
                restore_mnemonic(&vault, &id, phrase, password, context, tree_id, &key, 0, &path)
                    .await
                    .is_err(),
                "fee mnemonic accepted invalid phrase or password"
            );
            assert!(!vault.exists(&id).await.unwrap());
        }
        master = original.clone();
        restore_derived_and_wipe(&vault, &id, &mut master, context, tree_id, &key, 0, &path)
            .await
            .unwrap();
        assert!(master.iter().all(|b| *b == 0));
        let other = SecretId::new("mnemonic.fee");
        assert!(
            restore_mnemonic(&vault, &other, phrase, password, context, tree_id, &key, 0, &path)
                .await
                .is_ok(),
            "fee mnemonic rejected exact password"
        );
        let before = std::fs::read(&file).unwrap();
        assert!(
            restore_mnemonic(&vault, &other, phrase, password, context, tree_id, &key, 0, &path)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&file).unwrap(), before);
        drop(vault);
        let vault = super::super::tests::open(&file).await;
        for id in [&id, &other] {
            drop(super::super::load_bound(&vault, id, &key, 0, &path).await.unwrap());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "complete mnemonic-driven H20 rebuild; explicitly run in recovery validation"]
    async fn fee_mnemonic_rebuilds_tree_cache_and_encrypted_custody() {
        use wallet_pq_signer::fee::FeeTree;
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../wallet-pq-signer/tests/fixtures/native-fee-recovery.json"
        ))
        .unwrap();
        let key: [u8; 60] =
            hex::decode(v["public_key_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let expected_path = hex::decode(v["path_hex"].as_str().unwrap()).unwrap();
        let phrase = v["phrase"].as_str().unwrap();
        let password = v["password"].as_str().unwrap();
        let context = DerivationContext {
            network: [1; 32],
            global_id: 42,
            account_index: 5,
            key_generation: 7,
        };
        let tree_id = [0xa5; 32];
        let mut master = tos_native_mnemonic::private_seed(phrase, password).unwrap();
        let mut seed = [0; 48];
        derive_seed_and_wipe(&mut master, context, Material::Fee { tree_id }, &mut seed).unwrap();
        assert!(master.iter().all(|b| *b == 0));
        let tree = FeeTree::generate_and_wipe(&mut seed).unwrap();
        assert_eq!(seed, [0; 48]);
        assert_eq!(tree.public_key(), &key, "mnemonic rebuilt wrong fee enrollment");
        assert_eq!(tree.authentication_path(0).unwrap().as_slice(), expected_path);
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("public-tree.cache");
        tree.save_cache_new(&cache).unwrap();
        drop(tree);
        let tree = FeeTree::read_cache(std::fs::File::open(cache).unwrap(), &key).unwrap();
        let vault = super::super::tests::open(&dir.path().join("vault.json")).await;
        let id = SecretId::new("reconstructed.fee");
        let path = tree.authentication_path(0).unwrap();
        restore_mnemonic(&vault, &id, phrase, password, context, tree_id, &key, 0, &path)
            .await
            .unwrap();
        drop(super::super::load_bound(&vault, &id, &key, 0, &path).await.unwrap());
    }
}
