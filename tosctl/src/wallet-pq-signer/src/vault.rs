// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Load independently enrolled PQ keys from versioned Vault blob records.
//! The caller selects and authenticates the storage backend and keeps primary
//! and rescue custody separate. This adapter does not prove device isolation,
//! backup safety, revocation, chain state or approval to sign an action.
use crate::{Rejected, Role, Signer};
use secrets_vault::{
    types::{algorithm::Algorithm, secret::Secret, secret_id::SecretId},
    vault::SecretVault,
};

pub const PROFILE_TAG: &str = "tos-wallet-pq-seed-profile";
pub const ROLE_TAG: &str = "tos-wallet-pq-seed-role";
pub const PROFILE_V1: &str = "v5r2-seed-v1";

pub fn role_tag(role: Role) -> &'static str {
    match role {
        Role::Primary => "ml-dsa-44",
        Role::Rescue => "slh-dsa-sha2-128s",
    }
}

/// Open a seed record and bind the derived key to independently authenticated
/// enrollment. Records use Algorithm::None blobs, PROFILE_TAG/ROLE_TAG, and
/// exactly 32 primary or 48 rescue seed bytes. This is not a classical-key path.
/// Expiration is checked at opening; a returned handle does not poll revocation.
/// Backend errors deliberately do not propagate record contents into diagnostics.
pub async fn load_bound(
    vault: &SecretVault,
    id: &SecretId,
    role: Role,
    expected_key: &[u8],
) -> Result<Signer, Rejected> {
    if expected_key.len() != role.public_key_bytes() {
        return Err(Rejected);
    }
    let secret = vault.get(id).await.map_err(|_| Rejected)?;
    let Secret::Blob { blob } = secret else {
        return Err(Rejected);
    };
    let metadata = blob.metadata();
    if metadata.secret_id.as_ref() != Some(id) || metadata.algorithm != Algorithm::None {
        return Err(Rejected);
    }
    if metadata.get_tag(PROFILE_TAG) != Some(PROFILE_V1) {
        return Err(Rejected);
    }
    if metadata.get_tag(ROLE_TAG) != Some(role_tag(role)) {
        return Err(Rejected);
    }
    if metadata.is_expired() {
        return Err(Rejected);
    }
    let mut seed = blob.data().await.map_err(|_| Rejected)?;
    let mut locked = seed.lock_mut().await.map_err(|_| Rejected)?;
    let signer = Signer::import_and_wipe(role, &mut locked)?;
    if signer.public_key() != expected_key {
        return Err(Rejected);
    }
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrets_vault::{
        crypto::{
            factory::{AutoCryptoFactory, CryptoFactory},
            key_material::KeyMaterial,
            master_key::MasterKey,
        },
        events::null_handler::NullEventHandler,
        memory::protected_memory::ProtectedMemory,
        storage::file_json::FileJsonStorage,
        types::{metadata::Metadata, store_mode::StoreMode},
    };
    use std::{path::Path, sync::Arc};

    async fn open(path: &Path, master: u8) -> SecretVault {
        let key = ProtectedMemory::from_slice(&[master; 32]).await.expect("public test key");
        let master = MasterKey::from_key_material(
            KeyMaterial::new_symmetric_key(key).await.expect("key material"),
        )
        .await
        .expect("master");
        let storage = FileJsonStorage::new(master, path, Box::new(AutoCryptoFactory {}), false)
            .await
            .expect("file storage");
        SecretVault::new(Arc::new(storage), Arc::new(NullEventHandler {}))
    }

    fn metadata(id: &SecretId, role: Role) -> Metadata {
        Metadata::new(Some(id), Algorithm::None, true)
            .with_tag(PROFILE_TAG, PROFILE_V1)
            .with_tag(ROLE_TAG, role_tag(role))
    }

    async fn put(vault: &SecretVault, metadata: Metadata, seed: &[u8]) {
        let data = ProtectedMemory::from_slice(seed).await.expect("protected public fixture");
        let secret = Secret::from_protected_data(
            data,
            metadata,
            AutoCryptoFactory {}.new_crypto().expect("crypto"),
        )
        .await
        .expect("blob");
        vault.put(&secret, StoreMode::NewOnly).await.expect("store fixture");
        vault.flush().await.expect("flush fixture");
    }

    #[tokio::test]
    async fn encrypted_reopen_binds_both_pq_roles() {
        for role in [Role::Primary, Role::Rescue] {
            let dir = tempfile::tempdir().expect("fixture directory");
            let path = dir.path().join("vault.json");
            let id = SecretId::new("wallet.pq");
            let seed = vec![0x55; if role == Role::Primary { 32 } else { 48 }];
            let expected =
                Signer::import_and_wipe(role, &mut seed.clone()).expect("fixture signer");
            let key = expected.public_key().to_vec();
            {
                let vault = open(&path, 0x77).await;
                put(&vault, metadata(&id, role), &seed).await;
            }
            let vault = open(&path, 0x77).await;
            let mut loaded = load_bound(&vault, &id, role, &key).await.expect("reopen bound key");
            assert_eq!(loaded.public_key(), key);
            assert_eq!(
                loaded
                    .sign_bound(role, &key, crate::Purpose::Pop, &[9; 32])
                    .expect("real PQ signature")
                    .len(),
                role.signature_bytes()
            );
            let mut wrong_key = key.clone();
            wrong_key[0] ^= 1;
            assert!(
                load_bound(&vault, &id, role, &wrong_key).await.is_err(),
                "wrong enrollment accepted"
            );
            let wrong_master = open(&path, 0x78).await;
            assert!(
                load_bound(&wrong_master, &id, role, &key).await.is_err(),
                "wrong master accepted"
            );
        }
    }

    #[tokio::test]
    async fn rejects_record_profile_role_and_expiration() {
        let mut seed = [0x55; 32];
        let key = Signer::import_and_wipe(Role::Primary, &mut seed)
            .expect("fixture")
            .public_key()
            .to_vec();
        for bad in ["profile", "role", "expiration"] {
            let dir = tempfile::tempdir().expect("fixture directory");
            let vault = open(&dir.path().join("vault.json"), 0x77).await;
            let id = SecretId::new("wallet.pq");
            let mut meta = metadata(&id, Role::Primary);
            match bad {
                "profile" => {
                    meta.tags.insert(PROFILE_TAG.into(), "unknown".into());
                }
                "role" => {
                    meta.tags.insert(ROLE_TAG.into(), role_tag(Role::Rescue).into());
                }
                _ => {
                    meta.expires_at = Some(chrono::Utc::now() - chrono::Duration::days(1));
                }
            }
            put(&vault, meta, &[0x55; 32]).await;
            assert!(
                load_bound(&vault, &id, Role::Primary, &key).await.is_err(),
                "accepted invalid {bad}"
            );
        }
    }
}
