// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Create and load independently enrolled PQ keys from versioned Vault blob records.
//! The caller selects and authenticates the storage backend and keeps primary
//! and rescue custody separate. This adapter does not prove device isolation,
//! backup safety, revocation, chain state or approval to sign an action.
use crate::{Rejected, Role, Signer};
use secrets_vault::{
    crypto::factory::{AutoCryptoFactory, CryptoFactory},
    memory::protected_memory::ProtectedMemory,
    types::{
        algorithm::Algorithm, metadata::Metadata, secret::Secret, secret_id::SecretId,
        store_mode::StoreMode,
    },
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

/// Create a fresh PQ seed record without overwriting an existing ID. The caller
/// must provide authenticated encrypted storage with exclusive writer ownership.
/// Return a signer only after store, flush and public-key-bound readback succeed.
/// On failure/cancellation a record may already exist: do not delete or overwrite
/// it automatically. Resolve uncertain persistence before retrying enrollment.
pub async fn create_new(
    vault: &SecretVault,
    id: &SecretId,
    role: Role,
) -> Result<Signer, Rejected> {
    create_with_rng(vault, id, role, |seed| {
        // SAFETY: seed is a live writable protected buffer of 32 or 48 bytes.
        unsafe { openssl_sys::RAND_bytes(seed.as_mut_ptr(), seed.len() as i32) }
    })
    .await
}

async fn create_with_rng(
    vault: &SecretVault,
    id: &SecretId,
    role: Role,
    fill: impl FnOnce(&mut [u8]) -> i32,
) -> Result<Signer, Rejected> {
    let size = match role {
        Role::Primary => 32,
        Role::Rescue => 48,
    };
    let mut seed = ProtectedMemory::new(size).map_err(|_| Rejected)?;
    {
        let mut locked = seed.lock_mut().await.map_err(|_| Rejected)?;
        let status = fill(&mut locked);
        if status != 1 || locked.iter().all(|byte| *byte == 0) {
            return Err(Rejected);
        }
    }
    let expected_key = {
        let mut copy = seed.clone().await.map_err(|_| Rejected)?;
        let mut locked = copy.lock_mut().await.map_err(|_| Rejected)?;
        Signer::import_and_wipe(role, &mut locked)?.public_key().to_vec()
    };
    let metadata = Metadata::new(Some(id), Algorithm::None, true)
        .with_tag(PROFILE_TAG, PROFILE_V1)
        .with_tag(ROLE_TAG, role_tag(role));
    let secret = Secret::from_protected_data(
        seed,
        metadata,
        AutoCryptoFactory {}.new_crypto().map_err(|_| Rejected)?,
    )
    .await
    .map_err(|_| Rejected)?;
    vault.put(&secret, StoreMode::NewOnly).await.map_err(|_| Rejected)?;
    vault.flush().await.map_err(|_| Rejected)?;
    drop(secret);
    load_bound(vault, id, role, &expected_key).await
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
            drop(vault);
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

#[cfg(test)]
mod creation_tests {
    use super::*;
    use secrets_vault::{
        crypto::{key_material::KeyMaterial, master_key::MasterKey},
        events::null_handler::NullEventHandler,
        storage::{file_json::FileJsonStorage, storage_trait::Storage},
        types::secret_spec::SecretSpec,
    };
    use std::{path::Path, sync::Arc};

    #[derive(Clone, Copy)]
    enum Failure {
        None,
        Store,
        Flush,
        Read,
    }
    struct FaultStorage {
        inner: FileJsonStorage,
        failure: Failure,
    }

    #[async_trait::async_trait]
    impl Storage for FaultStorage {
        async fn flush(&self) -> anyhow::Result<()> {
            self.inner.flush().await?;
            anyhow::ensure!(!matches!(self.failure, Failure::Flush), "injected flush failure");
            Ok(())
        }
        async fn store(&self, secret: &Secret, mode: StoreMode) -> anyhow::Result<()> {
            self.inner.store(secret, mode).await?;
            anyhow::ensure!(!matches!(self.failure, Failure::Store), "injected store failure");
            Ok(())
        }
        async fn load(&self, id: &SecretId) -> anyhow::Result<Secret> {
            let actual = self.inner.load(id).await?;
            if matches!(self.failure, Failure::Read) {
                let seed = ProtectedMemory::from_slice(&[0x42; 32]).await?;
                return Secret::from_protected_data(
                    seed,
                    actual.metadata().clone(),
                    AutoCryptoFactory {}.new_crypto()?,
                )
                .await;
            }
            Ok(actual)
        }
        async fn generate_secret(
            &self,
            spec: &SecretSpec,
            id: &SecretId,
        ) -> anyhow::Result<Secret> {
            self.inner.generate_secret(spec, id).await
        }
        async fn store_vec(
            &self,
            records: Vec<(ProtectedMemory, Metadata, StoreMode)>,
        ) -> anyhow::Result<()> {
            self.inner.store_vec(records).await
        }
        async fn load_metadata(&self, id: &SecretId) -> anyhow::Result<Option<Metadata>> {
            self.inner.load_metadata(id).await
        }
        async fn list_metadata(&self) -> anyhow::Result<Vec<Metadata>> {
            self.inner.list_metadata().await
        }
        async fn delete(&self, id: &SecretId) -> anyhow::Result<()> {
            self.inner.delete(id).await
        }
        fn format_version(&self) -> anyhow::Result<u32> {
            self.inner.format_version()
        }
    }

    async fn open(path: &Path, failure: Failure) -> SecretVault {
        let key = ProtectedMemory::from_slice(&[0x77; 32]).await.expect("public master fixture");
        let master = MasterKey::from_key_material(
            KeyMaterial::new_symmetric_key(key).await.expect("material"),
        )
        .await
        .expect("master");
        let inner = FileJsonStorage::new(master, path, Box::new(AutoCryptoFactory {}), false)
            .await
            .expect("storage");
        SecretVault::new(Arc::new(FaultStorage { inner, failure }), Arc::new(NullEventHandler {}))
    }

    #[tokio::test]
    async fn creates_reopens_and_never_replaces_existing_keys() {
        for role in [Role::Primary, Role::Rescue] {
            let dir = tempfile::tempdir().expect("directory");
            let path = dir.path().join("vault.json");
            let id = SecretId::new("pq.created");
            let vault = open(&path, Failure::None).await;
            let created = create_new(&vault, &id, role).await.expect("create new PQ seed");
            let key = created.public_key().to_vec();
            drop(created);
            assert!(create_new(&vault, &id, role).await.is_err(), "overwrote existing PQ key");
            drop(vault);
            let reopened = open(&path, Failure::None).await;
            let mut signer = load_bound(&reopened, &id, role, &key).await.expect("durable key");
            assert_eq!(
                signer
                    .sign_bound(role, &key, crate::Purpose::Pop, &[9; 32])
                    .expect("native PQ signature")
                    .len(),
                role.signature_bytes()
            );
        }
    }

    #[tokio::test]
    async fn rejects_rng_failure_and_zero_without_storing() {
        let dir = tempfile::tempdir().expect("directory");
        let vault = open(&dir.path().join("vault.json"), Failure::None).await;
        let id = SecretId::new("pq.failed-rng");
        for (status, byte) in [(0, 0x11), (-1, 0x11), (1, 0)] {
            let result = create_with_rng(&vault, &id, Role::Primary, |seed| {
                seed.fill(byte);
                status
            })
            .await;
            assert!(result.is_err(), "accepted invalid seed randomness");
            assert!(!vault.exists(&id).await.expect("lookup"), "stored invalid seed randomness");
        }
    }

    #[tokio::test]
    async fn persistence_errors_and_wrong_readback_never_return_signer() {
        for failure in [Failure::Store, Failure::Flush, Failure::Read] {
            let dir = tempfile::tempdir().expect("directory");
            let path = dir.path().join("vault.json");
            let vault = open(&path, failure).await;
            let id = SecretId::new("pq.uncertain");
            let result = create_with_rng(&vault, &id, Role::Primary, |seed| {
                seed.fill(0x11);
                1
            })
            .await;
            let reason = match failure {
                Failure::Store => "store",
                Failure::Flush => "flush",
                _ => "readback",
            };
            assert!(result.is_err(), "returned signer after {reason} failure");
            drop(vault);
            // Storage may have succeeded before reporting failure. Never erase it.
            let reopened = open(&path, Failure::None).await;
            let mut seed = [0x11; 32];
            let expected = Signer::import_and_wipe(Role::Primary, &mut seed).expect("public seed");
            load_bound(&reopened, &id, Role::Primary, expected.public_key())
                .await
                .expect("uncertain record preserved");
        }
    }
}
