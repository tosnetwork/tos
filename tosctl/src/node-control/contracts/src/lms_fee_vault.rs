// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Encrypted fee-seed records. Journal state remains separate and mandatory.
use crate::{
    lms_fee_journal::{FeeJournal, SignedFeeMessage},
    wallet_v5r2_fee::FeePayload,
    wallet_v5r2_state::ProvenFeeVault,
};
use secrets_vault::{
    crypto::factory::{AutoCryptoFactory, CryptoFactory},
    memory::protected_memory::ProtectedMemory,
    types::{
        algorithm::Algorithm, metadata::Metadata, secret::Secret, secret_id::SecretId,
        store_mode::StoreMode,
    },
    vault::SecretVault,
};
use wallet_pq_signer::{Rejected, fee::verify_seed_and_wipe};
use zeroize::Zeroize;

const PROFILE_TAG: &str = "tos-wallet-fee-seed-profile";
const PROFILE: &str = "lms-h20-w4-seed-v1";
struct Wipe<'a>(&'a mut [u8]);
impl Drop for Wipe<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Restore a fee seed into a new record in an authenticated, exclusively owned
/// encrypted Vault. Enrollment must be independently authenticated. A public
/// path binds the seed without signing or consuming a leaf. Flush and bound
/// readback precede success. Cancellation/failure can leave a record: never
/// automatically overwrite or delete it. The input guard is installed before
/// returning the future, so even an unpolled future wipes the caller's seed.
/// This restores no journal state and does not revoke any old device.
pub fn restore_seed_and_wipe<'a>(
    vault: &'a SecretVault,
    id: &'a SecretId,
    seed: &'a mut [u8],
    key: &'a [u8; 60],
    leaf: u32,
    path: &'a [u8; 640],
) -> impl std::future::Future<Output = Result<(), Rejected>> + 'a {
    let seed = Wipe(seed);
    async move {
        if seed.0.len() != 48 {
            return Err(Rejected);
        }
        let protected = ProtectedMemory::from_slice(seed.0).await.map_err(|_| Rejected)?;
        verify_seed_and_wipe(seed.0, key, leaf, path)?;
        drop(seed);
        let metadata =
            Metadata::new(Some(id), Algorithm::None, true).with_tag(PROFILE_TAG, PROFILE);
        let secret = Secret::from_protected_data(
            protected,
            metadata,
            AutoCryptoFactory {}.new_crypto().map_err(|_| Rejected)?,
        )
        .await
        .map_err(|_| Rejected)?;
        vault.put(&secret, StoreMode::NewOnly).await.map_err(|_| Rejected)?;
        vault.flush().await.map_err(|_| Rejected)?;
        drop(secret);
        drop(load_bound(vault, id, key, leaf, path).await?);
        Ok(())
    }
}

async fn load_bound(
    vault: &SecretVault,
    id: &SecretId,
    key: &[u8; 60],
    leaf: u32,
    path: &[u8; 640],
) -> Result<ProtectedMemory, Rejected> {
    let secret = vault.get(id).await.map_err(|_| Rejected)?;
    let Secret::Blob { blob } = secret else {
        return Err(Rejected);
    };
    let meta = blob.metadata();
    if meta.secret_id.as_ref() != Some(id)
        || meta.algorithm != Algorithm::None
        || meta.get_tag(PROFILE_TAG) != Some(PROFILE)
        || meta.is_expired()
    {
        return Err(Rejected);
    }
    let seed = blob.data().await.map_err(|_| Rejected)?;
    let mut copy = seed.clone().await.map_err(|_| Rejected)?;
    let mut locked = copy.lock_mut().await.map_err(|_| Rejected)?;
    verify_seed_and_wipe(&mut locked, key, leaf, path)?;
    Ok(seed)
}

impl FeeJournal {
    /// Load a bound fee seed and sign only through this journal's durable
    /// reservation path. `clock` is sampled again after asynchronous loading;
    /// it must be a trusted local clock, not an endpoint-controlled timestamp.
    /// Proof time still determines leaf allocation. Recheck freshness and the
    /// restore barrier after loading; cancellation before reservation signs
    /// nothing. Cached retries require no key loading or new signature.
    pub async fn sign_proven_fee_from_vault(
        &mut self,
        storage: &SecretVault,
        id: &SecretId,
        view: &ProvenFeeVault,
        mut clock: impl FnMut() -> u32,
        valid_until: u32,
        value: u128,
        payload: FeePayload,
        path: &[u8; 640],
    ) -> anyhow::Result<SignedFeeMessage> {
        let plan = self.preview_proven(view, clock())?;
        let mut seed = load_bound(storage, id, view.fee_public_key(), plan.leaf, path).await?;
        let mut locked = seed.lock_mut().await.map_err(|_| Rejected)?;
        self.sign_proven_fee_with_seed_and_wipe(
            view,
            clock(),
            valid_until,
            value,
            payload,
            &mut locked,
            path,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use secrets_vault::{
        crypto::{key_material::KeyMaterial, master_key::MasterKey},
        events::null_handler::NullEventHandler,
        storage::file_json::FileJsonStorage,
    };
    use std::{path::Path, sync::Arc};

    pub(crate) async fn open(path: &Path) -> SecretVault {
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
    async fn fee_vault_restore_binds_reopens_and_never_overwrites() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../wallet-pq-signer/tests/fixtures/lms-fee-signature.json"
        ))
        .unwrap();
        let key: [u8; 60] =
            hex::decode(v["public_key"].as_str().unwrap()).unwrap().try_into().unwrap();
        let signature = hex::decode(v["signature"].as_str().unwrap()).unwrap();
        let path: [u8; 640] = signature[2192..].try_into().unwrap();
        fn seed() -> [u8; 48] {
            let mut s = [0x44; 48];
            s[32..].fill(0x55);
            s
        }
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("fee-vault.json");
        let id = SecretId::new("fee");
        let vault = open(&file).await;
        let mut input = seed();
        drop(restore_seed_and_wipe(&vault, &id, &mut input, &key, 12, &path));
        assert_eq!(input, [0; 48], "unpolled fee restore retained seed");
        assert!(vault.get(&id).await.is_err());
        input = seed();
        input[0] ^= 1;
        assert!(restore_seed_and_wipe(&vault, &id, &mut input, &key, 12, &path).await.is_err());
        assert_eq!(input, [0; 48]);
        assert!(vault.get(&id).await.is_err(), "fee restore persisted wrong seed");
        input = seed();
        restore_seed_and_wipe(&vault, &id, &mut input, &key, 12, &path).await.unwrap();
        assert_eq!(input, [0; 48]);
        let before = std::fs::read(&file).unwrap();
        input = seed();
        assert!(
            restore_seed_and_wipe(&vault, &id, &mut input, &key, 12, &path).await.is_err(),
            "fee restore overwrote enrolled record"
        );
        assert_eq!(input, [0; 48]);
        assert_eq!(std::fs::read(&file).unwrap(), before);
        drop(vault);
        let vault = open(&file).await;
        drop(load_bound(&vault, &id, &key, 12, &path).await.unwrap());
        let mut wrong = key;
        wrong[28] ^= 1;
        assert!(
            load_bound(&vault, &id, &wrong, 12, &path).await.is_err(),
            "fee vault loaded wrong enrollment"
        );
        // A valid seed in a generic blob must not be accepted as a fee record.
        let other = SecretId::new("untagged");
        let data = ProtectedMemory::from_slice(&seed()).await.unwrap();
        let secret = Secret::from_protected_data(
            data,
            Metadata::new(Some(&other), Algorithm::None, true),
            AutoCryptoFactory {}.new_crypto().unwrap(),
        )
        .await
        .unwrap();
        vault.put(&secret, StoreMode::NewOnly).await.unwrap();
        vault.flush().await.unwrap();
        assert!(
            load_bound(&vault, &other, &key, 12, &path).await.is_err(),
            "fee vault accepted untagged record"
        );
    }
}
