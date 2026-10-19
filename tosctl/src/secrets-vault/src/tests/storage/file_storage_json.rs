/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    storage::file_json::FileJsonStorage,
    tests::fixture::*,
    types::{algorithm::Algorithm, metadata::Metadata, secret::Secret, store_mode::StoreMode},
};

#[tokio::test]
#[serial_test::serial]
async fn test_file_format_is_json() -> anyhow::Result<()> {
    for config in fixture() {
        if config.storage_type != StorageType::FileJson {
            continue;
        }

        let crypto_factory = create_crypto_factory(config.crypto_type).await?;
        let storage = create_test_storage(&config).await.unwrap();
        let secret_id = "test/key".into();
        let metadata = Metadata::new(Some(&secret_id), Algorithm::Aes256Gcm, true);
        let secret =
            Secret::from_raw_data(b"test_value", metadata, crypto_factory.new_crypto()?).await?;

        storage.store(&secret, StoreMode::NewOnly).await?;

        let file_storage = storage.as_ref().downcast_ref::<FileJsonStorage>().unwrap();
        let file_content = tokio::fs::read_to_string(file_storage.file_path()).await?;
        let parsed: serde_json::Value = serde_json::from_str(&file_content)?;

        assert!(parsed.get("version").is_some());
        assert!(parsed.get("tree").is_some());
    }

    Ok(())
}

/// The vault is saved through the private writer: a symbolic link planted at
/// the old predictable temporary name is ignored, the saved file is 0600, and
/// a vault path that has been replaced by a link is refused.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn test_store_ignores_planted_temporary_and_refuses_linked_vault() -> anyhow::Result<()> {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let config = fixture()
        .into_iter()
        .find(|c| c.storage_type == StorageType::FileJson)
        .ok_or_else(|| anyhow::anyhow!("no file storage fixture"))?;
    let dir = private_tempdir()?;
    let file_path = dir.path().join("vault.json");
    let victim = dir.path().join("victim");
    std::fs::write(&victim, b"unchanged")?;
    symlink(&victim, file_path.with_extension("tmp"))?;

    let crypto_factory = create_crypto_factory(config.crypto_type).await?;
    let storage = FileJsonStorage::new(
        create_test_master_key().await?,
        &file_path,
        create_crypto_factory(config.crypto_type).await?,
        false,
    )
    .await?;
    let secret_id = "test/key".into();
    let metadata = Metadata::new(Some(&secret_id), Algorithm::Aes256Gcm, true);
    let secret = Secret::from_raw_data(b"value", metadata, crypto_factory.new_crypto()?).await?;
    crate::storage::storage_trait::Storage::store(&storage, &secret, StoreMode::NewOnly).await?;

    assert_eq!(std::fs::read(&victim)?, b"unchanged");
    let meta = std::fs::symlink_metadata(&file_path)?;
    assert!(meta.is_file());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    std::fs::remove_file(&file_path)?;
    symlink(&victim, &file_path)?;
    let other_id = "test/other".into();
    let metadata = Metadata::new(Some(&other_id), Algorithm::Aes256Gcm, true);
    let other = Secret::from_raw_data(b"other", metadata, crypto_factory.new_crypto()?).await?;
    assert!(crate::storage::storage_trait::Storage::store(&storage, &other, StoreMode::NewOnly)
        .await
        .is_err());
    assert_eq!(std::fs::read(&victim)?, b"unchanged");
    Ok(())
}
