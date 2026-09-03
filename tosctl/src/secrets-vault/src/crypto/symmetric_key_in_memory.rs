/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    crypto::key_material::KeyMaterial,
    errors::error::VaultError,
    memory::protected_memory::ProtectedMemory,
    types::{metadata::Metadata, secret::SymmetricKey, secret_id::SecretId},
};

pub struct SymmetricKeyInMemory {
    metadata: Metadata,
    key_material: KeyMaterial,
}

impl SymmetricKeyInMemory {
    pub fn new(metadata: &Metadata, key_material: KeyMaterial) -> Self {
        Self { metadata: metadata.clone(), key_material }
    }
}

#[async_trait::async_trait]
impl SymmetricKey for SymmetricKeyInMemory {
    fn id(&self) -> Option<&SecretId> {
        self.metadata.secret_id.as_ref()
    }

    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    async fn extractable(&self) -> anyhow::Result<bool> {
        Ok(self.metadata.extractable)
    }

    async fn key(&self) -> anyhow::Result<ProtectedMemory> {
        if !self.metadata.extractable {
            anyhow::bail!(VaultError::not_extractable(self.metadata.secret_id.as_ref()))
        }

        let secret_key = self
            .key_material
            .secret_key
            .as_ref()
            .ok_or_else(|| VaultError::empty_secret_key("Secret key is not set"))?;

        secret_key.clone().await
    }

    // Symmetric encryption through this in-memory handle is not implemented.
    // These return an error rather than aborting: the type is constructed for
    // every symmetric secret loaded from storage, so a caller reaching them --
    // today there is none -- would otherwise take the process down instead of
    // surfacing a missing capability.
    async fn encrypt(&self, _plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!(VaultError::encryption_failed(
            "in-memory symmetric key does not implement encryption"
        ))
    }

    async fn decrypt(&self, _ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!(VaultError::decryption_failed(
            "in-memory symmetric key does not implement decryption"
        ))
    }

    async fn serialize(&self) -> anyhow::Result<ProtectedMemory> {
        self.key_material.serialize().await
    }
}
