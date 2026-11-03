// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Bounded encrypted pages for state, journals and backups. This layer performs
//! no filesystem writes and does not establish freshness, balance or rollback
//! protection. The caller supplies authenticated expected pins and record position.
use crate::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroizing;

pub const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
const MAGIC: &[u8; 4] = b"TSP1";
const VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const HEADER_BYTES: usize = 4 + 1 + 1 + 8 + NONCE_BYTES;
const TAG_BYTES: usize = 16;
pub const MAX_SEALED_BYTES: usize = MAX_PLAINTEXT_BYTES + HEADER_BYTES + TAG_BYTES;
const KEY_LABEL: &[u8] = b"TOS-SHIELD-MOBILE-STATE-KEY-v1";
const AAD_LABEL: &[u8] = b"TOS-SHIELD-MOBILE-STATE-AAD-v1";

/// Fixed-width encoding prevents ambiguous concatenation. These are expected
/// local selections, never values accepted merely because a record decrypts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub global_id: i32,
    /// Canonical workchain-zero account ID. Other workchains are not supported
    /// by this format; callers must reject them before constructing the binding.
    pub pool_account: [u8; 32],
    pub genesis_root: [u8; 32],
    pub genesis_file: [u8; 32],
    pub code_hash: [u8; 32],
    pub profile_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub verifying_key_hash: [u8; 32],
}
impl Binding {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 7 * 32);
        out.extend_from_slice(&self.global_id.to_be_bytes());
        for field in [
            &self.pool_account,
            &self.genesis_root,
            &self.genesis_file,
            &self.code_hash,
            &self.profile_hash,
            &self.manifest_hash,
            &self.verifying_key_hash,
        ] {
            out.extend_from_slice(field);
        }
        out
    }
}
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    State = 1,
    Journal = 2,
    Backup = 3,
}

/// Owns only a zeroizing derived key, never the seed. Each operation's temporary
/// XChaCha20Poly1305 instance also zeroizes its internal key on drop.
pub struct RecordCipher {
    key: Zeroizing<[u8; 32]>,
    binding: Binding,
}
impl RecordCipher {
    /// The borrowed seed remains owned by the caller, which must clear it.
    /// No guarantee is made about erasure of the hash implementation's temporary state.
    pub fn derive(seed: &[u8; 32], binding: Binding) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        let mut shake = Shake256::default();
        shake.update(KEY_LABEL);
        shake.update(seed);
        shake.update(&binding.encode());
        shake.finalize_xof().read(key.as_mut());
        Self { key, binding }
    }
    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(self.key.as_ref()).map_err(|_| Error::Crypto)
    }
    fn aad(&self, header: &[u8]) -> Vec<u8> {
        let mut aad = self.binding.encode();
        aad.extend_from_slice(AAD_LABEL);
        aad.extend_from_slice(header);
        aad
    }
    /// A fresh random nonce is generated for every page, including replacement
    /// state and a backup made after restoring older state. RNG failure is an error.
    /// The caller remains responsible for clearing the borrowed plaintext.
    pub fn seal(&self, kind: Kind, sequence: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(Error::Limit);
        }
        let mut nonce = [0u8; NONCE_BYTES];
        rand::rngs::OsRng.try_fill_bytes(&mut nonce).map_err(|_| Error::Crypto)?;
        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.push(kind as u8);
        header.extend_from_slice(&sequence.to_be_bytes());
        header.extend_from_slice(&nonce);
        let aad = self.aad(&header);
        let ciphertext = self
            .cipher()?
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| Error::Crypto)?;
        let total = HEADER_BYTES.checked_add(ciphertext.len()).ok_or(Error::Limit)?;
        let mut out = Vec::new();
        out.try_reserve_exact(total).map_err(|_| Error::Limit)?;
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
    /// Expected kind and position belong to the caller's schema, not to a
    /// self-reported header. Old formats and partial records are never rewritten.
    pub fn open(&self, kind: Kind, sequence: u64, record: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if record.len() > MAX_SEALED_BYTES {
            return Err(Error::Limit);
        }
        if record.len() < HEADER_BYTES + TAG_BYTES
            || &record[..4] != MAGIC
            || record[4] != VERSION
            || record[5] != kind as u8
            || record[6..14] != sequence.to_be_bytes()
        {
            return Err(Error::InvalidInput);
        }
        let header = &record[..HEADER_BYTES];
        let aad = self.aad(header);
        self.cipher()?
            .decrypt(
                XNonce::from_slice(&header[14..]),
                Payload { msg: &record[HEADER_BYTES..], aad: &aad },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::Crypto)
    }
}
