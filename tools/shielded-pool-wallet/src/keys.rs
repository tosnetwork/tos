/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 2: the V1 key hierarchy.
//!
//! The mnemonic is the root and nothing else is stored. Every key a wallet
//! ever needs is recomputed from the seed and a `note_key_index`, which is
//! what makes mnemonic-only recovery possible: a restored wallet does not
//! reconstruct a keystore, it recomputes the keys and asks the chain which
//! ones were used.
//!
//! Everything below the instance master is derived from
//! `pool_instance_master`, never from the mnemonic-global `pool_master`. That
//! is what stops the same mnemonic and index from producing the same key on
//! two pools or on mainnet and testnet, and it is why the execution domain --
//! a deployment fact -- reaches this far into the wallet.

use ark_ff::{BigInteger, PrimeField};
use fips203::ml_kem_768;
use fips203::traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as _};
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use shielded_pool_circuit::domains::h7;
use shielded_pool_circuit::field::Fr;

use crate::error::{Error, Result};

/// Frozen sizes, section 2.2 and 2.3.
pub const MLKEM_ENCAPSULATION_KEY_BYTES: usize = 1184;
pub const MLKEM_CIPHERTEXT_BYTES: usize = 1088;
pub const MLDSA_PUBLIC_KEY_BYTES: usize = 1312;
pub const MLDSA_SIGNATURE_BYTES: usize = 2420;
pub const SHARED_SECRET_BYTES: usize = 32;

/// `SHAKE256(input, n)`.
fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut hasher = Shake256::default();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize_xof().read(out);
}

/// A field element as its 32 canonical big-endian bytes.
pub fn fr_be32(value: Fr) -> [u8; 32] {
    let digits = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - digits.len()..].copy_from_slice(&digits);
    out
}

/// The mnemonic-global base. Derived once per seed, and never used to derive
/// a key directly.
pub fn pool_master(tos_seed: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    shake(&[b"TOS-SHIELDED-POOL-MASTER-v1", tos_seed], &mut out);
    out
}

/// Everything a wallet holds for one pool on one chain.
///
/// Two execution domains from the same mnemonic share no key material below
/// this point, which is section 19 gate 30 and the reason this type exists
/// rather than a bag of free functions taking a domain.
pub struct PoolInstance {
    master: [u8; 64],
    domain: Fr,
}

impl PoolInstance {
    pub fn new(tos_seed: &[u8; 32], execution_domain: Fr) -> Self {
        let mut master = [0u8; 64];
        shake(
            &[b"TOS-SHIELDED-POOL-INSTANCE-v1", &pool_master(tos_seed), &fr_be32(execution_domain)],
            &mut master,
        );
        Self { master, domain: execution_domain }
    }

    pub fn execution_domain(&self) -> Fr {
        self.domain
    }

    /// Section 2.1. The retry rule is the interesting part: a derivation that
    /// reduces to zero is not usable, so attempt zero is the bare bytes and
    /// each retry appends its own counter. Returning the first non-zero result
    /// keeps the mapping from index to key deterministic, which is what a
    /// recovering wallet depends on.
    pub fn owner_nf_key(&self, note_key_index: u64) -> Result<Fr> {
        let index = note_key_index.to_be_bytes();
        for retry in 0u16..=255 {
            let mut wide = [0u8; 64];
            if retry == 0 {
                shake(&[b"TOS-SHIELDED-OWNER-NF-v1", &self.master, &index], &mut wide);
            } else {
                let counter = [retry as u8];
                shake(&[b"TOS-SHIELDED-OWNER-NF-v1", &self.master, &index, &counter], &mut wide);
            }
            let value = Fr::from_be_bytes_mod_order(&wide);
            if value != Fr::from(0u64) {
                return Ok(value);
            }
        }
        Err(Error::KeyDerivation(format!(
            "no non-zero owner-nullifier key for index {note_key_index} in 256 attempts"
        )))
    }

    /// Section 2.1, and what a note commitment binds rather than the key.
    pub fn owner_nf_key_hash(&self, note_key_index: u64) -> Result<Fr> {
        let key = self.owner_nf_key(note_key_index)?;
        Ok(h7(
            "OWNER-NF-HASH",
            &[
                key,
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            ],
        ))
    }

    /// Section 2.2. One long-lived ML-KEM key per execution domain, stored as
    /// the 64-byte `(d, z)` seed FIPS 203 permits, so a wallet still holds
    /// only a mnemonic. Long-lived within a domain is what lets a restored
    /// wallet decrypt everything ever sent to it.
    pub fn mlkem_seed(&self) -> ([u8; 32], [u8; 32]) {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        shake(&[b"TOS-SHIELDED-MLKEM-D-v1", &self.master], &mut d);
        shake(&[b"TOS-SHIELDED-MLKEM-Z-v1", &self.master], &mut z);
        (d, z)
    }

    pub fn mlkem_keys(&self) -> (ml_kem_768::EncapsKey, ml_kem_768::DecapsKey) {
        let (d, z) = self.mlkem_seed();
        ml_kem_768::KG::keygen_from_seed(d, z)
    }

    pub fn mlkem_encapsulation_key(&self) -> Result<[u8; MLKEM_ENCAPSULATION_KEY_BYTES]> {
        Ok(self.mlkem_keys().0.into_bytes())
    }

    /// Section 2.3. A different ML-DSA key per note, from the same index as
    /// the owner-nullifier key, so a descriptor carries no stable owner hash.
    pub fn mldsa_seed(&self, note_key_index: u64) -> [u8; 32] {
        let mut xi = [0u8; 32];
        shake(
            &[b"TOS-SHIELDED-MLDSA44-KEY-v1", &self.master, &note_key_index.to_be_bytes()],
            &mut xi,
        );
        xi
    }

    pub fn mldsa_keys(&self, note_key_index: u64) -> (ml_dsa_44::PublicKey, ml_dsa_44::PrivateKey) {
        ml_dsa_44::KG::keygen_from_seed(&self.mldsa_seed(note_key_index))
    }

    pub fn mldsa_public_key(&self, note_key_index: u64) -> Result<[u8; MLDSA_PUBLIC_KEY_BYTES]> {
        Ok(self.mldsa_keys(note_key_index).0.into_bytes())
    }

    /// Section 4.1, and public inputs 9 and 10.
    pub fn pq_auth_key_hash(&self, note_key_index: u64) -> Result<Fr> {
        Ok(shielded_pool_circuit::wire::pq_auth_key_hash(&self.mldsa_public_key(note_key_index)?))
    }

    /// Section 9.4: the signature a spend carries, over the intent digest's
    /// 32 big-endian bytes under the fixed 28-byte context.
    pub fn sign_intent(
        &self,
        note_key_index: u64,
        intent_digest: Fr,
    ) -> Result<[u8; MLDSA_SIGNATURE_BYTES]> {
        let (_, secret) = self.mldsa_keys(note_key_index);
        secret
            .try_sign(&fr_be32(intent_digest), crate::SIGNATURE_CONTEXT)
            .map_err(|error| Error::KeyDerivation(format!("ML-DSA-44 signing: {error}")))
    }

    /// Section 3 step 1: encapsulate to a recipient's key.
    pub fn encapsulate_to(
        encapsulation_key: &[u8; MLKEM_ENCAPSULATION_KEY_BYTES],
    ) -> Result<([u8; SHARED_SECRET_BYTES], [u8; MLKEM_CIPHERTEXT_BYTES])> {
        let key = ml_kem_768::EncapsKey::try_from_bytes(*encapsulation_key)
            .map_err(|error| Error::KeyDerivation(format!("ML-KEM-768 public key: {error}")))?;
        let (secret, ciphertext) = key
            .try_encaps()
            .map_err(|error| Error::KeyDerivation(format!("ML-KEM-768 encapsulation: {error}")))?;
        Ok((secret.into_bytes(), ciphertext.into_bytes()))
    }

    /// The other half, which only the holder of the mnemonic can do.
    pub fn decapsulate(
        &self,
        ciphertext: &[u8; MLKEM_CIPHERTEXT_BYTES],
    ) -> Result<[u8; SHARED_SECRET_BYTES]> {
        let (_, decaps) = self.mlkem_keys();
        let ciphertext = ml_kem_768::CipherText::try_from_bytes(*ciphertext)
            .map_err(|error| Error::KeyDerivation(format!("ML-KEM-768 ciphertext: {error}")))?;
        let secret = decaps
            .try_decaps(&ciphertext)
            .map_err(|error| Error::KeyDerivation(format!("ML-KEM-768 decapsulation: {error}")))?;
        Ok(secret.into_bytes())
    }
}
