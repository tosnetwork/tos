/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 2.4: the recipient descriptor.
//!
//! What a payee hands a payer. It never goes on chain; it is the off-chain
//! object that says "send to this index, under this domain, with this key".
//!
//! A descriptor is single use, and section 2.5 is careful that this is a
//! wallet issuance rule and not a consensus one. A payer who kept an old
//! descriptor can send to it again whenever they like, so the wallet's job is
//! to behave deterministically when they do rather than to assume they will
//! not.

use ark_ff::PrimeField;
use shielded_pool_circuit::field::{is_canonical, Fr};

use crate::error::{Error, Result};
use crate::keys::{fr_be32, PoolInstance, MLDSA_PUBLIC_KEY_BYTES, MLKEM_ENCAPSULATION_KEY_BYTES};

pub const MAGIC: u32 = 0x5348_4431;
pub const VERSION: u8 = 1;
/// 4 + 1 + 32 + 8 + 32 + 1312 + 1184.
pub const DESCRIPTOR_BYTES: usize = 2573;

/// Section 2.4's binary object.
#[derive(Clone)]
pub struct Descriptor {
    pub execution_domain: Fr,
    pub note_key_index: u64,
    pub owner_nf_key_hash: Fr,
    pub pq_auth_public_key: [u8; MLDSA_PUBLIC_KEY_BYTES],
    pub mlkem_encapsulation_key: [u8; MLKEM_ENCAPSULATION_KEY_BYTES],
}

impl Descriptor {
    /// Everything in a descriptor is derived, so issuing one is choosing an
    /// index and nothing else.
    pub fn issue(instance: &PoolInstance, note_key_index: u64) -> Result<Self> {
        Ok(Descriptor {
            execution_domain: instance.execution_domain(),
            note_key_index,
            owner_nf_key_hash: instance.owner_nf_key_hash(note_key_index)?,
            pq_auth_public_key: instance.mldsa_public_key(note_key_index)?,
            mlkem_encapsulation_key: instance.mlkem_encapsulation_key()?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DESCRIPTOR_BYTES);
        out.extend_from_slice(&MAGIC.to_be_bytes());
        out.push(VERSION);
        out.extend_from_slice(&fr_be32(self.execution_domain));
        out.extend_from_slice(&self.note_key_index.to_be_bytes());
        out.extend_from_slice(&fr_be32(self.owner_nf_key_hash));
        out.extend_from_slice(&self.pq_auth_public_key);
        out.extend_from_slice(&self.mlkem_encapsulation_key);
        out
    }

    /// Rejects rather than reduces: a descriptor carrying a non-canonical
    /// field element is not a descriptor whose domain happens to be large.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DESCRIPTOR_BYTES {
            return Err(Error::Encoding(format!(
                "a descriptor is {DESCRIPTOR_BYTES} bytes, not {}",
                bytes.len()
            )));
        }
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != MAGIC {
            return Err(Error::Encoding(format!("magic {magic:#010x}")));
        }
        if bytes[4] != VERSION {
            return Err(Error::Encoding(format!("version {}", bytes[4])));
        }
        // Rejects rather than reduces, per section 1.1.
        let field = |at: usize| -> Result<Fr> {
            let mut value = [0u8; 32];
            value.copy_from_slice(&bytes[at..at + 32]);
            if !is_canonical(&value) {
                return Err(Error::Encoding("a field element at or above the modulus".into()));
            }
            Ok(Fr::from_be_bytes_mod_order(&value))
        };
        let execution_domain = field(5)?;
        let mut index = [0u8; 8];
        index.copy_from_slice(&bytes[37..45]);
        let note_key_index = u64::from_be_bytes(index);
        let owner_nf_key_hash = field(45)?;
        let mut pq_auth_public_key = [0u8; MLDSA_PUBLIC_KEY_BYTES];
        pq_auth_public_key.copy_from_slice(&bytes[77..77 + MLDSA_PUBLIC_KEY_BYTES]);
        let mut mlkem_encapsulation_key = [0u8; MLKEM_ENCAPSULATION_KEY_BYTES];
        mlkem_encapsulation_key.copy_from_slice(
            &bytes[77 + MLDSA_PUBLIC_KEY_BYTES
                ..77 + MLDSA_PUBLIC_KEY_BYTES + MLKEM_ENCAPSULATION_KEY_BYTES],
        );
        Ok(Descriptor {
            execution_domain,
            note_key_index,
            owner_nf_key_hash,
            pq_auth_public_key,
            mlkem_encapsulation_key,
        })
    }

    /// A descriptor is valid only for the exact execution domain of the pool
    /// it names. Paying one under another domain would produce a note whose
    /// keys the recipient cannot derive.
    pub fn require_domain(&self, execution_domain: Fr) -> Result<()> {
        if self.execution_domain != execution_domain {
            return Err(Error::Encoding("a descriptor for another execution domain".to_string()));
        }
        Ok(())
    }
}
