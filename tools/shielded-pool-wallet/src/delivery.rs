/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 3: the 1233 bytes that travel with a note.
//!
//! Every output carries exactly these bytes, real or dummy, so the payload
//! length says nothing about which outputs are real. The contract hashes them
//! and puts the hash in the public input vector; it never looks inside.
//!
//! The plaintext is not self-authenticating. A payer chooses what goes in it,
//! and the contract cannot check it against anything. That is why section 3.1
//! exists and why `Payload::open` is not the end of importing a note.

use ark_ff::PrimeField;
use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::XChaCha20Poly1305;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use shielded_pool_circuit::field::{is_canonical, Fr};

use crate::error::{Error, Rejection, Result};
use crate::keys::{fr_be32, PoolInstance, MLKEM_CIPHERTEXT_BYTES, SHARED_SECRET_BYTES};

pub const PLAINTEXT_BYTES: usize = 128;
pub const AEAD_CIPHERTEXT_BYTES: usize = PLAINTEXT_BYTES + 16;
/// Section 3: `1 + 1088 + 144`.
pub const OUTPUT_DATA_BYTES: usize = 1 + MLKEM_CIPHERTEXT_BYTES + AEAD_CIPHERTEXT_BYTES;

pub const MAGIC: u32 = 0x5348_4e31;
pub const VERSION: u8 = 1;

/// Section 3's flags. Dummy and recovery must not both be set, and no other
/// bit may be.
pub const FLAG_DUMMY: u16 = 0x0001;
pub const FLAG_RECOVERY: u16 = 0x0002;

/// What an output slot says about itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A spendable note.
    Ordinary,
    /// A slot that carries no value and exists so the wire shape is constant.
    Dummy,
    /// A withdrawal's pre-authorised recovery template.
    Recovery,
}

impl Kind {
    fn from_flags(flags: u16) -> std::result::Result<Self, Rejection> {
        match flags {
            0 => Ok(Kind::Ordinary),
            FLAG_DUMMY => Ok(Kind::Dummy),
            FLAG_RECOVERY => Ok(Kind::Recovery),
            _ => Err(Rejection::Flags),
        }
    }

    fn flags(self) -> u16 {
        match self {
            Kind::Ordinary => 0,
            Kind::Dummy => FLAG_DUMMY,
            Kind::Recovery => FLAG_RECOVERY,
        }
    }
}

/// The 128-byte plaintext of section 3.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Plaintext {
    pub slot: u8,
    pub kind: Kind,
    pub amount: u128,
    pub note_secret: Fr,
    pub owner_nf_key_hash: Fr,
    pub note_key_index: u64,
    pub pq_auth_key_hash: Fr,
}

impl Plaintext {
    pub fn to_bytes(&self) -> [u8; PLAINTEXT_BYTES] {
        let mut out = [0u8; PLAINTEXT_BYTES];
        out[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        out[4] = VERSION;
        out[5] = self.slot;
        out[6..8].copy_from_slice(&self.kind.flags().to_be_bytes());
        out[8..24].copy_from_slice(&self.amount.to_be_bytes());
        out[24..56].copy_from_slice(&fr_be32(self.note_secret));
        out[56..88].copy_from_slice(&fr_be32(self.owner_nf_key_hash));
        out[88..96].copy_from_slice(&self.note_key_index.to_be_bytes());
        out[96..128].copy_from_slice(&fr_be32(self.pq_auth_key_hash));
        out
    }

    /// Section 3.1's common checks 1 to 3. Everything that can be judged from
    /// the bytes alone happens here; everything that needs the wallet's keys
    /// or the chain happens in `import`.
    pub fn from_bytes(bytes: &[u8], slot: u8) -> std::result::Result<Self, Rejection> {
        if bytes.len() != PLAINTEXT_BYTES {
            return Err(Rejection::PlaintextLength);
        }
        if u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != MAGIC {
            return Err(Rejection::Magic);
        }
        if bytes[4] != VERSION {
            return Err(Rejection::Version);
        }
        if bytes[5] != slot {
            return Err(Rejection::Slot);
        }
        let kind = Kind::from_flags(u16::from_be_bytes([bytes[6], bytes[7]]))?;
        let mut amount = [0u8; 16];
        amount.copy_from_slice(&bytes[8..24]);
        let amount = u128::from_be_bytes(amount);

        let field = |at: usize| -> std::result::Result<Fr, Rejection> {
            let mut value = [0u8; 32];
            value.copy_from_slice(&bytes[at..at + 32]);
            if !is_canonical(&value) {
                return Err(Rejection::NoteSecretNotCanonical);
            }
            Ok(Fr::from_be_bytes_mod_order(&value))
        };
        let note_secret = field(24)?;
        if note_secret == Fr::from(0u64) {
            return Err(Rejection::NoteSecretZero);
        }
        let owner_nf_key_hash = field(56)?;
        let mut index = [0u8; 8];
        index.copy_from_slice(&bytes[88..96]);
        let pq_auth_key_hash = field(96)?;

        Ok(Plaintext {
            slot,
            kind,
            amount,
            note_secret,
            owner_nf_key_hash,
            note_key_index: u64::from_be_bytes(index),
            pq_auth_key_hash,
        })
    }
}

/// Section 3 step 3: the AEAD key and nonce, bound to the domain and the slot
/// so the same shared secret cannot encrypt two slots the same way.
fn key_and_nonce(
    shared_secret: &[u8; SHARED_SECRET_BYTES],
    execution_domain: Fr,
    slot: u8,
) -> ([u8; 32], [u8; 24]) {
    let mut out = [0u8; 56];
    let mut hasher = Shake256::default();
    hasher.update(b"TOS-SHIELDED-DELIVERY-KDF-v1");
    hasher.update(shared_secret);
    hasher.update(&fr_be32(execution_domain));
    hasher.update(&[slot]);
    hasher.finalize_xof().read(&mut out);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    key.copy_from_slice(&out[0..32]);
    nonce.copy_from_slice(&out[32..56]);
    (key, nonce)
}

/// Section 3 step 4.
fn aad(execution_domain: Fr, slot: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    out.extend_from_slice(&fr_be32(execution_domain));
    out.push(slot);
    out
}

/// Seals a plaintext to a recipient's ML-KEM key, producing the exact 1233
/// bytes an output carries.
pub fn seal(
    encapsulation_key: &[u8; crate::keys::MLKEM_ENCAPSULATION_KEY_BYTES],
    execution_domain: Fr,
    plaintext: &Plaintext,
) -> Result<Vec<u8>> {
    let (shared_secret, kem_ciphertext) = PoolInstance::encapsulate_to(encapsulation_key)?;
    let (key, nonce) = key_and_nonce(&shared_secret, execution_domain, plaintext.slot);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|error| Error::Encoding(format!("AEAD key: {error}")))?;
    let sealed = cipher
        .encrypt(
            nonce.as_ref().into(),
            AeadPayload { msg: &plaintext.to_bytes(), aad: &aad(execution_domain, plaintext.slot) },
        )
        .map_err(|error| Error::Encoding(format!("AEAD seal: {error}")))?;
    if sealed.len() != AEAD_CIPHERTEXT_BYTES {
        return Err(Error::Encoding(format!("a {}-byte AEAD ciphertext", sealed.len())));
    }
    let mut out = Vec::with_capacity(OUTPUT_DATA_BYTES);
    out.push(VERSION);
    out.extend_from_slice(&kem_ciphertext);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// The other half. Failing to open is the ordinary case, not an error: most
/// payloads on a chain belong to somebody else.
pub fn open(
    instance: &PoolInstance,
    output_data: &[u8],
    slot: u8,
) -> std::result::Result<Plaintext, Rejection> {
    if output_data.len() != OUTPUT_DATA_BYTES || output_data[0] != VERSION {
        return Err(Rejection::PlaintextLength);
    }
    let mut kem_ciphertext = [0u8; MLKEM_CIPHERTEXT_BYTES];
    kem_ciphertext.copy_from_slice(&output_data[1..1 + MLKEM_CIPHERTEXT_BYTES]);
    let shared_secret =
        instance.decapsulate(&kem_ciphertext).map_err(|_| Rejection::Undecryptable)?;
    let domain = instance.execution_domain();
    let (key, nonce) = key_and_nonce(&shared_secret, domain, slot);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Rejection::Undecryptable)?;
    let opened = cipher
        .decrypt(
            nonce.as_ref().into(),
            AeadPayload {
                msg: &output_data[1 + MLKEM_CIPHERTEXT_BYTES..],
                aad: &aad(domain, slot),
            },
        )
        .map_err(|_| Rejection::Undecryptable)?;
    Plaintext::from_bytes(&opened, slot)
}
