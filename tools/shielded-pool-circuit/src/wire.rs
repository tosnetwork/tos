/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The public inputs the contract computes from bytes rather than reads off
//! the wire.
//!
//! Eight of the eighteen are derived: the three output-payload hashes, the two
//! ML-DSA public-key hashes, the recipient hash, the execution domain and the
//! recovery template hash. The contract recomputes each of them from the bytes
//! that actually arrived, so a prover that guesses them proves a transaction
//! the contract will refuse. These functions are how a wallet computes the
//! same values before it proves anything.
//!
//! Everything here is SHA-256 reduced into the field, which is a different
//! construction from the Poseidon2 commitments in `notes`. The profile uses
//! SHA-256 exactly where the operand is a long byte string the circuit never
//! has to open: a 1233-byte payload or a 1312-byte key is cheap to hash on
//! chain and would be ruinous in circuit.

use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

use crate::domains::h7;
use crate::field::Fr;

/// Section 3: the canonical outer payload is exactly this many bytes.
pub const OUTPUT_DATA_BYTES: usize = 1233;
/// Section 4.1: an ML-DSA-44 public key is exactly this many bytes.
pub const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;

/// `reduce_to_field(SHA256(tag || body))`, the construction every derivation
/// below shares. The contract spells it as `HASHEXT_SHA256` over the tag slice
/// followed by the operand's cells, which is the same byte stream: the chunks
/// are a cell-layout detail and hashing does not see them.
fn tagged(tag: &[u8], body: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(body);
    let digest: [u8; 32] = hasher.finalize().into();
    // The contract reduces rather than rejects here, because the operand is a
    // hash of its own making and not a user-supplied field element.
    Fr::from_be_bytes_mod_order(&digest)
}

/// Public inputs 6, 7 and 8. `bytes` is the whole 1233-byte payload.
pub fn output_data_hash(bytes: &[u8]) -> Fr {
    tagged(b"TOS-SHIELDED-OUTPUT-DATA-v1", bytes)
}

/// Section 4.1, and public inputs 9 and 10. `bytes` is the whole 1312-byte
/// ML-DSA-44 public key.
pub fn pq_auth_key_hash(bytes: &[u8]) -> Fr {
    tagged(b"TOS-SHIELDED-MLDSA44-PK-v1", bytes)
}

/// Public input 13. `account` is the 32-byte account id of a workchain-zero
/// standard address; a transfer's recipient hash is zero and never reaches
/// this function.
pub fn public_recipient_hash(account: &[u8; 32]) -> Fr {
    tagged(b"TOS-SHIELDED-RECIPIENT-v1", account)
}

/// Section 8, and public input 15. This is a deployment fact: it binds the
/// chain and the particular pool account, so a proof made for one pool cannot
/// be replayed against another, and a proof made for one chain cannot be
/// replayed on a fork with a different global id.
pub fn execution_domain(global_id: i32, pool_account: &[u8; 32]) -> Fr {
    let mut body = Vec::with_capacity(4 + 1 + 32 + 2);
    body.extend_from_slice(&global_id.to_be_bytes());
    body.push(0);
    body.extend_from_slice(pool_account);
    body.extend_from_slice(&1u16.to_be_bytes());
    tagged(b"TOS-SHIELDED-EXEC-v1", &body)
}

/// Section 15.1, and public input 16. Unlike the others this one is Poseidon2:
/// its operands are already field elements, so there is no long byte string to
/// hash. A transfer's is zero.
pub fn recovery_template_hash(recovery_owner_commitment: Fr, recovery_data_hash: Fr) -> Fr {
    h7(
        "RECOVERY-TEMPLATE",
        &[
            recovery_owner_commitment,
            recovery_data_hash,
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ],
    )
}
