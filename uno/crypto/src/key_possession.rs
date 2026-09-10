//! Registration Schnorr possession: zP = R + cH, H is the balance kernel's
//! Pedersen blinding generator. This independent entry has not undergone D34's
//! relation-family review: correspondence tests are not a reliability argument.
//!
//! Verification establishes possession and transcript binding, with nonidentity
//! P. The host must additionally match address/configuration fields independently.
//! It cannot establish the origin or independence of s: not reusing a Native
//! signing secret is wallet-side generation discipline, unverifiable on chain.
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::CompressedRistretto, Scalar, traits::IsIdentity};
use sha2::{Digest, Sha512};
use crate::ffi::{AbiStatus as Error, KeyPossessionRequestV1};

fn challenge(r: &KeyPossessionRequestV1, commitment: &[u8; 32]) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"TOS/UNO/REGISTER/KEY-POSSESSION/v1");
    // Fixed-width fields, in ABI declaration order, excluding abi_version and
    // proof response. Integer encodings are big-endian, never C padding/native
    // byte order. Version separation is provided by the literal domain above.
    hash.update(r.global_id.to_be_bytes());
    hash.update(r.genesis_hash);
    hash.update(r.workchain_id.to_be_bytes());
    hash.update(r.account);
    hash.update(r.incarnation);
    hash.update(r.asset);
    hash.update(r.custody);
    hash.update(r.policy);
    hash.update(r.schema_version.to_be_bytes());
    hash.update(r.relation_profile.to_be_bytes());
    hash.update(r.proof_profile.to_be_bytes());
    hash.update(r.key_epoch.to_be_bytes());
    hash.update(r.public_key);
    hash.update(commitment);
    Scalar::from_bytes_mod_order_wide(&hash.finalize().into())
}

pub(crate) fn verify(request: &KeyPossessionRequestV1) -> Result<(), Error> {
    let p = CompressedRistretto(request.public_key).decompress().ok_or(Error::UNO_CRYPTO_DECODE)?;
    let encoded_r: [u8; 32] = request.proof[..32].try_into().unwrap();
    let r = CompressedRistretto(encoded_r).decompress().ok_or(Error::UNO_CRYPTO_DECODE)?;
    if p.is_identity() || r.is_identity() { return Err(Error::UNO_CRYPTO_DECODE); }
    let encoded_z: [u8; 32] = request.proof[32..].try_into().unwrap();
    let z = Option::<Scalar>::from(Scalar::from_canonical_bytes(encoded_z)).ok_or(Error::UNO_CRYPTO_DECODE)?;
    let c = challenge(request, &encoded_r);
    if z * p != r + c * PedersenGens::default().B_blinding {
        return Err(Error::UNO_CRYPTO_VERIFY);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::uno_crypto_verify_key_possession_v1;

    fn signed() -> KeyPossessionRequestV1 {
        // Test-only fixed secrets/nonces; never a wallet generation routine.
        let s = Scalar::from(71u64);
        let k = Scalar::from(93u64);
        let p = s.invert() * PedersenGens::default().B_blinding;
        let commitment = (k * p).compress().to_bytes();
        let mut r = KeyPossessionRequestV1 { abi_version: 1, global_id: -23903,
            genesis_hash: [1;32], workchain_id: 2, account: [2;32], incarnation: [3;32],
            asset: [4;32], custody: [5;32], policy: [6;32], schema_version: 1,
            relation_profile: 1, proof_profile: 2, key_epoch: 0,
            public_key: p.compress().to_bytes(), proof: [0;64] };
        let z = k + challenge(&r, &commitment) * s;
        r.proof[..32].copy_from_slice(&commitment);
        r.proof[32..].copy_from_slice(&z.to_bytes());
        r
    }
    #[test]
    fn possession_and_every_context_field() {
        let r = signed();
        assert_eq!(unsafe { uno_crypto_verify_key_possession_v1(&r) }, 0);
        let changes: &[fn(&mut KeyPossessionRequestV1)] = &[
            |r| r.global_id += 1, |r| r.genesis_hash[0] ^= 1,
            |r| r.workchain_id += 1, |r| r.account[0] ^= 1,
            |r| r.incarnation[0] ^= 1, |r| r.asset[0] ^= 1,
            |r| r.custody[0] ^= 1, |r| r.policy[0] ^= 1,
            |r| r.schema_version += 1, |r| r.relation_profile += 1,
            |r| r.proof_profile += 1, |r| r.key_epoch += 1,
        ];
        for change in changes {
            let mut other = r;
            change(&mut other);
            assert_eq!(unsafe { uno_crypto_verify_key_possession_v1(&other) }, Error::UNO_CRYPTO_VERIFY as u32);
        }
    }
    #[test]
    fn malformed_and_wrong_proof() {
        let mut r = signed();
        r.proof[32] ^= 1;
        assert_ne!(unsafe { uno_crypto_verify_key_possession_v1(&r) }, 0);
        r = signed(); r.public_key = [0;32];
        assert_eq!(unsafe { uno_crypto_verify_key_possession_v1(&r) }, Error::UNO_CRYPTO_DECODE as u32);
        r = signed(); r.proof[32..].fill(255);
        assert_eq!(unsafe { uno_crypto_verify_key_possession_v1(&r) }, Error::UNO_CRYPTO_DECODE as u32);
        r = signed(); r.abi_version = 2;
        assert_eq!(unsafe { uno_crypto_verify_key_possession_v1(&r) }, Error::UNO_CRYPTO_ARGUMENTS as u32);
        assert_eq!(unsafe { uno_crypto_verify_key_possession_v1(std::ptr::null()) }, Error::UNO_CRYPTO_ARGUMENTS as u32);
    }
}
