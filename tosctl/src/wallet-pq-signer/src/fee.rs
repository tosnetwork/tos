// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Stateless fee signature verification, reusing the native consensus verifier.
//! This module supplies no LMS signing key, leaf reservation or rollback defense.
use crate::Rejected;
unsafe extern "C" {
    fn tos_wallet_lms_fee_verify(
        leaf: u32,
        digest: *const u8,
        digest_size: usize,
        signature: *const u8,
        signature_size: usize,
        public_key: *const u8,
        key_size: usize,
    ) -> i32;
}

/// Verify HSS L1 / LMS H20 / LMOTS W4 bytes against the exact reserved leaf,
/// fee-intent digest and independently enrolled public key. Failure exports no
/// usable signature. Success says nothing about freshness or leaf uniqueness.
pub fn verify_reserved_signature(
    public_key: &[u8],
    leaf: u32,
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), Rejected> {
    // SAFETY: all slices remain live for this synchronous call. Native code
    // checks exact lengths and the leaf bound before accessing any buffer.
    let valid = unsafe {
        tos_wallet_lms_fee_verify(
            leaf,
            digest.as_ptr(),
            digest.len(),
            signature.as_ptr(),
            signature.len(),
            public_key.as_ptr(),
            public_key.len(),
        )
    };
    if valid == 1 { Ok(()) } else { Err(Rejected) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fee_verifier_binds_reserved_leaf_digest_key_and_signature() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/lms-fee-signature.json")).unwrap();
        let key = hex::decode(v["public_key"].as_str().unwrap()).unwrap();
        let digest: [u8; 32] =
            hex::decode(v["digest"].as_str().unwrap()).unwrap().try_into().unwrap();
        let signature = hex::decode(v["signature"].as_str().unwrap()).unwrap();
        let leaf = u32::try_from(v["leaf"].as_u64().unwrap()).unwrap();
        verify_reserved_signature(&key, leaf, &digest, &signature).unwrap();
        assert!(
            verify_reserved_signature(&key, leaf + 1, &digest, &signature).is_err(),
            "fee verifier ignored reserved leaf"
        );
        let mut wrong = digest;
        wrong[0] ^= 1;
        assert!(
            verify_reserved_signature(&key, leaf, &wrong, &signature).is_err(),
            "fee verifier accepted wrong digest"
        );
        for offset in [0, 4, 8, 12, 28, 59] {
            let mut wrong = key.clone();
            wrong[offset] ^= 1;
            assert!(
                verify_reserved_signature(&wrong, leaf, &digest, &signature).is_err(),
                "fee verifier accepted changed key"
            );
        }
        for offset in [0, 4, 8, 12, 44, 2188, 2192, 2831] {
            let mut wrong = signature.clone();
            wrong[offset] ^= 1;
            assert!(
                verify_reserved_signature(&key, leaf, &digest, &wrong).is_err(),
                "fee verifier accepted changed signature"
            );
        }
        for invalid in [1 << 20, u32::MAX] {
            assert!(verify_reserved_signature(&key, invalid, &digest, &signature).is_err());
        }
        assert!(verify_reserved_signature(&[], leaf, &digest, &signature).is_err());
        assert!(verify_reserved_signature(&key, leaf, &digest, &[]).is_err());
        assert!(verify_reserved_signature(&key[..59], leaf, &digest, &signature).is_err());
        assert!(verify_reserved_signature(&key, leaf, &digest, &signature[..2831]).is_err());
    }
}
