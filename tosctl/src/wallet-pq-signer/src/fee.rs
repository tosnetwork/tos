// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Stateless fee signature verification, reusing the native consensus verifier.
//! This module supplies no LMS signing key, leaf reservation or rollback defense.
use crate::Rejected;
#[path = "fee_binding.rs"]
mod binding;
pub use binding::verify_seed_and_wipe;
#[path = "fee_tree.rs"]
mod tree;
pub use tree::FeeTree;
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

#[cfg(test)]
mod signing_primitive_tests {
    use super::*;
    unsafe extern "C" {
        fn tos_wallet_lms_fee_sign_reserved(
            seed: *const u8,
            seed_size: usize,
            leaf: u32,
            digest: *const u8,
            digest_size: usize,
            path: *const u8,
            path_size: usize,
            key: *const u8,
            key_size: usize,
            output: *mut u8,
            output_size: usize,
        ) -> i32;
    }
    #[test]
    fn internal_fee_primitive_signs_and_clears_rejected_outputs() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/lms-fee-signature.json")).unwrap();
        let key = hex::decode(v["public_key"].as_str().unwrap()).unwrap();
        let original = hex::decode(v["signature"].as_str().unwrap()).unwrap();
        let path = &original[2192..];
        let digest: [u8; 32] =
            hex::decode(v["digest"].as_str().unwrap()).unwrap().try_into().unwrap();
        let leaf = u32::try_from(v["leaf"].as_u64().unwrap()).unwrap();
        // Public fixture material only: never use this key for funds.
        let mut seed = [0x44; 48];
        seed[32..].fill(0x55);
        let sign = |seed: &[u8], leaf, key: &[u8], path: &[u8], digest: &[u8]| {
            let mut output = vec![0xa5; 2832];
            let result = unsafe {
                tos_wallet_lms_fee_sign_reserved(
                    seed.as_ptr(),
                    seed.len(),
                    leaf,
                    digest.as_ptr(),
                    digest.len(),
                    path.as_ptr(),
                    path.len(),
                    key.as_ptr(),
                    key.len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            };
            (result, output)
        };
        let (status, signature) = sign(&seed, leaf, &key, path, &digest);
        assert_eq!(status, 1);
        verify_reserved_signature(&key, leaf, &digest, &signature).unwrap();
        assert_eq!(sign(&seed, leaf, &key, path, &digest).1, signature);
        for case in 0..8 {
            let mut bad_seed = seed.to_vec();
            let mut bad_key = key.clone();
            let mut bad_path = path.to_vec();
            let mut bad_digest = digest.to_vec();
            let mut q = leaf;
            match case {
                0 => bad_seed[0] ^= 1,
                1 => bad_seed[32] ^= 1,
                2 => bad_key[28] ^= 1,
                3 => bad_path[0] ^= 1,
                4 => q = 1 << 20,
                5 => {
                    bad_seed.pop();
                }
                6 => {
                    bad_path.pop();
                }
                _ => {
                    bad_digest.pop();
                }
            }
            let (status, output) = sign(&bad_seed, q, &bad_key, &bad_path, &bad_digest);
            assert_eq!(status, 0, "fee primitive accepted bad input {case}");
            assert!(output.iter().all(|b| *b == 0), "fee primitive leaked rejected output {case}");
        }
    }
}
