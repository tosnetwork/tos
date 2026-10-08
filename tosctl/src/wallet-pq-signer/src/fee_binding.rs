// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Read-only seed enrollment check; no message signing or leaf consumption.
use crate::{Rejected, WipeSeed};

unsafe extern "C" {
    fn tos_wallet_lms_fee_bind_seed(
        seed: *const u8,
        seed_size: usize,
        leaf: u32,
        path: *const u8,
        path_size: usize,
        public_key: *const u8,
        key_size: usize,
    ) -> i32;
}

/// Bind SEED[32] || I[16] to independently authenticated enrollment using one
/// public authentication path. Derives the full public LMOTS chains, never an
/// OTS signature. Wipes the borrowed seed on every return. The path need not be
/// for an unused leaf: this read-only operation establishes neither freshness,
/// exclusive custody nor permission to sign. It cannot restore journal state.
pub fn verify_seed_and_wipe(
    seed: &mut [u8],
    public_key: &[u8],
    leaf: u32,
    authentication_path: &[u8],
) -> Result<(), Rejected> {
    let seed = WipeSeed(seed);
    // SAFETY: live slices for a synchronous call; native code checks all widths
    // and the fixed profile before indexing. It borrows but never retains seed.
    let valid = unsafe {
        tos_wallet_lms_fee_bind_seed(
            seed.0.as_ptr(),
            seed.0.len(),
            leaf,
            authentication_path.as_ptr(),
            authentication_path.len(),
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
    fn fee_seed_binding_checks_root_path_profile_and_wipes() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/lms-fee-signature.json")).unwrap();
        let key = hex::decode(fixture["public_key"].as_str().unwrap()).unwrap();
        let signature = hex::decode(fixture["signature"].as_str().unwrap()).unwrap();
        let path = &signature[2192..];
        fn seed() -> Vec<u8> {
            let mut bytes = vec![0x44; 48];
            bytes[32..].fill(0x55);
            bytes
        }
        let mut secret = seed();
        verify_seed_and_wipe(&mut secret, &key, 12, path).unwrap();
        assert!(secret.iter().all(|b| *b == 0), "fee binding retained valid seed");
        for case in 0..11 {
            let mut secret = seed();
            let mut key = key.clone();
            let mut path = path.to_vec();
            let mut leaf = 12;
            match case {
                0 => secret[0] ^= 1,
                1 => secret[32] ^= 1,
                2 => key[28] ^= 1,
                3 => path[0] ^= 1,
                4 => leaf = 13,
                5 => leaf = 1 << 20,
                6 => key[7] = 5,
                7 => key[11] = 4,
                8 => {
                    secret.pop();
                }
                9 => {
                    path.pop();
                }
                _ => {
                    key.pop();
                }
            }
            assert!(
                verify_seed_and_wipe(&mut secret, &key, leaf, &path).is_err(),
                "fee binding accepted invalid input {case}"
            );
            assert!(secret.iter().all(|b| *b == 0), "fee binding retained rejected seed {case}");
        }
    }
}
