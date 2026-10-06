// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Owned in-process wallet signer, with fixed PQ roles and contexts.
//! No persistence, seed export, chain proof validation or action approval is
//! provided here. Obtain the expected public key from authenticated enrollment.
use openssl_sys as _; // Carry the native backend's OpenSSL linkage.
use std::{ffi::c_void, marker::PhantomData, ptr::NonNull, rc::Rc};
use zeroize::Zeroize;

struct WipeSeed<'a>(&'a mut [u8]);
impl Drop for WipeSeed<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Role {
    Primary = 1,
    Rescue = 2,
}

impl Role {
    pub fn public_key_bytes(self) -> usize {
        match self {
            Self::Primary => 1312,
            Self::Rescue => 32,
        }
    }
    pub fn signature_bytes(self) -> usize {
        match self {
            Self::Primary => 2420,
            Self::Rescue => 7856,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Purpose {
    Auth = 1,
    Pop = 2,
    Preparation = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rejected;
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PQ wallet signer rejected the operation")
    }
}
impl std::error::Error for Rejected {}

/// Generate a public 256-bit POP challenge with the platform-seeded CSPRNG.
/// Failure (including an all-zero result) returns no usable challenge. Persist
/// the resulting request for retries; generate a new challenge for a new proof.
pub fn fresh_pop_challenge() -> Result<[u8; 32], Rejected> {
    challenge_from_rng(|output| {
        // SAFETY: output is a live writable 32-byte buffer; its length fits i32.
        unsafe { openssl_sys::RAND_bytes(output.as_mut_ptr(), 32) }
    })
}

fn challenge_from_rng(fill: impl FnOnce(&mut [u8; 32]) -> i32) -> Result<[u8; 32], Rejected> {
    let mut challenge = [0; 32];
    let status = fill(&mut challenge);
    if status != 1 || challenge == [0; 32] {
        return Err(Rejected);
    }
    Ok(challenge)
}

unsafe extern "C" {
    fn tos_wallet_pq_generate(role: i32) -> *mut c_void;
    fn tos_wallet_pq_import(role: i32, seed: *const u8, size: usize) -> *mut c_void;
    fn tos_wallet_pq_destroy(signer: *mut c_void);
    fn tos_wallet_pq_public_key(signer: *const c_void, output: *mut u8, size: usize) -> i32;
    fn tos_wallet_pq_sign(
        signer: *const c_void,
        role: i32,
        purpose: i32,
        key: *const u8,
        key_size: usize,
        digest: *const u8,
        digest_size: usize,
        output: *mut u8,
        output_size: usize,
    ) -> i32;
}

/// Single-owner, single-thread signer. Intentionally not Clone, Debug, Send or
/// Sync. The handle is destroyed exactly once; no native pointer is exposed.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<wallet_pq_signer::Signer>();
/// ```
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<wallet_pq_signer::Signer>();
/// ```
pub struct Signer {
    handle: NonNull<c_void>,
    role: Role,
    public_key: Vec<u8>,
    _single_thread: PhantomData<Rc<()>>,
}

impl Drop for Signer {
    fn drop(&mut self) {
        // SAFETY: only constructors install an owned non-null handle; no clone
        // or raw handle access exists, and operations borrow this object.
        unsafe { tos_wallet_pq_destroy(self.handle.as_ptr()) };
    }
}

impl Signer {
    pub fn generate(role: Role) -> Result<Self, Rejected> {
        // SAFETY: closed role enum; function returns a newly owned handle or null.
        Self::take(unsafe { tos_wallet_pq_generate(role as i32) }, role)
    }

    /// Wipe the supplied buffer on success, rejection and unwinding. Other
    /// copies/backups of the seed remain the caller's responsibility.
    pub fn import_and_wipe(role: Role, seed: &mut [u8]) -> Result<Self, Rejected> {
        let seed = WipeSeed(seed);
        // SAFETY: borrowed slice stays live for this synchronous call; native
        // import copies its material and never retains the pointer.
        let handle = unsafe { tos_wallet_pq_import(role as i32, seed.0.as_ptr(), seed.0.len()) };
        Self::take(handle, role)
    }

    fn take(handle: *mut c_void, role: Role) -> Result<Self, Rejected> {
        let mut signer = Self {
            handle: NonNull::new(handle).ok_or(Rejected)?,
            role,
            public_key: Vec::new(),
            _single_thread: PhantomData,
        };
        signer.public_key.resize(role.public_key_bytes(), 0);
        // SAFETY: handle is live and uniquely owned, and output is a writable
        // buffer of the exact role-specific size. Drop cleans up on failure.
        let status = unsafe {
            tos_wallet_pq_public_key(
                signer.handle.as_ptr(),
                signer.public_key.as_mut_ptr(),
                signer.public_key.len(),
            )
        };
        if status != 1 {
            return Err(Rejected);
        }
        Ok(signer)
    }

    pub fn role(&self) -> Role {
        self.role
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The expected role/key must be supplied independently from the wallet
    /// enrollment. This check is not proof of enrollment or owner approval.
    pub fn sign_bound(
        &mut self,
        expected_role: Role,
        expected_key: &[u8],
        purpose: Purpose,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, Rejected> {
        let mut output = vec![0; expected_role.signature_bytes()];
        // SAFETY: all slices remain live for the synchronous call; the output
        // has its stated capacity; exclusive borrow prevents racing destruction.
        let status = unsafe {
            tos_wallet_pq_sign(
                self.handle.as_ptr(),
                expected_role as i32,
                purpose as i32,
                expected_key.as_ptr(),
                expected_key.len(),
                digest.as_ptr(),
                digest.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        if status != 1 {
            return Err(Rejected);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::{SerDes, Verifier};

    #[test]
    fn challenge_rng_failures_are_rejected() {
        for status in [-1, 0] {
            assert_eq!(
                challenge_from_rng(|out| {
                    *out = [7; 32];
                    status
                }),
                Err(Rejected)
            );
        }
        assert_eq!(challenge_from_rng(|_| 1), Err(Rejected));
        assert_eq!(
            challenge_from_rng(|out| {
                *out = [7; 32];
                1
            }),
            Ok([7; 32])
        );
        let first = fresh_pop_challenge().expect("CSPRNG");
        let second = fresh_pop_challenge().expect("CSPRNG");
        assert_ne!(first, second);
        assert_ne!(first, [0; 32]);
    }

    #[test]
    fn import_wipes_on_success_and_failure() {
        for role in [Role::Primary, Role::Rescue] {
            let mut seed = vec![0x11; if role == Role::Primary { 32 } else { 48 }];
            let signer = Signer::import_and_wipe(role, &mut seed).expect("public seed");
            assert!(seed.iter().all(|byte| *byte == 0));
            assert_eq!(signer.public_key().len(), role.public_key_bytes());
            let mut wrong = vec![0x22; 31];
            assert!(Signer::import_and_wipe(role, &mut wrong).is_err());
            assert!(wrong.iter().all(|byte| *byte == 0));
        }
        let mut seed = [0x77; 48];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _wipe = WipeSeed(&mut seed);
            panic!("test unwind");
        }));
        assert!(result.is_err());
        assert_eq!(seed, [0; 48]);
    }

    #[test]
    fn bound_signatures_and_independent_primary_verification() {
        for role in [Role::Primary, Role::Rescue] {
            let mut signer = Signer::generate(role).expect("generate");
            let key = signer.public_key().to_vec();
            let mut wrong = key.clone();
            wrong[0] ^= 1;
            let other = if role == Role::Primary { Role::Rescue } else { Role::Primary };
            let digest = [0x33; 32];
            assert!(signer.sign_bound(role, &wrong, Purpose::Auth, &digest).is_err());
            assert!(signer.sign_bound(other, &key, Purpose::Auth, &digest).is_err());
            for purpose in [Purpose::Auth, Purpose::Pop, Purpose::Preparation] {
                let result = signer.sign_bound(role, &key, purpose, &digest);
                if role == Role::Primary && purpose == Purpose::Preparation {
                    assert!(result.is_err());
                    continue;
                }
                let signature = result.expect("allowed signature");
                assert_eq!(signature.len(), role.signature_bytes());
                if role == Role::Primary {
                    let pk = fips204::ml_dsa_44::PublicKey::try_from_bytes(
                        key.clone().try_into().expect("public key size"),
                    )
                    .expect("public key");
                    let bytes = signature.try_into().expect("signature size");
                    let context: &[u8] = if purpose == Purpose::Auth {
                        b"TOS-AUTH-V2-ML-DSA-44-v1"
                    } else {
                        b"TOS-RESCUE-POP-v1"
                    };
                    assert!(pk.verify(&digest, &bytes, context));
                    assert!(!pk.verify(&digest, &bytes, b"wrong-context"));
                }
            }
        }
    }
}
