// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Proof-bound fee signing through durable reservation and fixed native primitives.
//! Seed custody, authenticated path acquisition and old-writer revocation remain
//! caller responsibilities. No unreserved native signing entry is public here.
use super::{FeeJournal, SignedFeeMessage};
use crate::{wallet_v5r2_fee::FeePayload, wallet_v5r2_state::ProvenFeeVault};
use zeroize::Zeroize;

unsafe extern "C" {
    fn tos_wallet_lms_fee_sign_reserved(
        seed: *const u8,
        seed_size: usize,
        leaf: u32,
        digest: *const u8,
        digest_size: usize,
        path: *const u8,
        path_size: usize,
        public_key: *const u8,
        key_size: usize,
        output: *mut u8,
        output_size: usize,
    ) -> i32;
}
struct Wipe<'a>(&'a mut [u8]);
impl Drop for Wipe<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl FeeJournal {
    /// Sign an approved fee payload with borrowed SEED[32] || I[16]. Input is
    /// wiped on every return, and immediately after the native call on that path.
    /// The existing proof, route, freshness, deadline and restore gates precede
    /// durable reservation; only its signer callback can invoke the primitive.
    /// Native failure burns the reserved leaf. Retry by reading verified cached
    /// bytes, never by signing an already reserved leaf again. This is not Vault
    /// loading or a guarantee against cloned journals/devices.
    #[cfg(feature = "native-wallet-signer")]
    pub fn sign_proven_fee_with_seed_and_wipe(
        &mut self,
        vault: &ProvenFeeVault,
        now: u32,
        valid_until: u32,
        value: u128,
        payload: FeePayload,
        seed: &mut [u8],
        authentication_path: &[u8; 640],
    ) -> anyhow::Result<SignedFeeMessage> {
        let seed = Wipe(seed);
        anyhow::ensure!(seed.0.len() == 48, "fee seed must be SEED32 plus I16");
        let key = vault.fee_public_key();
        anyhow::ensure!(&seed.0[32..] == &key[12..28], "fee seed identifier mismatch");
        self.sign_proven_fee(
            vault,
            now,
            valid_until,
            value,
            payload,
            |leaf, digest| {
                let mut signature = vec![0u8; 2832];
                // SAFETY: live nonoverlapping buffers of bounded sizes, retained
                // for the synchronous native call. The seed guard owns cleanup.
                let status = unsafe {
                    tos_wallet_lms_fee_sign_reserved(
                        seed.0.as_ptr(),
                        seed.0.len(),
                        leaf,
                        digest.as_ptr(),
                        digest.len(),
                        authentication_path.as_ptr(),
                        authentication_path.len(),
                        key.as_ptr(),
                        key.len(),
                        signature.as_mut_ptr(),
                        signature.len(),
                    )
                };
                seed.0.zeroize();
                anyhow::ensure!(status == 1, "native fee signing rejected");
                Ok(signature)
            },
            |public_key, leaf, digest, signature| {
                Ok(wallet_pq_signer::fee::verify_reserved_signature(
                    public_key, leaf, digest, signature,
                )
                .is_ok())
            },
        )
    }
}
