// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// PUBLIC TEST SEEDS ONLY. Called only from the journal's post-reservation callback.
use std::io::{Read, Seek, SeekFrom};
use wallet_pq_signer as _;
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

pub(super) fn sign(
    input: &super::Input,
    leaf: u32,
    digest: &[u8; 32],
    key: &[u8],
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(leaf < (1 << 20), "public fixture leaf exhausted");
    let mut tree = std::fs::File::open(&input.tree)?;
    anyhow::ensure!(tree.metadata()?.len() == 64 * 1024 * 1024, "public fixture tree size");
    let mut index = (1u32 << 20) | leaf;
    let mut path = [0; 640];
    for node in path.chunks_exact_mut(32) {
        let offset = u64::from(index ^ 1)
            .checked_mul(32)
            .ok_or_else(|| anyhow::anyhow!("fixture node offset overflow"))?;
        tree.seek(SeekFrom::Start(offset))?;
        tree.read_exact(node)?;
        index >>= 1;
    }
    let mut seed = zeroize::Zeroizing::new([if input.successor { 0x77 } else { 0x44 }; 48]);
    seed[32..].fill(if input.successor { 0x88 } else { 0x55 });
    let mut output = vec![0; 2832];
    // SAFETY: synchronous native call with live nonoverlapping bounded buffers;
    // the journal has durably reserved this leaf before invoking this helper.
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
    seed.zeroize();
    anyhow::ensure!(result == 1, "native public fixture signer rejected");
    Ok(output)
}
