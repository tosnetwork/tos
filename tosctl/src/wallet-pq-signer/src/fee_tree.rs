// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Fixed H20/W4 public tree reconstruction. No message signing or journal state.
use crate::{Rejected, WipeSeed};
#[path = "fee_tree_cache.rs"]
mod cache;

const LEAVES: usize = 1 << 20;
const TREE_BYTES: usize = LEAVES * 2 * 32;
unsafe extern "C" {
    fn tos_wallet_lms_fee_generate_tree(
        seed: *const u8,
        seed_size: usize,
        output: *mut u8,
        output_size: usize,
    ) -> i32;
}

/// Public nodes only. Generating a tree does not restore signing permission,
/// prove leaf uniqueness, or replace the journal's next-slot restore barrier.
pub struct FeeTree {
    nodes: Vec<u8>,
    key: [u8; 60],
}

impl FeeTree {
    /// Rebuild the full fixed-profile tree from SEED[32] || I[16], clearing the
    /// caller's seed on every return. This synchronous, CPU-heavy operation
    /// requires 64 MiB for public nodes; invoke on a worker, not a UI/event loop.
    /// The result must match independently authenticated enrollment on restore.
    pub fn generate_and_wipe(seed: &mut [u8]) -> Result<Self, Rejected> {
        let seed = WipeSeed(seed);
        if seed.0.len() != 48 {
            return Err(Rejected);
        }
        let mut nodes = Vec::new();
        nodes.try_reserve_exact(TREE_BYTES).map_err(|_| Rejected)?;
        nodes.resize(TREE_BYTES, 0);
        // SAFETY: nonoverlapping, live buffers of exact checked widths. The
        // synchronous backend writes public nodes and retains no seed pointer.
        let status = unsafe {
            tos_wallet_lms_fee_generate_tree(
                seed.0.as_ptr(),
                seed.0.len(),
                nodes.as_mut_ptr(),
                nodes.len(),
            )
        };
        if status != 1 {
            return Err(Rejected);
        }
        let mut key = [0; 60];
        key[3] = 1;
        key[7] = 8;
        key[11] = 3;
        key[12..28].copy_from_slice(&seed.0[32..]);
        key[28..].copy_from_slice(&nodes[32..64]);
        Ok(Self { nodes, key })
    }

    pub fn public_key(&self) -> &[u8; 60] {
        &self.key
    }

    /// Return the twenty public siblings, from leaf level toward the root.
    /// This does not reserve the requested leaf or authorize any signature.
    pub fn authentication_path(&self, leaf: u32) -> Result<[u8; 640], Rejected> {
        if leaf >= LEAVES as u32 {
            return Err(Rejected);
        }
        let mut index = LEAVES | leaf as usize;
        let mut path = [0; 640];
        for node in path.chunks_exact_mut(32) {
            let offset = (index ^ 1).checked_mul(32).ok_or(Rejected)?;
            let end = offset.checked_add(32).ok_or(Rejected)?;
            node.copy_from_slice(self.nodes.get(offset..end).ok_or(Rejected)?);
            index >>= 1;
        }
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fee_tree_path_bounds_order_and_invalid_seed_cleanup() {
        let mut seed = [0x44; 47];
        assert!(FeeTree::generate_and_wipe(&mut seed).is_err());
        assert_eq!(seed, [0; 47], "fee tree rejected seed not cleared");
        let mut nodes = vec![0; TREE_BYTES];
        for (index, bytes) in nodes.chunks_exact_mut(32).enumerate() {
            bytes[..4].copy_from_slice(&(index as u32).to_be_bytes());
        }
        let tree = FeeTree { nodes, key: [0; 60] };
        for leaf in [0, 1, 12, (1 << 19) + 1, (1 << 20) - 1] {
            let path = tree.authentication_path(leaf).unwrap();
            for (level, node) in path.chunks_exact(32).enumerate() {
                let expected = (((1 << 20) + leaf) >> level) ^ 1;
                assert_eq!(&node[..4], &expected.to_be_bytes(), "fee path sibling/order mismatch");
            }
        }
        assert!(tree.authentication_path(1 << 20).is_err(), "fee path accepted exhausted leaf");
        assert!(tree.authentication_path(u32::MAX).is_err());
    }

    #[test]
    #[ignore = "full H20 reconstruction; explicitly run in fee tree validation"]
    fn fee_tree_matches_independent_enrollment() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/lms-fee-signature.json")).unwrap();
        let key = hex::decode(v["public_key"].as_str().unwrap()).unwrap();
        let signature = hex::decode(v["signature"].as_str().unwrap()).unwrap();
        fn seed() -> [u8; 48] {
            let mut s = [0x44; 48];
            s[32..].fill(0x55);
            s
        }
        let mut input = seed();
        let tree = FeeTree::generate_and_wipe(&mut input).unwrap();
        assert_eq!(input, [0; 48], "fee tree retained seed after generation");
        assert_eq!(tree.public_key().as_slice(), key, "fee tree independent root mismatch");
        assert_eq!(
            tree.authentication_path(12).unwrap().as_slice(),
            &signature[2192..],
            "fee tree independent path mismatch"
        );
        let mut encoded = Vec::new();
        tree.write_cache(&mut encoded).unwrap();
        let restored = FeeTree::read_cache(encoded.as_slice(), tree.public_key()).unwrap();
        assert_eq!(restored.public_key(), tree.public_key());
        assert_eq!(
            restored.authentication_path(12).unwrap(),
            tree.authentication_path(12).unwrap()
        );
        for q in [0, 1, 12, (1 << 19) + 1, (1 << 20) - 1] {
            crate::fee::verify_seed_and_wipe(
                &mut seed(),
                tree.public_key(),
                q,
                &tree.authentication_path(q).unwrap(),
            )
            .unwrap();
        }
    }
}
