// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Versioned public node cache; the enrolled root authenticates every node.
use super::{FeeTree, LEAVES, TREE_BYTES};
use crate::Rejected;
use std::io::{Read, Write};

const MAGIC: &[u8; 8] = b"TOSFT001";

impl FeeTree {
    /// Publish to a new file in a caller-controlled directory. Never overwrite
    /// an existing destination. Sync contents, validate readback on the same
    /// handle, then sync the parent directory before returning. A failed call
    /// may leave a partial file; this is not atomic directory publication.
    #[cfg(unix)]
    pub fn save_cache_new(&self, path: &std::path::Path) -> Result<(), Rejected> {
        use std::{
            io::{Seek, SeekFrom},
            os::unix::fs::OpenOptionsExt,
        };
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| Rejected)?;
        self.write_cache(&mut file)?;
        file.sync_all().map_err(|_| Rejected)?;
        file.seek(SeekFrom::Start(0)).map_err(|_| Rejected)?;
        drop(Self::read_cache(&mut file, &self.key)?);
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::File::open(parent).and_then(|dir| dir.sync_all()).map_err(|_| Rejected)?;
        Ok(())
    }

    /// Encode public data only. The caller owns filesystem publication and
    /// durability; a failed write may leave partial output, which must not be
    /// treated as a complete cache. No seed, reservation or signer state is saved.
    pub fn write_cache(&self, mut output: impl Write) -> Result<(), Rejected> {
        output.write_all(MAGIC).map_err(|_| Rejected)?;
        output.write_all(&self.key).map_err(|_| Rejected)?;
        output.write_all(&self.nodes).map_err(|_| Rejected)?;
        output.flush().map_err(|_| Rejected)
    }

    /// Decode an exact-size cache and authenticate all public nodes against a
    /// separately trusted key. Reject trailing bytes, unsupported profiles,
    /// altered root/parents/leaves and noncanonical unused node zero. Memory is
    /// bounded to one 64 MiB node buffer. A matching cache does not authenticate
    /// a supplied seed or restore permission to use any signing leaf.
    pub fn read_cache(mut input: impl Read, expected_key: &[u8; 60]) -> Result<Self, Rejected> {
        let mut magic = [0; 8];
        input.read_exact(&mut magic).map_err(|_| Rejected)?;
        if &magic != MAGIC {
            return Err(Rejected);
        }
        let mut key = [0; 60];
        input.read_exact(&mut key).map_err(|_| Rejected)?;
        if &key != expected_key {
            return Err(Rejected);
        }
        if key[..12] != [0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 3] {
            return Err(Rejected);
        }
        let mut nodes = Vec::new();
        nodes.try_reserve_exact(TREE_BYTES).map_err(|_| Rejected)?;
        nodes.resize(TREE_BYTES, 0);
        input.read_exact(&mut nodes).map_err(|_| Rejected)?;
        let mut extra = [0; 1];
        if input.read(&mut extra).map_err(|_| Rejected)? != 0 {
            return Err(Rejected);
        }
        if nodes[..32] != [0; 32] || nodes[32..64] != key[28..] {
            return Err(Rejected);
        }
        let mut preimage = [0; 86];
        preimage[..16].copy_from_slice(&key[12..28]);
        preimage[20..22].copy_from_slice(&[0x83, 0x83]);
        for parent in 1..LEAVES {
            let index = u32::try_from(parent).map_err(|_| Rejected)?;
            preimage[16..20].copy_from_slice(&index.to_be_bytes());
            let start = parent.checked_mul(64).ok_or(Rejected)?;
            let end = start.checked_add(64).ok_or(Rejected)?;
            preimage[22..].copy_from_slice(nodes.get(start..end).ok_or(Rejected)?);
            let digest = openssl::sha::sha256(&preimage);
            let start = parent.checked_mul(32).ok_or(Rejected)?;
            let end = start.checked_add(32).ok_or(Rejected)?;
            if nodes.get(start..end).ok_or(Rejected)? != digest {
                return Err(Rejected);
            }
        }
        Ok(Self { nodes, key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Structural cache fixture only: public zero leaf hashes, not an LMOTS key.
    fn structural_tree() -> FeeTree {
        let mut tree = FeeTree { nodes: vec![0; TREE_BYTES], key: [0; 60] };
        tree.key[..12].copy_from_slice(&[0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 3]);
        tree.key[12..28].fill(0x55);
        for index in (1..LEAVES).rev() {
            let mut hash = openssl::sha::Sha256::new();
            hash.update(&tree.key[12..28]);
            hash.update(&(index as u32).to_be_bytes());
            hash.update(&[0x83, 0x83]);
            hash.update(&tree.nodes[index * 64..index * 64 + 64]);
            tree.nodes[index * 32..index * 32 + 32].copy_from_slice(&hash.finish());
        }
        tree.key[28..].copy_from_slice(&tree.nodes[32..64]);
        tree
    }

    #[test]
    fn fee_tree_cache_authenticates_all_nodes_and_exact_framing() {
        let tree = structural_tree();
        let mut cache = Vec::new();
        tree.write_cache(&mut cache).unwrap();
        assert_eq!(cache.len(), TREE_BYTES + 68);
        let loaded = FeeTree::read_cache(cache.as_slice(), tree.public_key()).unwrap();
        assert_eq!(loaded.public_key(), tree.public_key());
        assert_eq!(loaded.authentication_path(12).unwrap(), tree.authentication_path(12).unwrap());
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("tree.cache");
            tree.save_cache_new(&file).unwrap();
            assert!(tree.save_cache_new(&file).is_err(), "fee cache overwrote destination");
            let reopened =
                FeeTree::read_cache(std::fs::File::open(&file).unwrap(), tree.public_key())
                    .unwrap();
            assert_eq!(
                reopened.authentication_path(12).unwrap(),
                tree.authentication_path(12).unwrap()
            );
            assert_eq!(std::fs::read(file).unwrap(), cache);
        }
        let mut wrong = *tree.public_key();
        wrong[28] ^= 1;
        assert!(
            FeeTree::read_cache(cache.as_slice(), &wrong).is_err(),
            "fee cache ignored enrollment"
        );
        for (name, offset) in [
            ("magic", 0),
            ("unused", 68),
            ("root", 100),
            ("parent", 68 + 32 * 3),
            ("leaf", 68 + LEAVES * 32),
        ] {
            cache[offset] ^= 1;
            assert!(
                FeeTree::read_cache(cache.as_slice(), tree.public_key()).is_err(),
                "fee cache accepted changed {name}"
            );
            cache[offset] ^= 1;
        }
        // A cache header and claimed enrollment cannot substitute a different
        // root while retaining a structurally valid tree for the original root.
        cache[8 + 28] ^= 1;
        assert!(
            FeeTree::read_cache(cache.as_slice(), &wrong).is_err(),
            "fee cache ignored tree root"
        );
        cache[8 + 28] ^= 1;
        let mut other_profile = *tree.public_key();
        other_profile[7] = 5;
        cache[8 + 7] = 5;
        assert!(
            FeeTree::read_cache(cache.as_slice(), &other_profile).is_err(),
            "fee cache accepted wrong profile"
        );
        cache[8 + 7] = 8;
        assert!(FeeTree::read_cache(&cache[..cache.len() - 1], tree.public_key()).is_err());
        cache.push(0);
        assert!(
            FeeTree::read_cache(cache.as_slice(), tree.public_key()).is_err(),
            "fee cache accepted trailing data"
        );
    }
}
