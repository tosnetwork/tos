/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! AIPoW epoch score-root merkle tree (methodology v0).
//!
//! This is an independent implementation of the tree the AIPoW scorer
//! commits and the score-commitment contract's challenge window guards.
//! It exists here so the on-chain distributor (and its CLI) can build the
//! inclusion proof a beneficiary presents when claiming, and verify it the
//! same way the contract will. Written from the normative methodology, not
//! copied from the scorer's Rust -- byte-for-byte agreement between the two
//! is the cross-implementation check, not an accident of shared code.
//!
//! Construction (methodology v0):
//! - entries are sorted by identity bytes; duplicate identities are an
//!   error, never silently merged;
//! - leaf: `sha256(0x00 || identity(32) || score as 16-byte big-endian)`;
//! - node: `sha256(0x01 || left(32) || right(32))`; an odd node at any
//!   level is promoted unchanged;
//! - the empty-epoch root is `sha256(0x02 || "aipow-empty-v0")`.

use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;
const EMPTY_PREFIX: u8 = 0x02;
const EMPTY_DOMAIN: &[u8] = b"aipow-empty-v0";

/// One scored identity: a 32-byte account id and its final u128 score.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScoreEntry {
    pub identity: [u8; 32],
    pub score: u128,
}

/// One step of an inclusion proof: a sibling hash and whether the sibling
/// sits on the left of the node being combined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    pub sibling_is_left: bool,
}

/// Errors building or verifying a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    DuplicateIdentity,
    IdentityNotFound,
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleError::DuplicateIdentity => f.write_str("duplicate identity in score entries"),
            MerkleError::IdentityNotFound => f.write_str("identity not present in the entry set"),
        }
    }
}

impl std::error::Error for MerkleError {}

/// The leaf hash of one entry.
pub fn leaf_hash(entry: &ScoreEntry) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(entry.identity);
    hasher.update(entry.score.to_be_bytes());
    hasher.finalize().into()
}

/// The parent hash of two child hashes.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The root of the empty epoch.
pub fn empty_root() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([EMPTY_PREFIX]);
    hasher.update(EMPTY_DOMAIN);
    hasher.finalize().into()
}

/// Sort entries by identity and reject duplicates.
fn sorted_unique(entries: &[ScoreEntry]) -> Result<Vec<ScoreEntry>, MerkleError> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.identity.cmp(&b.identity));
    for pair in sorted.windows(2) {
        if let [a, b] = pair {
            if a.identity == b.identity {
                return Err(MerkleError::DuplicateIdentity);
            }
        }
    }
    Ok(sorted)
}

/// Compute the epoch score root. Order-independent (entries are sorted);
/// duplicate identities are rejected.
pub fn score_root(entries: &[ScoreEntry]) -> Result<[u8; 32], MerkleError> {
    let sorted = sorted_unique(entries)?;
    if sorted.is_empty() {
        return Ok(empty_root());
    }
    let mut level: Vec<[u8; 32]> = sorted.iter().map(leaf_hash).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut chunks = level.chunks_exact(2);
        for pair in chunks.by_ref() {
            if let [left, right] = pair {
                next.push(node_hash(left, right));
            }
        }
        if let [odd] = chunks.remainder() {
            next.push(*odd);
        }
        level = next;
    }
    level.first().copied().ok_or(MerkleError::IdentityNotFound)
}

/// Build the inclusion proof for `identity`: the sibling hash and side at
/// each level from the leaf up to the root. An identity promoted as an odd
/// node at some level contributes no step for that level.
pub fn inclusion_proof(
    entries: &[ScoreEntry],
    identity: &[u8; 32],
) -> Result<Vec<ProofStep>, MerkleError> {
    let sorted = sorted_unique(entries)?;
    let mut index = sorted
        .iter()
        .position(|entry| &entry.identity == identity)
        .ok_or(MerkleError::IdentityNotFound)?;
    let mut level: Vec<[u8; 32]> = sorted.iter().map(leaf_hash).collect();
    let mut proof = Vec::new();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut chunks = level.chunks_exact(2);
        let mut position = 0usize;
        for pair in chunks.by_ref() {
            if let [left, right] = pair {
                if position == index {
                    proof.push(ProofStep { sibling: *right, sibling_is_left: false });
                } else if position + 1 == index {
                    proof.push(ProofStep { sibling: *left, sibling_is_left: true });
                }
                next.push(node_hash(left, right));
            }
            position += 2;
        }
        if let [odd] = chunks.remainder() {
            // The odd node is promoted with no sibling; if it is our node,
            // this level contributes no step.
            next.push(*odd);
        }
        index /= 2;
        level = next;
    }
    Ok(proof)
}

/// Recompute the root from a leaf and its inclusion proof. This is the
/// exact sequence the on-chain distributor performs, so the SDK and the
/// contract accept identical proofs.
pub fn root_from_proof(entry: &ScoreEntry, proof: &[ProofStep]) -> [u8; 32] {
    let mut current = leaf_hash(entry);
    for step in proof {
        current = if step.sibling_is_left {
            node_hash(&step.sibling, &current)
        } else {
            node_hash(&current, &step.sibling)
        };
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u8, score: u128) -> ScoreEntry {
        ScoreEntry { identity: [id; 32], score }
    }

    #[test]
    fn empty_root_is_stable_and_distinct() {
        assert_eq!(empty_root(), empty_root());
        assert_ne!(empty_root(), score_root(&[entry(1, 10)]).unwrap());
    }

    #[test]
    fn root_is_order_independent_and_rejects_duplicates() {
        let forward = score_root(&[entry(1, 10), entry(2, 20), entry(3, 30)]).unwrap();
        let shuffled = score_root(&[entry(3, 30), entry(1, 10), entry(2, 20)]).unwrap();
        assert_eq!(forward, shuffled);
        assert_eq!(score_root(&[entry(1, 10), entry(1, 20)]), Err(MerkleError::DuplicateIdentity));
    }

    #[test]
    fn proofs_reconstruct_the_root_for_every_member_at_every_width() {
        for count in 1u8..=9 {
            let entries: Vec<ScoreEntry> =
                (1..=count).map(|i| entry(i, u128::from(i) * 1000)).collect();
            let root = score_root(&entries).unwrap();
            for e in &entries {
                let proof = inclusion_proof(&entries, &e.identity).unwrap();
                assert_eq!(
                    root_from_proof(e, &proof),
                    root,
                    "proof for id {} at width {} did not reconstruct the root",
                    e.identity[0],
                    count
                );
            }
        }
    }

    #[test]
    fn a_wrong_score_or_sibling_breaks_the_proof() {
        let entries = [entry(1, 10), entry(2, 20), entry(3, 30)];
        let root = score_root(&entries).unwrap();
        let proof = inclusion_proof(&entries, &[2; 32]).unwrap();
        assert_eq!(root_from_proof(&entry(2, 20), &proof), root);
        // Wrong score: the claimed leaf differs, so the recomputed root
        // no longer matches.
        assert_ne!(root_from_proof(&entry(2, 21), &proof), root);
        // Tampered sibling.
        let mut tampered = proof.clone();
        tampered[0].sibling[0] ^= 0xFF;
        assert_ne!(root_from_proof(&entry(2, 20), &tampered), root);
    }

    #[test]
    fn missing_identity_is_an_error() {
        let entries = [entry(1, 10), entry(2, 20)];
        assert_eq!(inclusion_proof(&entries, &[9; 32]), Err(MerkleError::IdentityNotFound));
    }

    // Frozen vectors: these exact digests must match what any conforming
    // implementation produces for the same inputs. Cross-checked at commit
    // time against two independent implementations -- a standalone Python
    // reference and the aipow-scorer commitment crate -- which produced
    // byte-identical roots for empty, single, and three-entry inputs. A
    // divergence here, or in any other implementation, is a real
    // cross-implementation disagreement to investigate, never a value to
    // edit to match.
    #[test]
    fn frozen_v0_vectors() {
        // A single-entry root is exactly that entry's leaf hash.
        let single = score_root(&[entry(0xAB, 1_000_000)]).unwrap();
        assert_eq!(single, leaf_hash(&entry(0xAB, 1_000_000)));

        assert_eq!(
            hex::encode(empty_root()),
            "a16bdcc91c669673048b9c081d7e0365db5e4c97e084baddaeac0ac08ffa92dd"
        );
        assert_eq!(
            hex::encode(single),
            "b88e29199f6c5c9e0bfc8842a86a1193819d4ac9bb47f699b04b358516376346"
        );
        let three = score_root(&[entry(1, 1000), entry(2, 2000), entry(3, 3000)]).unwrap();
        assert_eq!(
            hex::encode(three),
            "53afdb59fbb74c3ee470ce1c8f28574e4e5740d56cb91c08b214f2237e4a03bf"
        );
    }
}
