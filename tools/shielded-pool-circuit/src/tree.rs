/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Profile section 5: the 7-ary depth-12 commitment tree, outside the
//! constraint system.

use ark_ff::AdditiveGroup;

use crate::domains::h7;
use crate::error::{Error, Result};
use crate::field::Fr;

/// Profile section 5: frozen shape.
pub const ARITY: usize = 7;
pub const DEPTH: usize = 12;
/// Leaf indices stay uint32 even though `7^12 > 2^32`.
pub const MAX_LEAVES: u64 = 1u64 << 32;

/// A node: `H7("COMMIT-NODE", child0, ..., child6)`.
pub fn commit_node(children: &[Fr; ARITY]) -> Fr {
    h7("COMMIT-NODE", children)
}

/// `EMPTY_ROOT[0] = 0`, `EMPTY_ROOT[level+1] = H7("COMMIT-NODE",
/// EMPTY_ROOT[level] repeated 7 times)`.
pub fn empty_roots() -> [Fr; DEPTH + 1] {
    let mut roots = [Fr::ZERO; DEPTH + 1];
    for level in 0..DEPTH {
        let child = roots[level];
        roots[level.saturating_add(1)] = commit_node(&[child; ARITY]);
    }
    roots
}

/// The 7-ary digit of `leaf_index` at `level`: `floor(i / 7^level) mod 7`.
pub fn digit_at(leaf_index: u64, level: usize) -> Result<usize> {
    let mut divisor: u64 = 1;
    for _ in 0..level {
        divisor = divisor
            .checked_mul(ARITY as u64)
            .ok_or_else(|| Error::Witness(format!("7^{level} overflows a u64")))?;
    }
    Ok(((leaf_index / divisor) % ARITY as u64) as usize)
}

/// One level of a membership path: the six siblings in slot order and the
/// position the child occupies among the seven.
#[derive(Clone, Debug)]
pub struct MerkleLevel {
    pub siblings: [Fr; ARITY - 1],
    pub position: usize,
}

/// A full depth-12 membership path.
#[derive(Clone, Debug)]
pub struct MerklePath {
    pub levels: [MerkleLevel; DEPTH],
}

impl MerklePath {
    /// Recomputes the root this path leads to from `leaf`.
    pub fn root(&self, leaf: Fr) -> Result<Fr> {
        let mut carry = leaf;
        for level in self.levels.iter() {
            if level.position >= ARITY {
                return Err(Error::Witness(format!(
                    "merkle position {} is not a 7-ary digit",
                    level.position
                )));
            }
            let mut children = [Fr::ZERO; ARITY];
            let mut sibling = 0usize;
            for (slot, child) in children.iter_mut().enumerate() {
                if slot == level.position {
                    *child = carry;
                } else {
                    *child = level.siblings[sibling];
                    sibling = sibling.saturating_add(1);
                }
            }
            carry = commit_node(&children);
        }
        Ok(carry)
    }
}

/// The persistent frontier of profile section 5.1, as a logical
/// `frontier[12][7]` array plus the next free leaf index.
#[derive(Clone, Debug)]
pub struct Frontier {
    slots: [[Fr; ARITY]; DEPTH],
    next_index: u64,
    empty: [Fr; DEPTH + 1],
    /// Every leaf appended so far, kept so that membership paths can be built
    /// for the tests. The contract keeps only the frontier.
    leaves: Vec<Fr>,
}

impl Default for Frontier {
    fn default() -> Self {
        Self::new()
    }
}

impl Frontier {
    pub fn new() -> Self {
        Self {
            slots: [[Fr::ZERO; ARITY]; DEPTH],
            next_index: 0,
            empty: empty_roots(),
            leaves: Vec::new(),
        }
    }

    /// The root of an empty tree.
    pub fn empty_root(&self) -> Fr {
        self.empty[DEPTH]
    }

    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Appends one leaf exactly as section 5.1 specifies and returns the new
    /// root together with the index the leaf took.
    pub fn append(&mut self, leaf: Fr) -> Result<(u64, Fr)> {
        if self.next_index >= MAX_LEAVES {
            return Err(Error::Witness("commitment tree is exhausted at 2^32 leaves".to_string()));
        }
        let index = self.next_index;
        let mut carry = leaf;
        for level in 0..DEPTH {
            let d = digit_at(index, level)?;
            self.slots[level][d] = carry;
            let mut children = [Fr::ZERO; ARITY];
            for (slot, child) in children.iter_mut().enumerate() {
                *child = if slot <= d { self.slots[level][slot] } else { self.empty[level] };
            }
            carry = commit_node(&children);
        }
        self.next_index = self.next_index.saturating_add(1);
        self.leaves.push(leaf);
        Ok((index, carry))
    }

    /// Rebuilds the full tree from the appended leaves and returns the root.
    /// Used to check the frontier against a straightforward construction.
    pub fn recomputed_root(&self) -> Fr {
        let mut level_nodes: Vec<Fr> = self.leaves.clone();
        for level in 0..DEPTH {
            let mut next: Vec<Fr> = Vec::new();
            let mut index = 0usize;
            while index < level_nodes.len() {
                let mut children = [self.empty[level]; ARITY];
                for (slot, child) in children.iter_mut().enumerate() {
                    if let Some(value) = level_nodes.get(index.saturating_add(slot)) {
                        *child = *value;
                    }
                }
                next.push(commit_node(&children));
                index = index.saturating_add(ARITY);
            }
            if next.is_empty() {
                return self.empty[DEPTH];
            }
            level_nodes = next;
        }
        match level_nodes.first() {
            Some(root) => *root,
            None => self.empty[DEPTH],
        }
    }

    /// Builds the membership path for an already appended leaf.
    pub fn path(&self, leaf_index: u64) -> Result<MerklePath> {
        if leaf_index >= self.next_index {
            return Err(Error::Witness(format!("leaf {leaf_index} has not been appended")));
        }
        let mut level_nodes: Vec<Fr> = self.leaves.clone();
        let mut levels: Vec<MerkleLevel> = Vec::with_capacity(DEPTH);
        let mut index = leaf_index as usize;
        for level in 0..DEPTH {
            let position = index % ARITY;
            let group_start = index.saturating_sub(position);
            let mut siblings = [Fr::ZERO; ARITY - 1];
            let mut sibling = 0usize;
            for slot in 0..ARITY {
                if slot == position {
                    continue;
                }
                siblings[sibling] = level_nodes
                    .get(group_start.saturating_add(slot))
                    .copied()
                    .unwrap_or(self.empty[level]);
                sibling = sibling.saturating_add(1);
            }
            levels.push(MerkleLevel { siblings, position });

            let mut next: Vec<Fr> = Vec::new();
            let mut cursor = 0usize;
            while cursor < level_nodes.len() {
                let mut children = [self.empty[level]; ARITY];
                for (slot, child) in children.iter_mut().enumerate() {
                    if let Some(value) = level_nodes.get(cursor.saturating_add(slot)) {
                        *child = *value;
                    }
                }
                next.push(commit_node(&children));
                cursor = cursor.saturating_add(ARITY);
            }
            level_nodes = next;
            index /= ARITY;
        }

        let levels: [MerkleLevel; DEPTH] = levels
            .try_into()
            .map_err(|_| Error::Witness("merkle path did not reach depth 12".to_string()))?;
        Ok(MerklePath { levels })
    }
}
