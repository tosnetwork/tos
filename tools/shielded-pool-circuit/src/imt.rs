/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 7: the nullifier indexed Merkle tree, as a wallet has to model it
//! in order to produce a witness.
//!
//! The circuit does not prove anything about this tree -- non-membership and
//! insertion are enforced on chain, in `imt.fc`. But a transaction cannot be
//! submitted without two witnesses against it, so a prover that cannot build
//! one cannot submit a proof, however good the proof is. That is why it is
//! here and not in a test.
//!
//! Nothing below folds a path or carries a frontier. Every root is rebuilt
//! from every allocated leaf, which is a different computation from the one
//! the contract performs and is the point: a path that happens to fold to a
//! plausible root is not the same thing as a tree that contains the leaf.

use std::collections::BTreeMap;

use ark_ff::AdditiveGroup;

use crate::domains::h7;
use crate::error::{Error, Result};
use crate::field::Fr;

/// Section 7.0.
pub const DEPTH: usize = 12;
pub const ARITY: u64 = 7;
/// Twelve levels, six siblings each.
pub const PATH_FIELDS: usize = DEPTH * 6;
/// `ARITY^DEPTH` is larger than this; section 7.0 caps the tree at 2^32 leaves.
pub const CAPACITY: u64 = 1 << 32;

fn imt_node(children: [Fr; 7]) -> Fr {
    h7("IMT-NODE", &children)
}

/// Section 7.0: `IMT_EMPTY[0] = 0`, then a level per copy under `IMT-NODE`.
/// This is a *different* ladder from the commitment tree's, which is built
/// under `COMMIT-NODE`; reusing the wrong one is the mistake this separation
/// exists to make visible.
pub fn empty_ladder() -> Vec<Fr> {
    let mut out = vec![Fr::ZERO];
    for level in 0..DEPTH {
        out.push(imt_node([out[level]; 7]));
    }
    out
}

/// A leaf of the indexed tree: a value and the link to its successor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Leaf {
    pub value: Fr,
    pub next_index: u32,
    pub next_value: Fr,
}

impl Leaf {
    /// Section 7.0: leaf zero is the head sentinel, and it is what reserves
    /// the value zero rather than a rule of its own.
    pub fn sentinel() -> Self {
        Leaf { value: Fr::ZERO, next_index: 0, next_value: Fr::ZERO }
    }

    pub fn hash(&self) -> Fr {
        h7(
            "IMT-LEAF",
            &[
                self.value,
                Fr::from(u64::from(self.next_index)),
                self.next_value,
                Fr::ZERO,
                Fr::ZERO,
                Fr::ZERO,
                Fr::ZERO,
            ],
        )
    }
}

/// A whole tree as a map from leaf index to leaf.
#[derive(Clone, Default)]
pub struct Tree {
    pub leaves: BTreeMap<u64, Leaf>,
}

impl Tree {
    /// Node values level by level, sparsely. A missing entry is that level's
    /// empty root.
    fn levels(&self) -> Vec<BTreeMap<u64, Fr>> {
        let empty = empty_ladder();
        let mut levels: Vec<BTreeMap<u64, Fr>> = Vec::with_capacity(DEPTH + 1);
        levels.push(self.leaves.iter().map(|(index, leaf)| (*index, leaf.hash())).collect());
        for level in 0..DEPTH {
            let current = &levels[level];
            let parents: Vec<u64> = {
                let mut seen: BTreeMap<u64, ()> = BTreeMap::new();
                for index in current.keys() {
                    seen.insert(index / ARITY, ());
                }
                seen.into_keys().collect()
            };
            let mut next: BTreeMap<u64, Fr> = BTreeMap::new();
            for parent in parents {
                let mut children = [empty[level]; 7];
                for (position, slot) in children.iter_mut().enumerate() {
                    if let Some(value) = current.get(&(parent * ARITY + position as u64)) {
                        *slot = *value;
                    }
                }
                next.insert(parent, imt_node(children));
            }
            levels.push(next);
        }
        levels
    }

    pub fn root(&self) -> Fr {
        let empty = empty_ladder();
        self.levels()[DEPTH].get(&0).copied().unwrap_or(empty[DEPTH])
    }

    /// Section 7.2: twelve levels, leaf to root, six siblings per level in
    /// ascending child position with the path digit skipped.
    pub fn path(&self, index: u64) -> Result<Vec<Fr>> {
        let empty = empty_ladder();
        let levels = self.levels();
        let mut out = Vec::with_capacity(PATH_FIELDS);
        let mut stride = 1u64;
        for (level, nodes) in levels.iter().take(DEPTH).enumerate() {
            let at_level = index / stride;
            let digit = at_level % ARITY;
            let base = (at_level / ARITY) * ARITY;
            for position in 0..ARITY {
                if position == digit {
                    continue;
                }
                out.push(nodes.get(&(base + position)).copied().unwrap_or(empty[level]));
            }
            stride *= ARITY;
        }
        if out.len() != PATH_FIELDS {
            return Err(Error::Backend(format!("a path is {} fields, not 72", out.len())));
        }
        Ok(out)
    }
}

/// Everything a caller supplies for one insertion, before encoding.
#[derive(Clone)]
pub struct Witness {
    pub low_index: u32,
    pub low_value: Fr,
    pub low_next_index: u32,
    pub low_next_value: Fr,
    pub low_path: Vec<Fr>,
    pub append_path: Vec<Fr>,
}

/// The contract's two persistent nullifier fields, with the tree behind them.
#[derive(Clone)]
pub struct State {
    pub tree: Tree,
    pub next_index: u64,
}

impl Default for State {
    fn default() -> Self {
        Self::genesis()
    }
}

impl State {
    /// Section 7.0: leaf 0 holds the head sentinel and the next index is 1.
    pub fn genesis() -> Self {
        let mut tree = Tree::default();
        tree.leaves.insert(0, Leaf::sentinel());
        State { tree, next_index: 1 }
    }

    pub fn root(&self) -> Fr {
        self.tree.root()
    }

    /// The allocated leaf with the greatest value strictly below `nullifier`.
    fn predecessor(&self, nullifier: &Fr) -> Result<(u64, Leaf)> {
        let mut best: Option<(u64, Leaf)> = None;
        for (index, leaf) in &self.tree.leaves {
            let better = match best {
                None => true,
                Some((_, chosen)) => leaf.value > chosen.value,
            };
            if leaf.value < *nullifier && better {
                best = Some((*index, *leaf));
            }
        }
        best.ok_or_else(|| Error::Backend("no predecessor; the sentinel is missing".to_string()))
    }

    /// The witness of 7.1, together with the tree the insertion leaves behind.
    /// Inserting two nullifiers therefore means taking the second witness
    /// against the tree the first one left, not against the tree the message
    /// started with.
    pub fn witness_for(&self, nullifier: &Fr) -> Result<(Witness, Tree)> {
        let (low_index, low) = self.predecessor(nullifier)?;
        let new_index = self.next_index;
        if new_index >= CAPACITY {
            return Err(Error::Backend("the nullifier tree is exhausted".to_string()));
        }

        let low_path = self.tree.path(low_index)?;

        let mut after_update = self.tree.clone();
        after_update.leaves.insert(
            low_index,
            Leaf {
                value: low.value,
                next_index: u32::try_from(new_index)
                    .map_err(|_| Error::Backend("leaf index is not a uint32".to_string()))?,
                next_value: *nullifier,
            },
        );
        let append_path = after_update.path(new_index)?;

        let mut after_insert = after_update;
        after_insert.leaves.insert(
            new_index,
            Leaf { value: *nullifier, next_index: low.next_index, next_value: low.next_value },
        );

        let witness = Witness {
            low_index: u32::try_from(low_index)
                .map_err(|_| Error::Backend("low index is not a uint32".to_string()))?,
            low_value: low.value,
            low_next_index: low.next_index,
            low_next_value: low.next_value,
            low_path,
            append_path,
        };
        Ok((witness, after_insert))
    }

    pub fn apply(&mut self, tree: Tree) {
        self.tree = tree;
        self.next_index += 1;
    }
}
