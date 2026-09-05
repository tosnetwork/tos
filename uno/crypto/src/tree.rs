//! Note-tree arithmetic and bounded frontier restoration. This is not a full
//! state codec: callers authenticate the snapshot, account for reservations,
//! enforce commitment uniqueness policy, and retain output history separately.

use incrementalmerkletree::frontier::Frontier;
use orchard::tree::MerkleHashOrchard;

const CAPACITY: u64 = 1u64 << 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeError {
    Capacity,
    NonCanonicalNode,
    FrontierShape,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontierSnapshot {
    pub next_position: u64,
    pub leaf: Option<[u8; 32]>,
    pub ommers: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct NoteTree {
    frontier: Frontier<MerkleHashOrchard, 32>,
}

fn decode(bytes: &[u8; 32]) -> Result<MerkleHashOrchard, TreeError> {
    Option::from(MerkleHashOrchard::from_bytes(bytes)).ok_or(TreeError::NonCanonicalNode)
}

impl Default for NoteTree {
    fn default() -> Self {
        Self { frontier: Frontier::empty() }
    }
}

impl NoteTree {
    pub fn next_position(&self) -> u64 {
        self.frontier.tree_size()
    }

    pub fn root(&self) -> [u8; 32] {
        self.frontier.root().to_bytes()
    }

    pub fn snapshot(&self) -> FrontierSnapshot {
        match self.frontier.value() {
            None => FrontierSnapshot { next_position: 0, leaf: None, ommers: Vec::new() },
            Some(value) => FrontierSnapshot {
                next_position: self.next_position(),
                leaf: Some(value.leaf().to_bytes()),
                ommers: value.ommers().iter().map(MerkleHashOrchard::to_bytes).collect(),
            },
        }
    }

    pub fn restore(snapshot: &FrontierSnapshot) -> Result<Self, TreeError> {
        if snapshot.next_position > CAPACITY || snapshot.ommers.len() > 32 {
            return Err(TreeError::Capacity);
        }
        if snapshot.next_position == 0 {
            return if snapshot.leaf.is_none() && snapshot.ommers.is_empty() {
                Ok(Self::default())
            } else {
                Err(TreeError::FrontierShape)
            };
        }
        let leaf = decode(snapshot.leaf.as_ref().ok_or(TreeError::FrontierShape)?)?;
        let ommers = snapshot.ommers.iter().map(decode).collect::<Result<Vec<_>, _>>()?;
        let frontier = Frontier::from_parts((snapshot.next_position - 1).into(), leaf, ommers)
            .map_err(|_| TreeError::FrontierShape)?;
        Ok(Self { frontier })
    }

    // All public outputs, including dummy/system outputs, must appear in order.
    // Reservations are an authenticated caller input, not mutable state here.
    // Refund execution releases its own reservation in the outer atomic state.
    pub fn append_batch(&self, commitments: &[[u8; 32]], reserved_leaves: u64) -> Result<Self, TreeError> {
        let available = CAPACITY.checked_sub(self.next_position())
            .and_then(|remaining| remaining.checked_sub(reserved_leaves))
            .ok_or(TreeError::Capacity)?;
        let count = u64::try_from(commitments.len()).map_err(|_| TreeError::Capacity)?;
        if count > available {
            return Err(TreeError::Capacity);
        }
        let mut next = self.clone();
        for commitment in commitments {
            if !next.frontier.append(decode(commitment)?) {
                return Err(TreeError::Capacity);
            }
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::Hashable;
    use orchard::tree::Anchor;

    fn leaf(value: u8) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[0] = value;
        bytes
    }

    // Independent full-layer reduction, without the incremental carry logic.
    fn full_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut nodes: Vec<_> = leaves.iter().map(|bytes| decode(bytes).expect("node")).collect();
        for level in 0..32u8 {
            if nodes.len() % 2 != 0 {
                nodes.push(MerkleHashOrchard::empty_root(level.into()));
            }
            nodes = nodes.chunks_exact(2)
                .map(|pair| MerkleHashOrchard::combine(level.into(), &pair[0], &pair[1])).collect();
        }
        assert_eq!(nodes.len(), 1);
        nodes[0].to_bytes()
    }

    #[test]
    fn append_matches_full_layers_and_restores() {
        let empty = NoteTree::default();
        assert_eq!(empty.root(), Anchor::empty_tree().to_bytes());
        assert_eq!(NoteTree::restore(&empty.snapshot()).expect("empty").root(), empty.root());
        let leaves: Vec<_> = (0..65).map(leaf).collect();
        let mut current = empty.clone();
        for (index, value) in leaves.iter().enumerate() {
            current = current.append_batch(&[*value], 0).expect("append");
            assert_eq!(current.next_position(), index as u64 + 1);
            assert_eq!(current.root(), full_root(&leaves[..=index]));
            let snapshot = current.snapshot();
            current = NoteTree::restore(&snapshot).expect("restore");
            assert_eq!(current.snapshot(), snapshot);
        }
        assert_eq!(empty.append_batch(&leaves, 0).expect("batch").root(), current.root());
        assert_eq!(empty.next_position(), 0);
    }

    #[test]
    fn malformed_and_late_failure_are_atomic() {
        let tree = NoteTree::default().append_batch(&[leaf(1), leaf(2)], 0).expect("tree");
        let original = tree.snapshot();
        assert_eq!(tree.append_batch(&[leaf(3), [255; 32]], 0).err(), Some(TreeError::NonCanonicalNode));
        assert_eq!(tree.snapshot(), original);
        let mut bad = original.clone();
        bad.ommers.clear();
        assert!(NoteTree::restore(&bad).is_err());
        bad = original.clone();
        bad.leaf = None;
        assert!(NoteTree::restore(&bad).is_err());
        bad = original.clone();
        bad.ommers[0] = [255; 32];
        assert_eq!(NoteTree::restore(&bad).err(), Some(TreeError::NonCanonicalNode));
        bad = original.clone();
        bad.next_position = 0;
        assert!(NoteTree::restore(&bad).is_err());
        bad = original;
        bad.ommers = vec![leaf(0); 33];
        assert!(NoteTree::restore(&bad).is_err());
    }

    #[test]
    fn capacity_and_reservations_do_not_wrap() {
        // Synthetic authenticated-state shape, not a claim of this history.
        let snapshot = FrontierSnapshot {
            next_position: CAPACITY - 1,
            leaf: Some(leaf(0)),
            ommers: vec![leaf(0); 31],
        };
        let tree = NoteTree::restore(&snapshot).expect("near capacity");
        assert_eq!(tree.append_batch(&[leaf(1)], 1).err(), Some(TreeError::Capacity));
        assert_eq!(tree.append_batch(&[], 2).err(), Some(TreeError::Capacity));
        assert_eq!(tree.append_batch(&[], u64::MAX).err(), Some(TreeError::Capacity));
        assert_eq!(tree.append_batch(&[leaf(1), leaf(2)], 0).err(), Some(TreeError::Capacity));
        let full = tree.append_batch(&[leaf(1)], 0).expect("last leaf");
        assert_eq!(full.next_position(), CAPACITY);
        assert_eq!(full.snapshot().ommers.len(), 32);
        assert_eq!(NoteTree::restore(&full.snapshot()).expect("full restore").root(), full.root());
        assert_eq!(full.append_batch(&[leaf(2)], 0).err(), Some(TreeError::Capacity));
        assert_eq!(full.append_batch(&[], 0).expect("empty batch").root(), full.root());
        let mut overflow = snapshot;
        overflow.next_position = CAPACITY + 1;
        assert!(NoteTree::restore(&overflow).is_err());
        assert_eq!(tree.next_position(), CAPACITY - 1);
    }
}
