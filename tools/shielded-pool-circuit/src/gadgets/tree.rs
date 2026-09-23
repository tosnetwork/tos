/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Profile section 5 inside the constraint system: 7-ary depth-12 membership.
//!
//! The position at each level is a witness, so it is constrained rather than
//! trusted. A one-hot selector over the seven slots does two jobs at once: it
//! proves the position is a 7-ary digit, and it places the running child in
//! exactly one slot. Without the one-hot enforcement a prover could place the
//! child in several slots, or in none, and re-root a leaf it does not own.

use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::field::Fr;
use crate::gadgets::poseidon2::{h7, FrVar};
use crate::tree::{ARITY, DEPTH};

/// A node: `H7("COMMIT-NODE", child0, ..., child6)`.
pub fn commit_node(children: &[FrVar; ARITY]) -> Result<FrVar, SynthesisError> {
    h7("COMMIT-NODE", children)
}

/// One level of an in-circuit membership path.
pub struct MerkleLevelVar {
    pub siblings: [FrVar; ARITY - 1],
    /// One boolean per slot. Exactly one is true; that is enforced here.
    pub selector: [Boolean<Fr>; ARITY],
}

impl MerkleLevelVar {
    /// Allocates one level from a witness path.
    pub fn new_witness(
        cs: ConstraintSystemRef<Fr>,
        level: &crate::tree::MerkleLevel,
    ) -> Result<Self, SynthesisError> {
        let mut siblings: Vec<FrVar> = Vec::with_capacity(ARITY - 1);
        for value in level.siblings.iter() {
            siblings.push(FrVar::new_witness(cs.clone(), || Ok(*value))?);
        }
        let siblings: [FrVar; ARITY - 1] =
            siblings.try_into().map_err(|_| SynthesisError::Unsatisfiable)?;

        let mut selector: Vec<Boolean<Fr>> = Vec::with_capacity(ARITY);
        for slot in 0..ARITY {
            selector.push(Boolean::new_witness(cs.clone(), || Ok(slot == level.position))?);
        }
        let selector: [Boolean<Fr>; ARITY] =
            selector.try_into().map_err(|_| SynthesisError::Unsatisfiable)?;

        Ok(Self { siblings, selector })
    }

    /// Folds the running child into this level and returns the parent.
    fn fold(&self, child: &FrVar) -> Result<FrVar, SynthesisError> {
        // Exactly one slot is taken. Booleans are already constrained to
        // {0,1} by their allocation; this pins the population count to one.
        let mut chosen = FrVar::zero();
        for flag in self.selector.iter() {
            chosen = &chosen + &FrVar::from(flag.clone());
        }
        chosen.enforce_equal(&FrVar::one())?;

        // Slot j holds the running child when selector[j] is set, and
        // otherwise the next sibling that has not been consumed yet: the six
        // siblings fill the six slots other than the chosen one, in order. So
        // slot j takes sibling j while j is below the chosen slot, and sibling
        // j-1 once the chosen slot has gone by.
        let mut children: Vec<FrVar> = Vec::with_capacity(ARITY);
        for slot in 0..ARITY {
            // `taken` is true once the chosen slot is at or before `slot`.
            let taken = Boolean::kary_or(&self.selector[..=slot])?;
            // Slot 0 never reads `after` for real (if it is taken it is the
            // chosen slot and the selection below overrides it), and slot 6 is
            // always taken, so the out-of-range ends are filled with a
            // neighbouring sibling rather than left unhandled.
            let after = self.siblings.get(slot.saturating_sub(1));
            let before = self.siblings.get(slot.min(ARITY.saturating_sub(2)));
            let (after, before) = match (after, before) {
                (Some(after), Some(before)) => (after, before),
                _ => return Err(SynthesisError::Unsatisfiable),
            };
            let sibling = FrVar::conditionally_select(&taken, after, before)?;
            let value = FrVar::conditionally_select(&self.selector[slot], child, &sibling)?;
            children.push(value);
        }
        let children: [FrVar; ARITY] =
            children.try_into().map_err(|_| SynthesisError::Unsatisfiable)?;
        commit_node(&children)
    }
}

/// A full depth-12 in-circuit membership path.
pub struct MerklePathVar {
    pub levels: Vec<MerkleLevelVar>,
}

impl MerklePathVar {
    pub fn new_witness(
        cs: ConstraintSystemRef<Fr>,
        path: &crate::tree::MerklePath,
    ) -> Result<Self, SynthesisError> {
        let mut levels = Vec::with_capacity(DEPTH);
        for level in path.levels.iter() {
            levels.push(MerkleLevelVar::new_witness(cs.clone(), level)?);
        }
        Ok(Self { levels })
    }

    /// Recomputes the root this path leads to from `leaf`.
    pub fn root(&self, leaf: &FrVar) -> Result<FrVar, SynthesisError> {
        if self.levels.len() != DEPTH {
            return Err(SynthesisError::Unsatisfiable);
        }
        let mut carry = leaf.clone();
        for level in self.levels.iter() {
            carry = level.fold(&carry)?;
        }
        Ok(carry)
    }

    /// The leaf index this path encodes, as a field element:
    /// `sum(position_level * 7^level)`.
    ///
    /// Profile section 4.3 hashes the leaf index into the note commitment, so
    /// the index used there and the path walked here must be the same number.
    /// Deriving it from the selectors is what ties them together.
    pub fn leaf_index(&self) -> Result<FrVar, SynthesisError> {
        let mut total = FrVar::zero();
        let mut weight = Fr::from(1u64);
        let arity = Fr::from(ARITY as u64);
        for level in self.levels.iter() {
            for (slot, flag) in level.selector.iter().enumerate() {
                let contribution = weight * Fr::from(slot as u64);
                if contribution == Fr::from(0u64) {
                    continue;
                }
                total = &total + &(&FrVar::from(flag.clone()) * &FrVar::Constant(contribution));
            }
            weight *= arity;
        }
        Ok(total)
    }
}
