/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The pool's state as a wallet rebuilds it from the pool's own history.
//!
//! The pool publishes no events, and none of its getters returns a Merkle path,
//! a frontier or a nullifier witness. A wallet that wants to spend therefore
//! has to replay every state change the pool accepted, in order, from genesis,
//! and arrive at exactly the state the chain holds. Anything less is a model of
//! some other pool.
//!
//! This module is that replay, with no chain types in it: a caller decodes each
//! committed pool transaction into an [`Event`] and applies it. The rules are
//! the contract's, section 16 of the profile:
//!
//! * a deposit appends one leaf, computed by the contract from what it admitted;
//! * a transact inserts both nullifiers, one after the other, and appends all
//!   three outputs -- dummies included, because the contract cannot tell them
//!   apart and neither may a wallet;
//! * a withdrawal also holds one leaf back for the recovery note its payout
//!   would need if it bounced, and that template is not a leaf;
//! * a bounce of one of the pool's own payouts consumes that reservation and,
//!   if what came back is worth more than putting it back costs, mints one note
//!   at whatever index is next when it arrives.
//!
//! A replay that ends anywhere other than the chain's state is refused by the
//! caller; [`Ledger::checkpoint`] is what it compares.

// Every amount in this module is money: no raw arithmetic, checked or saturating only.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::imt;
use shielded_pool_circuit::notes;
use shielded_pool_circuit::tree::Frontier;
use shielded_pool_circuit::wire;

use crate::delivery::RECOVERY_PAYLOAD_SLOT;
use crate::error::{Error, Result};
use crate::import::ChainSlot;
use crate::scan::ObservedOutput;

/// The withdrawal payout a transact emitted, as its transaction shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    /// The destination, in whatever canonical text form the caller uses for
    /// both this and [`Event::Bounce::sender`]. Only equality is used.
    pub recipient: String,
    /// The value the payout message carried.
    pub value: u128,
    /// The representation hash of the payout message body. A bounce carries
    /// the original body back, which is how the two are matched.
    pub body_hash: [u8; 32],
}

/// Section 16.2, decoded. `payout` is present exactly when
/// `public_amount_out > 0`.
#[derive(Clone, Debug)]
pub struct Transact {
    pub nullifiers: [Fr; 2],
    pub note_bodies: [Fr; 3],
    pub payloads: [Vec<u8>; 3],
    pub public_amount_out: u128,
    pub withdrawal_fee: u128,
    pub recovery_owner_commitment: Fr,
    pub recovery_payload: Option<Vec<u8>>,
    pub payout: Option<Payout>,
}

/// One transaction that changed the pool's state, decoded.
#[derive(Clone, Debug)]
pub enum Event {
    /// Section 16.1.
    Deposit { amount: u128, owner_commitment: Fr, output_data: Vec<u8> },
    /// Section 16.2.
    Transact(Box<Transact>),
    /// Section 16.3: a bounced message that carried a recovery envelope and
    /// that the pool accepted.
    Bounce { original_body_hash: [u8; 32], sender: String, value: u128 },
}

/// The pool state a replay is compared with: every field of the contract's
/// state cell that the history determines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub commitment_root: Fr,
    pub commitment_next_index: u64,
    pub reserved_recovery_leaves: u64,
    pub nullifier_root: Fr,
    pub nullifier_next_index: u64,
    pub native_liability: u128,
}

/// A withdrawal whose payout has not come back, or has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRecovery {
    pub payout: Payout,
    pub owner_commitment: Fr,
    pub payload: Vec<u8>,
    /// Set once its bounce has been applied, minted or not. A payout can only
    /// bounce once, and a second bounce for it is a replay.
    pub consumed: bool,
}

/// One output the chain carried, the leaf it became, and what to hand the
/// scan. A recovery template is carried but is not a leaf.
#[derive(Clone)]
pub struct Output {
    pub leaf: Option<u64>,
    pub observed: ObservedOutput,
}

/// The replayed pool.
#[derive(Clone)]
pub struct Ledger {
    frontier: Frontier,
    commitment_root: Fr,
    leaves: Vec<Fr>,
    imt: imt::State,
    nullifiers: Vec<Fr>,
    published: BTreeSet<Fr>,
    native_liability: u128,
    reserved_recovery_leaves: u64,
    pending: Vec<PendingRecovery>,
    outputs: Vec<Output>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self::genesis()
    }
}

fn overflow(what: &str) -> Error {
    Error::Encoding(format!("{what} overflows"))
}

impl Ledger {
    /// The state `state_genesis` writes: an empty commitment tree, the
    /// nullifier tree holding only its head sentinel, no liability.
    pub fn genesis() -> Self {
        let frontier = Frontier::new();
        let commitment_root = frontier.empty_root();
        Self {
            frontier,
            commitment_root,
            leaves: Vec::new(),
            imt: imt::State::genesis(),
            nullifiers: Vec::new(),
            published: BTreeSet::new(),
            native_liability: 0,
            reserved_recovery_leaves: 0,
            pending: Vec::new(),
            outputs: Vec::new(),
        }
    }

    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            commitment_root: self.commitment_root,
            commitment_next_index: self.frontier.next_index(),
            reserved_recovery_leaves: self.reserved_recovery_leaves,
            nullifier_root: self.imt.root(),
            nullifier_next_index: self.imt.next_index,
            native_liability: self.native_liability,
        }
    }

    /// Every leaf, in index order.
    pub fn leaves(&self) -> &[Fr] {
        &self.leaves
    }

    /// Every nullifier the pool has accepted, in insertion order.
    pub fn nullifiers(&self) -> &[Fr] {
        &self.nullifiers
    }

    pub fn published_nullifiers(&self) -> &BTreeSet<Fr> {
        &self.published
    }

    pub fn pending_recoveries(&self) -> &[PendingRecovery] {
        &self.pending
    }

    /// Every output, in the order the chain carried them.
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// The outputs from position `from` on, as the scan takes them, with the
    /// leaf each became.
    pub fn observed_since(&self, from: usize) -> Vec<(ObservedOutput, Option<u64>)> {
        self.outputs
            .iter()
            .skip(from)
            .map(|output| (output.observed.clone(), output.leaf))
            .collect()
    }

    /// The commitment tree, for membership paths.
    pub fn frontier(&self) -> &Frontier {
        &self.frontier
    }

    /// The nullifier tree as it stands, for insertion witnesses.
    pub fn nullifier_state(&self) -> &imt::State {
        &self.imt
    }

    fn append(&mut self, note_body: Fr) -> Result<u64> {
        let index = self.frontier.next_index();
        let leaf = notes::note_commitment(note_body, Fr::from(index));
        let (taken, root) = self
            .frontier
            .append(leaf)
            .map_err(|error| Error::Encoding(format!("commitment append: {error}")))?;
        if taken != index {
            return Err(Error::Encoding("commitment append took an unexpected index".into()));
        }
        self.commitment_root = root;
        self.leaves.push(leaf);
        Ok(index)
    }

    /// Room the contract requires before it appends: the leaves plus every
    /// reservation must still fit below the index sentinel.
    fn require_room(&self, leaves: u64, reservations: u64) -> Result<()> {
        const INDEX_SENTINEL: u64 = 1 << 32;
        let used = self
            .frontier
            .next_index()
            .checked_add(self.reserved_recovery_leaves)
            .and_then(|value| value.checked_add(leaves))
            .and_then(|value| value.checked_add(reservations))
            .ok_or_else(|| overflow("commitment index"))?;
        if used > INDEX_SENTINEL {
            return Err(Error::Encoding("the history appends past the commitment tree".into()));
        }
        Ok(())
    }

    /// Apply one committed state change. `recovery_charge` is the charge the
    /// contract applied to a bounce; only a bounce uses it.
    ///
    /// Every refusal here is a history the contract could not have produced,
    /// so the replay stops rather than guessing.
    pub fn apply(&mut self, event: &Event, recovery_charge: u128) -> Result<()> {
        match event {
            Event::Deposit { amount, owner_commitment, output_data } => {
                self.apply_deposit(*amount, *owner_commitment, output_data)
            }
            Event::Transact(transact) => self.apply_transact(transact),
            Event::Bounce { original_body_hash, sender, value } => {
                self.apply_bounce(original_body_hash, sender, *value, recovery_charge)
            }
        }
    }

    fn apply_deposit(&mut self, amount: u128, owner: Fr, payload: &[u8]) -> Result<()> {
        if amount == 0 {
            return Err(Error::Encoding("a committed deposit of zero".into()));
        }
        self.require_room(1, 0)?;
        let data_hash = wire::output_data_hash(payload);
        let note_body = notes::note_body_commitment(owner, Fr::from(amount), data_hash);
        let leaf = self.append(note_body)?;
        self.native_liability =
            self.native_liability.checked_add(amount).ok_or_else(|| overflow("liability"))?;
        self.outputs.push(Output {
            leaf: Some(leaf),
            observed: ObservedOutput {
                slot: 0,
                output_data: payload.to_vec(),
                chain: ChainSlot { output_data_hash: data_hash, note_body, recovered: None },
            },
        });
        Ok(())
    }

    fn apply_transact(&mut self, transact: &Transact) -> Result<()> {
        let Transact {
            nullifiers,
            note_bodies,
            payloads,
            public_amount_out,
            withdrawal_fee,
            recovery_owner_commitment: recovery_owner,
            recovery_payload,
            payout,
        } = transact;
        let (public_amount_out, withdrawal_fee, recovery_owner) =
            (*public_amount_out, *withdrawal_fee, *recovery_owner);
        let (recovery_payload, payout) = (recovery_payload.as_deref(), payout.as_ref());
        let withdrawal = public_amount_out > 0;
        match (withdrawal, recovery_payload, payout) {
            (true, Some(_), Some(payout)) if payout.value == public_amount_out => {}
            (false, None, None) => {}
            _ => {
                return Err(Error::Encoding(
                    "a committed transact whose payout does not match its amount".into(),
                ))
            }
        }
        if nullifiers[0] == nullifiers[1] {
            return Err(Error::Encoding("a committed transact repeats a nullifier".into()));
        }
        self.require_room(3, u64::from(withdrawal))?;

        // Both insertions against temporary state, as the contract does: the
        // second witness is taken against the tree the first one left, and
        // nothing is kept unless both succeed.
        let mut imt = self.imt.clone();
        for nullifier in nullifiers {
            if self.published.contains(nullifier) {
                return Err(Error::Encoding("a committed transact reuses a nullifier".into()));
            }
            let (_, tree) = imt
                .witness_for(nullifier)
                .map_err(|error| Error::Encoding(format!("nullifier insertion: {error}")))?;
            imt.apply(tree);
        }
        let mut liability = self.native_liability;
        if withdrawal {
            liability = liability
                .checked_sub(public_amount_out)
                .and_then(|value| value.checked_sub(withdrawal_fee))
                .ok_or_else(|| Error::Encoding("a withdrawal exceeds the liability".into()))?;
        }

        self.imt = imt;
        for nullifier in nullifiers {
            self.nullifiers.push(*nullifier);
            self.published.insert(*nullifier);
        }
        for (slot, (body, payload)) in note_bodies.iter().zip(payloads.iter()).enumerate() {
            let leaf = self.append(*body)?;
            self.outputs.push(Output {
                leaf: Some(leaf),
                observed: ObservedOutput {
                    slot: slot as u8,
                    output_data: payload.clone(),
                    chain: ChainSlot {
                        output_data_hash: wire::output_data_hash(payload),
                        note_body: *body,
                        recovered: None,
                    },
                },
            });
        }
        self.native_liability = liability;

        if let (Some(payload), Some(payout)) = (recovery_payload, payout) {
            self.reserved_recovery_leaves = self
                .reserved_recovery_leaves
                .checked_add(1)
                .ok_or_else(|| overflow("reservations"))?;
            // The template is what the withdrawal signed. It is offered to the
            // scan under the recovery slot only, so the sender learns which of
            // its indices it consumed; it carries no money and is no leaf.
            let data_hash = wire::output_data_hash(payload);
            self.outputs.push(Output {
                leaf: None,
                observed: ObservedOutput {
                    slot: RECOVERY_PAYLOAD_SLOT,
                    output_data: payload.to_vec(),
                    chain: ChainSlot {
                        output_data_hash: data_hash,
                        note_body: wire::recovery_template_hash(recovery_owner, data_hash),
                        recovered: None,
                    },
                },
            });
            self.pending.push(PendingRecovery {
                payout: payout.clone(),
                owner_commitment: recovery_owner,
                payload: payload.to_vec(),
                consumed: false,
            });
        }
        Ok(())
    }

    fn apply_bounce(
        &mut self,
        original_body_hash: &[u8; 32],
        sender: &str,
        value: u128,
        charge: u128,
    ) -> Result<()> {
        let mut matching = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, pending)| pending.payout.body_hash == *original_body_hash);
        let index = match (matching.next(), matching.next()) {
            (Some((index, _)), None) => index,
            (None, _) => {
                return Err(Error::Encoding("a recovery with no payout of this pool".into()))
            }
            (Some(_), Some(_)) => {
                return Err(Error::Encoding("two payouts share one body hash".into()))
            }
        };
        let pending = self.pending[index].clone();
        if pending.consumed {
            return Err(Error::Encoding("a payout recovered twice".into()));
        }
        if pending.payout.recipient != sender {
            return Err(Error::Encoding(
                "a recovery from an account the payout never went to".into(),
            ));
        }
        if value > pending.payout.value {
            return Err(Error::Encoding("a bounce returned more than its payout carried".into()));
        }
        if charge == 0 {
            return Err(Error::Encoding("a recovery charge of zero".into()));
        }
        self.reserved_recovery_leaves = self
            .reserved_recovery_leaves
            .checked_sub(1)
            .ok_or_else(|| Error::Encoding("a recovery with no reservation".into()))?;
        self.pending[index].consumed = true;
        // Section 15.4: at or below the charge nothing is minted, but the
        // reservation is still spent.
        if value <= charge {
            return Ok(());
        }
        let amount = value
            .checked_sub(charge)
            .ok_or_else(|| Error::Encoding("a recovery below its charge".into()))?;
        let data_hash = wire::output_data_hash(&pending.payload);
        let note_body =
            notes::note_body_commitment(pending.owner_commitment, Fr::from(amount), data_hash);
        // The leaf the reservation held; nothing else could have taken it.
        let leaf = self.append(note_body)?;
        self.native_liability =
            self.native_liability.checked_add(amount).ok_or_else(|| overflow("liability"))?;
        // The same payload, now money. The template stays where it was: the
        // output list is append-only so a wallet that has already scanned it
        // can scan only what follows, and the scan counts a template and the
        // note minted from it as one use of their index.
        self.outputs.push(Output {
            leaf: Some(leaf),
            observed: ObservedOutput {
                slot: RECOVERY_PAYLOAD_SLOT,
                output_data: pending.payload.clone(),
                chain: ChainSlot {
                    output_data_hash: data_hash,
                    note_body,
                    recovered: Some(amount),
                },
            },
        });
        Ok(())
    }
}

/// Everything a replay needs to continue from where it stopped, as plain
/// data a caller can persist however it likes. The outputs are not part of
/// it: they are scanned once, when they arrive, and other people's payloads
/// are not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub leaves: Vec<Fr>,
    pub nullifiers: Vec<Fr>,
    /// The nullifier tree's allocated leaves, index and leaf, in index order.
    pub nullifier_tree: Vec<(u64, imt::Leaf)>,
    pub nullifier_next_index: u64,
    pub native_liability: u128,
    pub reserved_recovery_leaves: u64,
    pub pending: Vec<PendingRecovery>,
}

impl Ledger {
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            leaves: self.leaves.clone(),
            nullifiers: self.nullifiers.clone(),
            nullifier_tree: self.imt.tree.leaves.iter().map(|(i, leaf)| (*i, *leaf)).collect(),
            nullifier_next_index: self.imt.next_index,
            native_liability: self.native_liability,
            reserved_recovery_leaves: self.reserved_recovery_leaves,
            pending: self.pending.clone(),
        }
    }

    /// The ledger a snapshot describes, with the commitment tree rebuilt from
    /// its leaves. A snapshot that does not describe a ledger this code could
    /// have produced is refused.
    pub fn restore(snapshot: Snapshot) -> Result<Self> {
        let mut ledger = Self::genesis();
        for leaf in &snapshot.leaves {
            let (_, root) = ledger
                .frontier
                .append(*leaf)
                .map_err(|error| Error::Encoding(format!("restore commitment tree: {error}")))?;
            ledger.commitment_root = root;
        }
        ledger.leaves = snapshot.leaves;
        let expected_leaves = usize::try_from(snapshot.nullifier_next_index)
            .map_err(|_| overflow("nullifier index"))?;
        if snapshot.nullifier_tree.len() != expected_leaves
            || snapshot.nullifiers.len().saturating_add(1) != expected_leaves
            || snapshot.nullifier_tree.first().map(|(index, _)| *index) != Some(0)
        {
            return Err(Error::Encoding("a snapshot whose nullifier tree does not fit".into()));
        }
        let mut tree = imt::Tree::default();
        for (index, leaf) in snapshot.nullifier_tree {
            if tree.leaves.insert(index, leaf).is_some() {
                return Err(Error::Encoding("a snapshot repeats a nullifier leaf".into()));
            }
        }
        ledger.imt = imt::State { tree, next_index: snapshot.nullifier_next_index };
        ledger.published = snapshot.nullifiers.iter().copied().collect();
        if ledger.published.len() != snapshot.nullifiers.len() {
            return Err(Error::Encoding("a snapshot repeats a nullifier".into()));
        }
        ledger.nullifiers = snapshot.nullifiers;
        ledger.native_liability = snapshot.native_liability;
        ledger.reserved_recovery_leaves = snapshot.reserved_recovery_leaves;
        ledger.pending = snapshot.pending;
        ledger.require_room(0, 0)?;
        Ok(ledger)
    }

    /// Hands over every output applied since the ledger was created or last
    /// drained, with the leaf each became, and keeps none of them.
    pub fn take_outputs(&mut self) -> Vec<(ObservedOutput, Option<u64>)> {
        std::mem::take(&mut self.outputs)
            .into_iter()
            .map(|output| (output.observed, output.leaf))
            .collect()
    }
}
