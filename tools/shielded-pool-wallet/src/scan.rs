/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Mnemonic-only recovery: gates 7, 18 and 26.
//!
//! A restored wallet has a mnemonic and nothing else. It does not know which
//! indices it used, how many notes it holds, or what they are worth. What it
//! does is try to open every payload the chain carries and let the ones that
//! open say which indices were used -- which works precisely because the
//! ML-KEM key is long-lived within an execution domain while the owner and
//! ML-DSA keys are not.
//!
//! Section 2.5 is the awkward part and the reason this is not just a loop.
//! "Single use" is a rule the wallet follows when issuing, not one the chain
//! enforces. A payer who kept a descriptor can pay it again, and the recovered
//! wallet has to import both notes, keep both spendable, and never hand that
//! index out again. Discarding the second note because the descriptor was
//! already used would lose money to somebody else's mistake.

use std::collections::{BTreeMap, BTreeSet};

use crate::delivery::{self, Kind};
use crate::error::{Rejection, Result};
use crate::import::{self, ChainSlot, Imported};
use crate::keys::PoolInstance;

use shielded_pool_circuit::field::Fr;

/// One output slot as the chain carries it.
#[derive(Clone)]
pub struct ObservedOutput {
    /// Which of the three slots of its transaction, or slot 0 for a deposit.
    pub slot: u8,
    /// The exact bytes, as the contract hashed them.
    pub output_data: Vec<u8>,
    /// What the chain published about the slot.
    pub chain: ChainSlot,
}

/// A payload that opened but did not belong to a valid local note. Section 3.1
/// requires these to be kept rather than dropped, so a malformed or malicious
/// delivery can be shown to somebody.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub slot: u8,
    pub why: Rejection,
}

/// What a restored wallet knows after scanning.
#[derive(Default)]
pub struct Recovered {
    /// Every note this wallet owns, in the order the chain carried them.
    pub notes: Vec<Imported>,
    /// The next index it is safe to issue.
    pub next_note_key_index: u64,
    /// Indices seen more than once, which a wallet must never issue again and
    /// should consolidate away.
    pub reused: BTreeSet<u64>,
    /// Payloads that opened and were refused, with the rule each broke.
    pub diagnostics: Vec<Diagnostic>,
}

impl Recovered {
    /// Reconcile against the nullifiers the chain has published.
    ///
    /// A note's nullifier is `H7("NULLIFIER", note_body, owner_nf_key)`, and
    /// the owner key comes from the mnemonic by index. So whether a note is
    /// spent is computable from the mnemonic and the chain and nothing else --
    /// which is the whole test for whether it is a property of this system at
    /// all. No wallet database, no kept payload, no device.
    ///
    /// Restoration is not finished until this has run. Before it, every note
    /// this wallet ever received looks alike, including the ones it spent.
    pub fn reconcile_spent(
        &mut self,
        instance: &PoolInstance,
        published: &BTreeSet<Fr>,
    ) -> Result<()> {
        for note in &mut self.notes {
            let key = instance.owner_nf_key(note.note_key_index)?;
            let nullifier = shielded_pool_circuit::notes::nullifier(note.note_body, key);
            note.spent = published.contains(&nullifier);
        }
        Ok(())
    }

    /// What this wallet can spend.
    ///
    /// A balance is a number somebody acts on, and the way they act is to
    /// spend it, so a number that cannot be spent is not a balance. This one
    /// excludes notes the chain has already consumed.
    ///
    /// It used to be `received()` under this name, which made a wallet report
    /// twice its money after a self-transfer: the input it spent and the
    /// outputs that replaced it were both counted. A green test asserted that
    /// doubled figure.
    pub fn balance(&self) -> u128 {
        self.notes
            .iter()
            .filter(|note| note.spendable && !note.spent)
            .map(|note| note.amount)
            .sum()
    }

    /// Everything this wallet was ever sent, spent or not.
    ///
    /// Kept because descriptor-index recovery needs every note that ever
    /// arrived -- the next safe index is derived from all of them, not only
    /// from the ones still unspent. It is a historical total and is named as
    /// one, so it cannot be mistaken for money.
    pub fn received(&self) -> u128 {
        self.notes.iter().filter(|note| note.spendable).map(|note| note.amount).sum()
    }

    /// The notes an input may be selected from.
    pub fn spendable_notes(&self) -> impl Iterator<Item = &Imported> {
        self.notes.iter().filter(|note| note.spendable && !note.spent)
    }

    /// Whether this index may be issued. False for an index already used, and
    /// for one used more than once.
    pub fn may_issue(&self, index: u64) -> bool {
        index >= self.next_note_key_index && !self.reused.contains(&index)
    }
}

/// Scan every output the chain carries and recover what belongs to this
/// wallet.
///
/// A payload that will not open is the ordinary case -- most of a chain
/// belongs to other people -- and is not recorded. A payload that opens and is
/// then refused is recorded, because that one is about this wallet.
pub fn recover(instance: &PoolInstance, outputs: &[ObservedOutput]) -> Result<Recovered> {
    let mut out = Recovered::default();
    let mut seen: BTreeMap<u64, usize> = BTreeMap::new();

    for output in outputs {
        let plaintext = match delivery::open(instance, &output.output_data, output.slot) {
            Ok(plaintext) => plaintext,
            // Not ours, or not a payload at all. Both are silence.
            Err(Rejection::Undecryptable) => continue,
            Err(why) => {
                out.diagnostics.push(Diagnostic { slot: output.slot, why });
                continue;
            }
        };
        match import::import(instance, &plaintext, &output.chain)? {
            Ok(note) => {
                // Section 2.5 rule 3: import all of them. A second note at the
                // same index is a privacy problem, not a reason to lose it.
                *seen.entry(note.note_key_index).or_insert(0) += 1;
                out.notes.push(note);
            }
            Err(why) => out.diagnostics.push(Diagnostic { slot: output.slot, why }),
        }
    }

    // Section 2.5 rule 2: the next index is past every index that was used,
    // whatever kind of output used it. A dummy consumes an index too.
    out.next_note_key_index = seen.keys().copied().max().map(|highest| highest + 1).unwrap_or(0);
    // Rule 4: an index that carried more than one note is burnt for good.
    out.reused = seen.iter().filter(|(_, count)| **count > 1).map(|(index, _)| *index).collect();
    Ok(out)
}

/// Every index a scan found in use, whatever it was used for. A wallet keeps
/// this so it can tell "never issued" from "issued and spent".
pub fn used_indices(recovered: &Recovered) -> BTreeSet<u64> {
    recovered.notes.iter().map(|note| note.note_key_index).collect()
}

/// Which of the recovered notes are dummies. They are recovered so their
/// indices are known to be consumed, never so their value is counted.
pub fn dummies(recovered: &Recovered) -> Vec<&Imported> {
    recovered.notes.iter().filter(|note| note.kind == Kind::Dummy).collect()
}
