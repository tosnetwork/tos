/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 3.1: turning a decrypted payload into a note, or refusing to.
//!
//! Decryption proves only that the payload was encrypted to this wallet's
//! ML-KEM key. It does not prove that the plaintext describes the note the
//! chain actually published: the payer wrote the plaintext, and the contract
//! never looked inside it. A relay cannot swap the bytes -- the hash is a
//! public input -- but the payer can put anything in them.
//!
//! So every field is checked against something outside the payload. The owner
//! and key hashes are checked against what this wallet's own index derives,
//! and the note the plaintext describes is rebuilt and checked against the
//! note body the transaction published, using the payload hash the *chain*
//! observed rather than one recomputed from the bytes in hand.

use shielded_pool_circuit::domains::dummy_owner_nf_hash;
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::notes;

use crate::delivery::{Kind, Plaintext};
use crate::error::{Rejection, Result};
use crate::keys::PoolInstance;

/// Section 11: every amount is bounded, and a note's is no exception.
const AMOUNT_BITS: u32 = 120;

/// A payload that belongs to a real local note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Imported {
    pub kind: Kind,
    pub note_key_index: u64,
    /// Zero for a dummy and for a recovery template. Only an ordinary output
    /// is balance.
    pub amount: u128,
    pub note_secret: Fr,
    pub owner_commitment: Fr,
    pub note_body: Fr,
    /// True for an ordinary output, which is the only kind a wallet may add
    /// to its balance and later spend.
    pub spendable: bool,
    /// Whether the chain has published this note's nullifier.
    ///
    /// A restored wallet learns this by deriving the nullifier -- which needs
    /// only the mnemonic and the note it already holds -- and looking it up in
    /// the set the chain publishes. Until that reconciliation is done nothing
    /// is known, so the honest default is "not known to be spent" and a
    /// balance built from it is not a spendable balance.
    pub spent: bool,
}

/// What the chain says about the slot this payload arrived in.
#[derive(Clone, Copy, Debug)]
pub struct ChainSlot {
    /// The hash the contract itself computed over the bytes that arrived.
    /// Using this rather than a hash of the bytes in hand is what ties the
    /// import to the transaction instead of to the payload.
    pub output_data_hash: Fr,
    /// The note body the transaction published for this slot.
    pub note_body: Fr,
    /// For a recovery slot after the bounce: what the note was minted for.
    ///
    /// `None` means the slot is still the template the withdrawal signed and
    /// carries no money. `Some(v)` is the amount the contract computed as
    /// `msg_value - recovery_charge`, read off the chain rather than assumed,
    /// because the delivered part depends on forward fees no prover knows in
    /// advance.
    pub recovered: Option<u128>,
}

/// Section 3.1 in full, for one decrypted payload against one published slot.
pub fn import(
    instance: &PoolInstance,
    plaintext: &Plaintext,
    slot: &ChainSlot,
) -> Result<std::result::Result<Imported, Rejection>> {
    // Common checks 4 and 5: what this wallet's own index derives.
    let derived_owner_hash = instance.owner_nf_key_hash(plaintext.note_key_index)?;
    let derived_pq_hash = instance.pq_auth_key_hash(plaintext.note_key_index)?;

    let expected_owner_hash = match plaintext.kind {
        // A dummy names the fixed constant, not this wallet's owner hash. The
        // index is still the wallet's and is still consumed; what differs is
        // that the note it describes is owned by nobody.
        Kind::Dummy => dummy_owner_nf_hash(),
        Kind::Ordinary | Kind::Recovery => derived_owner_hash,
    };
    if plaintext.owner_nf_key_hash != expected_owner_hash {
        return Ok(Err(Rejection::OwnerNfKeyHash));
    }
    if plaintext.pq_auth_key_hash != derived_pq_hash {
        return Ok(Err(Rejection::PqAuthKeyHash));
    }

    let amount_ok = match plaintext.kind {
        Kind::Ordinary => plaintext.amount > 0 && plaintext.amount < (1u128 << AMOUNT_BITS),
        Kind::Dummy | Kind::Recovery => plaintext.amount == 0,
    };
    if !amount_ok {
        return Ok(Err(Rejection::Amount));
    }

    // The note the plaintext describes, rebuilt from the wallet's own key
    // material and the chain's own payload hash.
    let owner_commitment = notes::owner_commitment(
        plaintext.owner_nf_key_hash,
        plaintext.pq_auth_key_hash,
        plaintext.note_secret,
    );
    let note_body = notes::note_body_commitment(
        owner_commitment,
        Fr::from(plaintext.amount),
        slot.output_data_hash,
    );

    // A recovery template is not a note yet -- its amount is not known until
    // a bounce returns -- so what it is checked against is the template hash
    // the withdrawal signed, not a published note body.
    //
    // Once the bounce has happened it *is* a note, for whatever the bounce
    // delivered less the pool's charge, and `recovered` carries that amount.
    // Without this branch a refused withdrawal strands the sender's money
    // from the sender's point of view: the chain holds a note with a valid
    // owner and the wallet can only ever import the zero-amount template.
    // The person who causes that is the recipient, not the sender.
    if plaintext.kind == Kind::Recovery {
        if let Some(amount) = slot.recovered {
            // Rebuilt and matched against the body the chain published, the
            // same way an ordinary output is. The template hash is what the
            // withdrawal signed; this is what the bounce minted, and only the
            // second one can be spent.
            let minted = shielded_pool_circuit::notes::note_body_commitment(
                owner_commitment,
                Fr::from(amount),
                slot.output_data_hash,
            );
            if minted != slot.note_body {
                return Ok(Err(Rejection::NoteBodyMismatch));
            }
            return Ok(Ok(Imported {
                kind: plaintext.kind,
                note_key_index: plaintext.note_key_index,
                amount,
                note_secret: plaintext.note_secret,
                owner_commitment,
                note_body: minted,
                spendable: true,
                spent: false,
            }));
        }
        let template = shielded_pool_circuit::wire::recovery_template_hash(
            owner_commitment,
            slot.output_data_hash,
        );
        if template != slot.note_body {
            return Ok(Err(Rejection::NoteBodyMismatch));
        }
        return Ok(Ok(Imported {
            kind: plaintext.kind,
            note_key_index: plaintext.note_key_index,
            amount: 0,
            note_secret: plaintext.note_secret,
            owner_commitment,
            note_body: template,
            spendable: false,
            spent: false,
        }));
    }

    if note_body != slot.note_body {
        return Ok(Err(Rejection::NoteBodyMismatch));
    }

    Ok(Ok(Imported {
        kind: plaintext.kind,
        note_key_index: plaintext.note_key_index,
        amount: plaintext.amount,
        note_secret: plaintext.note_secret,
        owner_commitment,
        note_body,
        spendable: plaintext.kind == Kind::Ordinary,
        spent: false,
    }))
}
