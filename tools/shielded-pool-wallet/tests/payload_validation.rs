/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 3.1 and gate 25: a payload is accepted only by the exact rules.
//!
//! Decryption proves the payload was encrypted to this wallet's key and
//! nothing else. The payer wrote the plaintext and the contract never looked
//! inside it, so every field has to be checked against something outside the
//! payload before a wallet counts it as money.
//!
//! Each rule below gets a payload that breaks it and nothing else, and the
//! rejection is required to name that rule. A test that only asserted "was
//! refused" would pass just as well if one check were doing all the work.

use shielded_pool_circuit::domains::dummy_owner_nf_hash;
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::{notes, wire};
use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
use shielded_pool_wallet::error::Rejection;
use shielded_pool_wallet::import::{import, ChainSlot};
use shielded_pool_wallet::keys::PoolInstance;

const SEED: [u8; 32] = [0x2a; 32];

fn domain() -> Fr {
    Fr::from(0x5348_4c44_5f54_4553u64)
}

fn instance() -> PoolInstance {
    PoolInstance::new(&SEED, domain())
}

/// A well-formed ordinary payload for `index`, and the slot the chain would
/// publish for it.
fn ordinary(instance: &PoolInstance, index: u64, amount: u128) -> (Plaintext, ChainSlot) {
    let plaintext = Plaintext {
        slot: 0,
        kind: Kind::Ordinary,
        amount,
        note_secret: Fr::from(0xc0ffeeu64 + index),
        owner_nf_key_hash: instance.owner_nf_key_hash(index).expect("an owner hash"),
        note_key_index: index,
        pq_auth_key_hash: instance.pq_auth_key_hash(index).expect("a key hash"),
    };
    (plaintext, chain_slot(instance, &plaintext))
}

/// What the chain would publish, given that payload: the hash of the sealed
/// bytes and the note body the contract's own inputs would carry.
fn chain_slot(instance: &PoolInstance, plaintext: &Plaintext) -> ChainSlot {
    let sealed = delivery::seal(
        &instance.mlkem_encapsulation_key().expect("a key"),
        instance.execution_domain(),
        plaintext,
    )
    .expect("seal");
    let output_data_hash = wire::output_data_hash(&sealed);
    let owner = notes::owner_commitment(
        plaintext.owner_nf_key_hash,
        plaintext.pq_auth_key_hash,
        plaintext.note_secret,
    );
    let note_body =
        notes::note_body_commitment(owner, Fr::from(plaintext.amount), output_data_hash);
    ChainSlot { output_data_hash, note_body, recovered: None }
}

fn refusal(instance: &PoolInstance, plaintext: &Plaintext, slot: &ChainSlot) -> Rejection {
    match import(instance, plaintext, slot).expect("import") {
        Ok(_) => panic!("a payload that should have been refused was imported"),
        Err(why) => why,
    }
}

/// The payload a payer sends, sealed and opened, arrives unchanged. Without
/// this the rejections below would not mean anything.
#[test]
fn a_well_formed_payload_seals_opens_and_imports() {
    let instance = instance();
    let (plaintext, slot) = ordinary(&instance, 3, 1_000_000_000);
    let sealed =
        delivery::seal(&instance.mlkem_encapsulation_key().expect("a key"), domain(), &plaintext)
            .expect("seal");
    assert_eq!(sealed.len(), delivery::OUTPUT_DATA_BYTES, "a payload is not 1233 bytes");

    let opened = delivery::open(&instance, &sealed, 0).expect("open");
    assert_eq!(opened, plaintext, "what came out is not what went in");

    let note = import(&instance, &opened, &slot).expect("import").expect("a valid note");
    assert_eq!(note.amount, 1_000_000_000);
    assert!(note.spendable, "an ordinary output is not spendable");
    assert_eq!(note.note_key_index, 3);
}

/// Section 3's slot binding: a payload sealed for one slot does not open in
/// another, because the slot is in the key derivation and in the AAD.
#[test]
fn a_payload_does_not_open_in_another_slot() {
    let instance = instance();
    let (plaintext, _) = ordinary(&instance, 1, 5);
    let sealed =
        delivery::seal(&instance.mlkem_encapsulation_key().expect("a key"), domain(), &plaintext)
            .expect("seal");
    assert_eq!(delivery::open(&instance, &sealed, 1), Err(Rejection::Undecryptable));
}

/// And the domain binding, which is what stops a payload from one pool being
/// replayed into another.
#[test]
fn a_payload_does_not_open_under_another_domain() {
    let here = instance();
    let (plaintext, _) = ordinary(&here, 1, 5);
    let sealed =
        delivery::seal(&here.mlkem_encapsulation_key().expect("a key"), domain(), &plaintext)
            .expect("seal");
    // The same mnemonic, another pool. Its ML-KEM key differs, so it cannot
    // even decapsulate.
    let there = PoolInstance::new(&SEED, Fr::from(999u64));
    assert_eq!(delivery::open(&there, &sealed, 0), Err(Rejection::Undecryptable));
}

/// Each rule of section 3.1, broken on its own, named by the refusal.
#[test]
fn each_rule_refuses_for_its_own_reason() {
    let instance = instance();
    let (good, good_slot) = ordinary(&instance, 4, 77);

    // The plaintext names an owner this index does not derive. This is the
    // check that stops a payer from describing somebody else's note.
    let mut wrong_owner = good;
    wrong_owner.owner_nf_key_hash = Fr::from(1u64);
    assert_eq!(
        refusal(&instance, &wrong_owner, &chain_slot(&instance, &wrong_owner)),
        Rejection::OwnerNfKeyHash
    );

    // And one that names a PQ key it does not derive, which would leave the
    // note unspendable.
    let mut wrong_key = good;
    wrong_key.pq_auth_key_hash = Fr::from(2u64);
    assert_eq!(
        refusal(&instance, &wrong_key, &chain_slot(&instance, &wrong_key)),
        Rejection::PqAuthKeyHash
    );

    // An ordinary output of zero is not an ordinary output.
    let mut zero = good;
    zero.amount = 0;
    assert_eq!(refusal(&instance, &zero, &chain_slot(&instance, &zero)), Rejection::Amount);

    // Nor one at or above 2^120, which conservation could otherwise be made
    // to balance by wrapping the field.
    let mut huge = good;
    huge.amount = 1u128 << 120;
    assert_eq!(refusal(&instance, &huge, &chain_slot(&instance, &huge)), Rejection::Amount);

    // The note the plaintext describes is not the note the chain published.
    // Everything in the payload is consistent; it simply is not this slot.
    let (_, other_slot) = ordinary(&instance, 4, 78);
    assert_eq!(refusal(&instance, &good, &other_slot), Rejection::NoteBodyMismatch);

    // And the same again through the chain's payload hash rather than the
    // note body, which is how a relay swapping bytes would show up.
    let mut swapped = good_slot;
    swapped.output_data_hash = Fr::from(12345u64);
    assert_eq!(refusal(&instance, &good, &swapped), Rejection::NoteBodyMismatch);
}

/// Bytes that are not a section 3 plaintext at all, each refused by the check
/// that sees it first.
#[test]
fn malformed_plaintexts_are_refused_by_shape() {
    let mut bytes = Plaintext {
        slot: 0,
        kind: Kind::Ordinary,
        amount: 1,
        note_secret: Fr::from(9u64),
        owner_nf_key_hash: Fr::from(1u64),
        note_key_index: 0,
        pq_auth_key_hash: Fr::from(2u64),
    }
    .to_bytes();

    assert_eq!(Plaintext::from_bytes(&bytes[..127], 0), Err(Rejection::PlaintextLength));

    let mut wrong = bytes;
    wrong[0] ^= 1;
    assert_eq!(Plaintext::from_bytes(&wrong, 0), Err(Rejection::Magic));

    let mut wrong = bytes;
    wrong[4] = 2;
    assert_eq!(Plaintext::from_bytes(&wrong, 0), Err(Rejection::Version));

    // The slot in the plaintext must be the slot it arrived in.
    assert_eq!(Plaintext::from_bytes(&bytes, 1), Err(Rejection::Slot));

    // Reserved flag bits, and the one combination section 3 forbids outright.
    for flags in [0x0004u16, 0x8000, delivery::FLAG_DUMMY | delivery::FLAG_RECOVERY] {
        let mut wrong = bytes;
        wrong[6..8].copy_from_slice(&flags.to_be_bytes());
        assert_eq!(Plaintext::from_bytes(&wrong, 0), Err(Rejection::Flags), "flags {flags:#06x}");
    }

    // A zero note secret would make two notes with the same owner and amount
    // the same note.
    let mut wrong = bytes;
    wrong[24..56].copy_from_slice(&[0u8; 32]);
    assert_eq!(Plaintext::from_bytes(&wrong, 0), Err(Rejection::NoteSecretZero));

    // And one at or above the modulus is not a field element.
    bytes[24..56].copy_from_slice(&[0xffu8; 32]);
    assert_eq!(Plaintext::from_bytes(&bytes, 0), Err(Rejection::NoteSecretNotCanonical));
}

/// A dummy names the fixed constant rather than this wallet's owner hash, so
/// it is owned by nobody -- but its index is this wallet's and is consumed.
#[test]
fn a_dummy_carries_no_balance_and_still_consumes_its_index() {
    let instance = instance();
    let plaintext = Plaintext {
        slot: 2,
        kind: Kind::Dummy,
        amount: 0,
        note_secret: Fr::from(0xd00du64),
        owner_nf_key_hash: dummy_owner_nf_hash(),
        note_key_index: 9,
        pq_auth_key_hash: instance.pq_auth_key_hash(9).expect("a key hash"),
    };
    let slot = chain_slot(&instance, &plaintext);
    let note = import(&instance, &plaintext, &slot).expect("import").expect("a valid dummy");
    assert_eq!(note.kind, Kind::Dummy);
    assert_eq!(note.amount, 0);
    assert!(!note.spendable, "a dummy was imported as spendable");
    assert_eq!(note.note_key_index, 9);

    // A dummy that names the wallet's own owner hash instead of the constant
    // is not a dummy, and is refused rather than quietly imported.
    let mut pretending = plaintext;
    pretending.owner_nf_key_hash = instance.owner_nf_key_hash(9).expect("an owner hash");
    assert_eq!(
        refusal(&instance, &pretending, &chain_slot(&instance, &pretending)),
        Rejection::OwnerNfKeyHash
    );

    // And a dummy carrying value is refused: the whole point is that it has
    // none.
    let mut funded = plaintext;
    funded.amount = 1;
    assert_eq!(refusal(&instance, &funded, &chain_slot(&instance, &funded)), Rejection::Amount);
}
