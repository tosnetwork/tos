/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! From notes a wallet holds to a transact the pool would accept and the
//! recipient would recognise: assembly checked against the circuit's own
//! relations, the signatures, the replay model and the scan, without a chain
//! and without a proving key.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use ark_ff::{AdditiveGroup, Zero};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use fips204::ml_dsa_44::PublicKey;
use fips204::traits::{SerDes as _, Verifier as _};
use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::{notes, wire};
use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
use shielded_pool_wallet::descriptor::Descriptor;
use shielded_pool_wallet::keys::{fr_be32, PoolInstance};
use shielded_pool_wallet::ledger::{Event, Ledger, Payout, Transact};
use shielded_pool_wallet::plan::{plan, Candidate, Plan, PoolTerms, RecipientKeys, Request};
use shielded_pool_wallet::scan::{self, Recovered};
use shielded_pool_wallet::spend::{assemble, nullifier_witnesses, Assembled, Terms};
use shielded_pool_wallet::SIGNATURE_CONTEXT;

const TOS: u128 = 1_000_000_000;
const FEE: u128 = 10_000_000;
const CHARGE: u128 = 1_466_669;
const NOW: u32 = 1_800_000_000;

fn domain() -> Fr {
    Fr::from(0x5e5e_0001u64)
}

fn sender() -> PoolInstance {
    PoolInstance::new(&[0x51; 32], domain())
}

fn recipient() -> PoolInstance {
    PoolInstance::new(&[0x52; 32], domain())
}

fn terms() -> PoolTerms {
    PoolTerms { denominations: vec![TOS], withdrawal_fee: FEE }
}

/// Deterministic non-zero field elements, distinct per call.
fn fresh() -> impl FnMut() -> shielded_pool_wallet::error::Result<Fr> {
    let mut counter = 0u64;
    move || {
        counter += 1;
        Ok(Fr::from(0xf00d_0000u64 + counter))
    }
}

fn indices_from(start: u64) -> impl FnMut() -> shielded_pool_wallet::error::Result<u64> {
    let mut next = start;
    move || {
        let index = next;
        next += 1;
        Ok(index)
    }
}

/// A deposit of `amount` to `instance` at `index`, as the chain would carry it.
fn deposit(instance: &PoolInstance, amount: u128, index: u64) -> Event {
    let plaintext = Plaintext {
        slot: 0,
        kind: Kind::Ordinary,
        amount,
        note_secret: Fr::from(0x5ec2e7u64 + index),
        owner_nf_key_hash: instance.owner_nf_key_hash(index).expect("owner hash"),
        note_key_index: index,
        pq_auth_key_hash: instance.pq_auth_key_hash(index).expect("pq hash"),
    };
    let output_data = delivery::seal(
        &instance.mlkem_encapsulation_key().expect("key"),
        instance.execution_domain(),
        &plaintext,
    )
    .expect("seal");
    Event::Deposit {
        amount,
        owner_commitment: notes::owner_commitment(
            plaintext.owner_nf_key_hash,
            plaintext.pq_auth_key_hash,
            plaintext.note_secret,
        ),
        output_data,
    }
}

/// Scans what the ledger carried since the last drain into `recovered`.
fn scan_into(ledger: &mut Ledger, instance: &PoolInstance, recovered: &mut Recovered) {
    let outputs = ledger.take_outputs();
    recovered.merge(scan::recover_indexed(instance, &outputs).expect("scan"));
    recovered.reconcile_spent(instance, ledger.published_nullifiers()).expect("reconcile");
}

fn candidates(recovered: &Recovered) -> Vec<Candidate> {
    recovered
        .spendable_with_leaves()
        .into_iter()
        .map(|(note, leaf)| Candidate { note: *note, leaf_index: leaf.expect("a leaf") })
        .collect()
}

/// The event the chain would commit for an assembled spend.
fn committed(assembled: &Assembled, plan: &Plan, payout: Option<Payout>) -> Event {
    Event::Transact(Box::new(Transact {
        intent_digest: assembled.intent_digest(),
        nullifiers: assembled.nullifiers(),
        note_bodies: [
            assembled.public.note_body_0,
            assembled.public.note_body_1,
            assembled.public.note_body_2,
        ],
        payloads: assembled.payloads.clone(),
        public_amount_out: plan.public_amount_out,
        withdrawal_fee: plan.withdrawal_fee,
        recovery_owner_commitment: assembled.recovery_owner_commitment,
        recovery_payload: assembled.recovery_payload.clone(),
        payout,
    }))
}

fn satisfied(assembled: &Assembled) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    ShieldedTransactionCircuit::new(assembled.public, assembled.witness.clone())
        .generate_constraints(cs.clone())
        .expect("synthesise");
    cs.is_satisfied().expect("satisfaction")
}

fn signatures_verify(assembled: &Assembled, digest: Fr) -> bool {
    assembled.input_keys.iter().zip(&assembled.signatures).all(|(key, signature)| {
        PublicKey::try_from_bytes(*key).expect("a public key").verify(
            &fr_be32(digest),
            signature,
            SIGNATURE_CONTEXT,
        )
    })
}

fn assembled_for(instance: &PoolInstance, ledger: &Ledger, plan: &Plan, nonce: u64) -> Assembled {
    let terms = Terms {
        anchor_root: ledger.checkpoint().commitment_root,
        valid_until: NOW + 600,
        intent_nonce: Fr::from(nonce),
    };
    assemble(instance, plan, ledger.frontier(), &terms, &mut fresh()).expect("assemble")
}

#[test]
fn a_transfer_is_satisfiable_signed_committed_and_found_by_both_sides() {
    let (alice, bob) = (sender(), recipient());
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&alice, 2 * TOS, 0), CHARGE).expect("deposit");
    ledger.apply(&deposit(&alice, 5 * TOS, 1), CHARGE).expect("deposit");
    let mut alice_notes = Recovered::default();
    scan_into(&mut ledger, &alice, &mut alice_notes);
    assert_eq!(alice_notes.balance(), 7 * TOS);

    let to = Descriptor::issue(&bob, 3).expect("bob's descriptor");
    let request = Request::Transfer { to: Box::new(RecipientKeys::of(&to)), amount: 3 * TOS / 2 };
    let plan =
        plan(&terms(), &candidates(&alice_notes), &request, &mut indices_from(10)).expect("plan");
    let assembled = assembled_for(&alice, &ledger, &plan, 0x77);

    // The circuit's own relations hold over what was assembled, and both
    // slots signed the intent with the key of their index.
    assert!(satisfied(&assembled));
    assert!(signatures_verify(&assembled, assembled.intent_digest()));
    assert!(!signatures_verify(&assembled, assembled.intent_digest() + Fr::from(1u64)));
    assert_eq!(assembled.input_indices, [0, 12], "the note's index and the phantom's");
    // Section 4.5: the empty slot's nullifier is the phantom one.
    assert_eq!(
        assembled.public.nullifier_1,
        notes::phantom_nullifier(
            Fr::from(0x77u64),
            Fr::from(1u64),
            alice.pq_auth_key_hash(12).expect("pq hash")
        )
    );
    assert!(assembled.recovery_payload.is_none());
    assert!(assembled.recovery_owner_commitment.is_zero());
    assert_eq!(assembled.public.public_recipient_hash, Fr::ZERO);

    // The nullifier witnesses, against the tree as it stands, insert cleanly
    // in the contract's order; the ledger applies the same two insertions.
    let witnesses =
        nullifier_witnesses(ledger.nullifier_state(), assembled.nullifiers()).expect("witnesses");
    assert_ne!(witnesses[0].low_index, u32::MAX);
    let before = ledger.nullifier_state().clone();
    ledger.apply(&committed(&assembled, &plan, None), CHARGE).expect("the pool accepts");
    assert_ne!(ledger.nullifier_state().root(), before.root());
    assert_eq!(ledger.accepted_intents(), &[assembled.intent_digest()]);
    assert!(ledger.published_nullifiers().contains(&assembled.public.nullifier_0));

    // Bob finds exactly one note, at his descriptor's index, for the amount.
    let mut bob_notes = Recovered::default();
    let outputs = ledger.take_outputs();
    bob_notes.merge(scan::recover_indexed(&bob, &outputs).expect("scan"));
    assert_eq!(bob_notes.notes.len(), 1);
    assert_eq!(bob_notes.notes[0].amount, 3 * TOS / 2);
    assert_eq!(bob_notes.notes[0].note_key_index, 3);
    assert!(bob_notes.notes[0].spendable);
    assert_eq!(bob_notes.leaves[0], Some(2), "the first output slot's leaf");

    // Alice finds her change and recognises her dummy, and her input is spent.
    alice_notes.merge(scan::recover_indexed(&alice, &outputs).expect("scan"));
    alice_notes.reconcile_spent(&alice, ledger.published_nullifiers()).expect("reconcile");
    let change = alice_notes.notes.iter().find(|n| n.note_key_index == 10).expect("change");
    assert_eq!((change.kind, change.amount, change.spendable), (Kind::Ordinary, TOS / 2, true));
    let dummy = alice_notes.notes.iter().find(|n| n.note_key_index == 11).expect("dummy");
    assert_eq!((dummy.kind, dummy.amount, dummy.spendable), (Kind::Dummy, 0, false));
    assert!(alice_notes.notes.iter().any(|n| n.note_key_index == 0 && n.spent));
    assert_eq!(alice_notes.balance(), 5 * TOS + TOS / 2);
    assert_eq!(alice_notes.next_note_key_index, 12, "past the dummy; the phantom left no note");
    assert!(!alice_notes.notes.iter().any(|n| n.note_key_index == 3), "Bob's note is not hers");
}

#[test]
fn a_two_input_transfer_without_change_is_satisfiable_and_spends_both() {
    let (alice, bob) = (sender(), recipient());
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&alice, TOS, 0), CHARGE).expect("deposit");
    ledger.apply(&deposit(&alice, 2 * TOS, 1), CHARGE).expect("deposit");
    let mut alice_notes = Recovered::default();
    scan_into(&mut ledger, &alice, &mut alice_notes);

    let to = Descriptor::issue(&bob, 0).expect("descriptor");
    let request = Request::Transfer { to: Box::new(RecipientKeys::of(&to)), amount: 3 * TOS };
    let plan =
        plan(&terms(), &candidates(&alice_notes), &request, &mut indices_from(10)).expect("plan");
    assert_eq!(plan.input_leaves(), vec![0, 1]);
    let assembled = assembled_for(&alice, &ledger, &plan, 0x78);
    assert!(satisfied(&assembled));
    assert_eq!(assembled.input_indices, [0, 1]);
    ledger.apply(&committed(&assembled, &plan, None), CHARGE).expect("accepted");
    scan_into(&mut ledger, &alice, &mut alice_notes);
    assert_eq!(alice_notes.balance(), 0);
    assert_eq!(alice_notes.notes.iter().filter(|n| n.kind == Kind::Dummy).count(), 2);
}

#[test]
fn a_withdrawal_that_bounces_mints_a_recovery_note_the_wallet_can_spend() {
    let (alice, bob) = (sender(), recipient());
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&alice, 3 * TOS / 2, 0), CHARGE).expect("deposit");
    let mut alice_notes = Recovered::default();
    scan_into(&mut ledger, &alice, &mut alice_notes);

    let recipient_account = [0xab; 32];
    let request = Request::Withdraw { amount: TOS, recipient_account };
    let plan =
        plan(&terms(), &candidates(&alice_notes), &request, &mut indices_from(20)).expect("plan");
    let assembled = assembled_for(&alice, &ledger, &plan, 0x79);
    assert!(satisfied(&assembled));
    assert!(signatures_verify(&assembled, assembled.intent_digest()));
    assert_eq!(
        assembled.public.public_recipient_hash,
        wire::public_recipient_hash(&recipient_account)
    );
    assert_eq!(assembled.public.public_amount_out, Fr::from(TOS));
    assert_eq!(assembled.public.withdrawal_fee, Fr::from(FEE));
    let recovery_payload = assembled.recovery_payload.clone().expect("a recovery template");
    assert_eq!(
        assembled.public.recovery_template_hash,
        wire::recovery_template_hash(
            assembled.recovery_owner_commitment,
            wire::output_data_hash(&recovery_payload)
        )
    );

    // The pool accepts, pays out, and the payout comes back.
    let payout = Payout { recipient: "0:recipient".into(), value: TOS, body_hash: [0x77; 32] };
    ledger.apply(&committed(&assembled, &plan, Some(payout.clone())), CHARGE).expect("accepted");
    scan_into(&mut ledger, &alice, &mut alice_notes);
    assert_eq!(alice_notes.balance(), TOS / 2 - FEE, "the change, before the bounce");
    let template = alice_notes.notes.iter().find(|n| n.kind == Kind::Recovery).expect("template");
    assert_eq!((template.amount, template.spendable, template.note_key_index), (0, false, 23));

    let bounce = Event::Bounce {
        original_body_hash: payout.body_hash,
        sender: payout.recipient.clone(),
        value: TOS - 3_000_000,
    };
    ledger.apply(&bounce, CHARGE).expect("the bounce");
    scan_into(&mut ledger, &alice, &mut alice_notes);
    let recovered = alice_notes
        .notes
        .iter()
        .find(|n| n.kind == Kind::Recovery && n.spendable)
        .expect("the minted recovery note");
    assert_eq!(recovered.amount, TOS - 3_000_000 - CHARGE);
    assert_eq!(recovered.output_data_hash, wire::output_data_hash(&recovery_payload));
    assert_eq!(alice_notes.balance(), TOS / 2 - FEE + TOS - 3_000_000 - CHARGE);

    // And the recovered note is an input like any other.
    let to = Descriptor::issue(&bob, 1).expect("descriptor");
    let request = Request::Transfer {
        to: Box::new(RecipientKeys::of(&to)),
        amount: TOS - 3_000_000 - CHARGE,
    };
    let second = shielded_pool_wallet::plan::plan(
        &terms(),
        &candidates(&alice_notes),
        &request,
        &mut indices_from(30),
    )
    .expect("plan");
    assert_eq!(second.input_leaves(), vec![4], "the recovery note's leaf, after three outputs");
    let assembled = assembled_for(&alice, &ledger, &second, 0x7a);
    assert!(satisfied(&assembled));
    ledger.apply(&committed(&assembled, &second, None), CHARGE).expect("accepted");
    let outputs = ledger.take_outputs();
    alice_notes.merge(scan::recover_indexed(&alice, &outputs).expect("scan"));
    alice_notes.reconcile_spent(&alice, ledger.published_nullifiers()).expect("reconcile");
    assert_eq!(alice_notes.balance(), TOS / 2 - FEE);
    let mut bob_notes = Recovered::default();
    bob_notes.merge(scan::recover_indexed(&bob, &outputs).expect("scan"));
    assert_eq!(bob_notes.received(), TOS - 3_000_000 - CHARGE);
}

#[test]
fn assembly_refuses_what_the_contract_or_the_scan_would() {
    let alice = sender();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&alice, 2 * TOS, 0), CHARGE).expect("deposit");
    let mut alice_notes = Recovered::default();
    scan_into(&mut ledger, &alice, &mut alice_notes);
    let to = Descriptor::issue(&recipient(), 0).expect("descriptor");
    let request = Request::Transfer { to: Box::new(RecipientKeys::of(&to)), amount: TOS };
    let plan =
        plan(&terms(), &candidates(&alice_notes), &request, &mut indices_from(10)).expect("plan");

    // A zero nonce.
    let terms = Terms {
        anchor_root: ledger.checkpoint().commitment_root,
        valid_until: NOW,
        intent_nonce: Fr::ZERO,
    };
    assert!(assemble(&alice, &plan, ledger.frontier(), &terms, &mut fresh()).is_err());

    // A plan whose accounting was tampered with after planning.
    let mut broken = plan.clone();
    broken.withdrawal_fee = 1;
    let terms = Terms { intent_nonce: Fr::from(5u64), ..terms };
    assert!(assemble(&alice, &broken, ledger.frontier(), &terms, &mut fresh()).is_err());

    // Randomness that comes back zero is refused, never sealed.
    let mut zeros = || Ok(Fr::ZERO);
    assert!(assemble(&alice, &plan, ledger.frontier(), &terms, &mut zeros).is_err());

    // A dummy whose plaintext claims to be an ordinary note is refused at the
    // scan: the contract does not look inside payloads, the wallet does.
    let assembled = assemble(&alice, &plan, ledger.frontier(), &terms, &mut fresh()).expect("ok");
    let dummy_secret = assembled.witness.outputs[2].note_secret;
    let forged = Plaintext {
        slot: 2,
        kind: Kind::Ordinary,
        amount: 0,
        note_secret: dummy_secret,
        owner_nf_key_hash: alice.owner_nf_key_hash(11).expect("hash"),
        note_key_index: 11,
        pq_auth_key_hash: alice.pq_auth_key_hash(11).expect("hash"),
    };
    let forged_payload = delivery::seal(
        &alice.mlkem_encapsulation_key().expect("key"),
        alice.execution_domain(),
        &forged,
    )
    .expect("seal");
    let opened = delivery::open(&alice, &forged_payload, 2).expect("opens: it is hers");
    let slot = shielded_pool_wallet::import::ChainSlot {
        output_data_hash: wire::output_data_hash(&forged_payload),
        note_body: assembled.public.note_body_2,
        recovered: None,
    };
    let imported = shielded_pool_wallet::import::import(&alice, &opened, &slot).expect("no error");
    assert!(imported.is_err(), "an ordinary note of zero at a dummy's slot imports nothing");
}
