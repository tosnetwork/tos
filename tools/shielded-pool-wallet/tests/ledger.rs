/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The replay model: every state change the contract can commit, applied in
//! order, and every history it cannot have committed refused.
//!
//! Agreement with the real contract is held elsewhere, by driving the pool in
//! the sandbox and comparing checkpoints; these tests pin the rules one at a
//! time so a broken rule names itself.

use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::tree::Frontier;
use shielded_pool_circuit::{imt, notes, wire};
use shielded_pool_wallet::delivery::{self, Kind, Plaintext, RECOVERY_PAYLOAD_SLOT};
use shielded_pool_wallet::keys::PoolInstance;
use shielded_pool_wallet::ledger::{Event, Ledger, Payout, Transact};
use shielded_pool_wallet::scan;

const SEED: [u8; 32] = [0x51; 32];
const CHARGE: u128 = 1_466_669;
const TOS: u128 = 1_000_000_000;

fn domain() -> Fr {
    Fr::from(0x4c45_4447_4552u64)
}

fn instance() -> PoolInstance {
    PoolInstance::new(&SEED, domain())
}

fn plaintext(instance: &PoolInstance, slot: u8, kind: Kind, amount: u128, index: u64) -> Plaintext {
    Plaintext {
        slot,
        kind,
        amount,
        note_secret: Fr::from(0x5ec2e7u64 + index * 7 + u64::from(slot)),
        owner_nf_key_hash: match kind {
            Kind::Dummy => shielded_pool_circuit::domains::dummy_owner_nf_hash(),
            _ => instance.owner_nf_key_hash(index).expect("owner hash"),
        },
        note_key_index: index,
        pq_auth_key_hash: instance.pq_auth_key_hash(index).expect("key hash"),
    }
}

fn seal(instance: &PoolInstance, plaintext: &Plaintext) -> Vec<u8> {
    delivery::seal(
        &instance.mlkem_encapsulation_key().expect("key"),
        instance.execution_domain(),
        plaintext,
    )
    .expect("seal")
}

fn owner(plaintext: &Plaintext) -> Fr {
    notes::owner_commitment(
        plaintext.owner_nf_key_hash,
        plaintext.pq_auth_key_hash,
        plaintext.note_secret,
    )
}

/// A deposit of `amount` to this wallet's own `index`.
fn deposit(instance: &PoolInstance, amount: u128, index: u64) -> Event {
    let plaintext = plaintext(instance, 0, Kind::Ordinary, amount, index);
    Event::Deposit {
        amount,
        owner_commitment: owner(&plaintext),
        output_data: seal(instance, &plaintext),
    }
}

/// A transact with three outputs to this wallet and the given nullifiers.
fn transfer(instance: &PoolInstance, nullifiers: [u64; 2], first_index: u64) -> Event {
    let mut bodies = [Fr::from(0u64); 3];
    let mut payloads: [Vec<u8>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for slot in 0..3u8 {
        let index = first_index + u64::from(slot);
        let kind = if slot == 2 { Kind::Dummy } else { Kind::Ordinary };
        let amount = if kind == Kind::Dummy { 0 } else { TOS };
        let p = plaintext(instance, slot, kind, amount, index);
        let sealed = seal(instance, &p);
        bodies[usize::from(slot)] = notes::note_body_commitment(
            owner(&p),
            Fr::from(amount),
            wire::output_data_hash(&sealed),
        );
        payloads[usize::from(slot)] = sealed;
    }
    Event::Transact(Box::new(Transact {
        nullifiers: [Fr::from(nullifiers[0]), Fr::from(nullifiers[1])],
        note_bodies: bodies,
        payloads,
        public_amount_out: 0,
        withdrawal_fee: 0,
        recovery_owner_commitment: Fr::from(0u64),
        recovery_payload: None,
        payout: None,
    }))
}

struct Withdrawal {
    event: Event,
    payout: Payout,
    recovery: Plaintext,
}

fn withdrawal(instance: &PoolInstance, nullifiers: [u64; 2], first_index: u64) -> Withdrawal {
    let Event::Transact(base) = transfer(instance, nullifiers, first_index) else {
        unreachable!("transfer builds a transact")
    };
    let recovery = plaintext(instance, RECOVERY_PAYLOAD_SLOT, Kind::Recovery, 0, first_index + 3);
    let payout = Payout { recipient: "0:recipient".into(), value: TOS, body_hash: [0x77; 32] };
    Withdrawal {
        event: Event::Transact(Box::new(Transact {
            public_amount_out: TOS,
            withdrawal_fee: 10_000_000,
            recovery_owner_commitment: owner(&recovery),
            recovery_payload: Some(seal(instance, &recovery)),
            payout: Some(payout.clone()),
            ..*base
        })),
        payout,
        recovery,
    }
}

fn bounce(payout: &Payout, value: u128) -> Event {
    Event::Bounce { original_body_hash: payout.body_hash, sender: payout.recipient.clone(), value }
}

#[test]
fn genesis_is_the_contract_genesis() {
    let ledger = Ledger::genesis();
    let checkpoint = ledger.checkpoint();
    assert_eq!(checkpoint.commitment_root, Frontier::new().empty_root());
    assert_eq!(checkpoint.commitment_next_index, 0);
    assert_eq!(checkpoint.nullifier_root, imt::State::genesis().root());
    assert_eq!(checkpoint.nullifier_next_index, 1, "the head sentinel holds leaf 0");
    assert_eq!(checkpoint.native_liability, 0);
    assert_eq!(checkpoint.reserved_recovery_leaves, 0);
}

#[test]
fn a_deposit_appends_the_note_the_contract_computes() {
    let wallet = instance();
    let event = deposit(&wallet, TOS, 0);
    let mut ledger = Ledger::genesis();
    ledger.apply(&event, CHARGE).expect("deposit");

    let Event::Deposit { amount, owner_commitment, output_data } = &event else { unreachable!() };
    let body = notes::note_body_commitment(
        *owner_commitment,
        Fr::from(*amount),
        wire::output_data_hash(output_data),
    );
    let mut expected = Frontier::new();
    let (_, root) = expected.append(notes::note_commitment(body, Fr::from(0u64))).expect("append");
    let checkpoint = ledger.checkpoint();
    assert_eq!(checkpoint.commitment_root, root);
    assert_eq!(checkpoint.commitment_next_index, 1);
    assert_eq!(checkpoint.native_liability, TOS);
    assert_eq!(ledger.outputs()[0].leaf, Some(0));
}

#[test]
fn a_transfer_appends_three_leaves_dummies_included() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&wallet, TOS, 0), CHARGE).expect("deposit");
    ledger.apply(&transfer(&wallet, [11, 12], 1), CHARGE).expect("transfer");
    let checkpoint = ledger.checkpoint();
    assert_eq!(checkpoint.commitment_next_index, 4);
    assert_eq!(checkpoint.nullifier_next_index, 3);
    assert_eq!(checkpoint.native_liability, TOS, "a transfer moves nothing across the boundary");
    let leaves: Vec<_> = ledger.outputs().iter().map(|output| output.leaf).collect();
    assert_eq!(leaves, vec![Some(0), Some(1), Some(2), Some(3)]);
    assert_eq!(ledger.published_nullifiers().len(), 2);
}

#[test]
fn a_reused_nullifier_is_a_history_the_contract_refuses() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&transfer(&wallet, [11, 12], 0), CHARGE).expect("first");
    let before = ledger.checkpoint();
    assert!(ledger.apply(&transfer(&wallet, [13, 11], 3), CHARGE).is_err());
    assert_eq!(ledger.checkpoint(), before, "a refused event changed the ledger");
    assert!(ledger.apply(&transfer(&wallet, [14, 14], 3), CHARGE).is_err());
    assert_eq!(ledger.checkpoint(), before);
}

#[test]
fn a_withdrawal_reserves_a_leaf_and_its_template_is_no_leaf() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&wallet, 2 * TOS, 0), CHARGE).expect("deposit");
    let w = withdrawal(&wallet, [21, 22], 1);
    ledger.apply(&w.event, CHARGE).expect("withdrawal");
    let checkpoint = ledger.checkpoint();
    assert_eq!(checkpoint.commitment_next_index, 4);
    assert_eq!(checkpoint.reserved_recovery_leaves, 1);
    assert_eq!(checkpoint.native_liability, 2 * TOS - TOS - 10_000_000);
    let template = ledger.outputs().last().expect("template");
    assert_eq!(template.leaf, None);
    assert_eq!(template.observed.slot, RECOVERY_PAYLOAD_SLOT);
}

#[test]
fn a_payout_that_does_not_match_its_amount_is_refused() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&wallet, 2 * TOS, 0), CHARGE).expect("deposit");
    let mut w = withdrawal(&wallet, [21, 22], 1);
    if let Event::Transact(transact) = &mut w.event {
        transact.payout.as_mut().expect("payout").value = TOS - 1;
    }
    assert!(ledger.apply(&w.event, CHARGE).is_err());
    let mut w = withdrawal(&wallet, [21, 22], 1);
    if let Event::Transact(transact) = &mut w.event {
        transact.payout = None;
    }
    assert!(ledger.apply(&w.event, CHARGE).is_err(), "a withdrawal without its payout");
}

#[test]
fn a_bounce_mints_at_the_index_that_is_next_when_it_arrives() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&wallet, 2 * TOS, 0), CHARGE).expect("deposit");
    let w = withdrawal(&wallet, [21, 22], 1);
    ledger.apply(&w.event, CHARGE).expect("withdrawal");
    // Somebody else deposits before the payout comes back.
    ledger.apply(&deposit(&wallet, TOS, 9), CHARGE).expect("later deposit");
    let returned = TOS - 5_000_000;
    ledger.apply(&bounce(&w.payout, returned), CHARGE).expect("bounce");

    let checkpoint = ledger.checkpoint();
    assert_eq!(checkpoint.reserved_recovery_leaves, 0);
    assert_eq!(checkpoint.commitment_next_index, 6);
    let minted = ledger.outputs().last().expect("minted");
    assert_eq!(minted.leaf, Some(5), "the recovery took the index next at its arrival");
    assert_eq!(minted.observed.chain.recovered, Some(returned - CHARGE));
    assert_eq!(checkpoint.native_liability, 2 * TOS - TOS - 10_000_000 + TOS + (returned - CHARGE));

    // The scan sees the template and the minted note as one use of the index,
    // and only the minted note as money.
    let recovered = scan::recover_indexed(&wallet, &ledger.observed_since(0)).expect("scan");
    assert!(recovered.reused.is_empty(), "template and minted note counted as two uses");
    assert_eq!(recovered.next_note_key_index, w.recovery.note_key_index + 6);
    let recovery_note = recovered
        .notes
        .iter()
        .zip(recovered.leaves.iter())
        .find(|(note, _)| note.kind == Kind::Recovery && note.spendable)
        .expect("the recovery note was not imported");
    assert_eq!(recovery_note.0.amount, returned - CHARGE);
    assert_eq!(*recovery_note.1, Some(5));
}

#[test]
fn a_bounce_at_or_below_the_charge_mints_nothing_but_spends_the_reservation() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&wallet, 2 * TOS, 0), CHARGE).expect("deposit");
    let w = withdrawal(&wallet, [21, 22], 1);
    ledger.apply(&w.event, CHARGE).expect("withdrawal");
    let before = ledger.checkpoint();
    ledger.apply(&bounce(&w.payout, CHARGE), CHARGE).expect("dust bounce");
    let after = ledger.checkpoint();
    assert_eq!(after.commitment_next_index, before.commitment_next_index);
    assert_eq!(after.commitment_root, before.commitment_root);
    assert_eq!(after.reserved_recovery_leaves, 0);
    assert!(ledger.pending_recoveries()[0].consumed);
}

#[test]
fn a_bounce_that_is_not_one_of_the_pools_payouts_is_refused() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&wallet, 2 * TOS, 0), CHARGE).expect("deposit");
    let w = withdrawal(&wallet, [21, 22], 1);
    ledger.apply(&w.event, CHARGE).expect("withdrawal");

    let mut stranger = w.payout.clone();
    stranger.body_hash = [0x01; 32];
    assert!(ledger.apply(&bounce(&stranger, TOS), CHARGE).is_err(), "no such payout");

    let mut wrong_sender = w.payout.clone();
    wrong_sender.recipient = "0:somebody-else".into();
    assert!(ledger.apply(&bounce(&wrong_sender, TOS), CHARGE).is_err(), "wrong sender");

    assert!(ledger.apply(&bounce(&w.payout, TOS + 1), CHARGE).is_err(), "more than was paid");
    assert!(ledger.apply(&bounce(&w.payout, TOS), 0).is_err(), "a zero charge");

    ledger.apply(&bounce(&w.payout, TOS), CHARGE).expect("the real bounce");
    assert!(ledger.apply(&bounce(&w.payout, TOS), CHARGE).is_err(), "the same payout twice");
}

#[test]
fn the_scan_returns_each_note_with_its_leaf() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&wallet, TOS, 0), CHARGE).expect("deposit");
    ledger.apply(&transfer(&wallet, [11, 12], 1), CHARGE).expect("transfer");
    let recovered = scan::recover_indexed(&wallet, &ledger.observed_since(0)).expect("scan");
    assert_eq!(recovered.leaves, vec![Some(0), Some(1), Some(2), Some(3)]);
    assert_eq!(recovered.next_note_key_index, 4);
    let spendable: Vec<_> =
        recovered.spendable_with_leaves().into_iter().map(|(_, leaf)| leaf).collect();
    assert_eq!(spendable, vec![Some(0), Some(1), Some(2)], "the dummy is not spendable");
}

#[test]
fn incremental_scans_merge_to_the_same_result_as_one_scan() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&wallet, TOS, 0), CHARGE).expect("deposit");
    let mut first = scan::recover_indexed(&wallet, &ledger.observed_since(0)).expect("scan");
    let seen = ledger.outputs().len();
    ledger.apply(&transfer(&wallet, [11, 12], 1), CHARGE).expect("transfer");
    first.merge(scan::recover_indexed(&wallet, &ledger.observed_since(seen)).expect("scan"));
    let whole = scan::recover_indexed(&wallet, &ledger.observed_since(0)).expect("scan");
    assert_eq!(first.leaves, whole.leaves);
    assert_eq!(first.next_note_key_index, whole.next_note_key_index);
    assert_eq!(first.balance(), whole.balance());
    assert_eq!(first.notes, whole.notes);
}

#[test]
fn the_same_deposit_twice_is_one_spendable_note() {
    let wallet = instance();
    let event = deposit(&wallet, TOS, 0);
    let mut ledger = Ledger::genesis();
    ledger.apply(&event, CHARGE).expect("first");
    ledger.apply(&event, CHARGE).expect("the payer can send the same bytes again");
    let recovered = scan::recover_indexed(&wallet, &ledger.observed_since(0)).expect("scan");
    assert_eq!(recovered.notes.len(), 2, "both copies are imported");
    assert_eq!(recovered.duplicates(), 1);
    assert_eq!(recovered.balance(), TOS, "one nullifier spends both, so it is one note's money");
    assert!(recovered.reused.is_empty(), "the same note twice is not two uses of the index");
}

#[test]
fn two_payments_to_one_index_burn_it() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&wallet, TOS, 0), CHARGE).expect("first payment");
    // A second payer picks its own note secret.
    let mut second = plaintext(&wallet, 0, Kind::Ordinary, 2 * TOS, 0);
    second.note_secret = Fr::from(0xabcdefu64);
    let second = Event::Deposit {
        amount: 2 * TOS,
        owner_commitment: owner(&second),
        output_data: seal(&wallet, &second),
    };
    ledger.apply(&second, CHARGE).expect("second payment");
    let recovered = scan::recover_indexed(&wallet, &ledger.observed_since(0)).expect("scan");
    assert_eq!(recovered.balance(), 3 * TOS, "both payments are money");
    assert!(recovered.reused.contains(&0));
    assert!(!recovered.may_issue(0));
}

#[test]
fn a_restored_snapshot_is_the_ledger_it_was_taken_from() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&wallet, 2 * TOS, 0), CHARGE).expect("deposit");
    let w = withdrawal(&wallet, [21, 22], 1);
    ledger.apply(&w.event, CHARGE).expect("withdrawal");
    ledger.apply(&transfer(&wallet, [31, 32], 5), CHARGE).expect("transfer");

    let restored = Ledger::restore(ledger.snapshot()).expect("restore");
    assert_eq!(restored.checkpoint(), ledger.checkpoint());
    assert_eq!(restored.snapshot(), ledger.snapshot());
    assert!(restored.outputs().is_empty(), "a snapshot carries no outputs");

    // Continuing from the snapshot reaches the same state as never stopping.
    let mut continued = restored;
    continued.apply(&bounce(&w.payout, TOS), CHARGE).expect("bounce after restore");
    ledger.apply(&bounce(&w.payout, TOS), CHARGE).expect("bounce");
    assert_eq!(continued.checkpoint(), ledger.checkpoint());
    assert_eq!(continued.outputs().len(), 1, "only the output applied since the restore");

    let mut broken = ledger.snapshot();
    broken.nullifiers.pop();
    assert!(Ledger::restore(broken).is_err(), "a snapshot missing a nullifier");
    let mut broken = ledger.snapshot();
    broken.nullifier_tree.remove(0);
    assert!(Ledger::restore(broken).is_err(), "a snapshot without the sentinel");
}

#[test]
fn draining_outputs_leaves_the_ledger_and_scans_only_what_is_new() {
    let wallet = instance();
    let mut ledger = Ledger::genesis();
    ledger.apply(&deposit(&wallet, TOS, 0), CHARGE).expect("deposit");
    let first = ledger.take_outputs();
    assert_eq!(first.len(), 1);
    assert!(ledger.outputs().is_empty());
    ledger.apply(&transfer(&wallet, [11, 12], 1), CHARGE).expect("transfer");
    let second = ledger.take_outputs();
    assert_eq!(second.len(), 3);
    assert_eq!(second[0].1, Some(1), "the leaf indices continue across a drain");
    let mut recovered = scan::recover_indexed(&wallet, &first).expect("scan");
    recovered.merge(scan::recover_indexed(&wallet, &second).expect("scan"));
    assert_eq!(recovered.leaves, vec![Some(0), Some(1), Some(2), Some(3)]);
}
