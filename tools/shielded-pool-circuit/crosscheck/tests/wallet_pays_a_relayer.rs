/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! A relayed transfer pays the relayer inside the spend, and the pool agrees.
//!
//! A relayer funds the message and is paid by a note to the descriptor its
//! quote named, in output slot 2. The planner takes the fee from the sender's
//! notes on top of the amount; the contract sees an ordinary three-output
//! transfer and conserves value as always. Three wallets then scan the chain:
//! the recipient finds the amount, the relayer finds its fee at the quoted
//! index as an ordinary spendable note, the sender finds the change. The
//! relayer's note is real value: it spends it in turn, and the pool accepts.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use chain_block::Cell;
use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::{groth16, notes};
use shielded_pool_circuit_crosscheck::pool::{dec, development_vk_bytes, Pool, DENOMINATION};
use shielded_pool_circuit_crosscheck::transact::{Anchor, Transact};
use shielded_pool_circuit_crosscheck::wire::byte_chain;
use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
use shielded_pool_wallet::descriptor::Descriptor;
use shielded_pool_wallet::keys::PoolInstance;
use shielded_pool_wallet::ledger::{Event, Ledger, Transact as Committed};
use shielded_pool_wallet::plan::{
    plan, Candidate, Fee, Plan, PlannedOutput, PoolTerms, RecipientKeys, Request,
};
use shielded_pool_wallet::scan::{self, Recovered};
use shielded_pool_wallet::spend::{assemble, nullifier_witnesses, Assembled, Terms};
use support::execution_domain;

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;
const ALICE: [u8; 32] = [0xa1; 32];
const BOB: [u8; 32] = [0xb0; 32];
const RELAYER: [u8; 32] = [0xee; 32];
/// The index the relayer's quote names.
const QUOTED_INDEX: u64 = 9;

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

fn terms() -> PoolTerms {
    PoolTerms { denominations: vec![u128::from(DENOMINATION)], withdrawal_fee: 1 }
}

fn deposit(pool: &mut Pool, ledger: &mut Ledger, wallet: &PoolInstance, index: u64) {
    let plaintext = Plaintext {
        slot: 0,
        kind: Kind::Ordinary,
        amount: u128::from(DENOMINATION),
        note_secret: Fr::from(0x5ec2e7u64 + index),
        owner_nf_key_hash: wallet.owner_nf_key_hash(index).expect("owner hash"),
        note_key_index: index,
        pq_auth_key_hash: wallet.pq_auth_key_hash(index).expect("pq hash"),
    };
    let output_data = delivery::seal(
        &wallet.mlkem_encapsulation_key().expect("key"),
        wallet.execution_domain(),
        &plaintext,
    )
    .expect("seal");
    let owner_commitment = notes::owner_commitment(
        plaintext.owner_nf_key_hash,
        plaintext.pq_auth_key_hash,
        plaintext.note_secret,
    );
    pool.send(
        DENOMINATION + COMPUTE_FEE,
        Pool::deposit_body(
            DENOMINATION,
            owner_commitment,
            byte_chain(&output_data).expect("chain"),
        )
        .expect("deposit body"),
    )
    .expect("deposit")
    .expect_success();
    ledger
        .apply(
            &Event::Deposit { amount: u128::from(DENOMINATION), owner_commitment, output_data },
            charge(pool),
        )
        .expect("the ledger takes the deposit");
}

fn charge(pool: &Pool) -> u128 {
    pool.get("recovery_charge").expect("the quoted recovery charge").parse().expect("a number")
}

fn scan_into(ledger: &mut Ledger, wallet: &PoolInstance, recovered: &mut Recovered) {
    let outputs = ledger.take_outputs();
    recovered.merge(scan::recover_indexed(wallet, &outputs).expect("scan"));
    recovered.reconcile_spent(wallet, ledger.published_nullifiers()).expect("reconcile");
}

fn candidates(recovered: &Recovered) -> Vec<Candidate> {
    recovered
        .spendable_with_leaves()
        .into_iter()
        .map(|(note, leaf)| Candidate { note: *note, leaf_index: leaf.expect("a leaf") })
        .collect()
}

struct Proven {
    assembled: Assembled,
    proof: groth16::CanonicalProof,
    witnesses: [shielded_pool_circuit::imt::Witness; 2],
}

fn prove(ledger: &Ledger, assembled: Assembled, nonce: u8) -> Proven {
    let keys = groth16::development_keys(ShieldedTransactionCircuit::blank(assembled.public))
        .expect("development keys");
    assert_eq!(
        groth16::canonical_verifying_key(&keys.verifying).expect("vk bytes").bytes,
        development_vk_bytes().expect("the fixture verifying key"),
        "the prover's verifying key is not the pool's"
    );
    let proof = groth16::prove(
        &keys,
        ShieldedTransactionCircuit::new(assembled.public, assembled.witness.clone()),
        nonce,
    )
    .expect("prove");
    let proof = groth16::CanonicalProof::from_proof(&proof).expect("canonical proof");
    let witnesses =
        nullifier_witnesses(ledger.nullifier_state(), assembled.nullifiers()).expect("witnesses");
    Proven { assembled, proof, witnesses }
}

fn body(proven: &Proven, anchor_root: Fr, valid_until: u32, plan: &Plan) -> Cell {
    let Proven { assembled, proof, witnesses } = proven;
    Transact {
        public: &assembled.public,
        proof,
        anchor_root,
        anchor: Anchor::Current,
        valid_until,
        output_payloads: &assembled.payloads,
        keys: [&assembled.input_keys[0], &assembled.input_keys[1]],
        signatures: &assembled.signatures,
        witnesses,
        public_amount_out: 0,
        withdrawal_fee: 0,
        recipient: None,
        recovery_owner_commitment: assembled.recovery_owner_commitment,
        recovery_payload: assembled.recovery_payload.clone(),
    }
    .body()
    .expect("a transact body")
}

fn committed(proven: &Proven) -> Event {
    let assembled = &proven.assembled;
    Event::Transact(Box::new(Committed {
        intent_digest: assembled.intent_digest(),
        nullifiers: assembled.nullifiers(),
        note_bodies: [
            assembled.public.note_body_0,
            assembled.public.note_body_1,
            assembled.public.note_body_2,
        ],
        payloads: assembled.payloads.clone(),
        public_amount_out: 0,
        withdrawal_fee: 0,
        recovery_owner_commitment: assembled.recovery_owner_commitment,
        recovery_payload: assembled.recovery_payload.clone(),
        payout: None,
    }))
}

/// Plans, assembles, proves and sends one transfer, and applies it to the
/// ledger once the pool accepted it.
fn transfer(
    pool: &mut Pool,
    ledger: &mut Ledger,
    sender: &PoolInstance,
    notes: &Recovered,
    request: &Request,
    first_index: u64,
    nonce: u8,
) -> Plan {
    let plan = plan(&terms(), &candidates(notes), request, &mut indices_from(first_index))
        .expect("a plan");
    let anchor_root = ledger.checkpoint().commitment_root;
    let valid_until = pool.bc.now() + 600;
    let assembled = assemble(
        sender,
        &plan,
        ledger.frontier(),
        &Terms { anchor_root, valid_until, intent_nonce: Fr::from(0x3000u64 + u64::from(nonce)) },
        &mut fresh(),
    )
    .expect("assemble");
    let proven = prove(ledger, assembled, nonce);
    let (exit, _, sent) = pool
        .run_counting_sends(COMPUTE_FEE * 4, body(&proven, anchor_root, valid_until, &plan))
        .expect("the transfer");
    assert_eq!(exit, 0, "the pool accepts the transfer");
    assert_eq!(sent, 0, "a transfer sends nothing");
    ledger.apply(&committed(&proven), charge(pool)).expect("the transfer");
    assert_eq!(
        pool.get("commitment_root").expect("root"),
        dec(ledger.checkpoint().commitment_root),
        "the ledger's tree is the contract's"
    );
    assert_eq!(ledger.accepted_intents().last(), Some(&proven.assembled.intent_digest()));
    plan
}

#[test]
fn a_relayed_transfer_pays_the_relayer_a_note_it_finds_and_spends() {
    let mut pool = Pool::deploy().expect("deploy the pool");
    let domain = execution_domain(&pool);
    let alice = PoolInstance::new(&ALICE, domain);
    let bob = PoolInstance::new(&BOB, domain);
    let relayer = PoolInstance::new(&RELAYER, domain);
    let mut ledger = Ledger::genesis();
    let mut alice_notes = Recovered::default();
    let mut bob_notes = Recovered::default();
    let mut relayer_notes = Recovered::default();

    deposit(&mut pool, &mut ledger, &alice, 0);
    deposit(&mut pool, &mut ledger, &alice, 1);
    scan_into(&mut ledger, &alice, &mut alice_notes);
    assert_eq!(alice_notes.balance(), 2 * u128::from(DENOMINATION));

    // --- the relayed transfer: amount to Bob, fee to the quoted index -----
    let amount = u128::from(DENOMINATION) / 2;
    let fee = u128::from(DENOMINATION) / 10;
    let to_bob = Descriptor::issue(&bob, 7).expect("bob's descriptor");
    let quoted = Descriptor::issue(&relayer, QUOTED_INDEX).expect("the relayer's descriptor");
    let request = Request::Transfer {
        to: Box::new(RecipientKeys::of(&to_bob)),
        amount,
        fee: Some(Fee { to: Box::new(RecipientKeys::of(&quoted)), amount: fee }),
    };
    let plan = transfer(&mut pool, &mut ledger, &alice, &alice_notes, &request, 10, 1);
    assert_eq!(plan.input_leaves(), vec![0], "one note covers the amount plus the fee");
    assert_eq!(
        plan.outputs[2],
        PlannedOutput::Recipient { to: Box::new(RecipientKeys::of(&quoted)), amount: fee },
        "the fee note is the third output"
    );
    assert_eq!(plan.own_indices(), vec![10, 11], "change and the phantom; the fee slot is theirs");

    // Three wallets scan the same outputs and each finds exactly its own.
    let outputs = ledger.take_outputs();
    bob_notes.merge(scan::recover_indexed(&bob, &outputs).expect("scan"));
    relayer_notes.merge(scan::recover_indexed(&relayer, &outputs).expect("scan"));
    alice_notes.merge(scan::recover_indexed(&alice, &outputs).expect("scan"));
    alice_notes.reconcile_spent(&alice, ledger.published_nullifiers()).expect("reconcile");
    assert_eq!(bob_notes.notes.len(), 1);
    assert_eq!((bob_notes.notes[0].amount, bob_notes.notes[0].note_key_index), (amount, 7));
    assert_eq!(relayer_notes.notes.len(), 1, "the relayer finds one note: its fee");
    let fee_note = &relayer_notes.notes[0];
    assert_eq!(fee_note.amount, fee);
    assert_eq!(fee_note.note_key_index, QUOTED_INDEX, "at the index the quote named");
    assert_eq!(fee_note.kind, Kind::Ordinary);
    assert!(fee_note.spendable && !fee_note.spent);
    assert_eq!(relayer_notes.balance(), fee);
    let change = u128::from(DENOMINATION) - amount - fee;
    assert_eq!(
        alice_notes.balance(),
        u128::from(DENOMINATION) + change,
        "the untouched note and the change, less the amount and the fee"
    );

    // --- the fee is real value: the relayer spends it -----------------------
    let to_bob_again = Descriptor::issue(&bob, 8).expect("bob's second descriptor");
    let payout = Request::Transfer {
        to: Box::new(RecipientKeys::of(&to_bob_again)),
        amount: fee,
        fee: None,
    };
    let spent = transfer(&mut pool, &mut ledger, &relayer, &relayer_notes, &payout, 20, 2);
    assert_eq!(spent.input_leaves(), vec![4], "the fee note's leaf: two deposits, three outputs");
    let outputs = ledger.take_outputs();
    bob_notes.merge(scan::recover_indexed(&bob, &outputs).expect("scan"));
    relayer_notes.merge(scan::recover_indexed(&relayer, &outputs).expect("scan"));
    relayer_notes.reconcile_spent(&relayer, ledger.published_nullifiers()).expect("reconcile");
    assert_eq!(bob_notes.balance(), amount + fee, "Bob holds the amount and the relayer's fee");
    assert_eq!(relayer_notes.balance(), 0, "the relayer spent its fee note");
    assert!(relayer_notes.notes.iter().any(|note| note.spent));
}
