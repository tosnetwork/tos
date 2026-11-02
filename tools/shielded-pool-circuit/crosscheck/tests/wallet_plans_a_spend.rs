/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The wallet's planner and assembly drive the real contract.
//!
//! The wallet library's own tests check a planned spend against the circuit's
//! relations and the replay model; this one hands what they assemble to the
//! deployed pool and lets the contract decide. One wallet deposits, withdraws
//! to an account that refuses the payout, has the bounce minted back into a
//! recovery note, and spends that note to a second wallet, which finds it. A
//! spend anchored to the current root is refused once a deposit moves the
//! root (exit 152), and a spend planned under a withdrawal fee the pool does
//! not charge is refused for exactly that (exit 242): the two refusals a
//! client has to plan around, and the two reasons it has to be the pool's
//! configuration and the pool's anchors that drive the plan.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use chain_block::{Cell, CommonMsgInfo, MsgAddressInt};
use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::{groth16, notes, wire};
use shielded_pool_circuit_crosscheck::pool::{
    be, dec, development_vk_bytes, Pool, DENOMINATION, WITHDRAWAL_FEE,
};
use shielded_pool_circuit_crosscheck::transact::{Anchor, Recipient, Transact};
use shielded_pool_circuit_crosscheck::wire::byte_chain;
use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
use shielded_pool_wallet::descriptor::Descriptor;
use shielded_pool_wallet::keys::PoolInstance;
use shielded_pool_wallet::ledger::{Event, Ledger, Payout, Transact as Committed};
use shielded_pool_wallet::plan::{plan, Candidate, Plan, PoolTerms, RecipientKeys, Request};
use shielded_pool_wallet::scan::{self, Recovered};
use shielded_pool_wallet::spend::{assemble, nullifier_witnesses, Assembled, Terms};
use support::{deploy_destination, execution_domain, REFUSER};

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;
const ALICE: [u8; 32] = [0xa1; 32];
const BOB: [u8; 32] = [0xb0; 32];

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

fn terms() -> PoolTerms {
    PoolTerms {
        denominations: vec![u128::from(DENOMINATION)],
        withdrawal_fee: u128::from(WITHDRAWAL_FEE),
    }
}

/// One deposit for `wallet` at `index`, sent to the pool and applied to the
/// ledger from what was sent.
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
    assert_eq!(
        pool.get("commitment_root").expect("root"),
        dec(ledger.checkpoint().commitment_root)
    );
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

/// What the pool knows about the spend after assembly: the proof under the
/// development key the pool was deployed with, and the nullifier witnesses
/// against the ledger's tree.
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

/// The transact body, in the sandbox's own serializer. The client's codec is
/// held to the chain's bytes by its fixture test; this is the same shape.
fn body(proven: &Proven, anchor: Anchor, anchor_root: Fr, valid_until: u32, plan: &Plan) -> Cell {
    let Proven { assembled, proof, witnesses } = proven;
    Transact {
        public: &assembled.public,
        proof,
        anchor_root,
        anchor,
        valid_until,
        output_payloads: &assembled.payloads,
        keys: [&assembled.input_keys[0], &assembled.input_keys[1]],
        signatures: &assembled.signatures,
        witnesses,
        public_amount_out: u64::try_from(plan.public_amount_out).expect("fits"),
        withdrawal_fee: u64::try_from(plan.withdrawal_fee).expect("fits"),
        recipient: plan.recipient_account.map(Recipient),
        recovery_owner_commitment: assembled.recovery_owner_commitment,
        recovery_payload: assembled.recovery_payload.clone(),
    }
    .body()
    .expect("a transact body")
}

/// The event the chain committed for an accepted spend, with the payout as
/// the pool's own transaction shows it.
fn committed(proven: &Proven, plan: &Plan, payout: Option<Payout>) -> Event {
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
        public_amount_out: plan.public_amount_out,
        withdrawal_fee: plan.withdrawal_fee,
        recovery_owner_commitment: assembled.recovery_owner_commitment,
        recovery_payload: assembled.recovery_payload.clone(),
        payout,
    }))
}

/// The one payout the pool's own transaction of this send emitted, as the
/// ledger records it. The pool's transactions come in order: the transact
/// first, the recovery of a bounce after it.
fn payout_of(
    transactions: &[(MsgAddressInt, chain_block::Transaction)],
    pool: &MsgAddressInt,
    recipient: &MsgAddressInt,
) -> Payout {
    let (_, transaction) =
        transactions.iter().find(|(address, _)| address == pool).expect("the pool ran");
    let mut payouts = Vec::new();
    transaction
        .iterate_out_msgs(|message| {
            let header = message.int_header().expect("an internal payout");
            let body = message.body().expect("a payout body").clone();
            payouts.push(Payout {
                recipient: header.dst.to_string(),
                value: header.value.coins.as_u128(),
                body_hash: *body.into_cell().expect("cell").repr_hash().as_array(),
            });
            Ok(true)
        })
        .expect("iterate");
    assert_eq!(payouts.len(), 1, "one payout");
    assert_eq!(payouts[0].recipient, recipient.to_string());
    payouts.remove(0)
}

fn account_of(address: &MsgAddressInt) -> [u8; 32] {
    address.address().clone().get_next_bytes(32).expect("32 bytes").try_into().expect("an account")
}

#[test]
fn a_planned_withdrawal_bounces_into_a_recovery_note_the_planner_then_spends() {
    let mut pool = Pool::deploy().expect("deploy the pool");
    let domain = execution_domain(&pool);
    let alice = PoolInstance::new(&ALICE, domain);
    let bob = PoolInstance::new(&BOB, domain);
    let refuser = deploy_destination(&mut pool.bc, "refuser", REFUSER);
    let mut ledger = Ledger::genesis();
    let mut alice_notes = Recovered::default();

    // Two denominations in: a withdrawal of one has to cover the fee too.
    deposit(&mut pool, &mut ledger, &alice, 0);
    deposit(&mut pool, &mut ledger, &alice, 1);
    scan_into(&mut ledger, &alice, &mut alice_notes);
    assert_eq!(alice_notes.balance(), 2 * u128::from(DENOMINATION));

    // --- the withdrawal, planned and assembled by the wallet ----------------
    let request = Request::Withdraw {
        amount: u128::from(DENOMINATION),
        recipient_account: account_of(&refuser),
    };
    let withdrawal =
        plan(&terms(), &candidates(&alice_notes), &request, &mut indices_from(10)).expect("plan");
    assert_eq!(withdrawal.input_leaves(), vec![0, 1], "both notes: one is short of the fee");
    let now: u32 = pool.bc.now();
    let valid_until = now + 600;
    let anchor_root = ledger.checkpoint().commitment_root;
    let assembled = assemble(
        &alice,
        &withdrawal,
        ledger.frontier(),
        &Terms { anchor_root, valid_until, intent_nonce: Fr::from(0x1001u64) },
        &mut fresh(),
    )
    .expect("assemble");
    let proven = prove(&ledger, assembled, 1);
    let result = pool
        .send(
            COMPUTE_FEE * 4,
            body(&proven, Anchor::Current, anchor_root, valid_until, &withdrawal),
        )
        .expect("the withdrawal");
    result.expect_success();
    assert_eq!(result.transaction_count(), 3, "in, payout out, bounce back");

    // The ledger follows the chain: the transact with its payout, then the
    // bounce the refuser sent back, as the pool's own transactions show them.
    let payout = payout_of(&result.transactions, &pool.addr, &refuser);
    let history_before = pool.history().len();
    ledger
        .apply(&committed(&proven, &withdrawal, Some(payout.clone())), charge(&pool))
        .expect("the transact");
    let bounce = result
        .transactions
        .iter()
        .find_map(|(address, transaction)| {
            let message = transaction.read_in_msg().ok()??;
            let CommonMsgInfo::IntMsgInfo(info) = message.header() else { return None };
            (info.bounced && *address == pool.addr).then(|| Event::Bounce {
                original_body_hash: payout.body_hash,
                sender: info.src_ref().expect("a sender").to_string(),
                value: info.value.coins.as_u128(),
            })
        })
        .expect("the bounce reached the pool");
    ledger.apply(&bounce, charge(&pool)).expect("the recovery");
    assert_eq!(pool.history().len(), history_before, "nothing else happened");
    assert_eq!(
        pool.get("commitment_root").expect("root"),
        dec(ledger.checkpoint().commitment_root),
        "the ledger's tree is the contract's after the cascade"
    );
    assert_eq!(pool.get("nullifier_root").expect("root"), dec(ledger.checkpoint().nullifier_root));
    assert_eq!(ledger.accepted_intents(), &[proven.assembled.intent_digest()]);

    // Alice: both inputs spent, the change found, the recovery note minted.
    scan_into(&mut ledger, &alice, &mut alice_notes);
    let recovered = alice_notes
        .notes
        .iter()
        .find(|note| note.kind == Kind::Recovery && note.spendable)
        .expect("the minted recovery note");
    let Event::Bounce { value: returned, .. } = bounce else { unreachable!() };
    assert_eq!(recovered.amount, returned - charge(&pool));
    assert_eq!(recovered.note_key_index, 13, "the index the plan reserved for recovery");
    let change = u128::from(DENOMINATION) - u128::from(WITHDRAWAL_FEE);
    assert_eq!(alice_notes.balance(), change + recovered.amount);
    assert!(alice_notes.notes.iter().filter(|note| note.spent).count() == 2);

    // --- the recovered note is an input like any other --------------------
    //
    // Anchored to the root the recovery preserved: the recent ring holds it
    // under the version the mint happened at, and the ledger reproduces it.
    let to = Descriptor::issue(&bob, 7).expect("bob's descriptor");
    let request =
        Request::Transfer { to: Box::new(RecipientKeys::of(&to)), amount: recovered.amount, fee: None };
    let transfer =
        plan(&terms(), &candidates(&alice_notes), &request, &mut indices_from(20)).expect("plan");
    assert_eq!(transfer.input_leaves(), vec![5], "the recovery leaf, after three outputs");
    let (recent, _) = pool.anchor_rings().expect("the anchor rings");
    let anchor_root = ledger.checkpoint().commitment_root;
    let covering = recent
        .iter()
        .filter(|entry| entry.root == be(anchor_root))
        .map(|entry| entry.version)
        .max();
    assert_eq!(covering, None, "the current root is never in the ring before the next change");
    let valid_until = pool.bc.now() + 600;
    let assembled = assemble(
        &alice,
        &transfer,
        ledger.frontier(),
        &Terms { anchor_root, valid_until, intent_nonce: Fr::from(0x1002u64) },
        &mut fresh(),
    )
    .expect("assemble");
    let proven = prove(&ledger, assembled, 2);
    let (exit, _, sent) = pool
        .run_counting_sends(
            COMPUTE_FEE * 4,
            body(&proven, Anchor::Current, anchor_root, valid_until, &transfer),
        )
        .expect("the transfer");
    assert_eq!(exit, 0, "the pool accepts the planned transfer");
    assert_eq!(sent, 0, "a transfer sends nothing");
    ledger.apply(&committed(&proven, &transfer, None), charge(&pool)).expect("the transfer");
    assert_eq!(
        pool.get("commitment_root").expect("root"),
        dec(ledger.checkpoint().commitment_root)
    );

    // Bob finds exactly the note the plan promised him; Alice her change.
    let outputs = ledger.take_outputs();
    let bob_notes = scan::recover_indexed(&bob, &outputs).expect("scan");
    assert_eq!(bob_notes.notes.len(), 1);
    assert_eq!(bob_notes.notes[0].amount, recovered.amount);
    assert_eq!(bob_notes.notes[0].note_key_index, 7);
    alice_notes.merge(scan::recover_indexed(&alice, &outputs).expect("scan"));
    alice_notes.reconcile_spent(&alice, ledger.published_nullifiers()).expect("reconcile");
    assert_eq!(alice_notes.balance(), change, "the recovered note is spent, the change remains");
}

#[test]
fn a_spend_anchored_to_a_root_that_moved_is_refused_and_a_preserved_root_is_not() {
    let mut pool = Pool::deploy().expect("deploy the pool");
    let domain = execution_domain(&pool);
    let alice = PoolInstance::new(&ALICE, domain);
    let bob = PoolInstance::new(&BOB, domain);
    let mut ledger = Ledger::genesis();
    let mut alice_notes = Recovered::default();
    deposit(&mut pool, &mut ledger, &alice, 0);
    scan_into(&mut ledger, &alice, &mut alice_notes);

    let to = Descriptor::issue(&bob, 1).expect("descriptor");
    let request = Request::Transfer {
        to: Box::new(RecipientKeys::of(&to)),
        amount: u128::from(DENOMINATION) / 2,
        fee: None,
    };
    let transfer =
        plan(&terms(), &candidates(&alice_notes), &request, &mut indices_from(10)).expect("plan");
    let anchor_root = ledger.checkpoint().commitment_root;
    let valid_until = pool.bc.now() + 600;
    let assembled = assemble(
        &alice,
        &transfer,
        ledger.frontier(),
        &Terms { anchor_root, valid_until, intent_nonce: Fr::from(0x2001u64) },
        &mut fresh(),
    )
    .expect("assemble");
    let proven = prove(&ledger, assembled, 3);

    // A deposit lands first. The current root is now another one; the
    // proof's root is preserved in the recent ring under version 1.
    deposit(&mut pool, &mut ledger, &alice, 2);
    let (exit, _) = pool
        .run(COMPUTE_FEE * 4, body(&proven, Anchor::Current, anchor_root, valid_until, &transfer))
        .expect("the stale spend");
    assert_eq!(exit, 152, "a current-root anchor that moved");

    let (recent, _) = pool.anchor_rings().expect("the anchor rings");
    let entry = recent
        .iter()
        .find(|entry| entry.root == be(anchor_root))
        .expect("the root the proof is against is preserved");
    assert_eq!(entry.version, 1, "preserved at the commitment index the deposit found");
    // The proof and the signatures bind the root, not how the pool finds it,
    // so the same assembled spend goes through as a recent anchor. Its
    // nullifier witnesses are against the tree as it is: the refused attempt
    // changed nothing.
    let (exit, _, sent) = pool
        .run_counting_sends(
            COMPUTE_FEE * 4,
            body(
                &proven,
                Anchor::Recent(u32::try_from(entry.version).expect("a version")),
                anchor_root,
                valid_until,
                &transfer,
            ),
        )
        .expect("the anchored spend");
    assert_eq!((exit, sent), (0, 0));
    ledger.apply(&committed(&proven, &transfer, None), charge(&pool)).expect("accepted");
    assert_eq!(
        pool.get("commitment_root").expect("root"),
        dec(ledger.checkpoint().commitment_root)
    );
}

#[test]
fn a_withdrawal_planned_under_a_fee_the_pool_does_not_charge_is_refused_for_it() {
    let mut pool = Pool::deploy().expect("deploy the pool");
    let domain = execution_domain(&pool);
    let alice = PoolInstance::new(&ALICE, domain);
    let refuser = deploy_destination(&mut pool.bc, "refuser", REFUSER);
    let mut ledger = Ledger::genesis();
    let mut alice_notes = Recovered::default();
    deposit(&mut pool, &mut ledger, &alice, 0);
    deposit(&mut pool, &mut ledger, &alice, 1);
    scan_into(&mut ledger, &alice, &mut alice_notes);

    // The planner takes the pool's terms from its caller; a stale fee plans
    // a spend that conserves value under the wrong fee, and the proof holds
    // over it. Only the pool can refuse it, and it does, for the fee.
    let stale = PoolTerms {
        denominations: vec![u128::from(DENOMINATION)],
        withdrawal_fee: u128::from(WITHDRAWAL_FEE) + 1,
    };
    let request = Request::Withdraw {
        amount: u128::from(DENOMINATION),
        recipient_account: account_of(&refuser),
    };
    let withdrawal =
        plan(&stale, &candidates(&alice_notes), &request, &mut indices_from(10)).expect("plan");
    withdrawal.check_conservation().expect("conserves under its own fee");
    let anchor_root = ledger.checkpoint().commitment_root;
    let valid_until = pool.bc.now() + 600;
    let assembled = assemble(
        &alice,
        &withdrawal,
        ledger.frontier(),
        &Terms { anchor_root, valid_until, intent_nonce: Fr::from(0x3001u64) },
        &mut fresh(),
    )
    .expect("assemble");
    let proven = prove(&ledger, assembled, 4);
    let (exit, _) = pool
        .run(COMPUTE_FEE * 4, body(&proven, Anchor::Current, anchor_root, valid_until, &withdrawal))
        .expect("the mispriced withdrawal");
    assert_eq!(exit, 242, "the withdrawal fee is the pool's, not the planner's");
    assert_eq!(
        pool.get("commitment_root").expect("root"),
        dec(ledger.checkpoint().commitment_root),
        "a refused spend changes nothing"
    );
}
