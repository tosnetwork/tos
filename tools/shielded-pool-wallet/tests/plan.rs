/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The planner's rules, one at a time: what it selects, what each slot
//! carries, what it refuses, and that a refusal consumes no index.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use shielded_pool_circuit::field::Fr;
use shielded_pool_wallet::delivery::Kind;
use shielded_pool_wallet::descriptor::Descriptor;
use shielded_pool_wallet::error::Error;
use shielded_pool_wallet::import::Imported;
use shielded_pool_wallet::keys::PoolInstance;
use shielded_pool_wallet::plan::{
    plan, Candidate, Plan, PlannedInput, PlannedOutput, PoolTerms, RecipientKeys, Request,
    MAX_AMOUNT,
};

const TOS: u128 = 1_000_000_000;
const FEE: u128 = 10_000_000;

fn terms() -> PoolTerms {
    PoolTerms { denominations: vec![TOS, 10 * TOS], withdrawal_fee: FEE }
}

fn note(leaf: u64, amount: u128) -> Candidate {
    Candidate {
        note: Imported {
            kind: Kind::Ordinary,
            note_key_index: leaf,
            amount,
            note_secret: Fr::from(0x5ec_0000 + leaf),
            owner_commitment: Fr::from(0x0c_0000 + leaf),
            note_body: Fr::from(0xb0d_0000 + leaf),
            output_data_hash: Fr::from(0xda7a_0000 + leaf),
            spendable: true,
            spent: false,
        },
        leaf_index: leaf,
    }
}

fn recipient() -> RecipientKeys {
    let other = PoolInstance::new(&[0x22; 32], Fr::from(0xd0_0001u64));
    RecipientKeys::of(&Descriptor::issue(&other, 5).expect("a descriptor"))
}

/// Indices from 100 upwards, counting how many were taken.
struct Indices(u64);

impl Indices {
    fn new() -> Self {
        Self(100)
    }
    fn taken(&self) -> u64 {
        self.0 - 100
    }
    fn next(&mut self) -> shielded_pool_wallet::error::Result<u64> {
        let index = self.0;
        self.0 += 1;
        Ok(index)
    }
}

fn transfer(amount: u128) -> Request {
    Request::Transfer { to: Box::new(recipient()), amount }
}

fn withdraw(amount: u128) -> Request {
    Request::Withdraw { amount, recipient_account: [0xab; 32] }
}

fn planned(candidates: &[Candidate], request: &Request) -> (Plan, u64) {
    let mut indices = Indices::new();
    let plan = plan(&terms(), candidates, request, &mut || indices.next()).expect("a plan");
    (plan, indices.taken())
}

fn refused(candidates: &[Candidate], request: &Request, expected: &str) {
    let mut indices = Indices::new();
    let error = plan(&terms(), candidates, request, &mut || indices.next()).expect_err("refused");
    let Error::Planning(message) = &error else { panic!("not a planning refusal: {error}") };
    assert!(message.contains(expected), "wrong refusal: {message}");
    assert_eq!(indices.taken(), 0, "a refusal consumed an index");
}

#[test]
fn a_single_note_that_covers_the_amount_spends_alone_with_a_phantom() {
    let (plan, taken) = planned(&[note(0, 2 * TOS), note(1, 5 * TOS)], &transfer(3 * TOS / 2));
    assert_eq!(plan.inputs[0], PlannedInput::Note(note(0, 2 * TOS)), "the smallest that covers");
    assert_eq!(plan.inputs[1], PlannedInput::Phantom { note_key_index: 102 });
    assert_eq!(
        plan.outputs[0],
        PlannedOutput::Recipient { to: Box::new(recipient()), amount: 3 * TOS / 2 }
    );
    assert_eq!(plan.outputs[1], PlannedOutput::Change { note_key_index: 100, amount: TOS / 2 });
    assert_eq!(plan.outputs[2], PlannedOutput::Dummy { note_key_index: 101 });
    assert_eq!(plan.own_indices(), vec![100, 101, 102]);
    assert_eq!(plan.input_leaves(), vec![0]);
    assert_eq!(taken, 3);
    assert!(!plan.is_withdrawal());
    assert!(plan.recovery.is_none());
    assert!(plan.recipient_account.is_none());
}

#[test]
fn an_exact_amount_leaves_a_dummy_where_the_change_would_be() {
    let (plan, taken) = planned(&[note(0, 2 * TOS)], &transfer(2 * TOS));
    assert_eq!(plan.outputs[1], PlannedOutput::Dummy { note_key_index: 100 });
    assert_eq!(plan.outputs[2], PlannedOutput::Dummy { note_key_index: 101 });
    assert_eq!(taken, 3, "two dummies and the phantom");
}

#[test]
fn two_notes_cover_what_no_single_note_does() {
    let (plan, taken) =
        planned(&[note(0, TOS), note(1, 2 * TOS), note(2, 3 * TOS)], &transfer(9 * TOS / 2));
    assert_eq!(plan.inputs[0], PlannedInput::Note(note(1, 2 * TOS)));
    assert_eq!(plan.inputs[1], PlannedInput::Note(note(2, 3 * TOS)), "the pair with the least sum");
    assert_eq!(plan.outputs[1], PlannedOutput::Change { note_key_index: 100, amount: TOS / 2 });
    assert_eq!(plan.input_leaves(), vec![1, 2]);
    assert_eq!(taken, 2, "change and dummy, no phantom");
}

#[test]
fn the_selection_does_not_depend_on_the_order_the_notes_are_given_in() {
    let forward = [note(0, TOS), note(1, 2 * TOS), note(2, 3 * TOS)];
    let backward = [note(2, 3 * TOS), note(1, 2 * TOS), note(0, TOS)];
    assert_eq!(
        planned(&forward, &transfer(9 * TOS / 2)),
        planned(&backward, &transfer(9 * TOS / 2))
    );
    assert_eq!(planned(&forward, &transfer(TOS)), planned(&backward, &transfer(TOS)));
}

#[test]
fn nothing_covers_refuses_and_consumes_no_index() {
    refused(&[note(0, TOS), note(1, 2 * TOS)], &transfer(4 * TOS), "consolidate");
    refused(&[], &transfer(1), "consolidate");
    // Three notes would cover it; the planner never spends three.
    refused(&[note(0, TOS), note(1, TOS), note(2, TOS)], &transfer(3 * TOS), "consolidate");
}

#[test]
fn a_withdrawal_takes_a_denomination_plus_the_fee_and_reserves_a_recovery_index() {
    let (plan, taken) = planned(&[note(0, 3 * TOS / 2), note(1, TOS)], &withdraw(TOS));
    assert_eq!(
        plan.inputs[0],
        PlannedInput::Note(note(0, 3 * TOS / 2)),
        "one TOS alone is short of the fee"
    );
    assert_eq!(plan.inputs[1], PlannedInput::Phantom { note_key_index: 104 });
    assert_eq!(
        plan.outputs[0],
        PlannedOutput::Change { note_key_index: 100, amount: TOS / 2 - FEE }
    );
    assert_eq!(plan.outputs[1], PlannedOutput::Dummy { note_key_index: 101 });
    assert_eq!(plan.outputs[2], PlannedOutput::Dummy { note_key_index: 102 });
    assert_eq!(plan.recovery.as_ref().map(|r| r.note_key_index), Some(103));
    assert_eq!(plan.own_indices(), vec![100, 101, 102, 103, 104]);
    assert_eq!(taken, 5);
    assert!(plan.is_withdrawal());
    assert_eq!(plan.public_amount_out, TOS);
    assert_eq!(plan.withdrawal_fee, FEE);
    assert_eq!(plan.recipient_account, Some([0xab; 32]));
}

#[test]
fn a_withdrawal_of_an_amount_the_pool_does_not_pay_in_one_piece_is_refused() {
    refused(&[note(0, 5 * TOS)], &withdraw(3 * TOS / 2), "denominations");
    refused(&[note(0, 5 * TOS)], &withdraw(TOS + 1), "denominations");
    // The amount alone is held, the fee is not.
    refused(&[note(0, TOS)], &withdraw(TOS), "consolidate");
}

#[test]
fn zero_and_out_of_range_amounts_and_a_broken_fee_are_refused() {
    refused(&[note(0, TOS)], &transfer(0), "zero");
    refused(&[note(0, TOS)], &withdraw(0), "zero");
    refused(&[note(0, TOS)], &transfer(MAX_AMOUNT + 1), "out of range");
    let broken = PoolTerms { denominations: vec![TOS], withdrawal_fee: 0 };
    let mut indices = Indices::new();
    let error = plan(&broken, &[note(0, 2 * TOS)], &withdraw(TOS), &mut || indices.next())
        .expect_err("a fee of zero");
    assert!(error.to_string().contains("withdrawal fee"), "{error}");
    assert_eq!(indices.taken(), 0);
}

#[test]
fn spent_valueless_and_repeated_notes_are_never_inputs() {
    let mut spent = note(0, 10 * TOS);
    spent.note.spent = true;
    let mut dummy = note(1, 0);
    dummy.note.kind = Kind::Dummy;
    dummy.note.spendable = false;
    let mut template = note(2, 10 * TOS);
    template.note.spendable = false;
    refused(&[spent, dummy, template], &transfer(1), "consolidate");

    // Two notes with one body share a nullifier: spendable once, never as a pair.
    let mut twin = note(4, TOS);
    twin.note.note_body = note(3, TOS).note.note_body;
    refused(&[note(3, TOS), twin], &transfer(2 * TOS), "consolidate");
}

#[test]
fn conservation_is_checked_on_the_plan_itself() {
    let (mut plan, _) = planned(&[note(0, 2 * TOS)], &transfer(TOS));
    plan.check_conservation().expect("the planner's own plan conserves");
    plan.outputs[1] = PlannedOutput::Change { note_key_index: 100, amount: TOS - 1 };
    assert!(plan.check_conservation().is_err(), "a short change");
    plan.outputs[1] = PlannedOutput::Change { note_key_index: 100, amount: TOS + 1 };
    assert!(plan.check_conservation().is_err(), "an excess change");
    plan.outputs[1] = PlannedOutput::Change { note_key_index: 100, amount: TOS };
    plan.withdrawal_fee = 1;
    assert!(plan.check_conservation().is_err(), "a fee from nowhere");

    // Amounts the field would wrap are refused as arithmetic, not as a wrap.
    let huge = [note(0, u128::MAX), note(1, 2)];
    let plan = Plan {
        inputs: [PlannedInput::Note(huge[0].clone()), PlannedInput::Note(huge[1].clone())],
        outputs: [
            PlannedOutput::Recipient { to: Box::new(recipient()), amount: 1 },
            PlannedOutput::Dummy { note_key_index: 100 },
            PlannedOutput::Dummy { note_key_index: 101 },
        ],
        public_amount_out: 0,
        withdrawal_fee: 0,
        recipient_account: None,
        recovery: None,
    };
    assert!(plan.input_total().is_err(), "inputs overflow");
    assert!(plan.check_conservation().is_err());
}
