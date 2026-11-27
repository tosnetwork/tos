/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Payouts and their outcomes (USDC settlement design 4.4-4.6, 5.4): every
//! payout kind delivered, refused at R and bounced at S, with the counters of
//! the exit-path table; returned entries; refusal records and re-reports.

use chain_block::{IBitstring, Message, MsgAddressInt};
use contracts::service_actor_token::{
    ServiceActorTokenContract as Actor, err, kind, outcome, protocol_constants,
};

use crate::harness::*;
use crate::world::*;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Way {
    Delivered,
    RefusedAtR,
    BouncedAtS,
}

pub struct Case {
    pub msg: Message,
    pub kind: u8,
    pub amount: u128,
    pub recipient: MsgAddressInt,
    /// The request or returned entry the payout comes from.
    pub source: u64,
}

/// A request expired into a refund; returns its id.
pub fn expired(w: &mut World, buyer: &MsgAddressInt) -> u64 {
    let id = w.call(buyer);
    w.advance(SLA);
    succeeded(&w.op(buyer, Actor::expire(1, id).unwrap(), TOS));
    id
}

/// A returned entry for `buyer`, made by a refund refused at R; returns its id.
pub fn returned_entry(w: &mut World, buyer: &MsgAddressInt) -> u64 {
    let id = expired(w, buyer);
    let funding = w.payout_funding();
    let msg = w.op_message(buyer, Actor::claim_refund(1, id, buyer).unwrap(), funding);
    let start = w.refusing_at_r(msg, false);
    let outcomes = w.outcome_logs_since(start);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].outcome, outcome::REFUSED);
    let entry = outcomes[0].payout_id;
    assert!(w.returned(entry).is_some());
    entry
}

/// Prepares a world in which `msg` creates a payout of `kind`.
pub fn prepare(w: &mut World, kind: u8) -> Case {
    let buyer = w.user(0);
    let dest = w.user(1);
    let funding = w.payout_funding();
    match kind {
        kind::REFUND => {
            let id = expired(w, &buyer);
            let msg = w.op_message(&buyer, Actor::claim_refund(2, id, &dest).unwrap(), funding);
            Case { msg, kind, amount: PRICE, recipient: dest, source: id }
        }
        kind::SWEEP => {
            let id = w.call(&buyer);
            w.advance(SLA + WINDOW);
            let stranger = w.net.stranger.address().clone();
            let msg =
                w.op_message(&stranger, Actor::sweep_expired_request(2, id).unwrap(), funding);
            Case { msg, kind, amount: PRICE, recipient: buyer, source: id }
        }
        kind::REVENUE => {
            let id = w.call(&buyer);
            let owner = w.owner.clone();
            succeeded(&w.op(&owner, Actor::respond(1, id, [1; 32]).unwrap(), TOS));
            let msg = w.op_message(&owner, Actor::withdraw_revenue(2, PRICE, 0).unwrap(), funding);
            Case { msg, kind, amount: PRICE, recipient: owner, source: 0 }
        }
        kind::FUNDING_RETURN => {
            let msg =
                w.funding_message(&buyer, PRICE + 5, w.call_forward(), Some(w.token_call([2; 32])));
            Case { msg, kind, amount: PRICE + 5, recipient: buyer, source: 0 }
        }
        kind::RETURNED_CLAIM => {
            let entry = returned_entry(w, &buyer);
            let msg =
                w.op_message(&buyer, Actor::claim_returned(3, entry, &dest).unwrap(), funding);
            Case { msg, kind, amount: PRICE, recipient: dest, source: entry }
        }
        kind::RETURNED_SWEEP => {
            let entry = returned_entry(w, &buyer);
            w.advance(MONTH);
            let stranger = w.net.stranger.address().clone();
            let msg = w.op_message(&stranger, Actor::sweep_returned(3, entry).unwrap(), funding);
            Case { msg, kind, amount: PRICE, recipient: buyer, source: entry }
        }
        kind::SURPLUS => {
            // An underfunded transfer: its tokens are surplus.
            w.fund(&buyer, 300, w.min_funding() - 1, Some(w.token_call([1; 32])));
            assert_eq!(w.surplus(), 300);
            let owner = w.owner.clone();
            let msg = w.op_message(&owner, Actor::recover_surplus(2, 300).unwrap(), 2 * funding);
            Case { msg, kind, amount: 300, recipient: owner, source: 0 }
        }
        other => panic!("no payout kind {other}"),
    }
}

/// Runs `case` the `way` it says and checks the counters of the exit-path table.
pub fn run(w: &mut World, case: Case, way: Way) {
    let before_recipient = w.tokens(&case.recipient);
    let before_native = w.native();
    let deadline_before = w.returned(case.source).map(|e| e.return_deadline);
    let start = match way {
        Way::Delivered => {
            let start = w.net.delivered.len();
            w.send(case.msg.clone());
            start
        }
        Way::RefusedAtR => w.refusing_at_r(case.msg.clone(), false),
        Way::BouncedAtS => w.bouncing_at_s(case.msg.clone()),
    };
    let what = format!("kind {} {:?}", case.kind, way);
    for d in w.actor_txs_since(start) {
        assert!(
            !outcome(&d.tx).aborted || label_of(&d.msg) == "empty",
            "{what}: an actor step failed"
        );
    }
    let outcomes = w.outcome_logs_since(start);
    assert_eq!(outcomes.len(), 1, "{what}: one outcome: {outcomes:?}");
    let o = &outcomes[0];
    let expected = match way {
        Way::Delivered => outcome::DELIVERED,
        Way::RefusedAtR => outcome::REFUSED,
        Way::BouncedAtS => outcome::BOUNCED,
    };
    assert_eq!((o.kind, o.outcome, o.amount), (case.kind, expected, case.amount), "{what}");
    assert!(w.payout(o.payout_id).is_none(), "{what}: the payout is gone");
    assert_eq!(w.native().locked_outcome_fees, 0, "{what}: the lock is released");
    let delivered = way == Way::Delivered;
    // A funding return's recipient sent the tokens in the same run.
    let sent = if case.kind == kind::FUNDING_RETURN { case.amount } else { 0 };
    assert_eq!(
        w.tokens(&case.recipient) + sent,
        before_recipient + if delivered { case.amount } else { 0 },
        "{what}: the recipient's tokens"
    );
    let ledger = w.ledger();
    let native = w.native();
    assert_eq!(ledger.in_flight, 0, "{what}");
    let p = case.amount;
    let settled_revenue = u64::try_from(STORAGE_FEE - BOUNTY).unwrap();
    match (case.kind, way) {
        (kind::REFUND, Way::BouncedAtS) => {
            assert_eq!(ledger.refundable, p, "{what}: the refund is back");
            assert!(w.refund_exists(case.source));
            assert_eq!(w.counters().2, 1, "{what}: still live");
            assert_eq!(native.locked_storage_fees, STORAGE_FEE);
            assert_eq!(native.withdrawable_revenue, 0);
        }
        (kind::SWEEP, Way::BouncedAtS) => {
            assert_eq!(ledger.pending, p, "{what}: the request is back");
            assert!(w.request_exists(case.source));
            assert_eq!(w.counters().1, 1);
            assert_eq!(w.counters().2, 1);
            assert_eq!(native.locked_storage_fees, STORAGE_FEE);
        }
        (kind::REFUND | kind::SWEEP, _) => {
            assert_eq!(w.counters().1, 0, "{what}: pending count");
            assert_eq!(w.counters().2, 0, "{what}: capacity released");
            assert_eq!(w.caller_live(&w.user(0)), 0);
            assert_eq!(native.locked_storage_fees, 0);
            assert_eq!(native.withdrawable_revenue, settled_revenue, "{what}: TOS settled once");
            if delivered {
                assert_eq!(ledger.attributed(), Some(0), "{what}");
                assert_eq!(native.returned_count, 0);
            } else {
                assert_eq!(ledger.returned, p, "{what}: a returned entry");
                assert_eq!(native.returned_count, 1);
                assert_eq!(w.caller_returned(&w.user(0)), 1);
                let entry = w.returned(o.payout_id).expect("keyed by the payout id");
                assert_eq!((entry.caller, entry.amount, entry.paying), (w.user(0), p, 0));
            }
        }
        (kind::REVENUE, _) => {
            assert_eq!(native.revenue_payouts_in_flight, 0, "{what}");
            assert_eq!(ledger.withdrawable_revenue, if delivered { 0 } else { p }, "{what}");
        }
        (kind::FUNDING_RETURN, _) => {
            if delivered {
                assert_eq!(ledger.attributed(), Some(0));
            } else {
                assert_eq!(ledger.returned, p, "{what}: a returned entry for its sender");
                let entry = w.returned(o.payout_id).expect("keyed by the payout id");
                assert_eq!((entry.caller, entry.amount), (w.user(0), p));
                assert_eq!(native.returned_count, before_native.returned_count + 1);
            }
        }
        (kind::RETURNED_CLAIM | kind::RETURNED_SWEEP, _) => {
            if delivered {
                assert!(w.returned(case.source).is_none(), "{what}: the entry is deleted");
                assert_eq!(ledger.returned, 0);
                assert_eq!(native.returned_count, 0);
                assert_eq!(w.caller_returned(&w.user(0)), 0);
            } else {
                let entry = w.returned(case.source).expect("the entry stays");
                assert_eq!((entry.amount, entry.paying), (p, 0), "{what}");
                assert_eq!(ledger.returned, p);
                assert_eq!(native.returned_count, 1);
                if case.kind == kind::RETURNED_SWEEP && way == Way::RefusedAtR {
                    assert_eq!(
                        entry.return_deadline,
                        u64::from(w.net.bc.now()) + u64::from(MONTH),
                        "{what}: the deadline is reset"
                    );
                } else {
                    assert_eq!(Some(entry.return_deadline), deadline_before, "{what}: unchanged");
                }
            }
        }
        (kind::SURPLUS, _) => {
            assert_eq!(ledger.attributed(), Some(0));
            assert_eq!(w.surplus(), if delivered { 0 } else { p as i128 }, "{what}");
        }
        other => panic!("no expectation for {other:?}"),
    }
    assert_eq!(w.balance_query().0, false, "{what}: no balance query is left pending");
}

const KINDS: [u8; 7] = [
    kind::REFUND,
    kind::SWEEP,
    kind::REVENUE,
    kind::FUNDING_RETURN,
    kind::RETURNED_CLAIM,
    kind::SURPLUS,
    kind::RETURNED_SWEEP,
];

fn every_kind(way: Way) {
    for k in KINDS {
        let mut w = World::new();
        let case = prepare(&mut w, k);
        run(&mut w, case, way);
    }
}

#[test]
fn every_payout_kind_delivered() {
    every_kind(Way::Delivered);
}

#[test]
fn every_payout_kind_refused_at_r() {
    every_kind(Way::RefusedAtR);
}

#[test]
fn every_payout_kind_bounced_at_s() {
    every_kind(Way::BouncedAtS);
}

#[test]
fn a_double_claim_returned_in_one_block_is_refused_with_1930() {
    let mut w = World::new();
    let buyer = w.user(0);
    let entry = returned_entry(&mut w, &buyer);
    let funding = w.payout_funding();
    // Both claims reach the actor before anything else is delivered.
    let first = w.op_one(&buyer, Actor::claim_returned(1, entry, &buyer).unwrap(), funding);
    succeeded(&first.tx);
    let second = w.op_one(&buyer, Actor::claim_returned(2, entry, &buyer).unwrap(), funding);
    refused_with(&second.tx, err::PAYOUT_IN_FLIGHT);
    let stranger = w.net.stranger.address().clone();
    w.advance(MONTH);
    let sweep = w.op_one(&stranger, Actor::sweep_returned(3, entry).unwrap(), funding);
    refused_with(&sweep.tx, err::PAYOUT_IN_FLIGHT);
    let before = w.tokens(&buyer);
    w.settle();
    assert_eq!(w.tokens(&buyer), before + PRICE, "paid once");
    assert!(w.returned(entry).is_none());
}

#[test]
fn claim_destinations_are_validated() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let funding = w.payout_funding();
    let actor = w.actor.clone();
    let masterchain = MsgAddressInt::with_params(-1, w.user(1).address().clone()).unwrap();
    let anycast = {
        let mut a = w.user(1);
        if let MsgAddressInt::AddrStd(ref mut s) = a {
            s.anycast = Some(
                chain_block::AnycastInfo::with_rewrite_pfx(chain_block::SliceData::from_raw(
                    vec![0x80],
                    1,
                ))
                .unwrap(),
            );
        }
        a
    };
    // addr_var$11 anycast:0 addr_len:256 workchain:0 address:256 bits.
    let var_body = cell(|b| {
        b.append_u32(contracts::service_actor_token::op::CLAIM_REFUND).unwrap();
        b.append_u64(1).unwrap();
        b.append_u64(id).unwrap();
        b.append_bits(0b110, 3).unwrap();
        b.append_bits(256, 9).unwrap();
        b.append_u32(0).unwrap();
        b.append_raw(&[0x55; 32], 256).unwrap();
    });
    // LDMSGADDR refuses addr_var from global version 10 (doc/GlobalVersions.md):
    // the claim fails in the parse, before any state change.
    let data = w.data_hash();
    let tx = w.op(&buyer, var_body, funding);
    refused_with(&tx, 9);
    assert_eq!(w.data_hash(), data, "addr_var: no state changed");
    // An anycast address is refused by LDMSGADDR as well (exit 9).
    for (name, dest, code) in [
        ("the actor", actor, err::INVALID_DESTINATION),
        ("masterchain", masterchain, err::INVALID_DESTINATION),
        ("anycast", anycast, 9),
    ] {
        let data = w.data_hash();
        let tx = w.op(&buyer, Actor::claim_refund(1, id, &dest).unwrap(), funding);
        println!("case {name}");
        refused_with(&tx, code);
        assert_eq!(w.data_hash(), data, "{name}: no state changed");
    }
    // The same for a returned entry.
    let mut w = World::new();
    let buyer = w.user(0);
    let entry = returned_entry(&mut w, &buyer);
    let actor = w.actor.clone();
    let tx = w.op(&buyer, Actor::claim_returned(1, entry, &actor).unwrap(), funding);
    refused_with(&tx, err::INVALID_DESTINATION);
    // Claims by another caller, and of an absent entry.
    let other = w.user(1);
    refused_with(
        &w.op(&other, Actor::claim_returned(1, entry, &other).unwrap(), funding),
        err::NOT_REFUND_CALLER,
    );
    refused_with(
        &w.op(&buyer, Actor::claim_returned(1, 999, &buyer).unwrap(), funding),
        err::RETURNED_NOT_FOUND,
    );
    // A claimer off workchain 0.
    let mc = MsgAddressInt::with_params(-1, buyer.address().clone()).unwrap();
    refused_with(
        &w.op(&mc, Actor::claim_returned(1, entry, &buyer).unwrap(), funding),
        err::INVALID_DESTINATION,
    );
}

#[test]
fn a_returned_entry_is_swept_to_its_caller_after_its_deadline() {
    let mut w = World::new();
    let buyer = w.user(0);
    let entry = returned_entry(&mut w, &buyer);
    let funding = w.payout_funding();
    let stranger = w.net.stranger.address().clone();
    refused_with(
        &w.op(&stranger, Actor::sweep_returned(1, entry).unwrap(), funding),
        err::SWEEP_TOO_EARLY,
    );
    w.advance(MONTH);
    let before = (w.tokens(&buyer), w.tokens(&stranger));
    succeeded(&w.op(&stranger, Actor::sweep_returned(2, entry).unwrap(), funding));
    assert_eq!(
        (w.tokens(&buyer), w.tokens(&stranger)),
        (before.0 + PRICE, before.1),
        "to the caller, never the sweeper"
    );
    assert!(w.returned(entry).is_none());
    refused_with(
        &w.op(&stranger, Actor::sweep_returned(3, entry).unwrap(), funding),
        err::RETURNED_NOT_FOUND,
    );
}

#[test]
fn a_refused_funding_return_becomes_a_returned_entry_claimed_double_claimed_and_swept() {
    let mut w = World::new();
    let buyer = w.user(0);
    let before = w.tokens(&buyer);
    let msg = w.funding_message(&buyer, PRICE + 1, w.call_forward(), Some(w.token_call([1; 32])));
    let start = w.refusing_at_r(msg, false);
    let id = w.funding_logs_since(start)[0].payout_id;
    let entry = w.returned(id).expect("the refused return is a returned entry for its sender");
    assert_eq!((entry.caller.clone(), entry.amount), (buyer.clone(), PRICE + 1));
    assert_eq!(w.surplus(), 0, "never surplus");
    let funding = w.payout_funding();
    // Claimed, refused again at R, then double-claimed within one block.
    let msg = w.op_message(&buyer, Actor::claim_returned(1, id, &buyer).unwrap(), funding);
    w.refusing_at_r(msg, false);
    assert_eq!(w.returned(id).unwrap().paying, 0);
    let first = w.op_one(&buyer, Actor::claim_returned(2, id, &buyer).unwrap(), funding);
    succeeded(&first.tx);
    refused_with(
        &w.op_one(&buyer, Actor::claim_returned(3, id, &buyer).unwrap(), funding).tx,
        err::PAYOUT_IN_FLIGHT,
    );
    // The first claim bounces at S: still the buyer's.
    let wallet = w.wallet();
    w.deliver_until(|m| body_op(m) == Some(OP_REPORTED_TRANSFER) && m.dst_ref() == Some(&wallet));
    w.net.remove_config();
    w.deliver_one();
    w.net.configure();
    w.settle();
    assert_eq!(w.returned(id).unwrap().paying, 0);
    // Swept to its caller after the deadline.
    w.advance(MONTH);
    let stranger = w.net.stranger.address().clone();
    succeeded(&w.op(&stranger, Actor::sweep_returned(4, id).unwrap(), funding));
    assert!(w.returned(id).is_none());
    assert_eq!(w.tokens(&buyer), before, "every token is back with its sender");
}

#[test]
fn returned_entries_stop_admission_at_the_per_caller_cap() {
    let mut w = World::new();
    let buyer = w.user(0);
    for _ in 0..protocol_constants::MAX_RETURNED_PER_CALLER {
        let msg =
            w.funding_message(&buyer, PRICE + 1, w.call_forward(), Some(w.token_call([1; 32])));
        w.refusing_at_r(msg, false);
    }
    assert_eq!(w.caller_returned(&buyer), protocol_constants::MAX_RETURNED_PER_CALLER);
    // At the cap this caller is refused (and returned); another caller is not.
    let before = w.tokens(&buyer);
    let start = w.fund(&buyer, PRICE, w.call_forward(), Some(w.token_call([1; 32])));
    assert_eq!(w.funding_logs_since(start)[0].reason as i32, err::NOT_ACCEPTING_TOKENS);
    assert_eq!(w.tokens(&buyer), before);
    let other = w.user(1);
    w.call(&other);
    // A claim frees a slot.
    let id = w.actor_data();
    let _ = id;
    let funding = w.payout_funding();
    let entry = (1..w.counters().3).find(|i| w.returned(*i).is_some()).unwrap();
    succeeded(&w.op(&buyer, Actor::claim_returned(1, entry, &buyer).unwrap(), funding));
    assert_eq!(w.caller_returned(&buyer), protocol_constants::MAX_RETURNED_PER_CALLER - 1);
    w.call(&buyer);
}

/// A refusal at R whose report is lost leaves a record at S; a funded re-report
/// then reaches the actor as transfer_rereported.
fn rereport(w: &mut World, query_id: u64) -> usize {
    let start = w.net.delivered.len();
    let stranger = w.net.stranger.address().clone();
    let funding = w.get("get_rereport_funding", vec![]).int_at(0) as u64;
    let msg =
        w.net.wallet_query(&stranger, &w.actor.clone(), OP_REREPORT_REFUSAL, query_id, funding);
    w.send(msg);
    start
}

#[test]
fn a_rereport_of_a_pending_payout_is_its_refusal_and_is_cleared() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let funding = w.payout_funding();
    let msg = w.op_message(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding);
    let start = w.refusing_at_r(msg, true);
    let payout = w.counters().3 - 1;
    assert!(w.payout(payout).is_some(), "the report was lost: still paying");
    assert_eq!(w.refusals(), 1, "S holds the record");
    assert!(w.outcome_logs_since(start).is_empty());
    let start = rereport(&mut w, payout);
    let outcomes = w.outcome_logs_since(start);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].outcome, outcome::REFUSED);
    assert!(w.payout(payout).is_none());
    assert_eq!(w.ledger().returned, PRICE);
    assert_eq!(w.refusals(), 0, "the actor answered with clear_refusal");
    // Re-reported again, the payout is gone: clear_refusal only (nothing to clear).
    let start = rereport(&mut w, payout);
    assert!(w.outcome_logs_since(start).is_empty());
}

#[test]
fn a_rereport_or_refusal_of_an_absent_payout_is_answered_with_clear_refusal_only() {
    let mut w = World::new();
    let buyer = w.user(0);
    w.call(&buyer); // the actor's wallet exists from its first credit
    w.fill_refusals(3, 0x4000_0000_0000_0000);
    assert_eq!(w.refusals(), 3);
    let data = w.data_hash();
    let key = 0x4000_0000_0000_0001u64;
    let start = rereport(&mut w, key);
    let txs = w.actor_txs_since(start);
    assert_eq!(txs.len(), 1, "the re-report reaches the actor, not the catch-all");
    succeeded(&txs[0].tx);
    assert!(
        txs[0].outs.iter().any(|m| body_op(m) == Some(OP_CLEAR_REFUSAL)),
        "answered with clear_refusal"
    );
    assert_eq!(w.data_hash(), data, "no state changed");
    assert_eq!(w.refusals(), 2, "the stale record is cleared");
    w.gas.get("52545232").copied().expect("the absent-payout re-report handler ran");
    // A forged refusal for an absent payout from anyone but the wallet is ignored.
    let stranger = w.net.stranger.address().clone();
    let body = cell(|b| {
        b.append_u32(OP_TRANSFER_REFUSED).unwrap().append_u64(key ^ 2).unwrap();
        coins(b, 1);
    });
    let start = w.net.delivered.len();
    w.send(forged(&stranger, &w.actor.clone(), TOS, body));
    assert!(w.actor_txs_since(start)[0].outs.is_empty(), "nothing is sent for a forged report");
    assert_eq!(w.refusals(), 2);
}

#[test]
fn a_rereport_with_another_total_is_logged_and_clears_nothing() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let funding = w.payout_funding();
    let msg = w.op_message(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding);
    w.refusing_at_r(msg, true);
    let payout = w.counters().3 - 1;
    // The record at S names another total than the payout.
    let actor = w.actor.clone();
    w.net.patch_wallet(&actor, |d| {
        use chain_block::{BuilderData, HashmapE, HashmapType, SliceData};
        let mut m = HashmapE::with_bit_len(64);
        let mut k = BuilderData::new();
        k.append_u64(payout).unwrap();
        m.set(
            SliceData::load_builder(k).unwrap(),
            &SliceData::load_cell(cell(|b| coins(b, PRICE + 7))).unwrap(),
        )
        .unwrap();
        d.refusals = m.data().cloned();
        d.refusals_count = 1;
    });
    let wallet = account_hash(&w.wallet());
    w.net.model.refusal_records.retain(|(x, _), _| *x != wallet);
    let start = rereport(&mut w, payout);
    let outcomes = w.outcome_logs_since(start);
    assert_eq!(outcomes.len(), 1);
    assert_eq!((outcomes[0].outcome, outcomes[0].amount), (outcome::MISMATCH, PRICE + 7));
    assert!(w.payout(payout).is_some(), "the payout stays");
    assert_eq!(w.refusals(), 1, "the record stays");
    let txs = w.actor_txs_since(start);
    assert!(!txs.iter().any(|d| d.outs.iter().any(|m| body_op(m) == Some(OP_CLEAR_REFUSAL))));
}

#[test]
fn a_refusals_full_or_refusal_pending_bounce_from_s_is_an_ordinary_s_refusal() {
    // 714: S holds REFUSALS_LIMIT records.
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    w.fill_refusals(32, 0x2000_0000_0000_0000);
    let funding = w.payout_funding();
    let start = w.net.delivered.len();
    w.op(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding);
    assert_eq!(w.net.exits_since(start, 714), 1, "S refused with refusals_full");
    let outcomes = w.outcome_logs_since(start);
    assert_eq!(outcomes[0].outcome, outcome::BOUNCED);
    assert!(w.refund_exists(id), "the pre-payout position");
    assert_eq!(w.ledger().refundable, PRICE);
    // 712: a record already exists under the payout's query id.
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let next = w.counters().3;
    w.fill_refusals(1, next ^ 1);
    let start = w.net.delivered.len();
    w.op(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding);
    assert_eq!(w.net.exits_since(start, 712), 1, "S refused with refusal_pending");
    assert_eq!(w.outcome_logs_since(start)[0].outcome, outcome::BOUNCED);
    assert!(w.refund_exists(id));
}

#[test]
fn no_permanent_halt_funded_rereports_clear_every_record_and_payouts_resume() {
    let mut w = World::new();
    let buyer = w.user(0);
    // 32 funding returns refused at R, every report lost: S is full.
    let mut ids = Vec::new();
    for i in 0..32u8 {
        let msg =
            w.funding_message(&buyer, PRICE + 1, w.call_forward(), Some(w.token_call([i; 32])));
        let start = w.refusing_at_r(msg, true);
        ids.push(w.funding_logs_since(start)[0].payout_id);
    }
    assert_eq!(w.refusals(), 32);
    for id in &ids {
        assert!(w.payout(*id).is_some(), "still paying");
    }
    // The next payout is refused at S (714) and returns to its pre-payout position.
    let id = expired(&mut w, &buyer);
    let funding = w.payout_funding();
    let start = w.net.delivered.len();
    w.op(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding);
    assert_eq!(w.net.exits_since(start, 714), 1);
    assert!(w.refund_exists(id));
    // Funded re-reports clear every record.
    for id in &ids {
        rereport(&mut w, *id);
    }
    assert_eq!(w.refusals(), 0);
    for id in &ids {
        assert!(w.payout(*id).is_none());
        assert!(w.returned(*id).is_some(), "each refused return is a returned entry");
    }
    let before = w.tokens(&buyer);
    succeeded(&w.op(&buyer, Actor::claim_refund(2, id, &buyer).unwrap(), funding));
    assert_eq!(w.tokens(&buyer), before + PRICE, "the next payout succeeds");
}

#[test]
fn an_unrecorded_refusal_at_the_limit_with_a_lost_report_stays_paying_and_owner_kinds_recover() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = w.call(&buyer);
    let owner = w.owner.clone();
    succeeded(&w.op(&owner, Actor::respond(1, id, [1; 32]).unwrap(), TOS));
    // A revenue payout in flight while S reaches the limit.
    let funding = w.payout_funding();
    w.execute(w.op_message(&owner, Actor::withdraw_revenue(2, PRICE, 0).unwrap(), funding));
    w.deliver_until(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER_REPORTED));
    w.fill_refusals(32, 0x1000_0000_0000_0000);
    w.net.remove_config();
    w.deliver_one();
    w.net.configure();
    let actor = w.actor.clone();
    w.intercept(|m| is_to(m, &actor) && body_op(m) == Some(OP_TRANSFER_REFUSED));
    w.settle();
    let payout = w.counters().3 - 1;
    assert!(w.payout(payout).is_some(), "the payout stays paying");
    assert_eq!(w.refusals(), 32, "the refusal was not recorded");
    assert_eq!(w.actor_tokens(), PRICE, "the tokens are back at S");
    // Kind 3 recovers through abandon_payout, then surplus.
    refused_with(
        &w.op(&owner, Actor::abandon_payout(1, payout).unwrap(), TOS),
        err::ABANDON_TOO_EARLY,
    );
    w.advance(MONTH);
    succeeded(&w.op(&owner, Actor::abandon_payout(1, payout).unwrap(), TOS));
    assert!(w.payout(payout).is_none());
    assert_eq!(w.native().revenue_payouts_in_flight, 0);
    assert_eq!(w.ledger().in_flight, 0);
    assert_eq!(w.surplus(), PRICE as i128, "the tokens show as surplus");
    w.fill_refusals(0, 0);
    let start = w.net.delivered.len();
    succeeded(&w.op(&owner, Actor::recover_surplus(1, PRICE).unwrap(), 2 * funding));
    assert_eq!(w.outcome_logs_since(start).last().unwrap().outcome, outcome::DELIVERED);
    assert_eq!(w.surplus(), 0);
}

#[test]
fn a_refusal_report_is_funded_by_the_payout_after_a_ninefold_price_rise() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let funding = w.payout_funding();
    w.execute(w.op_message(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding));
    w.deliver_until(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER_REPORTED));
    // Between the legs: prices rise ninefold, the storage reserve is 0 and S
    // holds REFUSALS_LIMIT records.
    w.net.wallet_min_storage = 0;
    w.net.configure();
    w.fill_refusals(32, 0x0800_0000_0000_0000);
    let gas = w.net.gas_price(false);
    w.net.set_gas_price(false, gas * 9);
    w.net.scale_forward_prices(false, 9, 1);
    w.net.remove_config();
    w.deliver_one();
    w.net.configure();
    let start = w.net.delivered.len();
    w.settle();
    let outcomes = w.outcome_logs_since(start);
    assert_eq!(outcomes.len(), 1, "the transfer_refused is delivered");
    assert_eq!(outcomes[0].outcome, outcome::REFUSED);
    assert_eq!(w.ledger().returned, PRICE, "the payout ended as refused");
}

#[test]
fn a_failing_in_handler_send_leaves_the_outcome_committed() {
    // Forwarding becomes so expensive while the report is in flight that no
    // send of the outcome handler can be paid: the log, clear_refusal, the
    // bounty and the change. Every one ignores errors, so the outcome commits.
    for way in [Way::RefusedAtR, Way::Delivered] {
        let mut w = World::new();
        let buyer = w.user(0);
        let id = expired(&mut w, &buyer);
        let funding = w.payout_funding();
        w.execute(w.op_message(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding));
        w.deliver_until(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER_REPORTED));
        if way == Way::RefusedAtR {
            w.net.remove_config();
        }
        w.deliver_one();
        w.net.configure();
        let actor = w.actor.clone();
        let op = if way == Way::RefusedAtR { OP_TRANSFER_REFUSED } else { OP_TRANSFER_DELIVERED };
        w.deliver_until(|m| is_to(m, &actor) && body_op(m) == Some(op));
        w.net.scale_forward_prices(false, 100_000, 1);
        let d = w.deliver_one();
        succeeded(&d.tx);
        // The log is external and still goes out; clear_refusal, the bounty and
        // the change are internal and none of them can be paid.
        assert!(
            d.outs.iter().all(|m| !m.is_internal()),
            "{way:?}: every internal in-handler send failed"
        );
        w.net.scale_forward_prices(false, 1, 100_000);
        w.settle();
        assert!(w.payout(w.counters().3 - 1).is_none(), "{way:?}: the outcome is committed");
        assert_eq!(w.native().locked_outcome_fees, 0);
        assert_eq!(w.native().withdrawable_revenue, STORAGE_FEE - BOUNTY, "{way:?}: TOS settled");
        if way == Way::RefusedAtR {
            assert_eq!(w.ledger().returned, PRICE);
            assert_eq!(w.refusals(), 1, "the record stays until a re-report clears it");
            let payout = w.counters().3 - 1;
            rereport(&mut w, payout);
            assert_eq!(w.refusals(), 0, "the re-report of the absent payout clears it");
        } else {
            assert_eq!(w.ledger().attributed(), Some(0));
        }
    }
}

#[test]
fn payouts_still_deliver_after_a_bridge_parameter_vote_raises_the_wallet_terms() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let before = w.payout_funding();
    // A ConfigParam 79 vote raises the wallet's gas and its storage reserve.
    w.net.wallet_gas = 4 * TOS / 10;
    w.net.wallet_min_storage = 2 * TOS;
    w.net.configure();
    let after = w.payout_funding();
    assert!(after >= before + 4 * TOS, "the payout budget follows the vote: {before} -> {after}");
    // The old budget is refused by the actor itself, before any payout.
    refused_with(
        &w.op(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), before),
        err::INSUFFICIENT_EXECUTION_PAYMENT,
    );
    let tokens = w.tokens(&buyer);
    let start = w.net.delivered.len();
    succeeded(&w.op(&buyer, Actor::claim_refund(2, id, &buyer).unwrap(), after));
    let outcomes = w.outcome_logs_since(start);
    assert_eq!(
        outcomes[0].outcome,
        outcome::DELIVERED,
        "S's value check holds under the new terms"
    );
    assert_eq!(w.tokens(&buyer), tokens + PRICE);
}

#[test]
fn usdt_returned_and_claim_match_the_usdc_path() {
    let mut results = Vec::new();
    let mut masters = Vec::new();
    let mut bridges = Vec::new();
    for asset in [(0x5a, 6), (0x74, 6)] {
        let mut w = World::with(Options { asset, ..Options::default() });
        let buyer = w.user(0);
        let destination = w.user(1);
        masters.push(w.init.route.master.clone());
        bridges.push(w.net.bridge.clone());
        assert_eq!(
            w.asset_record(chain_block::SettlementAssetStatus::Active, 10_000, None).decimals,
            6
        );
        assert_eq!(
            w.net.get(&w.init.route.master, "get_wrapped_token_data", vec![]).int_at(2),
            6,
            "the minter reports the source's 6 decimals"
        );
        let request = expired(&mut w, &buyer);
        let funding = w.payout_funding();
        let message =
            w.op_message(&buyer, Actor::claim_refund(11, request, &destination).unwrap(), funding);
        let start = w.refusing_at_r(message, false);
        let logs = w.outcome_logs_since(start);
        assert_eq!(logs.len(), 1);
        let refusal = &logs[0];
        assert_eq!(
            (refusal.kind, refusal.outcome, refusal.amount),
            (kind::REFUND, outcome::REFUSED, PRICE)
        );
        let entry = w.returned(refusal.payout_id).expect("the refused payout has a returned entry");
        assert_eq!(entry.caller, buyer);
        assert_eq!(entry.amount, PRICE);
        assert_eq!(w.ledger().returned, PRICE);
        let before = w.tokens(&destination);
        let start = w.net.delivered.len();
        let message = w.op_message(
            &buyer,
            Actor::claim_returned(12, refusal.payout_id, &destination).unwrap(),
            funding,
        );
        w.send(message);
        let delivered = w.outcome_logs_since(start);
        assert_eq!(delivered.len(), 1);
        assert_eq!(
            (delivered[0].kind, delivered[0].outcome, delivered[0].amount),
            (kind::RETURNED_CLAIM, outcome::DELIVERED, PRICE)
        );
        assert!(w.returned(refusal.payout_id).is_none());
        assert_eq!(w.tokens(&destination), before + PRICE);
        assert_eq!(w.ledger().returned, 0);
        assert_eq!(w.ledger().in_flight, 0);
        assert_eq!(w.surplus(), 0);
        results.push((
            refusal.kind,
            refusal.outcome,
            delivered[0].kind,
            delivered[0].outcome,
            w.ledger().returned,
        ));
    }
    assert_ne!(masters[0], masters[1], "each actor uses its own recognized master");
    assert_eq!(bridges[0], bridges[1], "both assets use the same bridge codes and identity");
    assert_eq!(results[0], results[1]);
}
