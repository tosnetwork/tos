/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Surplus recovery, recheck and abandon (USDC settlement design 4.5, 5.4):
//! the balance query, its races, the supersede rule, and the recovery of
//! payouts whose report was lost.

use chain_block::Message;
use contracts::service_actor_token::{
    ServiceActorTokenContract as Actor, err, kind, outcome, protocol_constants,
};

use crate::harness::*;
use crate::payouts::{Case, prepare};
use crate::world::*;

const TTL: u32 = protocol_constants::RECHECK_QUERY_TTL_SECS;

/// Makes `extra` tokens surplus with an underfunded transfer.
fn add_surplus(w: &mut World, extra: u128) {
    let buyer = w.user(3);
    w.fund(&buyer, extra, w.min_funding() - 1, Some(w.token_call([1; 32])));
}

fn is_take_balance(w: &World, m: &Message) -> bool {
    is_to(m, &w.actor) && body_op(m) == Some(OP_TAKE_BALANCE)
}

#[test]
fn surplus_recovery_pays_only_unattributed_tokens() {
    let mut w = World::new();
    let buyer = w.user(0);
    w.call(&buyer);
    add_surplus(&mut w, 400);
    let owner = w.owner.clone();
    let funding = 2 * w.payout_funding();
    // More than the surplus: refused (1936), the query cleared.
    let start = w.net.delivered.len();
    succeeded(&w.op(&owner, Actor::recover_surplus(1, 401).unwrap(), funding));
    let logs = w.balance_logs_since(start);
    assert_eq!(logs.len(), 1);
    assert_eq!(
        (logs[0].surplus, logs[0].result as i32, logs[0].payout_id),
        (400, err::SURPLUS_INSUFFICIENT, 0)
    );
    assert!(!w.balance_query().0, "the query is cleared");
    // Exactly the surplus: paid to the owner.
    let before = w.tokens(&owner);
    succeeded(&w.op(&owner, Actor::recover_surplus(2, 400).unwrap(), funding));
    assert_eq!(w.tokens(&owner), before + 400);
    assert_eq!(w.surplus(), 0);
    assert_eq!(w.ledger().pending, PRICE, "the customer's principal is untouched");
    // Owner only, a positive amount, and funded.
    let stranger = w.net.stranger.address().clone();
    refused_with(&w.op(&stranger, Actor::recover_surplus(3, 1).unwrap(), funding), err::NOT_OWNER);
    refused_with(
        &w.op(&owner, Actor::recover_surplus(3, 1).unwrap(), TOS / 10),
        err::INSUFFICIENT_EXECUTION_PAYMENT,
    );
}

#[test]
fn a_notification_in_flight_before_the_answer_is_counted_once() {
    let mut w = World::new();
    add_surplus(&mut w, 250);
    let buyer = w.user(0);
    // The funding transfer has reached the actor's wallet; its notification is queued.
    let msg = w.funding_message(&buyer, PRICE, w.call_forward(), Some(w.token_call([1; 32])));
    w.execute(msg);
    let actor = w.actor.clone();
    w.deliver_until(|m| is_to(m, &actor) && body_op(m) == Some(OP_TRANSFER_NOTIFICATION));
    let owner = w.owner.clone();
    let funding = 2 * w.payout_funding();
    w.op_one(&owner, Actor::recover_surplus(1, 250).unwrap(), funding);
    let start = w.net.delivered.len();
    w.settle();
    let logs = w.balance_logs_since(start);
    assert_eq!(
        (logs[0].surplus, logs[0].result),
        (250, 0),
        "exact: the admitted call is not surplus"
    );
    assert_eq!(w.ledger().pending, PRICE);
    assert_eq!(w.surplus(), 0);
}

#[test]
fn a_payout_delivered_between_the_query_and_its_answer_leaves_the_surplus_unchanged() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = crate::payouts::expired(&mut w, &buyer);
    add_surplus(&mut w, 300);
    let owner = w.owner.clone();
    let funding = w.payout_funding();
    w.op_one(&owner, Actor::recover_surplus(1, 300).unwrap(), 2 * funding);
    // A new payout after the query: S answers first, then debits it.
    w.op_one(&buyer, Actor::claim_refund(2, id, &buyer).unwrap(), funding);
    let answer = w.intercept(|m| body_op(m) == Some(OP_TAKE_BALANCE));
    w.settle(); // the payout is delivered before the answer arrives
    assert!(w.refund_exists(id) == false && w.ledger().in_flight == 0, "delivered");
    let (_, _, _, _, floor, delivered, _, _) = w.balance_query();
    assert!(floor <= w.counters().3 - 1);
    assert_eq!(delivered, PRICE, "the delivery is counted since the floor");
    let start = w.net.delivered.len();
    w.send(answer);
    let logs = w.balance_logs_since(start);
    assert_eq!(
        (logs[0].balance, logs[0].surplus, logs[0].result),
        (300 + PRICE, 300, 0),
        "unchanged"
    );
    assert_eq!(w.surplus(), 0);
}

#[test]
fn an_older_payout_still_in_flight_is_under_counted_never_over_counted() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = crate::payouts::expired(&mut w, &buyer);
    add_surplus(&mut w, 300);
    let funding = w.payout_funding();
    w.execute(w.op_message(&buyer, Actor::claim_refund(2, id, &buyer).unwrap(), funding));
    let held = w.intercept(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER_REPORTED));
    // The bridge model counts tokens in flight only while their message is
    // queued; this one is held aside. The actor's own invariant still counts it.
    w.net.model.enabled = false;
    let owner = w.owner.clone();
    let start = w.net.delivered.len();
    succeeded(&w.op(&owner, Actor::recover_surplus(1, 300).unwrap(), 2 * funding));
    let logs = w.balance_logs_since(start);
    assert_eq!(logs[0].balance, 300, "S debited the older payout before answering");
    assert_eq!(
        logs[0].surplus, 0,
        "under-counted: in_flight is subtracted although the balance excludes it"
    );
    assert_eq!(logs[0].result as i32, err::SURPLUS_INSUFFICIENT);
    w.send(held);
    assert_eq!(w.surplus(), 300, "the tokens stay recoverable by a later query");
    succeeded(&w.op(&owner, Actor::recover_surplus(3, 300).unwrap(), 2 * funding));
    assert_eq!(w.surplus(), 0);
}

#[test]
fn a_superseded_querys_late_answer_is_ignored() {
    let mut w = World::new();
    add_surplus(&mut w, 200);
    let owner = w.owner.clone();
    let funding = 2 * w.payout_funding();
    w.op_one(&owner, Actor::recover_surplus(1, 200).unwrap(), funding);
    let late = w.intercept(|m| body_op(m) == Some(OP_TAKE_BALANCE));
    // Within the TTL a new query is refused; after it, it supersedes.
    refused_with(
        &w.op(&owner, Actor::recover_surplus(2, 200).unwrap(), funding),
        err::BALANCE_QUERY_BUSY,
    );
    w.advance(TTL);
    succeeded(&w.op(&owner, Actor::recover_surplus(3, 200).unwrap(), funding));
    assert_eq!(w.surplus(), 0);
    let data = w.data_hash();
    let start = w.net.delivered.len();
    w.send(late);
    assert_eq!(w.data_hash(), data, "the late answer changes nothing");
    assert!(w.balance_logs_since(start).is_empty());
    assert!(w.outcome_logs_since(start).is_empty());
}

/// A payout of `kind` refused at R and its report lost; with `at_limit` S was
/// already full, so the refusal is not recorded either. Returns its id.
fn stuck(w: &mut World, k: u8, at_limit: bool) -> (u64, Case) {
    let case = prepare(w, k);
    w.execute(case.msg.clone());
    w.deliver_until(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER_REPORTED));
    if at_limit {
        w.fill_refusals(32, 0x0100_0000_0000_0000);
    }
    w.net.remove_config();
    w.deliver_one();
    w.net.configure();
    let actor = w.actor.clone();
    w.intercept(|m| is_to(m, &actor) && body_op(m) == Some(OP_TRANSFER_REFUSED));
    w.settle();
    let id = w.counters().3 - 1;
    let id = (1..=id).rev().find(|i| w.payout(*i).is_some()).expect("a stuck payout");
    (id, case)
}

#[test]
fn recheck_converts_each_buyer_kind_after_an_unrecorded_refusal_with_a_lost_report() {
    for k in [
        kind::REFUND,
        kind::SWEEP,
        kind::FUNDING_RETURN,
        kind::RETURNED_CLAIM,
        kind::RETURNED_SWEEP,
    ] {
        let mut w = World::new();
        let (id, case) = stuck(&mut w, k, true);
        let payout = w.payout(id).unwrap();
        assert_eq!(payout.kind, k);
        let stranger = w.net.stranger.address().clone();
        refused_with(
            &w.op(&stranger, Actor::recheck_payout(1, id).unwrap(), TOS),
            err::RECHECK_TOO_EARLY,
        );
        w.advance(MONTH);
        let start = w.net.delivered.len();
        succeeded(&w.op(&stranger, Actor::recheck_payout(2, id).unwrap(), TOS));
        let outcomes = w.outcome_logs_since(start);
        assert_eq!(outcomes.len(), 1, "kind {k}");
        assert_eq!((outcomes[0].outcome, outcomes[0].kind), (outcome::RECHECKED, k));
        assert!(w.payout(id).is_none());
        let ledger = w.ledger();
        assert_eq!(ledger.in_flight, 0);
        assert_eq!(ledger.returned, case.amount, "kind {k}: as its refused-at-R column");
        assert_eq!(w.native().locked_outcome_fees, 0);
        match k {
            kind::REFUND | kind::SWEEP => {
                assert_eq!(w.counters().2, 0, "capacity released");
                assert_eq!(w.native().locked_storage_fees, 0);
                assert_eq!(w.native().withdrawable_revenue, STORAGE_FEE - BOUNTY);
                assert!(w.returned(id).is_some());
            }
            kind::FUNDING_RETURN => assert!(w.returned(id).is_some()),
            _ => {
                let entry = w.returned(case.source).unwrap();
                assert_eq!(entry.paying, 0);
                if k == kind::RETURNED_SWEEP {
                    assert_eq!(entry.return_deadline, u64::from(w.net.bc.now()) + u64::from(MONTH));
                }
            }
        }
        assert_eq!(w.surplus(), 0, "kind {k}: converted from tokens provably back");
    }
}

#[test]
fn recheck_of_a_lost_delivery_without_surplus_leaves_it_paying_and_with_surplus_pays_from_it() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = crate::payouts::expired(&mut w, &buyer);
    let other = w.user(1);
    w.call(&other); // another customer's principal, which must stay backed
    let funding = w.payout_funding();
    let msg = w.op_message(&buyer, Actor::claim_refund(2, id, &buyer).unwrap(), funding);
    let actor = w.actor.clone();
    w.execute(msg);
    let report = w.intercept(|m| is_to(m, &actor) && body_op(m) == Some(OP_TRANSFER_DELIVERED));
    w.settle();
    let payout = w.counters().3 - 1;
    w.advance(MONTH);
    let stranger = w.net.stranger.address().clone();
    let start = w.net.delivered.len();
    succeeded(&w.op(&stranger, Actor::recheck_payout(1, payout).unwrap(), TOS));
    assert_eq!(w.balance_logs_since(start)[0].result as i32, err::SURPLUS_INSUFFICIENT);
    assert!(w.payout(payout).is_some(), "no surplus: it stays paying");
    // With enough surplus the conversion pays the buyer again, from surplus only.
    add_surplus(&mut w, PRICE);
    let start = w.net.delivered.len();
    succeeded(&w.op(&stranger, Actor::recheck_payout(2, payout).unwrap(), TOS));
    assert_eq!(w.outcome_logs_since(start)[0].outcome, outcome::RECHECKED);
    assert_eq!(w.ledger().returned, PRICE);
    assert_eq!(w.ledger().pending, PRICE, "the other customer's principal stays");
    assert_eq!(w.surplus(), 0, "paid from surplus only; every liability stays backed");
    // The late delivery report changes nothing.
    let data = w.data_hash();
    let start = w.net.delivered.len();
    w.send(report);
    assert_eq!(w.data_hash(), data);
    assert!(w.outcome_logs_since(start).is_empty());
    let before = w.tokens(&buyer);
    let funding = w.payout_funding();
    succeeded(&w.op(&buyer, Actor::claim_returned(3, payout, &buyer).unwrap(), funding));
    assert_eq!(w.tokens(&buyer), before + PRICE, "the owner bore the double payment");
}

#[test]
fn a_late_rereport_after_conversion_only_clears_and_a_resolved_target_makes_the_answer_a_no_op() {
    // Recorded refusal, lost report: converted by a recheck, then re-reported.
    let mut w = World::new();
    let (id, _) = stuck(&mut w, kind::REFUND, false);
    assert_eq!(w.refusals(), 1);
    w.advance(MONTH);
    let stranger = w.net.stranger.address().clone();
    succeeded(&w.op(&stranger, Actor::recheck_payout(1, id).unwrap(), TOS));
    assert!(w.payout(id).is_none());
    let data = w.data_hash();
    let rereport_funding = w.get("get_rereport_funding", vec![]).int_at(0) as u64;
    let msg =
        w.net.wallet_query(&stranger, &w.actor.clone(), OP_REREPORT_REFUSAL, id, rereport_funding);
    let start = w.net.delivered.len();
    w.send(msg);
    assert!(w.outcome_logs_since(start).is_empty());
    assert_eq!(w.data_hash(), data, "clear_refusal only");
    assert_eq!(w.refusals(), 0);

    // The target is resolved while the recheck query is pending.
    let mut w = World::new();
    let buyer = w.user(0);
    let id = crate::payouts::expired(&mut w, &buyer);
    let funding = w.payout_funding();
    let actor = w.actor.clone();
    w.execute(w.op_message(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding));
    let report = w.intercept(|m| is_to(m, &actor) && body_op(m) == Some(OP_TRANSFER_DELIVERED));
    w.settle();
    let payout = w.counters().3 - 1;
    w.advance(MONTH);
    let stranger = w.net.stranger.address().clone();
    w.op_one(&stranger, Actor::recheck_payout(1, payout).unwrap(), TOS);
    let answer = w.intercept(|m| body_op(m) == Some(OP_TAKE_BALANCE));
    w.send(report);
    assert!(w.payout(payout).is_none(), "resolved by its delivery");
    let ledger = w.ledger();
    let start = w.net.delivered.len();
    w.send(answer);
    assert!(w.outcome_logs_since(start).is_empty(), "the answer is a no-op");
    assert_eq!(w.ledger(), ledger);
    assert!(!w.balance_query().0);
}

#[test]
fn recheck_refuses_owner_kinds_early_and_absent_payouts() {
    let mut w = World::new();
    let stranger = w.net.stranger.address().clone();
    refused_with(
        &w.op(&stranger, Actor::recheck_payout(1, 77).unwrap(), TOS),
        err::PAYOUT_NOT_FOUND,
    );
    let (id, _) = stuck(&mut w, kind::REVENUE, false);
    w.advance(MONTH);
    refused_with(
        &w.op(&stranger, Actor::recheck_payout(1, id).unwrap(), TOS),
        err::RECHECK_NOT_ALLOWED,
    );
    let mut w = World::new();
    let (id, _) = stuck(&mut w, kind::SURPLUS, false);
    w.advance(MONTH);
    refused_with(
        &w.op(&stranger, Actor::recheck_payout(1, id).unwrap(), TOS),
        err::RECHECK_NOT_ALLOWED,
    );
    let mut w = World::new();
    let (id, _) = stuck(&mut w, kind::REFUND, false);
    refused_with(
        &w.op(&stranger, Actor::recheck_payout(1, id).unwrap(), TOS),
        err::RECHECK_TOO_EARLY,
    );
    w.advance(MONTH - 1);
    refused_with(
        &w.op(&stranger, Actor::recheck_payout(1, id).unwrap(), TOS),
        err::RECHECK_TOO_EARLY,
    );
    w.advance(1);
    succeeded(&w.op(&stranger, Actor::recheck_payout(1, id).unwrap(), TOS));
}

#[test]
fn abandon_checks_every_counter_and_respects_a_young_query() {
    for k in [kind::REVENUE, kind::SURPLUS] {
        let mut w = World::new();
        let (id, case) = stuck(&mut w, k, false);
        let owner = w.owner.clone();
        let stranger = w.net.stranger.address().clone();
        refused_with(&w.op(&stranger, Actor::abandon_payout(1, id).unwrap(), TOS), err::NOT_OWNER);
        refused_with(
            &w.op(&owner, Actor::abandon_payout(1, 999).unwrap(), TOS),
            err::PAYOUT_NOT_FOUND,
        );
        refused_with(
            &w.op(&owner, Actor::abandon_payout(1, id).unwrap(), TOS),
            err::ABANDON_TOO_EARLY,
        );
        w.advance(MONTH);
        // A pending query younger than the TTL refuses it.
        add_surplus(&mut w, 10);
        let funding = 2 * w.payout_funding();
        w.op_one(&owner, Actor::recover_surplus(1, 10).unwrap(), funding);
        let held = w.intercept(|m| body_op(m) == Some(OP_TAKE_BALANCE));
        refused_with(
            &w.op(&owner, Actor::abandon_payout(2, id).unwrap(), TOS),
            err::BALANCE_QUERY_BUSY,
        );
        w.advance(TTL);
        let lock = w.payout(id).unwrap().outcome_fee_lock;
        let native = w.native();
        let start = w.net.delivered.len();
        succeeded(&w.op(&owner, Actor::abandon_payout(3, id).unwrap(), TOS));
        assert!(!w.balance_query().0, "an older query is cleared");
        assert_eq!(w.outcome_logs_since(start)[0].outcome, outcome::ABANDONED);
        assert!(w.payout(id).is_none());
        assert_eq!(w.ledger().in_flight, 0, "kind {k}");
        assert_eq!(w.native().locked_outcome_fees, native.locked_outcome_fees - lock);
        assert_eq!(w.native().revenue_payouts_in_flight, 0);
        assert_eq!(w.ledger().withdrawable_revenue, 0, "abandon credits nothing");
        assert_eq!(w.surplus(), case.amount as i128 + 10, "the tokens show as surplus");
        // The cleared query's late answer is ignored.
        let data = w.data_hash();
        w.send(held);
        assert_eq!(w.data_hash(), data);
    }
    // Buyer kinds are never abandoned.
    let mut w = World::new();
    let (id, _) = stuck(&mut w, kind::REFUND, false);
    w.advance(MONTH);
    let owner = w.owner.clone();
    refused_with(
        &w.op(&owner, Actor::abandon_payout(1, id).unwrap(), TOS),
        err::RECHECK_NOT_ALLOWED,
    );
}

/// Issues the query op `which` (0 recover, 1 recheck, 2 abandon) against `id`.
fn query_op(w: &mut World, which: u8, id: u64) -> chain_block::Transaction {
    let owner = w.owner.clone();
    let funding = 2 * w.payout_funding();
    match which {
        0 => w.op(&owner, Actor::recover_surplus(9, 1).unwrap(), funding),
        1 => w.op(&owner, Actor::recheck_payout(9, id).unwrap(), TOS),
        _ => w.op(&owner, Actor::abandon_payout(9, id).unwrap(), TOS),
    }
}

#[test]
fn the_supersede_rule_holds_for_every_pair_of_query_ops() {
    for first in [0u8, 1] {
        for second in [0u8, 1, 2] {
            let mut w = World::new();
            add_surplus(&mut w, 50);
            let (buyer_payout, _) = stuck(&mut w, kind::REFUND, false);
            let (owner_payout, _) = stuck(&mut w, kind::REVENUE, false);
            w.advance(MONTH);
            let owner = w.owner.clone();
            let funding = 2 * w.payout_funding();
            let msg = match first {
                0 => w.op_message(&owner, Actor::recover_surplus(1, 1).unwrap(), funding),
                _ => w.op_message(&owner, Actor::recheck_payout(1, buyer_payout).unwrap(), TOS),
            };
            w.execute(msg);
            let _held = w.intercept(|m| body_op(m) == Some(OP_TAKE_BALANCE));
            let target = if second == 2 { owner_payout } else { buyer_payout };
            refused_with(&query_op(&mut w, second, target), err::BALANCE_QUERY_BUSY);
            w.advance(TTL - 1);
            refused_with(&query_op(&mut w, second, target), err::BALANCE_QUERY_BUSY);
            w.advance(1);
            succeeded(&query_op(&mut w, second, target));
        }
    }
}

#[test]
fn a_griefer_cannot_hold_the_query_slot_and_a_lost_answer_blocks_it_for_at_most_the_ttl() {
    let mut w = World::new();
    let (victim, _) = stuck(&mut w, kind::REFUND, true);
    w.advance(MONTH);
    let griefer = w.user(2);
    let stranger = w.net.stranger.address().clone();
    // Back-to-back griefer queries: each is answered and frees the slot, and the
    // victim lands in the gap after an answer.
    for round in 0..3u64 {
        w.op_one(&griefer, Actor::recheck_payout(round, victim).unwrap(), TOS);
        let answer = w.intercept(|m| body_op(m) == Some(OP_TAKE_BALANCE));
        refused_with(
            &w.op_one(&stranger, Actor::recheck_payout(9, victim).unwrap(), TOS).tx,
            err::BALANCE_QUERY_BUSY,
        );
        w.send(answer);
        if round < 2 {
            assert!(!w.balance_query().0, "the answer frees the slot");
            // the griefer's answer converted the victim's payout on round 0
        }
        if w.payout(victim).is_none() {
            break;
        }
    }
    assert!(w.payout(victim).is_none(), "the victim's payout is resolved");

    // A lost answer blocks the slot for at most the TTL.
    let mut w = World::new();
    let (id, _) = stuck(&mut w, kind::REFUND, true);
    w.advance(MONTH);
    w.op_one(&griefer, Actor::recheck_payout(1, id).unwrap(), TOS);
    w.intercept(|m| body_op(m) == Some(OP_TAKE_BALANCE)); // lost
    w.advance(TTL - 1);
    refused_with(
        &w.op(&stranger, Actor::recheck_payout(2, id).unwrap(), TOS),
        err::BALANCE_QUERY_BUSY,
    );
    w.advance(1);
    succeeded(&w.op(&stranger, Actor::recheck_payout(3, id).unwrap(), TOS));
    assert!(w.payout(id).is_none());
    let _ = is_take_balance;
}
