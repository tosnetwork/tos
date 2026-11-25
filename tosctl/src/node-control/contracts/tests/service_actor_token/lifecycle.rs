/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The request lifecycle on the token rail: deploy, call, respond, expire,
//! claim and sweep, as the native actor's sandbox covers them.

use chain_block::Deserializable;
use contracts::service_actor_token::{ServiceActorTokenContract as Actor, err, kind, outcome};

use crate::harness::*;
use crate::world::*;

#[test]
fn deploy_records_initial_state() {
    let w = World::new();
    assert!(w.active());
    assert_eq!(w.counters(), (0, 0, 0, 1), "no request, payout ids start at 1");
    assert_eq!(w.ledger(), Default::default());
    assert_eq!(w.native(), Default::default());
    let r = w.get("get_asset_route", vec![]);
    let master = chain_block::MsgAddressInt::construct_from(&mut r.slice_at(0)).unwrap();
    assert_eq!(master, w.net.minter());
    assert_eq!(r.cell_at(2).repr_hash(), codes().wallet.repr_hash());
    let own = chain_block::MsgAddressInt::construct_from(&mut w.get("get_own_wallet", vec![]).slice_at(0))
        .unwrap();
    assert_eq!(own, w.wallet(), "the actor derives its own wallet as the bridge does");
    assert_eq!(
        Actor::token_wallet_address(&w.actor, &w.init.route).unwrap(),
        w.wallet(),
        "the SDK derives the same wallet"
    );
    let terms = Actor::initial_terms(&w.init).unwrap();
    assert_eq!(terms.hash().unwrap(), w.terms_hash(), "the SDK reproduces the terms hash");
    assert_eq!(terms.to_cell().unwrap(), w.terms_cell());
}

#[test]
fn call_then_respond_round_trip() {
    let mut w = World::new();
    let buyer = w.user(0);
    let before = w.tokens(&buyer);
    let id = w.call(&buyer);
    assert_eq!(w.tokens(&buyer), before - PRICE);
    assert_eq!(w.actor_tokens(), PRICE);
    assert_eq!(w.ledger().pending, PRICE);
    assert_eq!(w.counters(), (1, 1, 1, 1));
    assert_eq!(w.native().locked_storage_fees, STORAGE_FEE);
    let owner = w.owner.clone();
    let tx = w.op(&owner, Actor::respond(1, id, [9; 32]).unwrap(), TOS);
    succeeded(&tx);
    assert_eq!(w.ledger().pending, 0);
    assert_eq!(w.ledger().withdrawable_revenue, PRICE);
    assert_eq!(w.native().withdrawable_revenue, STORAGE_FEE);
    assert_eq!(w.native().locked_storage_fees, 0);
    assert_eq!(w.counters(), (1, 0, 0, 1));
}

#[test]
fn a_refused_call_returns_the_tokens_to_their_sender() {
    let mut w = World::new();
    let buyer = w.user(0);
    let before = w.tokens(&buyer);
    // The wrong amount: refused and returned.
    let start = w.fund(&buyer, PRICE + 1, w.call_forward(), Some(w.token_call([1; 32])));
    let logs = w.funding_logs_since(start);
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].reason as i32, err::INSUFFICIENT_PAYMENT);
    assert_eq!(logs[0].from, buyer);
    assert_ne!(logs[0].payout_id, 0);
    let outcomes = w.outcome_logs_since(start);
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert_eq!(outcomes[0].kind, kind::FUNDING_RETURN);
    assert_eq!(outcomes[0].outcome, outcome::DELIVERED);
    assert_eq!(w.tokens(&buyer), before, "every token is back");
    assert_eq!(w.actor_tokens(), 0);
    assert_eq!(w.ledger(), Default::default());
    assert_eq!(w.native().locked_outcome_fees, 0);
    assert!(w.payout(logs[0].payout_id).is_none());
}

#[test]
fn an_expired_request_is_refunded_to_the_claimed_destination() {
    let mut w = World::new();
    let buyer = w.user(0);
    let dest = w.user(1);
    let id = w.call(&buyer);
    w.advance(SLA);
    succeeded(&w.op(&buyer, Actor::expire(1, id).unwrap(), TOS));
    assert_eq!(w.ledger().refundable, PRICE);
    let before = w.tokens(&dest);
    let funding = w.payout_funding();
    let start = w.net.delivered.len();
    succeeded(&w.op(&buyer, Actor::claim_refund(2, id, &dest).unwrap(), funding));
    assert_eq!(w.tokens(&dest), before + PRICE);
    let outcomes = w.outcome_logs_since(start);
    assert_eq!(outcomes.len(), 1);
    assert_eq!((outcomes[0].kind, outcomes[0].outcome), (kind::REFUND, outcome::DELIVERED));
    assert_eq!(w.ledger(), Default::default());
    assert_eq!(w.counters().2, 0, "capacity released");
    assert_eq!(w.native().locked_storage_fees, 0);
    assert_eq!(w.native().withdrawable_revenue, STORAGE_FEE - BOUNTY);
}

