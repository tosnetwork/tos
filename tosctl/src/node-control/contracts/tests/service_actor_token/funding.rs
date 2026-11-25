/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Funding a call (USDC settlement design 5.2-5.3): foreign and spoofed
//! notifications, underfunded ones, malformed payloads and recognition, and
//! every admission refusal, each ending in a funding return with no token
//! stranded.

use chain_block::{
    Cell, Deserializable, IBitstring, MsgAddressInt, Serializable, SettlementAssetStatus, StateInit,
    UInt256,
};
use contracts::service_actor_token::{
    ServiceActorTokenContract as Actor, err, kind, outcome, protocol_constants,
};
use tos_sandbox::MessageBuilder;

use crate::harness::*;
use crate::world::*;

/// A refused funding: logged with `reason`, returned through a delivered
/// funding return, every token back with `buyer`, nothing left in any ledger.
fn assert_returned(w: &World, start: usize, buyer: &MsgAddressInt, before: u128, reason: i32) {
    for d in w.actor_txs_since(start) {
        assert!(!outcome(&d.tx).aborted, "the notification handler never throws");
    }
    let logs = w.funding_logs_since(start);
    assert_eq!(logs.len(), 1, "one funding log");
    assert_eq!(logs[0].reason as i32, reason, "refused for its stated reason");
    assert_eq!(&logs[0].from, buyer);
    assert_ne!(logs[0].payout_id, 0, "a funding return was created");
    let outcomes = w.outcome_logs_since(start);
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert_eq!(outcomes[0].payout_id, logs[0].payout_id);
    assert_eq!((outcomes[0].kind, outcomes[0].outcome), (kind::FUNDING_RETURN, outcome::DELIVERED));
    assert_eq!(w.tokens(buyer), before, "every token is back with its sender");
    assert!(w.snapshots_since(start).is_empty(), "nothing was admitted");
    assert_eq!(w.surplus(), 0, "no token became surplus");
}

fn refused_call(w: &mut World, reason: i32) {
    let buyer = w.user(0);
    let before = w.tokens(&buyer);
    let ledger = w.ledger();
    let start = w.fund(&buyer, w.init.price_per_call, w.call_forward(), Some(w.token_call([3; 32])));
    assert_returned(w, start, &buyer, before, reason);
    assert_eq!(w.ledger(), ledger, "the ledger is as before");
    assert_eq!(w.native().locked_outcome_fees, 0, "the return's lock is released");
}

#[test]
fn a_spoofed_notification_changes_nothing_and_asks_its_sender_for_nothing_it_holds() {
    let mut w = World::new();
    let stranger = w.net.stranger.address().clone();
    let data = w.data_hash();
    let balance = w.balance(&w.actor);
    let body = cell(|b| {
        b.append_u32(OP_TRANSFER_NOTIFICATION).unwrap().append_u64(5).unwrap();
        coins(b, PRICE);
        w.user(0).write_to(b).unwrap();
        b.append_bit_one().unwrap();
        b.checked_append_reference(w.token_call([1; 32])).unwrap();
    });
    let start = w.net.delivered.len();
    let msg = forged(&stranger, &w.actor.clone(), w.call_forward() as u64, body);
    succeeded(&w.send(msg));
    assert_eq!(w.data_hash(), data, "no state changed");
    assert!(w.balance(&w.actor) >= balance, "the actor's own TOS paid nothing");
    let txs = w.actor_txs_since(start);
    assert_eq!(txs.len(), 1);
    let asks: Vec<_> = txs[0].outs.iter().filter(|m| body_op(m) == Some(OP_TRANSFER)).collect();
    assert_eq!(asks.len(), 1, "the actor asks the sender to transfer the amount back");
    assert!(is_to(asks[0], &stranger));
    assert!(w.funding_logs_since(start).is_empty());
}

#[test]
fn a_foreign_tokens_notification_returns_them_to_their_sender() {
    let mut w = World::new();
    let buyer = w.user(0);
    // A second token behind the same bridge: its minter is not the actor's master.
    let n = w.net.start_swap_token(&buyer, 5_000, 0x5b);
    let _ = n;
    w.settle();
    let foreign = w.net.minter_of(0x5b);
    let buyer_wallet = w.net.wallet_in(&foreign, &buyer);
    let actor_foreign = w.net.wallet_in(&foreign, &w.actor);
    let tokens = |w: &World, wallet: &MsgAddressInt| {
        w.net.try_get(wallet, "get_wallet_data", vec![]).map(|r| r.int_at(0) as u128).unwrap_or(0)
    };
    assert_eq!(tokens(&w, &buyer_wallet), 5_000);
    let data = w.data_hash();
    let actor = w.actor.clone();
    let body = cell(|b| {
        b.append_u32(OP_TRANSFER).unwrap().append_u64(9).unwrap();
        coins(b, PRICE);
        actor.write_to(b).unwrap();
        buyer.write_to(b).unwrap();
        b.append_bit_zero().unwrap();
        coins(b, TOS.into());
        b.append_bit_one().unwrap();
        b.checked_append_reference(w.token_call([1; 32])).unwrap();
    });
    let msg = MessageBuilder::internal(&buyer, &buyer_wallet, 2 * TOS).bounce(true).body(body).build();
    let start = w.net.delivered.len();
    w.send(msg);
    assert_eq!(w.data_hash(), data, "a foreign notification changes no state");
    assert_eq!(tokens(&w, &buyer_wallet), 5_000, "the foreign tokens are back with their sender");
    assert_eq!(tokens(&w, &actor_foreign), 0);
    assert!(w.funding_logs_since(start).is_empty());
    assert_eq!(w.actor_tokens(), 0);
}

#[test]
fn underfunded_and_forwardless_transfers_store_nothing_and_become_surplus() {
    let mut w = World::new();
    let buyer = w.user(0);
    let data = w.data_hash();
    // Below MIN_FUNDING_VALUE: logged as underfunded, nothing stored.
    let start = w.fund(&buyer, PRICE, w.min_funding() - 1, Some(w.token_call([1; 32])));
    let logs = w.funding_logs_since(start);
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].reason as i32, err::INSUFFICIENT_EXECUTION_PAYMENT);
    assert_eq!(logs[0].payout_id, 0, "no return");
    assert_eq!(w.data_hash(), data, "nothing is stored");
    assert_eq!(w.surplus(), PRICE as i128, "the tokens are surplus");
    // No forward amount: no notification at all.
    let start = w.fund(&buyer, PRICE, 0, Some(w.token_call([1; 32])));
    assert!(w.actor_txs_since(start).is_empty(), "no notification reaches the actor");
    assert_eq!(w.surplus(), 2 * PRICE as i128);
    // A forward that cannot pay for the handler up to its check: the
    // transaction fails, and the tokens are surplus too.
    let start = w.fund(&buyer, PRICE, 1, Some(w.token_call([1; 32])));
    let txs = w.actor_txs_since(start);
    assert_eq!(txs.len(), 1);
    assert!(outcome(&txs[0].tx).aborted, "too little to run");
    assert_eq!(w.data_hash(), data);
    assert_eq!(w.surplus(), 3 * PRICE as i128);
    assert_eq!(w.ledger(), Default::default());
}

#[test]
fn a_malformed_payload_takes_the_refusal_path_without_a_throw() {
    let cases: Vec<(&str, Option<Cell>)> = vec![
        ("no payload", None),
        ("another tag", Some(cell(|b| {
            b.append_u32(0x5354_4399).unwrap();
            b.append_raw(&[0u8; 64], 512).unwrap();
        }))),
        ("too short", Some(cell(|b| {
            b.append_u32(0x5354_4301).unwrap();
            b.append_raw(&[0u8; 32], 256).unwrap();
        }))),
        ("trailing bits", Some(cell(|b| {
            b.append_u32(0x5354_4301).unwrap();
            b.append_raw(&[0u8; 64], 512).unwrap();
            b.append_bit_one().unwrap();
        }))),
        ("a trailing reference", Some(cell(|b| {
            b.append_u32(0x5354_4301).unwrap();
            b.append_raw(&[0u8; 64], 512).unwrap();
            b.checked_append_reference(Cell::default()).unwrap();
        }))),
    ];
    for (name, payload) in cases {
        let mut w = World::new();
        let buyer = w.user(0);
        let before = w.tokens(&buyer);
        let start = w.fund(&buyer, PRICE, w.call_forward(), payload);
        println!("case {name}");
        assert_returned(&w, start, &buyer, before, err::MALFORMED_PAYLOAD);
    }
}

#[test]
fn an_inline_payload_is_admitted_like_a_referenced_one() {
    let mut w = World::new();
    let buyer = w.user(0);
    let wallet = w.net.wallet_of(&buyer);
    let actor = w.actor.clone();
    let terms = w.terms_hash();
    let body = cell(|b| {
        b.append_u32(OP_TRANSFER).unwrap().append_u64(1).unwrap();
        coins(b, PRICE);
        actor.write_to(b).unwrap();
        b.append_bits(0, 2).unwrap(); // no response destination: the notification still fits
        b.append_bit_zero().unwrap();
        coins(b, w.call_forward());
        b.append_bit_zero().unwrap();
        b.append_u32(0x5354_4301).unwrap();
        b.append_raw(&[4u8; 32], 256).unwrap();
        b.append_raw(&terms, 256).unwrap();
    });
    let value = w.call_forward() as u64 + TOS;
    let msg = MessageBuilder::internal(&buyer, &wallet, value).bounce(true).body(body).build();
    let start = w.net.delivered.len();
    w.send(msg);
    let snapshots = w.snapshots_since(start);
    assert_eq!(snapshots.len(), 1, "admitted: {:?}", w.funding_logs_since(start));
    assert_eq!(snapshots[0].request_hash, [4u8; 32]);
}

#[test]
fn an_absent_or_malformed_configparam_84_takes_the_refusal_path() {
    let malformed: Vec<(&str, Option<Cell>)> = vec![
        ("absent", None),
        ("empty cell", Some(Cell::default())),
        ("another tag", Some(cell(|b| {
            b.append_u8(2).unwrap();
            b.append_bit_zero().unwrap();
        }))),
        ("trailing bits", Some(cell(|b| {
            b.append_u8(1).unwrap();
            b.append_bit_zero().unwrap();
            b.append_bit_one().unwrap();
        }))),
        ("no entries", Some(cell(|b| {
            b.append_u8(1).unwrap();
            b.append_bit_zero().unwrap();
        }))),
    ];
    for (name, value) in malformed {
        let mut w = World::new();
        w.set_param_84(value);
        println!("case {name}");
        refused_call(&mut w, err::ASSET_NOT_RECOGNIZED);
    }
    // A record that does not parse, and records that parse but do not admit.
    let mut w = World::new();
    let master = UInt256::from_slice(&account_hash(&w.net.minter()));
    let record = |w: &World, tweak: &dyn Fn(&mut chain_block::BuilderData)| {
        use chain_block::{HashmapE, HashmapType, SliceData};
        let mut d = HashmapE::with_bit_len(256);
        let mut leaf = chain_block::BuilderData::new();
        tweak(&mut leaf);
        d.set(SliceData::from_raw(master.as_slice().to_vec(), 256), &SliceData::load_builder(leaf).unwrap())
            .unwrap();
        let _ = w;
        cell(|b| {
            b.append_u8(1).unwrap();
            b.append_bit_one().unwrap();
            b.checked_append_reference(d.data().cloned().unwrap()).unwrap();
        })
    };
    let good = w.asset_record(SettlementAssetStatus::Active, protocol_constants::NO_TOKEN_CAP, None);
    let good_cell = {
        let mut b = chain_block::BuilderData::new();
        good.write_to(&mut b).unwrap();
        b.into_cell().unwrap()
    };
    let bits = |c: &Cell| chain_block::SliceData::load_cell(c.clone()).unwrap();
    for (name, tweak) in [
        ("truncated", Box::new(|b: &mut chain_block::BuilderData| {
            b.append_u8(1).unwrap();
            b.append_u8(1).unwrap();
        }) as Box<dyn Fn(&mut chain_block::BuilderData)>),
        ("bad status 9", Box::new(|b: &mut chain_block::BuilderData| {
            let mut s = bits(&good_cell);
            s.get_next_bits(16).unwrap();
            b.append_u8(1).unwrap();
            b.append_u8(9).unwrap();
            b.append_bytestring(&s).unwrap();
        })),
    ] {
        let value = record(&w, &*tweak);
        w.set_param_84(Some(value));
        println!("case {name}");
        refused_call(&mut w, err::ASSET_NOT_RECOGNIZED);
    }
    for (name, status, hash) in [
        ("suspended", SettlementAssetStatus::AdmissionSuspended, None),
        ("retired", SettlementAssetStatus::Retired, None),
        ("another wallet code", SettlementAssetStatus::Active, Some([0x99; 32])),
    ] {
        w.recognize(Some(status), protocol_constants::NO_TOKEN_CAP, hash);
        println!("case {name}");
        refused_call(&mut w, err::ASSET_NOT_RECOGNIZED);
    }
    // Recognized again: admitted.
    w.recognize(Some(SettlementAssetStatus::Active), protocol_constants::NO_TOKEN_CAP, None);
    let buyer = w.user(0);
    w.call(&buyer);
}

#[test]
fn payouts_never_read_recognition() {
    let mut w = World::new();
    let buyer = w.user(0);
    let a = w.call(&buyer);
    let b = w.call(&buyer);
    w.advance(SLA);
    succeeded(&w.op(&buyer, Actor::expire(1, a).unwrap(), TOS));
    // Suspended, then absent: the refund and the sweep still pay.
    w.recognize(Some(SettlementAssetStatus::AdmissionSuspended), protocol_constants::NO_TOKEN_CAP, None);
    let funding = w.payout_funding();
    let before = w.tokens(&buyer);
    succeeded(&w.op(&buyer, Actor::claim_refund(1, a, &buyer).unwrap(), funding));
    assert_eq!(w.tokens(&buyer), before + PRICE);
    w.set_param_84(None);
    w.advance(WINDOW);
    let stranger = w.net.stranger.address().clone();
    succeeded(&w.op(&stranger, Actor::sweep_expired_request(1, b).unwrap(), funding));
    assert_eq!(w.tokens(&buyer), before + 2 * PRICE);
    assert_eq!(w.ledger(), Default::default());
}

#[test]
fn the_exact_amount_rule_refuses_over_and_underpayment() {
    for amount in [PRICE - 1, PRICE + 1, 1] {
        let mut w = World::new();
        let buyer = w.user(0);
        let before = w.tokens(&buyer);
        let start = w.fund(&buyer, amount, w.call_forward(), Some(w.token_call([1; 32])));
        assert_returned(&w, start, &buyer, before, err::INSUFFICIENT_PAYMENT);
    }
}

#[test]
fn a_zero_amount_notification_returns_nothing_and_stores_nothing() {
    let mut w = World::new();
    let buyer = w.user(0);
    let data = w.data_hash();
    let start = w.fund(&buyer, 0, w.call_forward(), Some(w.token_call([1; 32])));
    let logs = w.funding_logs_since(start);
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].reason as i32, err::INSUFFICIENT_PAYMENT);
    assert_eq!(logs[0].payout_id, 0, "no token to return");
    assert_eq!(w.data_hash(), data);
}

#[test]
fn the_exposure_caps_bound_the_token_liability() {
    // The owner's cap.
    let mut w = World::with(Options { max_token_liability: 2 * PRICE, ..Options::default() });
    let buyer = w.user(0);
    w.call(&buyer);
    w.call(&buyer);
    refused_call(&mut w, err::EXPOSURE_CAP);
    // The recognition record's cap, the lesser of the two.
    let mut w = World::with(Options { asset_cap: PRICE, ..Options::default() });
    let buyer = w.user(0);
    w.call(&buyer);
    refused_call(&mut w, err::EXPOSURE_CAP);
    // Revenue is not liability: once responded, the room is back.
    let owner = w.owner.clone();
    succeeded(&w.op(&owner, Actor::respond(1, 0, [1; 32]).unwrap(), TOS));
    w.call(&buyer);
}

#[test]
fn every_admission_refusal_ends_in_a_funding_return() {
    // inactive
    let mut w = World::new();
    let owner = w.owner.clone();
    let filler = owner.clone();
    let body = Actor::update_policy(
        1, PRICE, STORAGE_FEE, BOUNTY, SLA, WINDOW, false, true, None, &filler, 0,
        protocol_constants::NO_TOKEN_CAP, [0x11; 32], [0x22; 32],
    )
    .unwrap();
    succeeded(&w.op(&owner, body, TOS));
    refused_call(&mut w, err::INACTIVE);

    // policy bounds a deployer could set directly
    for (code, rewrite) in [
        (err::INVALID_RESPONSE_SLA, Options { response_sla: 10, ..Options::default() }),
        (err::INVALID_REFUND_CLAIM_WINDOW, Options { refund_claim_window: 10, ..Options::default() }),
        (err::INVALID_CLEANUP_BOUNTY, Options { cleanup_bounty: 1, ..Options::default() }),
        (err::INSUFFICIENT_STORAGE_FEE, Options { storage_fee: BOUNTY, ..Options::default() }),
    ] {
        let mut w = World::with(rewrite);
        refused_call(&mut w, code);
    }

    // restricted access
    let mut w = World::with(Options { open_access: false, authorized_caller: Some(1), ..Options::default() });
    refused_call(&mut w, err::NOT_AUTHORIZED);
    let caller = w.user(1);
    w.call(&caller);

    // a forward that covers the budget but not the storage fee
    let mut w = World::new();
    let buyer = w.user(0);
    let before = w.tokens(&buyer);
    let start = w.fund(&buyer, PRICE, w.call_forward() - 1, Some(w.token_call([1; 32])));
    assert_returned(&w, start, &buyer, before, err::INSUFFICIENT_PAYMENT);

    // terms quoted under another policy
    let mut w = World::new();
    let buyer = w.user(0);
    let before = w.tokens(&buyer);
    let payload = Actor::token_call([1; 32], [0x55; 32]).unwrap();
    let start = w.fund(&buyer, PRICE, w.call_forward(), Some(payload));
    assert_returned(&w, start, &buyer, before, err::TERMS_MISMATCH);

    // capacity, per caller, request ids, the returned stores
    let mut w = World::new();
    w.patch(|d| d.live_count = protocol_constants::MAX_LIVE_GLOBAL);
    refused_call(&mut w, err::CAPACITY_EXCEEDED_GLOBAL);
    let mut w = World::new();
    let buyer = w.user(0);
    w.patch(|d| d.requests[2] = counter_dict(&d.requests[2], &buyer, protocol_constants::MAX_LIVE_PER_CALLER));
    refused_call(&mut w, err::CAPACITY_EXCEEDED_CALLER);
    let mut w = World::new();
    w.patch(|d| d.next_request_id = u64::MAX);
    refused_call(&mut w, err::REQUEST_ID_OVERFLOW);
    let mut w = World::new();
    w.patch(|d| d.returned_count = protocol_constants::MAX_RETURNED_GLOBAL);
    refused_call(&mut w, err::NOT_ACCEPTING_TOKENS);
    let mut w = World::new();
    let buyer = w.user(0);
    w.patch(|d| {
        d.payout_dicts[2] = counter_dict(&d.payout_dicts[2], &buyer, protocol_constants::MAX_RETURNED_PER_CALLER)
    });
    refused_call(&mut w, err::NOT_ACCEPTING_TOKENS);

    // the daily rate limit
    let mut w = World::with(Options { rate_limit_per_day: 1, ..Options::default() });
    let buyer = w.user(0);
    w.call(&buyer);
    refused_call(&mut w, err::RATE_LIMITED);
    w.advance(DAY);
    w.call(&buyer);

    // an unfunded operating reserve
    let mut w = World::new();
    let actor = w.actor.clone();
    w.net.set_balance(&actor, u128::from(TOS / 2));
    refused_call(&mut w, err::OPERATING_RESERVE_UNFUNDED);

    // an attestor flag without a key, from the deploy data
    let mut w = World::with_data(Options::default(), |data| {
        let mut d = ActorData::parse(&data);
        let mut s = chain_block::SliceData::load_cell(d.policy.clone()).unwrap();
        let commitments = s.checked_drain_reference().unwrap();
        let mut c = chain_block::SliceData::load_cell(commitments).unwrap();
        let meta = c.get_next_bits(512).unwrap();
        let rebuilt = cell(|b| {
            b.append_raw(&meta, 512).unwrap();
            b.append_bit_one().unwrap(); // has_attestor, but no key
            b.append_raw(&[0x33; 32], 256).unwrap();
            b.append_bit_zero().unwrap();
        });
        d.policy = cell(|b| {
            b.append_bytestring(&s).unwrap();
            b.checked_append_reference(rebuilt).unwrap();
        });
        d.build()
    });
    refused_call(&mut w, err::BAD_ATTESTOR_KEY);

    // an asset route whose code hash is not its code's
    let mut w = World::with_data(Options::default(), |data| {
        let mut d = ActorData::parse(&data);
        let mut s = chain_block::SliceData::load_cell(d.route.clone()).unwrap();
        let master = MsgAddressInt::construct_from(&mut s).unwrap();
        let code = s.reference(0).unwrap();
        d.route = cell(|b| {
            master.write_to(b).unwrap();
            b.append_raw(&[0x44; 32], 256).unwrap();
            b.checked_append_reference(code).unwrap();
        });
        d.build()
    });
    refused_call(&mut w, err::ASSET_ROUTE_INVALID);
}

#[test]
fn a_flood_of_refused_fundings_leaves_no_entry_and_no_surplus() {
    let mut w = World::new();
    let buyer = w.user(0);
    let before = w.tokens(&buyer);
    let data_before = w.actor_data();
    for i in 0..12u8 {
        let payload = Actor::token_call([i; 32], [0xee; 32]).unwrap();
        w.fund(&buyer, PRICE, w.call_forward(), Some(payload));
    }
    assert_eq!(w.tokens(&buyer), before, "every refused funding came back");
    assert_eq!(w.ledger(), Default::default());
    assert_eq!(w.surplus(), 0);
    assert_eq!(w.native().returned_count, 0, "no returned entry");
    assert_eq!(w.native().locked_outcome_fees, 0);
    let data = w.actor_data();
    assert!(data.payout_dicts[0].is_none() && data.payout_dicts[1].is_none(), "nothing stored");
    assert_eq!(data.next_payout_id, data_before.next_payout_id + 12, "ids are never reused");
}

#[test]
fn accepting_tokens_is_false_at_the_global_returned_cap_and_reclassifies_nothing() {
    let mut w = World::new();
    let buyer = w.user(0);
    let a = w.call(&buyer);
    w.call(&buyer);
    w.patch(|d| d.returned_count = protocol_constants::MAX_RETURNED_GLOBAL);
    let ledger = w.ledger();
    refused_call(&mut w, err::NOT_ACCEPTING_TOKENS);
    assert_eq!(w.ledger(), ledger, "no money was reclassified");
    // Existing requests still settle.
    let owner = w.owner.clone();
    succeeded(&w.op(&owner, Actor::respond(1, a, [1; 32]).unwrap(), TOS));
    assert_eq!(w.ledger().pending, PRICE);
}

#[test]
fn a_sender_off_workchain_0_is_refused_and_its_return_becomes_a_returned_entry() {
    let mut w = World::new();
    // A wallet whose owner is a masterchain address, holding tokens.
    w.net.model.enabled = false;
    w.checking = true;
    let mc_owner = MsgAddressInt::with_params(-1, UInt256::from([0x61; 32])).unwrap();
    let init: StateInit = wallet_state_init(&w.net.minter(), &mc_owner);
    let wallet = w.net.deploy_initial(init, 0);
    w.net.patch_wallet(&mc_owner, |d| d.balance = 10 * PRICE);
    let actor = w.actor.clone();
    let terms = w.terms_hash();
    let forward = w.call_forward();
    let body = Actor::funding_transfer(3, PRICE, &actor, &mc_owner, forward, [1; 32], terms).unwrap();
    let msg = MessageBuilder::internal(&mc_owner, &wallet, forward as u64 + TOS).bounce(true).body(body).build();
    let start = w.net.delivered.len();
    w.send(msg);
    let logs = w.funding_logs_since(start);
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].reason as i32, err::INVALID_DESTINATION);
    // S refuses a destination off workchain 0: the return bounces and the
    // amount becomes a returned entry for its sender, never surplus.
    let outcomes = w.outcome_logs_since(start);
    assert_eq!(outcomes.len(), 1);
    assert_eq!((outcomes[0].kind, outcomes[0].outcome), (kind::FUNDING_RETURN, outcome::BOUNCED));
    let entry = w.returned(logs[0].payout_id).expect("a returned entry");
    assert_eq!((entry.caller, entry.amount, entry.paying), (mc_owner.clone(), PRICE, 0));
    assert_eq!(w.ledger().returned, PRICE);
    assert_eq!(w.surplus(), 0);
    // Its sender, off workchain 0, cannot claim it (1934).
    let funding = w.payout_funding();
    let tx = w.op(&mc_owner, Actor::claim_returned(1, logs[0].payout_id, &w.user(0)).unwrap(), funding);
    refused_with(&tx, err::INVALID_DESTINATION);
}
