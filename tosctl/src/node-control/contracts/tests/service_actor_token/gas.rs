/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The gas rule (USDC settlement design 2.3, 4.4) and the actor's gas
//! constants.
//!
//! No handler may raise its gas limit before its sender is authenticated, or
//! before its message pays for the raised gas. Each handler is sent forged and
//! underfunded messages, and the actor's TOS balance, excluding the message's
//! own value, never falls. The gas constants are each held to twice the most
//! measured with every dictionary at its deepest shape; with
//! TOKEN_BRIDGE_TRACE_DIR set the native engine replays every measured
//! transaction and must report the same gas.

use std::collections::BTreeMap;

use chain_block::{
    Cell, Coins, HashmapE, HashmapType, IBitstring, Message, MsgAddressInt, Serializable, SliceData,
};
use contracts::service_actor_token::{ServiceActorTokenContract as Actor, kind};
use tos_sandbox::MessageBuilder;

use crate::harness::*;
use crate::payouts::{expired, prepare, returned_entry};
use crate::world::*;

/// Delivers `msg` alone and requires that it changed no state and spent none
/// of the actor's own TOS.
fn assert_no_drain(w: &mut World, msg: Message, what: &str) {
    let data = w.data_hash();
    let balance = w.balance(&w.actor);
    let value = value_of(&msg);
    let d = w.execute(msg);
    let o = outcome(&d.tx);
    // Only what this message carried may pay for its gas.
    let gas_fee =
        w.net.bc.config_params().gas_prices(false).unwrap().calc_gas_fee(o.gas_used).unwrap()
            as u128;
    assert!(gas_fee <= value, "{what}: {} gas costs more than the message brought", o.gas_used);
    // Drop whatever it caused: its own value's bounce or answer.
    w.net.queue.clear();
    assert_eq!(w.data_hash(), data, "{what}: no state changed");
    assert!(w.balance(&w.actor) >= balance, "{what}: the actor's own TOS paid for it");
}

fn body(build: impl FnOnce(&mut chain_block::BuilderData)) -> Cell {
    cell(build)
}

#[test]
fn no_handler_lets_a_forged_or_underfunded_message_spend_the_actors_tos() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let funding = w.payout_funding();
    // A live payout whose report is still to come.
    w.execute(w.op_message(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding));
    let actor = w.actor.clone();
    let report = w.intercept(|m| is_to(m, &actor) && body_op(m) == Some(OP_TRANSFER_DELIVERED));
    w.settle();
    let payout = w.counters().3 - 1;
    let p = w.payout(payout).unwrap();
    let stranger = w.net.stranger.address().clone();
    let small = 50_000_000u64; // what a sender might attach: buys some gas, not the raise

    let delivered = |q: u64, amount: u128, recipient: &MsgAddressInt| {
        body(|b| {
            b.append_u32(OP_TRANSFER_DELIVERED).unwrap().append_u64(q).unwrap();
            coins(b, amount);
            recipient.write_to(b).unwrap();
        })
    };
    let refused = |op: u32, q: u64, amount: u128| {
        body(|b| {
            b.append_u32(op).unwrap().append_u64(q).unwrap();
            coins(b, amount);
        })
    };
    let r_wallet = p.recipient_wallet.clone();
    let s_wallet = p.own_wallet.clone();
    let cases: Vec<(&str, MsgAddressInt, Cell, u64)> = vec![
        ("delivered from a stranger", stranger.clone(), delivered(payout, PRICE, &buyer), small),
        ("delivered from S", s_wallet.clone(), delivered(payout, PRICE, &buyer), small),
        ("delivered, wrong amount", r_wallet.clone(), delivered(payout, PRICE - 1, &buyer), small),
        (
            "delivered, wrong recipient",
            r_wallet.clone(),
            delivered(payout, PRICE, &stranger),
            small,
        ),
        (
            "delivered, unknown payout",
            r_wallet.clone(),
            delivered(payout + 7, PRICE, &buyer),
            small,
        ),
        (
            "delivered, forged shape, underfunded",
            stranger.clone(),
            delivered(payout, PRICE, &buyer),
            1_000_000,
        ),
        (
            "refused from a stranger",
            stranger.clone(),
            refused(OP_TRANSFER_REFUSED, payout, PRICE),
            small,
        ),
        ("refused from R", r_wallet.clone(), refused(OP_TRANSFER_REFUSED, payout, PRICE), small),
        (
            "refused, unknown payout, stranger",
            stranger.clone(),
            refused(OP_TRANSFER_REFUSED, payout + 9, 1),
            small,
        ),
        (
            "rereported from a stranger",
            stranger.clone(),
            refused(OP_TRANSFER_REREPORTED, payout, PRICE),
            small,
        ),
        (
            "rereported, unknown, stranger",
            stranger.clone(),
            refused(OP_TRANSFER_REREPORTED, payout + 9, 1),
            small,
        ),
        (
            "refused, forged shape, underfunded",
            stranger.clone(),
            refused(OP_TRANSFER_REFUSED, payout, PRICE),
            1_000_000,
        ),
        ("take_balance from a stranger", stranger.clone(), refused(OP_TAKE_BALANCE, 1, 5), small),
        ("take_balance from S, no query", s_wallet.clone(), refused(OP_TAKE_BALANCE, 1, 5), small),
        (
            "notification from a stranger",
            stranger.clone(),
            body(|b| {
                b.append_u32(OP_TRANSFER_NOTIFICATION).unwrap().append_u64(1).unwrap();
                coins(b, PRICE);
                buyer.write_to(b).unwrap();
                b.append_bit_zero().unwrap();
            }),
            small,
        ),
        ("excesses", stranger.clone(), refused(OP_EXCESSES, 1, 0), small),
    ];
    for (what, from, b, value) in cases {
        let msg = MessageBuilder::internal(&from, &actor, value).bounce(false).body(b).build();
        assert_no_drain(&mut w, msg, what);
    }
    // A forged bounce of the actor's reported transfer from anyone but S.
    let reported = cell(|b| {
        b.append_u32(OP_REPORTED_TRANSFER).unwrap().append_u64(payout).unwrap();
        coins(b, PRICE);
    });
    for (what, from) in
        [("a bounce from a stranger", stranger.clone()), ("a bounce from R", r_wallet.clone())]
    {
        let mut msg = bounced_copy(
            &MessageBuilder::internal(&actor, &from, small).body(reported.clone()).build(),
        );
        if let Some(h) = msg.int_header_mut() {
            h.value = chain_block::CurrencyCollection::with_coins(small);
        }
        assert_no_drain(&mut w, msg, what);
    }
    // Every op of the actor, underfunded or by the wrong sender.
    let owner = w.owner.clone();
    let ops: Vec<(&str, MsgAddressInt, Cell)> = vec![
        ("respond by a stranger", stranger.clone(), Actor::respond(1, 0, [0; 32]).unwrap()),
        ("expire of nothing", stranger.clone(), Actor::expire(1, 99).unwrap()),
        ("claim_refund of nothing", buyer.clone(), Actor::claim_refund(1, 99, &buyer).unwrap()),
        ("sweep of nothing", stranger.clone(), Actor::sweep_expired_request(1, 99).unwrap()),
        ("claim_returned of nothing", buyer.clone(), Actor::claim_returned(1, 99, &buyer).unwrap()),
        ("sweep_returned of nothing", stranger.clone(), Actor::sweep_returned(1, 99).unwrap()),
        ("recheck of nothing", stranger.clone(), Actor::recheck_payout(1, 99).unwrap()),
        ("recheck too early", stranger.clone(), Actor::recheck_payout(1, payout).unwrap()),
        ("update_policy by a stranger", stranger.clone(), Actor::revoke_attestor(1).unwrap()),
        ("withdraw by a stranger", stranger.clone(), Actor::withdraw_revenue(1, 0, 0).unwrap()),
        ("recover by a stranger", stranger.clone(), Actor::recover_surplus(1, 1).unwrap()),
        ("abandon by a stranger", stranger.clone(), Actor::abandon_payout(1, payout).unwrap()),
        ("recover underfunded", owner.clone(), Actor::recover_surplus(1, 1).unwrap()),
        ("withdraw underfunded", owner.clone(), Actor::withdraw_revenue(1, 0, 0).unwrap()),
        (
            "unknown op",
            stranger.clone(),
            body(|b| {
                b.append_u32(0x5356_4301).unwrap().append_u64(1).unwrap();
            }),
        ),
    ];
    for (what, from, b) in ops {
        let msg = MessageBuilder::internal(&from, &actor, small).bounce(true).body(b).build();
        assert_no_drain(&mut w, msg, what);
    }
    // The genuine report still settles the payout.
    w.send(report);
    assert!(w.payout(payout).is_none());
}

#[test]
fn the_source_raises_gas_only_in_the_authenticated_outcome_handlers() {
    let source = std::fs::read_to_string(actor_source()).unwrap();
    let code: Vec<&str> = source.lines().map(|l| l.split(";;").next().unwrap_or("")).collect();
    assert!(!code.iter().any(|l| l.contains("accept_message")), "no accept_message");
    let raises: Vec<usize> = code
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("set_gas_limit"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(raises.len(), 3, "one raise in each outcome handler");
    for i in raises {
        assert_eq!(code[i].trim(), "set_gas_limit(OUTCOME_HANDLER_GAS);");
        // Within the handler, before the raise: the payout lookup and the
        // sender comparison against the stored wallet.
        let before = code[i.saturating_sub(25)..i].join("\n");
        assert!(before.contains("peek_payout("), "the raise follows the payout lookup");
        assert!(
            before.contains("equal_slice_bits(sender, own_wallet)")
                || before.contains("equal_slice_bits(sender, recipient_wallet)"),
            "the raise follows the sender check:\n{before}"
        );
        assert!(before.contains("!= amount"), "the raise follows the amount check");
    }
}

// ---- gas at capacity ------------------------------------------------------------------

/// Every 64-bit dictionary gets copies of one of its entries at the keys `2^i`
/// (i from 20), and every 256-bit counter dictionary copies of each entry at
/// keys differing in one of the top 48 bits: every lookup of a real key walks
/// a fork per copy, deeper than any sequence of ids or any hashed callers
/// would make it.
fn deepen(d: &Option<Cell>, bits: usize) -> Option<Cell> {
    let root = d.as_ref()?;
    let mut map = HashmapE::with_hashmap(bits, Some(root.clone()));
    let mut entries: Vec<(SliceData, SliceData)> = Vec::new();
    map.iterate_slices(|k, v| {
        entries.push((k, v));
        Ok(true)
    })
    .unwrap();
    for (key, value) in &entries {
        let key_bytes = key.get_bytestring(0);
        for i in 0..48usize {
            let mut k = key_bytes.clone();
            if bits == 64 {
                let mut n = u64::from_be_bytes(k[..8].try_into().unwrap());
                n |= 1u64 << (20 + i % 44);
                k[..8].copy_from_slice(&n.to_be_bytes());
            } else {
                k[i / 8] ^= 0x80 >> (i % 8);
            }
            let key = SliceData::from_raw(k, bits);
            if map.get(key.clone()).unwrap().is_none() {
                map.set(key, value).unwrap();
            }
        }
    }
    map.data().cloned()
}

fn at_capacity(w: &mut World) {
    at_capacity_with(w, true);
}

/// With `wide_tokens` the token revenue is widened too; a surplus recovery
/// needs it left as it is, or no surplus remains to pay.
fn at_capacity_with(w: &mut World, wide_tokens: bool) {
    w.checking = false;
    w.patch(|d| {
        for i in 0..3 {
            d.requests[i] = deepen(&d.requests[i], if i == 2 { 256 } else { 64 });
            d.payout_dicts[i] = deepen(&d.payout_dicts[i], if i == 2 { 256 } else { 64 });
        }
        // wide accounting: coin fields at their widest
        d.tos[0] = d.tos[0].max(1 << 100);
        if wide_tokens {
            d.token[4] = d.token[4].max(1 << 100);
        }
    });
    let actor = w.actor.clone();
    w.net.set_balance(&actor, 1_000_000 * u128::from(TOS));
}

#[derive(Default)]
struct Gas(BTreeMap<String, u64>);

impl Gas {
    fn take(&mut self, w: &World, start: usize, name: &str) {
        for d in w.actor_txs_since(start) {
            let label = label_of(&d.msg);
            if ["52544431", "52544631", "52545232", "bounce:52545231"].contains(&label.as_str()) {
                assert!(
                    !outcome(&d.tx).aborted,
                    "{name}: the outcome handler {label} completed at capacity"
                );
            }
            let e = self.0.entry(format!("{name} [{}]", label_of(&d.msg))).or_insert(0);
            *e = (*e).max(outcome(&d.tx).gas_used);
        }
    }
}

/// A world with one of every kind of entry, deepened.
fn populated(code: Option<Cell>) -> World {
    let mut w = World::with(Options { code, ..Options::default() });
    let buyer = w.user(0);
    w.call(&buyer);
    expired(&mut w, &buyer);
    returned_entry(&mut w, &buyer);
    w.call(&w.user(1));
    w
}

/// Every op's gas, and every outcome handler's, at capacity.
fn measure(code: Option<Cell>) -> BTreeMap<String, u64> {
    let mut gas = Gas::default();
    for k in [
        kind::REFUND,
        kind::SWEEP,
        kind::REVENUE,
        kind::FUNDING_RETURN,
        kind::RETURNED_CLAIM,
        kind::SURPLUS,
        kind::RETURNED_SWEEP,
    ] {
        for way in 0..3 {
            let mut w = populated(code.clone());
            let case = prepare(&mut w, k);
            at_capacity_with(&mut w, k != kind::SURPLUS);
            let start = match way {
                0 => {
                    let s = w.net.delivered.len();
                    w.send(case.msg);
                    s
                }
                1 => w.refusing_at_r(case.msg, false),
                _ => w.bouncing_at_s(case.msg),
            };
            gas.take(&w, start, &format!("kind {k} way {way}"));
        }
    }
    // The lifecycle ops and the absent-payout answers, with ConfigParam 84 at
    // its 16-entry cap and the actor's master its last entry.
    let mut w = populated(code.clone());
    at_capacity(&mut w);
    w.recognize_among(15);
    let buyer = w.user(0);
    let owner = w.owner.clone();
    let start = w.net.delivered.len();
    let id = w.counters().0;
    w.fund(&buyer, PRICE, w.call_forward(), Some(w.token_call([1; 32])));
    w.fund(&buyer, PRICE + 1, w.call_forward(), Some(w.token_call([1; 32])));
    w.op(&owner, Actor::respond(1, id, [1; 32]).unwrap(), TOS);
    let id = w.counters().0;
    w.fund(&buyer, PRICE, w.call_forward(), Some(w.token_call([1; 32])));
    w.advance(SLA);
    w.op(&buyer, Actor::expire(1, id).unwrap(), TOS);
    let filler = owner.clone();
    w.op(
        &owner,
        Actor::update_policy(
            1,
            PRICE,
            STORAGE_FEE,
            BOUNTY,
            SLA,
            WINDOW,
            true,
            true,
            None,
            &filler,
            0,
            contracts::service_actor_token::protocol_constants::NO_TOKEN_CAP,
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap(),
        TOS,
    );
    w.op(&owner, Actor::revoke_attestor(1).unwrap(), TOS);
    w.op(&owner, Actor::withdraw_revenue(1, 0, 1).unwrap(), w.payout_funding());
    w.fill_refusals(3, 0x4000_0000_0000_0000);
    let rereport = w.get("get_rereport_funding", vec![]).int_at(0) as u64;
    let stranger = w.net.stranger.address().clone();
    let msg = w.net.wallet_query(
        &stranger,
        &w.actor.clone(),
        OP_REREPORT_REFUSAL,
        0x4000_0000_0000_0001,
        rereport,
    );
    w.send(msg);
    gas.take(&w, start, "lifecycle");
    gas.0
}

fn max_of(gas: &BTreeMap<String, u64>, label: &str) -> u64 {
    gas.iter().filter(|(k, _)| k.contains(label)).map(|(_, v)| *v).max().unwrap_or(0)
}

#[test]
fn gas_at_capacity_is_within_every_constant() {
    let gas = measure(None);
    for (k, v) in &gas {
        println!("gas {v:>7} {k}");
    }
    let outcome_handlers = ["[52544431]", "[52544631]", "[52545232]", "[bounce:52545231]"];
    let outcome = outcome_handlers.iter().map(|l| max_of(&gas, l)).max().unwrap();
    let admission = max_of(&gas, "[7362d09c]");
    let absent = gas
        .iter()
        .filter(|(k, _)| k.starts_with("lifecycle") && k.contains("[52545232]"))
        .map(|(_, v)| *v)
        .max()
        .unwrap();
    println!("OUTCOME {outcome} ADMISSION {admission} ABSENT {absent}");
    let declared = |n: &str| actor_constant(n) as u64;
    assert!(
        2 * outcome <= declared("OUTCOME_HANDLER_GAS"),
        "OUTCOME_HANDLER_GAS: {outcome} measured"
    );
    assert!(2 * admission <= declared("ADMISSION_GAS"), "ADMISSION_GAS: {admission} measured");
    assert!(2 * absent <= declared("ABSENT_REPORT_GAS"), "ABSENT_REPORT_GAS: {absent} measured");
}

#[test]
fn pre_accept_gas_at_capacity_is_within_its_constant() {
    // Each outcome handler's path up to its raise, at capacity: messages from
    // the genuine wallets, naming a live payout, that pass every comparison
    // but the last one, so the handler reads and compares everything and
    // stops where it would raise its limit.
    let mut most = 0u64;
    for k in [kind::REFUND, kind::SWEEP, kind::RETURNED_CLAIM] {
        let mut w = populated(None);
        let case = prepare(&mut w, k);
        w.execute(case.msg);
        let actor = w.actor.clone();
        let report = w.intercept(|m| is_to(m, &actor) && body_op(m) == Some(OP_TRANSFER_DELIVERED));
        w.settle();
        at_capacity(&mut w);
        let id = w.counters().3 - 1;
        let p = w.payout(id).unwrap();
        let value = 10 * TOS;
        let delivered = cell(|b| {
            b.append_u32(OP_TRANSFER_DELIVERED).unwrap().append_u64(id).unwrap();
            coins(b, p.amount);
            w.owner.write_to(b).unwrap(); // not the recipient: the last comparison
        });
        let refused = |op: u32| {
            cell(|b| {
                b.append_u32(op).unwrap().append_u64(id).unwrap();
                coins(b, p.amount + 1); // not the amount: the last comparison
            })
        };
        let bounce = {
            let original = cell(|b| {
                b.append_u32(OP_REPORTED_TRANSFER).unwrap().append_u64(id).unwrap();
                coins(b, p.amount + 1);
            });
            let mut m = bounced_copy(
                &MessageBuilder::internal(&actor, &p.own_wallet, value).body(original).build(),
            );
            if let Some(h) = m.int_header_mut() {
                h.value = chain_block::CurrencyCollection::with_coins(value);
            }
            m
        };
        let msgs = vec![
            (
                "delivered",
                MessageBuilder::internal(&p.recipient_wallet, &actor, value)
                    .bounce(false)
                    .body(delivered)
                    .build(),
            ),
            (
                "refused",
                MessageBuilder::internal(&p.own_wallet, &actor, value)
                    .bounce(false)
                    .body(refused(OP_TRANSFER_REFUSED))
                    .build(),
            ),
            (
                "rereported",
                MessageBuilder::internal(&p.own_wallet, &actor, value)
                    .bounce(false)
                    .body(refused(OP_TRANSFER_REREPORTED))
                    .build(),
            ),
            ("bounce", bounce),
        ];
        for (name, msg) in msgs {
            let d = w.execute(msg);
            succeeded(&d.tx);
            let g = outcome(&d.tx).gas_used;
            println!("PRE_ACCEPT kind {k} {name} {g}");
            most = most.max(g);
            w.net.queue.clear();
        }
        assert!(w.payout(id).is_some(), "no near-miss raised the limit or settled the payout");
        w.send(report);
    }
    assert!(2 * most <= actor_constant("PRE_ACCEPT_GAS") as u64, "PRE_ACCEPT_GAS: {most} measured");
}

#[test]
fn an_authenticated_underfunded_notification_spends_none_of_the_actors_tos() {
    // The real wallet path: a buyer's transfer whose notification carries too
    // little. The actor's balance never falls below its value before the
    // message, and the log is sent only when the message pays for it.
    let mut w = World::new();
    let buyer = w.user(0);
    w.call(&buyer);
    let allowance = w.prices().1;
    for (forward, logged) in [
        (1u128, false),
        (allowance / 2, false),
        (allowance - 1, false),
        (allowance, true),
        (w.min_funding() - 1, true),
    ] {
        let balance = w.balance(&w.actor);
        let start = w.fund(&buyer, PRICE, forward, Some(w.token_call([1; 32])));
        let txs = w.actor_txs_since(start);
        assert_eq!(txs.len(), 1, "forward {forward}: the notification reached the actor");
        assert!(w.balance(&w.actor) >= balance, "forward {forward}: the actor paid for it");
        assert_eq!(!w.funding_logs_since(start).is_empty(), logged, "forward {forward}");
    }
}
