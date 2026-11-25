/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Mutation controls for the gas rule and the outcome handlers'
//! authentication guards.
//!
//! Each row removes one guard from a copy of the actor's source, or raises the
//! gas limit before the guards, compiles that test-only build, and sends the
//! forged message the guard exists for. The release code refuses it, changing
//! no state and spending none of the actor's TOS; the mutant must not. A guard
//! whose removal no message exposes would fail its row. No source in the
//! checkout is changed: every mutant is compiled from a staged copy.

use chain_block::{Cell, IBitstring, Message, MsgAddressInt, Serializable};
use contracts::service_actor_token::ServiceActorTokenContract as Actor;
use tos_sandbox::MessageBuilder;

use crate::harness::*;
use crate::payouts::expired;
use crate::world::*;

#[derive(Clone, Copy, Debug)]
enum Handler {
    Delivered,
    Refused,
    Bounce,
}

#[derive(Clone, Copy, Debug)]
enum Forgery {
    /// Every field right, sent by someone other than the guarded wallet.
    WrongSender,
    /// Sent from the guarded wallet's address, the amount (and for a delivery
    /// the recipient) wrong.
    WrongFields,
    /// The sender wrong and too little value to pay for the handler.
    Underfunded,
}

struct Row {
    name: &'static str,
    handler: Handler,
    forgery: Forgery,
    from: &'static str,
    to: &'static str,
}

const SET_GAS: &str = "      set_gas_limit(OUTCOME_HANDLER_GAS);\n";

const ROWS: &[Row] = &[
    Row {
        name: "delivered: sender check removed",
        handler: Handler::Delivered,
        forgery: Forgery::WrongSender,
        from: "if ((~ equal_slice_bits(sender, recipient_wallet)) | (reported_amount != amount)",
        to: "if ((reported_amount != amount)",
    },
    Row {
        name: "delivered: amount and recipient checks removed",
        handler: Handler::Delivered,
        forgery: Forgery::WrongFields,
        from: "    if ((~ equal_slice_bits(sender, recipient_wallet)) | (reported_amount != amount)\n        | (~ equal_slice_bits(reported_recipient, recipient))) {",
        to: "    if (~ equal_slice_bits(sender, recipient_wallet)) {",
    },
    Row {
        name: "delivered: gas raised before the checks",
        handler: Handler::Delivered,
        forgery: Forgery::Underfunded,
        from: "  if (op == op::transfer_delivered) {\n",
        to: "  if (op == op::transfer_delivered) {\n      set_gas_limit(OUTCOME_HANDLER_GAS);\n",
    },
    Row {
        name: "refused: sender check removed",
        handler: Handler::Refused,
        forgery: Forgery::WrongSender,
        from: "     slice own_wallet, int lock, cell undo) = unpack_payout(stored);\n    if (~ equal_slice_bits(sender, own_wallet)) {\n      return ();\n    }\n",
        to: "     slice own_wallet, int lock, cell undo) = unpack_payout(stored);\n",
    },
    Row {
        name: "refused: amount check removed",
        handler: Handler::Refused,
        forgery: Forgery::WrongFields,
        from: "    if (reported_amount != amount) {\n      ;; Query ids",
        to: "    if (false) {\n      ;; Query ids",
    },
    Row {
        name: "refused: gas raised before the checks",
        handler: Handler::Refused,
        forgery: Forgery::Underfunded,
        from: "  if ((op == op::transfer_refused) | (op == op::transfer_rereported)) {\n",
        to: "  if ((op == op::transfer_refused) | (op == op::transfer_rereported)) {\n      set_gas_limit(OUTCOME_HANDLER_GAS);\n",
    },
    Row {
        name: "bounce: sender check removed",
        handler: Handler::Bounce,
        forgery: Forgery::WrongSender,
        from: "      if (~ equal_slice_bits(sender, own_wallet)) {\n        return ();\n      }\n      if (in_msg~load_coins() != amount) {",
        to: "      if (in_msg~load_coins() != amount) {",
    },
    Row {
        name: "bounce: amount check removed",
        handler: Handler::Bounce,
        forgery: Forgery::WrongFields,
        from: "      if (in_msg~load_coins() != amount) {\n        return ();\n      }\n",
        to: "",
    },
    Row {
        name: "bounce: gas raised before the checks",
        handler: Handler::Bounce,
        forgery: Forgery::Underfunded,
        from: "    if (bounced_op == op::reported_transfer) {\n",
        to: "    if (bounced_op == op::reported_transfer) {\n      set_gas_limit(OUTCOME_HANDLER_GAS);\n",
    },
];

/// A world running `code` (or the release) with a live refund payout whose
/// report is still to come; returns the payout's id.
fn with_live_payout(code: Option<Cell>) -> (World, u64) {
    let mut w = World::with(Options { code, ..Options::default() });
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let funding = w.payout_funding();
    w.execute(w.op_message(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding));
    let actor = w.actor.clone();
    w.intercept(|m| is_to(m, &actor) && body_op(m) == Some(OP_TRANSFER_DELIVERED));
    w.settle();
    let payout = w.counters().3 - 1;
    assert!(w.payout(payout).is_some());
    (w, payout)
}

fn forged_message(w: &World, payout: u64, handler: Handler, forgery: Forgery, gas: u64) -> Message {
    let p = w.payout(payout).unwrap();
    let stranger = w.net.stranger.address().clone();
    let actor = w.actor.clone();
    // Four fifths of the gas the release spends on this path: reaches the
    // handler's raise, not its end.
    let underfunded =
        w.net.bc.config_params().gas_prices(false).unwrap().calc_gas_fee(gas * 4 / 5).unwrap()
            as u64;
    let value = if matches!(forgery, Forgery::Underfunded) { underfunded } else { TOS };
    let wrong = matches!(forgery, Forgery::WrongFields);
    let amount = if wrong { p.amount + 1 } else { p.amount };
    match handler {
        Handler::Delivered => {
            let from = if wrong { p.recipient_wallet.clone() } else { stranger };
            let recipient: MsgAddressInt =
                if wrong { w.owner.clone() } else { p.recipient.clone() };
            let body = cell(|b| {
                b.append_u32(OP_TRANSFER_DELIVERED).unwrap().append_u64(payout).unwrap();
                coins(b, amount);
                recipient.write_to(b).unwrap();
            });
            MessageBuilder::internal(&from, &actor, value).bounce(false).body(body).build()
        }
        Handler::Refused => {
            let from = if wrong { p.own_wallet.clone() } else { stranger };
            let body = cell(|b| {
                b.append_u32(OP_TRANSFER_REFUSED).unwrap().append_u64(payout).unwrap();
                coins(b, amount);
            });
            MessageBuilder::internal(&from, &actor, value).bounce(false).body(body).build()
        }
        Handler::Bounce => {
            let from = if wrong { p.own_wallet.clone() } else { stranger };
            let original = cell(|b| {
                b.append_u32(OP_REPORTED_TRANSFER).unwrap().append_u64(payout).unwrap();
                coins(b, amount);
            });
            let mut m = bounced_copy(
                &MessageBuilder::internal(&actor, &from, value).body(original).build(),
            );
            if let Some(h) = m.int_header_mut() {
                h.value = chain_block::CurrencyCollection::with_coins(value);
            }
            m
        }
    }
}

/// Whether delivering `msg` changed the actor's state or spent its own TOS.
fn exposed(w: &mut World, msg: Message) -> bool {
    let data = w.data_hash();
    let balance = w.balance(&w.actor);
    let value = value_of(&msg);
    let d = w.execute(msg);
    let o = outcome(&d.tx);
    println!(
        "  exposed? value {value} gas {} exit {:?} aborted {} balance {} -> {}",
        o.gas_used,
        o.exit_code,
        o.aborted,
        balance,
        w.balance(&w.actor)
    );
    w.net.queue.clear();
    w.data_hash() != data || w.balance(&w.actor) < balance
}

#[test]
fn every_outcome_guard_and_the_gas_rule_are_held_by_a_test() {
    let source = std::fs::read_to_string(actor_source()).unwrap();
    let _ = SET_GAS;
    for row in ROWS {
        assert_eq!(
            source.matches(row.from).count(),
            1,
            "{}: the guard text is found once",
            row.name
        );
        // The release code refuses the forgery.
        let (mut w, payout) = with_live_payout(None);
        w.checking = false;
        // The gas the release spends refusing a wrong sender on this handler.
        let probe = forged_message(&w, payout, row.handler, Forgery::WrongSender, 0);
        let gas = outcome(&w.execute(probe).tx).gas_used;
        w.net.queue.clear();
        let msg = forged_message(&w, payout, row.handler, row.forgery, gas);
        assert!(!exposed(&mut w, msg), "{}: the release code is exposed", row.name);
        // Without the guard, the same forgery gets through.
        let tag = row.name.replace([':', ' '], "-");
        let code = actor_variant(&tag, |s| s.replacen(row.from, row.to, 1));
        let (mut w, payout) = with_live_payout(Some(code));
        w.checking = false;
        let msg = forged_message(&w, payout, row.handler, row.forgery, gas);
        assert!(exposed(&mut w, msg), "{}: the mutant survives", row.name);
        println!("killed: {}", row.name);
    }
}
