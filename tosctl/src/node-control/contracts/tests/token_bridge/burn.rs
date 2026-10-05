/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Burns: owner -> wallet (hold) -> burn_admit -> minter -> burn_notice ->
//! bridge (LOG_BURN) -> burn_result -> minter -> burn_outcome -> wallet, and
//! the cancelled and refused ends: refund -> refund_recorded, admit_refused.

use chain_block::{IBitstring, Message, SliceData};

use crate::harness::*;

/// After user 0 minted 1 000 and burned 400: recorded, logged once.
pub fn assert_burned(net: &Net) {
    let user = net.user(0);
    assert_eq!(net.burn_logs(), 1, "LOG_BURN exactly once");
    assert_eq!(net.tokens(&user), 600);
    assert_eq!(net.held(&user, 0), -1, "the hold is gone");
    assert_eq!(net.supply_state(), (600, 0, 0, 0, 0));
    net.assert_no_settlement_bounce();
}

/// After user 0 minted 1 000 and the burn of 400 was cancelled or refused.
pub fn assert_returned(net: &Net) {
    let user = net.user(0);
    assert_eq!(net.burn_logs(), 0, "no LOG_BURN");
    assert_eq!(net.tokens(&user), 1_000, "the hold came back once");
    assert_eq!(net.held(&user, 0), -1);
    assert_eq!(net.supply_state(), (1_000, 0, 0, 0, 0));
    net.assert_no_settlement_bounce();
}

pub fn minted() -> Net {
    let mut net = Net::new();
    net.swap(1_000);
    net
}

/// The owner's own funded cancellation of user 0's burn b.
pub fn cancel_message(net: &Net, b: u64) -> Message {
    let user = net.user(0);
    let (need, _) = net.wallet_advance_cost(&user, advance::BURN);
    net.cancel_message(&user, b, need)
}

pub fn cancel(net: &mut Net, b: u64) -> chain_block::Transaction {
    let msg = cancel_message(net, b);
    net.send(msg)
}

/// T-B1: a burn, in one pass.
#[test]
fn t_b1_a_burn_is_recorded_once_and_logged_once() {
    let mut net = minted();
    net.start_burn(400);
    net.settle();
    assert_burned(&net);
}

/// T-B2: each message of the recorded path lost in turn, recovered by an
/// advance at the wallet at exactly its need (one unit less changes nothing),
/// and at the minter or the bridge where they hold the record.
#[test]
fn t_b2_each_lost_burn_message_is_recovered() {
    for op in [op::BURN_ADMIT, op::BURN_NOTICE, op::BURN_RESULT, op::BURN_OUTCOME] {
        let mut net = minted();
        let user = net.user(0);
        net.start_burn(400);
        net.drop_op(op);
        net.settle();
        assert_eq!(net.held(&user, 0), 400, "op {op}: the wallet still holds the burn");
        let (need, _) = net.wallet_advance_cost(&user, advance::BURN);
        let wallet = net.wallet_of(&user);
        let before = net.state_hashes();
        let short = net.advance_message(&wallet, advance::BURN, need - 1, |b| {
            b.append_u64(0).unwrap();
        });
        refused_with(&net.send(short), err("underfunded"));
        assert_eq!(net.state_hashes(), before, "op {op}: an underfunded advance changes nothing");
        let exact = net.advance_message(&wallet, advance::BURN, need, |b| {
            b.append_u64(0).unwrap();
        });
        succeeded(&net.send(exact));
        assert_burned(&net);
    }
    for op in [op::BURN_NOTICE, op::BURN_RESULT] {
        let mut net = minted();
        net.start_burn(400);
        net.drop_op(op);
        net.settle();
        let user = net.user(0);
        succeeded(&net.advance_minter(advance::BURN, &user, Some(0)));
        assert_burned(&net);
    }
    let mut net = minted();
    net.start_burn(400);
    net.drop_op(op::BURN_RESULT);
    net.settle();
    succeeded(&net.advance_bridge_burn_result(0));
    assert_burned(&net);
}

/// T-B2: the cancelled path's refund and its report lost in turn.
#[test]
fn t_b2_lost_refund_messages_are_recovered() {
    for op in [op::REFUND, op::REFUND_RECORDED] {
        let mut net = minted();
        net.start_burn(400);
        net.drop_op(op::BURN_NOTICE);
        net.settle();
        let msg = cancel_message(&net, 0);
        net.queue.push_back(msg);
        net.drop_op(op);
        net.settle();
        let user = net.user(0);
        succeeded(&net.advance_minter(advance::BURN, &user, Some(0)));
        assert_returned(&net);
    }
}

/// T-B2 and T-Y1: the refused admission's answer lost and recovered, and the
/// refusal durable after capacity returns: never an admission, released once.
#[test]
fn t_b2_t_y1_a_refused_admission_stays_refused_after_capacity_returns() {
    let mut net = Net::new();
    let window = declared("BURN_WINDOW") as usize;
    for i in 0..4 {
        let u = net.user(i);
        net.swap_to(&u, 1_000);
    }
    let mut held = Vec::new();
    for i in 0..window {
        let u = net.user(i % 4);
        net.start_burn_from(&u, 10);
        held.push(net.drop_op(op::BURN_NOTICE));
        net.settle();
    }
    let user = net.user(0);
    let b = net.wallet_state(&user)[6] as u64;
    net.start_burn_from(&user, 100);
    let refusal = net.drop_op(op::ADMIT_REFUSED);
    net.settle();
    assert_eq!(net.minter_burn(&user, b).1, burn_status::ADMIT_REFUSED);
    assert_eq!(net.held(&user, b), 100, "the answer was lost: still held");
    for m in held {
        net.send(m);
    }
    // capacity is back; the wallet asks again and is refused again
    succeeded(&net.advance_wallet(&user, advance::BURN, Some(b)));
    assert_eq!(net.held(&user, b), -1, "released");
    assert_eq!(net.minter_burn(&user, b).1, burn_status::ADMIT_REFUSED);
    let logs = net.burn_logs();
    let tokens = net.tokens(&user);
    net.send(refusal);
    assert_eq!((net.burn_logs(), net.tokens(&user)), (logs, tokens), "released once");
    assert_eq!(logs, window, "only the admitted burns logged");
}

/// T-B3: a gas rise before each burn leg stops it cleanly; an advance at the
/// new price completes the burn.
#[test]
fn t_b3_a_gas_rise_before_each_burn_leg_stops_it_cleanly() {
    for (op, masterchain) in [
        (op::BURN_ADMIT, false),
        (op::BURN_NOTICE, true),
        (op::BURN_RESULT, false),
        (op::BURN_OUTCOME, false),
    ] {
        let mut net = minted();
        net.start_burn(400);
        let held = net.intercept(|m| body_op(m) == Some(op));
        let price = net.gas_price(masterchain);
        net.set_gas_price(masterchain, price * 1_000);
        let before = net.state_hashes();
        stopped_for_funds(&net.send_one(held));
        assert_unchanged(&net, &before, &format!("op {op}"));
        net.settle();
        let user = net.user(0);
        succeeded(&net.advance_wallet(&user, advance::BURN, Some(0)));
        assert_burned(&net);
    }
}

/// T-B4: ConfigParam 79 removed after the burn started, and burns suspended:
/// the burn completes, new burns are refused, and the owner may still cancel.
#[test]
fn t_b4_burns_complete_without_configparam_79_and_while_suspended() {
    let mut net = minted();
    let from = net.delivered.len();
    net.start_burn(400);
    net.deliver_one();
    net.remove_config();
    net.drop_op(op::BURN_RESULT);
    net.settle();
    let user = net.user(0);
    succeeded(&net.advance_wallet(&user, advance::BURN, Some(0)));
    assert_burned(&net);
    assert_eq!(net.exits_since(from, 666), 0);

    let mut net = minted();
    net.start_burn(400);
    net.deliver_one();
    net.state_flags = 1; // burns suspended
    net.configure();
    net.drop_op(op::BURN_NOTICE);
    net.settle();
    succeeded(&cancel(&mut net, 0));
    assert_returned(&net);
    let user = net.user(0);
    let refused = net.burn_message(&user, 100, net.burn_fee);
    refused_with(&net.send(refused), declared("error::operation_suspended") as i32);
}

/// T-B5: the bridge decides each burn once. A cancellation wins only against a
/// notice that has not executed; both flags in either order give exactly one of
/// LOG_BURN and a refund; a stranger cannot cancel.
#[test]
fn t_b5_recorded_or_cancelled_once_never_both() {
    // (a) the notice lost, then cancelled; the old notice delivered after
    let mut net = minted();
    net.start_burn(400);
    let old = net.drop_op(op::BURN_NOTICE);
    net.settle();
    succeeded(&cancel(&mut net, 0));
    assert_returned(&net);
    net.send(old);
    assert_returned(&net);

    // (b) after RECORDED there is nothing to cancel
    let mut net = minted();
    net.start_burn(400);
    net.settle();
    refused_with(&cancel(&mut net, 0), err("nothing_to_advance"));
    assert_burned(&net);

    // (c) the admission lost, then the held burn cancelled
    let mut net = minted();
    net.start_burn(400);
    net.drop_op(op::BURN_ADMIT);
    net.settle();
    succeeded(&cancel(&mut net, 0));
    assert_returned(&net);

    // (d) both flags queued, in both orders
    for recorded_first in [true, false] {
        let mut net = minted();
        net.start_burn(400);
        let plain = net.drop_op(op::BURN_NOTICE);
        net.settle();
        let msg = cancel_message(&net, 0);
        net.queue.push_back(msg);
        let cancelling = net.drop_op(op::BURN_NOTICE);
        net.settle();
        let (first, second) = if recorded_first { (plain, cancelling) } else { (cancelling, plain) };
        net.send(first);
        net.send(second);
        if recorded_first {
            assert_burned(&net);
        } else {
            assert_returned(&net);
        }
    }

    // (e) a stranger cannot cancel
    let mut net = minted();
    net.start_burn(400);
    net.drop_op(op::BURN_NOTICE);
    net.settle();
    let wallet = net.wallet_of(&net.user(0));
    let stranger = net.stranger.address().clone();
    let msg = forged(&stranger, &wallet, TOS, cell(|x| {
        x.append_u32(op::CANCEL_BURN).unwrap().append_u64(0).unwrap();
        x.append_u64(0).unwrap();
    }));
    refused_with(&net.send(msg), err("not_owner"));
}

/// T-B6: every burn message delivered twice in flight and again after
/// completion, and after cancellation: no second log, refund, debit or supply
/// transition.
#[test]
fn t_b6_old_burn_messages_repeat_no_effect() {
    let mut net = minted();
    net.start_burn(400);
    let seen = crate::mint::settle_doubled(&mut net);
    assert_burned(&net);
    for m in seen {
        net.send(m);
    }
    assert_burned(&net);

    let mut net = minted();
    net.start_burn(400);
    net.drop_op(op::BURN_NOTICE);
    net.settle();
    let msg = cancel_message(&net, 0);
    net.queue.push_back(msg);
    let seen = crate::mint::settle_doubled(&mut net);
    assert_returned(&net);
    for m in seen {
        net.send(m);
    }
    assert_returned(&net);
}

/// T-B7: bounces cannot refund. Bounced copies of the burn's messages change
/// nothing.
#[test]
fn t_b7_bounces_cannot_refund() {
    let mut net = minted();
    net.start_burn(400);
    let mut copies = Vec::new();
    while let Some(m) = net.queue.pop_front() {
        if body_op(&m).is_some_and(|op| (40..=63).contains(&op)) {
            copies.push(bounced_copy(&m));
        }
        net.execute(m);
    }
    assert_burned(&net);
    for b in copies {
        let before = net.state_hashes();
        net.send(b);
        assert_eq!(net.state_hashes(), before, "a bounce changed settlement state");
    }
    assert_burned(&net);
}

/// A burn notice like `m`, from its minter, with another amount in its
/// descriptor.
pub fn notice_with_amount(m: &Message, amount: u128) -> chain_block::Cell {
    let mut s = settlement_body(m);
    let mut b = chain_block::BuilderData::new();
    // op, query, two lives, m, cancel, floor
    let bits = 32 + 64 + 64 + 64 + 64 + 1 + 64;
    let head = s.get_next_bits(bits).unwrap();
    b.append_raw(&head, bits).unwrap();
    let mut d = SliceData::load_cell(s.reference(0).unwrap()).unwrap();
    let tag = d.get_next_u32().unwrap();
    let bn = d.get_next_u64().unwrap();
    let _ = <chain_block::Coins as chain_block::Deserializable>::construct_from(&mut d).unwrap();
    let dest = d.get_next_bits(160).unwrap();
    let r = d.reference(0).unwrap();
    b.checked_append_reference(cell(|x| {
        x.append_u32(tag).unwrap();
        x.append_u64(bn).unwrap();
        coins(x, amount);
        x.append_raw(&dest, 160).unwrap();
        x.checked_append_reference(r.clone()).unwrap();
    }))
    .unwrap();
    b.into_cell().unwrap()
}

/// T-B8: a reused burn number with altered fields is refused and logs nothing.
#[test]
fn t_b8_a_reused_burn_identity_with_other_fields_is_refused() {
    let mut net = minted();
    net.start_burn(400);
    let old = net.drop_op(op::BURN_NOTICE);
    net.settle();
    succeeded(&cancel(&mut net, 0));
    assert_returned(&net);
    let minter = net.minter();
    let bridge = net.bridge.clone();
    let before = net.state_hashes();
    let forged_notice = forged(&minter, &bridge, 10 * TOS, notice_with_amount(&old, 999));
    refused_with(&net.send(forged_notice), err("operation_mismatch"));
    assert_eq!(net.state_hashes(), before);
    assert_eq!(net.burn_logs(), 0);
}

/// A burn admission like `m` with another amount in its descriptor and its
/// cancellation flag set.
fn admission_with_amount(m: &Message, amount: u128) -> chain_block::Cell {
    let mut s = settlement_body(m);
    let bits = s.remaining_bits();
    let mut head = s.get_next_slice(bits).unwrap();
    let mut b = chain_block::BuilderData::new();
    // op, query, two lives, then the cancellation flag
    let front = head.get_next_bits(32 + 64 + 64 + 64).unwrap();
    b.append_raw(&front, 32 + 64 + 64 + 64).unwrap();
    head.get_next_bit().unwrap();
    b.append_bit_one().unwrap();
    let rest = head.remaining_bits();
    let tail = head.get_next_bits(rest).unwrap();
    b.append_raw(&tail, rest).unwrap();
    let mut d = SliceData::load_cell(s.reference(0).unwrap()).unwrap();
    let tag = d.get_next_u32().unwrap();
    let bn = d.get_next_u64().unwrap();
    let _ = <chain_block::Coins as chain_block::Deserializable>::construct_from(&mut d).unwrap();
    let dest = d.get_next_bits(160).unwrap();
    let r = d.reference(0).unwrap();
    b.checked_append_reference(cell(|x| {
        x.append_u32(tag).unwrap();
        x.append_u64(bn).unwrap();
        coins(x, amount);
        x.append_raw(&dest, 160).unwrap();
        x.checked_append_reference(r.clone()).unwrap();
    }))
    .unwrap();
    b.into_cell().unwrap()
}

/// T-B8: an admission repeating an admitted burn's number with another amount
/// is refused at the minter: it neither answers nor marks the burn for
/// cancellation.
#[test]
fn t_b8_a_reused_admission_with_other_fields_is_refused_by_the_minter() {
    let mut net = minted();
    let user = net.user(0);
    net.start_burn(400);
    net.drop_op(op::BURN_NOTICE);
    net.settle();
    let admission = net
        .delivered
        .iter()
        .rev()
        .find(|d| body_op(&d.msg) == Some(op::BURN_ADMIT))
        .map(|d| d.msg.clone())
        .expect("the admission was delivered");
    let wallet = net.wallet_of(&user);
    let minter = net.minter();
    let before = net.state_hashes();
    let altered = forged(&wallet, &minter, 10 * TOS, admission_with_amount(&admission, 999));
    refused_with(&net.send(altered), err("operation_mismatch"));
    assert_eq!(net.state_hashes(), before, "nothing marked");
    assert_eq!(net.minter_burn(&user, 0).2, 0, "no cancellation requested");
}
