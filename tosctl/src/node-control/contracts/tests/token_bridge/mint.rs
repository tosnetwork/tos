/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Mints: bridge -> prepare -> minter -> open/opened -> prepared -> commit ->
//! credit -> credit_recorded -> mint_completed.

use chain_block::{IBitstring, Deserializable, Message, MsgAddressInt, SliceData};

use crate::harness::*;

/// The state a completed mint of `amount` to user 0 leaves behind.
pub fn assert_minted(net: &Net, n: u64, amount: u128) {
    let user = net.user(0);
    assert_eq!(net.tokens(&user), amount, "the wallet holds the mint once");
    assert_eq!(net.supply_state(), (amount as i128, 0, 0, 0, 0), "supply counted once, nothing reserved");
    assert_eq!(net.channel()[10], 0, "nothing pending at the bridge");
    let state = net.swap_record(n).0;
    assert!(state == -1 || state == swap_state::CONSUMED, "the lock is consumed, not {state}");
    net.assert_no_settlement_bounce();
}

/// The ops of the mint path, each with the contract that receives it.
pub const MINT_LEGS: [(u32, &str); 8] = [
    (op::PREPARE, "minter"),
    (op::OPEN, "wallet"),
    (op::OPENED, "minter"),
    (op::PREPARED, "bridge"),
    (op::COMMIT, "minter"),
    (op::CREDIT, "wallet"),
    (op::CREDIT_RECORDED, "minter"),
    (op::MINT_COMPLETED, "bridge"),
];

/// T-M1: a mint to a new holder, in one pass.
#[test]
fn t_m1_a_mint_to_a_new_holder_completes_in_one_pass() {
    let mut net = Net::new();
    let user = net.user(0);
    let n = net.swap(1_000);
    assert_minted(&net, n, 1_000);
    let holder = net.holder(&user);
    assert_eq!(holder[2], holder_state::OPEN);
    assert_eq!(net.mint_status(0), -1, "counted and folded");
    assert_eq!(net.minter_channels()[3], 1, "the mint watermark passed s = 0");
}

fn bridge_mint_advance(net: &Net, value: u64) -> Message {
    let minter = net.minter();
    net.advance_message(&net.bridge.clone(), advance::MINT, value, |b| {
        b.append_raw(&account_hash(&minter), 256).unwrap();
        b.append_u64(0).unwrap();
    })
}

/// T-M2: each message of the mint path lost in turn, recovered by a funded
/// advance at the bridge with only the identifier and the funding. The advance
/// at exactly its need goes through; one unit less changes nothing.
#[test]
fn t_m2_each_lost_mint_message_is_recovered_by_an_advance_at_the_bridge() {
    for (op, _) in MINT_LEGS {
        let mut net = Net::new();
        let n = net.start_swap(1_000);
        net.drop_op(op);
        net.settle();
        let landed = matches!(op, op::CREDIT_RECORDED | op::MINT_COMPLETED);
        assert_eq!(net.tokens(&net.user(0)), if landed { 1_000 } else { 0 }, "op {op}");
        assert_eq!(net.channel()[10], 1, "op {op}: the bridge still holds the mint");

        let (need, _) = net.bridge_advance_cost(advance::MINT, 0);
        let before = net.state_hashes();
        let short = bridge_mint_advance(&net, need - 1);
        refused_with(&net.send(short), err("underfunded"));
        assert_eq!(net.state_hashes(), before, "op {op}: an underfunded advance changes nothing");

        let exact = bridge_mint_advance(&net, need);
        let from = net.delivered.len();
        succeeded(&net.send(exact));
        if net.tokens(&net.user(0)) != 1_000 {
            eprintln!("op {op}");
            for line in &net.delivered_log()[from..] {
                eprintln!("{line}");
            }
        }
        assert_minted(&net, n, 1_000);
    }
}

/// T-M2: the same losses recovered from the minter's or the wallet's own
/// record, wherever that contract holds one.
#[test]
fn t_m2_lost_mint_messages_are_recovered_by_advances_at_the_minter_and_wallet() {
    for op in [op::OPEN, op::OPENED, op::PREPARED, op::CREDIT, op::CREDIT_RECORDED] {
        let mut net = Net::new();
        let n = net.start_swap(1_000);
        net.drop_op(op);
        net.settle();
        succeeded(&net.advance_minter_mint(0));
        assert_minted(&net, n, 1_000);
    }
    let mut net = Net::new();
    let n = net.start_swap(1_000);
    net.drop_op(op::CREDIT_RECORDED);
    net.settle();
    let user = net.user(0);
    assert_eq!(net.supply_state(), (0, 1_000, 0, 0, 0), "landed and uncounted");
    succeeded(&net.advance_wallet(&user, advance::REPORT, Some(0)));
    assert_minted(&net, n, 1_000);
}

/// T-M3: a gas price rise before each leg stops it with no effect; an advance
/// funded at the new price completes the mint.
#[test]
fn t_m3_a_gas_rise_before_each_mint_leg_stops_it_cleanly_and_funded_recovery_completes() {
    for (op, receiver) in MINT_LEGS {
        let mut net = Net::new();
        let n = net.start_swap(1_000);
        let held = net.intercept(|m| body_op(m) == Some(op));
        let masterchain = receiver == "bridge";
        let price = net.gas_price(masterchain);
        net.set_gas_price(masterchain, price * 1_000);
        let before = net.state_hashes();
        let tx = net.send_one(held);
        stopped_for_funds(&tx);
        assert_unchanged(&net, &before, &format!("op {op}: the underfunded leg"));
        net.settle();
        let from = net.delivered.len();
        succeeded(&net.advance_bridge_mint(0));
        if net.tokens(&net.user(0)) != 1_000 {
            eprintln!("op {op}");
            for l in &net.delivered_log()[from..] {
                eprintln!("{l}");
            }
        }
        assert_minted(&net, n, 1_000);
    }
}

/// Delivers everything, every settlement message twice in a row, and returns
/// a copy of each settlement message delivered.
pub fn settle_doubled(net: &mut Net) -> Vec<Message> {
    let mut seen = Vec::new();
    let mut steps = 0;
    while let Some(m) = net.queue.pop_front() {
        steps += 1;
        assert!(steps < 4096);
        if body_op(&m).is_some_and(|op| (40..=63).contains(&op)) {
            seen.push(m.clone());
            net.execute(m.clone());
        }
        net.execute(m);
    }
    seen
}

/// T-M4: every mint message duplicated in flight, then every copy delivered
/// again after completion: one credit, one count, one consumption.
#[test]
fn t_m4_duplicate_and_old_mint_messages_repeat_no_effect() {
    let mut net = Net::new();
    let n = net.start_swap(1_000);
    let seen = settle_doubled(&mut net);
    assert_minted(&net, n, 1_000);
    for m in seen.iter().cloned() {
        net.send(m);
    }
    assert_minted(&net, n, 1_000);
    // once the wallet has compacted the credit, the copies arrive below its
    // floors: only the report is repeated
    let user = net.user(0);
    succeeded(&net.advance_minter_sync(channel::C2, Some(&user)));
    assert_eq!(net.get(&net.wallet_of(&user), "get_credits_above_count", vec![]).int_at(0), 0, "compacted");
    for m in seen {
        net.send(m);
    }
    assert_minted(&net, n, 1_000);
}

/// T-M4: a duplicate report of a counted credit, arriving while an earlier
/// mint holds the minter's watermark, so the counted record is still stored:
/// it is counted once.
#[test]
fn t_m4_a_duplicate_report_behind_a_held_mint_is_counted_once() {
    let mut net = Net::new();
    let user = net.user(0);
    net.swap(10);
    let other = net.user(1);
    net.start_swap_to(&other, 5);
    let held = net.drop_op(op::PREPARE);
    net.settle();
    net.start_swap(100);
    let report = net.intercept(|m| body_op(m) == Some(op::CREDIT_RECORDED));
    net.send(report.clone());
    assert_eq!(net.mint_status(2), mint_status::COUNTED, "stored behind the held mint");
    net.send(report);
    assert_eq!(net.supply_state(), (110, 0, 0, 0, 0), "counted once");
    assert_eq!(net.tokens(&user), 110);
    net.send(held);
    assert_eq!(net.supply_state().0, 115);
}

/// T-M5: two mints to one holder delivered out of order on C1 and on C2.
#[test]
fn t_m5_reordered_mints_are_each_applied_once() {
    let mut net = Net::new();
    let user = net.user(0);
    net.swap(10);
    // C1: the second prepare overtakes the first
    net.start_swap(100);
    net.start_swap(1_000);
    let first = net.intercept(|m| body_op(m) == Some(op::PREPARE));
    net.settle();
    net.send(first);
    assert_eq!(net.tokens(&user), 1_110);
    // C2: the second credit overtakes the first
    net.start_swap(5);
    net.start_swap(7);
    let first = net.intercept(|m| body_op(m) == Some(op::CREDIT) && credit_amount(m) == 5);
    net.settle();
    assert_eq!(net.tokens(&user), 1_117, "the later credit is applied first");
    let st = net.wallet_state(&user);
    assert!(st[5] > st[3], "the out-of-order credit is stored above the watermark");
    net.send(first);
    assert_eq!(net.tokens(&user), 1_122);
    assert_eq!(net.supply_state(), (1_122, 0, 0, 0, 0));
    assert_eq!(net.wallet_state(&user)[3], 5, "the credit watermark folded over all five");
}

/// A copy of a settlement message whose descriptor carries another amount.
pub fn with_amount(m: &Message, words: usize, amount: u128) -> chain_block::Cell {
    let mut s = settlement_body(m);
    let mut b = chain_block::BuilderData::new();
    for _ in 0..words {
        let bits = s.get_next_bits(32).unwrap();
        b.append_raw(&bits, 32).unwrap();
    }
    let mut ds = SliceData::load_cell(s.reference(0).unwrap()).unwrap();
    let tag = ds.get_next_u32().unwrap();
    let nn = ds.get_next_u64().unwrap();
    let ss = ds.get_next_u64().unwrap();
    let _ = chain_block::Coins::construct_from(&mut ds).unwrap();
    let r1 = ds.reference(0).unwrap();
    let r2 = ds.reference(1).unwrap();
    b.checked_append_reference(cell(|x| {
        x.append_u32(tag).unwrap();
        x.append_u64(nn).unwrap();
        x.append_u64(ss).unwrap();
        coins(x, amount);
        x.checked_append_reference(r1.clone()).unwrap();
        x.checked_append_reference(r2.clone()).unwrap();
    }))
    .unwrap();
    b.into_cell().unwrap()
}

/// T-M6: a reused number with altered fields is refused; a second vote for a
/// lock that is consumed or being prepared is refused.
#[test]
fn t_m6_a_reused_identity_with_other_fields_is_refused() {
    let mut net = Net::new();
    let user = net.user(0);
    net.swap(10);
    // s = 1 stays reserved: its commit is lost
    let n = net.start_swap(100);
    let commit = net.drop_op(op::COMMIT);
    net.settle();
    let minter = net.minter();
    let bridge = net.bridge.clone();
    let before = net.state_hashes();
    // op, query, two lives, s and floor: 352 bits, eleven 32-bit words
    let forged_commit = forged(&bridge, &minter, 10 * TOS, with_amount(&commit, 11, 1_000_000));
    refused_with(&net.send(forged_commit), err("operation_mismatch"));
    assert_eq!(net.state_hashes(), before, "nothing applied");
    net.send(commit);
    assert_eq!(net.tokens(&user), 110, "the original commit still completes it");
    // the same credit number with another amount, while the wallet still
    // stores it, is refused at the wallet
    let credit = net
        .delivered
        .iter()
        .rev()
        .find(|d| body_op(&d.msg) == Some(op::CREDIT))
        .map(|d| d.msg.clone())
        .expect("the credit was delivered");
    let wallet = net.wallet_of(&user);
    let before = net.state_hashes();
    // op, query, two lives, k and floor: eleven 32-bit words
    let altered = forged(&minter, &wallet, 10 * TOS, with_amount(&credit, 11, 999));
    refused_with(&net.send(altered), err("operation_mismatch"));
    assert_eq!(net.state_hashes(), before, "nothing credited or reported");

    // a vote for the consumed lock, and for a lock still being prepared
    let voting = net.swap_voting(GENERATION, n, &user, 100, 0x5a);
    let vote = net.vote(900, voting);
    refused_with(&net.send(vote), err("not_admissible"));
    let p = net.start_swap(50);
    net.deliver_one();
    let held = net.take(|m| body_op(m) == Some(op::PREPARE));
    let voting = net.swap_voting(GENERATION, p, &user, 50, 0x5a);
    let vote = net.vote(901, voting);
    refused_with(&net.send(vote), declared("error::swap_not_paid") as i32);
    net.send(held);
    assert_eq!(net.tokens(&user), 160);
}

/// T-M7: ConfigParam 79 removed, or changed, after the vote: every later leg,
/// every duplicate and every advance completes without it.
#[test]
fn t_m7_mints_complete_without_and_despite_configparam_79() {
    // removed right after the vote, with a lost report recovered by advance
    let mut net = Net::new();
    let from = net.delivered.len();
    let n = net.start_swap(1_000);
    net.deliver_one();
    net.remove_config();
    net.drop_op(op::CREDIT_RECORDED);
    net.settle();
    succeeded(&net.advance_bridge_mint(0));
    succeeded(&net.advance_bridge_sync());
    assert_minted(&net, n, 1_000);
    assert_eq!(net.exits_since(from, 666), 0, "no handler read the missing parameter");

    // changed: another bridge address, other fees, every suspension flag
    let mut net = Net::new();
    let n = net.start_swap(1_000);
    net.deliver_one();
    let elsewhere = MsgAddressInt::with_params(-1, chain_block::UInt256::from([0x99; 32])).unwrap();
    net.configure_with(&elsewhere, 0x0f, 1, 1, None);
    let from = net.delivered.len();
    let commit = net.drop_op(op::COMMIT);
    net.settle();
    net.send(commit.clone());
    net.send(commit);
    assert_minted(&net, n, 1_000);
    assert_eq!(net.exits_since(from, 666), 0);
}

/// T-M8: a bounced copy of every mint message, delivered to its sender, changes
/// nothing; no settlement message is ever bounced, so suppressing bounces
/// changes no outcome.
#[test]
fn t_m8_bounces_change_nothing_in_the_mint_path() {
    let mut net = Net::new();
    let n = net.start_swap(1_000);
    let mut copies = Vec::new();
    while let Some(m) = net.queue.pop_front() {
        if body_op(&m).is_some_and(|op| (40..=63).contains(&op)) {
            copies.push(bounced_copy(&m));
        }
        net.execute(m);
    }
    assert_minted(&net, n, 1_000);
    for b in copies {
        let before = net.state_hashes();
        net.send(b);
        assert_eq!(net.state_hashes(), before, "a bounce changed settlement state");
    }
    assert_minted(&net, n, 1_000);
}

/// T-M9: anyone may advance; an advance of a final, absent or underfunded mint
/// is refused and bounces; an advance with extra fields is refused; an advance
/// while new business is suspended goes through.
#[test]
fn t_m9_advances_take_nothing_from_the_caller_but_the_identifier() {
    let mut net = Net::new();
    let n = net.start_swap(1_000);
    net.drop_op(op::PREPARE);
    net.settle();
    let minter = net.minter();
    let bridge = net.bridge.clone();
    let (need, quote) = net.bridge_advance_cost(advance::MINT, 0);

    let padded = net.advance_message(&bridge, advance::MINT, quote, |b| {
        b.append_raw(&account_hash(&minter), 256).unwrap();
        b.append_u64(0).unwrap();
        b.append_raw(&account_hash(&net.user(1)), 256).unwrap();
    });
    let tx = net.send(padded);
    assert!(outcome(&tx).aborted && outcome(&tx).bounced, "extra fields: refused and bounced back");

    let absent = net.advance_message(&bridge, advance::MINT, quote, |b| {
        b.append_raw(&account_hash(&minter), 256).unwrap();
        b.append_u64(77).unwrap();
    });
    refused_with(&net.send(absent), err("nothing_to_advance"));

    net.state_flags = 0x0f;
    net.configure();
    succeeded(&net.send(bridge_mint_advance(&net, need)));
    assert_minted(&net, n, 1_000);

    refused_with(&net.send(bridge_mint_advance(&net, quote)), err("nothing_to_advance"));
}

/// T-M10: a prepare the minter cannot reserve for is refused durably: the lock
/// stays paid and can be voted again, and that s can never be committed.
#[test]
fn t_m10_a_refused_prepare_leaves_the_lock_paid_and_the_number_dead() {
    let mut net = Net::new();
    let user = net.user(0);
    net.swap(MAX_SUPPLY);
    let n = net.swap(1);
    assert_eq!(net.mint_status(1), mint_status::REFUSED);
    assert_eq!(net.swap_record(n).0, swap_state::PAID, "the lock is paid again, unconsumed");
    assert_eq!(net.tokens(&user), MAX_SUPPLY);
    let minter = net.minter();
    let bridge = net.bridge.clone();
    let life = net.bridge_life();
    let minter_life = net.minter_channels()[0] as u64;
    let d = net.get(&minter, "get_mint_descriptor", vec![int_arg(1)]).cell_at(0);
    let body = cell(|b| {
        b.append_u32(op::COMMIT).unwrap().append_u64(0).unwrap();
        b.append_u64(life).unwrap();
        b.append_u64(minter_life).unwrap();
        b.append_u64(1).unwrap();
        b.append_u64(0).unwrap();
        b.checked_append_reference(d).unwrap();
    });
    let commit = forged(&bridge, &minter, 10 * TOS, body);
    net.send(commit);
    assert_eq!(net.tokens(&user), MAX_SUPPLY, "nothing credited");
    assert_eq!(net.mint_status(1), mint_status::REFUSED);
}

/// The amount a credit message carries in its descriptor.
pub fn credit_amount(m: &Message) -> u128 {
    let s = settlement_body(m);
    let mut d = SliceData::load_cell(s.reference(0).unwrap()).unwrap();
    d.get_next_u32().unwrap();
    d.get_next_u64().unwrap();
    d.get_next_u64().unwrap();
    chain_block::Coins::construct_from(&mut d).unwrap().as_u128()
}
