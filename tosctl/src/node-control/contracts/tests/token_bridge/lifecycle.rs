/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Deletion and recreation of participants: lives, stranding, and source
//! generations (SETTLEMENT-PROTOCOL.md section 10, owner ruling Y).

use chain_block::{IBitstring, Message, MsgAddressInt};

use crate::burn::minted;
use crate::harness::*;

pub fn stranded_logs(net: &Net) -> usize {
    net.logs_from(&net.minter(), declared("LOG_LIABILITY_STRANDED") as u32)
}

/// The holder's wallet asks to open; while its previous life still holds
/// records, the minter strands them in bounded steps until it can open.
pub fn reopen(net: &mut Net, owner: &MsgAddressInt) {
    succeeded(&net.open_wallet(owner));
    let mut rounds = 0;
    while net.holder(owner)[12] != 0 {
        rounds += 1;
        assert!(rounds < 16, "the old life never empties");
        let from = net.delivered.len();
        succeeded(&net.advance_minter(advance::STRAND, owner, None));
        for d in &net.delivered[from..] {
            let logs = d
                .outs
                .iter()
                .filter(|m| !m.is_internal())
                .count();
            assert!(logs <= declared("FOLD_LIMIT") as usize, "a transaction strands at most FOLD_LIMIT records");
        }
    }
    succeeded(&net.open_wallet(owner));
    assert_eq!(net.holder(owner)[2], holder_state::OPEN, "the new life is open");
}

/// T-X4: a wallet deleted with a credit that landed and was transferred away,
/// its report lost, and duplicates still queued. The recreated wallet is a new
/// life: old traffic is refused, the old credit is stranded once and logged,
/// and the new life opens and mints normally.
#[test]
fn t_x4_a_deleted_wallet_strands_its_life_and_the_new_life_starts_clean() {
    let mut net = minted();
    let user = net.user(0);
    let other = net.user(1);
    net.start_swap(500);
    let credit = net.intercept(|m| body_op(m) == Some(op::CREDIT));
    net.send_one(credit.clone());
    let report = net.drop_op(op::CREDIT_RECORDED);
    net.settle();
    let transfer = net.transfer(&user, &other, 300);
    net.send(transfer);
    let wallet = net.wallet_of(&user);
    net.delete_account(&wallet);
    net.recreate_wallet(&user);
    reopen(&mut net, &user);
    assert_eq!(stranded_logs(&net), 1, "the credit stranded once, and logged");
    assert_eq!(net.supply_state(), (1_000, 0, 0, 0, 500), "its amount is in stranded, once");
    assert_eq!(net.channel()[10], 0, "the bridge finalized it");
    // old traffic: the credit and its report, refused or ignored
    let before = net.state_hashes();
    net.send(credit);
    net.send(report);
    assert_eq!(net.state_hashes(), before, "old-life traffic changed nothing");
    assert_eq!(net.tokens(&user), 0);
    assert_eq!(net.tokens(&other), 300, "the transferred tokens stay where they went");
    // the new life mints normally
    net.swap(7);
    assert_eq!(net.tokens(&user), 7);
}

/// T-X4: a deleted and recreated minter is refused: its new life can serve no
/// old wallet, and the bridge's prepare to it is refused.
#[test]
fn t_x4_a_recreated_minter_is_refused_by_the_bridge_and_its_wallets() {
    let mut net = minted();
    let user = net.user(0);
    let minter = net.minter();
    net.delete_account(&minter);
    net.recreate_minter();
    let new_life = net.minter_channels()[0] as u64;
    // the bridge still expects the old life: its prepare is refused
    let n = net.start_swap(5);
    net.settle();
    assert_eq!(net.swap_record(n).0, swap_state::PREPARING, "stuck, under the accepted scope");
    assert_eq!(net.tokens(&user), 1_000);
    // a wallet refuses the newer minter life forever
    let wallet = net.wallet_of(&user);
    let open = cell(|b| {
        b.append_u32(op::OPEN).unwrap().append_u64(0).unwrap();
        b.append_u64(new_life).unwrap();
        b.append_u64(0).unwrap();
        b.append_u32(9).unwrap();
    });
    net.send(forged(&minter, &wallet, TOS, open));
    assert_eq!(net.wallet_state(&user)[2], 1, "the wallet marked its minter terminal");
    // the bridge refuses the newer minter life: the channel becomes terminal
    let life = net.bridge_life();
    let prepared = cell(|b| {
        b.append_u32(op::PREPARED).unwrap().append_u64(0).unwrap();
        b.append_u64(new_life).unwrap();
        b.append_u64(life).unwrap();
        b.append_u64(1).unwrap();
        b.append_u64(0).unwrap();
    });
    let bridge = net.bridge.clone();
    net.send(forged(&minter, &bridge, TOS, prepared));
    assert_eq!(net.channel()[1], 1, "the channel is terminal");
    refused_with(&net.advance_bridge_mint(1), err("terminal"));
}

/// T-X4: a deleted and recreated bridge cannot log an old burn again, accepts
/// no business until a new generation names its life, and its minters refuse
/// it.
#[test]
fn t_x4_a_recreated_bridge_never_logs_an_old_burn_and_its_minters_refuse_it() {
    let mut net = minted();
    net.start_burn(400);
    let notice = net.drop_op(op::BURN_NOTICE);
    net.settle();
    let bridge = net.bridge.clone();
    net.delete_account(&bridge);
    net.recreate_bridge();
    assert_eq!(net.bridge_state()[5], 0, "the recreated bridge is unset");
    let tx = net.send(notice);
    assert!(outcome(&tx).aborted, "the old notice is refused");
    assert_eq!(net.burn_logs(), 0);
    let tx = net.pay(net.next_nonce);
    refused_with(&tx, err("wrong_generation"));
    // a new generation for the new life
    let start = net.next_nonce + 10;
    net.activate(GENERATION + 1, start);
    let before = net.minter_channels();
    let user = net.user(0);
    let n = net.next_nonce;
    net.next_nonce += 1;
    let payer = net.stranger.address().clone();
    succeeded(&net.pay_from(&payer, GENERATION + 1, n, net.mint_fee));
    let voting = net.swap_voting(GENERATION + 1, n, &user, 5, 0x5a);
    let vote = net.vote(n + 100, voting);
    net.send(vote);
    assert_eq!(net.minter_channels()[2], 1, "the minter marked the newer bridge life terminal");
    assert_eq!(net.tokens(&user), 600, "nothing minted for the new life");
    assert_eq!(before[1], net.minter_channels()[1], "the minter still names the old bridge life");
    assert_eq!(net.burn_logs(), 0, "the old burn never logged");
}

/// T-Y6: stale opens and replies after the wallet's recreation are ignored:
/// another attempt's answer, an older life's answer; no credit reaches the new
/// life for an old operation.
#[test]
fn t_y6_stale_opening_messages_after_recreation_are_ignored() {
    let mut net = minted();
    let holder = net.user(1);
    net.start_swap_to(&holder, 5);
    let open_a = net.intercept(|m| body_op(m) == Some(op::OPEN));
    net.send_one(open_a.clone());
    let opened_b = net.drop_op(op::OPENED);
    net.send_one(opened_b.clone());
    net.settle();
    assert_eq!(net.tokens(&holder), 5);
    let wallet = net.wallet_of(&holder);
    net.delete_account(&wallet);
    net.recreate_wallet(&holder);
    reopen(&mut net, &holder);
    let before = net.state_hashes();
    net.send(open_a);
    net.send(opened_b);
    assert_eq!(net.state_hashes()[1..], before[1..], "stale opens changed nothing at the minter or bridge");
    assert_eq!(net.tokens(&holder), 0);
    assert_eq!(net.holder(&holder)[2], holder_state::OPEN);
    net.swap_to(&holder, 2);
    assert_eq!(net.tokens(&holder), 2, "the new life is served");
}

/// T-Z4: the wallet deleted at each point of a mint. Every bound mint ends
/// STRANDED exactly once, from its reservation or from in-flight, the bridge
/// finalizes it whatever the order of `prepared`, `commit` and `mint_stranded`,
/// and no credit reaches the new life.
#[test]
fn t_z4_a_wallet_deleted_at_each_point_of_a_mint_strands_it_exactly_once() {
    let points: [Option<u32>; 4] = [Some(op::PREPARE), Some(op::PREPARED), Some(op::COMMIT), Some(op::CREDIT)];
    for (i, point) in points.iter().enumerate() {
        for reorder in [false, true] {
            let mut net = minted();
            let user = net.user(0);
            net.start_swap(200);
            if let Some(op) = point {
                net.deliver_until(|m| body_op(m) == Some(*op));
            }
            let wallet = net.wallet_of(&user);
            net.delete_account(&wallet);
            // the prepared answer held back to arrive after the strand
            let held = if reorder && *point == Some(op::PREPARED) {
                Some(net.take(|m| body_op(m) == Some(op::PREPARED)))
            } else {
                None
            };
            net.settle();
            net.recreate_wallet(&user);
            reopen(&mut net, &user);
            if let Some(m) = held {
                net.send(m);
                if net.channel()[10] != 0 {
                    succeeded(&net.advance_minter_mint(1));
                }
            }
            let (supply, in_flight, mint_reserve, _, stranded) = net.supply_state();
            assert_eq!((supply, in_flight, mint_reserve, stranded), (1_000, 0, 0, 200), "point {i}");
            assert_eq!(stranded_logs(&net), 1, "point {i}: logged once");
            assert_eq!(net.channel()[10], 0, "point {i}: the bridge finalized the mint");
            assert_eq!(net.tokens(&user), 0, "point {i}: nothing reached the new life");
            // a duplicate of the strand report changes nothing
            succeeded(&net.advance_minter_mint(1));
            assert_eq!(net.supply_state().4, 200);
        }
    }
}

/// T-Z4: more old-life records than FOLD_LIMIT are stranded over several
/// transactions; the stranding log is mandatory, and a leg whose log cannot be
/// sent rolls back whole, to be completed by a later advance.
#[test]
fn t_z4_stranding_is_bounded_and_rolls_back_whole_without_its_log() {
    let mut net = minted();
    let user = net.user(0);
    let credits = declared("CREDIT_WINDOW") as usize;
    // a window of credits landed, their reports lost
    for _ in 0..credits - 1 {
        net.start_swap(10);
        net.drop_op(op::CREDIT_RECORDED);
        net.settle();
    }
    // two refunds in flight
    for _ in 0..2 {
        net.start_burn(1);
        net.drop_op(op::BURN_NOTICE);
        net.settle();
    }
    for b in 0..2 {
        let msg = crate::burn::cancel_message(&net, b);
        net.queue.push_back(msg);
        net.drop_op(op::REFUND);
        net.settle();
    }
    let wallet = net.wallet_of(&user);
    net.delete_account(&wallet);
    net.recreate_wallet(&user);
    succeeded(&net.open_wallet(&user));
    assert!(net.holder(&user)[12] != 0, "the old life holds its records");
    // a leg whose action phase fails rolls back whole: no record is
    // stranded without its log, and no log is emitted without its record
    let minter = net.minter();
    let (cells, _) = net.state_cells(&minter);
    let saved = net.bc.config_params().size_limits_config().expect("size limits");
    // below what any stranding step can shrink the state to
    let limit = (cells / 2) as u32;
    net.configure_limits(limit, limit);
    let before = net.state_hashes();
    let tx = net.advance_minter(advance::STRAND, &user, None);
    let o = outcome(&tx);
    assert!(!o.action_ok, "the action phase failed");
    assert_eq!(o.exit_code, Some(0), "the leg itself ran to completion");
    assert_eq!(net.state_hashes(), before, "nothing stranded without its log");
    assert_eq!(stranded_logs(&net), 0, "no log without its record");
    assert_eq!(net.supply_state().4, 0);
    net.configure_limits(saved.max_acc_state_cells, saved.max_mc_acc_state_cells);
    reopen(&mut net, &user);
    assert_eq!(stranded_logs(&net), credits - 1 + 2);
    assert_eq!(net.supply_state().4, 10 * (credits as i128 - 1) + 2);
}

/// T-Z1: source obligations after all three participants are recreated. Old
/// locks, consumed or cancelled, can never be paid, voted or cancelled again,
/// by a fresh vote, a replayed vote or a replayed activation, before or after
/// the new generation is activated.
#[test]
fn t_z1_old_locks_stay_ineligible_after_all_three_are_recreated() {
    let mut net = minted(); // lock 0 consumed
    let user = net.user(0);
    // lock 1 cancelled
    let cancelled = net.next_nonce;
    net.next_nonce += 1;
    succeeded(&net.pay(cancelled));
    let cancel = net.cancel_lock_vote(GENERATION, cancelled);
    let cancel_vote = net.vote(500, cancel);
    succeeded(&net.send(cancel_vote.clone()));
    // lock 2 stranded: paid and voted, its prepare lost
    let stranded = net.start_swap(9);
    let old_vote = net.queue.front().cloned().unwrap();
    net.deliver_one();
    net.drop_op(op::PREPARE);
    net.settle();
    let life = net.bridge_life();
    let old_activation = net.vote(1, net.activation(&account_hash(&net.bridge), life, GENERATION, 0));

    for addr in [net.bridge.clone(), net.minter(), net.wallet_of(&user)] {
        net.delete_account(&addr);
    }
    net.recreate_bridge();
    net.recreate_minter();
    net.recreate_wallet(&user);
    let payer = net.stranger.address().clone();
    let fee = net.mint_fee;
    let attempts = |net: &mut Net, generation: u32| -> Vec<Transaction> {
        let mut txs = Vec::new();
        for n in [0, cancelled, stranded] {
            txs.push(net.pay_from(&payer, generation, n, fee));
            let fresh = net.swap_voting(generation, n, &user, 1, 0x5a);
            let v = net.vote(700 + n, fresh);
            txs.push(net.send(v));
            let c = net.cancel_lock_vote(generation, n);
            let v = net.vote(800 + n, c);
            txs.push(net.send(v));
        }
        txs.push(net.send(old_vote.clone()));
        txs.push(net.send(cancel_vote.clone()));
        txs.push(net.send(old_activation.clone()));
        txs
    };
    use chain_block::Transaction;
    for tx in attempts(&mut net, GENERATION) {
        assert!(outcome(&tx).aborted, "refused before activation");
    }
    // the new generation starts above every old lock
    let start = stranded + 1;
    net.activate(GENERATION + 1, start);
    for generation in [GENERATION, GENERATION + 1] {
        for tx in attempts(&mut net, generation) {
            assert!(outcome(&tx).aborted, "refused after activation, generation {generation}");
        }
    }
    assert_eq!(net.model.consumed.values().filter(|c| **c > 1).count(), 0, "no lock consumed twice");
    // a payment, vote or cancellation naming the old generation with a nonce of
    // the new range is refused by its generation alone
    let fresh_n = net.next_nonce + 1;
    refused_with(&net.pay_from(&payer, GENERATION, fresh_n, fee), err("wrong_generation"));
    let v = net.swap_voting(GENERATION, fresh_n, &user, 1, 0x5a);
    let v = net.vote(900, v);
    refused_with(&net.send(v), err("wrong_generation"));
    let c = net.vote(901, net.cancel_lock_vote(GENERATION, fresh_n));
    refused_with(&net.send(c), err("wrong_generation"));
    // a fresh family serves only new locks, and new holders
    let newcomer = net.user(2);
    let n = net.next_nonce;
    net.next_nonce += 1;
    succeeded(&net.pay_from(&payer, GENERATION + 1, n, fee));
    let v = net.swap_voting(GENERATION + 1, n, &newcomer, 3, 0x5a);
    let vote = net.vote(n + 100, v);
    net.send(vote);
    assert_eq!(net.tokens(&newcomer), 3, "the fresh family works for a new lock");
    let _ = (Message::default, MsgAddressInt::default);
}

/// T-X4: the first credit of a wallet's life, still in flight when the wallet
/// is deleted, never lands in the recreated wallet: it names the old life.
#[test]
fn t_x4_an_old_life_credit_never_lands_in_the_new_life() {
    let mut net = minted();
    let holder = net.user(1);
    net.start_swap_to(&holder, 50);
    let credit = net.intercept(|m| body_op(m) == Some(op::CREDIT));
    net.settle();
    let wallet = net.wallet_of(&holder);
    net.delete_account(&wallet);
    net.recreate_wallet(&holder);
    reopen(&mut net, &holder);
    let before = net.state_hashes();
    refused_with(&net.send(credit), err("life_mismatch"));
    assert_eq!(net.state_hashes(), before);
    assert_eq!(net.tokens(&holder), 0, "nothing reached the new life");
    assert_eq!(stranded_logs(&net), 1, "the old credit was stranded once instead");
}

/// A settlement message like `m` that names another minter life.
fn with_minter_life(m: &chain_block::Message, life: u64) -> chain_block::Cell {
    let mut s = settlement_body(m);
    let mut b = chain_block::BuilderData::new();
    let head = s.get_next_bits(32 + 64).unwrap();
    b.append_raw(&head, 32 + 64).unwrap();
    s.get_next_u64().unwrap();
    b.append_u64(life).unwrap();
    let rest = s.remaining_bits();
    let tail = s.get_next_bits(rest).unwrap();
    b.append_raw(&tail, rest).unwrap();
    for i in 0..s.remaining_references() {
        b.checked_append_reference(s.reference(i).unwrap()).unwrap();
    }
    b.into_cell().unwrap()
}

/// T-Y6: a credit naming a newer minter life is not a recreated wallet's
/// business: the wallet marks its minter terminal and credits nothing, then
/// refuses everything from it.
#[test]
fn t_y6_a_newer_minter_life_is_terminal_at_the_wallet() {
    let mut net = minted();
    let user = net.user(0);
    net.start_swap(40);
    let credit = net.intercept(|m| body_op(m) == Some(op::CREDIT));
    let minter = net.minter();
    let wallet = net.wallet_of(&user);
    let newer = net.minter_channels()[0] as u64 + 1;
    let body = with_minter_life(&credit, newer);
    net.send(forged(&minter, &wallet, 10 * TOS, body));
    assert_eq!(net.tokens(&user), 1_000, "nothing credited from a newer life");
    assert_eq!(net.wallet_state(&user)[2], 1, "the minter is terminal at the wallet");
    refused_with(&net.send(credit), err("terminal"));
}
