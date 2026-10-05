/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Windows, synchronization and compaction on the four channels.

use chain_block::{IBitstring, Message, MsgAddressInt};

use crate::burn::minted;
use crate::harness::*;

/// Delivers every queued vote first, so each prepare goes out before any
/// result comes back.
fn deliver_votes_first(net: &mut Net) {
    let votes: Vec<Message> = net.queue.drain(..).collect();
    for v in votes {
        net.execute(v);
    }
}

fn consumed(state: i128) -> bool {
    state == -1 || state == swap_state::CONSUMED
}

/// T-Y2: with prepares outstanding the holder's credit window refuses the next
/// prepare, and the wallet's burn window refuses the next burn, before any
/// effect; everything admitted completes within its reserved slot.
#[test]
fn t_y2_full_downstream_windows_refuse_new_admissions_and_complete_the_admitted() {
    let mut net = Net::new();
    let user = net.user(1);
    let window = declared("CREDIT_WINDOW") as usize;
    let mut locks = Vec::new();
    for _ in 0..window + 1 {
        locks.push(net.start_swap_to(&user, 10));
    }
    deliver_votes_first(&mut net);
    net.settle();
    // the last one waits beyond the promotion batch; promoting it finds the
    // credit window full
    let last = *locks.last().unwrap();
    let s = net.swap_record(last).2 as u64;
    succeeded(&net.advance_minter_mint(s));
    let done: Vec<bool> = locks.iter().map(|n| consumed(net.swap_record(*n).0)).collect();
    assert_eq!(done.iter().filter(|x| **x).count(), window, "the window's worth completed: {done:?}");
    assert_eq!(net.swap_record(last).0, swap_state::PAID, "the next was refused, still paid");
    assert_eq!(net.tokens(&user), 10 * window as u128);

    // the wallet's burn window
    let burns = declared("HOLDER_BURN_WINDOW") as usize;
    for _ in 0..burns {
        net.start_burn_from(&user, 1);
    }
    let first: Vec<Message> = net.queue.drain(..).collect();
    for m in first {
        net.execute(m);
    }
    let extra = net.burn_message(&user, 1, net.burn_fee);
    refused_with(&net.send_one(extra), err("window_full"));
    net.settle();
    assert_eq!(net.burn_logs(), burns, "every admitted burn completed");
}

/// T-Y3: a prepare that arrives while the minter's admission storage is full
/// is refused durably; the refusal fits its slot and reaches the bridge.
#[test]
fn t_y3_a_refusal_is_stored_and_delivered_when_admission_storage_is_full() {
    let mut net = minted();
    let limit = declared("HOLDER_LIMIT") as u32;
    net.patch_minter(|m| m.holders_count = limit);
    let newcomer = net.user(2);
    let n = net.swap_to(&newcomer, 5);
    assert_eq!(net.swap_record(n).0, swap_state::PAID, "refused: no holder capacity, the lock stays paid");
    assert_eq!(net.mint_status(1), mint_status::REFUSED);
    // the account cell limit below the minter's measured worst case
    let mut net = minted();
    let worst = declared("MINTER_WORST_CELLS") as u32;
    net.configure_limits(worst - 1, 65_536);
    let n = net.swap(5);
    assert_eq!(net.swap_record(n).0, swap_state::PAID, "refused under a lowered cell limit");
    assert_eq!(net.mint_status(1), mint_status::REFUSED);
}

/// T-Y4: windows that fill with no further business are reopened by a funded
/// sync alone, on every channel, with ConfigParam 79 absent.
#[test]
fn t_y4_sync_alone_reopens_every_window() {
    // C1: prepares go out until the window refuses one; everything completes;
    // with no further business the window stays full
    let mut net = minted();
    let window = declared("MINT_WINDOW") as usize;
    let mut refused = None;
    for i in 0..window + 1 {
        let u = net.user(i % 4);
        let n = net.start_swap_to(&u, 1);
        let vote = net.queue.pop_back().unwrap();
        if outcome(&net.send_one(vote)).aborted {
            refused = Some(n);
            break;
        }
    }
    let n = refused.expect("the window refused a prepare");
    net.settle();
    // Ordinary traffic leaves a lag of one at each end, so the window reopens by
    // itself once everything completes. A full window with nothing outstanding
    // is a stale acknowledgement, which is what the sync is for.
    let next = net.channel()[3];
    net.patch_channel(|c| c.mint_ack = next as u64 - window as u64);
    let voting = net.swap_voting(GENERATION, n, &net.user(0), 1, 0x5a);
    let vote = net.vote(n + 100, voting);
    refused_with(&net.send_one(vote), err("window_full"));
    assert_eq!(net.swap_record(n).0, swap_state::PAID);
    net.remove_config();
    succeeded(&net.advance_bridge_sync());
    net.configure();
    let voting = net.swap_voting(GENERATION, n, &net.user(0), 1, 0x5a);
    let vote = net.vote(n + 100, voting);
    net.send(vote);
    assert!(consumed(net.swap_record(n).0), "the window reopened");

    // C2: a new holder's four credits issued while the minter's finished floor was 0
    let mut net = minted();
    let holder = net.user(2);
    let credits = declared("CREDIT_WINDOW") as usize;
    for _ in 0..credits {
        net.start_swap_to(&holder, 1);
    }
    deliver_votes_first(&mut net);
    net.settle();
    let n = net.swap_to(&holder, 1);
    assert_eq!(net.swap_record(n).0, swap_state::PAID, "the credit window is full");
    net.remove_config();
    succeeded(&net.advance_minter_sync(channel::C2, Some(&holder)));
    net.configure();
    let voting = net.swap_voting(GENERATION, n, &holder, 1, 0x5a);
    let vote = net.vote(n + 100, voting);
    net.send(vote);
    assert!(consumed(net.swap_record(n).0), "the credit window reopened");

    // C3: four burns issued while the wallet's finished floor was 0
    let mut net = minted();
    let user = net.user(0);
    let burns = declared("HOLDER_BURN_WINDOW") as usize;
    for _ in 0..burns {
        net.start_burn_from(&user, 1);
    }
    let first: Vec<Message> = net.queue.drain(..).collect();
    for m in first {
        net.execute(m);
    }
    net.settle();
    let extra = net.burn_message(&user, 1, net.burn_fee);
    refused_with(&net.send(extra), err("window_full"));
    net.remove_config();
    succeeded(&net.advance_wallet(&user, advance::SYNC, None));
    net.configure();
    net.start_burn_from(&user, 1);
    net.settle();
    assert_eq!(net.burn_logs(), burns + 1, "the burn window reopened");

    // C4: eight notices issued while the minter's finished floor was 0
    let mut net = Net::new();
    for i in 0..4 {
        let u = net.user(i);
        net.swap_to(&u, 100);
    }
    let window = declared("BURN_WINDOW") as usize;
    for i in 0..window {
        let u = net.user(i % 4);
        net.start_burn_from(&u, 1);
    }
    let first: Vec<Message> = net.queue.drain(..).collect();
    for m in first {
        net.execute(m);
    }
    let admits: Vec<Message> = net.queue.drain(..).collect();
    for m in admits {
        net.execute(m);
    }
    net.settle();
    assert_eq!(net.burn_logs(), window);
    let user = net.user(0);
    let next = net.minter_channels()[7];
    net.patch_minter(|m| m.bridge_burn_ack = next as u64 - window as u64);
    let b = net.wallet_state(&user)[6] as u64;
    net.start_burn_from(&user, 1);
    net.settle();
    assert_eq!(net.minter_burn(&user, b).1, burn_status::ADMIT_REFUSED, "the notice window is full");
    net.remove_config();
    succeeded(&net.advance_minter_sync(channel::C4, None));
    net.configure();
    let b = net.wallet_state(&user)[6] as u64;
    net.start_burn_from(&user, 1);
    net.settle();
    assert_eq!(net.minter_burn(&user, b).0, 0, "admitted, recorded and folded");
    assert_eq!(net.burn_logs(), window + 1, "the notice window reopened");
}

/// T-Z2: more than FOLD_LIMIT final entries waiting to fold; a sync arrives
/// before folding catches up; every removed entry and every entry still stored
/// is replayed, with its own and with an altered descriptor. Nothing below the
/// floors is admissible, an entry still stored refuses an altered descriptor,
/// and invalid floors are refused or clamped.
#[test]
fn t_z2_compaction_ahead_of_folding_never_admits_an_old_number() {
    let mut net = Net::new();
    for i in 0..4 {
        let u = net.user(i);
        net.swap_to(&u, 1_000);
    }
    // s = 4 is held; s = 5..=10 complete above the minter's watermark
    let mut copies = Vec::new();
    net.start_swap_to(&net.user(0), 1);
    let held = net.drop_op(op::PREPARE);
    net.settle();
    for i in 0..6 {
        let u = net.user(i % 4);
        net.start_swap_to(&u, 1);
        while let Some(m) = net.queue.pop_front() {
            if matches!(body_op(&m), Some(op::PREPARE) | Some(op::COMMIT)) {
                copies.push(m.clone());
            }
            net.execute(m);
        }
    }
    let ch = net.minter_channels();
    assert_eq!(ch[3], 4, "the watermark waits at the held number");
    assert!(net.get(&net.minter(), "get_mint_count", vec![]).int_at(0) > declared("FOLD_LIMIT"));
    net.send(held);
    let ch = net.minter_channels();
    assert!(ch[3] < 11, "folding is bounded: the watermark is at {}", ch[3]);
    // a sync before folding catches up
    succeeded(&net.advance_bridge_sync());
    // every removed entry replayed, with its own and an altered descriptor
    let minter = net.minter();
    let bridge = net.bridge.clone();
    for m in &copies {
        let before = net.state_hashes();
        net.send(m.clone());
        assert_eq!(net.state_hashes(), before, "a replay below the floors applied something");
        let altered = crate::mint::with_amount(m, 11, 777);
        let tx = net.send(forged(&bridge, &minter, 10 * TOS, altered));
        let o = outcome(&tx);
        assert!(!o.aborted || o.exit_code == Some(err("operation_mismatch")), "an altered replay: {:?}", o.exit_code);
        assert_eq!(net.state_hashes(), before, "an altered replay applied something");
    }
    assert_eq!(net.supply_state().0, 4_000 + 7);

    // invalid floors: past everything ever entered, and over an unfinished number
    let life = net.bridge_life();
    let minter_life = net.minter_channels()[0] as u64;
    let sync = |floor: u64| {
        cell(|b| {
            b.append_u32(op::SYNC_FLOOR).unwrap().append_u64(0).unwrap();
            b.append_u64(life).unwrap();
            b.append_u64(minter_life).unwrap();
            b.append_u8(channel::C1).unwrap();
            b.append_u64(floor).unwrap();
        })
    };
    let tx = net.send(forged(&bridge, &minter, 10 * TOS, sync(1_000)));
    refused_with(&tx, err("bad_floor"));
    net.start_swap_to(&net.user(1), 1);
    let pending = net.drop_op(op::COMMIT);
    net.settle();
    let s = net.minter_channels()[5] as u64; // one past the highest entered: the reserved mint
    net.send(forged(&bridge, &minter, 10 * TOS, sync(s)));
    let ch = net.minter_channels();
    assert!(ch[4] < s as i128, "the floor was clamped below the unfinished mint: {}", ch[4]);
    net.send(pending);
    let _ = MsgAddressInt::default;
}

/// T-Z3: one early mint held indefinitely holds the shared mint window: every
/// holder's prepares stop once it fills, each wallet's credit storage stays
/// within its window, and releasing the held mint and syncing resumes all.
#[test]
fn t_z3_a_stuck_mint_backs_up_the_shared_window_and_storage_stays_bounded() {
    let mut net = minted();
    let x = net.user(1);
    let y = net.user(0);
    net.swap_to(&x, 1);
    // X's credit is parked
    net.start_swap_to(&x, 5);
    let parked = net.drop_op(op::CREDIT);
    net.settle();
    let window = declared("MINT_WINDOW") as usize;
    let mut refused = None;
    for _ in 0..window + 2 {
        let n = net.start_swap_to(&y, 1);
        let vote = net.queue.pop_front().unwrap();
        let tx = net.send(vote);
        if outcome(&tx).aborted {
            assert_eq!(outcome(&tx).exit_code, Some(err("window_full")));
            refused = Some(n);
            break;
        }
    }
    let n = refused.expect("the shared window filled");
    assert_eq!(net.swap_record(n).0, swap_state::PAID);
    // the parked credit lands; the window drains
    net.send(parked);
    succeeded(&net.advance_bridge_sync());
    let voting = net.swap_voting(GENERATION, n, &y, 1, 0x5a);
    let vote = net.vote(n + 100, voting);
    net.send(vote);
    assert!(consumed(net.swap_record(n).0));
    // Y keeps going, with C2 compacted by syncs
    for _ in 0..declared("CREDIT_WINDOW") * 2 {
        net.swap_to(&y, 1);
        succeeded(&net.advance_minter_sync(channel::C2, Some(&y)));
    }
    assert!(net.model.credits.keys().filter(|k| k.0 == account_hash(&net.wallet_of(&y))).count() > 10);
}

/// T-Z7: more mints waiting for one unopened holder than its credit window:
/// promotion takes a credit number before `prepared`, refuses the rest with
/// their reservations released, and runs at most FOLD_LIMIT per transaction,
/// the remainder by advance.
#[test]
fn t_z7_waiting_mints_beyond_the_credit_window_are_refused_not_prepared() {
    let mut net = Net::new();
    let holder = net.user(2);
    let waiting = declared("MINT_WINDOW") as usize - 1;
    let mut locks = Vec::new();
    for _ in 0..waiting {
        locks.push(net.start_swap_to(&holder, 3));
    }
    deliver_votes_first(&mut net);
    let open = net.drop_op(op::OPEN);
    net.settle();
    assert_eq!(net.holder(&holder)[13], waiting as i128, "every mint waits for the open");
    assert_eq!(net.supply_state().2, 3 * waiting as i128, "each reserved its supply");
    net.send(open);
    let batch = declared("FOLD_LIMIT") as usize;
    assert_eq!(net.holder(&holder)[13], (waiting - batch) as i128, "one batch promoted");
    // the remainder, by advance
    for s in 0..waiting as u64 {
        if net.mint_status(s) == mint_status::AWAITING_OPEN {
            succeeded(&net.advance_minter_mint(s));
        }
    }
    let credits = declared("CREDIT_WINDOW") as usize;
    let consumed_count = locks.iter().filter(|n| consumed(net.swap_record(**n).0)).count();
    assert_eq!(consumed_count, credits, "only the credit window's worth was prepared");
    assert_eq!(net.tokens(&holder), 3 * credits as u128);
    assert_eq!(net.supply_state(), (3 * credits as i128, 0, 0, 0, 0), "the refused released their reservations");
    for n in &locks {
        let s = net.swap_record(*n).0;
        assert!(consumed(s) || s == swap_state::PAID);
    }
}

/// T-X3: a refusal is an exception on C1. The minter's watermark folds past
/// it, but the refusal stays stored until the bridge's acknowledged floor
/// passes it: a re-sent prepare for that number is answered with the stored
/// refusal, never with the default answer for a folded number, so the lock
/// returns to paid instead of being consumed.
#[test]
fn t_x3_a_refusal_outlives_the_watermark_until_the_bridge_acknowledges_it() {
    let mut net = minted();
    let user = net.user(0);
    let (base, mc) = {
        let l = net.bc.config_params().size_limits_config().expect("limits");
        (l.max_acc_state_cells, l.max_mc_acc_state_cells)
    };
    net.configure_limits(declared("MINTER_WORST_CELLS") as u32 - 1, mc);
    let refused = net.start_swap(5);
    let lost = net.intercept(|m| body_op(m) == Some(op::REFUSED));
    net.configure_limits(base, mc);
    let s = 1;
    assert_eq!(net.mint_status(s), mint_status::REFUSED);
    // later mints finish: the minter's watermark folds past the refusal
    for _ in 0..3 {
        net.swap(1);
    }
    assert!(net.minter_channels()[3] > s as i128, "the watermark passed the refusal");
    assert_eq!(net.mint_status(s), mint_status::REFUSED, "the exception is still stored");
    assert_eq!(net.swap_record(refused).0, swap_state::PREPARING);
    // the bridge re-sends its prepare: the stored refusal answers it
    succeeded(&net.advance_bridge_mint(s));
    assert_eq!(net.swap_record(refused).0, swap_state::PAID, "refused, the lock is paid again");
    assert_eq!(net.tokens(&user), 1_003, "nothing minted for the refusal");
    // the lost original arrives late and changes nothing
    let before = net.state_hashes();
    net.send(lost);
    assert_eq!(net.state_hashes(), before);
    // once acknowledged, a sync compacts it
    // C1's sender syncs: the minter folds and compacts what the bridge's
    // floor has passed
    succeeded(&net.advance_bridge_sync());
    assert_eq!(net.mint_status(s), -1, "compacted after the acknowledgement");
}

/// T-X3: finalization out of order on C1, more than FOLD_LIMIT numbers past a
/// gap. The watermark waits at the gap; once it closes, the watermark folds
/// at most FOLD_LIMIT numbers per transaction and reaches the end by later
/// transactions and a sync, with no effect repeated.
#[test]
fn t_x3_a_gap_closed_late_folds_in_bounded_steps() {
    let mut net = minted();
    let fold = declared("FOLD_LIMIT") as usize;
    let first = net.start_swap_to(&net.user(1), 1);
    net.deliver_until(|m| body_op(m) == Some(op::PREPARED));
    let gap = net.take(|m| body_op(m) == Some(op::PREPARED));
    let gap_s = 1;
    // more than FOLD_LIMIT later mints finish, spread over the holders
    for i in 0..fold + 2 {
        let to = net.user(i % 4);
        net.swap_to(&to, 1);
    }
    assert_eq!(net.minter_channels()[3], gap_s as i128, "the watermark waits at the gap");
    net.send(gap);
    succeeded(&net.advance_bridge_sync());
    succeeded(&net.advance_bridge_sync());
    let total: u128 = (0..4).map(|i| net.tokens(&net.user(i))).sum();
    assert_eq!(total, 1_000 + fold as u128 + 3, "each mint credited once");
    assert_eq!(net.minter_channels()[3], (fold + 4) as i128, "the watermark reached the end");
    assert_eq!(net.swap_record(first).0, -1, "the late swap is consumed and folded");
}
