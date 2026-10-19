/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! T-Z6: retransmission from stored records alone.

use std::collections::BTreeMap;

use chain_block::{Message, SliceData};

use crate::burn::{assert_burned, assert_returned, cancel_message, minted};
use crate::harness::*;
use crate::mint::assert_minted;

/// The descriptor hash a settlement message carries, keyed by its opcode.
fn descriptor_of(m: &Message) -> Option<(u32, chain_block::UInt256)> {
    let op = body_op(m)?;
    if !matches!(op, op::PREPARE | op::COMMIT | op::CREDIT | op::BURN_ADMIT | op::BURN_NOTICE) {
        return None;
    }
    let s = settlement_body(m);
    let d = s.reference(0).ok()?;
    let _ = SliceData::load_cell(d.clone()).ok()?;
    Some((op, d.repr_hash()))
}

/// Delivers `cut` messages, discards everything still in flight, and returns the
/// descriptors seen so far.
fn run_then_discard(net: &mut Net, cut: usize) -> (BTreeMap<u32, chain_block::UInt256>, bool) {
    let mut seen = BTreeMap::new();
    for _ in 0..cut {
        let Some(m) = net.queue.pop_front() else { return (seen, true) };
        if let Some((op, h)) = descriptor_of(&m) {
            seen.insert(op, h);
        }
        net.execute(m);
    }
    let finished = net.queue.is_empty();
    net.queue.clear();
    (seen, finished)
}

fn descriptors_since(net: &Net, from: usize) -> BTreeMap<u32, chain_block::UInt256> {
    let mut seen = BTreeMap::new();
    for d in &net.delivered[from..] {
        if let Some((op, h)) = descriptor_of(&d.msg) {
            seen.insert(op, h);
        }
    }
    seen
}

/// T-Z6: a mint cut at every point, everything in flight discarded, completed
/// by an advance carrying only its identifier and funding; every message the
/// advance rebuilt carries the same descriptor as the original.
#[test]
fn t_z6_a_mint_is_rebuilt_from_records_alone_at_every_point() {
    for cut in 1.. {
        let mut net = Net::new();
        let n = net.start_swap(1_000);
        let (original, finished) = run_then_discard(&mut net, cut);
        if finished {
            break;
        }
        let from = net.delivered.len();
        succeeded(&net.advance_bridge_mint(0));
        assert_minted(&net, n, 1_000);
        for (op, h) in descriptors_since(&net, from) {
            if let Some(o) = original.get(&op) {
                assert_eq!(*o, h, "cut {cut}: op {op} rebuilt with another descriptor");
            }
        }
    }
}

/// T-Z6: a burn, and a cancelled burn, cut at every point and completed from the
/// wallet's record alone.
#[test]
fn t_z6_a_burn_is_rebuilt_from_records_alone_at_every_point() {
    for cancelled in [false, true] {
        for cut in 1.. {
            let mut net = minted();
            if cancelled {
                net.start_burn(400);
                net.drop_op(op::BURN_NOTICE);
                net.settle();
                let msg = cancel_message(&net, 0);
                net.queue.push_back(msg);
            } else {
                net.start_burn(400);
            }
            let (original, finished) = run_then_discard(&mut net, cut);
            if finished {
                break;
            }
            let user = net.user(0);
            let from = net.delivered.len();
            if net.held(&user, 0) >= 0 {
                succeeded(&net.advance_wallet(&user, advance::BURN, Some(0)));
            } else {
                // the wallet finished; the minter's record carries the rest
                succeeded(&net.advance_minter(advance::BURN, &user, Some(0)));
            }
            if cancelled {
                assert_returned(&net);
            } else {
                assert_burned(&net);
            }
            for (op, h) in descriptors_since(&net, from) {
                if let Some(o) = original.get(&op) {
                    assert_eq!(*o, h, "cut {cut}: op {op} rebuilt with another descriptor");
                }
            }
        }
    }
}
