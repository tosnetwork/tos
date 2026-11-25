/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The actor's state stays under the basechain account cell limit
//! (ConfigParam 43 `max_acc_state_cells`) at every reachable state.
//!
//! A state over the limit fails the action phase, and a failed notification
//! leaves its tokens unattributed. Every structure that grows is therefore
//! capped, and the caps keep the worst state at 80% of the limit (the state
//! bound in service-actor-token-code.fc). Here that worst state is built with
//! every cap full and every cell distinct, and counted. A further funding is
//! refused before any cap is passed and returned; with the limit lowered below
//! the bound, the same funding fails, which pins the assumption.

use chain_block::{
    BuilderData, Cell, HashmapE, HashmapType, IBitstring, MsgAddressInt, Serializable, SliceData,
    UInt256,
};
use contracts::service_actor_token::{
    ServiceActorTokenContract as Actor, err, kind, outcome, protocol_constants as pc,
};

use crate::harness::*;
use crate::world::*;

/// The account's cells as the limit counts them: every distinct cell of its
/// code and data.
pub fn cells(w: &World) -> u64 {
    let account = w.net.bc.get_account(&w.actor).expect("deployed");
    let mut seen = std::collections::HashSet::new();
    let mut stack: Vec<Cell> =
        [account.get_code(), account.get_data()].into_iter().flatten().collect();
    while let Some(c) = stack.pop() {
        if seen.insert(c.repr_hash()) {
            for i in 0..c.references_count() {
                stack.push(c.reference(i).expect("a reference"));
            }
        }
    }
    seen.len() as u64
}

/// ConfigParam 43's basechain account cell limit, as the genesis sets it.
pub fn genesis_cell_limit() -> u64 {
    let source = std::fs::read_to_string(repo_root().join("crypto/smartcont/gen-zerostate.fif"))
        .expect("the genesis source");
    let start = source.find("<b x{03} s,").expect("the ConfigParam 43 builder");
    let end = start + source[start..].find("43 config!").expect("its end");
    let fields: Vec<u64> = source[start..end]
        .split(',')
        .filter_map(|f| f.split_whitespace().next()?.parse().ok())
        .collect();
    // max_msg_bits max_msg_cells max_library_cells max_vm_data_depth
    // max_ext_msg_size max_ext_msg_depth max_acc_state_cells ...
    fields[6]
}

/// The state bound of service-actor-token-code.fc, in cells.
const BASE: u64 = 320;
const LIVE: u64 = 9;
const RETURNED: u64 = 10;
const FUNDING_RETURN: u64 = 5;
const OWNER_PAYOUT: u64 = 5;
const TRANSIENT: u64 = 10;

fn bound() -> u64 {
    let (l, r, f) = (
        u64::from(pc::MAX_LIVE_GLOBAL),
        u64::from(pc::MAX_RETURNED_GLOBAL),
        u64::from(pc::MAX_RETURNS_IN_FLIGHT),
    );
    BASE + LIVE * l
        + RETURNED * (r + l + f)
        + FUNDING_RETURN * f
        + OWNER_PAYOUT * u64::from(pc::MAX_REVENUE_PAYOUTS + pc::MAX_SURPLUS_PAYOUTS)
        + TRANSIENT
}

/// A distinct basechain address for (tag, i).
fn addr(tag: u8, i: u64) -> MsgAddressInt {
    MsgAddressInt::with_params(0, UInt256::from(hash(tag, i))).unwrap()
}

fn hash(tag: u8, i: u64) -> [u8; 32] {
    let mut h = [tag; 32];
    h[24..].copy_from_slice(&i.to_be_bytes());
    h
}

fn ref_dict(entries: impl IntoIterator<Item = (u64, Cell)>) -> Option<Cell> {
    let mut d = HashmapE::with_bit_len(64);
    for (k, v) in entries {
        let mut key = BuilderData::new();
        key.append_u64(k).unwrap();
        let mut value = BuilderData::new();
        value.checked_append_reference(v).unwrap();
        d.set_builder(SliceData::load_builder(key).unwrap(), &value).unwrap();
    }
    d.data().cloned()
}

fn counters(callers: impl IntoIterator<Item = MsgAddressInt>) -> Option<Cell> {
    let mut d = HashmapE::with_bit_len(256);
    for c in callers {
        let mut value = BuilderData::new();
        value.append_u32(1).unwrap();
        d.set_builder(SliceData::from_raw(caller_key(&c).to_vec(), 256), &value).unwrap();
    }
    d.data().cloned()
}

fn pending_entry(i: u64, key: &Option<Cell>, key_id: &[u8; 32]) -> Cell {
    cell(|b| {
        addr(1, i).write_to(b).unwrap();
        coins(b, PRICE);
        coins(b, STORAGE_FEE.into());
        coins(b, BOUNTY.into());
        b.append_u64(1_000 + i).unwrap();
        b.append_u64(2_000 + i).unwrap();
        b.append_u32(0).unwrap();
        b.checked_append_reference(cell(|c| {
            c.append_raw(&hash(3, i), 256).unwrap();
            c.append_raw(&hash(4, 0), 256).unwrap();
            match key {
                Some(k) => {
                    c.append_bit_one().unwrap();
                    c.append_raw(key_id, 256).unwrap();
                    c.append_bit_one().unwrap();
                    c.checked_append_reference(k.clone()).unwrap();
                }
                None => {
                    c.append_bit_zero().unwrap();
                    c.append_raw(&[0; 32], 256).unwrap();
                    c.append_bit_zero().unwrap();
                }
            }
        }))
        .unwrap();
    })
}

fn payout(k: u8, id: u64, recipient: &MsgAddressInt, undo: Cell) -> Cell {
    cell(|b| {
        b.append_bits(k as usize, 3).unwrap();
        b.append_u64(id).unwrap();
        recipient.write_to(b).unwrap();
        addr(9, id).write_to(b).unwrap();
        coins(b, PRICE);
        b.append_u32(id as u32).unwrap();
        b.checked_append_reference(cell(|a| {
            addr(8, id).write_to(a).unwrap();
            addr(7, 0).write_to(a).unwrap();
            coins(a, u128::from(TOS));
            a.checked_append_reference(undo).unwrap();
        }))
        .unwrap();
    })
}

fn no_undo() -> Cell {
    cell(|b| {
        b.append_bits(0, 2).unwrap();
    })
}

/// Every cap full at once, every cell distinct, `returns_free` funding return
/// slots left.
fn worst_state(returns_free: u32) -> World {
    let attestor = contracts::native_registry::native_public_key_from_seed(&[0x31; 32]);
    let key_id = contracts::native_registry::controller_key_id(&attestor).unwrap();
    let mut w = World::with(Options { attestor_pubkey: Some(attestor), ..Options::default() });
    let buyer = w.user(0);
    w.call(&buyer); // the actor's wallet exists
    w.checking = false;
    let (l, r, f) = (
        u64::from(pc::MAX_LIVE_GLOBAL),
        u64::from(pc::MAX_RETURNED_GLOBAL),
        u64::from(pc::MAX_RETURNS_IN_FLIGHT),
    );
    let returns = f - u64::from(returns_free);
    w.patch(|d| {
        let mut s = SliceData::load_cell(d.policy.clone()).unwrap();
        let mut c = SliceData::load_cell(s.checked_drain_reference().unwrap()).unwrap();
        c.get_next_bits(256 + 256 + 1 + 256).unwrap();
        let key = if c.get_next_bit().unwrap() {
            Some(c.checked_drain_reference().unwrap())
        } else {
            None
        };
        let mut payouts: Vec<(u64, Cell)> = Vec::new();
        // Live entries, each being swept: the entry is in its payout's undo.
        for i in 0..l {
            let undo = cell(|b| {
                b.append_bits(1, 2).unwrap();
                b.checked_append_reference(pending_entry(i, &key, &key_id)).unwrap();
            });
            payouts.push((1 + i, payout(kind::SWEEP, i, &addr(1, i), undo)));
        }
        // Returned entries, each being paid.
        let mut returned: Vec<(u64, Cell)> = Vec::new();
        let returned_callers: Vec<MsgAddressInt> = (0..r + l + f).map(|j| addr(2, j)).collect();
        for (j, caller) in returned_callers.iter().enumerate() {
            let j = j as u64;
            let id = 1_000_000 + j;
            returned.push((
                500_000 + j,
                cell(|b| {
                    caller.write_to(b).unwrap();
                    coins(b, PRICE);
                    b.append_u64(id).unwrap();
                    b.append_u64(3_000 + j).unwrap();
                }),
            ));
            payouts.push((id, payout(kind::RETURNED_CLAIM, 500_000 + j, caller, no_undo())));
        }
        // Funding returns, and the owner payouts.
        for i in 0..returns {
            payouts.push((2_000_000 + i, payout(kind::FUNDING_RETURN, 0, &addr(5, i), no_undo())));
        }
        for i in 0..u64::from(pc::MAX_REVENUE_PAYOUTS + pc::MAX_SURPLUS_PAYOUTS) {
            let k = if i < 4 { kind::REVENUE } else { kind::SURPLUS };
            payouts.push((3_000_000 + i, payout(k, 0, &addr(6, i), no_undo())));
        }
        d.requests[0] = None;
        d.requests[2] = counters((0..l).map(|i| addr(1, i)));
        d.payout_dicts[0] = ref_dict(payouts);
        d.payout_dicts[1] = ref_dict(returned);
        d.payout_dicts[2] = counters(returned_callers);
        d.live_count = l as u32;
        d.pending_count = l as u32;
        d.returned_count = (r + l + f) as u32;
        d.returns_in_flight = returns as u16;
        d.revenue_payouts_in_flight = 4;
        d.surplus_payouts_in_flight = 4;
        d.next_payout_id = 4_000_000;
    });
    w
}

#[test]
fn the_derived_caps_keep_the_worst_state_within_80_percent_of_the_genesis_limit() {
    let limit = genesis_cell_limit();
    let budget = limit * 8 / 10;
    let w = worst_state(0);
    let worst = cells(&w);
    println!("worst state {worst} cells; bound {}; 80% of {limit} = {budget}", bound());
    assert!(worst <= bound(), "the bound under-counts the real state: {worst} > {}", bound());
    assert!(bound() <= budget, "the caps exceed 80% of the account cell limit");
    let base = cells(&World::with(Options {
        attestor_pubkey: Some(contracts::native_registry::native_public_key_from_seed(&[0x31; 32])),
        ..Options::default()
    }));
    println!("base state {base} cells");
    assert!(base <= BASE, "the base state is {base} cells");
}

/// A fully funded call from user 0: returns where it started and the
/// buyer's tokens before it.
fn further_funding(w: &mut World) -> (usize, u128) {
    let buyer = w.user(0);
    let before = w.tokens(&buyer);
    let start = w.fund(&buyer, PRICE, w.call_forward(), Some(w.token_call([0x77; 32])));
    (start, before)
}

#[test]
fn with_every_cap_full_a_further_funding_is_refused_and_returned() {
    let mut w = worst_state(1);
    let limit = genesis_cell_limit();
    let buyer = w.user(0);
    let (start, before) = further_funding(&mut w);
    for d in w.actor_txs_since(start) {
        assert!(!outcome(&d.tx).aborted && outcome(&d.tx).action_ok, "no step failed");
    }
    assert!(cells(&w) <= limit * 8 / 10, "the state stays within 80% of the limit");
    let logs = w.funding_logs_since(start);
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].reason as i32, err::CAPACITY_EXCEEDED_GLOBAL, "refused before any cap");
    assert_ne!(logs[0].payout_id, 0);
    let outcomes = w.outcome_logs_since(start);
    assert_eq!((outcomes[0].kind, outcomes[0].outcome), (kind::FUNDING_RETURN, outcome::DELIVERED));
    assert_eq!(w.tokens(&buyer), before, "returned, never surplus");
}

#[test]
fn with_the_account_cell_limit_below_the_bound_the_same_funding_fails() {
    // The assumption pinned: lower ConfigParam 43 to just above the worst state,
    // below the bound's transient, and the further funding no longer fits; its
    // notification fails and its tokens are left unattributed. The caps are
    // sound only against the genesis limit, which the first test reads.
    let mut w = worst_state(1);
    let worst = cells(&w);
    let lowered = worst + 2;
    assert!(lowered < bound(), "the lowered limit is below the bound");
    w.net.configure_limits(lowered as u32, 65_536);
    let actor_tokens = w.actor_tokens();
    let (start, _) = further_funding(&mut w);
    let txs = w.actor_txs_since(start);
    assert_eq!(txs.len(), 1);
    let o = outcome(&txs[0].tx);
    assert!(o.aborted && !o.action_ok, "the state does not fit: the action phase fails");
    assert_eq!(w.actor_tokens(), actor_tokens + PRICE, "the tokens are left unattributed");
}

#[test]
fn at_the_funding_return_cap_a_refusal_is_logged_and_its_tokens_are_surplus() {
    // The one case in which a refused funding is not returned: MAX_RETURNS_IN_FLIGHT
    // returns are already unresolved, which only a flood of refused fundings
    // faster than their returns resolve can reach. The log names the funding.
    let mut w = World::new();
    let buyer = w.user(0);
    w.call(&buyer);
    w.patch(|d| d.returns_in_flight = pc::MAX_RETURNS_IN_FLIGHT as u16);
    let start = w.fund(&buyer, PRICE + 1, w.call_forward(), Some(w.token_call([1; 32])));
    let logs = w.funding_logs_since(start);
    assert_eq!((logs[0].reason as i32, logs[0].payout_id), (err::INSUFFICIENT_PAYMENT, 0));
    assert_eq!(w.surplus(), (PRICE + 1) as i128);
    // One slot free: returned as always, and the slot released after.
    w.patch(|d| d.returns_in_flight = pc::MAX_RETURNS_IN_FLIGHT as u16 - 1);
    let before = w.tokens(&buyer);
    w.fund(&buyer, PRICE + 1, w.call_forward(), Some(w.token_call([1; 32])));
    assert_eq!(w.tokens(&buyer), before, "returned");
    assert_eq!(w.native().returns_in_flight, pc::MAX_RETURNS_IN_FLIGHT - 1);
}

#[test]
fn surplus_payouts_in_flight_are_capped() {
    let mut w = World::new();
    w.patch(|d| d.surplus_payouts_in_flight = pc::MAX_SURPLUS_PAYOUTS as u8);
    let owner = w.owner.clone();
    let funding = 2 * w.payout_funding();
    refused_with(
        &w.op(&owner, Actor::recover_surplus(1, 1).unwrap(), funding),
        err::PAYOUT_IN_FLIGHT,
    );
}
