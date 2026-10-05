/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Worst-case dictionary paths.
//!
//! A holder's key at the minter is its owner's address hash, and a swap's
//! recipient is whatever 256-bit hash the EVM locker names, so the holders
//! dictionary can be shaped by anyone willing to pay for the swaps. The
//! longest path a 256-bit key can have is a fork at every bit: the keys
//! {K} ∪ {K xor 2^i | i = 0..255}. Reading or rewriting K's record then walks
//! 256 forks, and a rewrite rebuilds every one of those cells.
//!
//! These tests put that shape around a real holder, and around a holder not
//! yet admitted, and run every minter step against it. The harness holds
//! each transaction to its contract's declared gas, so a declaration that
//! misses this shape fails here; recovery with exactly the quoted funding,
//! before and after a gas price rise, shows the quotes cover it.

use chain_block::{HashmapE, HashmapType, IBitstring, MsgAddressInt};

use crate::burn::minted;
use crate::harness::*;
use crate::lifecycle::reopen;
use crate::state::*;

/// The holder key with bit `i` (counting from the least significant) flipped.
fn flipped(k: &[u8], i: usize) -> Vec<u8> {
    let mut v = k.to_vec();
    v[31 - i / 8] ^= 1 << (i % 8);
    v
}

/// Surrounds `owner`'s key in the minter's holders dictionary with 256
/// holders, one differing from it at each of its 256 bits.
pub fn deepen(net: &mut Net, owner: &MsgAddressInt) {
    let k = account_hash(owner);
    net.patch_minter(|m| {
        let filler = Holder::empty().build();
        let mut d = HashmapE::with_hashmap(256, m.holders.clone());
        for i in 0..256 {
            d.setref(key256(&flipped(&k, i)), filler.clone()).unwrap();
        }
        m.holders = d.data().cloned();
        m.holders_count += 256;
    });
}

/// The depth of `owner`'s key: the forks its path passes, which are the
/// distinct positions at which another key first differs from it.
fn depth(net: &Net, owner: &MsgAddressInt) -> usize {
    let data = net.bc.get_account(&net.minter()).and_then(|a| a.get_data()).expect("a minter");
    let holders = HashmapE::with_hashmap(256, MinterData::parse(&data).holders);
    let k = account_hash(owner);
    let mut forks = std::collections::BTreeSet::new();
    holders
        .iterate_slices(|mut key, _| {
            let other = key.get_next_bytes(32).unwrap();
            if let Some(p) = (0..256).find(|p| (other[p / 8] ^ k[p / 8]) >> (7 - p % 8) & 1 == 1) {
                forks.insert(p);
            }
            Ok(true)
        })
        .unwrap();
    forks.len()
}

/// Runs `f` on a thread with room for recursion over a 256-deep tree; the
/// default test thread's stack is too small for the debug build.
fn deep_stack(f: impl FnOnce() + Send + 'static) {
    // keep the test's name: the trace for the native replay is filed under it
    let name = std::thread::current().name().unwrap_or("deep").to_string();
    std::thread::Builder::new()
        .name(name)
        .stack_size(512 << 20)
        .spawn(f)
        .expect("a test thread")
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e));
}

fn measuring() -> bool {
    std::env::var_os("TOKEN_BRIDGE_GAS_MEASURE").is_some()
}

fn report(net: &Net, what: &str) {
    for ((kind, op, sub), gas) in &net.gas_seen {
        if *kind == "minter" {
            eprintln!("{what}: minter op {op}/{sub}: {gas}");
        }
    }
}

/// Every minter step on a holder at the end of a 256-fork path: mint, lost
/// report, burn, cancelled burn and its refund, both syncs, and stranding of
/// a deleted wallet's life with the new life's opening.
#[test]
fn every_minter_step_on_a_holder_at_the_deepest_path_stays_within_its_gas() {
    deep_stack(every_minter_step_on_a_holder_at_the_deepest_path_stays_within_its_gas_body);
}

fn every_minter_step_on_a_holder_at_the_deepest_path_stays_within_its_gas_body() {
    let mut net = minted();
    net.gas_measuring = measuring();
    let user = net.user(0);
    deepen(&mut net, &user);
    assert_eq!(depth(&net, &user), 256, "the holder sits under a fork at every bit");
    // mint
    net.swap(5);
    // a lost report, recovered by the wallet
    net.start_swap(6);
    net.drop_op(op::CREDIT_RECORDED);
    net.settle();
    let k = net.wallet_state(&user)[3] as u64 - 1;
    succeeded(&net.advance_wallet(&user, advance::REPORT, Some(k)));
    // burn, and a cancelled burn with its refund
    net.start_burn(4);
    net.settle();
    net.start_burn(3);
    net.drop_op(op::BURN_NOTICE);
    net.settle();
    succeeded(&crate::burn::cancel(&mut net, 1));
    // syncs on C2 and C3
    succeeded(&net.advance_minter_sync(channel::C2, Some(&user)));
    succeeded(&net.advance_wallet(&user, advance::SYNC, None));
    assert_eq!(net.tokens(&user), 1_000 + 5 + 6 - 4);
    // the wallet deleted with a credit in flight: stranding and reopening
    net.start_swap(7);
    net.drop_op(op::CREDIT_RECORDED);
    net.settle();
    let wallet = net.wallet_of(&user);
    net.delete_account(&wallet);
    net.recreate_wallet(&user);
    reopen(&mut net, &user);
    net.swap(2);
    assert_eq!(net.tokens(&user), 2, "the new life is served at the deepest path");
    assert_eq!(depth(&net, &user), 256);
    report(&net, "deep update");
}

/// A new holder admitted at the end of a 256-fork path: its first prepare,
/// its wallet's opening and the promotion of its waiting mint.
#[test]
fn a_new_holder_admitted_at_the_deepest_path_stays_within_its_gas() {
    deep_stack(a_new_holder_admitted_at_the_deepest_path_stays_within_its_gas_body);
}

fn a_new_holder_admitted_at_the_deepest_path_stays_within_its_gas_body() {
    let mut net = minted();
    net.gas_measuring = measuring();
    let fresh = net.user(2);
    deepen(&mut net, &fresh);
    net.swap_to(&fresh, 9);
    assert_eq!(net.tokens(&fresh), 9);
    assert_eq!(depth(&net, &fresh), 256, "a fork at every bit");
    report(&net, "deep insert");
}

/// Recovery at the deepest path with exactly the quoted funding: a lost
/// credit report and a lost burn notice are completed by advances carrying
/// their quotes and nothing more, before and after a threefold gas price
/// rise. The quote from before the rise is refused after it, with no effect.
#[test]
fn recovery_at_the_deepest_path_succeeds_with_exactly_the_quoted_funding() {
    deep_stack(recovery_at_the_deepest_path_succeeds_with_exactly_the_quoted_funding_body);
}

fn recovery_at_the_deepest_path_succeeds_with_exactly_the_quoted_funding_body() {
    let mut net = minted();
    net.gas_measuring = measuring();
    let user = net.user(0);
    deepen(&mut net, &user);
    for rise in [false, true] {
        let stale = net.minter_advance_cost(advance::BURN, &user).1;
        if rise {
            let price = net.gas_price(false);
            net.set_gas_price(false, price * 3);
            let mc = net.gas_price(true);
            net.set_gas_price(true, mc * 3);
            // new business is priced by the configured fees, which follow
            // the prices; recovery below is priced by the quotes alone
            net.mint_fee *= 3;
            net.burn_fee *= 3;
            net.configure();
        }
        // a lost burn notice: the minter's advance re-sends it
        net.start_burn(2);
        net.drop_op(op::BURN_NOTICE);
        net.settle();
        let b = net.wallet_state(&user)[6] as u64 - 1;
        let (_, quote) = net.minter_advance_cost(advance::BURN, &user);
        if rise {
            assert!(quote > stale, "the quote follows the price");
            let before = net.state_hashes();
            let msg = minter_burn_advance(&net, &user, b, stale);
            let tx = net.send(msg);
            assert!(outcome(&tx).aborted, "the stale quote is refused");
            assert_unchanged(&net, &before, "a refused advance");
        }
        let msg = minter_burn_advance(&net, &user, b, quote);
        succeeded(&net.send(msg));
        assert_eq!(net.held(&user, b), -1, "the burn completed with the exact quote");
        // a lost credit report: the wallet's advance re-sends it
        net.start_swap(3);
        net.drop_op(op::CREDIT_RECORDED);
        net.settle();
        let k = net.wallet_state(&user)[3] as u64 - 1;
        let (_, quote) = net.wallet_advance_cost(&user, advance::REPORT);
        let wallet = net.wallet_of(&user);
        let msg = net.advance_message(&wallet, advance::REPORT, quote, |x| {
            x.append_u64(k).unwrap();
        });
        succeeded(&net.send(msg));
        assert_eq!(net.supply_state().1, 0, "the report counted with the exact quote");
    }
}

fn minter_burn_advance(
    net: &Net,
    owner: &MsgAddressInt,
    b: u64,
    value: u64,
) -> chain_block::Message {
    let minter = net.minter();
    let owner = owner.clone();
    net.advance_message(&minter, advance::BURN, value, |x| {
        x.append_raw(&account_hash(&owner), 256).unwrap();
        x.append_u64(b).unwrap();
    })
}

/// Surrounds the real minter's channel at the bridge with the other seven
/// channels the limit allows, each differing from it at one of its seven
/// lowest bits: the longest path eight 256-bit keys can give it.
fn deepen_channels(net: &mut Net) {
    let k = account_hash(&net.minter());
    let limit = declared("CHANNEL_LIMIT") as usize;
    net.patch_bridge(|b| {
        let filler = b.channel(&k).expect("the real channel").build();
        let mut d = HashmapE::with_hashmap(256, b.channels.clone());
        for i in 0..limit - 1 {
            d.setref(key256(&flipped(&k, i)), filler.clone()).unwrap();
        }
        b.channels = d.data().cloned();
        b.channels_count = limit as u32;
    });
}

/// Every bridge step on a channel at the deepest path the channel limit
/// allows: votes, results, burn notices, syncs and advances.
#[test]
fn every_bridge_step_on_the_deepest_channel_stays_within_its_gas() {
    deep_stack(every_bridge_step_on_the_deepest_channel_stays_within_its_gas_body);
}

fn every_bridge_step_on_the_deepest_channel_stays_within_its_gas_body() {
    let mut net = minted();
    net.gas_measuring = measuring();
    deepen_channels(&mut net);
    let user = net.user(0);
    net.swap(5);
    net.start_swap(6);
    net.drop_op(op::PREPARE);
    net.settle();
    let s = net.channel()[3] as u64 - 1;
    succeeded(&net.advance_bridge_mint(s));
    net.start_burn(4);
    net.settle();
    succeeded(&net.advance_bridge_sync());
    assert_eq!(net.tokens(&user), 1_000 + 5 + 6 - 4);
    for ((kind, op, sub), gas) in &net.gas_seen {
        if *kind == "bridge" {
            eprintln!("deep channel: bridge op {op}/{sub}: {gas}");
        }
    }
}
