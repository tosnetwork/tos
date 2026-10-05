/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! T-G: cells and gas at worst-case occupancy, measured on the compiled
//! contracts.
//!
//! Each participant's worst case is every window full, every record at its
//! largest, the holder and channel limits reached and an old life held in
//! full. One real record of every kind is taken from real traffic; the worst
//! case is that record cloned into every slot. Its size is counted with no
//! sharing: data cells at every occurrence, as distinct operations would
//! store them, and code once. The engines count distinct cells, so this is an
//! upper bound of what any reachable state occupies.

use std::collections::HashSet;

use chain_block::{
    BuilderData, Cell, HashmapE, HashmapType, IBitstring, MsgAddressInt, SliceData, UInt256,
};

use crate::burn::minted;
use crate::harness::*;
use crate::state::*;

/// Data counted as a tree; a code cell, wherever it appears, counted once.
fn tree_cells(c: &Cell, code: &HashSet<UInt256>, counted: &mut HashSet<UInt256>) -> usize {
    if code.contains(&c.repr_hash()) {
        return distinct_cells(c, counted);
    }
    let mut n = 1;
    for i in 0..c.references_count() {
        n += tree_cells(&c.reference(i).expect("a reference"), code, counted);
    }
    n
}

fn distinct_cells(c: &Cell, counted: &mut HashSet<UInt256>) -> usize {
    if !counted.insert(c.repr_hash()) {
        return 0;
    }
    let mut n = 1;
    for i in 0..c.references_count() {
        n += distinct_cells(&c.reference(i).expect("a reference"), counted);
    }
    n
}

/// The worst-case bound of a state whose code is `code` and data `data`.
fn bound(code: &Cell, data: &Cell) -> usize {
    let codes = codes();
    let roots: HashSet<UInt256> =
        [codes.bridge.repr_hash(), codes.minter.repr_hash(), codes.wallet.repr_hash()].into_iter().collect();
    let mut counted = HashSet::new();
    distinct_cells(code, &mut counted) + tree_cells(data, &roots, &mut counted)
}

fn key64(k: u64) -> SliceData {
    let mut b = BuilderData::new();
    b.append_u64(k).unwrap();
    SliceData::load_builder(b).unwrap()
}

fn key256(i: u64) -> SliceData {
    let mut b = BuilderData::new();
    b.append_raw(&[0xa5; 24], 192).unwrap();
    b.append_u64(i).unwrap();
    SliceData::load_builder(b).unwrap()
}

/// A dictionary of `n` entries keyed `first..first+n`, each holding `value`.
fn full64(first: u64, n: u64, value: &SliceData) -> Option<Cell> {
    let mut d = HashmapE::with_bit_len(64);
    for k in first..first + n {
        d.set(key64(k), value).unwrap();
    }
    d.data().cloned()
}

/// Any one value of a non-empty dictionary.
fn sample(dict: &Option<Cell>, bits: usize) -> SliceData {
    let d = HashmapE::with_hashmap(bits, dict.clone());
    let mut found = None;
    d.iterate_slices(|_, v| {
        found = Some(v);
        Ok(false)
    })
    .unwrap();
    found.expect("a record of this kind was produced")
}

fn data_of(net: &Net, addr: &MsgAddressInt) -> Cell {
    net.bc.get_account(addr).and_then(|a| a.get_data()).expect("deployed")
}

fn code_of(net: &Net, addr: &MsgAddressInt) -> Cell {
    net.bc.get_account(addr).and_then(|a| a.get_code()).expect("deployed")
}

/// One real record of every kind each contract stores.
struct Samples {
    net: Net,
    mint: SliceData,
    notice: SliceData,
    credit: SliceData,
    holder_burn: SliceData,
    awaiting: SliceData,
    swap: SliceData,
    pending: SliceData,
    outcome: SliceData,
    wallet_credit: SliceData,
    wallet_burn: SliceData,
}

fn samples() -> Samples {
    let mut net = minted();
    let user = net.user(0);
    // a mint held at CREDITING: a minter mint record with its descriptor, a
    // holder credit entry, a pending mint at the bridge
    net.start_swap(10);
    net.deliver_until(|m| body_op(m) == Some(op::CREDIT));
    let credit = net.take(|m| body_op(m) == Some(op::CREDIT));
    // a landed credit whose report was lost: the wallet's credit entry
    net.start_swap(10);
    net.drop_op(op::CREDIT_RECORDED);
    net.settle();
    // an admitted burn whose notice was lost: wallet and holder burn records
    // and a minter notice
    net.start_burn(5);
    net.drop_op(op::BURN_NOTICE);
    net.settle();
    // a recorded burn whose result was lost: the bridge's burn outcome
    net.start_burn(5);
    net.drop_op(op::BURN_RESULT);
    net.settle();
    // a voted swap whose prepare is held: a preparing swap
    net.start_swap(10);
    net.deliver_one();
    let _held = net.take(|m| body_op(m) == Some(op::PREPARE));
    // a mint to a holder whose wallet is still opening: an awaiting entry
    let fresh = net.user(1);
    net.start_swap_to(&fresh, 10);
    net.deliver_until(|m| body_op(m) == Some(op::OPEN));
    let _open = net.take(|m| body_op(m) == Some(op::OPEN));
    net.settle();

    let m = MinterData::parse(&data_of(&net, &net.minter()));
    let h = m.holder(&account_hash(&user)).expect("a holder");
    let opening = m.holder(&account_hash(&fresh)).expect("an opening holder");
    let b = BridgeData::parse(&data_of(&net, &net.bridge));
    let c = b.channel(&account_hash(&net.minter())).expect("a channel");
    let w = WalletData::parse(&data_of(&net, &net.wallet_of(&user)));
    let s = Samples {
        mint: sample(&m.mints, 64),
        notice: sample(&m.notices, 64),
        credit: sample(&h.credits, 64),
        holder_burn: sample(&h.burns, 64),
        awaiting: sample(&opening.awaiting, 64),
        swap: largest(&b.swaps),
        pending: sample(&c.pending, 64),
        outcome: sample(&c.burns, 64),
        wallet_credit: sample(&w.credits_above, 64),
        wallet_burn: sample(&w.burns, 64),
        net,
    };
    let _ = credit;
    s
}

/// The swap record with the most bits: a preparing swap carries its payer.
fn largest(dict: &Option<Cell>) -> SliceData {
    let d = HashmapE::with_hashmap(64, dict.clone());
    let mut best: Option<SliceData> = None;
    d.iterate_slices(|_, v| {
        if best.as_ref().is_none_or(|b| v.remaining_bits() > b.remaining_bits()) {
            best = Some(v);
        }
        Ok(true)
    })
    .unwrap();
    best.expect("a swap")
}

fn window(name: &str) -> u64 {
    declared(name) as u64
}

struct Worst {
    wallet: (Cell, usize),
    minter: (Cell, usize),
    bridge: (Cell, usize),
}

/// The three worst-case states and their bounds, from real samples.
fn worst(s: &Samples, holders: u64, channels: u64) -> Worst {
    let net = &s.net;
    let user = net.user(0);

    let mut w = WalletData::parse(&data_of(net, &net.wallet_of(&user)));
    w.credits_above = full64(0, window("CREDIT_WINDOW"), &s.wallet_credit);
    w.burns = full64(0, window("HOLDER_BURN_WINDOW"), &s.wallet_burn);
    let wallet = w.build();
    let wallet_bound = bound(&code_of(net, &net.wallet_of(&user)), &wallet);

    let mut m = MinterData::parse(&data_of(net, &net.minter()));
    let mut h = m.holder(&account_hash(&user)).expect("a holder");
    h.credits = full64(0, window("CREDIT_WINDOW"), &s.credit);
    h.burns = full64(0, window("HOLDER_BURN_WINDOW"), &s.holder_burn);
    h.awaiting = full64(0, window("MINT_WINDOW"), &s.awaiting);
    let old_credits = full64(0, window("CREDIT_WINDOW"), &s.credit);
    let old_burns = full64(0, window("HOLDER_BURN_WINDOW"), &s.holder_burn);
    h.old = Some(cell(|b| {
        b.append_u64(1).unwrap();
        for d in [&old_credits, &old_burns] {
            match d {
                Some(c) => {
                    b.append_bit_one().unwrap();
                    b.checked_append_reference(c.clone()).unwrap();
                }
                None => {
                    b.append_bit_zero().unwrap();
                }
            }
        }
    }));
    let holder = h.build();
    m.mints = full64(0, window("MINT_WINDOW"), &s.mint);
    m.notices = full64(0, window("BURN_WINDOW"), &s.notice);
    let mut dict = HashmapE::with_bit_len(256);
    for i in 0..holders {
        dict.setref(key256(i), holder.clone()).unwrap();
    }
    m.holders = dict.data().cloned();
    m.holders_count = holders as u32;
    let minter = m.build();
    let minter_bound = bound(&code_of(net, &net.minter()), &minter);

    let mut b = BridgeData::parse(&data_of(net, &net.bridge));
    let mut c = b.channel(&account_hash(&net.minter())).expect("a channel");
    c.pending = full64(0, window("MINT_WINDOW"), &s.pending);
    c.burns = full64(0, window("BURN_WINDOW"), &s.outcome);
    let channel = c.build();
    b.swaps = full64(0, window("SWAP_WINDOW"), &s.swap);
    let mut dict = HashmapE::with_bit_len(256);
    for i in 0..channels {
        dict.setref(key256(i), channel.clone()).unwrap();
    }
    b.channels = dict.data().cloned();
    b.channels_count = channels as u32;
    let bridge = b.build();
    let bridge_bound = bound(&code_of(net, &net.bridge), &bridge);

    Worst { wallet: (wallet, wallet_bound), minter: (minter, minter_bound), bridge: (bridge, bridge_bound) }
}

/// T-G: at every window full, the holder and channel limits reached and an
/// old life held in full, each state fits under the declared worst case, and
/// the declared worst case under its account limit: the ordinary basechain
/// limit for the minter and wallets, and the non-special masterchain limit
/// for the bridge, so losing ConfigParam 31 cannot stop a completion.
#[test]
fn t_g_worst_case_cells_fit_the_declared_bound_and_the_account_limit() {
    let s = samples();
    let w = worst(&s, window("HOLDER_LIMIT"), window("CHANNEL_LIMIT"));
    let limits = s.net.bc.config_params().size_limits_config().expect("size limits");
    eprintln!(
        "worst case: wallet {} cells, minter {} cells ({} holders), bridge {} cells ({} channels)",
        w.wallet.1,
        w.minter.1,
        window("HOLDER_LIMIT"),
        w.bridge.1,
        window("CHANNEL_LIMIT")
    );
    let one = worst(&s, 1, 1);
    let two = worst(&s, 2, 2);
    eprintln!(
        "per holder {} cells, per channel {} cells",
        two.minter.1 - one.minter.1,
        two.bridge.1 - one.bridge.1
    );
    for (name, measured, declared_name, limit) in [
        ("wallet", w.wallet.1, "WALLET_WORST_CELLS", limits.max_acc_state_cells),
        ("minter", w.minter.1, "MINTER_WORST_CELLS", limits.max_acc_state_cells),
        ("bridge", w.bridge.1, "BRIDGE_WORST_CELLS", limits.max_mc_acc_state_cells),
    ] {
        let declared_cells = declared(declared_name) as usize;
        assert!(measured <= declared_cells, "{name}: {measured} cells exceed the declared {declared_cells}");
        assert!(
            declared_cells <= limit as usize,
            "{name}: the declared {declared_cells} cells exceed the account limit {limit}"
        );
    }
}

/// T-G: every step at the holder and channel limits, with each other holder
/// and channel full, stays within its declared gas; the harness checks each
/// transaction against its contract's declaration. A new holder beyond the
/// limit is refused, not admitted.
#[test]
fn t_g_steps_at_the_holder_and_channel_limits_stay_within_gas() {
    let s = samples();
    let holder_limit = window("HOLDER_LIMIT");
    let channel_limit = window("CHANNEL_LIMIT");
    let mut net = minted();
    let user = net.user(0);
    // fill the minter to its holder limit and the bridge to its channel
    // limit with full clones beside the real ones
    let full = worst(&s, 1, 1);
    let clone_holder = MinterData::parse(&full.minter.0).holders;
    let clone_holder = sample_ref(&clone_holder);
    let clone_channel = BridgeData::parse(&full.bridge.0).channels;
    let clone_channel = sample_ref(&clone_channel);
    net.patch_minter(|m| {
        let mut d = HashmapE::with_hashmap(256, m.holders.clone());
        let real = m.holders_count as u64;
        for i in 0..holder_limit - real - 1 {
            d.setref(key256(i), clone_holder.clone()).unwrap();
        }
        m.holders = d.data().cloned();
        m.holders_count = (holder_limit - 1) as u32;
    });
    net.patch_bridge(|b| {
        let mut d = HashmapE::with_hashmap(256, b.channels.clone());
        let real = b.channels_count as u64;
        for i in 0..channel_limit - real {
            d.setref(key256(i), clone_channel.clone()).unwrap();
        }
        b.channels = d.data().cloned();
        b.channels_count = channel_limit as u32;
    });
    // the real holder mints and burns; a new holder takes the last slot
    let before = net.tokens(&user);
    net.swap(100);
    assert_eq!(net.tokens(&user), before + 100, "the real holder mints at the limits");
    net.start_burn(50);
    net.settle();
    let second = net.user(1);
    net.swap_to(&second, 7);
    assert_eq!(net.tokens(&second), 7, "the last holder slot is admitted");
    // beyond the limit the prepare is refused and the lock stays paid
    let third = net.user(2);
    let n = net.start_swap_to(&third, 7);
    net.settle();
    assert_eq!(net.tokens(&third), 0, "no holder beyond the limit");
    assert_eq!(net.swap_record(n).0, declared("SWAP_PAID") as i128, "the lock stays paid");
    // a token beyond the channel limit is refused at the bridge
    let n = net.next_nonce;
    net.next_nonce += 1;
    succeeded(&net.pay(n));
    let voting = net.swap_voting(GENERATION, n, &user, 5, 0x77);
    let vote = net.vote(300, voting);
    assert!(outcome(&net.send(vote)).aborted, "no channel beyond the limit");
    for ((kind, op, sub), gas) in &net.gas_seen {
        eprintln!("gas at the limits: {kind} op {op}/{sub}: {gas}");
    }
}

fn sample_ref(dict: &Option<Cell>) -> Cell {
    let mut v = sample(dict, 256);
    v.checked_drain_reference().expect("a record reference")
}
