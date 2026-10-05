/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! An independent record of every settlement effect, kept outside the contracts.
//!
//! The contracts compact their own records; this model never does. It watches
//! every delivered transaction, reads the state of the contract that ran before
//! and after, attributes each change to the message that caused it, and checks
//! the protocol invariants (I1 to I9 in SETTLEMENT-PROTOCOL.md) after every
//! transaction. A duplicate the contracts no longer remember is still a
//! duplicate here.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use chain_block::{Deserializable, Message, MsgAddressInt, SliceData};

use crate::harness::*;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct WalletSnap {
    pub balance: i128,
    pub born: i128,
    pub minter_life: i128,
    /// b -> held amount
    pub holds: BTreeMap<u64, i128>,
    pub credits_above: usize,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MinterSnap {
    pub born: i128,
    pub supply: i128,
    pub in_flight: i128,
    pub mint_reserve: i128,
    pub burn_reserve: i128,
    pub stranded: i128,
    /// s -> (status, bound life, k, owner-hash-low, amount)
    pub mints: BTreeMap<u64, (i128, i128, i128, i128)>,
    /// (owner, b) -> (where, status, amount)
    pub burns: BTreeMap<(Vec<u8>, u64), (i128, i128, i128)>,
    pub mint_entries: i128,
    pub holder_burn_entries: BTreeMap<Vec<u8>, i128>,
    pub mint_wm: u64,
    /// owner -> burn watermark of the current life
    pub burn_wm: BTreeMap<Vec<u8>, u64>,
    /// s -> escrow held for a waiting mint
    pub escrows: BTreeMap<u64, i128>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BridgeSnap {
    pub born: i128,
    /// n -> state
    pub swaps: BTreeMap<u64, i128>,
    /// (minter, m) -> outcome
    pub outcomes: BTreeMap<(Vec<u8>, u64), i128>,
    /// minter -> pending count
    pub pending: BTreeMap<Vec<u8>, i128>,
    pub burns_stored: BTreeMap<Vec<u8>, usize>,
    pub swaps_stored: usize,
    /// minter -> (burn watermark, compaction floor)
    pub burn_bounds: BTreeMap<Vec<u8>, (u64, u64)>,
    pub swap_wm: u64,
    /// n -> recorded fee of a paid or preparing lock
    pub fees: BTreeMap<u64, i128>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Snap {
    None,
    Wallet(WalletSnap),
    Minter(MinterSnap),
    Bridge(BridgeSnap),
    Other,
}

/// Every effect the model has seen, keyed by the operation it belongs to.
#[derive(Default)]
pub struct Model {
    /// (wallet, wallet life, k) -> credits applied
    pub credits: BTreeMap<(Vec<u8>, i128, u64), u32>,
    /// (minter, minter life, s) -> supply counts
    pub counts: BTreeMap<(Vec<u8>, i128, u64), u32>,
    /// (minter, minter life, s) -> amount landed in a wallet and not yet counted
    pub landed: BTreeMap<(Vec<u8>, i128, u64), i128>,
    /// (wallet, life, b) -> refunds or releases applied
    pub returns: BTreeMap<(Vec<u8>, i128, u64), u32>,
    /// (minter, owner, life, b) -> amount of a refund landed and not yet counted
    pub landed_refunds: BTreeMap<(Vec<u8>, Vec<u8>, i128, u64), i128>,
    /// (minter, owner, life, b) -> admitted amount (supply reduced)
    pub admitted: BTreeMap<(Vec<u8>, Vec<u8>, i128, u64), i128>,
    /// (bridge life, minter, m) -> LOG_BURN emissions
    pub burn_logs: BTreeMap<(i128, Vec<u8>, u64), u32>,
    /// (bridge life, minter, m) -> decided outcome
    pub decisions: BTreeMap<(i128, Vec<u8>, u64), i128>,
    /// (wallet, life, b) refunded at a wallet, for exclusivity with LOG_BURN
    pub refunded_burns: BTreeSet<(Vec<u8>, i128, u64)>,
    /// (bridge life, n) -> consumptions
    pub consumed: BTreeMap<(i128, u64), u32>,
    /// (bridge life, n) -> cancellations logged
    pub cancelled: BTreeMap<(i128, u64), u32>,
    /// Balances and unadmitted holds of deleted wallets.
    pub deleted_balances: i128,
    /// Supply of minter lives that no longer exist.
    pub deleted_supply: i128,
    /// Addresses of every wallet the model has seen run.
    pub wallets: BTreeSet<String>,
    pub minters: BTreeSet<String>,
    /// Failed atomic-send checks, kept for tests that expect them.
    pub atomic_violations: Vec<String>,
    /// When set, an atomic-send failure is recorded instead of failing the test.
    pub tolerate_atomic: bool,
    pub enabled: bool,
    /// Set by tests that patch a counter next to exhaustion, where a sender's
    /// acknowledged floor and a receiver's storage are made inconsistent on purpose.
    pub skip_window_checks: bool,
    /// Accounts the chain froze or deleted: address -> (wallet?, amount, life).
    pub lost: BTreeMap<String, (bool, i128, i128)>,
}

fn key(addr: &MsgAddressInt) -> Vec<u8> {
    account_hash(addr)
}

fn kind_of(net: &Net, addr: &MsgAddressInt) -> Option<&'static str> {
    let code = net.bc.get_account(addr)?.get_code()?;
    let h = code.repr_hash();
    let c = codes();
    if h == c.bridge.repr_hash() {
        Some("bridge")
    } else if h == c.minter.repr_hash() {
        Some("minter")
    } else if h == c.wallet.repr_hash() {
        Some("wallet")
    } else {
        None
    }
}

fn outs_with_op(outs: &[Message], op: u32) -> usize {
    outs.iter().filter(|m| m.is_internal() && body_op(m) == Some(op)).count()
}

pub fn ext_topic(m: &Message) -> Option<u32> {
    let h = m.ext_out_header()?;
    match &h.dst {
        chain_block::MsgAddressExt::AddrExtern(ext) => {
            let bytes = ext.external_address.get_bytestring(0);
            Some(u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().ok()?))
        }
        _ => None,
    }
}

fn logs_with(outs: &[Message], topic: u32) -> usize {
    outs.iter().filter(|m| ext_topic(m) == Some(topic)).count()
}

impl Model {
    pub fn snapshot(&self, net: &Net, addr: &MsgAddressInt) -> Snap {
        if !self.enabled {
            return Snap::Other;
        }
        match kind_of(net, addr) {
            None => {
                if net.bc.get_account(addr).is_none() {
                    Snap::None
                } else {
                    Snap::Other
                }
            }
            Some("wallet") => Snap::Wallet(wallet_snap(net, addr)),
            Some("minter") => Snap::Minter(minter_snap(net, addr)),
            Some(_) => Snap::Bridge(bridge_snap(net, addr)),
        }
    }

    /// What `addr` would take out of the live sums if it stopped running now:
    /// a wallet's balance and unadmitted holds, or a minter's supply.
    pub fn exposure(&self, net: &Net, addr: &MsgAddressInt) -> Option<(bool, i128, i128)> {
        if !self.enabled {
            return None;
        }
        match kind_of(net, addr) {
            Some("wallet") => {
                let w = wallet_snap(net, addr);
                let minter = wallet_master(net, addr);
                let owner = wallet_owner(net, addr);
                let mut lost = w.balance;
                for (b, amount) in &w.holds {
                    if !self.admitted.contains_key(&(key(&minter), key(&owner), w.born, *b)) {
                        lost += amount;
                    }
                }
                Some((true, lost, w.born))
            }
            Some("minter") => {
                let m = minter_snap(net, addr);
                Some((false, m.supply, m.born))
            }
            _ => None,
        }
    }

    /// After a transaction on `addr` that held `exposure` before: if the chain
    /// froze or deleted it, its holdings leave the live sums; if it came back
    /// (unfrozen into the same life), they return.
    pub fn lifecycle(
        &mut self,
        net: &Net,
        addr: &MsgAddressInt,
        exposure: Option<(bool, i128, i128)>,
    ) {
        if !self.enabled {
            return;
        }
        let k = addr.to_string();
        let running = kind_of(net, addr).is_some();
        if let Some((wallet, amount, life)) = exposure {
            if !running {
                if wallet {
                    self.deleted_balances += amount;
                    self.wallets.remove(&k);
                } else {
                    self.deleted_supply += amount;
                    self.minters.remove(&k);
                }
                self.lost.insert(k, (wallet, amount, life));
            }
        } else if running {
            if let Some((wallet, amount, life)) = self.lost.get(&k).copied() {
                let now = self.exposure(net, addr).map(|e| e.2);
                if now == Some(life) {
                    if wallet {
                        self.deleted_balances -= amount;
                    } else {
                        self.deleted_supply -= amount;
                    }
                    self.lost.remove(&k);
                }
            }
        }
    }

    /// The chain deleted `addr`: what it held leaves the live sums.
    pub fn account_deleted(&mut self, net: &Net, addr: &MsgAddressInt) {
        if !self.enabled {
            return;
        }
        match kind_of(net, addr) {
            Some("wallet") => {
                let w = wallet_snap(net, addr);
                let minter = wallet_master(net, addr);
                let owner = wallet_owner(net, addr);
                let mut lost = w.balance;
                for (b, amount) in &w.holds {
                    let admitted =
                        self.admitted.contains_key(&(key(&minter), key(&owner), w.born, *b));
                    if !admitted {
                        lost += amount;
                    }
                }
                self.deleted_balances += lost;
                self.wallets.remove(&addr.to_string());
            }
            Some("minter") => {
                let m = minter_snap(net, addr);
                self.deleted_supply += m.supply;
                self.minters.remove(&addr.to_string());
            }
            _ => {}
        }
    }

    pub fn observe(&mut self, net: &Net, d: &Delivery, before: Snap, after: Snap) {
        if !self.enabled {
            return;
        }
        let o = outcome(&d.tx);
        let op = if d.msg.int_header().map(|h| h.bounced).unwrap_or(false) {
            None
        } else {
            body_op(&d.msg)
        };
        match (&before, &after) {
            (_, Snap::Wallet(a)) => {
                self.wallets.insert(d.addr.to_string());
                let empty = WalletSnap::default();
                let b = match &before {
                    Snap::Wallet(b) => b,
                    _ => &empty,
                };
                self.observe_wallet(net, d, op, b, a, o.aborted);
            }
            (_, Snap::Minter(a)) => {
                self.minters.insert(d.addr.to_string());
                let empty = MinterSnap::default();
                let b = match &before {
                    Snap::Minter(b) => b,
                    _ => &empty,
                };
                self.observe_minter(net, d, op, b, a, o.aborted);
            }
            (_, Snap::Bridge(a)) => {
                let empty = BridgeSnap::default();
                let b = match &before {
                    Snap::Bridge(b) => b,
                    _ => &empty,
                };
                self.observe_bridge(net, d, op, b, a);
            }
            _ => {}
        }
        self.check_funded(net, d, &before, &after);
        // The storage phase may freeze or delete the account even when the
        // rest of the transaction is aborted; its data is then out of reach,
        // which lifecycle() has accounted for.
        let gone = after == Snap::Other || after == Snap::None;
        if o.aborted && before != Snap::None && before != Snap::Other && !gone {
            // A failed deployment is left as an empty account by one engine and
            // not created by the other; neither carries any state.
            assert_eq!(before, after, "an aborted transaction changed the state it reports");
        }
        self.check_conservation(net);
        if !self.skip_window_checks {
            self.check_windows(net);
        }
    }

    /// I7: a protocol leg spends its incoming value and nothing of the
    /// contract's own balance, beyond storage; the exceptions spend only what
    /// they recorded earlier: a vote or a cancellation spends a lock's fee, a
    /// promotion spends a waiting mint's escrow.
    fn check_funded(&self, net: &Net, d: &Delivery, before: &Snap, after: &Snap) {
        let op = body_op(&d.msg);
        let bounced = d.msg.int_header().map(|h| h.bounced).unwrap_or(false);
        let protocol = !bounced
            && op.is_some_and(|o| (40..=63).contains(&o) || o == OP_BURN || o == OP_EXECUTE_VOTING);
        if !protocol {
            return;
        }
        if op == Some(OP_EXECUTE_VOTING) {
            // Of the votes, only a swap and a lock cancellation are settlement.
            let mut b = d.msg.body().unwrap().clone();
            b.get_next_u32().unwrap();
            b.get_next_u64().unwrap();
            let sub = b.get_next_byte().unwrap();
            if sub != 0 && sub != 9 {
                return;
            }
        }
        // Optional records are paid from the contract's balance, by design.
        let mut allowed: i128 = d
            .outs
            .iter()
            .filter(|m| !m.is_internal())
            .filter(|m| {
                let t = ext_topic(m);
                t != Some(LOG_BURN)
                    && t != Some(declared("LOG_SWAP_CANCELLED") as u32)
                    && t != Some(declared("LOG_LIABILITY_STRANDED") as u32)
            })
            .map(|m| forward_fee_of(net, m, d.addr.workchain_id() == -1) as i128)
            .sum();
        match (before, after) {
            (Snap::Minter(b), Snap::Minter(a)) => {
                for (s, e) in &b.escrows {
                    let was = b.mints.get(s).map(|x| x.0);
                    let now = a.mints.get(s).map(|x| x.0);
                    if was == Some(mint_status::AWAITING_OPEN)
                        && now != Some(mint_status::AWAITING_OPEN)
                    {
                        allowed += e;
                    }
                }
            }
            (Snap::Bridge(b), Snap::Bridge(a)) => {
                for (n, fee) in &b.fees {
                    if b.swaps.get(n) == Some(&swap_state::PAID)
                        && a.swaps.get(n) != Some(&swap_state::PAID)
                    {
                        allowed += fee;
                    }
                }
            }
            _ => {}
        }
        let o = outcome(&d.tx);
        let value = value_of(&d.msg) as i128;
        let after_balance = net.balance(&d.addr) as i128;
        let before_balance = d.balance_before as i128;
        let spent = before_balance + value - o.storage_fees as i128 - after_balance;
        assert!(
            spent <= value + allowed,
            "I7: op {op:?} spent {spent} of an incoming {value} (allowed beyond it: {allowed})"
        );
    }

    /// I9 and the acknowledged floors: no receiver holds more than its window
    /// per channel, and no sender's acknowledged floor exceeds what its
    /// receiver actually still stores.
    pub fn check_windows(&self, net: &Net) {
        if kind_of(net, &net.bridge) != Some("bridge") {
            return; // not deployed yet
        }
        let minter = net.minter();
        let Some(ch) = net.try_get(&minter, "get_channels", vec![]) else { return };
        let mint_count = net.get(&minter, "get_mint_count", vec![]).int_at(0);
        assert!(mint_count <= declared("MINT_WINDOW"), "I9: the minter stores {mint_count} mints");
        if let Some(c) = net.try_get(&net.bridge, "get_channel", vec![addr_arg(&minter)]) {
            // floors bind one pair of lives; a recreated minter starts a new
            // relationship the bridge treats as terminal
            let same_lives =
                c.int_at(2) == ch.int_at(0) && ch.int_at(1) == net.bridge_life() as i128;
            if c.int_at(0) != 0 && same_lives {
                assert!(
                    c.int_at(4) <= ch.int_at(6),
                    "C1: the bridge's acknowledged floor {} exceeds the minter's storage floor {}",
                    c.int_at(4),
                    ch.int_at(6)
                );
                assert!(
                    ch.int_at(8) <= c.int_at(9),
                    "C4: the minter's acknowledged floor {} exceeds the bridge's storage floor {}",
                    ch.int_at(8),
                    c.int_at(9)
                );
            }
        }
        for owner in known_owners(net) {
            let h = net.get(&minter, "get_holder", vec![addr_arg(&owner)]);
            if h.int_at(0) == 0 || h.int_at(2) != holder_state::OPEN {
                continue;
            }
            assert!(
                h.int_at(14) <= declared("HOLDER_BURN_WINDOW"),
                "I9: a holder stores {} burns",
                h.int_at(14)
            );
            let wallet = net.wallet_of(&owner);
            let Some(st) = net.try_get(&wallet, "get_settlement_state", vec![]) else { continue };
            if st.int_at(0) != h.int_at(1) {
                continue; // another life of this wallet
            }
            assert!(
                h.int_at(6) <= st.int_at(8),
                "C2: the minter's acknowledged floor {} exceeds the wallet's storage floor {}",
                h.int_at(6),
                st.int_at(8)
            );
            assert!(
                st.int_at(7) <= h.int_at(11),
                "C3: the wallet's acknowledged floor {} exceeds the holder's storage floor {}",
                st.int_at(7),
                h.int_at(11)
            );
            let above = net.get(&wallet, "get_credits_above_count", vec![]).int_at(0);
            assert!(above <= declared("CREDIT_WINDOW"), "I9: a wallet stores {above} credits");
        }
    }

    fn atomic(&mut self, ok: bool, what: String) {
        if !ok {
            if self.tolerate_atomic {
                self.atomic_violations.push(what);
            } else {
                panic!("I8 atomic send: {what}");
            }
        }
    }

    fn observe_wallet(
        &mut self,
        net: &Net,
        d: &Delivery,
        op: Option<u32>,
        b: &WalletSnap,
        a: &WalletSnap,
        aborted: bool,
    ) {
        if aborted {
            return;
        }
        let wallet = key(&d.addr);
        let minter = wallet_master(net, &d.addr);
        let owner = wallet_owner(net, &d.addr);
        let gained = a.balance - b.balance;
        let life = a.born;
        match op {
            Some(op::CREDIT) => {
                let mut s = settlement_body(&d.msg);
                s.get_next_u32().unwrap();
                s.get_next_u64().unwrap();
                let _minter_life = s.get_next_u64().unwrap();
                let _wallet_life = s.get_next_u64().unwrap();
                let k = s.get_next_u64().unwrap();
                if gained > 0 {
                    let n = self.credits.entry((wallet.clone(), life, k)).or_insert(0);
                    *n += 1;
                    assert!(*n <= 1, "I6: credit k={k} applied twice at one wallet life");
                    let desc = s.reference(0).expect("a descriptor");
                    let sn = mint_descriptor_s(&desc);
                    let minter_life = minter_life_of(net, &minter);
                    let entry = self.landed.entry((key(&minter), minter_life, sn)).or_insert(0);
                    assert_eq!(*entry, 0, "I6: mint s={sn} landed twice");
                    *entry += gained;
                    self.atomic(
                        outs_with_op(&d.outs, op::CREDIT_RECORDED) == 1,
                        format!("credit {k} without its report"),
                    );
                }
            }
            Some(op::REFUND) | Some(op::ADMIT_REFUSED) => {
                let mut s = settlement_body(&d.msg);
                s.get_next_u32().unwrap();
                s.get_next_u64().unwrap();
                s.get_next_u64().unwrap();
                s.get_next_u64().unwrap();
                let bn = s.get_next_u64().unwrap();
                if gained > 0 {
                    let n = self.returns.entry((wallet.clone(), life, bn)).or_insert(0);
                    *n += 1;
                    assert!(*n <= 1, "I3: burn b={bn} returned twice");
                    if op == Some(op::REFUND) {
                        self.refunded_burns.insert((wallet.clone(), life, bn));
                        self.landed_refunds.insert((key(&minter), key(&owner), life, bn), gained);
                        self.admitted.remove(&(key(&minter), key(&owner), life, bn));
                        self.atomic(
                            outs_with_op(&d.outs, op::REFUND_RECORDED) == 1,
                            format!("refund {bn} without its report"),
                        );
                    }
                }
            }
            Some(op::BURN_OUTCOME) => {
                for (bn, _) in b.holds.iter().filter(|(bn, _)| !a.holds.contains_key(bn)) {
                    self.admitted.remove(&(key(&minter), key(&owner), life, *bn));
                }
            }
            Some(OP_BURN) | Some(op::CANCEL_BURN) => {
                if a.holds.len() > b.holds.len() || op == Some(op::CANCEL_BURN) {
                    self.atomic(
                        outs_with_op(&d.outs, op::BURN_ADMIT) == 1,
                        "a hold without its admission request".into(),
                    );
                }
            }
            _ => {}
        }
    }

    fn observe_minter(
        &mut self,
        net: &Net,
        d: &Delivery,
        _op: Option<u32>,
        b: &MinterSnap,
        a: &MinterSnap,
        aborted: bool,
    ) {
        if aborted {
            return;
        }
        let minter = key(&d.addr);
        let life = a.born;
        let mut changes: Vec<(u64, i128, i128, i128)> = Vec::new();
        for (s, after) in &a.mints {
            changes.push((*s, b.mints.get(s).map(|x| x.0).unwrap_or(-1), after.0, after.3));
        }
        for (s, before) in &b.mints {
            if !a.mints.contains_key(s) && *s < a.mint_wm && before.0 == mint_status::CREDITING {
                // counted, then folded below the watermark: the channel default
                changes.push((*s, before.0, mint_status::COUNTED, before.3));
            }
        }
        for (s, before, now, amount) in changes {
            let s = &s;
            let after = (now, 0, 0, amount);
            if before == now {
                continue;
            }
            match now {
                mint_status::COUNTED => {
                    let n = self.counts.entry((minter.clone(), life, *s)).or_insert(0);
                    *n += 1;
                    assert!(*n <= 1, "I6: mint s={s} counted twice");
                    let landed = self.landed.remove(&(minter.clone(), life, *s));
                    assert_eq!(landed, Some(after.3), "a mint counted that never landed");
                    self.atomic(
                        outs_with_op(&d.outs, op::MINT_COMPLETED) >= 1,
                        format!("count of {s} without completion"),
                    );
                }
                mint_status::RESERVED => {
                    self.atomic(
                        outs_with_op(&d.outs, op::PREPARED) >= 1,
                        format!("reservation of {s} without prepared"),
                    );
                }
                mint_status::REFUSED => {
                    self.atomic(
                        outs_with_op(&d.outs, op::REFUSED) >= 1,
                        format!("refusal of {s} without refused"),
                    );
                }
                mint_status::CREDITING => {
                    self.atomic(
                        outs_with_op(&d.outs, op::CREDIT) >= 1,
                        format!("crediting {s} without a credit"),
                    );
                }
                mint_status::STRANDED => {
                    self.atomic(
                        outs_with_op(&d.outs, op::MINT_STRANDED) >= 1
                            && logs_with(&d.outs, declared("LOG_LIABILITY_STRANDED") as u32) >= 1,
                        format!("stranding {s} without its log and report"),
                    );
                }
                _ => {}
            }
        }
        let mut burn_changes: Vec<((Vec<u8>, u64), (i128, i128, i128), i128)> = Vec::new();
        for (k, after) in &a.burns {
            burn_changes.push((k.clone(), *after, b.burns.get(k).map(|x| x.1).unwrap_or(-1)));
        }
        for (k, before) in &b.burns {
            if a.burns.contains_key(k) || before.0 != 1 {
                continue;
            }
            // folded away in this transaction: a recorded burn, the default, or
            // a refund counted at once
            let now = match before.1 {
                burn_status::AWAITING_BRIDGE => burn_status::RECORDED,
                burn_status::REFUNDING => burn_status::REFUNDED,
                other => other,
            };
            burn_changes.push((k.clone(), (before.0, now, before.2), before.1));
        }
        for ((owner, bn), after, before) in burn_changes {
            let (owner, bn) = (&owner, &bn);
            let after = &after;
            let now = after.1;
            if before == now {
                continue;
            }
            let burn_life = burn_life_of(net, &d.addr, owner, after.0);
            match now {
                burn_status::AWAITING_BRIDGE => {
                    self.admitted.insert((minter.clone(), owner.clone(), burn_life, *bn), after.2);
                    self.atomic(
                        outs_with_op(&d.outs, op::BURN_NOTICE) >= 1,
                        format!("admission of {bn} without a notice"),
                    );
                }
                burn_status::ADMIT_REFUSED => {
                    self.atomic(
                        outs_with_op(&d.outs, op::ADMIT_REFUSED) >= 1,
                        format!("refused admission {bn} without its answer"),
                    );
                }
                burn_status::REFUNDING if after.0 == 1 => {
                    self.atomic(
                        outs_with_op(&d.outs, op::REFUND) >= 1,
                        format!("refunding {bn} without a refund"),
                    );
                }
                burn_status::REFUNDED => {
                    let landed = self.landed_refunds.remove(&(
                        minter.clone(),
                        owner.clone(),
                        burn_life,
                        *bn,
                    ));
                    assert_eq!(landed, Some(after.2), "a refund counted that never landed");
                }
                _ => {}
            }
        }
    }

    fn observe_bridge(
        &mut self,
        _net: &Net,
        d: &Delivery,
        op: Option<u32>,
        b: &BridgeSnap,
        a: &BridgeSnap,
    ) {
        let life = a.born;
        let burn_logs = logs_with(&d.outs, LOG_BURN);
        let mut new_decision = None;
        if op == Some(op::BURN_NOTICE) && !outcome(&d.tx).aborted {
            let mut s = settlement_body(&d.msg);
            s.get_next_u32().unwrap();
            s.get_next_u64().unwrap();
            s.get_next_u64().unwrap();
            s.get_next_u64().unwrap();
            let m = s.get_next_u64().unwrap();
            let sender = key(&d.msg.src_ref().expect("a source").clone());
            let (wm, cf) = b.burn_bounds.get(&sender).copied().unwrap_or((0, 0));
            let was_new = m >= wm.max(cf) && !b.outcomes.contains_key(&(sender.clone(), m));
            if was_new {
                let result = d.outs.iter().find(|x| body_op(x) == Some(op::BURN_RESULT));
                if let Some(result) = result {
                    let mut r = settlement_body(result);
                    r.get_next_u32().unwrap();
                    r.get_next_u64().unwrap();
                    r.get_next_u64().unwrap();
                    r.get_next_u64().unwrap();
                    assert_eq!(r.get_next_u64().unwrap(), m);
                    let outcome = r.get_next_bit().unwrap() as i128;
                    let e = self.decisions.entry((life, sender.clone(), m)).or_insert(outcome);
                    assert_eq!(*e, outcome, "I4: m={m} decided twice, differently");
                    new_decision = Some(((sender, m), outcome));
                }
            }
        }
        // every result the bridge sends repeats the decision it first made
        if op == Some(op::BURN_NOTICE) && !outcome(&d.tx).aborted {
            let sender = key(&d.msg.src_ref().expect("a source").clone());
            for result in d.outs.iter().filter(|x| body_op(x) == Some(op::BURN_RESULT)) {
                let mut r = settlement_body(result);
                r.get_next_u32().unwrap();
                r.get_next_u64().unwrap();
                r.get_next_u64().unwrap();
                r.get_next_u64().unwrap();
                let m = r.get_next_u64().unwrap();
                let outcome = r.get_next_bit().unwrap() as i128;
                if let Some(first) = self.decisions.get(&(life, sender.clone(), m)) {
                    assert_eq!(*first, outcome, "I4: m={m} answered against its decision");
                }
            }
        }
        if burn_logs > 0 {
            assert_eq!(op, Some(op::BURN_NOTICE), "LOG_BURN outside a burn notice");
            let mut s = settlement_body(&d.msg);
            s.get_next_u32().unwrap();
            s.get_next_u64().unwrap();
            s.get_next_u64().unwrap();
            s.get_next_u64().unwrap();
            let m = s.get_next_u64().unwrap();
            let sender = key(&d.msg.src_ref().expect("a source").clone());
            let n = self.burn_logs.entry((life, sender.clone(), m)).or_insert(0);
            *n += burn_logs as u32;
            assert!(*n <= 1, "I2: LOG_BURN emitted twice for m={m}");
            assert!(
                matches!(&new_decision, Some((k, o)) if k.1 == m && *o == OUTCOME_RECORDED),
                "LOG_BURN without a new RECORDED decision"
            );
        }
        if let Some((k, outcome)) = &new_decision {
            if *outcome == OUTCOME_RECORDED {
                self.atomic(burn_logs == 1, format!("RECORDED {} without LOG_BURN", k.1));
            }
            self.atomic(
                outs_with_op(&d.outs, op::BURN_RESULT) == 1,
                format!("decision {} without a result", k.1),
            );
        }
        let mut swap_changes: Vec<(u64, i128, i128)> = Vec::new();
        for (n, state) in &a.swaps {
            swap_changes.push((*n, b.swaps.get(n).copied().unwrap_or(-1), *state));
        }
        let activation = op == Some(OP_EXECUTE_VOTING) && {
            let mut body = d.msg.body().unwrap().clone();
            body.get_next_u32().unwrap();
            body.get_next_u64().unwrap();
            body.get_next_byte().unwrap() == 8
        };
        // An activation sets the watermark to the generation's start; nothing
        // is consumed or cancelled by it.
        let passed = if activation { 0..0 } else { b.swap_wm..a.swap_wm };
        for n in passed {
            if a.swaps.contains_key(&n) {
                continue;
            }
            // passed by the watermark in this transaction: consumed or cancelled
            let before = b.swaps.get(&n).copied().unwrap_or(-1);
            let now = if before == swap_state::PREPARING || before == swap_state::CONSUMED {
                swap_state::CONSUMED
            } else {
                swap_state::CANCELLED
            };
            swap_changes.push((n, before, now));
        }
        for (n, before, state) in swap_changes {
            let (n, state) = (&n, &state);
            if before == *state {
                continue;
            }
            if *state == swap_state::CONSUMED {
                let c = self.consumed.entry((life, *n)).or_insert(0);
                *c += 1;
                assert!(*c <= 1, "I5: lock {n} consumed twice");
                assert!(
                    !self.cancelled.contains_key(&(life, *n)),
                    "I5: lock {n} consumed after cancellation"
                );
            }
            if *state == swap_state::CANCELLED {
                let logs = logs_with(&d.outs, declared("LOG_SWAP_CANCELLED") as u32);
                self.atomic(logs == 1, format!("cancellation of {n} without its log"));
                if before == swap_state::PAID {
                    // the payment goes back in the same leg: a plain message
                    let refunds =
                        d.outs.iter().filter(|m| m.is_internal() && body_op(m).is_none()).count();
                    self.atomic(
                        refunds == 1,
                        format!("cancellation of paid {n} without its refund"),
                    );
                }
                let c = self.cancelled.entry((life, *n)).or_insert(0);
                *c += 1;
                assert!(*c <= 1, "lock {n} cancelled twice");
                assert!(
                    !self.consumed.contains_key(&(life, *n)),
                    "I5: lock {n} cancelled after consumption"
                );
            }
        }
        // A cancellation log is only ever part of a new cancellation.
        let cancel_logs = logs_with(&d.outs, declared("LOG_SWAP_CANCELLED") as u32);
        let new_cancels = a
            .swaps
            .iter()
            .filter(|(n, s)| {
                **s == swap_state::CANCELLED && b.swaps.get(n) != Some(&swap_state::CANCELLED)
            })
            .count();
        // A cancelled lock may fold out of the window in the same transaction.
        let folded = (if activation { 0..0 } else { b.swap_wm..a.swap_wm })
            .filter(|n| {
                !matches!(
                    b.swaps.get(n),
                    Some(&swap_state::PREPARING)
                        | Some(&swap_state::CONSUMED)
                        | Some(&swap_state::CANCELLED)
                )
            })
            .count();
        assert!(
            cancel_logs <= new_cancels + folded,
            "LOG_SWAP_CANCELLED without a new cancellation"
        );
    }

    /// I1 and the capacity bound, after every transaction.
    pub fn check_conservation(&self, net: &Net) {
        let mut balances: i128 = 0;
        let mut holds: i128 = 0;
        let mut pending: i128 = 0;
        for w in &self.wallets {
            let addr: MsgAddressInt = w.parse().expect("a wallet address");
            if kind_of(net, &addr) != Some("wallet") {
                continue;
            }
            let snap = wallet_snap(net, &addr);
            let minter = wallet_master(net, &addr);
            let owner = wallet_owner(net, &addr);
            balances += snap.balance;
            for (b, amount) in &snap.holds {
                holds += amount;
                if self.admitted.contains_key(&(key(&minter), key(&owner), snap.born, *b)) {
                    pending += amount;
                }
            }
        }
        let mut transfers: i128 = 0;
        for m in &net.queue {
            if body_op(m) == Some(OP_INTERNAL_TRANSFER) || bounced_transfer(m) {
                let mut s = m.body().expect("a body").clone();
                if m.int_header().map(|h| h.bounced).unwrap_or(false) {
                    s.get_next_u32().unwrap();
                }
                if s.remaining_bits() == 0 {
                    s = SliceData::load_cell(s.reference(0).unwrap()).unwrap();
                }
                s.get_next_u32().unwrap();
                s.get_next_u64().unwrap();
                let amount = chain_block::Coins::construct_from(&mut s)
                    .expect("an amount")
                    .as_u128() as i128;
                transfers += amount;
            }
        }
        let mut supply: i128 = self.deleted_supply;
        let mut capacity_ok = true;
        for m in &self.minters {
            let addr: MsgAddressInt = m.parse().expect("a minter address");
            if kind_of(net, &addr) != Some("minter") {
                continue;
            }
            let (s, f, mr, br, st) = net.supply_state_of(&addr);
            supply += s;
            capacity_ok &= s + f + mr + br + st <= MAX_SUPPLY as i128;
        }
        let landed: i128 =
            self.landed.values().sum::<i128>() + self.landed_refunds.values().sum::<i128>();
        assert!(capacity_ok, "capacity in use exceeds MAX_SUPPLY");
        assert_eq!(
            balances + holds + transfers + self.deleted_balances,
            supply + landed + pending,
            "I1: balances {balances} + holds {holds} + transfers {transfers} + deleted {} != supply {supply} + landed {landed} + admitted holds {pending}",
            self.deleted_balances
        );
    }
}

fn bounced_transfer(m: &Message) -> bool {
    if !m.int_header().map(|h| h.bounced).unwrap_or(false) {
        return false;
    }
    let mut s = m.body().expect("a body").clone();
    s.get_next_u32().ok();
    s.get_next_u32().ok() == Some(OP_INTERNAL_TRANSFER)
}

pub fn wallet_master(net: &Net, wallet: &MsgAddressInt) -> MsgAddressInt {
    let r = net.get(wallet, "get_wallet_data", vec![]);
    MsgAddressInt::construct_from(&mut r.slice_at(2)).expect("a master")
}

pub fn wallet_owner(net: &Net, wallet: &MsgAddressInt) -> MsgAddressInt {
    let r = net.get(wallet, "get_wallet_data", vec![]);
    MsgAddressInt::construct_from(&mut r.slice_at(1)).expect("an owner")
}

fn minter_life_of(net: &Net, minter: &MsgAddressInt) -> i128 {
    net.try_get(minter, "get_channels", vec![]).map(|r| r.int_at(0)).unwrap_or(0)
}

fn burn_life_of(net: &Net, minter: &MsgAddressInt, owner: &[u8], where_: i128) -> i128 {
    let owner_addr =
        MsgAddressInt::with_params(0, chain_block::UInt256::from_slice(owner)).unwrap();
    let r = net.get(minter, "get_holder", vec![addr_arg(&owner_addr)]);
    if where_ == 2 { r.int_at(12) } else { r.int_at(1) }
}

pub fn mint_descriptor_s(d: &chain_block::Cell) -> u64 {
    let mut s = SliceData::load_cell(d.clone()).unwrap();
    s.get_next_u32().unwrap();
    s.get_next_u64().unwrap();
    s.get_next_u64().unwrap()
}

pub fn wallet_snap(net: &Net, addr: &MsgAddressInt) -> WalletSnap {
    let data = net.get(addr, "get_wallet_data", vec![]);
    let st = net.get(addr, "get_settlement_state", vec![]);
    let next_burn = st.int_at(6) as u64;
    let floor = st.int_at(9) as u64;
    let mut holds = BTreeMap::new();
    for b in floor..next_burn {
        let r = net.get(addr, "get_burn", vec![int_arg(b)]);
        if r.int_at(0) >= 0 {
            holds.insert(b, r.int_at(0));
        }
    }
    let credits_above = net.get(addr, "get_credits_above_count", vec![]).int_at(0) as usize;
    WalletSnap {
        balance: data.int_at(0),
        born: st.int_at(0),
        minter_life: st.int_at(1),
        holds,
        credits_above,
    }
}

pub fn minter_snap(net: &Net, addr: &MsgAddressInt) -> MinterSnap {
    let (supply, in_flight, mint_reserve, burn_reserve, stranded) = net.supply_state_of(addr);
    let ch = net.get(addr, "get_channels", vec![]);
    let born = ch.int_at(0);
    let floor = ch.int_at(6).min(ch.int_at(3)) as u64;
    let high = ch.int_at(5) as u64;
    let mut mints = BTreeMap::new();
    let mut escrows = BTreeMap::new();
    for s in floor..high {
        let r = net.get(addr, "get_mint", vec![int_arg(s)]);
        if r.int_at(0) >= 0 {
            mints.insert(s, (r.int_at(0), r.int_at(1), r.int_at(2), r.int_at(5)));
            escrows.insert(s, r.int_at(3));
        }
    }
    let mint_entries = net.get(addr, "get_mint_count", vec![]).int_at(0);
    let mut burns = BTreeMap::new();
    let mut holder_burn_entries = BTreeMap::new();
    for owner in known_owners(net) {
        let h = net.get(addr, "get_holder", vec![addr_arg(&owner)]);
        if h.int_at(0) == 0 {
            continue;
        }
        holder_burn_entries.insert(account_hash(&owner), h.int_at(14));
        let from = h.int_at(11).max(0) as u64;
        let to = h.int_at(10) as u64;
        for b in from..to {
            let r = net.get(addr, "get_burn", vec![addr_arg(&owner), int_arg(b)]);
            if r.int_at(0) > 0 {
                burns.insert((account_hash(&owner), b), (r.int_at(0), r.int_at(1), r.int_at(4)));
            }
        }
        // the old life's burns are numbered from 0 in their own life
        if h.int_at(12) != 0 {
            for b in 0..8 {
                let r = net.get(addr, "get_burn", vec![addr_arg(&owner), int_arg(b)]);
                if r.int_at(0) == 2 {
                    burns
                        .insert((account_hash(&owner), b), (r.int_at(0), r.int_at(1), r.int_at(4)));
                }
            }
        }
    }
    let mint_wm = ch.int_at(3) as u64;
    let mut burn_wm = BTreeMap::new();
    for owner in known_owners(net) {
        let h = net.get(addr, "get_holder", vec![addr_arg(&owner)]);
        if h.int_at(0) != 0 {
            burn_wm.insert(account_hash(&owner), h.int_at(8) as u64);
        }
    }
    MinterSnap {
        escrows,
        mint_wm,
        burn_wm,
        born,
        supply,
        in_flight,
        mint_reserve,
        burn_reserve,
        stranded,
        mints,
        burns,
        mint_entries,
        holder_burn_entries,
    }
}

pub fn known_owners(net: &Net) -> Vec<MsgAddressInt> {
    let mut owners: Vec<MsgAddressInt> = net.users.iter().map(|u| u.address().clone()).collect();
    owners.push(net.stranger.address().clone());
    owners
}

pub fn bridge_snap(net: &Net, addr: &MsgAddressInt) -> BridgeSnap {
    let st = net.get(addr, "get_bridge_state", vec![]);
    let born = st.int_at(0);
    let wm = st.int_at(6) as u64;
    let window = declared("SWAP_WINDOW") as u64;
    let mut swaps = BTreeMap::new();
    let mut fees = BTreeMap::new();
    let mut stored = 0;
    for n in wm.saturating_sub(1)..wm.saturating_add(window + 1) {
        let r = net.get(addr, "get_swap", vec![int_arg(n)]);
        if r.int_at(0) >= 0 {
            swaps.insert(n, r.int_at(0));
            fees.insert(n, r.int_at(1));
            stored += 1;
        }
    }
    let mut outcomes = BTreeMap::new();
    let mut pending = BTreeMap::new();
    let mut burns_stored = BTreeMap::new();
    let mut burn_bounds = BTreeMap::new();
    for minter in net.minters.values().cloned().chain(std::iter::once(net.minter())) {
        let c = net.get(addr, "get_channel", vec![addr_arg(&minter)]);
        if c.int_at(0) == 0 {
            continue;
        }
        pending.insert(account_hash(&minter), c.int_at(10));
        let from = c.int_at(9) as u64;
        let to = c.int_at(8) as u64;
        let mut n = 0;
        for m in from..to {
            let r = net.get(addr, "get_burn_outcome", vec![addr_arg(&minter), int_arg(m)]);
            if r.int_at(0) >= 0 {
                outcomes.insert((account_hash(&minter), m), r.int_at(0));
                n += 1;
            }
        }
        burns_stored.insert(account_hash(&minter), n);
        burn_bounds.insert(account_hash(&minter), (c.int_at(6) as u64, c.int_at(7) as u64));
    }
    BridgeSnap {
        born,
        swaps,
        outcomes,
        pending,
        burns_stored,
        swaps_stored: stored,
        burn_bounds,
        swap_wm: wm,
        fees,
    }
}
