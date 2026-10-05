/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The three contracts' storage layouts, mirrored field for field, so a test can
//! put a contract into a state ordinary traffic would take too long to reach:
//! a counter next to exhaustion, a dictionary filled to its limit. Every layout
//! here must equal the contract's own load_data and save_data; a mismatch makes
//! the next transaction on the patched account fail to load its storage.

#![allow(dead_code)]

use chain_block::{
    BuilderData, Cell, Coins, Deserializable, HashmapE, HashmapType, IBitstring, MsgAddressInt,
    Serializable, SliceData,
};

use crate::harness::*;

fn coins_of(s: &mut SliceData) -> u128 {
    Coins::construct_from(s).expect("coins").as_u128()
}

fn dict_of(s: &mut SliceData) -> Option<Cell> {
    if s.get_next_bit().expect("a dict bit") {
        Some(s.checked_drain_reference().expect("a dict root"))
    } else {
        None
    }
}

fn store_dict(b: &mut BuilderData, d: &Option<Cell>) {
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

fn key(bits: usize, value: &[u8]) -> SliceData {
    let mut b = BuilderData::new();
    b.append_raw(value, bits).unwrap();
    SliceData::load_builder(b).unwrap()
}

pub fn key64(k: u64) -> SliceData {
    key(64, &k.to_be_bytes())
}

pub fn key256(k: &[u8]) -> SliceData {
    key(256, k)
}

pub struct MinterData {
    pub supply: i128,
    pub in_flight: u128,
    pub mint_reserve: u128,
    pub burn_reserve: u128,
    pub stranded: u128,
    pub content: Cell,
    pub code: Cell,
    pub bridge: MsgAddressInt,
    pub bridge_life: u64,
    pub born: u64,
    pub terminal: bool,
    pub mint_wm: u64,
    pub mint_cf: u64,
    pub next_notice: u64,
    pub bridge_burn_ack: u64,
    pub holders_count: u32,
    pub mints: Option<Cell>,
    pub notices: Option<Cell>,
    pub holders: Option<Cell>,
}

impl MinterData {
    pub fn parse(data: &Cell) -> Self {
        let mut s = SliceData::load_cell(data.clone()).unwrap();
        let supply = {
            let raw = s.get_next_bits(128).unwrap();
            i128::from_be_bytes(raw.try_into().unwrap())
        };
        let in_flight = coins_of(&mut s);
        let mint_reserve = coins_of(&mut s);
        let burn_reserve = coins_of(&mut s);
        let stranded = coins_of(&mut s);
        let content = s.checked_drain_reference().unwrap();
        let code = s.checked_drain_reference().unwrap();
        let mut a = SliceData::load_cell(s.checked_drain_reference().unwrap()).unwrap();
        let bridge = MsgAddressInt::construct_from(&mut a).unwrap();
        let bridge_life = a.get_next_u64().unwrap();
        let born = a.get_next_u64().unwrap();
        let terminal = a.get_next_bit().unwrap();
        let mint_wm = a.get_next_u64().unwrap();
        let mint_cf = a.get_next_u64().unwrap();
        let next_notice = a.get_next_u64().unwrap();
        let bridge_burn_ack = a.get_next_u64().unwrap();
        let holders_count = a.get_next_u32().unwrap();
        let mints = dict_of(&mut a);
        let notices = dict_of(&mut a);
        let holders = dict_of(&mut a);
        Self {
            supply,
            in_flight,
            mint_reserve,
            burn_reserve,
            stranded,
            content,
            code,
            bridge,
            bridge_life,
            born,
            terminal,
            mint_wm,
            mint_cf,
            next_notice,
            bridge_burn_ack,
            holders_count,
            mints,
            notices,
            holders,
        }
    }

    pub fn build(&self) -> Cell {
        cell(|b| {
            b.append_raw(&self.supply.to_be_bytes(), 128).unwrap();
            coins(b, self.in_flight);
            coins(b, self.mint_reserve);
            coins(b, self.burn_reserve);
            coins(b, self.stranded);
            b.checked_append_reference(self.content.clone()).unwrap();
            b.checked_append_reference(self.code.clone()).unwrap();
            b.checked_append_reference(cell(|a| {
                self.bridge.write_to(a).unwrap();
                a.append_u64(self.bridge_life).unwrap();
                a.append_u64(self.born).unwrap();
                a.append_bit_bool(self.terminal).unwrap();
                a.append_u64(self.mint_wm).unwrap();
                a.append_u64(self.mint_cf).unwrap();
                a.append_u64(self.next_notice).unwrap();
                a.append_u64(self.bridge_burn_ack).unwrap();
                a.append_u32(self.holders_count).unwrap();
                store_dict(a, &self.mints);
                store_dict(a, &self.notices);
                store_dict(a, &self.holders);
            }))
            .unwrap();
        })
    }

    pub fn holder(&self, owner: &[u8]) -> Option<Holder> {
        let dict = HashmapE::with_hashmap(256, self.holders.clone());
        let v = dict.get(key256(owner)).unwrap()?;
        let mut v = v;
        Some(Holder::parse(&v.checked_drain_reference().unwrap()))
    }

    pub fn set_holder(&mut self, owner: &[u8], h: &Holder) {
        let mut dict = HashmapE::with_hashmap(256, self.holders.clone());
        dict.setref(key256(owner), h.build()).unwrap();
        self.holders = dict.data().cloned();
    }
}

pub struct Holder {
    pub wallet_life: u64,
    pub open: u8,
    pub attempt: u32,
    pub opening_life: u64,
    pub next_credit: u64,
    pub credit_ack: u64,
    pub burn_wm: u64,
    pub burn_cf: u64,
    pub credits: Option<Cell>,
    pub burns: Option<Cell>,
    pub awaiting: Option<Cell>,
    pub old: Option<Cell>,
}

impl Holder {
    pub fn empty() -> Self {
        Self {
            wallet_life: 0,
            open: 0,
            attempt: 0,
            opening_life: 0,
            next_credit: 0,
            credit_ack: 0,
            burn_wm: 0,
            burn_cf: 0,
            credits: None,
            burns: None,
            awaiting: None,
            old: None,
        }
    }

    pub fn parse(c: &Cell) -> Self {
        let mut s = SliceData::load_cell(c.clone()).unwrap();
        let wallet_life = s.get_next_u64().unwrap();
        let open = s.get_next_bits(2).unwrap()[0] >> 6;
        let attempt = s.get_next_u32().unwrap();
        let opening_life = s.get_next_u64().unwrap();
        let next_credit = s.get_next_u64().unwrap();
        let credit_ack = s.get_next_u64().unwrap();
        let burn_wm = s.get_next_u64().unwrap();
        let burn_cf = s.get_next_u64().unwrap();
        let credits = dict_of(&mut s);
        let burns = dict_of(&mut s);
        let awaiting = dict_of(&mut s);
        let old = dict_of(&mut s);
        Self { wallet_life, open, attempt, opening_life, next_credit, credit_ack, burn_wm, burn_cf, credits, burns, awaiting, old }
    }

    pub fn build(&self) -> Cell {
        cell(|b| {
            b.append_u64(self.wallet_life).unwrap();
            b.append_bits(self.open as usize, 2).unwrap();
            b.append_u32(self.attempt).unwrap();
            b.append_u64(self.opening_life).unwrap();
            b.append_u64(self.next_credit).unwrap();
            b.append_u64(self.credit_ack).unwrap();
            b.append_u64(self.burn_wm).unwrap();
            b.append_u64(self.burn_cf).unwrap();
            store_dict(b, &self.credits);
            store_dict(b, &self.burns);
            store_dict(b, &self.awaiting);
            store_dict(b, &self.old);
        })
    }
}

pub struct WalletData {
    pub balance: u128,
    pub owner: MsgAddressInt,
    pub master: MsgAddressInt,
    pub code: Cell,
    pub born: u64,
    pub minter_life: u64,
    pub terminal: bool,
    pub attempt: u32,
    pub credit_wm: u64,
    pub credit_cf: u64,
    pub credit_high: u64,
    pub credits_above: Option<Cell>,
    pub next_burn: u64,
    pub burn_ack: u64,
    pub burns: Option<Cell>,
}

impl WalletData {
    pub fn parse(data: &Cell) -> Self {
        let mut s = SliceData::load_cell(data.clone()).unwrap();
        let balance = coins_of(&mut s);
        let owner = MsgAddressInt::construct_from(&mut s).unwrap();
        let master = MsgAddressInt::construct_from(&mut s).unwrap();
        let code = s.checked_drain_reference().unwrap();
        let mut t = SliceData::load_cell(s.checked_drain_reference().unwrap()).unwrap();
        let born = t.get_next_u64().unwrap();
        let minter_life = t.get_next_u64().unwrap();
        let terminal = t.get_next_bit().unwrap();
        let attempt = t.get_next_u32().unwrap();
        let credit_wm = t.get_next_u64().unwrap();
        let credit_cf = t.get_next_u64().unwrap();
        let credit_high = t.get_next_u64().unwrap();
        let credits_above = dict_of(&mut t);
        let next_burn = t.get_next_u64().unwrap();
        let burn_ack = t.get_next_u64().unwrap();
        let burns = dict_of(&mut t);
        Self { balance, owner, master, code, born, minter_life, terminal, attempt, credit_wm, credit_cf, credit_high, credits_above, next_burn, burn_ack, burns }
    }

    pub fn build(&self) -> Cell {
        cell(|b| {
            coins(b, self.balance);
            self.owner.write_to(b).unwrap();
            self.master.write_to(b).unwrap();
            b.checked_append_reference(self.code.clone()).unwrap();
            b.checked_append_reference(cell(|t| {
                t.append_u64(self.born).unwrap();
                t.append_u64(self.minter_life).unwrap();
                t.append_bit_bool(self.terminal).unwrap();
                t.append_u32(self.attempt).unwrap();
                t.append_u64(self.credit_wm).unwrap();
                t.append_u64(self.credit_cf).unwrap();
                t.append_u64(self.credit_high).unwrap();
                store_dict(t, &self.credits_above);
                t.append_u64(self.next_burn).unwrap();
                t.append_u64(self.burn_ack).unwrap();
                store_dict(t, &self.burns);
            }))
            .unwrap();
        })
    }
}

pub struct BridgeData {
    pub born: u64,
    pub evm_chain: u32,
    pub evm_bridge: Vec<u8>,
    pub generation: u32,
    pub gen_start: u64,
    pub gen_state: u8,
    pub collector: MsgAddressInt,
    pub minter_code: Cell,
    pub wallet_code: Cell,
    pub swap_wm: u64,
    pub swaps: Option<Cell>,
    pub channels: Option<Cell>,
    pub channels_count: u32,
}

impl BridgeData {
    pub fn parse(data: &Cell) -> Self {
        let mut s = SliceData::load_cell(data.clone()).unwrap();
        let born = s.get_next_u64().unwrap();
        let evm_chain = s.get_next_u32().unwrap();
        let evm_bridge = s.get_next_bits(160).unwrap();
        let generation = s.get_next_u32().unwrap();
        let gen_start = s.get_next_u64().unwrap();
        let gen_state = s.get_next_bits(2).unwrap()[0] >> 6;
        let collector = MsgAddressInt::construct_from(&mut s).unwrap();
        let minter_code = s.checked_drain_reference().unwrap();
        let wallet_code = s.checked_drain_reference().unwrap();
        let mut t = SliceData::load_cell(s.checked_drain_reference().unwrap()).unwrap();
        let swap_wm = t.get_next_u64().unwrap();
        let swaps = dict_of(&mut t);
        let channels = dict_of(&mut t);
        let channels_count = t.get_next_u32().unwrap();
        Self { born, evm_chain, evm_bridge, generation, gen_start, gen_state, collector, minter_code, wallet_code, swap_wm, swaps, channels, channels_count }
    }

    pub fn build(&self) -> Cell {
        cell(|b| {
            b.append_u64(self.born).unwrap();
            b.append_u32(self.evm_chain).unwrap();
            b.append_raw(&self.evm_bridge, 160).unwrap();
            b.append_u32(self.generation).unwrap();
            b.append_u64(self.gen_start).unwrap();
            b.append_bits(self.gen_state as usize, 2).unwrap();
            self.collector.write_to(b).unwrap();
            b.checked_append_reference(self.minter_code.clone()).unwrap();
            b.checked_append_reference(self.wallet_code.clone()).unwrap();
            b.checked_append_reference(cell(|t| {
                t.append_u64(self.swap_wm).unwrap();
                store_dict(t, &self.swaps);
                store_dict(t, &self.channels);
                t.append_u32(self.channels_count).unwrap();
            }))
            .unwrap();
        })
    }

    pub fn channel(&self, minter: &[u8]) -> Option<Channel> {
        let dict = HashmapE::with_hashmap(256, self.channels.clone());
        let mut v = dict.get(key256(minter)).unwrap()?;
        Some(Channel::parse(&v.checked_drain_reference().unwrap()))
    }

    pub fn set_channel(&mut self, minter: &[u8], c: &Channel) {
        let mut dict = HashmapE::with_hashmap(256, self.channels.clone());
        dict.setref(key256(minter), c.build()).unwrap();
        self.channels = dict.data().cloned();
    }
}

pub struct Channel {
    pub terminal: bool,
    pub minter_life: u64,
    pub next_mint: u64,
    pub mint_ack: u64,
    pub burn_wm: u64,
    pub burn_cf: u64,
    pub burn_high: u64,
    pub token_data: Cell,
    pub pending: Option<Cell>,
    pub burns: Option<Cell>,
}

impl Channel {
    pub fn parse(c: &Cell) -> Self {
        let mut s = SliceData::load_cell(c.clone()).unwrap();
        let terminal = s.get_next_bit().unwrap();
        let minter_life = s.get_next_u64().unwrap();
        let next_mint = s.get_next_u64().unwrap();
        let mint_ack = s.get_next_u64().unwrap();
        let burn_wm = s.get_next_u64().unwrap();
        let burn_cf = s.get_next_u64().unwrap();
        let burn_high = s.get_next_u64().unwrap();
        let token_data = s.checked_drain_reference().unwrap();
        let pending = dict_of(&mut s);
        let burns = dict_of(&mut s);
        Self { terminal, minter_life, next_mint, mint_ack, burn_wm, burn_cf, burn_high, token_data, pending, burns }
    }

    pub fn build(&self) -> Cell {
        cell(|b| {
            b.append_bit_bool(self.terminal).unwrap();
            b.append_u64(self.minter_life).unwrap();
            b.append_u64(self.next_mint).unwrap();
            b.append_u64(self.mint_ack).unwrap();
            b.append_u64(self.burn_wm).unwrap();
            b.append_u64(self.burn_cf).unwrap();
            b.append_u64(self.burn_high).unwrap();
            b.checked_append_reference(self.token_data.clone()).unwrap();
            store_dict(b, &self.pending);
            store_dict(b, &self.burns);
        })
    }
}

impl Net {
    fn data_of(&self, addr: &MsgAddressInt) -> Cell {
        self.bc.get_account(addr).and_then(|a| a.get_data()).expect("deployed")
    }

    fn set_data_of(&mut self, addr: &MsgAddressInt, data: Cell) {
        let mut account = self.bc.get_account(addr).expect("deployed").clone();
        assert!(account.set_data(data), "the data is replaced");
        self.bc.set_account(addr.clone(), account);
    }

    pub fn patch_minter(&mut self, f: impl FnOnce(&mut MinterData)) {
        let addr = self.minter();
        let mut m = MinterData::parse(&self.data_of(&addr));
        f(&mut m);
        let data = m.build();
        self.set_data_of(&addr, data);
    }

    pub fn patch_holder(&mut self, owner: &MsgAddressInt, f: impl FnOnce(&mut Holder)) {
        let o = account_hash(owner);
        self.patch_minter(|m| {
            let mut h = m.holder(&o).expect("a holder");
            f(&mut h);
            m.set_holder(&o, &h);
        });
    }

    pub fn patch_wallet(&mut self, owner: &MsgAddressInt, f: impl FnOnce(&mut WalletData)) {
        let addr = self.wallet_of(owner);
        let mut w = WalletData::parse(&self.data_of(&addr));
        f(&mut w);
        let data = w.build();
        self.set_data_of(&addr, data);
    }

    pub fn patch_bridge(&mut self, f: impl FnOnce(&mut BridgeData)) {
        let addr = self.bridge.clone();
        let mut b = BridgeData::parse(&self.data_of(&addr));
        f(&mut b);
        let data = b.build();
        self.set_data_of(&addr, data);
    }

    pub fn patch_channel(&mut self, f: impl FnOnce(&mut Channel)) {
        let minter = account_hash(&self.minter());
        self.patch_bridge(|b| {
            let mut c = b.channel(&minter).expect("a channel");
            f(&mut c);
            b.set_channel(&minter, &c);
        });
    }

    /// The cells an account's state occupies, counted as the engines count them:
    /// every distinct cell of its code and data.
    pub fn state_cells(&self, addr: &MsgAddressInt) -> (usize, usize) {
        let account = self.bc.get_account(addr).expect("deployed");
        let mut seen = std::collections::HashSet::new();
        let mut bits = 0usize;
        fn visit(c: &Cell, seen: &mut std::collections::HashSet<chain_block::UInt256>, bits: &mut usize) {
            if seen.insert(c.repr_hash()) {
                *bits += c.bit_length();
                for i in 0..c.references_count() {
                    visit(&c.reference(i).unwrap(), seen, bits);
                }
            }
        }
        if let Some(code) = account.get_code() {
            visit(&code, &mut seen, &mut bits);
        }
        if let Some(data) = account.get_data() {
            visit(&data, &mut seen, &mut bits);
        }
        (seen.len(), bits)
    }
}

/// Round trip: a parsed and rebuilt state is the same cell, so a patch changes
/// only the field it means to.
pub fn assert_round_trip(net: &Net) {
    let m = net.bc.get_account(&net.minter()).and_then(|a| a.get_data()).unwrap();
    assert_eq!(MinterData::parse(&m).build().repr_hash(), m.repr_hash(), "the minter layout");
    let w = net.bc.get_account(&net.wallet_of(&net.user(0))).and_then(|a| a.get_data()).unwrap();
    assert_eq!(WalletData::parse(&w).build().repr_hash(), w.repr_hash(), "the wallet layout");
    let b = net.bc.get_account(&net.bridge).and_then(|a| a.get_data()).unwrap();
    assert_eq!(BridgeData::parse(&b).build().repr_hash(), b.repr_hash(), "the bridge layout");
}
