/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The bridge oracle multisigs as a test drives them: their initial data, the
//! vote message a query asks them to send, and a quorum query signed by two
//! real owner keys. Shared by bridge_multisig_sandbox and token_bridge_sandbox.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use chain_block::{
    BuilderData, Cell, Coins, CurrencyCollection, IBitstring, InternalMessageHeader, Message,
    MsgAddressInt, Serializable, SliceData, StateInit, UInt256,
};
use ed25519_dalek::{Signer, SigningKey};

pub const TOS: u64 = 1_000_000_000;
pub const WALLET_ID: u32 = 0x4554_4831;
/// The network id the sandbox chain reports through `GLOBALID`.
pub const SANDBOX_GLOBAL_ID: i32 = 42;

/// The exit codes of the guards at `check_proposed_query`, and of
/// `create_init_state` for an empty allowlist.
pub const ERR_DESTINATION: i32 = 46;
pub const ERR_NOT_BOUNCEABLE: i32 = 47;
pub const ERR_SEND_MODE: i32 = 48;
pub const ERR_VALUE: i32 = 49;
pub const ERR_STATE_INIT: i32 = 50;
pub const ERR_EMPTY_ALLOWLIST: i32 = 51;

/// The repository the sources are read from: `TOS_ROOT` when set, so a
/// mutation control can point the suite at a mutated copy.
pub fn repo_root() -> PathBuf {
    std::env::var("TOS_ROOT").map(PathBuf::from).unwrap_or_else(|_| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root above the contracts crate")
            .to_path_buf()
    })
}

pub fn crosschain(path: &str) -> PathBuf {
    repo_root().join("crosschain").join(path)
}

/// One bridge multisig: its name, the sources its build compiles in order,
/// and the directory that holds them and its `new-multisig.fif`.
pub struct Variant {
    pub name: &'static str,
    pub sources: Vec<PathBuf>,
    pub dir: PathBuf,
}

impl Variant {
    pub fn main_source(&self) -> &Path {
        self.sources.last().expect("a multisig source")
    }

    /// A constant as the multisig source declares it.
    pub fn declared(&self, name: &str) -> u128 {
        let source = std::fs::read_to_string(self.main_source()).expect("the multisig source");
        let prefix = format!("const int {name} = ");
        let line = source
            .lines()
            .find(|line| line.starts_with(&prefix))
            .unwrap_or_else(|| panic!("{}: no declaration of {name}", self.name));
        line[prefix.len()..].split(';').next().expect("a value").trim().parse().expect("a number")
    }
}

pub fn token_variant() -> Variant {
    let dir = crosschain("token-bridge/tvm/contracts");
    Variant { name: "token-bridge", sources: vec![dir.join("multisig.fc")], dir }
}

pub fn coin_variant(network: &'static str) -> Variant {
    let dir = crosschain(&format!("coin-bridge/tvm/{network}"));
    let name = if network == "ethereum" { "coin-bridge/ethereum" } else { "coin-bridge/bsc" };
    Variant { name, sources: vec![dir.join("stdlib.fc"), dir.join("multisig-code.fc")], dir }
}

/// Every bridge multisig.
pub fn variants() -> Vec<Variant> {
    vec![coin_variant("ethereum"), coin_variant("bsc"), token_variant()]
}

pub fn cell(build: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    build(&mut b);
    b.into_cell().expect("cell")
}

pub fn coins(b: &mut BuilderData, amount: u128) {
    amount.to_string().parse::<Coins>().expect("coins").write_to(b).expect("coins");
}

pub fn hash_of(addr: &MsgAddressInt) -> [u8; 32] {
    addr.address().get_bytestring(0).try_into().expect("a 256-bit account id")
}

pub fn masterchain(hash: [u8; 32]) -> MsgAddressInt {
    MsgAddressInt::with_params(-1, UInt256::from(hash)).expect("an address")
}

pub fn basechain(hash: [u8; 32]) -> MsgAddressInt {
    MsgAddressInt::with_params(0, UInt256::from(hash)).expect("an address")
}

pub fn owner_keys() -> [SigningKey; 2] {
    [SigningKey::from_bytes(&[0x51; 32]), SigningKey::from_bytes(&[0x52; 32])]
}

pub fn public_keys(keys: &[SigningKey]) -> Vec<[u8; 32]> {
    keys.iter().map(|key| key.verifying_key().to_bytes()).collect()
}

pub fn owner_dict(keys: &[[u8; 32]]) -> Cell {
    let mut dict = chain_block::HashmapE::with_bit_len(8);
    for (index, key) in keys.iter().enumerate() {
        let index =
            SliceData::load_builder(BuilderData::with_raw(vec![index as u8], 8).unwrap()).unwrap();
        let value = SliceData::load_cell(cell(|b| {
            b.append_u256(key).unwrap();
            b.append_u8(0).unwrap();
        }))
        .unwrap();
        dict.set(index, &value).unwrap();
    }
    chain_block::HashmapType::data(&dict).cloned().expect("non-empty owner set")
}

/// The allowlist as the multisig stores it: HashmapE 256 of empty values.
pub fn allowlist(bridges: &[[u8; 32]]) -> Option<Cell> {
    let mut dict = chain_block::HashmapE::with_bit_len(256);
    for hash in bridges {
        let key =
            SliceData::load_builder(BuilderData::with_raw(hash.to_vec(), 256).unwrap()).unwrap();
        dict.set(key, &SliceData::default()).unwrap();
    }
    chain_block::HashmapType::data(&dict).cloned()
}

/// wallet_id n k last_cleaned owners pending lock_until allowed, as the bridge
/// multisigs store it.
pub fn wallet_data(owners: &[[u8; 32]], k: u8, allowed: &[[u8; 32]]) -> Cell {
    wallet_data_with_pending(&owner_dict(owners), owners.len() as u8, k, allowed, None)
}

/// The owner set with each owner's count of pending queries it created.
pub fn owner_dict_with_floods(keys: &[[u8; 32]], floods: &[u8]) -> Cell {
    let mut dict = chain_block::HashmapE::with_bit_len(8);
    for (index, (key, flood)) in keys.iter().zip(floods).enumerate() {
        let index =
            SliceData::load_builder(BuilderData::with_raw(vec![index as u8], 8).unwrap()).unwrap();
        let value = SliceData::load_cell(cell(|b| {
            b.append_u256(key).unwrap();
            b.append_u8(*flood).unwrap();
        }))
        .unwrap();
        dict.set(index, &value).unwrap();
    }
    chain_block::HashmapType::data(&dict).cloned().expect("non-empty owner set")
}

/// The data with a given owner dictionary and pending-query dictionary, as
/// only a hand-built StateInit can start with.
pub fn wallet_data_with_pending(
    owners: &Cell,
    n: u8,
    k: u8,
    allowed: &[[u8; 32]],
    pending: Option<Cell>,
) -> Cell {
    cell(|b| {
        b.append_u32(WALLET_ID).unwrap();
        b.append_u8(n).unwrap();
        b.append_u8(k).unwrap();
        b.append_u64(0).unwrap();
        b.append_bit_one().unwrap();
        b.checked_append_reference(owners.clone()).unwrap();
        match pending {
            Some(dict) => {
                b.append_bit_one().unwrap();
                b.checked_append_reference(dict).unwrap();
            }
            None => {
                b.append_bit_zero().unwrap();
            }
        }
        b.append_u32(0).unwrap();
        match allowlist(allowed) {
            Some(dict) => {
                b.append_bit_one().unwrap();
                b.checked_append_reference(dict).unwrap();
            }
            None => {
                b.append_bit_zero().unwrap();
            }
        }
    })
}

pub fn state_init(code: &Cell, owners: &[[u8; 32]], k: u8, allowed: &[[u8; 32]]) -> StateInit {
    StateInit::with_code_and_data(code.clone(), wallet_data(owners, k, allowed))
}

pub fn address_of(init: &StateInit, workchain: i8) -> MsgAddressInt {
    let hash = init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    MsgAddressInt::with_params(i32::from(workchain), hash).unwrap()
}

/// The message a query asks the multisig to send. The default is what every
/// oracle flow sends: an internal, bounceable vote of one TOS with no
/// StateInit.
#[derive(Clone)]
pub struct Vote {
    pub dest: MsgAddressInt,
    pub value: u64,
    pub bounce: bool,
    pub extra_currency: bool,
    pub state_init: Option<StateInit>,
    pub body: Option<Cell>,
    /// The bounced flag, which only the network sets on a real bounce.
    pub bounced: bool,
    /// A message cell built bit by bit, for layouts the typed header cannot
    /// express; it replaces every field above.
    pub raw: Option<Cell>,
}

impl Vote {
    pub fn to(dest: &MsgAddressInt) -> Self {
        Vote {
            dest: dest.clone(),
            value: TOS,
            bounce: true,
            extra_currency: false,
            state_init: None,
            body: None,
            bounced: false,
            raw: None,
        }
    }

    /// An internal, bounceable message of one TOS whose destination field is
    /// `dest`, written as given, followed by an otherwise ordinary header.
    pub fn raw_destination(dest: impl FnOnce(&mut BuilderData)) -> Self {
        let raw = cell(|b| {
            b.append_bits(0b0110, 4).unwrap(); // int_msg_info, ihr disabled, bounce
            b.append_bits(0, 2).unwrap(); // src: addr_none
            dest(b);
            coins(b, u128::from(TOS));
            b.append_bit_zero().unwrap(); // no extra currencies
            coins(b, 0); // ihr_fee
            coins(b, 0); // fwd_fee
            b.append_u64(0).unwrap();
            b.append_u32(0).unwrap();
            b.append_bit_zero().unwrap(); // no StateInit
            b.append_bit_zero().unwrap(); // body in place, empty
        });
        Vote { raw: Some(raw), ..Vote::to(&masterchain([0; 32])) }
    }

    pub fn message(&self) -> Message {
        let mut value = CurrencyCollection::with_coins(self.value);
        if self.extra_currency {
            value.set_other(7, 1).expect("an extra currency");
        }
        let header = InternalMessageHeader {
            bounce: self.bounce,
            bounced: self.bounced,
            dst: self.dest.clone(),
            value,
            ..Default::default()
        };
        let mut msg = Message::with_int_header(header);
        if let Some(init) = &self.state_init {
            msg.set_state_init(init.clone());
        }
        if let Some(body) = &self.body {
            msg.set_body(SliceData::load_cell(body.clone()).expect("a body"));
        }
        msg
    }

    pub fn cell(&self) -> Cell {
        if let Some(raw) = &self.raw {
            return raw.clone();
        }
        self.message().serialize().expect("a message cell")
    }
}

/// A query both owners sign (owner 0 as root, owner 1 as co-signer), so it
/// reaches k = 2 in one message.
/// A query owner `index` signs alone, as root, with no co-signatures.
pub fn root_query(key: &SigningKey, index: u8, query_id: u64, mode: u8, msg: Cell) -> Cell {
    let signed = cell(|b| {
        b.append_u8(index).unwrap();
        b.append_bit_zero().unwrap();
        b.append_u32(WALLET_ID).unwrap();
        b.append_i32(SANDBOX_GLOBAL_ID).unwrap();
        b.append_u64(query_id).unwrap();
        b.append_u8(mode).unwrap();
        b.checked_append_reference(msg).unwrap();
    });
    let signature = key.sign(signed.repr_hash().as_slice()).to_bytes();
    let signed = SliceData::load_cell(signed).unwrap();
    cell(|b| {
        b.append_raw(&signature, 512).unwrap();
        b.append_builder(&signed.as_builder().unwrap()).unwrap();
    })
}

pub fn quorum_query(keys: &[SigningKey; 2], query_id: u64, mode: u8, msg: Cell) -> Cell {
    let rest = cell(|b| {
        b.append_u32(WALLET_ID).unwrap();
        b.append_i32(SANDBOX_GLOBAL_ID).unwrap();
        b.append_u64(query_id).unwrap();
        b.append_u8(mode).unwrap();
        b.checked_append_reference(msg).unwrap();
    });
    let co_signature = keys[1].sign(rest.repr_hash().as_slice()).to_bytes();
    let signatures = cell(|b| {
        b.append_raw(&co_signature, 512).unwrap();
        b.append_u8(1).unwrap();
        b.append_bit_zero().unwrap();
    });
    let rest = SliceData::load_cell(rest).unwrap();
    let signed = cell(|b| {
        b.append_u8(0).unwrap();
        b.append_bit_one().unwrap();
        b.checked_append_reference(signatures).unwrap();
        b.append_builder(&rest.as_builder().unwrap()).unwrap();
    });
    let root_signature = keys[0].sign(signed.repr_hash().as_slice()).to_bytes();
    let signed = SliceData::load_cell(signed).unwrap();
    cell(|b| {
        b.append_raw(&root_signature, 512).unwrap();
        b.append_builder(&signed.as_builder().unwrap()).unwrap();
    })
}

/// A query id the multisig accepts at the sandbox clock `now`: more than an
/// hour ahead, so a query that does not reach k at once is still admitted.
pub fn query_id(now: u32, i: u32) -> u64 {
    ((u64::from(now) + 7200) << 32) | u64::from(i)
}
