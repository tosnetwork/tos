/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The source side: EVM vectors shared with the Hardhat suite, and the swap
//! window's gaps closed by cancellation (T-Y5).

use chain_block::{Deserializable, IBitstring, MsgAddressInt};

use crate::harness::*;

/// The fields the EVM side emits and the TOS side votes on, shared with
/// `crosschain/token-bridge/evm/test/Settlement.test.ts`.
pub struct Vectors {
    pub evm_chain_id: u32,
    pub evm_bridge: [u8; 20],
    pub token: [u8; 20],
    pub decimals: u8,
    pub generation: u32,
    pub tos_bridge: [u8; 32],
    pub tos_life: u64,
    pub start: u64,
    pub locks: Vec<(u64, [u8; 32], u128)>,
}

fn hex_bytes<const N: usize>(v: &serde_json::Value) -> [u8; N] {
    let text = v.as_str().expect("a hex string");
    let bytes = hex::decode(text.trim_start_matches("0x")).expect("hex");
    bytes.try_into().expect("the field's width")
}

pub fn vectors() -> Vectors {
    let path = repo_root().join("crosschain/token-bridge/tests/vectors/source-events.json");
    let text = std::fs::read_to_string(&path).expect("the shared vectors");
    let v: serde_json::Value = serde_json::from_str(&text).expect("json");
    let a = &v["activation"];
    Vectors {
        evm_chain_id: v["evm_chain_id"].as_u64().expect("chain id") as u32,
        evm_bridge: hex_bytes(&v["evm_bridge"]),
        token: hex_bytes(&v["token"]),
        decimals: v["decimals"].as_u64().expect("decimals") as u8,
        generation: a["generation"].as_u64().expect("generation") as u32,
        tos_bridge: hex_bytes(&a["tos_bridge"]),
        tos_life: a["tos_life"].as_str().expect("life").parse().expect("a number"),
        start: a["start"].as_str().expect("start").parse().expect("a number"),
        locks: v["locks"]
            .as_array()
            .expect("locks")
            .iter()
            .map(|l| {
                (
                    l["n"].as_str().expect("n").parse().expect("a number"),
                    hex_bytes(&l["to"]),
                    l["amount"].as_str().expect("amount").parse().expect("a number"),
                )
            })
            .collect(),
    }
}

/// The swap vote an oracle builds from one `Lock` event.
pub fn wrapped_token(v: &Vectors) -> chain_block::Cell {
    cell(|t| {
        t.append_u32(v.evm_chain_id).unwrap();
        t.append_raw(&v.token, 160).unwrap();
        t.append_u8(v.decimals).unwrap();
    })
}

pub fn vote_from_lock(v: &Vectors, n: u64, to: &[u8; 32], amount: u128) -> chain_block::Cell {
    cell(|b| {
        b.append_u8(0).unwrap();
        b.append_u32(v.generation).unwrap();
        b.append_u64(n).unwrap();
        b.append_u32(v.evm_chain_id).unwrap();
        b.append_raw(&v.evm_bridge, 160).unwrap();
        b.append_raw(to, 256).unwrap();
        coins(b, amount);
        b.checked_append_reference(wrapped_token(v)).unwrap();
    })
}

/// The EVM generation vote and lock events of the Hardhat suite, read as an
/// oracle reads them, activate this bridge and mint each lock once. The
/// vectors name this bridge's own address and life, its pinned namespace and a
/// sandbox holder, so a field either side encodes differently fails here or
/// there.
#[test]
fn coupled_vectors_activate_the_bridge_and_mint_each_lock_once() {
    let mut net = Net::unactivated(Deployment::Direct);
    let user = net.user(0);
    let v = vectors();
    assert_eq!(v.evm_chain_id, CHAIN_ID, "the namespace's chain");
    assert_eq!(v.evm_bridge, EVM_BRIDGE, "the namespace's EVM bridge");
    assert_eq!(v.tos_bridge.as_slice(), account_hash(&net.bridge).as_slice(), "the generation names this bridge");
    assert_eq!(v.tos_life, net.bridge_life(), "the generation names this bridge's life");

    let activation = net.activation(&v.tos_bridge, v.tos_life, v.generation, v.start);
    let vote = net.vote(1, activation);
    succeeded(&net.send(vote));
    let r = net.get(&net.bridge, "get_minter_address", vec![tos_vm::stack::StackItem::cell(wrapped_token(&v))]);
    let minter = MsgAddressInt::construct_from(&mut r.slice_at(0)).expect("a minter");
    let wallet = net.wallet_in(&minter, &user);
    let tokens = |net: &Net| net.try_get(&wallet, "get_wallet_data", vec![]).map(|r| r.int_at(0) as u128).unwrap_or(0);
    let mut total = 0u128;
    for (i, (n, to, amount)) in v.locks.iter().enumerate() {
        assert_eq!(to.as_slice(), account_hash(&user).as_slice(), "the lock names a sandbox holder");
        succeeded(&net.pay_from(&net.stranger.address().clone(), v.generation, *n, net.mint_fee));
        let vote = net.vote(100 + i as u64, vote_from_lock(&v, *n, to, *amount));
        net.queue.push_back(vote.clone());
        net.settle();
        total = total.checked_add(*amount).expect("no overflow");
        assert_eq!(tokens(&net), total, "lock {n} minted once");
        // the same event voted again mints nothing
        let before = net.state_hashes();
        assert!(outcome(&net.send(vote)).aborted);
        assert_eq!(net.state_hashes(), before);
    }
}
