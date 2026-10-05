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
    let path = vectors_path();
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

fn vectors_path() -> std::path::PathBuf {
    repo_root().join("crosschain/token-bridge/tests/vectors/source-events.json")
}

/// Rewrites the TOS-side fields of the shared vectors: this bridge's address
/// and life, and the holder the locks name. The EVM-side fields are left as
/// the Hardhat suite checks them.
fn write_tos_fields(net: &Net, user: &chain_block::MsgAddressInt) {
    let text = std::fs::read_to_string(vectors_path()).expect("the shared vectors");
    let mut v: serde_json::Value = serde_json::from_str(&text).expect("json");
    v["activation"]["tos_bridge"] = serde_json::json!(format!("0x{}", hex::encode(account_hash(&net.bridge))));
    v["activation"]["tos_life"] = serde_json::json!(net.bridge_life().to_string());
    for lock in v["locks"].as_array_mut().expect("locks") {
        lock["to"] = serde_json::json!(format!("0x{}", hex::encode(account_hash(user))));
    }
    let out = serde_json::to_string_pretty(&v).expect("json") + "\n";
    std::fs::write(vectors_path(), out).expect("the vectors are written");
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
    if std::env::var_os("TOKEN_BRIDGE_WRITE_VECTORS").is_some() {
        write_tos_fields(&net, &user);
    }
    let v = vectors();
    assert_eq!(v.evm_chain_id, CHAIN_ID, "the namespace's chain");
    assert_eq!(v.evm_bridge, EVM_BRIDGE, "the namespace's EVM bridge");
    assert_eq!(
        v.tos_bridge.as_slice(),
        account_hash(&net.bridge).as_slice(),
        "the generation names this bridge; after a bridge code change, rerun this test \
         with TOKEN_BRIDGE_WRITE_VECTORS=1 and then the Hardhat suite"
    );
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

fn cancel_logs(net: &Net) -> usize {
    net.logs_from(&net.bridge, declared("LOG_SWAP_CANCELLED") as u32)
}

/// T-Y5: an unpaid early lock blocks the payment window until the oracles
/// cancel it. The cancellation is terminal and logged once; a paid lock's fee
/// goes back to its payer; a preparing lock cannot be cancelled.
#[test]
fn t_y5_an_unpaid_early_lock_blocks_the_window_until_it_is_cancelled() {
    let mut net = Net::new();
    let window = declared("SWAP_WINDOW") as u64;
    let payer = net.stranger.address().clone();
    let fee = net.mint_fee;
    // lock 0 is never paid; locks 1.. fill the window
    for n in 1..window {
        succeeded(&net.pay(n));
    }
    let before = net.swap_record(window);
    let tx = net.pay_from(&payer, GENERATION, window, fee);
    refused_with(&tx, declared("error::window_full") as i32);
    assert_eq!(net.swap_record(window), before, "nothing recorded");

    // lock 1 is voted and held while preparing: it cannot be cancelled
    let voting = net.swap_voting(GENERATION, 1, &net.user(0), 5, 0x5a);
    let vote = net.vote(201, voting);
    net.queue.push_back(vote);
    net.deliver_one();
    let held = net.take(|m| body_op(m) == Some(op::PREPARE));
    let before = net.state_hashes();
    let cancel = net.vote(202, net.cancel_lock_vote(GENERATION, 1));
    refused_with(&net.send(cancel), declared("error::not_admissible") as i32);
    assert_eq!(net.state_hashes(), before, "a preparing lock is not cancelled");
    assert_eq!(cancel_logs(&net), 0);

    // a cancellation whose vote cannot pay for its log is refused
    let mut poor = net.vote(207, net.cancel_lock_vote(GENERATION, 0));
    if let Some(h) = poor.int_header_mut() {
        let cost = net.get(&net.bridge, "get_cancel_cost", vec![]).int_at(0) as u64;
        h.value.coins = chain_block::Coins::from(cost.checked_sub(1).expect("a positive cost"));
    }
    let before = net.state_hashes();
    refused_with(&net.send(poor), declared("error::underfunded") as i32);
    assert_eq!(net.state_hashes(), before);

    // lock 0 is cancelled: terminal, logged once, and the window moves
    let cancel = net.vote(203, net.cancel_lock_vote(GENERATION, 0));
    succeeded(&net.send(cancel.clone()));
    assert_eq!(cancel_logs(&net), 1);
    assert_eq!(net.bridge_state()[6], 1, "the watermark folds over the cancelled lock");
    let again = net.vote(204, net.cancel_lock_vote(GENERATION, 0));
    assert!(outcome(&net.send(again)).aborted, "below the watermark nothing is evaluated");
    assert!(outcome(&net.send(cancel)).aborted, "the same vote replayed");
    assert_eq!(cancel_logs(&net), 1, "logged once");
    let tx = net.pay_from(&payer, GENERATION, 0, fee);
    refused_with(&tx, declared("error::not_admissible") as i32);
    succeeded(&net.pay(window));

    // a paid lock cancelled returns its fee, less the cancellation's own costs
    let balance = net.balance(&payer);
    let cancel = net.vote(205, net.cancel_lock_vote(GENERATION, 2));
    succeeded(&net.send(cancel));
    assert_eq!(cancel_logs(&net), 2);
    let returned = net.balance(&payer).checked_sub(balance).expect("the payer was refunded");
    assert!(returned > 0 && returned < u128::from(fee), "the payer got the fee back once: {returned}");
    let vote = net.vote(206, net.swap_voting(GENERATION, 2, &net.user(0), 5, 0x5a));
    assert!(outcome(&net.send(vote)).aborted, "a cancelled lock is never voted");

    // the preparing lock still completes
    net.send(held);
    net.settle();
    assert_eq!(net.tokens(&net.user(0)), 5);
}
