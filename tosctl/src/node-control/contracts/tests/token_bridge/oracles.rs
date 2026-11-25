/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The oracle multisig as the bridge's real oracle account. Its queries may
//! only send bounceable votes to the bridges its StateInit lists, and never
//! consult ConfigParam 79, so a bridge the configuration no longer names can
//! still be voted to while it finishes its old generation
//! (SETTLEMENT-PROTOCOL.md section 4, "A replaced bridge").

use chain_block::{IBitstring, MsgAddressInt, SliceData};
use tos_sandbox::MessageBuilder;

use crate::harness::*;
use crate::query;

/// Deploys the token-bridge multisig, owned by the two test keys with k = 2,
/// allowed to vote to `bridges`.
fn deploy_multisig(net: &mut Net, bridges: &[MsgAddressInt]) -> MsgAddressInt {
    let code = tos_sandbox::compile_func(&query::token_variant().sources).expect("multisig.fc");
    let keys = query::public_keys(&query::owner_keys());
    let allowed: Vec<[u8; 32]> = bridges.iter().map(query::hash_of).collect();
    let init = query::state_init(&code, &keys, 2, &allowed);
    let multisig = query::address_of(&init, -1);
    let deploy = MessageBuilder::internal(net.deployer.address(), &multisig, 100 * TOS)
        .bounce(false)
        .state_init(init)
        .build();
    succeeded(&net.send(deploy));
    multisig
}

/// A quorum query asking the multisig to send `voting` to `bridge` as a vote
/// of `value`, relayed by a user.
fn voted(
    net: &Net,
    multisig: &MsgAddressInt,
    bridge: &MsgAddressInt,
    query_id: u64,
    voting: chain_block::Cell,
    value: u64,
) -> chain_block::Message {
    let body = cell(|b| {
        b.append_u32(OP_EXECUTE_VOTING).unwrap().append_u64(query_id).unwrap();
        b.checked_append_references_and_data(&SliceData::load_cell(voting).unwrap()).unwrap();
    });
    let vote = query::Vote { body: Some(body), value, ..query::Vote::to(bridge) };
    let id = query::query_id(net.bc.now(), query_id as u32);
    let signed = query::quorum_query(&query::owner_keys(), id, 1, vote.cell());
    MessageBuilder::internal(net.users[1].address(), multisig, TOS)
        .bounce(true)
        .body(signed)
        .build()
}

/// The old bridge, replaced in ConfigParam 79 by another, still cancels a
/// lock of its own generation when the oracles vote it through their
/// multisig: the multisig dispatches exactly one bounceable vote to it, and
/// the cancellation is terminal, logged once and refunds the payer.
#[test]
fn a_replaced_bridge_cancels_an_old_generation_lock_voted_through_the_multisig() {
    let mut net = Net::new();
    let old = net.bridge.clone();
    let replacement = query::masterchain([0x9b; 32]);
    let multisig = deploy_multisig(&mut net, &[old.clone(), replacement.clone()]);

    let payer = net.stranger.address().clone();
    let fee = net.mint_fee;
    succeeded(&net.pay_from(&payer, GENERATION, 0, fee));
    assert_eq!(net.swap_record(0).0, swap_state::PAID);

    // The configuration now names the replacement and the multisig.
    net.oracles_account = Some(multisig.clone());
    let (flags, burn_fee, mint_fee) = (net.state_flags, net.burn_fee, net.mint_fee);
    net.configure_with(&replacement, flags, burn_fee, mint_fee, Some(EVM_BRIDGE));

    let balance = net.balance(&payer);
    let relay = voted(&net, &multisig, &old, 1, net.cancel_lock_vote(GENERATION, 0), 2 * TOS);
    let d = net.execute(relay);
    succeeded(&d.tx);
    let to_bridge: Vec<_> = d.outs.iter().filter(|m| is_to(m, &old)).collect();
    assert_eq!(to_bridge.len(), 1, "exactly one vote leaves the multisig for the old bridge");
    let header = to_bridge[0].int_header().expect("an internal vote");
    assert!(header.bounce, "the vote is bounceable");
    assert_eq!(value_of(to_bridge[0]), u128::from(2 * TOS), "mode 1 carries the voted value");
    let relayer = net.users[1].address().clone();
    assert_eq!(d.outs.len(), 2, "the vote and the relayer's change");
    assert!(d.outs.iter().any(|m| is_to(m, &relayer)), "the relayer's change");
    net.settle();

    // Cancelled and folded: the watermark moved past the lock.
    assert_eq!(net.logs_from(&old, declared("LOG_SWAP_CANCELLED") as u32), 1, "logged once");
    assert_eq!(net.bridge_state()[6], 1, "the old bridge's watermark folds over the lock");
    assert_eq!(net.swap_record(0).0, -1, "the cancelled lock is folded away");
    assert!(net.balance(&payer) > balance, "the payer was refunded");
}

/// A vote to a bridge the multisig does not list is refused before anything
/// is recorded (exit code 46), even when ConfigParam 79 names that bridge.
#[test]
fn the_multisig_votes_only_to_listed_bridges_whatever_the_configuration_names() {
    let mut net = Net::new();
    let old = net.bridge.clone();
    let multisig = deploy_multisig(&mut net, &[old.clone()]);
    let unlisted = query::masterchain([0x9c; 32]);
    net.oracles_account = Some(multisig.clone());
    let (flags, burn_fee, mint_fee) = (net.state_flags, net.burn_fee, net.mint_fee);
    net.configure_with(&unlisted, flags, burn_fee, mint_fee, Some(EVM_BRIDGE));

    let relay = voted(&net, &multisig, &unlisted, 1, net.cancel_lock_vote(GENERATION, 0), 2 * TOS);
    let before = net.state_hashes();
    let multisig_data = net.bc.get_account(&multisig).and_then(|a| a.get_data_hash());
    let d = net.execute(relay);
    refused_with(&d.tx, query::ERR_DESTINATION);
    assert!(d.outs.iter().all(|m| !is_to(m, &unlisted)), "no vote left the multisig");
    net.settle();
    assert_eq!(net.state_hashes(), before, "no bridge state changed");
    assert_eq!(
        net.bc.get_account(&multisig).and_then(|a| a.get_data_hash()),
        multisig_data,
        "the refused query was not recorded"
    );
}

/// MAX_VOTE_VALUE holds the costliest vote, a cancellation of an unpaid lock
/// (get_cancel_cost), four times over at current prices, and the value this
/// suite's votes attach.
#[test]
fn max_vote_value_covers_the_costliest_vote_with_margin() {
    let net = Net::new();
    let cost = net.get(&net.bridge, "get_cancel_cost", vec![]).int_at(0) as u128;
    let max = query::token_variant().declared("MAX_VOTE_VALUE");
    eprintln!("get_cancel_cost {cost}, MAX_VOTE_VALUE {max}");
    assert!(cost > 0, "a cancellation costs something");
    assert!(
        cost.checked_mul(4).expect("no overflow") <= max,
        "get_cancel_cost {cost} against {max}"
    );
    assert!(u128::from(2 * TOS) <= max, "the votes this suite sends are admitted");
}
