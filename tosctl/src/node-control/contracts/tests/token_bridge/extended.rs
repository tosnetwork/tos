/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Capacity, exhaustion, interleaving, duplicate-path fees, authentication,
//! payments, deployment and removed opcodes.

use chain_block::{IBitstring, Message, MsgAddressInt, Serializable, UInt256};
use tos_sandbox::MessageBuilder;

use crate::burn::{assert_burned, assert_returned, cancel, cancel_message, minted};
use crate::harness::*;
use crate::mint::assert_minted;

/// T-S: the bridge new-bridge.fif deploys completes a mint and a burn.
#[test]
fn t_s_a_bridge_deployed_by_its_script_mints_and_burns() {
    let mut net = Net::deployed(Deployment::Script);
    let n = net.swap(1_000);
    assert_minted(&net, n, 1_000);
    net.start_burn(400);
    net.settle();
    assert_burned(&net);
    crate::state::assert_round_trip(&net);
}

/// T-S: every opcode the earlier completion protocol used is refused, before
/// any effect, by every contract.
#[test]
fn t_s_the_removed_opcodes_are_refused_before_any_effect() {
    let mut net = minted();
    let targets = [net.bridge.clone(), net.minter(), net.wallet_of(&net.user(0))];
    let stranger = net.stranger.address().clone();
    for op in 21u32..=27 {
        for to in &targets {
            let before = net.state_hashes();
            let msg = forged(&stranger, to, TOS, cell(|b| {
                b.append_u32(op).unwrap().append_u64(0).unwrap();
                b.append_u64(0).unwrap();
            }));
            let tx = net.send(msg);
            assert!(outcome(&tx).aborted, "op {op} at {to}: refused");
            assert_eq!(net.state_hashes(), before, "op {op} at {to}: nothing changed");
        }
    }
}

/// T-X1: a burn's amount stays reserved until the bridge decides. While it is
/// undecided no mint can take its capacity; a cancellation's refund always
/// fits; only a recorded burn frees capacity for mints.
#[test]
fn t_x1_the_refund_of_an_undecided_burn_always_fits() {
    for recorded in [false, true] {
        let mut net = Net::new();
        let user = net.user(0);
        net.swap(MAX_SUPPLY);
        net.start_burn(100);
        let held = net.drop_op(op::BURN_NOTICE);
        net.settle();
        assert_eq!(net.supply_state(), (MAX_SUPPLY as i128 - 100, 0, 0, 100, 0));
        // no mint may take the burn's capacity while it is undecided
        let n = net.swap(1);
        assert_eq!(net.swap_record(n).0, swap_state::PAID, "refused: the capacity is reserved");
        if recorded {
            net.send(held);
            assert_eq!(net.supply_state(), (MAX_SUPPLY as i128 - 100, 0, 0, 0, 0));
            let m = net.swap(100);
            // consumed; the earlier refused lock, still paid, holds the watermark
            assert_eq!(net.swap_record(m).0, swap_state::CONSUMED, "a recorded burn freed its capacity");
            assert_eq!(net.tokens(&user), MAX_SUPPLY);
        } else {
            succeeded(&cancel(&mut net, 0));
            net.send(held);
            assert_eq!(net.supply_state(), (MAX_SUPPLY as i128, 0, 0, 0, 0), "the refund fit");
            assert_eq!(net.tokens(&user), MAX_SUPPLY);
            let m = net.swap(1);
            assert_eq!(net.swap_record(m).0, swap_state::PAID, "and the supply is full again");
        }
    }
    // the cancellation's result lost, and the refund's legs reordered
    let mut net = Net::new();
    net.swap(MAX_SUPPLY);
    net.start_burn(100);
    net.drop_op(op::BURN_NOTICE);
    net.settle();
    let msg = cancel_message(&net, 0);
    net.queue.push_back(msg);
    net.drop_op(op::BURN_RESULT);
    net.settle();
    let user = net.user(0);
    succeeded(&net.advance_minter(advance::BURN, &user, Some(0)));
    assert_eq!(net.supply_state(), (MAX_SUPPLY as i128, 0, 0, 0, 0));
}

/// T-X2: every counter refuses at its sentinel, before anything irrevocable:
/// s and k refuse the prepare (the lock stays paid), m refuses the admission
/// (the hold is released), b refuses the burn (the tokens stay), n refuses the
/// payment, and an exhausted opening attempt refuses the prepare.
#[test]
fn t_x2_every_counter_refuses_at_its_sentinel() {
    // s: the bridge's mint numbers
    let mut net = minted();
    net.patch_channel(|c| {
        c.next_mint = MAX_SEQ;
        c.mint_ack = MAX_SEQ;
    });
    net.patch_minter(|m| {
        m.mint_wm = MAX_SEQ;
        m.mint_cf = MAX_SEQ;
    });
    let n = net.swap(5);
    assert_eq!(net.swap_record(n).0, -1, "the last allocatable s completes");
    let n = net.next_nonce;
    net.next_nonce += 1;
    succeeded(&net.pay(n));
    let voting = net.swap_voting(GENERATION, n, &net.user(0), 5, 0x5a);
    let vote = net.vote(77, voting);
    refused_with(&net.send(vote), err("sequence_exhausted"));
    assert_eq!(net.swap_record(n).0, swap_state::PAID, "the lock stays paid");

    // k: the holder's credit numbers
    let mut net = minted();
    let user = net.user(0);
    net.patch_holder(&user, |h| {
        h.next_credit = MAX_SEQ;
        h.credit_ack = MAX_SEQ;
    });
    net.patch_wallet(&user, |w| {
        w.credit_wm = MAX_SEQ;
        w.credit_cf = MAX_SEQ;
        w.credit_high = MAX_SEQ;
        w.credits_above = None;
    });
    let n = net.swap(5);
    assert_eq!(net.swap_record(n).0, -1, "the last allocatable k completes");
    assert_eq!(net.tokens(&user), 1_005);
    let n = net.swap(5);
    assert_eq!(net.swap_record(n).0, swap_state::PAID, "k exhausted: refused, the lock stays paid");

    // m: the minter's notice numbers
    let mut net = minted();
    net.patch_minter(|m| {
        m.next_notice = MAX_SEQ;
        m.bridge_burn_ack = MAX_SEQ;
    });
    net.patch_channel(|c| {
        c.burn_wm = MAX_SEQ;
        c.burn_cf = MAX_SEQ;
        c.burn_high = MAX_SEQ;
    });
    net.start_burn(100);
    net.settle();
    assert_eq!(net.burn_logs(), 1, "the last allocatable m is recorded");
    let user = net.user(0);
    net.start_burn(100);
    net.settle();
    assert_eq!(net.minter_burn(&user, 1).1, burn_status::ADMIT_REFUSED, "m exhausted: refused");
    assert_eq!(net.tokens(&user), 900, "the second hold was released");

    // b: the wallet's burn numbers
    let mut net = minted();
    let user = net.user(0);
    net.patch_wallet(&user, |w| {
        w.next_burn = MAX_SEQ;
        w.burn_ack = MAX_SEQ;
    });
    net.patch_holder(&user, |h| {
        h.burn_wm = MAX_SEQ;
        h.burn_cf = MAX_SEQ;
    });
    net.start_burn(100);
    net.settle();
    assert_eq!(net.burn_logs(), 1, "the last allocatable b is recorded");
    let burn = net.burn_message(&user, 100, net.burn_fee);
    refused_with(&net.send(burn), err("sequence_exhausted"));
    assert_eq!(net.tokens(&user), 900, "the tokens stay");

    // n: the lock nonce
    let mut net = minted();
    net.patch_bridge(|b| b.swap_wm = MAX_SEQ);
    net.next_nonce = MAX_SEQ;
    let n = net.swap(5);
    assert_eq!(n, MAX_SEQ);
    let payer = net.stranger.address().clone();
    let tx = net.pay_from(&payer, GENERATION, MAX_SEQ + 1, net.mint_fee);
    refused_with(&tx, err("sequence_exhausted"));

    // the opening attempt: one left, then none
    let mut net = minted();
    let other = net.user(1);
    net.swap_to(&other, 1);
    net.patch_holder(&other, |h| {
        h.open = 0;
        h.wallet_life = 0;
        h.attempt = 0xffff_fffe;
    });
    let n = net.swap_to(&other, 1);
    assert_eq!(net.swap_record(n).0, swap_state::PAID, "attempts exhausted: refused");
    let tx = net.open_wallet(&other);
    assert_eq!(net.exits_since(net.delivered.len() - 2, err("sequence_exhausted")), 1, "the open request is refused");
    let _ = tx;
}

/// T-X5: tokens credited but not yet counted are transferred and burned
/// before their credit is counted. Supply goes below zero for a while and I1
/// holds throughout, with the transfer in flight counted.
#[test]
fn t_x5_a_landed_credit_transferred_and_burned_before_it_is_counted() {
    for cancelled in [false, true] {
        let mut net = Net::new();
        let user = net.user(0);
        let other = net.user(1);
        net.start_swap(1_000);
        let report = net.drop_op(op::CREDIT_RECORDED);
        net.settle();
        assert_eq!(net.supply_state(), (0, 1_000, 0, 0, 0));
        let transfer = net.transfer(&user, &other, 600);
        net.send(transfer);
        assert_eq!(net.tokens(&other), 600);
        succeeded(&net.open_wallet(&other));
        net.start_burn_from(&other, 600);
        if cancelled {
            net.drop_op(op::BURN_NOTICE);
            net.settle();
            let (need, _) = net.wallet_advance_cost(&other, advance::BURN);
            let msg = net.cancel_message(&other, 0, need);
            succeeded(&net.send(msg));
            assert_eq!(net.supply_state().0, 0, "the refund restored the supply");
            assert_eq!(net.tokens(&other), 600);
        } else {
            net.settle();
            assert_eq!(net.supply_state().0, -600, "the burn was admitted before the credit was counted");
            assert_eq!(net.burn_logs(), 1);
        }
        net.send(report);
        let expect = if cancelled { 1_000 } else { 400 };
        assert_eq!(net.supply_state(), (expect, 0, 0, 0, 0));
    }
}

/// T-X6: a price rise before a re-send from a final record stops it with no
/// effect, and an advance at the new price completes.
#[test]
fn t_x6_a_gas_rise_before_a_resend_from_a_final_record_is_recovered() {
    // the completion re-sent from a counted mint
    let mut net = Net::new();
    let n = net.start_swap(1_000);
    net.drop_op(op::MINT_COMPLETED);
    net.settle();
    let (need, _) = net.bridge_advance_cost(advance::MINT, 0);
    let minter = net.minter();
    let bridge = net.bridge.clone();
    let adv = net.advance_message(&bridge, advance::MINT, need, |b| {
        b.append_raw(&account_hash(&minter), 256).unwrap();
        b.append_u64(0).unwrap();
    });
    net.queue.push_back(adv);
    let resent = net.intercept(|m| body_op(m) == Some(op::MINT_COMPLETED));
    let price = net.gas_price(true);
    net.set_gas_price(true, price * 1_000);
    stopped_for_funds(&net.send_one(resent));
    succeeded(&net.advance_bridge_mint(0));
    assert_minted(&net, n, 1_000);

    // the refund's report re-sent by a wallet that already credited it
    let mut net = minted();
    net.start_burn(400);
    net.drop_op(op::BURN_NOTICE);
    net.settle();
    let msg = cancel_message(&net, 0);
    net.queue.push_back(msg);
    net.drop_op(op::REFUND_RECORDED);
    net.settle();
    let user = net.user(0);
    let (_, quote) = net.minter_advance_cost(advance::BURN, &user);
    let minter = net.minter();
    let adv = net.advance_message(&minter, advance::BURN, quote, |b| {
        b.append_raw(&account_hash(&user), 256).unwrap();
        b.append_u64(0).unwrap();
    });
    net.queue.push_back(adv);
    let resent = net.intercept(|m| body_op(m) == Some(op::REFUND_RECORDED));
    let price = net.gas_price(false);
    net.set_gas_price(false, price * 1_000);
    stopped_for_funds(&net.send_one(resent));
    succeeded(&net.advance_minter(advance::BURN, &user, Some(0)));
    assert_returned(&net);

    // the result re-sent for a recorded burn
    let mut net = minted();
    net.start_burn(400);
    net.drop_op(op::BURN_RESULT);
    net.settle();
    let (_, quote) = net.bridge_advance_cost(advance::BURN_RESULT, 0);
    let minter = net.minter();
    let bridge = net.bridge.clone();
    let adv = net.advance_message(&bridge, advance::BURN_RESULT, quote, |b| {
        b.append_raw(&account_hash(&minter), 256).unwrap();
        b.append_u64(0).unwrap();
    });
    net.queue.push_back(adv);
    let resent = net.intercept(|m| body_op(m) == Some(op::BURN_RESULT));
    let price = net.gas_price(false);
    net.set_gas_price(false, price * 1_000);
    stopped_for_funds(&net.send_one(resent));
    succeeded(&net.advance_bridge_burn_result(0));
    assert_burned(&net);
}

/// T-X8: a message from any other sender, another holder's wallet, another
/// token's minter, or naming another life, is refused or changes nothing; it
/// never finishes an operation that is not its own.
#[test]
fn t_x8_substituted_senders_and_lives_are_refused() {
    let mut net = minted();
    let stranger_bc = net.user(3);
    let bridge = net.bridge.clone();
    let minter = net.minter();
    let wallet = net.wallet_of(&net.user(0));
    let body = |op: u32| {
        cell(|b| {
            b.append_u32(op).unwrap().append_u64(0).unwrap();
            for _ in 0..5 {
                b.append_u64(0).unwrap();
            }
        })
    };
    for (to, ops) in [
        (minter.clone(), vec![op::PREPARE, op::COMMIT, op::BURN_RESULT, op::SYNC_FLOOR, op::CREDIT_RECORDED, op::BURN_ADMIT]),
        (bridge.clone(), vec![op::PREPARED, op::MINT_COMPLETED, op::BURN_NOTICE, op::SYNC_FLOOR]),
        (wallet.clone(), vec![op::CREDIT, op::OPEN, op::REFUND, op::BURN_OUTCOME, op::ADMIT_REFUSED]),
    ] {
        for op in ops {
            let before = net.state_hashes();
            let tx = net.send(forged(&stranger_bc, &to, TOS, body(op)));
            assert!(outcome(&tx).aborted, "op {op} from a stranger is refused");
            assert_eq!(net.state_hashes(), before);
        }
    }

    // another holder's wallet reporting user 0's credit
    let other = net.user(1);
    net.swap_to(&other, 1);
    let other_wallet = net.wallet_of(&other);
    let st = net.wallet_state(&other);
    let life = st[0] as u64;
    let minter_life = net.minter_channels()[0] as u64;
    let user0 = net.user(0);
    let report = cell(|b| {
        b.append_u32(op::CREDIT_RECORDED).unwrap().append_u64(0).unwrap();
        b.append_u64(life).unwrap();
        b.append_u64(minter_life).unwrap();
        b.append_u64(0).unwrap();
        b.append_u64(0).unwrap();
        user0.write_to(b).unwrap();
    });
    let before = net.state_hashes();
    refused_with(&net.send(forged(&other_wallet, &minter, TOS, report)), declared("error::owner_not_sender") as i32);
    assert_eq!(net.state_hashes(), before);

    // another token's minter completing this token's pending mint
    let mut net = Net::new();
    net.start_swap(1_000);
    net.drop_op(op::MINT_COMPLETED);
    net.settle();
    let token_b = net.minter_of(0x6b);
    net.minters.insert(0x6b, token_b.clone());
    let user = net.user(1);
    net.start_swap_token(&user, 5, 0x6b);
    net.settle();
    let life = net.bridge_life();
    let minter_b_life = net.get(&token_b, "get_channels", vec![]).int_at(0) as u64;
    let completed = cell(|b| {
        b.append_u32(op::MINT_COMPLETED).unwrap().append_u64(0).unwrap();
        b.append_u64(minter_b_life).unwrap();
        b.append_u64(life).unwrap();
        b.append_u64(0).unwrap();
        b.append_u64(0).unwrap();
    });
    let bridge = net.bridge.clone();
    net.send(forged(&token_b, &bridge, TOS, completed));
    assert_eq!(net.pending(0), 1, "the first token's mint is still pending: committed");

    // a credit naming another wallet life
    let mut net = minted();
    let user = net.user(0);
    let wallet = net.wallet_of(&user);
    let minter = net.minter();
    let st = net.wallet_state(&user);
    let minter_life = net.minter_channels()[0] as u64;
    let d = net.get(&minter, "get_mint_descriptor", vec![int_arg(0)]);
    let _ = d;
    let credit = cell(|b| {
        b.append_u32(op::CREDIT).unwrap().append_u64(0).unwrap();
        b.append_u64(minter_life).unwrap();
        b.append_u64(st[0] as u64 + 1).unwrap();
        b.append_u64(9).unwrap();
        b.append_u64(0).unwrap();
        b.checked_append_reference(cell(|_| {})).unwrap();
    });
    let before = net.state_hashes();
    assert!(outcome(&net.send(forged(&minter, &wallet, 10 * TOS, credit))).aborted);
    assert_eq!(net.state_hashes(), before);
}

/// T-X9: a payment for a consumed lock, a second payment, a payment for a lock
/// being prepared, or one outside the window is refused and bounced, and
/// records nothing.
#[test]
fn t_x9_payments_are_refused_unless_for_a_fresh_lock_in_the_window() {
    let mut net = minted();
    let payer = net.stranger.address().clone();
    let fee = net.mint_fee;
    let check = |net: &mut Net, n: u64, code: &str| {
        let before = net.swap_record(n);
        let tx = net.pay_from(&payer, GENERATION, n, fee);
        refused_with(&tx, err(code));
        assert!(outcome(&tx).bounced, "the payment is bounced back");
        assert_eq!(net.swap_record(n), before, "nothing recorded");
    };
    check(&mut net, 0, "not_admissible"); // consumed
    let n = net.next_nonce;
    net.next_nonce += 1;
    succeeded(&net.pay(n));
    check(&mut net, n, "not_admissible"); // paid already
    let voting = net.swap_voting(GENERATION, n, &net.user(0), 5, 0x5a);
    let vote = net.vote(55, voting);
    net.queue.push_back(vote);
    net.deliver_one();
    let held = net.take(|m| body_op(m) == Some(op::PREPARE));
    check(&mut net, n, "not_admissible"); // preparing
    let window = declared("SWAP_WINDOW") as u64;
    let wm = net.bridge_state()[6] as u64;
    check(&mut net, wm + window, "window_full");
    net.send(held);
    net.settle();
}

/// T-X10: the independent model saw every effect: one credit per mint, one
/// count, one consumption, one log per recorded burn.
#[test]
fn t_x10_the_model_records_every_effect_outside_the_contracts() {
    let mut net = minted();
    net.start_burn(400);
    net.settle();
    assert_eq!(net.model.credits.len(), 1);
    assert_eq!(net.model.counts.len(), 1);
    assert_eq!(net.model.consumed.len(), 1);
    assert_eq!(net.model.burn_logs.values().sum::<u32>(), 1);
    assert!(net.model.landed.is_empty() && net.model.admitted.is_empty());
    let _ = (Message::default, MsgAddressInt::default, UInt256::default);
}

/// T-X8: a vote naming another chain, another EVM bridge or a token of
/// another chain, or minting nothing, is refused before any effect; a burn to
/// the zero destination is refused while the holder still has the tokens.
#[test]
fn t_x8_votes_outside_the_namespace_and_burns_to_nowhere_are_refused() {
    let mut net = Net::new();
    let user = net.user(0);
    let n = net.next_nonce;
    net.next_nonce += 1;
    succeeded(&net.pay(n));
    let voting = |chain: u32, evm_bridge: [u8; 20], token_chain: u32, amount: u128| {
        cell(|b| {
            b.append_u8(0).unwrap();
            b.append_u32(GENERATION).unwrap();
            b.append_u64(n).unwrap();
            b.append_u32(chain).unwrap();
            b.append_raw(&evm_bridge, 160).unwrap();
            b.append_raw(&account_hash(&user), 256).unwrap();
            coins(b, amount);
            b.checked_append_reference(cell(|t| {
                t.append_u32(token_chain).unwrap();
                t.append_raw(&[0x5a; 20], 160).unwrap();
                t.append_u8(18).unwrap();
            }))
            .unwrap();
        })
    };
    let mut other_bridge = EVM_BRIDGE;
    other_bridge[19] ^= 1;
    for (v, code) in [
        (voting(CHAIN_ID + 1, EVM_BRIDGE, CHAIN_ID, 10), "error::wrong_namespace"),
        (voting(CHAIN_ID, other_bridge, CHAIN_ID, 10), "error::wrong_namespace"),
        (voting(CHAIN_ID, EVM_BRIDGE, CHAIN_ID + 1, 10), "error::wrong_external_chain_id"),
        (voting(CHAIN_ID, EVM_BRIDGE, CHAIN_ID, 0), "error::not_enough_funds"),
    ] {
        let before = net.state_hashes();
        let vote = net.vote(900, v);
        refused_with(&net.send(vote), declared(code) as i32);
        assert_eq!(net.state_hashes(), before, "{code}: no effect");
    }
    // the same lock in this namespace still mints
    let vote = net.vote(900, voting(CHAIN_ID, EVM_BRIDGE, CHAIN_ID, 10));
    succeeded(&net.send(vote));
    assert_minted(&net, n, 10);

    let balance = net.tokens(&user);
    let wallet = net.wallet_of(&user);
    let burn = MessageBuilder::internal(&user, &wallet, net.burn_fee)
        .bounce(true)
        .body(cell(|b| {
            b.append_u32(OP_BURN).unwrap().append_u64(7).unwrap();
            coins(b, 5);
            user.write_to(b).unwrap();
            b.append_bit_one().unwrap();
            b.checked_append_reference(cell(|d| {
                d.append_raw(&[0; 20], 160).unwrap();
            }))
            .unwrap();
        }))
        .build();
    let before = net.state_hashes();
    refused_with(&net.send(burn), declared("error::zero_destination") as i32);
    assert_eq!(net.state_hashes(), before, "nothing held");
    assert_eq!(net.tokens(&user), balance);
    assert_eq!(net.held(&user, 0), -1, "no burn opened");
}
