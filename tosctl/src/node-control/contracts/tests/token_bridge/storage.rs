/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Storage rent: freezing and deletion by the chain itself (T-Y7), the
//! special-account exemptions (T-Z5), and storage maintenance (T-L).

use chain_block::{IBitstring, Message, MsgAddressInt};
use tos_sandbox::MessageBuilder;

use crate::burn::minted;
use crate::harness::*;
use crate::lifecycle::{reopen, stranded_logs};

/// A bounceable message with a little value and no body: it runs only the
/// storage phase that matters here.
fn poke(net: &Net, to: &MsgAddressInt) -> Message {
    MessageBuilder::internal(net.stranger.address(), to, 1_000_000).bounce(true).build()
}

/// Prices that make one basechain or masterchain account's rent outrun any
/// balance it holds within a few thousand seconds.
fn price_jump(net: &mut Net, basechain: bool) {
    if basechain {
        net.set_storage_prices(1 << 30, 1 << 40, 1, 500);
    } else {
        net.set_storage_prices(1, 500, 1 << 30, 1 << 40);
    }
}

fn ordinary_prices(net: &mut Net) {
    net.set_storage_prices(1, 500, 1000, 500_000);
}

/// Freezes, then deletes, `addr` through the chain's own storage phase in
/// two consecutive transactions on it.
fn freeze_then_delete(net: &mut Net, addr: &MsgAddressInt, basechain: bool) {
    price_jump(net, basechain);
    net.advance_time(1_000);
    let msg = poke(net, addr);
    net.send_one(msg);
    net.queue.clear();
    assert!(net.is_frozen(addr), "the rent froze the account");
    net.advance_time(100_000);
    let msg = poke(net, addr);
    net.send_one(msg);
    net.queue.clear();
    assert!(!net.exists(addr), "the rent deleted the frozen account");
    ordinary_prices(net);
}

/// T-Y7: a storage-price jump freezes and then deletes a wallet holding a
/// landed, unreported credit. Its deletion is detected through its life at
/// the next opening: the credit is stranded once and logged, the new life
/// opens clean and mints, and the old credit's report changes nothing.
#[test]
fn t_y7_rent_deletes_a_wallet_and_its_life_is_stranded_once() {
    let mut net = minted();
    let user = net.user(0);
    ordinary_prices(&mut net);
    net.start_swap(500);
    let report = net.drop_op(op::CREDIT_RECORDED);
    net.settle();
    let wallet = net.wallet_of(&user);
    freeze_then_delete(&mut net, &wallet, true);
    net.recreate_wallet(&user);
    reopen(&mut net, &user);
    assert_eq!(stranded_logs(&net), 1, "stranded once, and logged");
    assert_eq!(net.supply_state().4, 500, "its amount is in stranded, once");
    let before = net.state_hashes();
    net.send(report);
    assert_eq!(net.state_hashes(), before, "the old report changes nothing");
    net.swap(9);
    assert_eq!(net.tokens(&user), 9, "the new life mints");
    assert_eq!(stranded_logs(&net), 1, "no second strand");
}

/// T-Y7: the same jump deletes the minter. Its recreation is a new life: the
/// bridge's channel and every wallet treat it as terminal, nothing is
/// credited or counted twice, and the old minter's in-flight mint stays
/// stuck under the accepted scope rather than completing twice.
#[test]
fn t_y7_rent_deletes_the_minter_and_its_new_life_is_terminal_everywhere() {
    let mut net = minted();
    let user = net.user(0);
    ordinary_prices(&mut net);
    net.start_swap(500);
    net.deliver_until(|m| body_op(m) == Some(op::CREDIT));
    let credit = net.take(|m| body_op(m) == Some(op::CREDIT));
    net.settle();
    let minter = net.minter();
    freeze_then_delete(&mut net, &minter, true);
    net.recreate_minter();
    // the held credit lands at the wallet; its report reaches the new life
    net.send(credit);
    assert_eq!(net.tokens(&user), 1_500, "the credit landed once");
    assert_eq!(net.supply_state().0, 0, "the new minter life counts nothing old");
    // the bridge's next prepare to the new life ends the relationship
    let n = net.start_swap(5);
    net.settle();
    assert_eq!(net.swap_record(n).0, swap_state::PREPARING, "stuck, under the accepted scope");
    assert_eq!(net.tokens(&user), 1_500, "nothing minted through the new life");
}

/// T-Y7 and T-Z5: the bridge listed in ConfigParam 31 pays no rent and is
/// never frozen by the same jump; unlisted, the jump freezes it. The listing
/// is a release prerequisite.
#[test]
fn t_y7_t_z5_a_listed_bridge_is_exempt_from_rent_and_an_unlisted_one_is_not() {
    for listed in [true, false] {
        let mut net = minted();
        ordinary_prices(&mut net);
        let bridge = net.bridge.clone();
        net.set_special(&bridge, listed);
        price_jump(&mut net, false);
        net.advance_time(1_000);
        let msg = poke(&net, &bridge);
        let tx = net.send_one(msg);
        net.queue.clear();
        if listed {
            assert_eq!(outcome(&tx).storage_fees, 0, "a listed bridge pays no rent");
            assert!(!net.is_frozen(&bridge), "a listed bridge is never frozen");
            ordinary_prices(&mut net);
            net.swap(3);
            assert_eq!(net.tokens(&net.user(0)), 1_003, "and keeps completing");
        } else {
            assert!(outcome(&tx).storage_fees > 0, "an unlisted bridge pays rent");
            assert!(net.is_frozen(&bridge), "the jump froze the unlisted bridge");
        }
    }
}

/// T-X4: a wallet frozen by rent and restored from its own state keeps its
/// life and its history: nothing is stranded, its unreported credit is
/// counted once, and it burns as before.
#[test]
fn t_x4_a_frozen_wallet_restored_keeps_its_life_and_history() {
    let mut net = minted();
    let user = net.user(0);
    ordinary_prices(&mut net);
    net.start_swap(500);
    let report = net.drop_op(op::CREDIT_RECORDED);
    net.settle();
    let wallet = net.wallet_of(&user);
    let state = net.state_of(&wallet);
    let life = net.wallet_state(&user)[0];
    price_jump(&mut net, true);
    net.advance_time(10); // a debt the restorer can pay
    let msg = poke(&net, &wallet);
    net.send_one(msg);
    net.queue.clear();
    assert!(net.is_frozen(&wallet), "the rent froze the wallet");
    ordinary_prices(&mut net);
    // anyone may restore it with its own state and pay its debt
    let restore = MessageBuilder::internal(net.stranger.address(), &wallet, 2_000 * TOS)
        .bounce(false)
        .state_init(state)
        .build();
    net.send(restore);
    assert!(!net.is_frozen(&wallet) && net.exists(&wallet), "restored");
    assert_eq!(net.wallet_state(&user)[0], life, "the same life");
    net.send(report);
    assert_eq!(net.supply_state(), (1_500, 0, 0, 0, 0), "counted once, nothing stranded");
    assert_eq!(stranded_logs(&net), 0);
    net.start_burn(100);
    net.settle();
    assert_eq!(net.tokens(&user), 1_400);
    assert_eq!(net.burn_logs(), 1);
}

fn fwd_fees(tx: &chain_block::Transaction) -> u128 {
    match tx.read_description().expect("a description") {
        chain_block::TransactionDescr::Ordinary(d) => d
            .action
            .as_ref()
            .and_then(|a| a.total_fwd_fees.as_ref())
            .map(|c| c.as_u128())
            .unwrap_or(0),
        _ => 0,
    }
}

/// T-Z5: the exemptions of a bridge listed in ConfigParam 31 are measured,
/// not assumed: its sends pay no forwarding fee, and a masterchain limit
/// below its present size does not stop its completions. Unlisted, both
/// apply.
#[test]
fn t_z5_a_listed_bridge_pays_no_forwarding_and_ignores_the_size_limit() {
    for listed in [true, false] {
        let mut net = minted();
        let bridge = net.bridge.clone();
        net.set_special(&bridge, listed);
        let from = net.delivered.len();
        net.swap(2);
        let vote = net.delivered[from..]
            .iter()
            .find(|d| d.addr == bridge && body_op(&d.msg) == Some(OP_EXECUTE_VOTING))
            .expect("the vote ran at the bridge");
        let fees = fwd_fees(&vote.tx);
        if listed {
            assert_eq!(fees, 0, "a listed bridge pays no forwarding");
        } else {
            assert!(fees > 0, "an unlisted bridge pays forwarding");
        }
        // a masterchain limit below the bridge's present size, from the
        // version that applies it
        let (cells, _) = net.state_cells(&bridge);
        let base = net.bc.config_params().size_limits_config().expect("limits").max_acc_state_cells;
        net.start_swap(3);
        net.deliver_until(|m| body_op(m) == Some(op::PREPARED));
        net.configure_limits(base, cells as u32 - 1);
        let prepared = net.take(|m| body_op(m) == Some(op::PREPARED));
        let tx = net.send_one(prepared);
        if listed {
            assert!(outcome(&tx).action_ok, "the size limit does not apply to a listed bridge");
            net.settle();
            assert_eq!(net.tokens(&net.user(0)), 1_005);
        } else {
            assert!(!outcome(&tx).action_ok, "the size limit applies to an unlisted bridge");
            net.queue.clear();
        }
    }
}

/// T-Z5: a listed bridge at its worst-case occupancy, every channel full,
/// then removed from ConfigParam 31: rent accrues, its state stays under the
/// ordinary masterchain limit, and its completions still execute.
#[test]
fn t_z5_a_bridge_removed_from_the_list_at_worst_case_occupancy_still_completes() {
    let mut net = minted();
    let bridge = net.bridge.clone();
    net.set_special(&bridge, true);
    // the real channel's mint window held full, the other channels full clones
    let window = declared("MINT_WINDOW") as usize;
    let mut held = Vec::new();
    for i in 0..window - 1 {
        // spread over the holders: each holder's own credit window is smaller
        let to = net.user(i % 4);
        net.start_swap_to(&to, 1);
        net.deliver_until(|m| body_op(m) == Some(op::PREPARED));
        held.push(net.take(|m| body_op(m) == Some(op::PREPARED)));
    }
    crate::gauge::fill_channels(&mut net);
    let (cells, _) = net.state_cells(&bridge);
    let mc = net.bc.config_params().size_limits_config().expect("limits").max_mc_acc_state_cells;
    assert!(cells <= mc as usize, "the full bridge, {cells} cells, fits the ordinary limit {mc}");
    net.set_special(&bridge, false);
    ordinary_prices(&mut net);
    // a special account keeps no time of last payment: rent runs from the
    // first transaction after its removal
    let msg = poke(&net, &bridge);
    let first = net.send_one(msg);
    net.queue.clear();
    assert_eq!(outcome(&first).storage_fees, 0, "nothing is charged for the listed period");
    net.advance_time(86_400);
    let mut rent = 0;
    for m in held {
        let tx = net.send_one(m);
        rent += outcome(&tx).storage_fees;
        net.settle();
    }
    assert!(rent > 0, "rent accrues once unlisted");
    let total: u128 = (0..4).map(|i| net.tokens(&net.user(i))).sum();
    assert_eq!(total, 1_000 + window as u128 - 1, "every held mint completed");
    assert_eq!(net.channel()[10], 0, "nothing pending");
}

fn wallet_advance(net: &Net, owner: &MsgAddressInt, b: u64, value: u64) -> Message {
    let wallet = net.wallet_of(owner);
    net.advance_message(&wallet, advance::BURN, value, |x| {
        x.append_u64(b).unwrap();
    })
}

/// T-L: a wallet drained below its reserve: the quote adds the shortfall and
/// a day of rent to the need. Half a day later an advance carrying only the
/// need is refused before any effect; one carrying the quote completes, pays
/// the rent from its own value and restores the reserve (I7 after every
/// transaction).
#[test]
fn t_l_a_quote_covers_the_reserve_shortfall_and_a_day_of_rent() {
    let mut net = minted();
    let user = net.user(0);
    ordinary_prices(&mut net);
    net.start_burn(10);
    net.drop_op(op::BURN_ADMIT);
    net.settle();
    let wallet = net.wallet_of(&user);
    let reserve = declared("WALLET_RESERVE") as u64;
    net.set_balance(&wallet, u128::from(reserve / 2));
    let (need, quote) = net.wallet_advance_cost(&user, advance::BURN);
    assert!(quote >= need + reserve / 2, "the quote adds the shortfall: need {need}, quote {quote}");
    net.advance_time(43_200);
    let before = net.state_hashes();
    let short = wallet_advance(&net, &user, 0, need);
    let tx = net.send(short);
    assert!(outcome(&tx).aborted, "the need alone does not restore the reserve");
    assert!(outcome(&tx).storage_fees > 0, "rent was due, and paid even by the refusal");
    assert_eq!(net.state_hashes(), before, "no effect");
    let enough = wallet_advance(&net, &user, 0, quote);
    let tx = net.send(enough);
    succeeded(&tx);
    assert!(net.balance(&wallet) >= u128::from(reserve), "the reserve is restored");
    assert_eq!(net.tokens(&user), 990);
    assert_eq!(net.burn_logs(), 1, "the burn completed once");
    assert_eq!(net.held(&user, 0), -1, "nothing held");
}

/// T-L: rent leaves a wallet in debt; a plain top-up, a message with no
/// body, pays the debt and its business continues.
#[test]
fn t_l_a_plain_top_up_pays_a_debt() {
    let mut net = minted();
    let user = net.user(0);
    ordinary_prices(&mut net);
    let wallet = net.wallet_of(&user);
    net.set_balance(&wallet, 0);
    net.advance_time(3_600);
    let msg = poke(&net, &wallet);
    let tx = net.send_one(msg);
    net.queue.clear();
    assert!(outcome(&tx).storage_fees == 0 && !net.is_frozen(&wallet), "a small debt, not frozen");
    let top_up = MessageBuilder::internal(net.stranger.address(), &wallet, TOS).bounce(false).build();
    succeeded(&net.send(top_up));
    let due = net.bc.get_account(&wallet).and_then(|a| a.due_payment().cloned());
    assert!(due.is_none_or(|d| d.is_zero()), "the debt is paid");
    net.start_burn(10);
    net.settle();
    assert_eq!(net.tokens(&user), 990);
    assert_eq!(net.burn_logs(), 1);
}

/// T-X7: a leg whose sends exceed the balance fails in its action phase and
/// rolls back whole. A bridge drained below its recorded payments cannot
/// return a cancelled lock's fee: the cancellation is not recorded and
/// nothing is logged. After a plain top-up the same cancellation succeeds
/// once.
#[test]
fn t_x7_a_send_above_the_balance_rolls_the_leg_back_whole() {
    let mut net = minted();
    let n = net.next_nonce;
    net.next_nonce += 1;
    succeeded(&net.pay(n));
    let bridge = net.bridge.clone();
    net.set_balance(&bridge, 0);
    let before = net.state_hashes();
    let cancel = net.vote(400, net.cancel_lock_vote(GENERATION, n));
    let tx = net.send_one(cancel);
    net.queue.clear();
    assert!(!outcome(&tx).action_ok, "the refund exceeds the balance: the action phase fails");
    assert_eq!(net.state_hashes(), before, "rolled back whole");
    assert_eq!(net.logs_from(&bridge, declared("LOG_SWAP_CANCELLED") as u32), 0, "nothing logged");
    let top_up = MessageBuilder::internal(net.stranger.address(), &bridge, 50 * TOS).bounce(false).build();
    succeeded(&net.send(top_up));
    let cancel = net.vote(401, net.cancel_lock_vote(GENERATION, n));
    succeeded(&net.send(cancel));
    assert_eq!(net.swap_record(n).0, -1, "cancelled and folded");
    assert_eq!(net.logs_from(&bridge, declared("LOG_SWAP_CANCELLED") as u32), 1, "logged once");
}
