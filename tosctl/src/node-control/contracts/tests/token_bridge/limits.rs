/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! T-Y8: the account cell limit (ConfigParam 43) and the global version that
//! switches the masterchain limit on, changed between admission and
//! completion.

use crate::burn::minted;
use crate::harness::*;

fn limits(net: &Net) -> (u32, u32) {
    let l = net.bc.config_params().size_limits_config().expect("size limits");
    (l.max_acc_state_cells, l.max_mc_acc_state_cells)
}

/// T-Y8: with the basechain limit below the minter's and wallets' declared
/// worst case, new business stops before any effect: a burn is refused at
/// the wallet and a prepare is refused at the minter, its lock staying paid.
/// With the masterchain limit below the bridge's, payments and votes are
/// refused, unless the bridge is listed in ConfigParam 31.
#[test]
fn t_y8_a_lowered_cell_limit_stops_admission_before_any_effect() {
    let mut net = minted();
    let user = net.user(0);
    let (base, mc) = limits(&net);
    net.configure_limits(declared("WALLET_WORST_CELLS") as u32 - 1, mc);
    let before = net.state_hashes();
    let burn = net.burn_message(&user, 10, net.burn_fee);
    refused_with(&net.send(burn), err("cell_limit"));
    assert_eq!(net.state_hashes(), before, "no hold");

    net.configure_limits(declared("MINTER_WORST_CELLS") as u32 - 1, mc);
    let n = net.start_swap(10);
    net.settle();
    assert_eq!(net.swap_record(n).0, swap_state::PAID, "refused at the minter, the lock stays paid");
    assert_eq!(net.tokens(&user), 1_000);
    assert_eq!(net.supply_state(), (1_000, 0, 0, 0, 0), "no supply reserved");
    net.configure_limits(base, mc);

    net.configure_limits(base, declared("BRIDGE_WORST_CELLS") as u32 - 1);
    let tx = net.pay(net.next_nonce);
    refused_with(&tx, err("cell_limit"));
    let bridge = net.bridge.clone();
    net.set_special(&bridge, true);
    net.swap(5);
    assert_eq!(net.tokens(&user), 1_005, "a listed bridge is unaffected");
}

/// T-Y8: a limit lowered below an account's present size between admission
/// and completion fails the growing completion in its action phase. The leg
/// rolls back whole, its predecessor's record stays advanceable, and the
/// operation completes once the limit is restored.
#[test]
fn t_y8_a_growing_completion_rolls_back_and_completes_after_the_limit_returns() {
    let mut net = minted();
    let user = net.user(0);
    let (base, mc) = limits(&net);
    net.start_swap(300);
    let credit = net.intercept(|m| body_op(m) == Some(op::CREDIT));
    let wallet = net.wallet_of(&user);
    let (cells, _) = net.state_cells(&wallet);
    // below the wallet's present size: whatever the credit stores, it does not fit
    net.configure_limits(cells as u32 - 1, mc);
    let before = net.state_hashes();
    let tx = net.send_one(credit);
    let o = outcome(&tx);
    assert!(!o.action_ok, "the credit fails the action phase");
    net.queue.clear();
    assert_eq!(net.state_hashes(), before, "rolled back whole");
    assert_eq!(net.tokens(&user), 1_000);
    net.configure_limits(base, mc);
    succeeded(&net.advance_minter_mint(1));
    assert_eq!(net.tokens(&user), 1_300, "completed once, after the limit returned");
    assert_eq!(net.supply_state(), (1_300, 0, 0, 0, 0));
}

/// T-Y8: the masterchain limit applies from global version 12. Below it the
/// bridge reads the basechain limit and admits; from it, a masterchain limit
/// below the bridge's worst case stops admission. Both engines agree on each
/// transaction through the trace replay.
#[test]
fn t_y8_the_masterchain_limit_switches_on_at_version_12() {
    let mut net = minted();
    let user = net.user(0);
    let (base, _) = limits(&net);
    net.configure_limits(base, declared("BRIDGE_WORST_CELLS") as u32 - 1);
    net.set_global_version(11);
    net.swap(4);
    assert_eq!(net.tokens(&user), 1_004, "before version 12 the masterchain limit does not apply");
    net.set_global_version(12);
    let tx = net.pay(net.next_nonce);
    refused_with(&tx, err("cell_limit"));
}
