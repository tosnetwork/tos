/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Burns: owner -> wallet (hold) -> burn_admit -> minter -> burn_notice ->
//! bridge (LOG_BURN) -> burn_result -> minter -> burn_outcome -> wallet.

use crate::harness::*;

/// T-B1: a burn, in one pass.
#[test]
fn t_b1_a_burn_is_recorded_once_and_logged_once() {
    let mut net = Net::new();
    net.model.enabled = true;
    let user = net.user(0);
    net.swap(1_000);
    net.start_burn(400);
    net.settle();

    assert_eq!(net.burn_logs(), 1);
    assert_eq!(net.tokens(&user), 600);
    assert_eq!(net.held(&user, 0), -1, "the hold is gone");
    assert_eq!(net.supply_state(), (600, 0, 0, 0, 0));
}
