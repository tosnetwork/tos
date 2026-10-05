/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Mints: bridge -> prepare -> minter -> open/opened -> prepared -> commit ->
//! credit -> credit_recorded -> mint_completed.

use crate::harness::*;

/// T-M1: a mint to a new holder, in one pass.
#[test]
fn t_m1_a_mint_to_a_new_holder_completes_in_one_pass() {
    let mut net = Net::new();
    net.model.enabled = true;
    let user = net.user(0);
    let n = net.swap(1_000);
    net.dump();

    assert_eq!(net.swap_record(n).0, -1, "the lock folded below the watermark: consumed");
    assert_eq!(net.tokens(&user), 1_000);
    assert_eq!(net.supply_state(), (1_000, 0, 0, 0, 0));
    assert_eq!(net.channel()[10], 0, "nothing pending at the bridge");
    let holder = net.holder(&user);
    assert_eq!(holder[2], holder_state::OPEN);
    assert_eq!(net.mint_status(0), -1, "counted and folded");
    assert_eq!(net.minter_channels()[3], 1, "the mint watermark passed s = 0");
}
