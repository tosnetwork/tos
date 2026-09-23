/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The anchor rings are empty exactly once, and every gas figure taken
//! against that state is the cheapest the contract will ever be.
//!
//! Section 6's rings hold 4,096 recent roots and 2,880 epoch checkpoints. A
//! pool doing one transaction a second fills the recent ring in about an hour
//! and never empties it again. A harness that deploys a pool and sends three
//! messages measures the empty case, and a proof against the current root --
//! which is what a harness naturally builds -- skips the ring read entirely.

use shielded_pool_circuit_crosscheck::anchor_probe::{AnchorProbe, EPOCH_SLOTS, RECENT_SLOTS};

#[test]
fn the_rings_cost_more_once_they_are_full() {
    let probe = AnchorProbe::deploy().expect("deploy the anchor probe");

    let empty = probe.preserve_gas(0, 0, true).expect("preserve into empty rings");
    let full = probe.preserve_gas(RECENT_SLOTS, EPOCH_SLOTS, true).expect("preserve into full rings");
    let full_quiet =
        probe.preserve_gas(RECENT_SLOTS, EPOCH_SLOTS, false).expect("preserve without a checkpoint");

    eprintln!("preserve, empty rings, epoch advances: {empty} gas");
    eprintln!("preserve, full rings, epoch advances: {full} gas");
    eprintln!("preserve, full rings, same epoch: {full_quiet} gas");

    let read_empty = probe.check_recent_gas(1, 0).expect("check against a one-entry ring");
    let read_full = probe.check_recent_gas(RECENT_SLOTS, RECENT_SLOTS - 1).expect("check against a full ring");
    eprintln!("recent-root check, one entry: {read_empty} gas");
    eprintln!("recent-root check, full ring: {read_full} gas");

    // Without this the probe could be reporting a constant and nobody would
    // know the ceilings are carrying an unmeasured term.
    assert!(
        full > empty,
        "preserve costs the same into empty and full rings ({empty} gas): either the \
         dictionary work stopped depending on occupancy, or the probe is not measuring it"
    );
    assert!(read_full > read_empty, "a lookup in a full ring cannot be as cheap as in a ring of one");

    eprintln!(
        "a transact against a recent root pays up to {} gas more than the harness measures",
        (full - empty) + (read_full - 0)
    );
}
