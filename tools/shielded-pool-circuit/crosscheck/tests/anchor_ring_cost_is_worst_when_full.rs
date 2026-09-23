/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Every gas ceiling in the contract is measured at one state: both anchor
//! rings full. That is a choice, and until now it rested on two data points.
//!
//! `anchor_ring_cost_grows` measures the rings empty and full and asserts the
//! full one costs more. It does not say what happens in between, and "the
//! endpoints are ordered" is not "the maximum is at the end". A dictionary's
//! cost is not obviously monotone in its size: the rings are keyed by slot
//! number, so a count one past a power of two deepens some paths and not
//! others, and the rebuild on a write touches a different number of cells
//! depending on which branches exist. If the cost peaked anywhere other than
//! at capacity, every
//! ceiling in the contract would be set from a state that is not the worst
//! one, and the pool would refuse messages somewhere in the middle of its
//! life -- for a while, until the rings filled past it, which is the worst
//! shape a bug can have.
//!
//! So this sweeps the occupancy rather than sampling it, on both rings and on
//! both operations that touch them, and requires the maximum to be at
//! capacity. It is cheap enough to run every time: filling a ring to capacity
//! is a handful of get-method calls, not a proof.

use shielded_pool_circuit_crosscheck::anchor_probe::{AnchorProbe, EPOCH_SLOTS, RECENT_SLOTS};

/// Occupancies to sample between empty and full.
///
/// Not a uniform grid. A dictionary's shape changes at its boundaries, so the
/// points that could hide a peak are the small ones, the powers of two either
/// side of a level boundary, and capacity itself -- a uniform sweep of the
/// same size would spend all its calls in the flat middle.
fn occupancies(capacity: u64) -> Vec<u64> {
    let mut points = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33];
    let mut step = 64;
    while step < capacity {
        points.push(step - 1);
        points.push(step);
        points.push(step + 1);
        step *= 2;
    }
    points.push(capacity / 3);
    points.push(capacity / 2);
    points.push(capacity - 1);
    points.push(capacity);
    points.retain(|point| *point <= capacity);
    points.sort_unstable();
    points.dedup();
    points
}

#[test]
fn preserving_an_anchor_is_dearest_with_both_rings_full() {
    let probe = AnchorProbe::deploy().expect("deploy the anchor probe");

    // The epoch ring held at capacity while the recent one is swept, and the
    // other way round. Sweeping one at a time is what makes a peak
    // attributable: a joint grid of the same cost would not say which ring
    // moved.
    let mut worst = (0i64, 0u64, 0u64);
    let mut readings = Vec::new();
    for recent in occupancies(RECENT_SLOTS) {
        let gas = probe
            .preserve_gas(recent, EPOCH_SLOTS, true)
            .expect("preserve against a partly filled recent ring");
        readings.push((recent, EPOCH_SLOTS, gas));
        if gas > worst.0 {
            worst = (gas, recent, EPOCH_SLOTS);
        }
    }
    for epoch in occupancies(EPOCH_SLOTS) {
        let gas = probe
            .preserve_gas(RECENT_SLOTS, epoch, true)
            .expect("preserve against a partly filled epoch ring");
        readings.push((RECENT_SLOTS, epoch, gas));
        if gas > worst.0 {
            worst = (gas, RECENT_SLOTS, epoch);
        }
    }

    let at_capacity = probe
        .preserve_gas(RECENT_SLOTS, EPOCH_SLOTS, true)
        .expect("preserve against both rings full");
    eprintln!(
        "preserve swept over {} occupancies: worst {} gas at recent {} / epoch {}; \
         at capacity {at_capacity} gas",
        readings.len(),
        worst.0,
        worst.1,
        worst.2
    );

    assert_eq!(
        worst.0, at_capacity,
        "preserving an anchor costs {} gas at recent {} / epoch {}, more than the {at_capacity} \
         it costs with both rings full. Every ceiling in the contract is measured with the \
         rings full, so the pool would refuse messages in the middle of its life and stop \
         refusing them once the rings filled past this point",
        worst.0, worst.1, worst.2
    );

    // And the sweep has to be able to see a difference at all, or it is
    // asserting that a constant equals itself.
    let spread = worst.0 - readings.iter().map(|(_, _, gas)| *gas).min().expect("a reading");
    assert!(
        spread > 0,
        "the sweep found the same cost at every occupancy, so it is not measuring occupancy"
    );
    eprintln!("preserve costs {spread} gas more at capacity than at its cheapest occupancy");
}

#[test]
fn reading_the_recent_ring_is_dearest_with_it_full() {
    let probe = AnchorProbe::deploy().expect("deploy the anchor probe");

    // The read takes a slot as well as an occupancy, and the two are not
    // independent: a given slot's path through the dictionary depends on
    // which of its neighbours exist. So this sweeps both, at the slots a
    // lookup can actually land on for that occupancy.
    let mut worst = (0i64, 0u64, 0u64);
    let mut count = 0usize;
    let mut cheapest = i64::MAX;
    for recent in occupancies(RECENT_SLOTS) {
        if recent == 0 {
            continue; // nothing is preserved, so there is nothing to look up
        }
        // Only slots the fill actually wrote: a lookup of a slot beyond the
        // occupancy is a root the pool never preserved, which the contract
        // refuses rather than prices.
        let mut ids = vec![0, 1, recent / 2, recent - 1];
        ids.retain(|id| *id < recent);
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            let gas = probe
                .check_recent_gas(recent, id)
                .expect("check a recent root against a partly filled ring");
            count += 1;
            cheapest = cheapest.min(gas);
            if gas > worst.0 {
                worst = (gas, recent, id);
            }
        }
    }

    let at_capacity = (0..RECENT_SLOTS)
        .step_by((RECENT_SLOTS / 16) as usize)
        .chain(std::iter::once(RECENT_SLOTS - 1))
        .map(|id| probe.check_recent_gas(RECENT_SLOTS, id).expect("check against a full ring"))
        .max()
        .expect("a reading at capacity");

    eprintln!(
        "recent-root check swept over {count} points: worst {} gas at occupancy {} slot {}; \
         worst at capacity {at_capacity} gas",
        worst.0, worst.1, worst.2
    );

    assert_eq!(
        worst.0, at_capacity,
        "a recent-root check costs {} gas at occupancy {} slot {}, more than the {at_capacity} \
         it costs in a full ring",
        worst.0, worst.1, worst.2
    );
    assert!(
        worst.0 > cheapest,
        "every slot at every occupancy costs the same, so this sweep is not measuring the ring"
    );
}
