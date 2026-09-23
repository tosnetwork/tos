/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 19 gate 17, over runs of real transactions.
//!
//! The arithmetic of `anchors_preserve` is tested against the function
//! directly in the contracts crate. What that cannot show is what a *run*
//! does, and the run is where the interesting part is: a deposit appends one
//! leaf and a transact appends three, so the versions a mixed run preserves
//! skip numbers, and a ring slot whose residue is skipped keeps its occupant
//! past the nominal four thousand and ninety-six.
//!
//! Every transaction here is a real message to the shipping contract, and
//! every transact carries a real Groth16 proof.

mod traffic;

use shielded_pool_circuit_crosscheck::transact::Anchor;
use traffic::{Traffic, RECENT_SLOTS};

/// Section 6.2: a root that has been overwritten in its slot.
const ANCHOR_NOT_IN_THE_RING: i32 = 153;

/// Pure deposits: one leaf each, so every version in the run is used and
/// every slot is written in turn.
#[test]
fn pure_deposit_traffic_writes_every_consecutive_slot() {
    let mut run = Traffic::start();
    let mut versions = Vec::new();
    for _ in 0..6 {
        versions.push(run.deposit());
    }
    assert_eq!(versions, vec![0, 1, 2, 3, 4, 5], "a deposit moved the index by other than one");

    let (recent, _) = run.rings();
    let slots: Vec<u64> = recent.iter().map(|entry| entry.slot).collect();
    let ids: Vec<u64> = recent.iter().map(|entry| entry.version).collect();
    assert_eq!(slots, versions, "a deposit run did not write one slot per version");
    assert_eq!(ids, versions, "a slot holds a version that is not its own");
}

/// Mixed traffic: the run alternates one-leaf and three-leaf mutations, so
/// two residues out of every four are never used as a version at all.
#[test]
fn mixed_traffic_leaves_the_skipped_slots_alone() {
    let mut run = Traffic::start();

    // deposit(0) -> transfer(1..3) -> deposit(4) -> transfer(5..7) -> ...
    let mut preserved = Vec::new();
    for _ in 0..3 {
        preserved.push(run.deposit());
        let against = run.snapshot();
        let (version, exit) = run.transfer(Anchor::Current, &against);
        assert_eq!(exit, 0, "the transfer was refused with exit {exit}");
        preserved.push(version);
    }
    assert_eq!(
        preserved,
        vec![0, 1, 4, 5, 8, 9],
        "a three-leaf mutation did not move the index by three"
    );

    let (recent, _) = run.rings();
    let slots: Vec<u64> = recent.iter().map(|entry| entry.slot).collect();
    assert_eq!(slots, preserved, "the ring holds a slot no mutation preserved a root under");

    // The versions the three-leaf batches consumed as leaf indices were never
    // anybody's pre-transaction root, so nothing was ever stored for them.
    for skipped in [2u64, 3, 6, 7, 10, 11] {
        assert!(
            !recent.iter().any(|entry| entry.slot == skipped),
            "slot {skipped} holds an entry, but no transaction ever had version {skipped}"
        );
    }
    for entry in &recent {
        assert_eq!(
            entry.version, entry.slot,
            "below one ring a slot must hold its own version, not {}",
            entry.version
        );
    }
}

/// A recent root is good until its own slot is taken, and the proof that says
/// so is a real transact against it.
#[test]
fn a_recent_root_is_accepted_until_its_slot_is_overwritten() {
    let mut run = Traffic::start();
    run.deposit();
    // The root after the first deposit, which the second deposit preserves
    // under version 1.
    let after_first = run.snapshot();
    assert_eq!(after_first.version, 1, "the first deposit did not take leaf zero");
    run.deposit();

    let (recent, _) = run.rings();
    assert!(
        recent.iter().any(|entry| entry.slot == 1 && entry.version == 1),
        "the second deposit did not preserve the first's root under version 1"
    );

    // Some traffic moves on, and the root stays good because its slot is
    // untouched.
    run.deposit();
    run.deposit();
    let (version, exit) = run.transfer(Anchor::Recent(1), &after_first);
    assert_eq!(
        exit, 0,
        "a transact against a recent root whose slot is untouched was refused with exit {exit} \
         (it preserved version {version})"
    );
}

/// The other half of the same rule: once the slot is taken, the root is not.
///
/// Reaching version 4097 by sending four thousand messages would measure the
/// harness. The counter is moved instead, which is sound because the versions
/// in between were never externally visible roots -- no proof can name one.
#[test]
fn a_recent_root_is_refused_once_its_slot_is_overwritten() {
    let mut run = Traffic::start();
    run.deposit();
    let after_first = run.snapshot();
    run.deposit();

    let (before, _) = run.rings();
    let held = before
        .iter()
        .find(|entry| entry.slot == 1)
        .copied()
        .expect("version 1 was never preserved");

    // One index short of the version that lands on slot 1 again.
    run.skip_to(RECENT_SLOTS + 1);
    let (still, _) = run.rings();
    assert!(
        still.iter().any(|entry| entry.slot == 1 && entry.version == held.version),
        "moving the counter disturbed the ring, which it must not"
    );

    // This deposit's version is 4097, whose slot is 1.
    let overwriting = run.deposit();
    assert_eq!(overwriting, RECENT_SLOTS + 1, "the counter did not land where it was put");
    let (after, _) = run.rings();
    let taken = after
        .iter()
        .find(|entry| entry.slot == 1)
        .copied()
        .expect("slot 1 lost its entry entirely");
    assert_eq!(taken.version, RECENT_SLOTS + 1, "slot 1 was not taken over by its own version");
    assert_ne!(taken.root, held.root, "slot 1 still holds the root it held before");

    let (_, exit) = run.transfer(Anchor::Recent(1), &after_first);
    assert_eq!(
        exit, ANCHOR_NOT_IN_THE_RING,
        "a root whose slot has been overwritten was still accepted (exit {exit})"
    );
}

/// Half a ring away lands on its own slot.
///
/// This is what tells the ring's own size from any divisor of it: version
/// 2,048 folds onto slot 0 in a 2,048-slot ring and onto slot 2,048 in a
/// 4,096-slot one, and only in the second does the entry written at version 1
/// survive. Version 4,097 cannot tell them apart, because it lands on slot 1
/// either way.
#[test]
fn a_version_half_a_ring_away_lands_on_its_own_slot() {
    let mut run = Traffic::start();
    run.deposit();
    let after_first = run.snapshot();
    run.deposit();

    let held = run
        .rings()
        .0
        .iter()
        .find(|entry| entry.slot == 1)
        .copied()
        .expect("version 1 was never preserved");

    run.skip_to(RECENT_SLOTS / 2 + 1);
    let version = run.deposit();
    assert_eq!(version, RECENT_SLOTS / 2 + 1, "the counter did not land where it was put");

    let (recent, _) = run.rings();
    let still = recent
        .iter()
        .find(|entry| entry.slot == 1)
        .copied()
        .unwrap_or_else(|| panic!("slot 1 lost its entry to a version half a ring away"));
    assert_eq!(still, held, "a version half a ring away overwrote slot 1");
    assert!(
        recent.iter().any(|entry| entry.slot == RECENT_SLOTS / 2 + 1),
        "the new version did not take a slot of its own"
    );

    // And the root is still spendable, which is the property the slot
    // arithmetic exists to provide.
    let (_, exit) = run.transfer(Anchor::Recent(1), &after_first);
    assert_eq!(exit, 0, "a root half a ring from the newest was refused with exit {exit}");
}
