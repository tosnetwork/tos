/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 15.4 and gate 27: the smallest bounce that can still be recovered.
//!
//! A bounced message has to pay for its own authentication out of the value it
//! carries, because those checks run before ACCEPT -- a message the pool has
//! not authenticated must not be able to spend the pool's balance. So there is
//! a value below which a bounce cannot be recovered at all, and section 15.4
//! is explicit that V1 does not promise recovery below it: whatever is
//! credited but cannot execute recovery becomes unencumbered reserve, which is
//! the withdrawing user's loss.
//!
//! The profile requires that threshold to be measured and frozen for the
//! active fee schedule rather than assumed, and measured from real
//! protocol-generated bounces. That is what this does: it withdraws smaller
//! and smaller denominations, each one a whole proved withdrawal whose payout
//! a real destination refuses, and finds the boundary by bisection.
//!
//! The number it prints is a fact about *this* fee schedule. It moves with the
//! gas price, with the Poseidon2 tariff, and with anything that changes what
//! the pre-ACCEPT checks cost.

mod support;

use shielded_pool_circuit_crosscheck::pool::{DENOMINATION, WITHDRAWAL_FEE};
use support::{Withdrawal, REFUSER};

/// One whole withdrawal of `amount`, refused by its destination.
fn refused_withdrawal(amount: u64) -> support::Outcome {
    // The configured list has to hold the value being withdrawn and the one
    // being deposited, ascending.
    let denominations: Vec<u64> =
        if amount == DENOMINATION { vec![DENOMINATION] } else { vec![amount, DENOMINATION] };
    support::run(&Withdrawal {
        denominations: &denominations,
        amount,
        destination_name: "dust_refuser",
        destination_source: REFUSER,
        age: None,
        before_transact: Default::default(),
    })
}

/// Did the bounce become a note?
fn recovered(outcome: &support::Outcome) -> bool {
    // Two deposits and three outputs are five leaves; a recovery note is the
    // sixth. Counting leaves rather than reading an exit code is deliberate:
    // what section 15.4 forbids below the threshold is *minting*, whatever the
    // handler's exit code happens to be.
    outcome.commitment_next_index == "6"
}

#[test]
fn the_smallest_recoverable_bounce_is_measured_rather_than_assumed() {
    // A denomination large enough to be recovered, established rather than
    // assumed, so the bisection has an upper bound it has seen work.
    let high_amount = DENOMINATION;
    let high = refused_withdrawal(high_amount);
    assert!(
        recovered(&high),
        "a whole denomination did not come back, so there is no boundary to find"
    );
    assert!(high.bounced_value > 0, "a whole denomination bounced back nothing");

    // And one small enough not to be. A single nanotos cannot pay for its own
    // authentication under any fee schedule worth having.
    let low = refused_withdrawal(1);
    assert!(
        !recovered(&low),
        "a one-nanotos bounce minted a note, so recovery is not paying for itself"
    );
    // Section 15.4: below the threshold the handler mints nothing, and what
    // was credited stays as unencumbered reserve rather than becoming a debt.
    assert_eq!(
        low.pool_liability_after,
        low.pool_liability_before - 1 - u128::from(WITHDRAWAL_FEE),
        "a bounce too small to recover still changed what the pool owes"
    );
    assert!(
        low.holds >= low.pool_liability_after + low.reserve,
        "the pool owes {} with a {} floor and holds only {}",
        low.pool_liability_after,
        low.reserve,
        low.holds
    );

    // Bisect on the withdrawn amount. Each probe is a whole proved withdrawal
    // whose payout is really sent and really refused, so the bounce it
    // measures is the protocol's.
    let (mut fails, mut works) = (1u64, high_amount);
    let mut works_outcome = high;
    let mut fails_outcome = low;
    while fails + 1 < works {
        let middle = fails + (works - fails) / 2;
        let outcome = refused_withdrawal(middle);
        if recovered(&outcome) {
            works = middle;
            works_outcome = outcome;
        } else {
            fails = middle;
            fails_outcome = outcome;
        }
    }

    // What the profile calls min_recoverable_bounce_value is the value the
    // bounce carried, not the amount withdrawn: the destination's compute and
    // the transport have already been taken out of it by then.
    let boundary = works_outcome.bounced_value;
    eprintln!(
        "min_recoverable_bounce_value = {boundary} nanotos \
         (withdrawing {works} bounces back {boundary} and recovers; \
         withdrawing {fails} does not)"
    );
    eprintln!(
        "the recovery at the boundary: {} gas, exit {}",
        works_outcome.recovery_gas, works_outcome.recovery_exit
    );

    assert!(boundary > 0, "the boundary bounce carried nothing");
    assert_eq!(works, fails + 1, "the bisection did not close");

    // The sharp statement of the boundary, and the one gate 27 is about: one
    // nanotos below it a bounce still comes back -- the protocol generated it,
    // it carried value, it reached the pool -- and the pool still mints
    // nothing. The failure is not that no bounce arrived; it is that the
    // bounce could not pay for putting itself back.
    assert!(
        fails_outcome.bounced_from.is_some(),
        "one below the boundary nothing bounced at all, so this is not the dust boundary \
         but the point where the destination stops being able to run"
    );
    assert!(fails_outcome.bounced_value > 0, "the bounce one below the boundary carried nothing");
    assert!(!recovered(&fails_outcome), "the bisection put a recovered case on the failing side");

    // And *which* threshold this is, which the bisection alone cannot say.
    //
    // There are two, and they moved past each other. A bounce has to carry
    // enough to run the pre-ACCEPT authentication, and since section 15.4
    // started charging the recovery to the recovered amount it also has to
    // carry more than that charge or the pool mints nothing. The second is now
    // about twenty times the first, so it is the one that binds, and the
    // boundary is exactly one nanotos above it.
    //
    // Without this the test passes for any boundary at all -- it did, while
    // the charge moved it from a few tens of thousands of nanotos to one and a
    // half million, and the comment above went on describing the old reason.
    let charge = works_outcome.recovery_charge;
    assert_eq!(
        boundary,
        charge + 1,
        "the smallest recoverable bounce is {boundary} and the recovery charges {charge}; if \
         these have come apart, the binding threshold is no longer the charge -- most likely \
         the pre-ACCEPT authentication has become the dearer of the two, which is a different \
         statement and wants a different test"
    );
    eprintln!(
        "the binding threshold is the recovery charge, {charge}, not the authentication: \
         a bounce must carry more than what putting it back costs"
    );
    eprintln!(
        "one below: a bounce of {} came back and minted nothing",
        fails_outcome.bounced_value
    );

    // Section 15.4: what was credited but could not execute recovery is
    // unencumbered reserve, not a debt. The pool owes less, not more.
    assert_eq!(
        fails_outcome.pool_liability_after,
        fails_outcome.pool_liability_before - u128::from(fails) - u128::from(WITHDRAWAL_FEE),
        "a bounce too small to recover still changed what the pool owes"
    );
    assert!(
        fails_outcome.holds >= fails_outcome.pool_liability_after + fails_outcome.reserve,
        "below the boundary the pool owes more than it holds"
    );

    // The pool is whole at the boundary too: it minted back only what came
    // back, and what it owes is still covered.
    assert!(
        works_outcome.holds >= works_outcome.pool_liability_after + works_outcome.reserve,
        "at the boundary the pool owes more than it holds"
    );
}
