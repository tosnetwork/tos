/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The withdrawal and its bounce, measured against a pool that has run for a
//! while rather than one deployed a moment ago.
//!
//! The companion test on deposits shows why this matters: three of the
//! contract's costs grow with the pool's history, and every frozen ceiling
//! was set from a measurement taken before any of that growth existed. A
//! withdrawal appends three leaves instead of one, so it carries three times
//! the frontier term.
//!
//! The proof is a real one and it is not regenerated for the aged pool,
//! because it does not have to be: no public input names a leaf index. The
//! circuit commits to note bodies and the contract pairs each body with the
//! index it assigns.
//!
//! The pool here carries the **deployed** denomination list. Until
//! 2026-09-21 it carried one denomination, because that is the cheapest thing
//! two deposits and a withdrawal can be built from, and the ceiling was set
//! from that. Putting the same withdrawal through the deployed configuration
//! on a real node showed the difference: the contract walks the list to
//! validate an amount, and the figure was low.

mod support;

use support::{Age, Withdrawal};

/// The ceilings frozen into the contract, read from it rather than copied.
///
/// A copy would make the rule below an agreement between two numbers in this
/// file. It has to be an agreement between the measurement and the contract.
fn transact_gas_ceiling() -> i64 {
    shielded_pool_circuit_crosscheck::pool::contract_gas_ceiling("transact_gas_ceiling")
        .expect("the contract's transact ceiling")
}

fn bounce_gas_ceiling() -> i64 {
    shielded_pool_circuit_crosscheck::pool::contract_gas_ceiling("bounce_gas_ceiling")
        .expect("the contract's bounce ceiling")
}

/// Out of gas.
const OUT_OF_GAS: i32 = -14;

/// The largest digit sum a legal index has is 67, at `WORST_INDEX`. Appends
/// at consecutive indices cannot all sit there, so which of them lands on it
/// depends on where the run starts, and the transact and its bounce want
/// different starts.
const WORST_INDEX: u64 = 2 * 1_977_326_743 - 1;

/// Three outputs at digit sums 65, 66, 67: the most a transact can pay.
const WORST_FOR_TRANSACT: u64 = WORST_INDEX - 2;

/// The bounce mints its recovery note after those three, so its append lands
/// on 67 when the run starts one earlier. The transact is then slightly
/// cheaper, which is the point: the two maxima are not reached together.
const WORST_FOR_RECOVERY: u64 = WORST_INDEX - 3;

const RECENT_SLOTS: u64 = 4096;
const EPOCH_SLOTS: u64 = 2880;

/// The youngest tree that can have full anchor rings.
///
/// The recent ring is keyed by `root_version % 4096` and the version is the
/// leaf counter, so it takes 4,096 mutations to fill and the index is at
/// least that by the time it is full. That corner matters because the two
/// costs now pull in opposite directions: the rings make a transact dearer
/// and a higher leaf index makes it slightly cheaper, so the dearest state a
/// pool can be in is full rings at the lowest index that allows them --
/// which is neither of the two ends this test used to measure.
const YOUNGEST_FULL_RINGS: u64 = RECENT_SLOTS;

fn withdraw(age: Option<Age>) -> support::Outcome {
    support::run(&Withdrawal {
        // The list a pool is deployed with, not the one denomination the
        // other tests use. The contract walks the list to validate the
        // amount, so a maximum measured against a shorter list is a maximum
        // for a pool nobody deploys -- which is what the frozen figure was,
        // and it was 4,305 gas low.
        denominations: &shielded_pool_circuit_crosscheck::pool::DEPLOYED_DENOMINATIONS,
        amount: shielded_pool_circuit_crosscheck::pool::DENOMINATION,
        destination_name: "mature_refuser",
        destination_source: support::REFUSER,
        age,
        before_transact: Default::default(),
    })
}

#[test]
fn a_withdrawal_and_its_bounce_in_a_pool_with_history() {
    let fresh = withdraw(None);
    eprintln!(
        "fresh pool: transact exit {}, {} gas; recovery exit {}, {} gas",
        fresh.exit, fresh.gas, fresh.recovery_exit, fresh.recovery_gas
    );
    assert_eq!(fresh.exit, 0, "the fresh withdrawal is the baseline and has to succeed");
    assert_eq!(fresh.recovery_exit, 0, "the fresh bounce is the baseline and has to succeed");

    let aged =
        |index: u64| withdraw(Some(Age { index, recent: RECENT_SLOTS, epoch: EPOCH_SLOTS }));

    let for_transact = aged(WORST_FOR_TRANSACT);
    let for_recovery = aged(WORST_FOR_RECOVERY);
    let young_full = aged(YOUNGEST_FULL_RINGS);
    for (name, outcome) in [
        ("worst for the transact", &for_transact),
        ("worst for the bounce", &for_recovery),
        ("full rings, youngest tree", &young_full),
    ] {
        eprintln!(
            "{name}: transact exit {}, {} gas; recovery exit {}, {} gas",
            outcome.exit, outcome.gas, outcome.recovery_exit, outcome.recovery_gas
        );
        assert_eq!(outcome.exit, 0, "the withdrawal at {name} was refused");
        assert_eq!(
            outcome.recovery_exit, 0,
            "the bounce at {name} was refused with exit {}: a refused bounce is the payout \
             already returned and the recovery note never minted",
            outcome.recovery_exit
        );
    }

    // The maximum over every state measured, the fresh pool included.
    //
    // It did not used to include it, because a fresh pool was by definition
    // the cheapest: every growing cost was at its minimum there. The frontier
    // stopped growing on 2026-09-21 and started costing slightly *less* as
    // the index rises, so the dearest transact a pool can do is now its
    // first -- and a maximum taken over the aged runs alone missed it.
    let transact_ceiling = transact_gas_ceiling();
    let bounce_ceiling = bounce_gas_ceiling();
    let transact_max =
        fresh.gas.max(for_transact.gas).max(for_recovery.gas).max(young_full.gas);
    let recovery_max = fresh
        .recovery_gas
        .max(for_transact.recovery_gas)
        .max(for_recovery.recovery_gas)
        .max(young_full.recovery_gas);
    eprintln!(
        "transact: {} fresh, {} / {} oldest, {} full rings youngest tree; maximum          {transact_max}, ceiling {transact_ceiling}",
        fresh.gas, for_transact.gas, for_recovery.gas, young_full.gas
    );
    eprintln!(
        "bounce:   {} fresh, {} / {} oldest, {} full rings youngest tree; maximum          {recovery_max}, ceiling {bounce_ceiling}",
        fresh.recovery_gas,
        for_transact.recovery_gas,
        for_recovery.recovery_gas,
        young_full.recovery_gas
    );

    // Section 14's margin, over the maximum the pool can ever reach rather
    // than the one a fresh pool shows. Against the first set of ceilings the
    // bounce had none: it ran out of gas from about four million notes on.
    assert!(
        transact_max * 5 <= transact_ceiling * 4,
        "the transact ceiling {transact_ceiling} is not a quarter above the measured \
         maximum {transact_max}"
    );
    assert!(
        recovery_max * 5 <= bounce_ceiling * 4,
        "the bounce ceiling {bounce_ceiling} is not a quarter above the measured maximum \
         {recovery_max}"
    );
}

/// No pool size refuses a bounce.
///
/// The cost follows the base-seven digit sum of the leaf index the recovery
/// note lands on, not the index itself, so this walks the smallest index at
/// each digit sum rather than scanning upward. Every point is a real
/// withdrawal with a real proof, bounced by a real refusal.
///
/// This is the test that found the defect: against the first set of ceilings
/// the bounce was refused from digit sum 46, first reached at leaf index
/// 4,117,714.
#[test]
#[ignore = "sixty-odd full withdrawals; run it when the ceiling is being set"]
fn no_pool_size_refuses_a_bounce() {
    /// The smallest index whose base-seven digits sum to `target`.
    fn smallest_with_digit_sum(target: u64) -> Option<u64> {
        let mut remaining = target;
        let mut index = 0u64;
        let mut place = 1u64;
        for _ in 0..12 {
            if remaining == 0 {
                return Some(index);
            }
            let digit = remaining.min(6);
            index += digit * place;
            remaining -= digit;
            place *= 7;
        }
        if remaining == 0 && index < 4_294_967_296 {
            Some(index)
        } else {
            None
        }
    }

    for digit_sum in 1..=67u64 {
        // The recovery note lands three leaves after the transact's first.
        let Some(recovery_index) = smallest_with_digit_sum(digit_sum) else { continue };
        // The pool has already taken the two deposits the withdrawal spends,
        // so it can only be aged forward from index two.
        if recovery_index < 6 || recovery_index >= 4_294_967_296 {
            continue;
        }
        let outcome = withdraw(Some(Age {
            index: recovery_index - 3,
            recent: RECENT_SLOTS,
            epoch: EPOCH_SLOTS,
        }));
        eprintln!(
            "digit sum {digit_sum} (recovery at index {recovery_index}): bounce exit {}, {} gas",
            outcome.recovery_exit, outcome.recovery_gas
        );
        assert_eq!(
            outcome.recovery_exit, 0,
            "a pool of about {recovery_index} notes cannot recover a refused payout: exit {} \
             at {} gas against the {} ceiling",
            outcome.recovery_exit,
            outcome.recovery_gas,
            bounce_gas_ceiling()
        );
    }
}
