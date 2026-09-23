/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The backing check, at the only place the two readings of it differ.
//!
//! `balance >= liability + reserve_floor` can be asked of the balance the
//! contract can see, or of the balance the transaction will leave. Those are
//! different numbers: the executor takes this transaction's compute fee after
//! the contract has returned, and protocol storage may already have taken its
//! own before the contract began. Neither is reversible by throwing.
//!
//! Everywhere with headroom the two readings agree, which is why every
//! existing backing test passes under both and none of them discriminates.
//! They differ in a band one fee wide, just under the floor -- and a pool can
//! be just under the floor without anybody misbehaving, because storage is
//! charged whether or not the pool is used.
//!
//! This is the review's F-04 counterexample, built: a pool already below its
//! floor by less than one deposit fee. The pre-fee reading accepts the deposit
//! and the post-fee reading refuses it, so the assertion below is the whole
//! difference between the two.

use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit_crosscheck::pool::Pool;

const TOS: u64 = 1_000_000_000;
const DENOMINATION: u64 = TOS;

/// The deposit ceiling's fee, which the funding rule already makes the sender
/// pay and which the executor takes after this contract returns.
///
/// Measured against the contract, twice over now. A first version worked the
/// formula out by hand and landed 126 nanotos low, so every case died on the
/// *funding* check at exit 203 and never reached the backing one -- a test
/// red for a reason that had nothing to do with what it was testing. The
/// second borrowed `recovery_charge`, which is the *bounce* ceiling's fee and
/// was the same number only while the two ceilings happened to agree; they
/// were re-derived separately and do not.
///
/// So it is found rather than computed. The funding rule refuses below
/// `deposit_amount + get_compute_fee(0, deposit_gas_ceiling())` and accepts
/// at it, so a bisection on the value returns that term exactly, whatever the
/// ceiling is and whatever the chain charges for gas.
fn deposit_fee(amount: u64) -> u64 {
    let mut pool =
        Pool::deploy_with_balance(&[amount], 1_000 * TOS).expect("a well funded probe pool");
    let payload = shielded_pool_circuit_crosscheck::wire::byte_chain(&vec![
        0x11u8;
        shielded_pool_circuit::wire::OUTPUT_DATA_BYTES
    ])
    .expect("a payload");
    let mut probe = |over: u64| -> i32 {
        let body = Pool::deposit_body(amount, Fr::from(0x4242u64), payload.clone())
            .expect("a deposit body");
        pool.run(amount + over, body).expect("a probe deposit").0
    };

    // The ends have to be what they claim before a bisection between them
    // means anything.
    let mut refused = 0u64;
    let mut accepted = 100 * TOS;
    assert_eq!(probe(refused), 203, "a deposit with nothing for gas was not refused for funding");
    assert_eq!(probe(accepted), 0, "a generously funded deposit was refused");

    while accepted - refused > 1 {
        let middle = refused + (accepted - refused) / 2;
        match probe(middle) {
            203 => refused = middle,
            0 => accepted = middle,
            other => panic!("a deposit funded {middle} over its principal exited {other}"),
        }
    }
    accepted
}

#[test]
fn a_pool_just_under_its_floor_refuses_a_deposit_it_could_not_back() {
    // The fee is read from a pool before the one under test is built, because
    // the pool under test is deliberately too poor to answer anything.
    let fee = deposit_fee(DENOMINATION);

    // A pool that starts below its own floor. Storage does this without
    // anybody doing anything; here it is arranged directly so the case is
    // reachable in a test rather than after a simulated year.
    // Read from the deployment's own parameters, not written down here. A
    // copy would keep saying five TOS after the floor was re-derived, and
    // the case would then be built at a level that is no longer the floor.
    let floor = u64::try_from(shielded_pool_genesis::RESERVE_FLOOR).expect("the floor fits");
    let mut pool = Pool::deploy_with_balance(&[DENOMINATION], floor - fee / 2)
        .expect("deploy a pool at its floor");

    let liability: u128 = pool.get("native_liability").expect("liability").parse().expect("number");
    let reserve: u128 = pool.get("reserve_floor").expect("reserve").parse().expect("number");
    assert_eq!(liability, 0, "a fresh pool owes nothing");
    assert_eq!(u128::from(floor), reserve, "the floor is not what this test assumes");

    // One deposit, funded exactly as the rule demands and not a nanoto more.
    let owner = Fr::from(0x7777u64);
    let payload = shielded_pool_circuit_crosscheck::wire::byte_chain(&vec![
        0x5eu8;
        shielded_pool_circuit::wire::OUTPUT_DATA_BYTES
    ])
    .expect("a payload");
    let body = Pool::deposit_body(DENOMINATION, owner, payload).expect("a deposit body");
    let (exit, _gas) = pool.run(DENOMINATION + fee, body).expect("the deposit ran");

    // The reading that used to be taken sees `balance + principal + fee`
    // against `liability + principal + floor`, and the fee makes up the
    // difference: it accepts. The reading taken now subtracts the fee it is
    // about to lose, and refuses.
    assert_eq!(
        exit, 204,
        "a pool below its floor accepted a deposit it cannot back once its own fee is taken \
         (exit {exit}). Checking a balance at a moment when it is known to still change is \
         not checking it."
    );
}

/// And the same pool, given room, still works.
///
/// A check that refuses everything is not a check. This is the control: move
/// the pool one fee above its floor instead of half a fee below, and the same
/// deposit must be accepted.
#[test]
fn a_pool_above_its_floor_still_takes_deposits() {
    let fee = deposit_fee(DENOMINATION);
    // Read from the deployment's own parameters, not written down here. A
    // copy would keep saying five TOS after the floor was re-derived, and
    // the case would then be built at a level that is no longer the floor.
    let floor = u64::try_from(shielded_pool_genesis::RESERVE_FLOOR).expect("the floor fits");
    let mut pool = Pool::deploy_with_balance(&[DENOMINATION], floor + 2 * fee)
        .expect("deploy a pool above its floor");

    let owner = Fr::from(0x8888u64);
    let payload = shielded_pool_circuit_crosscheck::wire::byte_chain(&vec![
        0x5fu8;
        shielded_pool_circuit::wire::OUTPUT_DATA_BYTES
    ])
    .expect("a payload");
    let body = Pool::deposit_body(DENOMINATION, owner, payload).expect("a deposit body");
    let (exit, _gas) = pool.run(DENOMINATION + fee, body).expect("the deposit ran");
    assert_eq!(exit, 0, "a pool with room refused a well-funded deposit with exit {exit}");
}
