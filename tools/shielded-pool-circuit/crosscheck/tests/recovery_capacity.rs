/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The last leaves of the commitment tree, with withdrawals still in flight.
//!
//! A withdrawal's payout can bounce, and the recovery note that puts the money
//! back needs a leaf. If the tree has filled in the meantime, the bounce is
//! authentic, the money has come back, and there is nowhere to put it: the
//! user's value is stranded in the pool's balance as nobody's reserve. So
//! every accepted withdrawal reserves one leaf, nothing else may append into
//! reserved space, and only the authentic bounce consumes the reservation.
//!
//! Everything here is real except the pool's age. The withdrawals carry real
//! proofs; the payouts are sent by the pool's own handler; a real recipient
//! refuses them and the executor bounces them. What the test arranges is the
//! order: each message is executed on its own, so both payouts can be in
//! flight at once and their bounces can be delivered late and in the reverse
//! order of the withdrawals that sent them. The leaf counter is moved to the
//! end of the tree directly, which changes nothing a later transaction reads
//! except the counter itself -- see `Pool::age_index_to`.

mod support;

use chain_block::{CommonMsgInfo, Message, MsgAddressInt, TrComputePhase, TransactionDescr};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::imt;
use shielded_pool_circuit_crosscheck::pool::{Pool, DENOMINATION};
use shielded_pool_circuit_crosscheck::transact::Anchor;
use shielded_pool_circuit_crosscheck::wire::byte_chain;
use support::{
    deploy_destination, deposit_notes, execution_domain, prove_withdrawal, ProvedWithdrawal,
    REFUSER,
};
use tos_sandbox::MessageBuilder;

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;
/// The exhausted sentinel of section 5: one past the last leaf.
const SENTINEL: u64 = 1 << 32;
/// What the refuser throws, so its payout fails in the compute phase.
const REFUSED: i32 = 701;
/// Section 13: no room left beside the reserved leaves.
const NO_ROOM: i32 = 190;
/// Section 13: a recovery with no reservation left to consume.
const NO_RESERVATION: i32 = 191;
/// Section 6: the anchor store refuses a pre-mutation root at the sentinel.
/// The exit a recovery used to die with when the tree had filled under it.
const ANCHOR_AT_SENTINEL: i32 = 156;
/// The recent-root ring's slot count.
const RECENT_SLOTS: u64 = 4096;

/// One transaction, executed on its own, with what it sent left undelivered.
struct Step {
    exit: i32,
    aborted: bool,
    sent: Vec<Message>,
}

fn step(pool: &mut Pool, message: Message) -> Step {
    let (_, tx, sent) = pool.bc.execute_one(message).expect("the executor runs");
    let TransactionDescr::Ordinary(description) = tx.read_description().expect("a description")
    else {
        panic!("not an ordinary transaction");
    };
    let exit = match description.compute_ph {
        TrComputePhase::Vm(vm) => vm.exit_code,
        TrComputePhase::Skipped(skipped) => panic!("compute skipped: {:?}", skipped.reason),
    };
    Step { exit, aborted: description.aborted, sent }
}

fn value_of(message: &Message) -> u128 {
    match message.header() {
        CommonMsgInfo::IntMsgInfo(info) => info.value.coins.as_u128(),
        _ => panic!("not an internal message"),
    }
}

fn is_bounce(message: &Message) -> bool {
    matches!(message.header(), CommonMsgInfo::IntMsgInfo(info) if info.bounced)
}

fn get(pool: &Pool, method: &str) -> String {
    pool.get(method).unwrap_or_else(|error| panic!("{method}: {error}"))
}

fn number(pool: &Pool, method: &str) -> u128 {
    get(pool, method).parse().unwrap_or_else(|error| panic!("{method}: {error}"))
}

/// A pool holding four denominations' worth of notes, the refuser its
/// payouts go to, and two withdrawals proved against the root the four
/// deposits leave -- the first against it as the current root, the second
/// against it as the recent root the first one preserves at `start`.
struct Scenario {
    pool: Pool,
    refuser: MsgAddressInt,
    first: chain_block::Cell,
    second: chain_block::Cell,
}

fn scenario(start: u64) -> Scenario {
    let mut pool = Pool::deploy().expect("deploy the pool");
    let refuser = deploy_destination(&mut pool.bc, "capacity_refuser", REFUSER);
    let domain = execution_domain(&pool);
    let mut frontier = shielded_pool_circuit::tree::Frontier::new();
    let (held, root) = deposit_notes(&mut pool, &mut frontier, &[0x41, 0x42, 0x43, 0x44]);

    let mut nullifiers = imt::State::genesis();
    let first = prove_withdrawal(ProvedWithdrawal {
        pool: &pool,
        domain,
        frontier: &frontier,
        root,
        anchor: Anchor::Current,
        inputs: [&held[0], &held[1]],
        amount: DENOMINATION,
        recipient: &refuser,
        intent_nonce: 0xa1,
        recovery_owner_commitment: Fr::from(0xa11ce_u64),
        nullifiers: &mut nullifiers,
    });
    let second = prove_withdrawal(ProvedWithdrawal {
        pool: &pool,
        domain,
        frontier: &frontier,
        root,
        anchor: Anchor::Recent(u32::try_from(start).expect("a leaf index")),
        inputs: [&held[2], &held[3]],
        amount: DENOMINATION,
        recipient: &refuser,
        intent_nonce: 0xb2,
        recovery_owner_commitment: Fr::from(0xb0b_u64),
        nullifiers: &mut nullifiers,
    });

    pool.age_index_to(start).expect("move the pool to the end of its tree");
    assert_eq!(get(&pool, "commitment_next_index"), start.to_string());
    assert_eq!(get(&pool, "reserved_recovery_leaves"), "0");
    Scenario { pool, refuser, first, second }
}

fn transact(pool: &mut Pool, body: chain_block::Cell) -> Step {
    let relay = pool.bc.treasury("capacity_relay", 1_000 * TOS).expect("a relay");
    let message = MessageBuilder::internal(relay.address(), &pool.addr, COMPUTE_FEE * 4)
        .bounce(true)
        .body(body)
        .build();
    step(pool, message)
}

fn deposit(pool: &mut Pool) -> i32 {
    let payload: Vec<u8> =
        (0..shielded_pool_circuit::wire::OUTPUT_DATA_BYTES as u32).map(|i| i as u8).collect();
    let body = Pool::deposit_body(
        DENOMINATION,
        Fr::from(0xd0_u64),
        byte_chain(&payload).expect("a payload"),
    )
    .expect("a deposit body");
    pool.run(DENOMINATION + COMPUTE_FEE, body).expect("the deposit runs").0
}

/// A withdrawal the pool accepted, and the bounce its refused payout became.
fn send_and_bounce(pool: &mut Pool, refuser: &MsgAddressInt, body: chain_block::Cell) -> Message {
    let withdrawal = transact(pool, body);
    assert_eq!(withdrawal.exit, 0, "the withdrawal was refused with exit {}", withdrawal.exit);
    assert!(!withdrawal.aborted, "the withdrawal was rolled back");
    assert_eq!(withdrawal.sent.len(), 1, "a withdrawal sends its payout and nothing else");
    let payout = withdrawal.sent.into_iter().next().expect("the payout");
    assert_eq!(
        payout.dst().map(|addr| addr.to_string()),
        Some(refuser.to_string()),
        "the payout went somewhere other than the recipient"
    );
    let refusal = step(pool, payout);
    assert_eq!(refusal.exit, REFUSED, "the recipient did not refuse the payout");
    let mut bounces = refusal.sent.into_iter().filter(is_bounce);
    let bounce = bounces.next().expect("the refused payout bounced");
    assert!(bounces.next().is_none(), "one refused payout bounced twice");
    bounce
}

/// Two withdrawals take the last room in the tree, the bounces come back late
/// and in reverse order, and every one of them is recovered -- the last one
/// into the final leaf.
#[test]
fn bounces_still_in_flight_keep_their_leaves_to_the_end_of_the_tree() {
    let start = SENTINEL - 8;
    let Scenario { mut pool, refuser, first, second } = scenario(start);

    // Two withdrawals: three outputs each, and one leaf held back each.
    let bounce_first = send_and_bounce(&mut pool, &refuser, first);
    assert_eq!(get(&pool, "commitment_next_index"), (SENTINEL - 5).to_string());
    assert_eq!(
        get(&pool, "reserved_recovery_leaves"),
        "1",
        "the first withdrawal reserved nothing"
    );
    let bounce_second = send_and_bounce(&mut pool, &refuser, second);
    assert_eq!(get(&pool, "commitment_next_index"), (SENTINEL - 2).to_string());
    assert_eq!(
        get(&pool, "reserved_recovery_leaves"),
        "2",
        "the second withdrawal reserved nothing"
    );

    // Two leaves are left and both are spoken for. A deposit that took one
    // would leave one of those bounces with nowhere to go.
    let before = pool.state_snapshot().expect("the state");
    assert_eq!(deposit(&mut pool), NO_ROOM, "a deposit took a leaf reserved for a recovery");
    assert_eq!(
        pool.state_snapshot().expect("the state"),
        before,
        "a refused deposit moved the state"
    );

    let charge = number(&pool, "recovery_charge");

    // The second withdrawal's bounce first.
    let liability = number(&pool, "native_liability");
    let root = get(&pool, "commitment_root");
    let returned = value_of(&bounce_second);
    assert!(returned > charge, "the bounce carried too little to be recovered at all");
    let recovery = step(&mut pool, bounce_second);
    assert_eq!(recovery.exit, 0, "the later withdrawal's bounce was not recovered");
    assert!(!recovery.aborted, "the recovery was rolled back");
    assert_eq!(get(&pool, "commitment_next_index"), (SENTINEL - 1).to_string());
    assert_eq!(
        get(&pool, "reserved_recovery_leaves"),
        "1",
        "the recovery did not consume its reservation"
    );
    assert_ne!(get(&pool, "commitment_root"), root, "the recovery minted no note");
    assert_eq!(number(&pool, "native_liability"), liability + returned - charge);

    // Then the first one's, into the very last leaf.
    let liability = number(&pool, "native_liability");
    let root = get(&pool, "commitment_root");
    let returned = value_of(&bounce_first);
    let recovery = step(&mut pool, bounce_first.clone());
    assert_eq!(
        recovery.exit, 0,
        "the earlier withdrawal's bounce, delivered last, was not recovered (exit {}); {} is the \
         failure a tree that filled under it used to produce",
        recovery.exit, ANCHOR_AT_SENTINEL
    );
    assert_eq!(get(&pool, "commitment_next_index"), SENTINEL.to_string(), "the tree is not full");
    assert_eq!(get(&pool, "reserved_recovery_leaves"), "0", "a reservation outlived its bounce");
    assert_ne!(get(&pool, "commitment_root"), root, "the last recovery minted no note");
    assert_eq!(number(&pool, "native_liability"), liability + returned - charge);

    // The root the last leaf was appended to was preserved, at the version of
    // that leaf, which is the last version the ring can ever hold.
    let (recent, _) = pool.anchor_rings().expect("the rings");
    let last = SENTINEL - 1;
    let entry = recent
        .iter()
        .find(|entry| entry.slot == last % RECENT_SLOTS)
        .expect("the last pre-mutation root was not preserved");
    assert_eq!(entry.version, last, "the last slot holds another version");
    assert_eq!(
        dec_bytes(&entry.root),
        root,
        "the root preserved at the last version is not the one the last leaf was appended to"
    );

    // Full, and nothing reserved. A deposit is refused by the room rule
    // before it reaches the anchor store's own sentinel check.
    let before = pool.state_snapshot().expect("the state");
    assert_eq!(
        deposit(&mut pool),
        NO_ROOM,
        "a deposit into the full tree was not refused for room"
    );
    assert_eq!(
        pool.state_snapshot().expect("the state"),
        before,
        "a refused deposit moved the state"
    );

    // The first bounce again. A real chain delivers it once; delivered twice,
    // there is no reservation left for it and it does not touch the tree.
    let recovery = step(&mut pool, bounce_first);
    assert_eq!(
        recovery.exit, NO_RESERVATION,
        "a bounce delivered a second time was not refused for want of a reservation"
    );
    assert_eq!(
        pool.state_snapshot().expect("the state"),
        before,
        "a refused recovery moved the state"
    );
}

/// The red/green pair for the reservation itself.
///
/// From three leaves before the end, a transfer's three outputs would fit
/// exactly; a withdrawal's would too, but its recovery leaf would not. The
/// pool used to accept that withdrawal and then fail its bounce at the
/// sentinel, after the money had already come back. It now refuses the
/// withdrawal before anything moves. One leaf earlier the same withdrawal
/// fits, and its bounce is recovered into the final leaf -- which is what
/// shows the refusal is about room and not about the message.
#[test]
fn a_withdrawal_without_room_for_its_recovery_is_refused_before_it_pays() {
    let Scenario { mut pool, refuser, first, .. } = scenario(SENTINEL - 4);
    let fits = pool.bc.snapshot();

    pool.age_index_to(SENTINEL - 3).expect("one leaf further");
    let before = pool.state_snapshot().expect("the state");
    let refused = transact(&mut pool, first.clone());
    assert_eq!(
        refused.exit, NO_ROOM,
        "a withdrawal with no leaf left for its recovery was not refused for room"
    );
    assert!(
        refused.sent.iter().all(is_bounce),
        "a refused withdrawal sent something other than its own bounce"
    );
    assert_eq!(
        pool.state_snapshot().expect("the state"),
        before,
        "a refused withdrawal moved the state"
    );

    pool.bc.restore(fits);
    assert_eq!(get(&pool, "commitment_next_index"), (SENTINEL - 4).to_string());
    let bounce = send_and_bounce(&mut pool, &refuser, first);
    assert_eq!(get(&pool, "commitment_next_index"), (SENTINEL - 1).to_string());
    assert_eq!(get(&pool, "reserved_recovery_leaves"), "1");
    let recovery = step(&mut pool, bounce);
    assert_eq!(recovery.exit, 0, "the bounce of a withdrawal that fitted was not recovered");
    assert_eq!(get(&pool, "commitment_next_index"), SENTINEL.to_string());
    assert_eq!(get(&pool, "reserved_recovery_leaves"), "0");
}

/// A root as the decimal string a get-method prints.
fn dec_bytes(bytes: &[u8; 32]) -> String {
    let mut digits = vec![0u8];
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let value = u32::from(*digit) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}
