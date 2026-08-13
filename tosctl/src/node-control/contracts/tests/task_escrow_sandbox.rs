/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) lifecycle tests for the Task Escrow contract.
//!
//! These execute the compiled contract embedded in `TaskEscrowContract`
//! against the in-process executor: deployment, the full
//! accept -> result -> settle flow, the cancel and timeout flows, and the
//! unauthorized/illegal-transition rejections.

use chain_block::{BuilderData, Cell, Coins, IBitstring, MsgAddressInt, Serializable, StateInit};
use contracts::{TaskEscrowContract, TaskEscrowInit};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, Treasury};

const TOS: u64 = 1_000_000_000;
const STATUS_OPEN: i128 = 0;
const STATUS_ACCEPTED: i128 = 1;
const STATUS_RESULT_SUBMITTED: i128 = 2;
const STATUS_SETTLED: i128 = 3;
const STATUS_CANCELLED: i128 = 4;
const STATUS_EXPIRED: i128 = 5;
const STATUS_REJECTED: i128 = 6;
const STATUS_DISPUTED: i128 = 7;

struct Fixture {
    bc: Blockchain,
    creator: Treasury,
    agent: Treasury,
    verifier: Treasury,
    outsider: Treasury,
    escrow: MsgAddressInt,
    deadline: u64,
}

impl Fixture {
    fn new(budget: u64, funding: u64) -> Self {
        Self::with_assignment(budget, funding, true)
    }

    fn open(budget: u64, funding: u64) -> Self {
        Self::with_assignment(budget, funding, false)
    }

    fn with_assignment(budget: u64, funding: u64, assigned: bool) -> Self {
        Self::build(budget, funding, assigned, None, true)
    }

    fn with_attestor(budget: u64, funding: u64, attestor_pubkey: [u8; 32]) -> Self {
        Self::build(budget, funding, true, Some(attestor_pubkey), true)
    }

    fn without_verifier(budget: u64, funding: u64) -> Self {
        Self::build(budget, funding, true, None, false)
    }

    fn build(
        budget: u64,
        funding: u64,
        assigned: bool,
        attestor_pubkey: Option<[u8; 32]>,
        has_verifier: bool,
    ) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        // The sandbox config has no basechain workchain descriptor, so run
        // everything in the masterchain where outbound sends are permitted.
        bc.set_workchain(-1);
        let creator = bc.treasury("creator", 1_000 * TOS).expect("creator");
        let agent = bc.treasury("agent", 1_000 * TOS).expect("agent");
        let verifier = bc.treasury("verifier", 1_000 * TOS).expect("verifier");
        let outsider = bc.treasury("outsider", 1_000 * TOS).expect("outsider");
        let deadline = u64::from(bc.now()) + 3_600;
        let init = TaskEscrowInit {
            creator: creator.address().clone(),
            assigned_agent: assigned.then(|| agent.address().clone()),
            verifier: has_verifier.then(|| verifier.address().clone()),
            budget,
            deadline,
            review_period: 3_600,
            settlement_policy_hash: [0x11; 32],
            permission_hash: [0x22; 32],
            attestor_pubkey,
        };
        let escrow = TaskEscrowContract::calculate_address(-1, &init).expect("address");
        let state_init = TaskEscrowContract::build_state_init(&init).expect("state init");
        let deploy = MessageBuilder::internal(creator.address(), &escrow, funding)
            .bounce(false)
            .state_init(state_init)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, creator, agent, verifier, outsider, escrow, deadline }
    }

    fn send_from(&mut self, from: &MsgAddressInt, body: Cell) -> SendResult {
        // 0.1 TOS: masterchain gas is 10x basechain pricing, and the credited
        // gas limit is derived from the message value.
        self.send_from_with_value(from, body, TOS / 10)
    }

    /// Like [`Fixture::send_from`], but with an explicit message value.
    /// Attestor-signature-checking calls do the extra work of building and
    /// hashing the domain-separation cell, which needs more gas headroom
    /// than the default `TOS / 10` credits in the masterchain.
    fn send_from_with_value(&mut self, from: &MsgAddressInt, body: Cell, value: u64) -> SendResult {
        let msg = MessageBuilder::internal(from, &self.escrow, value).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    /// Sends a message with the `bounced` header flag set -- simulating an
    /// automatic network bounce rather than a genuine call -- to verify the
    /// contract ignores it instead of parsing the body as a real operation.
    fn send_bounced_from(&mut self, from: &MsgAddressInt, body: Cell) -> SendResult {
        let mut msg = MessageBuilder::internal(from, &self.escrow, TOS / 10).body(body).build();
        msg.int_header_mut().expect("internal header").bounced = true;
        self.bc.send_message(msg).expect("send")
    }

    fn status(&self) -> i128 {
        self.bc
            .run_get_method(&self.escrow, "get_task_data", vec![])
            .expect("get_task_data")
            .expect_success()
            .int_at(7)
    }

    fn review_deadline(&self) -> u64 {
        self.bc
            .run_get_method(&self.escrow, "get_task_data", vec![])
            .expect("get_task_data")
            .expect_success()
            .int_at(13) as u64
    }

    fn balance(&self, addr: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(addr)
            .and_then(|acc| acc.balance().and_then(|cc| cc.coins.as_u64()))
            .unwrap_or(0)
    }

    fn has_attestor(&self) -> bool {
        self.bc
            .run_get_method(&self.escrow, "get_task_data", vec![])
            .expect("get_task_data")
            .expect_success()
            .int_at(15)
            != 0
    }
}

/// Mirrors `TaskEscrowContract::build_data` byte-for-byte, minus the
/// client-side `review_period` floor check -- this simulates an attacker (or
/// a careless custom deploy tool) that hand-builds `StateInit` directly
/// instead of going through `tosctl`/`TaskEscrowContract::build_data`, which
/// is exactly the bypass the on-chain `err::review_period_too_short` check
/// in `claim()`/`accept()`/`result()` has to hold up against on its own.
fn build_state_init_bypassing_client_side_review_period_check(init: &TaskEscrowInit) -> StateInit {
    let agent = init.assigned_agent.as_ref().unwrap_or(&init.creator);
    let verifier = init.verifier.as_ref().unwrap_or(&init.creator);
    let mut data = BuilderData::new();
    init.creator.write_to(&mut data).unwrap();
    if init.assigned_agent.is_some() {
        data.append_bit_one().unwrap();
    } else {
        data.append_bit_zero().unwrap();
    }
    agent.write_to(&mut data).unwrap();
    if init.verifier.is_some() {
        data.append_bit_one().unwrap();
    } else {
        data.append_bit_zero().unwrap();
    }
    verifier.write_to(&mut data).unwrap();
    Coins::new(init.budget).write_to(&mut data).unwrap();
    data.append_u64(init.deadline).unwrap().append_u8(0).unwrap();
    let mut hashes = BuilderData::new();
    let mut permission = BuilderData::new();
    permission.append_u256(&init.permission_hash).unwrap().append_u256(&[0; 32]).unwrap();
    hashes
        .append_u256(&[0; 32])
        .unwrap()
        .append_u256(&[0; 32])
        .unwrap()
        .append_u256(&init.settlement_policy_hash)
        .unwrap()
        .append_u32(init.review_period)
        .unwrap()
        .append_u64(0)
        .unwrap()
        .checked_append_reference(permission.into_cell().unwrap())
        .unwrap();
    let mut attestor = BuilderData::new();
    attestor.append_bit_zero().unwrap().append_raw(&[0; 32], 256).unwrap();
    hashes.checked_append_reference(attestor.into_cell().unwrap()).unwrap();
    data.checked_append_reference(hashes.into_cell().unwrap()).unwrap();
    StateInit::with_code_and_data(TaskEscrowContract::code().unwrap(), data.into_cell().unwrap())
}

#[test]
fn claim_and_accept_reject_a_too_short_review_period_before_the_agent_does_any_work() {
    const ERR_REVIEW_PERIOD_TOO_SHORT: i32 = 132;
    let mut bc = Blockchain::new().expect("blockchain");
    bc.set_workchain(-1);
    let creator = bc.treasury("creator", 1_000 * TOS).expect("creator");
    let agent = bc.treasury("agent", 1_000 * TOS).expect("agent");
    let init = TaskEscrowInit {
        creator: creator.address().clone(),
        assigned_agent: None,
        verifier: None,
        budget: 2 * TOS,
        deadline: u64::from(bc.now()) + 3_600,
        review_period: 1, // far below the on-chain 3600s floor
        settlement_policy_hash: [0x11; 32],
        permission_hash: [0x22; 32],
        attestor_pubkey: None,
    };
    let state_init = build_state_init_bypassing_client_side_review_period_check(&init);
    let escrow_cell = state_init.write_to_new_cell().unwrap().into_cell().unwrap();
    let escrow = MsgAddressInt::with_params(-1, escrow_cell.hash(0)).expect("address");
    let deploy = MessageBuilder::internal(creator.address(), &escrow, 2 * TOS + TOS / 10)
        .bounce(false)
        .state_init(state_init)
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();

    // claim() must reject before the agent has done anything at all --
    // unlike a check only in result(), this can't be bypassed by an agent
    // that already invested effort into a task it could never get paid for.
    let agent_addr = agent.address().clone();
    let claim_msg = MessageBuilder::internal(&agent_addr, &escrow, TOS / 10)
        .body(TaskEscrowContract::claim(1).unwrap())
        .build();
    bc.send_message(claim_msg)
        .expect("claim")
        .expect_aborted()
        .expect_exit_code(ERR_REVIEW_PERIOD_TOO_SHORT);

    // accept() on a pre-assigned task must reject the same way.
    let init2 = TaskEscrowInit { assigned_agent: Some(agent_addr.clone()), ..init };
    let state_init2 = build_state_init_bypassing_client_side_review_period_check(&init2);
    let escrow_cell2 = state_init2.write_to_new_cell().unwrap().into_cell().unwrap();
    let escrow2 = MsgAddressInt::with_params(-1, escrow_cell2.hash(0)).expect("address");
    let deploy2 = MessageBuilder::internal(creator.address(), &escrow2, 2 * TOS + TOS / 10)
        .bounce(false)
        .state_init(state_init2)
        .body(Cell::default())
        .build();
    bc.send_message(deploy2).expect("deploy2").expect_success();
    let accept_msg = MessageBuilder::internal(&agent_addr, &escrow2, TOS / 10)
        .body(TaskEscrowContract::accept(1).unwrap())
        .build();
    bc.send_message(accept_msg)
        .expect("accept")
        .expect_aborted()
        .expect_exit_code(ERR_REVIEW_PERIOD_TOO_SHORT);
}

#[test]
fn open_task_claim_atomically_assigns_first_agent() {
    let mut f = Fixture::open(2 * TOS, 2 * TOS + TOS / 10);
    let agent_addr = f.agent.address().clone();

    // Open tasks cannot bypass the explicit claim transition.
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap())
        .expect_aborted()
        .expect_exit_code(101);
    assert_eq!(f.status(), STATUS_OPEN);

    let outsider_addr = f.outsider.address().clone();
    f.send_from(&outsider_addr, TaskEscrowContract::claim(2).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_ACCEPTED);

    // The accepted state prevents a competing claim, and only the winner can submit a result.
    f.send_from(&agent_addr, TaskEscrowContract::claim(3).unwrap())
        .expect_aborted()
        .expect_exit_code(115);
    f.send_from(&agent_addr, TaskEscrowContract::result(4, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(103);
    f.send_from(&outsider_addr, TaskEscrowContract::result(5, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_success();
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);
}

#[test]
fn full_happy_path_settles_exact_payout() {
    let mut f = Fixture::new(5 * TOS, 5 * TOS + TOS / 5);
    assert_eq!(f.status(), STATUS_OPEN);

    let agent_addr = f.agent.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_ACCEPTED);

    f.send_from(&agent_addr, TaskEscrowContract::result(2, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_success();
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);

    let agent_before = f.balance(&agent_addr);
    let creator_addr = f.creator.address().clone();
    let creator_before = f.balance(&creator_addr);
    f.send_from(&creator_addr, TaskEscrowContract::settle(3, 3 * TOS).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_SETTLED);

    let agent_delta = f.balance(&agent_addr) - agent_before;
    // The sandbox executor deducts the forward fee from the value even with
    // send mode +1; allow up to that fee below the exact payout.
    assert!(
        agent_delta > 3 * TOS - TOS / 100 && agent_delta <= 3 * TOS,
        "agent must receive the payout minus at most the forward fee, got {agent_delta}"
    );
    let creator_delta = f.balance(&creator_addr) - creator_before;
    assert!(
        creator_delta > 2 * TOS && creator_delta < 3 * TOS,
        "creator must receive roughly the remainder, got {creator_delta}"
    );
    assert!(f.balance(&f.escrow.clone()) < TOS / 100, "escrow must be drained");
}

#[test]
fn cancel_refunds_creator() {
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 10);
    let creator_addr = f.creator.address().clone();
    let creator_before = f.balance(&creator_addr);
    f.send_from(&creator_addr, TaskEscrowContract::cancel(1).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_CANCELLED);
    let refund = f.balance(&creator_addr) - creator_before;
    assert!(refund > 2 * TOS, "creator refund too small: {refund}");
    assert!(f.balance(&f.escrow.clone()) < TOS / 100, "escrow must be drained");
}

#[test]
fn trailing_bits_after_a_well_formed_op_are_rejected() {
    // `cancel`'s body is just op+query_id; any extra bits appended after
    // that must now be rejected by `in_msg.end_parse()` rather than
    // silently ignored (defense in depth against malformed/extended
    // messages, matching every sibling AI-actor contract's convention).
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 10);
    let creator_addr = f.creator.address().clone();
    let mut body = chain_block::BuilderData::new();
    chain_block::IBitstring::append_u32(&mut body, contracts::task_escrow::TASK_CANCEL_OPCODE)
        .unwrap();
    chain_block::IBitstring::append_u64(&mut body, 1).unwrap();
    chain_block::IBitstring::append_u32(&mut body, 0xDEAD_BEEF).unwrap();
    f.send_from(&creator_addr, body.into_cell().unwrap()).expect_aborted().expect_exit_code(9);
    assert_eq!(f.status(), STATUS_OPEN, "the malformed cancel must not have taken effect");
}

#[test]
fn a_bounced_message_is_ignored_rather_than_parsed_as_a_real_operation() {
    // If this were *not* filtered, a bounced message carrying a `cancel` body
    // sent from `creator` (the exact sender `cancel` authorizes) would cancel
    // the task -- even though no real `cancel` was ever sent. The contract
    // must ignore it and leave state untouched.
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 10);
    let creator_addr = f.creator.address().clone();
    f.send_bounced_from(&creator_addr, TaskEscrowContract::cancel(1).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_OPEN, "a bounced message must not affect contract state");
}

#[test]
fn assigned_agent_can_reject_and_refund_creator() {
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 10);
    let creator_addr = f.creator.address().clone();
    let creator_before = f.balance(&creator_addr);
    let outsider_addr = f.outsider.address().clone();
    f.send_from(&outsider_addr, TaskEscrowContract::reject(1).unwrap())
        .expect_aborted()
        .expect_exit_code(114);
    assert_eq!(f.status(), STATUS_OPEN);

    let agent_addr = f.agent.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::reject(2).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_REJECTED);
    let refund = f.balance(&creator_addr) - creator_before;
    assert!(refund > 2 * TOS, "creator refund too small: {refund}");
    assert!(f.balance(&f.escrow.clone()) < TOS / 100, "escrow must be drained");

    f.send_from(&agent_addr, TaskEscrowContract::reject(3).unwrap())
        .expect_aborted()
        .expect_exit_code(113);
}

#[test]
fn timeout_after_deadline_expires_and_refunds() {
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 10);
    let agent_addr = f.agent.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();

    // Before the deadline, timeout must be rejected (error 109).
    let outsider_addr = f.outsider.address().clone();
    f.send_from(&outsider_addr, TaskEscrowContract::timeout(2).unwrap())
        .expect_aborted()
        .expect_exit_code(109);
    assert_eq!(f.status(), STATUS_ACCEPTED);

    let deadline = f.deadline;
    f.bc.set_now((deadline + 1) as u32);
    let creator_addr = f.creator.address().clone();
    let creator_before = f.balance(&creator_addr);
    f.send_from(&outsider_addr, TaskEscrowContract::timeout(3).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_EXPIRED);
    assert!(f.balance(&creator_addr) > creator_before + 2 * TOS - TOS / 10);
}

#[test]
fn submitted_result_uses_review_deadline_for_settlement_and_timeout() {
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 10);
    let agent_addr = f.agent.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(2, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_success();
    let review_deadline = f.review_deadline();
    assert_eq!(review_deadline, u64::from(f.bc.now()) + 3_600);

    let outsider_addr = f.outsider.address().clone();
    f.send_from(&outsider_addr, TaskEscrowContract::timeout(3).unwrap())
        .expect_aborted()
        .expect_exit_code(109);

    f.bc.set_now((review_deadline + 1) as u32);
    let creator_addr = f.creator.address().clone();
    f.send_from(&creator_addr, TaskEscrowContract::settle(4, TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(118);
    f.send_from(&outsider_addr, TaskEscrowContract::timeout(5).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_EXPIRED);
}

#[test]
fn submitted_result_without_verifier_defaults_to_agent_payment_after_review() {
    let mut f = Fixture::without_verifier(2 * TOS, 2 * TOS + TOS / 5);
    let agent_addr = f.agent.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(2, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_success();

    let review_deadline = f.review_deadline();
    f.bc.set_now((review_deadline + 1) as u32);
    let agent_before = f.balance(&agent_addr);
    let outsider_addr = f.outsider.address().clone();
    f.send_from(&outsider_addr, TaskEscrowContract::timeout(3).unwrap()).expect_success();

    assert_eq!(f.status(), STATUS_SETTLED);
    let payout = f.balance(&agent_addr) - agent_before;
    assert!(payout > 2 * TOS - TOS / 10, "agent payout too small: {payout}");
    assert!(f.balance(&f.escrow.clone()) < TOS / 100, "escrow must be drained");
}

#[test]
fn creator_disputes_and_verifier_resolves() {
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 5);
    let agent_addr = f.agent.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(2, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_success();

    let outsider_addr = f.outsider.address().clone();
    f.send_from(&outsider_addr, TaskEscrowContract::dispute(3, [0xCC; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(120);
    let creator_addr = f.creator.address().clone();
    f.send_from(&creator_addr, TaskEscrowContract::dispute(4, [0xCC; 32]).unwrap())
        .expect_success();
    assert_eq!(f.status(), STATUS_DISPUTED);

    f.send_from(&creator_addr, TaskEscrowContract::settle(5, TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(104);
    f.send_from(&outsider_addr, TaskEscrowContract::timeout(6).unwrap())
        .expect_aborted()
        .expect_exit_code(110);
    f.send_from(&outsider_addr, TaskEscrowContract::resolve(7, TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(124);

    let verifier_addr = f.verifier.address().clone();
    f.send_from(&verifier_addr, TaskEscrowContract::resolve(8, 3 * TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(125);
    f.send_from(&verifier_addr, TaskEscrowContract::resolve(9, TOS).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_SETTLED);
    assert!(f.balance(&f.escrow.clone()) < TOS / 100, "escrow must be drained");
}

#[test]
fn result_submission_after_task_deadline_is_rejected() {
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 10);
    let agent_addr = f.agent.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    f.bc.set_now((f.deadline + 1) as u32);
    f.send_from(&agent_addr, TaskEscrowContract::result(2, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(117);
    assert_eq!(f.status(), STATUS_ACCEPTED);
}

#[test]
fn unauthorized_and_out_of_order_messages_are_rejected() {
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 10);
    let creator_addr = f.creator.address().clone();
    let agent_addr = f.agent.address().clone();
    let outsider_addr = f.outsider.address().clone();

    // Only the assigned agent may accept.
    f.send_from(&outsider_addr, TaskEscrowContract::accept(1).unwrap())
        .expect_aborted()
        .expect_exit_code(101);
    // Result before accept violates the state machine.
    f.send_from(&agent_addr, TaskEscrowContract::result(2, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(102);

    f.send_from(&agent_addr, TaskEscrowContract::accept(3).unwrap()).expect_success();

    // Double accept is rejected.
    f.send_from(&agent_addr, TaskEscrowContract::accept(4).unwrap())
        .expect_aborted()
        .expect_exit_code(100);
    // Cancel after accept is rejected (only open tasks can be cancelled).
    f.send_from(&creator_addr, TaskEscrowContract::cancel(5).unwrap())
        .expect_aborted()
        .expect_exit_code(107);
    // Only the agent may submit the result.
    f.send_from(&creator_addr, TaskEscrowContract::result(6, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(103);
    // Settle before a result is rejected.
    f.send_from(&creator_addr, TaskEscrowContract::settle(7, TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(104);

    f.send_from(&agent_addr, TaskEscrowContract::result(8, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_success();

    // The assigned agent may not settle.
    f.send_from(&agent_addr, TaskEscrowContract::settle(9, TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(105);
    // Payout above the budget is rejected.
    f.send_from(&creator_addr, TaskEscrowContract::settle(10, 3 * TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(106);
    // Double result is rejected.
    f.send_from(&agent_addr, TaskEscrowContract::result(11, [0xCC; 32], [0xDD; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(102);

    // The configured verifier may settle on behalf of the creator.
    let verifier_addr = f.verifier.address().clone();
    f.send_from(&verifier_addr, TaskEscrowContract::settle(12, TOS).unwrap()).expect_success();
    // Settle after settle is rejected.
    f.send_from(&creator_addr, TaskEscrowContract::settle(13, TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(104);
    assert_eq!(f.status(), STATUS_SETTLED);
}

#[test]
fn settlement_rejects_payout_above_actual_contract_balance() {
    let mut f = Fixture::new(5 * TOS, 2 * TOS);
    let agent_addr = f.agent.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(2, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_success();
    let creator_addr = f.creator.address().clone();
    f.send_from(&creator_addr, TaskEscrowContract::settle(3, 4 * TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(112);
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);
}

#[test]
fn settlement_rejects_payout_one_nanoton_above_the_exact_available_balance() {
    // Budget (5 TOS) intentionally exceeds funding (2 TOS), so the actual
    // contract balance -- not the budget -- is the binding constraint here.
    // `send_from` always attaches TOS/10 as the message's own value, which
    // is credited to the contract's balance before `get_balance()` runs
    // inside the transaction, so the balance settle actually checks against
    // is the pre-message balance plus that credit. This tightens
    // `settlement_rejects_payout_above_actual_contract_balance` (which uses
    // a payout far above the balance) down to the exact off-by-one boundary.
    let mut f = Fixture::new(5 * TOS, 2 * TOS);
    let agent_addr = f.agent.address().clone();
    let creator_addr = f.creator.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(2, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_success();
    let available_at_settle = f.balance(&f.escrow.clone()) + TOS / 10;
    f.send_from(&creator_addr, TaskEscrowContract::settle(3, available_at_settle + 1).unwrap())
        .expect_aborted()
        .expect_exit_code(112);
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);
}

#[test]
fn settle_on_an_attestor_configured_task_requires_a_valid_signature() {
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let result_hash = [0xAA; 32];
    let mut f = Fixture::with_attestor(2 * TOS, 2 * TOS + TOS / 5, attestor_pubkey);
    let agent_addr = f.agent.address().clone();
    let creator_addr = f.creator.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(2, result_hash, [0xBB; 32]).unwrap())
        .expect_success();

    // Plain `settle` (no signature at all) is rejected: the message body ends
    // early and the contract's load of the trailing 512-bit signature fails.
    f.send_from(&creator_addr, TaskEscrowContract::settle(3, TOS).unwrap()).expect_aborted();
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);

    let domain_hash = contracts::settle_domain_hash(&f.escrow, &result_hash, TOS).unwrap();

    // A signature from the wrong key is rejected. (Domain-bound hashing and
    // signature verification both run before the signature is judged
    // invalid, so this needs the higher attestation gas credit too.)
    let wrong_key = SigningKey::from_bytes(&[0x88; 32]);
    let wrong_signature: [u8; 64] = wrong_key.sign(&domain_hash).to_bytes();
    f.send_from_with_value(
        &creator_addr,
        TaskEscrowContract::settle_signed(4, TOS, &wrong_signature).unwrap(),
        TOS / 4,
    )
    .expect_aborted()
    .expect_exit_code(127);
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);

    // A signature over a hash other than the domain-bound result_hash is rejected.
    let tampered_signature: [u8; 64] = attestor.sign(&[0xCC; 32]).to_bytes();
    f.send_from_with_value(
        &creator_addr,
        TaskEscrowContract::settle_signed(5, TOS, &tampered_signature).unwrap(),
        TOS / 4,
    )
    .expect_aborted()
    .expect_exit_code(127);
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);

    // The correct attestor signature over the domain-bound hash settles the
    // task. Sender authorization (creator/verifier) is still independently
    // enforced.
    let outsider_addr = f.outsider.address().clone();
    let valid_signature: [u8; 64] = attestor.sign(&domain_hash).to_bytes();
    f.send_from_with_value(
        &outsider_addr,
        TaskEscrowContract::settle_signed(6, TOS, &valid_signature).unwrap(),
        TOS / 4,
    )
    .expect_aborted()
    .expect_exit_code(105);
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);

    f.send_from_with_value(
        &creator_addr,
        TaskEscrowContract::settle_signed(7, TOS, &valid_signature).unwrap(),
        TOS / 4,
    )
    .expect_success();
    assert_eq!(f.status(), STATUS_SETTLED);
}

#[test]
fn settle_signature_is_bound_to_the_exact_payout_amount() {
    // The attestor signs (result_hash, payout) together, not result_hash
    // alone -- a signature the attestor produced for one payout must not
    // authorize settling with a *different* payout, even though the sender
    // (creator) and result_hash are unchanged. Before this domain included
    // payout, a single attestor signature over a result could be replayed
    // with any payout up to the task's budget.
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let result_hash = [0xAA; 32];
    let mut f = Fixture::with_attestor(2 * TOS, 2 * TOS + TOS / 5, attestor_pubkey);
    let agent_addr = f.agent.address().clone();
    let creator_addr = f.creator.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(2, result_hash, [0xBB; 32]).unwrap())
        .expect_success();

    // The attestor signs off on a payout of TOS / 2.
    let approved_payout_domain_hash =
        contracts::settle_domain_hash(&f.escrow, &result_hash, TOS / 2).unwrap();
    let signature: [u8; 64] = attestor.sign(&approved_payout_domain_hash).to_bytes();

    // Settling with a larger payout, reusing that same signature, is rejected:
    // the signature does not cover this domain hash (it covers the TOS / 2
    // one).
    f.send_from_with_value(
        &creator_addr,
        TaskEscrowContract::settle_signed(3, TOS, &signature).unwrap(),
        TOS / 4,
    )
    .expect_aborted()
    .expect_exit_code(127);
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);

    // Settling with the exact payout the attestor signed succeeds.
    f.send_from_with_value(
        &creator_addr,
        TaskEscrowContract::settle_signed(4, TOS / 2, &signature).unwrap(),
        TOS / 4,
    )
    .expect_success();
    assert_eq!(f.status(), STATUS_SETTLED);
}

#[test]
fn resolve_on_an_attestor_configured_task_requires_a_valid_signature() {
    // resolve() is a separate payout-authorizing path from settle() (reached
    // via dispute -> resolve) and must enforce the same attestor requirement
    // -- otherwise a creator + verifier could bypass a configured attestor
    // entirely by disputing and resolving instead of settling.
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let result_hash = [0xAA; 32];
    let dispute_hash = [0xCC; 32];
    let mut f = Fixture::with_attestor(2 * TOS, 2 * TOS + TOS / 5, attestor_pubkey);
    let agent_addr = f.agent.address().clone();
    let creator_addr = f.creator.address().clone();
    let verifier_addr = f.verifier.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(2, result_hash, [0xBB; 32]).unwrap())
        .expect_success();
    f.send_from(&creator_addr, TaskEscrowContract::dispute(3, dispute_hash).unwrap())
        .expect_success();
    assert_eq!(f.status(), STATUS_DISPUTED);

    // Plain `resolve` (no signature at all) is rejected: the message body
    // ends early and the contract's load of the trailing 512-bit signature
    // fails.
    f.send_from(&verifier_addr, TaskEscrowContract::resolve(4, TOS).unwrap()).expect_aborted();
    assert_eq!(f.status(), STATUS_DISPUTED);

    let domain_hash =
        contracts::resolve_domain_hash(&f.escrow, &result_hash, &dispute_hash, TOS).unwrap();

    // A signature from the wrong key is rejected.
    let wrong_key = SigningKey::from_bytes(&[0x88; 32]);
    let wrong_signature: [u8; 64] = wrong_key.sign(&domain_hash).to_bytes();
    f.send_from_with_value(
        &verifier_addr,
        TaskEscrowContract::resolve_signed(5, TOS, &wrong_signature).unwrap(),
        TOS / 4,
    )
    .expect_aborted()
    .expect_exit_code(131);
    assert_eq!(f.status(), STATUS_DISPUTED);

    // A signature over the settle-style domain (result_hash + payout, no
    // dispute_hash) is rejected: resolve's domain also binds dispute_hash.
    let settle_style_hash = contracts::settle_domain_hash(&f.escrow, &result_hash, TOS).unwrap();
    let mismatched_domain_signature: [u8; 64] = attestor.sign(&settle_style_hash).to_bytes();
    f.send_from_with_value(
        &verifier_addr,
        TaskEscrowContract::resolve_signed(6, TOS, &mismatched_domain_signature).unwrap(),
        TOS / 4,
    )
    .expect_aborted()
    .expect_exit_code(131);
    assert_eq!(f.status(), STATUS_DISPUTED);

    // The correct attestor signature over the resolve domain hash settles
    // the dispute. Sender authorization (verifier-only) is still
    // independently enforced.
    let outsider_addr = f.outsider.address().clone();
    let valid_signature: [u8; 64] = attestor.sign(&domain_hash).to_bytes();
    f.send_from_with_value(
        &outsider_addr,
        TaskEscrowContract::resolve_signed(7, TOS, &valid_signature).unwrap(),
        TOS / 4,
    )
    .expect_aborted()
    .expect_exit_code(124);
    assert_eq!(f.status(), STATUS_DISPUTED);

    f.send_from_with_value(
        &verifier_addr,
        TaskEscrowContract::resolve_signed(8, TOS, &valid_signature).unwrap(),
        TOS / 4,
    )
    .expect_success();
    assert_eq!(f.status(), STATUS_SETTLED);
}

#[test]
fn creator_can_rotate_and_revoke_the_attestor_key_others_rejected() {
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let result_hash = [0xAA; 32];
    // Deployed with no attestor at all -- settle should work unattested until
    // the creator opts in via rotate_attestor_key. Rotate/revoke both happen
    // while the task is still open: they are frozen from accepted onward
    // (see attestor_rotate_and_revoke_are_frozen_once_the_agent_has_accepted),
    // so exercising creator-only-ness here has to happen before accept.
    let mut f = Fixture::open(2 * TOS, 2 * TOS + TOS / 5);
    let creator_addr = f.creator.address().clone();
    let agent_addr = f.agent.address().clone();
    let outsider_addr = f.outsider.address().clone();
    assert!(!f.has_attestor());

    // Non-creator rotate is rejected; attestor state is unaffected.
    f.send_from(
        &outsider_addr,
        TaskEscrowContract::rotate_attestor_key(1, attestor_pubkey).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(128);
    assert!(!f.has_attestor());

    // Creator rotates in an attestor key: settle now requires a signature.
    f.send_from(
        &creator_addr,
        TaskEscrowContract::rotate_attestor_key(2, attestor_pubkey).unwrap(),
    )
    .expect_success();
    assert!(f.has_attestor());

    f.send_from(&agent_addr, TaskEscrowContract::claim(3).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(4, result_hash, [0xBB; 32]).unwrap())
        .expect_success();
    f.send_from(&creator_addr, TaskEscrowContract::settle(5, TOS).unwrap()).expect_aborted();
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);

    // Non-creator revoke is rejected; attestor requirement still in force.
    // (revoke_attestor is frozen from accepted onward too, but the sender
    // check runs first, so a non-creator sender still fails on error 129
    // regardless of status -- covered again, precisely, by the freeze test.)
    f.send_from(&outsider_addr, TaskEscrowContract::revoke_attestor(6).unwrap())
        .expect_aborted()
        .expect_exit_code(129);
    assert!(f.has_attestor());

    // Creator settles with a valid attestor signature, reaching the terminal
    // settled state -- where rotate/revoke are unfrozen again.
    let domain_hash = contracts::settle_domain_hash(&f.escrow, &result_hash, TOS).unwrap();
    let signature: [u8; 64] = attestor.sign(&domain_hash).to_bytes();
    f.send_from_with_value(
        &creator_addr,
        TaskEscrowContract::settle_signed(7, TOS, &signature).unwrap(),
        TOS / 4,
    )
    .expect_success();
    assert_eq!(f.status(), STATUS_SETTLED);

    // Creator revokes post-settlement: allowed once more now that the task
    // reached a terminal status, and has no further effect on the outcome.
    f.send_from(&creator_addr, TaskEscrowContract::revoke_attestor(8).unwrap()).expect_success();
    assert!(!f.has_attestor());
}

#[test]
fn attestor_rotate_and_revoke_are_frozen_once_the_agent_has_accepted() {
    // Once an agent has accepted a task advertising an attestor, the creator
    // must not be able to unilaterally rotate in a key they control (or
    // revoke the requirement entirely) right before settle/resolve -- that
    // would let them forge the independent verification the agent relied on
    // when it accepted. rotate_attestor_key/revoke_attestor are frozen for
    // accepted, result_submitted and disputed; allowed at open and at every
    // terminal status.
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let other_pubkey = SigningKey::from_bytes(&[0x99; 32]).verifying_key().to_bytes();
    let mut f = Fixture::with_attestor(2 * TOS, 2 * TOS + TOS / 5, attestor_pubkey);
    let creator_addr = f.creator.address().clone();
    let agent_addr = f.agent.address().clone();
    let outsider_addr = f.outsider.address().clone();

    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_ACCEPTED);
    f.send_from(&creator_addr, TaskEscrowContract::rotate_attestor_key(2, other_pubkey).unwrap())
        .expect_aborted()
        .expect_exit_code(130);
    f.send_from(&creator_addr, TaskEscrowContract::revoke_attestor(3).unwrap())
        .expect_aborted()
        .expect_exit_code(130);
    assert!(f.has_attestor());

    f.send_from(&agent_addr, TaskEscrowContract::result(4, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_success();
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);
    f.send_from(&creator_addr, TaskEscrowContract::rotate_attestor_key(5, other_pubkey).unwrap())
        .expect_aborted()
        .expect_exit_code(130);
    f.send_from(&creator_addr, TaskEscrowContract::revoke_attestor(6).unwrap())
        .expect_aborted()
        .expect_exit_code(130);
    assert!(f.has_attestor());

    f.send_from(&creator_addr, TaskEscrowContract::dispute(7, [0xCC; 32]).unwrap())
        .expect_success();
    assert_eq!(f.status(), STATUS_DISPUTED);
    f.send_from(&creator_addr, TaskEscrowContract::rotate_attestor_key(8, other_pubkey).unwrap())
        .expect_aborted()
        .expect_exit_code(130);
    f.send_from(&creator_addr, TaskEscrowContract::revoke_attestor(9).unwrap())
        .expect_aborted()
        .expect_exit_code(130);
    assert!(f.has_attestor());

    // A non-creator sender is still rejected on the sender check (128/129),
    // not the freeze check -- the freeze does not relax authorization.
    f.send_from(&outsider_addr, TaskEscrowContract::rotate_attestor_key(10, other_pubkey).unwrap())
        .expect_aborted()
        .expect_exit_code(128);
    f.send_from(&outsider_addr, TaskEscrowContract::revoke_attestor(11).unwrap())
        .expect_aborted()
        .expect_exit_code(129);

    // The verifier resolves the dispute, reaching the terminal settled
    // status -- rotate/revoke are unfrozen again.
    let verifier_addr = f.verifier.address().clone();
    let domain_hash =
        contracts::resolve_domain_hash(&f.escrow, &[0xAA; 32], &[0xCC; 32], TOS).unwrap();
    let signature: [u8; 64] = attestor.sign(&domain_hash).to_bytes();
    f.send_from_with_value(
        &verifier_addr,
        TaskEscrowContract::resolve_signed(12, TOS, &signature).unwrap(),
        TOS / 4,
    )
    .expect_success();
    assert_eq!(f.status(), STATUS_SETTLED);
    f.send_from(&creator_addr, TaskEscrowContract::revoke_attestor(13).unwrap()).expect_success();
    assert!(!f.has_attestor());
}

#[test]
fn configured_attestor_is_immutable_even_while_task_is_open() {
    let old_attestor = SigningKey::from_bytes(&[0x11; 32]);
    let old_pubkey = old_attestor.verifying_key().to_bytes();
    let new_pubkey = SigningKey::from_bytes(&[0x22; 32]).verifying_key().to_bytes();
    let result_hash = [0xAA; 32];

    let mut f = Fixture::with_attestor(2 * TOS, 2 * TOS + TOS / 5, old_pubkey);
    let creator_addr = f.creator.address().clone();
    let agent_addr = f.agent.address().clone();

    // Rotation is already frozen while open. Otherwise the creator can race
    // an accept message after the agent inspected the advertised key.
    f.send_from(&creator_addr, TaskEscrowContract::rotate_attestor_key(1, new_pubkey).unwrap())
        .expect_aborted()
        .expect_exit_code(130);

    f.send_from(&agent_addr, TaskEscrowContract::accept(2).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(3, result_hash, [0xBB; 32]).unwrap())
        .expect_success();

    let domain_hash = contracts::settle_domain_hash(&f.escrow, &result_hash, TOS).unwrap();

    // The deployment key remains authoritative.
    let old_signature: [u8; 64] = old_attestor.sign(&domain_hash).to_bytes();
    f.send_from_with_value(
        &creator_addr,
        TaskEscrowContract::settle_signed(4, TOS, &old_signature).unwrap(),
        TOS / 4,
    )
    .expect_success();
    assert_eq!(f.status(), STATUS_SETTLED);
}

#[test]
fn result_and_settle_deadlines_are_inclusive_boundaries() {
    // now() <= deadline (result) and now() <= review_deadline (settle) both
    // allow the exact boundary second, not just strictly-before.
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 5);
    let agent_addr = f.agent.address().clone();
    let creator_addr = f.creator.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();

    f.bc.set_now(f.deadline as u32);
    f.send_from(&agent_addr, TaskEscrowContract::result(2, [0xAA; 32], [0xBB; 32]).unwrap())
        .expect_success();
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);

    let review_deadline = f.review_deadline();
    f.bc.set_now(review_deadline as u32);
    f.send_from(&creator_addr, TaskEscrowContract::settle(3, TOS).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_SETTLED);
}

#[test]
fn timeout_deadlines_are_inclusive_boundaries() {
    // deadline <= now() (open/accepted) and review_deadline <= now()
    // (result_submitted) both allow the exact boundary second.
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 10);
    let agent_addr = f.agent.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    let deadline = f.deadline;
    f.bc.set_now(deadline as u32);
    let outsider_addr = f.outsider.address().clone();
    f.send_from(&outsider_addr, TaskEscrowContract::timeout(2).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_EXPIRED);
}

#[test]
fn attestation_signature_is_bound_to_the_contract_address_and_rejected_across_tasks() {
    // The signed message is domain_bound_hash(contract_address, result_hash),
    // not the bare result_hash -- so a signature minted for one Task Escrow
    // instance is *not* accepted by a second, independent instance that
    // happens to share the same attestor_pubkey and the same result_hash
    // (e.g. copied from public on-chain data). This closes the replay gap
    // that a bare-hash signature would otherwise have.
    let attestor = SigningKey::from_bytes(&[0x33; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let shared_result_hash = [0xEE; 32];

    let mut task_a = Fixture::with_attestor(TOS, TOS + TOS / 5, attestor_pubkey);
    let agent_a = task_a.agent.address().clone();
    let creator_a = task_a.creator.address().clone();
    task_a.send_from(&agent_a, TaskEscrowContract::accept(1).unwrap()).expect_success();
    task_a
        .send_from(&agent_a, TaskEscrowContract::result(2, shared_result_hash, [0; 32]).unwrap())
        .expect_success();
    let domain_hash_a =
        contracts::settle_domain_hash(&task_a.escrow, &shared_result_hash, TOS / 2).unwrap();
    let signature: [u8; 64] = attestor.sign(&domain_hash_a).to_bytes();
    task_a
        .send_from_with_value(
            &creator_a,
            TaskEscrowContract::settle_signed(3, TOS / 2, &signature).unwrap(),
            TOS / 4,
        )
        .expect_success();
    assert_eq!(task_a.status(), STATUS_SETTLED);

    // A second, entirely independent task -- different budget (and so a
    // different calculated contract address; the Fixture's fixed treasury
    // names would otherwise make two same-shaped deploys collide) -- deployed
    // with the same attestor key and, here, the same result hash. The
    // signature minted for task_a's settlement is replayed as-is and must be
    // rejected: it was signed over task_a's address, not task_b's.
    let mut task_b = Fixture::with_attestor(2 * TOS, 2 * TOS + TOS / 5, attestor_pubkey);
    let agent_b = task_b.agent.address().clone();
    let creator_b = task_b.creator.address().clone();
    assert_ne!(task_a.escrow, task_b.escrow, "fixtures must deploy to different addresses");
    task_b.send_from(&agent_b, TaskEscrowContract::accept(1).unwrap()).expect_success();
    task_b
        .send_from(&agent_b, TaskEscrowContract::result(2, shared_result_hash, [0; 32]).unwrap())
        .expect_success();
    task_b
        .send_from_with_value(
            &creator_b,
            TaskEscrowContract::settle_signed(3, TOS / 2, &signature).unwrap(),
            TOS / 4,
        )
        .expect_aborted()
        .expect_exit_code(127);
    assert_eq!(
        task_b.status(),
        STATUS_RESULT_SUBMITTED,
        "a signature bound to task_a's address must not settle task_b"
    );

    // A correctly re-signed (domain-bound to task_b) signature still works.
    let domain_hash_b =
        contracts::settle_domain_hash(&task_b.escrow, &shared_result_hash, TOS / 2).unwrap();
    let signature_b: [u8; 64] = attestor.sign(&domain_hash_b).to_bytes();
    task_b
        .send_from_with_value(
            &creator_b,
            TaskEscrowContract::settle_signed(4, TOS / 2, &signature_b).unwrap(),
            TOS / 4,
        )
        .expect_success();
    assert_eq!(task_b.status(), STATUS_SETTLED);
}
