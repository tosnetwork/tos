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

use contracts::{TaskEscrowContract, TaskEscrowInit};
use chain_block::{Cell, MsgAddressInt};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, Treasury};

const TOS: u64 = 1_000_000_000;
const STATUS_OPEN: i128 = 0;
const STATUS_ACCEPTED: i128 = 1;
const STATUS_RESULT_SUBMITTED: i128 = 2;
const STATUS_SETTLED: i128 = 3;
const STATUS_CANCELLED: i128 = 4;
const STATUS_EXPIRED: i128 = 5;

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
            assigned_agent: Some(agent.address().clone()),
            verifier: Some(verifier.address().clone()),
            budget,
            deadline,
            settlement_policy_hash: [0x11; 32],
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
        let msg = MessageBuilder::internal(from, &self.escrow, TOS / 10).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    fn status(&self) -> i128 {
        self.bc
            .run_get_method(&self.escrow, "get_task_data", vec![])
            .expect("get_task_data")
            .expect_success()
            .int_at(7)
    }

    fn balance(&self, addr: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(addr)
            .and_then(|acc| acc.balance().and_then(|cc| cc.coins.as_u64()))
            .unwrap_or(0)
    }
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
    f.send_from(&creator_addr, TaskEscrowContract::settle(3, 3 * TOS).unwrap())
        .expect_success();
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
