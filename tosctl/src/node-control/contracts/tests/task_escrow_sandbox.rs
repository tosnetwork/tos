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

use chain_block::{Cell, MsgAddressInt};
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
        Self::build(budget, funding, assigned, None)
    }

    fn with_attestor(budget: u64, funding: u64, attestor_pubkey: [u8; 32]) -> Self {
        Self::build(budget, funding, true, Some(attestor_pubkey))
    }

    fn build(
        budget: u64,
        funding: u64,
        assigned: bool,
        attestor_pubkey: Option<[u8; 32]>,
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
            verifier: Some(verifier.address().clone()),
            budget,
            deadline,
            review_period: 600,
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
    assert_eq!(review_deadline, u64::from(f.bc.now()) + 600);

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
    f.send_from(&verifier_addr, TaskEscrowContract::resolve(9, TOS).unwrap())
        .expect_success();
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

    let domain_hash = contracts::domain_bound_hash(&f.escrow, &result_hash).unwrap();

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
fn creator_can_rotate_and_revoke_the_attestor_key_others_rejected() {
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let result_hash = [0xAA; 32];
    // Deployed with no attestor at all -- settle should work unattested until
    // the creator opts in via rotate_attestor_key.
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 5);
    let creator_addr = f.creator.address().clone();
    let agent_addr = f.agent.address().clone();
    let outsider_addr = f.outsider.address().clone();
    assert!(!f.has_attestor());

    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(2, result_hash, [0xBB; 32]).unwrap())
        .expect_success();

    // Non-creator rotate is rejected; attestor state is unaffected.
    f.send_from(
        &outsider_addr,
        TaskEscrowContract::rotate_attestor_key(3, attestor_pubkey).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(128);
    assert!(!f.has_attestor());

    // Creator rotates in an attestor key: settle now requires a signature.
    f.send_from(&creator_addr, TaskEscrowContract::rotate_attestor_key(4, attestor_pubkey).unwrap())
        .expect_success();
    assert!(f.has_attestor());

    f.send_from(&creator_addr, TaskEscrowContract::settle(5, TOS).unwrap()).expect_aborted();
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);

    // Non-creator revoke is rejected; attestor requirement still in force.
    f.send_from(&outsider_addr, TaskEscrowContract::revoke_attestor(6).unwrap())
        .expect_aborted()
        .expect_exit_code(129);
    assert!(f.has_attestor());

    // Creator revokes: settle works again without any signature.
    f.send_from(&creator_addr, TaskEscrowContract::revoke_attestor(7).unwrap()).expect_success();
    assert!(!f.has_attestor());

    f.send_from(&creator_addr, TaskEscrowContract::settle(8, TOS).unwrap()).expect_success();
    assert_eq!(f.status(), STATUS_SETTLED);
}

#[test]
fn rotating_the_attestor_key_invalidates_signatures_from_the_old_key() {
    let old_attestor = SigningKey::from_bytes(&[0x11; 32]);
    let old_pubkey = old_attestor.verifying_key().to_bytes();
    let new_attestor = SigningKey::from_bytes(&[0x22; 32]);
    let new_pubkey = new_attestor.verifying_key().to_bytes();
    let result_hash = [0xAA; 32];

    let mut f = Fixture::with_attestor(2 * TOS, 2 * TOS + TOS / 5, old_pubkey);
    let creator_addr = f.creator.address().clone();
    let agent_addr = f.agent.address().clone();
    f.send_from(&agent_addr, TaskEscrowContract::accept(1).unwrap()).expect_success();
    f.send_from(&agent_addr, TaskEscrowContract::result(2, result_hash, [0xBB; 32]).unwrap())
        .expect_success();

    let domain_hash = contracts::domain_bound_hash(&f.escrow, &result_hash).unwrap();

    // A signature from the currently-configured old key is valid...
    let old_signature: [u8; 64] = old_attestor.sign(&domain_hash).to_bytes();

    // ...until the creator rotates to a new key.
    f.send_from(&creator_addr, TaskEscrowContract::rotate_attestor_key(3, new_pubkey).unwrap())
        .expect_success();

    // The old signature, still cryptographically valid under the old key, is
    // now rejected: settle checks against whichever key is configured *now*.
    f.send_from_with_value(
        &creator_addr,
        TaskEscrowContract::settle_signed(4, TOS, &old_signature).unwrap(),
        TOS / 4,
    )
    .expect_aborted()
    .expect_exit_code(127);
    assert_eq!(f.status(), STATUS_RESULT_SUBMITTED);

    // Only a fresh signature from the new key settles the task.
    let new_signature: [u8; 64] = new_attestor.sign(&domain_hash).to_bytes();
    f.send_from_with_value(
        &creator_addr,
        TaskEscrowContract::settle_signed(5, TOS, &new_signature).unwrap(),
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
    let domain_hash_a = contracts::domain_bound_hash(&task_a.escrow, &shared_result_hash).unwrap();
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
    let domain_hash_b = contracts::domain_bound_hash(&task_b.escrow, &shared_result_hash).unwrap();
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
