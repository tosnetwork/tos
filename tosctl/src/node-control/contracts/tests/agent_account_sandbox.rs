/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use chain_block::{Cell, MsgAddressInt, SliceData, ed25519_create_private_key};
use contracts::{
    AgentAccountContract, AgentAccountInit, AgentAccountPolicyUpdate, TaskEscrowContract,
    TaskEscrowInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, SandboxResult, SendResult, Treasury};

const TOS: u64 = 1_000_000_000;

struct Fixture {
    bc: Blockchain,
    account: MsgAddressInt,
    owner: Treasury,
    outsider: Treasury,
    target: Treasury,
    controller_secret: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        Self::with_controller([0x42; 32])
    }

    fn with_controller(controller_secret: [u8; 32]) -> Self {
        Self::with_controller_and_limit(controller_secret, 5 * TOS)
    }

    /// `max_per_tx` also acts as a deploy-data salt: two fixtures that would
    /// otherwise be identical (same controller key, same treasury names --
    /// deterministic across independent `Blockchain` instances) must use
    /// different values here to actually deploy to different addresses,
    /// which the cross-account replay test below depends on.
    fn with_controller_and_limit(controller_secret: [u8; 32], max_per_tx: u64) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let owner = bc.treasury("owner", 1_000 * TOS).expect("owner");
        let outsider = bc.treasury("outsider", 1_000 * TOS).expect("outsider");
        let target = bc.treasury("target", 1_000 * TOS).expect("target");
        let controller = ed25519_create_private_key(&controller_secret).expect("controller key");
        let init = AgentAccountInit {
            owner: owner.address().clone(),
            controller_pubkey: controller.verifying_key(),
            max_per_tx,
            daily_limit: max_per_tx + TOS,
            default_task_timeout_secs: 3_600,
            metadata_hash: None,
            service_endpoint_hash: None,
        };
        let account = AgentAccountContract::calculate_address(-1, &init).expect("address");
        let deploy = MessageBuilder::internal(owner.address(), &account, 20 * TOS)
            .bounce(false)
            .state_init(AgentAccountContract::build_state_init(&init).expect("state init"))
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, account, owner, outsider, target, controller_secret }
    }

    fn send_internal(&mut self, from: &MsgAddressInt, body: Cell) -> SendResult {
        let msg = MessageBuilder::internal(from, &self.account, TOS / 10).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    /// Sends a message with the `bounced` header flag set -- simulating an
    /// automatic network bounce rather than a genuine call -- to verify the
    /// contract ignores it instead of parsing the body as a real operation.
    fn send_bounced_internal(&mut self, from: &MsgAddressInt, body: Cell) -> SendResult {
        let mut msg = MessageBuilder::internal(from, &self.account, TOS / 10).body(body).build();
        msg.int_header_mut().expect("internal header").bounced = true;
        self.bc.send_message(msg).expect("send")
    }

    fn signed_action(&self, secret: &[u8; 32], seqno: u32, valid_until: u32, value: u64) -> Cell {
        self.signed_action_to(
            secret,
            seqno,
            valid_until,
            self.target.address(),
            value,
            Cell::default(),
        )
    }

    fn signed_action_to(
        &self,
        secret: &[u8; 32],
        seqno: u32,
        valid_until: u32,
        target: &MsgAddressInt,
        value: u64,
        body: Cell,
    ) -> Cell {
        let payload =
            AgentAccountContract::build_task_send_payload(seqno, valid_until, target, value, body)
                .expect("payload");
        let hash_to_sign =
            AgentAccountContract::task_send_hash_to_sign(&self.account, &payload).expect("hash");
        let key = ed25519_create_private_key(secret).expect("signing key");
        let signature = key.sign(&hash_to_sign);
        AgentAccountContract::build_signed_task_send_message(payload, &signature)
            .expect("signed body")
    }

    fn send_external(&mut self, body: Cell) -> SandboxResult<SendResult> {
        let body = SliceData::load_cell(body).expect("body slice");
        let message = MessageBuilder::external(&self.account).body_slice(body).build();
        self.bc.send_message(message)
    }

    fn expect_external_exit(&mut self, body: Cell, exit_code: i32) {
        let error = match self.send_external(body) {
            Ok(_) => panic!("external message must fail"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(&format!("exit code: {exit_code}")),
            "expected exit code {exit_code}, got {error}"
        );
    }

    fn seqno(&self) -> i128 {
        self.bc
            .run_get_method(&self.account, "get_agent_account_data", vec![])
            .expect("get data")
            .expect_success()
            .int_at(7)
    }

    fn policy(&self) -> (u64, u64) {
        let binding = self
            .bc
            .run_get_method(&self.account, "get_agent_policy", vec![])
            .expect("get_agent_policy");
        let stack = binding.expect_success();
        (stack.int_at(0) as u64, stack.int_at(1) as u64)
    }
}

#[test]
fn controller_signed_action_transfers_value_and_advances_seqno() {
    let mut fixture = Fixture::new();
    let before = fixture
        .bc
        .get_account(fixture.target.address())
        .and_then(|account| account.balance().and_then(|balance| balance.coins.as_u64()))
        .unwrap();
    let body = fixture.signed_action(&fixture.controller_secret, 0, fixture.bc.now() + 300, TOS);
    fixture.send_external(body).expect("external message").expect_success();

    assert_eq!(fixture.seqno(), 1);
    let after = fixture
        .bc
        .get_account(fixture.target.address())
        .and_then(|account| account.balance().and_then(|balance| balance.coins.as_u64()))
        .unwrap();
    assert!(after > before + TOS - TOS / 100);
}

#[test]
fn controller_action_rejects_invalid_signature_expiry_replay_and_policy_overflow() {
    let mut fixture = Fixture::new();
    let valid_until = fixture.bc.now() + 300;

    let bad_signature = fixture.signed_action(&[0x24; 32], 0, valid_until, TOS);
    fixture.expect_external_exit(bad_signature, 1704);

    let expired = fixture.signed_action(&fixture.controller_secret, 0, fixture.bc.now(), TOS);
    fixture.expect_external_exit(expired, 1706);

    let oversized = fixture.signed_action(&fixture.controller_secret, 0, valid_until, 6 * TOS);
    fixture.expect_external_exit(oversized, 1707);

    let valid = fixture.signed_action(&fixture.controller_secret, 0, valid_until, TOS);
    fixture.send_external(valid.clone()).expect("valid message").expect_success();
    fixture.expect_external_exit(valid, 1705);
    assert_eq!(fixture.seqno(), 1);
}

#[test]
fn controller_action_enforces_and_resets_daily_limit() {
    let mut fixture = Fixture::new();
    let valid_until = fixture.bc.now() + 86_700;
    let first = fixture.signed_action(&fixture.controller_secret, 0, valid_until, 4 * TOS);
    fixture.send_external(first).expect("first action").expect_success();

    let over_daily = fixture.signed_action(&fixture.controller_secret, 1, valid_until, 3 * TOS);
    fixture.expect_external_exit(over_daily, 1707);

    fixture.bc.set_now(fixture.bc.now() + 86_400);
    let next_day = fixture.signed_action(&fixture.controller_secret, 1, valid_until, 3 * TOS);
    fixture.send_external(next_day).expect("next-day action").expect_success();
    assert_eq!(fixture.seqno(), 2);
}

#[test]
fn controller_action_accepts_assigned_task_escrow() {
    let mut fixture = Fixture::new();
    let creator = fixture.bc.treasury("task-creator", 100 * TOS).expect("creator");
    let init = TaskEscrowInit {
        creator: creator.address().clone(),
        assigned_agent: Some(fixture.account.clone()),
        verifier: None,
        budget: 2 * TOS,
        deadline: u64::from(fixture.bc.now()) + 3_600,
        review_period: 3_600,
        settlement_policy_hash: [0x11; 32],
        permission_hash: [0x22; 32],
        attestor_pubkey: None,
    };
    let escrow = TaskEscrowContract::calculate_address(-1, &init).expect("escrow address");
    let deploy = MessageBuilder::internal(creator.address(), &escrow, 3 * TOS)
        .bounce(false)
        .state_init(TaskEscrowContract::build_state_init(&init).expect("escrow state"))
        .body(Cell::default())
        .build();
    fixture.bc.send_message(deploy).expect("deploy escrow").expect_success();

    let action = fixture.signed_action_to(
        &fixture.controller_secret,
        0,
        fixture.bc.now() + 300,
        &escrow,
        TOS / 10,
        TaskEscrowContract::accept(1).expect("accept body"),
    );
    fixture.send_external(action).expect("controller action").expect_success();
    let status = fixture
        .bc
        .run_get_method(&escrow, "get_task_data", vec![])
        .expect("task data")
        .expect_success()
        .int_at(7);
    assert_eq!(status, 1);
}

#[test]
fn a_bounced_message_is_ignored_rather_than_parsed_as_a_real_operation() {
    // If this were *not* filtered, a bounced message carrying an
    // update_policy body sent from `owner` (the exact sender update_policy
    // authorizes) would change the policy -- even though no real
    // update_policy was ever sent. The contract must ignore it and leave
    // state untouched.
    let mut fixture = Fixture::new();
    let owner_addr = fixture.owner.address().clone();
    let policy = AgentAccountPolicyUpdate {
        max_per_tx: 2 * TOS,
        daily_limit: 3 * TOS,
        default_task_timeout_secs: 7_200,
        metadata_hash: None,
        service_endpoint_hash: None,
    };
    let update_body = AgentAccountContract::build_update_policy_message(1, &policy).unwrap();
    fixture.send_bounced_internal(&owner_addr, update_body).expect_success();
    assert_eq!(
        fixture.policy(),
        (5 * TOS, 6 * TOS),
        "a bounced message must not affect contract state"
    );
}

#[test]
fn owner_can_update_policy_and_rotate_controller_others_rejected() {
    let mut fixture = Fixture::new();
    let owner_addr = fixture.owner.address().clone();
    let outsider_addr = fixture.outsider.address().clone();

    // Non-owner cannot update policy.
    let policy = AgentAccountPolicyUpdate {
        max_per_tx: 2 * TOS,
        daily_limit: 3 * TOS,
        default_task_timeout_secs: 7_200,
        metadata_hash: None,
        service_endpoint_hash: None,
    };
    let update_body = AgentAccountContract::build_update_policy_message(1, &policy).unwrap();
    fixture
        .send_internal(&outsider_addr, update_body.clone())
        .expect_aborted()
        .expect_exit_code(1702);
    assert_eq!(fixture.policy(), (5 * TOS, 6 * TOS), "rejected update must not change policy");

    // Owner can update policy.
    fixture.send_internal(&owner_addr, update_body).expect_success();
    assert_eq!(fixture.policy(), (2 * TOS, 3 * TOS));

    // Non-owner cannot rotate the controller key.
    let new_secret = [0x99; 32];
    let new_pubkey = ed25519_create_private_key(&new_secret).expect("new key").verifying_key();
    let rotate_body = AgentAccountContract::build_rotate_controller_message(2, new_pubkey).unwrap();
    fixture
        .send_internal(&outsider_addr, rotate_body.clone())
        .expect_aborted()
        .expect_exit_code(1702);

    // The rejected rotation left the old controller key in force.
    let valid_until = fixture.bc.now() + 300;
    let old_key_action = fixture.signed_action(&fixture.controller_secret, 0, valid_until, TOS);
    fixture.send_external(old_key_action).expect("old key still works").expect_success();
    assert_eq!(fixture.seqno(), 1);

    // Owner rotates the controller key.
    fixture.send_internal(&owner_addr, rotate_body).expect_success();

    // The old key's signature is now rejected...
    let old_key_action_2 = fixture.signed_action(&fixture.controller_secret, 1, valid_until, TOS);
    fixture.expect_external_exit(old_key_action_2, 1704);
    assert_eq!(fixture.seqno(), 1);

    // ...only the newly-rotated-in key works.
    let new_key_action = fixture.signed_action(&new_secret, 1, valid_until, TOS);
    fixture.send_external(new_key_action).expect("new key works").expect_success();
    assert_eq!(fixture.seqno(), 2);
}

#[test]
fn task_send_signature_is_bound_to_the_account_address_and_rejected_across_accounts() {
    // The signed message is domain_bound_hash(account_address, payload_hash),
    // not the bare payload hash -- so a signature minted for one Agent
    // Account is *not* accepted by a second, independent Agent Account that
    // happens to share the same controller key (e.g. an operator reusing
    // key material across several agent identities) and, since both are
    // freshly deployed, the same seqno.
    let shared_secret = [0x77; 32];
    let mut account_a = Fixture::with_controller_and_limit(shared_secret, 5 * TOS);
    let mut account_b = Fixture::with_controller_and_limit(shared_secret, 6 * TOS);
    assert_ne!(account_a.account, account_b.account, "fixtures must deploy to different addresses");

    let valid_until = account_a.bc.now() + 300;
    let action_for_a = account_a.signed_action(&shared_secret, 0, valid_until, TOS);

    account_a.send_external(action_for_a.clone()).expect("account_a action").expect_success();
    assert_eq!(account_a.seqno(), 1);

    // The same signed message, replayed verbatim against account_b, must be
    // rejected: it was signed for account_a's address, not account_b's.
    account_b.expect_external_exit(action_for_a, 1704);
    assert_eq!(account_b.seqno(), 0);

    // A correctly re-signed (domain-bound to account_b) message still works.
    let action_for_b = account_b.signed_action(&shared_secret, 0, valid_until, TOS);
    account_b.send_external(action_for_b).expect("account_b action").expect_success();
    assert_eq!(account_b.seqno(), 1);
}
