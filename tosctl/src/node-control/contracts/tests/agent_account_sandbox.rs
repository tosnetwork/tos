/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use chain_block::{ed25519_create_private_key, Cell, MsgAddressInt, SliceData};
use contracts::{AgentAccountContract, AgentAccountInit, TaskEscrowContract, TaskEscrowInit};
use tos_sandbox::{Blockchain, MessageBuilder, SandboxResult, SendResult, Treasury};

const TOS: u64 = 1_000_000_000;

struct Fixture {
    bc: Blockchain,
    account: MsgAddressInt,
    target: Treasury,
    controller_secret: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let owner = bc.treasury("owner", 1_000 * TOS).expect("owner");
        let target = bc.treasury("target", 1_000 * TOS).expect("target");
        let controller_secret = [0x42; 32];
        let controller = ed25519_create_private_key(&controller_secret).expect("controller key");
        let init = AgentAccountInit {
            owner: owner.address().clone(),
            controller_pubkey: controller.verifying_key(),
            max_per_tx: 5 * TOS,
            daily_limit: 6 * TOS,
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
        Self { bc, account, target, controller_secret }
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
        let key = ed25519_create_private_key(secret).expect("signing key");
        let signature = key.sign(payload.hash(0).as_slice());
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
        review_period: 600,
        settlement_policy_hash: [0x11; 32],
        permission_hash: [0x22; 32],
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
