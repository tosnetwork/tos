/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use chain_block::{
    BuilderData, Cell, Coins, IBitstring, MsgAddressInt, Serializable, SliceData,
    ed25519_create_private_key,
};
use contracts::{
    AGENT_ACCOUNT_MAX_ACTION_VALUE, AGENT_UPDATE_POLICY_OPCODE, AgentAccountContract,
    AgentAccountInit, AgentAccountPolicyUpdate, TaskEscrowContract, TaskEscrowInit,
};
use tos_sandbox::{
    Blockchain, MessageBuilder, SandboxResult, SendResult, Treasury, compile_func_with_stdlib,
};

const TOS: u64 = 1_000_000_000;
const GLOBAL_ID: i32 = 42;

#[test]
fn source_compiles_to_the_embedded_final_interface() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../crypto/smartcont/agent-account-code.fc");
    let compiled = compile_func_with_stdlib(&[source]).expect("compile Agent Account source");
    assert_eq!(
        compiled.repr_hash(),
        AgentAccountContract::code().expect("embedded Agent Account code").repr_hash(),
        "embedded Agent Account BOC must be regenerated whenever FunC changes"
    );
}

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
        // Agent Account pins the minimum supported TVM global version.
        let mut bc = Blockchain::with_global_version(4).expect("blockchain");
        bc.set_workchain(-1);
        let owner = bc.treasury("owner", 1_000 * TOS).expect("owner");
        let outsider = bc.treasury("outsider", 1_000 * TOS).expect("outsider");
        let target = bc.treasury("target", 1_000 * TOS).expect("target");
        let controller = ed25519_create_private_key(&controller_secret).expect("controller key");
        let init = AgentAccountInit {
            owner: owner.address().clone(),
            controller_pubkey: controller.verifying_key(),
            deployment_id: [(max_per_tx / TOS) as u8; 32],
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
        let payload = AgentAccountContract::build_task_send_payload(
            GLOBAL_ID,
            self.controller_epoch() as u64,
            seqno,
            valid_until,
            target,
            value,
            body,
        )
        .expect("payload");
        self.sign_payload(secret, GLOBAL_ID, payload)
    }

    fn sign_payload(&self, secret: &[u8; 32], global_id: i32, payload: Cell) -> Cell {
        let hash_to_sign =
            AgentAccountContract::controller_hash_to_sign(&self.account, global_id, &payload)
                .expect("hash");
        let key = ed25519_create_private_key(secret).expect("signing key");
        let signature = key.sign(&hash_to_sign);
        AgentAccountContract::build_signed_controller_message(payload, &signature)
            .expect("signed body")
    }

    fn signed_native(
        &self,
        secret: &[u8; 32],
        global_id: i32,
        seqno: u32,
        valid_until: u32,
        target: &MsgAddressInt,
        value: u64,
    ) -> Cell {
        let payload = AgentAccountContract::build_native_send_payload(
            global_id,
            self.controller_epoch() as u64,
            seqno,
            valid_until,
            target,
            value,
        )
        .expect("native payload");
        self.sign_payload(secret, global_id, payload)
    }

    fn signed_cancel(
        &self,
        secret: &[u8; 32],
        global_id: i32,
        seqno: u32,
        valid_until: u32,
    ) -> Cell {
        let payload = AgentAccountContract::build_cancel_seqno_payload(
            global_id,
            self.controller_epoch() as u64,
            seqno,
            valid_until,
        )
        .expect("cancel payload");
        self.sign_payload(secret, global_id, payload)
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
            .int_at(9)
    }

    fn controller_epoch(&self) -> i128 {
        self.bc
            .run_get_method(&self.account, "get_agent_account_data", vec![])
            .expect("get data")
            .expect_success()
            .int_at(3)
    }

    fn spent_today(&self) -> i128 {
        self.bc
            .run_get_method(&self.account, "get_agent_account_data", vec![])
            .expect("get data")
            .expect_success()
            .int_at(11)
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
fn native_send_is_one_bodyless_non_bouncing_transfer() {
    let mut fixture = Fixture::new();
    let target = fixture.target.address().clone();
    let action = fixture.signed_native(
        &fixture.controller_secret,
        GLOBAL_ID,
        0,
        fixture.bc.now() + 300,
        &target,
        TOS,
    );
    let result = fixture.send_external(action).expect("native send");
    result.expect_success().expect_out_msgs(1);

    assert_eq!(fixture.seqno(), 1);
    assert_eq!(fixture.spent_today(), TOS as i128);
    let target_tx = result
        .transactions_for(&target)
        .into_iter()
        .next()
        .expect("exact destination must receive the transfer");
    let inbound = target_tx.read_in_msg().expect("read inbound").expect("inbound message");
    let header = inbound.int_header().expect("internal header");
    assert!(!header.bounce, "native sends are intentionally non-bouncing");
    assert!(inbound.state_init().is_none(), "native sends never carry StateInit");
    assert!(
        inbound
            .body()
            .is_none_or(|body| body.remaining_bits() == 0 && body.remaining_references() == 0)
    );
}

#[test]
fn cancel_consumes_seqno_without_spend_or_outbound_message() {
    let mut fixture = Fixture::new();
    let cancel =
        fixture.signed_cancel(&fixture.controller_secret, GLOBAL_ID, 0, fixture.bc.now() + 300);
    fixture.send_external(cancel).expect("cancel").expect_success().expect_out_msgs(0);
    assert_eq!(fixture.seqno(), 1);
    assert_eq!(fixture.spent_today(), 0);
}

#[test]
fn controller_message_rejects_wrong_network_and_payload_tampering() {
    let mut fixture = Fixture::new();
    let valid_until = fixture.bc.now() + 300;
    let target = fixture.target.address().clone();

    let wrong_network = fixture.signed_native(
        &fixture.controller_secret,
        GLOBAL_ID + 1,
        0,
        valid_until,
        &target,
        TOS,
    );
    fixture.expect_external_exit(wrong_network, 1708);

    let original =
        AgentAccountContract::build_native_send_payload(GLOBAL_ID, 0, 0, valid_until, &target, TOS)
            .expect("original payload");
    let original_hash =
        AgentAccountContract::controller_hash_to_sign(&fixture.account, GLOBAL_ID, &original)
            .expect("hash");
    let key = ed25519_create_private_key(&fixture.controller_secret).expect("key");
    let signature = key.sign(&original_hash);
    let tampered = AgentAccountContract::build_native_send_payload(
        GLOBAL_ID,
        0,
        0,
        valid_until,
        &target,
        2 * TOS,
    )
    .expect("tampered payload");
    let tampered =
        AgentAccountContract::build_signed_controller_message(tampered, &signature).unwrap();
    fixture.expect_external_exit(tampered, 1704);
    assert_eq!(fixture.seqno(), 0);
}

#[test]
fn ignored_native_send_action_still_consumes_seqno_and_daily_budget() {
    let mut fixture = Fixture::new();
    let invalid_workchain = MsgAddressInt::with_params(1, [0x55; 32]).unwrap();
    let action = fixture.signed_native(
        &fixture.controller_secret,
        GLOBAL_ID,
        0,
        fixture.bc.now() + 300,
        &invalid_workchain,
        TOS,
    );
    fixture
        .send_external(action)
        .expect("mode 3 keeps compute/state successful when the send action is invalid")
        .expect_success()
        .expect_out_msgs(0);
    assert_eq!(fixture.seqno(), 1);
    assert_eq!(fixture.spent_today(), TOS as i128);
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

    let too_far =
        fixture.signed_action(&fixture.controller_secret, 0, fixture.bc.now() + 3_601, TOS);
    fixture.expect_external_exit(too_far, 1706);

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
    let owner_addr = fixture.owner.address().clone();
    let long_timeout = AgentAccountPolicyUpdate {
        max_per_tx: 5 * TOS,
        daily_limit: 6 * TOS,
        default_task_timeout_secs: 2 * 86_400,
        metadata_hash: None,
        service_endpoint_hash: None,
    };
    let update = AgentAccountContract::build_update_policy_message(1, &long_timeout).unwrap();
    fixture.send_internal(&owner_addr, update).expect_success();
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

    // Mint a future-seqno signature while controller A is in epoch 0. Merely
    // bumping seqno on rotation would let this revive after A -> B -> A.
    let target = fixture.target.address().clone();
    let pre_rotation_payload = AgentAccountContract::build_task_send_payload(
        GLOBAL_ID,
        0,
        4,
        fixture.bc.now() + 300,
        &target,
        TOS,
        Cell::default(),
    )
    .unwrap();
    let pre_rotation_signature =
        fixture.sign_payload(&fixture.controller_secret, GLOBAL_ID, pre_rotation_payload);

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
    assert_eq!(fixture.seqno(), 2, "controller rotation invalidates every outstanding signature");
    assert_eq!(fixture.controller_epoch(), 1);

    // The old key's signature is now rejected...
    let old_key_action_2 = fixture.signed_action(&fixture.controller_secret, 2, valid_until, TOS);
    fixture.expect_external_exit(old_key_action_2, 1704);
    assert_eq!(fixture.seqno(), 2);

    // ...only the newly-rotated-in key works.
    let new_key_action = fixture.signed_action(&new_secret, 2, valid_until, TOS);
    fixture.send_external(new_key_action).expect("new key works").expect_success();
    assert_eq!(fixture.seqno(), 3);

    let old_pubkey =
        ed25519_create_private_key(&fixture.controller_secret).expect("old key").verifying_key();
    let rotate_back = AgentAccountContract::build_rotate_controller_message(3, old_pubkey).unwrap();
    fixture.send_internal(&owner_addr, rotate_back).expect_success();
    assert_eq!(fixture.seqno(), 4);
    assert_eq!(fixture.controller_epoch(), 2);

    // Controller A is active again and the seqno now matches, but the epoch
    // proves this signature belongs to the retired A/epoch-0 generation.
    fixture.expect_external_exit(pre_rotation_signature, 1710);
}

#[test]
fn owner_cannot_install_a_policy_above_the_signed_action_wire_limit() {
    let mut fixture = Fixture::new();
    let owner_addr = fixture.owner.address().clone();
    let too_large = AGENT_ACCOUNT_MAX_ACTION_VALUE + 1;
    let mut body = BuilderData::new();
    body.append_u32(AGENT_UPDATE_POLICY_OPCODE).unwrap().append_u64(1).unwrap();
    Coins::new(too_large).write_to(&mut body).unwrap();
    Coins::new(too_large).write_to(&mut body).unwrap();
    body.append_u64(3_600).unwrap().append_bit_zero().unwrap().append_bit_zero().unwrap();
    fixture
        .send_internal(&owner_addr, body.into_cell().unwrap())
        .expect_aborted()
        .expect_exit_code(1701);
    assert_eq!(fixture.policy(), (5 * TOS, 6 * TOS));
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
