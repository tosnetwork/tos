/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use chain_block::{
    BuilderData, Cell, Coins, CurrencyCollection, Deserializable, IBitstring, MerkleProof,
    MsgAddressInt, Serializable, SizeLimitsConfig, SliceData, TickTock, TrComputePhase,
    ed25519_create_private_key,
};
use contracts::{
    AGENT_ACCOUNT_MAX_ACTION_GAS, AGENT_ACCOUNT_MAX_ACTION_VALUE, AGENT_UPDATE_POLICY_OPCODE,
    AgentAccountContract, AgentAccountInit, AgentAccountPolicyUpdate, AgentCheckedContractCallV2,
    AgentDeploySend, TaskEscrowContract, TaskEscrowInit,
};
use tos_sandbox::{
    Blockchain, MessageBuilder, SandboxResult, SendResult, Treasury, compile_func_with_stdlib,
};

const TOS: u64 = 1_000_000_000;
const GLOBAL_ID: i32 = 42;
fn compute_gas_used(result: &SendResult) -> u64 {
    match result.read_primary_description().compute_ph {
        TrComputePhase::Vm(vm) => vm.gas_used.as_u64(),
        TrComputePhase::Skipped(skipped) => {
            panic!("compute phase was skipped: {:?}", skipped.reason)
        }
    }
}

/// Builds a deploy-send payload without the client-side shape validation of
/// `AgentAccountContract::build_deploy_send_payload`, to exercise the
/// contract's own rejection of unsupported requests.
fn raw_deploy_payload(
    seqno: u32,
    valid_until: u32,
    target: &MsgAddressInt,
    value: u64,
    state_cell: Cell,
    body: Cell,
) -> Cell {
    let mut payload = BuilderData::new();
    payload
        .append_u32(contracts::AGENT_DEPLOY_SEND_OPCODE)
        .expect("opcode")
        .append_i32(GLOBAL_ID)
        .expect("network")
        .append_u64(0)
        .expect("epoch")
        .append_u32(seqno)
        .expect("seqno")
        .append_u32(valid_until)
        .expect("expiry");
    target.write_to(&mut payload).expect("target");
    Coins::new(value).write_to(&mut payload).expect("value");
    payload.checked_append_reference(state_cell).expect("StateInit ref");
    payload.checked_append_reference(body).expect("body ref");
    payload.into_cell().expect("payload")
}

fn raw_checked_call_payload(
    seqno: u32,
    valid_until: u32,
    target: &MsgAddressInt,
    value: u64,
    extra_flags: u8,
    body: Cell,
) -> Cell {
    let mut payload = BuilderData::new();
    payload
        .append_u32(contracts::AGENT_CHECKED_CONTRACT_CALL_V2_OPCODE)
        .expect("opcode")
        .append_i32(GLOBAL_ID)
        .expect("network")
        .append_u64(0)
        .expect("epoch")
        .append_u32(seqno)
        .expect("seqno")
        .append_u32(valid_until)
        .expect("expiry");
    target.write_to(&mut payload).expect("target");
    Coins::new(value).write_to(&mut payload).expect("value");
    payload.append_u8(extra_flags).expect("flags");
    payload.checked_append_reference(body).expect("body ref");
    payload.into_cell().expect("payload")
}

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
        Self::with_controller_limit_and_funding(controller_secret, max_per_tx, 20 * TOS)
    }

    fn with_controller_limit_and_funding(
        controller_secret: [u8; 32],
        max_per_tx: u64,
        funding: u64,
    ) -> Self {
        // Agent Account pins the minimum supported TVM global version: the
        // fee reserve relies on the version-6 GETFORWARDFEE / GETGASFEE
        // primitives (the genesis configuration activates version 14).
        let mut bc = Blockchain::with_global_version(6).expect("blockchain");
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
        let deploy = MessageBuilder::internal(owner.address(), &account, funding)
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

    fn signed_deploy(
        &self,
        secret: &[u8; 32],
        seqno: u32,
        valid_until: u32,
        target: &MsgAddressInt,
        value: u64,
        state_init: chain_block::StateInit,
        body: Cell,
    ) -> Cell {
        let payload = AgentAccountContract::build_deploy_send_payload(
            GLOBAL_ID,
            self.controller_epoch() as u64,
            seqno,
            valid_until,
            &AgentDeploySend { target: target.clone(), value, state_init, body },
        )
        .expect("deploy payload");
        self.sign_payload(secret, GLOBAL_ID, payload)
    }

    fn signed_checked_call(
        &self,
        secret: &[u8; 32],
        seqno: u32,
        valid_until: u32,
        target: &MsgAddressInt,
        value: u64,
        body: Cell,
    ) -> Cell {
        let payload = AgentAccountContract::build_checked_contract_call_v2_payload(
            GLOBAL_ID,
            self.controller_epoch() as u64,
            seqno,
            valid_until,
            &AgentCheckedContractCallV2 { target: target.clone(), value, body },
        )
        .expect("checked-call payload");
        self.sign_payload(secret, GLOBAL_ID, payload)
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

    fn expect_external_rejected(&mut self, body: Cell) {
        assert!(
            self.send_external(body).is_err(),
            "external message must be rejected before acceptance"
        );
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

    fn balance(&self) -> u64 {
        self.bc
            .get_account(&self.account)
            .and_then(|account| account.balance().and_then(|balance| balance.coins.as_u64()))
            .expect("agent account balance")
    }

    fn policy(&self) -> (u64, u64) {
        let binding = self
            .bc
            .run_get_method(&self.account, "get_agent_policy", vec![])
            .expect("get_agent_policy");
        let stack = binding.expect_success();
        (stack.int_at(0) as u64, stack.int_at(1) as u64)
    }

    /// Rewrites the deployed account's own persistent data to force an
    /// arbitrary seqno, without going through 2^32 real increments. Every
    /// other field is round-tripped unchanged from the live data cell.
    fn force_counters(&mut self, seqno: u32, controller_epoch: u64) {
        let mut account = self.bc.get_account(&self.account).cloned().expect("account exists");
        let data_cell = account.get_data().expect("account has data");
        let mut slice = SliceData::load_cell(data_cell).expect("data slice");
        let owner = MsgAddressInt::construct_from(&mut slice).expect("owner");
        let controller_pubkey = slice.get_next_bytes(32).expect("controller pubkey");
        let deployment_id = slice.get_next_bytes(32).expect("deployment id");
        let _old_controller_epoch = slice.get_next_u64().expect("controller epoch");
        let _old_seqno = slice.get_next_u32().expect("seqno");
        let spend_day = slice.get_next_u32().expect("spend day");
        let spent_today = Coins::construct_from(&mut slice).expect("spent today");
        let policy = slice.reference(0).expect("policy ref");

        let mut builder = BuilderData::new();
        owner.write_to(&mut builder).expect("owner");
        builder.append_raw(&controller_pubkey, 256).expect("pubkey");
        builder.append_raw(&deployment_id, 256).expect("deployment id");
        builder.append_u64(controller_epoch).expect("epoch");
        builder.append_u32(seqno).expect("forced seqno");
        builder.append_u32(spend_day).expect("spend day");
        spent_today.write_to(&mut builder).expect("spent today");
        builder.checked_append_reference(policy).expect("policy ref");
        let new_data = builder.into_cell().expect("data cell");

        account.set_data(new_data);
        self.bc.set_account(self.account.clone(), account);
    }

    fn force_seqno(&mut self, seqno: u32) {
        let controller_epoch = self.controller_epoch() as u64;
        self.force_counters(seqno, controller_epoch);
    }

    fn force_controller_epoch(&mut self, controller_epoch: u64) {
        let seqno = self.seqno() as u32;
        self.force_counters(seqno, controller_epoch);
    }

    fn force_balance(&mut self, balance: u64) {
        let mut account = self.bc.get_account(&self.account).cloned().expect("account exists");
        account.set_balance(CurrencyCollection::with_coins(balance));
        self.bc.set_account(self.account.clone(), account);
    }
}

#[test]
fn native_send_is_one_bodyless_non_bouncing_transfer() {
    let mut fixture = Fixture::new();
    let target = fixture.target.address().clone();
    let action = fixture.signed_native(
        &fixture.controller_secret,
        GLOBAL_ID,
        u64::from(contracts::AGENT_CHECKED_CONTRACT_CALL_V2_FLAGS),
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
fn checked_contract_call_v2_is_one_bounceable_exact_body_transfer() {
    let mut fixture = Fixture::new();
    let target = fixture.target.address().clone();
    let mut body_builder = BuilderData::new();
    body_builder.append_u32(0x504d_0001).expect("operation");
    body_builder.append_u64(77).expect("query id");
    let expected_body = body_builder.into_cell().expect("body");
    let action = fixture.signed_checked_call(
        &fixture.controller_secret,
        0,
        fixture.bc.now() + 300,
        &target,
        TOS,
        expected_body.clone(),
    );
    let result = fixture.send_external(action).expect("checked contract call");
    result.expect_success().expect_out_msgs(1);

    assert_eq!(fixture.seqno(), 1);
    assert_eq!(fixture.spent_today(), TOS as i128);
    let target_tx = result
        .transactions_for(&target)
        .into_iter()
        .next()
        .expect("destination receives the checked call");
    let inbound = target_tx.read_in_msg().expect("read inbound").expect("inbound message");
    let header = inbound.int_header().expect("internal header");
    assert!(header.bounce, "V2 checked contract calls must be bounceable");
    assert_eq!(
        header.extra_flags.as_u64().expect("V2 extra flags fit u64"),
        0,
        "V2 checked calls must request the rich bounce envelope"
    );
    assert!(inbound.state_init().is_none(), "V2 calls must never carry StateInit");
    let actual_body = inbound.body().expect("V2 body").clone().into_cell().expect("body cell");
    assert_eq!(actual_body.repr_hash(), expected_body.repr_hash());
}

#[test]
fn checked_contract_call_v2_rejects_weakening_or_empty_body_before_acceptance() {
    let mut fixture = Fixture::new();
    let target = fixture.target.address().clone();
    let mut nonempty = BuilderData::new();
    nonempty.append_u32(0x504d_0001).expect("operation");

    let bad_flags = raw_checked_call_payload(
        0,
        fixture.bc.now() + 300,
        &target,
        TOS,
        1,
        nonempty.into_cell().expect("body"),
    );
    let bad_flags = fixture.sign_payload(&fixture.controller_secret, GLOBAL_ID, bad_flags);
    fixture.expect_external_exit(bad_flags, 1718);
    assert_eq!(fixture.seqno(), 0);

    let empty = raw_checked_call_payload(
        0,
        fixture.bc.now() + 300,
        &target,
        TOS,
        contracts::AGENT_CHECKED_CONTRACT_CALL_V2_FLAGS,
        Cell::default(),
    );
    let empty = fixture.sign_payload(&fixture.controller_secret, GLOBAL_ID, empty);
    fixture.expect_external_exit(empty, 1719);
    assert_eq!(fixture.seqno(), 0);
}

#[test]
fn owner_rotation_rejects_small_order_and_noncanonical_controller_keys() {
    let mut fixture = Fixture::new();
    let owner = fixture.owner.address().clone();
    for encoded in [
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ] {
        let key: [u8; 32] = hex::decode(encoded).expect("hex").try_into().expect("key");
        let mut body = BuilderData::new();
        body.append_u32(contracts::agent_account::AGENT_ROTATE_CONTROLLER_OPCODE)
            .expect("opcode")
            .append_u64(1)
            .expect("query id")
            .append_raw(&key, 256)
            .expect("key");
        fixture
            .send_internal(&owner, body.into_cell().expect("body"))
            .expect_aborted()
            .expect_exit_code(1720);
        assert_eq!(fixture.seqno(), 0);
        assert_eq!(fixture.controller_epoch(), 0);
    }
}

#[test]
fn deploy_send_atomically_installs_exact_state_init_and_funds_task() {
    let mut fixture = Fixture::new();
    let init = TaskEscrowInit {
        creator: fixture.account.clone(),
        assigned_agent: None,
        verifier: None,
        budget: 2 * TOS,
        deadline: u64::from(fixture.bc.now()) + 3_600,
        review_period: 3_600,
        settlement_policy_hash: [0x31; 32],
        permission_hash: [0x32; 32],
        attestor_pubkey: None,
    };
    let target = TaskEscrowContract::calculate_address(-1, &init).expect("task address");
    let state_init = TaskEscrowContract::build_state_init(&init).expect("task StateInit");
    let expected_state_hash = state_init
        .write_to_new_cell()
        .expect("serialize StateInit")
        .into_cell()
        .expect("StateInit cell")
        .hash(0);
    let action = fixture.signed_deploy(
        &fixture.controller_secret,
        0,
        fixture.bc.now() + 300,
        &target,
        3 * TOS,
        state_init,
        Cell::default(),
    );
    let result = fixture.send_external(action).expect("deploy send");
    result.expect_success().expect_out_msgs(1);

    assert_eq!(fixture.seqno(), 1);
    assert_eq!(fixture.spent_today(), 3 * TOS as i128);
    let target_tx = result
        .transactions_for(&target)
        .into_iter()
        .next()
        .expect("deployed task must receive the transfer");
    let inbound = target_tx.read_in_msg().expect("read inbound").expect("inbound message");
    let deployed_state = inbound.state_init().expect("deploy send must carry StateInit");
    assert_eq!(
        deployed_state
            .write_to_new_cell()
            .expect("serialize deployed StateInit")
            .into_cell()
            .expect("deployed StateInit cell")
            .hash(0),
        expected_state_hash
    );
    assert_eq!(
        fixture
            .bc
            .run_get_method(&target, "get_task_data", vec![])
            .expect("task data")
            .expect_success()
            .int_at(7),
        0
    );
}

#[test]
fn deploy_send_reserves_the_real_forward_fee_instead_of_skipping_silently() {
    // A deploy carries the whole StateInit, so its forward fee is an order of
    // magnitude above what a bodyless transfer costs. The compute phase must
    // reserve the fee for the actual message size and fee schedule before
    // accepting: an underfunded action is then rejected without gas or a
    // replayable transaction, and the identical signed bytes stay submittable.
    let mut fixture = Fixture::with_controller_limit_and_funding([0x51; 32], 5 * TOS, 3 * TOS);
    let init = TaskEscrowInit {
        creator: fixture.account.clone(),
        assigned_agent: None,
        verifier: None,
        budget: TOS,
        deadline: u64::from(fixture.bc.now()) + 3_600,
        review_period: 3_600,
        settlement_policy_hash: [0x51; 32],
        permission_hash: [0x52; 32],
        attestor_pubkey: None,
    };
    let target = TaskEscrowContract::calculate_address(-1, &init).expect("task address");
    let state_init = TaskEscrowContract::build_state_init(&init).expect("task StateInit");
    // Leave 0.05 TOS above the transfer: several times a bodyless send's fee,
    // but far below the masterchain forward fee of a ~2 KB StateInit.
    let value = fixture.balance() - TOS / 20;
    let action = fixture.signed_deploy(
        &fixture.controller_secret,
        0,
        fixture.bc.now() + 300,
        &target,
        value,
        state_init,
        Cell::default(),
    );
    fixture.expect_external_exit(action.clone(), 1711);
    assert_eq!(fixture.seqno(), 0);
    assert_eq!(fixture.spent_today(), 0);
    assert!(fixture.bc.get_account(&target).is_none(), "nothing may reach the target");

    // Fund the account, then resubmit the very same signed bytes.
    let top_up = MessageBuilder::internal(fixture.owner.address(), &fixture.account, 2 * TOS)
        .bounce(false)
        .body(Cell::default())
        .build();
    fixture.bc.send_message(top_up).expect("top up").expect_success();
    let result = fixture.send_external(action).expect("funded resend");
    result.expect_success().expect_out_msgs(1);
    let gas_used = compute_gas_used(&result);
    assert!(
        gas_used * 3 <= AGENT_ACCOUNT_MAX_ACTION_GAS * 2,
        "reserved compute budget must keep at least 1.5x margin over real usage ({gas_used} gas)"
    );
    assert_eq!(fixture.seqno(), 1);
    assert_eq!(fixture.spent_today(), value as i128);
    let target_tx = result
        .transactions_for(&target)
        .into_iter()
        .next()
        .expect("deployed task must receive the transfer");
    let inbound = target_tx.read_in_msg().expect("read inbound").expect("inbound message");
    assert!(inbound.state_init().is_some(), "deploy send must carry the StateInit");
    assert_eq!(
        inbound.int_header().expect("internal header").value.coins.as_u64(),
        Some(value),
        "fees are paid by the account, the target receives the full signed value"
    );
}

#[test]
fn deploy_send_is_bound_by_policy_and_cannot_be_replayed() {
    let mut fixture = Fixture::new();
    let init = TaskEscrowInit {
        creator: fixture.account.clone(),
        assigned_agent: None,
        verifier: None,
        budget: TOS,
        deadline: u64::from(fixture.bc.now()) + 3_600,
        review_period: 3_600,
        settlement_policy_hash: [0x61; 32],
        permission_hash: [0x62; 32],
        attestor_pubkey: None,
    };
    let target = TaskEscrowContract::calculate_address(-1, &init).expect("task address");
    let state_init = TaskEscrowContract::build_state_init(&init).expect("task StateInit");
    let valid_until = fixture.bc.now() + 300;

    // Above max_per_tx: rejected before acceptance, nothing consumed.
    let oversized = fixture.signed_deploy(
        &fixture.controller_secret,
        0,
        valid_until,
        &target,
        6 * TOS,
        state_init.clone(),
        Cell::default(),
    );
    fixture.expect_external_exit(oversized, 1707);
    assert_eq!(fixture.seqno(), 0);
    assert_eq!(fixture.spent_today(), 0);

    // Within policy: deploys exactly once and charges the daily budget.
    let action = fixture.signed_deploy(
        &fixture.controller_secret,
        0,
        valid_until,
        &target,
        2 * TOS,
        state_init,
        Cell::default(),
    );
    fixture.send_external(action.clone()).expect("deploy").expect_success().expect_out_msgs(1);
    assert_eq!(fixture.seqno(), 1);
    assert_eq!(fixture.spent_today(), 2 * TOS as i128);

    // The identical signed bytes are dead afterwards.
    fixture.expect_external_exit(action, 1705);
    assert_eq!(fixture.seqno(), 1);
    assert_eq!(fixture.spent_today(), 2 * TOS as i128);
}

#[test]
fn deploy_send_rejects_a_state_init_for_another_destination_without_consuming_seqno() {
    let mut fixture = Fixture::new();
    let init = TaskEscrowInit {
        creator: fixture.account.clone(),
        assigned_agent: None,
        verifier: None,
        budget: TOS,
        deadline: u64::from(fixture.bc.now()) + 3_600,
        review_period: 3_600,
        settlement_policy_hash: [0x41; 32],
        permission_hash: [0x42; 32],
        attestor_pubkey: None,
    };
    let state_init = TaskEscrowContract::build_state_init(&init).expect("task StateInit");
    let wrong_target = fixture.target.address().clone();
    let payload = {
        let state_cell = state_init
            .write_to_new_cell()
            .expect("serialize StateInit")
            .into_cell()
            .expect("StateInit cell");
        let mut payload = BuilderData::new();
        payload
            .append_u32(contracts::AGENT_DEPLOY_SEND_OPCODE)
            .expect("opcode")
            .append_i32(GLOBAL_ID)
            .expect("network")
            .append_u64(0)
            .expect("epoch")
            .append_u32(0)
            .expect("seqno")
            .append_u32(fixture.bc.now() + 300)
            .expect("expiry");
        wrong_target.write_to(&mut payload).expect("target");
        Coins::new(TOS).write_to(&mut payload).expect("value");
        payload.checked_append_reference(state_cell).expect("StateInit ref");
        payload.checked_append_reference(Cell::default()).expect("body ref");
        payload.into_cell().expect("payload")
    };
    let action = fixture.sign_payload(&fixture.controller_secret, GLOBAL_ID, payload);
    fixture.expect_external_exit(action, 1712);
    assert_eq!(fixture.seqno(), 0);
    assert_eq!(fixture.spent_today(), 0);
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
fn underfunded_cancel_is_rejected_before_acceptance_and_remains_resubmittable() {
    let mut fixture = Fixture::new();
    let cancel =
        fixture.signed_cancel(&fixture.controller_secret, GLOBAL_ID, 0, fixture.bc.now() + 300);
    // The masterchain import fee is below 0.1 TOS, while the contract's
    // conservative 30k-gas reserve is about 0.3 TOS under the sandbox fee
    // schedule. This reaches the contract and fails its own pre-accept gate.
    fixture.force_balance(TOS / 10);

    fixture.expect_external_exit(cancel.clone(), 1711);
    assert_eq!(fixture.seqno(), 0);
    assert_eq!(fixture.balance(), TOS / 10, "a pre-accept rejection must not charge the account");

    fixture.force_balance(TOS);
    fixture.send_external(cancel).expect("funded retry").expect_success().expect_out_msgs(0);
    assert_eq!(fixture.seqno(), 1);
}

#[test]
fn a_saturated_seqno_is_rejected_before_acceptance_on_every_external_path() {
    // Every external op stores seqno + 1 through the same two accept_message()
    // call sites (recv_external's cancel branch and its shared tail for
    // task/native/deploy send). At seqno = u32::MAX, storing seqno + 1 back
    // through pack_agent_state's store_uint(_, 32) would throw only *after*
    // accept_message(): the transaction would still be valid and charged, but
    // the state mutation would never commit, leaving the exact same signed
    // bytes accepted-but-inert and resubmittable for as long as valid_until
    // allows. require_seqno_not_saturated must catch this before acceptance
    // on both call sites, for every op, so nothing is ever consumed.
    let mut fixture = Fixture::new();
    fixture.force_seqno(u32::MAX);
    let balance = fixture.balance();
    let target = fixture.target.address().clone();
    let valid_until = fixture.bc.now() + 300;

    let cancel =
        fixture.signed_cancel(&fixture.controller_secret, GLOBAL_ID, u32::MAX, valid_until);
    fixture.expect_external_exit(cancel, 1716);
    assert_eq!(fixture.seqno(), u32::MAX as i128);
    assert_eq!(fixture.balance(), balance);

    let native = fixture.signed_native(
        &fixture.controller_secret,
        GLOBAL_ID,
        u32::MAX,
        valid_until,
        &target,
        TOS,
    );
    fixture.expect_external_exit(native, 1716);
    assert_eq!(fixture.seqno(), u32::MAX as i128);
    assert_eq!(fixture.balance(), balance);
    assert_eq!(fixture.spent_today(), 0);
}

#[test]
fn owner_rotation_is_rejected_before_acceptance_when_seqno_is_saturated() {
    // agent_rotate_controller is internal, not external, but it stores
    // seqno + 1 through the exact same pack_agent_state() call after its own
    // accept_message(). Without the guard, a rotation submitted at
    // seqno = u32::MAX would still be "accepted" by the network (the owner's
    // message value pays for it) but the compute phase would abort inside
    // set_data() -- silently leaving the old, possibly-compromised
    // controller key in force while the owner believes the rotation
    // succeeded, since nothing about an internal message's own success tells
    // the owner the state mutation was actually committed.
    let mut fixture = Fixture::new();
    fixture.force_seqno(u32::MAX);
    let owner_addr = fixture.owner.address().clone();
    let new_secret = [0x99; 32];
    let new_pubkey = ed25519_create_private_key(&new_secret).expect("new key").verifying_key();
    let rotate_body = AgentAccountContract::build_rotate_controller_message(1, new_pubkey).unwrap();

    fixture.send_internal(&owner_addr, rotate_body).expect_aborted().expect_exit_code(1716);
    assert_eq!(fixture.seqno(), u32::MAX as i128);
    assert_eq!(fixture.controller_epoch(), 0, "rotation must not have taken effect");

    // The old controller key must still be the one in force.
    let valid_until = fixture.bc.now() + 300;
    let old_key_action = fixture.signed_native(
        &fixture.controller_secret,
        GLOBAL_ID,
        1,
        valid_until,
        fixture.target.address(),
        TOS,
    );
    fixture.expect_external_exit(old_key_action, 1705); // seqno mismatch: still at u32::MAX, not 1
}

#[test]
fn owner_rotation_rejects_a_saturated_controller_epoch_before_acceptance() {
    let mut fixture = Fixture::new();
    fixture.force_controller_epoch(u64::MAX);
    let owner_addr = fixture.owner.address().clone();
    let new_secret = [0x9a; 32];
    let new_pubkey = ed25519_create_private_key(&new_secret).expect("new key").verifying_key();
    let rotate_body = AgentAccountContract::build_rotate_controller_message(1, new_pubkey).unwrap();

    fixture.send_internal(&owner_addr, rotate_body).expect_aborted().expect_exit_code(1717);
    assert_eq!(fixture.controller_epoch(), u64::MAX as i128);
    assert_eq!(fixture.seqno(), 0, "failed rotation must not consume seqno");
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
        .send_external(action.clone())
        .expect("mode 3 keeps compute/state successful when the send action is invalid")
        .expect_success()
        .expect_out_msgs(0);
    assert_eq!(fixture.seqno(), 1);
    assert_eq!(fixture.spent_today(), TOS as i128);

    // The identical bytes are dead afterwards: rejected before acceptance, so a
    // public rebroadcast cannot charge the account again.
    let balance = fixture.balance();
    fixture.expect_external_exit(action, 1705);
    assert_eq!(fixture.balance(), balance);
}

#[test]
fn deploy_send_outside_the_account_workchain_is_rejected_before_acceptance() {
    // Destination validity is decided by the action phase from ConfigParam 12,
    // which the compute phase cannot afford to consult. Deploys are therefore
    // confined to the account's own workchain, where delivery is guaranteed,
    // and anything else is refused before acceptance instead of being skipped
    // with seqno and daily spend consumed.
    let mut fixture = Fixture::new();
    let init = TaskEscrowInit {
        creator: fixture.account.clone(),
        assigned_agent: None,
        verifier: None,
        budget: TOS,
        deadline: u64::from(fixture.bc.now()) + 3_600,
        review_period: 3_600,
        settlement_policy_hash: [0x81; 32],
        permission_hash: [0x82; 32],
        attestor_pubkey: None,
    };
    let target = TaskEscrowContract::calculate_address(0, &init).expect("task address");
    let state_init = TaskEscrowContract::build_state_init(&init).expect("task StateInit");
    let action = fixture.signed_deploy(
        &fixture.controller_secret,
        0,
        fixture.bc.now() + 300,
        &target,
        2 * TOS,
        state_init,
        Cell::default(),
    );
    fixture.expect_external_exit(action, 1714);
    assert_eq!(fixture.seqno(), 0);
    assert_eq!(fixture.spent_today(), 0);
    assert!(fixture.bc.get_account(&target).is_none(), "nothing may reach the target");
}

#[test]
fn deploy_send_above_the_configured_message_limit_is_rejected_before_acceptance() {
    // The size preflight reads the live ConfigParam 43 through the unpacked
    // configuration register, so a network that tightens the limits below the
    // protocol defaults refuses the deploy up front instead of letting the
    // action phase skip it after seqno and daily spend were committed.
    let mut fixture = Fixture::new();
    let init = TaskEscrowInit {
        creator: fixture.account.clone(),
        assigned_agent: None,
        verifier: None,
        budget: TOS,
        deadline: u64::from(fixture.bc.now()) + 3_600,
        review_period: 3_600,
        settlement_policy_hash: [0x91; 32],
        permission_hash: [0x92; 32],
        attestor_pubkey: None,
    };
    let target = TaskEscrowContract::calculate_address(-1, &init).expect("task address");
    let state_init = TaskEscrowContract::build_state_init(&init).expect("task StateInit");
    let action = fixture.signed_deploy(
        &fixture.controller_secret,
        0,
        fixture.bc.now() + 300,
        &target,
        2 * TOS,
        state_init,
        Cell::default(),
    );

    let tightened = SizeLimitsConfig { max_msg_cells: 8, ..SizeLimitsConfig::default() };
    fixture.bc.set_size_limits_config(tightened).expect("tighten");
    fixture.expect_external_exit(action.clone(), 1713);
    assert_eq!(fixture.seqno(), 0);
    assert_eq!(fixture.spent_today(), 0);
    assert!(fixture.bc.get_account(&target).is_none(), "nothing may reach the target");

    // Once the limit allows the message again, the identical signed bytes go
    // through: nothing was consumed by the rejection.
    fixture.bc.set_size_limits_config(SizeLimitsConfig::default()).expect("restore");
    let result = fixture.send_external(action).expect("same bytes after the fix");
    result.expect_success().expect_out_msgs(1);
    assert_eq!(fixture.seqno(), 1);
    assert_eq!(fixture.spent_today(), 2 * TOS as i128);
    assert!(fixture.bc.get_account(&target).is_some(), "the deploy reached the target");
}

#[test]
fn deploy_send_rejects_unsupported_state_init_shapes_before_acceptance() {
    // Only the plain code+data StateInit the repository contracts produce is
    // supported. Libraries, tick-tock flags and exotic root cells could all
    // make the action phase or the receiving account reject the deploy, so
    // they are refused before acceptance rather than skipped or replayed.
    let mut fixture = Fixture::new();
    let init = TaskEscrowInit {
        creator: fixture.account.clone(),
        assigned_agent: None,
        verifier: None,
        budget: TOS,
        deadline: u64::from(fixture.bc.now()) + 3_600,
        review_period: 3_600,
        settlement_policy_hash: [0xa1; 32],
        permission_hash: [0xa2; 32],
        attestor_pubkey: None,
    };
    let plain = TaskEscrowContract::build_state_init(&init).expect("task StateInit");
    let plain_cell = plain.write_to_new_cell().expect("serialize").into_cell().expect("cell");
    let valid_until = fixture.bc.now() + 300;

    let mut with_library = plain.clone();
    with_library.set_library_code(Cell::default(), true).expect("library");
    let mut with_special = plain.clone();
    with_special.set_special(TickTock::with_values(true, false));
    let exotic_root =
        MerkleProof::create(&plain_cell, |_| true).expect("proof").serialize().expect("proof cell");
    // A level-zero Merkle proof nested as code is not distinguishable with
    // CLEVEL alone. It is outside the on-chain supported profile, and the
    // recursive client-side validation below must reject it before signing.
    let mut with_exotic_code = plain.clone();
    let exotic_code = MerkleProof::create(&Cell::default(), |_| true)
        .expect("proof")
        .serialize()
        .expect("proof cell");
    with_exotic_code.code = Some(exotic_code);

    let variants = [
        (
            with_library.write_to_new_cell().expect("serialize").into_cell().expect("cell"),
            Some(1715),
        ),
        (
            with_special.write_to_new_cell().expect("serialize").into_cell().expect("cell"),
            Some(1715),
        ),
        (exotic_root, None),
    ];
    for (state_cell, expected_exit) in variants {
        let target = MsgAddressInt::with_params(-1, state_cell.hash(0)).expect("target");
        let payload = raw_deploy_payload(0, valid_until, &target, TOS, state_cell, Cell::default());
        let action = fixture.sign_payload(&fixture.controller_secret, GLOBAL_ID, payload);
        match expected_exit {
            Some(exit_code) => fixture.expect_external_exit(action, exit_code),
            None => fixture.expect_external_rejected(action),
        }
        assert_eq!(fixture.seqno(), 0);
        assert_eq!(fixture.spent_today(), 0);
    }

    // The client-side builder refuses the same shapes before anything is signed.
    let target = MsgAddressInt::with_params(-1, plain_cell.hash(0)).expect("target");
    assert!(
        AgentAccountContract::build_deploy_send_payload(
            GLOBAL_ID,
            0,
            0,
            valid_until,
            &AgentDeploySend {
                target: target.clone(),
                value: TOS,
                state_init: with_special,
                body: Cell::default(),
            },
        )
        .is_err()
    );
    let exotic_state_cell =
        with_exotic_code.write_to_new_cell().expect("serialize").into_cell().expect("cell");
    let exotic_target = MsgAddressInt::with_params(-1, exotic_state_cell.hash(0)).expect("target");
    let error = AgentAccountContract::build_deploy_send_payload(
        GLOBAL_ID,
        0,
        0,
        valid_until,
        &AgentDeploySend {
            target: exotic_target,
            value: TOS,
            state_init: with_exotic_code,
            body: Cell::default(),
        },
    )
    .expect_err("the client-side builder must reject a Merkle-proof-wrapped code cell");
    assert!(
        error.to_string().contains("ordinary cells"),
        "the rejection must come from recursive exotic-cell validation: {error}"
    );
}

#[test]
fn underfunded_action_is_rejected_preserving_seqno_and_succeeds_after_top_up() {
    // Policy allows more than the account holds: 50 TOS per tx, 20 TOS funded.
    let mut fixture = Fixture::with_controller_and_limit([0x47; 32], 50 * TOS);
    let target = fixture.target.address().clone();
    let action = fixture.signed_native(
        &fixture.controller_secret,
        GLOBAL_ID,
        0,
        fixture.bc.now() + 300,
        &target,
        30 * TOS,
    );

    // The balance cannot cover the value plus fee headroom: the action is
    // rejected in the compute phase, before accept_message, so the seqno and
    // the daily budget are untouched and the signed bytes stay submittable.
    fixture.expect_external_exit(action.clone(), 1711);
    assert_eq!(fixture.seqno(), 0);
    assert_eq!(fixture.spent_today(), 0);

    // Top up the account, then resubmit the very same signed message.
    let top_up = MessageBuilder::internal(fixture.owner.address(), &fixture.account, 20 * TOS)
        .bounce(false)
        .body(Cell::default())
        .build();
    fixture.bc.send_message(top_up).expect("top up").expect_success();
    fixture.send_external(action).expect("funded resend").expect_success();
    assert_eq!(fixture.seqno(), 1);
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
