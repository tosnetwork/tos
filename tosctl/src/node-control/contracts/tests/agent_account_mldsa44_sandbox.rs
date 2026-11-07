/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The Agent Account's ML-DSA-44 route, driven through the same SDK builders
//! the CLI uses: the embedded module and account bytecode, a real ML-DSA-44
//! signature, and every hop executed as its own transaction so each refusal is
//! observed where it happens (relayer -> module -> account -> target).

use chain_block::{
    CurrencyCollection, Message, MsgAddressInt, SliceData, TrComputePhase, Transaction,
    TransactionDescr, ed25519_create_private_key,
};
use contracts::agent_account_auth::{
    AUTH_KIND_EXECUTE, AUTH_MODE_LEGACY, AUTH_MODE_STAGED, AgentAuthState, AuthRequest,
    Mldsa44AuthModule, auth_request_commitment, build_auth_envelope, build_mldsa44_submit,
    build_stage_auth_message, read_byte_chain, sign_auth_request,
};
use contracts::native_registry::{
    NATIVE_REGISTRY_SIGNATURE_CONTEXT, native_public_key_from_seed, sign_ml_dsa_44,
};
use contracts::{AgentAccountContract, AgentAccountInit};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

#[path = "fixtures/current_network.rs"]
mod current_network;

const TOS: u64 = 1_000_000_000;
const CONTROLLER_SECRET: [u8; 32] = [0x42; 32];
const MLDSA_SEED: [u8; 32] = [0x5d; 32];
const OTHER_MLDSA_SEED: [u8; 32] = [0x5e; 32];
const RELAY: u64 = 2 * TOS;
const ERR_BAD_NONCE: i32 = 1804;
const ERR_BAD_SEQNO: i32 = 1705;
const ERR_INSUFFICIENT_BALANCE: i32 = 1711;
const ERR_BAD_SIGNATURE: i32 = 1808;

struct Fixture {
    bc: Blockchain,
    owner: Treasury,
    relayer: Treasury,
    target: Treasury,
    account: MsgAddressInt,
    module: MsgAddressInt,
    global_id: i32,
}

/// What one executed transaction did.
#[derive(Debug)]
struct Outcome {
    aborted: bool,
    /// The compute phase committed state (a throw after commit() included).
    committed: bool,
    exit_code: Option<i32>,
    outbound: Vec<Message>,
}

fn outcome(transaction: &Transaction, outbound: Vec<Message>) -> Outcome {
    let TransactionDescr::Ordinary(description) =
        transaction.read_description().expect("description")
    else {
        panic!("expected an ordinary transaction");
    };
    let (committed, exit_code) = match description.compute_ph {
        TrComputePhase::Vm(vm) => (vm.success, Some(vm.exit_code)),
        TrComputePhase::Skipped(_) => (false, None),
    };
    Outcome { aborted: description.aborted, committed, exit_code, outbound }
}

/// Only integers: get_auth_state and the agent data counters.
fn integer_stack(stack: &[tos_vm::stack::StackItem]) -> common::tvm_stack_parser::TvmStackParser {
    use tl_api::tos::tvm::{
        Number, StackEntry, numberdecimal::NumberDecimal, stackentry::StackEntryNumber,
    };
    common::tvm_stack_parser::TvmStackParser::new(
        stack
            .iter()
            .map(|item| {
                let number = item.as_integer().expect("integer stack entry").to_string();
                StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
                    number: Number::Tvm_NumberDecimal(NumberDecimal { number }),
                })
            })
            .collect(),
    )
}

impl Fixture {
    fn new() -> Self {
        let mut bc =
            Blockchain::with_global_version(current_network::global_version()).expect("blockchain");
        bc.set_workchain(-1);
        let owner = bc.treasury("owner", 1_000 * TOS).expect("owner");
        let relayer = bc.treasury("relayer", 1_000 * TOS).expect("relayer");
        let target = bc.treasury("target", 1_000 * TOS).expect("target");
        let controller = ed25519_create_private_key(&CONTROLLER_SECRET).expect("controller key");
        let init = AgentAccountInit {
            owner: owner.address().clone(),
            controller_pubkey: controller.verifying_key(),
            deployment_id: [0x5a; 32],
            max_per_tx: 5 * TOS,
            daily_limit: 50 * TOS,
            default_task_timeout_secs: 3_600,
            metadata_hash: None,
            service_endpoint_hash: None,
        };
        let account = AgentAccountContract::calculate_address(-1, &init).expect("address");
        let deploy = MessageBuilder::internal(owner.address(), &account, 20 * TOS)
            .bounce(false)
            .state_init(AgentAccountContract::build_state_init(&init).expect("state init"))
            .body(chain_block::Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy account").expect_success();

        let global_id = match bc.config_params().config(19).expect("parameter 19") {
            Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
            other => panic!("parameter 19 is not the global id: {other:?}"),
        };
        let public_key = native_public_key_from_seed(&MLDSA_SEED);
        let module =
            Mldsa44AuthModule::calculate_address(-1, global_id, &public_key).expect("module");
        let deploy = MessageBuilder::internal(owner.address(), &module, TOS)
            .bounce(false)
            .state_init(
                Mldsa44AuthModule::build_state_init(global_id, &public_key).expect("module init"),
            )
            .body(chain_block::Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy module").expect_success();
        Self { bc, owner, relayer, target, account, module, global_id }
    }

    fn auth(&self) -> AgentAuthState {
        let result = self
            .bc
            .run_get_method(&self.account, "get_auth_state", vec![])
            .expect("get_auth_state")
            .expect_success()
            .stack
            .clone();
        AgentAuthState::decode(&integer_stack(&result)).expect("auth state")
    }

    /// (controller_epoch, seqno)
    fn counters(&self) -> (u64, u32) {
        let result = self
            .bc
            .run_get_method(&self.account, "get_agent_account_data", vec![])
            .expect("get_agent_account_data");
        result.expect_success();
        (
            u64::try_from(result.int_at(3)).expect("epoch"),
            u32::try_from(result.int_at(9)).expect("seqno"),
        )
    }

    fn balance(&self, address: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(address)
            .and_then(|account| account.balance().and_then(|cc| cc.coins.as_u64()))
            .unwrap_or(0)
    }

    fn stage(&mut self) {
        let before = self.auth();
        let (epoch, seqno) = self.counters();
        let body = build_stage_auth_message(1, self.global_id, before.epoch, &self.module)
            .expect("stage body");
        let message = MessageBuilder::internal(self.owner.address(), &self.account, TOS / 2)
            .body(body)
            .build();
        self.bc.send_message(message).expect("stage").expect_success();
        let after = self.auth();
        assert_eq!(after.mode, AUTH_MODE_STAGED);
        assert_eq!(after.epoch, before.epoch.checked_add(1).unwrap());
        assert_eq!(after.nonce, 0);
        assert_eq!(after.module_address(-1).unwrap(), Some(self.module.clone()));
        assert_eq!(
            self.counters(),
            (epoch.checked_add(1).unwrap(), seqno.checked_add(1).unwrap()),
            "staging advances the controller epoch and seqno"
        );
    }

    /// A kind-0 request for a native send of `value` to the target under the
    /// current counters, and its envelope.
    fn request(&self, value: u64, valid_until: u32) -> (chain_block::Cell, chain_block::Cell) {
        let auth = self.auth();
        let (epoch, seqno) = self.counters();
        let payload = AgentAccountContract::build_native_send_payload(
            self.global_id,
            epoch,
            seqno,
            valid_until,
            self.target.address(),
            value,
        )
        .expect("payload");
        let request = AuthRequest {
            global_id: self.global_id,
            account: self.account.clone(),
            epoch: auth.epoch,
            nonce: auth.nonce,
            valid_until,
            kind: AUTH_KIND_EXECUTE,
            payload,
        }
        .to_cell()
        .expect("request");
        let envelope = build_auth_envelope(&request).expect("envelope");
        (request, envelope)
    }

    fn submission(&self, value: u64) -> (chain_block::Cell, chain_block::Cell) {
        let (request, envelope) = self.request(value, self.bc.now().checked_add(600).unwrap());
        let signature = sign_auth_request(&MLDSA_SEED, &request).expect("signature");
        (build_mldsa44_submit(9, &envelope, &signature).expect("submit"), envelope)
    }

    /// The relayer's transaction at the module.
    fn relay(&mut self, body: chain_block::Cell, value: u64) -> Outcome {
        let message = MessageBuilder::internal(self.relayer.address(), &self.module, value)
            .body(body)
            .build();
        let (address, transaction, outbound) = self.bc.execute_one(message).expect("relay");
        assert_eq!(address, self.module);
        outcome(&transaction, outbound)
    }

    /// Delivers the module's one forwarded message to the account.
    fn deliver(&mut self, relayed: &Outcome, envelope: &chain_block::Cell) -> Outcome {
        assert!(!relayed.aborted, "the module must accept before anything is forwarded");
        assert_eq!(relayed.outbound.len(), 1, "a successful module forwards exactly one message");
        let message = relayed.outbound[0].clone();
        assert_eq!(message.dst().as_ref(), Some(&self.account));
        // The module stores the envelope as the referenced body.
        let body = message.body().cloned().expect("relay body").into_cell().expect("body cell");
        assert_eq!(body.repr_hash(), envelope.repr_hash(), "the module relays the exact envelope");
        let (address, transaction, outbound) = self.bc.execute_one(message).expect("deliver");
        assert_eq!(address, self.account);
        outcome(&transaction, outbound)
    }

    fn transfers_to_target(&self, outcome: &Outcome) -> Vec<u64> {
        outcome
            .outbound
            .iter()
            .filter(|message| message.dst().as_ref() == Some(self.target.address()))
            .map(|message| message.int_header().expect("internal").value.coins.as_u64().unwrap())
            .collect()
    }

    /// One Ed25519 controller native send, consuming the current seqno.
    fn ed25519_native_send(&mut self, value: u64) {
        let (epoch, seqno) = self.counters();
        let payload = AgentAccountContract::build_native_send_payload(
            self.global_id,
            epoch,
            seqno,
            self.bc.now().checked_add(600).unwrap(),
            self.target.address(),
            value,
        )
        .expect("payload");
        let hash =
            AgentAccountContract::controller_hash_to_sign(&self.account, self.global_id, &payload)
                .expect("hash");
        let signature = ed25519_create_private_key(&CONTROLLER_SECRET).expect("key").sign(&hash);
        let signed = AgentAccountContract::build_signed_controller_message(payload, &signature)
            .expect("signed");
        let message = MessageBuilder::external(&self.account)
            .body_slice(SliceData::load_cell(signed).expect("slice"))
            .build();
        self.bc.send_message(message).expect("controller send").expect_success();
        assert_eq!(self.counters().1, seqno.checked_add(1).unwrap());
    }
}

#[test]
fn the_module_config_and_address_are_what_the_sdk_derives() {
    let f = Fixture::new();
    let result =
        f.bc.run_get_method(&f.module, "get_mldsa44_config", vec![]).expect("get_mldsa44_config");
    result.expect_success();
    assert_eq!(i32::try_from(result.int_at(0)).unwrap(), f.global_id);
    assert_eq!(
        read_byte_chain(&result.cell_at(1), 1312).unwrap(),
        native_public_key_from_seed(&MLDSA_SEED)
    );
    let code_hash = f.bc.get_account(&f.module).unwrap().get_code().unwrap().repr_hash();
    assert_eq!(code_hash, Mldsa44AuthModule::code().unwrap().repr_hash());
    assert_eq!(f.auth().mode, AUTH_MODE_LEGACY);
}

#[test]
fn a_staged_module_executes_one_native_send_and_refuses_its_replay() {
    let mut f = Fixture::new();
    // Stage from a nonzero seqno: the contract advances it, not resets it.
    f.ed25519_native_send(TOS / 10);
    f.stage();
    let (_, seqno) = f.counters();
    let target_before = f.balance(f.target.address());

    let (body, envelope) = f.submission(TOS);
    let relayed = f.relay(body.clone(), RELAY);
    let delivered = f.deliver(&relayed, &envelope);
    assert!(!delivered.aborted, "{delivered:?}");
    assert_eq!(f.transfers_to_target(&delivered), vec![TOS], "exactly the signed transfer");
    assert_eq!(f.auth().nonce, 1);
    assert_eq!(f.counters().1, seqno.checked_add(1).unwrap());
    let transfer = delivered.outbound[0].clone();
    f.bc.execute_one(transfer).expect("transfer arrives");
    assert!(f.balance(f.target.address()) > target_before);

    // The same submission verifies at the module again, but the account
    // refuses the consumed nonce: no second transfer, counters unchanged.
    let replayed = f.relay(body, RELAY);
    let refused = f.deliver(&replayed, &envelope);
    assert!(refused.aborted && !refused.committed);
    assert_eq!(refused.exit_code, Some(ERR_BAD_NONCE));
    assert!(f.transfers_to_target(&refused).is_empty());
    assert_eq!(f.auth().nonce, 1);
    assert_eq!(f.counters().1, seqno.checked_add(1).unwrap());
}

#[test]
fn the_module_refuses_another_key_another_context_and_too_little_funding() {
    let mut f = Fixture::new();
    f.stage();
    let valid_until = f.bc.now().checked_add(600).unwrap();
    let (request, envelope) = f.request(TOS, valid_until);
    let commitment = auth_request_commitment(&request).unwrap();

    let other_key = sign_auth_request(&OTHER_MLDSA_SEED, &request).unwrap();
    let other_context = sign_ml_dsa_44(&MLDSA_SEED, &commitment, NATIVE_REGISTRY_SIGNATURE_CONTEXT)
        .unwrap()
        .signature;
    for (label, signature) in [("another key", other_key), ("another context", other_context)] {
        let refused = f.relay(build_mldsa44_submit(9, &envelope, &signature).unwrap(), RELAY);
        assert!(refused.aborted, "{label}");
        assert_eq!(refused.exit_code, Some(ERR_BAD_SIGNATURE), "{label}");
        assert!(
            refused.outbound.iter().all(|m| m.dst().as_ref() != Some(&f.account)),
            "{label}: nothing reaches the account"
        );
    }

    // Too little funding for verification: the module cannot finish, nothing
    // is forwarded.
    let good = sign_auth_request(&MLDSA_SEED, &request).unwrap();
    let body = build_mldsa44_submit(9, &envelope, &good).unwrap();
    let starved = f.relay(body.clone(), TOS / 1_000);
    assert!(starved.aborted, "{starved:?}");
    assert!(starved.outbound.iter().all(|m| m.dst().as_ref() != Some(&f.account)));
    assert_eq!(f.auth().nonce, 0);

    // Positive control in the same state.
    let relayed = f.relay(body, RELAY);
    let delivered = f.deliver(&relayed, &envelope);
    assert!(!delivered.aborted, "{delivered:?}");
    assert_eq!(f.transfers_to_target(&delivered), vec![TOS]);
}

#[test]
fn a_controller_action_that_takes_the_sequence_first_wins() {
    let mut f = Fixture::new();
    f.stage();
    let (body, envelope) = f.submission(TOS);
    // The Ed25519 controller consumes the seqno the request was signed for.
    f.ed25519_native_send(TOS / 10);
    let relayed = f.relay(body, RELAY);
    let refused = f.deliver(&relayed, &envelope);
    assert!(refused.aborted && !refused.committed, "{refused:?}");
    assert_eq!(refused.exit_code, Some(ERR_BAD_SEQNO));
    assert!(f.transfers_to_target(&refused).is_empty());
    assert_eq!(f.auth().nonce, 0, "a refused request leaves the auth nonce unspent");
}

#[test]
fn a_refusal_after_acceptance_consumes_the_counters_without_a_transfer() {
    let mut f = Fixture::new();
    f.stage();
    let (_, seqno) = f.counters();
    let value = 4 * TOS;
    let (body, envelope) = f.submission(value);
    let relayed = f.relay(body, RELAY);
    let forwarded = relayed.outbound[0].int_header().unwrap().value.coins.as_u64().unwrap();
    // Leave the account just enough for the transfer itself but not for its
    // fee reserve: the cheap pre-accept floor passes, the exact reserve after
    // acceptance does not.
    let mut account = f.bc.get_account(&f.account).unwrap().clone();
    let balance = value.checked_sub(forwarded).unwrap().checked_add(1_000).unwrap();
    account.set_balance(CurrencyCollection::with_coins(balance));
    f.bc.set_account(f.account.clone(), account);

    let refused = f.deliver(&relayed, &envelope);
    assert_eq!(refused.exit_code, Some(ERR_INSUFFICIENT_BALANCE), "{refused:?}");
    assert!(refused.committed, "the refusal comes after commit(): the state is committed");
    assert!(f.transfers_to_target(&refused).is_empty(), "{refused:?}");
    assert_eq!(f.counters().1, seqno.checked_add(1).unwrap(), "the seqno was committed");
    assert_eq!(f.auth().nonce, 1, "the auth nonce was committed");
}
