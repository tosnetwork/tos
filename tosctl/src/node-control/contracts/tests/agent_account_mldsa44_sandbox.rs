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

use chain_block::{BuilderData, Deserializable, IBitstring, Serializable, write_boc};
use chain_block::{
    CurrencyCollection, Message, MsgAddressInt, SliceData, TrComputePhase, Transaction,
    TransactionDescr, ed25519_create_private_key,
};
use common::{WalletVersion, signer::Signer, tvm_stack_parser::TvmStackParser};
use contracts::agent_account_auth::{
    AUTH_KIND_EXECUTE, AUTH_MODE_LEGACY, AUTH_MODE_STAGED, AgentAccountState, AgentAuthState,
    AuthRequest, Mldsa44AuthModule, auth_request_commitment, build_auth_envelope,
    build_mldsa44_relay_wallet_message, build_mldsa44_submit, build_stage_auth_message,
    mldsa44_relay_body, read_byte_chain, request_superseded, sign_auth_request,
};
use contracts::native_registry::{
    NATIVE_REGISTRY_SIGNATURE_CONTEXT, native_public_key_from_seed, sign_ml_dsa_44,
};
use contracts::{
    AgentAccountContract, AgentAccountInit, ContractProvider, SmartContract, Wallet, WalletContract,
};
use ed25519_dalek::Signer as _;
use sha2::Digest as _;
use std::sync::Arc;
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

/// The raw account data, parsed as the resolver reads it from a proven snapshot.
fn account_state(f: &Fixture) -> AgentAccountState {
    let data = f.bc.get_account(&f.account).unwrap().get_data().unwrap();
    AgentAccountState::parse(&data).expect("account state")
}

/// Supersession, proven from the real account state: the controller takes the
/// request's sequence first, or an owner rotation advances the epoch. The old
/// envelope is refused if delivered afterwards, and a fresh request at the new
/// counters executes.
#[test]
fn a_superseded_request_is_proven_from_state_and_a_fresh_one_executes() {
    for rotation in [false, true] {
        let mut f = Fixture::new();
        f.stage();
        let signed_at = f.counters();
        let signed_auth = f.auth();
        let (body, envelope) = f.submission(TOS);
        let before = account_state(&f);
        assert!(!request_superseded(&before, signed_at.0, signed_at.1, signed_auth.epoch, 0));
        if rotation {
            let rotate = AgentAccountContract::build_rotate_controller_message(
                5,
                ed25519_create_private_key(&CONTROLLER_SECRET).unwrap().verifying_key(),
            )
            .unwrap();
            let message = MessageBuilder::internal(f.owner.address(), &f.account, TOS / 2)
                .body(rotate)
                .build();
            f.bc.send_message(message).expect("rotate").expect_success();
        } else {
            f.ed25519_native_send(TOS / 10);
        }
        let after = account_state(&f);
        assert_eq!(after.auth, f.auth(), "the parser agrees with get_auth_state");
        assert_eq!((after.controller_epoch, after.seqno), f.counters());
        assert!(
            request_superseded(&after, signed_at.0, signed_at.1, signed_auth.epoch, 0),
            "rotation={rotation}: counters moved, auth nonce unconsumed"
        );
        // The old envelope can never apply after supersession.
        let relayed = f.relay(body, RELAY);
        let refused = f.deliver(&relayed, &envelope);
        assert!(refused.aborted && !refused.committed, "{refused:?}");
        assert!(f.transfers_to_target(&refused).is_empty());
        assert!(request_superseded(
            &account_state(&f),
            signed_at.0,
            signed_at.1,
            signed_auth.epoch,
            0
        ));
        // A fresh request at the new counters executes.
        let (fresh, fresh_envelope) = f.submission(TOS);
        let relayed = f.relay(fresh, RELAY);
        let delivered = f.deliver(&relayed, &fresh_envelope);
        assert!(!delivered.aborted, "{delivered:?}");
        assert_eq!(f.transfers_to_target(&delivered), vec![TOS]);
    }
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
    assert!(!refused.aborted, "an empty action phase succeeds, so the transaction is not aborted");
    assert!(refused.outbound.is_empty(), "no bounce: the forwarded value stays in the account");
    assert!(f.transfers_to_target(&refused).is_empty(), "{refused:?}");
    assert_eq!(f.counters().1, seqno.checked_add(1).unwrap(), "the seqno was committed");
    assert_eq!(f.auth().nonce, 1, "the auth nonce was committed");
    // Even if this transaction were outside the history read, the moved
    // counters cannot be taken for supersession: the consumed nonce shows
    // the request was applied.
    let epoch = f.counters().0;
    assert!(!request_superseded(&account_state(&f), epoch, seqno, f.auth().epoch, 0));
}

/// Deterministic in-process signer standing in for the vault-backed one.
struct TestSigner(ed25519_dalek::SigningKey);

#[async_trait::async_trait]
impl Signer for TestSigner {
    async fn public_key(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.verifying_key().to_bytes().to_vec())
    }

    async fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

/// The sandbox has no RPC surface; every wallet message passes its seqno.
struct NoProvider;

#[async_trait::async_trait]
impl ContractProvider for NoProvider {
    async fn get_method(
        &self,
        _address: String,
        method: &str,
        _stack: Vec<tl_api::tos::tvm::StackEntry>,
    ) -> anyhow::Result<TvmStackParser> {
        anyhow::bail!("sandbox relays must not query get-method {method} through RPC")
    }

    async fn balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
        anyhow::bail!("sandbox relays must not query a balance through RPC")
    }
}

/// A deployed V5 wallet that relays; it is never the Agent Account owner.
struct RelayWallet {
    wallet: WalletContract,
    seqno: u32,
}

impl RelayWallet {
    fn address(&self) -> MsgAddressInt {
        self.wallet.address()
    }
}

/// The relay as it reached the module: the wallet's transaction and the one
/// message it sent there.
struct WalletRelay {
    wallet: Outcome,
    to_module: Message,
}

/// What the custody journal holds for a signed submission: exact bytes and digest.
fn journaled(body: &chain_block::Cell) -> (Vec<u8>, String) {
    let bytes = write_boc(body).expect("boc");
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&bytes)));
    (bytes, digest)
}

impl Fixture {
    /// Deploys a funded V5 wallet controlled by `secret` with one signed
    /// transfer, as a relaying operator's wallet would exist on chain.
    async fn relay_wallet(&mut self, secret: [u8; 32]) -> RelayWallet {
        let wallet = WalletContract::new(
            Box::new(TestSigner(ed25519_dalek::SigningKey::from_bytes(&secret))),
            WalletVersion::V5R1,
            0x2a,
            -1,
            self.global_id,
            Arc::new(NoProvider),
        )
        .await
        .expect("wallet");
        let address = wallet.address();
        assert_ne!(&address, self.owner.address(), "a relaying wallet is not the owner");
        let fund = self.owner.build_message(&address, 50 * TOS, false, None);
        self.bc.send_message(fund).expect("fund relaying wallet");
        let deploy = wallet
            .build_message(
                self.target.address().clone(),
                TOS / 100,
                chain_block::Cell::default(),
                false,
                Some(0),
                Some(wallet.state_init().await.expect("state init")),
                None,
            )
            .await
            .expect("deploy message");
        self.bc
            .send_message(Message::construct_from_cell(deploy).expect("external"))
            .expect("deploy relaying wallet")
            .expect_success();
        RelayWallet { wallet, seqno: 1 }
    }

    /// The relayer's signed wallet message for the journaled bytes, built by
    /// the same SDK calls the CLI makes, without sending it.
    async fn relay_message(
        &self,
        relayer: &RelayWallet,
        bytes: &[u8],
        digest: &str,
        value: u64,
    ) -> Message {
        let body = mldsa44_relay_body(bytes, digest).expect("journaled relay body");
        let boc = build_mldsa44_relay_wallet_message(
            &relayer.wallet,
            &self.module,
            value,
            body,
            Some(relayer.seqno),
        )
        .await
        .expect("relay wallet message");
        Message::construct_from_cell(chain_block::read_single_root_boc(&boc).expect("boc"))
            .expect("external message")
    }

    /// Executes a relay wallet message and returns the message it sent to the module.
    fn execute_wallet_relay(&mut self, relayer: &mut RelayWallet, message: Message) -> WalletRelay {
        let (address, transaction, outbound) = self.bc.execute_one(message).expect("wallet");
        assert_eq!(address, relayer.address());
        let wallet = outcome(&transaction, outbound);
        assert!(!wallet.aborted && wallet.committed, "{wallet:?}");
        relayer.seqno = relayer.seqno.checked_add(1).unwrap();
        let to_module: Vec<_> = wallet
            .outbound
            .iter()
            .filter(|message| message.dst().as_ref() == Some(&self.module))
            .cloned()
            .collect();
        assert_eq!(to_module.len(), 1, "the wallet sends exactly one relay");
        let to_module = to_module[0].clone();
        let header = to_module.int_header().expect("internal relay");
        assert_eq!(&header.src_ref().cloned(), &Some(relayer.address()), "from the relayer");
        assert!(header.bounce, "the relay is bounceable");
        WalletRelay { wallet, to_module }
    }

    /// Executes the module's transaction for a relay message.
    fn module_transaction(&mut self, message: Message) -> Outcome {
        let (address, transaction, outbound) = self.bc.execute_one(message).expect("module");
        assert_eq!(address, self.module);
        outcome(&transaction, outbound)
    }
}

fn body_bytes(message: &Message) -> Vec<u8> {
    write_boc(&message.body().cloned().expect("body").into_cell().expect("body cell")).expect("boc")
}

#[tokio::test]
async fn a_send_relayed_by_a_non_owner_wallet_applies() {
    let mut f = Fixture::new();
    f.stage();
    let mut relayer = f.relay_wallet([0x61; 32]).await;
    let (submission, envelope) = f.submission(TOS);
    let (bytes, digest) = journaled(&submission);
    let owner_before = f.balance(f.owner.address());
    let relayer_before = f.balance(&relayer.address());
    let target_before = f.balance(f.target.address());

    let message = f.relay_message(&relayer, &bytes, &digest, RELAY).await;
    let relay = f.execute_wallet_relay(&mut relayer, message);
    assert_eq!(body_bytes(&relay.to_module), bytes, "the module receives the journaled bytes");
    let relayed = f.module_transaction(relay.to_module);
    let delivered = f.deliver(&relayed, &envelope);
    assert!(!delivered.aborted, "{delivered:?}");
    assert_eq!(f.transfers_to_target(&delivered), vec![TOS], "exactly the signed transfer");
    f.bc.execute_one(delivered.outbound[0].clone()).expect("transfer arrives");
    assert!(f.balance(f.target.address()) > target_before);
    assert_eq!(f.auth().nonce, 1);

    // The relayer paid the relay value and its own fees; the owner nothing.
    let spent = relayer_before.checked_sub(f.balance(&relayer.address())).unwrap();
    assert!(spent > RELAY, "the relayer pays the relay and its fees: {spent}");
    assert!(relay.wallet.committed);
    assert_eq!(f.balance(f.owner.address()), owner_before, "the owner pays nothing");
}

#[tokio::test]
async fn a_rebroadcast_through_another_relayer_sends_identical_bytes() {
    let mut f = Fixture::new();
    f.stage();
    let mut first = f.relay_wallet([0x61; 32]).await;
    let mut second = f.relay_wallet([0x62; 32]).await;
    assert_ne!(first.address(), second.address());
    let (submission, envelope) = f.submission(TOS);
    let (bytes, digest) = journaled(&submission);

    // The first relayer's message is built and withheld.
    let withheld = f.relay_message(&first, &bytes, &digest, RELAY).await;
    // The second relayer relays the same journaled bytes, and they apply.
    let message = f.relay_message(&second, &bytes, &digest, RELAY).await;
    let relay = f.execute_wallet_relay(&mut second, message);
    let second_body = body_bytes(&relay.to_module);
    assert_eq!(second_body, bytes);
    let relayed = f.module_transaction(relay.to_module);
    let delivered = f.deliver(&relayed, &envelope);
    assert!(!delivered.aborted, "{delivered:?}");
    assert_eq!(f.transfers_to_target(&delivered), vec![TOS]);
    let (_, seqno) = f.counters();

    // The withheld message, sent late, carries byte-identical bytes; the
    // module verifies them again and the account refuses the consumed nonce.
    let relay = f.execute_wallet_relay(&mut first, withheld);
    assert_eq!(body_bytes(&relay.to_module), second_body, "byte-identical submission");
    let replayed = f.module_transaction(relay.to_module);
    let refused = f.deliver(&replayed, &envelope);
    assert!(refused.aborted && !refused.committed, "{refused:?}");
    assert_eq!(refused.exit_code, Some(ERR_BAD_NONCE));
    assert!(f.transfers_to_target(&refused).is_empty());
    assert_eq!(f.auth().nonce, 1);
    assert_eq!(f.counters().1, seqno);
}

#[tokio::test]
async fn a_relay_the_module_refuses_bounces_to_its_relayer() {
    let mut f = Fixture::new();
    f.stage();
    let mut relayer = f.relay_wallet([0x63; 32]).await;
    // Well funded but signed with another key: verification runs to the end
    // and refuses, and what it did not spend returns to the relaying wallet.
    let valid_until = f.bc.now().checked_add(600).unwrap();
    let (request, envelope) = f.request(TOS, valid_until);
    let forged = sign_auth_request(&OTHER_MLDSA_SEED, &request).unwrap();
    let (bytes, digest) = journaled(&build_mldsa44_submit(9, &envelope, &forged).unwrap());
    let message = f.relay_message(&relayer, &bytes, &digest, RELAY).await;
    let relay = f.execute_wallet_relay(&mut relayer, message);
    let refused = f.module_transaction(relay.to_module);
    assert!(refused.aborted, "{refused:?}");
    assert_eq!(refused.exit_code, Some(ERR_BAD_SIGNATURE));
    assert!(refused.outbound.iter().all(|m| m.dst().as_ref() != Some(&f.account)));
    let bounces: Vec<_> = refused
        .outbound
        .iter()
        .filter(|m| m.int_header().is_some_and(|header| header.bounced))
        .cloned()
        .collect();
    assert_eq!(bounces.len(), 1, "{refused:?}");
    assert_eq!(bounces[0].dst(), Some(relayer.address()), "the remainder returns to the relayer");
    let returned = bounces[0].int_header().unwrap().value.coins.as_u64().unwrap();
    assert!(returned > 0 && returned < RELAY, "{returned}");
    let before = f.balance(&relayer.address());
    f.bc.execute_one(bounces[0].clone()).expect("bounce arrives");
    assert!(f.balance(&relayer.address()) > before, "the relaying wallet is credited");
    assert_eq!(f.auth().nonce, 0);

    // Funding that runs out during verification leaves nothing to return.
    let (submission, _) = f.submission(TOS);
    let (bytes, digest) = journaled(&submission);
    let message = f.relay_message(&relayer, &bytes, &digest, TOS / 1_000).await;
    let relay = f.execute_wallet_relay(&mut relayer, message);
    let starved = f.module_transaction(relay.to_module);
    assert!(starved.aborted, "{starved:?}");
    assert!(starved.outbound.is_empty(), "{starved:?}");
    assert_eq!(f.auth().nonce, 0);
}

/// `request$_ global_id account epoch nonce valid_until kind payload`, built
/// raw so a field can take any structurally valid value, kinds 1 and 2 included.
struct RawRequest {
    global_id: i32,
    account: MsgAddressInt,
    epoch: u64,
    nonce: u64,
    valid_until: u32,
    kind: u8,
    payload: chain_block::Cell,
}

impl RawRequest {
    fn cell(&self) -> chain_block::Cell {
        let mut request = BuilderData::new();
        request.append_i32(self.global_id).unwrap();
        self.account.write_to(&mut request).unwrap();
        request.append_u64(self.epoch).unwrap();
        request.append_u64(self.nonce).unwrap();
        request.append_u32(self.valid_until).unwrap();
        request.append_u8(self.kind).unwrap();
        request.checked_append_reference(self.payload.clone()).unwrap();
        request.into_cell().unwrap()
    }
}

#[test]
fn a_relayer_cannot_change_any_signed_field() {
    let mut f = Fixture::new();
    f.stage();
    let auth = f.auth();
    let (epoch, seqno) = f.counters();
    let valid_until = f.bc.now().checked_add(600).unwrap();
    let payload = |value: u64, target: &MsgAddressInt, seqno: u32| {
        AgentAccountContract::build_native_send_payload(
            f.global_id,
            epoch,
            seqno,
            valid_until,
            target,
            value,
        )
        .unwrap()
    };
    let original = RawRequest {
        global_id: f.global_id,
        account: f.account.clone(),
        epoch: auth.epoch,
        nonce: auth.nonce,
        valid_until,
        kind: AUTH_KIND_EXECUTE,
        payload: payload(TOS, f.target.address(), seqno),
    };
    let signature = sign_auth_request(&MLDSA_SEED, &original.cell()).unwrap();
    let other_target = f.relayer.address().clone();
    let altered = |change: &dyn Fn(&mut RawRequest)| {
        let mut request = original.clone_fields();
        change(&mut request);
        request.cell()
    };
    let cases: Vec<(&str, chain_block::Cell, i32)> = vec![
        ("global_id", altered(&|r| r.global_id = r.global_id.wrapping_add(1)), 1801),
        ("account", altered(&|r| r.account = other_target.clone()), ERR_BAD_SIGNATURE),
        ("epoch", altered(&|r| r.epoch = r.epoch.checked_add(1).unwrap()), ERR_BAD_SIGNATURE),
        ("nonce", altered(&|r| r.nonce = r.nonce.checked_add(1).unwrap()), ERR_BAD_SIGNATURE),
        (
            "valid_until",
            altered(&|r| r.valid_until = r.valid_until.checked_sub(1).unwrap()),
            ERR_BAD_SIGNATURE,
        ),
        ("kind 1", altered(&|r| r.kind = 1), ERR_BAD_SIGNATURE),
        ("kind 2", altered(&|r| r.kind = 2), ERR_BAD_SIGNATURE),
        (
            "payload value",
            altered(&|r| {
                r.payload = payload(TOS.checked_add(1).unwrap(), f.target.address(), seqno)
            }),
            ERR_BAD_SIGNATURE,
        ),
        (
            "payload target",
            altered(&|r| r.payload = payload(TOS, &other_target, seqno)),
            ERR_BAD_SIGNATURE,
        ),
        (
            "payload seqno",
            altered(&|r| {
                r.payload = payload(TOS, f.target.address(), seqno.checked_add(1).unwrap())
            }),
            ERR_BAD_SIGNATURE,
        ),
    ];
    for (label, request, exit_code) in cases {
        let body =
            build_mldsa44_submit(9, &build_auth_envelope(&request).unwrap(), &signature).unwrap();
        let refused = f.relay(body, RELAY);
        assert!(refused.aborted, "{label}: {refused:?}");
        assert_eq!(refused.exit_code, Some(exit_code), "{label}");
        assert!(
            refused.outbound.iter().all(|m| m.dst().as_ref() != Some(&f.account)),
            "{label}: nothing reaches the account"
        );
        assert_eq!(f.auth(), auth, "{label}: auth state unchanged");
        assert_eq!(f.counters(), (epoch, seqno), "{label}: counters unchanged");
    }

    // A cosignature is not covered by the ML-DSA-44 signature: the module
    // verifies the request and forwards, and the account refuses it outside
    // mode 3.
    let request = original.cell();
    let mut cosigned = BuilderData::new();
    cosigned.append_u32(0x4155_5448).unwrap();
    cosigned.checked_append_reference(request.clone()).unwrap();
    cosigned.append_bit_one().unwrap();
    let mut cosignature = BuilderData::new();
    cosignature.append_raw(&[0x5a; 64], 512).unwrap();
    cosigned.checked_append_reference(cosignature.into_cell().unwrap()).unwrap();
    let cosigned = cosigned.into_cell().unwrap();
    let relayed = f.relay(build_mldsa44_submit(9, &cosigned, &signature).unwrap(), RELAY);
    let refused = f.deliver(&relayed, &cosigned);
    assert!(refused.aborted && !refused.committed, "{refused:?}");
    assert_eq!(refused.exit_code, Some(ERR_BAD_SIGNATURE));
    assert!(f.transfers_to_target(&refused).is_empty());
    assert_eq!(f.auth(), auth);

    // Positive control: the unsigned query_id is the relayer's to choose.
    let envelope = build_auth_envelope(&request).unwrap();
    let relayed = f.relay(build_mldsa44_submit(0xfeed, &envelope, &signature).unwrap(), RELAY);
    let delivered = f.deliver(&relayed, &envelope);
    assert!(!delivered.aborted, "{delivered:?}");
    assert_eq!(f.transfers_to_target(&delivered), vec![TOS]);
}

impl RawRequest {
    fn clone_fields(&self) -> Self {
        Self {
            global_id: self.global_id,
            account: self.account.clone(),
            epoch: self.epoch,
            nonce: self.nonce,
            valid_until: self.valid_until,
            kind: self.kind,
            payload: self.payload.clone(),
        }
    }
}
