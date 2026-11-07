/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The gated strict reconfiguration of an ML-DSA-44 Agent Account
//! (`contracts::agent_account_reconfigure`), run as the CLI runs it, against
//! the embedded account and module bytecode: the cutover to mode 2, the
//! strict rotation of the root, every refusal, and every interruption point.
//! A refusal is asserted with its message, unchanged account data, and no
//! signature and no relay where it precedes them.

use chain_block::{
    BuilderData, Cell, IBitstring, Message, MsgAddressInt, Serializable, SliceData, TrComputePhase,
    TransactionDescr, ed25519_create_private_key, write_boc,
};
use contracts::agent_account_auth::{
    AUTH_KIND_EXECUTE, AUTH_MODE_LEGACY, AUTH_MODE_MODULE_ONLY, AUTH_MODE_STAGED,
    AgentAccountState, AuthRequest, ConfigureRequest, Mldsa44AuthConfig, Mldsa44AuthModule,
    build_auth_envelope, build_mldsa44_submit, build_stage_auth_message, read_byte_chain,
    sign_auth_request,
};
use contracts::agent_account_custody::MLDSA44_NATIVE_SEND_ACTION_KIND;
use contracts::agent_account_reconfigure::{
    AccountSnapshot, ModuleView, PreparedRelay, Reconfiguration, ReconfigureChain,
    ReconfigureOutcome, ReconfigureRequest, check_state, reconfigure,
};
use contracts::native_registry::native_public_key_from_seed;
use contracts::{
    AgentAccountContract, AgentAccountCustodyJournal, AgentAccountInit, ControllerActionClaim,
};
use std::cell::{Cell as Counter, RefCell};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

#[path = "fixtures/current_network.rs"]
mod current_network;

const TOS: u64 = 1_000_000_000;
const CONTROLLER_SECRET: [u8; 32] = [0x42; 32];
const ROOT_SEED: [u8; 32] = [0x5d; 32];
const NEXT_SEED: [u8; 32] = [0x5e; 32];
const STRANGER_SEED: [u8; 32] = [0x5f; 32];
const RELAY: u64 = 2 * TOS;
const ERR_NOT_MODULE: i32 = 1800;
const ERR_BAD_MODE: i32 = 1806;
const ERR_LEGACY_DISABLED: i32 = 1807;

/// Where an injected failure interrupts the orchestration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Interrupt {
    None,
    /// The signer fails: after fencing, before anything is signed.
    Sign,
    /// The relaying wallet fails to build its message: after binding.
    PrepareRelay,
    /// The relay is sent and lands, then the run dies before it observes it.
    AfterBroadcast,
    /// The relay is lost on the way: nothing reaches the module.
    LostRelay,
}

struct Sandbox {
    bc: Blockchain,
    owner: Treasury,
    relayer: Treasury,
    target: Treasury,
    account: MsgAddressInt,
    global_id: i32,
}

impl Sandbox {
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
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy account").expect_success();
        let global_id = match bc.config_params().config(19).expect("parameter 19") {
            Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
            other => panic!("parameter 19 is not the global id: {other:?}"),
        };
        let mut sandbox = Self { bc, owner, relayer, target, account, global_id };
        sandbox.deploy_module(&ROOT_SEED);
        sandbox
    }

    fn module_of(&self, seed: &[u8; 32]) -> MsgAddressInt {
        Mldsa44AuthModule::calculate_address(-1, self.global_id, &native_public_key_from_seed(seed))
            .expect("module")
    }

    fn deploy_module(&mut self, seed: &[u8; 32]) {
        let public_key = native_public_key_from_seed(seed);
        let module = self.module_of(seed);
        let deploy = MessageBuilder::internal(self.owner.address(), &module, TOS)
            .bounce(false)
            .state_init(
                Mldsa44AuthModule::build_state_init(self.global_id, &public_key)
                    .expect("module init"),
            )
            .body(Cell::default())
            .build();
        self.bc.send_message(deploy).expect("deploy module").expect_success();
    }

    fn state(&self) -> AgentAccountState {
        let data = self.bc.get_account(&self.account).unwrap().get_data().unwrap();
        AgentAccountState::parse(&data).expect("account state")
    }

    fn data(&self) -> Cell {
        self.bc.get_account(&self.account).unwrap().get_data().unwrap()
    }

    fn stage(&mut self, seed: &[u8; 32]) {
        let before = self.state();
        let body =
            build_stage_auth_message(1, self.global_id, before.auth.epoch, &self.module_of(seed))
                .expect("stage body");
        let message = MessageBuilder::internal(self.owner.address(), &self.account, TOS / 2)
            .body(body)
            .build();
        self.bc.send_message(message).expect("stage").expect_success();
        assert_eq!(self.state().auth.mode, AUTH_MODE_STAGED);
    }

    /// Delivers `body` from the relayer treasury to `module`, then whatever
    /// the module forwards; returns the account's transaction exit code, if
    /// the account ran.
    fn relay(&mut self, module: &MsgAddressInt, body: Cell) -> Option<(bool, Option<i32>)> {
        let message =
            MessageBuilder::internal(self.relayer.address(), module, RELAY).body(body).build();
        let result = self.bc.send_message(message).expect("relay");
        result.transactions.iter().find(|(address, _)| address == &self.account).map(
            |(_, transaction)| {
                let TransactionDescr::Ordinary(description) =
                    transaction.read_description().expect("description")
                else {
                    panic!("ordinary transaction expected");
                };
                let exit = match description.compute_ph {
                    TrComputePhase::Vm(vm) => Some(vm.exit_code),
                    TrComputePhase::Skipped(_) => None,
                };
                (description.aborted, exit)
            },
        )
    }

    /// A kind-0 native send of `value` signed by `seed`, under the current counters.
    fn execute_submission(&self, seed: &[u8; 32], value: u64) -> Cell {
        let state = self.state();
        let valid_until = self.bc.now().checked_add(600).unwrap();
        let payload = AgentAccountContract::build_native_send_payload(
            self.global_id,
            state.controller_epoch,
            state.seqno,
            valid_until,
            self.target.address(),
            value,
        )
        .expect("payload");
        let request = AuthRequest {
            global_id: self.global_id,
            account: self.account.clone(),
            epoch: state.auth.epoch,
            nonce: state.auth.nonce,
            valid_until,
            kind: AUTH_KIND_EXECUTE,
            payload,
        }
        .to_cell()
        .expect("request");
        let signature = sign_auth_request(seed, &request).expect("signature");
        build_mldsa44_submit(9, &build_auth_envelope(&request).unwrap(), &signature).unwrap()
    }

    /// One module-authenticated native send through `seed`'s module.
    fn module_send(&mut self, seed: &[u8; 32]) -> Option<(bool, Option<i32>)> {
        let body = self.execute_submission(seed, TOS / 10);
        let module = self.module_of(seed);
        self.relay(&module, body)
    }

    /// One Ed25519 controller send; returns the external message's refusal, if any.
    fn ed25519_send(&mut self) -> Result<(), String> {
        let state = self.state();
        let payload = AgentAccountContract::build_native_send_payload(
            self.global_id,
            state.controller_epoch,
            state.seqno,
            self.bc.now().checked_add(600).unwrap(),
            self.target.address(),
            TOS / 10,
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
        match self.bc.send_message(message) {
            Ok(_) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// The orchestration's view of the sandbox: real bytecode, a treasury
/// relayer, the current root's seed; it counts signatures and relays.
struct SandboxChain {
    sandbox: RefCell<Sandbox>,
    seed: [u8; 32],
    relayer_can_pay: Counter<bool>,
    interrupt: Counter<Interrupt>,
    signatures: Counter<u32>,
    relays: Counter<u32>,
}

impl SandboxChain {
    fn new(sandbox: Sandbox, seed: [u8; 32]) -> Self {
        Self {
            sandbox: RefCell::new(sandbox),
            seed,
            relayer_can_pay: Counter::new(true),
            interrupt: Counter::new(Interrupt::None),
            signatures: Counter::new(0),
            relays: Counter::new(0),
        }
    }
}

impl ReconfigureChain for SandboxChain {
    async fn account(&self, account: &MsgAddressInt) -> anyhow::Result<AccountSnapshot> {
        let sandbox = self.sandbox.borrow();
        assert_eq!(account, &sandbox.account);
        Ok(AccountSnapshot {
            state: sandbox.state(),
            state_time: sandbox.bc.now(),
            default_task_timeout_secs: 3_600,
        })
    }

    async fn module(&self, module: &MsgAddressInt) -> anyhow::Result<ModuleView> {
        let sandbox = self.sandbox.borrow();
        let Some(account) = sandbox.bc.get_account(module) else {
            return Ok(ModuleView { active: false, code_hash: None, config: None });
        };
        let code_hash = account.get_code().map(|code| code.repr_hash());
        let result = sandbox
            .bc
            .run_get_method(module, "get_mldsa44_config", vec![])
            .expect("get_mldsa44_config");
        result.expect_success();
        let config = Mldsa44AuthConfig {
            global_id: i32::try_from(result.int_at(0)).unwrap(),
            public_key: read_byte_chain(&result.cell_at(1), 1312).unwrap(),
        };
        Ok(ModuleView { active: true, code_hash, config: Some(config) })
    }

    async fn check_relayer(&self, _body: &Cell, _amount: u64) -> anyhow::Result<MsgAddressInt> {
        anyhow::ensure!(self.relayer_can_pay.get(), "the relaying wallet cannot pay");
        Ok(self.sandbox.borrow().relayer.address().clone())
    }

    async fn sign(&self, request: &Cell) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(self.interrupt.get() != Interrupt::Sign, "the signer is unavailable");
        self.signatures.set(self.signatures.get().checked_add(1).unwrap());
        sign_auth_request(&self.seed, request)
    }

    async fn prepare_relay(
        &self,
        module: &MsgAddressInt,
        amount: u64,
        body: Cell,
    ) -> anyhow::Result<PreparedRelay> {
        anyhow::ensure!(
            self.interrupt.get() != Interrupt::PrepareRelay,
            "the relaying wallet is unavailable"
        );
        let sandbox = self.sandbox.borrow();
        let message =
            MessageBuilder::internal(sandbox.relayer.address(), module, amount).body(body).build();
        Ok(PreparedRelay {
            relayer: sandbox.relayer.address().clone(),
            wallet_message: write_boc(&message.serialize().unwrap()).unwrap(),
        })
    }

    async fn broadcast(
        &self,
        relay: &PreparedRelay,
        _module: &MsgAddressInt,
    ) -> anyhow::Result<()> {
        self.relays.set(self.relays.get().checked_add(1).unwrap());
        if self.interrupt.get() == Interrupt::LostRelay {
            return Ok(());
        }
        let cell = chain_block::read_single_root_boc(&relay.wallet_message).unwrap();
        let message = <Message as chain_block::Deserializable>::construct_from_cell(cell).unwrap();
        self.sandbox.borrow_mut().bc.send_message(message).expect("relay");
        anyhow::ensure!(
            self.interrupt.get() != Interrupt::AfterBroadcast,
            "the run died after sending"
        );
        Ok(())
    }

    async fn pause(&self, _attempt: u32) -> bool {
        false
    }
}

fn journal() -> (tempfile::TempDir, AgentAccountCustodyJournal) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let journal =
        AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
    (directory, journal)
}

fn token(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn cutover(chain: &SandboxChain) -> ReconfigureRequest {
    let sandbox = chain.sandbox.borrow();
    ReconfigureRequest {
        change: Reconfiguration::Cutover,
        mode: AUTH_MODE_MODULE_ONLY,
        confirm_account: sandbox.account.to_string(),
        account: sandbox.account.clone(),
        global_id: sandbox.global_id,
        module: sandbox.module_of(&chain.seed),
        public_key: native_public_key_from_seed(&chain.seed),
        valid_until: sandbox.bc.now().checked_add(600).unwrap(),
        relay_amount: RELAY,
        recover_interrupted: false,
        query_id: 7,
        owner_token: token('c'),
    }
}

fn rotation(chain: &SandboxChain, next: &[u8; 32]) -> ReconfigureRequest {
    let module = chain.sandbox.borrow().module_of(next);
    ReconfigureRequest {
        change: Reconfiguration::Rotate { module, public_key: native_public_key_from_seed(next) },
        owner_token: token('d'),
        ..cutover(chain)
    }
}

/// A staged account whose module already authenticated one real request.
fn staged_and_used() -> SandboxChain {
    let mut sandbox = Sandbox::new();
    sandbox.stage(&ROOT_SEED);
    let (aborted, exit) = sandbox.module_send(&ROOT_SEED).expect("delivered");
    assert!(!aborted && exit == Some(0), "the staged module's request applies");
    assert_eq!(sandbox.state().auth.nonce, 1);
    SandboxChain::new(sandbox, ROOT_SEED)
}

/// Runs `request` and requires the refusal `expected`, with the account
/// data, the signatures and the relays unchanged.
async fn refused(
    chain: &SandboxChain,
    journal: &AgentAccountCustodyJournal,
    request: &ReconfigureRequest,
    expected: &str,
) {
    let data = chain.sandbox.borrow().data();
    let (signatures, relays) = (chain.signatures.get(), chain.relays.get());
    let error = reconfigure(chain, journal, request).await.expect_err(expected).to_string();
    assert!(error.contains(expected), "expected {expected:?}, got {error:?}");
    assert_eq!(chain.sandbox.borrow().data(), data, "{expected}: account data unchanged");
    assert_eq!(chain.signatures.get(), signatures, "{expected}: nothing signed");
    assert_eq!(chain.relays.get(), relays, "{expected}: nothing relayed");
}

fn landed(outcome: ReconfigureOutcome) -> AgentAccountState {
    match outcome {
        ReconfigureOutcome::Landed { after, .. } => after,
        other => panic!("expected this run to land the change: {other:?}"),
    }
}

#[tokio::test]
async fn a_cutover_lands_mode_two_and_ends_every_classical_authority() {
    let chain = staged_and_used();
    let (_directory, journal) = journal();
    let before = chain.sandbox.borrow().state();
    let after = landed(reconfigure(&chain, &journal, &cutover(&chain)).await.unwrap());
    assert_eq!(after.auth.mode, AUTH_MODE_MODULE_ONLY);
    assert_eq!(after.auth.epoch, before.auth.epoch.checked_add(1).unwrap());
    assert_eq!(after.auth.nonce, 0);
    assert_eq!(after.auth.module_hash, before.auth.module_hash, "the staged module is the root");
    assert_eq!((chain.signatures.get(), chain.relays.get()), (1, 1));
    // The fence is lifted: the next module send is admitted by the journal.
    assert!(
        journal
            .controller_epoch_change(
                &after_account(&chain),
                chain.sandbox.borrow().global_id,
                &hex::encode([0x5a; 32])
            )
            .unwrap()
            .is_none()
    );

    let mut sandbox = chain.sandbox.borrow_mut();
    // The Ed25519 controller is refused.
    let error = sandbox.ed25519_send().expect_err("legacy controller in strict mode");
    assert!(error.contains(&format!("exit code: {ERR_LEGACY_DISABLED}")), "{error}");
    // The owner can no longer stage a module.
    let stage = build_stage_auth_message(
        2,
        sandbox.global_id,
        after.auth.epoch,
        &sandbox.module_of(&NEXT_SEED),
    )
    .unwrap();
    let message = MessageBuilder::internal(sandbox.owner.address(), &sandbox.account, TOS / 2)
        .body(stage)
        .build();
    let result = sandbox.bc.send_message(message).expect("owner stage");
    let refusal = result.transactions.iter().find(|(address, _)| address == &sandbox.account).map(
        |(_, tx)| match tx.read_description().unwrap() {
            TransactionDescr::Ordinary(d) => match d.compute_ph {
                TrComputePhase::Vm(vm) => vm.exit_code,
                TrComputePhase::Skipped(_) => -1,
            },
            _ => -1,
        },
    );
    assert_eq!(refusal, Some(ERR_LEGACY_DISABLED));
    // The root still authenticates a native send.
    let (aborted, exit) = sandbox.module_send(&ROOT_SEED).expect("delivered");
    assert!(!aborted && exit == Some(0));
}

fn after_account(chain: &SandboxChain) -> String {
    chain.sandbox.borrow().account.to_string()
}

#[tokio::test]
async fn a_downgrade_to_staged_is_refused_by_the_account() {
    let chain = staged_and_used();
    let (_directory, journal) = journal();
    landed(reconfigure(&chain, &journal, &cutover(&chain)).await.unwrap());
    let mut sandbox = chain.sandbox.borrow_mut();
    // A kind-1 request to mode 1, signed by the root itself: the CLI never
    // builds it, and the account refuses it.
    let state = sandbox.state();
    let module = sandbox.module_of(&ROOT_SEED);
    let mut payload = BuilderData::new();
    payload.append_bits(1, 2).unwrap();
    module.write_to(&mut payload).unwrap();
    let mut request = BuilderData::new();
    request.append_i32(sandbox.global_id).unwrap();
    sandbox.account.write_to(&mut request).unwrap();
    request.append_u64(state.auth.epoch).unwrap();
    request.append_u64(state.auth.nonce).unwrap();
    request.append_u32(sandbox.bc.now().checked_add(600).unwrap()).unwrap();
    request.append_u8(1).unwrap();
    request.checked_append_reference(payload.into_cell().unwrap()).unwrap();
    let request = request.into_cell().unwrap();
    let signature = sign_auth_request(&ROOT_SEED, &request).unwrap();
    let body =
        build_mldsa44_submit(3, &build_auth_envelope(&request).unwrap(), &signature).unwrap();
    let (aborted, exit) = sandbox.relay(&module, body).expect("delivered");
    assert!(aborted && exit == Some(ERR_BAD_MODE), "{exit:?}");
    assert_eq!(sandbox.state().auth.mode, AUTH_MODE_MODULE_ONLY);
}

#[tokio::test]
async fn a_strict_rotation_moves_the_root_and_the_old_root_is_refused() {
    let chain = staged_and_used();
    let (_directory, journal) = journal();
    landed(reconfigure(&chain, &journal, &cutover(&chain)).await.unwrap());
    chain.sandbox.borrow_mut().deploy_module(&NEXT_SEED);
    let before = chain.sandbox.borrow().state();
    let after = landed(reconfigure(&chain, &journal, &rotation(&chain, &NEXT_SEED)).await.unwrap());
    assert_eq!(after.auth.mode, AUTH_MODE_MODULE_ONLY);
    assert_eq!(after.auth.epoch, before.auth.epoch.checked_add(1).unwrap());
    let next_module = chain.sandbox.borrow().module_of(&NEXT_SEED);
    assert_eq!(after.auth.module_address(-1).unwrap(), Some(next_module));

    let mut sandbox = chain.sandbox.borrow_mut();
    // A fresh request signed by the old root, through the old module: the
    // module verifies it, the account refuses its sender.
    let (aborted, exit) = sandbox.module_send(&ROOT_SEED).expect("delivered");
    assert!(aborted && exit == Some(ERR_NOT_MODULE), "{exit:?}");
    // The new root sends.
    let (aborted, exit) = sandbox.module_send(&NEXT_SEED).expect("delivered");
    assert!(!aborted && exit == Some(0), "{exit:?}");
}

#[tokio::test]
async fn every_gate_refuses_before_anything_is_fenced_signed_or_relayed() {
    let chain = staged_and_used();
    let (_directory, journal) = journal();
    let account = chain.sandbox.borrow().account.to_string();
    let base = cutover(&chain);
    for (mode, expected) in
        [(1, "mode 1 is refused"), (3, "mode 3 is refused"), (0, "mode 0 is refused")]
    {
        refused(&chain, &journal, &ReconfigureRequest { mode, ..base.clone() }, expected).await;
    }
    // The typed address must be exactly the account's.
    let mut one_off = account.clone().into_bytes();
    let last = one_off.len().checked_sub(1).unwrap();
    one_off[last] = if one_off[last] == b'0' { b'1' } else { b'0' };
    let parsed = chain.sandbox.borrow().account.clone();
    for typed in [
        String::from_utf8(one_off).unwrap(),
        account.to_uppercase(),
        format!(" {account}"),
        String::new(),
        parsed.to_string().replacen("-1:", "-1:0", 1),
    ] {
        if typed == account {
            continue;
        }
        refused(
            &chain,
            &journal,
            &ReconfigureRequest { confirm_account: typed, ..base.clone() },
            "--confirm-account must be exactly",
        )
        .await;
    }
    // Another controller's module is not the staged root.
    let stranger = chain.sandbox.borrow().module_of(&STRANGER_SEED);
    refused(
        &chain,
        &journal,
        &ReconfigureRequest {
            module: stranger,
            public_key: native_public_key_from_seed(&STRANGER_SEED),
            ..base.clone()
        },
        "not this controller's ML-DSA-44 module",
    )
    .await;
    // A rotation from staged mode is refused: cut over first.
    chain.sandbox.borrow_mut().deploy_module(&NEXT_SEED);
    refused(&chain, &journal, &rotation(&chain, &NEXT_SEED), "not strict mode 2").await;
    // Expired and too-long windows.
    let now = chain.sandbox.borrow().bc.now();
    refused(
        &chain,
        &journal,
        &ReconfigureRequest { valid_until: now, ..base.clone() },
        "valid_until must be after",
    )
    .await;
    refused(
        &chain,
        &journal,
        &ReconfigureRequest { valid_until: now.checked_add(3_601).unwrap(), ..base.clone() },
        "more than 3600 seconds",
    )
    .await;
    // A relayer that cannot pay.
    chain.relayer_can_pay.set(false);
    refused(&chain, &journal, &base, "cannot pay").await;
    chain.relayer_can_pay.set(true);
    // Neighbouring success, in the same state.
    landed(reconfigure(&chain, &journal, &base).await.unwrap());
}

#[tokio::test]
async fn a_legacy_account_or_an_unused_staged_module_is_refused() {
    // Nothing staged.
    let chain = SandboxChain::new(Sandbox::new(), ROOT_SEED);
    let (_directory, journal) = journal();
    assert_eq!(chain.sandbox.borrow().state().auth.mode, AUTH_MODE_LEGACY);
    refused(&chain, &journal, &cutover(&chain), "has no staged module").await;
    // Staged, but the module never authenticated a request.
    chain.sandbox.borrow_mut().stage(&ROOT_SEED);
    refused(&chain, &journal, &cutover(&chain), "has not authenticated a request").await;
    // One real request later the same cutover lands.
    let (aborted, exit) = chain.sandbox.borrow_mut().module_send(&ROOT_SEED).expect("delivered");
    assert!(!aborted && exit == Some(0));
    landed(reconfigure(&chain, &journal, &cutover(&chain)).await.unwrap());
    // Already strict: a second cutover is refused.
    refused(
        &chain,
        &journal,
        &ReconfigureRequest { owner_token: token('e'), ..cutover(&chain) },
        "already in strict authentication mode 2",
    )
    .await;
    // A rotation to the root already installed is refused.
    refused(&chain, &journal, &rotation(&chain, &ROOT_SEED), "already installed").await;
    // A rotation to a module that is not deployed, or holds another key.
    refused(&chain, &journal, &rotation(&chain, &NEXT_SEED), "is not active").await;
    chain.sandbox.borrow_mut().deploy_module(&NEXT_SEED);
    let wrong_key = ReconfigureRequest {
        change: Reconfiguration::Rotate {
            module: chain.sandbox.borrow().module_of(&NEXT_SEED),
            public_key: native_public_key_from_seed(&STRANGER_SEED),
        },
        ..rotation(&chain, &NEXT_SEED)
    };
    refused(&chain, &journal, &wrong_key, "holds another ML-DSA-44 key").await;
    landed(reconfigure(&chain, &journal, &rotation(&chain, &NEXT_SEED)).await.unwrap());
}

fn open_claim(chain: &SandboxChain, seqno: u32) -> ControllerActionClaim {
    let sandbox = chain.sandbox.borrow();
    let state = sandbox.state();
    ControllerActionClaim {
        account: sandbox.account.to_string(),
        network_global_id: sandbox.global_id,
        network_domain: Some(chain_rpc_client::v2::data_models::RelayNetworkDomainPin {
            network_id: format!("tos:global-id:{}", sandbox.global_id),
            global_id: sandbox.global_id,
            zero_state_root_hash: format!("sha256:{}", "a".repeat(64)),
            zero_state_file_hash: format!("sha256:{}", "b".repeat(64)),
            workchain_id: -1,
        }),
        deployment_id: hex::encode(state.deployment_id),
        controller_epoch: state.controller_epoch,
        seqno,
        target: sandbox.target.address().to_string(),
        value_atomic: 1,
        body_hash: None,
        state_init_hash: None,
        action_kind: MLDSA44_NATIVE_SEND_ACTION_KIND.to_owned(),
        idempotency_key: "9".repeat(64),
        action_identity: format!("sha256:{}", "9".repeat(64)),
        valid_until: 2_000_000_000,
        auth_module: Some(sandbox.module_of(&ROOT_SEED).to_string()),
    }
}

#[tokio::test]
async fn an_open_custody_action_or_another_fence_refuses_the_cutover() {
    let chain = staged_and_used();
    let (_directory, journal) = journal();
    let seqno = chain.sandbox.borrow().state().seqno;
    journal.claim_primary(open_claim(&chain, seqno), 10).unwrap();
    refused(&chain, &journal, &cutover(&chain), "are unresolved").await;

    let (_other, fenced) = self::journal();
    let state = chain.sandbox.borrow().state();
    fenced
        .begin_controller_epoch_change(
            &after_account(&chain),
            chain.sandbox.borrow().global_id,
            &hex::encode(state.deployment_id),
            state.controller_epoch,
            state.seqno,
            state.auth.epoch,
            &[0x77; 32],
            &token('f'),
        )
        .unwrap();
    refused(&chain, &fenced, &cutover(&chain), "still fenced").await;
}

#[tokio::test]
async fn a_failure_before_the_bind_releases_the_fence_and_nothing_was_signed() {
    let chain = staged_and_used();
    let (_directory, journal) = journal();
    chain.interrupt.set(Interrupt::Sign);
    let data = chain.sandbox.borrow().data();
    assert!(reconfigure(&chain, &journal, &cutover(&chain)).await.is_err());
    assert_eq!(chain.sandbox.borrow().data(), data);
    assert_eq!((chain.signatures.get(), chain.relays.get()), (0, 0));
    // No fence is left: the next run lands.
    chain.interrupt.set(Interrupt::None);
    landed(reconfigure(&chain, &journal, &cutover(&chain)).await.unwrap());
}

#[tokio::test]
async fn a_bound_fence_holds_until_expiry_and_is_never_lifted_early() {
    let chain = staged_and_used();
    let (_directory, journal) = journal();
    chain.interrupt.set(Interrupt::PrepareRelay);
    let request = cutover(&chain);
    assert!(reconfigure(&chain, &journal, &request).await.is_err());
    assert_eq!((chain.signatures.get(), chain.relays.get()), (1, 0));
    chain.interrupt.set(Interrupt::None);
    // Sends are refused while it is held.
    let seqno = chain.sandbox.borrow().state().seqno;
    assert!(journal.claim_primary(open_claim(&chain, seqno), 10).is_err());
    // A re-run without recovery is refused, and signs nothing.
    let rerun = ReconfigureRequest { owner_token: token('e'), ..cutover(&chain) };
    refused(&chain, &journal, &rerun, "still fenced").await;
    // Recovery before the expiry is refused, through the orchestration and
    // through the journal recovery install uses.
    let recover = ReconfigureRequest { recover_interrupted: true, ..rerun.clone() };
    refused(&chain, &journal, &recover, "may still land until").await;
    let state = chain.sandbox.borrow().state();
    let now = chain.sandbox.borrow().bc.now();
    assert!(
        journal
            .recover_controller_epoch_change(
                &after_account(&chain),
                chain.sandbox.borrow().global_id,
                &hex::encode(state.deployment_id),
                &state,
                now,
            )
            .is_err()
    );
    assert!(
        journal
            .end_controller_epoch_change(
                &after_account(&chain),
                chain.sandbox.borrow().global_id,
                &hex::encode(state.deployment_id),
                state.controller_epoch,
                state.seqno,
                None,
            )
            .is_err()
    );
    // Past the expiry the recovery lifts it, and a fresh cutover lands.
    chain.sandbox.borrow_mut().bc.set_now(request.valid_until.checked_add(1).unwrap());
    let fresh = ReconfigureRequest {
        valid_until: request.valid_until.checked_add(600).unwrap(),
        ..recover
    };
    landed(reconfigure(&chain, &journal, &fresh).await.unwrap());
}

#[tokio::test]
async fn a_change_that_landed_unobserved_is_finished_without_a_resend() {
    let chain = staged_and_used();
    let (_directory, journal) = journal();
    chain.interrupt.set(Interrupt::AfterBroadcast);
    assert!(reconfigure(&chain, &journal, &cutover(&chain)).await.is_err());
    assert_eq!(chain.sandbox.borrow().state().auth.mode, AUTH_MODE_MODULE_ONLY);
    chain.interrupt.set(Interrupt::None);
    let rerun = ReconfigureRequest { owner_token: token('e'), ..cutover(&chain) };
    let outcome = reconfigure(&chain, &journal, &rerun).await.unwrap();
    assert!(matches!(outcome, ReconfigureOutcome::EarlierLanded { .. }), "{outcome:?}");
    assert_eq!((chain.signatures.get(), chain.relays.get()), (1, 1), "nothing resent");
    let seqno = chain.sandbox.borrow().state().seqno;
    let claim = ControllerActionClaim {
        controller_epoch: chain.sandbox.borrow().state().controller_epoch,
        ..open_claim(&chain, seqno)
    };
    journal.claim_primary(claim, 11).unwrap();
}

#[tokio::test]
async fn a_lost_relay_stays_fenced_until_it_expires() {
    let chain = staged_and_used();
    let (_directory, journal) = journal();
    chain.interrupt.set(Interrupt::LostRelay);
    let request = cutover(&chain);
    let error = reconfigure(&chain, &journal, &request).await.unwrap_err().to_string();
    assert!(error.contains("has not landed yet"), "{error}");
    assert_eq!(chain.sandbox.borrow().state().auth.mode, AUTH_MODE_STAGED);
    chain.interrupt.set(Interrupt::None);
    // The account's own stage path (install) cannot lift it early either.
    let state = chain.sandbox.borrow().state();
    let now = chain.sandbox.borrow().bc.now();
    assert!(
        journal
            .recover_controller_epoch_change(
                &after_account(&chain),
                chain.sandbox.borrow().global_id,
                &hex::encode(state.deployment_id),
                &state,
                now,
            )
            .is_err()
    );
    chain.sandbox.borrow_mut().bc.set_now(request.valid_until.checked_add(1).unwrap());
    assert_eq!(
        journal
            .recover_controller_epoch_change(
                &after_account(&chain),
                chain.sandbox.borrow().global_id,
                &hex::encode(state.deployment_id),
                &state,
                request.valid_until.checked_add(1).unwrap(),
            )
            .unwrap(),
        contracts::EpochChangeRecovery::Lifted
    );
}

#[test]
fn exhausted_counters_are_refused() {
    let sandbox = Sandbox::new();
    let chain = SandboxChain::new(sandbox, ROOT_SEED);
    let request = cutover(&chain);
    let module_hash: [u8; 32] = request.module.address().get_bytestring(0).try_into().unwrap();
    let staged = AgentAccountState {
        deployment_id: [0x5a; 32],
        controller_epoch: 3,
        seqno: 4,
        auth: contracts::agent_account_auth::AgentAuthState {
            mode: AUTH_MODE_STAGED,
            epoch: 2,
            nonce: 1,
            module_hash,
        },
    };
    let snapshot = |state| AccountSnapshot {
        state,
        state_time: request.valid_until.checked_sub(600).unwrap(),
        default_task_timeout_secs: 3_600,
    };
    check_state(&request, &snapshot(staged)).unwrap();
    let mut auth_epoch = staged;
    auth_epoch.auth.epoch = u64::MAX;
    let mut auth_nonce = staged;
    auth_nonce.auth.nonce = u64::MAX;
    for exhausted in [
        auth_epoch,
        auth_nonce,
        AgentAccountState { controller_epoch: u64::MAX, ..staged },
        AgentAccountState { seqno: u32::MAX, ..staged },
    ] {
        assert!(check_state(&request, &snapshot(exhausted)).is_err());
    }
    // The configure payload builder refuses a staged target.
    let configure = ConfigureRequest {
        global_id: request.global_id,
        account: request.account.clone(),
        epoch: 2,
        nonce: 1,
        valid_until: request.valid_until,
        mode: AUTH_MODE_STAGED,
        module: request.module.clone(),
    };
    assert!(configure.to_cell().is_err());
}
