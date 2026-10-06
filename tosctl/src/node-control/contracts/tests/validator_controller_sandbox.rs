/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Validator Controller v1, run rather than read.
//!
//! The controller is the root of a validator's authority. Its security property is
//! carried by its code, so what that code does has to be exercised: that an
//! authorisation only works once, only for this account, only on this network, only
//! while it is valid, and only under a real ML-DSA-44 signature from the root it holds;
//! and that a root rotation needs both the current root's authority and the successor's
//! proof that it exists.

use chain_block::{Cell, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};

const TOS: u64 = 1_000_000_000;
const CONTROLLER_OP: u32 = 0x5051_6361;
const CONTROLLER_CONTEXT: &[u8] = b"TOS-VALIDATOR-CONTROLLER-v1";
const KIND_SEND: u8 = 1;
const KIND_ROTATE_ROOT: u8 = 2;
const KIND_BIND_CONSENSUS: u8 = 3;

/// Request-bound stake relay and its forwarded stake.
const RELAY_OP: u32 = 0x5051_7232;
const STAKE_OP: u32 = 0x5051_7332;

const ERROR_WRONG_NETWORK: i32 = 91;
const ERROR_STALE_EPOCH: i32 = 92;
const ERROR_BAD_NONCE: i32 = 93;
const ERROR_EXPIRED: i32 = 94;
const ERROR_BAD_KIND: i32 = 95;
const ERROR_BAD_COSIGNATURE: i32 = 96;
const ERROR_BAD_ACTION: i32 = 97;
const ERROR_BAD_SIGNATURE: i32 = 98;
const ERROR_NOT_INTERNAL: i32 = 99;
const ERROR_NO_CONSENSUS_KEY: i32 = 100;
const ERROR_WRONG_CONSENSUS_KEY: i32 = 101;
const ERROR_RELAY_UNDERFUNDED: i32 = 102;
const ERROR_OWNER_NOT_MASTERCHAIN: i32 = 103;

fn repo_root() -> std::path::PathBuf {
    std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root")
            .to_path_buf()
    })
}

fn key_tool() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("PQ_KEY_TOOL") {
        return std::path::PathBuf::from(path);
    }
    for candidate in ["build-pq-key/tos-pq-key", "build/tos-pq-key"] {
        let path = repo_root().join(candidate);
        if path.exists() {
            return path;
        }
    }
    panic!("build crypto/pq/tools, or point PQ_KEY_TOOL at tos-pq-key");
}

fn run_key_tool(args: &[&str]) -> Vec<String> {
    let out =
        std::process::Command::new(key_tool()).args(args).output().expect("the key tool runs");
    assert!(out.status.success(), "the key tool failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).lines().map(|line| line.trim().to_string()).collect()
}

/// A post-quantum root key, held the way an operator would hold one.
struct RootKey {
    file: std::path::PathBuf,
    public_key: Vec<u8>,
}

impl RootKey {
    fn new(index: u8) -> Self {
        let file = std::env::temp_dir().join(format!("tos-controller-root-{index}.key"));
        if !file.exists() {
            // Generated under a name of this call's own and only then published by linking,
            // because these tests run on threads of one process: generating straight into
            // the shared name let two threads write it at once, and let a third read it
            // half-written. A name is not made unique by a process id when every racer
            // shares the process. The shared published name is deliberate -- generating an
            // ML-DSA key is slow and the tests only need the same key each time.
            static SCRATCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let scratch = SCRATCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mine = file.with_extension(format!("{}.{scratch}.tmp", std::process::id()));
            run_key_tool(&["keygen", mine.to_str().expect("path")]);
            match std::fs::hard_link(&mine, &file) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("the key could not be put in place: {e}"),
            }
            let _ = std::fs::remove_file(&mine);
        }
        let public_key =
            hex::decode(&run_key_tool(&["public", file.to_str().expect("path")])[0]).expect("hex");
        assert_eq!(public_key.len(), 1312);
        RootKey { file, public_key }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign_under(message, CONTROLLER_CONTEXT)
    }

    fn sign_under(&self, message: &[u8], context: &[u8]) -> Vec<u8> {
        let signature = hex::decode(
            &run_key_tool(&[
                "sign",
                self.file.to_str().expect("path"),
                &hex::encode(message),
                &hex::encode(context),
            ])[0],
        )
        .expect("hex");
        assert_eq!(signature.len(), 2420);
        signature
    }
}

fn stored(bytes: &[u8]) -> Cell {
    chain_block::pq_bytes::pack_pq_bytes(bytes, chain_block::pq_bytes::PQ_BYTES_HARD_MAX)
        .expect("bytes of admitted length")
}

fn controller_code() -> Cell {
    compile_func_with_stdlib(&[repo_root().join("crypto/smartcont/validator-controller-v1.fc")])
        .expect("the controller compiles")
}

fn controller_data(root: &RootKey, epoch: u64, nonce: u64) -> Cell {
    controller_data_bound(root, epoch, nonce, 0, &[0u8; 32])
}

/// The same, with a consensus key already bound. Zero is no key: a controller that has
/// never been bound relays nothing.
fn controller_data_bound(
    root: &RootKey,
    epoch: u64,
    nonce: u64,
    consensus_algorithm: u16,
    consensus_key_id: &[u8],
) -> Cell {
    use chain_block::IBitstring;
    let mut data = chain_block::BuilderData::new();
    data.append_u64(epoch).expect("epoch");
    data.append_u64(nonce).expect("nonce");
    data.append_u16(consensus_algorithm).expect("consensus algorithm");
    data.append_raw(consensus_key_id, 256).expect("consensus key identity");
    data.checked_append_reference(stored(&root.public_key)).expect("root key");
    data.into_cell().expect("controller data")
}

struct Controller {
    chain: Blockchain,
    address: MsgAddressInt,
    global_id: i32,
}

fn deploy(root: &RootKey) -> Controller {
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    let state = StateInit::with_code_and_data(controller_code(), controller_data(root, 0, 0));
    let address = MsgAddressInt::with_params(
        -1,
        state.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("address");
    let deployer = chain.treasury("controller-deployer", 100_000 * TOS).expect("funding");
    chain
        .send_message(
            MessageBuilder::internal(deployer.address(), &address, 10_000 * TOS)
                .bounce(false)
                .state_init(state)
                .body(Cell::default())
                .build(),
        )
        .expect("deployment")
        .expect_success();
    let global_id = match chain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("the chain states no network id"),
    };
    Controller { chain, address, global_id }
}

impl Controller {
    fn state(&self) -> (u64, u64, Vec<u8>) {
        let result = self
            .chain
            .run_get_method(&self.address, "controller_state", vec![])
            .expect("the controller answers");
        assert_eq!(result.exit_code, 0, "controller_state failed");
        let epoch = result.stack[0].as_integer().expect("epoch").to_string().parse().expect("u64");
        let nonce = result.stack[1].as_integer().expect("nonce").to_string().parse().expect("u64");
        let key = result.stack[4].as_cell().expect("a key cell").clone();
        let mut slice = chain_block::SliceData::load_cell(key).expect("key");
        slice.get_next_u32().expect("declared length");
        let mut chain_cell = slice.checked_drain_reference().expect("the chain");
        let mut bytes = Vec::new();
        loop {
            let mut cs = chain_block::SliceData::load_cell(chain_cell.clone()).expect("a chunk");
            let bits = cs.remaining_bits();
            bytes.extend_from_slice(&cs.get_next_bits(bits).expect("chunk bytes"));
            if cs.remaining_references() == 0 {
                break;
            }
            chain_cell = cs.checked_drain_reference().expect("the continuation");
        }
        (epoch, nonce, bytes)
    }

    fn id(&self) -> chain_block::UInt256 {
        chain_block::UInt256::from_slice(&self.address.address().get_bytestring(0))
    }
}

/// The 93 bytes a controller root signs.
#[allow(clippy::too_many_arguments)]
fn preimage(
    global_id: i32,
    controller: &chain_block::UInt256,
    epoch: u64,
    nonce: u64,
    valid_until: u32,
    kind: u8,
    payload: &Cell,
) -> Vec<u8> {
    chain_block::pq_controller::controller_auth_preimage(
        global_id,
        controller,
        epoch,
        nonce,
        valid_until,
        kind,
        &payload.repr_hash(),
    )
}

/// A payload that asks the controller to send one message.
///
/// The source has to be the controller itself: an outbound message naming anyone else is
/// refused by the action phase, with the compute phase already reported as successful.
fn send_payload(from: &MsgAddressInt, to: &MsgAddressInt, value: u64, mode: u8) -> Cell {
    use chain_block::IBitstring;
    let message =
        MessageBuilder::internal(from, to, value).bounce(false).body(Cell::default()).build();
    let out = message.serialize().expect("an outbound message");
    let mut payload = chain_block::BuilderData::new();
    payload.append_u8(mode).expect("mode");
    payload.checked_append_reference(out).expect("the message");
    payload.into_cell().expect("a send payload")
}

#[allow(clippy::too_many_arguments)]
fn authorize(
    controller: &mut Controller,
    root: &RootKey,
    epoch: u64,
    nonce: u64,
    valid_until: u32,
    kind: u8,
    payload: Cell,
    cosignature: Option<Vec<u8>>,
    global_id: i32,
) -> tos_sandbox::SendResult {
    use chain_block::IBitstring;
    let id = controller.id();
    let message = preimage(global_id, &id, epoch, nonce, valid_until, kind, &payload);
    let signature = root.sign(&message);

    let mut body = chain_block::BuilderData::new();
    body.append_u32(CONTROLLER_OP).expect("operation");
    body.append_u64(1).expect("query id");
    body.append_i32(global_id).expect("network");
    body.append_u64(epoch).expect("epoch");
    body.append_u64(nonce).expect("nonce");
    body.append_u32(valid_until).expect("expiry");
    body.append_u8(kind).expect("kind");
    body.checked_append_reference(payload).expect("payload");
    body.checked_append_reference(stored(&signature)).expect("signature");
    match cosignature {
        Some(bytes) => {
            body.append_bit_one().expect("a cosignature is present");
            body.checked_append_reference(stored(&bytes)).expect("cosignature");
        }
        None => {
            body.append_bit_zero().expect("no cosignature");
        }
    }

    let relayer = controller.chain.treasury("controller-relayer", 10_000 * TOS).expect("relayer");
    controller
        .chain
        .send_message(relayer.build_message(
            &controller.address,
            100 * TOS,
            true,
            Some(body.into_cell().expect("an authorisation")),
        ))
        .expect("the authorisation is delivered")
}

fn exit_code(result: &tos_sandbox::SendResult) -> i32 {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    match transaction.read_description().expect("description") {
        chain_block::TransactionDescr::Ordinary(descr) => match descr.compute_ph {
            chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
            other => panic!("the compute phase did not run: {other:?}"),
        },
        other => panic!("not an ordinary transaction: {other:?}"),
    }
}

fn valid_until(controller: &Controller) -> u32 {
    controller.chain.now() + 600
}

#[test]
fn an_authorised_send_happens_once() {
    let root = RootKey::new(1);
    let mut controller = deploy(&root);
    let target = controller.chain.treasury("controller-target", TOS).expect("a target");
    let expiry = valid_until(&controller);
    let payload = send_payload(&controller.address.clone(), &target.address().clone(), 5 * TOS, 3);

    assert_eq!(controller.state().0, 0, "the fixture starts at epoch zero");
    assert_eq!(controller.state().1, 0, "the fixture starts at nonce zero");

    let global_id = controller.global_id;
    let result = authorize(
        &mut controller,
        &root,
        0,
        0,
        expiry,
        KIND_SEND,
        payload.clone(),
        None,
        global_id,
    );
    assert_eq!(exit_code(&result), 0, "a correctly authorised send was refused");
    assert_eq!(controller.state().1, 1, "the nonce did not advance");

    // The same authorisation again: its nonce is spent.
    let again =
        authorize(&mut controller, &root, 0, 0, expiry, KIND_SEND, payload, None, global_id);
    assert_eq!(exit_code(&again), ERROR_BAD_NONCE, "an authorisation was replayed");
}

#[test]
fn every_field_of_an_authorisation_is_checked_before_the_signature() {
    let root = RootKey::new(2);
    let other = RootKey::new(3);
    let mut controller = deploy(&root);
    let target = controller.chain.treasury("controller-target-2", TOS).expect("a target");
    let expiry = valid_until(&controller);
    let now = controller.chain.now();
    let target_address = target.address().clone();
    let own = controller.address.clone();
    let payload = || send_payload(&own, &target_address, 5 * TOS, 3);
    let global_id = controller.global_id;

    let cases: Vec<(&str, i32, tos_sandbox::SendResult)> = vec![
        (
            "another network",
            ERROR_WRONG_NETWORK,
            authorize(
                &mut controller,
                &root,
                0,
                0,
                expiry,
                KIND_SEND,
                payload(),
                None,
                global_id ^ 1,
            ),
        ),
        (
            "another epoch",
            ERROR_STALE_EPOCH,
            authorize(&mut controller, &root, 1, 0, expiry, KIND_SEND, payload(), None, global_id),
        ),
        (
            "another nonce",
            ERROR_BAD_NONCE,
            authorize(&mut controller, &root, 0, 9, expiry, KIND_SEND, payload(), None, global_id),
        ),
        (
            "an expiry already past",
            ERROR_EXPIRED,
            authorize(&mut controller, &root, 0, 0, now - 1, KIND_SEND, payload(), None, global_id),
        ),
        (
            "an expiry beyond the window",
            ERROR_EXPIRED,
            authorize(
                &mut controller,
                &root,
                0,
                0,
                now + 7200,
                KIND_SEND,
                payload(),
                None,
                global_id,
            ),
        ),
        (
            "a kind that is not admitted",
            ERROR_BAD_KIND,
            authorize(&mut controller, &root, 0, 0, expiry, 7, payload(), None, global_id),
        ),
        (
            "a cosignature on a send",
            ERROR_BAD_COSIGNATURE,
            authorize(
                &mut controller,
                &root,
                0,
                0,
                expiry,
                KIND_SEND,
                payload(),
                Some(vec![0u8; 2420]),
                global_id,
            ),
        ),
        (
            "a send that would destroy the account",
            ERROR_BAD_ACTION,
            authorize(
                &mut controller,
                &root,
                0,
                0,
                expiry,
                KIND_SEND,
                send_payload(&own, &target_address, 5 * TOS, 32 + 3),
                None,
                global_id,
            ),
        ),
    ];

    for (what, expected, result) in cases {
        assert_eq!(
            exit_code(&result),
            expected,
            "an authorisation with {what} was not refused for it"
        );
        assert_eq!(controller.state().1, 0, "{what}: a refused authorisation spent the nonce");
    }

    // And a request signed by a key this controller does not hold.
    let id = controller.id();
    let message = preimage(global_id, &id, 0, 0, expiry, KIND_SEND, &payload());
    let forged = other.sign(&message);
    let result = send_authorisation(
        &mut controller,
        0,
        0,
        expiry,
        KIND_SEND,
        payload(),
        &forged,
        None,
        global_id,
    );
    assert_eq!(exit_code(&result), ERROR_BAD_SIGNATURE, "a stranger's signature authorised a send");
    assert_eq!(controller.state().1, 0, "a forged authorisation spent the nonce");
}

fn controller_now(controller: &Controller) -> u32 {
    controller.chain.now()
}

/// The same as `authorize`, with the signature supplied rather than made.
#[allow(clippy::too_many_arguments)]
fn send_authorisation(
    controller: &mut Controller,
    epoch: u64,
    nonce: u64,
    valid_until: u32,
    kind: u8,
    payload: Cell,
    signature: &[u8],
    cosignature: Option<Vec<u8>>,
    global_id: i32,
) -> tos_sandbox::SendResult {
    use chain_block::IBitstring;
    let mut body = chain_block::BuilderData::new();
    body.append_u32(CONTROLLER_OP).expect("operation");
    body.append_u64(1).expect("query id");
    body.append_i32(global_id).expect("network");
    body.append_u64(epoch).expect("epoch");
    body.append_u64(nonce).expect("nonce");
    body.append_u32(valid_until).expect("expiry");
    body.append_u8(kind).expect("kind");
    body.checked_append_reference(payload).expect("payload");
    body.checked_append_reference(stored(signature)).expect("signature");
    match cosignature {
        Some(bytes) => {
            body.append_bit_one().expect("a cosignature is present");
            body.checked_append_reference(stored(&bytes)).expect("cosignature");
        }
        None => {
            body.append_bit_zero().expect("no cosignature");
        }
    }
    let relayer = controller.chain.treasury("controller-relayer-2", 10_000 * TOS).expect("relayer");
    controller
        .chain
        .send_message(relayer.build_message(
            &controller.address,
            100 * TOS,
            true,
            Some(body.into_cell().expect("an authorisation")),
        ))
        .expect("the authorisation is delivered")
}

#[test]
fn a_root_rotation_needs_both_the_old_root_and_the_new_one() {
    let root = RootKey::new(4);
    let next = RootKey::new(5);
    let stranger = RootKey::new(6);
    let mut controller = deploy(&root);
    let expiry = valid_until(&controller);
    let global_id = controller.global_id;

    let payload = {
        use chain_block::IBitstring;
        let mut payload = chain_block::BuilderData::new();
        payload.checked_append_reference(stored(&next.public_key)).expect("the successor");
        payload.into_cell().expect("a rotation payload")
    };
    let id = controller.id();
    let message = preimage(global_id, &id, 0, 0, expiry, KIND_ROTATE_ROOT, &payload);

    // A successor that cannot prove it exists: the proof is another key's.
    let refused = authorize(
        &mut controller,
        &root,
        0,
        0,
        expiry,
        KIND_ROTATE_ROOT,
        payload.clone(),
        Some(stranger.sign(&message)),
        global_id,
    );
    assert_eq!(
        exit_code(&refused),
        ERROR_BAD_COSIGNATURE,
        "a root was installed without proving its private half exists"
    );
    assert_eq!(controller.state().2, root.public_key, "a refused rotation replaced the root");

    let accepted = authorize(
        &mut controller,
        &root,
        0,
        0,
        expiry,
        KIND_ROTATE_ROOT,
        payload,
        Some(next.sign(&message)),
        global_id,
    );
    assert_eq!(exit_code(&accepted), 0, "a rotation with both signatures was refused");

    let (epoch, nonce, key) = controller.state();
    assert_eq!(key, next.public_key, "the successor was not installed");
    assert_eq!(epoch, 1, "the epoch did not move, so the old root's authorisations still stand");
    assert_eq!(nonce, 0, "the nonce did not restart in the new epoch");

    // The old root is finished, and its epoch is gone with it.
    let own_address = controller.address.clone();
    let stale = authorize(
        &mut controller,
        &root,
        0,
        0,
        expiry,
        KIND_SEND,
        send_payload(&own_address, &own_address, TOS, 3),
        None,
        global_id,
    );
    assert_eq!(
        exit_code(&stale),
        ERROR_STALE_EPOCH,
        "an authorisation under the old epoch was accepted"
    );
}

/// What the controller says about itself, in full. The key identity comes back as an
/// integer, so it is compared as one rather than converted back into bytes.
fn bound(controller: &Controller) -> (u64, u64, u16, String) {
    let result = controller
        .chain
        .run_get_method(&controller.address, "controller_state", vec![])
        .expect("the controller answers");
    assert_eq!(result.exit_code, 0, "controller_state failed");
    let epoch = result.stack[0].as_integer().expect("epoch").to_string().parse().expect("u64");
    let nonce = result.stack[1].as_integer().expect("nonce").to_string().parse().expect("u64");
    let algorithm: u16 =
        result.stack[2].as_integer().expect("algorithm").to_string().parse().expect("u16");
    let key_id = result.stack[3].as_integer().expect("key identity").to_string();
    (epoch, nonce, algorithm, key_id)
}

/// The identity a key derives, as the get-method reports it.
fn key_identity(key: &[u8]) -> String {
    tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(
        chain_block::derive_consensus_key_id(1, key).as_slice(),
    )
    .to_string()
}

/// The payload that binds a consensus key: which suite, and the key itself.
fn bind_payload(algorithm: u16, key: &[u8]) -> Cell {
    use chain_block::IBitstring;
    let mut payload = chain_block::BuilderData::new();
    payload.append_u16(algorithm).expect("algorithm");
    payload.checked_append_reference(stored(key)).expect("the key");
    payload.into_cell().expect("a bind payload")
}

/// A controller binds the consensus key it will act through, and the key proves it exists.
///
/// The root does this once. Every election afterwards is authorised by the consensus key
/// alone, which is the point: the offline root stops being part of a routine operation.
#[test]
fn binding_a_consensus_key_needs_the_root_and_the_key_itself() {
    let root = RootKey::new(0xb0);
    let consensus = RootKey::new(0xb1);
    let mut controller = deploy(&root);
    assert_eq!(bound(&controller).3, "0", "a fresh controller is bound to a key");

    let payload = bind_payload(1, &consensus.public_key);
    let until = valid_until(&controller);
    let id = controller.id();
    let global_id = controller.global_id;
    let commitment = preimage(global_id, &id, 0, 0, until, KIND_BIND_CONSENSUS, &payload);

    // Without the key's own signature there is no proof it exists, and a controller bound
    // to a key nobody holds is a validator that cannot validate.
    let alone = authorize(
        &mut controller,
        &root,
        0,
        0,
        until,
        KIND_BIND_CONSENSUS,
        payload.clone(),
        None,
        global_id,
    );
    assert_eq!(exit_code(&alone), ERROR_BAD_COSIGNATURE, "a key bound itself without proving it");
    assert_eq!(bound(&controller).3, "0", "a refused bind bound something anyway");

    // Somebody else's signature is not that proof either.
    let impostor = RootKey::new(0xb2);
    let wrong = authorize(
        &mut controller,
        &root,
        0,
        0,
        until,
        KIND_BIND_CONSENSUS,
        payload.clone(),
        Some(impostor.sign(&commitment)),
        global_id,
    );
    assert_eq!(exit_code(&wrong), ERROR_BAD_COSIGNATURE, "another key's signature bound this one");

    // With both, it binds.
    let done = authorize(
        &mut controller,
        &root,
        0,
        0,
        until,
        KIND_BIND_CONSENSUS,
        payload,
        Some(consensus.sign(&commitment)),
        global_id,
    );
    assert_eq!(exit_code(&done), 0, "a correctly authorised bind was refused");
    let (epoch, nonce, algorithm, key_id) = bound(&controller);
    assert_eq!(epoch, 0, "binding a consensus key moved the root's epoch");
    assert_eq!(nonce, 1, "binding a consensus key did not spend its nonce");
    assert_eq!(algorithm, 1, "the suite was not recorded");
    assert_eq!(
        key_id,
        key_identity(&consensus.public_key),
        "the key recorded is not the key bound"
    );
}

/// Name an elector in the chain's configuration, and return the address it names.
fn name_an_elector(chain: &mut Blockchain) -> MsgAddressInt {
    let id = chain_block::AccountId::from([0x33u8; 32]);
    let mut config = chain.config_params().clone();
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParam1(chain_block::ConfigParam1 {
            elector_addr: id.clone(),
        }))
        .expect("the elector is named");
    // Naming one parameter makes the configuration one the sandbox must build a whole
    // blockchain configuration from, and that needs the fundamental-contract list too.
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParam31(chain_block::ConfigParam31 {
            fundamental_smc_addr: chain_block::FundamentalSmcAddresses::default(),
        }))
        .expect("the fundamental contracts are listed");
    chain.set_config(config).expect("the chain adopts it");
    MsgAddressInt::with_standart(None, -1, id).expect("the elector address")
}

/// A relay request: the terms of a stake and the key that authorised it.
fn relay_body_with_signature(
    owner: &MsgAddressInt,
    algorithm: u16,
    key: &[u8],
    signature: Cell,
) -> Cell {
    use chain_block::IBitstring;
    let mut terms = chain_block::BuilderData::new();
    terms.append_u32(1_789_434_000).expect("election");
    terms.append_u32(0x10000).expect("factor");
    terms.append_raw(&[0xa5; 32], 256).expect("adnl");
    terms.append_u16(algorithm).expect("suite");
    terms.checked_append_reference(stored(key)).expect("key");
    terms.checked_append_reference(signature).expect("signature");
    terms.append_bit_zero().expect("no witness");
    let terms = terms.into_cell().expect("terms");
    let elector = chain_block::UInt256::from([0x33; 32]);
    let mut commitment = chain_block::BuilderData::new();
    commitment.append_u32(RELAY_OP).expect("op");
    commitment.append_raw(&owner.address().get_bytestring(0), 256).expect("owner");
    commitment.append_raw(elector.as_slice(), 256).expect("elector");
    chain_block::Coins::new(4_900 * TOS).write_to(&mut commitment).expect("exact forward");
    commitment.checked_append_reference(terms.clone()).expect("terms");
    commitment.checked_append_reference(owner.serialize().expect("payer")).expect("payer");
    let commitment = commitment.into_cell().expect("commitment").hash(0);
    let mut body = chain_block::BuilderData::new();
    body.append_u32(RELAY_OP).expect("operation");
    body.append_u64((1 << 63) | 1).expect("query");
    body.append_raw(&commitment.as_slice()[..20], 160).expect("bounce commitment");
    chain_block::Coins::new(4_900 * TOS).write_to(&mut body).expect("forwarded");
    body.append_raw(elector.as_slice(), 256).expect("elector");
    body.checked_append_reference(terms).expect("terms");
    body.checked_append_reference(owner.serialize().expect("payer")).expect("payer");
    body.into_cell().expect("a relay request")
}
fn relay_body(owner: &MsgAddressInt, algorithm: u16, key: &[u8], signature: &[u8]) -> Cell {
    relay_body_with_signature(owner, algorithm, key, stored(signature))
}
fn signed_relay_body(controller: &Controller, owner: &MsgAddressInt, key: &RootKey) -> Cell {
    let network =
        match controller.chain.config_params().config(19).expect("network").expect("network") {
            chain_block::ConfigParamEnum::ConfigParam19(id) => id as i32,
            _ => panic!("network parameter"),
        };
    let preimage = chain_block::pq_elector::stake_preimage(
        network,
        1_789_434_000,
        0x10000,
        &chain_block::UInt256::from_slice(&controller.address.address().get_bytestring(0)),
        &chain_block::UInt256::from_slice(&owner.address().get_bytestring(0)),
        1,
        &chain_block::derive_consensus_key_id(1, &key.public_key),
        &chain_block::UInt256::from([0xa5; 32]),
    );
    let signature = key.sign_under(&preimage, b"TOS-VALIDATOR-ELECTION-v1");
    relay_body(owner, 1, &key.public_key, &signature)
}

/// What the controller sent on, if anything: where, carrying what, and stating whom.
fn relayed(result: &tos_sandbox::SendResult) -> Option<(MsgAddressInt, u128, String)> {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    let mut sent = None;
    transaction
        .iterate_out_msgs(|message| {
            // A refused relay still produces an out-message: the inbound one, bounced.
            // Only a stake is a relay, and reading a bounce as one would report the
            // refusal as a relay to nowhere.
            let Some(body) = message.body() else { return Ok(true) };
            let mut body = body.clone();
            let Ok(operation) = body.get_next_u32() else { return Ok(true) };
            if operation != STAKE_OP || sent.is_some() {
                return Ok(true);
            }
            let value = message.get_value().map(|v| v.coins.as_u128()).unwrap_or(0);
            let destination = message.dst().expect("a destination");
            body.get_next_u64().expect("query id");
            body.get_next_bits(160).expect("payload commitment");
            body.get_next_u16().expect("algorithm");
            body.get_next_u32().expect("election");
            body.get_next_u32().expect("max factor");
            body.get_next_bits(256).expect("adnl");
            assert!(!body.get_next_bit().expect("witness bit"), "a witness appeared");
            assert!(body.get_next_bit().expect("owner bit"), "the relay stated no owner");
            let owner = hex::encode(body.get_next_bits(256).expect("the owner"));
            sent = Some((destination, value, owner));
            Ok(true)
        })
        .expect("out messages");
    sent
}

/// The stake a pool sends goes to the elector, carrying the pool's money and naming the
/// pool as whose money it is.
///
/// This is the whole of what a consensus key may make this account do. It is not a root
/// authorisation: the key authorised the stake the elector will verify, and this account
/// checks the bound key and its stake signature before retaining the one pending slot.
#[test]
fn a_bound_consensus_key_relays_a_stake_for_whoever_sent_the_money() {
    let root = RootKey::new(0xb3);
    let consensus = RootKey::new(0xb4);
    let mut controller = Controller {
        chain: Blockchain::with_global_version(16).expect("a chain"),
        address: MsgAddressInt::default(),
        global_id: 0,
    };
    controller.chain.set_workchain(-1);
    // The elector this relay will send to. The bare sandbox configuration names none, and
    // a relay reads the address from the configuration rather than from its request --
    // which is what stops it being pointed anywhere else.
    let elector = name_an_elector(&mut controller.chain);
    let state = StateInit::with_code_and_data(
        controller_code(),
        controller_data_bound(
            &root,
            0,
            0,
            1,
            chain_block::derive_consensus_key_id(1, &consensus.public_key).as_slice(),
        ),
    );
    controller.address = MsgAddressInt::with_params(
        -1,
        state.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("address");
    let funder = controller.chain.treasury("relay-deployer", 100_000 * TOS).expect("funding");
    controller
        .chain
        .send_message(
            MessageBuilder::internal(funder.address(), &controller.address, 10_000 * TOS)
                .bounce(false)
                .state_init(state)
                .body(Cell::default())
                .build(),
        )
        .expect("deployment")
        .expect_success();

    let payer = controller.chain.treasury("controller-relayer", 10_000 * TOS).expect("payer");
    let payload = contracts::validator_controller::operating_funding_payload(
        &contracts::validator_controller::OperatingFunding {
            payer: payer.address(),
            deposit: u128::from(80 * TOS),
            allowance: u128::from(60 * TOS),
            per_request_limit: u128::from(20 * TOS),
            storage_floor: u128::from(10 * TOS),
            expires_at: controller.chain.now() + 86_400,
        },
    )
    .expect("operating payload");
    let expires = controller.chain.now() + 600;
    let network = match controller.chain.config_params().config(19).expect("network") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("missing network id"),
    };
    let funding = authorize(&mut controller, &root, 0, 0, expires, 4, payload, None, network);
    assert_eq!(exit_code(&funding), 0);
    let pool = controller.chain.treasury("relay-pool", 100_000 * TOS).expect("a pool");
    let before = controller
        .chain
        .get_account(&controller.address)
        .and_then(|account| account.balance().and_then(|balance| balance.coins.as_u64()))
        .expect("a balance");

    let relay = signed_relay_body(&controller, pool.address(), &consensus);
    let result = controller
        .chain
        .send_message(pool.build_message(&controller.address, 5_000 * TOS, true, Some(relay)))
        .expect("the relay request is delivered");
    assert_eq!(exit_code(&result), 0, "a relay from the bound key was refused");

    let (destination, value, owner) = relayed(&result).expect("the controller sent nothing on");
    assert_eq!(destination, elector, "the relay went somewhere that is not the elector");
    assert_eq!(
        owner,
        hex::encode(pool.address().address().get_bytestring(0)),
        "the relay stated an owner that is not the account that sent the money"
    );
    // Only what arrived. The account's own balance is not what a stake is made of.
    assert_eq!(
        value,
        u128::from(4_900 * TOS),
        "caller-funded fees cannot change exact forwarded principal"
    );
    let after = controller
        .chain
        .get_account(&controller.address)
        .and_then(|account| account.balance().and_then(|balance| balance.coins.as_u64()))
        .expect("a balance");
    let operations = controller
        .chain
        .run_get_method(&controller.address, "operating_state", vec![])
        .expect("operating ledger");
    let funds: u64 =
        operations.stack[0].as_integer().expect("funds").to_string().parse().expect("funds");
    let grant = (80 * TOS).checked_sub(funds).expect("reserved grant");
    assert_eq!(after, before - grant, "only the explicitly reserved operating grant is spent");
}

/// Everything the relay refuses, and the fact that it sends nothing when it does.
#[test]
fn a_relay_is_refused_unless_the_key_is_the_bound_one_and_the_money_is_enough() {
    let root = RootKey::new(0xb5);
    let consensus = RootKey::new(0xb6);
    let stranger = RootKey::new(0xb7);

    // Unbound: this controller has no consensus key, so nothing may relay through it.
    let mut unbound = deploy(&root);
    name_an_elector(&mut unbound.chain);
    let pool = unbound.chain.treasury("relay-pool-a", 100_000 * TOS).expect("a pool");
    let result = unbound
        .chain
        .send_message(pool.build_message(
            &unbound.address,
            5_000 * TOS,
            true,
            Some(relay_body(pool.address(), 1, &consensus.public_key, &vec![0x5a; 2420])),
        ))
        .expect("delivered");
    assert_eq!(exit_code(&result), ERROR_NO_CONSENSUS_KEY, "an unbound controller relayed a stake");
    assert!(relayed(&result).is_none(), "a refused relay sent something anyway");

    // Bound, but the request carries another key.
    let mut controller = deploy(&root);
    name_an_elector(&mut controller.chain);
    let account = controller
        .chain
        .get_account(&controller.address)
        .expect("the controller is deployed")
        .clone();
    let mut with_key = account;
    with_key.set_data(controller_data_bound(
        &root,
        0,
        0,
        1,
        chain_block::derive_consensus_key_id(1, &consensus.public_key).as_slice(),
    ));
    let address = controller.address.clone();
    controller.chain.set_account(address, with_key);

    let pool = controller.chain.treasury("relay-pool-b", 100_000 * TOS).expect("a pool");
    let wrong = controller
        .chain
        .send_message(pool.build_message(
            &controller.address,
            5_000 * TOS,
            true,
            Some(relay_body(pool.address(), 1, &stranger.public_key, &vec![0x5a; 2420])),
        ))
        .expect("delivered");
    assert_eq!(
        exit_code(&wrong),
        ERROR_WRONG_CONSENSUS_KEY,
        "a stake signed by another key was relayed"
    );
    assert!(relayed(&wrong).is_none(), "a refused relay sent something anyway");

    // A suite this chain does not know. The identity would not match either, but the
    // reason has to be that it is the wrong key and not whatever the key parser makes of
    // a length it cannot know.
    let unknown_suite = controller
        .chain
        .send_message(pool.build_message(
            &controller.address,
            5_000 * TOS,
            true,
            Some(relay_body(pool.address(), 7, &consensus.public_key, &vec![0x5a; 2420])),
        ))
        .expect("delivered");
    assert_eq!(
        exit_code(&unknown_suite),
        ERROR_WRONG_CONSENSUS_KEY,
        "a request naming an unknown suite was refused for the wrong reason"
    );
    assert!(relayed(&unknown_suite).is_none(), "a refused relay sent something anyway");

    // The right key, and not enough money to pay for what it asks the elector to do.
    let poor = controller
        .chain
        .send_message(pool.build_message(
            &controller.address,
            TOS,
            true,
            Some(relay_body(pool.address(), 1, &consensus.public_key, &vec![0x5a; 2420])),
        ))
        .expect("delivered");
    assert_eq!(
        exit_code(&poor),
        ERROR_RELAY_UNDERFUNDED,
        "a relay that cannot pay for its own stake was carried out"
    );
    assert!(relayed(&poor).is_none(), "a refused relay sent something anyway");
}

/// Money from outside the masterchain is refused before anything is relayed.
///
/// The stake wire carries the owner's 256 bits alone, and the elector answers -- and at
/// unfreeze pays -- `-1:owner`. Money from `0:X` would be owed to `-1:X`, an account that
/// may not exist and is not the sender's either way. Every pool that stakes is a
/// masterchain contract, so this turns away only money that could not have come back.
#[test]
fn a_stake_owner_outside_the_masterchain_is_refused_before_anything_is_relayed() {
    let root = RootKey::new(0xbb);
    let consensus = RootKey::new(0xbc);
    let mut controller = deploy(&root);
    name_an_elector(&mut controller.chain);
    let account = controller
        .chain
        .get_account(&controller.address)
        .expect("the controller is deployed")
        .clone();
    let mut with_key = account;
    with_key.set_data(controller_data_bound(
        &root,
        0,
        0,
        1,
        chain_block::derive_consensus_key_id(1, &consensus.public_key).as_slice(),
    ));
    let address = controller.address.clone();
    controller.chain.set_account(address, with_key);

    // A sender in the base workchain. The sandbox runs the controller's transaction and
    // nothing of the sender's, so an address is all that is needed to be one.
    let basechain =
        MsgAddressInt::with_standart(None, 0, chain_block::AccountId::from([0x44u8; 32]))
            .expect("a basechain address");
    let result = controller
        .chain
        .send_message(
            MessageBuilder::internal(&basechain, &controller.address, 5_000 * TOS)
                .bounce(true)
                .body(relay_body(&basechain, 1, &consensus.public_key, &vec![0x5a; 2420]))
                .build(),
        )
        .expect("the relay request is delivered");
    assert_eq!(
        exit_code(&result),
        ERROR_OWNER_NOT_MASTERCHAIN,
        "money from outside the masterchain was relayed, or refused for another reason"
    );
    assert!(relayed(&result).is_none(), "a refused relay sent something anyway");
}

/// A stake the elector would abort on must not get past this account.
///
/// The elector answers a stake it dislikes by sending the money back; it aborts only on
/// one that it cannot parse, and the signature is the one field whose shape nothing
/// checked before it arrived there. An abort bounces to whoever sent the message, and
/// since the relay put this account there, the bounce stops here: the pool never learns
/// its stake died, stays waiting for an answer that cannot come, and its principal rests
/// in this account's balance. So the shape is checked here, where a refusal still bounces
/// back to the pool, which knows what to do with one.
#[test]
fn a_signature_the_elector_could_not_parse_never_leaves_this_account() {
    let root = RootKey::new(0xb8);
    let consensus = RootKey::new(0xb9);
    let mut controller = deploy(&root);
    name_an_elector(&mut controller.chain);
    let account = controller
        .chain
        .get_account(&controller.address)
        .expect("the controller is deployed")
        .clone();
    let mut with_key = account;
    with_key.set_data(controller_data_bound(
        &root,
        0,
        0,
        1,
        chain_block::derive_consensus_key_id(1, &consensus.public_key).as_slice(),
    ));
    let address = controller.address.clone();
    controller.chain.set_account(address, with_key);
    let pool = controller.chain.treasury("relay-pool-c", 100_000 * TOS).expect("a pool");

    // Every length but the one ML-DSA-44 signs with, including the empty one.
    for length in [0usize, 1, 2419, 2421, 8192] {
        let result = controller
            .chain
            .send_message(pool.build_message(
                &controller.address,
                5_000 * TOS,
                true,
                Some(relay_body(pool.address(), 1, &consensus.public_key, &vec![0x5a; length])),
            ))
            .expect("delivered");
        assert_ne!(
            exit_code(&result),
            0,
            "a {length}-byte signature was relayed to an elector that cannot parse it"
        );
        assert!(relayed(&result).is_none(), "a refused relay sent something anyway");
    }

    // The length is not the only thing that makes a chain unreadable: a declared length
    // that the bytes behind it do not carry is refused too.
    let mut lying = chain_block::BuilderData::new();
    {
        use chain_block::IBitstring;
        lying.append_u32(2420).expect("a declared length");
    }
    lying
        .checked_append_reference(
            chain_block::BuilderData::new().into_cell().expect("an empty chain"),
        )
        .expect("the chain");
    let body = relay_body_with_signature(
        pool.address(),
        1,
        &consensus.public_key,
        lying.into_cell().expect("lying signature"),
    );
    let result = controller
        .chain
        .send_message(pool.build_message(&controller.address, 5_000 * TOS, true, Some(body)))
        .expect("delivered");
    assert_ne!(exit_code(&result), 0, "a signature that lies about its length was relayed");
    assert!(relayed(&result).is_none(), "a refused relay sent something anyway");
}

/// Something this account sent, coming back.
///
/// A relay is bounceable on purpose, so the one message this account sends is also the one
/// that can return. Treating that return as a request would abort the transaction, which
/// moves the money nowhere and burns what came back with it.
#[test]
fn a_relay_that_comes_back_is_held_rather_than_thrown_over() {
    use chain_block::IBitstring;
    let root = RootKey::new(0xba);
    let mut controller = deploy(&root);
    let elector = name_an_elector(&mut controller.chain);
    let before = controller
        .chain
        .get_account(&controller.address)
        .and_then(|account| account.balance().and_then(|balance| balance.coins.as_u64()))
        .expect("a balance");

    // What a bounced stake looks like: the bounce marker, then as much of the body the
    // elector could not carry out as fits.
    let mut bounced = chain_block::BuilderData::new();
    bounced.append_u32(0xffff_ffff).expect("the bounce marker");
    bounced.append_u32(STAKE_OP).expect("the operation that bounced");
    bounced.append_u64(7).expect("query id");

    let mut bounce = MessageBuilder::internal(&elector, &controller.address, 5_000 * TOS)
        .bounce(false)
        .body(bounced.into_cell().expect("a bounced body"))
        .build();
    // The bit that tells a return from a request. Without it this is an ordinary message
    // carrying `0xffffffff`, which is a different thing entirely.
    bounce.int_header_mut().expect("an internal message").bounced = true;

    let result = controller.chain.send_message(bounce).expect("the bounce is delivered");
    assert_eq!(exit_code(&result), 0, "a returning relay was thrown over");

    let after = controller
        .chain
        .get_account(&controller.address)
        .and_then(|account| account.balance().and_then(|balance| balance.coins.as_u64()))
        .expect("a balance");
    assert!(after > before, "the money that came back was not kept: {before} -> {after}");
}

#[test]
fn there_is_no_external_way_in() {
    use chain_block::IBitstring;
    let root = RootKey::new(7);
    let controller = deploy(&root);
    let mut body = chain_block::BuilderData::new();
    body.append_u32(CONTROLLER_OP).expect("operation");
    let mut chain = controller.chain;
    let result = chain.send_message(
        MessageBuilder::external(&controller.address)
            .body(body.into_cell().expect("a body"))
            .build(),
    );
    match result {
        Ok(sent) => assert_eq!(
            exit_code(&sent),
            ERROR_NOT_INTERNAL,
            "an external message was admitted to the controller"
        ),
        Err(_) => {
            // The chain refused to deliver it at all, which is the same closed door.
        }
    }
}

// ── Capital top-up, executed ───────────────────────────────────────────────
//
// `controller operations plan` prices a plain transfer that must leave the relay's
// capital (`balance - msg_value >= funds + floor`) in place. These run that transfer,
// the renewal and the relay against the controller compiled from source, rather than
// adding the planned amount to a balance.

use contracts::validator_controller::{
    CapitalCosts, OperatingState, PLAIN_RECEIVE_GAS, RelayFees, RenewalPlan, RenewalRequest,
    capital_costs, gas_fee, plan_renewal,
};
use contracts::wallet::send_fees::AccountStorage;

/// `sr::error` in `stake-relay.fc`: every relay precondition, the capital check
/// included, fails with it.
const RELAY_REFUSED: i32 = 180;

fn compute_gas(result: &tos_sandbox::SendResult) -> u64 {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    match transaction.read_description().expect("description") {
        chain_block::TransactionDescr::Ordinary(descr) => match descr.compute_ph {
            chain_block::TrComputePhase::Vm(vm) => vm.gas_used.as_u64(),
            other => panic!("the compute phase did not run: {other:?}"),
        },
        other => panic!("not an ordinary transaction: {other:?}"),
    }
}

/// A controller bound to `consensus`, with an elector named, deployed with `value`.
fn bound_controller(root: &RootKey, consensus: &RootKey, value: u64) -> Controller {
    let mut controller = Controller {
        chain: Blockchain::with_global_version(16).expect("a chain"),
        address: MsgAddressInt::default(),
        global_id: 0,
    };
    controller.chain.set_workchain(-1);
    name_an_elector(&mut controller.chain);
    let state = StateInit::with_code_and_data(
        controller_code(),
        controller_data_bound(
            root,
            0,
            0,
            1,
            chain_block::derive_consensus_key_id(1, &consensus.public_key).as_slice(),
        ),
    );
    controller.address = MsgAddressInt::with_params(
        -1,
        state.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("address");
    let funder = controller.chain.treasury("capital-deployer", 100_000 * TOS).expect("funding");
    controller
        .chain
        .send_message(
            MessageBuilder::internal(funder.address(), &controller.address, value)
                .bounce(false)
                .state_init(state)
                .body(Cell::default())
                .build(),
        )
        .expect("deployment")
        .expect_success();
    controller.global_id = match controller.chain.config_params().config(19).expect("network") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("the chain states no network id"),
    };
    controller
}

/// What a plan reads, taken from the chain as it is now: never a locally adjusted
/// balance.
struct Observed {
    state: OperatingState,
    nonce: u64,
    balance: u128,
    storage: AccountStorage,
}

fn observe(controller: &Controller) -> Observed {
    use tl_api::tos::tvm::{
        Number, StackEntry,
        numberdecimal::NumberDecimal,
        slice,
        stackentry::{StackEntryNumber, StackEntrySlice},
    };
    let result = controller
        .chain
        .run_get_method(&controller.address, "operating_state", vec![])
        .expect("operating_state");
    assert_eq!(result.exit_code, 0);
    let entries = result
        .stack
        .iter()
        .map(|item| {
            if let Ok(int) = item.as_integer() {
                return StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
                    number: Number::Tvm_NumberDecimal(NumberDecimal { number: int.to_string() }),
                });
            }
            let cell = item.as_slice().expect("a slice").clone().into_cell().expect("a cell");
            StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
                slice: slice::Slice { bytes: chain_block::write_boc(&cell).expect("boc") },
            })
        })
        .collect();
    let state = OperatingState::decode(&common::tvm_stack_parser::TvmStackParser::new(entries))
        .expect("operating_state decodes");
    let account = controller.chain.get_account(&controller.address).expect("the controller");
    Observed {
        state,
        nonce: controller.state().1,
        balance: account.balance().expect("a balance").coins.as_u128(),
        storage: AccountStorage::from_account(account).expect("storage"),
    }
}

struct Prices {
    gas: chain_block::GasLimitsPrices,
    fees: RelayFees,
    storage: Vec<chain_block::StoragePrices>,
}

fn prices(chain: &Blockchain) -> Prices {
    let config = chain.config_params();
    let gas = config.gas_prices(true).expect("gas prices");
    let forward = config.fwd_prices(true).expect("forward prices");
    Prices {
        fees: RelayFees::from_prices(&gas, &forward).expect("relay fees"),
        storage: config.storage_prices().expect("storage").prices().expect("prices"),
        gas,
    }
}

/// The renewal the tests ask for: `grant`-sized funds and limits, the given floor and
/// expiry, paid by the account `authorize` sends from.
fn renewal(
    controller: &mut Controller,
    fees: &RelayFees,
    floor: u128,
    expires_at: u32,
) -> RenewalRequest {
    let payer = controller.chain.treasury("controller-relayer", 10_000 * TOS).expect("payer");
    RenewalRequest {
        payer: payer.address().clone(),
        funds_target: 3 * fees.grant,
        allowance: 3 * fees.grant,
        limit: 2 * fees.grant,
        floor,
        expires_at,
        margin: u128::from(TOS),
        allow_payer_change: false,
    }
}

fn plan(
    controller: &Controller,
    seen: &Observed,
    fees: &RelayFees,
    request: &RenewalRequest,
    costs: &CapitalCosts,
) -> RenewalPlan {
    plan_renewal(
        &controller.address,
        &seen.state,
        seen.balance,
        fees,
        false,
        u64::from(controller.chain.now()),
        request,
        costs,
    )
    .expect("a plan")
}

/// A plain transfer with an empty body, as `tosctl wallet send` without a body sends.
fn plain_transfer(controller: &mut Controller, value: u128) {
    let funder = controller.chain.treasury("capital-funder", 100_000 * TOS).expect("funder");
    let value = u64::try_from(value).expect("a transfer value");
    let result = controller
        .chain
        .send_message(
            MessageBuilder::internal(funder.address(), &controller.address, value)
                .bounce(false)
                .body(Cell::default())
                .build(),
        )
        .expect("the transfer is delivered");
    assert_eq!(exit_code(&result), 0, "the controller refused a plain transfer");
}

/// Signs and delivers the plan's kind 4 request; returns its exit code.
fn renew(controller: &mut Controller, root: &RootKey, plan: &RenewalPlan, nonce: u64) -> i32 {
    let valid = valid_until(controller);
    let global_id = controller.global_id;
    let result =
        authorize(controller, root, 0, nonce, valid, 4, plan.payload.clone(), None, global_id);
    exit_code(&result)
}

/// A relay from `pool` signed by `consensus`; returns its exit code and whether the
/// stake was sent on.
fn relay(controller: &mut Controller, consensus: &RootKey) -> (i32, bool) {
    let pool = controller.chain.treasury("relay-pool", 100_000 * TOS).expect("a pool");
    let body = signed_relay_body(controller, pool.address(), consensus);
    let result = controller
        .chain
        .send_message(pool.build_message(&controller.address, 5_000 * TOS, true, Some(body)))
        .expect("the relay request is delivered");
    (exit_code(&result), relayed(&result).is_some())
}

/// The gas the plan prices the controller's own receive at is the gas that receive
/// uses, measured on the controller compiled from source, and the balance moves by
/// exactly the value less that fee.
#[test]
fn a_plain_transfer_costs_the_controller_exactly_the_pinned_receive_gas() {
    let root = RootKey::new(0xc1);
    let mut controller = deploy(&root);
    let before = observe(&controller);
    let funder = controller.chain.treasury("capital-funder", 100_000 * TOS).expect("funder");
    let result = controller
        .chain
        .send_message(
            MessageBuilder::internal(funder.address(), &controller.address, TOS)
                .bounce(false)
                .body(Cell::default())
                .build(),
        )
        .expect("the transfer is delivered");
    assert_eq!(exit_code(&result), 0);
    let gas = compute_gas(&result);
    assert_eq!(
        gas, PLAIN_RECEIVE_GAS,
        "the controller's plain receive uses {gas} gas; update PLAIN_RECEIVE_GAS"
    );
    let fee = gas_fee(&prices(&controller.chain).gas, PLAIN_RECEIVE_GAS).expect("a fee");
    let after = observe(&controller);
    assert_eq!(after.balance, before.balance + u128::from(TOS) - fee);
}

#[derive(Clone, Copy, Debug)]
enum Transfer {
    /// What the plan says to send.
    Planned,
    /// One nano-TOS less.
    PlannedLessOne,
    /// The net shortfall alone, as the plan used to say.
    ShortfallOnly,
}

/// Exactness with no storage and no margin: the planned transfer, then the renewal,
/// then a relay. Returns the relay's exit code, whether it relayed, and whether the
/// plan re-run after the transfer called the capital ready.
fn top_up_then_relay(transfer: Transfer) -> (i32, bool, bool) {
    let root = RootKey::new(0xc2);
    let consensus = RootKey::new(0xc3);
    let mut controller = bound_controller(&root, &consensus, 30 * TOS);
    let prices = prices(&controller.chain);
    let now = controller.chain.now();
    let seen = observe(&controller);
    assert_eq!(seen.storage.last_paid, now, "the deployment paid storage at this time");
    // A floor ten TOS above the balance: the plan must ask for capital.
    let floor = seen.balance + 10 * u128::from(TOS);
    let request = renewal(&mut controller, &prices.fees, floor, now + 86_400);
    // Zero accrued and zero future storage (the horizon is now), zero margin.
    let costs = capital_costs(&prices.gas, &prices.storage, &seen.storage, now, 0).expect("costs");
    assert_eq!(costs.storage_forecast, 0);
    assert_eq!(costs.receive_fee, gas_fee(&prices.gas, PLAIN_RECEIVE_GAS).expect("fee"));
    let first = plan(&controller, &seen, &prices.fees, &request, &costs);
    assert_eq!(first.capital_shortfall, 10 * u128::from(TOS));
    assert_eq!(first.capital_top_up_net, first.capital_shortfall);
    assert_eq!(first.capital_transfer_value, first.capital_shortfall + costs.receive_fee);

    let value = match transfer {
        Transfer::Planned => first.capital_transfer_value,
        Transfer::PlannedLessOne => first.capital_transfer_value - 1,
        Transfer::ShortfallOnly => first.capital_shortfall,
    };
    plain_transfer(&mut controller, value);

    // Re-running the plan reads the chain again: the new balance and storage record,
    // and an authorization and nonce the transfer did not touch.
    let again = observe(&controller);
    assert_eq!(again.state, seen.state, "a plain transfer changed the authorization");
    assert_eq!(again.nonce, seen.nonce, "a plain transfer spent the root nonce");
    assert_eq!(again.storage.last_paid, now);
    assert_eq!(again.balance, seen.balance + value - costs.receive_fee);
    let costs = capital_costs(&prices.gas, &prices.storage, &again.storage, now, 0).expect("costs");
    let second = plan(&controller, &again, &prices.fees, &request, &costs);
    assert_eq!(second.payload.repr_hash(), first.payload.repr_hash(), "the request is the same");

    assert_eq!(renew(&mut controller, &root, &second, 0), 0, "the renewal was refused");
    let renewed = observe(&controller);
    assert_eq!(renewed.state, second.projected_state());
    assert_eq!(renewed.balance, second.capital_after, "the renewal kept the planned balance");
    let (code, relayed) = relay(&mut controller, &consensus);
    (code, relayed, second.capital_ready())
}

#[test]
fn the_planned_transfer_leaves_exactly_the_capital_the_relay_checks() {
    let (code, relayed, ready) = top_up_then_relay(Transfer::Planned);
    assert!(ready, "the re-run plan did not see the capital");
    assert_eq!(code, 0, "the relay was refused after the planned transfer");
    assert!(relayed, "the relay sent nothing on");
}

#[test]
fn one_nano_less_than_the_planned_transfer_fails_the_capital_check() {
    let (code, relayed, ready) = top_up_then_relay(Transfer::PlannedLessOne);
    assert!(!ready, "the re-run plan called a short controller ready");
    assert_eq!(code, RELAY_REFUSED);
    assert!(!relayed);
}

#[test]
fn the_net_shortfall_alone_leaves_the_controller_underfunded() {
    let (code, relayed, ready) = top_up_then_relay(Transfer::ShortfallOnly);
    assert!(!ready);
    assert_eq!(code, RELAY_REFUSED, "the old net amount must not pass the capital check");
    assert!(!relayed);
}

/// Storage charged later: an authorization in force, optional recorded debt and
/// storage elapsed before the plan, then a renewal to the same terms, then a relay
/// one second before the expiry. Returns that relay's exit code.
fn storage_until_expiry(debt: u128, elapsed: u32, with_forecast: bool) -> (i32, u128) {
    let root = RootKey::new(0xc4);
    let consensus = RootKey::new(0xc5);
    let mut controller = bound_controller(&root, &consensus, 30 * TOS);
    let prices = prices(&controller.chain);
    let start = controller.chain.now();
    let expires_at = start + 30 * 86_400;
    let seen = observe(&controller);
    let floor = seen.balance + 10 * u128::from(TOS);
    let request = renewal(&mut controller, &prices.fees, floor, expires_at);
    let zero = CapitalCosts { receive_fee: 0, storage_forecast: 0, margin: 0 };
    let initial = plan(&controller, &seen, &prices.fees, &request, &zero);
    assert_eq!(renew(&mut controller, &root, &initial, 0), 0);

    controller.chain.set_now(start + elapsed);
    if debt > 0 {
        let mut account =
            controller.chain.get_account(&controller.address).expect("controller").clone();
        account.set_due_payment(Some(chain_block::Coins::from(u64::try_from(debt).expect("debt"))));
        controller.chain.set_account(controller.address.clone(), account);
    }
    let seen = observe(&controller);
    assert_eq!(seen.storage.due_payment, debt);
    let horizon = expires_at;
    let costs =
        capital_costs(&prices.gas, &prices.storage, &seen.storage, horizon, 0).expect("costs");
    assert!(costs.storage_forecast > debt, "the sandbox charges no storage; nothing is tested");
    let costs = if with_forecast { costs } else { CapitalCosts { storage_forecast: 0, ..costs } };
    let renewal_plan = plan(&controller, &seen, &prices.fees, &request, &costs);
    plain_transfer(&mut controller, renewal_plan.capital_transfer_value);
    let again = observe(&controller);
    assert_eq!(again.storage.due_payment, 0, "the transfer paid the recorded debt");
    assert_eq!(renew(&mut controller, &root, &renewal_plan, 1), 0);
    controller.chain.set_now(expires_at - 1);
    (relay(&mut controller, &consensus).0, costs.storage_forecast)
}

#[test]
fn the_storage_forecast_keeps_the_capital_until_the_expiry() {
    for (debt, elapsed) in [(0, 0), (0, 86_400), (70_000_000, 86_400)] {
        let (code, forecast) = storage_until_expiry(debt, elapsed, true);
        assert_eq!(code, 0, "debt {debt}, elapsed {elapsed}: forecast {forecast} fell short");
        let (code, _) = storage_until_expiry(debt, elapsed, false);
        assert_eq!(
            code, RELAY_REFUSED,
            "debt {debt}, elapsed {elapsed}: without the forecast the relay must fail"
        );
    }
}

/// A deposit of any coin-encoding length leaves exactly the planned balance and
/// funds. A kind 4 request rewrites the persistent data, which is why the storage
/// figure the plan prints is a forecast from the occupancy it read.
#[test]
fn deposits_of_every_encoding_length_leave_the_planned_balance() {
    let root = RootKey::new(0xc6);
    let consensus = RootKey::new(0xc7);
    let zero = CapitalCosts { receive_fee: 0, storage_forecast: 0, margin: 0 };
    for deposit in [1u128, 256, 65_536, 1_000_000_007, 50 * u128::from(TOS)] {
        let mut controller = bound_controller(&root, &consensus, 30 * TOS);
        let prices = prices(&controller.chain);
        let expires_at = controller.chain.now() + 86_400;
        // An authorization of one grant first, so that any deposit admits a relay.
        let deployed = observe(&controller);
        let mut request = renewal(&mut controller, &prices.fees, 0, expires_at);
        request.funds_target = prices.fees.grant;
        request.allowance = prices.fees.grant;
        request.limit = prices.fees.grant;
        let first = plan(&controller, &deployed, &prices.fees, &request, &zero);
        assert_eq!(renew(&mut controller, &root, &first, 0), 0);
        let funded = observe(&controller);
        assert!(
            funded.storage.bits > deployed.storage.bits,
            "the first authorization did not grow the persistent data"
        );

        request.funds_target = funded.state.funds + deposit;
        let planned = plan(&controller, &funded, &prices.fees, &request, &zero);
        assert_eq!(planned.deposit, deposit);
        assert_eq!(renew(&mut controller, &root, &planned, 1), 0, "deposit {deposit}");
        let after = observe(&controller);
        assert_eq!(after.balance, planned.capital_after, "deposit {deposit}");
        assert_eq!(after.state.funds, planned.funds_after, "deposit {deposit}");
    }
}
