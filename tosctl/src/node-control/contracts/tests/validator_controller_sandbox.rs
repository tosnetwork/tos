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

const ERROR_WRONG_NETWORK: i32 = 91;
const ERROR_STALE_EPOCH: i32 = 92;
const ERROR_BAD_NONCE: i32 = 93;
const ERROR_EXPIRED: i32 = 94;
const ERROR_BAD_KIND: i32 = 95;
const ERROR_BAD_COSIGNATURE: i32 = 96;
const ERROR_BAD_ACTION: i32 = 97;
const ERROR_BAD_SIGNATURE: i32 = 98;
const ERROR_NOT_INTERNAL: i32 = 99;

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
            run_key_tool(&["keygen", file.to_str().expect("path")]);
        }
        let public_key =
            hex::decode(&run_key_tool(&["public", file.to_str().expect("path")])[0]).expect("hex");
        assert_eq!(public_key.len(), 1312);
        RootKey { file, public_key }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = hex::decode(
            &run_key_tool(&[
                "sign",
                self.file.to_str().expect("path"),
                &hex::encode(message),
                &hex::encode(CONTROLLER_CONTEXT),
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
    use chain_block::IBitstring;
    let mut data = chain_block::BuilderData::new();
    data.append_u64(epoch).expect("epoch");
    data.append_u64(nonce).expect("nonce");
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
        let key = result.stack[2].as_cell().expect("a key cell").clone();
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
