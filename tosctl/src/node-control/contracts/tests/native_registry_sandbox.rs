/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Executable lifecycle evidence for the TOS Native Service Registry.
//!
//! These tests deliberately build the canonical cells directly. This keeps
//! the contract test independent of the Go SDK while proving that the TVM
//! accepts generation resets with a live predecessor and that recovery is
//! bound to the policy under which it was initiated.
//!
//! Controllers are ML-DSA-44 keys derived from fixed seeds, and every
//! signature is a real Pure ML-DSA-44 signature over the 32 raw bytes of the
//! action hash under the registry context, checked by PQCHECKSIG_MLDSA44.

#[path = "fixtures/current_network.rs"]
mod current_network;

use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
    TrComputePhase, TransactionDescr, base64_decode, read_single_root_boc,
};
use contracts::native_registry::{
    NATIVE_REGISTRY_ERR_POLICY_TOO_WIDE, NATIVE_REGISTRY_GAS_CEILING,
    NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS, NATIVE_REGISTRY_TRANSACTION_GAS_LIMIT, NativePolicy,
    NativePolicyController, build_policy,
};
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer as _};
use sha2::{Digest, Sha256};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, Treasury};

const TOS: u64 = 1_000_000_000;
const OP_SUBMIT: u32 = 0x4e56_0001;
const OP_AUTHORIZE_CAPABILITY: u32 = 0x4e56_0002;
const OP_AUTHORIZED_CAPABILITY: u32 = 0x4e56_0003;
const MAGIC_DATA: u32 = 0x4e56_4431;
const MAGIC_ACTION: u32 = 0x4e56_4131;
const MAGIC_STATE: u32 = 0x4e56_5331;
const MAGIC_POLICY: u32 = 0x4e56_5031;
const MAGIC_IDENTITY: u32 = 0x4e56_4931;
const REGISTER_AGENT: u8 = 1;
const UPDATE_AGENT_POLICY: u8 = 2;
const DELEGATE_AGENT: u8 = 3;
const INITIATE_RECOVERY: u8 = 4;
const COMPLETE_RECOVERY: u8 = 5;
const REVOKE_AGENT: u8 = 6;
const REGISTER_CAPABILITY: u8 = 7;
const ADD_CAPABILITY_VERSION: u8 = 8;
const TRANSFER_CAPABILITY: u8 = 9;
const REVOKE_CAPABILITY: u8 = 10;
const ERR_WRONG_NETWORK: i32 = 2201;
const ERR_BAD_ACTION: i32 = 2203;
const ERR_BAD_PREDECESSOR: i32 = 2204;
const ERR_BAD_SEQUENCE: i32 = 2205;
const ERR_TOMBSTONED: i32 = 2206;
const ERR_BAD_TRANSITION: i32 = 2210;
const ERR_BAD_POLICY: i32 = 2207;
const ERR_BAD_SIGNATURE: i32 = 2208;
const ERR_IMMUTABLE_VERSION: i32 = 2211;
const ERR_TIMELOCK: i32 = 2212;

fn code() -> Cell {
    let encoded: String =
        include_str!("../../../../../crypto/smartcont/tos-service-native-registry-v1.boc.base64")
            .split_whitespace()
            .collect();
    read_single_root_boc(base64_decode(&encoded).expect("base64 code"))
        .expect("native registry code")
}

fn bytes_hash(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

const SIGNATURE_CONTEXT: &[u8] = b"TOS-NATIVE-REGISTRY";
const KEY_ID_DOMAIN: &[u8] = b"TOS-PQ-CONSENSUS-KEY-v1";
const ML_DSA_44_PUBLIC_KEY_BYTES: usize = 1312;
const ML_DSA_44_SIGNATURE_BYTES: usize = 2420;
const CHUNK_BYTES: usize = 127;
const ALL_PURPOSES: u16 = 0x0f;

/// Bytes as the registry stores key and signature material: a chain of full
/// 127-byte cells ending in a non-empty cell.
fn byte_chain(bytes: &[u8]) -> Cell {
    let mut next: Option<Cell> = None;
    for chunk in bytes.chunks(CHUNK_BYTES).rev() {
        let mut cell = BuilderData::new();
        cell.append_raw(chunk, chunk.len() * 8).unwrap();
        if let Some(link) = next {
            cell.checked_append_reference(link).unwrap();
        }
        next = Some(cell.into_cell().unwrap());
    }
    next.expect("non-empty key or signature material")
}

/// `len:uint32 ^chain`, the wrapper a stored key or signature travels in.
fn stored_with_length(length: u32, chain: Cell) -> Cell {
    let mut wrapper = BuilderData::new();
    wrapper.append_u32(length).unwrap().checked_append_reference(chain).unwrap();
    wrapper.into_cell().unwrap()
}

fn stored(bytes: &[u8]) -> Cell {
    stored_with_length(bytes.len() as u32, byte_chain(bytes))
}

/// The registry's key identity: SHA-256 over the domain, the suite number 1
/// as two little-endian bytes, and the public key.
fn key_id(public_key: &[u8]) -> [u8; 32] {
    let mut preimage = KEY_ID_DOMAIN.to_vec();
    preimage.extend_from_slice(&[1, 0]);
    preimage.extend_from_slice(public_key);
    bytes_hash(&preimage)
}

/// An ML-DSA-44 registry controller derived from a fixed seed, so every key
/// in this suite is the same on every run.
#[derive(Clone)]
struct RegistryKey {
    seed: [u8; 32],
    public_key: Vec<u8>,
    secret: ml_dsa_44::PrivateKey,
}

impl RegistryKey {
    fn from_bytes(seed: &[u8; 32]) -> Self {
        let (public_key, secret) = ml_dsa_44::KG::keygen_from_seed(seed);
        let public_key = public_key.into_bytes().to_vec();
        assert_eq!(public_key.len(), ML_DSA_44_PUBLIC_KEY_BYTES);
        Self { seed: *seed, public_key, secret }
    }

    fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn id(&self) -> [u8; 32] {
        key_id(&self.public_key)
    }

    fn stored_key(&self) -> Cell {
        stored(&self.public_key)
    }

    /// The raw signature over `action`'s hash under `context`. The signing
    /// randomness is an explicit argument so that tests are reproducible and
    /// can produce two distinct valid signatures for one action.
    fn signature_bytes(&self, action: &Cell, context: &[u8], randomness: &[u8; 32]) -> Vec<u8> {
        self.secret
            .try_sign_with_seed(randomness, action.hash(0).as_slice(), context)
            .expect("ML-DSA-44 signing")
            .to_vec()
    }

    /// A stored signature wrapper for `action`, as the registry expects it.
    fn sign(&self, action: &Cell) -> Cell {
        stored(&self.signature_bytes(action, SIGNATURE_CONTEXT, &[0x5a; 32]))
    }
}

/// One controller entry: `(key, weight, purposes, recovery)`.
type ControllerSpec<'a> = (&'a RegistryKey, u32, u16, bool);

/// One raw controller entry: `(key_id, stored_key, weight, purposes,
/// recovery)`, so that a test can declare an id or a wrapper that does not
/// match its key.
type ControllerCells = ([u8; 32], Cell, u32, u16, bool);

/// A policy in the registry's layout from raw controller entries, sorted by
/// key id the way the contract requires; the recovery timelock is 10 s.
fn policy_cells(
    threshold: u32,
    recovery_threshold: u32,
    mut entries: Vec<ControllerCells>,
) -> Cell {
    entries.sort_by_key(|entry| entry.0);
    let count = entries.len() as u8;
    let mut next: Option<Cell> = None;
    for (id, stored_key, weight, purposes, recovery) in entries.into_iter().rev() {
        let mut controller = BuilderData::new();
        controller
            .append_u256(&id)
            .unwrap()
            .append_u32(weight)
            .unwrap()
            .append_u16(purposes)
            .unwrap()
            .append_bit_bool(recovery)
            .unwrap()
            .checked_append_reference(stored_key)
            .unwrap();
        if let Some(link) = next {
            controller.checked_append_reference(link).unwrap();
        }
        next = Some(controller.into_cell().unwrap());
    }
    let mut root = BuilderData::new();
    root.append_u32(MAGIC_POLICY)
        .unwrap()
        .append_u16(1)
        .unwrap()
        .append_u32(threshold)
        .unwrap()
        .append_u32(recovery_threshold)
        .unwrap()
        .append_u64(10)
        .unwrap()
        .append_u8(count)
        .unwrap()
        .checked_append_reference(next.expect("a policy has a controller"))
        .unwrap();
    root.into_cell().unwrap()
}

/// A policy over `(key, weight, purposes, recovery)` controllers.
fn policy_of(threshold: u32, recovery_threshold: u32, controllers: &[ControllerSpec]) -> Cell {
    policy_cells(
        threshold,
        recovery_threshold,
        controllers
            .iter()
            .map(|(key, weight, purposes, recovery)| {
                (key.id(), key.stored_key(), *weight, *purposes, *recovery)
            })
            .collect(),
    )
}

/// One controller holding every purpose and the recovery designation.
fn policy(key: &RegistryKey) -> Cell {
    policy_of(1, 1, &[(key, 1, ALL_PURPOSES, true)])
}

/// Two controllers whose purposes are partitioned so that the agent
/// threshold of 2 is reachable only by pooling weight across purposes.
fn purpose_partitioned_unreachable_policy() -> Cell {
    let first = RegistryKey::from_bytes(&[0x81; 32]);
    let second = RegistryKey::from_bytes(&[0x82; 32]);
    policy_of(2, 1, &[(&first, 1, 0x05, true), (&second, 1, 0x0a, false)])
}

fn signature_set(key: &RegistryKey, action: &Cell) -> Cell {
    signature_set_many(&[key], action)
}

fn purpose_isolated_policy() -> (Cell, Vec<RegistryKey>) {
    three_controller_policy([0x05, 0x02, 0x08])
}

/// Three controllers with the given purpose bits (0x04 marks a recovery key),
/// threshold 1 for every purpose. Keys are returned in policy (key id) order
/// so a possession list signed in that order lines up with the policy.
fn three_controller_policy(purposes: [u16; 3]) -> (Cell, Vec<RegistryKey>) {
    let mut keyed: Vec<(RegistryKey, u16)> = [[0x91u8; 32], [0x92; 32], [0x93; 32]]
        .iter()
        .zip(purposes)
        .map(|(seed, purpose)| (RegistryKey::from_bytes(seed), purpose))
        .collect();
    keyed.sort_by_key(|(key, _)| key.id());
    let controllers: Vec<ControllerSpec> =
        keyed.iter().map(|(key, purpose)| (key, 1, *purpose, purpose & 0x04 != 0)).collect();
    let policy = policy_of(1, 1, &controllers);
    (policy, keyed.into_iter().map(|(key, _)| key).collect())
}

/// A signature list from `(key_id, stored_signature)` pairs, sorted by id.
fn signature_entries(mut entries: Vec<([u8; 32], Cell)>) -> Cell {
    entries.sort_by_key(|entry| entry.0);
    signature_entries_in_order(entries)
}

/// [`signature_entries`] without sorting, for tests of the order rule.
fn signature_entries_in_order(entries: Vec<([u8; 32], Cell)>) -> Cell {
    let count = entries.len() as u8;
    let mut next: Option<Cell> = None;
    for (id, signature) in entries.into_iter().rev() {
        let mut entry = BuilderData::new();
        entry.append_u256(&id).unwrap().checked_append_reference(signature).unwrap();
        if let Some(link) = next {
            entry.checked_append_reference(link).unwrap();
        }
        next = Some(entry.into_cell().unwrap());
    }
    let mut root = BuilderData::new();
    root.append_u8(count).unwrap();
    if let Some(first) = next {
        root.checked_append_reference(first).unwrap();
    }
    root.into_cell().unwrap()
}

fn signed(key: &RegistryKey, action: &Cell) -> ([u8; 32], Cell) {
    (key.id(), key.sign(action))
}

fn signature_set_many(keys: &[&RegistryKey], action: &Cell) -> Cell {
    signature_entries(keys.iter().map(|key| signed(key, action)).collect())
}

fn empty_signatures() -> Cell {
    let mut b = BuilderData::new();
    b.append_u8(0).unwrap();
    b.into_cell().unwrap()
}

fn action(
    kind: u8,
    target_kind: u8,
    generation: u64,
    sequence: u64,
    object_id: &[u8; 32],
    predecessor: &[u8; 32],
    nonce: u8,
    domain: &Cell,
    payload: Cell,
) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(MAGIC_ACTION)
        .unwrap()
        .append_u16(1)
        .unwrap()
        .append_u8(kind)
        .unwrap()
        .append_u8(target_kind)
        .unwrap()
        .append_u64(generation)
        .unwrap()
        .append_u64(sequence)
        .unwrap()
        .append_u256(object_id)
        .unwrap()
        .append_u256(predecessor)
        .unwrap()
        .append_u256(&[nonce; 32])
        .unwrap()
        .checked_append_reference(domain.clone())
        .unwrap()
        .checked_append_reference(payload)
        .unwrap();
    b.into_cell().unwrap()
}

fn authorization_body(action: Cell, authority: Cell, counterparty: Cell) -> Cell {
    capability_body(OP_AUTHORIZE_CAPABILITY, action, authority, counterparty)
}

fn capability_body(opcode: u32, action: Cell, authority: Cell, counterparty: Cell) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(opcode)
        .unwrap()
        .append_u64(1)
        .unwrap()
        .checked_append_reference(action)
        .unwrap()
        .checked_append_reference(authority)
        .unwrap()
        .checked_append_reference(counterparty)
        .unwrap();
    b.into_cell().unwrap()
}

fn submit_body(action: Cell, authority: Cell, counterparty: Cell) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(OP_SUBMIT)
        .unwrap()
        .append_u64(1)
        .unwrap()
        .checked_append_reference(action)
        .unwrap()
        .checked_append_reference(authority)
        .unwrap()
        .checked_append_reference(counterparty)
        .unwrap();
    b.into_cell().unwrap()
}

/// Runs `send` and, when `NATIVE_REGISTRY_TRACE_DIR` is set, records every
/// transaction it caused in the format `scripts/replay-token-bridge-trace.py`
/// replays through the native (C++) transaction engine: the configuration,
/// the account before the send, the inbound message, and the Rust
/// transaction and account afterwards. An account that runs more than once in
/// one cascade has no recorded intermediate state, so only accounts that ran
/// once are recorded.
fn traced(bc: &mut Blockchain, send: impl FnOnce(&mut Blockchain) -> SendResult) -> SendResult {
    use chain_block::{Account, HashmapType, ShardAccount, UInt256, base64_encode, write_boc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    static RECORD: AtomicUsize = AtomicUsize::new(0);

    let Some(dir) = std::env::var_os("NATIVE_REGISTRY_TRACE_DIR") else {
        return send(bc);
    };
    let boc = |cell: Cell| base64_encode(write_boc(&cell).unwrap());
    let config = boc(HashmapType::data(&bc.config_params().config_params).unwrap().clone());
    let before = bc.snapshot();
    let result = send(bc);
    let after = bc.snapshot();

    let mut runs = std::collections::HashMap::<String, usize>::new();
    for (address, _) in &result.transactions {
        *runs.entry(address.to_string()).or_default() += 1;
    }
    let once: Vec<_> =
        result.transactions.iter().filter(|(address, _)| runs[&address.to_string()] == 1).collect();
    bc.restore(before);
    let accounts_before: Vec<Account> = once
        .iter()
        .map(|(address, _)| bc.get_account(address).cloned().unwrap_or_default())
        .collect();
    bc.restore(after);

    let thread = std::thread::current();
    let dir =
        std::path::PathBuf::from(dir).join(thread.name().unwrap_or("main").replace("::", "-"));
    std::fs::create_dir_all(&dir).unwrap();
    for ((address, transaction), account_before) in once.into_iter().zip(accounts_before) {
        let account_after = bc.get_account(address).cloned().unwrap_or_default();
        let record = serde_json::json!({
            "address": address.to_string(),
            "unixtime": transaction.now(),
            "lt": transaction.logical_time().to_string(),
            "config": config,
            "shard_account": boc(
                ShardAccount::with_params(&account_before, UInt256::default(), 0)
                    .unwrap()
                    .serialize()
                    .unwrap()
            ),
            "message": boc(transaction.in_msg_cell().expect("an inbound message")),
            "rust_transaction": boc(transaction.serialize().unwrap()),
            "shard_account_after": boc(
                ShardAccount::with_params(&account_after, UInt256::default(), 0)
                    .unwrap()
                    .serialize()
                    .unwrap()
            ),
        });
        let index = RECORD.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("{index:05}-{}.json", transaction.logical_time()));
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();
        serde_json::to_writer(file, &record).unwrap();
    }
    result
}

struct Fixture {
    bc: Blockchain,
    relayer: Treasury,
    registry: MsgAddressInt,
    object_id: [u8; 32],
    domain: Cell,
    identity_domain: Cell,
    config: Cell,
    contract_code: Cell,
    old_key: RegistryKey,
}

impl Fixture {
    fn new() -> Self {
        // Execute the frozen registry on the current network version, including SHA256C.
        // The registry admits workchain 0 only; run it there under the genesis
        // basechain per-transaction gas limit.
        let mut bc =
            Blockchain::with_global_version_and_base_workchain(current_network::global_version())
                .expect("blockchain");
        bc.set_workchain(0);
        bc.set_workchain_gas_limit(NATIVE_REGISTRY_TRANSACTION_GAS_LIMIT);
        let relayer = bc.treasury("native-registry-relayer", 1_000 * TOS).expect("relayer");
        let old_key = RegistryKey::from_bytes(&[0x31; 32]);
        let old_policy = policy(&old_key);
        let contract_code = code();
        let code_hash = contract_code.hash(0);
        let genesis_root = [0x11; 32];
        let genesis_file = [0x22; 32];
        let network_hash = bytes_hash(b"tos-testnet");

        let mut identity_domain = BuilderData::new();
        identity_domain
            .append_u256(&genesis_root)
            .unwrap()
            .append_u256(&genesis_file)
            .unwrap()
            .append_u256(&network_hash)
            .unwrap();
        let identity_domain = identity_domain.into_cell().unwrap();
        let mut identity = BuilderData::new();
        identity
            .append_u32(MAGIC_IDENTITY)
            .unwrap()
            .append_u8(1)
            .unwrap()
            .append_u256(&[0x44; 32])
            .unwrap()
            .append_raw(old_policy.hash(0).as_slice(), 256)
            .unwrap()
            .checked_append_reference(identity_domain.clone())
            .unwrap();
        let object_id = *identity.into_cell().unwrap().hash(0).as_slice();

        let mut network_id = BuilderData::new();
        network_id.append_raw(b"tos-testnet", 11 * 8).unwrap();
        let mut runtime = BuilderData::new();
        runtime
            .append_i32(0)
            .unwrap()
            .append_raw(code_hash.as_slice(), 256)
            .unwrap()
            .checked_append_reference(network_id.into_cell().unwrap())
            .unwrap()
            .checked_append_reference(contract_code.clone())
            .unwrap();
        let mut config = BuilderData::new();
        config
            .append_u256(&genesis_root)
            .unwrap()
            .append_u256(&genesis_file)
            .unwrap()
            .append_u256(&network_hash)
            .unwrap()
            .checked_append_reference(runtime.into_cell().unwrap())
            .unwrap();
        let config = config.into_cell().unwrap();

        let mut signed_code = BuilderData::new();
        signed_code.append_raw(code_hash.as_slice(), 256).unwrap();
        let mut domain = BuilderData::new();
        domain
            .append_u256(&genesis_root)
            .unwrap()
            .append_u256(&genesis_file)
            .unwrap()
            .append_u256(&network_hash)
            .unwrap()
            .checked_append_reference(signed_code.into_cell().unwrap())
            .unwrap();
        let domain = domain.into_cell().unwrap();

        let mut data = BuilderData::new();
        data.append_u32(MAGIC_DATA)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u8(1)
            .unwrap()
            .append_u256(&object_id)
            .unwrap()
            .checked_append_reference(config.clone())
            .unwrap()
            .append_bit_zero()
            .unwrap();
        let state_init =
            StateInit::with_code_and_data(contract_code.clone(), data.into_cell().unwrap());
        let registry_hash = state_init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let registry = MsgAddressInt::with_params(0, registry_hash).expect("registry address");

        let mut register_payload = BuilderData::new();
        register_payload
            .append_u256(&[0x44; 32])
            .unwrap()
            .checked_append_reference(old_policy)
            .unwrap();
        let register = action(
            REGISTER_AGENT,
            1,
            1,
            1,
            &object_id,
            &[0; 32],
            1,
            &domain,
            register_payload.into_cell().unwrap(),
        );
        let body =
            submit_body(register.clone(), signature_set(&old_key, &register), empty_signatures());
        let deploy = MessageBuilder::internal(relayer.address(), &registry, 20 * TOS)
            .bounce(false)
            .state_init(state_init)
            .body(body)
            .build();
        bc.send_message(deploy).expect("register").expect_success();

        Self {
            bc,
            relayer,
            registry,
            object_id,
            domain,
            identity_domain,
            config,
            contract_code,
            old_key,
        }
    }

    fn state(&self) -> Cell {
        let data = self.bc.get_account(&self.registry).unwrap().get_data().unwrap();
        let mut slice = SliceData::load_cell(data).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), MAGIC_DATA);
        slice.move_by(16 + 8 + 256).unwrap();
        slice.checked_drain_reference().unwrap();
        assert!(slice.get_next_bit().unwrap());
        slice.checked_drain_reference().unwrap()
    }

    fn state_position(&self) -> (u64, u64) {
        let mut state = SliceData::load_cell(self.state()).unwrap();
        assert_eq!(state.get_next_u32().unwrap(), MAGIC_STATE);
        state.move_by(16 + 8 + 1).unwrap();
        (state.get_next_u64().unwrap(), state.get_next_u64().unwrap())
    }

    fn send(&mut self, body: Cell) -> SendResult {
        self.send_to(self.registry.clone(), body)
    }

    fn send_to(&mut self, destination: MsgAddressInt, body: Cell) -> SendResult {
        self.send_value(destination, body, TOS)
    }

    fn send_value(&mut self, destination: MsgAddressInt, body: Cell, value: u64) -> SendResult {
        let msg = MessageBuilder::internal(self.relayer.address(), &destination, value)
            .body(body)
            .build();
        traced(&mut self.bc, |bc| bc.send_message(msg).expect("submit"))
    }

    fn deploy_agent(
        &mut self,
        key: &RegistryKey,
        object_nonce: [u8; 32],
    ) -> ([u8; 32], MsgAddressInt) {
        let agent_policy = policy(key);
        let mut identity = BuilderData::new();
        identity
            .append_u32(MAGIC_IDENTITY)
            .unwrap()
            .append_u8(1)
            .unwrap()
            .append_u256(&object_nonce)
            .unwrap()
            .append_raw(agent_policy.hash(0).as_slice(), 256)
            .unwrap()
            .checked_append_reference(self.identity_domain.clone())
            .unwrap();
        let object_id = *identity.into_cell().unwrap().hash(0).as_slice();

        let mut data = BuilderData::new();
        data.append_u32(MAGIC_DATA)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u8(1)
            .unwrap()
            .append_u256(&object_id)
            .unwrap()
            .checked_append_reference(self.config.clone())
            .unwrap()
            .append_bit_zero()
            .unwrap();
        let state_init =
            StateInit::with_code_and_data(self.contract_code.clone(), data.into_cell().unwrap());
        let address_hash = state_init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let address = MsgAddressInt::with_params(0, address_hash).expect("agent address");

        let mut payload = BuilderData::new();
        payload.append_u256(&object_nonce).unwrap().checked_append_reference(agent_policy).unwrap();
        let register = action(
            REGISTER_AGENT,
            1,
            1,
            1,
            &object_id,
            &[0; 32],
            object_nonce[0],
            &self.domain,
            payload.into_cell().unwrap(),
        );
        let deploy = MessageBuilder::internal(self.relayer.address(), &address, 20 * TOS)
            .bounce(false)
            .state_init(state_init)
            .body(submit_body(register.clone(), signature_set(key, &register), empty_signatures()))
            .build();
        self.bc.send_message(deploy).expect("register agent").expect_success();
        (object_id, address)
    }

    fn state_at(&self, address: &MsgAddressInt) -> Cell {
        let data = self.bc.get_account(address).unwrap().get_data().unwrap();
        let mut slice = SliceData::load_cell(data).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), MAGIC_DATA);
        slice.move_by(16 + 8 + 256).unwrap();
        slice.checked_drain_reference().unwrap();
        assert!(slice.get_next_bit().unwrap());
        slice.checked_drain_reference().unwrap()
    }

    fn build_action(
        &self,
        kind: u8,
        generation: u64,
        sequence: u64,
        nonce: u8,
        payload: Cell,
    ) -> Cell {
        let predecessor = *self.state().hash(0).as_slice();
        action(
            kind,
            1,
            generation,
            sequence,
            &self.object_id,
            &predecessor,
            nonce,
            &self.domain,
            payload,
        )
    }

    fn object_address(&self, object_kind: u8, object_id: &[u8; 32]) -> (MsgAddressInt, StateInit) {
        let mut data = BuilderData::new();
        data.append_u32(MAGIC_DATA)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u8(object_kind)
            .unwrap()
            .append_u256(object_id)
            .unwrap()
            .checked_append_reference(self.config.clone())
            .unwrap()
            .append_bit_zero()
            .unwrap();
        let state_init =
            StateInit::with_code_and_data(self.contract_code.clone(), data.into_cell().unwrap());
        let address_hash = state_init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        (MsgAddressInt::with_params(0, address_hash).expect("object address"), state_init)
    }

    fn build_capability_action(
        &self,
        kind: u8,
        capability_id: &[u8; 32],
        capability_address: &MsgAddressInt,
        generation: u64,
        sequence: u64,
        nonce: u8,
        payload: Cell,
    ) -> Cell {
        let predecessor = if generation == 1 && sequence == 1 {
            [0; 32]
        } else {
            *self.state_at(capability_address).hash(0).as_slice()
        };
        action(
            kind,
            2,
            generation,
            sequence,
            capability_id,
            &predecessor,
            nonce,
            &self.domain,
            payload,
        )
    }

    fn register_capability(
        &mut self,
        owner_id: &[u8; 32],
        owner_address: &MsgAddressInt,
        owner_key: &RegistryKey,
        object_nonce: [u8; 32],
        version: &[u8],
        manifest: [u8; 32],
    ) -> CapabilityHandle {
        let (result, capability) = self.register_capability_by(
            owner_id,
            owner_address,
            |register| signature_set(owner_key, register),
            object_nonce,
            version,
            manifest,
            TOS,
        );
        result.expect_success();
        assert_address_success(&result, &capability.address);
        assert_eq!(capability_position(&self.state_at(&capability.address)), (1, 1));
        capability
    }

    /// Sends a capability registration to its owner agent, signed by
    /// `authority`, carrying `value`; returns the result without judging it.
    #[allow(clippy::too_many_arguments)]
    fn register_capability_by(
        &mut self,
        owner_id: &[u8; 32],
        owner_address: &MsgAddressInt,
        authority: impl Fn(&Cell) -> Cell,
        object_nonce: [u8; 32],
        version: &[u8],
        manifest: [u8; 32],
        value: u64,
    ) -> (SendResult, CapabilityHandle) {
        let version_name = protocol_text(version);
        let version_hash = bytes_hash(version);
        let mut identity_details = BuilderData::new();
        identity_details.append_u256(&version_hash).unwrap().append_u256(&manifest).unwrap();
        let mut identity = BuilderData::new();
        identity
            .append_u32(MAGIC_IDENTITY)
            .unwrap()
            .append_u8(2)
            .unwrap()
            .append_u256(&object_nonce)
            .unwrap()
            .append_u256(owner_id)
            .unwrap()
            .checked_append_reference(self.identity_domain.clone())
            .unwrap()
            .checked_append_reference(identity_details.into_cell().unwrap())
            .unwrap();
        let capability_id = *identity.into_cell().unwrap().hash(0).as_slice();
        let (address, _) = self.object_address(2, &capability_id);

        let mut version_details = BuilderData::new();
        version_details
            .append_u256(&version_hash)
            .unwrap()
            .append_u256(&manifest)
            .unwrap()
            .checked_append_reference(version_name)
            .unwrap();
        let mut payload = BuilderData::new();
        payload
            .append_u256(&object_nonce)
            .unwrap()
            .append_u256(owner_id)
            .unwrap()
            .checked_append_reference(version_details.into_cell().unwrap())
            .unwrap();
        let register = self.build_capability_action(
            REGISTER_CAPABILITY,
            &capability_id,
            &address,
            1,
            1,
            object_nonce[0],
            payload.into_cell().unwrap(),
        );
        let result = self.send_value(
            owner_address.clone(),
            authorization_body(register.clone(), authority(&register), empty_signatures()),
            value,
        );
        (
            result,
            CapabilityHandle { id: capability_id, address, initial_version_hash: version_hash },
        )
    }
}

struct CapabilityHandle {
    id: [u8; 32],
    address: MsgAddressInt,
    initial_version_hash: [u8; 32],
}

/// Canonical protocol text: a byte snake whose every non-final cell holds 127 bytes.
fn protocol_text(value: &[u8]) -> Cell {
    let (head, tail) = value.split_at(value.len().min(127));
    let mut text = BuilderData::new();
    text.append_raw(head, head.len() * 8).unwrap();
    if !tail.is_empty() {
        text.checked_append_reference(protocol_text(tail)).unwrap();
    }
    text.into_cell().unwrap()
}

fn state_header(state: &Cell) -> (u8, bool, u64, u64) {
    let mut state = SliceData::load_cell(state.clone()).unwrap();
    assert_eq!(state.get_next_u32().unwrap(), MAGIC_STATE);
    state.move_by(16).unwrap();
    let kind = state.get_next_int(8).unwrap() as u8;
    let tombstone = state.get_next_bit().unwrap();
    let generation = state.get_next_u64().unwrap();
    let sequence = state.get_next_u64().unwrap();
    (kind, tombstone, generation, sequence)
}

fn capability_position(state: &Cell) -> (u64, u64) {
    let (kind, _, generation, sequence) = state_header(state);
    assert_eq!(kind, 2);
    (generation, sequence)
}

fn capability_owner(state: &Cell) -> [u8; 32] {
    let mut state = SliceData::load_cell(state.clone()).unwrap();
    state.move_by(32 + 16 + 8 + 1 + 64 + 64 + 256).unwrap();
    let mut owner = [0; 32];
    owner.copy_from_slice(&state.get_next_bytes(32).unwrap());
    owner
}

fn assert_address_exit(result: &SendResult, address: &MsgAddressInt, code: i32) {
    let transaction = result
        .transactions_for(address)
        .into_iter()
        .last()
        .expect("expected transaction for address");
    let description = transaction.read_description().expect("transaction description");
    let TransactionDescr::Ordinary(description) = description else {
        panic!("expected ordinary transaction")
    };
    assert!(description.aborted, "expected transaction to abort");
    let TrComputePhase::Vm(vm) = description.compute_ph else {
        panic!("expected VM compute phase")
    };
    assert_eq!(vm.exit_code, code);
}

fn assert_address_success(result: &SendResult, address: &MsgAddressInt) {
    let transaction = result
        .transactions_for(address)
        .into_iter()
        .last()
        .expect("expected transaction for address");
    let description = transaction.read_description().expect("transaction description");
    let TransactionDescr::Ordinary(description) = description else {
        panic!("expected ordinary transaction")
    };
    if description.aborted {
        let code = match description.compute_ph {
            TrComputePhase::Vm(vm) => vm.exit_code,
            _ => i32::MIN,
        };
        panic!("expected transaction to succeed, but it aborted with {code}");
    }
}

#[test]
fn recovery_survives_delegation_and_completes_with_generation_reset() {
    let mut f = Fixture::new();
    let recovery_key = RegistryKey::from_bytes(&[0x52; 32]);
    let recovery_policy = policy(&recovery_key);
    let execute_after = u64::from(f.bc.now()) + 10;

    let mut initiate_payload = BuilderData::new();
    initiate_payload
        .append_u64(execute_after)
        .unwrap()
        .checked_append_reference(recovery_policy)
        .unwrap();
    let initiate =
        f.build_action(INITIATE_RECOVERY, 1, 2, 2, initiate_payload.into_cell().unwrap());
    let initiation_hash = *initiate.hash(0).as_slice();
    f.send(submit_body(
        initiate.clone(),
        signature_set(&f.old_key, &initiate),
        signature_set(&recovery_key, &initiate),
    ))
    .expect_success();

    let mut delegate_payload = BuilderData::new();
    delegate_payload.append_u256(&[0x71; 32]).unwrap();
    let delegate = f.build_action(DELEGATE_AGENT, 1, 3, 3, delegate_payload.into_cell().unwrap());
    f.send(submit_body(delegate.clone(), signature_set(&f.old_key, &delegate), empty_signatures()))
        .expect_success();

    f.bc.set_now((execute_after + 1) as u32);
    let mut complete_payload = BuilderData::new();
    complete_payload.append_u256(&initiation_hash).unwrap();
    let complete =
        f.build_action(COMPLETE_RECOVERY, 2, 1, 4, complete_payload.into_cell().unwrap());
    f.send(submit_body(complete.clone(), signature_set(&f.old_key, &complete), empty_signatures()))
        .expect_success();

    assert_eq!(f.state_position(), (2, 1));
}

#[test]
fn policy_replacement_invalidates_pending_recovery() {
    let mut f = Fixture::new();
    let recovery_key = RegistryKey::from_bytes(&[0x52; 32]);
    let recovery_policy = policy(&recovery_key);
    let execute_after = u64::from(f.bc.now()) + 10;

    let mut initiate_payload = BuilderData::new();
    initiate_payload
        .append_u64(execute_after)
        .unwrap()
        .checked_append_reference(recovery_policy)
        .unwrap();
    let initiate =
        f.build_action(INITIATE_RECOVERY, 1, 2, 2, initiate_payload.into_cell().unwrap());
    let initiation_hash = *initiate.hash(0).as_slice();
    f.send(submit_body(
        initiate.clone(),
        signature_set(&f.old_key, &initiate),
        signature_set(&recovery_key, &initiate),
    ))
    .expect_success();

    let replacement_key = RegistryKey::from_bytes(&[0x63; 32]);
    let mut update_payload = BuilderData::new();
    update_payload.checked_append_reference(policy(&replacement_key)).unwrap();
    let update = f.build_action(UPDATE_AGENT_POLICY, 1, 3, 3, update_payload.into_cell().unwrap());
    f.send(submit_body(
        update.clone(),
        signature_set(&f.old_key, &update),
        signature_set(&replacement_key, &update),
    ))
    .expect_success();

    f.bc.set_now((execute_after + 1) as u32);
    let mut complete_payload = BuilderData::new();
    complete_payload.append_u256(&initiation_hash).unwrap();
    let complete =
        f.build_action(COMPLETE_RECOVERY, 2, 1, 4, complete_payload.into_cell().unwrap());
    f.send(submit_body(
        complete.clone(),
        signature_set(&replacement_key, &complete),
        empty_signatures(),
    ))
    .expect_aborted()
    .expect_exit_code(ERR_BAD_TRANSITION);

    assert_eq!(f.state_position(), (1, 3));
}

#[test]
fn policy_update_rejects_threshold_pooled_across_disjoint_purposes() {
    let mut f = Fixture::new();
    let before = f.state().hash(0);
    let bad_policy = purpose_partitioned_unreachable_policy();
    let mut payload = BuilderData::new();
    payload.checked_append_reference(bad_policy).unwrap();
    let update = f.build_action(UPDATE_AGENT_POLICY, 1, 2, 9, payload.into_cell().unwrap());
    f.send(submit_body(update.clone(), signature_set(&f.old_key, &update), empty_signatures()))
        .expect_aborted()
        .expect_exit_code(ERR_BAD_POLICY);
    assert_eq!(f.state().hash(0), before, "rejected policy update changed state");
}

#[test]
fn policy_update_accepts_reachable_purpose_isolation() {
    let mut f = Fixture::new();
    let (isolated_policy, keys) = purpose_isolated_policy();
    let mut payload = BuilderData::new();
    payload.checked_append_reference(isolated_policy).unwrap();
    let update = f.build_action(UPDATE_AGENT_POLICY, 1, 2, 10, payload.into_cell().unwrap());
    let possession_keys: Vec<_> = keys.iter().collect();
    f.send(submit_body(
        update.clone(),
        signature_set(&f.old_key, &update),
        signature_set_many(&possession_keys, &update),
    ))
    .expect_success();
    assert_eq!(f.state_position(), (1, 2));
}

#[test]
fn agent_registration_rejects_caller_selected_identity() {
    let mut f = Fixture::new();
    let chosen_id = [0xf1; 32];
    let chosen_key = RegistryKey::from_bytes(&[0xf2; 32]);
    let chosen_policy = policy(&chosen_key);
    let (address, state_init) = f.object_address(1, &chosen_id);
    let mut payload = BuilderData::new();
    payload.append_u256(&[0xf3; 32]).unwrap().checked_append_reference(chosen_policy).unwrap();
    let register = action(
        REGISTER_AGENT,
        1,
        1,
        1,
        &chosen_id,
        &[0; 32],
        70,
        &f.domain,
        payload.into_cell().unwrap(),
    );
    let deploy = MessageBuilder::internal(f.relayer.address(), &address, 20 * TOS)
        .bounce(false)
        .state_init(state_init)
        .body(submit_body(
            register.clone(),
            signature_set(&chosen_key, &register),
            empty_signatures(),
        ))
        .build();
    f.bc.send_message(deploy)
        .expect("caller-selected registration")
        .expect_aborted()
        .expect_exit_code(ERR_BAD_TRANSITION);
}

#[test]
fn agent_full_lifecycle_replay_revocation_and_terminal_rejection() {
    let mut f = Fixture::new();
    assert_eq!(f.state_position(), (1, 1), "registration position");

    let replacement_key = RegistryKey::from_bytes(&[0xa1; 32]);
    let mut update_payload = BuilderData::new();
    update_payload.checked_append_reference(policy(&replacement_key)).unwrap();
    let update = f.build_action(UPDATE_AGENT_POLICY, 1, 2, 20, update_payload.into_cell().unwrap());
    let update_body = submit_body(
        update.clone(),
        signature_set(&f.old_key, &update),
        signature_set(&replacement_key, &update),
    );
    f.send(update_body.clone()).expect_success();
    let updated = f.state();
    assert_eq!(f.state_position(), (1, 2));

    f.send(update_body).expect_success();
    assert_eq!(f.state().hash(0), updated.hash(0), "exact replay changed state");

    let mut delegation_payload = BuilderData::new();
    delegation_payload.append_u256(&[0xa2; 32]).unwrap();
    let delegation =
        f.build_action(DELEGATE_AGENT, 1, 3, 21, delegation_payload.into_cell().unwrap());
    f.send(submit_body(
        delegation.clone(),
        signature_set(&replacement_key, &delegation),
        empty_signatures(),
    ))
    .expect_success();
    assert_eq!(f.state_position(), (1, 3));

    let revoke = f.build_action(REVOKE_AGENT, 1, 4, 22, BuilderData::new().into_cell().unwrap());
    f.send(submit_body(
        revoke.clone(),
        signature_set(&replacement_key, &revoke),
        empty_signatures(),
    ))
    .expect_success();
    let revoked = f.state();
    let (kind, tombstone, generation, sequence) = state_header(&revoked);
    assert_eq!((kind, tombstone, generation, sequence), (1, true, 1, 4));

    let mut forbidden_payload = BuilderData::new();
    forbidden_payload.append_u256(&[0xa3; 32]).unwrap();
    let forbidden =
        f.build_action(DELEGATE_AGENT, 1, 5, 23, forbidden_payload.into_cell().unwrap());
    f.send(submit_body(
        forbidden.clone(),
        signature_set(&replacement_key, &forbidden),
        empty_signatures(),
    ))
    .expect_aborted()
    .expect_exit_code(ERR_TOMBSTONED);
    assert_eq!(f.state().hash(0), revoked.hash(0));
}

#[test]
fn agent_rejects_stale_predecessor_skipped_sequence_wrong_target_and_bad_signature() {
    let mut f = Fixture::new();
    let original_state = f.state();

    let mut payload = BuilderData::new();
    payload.append_u256(&[0xb1; 32]).unwrap();
    let skipped = f.build_action(DELEGATE_AGENT, 1, 3, 30, payload.into_cell().unwrap());
    f.send(submit_body(skipped.clone(), signature_set(&f.old_key, &skipped), empty_signatures()))
        .expect_aborted()
        .expect_exit_code(ERR_BAD_SEQUENCE);

    let mut valid_payload = BuilderData::new();
    valid_payload.append_u256(&[0xb2; 32]).unwrap();
    let valid = f.build_action(DELEGATE_AGENT, 1, 2, 31, valid_payload.into_cell().unwrap());
    f.send(submit_body(valid.clone(), signature_set(&f.old_key, &valid), empty_signatures()))
        .expect_success();

    let mut stale_payload = BuilderData::new();
    stale_payload.append_u256(&[0xb3; 32]).unwrap();
    let stale = action(
        DELEGATE_AGENT,
        1,
        1,
        3,
        &f.object_id,
        original_state.hash(0).as_slice(),
        32,
        &f.domain,
        stale_payload.into_cell().unwrap(),
    );
    f.send(submit_body(stale.clone(), signature_set(&f.old_key, &stale), empty_signatures()))
        .expect_aborted()
        .expect_exit_code(ERR_BAD_PREDECESSOR);

    let mut wrong_target_payload = BuilderData::new();
    wrong_target_payload.append_u256(&[0xb4; 32]).unwrap();
    let wrong_target = action(
        DELEGATE_AGENT,
        1,
        1,
        3,
        &[0xff; 32],
        f.state().hash(0).as_slice(),
        33,
        &f.domain,
        wrong_target_payload.into_cell().unwrap(),
    );
    f.send(submit_body(
        wrong_target.clone(),
        signature_set(&f.old_key, &wrong_target),
        empty_signatures(),
    ))
    .expect_aborted()
    .expect_exit_code(ERR_BAD_ACTION);

    let attacker = RegistryKey::from_bytes(&[0xb5; 32]);
    let mut unsigned_payload = BuilderData::new();
    unsigned_payload.append_u256(&[0xb6; 32]).unwrap();
    let unsigned = f.build_action(DELEGATE_AGENT, 1, 3, 34, unsigned_payload.into_cell().unwrap());
    f.send(submit_body(unsigned.clone(), signature_set(&attacker, &unsigned), empty_signatures()))
        .expect_aborted()
        .expect_exit_code(ERR_BAD_SIGNATURE);

    let mut signed_code = BuilderData::new();
    signed_code.append_raw(f.contract_code.hash(0).as_slice(), 256).unwrap();
    let mut wrong_domain = BuilderData::new();
    wrong_domain
        .append_u256(&[0xff; 32])
        .unwrap()
        .append_u256(&[0x22; 32])
        .unwrap()
        .append_u256(&bytes_hash(b"tos-testnet"))
        .unwrap()
        .checked_append_reference(signed_code.into_cell().unwrap())
        .unwrap();
    let mut wrong_network_payload = BuilderData::new();
    wrong_network_payload.append_u256(&[0xb7; 32]).unwrap();
    let wrong_network = action(
        DELEGATE_AGENT,
        1,
        1,
        3,
        &f.object_id,
        f.state().hash(0).as_slice(),
        35,
        &wrong_domain.into_cell().unwrap(),
        wrong_network_payload.into_cell().unwrap(),
    );
    f.send(submit_body(
        wrong_network.clone(),
        signature_set(&f.old_key, &wrong_network),
        empty_signatures(),
    ))
    .expect_aborted()
    .expect_exit_code(ERR_WRONG_NETWORK);

    let mut extra_signature_payload = BuilderData::new();
    extra_signature_payload.append_u256(&[0xb8; 32]).unwrap();
    let extra_signature =
        f.build_action(DELEGATE_AGENT, 1, 3, 36, extra_signature_payload.into_cell().unwrap());
    f.send(submit_body(
        extra_signature.clone(),
        signature_set(&f.old_key, &extra_signature),
        signature_set(&f.old_key, &extra_signature),
    ))
    .expect_aborted()
    .expect_exit_code(ERR_BAD_SIGNATURE);
    assert_eq!(f.state_position(), (1, 2));
}

#[test]
fn recovery_rejects_early_completion_and_superseded_initiation() {
    let mut f = Fixture::new();
    let first_key = RegistryKey::from_bytes(&[0xc1; 32]);
    let second_key = RegistryKey::from_bytes(&[0xc2; 32]);
    let first_execute_after = u64::from(f.bc.now()) + 10;

    let mut first_payload = BuilderData::new();
    first_payload
        .append_u64(first_execute_after)
        .unwrap()
        .checked_append_reference(policy(&first_key))
        .unwrap();
    let first = f.build_action(INITIATE_RECOVERY, 1, 2, 40, first_payload.into_cell().unwrap());
    let first_hash = *first.hash(0).as_slice();
    f.send(submit_body(
        first.clone(),
        signature_set(&f.old_key, &first),
        signature_set(&first_key, &first),
    ))
    .expect_success();

    let mut zero_predecessor_payload = BuilderData::new();
    zero_predecessor_payload.append_u256(&first_hash).unwrap();
    let zero_predecessor = action(
        COMPLETE_RECOVERY,
        1,
        2,
        1,
        &f.object_id,
        &[0; 32],
        45,
        &f.domain,
        zero_predecessor_payload.into_cell().unwrap(),
    );
    f.send(submit_body(
        zero_predecessor.clone(),
        signature_set(&f.old_key, &zero_predecessor),
        empty_signatures(),
    ))
    .expect_aborted()
    .expect_exit_code(ERR_BAD_PREDECESSOR);

    let mut early_payload = BuilderData::new();
    early_payload.append_u256(&first_hash).unwrap();
    let early = f.build_action(COMPLETE_RECOVERY, 2, 1, 41, early_payload.into_cell().unwrap());
    f.send(submit_body(early.clone(), signature_set(&f.old_key, &early), empty_signatures()))
        .expect_aborted()
        .expect_exit_code(ERR_TIMELOCK);

    let second_execute_after = first_execute_after + 1;
    let mut second_payload = BuilderData::new();
    second_payload
        .append_u64(second_execute_after)
        .unwrap()
        .checked_append_reference(policy(&second_key))
        .unwrap();
    let second = f.build_action(INITIATE_RECOVERY, 1, 3, 42, second_payload.into_cell().unwrap());
    let second_hash = *second.hash(0).as_slice();
    f.send(submit_body(
        second.clone(),
        signature_set(&f.old_key, &second),
        signature_set(&second_key, &second),
    ))
    .expect_success();

    f.bc.set_now((second_execute_after + 1) as u32);
    let mut stale_payload = BuilderData::new();
    stale_payload.append_u256(&first_hash).unwrap();
    let stale = f.build_action(COMPLETE_RECOVERY, 2, 1, 43, stale_payload.into_cell().unwrap());
    f.send(submit_body(stale.clone(), signature_set(&f.old_key, &stale), empty_signatures()))
        .expect_aborted()
        .expect_exit_code(ERR_BAD_TRANSITION);

    let mut complete_payload = BuilderData::new();
    complete_payload.append_u256(&second_hash).unwrap();
    let complete =
        f.build_action(COMPLETE_RECOVERY, 2, 1, 44, complete_payload.into_cell().unwrap());
    f.send(submit_body(complete.clone(), signature_set(&f.old_key, &complete), empty_signatures()))
        .expect_success();
    assert_eq!(f.state_position(), (2, 1));
}

#[test]
fn capability_full_lifecycle_transfer_is_atomic_and_terminal() {
    let mut f = Fixture::new();
    let old_owner_id = f.object_id;
    let old_owner_address = f.registry.clone();
    let old_owner_key = RegistryKey::from_bytes(&f.old_key.to_bytes());
    let new_owner_key = RegistryKey::from_bytes(&[0xd1; 32]);
    let (new_owner_id, new_owner_address) = f.deploy_agent(&new_owner_key, [0xd2; 32]);
    let capability = f.register_capability(
        &old_owner_id,
        &old_owner_address,
        &old_owner_key,
        [0xd3; 32],
        b"1.0.0",
        [0xd4; 32],
    );
    assert_eq!(capability_owner(&f.state_at(&capability.address)), old_owner_id);

    let version_name = protocol_text(b"1.1.0");
    let version_hash = bytes_hash(b"1.1.0");
    let mut add_payload = BuilderData::new();
    add_payload
        .append_u256(&old_owner_id)
        .unwrap()
        .append_u256(&version_hash)
        .unwrap()
        .append_u256(&[0xd5; 32])
        .unwrap()
        .checked_append_reference(version_name.clone())
        .unwrap();
    let add = f.build_capability_action(
        ADD_CAPABILITY_VERSION,
        &capability.id,
        &capability.address,
        1,
        2,
        50,
        add_payload.into_cell().unwrap(),
    );
    f.send_to(
        old_owner_address.clone(),
        authorization_body(add.clone(), signature_set(&old_owner_key, &add), empty_signatures()),
    )
    .expect_success();
    assert_eq!(capability_position(&f.state_at(&capability.address)), (1, 2));

    let mut revoke_version_payload = BuilderData::new();
    revoke_version_payload
        .append_u256(&old_owner_id)
        .unwrap()
        .append_bit_one()
        .unwrap()
        .append_u256(&version_hash)
        .unwrap()
        .checked_append_reference(version_name)
        .unwrap();
    let revoke_version = f.build_capability_action(
        REVOKE_CAPABILITY,
        &capability.id,
        &capability.address,
        1,
        3,
        51,
        revoke_version_payload.into_cell().unwrap(),
    );
    f.send_to(
        old_owner_address.clone(),
        authorization_body(
            revoke_version.clone(),
            signature_set(&old_owner_key, &revoke_version),
            empty_signatures(),
        ),
    )
    .expect_success();

    let after_version_revoke = f.state_at(&capability.address);
    let mut repeat_revoke_payload = BuilderData::new();
    repeat_revoke_payload
        .append_u256(&old_owner_id)
        .unwrap()
        .append_bit_one()
        .unwrap()
        .append_u256(&version_hash)
        .unwrap()
        .checked_append_reference(protocol_text(b"1.1.0"))
        .unwrap();
    let repeat_revoke = f.build_capability_action(
        REVOKE_CAPABILITY,
        &capability.id,
        &capability.address,
        1,
        4,
        56,
        repeat_revoke_payload.into_cell().unwrap(),
    );
    let repeat_result = f.send_to(
        old_owner_address.clone(),
        authorization_body(
            repeat_revoke.clone(),
            signature_set(&old_owner_key, &repeat_revoke),
            empty_signatures(),
        ),
    );
    assert_address_exit(&repeat_result, &capability.address, ERR_IMMUTABLE_VERSION);
    assert_eq!(f.state_at(&capability.address).hash(0), after_version_revoke.hash(0));

    let mut transfer_payload = BuilderData::new();
    transfer_payload.append_u256(&old_owner_id).unwrap().append_u256(&new_owner_id).unwrap();
    let transfer = f.build_capability_action(
        TRANSFER_CAPABILITY,
        &capability.id,
        &capability.address,
        2,
        1,
        52,
        transfer_payload.into_cell().unwrap(),
    );
    f.send_to(
        old_owner_address.clone(),
        authorization_body(
            transfer.clone(),
            signature_set(&old_owner_key, &transfer),
            signature_set(&new_owner_key, &transfer),
        ),
    )
    .expect_success();
    let transferred = f.state_at(&capability.address);
    assert_eq!(capability_position(&transferred), (2, 1));
    assert_eq!(capability_owner(&transferred), new_owner_id);

    let mut old_owner_payload = BuilderData::new();
    old_owner_payload
        .append_u256(&old_owner_id)
        .unwrap()
        .append_u256(&bytes_hash(b"2.0.0"))
        .unwrap()
        .append_u256(&[0xd6; 32])
        .unwrap()
        .checked_append_reference(protocol_text(b"2.0.0"))
        .unwrap();
    let former_owner_action = f.build_capability_action(
        ADD_CAPABILITY_VERSION,
        &capability.id,
        &capability.address,
        2,
        2,
        53,
        old_owner_payload.into_cell().unwrap(),
    );
    let result = f.send_to(
        old_owner_address,
        authorization_body(
            former_owner_action.clone(),
            signature_set(&old_owner_key, &former_owner_action),
            empty_signatures(),
        ),
    );
    assert_address_exit(&result, &capability.address, ERR_BAD_TRANSITION);
    assert_eq!(f.state_at(&capability.address).hash(0), transferred.hash(0));

    let mut terminal_payload = BuilderData::new();
    terminal_payload.append_u256(&new_owner_id).unwrap().append_bit_zero().unwrap();
    let terminal = f.build_capability_action(
        REVOKE_CAPABILITY,
        &capability.id,
        &capability.address,
        2,
        2,
        54,
        terminal_payload.into_cell().unwrap(),
    );
    f.send_to(
        new_owner_address.clone(),
        authorization_body(
            terminal.clone(),
            signature_set(&new_owner_key, &terminal),
            empty_signatures(),
        ),
    )
    .expect_success();
    let tombstoned = f.state_at(&capability.address);
    assert_eq!(state_header(&tombstoned), (2, true, 2, 2));

    let mut forbidden_payload = BuilderData::new();
    forbidden_payload
        .append_u256(&new_owner_id)
        .unwrap()
        .append_u256(&bytes_hash(b"3.0.0"))
        .unwrap()
        .append_u256(&[0xd7; 32])
        .unwrap()
        .checked_append_reference(protocol_text(b"3.0.0"))
        .unwrap();
    let forbidden = f.build_capability_action(
        ADD_CAPABILITY_VERSION,
        &capability.id,
        &capability.address,
        2,
        3,
        55,
        forbidden_payload.into_cell().unwrap(),
    );
    let result = f.send_to(
        new_owner_address,
        authorization_body(
            forbidden.clone(),
            signature_set(&new_owner_key, &forbidden),
            empty_signatures(),
        ),
    );
    assert_address_exit(&result, &capability.address, ERR_TOMBSTONED);
    assert_eq!(f.state_at(&capability.address).hash(0), tombstoned.hash(0));
}

#[test]
fn capability_rejects_duplicate_version_and_failed_transfer_is_state_atomic() {
    let mut f = Fixture::new();
    let old_owner_id = f.object_id;
    let old_owner_address = f.registry.clone();
    let old_owner_key = RegistryKey::from_bytes(&f.old_key.to_bytes());
    let new_owner_key = RegistryKey::from_bytes(&[0xe1; 32]);
    let wrong_acceptance_key = RegistryKey::from_bytes(&[0xe2; 32]);
    let (new_owner_id, _) = f.deploy_agent(&new_owner_key, [0xe3; 32]);
    let capability = f.register_capability(
        &old_owner_id,
        &old_owner_address,
        &old_owner_key,
        [0xe4; 32],
        b"1.0.0",
        [0xe5; 32],
    );

    let before_duplicate = f.state_at(&capability.address);
    let direct_version = b"1.0.1";
    let mut direct_payload = BuilderData::new();
    direct_payload
        .append_u256(&old_owner_id)
        .unwrap()
        .append_u256(&bytes_hash(direct_version))
        .unwrap()
        .append_u256(&[0xe6; 32])
        .unwrap()
        .checked_append_reference(protocol_text(direct_version))
        .unwrap();
    let direct = f.build_capability_action(
        ADD_CAPABILITY_VERSION,
        &capability.id,
        &capability.address,
        1,
        2,
        59,
        direct_payload.into_cell().unwrap(),
    );
    let direct_result = f.send_to(
        capability.address.clone(),
        capability_body(
            OP_AUTHORIZED_CAPABILITY,
            direct.clone(),
            signature_set(&old_owner_key, &direct),
            empty_signatures(),
        ),
    );
    direct_result.expect_aborted().expect_exit_code(ERR_BAD_SIGNATURE);
    assert_eq!(f.state_at(&capability.address).hash(0), before_duplicate.hash(0));

    let mut duplicate_payload = BuilderData::new();
    duplicate_payload
        .append_u256(&old_owner_id)
        .unwrap()
        .append_u256(&capability.initial_version_hash)
        .unwrap()
        .append_u256(&[0xff; 32])
        .unwrap()
        .checked_append_reference(protocol_text(b"1.0.0"))
        .unwrap();
    let duplicate = f.build_capability_action(
        ADD_CAPABILITY_VERSION,
        &capability.id,
        &capability.address,
        1,
        2,
        60,
        duplicate_payload.into_cell().unwrap(),
    );
    let result = f.send_to(
        old_owner_address.clone(),
        authorization_body(
            duplicate.clone(),
            signature_set(&old_owner_key, &duplicate),
            empty_signatures(),
        ),
    );
    assert_address_exit(&result, &capability.address, ERR_IMMUTABLE_VERSION);
    assert_eq!(f.state_at(&capability.address).hash(0), before_duplicate.hash(0));

    let mut transfer_payload = BuilderData::new();
    transfer_payload.append_u256(&old_owner_id).unwrap().append_u256(&new_owner_id).unwrap();
    let transfer = f.build_capability_action(
        TRANSFER_CAPABILITY,
        &capability.id,
        &capability.address,
        2,
        1,
        61,
        transfer_payload.into_cell().unwrap(),
    );
    let rejected_by_current_owner = f.send_to(
        old_owner_address.clone(),
        authorization_body(
            transfer.clone(),
            signature_set(&wrong_acceptance_key, &transfer),
            signature_set(&new_owner_key, &transfer),
        ),
    );
    rejected_by_current_owner.expect_aborted().expect_exit_code(ERR_BAD_SIGNATURE);
    assert_eq!(f.state_at(&capability.address).hash(0), before_duplicate.hash(0));

    let failed = f.send_to(
        old_owner_address,
        authorization_body(
            transfer.clone(),
            signature_set(&old_owner_key, &transfer),
            signature_set(&wrong_acceptance_key, &transfer),
        ),
    );
    assert_address_exit(&failed, &f.object_address(1, &new_owner_id).0, ERR_BAD_SIGNATURE);
    assert_eq!(f.state_at(&capability.address).hash(0), before_duplicate.hash(0));
    assert_eq!(capability_owner(&f.state_at(&capability.address)), old_owner_id);
}

const ERR_THRESHOLD: i32 = 2209;

impl Fixture {
    /// Replaces the agent's stored policy without going through any action,
    /// as a hand-built account state could carry it.
    fn install_policy(&mut self, policy: Cell) {
        let (address, object_id) = (self.registry.clone(), self.object_id);
        self.install_policy_at(&address, &object_id, policy);
    }

    /// [`Fixture::install_policy`] for the agent at `address`.
    fn install_policy_at(&mut self, address: &MsgAddressInt, object_id: &[u8; 32], policy: Cell) {
        let mut state = SliceData::load_cell(self.state_at(address)).unwrap();
        let header = state.get_next_slice(32 + 16 + 8 + 1 + 64 + 64 + 256).unwrap();
        state.checked_drain_reference().unwrap();
        let delegations = state.checked_drain_reference().unwrap();
        let recovery = state.checked_drain_reference().unwrap();
        let mut next_state = BuilderData::new();
        next_state
            .append_builder(&header.as_builder().unwrap())
            .unwrap()
            .checked_append_reference(policy)
            .unwrap()
            .checked_append_reference(delegations)
            .unwrap()
            .checked_append_reference(recovery)
            .unwrap();
        let mut data = BuilderData::new();
        data.append_u32(MAGIC_DATA)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u8(1)
            .unwrap()
            .append_u256(object_id)
            .unwrap()
            .checked_append_reference(self.config.clone())
            .unwrap()
            .append_bit_one()
            .unwrap()
            .checked_append_reference(next_state.into_cell().unwrap())
            .unwrap();
        let mut account = self.bc.get_account(address).unwrap().clone();
        assert!(account.set_data(data.into_cell().unwrap()));
        self.bc.set_account(address.clone(), account);
    }

    fn delegate_action(&self, sequence: u64, nonce: u8) -> Cell {
        let mut payload = BuilderData::new();
        payload.append_u256(&[nonce; 32]).unwrap();
        self.build_action(DELEGATE_AGENT, 1, sequence, nonce, payload.into_cell().unwrap())
    }

    /// Deploys a new agent registering `agent_policy`, signed by `authority`.
    fn register_with(
        &mut self,
        agent_policy: Cell,
        object_nonce: [u8; 32],
        authority: impl Fn(&Cell) -> Cell,
    ) -> (SendResult, MsgAddressInt) {
        let (deploy, address) = self.registration_message(agent_policy, object_nonce, authority);
        (traced(&mut self.bc, |bc| bc.send_message(deploy).expect("register")), address)
    }

    /// The deploying registration message [`Fixture::register_with`] sends.
    fn registration_message(
        &self,
        agent_policy: Cell,
        object_nonce: [u8; 32],
        authority: impl Fn(&Cell) -> Cell,
    ) -> (chain_block::Message, MsgAddressInt) {
        let mut identity = BuilderData::new();
        identity
            .append_u32(MAGIC_IDENTITY)
            .unwrap()
            .append_u8(1)
            .unwrap()
            .append_u256(&object_nonce)
            .unwrap()
            .append_raw(agent_policy.hash(0).as_slice(), 256)
            .unwrap()
            .checked_append_reference(self.identity_domain.clone())
            .unwrap();
        let object_id = *identity.into_cell().unwrap().hash(0).as_slice();
        let (address, state_init) = self.object_address(1, &object_id);
        let mut payload = BuilderData::new();
        payload.append_u256(&object_nonce).unwrap().checked_append_reference(agent_policy).unwrap();
        let register = action(
            REGISTER_AGENT,
            1,
            1,
            1,
            &object_id,
            &[0; 32],
            object_nonce[0],
            &self.domain,
            payload.into_cell().unwrap(),
        );
        let deploy = MessageBuilder::internal(self.relayer.address(), &address, 20 * TOS)
            .bounce(false)
            .state_init(state_init)
            .body(submit_body(register.clone(), authority(&register), empty_signatures()))
            .build();
        (deploy, address)
    }

    fn registered(&self, address: &MsgAddressInt) -> bool {
        self.bc.get_account(address).and_then(|account| account.get_data()).is_some_and(|data| {
            let mut slice = SliceData::load_cell(data).unwrap();
            slice.move_by(32 + 16 + 8 + 256).unwrap();
            slice.checked_drain_reference().unwrap();
            slice.get_next_bit().unwrap()
        })
    }
}

// ---------------------------------------------------------------------------
// Supported policy width.
//
// Every path that walks a policy or checks a signature per controller is
// measured at maximum-width inputs: every controller holds every purpose and
// the recovery flag, and every controller signs. Each such path must stay
// within the gas ceiling at the supported width, and one controller more must
// be refused wherever a policy enters storage.
// ---------------------------------------------------------------------------

const MAX_WIDTH: usize = NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS;
const ERR_POLICY_TOO_WIDE: i32 = NATIVE_REGISTRY_ERR_POLICY_TOO_WIDE;
/// Enough value for the whole basechain gas limit and a second leg.
const MEASURE_VALUE: u64 = 40 * TOS;

/// `width` deterministic keys, distinct per `salt`.
fn width_keys(width: usize, salt: u8) -> Vec<RegistryKey> {
    (0..width as u32)
        .map(|counter| {
            let mut seed = vec![salt];
            seed.extend_from_slice(&counter.to_be_bytes());
            RegistryKey::from_bytes(&bytes_hash(&seed))
        })
        .collect()
}

/// Every key holds every purpose and the recovery flag with weight 1, and both
/// thresholds need every key.
fn wide_policy(keys: &[RegistryKey]) -> Cell {
    let controllers: Vec<ControllerSpec> =
        keys.iter().map(|key| (key, 1, ALL_PURPOSES, true)).collect();
    policy_of(keys.len() as u32, keys.len() as u32, &controllers)
}

fn all_sign(keys: &[RegistryKey], action: &Cell) -> Cell {
    signature_entries(keys.iter().map(|key| signed(key, action)).collect())
}

#[derive(Clone, Copy, Debug)]
struct Gas {
    used: u64,
    limit: u64,
    exit: i32,
    aborted: bool,
}

/// The compute phase of the last transaction `result` ran on `address`.
fn gas_at(result: &SendResult, address: &MsgAddressInt) -> Gas {
    let transaction =
        result.transactions_for(address).into_iter().last().expect("transaction for address");
    let TransactionDescr::Ordinary(description) =
        transaction.read_description().expect("transaction description")
    else {
        panic!("expected ordinary transaction")
    };
    match description.compute_ph {
        TrComputePhase::Vm(vm) => Gas {
            used: vm.gas_used.as_u64(),
            limit: vm.gas_limit.as_u64(),
            exit: vm.exit_code,
            aborted: description.aborted,
        },
        TrComputePhase::Skipped(skipped) => panic!("compute skipped: {:?}", skipped.reason),
    }
}

/// Every policy-walking path, measured once.
#[derive(Debug)]
struct PathGas {
    register: Gas,
    delegate: Gas,
    revoke_agent: Gas,
    update: Gas,
    initiate_recovery: Gas,
    complete_recovery: Gas,
    authorize_register_capability: Gas,
    authorize_add_version: Gas,
    authorize_revoke_version: Gas,
    transfer_old_owner: Gas,
    transfer_new_owner: Gas,
}

impl PathGas {
    fn rows(&self) -> [(&'static str, Gas); 11] {
        [
            ("register_agent", self.register),
            ("delegate_agent", self.delegate),
            ("revoke_agent", self.revoke_agent),
            ("update_agent_policy", self.update),
            ("initiate_recovery", self.initiate_recovery),
            ("complete_recovery", self.complete_recovery),
            ("authorize register_capability", self.authorize_register_capability),
            ("authorize add_capability_version", self.authorize_add_version),
            ("authorize revoke_capability", self.authorize_revoke_version),
            ("transfer_capability (old owner)", self.transfer_old_owner),
            ("transfer_capability (new owner)", self.transfer_new_owner),
        ]
    }
}

/// A 128-byte version name, the longest protocol text, so the capability
/// paths carry their largest payload.
fn longest_version(tag: u8) -> Vec<u8> {
    let mut name = vec![b'v'; 128];
    name[1] = b'a' + tag;
    name
}

/// Measures every path for an agent whose policy has `width` controllers and
/// whose new, recovery or transfer-recipient policy has `next_width`.
fn measure_paths(width: usize, next_width: usize) -> PathGas {
    let keys = width_keys(width, 1);
    let next_keys = width_keys(next_width, 2);

    // Registration of a `width` policy.
    let register = {
        let mut f = Fixture::new();
        let (result, address) =
            f.register_with(wide_policy(&keys), [0x60; 32], |action| all_sign(&keys, action));
        gas_at(&result, &address)
    };

    // Actions authorized by a stored `width` policy.
    let agent = |kind: u8, payload: Cell| {
        let mut f = Fixture::new();
        f.install_policy(wide_policy(&keys));
        let action = f.build_action(kind, 1, 2, 0x61, payload);
        let result = f.send_value(
            f.registry.clone(),
            submit_body(action.clone(), all_sign(&keys, &action), empty_signatures()),
            MEASURE_VALUE,
        );
        gas_at(&result, &f.registry)
    };
    let delegate = {
        let mut payload = BuilderData::new();
        payload.append_u256(&[0x62; 32]).unwrap();
        agent(DELEGATE_AGENT, payload.into_cell().unwrap())
    };
    let revoke_agent = agent(REVOKE_AGENT, BuilderData::new().into_cell().unwrap());

    // Policy update from `width` to `next_width`.
    let update = {
        let mut f = Fixture::new();
        f.install_policy(wide_policy(&keys));
        let mut payload = BuilderData::new();
        payload.checked_append_reference(wide_policy(&next_keys)).unwrap();
        let action = f.build_action(UPDATE_AGENT_POLICY, 1, 2, 0x63, payload.into_cell().unwrap());
        let result = f.send_value(
            f.registry.clone(),
            submit_body(action.clone(), all_sign(&keys, &action), all_sign(&next_keys, &action)),
            MEASURE_VALUE,
        );
        gas_at(&result, &f.registry)
    };

    // Recovery from `width` to a `next_width` recovery policy, then completion.
    let (initiate_recovery, complete_recovery) = {
        let mut f = Fixture::new();
        f.install_policy(wide_policy(&keys));
        let execute_after = u64::from(f.bc.now()) + 10;
        let mut payload = BuilderData::new();
        payload
            .append_u64(execute_after)
            .unwrap()
            .checked_append_reference(wide_policy(&next_keys))
            .unwrap();
        let initiate = f.build_action(INITIATE_RECOVERY, 1, 2, 0x64, payload.into_cell().unwrap());
        let result = f.send_value(
            f.registry.clone(),
            submit_body(
                initiate.clone(),
                all_sign(&keys, &initiate),
                all_sign(&next_keys, &initiate),
            ),
            MEASURE_VALUE,
        );
        let initiate_gas = gas_at(&result, &f.registry);
        f.bc.set_now((execute_after + 1) as u32);
        let mut payload = BuilderData::new();
        payload.append_raw(initiate.hash(0).as_slice(), 256).unwrap();
        let complete = f.build_action(COMPLETE_RECOVERY, 2, 1, 0x65, payload.into_cell().unwrap());
        let result = f.send_value(
            f.registry.clone(),
            submit_body(complete.clone(), all_sign(&keys, &complete), empty_signatures()),
            MEASURE_VALUE,
        );
        (initiate_gas, gas_at(&result, &f.registry))
    };

    // Capability authorization by a `width` owner, and a transfer to a second
    // agent whose policy has `next_width` controllers.
    let mut f = Fixture::new();
    f.install_policy(wide_policy(&keys));
    let owner_id = f.object_id;
    let owner = f.registry.clone();
    let version = longest_version(0);
    let (result, capability) = f.register_capability_by(
        &owner_id,
        &owner,
        |action| all_sign(&keys, action),
        [0x66; 32],
        &version,
        [0x67; 32],
        MEASURE_VALUE,
    );
    let authorize_register_capability = gas_at(&result, &owner);
    if authorize_register_capability.exit == 0 {
        assert_address_success(&result, &capability.address);
    }

    let added = longest_version(1);
    let mut payload = BuilderData::new();
    payload
        .append_u256(&owner_id)
        .unwrap()
        .append_u256(&bytes_hash(&added))
        .unwrap()
        .append_u256(&[0x68; 32])
        .unwrap()
        .checked_append_reference(protocol_text(&added))
        .unwrap();
    let mut authorize_add_version = authorize_register_capability;
    let mut authorize_revoke_version = authorize_register_capability;
    let mut transfer_old_owner = authorize_register_capability;
    let mut transfer_new_owner = authorize_register_capability;
    if authorize_register_capability.exit == 0 {
        let add = f.build_capability_action(
            ADD_CAPABILITY_VERSION,
            &capability.id,
            &capability.address,
            1,
            2,
            0x69,
            payload.into_cell().unwrap(),
        );
        let result = f.send_value(
            owner.clone(),
            authorization_body(add.clone(), all_sign(&keys, &add), empty_signatures()),
            MEASURE_VALUE,
        );
        authorize_add_version = gas_at(&result, &owner);
        assert_address_success(&result, &capability.address);

        let mut payload = BuilderData::new();
        payload
            .append_u256(&owner_id)
            .unwrap()
            .append_bit_one()
            .unwrap()
            .append_u256(&bytes_hash(&added))
            .unwrap()
            .checked_append_reference(protocol_text(&added))
            .unwrap();
        let revoke = f.build_capability_action(
            REVOKE_CAPABILITY,
            &capability.id,
            &capability.address,
            1,
            3,
            0x6a,
            payload.into_cell().unwrap(),
        );
        let result = f.send_value(
            owner.clone(),
            authorization_body(revoke.clone(), all_sign(&keys, &revoke), empty_signatures()),
            MEASURE_VALUE,
        );
        authorize_revoke_version = gas_at(&result, &owner);
        assert_address_success(&result, &capability.address);

        let placeholder = RegistryKey::from_bytes(&[0x6b; 32]);
        let (new_owner_id, new_owner) = f.deploy_agent(&placeholder, [0x6c; 32]);
        f.install_policy_at(&new_owner, &new_owner_id, wide_policy(&next_keys));
        let mut payload = BuilderData::new();
        payload.append_u256(&owner_id).unwrap().append_u256(&new_owner_id).unwrap();
        let transfer = f.build_capability_action(
            TRANSFER_CAPABILITY,
            &capability.id,
            &capability.address,
            2,
            1,
            0x6d,
            payload.into_cell().unwrap(),
        );
        let result = f.send_value(
            owner.clone(),
            authorization_body(
                transfer.clone(),
                all_sign(&keys, &transfer),
                all_sign(&next_keys, &transfer),
            ),
            MEASURE_VALUE,
        );
        transfer_old_owner = gas_at(&result, &owner);
        transfer_new_owner = gas_at(&result, &new_owner);
        if transfer_new_owner.exit == 0 {
            assert_address_success(&result, &capability.address);
            assert_eq!(capability_owner(&f.state_at(&capability.address)), new_owner_id);
        }
    }

    PathGas {
        register,
        delegate,
        revoke_agent,
        update,
        initiate_recovery,
        complete_recovery,
        authorize_register_capability,
        authorize_add_version,
        authorize_revoke_version,
        transfer_old_owner,
        transfer_new_owner,
    }
}

/// Every policy-walking path succeeds at the supported width, from and to a
/// maximum-width policy, within the registry's gas ceiling. A
/// cost increase that erodes the headroom fails here before it can strand a
/// supported policy.
#[test]
fn every_policy_path_fits_the_gas_ceiling_at_the_supported_width() {
    let gas = measure_paths(MAX_WIDTH, MAX_WIDTH);
    for (path, gas) in gas.rows() {
        eprintln!("width {MAX_WIDTH}: {path}: gas {} of {}", gas.used, gas.limit);
        assert_eq!(gas.limit, NATIVE_REGISTRY_TRANSACTION_GAS_LIMIT, "{path}: gas limit");
        assert!(!gas.aborted && gas.exit == 0, "{path} must succeed at width {MAX_WIDTH}: {gas:?}");
        assert!(
            gas.used <= NATIVE_REGISTRY_GAS_CEILING,
            "{path}: {} gas exceeds the ceiling of {NATIVE_REGISTRY_GAS_CEILING}",
            gas.used
        );
    }
}

/// Largest external message a validator accepts (genesis ConfigParam 43,
/// `max_ext_msg_size`).
const MAX_EXTERNAL_MESSAGE_BYTES: usize = 65_535;

/// The relayer route's external message around `internal`: an `ext_in`
/// header to the relayer wallet and a wallet v3r2 request -- placeholder
/// signature, the TOS `global_id`, subwallet, expiry, seqno and send mode --
/// carrying the internal message to the registry. The wallet's signature
/// authorizes only the transport; the registry's authority is the ML-DSA-44
/// signature sets inside the body.
fn relayer_external_bytes(internal: &chain_block::Message) -> usize {
    use chain_block::{ExternalInboundMessageHeader, Message, MsgAddressExt, UInt256};
    let mut wallet_body = BuilderData::new();
    wallet_body
        .append_raw(&[0x5e; 64], 512)
        .unwrap()
        .append_i32(2)
        .unwrap()
        .append_u32(698_983_191)
        .unwrap()
        .append_u32(1_800_000_000)
        .unwrap()
        .append_u32(7)
        .unwrap()
        .append_u8(3)
        .unwrap()
        .checked_append_reference(internal.serialize().unwrap())
        .unwrap();
    let header = ExternalInboundMessageHeader {
        src: MsgAddressExt::AddrNone,
        dst: MsgAddressInt::with_params(0, UInt256::from([0x77; 32])).unwrap(),
        import_fee: Default::default(),
    };
    let message = Message::with_ext_in_header_and_body(
        header,
        SliceData::load_cell(wallet_body.into_cell().unwrap()).unwrap(),
    );
    chain_block::write_boc(&message.serialize().unwrap()).unwrap().len()
}

/// Every path's relayer message at the supported width fits one external
/// message: registration (it carries the code and account data), and the
/// paths that carry two maximum-width signature sets -- a disjoint policy
/// update, a recovery initiation, and the transfer leg that carries both
/// owners' sets. This bounds the route's envelope as built here; the gate on
/// the exact bytes the relayer wallet broadcasts is run against a test
/// network.
#[test]
fn every_widest_relayer_message_fits_one_external_message() {
    let keys = width_keys(MAX_WIDTH, 1);
    let next_keys = width_keys(MAX_WIDTH, 2);
    let mut f = Fixture::new();
    f.install_policy(wide_policy(&keys));
    let to_registry = |f: &Fixture, destination: &MsgAddressInt, body: Cell| {
        MessageBuilder::internal(f.relayer.address(), destination, MEASURE_VALUE).body(body).build()
    };

    let (registration, _) =
        f.registration_message(wide_policy(&keys), [0x60; 32], |action| all_sign(&keys, action));

    let mut payload = BuilderData::new();
    payload.checked_append_reference(wide_policy(&next_keys)).unwrap();
    let update = f.build_action(UPDATE_AGENT_POLICY, 1, 2, 0x63, payload.into_cell().unwrap());
    let update = to_registry(
        &f,
        &f.registry,
        submit_body(update.clone(), all_sign(&keys, &update), all_sign(&next_keys, &update)),
    );

    let mut payload = BuilderData::new();
    payload
        .append_u64(u64::from(f.bc.now()) + 10)
        .unwrap()
        .checked_append_reference(wide_policy(&next_keys))
        .unwrap();
    let initiate = f.build_action(INITIATE_RECOVERY, 1, 2, 0x64, payload.into_cell().unwrap());
    let initiate = to_registry(
        &f,
        &f.registry,
        submit_body(initiate.clone(), all_sign(&keys, &initiate), all_sign(&next_keys, &initiate)),
    );

    let mut payload = BuilderData::new();
    payload.append_u256(&f.object_id).unwrap().append_u256(&[0x6c; 32]).unwrap();
    let (capability, _) = f.object_address(2, &[0x66; 32]);
    let transfer = f.build_capability_action(
        TRANSFER_CAPABILITY,
        &[0x66; 32],
        &capability,
        1,
        1,
        0x6d,
        payload.into_cell().unwrap(),
    );
    let transfer = to_registry(
        &f,
        &f.registry,
        authorization_body(
            transfer.clone(),
            all_sign(&keys, &transfer),
            all_sign(&next_keys, &transfer),
        ),
    );

    for (path, message) in [
        ("register_agent", registration),
        ("update_agent_policy", update),
        ("initiate_recovery", initiate),
        ("transfer_capability", transfer),
    ] {
        let bytes = relayer_external_bytes(&message);
        eprintln!(
            "width {MAX_WIDTH}: {path}: external message {bytes} B of {MAX_EXTERNAL_MESSAGE_BYTES}"
        );
        assert!(bytes <= MAX_EXTERNAL_MESSAGE_BYTES, "{path}: {bytes} B exceeds max_ext_msg_size");
    }
}

/// The capacity table behind the supported width. Run with
/// `--ignored --nocapture`.
#[test]
#[ignore = "measurement sweep; prints the gas table"]
fn policy_width_gas_table() {
    let mut cases: Vec<(usize, usize)> = [1, 2, 4, 6, 8, 9].iter().map(|w| (*w, *w)).collect();
    cases.extend([(MAX_WIDTH, 1), (1, MAX_WIDTH)]);
    for (width, next_width) in cases {
        let gas = measure_paths(width, next_width);
        for (path, gas) in gas.rows() {
            println!(
                "{width:>2} -> {next_width:>2} | {path:<34} | {:>9} | exit {:>4}",
                gas.used, gas.exit
            );
        }
    }
}

// One controller more than the supported width is refused with its own exit
// code wherever a policy enters storage -- registration, policy update and
// recovery initiation. Each admission point has its own test so that each
// one's guard is shown to be what refuses it. A stored policy is never
// re-validated: only an admitted policy is ever stored, so the bound on what
// a stored policy can authorize is the signature-list bound.

fn too_wide_keys() -> Vec<RegistryKey> {
    width_keys(MAX_WIDTH + 1, 4)
}

/// Registration admits the supported width and refuses one controller more.
#[test]
fn registration_refuses_a_policy_wider_than_supported() {
    let keys = width_keys(MAX_WIDTH, 3);
    let wide_keys = too_wide_keys();
    let mut f = Fixture::new();

    let (result, address) =
        f.register_with(wide_policy(&keys), [0x70; 32], |action| all_sign(&keys, action));
    result.expect_success();
    assert!(f.registered(&address), "a {MAX_WIDTH}-controller policy must register");

    let (result, address) =
        f.register_with(wide_policy(&wide_keys), [0x71; 32], |action| all_sign(&wide_keys, action));
    let gas = gas_at(&result, &address);
    assert!(gas.aborted && gas.exit == ERR_POLICY_TOO_WIDE, "registration: {gas:?}");
    assert!(!f.registered(&address), "a too-wide policy must not register");
}

/// A policy update to one controller more than supported is refused, while
/// the same update to the supported width is installed.
#[test]
fn policy_update_refuses_a_policy_wider_than_supported() {
    let update_to = |f: &mut Fixture, keys: &[RegistryKey]| {
        let mut payload = BuilderData::new();
        payload.checked_append_reference(wide_policy(keys)).unwrap();
        let update = f.build_action(UPDATE_AGENT_POLICY, 1, 2, 0x72, payload.into_cell().unwrap());
        f.send_value(
            f.registry.clone(),
            submit_body(
                update.clone(),
                signature_set(&f.old_key, &update),
                all_sign(keys, &update),
            ),
            MEASURE_VALUE,
        )
    };
    let mut f = Fixture::new();
    let before = f.state().hash(0);
    update_to(&mut f, &too_wide_keys()).expect_aborted().expect_exit_code(ERR_POLICY_TOO_WIDE);
    assert_eq!(f.state().hash(0), before, "a too-wide policy must not be installed");
    update_to(&mut f, &width_keys(MAX_WIDTH, 3)).expect_success();
    assert_eq!(f.state_position(), (1, 2));
}

/// Recovery toward one controller more than supported is refused at
/// initiation, while recovery toward the supported width is accepted.
#[test]
fn recovery_initiation_refuses_a_policy_wider_than_supported() {
    let initiate_to = |f: &mut Fixture, keys: &[RegistryKey]| {
        let execute_after = u64::from(f.bc.now()) + 10;
        let mut payload = BuilderData::new();
        payload
            .append_u64(execute_after)
            .unwrap()
            .checked_append_reference(wide_policy(keys))
            .unwrap();
        let initiate = f.build_action(INITIATE_RECOVERY, 1, 2, 0x73, payload.into_cell().unwrap());
        f.send_value(
            f.registry.clone(),
            submit_body(
                initiate.clone(),
                signature_set(&f.old_key, &initiate),
                all_sign(keys, &initiate),
            ),
            MEASURE_VALUE,
        )
    };
    let mut f = Fixture::new();
    let before = f.state().hash(0);
    initiate_to(&mut f, &too_wide_keys()).expect_aborted().expect_exit_code(ERR_POLICY_TOO_WIDE);
    assert_eq!(f.state().hash(0), before, "a too-wide recovery policy must not be stored");
    initiate_to(&mut f, &width_keys(MAX_WIDTH, 3)).expect_success();
    assert_eq!(f.state_position(), (1, 2));
}

/// A stored policy wider than supported, which only a hand-built state could
/// carry, is not re-validated; a threshold that needs every one of its
/// controllers still cannot be met, because a signature list longer than the
/// supported width is refused first.
#[test]
fn a_stored_policy_wider_than_supported_cannot_be_met_by_all_its_controllers() {
    let wide_keys = too_wide_keys();
    let mut f = Fixture::new();
    f.install_policy(wide_policy(&wide_keys));
    let before = f.state().hash(0);
    let delegate = f.delegate_action(2, 0x74);
    f.send_value(
        f.registry.clone(),
        submit_body(delegate.clone(), all_sign(&wide_keys, &delegate), empty_signatures()),
        MEASURE_VALUE,
    )
    .expect_aborted()
    .expect_exit_code(ERR_THRESHOLD);
    assert_eq!(f.state().hash(0), before);
}

/// A signature list longer than the supported width is refused before any
/// entry is looked up, rather than after walking the policy for each one.
#[test]
fn a_signature_list_longer_than_the_supported_width_is_refused_unread() {
    let keys = width_keys(MAX_WIDTH, 5);
    let extra = width_keys(MAX_WIDTH + 1, 6).pop().unwrap();
    let mut f = Fixture::new();
    f.install_policy(wide_policy(&keys));
    let before = f.state().hash(0);
    let delegate = f.delegate_action(2, 0x75);
    let mut signers: Vec<RegistryKey> = keys.clone();
    signers.push(extra);
    f.send_value(
        f.registry.clone(),
        submit_body(delegate.clone(), all_sign(&signers, &delegate), empty_signatures()),
        MEASURE_VALUE,
    )
    .expect_aborted()
    .expect_exit_code(ERR_THRESHOLD);
    assert_eq!(f.state().hash(0), before);

    // Positive control: the same policy's own signers authorize the action.
    f.send_value(
        f.registry.clone(),
        submit_body(delegate.clone(), all_sign(&keys, &delegate), empty_signatures()),
        MEASURE_VALUE,
    )
    .expect_success();
    assert_eq!(f.state_position(), (1, 2));
}

/// The client builder encodes a policy exactly as the contract reads it, and
/// refuses one controller more than the contract admits.
#[test]
fn the_client_builder_matches_the_contract_and_refuses_the_same_width() {
    let to_policy = |keys: &[RegistryKey]| NativePolicy {
        threshold: keys.len() as u32,
        recovery_threshold: keys.len() as u32,
        recovery_timelock: 10,
        controllers: keys
            .iter()
            .map(|key| NativePolicyController {
                public_key: key.public_key().to_vec(),
                weight: 1,
                purposes: ALL_PURPOSES,
            })
            .collect(),
    };
    let keys = width_keys(MAX_WIDTH, 7);
    let built = build_policy(&to_policy(&keys)).expect("a supported policy builds");
    assert_eq!(built.hash(0), wide_policy(&keys).hash(0));

    let mut f = Fixture::new();
    let (result, address) = f.register_with(built, [0x76; 32], |action| all_sign(&keys, action));
    result.expect_success();
    assert!(f.registered(&address));

    let error = build_policy(&to_policy(&width_keys(MAX_WIDTH + 1, 7)))
        .expect_err("one controller more is refused")
        .to_string();
    assert!(error.contains(&format!("at most {MAX_WIDTH}")), "unexpected error: {error}");
}

// ---------------------------------------------------------------------------
// Registration of purpose-isolated policies, and canonical protocol text.
// ---------------------------------------------------------------------------

/// Every controller of the initial policy proves possession; consent is the
/// agent-control weight among them. A policy that isolates purposes (one key
/// each for agent control, delegation and capability control) therefore
/// registers, within the gas ceiling, and so does the same set of keys when
/// every one of them carries agent control.
#[test]
fn registration_accepts_a_purpose_isolated_policy_every_key_signed() {
    let mut f = Fixture::new();
    let (isolated, keys) = purpose_isolated_policy();
    let (result, address) = f.register_with(isolated, [0x7a; 32], |action| all_sign(&keys, action));
    let gas = gas_at(&result, &address);
    assert!(!gas.aborted && gas.exit == 0, "a purpose-isolated policy did not register: {gas:?}");
    assert!(f.registered(&address), "the purpose-isolated agent must be registered");
    assert!(
        gas.used <= NATIVE_REGISTRY_GAS_CEILING,
        "registration gas {} above the ceiling",
        gas.used
    );

    let (all_agent_control, control_keys) = three_controller_policy([0x05, 0x03, 0x09]);
    let (result, address) =
        f.register_with(all_agent_control, [0x7b; 32], |action| all_sign(&control_keys, action));
    let gas = gas_at(&result, &address);
    assert!(!gas.aborted && gas.exit == 0, "the control policy did not register: {gas:?}");
    assert!(f.registered(&address), "the control agent must be registered");
}

/// Possession still has to be complete: the isolated policy with one
/// controller's signature missing is refused, so consent without possession
/// is not a way in.
#[test]
fn registration_of_a_purpose_isolated_policy_still_needs_every_key() {
    let mut f = Fixture::new();
    let (isolated, keys) = purpose_isolated_policy();
    let (result, address) =
        f.register_with(isolated, [0x7c; 32], |action| all_sign(&keys[..2], action));
    let gas = gas_at(&result, &address);
    assert!(gas.aborted && gas.exit == ERR_BAD_SIGNATURE, "registration: {gas:?}");
    assert!(!f.registered(&address));
}

/// Protocol text is one cell tree per text: a full 127-byte cell followed by
/// an empty one is refused, while the same text in one cell is accepted.
#[test]
fn protocol_text_with_an_empty_tail_cell_is_refused() {
    let mut f = Fixture::new();
    let owner_id = f.object_id;
    let owner_address = f.registry.clone();
    let owner_key = RegistryKey::from_bytes(&f.old_key.to_bytes());
    let capability = f.register_capability(
        &owner_id,
        &owner_address,
        &owner_key,
        [0xe3; 32],
        b"1.0.0",
        [0xe4; 32],
    );
    let text = [b'a'; 127];
    let version_hash = bytes_hash(&text);

    let add_version = |f: &mut Fixture, version_name: Cell, sequence: u64, nonce: u8| {
        let mut payload = BuilderData::new();
        payload
            .append_u256(&owner_id)
            .unwrap()
            .append_u256(&version_hash)
            .unwrap()
            .append_u256(&[0xe5; 32])
            .unwrap()
            .checked_append_reference(version_name)
            .unwrap();
        let add = f.build_capability_action(
            ADD_CAPABILITY_VERSION,
            &capability.id,
            &capability.address,
            1,
            sequence,
            nonce,
            payload.into_cell().unwrap(),
        );
        f.send_to(
            owner_address.clone(),
            authorization_body(add.clone(), signature_set(&owner_key, &add), empty_signatures()),
        )
    };

    // The same bytes, with an empty tail cell appended.
    let mut padded = BuilderData::new();
    padded.append_raw(&text, text.len() * 8).unwrap();
    padded.checked_append_reference(Cell::default()).unwrap();
    let result = add_version(&mut f, padded.into_cell().unwrap(), 2, 50);
    let gas = gas_at(&result, &capability.address);
    assert!(gas.aborted && gas.exit == ERR_BAD_ACTION, "an empty tail cell was accepted: {gas:?}");
    assert_eq!(capability_position(&f.state_at(&capability.address)), (1, 1));

    // The canonical single cell is accepted.
    let result = add_version(&mut f, protocol_text(&text), 2, 51);
    let gas = gas_at(&result, &capability.address);
    assert!(!gas.aborted && gas.exit == 0, "the canonical text was refused: {gas:?}");
    assert_eq!(capability_position(&f.state_at(&capability.address)), (1, 2));
}

// ---------------------------------------------------------------------------
// ML-DSA-44 controllers: adversarial cases.
//
// Each refusal leaves the agent's state exactly as it was. Where a check is the
// contract's own, the exit code is the registry's; where the material reaches
// PQCHECKSIG_MLDSA44 malformed, the instruction itself refuses it (exit 9), and
// a cell that is not ordinary is refused by the codec's parse (exit 63) before
// anything is read from it.
// ---------------------------------------------------------------------------

const ERR_WRONG_CONTRACT: i32 = 2202;
const ERR_DUPLICATE_SIGNATURE: i32 = 2213;
const EXIT_CELL_UNDERFLOW: i32 = 9;
const EXIT_NOT_ORDINARY: i32 = 63;

/// The same cell, presented as a reference into the library collection.
fn library_reference(root: &Cell) -> Cell {
    let mut data = vec![0x80u8; 34];
    data[0] = u8::from(chain_block::CellType::LibraryReference);
    data[1..33].copy_from_slice(root.repr_hash().as_slice());
    Cell::with_cell_impl(
        chain_block::DataCell::with_params(
            vec![],
            &data,
            chain_block::CellType::LibraryReference,
            0,
            None,
        )
        .expect("a library reference"),
    )
}

/// [`byte_chain`] with the cell at `index` (and so everything after it)
/// replaced by a library reference to it.
fn chain_with_library_at(bytes: &[u8], index: usize) -> Cell {
    let chunks: Vec<&[u8]> = bytes.chunks(CHUNK_BYTES).collect();
    let mut next: Option<Cell> = None;
    for (position, chunk) in chunks.iter().enumerate().rev() {
        let mut cell = BuilderData::new();
        cell.append_raw(chunk, chunk.len() * 8).unwrap();
        if let Some(link) = next {
            cell.checked_append_reference(link).unwrap();
        }
        let cell = cell.into_cell().unwrap();
        next = Some(if position == index { library_reference(&cell) } else { cell });
    }
    next.unwrap()
}

/// A chain carrying `bytes` whose first cell holds `first` bytes instead of a
/// full 127: the same bytes in a non-canonical shape.
fn non_canonical_chain(bytes: &[u8], first: usize) -> Cell {
    let (head, tail) = bytes.split_at(first);
    let mut cell = BuilderData::new();
    cell.append_raw(head, head.len() * 8)
        .unwrap()
        .checked_append_reference(byte_chain(tail))
        .unwrap();
    cell.into_cell().unwrap()
}

/// A stored wrapper with one data bit, or one reference, after the chain.
fn wrapper_with_trailing(bytes: &[u8], extra_reference: bool) -> Cell {
    let mut wrapper = BuilderData::new();
    wrapper
        .append_u32(bytes.len() as u32)
        .unwrap()
        .checked_append_reference(byte_chain(bytes))
        .unwrap();
    if extra_reference {
        wrapper.checked_append_reference(Cell::default()).unwrap();
    } else {
        wrapper.append_bit_one().unwrap();
    }
    wrapper.into_cell().unwrap()
}

/// The exit code `result` aborted with on `address`, asserting that it did.
fn refusal(result: &SendResult, address: &MsgAddressInt) -> i32 {
    let gas = gas_at(result, address);
    assert!(gas.aborted, "expected a refusal, got {gas:?}");
    gas.exit
}

impl Fixture {
    /// A policy update to `next` authorized by the fixture's key, with the
    /// possession set `possession` builds over the action.
    fn update_to(
        &mut self,
        next: Cell,
        nonce: u8,
        possession: impl Fn(&Cell) -> Cell,
    ) -> SendResult {
        let mut payload = BuilderData::new();
        payload.checked_append_reference(next).unwrap();
        let update =
            self.build_action(UPDATE_AGENT_POLICY, 1, 2, nonce, payload.into_cell().unwrap());
        let authority = signature_set(&self.old_key, &update);
        let counterparty = possession(&update);
        self.send_value(
            self.registry.clone(),
            submit_body(update, authority, counterparty),
            MEASURE_VALUE,
        )
    }

    /// A delegation authorized by the signature set `authority` builds.
    fn delegate_by(&mut self, nonce: u8, authority: impl Fn(&Cell) -> Cell) -> SendResult {
        let delegate = self.delegate_action(2, nonce);
        let signatures = authority(&delegate);
        self.send_value(
            self.registry.clone(),
            submit_body(delegate, signatures, empty_signatures()),
            MEASURE_VALUE,
        )
    }

    /// Asserts that `result` was refused with `code` and changed nothing.
    fn assert_refused(&self, result: &SendResult, code: i32, before: &Cell, case: &str) {
        assert_eq!(refusal(result, &self.registry), code, "{case}");
        assert_eq!(self.state().hash(0), before.hash(0), "{case} changed state");
    }
}

/// A signature by the right key over the right action, but under any context
/// other than the registry's -- none, a near miss, the consensus key-identity
/// domain or a consensus role -- does not authorize: one key may serve several
/// roles without a signature in one being usable in another.
#[test]
fn a_signature_under_another_context_is_refused() {
    let mut f = Fixture::new();
    let before = f.state();
    let contexts: [&[u8]; 4] =
        [b"", b"TOS-NATIVE-REGISTRY-v2", b"TOS-PQ-CONSENSUS-KEY-v1", b"TOS-CONSENSUS-VOTE"];
    for (i, context) in contexts.into_iter().enumerate() {
        let key = f.old_key.clone();
        let result = f.delegate_by(0x80 + i as u8, |action| {
            let signature = stored(&key.signature_bytes(action, context, &[0x5a; 32]));
            signature_entries(vec![(key.id(), signature)])
        });
        f.assert_refused(&result, ERR_BAD_SIGNATURE, &before, "foreign context");
    }
    let key = f.old_key.clone();
    f.delegate_by(0x84, |action| signature_set(&key, action)).expect_success();
    assert_eq!(f.state_position(), (1, 2));
}

/// A controller whose declared id is another key's -- a victim's -- is
/// refused even though the signature verifies against the key it carries:
/// the id is derived from the verified key and must equal the declared one.
#[test]
fn a_controller_id_that_does_not_match_its_key_is_refused() {
    let mut f = Fixture::new();
    let before = f.state();
    let attacker = RegistryKey::from_bytes(&[0x85; 32]);
    let victim = RegistryKey::from_bytes(&[0x86; 32]);
    let forged =
        policy_cells(1, 1, vec![(victim.id(), attacker.stored_key(), 1, ALL_PURPOSES, true)]);
    let result = f.update_to(forged, 0x85, |action| {
        signature_entries(vec![(victim.id(), attacker.sign(action))])
    });
    f.assert_refused(&result, ERR_BAD_POLICY, &before, "mismatched key id");

    let honest = policy(&attacker);
    f.update_to(honest, 0x86, |action| signature_set(&attacker, action)).expect_success();
    assert_eq!(f.state_position(), (1, 2));
}

/// Stored key wrappers of the wrong declared length, with trailing data, or
/// carrying a key in a non-canonical, short or long chain are refused at
/// admission.
#[test]
fn malformed_stored_keys_are_refused() {
    let mut f = Fixture::new();
    let before = f.state();
    let key = RegistryKey::from_bytes(&[0x87; 32]);
    let bytes = key.public_key().to_vec();
    let mut long = bytes.clone();
    long.push(0);
    let cases: Vec<(&str, Cell, i32)> = vec![
        ("declared one byte short", stored_with_length(1311, byte_chain(&bytes)), ERR_BAD_POLICY),
        ("declared as an Ed25519 key", stored_with_length(32, byte_chain(&bytes)), ERR_BAD_POLICY),
        ("short chain", stored_with_length(1312, byte_chain(&bytes[..1311])), EXIT_CELL_UNDERFLOW),
        ("long chain", stored_with_length(1312, byte_chain(&long)), EXIT_CELL_UNDERFLOW),
        (
            "non-canonical chain",
            stored_with_length(1312, non_canonical_chain(&bytes, 126)),
            EXIT_CELL_UNDERFLOW,
        ),
        ("trailing bit", wrapper_with_trailing(&bytes, false), EXIT_CELL_UNDERFLOW),
        ("trailing reference", wrapper_with_trailing(&bytes, true), EXIT_CELL_UNDERFLOW),
    ];
    for (i, (case, wrapper, code)) in cases.into_iter().enumerate() {
        let next = policy_cells(1, 1, vec![(key.id(), wrapper, 1, ALL_PURPOSES, true)]);
        let result = f.update_to(next, 0x90 + i as u8, |action| signature_set(&key, action));
        f.assert_refused(&result, code, &before, case);
    }
}

/// Stored signature wrappers of the wrong declared length, with trailing
/// data, or in a non-canonical, short or long chain do not authorize.
#[test]
fn malformed_stored_signatures_are_refused() {
    let mut f = Fixture::new();
    let before = f.state();
    let key = f.old_key.clone();
    let cases: [(&str, i32); 7] = [
        ("declared one byte short", ERR_BAD_SIGNATURE),
        ("declared as an Ed25519 signature", ERR_BAD_SIGNATURE),
        ("short chain", EXIT_CELL_UNDERFLOW),
        ("long chain", EXIT_CELL_UNDERFLOW),
        ("non-canonical chain", EXIT_CELL_UNDERFLOW),
        ("trailing bit", EXIT_CELL_UNDERFLOW),
        ("trailing reference", EXIT_CELL_UNDERFLOW),
    ];
    for (i, (case, code)) in cases.into_iter().enumerate() {
        let result = f.delegate_by(0xa0 + i as u8, |action| {
            let bytes = key.signature_bytes(action, SIGNATURE_CONTEXT, &[0x5a; 32]);
            assert_eq!(bytes.len(), ML_DSA_44_SIGNATURE_BYTES);
            let mut long = bytes.clone();
            long.push(0);
            let wrapper = match i {
                0 => stored_with_length(2419, byte_chain(&bytes)),
                1 => stored_with_length(64, byte_chain(&bytes)),
                2 => stored_with_length(2420, byte_chain(&bytes[..2419])),
                3 => stored_with_length(2420, byte_chain(&long)),
                4 => stored_with_length(2420, non_canonical_chain(&bytes, 126)),
                5 => wrapper_with_trailing(&bytes, false),
                _ => wrapper_with_trailing(&bytes, true),
            };
            signature_entries(vec![(key.id(), wrapper)])
        });
        f.assert_refused(&result, code, &before, case);
    }
}

/// A library reference in place of a controller cell, a stored key wrapper,
/// a key chain's first or a continuation cell, a signature wrapper or a
/// signature chain cell is refused: the registry reads material as itself,
/// never as a reference to it.
#[test]
fn library_cells_in_place_of_key_or_signature_cells_are_refused() {
    let mut f = Fixture::new();
    let before = f.state();
    let key = RegistryKey::from_bytes(&[0x88; 32]);
    let bytes = key.public_key().to_vec();

    let mut controller_as_library = None;
    let honest = policy(&key);
    {
        let mut root = SliceData::load_cell(honest.clone()).unwrap();
        let header = root.get_next_slice(32 + 16 + 32 + 32 + 64 + 8).unwrap();
        let controller = root.checked_drain_reference().unwrap();
        let mut rebuilt = BuilderData::new();
        rebuilt
            .append_builder(&header.as_builder().unwrap())
            .unwrap()
            .checked_append_reference(library_reference(&controller))
            .unwrap();
        controller_as_library.replace(rebuilt.into_cell().unwrap());
    }
    let key_cases: Vec<(&str, Cell, i32)> = vec![
        ("controller cell", controller_as_library.unwrap(), EXIT_NOT_ORDINARY),
        (
            "stored key wrapper",
            policy_cells(
                1,
                1,
                vec![(key.id(), library_reference(&key.stored_key()), 1, ALL_PURPOSES, true)],
            ),
            EXIT_NOT_ORDINARY,
        ),
        (
            "first key chain cell",
            policy_cells(
                1,
                1,
                vec![(
                    key.id(),
                    stored_with_length(1312, chain_with_library_at(&bytes, 0)),
                    1,
                    ALL_PURPOSES,
                    true,
                )],
            ),
            EXIT_CELL_UNDERFLOW,
        ),
        (
            "key continuation cell",
            policy_cells(
                1,
                1,
                vec![(
                    key.id(),
                    stored_with_length(1312, chain_with_library_at(&bytes, 5)),
                    1,
                    ALL_PURPOSES,
                    true,
                )],
            ),
            EXIT_CELL_UNDERFLOW,
        ),
    ];
    for (i, (case, next, code)) in key_cases.into_iter().enumerate() {
        let result = f.update_to(next, 0xb0 + i as u8, |action| signature_set(&key, action));
        f.assert_refused(&result, code, &before, case);
    }

    let signer = f.old_key.clone();
    let signature_cases: [(&str, i32); 3] = [
        ("signature wrapper", EXIT_NOT_ORDINARY),
        ("first signature chain cell", EXIT_CELL_UNDERFLOW),
        ("signature continuation cell", EXIT_CELL_UNDERFLOW),
    ];
    for (i, (case, code)) in signature_cases.into_iter().enumerate() {
        let result = f.delegate_by(0xb8 + i as u8, |action| {
            let bytes = signer.signature_bytes(action, SIGNATURE_CONTEXT, &[0x5a; 32]);
            let wrapper = match i {
                0 => library_reference(&stored(&bytes)),
                1 => stored_with_length(2420, chain_with_library_at(&bytes, 0)),
                _ => stored_with_length(2420, chain_with_library_at(&bytes, 9)),
            };
            signature_entries(vec![(signer.id(), wrapper)])
        });
        f.assert_refused(&result, code, &before, case);
    }
    f.update_to(honest, 0xbf, |action| signature_set(&key, action)).expect_success();
}

/// Signature entries must be strictly ascending by key id: a repeated or an
/// out-of-order entry is refused when authorizing, and a possession set out of
/// the policy's order is refused at admission.
#[test]
fn duplicate_and_out_of_order_signature_entries_are_refused() {
    let mut f = Fixture::new();
    let mut keys = vec![RegistryKey::from_bytes(&[0x89; 32]), RegistryKey::from_bytes(&[0x8a; 32])];
    keys.sort_by_key(RegistryKey::id);
    f.install_policy(wide_policy(&keys));
    let before = f.state();

    let (low, high) = (keys[0].clone(), keys[1].clone());
    let result = f.delegate_by(0xc0, |action| {
        signature_entries_in_order(vec![signed(&high, action), signed(&low, action)])
    });
    f.assert_refused(&result, ERR_DUPLICATE_SIGNATURE, &before, "out of order");
    let result = f.delegate_by(0xc1, |action| {
        signature_entries_in_order(vec![signed(&low, action), signed(&low, action)])
    });
    f.assert_refused(&result, ERR_DUPLICATE_SIGNATURE, &before, "repeated entry");

    let mut payload = BuilderData::new();
    let next = RegistryKey::from_bytes(&[0x8b; 32]);
    let mut next_keys = vec![next.clone(), RegistryKey::from_bytes(&[0x8c; 32])];
    next_keys.sort_by_key(RegistryKey::id);
    payload.checked_append_reference(wide_policy(&next_keys)).unwrap();
    let update = f.build_action(UPDATE_AGENT_POLICY, 1, 2, 0xc3, payload.into_cell().unwrap());
    let reversed = signature_entries_in_order(vec![
        signed(&next_keys[1], &update),
        signed(&next_keys[0], &update),
    ]);
    let result = f.send_value(
        f.registry.clone(),
        submit_body(update.clone(), all_sign(&keys, &update), reversed),
        MEASURE_VALUE,
    );
    f.assert_refused(&result, ERR_BAD_SIGNATURE, &before, "possession out of policy order");
    f.send_value(
        f.registry.clone(),
        submit_body(update.clone(), all_sign(&keys, &update), all_sign(&next_keys, &update)),
        MEASURE_VALUE,
    )
    .expect_success();
    assert_eq!(f.state_position(), (1, 2));
}

/// ML-DSA-44 signing is randomized: one action has many valid signature sets.
/// Whichever arrives first makes the one transition; a second, differently
/// signed copy of the same action changes nothing.
#[test]
fn two_valid_signature_sets_for_one_action_make_one_transition() {
    let mut f = Fixture::new();
    let next = RegistryKey::from_bytes(&[0x8d; 32]);
    let mut payload = BuilderData::new();
    payload.checked_append_reference(policy(&next)).unwrap();
    let update = f.build_action(UPDATE_AGENT_POLICY, 1, 2, 0xd0, payload.into_cell().unwrap());
    let signed_with = |key: &RegistryKey, randomness: [u8; 32]| {
        let signature = stored(&key.signature_bytes(&update, SIGNATURE_CONTEXT, &randomness));
        signature_entries(vec![(key.id(), signature)])
    };
    let first = submit_body(
        update.clone(),
        signed_with(&f.old_key, [0x01; 32]),
        signed_with(&next, [0x02; 32]),
    );
    let second = submit_body(
        update.clone(),
        signed_with(&f.old_key, [0x03; 32]),
        signed_with(&next, [0x04; 32]),
    );
    assert_ne!(first.hash(0), second.hash(0), "the two signature sets must differ");

    f.send(first).expect_success();
    let applied = f.state();
    assert_eq!(f.state_position(), (1, 2));
    // The action is already applied: the registry recognizes it by its hash
    // and accepts the copy as a replay, without a second transition. Being
    // refused instead -- by the predecessor check, say -- would make a
    // re-signed broadcast look like a failure of an operation that succeeded.
    let result = f.send(second);
    let gas = gas_at(&result, &f.registry);
    assert!(
        !gas.aborted && gas.exit == 0,
        "a re-signed copy was not accepted as a replay: {gas:?}"
    );
    assert_eq!(
        f.state().hash(0),
        applied.hash(0),
        "a re-signed copy made a second transition: {gas:?}"
    );
    assert_eq!(f.state_position(), (1, 2));
}

/// The previous Ed25519 layouts -- a controller of two 256-bit key fields and
/// no stored key, and a signature entry of a key and 512 signature bits -- are
/// refused, not read as something else.
#[test]
fn ed25519_shaped_policies_and_signature_entries_are_refused() {
    let mut f = Fixture::new();
    let before = f.state();
    let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[0x8e; 32]);
    let public_key = ed25519.verifying_key().to_bytes();

    let mut controller = BuilderData::new();
    controller
        .append_u256(&public_key)
        .unwrap()
        .append_u256(&public_key)
        .unwrap()
        .append_u32(1)
        .unwrap()
        .append_u16(ALL_PURPOSES)
        .unwrap()
        .append_bit_one()
        .unwrap();
    let mut root = BuilderData::new();
    root.append_u32(MAGIC_POLICY)
        .unwrap()
        .append_u16(1)
        .unwrap()
        .append_u32(1)
        .unwrap()
        .append_u32(1)
        .unwrap()
        .append_u64(10)
        .unwrap()
        .append_u8(1)
        .unwrap()
        .checked_append_reference(controller.into_cell().unwrap())
        .unwrap();
    let old_policy = root.into_cell().unwrap();
    let result = f.update_to(old_policy, 0xe0, |action| {
        use ed25519_dalek::Signer;
        let mut entry = BuilderData::new();
        entry
            .append_u256(&public_key)
            .unwrap()
            .append_raw(&ed25519.sign(action.hash(0).as_slice()).to_bytes(), 512)
            .unwrap();
        let mut set = BuilderData::new();
        set.append_u8(1).unwrap().checked_append_reference(entry.into_cell().unwrap()).unwrap();
        set.into_cell().unwrap()
    });
    let code = refusal(&result, &f.registry);
    assert!(code == ERR_BAD_POLICY || code == EXIT_CELL_UNDERFLOW, "Ed25519 policy: exit {code}");
    assert_eq!(f.state().hash(0), before.hash(0));

    let result = f.delegate_by(0xe1, |action| {
        use ed25519_dalek::Signer;
        let mut entry = BuilderData::new();
        entry
            .append_u256(&fixture_controller_id())
            .unwrap()
            .append_raw(&ed25519.sign(action.hash(0).as_slice()).to_bytes(), 512)
            .unwrap();
        let mut set = BuilderData::new();
        set.append_u8(1).unwrap().checked_append_reference(entry.into_cell().unwrap()).unwrap();
        set.into_cell().unwrap()
    });
    f.assert_refused(&result, EXIT_CELL_UNDERFLOW, &before, "Ed25519 signature entry");
}

/// The id of the fixture's own controller, so that an Ed25519-shaped entry
/// names a real member and is refused for its shape alone.
fn fixture_controller_id() -> [u8; 32] {
    RegistryKey::from_bytes(&[0x31; 32]).id()
}

/// Rebuilds the fixture's configuration with its runtime workchain set to
/// `workchain`.
fn config_in_workchain(config: &Cell, workchain: i32) -> Cell {
    let mut outer = SliceData::load_cell(config.clone()).unwrap();
    let roots = outer.get_next_slice(256 * 3).unwrap();
    let mut runtime = SliceData::load_cell(outer.checked_drain_reference().unwrap()).unwrap();
    runtime.move_by(32).unwrap();
    let code_hash = runtime.get_next_bytes(32).unwrap();
    let network_id = runtime.checked_drain_reference().unwrap();
    let code = runtime.checked_drain_reference().unwrap();
    let mut rebuilt = BuilderData::new();
    rebuilt
        .append_i32(workchain)
        .unwrap()
        .append_raw(&code_hash, 256)
        .unwrap()
        .checked_append_reference(network_id)
        .unwrap()
        .checked_append_reference(code)
        .unwrap();
    let mut next = BuilderData::new();
    next.append_builder(&roots.as_builder().unwrap())
        .unwrap()
        .checked_append_reference(rebuilt.into_cell().unwrap())
        .unwrap();
    next.into_cell().unwrap()
}

/// The registry admits workchain 0 only: a registry whose configuration
/// names the masterchain, or one deployed in the masterchain under a
/// workchain-0 configuration, registers nothing.
#[test]
fn a_registry_outside_workchain_zero_registers_nothing() {
    let mut f = Fixture::new();
    let key = RegistryKey::from_bytes(&[0x8f; 32]);
    for (i, (config_workchain, address_workchain)) in [(-1, -1), (0, -1)].into_iter().enumerate() {
        let agent_policy = policy(&key);
        let nonce = [0xf0 + i as u8; 32];
        let mut identity = BuilderData::new();
        identity
            .append_u32(MAGIC_IDENTITY)
            .unwrap()
            .append_u8(1)
            .unwrap()
            .append_u256(&nonce)
            .unwrap()
            .append_raw(agent_policy.hash(0).as_slice(), 256)
            .unwrap()
            .checked_append_reference(f.identity_domain.clone())
            .unwrap();
        let object_id = *identity.into_cell().unwrap().hash(0).as_slice();
        let config = config_in_workchain(&f.config, config_workchain);
        let mut data = BuilderData::new();
        data.append_u32(MAGIC_DATA)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u8(1)
            .unwrap()
            .append_u256(&object_id)
            .unwrap()
            .checked_append_reference(config)
            .unwrap()
            .append_bit_zero()
            .unwrap();
        let state_init =
            StateInit::with_code_and_data(f.contract_code.clone(), data.into_cell().unwrap());
        let address_hash = state_init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let address = MsgAddressInt::with_params(address_workchain, address_hash).unwrap();
        let mut payload = BuilderData::new();
        payload.append_u256(&nonce).unwrap().checked_append_reference(agent_policy).unwrap();
        let register = action(
            REGISTER_AGENT,
            1,
            1,
            1,
            &object_id,
            &[0; 32],
            nonce[0],
            &f.domain,
            payload.into_cell().unwrap(),
        );
        let deploy = MessageBuilder::internal(f.relayer.address(), &address, 20 * TOS)
            .bounce(false)
            .state_init(state_init)
            .body(submit_body(register.clone(), signature_set(&key, &register), empty_signatures()))
            .build();
        let result = f.bc.send_message(deploy).expect("registration outside workchain 0");
        assert_eq!(refusal(&result, &address), ERR_WRONG_CONTRACT, "config {config_workchain}");
        assert!(!f.registered(&address));
    }
}

#[path = "served/service_journey.rs"]
mod service_journey;

/// The public SC-01/SC-02 journeys driven only through the client builders in
/// `contracts::native_registry` (no hand-built cells), against the release code
/// and the frozen public identity domain: the testnet genesis anchors and the
/// label `tos:global-id:2`. Every action's generation, sequence and predecessor
/// come from `next_native_position` over the decoded on-chain state, and every
/// signer set passes the client's threshold/possession checks before it is sent,
/// except where a test deliberately sends what the client would refuse.
mod builder_driven {
    use super::{assert_address_exit, assert_address_success, current_network};
    use chain_block::{Cell, MsgAddressInt, SliceData, base64_decode};
    use contracts::native_registry::*;
    use tos_sandbox::{Blockchain, MessageBuilder, SendResult, Treasury};

    const TOS: u64 = 1_000_000_000;
    const LABEL: &[u8] = b"tos:global-id:2";
    // Public testnet genesis anchors (tos.network/testnet-global.config.json).
    const GENESIS_ROOT: &str = "/2BFnLilFwhUgpCvoW/U34DRZ3W/PBM5IUam0bVmLVc=";
    const GENESIS_FILE: &str = "OzdN9evRg2jUvw6zdHBHcdr42s2FF1YF87/Rx6kioDk=";
    // The registry admits workchain 0 only.
    const WORKCHAIN: i8 = 0;
    const ERR_WRONG_NETWORK: i32 = 2201;
    const ERR_BAD_PREDECESSOR: i32 = 2204;
    const ERR_TOMBSTONED: i32 = 2206;
    const ERR_BAD_SIGNATURE: i32 = 2208;
    const ERR_BAD_TRANSITION: i32 = 2210;
    const ERR_IMMUTABLE_VERSION: i32 = 2211;
    const ERR_TIMELOCK: i32 = 2212;

    fn anchor(value: &str) -> [u8; 32] {
        base64_decode(value).expect("anchor base64").try_into().expect("anchor width")
    }

    fn public_domain(code: &Cell) -> NativeRegistryDomain {
        NativeRegistryDomain::for_label(
            anchor(GENESIS_ROOT),
            anchor(GENESIS_FILE),
            LABEL,
            *code.repr_hash().as_array(),
        )
        .expect("public domain")
    }

    /// A deliberately public deterministic ML-DSA-44 test controller, held as
    /// its key-generation seed; never an operational key.
    #[derive(Clone)]
    struct SigningKey([u8; 32]);

    impl SigningKey {
        fn from_bytes(seed: &[u8; 32]) -> Self {
            Self(*seed)
        }

        fn public_key(&self) -> Vec<u8> {
            native_public_key_from_seed(&self.0)
        }

        fn key_id(&self) -> [u8; 32] {
            controller_key_id(&self.public_key()).expect("fixture key id")
        }
    }

    struct Agent {
        id: [u8; 32],
        address: MsgAddressInt,
        key: SigningKey,
    }

    struct Capability {
        id: [u8; 32],
        address: MsgAddressInt,
    }

    struct Net {
        bc: Blockchain,
        relayer: Treasury,
        domain: NativeRegistryDomain,
        code: Cell,
    }

    fn single_controller_policy(key: &SigningKey, timelock: u64) -> NativePolicy {
        NativePolicy {
            threshold: 1,
            recovery_threshold: 1,
            recovery_timelock: timelock,
            controllers: vec![NativePolicyController {
                public_key: key.public_key(),
                weight: 1,
                purposes: 15,
            }],
        }
    }

    fn signatures(keys: &[&SigningKey], action: &Cell) -> Vec<NativeControllerSignature> {
        keys.iter().map(|k| sign_native_action(&k.0, action).expect("fixture signature")).collect()
    }

    /// The key ids the client's threshold and possession checks take.
    fn public_keys(keys: &[&SigningKey]) -> Vec<[u8; 32]> {
        keys.iter().map(|k| k.key_id()).collect()
    }

    fn agent_policy(state: &NativeRegistryState) -> NativePolicy {
        let NativeRegistryStateDetail::Agent { policy, .. } = &state.detail else {
            panic!("expected an Agent state")
        };
        decode_native_policy(policy).expect("stored policy")
    }

    impl Net {
        fn new() -> Self {
            let mut bc = Blockchain::with_global_version_and_base_workchain(
                current_network::global_version(),
            )
            .expect("blockchain");
            bc.set_workchain(WORKCHAIN);
            bc.set_workchain_gas_limit(NATIVE_REGISTRY_TRANSACTION_GAS_LIMIT);
            let relayer =
                bc.treasury("native-registry-builder-relayer", 1_000 * TOS).expect("relayer");
            let code = native_registry_release_code().expect("release code");
            let domain = public_domain(&code);
            Self { bc, relayer, domain, code }
        }

        /// The decoded stored state at `address`, `None` before registration.
        /// Every read goes through the client's account verifier, as the CLI's
        /// pre-sign checks do.
        fn state(&self, address: &MsgAddressInt) -> Option<NativeRegistryState> {
            let account = self.bc.get_account(address)?;
            let (code, data) = (account.get_code()?, account.get_data()?);
            verify_native_registry_account(&self.domain, LABEL, &self.code, address, &code, &data)
                .expect("verified registry account")
                .state
        }

        fn object_address(&self, kind: u8, id: [u8; 32]) -> MsgAddressInt {
            build_native_registry_deployment(&self.domain, kind, id, WORKCHAIN, LABEL, &self.code)
                .expect("deployment")
                .1
        }

        fn action(
            &self,
            domain: &NativeRegistryDomain,
            kind: u8,
            object_id: [u8; 32],
            current: Option<&NativeRegistryState>,
            nonce: u8,
            payload: Cell,
        ) -> Cell {
            let (generation, sequence, predecessor) =
                next_native_position(current, kind).expect("position");
            build_native_action(
                domain,
                &NativeRegistryAction {
                    kind,
                    generation,
                    sequence,
                    object_id,
                    predecessor,
                    nonce: [nonce; 32],
                    payload,
                },
            )
            .expect("action")
        }

        fn register_agent(&mut self, seed: u8, timelock: u64) -> Agent {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let policy = single_controller_policy(&key, timelock);
            let registration =
                build_native_agent_registration(&self.domain, [seed; 32], &policy).expect("reg");
            let (init, address) = build_native_registry_deployment(
                &self.domain,
                1,
                registration.object_id,
                WORKCHAIN,
                LABEL,
                &self.code,
            )
            .expect("deployment");
            assert!(self.state(&address).is_none());
            let action = self.action(
                &self.domain,
                NATIVE_KIND_REGISTER_AGENT,
                registration.object_id,
                None,
                seed,
                registration.payload,
            );
            check_native_possession(&policy, &public_keys(&[&key])).expect("possession");
            let body = build_native_submission(
                &self.domain,
                &action,
                1,
                &signatures(&[&key], &action),
                &[],
            )
            .expect("body");
            let msg = MessageBuilder::internal(self.relayer.address(), &address, TOS)
                .bounce(false)
                .state_init(init)
                .body(body)
                .build();
            let result = self.bc.send_message(msg).expect("register");
            assert_address_success(&result, &address);
            let state = self.state(&address).expect("registered");
            assert_eq!((state.generation, state.sequence, state.tombstone), (1, 1, false));
            assert_eq!(state.last_action, *action.repr_hash().as_array());
            Agent { id: registration.object_id, address, key }
        }

        fn send(&mut self, to: &MsgAddressInt, body: Cell) -> SendResult {
            let msg =
                MessageBuilder::internal(self.relayer.address(), to, TOS / 2).body(body).build();
            self.bc.send_message(msg).expect("send")
        }

        /// An Agent action signed by `signers` (checked against the stored
        /// policy first) and, for counterparty kinds, `counter`.
        fn agent_action(
            &mut self,
            agent: &Agent,
            kind: u8,
            payload: Cell,
            signers: &[&SigningKey],
            counter: &[&SigningKey],
            nonce: u8,
        ) -> (SendResult, Cell) {
            let current = self.state(&agent.address).expect("agent state");
            check_native_threshold(&agent_policy(&current), &public_keys(signers), kind)
                .expect("signer threshold");
            let action = self.action(&self.domain, kind, agent.id, Some(&current), nonce, payload);
            let body = build_native_submission(
                &self.domain,
                &action,
                1,
                &signatures(signers, &action),
                &signatures(counter, &action),
            )
            .expect("body");
            (self.send(&agent.address, body), action)
        }

        /// A Capability action sent to `via` (its owner Agent, or the old owner
        /// for a transfer).
        fn capability_action(
            &mut self,
            via: &Agent,
            capability: &Capability,
            kind: u8,
            payload: Cell,
            signers: &[&SigningKey],
            counter: &[&SigningKey],
            nonce: u8,
        ) -> SendResult {
            let current = self.state(&capability.address);
            let action =
                self.action(&self.domain, kind, capability.id, current.as_ref(), nonce, payload);
            let body = build_native_submission(
                &self.domain,
                &action,
                1,
                &signatures(signers, &action),
                &signatures(counter, &action),
            )
            .expect("body");
            self.send(&via.address, body)
        }

        fn register_capability(&mut self, owner: &Agent, nonce: u8, version: &[u8]) -> Capability {
            let registration = build_native_capability_registration(
                &self.domain,
                [nonce; 32],
                owner.id,
                version,
                [0x5e; 32],
            )
            .expect("capability registration");
            let capability = Capability {
                id: registration.object_id,
                address: self.object_address(2, registration.object_id),
            };
            let key = owner.key.clone();
            let result = self.capability_action(
                owner,
                &capability,
                NATIVE_KIND_REGISTER_CAPABILITY,
                registration.payload,
                &[&key],
                &[],
                nonce,
            );
            assert_address_success(&result, &capability.address);
            capability
        }
    }

    fn capability_owner(state: &NativeRegistryState) -> [u8; 32] {
        let NativeRegistryStateDetail::Capability { owner, .. } = state.detail else {
            panic!("expected a Capability state")
        };
        owner
    }

    #[test]
    fn public_domain_reproduces_the_inventory_hash_and_binds_addresses() {
        let code = native_registry_release_code().expect("release code");
        let domain = public_domain(&code);
        assert_eq!(
            hex::encode(domain.network_tag),
            "867b460108f617ef4508e406addf30db563dbabf44f7e90e58cff93ddeacf4a9"
        );
        let key = SigningKey::from_bytes(&[0x61; 32]);
        let reg = build_native_agent_registration(
            &domain,
            [0x61; 32],
            &single_controller_policy(&key, 60),
        )
        .expect("registration");
        let (_, public) =
            build_native_registry_deployment(&domain, 1, reg.object_id, 0, LABEL, &code)
                .expect("public address");
        let local = NativeRegistryDomain::for_label(
            domain.genesis_root,
            domain.genesis_file,
            b"tos-e6-e7-isolated-native",
            domain.runtime_code_hash,
        )
        .expect("local domain");
        let local_reg = build_native_agent_registration(
            &local,
            [0x61; 32],
            &single_controller_policy(&key, 60),
        )
        .expect("local registration");
        let (_, other) = build_native_registry_deployment(
            &local,
            1,
            local_reg.object_id,
            0,
            b"tos-e6-e7-isolated-native",
            &code,
        )
        .expect("local address");
        assert_ne!(reg.object_id, local_reg.object_id, "the label binds the identity");
        assert_ne!(public, other, "the label binds the address");
    }

    #[test]
    fn account_verifier_refuses_another_domain_label_or_code() {
        let mut net = Net::new();
        let a = net.register_agent(0x67, 60);
        let account = net.bc.get_account(&a.address).expect("account");
        let (code, data) = (account.get_code().expect("code"), account.get_data().expect("data"));
        let object =
            verify_native_registry_account(&net.domain, LABEL, &net.code, &a.address, &code, &data)
                .expect("verified");
        assert_eq!((object.object_kind, object.object_id), (1, a.id));
        let other = NativeRegistryDomain::for_label(
            net.domain.genesis_root,
            net.domain.genesis_file,
            b"tos:global-id:1",
            net.domain.runtime_code_hash,
        )
        .expect("other domain");
        assert!(
            verify_native_registry_account(
                &other,
                b"tos:global-id:1",
                &net.code,
                &a.address,
                &code,
                &data
            )
            .is_err()
        );
        let mut moved = net.domain.clone();
        moved.genesis_file[0] ^= 1;
        assert!(
            verify_native_registry_account(&moved, LABEL, &net.code, &a.address, &code, &data)
                .is_err()
        );
        let foreign_code = chain_block::Cell::default();
        assert!(
            verify_native_registry_account(
                &net.domain,
                LABEL,
                &net.code,
                &a.address,
                &foreign_code,
                &data
            )
            .is_err()
        );
        let b = net.register_agent(0x68, 60);
        assert!(
            verify_native_registry_account(&net.domain, LABEL, &net.code, &b.address, &code, &data)
                .is_err(),
            "another object's data at this address is refused"
        );
    }

    #[test]
    fn agent_and_capability_lifecycle_through_the_builders() {
        let mut net = Net::new();
        let a = net.register_agent(0x61, 60);
        let b = net.register_agent(0x62, 60);
        let a_key = a.key.clone();
        let b_key = b.key.clone();

        // Delegation, then the identical action again: a silent no-op.
        let (result, delegate) = net.agent_action(
            &a,
            NATIVE_KIND_DELEGATE_AGENT,
            build_native_delegate_payload([0x71; 32]).expect("payload"),
            &[&a_key],
            &[],
            2,
        );
        assert_address_success(&result, &a.address);
        let after = net.state(&a.address).expect("state");
        assert_eq!((after.generation, after.sequence), (1, 2));
        let NativeRegistryStateDetail::Agent { delegations, delegation_root, .. } = &after.detail
        else {
            panic!("agent")
        };
        assert_eq!(*delegations, 1);
        assert!(native_dict_contains(delegation_root, &[0x71; 32]).expect("lookup"));
        let replay = build_native_submission(
            &net.domain,
            &delegate,
            1,
            &signatures(&[&a_key], &delegate),
            &[],
        )
        .expect("replay body");
        let result = net.send(&a.address, replay);
        assert_address_success(&result, &a.address);
        assert_eq!(net.state(&a.address).expect("state").state_hash, after.state_hash);

        // Capability under A, a second version, and a refused duplicate version.
        let cap = net.register_capability(&a, 0x81, b"1.0.0");
        let cs = net.state(&cap.address).expect("capability state");
        assert_eq!((cs.generation, cs.sequence, capability_owner(&cs)), (1, 1, a.id));
        let result = net.capability_action(
            &a,
            &cap,
            NATIVE_KIND_ADD_CAPABILITY_VERSION,
            build_native_add_version_payload(a.id, b"1.1.0", [0x5f; 32]).expect("payload"),
            &[&a_key],
            &[],
            0x82,
        );
        assert_address_success(&result, &cap.address);
        let result = net.capability_action(
            &a,
            &cap,
            NATIVE_KIND_ADD_CAPABILITY_VERSION,
            build_native_add_version_payload(a.id, b"1.1.0", [0x60; 32]).expect("payload"),
            &[&a_key],
            &[],
            0x83,
        );
        assert_address_exit(&result, &cap.address, ERR_IMMUTABLE_VERSION);
        let cs = net.state(&cap.address).expect("capability state");
        let NativeRegistryStateDetail::Capability { versions, version_root, .. } = &cs.detail
        else {
            panic!("capability")
        };
        assert_eq!(*versions, 2);
        use sha2::{Digest, Sha256};
        let v11: [u8; 32] = Sha256::digest(b"1.1.0").into();
        assert!(native_dict_contains(version_root, &v11).expect("lookup"));

        // Transfer A -> B: the client refuses it without B's consent; with it,
        // the Capability moves to the next generation under B.
        let transfer_action = net.action(
            &net.domain,
            NATIVE_KIND_TRANSFER_CAPABILITY,
            cap.id,
            Some(&cs),
            0x84,
            build_native_transfer_payload(a.id, b.id).expect("payload"),
        );
        assert!(
            build_native_submission(
                &net.domain,
                &transfer_action,
                1,
                &signatures(&[&a_key], &transfer_action),
                &[],
            )
            .is_err()
        );
        let result = net.capability_action(
            &a,
            &cap,
            NATIVE_KIND_TRANSFER_CAPABILITY,
            build_native_transfer_payload(a.id, b.id).expect("payload"),
            &[&a_key],
            &[&b_key],
            0x84,
        );
        assert_address_success(&result, &b.address);
        assert_address_success(&result, &cap.address);
        let cs = net.state(&cap.address).expect("capability state");
        assert_eq!((cs.generation, cs.sequence, capability_owner(&cs)), (2, 1, b.id));

        // Stale authority: the previous owner can no longer add a version.
        let result = net.capability_action(
            &a,
            &cap,
            NATIVE_KIND_ADD_CAPABILITY_VERSION,
            build_native_add_version_payload(a.id, b"2.0.0", [0x61; 32]).expect("payload"),
            &[&a_key],
            &[],
            0x85,
        );
        assert_address_exit(&result, &cap.address, ERR_BAD_TRANSITION);
        assert_eq!(net.state(&cap.address).expect("state").state_hash, cs.state_hash);

        // Revoke one version, then the whole Capability; nothing applies after.
        let result = net.capability_action(
            &b,
            &cap,
            NATIVE_KIND_REVOKE_CAPABILITY,
            build_native_revoke_capability_payload(b.id, Some(b"1.0.0")).expect("payload"),
            &[&b_key],
            &[],
            0x86,
        );
        assert_address_success(&result, &cap.address);
        let after_version = net.state(&cap.address).expect("state");
        assert!(!after_version.tombstone);
        let NativeRegistryStateDetail::Capability { versions, version_root, .. } =
            &after_version.detail
        else {
            panic!("capability")
        };
        assert_eq!(*versions, 2, "revoking a version keeps it in the collection");
        let v10: [u8; 32] = Sha256::digest(b"1.0.0").into();
        let revoked_version =
            native_capability_version(version_root, &v10).expect("decode").expect("present");
        assert!(revoked_version.revoked);
        assert_eq!(revoked_version.manifest_digest, [0x5e; 32], "manifest unchanged");
        let mut name = SliceData::load_cell(revoked_version.name).expect("name");
        assert_eq!(name.get_next_bytes(5).expect("name bytes"), b"1.0.0".to_vec());
        let other =
            native_capability_version(version_root, &v11).expect("decode").expect("present");
        assert!(!other.revoked, "the other version is unaffected");
        assert_eq!(other.manifest_digest, [0x5f; 32]);
        let result = net.capability_action(
            &b,
            &cap,
            NATIVE_KIND_REVOKE_CAPABILITY,
            build_native_revoke_capability_payload(b.id, None).expect("payload"),
            &[&b_key],
            &[],
            0x87,
        );
        assert_address_success(&result, &cap.address);
        let revoked = net.state(&cap.address).expect("state");
        assert!(revoked.tombstone);
        assert!(next_native_position(Some(&revoked), NATIVE_KIND_ADD_CAPABILITY_VERSION).is_err());
        let late = net.action(
            &net.domain,
            NATIVE_KIND_ADD_CAPABILITY_VERSION,
            cap.id,
            Some(&cs),
            0x88,
            build_native_add_version_payload(b.id, b"3.0.0", [0x62; 32]).expect("payload"),
        );
        let late =
            build_native_submission(&net.domain, &late, 1, &signatures(&[&b_key], &late), &[])
                .expect("late body");
        let result = net.send(&b.address, late);
        assert_address_exit(&result, &cap.address, ERR_TOMBSTONED);

        // Agent revocation is terminal.
        let (result, _) = net.agent_action(
            &a,
            NATIVE_KIND_REVOKE_AGENT,
            build_native_revoke_agent_payload().expect("payload"),
            &[&a_key],
            &[],
            3,
        );
        assert_address_success(&result, &a.address);
        let dead = net.state(&a.address).expect("state");
        assert!(dead.tombstone);
        let late = net.action(
            &net.domain,
            NATIVE_KIND_DELEGATE_AGENT,
            a.id,
            Some(&after),
            4,
            build_native_delegate_payload([0x72; 32]).expect("payload"),
        );
        let late =
            build_native_submission(&net.domain, &late, 1, &signatures(&[&a_key], &late), &[])
                .expect("late body");
        let result = net.send(&a.address, late);
        assert_address_exit(&result, &a.address, ERR_TOMBSTONED);
    }

    #[test]
    fn refusals_wrong_network_controller_and_predecessor_leave_state_unchanged() {
        let mut net = Net::new();
        let a = net.register_agent(0x63, 60);
        let a_key = a.key.clone();
        let before = net.state(&a.address).expect("state");

        // Wrong network: a consistent action for another label.
        let other = NativeRegistryDomain::for_label(
            net.domain.genesis_root,
            net.domain.genesis_file,
            b"tos:global-id:1",
            net.domain.runtime_code_hash,
        )
        .expect("other domain");
        let action = net.action(
            &other,
            NATIVE_KIND_DELEGATE_AGENT,
            a.id,
            Some(&before),
            2,
            build_native_delegate_payload([0x73; 32]).expect("payload"),
        );
        let body =
            build_native_submission(&other, &action, 1, &signatures(&[&a_key], &action), &[])
                .expect("body");
        assert!(
            build_native_submission(&net.domain, &action, 1, &signatures(&[&a_key], &action), &[])
                .is_err()
        );
        let result = net.send(&a.address, body);
        assert_address_exit(&result, &a.address, ERR_WRONG_NETWORK);

        // Wrong controller: refused by the client check, and by the contract.
        let stranger = SigningKey::from_bytes(&[0x99; 32]);
        assert!(
            check_native_threshold(
                &agent_policy(&before),
                &public_keys(&[&stranger]),
                NATIVE_KIND_DELEGATE_AGENT
            )
            .is_err()
        );
        let action = net.action(
            &net.domain,
            NATIVE_KIND_DELEGATE_AGENT,
            a.id,
            Some(&before),
            3,
            build_native_delegate_payload([0x74; 32]).expect("payload"),
        );
        let body = build_native_submission(
            &net.domain,
            &action,
            1,
            &signatures(&[&stranger], &action),
            &[],
        )
        .expect("body");
        let result = net.send(&a.address, body);
        assert_address_exit(&result, &a.address, ERR_BAD_SIGNATURE);
        assert_eq!(net.state(&a.address).expect("state").state_hash, before.state_hash);

        // Stale predecessor: an action positioned on the state before a
        // successful one.
        let (result, _) = net.agent_action(
            &a,
            NATIVE_KIND_DELEGATE_AGENT,
            build_native_delegate_payload([0x75; 32]).expect("payload"),
            &[&a_key],
            &[],
            4,
        );
        assert_address_success(&result, &a.address);
        let moved = net.state(&a.address).expect("state");
        let action = net.action(
            &net.domain,
            NATIVE_KIND_DELEGATE_AGENT,
            a.id,
            Some(&before),
            5,
            build_native_delegate_payload([0x76; 32]).expect("payload"),
        );
        let body =
            build_native_submission(&net.domain, &action, 1, &signatures(&[&a_key], &action), &[])
                .expect("body");
        let result = net.send(&a.address, body);
        assert_address_exit(&result, &a.address, ERR_BAD_PREDECESSOR);
        assert_eq!(net.state(&a.address).expect("state").state_hash, moved.state_hash);
    }

    #[test]
    fn recovery_waits_for_its_timelock_and_policy_update_retires_the_old_key() {
        let mut net = Net::new();
        let a = net.register_agent(0x64, 60);
        let a_key = a.key.clone();
        let rescue = SigningKey::from_bytes(&[0x65; 32]);
        let rescue_policy = single_controller_policy(&rescue, 60);

        // Initiation needs possession of the recovery policy.
        check_native_possession(&rescue_policy, &public_keys(&[&rescue])).expect("possession");
        let execute_after = u64::from(net.bc.now()) + 60;
        let (result, initiate) = net.agent_action(
            &a,
            NATIVE_KIND_INITIATE_RECOVERY,
            build_native_initiate_recovery_payload(execute_after, &rescue_policy).expect("payload"),
            &[&a_key],
            &[&rescue],
            2,
        );
        assert_address_success(&result, &a.address);
        let pending = net.state(&a.address).expect("state");
        let NativeRegistryStateDetail::Agent { recovery: Some(r), .. } = &pending.detail else {
            panic!("pending recovery")
        };
        assert_eq!(r.initiation, *initiate.repr_hash().as_array());
        assert_eq!(r.execute_after, execute_after);

        // Completion before the timelock is refused and changes nothing.
        let payload = build_native_complete_recovery_payload(r.initiation).expect("payload");
        let (result, _) =
            net.agent_action(&a, NATIVE_KIND_COMPLETE_RECOVERY, payload.clone(), &[&a_key], &[], 3);
        assert_address_exit(&result, &a.address, ERR_TIMELOCK);
        assert_eq!(net.state(&a.address).expect("state").state_hash, pending.state_hash);

        // At the timelock it completes and starts the next generation under
        // the recovery policy.
        net.bc.set_now(u32::try_from(execute_after).expect("time"));
        let (result, _) =
            net.agent_action(&a, NATIVE_KIND_COMPLETE_RECOVERY, payload, &[&a_key], &[], 4);
        assert_address_success(&result, &a.address);
        let recovered = net.state(&a.address).expect("state");
        assert_eq!((recovered.generation, recovered.sequence), (2, 1));
        assert_eq!(agent_policy(&recovered), rescue_policy);

        // The old key is no longer a controller.
        let old = net.action(
            &net.domain,
            NATIVE_KIND_DELEGATE_AGENT,
            a.id,
            Some(&recovered),
            5,
            build_native_delegate_payload([0x77; 32]).expect("payload"),
        );
        let body = build_native_submission(&net.domain, &old, 1, &signatures(&[&a_key], &old), &[])
            .expect("body");
        let result = net.send(&a.address, body);
        assert_address_exit(&result, &a.address, ERR_BAD_SIGNATURE);

        // Policy update to a third key needs its possession signature; afterwards
        // the recovery key is retired the same way.
        let third = SigningKey::from_bytes(&[0x66; 32]);
        let next = single_controller_policy(&third, 120);
        let (result, _) = net.agent_action(
            &a,
            NATIVE_KIND_UPDATE_AGENT_POLICY,
            build_native_update_policy_payload(&next).expect("payload"),
            &[&rescue],
            &[&third],
            6,
        );
        assert_address_success(&result, &a.address);
        let updated = net.state(&a.address).expect("state");
        assert_eq!((updated.generation, updated.sequence), (2, 2));
        assert_eq!(agent_policy(&updated), next);
        assert!(
            check_native_threshold(
                &agent_policy(&updated),
                &public_keys(&[&rescue]),
                NATIVE_KIND_DELEGATE_AGENT
            )
            .is_err()
        );
    }
}

/// Conformance vectors for the off-chain Native Registry encoders in
/// tosnetwork/tos-service-protocol (`pkg/nativecore/testdata/native_registry_v1_vectors.json`),
/// produced by executing the release code: the inputs are the protocol's frozen
/// inputs; the object ids must equal its frozen ids (they do not depend on the
/// code); the contract address, action hash, action BOC and signature depend on
/// the code hash and are recorded in `fixtures/native_registry/protocol-vectors.json`
/// only after the release contract accepted exactly these actions at exactly
/// these addresses. `NATIVE_REGISTRY_VECTORS_OUT=<path>` writes the values
/// instead of comparing them.
mod protocol_vectors {
    use super::assert_address_success;
    use super::current_network;
    use chain_block::{Cell, MsgAddressInt};
    use contracts::native_registry::*;
    use fips204::ml_dsa_44;
    use fips204::traits::{KeyGen, SerDes, Signer};
    use sha2::{Digest, Sha256};
    use tos_sandbox::{Blockchain, MessageBuilder};

    const TOS: u64 = 1_000_000_000;
    const FIXTURE: &str = include_str!("fixtures/native_registry/protocol-vectors.json");

    /// The frozen controller: an ML-DSA-44 key from a fixed public seed, signing
    /// with the FIPS 204 deterministic variant (all-zero randomness) so that
    /// any implementation reproduces its signatures. Never an operational key.
    struct VectorKey {
        public_key: Vec<u8>,
        secret: ml_dsa_44::PrivateKey,
    }

    impl VectorKey {
        fn from_seed(seed: &[u8; 32]) -> Self {
            let (public_key, secret) = ml_dsa_44::KG::keygen_from_seed(seed);
            Self { public_key: public_key.into_bytes().to_vec(), secret }
        }

        fn sign(&self, action: &Cell) -> NativeControllerSignature {
            let signature = self
                .secret
                .try_sign_with_seed(
                    &[0; 32],
                    action.repr_hash().as_slice(),
                    NATIVE_REGISTRY_SIGNATURE_CONTEXT,
                )
                .expect("vector signature");
            NativeControllerSignature {
                public_key: self.public_key.clone(),
                signature: signature.to_vec(),
            }
        }
    }

    fn hex32(value: &str) -> [u8; 32] {
        hex::decode(value).expect("hex").try_into().expect("32 bytes")
    }

    fn data_state(bc: &Blockchain, address: &MsgAddressInt) -> NativeRegistryState {
        let data = bc.get_account(address).expect("account").get_data().expect("data");
        decode_native_registry_data(&data).expect("data").state.expect("registered")
    }

    /// The protocol's frozen action BOCs carry a CRC32-C trailer (`te6cck…`).
    fn b64(cell: &Cell) -> String {
        use base64::Engine;
        let mut bytes = Vec::new();
        chain_block::BocWriter::with_flags([cell.clone()], chain_block::BocFlags::Crc32)
            .expect("boc writer")
            .write(&mut bytes)
            .expect("boc");
        assert!(bytes.starts_with(&[0xb5, 0xee, 0x9c, 0x72]));
        assert_eq!(chain_block::read_single_root_boc(bytes.clone()).expect("reread"), *cell);
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn protocol_registration_vectors_execute_on_the_release_code() {
        let code = native_registry_release_code().expect("release code");
        let domain = NativeRegistryDomain::for_label(
            [0x11; 32],
            [0x22; 32],
            b"tos-testnet",
            *code.repr_hash().as_array(),
        )
        .expect("domain");
        // The protocol's vectors live in basechain 0, which the default sandbox
        // config does not describe.
        let mut bc =
            Blockchain::with_global_version_and_base_workchain(current_network::global_version())
                .expect("blockchain");
        bc.set_workchain(0);
        let relayer = bc.treasury("protocol-vector-relayer", 100 * TOS).expect("relayer");

        // Agent registration (the protocol's inputs).
        let key = VectorKey::from_seed(&hex32(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        ));
        let key_id = controller_key_id(&key.public_key).expect("key id");
        let policy = NativePolicy {
            threshold: 1,
            recovery_threshold: 1,
            recovery_timelock: 86_400,
            controllers: vec![NativePolicyController {
                public_key: key.public_key.clone(),
                weight: 1,
                purposes: 15,
            }],
        };
        let agent = build_native_agent_registration(&domain, [0x6f; 32], &policy).expect("agent");
        let (init, agent_address) =
            build_native_registry_deployment(&domain, 1, agent.object_id, 0, b"tos-testnet", &code)
                .expect("agent deployment");
        let agent_action = build_native_action(
            &domain,
            &NativeRegistryAction {
                kind: NATIVE_KIND_REGISTER_AGENT,
                generation: 1,
                sequence: 1,
                object_id: agent.object_id,
                predecessor: [0; 32],
                nonce: [0x61; 32],
                payload: agent.payload,
            },
        )
        .expect("agent action");
        let agent_signature = key.sign(&agent_action);
        let body =
            build_native_submission(&domain, &agent_action, 1, &[agent_signature.clone()], &[])
                .expect("agent body");
        let agent_body_hash = hex::encode(body.repr_hash().as_slice());
        let result = bc
            .send_message(
                MessageBuilder::internal(relayer.address(), &agent_address, TOS)
                    .bounce(false)
                    .state_init(init)
                    .body(body)
                    .build(),
            )
            .expect("register agent");
        assert_address_success(&result, &agent_address);
        assert_eq!(
            data_state(&bc, &agent_address).last_action,
            *agent_action.repr_hash().as_array()
        );

        // Capability registration under that Agent (the protocol's inputs).
        let capability = build_native_capability_registration(
            &domain,
            [0x63; 32],
            agent.object_id,
            b"1.0.0",
            [0x55; 32],
        )
        .expect("capability");
        let (_, capability_address) = build_native_registry_deployment(
            &domain,
            2,
            capability.object_id,
            0,
            b"tos-testnet",
            &code,
        )
        .expect("capability deployment");
        let capability_action = build_native_action(
            &domain,
            &NativeRegistryAction {
                kind: NATIVE_KIND_REGISTER_CAPABILITY,
                generation: 1,
                sequence: 1,
                object_id: capability.object_id,
                predecessor: [0; 32],
                nonce: [0x62; 32],
                payload: capability.payload,
            },
        )
        .expect("capability action");
        let capability_signature = key.sign(&capability_action);
        let body = build_native_submission(
            &domain,
            &capability_action,
            1,
            &[capability_signature.clone()],
            &[],
        )
        .expect("capability body");
        let capability_body_hash = hex::encode(body.repr_hash().as_slice());
        let result = bc
            .send_message(
                MessageBuilder::internal(relayer.address(), &agent_address, TOS).body(body).build(),
            )
            .expect("register capability");
        assert_address_success(&result, &capability_address);
        assert_eq!(
            data_state(&bc, &capability_address).last_action,
            *capability_action.repr_hash().as_array()
        );

        // Revocations, executed in order on the registered objects with the same
        // deterministic controller: one version, then the Capability, then the
        // Agent. For each, the vector records the inbound body the revoked
        // object's own account received, so a client decoding transitions from
        // account history reproduces exactly what the contract applied.
        let inbound_body = |result: &tos_sandbox::SendResult, address: &MsgAddressInt| -> Cell {
            let txs = result.transactions_for(address);
            assert_eq!(txs.len(), 1, "one transaction on the revoked object");
            let message = txs[0].read_in_msg().expect("in_msg").expect("inbound");
            message.body().expect("body").clone().into_cell().expect("body cell")
        };
        let mut revocations = Vec::new();
        let steps: [(&str, u8, &MsgAddressInt, [u8; 32], Cell); 3] = [
            (
                "revoke_version",
                NATIVE_KIND_REVOKE_CAPABILITY,
                &capability_address,
                [0x64; 32],
                build_native_revoke_capability_payload(agent.object_id, Some(b"1.0.0"))
                    .expect("payload"),
            ),
            (
                "revoke_capability",
                NATIVE_KIND_REVOKE_CAPABILITY,
                &capability_address,
                [0x65; 32],
                build_native_revoke_capability_payload(agent.object_id, None).expect("payload"),
            ),
            (
                "revoke_agent",
                NATIVE_KIND_REVOKE_AGENT,
                &agent_address,
                [0x66; 32],
                build_native_revoke_agent_payload().expect("payload"),
            ),
        ];
        for (name, kind, target, nonce, payload) in steps {
            let before = data_state(&bc, target);
            let (generation, sequence, predecessor) =
                next_native_position(Some(&before), kind).expect("position");
            let object_id =
                if *target == agent_address { agent.object_id } else { capability.object_id };
            let action = build_native_action(
                &domain,
                &NativeRegistryAction {
                    kind,
                    generation,
                    sequence,
                    object_id,
                    predecessor,
                    nonce,
                    payload,
                },
            )
            .expect("revocation action");
            let signature = key.sign(&action);
            let body = build_native_submission(&domain, &action, 1, &[signature.clone()], &[])
                .expect("revocation body");
            let body_hash = hex::encode(body.repr_hash().as_slice());
            let result = bc
                .send_message(
                    MessageBuilder::internal(relayer.address(), &agent_address, TOS)
                        .body(body)
                        .build(),
                )
                .expect(name);
            assert_address_success(&result, target);
            let received = inbound_body(&result, target);
            let after = data_state(&bc, target);
            assert_eq!(after.last_action, *action.repr_hash().as_array(), "{name} applied");
            let mut opcode =
                chain_block::SliceData::load_cell(received.clone()).expect("received body");
            revocations.push(serde_json::json!({
                "name": name,
                "object_id": format!(
                    "{}_{}",
                    if *target == agent_address { "agent" } else { "cap" },
                    hex::encode(object_id)
                ),
                "nonce": hex::encode(nonce),
                "contract_address": target.to_string(),
                "generation": generation,
                "sequence": sequence,
                "predecessor": hex::encode(predecessor),
                "action_hash": format!("sha256:{}", hex::encode(action.repr_hash().as_slice())),
                "action_boc_base64": b64(&action),
                "signature_sha256": format!("sha256:{}", hex::encode(Sha256::digest(&signature.signature))),
                "submission_body_hash": format!("tvm-cell-sha256:{}", body_hash),
                "object_inbound_opcode": format!("0x{:08x}", opcode.get_next_u32().expect("opcode")),
                "object_inbound_body_boc_base64": b64(&received),
                "state_hash_after": hex::encode(after.state_hash),
                "tombstone_after": after.tombstone,
            }));
        }

        let address_text = |a: &MsgAddressInt| a.to_string();
        let actual = serde_json::json!({
            "contract_code_hash": format!("tvm-cell-sha256:{}", hex::encode(code.repr_hash().as_slice())),
            "controller": {
                "key_seed_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                "suite": "ML-DSA-44",
                "public_key_sha256": format!("sha256:{}", hex::encode(Sha256::digest(&key.public_key))),
                "key_id": hex::encode(key_id),
                "signature_context": String::from_utf8_lossy(NATIVE_REGISTRY_SIGNATURE_CONTEXT),
                "signing": "deterministic (rnd = 0^32)",
            },
            "agent_registration": {
                "object_id": format!("agent_{}", hex::encode(agent.object_id)),
                "contract_address": address_text(&agent_address),
                "action_hash": format!("sha256:{}", hex::encode(agent_action.repr_hash().as_slice())),
                "action_boc_base64": b64(&agent_action),
                "signature_sha256": format!("sha256:{}", hex::encode(Sha256::digest(&agent_signature.signature))),
                "submission_body_hash": format!("tvm-cell-sha256:{}", agent_body_hash),
            },
            "capability_registration": {
                "object_id": format!("cap_{}", hex::encode(capability.object_id)),
                "contract_address": address_text(&capability_address),
                "action_hash": format!("sha256:{}", hex::encode(capability_action.repr_hash().as_slice())),
                "action_boc_base64": b64(&capability_action),
                "signature_sha256": format!("sha256:{}", hex::encode(Sha256::digest(&capability_signature.signature))),
                "submission_body_hash": format!("tvm-cell-sha256:{}", capability_body_hash),
            },
            "revocations": revocations,
        });
        // The full protocol-format vector file (tos-service-protocol
        // pkg/nativecore/testdata and tos-service-spec test-vectors). Every
        // positive value is taken from this contract-executed run. The negative
        // mutations are not executed here: they are the protocol's own
        // client-side checks, listed with the contract error code each must
        // map to, so the file is produced in one place. The document is built
        // and checked on every run; it is written only when requested.
        {
            let code_boc: String = NATIVE_REGISTRY_RELEASE_CODE_B64.split_whitespace().collect();
            let mutation = |registration: &str, mutation: &str, code: i32| {
                serde_json::json!({"registration": registration, "mutation": mutation,
                    "expected_code": code})
            };
            let full = serde_json::json!({
                "schema": "tos.service.registry.v1.vectors",
                "protocol": "tos_service_v1",
                "contract_code_hash": actual["contract_code_hash"],
                "contract_code_boc_base64": code_boc,
                "network": {
                    "network_id": "tos-testnet",
                    "genesis_root_hash": format!("sha256:{}", hex::encode([0x11; 32])),
                    "genesis_file_hash": format!("sha256:{}", hex::encode([0x22; 32])),
                },
                "signature": {
                    "suite": "ML-DSA-44",
                    "context": String::from_utf8_lossy(NATIVE_REGISTRY_SIGNATURE_CONTEXT),
                    "signing": "FIPS 204 deterministic variant (rnd = 0^32) over the 32-byte action hash",
                },
                "agent_registration": {
                    "private_seed_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                    "object_nonce_hex": hex::encode([0x6f; 32]),
                    "action_nonce_hex": hex::encode([0x61; 32]),
                    "policy": {
                        "threshold": 1,
                        "recovery_threshold": 1,
                        "recovery_timelock_seconds": 86_400,
                        "controllers": [{
                            "public_key_hex": hex::encode(&key.public_key),
                            "key_id": format!("mldsa44:{}", hex::encode(key_id)),
                            "weight": 1,
                            "purpose_mask": 15,
                            "recovery": true,
                        }],
                    },
                    "expected": {
                        "object_id": actual["agent_registration"]["object_id"],
                        "contract_address": actual["agent_registration"]["contract_address"],
                        "action_hash": actual["agent_registration"]["action_hash"],
                        "action_boc_base64": actual["agent_registration"]["action_boc_base64"],
                        "signature_hex": hex::encode(&agent_signature.signature),
                        "submission_body_hash": actual["agent_registration"]["submission_body_hash"],
                    },
                },
                "capability_registration": {
                    "owner_agent_id": actual["agent_registration"]["object_id"],
                    "object_nonce_hex": hex::encode([0x63; 32]),
                    "action_nonce_hex": hex::encode([0x62; 32]),
                    "version": "1.0.0",
                    "manifest_digest": format!("sha256:{}", hex::encode([0x55; 32])),
                    "expected": {
                        "object_id": actual["capability_registration"]["object_id"],
                        "contract_address": actual["capability_registration"]["contract_address"],
                        "action_hash": actual["capability_registration"]["action_hash"],
                        "action_boc_base64": actual["capability_registration"]["action_boc_base64"],
                        "signature_hex": hex::encode(&capability_signature.signature),
                        "submission_body_hash": actual["capability_registration"]["submission_body_hash"],
                    },
                },
                "revocations": actual["revocations"],
                "negative_mutations": [
                    mutation("agent", "wrong_protocol", 2200),
                    mutation("agent", "empty_network_id", 2201),
                    mutation("agent", "zero_genesis_root", 2201),
                    mutation("agent", "wrong_contract_hash", 2202),
                    mutation("agent", "zero_action_nonce", 2203),
                    mutation("agent", "zero_target_id", 2203),
                    mutation("agent", "zero_object_nonce", 2203),
                    mutation("agent", "unattainable_policy", 2207),
                    mutation("agent", "caller_selected_id", 2210),
                    mutation("agent", "generation_zero", 2205),
                    mutation("agent", "registration_generation_two", 2205),
                    mutation("capability", "wrong_owner_kind", 2203),
                    mutation("capability", "zero_object_nonce", 2203),
                    mutation("capability", "revoked_initial_version", 2203),
                    mutation("capability", "version_too_long", 2203),
                    mutation("capability", "version_non_printable", 2203),
                    mutation("capability", "caller_selected_id", 2210),
                    mutation("capability", "registration_sequence_two", 2205),
                ],
            });
            let released = chain_block::read_single_root_boc(
                chain_block::base64_decode(&code_boc).expect("code base64"),
            )
            .expect("code BOC");
            assert_eq!(
                full["contract_code_hash"],
                serde_json::json!(format!(
                    "tvm-cell-sha256:{}",
                    hex::encode(released.repr_hash().as_slice())
                )),
                "the exported code BOC is the code this run executed"
            );
            let negatives = full["negative_mutations"].as_array().expect("negative mutations");
            assert_eq!(negatives.len(), 18, "every client-side negative check is listed");
            let mut seen = std::collections::BTreeSet::new();
            for entry in negatives {
                let key = (entry["registration"].to_string(), entry["mutation"].to_string());
                assert!(seen.insert(key), "duplicate negative check {entry}");
                let code = entry["expected_code"].as_i64().expect("expected code");
                assert!((2200..=2215).contains(&code), "{entry} maps outside the registry codes");
            }
            for registration in ["agent_registration", "capability_registration"] {
                assert!(full[registration].is_object(), "{registration} is exported");
            }
            if let Ok(path) = std::env::var("NATIVE_REGISTRY_PROTOCOL_VECTORS_OUT") {
                std::fs::write(&path, serde_json::to_string_pretty(&full).expect("json") + "\n")
                    .expect("write protocol vectors");
            }
        }
        if let Ok(path) = std::env::var("NATIVE_REGISTRY_VECTORS_OUT") {
            std::fs::write(&path, serde_json::to_string_pretty(&actual).expect("json") + "\n")
                .expect("write vectors");
            return;
        }
        let expected: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture");
        assert_eq!(actual, expected, "conformance vectors moved; regenerate deliberately");
    }
}
