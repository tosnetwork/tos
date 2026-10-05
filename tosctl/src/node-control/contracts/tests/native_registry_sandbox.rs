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

use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
    TrComputePhase, TransactionDescr, base64_decode, read_single_root_boc,
};
use contracts::native_registry::{
    NATIVE_REGISTRY_ERR_POLICY_TOO_WIDE, NATIVE_REGISTRY_GAS_CEILING,
    NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS, NATIVE_REGISTRY_TRANSACTION_GAS_LIMIT, NativePolicy,
    NativePolicyController, build_policy,
};
use ed25519_dalek::{Signer, SigningKey};
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

fn policy(key: &SigningKey) -> Cell {
    let public_key = key.verifying_key().to_bytes();
    let mut controller = BuilderData::new();
    controller
        .append_u256(&public_key)
        .unwrap()
        .append_u256(&public_key)
        .unwrap()
        .append_u32(1)
        .unwrap()
        .append_u16(0x0f)
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
    root.into_cell().unwrap()
}

fn purpose_partitioned_unreachable_policy() -> Cell {
    let first = SigningKey::from_bytes(&[0x81; 32]).verifying_key().to_bytes();
    let second = SigningKey::from_bytes(&[0x82; 32]).verifying_key().to_bytes();
    let mut controllers = vec![(first, 0x05_u16, true), (second, 0x0a_u16, false)];
    controllers.sort_by_key(|entry| entry.0);
    let mut next: Option<Cell> = None;
    for (public_key, purposes, recovery) in controllers.into_iter().rev() {
        let mut controller = BuilderData::new();
        controller
            .append_u256(&public_key)
            .unwrap()
            .append_u256(&public_key)
            .unwrap()
            .append_u32(1)
            .unwrap()
            .append_u16(purposes)
            .unwrap()
            .append_bit_bool(recovery)
            .unwrap();
        if let Some(cell) = next {
            controller.checked_append_reference(cell).unwrap();
        }
        next = Some(controller.into_cell().unwrap());
    }
    let mut root = BuilderData::new();
    root.append_u32(MAGIC_POLICY)
        .unwrap()
        .append_u16(1)
        .unwrap()
        .append_u32(2)
        .unwrap()
        .append_u32(1)
        .unwrap()
        .append_u64(10)
        .unwrap()
        .append_u8(2)
        .unwrap()
        .checked_append_reference(next.unwrap())
        .unwrap();
    root.into_cell().unwrap()
}

fn signature_set(key: &SigningKey, action: &Cell) -> Cell {
    signature_set_many(&[key], action)
}

fn purpose_isolated_policy() -> (Cell, Vec<SigningKey>) {
    let keys = vec![
        SigningKey::from_bytes(&[0x91; 32]),
        SigningKey::from_bytes(&[0x92; 32]),
        SigningKey::from_bytes(&[0x93; 32]),
    ];
    let mut controllers = vec![
        (keys[0].verifying_key().to_bytes(), 0x05_u16, true),
        (keys[1].verifying_key().to_bytes(), 0x02_u16, false),
        (keys[2].verifying_key().to_bytes(), 0x08_u16, false),
    ];
    controllers.sort_by_key(|entry| entry.0);
    let mut next: Option<Cell> = None;
    for (public_key, purposes, recovery) in controllers.into_iter().rev() {
        let mut controller = BuilderData::new();
        controller
            .append_u256(&public_key)
            .unwrap()
            .append_u256(&public_key)
            .unwrap()
            .append_u32(1)
            .unwrap()
            .append_u16(purposes)
            .unwrap()
            .append_bit_bool(recovery)
            .unwrap();
        if let Some(cell) = next {
            controller.checked_append_reference(cell).unwrap();
        }
        next = Some(controller.into_cell().unwrap());
    }
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
        .append_u8(3)
        .unwrap()
        .checked_append_reference(next.unwrap())
        .unwrap();
    (root.into_cell().unwrap(), keys)
}

fn signature_set_many(keys: &[&SigningKey], action: &Cell) -> Cell {
    let mut signatures: Vec<_> = keys
        .iter()
        .map(|key| {
            let public_key = key.verifying_key().to_bytes();
            let signature = key.sign(action.hash(0).as_slice()).to_bytes();
            (public_key, signature)
        })
        .collect();
    signatures.sort_by_key(|entry| entry.0);
    let mut next: Option<Cell> = None;
    for (public_key, signature) in signatures.into_iter().rev() {
        let mut entry = BuilderData::new();
        entry.append_u256(&public_key).unwrap().append_raw(&signature, 512).unwrap();
        if let Some(cell) = next {
            entry.checked_append_reference(cell).unwrap();
        }
        next = Some(entry.into_cell().unwrap());
    }
    let mut root = BuilderData::new();
    root.append_u8(keys.len() as u8).unwrap().checked_append_reference(next.unwrap()).unwrap();
    root.into_cell().unwrap()
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

struct Fixture {
    bc: Blockchain,
    relayer: Treasury,
    registry: MsgAddressInt,
    object_id: [u8; 32],
    domain: Cell,
    identity_domain: Cell,
    config: Cell,
    contract_code: Cell,
    old_key: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        // The frozen Native Registry uses SHA256C, a version-14 opcode. The
        // network has not activated v14 yet, so this sandbox opts into the
        // pre-activation version explicitly instead of weakening opcode gates.
        let mut bc = Blockchain::with_global_version(14).expect("blockchain");
        bc.set_workchain(-1);
        let relayer = bc.treasury("native-registry-relayer", 1_000 * TOS).expect("relayer");
        let old_key = SigningKey::from_bytes(&[0x31; 32]);
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
            .append_i32(-1)
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
        let registry = MsgAddressInt::with_params(-1, registry_hash).expect("registry address");

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
        self.bc.send_message(msg).expect("submit")
    }

    fn deploy_agent(
        &mut self,
        key: &SigningKey,
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
        let address = MsgAddressInt::with_params(-1, address_hash).expect("agent address");

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
        (MsgAddressInt::with_params(-1, address_hash).expect("object address"), state_init)
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
        owner_key: &SigningKey,
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
    let recovery_key = SigningKey::from_bytes(&[0x52; 32]);
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
    let recovery_key = SigningKey::from_bytes(&[0x52; 32]);
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

    let replacement_key = SigningKey::from_bytes(&[0x63; 32]);
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
    let chosen_key = SigningKey::from_bytes(&[0xf2; 32]);
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

    let replacement_key = SigningKey::from_bytes(&[0xa1; 32]);
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

    let attacker = SigningKey::from_bytes(&[0xb5; 32]);
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
    let first_key = SigningKey::from_bytes(&[0xc1; 32]);
    let second_key = SigningKey::from_bytes(&[0xc2; 32]);
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
    let old_owner_key = SigningKey::from_bytes(&f.old_key.to_bytes());
    let new_owner_key = SigningKey::from_bytes(&[0xd1; 32]);
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
    let old_owner_key = SigningKey::from_bytes(&f.old_key.to_bytes());
    let new_owner_key = SigningKey::from_bytes(&[0xe1; 32]);
    let wrong_acceptance_key = SigningKey::from_bytes(&[0xe2; 32]);
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

mod weak_ed25519;

const ERR_THRESHOLD: i32 = 2209;
const ERR_WEAK_KEY: i32 = 2214;
const ALL_PURPOSES: u16 = 0x0f;

/// Exit code a policy naming `key` is refused with. The all-zero key already
/// fails the older nonzero check, which runs first and answers with
/// `bad_policy`; every other weak key reaches the weak-key check.
fn weak_admission_code(key: &[u8; 32]) -> i32 {
    if key == &[0u8; 32] { ERR_BAD_POLICY } else { ERR_WEAK_KEY }
}

/// A policy over `(public_key, weight, purposes, recovery)` controllers, sorted
/// by key the way the contract requires.
fn policy_of(
    threshold: u32,
    recovery_threshold: u32,
    controllers: &[([u8; 32], u32, u16, bool)],
) -> Cell {
    let mut sorted = controllers.to_vec();
    sorted.sort_by_key(|entry| entry.0);
    let mut next: Option<Cell> = None;
    for (public_key, weight, purposes, recovery) in sorted.into_iter().rev() {
        let mut controller = BuilderData::new();
        controller
            .append_u256(&public_key)
            .unwrap()
            .append_u256(&public_key)
            .unwrap()
            .append_u32(weight)
            .unwrap()
            .append_u16(purposes)
            .unwrap()
            .append_bit_bool(recovery)
            .unwrap();
        if let Some(cell) = next {
            controller.checked_append_reference(cell).unwrap();
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
        .append_u8(controllers.len() as u8)
        .unwrap()
        .checked_append_reference(next.unwrap())
        .unwrap();
    root.into_cell().unwrap()
}

/// A signature list from `(public_key, signature)` pairs, sorted by key.
fn signature_entries(mut entries: Vec<([u8; 32], [u8; 64])>) -> Cell {
    entries.sort_by_key(|entry| entry.0);
    let count = entries.len() as u8;
    let mut next: Option<Cell> = None;
    for (public_key, signature) in entries.into_iter().rev() {
        let mut entry = BuilderData::new();
        entry.append_u256(&public_key).unwrap().append_raw(&signature, 512).unwrap();
        if let Some(cell) = next {
            entry.checked_append_reference(cell).unwrap();
        }
        next = Some(entry.into_cell().unwrap());
    }
    let mut root = BuilderData::new();
    root.append_u8(count).unwrap().checked_append_reference(next.unwrap()).unwrap();
    root.into_cell().unwrap()
}

fn signed(key: &SigningKey, action: &Cell) -> ([u8; 32], [u8; 64]) {
    (key.verifying_key().to_bytes(), key.sign(action.hash(0).as_slice()).to_bytes())
}

/// The order-2 torsion key: canonical, on the curve, and forgeable for about
/// half of all messages.
fn forgeable_weak_key() -> [u8; 32] {
    let key = weak_ed25519::weak_keys()[4];
    assert_eq!(key[0], 0xec, "the order-2 point (y = -1)");
    key
}

/// Builds the action `make(nonce)` for successive nonces until the weak key's
/// signature over it can be forged, and returns both.
fn forge_for(weak: &[u8; 32], make: impl Fn(u8) -> Cell) -> (Cell, [u8; 64]) {
    (100..=255)
        .find_map(|nonce| {
            let action = make(nonce);
            weak_ed25519::forge(weak, action.hash(0).as_slice()).map(|sig| (action, sig))
        })
        .expect("some nonce admits a forged signature")
}

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
        (self.bc.send_message(deploy).expect("register"), address)
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

/// Every weak key is refused when an agent registers a policy naming it, even
/// next to a strong key that alone meets every threshold.
#[test]
fn registration_refuses_every_weak_controller_key() {
    let mut f = Fixture::new();
    let strong = SigningKey::from_bytes(&[0xc1; 32]);
    for (i, weak) in weak_ed25519::weak_keys().into_iter().enumerate() {
        let weak_policy = policy_of(
            1,
            1,
            &[
                (strong.verifying_key().to_bytes(), 1, ALL_PURPOSES, true),
                (weak, 1, ALL_PURPOSES, true),
            ],
        );
        let nonce = [0xd0 + i as u8; 32];
        let (result, address) = f.register_with(weak_policy, nonce, |register| {
            signature_entries(vec![signed(&strong, register), (weak, [0u8; 64])])
        });
        result.expect_aborted().expect_exit_code(weak_admission_code(&weak));
        assert!(!f.registered(&address), "weak key {i} must not leave a registered agent");
    }
    // The same strong key alone registers: the refusals above are the weak key's.
    let strong_policy =
        policy_of(1, 1, &[(strong.verifying_key().to_bytes(), 1, ALL_PURPOSES, true)]);
    let (result, address) = f.register_with(strong_policy, [0xcf; 32], |register| {
        signature_entries(vec![signed(&strong, register)])
    });
    result.expect_success();
    assert!(f.registered(&address));
}

/// Every weak key is refused when an existing agent rotates to a policy naming it.
#[test]
fn policy_update_refuses_every_weak_controller_key() {
    let mut f = Fixture::new();
    let before = f.state().hash(0);
    let strong = SigningKey::from_bytes(&[0xc2; 32]);
    for weak in weak_ed25519::weak_keys() {
        let weak_policy = policy_of(
            1,
            1,
            &[
                (strong.verifying_key().to_bytes(), 1, ALL_PURPOSES, true),
                (weak, 1, ALL_PURPOSES, true),
            ],
        );
        let mut payload = BuilderData::new();
        payload.checked_append_reference(weak_policy).unwrap();
        let update = f.build_action(UPDATE_AGENT_POLICY, 1, 2, 40, payload.into_cell().unwrap());
        f.send(submit_body(
            update.clone(),
            signature_set(&f.old_key, &update),
            signature_entries(vec![signed(&strong, &update), (weak, [0u8; 64])]),
        ))
        .expect_aborted()
        .expect_exit_code(weak_admission_code(&weak));
        assert_eq!(f.state().hash(0), before, "a refused policy must not be installed");
    }
}

/// A recovery policy naming a weak key is refused when recovery is initiated.
#[test]
fn recovery_initiation_refuses_a_weak_controller_key() {
    let mut f = Fixture::new();
    let before = f.state().hash(0);
    let weak = forgeable_weak_key();
    let strong = SigningKey::from_bytes(&[0xc3; 32]);
    let recovery_policy = policy_of(
        1,
        1,
        &[
            (strong.verifying_key().to_bytes(), 1, ALL_PURPOSES, true),
            (weak, 1, ALL_PURPOSES, true),
        ],
    );
    let execute_after = u64::from(f.bc.now()) + 10;
    let (initiate, forged) = forge_for(&weak, |nonce| {
        let mut payload = BuilderData::new();
        payload
            .append_u64(execute_after)
            .unwrap()
            .checked_append_reference(recovery_policy.clone())
            .unwrap();
        f.build_action(INITIATE_RECOVERY, 1, 2, nonce, payload.into_cell().unwrap())
    });
    f.send(submit_body(
        initiate.clone(),
        signature_set(&f.old_key, &initiate),
        signature_entries(vec![signed(&strong, &initiate), (weak, forged)]),
    ))
    .expect_aborted()
    .expect_exit_code(ERR_WEAK_KEY);
    assert_eq!(f.state().hash(0), before);
}

/// Proof of possession for a weak key proves nothing: a signature forged with
/// no secret verifies under it, and the policy is still refused.
#[test]
fn a_forged_possession_signature_does_not_install_a_weak_key() {
    let mut f = Fixture::new();
    let before = f.state().hash(0);
    let weak = forgeable_weak_key();
    let strong = SigningKey::from_bytes(&[0xc4; 32]);
    let weak_policy = policy_of(
        1,
        1,
        &[
            (strong.verifying_key().to_bytes(), 1, ALL_PURPOSES, true),
            (weak, 1, ALL_PURPOSES, true),
        ],
    );
    let (update, forged) = forge_for(&weak, |nonce| {
        let mut payload = BuilderData::new();
        payload.checked_append_reference(weak_policy.clone()).unwrap();
        f.build_action(UPDATE_AGENT_POLICY, 1, 2, nonce, payload.into_cell().unwrap())
    });
    f.send(submit_body(
        update.clone(),
        signature_set(&f.old_key, &update),
        signature_entries(vec![signed(&strong, &update), (weak, forged)]),
    ))
    .expect_aborted()
    .expect_exit_code(ERR_WEAK_KEY);
    assert_eq!(f.state().hash(0), before, "a forged possession proof installed a weak key");
}

/// A stored policy that names a weak key -- one no action could have installed
/// -- is refused when it is used, so a threshold met only by counting the weak
/// key's forged signature authorizes nothing.
#[test]
fn a_stored_weak_key_does_not_count_toward_a_threshold() {
    let mut f = Fixture::new();
    let weak = forgeable_weak_key();
    let strong = SigningKey::from_bytes(&[0xc5; 32]);
    let second = SigningKey::from_bytes(&[0xc6; 32]);

    // Positive control for the injection itself: a stored 2-of-2 of strong keys
    // authorizes with both signatures and not with one.
    f.install_policy(policy_of(
        2,
        1,
        &[
            (strong.verifying_key().to_bytes(), 1, ALL_PURPOSES, true),
            (second.verifying_key().to_bytes(), 1, ALL_PURPOSES, true),
        ],
    ));
    let one = f.delegate_action(2, 50);
    f.send(submit_body(one.clone(), signature_set(&strong, &one), empty_signatures()))
        .expect_aborted()
        .expect_exit_code(ERR_THRESHOLD);
    let both = f.delegate_action(2, 51);
    f.send(submit_body(
        both.clone(),
        signature_set_many(&[&strong, &second], &both),
        empty_signatures(),
    ))
    .expect_success();
    assert_eq!(f.state_position(), (1, 2));

    // The same threshold where the second key is weak: the strong signature
    // alone is short, and the weak key's forged signature must not fill the gap.
    f.install_policy(policy_of(
        2,
        1,
        &[
            (strong.verifying_key().to_bytes(), 1, ALL_PURPOSES, true),
            (weak, 1, ALL_PURPOSES, true),
        ],
    ));
    let before = f.state().hash(0);
    let (counted, forged) = forge_for(&weak, |nonce| f.delegate_action(3, nonce));
    f.send(submit_body(
        counted.clone(),
        signature_entries(vec![signed(&strong, &counted), (weak, forged)]),
        empty_signatures(),
    ))
    .expect_aborted()
    .expect_exit_code(ERR_WEAK_KEY);
    assert_eq!(f.state().hash(0), before, "a forged weak signature completed a threshold");
}

/// The identity and the order-2 point spelled with the sign bit set pass a y
/// range check. Each is refused at admission even with a forged possession
/// proof, and a stored policy naming one does not let its forged signature
/// complete a threshold.
#[test]
fn sign_bit_aliases_neither_install_nor_count() {
    let strong = SigningKey::from_bytes(&[0xc7; 32]);
    for alias in weak_ed25519::sign_bit_aliases() {
        let alias_policy = |threshold| {
            policy_of(
                threshold,
                1,
                &[
                    (strong.verifying_key().to_bytes(), 1, ALL_PURPOSES, true),
                    (alias, 1, ALL_PURPOSES, true),
                ],
            )
        };

        let mut f = Fixture::new();
        let before = f.state().hash(0);
        let (update, forged) = forge_for(&alias, |nonce| {
            let mut payload = BuilderData::new();
            payload.checked_append_reference(alias_policy(1)).unwrap();
            f.build_action(UPDATE_AGENT_POLICY, 1, 2, nonce, payload.into_cell().unwrap())
        });
        f.send(submit_body(
            update.clone(),
            signature_set(&f.old_key, &update),
            signature_entries(vec![signed(&strong, &update), (alias, forged)]),
        ))
        .expect_aborted()
        .expect_exit_code(ERR_WEAK_KEY);
        assert_eq!(f.state().hash(0), before, "a forged possession proof installed an alias");

        f.install_policy(alias_policy(2));
        let before = f.state().hash(0);
        let (counted, forged) = forge_for(&alias, |nonce| f.delegate_action(2, nonce));
        f.send(submit_body(
            counted.clone(),
            signature_entries(vec![signed(&strong, &counted), (alias, forged)]),
            empty_signatures(),
        ))
        .expect_aborted()
        .expect_exit_code(ERR_WEAK_KEY);
        assert_eq!(f.state().hash(0), before, "an alias's forged signature completed a threshold");
    }
}

// ---------------------------------------------------------------------------
// Supported policy width.
//
// Every path that walks a policy or checks a signature per controller is
// measured at maximum-width inputs: every controller holds every purpose and
// the recovery flag, every controller signs, and every key takes the weak-key
// check's longer branch. Each such path must stay within the gas ceiling at
// the supported width, and one controller more must be refused wherever a
// policy enters storage.
// ---------------------------------------------------------------------------

const MAX_WIDTH: usize = NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS;
const ERR_POLICY_TOO_WIDE: i32 = NATIVE_REGISTRY_ERR_POLICY_TOO_WIDE;
/// Enough value for the whole masterchain gas limit and a second leg.
const MEASURE_VALUE: u64 = 40 * TOS;

/// `width` deterministic keys whose first byte is below 0xec, where the
/// weak-key check runs its longer branch.
fn width_keys(width: usize, salt: u8) -> Vec<SigningKey> {
    let mut keys = Vec::with_capacity(width);
    let mut counter: u32 = 0;
    while keys.len() < width {
        let mut seed = vec![salt];
        seed.extend_from_slice(&counter.to_be_bytes());
        counter += 1;
        let key = SigningKey::from_bytes(&bytes_hash(&seed));
        if key.verifying_key().to_bytes()[0] < 0xec {
            keys.push(key);
        }
    }
    keys
}

/// Every key holds every purpose and the recovery flag with weight 1, and both
/// thresholds need every key.
fn wide_policy(keys: &[SigningKey]) -> Cell {
    let controllers: Vec<_> =
        keys.iter().map(|key| (key.verifying_key().to_bytes(), 1, ALL_PURPOSES, true)).collect();
    policy_of(keys.len() as u32, keys.len() as u32, &controllers)
}

fn all_sign(keys: &[SigningKey], action: &Cell) -> Cell {
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

        let placeholder = SigningKey::from_bytes(&[0x6b; 32]);
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
/// maximum-width policy, within the gas ceiling of the masterchain limit. A
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

/// The capacity table behind the supported width. Run with
/// `--ignored --nocapture`.
#[test]
#[ignore = "measurement sweep; prints the gas table"]
fn policy_width_gas_table() {
    let mut cases: Vec<(usize, usize)> =
        [1, 4, 8, 12, 16, 18, 20, 21, 22, 24, 26, 28].iter().map(|w| (*w, *w)).collect();
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
// recovery initiation -- and a stored policy that wide, which only a
// hand-built state could carry, authorizes nothing. Each admission point has
// its own test so that each one's guard is shown to be what refuses it.

fn too_wide_keys() -> Vec<SigningKey> {
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
    let update_to = |f: &mut Fixture, keys: &[SigningKey]| {
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
    let initiate_to = |f: &mut Fixture, keys: &[SigningKey]| {
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

/// A stored policy wider than supported authorizes nothing, even with every
/// one of its controllers signing.
#[test]
fn a_stored_policy_wider_than_supported_authorizes_nothing() {
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
    .expect_exit_code(ERR_POLICY_TOO_WIDE);
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
    let mut signers: Vec<SigningKey> = keys.clone();
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
    let to_policy = |keys: &[SigningKey]| NativePolicy {
        threshold: keys.len() as u32,
        recovery_threshold: keys.len() as u32,
        recovery_timelock: 10,
        controllers: keys
            .iter()
            .map(|key| NativePolicyController {
                public_key: key.verifying_key().to_bytes(),
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
