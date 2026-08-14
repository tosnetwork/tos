/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Executable lifecycle evidence for the ATOS Native Registry.
//!
//! These tests deliberately build the canonical cells directly. This keeps
//! the contract test independent of the Go SDK while proving that the TVM
//! accepts generation resets with a live predecessor and that recovery is
//! bound to the policy under which it was initiated.

use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
    base64_decode, read_single_root_boc,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, Treasury};

const TOS: u64 = 1_000_000_000;
const OP_SUBMIT: u32 = 0x4e56_0001;
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
const ERR_BAD_TRANSITION: i32 = 2210;
const ERR_BAD_POLICY: i32 = 2207;

fn code() -> Cell {
    let encoded: String =
        include_str!("../../../../../crypto/smartcont/atos-native-registry-v1.boc.base64")
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
    let public_key = key.verifying_key().to_bytes();
    let signature = key.sign(action.hash(0).as_slice()).to_bytes();
    let mut entry = BuilderData::new();
    entry.append_u256(&public_key).unwrap().append_raw(&signature, 512).unwrap();
    let mut root = BuilderData::new();
    root.append_u8(1).unwrap().checked_append_reference(entry.into_cell().unwrap()).unwrap();
    root.into_cell().unwrap()
}

fn empty_signatures() -> Cell {
    let mut b = BuilderData::new();
    b.append_u8(0).unwrap();
    b.into_cell().unwrap()
}

fn action(
    kind: u8,
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
        .append_u8(1)
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
    old_key: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
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
            .checked_append_reference(identity_domain.into_cell().unwrap())
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
            .checked_append_reference(config)
            .unwrap()
            .append_bit_zero()
            .unwrap();
        let state_init = StateInit::with_code_and_data(contract_code, data.into_cell().unwrap());
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

        Self { bc, relayer, registry, object_id, domain, old_key }
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
        let msg = MessageBuilder::internal(self.relayer.address(), &self.registry, TOS)
            .body(body)
            .build();
        self.bc.send_message(msg).expect("submit")
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
            generation,
            sequence,
            &self.object_id,
            &predecessor,
            nonce,
            &self.domain,
            payload,
        )
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
