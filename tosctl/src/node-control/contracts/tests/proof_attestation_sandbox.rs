/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) lifecycle tests for the Proof Attestation contract.
//!
//! These execute the compiled contract embedded in `ProofAttestationContract`
//! against the in-process executor, which is what makes this suite the real
//! crux of the "proof adapter" feature: it proves TVM's native `CHKSIGNU`
//! opcode actually accepts a signature produced off-chain by `ed25519-dalek`
//! (the same library `secrets-vault`'s ed25519 backend uses in production),
//! not just that the Rust-side encoding round-trips.

use chain_block::{Cell, MsgAddressInt};
use contracts::{ProofAttestationContract, ProofAttestationInit};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

const TOS: u64 = 1_000_000_000;
const ERR_REVOKED: i32 = 2100;
const ERR_BAD_SIGNATURE: i32 = 2101;
const ERR_NOT_OWNER: i32 = 2102;
const ERR_UNKNOWN_OP: i32 = 2103;

struct Fixture {
    bc: Blockchain,
    owner: Treasury,
    outsider: Treasury,
    signing_key: SigningKey,
    attestation: MsgAddressInt,
}

impl Fixture {
    fn new(funding: u64) -> Self {
        Self::with_subject_hash(funding, SigningKey::from_bytes(&[0x42; 32]), [0x11; 32])
    }

    /// `subject_hash` doubles as a deploy-data salt: two fixtures with the
    /// same `signing_key` but different `subject_hash` deploy to distinct
    /// addresses, which is what makes the cross-instance replay test below
    /// meaningful (`calculate_address` hashes the full `StateInit`).
    fn with_subject_hash(funding: u64, signing_key: SigningKey, subject_hash: [u8; 32]) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let owner = bc.treasury("owner", 1_000 * TOS).expect("owner");
        let outsider = bc.treasury("outsider", 1_000 * TOS).expect("outsider");
        let init = ProofAttestationInit {
            owner: owner.address().clone(),
            public_key: signing_key.verifying_key().to_bytes(),
            subject_hash,
        };
        let attestation = ProofAttestationContract::calculate_address(-1, &init).expect("address");
        let state_init = ProofAttestationContract::build_state_init(&init).expect("state init");
        let deploy = MessageBuilder::internal(owner.address(), &attestation, funding)
            .bounce(false)
            .state_init(state_init)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, owner, outsider, signing_key, attestation }
    }

    fn send_from(&mut self, from: &MsgAddressInt, body: Cell) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(from, &self.attestation, TOS / 10).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    fn data(&self) -> contracts::ProofAttestationData {
        let stack = self
            .bc
            .run_get_method(&self.attestation, "get_proof_attestation_data", vec![])
            .expect("get_proof_attestation_data")
            .expect_success()
            .stack
            .clone();
        let entries = stack
            .iter()
            .map(sandbox_stack_item_to_entry)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("stack conversion");
        ProofAttestationContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(
            entries,
        ))
        .expect("decode_data")
    }
}

/// Mirrors the equivalent helper in `capability_registry_sandbox.rs` /
/// `service_actor_sandbox.rs` / `dispute_sandbox.rs`.
fn sandbox_stack_item_to_entry(
    item: &tos_vm::stack::StackItem,
) -> anyhow::Result<tl_api::tos::tvm::StackEntry> {
    use tl_api::tos::tvm::{
        Number, StackEntry,
        numberdecimal::NumberDecimal,
        slice,
        stackentry::{StackEntryNumber, StackEntrySlice},
    };
    if let Ok(int) = item.as_integer() {
        return Ok(StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
            number: Number::Tvm_NumberDecimal(NumberDecimal { number: int.to_string() }),
        }));
    }
    if let Ok(slice) = item.as_slice() {
        let bytes = slice.clone().get_bytestring(0);
        return Ok(StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
            slice: slice::Slice { bytes },
        }));
    }
    if let Ok(cell) = item.as_cell() {
        let bytes = chain_block::SliceData::load_cell(cell.clone())?.get_bytestring(0);
        return Ok(StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
            slice: slice::Slice { bytes },
        }));
    }
    anyhow::bail!("unsupported sandbox stack item")
}

#[test]
fn deploy_records_initial_state() {
    let f = Fixture::new(TOS / 10);
    let data = f.data();
    assert_eq!(data.owner, f.owner.address().clone());
    assert_eq!(data.public_key, f.signing_key.verifying_key().to_bytes());
    assert!(!data.revoked);
    assert!(!data.has_attestation);
    assert_eq!(data.subject_hash, [0x11; 32]);
}

#[test]
fn valid_signature_from_the_registered_key_is_accepted() {
    let mut f = Fixture::new(TOS / 10);
    let attested_hash = [0xAA; 32];
    let hash_to_sign =
        ProofAttestationContract::attest_hash_to_sign(&f.attestation, &attested_hash).unwrap();
    let signature = f.signing_key.sign(&hash_to_sign).to_bytes();
    let outsider = f.outsider.address().clone();

    f.send_from(&outsider, ProofAttestationContract::attest(1, attested_hash, &signature).unwrap())
        .expect_success();
    let data = f.data();
    assert!(data.has_attestation);
    assert_eq!(data.attested_hash, attested_hash);
    assert!(data.attested_at > 0);
}

#[test]
fn signature_from_a_different_key_is_rejected() {
    let mut f = Fixture::new(TOS / 10);
    let attested_hash = [0xBB; 32];
    let hash_to_sign =
        ProofAttestationContract::attest_hash_to_sign(&f.attestation, &attested_hash).unwrap();
    let wrong_key = SigningKey::from_bytes(&[0x99; 32]);
    let bad_signature = wrong_key.sign(&hash_to_sign).to_bytes();
    let outsider = f.outsider.address().clone();

    f.send_from(
        &outsider,
        ProofAttestationContract::attest(1, attested_hash, &bad_signature).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_BAD_SIGNATURE);
    assert!(!f.data().has_attestation);
}

#[test]
fn tampered_hash_invalidates_an_otherwise_valid_signature() {
    let mut f = Fixture::new(TOS / 10);
    let signed_hash = [0xCC; 32];
    let hash_to_sign =
        ProofAttestationContract::attest_hash_to_sign(&f.attestation, &signed_hash).unwrap();
    let signature = f.signing_key.sign(&hash_to_sign).to_bytes();
    let tampered_hash = [0xDD; 32];
    let outsider = f.outsider.address().clone();

    // The signature is valid for `signed_hash` but is being relayed against
    // a different `attested_hash` -- CHKSIGNU must reject the mismatch.
    f.send_from(&outsider, ProofAttestationContract::attest(1, tampered_hash, &signature).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_BAD_SIGNATURE);
}

#[test]
fn attest_is_permissionless_any_sender_may_relay_a_valid_signature() {
    // Already exercised implicitly above (sent from `outsider`, not
    // `owner`), asserted explicitly here for clarity.
    let mut f = Fixture::new(TOS / 10);
    let attested_hash = [0xEE; 32];
    let hash_to_sign =
        ProofAttestationContract::attest_hash_to_sign(&f.attestation, &attested_hash).unwrap();
    let signature = f.signing_key.sign(&hash_to_sign).to_bytes();
    let outsider = f.outsider.address().clone();
    assert_ne!(outsider, f.owner.address().clone());
    f.send_from(&outsider, ProofAttestationContract::attest(1, attested_hash, &signature).unwrap())
        .expect_success();
    assert_eq!(f.data().attested_hash, attested_hash);
}

#[test]
fn owner_can_rotate_key_resetting_attestation_others_rejected() {
    let mut f = Fixture::new(TOS / 10);
    let attested_hash = [0x01; 32];
    let hash_to_sign =
        ProofAttestationContract::attest_hash_to_sign(&f.attestation, &attested_hash).unwrap();
    let signature = f.signing_key.sign(&hash_to_sign).to_bytes();
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, ProofAttestationContract::attest(1, attested_hash, &signature).unwrap())
        .expect_success();
    assert!(f.data().has_attestation);

    let new_key = SigningKey::from_bytes(&[0x55; 32]);
    f.send_from(
        &outsider,
        ProofAttestationContract::rotate_key(2, new_key.verifying_key().to_bytes()).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_NOT_OWNER);

    let owner = f.owner.address().clone();
    f.send_from(
        &owner,
        ProofAttestationContract::rotate_key(3, new_key.verifying_key().to_bytes()).unwrap(),
    )
    .expect_success();
    let data = f.data();
    assert_eq!(data.public_key, new_key.verifying_key().to_bytes());
    assert!(!data.has_attestation, "rotating the key must reset any existing attestation");

    // The old key's signature is no longer valid against the new key.
    f.send_from(&outsider, ProofAttestationContract::attest(4, attested_hash, &signature).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_BAD_SIGNATURE);

    // A fresh signature from the new key is accepted.
    let new_signature = new_key.sign(&hash_to_sign).to_bytes();
    f.send_from(
        &outsider,
        ProofAttestationContract::attest(5, attested_hash, &new_signature).unwrap(),
    )
    .expect_success();
    assert_eq!(f.data().attested_hash, attested_hash);
}

#[test]
fn owner_can_revoke_blocking_further_attestations_others_rejected() {
    let mut f = Fixture::new(TOS / 10);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, ProofAttestationContract::revoke(1).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);

    let owner = f.owner.address().clone();
    f.send_from(&owner, ProofAttestationContract::revoke(2).unwrap()).expect_success();
    assert!(f.data().revoked);

    let attested_hash = [0x02; 32];
    let hash_to_sign =
        ProofAttestationContract::attest_hash_to_sign(&f.attestation, &attested_hash).unwrap();
    let signature = f.signing_key.sign(&hash_to_sign).to_bytes();
    f.send_from(&outsider, ProofAttestationContract::attest(3, attested_hash, &signature).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_REVOKED);
}

#[test]
fn attest_signature_is_bound_to_the_attestation_address_and_rejected_across_instances() {
    // Two Proof Attestation instances sharing the same attestor key but
    // deployed against different subject_hash values -- and therefore
    // different addresses -- must not accept each other's signatures, even
    // for the exact same attested_hash.
    let mut a = Fixture::new(TOS / 10);
    let mut b = Fixture::with_subject_hash(TOS / 10, a.signing_key.clone(), [0x99; 32]);
    assert_ne!(a.attestation, b.attestation);

    let attested_hash = [0x77; 32];
    let outsider_a = a.outsider.address().clone();
    let outsider_b = b.outsider.address().clone();

    let hash_for_a =
        ProofAttestationContract::attest_hash_to_sign(&a.attestation, &attested_hash).unwrap();
    let signature_for_a = a.signing_key.sign(&hash_for_a).to_bytes();

    // Valid against instance a...
    a.send_from(
        &outsider_a,
        ProofAttestationContract::attest(1, attested_hash, &signature_for_a).unwrap(),
    )
    .expect_success();

    // ...but rejected when replayed against instance b, despite the same key
    // and the same attested_hash.
    b.send_from(
        &outsider_b,
        ProofAttestationContract::attest(1, attested_hash, &signature_for_a).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_BAD_SIGNATURE);
    assert!(!b.data().has_attestation);

    // A freshly-signed message for instance b succeeds.
    let hash_for_b =
        ProofAttestationContract::attest_hash_to_sign(&b.attestation, &attested_hash).unwrap();
    let signature_for_b = b.signing_key.sign(&hash_for_b).to_bytes();
    b.send_from(
        &outsider_b,
        ProofAttestationContract::attest(2, attested_hash, &signature_for_b).unwrap(),
    )
    .expect_success();
    assert_eq!(b.data().attested_hash, attested_hash);
}

#[test]
fn unknown_operation_is_rejected() {
    let mut f = Fixture::new(TOS / 10);
    let owner = f.owner.address().clone();
    let mut body = chain_block::BuilderData::new();
    chain_block::IBitstring::append_u32(&mut body, 0xDEAD_BEEF).unwrap();
    chain_block::IBitstring::append_u64(&mut body, 1).unwrap();
    f.send_from(&owner, body.into_cell().unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_UNKNOWN_OP);
}
