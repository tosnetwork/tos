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

mod weak_ed25519;

const TOS: u64 = 1_000_000_000;
const ERR_REVOKED: i32 = 2100;
const ERR_BAD_SIGNATURE: i32 = 2101;
const ERR_NOT_OWNER: i32 = 2102;
const ERR_UNKNOWN_OP: i32 = 2103;
const ERR_STALE_SEQUENCE: i32 = 2105;

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
        let public_key = signing_key.verifying_key().to_bytes();
        Self::with_public_key(funding, signing_key, public_key, subject_hash)
    }

    /// Deploys with `public_key` as stored, whatever `signing_key` is: how a
    /// hand-built StateInit would carry a key the contract never admitted.
    fn with_public_key(
        funding: u64,
        signing_key: SigningKey,
        public_key: [u8; 32],
        subject_hash: [u8; 32],
    ) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let owner = bc.treasury("owner", 1_000 * TOS).expect("owner");
        let outsider = bc.treasury("outsider", 1_000 * TOS).expect("outsider");
        let init =
            ProofAttestationInit { owner: owner.address().clone(), public_key, subject_hash };
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

    /// An `attest` body claiming `sequence` over `attested_hash`, signed by
    /// `key` the way the CLI signs: over the domain-bound hash that carries
    /// this contract's address, its current key epoch and the sequence.
    fn attest_body(
        &self,
        key: &SigningKey,
        query_id: u64,
        sequence: u64,
        attested_hash: [u8; 32],
    ) -> Cell {
        self.attest_body_in_epoch(key, query_id, self.data().key_epoch, sequence, attested_hash)
    }

    /// Like [`Fixture::attest_body`], signed for an explicit key epoch.
    fn attest_body_in_epoch(
        &self,
        key: &SigningKey,
        query_id: u64,
        key_epoch: u32,
        sequence: u64,
        attested_hash: [u8; 32],
    ) -> Cell {
        let hash_to_sign = ProofAttestationContract::attest_hash_to_sign(
            sandbox_global_id(&self.bc),
            &self.attestation,
            key_epoch,
            sequence,
            &attested_hash,
        )
        .unwrap();
        let signature = key.sign(&hash_to_sign).to_bytes();
        ProofAttestationContract::attest(query_id, sequence, attested_hash, &signature).unwrap()
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
    assert_eq!(data.sequence, 0);
    assert_eq!(data.key_epoch, 0);
    assert_eq!(data.subject_hash, [0x11; 32]);
}

#[test]
fn valid_signature_from_the_registered_key_is_accepted() {
    let mut f = Fixture::new(TOS / 10);
    let attested_hash = [0xAA; 32];
    let body = f.attest_body(&f.signing_key, 1, 1, attested_hash);
    let outsider = f.outsider.address().clone();

    f.send_from(&outsider, body).expect_success();
    let data = f.data();
    assert!(data.has_attestation);
    assert_eq!(data.attested_hash, attested_hash);
    assert!(data.attested_at > 0);
    assert_eq!(data.sequence, 1);
}

#[test]
fn signature_from_a_different_key_is_rejected() {
    let mut f = Fixture::new(TOS / 10);
    let wrong_key = SigningKey::from_bytes(&[0x99; 32]);
    let body = f.attest_body(&wrong_key, 1, 1, [0xBB; 32]);
    let outsider = f.outsider.address().clone();

    f.send_from(&outsider, body).expect_aborted().expect_exit_code(ERR_BAD_SIGNATURE);
    assert!(!f.data().has_attestation);
}

#[test]
fn tampered_hash_or_sequence_invalidates_an_otherwise_valid_signature() {
    let mut f = Fixture::new(TOS / 10);
    let signed_hash = [0xCC; 32];
    let hash_to_sign = ProofAttestationContract::attest_hash_to_sign(
        sandbox_global_id(&f.bc),
        &f.attestation,
        0,
        1,
        &signed_hash,
    )
    .unwrap();
    let signature = f.signing_key.sign(&hash_to_sign).to_bytes();
    let outsider = f.outsider.address().clone();

    // The signature is valid for `signed_hash` at sequence 1 but is relayed
    // against a different `attested_hash` -- CHKSIGNU must reject the mismatch.
    let tampered_hash = [0xDD; 32];
    f.send_from(
        &outsider,
        ProofAttestationContract::attest(1, 1, tampered_hash, &signature).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_BAD_SIGNATURE);
    // The sequence is under the signature too: the same signature relayed
    // with a higher sequence passes the sequence check and fails the key.
    f.send_from(
        &outsider,
        ProofAttestationContract::attest(2, 2, signed_hash, &signature).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_BAD_SIGNATURE);
    assert!(!f.data().has_attestation);
}

#[test]
fn attest_is_permissionless_any_sender_may_relay_a_valid_signature() {
    // Already exercised implicitly above (sent from `outsider`, not
    // `owner`), asserted explicitly here for clarity.
    let mut f = Fixture::new(TOS / 10);
    let attested_hash = [0xEE; 32];
    let body = f.attest_body(&f.signing_key, 1, 1, attested_hash);
    let outsider = f.outsider.address().clone();
    assert_ne!(outsider, f.owner.address().clone());
    f.send_from(&outsider, body).expect_success();
    assert_eq!(f.data().attested_hash, attested_hash);
}

/// A recorded attestation message is public. Without the sequence anyone could
/// relay it again after the signer moved on and reinstate the superseded hash;
/// the contract admits only a sequence above the one it recorded.
#[test]
fn a_recorded_attestation_cannot_be_relayed_again_once_superseded() {
    let mut f = Fixture::new(TOS / 10);
    let outsider = f.outsider.address().clone();
    let first = f.attest_body(&f.signing_key, 1, 1, [0xA1; 32]);
    f.send_from(&outsider, first.clone()).expect_success();
    assert_eq!(f.data().sequence, 1);

    // The same message again: refused before the signature is even checked.
    f.send_from(&outsider, first.clone()).expect_aborted().expect_exit_code(ERR_STALE_SEQUENCE);

    // The signer may skip values; only the order matters.
    let third = f.attest_body(&f.signing_key, 2, 5, [0xA5; 32]);
    f.send_from(&outsider, third).expect_success();
    let data = f.data();
    assert_eq!((data.sequence, data.attested_hash), (5, [0xA5; 32]));

    // Anything at or below the recorded sequence is stale, however well signed.
    let stale = f.attest_body(&f.signing_key, 3, 3, [0xA3; 32]);
    f.send_from(&outsider, stale).expect_aborted().expect_exit_code(ERR_STALE_SEQUENCE);
    let same = f.attest_body(&f.signing_key, 4, 5, [0xA6; 32]);
    f.send_from(&outsider, same).expect_aborted().expect_exit_code(ERR_STALE_SEQUENCE);
    f.send_from(&outsider, first).expect_aborted().expect_exit_code(ERR_STALE_SEQUENCE);
    let data = f.data();
    assert_eq!(
        (data.sequence, data.attested_hash),
        (5, [0xA5; 32]),
        "a stale message changed state"
    );
}

#[test]
fn owner_can_rotate_key_resetting_attestation_others_rejected() {
    let mut f = Fixture::new(TOS / 10);
    let attested_hash = [0x01; 32];
    let first = f.attest_body(&f.signing_key, 1, 1, attested_hash);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, first.clone()).expect_success();
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
    assert_eq!((data.key_epoch, data.sequence), (1, 0), "a rotation starts a fresh epoch");

    // The message the old key signed stays out: it was signed in epoch 0.
    f.send_from(&outsider, first).expect_aborted().expect_exit_code(ERR_BAD_SIGNATURE);
    // A fresh message from the old key fails on the key itself.
    let from_old_key = f.attest_body(&f.signing_key, 4, 1, attested_hash);
    f.send_from(&outsider, from_old_key).expect_aborted().expect_exit_code(ERR_BAD_SIGNATURE);

    // A fresh signature from the new key is accepted, at sequence 1 of epoch 1.
    let from_new_key = f.attest_body(&new_key, 5, 1, attested_hash);
    f.send_from(&outsider, from_new_key).expect_success();
    let data = f.data();
    assert_eq!((data.attested_hash, data.key_epoch, data.sequence), (attested_hash, 1, 1));
}

/// A leaked key is what rotation exists for, so nothing the leaked key can do
/// may outlive the rotation: driving the sequence to its limit is undone by the
/// new epoch, and the messages it signed stay out even if the owner rotates
/// back to the very same key.
#[test]
fn rotation_undoes_everything_a_leaked_key_did_including_key_reuse() {
    let mut f = Fixture::new(TOS / 10);
    let outsider = f.outsider.address().clone();
    let owner = f.owner.address().clone();
    let leaked = f.signing_key.clone();

    // The leaked key spends the whole counter.
    let exhausting = f.attest_body(&leaked, 1, u64::MAX, [0xBA; 32]);
    f.send_from(&outsider, exhausting.clone()).expect_success();
    let dead = f.attest_body(&leaked, 2, u64::MAX, [0xBB; 32]);
    f.send_from(&outsider, dead).expect_aborted().expect_exit_code(ERR_STALE_SEQUENCE);

    // Rotation to a clean key recovers the instance.
    let clean = SigningKey::from_bytes(&[0x77; 32]);
    f.send_from(
        &owner,
        ProofAttestationContract::rotate_key(3, clean.verifying_key().to_bytes()).unwrap(),
    )
    .expect_success();
    assert_eq!((f.data().key_epoch, f.data().sequence), (1, 0));
    let recovered = f.attest_body(&clean, 4, 1, [0xC1; 32]);
    f.send_from(&outsider, recovered).expect_success();
    assert_eq!((f.data().attested_hash, f.data().sequence), ([0xC1; 32], 1));

    // Rotating back to the leaked key reuses the key, not the epoch: the
    // message that exhausted epoch 0 cannot be relayed into epoch 2, and the
    // counter starts over.
    f.send_from(
        &owner,
        ProofAttestationContract::rotate_key(5, leaked.verifying_key().to_bytes()).unwrap(),
    )
    .expect_success();
    assert_eq!((f.data().key_epoch, f.data().sequence), (2, 0));
    f.send_from(&outsider, exhausting).expect_aborted().expect_exit_code(ERR_BAD_SIGNATURE);
    let signed_for_epoch_0 = f.attest_body_in_epoch(&leaked, 6, 0, 1, [0xC2; 32]);
    f.send_from(&outsider, signed_for_epoch_0).expect_aborted().expect_exit_code(ERR_BAD_SIGNATURE);
    let signed_for_epoch_2 = f.attest_body(&leaked, 7, 1, [0xC2; 32]);
    f.send_from(&outsider, signed_for_epoch_2).expect_success();
    assert_eq!((f.data().attested_hash, f.data().key_epoch, f.data().sequence), ([0xC2; 32], 2, 1));
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

    let body = f.attest_body(&f.signing_key, 3, 1, [0x02; 32]);
    f.send_from(&outsider, body).expect_aborted().expect_exit_code(ERR_REVOKED);
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

    // Valid against instance a...
    let for_a = a.attest_body(&a.signing_key, 1, 1, attested_hash);
    a.send_from(&outsider_a, for_a.clone()).expect_success();

    // ...but rejected when replayed against instance b, despite the same key,
    // the same attested_hash and a sequence b would otherwise admit.
    b.send_from(&outsider_b, for_a).expect_aborted().expect_exit_code(ERR_BAD_SIGNATURE);
    assert!(!b.data().has_attestation);

    // A freshly-signed message for instance b succeeds.
    let for_b = b.attest_body(&b.signing_key, 2, 1, attested_hash);
    b.send_from(&outsider_b, for_b).expect_success();
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

/// The network the sandbox runs, as GLOBALID reads it from ConfigParam 19.
fn sandbox_global_id(bc: &Blockchain) -> i32 {
    match bc.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        other => panic!("parameter 19 is not the global id: {other:?}"),
    }
}

const ERR_WEAK_KEY: i32 = 2104;

/// An attestor key anyone could sign for is refused when the owner rotates to
/// it, and refused at attestation when it arrived in a hand-built StateInit.
#[test]
fn weak_attestor_keys_are_refused_when_set_and_when_used() {
    let mut f = Fixture::new(TOS / 10);
    let owner = f.owner.address().clone();
    let before = f.data().public_key;
    for weak in weak_ed25519::weak_keys() {
        f.send_from(&owner, ProofAttestationContract::rotate_key(1, weak).unwrap())
            .expect_aborted()
            .expect_exit_code(ERR_WEAK_KEY);
    }
    assert_eq!(f.data().public_key, before, "a refused key must not be stored");

    let weak = weak_ed25519::weak_keys()[0];
    let mut f =
        Fixture::with_public_key(TOS / 10, SigningKey::from_bytes(&[0x42; 32]), weak, [0x11; 32]);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, ProofAttestationContract::attest(1, 1, [0xAB; 32], &[0u8; 64]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_WEAK_KEY);
    assert!(!f.data().has_attestation);
}

/// An attestation signed for another network does not attest here.
#[test]
fn an_attestation_signed_for_another_network_is_refused() {
    let mut f = Fixture::new(TOS / 10);
    let outsider = f.outsider.address().clone();
    let attested_hash = [0xAB; 32];
    let here = sandbox_global_id(&f.bc);
    let elsewhere = ProofAttestationContract::attest_hash_to_sign(
        here.wrapping_add(1),
        &f.attestation,
        0,
        1,
        &attested_hash,
    )
    .unwrap();
    let signature = f.signing_key.sign(&elsewhere).to_bytes();
    f.send_from(
        &outsider,
        ProofAttestationContract::attest(1, 1, attested_hash, &signature).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_BAD_SIGNATURE);
    let this_network = f.attest_body(&f.signing_key, 2, 1, attested_hash);
    f.send_from(&outsider, this_network).expect_success();
    assert!(f.data().has_attestation);
}
