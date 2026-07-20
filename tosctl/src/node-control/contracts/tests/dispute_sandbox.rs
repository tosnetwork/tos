/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) lifecycle tests for the Dispute contract.
//!
//! These execute the compiled contract embedded in `DisputeContract` against
//! the in-process executor: deployment and get-method inspection,
//! respondent-only evidence submission, reviewer-only rulings (claimant,
//! respondent, and split outcomes), invalid-ruling/invalid-split-bps
//! rejections, and the already-resolved rejection -- plus the unauthorized
//! sender rejections for each.

use chain_block::{Cell, MsgAddressInt};
use contracts::{
    DisputeContract, DisputeInit, DISPUTE_STATUS_EVIDENCE_SUBMITTED, DISPUTE_STATUS_OPEN,
    DISPUTE_STATUS_RESOLVED, RULING_CLAIMANT, RULING_RESPONDENT, RULING_SPLIT,
};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

const TOS: u64 = 1_000_000_000;
const ERR_NOT_RESPONDENT: i32 = 2000;
const ERR_NOT_REVIEWER: i32 = 2001;
const ERR_ALREADY_RESOLVED: i32 = 2002;
const ERR_INVALID_RULING: i32 = 2003;
const ERR_INVALID_SPLIT_BPS: i32 = 2004;
const ERR_UNKNOWN_OP: i32 = 2005;
const ERR_BAD_RULING_SIGNATURE: i32 = 2006;

struct Fixture {
    bc: Blockchain,
    claimant: Treasury,
    respondent: Treasury,
    reviewer: Treasury,
    outsider: Treasury,
    dispute: MsgAddressInt,
}

impl Fixture {
    fn new(funding: u64) -> Self {
        Self::build(funding, None)
    }

    fn with_attestor(funding: u64, attestor_pubkey: [u8; 32]) -> Self {
        Self::build(funding, Some(attestor_pubkey))
    }

    fn build(funding: u64, attestor_pubkey: Option<[u8; 32]>) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let claimant = bc.treasury("claimant", 1_000 * TOS).expect("claimant");
        let respondent = bc.treasury("respondent", 1_000 * TOS).expect("respondent");
        let reviewer = bc.treasury("reviewer", 1_000 * TOS).expect("reviewer");
        let outsider = bc.treasury("outsider", 1_000 * TOS).expect("outsider");
        let init = DisputeInit {
            claimant: claimant.address().clone(),
            respondent: respondent.address().clone(),
            reviewer: reviewer.address().clone(),
            deadline: 1_800_000_000,
            subject_hash: [0x11; 32],
            claimant_evidence_hash: [0x22; 32],
            attestor_pubkey,
        };
        let dispute = DisputeContract::calculate_address(-1, &init).expect("address");
        let state_init = DisputeContract::build_state_init(&init).expect("state init");
        let deploy = MessageBuilder::internal(claimant.address(), &dispute, funding)
            .bounce(false)
            .state_init(state_init)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, claimant, respondent, reviewer, outsider, dispute }
    }

    fn send_from(&mut self, from: &MsgAddressInt, body: Cell) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(from, &self.dispute, TOS / 10).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    fn data(&self) -> contracts::DisputeData {
        let stack = self
            .bc
            .run_get_method(&self.dispute, "get_dispute_data", vec![])
            .expect("get_dispute_data")
            .expect_success()
            .stack
            .clone();
        let entries = stack
            .iter()
            .map(sandbox_stack_item_to_entry)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("stack conversion");
        DisputeContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(entries))
            .expect("decode_data")
    }
}

/// Mirrors the equivalent helper in `capability_registry_sandbox.rs` /
/// `service_actor_sandbox.rs`: converts a real sandbox VM stack item into
/// the wire `StackEntry` shape `TvmStackParser` expects.
fn sandbox_stack_item_to_entry(
    item: &tos_vm::stack::StackItem,
) -> anyhow::Result<tl_api::tos::tvm::StackEntry> {
    use tl_api::tos::tvm::{
        Number, StackEntry, numberdecimal::NumberDecimal, slice,
        stackentry::{StackEntryNumber, StackEntrySlice},
    };
    if let Ok(int) = item.as_integer() {
        return Ok(StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
            number: Number::Tvm_NumberDecimal(NumberDecimal { number: int.to_string() }),
        }));
    }
    if let Ok(slice) = item.as_slice() {
        let bytes = slice.clone().get_bytestring(0);
        return Ok(StackEntry::Tvm_StackEntrySlice(StackEntrySlice { slice: slice::Slice { bytes } }));
    }
    if let Ok(cell) = item.as_cell() {
        let bytes = chain_block::SliceData::load_cell(cell.clone())?.get_bytestring(0);
        return Ok(StackEntry::Tvm_StackEntrySlice(StackEntrySlice { slice: slice::Slice { bytes } }));
    }
    anyhow::bail!("unsupported sandbox stack item")
}

#[test]
fn deploy_records_initial_state() {
    let f = Fixture::new(TOS / 10);
    let data = f.data();
    assert_eq!(data.claimant, f.claimant.address().clone());
    assert_eq!(data.respondent, f.respondent.address().clone());
    assert_eq!(data.reviewer, f.reviewer.address().clone());
    assert_eq!(data.status, DISPUTE_STATUS_OPEN);
    assert_eq!(data.ruling, 0);
    assert_eq!(data.split_bps, 0);
    assert_eq!(data.deadline, 1_800_000_000);
    assert_eq!(data.subject_hash, [0x11; 32]);
    assert_eq!(data.claimant_evidence_hash, [0x22; 32]);
}

#[test]
fn respondent_can_submit_evidence_others_rejected() {
    let mut f = Fixture::new(TOS / 10);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, DisputeContract::submit_respondent_evidence(1, [0xAA; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_RESPONDENT);

    let respondent = f.respondent.address().clone();
    f.send_from(&respondent, DisputeContract::submit_respondent_evidence(2, [0xAA; 32]).unwrap())
        .expect_success();
    let data = f.data();
    assert_eq!(data.status, DISPUTE_STATUS_EVIDENCE_SUBMITTED);
    assert_eq!(data.respondent_evidence_hash, [0xAA; 32]);
}

#[test]
fn reviewer_can_rule_for_claimant_others_rejected() {
    let mut f = Fixture::new(TOS / 10);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, DisputeContract::rule(1, RULING_CLAIMANT, 0, [0xBB; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_REVIEWER);

    let reviewer = f.reviewer.address().clone();
    f.send_from(&reviewer, DisputeContract::rule(2, RULING_CLAIMANT, 0, [0xBB; 32]).unwrap())
        .expect_success();
    let data = f.data();
    assert_eq!(data.status, DISPUTE_STATUS_RESOLVED);
    assert_eq!(data.ruling, RULING_CLAIMANT);
    assert_eq!(data.ruling_hash, [0xBB; 32]);
}

#[test]
fn reviewer_can_rule_without_respondent_evidence() {
    // A reviewer may rule based on the claimant's evidence alone if the
    // respondent never shows up -- submit_respondent_evidence is optional.
    let mut f = Fixture::new(TOS / 10);
    let reviewer = f.reviewer.address().clone();
    f.send_from(&reviewer, DisputeContract::rule(1, RULING_RESPONDENT, 0, [0xCC; 32]).unwrap())
        .expect_success();
    assert_eq!(f.data().ruling, RULING_RESPONDENT);
}

#[test]
fn split_ruling_records_basis_points_and_validates_range() {
    let mut f = Fixture::new(TOS / 10);
    let reviewer = f.reviewer.address().clone();

    // A split ruling requires a valid 0..=10000 bps value.
    f.send_from(&reviewer, DisputeContract::rule(1, RULING_SPLIT, 10_001, [0xDD; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_INVALID_SPLIT_BPS);
    assert_eq!(f.data().status, DISPUTE_STATUS_OPEN);

    f.send_from(&reviewer, DisputeContract::rule(2, RULING_SPLIT, 6_500, [0xDD; 32]).unwrap())
        .expect_success();
    let data = f.data();
    assert_eq!(data.ruling, RULING_SPLIT);
    assert_eq!(data.split_bps, 6_500);
}

#[test]
fn invalid_ruling_value_is_rejected() {
    let mut f = Fixture::new(TOS / 10);
    let reviewer = f.reviewer.address().clone();
    f.send_from(&reviewer, DisputeContract::rule(1, 99, 0, [0xEE; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_INVALID_RULING);
}

#[test]
fn already_resolved_dispute_rejects_further_actions() {
    let mut f = Fixture::new(TOS / 10);
    let reviewer = f.reviewer.address().clone();
    let respondent = f.respondent.address().clone();
    f.send_from(&reviewer, DisputeContract::rule(1, RULING_CLAIMANT, 0, [0xFF; 32]).unwrap())
        .expect_success();

    f.send_from(&respondent, DisputeContract::submit_respondent_evidence(2, [0x01; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_ALREADY_RESOLVED);
    f.send_from(&reviewer, DisputeContract::rule(3, RULING_RESPONDENT, 0, [0x02; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_ALREADY_RESOLVED);
}

#[test]
fn unknown_operation_is_rejected() {
    let mut f = Fixture::new(TOS / 10);
    let claimant = f.claimant.address().clone();
    let mut body = chain_block::BuilderData::new();
    chain_block::IBitstring::append_u32(&mut body, 0xDEAD_BEEF).unwrap();
    chain_block::IBitstring::append_u64(&mut body, 1).unwrap();
    f.send_from(&claimant, body.into_cell().unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_UNKNOWN_OP);
}

#[test]
fn rule_on_an_attestor_configured_dispute_requires_a_valid_signature() {
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let ruling_hash = [0xBB; 32];
    let mut f = Fixture::with_attestor(TOS / 10, attestor_pubkey);
    let reviewer = f.reviewer.address().clone();

    // Plain `rule` (no signature) is rejected by the trailing signature load.
    f.send_from(&reviewer, DisputeContract::rule(1, RULING_CLAIMANT, 0, ruling_hash).unwrap())
        .expect_aborted();
    assert_eq!(f.data().status, DISPUTE_STATUS_OPEN);

    // A signature from the wrong key is rejected.
    let wrong_key = SigningKey::from_bytes(&[0x88; 32]);
    let wrong_signature: [u8; 64] = wrong_key.sign(&ruling_hash).to_bytes();
    f.send_from(
        &reviewer,
        DisputeContract::rule_signed(2, RULING_CLAIMANT, 0, ruling_hash, &wrong_signature)
            .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_BAD_RULING_SIGNATURE);
    assert_eq!(f.data().status, DISPUTE_STATUS_OPEN);

    // A non-reviewer sender is still rejected, even with a valid signature.
    let outsider = f.outsider.address().clone();
    let valid_signature: [u8; 64] = attestor.sign(&ruling_hash).to_bytes();
    f.send_from(
        &outsider,
        DisputeContract::rule_signed(3, RULING_CLAIMANT, 0, ruling_hash, &valid_signature)
            .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_NOT_REVIEWER);
    assert_eq!(f.data().status, DISPUTE_STATUS_OPEN);

    // The reviewer, with the correct attestor signature, resolves the dispute.
    f.send_from(
        &reviewer,
        DisputeContract::rule_signed(4, RULING_CLAIMANT, 0, ruling_hash, &valid_signature)
            .unwrap(),
    )
    .expect_success();
    let data = f.data();
    assert_eq!(data.status, DISPUTE_STATUS_RESOLVED);
    assert_eq!(data.ruling, RULING_CLAIMANT);
    assert_eq!(data.ruling_hash, ruling_hash);
}
