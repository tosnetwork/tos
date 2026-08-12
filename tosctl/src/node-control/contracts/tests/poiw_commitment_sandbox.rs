/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) lifecycle tests for the PoIW score-commitment
//! contract.
//!
//! These execute the compiled contract embedded in `PoiwCommitmentContract`
//! against the in-process executor: deployment and get-method inspection,
//! the bonded challenge path (insufficient bond, zero evidence, and
//! after-deadline rejections), permissionless finalization returning the
//! committer's bond, reviewer-only rulings in both directions with bond
//! flows asserted, terminal-state rejections, bounced-message immunity, and
//! trailing-garbage rejection.

use chain_block::{Cell, MsgAddressInt};
use contracts::{
    POIW_COMMITMENT_STATUS_CHALLENGED, POIW_COMMITMENT_STATUS_COMMITTED,
    POIW_COMMITMENT_STATUS_FINAL, POIW_COMMITMENT_STATUS_REJECTED, PoiwCommitmentContract,
    PoiwCommitmentInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

const TOS: u64 = 1_000_000_000;
const COMMIT_BOND: u64 = 5 * TOS;
const ERR_NOT_COMMITTED: i32 = 2100;
const ERR_WINDOW_CLOSED: i32 = 2101;
const ERR_INSUFFICIENT_BOND: i32 = 2102;
const ERR_WINDOW_OPEN: i32 = 2103;
const ERR_NOT_CHALLENGED: i32 = 2104;
const ERR_NOT_REVIEWER: i32 = 2105;
const ERR_INVALID_RULING: i32 = 2106;
const ERR_UNKNOWN_OP: i32 = 2107;
const ERR_ZERO_EVIDENCE: i32 = 2108;

struct Fixture {
    bc: Blockchain,
    committer: Treasury,
    reviewer: Treasury,
    challenger: Treasury,
    commitment: MsgAddressInt,
    window_deadline: u64,
}

impl Fixture {
    fn new() -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let committer = bc.treasury("poiw-committer", 1_000 * TOS).expect("committer");
        let reviewer = bc.treasury("poiw-reviewer", 1_000 * TOS).expect("reviewer");
        let challenger = bc.treasury("poiw-challenger", 1_000 * TOS).expect("challenger");
        let window_deadline = u64::from(bc.now()) + 3_600;
        let init = PoiwCommitmentInit {
            committer: committer.address().clone(),
            reviewer: reviewer.address().clone(),
            epoch: 27_260,
            window_deadline,
            commit_bond: COMMIT_BOND,
            score_root: [0x33; 32],
            methodology_hash: [0x44; 32],
        };
        let commitment = PoiwCommitmentContract::calculate_address(-1, &init).expect("address");
        let state_init = PoiwCommitmentContract::build_state_init(&init).expect("state init");
        // Deploy value = bond + fee/storage margin, mirroring Task Escrow's
        // budget-plus-margin funding convention.
        let deploy = MessageBuilder::internal(committer.address(), &commitment, COMMIT_BOND + TOS)
            .bounce(false)
            .state_init(state_init)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, committer, reviewer, challenger, commitment, window_deadline }
    }

    fn send_from_with_value(
        &mut self,
        from: &MsgAddressInt,
        body: Cell,
        value: u64,
    ) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(from, &self.commitment, value).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    fn send_from(&mut self, from: &MsgAddressInt, body: Cell) -> tos_sandbox::SendResult {
        self.send_from_with_value(from, body, TOS / 10)
    }

    fn balance(&self, addr: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(addr)
            .and_then(|acc| acc.balance().and_then(|cc| cc.coins.as_u64()))
            .unwrap_or(0)
    }

    fn data(&self) -> contracts::PoiwCommitmentData {
        let stack = self
            .bc
            .run_get_method(&self.commitment, "get_poiw_commitment_data", vec![])
            .expect("get_poiw_commitment_data")
            .expect_success()
            .stack
            .clone();
        let entries = stack
            .iter()
            .map(sandbox_stack_item_to_entry)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("stack conversion");
        PoiwCommitmentContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(entries))
            .expect("decode_data")
    }
}

/// Mirrors the equivalent helper in the sibling sandbox suites: converts a
/// real sandbox VM stack item into the wire `StackEntry` shape
/// `TvmStackParser` expects.
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
fn deploys_committed_and_readable() {
    let f = Fixture::new();
    let data = f.data();
    assert_eq!(data.status, POIW_COMMITMENT_STATUS_COMMITTED);
    assert_eq!(data.epoch, 27_260);
    assert_eq!(data.window_deadline, f.window_deadline);
    assert_eq!(data.commit_bond, COMMIT_BOND);
    assert_eq!(data.challenge_bond, 0);
    assert_eq!(data.score_root, [0x33; 32]);
    assert_eq!(data.methodology_hash, [0x44; 32]);
    assert_eq!(&data.committer, f.committer.address());
    assert_eq!(&data.reviewer, f.reviewer.address());
}

#[test]
fn finalize_after_window_returns_the_bond() {
    let mut f = Fixture::new();
    let committer_addr = f.committer.address().clone();

    // Before the deadline, finalize is rejected.
    f.send_from(&committer_addr, PoiwCommitmentContract::finalize(1).unwrap())
        .expect_exit_code(ERR_WINDOW_OPEN);
    assert_eq!(f.data().status, POIW_COMMITMENT_STATUS_COMMITTED);

    f.bc.set_now((f.window_deadline + 1) as u32);
    let before = f.balance(&committer_addr);
    // Permissionless: an outsider (the challenger treasury here) finalizes,
    // yet the bond goes to the committer.
    let outsider = f.challenger.address().clone();
    f.send_from(&outsider, PoiwCommitmentContract::finalize(2).unwrap()).expect_success();
    assert_eq!(f.data().status, POIW_COMMITMENT_STATUS_FINAL);
    let delta = f.balance(&committer_addr) - before;
    assert!(
        delta > COMMIT_BOND - TOS / 100 && delta <= COMMIT_BOND,
        "committer must get the bond back minus at most the forward fee, got {delta}"
    );

    // Terminal: further finalize or challenge attempts are rejected.
    f.send_from(&outsider, PoiwCommitmentContract::finalize(3).unwrap())
        .expect_exit_code(ERR_NOT_COMMITTED);
    f.send_from_with_value(
        &outsider,
        PoiwCommitmentContract::challenge(4, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_exit_code(ERR_NOT_COMMITTED);
}

#[test]
fn challenge_requires_bond_evidence_and_open_window() {
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();

    // Insufficient bond is rejected.
    f.send_from_with_value(
        &challenger_addr,
        PoiwCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        COMMIT_BOND / 2,
    )
    .expect_exit_code(ERR_INSUFFICIENT_BOND);
    assert_eq!(f.data().status, POIW_COMMITMENT_STATUS_COMMITTED);

    // Zero evidence is reserved for "no challenge" and rejected.
    f.send_from_with_value(
        &challenger_addr,
        PoiwCommitmentContract::challenge(2, [0x00; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_exit_code(ERR_ZERO_EVIDENCE);

    // A well-formed challenge is recorded with the attached value as bond.
    f.send_from_with_value(
        &challenger_addr,
        PoiwCommitmentContract::challenge(3, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_success();
    let data = f.data();
    assert_eq!(data.status, POIW_COMMITMENT_STATUS_CHALLENGED);
    assert_eq!(&data.challenger, f.challenger.address());
    assert_eq!(data.challenge_evidence_hash, [0xEE; 32]);
    assert_eq!(data.challenge_bond, COMMIT_BOND + TOS);

    // A second challenge and a finalize are both rejected now.
    f.send_from_with_value(
        &challenger_addr,
        PoiwCommitmentContract::challenge(4, [0xDD; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_exit_code(ERR_NOT_COMMITTED);
    f.bc.set_now((f.window_deadline + 1) as u32);
    f.send_from(&challenger_addr, PoiwCommitmentContract::finalize(5).unwrap())
        .expect_exit_code(ERR_NOT_COMMITTED);
}

#[test]
fn challenge_after_the_deadline_is_rejected() {
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();
    f.bc.set_now((f.window_deadline + 1) as u32);
    f.send_from_with_value(
        &challenger_addr,
        PoiwCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_exit_code(ERR_WINDOW_CLOSED);
}

#[test]
fn upheld_challenge_rejects_the_root_and_pays_the_challenger() {
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();
    let reviewer_addr = f.reviewer.address().clone();
    f.send_from_with_value(
        &challenger_addr,
        PoiwCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_success();

    // Only the reviewer may rule; a malformed ruling value is rejected.
    f.send_from(&challenger_addr, PoiwCommitmentContract::rule(2, true).unwrap())
        .expect_exit_code(ERR_NOT_REVIEWER);
    {
        // uphold outside {0, 1}: craft the body manually.
        use chain_block::IBitstring;
        let mut body = chain_block::BuilderData::new();
        body.append_u32(contracts::poiw_commitment::PWC_RULE_OPCODE).unwrap();
        body.append_u64(3).unwrap();
        body.append_u8(7).unwrap();
        f.send_from(&reviewer_addr, body.into_cell().unwrap()).expect_exit_code(ERR_INVALID_RULING);
    }

    let before = f.balance(&challenger_addr);
    f.send_from(&reviewer_addr, PoiwCommitmentContract::rule(4, true).unwrap()).expect_success();
    assert_eq!(f.data().status, POIW_COMMITMENT_STATUS_REJECTED);
    let expected = 2 * COMMIT_BOND + TOS;
    let delta = f.balance(&challenger_addr) - before;
    assert!(
        delta > expected - TOS / 100 && delta <= expected,
        "challenger must receive both bonds minus at most the forward fee, got {delta}"
    );

    // Terminal: ruling again is rejected.
    f.send_from(&reviewer_addr, PoiwCommitmentContract::rule(5, true).unwrap())
        .expect_exit_code(ERR_NOT_CHALLENGED);
}

#[test]
fn dismissed_challenge_finalizes_and_pays_the_committer() {
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();
    let reviewer_addr = f.reviewer.address().clone();
    let committer_addr = f.committer.address().clone();
    f.send_from_with_value(
        &challenger_addr,
        PoiwCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_success();

    let before = f.balance(&committer_addr);
    f.send_from(&reviewer_addr, PoiwCommitmentContract::rule(2, false).unwrap()).expect_success();
    assert_eq!(f.data().status, POIW_COMMITMENT_STATUS_FINAL);
    let expected = 2 * COMMIT_BOND + TOS;
    let delta = f.balance(&committer_addr) - before;
    assert!(
        delta > expected - TOS / 100 && delta <= expected,
        "committer must receive both bonds minus at most the forward fee, got {delta}"
    );

    // Ruling before any challenge on a fresh instance is rejected.
    let mut fresh = Fixture::new();
    let fresh_reviewer = fresh.reviewer.address().clone();
    fresh
        .send_from(&fresh_reviewer, PoiwCommitmentContract::rule(1, true).unwrap())
        .expect_exit_code(ERR_NOT_CHALLENGED);
}

#[test]
fn unknown_ops_trailing_garbage_and_bounces_are_handled() {
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();

    // Unknown opcode throws.
    {
        use chain_block::IBitstring;
        let mut body = chain_block::BuilderData::new();
        body.append_u32(0x5057_43FF).unwrap();
        body.append_u64(1).unwrap();
        f.send_from(&challenger_addr, body.into_cell().unwrap()).expect_exit_code(ERR_UNKNOWN_OP);
    }

    // Trailing garbage after an otherwise well-formed challenge is rejected.
    {
        use chain_block::IBitstring;
        let mut body = chain_block::BuilderData::new();
        body.append_u32(contracts::poiw_commitment::PWC_CHALLENGE_OPCODE).unwrap();
        body.append_u64(2).unwrap();
        body.append_u256(&[0xEE; 32]).unwrap();
        body.append_u8(0xAB).unwrap();
        f.send_from_with_value(&challenger_addr, body.into_cell().unwrap(), COMMIT_BOND + TOS)
            .expect_aborted();
        assert_eq!(f.data().status, POIW_COMMITMENT_STATUS_COMMITTED);
    }

    // A bounced message carrying an otherwise-valid reviewer ruling is
    // silently ignored with state untouched.
    {
        let mut msg = MessageBuilder::internal(f.reviewer.address(), &f.commitment, TOS / 10)
            .body(PoiwCommitmentContract::rule(3, true).unwrap())
            .build();
        msg.int_header_mut().expect("internal header").bounced = true;
        f.bc.send_message(msg).expect("send bounced").expect_success();
        assert_eq!(f.data().status, POIW_COMMITMENT_STATUS_COMMITTED);
    }
}
