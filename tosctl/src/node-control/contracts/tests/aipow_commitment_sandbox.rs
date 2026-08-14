/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) lifecycle tests for the AIPoW score-commitment
//! contract.
//!
//! These execute the compiled contract embedded in `AipowCommitmentContract`
//! against the in-process executor: deployment and get-method inspection,
//! the bonded challenge path (insufficient bond, zero evidence, conflicted
//! challenger, excess refund, and after-deadline rejections), permissionless
//! finalization returning the committer's bond, reviewer-only rulings in both
//! directions with bond flows asserted, the permissionless review-timeout
//! fail-safe returning each party its own bond, terminal-state rejections,
//! bounced-message immunity, and trailing-garbage rejection.

use chain_block::{Cell, MsgAddressInt};
use contracts::{
    AIPOW_COMMITMENT_STATUS_CHALLENGED, AIPOW_COMMITMENT_STATUS_COMMITTED,
    AIPOW_COMMITMENT_STATUS_FINAL, AIPOW_COMMITMENT_STATUS_REJECTED, AipowCommitmentContract,
    AipowCommitmentInit, AipowDistributorContract, AipowMaturation, AipowSettlementContract,
    AipowSettlementInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

const TOS: u64 = 1_000_000_000;
const COMMIT_BOND: u64 = 5 * TOS;
/// Mirrors the contract's MIN_TON_STORAGE: the floor the commitment always keeps back
/// so it can pay storage rent and never freeze (a frozen FINAL commitment is unreadable
/// to the native mint and its reward would be lost).
const MIN_TON_STORAGE: u64 = 50_000_000; // 0.05 TOS
const COMMIT_EPOCH: u64 = 27_260;
const TOTAL_SCORE: u128 = 1_000_000;
const ORGANIC_VALUE: u128 = 42 * TOS as u128;
const SCORE_ROOT: [u8; 32] = [0x33; 32];
/// The settlement's cursor: at or below the commitment epoch so its announce
/// registration is accepted (register requires epoch >= cursor).
const SETTLEMENT_NEXT_EPOCH: u32 = COMMIT_EPOCH as u32;
const ERR_NOT_COMMITTED: i32 = 2100;
const ERR_WINDOW_CLOSED: i32 = 2101;
const ERR_INSUFFICIENT_BOND: i32 = 2102;
const ERR_WINDOW_OPEN: i32 = 2103;
const ERR_NOT_CHALLENGED: i32 = 2104;
const ERR_NOT_REVIEWER: i32 = 2105;
const ERR_INVALID_RULING: i32 = 2106;
const ERR_UNKNOWN_OP: i32 = 2107;
const ERR_ZERO_EVIDENCE: i32 = 2108;
const ERR_CONFLICTED_CHALLENGER: i32 = 2109;
const ERR_REVIEW_OPEN: i32 = 2110;
const ERR_REVIEW_CLOSED: i32 = 2111;
const ERR_BOND_NOT_ESCROWED: i32 = 2112;
// Mirrors `review_window` in the contract (7 days).
const REVIEW_WINDOW: u64 = 604_800;

struct Fixture {
    bc: Blockchain,
    committer: Treasury,
    reviewer: Treasury,
    challenger: Treasury,
    commitment: MsgAddressInt,
    settlement: MsgAddressInt,
    window_deadline: u64,
}

/// Deploy a real AIPoW settlement (the announce registration target) so the
/// full announce -> register -> settlement chain runs against a live account.
fn deploy_settlement(bc: &mut Blockchain, deployer: &MsgAddressInt) -> MsgAddressInt {
    let init = AipowSettlementInit {
        next_epoch: SETTLEMENT_NEXT_EPOCH,
        epoch_seconds: 65_536,
        register_grace: 3_600,
        challenge_window: 900,
        earner_workchain: -1,
        maturation: AipowMaturation::methodology_v0(),
        total_cap: 4_500_000_000 * TOS,
        distributor_code: AipowDistributorContract::code().unwrap(),
        // The commitment code the announcing commitments in this suite run, so the
        // settlement can authenticate their register (H1).
        commitment_code: AipowCommitmentContract::code().unwrap(),
    };
    let addr = AipowSettlementContract::calculate_address(-1, &init).unwrap();
    let deploy = MessageBuilder::internal(deployer, &addr, 2 * TOS)
        .bounce(false)
        .state_init(AipowSettlementContract::build_state_init(&init).unwrap())
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("settlement deploy").expect_success();
    addr
}

impl Fixture {
    fn new() -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let committer = bc.treasury("aipow-committer", 1_000 * TOS).expect("committer");
        let reviewer = bc.treasury("aipow-reviewer", 1_000 * TOS).expect("reviewer");
        let challenger = bc.treasury("aipow-challenger", 1_000 * TOS).expect("challenger");
        let settlement = deploy_settlement(&mut bc, committer.address());
        let window_deadline = u64::from(bc.now()) + 3_600;
        let init = AipowCommitmentInit {
            committer: committer.address().clone(),
            reviewer: reviewer.address().clone(),
            epoch: COMMIT_EPOCH,
            window_deadline,
            commit_bond: COMMIT_BOND,
            score_root: SCORE_ROOT,
            methodology_hash: [0x44; 32],
            rate_card_hash: [0x66; 32],
            total_score: TOTAL_SCORE,
            organic_settled_value: ORGANIC_VALUE,
            settlement: Some(settlement.clone()),
        };
        let commitment = AipowCommitmentContract::calculate_address(-1, &init).expect("address");
        let state_init = AipowCommitmentContract::build_state_init(&init).expect("state init");
        // Deploy value = bond + fee/storage margin, mirroring Task Escrow's
        // budget-plus-margin funding convention.
        let deploy = MessageBuilder::internal(committer.address(), &commitment, COMMIT_BOND + TOS)
            .bounce(false)
            .state_init(state_init)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, committer, reviewer, challenger, commitment, settlement, window_deadline }
    }

    /// The candidate the settlement recorded FOR THIS COMMITMENT at `epoch`, if
    /// the commitment finalized and advertised it (the commitment's own account
    /// id is the candidate key).
    fn settlement_candidate(&self, epoch: u32) -> Option<contracts::AipowCandidate> {
        let id: [u8; 32] =
            self.commitment.address().get_bytestring(0).try_into().expect("32-byte account id");
        let arg = vec![
            tos_vm::stack::StackItem::int(epoch as i64),
            tos_vm::stack::StackItem::int(
                tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(id),
            ),
        ];
        let stack = self
            .bc
            .run_get_method(&self.settlement, "get_candidate", arg)
            .expect("get_candidate")
            .expect_success()
            .stack
            .clone();
        let entries = stack
            .iter()
            .map(sandbox_stack_item_to_entry)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("stack conversion");
        AipowSettlementContract::decode_candidate(&common::tvm_stack_parser::TvmStackParser::new(
            entries,
        ))
        .expect("decode_candidate")
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
        // Half a TOS covers masterchain gas comfortably, including the extra work
        // when announce emits the settlement registration.
        self.send_from_with_value(from, body, TOS / 2)
    }

    fn balance(&self, addr: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(addr)
            .and_then(|acc| acc.balance().and_then(|cc| cc.coins.as_u64()))
            .unwrap_or(0)
    }

    fn data(&self) -> contracts::AipowCommitmentData {
        let stack = self
            .bc
            .run_get_method(&self.commitment, "get_aipow_commitment_data", vec![])
            .expect("get_aipow_commitment_data")
            .expect_success()
            .stack
            .clone();
        let entries = stack
            .iter()
            .map(sandbox_stack_item_to_entry)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("stack conversion");
        AipowCommitmentContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(
            entries,
        ))
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
fn announce_requires_the_commit_bond_to_be_escrowed() {
    // The challenge mechanism assumes commit_bond is actually held by the commitment
    // through the window: finalize, rule and timeout all pay it out. Nothing verified the
    // deploy funded it, so an underfunded committer could pass the window with no stake at
    // risk (finalizing by briefly attaching the bond), while challenging such a commitment
    // would lock the challenger's bond in an insolvent contract. announce is the mandatory
    // gate before a commitment can register (hence be minted), so it now refuses unless the
    // bond is funded here, then reserves it.
    let mut bc = Blockchain::new().unwrap();
    bc.set_workchain(-1);
    let committer = bc.treasury("aipow-underfunded-committer", 1_000 * TOS).unwrap();
    let reviewer = bc.treasury("aipow-underfunded-reviewer", 1_000 * TOS).unwrap();
    let settlement = deploy_settlement(&mut bc, committer.address());
    let init = AipowCommitmentInit {
        committer: committer.address().clone(),
        reviewer: reviewer.address().clone(),
        epoch: COMMIT_EPOCH,
        window_deadline: u64::from(bc.now()) + 3_600,
        commit_bond: COMMIT_BOND,
        score_root: SCORE_ROOT,
        methodology_hash: [0x44; 32],
        rate_card_hash: [0x66; 32],
        total_score: TOTAL_SCORE,
        organic_settled_value: ORGANIC_VALUE,
        settlement: Some(settlement.clone()),
    };
    let commitment = AipowCommitmentContract::calculate_address(-1, &init).unwrap();
    // Deploy UNDERFUNDED: far below commit_bond, so the bond was never staked.
    let deploy = MessageBuilder::internal(committer.address(), &commitment, 2 * TOS)
        .bounce(false)
        .state_init(AipowCommitmentContract::build_state_init(&init).unwrap())
        .body(Cell::default())
        .build();
    bc.send_message(deploy).unwrap().expect_success();

    let mut announce = |bc: &mut Blockchain, value: u64| {
        let msg = MessageBuilder::internal(committer.address(), &commitment, value)
            .body(AipowCommitmentContract::announce(1).unwrap())
            .build();
        bc.send_message(msg).unwrap()
    };
    // Balance stays below commit_bond + registration_value: announce is refused.
    announce(&mut bc, TOS / 2).expect_exit_code(ERR_BOND_NOT_ESCROWED);

    // Funding the instance to cover the bond (here via the announce value itself) lets it
    // through and escrows the bond, so the balance now covers commit_bond.
    announce(&mut bc, 5 * TOS).expect_success();
    let bal = bc
        .get_account(&commitment)
        .and_then(|a| a.balance())
        .and_then(|c| c.coins.as_u64())
        .unwrap_or(0);
    assert!(bal >= COMMIT_BOND, "the commit bond is escrowed after a funded announce (balance {bal})");
}

#[test]
fn deploys_committed_and_readable() {
    let f = Fixture::new();
    let data = f.data();
    assert_eq!(data.status, AIPOW_COMMITMENT_STATUS_COMMITTED);
    assert_eq!(data.epoch, 27_260);
    assert_eq!(data.window_deadline, f.window_deadline);
    assert_eq!(data.review_deadline, 0);
    assert_eq!(data.commit_bond, COMMIT_BOND);
    assert_eq!(data.challenge_bond, 0);
    assert_eq!(data.score_root, [0x33; 32]);
    assert_eq!(data.methodology_hash, [0x44; 32]);
    // The committer binds the full economic tuple, not just the root.
    assert_eq!(data.total_score, TOTAL_SCORE);
    assert_eq!(data.organic_settled_value, ORGANIC_VALUE);
    assert_eq!(&data.committer, f.committer.address());
    assert_eq!(&data.reviewer, f.reviewer.address());
    assert_eq!(data.version, contracts::AIPOW_COMMITMENT_VERSION);
    assert_eq!(data.settlement, Some(f.settlement.clone()));
    // Nothing is advertised to the settlement while merely committed.
    assert_eq!(f.settlement_candidate(COMMIT_EPOCH as u32), None);
}

#[test]
fn permissionless_announce_registers_the_committed_tuple_with_the_settlement() {
    let mut f = Fixture::new();
    let outsider = f.challenger.address().clone();
    // Announce is sent while still committed (early), so the settlement records
    // registered_at with its own clock -- the anchor the native window runs from.
    f.send_from(&outsider, AipowCommitmentContract::announce(1).unwrap()).expect_success();
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_COMMITTED);

    // The announce emitted an authenticated register to the settlement: the
    // settlement recorded the commitment address as the nomination source and
    // the committed economic tuple.
    let reg = f.settlement_candidate(COMMIT_EPOCH as u32).expect("registered on announce");
    assert_eq!(reg.score_root, SCORE_ROOT);
    assert_eq!(reg.total_score, TOTAL_SCORE);
    assert_eq!(reg.organic_settled_value, ORGANIC_VALUE);

    // Finalize is now local: it flips the status to final and does NOT emit a
    // second registration (the nomination already exists from the announce).
    f.bc.set_now((f.window_deadline + 1) as u32);
    f.send_from(&outsider, AipowCommitmentContract::finalize(2).unwrap()).expect_success();
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_FINAL);
    let reg2 =
        f.settlement_candidate(COMMIT_EPOCH as u32).expect("still registered after finalize");
    assert_eq!(reg2.total_score, TOTAL_SCORE);
}

#[test]
fn announce_registers_early_and_a_dismissed_challenge_returns_to_committed() {
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();
    let reviewer_addr = f.reviewer.address().clone();
    // The nomination is recorded at announce, while committed and before any
    // dispute -- the candidate exists throughout the challenge lifecycle.
    f.send_from(&challenger_addr, AipowCommitmentContract::announce(1).unwrap()).expect_success();
    let reg = f.settlement_candidate(COMMIT_EPOCH as u32).expect("registered on announce");
    assert_eq!(reg.total_score, TOTAL_SCORE);

    f.send_from_with_value(
        &challenger_addr,
        AipowCommitmentContract::challenge(2, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_success();
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_CHALLENGED);
    // H3: dismissing a frivolous challenge does NOT finalize -- it returns to
    // committed so the root stays challengeable for the rest of its window (a
    // dismissed challenge must not close the provenance window early).
    f.send_from(&reviewer_addr, AipowCommitmentContract::rule(3, false).unwrap()).expect_success();
    let data = f.data();
    assert_eq!(data.status, AIPOW_COMMITMENT_STATUS_COMMITTED);
    assert_eq!(data.challenge_bond, 0, "review fields reset on dismissal");
    assert_eq!(data.review_deadline, 0);
    // Still challengeable after the dismissal (genuine challengers are not locked out).
    f.send_from_with_value(
        &challenger_addr,
        AipowCommitmentContract::challenge(4, [0xAB; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_success();
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_CHALLENGED, "re-challengeable");
    assert!(f.settlement_candidate(COMMIT_EPOCH as u32).is_some(), "candidate still present");
}

#[test]
fn a_reviewer_ruling_after_the_review_deadline_is_rejected() {
    // M5: after the review deadline only the permissionless timeout (which rejects,
    // failing safe) may resolve a challenge; a late reviewer ruling is rejected so it
    // cannot finalize a root that should have timed out.
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();
    let reviewer_addr = f.reviewer.address().clone();
    f.send_from_with_value(
        &challenger_addr,
        AipowCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_success();
    let review_deadline = f.data().review_deadline;
    f.bc.set_now((review_deadline + 1) as u32);
    f.send_from(&reviewer_addr, AipowCommitmentContract::rule(2, false).unwrap())
        .expect_exit_code(ERR_REVIEW_CLOSED);
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_CHALLENGED, "still challenged");
    // The permissionless timeout now resolves it by rejection.
    f.send_from(&challenger_addr, AipowCommitmentContract::timeout(3).unwrap()).expect_success();
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_REJECTED);
}

#[test]
fn a_root_rejected_before_announcing_can_never_register() {
    // A commitment that is rejected before it announces can never nominate
    // itself: announce requires status == committed. (An already-announced root
    // that is later rejected still leaves its candidate in the settlement, but
    // the native derivation filters it out by its live `rejected` status -- that
    // filtering is covered in the C++ derive tests.)
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();
    let reviewer_addr = f.reviewer.address().clone();
    f.send_from_with_value(
        &challenger_addr,
        AipowCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_success();
    f.send_from(&reviewer_addr, AipowCommitmentContract::rule(2, true).unwrap()).expect_success();
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_REJECTED);
    // Announcing a rejected root is rejected (not_committed), so it never registers.
    f.send_from(&challenger_addr, AipowCommitmentContract::announce(3).unwrap())
        .expect_exit_code(ERR_NOT_COMMITTED);
    assert_eq!(f.settlement_candidate(COMMIT_EPOCH as u32), None, "rejected root not advertised");
}

#[test]
fn finalize_after_window_returns_the_bond() {
    let mut f = Fixture::new();
    let committer_addr = f.committer.address().clone();

    // Before the deadline, finalize is rejected.
    f.send_from(&committer_addr, AipowCommitmentContract::finalize(1).unwrap())
        .expect_exit_code(ERR_WINDOW_OPEN);
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_COMMITTED);

    f.bc.set_now((f.window_deadline + 1) as u32);
    let before = f.balance(&committer_addr);
    // Permissionless: an outsider (the challenger treasury here) finalizes,
    // yet the bond goes to the committer.
    let outsider = f.challenger.address().clone();
    f.send_from(&outsider, AipowCommitmentContract::finalize(2).unwrap()).expect_success();
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_FINAL);
    let delta = f.balance(&committer_addr) - before;
    assert!(
        delta > COMMIT_BOND - TOS / 100 && delta <= COMMIT_BOND,
        "committer must get the bond back minus at most the forward fee, got {delta}"
    );
    // Returning the full bond must NOT run the commitment out of storage rent: it keeps
    // its floor and stays active, so the native mint can still read its `final` status
    // when the cursor reaches its epoch. (raw_reserve(MIN_TON_STORAGE, 2) before the send.)
    let kept = f.balance(&f.commitment);
    assert!(
        kept >= MIN_TON_STORAGE,
        "a finalized commitment must retain its storage floor and stay active, got {kept}"
    );

    // Terminal: further finalize or challenge attempts are rejected.
    f.send_from(&outsider, AipowCommitmentContract::finalize(3).unwrap())
        .expect_exit_code(ERR_NOT_COMMITTED);
    f.send_from_with_value(
        &outsider,
        AipowCommitmentContract::challenge(4, [0xEE; 32]).unwrap(),
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
        AipowCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        COMMIT_BOND / 2,
    )
    .expect_exit_code(ERR_INSUFFICIENT_BOND);
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_COMMITTED);

    // Zero evidence is reserved for "no challenge" and rejected.
    f.send_from_with_value(
        &challenger_addr,
        AipowCommitmentContract::challenge(2, [0x00; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_exit_code(ERR_ZERO_EVIDENCE);

    // A well-formed challenge is recorded. The bond is fixed at the commit
    // bond (the overpaid excess is refunded -- asserted in isolation by
    // `challenge_refunds_the_overpaid_excess`), and the review deadline is set.
    f.send_from_with_value(
        &challenger_addr,
        AipowCommitmentContract::challenge(3, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_success();
    let data = f.data();
    assert_eq!(data.status, AIPOW_COMMITMENT_STATUS_CHALLENGED);
    assert_eq!(&data.challenger, f.challenger.address());
    assert_eq!(data.challenge_evidence_hash, [0xEE; 32]);
    assert_eq!(data.challenge_bond, COMMIT_BOND);
    assert_eq!(data.review_deadline, u64::from(f.bc.now()) + REVIEW_WINDOW);

    // A second challenge and a finalize are both rejected now.
    f.send_from_with_value(
        &challenger_addr,
        AipowCommitmentContract::challenge(4, [0xDD; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_exit_code(ERR_NOT_COMMITTED);
    f.bc.set_now((f.window_deadline + 1) as u32);
    f.send_from(&challenger_addr, AipowCommitmentContract::finalize(5).unwrap())
        .expect_exit_code(ERR_NOT_COMMITTED);
}

#[test]
fn challenge_after_the_deadline_is_rejected() {
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();
    f.bc.set_now((f.window_deadline + 1) as u32);
    f.send_from_with_value(
        &challenger_addr,
        AipowCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
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
        AipowCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_success();

    // Only the reviewer may rule; a malformed ruling value is rejected.
    f.send_from(&challenger_addr, AipowCommitmentContract::rule(2, true).unwrap())
        .expect_exit_code(ERR_NOT_REVIEWER);
    {
        // uphold outside {0, 1}: craft the body manually.
        use chain_block::IBitstring;
        let mut body = chain_block::BuilderData::new();
        body.append_u32(contracts::aipow_commitment::APW_RULE_OPCODE).unwrap();
        body.append_u64(3).unwrap();
        body.append_u8(7).unwrap();
        f.send_from(&reviewer_addr, body.into_cell().unwrap()).expect_exit_code(ERR_INVALID_RULING);
    }

    let before = f.balance(&challenger_addr);
    f.send_from(&reviewer_addr, AipowCommitmentContract::rule(4, true).unwrap()).expect_success();
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_REJECTED);
    // Both bonds are the fixed commit bond, so an upheld challenge pays 2x.
    let expected = 2 * COMMIT_BOND;
    let delta = f.balance(&challenger_addr) - before;
    assert!(
        delta > expected - TOS / 100 && delta <= expected,
        "challenger must receive both bonds minus at most the forward fee, got {delta}"
    );

    // Terminal: ruling again is rejected.
    f.send_from(&reviewer_addr, AipowCommitmentContract::rule(5, true).unwrap())
        .expect_exit_code(ERR_NOT_CHALLENGED);
}

#[test]
fn dismissed_challenge_returns_to_committed_and_pays_the_committer_the_challenge_bond() {
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();
    let reviewer_addr = f.reviewer.address().clone();
    let committer_addr = f.committer.address().clone();
    f.send_from_with_value(
        &challenger_addr,
        AipowCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_success();

    let before = f.balance(&committer_addr);
    f.send_from(&reviewer_addr, AipowCommitmentContract::rule(2, false).unwrap()).expect_success();
    // H3: dismissal returns to committed (not final); the committer is compensated
    // with the frivolous challenger's bond only, and its own commit_bond stays locked
    // until finalize (so it pays 1x, not 2x).
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_COMMITTED);
    let expected = COMMIT_BOND;
    let delta = f.balance(&committer_addr) - before;
    assert!(
        delta > expected - TOS / 100 && delta <= expected,
        "committer must receive the challenger's bond (1x) minus at most the forward fee, got {delta}"
    );

    // Ruling before any challenge on a fresh instance is rejected.
    let mut fresh = Fixture::new();
    let fresh_reviewer = fresh.reviewer.address().clone();
    fresh
        .send_from(&fresh_reviewer, AipowCommitmentContract::rule(1, true).unwrap())
        .expect_exit_code(ERR_NOT_CHALLENGED);
}

#[test]
fn challenge_refunds_the_overpaid_excess() {
    // Sandbox treasuries are faucets (a sender is not debited for value it
    // sends), so the refund is measured from the contract side: on a 3x
    // overpayment the contract must retain only the fixed commit bond and send
    // the excess straight back, so its balance grows by ~COMMIT_BOND, not 3x.
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();
    let commitment_addr = f.commitment.clone();
    let before = f.balance(&commitment_addr);
    f.send_from_with_value(
        &challenger_addr,
        AipowCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        3 * COMMIT_BOND,
    )
    .expect_success();
    assert_eq!(f.data().challenge_bond, COMMIT_BOND);
    let retained = f.balance(&commitment_addr) - before;
    assert!(
        retained > COMMIT_BOND - TOS && retained < 2 * COMMIT_BOND,
        "only the fixed bond is retained; the 2x overpayment is refunded, retained {retained}"
    );
}

#[test]
fn committer_and_reviewer_cannot_challenge() {
    let mut f = Fixture::new();
    let committer_addr = f.committer.address().clone();
    let reviewer_addr = f.reviewer.address().clone();

    // A conflicted challenger could route the committer's bond to itself via
    // the ruling, so both the committer and the reviewer are barred.
    f.send_from_with_value(
        &committer_addr,
        AipowCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_exit_code(ERR_CONFLICTED_CHALLENGER);
    f.send_from_with_value(
        &reviewer_addr,
        AipowCommitmentContract::challenge(2, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_exit_code(ERR_CONFLICTED_CHALLENGER);
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_COMMITTED);
}

#[test]
fn review_timeout_fails_safe_and_returns_each_bond() {
    let mut f = Fixture::new();
    let challenger_addr = f.challenger.address().clone();
    let committer_addr = f.committer.address().clone();
    f.send_from_with_value(
        &challenger_addr,
        AipowCommitmentContract::challenge(1, [0xEE; 32]).unwrap(),
        COMMIT_BOND + TOS,
    )
    .expect_success();
    let review_deadline = f.data().review_deadline;

    // Before the review deadline the timeout is rejected: the reviewer still
    // owns the decision.
    f.send_from(&challenger_addr, AipowCommitmentContract::timeout(2).unwrap())
        .expect_exit_code(ERR_REVIEW_OPEN);
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_CHALLENGED);

    // Past it, anyone may fail it safe: the root is rejected and each party
    // recovers its own bond (the fixed commit bond).
    f.bc.set_now((review_deadline + 1) as u32);
    let committer_before = f.balance(&committer_addr);
    let challenger_before = f.balance(&challenger_addr);
    // Permissionless: an outsider (committer here) may trigger it.
    f.send_from(&committer_addr, AipowCommitmentContract::timeout(3).unwrap()).expect_success();
    assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_REJECTED);
    let committer_delta = f.balance(&committer_addr) - committer_before;
    let challenger_delta = f.balance(&challenger_addr) - challenger_before;
    assert!(
        committer_delta > COMMIT_BOND - TOS && committer_delta <= COMMIT_BOND,
        "committer recovers its own bond, got {committer_delta}"
    );
    assert!(
        challenger_delta > COMMIT_BOND - TOS / 20 && challenger_delta <= COMMIT_BOND,
        "challenger recovers its own bond, got {challenger_delta}"
    );

    // Terminal: a second timeout is rejected.
    f.send_from(&challenger_addr, AipowCommitmentContract::timeout(4).unwrap())
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
        body.append_u32(0x4150_57FF).unwrap();
        body.append_u64(1).unwrap();
        f.send_from(&challenger_addr, body.into_cell().unwrap()).expect_exit_code(ERR_UNKNOWN_OP);
    }

    // Trailing garbage after an otherwise well-formed challenge is rejected.
    {
        use chain_block::IBitstring;
        let mut body = chain_block::BuilderData::new();
        body.append_u32(contracts::aipow_commitment::APW_CHALLENGE_OPCODE).unwrap();
        body.append_u64(2).unwrap();
        body.append_u256(&[0xEE; 32]).unwrap();
        body.append_u8(0xAB).unwrap();
        f.send_from_with_value(&challenger_addr, body.into_cell().unwrap(), COMMIT_BOND + TOS)
            .expect_aborted();
        assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_COMMITTED);
    }

    // A bounced message carrying an otherwise-valid reviewer ruling is
    // silently ignored with state untouched.
    {
        let mut msg = MessageBuilder::internal(f.reviewer.address(), &f.commitment, TOS / 10)
            .body(AipowCommitmentContract::rule(3, true).unwrap())
            .build();
        msg.int_header_mut().expect("internal header").bounced = true;
        f.bc.send_message(msg).expect("send bounced").expect_success();
        assert_eq!(f.data().status, AIPOW_COMMITMENT_STATUS_COMMITTED);
    }
}

#[test]
fn finalize_with_no_settlement_still_finalizes_and_returns_the_bond() {
    // A commitment deployed with addr_none settlement (registration disabled):
    // announce is a harmless no-op (the structurally-impossible registration is
    // skipped on-chain) and finalize still finalizes and returns the bond.
    let mut bc = Blockchain::new().expect("blockchain");
    bc.set_workchain(-1);
    let committer = bc.treasury("aipow-committer-ns", 1_000 * TOS).expect("committer");
    let reviewer = bc.treasury("aipow-reviewer-ns", 1_000 * TOS).expect("reviewer");
    let window_deadline = u64::from(bc.now()) + 3_600;
    let init = AipowCommitmentInit {
        committer: committer.address().clone(),
        reviewer: reviewer.address().clone(),
        epoch: COMMIT_EPOCH,
        window_deadline,
        commit_bond: COMMIT_BOND,
        score_root: SCORE_ROOT,
        methodology_hash: [0x44; 32],
        rate_card_hash: [0x66; 32],
        total_score: TOTAL_SCORE,
        organic_settled_value: ORGANIC_VALUE,
        settlement: None,
    };
    let commitment = AipowCommitmentContract::calculate_address(-1, &init).unwrap();
    let deploy = MessageBuilder::internal(committer.address(), &commitment, COMMIT_BOND + TOS)
        .bounce(false)
        .state_init(AipowCommitmentContract::build_state_init(&init).unwrap())
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();

    // Announce with registration disabled: a harmless no-op, still committed.
    let announce = MessageBuilder::internal(reviewer.address(), &commitment, TOS / 2)
        .body(AipowCommitmentContract::announce(9).unwrap())
        .build();
    bc.send_message(announce).expect("announce").expect_success();

    let read_status = |bc: &Blockchain| -> u8 {
        let stack = bc
            .run_get_method(&commitment, "get_aipow_commitment_data", vec![])
            .unwrap()
            .expect_success()
            .stack
            .clone();
        let entries = stack
            .iter()
            .map(sandbox_stack_item_to_entry)
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        AipowCommitmentContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(
            entries,
        ))
        .unwrap()
        .status
    };

    bc.set_now((window_deadline + 1) as u32);
    let before = bc
        .get_account(committer.address())
        .and_then(|a| a.balance().and_then(|c| c.coins.as_u64()))
        .unwrap_or(0);
    let finalize = MessageBuilder::internal(reviewer.address(), &commitment, TOS / 2)
        .body(AipowCommitmentContract::finalize(1).unwrap())
        .build();
    bc.send_message(finalize).expect("finalize").expect_success();
    assert_eq!(read_status(&bc), AIPOW_COMMITMENT_STATUS_FINAL);
    let after = bc
        .get_account(committer.address())
        .and_then(|a| a.balance().and_then(|c| c.coins.as_u64()))
        .unwrap_or(0);
    let delta = after - before;
    assert!(
        delta > COMMIT_BOND - TOS / 100 && delta <= COMMIT_BOND,
        "committer still gets the bond back with registration disabled, got {delta}"
    );
    // decode_data round-trips addr_none as None.
    let stack = bc
        .run_get_method(&commitment, "get_aipow_commitment_data", vec![])
        .unwrap()
        .expect_success()
        .stack
        .clone();
    let entries =
        stack.iter().map(sandbox_stack_item_to_entry).collect::<anyhow::Result<Vec<_>>>().unwrap();
    let data = AipowCommitmentContract::decode_data(
        &common::tvm_stack_parser::TvmStackParser::new(entries),
    )
    .unwrap();
    assert_eq!(data.settlement, None);
}
