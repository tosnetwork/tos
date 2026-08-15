/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) tests for the AIPoW reward distributor (W4.3:
//! custody + payout).
//!
//! The load-bearing check remains the on-chain root recomputation: the
//! compiled contract recomputes epoch score roots with `string_hash`
//! (SHA256U) over methodology-v0 leaf/node preimages, and that must equal
//! the Rust `aipow_merkle` root byte for byte, or a valid beneficiary's
//! inclusion proof would be rejected. On top of that, W4.3 makes the
//! distributor hold the epoch pool and pay matured reward to each identity's
//! own address: a claim records the pro-rata amount once and pays the
//! immediate tranche; permissionless `payout` pokes stream the rest as it
//! matures; a forfeit freezes maturation and never sends the voided
//! remainder. These tests deploy a funded distributor, claim every member,
//! assert the on-chain payments actually credit the identity addresses, walk
//! the payout stream, and cover the rejection paths (wrong score, tampered
//! proof, double claim, zero/understated denominator, zero score, underfunded
//! poke, malformed proof, unknown op, payout of an unclaimed identity).

use chain_block::{Cell, MsgAddressInt};
use contracts::aipow_merkle::{ProofStep, ScoreEntry, inclusion_proof, score_root};
use contracts::{AipowDistributorContract, AipowDistributorInit, AipowMaturation};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

const TOS: u64 = 1_000_000_000;
const POOL: u64 = 10 * TOS;
/// The instance is funded with the pool plus a gas/fee reserve so its payouts
/// (mode 1, exact amount) draw from a balance that covers the whole cohort.
const DEPLOY_VALUE: u64 = POOL + 3 * TOS;
/// The scored identities are paid on this workchain. The test keeps them on the
/// masterchain the distributor lives on (same-chain delivery) and exercises the
/// signed `store_int(-1, 8)` = 0xFF workchain encoding.
const EARNER_WC: i8 = -1;

const ERR_INVALID_TOTAL_SCORE: i32 = 2200;
const ERR_ALREADY_CLAIMED: i32 = 2201;
const ERR_BAD_PROOF: i32 = 2202;
const ERR_UNKNOWN_OP: i32 = 2204;
const ERR_NOT_CLAIMED: i32 = 2206;
const ERR_SCORE_EXCEEDS_TOTAL: i32 = 2208;
const ERR_ZERO_SCORE: i32 = 2209;
const ERR_INSUFFICIENT_VALUE: i32 = 2210;
const ERR_MALFORMED_PROOF: i32 = 2211;
const ERR_NOTHING_TO_PAY: i32 = 2212;
const ERR_NOT_ACTIVATED: i32 = 2213;

struct Fixture {
    bc: Blockchain,
    caller: Treasury,
    operator: Treasury,
    distributor: MsgAddressInt,
}

fn entries() -> Vec<ScoreEntry> {
    // Five members with distinct scores summing to a round total; an odd
    // count exercises the odd-node promotion path in the tree.
    vec![
        ScoreEntry { identity: [0x11; 32], score: 100_000 },
        ScoreEntry { identity: [0x22; 32], score: 200_000 },
        ScoreEntry { identity: [0x33; 32], score: 300_000 },
        ScoreEntry { identity: [0x44; 32], score: 150_000 },
        ScoreEntry { identity: [0x55; 32], score: 250_000 },
    ]
}

const TOTAL_SCORE: u128 = 1_000_000;

/// The immediate tranche the contract pays at claim time for a recorded
/// `amount`, matching `compute_matured` at claim time (25% floored).
fn immediate(amount: u64) -> u64 {
    (u128::from(amount) * u128::from(AipowMaturation::methodology_v0().immediate_bps) / 10_000)
        as u64
}

/// The address an identity is paid at: `addr_std(EARNER_WC, identity)`.
fn earner_addr(identity: [u8; 32]) -> MsgAddressInt {
    MsgAddressInt::with_standart(None, EARNER_WC, identity.into()).unwrap()
}

impl Fixture {
    fn new(total_score: u128, root: [u8; 32]) -> Self {
        Self::new_with(total_score, root, AipowMaturation::methodology_v0(), DEPLOY_VALUE)
    }

    fn new_with(
        total_score: u128,
        root: [u8; 32],
        maturation: AipowMaturation,
        deploy_value: u64,
    ) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let operator = bc.treasury("aipow-dist-operator", 1_000 * TOS).expect("operator");
        let caller = bc.treasury("aipow-dist-caller", 1_000 * TOS).expect("caller");
        let init = AipowDistributorInit {
            operator: operator.address().clone(),
            epoch: 27_260,
            earner_workchain: EARNER_WC,
            total_score,
            pool: POOL,
            maturation,
            score_root: root,
            commitment_ref: [0x99; 32],
        };
        let distributor = AipowDistributorContract::calculate_address(-1, &init).expect("address");
        let deploy = MessageBuilder::internal(operator.address(), &distributor, deploy_value)
            .bounce(false)
            .state_init(AipowDistributorContract::build_state_init(&init).expect("state init"))
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, caller, operator, distributor }
    }

    fn send(&mut self, body: Cell) -> tos_sandbox::SendResult {
        self.send_with_value(body, TOS / 2)
    }

    fn send_with_value(&mut self, body: Cell, value: u64) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(self.caller.address(), &self.distributor, value)
            .body(body)
            .build();
        self.bc.send_message(msg).expect("send")
    }

    fn send_from(&mut self, from: &MsgAddressInt, body: Cell) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(from, &self.distributor, TOS / 2).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    /// The coin balance credited to an arbitrary address (0 if it has no
    /// account yet). Used to prove a payout actually moved funds.
    fn balance_of(&self, addr: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(addr)
            .and_then(|a| a.balance())
            .and_then(|c| c.coins.as_u64())
            .unwrap_or(0)
    }

    fn earner_balance(&self, identity: [u8; 32]) -> u64 {
        self.balance_of(&earner_addr(identity))
    }

    fn identity_arg(identity: [u8; 32]) -> tos_vm::stack::StackItem {
        tos_vm::stack::StackItem::int(tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(
            identity,
        ))
    }

    fn parse_stack(stack: &[tos_vm::stack::StackItem]) -> common::tvm_stack_parser::TvmStackParser {
        let entries = stack
            .iter()
            .map(sandbox_stack_item_to_entry)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("stack conversion");
        common::tvm_stack_parser::TvmStackParser::new(entries)
    }

    fn claim(&self, identity: [u8; 32]) -> Option<contracts::AipowClaim> {
        let stack = self
            .bc
            .run_get_method(&self.distributor, "get_claim", vec![Self::identity_arg(identity)])
            .expect("get_claim")
            .expect_success()
            .stack
            .clone();
        AipowDistributorContract::decode_claim(&Self::parse_stack(&stack)).expect("decode_claim")
    }

    fn claim_amount(&self, identity: [u8; 32]) -> Option<u64> {
        self.claim(identity).map(|c| c.amount)
    }

    fn matured(&self, identity: [u8; 32], at_time: u64) -> Option<u64> {
        let arg = vec![Self::identity_arg(identity), tos_vm::stack::StackItem::int(at_time as i64)];
        let stack = self
            .bc
            .run_get_method(&self.distributor, "get_matured", arg)
            .expect("get_matured")
            .expect_success()
            .stack
            .clone();
        AipowDistributorContract::decode_matured(&Self::parse_stack(&stack))
            .expect("decode_matured")
    }

    fn matured_now(&self, identity: [u8; 32]) -> Option<u64> {
        let stack = self
            .bc
            .run_get_method(
                &self.distributor,
                "get_matured_now",
                vec![Self::identity_arg(identity)],
            )
            .expect("get_matured_now")
            .expect_success()
            .stack
            .clone();
        AipowDistributorContract::decode_matured(&Self::parse_stack(&stack))
            .expect("decode_matured")
    }

    fn now(&self) -> u64 {
        u64::from(self.bc.now())
    }

    fn data(&self) -> contracts::AipowDistributorData {
        let stack = self
            .bc
            .run_get_method(&self.distributor, "get_aipow_distributor_data", vec![])
            .expect("get_data")
            .expect_success()
            .stack
            .clone();
        AipowDistributorContract::decode_data(&Self::parse_stack(&stack)).expect("decode_data")
    }

    fn claimed_count(&self) -> u32 {
        self.data().claimed_count
    }
}

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
fn deploys_with_the_snapshot_layout_readable() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let f = Fixture::new(TOTAL_SCORE, root);
    let data = f.data();
    assert_eq!(data.version, contracts::AIPOW_DISTRIBUTOR_VERSION);
    assert_eq!(data.epoch, 27_260);
    assert_eq!(data.earner_workchain, EARNER_WC);
    assert_eq!(data.total_score, TOTAL_SCORE);
    assert_eq!(data.pool, POOL);
    assert_eq!(data.claimed_count, 0);
    assert_eq!(data.maturation, AipowMaturation::methodology_v0());
    assert_eq!(data.score_root, root);
    assert_eq!(data.commitment_ref, [0x99; 32]);
}

#[test]
fn every_member_claims_its_pro_rata_share_and_is_paid_the_immediate_tranche() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);

    for (index, entry) in members.iter().enumerate() {
        assert_eq!(f.claim_amount(entry.identity), None, "unclaimed before claim");
        assert_eq!(f.earner_balance(entry.identity), 0, "unpaid before claim");
        let proof = inclusion_proof(&members, &entry.identity).unwrap();
        let body =
            AipowDistributorContract::claim(index as u64, entry.identity, entry.score, &proof)
                .unwrap();
        // The claim emits exactly one payment (the immediate tranche).
        f.send(body).expect_success().expect_out_msgs(1);

        // The recorded amount is the flooring pro-rata share of the pool, and
        // its immediate tranche was paid to the identity's own address.
        let expected = (u128::from(POOL) * entry.score / TOTAL_SCORE) as u64;
        assert_eq!(
            f.claim_amount(entry.identity),
            Some(expected),
            "member {index} pro-rata amount"
        );
        let paid = f.claim(entry.identity).unwrap().paid;
        assert_eq!(paid, immediate(expected), "member {index} immediate paid recorded");
        assert_eq!(
            f.earner_balance(entry.identity),
            immediate(expected),
            "member {index} received the immediate tranche"
        );
    }
    assert_eq!(f.claimed_count(), members.len() as u32);
    // Every member claimed, so the running claimed_score equals the full
    // denominator -- the cumulative cap is satisfied with no slack left.
    assert_eq!(f.data().claimed_score, TOTAL_SCORE);
    // The five flooring shares sum to at most the pool; dust is unallocated.
    let total: u64 =
        members.iter().map(|e| (u128::from(POOL) * e.score / TOTAL_SCORE) as u64).sum();
    assert!(total <= POOL);
}

#[test]
fn claim_pays_the_immediate_tranche_and_payout_streams_the_rest() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);
    let e = u64::from(AipowMaturation::methodology_v0().epoch_seconds);

    let entry = &members[2]; // identity 0x33, score 300_000 -> 3 TOS share
    let id = entry.identity;
    let proof = inclusion_proof(&members, &id).unwrap();
    f.send(AipowDistributorContract::claim(0, id, entry.score, &proof).unwrap()).expect_success();
    let amount = f.claim(id).unwrap().amount;
    let claimed_at = f.claim(id).unwrap().claimed_at;

    // Claim paid the immediate 25% and recorded it as paid.
    assert_eq!(f.claim(id).unwrap().paid, immediate(amount));
    assert_eq!(f.earner_balance(id), immediate(amount));

    // Right after the claim nothing more has matured: a payout poke is rejected.
    f.send(AipowDistributorContract::payout(1, id).unwrap()).expect_exit_code(ERR_NOTHING_TO_PAY);

    // Advance four epochs and poke: the newly-matured delta is paid and paid
    // advances to the four-epoch matured value.
    f.bc.set_now((claimed_at + 4 * e) as u32);
    let matured_4 = f.matured_now(id).unwrap();
    f.send(AipowDistributorContract::payout(2, id).unwrap()).expect_success().expect_out_msgs(1);
    assert_eq!(f.claim(id).unwrap().paid, matured_4);
    assert_eq!(f.earner_balance(id), matured_4);

    // A second poke at the same time has nothing new to pay.
    f.send(AipowDistributorContract::payout(3, id).unwrap()).expect_exit_code(ERR_NOTHING_TO_PAY);

    // Past full maturation the identity has received the whole amount.
    f.bc.set_now((claimed_at + 8 * e) as u32);
    f.send(AipowDistributorContract::payout(4, id).unwrap()).expect_success().expect_out_msgs(1);
    assert_eq!(f.claim(id).unwrap().paid, amount);
    assert_eq!(f.earner_balance(id), amount);

    // Fully paid: another poke is rejected.
    f.send(AipowDistributorContract::payout(5, id).unwrap()).expect_exit_code(ERR_NOTHING_TO_PAY);
}

#[test]
fn payout_on_an_unclaimed_identity_is_rejected() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);
    f.send(AipowDistributorContract::payout(0, [0x11; 32]).unwrap())
        .expect_exit_code(ERR_NOT_CLAIMED);
    assert_eq!(f.earner_balance([0x11; 32]), 0);
}

#[test]
fn an_underfunded_payout_is_rejected() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);
    let entry = &members[0];
    let proof = inclusion_proof(&members, &entry.identity).unwrap();
    f.send(AipowDistributorContract::claim(0, entry.identity, entry.score, &proof).unwrap())
        .expect_success();
    // A permissionless payout poke must also fund its own gas.
    f.send_with_value(
        AipowDistributorContract::payout(1, entry.identity).unwrap(),
        contracts::AIPOW_MIN_CLAIM_VALUE - 1,
    )
    .expect_exit_code(ERR_INSUFFICIENT_VALUE);
}

#[test]
fn single_member_tree_claims_with_an_empty_proof() {
    let only = vec![ScoreEntry { identity: [0x77; 32], score: 500_000 }];
    let root = score_root(&only).unwrap();
    let mut f = Fixture::new(500_000, root);
    // Single member: leaf == root, so the proof is empty.
    let proof: Vec<ProofStep> = inclusion_proof(&only, &[0x77; 32]).unwrap();
    assert!(proof.is_empty());
    let body = AipowDistributorContract::claim(0, [0x77; 32], 500_000, &proof).unwrap();
    f.send(body).expect_success();
    assert_eq!(f.claim_amount([0x77; 32]), Some(POOL)); // full pool: sole member
    assert_eq!(f.earner_balance([0x77; 32]), immediate(POOL));
}

#[test]
fn a_wrong_score_is_rejected_by_the_on_chain_root_check() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);
    let proof = inclusion_proof(&members, &[0x22; 32]).unwrap();
    // Claim member 0x22 with an inflated score: the leaf differs, so the
    // recomputed root no longer matches and the contract rejects it.
    let body = AipowDistributorContract::claim(0, [0x22; 32], 999_999, &proof).unwrap();
    f.send(body).expect_exit_code(ERR_BAD_PROOF);
    assert_eq!(f.claim_amount([0x22; 32]), None);
    assert_eq!(f.claimed_count(), 0);
}

#[test]
fn a_tampered_proof_is_rejected() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);
    let mut proof = inclusion_proof(&members, &[0x33; 32]).unwrap();
    proof[0].sibling[0] ^= 0xFF;
    let body = AipowDistributorContract::claim(0, [0x33; 32], 300_000, &proof).unwrap();
    f.send(body).expect_exit_code(ERR_BAD_PROOF);
}

#[test]
fn an_identity_not_in_the_tree_cannot_forge_a_claim() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);
    // Borrow a real member's proof but claim under a different identity:
    // the leaf changes, so the root check fails.
    let proof = inclusion_proof(&members, &[0x11; 32]).unwrap();
    let body = AipowDistributorContract::claim(0, [0xAB; 32], 100_000, &proof).unwrap();
    f.send(body).expect_exit_code(ERR_BAD_PROOF);
}

#[test]
fn a_second_claim_by_the_same_identity_is_rejected() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);
    let proof = inclusion_proof(&members, &[0x44; 32]).unwrap();
    let body = AipowDistributorContract::claim(0, [0x44; 32], 150_000, &proof).unwrap();
    f.send(body.clone()).expect_success();
    f.send(body).expect_exit_code(ERR_ALREADY_CLAIMED);
    assert_eq!(f.claimed_count(), 1);
}

#[test]
fn a_zero_total_score_distributor_cannot_be_built() {
    // build_data rejects a zero total_score outright, so a zero-denominator
    // distributor can never be deployed through the SDK.
    assert!(
        contracts::AipowDistributorContract::build_data(&AipowDistributorInit {
            operator: MsgAddressInt::with_standart(None, -1, [1; 32].into()).unwrap(),
            epoch: 1,
            earner_workchain: 0,
            total_score: 0,
            pool: POOL,
            maturation: AipowMaturation::methodology_v0(),
            score_root: [1; 32],
            commitment_ref: [0; 32],
        })
        .is_err()
    );
    let _ = ERR_INVALID_TOTAL_SCORE;
}

#[test]
fn a_zero_score_claim_is_rejected() {
    // A zero score earns nothing and would only pollute the dict, so it is
    // rejected before the proof is even folded.
    let members = vec![
        ScoreEntry { identity: [0x11; 32], score: 0 },
        ScoreEntry { identity: [0x22; 32], score: 1_000_000 },
    ];
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(1_000_000, root);
    let proof = inclusion_proof(&members, &[0x11; 32]).unwrap();
    let body = AipowDistributorContract::claim(0, [0x11; 32], 0, &proof).unwrap();
    f.send(body).expect_exit_code(ERR_ZERO_SCORE);
    assert_eq!(f.claim_amount([0x11; 32]), None);
    assert_eq!(f.claimed_count(), 0);
}

#[test]
fn an_understated_denominator_caps_the_cumulative_claimed_score() {
    // Deploy with a denominator (250_000) smaller than the true sum of the
    // committed leaves (300_000). Claims succeed until the running claimed
    // score would exceed the denominator; the overshooting claim is rejected,
    // so the aggregate recorded amount can never exceed the pool.
    let members = vec![
        ScoreEntry { identity: [0x11; 32], score: 200_000 },
        ScoreEntry { identity: [0x22; 32], score: 100_000 },
    ];
    let root = score_root(&members).unwrap();
    let understated: u128 = 250_000;
    let mut f = Fixture::new(understated, root);

    let proof0 = inclusion_proof(&members, &[0x11; 32]).unwrap();
    f.send(AipowDistributorContract::claim(0, [0x11; 32], 200_000, &proof0).unwrap())
        .expect_success();
    assert_eq!(f.data().claimed_score, 200_000);

    // 200_000 + 100_000 = 300_000 > 250_000: the cap rejects it.
    let proof1 = inclusion_proof(&members, &[0x22; 32]).unwrap();
    f.send(AipowDistributorContract::claim(1, [0x22; 32], 100_000, &proof1).unwrap())
        .expect_exit_code(ERR_SCORE_EXCEEDS_TOTAL);
    assert_eq!(f.claimed_count(), 1);
    assert_eq!(f.claim_amount([0x22; 32]), None);
}

#[test]
fn an_underfunded_claim_is_rejected() {
    // A permissionless claim must carry at least the minimum value so it funds
    // its own gas and storage rent rather than draining the contract.
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);
    let entry = &members[0];
    let proof = inclusion_proof(&members, &entry.identity).unwrap();
    let body = AipowDistributorContract::claim(0, entry.identity, entry.score, &proof).unwrap();
    f.send_with_value(body, contracts::AIPOW_MIN_CLAIM_VALUE - 1)
        .expect_exit_code(ERR_INSUFFICIENT_VALUE);
    assert_eq!(f.claimed_count(), 0);
}

#[test]
fn a_non_canonical_proof_cell_is_rejected() {
    // Craft a claim whose proof reference is neither an empty terminator nor a
    // canonical 257-bit node (128 junk bits here). The strict parser rejects
    // it as malformed rather than silently treating it as a terminator.
    use chain_block::{BuilderData, IBitstring};
    let only = vec![ScoreEntry { identity: [0x77; 32], score: 500_000 }];
    let root = score_root(&only).unwrap();
    let mut f = Fixture::new(500_000, root);

    let mut junk = BuilderData::new();
    junk.append_raw(&[0xAB; 16], 128).unwrap(); // 128 bits: not 0, not 257
    let mut body = BuilderData::new();
    body.append_u32(contracts::aipow_distributor::AIPOW_DISTRIBUTOR_CLAIM_OPCODE).unwrap();
    body.append_u64(0).unwrap();
    body.append_raw(&[0x77; 32], 256).unwrap();
    body.append_raw(&500_000u128.to_be_bytes(), 128).unwrap();
    body.checked_append_reference(junk.into_cell().unwrap()).unwrap();
    f.send(body.into_cell().unwrap()).expect_exit_code(ERR_MALFORMED_PROOF);
    assert_eq!(f.claim_amount([0x77; 32]), None);
}

#[test]
fn an_unknown_op_is_rejected() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);
    use chain_block::{BuilderData, IBitstring};
    let mut body = BuilderData::new();
    body.append_u32(0x4150_44FF).unwrap();
    body.append_u64(1).unwrap();
    f.send(body.into_cell().unwrap()).expect_exit_code(ERR_UNKNOWN_OP);
}

#[test]
fn a_claim_matures_on_chain_matching_the_sdk_curve() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);
    let mat = AipowMaturation::methodology_v0();
    let epoch_secs = u64::from(mat.epoch_seconds);

    let entry = &members[2]; // identity 0x33, score 300_000
    let proof = inclusion_proof(&members, &entry.identity).unwrap();
    f.send(AipowDistributorContract::claim(0, entry.identity, entry.score, &proof).unwrap())
        .expect_success();
    let claimed = f.claim(entry.identity).unwrap();
    let claimed_at = claimed.claimed_at;
    assert_eq!(claimed_at, f.now());
    assert!(!claimed.forfeited);
    let amount = claimed.amount;

    // The on-chain get_matured must equal the SDK's compute_matured at each
    // point on the curve.
    for elapsed in [0u64, 1, 4, 8, 100] {
        let at = claimed_at + elapsed * epoch_secs;
        let sdk = contracts::compute_matured(
            &contracts::AipowClaim { amount, claimed_at, forfeited: false, forfeit_at: 0, paid: 0 },
            &mat,
            at,
        );
        assert_eq!(f.matured(entry.identity, at), Some(sdk), "elapsed {elapsed} epochs");
    }
    // Immediately, that is 25% of the amount.
    assert_eq!(f.matured(entry.identity, claimed_at), Some(amount / 4));
    // Fully matured after 8 epochs.
    assert_eq!(f.matured(entry.identity, claimed_at + 8 * epoch_secs), Some(amount));

    // get_matured_now uses chain time, not a caller-supplied one. Right after
    // the claim it equals the immediate fraction; advancing chain time by four
    // epochs, it tracks now() and equals get_matured(now).
    assert_eq!(f.matured_now(entry.identity), Some(amount / 4));
    f.bc.set_now((claimed_at + 4 * epoch_secs) as u32);
    assert_eq!(f.matured_now(entry.identity), f.matured(entry.identity, f.now()));
    assert_eq!(f.matured_now(entry.identity), Some(amount / 4 + (amount - amount / 4) * 4 / 8));
}

#[test]
fn a_predeployed_instance_cannot_claim_before_the_operator_funds_it() {
    // The distributor address + StateInit are publicly derivable from the candidate
    // record, so anyone (a legitimate earner) could deploy the instance early and
    // prefund it. Without activation-gating it could then `claim` before issuance,
    // stamping claimed_at ahead of the mint and maturing its stream out of the
    // operator's forfeiture window. Activation closes that: only the operator's
    // funding message stamps the clock, and no claim is admitted before it.
    let only = vec![ScoreEntry { identity: [0x77; 32], score: 500_000 }];
    let root = score_root(&only).unwrap();
    let mut bc = Blockchain::new().expect("blockchain");
    bc.set_workchain(-1);
    let operator = bc.treasury("aipow-dist-op-gate", 1_000 * TOS).expect("operator");
    let attacker = bc.treasury("aipow-dist-attacker", 1_000 * TOS).expect("attacker");
    let init = AipowDistributorInit {
        operator: operator.address().clone(),
        epoch: 27_260,
        earner_workchain: EARNER_WC,
        total_score: 500_000,
        pool: POOL,
        maturation: AipowMaturation::methodology_v0(),
        score_root: root,
        commitment_ref: [0x99; 32],
    };
    let distributor = AipowDistributorContract::calculate_address(-1, &init).unwrap();

    // The earner pre-deploys the canonical instance itself and PREFUNDS it (enough
    // to cover the immediate tranche), all before the pool is minted.
    let predeploy = MessageBuilder::internal(attacker.address(), &distributor, DEPLOY_VALUE)
        .bounce(false)
        .state_init(AipowDistributorContract::build_state_init(&init).unwrap())
        .body(Cell::default())
        .build();
    bc.send_message(predeploy).expect("predeploy").expect_success();

    let send = |bc: &mut Blockchain, from: &MsgAddressInt, value: u64, body: Cell| {
        let msg = MessageBuilder::internal(from, &distributor, value).body(body).build();
        bc.send_message(msg).expect("send")
    };
    let read_data = |bc: &Blockchain| -> contracts::AipowDistributorData {
        let stack = bc
            .run_get_method(&distributor, "get_aipow_distributor_data", vec![])
            .unwrap()
            .expect_success()
            .stack
            .clone();
        AipowDistributorContract::decode_data(&Fixture::parse_stack(&stack)).unwrap()
    };

    // Not activated by the pre-deploy (it came from a non-operator).
    assert_eq!(read_data(&bc).activated_at, 0, "a non-operator pre-deploy must not activate");

    // The early claim is refused.
    let proof: Vec<ProofStep> = inclusion_proof(&only, &[0x77; 32]).unwrap();
    let claim_body = AipowDistributorContract::claim(0, [0x77; 32], 500_000, &proof).unwrap();
    send(&mut bc, attacker.address(), TOS, claim_body.clone()).expect_exit_code(ERR_NOT_ACTIVATED);

    // A stray empty message from a non-operator still does not activate.
    send(&mut bc, attacker.address(), TOS, Cell::default()).expect_success();
    assert_eq!(read_data(&bc).activated_at, 0, "a non-operator empty message must not activate");
    send(&mut bc, attacker.address(), TOS, claim_body.clone()).expect_exit_code(ERR_NOT_ACTIVATED);

    // The pool is minted later: the settlement (operator) funds the instance, which
    // activates it and stamps the clock at THIS (issuance) time -- a modest jump
    // forward from the pre-deploy so the anchoring is observable (a large jump would
    // just drain the instance on storage rent, a sandbox artifact unrelated to the fix).
    let issuance = bc.now() + 50_000;
    bc.set_now(issuance);
    send(&mut bc, operator.address(), POOL, Cell::default()).expect_success();
    let activated = read_data(&bc).activated_at;
    assert_eq!(activated, u64::from(issuance), "operator funding stamps the activation clock");

    // Now the claim is admitted, and its maturation clock starts at issuance (the
    // funding time), never at the earlier pre-deploy time.
    send(&mut bc, attacker.address(), TOS, claim_body).expect_success();
    let arg = vec![tos_vm::stack::StackItem::int(
        tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be([0x77; 32]),
    )];
    let stack =
        bc.run_get_method(&distributor, "get_claim", arg).unwrap().expect_success().stack.clone();
    let claim =
        AipowDistributorContract::decode_claim(&Fixture::parse_stack(&stack)).unwrap().unwrap();
    assert_eq!(
        claim.claimed_at,
        u64::from(issuance),
        "vesting is anchored at issuance, not pre-deploy"
    );

    // A second operator funding does not reset the activation clock.
    send(&mut bc, operator.address(), POOL, Cell::default()).expect_success();
    assert_eq!(read_data(&bc).activated_at, u64::from(issuance), "activation is once-only");
}

#[test]
fn operator_forfeit_freezes_maturation_and_is_once_only() {
    let members = entries();
    let root = score_root(&members).unwrap();
    // Deploy funded so the operator can send forfeit from its own address.
    let mut bc = Blockchain::new().expect("blockchain");
    bc.set_workchain(-1);
    let operator = bc.treasury("aipow-dist-op2", 1_000 * TOS).expect("operator");
    let outsider = bc.treasury("aipow-dist-out", 1_000 * TOS).expect("outsider");
    let init = AipowDistributorInit {
        operator: operator.address().clone(),
        epoch: 27_260,
        earner_workchain: EARNER_WC,
        total_score: TOTAL_SCORE,
        pool: POOL,
        maturation: AipowMaturation::methodology_v0(),
        score_root: root,
        commitment_ref: [0x99; 32],
    };
    let distributor = AipowDistributorContract::calculate_address(-1, &init).unwrap();
    let deploy = MessageBuilder::internal(operator.address(), &distributor, DEPLOY_VALUE)
        .bounce(false)
        .state_init(AipowDistributorContract::build_state_init(&init).unwrap())
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();

    let send = |bc: &mut Blockchain, from: &MsgAddressInt, body: Cell| {
        let msg = MessageBuilder::internal(from, &distributor, TOS / 2).body(body).build();
        bc.send_message(msg).expect("send")
    };
    let epoch_secs = u64::from(AipowMaturation::methodology_v0().epoch_seconds);
    let entry = &members[1]; // 0x22, score 200_000
    let proof = inclusion_proof(&members, &entry.identity).unwrap();
    send(
        &mut bc,
        outsider.address(),
        AipowDistributorContract::claim(0, entry.identity, entry.score, &proof).unwrap(),
    )
    .expect_success();

    let read_claim = |bc: &Blockchain| -> contracts::AipowClaim {
        let arg = vec![tos_vm::stack::StackItem::int(
            tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(entry.identity),
        )];
        let stack = bc
            .run_get_method(&distributor, "get_claim", arg)
            .unwrap()
            .expect_success()
            .stack
            .clone();
        AipowDistributorContract::decode_claim(&Fixture::parse_stack(&stack)).unwrap().unwrap()
    };
    let read_matured = |bc: &Blockchain, at: u64| -> u64 {
        let arg = vec![
            tos_vm::stack::StackItem::int(
                tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(entry.identity),
            ),
            tos_vm::stack::StackItem::int(at as i64),
        ];
        let stack = bc
            .run_get_method(&distributor, "get_matured", arg)
            .unwrap()
            .expect_success()
            .stack
            .clone();
        AipowDistributorContract::decode_matured(&Fixture::parse_stack(&stack)).unwrap().unwrap()
    };
    let claimed = read_claim(&bc);
    let claimed_at = claimed.claimed_at;
    // The claim already paid the immediate tranche.
    assert_eq!(claimed.paid, immediate(claimed.amount));

    // A non-operator cannot forfeit.
    send(
        &mut bc,
        outsider.address(),
        AipowDistributorContract::forfeit(1, entry.identity).unwrap(),
    )
    .expect_exit_code(2205);

    // Advance two epochs, then the operator forfeits.
    bc.set_now((claimed_at + 2 * epoch_secs) as u32);
    send(
        &mut bc,
        operator.address(),
        AipowDistributorContract::forfeit(2, entry.identity).unwrap(),
    )
    .expect_success();
    let after = read_claim(&bc);
    assert!(after.forfeited);
    assert_eq!(after.forfeit_at, claimed_at + 2 * epoch_secs);
    // Forfeit does not itself pay; paid is unchanged (still the immediate).
    assert_eq!(after.paid, immediate(after.amount));

    // Maturation is frozen at the forfeit time: querying far in the future
    // yields the same frozen value, not full maturation.
    let frozen = read_matured(&bc, claimed_at + 2 * epoch_secs);
    assert_eq!(read_matured(&bc, claimed_at + 100 * epoch_secs), frozen);
    assert!(frozen < after.amount, "unmatured remainder is voided");

    // A payout after the forfeit pays only up to the frozen value, never the
    // voided remainder.
    send(&mut bc, outsider.address(), AipowDistributorContract::payout(5, entry.identity).unwrap())
        .expect_success();
    assert_eq!(read_claim(&bc).paid, frozen);
    bc.set_now((claimed_at + 100 * epoch_secs) as u32);
    send(&mut bc, outsider.address(), AipowDistributorContract::payout(6, entry.identity).unwrap())
        .expect_exit_code(ERR_NOTHING_TO_PAY);

    // A second forfeit is rejected.
    send(
        &mut bc,
        operator.address(),
        AipowDistributorContract::forfeit(3, entry.identity).unwrap(),
    )
    .expect_exit_code(2207);
    // Forfeiting an unclaimed identity is rejected.
    send(&mut bc, operator.address(), AipowDistributorContract::forfeit(4, [0xEE; 32]).unwrap())
        .expect_exit_code(2206);
}

// --- W4.3 review hardening (codex review round 1: not-a-bug coverage gaps) ---

#[test]
fn a_failed_payment_rolls_back_the_claim_record() {
    // Send/record atomicity: if the immediate-tranche payment cannot be funded,
    // the action phase aborts and the compute-phase state (the recorded claim
    // and its paid cursor) must NOT persist -- there is no "recorded but never
    // paid" state. Deploy underfunded so the immediate tranche (0.75 TOS for
    // the 0x33 share) exceeds the instance balance.
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new_with(TOTAL_SCORE, root, AipowMaturation::methodology_v0(), TOS / 2);
    let entry = &members[2]; // 0x33, score 300_000 -> 3 TOS share, 0.75 TOS immediate
    let proof = inclusion_proof(&members, &entry.identity).unwrap();
    // Carry exactly the min claim value; the compute-phase gate passes, but the
    // action-phase send of the immediate tranche cannot be funded.
    f.send_with_value(
        AipowDistributorContract::claim(0, entry.identity, entry.score, &proof).unwrap(),
        contracts::AIPOW_MIN_CLAIM_VALUE,
    )
    .expect_aborted();
    // Rolled back: nothing recorded, nothing paid.
    assert_eq!(f.claim(entry.identity), None);
    assert_eq!(f.claimed_count(), 0);
    assert_eq!(f.data().claimed_score, 0);
    assert_eq!(f.earner_balance(entry.identity), 0);
}

#[test]
fn on_chain_maturation_matches_the_sdk_for_non_round_amounts() {
    // Differential Rust-vs-TVM maturation with a deliberately non-round
    // pro-rata amount and non-epoch-aligned query times, so any flooring or
    // operation-order divergence between the SDK and the contract surfaces.
    let members = vec![
        ScoreEntry { identity: [0xA1; 32], score: 1_234_567 },
        ScoreEntry { identity: [0xB2; 32], score: 2_345_678 },
        ScoreEntry { identity: [0xC3; 32], score: 3_420_003 },
    ];
    let total: u128 = members.iter().map(|e| u128::from(e.score)).sum();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(total, root);
    let mat = AipowMaturation::methodology_v0();
    let e = u64::from(mat.epoch_seconds);

    let entry = &members[1]; // non-round share of the pool
    let proof = inclusion_proof(&members, &entry.identity).unwrap();
    f.send(AipowDistributorContract::claim(0, entry.identity, entry.score, &proof).unwrap())
        .expect_success();
    let claimed = f.claim(entry.identity).unwrap();
    let amount = claimed.amount;
    let claimed_at = claimed.claimed_at;
    // The amount must genuinely be non-round to make the test meaningful.
    assert_ne!(amount % 4, 0, "share should not be divisible by the immediate quarter");

    // Times that are NOT epoch-aligned (fractions of an epoch, offsets), and the
    // full range including past-maturity.
    for at in [
        claimed_at,
        claimed_at + 1,
        claimed_at + e / 3,
        claimed_at + e,
        claimed_at + e + e / 2,
        claimed_at + 3 * e + e / 7,
        claimed_at + 7 * e + e - 1,
        claimed_at + 8 * e,
        claimed_at + 8 * e + 1,
        claimed_at + 100 * e,
    ] {
        let sdk = contracts::compute_matured(
            &contracts::AipowClaim { amount, claimed_at, forfeited: false, forfeit_at: 0, paid: 0 },
            &mat,
            at,
        );
        assert_eq!(f.matured(entry.identity, at), Some(sdk), "at t={at}");
    }
}

#[test]
fn on_chain_maturation_matches_the_sdk_at_boundary_bps() {
    // Boundary maturation curves: all-immediate (10000 bps) and all-streamed
    // (0 bps). Deploy an instance with each and differential-check a claim.
    for immediate_bps in [0u16, 10_000u16] {
        let mat = AipowMaturation { immediate_bps, stream_epochs: 8, epoch_seconds: 65_536 };
        let members = entries();
        let root = score_root(&members).unwrap();
        let mut f = Fixture::new_with(TOTAL_SCORE, root, mat, DEPLOY_VALUE);
        let e = u64::from(mat.epoch_seconds);
        let entry = &members[4]; // 0x55, score 250_000
        let proof = inclusion_proof(&members, &entry.identity).unwrap();
        f.send(AipowDistributorContract::claim(0, entry.identity, entry.score, &proof).unwrap())
            .expect_success();
        let claimed = f.claim(entry.identity).unwrap();
        let amount = claimed.amount;
        let claimed_at = claimed.claimed_at;
        // Immediate paid at claim time equals the bps fraction of the amount.
        let expect_immediate = (u128::from(amount) * u128::from(immediate_bps) / 10_000) as u64;
        assert_eq!(claimed.paid, expect_immediate, "bps={immediate_bps} immediate");
        for at in [claimed_at, claimed_at + e, claimed_at + 4 * e, claimed_at + 8 * e] {
            let sdk = contracts::compute_matured(
                &contracts::AipowClaim {
                    amount,
                    claimed_at,
                    forfeited: false,
                    forfeit_at: 0,
                    paid: 0,
                },
                &mat,
                at,
            );
            assert_eq!(f.matured(entry.identity, at), Some(sdk), "bps={immediate_bps} at t={at}");
        }
    }
}

#[test]
fn forfeit_between_epoch_boundaries_matches_the_sdk() {
    // Forfeit at a time that is NOT an epoch boundary; the frozen maturation the
    // contract reports must equal the SDK's compute_matured for the same
    // forfeited claim (differential across the freeze).
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);
    let mat = AipowMaturation::methodology_v0();
    let e = u64::from(mat.epoch_seconds);
    let operator = f.operator.address().clone();

    let entry = &members[3]; // 0x44, score 150_000
    let proof = inclusion_proof(&members, &entry.identity).unwrap();
    f.send(AipowDistributorContract::claim(0, entry.identity, entry.score, &proof).unwrap())
        .expect_success();
    let claimed = f.claim(entry.identity).unwrap();
    let amount = claimed.amount;
    let claimed_at = claimed.claimed_at;

    // Forfeit 2.4 epochs in (a non-boundary offset).
    let forfeit_at = claimed_at + 2 * e + (2 * e) / 5;
    f.bc.set_now(forfeit_at as u32);
    f.send_from(&operator, AipowDistributorContract::forfeit(1, entry.identity).unwrap())
        .expect_success();
    let after = f.claim(entry.identity).unwrap();
    assert!(after.forfeited);
    assert_eq!(after.forfeit_at, forfeit_at);

    // Frozen value the contract reports at several later times equals the SDK.
    for at in [forfeit_at, forfeit_at + e, claimed_at + 100 * e] {
        let sdk = contracts::compute_matured(
            &contracts::AipowClaim { amount, claimed_at, forfeited: true, forfeit_at, paid: 0 },
            &mat,
            at,
        );
        assert_eq!(f.matured(entry.identity, at), Some(sdk), "frozen at t={at}");
    }
}
