/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) tests for the AIPoW reward distributor.
//!
//! The load-bearing check: the compiled contract recomputes epoch score
//! roots on-chain with `string_hash` (SHA256U) over methodology-v0
//! leaf/node preimages, and that must equal the Rust `aipow_merkle` root
//! byte for byte -- otherwise a valid beneficiary's inclusion proof would
//! be rejected. These tests deploy a distributor carrying a real Rust-built
//! root and then claim every member through the contract, plus the
//! rejection paths (wrong score, tampered proof, double claim, zero
//! total score, zero score, an understated denominator's cumulative-score
//! cap, an underfunded claim, a malformed proof, unknown op) and the pro-rata
//! amount recorded per claim.

use chain_block::{Cell, MsgAddressInt};
use contracts::aipow_merkle::{inclusion_proof, score_root, ProofStep, ScoreEntry};
use contracts::{AipowDistributorContract, AipowDistributorInit};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

const TOS: u64 = 1_000_000_000;
const POOL: u64 = 10 * TOS;
const ERR_INVALID_TOTAL_SCORE: i32 = 2200;
const ERR_ALREADY_CLAIMED: i32 = 2201;
const ERR_BAD_PROOF: i32 = 2202;
const ERR_UNKNOWN_OP: i32 = 2204;
const ERR_SCORE_EXCEEDS_TOTAL: i32 = 2208;
const ERR_ZERO_SCORE: i32 = 2209;
const ERR_INSUFFICIENT_VALUE: i32 = 2210;
const ERR_MALFORMED_PROOF: i32 = 2211;

struct Fixture {
    bc: Blockchain,
    caller: Treasury,
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

impl Fixture {
    fn new(total_score: u128, root: [u8; 32]) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let operator = bc.treasury("aipow-dist-operator", 1_000 * TOS).expect("operator");
        let caller = bc.treasury("aipow-dist-caller", 1_000 * TOS).expect("caller");
        let init = AipowDistributorInit {
            operator: operator.address().clone(),
            epoch: 27_260,
            total_score,
            pool: POOL,
            score_root: root,
            commitment_ref: [0x99; 32],
        };
        let distributor =
            AipowDistributorContract::calculate_address(-1, &init).expect("address");
        let deploy = MessageBuilder::internal(operator.address(), &distributor, 2 * TOS)
            .bounce(false)
            .state_init(AipowDistributorContract::build_state_init(&init).expect("state init"))
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, caller, distributor }
    }

    fn send(&mut self, body: Cell) -> tos_sandbox::SendResult {
        self.send_with_value(body, TOS / 2)
    }

    fn send_with_value(&mut self, body: Cell, value: u64) -> tos_sandbox::SendResult {
        let msg =
            MessageBuilder::internal(self.caller.address(), &self.distributor, value).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    fn identity_arg(identity: [u8; 32]) -> tos_vm::stack::StackItem {
        tos_vm::stack::StackItem::int(
            tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(identity),
        )
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
        let arg = vec![
            Self::identity_arg(identity),
            tos_vm::stack::StackItem::int(at_time as i64),
        ];
        let stack = self
            .bc
            .run_get_method(&self.distributor, "get_matured", arg)
            .expect("get_matured")
            .expect_success()
            .stack
            .clone();
        AipowDistributorContract::decode_matured(&Self::parse_stack(&stack)).expect("decode_matured")
    }

    fn matured_now(&self, identity: [u8; 32]) -> Option<u64> {
        let stack = self
            .bc
            .run_get_method(&self.distributor, "get_matured_now", vec![Self::identity_arg(identity)])
            .expect("get_matured_now")
            .expect_success()
            .stack
            .clone();
        AipowDistributorContract::decode_matured(&Self::parse_stack(&stack)).expect("decode_matured")
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
        let entries = stack
            .iter()
            .map(sandbox_stack_item_to_entry)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("stack conversion");
        AipowDistributorContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(
            entries,
        ))
        .expect("decode_data")
    }

    fn claimed_count(&self) -> u32 {
        self.data().claimed_count
    }
}

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
fn every_member_claims_its_pro_rata_share_and_the_contract_recomputes_the_root() {
    let members = entries();
    let root = score_root(&members).unwrap();
    let mut f = Fixture::new(TOTAL_SCORE, root);

    for (index, entry) in members.iter().enumerate() {
        assert_eq!(f.claim_amount(entry.identity), None, "unclaimed before claim");
        let proof = inclusion_proof(&members, &entry.identity).unwrap();
        let body = AipowDistributorContract::claim(
            index as u64,
            entry.identity,
            entry.score,
            &proof,
        )
        .unwrap();
        f.send(body).expect_success();

        // The recorded amount is the flooring pro-rata share of the pool.
        let expected = (u128::from(POOL) * entry.score / TOTAL_SCORE) as u64;
        assert_eq!(
            f.claim_amount(entry.identity),
            Some(expected),
            "member {index} pro-rata amount"
        );
    }
    assert_eq!(f.claimed_count(), members.len() as u32);
    // Every member claimed, so the running claimed_score equals the full
    // denominator -- the cumulative cap is satisfied with no slack left.
    assert_eq!(f.data().claimed_score, TOTAL_SCORE);
    // The five flooring shares sum to at most the pool; dust is unallocated.
    let total: u64 = members
        .iter()
        .map(|e| (u128::from(POOL) * e.score / TOTAL_SCORE) as u64)
        .sum();
    assert!(total <= POOL);
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
    assert!(contracts::AipowDistributorContract::build_data(&AipowDistributorInit {
        operator: MsgAddressInt::with_standart(None, -1, [1; 32].into()).unwrap(),
        epoch: 1,
        total_score: 0,
        pool: POOL,
        score_root: [1; 32],
        commitment_ref: [0; 32],
    })
    .is_err());
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
    let epoch_secs = contracts::AIPOW_MATURATION_EPOCH_SECONDS;

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
            &contracts::AipowClaim { amount, claimed_at, forfeited: false, forfeit_at: 0 },
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
        total_score: TOTAL_SCORE,
        pool: POOL,
        score_root: root,
        commitment_ref: [0x99; 32],
    };
    let distributor = AipowDistributorContract::calculate_address(-1, &init).unwrap();
    let deploy = MessageBuilder::internal(operator.address(), &distributor, 2 * TOS)
        .bounce(false)
        .state_init(AipowDistributorContract::build_state_init(&init).unwrap())
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();

    let send = |bc: &mut Blockchain, from: &MsgAddressInt, body: Cell| {
        let msg = MessageBuilder::internal(from, &distributor, TOS / 2).body(body).build();
        bc.send_message(msg).expect("send")
    };
    let epoch_secs = contracts::AIPOW_MATURATION_EPOCH_SECONDS;
    let entry = &members[1]; // 0x22, score 200_000
    let proof = inclusion_proof(&members, &entry.identity).unwrap();
    send(&mut bc, outsider.address(), AipowDistributorContract::claim(0, entry.identity, entry.score, &proof).unwrap())
        .expect_success();

    let read_claim = |bc: &Blockchain| -> contracts::AipowClaim {
        let arg = vec![tos_vm::stack::StackItem::int(
            tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(entry.identity),
        )];
        let stack = bc.run_get_method(&distributor, "get_claim", arg).unwrap().expect_success().stack.clone();
        AipowDistributorContract::decode_claim(&Fixture::parse_stack(&stack)).unwrap().unwrap()
    };
    let read_matured = |bc: &Blockchain, at: u64| -> u64 {
        let arg = vec![
            tos_vm::stack::StackItem::int(tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(entry.identity)),
            tos_vm::stack::StackItem::int(at as i64),
        ];
        let stack = bc.run_get_method(&distributor, "get_matured", arg).unwrap().expect_success().stack.clone();
        AipowDistributorContract::decode_matured(&Fixture::parse_stack(&stack)).unwrap().unwrap()
    };
    let claimed_at = read_claim(&bc).claimed_at;

    // A non-operator cannot forfeit.
    send(&mut bc, outsider.address(), AipowDistributorContract::forfeit(1, entry.identity).unwrap())
        .expect_exit_code(2205);

    // Advance two epochs, then the operator forfeits.
    bc.set_now((claimed_at + 2 * epoch_secs) as u32);
    send(&mut bc, operator.address(), AipowDistributorContract::forfeit(2, entry.identity).unwrap())
        .expect_success();
    let after = read_claim(&bc);
    assert!(after.forfeited);
    assert_eq!(after.forfeit_at, claimed_at + 2 * epoch_secs);

    // Maturation is frozen at the forfeit time: querying far in the future
    // yields the same frozen value, not full maturation.
    let frozen = read_matured(&bc, claimed_at + 2 * epoch_secs);
    assert_eq!(read_matured(&bc, claimed_at + 100 * epoch_secs), frozen);
    assert!(frozen < after.amount, "unmatured remainder is voided");

    // A second forfeit is rejected.
    send(&mut bc, operator.address(), AipowDistributorContract::forfeit(3, entry.identity).unwrap())
        .expect_exit_code(2207);
    // Forfeiting an unclaimed identity is rejected.
    send(&mut bc, operator.address(), AipowDistributorContract::forfeit(4, [0xEE; 32]).unwrap())
        .expect_exit_code(2206);
}
