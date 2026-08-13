/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) tests for the AIPoW settlement account:
//! deployment + get-method inspection, the register path (first-wins, duplicate
//! rejection, zero-total-score rejection, an epoch behind the cursor rejected),
//! the skip path (too-early rejection, a registered epoch not skippable, and a
//! permissionless skip advancing the cursor with zero mint past the grace
//! deadline), and (W4.1 part 3) the settle path: the on-chain derivation of the
//! canonical per-epoch distributor address is checked against a real deployment
//! of the audited distributor SDK, and the authenticated mint (empty body, from
//! the minter -1:00..00) deploys+funds that distributor and advances the ledger,
//! while a non-minter value message and a mint for an unregistered epoch do not.

use chain_block::{Cell, MsgAddressInt};
use contracts::{
    AipowDistributorContract, AipowDistributorInit, AipowMaturation, AipowSettlementContract,
    AipowSettlementInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

const TOS: u64 = 1_000_000_000;
const EPOCH_SECONDS: u32 = 65_536;
const REGISTER_GRACE: u32 = 3600;
const TOTAL_CAP: u64 = 4_500_000_000 * TOS;
/// The distributors are deployed on, and pay identities on, this workchain. The
/// test keeps it on the masterchain the settlement lives on so the settle
/// forward is delivered by the in-memory sandbox (which does not route
/// cross-workchain messages) and it exercises the signed int8 encoding.
const EARNER_WC: i8 = -1;

const ERR_EPOCH_SETTLED: i32 = 2301;
const ERR_ALREADY_REGISTERED: i32 = 2302;
const ERR_ZERO_TOTAL_SCORE: i32 = 2303;
const ERR_SKIP_TOO_EARLY: i32 = 2304;
const ERR_SKIP_REGISTERED: i32 = 2305;
const ERR_SETTLE_NO_REGISTRATION: i32 = 2306;
const ERR_UNKNOWN_OP: i32 = 2307;

/// The audited distributor code the settlement derives addresses against and
/// deploys. Using the real code (not a stub) is what makes the derived address
/// equal a genuine distributor deployment.
fn distributor_code() -> Cell {
    AipowDistributorContract::code().unwrap()
}

/// The masterchain minter address (-1:00..00) whose empty-body value message is
/// the authenticated settle trigger.
fn minter() -> MsgAddressInt {
    MsgAddressInt::with_standart(None, -1, [0u8; 32].into()).unwrap()
}

struct Fixture {
    bc: Blockchain,
    committer: Treasury,
    settlement: MsgAddressInt,
    next_epoch: u32,
}

impl Fixture {
    fn new() -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let deployer = bc.treasury("aipow-settlement-deployer", 1_000 * TOS).expect("deployer");
        let committer = bc.treasury("aipow-settlement-committer", 1_000 * TOS).expect("committer");
        // Anchor the cursor at the current wall-clock epoch so the skip deadline
        // sits ahead of the sandbox clock (time must move forward, not back).
        let next_epoch = bc.now() / EPOCH_SECONDS;
        let init = AipowSettlementInit {
            next_epoch,
            epoch_seconds: EPOCH_SECONDS,
            register_grace: REGISTER_GRACE,
            earner_workchain: EARNER_WC,
            maturation: AipowMaturation::methodology_v0(),
            total_cap: TOTAL_CAP,
            distributor_code: distributor_code(),
        };
        let settlement = AipowSettlementContract::calculate_address(-1, &init).expect("address");
        let deploy = MessageBuilder::internal(deployer.address(), &settlement, 2 * TOS)
            .bounce(false)
            .state_init(AipowSettlementContract::build_state_init(&init).expect("state init"))
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, committer, settlement, next_epoch }
    }

    fn send_from(&mut self, from: &MsgAddressInt, body: Cell) -> tos_sandbox::SendResult {
        self.send_from_value(from, body, TOS / 10)
    }

    fn send_from_value(&mut self, from: &MsgAddressInt, body: Cell, value: u64) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(from, &self.settlement, value).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    fn parse_stack(stack: &[tos_vm::stack::StackItem]) -> common::tvm_stack_parser::TvmStackParser {
        let entries = stack
            .iter()
            .map(sandbox_stack_item_to_entry)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("stack conversion");
        common::tvm_stack_parser::TvmStackParser::new(entries)
    }

    fn data(&self) -> contracts::AipowSettlementData {
        let stack = self
            .bc
            .run_get_method(&self.settlement, "get_aipow_settlement_data", vec![])
            .expect("get_aipow_settlement_data")
            .expect_success()
            .stack
            .clone();
        AipowSettlementContract::decode_data(&Self::parse_stack(&stack)).expect("decode_data")
    }

    fn candidate_count(&self, epoch: u32) -> u16 {
        let arg = vec![tos_vm::stack::StackItem::int(epoch as i64)];
        let stack = self
            .bc
            .run_get_method(&self.settlement, "get_candidate_count", arg)
            .expect("get_candidate_count")
            .expect_success()
            .stack
            .clone();
        AipowSettlementContract::decode_candidate_count(&Self::parse_stack(&stack))
            .expect("decode_candidate_count")
    }

    fn candidate(&self, epoch: u32, id: [u8; 32]) -> Option<contracts::AipowCandidate> {
        let arg = vec![
            tos_vm::stack::StackItem::int(epoch as i64),
            id_arg(id),
        ];
        let stack = self
            .bc
            .run_get_method(&self.settlement, "get_candidate", arg)
            .expect("get_candidate")
            .expect_success()
            .stack
            .clone();
        AipowSettlementContract::decode_candidate(&Self::parse_stack(&stack)).expect("decode_candidate")
    }

    fn min_candidate(&self, epoch: u32) -> Option<[u8; 32]> {
        let arg = vec![tos_vm::stack::StackItem::int(epoch as i64)];
        let stack = self
            .bc
            .run_get_method(&self.settlement, "get_min_candidate", arg)
            .expect("get_min_candidate")
            .expect_success()
            .stack
            .clone();
        AipowSettlementContract::decode_candidate_id(&Self::parse_stack(&stack))
            .expect("decode_candidate_id")
    }

    /// The distributor address the settle path would deploy for the `winner_id`
    /// candidate of `epoch` funded with `pool`, per the settlement's derivation.
    fn derived_distributor(&self, epoch: u32, winner_id: [u8; 32], pool: u64) -> Option<MsgAddressInt> {
        let arg = vec![
            tos_vm::stack::StackItem::int(epoch as i64),
            id_arg(winner_id),
            tos_vm::stack::StackItem::int(pool as i64),
        ];
        let stack = self
            .bc
            .run_get_method(&self.settlement, "get_distributor_address", arg)
            .expect("get_distributor_address")
            .expect_success()
            .stack
            .clone();
        AipowSettlementContract::decode_distributor_address(&Self::parse_stack(&stack))
            .expect("decode_distributor_address")
    }

    /// Read a deployed distributor's data (proves the settle path actually
    /// deployed one at the derived address).
    fn distributor_data(&self, addr: &MsgAddressInt) -> contracts::AipowDistributorData {
        let stack = self
            .bc
            .run_get_method(addr, "get_aipow_distributor_data", vec![])
            .expect("get_aipow_distributor_data")
            .expect_success()
            .stack
            .clone();
        AipowDistributorContract::decode_data(&Self::parse_stack(&stack)).expect("decode_data")
    }

    fn balance_of(&self, addr: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(addr)
            .and_then(|a| a.balance())
            .and_then(|c| c.coins.as_u64())
            .unwrap_or(0)
    }

    /// The masterchain minter delivers the epoch pool naming the native-selected
    /// winning candidate (its account id); this is the authenticated settle
    /// trigger.
    fn mint(&mut self, winner_id: [u8; 32], value: u64) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(&minter(), &self.settlement, value)
            .body(AipowSettlementContract::settle_body(winner_id).unwrap())
            .build();
        self.bc.send_message(msg).expect("mint")
    }

    /// Send a settle-shaped message (a winner id body) from an arbitrary
    /// (non-minter) sender.
    fn settle_from(&mut self, from: &MsgAddressInt, winner_id: [u8; 32], value: u64) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(from, &self.settlement, value)
            .body(AipowSettlementContract::settle_body(winner_id).unwrap())
            .build();
        self.bc.send_message(msg).expect("send")
    }
}

/// The 256-bit account id of a standard address (its `commitment_ref`).
fn account_id(addr: &MsgAddressInt) -> [u8; 32] {
    addr.address().get_bytestring(0).try_into().expect("32-byte account id")
}

/// A 256-bit account id as a get-method integer argument.
fn id_arg(id: [u8; 32]) -> tos_vm::stack::StackItem {
    tos_vm::stack::StackItem::int(tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(id))
}

fn sandbox_stack_item_to_entry(
    item: &tos_vm::stack::StackItem,
) -> anyhow::Result<tl_api::tos::tvm::StackEntry> {
    use tl_api::tos::tvm::{
        numberdecimal::NumberDecimal,
        slice,
        stackentry::{StackEntryNumber, StackEntrySlice},
        Number, StackEntry,
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
fn deploys_and_readable() {
    let f = Fixture::new();
    let next_epoch = f.next_epoch;
    let data = f.data();
    assert_eq!(data.version, contracts::AIPOW_SETTLEMENT_VERSION);
    assert_eq!(data.next_epoch, next_epoch);
    assert_eq!(data.epoch_seconds, EPOCH_SECONDS);
    assert_eq!(data.register_grace, REGISTER_GRACE);
    assert_eq!(data.minted_total, 0);
    assert_eq!(data.total_cap, TOTAL_CAP);
    assert_eq!(f.candidate_count(next_epoch), 0, "no candidates at deploy");
    assert_eq!(f.min_candidate(next_epoch), None);
}

#[test]
fn register_records_multiple_candidates_and_dedups_per_commitment() {
    let mut f = Fixture::new();
    let epoch = f.next_epoch + 5;
    let a = f.committer.address().clone();
    let b = f.bc.treasury("committer-b", 1_000 * TOS).unwrap().address().clone();

    // Two different commitments nominate the SAME epoch -- both are candidates
    // (no first-wins). A bogus nomination cannot exclude a genuine one.
    f.send_from(&a, AipowSettlementContract::register(1, epoch, [0xAB; 32], 1_000_000, 42 * TOS as u128).unwrap())
        .expect_success();
    f.send_from(&b, AipowSettlementContract::register(2, epoch, [0xCD; 32], 2_000_000, 7).unwrap())
        .expect_success();
    assert_eq!(f.candidate_count(epoch), 2);

    let ca = f.candidate(epoch, account_id(&a)).expect("a is a candidate");
    assert_eq!(ca.score_root, [0xAB; 32]);
    assert_eq!(ca.total_score, 1_000_000);
    assert_eq!(ca.organic_settled_value, 42 * TOS as u128);
    let cb = f.candidate(epoch, account_id(&b)).expect("b is a candidate");
    assert_eq!(cb.score_root, [0xCD; 32]);

    // A single commitment may nominate an epoch at most once.
    f.send_from(&a, AipowSettlementContract::register(3, epoch, [0xEE; 32], 5, 5).unwrap())
        .expect_exit_code(ERR_ALREADY_REGISTERED);
    assert_eq!(f.candidate_count(epoch), 2);
    // The first nomination is untouched.
    assert_eq!(f.candidate(epoch, account_id(&a)).unwrap().score_root, [0xAB; 32]);
}

#[test]
fn register_rejects_settled_epoch_and_zero_total_score() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let committer = f.committer.address().clone();

    f.send_from(&committer, AipowSettlementContract::register(1, next_epoch - 1, [0xAB; 32], 1_000_000, 1).unwrap())
        .expect_exit_code(ERR_EPOCH_SETTLED);
    f.send_from(&committer, AipowSettlementContract::register(2, next_epoch, [0xAB; 32], 0, 1).unwrap())
        .expect_exit_code(ERR_ZERO_TOTAL_SCORE);
    assert_eq!(f.candidate_count(next_epoch), 0);
}

#[test]
fn skip_advances_an_unregistered_epoch_past_the_deadline() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let poker = f.committer.address().clone();
    let skippable_at = (next_epoch + 1) as u64 * EPOCH_SECONDS as u64 + REGISTER_GRACE as u64;
    f.bc.set_now((skippable_at - 1) as u32);
    f.send_from(&poker, AipowSettlementContract::skip(1).unwrap())
        .expect_exit_code(ERR_SKIP_TOO_EARLY);
    assert_eq!(f.data().next_epoch, next_epoch);
    f.bc.set_now(skippable_at as u32);
    f.send_from(&poker, AipowSettlementContract::skip(2).unwrap()).expect_success();
    assert_eq!(f.data().next_epoch, next_epoch + 1);
    assert_eq!(f.data().minted_total, 0);
}

#[test]
fn skip_advances_a_registered_epoch_past_grace_so_a_bogus_nomination_cannot_freeze_it() {
    // The griefing fix: an attacker registers a (bogus) candidate for the cursor
    // epoch. Past the grace deadline the epoch is STILL skippable -- the bogus
    // nomination cannot freeze the cursor (skip_registered retired).
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let attacker = f.committer.address().clone();
    f.send_from(&attacker, AipowSettlementContract::register(1, next_epoch, [0xBA; 32], 1_000_000, 1).unwrap())
        .expect_success();
    assert_eq!(f.candidate_count(next_epoch), 1);
    let skippable_at = (next_epoch + 1) as u64 * EPOCH_SECONDS as u64 + REGISTER_GRACE as u64;
    f.bc.set_now(skippable_at as u32);
    f.send_from(&attacker, AipowSettlementContract::skip(2).unwrap()).expect_success();
    assert_eq!(f.data().next_epoch, next_epoch + 1, "registered epoch still advances");
}

#[test]
fn the_candidate_set_is_bounded_and_keeps_the_smallest_addresses() {
    let mut f = Fixture::new();
    let epoch = f.next_epoch + 2;
    // Register nine distinct commitments (MAX_CANDIDATES is 8). The first eight
    // always fit; the ninth is admitted (evicting the current max) only if its
    // address is smaller, else rejected as full -- either way the final set is
    // the eight smallest addresses.
    let mut ids: Vec<[u8; 32]> = Vec::new();
    for i in 0..9 {
        let c = f.bc.treasury(&format!("cand-{i}"), 1_000 * TOS).unwrap().address().clone();
        ids.push(account_id(&c));
        // A larger candidate set costs more gas per insert on masterchain, so
        // fund these registrations generously.
        let r = f.send_from_value(&c, AipowSettlementContract::register(i as u64, epoch, [i as u8; 32], 1_000, 1).unwrap(), 2 * TOS);
        if i < 8 {
            r.expect_success();
        }
    }
    // Capped at 8; the single largest-address candidate is the one excluded.
    assert_eq!(f.candidate_count(epoch), 8);
    ids.sort();
    let largest = ids[8];
    assert_eq!(f.candidate(epoch, largest), None, "the largest address is evicted");
    for id in &ids[..8] {
        assert!(f.candidate(epoch, *id).is_some(), "the 8 smallest addresses are kept");
    }
    assert_eq!(f.min_candidate(epoch), Some(ids[0]), "min candidate is the smallest address");
}

#[test]
fn unknown_op_rejected_empty_body_is_a_noop() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let sender = f.committer.address().clone();
    {
        use chain_block::IBitstring;
        let mut body = chain_block::BuilderData::new();
        body.append_u32(0x4150_53FF).unwrap();
        body.append_u64(1).unwrap();
        f.send_from(&sender, body.into_cell().unwrap()).expect_exit_code(ERR_UNKNOWN_OP);
    }
    // An empty body from a non-minter (deploy, stray) is a no-op.
    f.send_from(&sender, Cell::default()).expect_success();
    assert_eq!(f.data().next_epoch, next_epoch);
}

// --- distributor-address derivation + the settle path (per-winner) ---

fn expected_distributor_init(
    settlement: &MsgAddressInt,
    winner_id: [u8; 32],
    epoch: u32,
    total_score: u128,
    pool: u64,
    score_root: [u8; 32],
) -> AipowDistributorInit {
    AipowDistributorInit {
        operator: settlement.clone(),
        epoch: epoch as u64,
        earner_workchain: EARNER_WC,
        total_score,
        pool,
        maturation: AipowMaturation::methodology_v0(),
        score_root,
        commitment_ref: winner_id,
    }
}

#[test]
fn derived_distributor_address_matches_a_real_deployment() {
    let mut f = Fixture::new();
    let committer = f.committer.address().clone();
    let settlement = f.settlement.clone();
    let epoch = f.next_epoch + 3;
    let winner = account_id(&committer);
    let total_score: u128 = 4_000_000;
    let score_root = [0x5C; 32];
    let pool = 7 * TOS;

    // An unregistered candidate has no derivable distributor.
    assert_eq!(f.derived_distributor(epoch, winner, pool), None, "no derivation before registration");

    f.send_from(&committer, AipowSettlementContract::register(1, epoch, score_root, total_score, 9 * TOS as u128).unwrap())
        .expect_success();

    let derived = f.derived_distributor(epoch, winner, pool).expect("derivable after registration");
    let init = expected_distributor_init(&settlement, winner, epoch, total_score, pool, score_root);
    let sdk_addr = AipowDistributorContract::calculate_address(EARNER_WC as i32, &init).unwrap();
    assert_eq!(derived, sdk_addr, "derived distributor address == real deployment address");

    let deployer = f.bc.treasury("dist-deployer", 100 * TOS).unwrap();
    let deploy = MessageBuilder::internal(deployer.address(), &sdk_addr, 13 * TOS)
        .bounce(false)
        .state_init(AipowDistributorContract::build_state_init(&init).unwrap())
        .body(Cell::default())
        .build();
    f.bc.send_message(deploy).expect("deploy").expect_success();
    let d = f.distributor_data(&derived);
    assert_eq!(d.epoch, epoch as u64);
    assert_eq!(d.total_score, total_score);
    assert_eq!(d.pool, pool);
}

#[test]
fn settle_deploys_and_funds_the_winners_distributor_and_advances_the_ledger() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let committer = f.committer.address().clone();
    let settlement = f.settlement.clone();
    let winner = account_id(&committer);
    let total_score: u128 = 3_000_000;
    let score_root = [0xA7; 32];
    let pool = 7 * TOS;

    f.send_from(&committer, AipowSettlementContract::register(1, next_epoch, score_root, total_score, 5 * TOS as u128).unwrap())
        .expect_success();
    let derived = f.derived_distributor(next_epoch, winner, pool).expect("derivable");
    assert_eq!(f.balance_of(&derived), 0, "distributor not yet deployed");

    // The mint from the minter naming the winner settles the cursor.
    f.mint(winner, pool).expect_success();

    let data = f.data();
    assert_eq!(data.next_epoch, next_epoch + 1, "cursor advanced");
    assert_eq!(data.minted_total, pool, "minted total recorded");

    let d = f.distributor_data(&derived);
    assert_eq!(d.version, contracts::AIPOW_DISTRIBUTOR_VERSION);
    assert_eq!(d.operator, settlement);
    assert_eq!(d.epoch, next_epoch as u64);
    assert_eq!(d.earner_workchain, EARNER_WC);
    assert_eq!(d.total_score, total_score);
    assert_eq!(d.pool, pool);
    assert_eq!(d.maturation, AipowMaturation::methodology_v0());
    assert_eq!(d.score_root, score_root);
    assert_eq!(d.commitment_ref, winner);
    let funded = f.balance_of(&derived);
    assert!(funded > pool * 9 / 10 && funded <= pool, "funded ~pool, got {funded}");
}

#[test]
fn a_settle_message_from_a_non_minter_does_not_settle() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let committer = f.committer.address().clone();
    let winner = account_id(&committer);

    f.send_from(&committer, AipowSettlementContract::register(1, next_epoch, [0xAB; 32], 1_000_000, 1).unwrap())
        .expect_success();
    // A winner-id body from a non-minter is a no-op (it parses as an unknown op,
    // not a settle -- only the authenticated minter settles).
    let r = f.settle_from(&committer, winner, 7 * TOS);
    // The non-minter's message is not a settle; the cursor is unchanged.
    let _ = r;
    assert_eq!(f.data().next_epoch, next_epoch, "cursor unchanged");
    assert_eq!(f.data().minted_total, 0, "nothing minted");
}

#[test]
fn a_mint_naming_an_unrecorded_winner_is_rejected() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    // No candidate for the cursor epoch: the mint throws (bounceable, returns the
    // value) rather than advancing the cursor.
    f.mint([0x11; 32], 7 * TOS).expect_exit_code(ERR_SETTLE_NO_REGISTRATION);
    assert_eq!(f.data().next_epoch, next_epoch, "cursor unchanged");
    assert_eq!(f.data().minted_total, 0);
}
