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
        let msg = MessageBuilder::internal(from, &self.settlement, TOS / 10).body(body).build();
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

    fn registration(&self, epoch: u32) -> Option<contracts::AipowRegistration> {
        let arg = vec![tos_vm::stack::StackItem::int(epoch as i64)];
        let stack = self
            .bc
            .run_get_method(&self.settlement, "get_registration", arg)
            .expect("get_registration")
            .expect_success()
            .stack
            .clone();
        AipowSettlementContract::decode_registration(&Self::parse_stack(&stack))
            .expect("decode_registration")
    }

    /// The distributor address the settle path would deploy for `epoch` funded
    /// with `pool`, per the settlement's own on-chain derivation.
    fn derived_distributor(&self, epoch: u32, pool: u64) -> Option<MsgAddressInt> {
        let arg = vec![
            tos_vm::stack::StackItem::int(epoch as i64),
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

    /// The masterchain minter delivers the epoch pool as an empty-body value
    /// message; this is the authenticated settle trigger.
    fn mint(&mut self, value: u64) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(&minter(), &self.settlement, value)
            .body(Cell::default())
            .build();
        self.bc.send_message(msg).expect("mint")
    }

    /// Send an empty-body value message from an arbitrary (non-minter) sender.
    fn value_from(&mut self, from: &MsgAddressInt, value: u64) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(from, &self.settlement, value).body(Cell::default()).build();
        self.bc.send_message(msg).expect("send")
    }
}

/// The 256-bit account id of a standard address (its `commitment_ref`).
fn account_id(addr: &MsgAddressInt) -> [u8; 32] {
    addr.address().get_bytestring(0).try_into().expect("32-byte account id")
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
    assert_eq!(f.registration(next_epoch), None, "no registrations at deploy");
}

#[test]
fn register_records_the_first_nomination_per_epoch() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let committer = f.committer.address().clone();

    // A commitment nominates itself for a future epoch with its committed tuple.
    f.send_from(&committer, AipowSettlementContract::register(1, next_epoch + 5, [0xAB; 32], 1_000_000, 42 * TOS as u128).unwrap())
        .expect_success();
    let reg = f.registration(next_epoch + 5).expect("registered");
    assert_eq!(&reg.commitment_addr, f.committer.address());
    assert_eq!(reg.score_root, [0xAB; 32]);
    assert_eq!(reg.total_score, 1_000_000);
    assert_eq!(reg.organic_settled_value, 42 * TOS as u128);

    // A second nomination for the same epoch is rejected (first-wins).
    f.send_from(&committer, AipowSettlementContract::register(2, next_epoch + 5, [0xCD; 32], 2_000_000, 1).unwrap())
        .expect_exit_code(ERR_ALREADY_REGISTERED);
    // The first nomination is untouched.
    assert_eq!(f.registration(next_epoch + 5).unwrap().score_root, [0xAB; 32]);
}

#[test]
fn register_rejects_settled_epoch_and_zero_total_score() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let committer = f.committer.address().clone();

    // An epoch the cursor has already passed cannot be nominated.
    f.send_from(&committer, AipowSettlementContract::register(1, next_epoch - 1, [0xAB; 32], 1_000_000, 1).unwrap())
        .expect_exit_code(ERR_EPOCH_SETTLED);
    // A zero denominator is rejected.
    f.send_from(&committer, AipowSettlementContract::register(2, next_epoch, [0xAB; 32], 0, 1).unwrap())
        .expect_exit_code(ERR_ZERO_TOTAL_SCORE);
    assert_eq!(f.registration(next_epoch), None);
}

#[test]
fn skip_advances_the_cursor_with_zero_mint_past_the_deadline() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let poker = f.committer.address().clone();

    // Before the grace deadline the epoch at the cursor cannot be skipped.
    // Epoch next_epoch ends at (next_epoch+1)*EPOCH_SECONDS; it is skippable at
    // that plus REGISTER_GRACE.
    let skippable_at = (next_epoch + 1) as u64 * EPOCH_SECONDS as u64 + REGISTER_GRACE as u64;
    f.bc.set_now((skippable_at - 1) as u32);
    f.send_from(&poker, AipowSettlementContract::skip(1).unwrap())
        .expect_exit_code(ERR_SKIP_TOO_EARLY);
    assert_eq!(f.data().next_epoch, next_epoch);

    // Past the deadline, permissionlessly skip: the cursor advances, minted
    // total is untouched.
    f.bc.set_now(skippable_at as u32);
    f.send_from(&poker, AipowSettlementContract::skip(2).unwrap()).expect_success();
    assert_eq!(f.data().next_epoch, next_epoch + 1);
    assert_eq!(f.data().minted_total, 0);
}

#[test]
fn skip_is_rejected_when_the_cursor_epoch_has_a_registration() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let committer = f.committer.address().clone();

    // Register the epoch at the cursor, then try to skip it past the deadline.
    f.send_from(&committer, AipowSettlementContract::register(1, next_epoch, [0xAB; 32], 1_000_000, 1).unwrap())
        .expect_success();
    let skippable_at = (next_epoch + 1) as u64 * EPOCH_SECONDS as u64 + REGISTER_GRACE as u64;
    f.bc.set_now(skippable_at as u32);
    f.send_from(&committer, AipowSettlementContract::skip(2).unwrap())
        .expect_exit_code(ERR_SKIP_REGISTERED);
    assert_eq!(f.data().next_epoch, next_epoch);
}

#[test]
fn unknown_op_rejected_empty_body_is_a_noop() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let sender = f.committer.address().clone();

    // Unknown opcode throws.
    {
        use chain_block::IBitstring;
        let mut body = chain_block::BuilderData::new();
        body.append_u32(0x4150_53FF).unwrap();
        body.append_u64(1).unwrap();
        f.send_from(&sender, body.into_cell().unwrap()).expect_exit_code(ERR_UNKNOWN_OP);
    }
    // Empty body is a no-op in this checkpoint (it also covers the deploy
    // message); the cursor is unchanged. It becomes the settle path later.
    f.send_from(&sender, Cell::default()).expect_success();
    assert_eq!(f.data().next_epoch, next_epoch);
}

// --- W4.1 part 3: distributor-address derivation + the settle path ---

/// Build the distributor the settlement should derive/deploy for `epoch`,
/// funded with `pool`, from the same inputs the settle path uses: operator is
/// the settlement account, the epoch tuple is the registration, and the
/// maturation/earner-workchain are the settlement's snapshot.
fn expected_distributor_init(
    settlement: &MsgAddressInt,
    committer: &MsgAddressInt,
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
        commitment_ref: account_id(committer),
    }
}

#[test]
fn derived_distributor_address_matches_a_real_deployment() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let committer = f.committer.address().clone();
    let settlement = f.settlement.clone();
    let epoch = next_epoch + 3;
    let total_score: u128 = 4_000_000;
    let score_root = [0x5C; 32];
    let pool = 7 * TOS;

    // An unregistered epoch has no derivable distributor.
    assert_eq!(f.derived_distributor(epoch, pool), None, "no derivation before registration");

    f.send_from(&committer, AipowSettlementContract::register(1, epoch, score_root, total_score, 9 * TOS as u128).unwrap())
        .expect_success();

    // The settlement's on-chain derivation must equal the address a real
    // deployment of the audited distributor SDK produces from the same inputs.
    let derived = f.derived_distributor(epoch, pool).expect("derivable after registration");
    let init = expected_distributor_init(&settlement, &committer, epoch, total_score, pool, score_root);
    let sdk_addr = AipowDistributorContract::calculate_address(EARNER_WC as i32, &init).unwrap();
    assert_eq!(derived, sdk_addr, "derived distributor address == real deployment address");

    // And deploying that init really does land a working distributor there.
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
fn settle_deploys_and_funds_the_derived_distributor_and_advances_the_ledger() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let committer = f.committer.address().clone();
    let settlement = f.settlement.clone();
    let total_score: u128 = 3_000_000;
    let score_root = [0xA7; 32];
    let pool = 7 * TOS;

    // Register the epoch at the cursor, then mint its pool from the minter.
    f.send_from(&committer, AipowSettlementContract::register(1, next_epoch, score_root, total_score, 5 * TOS as u128).unwrap())
        .expect_success();
    let derived = f.derived_distributor(next_epoch, pool).expect("derivable");
    assert_eq!(f.balance_of(&derived), 0, "distributor not yet deployed");

    // The mint (empty body, value = pool, from -1:00..00) settles the cursor.
    f.mint(pool).expect_success();

    // Ledger advanced exactly once; the cap tracker recorded the pool.
    let data = f.data();
    assert_eq!(data.next_epoch, next_epoch + 1, "cursor advanced");
    assert_eq!(data.minted_total, pool, "minted total recorded");

    // The distributor was deployed at the derived address with the registration
    // tuple and the settlement's snapshot, and funded with ~the pool.
    let d = f.distributor_data(&derived);
    assert_eq!(d.version, contracts::AIPOW_DISTRIBUTOR_VERSION);
    assert_eq!(d.operator, settlement);
    assert_eq!(d.epoch, next_epoch as u64);
    assert_eq!(d.earner_workchain, EARNER_WC);
    assert_eq!(d.total_score, total_score);
    assert_eq!(d.pool, pool);
    assert_eq!(d.maturation, AipowMaturation::methodology_v0());
    assert_eq!(d.score_root, score_root);
    assert_eq!(d.commitment_ref, account_id(&committer));
    let funded = f.balance_of(&derived);
    assert!(funded > pool * 9 / 10 && funded <= pool, "funded ~pool, got {funded}");
}

#[test]
fn a_value_message_from_a_non_minter_does_not_settle() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let committer = f.committer.address().clone();

    f.send_from(&committer, AipowSettlementContract::register(1, next_epoch, [0xAB; 32], 1_000_000, 1).unwrap())
        .expect_success();
    // An empty-body value message from a non-minter is a no-op: only the
    // authenticated minter triggers settlement.
    f.value_from(&committer, 7 * TOS).expect_success();
    assert_eq!(f.data().next_epoch, next_epoch, "cursor unchanged");
    assert_eq!(f.data().minted_total, 0, "nothing minted");
    assert_eq!(f.derived_distributor(next_epoch, 7 * TOS).map(|a| f.balance_of(&a)), Some(0));
}

#[test]
fn a_mint_for_an_unregistered_cursor_epoch_is_rejected() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    // No registration for the cursor epoch: the mint throws (and, being
    // bounceable, returns the value) rather than advancing the cursor.
    f.mint(7 * TOS).expect_exit_code(ERR_SETTLE_NO_REGISTRATION);
    assert_eq!(f.data().next_epoch, next_epoch, "cursor unchanged");
    assert_eq!(f.data().minted_total, 0);
}
