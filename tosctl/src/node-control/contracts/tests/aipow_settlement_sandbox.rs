/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) tests for the AIPoW settlement account (W4.1, part 1):
//! deployment + get-method inspection, the register path (first-wins, duplicate
//! rejection, zero-total-score rejection, an epoch behind the cursor rejected),
//! and the skip path (too-early rejection, a registered epoch not skippable,
//! and a permissionless skip advancing the cursor with zero mint past the grace
//! deadline). The settle/forward path is added in the next checkpoint.

use chain_block::{BuilderData, Cell, MsgAddressInt};
use contracts::{AipowSettlementContract, AipowSettlementInit};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

const TOS: u64 = 1_000_000_000;
const EPOCH_SECONDS: u32 = 65_536;
const REGISTER_GRACE: u32 = 3600;
const TOTAL_CAP: u64 = 4_500_000_000 * TOS;

const ERR_EPOCH_SETTLED: i32 = 2301;
const ERR_ALREADY_REGISTERED: i32 = 2302;
const ERR_ZERO_TOTAL_SCORE: i32 = 2303;
const ERR_SKIP_TOO_EARLY: i32 = 2304;
const ERR_SKIP_REGISTERED: i32 = 2305;
const ERR_UNKNOWN_OP: i32 = 2307;

fn dummy_distributor_code() -> Cell {
    BuilderData::with_raw(vec![0xD1], 8).unwrap().into_cell().unwrap()
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
            total_cap: TOTAL_CAP,
            distributor_code: dummy_distributor_code(),
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
