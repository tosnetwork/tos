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

use chain_block::{BuilderData, Cell, MsgAddressInt, Serializable, StateInit};
use contracts::{
    AipowDistributorContract, AipowDistributorInit, AipowMaturation, AipowSettlementContract,
    AipowSettlementInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

const TOS: u64 = 1_000_000_000;
const EPOCH_SECONDS: u32 = 65_536;
const REGISTER_GRACE: u32 = 3600;
const CHALLENGE_WINDOW: u32 = 900;  // < REGISTER_GRACE (deploy invariant)
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
const ERR_CANDIDATE_SET_FULL: i32 = 2309;
const ERR_EPOCH_TOO_FAR: i32 = 2310;
const ERR_CURSOR_EXHAUSTED: i32 = 2311;
const ERR_UNAUTHORIZED_REGISTRATION: i32 = 2312;
const ERR_INSUFFICIENT_BOND: i32 = 2313;
const ERR_TOO_LATE_TO_REGISTER: i32 = 2314;
const ERR_ZERO_SCORE_ROOT: i32 = 2315;
const ERR_WRONG_WORKCHAIN: i32 = 2316;

/// Mirrors the contract's REGISTER_HORIZON: the furthest future epoch, relative
/// to the cursor, a registration may target.
const REGISTER_HORIZON: u32 = 1024;

/// The audited distributor code the settlement derives addresses against and
/// deploys. Using the real code (not a stub) is what makes the derived address
/// equal a genuine distributor deployment.
fn distributor_code() -> Cell {
    AipowDistributorContract::code().unwrap()
}

/// The "audited" commitment code the settlement stores and authenticates
/// nominators against (H1). The settlement never runs or parses it -- it only
/// checks sender == hash(StateInit(commitment_code, data)) -- so any fixed cell
/// serves here.
fn commitment_code() -> Cell {
    BuilderData::with_raw(vec![0xC0, 0xDE], 16).unwrap().into_cell().unwrap()
}

/// An authorised nominator: (address, data) whose address is the canonical
/// commitment address hash(StateInit(commitment_code, data)). Distinct `seed`s give
/// distinct data, hence distinct addresses; the settlement accepts a register from
/// `address` carrying `data`. (Sending from the same seed twice models one
/// commitment re-nominating.)
fn nominator(seed: u64) -> (MsgAddressInt, Cell) {
    let data = BuilderData::with_raw(seed.to_be_bytes().to_vec(), 64).unwrap().into_cell().unwrap();
    let si = StateInit::with_code_and_data(commitment_code(), data.clone());
    let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    let address = MsgAddressInt::with_params(-1, hash).unwrap();
    (address, data)
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
        // Anchor the cursor at the current wall-clock epoch so the skip deadline
        // sits ahead of the sandbox clock (time must move forward, not back).
        Self::with_next_epoch(None)
    }

    /// Deploy with an explicit cursor epoch (used to reach the uint32 ceiling for
    /// the cursor-exhaustion guard); `None` anchors it at the wall-clock epoch.
    fn with_next_epoch(next_epoch: Option<u32>) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let deployer = bc.treasury("aipow-settlement-deployer", 1_000 * TOS).expect("deployer");
        let committer = bc.treasury("aipow-settlement-committer", 1_000 * TOS).expect("committer");
        let next_epoch = next_epoch.unwrap_or_else(|| bc.now() / EPOCH_SECONDS);
        let init = AipowSettlementInit {
            next_epoch,
            epoch_seconds: EPOCH_SECONDS,
            register_grace: REGISTER_GRACE,
            challenge_window: CHALLENGE_WINDOW,
            earner_workchain: EARNER_WC,
            maturation: AipowMaturation::methodology_v0(),
            total_cap: TOTAL_CAP,
            distributor_code: distributor_code(),
            commitment_code: commitment_code(),
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
        self.send_from_value(from, body, TOS)
    }

    fn send_from_value(&mut self, from: &MsgAddressInt, body: Cell, value: u64) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(from, &self.settlement, value).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    /// Send an authenticated register from nominator `nom` = (canonical address,
    /// data): the body carries `nom.data`, so the settlement's H1 check
    /// (sender == hash(StateInit(commitment_code, data))) passes.
    #[allow(clippy::too_many_arguments)]
    fn register(&mut self, nom: &(MsgAddressInt, Cell), query_id: u64, epoch: u32, score_root: [u8; 32],
                total_score: u128, organic: u128, value: u64) -> tos_sandbox::SendResult {
        let body =
            AipowSettlementContract::register(query_id, epoch, score_root, total_score, organic, nom.1.clone())
                .unwrap();
        let msg = MessageBuilder::internal(&nom.0, &self.settlement, value).body(body).build();
        self.bc.send_message(msg).expect("register")
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
    assert_eq!(data.challenge_window, CHALLENGE_WINDOW);
    assert_eq!(data.minted_total, 0);
    assert_eq!(data.total_cap, TOTAL_CAP);
    assert_eq!(f.candidate_count(next_epoch), 0, "no candidates at deploy");
    assert_eq!(f.min_candidate(next_epoch), None);
}

#[test]
fn register_records_multiple_candidates_and_dedups_per_commitment() {
    let mut f = Fixture::new();
    let epoch = f.next_epoch + 5;
    let a = nominator(1);
    let b = nominator(2);

    // Two different commitments nominate the SAME epoch -- both are candidates
    // (no first-wins). A bogus nomination cannot exclude a genuine one.
    f.register(&a, 1, epoch, [0xAB; 32], 1_000_000, 42 * TOS as u128, TOS).expect_success();
    f.register(&b, 2, epoch, [0xCD; 32], 2_000_000, 7, TOS).expect_success();
    assert_eq!(f.candidate_count(epoch), 2);

    let ca = f.candidate(epoch, account_id(&a.0)).expect("a is a candidate");
    assert_eq!(ca.score_root, [0xAB; 32]);
    assert_eq!(ca.total_score, 1_000_000);
    assert_eq!(ca.organic_settled_value, 42 * TOS as u128);
    let cb = f.candidate(epoch, account_id(&b.0)).expect("b is a candidate");
    assert_eq!(cb.score_root, [0xCD; 32]);

    // A single commitment (same address) may nominate an epoch at most once.
    f.register(&a, 3, epoch, [0xEE; 32], 5, 5, TOS).expect_exit_code(ERR_ALREADY_REGISTERED);
    assert_eq!(f.candidate_count(epoch), 2);
    // The first nomination is untouched.
    assert_eq!(f.candidate(epoch, account_id(&a.0)).unwrap().score_root, [0xAB; 32]);
}

#[test]
fn register_rejects_settled_epoch_and_zero_total_score() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let n = nominator(1);

    // epoch_settled and zero_total_score are checked before the H1 auth, so a
    // canonical nominator still trips them.
    f.register(&n, 1, next_epoch - 1, [0xAB; 32], 1_000_000, 1, TOS).expect_exit_code(ERR_EPOCH_SETTLED);
    f.register(&n, 2, next_epoch, [0xAB; 32], 0, 1, TOS).expect_exit_code(ERR_ZERO_TOTAL_SCORE);
    assert_eq!(f.candidate_count(next_epoch), 0);
}

#[test]
fn register_rejects_a_bond_below_the_minimum() {
    // H1 economic close: a nomination must lock at least MIN_REGISTRATION_BOND
    // (0.5 TOS), so grinding many junk candidates to evict a genuine one costs at
    // least that per slot per epoch.
    let mut f = Fixture::new();
    let epoch = f.next_epoch;
    let n = nominator(1);
    f.register(&n, 1, epoch, [0xAB; 32], 1_000_000, 1, 4 * TOS / 10)
        .expect_exit_code(ERR_INSUFFICIENT_BOND); // 0.4 TOS < 0.5
    assert_eq!(f.candidate_count(epoch), 0, "no candidate admitted below the bond");
    f.register(&n, 2, epoch, [0xAB; 32], 1_000_000, 1, TOS).expect_success();
    assert_eq!(f.candidate_count(epoch), 1);
}

#[test]
fn register_rejects_a_nomination_too_late_for_its_challenge_window() {
    // H2: a nomination whose challenge window would not elapse before the epoch
    // becomes skippable is rejected, so a genuine but late candidate can never be
    // stranded by a skip that fires while it is still inside its provenance window.
    let mut f = Fixture::new();
    let epoch = f.next_epoch;
    let n = nominator(1);
    let skippable_at = (epoch + 1) as u64 * EPOCH_SECONDS as u64 + REGISTER_GRACE as u64;
    // At the cutoff the window just fits (boundary is inclusive: now + window == deadline).
    f.bc.set_now((skippable_at - CHALLENGE_WINDOW as u64) as u32);
    f.register(&n, 1, epoch, [0xAB; 32], 1_000_000, 1, TOS).expect_success();
    assert_eq!(f.candidate_count(epoch), 1);
    // One second later the window would end after the skip deadline -> too late.
    let late = nominator(2);
    f.bc.set_now((skippable_at - CHALLENGE_WINDOW as u64 + 1) as u32);
    f.register(&late, 1, epoch, [0xAB; 32], 1_000_000, 1, TOS).expect_exit_code(ERR_TOO_LATE_TO_REGISTER);
    assert_eq!(f.candidate_count(epoch), 1, "the late nomination is not admitted");
}

#[test]
fn register_rejects_a_zero_score_root() {
    // Round-4: a zero score root is reserved (unclaimable pool), kept out of the set.
    let mut f = Fixture::new();
    let epoch = f.next_epoch;
    let n = nominator(1);
    f.register(&n, 1, epoch, [0u8; 32], 1_000_000, 1, TOS).expect_exit_code(ERR_ZERO_SCORE_ROOT);
    assert_eq!(f.candidate_count(epoch), 0);
}

#[test]
fn register_rejects_a_non_masterchain_nominator() {
    // Round-4: candidates are masterchain-only (both native resolvers reject wc != -1),
    // so a canonically-addressed but wc-0 commitment cannot occupy a candidate slot.
    let mut f = Fixture::new();
    let epoch = f.next_epoch;
    let (_, data) = nominator(1);
    // Same canonical account id, but on workchain 0 instead of -1.
    let si = StateInit::with_code_and_data(commitment_code(), data.clone());
    let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    let wc0 = MsgAddressInt::with_params(0, hash).unwrap();
    let body = AipowSettlementContract::register(1, epoch, [0xAB; 32], 1_000_000, 1, data).unwrap();
    f.send_from_value(&wc0, body, TOS).expect_exit_code(ERR_WRONG_WORKCHAIN);
    assert_eq!(f.candidate_count(epoch), 0);
}

#[test]
fn register_rejects_a_non_canonical_sender() {
    // H1: a plain account (not deployed with the audited commitment code, so its
    // address is not hash(StateInit(commitment_code, data))) cannot occupy a
    // candidate slot, even presenting some data cell -- junk wallets can no longer
    // evict a genuine nomination.
    let mut f = Fixture::new();
    let epoch = f.next_epoch;
    let impostor = f.committer.address().clone();  // a wallet, not a canonical commitment
    let body = AipowSettlementContract::register(1, epoch, [0xAB; 32], 1_000_000, 1, commitment_code()).unwrap();
    // Carry a sufficient bond so the auth check (not the bond check) is what rejects.
    f.send_from_value(&impostor, body, TOS).expect_exit_code(ERR_UNAUTHORIZED_REGISTRATION);
    assert_eq!(f.candidate_count(epoch), 0, "no candidate admitted");
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
    let attacker = nominator(1);
    f.register(&attacker, 1, next_epoch, [0xBA; 32], 1_000_000, 1, TOS).expect_success();
    assert_eq!(f.candidate_count(next_epoch), 1);
    let skippable_at = (next_epoch + 1) as u64 * EPOCH_SECONDS as u64 + REGISTER_GRACE as u64;
    f.bc.set_now(skippable_at as u32);
    // skip is permissionless (no auth), so any address may poke it.
    let poker = f.committer.address().clone();
    f.send_from(&poker, AipowSettlementContract::skip(2).unwrap()).expect_success();
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
    for i in 0..9u64 {
        let c = nominator(100 + i);  // distinct canonical commitments
        ids.push(account_id(&c.0));
        // A larger candidate set costs more gas per insert on masterchain, so
        // fund these registrations generously.
        // score_root must be non-zero (round-4 zero-root rejection); vary by i+1.
        let r = f.register(&c, i, epoch, [(i + 1) as u8; 32], 1_000, 1, 2 * TOS);
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
fn the_cursor_epochs_candidate_bucket_is_frozen_against_eviction() {
    // A full candidate bucket for the CURSOR epoch (epoch == next_epoch) must not
    // evict its current maximum mid-block. The collator derives the epoch's mint from
    // the pre-block candidate set and the mandatory settle names that winner; a
    // same-block registration that evicted it would strand the settle
    // (settle_no_registration) and force an invalid block (produce/check divergence).
    // For the cursor epoch a full set therefore rejects any new nomination -- even a
    // smaller address that would normally evict the maximum -- leaving the bucket
    // untouched. (Future-epoch buckets still evict; that lands in pre-block state and
    // both collator and validator derive it identically.)
    let mut f = Fixture::new();
    let epoch = f.next_epoch; // the cursor epoch: eligible to be minted in the block
    let mut ids: Vec<[u8; 32]> = Vec::new();
    for i in 0..8u64 {
        let c = nominator(200 + i);
        ids.push(account_id(&c.0));
        f.register(&c, i, epoch, [(i + 1) as u8; 32], 1_000, 1, 2 * TOS).expect_success();
    }
    assert_eq!(f.candidate_count(epoch), 8);
    ids.sort();
    let max_before = ids[7];

    // A ninth canonical commitment whose address is SMALLER than the current maximum
    // would evict that maximum for a FUTURE epoch. For the cursor epoch it is rejected
    // as full instead, and the pre-state winner is preserved.
    let smaller = (300..400u64)
        .map(nominator)
        .find(|c| account_id(&c.0) < max_before)
        .expect("a smaller-address canonical commitment exists among the seeds");
    f.register(&smaller, 99, epoch, [0x7F; 32], 1_000, 1, 2 * TOS)
        .expect_exit_code(ERR_CANDIDATE_SET_FULL);

    // The bucket is completely unchanged: same eight members, the maximum still present,
    // the late nomination excluded.
    assert_eq!(f.candidate_count(epoch), 8);
    assert!(
        f.candidate(epoch, max_before).is_some(),
        "the pre-state winner (max address) is NOT evicted for the cursor epoch"
    );
    assert!(
        f.candidate(epoch, account_id(&smaller.0)).is_none(),
        "the late same-epoch nomination did not enter the bucket"
    );
    for id in &ids {
        assert!(f.candidate(epoch, *id).is_some(), "every original cursor-epoch candidate is retained");
    }
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
    let n = nominator(1);
    let settlement = f.settlement.clone();
    let epoch = f.next_epoch + 3;
    let winner = account_id(&n.0);
    let total_score: u128 = 4_000_000;
    let score_root = [0x5C; 32];
    let pool = 7 * TOS;

    // An unregistered candidate has no derivable distributor.
    assert_eq!(f.derived_distributor(epoch, winner, pool), None, "no derivation before registration");

    f.register(&n, 1, epoch, score_root, total_score, 9 * TOS as u128, TOS).expect_success();

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
    let n = nominator(1);
    let settlement = f.settlement.clone();
    let winner = account_id(&n.0);
    let total_score: u128 = 3_000_000;
    let score_root = [0xA7; 32];
    let pool = 7 * TOS;

    f.register(&n, 1, next_epoch, score_root, total_score, 5 * TOS as u128, TOS).expect_success();
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
    let n = nominator(1);
    let winner = account_id(&n.0);

    f.register(&n, 1, next_epoch, [0xAB; 32], 1_000_000, 1, TOS).expect_success();
    // A winner-id body from a non-minter is a no-op (it parses as an unknown op,
    // not a settle -- only the authenticated minter settles).
    let impostor = f.committer.address().clone();
    let r = f.settle_from(&impostor, winner, 7 * TOS);
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

// --- H4: bounded future horizon + pruning settled/skipped buckets ---

#[test]
fn register_rejects_epochs_beyond_the_horizon() {
    // Registration for a far-future epoch is capped so it cannot create unbounded
    // registrations state. The last epoch inside the horizon is accepted; the
    // first one at/after it is rejected.
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let a = nominator(1);
    let b = nominator(2);

    let last_in = next_epoch + REGISTER_HORIZON - 1;
    f.register(&a, 1, last_in, [0xAB; 32], 1, 1, 2 * TOS).expect_success();
    assert_eq!(f.candidate_count(last_in), 1);

    let too_far = next_epoch + REGISTER_HORIZON;
    f.register(&b, 2, too_far, [0xCD; 32], 1, 1, 2 * TOS).expect_exit_code(ERR_EPOCH_TOO_FAR);
    assert_eq!(f.candidate_count(too_far), 0);
}

#[test]
fn settle_prunes_the_settled_epochs_candidate_bucket() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let n = nominator(1);
    let winner = account_id(&n.0);
    let pool = 7 * TOS;

    f.register(&n, 1, next_epoch, [0xA7; 32], 3_000_000, 5 * TOS as u128, TOS).expect_success();
    assert_eq!(f.candidate_count(next_epoch), 1);

    f.mint(winner, pool).expect_success();
    assert_eq!(f.data().next_epoch, next_epoch + 1, "cursor advanced");
    // The settled epoch's candidate bucket is pruned: the cursor never returns to
    // it, so retaining it would only grow the state.
    assert_eq!(f.candidate_count(next_epoch), 0, "settled epoch bucket pruned");
    assert_eq!(f.min_candidate(next_epoch), None);
}

#[test]
fn skip_prunes_the_skipped_epochs_candidate_bucket() {
    let mut f = Fixture::new();
    let next_epoch = f.next_epoch;
    let attacker = nominator(1);
    // A bogus nomination for the cursor epoch.
    f.register(&attacker, 1, next_epoch, [0xBA; 32], 1_000_000, 1, TOS).expect_success();
    assert_eq!(f.candidate_count(next_epoch), 1);

    let skippable_at = (next_epoch + 1) as u64 * EPOCH_SECONDS as u64 + REGISTER_GRACE as u64;
    f.bc.set_now(skippable_at as u32);
    let poker = f.committer.address().clone();
    f.send_from(&poker, AipowSettlementContract::skip(2).unwrap()).expect_success();
    assert_eq!(f.data().next_epoch, next_epoch + 1);
    // The skipped epoch's (bogus) bucket is pruned too.
    assert_eq!(f.candidate_count(next_epoch), 0, "skipped epoch bucket pruned");
}

// --- L2: the uint32 cursor cannot wrap ---

#[test]
fn cursor_exhausted_halts_settle_and_skip_at_the_max_epoch() {
    // At the uint32 ceiling `next_epoch + 1` would overflow the 32-bit cursor
    // field; both settle and skip fail closed with a clear terminal error rather
    // than raising a raw range-check exception (or wrapping to epoch 0).
    let mut f = Fixture::with_next_epoch(Some(u32::MAX));
    let n = nominator(1);
    let winner = account_id(&n.0);

    // skip halts immediately (the guard precedes the deadline computation, which
    // would otherwise overflow into an unreachable time).
    let poker = f.committer.address().clone();
    f.send_from(&poker, AipowSettlementContract::skip(1).unwrap())
        .expect_exit_code(ERR_CURSOR_EXHAUSTED);
    assert_eq!(f.data().next_epoch, u32::MAX, "cursor unchanged");

    // A registered candidate at the ceiling epoch resolves, but the settle still
    // refuses to advance past the ceiling.
    f.register(&n, 2, u32::MAX, [0xA7; 32], 3_000_000, 5 * TOS as u128, 2 * TOS).expect_success();
    f.mint(winner, 7 * TOS).expect_exit_code(ERR_CURSOR_EXHAUSTED);
    assert_eq!(f.data().next_epoch, u32::MAX, "cursor still unchanged");
    assert_eq!(f.data().minted_total, 0, "nothing minted");
}
