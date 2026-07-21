/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) lifecycle tests for the Service Actor contract.
//!
//! These execute the compiled contract embedded in `ServiceActorContract`
//! against the in-process executor: deployment and get-method inspection,
//! access-policy gating (open vs. single authorized caller), payment
//! enforcement and revenue accounting, daily rate limiting, owner-signed
//! response commitments, owner-authorized revenue withdrawal, and the
//! deactivate/reactivate lifecycle -- plus the unauthorized/illegal
//! rejections for each.

use chain_block::{Cell, MsgAddressInt};
use contracts::{ServiceActorContract, ServiceActorInit};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

const TOS: u64 = 1_000_000_000;
const ERR_NOT_OWNER: i32 = 1900;
const ERR_NOT_AUTHORIZED: i32 = 1901;
const ERR_INACTIVE: i32 = 1902;
const ERR_ALREADY_ACTIVE: i32 = 1903;
const ERR_RATE_LIMITED: i32 = 1904;
const ERR_INSUFFICIENT_PAYMENT: i32 = 1905;
const ERR_INSUFFICIENT_REVENUE: i32 = 1906;
const ERR_BAD_RESPONSE_SIGNATURE: i32 = 1909;
const ERR_ATTESTOR_FROZEN: i32 = 1910;
const ERR_RESPONSE_PENDING: i32 = 1911;
const ERR_NO_PENDING_RESPONSE: i32 = 1912;

struct Fixture {
    bc: Blockchain,
    owner: Treasury,
    caller: Treasury,
    outsider: Treasury,
    service: MsgAddressInt,
}

impl Fixture {
    fn new(
        price_per_call: u64,
        rate_limit_per_day: u32,
        open_access: bool,
        funding: u64,
    ) -> Self {
        Self::build(price_per_call, rate_limit_per_day, open_access, funding, None)
    }

    fn with_attestor(
        price_per_call: u64,
        rate_limit_per_day: u32,
        open_access: bool,
        funding: u64,
        attestor_pubkey: [u8; 32],
    ) -> Self {
        Self::build(price_per_call, rate_limit_per_day, open_access, funding, Some(attestor_pubkey))
    }

    fn build(
        price_per_call: u64,
        rate_limit_per_day: u32,
        open_access: bool,
        funding: u64,
        attestor_pubkey: Option<[u8; 32]>,
    ) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let owner = bc.treasury("owner", 1_000 * TOS).expect("owner");
        let caller = bc.treasury("caller", 1_000 * TOS).expect("caller");
        let outsider = bc.treasury("outsider", 1_000 * TOS).expect("outsider");
        let init = ServiceActorInit {
            owner: owner.address().clone(),
            authorized_caller: (!open_access).then(|| caller.address().clone()),
            open_access,
            price_per_call,
            rate_limit_per_day,
            metadata_hash: [0x11; 32],
            proof_scheme_hash: [0x22; 32],
            attestor_pubkey,
        };
        let service = ServiceActorContract::calculate_address(-1, &init).expect("address");
        let state_init = ServiceActorContract::build_state_init(&init).expect("state init");
        let deploy = MessageBuilder::internal(owner.address(), &service, funding)
            .bounce(false)
            .state_init(state_init)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, owner, caller, outsider, service }
    }

    fn send_from(&mut self, from: &MsgAddressInt, value: u64, body: Cell) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(from, &self.service, value).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    fn data(&self) -> contracts::ServiceActorData {
        let stack = self
            .bc
            .run_get_method(&self.service, "get_service_actor_data", vec![])
            .expect("get_service_actor_data")
            .expect_success()
            .stack
            .clone();
        let entries = stack
            .iter()
            .map(sandbox_stack_item_to_entry)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("stack conversion");
        ServiceActorContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(entries))
            .expect("decode_data")
    }

    fn balance(&self, addr: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(addr)
            .and_then(|acc| acc.balance().and_then(|cc| cc.coins.as_u64()))
            .unwrap_or(0)
    }
}

/// Mirrors the equivalent helper in `capability_registry_sandbox.rs` /
/// `service::http::agent_query_api`'s test module: converts a real sandbox
/// VM stack item into the wire `StackEntry` shape `TvmStackParser` expects.
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
    let f = Fixture::new(TOS / 10, 5, false, TOS / 10);
    let data = f.data();
    assert_eq!(data.owner, f.owner.address().clone());
    assert_eq!(data.authorized_caller, Some(f.caller.address().clone()));
    assert!(!data.open_access);
    assert!(data.active);
    assert_eq!(data.price_per_call, TOS / 10);
    assert_eq!(data.rate_limit_per_day, 5);
    assert_eq!(data.calls_today, 0);
    assert_eq!(data.total_revenue, 0);
    assert_eq!(data.metadata_hash, [0x11; 32]);
    assert_eq!(data.proof_scheme_hash, [0x22; 32]);
}

#[test]
fn authorized_caller_can_call_outsider_rejected() {
    let mut f = Fixture::new(TOS / 10, 0, false, TOS / 10);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, TOS / 5, ServiceActorContract::call(1, [0xAA; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_AUTHORIZED);

    // The caller overpays (TOS / 5 against a TOS / 10 price): only the
    // quoted price is revenue, the rest is refunded (see
    // call_refunds_the_excess_when_the_caller_overpays). The sandbox harness
    // credits a message's value to the destination without ever debiting the
    // sender treasury for the outbound send itself, so the caller's balance
    // here only ever *increases*, by exactly the TOS / 10 refund it receives
    // back.
    let caller = f.caller.address().clone();
    let caller_before = f.balance(&caller);
    f.send_from(&caller, TOS / 5, ServiceActorContract::call(2, [0xAA; 32]).unwrap())
        .expect_success();
    let data = f.data();
    assert_eq!(data.calls_today, 1);
    assert_eq!(data.total_revenue, TOS / 10);
    assert_eq!(data.last_request_hash, [0xAA; 32]);
    let caller_delta = f.balance(&caller) - caller_before;
    assert!(
        caller_delta > TOS / 10 - TOS / 100 && caller_delta <= TOS / 10,
        "caller should have received close to the TOS / 10 overpayment back as a refund, got {caller_delta}"
    );
}

#[test]
fn call_refunds_the_excess_when_the_caller_overpays() {
    // Only `price_per_call` is revenue; a caller who sends more than that
    // (rounding, a wallet's gas-margin padding, a client bug) gets the
    // difference refunded rather than permanently losing it to the owner.
    let mut f = Fixture::new(TOS / 10, 0, true, TOS / 10);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();
    let outsider_before = f.balance(&outsider);
    f.send_from(&outsider, TOS, ServiceActorContract::call(1, [0xAA; 32]).unwrap())
        .expect_success();
    assert_eq!(f.data().total_revenue, TOS / 10, "only the quoted price is revenue");
    // The sandbox harness credits a message's value to the destination
    // without ever debiting the sender treasury for the outbound send
    // itself, so the caller's balance here only ever *increases*, by
    // exactly the 0.9 TOS overpayment (TOS sent - TOS / 10 price) it
    // receives back as a refund.
    let outsider_delta = f.balance(&outsider) - outsider_before;
    let expected_refund = TOS - TOS / 10;
    assert!(
        outsider_delta > expected_refund - TOS / 100 && outsider_delta <= expected_refund,
        "caller should have received close to the overpayment back as a refund, got {outsider_delta}"
    );

    // Calls are serialized on the single outstanding response slot: the
    // first call must be answered before a second one is accepted.
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(2, [0xEE; 32]).unwrap())
        .expect_success();

    // An exact payment (no overpayment) needs no refund and is unaffected.
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(3, [0xBB; 32]).unwrap())
        .expect_success();
    assert_eq!(f.data().total_revenue, TOS / 5);
}

#[test]
fn calls_are_serialized_on_the_single_outstanding_response_slot() {
    let mut f = Fixture::new(TOS / 10, 0, true, TOS / 10);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();

    // First call opens a pending response.
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(1, [0xAA; 32]).unwrap())
        .expect_success();
    assert!(f.data().has_pending_response);

    // A second call while the first is still unanswered would silently
    // overwrite last_request_hash: respond() would then clear
    // has_pending_response (and unfreeze the attestor) having only ever
    // answered the second caller, losing the first caller's paid-for
    // request -- and the attestor guarantee it relied on -- with no
    // on-chain trace. This must be rejected outright.
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(2, [0xBB; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_RESPONSE_PENDING);
    assert_eq!(f.data().last_request_hash, [0xAA; 32], "the first request must not be overwritten");

    // Answering the first call frees the slot for the next one.
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(3, [0xEE; 32]).unwrap())
        .expect_success();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(4, [0xBB; 32]).unwrap())
        .expect_success();
    assert_eq!(f.data().last_request_hash, [0xBB; 32]);
}

#[test]
fn respond_without_an_outstanding_call_is_rejected() {
    let mut f = Fixture::new(TOS / 10, 0, true, TOS / 10);
    let owner = f.owner.address().clone();

    // Nothing has been paid for yet -- a response here would prove nothing
    // about any specific call, and could otherwise be used purely to clear
    // has_pending_response (and unfreeze the attestor) without ever having
    // answered anyone.
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(1, [0xDD; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NO_PENDING_RESPONSE);
    assert_eq!(f.data().last_response_hash, [0; 32]);
}

#[test]
fn open_access_allows_any_caller() {
    let mut f = Fixture::new(TOS / 10, 0, true, TOS / 10);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(1, [0xBB; 32]).unwrap())
        .expect_success();
    assert_eq!(f.data().total_revenue, TOS / 10);
}

#[test]
fn call_below_price_is_rejected() {
    let mut f = Fixture::new(TOS / 2, 0, true, TOS / 10);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(1, [0xCC; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_INSUFFICIENT_PAYMENT);
}

#[test]
fn rate_limit_blocks_calls_past_the_daily_cap() {
    // Funded well beyond a single TOS / 10 message: each call here overpays
    // 10x the TOS / 100 price and is refunded the difference, and masterchain
    // fwd/action fees on that refund send (observed ~0.07 TOS/call) drain a
    // TOS / 10 starting balance within 1-2 calls otherwise.
    let mut f = Fixture::new(TOS / 100, 2, true, TOS);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(1, [0x01; 32]).unwrap())
        .expect_success();
    // Calls are serialized: answer the first before the second is accepted.
    // This does not affect the rate limit itself -- calls_today is bumped on
    // call(), not on respond().
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(2, [0xEE; 32]).unwrap())
        .expect_success();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(3, [0x02; 32]).unwrap())
        .expect_success();
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(4, [0xEE; 32]).unwrap())
        .expect_success();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(5, [0x03; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_RATE_LIMITED);
    assert_eq!(f.data().calls_today, 2);
}

#[test]
fn zero_rate_limit_means_unlimited() {
    // See the funding comment on rate_limit_blocks_calls_past_the_daily_cap;
    // this test makes 10 overpaying calls, so it needs a bigger balance.
    let mut f = Fixture::new(TOS / 100, 0, true, 5 * TOS);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();
    for i in 1..=10u64 {
        // Calls are serialized on the single outstanding response slot, so
        // each call must be answered before the next is accepted.
        f.send_from(&outsider, TOS / 10, ServiceActorContract::call(2 * i - 1, [i as u8; 32]).unwrap())
            .expect_success();
        f.send_from(&owner, TOS / 10, ServiceActorContract::respond(2 * i, [0xEE; 32]).unwrap())
            .expect_success();
    }
    assert_eq!(f.data().calls_today, 10);
}

#[test]
fn owner_can_respond_others_rejected() {
    let mut f = Fixture::new(TOS / 10, 0, true, TOS / 10);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::respond(1, [0xDD; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);

    let owner = f.owner.address().clone();
    // A response must answer an outstanding call.
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(2, [0xAA; 32]).unwrap())
        .expect_success();
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(3, [0xDD; 32]).unwrap())
        .expect_success();
    assert_eq!(f.data().last_response_hash, [0xDD; 32]);
}

#[test]
fn owner_can_update_policy_others_rejected() {
    let mut f = Fixture::new(TOS / 10, 5, false, TOS / 10);
    let owner = f.owner.address().clone();
    let outsider_addr = f.outsider.address().clone();

    f.send_from(
        &outsider_addr,
        TOS / 10,
        ServiceActorContract::update_policy(
            1, TOS / 5, 10, true, None, &owner, [0xEE; 32], [0xFF; 32],
        )
        .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_NOT_OWNER);

    f.send_from(
        &owner,
        TOS / 10,
        ServiceActorContract::update_policy(
            2, TOS / 5, 10, true, None, &owner, [0xEE; 32], [0xFF; 32],
        )
        .unwrap(),
    )
    .expect_success();
    let data = f.data();
    assert_eq!(data.price_per_call, TOS / 5);
    assert_eq!(data.rate_limit_per_day, 10);
    assert!(data.open_access);
    assert_eq!(data.authorized_caller, None);
    assert_eq!(data.metadata_hash, [0xEE; 32]);
    assert_eq!(data.proof_scheme_hash, [0xFF; 32]);

    // Now open access: the former outsider can call.
    f.send_from(&outsider_addr, TOS / 5, ServiceActorContract::call(3, [0x01; 32]).unwrap())
        .expect_success();
}

#[test]
fn update_policy_is_frozen_while_a_response_is_pending() {
    let mut f = Fixture::new(TOS / 10, 0, true, TOS / 10);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();

    // A caller pays under the current metadata_hash/proof_scheme_hash --
    // the response it's waiting for is supposed to be verifiable against
    // that commitment, not whatever the owner might change it to later.
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(1, [0xAA; 32]).unwrap())
        .expect_success();

    f.send_from(
        &owner,
        TOS / 10,
        ServiceActorContract::update_policy(
            2, TOS / 5, 10, true, None, &owner, [0xEE; 32], [0xFF; 32],
        )
        .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_RESPONSE_PENDING);
    let data = f.data();
    assert_eq!(data.price_per_call, TOS / 10, "price must be unchanged while pending");
    assert_eq!(data.metadata_hash, [0x11; 32], "metadata must be unchanged while pending");
    assert_eq!(data.proof_scheme_hash, [0x22; 32], "proof scheme must be unchanged while pending");

    // Answering the call frees update_policy() again.
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(3, [0xBB; 32]).unwrap())
        .expect_success();
    f.send_from(
        &owner,
        TOS / 10,
        ServiceActorContract::update_policy(
            4, TOS / 5, 10, true, None, &owner, [0xEE; 32], [0xFF; 32],
        )
        .unwrap(),
    )
    .expect_success();
    assert_eq!(f.data().price_per_call, TOS / 5);
}

#[test]
fn owner_can_withdraw_revenue_within_limit_others_and_overdraw_rejected() {
    let mut f = Fixture::new(TOS, 0, true, TOS / 10);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();
    // Three exact (no-overpayment) calls, rather than one call overpaying
    // 3x, so this test's revenue accounting stays independent of the
    // overpayment-refund behavior covered separately by
    // call_refunds_the_excess_when_the_caller_overpays. Calls are serialized
    // on the single outstanding response slot, so each is answered before
    // the next lands.
    f.send_from(&outsider, TOS, ServiceActorContract::call(1, [0x01; 32]).unwrap())
        .expect_success();
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(2, [0xEE; 32]).unwrap())
        .expect_success();
    f.send_from(&outsider, TOS, ServiceActorContract::call(3, [0x02; 32]).unwrap())
        .expect_success();
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(4, [0xEE; 32]).unwrap())
        .expect_success();
    f.send_from(&outsider, TOS, ServiceActorContract::call(5, [0x03; 32]).unwrap())
        .expect_success();
    assert_eq!(f.data().total_revenue, 3 * TOS);
    f.send_from(&outsider, TOS / 10, ServiceActorContract::withdraw_revenue(4, TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);
    f.send_from(&owner, TOS / 10, ServiceActorContract::withdraw_revenue(5, 100 * TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_INSUFFICIENT_REVENUE);

    let owner_before = f.balance(&owner);
    f.send_from(&owner, TOS / 10, ServiceActorContract::withdraw_revenue(6, 2 * TOS).unwrap())
        .expect_success();
    let delta = f.balance(&owner) - owner_before;
    assert!(delta > 2 * TOS - TOS / 100 && delta <= 2 * TOS, "unexpected withdrawal delta: {delta}");
    assert_eq!(f.data().total_revenue, TOS);
}

#[test]
fn deactivate_sweeps_revenue_blocks_calls_and_reactivate_restores() {
    let mut f = Fixture::new(TOS / 10, 0, true, TOS / 10);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(1, [0x01; 32]).unwrap())
        .expect_success();

    f.send_from(&outsider, TOS / 10, ServiceActorContract::deactivate(2).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);

    let owner_before = f.balance(&owner);
    f.send_from(&owner, TOS / 10, ServiceActorContract::deactivate(3).unwrap()).expect_success();
    assert!(!f.data().active);
    assert_eq!(f.data().total_revenue, 0);
    assert!(f.balance(&owner) > owner_before, "deactivate did not sweep revenue to owner");
    assert!(f.balance(&f.service.clone()) < TOS / 100, "service balance should be drained");

    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(4, [0x02; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_INACTIVE);

    f.send_from(&owner, TOS / 10, ServiceActorContract::deactivate(5).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_INACTIVE);

    f.send_from(&outsider, TOS / 10, ServiceActorContract::reactivate(6).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);
    f.send_from(&owner, TOS / 10, ServiceActorContract::reactivate(7).unwrap()).expect_success();
    assert!(f.data().active);

    f.send_from(&owner, TOS / 10, ServiceActorContract::reactivate(8).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_ALREADY_ACTIVE);
}

#[test]
fn respond_on_an_attestor_configured_service_requires_a_valid_signature() {
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let response_hash = [0xDD; 32];
    let mut f = Fixture::with_attestor(TOS / 10, 0, true, TOS / 10, attestor_pubkey);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();

    // Plain `respond` (no signature) is rejected -- there is no outstanding
    // call to answer yet, let alone one with a valid signature.
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(1, response_hash).unwrap())
        .expect_aborted();
    assert_eq!(f.data().last_response_hash, [0; 32]);

    // A response must answer an outstanding call.
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(10, [0xAA; 32]).unwrap())
        .expect_success();

    let domain_hash =
        contracts::service_respond_domain_hash(&f.service, &[0xAA; 32], &response_hash).unwrap();

    // A signature from the wrong key is rejected. (Domain-bound hashing runs
    // before the signature is judged invalid, so this needs the higher
    // attestation gas credit too.)
    let wrong_key = SigningKey::from_bytes(&[0x88; 32]);
    let wrong_signature: [u8; 64] = wrong_key.sign(&domain_hash).to_bytes();
    f.send_from(
        &owner,
        TOS / 4,
        ServiceActorContract::respond_signed(2, response_hash, &wrong_signature).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_BAD_RESPONSE_SIGNATURE);
    assert_eq!(f.data().last_response_hash, [0; 32]);

    // A non-owner sender is still rejected, even with a valid signature.
    let outsider = f.outsider.address().clone();
    let valid_signature: [u8; 64] = attestor.sign(&domain_hash).to_bytes();
    f.send_from(
        &outsider,
        TOS / 4,
        ServiceActorContract::respond_signed(3, response_hash, &valid_signature).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_NOT_OWNER);
    assert_eq!(f.data().last_response_hash, [0; 32]);

    // The owner, with the correct attestor signature, commits the response.
    f.send_from(
        &owner,
        TOS / 4,
        ServiceActorContract::respond_signed(4, response_hash, &valid_signature).unwrap(),
    )
    .expect_success();
    assert_eq!(f.data().last_response_hash, response_hash);
}

#[test]
fn attestor_signature_for_one_request_cannot_answer_a_different_request() {
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let response_hash = [0xDD; 32];
    let mut f = Fixture::with_attestor(TOS / 10, 0, true, TOS / 10, attestor_pubkey);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();

    // Request A gets a signature over (request_a, response_hash) and is
    // answered with it.
    let request_a = [0xAA; 32];
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(1, request_a).unwrap())
        .expect_success();
    let domain_a =
        contracts::service_respond_domain_hash(&f.service, &request_a, &response_hash).unwrap();
    let signature_a: [u8; 64] = attestor.sign(&domain_a).to_bytes();
    f.send_from(
        &owner,
        TOS / 10,
        ServiceActorContract::respond_signed(2, response_hash, &signature_a).unwrap(),
    )
    .expect_success();
    assert_eq!(f.data().last_response_hash, response_hash);

    // Request B lands with the same response content the owner intends to
    // send again. Replaying A's signature must not authorize it -- the
    // attestor never saw request B.
    let request_b = [0xBB; 32];
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(3, request_b).unwrap())
        .expect_success();
    f.send_from(
        &owner,
        TOS / 10,
        ServiceActorContract::respond_signed(4, response_hash, &signature_a).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_BAD_RESPONSE_SIGNATURE);

    // A signature freshly bound to request B succeeds.
    let domain_b =
        contracts::service_respond_domain_hash(&f.service, &request_b, &response_hash).unwrap();
    let signature_b: [u8; 64] = attestor.sign(&domain_b).to_bytes();
    f.send_from(
        &owner,
        TOS / 10,
        ServiceActorContract::respond_signed(5, response_hash, &signature_b).unwrap(),
    )
    .expect_success();
    assert_eq!(f.data().last_response_hash, response_hash);
}

#[test]
fn owner_can_rotate_and_revoke_the_attestor_key_while_idle_but_not_while_a_response_is_pending() {
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let response_hash = [0xDD; 32];
    // Deployed with no attestor at all -- respond should work unattested
    // until the owner opts in via rotate_attestor_key.
    let mut f = Fixture::new(TOS / 10, 0, true, TOS / 10);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();
    assert!(f.data().attestor_pubkey.is_none());

    // Non-owner rotate is rejected; attestor state is unaffected.
    f.send_from(
        &outsider,
        TOS / 10,
        ServiceActorContract::rotate_attestor_key(1, attestor_pubkey).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_NOT_OWNER);
    assert!(f.data().attestor_pubkey.is_none());

    // Owner rotates in an attestor key while idle (no call outstanding):
    // respond now requires a signature.
    f.send_from(
        &owner,
        TOS / 10,
        ServiceActorContract::rotate_attestor_key(2, attestor_pubkey).unwrap(),
    )
    .expect_success();
    assert_eq!(f.data().attestor_pubkey, Some(attestor_pubkey));

    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(3, response_hash).unwrap())
        .expect_aborted();
    assert_eq!(f.data().last_response_hash, [0; 32]);

    // Non-owner revoke is rejected; attestor requirement still in force.
    f.send_from(&outsider, TOS / 10, ServiceActorContract::revoke_attestor(4).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);
    assert!(f.data().attestor_pubkey.is_some());

    // A caller pays: the response to this call is now outstanding, so the
    // owner can no longer swap out or drop the independent check the caller
    // relied on when it paid.
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(5, [0xAA; 32]).unwrap())
        .expect_success();
    assert!(f.data().has_pending_response);
    f.send_from(&owner, TOS / 10, ServiceActorContract::revoke_attestor(6).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_ATTESTOR_FROZEN);
    assert_eq!(f.data().attestor_pubkey, Some(attestor_pubkey));

    let domain_hash =
        contracts::service_respond_domain_hash(&f.service, &[0xAA; 32], &response_hash).unwrap();
    let signature: [u8; 64] = attestor.sign(&domain_hash).to_bytes();
    f.send_from(
        &owner,
        TOS / 10,
        ServiceActorContract::respond_signed(7, response_hash, &signature).unwrap(),
    )
    .expect_success();
    assert_eq!(f.data().last_response_hash, response_hash);
    assert!(!f.data().has_pending_response);

    // The pending response has been answered: the owner can now recover
    // from a key it no longer wants to trust (e.g. suspected compromise).
    f.send_from(&owner, TOS / 10, ServiceActorContract::revoke_attestor(8).unwrap())
        .expect_success();
    assert!(f.data().attestor_pubkey.is_none());
}

#[test]
fn attestor_rotation_is_frozen_only_while_a_response_is_pending() {
    let old_attestor = SigningKey::from_bytes(&[0x11; 32]);
    let old_pubkey = old_attestor.verifying_key().to_bytes();
    let new_pubkey = SigningKey::from_bytes(&[0x22; 32]).verifying_key().to_bytes();
    let response_hash = [0xDD; 32];

    let mut f = Fixture::with_attestor(TOS / 10, 0, true, TOS / 10, old_pubkey);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();

    // No call has landed yet: rotation is unrestricted even though an
    // attestor is already configured -- there is nothing pending to bypass.
    f.send_from(&owner, TOS / 10, ServiceActorContract::rotate_attestor_key(1, new_pubkey).unwrap())
        .expect_success();
    assert_eq!(f.data().attestor_pubkey, Some(new_pubkey));
    f.send_from(&owner, TOS / 10, ServiceActorContract::rotate_attestor_key(2, old_pubkey).unwrap())
        .expect_success();

    // A caller pays for a call: the response is now outstanding.
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(3, [0xAA; 32]).unwrap())
        .expect_success();

    // The owner cannot swap out the key while that response is outstanding
    // -- doing so would let it forge the independent check the caller paid
    // for.
    f.send_from(&owner, TOS / 10, ServiceActorContract::rotate_attestor_key(4, new_pubkey).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_ATTESTOR_FROZEN);
    assert_eq!(f.data().attestor_pubkey, Some(old_pubkey));

    let domain_hash =
        contracts::service_respond_domain_hash(&f.service, &[0xAA; 32], &response_hash).unwrap();
    let old_signature: [u8; 64] = old_attestor.sign(&domain_hash).to_bytes();
    f.send_from(
        &owner,
        TOS / 4,
        ServiceActorContract::respond_signed(5, response_hash, &old_signature).unwrap(),
    )
    .expect_success();
    assert_eq!(f.data().last_response_hash, response_hash);

    // The pending response has been answered: rotation is unrestricted
    // again.
    f.send_from(&owner, TOS / 10, ServiceActorContract::rotate_attestor_key(6, new_pubkey).unwrap())
        .expect_success();
    assert_eq!(f.data().attestor_pubkey, Some(new_pubkey));
}
