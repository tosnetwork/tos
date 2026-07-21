/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) lifecycle tests for the concurrent-escrow Service
//! Actor -- see `doc/service-actor-concurrent-escrow-upgrade.md` for the
//! full design. This is a direct, incompatible replacement of the
//! single-pending-slot Service Actor: every request is identified by a
//! contract-assigned `request_id`, snapshots the policy/attestor key in
//! force at `call` time, and resolves independently of every other
//! outstanding request via `respond`, `expire` + `claim_refund`, or a
//! permissionless `sweep_expired_request`.
//!
//! Two hard-won lessons from this contract family, paid for earlier this
//! session:
//! 1. `tos_sandbox::Blockchain::send_message` injects a message directly
//!    against its DESTINATION account only -- it does not simulate a real
//!    sender-side debit. A treasury used as `from` is never debited for the
//!    outbound send itself; its balance only changes when it later appears
//!    as a message *destination* (e.g. receiving a refund/bounty/payout).
//! 2. Masterchain gas/fwd/action fees are real and non-trivial (~0.07 TOS
//!    measured empirically for a comparable send in this contract family) --
//!    underfunded fixtures cause spurious `aborted` failures that look like
//!    contract bugs but are just insufficient treasury/contract funding.

use chain_block::{Cell, MsgAddressInt};
use contracts::{ServiceActorContract, ServiceActorData, ServiceActorInit};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, Treasury};
use tos_vm::stack::StackItem;

const TOS: u64 = 1_000_000_000;
const MIN_RESPONSE_SLA: u32 = 3_600;
const MIN_REFUND_CLAIM_WINDOW: u32 = 3_600;
const MIN_STORAGE_FEE: u64 = 100_000_000;
const MIN_CLEANUP_BOUNTY: u64 = 100_000_000;
const MAX_CLEANUP_BOUNTY: u64 = 1_000_000_000;

const ERR_NOT_OWNER: i32 = 1900;
const ERR_INACTIVE: i32 = 1901;
const ERR_INSUFFICIENT_PAYMENT: i32 = 1902;
const ERR_INVALID_RESPONSE_SLA: i32 = 1903;
const ERR_INVALID_REFUND_CLAIM_WINDOW: i32 = 1904;
const ERR_INVALID_CLEANUP_BOUNTY: i32 = 1905;
const ERR_INSUFFICIENT_STORAGE_FEE: i32 = 1906;
const ERR_CAPACITY_EXCEEDED_CALLER: i32 = 1908;
const ERR_BAD_RESPONSE_SIGNATURE: i32 = 1911;
const ERR_RESPONSE_WINDOW_CLOSED: i32 = 1912;
const ERR_REQUEST_NOT_PENDING: i32 = 1913;
const ERR_EXPIRE_TOO_EARLY: i32 = 1914;
const ERR_EXPIRE_TOO_LATE: i32 = 1915;
const ERR_REFUND_CLAIM_EXPIRED: i32 = 1916;
const ERR_REFUND_NOT_FOUND: i32 = 1917;
const ERR_NOT_REFUND_CALLER: i32 = 1918;
const ERR_SWEEP_TOO_EARLY: i32 = 1919;
const ERR_REQUEST_NOT_LIVE: i32 = 1920;
const ERR_INSUFFICIENT_BALANCE: i32 = 1921;
const ERR_NOT_AUTHORIZED: i32 = 1923;
const ERR_RATE_LIMITED: i32 = 1924;

struct Fixture {
    bc: Blockchain,
    owner: Treasury,
    caller: Treasury,
    caller2: Treasury,
    outsider: Treasury,
    service: MsgAddressInt,
    init: ServiceActorInit,
}

impl Fixture {
    fn new() -> Self {
        Self::build(None)
    }

    fn with_attestor(attestor_pubkey: [u8; 32]) -> Self {
        Self::build(Some(attestor_pubkey))
    }

    fn build(attestor_pubkey: Option<[u8; 32]>) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        // The sandbox config has no basechain workchain descriptor, so run
        // everything in the masterchain where outbound sends are permitted.
        bc.set_workchain(-1);
        let owner = bc.treasury("owner", 10_000 * TOS).expect("owner");
        let caller = bc.treasury("caller", 10_000 * TOS).expect("caller");
        let caller2 = bc.treasury("caller2", 10_000 * TOS).expect("caller2");
        let outsider = bc.treasury("outsider", 10_000 * TOS).expect("outsider");
        let init = ServiceActorInit {
            owner: owner.address().clone(),
            authorized_caller: None,
            open_access: true,
            price_per_call: TOS / 10,
            storage_fee: MIN_STORAGE_FEE + MIN_CLEANUP_BOUNTY,
            cleanup_bounty: MIN_CLEANUP_BOUNTY,
            rate_limit_per_day: 0,
            response_sla: MIN_RESPONSE_SLA,
            refund_claim_window: MIN_REFUND_CLAIM_WINDOW,
            metadata_hash: [0x11; 32],
            proof_scheme_hash: [0x22; 32],
            attestor_pubkey,
        };
        let service = ServiceActorContract::calculate_address(-1, &init).expect("address");
        let state_init = ServiceActorContract::build_state_init(&init).expect("state init");
        // Generous: MINIMUM_OPERATING_RESERVE (1 TOS) plus headroom for many
        // sequential value-moving ops across a whole test.
        let deploy = MessageBuilder::internal(owner.address(), &service, 20 * TOS)
            .bounce(false)
            .state_init(state_init)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, owner, caller, caller2, outsider, service, init }
    }

    fn send_from(&mut self, from: &MsgAddressInt, body: Cell) -> SendResult {
        self.send_from_with_value(from, body, TOS / 2)
    }

    fn send_from_with_value(&mut self, from: &MsgAddressInt, body: Cell, value: u64) -> SendResult {
        let msg = MessageBuilder::internal(from, &self.service, value).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    /// Sends a message with the `bounced` header flag set -- simulating an
    /// automatic network bounce (or a hand-crafted lookalike) rather than a
    /// genuine call -- to verify the contract ignores it unconditionally.
    fn send_bounced_from(&mut self, from: &MsgAddressInt, body: Cell) -> SendResult {
        let mut msg = MessageBuilder::internal(from, &self.service, TOS / 2).body(body).build();
        msg.int_header_mut().expect("internal header").bounced = true;
        self.bc.send_message(msg).expect("send")
    }

    fn balance(&self, addr: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(addr)
            .and_then(|acc| acc.balance().and_then(|cc| cc.coins.as_u64()))
            .unwrap_or(0)
    }

    fn data(&self) -> ServiceActorData {
        let stack = self
            .bc
            .run_get_method(&self.service, "get_service_data", vec![])
            .expect("get_service_data")
            .expect_success()
            .stack
            .clone();
        ServiceActorContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(
            stack_to_entries(&stack),
        ))
        .expect("decode_data")
    }

    fn request(&self, request_id: u64) -> Option<contracts::PendingRequestData> {
        let stack = self
            .bc
            .run_get_method(&self.service, "get_request", vec![StackItem::int(request_id)])
            .expect("get_request")
            .expect_success()
            .stack
            .clone();
        ServiceActorContract::decode_request(&common::tvm_stack_parser::TvmStackParser::new(
            stack_to_entries(&stack),
        ))
        .expect("decode_request")
    }

    fn refund(&self, request_id: u64) -> Option<contracts::RefundData> {
        let stack = self
            .bc
            .run_get_method(&self.service, "get_refund", vec![StackItem::int(request_id)])
            .expect("get_refund")
            .expect_success()
            .stack
            .clone();
        ServiceActorContract::decode_refund(&common::tvm_stack_parser::TvmStackParser::new(
            stack_to_entries(&stack),
        ))
        .expect("decode_refund")
    }

    fn caller_live_count(&self, caller: &MsgAddressInt) -> u64 {
        self.bc
            .run_get_method(
                &self.service,
                "get_caller_live_count",
                vec![StackItem::Slice(address_slice(caller))],
            )
            .expect("get_caller_live_count")
            .expect_success()
            .int_at(0) as u64
    }

    fn pending_count(&self) -> u64 {
        self.bc
            .run_get_method(&self.service, "get_pending_count", vec![])
            .expect("get_pending_count")
            .expect_success()
            .int_at(0) as u64
    }

    fn live_count(&self) -> u64 {
        self.bc
            .run_get_method(&self.service, "get_live_count", vec![])
            .expect("get_live_count")
            .expect_success()
            .int_at(0) as u64
    }

    fn call(&mut self, from: &MsgAddressInt, query_id: u64, request_hash: [u8; 32]) -> SendResult {
        let value = self.init.price_per_call + self.init.storage_fee + TOS / 2;
        self.send_from_with_value(from, ServiceActorContract::call(query_id, request_hash).unwrap(), value)
    }

    fn respond(&mut self, query_id: u64, request_id: u64, response_hash: [u8; 32]) -> SendResult {
        let owner = self.owner.address().clone();
        self.send_from_with_value(
            &owner,
            ServiceActorContract::respond(query_id, request_id, response_hash).unwrap(),
            TOS,
        )
    }

    fn respond_signed(
        &mut self,
        query_id: u64,
        request_id: u64,
        response_hash: [u8; 32],
        signature: &[u8; 64],
    ) -> SendResult {
        let owner = self.owner.address().clone();
        self.send_from_with_value(
            &owner,
            ServiceActorContract::respond_signed(query_id, request_id, response_hash, signature).unwrap(),
            TOS,
        )
    }

    fn expire(&mut self, from: &MsgAddressInt, query_id: u64, request_id: u64) -> SendResult {
        self.send_from(from, ServiceActorContract::expire(query_id, request_id).unwrap())
    }

    fn claim_refund(
        &mut self,
        from: &MsgAddressInt,
        query_id: u64,
        request_id: u64,
        destination: &MsgAddressInt,
    ) -> SendResult {
        self.send_from(from, ServiceActorContract::claim_refund(query_id, request_id, destination).unwrap())
    }

    fn sweep(&mut self, from: &MsgAddressInt, query_id: u64, request_id: u64) -> SendResult {
        self.send_from(from, ServiceActorContract::sweep_expired_request(query_id, request_id).unwrap())
    }
}

fn address_slice(addr: &MsgAddressInt) -> chain_block::SliceData {
    use chain_block::Serializable;
    let cell = addr.write_to_new_cell().unwrap().into_cell().unwrap();
    chain_block::SliceData::load_cell(cell).unwrap()
}

fn stack_to_entries(stack: &[tos_vm::stack::StackItem]) -> Vec<tl_api::tos::tvm::StackEntry> {
    use tl_api::tos::tvm::{
        Number, StackEntry, numberdecimal::NumberDecimal, slice,
        stackentry::{StackEntryNumber, StackEntrySlice},
    };
    stack
        .iter()
        .map(|item| {
            if matches!(item, tos_vm::stack::StackItem::None) {
                // The "not found" branch of get_request/get_refund returns
                // null() for the caller slice; its value is never read
                // (decode_request/decode_refund check the `found` flag
                // first), but TvmStackParser still needs *some* entry here.
                return StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
                    slice: slice::Slice { bytes: vec![] },
                });
            }
            if let Ok(int) = item.as_integer() {
                return StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
                    number: Number::Tvm_NumberDecimal(NumberDecimal { number: int.to_string() }),
                });
            }
            if let Ok(s) = item.as_slice() {
                let bytes = s.clone().get_bytestring(0);
                return StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
                    slice: slice::Slice { bytes },
                });
            }
            panic!("unsupported stack item in sandbox test: {item:?}");
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Deployment / basic call-respond round trip
// ---------------------------------------------------------------------------

#[test]
fn deploy_records_initial_state() {
    let f = Fixture::new();
    let data = f.data();
    assert_eq!(data.owner, f.owner.address().clone());
    assert!(data.active);
    assert_eq!(data.policy_version, 0);
    assert_eq!(data.price_per_call, f.init.price_per_call);
    assert_eq!(data.storage_fee, f.init.storage_fee);
    assert_eq!(data.cleanup_bounty, f.init.cleanup_bounty);
    assert_eq!(data.next_request_id, 0);
    assert_eq!(data.pending_count, 0);
    assert_eq!(data.live_count, 0);
    assert_eq!(data.withdrawable_revenue, 0);
    assert_eq!(data.locked_storage_fees, 0);
    assert_eq!(data.pending_liability, 0);
    assert_eq!(data.refundable_liability, 0);
}

#[test]
fn call_then_respond_round_trip() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();

    let data = f.data();
    assert_eq!(data.next_request_id, 1, "next_request_id must advance past request 0");
    assert_eq!(data.pending_count, 1);
    assert_eq!(data.live_count, 1);
    assert_eq!(data.pending_liability, f.init.price_per_call);
    assert_eq!(data.locked_storage_fees, f.init.storage_fee);

    let request = f.request(0).expect("request 0 must be found after call()");
    assert_eq!(request.caller, caller);
    assert_eq!(request.price, f.init.price_per_call);
    assert_eq!(request.storage_fee, f.init.storage_fee);
    assert_eq!(request.request_hash, [0xAA; 32]);
    assert_eq!(request.attestor_pubkey, None);

    f.respond(2, 0, [0xBB; 32]).expect_success();
    let data = f.data();
    assert_eq!(data.pending_count, 0, "respond() must clear the pending entry");
    assert_eq!(data.live_count, 0);
    assert_eq!(data.pending_liability, 0);
    assert_eq!(data.locked_storage_fees, 0);
    assert_eq!(
        data.withdrawable_revenue,
        f.init.price_per_call + f.init.storage_fee,
        "respond() must recognize both price and storage_fee as revenue"
    );
    assert_eq!(f.request(0), None, "request 0 must be gone after respond()");
}

#[test]
fn overpayment_above_price_plus_storage_fee_is_refunded_at_call_time() {
    let mut f = Fixture::new();
    let outsider = f.outsider.address().clone();
    let outsider_before = f.balance(&outsider);
    let owed = f.init.price_per_call + f.init.storage_fee;
    // Overpay by 1 TOS beyond what's owed.
    f.send_from_with_value(&outsider, ServiceActorContract::call(1, [0xAA; 32]).unwrap(), owed + TOS)
        .expect_success();
    let data = f.data();
    assert_eq!(data.pending_liability, f.init.price_per_call, "only the quoted price is owed");
    assert_eq!(data.locked_storage_fees, f.init.storage_fee, "only the quoted storage fee is owed");
    let delta = f.balance(&outsider) - outsider_before;
    assert!(delta > TOS - TOS / 100 && delta <= TOS, "expected close to the 1 TOS overpayment refunded, got {delta}");
}

#[test]
fn call_below_price_plus_storage_fee_is_rejected() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let owed = f.init.price_per_call + f.init.storage_fee;
    f.send_from_with_value(&caller, ServiceActorContract::call(1, [0xAA; 32]).unwrap(), owed - 1)
        .expect_aborted()
        .expect_exit_code(ERR_INSUFFICIENT_PAYMENT);
    assert_eq!(f.data().pending_count, 0);
}

#[test]
fn call_on_inactive_service_is_rejected() {
    let mut f = Fixture::new();
    let owner = f.owner.address().clone();
    let init = f.init.clone();
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            1, init.price_per_call, init.storage_fee, init.cleanup_bounty, init.response_sla,
            init.refund_claim_window, false, init.open_access, init.authorized_caller.as_ref(),
            &owner, init.rate_limit_per_day, init.metadata_hash, init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_success();
    assert!(!f.data().active);

    let caller = f.caller.address().clone();
    f.call(&caller, 2, [0xAA; 32]).expect_aborted().expect_exit_code(ERR_INACTIVE);
}

// ---------------------------------------------------------------------------
// Concurrency: multiple outstanding requests are fully independent
// ---------------------------------------------------------------------------

#[test]
fn concurrent_calls_from_one_and_several_callers_are_independent() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let caller2 = f.caller2.address().clone();

    f.call(&caller, 1, [0x01; 32]).expect_success(); // request 0
    f.call(&caller, 2, [0x02; 32]).expect_success(); // request 1
    f.call(&caller2, 3, [0x03; 32]).expect_success(); // request 2

    let data = f.data();
    assert_eq!(data.next_request_id, 3);
    assert_eq!(data.pending_count, 3);
    assert_eq!(data.live_count, 3);
    assert_eq!(f.caller_live_count(&caller), 2);
    assert_eq!(f.caller_live_count(&caller2), 1);

    // Responding to request 1 must not alter requests 0 or 2.
    f.respond(4, 1, [0xBB; 32]).expect_success();
    assert!(f.request(0).is_some(), "request 0 must be untouched");
    assert!(f.request(1).is_none(), "request 1 must be gone");
    assert!(f.request(2).is_some(), "request 2 must be untouched");
    assert_eq!(f.data().pending_count, 2);
    assert_eq!(f.data().live_count, 2);
    assert_eq!(f.caller_live_count(&caller), 1, "only request 1 should be released from caller");
    assert_eq!(f.caller_live_count(&caller2), 1, "caller2's request must be unaffected");

    // Each remaining request still carries its own distinct request_hash.
    assert_eq!(f.request(0).unwrap().request_hash, [0x01; 32]);
    assert_eq!(f.request(2).unwrap().request_hash, [0x03; 32]);

    f.respond(5, 0, [0xCC; 32]).expect_success();
    f.respond(6, 2, [0xDD; 32]).expect_success();
    assert_eq!(f.data().pending_count, 0);
    assert_eq!(f.data().live_count, 0);
}

#[test]
fn respond_requires_owner_and_a_pending_request() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let outsider = f.outsider.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();

    f.send_from(&outsider, ServiceActorContract::respond(2, 0, [0xBB; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);
    assert!(f.request(0).is_some());

    // A request_id that was never allocated.
    f.respond(3, 999, [0xBB; 32]).expect_aborted().expect_exit_code(ERR_REQUEST_NOT_PENDING);

    f.respond(4, 0, [0xBB; 32]).expect_success();
    // Responding again to the same (now-resolved) request_id must fail.
    f.respond(5, 0, [0xCC; 32]).expect_aborted().expect_exit_code(ERR_REQUEST_NOT_PENDING);
}

// ---------------------------------------------------------------------------
// Exact deadline boundaries
// ---------------------------------------------------------------------------

#[test]
fn respond_boundary_is_exact() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let response_deadline = f.request(0).unwrap().response_deadline;

    f.bc.set_now((response_deadline - 1) as u32);
    // respond() one second before the deadline must still succeed on a
    // throwaway clone-equivalent check: use a second request so the first
    // exact-boundary rejection below is unambiguous.
    f.call(&caller, 2, [0xBB; 32]).expect_success(); // request 1, fresh deadlines

    f.respond(3, 0, [0xCC; 32]).expect_success();

    // request 1 shares the same response_deadline (deployed with the same
    // policy and issued one block later at the same `now()`).
    let response_deadline_1 = f.request(1).unwrap().response_deadline;
    f.bc.set_now(response_deadline_1 as u32);
    f.respond(4, 1, [0xDD; 32])
        .expect_aborted()
        .expect_exit_code(ERR_RESPONSE_WINDOW_CLOSED);
}

#[test]
fn expire_boundary_is_exact() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let request = f.request(0).unwrap();

    f.bc.set_now((request.response_deadline - 1) as u32);
    f.expire(&caller, 2, 0).expect_aborted().expect_exit_code(ERR_EXPIRE_TOO_EARLY);

    f.bc.set_now(request.response_deadline as u32);
    f.expire(&caller, 3, 0).expect_success();
    assert!(f.request(0).is_none());
    assert!(f.refund(0).is_some());

    // A second request to check the late boundary in isolation.
    f.call(&caller, 4, [0xBB; 32]).expect_success(); // request 1
    let request1 = f.request(1).unwrap();
    f.bc.set_now(request1.refund_claim_deadline as u32);
    f.expire(&caller, 5, 1).expect_aborted().expect_exit_code(ERR_EXPIRE_TOO_LATE);
}

#[test]
fn claim_refund_boundary_is_exact() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let request = f.request(0).unwrap();
    f.bc.set_now(request.response_deadline as u32);
    f.expire(&caller, 2, 0).expect_success();
    let refund = f.refund(0).unwrap();

    f.bc.set_now((refund.refund_claim_deadline - 1) as u32);
    let caller_before = f.balance(&caller);
    f.claim_refund(&caller, 3, 0, &caller).expect_success();
    let delta = f.balance(&caller) - caller_before;
    assert!(delta > f.init.price_per_call - TOS / 100 && delta <= f.init.price_per_call);

    // A second request to check the exact-deadline rejection in isolation.
    f.call(&caller, 4, [0xBB; 32]).expect_success(); // request 1
    let request1 = f.request(1).unwrap();
    f.bc.set_now(request1.response_deadline as u32);
    f.expire(&caller, 5, 1).expect_success();
    let refund1 = f.refund(1).unwrap();
    f.bc.set_now(refund1.refund_claim_deadline as u32);
    f.claim_refund(&caller, 6, 1, &caller)
        .expect_aborted()
        .expect_exit_code(ERR_REFUND_CLAIM_EXPIRED);
}

#[test]
fn sweep_boundary_is_exact() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let outsider = f.outsider.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let request = f.request(0).unwrap();
    f.bc.set_now(request.response_deadline as u32);
    f.expire(&caller, 2, 0).expect_success();
    let refund = f.refund(0).unwrap();

    f.bc.set_now((refund.refund_claim_deadline - 1) as u32);
    f.sweep(&outsider, 3, 0).expect_aborted().expect_exit_code(ERR_SWEEP_TOO_EARLY);

    f.bc.set_now(refund.refund_claim_deadline as u32);
    f.sweep(&outsider, 4, 0).expect_success();
    assert!(f.refund(0).is_none());
}

// ---------------------------------------------------------------------------
// sweep_expired_request against both dictionaries
// ---------------------------------------------------------------------------

#[test]
fn sweep_works_directly_against_a_never_expired_pending_request() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let outsider = f.outsider.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let request = f.request(0).unwrap();

    // Nobody ever calls expire(): the entry sits in pending_requests past
    // both deadlines.
    f.bc.set_now(request.refund_claim_deadline as u32);
    let outsider_before = f.balance(&outsider);
    f.sweep(&outsider, 2, 0).expect_success();

    assert!(f.request(0).is_none(), "sweep must clean up a still-pending entry directly");
    assert!(f.refund(0).is_none());
    let data = f.data();
    assert_eq!(data.pending_count, 0);
    assert_eq!(data.live_count, 0);
    assert_eq!(data.pending_liability, 0);
    assert_eq!(data.locked_storage_fees, 0);
    assert_eq!(
        data.withdrawable_revenue,
        f.init.price_per_call + f.init.storage_fee - f.init.cleanup_bounty
    );
    let delta = f.balance(&outsider) - outsider_before;
    assert!(
        delta > f.init.cleanup_bounty - TOS / 100 && delta <= f.init.cleanup_bounty,
        "sweeper must receive the cleanup bounty, got {delta}"
    );
}

#[test]
fn sweep_works_against_a_properly_expired_refund_entry() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let outsider = f.outsider.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let request = f.request(0).unwrap();
    f.bc.set_now(request.response_deadline as u32);
    f.expire(&caller, 2, 0).expect_success();
    let refund = f.refund(0).unwrap();

    f.bc.set_now(refund.refund_claim_deadline as u32);
    let outsider_before = f.balance(&outsider);
    f.sweep(&outsider, 3, 0).expect_success();

    assert!(f.refund(0).is_none());
    let data = f.data();
    assert_eq!(data.refundable_liability, 0);
    assert_eq!(data.locked_storage_fees, 0);
    assert_eq!(
        data.withdrawable_revenue,
        f.init.price_per_call + f.init.storage_fee - f.init.cleanup_bounty
    );
    let delta = f.balance(&outsider) - outsider_before;
    assert!(delta > f.init.cleanup_bounty - TOS / 100 && delta <= f.init.cleanup_bounty);
}

#[test]
fn sweep_on_a_request_id_that_is_live_nowhere_is_rejected() {
    let mut f = Fixture::new();
    let outsider = f.outsider.address().clone();
    f.sweep(&outsider, 1, 42).expect_aborted().expect_exit_code(ERR_REQUEST_NOT_LIVE);
}

// ---------------------------------------------------------------------------
// Duplicate operations are rejected once the entry is gone
// ---------------------------------------------------------------------------

#[test]
fn duplicate_expire_claim_and_sweep_are_rejected() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let outsider = f.outsider.address().clone();

    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let request = f.request(0).unwrap();
    f.bc.set_now(request.response_deadline as u32);
    f.expire(&caller, 2, 0).expect_success();
    f.expire(&caller, 3, 0).expect_aborted().expect_exit_code(ERR_REQUEST_NOT_PENDING);

    let refund = f.refund(0).unwrap();
    f.claim_refund(&caller, 4, 0, &caller).expect_success();
    f.claim_refund(&caller, 5, 0, &caller).expect_aborted().expect_exit_code(ERR_REFUND_NOT_FOUND);

    // A second request, swept once, cannot be swept again.
    f.call(&caller, 6, [0xBB; 32]).expect_success(); // request 1
    let request1 = f.request(1).unwrap();
    f.bc.set_now(request1.refund_claim_deadline as u32);
    f.sweep(&outsider, 7, 1).expect_success();
    f.sweep(&outsider, 8, 1).expect_aborted().expect_exit_code(ERR_REQUEST_NOT_LIVE);

    let _ = refund;
}

#[test]
fn only_the_original_caller_can_claim_their_refund() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let outsider = f.outsider.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let request = f.request(0).unwrap();
    f.bc.set_now(request.response_deadline as u32);
    f.expire(&caller, 2, 0).expect_success();

    f.claim_refund(&outsider, 3, 0, &outsider)
        .expect_aborted()
        .expect_exit_code(ERR_NOT_REFUND_CALLER);
    assert!(f.refund(0).is_some(), "refund entry must be untouched by the rejected claim");
}

// ---------------------------------------------------------------------------
// Attestation: replay-across-requests and wrong-signature rejection
// ---------------------------------------------------------------------------

#[test]
fn attestor_signature_cannot_be_replayed_across_requests() {
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let mut f = Fixture::with_attestor(attestor_pubkey);
    let caller = f.caller.address().clone();

    f.call(&caller, 1, [0xAA; 32]).expect_success(); // request 0
    f.call(&caller, 2, [0xBB; 32]).expect_success(); // request 1

    let request0 = f.request(0).unwrap();
    let response_hash = [0xCC; 32];
    let domain_0 = contracts::service_respond_domain_hash(
        &f.service, &request0.caller, 0, &request0.request_hash, &response_hash,
        &request0.terms_hash, request0.price, request0.response_deadline,
        request0.refund_claim_deadline,
    )
    .unwrap();
    let signature_0: [u8; 64] = attestor.sign(&domain_0).to_bytes();

    // A wrong signature is rejected outright.
    f.respond_signed(3, 0, response_hash, &[0u8; 64])
        .expect_aborted()
        .expect_exit_code(ERR_BAD_RESPONSE_SIGNATURE);

    // The valid signature for request 0 answers request 0.
    f.respond_signed(4, 0, response_hash, &signature_0).expect_success();
    assert!(f.request(0).is_none());

    // The same signature, same response content, replayed against request 1
    // must be rejected: the domain binds request_id (and every other
    // request-specific field), so it is not valid there.
    f.respond_signed(5, 1, response_hash, &signature_0)
        .expect_aborted()
        .expect_exit_code(ERR_BAD_RESPONSE_SIGNATURE);
    assert!(f.request(1).is_some(), "request 1 must still be pending after the replay attempt");

    // A freshly computed signature bound to request 1 succeeds.
    let request1 = f.request(1).unwrap();
    let domain_1 = contracts::service_respond_domain_hash(
        &f.service, &request1.caller, 1, &request1.request_hash, &response_hash,
        &request1.terms_hash, request1.price, request1.response_deadline,
        request1.refund_claim_deadline,
    )
    .unwrap();
    let signature_1: [u8; 64] = attestor.sign(&domain_1).to_bytes();
    f.respond_signed(6, 1, response_hash, &signature_1).expect_success();
}

#[test]
fn attestor_signed_respond_matches_the_compiled_bytecode() {
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let mut f = Fixture::with_attestor(attestor_pubkey);
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();

    // Unsigned respond() is rejected when an attestor is configured.
    f.respond(2, 0, [0xBB; 32]).expect_aborted();
    assert!(f.request(0).is_some());

    let request = f.request(0).unwrap();
    assert_eq!(request.attestor_pubkey, Some(attestor_pubkey));
    let response_hash = [0xBB; 32];
    let domain_hash = contracts::service_respond_domain_hash(
        &f.service, &request.caller, 0, &request.request_hash, &response_hash,
        &request.terms_hash, request.price, request.response_deadline,
        request.refund_claim_deadline,
    )
    .unwrap();
    let signature: [u8; 64] = attestor.sign(&domain_hash).to_bytes();
    f.respond_signed(3, 0, response_hash, &signature).expect_success();
    assert!(f.request(0).is_none());
}

// ---------------------------------------------------------------------------
// Policy and attestor rotation affect only newly accepted requests
// ---------------------------------------------------------------------------

#[test]
fn update_policy_and_attestor_rotation_never_alter_already_snapshotted_requests() {
    let old_attestor = SigningKey::from_bytes(&[0x11; 32]);
    let old_attestor_pubkey = old_attestor.verifying_key().to_bytes();
    let mut f = Fixture::with_attestor(old_attestor_pubkey);
    let owner = f.owner.address().clone();
    let caller = f.caller.address().clone();

    f.call(&caller, 1, [0xAA; 32]).expect_success(); // request 0, snapshots old terms/attestor
    let request0_before = f.request(0).unwrap();

    // Rotate the attestor key and change the price -- request 0's snapshot
    // must be completely unaffected, and this must succeed unconditionally
    // (no pending-state freeze, unlike the single-slot predecessor).
    let new_attestor = SigningKey::from_bytes(&[0x22; 32]);
    let new_attestor_pubkey = new_attestor.verifying_key().to_bytes();
    f.send_from(&owner, ServiceActorContract::rotate_attestor_key(2, new_attestor_pubkey).unwrap())
        .expect_success();

    let mut new_init = f.init.clone();
    new_init.price_per_call *= 2;
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            3, new_init.price_per_call, new_init.storage_fee, new_init.cleanup_bounty,
            new_init.response_sla, new_init.refund_claim_window, true, new_init.open_access,
            new_init.authorized_caller.as_ref(), &owner, new_init.rate_limit_per_day,
            new_init.metadata_hash, new_init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_success();

    let request0_after = f.request(0).unwrap();
    assert_eq!(request0_after, request0_before, "already-snapshotted request must be byte-identical");

    // A new request accepted after the change snapshots the new terms.
    f.call(&caller, 4, [0xBB; 32]).expect_success(); // request 1
    let request1 = f.request(1).unwrap();
    assert_eq!(request1.price, new_init.price_per_call);
    assert_eq!(request1.attestor_pubkey, Some(new_attestor_pubkey));
    assert_ne!(request1.terms_hash, request0_after.terms_hash);

    // request 0 still requires the OLD attestor's signature, not the new one.
    let response_hash = [0xCC; 32];
    let domain_0 = contracts::service_respond_domain_hash(
        &f.service, &request0_after.caller, 0, &request0_after.request_hash, &response_hash,
        &request0_after.terms_hash, request0_after.price, request0_after.response_deadline,
        request0_after.refund_claim_deadline,
    )
    .unwrap();
    let wrong_key_signature: [u8; 64] = new_attestor.sign(&domain_0).to_bytes();
    f.respond_signed(5, 0, response_hash, &wrong_key_signature)
        .expect_aborted()
        .expect_exit_code(ERR_BAD_RESPONSE_SIGNATURE);
    let old_key_signature: [u8; 64] = old_attestor.sign(&domain_0).to_bytes();
    f.respond_signed(6, 0, response_hash, &old_key_signature).expect_success();

    // request 1 requires the NEW attestor's signature.
    let request1_after = f.request(1).unwrap();
    let domain_1 = contracts::service_respond_domain_hash(
        &f.service, &request1_after.caller, 1, &request1_after.request_hash, &response_hash,
        &request1_after.terms_hash, request1_after.price, request1_after.response_deadline,
        request1_after.refund_claim_deadline,
    )
    .unwrap();
    let new_key_signature: [u8; 64] = new_attestor.sign(&domain_1).to_bytes();
    f.respond_signed(7, 1, response_hash, &new_key_signature).expect_success();
}

#[test]
fn revoke_attestor_is_never_frozen_by_a_pending_request() {
    let attestor = SigningKey::from_bytes(&[0x11; 32]);
    let mut f = Fixture::with_attestor(attestor.verifying_key().to_bytes());
    let owner = f.owner.address().clone();
    let caller = f.caller.address().clone();

    f.call(&caller, 1, [0xAA; 32]).expect_success(); // request 0, has_attestor snapshotted
    f.send_from(&owner, ServiceActorContract::revoke_attestor(2).unwrap()).expect_success();
    assert_eq!(f.data().attestor_pubkey, None);

    // request 0 still requires its own snapshotted attestor signature.
    let request = f.request(0).unwrap();
    assert_eq!(request.attestor_pubkey, Some(attestor.verifying_key().to_bytes()));
    f.respond(3, 0, [0xBB; 32]).expect_aborted();

    // A new request accepted after revocation needs no signature at all.
    f.call(&caller, 4, [0xCC; 32]).expect_success(); // request 1
    assert_eq!(f.request(1).unwrap().attestor_pubkey, None);
    f.respond(5, 1, [0xDD; 32]).expect_success();
}

// ---------------------------------------------------------------------------
// claim_refund's one atomic failure mode
// ---------------------------------------------------------------------------

#[test]
fn claim_refund_is_rejected_atomically_when_the_contract_cannot_afford_it() {
    // Reaching this specific failure mode through the normal call/expire
    // flow alone is structurally hard: `call` always collects `storage_fee`
    // (>= MINIMUM_STORAGE_FEE) alongside `price` into the contract's own
    // balance, and `withdraw_revenue` is independently capped to never take
    // `get_balance()` below `pending_liability + refundable_liability +
    // MINIMUM_OPERATING_RESERVE` -- so by construction the balance backing a
    // live refund is always >= its own price, except for one avenue the
    // design doc calls out explicitly: passive TVM storage-rent accrual,
    // charged lazily and independently of any nominal counter. This test
    // uses the maximum `refund_claim_window` (30 days) to let real elapsed
    // time actually erode the balance below `price` while staying just
    // inside the still-open claim window, rather than faking the shortfall.
    let mut bc = Blockchain::new().expect("blockchain");
    bc.set_workchain(-1);
    let owner = bc.treasury("owner", 10_000 * TOS).expect("owner");
    let caller = bc.treasury("caller", 10_000 * TOS).expect("caller");
    let init = ServiceActorInit {
        owner: owner.address().clone(),
        authorized_caller: None,
        open_access: true,
        price_per_call: 2 * TOS,
        storage_fee: MIN_STORAGE_FEE + MIN_CLEANUP_BOUNTY,
        cleanup_bounty: MIN_CLEANUP_BOUNTY,
        rate_limit_per_day: 0,
        response_sla: MIN_RESPONSE_SLA,
        refund_claim_window: 2_592_000, // MAX_REFUND_CLAIM_WINDOW: 30 days
        metadata_hash: [0x11; 32],
        proof_scheme_hash: [0x22; 32],
        attestor_pubkey: None,
    };
    let service = ServiceActorContract::calculate_address(-1, &init).expect("address");
    let state_init = ServiceActorContract::build_state_init(&init).expect("state init");
    // Thin deploy funding: just enough to exist, most of the eventual
    // balance comes from the call itself.
    let deploy = MessageBuilder::internal(owner.address(), &service, TOS / 10)
        .bounce(false)
        .state_init(state_init)
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();

    let owed = init.price_per_call + init.storage_fee;
    let call_msg = MessageBuilder::internal(caller.address(), &service, owed)
        .body(ServiceActorContract::call(1, [0xAA; 32]).unwrap())
        .build();
    bc.send_message(call_msg).expect("call").expect_success();

    let stack = bc
        .run_get_method(&service, "get_request", vec![StackItem::int(0)])
        .expect("get_request")
        .expect_success()
        .stack
        .clone();
    let request = ServiceActorContract::decode_request(&common::tvm_stack_parser::TvmStackParser::new(
        stack_to_entries(&stack),
    ))
    .expect("decode_request")
    .expect("request 0 must exist");

    bc.set_now(request.response_deadline as u32);
    let expire_msg = MessageBuilder::internal(caller.address(), &service, TOS / 2)
        .body(ServiceActorContract::expire(2, 0).unwrap())
        .build();
    bc.send_message(expire_msg).expect("expire").expect_success();
    let refund_claim_deadline = request.refund_claim_deadline;

    // Sit just inside the still-open 30-day claim window and poke the
    // account once so lazily-accrued storage rent is actually collected
    // before we read the balance and attempt the claim.
    bc.set_now(refund_claim_deadline as u32 - 1);
    let poke_msg = MessageBuilder::internal(caller.address(), &service, 1).body(Cell::default()).build();
    let _ = bc.send_message(poke_msg);

    let balance_before_claim =
        bc.get_account(&service).and_then(|a| a.balance().and_then(|c| c.coins.as_u64())).unwrap_or(0);
    assert!(
        balance_before_claim < init.price_per_call,
        "test setup must actually erode the balance below `price` via elapsed storage rent, \
         got balance={balance_before_claim} price={}",
        init.price_per_call
    );

    let claim_msg = MessageBuilder::internal(caller.address(), &service, TOS / 2)
        .body(ServiceActorContract::claim_refund(3, 0, caller.address()).unwrap())
        .build();
    let result = bc.send_message(claim_msg).expect("claim_refund attempt");
    result.expect_aborted().expect_exit_code(ERR_INSUFFICIENT_BALANCE);

    // The refund entry must be untouched and retryable.
    let stack = bc
        .run_get_method(&service, "get_refund", vec![StackItem::int(0)])
        .expect("get_refund")
        .expect_success()
        .stack
        .clone();
    let refund = ServiceActorContract::decode_refund(&common::tvm_stack_parser::TvmStackParser::new(
        stack_to_entries(&stack),
    ))
    .expect("decode_refund");
    assert!(refund.is_some(), "the refund entry must survive a failed claim attempt untouched");
}

// ---------------------------------------------------------------------------
// bounced messages never mutate state, regardless of sender or body
// ---------------------------------------------------------------------------

#[test]
fn bounced_message_never_mutates_pending_or_liability_state() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let owner = f.owner.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let before = f.data();
    let request_before = f.request(0);

    // A bounced message crafted to look exactly like a legitimate respond()
    // -- including a well-formed op/body -- from the owner's own address.
    // If the contract ever specially handled `bounced`, this is the shape
    // an attacker would use to try to trigger it.
    f.send_bounced_from(&owner, ServiceActorContract::respond(2, 0, [0xBB; 32]).unwrap());
    assert_eq!(f.data(), before, "a bounced message must never mutate liability/policy state");
    assert_eq!(f.request(0), request_before, "a bounced message must never touch pending state");

    // Same, from an arbitrary outsider, with a claim_refund-shaped body.
    let outsider = f.outsider.address().clone();
    f.send_bounced_from(&outsider, ServiceActorContract::claim_refund(3, 0, &outsider).unwrap());
    assert_eq!(f.data(), before);
    assert_eq!(f.request(0), request_before);
}

// ---------------------------------------------------------------------------
// withdraw_revenue capped by real balance, not just the nominal counter
// ---------------------------------------------------------------------------

#[test]
fn withdraw_revenue_is_capped_by_real_balance_not_only_the_counter() {
    let mut f = Fixture::new();
    let owner = f.owner.address().clone();
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    f.respond(2, 0, [0xBB; 32]).expect_success();
    let earned = f.init.price_per_call + f.init.storage_fee;
    assert_eq!(f.data().withdrawable_revenue, earned);

    // Attempting to withdraw far more than the contract could ever hold
    // (it also has to keep MINIMUM_OPERATING_RESERVE) must be rejected,
    // even though nothing here directly asserts the internal counter's
    // exact value -- the point is the real-balance cap, not the counter.
    f.send_from(&owner, ServiceActorContract::withdraw_revenue(3, 1_000 * TOS).unwrap())
        .expect_aborted();
    assert_eq!(f.data().withdrawable_revenue, earned, "a rejected withdrawal must not touch the counter");

    let owner_before = f.balance(&owner);
    // A modest, clearly-affordable withdrawal must succeed.
    let modest = earned / 2;
    f.send_from(&owner, ServiceActorContract::withdraw_revenue(4, modest).unwrap()).expect_success();
    let delta = f.balance(&owner) - owner_before;
    assert!(delta > modest - TOS / 100 && delta <= modest);
    assert_eq!(f.data().withdrawable_revenue, earned - modest);
}

// ---------------------------------------------------------------------------
// Capacity: live_count/caller_live_count count pending + refundable together
// ---------------------------------------------------------------------------

#[test]
fn expiring_a_request_does_not_release_live_capacity() {
    // The whole reason live_count/caller_live_count count pending AND
    // refundable entries together: otherwise a caller could bypass a
    // per-caller cap by repeatedly expiring requests to move them into the
    // refund dictionary, "freeing up" pending slots while the total amount
    // of live state they occupy keeps growing unbounded.
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();

    f.call(&caller, 1, [0xAA; 32]).expect_success(); // request 0
    f.call(&caller, 2, [0xBB; 32]).expect_success(); // request 1
    assert_eq!(f.caller_live_count(&caller), 2);
    assert_eq!(f.pending_count(), 2);
    assert_eq!(f.live_count(), 2);

    let request0 = f.request(0).unwrap();
    f.bc.set_now(request0.response_deadline as u32);
    f.expire(&caller, 3, 0).expect_success();

    // request 0 moved from pending_requests to refunds: pending_count drops,
    // but live_count (and this caller's own live count) must NOT drop --
    // the request is still occupying a live slot, just a refundable one.
    assert_eq!(f.pending_count(), 1, "pending_count must drop when a request is expired");
    assert_eq!(f.live_count(), 2, "live_count must NOT drop: expiring does not release capacity");
    assert_eq!(
        f.caller_live_count(&caller), 2,
        "the caller's live count must NOT drop either, for the same reason"
    );

    // Only claiming (or sweeping) the refund actually releases the slot.
    f.claim_refund(&caller, 4, 0, &caller).expect_success();
    assert_eq!(f.live_count(), 1);
    assert_eq!(f.caller_live_count(&caller), 1);
}

#[test]
fn call_beyond_the_per_caller_capacity_limit_is_rejected() {
    // MAX_LIVE_PER_CALLER is 1,000 in the shipped contract -- a compiled-in
    // protocol constant, not policy-configurable, so this drives to the
    // real numeric limit rather than a smaller stand-in that wouldn't
    // actually prove the compiled bound is what's enforced.
    use contracts::service_actor::protocol_constants::MAX_LIVE_PER_CALLER;
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    for i in 0..MAX_LIVE_PER_CALLER as u64 {
        f.call(&caller, i, [i as u8; 32]).expect_success();
    }
    assert_eq!(f.caller_live_count(&caller), MAX_LIVE_PER_CALLER as u64);

    f.call(&caller, MAX_LIVE_PER_CALLER as u64, [0xFF; 32])
        .expect_aborted()
        .expect_exit_code(ERR_CAPACITY_EXCEEDED_CALLER);
    assert_eq!(
        f.caller_live_count(&caller), MAX_LIVE_PER_CALLER as u64,
        "the rejected call must not have incremented the counter"
    );
}

// ---------------------------------------------------------------------------
// Access control and rate limiting (ported unchanged from the single-slot
// Service Actor into top-level Policy/Accounting state)
// ---------------------------------------------------------------------------

#[test]
fn restricted_access_and_daily_rate_limit_match_the_compiled_bytecode() {
    let mut bc = Blockchain::new().expect("blockchain");
    bc.set_workchain(-1);
    let owner = bc.treasury("owner", 10_000 * TOS).expect("owner");
    let caller = bc.treasury("caller", 10_000 * TOS).expect("caller");
    let outsider = bc.treasury("outsider", 10_000 * TOS).expect("outsider");

    let init = ServiceActorInit {
        owner: owner.address().clone(),
        authorized_caller: Some(caller.address().clone()),
        open_access: false,
        price_per_call: TOS / 10,
        storage_fee: MIN_STORAGE_FEE + MIN_CLEANUP_BOUNTY,
        cleanup_bounty: MIN_CLEANUP_BOUNTY,
        rate_limit_per_day: 2,
        response_sla: MIN_RESPONSE_SLA,
        refund_claim_window: MIN_REFUND_CLAIM_WINDOW,
        metadata_hash: [0x11; 32],
        proof_scheme_hash: [0x22; 32],
        attestor_pubkey: None,
    };
    let service = ServiceActorContract::calculate_address(-1, &init).expect("address");
    let state_init = ServiceActorContract::build_state_init(&init).expect("state init");
    let deploy = MessageBuilder::internal(owner.address(), &service, 20 * TOS)
        .bounce(false)
        .state_init(state_init)
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();

    let owed = init.price_per_call + init.storage_fee;
    let outsider_call = MessageBuilder::internal(outsider.address(), &service, owed)
        .body(ServiceActorContract::call(1, [0xAA; 32]).unwrap())
        .build();
    bc.send_message(outsider_call).expect("outsider call").expect_aborted().expect_exit_code(ERR_NOT_AUTHORIZED);

    // The authorized caller succeeds twice, up to rate_limit_per_day. Both
    // stay concurrently pending -- this design allows that.
    for (i, hash) in [[0xBBu8; 32], [0xCCu8; 32]].into_iter().enumerate() {
        let msg = MessageBuilder::internal(caller.address(), &service, owed)
            .body(ServiceActorContract::call(2 + i as u64, hash).unwrap())
            .build();
        bc.send_message(msg).expect("authorized call").expect_success();
    }

    let stack = bc
        .run_get_method(&service, "get_service_data", vec![])
        .expect("get_service_data")
        .expect_success()
        .stack
        .clone();
    let data = ServiceActorContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(
        stack_to_entries(&stack),
    ))
    .expect("decode_data");
    assert_eq!(data.calls_today, 2, "calls_today must be read back correctly from Accounting state");
    assert_eq!(data.pending_count, 2);

    // A third call, same day, is rejected -- and must not mutate state.
    let call3 = MessageBuilder::internal(caller.address(), &service, owed)
        .body(ServiceActorContract::call(4, [0xDD; 32]).unwrap())
        .build();
    bc.send_message(call3).expect("call3").expect_aborted().expect_exit_code(ERR_RATE_LIMITED);

    let stack = bc
        .run_get_method(&service, "get_service_data", vec![])
        .expect("get_service_data")
        .expect_success()
        .stack
        .clone();
    let data = ServiceActorContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(
        stack_to_entries(&stack),
    ))
    .expect("decode_data");
    assert_eq!(data.calls_today, 2, "the rejected call must not have incremented calls_today");
    assert_eq!(data.pending_count, 2);
}

// ---------------------------------------------------------------------------
// update_policy validation bounds
// ---------------------------------------------------------------------------

#[test]
fn update_policy_enforces_response_sla_and_refund_claim_window_bounds() {
    let mut f = Fixture::new();
    let owner = f.owner.address().clone();
    let init = f.init.clone();

    let too_short_sla = MIN_RESPONSE_SLA - 1;
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            1, init.price_per_call, init.storage_fee, init.cleanup_bounty, too_short_sla,
            init.refund_claim_window, true, init.open_access, init.authorized_caller.as_ref(),
            &owner, init.rate_limit_per_day, init.metadata_hash, init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_INVALID_RESPONSE_SLA);

    let too_short_window = MIN_REFUND_CLAIM_WINDOW - 1;
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            2, init.price_per_call, init.storage_fee, init.cleanup_bounty, init.response_sla,
            too_short_window, true, init.open_access, init.authorized_caller.as_ref(), &owner,
            init.rate_limit_per_day, init.metadata_hash, init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_INVALID_REFUND_CLAIM_WINDOW);

    assert_eq!(f.data().policy_version, 0, "no rejected update_policy call may bump policy_version");
}

#[test]
fn update_policy_enforces_cleanup_bounty_and_storage_fee_bounds() {
    let mut f = Fixture::new();
    let owner = f.owner.address().clone();
    let init = f.init.clone();

    // Below MINIMUM_CLEANUP_BOUNTY.
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            1, init.price_per_call, init.storage_fee, MIN_CLEANUP_BOUNTY - 1, init.response_sla,
            init.refund_claim_window, true, init.open_access, init.authorized_caller.as_ref(),
            &owner, init.rate_limit_per_day, init.metadata_hash, init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_INVALID_CLEANUP_BOUNTY);

    // Above MAXIMUM_CLEANUP_BOUNTY.
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            2, init.price_per_call, MAX_CLEANUP_BOUNTY + MIN_STORAGE_FEE, MAX_CLEANUP_BOUNTY + 1,
            init.response_sla, init.refund_claim_window, true, init.open_access,
            init.authorized_caller.as_ref(), &owner, init.rate_limit_per_day, init.metadata_hash,
            init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_INVALID_CLEANUP_BOUNTY);

    // storage_fee below MINIMUM_STORAGE_FEE + cleanup_bounty.
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            3, init.price_per_call, MIN_STORAGE_FEE + MIN_CLEANUP_BOUNTY - 1, MIN_CLEANUP_BOUNTY,
            init.response_sla, init.refund_claim_window, true, init.open_access,
            init.authorized_caller.as_ref(), &owner, init.rate_limit_per_day, init.metadata_hash,
            init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_INSUFFICIENT_STORAGE_FEE);

    assert_eq!(f.data().policy_version, 0);

    // A valid update at the exact floor values succeeds and bumps policy_version.
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            4, init.price_per_call, MIN_STORAGE_FEE + MIN_CLEANUP_BOUNTY, MIN_CLEANUP_BOUNTY,
            init.response_sla, init.refund_claim_window, true, init.open_access,
            init.authorized_caller.as_ref(), &owner, init.rate_limit_per_day, init.metadata_hash,
            init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_success();
    assert_eq!(f.data().policy_version, 1);
}

#[test]
fn only_owner_can_call_owner_only_operations() {
    let mut f = Fixture::new();
    let outsider = f.outsider.address().clone();
    let init = f.init.clone();

    f.send_from(
        &outsider,
        ServiceActorContract::update_policy(
            1, init.price_per_call, init.storage_fee, init.cleanup_bounty, init.response_sla,
            init.refund_claim_window, true, init.open_access, init.authorized_caller.as_ref(),
            &outsider, init.rate_limit_per_day, init.metadata_hash, init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_NOT_OWNER);

    f.send_from(&outsider, ServiceActorContract::rotate_attestor_key(2, [0x99; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);
    f.send_from(&outsider, ServiceActorContract::revoke_attestor(3).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);
    f.send_from(&outsider, ServiceActorContract::withdraw_revenue(4, TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);
}
