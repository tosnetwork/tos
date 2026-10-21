/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) lifecycle tests for the concurrent-escrow Service
//! Actor -- see `https://github.com/tosnetwork/doc/blob/main/tos-blockchain/service-actor-concurrent-escrow-upgrade.md` for the
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

use chain_block::{
    BuilderData, Cell, Deserializable, IBitstring, MsgAddressInt, Serializable, SliceData,
    StateInit,
};
use contracts::service_actor::protocol_constants::{
    ADMISSION_GAS_ALLOWANCE, MINIMUM_OPERATING_RESERVE, PAYOUT_GAS_ALLOWANCE,
};
use contracts::{ServiceActorContract, ServiceActorData, ServiceActorInit};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, Treasury};
use tos_vm::stack::StackItem;

#[path = "fixtures/current_network.rs"]
mod current_network;
mod weak_ed25519;

const TOS: u64 = 1_000_000_000;
const MIN_RESPONSE_SLA: u32 = 3_600;
const MIN_REFUND_CLAIM_WINDOW: u32 = 3_600;
const MIN_STORAGE_FEE: u64 = 100_000_000;
const MIN_CLEANUP_BOUNTY: u64 = 100_000_000;
const MAX_CLEANUP_BOUNTY: u64 = 1_000_000_000;
const ERR_TERMS_MISMATCH: i32 = 1926;
const ERR_INSUFFICIENT_REVENUE: i32 = 1922;

const ERR_NOT_OWNER: i32 = 1900;
const ERR_INACTIVE: i32 = 1901;
const ERR_INSUFFICIENT_PAYMENT: i32 = 1902;
const ERR_INVALID_RESPONSE_SLA: i32 = 1903;
const ERR_INVALID_REFUND_CLAIM_WINDOW: i32 = 1904;
const ERR_INVALID_CLEANUP_BOUNTY: i32 = 1905;
const ERR_INSUFFICIENT_STORAGE_FEE: i32 = 1906;
const ERR_CAPACITY_EXCEEDED_GLOBAL: i32 = 1907;
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
const ERR_OPERATING_RESERVE_UNFUNDED: i32 = 1928;
const ERR_INSUFFICIENT_EXECUTION_PAYMENT: i32 = 1929;

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
        let mut bc =
            Blockchain::with_global_version(current_network::global_version()).expect("blockchain");
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
        self.send_with_optional_trace(msg)
    }

    /// Preserve the real executor inputs and outputs for production-engine replay.
    /// Recording is opt-in so ordinary sandbox runs create no files.
    fn send_with_optional_trace(&mut self, msg: chain_block::Message) -> SendResult {
        use chain_block::{HashmapType, ShardAccount, UInt256, base64_encode, write_boc};

        let boc = |cell: Cell| base64_encode(write_boc(&cell).expect("trace BOC"));
        let trace = std::env::var_os("SERVICE_ACTOR_TRACE_DIR").map(|dir| {
            let account = self.bc.get_account(&self.service).expect("service before transaction");
            let shard =
                ShardAccount::with_params(account, UInt256::default(), 0).expect("trace pre-state");
            let config = HashmapType::data(&self.bc.config_params().config_params)
                .cloned()
                .expect("trace configuration");
            (dir, boc(config), boc(shard.serialize().unwrap()), boc(msg.serialize().unwrap()))
        });
        let result = self.bc.send_message(msg).expect("send");
        if let Some((dir, config, shard_account, message)) = trace {
            assert_eq!(
                result.transactions_for(&self.service).len(),
                1,
                "native trace requires one service transaction per cascade"
            );
            let tx = result.first_transaction().expect("service transaction");
            let after = self.bc.get_account(&self.service).expect("service after transaction");
            let shard_after =
                ShardAccount::with_params(after, UInt256::default(), 0).expect("trace post-state");
            let record = serde_json::json!({
                "unixtime": self.bc.now(),
                "lt": tx.logical_time().to_string(),
                "config": config,
                "shard_account": shard_account,
                "message": message,
                "rust_transaction": boc(tx.serialize().unwrap()),
                "shard_account_after": boc(shard_after.serialize().unwrap()),
            });
            let thread = std::thread::current();
            let test = thread.name().unwrap_or("unnamed").replace("::", "-");
            let dir = std::path::PathBuf::from(dir).join(test);
            std::fs::create_dir_all(&dir).expect("trace directory");
            static NEXT_TRACE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let index = NEXT_TRACE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::fs::write(dir.join(format!("{index:04}.json")), record.to_string())
                .expect("trace record");
        }
        result
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

    /// A call that commits to the terms the service currently publishes, paying
    /// the current price and storage fee plus a gas margin.
    fn call(&mut self, from: &MsgAddressInt, query_id: u64, request_hash: [u8; 32]) -> SendResult {
        let data = self.data();
        let value = data.price_per_call + data.storage_fee + TOS / 2;
        let terms = ServiceActorContract::terms_hash_of_data(&data).unwrap();
        self.send_from_with_value(
            from,
            ServiceActorContract::call(query_id, request_hash, terms).unwrap(),
            value,
        )
    }

    /// The terms hash the service currently publishes.
    fn terms(&self) -> [u8; 32] {
        ServiceActorContract::terms_hash_of_data(&self.data()).unwrap()
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
            ServiceActorContract::respond_signed(query_id, request_id, response_hash, signature)
                .unwrap(),
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
        self.send_from(
            from,
            ServiceActorContract::claim_refund(query_id, request_id, destination).unwrap(),
        )
    }

    fn sweep(&mut self, from: &MsgAddressInt, query_id: u64, request_id: u64) -> SendResult {
        self.send_from(
            from,
            ServiceActorContract::sweep_expired_request(query_id, request_id).unwrap(),
        )
    }
}

fn address_slice(addr: &MsgAddressInt) -> chain_block::SliceData {
    use chain_block::Serializable;
    let cell = addr.write_to_new_cell().unwrap().into_cell().unwrap();
    chain_block::SliceData::load_cell(cell).unwrap()
}

/// Inspect the service's own output messages, before recipient execution fees.
fn service_outputs(result: &SendResult) -> Vec<(MsgAddressInt, u64)> {
    let mut outputs = Vec::new();
    result
        .first_transaction()
        .expect("service transaction")
        .iterate_out_msgs(|message| {
            outputs.push((
                message.dst().expect("internal destination"),
                message.get_value().expect("internal value").coins.as_u64().expect("u64 value"),
            ));
            Ok(true)
        })
        .expect("outgoing messages");
    outputs
}

fn execution_fees(result: &SendResult) -> u64 {
    let description = result.read_primary_description();
    let chain_block::TrComputePhase::Vm(vm) = description.compute_ph else {
        panic!("expected VM computation");
    };
    vm.gas_fees
        .as_u64()
        .unwrap()
        .checked_add(description.action.expect("action phase").total_fwd_fees().as_u64().unwrap())
        .unwrap()
}

fn storage_fees(result: &SendResult) -> u64 {
    result
        .read_primary_description()
        .storage_ph
        .map(|phase| phase.storage_fees_collected.as_u64().unwrap())
        .unwrap_or(0)
}

fn expect_payment_and_change(
    result: &SendResult,
    destination: &MsgAddressInt,
    payer: &MsgAddressInt,
    principal: u64,
    budget: u64,
) {
    result.expect_success().expect_exit_code(0);
    let outputs = service_outputs(result);
    let change = if principal > 0 {
        assert_eq!(outputs.len(), 2, "principal and change have distinct messages");
        assert_eq!(outputs[0], (destination.clone(), principal), "principal is paid in full");
        &outputs[1]
    } else {
        assert_eq!(outputs.len(), 1, "zero principal returns only the execution change");
        &outputs[0]
    };
    assert_eq!(change.0, *payer, "unused execution funding belongs to its sender");
    assert_eq!(
        change.1,
        budget.checked_sub(execution_fees(result)).unwrap(),
        "only this operation's execution and forwarding fees reduce change"
    );
}

/// Rebuild only the scalar prefix of Service Actor data while preserving all
/// policy/accounting/dictionary references. This lets boundary tests exercise
/// otherwise impractical uint64/global-cap states against the shipped BOC.
fn data_with_runtime_counters(
    init: &ServiceActorInit,
    next_request_id: u64,
    pending_count: u32,
    live_count: u32,
) -> Cell {
    let original = ServiceActorContract::build_data(init).expect("build data");
    let mut slice = SliceData::load_cell(original).expect("data slice");
    let owner = MsgAddressInt::construct_from(&mut slice).expect("owner");
    let active = slice.get_next_bit().expect("active");
    let _old_next = slice.get_next_u64().expect("next_request_id");
    let _old_pending = slice.get_next_u32().expect("pending_count");
    let _old_live = slice.get_next_u32().expect("live_count");
    let policy = slice.checked_drain_reference().expect("policy");
    let accounting = slice.checked_drain_reference().expect("accounting");
    let dicts = slice.checked_drain_reference().expect("dicts");

    let mut data = BuilderData::new();
    owner.write_to(&mut data).expect("owner write");
    if active {
        data.append_bit_one().unwrap()
    } else {
        data.append_bit_zero().unwrap()
    };
    data.append_u64(next_request_id).unwrap();
    data.append_u32(pending_count).unwrap();
    data.append_u32(live_count).unwrap();
    data.checked_append_reference(policy).unwrap();
    data.checked_append_reference(accounting).unwrap();
    data.checked_append_reference(dicts).unwrap();
    data.into_cell().expect("patched data")
}

fn deploy_with_runtime_counters(
    bc: &mut Blockchain,
    owner: &Treasury,
    init: &ServiceActorInit,
    next_request_id: u64,
    pending_count: u32,
    live_count: u32,
) -> MsgAddressInt {
    let state_init = StateInit::with_code_and_data(
        ServiceActorContract::code().expect("code"),
        data_with_runtime_counters(init, next_request_id, pending_count, live_count),
    );
    let hash = state_init
        .write_to_new_cell()
        .expect("state init builder")
        .into_cell()
        .expect("state init cell")
        .hash(0);
    let address = MsgAddressInt::with_params(-1, hash).expect("address");
    let deploy = MessageBuilder::internal(owner.address(), &address, 20 * TOS)
        .bounce(false)
        .state_init(state_init)
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();
    address
}

fn stack_to_entries(stack: &[tos_vm::stack::StackItem]) -> Vec<tl_api::tos::tvm::StackEntry> {
    use tl_api::tos::tvm::{
        Number, StackEntry,
        numberdecimal::NumberDecimal,
        slice,
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
    let result = f.send_from_with_value(
        &outsider,
        ServiceActorContract::call(1, [0xAA; 32], f.terms()).unwrap(),
        owed + TOS,
    );
    result.expect_success();
    let data = f.data();
    assert_eq!(data.pending_liability, f.init.price_per_call, "only the quoted price is owed");
    assert_eq!(data.locked_storage_fees, f.init.storage_fee, "only the quoted storage fee is owed");
    let delta = f.balance(&outsider) - outsider_before;
    assert!(
        delta > TOS.checked_sub(ADMISSION_GAS_ALLOWANCE).unwrap() && delta < TOS,
        "the caller receives unused execution funding after fees, got {delta}"
    );
}

#[test]
fn call_below_price_plus_storage_fee_is_rejected() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let owed = f.init.price_per_call + f.init.storage_fee;
    f.send_from_with_value(
        &caller,
        ServiceActorContract::call(1, [0xAA; 32], f.terms()).unwrap(),
        owed - 1,
    )
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
            1,
            init.price_per_call,
            init.storage_fee,
            init.cleanup_bounty,
            init.response_sla,
            init.refund_claim_window,
            false,
            init.open_access,
            init.authorized_caller.as_ref(),
            &owner,
            init.rate_limit_per_day,
            init.metadata_hash,
            init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_success();
    assert!(!f.data().active);

    let caller = f.caller.address().clone();
    f.call(&caller, 2, [0xAA; 32]).expect_aborted().expect_exit_code(ERR_INACTIVE);
}

#[test]
fn deploy_with_out_of_bounds_policy_is_rejected_at_call_time() {
    // The protocol constants (MIN/MAX_RESPONSE_SLA, MIN/MAX_REFUND_CLAIM_WINDOW,
    // MIN/MAX_CLEANUP_BOUNTY, storage_fee >= MINIMUM_STORAGE_FEE + cleanup_bounty)
    // are only checked by update_policy -- the StateInit an owner supplies at
    // deploy time never passes through it. Deploy directly with an
    // out-of-bounds cleanup_bounty (bypassing any client-side validation the
    // Rust SDK/CLI might separately add) and confirm the chain itself, not
    // just the tooling, rejects the first call rather than silently admitting
    // requests under a policy with e.g. zero incentive to ever sweep an
    // expired entry.
    let mut bc =
        Blockchain::with_global_version(current_network::global_version()).expect("blockchain");
    bc.set_workchain(-1);
    let owner = bc.treasury("bad-deploy-owner", 100 * TOS).unwrap();
    let caller = bc.treasury("bad-deploy-caller", 100 * TOS).unwrap();

    let bad_init = ServiceActorInit {
        owner: owner.address().clone(),
        authorized_caller: None,
        open_access: true,
        price_per_call: TOS / 10,
        storage_fee: MIN_STORAGE_FEE,
        cleanup_bounty: 0, // below MINIMUM_CLEANUP_BOUNTY
        rate_limit_per_day: 0,
        response_sla: MIN_RESPONSE_SLA,
        refund_claim_window: MIN_REFUND_CLAIM_WINDOW,
        metadata_hash: [0x11; 32],
        proof_scheme_hash: [0x22; 32],
        attestor_pubkey: None,
    };
    let service = ServiceActorContract::calculate_address(-1, &bad_init).expect("address");
    let state_init = ServiceActorContract::build_state_init(&bad_init).expect("state init");
    let deploy = MessageBuilder::internal(owner.address(), &service, 20 * TOS)
        .bounce(false)
        .state_init(state_init)
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();

    let msg = MessageBuilder::internal(caller.address(), &service, TOS)
        .body(
            ServiceActorContract::call(
                1,
                [0xAA; 32],
                ServiceActorContract::terms_hash_of_init(&bad_init).unwrap(),
            )
            .unwrap(),
        )
        .build();
    bc.send_message(msg).unwrap().expect_aborted().expect_exit_code(ERR_INVALID_CLEANUP_BOUNTY);

    let stack = bc
        .run_get_method(&service, "get_service_data", vec![])
        .unwrap()
        .expect_success()
        .stack
        .clone();
    let data = ServiceActorContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(
        stack_to_entries(&stack),
    ))
    .unwrap();
    assert_eq!(data.pending_count, 0);
    assert_eq!(data.live_count, 0);
}

#[test]
fn request_id_overflow_is_rejected_without_mutating_state() {
    let mut bc =
        Blockchain::with_global_version(current_network::global_version()).expect("blockchain");
    bc.set_workchain(-1);
    let owner = bc.treasury("overflow-owner", 100 * TOS).unwrap();
    let caller = bc.treasury("overflow-caller", 100 * TOS).unwrap();
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
        attestor_pubkey: None,
    };
    let service = deploy_with_runtime_counters(&mut bc, &owner, &init, u64::MAX, 0, 0);
    let msg = MessageBuilder::internal(caller.address(), &service, TOS)
        .body(
            ServiceActorContract::call(
                1,
                [0xAA; 32],
                ServiceActorContract::terms_hash_of_init(&init).unwrap(),
            )
            .unwrap(),
        )
        .build();
    bc.send_message(msg).unwrap().expect_aborted().expect_exit_code(1909);
    let stack = bc
        .run_get_method(&service, "get_service_data", vec![])
        .unwrap()
        .expect_success()
        .stack
        .clone();
    let data = ServiceActorContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(
        stack_to_entries(&stack),
    ))
    .unwrap();
    assert_eq!(data.next_request_id, u64::MAX);
    assert_eq!(data.live_count, 0);
}

#[test]
fn global_live_capacity_is_enforced_by_the_shipped_bytecode() {
    let mut bc =
        Blockchain::with_global_version(current_network::global_version()).expect("blockchain");
    bc.set_workchain(-1);
    let owner = bc.treasury("global-cap-owner", 100 * TOS).unwrap();
    let caller = bc.treasury("global-cap-caller", 100 * TOS).unwrap();
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
        attestor_pubkey: None,
    };
    let service = deploy_with_runtime_counters(&mut bc, &owner, &init, 7, 0, 100_000);
    let msg = MessageBuilder::internal(caller.address(), &service, TOS)
        .body(
            ServiceActorContract::call(
                1,
                [0xBB; 32],
                ServiceActorContract::terms_hash_of_init(&init).unwrap(),
            )
            .unwrap(),
        )
        .build();
    bc.send_message(msg).unwrap().expect_aborted().expect_exit_code(ERR_CAPACITY_EXCEEDED_GLOBAL);
    let stack = bc
        .run_get_method(&service, "get_service_data", vec![])
        .unwrap()
        .expect_success()
        .stack
        .clone();
    let data = ServiceActorContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(
        stack_to_entries(&stack),
    ))
    .unwrap();
    assert_eq!(data.next_request_id, 7);
    assert_eq!(data.live_count, 100_000);
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
    f.respond(4, 1, [0xDD; 32]).expect_aborted().expect_exit_code(ERR_RESPONSE_WINDOW_CLOSED);
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
    let result = f.claim_refund(&caller, 3, 0, &caller);
    expect_payment_and_change(&result, &caller, &caller, f.init.price_per_call, TOS / 2);

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
    let result = f.sweep(&outsider, 2, 0);
    expect_payment_and_change(&result, &outsider, &outsider, f.init.cleanup_bounty, TOS / 2);

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
    let result = f.sweep(&outsider, 3, 0);
    expect_payment_and_change(&result, &outsider, &outsider, f.init.cleanup_bounty, TOS / 2);

    assert!(f.refund(0).is_none());
    let data = f.data();
    assert_eq!(data.refundable_liability, 0);
    assert_eq!(data.locked_storage_fees, 0);
    assert_eq!(
        data.withdrawable_revenue,
        f.init.price_per_call + f.init.storage_fee - f.init.cleanup_bounty
    );
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
        sandbox_global_id(&f.bc),
        &f.service,
        &request0.caller,
        0,
        &request0.request_hash,
        &response_hash,
        &request0.terms_hash,
        request0.price,
        request0.response_deadline,
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
        sandbox_global_id(&f.bc),
        &f.service,
        &request1.caller,
        1,
        &request1.request_hash,
        &response_hash,
        &request1.terms_hash,
        request1.price,
        request1.response_deadline,
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
        sandbox_global_id(&f.bc),
        &f.service,
        &request.caller,
        0,
        &request.request_hash,
        &response_hash,
        &request.terms_hash,
        request.price,
        request.response_deadline,
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
            3,
            new_init.price_per_call,
            new_init.storage_fee,
            new_init.cleanup_bounty,
            new_init.response_sla,
            new_init.refund_claim_window,
            true,
            new_init.open_access,
            new_init.authorized_caller.as_ref(),
            &owner,
            new_init.rate_limit_per_day,
            new_init.metadata_hash,
            new_init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_success();

    let request0_after = f.request(0).unwrap();
    assert_eq!(
        request0_after, request0_before,
        "already-snapshotted request must be byte-identical"
    );

    // A new request accepted after the change snapshots the new terms.
    f.call(&caller, 4, [0xBB; 32]).expect_success(); // request 1
    let request1 = f.request(1).unwrap();
    assert_eq!(request1.price, new_init.price_per_call);
    assert_eq!(request1.attestor_pubkey, Some(new_attestor_pubkey));
    assert_ne!(request1.terms_hash, request0_after.terms_hash);

    // request 0 still requires the OLD attestor's signature, not the new one.
    let response_hash = [0xCC; 32];
    let domain_0 = contracts::service_respond_domain_hash(
        sandbox_global_id(&f.bc),
        &f.service,
        &request0_after.caller,
        0,
        &request0_after.request_hash,
        &response_hash,
        &request0_after.terms_hash,
        request0_after.price,
        request0_after.response_deadline,
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
        sandbox_global_id(&f.bc),
        &f.service,
        &request1_after.caller,
        1,
        &request1_after.request_hash,
        &response_hash,
        &request1_after.terms_hash,
        request1_after.price,
        request1_after.response_deadline,
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
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    f.bc.set_now(f.request(0).unwrap().response_deadline as u32);
    f.send_from(&caller, ServiceActorContract::expire(2, 0).unwrap()).expect_success();
    // Model an already rent-eroded account without admitting new work while
    // underfunded. The claim must survive even when its own price is unbacked.
    f.set_balance(1);
    f.send_from_with_value(
        &caller,
        ServiceActorContract::claim_refund(3, 0, &caller).unwrap(),
        TOS / 20,
    )
    .expect_aborted()
    .expect_exit_code(ERR_INSUFFICIENT_BALANCE);
    assert!(f.refund(0).is_some());
}

#[test]
fn claim_to_nonexistent_destination_does_not_restore_or_double_count_liability() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [0xAB; 32]).expect_success();
    let deadline = f.request(0).unwrap().response_deadline;
    f.bc.set_now(deadline as u32);
    f.expire(&caller, 2, 0).expect_success();

    let missing = MsgAddressInt::with_params(-1, [0xFE; 32]).expect("missing address");
    f.claim_refund(&caller, 3, 0, &missing).expect_success();

    // The destination cannot process the transfer. Any protocol bounce is
    // ordinary contract balance and, by design, cannot authenticate a
    // restoration. The request remains final with no duplicate liability.
    assert!(f.refund(0).is_none());
    let data = f.data();
    assert_eq!(data.refundable_liability, 0);
    assert_eq!(data.pending_liability, 0);
    assert_eq!(data.live_count, 0);
    assert!(f.balance(&f.service) >= TOS, "operating reserve must remain backed");
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
    assert_eq!(
        f.data().withdrawable_revenue,
        earned,
        "a rejected withdrawal must not touch the counter"
    );

    // A modest, clearly-affordable withdrawal must succeed.
    let modest = earned / 2;
    let result = f.send_from(&owner, ServiceActorContract::withdraw_revenue(4, modest).unwrap());
    expect_payment_and_change(&result, &owner, &owner, modest, TOS / 2);
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
        f.caller_live_count(&caller),
        2,
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
        f.caller_live_count(&caller),
        MAX_LIVE_PER_CALLER as u64,
        "the rejected call must not have incremented the counter"
    );
}

// ---------------------------------------------------------------------------
// Access control and rate limiting (ported unchanged from the single-slot
// Service Actor into top-level Policy/Accounting state)
// ---------------------------------------------------------------------------

#[test]
fn restricted_access_and_daily_rate_limit_match_the_compiled_bytecode() {
    let mut bc =
        Blockchain::with_global_version(current_network::global_version()).expect("blockchain");
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

    let funding = ServiceActorContract::minimum_call_payment(init.price_per_call, init.storage_fee)
        .expect("funded call");
    let outsider_call = MessageBuilder::internal(outsider.address(), &service, funding)
        .body(
            ServiceActorContract::call(
                1,
                [0xAA; 32],
                ServiceActorContract::terms_hash_of_init(&init).unwrap(),
            )
            .unwrap(),
        )
        .build();
    bc.send_message(outsider_call)
        .expect("outsider call")
        .expect_aborted()
        .expect_exit_code(ERR_NOT_AUTHORIZED);

    // The authorized caller succeeds twice, up to rate_limit_per_day. Both
    // stay concurrently pending -- this design allows that.
    for (i, hash) in [[0xBBu8; 32], [0xCCu8; 32]].into_iter().enumerate() {
        let msg = MessageBuilder::internal(caller.address(), &service, funding)
            .body(
                ServiceActorContract::call(
                    2 + i as u64,
                    hash,
                    ServiceActorContract::terms_hash_of_init(&init).unwrap(),
                )
                .unwrap(),
            )
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
    assert_eq!(
        data.calls_today, 2,
        "calls_today must be read back correctly from Accounting state"
    );
    assert_eq!(data.pending_count, 2);

    // A third call, same day, is rejected -- and must not mutate state.
    let call3 = MessageBuilder::internal(caller.address(), &service, funding)
        .body(
            ServiceActorContract::call(
                4,
                [0xDD; 32],
                ServiceActorContract::terms_hash_of_init(&init).unwrap(),
            )
            .unwrap(),
        )
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
            1,
            init.price_per_call,
            init.storage_fee,
            init.cleanup_bounty,
            too_short_sla,
            init.refund_claim_window,
            true,
            init.open_access,
            init.authorized_caller.as_ref(),
            &owner,
            init.rate_limit_per_day,
            init.metadata_hash,
            init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_INVALID_RESPONSE_SLA);

    let too_short_window = MIN_REFUND_CLAIM_WINDOW - 1;
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            2,
            init.price_per_call,
            init.storage_fee,
            init.cleanup_bounty,
            init.response_sla,
            too_short_window,
            true,
            init.open_access,
            init.authorized_caller.as_ref(),
            &owner,
            init.rate_limit_per_day,
            init.metadata_hash,
            init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_INVALID_REFUND_CLAIM_WINDOW);

    assert_eq!(
        f.data().policy_version,
        0,
        "no rejected update_policy call may bump policy_version"
    );
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
            1,
            init.price_per_call,
            init.storage_fee,
            MIN_CLEANUP_BOUNTY - 1,
            init.response_sla,
            init.refund_claim_window,
            true,
            init.open_access,
            init.authorized_caller.as_ref(),
            &owner,
            init.rate_limit_per_day,
            init.metadata_hash,
            init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_INVALID_CLEANUP_BOUNTY);

    // Above MAXIMUM_CLEANUP_BOUNTY.
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            2,
            init.price_per_call,
            MAX_CLEANUP_BOUNTY + MIN_STORAGE_FEE,
            MAX_CLEANUP_BOUNTY + 1,
            init.response_sla,
            init.refund_claim_window,
            true,
            init.open_access,
            init.authorized_caller.as_ref(),
            &owner,
            init.rate_limit_per_day,
            init.metadata_hash,
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
            3,
            init.price_per_call,
            MIN_STORAGE_FEE + MIN_CLEANUP_BOUNTY - 1,
            MIN_CLEANUP_BOUNTY,
            init.response_sla,
            init.refund_claim_window,
            true,
            init.open_access,
            init.authorized_caller.as_ref(),
            &owner,
            init.rate_limit_per_day,
            init.metadata_hash,
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
            4,
            init.price_per_call,
            MIN_STORAGE_FEE + MIN_CLEANUP_BOUNTY,
            MIN_CLEANUP_BOUNTY,
            init.response_sla,
            init.refund_claim_window,
            true,
            init.open_access,
            init.authorized_caller.as_ref(),
            &owner,
            init.rate_limit_per_day,
            init.metadata_hash,
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
            1,
            init.price_per_call,
            init.storage_fee,
            init.cleanup_bounty,
            init.response_sla,
            init.refund_claim_window,
            true,
            init.open_access,
            init.authorized_caller.as_ref(),
            &outsider,
            init.rate_limit_per_day,
            init.metadata_hash,
            init.proof_scheme_hash,
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

/// The network the sandbox runs, as GLOBALID reads it from ConfigParam 19.
fn sandbox_global_id(bc: &Blockchain) -> i32 {
    match bc.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        other => panic!("parameter 19 is not the global id: {other:?}"),
    }
}

const ERR_WEAK_ATTESTOR: i32 = 1925;

/// An attestor key anyone could sign for is refused when the owner rotates to
/// it, and refused at response when it arrived in a hand-built StateInit.
#[test]
fn weak_attestor_keys_are_refused_when_set_and_when_used() {
    let mut f = Fixture::new();
    let owner = f.owner.address().clone();
    for weak in weak_ed25519::weak_keys() {
        f.send_from(&owner, ServiceActorContract::rotate_attestor_key(1, weak).unwrap())
            .expect_aborted()
            .expect_exit_code(ERR_WEAK_ATTESTOR);
    }
    assert_eq!(f.data().attestor_pubkey, None, "a refused key must not be stored");
    let strong = SigningKey::from_bytes(&[0x77; 32]).verifying_key().to_bytes();
    f.send_from(&owner, ServiceActorContract::rotate_attestor_key(2, strong).unwrap())
        .expect_success();
    assert_eq!(f.data().attestor_pubkey, Some(strong));

    let mut f = Fixture::with_attestor(weak_ed25519::weak_keys()[0]);
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    f.respond_signed(2, 0, [0xBB; 32], &[0u8; 64])
        .expect_aborted()
        .expect_exit_code(ERR_WEAK_ATTESTOR);
    assert!(f.request(0).is_some());
}

/// A response signed for another network does not answer here.
#[test]
fn a_response_signed_for_another_network_is_refused() {
    let attestor = SigningKey::from_bytes(&[0x77; 32]);
    let mut f = Fixture::with_attestor(attestor.verifying_key().to_bytes());
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let request = f.request(0).unwrap();
    let response_hash = [0xBB; 32];
    let here = sandbox_global_id(&f.bc);
    let domain = |global_id: i32| {
        contracts::service_respond_domain_hash(
            global_id,
            &f.service,
            &request.caller,
            0,
            &request.request_hash,
            &response_hash,
            &request.terms_hash,
            request.price,
            request.response_deadline,
            request.refund_claim_deadline,
        )
        .unwrap()
    };
    let elsewhere = attestor.sign(&domain(here.wrapping_add(1))).to_bytes();
    let this_network = attestor.sign(&domain(here)).to_bytes();
    f.respond_signed(2, 0, response_hash, &elsewhere)
        .expect_aborted()
        .expect_exit_code(ERR_BAD_RESPONSE_SIGNATURE);
    f.respond_signed(3, 0, response_hash, &this_network).expect_success();
    assert!(f.request(0).is_none());
}

// ---------------------------------------------------------------------------
// Terms binding and the liability floor (audit findings M-SA-02 and M-SA-01).
// ---------------------------------------------------------------------------

/// A call commits to the terms it was quoted. When the owner revokes the
/// attestor and doubles the price between the quote and the call, the call
/// built for the quote is refused before any state moves, and a call built
/// for the new terms is admitted under them.
#[test]
fn a_call_quoted_under_one_policy_is_refused_under_another() {
    let attestor = SigningKey::from_bytes(&[0x11; 32]);
    let mut f = Fixture::with_attestor(attestor.verifying_key().to_bytes());
    let owner = f.owner.address().clone();
    let caller = f.caller.address().clone();

    // The quote: a first call snapshots the terms the caller agreed to.
    let quoted_terms = f.terms();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let quoted = f.request(0).expect("request 0");
    assert_eq!(quoted.price, f.init.price_per_call);
    assert_eq!(quoted.attestor_pubkey, Some(attestor.verifying_key().to_bytes()));
    assert_eq!(quoted.terms_hash, quoted_terms, "the snapshot carries the published terms");

    // Between quote and execution the owner revokes the attestor and doubles
    // the price.
    f.send_from(&owner, ServiceActorContract::revoke_attestor(2).unwrap()).expect_success();
    let doubled = f.init.price_per_call * 2;
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            3,
            doubled,
            f.init.storage_fee,
            f.init.cleanup_bounty,
            f.init.response_sla,
            f.init.refund_claim_window,
            true,
            f.init.open_access,
            f.init.authorized_caller.as_ref(),
            &owner,
            f.init.rate_limit_per_day,
            f.init.metadata_hash,
            f.init.proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_success();
    assert_ne!(f.terms(), quoted_terms, "the published terms changed");

    // The caller sends exactly the message it built for the quote, with
    // enough value for the new price: refused on the terms, nothing admitted.
    let liability_before = f.data().pending_liability;
    let value = doubled + quoted.storage_fee + TOS / 2;
    f.send_from_with_value(
        &caller,
        ServiceActorContract::call(4, [0xAB; 32], quoted_terms).unwrap(),
        value,
    )
    .expect_aborted()
    .expect_exit_code(ERR_TERMS_MISMATCH);
    assert!(f.request(1).is_none(), "a call for stale terms was admitted");
    assert_eq!(f.data().pending_liability, liability_before, "a refused call moved liability");

    // A call built for the new terms is admitted under them.
    f.call(&caller, 5, [0xAC; 32]).expect_success();
    let admitted = f.request(1).expect("request 1");
    assert_eq!(admitted.price, doubled);
    assert_eq!(admitted.attestor_pubkey, None);
    assert_eq!(admitted.terms_hash, f.terms());
}

/// The owner's withdrawal cap keeps the storage fees locked for live entries
/// in the contract. Storage rent erodes backing; successful calls separately
/// fund their own execution. The test uses rent,
/// letting it accrue until the balance no longer covers pending +
/// refundable + locked + reserve + revenue, then shows the nominal revenue is
/// refused while the amount that leaves the locked fees intact is paid.
#[test]
fn withdraw_revenue_never_takes_the_storage_fees_locked_for_live_entries() {
    const RESERVE: u64 = TOS; // MINIMUM_OPERATING_RESERVE in the contract
    let mut bc =
        Blockchain::with_global_version(current_network::global_version()).expect("blockchain");
    bc.set_workchain(-1);
    let owner = bc.treasury("owner", 10_000 * TOS).expect("owner");
    let caller = bc.treasury("caller", 10_000 * TOS).expect("caller");
    let client = bc.treasury("client", 10_000 * TOS).expect("client");
    let outsider = bc.treasury("outsider", 10_000 * TOS).expect("outsider");
    // A large storage fee makes the locked amount, and so the gap between a
    // cap that ignores it and one that keeps it, wide enough for rent to land
    // inside.
    let init = ServiceActorInit {
        owner: owner.address().clone(),
        authorized_caller: None,
        open_access: true,
        price_per_call: TOS / 10,
        storage_fee: 5 * TOS,
        cleanup_bounty: MIN_CLEANUP_BOUNTY,
        rate_limit_per_day: 0,
        response_sla: MIN_RESPONSE_SLA,
        // The live entry must stay live for the whole accrual, so its rights
        // window is the maximum.
        refund_claim_window: 2_592_000,
        metadata_hash: [0x11; 32],
        proof_scheme_hash: [0x22; 32],
        attestor_pubkey: None,
    };
    let service = ServiceActorContract::calculate_address(-1, &init).expect("address");
    let state_init = ServiceActorContract::build_state_init(&init).expect("state init");
    let deploy = MessageBuilder::internal(owner.address(), &service, RESERVE + TOS / 5)
        .bounce(false)
        .state_init(state_init)
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();
    let mut f = Fixture { bc, owner, caller, caller2: client, outsider, service, init };
    let owner = f.owner.address().clone();
    let caller = f.caller.address().clone();
    let client = f.caller2.address().clone();

    // One live client request: its storage fee is locked. One responded
    // request: nominal revenue.
    f.call(&client, 1, [0xCC; 32]).expect_success();
    f.call(&caller, 2, [0xAA; 32]).expect_success();
    f.respond(3, 1, [0xBB; 32]).expect_success();
    let revenue = f.data().withdrawable_revenue;
    assert_eq!(revenue, f.init.price_per_call + f.init.storage_fee);
    let probe_value = TOS / 20;
    let floor_with_locked = |f: &Fixture| {
        let d = f.data();
        d.pending_liability + d.refundable_liability + d.locked_storage_fees + RESERVE
    };

    // Let rent accrue, a day at a time, until the balance (with the probe's
    // own value) no longer covers the floor plus the whole revenue. Each probe
    // is a withdrawal nobody could ever afford, sent without bounce so its
    // value stays: it applies the storage phase and changes nothing else.
    let mut q = 10u64;
    let mut day = 0u32;
    loop {
        day += 1;
        assert!(day <= 400, "rent never brought the balance below the floor plus revenue");
        f.bc.set_now(f.bc.now() + 86_400);
        let probe = MessageBuilder::internal(&owner, &f.service, probe_value)
            .bounce(false)
            .body(ServiceActorContract::withdraw_revenue(q, u64::MAX).unwrap())
            .build();
        f.bc.send_message(probe).expect("probe").expect_aborted();
        q += 1;
        if f.balance(&f.service) + probe_value < floor_with_locked(&f) + revenue {
            break;
        }
    }
    let balance = f.balance(&f.service);
    let d = f.data();
    let floor_without_locked = d.pending_liability + d.refundable_liability + RESERVE;
    assert!(
        balance + probe_value >= floor_without_locked + revenue,
        "rent ran past the window: a cap ignoring locked fees would refuse this too (balance {balance})"
    );
    eprintln!("day {day}: balance {balance}, locked {}, revenue {revenue}", d.locked_storage_fees);

    // The nominal revenue is refused: paying it would take locked fees.
    let withdraw = MessageBuilder::internal(&owner, &f.service, probe_value)
        .bounce(false)
        .body(ServiceActorContract::withdraw_revenue(q, revenue).unwrap())
        .build();
    f.bc.send_message(withdraw)
        .expect("withdraw")
        .expect_aborted()
        .expect_exit_code(ERR_INSUFFICIENT_REVENUE);
    q += 1;
    assert_eq!(f.data().withdrawable_revenue, revenue, "a refused withdrawal touched the counter");

    // What leaves the locked fees intact is paid, and the floor holds after.
    // (The refused message's own value stayed in the contract, so the cap may
    // have moved up by it since.)
    let balance = f.balance(&f.service);
    let affordable = balance.checked_sub(floor_with_locked(&f)).unwrap().min(revenue);
    assert!(affordable > 0, "nothing affordable at balance {balance}");
    let withdraw = MessageBuilder::internal(&owner, &f.service, PAYOUT_GAS_ALLOWANCE)
        .bounce(false)
        .body(ServiceActorContract::withdraw_revenue(q, affordable).unwrap())
        .build();
    f.bc.send_message(withdraw).expect("withdraw").expect_success();
    assert!(
        f.balance(&f.service) >= floor_with_locked(&f),
        "the paid withdrawal took the balance below pending + refundable + locked + reserve"
    );
    assert_eq!(f.data().withdrawable_revenue, revenue - affordable);
}

// ---------------------------------------------------------------------------
// Coin arithmetic: every coin computation is bounded where it happens
// ---------------------------------------------------------------------------

/// A coin computation left the range a Coins field holds: a sum at or past
/// 2^120, or a liability going negative. Never a caller's refusal code.
const ERR_AMOUNT_RANGE: i32 = 1927;
/// The largest value a Coins field holds: 2^120 - 1, written out so the bound is
/// a literal and not a computation.
const MAX_COINS: u128 = 1_329_227_995_784_915_872_903_807_060_280_344_575;
/// The gas margin the fixture attaches to a call, in nanotos (0.5 TOS).
const CALL_GAS_MARGIN: u64 = 500_000_000;
/// A balance just short of the largest bounty, in nanotos (0.9 TOS).
const BALANCE_BELOW_MAX_BOUNTY: u64 = 900_000_000;
/// The value a sweeper attaches in the shortfall case, in nanotos (0.05 TOS).
const SWEEP_VALUE_BELOW_SHORTFALL: u64 = 50_000_000;

/// The accounting cell of a Service Actor's data, in the order `build_data`
/// writes it. Values beyond u64 are what these tests are about, so the cell is
/// read and written here rather than through the u64 decoder.
#[derive(Clone, Copy, Debug)]
struct Accounting {
    withdrawable_revenue: u128,
    locked_storage_fees: u128,
    pending_liability: u128,
    refundable_liability: u128,
    call_day: u32,
    calls_today: u32,
}

fn coins(value: u128) -> chain_block::Coins {
    use std::str::FromStr;
    chain_block::Coins::from_str(&value.to_string()).expect("coins")
}

fn read_accounting(cell: &Cell) -> Accounting {
    let mut s = SliceData::load_cell(cell.clone()).expect("accounting slice");
    let withdrawable_revenue =
        chain_block::Coins::construct_from(&mut s).expect("revenue").as_u128();
    let locked_storage_fees = chain_block::Coins::construct_from(&mut s).expect("locked").as_u128();
    let pending_liability = chain_block::Coins::construct_from(&mut s).expect("pending").as_u128();
    let refundable_liability =
        chain_block::Coins::construct_from(&mut s).expect("refundable").as_u128();
    let call_day = s.get_next_u32().expect("call_day");
    let calls_today = s.get_next_u32().expect("calls_today");
    assert!(
        s.remaining_bits() == 0 && s.remaining_references() == 0,
        "the accounting cell holds exactly the six fields"
    );
    Accounting {
        withdrawable_revenue,
        locked_storage_fees,
        pending_liability,
        refundable_liability,
        call_day,
        calls_today,
    }
}

fn write_accounting(a: &Accounting) -> Cell {
    let mut b = BuilderData::new();
    coins(a.withdrawable_revenue).write_to(&mut b).unwrap();
    coins(a.locked_storage_fees).write_to(&mut b).unwrap();
    coins(a.pending_liability).write_to(&mut b).unwrap();
    coins(a.refundable_liability).write_to(&mut b).unwrap();
    b.append_u32(a.call_day).unwrap();
    b.append_u32(a.calls_today).unwrap();
    b.into_cell().unwrap()
}

/// `data` with its accounting cell replaced by `patch(current)`; every other
/// field and reference is carried over unchanged.
fn data_with_accounting(data: Cell, patch: impl FnOnce(Accounting) -> Accounting) -> Cell {
    let mut slice = SliceData::load_cell(data).expect("data slice");
    let owner = MsgAddressInt::construct_from(&mut slice).expect("owner");
    let active = slice.get_next_bit().expect("active");
    let next_request_id = slice.get_next_u64().expect("next_request_id");
    let pending_count = slice.get_next_u32().expect("pending_count");
    let live_count = slice.get_next_u32().expect("live_count");
    let policy = slice.checked_drain_reference().expect("policy");
    let accounting = slice.checked_drain_reference().expect("accounting");
    let dicts = slice.checked_drain_reference().expect("dicts");

    let mut b = BuilderData::new();
    owner.write_to(&mut b).unwrap();
    if active {
        b.append_bit_one().unwrap();
    } else {
        b.append_bit_zero().unwrap();
    }
    b.append_u64(next_request_id).unwrap();
    b.append_u32(pending_count).unwrap();
    b.append_u32(live_count).unwrap();
    b.checked_append_reference(policy).unwrap();
    b.checked_append_reference(write_accounting(&patch(read_accounting(&accounting)))).unwrap();
    b.checked_append_reference(dicts).unwrap();
    b.into_cell().unwrap()
}

impl Fixture {
    /// Rewrites the deployed contract's accounting cell in place, the way a
    /// state no sequence of messages could reach is put under test.
    fn patch_accounting(&mut self, patch: impl FnOnce(Accounting) -> Accounting) {
        let mut account = self.bc.get_account(&self.service).expect("service account").clone();
        let data = account.get_data().expect("service data");
        assert!(account.set_data(data_with_accounting(data, patch)), "data replaced");
        self.bc.set_account(self.service.clone(), account);
    }

    /// One of the getter's coin counters, read as the full integer the
    /// contract holds (the typed decoder stops at u64).
    fn coin_counter(&self, index: usize) -> u128 {
        let value = self
            .bc
            .run_get_method(&self.service, "get_service_data", vec![])
            .expect("get_service_data")
            .expect_success()
            .int_at(index);
        u128::try_from(value).expect("a coin counter is never negative")
    }

    /// A call committing to the deploy-time terms, priced from the init rather
    /// than from the typed getter, whose u64 fields cannot carry the counters
    /// these tests put near the coin bound.
    fn call_from_init(
        &mut self,
        from: &MsgAddressInt,
        query_id: u64,
        request_hash: [u8; 32],
    ) -> SendResult {
        let value = self
            .init
            .price_per_call
            .checked_add(self.init.storage_fee)
            .and_then(|owed| owed.checked_add(CALL_GAS_MARGIN))
            .expect("call value fits u64");
        let terms = ServiceActorContract::terms_hash_of_init(&self.init).unwrap();
        self.send_from_with_value(
            from,
            ServiceActorContract::call(query_id, request_hash, terms).unwrap(),
            value,
        )
    }

    fn data_hash(&self) -> chain_block::UInt256 {
        self.bc
            .get_account(&self.service)
            .and_then(|account| account.get_data())
            .expect("service data")
            .repr_hash()
    }
}

const REVENUE_INDEX: usize = 19;
const PENDING_INDEX: usize = 21;

fn coins_below_max(by: u128) -> u128 {
    MAX_COINS.checked_sub(by).expect("below the coin bound")
}

fn tos(amount: u128) -> u128 {
    amount.checked_mul(u128::from(TOS)).expect("a test amount fits u128")
}

#[test]
fn a_call_that_would_push_a_liability_past_the_coin_bound_is_refused_before_any_state_change() {
    let price = u128::from(Fixture::new().init.price_per_call);

    // Positive control near the Coins bound, with the remaining locked fee,
    // operating reserve and execution fees backed by an equally large balance.
    // A liability at MAX_COINS itself cannot coexist with those obligations.
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let target = coins_below_max(u128::from(f.init.storage_fee) + 2 * u128::from(TOS));
    f.patch_accounting(|a| Accounting { pending_liability: target - price, ..a });
    let mut account = f.bc.get_account(&f.service).unwrap().clone();
    account.set_balance(chain_block::CurrencyCollection::from_coins(coins(coins_below_max(
        price + u128::from(f.init.storage_fee) + u128::from(CALL_GAS_MARGIN),
    ))));
    f.bc.set_account(f.service.clone(), account);
    f.call_from_init(&caller, 1, [0xAA; 32]).expect_success();
    assert_eq!(f.coin_counter(PENDING_INDEX), target);
    assert_eq!(f.pending_count(), 1);

    // One more unit and the sum does not fit: refused with the range code
    // before the request, the counters or the dictionaries change.
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let one_past = coins_below_max(price).checked_add(1).expect("one unit past the bound");
    f.patch_accounting(|a| Accounting { pending_liability: one_past, ..a });
    let before = f.data_hash();
    f.call_from_init(&caller, 1, [0xAA; 32]).expect_aborted().expect_exit_code(ERR_AMOUNT_RANGE);
    assert_eq!(f.data_hash(), before, "a refused call must not touch the state");
    assert_eq!(f.pending_count(), 0);
    assert!(f.request(0).is_none());
}

#[test]
fn a_liability_that_would_go_negative_is_refused_with_the_range_code() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    // A pending request whose price the liability counter no longer carries:
    // responding would subtract more than there is.
    f.patch_accounting(|a| Accounting { pending_liability: 0, ..a });
    let before = f.data_hash();
    f.respond(2, 0, [0xBB; 32]).expect_aborted().expect_exit_code(ERR_AMOUNT_RANGE);
    assert_eq!(f.data_hash(), before);
    assert!(f.request(0).is_some(), "the request stays pending");
}

/// The sweep's revenue credit is taken in the order whose checked steps never
/// exceed the final result: `price + (fee - bounty)`, added to the revenue. A
/// checked sum that first added price and fee to the revenue would refuse this
/// state although the result fits. The pre-fix raw arithmetic also produced the
/// result, so this guards the order of the checked operations, not a change in
/// what the contract accepts.
#[test]
fn a_sweep_credits_the_net_fee_so_no_checked_step_exceeds_the_result() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let outsider = f.outsider.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    let price = u128::from(f.init.price_per_call);
    let fee = u128::from(f.init.storage_fee);
    let bounty = u128::from(f.init.cleanup_bounty);
    let credit = price
        .checked_add(fee)
        .and_then(|gross| gross.checked_sub(bounty))
        .expect("the storage fee covers the bounty");
    // revenue + price + fee would pass the bound; revenue + (price + fee - bounty) is the maximum.
    f.patch_accounting(|a| Accounting { withdrawable_revenue: coins_below_max(credit), ..a });
    let request = f.request(0).expect("pending request");
    f.bc.set_now(request.refund_claim_deadline as u32);
    f.sweep(&outsider, 2, 0).expect_success();
    assert_eq!(f.coin_counter(REVENUE_INDEX), MAX_COINS);
    assert!(f.request(0).is_none());
}

#[test]
fn an_unaffordable_sweep_is_refused_as_insufficient_balance_not_as_a_range_error() {
    let mut f = Fixture::new();
    let caller = f.caller.address().clone();
    let outsider = f.outsider.address().clone();
    f.call(&caller, 1, [0xAA; 32]).expect_success();
    // Other live entries are owed far more than the contract holds.
    f.patch_accounting(|a| Accounting {
        pending_liability: a.pending_liability.checked_add(tos(1_000)).expect("liability fits"),
        ..a
    });
    let request = f.request(0).expect("pending request");
    f.bc.set_now(request.refund_claim_deadline as u32);
    let before = f.data_hash();
    f.sweep(&outsider, 2, 0).expect_aborted().expect_exit_code(ERR_INSUFFICIENT_BALANCE);
    assert_eq!(f.data_hash(), before);
    assert!(f.request(0).is_some(), "the entry stays live");
}

#[test]
fn a_zero_withdrawal_is_refused_when_the_balance_does_not_cover_the_obligations() {
    let mut f = Fixture::new();
    let owner = f.owner.address().clone();
    f.patch_accounting(|a| Accounting { pending_liability: tos(1_000), ..a });
    let before = f.data_hash();
    for amount in [0, 1] {
        f.send_from(&owner, ServiceActorContract::withdraw_revenue(1, amount).unwrap())
            .expect_aborted()
            .expect_exit_code(ERR_INSUFFICIENT_REVENUE);
    }
    assert_eq!(f.data_hash(), before);
}

#[test]
fn a_bounty_the_balance_cannot_pay_is_refused_as_insufficient_balance() {
    let mut f = Fixture::new();
    let owner = f.owner.address().clone();
    let caller = f.caller.address().clone();
    let outsider = f.outsider.address().clone();
    // The largest bounty the policy admits, so a balance just short of it still
    // buys the gas to reach the check.
    let storage_fee = MIN_STORAGE_FEE.checked_add(MAX_CLEANUP_BOUNTY).expect("fee fits");
    let (price, sla, window, open_access, rate_limit, metadata_hash, proof_scheme_hash) = (
        f.init.price_per_call,
        f.init.response_sla,
        f.init.refund_claim_window,
        f.init.open_access,
        f.init.rate_limit_per_day,
        f.init.metadata_hash,
        f.init.proof_scheme_hash,
    );
    f.send_from(
        &owner,
        ServiceActorContract::update_policy(
            1,
            price,
            storage_fee,
            MAX_CLEANUP_BOUNTY,
            sla,
            window,
            true,
            open_access,
            None,
            &owner,
            rate_limit,
            metadata_hash,
            proof_scheme_hash,
        )
        .unwrap(),
    )
    .expect_success();
    f.call(&caller, 2, [0xAA; 32]).expect_success();
    let request = f.request(0).expect("pending request");
    assert_eq!(request.cleanup_bounty, MAX_CLEANUP_BOUNTY);
    f.bc.set_now(request.refund_claim_deadline as u32);

    // The contract's own balance plus the sweeper's value stays below the bounty.
    let mut account = f.bc.get_account(&f.service).expect("service account").clone();
    account.set_balance(chain_block::CurrencyCollection::from(BALANCE_BELOW_MAX_BOUNTY));
    f.bc.set_account(f.service.clone(), account);
    let before = f.data_hash();
    f.send_from_with_value(
        &outsider,
        ServiceActorContract::sweep_expired_request(3, 0).unwrap(),
        SWEEP_VALUE_BELOW_SHORTFALL,
    )
    .expect_aborted()
    .expect_exit_code(ERR_INSUFFICIENT_BALANCE);
    assert_eq!(f.data_hash(), before);
    assert!(f.request(0).is_some(), "the entry stays live");
}

// Solvency tests execute compiled source; the equality test binds that source
// to the deployed SDK artifact. A mutation runner supplies an alternate source
// only to this fixture, so removal controls exercise the real action phase.
fn solvency_code() -> Cell {
    static CODE: std::sync::OnceLock<Cell> = std::sync::OnceLock::new();
    CODE.get_or_init(|| {
        let source = std::env::var("SERVICE_ACTOR_SOLVENCY_SOURCE").unwrap_or_else(|_| {
            tos_sandbox::find_tos_root()
                .expect("checkout root")
                .join("crypto/smartcont/service-actor-code.fc")
                .to_string_lossy()
                .into_owned()
        });
        tos_sandbox::compile_func_with_stdlib(&[source]).expect("compile Service Actor")
    })
    .clone()
}

impl Fixture {
    fn solvency() -> Self {
        let mut f = Self::new();
        let mut account = f.bc.get_account(&f.service).unwrap().clone();
        assert!(account.set_code(solvency_code()));
        f.bc.set_account(f.service.clone(), account);
        f
    }

    fn set_balance(&mut self, balance: u64) {
        let mut account = self.bc.get_account(&self.service).unwrap().clone();
        account.set_balance(chain_block::CurrencyCollection::from(balance));
        self.bc.set_account(self.service.clone(), account);
    }

    fn state_hash(&self) -> chain_block::UInt256 {
        self.bc.get_account(&self.service).unwrap().get_data().unwrap().repr_hash()
    }

    fn floor(&self) -> u64 {
        let d = self.data();
        d.pending_liability
            .checked_add(d.refundable_liability)
            .unwrap()
            .checked_add(d.locked_storage_fees)
            .unwrap()
            .checked_add(MINIMUM_OPERATING_RESERVE)
            .unwrap()
    }

    fn no_bounce(&mut self, sender: &MsgAddressInt, value: u64, body: Cell) -> SendResult {
        self.send_with_optional_trace(
            MessageBuilder::internal(sender, &self.service, value).bounce(false).body(body).build(),
        )
    }
}

fn expect_solvency_action_failure(result: &SendResult) {
    result.expect_aborted().expect_exit_code(0).expect_out_msgs(0);
    let action = result.read_primary_description().action.unwrap();
    assert!(!action.success);
    assert_eq!(action.result_code, 37, "must fail for insufficient action-phase funds");
}

#[test]
fn solvency_source_matches_embedded_code() {
    assert_eq!(solvency_code().repr_hash(), ServiceActorContract::code().unwrap().repr_hash());
}

#[test]
fn solvency_admission_requires_preexisting_reserve() {
    let mut f = Fixture::solvency();
    let caller = f.caller.address().clone();
    f.set_balance(MINIMUM_OPERATING_RESERVE.checked_sub(1).unwrap());
    let before = f.state_hash();
    // Overpayment cannot stand in for the operator's independently funded reserve.
    f.call(&caller, 1, [1; 32]).expect_aborted().expect_exit_code(ERR_OPERATING_RESERVE_UNFUNDED);
    assert_eq!(f.state_hash(), before);
    f.set_balance(2 * TOS);
    f.call(&caller, 2, [1; 32]).expect_success();
    assert!(f.balance(&f.service) >= f.floor());
}

#[test]
fn solvency_admission_requires_existing_obligations() {
    let mut f = Fixture::solvency();
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [1; 32]).expect_success();
    f.call(&caller, 2, [2; 32]).expect_success();
    f.bc.set_now(f.request(0).unwrap().response_deadline as u32);
    f.expire(&caller, 10, 0).expect_success();
    assert!(f.data().pending_liability > 0 && f.data().refundable_liability > 0);
    let floor = f.floor();
    f.set_balance(floor.checked_sub(1).unwrap());
    assert!(f.balance(&f.service) >= MINIMUM_OPERATING_RESERVE);
    let before = f.state_hash();
    f.call(&caller, 3, [3; 32]).expect_aborted().expect_exit_code(ERR_OPERATING_RESERVE_UNFUNDED);
    assert_eq!(f.state_hash(), before);
    f.set_balance(floor.checked_add(TOS).unwrap());
    f.call(&caller, 4, [3; 32]).expect_success();
    assert!(f.balance(&f.service) >= f.floor());
}

#[test]
fn solvency_admission_requires_execution_budget() {
    let mut f = Fixture::solvency();
    let caller = f.caller.address().clone();
    let principal = f.init.price_per_call.checked_add(f.init.storage_fee).unwrap();
    let before = f.state_hash();
    for budget in [0, ADMISSION_GAS_ALLOWANCE.checked_sub(1).unwrap()] {
        let body = ServiceActorContract::call(1, [1; 32], f.terms()).unwrap();
        f.send_from_with_value(&caller, body, principal.checked_add(budget).unwrap())
            .expect_aborted()
            .expect_exit_code(ERR_INSUFFICIENT_EXECUTION_PAYMENT);
        assert_eq!(f.state_hash(), before, "underfunded call changed persistent state");
    }
    f.set_balance(MINIMUM_OPERATING_RESERVE);
    let body = ServiceActorContract::call(1, [1; 32], f.terms()).unwrap();
    let result =
        f.no_bounce(&caller, principal.checked_add(ADMISSION_GAS_ALLOWANCE).unwrap(), body);
    result.expect_success().expect_out_msgs(1);
    assert_eq!(f.balance(&f.service), MINIMUM_OPERATING_RESERVE.checked_add(principal).unwrap());
    assert_eq!(
        service_outputs(&result),
        vec![(caller, ADMISSION_GAS_ALLOWANCE.checked_sub(execution_fees(&result)).unwrap())]
    );
}

#[test]
fn solvency_admission_preserves_operator_excess() {
    for bounce in [true, false] {
        let mut f = Fixture::solvency();
        let caller = f.caller.address().clone();
        let principal = f.init.price_per_call.checked_add(f.init.storage_fee).unwrap();
        // A finite deployment margin must survive arbitrarily many funded calls.
        f.set_balance(MINIMUM_OPERATING_RESERVE.checked_add(TOS / 5).unwrap());
        let excess = f.balance(&f.service).checked_sub(f.floor()).unwrap();
        for id in 0..24 {
            let before = f.balance(&f.service);
            let budget =
                ADMISSION_GAS_ALLOWANCE.checked_add(if id % 2 == 0 { 0 } else { TOS }).unwrap();
            let body = ServiceActorContract::call(id, [1; 32], f.terms()).unwrap();
            let result =
                f.bc.send_message(
                    MessageBuilder::internal(
                        &caller,
                        &f.service,
                        principal.checked_add(budget).unwrap(),
                    )
                    .bounce(bounce)
                    .body(body)
                    .build(),
                )
                .unwrap();
            result.expect_success().expect_out_msgs(1);
            assert_eq!(storage_fees(&result), 0, "fixed-time admissions accrue no rent");
            assert_eq!(
                f.balance(&f.service),
                before.checked_add(principal).unwrap(),
                "successful admission spent preexisting backing"
            );
            assert_eq!(
                f.balance(&f.service).checked_sub(f.floor()).unwrap(),
                excess,
                "successful admission eroded operator excess"
            );
            assert_eq!(
                service_outputs(&result),
                vec![(caller.clone(), budget.checked_sub(execution_fees(&result)).unwrap())]
            );
        }
    }
}

#[test]
fn solvency_exact_withdrawal_cap_cannot_spend_fee_backing() {
    let mut f = Fixture::solvency();
    let caller = f.caller.address().clone();
    let owner = f.owner.address().clone();
    f.call(&caller, 1, [1; 32]).expect_success();
    f.call(&caller, 2, [2; 32]).expect_success();
    f.respond(3, 0, [3; 32]).expect_success();
    let amount = f.data().withdrawable_revenue;
    f.set_balance(f.floor().checked_add(amount).unwrap().checked_sub(1).unwrap());
    let before = f.state_hash();
    let body = ServiceActorContract::withdraw_revenue(4, amount).unwrap();
    // The transaction's fee budget cannot masquerade as withdrawable revenue.
    f.send_from_with_value(&owner, body.clone(), TOS)
        .expect_aborted()
        .expect_exit_code(ERR_INSUFFICIENT_REVENUE);
    assert_eq!(f.state_hash(), before, "failed withdrawal changed revenue");
    f.set_balance(f.floor().checked_add(amount).unwrap());
    let result = f.no_bounce(&owner, PAYOUT_GAS_ALLOWANCE, body);
    expect_payment_and_change(&result, &owner, &owner, amount, PAYOUT_GAS_ALLOWANCE);
    assert_eq!(f.balance(&f.service), f.floor(), "withdrawal spent protected backing");
    assert_eq!(f.data().withdrawable_revenue, 0);
}

#[test]
fn solvency_zero_withdrawal_at_floor_returns_execution_change() {
    let mut f = Fixture::solvency();
    let owner = f.owner.address().clone();
    f.set_balance(f.floor());
    let before = f.state_hash();
    let result = f.no_bounce(
        &owner,
        PAYOUT_GAS_ALLOWANCE,
        ServiceActorContract::withdraw_revenue(1, 0).unwrap(),
    );
    expect_payment_and_change(&result, &owner, &owner, 0, PAYOUT_GAS_ALLOWANCE);
    assert_eq!(f.state_hash(), before);
    assert_eq!(f.balance(&f.service), f.floor());
}

#[test]
fn solvency_claim_preserves_other_entries_and_reserves_after_fees() {
    let mut f = Fixture::solvency();
    let caller = f.caller.address().clone();
    for id in 0..3 {
        f.call(&caller, id, [1; 32]).expect_success();
    }
    f.bc.set_now(f.request(0).unwrap().response_deadline as u32);
    for id in 0..2 {
        f.send_from(&caller, ServiceActorContract::expire(10 + id, id).unwrap()).expect_success();
    }
    let price = f.init.price_per_call;
    let destination = f.outsider.address().clone();
    let floor_after = f
        .floor()
        .checked_sub(MINIMUM_OPERATING_RESERVE)
        .unwrap()
        .checked_sub(price)
        .unwrap()
        .checked_sub(f.init.storage_fee)
        .unwrap();
    let body = ServiceActorContract::claim_refund(20, 0, &destination).unwrap();
    let before = f.state_hash();
    // Covers this price, but not every other customer's backing. A large
    // execution payment cannot hide even a one-unit customer shortfall.
    f.set_balance(floor_after.checked_add(price).unwrap().checked_sub(1).unwrap());
    f.send_from_with_value(&caller, body.clone(), TOS)
        .expect_aborted()
        .expect_exit_code(ERR_INSUFFICIENT_BALANCE);
    assert_eq!(f.state_hash(), before);
    // Customer obligations are fully backed, with no operator buffer at all.
    f.set_balance(floor_after.checked_add(price).unwrap());
    let result = f.no_bounce(&caller, PAYOUT_GAS_ALLOWANCE, body);
    expect_payment_and_change(&result, &destination, &caller, price, PAYOUT_GAS_ALLOWANCE);
    assert_eq!(f.balance(&f.service), floor_after, "refund spent another customer's backing");
    assert!(f.refund(0).is_none());
    assert!(f.refund(1).is_some());
    assert!(f.request(2).is_some());
    assert_eq!(f.caller_live_count(&caller), 2);
    f.call(&caller, 21, [3; 32]).expect_aborted().expect_exit_code(ERR_OPERATING_RESERVE_UNFUNDED);
    let owner = f.owner.address().clone();
    f.send_from(&owner, ServiceActorContract::withdraw_revenue(22, 0).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_INSUFFICIENT_REVENUE);
}

#[test]
fn solvency_payouts_require_execution_budget() {
    for operation in ["refund", "sweep", "withdrawal"] {
        let mut f = Fixture::solvency();
        let caller = f.caller.address().clone();
        let owner = f.owner.address().clone();
        f.call(&caller, 1, [1; 32]).expect_success();
        let request = f.request(0).unwrap();
        let (payer, body, principal) = match operation {
            "refund" => {
                f.bc.set_now(request.response_deadline as u32);
                f.expire(&caller, 2, 0).expect_success();
                (
                    caller.clone(),
                    ServiceActorContract::claim_refund(3, 0, &caller).unwrap(),
                    request.price,
                )
            }
            "sweep" => {
                f.bc.set_now(request.refund_claim_deadline as u32);
                (
                    caller.clone(),
                    ServiceActorContract::sweep_expired_request(3, 0).unwrap(),
                    request.cleanup_bounty,
                )
            }
            _ => {
                f.respond(2, 0, [2; 32]).expect_success();
                (
                    owner,
                    ServiceActorContract::withdraw_revenue(3, request.price).unwrap(),
                    request.price,
                )
            }
        };
        let before = f.state_hash();
        f.send_from_with_value(&payer, body.clone(), PAYOUT_GAS_ALLOWANCE.checked_sub(1).unwrap())
            .expect_aborted()
            .expect_exit_code(ERR_INSUFFICIENT_EXECUTION_PAYMENT);
        assert_eq!(f.state_hash(), before, "underfunded payout consumed an entry");
        let backing = f.balance(&f.service);
        let result = f.no_bounce(&payer, PAYOUT_GAS_ALLOWANCE, body);
        expect_payment_and_change(&result, &payer, &payer, principal, PAYOUT_GAS_ALLOWANCE);
        assert_eq!(
            f.balance(&f.service),
            backing.checked_sub(principal).unwrap().checked_sub(storage_fees(&result)).unwrap(),
            "payout spent more than its entitlement"
        );
    }
}

#[test]
fn solvency_refund_never_haircuts_principal_when_fees_rise() {
    let mut f = Fixture::solvency();
    let caller = f.caller.address().clone();
    f.call(&caller, 1, [1; 32]).expect_success();
    f.bc.set_now(f.request(0).unwrap().response_deadline as u32);
    f.expire(&caller, 2, 0).expect_success();
    let body = ServiceActorContract::claim_refund(3, 0, &caller).unwrap();
    let snapshot = f.bc.snapshot();
    let trial = f.no_bounce(&caller, PAYOUT_GAS_ALLOWANCE, body.clone());
    trial.expect_success();
    let chain_block::TrComputePhase::Vm(vm) = trial.read_primary_description().compute_ph else {
        panic!("expected VM computation");
    };
    f.bc.restore(snapshot.clone());
    let original_config = f.bc.config_params().clone();
    let mut config = original_config.clone();
    let mut prices = config.fwd_prices(true).unwrap();
    // One carry-all send could pay this fee by taking half the refund's
    // principal. An exact principal send must abort instead, even when the
    // allowance passed its early check and the operator has ample excess.
    prices.lump_price = PAYOUT_GAS_ALLOWANCE
        .checked_sub(vm.gas_fees.as_u64().unwrap())
        .unwrap()
        .checked_add(f.init.price_per_call / 2)
        .unwrap();
    config.set_config(chain_block::ConfigParamEnum::ConfigParam24(prices)).unwrap();
    if config.config(31).unwrap().is_none() {
        config
            .set_config(chain_block::ConfigParamEnum::ConfigParam31(chain_block::ConfigParam31 {
                fundamental_smc_addr: chain_block::FundamentalSmcAddresses::default(),
            }))
            .unwrap();
    }
    f.bc.set_config(config).unwrap();
    let before = f.state_hash();
    let result = f.no_bounce(&caller, PAYOUT_GAS_ALLOWANCE, body.clone());
    expect_solvency_action_failure(&result);
    assert_eq!(
        result.read_primary_description().action.unwrap().result_arg,
        Some(1),
        "principal send was the failing action"
    );
    assert_eq!(f.state_hash(), before, "failed action consumed the refund");
    assert!(f.refund(0).is_some());

    // Now make one forwarding fee affordable, but two unaffordable. The first
    // send must also disappear when the later change send fails.
    f.bc.restore(snapshot);
    let mut config = original_config.clone();
    let mut prices = config.fwd_prices(true).unwrap();
    prices.lump_price = PAYOUT_GAS_ALLOWANCE
        .checked_sub(vm.gas_fees.as_u64().unwrap())
        .unwrap()
        .checked_mul(3)
        .unwrap()
        .checked_div(4)
        .unwrap();
    config.set_config(chain_block::ConfigParamEnum::ConfigParam24(prices)).unwrap();
    if config.config(31).unwrap().is_none() {
        config
            .set_config(chain_block::ConfigParamEnum::ConfigParam31(chain_block::ConfigParam31 {
                fundamental_smc_addr: chain_block::FundamentalSmcAddresses::default(),
            }))
            .unwrap();
    }
    f.bc.set_config(config).unwrap();
    let result = f.no_bounce(&caller, PAYOUT_GAS_ALLOWANCE, body.clone());
    expect_solvency_action_failure(&result);
    assert_eq!(
        result.read_primary_description().action.unwrap().result_arg,
        Some(2),
        "change send was the failing action"
    );
    assert_eq!(f.state_hash(), before, "second action failure consumed the refund");
    assert!(f.refund(0).is_some());
    // Restoring fees and retrying the same claim must pay its full principal.
    let mut config = original_config;
    if config.config(31).unwrap().is_none() {
        config
            .set_config(chain_block::ConfigParamEnum::ConfigParam31(chain_block::ConfigParam31 {
                fundamental_smc_addr: chain_block::FundamentalSmcAddresses::default(),
            }))
            .unwrap();
    }
    f.bc.set_config(config).unwrap();
    let result = f.no_bounce(&caller, PAYOUT_GAS_ALLOWANCE, body);
    expect_payment_and_change(
        &result,
        &caller,
        &caller,
        f.init.price_per_call,
        PAYOUT_GAS_ALLOWANCE,
    );
}

#[test]
fn solvency_sweep_after_real_rent_preserves_other_entries() {
    for refund in [false, true] {
        let mut f = Fixture::solvency();
        let caller = f.caller.address().clone();
        let sweeper = f.outsider.address().clone();
        for id in 0..3 {
            f.call(&caller, id, [1; 32]).expect_success();
        }
        let request = f.request(0).unwrap();
        f.bc.set_now(request.response_deadline as u32);
        f.send_from(&caller, ServiceActorContract::expire(4, 1).unwrap()).expect_success();
        let target = if refund { 1 } else { 0 };
        let floor_after = f.floor() - f.init.price_per_call - f.init.storage_fee;
        let cap = floor_after + f.init.cleanup_bounty;
        let before = f.state_hash();
        // Real storage-phase charges, with all three entries still in storage.
        let mut day = 0;
        while f.balance(&f.service) >= cap - TOS / 5 {
            day += 1;
            assert!(day < 1000, "rent failed to erode the balance");
            f.bc.set_now(request.refund_claim_deadline as u32 + day * 86400);
            f.no_bounce(&sweeper, 1_000_000, Cell::default()).expect_success();
        }
        assert_eq!(f.state_hash(), before);
        let body = ServiceActorContract::sweep_expired_request(5, target).unwrap();
        // The sweeper's execution budget does not repair insolvency as a side
        // effect. A top-up is a separate, explicit operation.
        f.send_from_with_value(&sweeper, body.clone(), TOS)
            .expect_aborted()
            .expect_exit_code(ERR_INSUFFICIENT_BALANCE);
        assert_eq!(f.state_hash(), before, "failed sweep removed an entry or caller slot");
        f.no_bounce(&sweeper, TOS, Cell::default()).expect_success();
        assert_eq!(f.state_hash(), before, "top-up changed service data");
        let backing = f.balance(&f.service);
        let result = f.no_bounce(&sweeper, PAYOUT_GAS_ALLOWANCE, body);
        expect_payment_and_change(
            &result,
            &sweeper,
            &sweeper,
            f.init.cleanup_bounty,
            PAYOUT_GAS_ALLOWANCE,
        );
        assert_eq!(
            f.balance(&f.service),
            backing
                .checked_sub(f.init.cleanup_bounty)
                .unwrap()
                .checked_sub(storage_fees(&result))
                .unwrap(),
            "sweep spent protected backing"
        );
        assert_eq!(f.data().live_count, 2);
        assert!(f.request(2).is_some());
        assert!(f.balance(&f.service) >= f.floor());
    }
}
// This measures deliberately large, coherent stress states. It is not a proof
// that the production account-cell limits admit 100,000 independent requests.

const GAS_STRESS_LIVE: u32 = 99_999;
const GAS_STRESS_PRICE: u128 = 1_u128 << 100;
const GAS_STRESS_STORAGE: u128 = 1_u128 << 99;
const GAS_STRESS_SPARE: u128 = 1_u128 << 110;
const GAS_STRESS_NEXT_ID: u64 = u64::MAX - 1;
const GAS_STRESS_PENDING_ID: u64 = u64::MAX - 2;
const GAS_STRESS_REFUND_ID: u64 = u64::MAX - 4;
const GAS_STRESS_PERIOD: u32 = 2_592_000;

struct GasStressSeed {
    data: Cell,
    balance: u128,
    created_at: u32,
    deadline: u32,
    current_terms: [u8; 32],
}

fn gas_stress_terms(
    init: &ServiceActorInit,
    version: u32,
    price: u128,
    storage: u128,
    sla: u32,
    window: u32,
) -> [u8; 32] {
    let mut tail = BuilderData::new();
    tail.append_u256(&init.metadata_hash).unwrap();
    tail.append_u256(&init.proof_scheme_hash).unwrap();
    tail.append_bit_zero().unwrap();
    tail.append_u256(&[0; 32]).unwrap();
    let mut root = BuilderData::new();
    root.append_u32(version).unwrap();
    coins(price).write_to(&mut root).unwrap();
    coins(storage).write_to(&mut root).unwrap();
    coins(u128::from(init.cleanup_bounty)).write_to(&mut root).unwrap();
    root.append_u32(sla).unwrap();
    root.append_u32(window).unwrap();
    root.checked_append_reference(tail.into_cell().unwrap()).unwrap();
    *root.into_cell().unwrap().repr_hash().as_array()
}

fn gas_stress_key(id: u64) -> SliceData {
    let mut key = BuilderData::new();
    key.append_u64(id).unwrap();
    SliceData::load_builder(key).unwrap()
}

fn gas_stress_seed(f: &Fixture) -> &'static GasStressSeed {
    use chain_block::{HashmapE, HashmapType};
    static SEED: std::sync::OnceLock<GasStressSeed> = std::sync::OnceLock::new();
    SEED.get_or_init(|| {
        let created_at = f.bc.now();
        // These requests were admitted one maximum SLA before the snapshot.
        // Refund entries have just expired; pending entries may still await
        // permissionless expiry. They reach 60 days of age at `deadline`.
        let response_deadline = created_at;
        let deadline = response_deadline.checked_add(GAS_STRESS_PERIOD).unwrap();
        let old_terms = gas_stress_terms(
            &f.init,
            0,
            GAS_STRESS_PRICE,
            GAS_STRESS_STORAGE,
            GAS_STRESS_PERIOD,
            GAS_STRESS_PERIOD,
        );
        let current_terms = gas_stress_terms(
            &f.init,
            1,
            u128::from(f.init.price_per_call),
            u128::from(f.init.storage_fee),
            f.init.response_sla,
            f.init.refund_claim_window,
        );
        let mut commitments = BuilderData::new();
        commitments.append_u256(&[0x79; 32]).unwrap();
        commitments.append_u256(&old_terms).unwrap();
        commitments.append_bit_zero().unwrap();
        commitments.append_u256(&[0; 32]).unwrap();
        let commitments = commitments.into_cell().unwrap();

        // Each populated trie has a long path near the uint64 limit, modeling
        // sparse survivors after older request IDs have been removed. All IDs
        // are below next_request_id and each is present in exactly one map.
        let mut sparse = Vec::new();
        for (target, is_refund) in [(GAS_STRESS_PENDING_ID, false), (GAS_STRESS_REFUND_ID, true)] {
            sparse.push((target, is_refund));
            for bit in 0..64 {
                let mask = 1_u64.checked_shl(bit).unwrap();
                if target & mask != 0 {
                    sparse.push((target ^ mask, is_refund));
                }
            }
        }
        let mut sparse_keys = std::collections::BTreeSet::new();
        sparse.retain(|(id, _)| sparse_keys.insert(*id));
        let dense_count =
            usize::try_from(GAS_STRESS_LIVE).unwrap().checked_sub(sparse.len()).unwrap();
        let mut entries: Vec<(u64, bool)> =
            (0..dense_count).map(|id| (u64::try_from(id).unwrap(), id % 2 == 0)).collect();
        entries.extend(sparse);
        let mut unique = std::collections::BTreeSet::new();
        let mut pending = HashmapE::with_bit_len(64);
        let mut refunds = HashmapE::with_bit_len(64);
        let mut callers = HashmapE::with_bit_len(256);
        let mut pending_count = 0_u32;
        let mut refund_count = 0_u32;
        for (index, (id, is_refund)) in entries.into_iter().enumerate() {
            assert!(id < GAS_STRESS_NEXT_ID && unique.insert(id), "unique historical ID");
            let caller = if index >= 99_000 {
                f.caller.address().clone()
            } else {
                let mut address = [0xC7; 32];
                address[24..].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
                MsgAddressInt::standard(-1, address)
            };
            // Every caller has one live entry except the existing caller whose
            // 999 entries exercise the final available per-caller slot.
            if index < 99_000 || index == 99_000 {
                let key = address_slice(&caller).into_cell().unwrap().repr_hash();
                let mut key_bits = BuilderData::new();
                key_bits.append_u256(key.as_array()).unwrap();
                let mut count = BuilderData::new();
                count.append_u32(if index < 99_000 { 1 } else { 999 }).unwrap();
                assert!(
                    callers
                        .set_builder(SliceData::load_builder(key_bits).unwrap(), &count)
                        .unwrap()
                        .is_none()
                );
            }
            let mut entry = BuilderData::new();
            caller.write_to(&mut entry).unwrap();
            coins(GAS_STRESS_PRICE).write_to(&mut entry).unwrap();
            coins(GAS_STRESS_STORAGE).write_to(&mut entry).unwrap();
            coins(u128::from(f.init.cleanup_bounty)).write_to(&mut entry).unwrap();
            if is_refund {
                entry.append_u64(u64::from(deadline)).unwrap();
                assert!(
                    refunds
                        .setref(gas_stress_key(id), entry.into_cell().unwrap())
                        .unwrap()
                        .is_none()
                );
                refund_count = refund_count.checked_add(1).unwrap();
            } else {
                entry.append_u64(u64::from(response_deadline)).unwrap();
                entry.append_u64(u64::from(deadline)).unwrap();
                entry.append_u32(0).unwrap();
                entry.checked_append_reference(commitments.clone()).unwrap();
                assert!(
                    pending
                        .setref(gas_stress_key(id), entry.into_cell().unwrap())
                        .unwrap()
                        .is_none()
                );
                pending_count = pending_count.checked_add(1).unwrap();
            }
        }
        assert_eq!(pending_count.checked_add(refund_count).unwrap(), GAS_STRESS_LIVE);
        assert_eq!(pending.len().unwrap(), usize::try_from(pending_count).unwrap());
        assert_eq!(refunds.len().unwrap(), usize::try_from(refund_count).unwrap());
        assert_eq!(callers.len().unwrap(), 99_001);
        let mut dicts = BuilderData::new();
        pending.write_hashmap_data(&mut dicts).unwrap();
        refunds.write_hashmap_data(&mut dicts).unwrap();
        callers.write_hashmap_data(&mut dicts).unwrap();
        let accounting = Accounting {
            withdrawable_revenue: u128::from(TOS),
            locked_storage_fees: GAS_STRESS_STORAGE
                .checked_mul(u128::from(GAS_STRESS_LIVE))
                .unwrap(),
            pending_liability: GAS_STRESS_PRICE.checked_mul(u128::from(pending_count)).unwrap(),
            refundable_liability: GAS_STRESS_PRICE.checked_mul(u128::from(refund_count)).unwrap(),
            call_day: created_at / 86_400,
            calls_today: GAS_STRESS_LIVE,
        };
        let balance = accounting
            .pending_liability
            .checked_add(accounting.refundable_liability)
            .and_then(|v| v.checked_add(accounting.locked_storage_fees))
            .and_then(|v| v.checked_add(GAS_STRESS_SPARE))
            .unwrap();
        assert!(balance < MAX_COINS);

        // Version 0 was the wide-valued historical policy; version 1 is the
        // current ordinary policy. Preserve every other policy field/ref.
        let original = ServiceActorContract::build_data(&f.init).unwrap();
        let mut policy = SliceData::load_cell(original.reference(0).unwrap()).unwrap();
        assert_eq!(policy.get_next_u32().unwrap(), 0);
        let mut updated_policy = BuilderData::new();
        updated_policy.append_u32(1).unwrap();
        updated_policy.checked_append_references_and_data(&policy).unwrap();
        let mut data = BuilderData::new();
        f.owner.address().write_to(&mut data).unwrap();
        data.append_bit_one().unwrap();
        data.append_u64(GAS_STRESS_NEXT_ID).unwrap();
        data.append_u32(pending_count).unwrap();
        data.append_u32(GAS_STRESS_LIVE).unwrap();
        data.checked_append_reference(updated_policy.into_cell().unwrap()).unwrap();
        data.checked_append_reference(write_accounting(&accounting)).unwrap();
        data.checked_append_reference(dicts.into_cell().unwrap()).unwrap();
        GasStressSeed {
            data: data.into_cell().unwrap(),
            balance,
            created_at,
            deadline,
            current_terms,
        }
    })
}

fn gas_stress_fixture() -> (Fixture, &'static GasStressSeed) {
    let mut f = Fixture::solvency();
    let seed = gas_stress_seed(&f);
    assert_eq!(f.bc.now(), seed.created_at, "stress seed uses deterministic sandbox time");
    let mut account = f.bc.get_account(&f.service).unwrap().clone();
    assert!(account.set_data(seed.data.clone()));
    account.set_balance(chain_block::CurrencyCollection {
        coins: coins(seed.balance),
        ..Default::default()
    });
    account.set_last_paid(seed.created_at);
    // Replacing persistent data invalidated the old account's storage usage.
    // Recompute it before asking init_storage_stat to validate the snapshot.
    account.update_storage_stat(26).unwrap();
    account.init_storage_stat(26).unwrap();
    let cell_count = account.storage_info_cells();
    // Only lift the account-size cap so the contract's declared 100,000-entry
    // boundary can be measured. Keep real gas, storage and forwarding prices.
    // The stock 2,048 masterchain / 65,536 basechain limits can reject smaller
    // real-world states; this fixture does not claim otherwise.
    let mut limits = f.bc.config_params().size_limits_config().unwrap();
    let stress_cap = u32::try_from(cell_count.checked_add(1_024).unwrap()).unwrap();
    limits.max_acc_state_cells = limits.max_acc_state_cells.max(stress_cap);
    limits.max_mc_acc_state_cells = limits.max_mc_acc_state_cells.max(stress_cap);
    f.bc.set_size_limits_config(limits).unwrap();
    eprintln!(
        "service gas stress: live={GAS_STRESS_LIVE}, callers=99001, unique_cells={cell_count}, test_state_cap={stress_cap}"
    );
    f.bc.set_account(f.service.clone(), account);
    assert_eq!(f.live_count(), u64::from(GAS_STRESS_LIVE));
    assert_eq!(f.caller_live_count(f.caller.address()), 999);
    assert_eq!(f.caller_live_count(f.caller2.address()), 0);
    (f, seed)
}

fn gas_stress_balance(f: &Fixture) -> u128 {
    f.bc.get_account(&f.service).unwrap().balance().unwrap().coins.as_u128()
}

// total_fwd_fees already contains its action-fee component; do not add the
// separately reported total_action_fees again. Storage rent is operator-funded
// and reported separately from the incoming execution allowance.
fn gas_stress_measure(label: &str, result: &SendResult, allowance: u64) -> (u128, u128) {
    let desc = result.read_primary_description();
    let compute = match &desc.compute_ph {
        chain_block::TrComputePhase::Vm(vm) => vm,
        skipped => panic!("{label}: compute skipped: {skipped:?}"),
    };
    let gas = compute.gas_fees.as_u128();
    let rent = desc.storage_ph.as_ref().map(|s| s.storage_fees_collected.as_u128()).unwrap_or(0);
    let forwarding = desc
        .action
        .as_ref()
        .and_then(|a| a.total_fwd_fees.as_ref())
        .map(chain_block::Coins::as_u128)
        .unwrap_or(0);
    let action = desc
        .action
        .as_ref()
        .and_then(|a| a.total_action_fees.as_ref())
        .map(chain_block::Coins::as_u128)
        .unwrap_or(0);
    let cost = gas.checked_add(forwarding).unwrap();
    eprintln!(
        "service gas trace {label}: used={} gas={gas} forwarding={forwarding} action_component={action} rent={rent} execution_cost={cost} allowance={allowance} exit={} action_result={:?}",
        compute.gas_used.as_u64(),
        compute.exit_code,
        desc.action.as_ref().map(|a| a.result_code)
    );
    result.expect_success();
    assert!(
        cost.checked_mul(4).unwrap() <= u128::from(allowance).checked_mul(3).unwrap(),
        "{label}: measured execution cost must leave at least 25% allowance headroom"
    );
    (cost, rent)
}

#[test]
fn solvency_admission_gas_at_capacity_with_sparse_ids_and_wide_accounting() {
    use contracts::service_actor::protocol_constants::ADMISSION_GAS_ALLOWANCE;
    for existing in [false, true] {
        let (mut f, seed) = gas_stress_fixture();
        // Entries are almost their full permitted 60-day age; storage rent is
        // actually charged using their initialized storage statistics.
        f.bc.set_now(seed.deadline.checked_sub(1).unwrap());
        let caller = if existing { f.caller.address() } else { f.caller2.address() }.clone();
        let before = gas_stress_balance(&f);
        let principal = f.init.price_per_call.checked_add(f.init.storage_fee).unwrap();
        let value = principal.checked_add(ADMISSION_GAS_ALLOWANCE).unwrap();
        let result = f.no_bounce(
            &caller,
            value,
            ServiceActorContract::call(77, [0x77; 32], seed.current_terms).unwrap(),
        );
        let label = if existing { "admit/existing-caller" } else { "admit/new-caller" };
        let (cost, rent) = gas_stress_measure(label, &result, ADMISSION_GAS_ALLOWANCE);
        result.expect_out_msgs(1);
        assert_eq!(f.live_count(), 100_000);
        assert_eq!(f.caller_live_count(&caller), if existing { 1000 } else { 1 });
        assert_eq!(
            gas_stress_balance(&f),
            before.checked_sub(rent).unwrap().checked_add(u128::from(principal)).unwrap(),
            "successful admission cannot spend preexisting backing on execution"
        );
        let outgoing = result.first_transaction().unwrap().get_out_msg(0).unwrap().unwrap();
        assert_eq!(
            outgoing.int_header().unwrap().value.coins.as_u128(),
            u128::from(ADMISSION_GAS_ALLOWANCE).checked_sub(cost).unwrap()
        );
    }
}

#[test]
fn solvency_payout_gas_at_capacity_with_sparse_ids_and_wide_coins() {
    use contracts::service_actor::protocol_constants::PAYOUT_GAS_ALLOWANCE;
    let (mut f, seed) = gas_stress_fixture();
    let snapshot = f.bc.get_account(&f.service).unwrap().clone();
    for operation in ["refund", "sweep-pending", "sweep-refund", "withdraw"] {
        f.bc.set_account(f.service.clone(), snapshot.clone());
        f.bc.set_now(if operation == "refund" {
            seed.deadline.checked_sub(1).unwrap()
        } else {
            seed.deadline
        });
        let caller = f.caller.address().clone();
        let outsider = f.outsider.address().clone();
        let owner = f.owner.address().clone();
        let (sender, body, amount) = match operation {
            "refund" => (
                caller.clone(),
                ServiceActorContract::claim_refund(80, GAS_STRESS_REFUND_ID, &outsider).unwrap(),
                GAS_STRESS_PRICE,
            ),
            "sweep-pending" => (
                outsider.clone(),
                ServiceActorContract::sweep_expired_request(81, GAS_STRESS_PENDING_ID).unwrap(),
                u128::from(f.init.cleanup_bounty),
            ),
            "sweep-refund" => (
                outsider.clone(),
                ServiceActorContract::sweep_expired_request(82, GAS_STRESS_REFUND_ID).unwrap(),
                u128::from(f.init.cleanup_bounty),
            ),
            "withdraw" => {
                (owner, ServiceActorContract::withdraw_revenue(83, TOS).unwrap(), u128::from(TOS))
            }
            _ => unreachable!(),
        };
        let before = gas_stress_balance(&f);
        let result = f.no_bounce(&sender, PAYOUT_GAS_ALLOWANCE, body);
        let (cost, rent) = gas_stress_measure(operation, &result, PAYOUT_GAS_ALLOWANCE);
        result.expect_out_msgs(2);
        assert_eq!(
            gas_stress_balance(&f),
            before.checked_sub(rent).unwrap().checked_sub(amount).unwrap(),
            "successful payout cannot spend any backing beyond its authorized principal"
        );
        let transaction = result.first_transaction().unwrap();
        let paid = transaction.get_out_msg(0).unwrap().unwrap();
        let change = transaction.get_out_msg(1).unwrap().unwrap();
        assert_eq!(
            paid.int_header().unwrap().value.coins.as_u128(),
            amount,
            "principal must be exact"
        );
        assert_eq!(
            change.int_header().unwrap().value.coins.as_u128(),
            u128::from(PAYOUT_GAS_ALLOWANCE).checked_sub(cost).unwrap(),
            "only unused execution funding returns as change"
        );
    }
}

#[test]
fn solvency_change_does_not_transfer_preexisting_extra_currencies() {
    use contracts::service_actor::protocol_constants::{
        ADMISSION_GAS_ALLOWANCE, PAYOUT_GAS_ALLOWANCE,
    };
    let mut f = Fixture::solvency();
    // The supported current executor (global version 16) implements currency
    // v2: carry-all mode 128 carries native coins only. Nonempty RAWRESERVEX is
    // deliberately rejected there, so reserving extra currencies would break
    // this otherwise native-only settlement. Pin this real behavior explicitly.
    assert_eq!(f.bc.config_params().global_version(), current_network::global_version());
    assert!(current_network::global_version() >= 10, "currency-v2 settlement is required");
    let mut account = f.bc.get_account(&f.service).unwrap().clone();
    let mut balance = account.balance().unwrap().clone();
    balance.set_other(0x71_53, 123_456).unwrap();
    let extras = balance.other.clone();
    account.set_balance(balance);
    account.update_storage_stat(26).unwrap();
    f.bc.set_account(f.service.clone(), account);
    let caller = f.caller.address().clone();
    let destination = f.outsider.address().clone();
    let value = f
        .init
        .price_per_call
        .checked_add(f.init.storage_fee)
        .and_then(|v| v.checked_add(ADMISSION_GAS_ALLOWANCE))
        .unwrap();
    let body = ServiceActorContract::call(90, [0x90; 32], f.terms()).unwrap();
    let admission = f.no_bounce(&caller, value, body);
    admission.expect_success();
    assert_eq!(f.bc.get_account(&f.service).unwrap().balance().unwrap().other, extras);
    admission
        .first_transaction()
        .unwrap()
        .iterate_out_msgs(|message| {
            assert!(
                message.get_value().unwrap().other.is_empty(),
                "change must not sweep unrelated currencies"
            );
            Ok(true)
        })
        .unwrap();

    f.bc.set_now(u32::try_from(f.request(0).unwrap().response_deadline).unwrap());
    f.expire(&caller, 91, 0).expect_success();
    let refund = f.no_bounce(
        &caller,
        PAYOUT_GAS_ALLOWANCE,
        ServiceActorContract::claim_refund(92, 0, &destination).unwrap(),
    );
    refund.expect_success();
    assert_eq!(f.bc.get_account(&f.service).unwrap().balance().unwrap().other, extras);
    refund
        .first_transaction()
        .unwrap()
        .iterate_out_msgs(|message| {
            assert!(
                message.get_value().unwrap().other.is_empty(),
                "principal and change carry native coins only"
            );
            Ok(true)
        })
        .unwrap();
}
