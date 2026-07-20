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

    let caller = f.caller.address().clone();
    f.send_from(&caller, TOS / 5, ServiceActorContract::call(2, [0xAA; 32]).unwrap())
        .expect_success();
    let data = f.data();
    assert_eq!(data.calls_today, 1);
    assert_eq!(data.total_revenue, TOS / 5);
    assert_eq!(data.last_request_hash, [0xAA; 32]);
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
    let mut f = Fixture::new(TOS / 100, 2, true, TOS / 10);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(1, [0x01; 32]).unwrap())
        .expect_success();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(2, [0x02; 32]).unwrap())
        .expect_success();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::call(3, [0x03; 32]).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_RATE_LIMITED);
    assert_eq!(f.data().calls_today, 2);
}

#[test]
fn zero_rate_limit_means_unlimited() {
    let mut f = Fixture::new(TOS / 100, 0, true, TOS / 10);
    let outsider = f.outsider.address().clone();
    for i in 1..=10u64 {
        f.send_from(&outsider, TOS / 10, ServiceActorContract::call(i, [i as u8; 32]).unwrap())
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
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(2, [0xDD; 32]).unwrap())
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
fn owner_can_withdraw_revenue_within_limit_others_and_overdraw_rejected() {
    let mut f = Fixture::new(TOS, 0, true, TOS / 10);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, 3 * TOS, ServiceActorContract::call(1, [0x01; 32]).unwrap())
        .expect_success();
    assert_eq!(f.data().total_revenue, 3 * TOS);

    let owner = f.owner.address().clone();
    f.send_from(&outsider, TOS / 10, ServiceActorContract::withdraw_revenue(2, TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);
    f.send_from(&owner, TOS / 10, ServiceActorContract::withdraw_revenue(3, 100 * TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_INSUFFICIENT_REVENUE);

    let owner_before = f.balance(&owner);
    f.send_from(&owner, TOS / 10, ServiceActorContract::withdraw_revenue(4, 2 * TOS).unwrap())
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

    // Plain `respond` (no signature) is rejected by the trailing signature load.
    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(1, response_hash).unwrap())
        .expect_aborted();
    assert_eq!(f.data().last_response_hash, [0; 32]);

    // A signature from the wrong key is rejected.
    let wrong_key = SigningKey::from_bytes(&[0x88; 32]);
    let wrong_signature: [u8; 64] = wrong_key.sign(&response_hash).to_bytes();
    f.send_from(
        &owner,
        TOS / 10,
        ServiceActorContract::respond_signed(2, response_hash, &wrong_signature).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_BAD_RESPONSE_SIGNATURE);
    assert_eq!(f.data().last_response_hash, [0; 32]);

    // A non-owner sender is still rejected, even with a valid signature.
    let outsider = f.outsider.address().clone();
    let valid_signature: [u8; 64] = attestor.sign(&response_hash).to_bytes();
    f.send_from(
        &outsider,
        TOS / 10,
        ServiceActorContract::respond_signed(3, response_hash, &valid_signature).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_NOT_OWNER);
    assert_eq!(f.data().last_response_hash, [0; 32]);

    // The owner, with the correct attestor signature, commits the response.
    f.send_from(
        &owner,
        TOS / 10,
        ServiceActorContract::respond_signed(4, response_hash, &valid_signature).unwrap(),
    )
    .expect_success();
    assert_eq!(f.data().last_response_hash, response_hash);
}

#[test]
fn owner_can_rotate_and_revoke_the_attestor_key_others_rejected() {
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

    // Owner rotates in an attestor key: respond now requires a signature.
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

    // Owner revokes: respond works again without any signature.
    f.send_from(&owner, TOS / 10, ServiceActorContract::revoke_attestor(5).unwrap())
        .expect_success();
    assert!(f.data().attestor_pubkey.is_none());

    f.send_from(&owner, TOS / 10, ServiceActorContract::respond(6, response_hash).unwrap())
        .expect_success();
    assert_eq!(f.data().last_response_hash, response_hash);
}
