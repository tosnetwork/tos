/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) lifecycle tests for the Capability Registry contract.
//!
//! These execute the compiled contract embedded in
//! `CapabilityRegistryContract` against the in-process executor: deployment
//! and get-method inspection, owner-authorized metadata/verifier updates,
//! permissionless staking, owner-authorized bond withdrawal, verifier-gated
//! reputation updates, and the deactivate/reactivate lifecycle -- plus the
//! unauthorized/illegal-transition rejections for each.

use chain_block::{Cell, IBitstring, MsgAddressInt};
use contracts::{CapabilityRegistryContract, CapabilityRegistryInit};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};

const TOS: u64 = 1_000_000_000;
const ERR_NOT_OWNER: i32 = 1800;
const ERR_NOT_VERIFIER: i32 = 1801;
const ERR_NO_VERIFIER: i32 = 1802;
const ERR_INACTIVE: i32 = 1803;
const ERR_ALREADY_ACTIVE: i32 = 1804;
const ERR_INSUFFICIENT_BOND: i32 = 1805;
const ERR_UNKNOWN_OP: i32 = 1807;

struct Fixture {
    bc: Blockchain,
    owner: Treasury,
    verifier: Treasury,
    outsider: Treasury,
    registry: MsgAddressInt,
}

impl Fixture {
    fn new(initial_bond: u64, funding: u64, with_verifier: bool) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        // No basechain workchain descriptor in the sandbox config, so run in
        // the masterchain (matches task_escrow_sandbox.rs / agent_account_sandbox.rs).
        bc.set_workchain(-1);
        let owner = bc.treasury("owner", 1_000 * TOS).expect("owner");
        let verifier = bc.treasury("verifier", 1_000 * TOS).expect("verifier");
        let outsider = bc.treasury("outsider", 1_000 * TOS).expect("outsider");
        let init = CapabilityRegistryInit {
            owner: owner.address().clone(),
            verifier: with_verifier.then(|| verifier.address().clone()),
            task_categories_hash: [0x11; 32],
            pricing_hash: [0x22; 32],
            metadata_hash: [0x33; 32],
            verification_method_hash: [0x44; 32],
            initial_bond,
            registered_at: 1_700_000_000,
        };
        let registry = CapabilityRegistryContract::calculate_address(-1, &init).expect("address");
        let state_init = CapabilityRegistryContract::build_state_init(&init).expect("state init");
        let deploy = MessageBuilder::internal(owner.address(), &registry, funding)
            .bounce(false)
            .state_init(state_init)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, owner, verifier, outsider, registry }
    }

    fn send_from(&mut self, from: &MsgAddressInt, body: Cell) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(from, &self.registry, TOS / 10).body(body).build();
        self.bc.send_message(msg).expect("send")
    }

    fn data(&self) -> contracts::CapabilityRegistryData {
        let stack = self
            .bc
            .run_get_method(&self.registry, "get_capability_registry_data", vec![])
            .expect("get_capability_registry_data")
            .expect_success()
            .stack
            .clone();
        // Reuse the production decoder against a stack built the same way
        // the real DefaultChainProvider does (bottom-first StackEntry list).
        let entries = stack
            .iter()
            .map(sandbox_stack_item_to_entry)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("stack conversion");
        CapabilityRegistryContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(entries))
            .expect("decode_data")
    }

    fn balance(&self, addr: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(addr)
            .and_then(|acc| acc.balance().and_then(|cc| cc.coins.as_u64()))
            .unwrap_or(0)
    }
}

/// Converts one sandbox VM stack item into the wire `StackEntry` shape that
/// `TvmStackParser` expects, mirroring what a real JSON-RPC server does when
/// serializing get-method results (see also the equivalent helper in
/// `service::http::agent_query_api`'s test module).
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
    let f = Fixture::new(2 * TOS, 2 * TOS + TOS / 10, true);
    let data = f.data();
    assert_eq!(data.owner, f.owner.address().clone());
    assert_eq!(data.verifier, Some(f.verifier.address().clone()));
    assert!(data.active);
    assert_eq!(data.registered_at, 1_700_000_000);
    assert_eq!(data.bond, 2 * TOS);
    assert_eq!(data.reputation_score, 0);
    assert_eq!(data.task_categories_hash, [0x11; 32]);
    assert_eq!(data.pricing_hash, [0x22; 32]);
    assert_eq!(data.metadata_hash, [0x33; 32]);
    assert_eq!(data.verification_method_hash, [0x44; 32]);
}

#[test]
fn deploy_without_verifier_reports_none() {
    let f = Fixture::new(TOS, TOS + TOS / 10, false);
    assert_eq!(f.data().verifier, None);
}

#[test]
fn owner_can_update_metadata_others_rejected() {
    let mut f = Fixture::new(TOS, TOS + TOS / 10, true);
    let outsider = f.outsider.address().clone();
    f.send_from(
        &outsider,
        CapabilityRegistryContract::update_metadata(1, [0xAA; 32], [0xBB; 32], [0xCC; 32], [0xDD; 32])
            .unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_NOT_OWNER);

    let owner = f.owner.address().clone();
    f.send_from(
        &owner,
        CapabilityRegistryContract::update_metadata(2, [0xAA; 32], [0xBB; 32], [0xCC; 32], [0xDD; 32])
            .unwrap(),
    )
    .expect_success();
    let data = f.data();
    assert_eq!(data.task_categories_hash, [0xAA; 32]);
    assert_eq!(data.pricing_hash, [0xBB; 32]);
    assert_eq!(data.metadata_hash, [0xCC; 32]);
    assert_eq!(data.verification_method_hash, [0xDD; 32]);
}

#[test]
fn owner_can_rotate_verifier_and_new_verifier_takes_effect() {
    let mut f = Fixture::new(TOS, TOS + TOS / 10, true);
    let owner = f.owner.address().clone();
    let outsider_addr = f.outsider.address().clone();

    // Rotate the verifier to `outsider`.
    f.send_from(
        &owner,
        CapabilityRegistryContract::update_verifier(1, Some(&outsider_addr), &owner).unwrap(),
    )
    .expect_success();
    assert_eq!(f.data().verifier, Some(outsider_addr.clone()));

    // The old verifier is no longer authorized to update reputation.
    let old_verifier = f.verifier.address().clone();
    f.send_from(&old_verifier, CapabilityRegistryContract::update_reputation(2, 5).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_VERIFIER);

    // The new verifier (outsider) is now authorized.
    f.send_from(&outsider_addr, CapabilityRegistryContract::update_reputation(3, 5).unwrap())
        .expect_success();
    assert_eq!(f.data().reputation_score, 5);
}

#[test]
fn anyone_can_stake_increasing_recorded_bond() {
    let mut f = Fixture::new(TOS, TOS + TOS / 10, true);
    let outsider = f.outsider.address().clone();
    let stake_amount = 3 * TOS;
    let msg = tos_sandbox::MessageBuilder::internal(&outsider, &f.registry, stake_amount)
        .body(CapabilityRegistryContract::stake(1).unwrap())
        .build();
    f.bc.send_message(msg).expect("send").expect_success();
    // The recorded bond grows by (roughly) the sent value; sandbox forward
    // fees are deducted from the credited value, so allow a small margin.
    let bond = f.data().bond;
    assert!(bond > TOS + stake_amount - TOS / 100, "bond too small after stake: {bond}");
}

#[test]
fn owner_can_withdraw_bond_within_limit_others_and_overdraw_rejected() {
    let mut f = Fixture::new(5 * TOS, 5 * TOS + TOS / 5, true);
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, CapabilityRegistryContract::withdraw_bond(1, TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);

    let owner = f.owner.address().clone();
    f.send_from(&owner, CapabilityRegistryContract::withdraw_bond(2, 10 * TOS).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_INSUFFICIENT_BOND);

    let owner_before = f.balance(&owner);
    f.send_from(&owner, CapabilityRegistryContract::withdraw_bond(3, 2 * TOS).unwrap())
        .expect_success();
    let delta = f.balance(&owner) - owner_before;
    assert!(delta > 2 * TOS - TOS / 100 && delta <= 2 * TOS, "unexpected withdrawal delta: {delta}");
    assert_eq!(f.data().bond, 3 * TOS);
}

#[test]
fn verifier_gated_reputation_updates() {
    // No verifier configured at all: even the "verifier" treasury cannot update.
    let mut f = Fixture::new(TOS, TOS + TOS / 10, false);
    let verifier = f.verifier.address().clone();
    f.send_from(&verifier, CapabilityRegistryContract::update_reputation(1, 10).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NO_VERIFIER);

    // With a verifier configured, only that address may adjust the score,
    // and deltas accumulate (including negative deltas).
    let mut f = Fixture::new(TOS, TOS + TOS / 10, true);
    let verifier = f.verifier.address().clone();
    let outsider = f.outsider.address().clone();
    f.send_from(&outsider, CapabilityRegistryContract::update_reputation(2, 10).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_VERIFIER);
    f.send_from(&verifier, CapabilityRegistryContract::update_reputation(3, 10).unwrap())
        .expect_success();
    f.send_from(&verifier, CapabilityRegistryContract::update_reputation(4, -3).unwrap())
        .expect_success();
    assert_eq!(f.data().reputation_score, 7);
}

#[test]
fn deactivate_refunds_owner_blocks_updates_and_reactivate_restores() {
    let mut f = Fixture::new(2 * TOS, 2 * TOS + TOS / 10, true);
    let owner = f.owner.address().clone();
    let outsider = f.outsider.address().clone();

    f.send_from(&outsider, CapabilityRegistryContract::deactivate(1).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);

    let owner_before = f.balance(&owner);
    f.send_from(&owner, CapabilityRegistryContract::deactivate(2).unwrap()).expect_success();
    assert!(!f.data().active);
    assert_eq!(f.data().bond, 0);
    assert!(f.balance(&owner) > owner_before + 2 * TOS - TOS / 10, "deactivate did not refund bond");
    assert!(f.balance(&f.registry.clone()) < TOS / 100, "registry balance should be drained");

    // update_metadata requires the entry to be active.
    f.send_from(
        &owner,
        CapabilityRegistryContract::update_metadata(3, [0; 32], [0; 32], [0; 32], [0; 32]).unwrap(),
    )
    .expect_aborted()
    .expect_exit_code(ERR_INACTIVE);

    // Double-deactivate is rejected.
    f.send_from(&owner, CapabilityRegistryContract::deactivate(4).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_INACTIVE);

    f.send_from(&outsider, CapabilityRegistryContract::reactivate(5).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_NOT_OWNER);
    f.send_from(&owner, CapabilityRegistryContract::reactivate(6).unwrap()).expect_success();
    assert!(f.data().active);

    // Double-reactivate is rejected.
    f.send_from(&owner, CapabilityRegistryContract::reactivate(7).unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_ALREADY_ACTIVE);
}

#[test]
fn unknown_operation_is_rejected() {
    let mut f = Fixture::new(TOS, TOS + TOS / 10, true);
    let owner = f.owner.address().clone();
    let mut body = chain_block::BuilderData::new();
    body.append_u32(0xDEAD_BEEF).unwrap().append_u64(1).unwrap();
    f.send_from(&owner, body.into_cell().unwrap())
        .expect_aborted()
        .expect_exit_code(ERR_UNKNOWN_OP);
}
