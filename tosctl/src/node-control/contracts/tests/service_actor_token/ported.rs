/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The native actor's sandbox cases (service_actor_sandbox.rs) on the token
//! rail. Each keeps the native case's name where the behaviour carries over;
//! where the token rail changes it (principal in tokens, payouts reported),
//! the case checks the token rail's rule instead, as its comment says.

use chain_block::{Cell, CurrencyCollection, IBitstring, MsgAddressInt};
use contracts::service_actor_token::{
    ServiceActorTokenCodeProfile, ServiceActorTokenContract as Actor, decode_request_snapshot, err,
    outcome, protocol_constants,
};

use crate::harness::*;
use crate::payouts::{expired, returned_entry};
use crate::world::*;

const MIN_WINDOW: u32 = 3_600;

pub(crate) struct Attestor {
    seed: [u8; 32],
    pub(crate) public_key: Vec<u8>,
}

impl Attestor {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self { seed, public_key: contracts::native_registry::native_public_key_from_seed(&seed) }
    }

    fn key_id(&self) -> [u8; 32] {
        contracts::native_registry::controller_key_id(&self.public_key).unwrap()
    }

    fn sign(&self, domain: &[u8; 32]) -> Vec<u8> {
        contracts::service_actor::sign_service_response(&self.seed, domain).unwrap().1
    }
}

/// A 256-bit unsigned integer on the stack, as 32 big-endian bytes.
fn int256(item: &tos_vm::stack::StackItem) -> [u8; 32] {
    let text = item.as_integer().unwrap().to_str_radix(16);
    let padded = format!("{text:0>64}");
    hex::decode(padded).unwrap().try_into().unwrap()
}

pub(crate) fn global_id(w: &World) -> i32 {
    match w.net.bc.config_params().config(19).unwrap() {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        other => panic!("parameter 19 is not the global id: {other:?}"),
    }
}

/// (caller, price, response_deadline, refund_claim_deadline, request_hash, terms_hash)
fn request(w: &World, id: u64) -> (MsgAddressInt, u128, u64, u64, [u8; 32], [u8; 32]) {
    let r = w.get("get_request", vec![int_arg(id)]);
    assert_eq!(r.int_at(0), 1, "request {id} is pending");
    let hash = |i: usize| int256(&r.stack[i]);
    (
        chain_block::Deserializable::construct_from(&mut r.slice_at(1)).unwrap(),
        r.int_at(2) as u128,
        r.int_at(5) as u64,
        r.int_at(6) as u64,
        hash(8),
        hash(9),
    )
}

pub(crate) fn signed_respond(
    w: &World,
    attestor: &Attestor,
    network: i32,
    id: u64,
    response: [u8; 32],
) -> Cell {
    let (caller, price, rd, cd, rh, th) = request(w, id);
    let domain = contracts::service_respond_domain_hash(
        network,
        &w.actor,
        &caller,
        id,
        &rh,
        &response,
        &th,
        u64::try_from(price).unwrap(),
        rd,
        cd,
    )
    .unwrap();
    Actor::respond_signed(1, id, response, &attestor.sign(&domain)).unwrap()
}

fn attested(seed: u8) -> (World, Attestor) {
    let attestor = Attestor::new([seed; 32]);
    let w = World::with(Options {
        attestor_pubkey: Some(attestor.public_key.clone()),
        ..Options::default()
    });
    (w, attestor)
}

fn update(
    w: &World,
    active: bool,
    price: u128,
    fee: u64,
    bounty: u64,
    sla: u32,
    window: u32,
) -> Cell {
    Actor::update_policy(
        1,
        price,
        fee,
        bounty,
        sla,
        window,
        active,
        true,
        None,
        &w.owner,
        0,
        protocol_constants::NO_TOKEN_CAP,
        [0x11; 32],
        [0x22; 32],
    )
    .unwrap()
}

#[test]
fn overpayment_in_tos_is_returned_at_call_time_and_token_overpayment_is_refused() {
    let mut w = World::new();
    let buyer = w.user(0);
    let actor_before = w.balance(&w.actor);
    // Five TOS more than the budget: the change returns to the buyer.
    let start =
        w.fund(&buyer, PRICE, w.call_forward() + u128::from(5 * TOS), Some(w.token_call([1; 32])));
    assert_eq!(w.ledger().pending, PRICE);
    let change: u128 = w
        .actor_txs_since(start)
        .iter()
        .flat_map(|d| d.outs.iter())
        .filter(|m| is_to(m, &buyer))
        .map(value_of)
        .sum();
    assert!(change > u128::from(5 * TOS), "the TOS overpayment came back: {change}");
    assert!(
        w.balance(&w.actor) >= actor_before + u128::from(STORAGE_FEE),
        "the storage fee is kept"
    );
    // Overpaying in tokens is refused by the exact-amount rule (funding.rs).
}

#[test]
fn ten_minute_windows_are_refused_by_the_release_code_and_admitted_by_the_test_code() {
    let ten = protocol_constants::TEST_PROFILE_MIN_WINDOW_SECS;
    let mut w =
        World::with(Options { response_sla: ten, refund_claim_window: ten, ..Options::default() });
    let buyer = w.user(0);
    let start = w.fund(&buyer, PRICE, w.call_forward(), Some(w.token_call([1; 32])));
    assert_eq!(w.funding_logs_since(start)[0].reason as i32, err::INVALID_RESPONSE_SLA);
    let mut w = World::with(Options {
        profile: ServiceActorTokenCodeProfile::TestProfile,
        response_sla: ten,
        refund_claim_window: ten,
        ..Options::default()
    });
    let buyer = w.user(0);
    let id = w.call(&buyer);
    w.advance(ten);
    succeeded(&w.op(&buyer, Actor::expire(1, id).unwrap(), TOS));
    assert_eq!(ServiceActorTokenCodeProfile::TestProfile.min_window_secs(), ten);
}

#[test]
fn the_test_code_hash_differs_from_the_release_code_hash() {
    let release = Actor::code_for(ServiceActorTokenCodeProfile::Release).unwrap();
    let test = Actor::code_for(ServiceActorTokenCodeProfile::TestProfile).unwrap();
    assert_ne!(release.repr_hash(), test.repr_hash());
}

#[test]
fn solvency_source_matches_embedded_code() {
    let compiled = tos_sandbox::compile_func(&[
        repo_root().join("crypto/smartcont/stdlib.fc"),
        actor_source(),
    ])
    .unwrap();
    assert_eq!(
        compiled.repr_hash(),
        Actor::code().unwrap().repr_hash(),
        "the embedded code is the source's"
    );
}

#[test]
fn concurrent_calls_from_one_and_several_callers_are_independent() {
    let mut w = World::new();
    let (a, b) = (w.user(0), w.user(1));
    let ids = [w.call(&a), w.call(&a), w.call(&b)];
    assert_eq!(w.counters().2, 3);
    assert_eq!((w.caller_live(&a), w.caller_live(&b)), (2, 1));
    let owner = w.owner.clone();
    succeeded(&w.op(&owner, Actor::respond(1, ids[1], [1; 32]).unwrap(), TOS));
    assert!(w.request_exists(ids[0]) && !w.request_exists(ids[1]) && w.request_exists(ids[2]));
    w.advance(SLA);
    succeeded(&w.op(&b, Actor::expire(1, ids[2]).unwrap(), TOS));
    let funding = w.payout_funding();
    succeeded(&w.op(&b, Actor::claim_refund(1, ids[2], &b).unwrap(), funding));
    assert!(w.request_exists(ids[0]), "an unrelated request is untouched");
    assert_eq!(w.ledger().pending, PRICE);
    assert_eq!(w.ledger().withdrawable_revenue, PRICE);
}

#[test]
fn respond_requires_owner_and_a_pending_request() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = w.call(&buyer);
    refused_with(&w.op(&buyer, Actor::respond(1, id, [1; 32]).unwrap(), TOS), err::NOT_OWNER);
    let owner = w.owner.clone();
    refused_with(
        &w.op(&owner, Actor::respond(1, id + 1, [1; 32]).unwrap(), TOS),
        err::REQUEST_NOT_PENDING,
    );
    succeeded(&w.op(&owner, Actor::respond(1, id, [1; 32]).unwrap(), TOS));
    refused_with(
        &w.op(&owner, Actor::respond(1, id, [1; 32]).unwrap(), TOS),
        err::REQUEST_NOT_PENDING,
    );
}

#[test]
fn respond_boundary_is_exact() {
    let mut w = World::new();
    let buyer = w.user(0);
    let owner = w.owner.clone();
    let a = w.call(&buyer);
    let b = w.call(&buyer);
    w.advance(SLA - 1);
    succeeded(&w.op(&owner, Actor::respond(1, a, [1; 32]).unwrap(), TOS));
    w.advance(1);
    refused_with(
        &w.op(&owner, Actor::respond(1, b, [1; 32]).unwrap(), TOS),
        err::RESPONSE_WINDOW_CLOSED,
    );
}

#[test]
fn expire_boundary_is_exact() {
    let mut w = World::new();
    let buyer = w.user(0);
    let a = w.call(&buyer);
    let b = w.call(&buyer);
    w.advance(SLA - 1);
    refused_with(&w.op(&buyer, Actor::expire(1, a).unwrap(), TOS), err::EXPIRE_TOO_EARLY);
    w.advance(1);
    succeeded(&w.op(&buyer, Actor::expire(1, a).unwrap(), TOS));
    w.advance(WINDOW);
    refused_with(&w.op(&buyer, Actor::expire(1, b).unwrap(), TOS), err::EXPIRE_TOO_LATE);
}

#[test]
fn claim_refund_boundary_is_exact() {
    let mut w = World::new();
    let buyer = w.user(0);
    let a = expired(&mut w, &buyer);
    let funding = w.payout_funding();
    w.advance(WINDOW - 1);
    succeeded(&w.op(&buyer, Actor::claim_refund(1, a, &buyer).unwrap(), funding));
    let mut w = World::new();
    let buyer = w.user(0);
    let a = expired(&mut w, &buyer);
    w.advance(WINDOW);
    refused_with(
        &w.op(&buyer, Actor::claim_refund(1, a, &buyer).unwrap(), funding),
        err::REFUND_CLAIM_EXPIRED,
    );
}

#[test]
fn sweep_boundary_is_exact() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = w.call(&buyer);
    let stranger = w.net.stranger.address().clone();
    let funding = w.payout_funding();
    w.advance(SLA + WINDOW - 1);
    refused_with(
        &w.op(&stranger, Actor::sweep_expired_request(1, id).unwrap(), funding),
        err::SWEEP_TOO_EARLY,
    );
    w.advance(1);
    succeeded(&w.op(&stranger, Actor::sweep_expired_request(1, id).unwrap(), funding));
}

#[test]
fn every_admission_emits_a_snapshot_matching_the_stored_request() {
    let mut w = World::new();
    for i in 0..3 {
        let buyer = w.user(i);
        let start = w.fund(&buyer, PRICE, w.call_forward(), Some(w.token_call([i as u8; 32])));
        let s = &w.snapshots_since(start)[0];
        let (caller, price, rd, cd, rh, th) = request(&w, s.request_id);
        assert_eq!(
            (caller, price, rd, cd, rh, th),
            (
                buyer,
                PRICE,
                s.response_deadline,
                s.refund_claim_deadline,
                s.request_hash,
                s.terms_hash
            )
        );
        assert_eq!(s.terms_hash, w.terms_hash());
        assert_eq!(
            s.terms.asset_master.to_vec(),
            account_hash(&w.net.minter()),
            "the terms bind the asset"
        );
        assert_eq!(s.terms.asset_wallet_code_hash, codes().wallet.repr_hash().inner());
    }
}

#[test]
fn sweep_works_against_a_properly_expired_refund_entry_and_not_on_a_request_live_nowhere() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    w.advance(WINDOW);
    let stranger = w.net.stranger.address().clone();
    let funding = w.payout_funding();
    let before = w.tokens(&buyer);
    succeeded(&w.op(&stranger, Actor::sweep_expired_request(1, id).unwrap(), funding));
    assert_eq!(w.tokens(&buyer), before + PRICE, "the price returns to the caller");
    assert!(!w.refund_exists(id));
    refused_with(
        &w.op(&stranger, Actor::sweep_expired_request(1, id).unwrap(), funding),
        err::REQUEST_NOT_LIVE,
    );
    refused_with(
        &w.op(&stranger, Actor::sweep_expired_request(1, 77).unwrap(), funding),
        err::REQUEST_NOT_LIVE,
    );
}

#[test]
fn duplicate_expire_claim_and_sweep_are_rejected() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    refused_with(&w.op(&buyer, Actor::expire(1, id).unwrap(), TOS), err::REQUEST_NOT_PENDING);
    let funding = w.payout_funding();
    succeeded(&w.op(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding));
    refused_with(
        &w.op(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding),
        err::REFUND_NOT_FOUND,
    );
    w.advance(WINDOW);
    let stranger = w.net.stranger.address().clone();
    refused_with(
        &w.op(&stranger, Actor::sweep_expired_request(1, id).unwrap(), funding),
        err::REQUEST_NOT_LIVE,
    );
}

#[test]
fn only_the_original_caller_can_claim_their_refund() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let other = w.user(1);
    let funding = w.payout_funding();
    refused_with(
        &w.op(&other, Actor::claim_refund(1, id, &other).unwrap(), funding),
        err::NOT_REFUND_CALLER,
    );
    succeeded(&w.op(&buyer, Actor::claim_refund(1, id, &other).unwrap(), funding));
}

#[test]
fn attestor_signature_cannot_be_replayed_across_requests_and_matches_the_compiled_bytecode() {
    let (mut w, attestor) = attested(0x41);
    let buyer = w.user(0);
    let a = w.call(&buyer);
    let b = w.call(&buyer);
    let network = global_id(&w);
    let for_a = signed_respond(&w, &attestor, network, a, [5; 32]);
    let replay = {
        // a's signature presented for b
        let (caller, price, rd, cd, rh, th) = request(&w, a);
        let domain = contracts::service_respond_domain_hash(
            network,
            &w.actor,
            &caller,
            a,
            &rh,
            &[5; 32],
            &th,
            price as u64,
            rd,
            cd,
        )
        .unwrap();
        Actor::respond_signed(1, b, [5; 32], &attestor.sign(&domain)).unwrap()
    };
    let owner = w.owner.clone();
    refused_with(&w.op(&owner, replay, TOS), err::BAD_RESPONSE_SIGNATURE);
    succeeded(&w.op(&owner, for_a, TOS));
    assert!(!w.request_exists(a) && w.request_exists(b));
    // Unsigned on an attested request.
    refused_with(&w.op(&owner, Actor::respond(1, b, [5; 32]).unwrap(), TOS), 9);
    let snapshot_key = w.get("get_request", vec![int_arg(b)]);
    let id = int256(&snapshot_key.stack[11]);
    assert_eq!(id, attestor.key_id(), "the request snapshots the attestor key id");
}

#[test]
fn a_response_signed_for_another_network_is_refused() {
    let (mut w, attestor) = attested(0x77);
    let buyer = w.user(0);
    let id = w.call(&buyer);
    let here = global_id(&w);
    let elsewhere = signed_respond(&w, &attestor, here.wrapping_add(1), id, [6; 32]);
    let this_one = signed_respond(&w, &attestor, here, id, [6; 32]);
    let owner = w.owner.clone();
    refused_with(&w.op(&owner, elsewhere, TOS), err::BAD_RESPONSE_SIGNATURE);
    succeeded(&w.op(&owner, this_one, TOS));
}

#[test]
fn update_policy_and_attestor_rotation_never_alter_already_snapshotted_requests() {
    let (mut w, attestor) = attested(0x42);
    let buyer = w.user(0);
    let id = w.call(&buyer);
    let (_, _, rd, cd, _, th) = request(&w, id);
    let owner = w.owner.clone();
    let body = update(&w, true, 2 * PRICE, STORAGE_FEE, BOUNTY, 2 * SLA, WINDOW);
    succeeded(&w.op(&owner, body, TOS));
    let other = Attestor::new([0x43; 32]);
    succeeded(&w.op(&owner, Actor::rotate_attestor_key(1, &other.public_key).unwrap(), TOS));
    let (_, price, rd2, cd2, _, th2) = request(&w, id);
    assert_eq!((price, rd2, cd2, th2), (PRICE, rd, cd, th), "the snapshot is unchanged");
    assert_ne!(w.terms_hash(), th, "the published terms moved");
    let network = global_id(&w);
    succeeded(&w.op(&owner, signed_respond(&w, &attestor, network, id, [7; 32]), TOS));
}

#[test]
fn a_deployed_attestor_key_must_match_its_published_key_id_and_revocation_clears_it() {
    // A key id that is not the key's: admission refuses (a funding return).
    let attestor = Attestor::new([0x50; 32]);
    let mut w = World::with_data(
        Options { attestor_pubkey: Some(attestor.public_key.clone()), ..Options::default() },
        |data| {
            let mut d = ActorData::parse(&data);
            let mut s = chain_block::SliceData::load_cell(d.policy.clone()).unwrap();
            let commitments = s.checked_drain_reference().unwrap();
            let mut c = chain_block::SliceData::load_cell(commitments).unwrap();
            let meta = c.get_next_bits(512).unwrap();
            c.get_next_bits(1 + 256).unwrap();
            let key = c.checked_drain_reference().ok();
            let rebuilt = cell(|b| {
                b.append_raw(&meta, 512).unwrap();
                b.append_bit_one().unwrap();
                b.append_raw(&[0x13; 32], 256).unwrap();
                b.append_bit_one().unwrap();
                b.checked_append_reference(key.clone().unwrap()).unwrap();
            });
            d.policy = cell(|b| {
                b.append_bytestring(&s).unwrap();
                b.checked_append_reference(rebuilt).unwrap();
            });
            d.build()
        },
    );
    let buyer = w.user(0);
    let start = w.fund(&buyer, PRICE, w.call_forward(), Some(w.token_call([1; 32])));
    assert_eq!(w.funding_logs_since(start)[0].reason as i32, err::BAD_ATTESTOR_KEY);
    // Revocation clears the key and its id, and is never frozen by a pending request.
    let (mut w, _) = attested(0x51);
    let buyer = w.user(0);
    let id = w.call(&buyer);
    let owner = w.owner.clone();
    succeeded(&w.op(&owner, Actor::revoke_attestor(1).unwrap(), TOS));
    let r = w.get("get_service_data", vec![]);
    assert_eq!((r.int_at(14), r.int_at(15)), (0, 0), "no attestor, no key id");
    assert!(w.get("get_attestor_key", vec![]).stack[0].is_null());
    assert!(w.request_exists(id), "the pending request keeps its snapshot");
    let snapshot = w.call(&buyer);
    let r = w.get("get_request", vec![int_arg(snapshot)]);
    assert_eq!(r.int_at(10), 0, "a request after revocation has no attestor");
}

#[test]
fn malformed_attestor_keys_and_signatures_are_refused() {
    let (mut w, _attestor) = attested(0x60);
    let owner = w.owner.clone();
    let short = cell(|b| {
        b.append_u32(0x5354_4307).unwrap().append_u64(1).unwrap();
        b.checked_append_reference(cell(|k| {
            k.append_u32(12).unwrap();
        }))
        .unwrap();
    });
    assert!(outcome(&w.op(&owner, short, TOS)).aborted, "a short key is refused");
    let buyer = w.user(0);
    let id = w.call(&buyer);
    let bad = Actor::respond_signed(1, id, [1; 32], &[7u8; 2420]).unwrap();
    refused_with(&w.op(&owner, bad, TOS), err::BAD_RESPONSE_SIGNATURE);
    let short_sig = cell(|b| {
        b.append_u32(0x5354_4302).unwrap().append_u64(1).unwrap().append_u64(id).unwrap();
        b.append_raw(&[1; 32], 256).unwrap();
        b.checked_append_reference(cell(|s| {
            s.append_u32(3).unwrap();
        }))
        .unwrap();
    });
    assert!(outcome(&w.op(&owner, short_sig, TOS)).aborted, "a short signature is refused");
    assert!(w.request_exists(id));
}

#[test]
fn claim_to_a_destination_without_a_wallet_deploys_it_and_counts_once() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let fresh = MsgAddressInt::with_params(0, chain_block::UInt256::from([0x99; 32])).unwrap();
    assert!(!w.net.exists(&w.net.wallet_of(&fresh)));
    let funding = w.payout_funding();
    succeeded(&w.op(&buyer, Actor::claim_refund(1, id, &fresh).unwrap(), funding));
    assert_eq!(w.tokens(&fresh), PRICE, "the transfer's StateInit deploys the wallet");
    assert_eq!(w.ledger().attributed(), Some(0), "counted once");
}

#[test]
fn bounced_messages_other_than_the_actors_own_reports_never_mutate_state() {
    let mut w = World::new();
    let buyer = w.user(0);
    w.call(&buyer);
    let data = w.data_hash();
    for b in [
        Actor::claim_refund(1, 0, &buyer).unwrap(),
        Actor::respond(1, 0, [0; 32]).unwrap(),
        cell(|b| {
            b.append_u32(OP_TRANSFER_DELIVERED).unwrap().append_u64(1).unwrap();
        }),
    ] {
        let original = tos_sandbox::MessageBuilder::internal(&w.actor, &buyer, TOS).body(b).build();
        let bounce = bounced_copy(&original);
        w.send(bounce);
        assert_eq!(w.data_hash(), data);
    }
}

#[test]
fn expiring_a_request_does_not_release_live_capacity() {
    let mut w = World::new();
    let buyer = w.user(0);
    expired(&mut w, &buyer);
    assert_eq!(w.counters().1, 0, "no longer pending");
    assert_eq!(w.counters().2, 1, "still live");
    assert_eq!(w.caller_live(&buyer), 1);
}

#[test]
fn update_policy_enforces_every_bound() {
    let mut w = World::new();
    let owner = w.owner.clone();
    for (code, body) in [
        (
            err::INVALID_RESPONSE_SLA,
            update(&w, true, PRICE, STORAGE_FEE, BOUNTY, MIN_WINDOW - 1, WINDOW),
        ),
        (
            err::INVALID_RESPONSE_SLA,
            update(&w, true, PRICE, STORAGE_FEE, BOUNTY, MONTH + 1, WINDOW),
        ),
        (
            err::INVALID_REFUND_CLAIM_WINDOW,
            update(&w, true, PRICE, STORAGE_FEE, BOUNTY, SLA, MIN_WINDOW - 1),
        ),
        (
            err::INVALID_REFUND_CLAIM_WINDOW,
            update(&w, true, PRICE, STORAGE_FEE, BOUNTY, SLA, MONTH + 1),
        ),
        (
            err::INVALID_CLEANUP_BOUNTY,
            update(&w, true, PRICE, STORAGE_FEE, BOUNTY - 1, SLA, WINDOW),
        ),
        (err::INVALID_CLEANUP_BOUNTY, update(&w, true, PRICE, 2 * TOS, TOS + 1, SLA, WINDOW)),
        (
            err::INSUFFICIENT_STORAGE_FEE,
            update(&w, true, PRICE, STORAGE_FEE - 1, BOUNTY, SLA, WINDOW),
        ),
        (err::INSUFFICIENT_PAYMENT, update(&w, true, 0, STORAGE_FEE, BOUNTY, SLA, WINDOW)),
    ] {
        refused_with(&w.op(&owner, body, TOS), code);
    }
    let zero_cap = Actor::update_policy(
        1,
        PRICE,
        STORAGE_FEE,
        BOUNTY,
        SLA,
        WINDOW,
        true,
        true,
        None,
        &owner,
        0,
        0,
        [0; 32],
        [0; 32],
    )
    .unwrap();
    refused_with(&w.op(&owner, zero_cap, TOS), err::EXPOSURE_CAP);
    assert_eq!(w.policy_version(), 0, "nothing changed");
    succeeded(&w.op(&owner, update(&w, true, 2 * PRICE, STORAGE_FEE, BOUNTY, SLA, WINDOW), TOS));
    assert_eq!(w.policy_version(), 1);
}

#[test]
fn only_owner_can_call_owner_only_operations() {
    let mut w = World::new();
    let stranger = w.net.stranger.address().clone();
    let attestor = Attestor::new([0x61; 32]);
    for b in [
        update(&w, true, PRICE, STORAGE_FEE, BOUNTY, SLA, WINDOW),
        Actor::rotate_attestor_key(1, &attestor.public_key).unwrap(),
        Actor::revoke_attestor(1).unwrap(),
        Actor::withdraw_revenue(1, 0, 0).unwrap(),
        Actor::recover_surplus(1, 1).unwrap(),
        Actor::abandon_payout(1, 1).unwrap(),
    ] {
        refused_with(&w.op(&stranger, b, TOS), err::NOT_OWNER);
    }
}

#[test]
fn a_call_quoted_under_one_policy_is_refused_under_another() {
    let mut w = World::new();
    let buyer = w.user(0);
    let quoted = w.token_call([1; 32]);
    let owner = w.owner.clone();
    succeeded(&w.op(&owner, update(&w, true, PRICE, STORAGE_FEE, BOUNTY, SLA, WINDOW), TOS));
    let start = w.fund(&buyer, PRICE, w.call_forward(), Some(quoted));
    assert_eq!(w.funding_logs_since(start)[0].reason as i32, err::TERMS_MISMATCH);
    w.call(&buyer);
}

#[test]
fn withdraw_revenue_is_capped_by_balance_and_never_takes_locked_fees() {
    let mut w = World::new();
    let buyer = w.user(0);
    let owner = w.owner.clone();
    let a = w.call(&buyer);
    w.call(&buyer); // a live entry whose storage fee stays locked
    succeeded(&w.op(&owner, Actor::respond(1, a, [1; 32]).unwrap(), TOS));
    let native = w.native();
    assert_eq!(native.withdrawable_revenue, STORAGE_FEE);
    // The balance no longer covers the lock and the reserve: every withdrawal, the
    // zero one included, is refused.
    let actor = w.actor.clone();
    let floor = u128::from(native.locked_storage_fees)
        + u128::from(protocol_constants::MINIMUM_OPERATING_RESERVE);
    w.net.set_balance(&actor, floor - 1);
    refused_with(
        &w.op(&owner, Actor::withdraw_revenue(1, 0, 0).unwrap(), TOS),
        err::INSUFFICIENT_REVENUE,
    );
    // Exactly at the floor plus the revenue: the revenue, and no more.
    w.net.set_balance(&actor, floor + u128::from(STORAGE_FEE));
    refused_with(
        &w.op(&owner, Actor::withdraw_revenue(1, 0, STORAGE_FEE + 1).unwrap(), TOS),
        err::INSUFFICIENT_REVENUE,
    );
    let before = w.balance(&owner);
    succeeded(&w.op(&owner, Actor::withdraw_revenue(1, 0, STORAGE_FEE).unwrap(), TOS));
    assert!(
        w.balance(&owner) + u128::from(TOS) >= before + u128::from(STORAGE_FEE),
        "paid, with change"
    );
    assert!(w.balance(&w.actor) >= floor, "the locked fee and the reserve stay");
    // A zero withdrawal at the floor returns its execution change.
    succeeded(&w.op(&owner, Actor::withdraw_revenue(2, 0, 0).unwrap(), TOS));
    // Token revenue above the booked amount is refused.
    let funding = w.payout_funding();
    refused_with(
        &w.op(&owner, Actor::withdraw_revenue(3, PRICE + 1, 0).unwrap(), funding),
        err::INSUFFICIENT_REVENUE,
    );
    // At most four revenue payouts are in flight.
    w.patch(|d| d.revenue_payouts_in_flight = 4);
    refused_with(
        &w.op(&owner, Actor::withdraw_revenue(4, 1, 0).unwrap(), funding),
        err::PAYOUT_IN_FLIGHT,
    );
}

#[test]
fn a_liability_that_would_go_negative_is_refused_with_the_range_code() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = w.call(&buyer);
    w.checking = false;
    w.patch(|d| d.token[0] = 0);
    let owner = w.owner.clone();
    refused_with(&w.op(&owner, Actor::respond(1, id, [1; 32]).unwrap(), TOS), err::AMOUNT_RANGE);
}

#[test]
fn solvency_admission_requires_existing_obligations_and_preserves_operator_excess() {
    let mut w = World::new();
    let buyer = w.user(0);
    w.call(&buyer);
    let native = w.native();
    let actor = w.actor.clone();
    let floor = u128::from(native.locked_storage_fees)
        + u128::from(protocol_constants::MINIMUM_OPERATING_RESERVE);
    w.net.set_balance(&actor, floor - 1);
    let start = w.fund(&buyer, PRICE, w.call_forward(), Some(w.token_call([1; 32])));
    assert_eq!(w.funding_logs_since(start)[0].reason as i32, err::OPERATING_RESERVE_UNFUNDED);
    // With an excess, admission keeps all of it and adds the storage fee.
    w.net.set_balance(&actor, floor + u128::from(3 * TOS));
    let before = w.balance(&actor);
    w.call(&buyer);
    assert!(w.balance(&actor) >= before + u128::from(STORAGE_FEE) - 1);
}

#[test]
fn solvency_payouts_require_execution_budget() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let short = w.payout_funding() - 1;
    refused_with(
        &w.op(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), short),
        err::INSUFFICIENT_EXECUTION_PAYMENT,
    );
    let other = w.call(&buyer);
    w.advance(SLA + WINDOW);
    let stranger = w.net.stranger.address().clone();
    refused_with(
        &w.op(&stranger, Actor::sweep_expired_request(1, other).unwrap(), short),
        err::INSUFFICIENT_EXECUTION_PAYMENT,
    );
    let mut w = World::new();
    let buyer = w.user(0);
    let entry = returned_entry(&mut w, &buyer);
    let short = w.payout_funding() - 1;
    refused_with(
        &w.op(&buyer, Actor::claim_returned(1, entry, &buyer).unwrap(), short),
        err::INSUFFICIENT_EXECUTION_PAYMENT,
    );
    w.advance(MONTH);
    refused_with(
        &w.op(&stranger, Actor::sweep_returned(1, entry).unwrap(), short),
        err::INSUFFICIENT_EXECUTION_PAYMENT,
    );
    let stranger = w.net.stranger.address().clone();
    let _ = stranger;
}

#[test]
fn solvency_refund_never_haircuts_principal_when_fees_rise() {
    let mut w = World::new();
    let buyer = w.user(0);
    let id = expired(&mut w, &buyer);
    let gas = w.net.gas_price(false);
    w.net.set_gas_price(false, gas * 3);
    w.net.scale_forward_prices(false, 3, 1);
    let funding = w.payout_funding();
    let before = w.tokens(&buyer);
    succeeded(&w.op(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding));
    assert_eq!(w.tokens(&buyer), before + PRICE, "the whole principal, whatever the fees");
}

#[test]
fn solvency_sweep_after_real_rent_and_below_the_reserve_pays_the_principal() {
    let mut w = World::new();
    let buyer = w.user(0);
    let a = w.call(&buyer);
    w.call(&buyer);
    w.advance(SLA + WINDOW + 30 * DAY);
    let actor = w.actor.clone();
    // Rent and an operator who let the reserve run down.
    // Below the operating reserve, just above the locks.
    let native = w.native();
    let locks = u128::from(native.locked_storage_fees) + u128::from(native.locked_outcome_fees);
    w.net.set_balance(&actor, locks + u128::from(TOS / 100));
    let stranger = w.net.stranger.address().clone();
    let funding = w.payout_funding();
    let before = w.tokens(&buyer);
    let start = w.net.delivered.len();
    succeeded(&w.op(&stranger, Actor::sweep_expired_request(1, a).unwrap(), funding));
    assert_eq!(w.tokens(&buyer), before + PRICE, "the principal is paid");
    assert_eq!(w.outcome_logs_since(start)[0].outcome, outcome::DELIVERED);
    assert_eq!(w.ledger().pending, PRICE, "the other entry stays");
}

#[test]
fn solvency_change_does_not_transfer_preexisting_extra_currencies() {
    let mut w = World::new();
    let actor = w.actor.clone();
    let mut account = w.net.bc.get_account(&actor).unwrap().clone();
    let mut balance: CurrencyCollection = account.balance().unwrap().clone();
    balance.set_other(0x71_53, 123_456).unwrap();
    let extras = balance.other.clone();
    account.set_balance(balance);
    account.update_storage_stat(26).unwrap();
    w.net.bc.set_account(actor.clone(), account);
    let buyer = w.user(0);
    let start = w.net.delivered.len();
    w.call(&buyer);
    let id = expired(&mut w, &buyer);
    let funding = w.payout_funding();
    succeeded(&w.op(&buyer, Actor::claim_refund(1, id, &buyer).unwrap(), funding));
    assert_eq!(w.net.bc.get_account(&actor).unwrap().balance().unwrap().other, extras);
    for d in w.actor_txs_since(start) {
        for m in &d.outs {
            if let Some(v) = m.get_value() {
                assert!(v.other.is_empty(), "no send sweeps unrelated currencies");
            }
        }
    }
}

#[test]
fn conformance_vectors_come_from_contract_execution() {
    use chain_block::{base64_encode, write_boc};
    const FIXTURE: &str = include_str!("../fixtures/service_actor_token/conformance-vectors.json");
    let b64 = |cell: &Cell| base64_encode(write_boc(cell).expect("BOC"));
    let hex32 = |bytes: &[u8]| hex::encode(bytes);
    let mut w = World::new();
    let deploy_data = w.net.bc.get_account(&w.actor).unwrap().get_data().unwrap();
    let buyer = w.user(0);
    let terms = w.terms_cell();
    let forward = w.call_forward();
    // The funding prices at the state the funding vectors are taken in, from
    // get_funding_prices and get_service_data.
    let funding_prices = |w: &World| {
        let (min_funding, admission, return_budget, report, lock, payout) = w.prices();
        serde_json::json!({
            "storage_fee": w.get("get_service_data", vec![]).int_at(4).to_string(),
            "min_funding_value": min_funding.to_string(),
            "admission_gas_allowance": admission.to_string(),
            "return_budget": return_budget.to_string(),
            "report_tos_amount": report.to_string(),
            "outcome_fee_lock": lock.to_string(),
            "payout_funding": payout.to_string(),
            "accepting_tokens": w.get("get_accepting_tokens", vec![]).int_at(0) != 0,
        })
    };
    let prices_at_funding = funding_prices(&w);
    let funding = Actor::funding_transfer(
        41,
        PRICE,
        &w.actor,
        &buyer,
        forward,
        &w.funding_prices(),
        [0xA7; 32],
        w.terms_hash(),
    )
    .unwrap();
    let mut outcomes = serde_json::Map::new();
    let mut log_bodies = |w: &World, start: usize, tag: u32| -> Vec<String> {
        w.actor_txs_since(start)
            .iter()
            .flat_map(|d| d.outs.iter())
            .filter(|m| !m.is_internal())
            .filter_map(|m| {
                let body = m.body()?;
                let cell = if body.remaining_bits() == 0 {
                    body.reference(0).ok()?
                } else {
                    body.clone().into_cell().ok()?
                };
                let mut s = chain_block::SliceData::load_cell(cell.clone()).ok()?;
                (s.get_next_u32().ok()? == tag).then(|| b64(&cell))
            })
            .collect()
    };
    let start = w.fund(&buyer, PRICE, forward, Some(w.token_call([0xA7; 32])));
    let sat1 = log_bodies(&w, start, 0x5341_5431);
    let snapshot = decode_request_snapshot(
        &chain_block::read_single_root_boc(chain_block::base64_decode(&sat1[0]).unwrap()).unwrap(),
    )
    .unwrap();
    let start = w.fund(&buyer, PRICE + 1, forward, Some(w.token_call([0xA8; 32])));
    let saf1 = log_bodies(&w, start, 0x5341_4631);
    let sao1_return = log_bodies(&w, start, 0x5341_4f31);
    // A payout of every kind and outcome is covered in payouts.rs; one of each
    // outcome is pinned here.
    let id = expired(&mut w, &buyer);
    let fund = w.payout_funding();
    let refund_msg = w.op_message(&buyer, Actor::claim_refund(42, id, &buyer).unwrap(), fund);
    let start = w.refusing_at_r(refund_msg, false);
    let sao1_refused = log_bodies(&w, start, 0x5341_4f31);
    let entry = w.counters().3 - 1;
    let claim = w.op_message(&buyer, Actor::claim_returned(43, entry, &buyer).unwrap(), fund);
    let start = w.bouncing_at_s(claim);
    let sao1_bounced = log_bodies(&w, start, 0x5341_4f31);
    w.fund(&w.user(3), 250, w.min_funding() - 1, Some(w.token_call([1; 32])));
    let owner = w.owner.clone();
    let start = w.net.delivered.len();
    succeeded(&w.op(&owner, Actor::recover_surplus(44, 250).unwrap(), 2 * fund));
    let sab1 = log_bodies(&w, start, 0x5341_4231);
    let sao1_surplus = log_bodies(&w, start, 0x5341_4f31);
    // Every payout kind and outcome, each from its own world.
    for k in 1..=7u8 {
        for (way, name) in [
            (crate::payouts::Way::Delivered, "delivered"),
            (crate::payouts::Way::RefusedAtR, "refused_at_r"),
            (crate::payouts::Way::BouncedAtS, "bounced_at_s"),
        ] {
            let mut v = World::new();
            let case = crate::payouts::prepare(&mut v, k);
            let start = v.net.delivered.len();
            crate::payouts::run(&mut v, case, way);
            outcomes.insert(
                format!("kind_{k}_{name}"),
                serde_json::json!(log_bodies(&v, start, 0x5341_4f31)),
            );
        }
    }
    let start = w.fund(&buyer, PRICE, w.min_funding() - 1, Some(w.token_call([0xA9; 32])));
    let saf1_underfunded = log_bodies(&w, start, 0x5341_4631);
    outcomes.insert("funding_return_delivered".into(), serde_json::json!(sao1_return));
    outcomes.insert("refund_refused_at_r".into(), serde_json::json!(sao1_refused));
    outcomes.insert("returned_claim_bounced_at_s".into(), serde_json::json!(sao1_bounced));
    outcomes.insert("surplus_delivered".into(), serde_json::json!(sao1_surplus));
    // A call whose terms carry an attestor, answered by a signed respond. The
    // ML-DSA-44 signature is hedged, so the vector pins the key, the terms, the
    // snapshot and the response domain hash, and that the signed respond is
    // accepted; the signature bytes themselves differ per run.
    let attestor = Attestor::new([0x5a; 32]);
    let mut a = World::with(Options {
        attestor_pubkey: Some(attestor.public_key.clone()),
        ..Options::default()
    });
    let a_deploy = a.net.bc.get_account(&a.actor).unwrap().get_data().unwrap();
    let a_buyer = a.user(0);
    let a_terms = a.terms_cell();
    let a_prices = funding_prices(&a);
    let a_start = a.fund(&a_buyer, PRICE, a.call_forward(), Some(a.token_call([0xB1; 32])));
    let a_sat1 = log_bodies(&a, a_start, 0x5341_5431);
    let a_snapshot = decode_request_snapshot(
        &chain_block::read_single_root_boc(chain_block::base64_decode(&a_sat1[0]).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        a_snapshot.terms.attestor_key_id,
        Some(attestor.key_id()),
        "the terms carry the attestor"
    );
    let (caller, price, rd, cd, rh, th) = request(&a, a_snapshot.request_id);
    let response_hash = [0xB2; 32];
    let network = global_id(&a);
    let domain = contracts::service_respond_domain_hash(
        network,
        &a.actor,
        &caller,
        a_snapshot.request_id,
        &rh,
        &response_hash,
        &th,
        price as u64,
        rd,
        cd,
    )
    .unwrap();
    let respond =
        Actor::respond_signed(51, a_snapshot.request_id, response_hash, &attestor.sign(&domain))
            .unwrap();
    let a_owner = a.owner.clone();
    succeeded(&a.op(&a_owner, respond, TOS));
    assert!(!a.request_exists(a_snapshot.request_id), "the signed respond is accepted");
    let key_sha256 = {
        use sha2::{Digest, Sha256};
        hex32(&Sha256::digest(&attestor.public_key))
    };
    let attested = serde_json::json!({
        "actor": a.actor.to_string(),
        "attestor_seed_hex": hex32(&[0x5a; 32]),
        "attestor_key_id": hex32(&attestor.key_id()),
        "attestor_public_key_sha256": key_sha256,
        "deploy_data_boc_base64": b64(&a_deploy),
        "terms_hash": hex32(&a_snapshot.terms_hash),
        "terms_cell_boc_base64": b64(&a_terms),
        "funding_prices": a_prices,
        "sat1": a_sat1,
        "respond": {
            "global_id": network,
            "request_id": a_snapshot.request_id,
            "response_hash": hex32(&response_hash),
            "domain_hash": hex32(&domain),
            "signature_context": String::from_utf8_lossy(contracts::service_actor::SERVICE_ACTOR_RESPOND_CONTEXT),
            "accepted": true,
        },
    });
    let code = Actor::code().unwrap();
    let actual = serde_json::json!({
        "schema": "tos.service.actor.token.v1.vectors",
        "rail": contracts::service_actor_token::SERVICE_ACTOR_TOKEN_RAIL,
        "contract_code_hash": format!("tvm-cell-sha256:{}", hex32(code.repr_hash().as_slice())),
        "contract_code_boc_base64": b64(&code),
        "wallet_code_hash": hex32(codes().wallet.repr_hash().as_slice()),
        "master": w.net.minter().to_string(),
        "actor": w.actor.to_string(),
        "actor_wallet": w.wallet().to_string(),
        "init": {
            "owner": w.init.owner.to_string(),
            "price_per_call": w.init.price_per_call.to_string(),
            "storage_fee": w.init.storage_fee.to_string(),
            "cleanup_bounty": w.init.cleanup_bounty.to_string(),
            "response_sla": w.init.response_sla,
            "refund_claim_window": w.init.refund_claim_window,
            "max_token_liability": w.init.max_token_liability.to_string(),
        },
        "deploy_data_boc_base64": b64(&deploy_data),
        "terms_hash": hex32(&snapshot.terms_hash),
        "terms_cell_boc_base64": b64(&terms),
        "funding_prices": prices_at_funding,
        "funding_transfer_body_boc_base64": b64(&funding),
        "sat1": sat1,
        "saf1_refused_amount": saf1,
        "saf1_underfunded": saf1_underfunded,
        "sao1": outcomes,
        "sab1_surplus": sab1,
        "attested": attested,
    });
    if let Ok(path) = std::env::var("SERVICE_ACTOR_TOKEN_VECTORS_OUT") {
        std::fs::write(&path, serde_json::to_string_pretty(&actual).unwrap() + "\n").unwrap();
        return;
    }
    let expected: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture");
    assert_eq!(actual, expected, "conformance vectors moved; regenerate deliberately");
}
