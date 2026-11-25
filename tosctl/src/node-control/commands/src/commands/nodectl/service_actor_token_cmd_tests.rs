/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! Planner tests for `agent service-token`, and the golden `--build-only`
//! documents under `fixtures/service_actor_token/`. Each case has
//! `<name>.inputs.json` (the state read and the arguments) and
//! `<name>.out.json` (the exact bytes `--build-only` prints for them). Set
//! `TOSCTL_UPDATE_GOLDEN=1` to rewrite them after an intended change.

use super::*;
use chain_block::{AnycastInfo, SliceData};
use contracts::service_actor_token::{TokenTerms, protocol_constants::NO_TOKEN_CAP};

fn basechain(byte: u8) -> MsgAddressInt {
    MsgAddressInt::with_standart(None, 0, [byte; 32].into()).unwrap()
}

fn wallet_code() -> Cell {
    let mut b = BuilderData::new();
    b.append_raw(b"bridge token wallet code (fixture)", 34 * 8).unwrap();
    b.into_cell().unwrap()
}

const OWNER: u8 = 0x01;
const ACTOR: u8 = 0x5a;
const MASTER: u8 = 0xa1;
const BUYER: u8 = 0xb0;
const PRICE: u128 = 2_500_000; // 2.5 tokens of 6 decimals
const STORAGE_FEE: u64 = 200_000_000;

fn data() -> ServiceActorTokenData {
    ServiceActorTokenData {
        owner: basechain(OWNER),
        active: true,
        policy_version: 2,
        price_per_call: PRICE,
        storage_fee: STORAGE_FEE,
        cleanup_bounty: 100_000_000,
        response_sla: 3_600,
        refund_claim_window: 3_600,
        open_access: true,
        authorized_caller: None,
        rate_limit_per_day: 0,
        metadata_hash: [0x11; 32],
        proof_scheme_hash: [0x22; 32],
        attestor_key_id: None,
        max_token_liability: NO_TOKEN_CAP,
        next_request_id: 7,
        pending_count: 1,
        live_count: 2,
        next_payout_id: 12,
    }
}

fn terms_hash(data: &ServiceActorTokenData) -> [u8; 32] {
    TokenTerms {
        policy_version: data.policy_version,
        price_per_call: data.price_per_call,
        storage_fee: data.storage_fee.into(),
        cleanup_bounty: data.cleanup_bounty.into(),
        response_sla: data.response_sla,
        refund_claim_window: data.refund_claim_window,
        asset_master: [MASTER; 32],
        asset_wallet_code_hash: wallet_code().repr_hash().inner(),
        metadata_hash: data.metadata_hash,
        proof_scheme_hash: data.proof_scheme_hash,
        attestor_key_id: data.attestor_key_id,
    }
    .hash()
    .unwrap()
}

fn view() -> ActorView {
    let actor = basechain(ACTOR);
    let master = basechain(MASTER);
    let own_wallet = wallet_of(&actor, &master, &wallet_code()).unwrap();
    let data = data();
    ActorView {
        read_at: ReadAt { seqno: 4242, root_hash: "ab".repeat(32) },
        actor,
        profile: ServiceActorTokenCodeProfile::Release,
        balance: 5_000_000_000,
        terms_hash: terms_hash(&data),
        data,
        token: TokenLedger {
            pending: 2_500_000,
            refundable: 2_500_000,
            returned: 1_000_000,
            in_flight: 500_000,
            withdrawable_revenue: 10_000_000,
        },
        native: NativeLedger {
            withdrawable_revenue: 800_000_000,
            locked_storage_fees: 400_000_000,
            locked_outcome_fees: 300_000_000,
            call_day: 20_000,
            calls_today: 3,
            revenue_payouts_in_flight: 1,
            returned_count: 1,
            returns_in_flight: 0,
            surplus_payouts_in_flight: 0,
        },
        quote: FundingQuote {
            min_funding_value: 1_300_000_000,
            admission_gas_allowance: 300_000_000,
            return_budget: 1_000_000_000,
            report_tos_amount: 60_000_000,
            outcome_fee_lock: 150_000_000,
            payout_funding: 1_200_000_000,
        },
        accepting_tokens: true,
        attestor_key_count: 0,
        master,
        wallet_code: wallet_code(),
        own_wallet,
    }
}

fn call_reads() -> CallReads {
    CallReads {
        asset: Some(RecognizedAsset {
            status: 1,
            decimals: 6,
            wallet_code_hash: wallet_code().repr_hash().inner(),
            max_liability_per_actor: 1_000_000_000_000,
            bridge_config_param: Some(79),
        }),
        wallet_prices: Some((15_000_000, 10_000_000)),
        sender_token_balance: Some(100_000_000),
    }
}

fn call_args() -> CallArgs {
    let view = view();
    CallArgs {
        sender: basechain(BUYER),
        query_id: 9,
        request_hash: [0x33; 32],
        expected_terms_hash: view.terms_hash,
        forward_tos_amount: None,
        wallet_value: None,
    }
}

fn returned(caller: u8, paying: u64) -> ReturnedData {
    ReturnedData {
        caller: basechain(caller),
        amount: 1_000_000,
        paying,
        return_deadline: 1_900_000_000,
    }
}

fn payout(kind: u8) -> PayoutData {
    PayoutData {
        kind,
        request_id: if kind == kind::REVENUE { 0 } else { 5 },
        recipient: basechain(BUYER),
        requester: basechain(BUYER),
        amount: 500_000,
        created_at: 1_800_000_000,
        recipient_wallet: wallet_of(&basechain(BUYER), &basechain(MASTER), &wallet_code()).unwrap(),
        own_wallet: view().own_wallet,
        outcome_fee_lock: 150_000_000,
    }
}

fn pending(attested: bool) -> TokenPendingRequest {
    TokenPendingRequest {
        caller: basechain(BUYER),
        price: PRICE,
        storage_fee: STORAGE_FEE,
        cleanup_bounty: 100_000_000,
        response_deadline: 1_800_003_600,
        refund_claim_deadline: 1_800_007_200,
        policy_version: 2,
        request_hash: [0x33; 32],
        terms_hash: view().terms_hash,
        attestor_key_id: attested.then_some([0x44; 32]),
    }
}

fn op(sender: u8, reads: &OpReads, args: &OpArgs) -> anyhow::Result<Prepared> {
    plan_op(&view(), reads, &basechain(sender), 3, args, None)
}

fn anycast() -> MsgAddressInt {
    let pfx = AnycastInfo::with_rewrite_pfx(SliceData::new(vec![0b1010_0000, 0x80])).unwrap();
    MsgAddressInt::with_standart(Some(pfx), 0, [0x77; 32].into()).unwrap()
}

fn invalid_destinations() -> Vec<(&'static str, MsgAddressInt)> {
    vec![
        ("the actor", basechain(ACTOR)),
        ("workchain -1", MsgAddressInt::with_standart(None, -1, [0x77; 32].into()).unwrap()),
        ("workchain 7", MsgAddressInt::with_standart(None, 7, [0x77; 32].into()).unwrap()),
        ("anycast", anycast()),
        ("addr_var", MsgAddressInt::with_variant(None, 0, SliceData::new(vec![0x77; 33])).unwrap()),
    ]
}

fn error_of(result: anyhow::Result<Prepared>) -> String {
    format!("{:#}", result.expect_err("refused"))
}

// ---- Golden documents ---------------------------------------------------------------

fn view_inputs(view: &ActorView) -> serde_json::Value {
    let data = &view.data;
    serde_json::json!({
        "actor": view.actor.to_string(),
        "code_profile": profile_name(view.profile),
        "read_at": view.read_at,
        "balance": view.balance.to_string(),
        "get_service_data": {
            "owner": data.owner.to_string(),
            "active": data.active,
            "open_access": data.open_access,
            "authorized_caller": data.authorized_caller.as_ref().map(|a| a.to_string()),
            "price_per_call": data.price_per_call.to_string(),
            "storage_fee": data.storage_fee.to_string(),
            "max_token_liability": data.max_token_liability.to_string(),
        },
        "get_terms_hash": hex::encode(view.terms_hash),
        "get_token_ledger": [
            view.token.pending.to_string(),
            view.token.refundable.to_string(),
            view.token.returned.to_string(),
            view.token.in_flight.to_string(),
            view.token.withdrawable_revenue.to_string(),
        ],
        "get_native_ledger": {
            "withdrawable_revenue": view.native.withdrawable_revenue.to_string(),
            "locked_storage_fees": view.native.locked_storage_fees.to_string(),
            "locked_outcome_fees": view.native.locked_outcome_fees.to_string(),
            "revenue_payouts_in_flight": view.native.revenue_payouts_in_flight,
            "surplus_payouts_in_flight": view.native.surplus_payouts_in_flight,
        },
        "get_funding_prices": [
            view.quote.min_funding_value.to_string(),
            view.quote.admission_gas_allowance.to_string(),
            view.quote.return_budget.to_string(),
            view.quote.report_tos_amount.to_string(),
            view.quote.outcome_fee_lock.to_string(),
            view.quote.payout_funding.to_string(),
        ],
        "get_accepting_tokens": view.accepting_tokens,
        "get_attestor_key_count": view.attestor_key_count,
        "get_asset_route": {
            "master": view.master.to_string(),
            "wallet_code_boc": base64::engine::general_purpose::STANDARD
                .encode(write_boc(&view.wallet_code).unwrap()),
        },
        "get_own_wallet": view.own_wallet.to_string(),
    })
}

struct Case {
    name: &'static str,
    inputs: serde_json::Value,
    prepared: Prepared,
}

fn op_case(
    name: &'static str,
    sender: u8,
    reads: OpReads,
    reads_json: serde_json::Value,
    args: OpArgs,
    args_json: serde_json::Value,
) -> Case {
    let prepared = plan_op(&view(), &reads, &basechain(sender), 3, &args, None).unwrap();
    Case {
        name,
        inputs: serde_json::json!({
            "state": view_inputs(&view()),
            "reads": reads_json,
            "sender": basechain(sender).to_string(),
            "query_id": 3,
            "operation": args.operation().name(),
            "arguments": args_json,
        }),
        prepared,
    }
}

fn cases() -> Vec<Case> {
    let none = serde_json::json!({});
    let mut cases = Vec::new();

    let reads = call_reads();
    let args = call_args();
    cases.push(Case {
        name: "call",
        inputs: serde_json::json!({
            "state": view_inputs(&view()),
            "reads": {
                "config_param_84_entry": {
                    "status": 1,
                    "decimals": 6,
                    "wallet_code_hash": hex::encode(wallet_code().repr_hash().as_slice()),
                    "max_liability_per_actor": "1000000000000",
                    "source_chain_id": 1,
                },
                "config_param_79_prices": {
                    "wallet_gas_consumption": "15000000",
                    "wallet_min_tos_for_storage": "10000000",
                },
                "sender_token_wallet_balance": "100000000",
            },
            "sender": basechain(BUYER).to_string(),
            "query_id": 9,
            "operation": "call",
            "arguments": {
                "request_hash": hex::encode([0x33; 32]),
                "expected_terms_hash": hex::encode(view().terms_hash),
                "forward_tos_nanotos": null,
                "wallet_value_nanotos": null,
            },
        }),
        prepared: plan_call(&view(), &reads, &args).unwrap(),
    });

    let request = OpReads { request: Some(pending(false)), ..OpReads::default() };
    let request_json = serde_json::json!({"get_request": {"found": true, "attestor_key_id": null}});
    cases.push(op_case(
        "respond",
        OWNER,
        request.clone(),
        request_json.clone(),
        OpArgs::Respond { request_id: 5, response_hash: [0x55; 32], signature: None },
        serde_json::json!({"request_id": 5, "response_hash": hex::encode([0x55; 32])}),
    ));
    cases.push(op_case(
        "expire",
        BUYER,
        request,
        request_json,
        OpArgs::Expire { request_id: 5 },
        serde_json::json!({"request_id": 5}),
    ));
    cases.push(op_case(
        "claim-refund",
        BUYER,
        OpReads::default(),
        none.clone(),
        OpArgs::ClaimRefund { request_id: 5, destination: basechain(0xc0) },
        serde_json::json!({"request_id": 5, "destination": basechain(0xc0).to_string()}),
    ));
    cases.push(op_case(
        "sweep-expired-request",
        0xd0,
        OpReads::default(),
        none.clone(),
        OpArgs::SweepExpiredRequest { request_id: 5 },
        serde_json::json!({"request_id": 5}),
    ));
    let policy = PolicyArgs {
        price_per_call: 3_000_000,
        storage_fee: 250_000_000,
        cleanup_bounty: 100_000_000,
        response_sla: 7_200,
        refund_claim_window: 3_600,
        active: true,
        open_access: false,
        authorized_caller: Some(basechain(BUYER)),
        rate_limit_per_day: 100,
        max_token_liability: 50_000_000,
        metadata_hash: [0x66; 32],
        proof_scheme_hash: [0x22; 32],
    };
    cases.push(op_case(
        "update-policy",
        OWNER,
        OpReads::default(),
        none.clone(),
        OpArgs::UpdatePolicy(Box::new(policy)),
        serde_json::json!({
            "price_per_call_units": "3000000",
            "storage_fee_nanotos": "250000000",
            "cleanup_bounty_nanotos": "100000000",
            "response_sla": 7200,
            "refund_claim_window": 3600,
            "active": true,
            "open_access": false,
            "authorized_caller": basechain(BUYER).to_string(),
            "rate_limit_per_day": 100,
            "max_token_liability": "50000000",
            "metadata_hash": hex::encode([0x66; 32]),
            "proof_scheme_hash": hex::encode([0x22; 32]),
        }),
    ));
    let key = contracts::native_registry::native_public_key_from_seed(&[7; 32]);
    cases.push(op_case(
        "rotate-attestor-key",
        OWNER,
        OpReads::default(),
        none.clone(),
        OpArgs::RotateAttestorKey { public_key: key.clone() },
        serde_json::json!({"new_attestor_pubkey": hex::encode(&key)}),
    ));
    cases.push(op_case(
        "revoke-attestor",
        OWNER,
        OpReads::default(),
        none.clone(),
        OpArgs::RevokeAttestor,
        none.clone(),
    ));
    cases.push(op_case(
        "withdraw-revenue",
        OWNER,
        OpReads::default(),
        none.clone(),
        OpArgs::WithdrawRevenue { token_amount: 4_000_000, tos_amount: 500_000_000 },
        serde_json::json!({"token_amount": "4000000", "tos_amount_nanotos": "500000000"}),
    ));
    cases.push(op_case(
        "withdraw-revenue-tos-only",
        OWNER,
        OpReads::default(),
        none.clone(),
        OpArgs::WithdrawRevenue { token_amount: 0, tos_amount: 500_000_000 },
        serde_json::json!({"token_amount": "0", "tos_amount_nanotos": "500000000"}),
    ));
    let entry = OpReads { returned: Some(returned(BUYER, 0)), ..OpReads::default() };
    let entry_json = serde_json::json!({"get_returned": {
        "found": true, "caller": basechain(BUYER).to_string(), "amount": "1000000",
        "paying": 0, "return_deadline": 1_900_000_000u64,
    }});
    cases.push(op_case(
        "claim-returned",
        BUYER,
        entry.clone(),
        entry_json.clone(),
        OpArgs::ClaimReturned { id: 8, destination: basechain(0xc0) },
        serde_json::json!({"id": 8, "destination": basechain(0xc0).to_string()}),
    ));
    cases.push(op_case(
        "sweep-returned",
        0xd0,
        entry,
        entry_json,
        OpArgs::SweepReturned { id: 8 },
        serde_json::json!({"id": 8}),
    ));
    cases.push(op_case(
        "recover-surplus",
        OWNER,
        OpReads { own_wallet_balance: Some(20_000_000), ..OpReads::default() },
        serde_json::json!({"own_wallet_balance": "20000000"}),
        OpArgs::RecoverSurplus { amount: 3_000_000 },
        serde_json::json!({"token_amount": "3000000"}),
    ));
    cases.push(op_case(
        "abandon-payout",
        OWNER,
        OpReads { payout: Some(payout(kind::REVENUE)), ..OpReads::default() },
        serde_json::json!({"get_payout": {"found": true, "kind": 3, "created_at": 1_800_000_000u32}}),
        OpArgs::AbandonPayout { id: 10 },
        serde_json::json!({"id": 10}),
    ));
    cases.push(op_case(
        "recheck-payout",
        0xd0,
        OpReads { payout: Some(payout(kind::REFUND)), ..OpReads::default() },
        serde_json::json!({"get_payout": {"found": true, "kind": 1, "created_at": 1_800_000_000u32}}),
        OpArgs::RecheckPayout { id: 11 },
        serde_json::json!({"id": 11}),
    ));
    for (name, target) in
        [("top-up-actor", TopUpTarget::Actor), ("top-up-wallet", TopUpTarget::Wallet)]
    {
        cases.push(Case {
            name,
            inputs: serde_json::json!({
                "state": view_inputs(&view()),
                "reads": {"own_wallet_deployed": true},
                "sender": basechain(OWNER).to_string(),
                "operation": name,
                "arguments": {"amount_nanotos": "700000000"},
            }),
            prepared: plan_top_up(&view(), &basechain(OWNER), target, 700_000_000, true).unwrap(),
        });
    }
    cases
}

fn fixture_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/nodectl/fixtures/service_actor_token")
}

#[test]
fn build_only_documents_equal_their_golden_fixtures() {
    let dir = fixture_dir();
    let update = std::env::var_os("TOSCTL_UPDATE_GOLDEN").is_some();
    for case in cases() {
        let output = format!("{}\n", render(&case.prepared.view).unwrap());
        let inputs = format!("{}\n", serde_json::to_string_pretty(&case.inputs).unwrap());
        let out_path = dir.join(format!("{}.out.json", case.name));
        let in_path = dir.join(format!("{}.inputs.json", case.name));
        if update {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&out_path, &output).unwrap();
            std::fs::write(&in_path, &inputs).unwrap();
            continue;
        }
        let golden = std::fs::read_to_string(&out_path)
            .unwrap_or_else(|e| panic!("{}: {e}", out_path.display()));
        assert_eq!(output, golden, "{}: the document differs from its golden bytes", case.name);
        let recorded: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&in_path).unwrap()).unwrap();
        assert_eq!(recorded, case.inputs, "{}: the recorded inputs differ", case.name);
    }
}

/// Every golden body is the SDK builder's output for the recorded arguments,
/// and the document's BOC and hash are that body's.
#[test]
fn every_document_carries_the_sdk_body() {
    let v = view();
    let expected: Vec<(&str, Cell)> = vec![
        (
            "call",
            Actor::funding_transfer(
                9,
                PRICE,
                &v.actor,
                &basechain(BUYER),
                2 * (u128::from(STORAGE_FEE) + v.quote.min_funding_value),
                &v.quote.prices(STORAGE_FEE, true),
                [0x33; 32],
                v.terms_hash,
            )
            .unwrap(),
        ),
        ("respond", Actor::respond(3, 5, [0x55; 32]).unwrap()),
        ("expire", Actor::expire(3, 5).unwrap()),
        ("claim-refund", Actor::claim_refund(3, 5, &basechain(0xc0)).unwrap()),
        ("sweep-expired-request", Actor::sweep_expired_request(3, 5).unwrap()),
        ("revoke-attestor", Actor::revoke_attestor(3).unwrap()),
        ("withdraw-revenue", Actor::withdraw_revenue(3, 4_000_000, 500_000_000).unwrap()),
        ("claim-returned", Actor::claim_returned(3, 8, &basechain(0xc0)).unwrap()),
        ("sweep-returned", Actor::sweep_returned(3, 8).unwrap()),
        ("recover-surplus", Actor::recover_surplus(3, 3_000_000).unwrap()),
        ("abandon-payout", Actor::abandon_payout(3, 10).unwrap()),
        ("recheck-payout", Actor::recheck_payout(3, 11).unwrap()),
        ("top-up-actor", BuilderData::new().into_cell().unwrap()),
    ];
    let cases = cases();
    for (name, body) in expected {
        let case = cases.iter().find(|c| c.name == name).unwrap();
        assert_eq!(case.prepared.body, body, "{name}");
        let boc =
            base64::engine::general_purpose::STANDARD.decode(&case.prepared.view.body_boc).unwrap();
        assert_eq!(read_single_root_boc(boc).unwrap(), body, "{name}");
        assert_eq!(
            case.prepared.view.body_hash,
            hex::encode(body.repr_hash().as_slice()),
            "{name}"
        );
    }
}

#[test]
fn the_same_state_and_arguments_give_the_same_document() {
    for (a, b) in cases().into_iter().zip(cases()) {
        assert_eq!(
            render(&a.prepared.view).unwrap(),
            render(&b.prepared.view).unwrap(),
            "{}",
            a.name
        );
    }
}

#[test]
fn the_call_goes_to_the_senders_token_wallet_with_the_budgeted_values() {
    let p = plan_call(&view(), &call_reads(), &call_args()).unwrap();
    assert_eq!(
        p.destination,
        wallet_of(&basechain(BUYER), &basechain(MASTER), &wallet_code()).unwrap()
    );
    let budget = u128::from(STORAGE_FEE) + view().quote.min_funding_value;
    assert_eq!(p.view.details["minimum_forward"], budget.to_string());
    assert_eq!(p.view.details["forward_tos_amount"], (2 * budget).to_string());
    // forward + 2 * wallet gas + wallet reserve + 2 forwarding allowances
    let value = 2 * budget + 2 * 15_000_000 + 10_000_000 + 2 * FORWARD_FEE_ALLOWANCE;
    assert_eq!(u128::from(p.value), value);
    assert!(p.view.bounce);
}

// ---- Refusals -----------------------------------------------------------------------

#[test]
fn a_forward_below_the_budget_is_refused_and_the_budget_itself_is_accepted() {
    let budget = u128::from(STORAGE_FEE) + view().quote.min_funding_value;
    let mut args = call_args();
    args.forward_tos_amount = Some(budget - 1);
    let error = error_of(plan_call(&view(), &call_reads(), &args));
    assert!(error.contains("below the call's budget"), "{error}");
    args.forward_tos_amount = Some(0);
    assert!(error_of(plan_call(&view(), &call_reads(), &args)).contains("below the call's budget"));
    args.forward_tos_amount = Some(budget);
    let p = plan_call(&view(), &call_reads(), &args).unwrap();
    assert_eq!(p.view.details["forward_tos_amount"], budget.to_string());
    // An explicit wallet value must exceed the forward.
    args.wallet_value = Some(u64::try_from(budget).unwrap());
    assert!(error_of(plan_call(&view(), &call_reads(), &args)).contains("does not exceed"));
}

#[test]
fn a_call_is_refused_while_the_actor_is_not_accepting_tokens() {
    let mut v = view();
    v.accepting_tokens = false;
    let error = error_of(plan_call(&v, &call_reads(), &call_args()));
    assert!(error.contains("not accepting tokens"), "{error}");
}

#[test]
fn a_call_the_actor_would_refuse_is_refused_before_signing() {
    let refused = |change: &dyn Fn(&mut ActorView, &mut CallReads, &mut CallArgs), needle: &str| {
        let (mut v, mut r, mut a) = (view(), call_reads(), call_args());
        change(&mut v, &mut r, &mut a);
        let error = error_of(plan_call(&v, &r, &a));
        assert!(error.contains(needle), "expected {needle}: {error}");
    };
    refused(&|v, _, _| v.data.active = false, "1901");
    refused(
        &|v, _, _| {
            v.data.open_access = false;
            v.data.authorized_caller = Some(basechain(0xee));
        },
        "1923",
    );
    refused(&|_, _, a| a.expected_terms_hash = [0; 32], "1926");
    refused(&|_, r, _| r.asset = None, "1933");
    refused(&|_, r, _| r.asset.as_mut().unwrap().status = 2, "1933");
    refused(&|_, r, _| r.asset.as_mut().unwrap().wallet_code_hash = [9; 32], "1933");
    refused(&|_, r, _| r.asset.as_mut().unwrap().max_liability_per_actor = 6_500_000, "1937");
    refused(&|v, _, _| v.data.max_token_liability = 6_499_999 + PRICE, "1937");
    refused(&|_, r, _| r.sender_token_balance = Some(PRICE - 1), "below the price");
    refused(&|_, r, _| r.sender_token_balance = None, "no token wallet");
    refused(&|_, r, _| r.wallet_prices = None, "--wallet-value-nanotos");
    refused(
        &|_, _, a| a.sender = MsgAddressInt::with_standart(None, -1, [BUYER; 32].into()).unwrap(),
        "1934",
    );
    refused(&|_, _, a| a.sender = anycast(), "1934");
    // At the cap exactly, the call is admitted.
    let (v, mut r, a) = (view(), call_reads(), call_args());
    r.asset.as_mut().unwrap().max_liability_per_actor = 6_500_000 + PRICE;
    assert!(plan_call(&v, &r, &a).is_ok());
}

#[test]
fn an_invalid_destination_is_refused_for_claim_refund_and_claim_returned() {
    let entry = OpReads { returned: Some(returned(BUYER, 0)), ..OpReads::default() };
    for (name, destination) in invalid_destinations() {
        let refund = OpArgs::ClaimRefund { request_id: 5, destination: destination.clone() };
        let error = error_of(op(BUYER, &OpReads::default(), &refund));
        assert!(error.contains("1934"), "claim-refund to {name}: {error}");
        let claim = OpArgs::ClaimReturned { id: 8, destination };
        let error = error_of(op(BUYER, &entry, &claim));
        assert!(error.contains("1934"), "claim-returned to {name}: {error}");
    }
    // A claimant off workchain 0 is refused too.
    let masterchain_buyer = MsgAddressInt::with_standart(None, -1, [BUYER; 32].into()).unwrap();
    let claim = OpArgs::ClaimReturned { id: 8, destination: basechain(0xc0) };
    let error = error_of(plan_op(&view(), &entry, &masterchain_buyer, 3, &claim, None));
    assert!(error.contains("1934"), "{error}");
}

#[test]
fn returned_entry_ops_check_existence_ownership_and_the_payout_in_flight() {
    let claim = OpArgs::ClaimReturned { id: 8, destination: basechain(0xc0) };
    let sweep = OpArgs::SweepReturned { id: 8 };
    assert!(error_of(op(BUYER, &OpReads::default(), &claim)).contains("1931"));
    assert!(error_of(op(0xd0, &OpReads::default(), &sweep)).contains("1931"));
    let paying = OpReads { returned: Some(returned(BUYER, 13)), ..OpReads::default() };
    assert!(error_of(op(BUYER, &paying, &claim)).contains("1930"));
    assert!(error_of(op(0xd0, &paying, &sweep)).contains("1930"));
    let other = OpReads { returned: Some(returned(0xee, 0)), ..OpReads::default() };
    assert!(error_of(op(BUYER, &other, &claim)).contains("1918"));
    // A sweep is permissionless and pays the entry's caller.
    let p = op(0xd0, &other, &sweep).unwrap();
    assert_eq!(p.view.details["recipient"], basechain(0xee).to_string());
}

#[test]
fn abandon_and_recheck_take_only_their_own_kinds() {
    let abandon = OpArgs::AbandonPayout { id: 10 };
    let recheck = OpArgs::RecheckPayout { id: 10 };
    assert!(error_of(op(OWNER, &OpReads::default(), &abandon)).contains("1940"));
    assert!(error_of(op(0xd0, &OpReads::default(), &recheck)).contains("1940"));
    for k in 1..=7u8 {
        let reads = OpReads { payout: Some(payout(k)), ..OpReads::default() };
        let owner_kind = k == kind::REVENUE || k == kind::SURPLUS;
        assert_eq!(op(OWNER, &reads, &abandon).is_ok(), owner_kind, "abandon kind {k}");
        assert_eq!(op(0xd0, &reads, &recheck).is_ok(), !owner_kind, "recheck kind {k}");
        if owner_kind {
            assert!(error_of(op(0xd0, &reads, &recheck)).contains("1941"));
        } else {
            assert!(error_of(op(OWNER, &reads, &abandon)).contains("1941"));
        }
    }
}

#[test]
fn owner_ops_are_refused_to_anyone_else() {
    let reads = OpReads {
        request: Some(pending(false)),
        payout: Some(payout(kind::REVENUE)),
        own_wallet_balance: Some(20_000_000),
        ..OpReads::default()
    };
    let ops = [
        OpArgs::Respond { request_id: 5, response_hash: [5; 32], signature: None },
        OpArgs::RevokeAttestor,
        OpArgs::WithdrawRevenue { token_amount: 1, tos_amount: 0 },
        OpArgs::RecoverSurplus { amount: 1 },
        OpArgs::AbandonPayout { id: 10 },
    ];
    for args in ops {
        assert!(op(OWNER, &reads, &args).is_ok(), "{}", args.operation().name());
        assert!(error_of(op(BUYER, &reads, &args)).contains("1900"), "{}", args.operation().name());
    }
}

#[test]
fn withdraw_revenue_checks_both_parts() {
    let w = |token_amount, tos_amount| OpArgs::WithdrawRevenue { token_amount, tos_amount };
    let reads = OpReads::default();
    assert!(error_of(op(OWNER, &reads, &w(0, 0))).contains("positive"));
    assert!(error_of(op(OWNER, &reads, &w(10_000_001, 0))).contains("1922"));
    // balance 5 TOS - 0.4 - 0.3 locked - 1 reserve = 3.3 TOS free; revenue 0.8 TOS.
    assert!(op(OWNER, &reads, &w(0, 800_000_000)).is_ok());
    assert!(error_of(op(OWNER, &reads, &w(0, 800_000_001))).contains("1922"));
    let mut poor = view();
    poor.balance = 1_900_000_000;
    let error = error_of(plan_op(&poor, &reads, &basechain(OWNER), 3, &w(0, 200_000_001), None));
    assert!(error.contains("1922"), "{error}");
    let mut full = view();
    full.native.revenue_payouts_in_flight = protocol_constants::MAX_REVENUE_PAYOUTS;
    let error = error_of(plan_op(&full, &reads, &basechain(OWNER), 3, &w(1, 0), None));
    assert!(error.contains("1930"), "{error}");
    // The TOS part alone needs no payout funding.
    assert!(plan_op(&full, &reads, &basechain(OWNER), 3, &w(0, 1), None).is_ok());
    let tos_only = op(OWNER, &reads, &w(0, 1)).unwrap();
    assert_eq!(tos_only.value, 2 * protocol_constants::PAYOUT_GAS_ALLOWANCE);
    let both = op(OWNER, &reads, &w(1, 1)).unwrap();
    assert_eq!(u128::from(both.value), 2 * view().quote.payout_funding);
}

#[test]
fn recover_surplus_is_bounded_by_the_unattributed_balance() {
    // Attributed: 2.5 + 2.5 + 1 + 0.5 + 10 = 16.5 tokens; the wallet holds 20.
    let reads = OpReads { own_wallet_balance: Some(20_000_000), ..OpReads::default() };
    assert!(op(OWNER, &reads, &OpArgs::RecoverSurplus { amount: 3_500_000 }).is_ok());
    let error = error_of(op(OWNER, &reads, &OpArgs::RecoverSurplus { amount: 3_500_001 }));
    assert!(error.contains("1936"), "{error}");
    assert!(
        error_of(op(OWNER, &reads, &OpArgs::RecoverSurplus { amount: 0 })).contains("positive")
    );
    let mut full = view();
    full.native.surplus_payouts_in_flight = protocol_constants::MAX_SURPLUS_PAYOUTS;
    let error = error_of(plan_op(
        &full,
        &reads,
        &basechain(OWNER),
        3,
        &OpArgs::RecoverSurplus { amount: 1 },
        None,
    ));
    assert!(error.contains("1930"), "{error}");
    let undeployed = OpReads::default();
    assert!(
        error_of(op(OWNER, &undeployed, &OpArgs::RecoverSurplus { amount: 1 }))
            .contains("not deployed")
    );
}

#[test]
fn an_explicit_value_below_the_op_minimum_is_refused() {
    let v = view();
    let claim = OpArgs::ClaimRefund { request_id: 5, destination: basechain(0xc0) };
    let minimum = u64::try_from(v.quote.payout_funding).unwrap();
    let ok = plan_op(&v, &OpReads::default(), &basechain(BUYER), 3, &claim, Some(minimum)).unwrap();
    assert_eq!(ok.value, minimum);
    let error =
        error_of(plan_op(&v, &OpReads::default(), &basechain(BUYER), 3, &claim, Some(minimum - 1)));
    assert!(error.contains("1929"), "{error}");
    let error = error_of(plan_op(
        &v,
        &OpReads::default(),
        &basechain(OWNER),
        3,
        &OpArgs::RevokeAttestor,
        Some(0),
    ));
    assert!(error.contains("positive"), "{error}");
}

#[test]
fn respond_and_rotate_follow_the_attestor_state() {
    let attested = OpReads { request: Some(pending(true)), ..OpReads::default() };
    let unsigned = OpArgs::Respond { request_id: 5, response_hash: [5; 32], signature: None };
    assert!(error_of(op(OWNER, &attested, &unsigned)).contains("1911"));
    let signed = OpArgs::Respond {
        request_id: 5,
        response_hash: [5; 32],
        signature: Some(vec![3; contracts::native_registry::NATIVE_REGISTRY_SIGNATURE_BYTES]),
    };
    assert!(op(OWNER, &attested, &signed).is_ok());
    let plain = OpReads { request: Some(pending(false)), ..OpReads::default() };
    assert!(op(OWNER, &plain, &signed).is_err());
    assert!(error_of(op(OWNER, &OpReads::default(), &unsigned)).contains("1913"));
    assert!(
        error_of(op(BUYER, &OpReads::default(), &OpArgs::Expire { request_id: 5 }))
            .contains("1913")
    );

    let key = contracts::native_registry::native_public_key_from_seed(&[7; 32]);
    let mut full = view();
    full.attestor_key_count = protocol_constants::MAX_LIVE_ATTESTOR_KEYS;
    let rotate = OpArgs::RotateAttestorKey { public_key: key };
    let error = error_of(plan_op(&full, &OpReads::default(), &basechain(OWNER), 3, &rotate, None));
    assert!(error.contains("1944"), "{error}");
    let short = OpArgs::RotateAttestorKey { public_key: vec![1; 32] };
    assert!(op(OWNER, &OpReads::default(), &short).is_err());
}

#[test]
fn update_policy_is_checked_as_the_actor_checks_it() {
    let base = PolicyArgs {
        price_per_call: 1,
        storage_fee: 200_000_000,
        cleanup_bounty: 100_000_000,
        response_sla: 3_600,
        refund_claim_window: 3_600,
        active: true,
        open_access: true,
        authorized_caller: None,
        rate_limit_per_day: 0,
        max_token_liability: NO_TOKEN_CAP,
        metadata_hash: [1; 32],
        proof_scheme_hash: [2; 32],
    };
    let plan = |change: &dyn Fn(&mut PolicyArgs)| {
        let mut policy = base.clone();
        change(&mut policy);
        op(OWNER, &OpReads::default(), &OpArgs::UpdatePolicy(Box::new(policy)))
    };
    assert!(plan(&|_| {}).is_ok());
    assert!(error_of(plan(&|p| p.response_sla = 3_599)).contains("1903"));
    assert!(error_of(plan(&|p| p.refund_claim_window = 2_592_001)).contains("1904"));
    assert!(error_of(plan(&|p| p.cleanup_bounty = 99_999_999)).contains("1905"));
    assert!(error_of(plan(&|p| p.storage_fee = 199_999_999)).contains("1906"));
    assert!(error_of(plan(&|p| p.price_per_call = 0)).contains("1902"));
    assert!(error_of(plan(&|p| p.max_token_liability = 0)).contains("1937"));
    assert!(error_of(plan(&|p| p.max_token_liability = NO_TOKEN_CAP + 1)).contains("1937"));
    assert!(plan(&|p| p.open_access = false).is_err());
    // The test build accepts 600-second windows; the release does not.
    let mut test_view = view();
    test_view.profile = ServiceActorTokenCodeProfile::TestProfile;
    let mut short = base.clone();
    short.response_sla = 600;
    short.refund_claim_window = 600;
    let args = OpArgs::UpdatePolicy(Box::new(short));
    assert!(plan_op(&test_view, &OpReads::default(), &basechain(OWNER), 3, &args, None).is_ok());
    assert!(op(OWNER, &OpReads::default(), &args).is_err());
}

#[test]
fn a_wallet_top_up_needs_a_deployed_wallet_and_a_positive_amount() {
    let v = view();
    let error = error_of(plan_top_up(&v, &basechain(OWNER), TopUpTarget::Wallet, 1, false));
    assert!(error.contains("not deployed"), "{error}");
    assert!(plan_top_up(&v, &basechain(OWNER), TopUpTarget::Actor, 0, true).is_err());
    let p = plan_top_up(&v, &basechain(OWNER), TopUpTarget::Wallet, 1, true).unwrap();
    assert_eq!(p.destination, v.own_wallet);
    assert_eq!(p.body, BuilderData::new().into_cell().unwrap());
}

// ---- Arguments ----------------------------------------------------------------------

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    action: TokenAction,
}

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    use clap::Parser;
    Cli::try_parse_from(std::iter::once("service-token").chain(args.iter().copied()))
}

#[test]
fn sender_without_a_wallet_is_for_build_only() {
    let actor = format!("0:{}", "5a".repeat(32));
    let buyer = format!("0:{}", "b0".repeat(32));
    let hash = "33".repeat(32);
    let base =
        ["call", "--address", &actor, "--request-hash", &hash, "--expected-terms-hash", &hash];
    let with = |extra: &[&str]| {
        let mut args: Vec<&str> = base.to_vec();
        args.extend_from_slice(extra);
        parse(&args)
    };
    assert!(with(&["--sender", &buyer, "--build-only"]).is_ok());
    assert!(with(&["--sender", &buyer]).is_err(), "--sender requires --build-only");
    assert!(with(&["--from", "w", "--sender", &buyer, "--build-only"]).is_err());
    assert!(with(&[]).is_err(), "one of --from or --sender is required");
    assert!(with(&["--from", "w"]).is_ok());
    assert!(with(&["--from", "w", "--sender", "-1:00"]).is_err());
    let send = parse(&[
        "send",
        "--operation",
        "withdraw-revenue",
        "--address",
        &actor,
        "--from",
        "w",
        "--token-amount",
        "1329227995784915872903807060280344575",
        "--tos-amount-nanotos",
        "5",
    ]);
    assert!(send.is_ok());
    let top_up = parse(&[
        "top-up",
        "--target",
        "wallet",
        "--address",
        &actor,
        "--from",
        "w",
        "--amount-nanotos",
        "5",
    ]);
    assert!(top_up.is_ok());
}
