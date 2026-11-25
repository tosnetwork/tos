/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! Planner tests for `agent service-token`, and the golden `--build-only`
//! documents under `fixtures/service_actor_token/`. Each case has
//! `<name>.inputs.json` (the state read, the extra reads, the sender and the
//! arguments, in the schema `FixtureInputs` below) and `<name>.out.json` (the
//! exact bytes `--build-only` prints for them). The golden test plans every
//! inputs file it finds and compares the result with its out file. Re-pin
//! with `TOSCTL_UPDATE_GOLDEN=1 cargo test -p commands service_actor_token`.

use super::*;
use chain_block::{AnycastInfo, IBitstring};
use contracts::service_actor_token::{TokenTerms, protocol_constants::NO_TOKEN_CAP};
use serde::{Deserialize, Serialize};

// ---- The fixture schema -----------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureInputs {
    state: StateJson,
    reads: ReadsJson,
    sender: String,
    query_id: u64,
    operation: String,
    arguments: ArgsJson,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateJson {
    actor: String,
    code_profile: String,
    read_at: ReadAt,
    balance: String,
    get_service_data: ServiceDataJson,
    get_terms_hash: String,
    /// pending, refundable, returned, in_flight, withdrawable_revenue.
    get_token_ledger: [String; 5],
    get_native_ledger: NativeLedgerJson,
    /// min_funding_value, admission_gas_allowance, return_budget,
    /// report_tos_amount, outcome_fee_lock, payout_funding.
    get_funding_prices: [String; 6],
    get_accepting_tokens: bool,
    get_attestor_key_count: u32,
    /// Whether the actor's attestor-key store holds the current key.
    current_attestor_key_stored: bool,
    get_asset_route: RouteJson,
    get_own_wallet: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceDataJson {
    owner: String,
    active: bool,
    policy_version: u32,
    price_per_call: String,
    storage_fee: String,
    cleanup_bounty: String,
    response_sla: u32,
    refund_claim_window: u32,
    open_access: bool,
    authorized_caller: Option<String>,
    rate_limit_per_day: u32,
    metadata_hash: String,
    proof_scheme_hash: String,
    attestor_key_id: Option<String>,
    max_token_liability: String,
    next_request_id: u64,
    pending_count: u32,
    live_count: u32,
    next_payout_id: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeLedgerJson {
    withdrawable_revenue: String,
    locked_storage_fees: String,
    locked_outcome_fees: String,
    call_day: u32,
    calls_today: u32,
    revenue_payouts_in_flight: u32,
    returned_count: u32,
    returns_in_flight: u32,
    surplus_payouts_in_flight: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteJson {
    master: String,
    wallet_code_boc: String,
    bridge_config_param: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadsJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config_param_84_entry: Option<AssetJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bridge_wallet_terms: Option<WalletTermsJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config_param_25: Option<ForwardPricesJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sender_token_wallet_balance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    get_caller_live_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    get_caller_returned_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    get_request: Option<RequestJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    get_refund: Option<RefundJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    get_payout: Option<PayoutJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    get_returned: Option<ReturnedJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    own_wallet_balance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    own_wallet_deployed: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetJson {
    status: u8,
    decimals: u8,
    wallet_code_hash: String,
    max_liability_per_actor: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletTermsJson {
    wallet_gas_consumption: String,
    wallet_min_tos_for_storage: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardPricesJson {
    lump_price: u64,
    bit_price: u64,
    cell_price: u64,
    first_frac: u16,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestJson {
    caller: String,
    price: String,
    storage_fee: String,
    cleanup_bounty: String,
    response_deadline: u64,
    refund_claim_deadline: u64,
    policy_version: u32,
    request_hash: String,
    terms_hash: String,
    attestor_key_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefundJson {
    caller: String,
    price: String,
    storage_fee: String,
    cleanup_bounty: String,
    refund_claim_deadline: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayoutJson {
    kind: u8,
    request_id: u64,
    recipient: String,
    requester: String,
    amount: String,
    created_at: u32,
    recipient_wallet: String,
    own_wallet: String,
    outcome_fee_lock: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReturnedJson {
    caller: String,
    amount: String,
    paying: u64,
    return_deadline: u64,
}

/// The command-line arguments, by flag name.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArgsJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_terms_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    forward_tos_nanotos: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wallet_value_nanotos: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tos_amount_nanotos: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    price_per_call_units: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage_fee_nanotos: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleanup_bounty_nanotos: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_sla: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refund_claim_window: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    open_access: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorized_caller: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    clear_authorized_caller: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_limit_per_day: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_token_liability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof_scheme_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    new_attestor_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    amount_nanotos: Option<String>,
}

// ---- From the schema to the planner's inputs ----------------------------------------

fn addr(text: &str) -> MsgAddressInt {
    text.parse().unwrap()
}

fn num<T: std::str::FromStr>(text: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    text.parse().unwrap()
}

fn hash(text: &str) -> [u8; 32] {
    hex::decode(text).unwrap().try_into().unwrap()
}

fn view_from(state: &StateJson) -> ActorView {
    let s = &state.get_service_data;
    let n = &state.get_native_ledger;
    let t = &state.get_token_ledger;
    let q = &state.get_funding_prices;
    let wallet_code = read_single_root_boc(
        base64::engine::general_purpose::STANDARD
            .decode(&state.get_asset_route.wallet_code_boc)
            .unwrap(),
    )
    .unwrap();
    ActorView {
        read_at: state.read_at.clone(),
        actor: addr(&state.actor),
        profile: match state.code_profile.as_str() {
            "release" => ServiceActorTokenCodeProfile::Release,
            "test" => ServiceActorTokenCodeProfile::TestProfile,
            other => panic!("code profile {other}"),
        },
        balance: num(&state.balance),
        data: ServiceActorTokenData {
            owner: addr(&s.owner),
            active: s.active,
            policy_version: s.policy_version,
            price_per_call: num(&s.price_per_call),
            storage_fee: num(&s.storage_fee),
            cleanup_bounty: num(&s.cleanup_bounty),
            response_sla: s.response_sla,
            refund_claim_window: s.refund_claim_window,
            open_access: s.open_access,
            authorized_caller: s.authorized_caller.as_deref().map(addr),
            rate_limit_per_day: s.rate_limit_per_day,
            metadata_hash: hash(&s.metadata_hash),
            proof_scheme_hash: hash(&s.proof_scheme_hash),
            attestor_key_id: s.attestor_key_id.as_deref().map(hash),
            max_token_liability: num(&s.max_token_liability),
            next_request_id: s.next_request_id,
            pending_count: s.pending_count,
            live_count: s.live_count,
            next_payout_id: s.next_payout_id,
        },
        terms_hash: hash(&state.get_terms_hash),
        token: TokenLedger {
            pending: num(&t[0]),
            refundable: num(&t[1]),
            returned: num(&t[2]),
            in_flight: num(&t[3]),
            withdrawable_revenue: num(&t[4]),
        },
        native: NativeLedger {
            withdrawable_revenue: num(&n.withdrawable_revenue),
            locked_storage_fees: num(&n.locked_storage_fees),
            locked_outcome_fees: num(&n.locked_outcome_fees),
            call_day: n.call_day,
            calls_today: n.calls_today,
            revenue_payouts_in_flight: n.revenue_payouts_in_flight,
            returned_count: n.returned_count,
            returns_in_flight: n.returns_in_flight,
            surplus_payouts_in_flight: n.surplus_payouts_in_flight,
        },
        quote: FundingQuote {
            min_funding_value: num(&q[0]),
            admission_gas_allowance: num(&q[1]),
            return_budget: num(&q[2]),
            report_tos_amount: num(&q[3]),
            outcome_fee_lock: num(&q[4]),
            payout_funding: num(&q[5]),
        },
        accepting_tokens: state.get_accepting_tokens,
        attestor_key_count: state.get_attestor_key_count,
        current_key_stored: state.current_attestor_key_stored,
        master: addr(&state.get_asset_route.master),
        wallet_code,
        bridge_config_param: state.get_asset_route.bridge_config_param,
        own_wallet: addr(&state.get_own_wallet),
    }
}

fn call_reads_from(r: &ReadsJson) -> CallReads {
    CallReads {
        asset: r.config_param_84_entry.as_ref().map(|a| RecognizedAsset {
            status: a.status,
            decimals: a.decimals,
            wallet_code_hash: hash(&a.wallet_code_hash),
            max_liability_per_actor: num(&a.max_liability_per_actor),
        }),
        wallet_terms: r
            .bridge_wallet_terms
            .as_ref()
            .map(|w| (num(&w.wallet_gas_consumption), num(&w.wallet_min_tos_for_storage))),
        forward_prices: r.config_param_25.as_ref().map(|p| MsgForwardPrices {
            lump_price: p.lump_price,
            bit_price: p.bit_price,
            cell_price: p.cell_price,
            ihr_price_factor: 0,
            first_frac: p.first_frac,
            next_frac: 0,
        }),
        sender_token_balance: r.sender_token_wallet_balance.as_deref().map(num),
        caller_live: r.get_caller_live_count.unwrap_or(0),
        caller_returned: r.get_caller_returned_count.unwrap_or(0),
    }
}

fn op_reads_from(r: &ReadsJson) -> OpReads {
    OpReads {
        request: r.get_request.as_ref().map(|q| TokenPendingRequest {
            caller: addr(&q.caller),
            price: num(&q.price),
            storage_fee: num(&q.storage_fee),
            cleanup_bounty: num(&q.cleanup_bounty),
            response_deadline: q.response_deadline,
            refund_claim_deadline: q.refund_claim_deadline,
            policy_version: q.policy_version,
            request_hash: hash(&q.request_hash),
            terms_hash: hash(&q.terms_hash),
            attestor_key_id: q.attestor_key_id.as_deref().map(hash),
        }),
        refund: r.get_refund.as_ref().map(|f| TokenRefund {
            caller: addr(&f.caller),
            price: num(&f.price),
            storage_fee: num(&f.storage_fee),
            cleanup_bounty: num(&f.cleanup_bounty),
            refund_claim_deadline: f.refund_claim_deadline,
        }),
        payout: r.get_payout.as_ref().map(|p| PayoutData {
            kind: p.kind,
            request_id: p.request_id,
            recipient: addr(&p.recipient),
            requester: addr(&p.requester),
            amount: num(&p.amount),
            created_at: p.created_at,
            recipient_wallet: addr(&p.recipient_wallet),
            own_wallet: addr(&p.own_wallet),
            outcome_fee_lock: num(&p.outcome_fee_lock),
        }),
        returned: r.get_returned.as_ref().map(|e| ReturnedData {
            caller: addr(&e.caller),
            amount: num(&e.amount),
            paying: e.paying,
            return_deadline: e.return_deadline,
        }),
        own_wallet_balance: r.own_wallet_balance.as_deref().map(num),
        attestor_key: None,
        global_id: None,
    }
}

fn op_args_from(operation: &str, a: &ArgsJson) -> OpArgs {
    let request_id = || a.request_id.unwrap();
    let id = || a.id.unwrap();
    match operation {
        "respond" => OpArgs::Respond {
            request_id: request_id(),
            response_hash: hash(a.response_hash.as_deref().unwrap()),
            signature: None,
        },
        "expire" => OpArgs::Expire { request_id: request_id() },
        "claim-refund" => OpArgs::ClaimRefund {
            request_id: request_id(),
            destination: addr(a.destination.as_deref().unwrap()),
        },
        "sweep-expired-request" => OpArgs::SweepExpiredRequest { request_id: request_id() },
        "update-policy" => OpArgs::UpdatePolicy(Box::new(PolicyChange {
            price_per_call: a.price_per_call_units.as_deref().map(num),
            storage_fee: a.storage_fee_nanotos.as_deref().map(num),
            cleanup_bounty: a.cleanup_bounty_nanotos.as_deref().map(num),
            response_sla: a.response_sla,
            refund_claim_window: a.refund_claim_window,
            active: a.active,
            open_access: a.open_access,
            authorized_caller: match (&a.authorized_caller, a.clear_authorized_caller) {
                (Some(text), _) => Some(Some(addr(text))),
                (None, true) => Some(None),
                (None, false) => None,
            },
            rate_limit_per_day: a.rate_limit_per_day,
            max_token_liability: a.max_token_liability.as_deref().map(num),
            metadata_hash: a.metadata_hash.as_deref().map(hash),
            proof_scheme_hash: a.proof_scheme_hash.as_deref().map(hash),
        })),
        "rotate-attestor-key" => OpArgs::RotateAttestorKey {
            public_key: hex::decode(a.new_attestor_pubkey.as_deref().unwrap()).unwrap(),
        },
        "revoke-attestor" => OpArgs::RevokeAttestor,
        "withdraw-revenue" => OpArgs::WithdrawRevenue {
            token_amount: a.token_amount.as_deref().map(num).unwrap_or(0),
            tos_amount: a.tos_amount_nanotos.as_deref().map(num).unwrap_or(0),
        },
        "claim-returned" => {
            OpArgs::ClaimReturned { id: id(), destination: addr(a.destination.as_deref().unwrap()) }
        }
        "sweep-returned" => OpArgs::SweepReturned { id: id() },
        "recover-surplus" => {
            OpArgs::RecoverSurplus { amount: num(a.token_amount.as_deref().unwrap()) }
        }
        "abandon-payout" => OpArgs::AbandonPayout { id: id() },
        "recheck-payout" => OpArgs::RecheckPayout { id: id() },
        other => panic!("operation {other}"),
    }
}

/// Plans a fixture exactly as the command plans its state read.
fn plan_fixture(f: &FixtureInputs) -> anyhow::Result<Prepared> {
    let view = view_from(&f.state);
    let sender = addr(&f.sender);
    let a = &f.arguments;
    match f.operation.as_str() {
        "call" => plan_call(
            &view,
            &call_reads_from(&f.reads),
            &CallArgs {
                sender,
                query_id: f.query_id,
                request_hash: hash(a.request_hash.as_deref().unwrap()),
                expected_terms_hash: hash(a.expected_terms_hash.as_deref().unwrap()),
                forward_tos_amount: a.forward_tos_nanotos.as_deref().map(num),
                wallet_value: a.wallet_value_nanotos.as_deref().map(num),
            },
        ),
        "top-up-actor" | "top-up-wallet" => plan_top_up(
            &view,
            &sender,
            if f.operation == "top-up-actor" { TopUpTarget::Actor } else { TopUpTarget::Wallet },
            num(a.amount_nanotos.as_deref().unwrap()),
            f.reads.own_wallet_deployed.unwrap_or(false),
        ),
        operation => plan_op(
            &view,
            &op_reads_from(&f.reads),
            &sender,
            f.query_id,
            &op_args_from(operation, a),
            a.amount_nanotos.as_deref().map(num),
        ),
    }
}

// ---- The scenario ---------------------------------------------------------------------

fn basechain(byte: u8) -> MsgAddressInt {
    MsgAddressInt::with_standart(None, 0, [byte; 32].into()).unwrap()
}

fn b(byte: u8) -> String {
    basechain(byte).to_string()
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
const NOW: u32 = 1_800_000_000;

fn terms_hash() -> [u8; 32] {
    TokenTerms {
        policy_version: 2,
        price_per_call: PRICE,
        storage_fee: STORAGE_FEE.into(),
        cleanup_bounty: 100_000_000,
        response_sla: 3_600,
        refund_claim_window: 3_600,
        asset_master: [MASTER; 32],
        asset_wallet_code_hash: wallet_code().repr_hash().inner(),
        metadata_hash: [0x11; 32],
        proof_scheme_hash: [0x22; 32],
        attestor_key_id: None,
    }
    .hash()
    .unwrap()
}

fn own_wallet() -> MsgAddressInt {
    wallet_of(&basechain(ACTOR), &basechain(MASTER), &wallet_code()).unwrap()
}

fn state() -> StateJson {
    StateJson {
        actor: b(ACTOR),
        code_profile: "release".into(),
        read_at: ReadAt { seqno: 4242, root_hash: "ab".repeat(32), gen_utime: NOW },
        balance: "5000000000".into(),
        get_service_data: ServiceDataJson {
            owner: b(OWNER),
            active: true,
            policy_version: 2,
            price_per_call: PRICE.to_string(),
            storage_fee: STORAGE_FEE.to_string(),
            cleanup_bounty: "100000000".into(),
            response_sla: 3_600,
            refund_claim_window: 3_600,
            open_access: true,
            authorized_caller: None,
            rate_limit_per_day: 0,
            metadata_hash: hex::encode([0x11; 32]),
            proof_scheme_hash: hex::encode([0x22; 32]),
            attestor_key_id: None,
            max_token_liability: NO_TOKEN_CAP.to_string(),
            next_request_id: 7,
            pending_count: 1,
            live_count: 2,
            next_payout_id: 12,
        },
        get_terms_hash: hex::encode(terms_hash()),
        get_token_ledger: ["2500000", "2500000", "1000000", "500000", "10000000"].map(String::from),
        get_native_ledger: NativeLedgerJson {
            withdrawable_revenue: "800000000".into(),
            locked_storage_fees: "400000000".into(),
            locked_outcome_fees: "300000000".into(),
            call_day: NOW / SECONDS_PER_DAY,
            calls_today: 3,
            revenue_payouts_in_flight: 1,
            returned_count: 1,
            returns_in_flight: 0,
            surplus_payouts_in_flight: 0,
        },
        get_funding_prices: [
            "1300000000",
            "300000000",
            "1000000000",
            "60000000",
            "150000000",
            "1200000000",
        ]
        .map(String::from),
        get_accepting_tokens: true,
        get_attestor_key_count: 0,
        current_attestor_key_stored: false,
        get_asset_route: RouteJson {
            master: b(MASTER),
            wallet_code_boc: base64::engine::general_purpose::STANDARD
                .encode(write_boc(&wallet_code()).unwrap()),
            bridge_config_param: 79,
        },
        get_own_wallet: own_wallet().to_string(),
    }
}

fn view() -> ActorView {
    view_from(&state())
}

fn call_reads_json() -> ReadsJson {
    ReadsJson {
        config_param_84_entry: Some(AssetJson {
            status: 1,
            decimals: 6,
            wallet_code_hash: hex::encode(wallet_code().repr_hash().as_slice()),
            max_liability_per_actor: "1000000000000".into(),
        }),
        bridge_wallet_terms: Some(WalletTermsJson {
            wallet_gas_consumption: "15000000".into(),
            wallet_min_tos_for_storage: "10000000".into(),
        }),
        config_param_25: Some(ForwardPricesJson {
            lump_price: 400_000,
            bit_price: 26_214_400,
            cell_price: 2_621_440_000,
            first_frac: 21_845,
        }),
        sender_token_wallet_balance: Some("100000000".into()),
        get_caller_live_count: Some(0),
        get_caller_returned_count: Some(0),
        ..ReadsJson::default()
    }
}

fn call_reads() -> CallReads {
    call_reads_from(&call_reads_json())
}

fn call_args() -> CallArgs {
    CallArgs {
        sender: basechain(BUYER),
        query_id: 9,
        request_hash: [0x33; 32],
        expected_terms_hash: terms_hash(),
        forward_tos_amount: None,
        wallet_value: None,
    }
}

fn request_json(attested: bool) -> RequestJson {
    RequestJson {
        caller: b(BUYER),
        price: PRICE.to_string(),
        storage_fee: STORAGE_FEE.to_string(),
        cleanup_bounty: "100000000".into(),
        response_deadline: u64::from(NOW) + 1_800,
        refund_claim_deadline: u64::from(NOW) + 5_400,
        policy_version: 2,
        request_hash: hex::encode([0x33; 32]),
        terms_hash: hex::encode(terms_hash()),
        attestor_key_id: attested.then(|| hex::encode([0x44; 32])),
    }
}

fn refund_json(caller: u8) -> RefundJson {
    RefundJson {
        caller: b(caller),
        price: PRICE.to_string(),
        storage_fee: STORAGE_FEE.to_string(),
        cleanup_bounty: "100000000".into(),
        refund_claim_deadline: u64::from(NOW) + 600,
    }
}

fn returned_json(caller: u8, paying: u64) -> ReturnedJson {
    ReturnedJson {
        caller: b(caller),
        amount: "1000000".into(),
        paying,
        return_deadline: u64::from(NOW) - 60,
    }
}

fn payout_json(kind: u8) -> PayoutJson {
    PayoutJson {
        kind,
        request_id: if kind == kind::REVENUE { 0 } else { 5 },
        recipient: b(BUYER),
        requester: b(BUYER),
        amount: "500000".into(),
        created_at: NOW - protocol_constants::PAYOUT_RECHECK_AGE_SECS - 1,
        recipient_wallet: wallet_of(&basechain(BUYER), &basechain(MASTER), &wallet_code())
            .unwrap()
            .to_string(),
        own_wallet: own_wallet().to_string(),
        outcome_fee_lock: "150000000".into(),
    }
}

fn fixture(
    name: &str,
    sender: u8,
    reads: ReadsJson,
    args: ArgsJson,
    query_id: u64,
) -> (String, FixtureInputs) {
    (
        name.to_owned(),
        FixtureInputs {
            state: state(),
            reads,
            sender: b(sender),
            query_id,
            operation: name.trim_end_matches("-tos-only").to_owned(),
            arguments: args,
        },
    )
}

fn cases() -> Vec<(String, FixtureInputs)> {
    let none = ReadsJson::default;
    let args = ArgsJson::default;
    let key = contracts::native_registry::native_public_key_from_seed(&[7; 32]);
    vec![
        fixture(
            "call",
            BUYER,
            call_reads_json(),
            ArgsJson {
                request_hash: Some(hex::encode([0x33; 32])),
                expected_terms_hash: Some(hex::encode(terms_hash())),
                ..args()
            },
            9,
        ),
        fixture(
            "respond",
            OWNER,
            ReadsJson { get_request: Some(request_json(false)), ..none() },
            ArgsJson {
                request_id: Some(5),
                response_hash: Some(hex::encode([0x55; 32])),
                ..args()
            },
            3,
        ),
        fixture(
            "expire",
            BUYER,
            ReadsJson { get_request: Some(request_json(false)), ..none() },
            ArgsJson { request_id: Some(5), ..args() },
            3,
        ),
        fixture(
            "claim-refund",
            BUYER,
            ReadsJson { get_refund: Some(refund_json(BUYER)), ..none() },
            ArgsJson { request_id: Some(5), destination: Some(b(0xc0)), ..args() },
            3,
        ),
        fixture(
            "sweep-expired-request",
            0xd0,
            ReadsJson { get_refund: Some(refund_json(BUYER)), ..none() },
            ArgsJson { request_id: Some(5), ..args() },
            3,
        ),
        fixture(
            "update-policy",
            OWNER,
            none(),
            ArgsJson {
                price_per_call_units: Some("3000000".into()),
                response_sla: Some(7_200),
                open_access: Some(false),
                authorized_caller: Some(b(BUYER)),
                rate_limit_per_day: Some(100),
                max_token_liability: Some("50000000".into()),
                metadata_hash: Some(hex::encode([0x66; 32])),
                ..args()
            },
            3,
        ),
        fixture(
            "rotate-attestor-key",
            OWNER,
            none(),
            ArgsJson { new_attestor_pubkey: Some(hex::encode(&key)), ..args() },
            3,
        ),
        fixture("revoke-attestor", OWNER, none(), args(), 3),
        fixture(
            "withdraw-revenue",
            OWNER,
            none(),
            ArgsJson {
                token_amount: Some("4000000".into()),
                tos_amount_nanotos: Some("500000000".into()),
                ..args()
            },
            3,
        ),
        fixture(
            "withdraw-revenue-tos-only",
            OWNER,
            none(),
            ArgsJson { tos_amount_nanotos: Some("500000000".into()), ..args() },
            3,
        ),
        fixture(
            "claim-returned",
            BUYER,
            ReadsJson { get_returned: Some(returned_json(BUYER, 0)), ..none() },
            ArgsJson { id: Some(8), destination: Some(b(0xc0)), ..args() },
            3,
        ),
        fixture(
            "sweep-returned",
            0xd0,
            ReadsJson { get_returned: Some(returned_json(BUYER, 0)), ..none() },
            ArgsJson { id: Some(8), ..args() },
            3,
        ),
        fixture(
            "recover-surplus",
            OWNER,
            ReadsJson { own_wallet_balance: Some("20000000".into()), ..none() },
            ArgsJson { token_amount: Some("3000000".into()), ..args() },
            3,
        ),
        fixture(
            "abandon-payout",
            OWNER,
            ReadsJson { get_payout: Some(payout_json(kind::REVENUE)), ..none() },
            ArgsJson { id: Some(10), ..args() },
            3,
        ),
        fixture(
            "recheck-payout",
            0xd0,
            ReadsJson { get_payout: Some(payout_json(kind::REFUND)), ..none() },
            ArgsJson { id: Some(11), ..args() },
            3,
        ),
        fixture(
            "top-up-actor",
            OWNER,
            ReadsJson { own_wallet_deployed: Some(true), ..none() },
            ArgsJson { amount_nanotos: Some("700000000".into()), ..args() },
            0,
        ),
        fixture(
            "top-up-wallet",
            OWNER,
            ReadsJson { own_wallet_deployed: Some(true), ..none() },
            ArgsJson { amount_nanotos: Some("700000000".into()), ..args() },
            0,
        ),
    ]
}

fn fixture_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/nodectl/fixtures/service_actor_token")
}

fn pretty<T: Serialize>(value: &T) -> String {
    format!("{}\n", serde_json::to_string_pretty(value).unwrap())
}

fn error_of(result: anyhow::Result<Prepared>) -> String {
    format!("{:#}", result.expect_err("refused"))
}

// ---- Golden documents ---------------------------------------------------------------

/// Every inputs file in the fixture directory is planned from its own bytes
/// and must give its out file exactly; the in-code cases must be the inputs
/// recorded, and no case may lack its files.
#[test]
fn build_only_documents_equal_their_golden_fixtures() {
    let dir = fixture_dir();
    if std::env::var_os("TOSCTL_UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        for (name, inputs) in cases() {
            let output = format!("{}\n", render(&plan_fixture(&inputs).unwrap().view).unwrap());
            std::fs::write(dir.join(format!("{name}.inputs.json")), pretty(&inputs)).unwrap();
            std::fs::write(dir.join(format!("{name}.out.json")), output).unwrap();
        }
    }
    let mut planned = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        let Some(case) = name.strip_suffix(".inputs.json") else { continue };
        let inputs: FixtureInputs =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let out = std::fs::read_to_string(dir.join(format!("{case}.out.json"))).unwrap();
        let output = format!("{}\n", render(&plan_fixture(&inputs).unwrap().view).unwrap());
        assert_eq!(output, out, "{case}: the document differs from its golden bytes");
        planned += 1;
    }
    let cases = cases();
    assert_eq!(planned, cases.len(), "every case has its files and no file is stale");
    for (name, inputs) in cases {
        let recorded = std::fs::read_to_string(dir.join(format!("{name}.inputs.json"))).unwrap();
        assert_eq!(pretty(&inputs), recorded, "{name}: the recorded inputs differ");
    }
}

/// Every document's body is the SDK builder's output for the recorded
/// arguments, and its BOC and hash are that body's.
#[test]
fn every_document_carries_the_sdk_body() {
    let v = view();
    let forward = 2 * (u128::from(STORAGE_FEE) + v.quote.min_funding_value);
    let key = contracts::native_registry::native_public_key_from_seed(&[7; 32]);
    let expected: Vec<(&str, Cell)> = vec![
        (
            "call",
            Actor::funding_transfer(
                9,
                PRICE,
                &v.actor,
                &basechain(BUYER),
                forward,
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
        (
            "update-policy",
            Actor::update_policy(
                3,
                3_000_000,
                STORAGE_FEE,
                100_000_000,
                7_200,
                3_600,
                true,
                false,
                Some(&basechain(BUYER)),
                &basechain(OWNER),
                100,
                50_000_000,
                [0x66; 32],
                [0x22; 32],
            )
            .unwrap(),
        ),
        ("rotate-attestor-key", Actor::rotate_attestor_key(3, &key).unwrap()),
        ("revoke-attestor", Actor::revoke_attestor(3).unwrap()),
        ("withdraw-revenue", Actor::withdraw_revenue(3, 4_000_000, 500_000_000).unwrap()),
        ("withdraw-revenue-tos-only", Actor::withdraw_revenue(3, 0, 500_000_000).unwrap()),
        ("claim-returned", Actor::claim_returned(3, 8, &basechain(0xc0)).unwrap()),
        ("sweep-returned", Actor::sweep_returned(3, 8).unwrap()),
        ("recover-surplus", Actor::recover_surplus(3, 3_000_000).unwrap()),
        ("abandon-payout", Actor::abandon_payout(3, 10).unwrap()),
        ("recheck-payout", Actor::recheck_payout(3, 11).unwrap()),
        ("top-up-actor", BuilderData::new().into_cell().unwrap()),
        ("top-up-wallet", BuilderData::new().into_cell().unwrap()),
    ];
    let cases = cases();
    assert_eq!(expected.len(), cases.len(), "every case is checked");
    for (name, body) in expected {
        let (_, inputs) = cases.iter().find(|(n, _)| n == name).unwrap();
        let prepared = plan_fixture(inputs).unwrap();
        assert_eq!(prepared.body, body, "{name}");
        let boc =
            base64::engine::general_purpose::STANDARD.decode(&prepared.view.body_boc).unwrap();
        assert_eq!(boc, write_boc(&body).unwrap(), "{name}");
        assert_eq!(prepared.view.body_hash, hex::encode(body.repr_hash().as_slice()), "{name}");
    }
    let wallet = cases.iter().find(|(n, _)| n == "top-up-wallet").unwrap();
    assert_eq!(plan_fixture(&wallet.1).unwrap().destination, own_wallet());
}

/// The document depends on nothing but its inputs: inputs serialized,
/// reparsed and planned again, on another thread, give the same bytes.
#[test]
fn the_document_is_a_function_of_its_inputs() {
    for (name, inputs) in cases() {
        let first = render(&plan_fixture(&inputs).unwrap().view).unwrap();
        let text = serde_json::to_string(&inputs).unwrap();
        let second = std::thread::spawn(move || {
            let reparsed: FixtureInputs = serde_json::from_str(&text).unwrap();
            render(&plan_fixture(&reparsed).unwrap().view).unwrap()
        })
        .join()
        .unwrap();
        assert_eq!(first, second, "{name}");
    }
}

#[test]
fn the_body_boc_is_the_documented_encoding() {
    let (_, inputs) = cases().into_iter().find(|(n, _)| n == "claim-returned").unwrap();
    let boc = base64::engine::general_purpose::STANDARD
        .decode(plan_fixture(&inputs).unwrap().view.body_boc)
        .unwrap();
    assert_eq!(&boc[..4], &[0xb5, 0xee, 0x9c, 0x72]);
    assert_eq!(boc[4], 0x01, "no index, no CRC32C, reference size 1");
    assert_eq!(boc[5], 1, "offset size 1");
    assert_eq!((boc[6], boc[7], boc[8]), (1, 1, 0), "one cell, one root, no absent cells");
}

// ---- The call --------------------------------------------------------------------------

fn independent_wallet_need(forward: u128, body: &Cell) -> u128 {
    // A second computation of the bridge wallet's check for this body: the
    // transfer cell and its token_call reference.
    let token_call = body.reference(0).unwrap();
    let bits = (body.bit_length() + token_call.bit_length()) as u128;
    let fee = 400_000 + ((bits * 26_214_400 + 2 * 2_621_440_000 + 0xffff) >> 16);
    let remaining = fee - ((fee * 21_845) >> 16);
    forward + 2 * (remaining * 3 / 2) + 2 * 15_000_000 + 10_000_000
}

#[test]
fn the_call_goes_to_the_senders_token_wallet_with_the_wallets_need() {
    let p = plan_call(&view(), &call_reads(), &call_args()).unwrap();
    assert_eq!(
        p.destination,
        wallet_of(&basechain(BUYER), &basechain(MASTER), &wallet_code()).unwrap()
    );
    let budget = u128::from(STORAGE_FEE) + view().quote.min_funding_value;
    assert_eq!(p.view.details["minimum_forward"], budget.to_string());
    assert_eq!(p.view.details["forward_tos_amount"], (2 * budget).to_string());
    let need = independent_wallet_need(2 * budget, &p.body);
    assert_eq!(p.view.details["wallet_need"], need.to_string());
    assert_eq!(u128::from(p.value), need + WALLET_VALUE_MARGIN);
    assert!(p.view.bounce);
    // An explicit wallet value must exceed the need, as the wallet requires.
    let mut args = call_args();
    args.wallet_value = Some(u64::try_from(need).unwrap());
    assert!(error_of(plan_call(&view(), &call_reads(), &args)).contains("does not exceed"));
    args.wallet_value = Some(u64::try_from(need + 1).unwrap());
    assert_eq!(u128::from(plan_call(&view(), &call_reads(), &args).unwrap().value), need + 1);
}

#[test]
fn a_forward_below_the_budget_is_refused_and_the_budget_itself_is_accepted() {
    let budget = u128::from(STORAGE_FEE) + view().quote.min_funding_value;
    let mut args = call_args();
    for short in [0, budget - 1] {
        args.forward_tos_amount = Some(short);
        let error = error_of(plan_call(&view(), &call_reads(), &args));
        assert!(error.contains("below the call's budget"), "{error}");
    }
    args.forward_tos_amount = Some(budget);
    let p = plan_call(&view(), &call_reads(), &args).unwrap();
    assert_eq!(p.view.details["forward_tos_amount"], budget.to_string());
}

#[test]
fn a_call_is_refused_while_the_actor_is_not_accepting_tokens() {
    let mut v = view();
    v.accepting_tokens = false;
    let error = error_of(plan_call(&v, &call_reads(), &call_args()));
    assert!(error.contains("not accepting tokens"), "{error}");
}

type Change = dyn Fn(&mut ActorView, &mut CallReads, &mut CallArgs);

fn call_with(change: &Change) -> anyhow::Result<Prepared> {
    let (mut v, mut r, mut a) = (view(), call_reads(), call_args());
    change(&mut v, &mut r, &mut a);
    plan_call(&v, &r, &a)
}

#[test]
fn every_admission_refusal_visible_at_the_read_is_refused_before_signing() {
    use protocol_constants::*;
    let refused = |change: &Change, needle: &str| {
        let error = error_of(call_with(change));
        assert!(error.contains(needle), "expected {needle}: {error}");
    };
    refused(&|v, _, _| v.data.active = false, "1901");
    refused(
        &|v, _, _| {
            v.data.attestor_key_id = Some([0x44; 32]);
            v.attestor_key_count = MAX_LIVE_ATTESTOR_KEYS;
        },
        "1944",
    );
    refused(&|v, _, _| v.bridge_config_param = 80, "1932");
    refused(&|_, r, _| r.asset = None, "1933");
    refused(&|_, r, _| r.asset.as_mut().unwrap().status = 2, "1933");
    refused(&|_, r, _| r.asset.as_mut().unwrap().wallet_code_hash = [9; 32], "1933");
    refused(
        &|_, _, a| a.sender = MsgAddressInt::with_standart(None, -1, [BUYER; 32].into()).unwrap(),
        "1934",
    );
    refused(&|_, _, a| a.sender = anycast(), "1934");
    refused(
        &|v, _, _| {
            v.data.open_access = false;
            v.data.authorized_caller = Some(basechain(0xee));
        },
        "1923",
    );
    refused(&|v, _, _| v.data.live_count = MAX_LIVE_GLOBAL, "1907");
    refused(&|_, r, _| r.caller_live = MAX_LIVE_PER_CALLER, "1908");
    refused(&|v, _, _| v.data.next_request_id = u64::MAX, "1909");
    refused(
        &|v, _, _| {
            v.data.rate_limit_per_day = 3;
            v.read_at.gen_utime = v.native.call_day * SECONDS_PER_DAY + 1_000;
        },
        "1924",
    );
    refused(&|v, _, _| v.native.returned_count = MAX_RETURNED_GLOBAL, "1935");
    refused(&|_, r, _| r.caller_returned = MAX_RETURNED_PER_CALLER, "1935");
    refused(&|_, r, _| r.asset.as_mut().unwrap().max_liability_per_actor = 8_999_999, "1937");
    refused(&|v, _, _| v.data.max_token_liability = 8_999_999, "1937");
    refused(&|_, _, a| a.expected_terms_hash = [0; 32], "1926");
    refused(&|v, _, _| v.balance = 1_699_999_999, "1928");
    refused(&|_, r, _| r.sender_token_balance = Some(PRICE - 1), "below the price");
    refused(&|_, r, _| r.sender_token_balance = None, "no token wallet");
    refused(&|_, r, _| r.wallet_terms = None, "negative slot are absent");
    refused(&|_, r, _| r.forward_prices = None, "ConfigParam 25");

    // The boundaries are admitted: the cap exactly, the backing exactly, a
    // stored attestor key while the store is full, one call left today, and
    // yesterday's count.
    let admitted = |change: &Change| call_with(change).unwrap();
    admitted(&|_, r, _| r.asset.as_mut().unwrap().max_liability_per_actor = 9_000_000);
    admitted(&|v, _, _| v.balance = 1_700_000_000);
    admitted(&|v, _, _| {
        v.data.attestor_key_id = Some([0x44; 32]);
        v.attestor_key_count = MAX_LIVE_ATTESTOR_KEYS;
        v.current_key_stored = true;
    });
    admitted(&|v, _, _| v.data.rate_limit_per_day = 4);
    admitted(&|_, r, _| r.caller_returned = MAX_RETURNED_PER_CALLER - 1);
    admitted(&|v, _, _| {
        v.data.rate_limit_per_day = 3;
        v.native.call_day -= 1;
    });
    // At the end of the day the limit is only a warning.
    let p = admitted(&|v, _, _| {
        v.data.rate_limit_per_day = 3;
        v.read_at.gen_utime = (v.native.call_day + 1) * SECONDS_PER_DAY - 60;
    });
    assert!(p.warnings.iter().any(|w| w.contains("1924")), "{:?}", p.warnings);
}

// ---- Operations ---------------------------------------------------------------------

fn op(sender: u8, reads: &OpReads, args: &OpArgs) -> anyhow::Result<Prepared> {
    plan_op(&view(), reads, &basechain(sender), 3, args, None)
}

fn reads(json: ReadsJson) -> OpReads {
    op_reads_from(&json)
}

fn anycast() -> MsgAddressInt {
    let pfx = AnycastInfo::with_rewrite_pfx(SliceData::new(vec![0b1010_0000, 0x80])).unwrap();
    MsgAddressInt::with_standart(Some(pfx), 0, [0x77; 32].into()).unwrap()
}

#[test]
fn an_invalid_destination_is_refused_for_claim_refund_and_claim_returned() {
    let refund = reads(ReadsJson { get_refund: Some(refund_json(BUYER)), ..Default::default() });
    let entry =
        reads(ReadsJson { get_returned: Some(returned_json(BUYER, 0)), ..Default::default() });
    let invalid = [
        ("the actor", basechain(ACTOR)),
        ("workchain -1", MsgAddressInt::with_standart(None, -1, [0x77; 32].into()).unwrap()),
        ("workchain 7", MsgAddressInt::with_standart(None, 7, [0x77; 32].into()).unwrap()),
        ("anycast", anycast()),
        ("addr_var", MsgAddressInt::with_variant(None, 0, SliceData::new(vec![0x77; 33])).unwrap()),
    ];
    for (name, destination) in invalid {
        let claim = OpArgs::ClaimRefund { request_id: 5, destination: destination.clone() };
        let error = error_of(op(BUYER, &refund, &claim));
        assert!(error.contains("1934"), "claim-refund to {name}: {error}");
        let claim = OpArgs::ClaimReturned { id: 8, destination };
        let error = error_of(op(BUYER, &entry, &claim));
        assert!(error.contains("1934"), "claim-returned to {name}: {error}");
    }
    let masterchain_buyer = MsgAddressInt::with_standart(None, -1, [BUYER; 32].into()).unwrap();
    let claim = OpArgs::ClaimReturned { id: 8, destination: basechain(0xc0) };
    let error = error_of(plan_op(&view(), &entry, &masterchain_buyer, 3, &claim, None));
    assert!(error.contains("1934"), "{error}");
}

#[test]
fn claim_refund_and_sweep_read_the_refund_and_the_request() {
    let claim = OpArgs::ClaimRefund { request_id: 5, destination: basechain(0xc0) };
    assert!(error_of(op(BUYER, &OpReads::default(), &claim)).contains("1917"));
    let other = reads(ReadsJson { get_refund: Some(refund_json(0xee)), ..Default::default() });
    assert!(error_of(op(BUYER, &other, &claim)).contains("1918"));
    let mut late = refund_json(BUYER);
    late.refund_claim_deadline = u64::from(NOW);
    let late = reads(ReadsJson { get_refund: Some(late), ..Default::default() });
    assert!(error_of(op(BUYER, &late, &claim)).contains("1916"));

    let sweep = OpArgs::SweepExpiredRequest { request_id: 5 };
    assert!(error_of(op(0xd0, &OpReads::default(), &sweep)).contains("1920"));
    let pending = reads(ReadsJson { get_request: Some(request_json(false)), ..Default::default() });
    let p = op(0xd0, &pending, &sweep).unwrap();
    assert!(p.warnings.iter().any(|w| w.contains("1919")), "{:?}", p.warnings);
}

#[test]
fn returned_entry_ops_check_existence_ownership_and_the_payout_in_flight() {
    let claim = OpArgs::ClaimReturned { id: 8, destination: basechain(0xc0) };
    let sweep = OpArgs::SweepReturned { id: 8 };
    assert!(error_of(op(BUYER, &OpReads::default(), &claim)).contains("1931"));
    assert!(error_of(op(0xd0, &OpReads::default(), &sweep)).contains("1931"));
    let paying =
        reads(ReadsJson { get_returned: Some(returned_json(BUYER, 13)), ..Default::default() });
    assert!(error_of(op(BUYER, &paying, &claim)).contains("1930"));
    assert!(error_of(op(0xd0, &paying, &sweep)).contains("1930"));
    let other =
        reads(ReadsJson { get_returned: Some(returned_json(0xee, 0)), ..Default::default() });
    assert!(error_of(op(BUYER, &other, &claim)).contains("1918"));
    let p = op(0xd0, &other, &sweep).unwrap();
    assert_eq!(p.view.details["recipient"], b(0xee));
    let mut early = returned_json(0xee, 0);
    early.return_deadline = u64::from(NOW) + 60;
    let early = reads(ReadsJson { get_returned: Some(early), ..Default::default() });
    assert!(op(0xd0, &early, &sweep).unwrap().warnings.iter().any(|w| w.contains("1919")));
}

#[test]
fn abandon_and_recheck_take_only_their_own_kinds() {
    let abandon = OpArgs::AbandonPayout { id: 10 };
    let recheck = OpArgs::RecheckPayout { id: 10 };
    assert!(error_of(op(OWNER, &OpReads::default(), &abandon)).contains("1940"));
    assert!(error_of(op(0xd0, &OpReads::default(), &recheck)).contains("1940"));
    for k in 1..=7u8 {
        let r = reads(ReadsJson { get_payout: Some(payout_json(k)), ..Default::default() });
        let owner_kind = k == kind::REVENUE || k == kind::SURPLUS;
        assert_eq!(op(OWNER, &r, &abandon).is_ok(), owner_kind, "abandon kind {k}");
        assert_eq!(op(0xd0, &r, &recheck).is_ok(), !owner_kind, "recheck kind {k}");
        let refused = if owner_kind { op(0xd0, &r, &recheck) } else { op(OWNER, &r, &abandon) };
        assert!(error_of(refused).contains("1941"));
    }
    let mut young = payout_json(kind::REFUND);
    young.created_at = NOW;
    let young = reads(ReadsJson { get_payout: Some(young), ..Default::default() });
    assert!(op(0xd0, &young, &recheck).unwrap().warnings.iter().any(|w| w.contains("1942")));
}

#[test]
fn owner_ops_are_refused_to_anyone_else() {
    let r = reads(ReadsJson {
        get_request: Some(request_json(false)),
        get_payout: Some(payout_json(kind::REVENUE)),
        own_wallet_balance: Some("20000000".into()),
        ..Default::default()
    });
    let ops = [
        OpArgs::Respond { request_id: 5, response_hash: [5; 32], signature: None },
        OpArgs::UpdatePolicy(Box::default()),
        OpArgs::RevokeAttestor,
        OpArgs::WithdrawRevenue { token_amount: 1, tos_amount: 0 },
        OpArgs::RecoverSurplus { amount: 1 },
        OpArgs::AbandonPayout { id: 10 },
    ];
    for args in ops {
        assert!(op(OWNER, &r, &args).is_ok(), "{}", args.operation().name());
        assert!(error_of(op(BUYER, &r, &args)).contains("1900"), "{}", args.operation().name());
    }
}

#[test]
fn withdraw_revenue_checks_both_parts_and_the_backing() {
    let w = |token_amount, tos_amount| OpArgs::WithdrawRevenue { token_amount, tos_amount };
    let none = OpReads::default();
    let owner = basechain(OWNER);
    assert!(error_of(op(OWNER, &none, &w(0, 0))).contains("positive"));
    assert!(error_of(op(OWNER, &none, &w(10_000_001, 0))).contains("1922"));
    // 5 TOS - 0.4 - 0.3 locked - 1 reserve = 3.3 TOS free; revenue 0.8 TOS.
    assert!(op(OWNER, &none, &w(0, 800_000_000)).is_ok());
    assert!(error_of(op(OWNER, &none, &w(0, 800_000_001))).contains("1922"));
    let mut poor = view();
    poor.balance = 1_900_000_000;
    let error = error_of(plan_op(&poor, &none, &owner, 3, &w(0, 200_000_001), None));
    assert!(error.contains("1922"), "{error}");
    // Below the locks and the reserve, any withdrawal is refused.
    let mut short = view();
    short.balance = 1_699_999_999;
    for (token, tos) in [(1, 0), (0, 1)] {
        let error = error_of(plan_op(&short, &none, &owner, 3, &w(token, tos), None));
        assert!(error.contains("1922") && error.contains("operating reserve"), "{error}");
    }
    short.balance = 1_700_000_000;
    assert!(plan_op(&short, &none, &owner, 3, &w(1, 0), None).is_ok());
    let mut full = view();
    full.native.revenue_payouts_in_flight = protocol_constants::MAX_REVENUE_PAYOUTS;
    let error = error_of(plan_op(&full, &none, &owner, 3, &w(1, 0), None));
    assert!(error.contains("1930"), "{error}");
    assert!(plan_op(&full, &none, &owner, 3, &w(0, 1), None).is_ok());
    assert_eq!(
        op(OWNER, &none, &w(0, 1)).unwrap().value,
        2 * protocol_constants::PAYOUT_GAS_ALLOWANCE
    );
    assert_eq!(
        u128::from(op(OWNER, &none, &w(1, 1)).unwrap().value),
        2 * view().quote.payout_funding
    );
}

#[test]
fn recover_surplus_is_bounded_by_the_unattributed_balance() {
    // Attributed: 2.5 + 2.5 + 1 + 0.5 + 10 = 16.5 tokens; the wallet holds 20.
    let r = reads(ReadsJson { own_wallet_balance: Some("20000000".into()), ..Default::default() });
    assert!(op(OWNER, &r, &OpArgs::RecoverSurplus { amount: 3_500_000 }).is_ok());
    let error = error_of(op(OWNER, &r, &OpArgs::RecoverSurplus { amount: 3_500_001 }));
    assert!(error.contains("1936"), "{error}");
    assert!(error_of(op(OWNER, &r, &OpArgs::RecoverSurplus { amount: 0 })).contains("positive"));
    let mut full = view();
    full.native.surplus_payouts_in_flight = protocol_constants::MAX_SURPLUS_PAYOUTS;
    let one = OpArgs::RecoverSurplus { amount: 1 };
    assert!(error_of(plan_op(&full, &r, &basechain(OWNER), 3, &one, None)).contains("1930"));
    assert!(error_of(op(OWNER, &OpReads::default(), &one)).contains("not deployed"));
}

#[test]
fn an_explicit_value_below_the_op_minimum_is_refused() {
    let v = view();
    let r = reads(ReadsJson { get_refund: Some(refund_json(BUYER)), ..Default::default() });
    let claim = OpArgs::ClaimRefund { request_id: 5, destination: basechain(0xc0) };
    let minimum = u64::try_from(v.quote.payout_funding).unwrap();
    let ok = plan_op(&v, &r, &basechain(BUYER), 3, &claim, Some(minimum)).unwrap();
    assert_eq!(ok.value, minimum);
    let error = error_of(plan_op(&v, &r, &basechain(BUYER), 3, &claim, Some(minimum - 1)));
    assert!(error.contains("1929"), "{error}");
    let revoke = OpArgs::RevokeAttestor;
    let error = error_of(plan_op(&v, &r, &basechain(OWNER), 3, &revoke, Some(0)));
    assert!(error.contains("positive"), "{error}");
}

#[test]
fn respond_checks_the_window_and_verifies_a_given_signature() {
    let seed = [9u8; 32];
    let public_key = contracts::native_registry::native_public_key_from_seed(&seed);
    let key_id = contracts::native_registry::controller_key_id(&public_key).unwrap();
    let mut request = request_json(true);
    request.attestor_key_id = Some(hex::encode(key_id));
    let mut attested = reads(ReadsJson { get_request: Some(request), ..Default::default() });
    attested.attestor_key = Some(public_key.clone());
    attested.global_id = Some(7);
    let pending = attested.request.clone().unwrap();
    let domain = Actor::respond_domain_hash(7, &basechain(ACTOR), 5, &pending, [5; 32]).unwrap();
    let (_, signature) = contracts::service_actor::sign_service_response(&seed, &domain).unwrap();

    let signed = |signature: Vec<u8>| OpArgs::Respond {
        request_id: 5,
        response_hash: [5; 32],
        signature: Some(signature),
    };
    assert!(op(OWNER, &attested, &signed(signature.clone())).is_ok());
    // Another network's domain does not verify; nor does another key.
    let other = Actor::respond_domain_hash(8, &basechain(ACTOR), 5, &pending, [5; 32]).unwrap();
    let (_, foreign) = contracts::service_actor::sign_service_response(&seed, &other).unwrap();
    assert!(error_of(op(OWNER, &attested, &signed(foreign))).contains("1911"));
    let mut wrong_key = attested.clone();
    wrong_key.attestor_key =
        Some(contracts::native_registry::native_public_key_from_seed(&[8; 32]));
    assert!(error_of(op(OWNER, &wrong_key, &signed(signature.clone()))).contains("key id"));

    let unsigned = OpArgs::Respond { request_id: 5, response_hash: [5; 32], signature: None };
    assert!(error_of(op(OWNER, &attested, &unsigned)).contains("1911"));
    let plain = reads(ReadsJson { get_request: Some(request_json(false)), ..Default::default() });
    assert!(op(OWNER, &plain, &signed(signature)).is_err());
    assert!(error_of(op(OWNER, &OpReads::default(), &unsigned)).contains("1913"));
    let mut closed = request_json(false);
    closed.response_deadline = u64::from(NOW);
    let closed = reads(ReadsJson { get_request: Some(closed), ..Default::default() });
    assert!(error_of(op(OWNER, &closed, &unsigned)).contains("1912"));

    let expire = OpArgs::Expire { request_id: 5 };
    assert!(error_of(op(BUYER, &OpReads::default(), &expire)).contains("1913"));
    assert!(op(BUYER, &plain, &expire).unwrap().warnings.iter().any(|w| w.contains("1914")));
    let mut over = request_json(false);
    over.refund_claim_deadline = u64::from(NOW);
    over.response_deadline = u64::from(NOW) - 10;
    let over = reads(ReadsJson { get_request: Some(over), ..Default::default() });
    assert!(error_of(op(BUYER, &over, &expire)).contains("1915"));
}

#[test]
fn rotation_is_refused_at_the_key_cap() {
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
fn update_policy_keeps_unset_fields_and_is_checked_as_the_actor_checks_it() {
    let plan = |change: PolicyChange| {
        op(OWNER, &OpReads::default(), &OpArgs::UpdatePolicy(Box::new(change)))
    };
    // Nothing given: the current policy, every field shown.
    let p = plan(PolicyChange::default()).unwrap();
    let d = &p.view.details;
    assert_eq!(d["price_per_call"], PRICE.to_string());
    assert_eq!(d["storage_fee"], STORAGE_FEE.to_string());
    assert_eq!(d["open_access"], "true");
    assert_eq!(d["authorized_caller"], "");
    assert_eq!(d["max_token_liability"], NO_TOKEN_CAP.to_string());
    assert_eq!(d["metadata_hash"], hex::encode([0x11; 32]));
    assert_eq!(d.len(), 13);
    // The actor accepts a policy that admits nobody; so does the command.
    assert!(plan(PolicyChange { open_access: Some(false), ..Default::default() }).is_ok());
    let error = |change: PolicyChange| error_of(plan(change));
    let d = PolicyChange::default;
    assert!(error(PolicyChange { response_sla: Some(3_599), ..d() }).contains("1903"));
    assert!(error(PolicyChange { refund_claim_window: Some(2_592_001), ..d() }).contains("1904"));
    assert!(error(PolicyChange { cleanup_bounty: Some(99_999_999), ..d() }).contains("1905"));
    assert!(error(PolicyChange { storage_fee: Some(199_999_999), ..d() }).contains("1906"));
    assert!(error(PolicyChange { price_per_call: Some(0), ..d() }).contains("1902"));
    assert!(error(PolicyChange { max_token_liability: Some(0), ..d() }).contains("1937"));
    let off_chain = MsgAddressInt::with_standart(None, -1, [3; 32].into()).unwrap();
    assert!(
        error(PolicyChange { authorized_caller: Some(Some(off_chain)), ..d() })
            .contains("never admit")
    );
    // The test build accepts 600-second windows; the release does not.
    let short = PolicyChange { response_sla: Some(600), refund_claim_window: Some(600), ..d() };
    let mut test_view = view();
    test_view.profile = ServiceActorTokenCodeProfile::TestProfile;
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
}

// ---- The reader -------------------------------------------------------------------

fn block(seqno: u32, root: u8) -> BlockIdExt {
    serde_json::from_value(serde_json::json!({
        "@type": "ton.blockIdExt",
        "workchain": -1,
        "shard": "-9223372036854775808",
        "seqno": seqno,
        "root_hash": base64::engine::general_purpose::STANDARD.encode([root; 32]),
        "file_hash": base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
    }))
    .unwrap()
}

#[test]
fn a_read_at_another_block_is_refused() {
    let anchor = block(10, 1);
    assert!(check_same_block(&anchor, "x", &block(10, 1)).is_ok());
    assert!(check_same_block(&anchor, "x", &block(11, 1)).is_err());
    assert!(check_same_block(&anchor, "x", &block(10, 2)).is_err());
    let mut shard = block(10, 1);
    shard.workchain = 0;
    assert!(check_same_block(&anchor, "x", &shard).is_err());
}

#[test]
fn the_rpc_stack_is_reversed_into_return_order() {
    let entry = |n: u64| RPCStackEntry::from(contracts::stack_utils::u64_to_stack_entry(n));
    // The endpoint lists the top of the stack first: the last return value.
    let stack = stack_from_rpc(vec![entry(3), entry(2), entry(1)]);
    assert_eq!((stack.u64(0).unwrap(), stack.u64(1).unwrap(), stack.u64(2).unwrap()), (1, 2, 3));
}

#[test]
fn bridge_wallet_terms_are_read_as_the_wallet_reads_them() {
    let mut prices = BuilderData::new();
    for value in [1u64, 2, 10_000_000, 15_000_000, 5, 6] {
        chain_block::Serializable::write_to(&chain_block::Coins::new(value), &mut prices).unwrap();
    }
    let param = |trailing: bool| {
        let mut p = BuilderData::new();
        p.append_u8(0x01).unwrap();
        p.append_u256(&[1; 32]).unwrap();
        p.append_u256(&[2; 32]).unwrap();
        p.append_bit_zero().unwrap(); // no oracles
        p.append_u8(0).unwrap();
        p.checked_append_reference(prices.clone().into_cell().unwrap()).unwrap();
        if trailing {
            p.append_u256(&[3; 32]).unwrap();
        }
        p.into_cell().unwrap()
    };
    assert_eq!(Actor::bridge_wallet_terms(&param(false)).unwrap(), (15_000_000, 10_000_000));
    assert_eq!(Actor::bridge_wallet_terms(&param(true)).unwrap(), (15_000_000, 10_000_000));
    assert!(Actor::bridge_wallet_terms(&BuilderData::new().into_cell().unwrap()).is_err());
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
    let actor = b(ACTOR);
    let buyer = b(BUYER);
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
    let update = |extra: &[&str]| {
        let mut args =
            vec!["send", "--operation", "update-policy", "--address", &actor, "--from", "w"];
        args.extend_from_slice(extra);
        parse(&args)
    };
    assert!(update(&["--open-access", "false", "--clear-authorized-caller"]).is_ok());
    assert!(update(&["--authorized-caller", &buyer, "--clear-authorized-caller"]).is_err());
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
