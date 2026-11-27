/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! A token-rail Service Actor on the token bridge's sandbox network: the bridge,
//! a minter that has minted to every user, the users' wallets and the actor's
//! own wallet, all running the real contracts. Every message is delivered one
//! at a time, so a test can drop, hold, reorder or forge any of them, and after
//! every delivered message the actor's token invariant is checked:
//!
//!   wallet balance + tokens of live payouts that have left the wallet
//!     >= pending + refundable + returned + in_flight + token revenue
//!
//! The difference is surplus, which is never negative. The bridge model of
//! token_bridge/model.rs checks supply and balance conservation as well.

#![allow(dead_code)]

use std::collections::BTreeMap;

use chain_block::{
    Cell, Coins, ConfigParamEnum, Deserializable, IBitstring, Message, MsgAddressInt, Serializable,
    SettlementAsset, SettlementAssetOrigin, SettlementAssetOriginKind, SettlementAssetStatus,
    SettlementAssets, SliceData, StateInit, UInt256,
};
use contracts::service_actor_token::{
    AssetRoute, BalanceLog, FundingLog, NativeLedger, OutcomeLog, PayoutData, ReturnedData,
    ServiceActorTokenCodeProfile, ServiceActorTokenContract, ServiceActorTokenInit, TokenLedger,
    TokenRequestSnapshot, decode_balance_log, decode_funding_log, decode_outcome_log,
    decode_request_snapshot, log, protocol_constants,
};
use tos_sandbox::{MessageBuilder, Treasury};
use tos_vm::stack::StackItem;

use crate::harness::*;

pub const PRICE: u128 = 1_000;
pub const MINTED: u128 = 1_000_000;
pub const STORAGE_FEE: u64 = 200_000_000;
pub const BOUNTY: u64 = 100_000_000;
pub const SLA: u32 = 3_600;
pub const WINDOW: u32 = 3_600;
pub const ACTOR_FUNDING: u64 = 20 * TOS;
pub const DAY: u32 = 86_400;
pub const MONTH: u32 = 2_592_000;

/// The actor's source, compiled by the release tooling and embedded in the SDK.
pub fn actor_source() -> std::path::PathBuf {
    repo_root().join("crypto/smartcont/service-actor-token-code.fc")
}

/// A constant as the actor's source declares it.
pub fn actor_constant(name: &str) -> i128 {
    let source = std::fs::read_to_string(actor_source()).expect("the actor source");
    let prefix = format!("const int {name} = ");
    let line = source
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("the actor declares {name}"));
    let value = line[prefix.len()..].split(';').next().expect("a value").trim();
    if let Some(hex) = value.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).expect("a hex constant")
    } else {
        value.parse().expect("a constant")
    }
}

/// A test-only build of the actor, compiled after `edit` rewrote its source.
pub fn actor_variant(tag: &str, edit: impl Fn(String) -> String) -> Cell {
    let stage = std::env::temp_dir().join(format!(
        "tos-service-actor-token-variant-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&stage).expect("a stage");
    let smartcont = repo_root().join("crypto/smartcont");
    for name in ["stdlib.fc", "signing-domain.fc", "pq.fc", "pq-bytes.fc"] {
        std::fs::copy(smartcont.join(name), stage.join(name)).expect("a staged include");
    }
    let source = std::fs::read_to_string(actor_source()).expect("the actor source");
    let edited = edit(source.clone());
    assert_ne!(edited, source, "the variant {tag} changes the actor");
    let path = stage.join("service-actor-token-code.fc");
    std::fs::write(&path, edited).expect("the variant source");
    let code = tos_sandbox::compile_func(&[stage.join("stdlib.fc"), path])
        .unwrap_or_else(|e| panic!("the actor variant {tag} compiles: {e}"));
    let _ = std::fs::remove_dir_all(&stage);
    code
}

#[derive(Clone, Debug)]
pub struct Options {
    /// Primary source token byte and decimals for this sandbox world.
    pub asset: (u8, u8),
    pub profile: ServiceActorTokenCodeProfile,
    pub code: Option<Cell>,
    pub price: u128,
    pub storage_fee: u64,
    pub cleanup_bounty: u64,
    pub response_sla: u32,
    pub refund_claim_window: u32,
    pub open_access: bool,
    pub authorized_caller: Option<usize>,
    pub rate_limit_per_day: u32,
    pub max_token_liability: u128,
    pub attestor_pubkey: Option<Vec<u8>>,
    /// ConfigParam 84's status for the actor's master, or no record.
    pub status: Option<SettlementAssetStatus>,
    pub asset_cap: u128,
    pub wallet_code_hash: Option<[u8; 32]>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            asset: (0x5a, 18),
            profile: ServiceActorTokenCodeProfile::Release,
            code: None,
            price: PRICE,
            storage_fee: STORAGE_FEE,
            cleanup_bounty: BOUNTY,
            response_sla: SLA,
            refund_claim_window: WINDOW,
            open_access: true,
            authorized_caller: None,
            rate_limit_per_day: 0,
            max_token_liability: protocol_constants::NO_TOKEN_CAP,
            attestor_pubkey: None,
            status: Some(SettlementAssetStatus::Active),
            asset_cap: protocol_constants::NO_TOKEN_CAP,
            wallet_code_hash: None,
        }
    }
}

pub struct World {
    pub net: Net,
    pub owner: MsgAddressInt,
    pub actor: MsgAddressInt,
    pub code: Cell,
    pub init: ServiceActorTokenInit,
    /// Live payouts whose tokens have left the actor's wallet.
    pub out_of_wallet: BTreeMap<u64, u128>,
    /// The most gas each kind of actor transaction used.
    pub gas: BTreeMap<String, u64>,
    pub checking: bool,
    pub steps: usize,
}

impl World {
    pub fn new() -> Self {
        Self::with(Options::default())
    }

    pub fn with(options: Options) -> Self {
        Self::with_data(options, |data| data)
    }

    /// Deploys with the data rewritten by `rewrite`, as a deployer controlling
    /// its own StateInit can.
    pub fn with_data(options: Options, rewrite: impl FnOnce(Cell) -> Cell) -> Self {
        let mut net = Net::with_asset(options.asset.0, options.asset.1);
        let owner = net.bc.treasury("token-actor-owner", 10_000 * TOS).expect("an owner");
        let owner = owner.address().clone();
        for i in 0..net.users.len() {
            let user = net.user(i);
            net.swap_to(&user, MINTED);
        }
        let route = AssetRoute {
            master: net.minter(),
            wallet_code: codes().wallet.clone(),
            bridge_config_param: CONFIG_PARAM,
        };
        let init = ServiceActorTokenInit {
            owner: owner.clone(),
            authorized_caller: options.authorized_caller.map(|i| net.user(i)),
            open_access: options.open_access,
            price_per_call: options.price,
            storage_fee: options.storage_fee,
            cleanup_bounty: options.cleanup_bounty,
            rate_limit_per_day: options.rate_limit_per_day,
            response_sla: options.response_sla,
            refund_claim_window: options.refund_claim_window,
            metadata_hash: [0x11; 32],
            proof_scheme_hash: [0x22; 32],
            attestor_pubkey: options.attestor_pubkey.clone(),
            max_token_liability: options.max_token_liability,
            route,
        };
        let code = match &options.code {
            Some(code) => code.clone(),
            None => {
                ServiceActorTokenContract::code_for(options.profile).expect("the embedded code")
            }
        };
        let data = rewrite(ServiceActorTokenContract::build_data(&init).expect("deploy data"));
        let state_init = StateInit::with_code_and_data(code.clone(), data);
        let actor = MsgAddressInt::with_params(0, state_init.serialize().unwrap().repr_hash())
            .expect("an actor address");
        let deploy = MessageBuilder::internal(&owner, &actor, ACTOR_FUNDING)
            .bounce(false)
            .state_init(state_init)
            .build();
        let mut world = Self {
            net,
            owner,
            actor,
            code,
            init,
            out_of_wallet: BTreeMap::new(),
            gas: BTreeMap::new(),
            checking: true,
            steps: 0,
        };
        world.net.send(deploy);
        world.recognize(options.status, options.asset_cap, options.wallet_code_hash);
        world
    }

    // ---- recognition -----------------------------------------------------------------

    pub fn asset_record(
        &self,
        status: SettlementAssetStatus,
        cap: u128,
        wallet_code_hash: Option<[u8; 32]>,
    ) -> SettlementAsset {
        SettlementAsset {
            status,
            decimals: self.net.primary_asset.1,
            minter_code_hash: codes().minter.repr_hash(),
            wallet_code_hash: wallet_code_hash
                .map(UInt256::from)
                .unwrap_or_else(|| codes().wallet.repr_hash()),
            max_liability_per_actor: cap.to_string().parse::<Coins>().expect("a cap"),
            origin: SettlementAssetOrigin {
                kind: SettlementAssetOriginKind::TokenBridge,
                bridge_address: UInt256::from_slice(&account_hash(&self.net.bridge)),
                source_chain_id: CHAIN_ID,
                source_token: [self.net.primary_asset.0; 20],
            },
        }
    }

    /// ConfigParam 84 with the actor's master at `status`, or without it.
    pub fn recognize(
        &mut self,
        status: Option<SettlementAssetStatus>,
        cap: u128,
        wallet_code_hash: Option<[u8; 32]>,
    ) {
        let mut assets = SettlementAssets::new();
        if let Some(status) = status {
            let master = UInt256::from_slice(&account_hash(&self.net.minter()));
            assets.insert(master, self.asset_record(status, cap, wallet_code_hash)).unwrap();
        }
        self.set_param_84(Some(assets.to_cell().unwrap()));
    }

    /// ConfigParam 84 with `others` further records, all keyed below the
    /// actor's master, so the master is the last entry a lookup reaches.
    pub fn recognize_among(&mut self, others: usize) {
        let master = account_hash(&self.net.minter());
        let record = self.asset_record(
            SettlementAssetStatus::Active,
            protocol_constants::NO_TOKEN_CAP,
            None,
        );
        let mut assets = SettlementAssets::new();
        for i in 0..others {
            let mut key = [0u8; 32];
            key[31] = i as u8 + 1;
            assert!(key.as_slice() < master.as_slice(), "the master is the last key");
            assets.insert(UInt256::from(key), record.clone()).unwrap();
        }
        assets.insert(UInt256::from_slice(&master), record).unwrap();
        self.set_param_84(Some(assets.to_cell().unwrap()));
    }

    /// Sets ConfigParam 84 to `value` exactly, or removes it.
    pub fn set_param_84(&mut self, value: Option<Cell>) {
        let mut config = self.net.bc.config_params().clone();
        let mut key = chain_block::BuilderData::new();
        key.append_u32(84).unwrap();
        let key = SliceData::load_builder(key).unwrap();
        let _ = config.config_params.remove(key);
        if let Some(value) = value {
            config.set_config(ConfigParamEnum::ConfigParamAny(84, value)).expect("param 84");
        }
        self.net.bc.set_config(config).expect("the chain adopts it");
    }

    // ---- addresses and state -------------------------------------------------------------

    pub fn user(&self, i: usize) -> MsgAddressInt {
        self.net.user(i)
    }

    pub fn wallet(&self) -> MsgAddressInt {
        self.net.wallet_of(&self.actor)
    }

    pub fn tokens(&self, owner: &MsgAddressInt) -> u128 {
        self.net.tokens(owner)
    }

    pub fn actor_tokens(&self) -> u128 {
        self.net.tokens(&self.actor)
    }

    pub fn balance(&self, addr: &MsgAddressInt) -> u128 {
        self.net.balance(addr)
    }

    pub fn data_hash(&self) -> Option<UInt256> {
        self.net.bc.get_account(&self.actor).and_then(|a| a.get_data_hash())
    }

    pub fn get(&self, method: &str, args: Vec<StackItem>) -> tos_sandbox::GetMethodResult {
        self.net.get(&self.actor, method, args)
    }

    pub fn ledger(&self) -> TokenLedger {
        let r = self.get("get_token_ledger", vec![]);
        TokenLedger {
            pending: r.int_at(0) as u128,
            refundable: r.int_at(1) as u128,
            returned: r.int_at(2) as u128,
            in_flight: r.int_at(3) as u128,
            withdrawable_revenue: r.int_at(4) as u128,
        }
    }

    pub fn native(&self) -> NativeLedger {
        let r = self.get("get_native_ledger", vec![]);
        NativeLedger {
            withdrawable_revenue: r.int_at(0) as u64,
            locked_storage_fees: r.int_at(1) as u64,
            locked_outcome_fees: r.int_at(2) as u64,
            call_day: r.int_at(3) as u32,
            calls_today: r.int_at(4) as u32,
            revenue_payouts_in_flight: r.int_at(5) as u32,
            returned_count: r.int_at(6) as u32,
            returns_in_flight: r.int_at(7) as u32,
            surplus_payouts_in_flight: r.int_at(8) as u32,
        }
    }

    /// (next_request_id, pending_count, live_count, next_payout_id)
    pub fn counters(&self) -> (u64, u32, u32, u64) {
        let r = self.get("get_service_data", vec![]);
        (r.int_at(17) as u64, r.int_at(18) as u32, r.int_at(19) as u32, r.int_at(20) as u64)
    }

    pub fn active(&self) -> bool {
        self.get("get_service_data", vec![]).int_at(1) != 0
    }

    pub fn policy_version(&self) -> u32 {
        self.get("get_service_data", vec![]).int_at(2) as u32
    }

    pub fn terms_hash(&self) -> [u8; 32] {
        self.terms_cell().repr_hash().inner()
    }

    pub fn terms_cell(&self) -> Cell {
        self.get("get_terms", vec![]).cell_at(0)
    }

    /// (min_funding_value, admission allowance, return budget, report value,
    /// outcome lock, payout funding)
    pub fn prices(&self) -> (u128, u128, u128, u128, u128, u128) {
        let r = self.get("get_funding_prices", vec![]);
        (
            r.int_at(0) as u128,
            r.int_at(1) as u128,
            r.int_at(2) as u128,
            r.int_at(3) as u128,
            r.int_at(4) as u128,
            r.int_at(5) as u128,
        )
    }

    /// The prices a funding transfer is built against.
    pub fn funding_prices(&self) -> contracts::service_actor_token::FundingPrices {
        contracts::service_actor_token::FundingPrices {
            storage_fee: self.get("get_service_data", vec![]).int_at(4) as u64,
            min_funding_value: self.min_funding(),
            accepting_tokens: self.get("get_accepting_tokens", vec![]).int_at(0) != 0,
        }
    }

    pub fn min_funding(&self) -> u128 {
        self.prices().0
    }

    pub fn payout_funding(&self) -> u64 {
        self.prices().5 as u64
    }

    /// The forward value a fully funded call carries.
    pub fn call_forward(&self) -> u128 {
        u128::from(self.init.storage_fee) + self.min_funding()
    }

    pub fn payout(&self, id: u64) -> Option<PayoutData> {
        let r = self.get("get_payout", vec![int_arg(id)]);
        if r.int_at(0) == 0 {
            return None;
        }
        let addr =
            |i: usize| MsgAddressInt::construct_from(&mut r.slice_at(i)).expect("an address");
        Some(PayoutData {
            kind: r.int_at(1) as u8,
            request_id: r.int_at(2) as u64,
            recipient: addr(3),
            requester: addr(4),
            amount: r.int_at(5) as u128,
            created_at: r.int_at(6) as u32,
            recipient_wallet: addr(7),
            own_wallet: addr(8),
            outcome_fee_lock: r.int_at(9) as u64,
        })
    }

    pub fn returned(&self, id: u64) -> Option<ReturnedData> {
        let r = self.get("get_returned", vec![int_arg(id)]);
        if r.int_at(0) == 0 {
            return None;
        }
        Some(ReturnedData {
            caller: MsgAddressInt::construct_from(&mut r.slice_at(1)).expect("a caller"),
            amount: r.int_at(2) as u128,
            paying: r.int_at(3) as u64,
            return_deadline: r.int_at(4) as u64,
        })
    }

    pub fn request_exists(&self, id: u64) -> bool {
        self.get("get_request", vec![int_arg(id)]).int_at(0) != 0
    }

    pub fn refund_exists(&self, id: u64) -> bool {
        self.get("get_refund", vec![int_arg(id)]).int_at(0) != 0
    }

    pub fn caller_live(&self, caller: &MsgAddressInt) -> u32 {
        self.get("get_caller_live_count", vec![slice_arg(caller)]).int_at(0) as u32
    }

    pub fn caller_returned(&self, caller: &MsgAddressInt) -> u32 {
        self.get("get_caller_returned_count", vec![slice_arg(caller)]).int_at(0) as u32
    }

    /// (active, query_id, purpose, created_at, floor, delivered, target, amount)
    pub fn balance_query(&self) -> (bool, u64, u8, u32, u64, u128, u64, u128) {
        let r = self.get("get_balance_query", vec![]);
        (
            r.int_at(0) != 0,
            r.int_at(1) as u64,
            r.int_at(2) as u8,
            r.int_at(3) as u32,
            r.int_at(4) as u64,
            r.int_at(5) as u128,
            r.int_at(6) as u64,
            r.int_at(7) as u128,
        )
    }

    /// The tokens no ledger entry attributes: what surplus recovery may take.
    pub fn surplus(&self) -> i128 {
        let ledger = self.ledger();
        let out: u128 = self.out_of_wallet.values().sum();
        (self.actor_tokens() + out) as i128 - ledger.attributed().expect("a ledger sum") as i128
    }

    // ---- the invariant ---------------------------------------------------------------------

    /// The token invariant: every attributed token is in the wallet or in a live
    /// payout that has left it.
    pub fn check_invariant(&mut self, what: &str) {
        if !self.checking || !self.net.exists(&self.actor) {
            return;
        }
        let live: Vec<u64> = self.out_of_wallet.keys().copied().collect();
        for id in live {
            if self.payout(id).is_none() {
                self.out_of_wallet.remove(&id);
            }
        }
        let ledger = self.ledger();
        let attributed = ledger.attributed().expect("the ledger sum fits");
        let held = self.actor_tokens() + self.out_of_wallet.values().sum::<u128>();
        assert!(
            held >= attributed,
            "token invariant after {what}: the wallet holds {} and {} more is out in live \
             payouts, but the ledger attributes {attributed} ({ledger:?})",
            self.actor_tokens(),
            self.out_of_wallet.values().sum::<u128>()
        );
        let native = self.native();
        assert!(
            u128::from(native.locked_storage_fees) + u128::from(native.locked_outcome_fees)
                <= self.balance(&self.actor),
            "the actor's TOS balance no longer covers its locks after {what}"
        );
    }

    /// Records what one delivery did to the actor's wallet and the actor's gas.
    fn observe(&mut self, d: &Delivery) {
        let wallet = self.wallet();
        if d.addr == wallet {
            for m in &d.outs {
                if body_op(m) == Some(OP_INTERNAL_TRANSFER_REPORTED) && m.int_header().is_some() {
                    let mut s = settlement_body(m);
                    s.get_next_u32().unwrap();
                    let id = s.get_next_u64().unwrap();
                    let amount = Coins::construct_from(&mut s).unwrap().as_u128();
                    self.out_of_wallet.insert(id, amount);
                }
            }
            if let Some((id, _)) = crate::model::reported_bounce(&d.msg) {
                self.out_of_wallet.remove(&id);
            }
        }
        if d.addr == self.actor {
            let o = outcome(&d.tx);
            let label = label_of(&d.msg);
            let entry = self.gas.entry(label).or_insert(0);
            *entry = (*entry).max(o.gas_used);
        }
    }

    // ---- delivery -------------------------------------------------------------------------

    pub fn execute(&mut self, msg: Message) -> Delivery {
        let d = self.net.execute(msg);
        self.steps += 1;
        self.observe(&d);
        let what = format!("step {} ({})", self.steps, label_of(&d.msg));
        self.check_invariant(&what);
        d
    }

    pub fn deliver_one(&mut self) -> Delivery {
        let msg = self.net.queue.pop_front().expect("a message to deliver");
        self.execute(msg)
    }

    pub fn settle(&mut self) {
        let mut steps = 0;
        while !self.net.queue.is_empty() {
            steps += 1;
            assert!(steps < 4096, "the cascade does not end");
            self.deliver_one();
        }
    }

    /// Executes `msg` and everything it causes; returns the first transaction.
    pub fn send(&mut self, msg: Message) -> chain_block::Transaction {
        let d = self.execute(msg);
        self.settle();
        d.tx
    }

    /// Delivers until the next message is one `stop` names, and leaves it queued.
    pub fn deliver_until(&mut self, stop: impl Fn(&Message) -> bool) {
        let mut steps = 0;
        while let Some(next) = self.net.queue.front() {
            if stop(next) {
                return;
            }
            steps += 1;
            assert!(steps < 4096, "the cascade does not end");
            self.deliver_one();
        }
        panic!("the cascade ended before the awaited message");
    }

    /// Delivers until a message `pick` names is queued, and takes it out.
    pub fn intercept(&mut self, pick: impl Fn(&Message) -> bool) -> Message {
        let mut steps = 0;
        loop {
            if let Some(index) = self.net.queue.iter().position(|m| pick(m)) {
                return self.net.queue.remove(index).expect("the message");
            }
            steps += 1;
            assert!(steps < 4096, "the cascade does not end");
            assert!(!self.net.queue.is_empty(), "the cascade ended before the awaited message");
            self.deliver_one();
        }
    }

    // ---- the actor's ops -------------------------------------------------------------------

    /// `from` sends `body` to the actor with `value`, bounceable, and everything
    /// it causes runs. Returns the actor's transaction.
    pub fn op(&mut self, from: &MsgAddressInt, body: Cell, value: u64) -> chain_block::Transaction {
        let msg =
            MessageBuilder::internal(from, &self.actor, value).bounce(true).body(body).build();
        self.send(msg)
    }

    /// The same, but only the actor's own transaction runs.
    pub fn op_one(&mut self, from: &MsgAddressInt, body: Cell, value: u64) -> Delivery {
        let msg =
            MessageBuilder::internal(from, &self.actor, value).bounce(true).body(body).build();
        self.execute(msg)
    }

    /// A buyer's funding transfer: `amount` tokens to the actor, `forward` TOS
    /// for the notification, and `payload` as the forward payload (by
    /// reference), or none.
    pub fn funding_message(
        &self,
        buyer: &MsgAddressInt,
        amount: u128,
        forward: u128,
        payload: Option<Cell>,
    ) -> Message {
        let wallet = self.net.wallet_of(buyer);
        let actor = self.actor.clone();
        let body = cell(|b| {
            b.append_u32(OP_TRANSFER).unwrap().append_u64(77).unwrap();
            coins(b, amount);
            actor.write_to(b).unwrap();
            buyer.write_to(b).unwrap();
            b.append_bit_zero().unwrap();
            coins(b, forward);
            match &payload {
                Some(p) => {
                    b.append_bit_one().unwrap();
                    b.checked_append_reference(p.clone()).unwrap();
                }
                None => {
                    b.append_bit_zero().unwrap();
                }
            }
        });
        let value = forward as u64 + TOS;
        MessageBuilder::internal(buyer, &wallet, value).bounce(true).body(body).build()
    }

    pub fn token_call(&self, request_hash: [u8; 32]) -> Cell {
        ServiceActorTokenContract::token_call(request_hash, self.terms_hash()).unwrap()
    }

    /// Funds a call from `buyer` and lets it run; returns the delivery index it
    /// started at.
    pub fn fund(
        &mut self,
        buyer: &MsgAddressInt,
        amount: u128,
        forward: u128,
        payload: Option<Cell>,
    ) -> usize {
        let start = self.net.delivered.len();
        let msg = self.funding_message(buyer, amount, forward, payload);
        self.send(msg);
        start
    }

    /// A fully funded call at the published terms; returns its request id.
    pub fn call(&mut self, buyer: &MsgAddressInt) -> u64 {
        let (next, ..) = self.counters();
        let start = self.fund(
            buyer,
            self.init.price_per_call,
            self.call_forward(),
            Some(self.token_call([7; 32])),
        );
        let snapshots = self.snapshots_since(start);
        assert_eq!(
            snapshots.len(),
            1,
            "the call was admitted: {:?}",
            self.funding_logs_since(start)
        );
        assert_eq!(snapshots[0].request_id, next);
        next
    }

    // ---- logs -----------------------------------------------------------------------------

    fn actor_logs_since(&self, start: usize, tag: u32) -> Vec<Cell> {
        self.net.delivered[start..]
            .iter()
            .filter(|d| d.addr == self.actor)
            .flat_map(|d| d.outs.iter())
            .filter(|m| !m.is_internal())
            .filter_map(|m| {
                let body = m.body()?;
                let cell = if body.remaining_bits() == 0 && body.remaining_references() == 1 {
                    body.reference(0).ok()?
                } else {
                    body.clone().into_cell().ok()?
                };
                let mut s = SliceData::load_cell(cell.clone()).ok()?;
                (s.get_next_u32().ok()? == tag).then_some(cell)
            })
            .collect()
    }

    pub fn snapshots_since(&self, start: usize) -> Vec<TokenRequestSnapshot> {
        self.actor_logs_since(start, log::REQUEST_SNAPSHOT)
            .iter()
            .map(|c| decode_request_snapshot(c).expect("a well-formed SAT1"))
            .collect()
    }

    pub fn funding_logs_since(&self, start: usize) -> Vec<FundingLog> {
        self.actor_logs_since(start, log::FUNDING)
            .iter()
            .map(|c| decode_funding_log(c).expect("a well-formed SAF1"))
            .collect()
    }

    pub fn outcome_logs_since(&self, start: usize) -> Vec<OutcomeLog> {
        self.actor_logs_since(start, log::OUTCOME)
            .iter()
            .map(|c| decode_outcome_log(c).expect("a well-formed SAO1"))
            .collect()
    }

    pub fn balance_logs_since(&self, start: usize) -> Vec<BalanceLog> {
        self.actor_logs_since(start, log::BALANCE)
            .iter()
            .map(|c| decode_balance_log(c).expect("a well-formed SAB1"))
            .collect()
    }

    /// Every actor transaction since `start`.
    pub fn actor_txs_since(&self, start: usize) -> Vec<&Delivery> {
        self.net.delivered[start..].iter().filter(|d| d.addr == self.actor).collect()
    }

    pub fn advance(&mut self, seconds: u32) {
        self.net.advance_time(seconds);
    }
}

/// A short name for what a message to the actor carries: its op, or the op of
/// the message whose bounce it is.
pub fn label_of(msg: &Message) -> String {
    let bounced = msg.int_header().is_some_and(|h| h.bounced);
    let Some(body) = msg.body() else { return "empty".into() };
    let mut s = body.clone();
    if bounced {
        let _ = s.get_next_u32();
        return format!("bounce:{:08x}", s.get_next_u32().unwrap_or(0));
    }
    if s.remaining_bits() < 32 {
        return "empty".into();
    }
    format!("{:08x}", s.get_next_u32().unwrap_or(0))
}

pub fn exit_code(tx: &chain_block::Transaction) -> Option<i32> {
    outcome(tx).exit_code
}

pub fn assert_refused(tx: &chain_block::Transaction, code: i32) {
    refused_with(tx, code);
}

/// A treasury on workchain 0 with `tos` TOS.
pub fn treasury(net: &mut Net, name: &str, tos: u64) -> Treasury {
    net.bc.treasury(name, tos * TOS).expect("a treasury")
}

// ---- the actor's state, as a deployer or a long history could leave it ----------------

/// The actor's data, split into the parts its layout names.
pub struct ActorData {
    pub owner: MsgAddressInt,
    pub active: bool,
    pub next_request_id: u64,
    pub pending_count: u32,
    pub live_count: u32,
    pub next_payout_id: u64,
    pub policy: Cell,
    /// withdrawable_tos_revenue, locked_storage_fees, locked_outcome_fees
    pub tos: [u128; 3],
    pub call_day: u32,
    pub calls_today: u32,
    pub revenue_payouts_in_flight: u8,
    pub returned_count: u32,
    pub returns_in_flight: u16,
    pub surplus_payouts_in_flight: u8,
    pub attestor_key_count: u8,
    /// pending, refundable, returned, in_flight, token revenue
    pub token: [u128; 5],
    pub query: Cell,
    pub route: Cell,
    /// pending_requests, refunds, caller_live_counts, attestor_keys
    pub requests: [Option<Cell>; 4],
    /// payouts, returned, caller_returned_counts
    pub payout_dicts: [Option<Cell>; 3],
}

fn dict_of(s: &mut SliceData) -> Option<Cell> {
    if s.get_next_bit().unwrap() { Some(s.checked_drain_reference().unwrap()) } else { None }
}

fn put_dict(b: &mut chain_block::BuilderData, d: &Option<Cell>) {
    match d {
        Some(c) => {
            b.append_bit_one().unwrap();
            b.checked_append_reference(c.clone()).unwrap();
        }
        None => {
            b.append_bit_zero().unwrap();
        }
    }
}

impl ActorData {
    pub fn parse(data: &Cell) -> Self {
        let mut s = SliceData::load_cell(data.clone()).unwrap();
        let owner = MsgAddressInt::construct_from(&mut s).unwrap();
        let active = s.get_next_bit().unwrap();
        let next_request_id = s.get_next_u64().unwrap();
        let pending_count = s.get_next_u32().unwrap();
        let live_count = s.get_next_u32().unwrap();
        let next_payout_id = s.get_next_u64().unwrap();
        let policy = s.checked_drain_reference().unwrap();
        let mut a = SliceData::load_cell(s.checked_drain_reference().unwrap()).unwrap();
        let mut r = SliceData::load_cell(s.checked_drain_reference().unwrap()).unwrap();
        let mut p = SliceData::load_cell(s.checked_drain_reference().unwrap()).unwrap();
        let c = |s: &mut SliceData| Coins::construct_from(s).unwrap().as_u128();
        let tos = [c(&mut a), c(&mut a), c(&mut a)];
        let call_day = a.get_next_u32().unwrap();
        let calls_today = a.get_next_u32().unwrap();
        let revenue_payouts_in_flight = a.get_next_byte().unwrap();
        let returned_count = a.get_next_u32().unwrap();
        let returns_in_flight = a.get_next_u16().unwrap();
        let surplus_payouts_in_flight = a.get_next_byte().unwrap();
        let attestor_key_count = a.get_next_byte().unwrap();
        let mut t = SliceData::load_cell(a.checked_drain_reference().unwrap()).unwrap();
        let token = [c(&mut t), c(&mut t), c(&mut t), c(&mut t), c(&mut t)];
        let query = a.checked_drain_reference().unwrap();
        let route = a.checked_drain_reference().unwrap();
        let requests = [dict_of(&mut r), dict_of(&mut r), dict_of(&mut r), dict_of(&mut r)];
        let payout_dicts = [dict_of(&mut p), dict_of(&mut p), dict_of(&mut p)];
        Self {
            owner,
            active,
            next_request_id,
            pending_count,
            live_count,
            next_payout_id,
            policy,
            tos,
            call_day,
            calls_today,
            revenue_payouts_in_flight,
            returned_count,
            returns_in_flight,
            surplus_payouts_in_flight,
            attestor_key_count,
            token,
            query,
            route,
            requests,
            payout_dicts,
        }
    }

    pub fn build(&self) -> Cell {
        let token = cell(|b| {
            for v in self.token {
                coins(b, v);
            }
        });
        let accounting = cell(|b| {
            for v in self.tos {
                coins(b, v);
            }
            b.append_u32(self.call_day).unwrap();
            b.append_u32(self.calls_today).unwrap();
            b.append_u8(self.revenue_payouts_in_flight).unwrap();
            b.append_u32(self.returned_count).unwrap();
            b.append_u16(self.returns_in_flight).unwrap();
            b.append_u8(self.surplus_payouts_in_flight).unwrap();
            b.append_u8(self.attestor_key_count).unwrap();
            b.checked_append_reference(token).unwrap();
            b.checked_append_reference(self.query.clone()).unwrap();
            b.checked_append_reference(self.route.clone()).unwrap();
        });
        let requests = cell(|b| self.requests.iter().for_each(|d| put_dict(b, d)));
        let payouts = cell(|b| self.payout_dicts.iter().for_each(|d| put_dict(b, d)));
        cell(|b| {
            self.owner.write_to(b).unwrap();
            if self.active {
                b.append_bit_one().unwrap();
            } else {
                b.append_bit_zero().unwrap();
            }
            b.append_u64(self.next_request_id).unwrap();
            b.append_u32(self.pending_count).unwrap();
            b.append_u32(self.live_count).unwrap();
            b.append_u64(self.next_payout_id).unwrap();
            b.checked_append_reference(self.policy.clone()).unwrap();
            b.checked_append_reference(accounting).unwrap();
            b.checked_append_reference(requests).unwrap();
            b.checked_append_reference(payouts).unwrap();
        })
    }
}

/// The key the actor's per-caller counters use: the hash of the address's bits.
pub fn caller_key(caller: &MsgAddressInt) -> [u8; 32] {
    cell(|b| caller.write_to(b).unwrap()).repr_hash().inner()
}

/// A per-caller counter dictionary with `caller` at `count`.
pub fn counter_dict(existing: &Option<Cell>, caller: &MsgAddressInt, count: u32) -> Option<Cell> {
    use chain_block::{HashmapE, HashmapType};
    let mut d = match existing {
        Some(c) => HashmapE::with_hashmap(256, Some(c.clone())),
        None => HashmapE::with_bit_len(256),
    };
    let key = SliceData::from_raw(caller_key(caller).to_vec(), 256);
    let value = SliceData::load_cell(cell(|b| {
        b.append_u32(count).unwrap();
    }))
    .unwrap();
    d.set(key, &value).unwrap();
    d.data().cloned()
}

impl World {
    pub fn actor_data(&self) -> ActorData {
        ActorData::parse(&self.net.bc.get_account(&self.actor).and_then(|a| a.get_data()).unwrap())
    }

    /// Rewrites the actor's data as `f` says, and its usage with it.
    pub fn patch(&mut self, f: impl FnOnce(&mut ActorData)) {
        let mut data = self.actor_data();
        f(&mut data);
        let mut account = self.net.bc.get_account(&self.actor).expect("deployed").clone();
        assert!(account.set_data(data.build()), "the data is replaced");
        let min = self
            .net
            .bc
            .config_params()
            .size_limits_config()
            .expect("limits")
            .acc_state_cells_for_storage_dict;
        account.update_storage_stat(min).expect("the usage is recomputed");
        self.net.bc.set_account(self.actor.clone(), account);
    }

    fn is_s_to_r(&self, m: &Message) -> bool {
        body_op(m) == Some(OP_INTERNAL_TRANSFER_REPORTED)
            && m.src_ref() == Some(&self.wallet())
            && !m.int_header().is_some_and(|h| h.bounced)
    }

    fn is_reported_from_actor(&self, m: &Message) -> bool {
        body_op(m) == Some(OP_REPORTED_TRANSFER)
            && m.dst_ref() == Some(&self.wallet())
            && !m.int_header().is_some_and(|h| h.bounced)
    }

    /// Delivers `msg`, then refuses the actor's next reported transfer at R:
    /// ConfigParam 79 is taken away while S's message is in flight, so R throws
    /// and bounces. With `drop_report` the refusal report is lost.
    pub fn refusing_at_r(&mut self, msg: Message, drop_report: bool) -> usize {
        let start = self.net.delivered.len();
        self.execute(msg);
        self.deliver_until(|m| {
            body_op(m) == Some(OP_INTERNAL_TRANSFER_REPORTED)
                && !m.int_header().is_some_and(|h| h.bounced)
        });
        self.net.remove_config();
        self.deliver_one();
        self.net.configure();
        if drop_report {
            let actor = self.actor.clone();
            self.intercept(|m| is_to(m, &actor) && body_op(m) == Some(OP_TRANSFER_REFUSED));
        }
        self.settle();
        start
    }

    /// Delivers `msg`, then makes S refuse the actor's next reported transfer:
    /// without ConfigParam 79 the wallet throws at dispatch and the message
    /// bounces back to the actor.
    pub fn bouncing_at_s(&mut self, msg: Message) -> usize {
        let start = self.net.delivered.len();
        self.execute(msg);
        let wallet = self.wallet();
        self.deliver_until(|m| {
            body_op(m) == Some(OP_REPORTED_TRANSFER) && m.dst_ref() == Some(&wallet)
        });
        self.net.remove_config();
        self.deliver_one();
        self.net.configure();
        self.settle();
        start
    }

    /// Delivers `msg` and everything after it except the delivery report of the
    /// actor's next payout, which is lost.
    pub fn losing_delivery_report(&mut self, msg: Message) -> usize {
        let start = self.net.delivered.len();
        self.execute(msg);
        let actor = self.actor.clone();
        self.intercept(|m| is_to(m, &actor) && body_op(m) == Some(OP_TRANSFER_DELIVERED));
        self.settle();
        start
    }

    pub fn op_message(&self, from: &MsgAddressInt, body: Cell, value: u64) -> Message {
        MessageBuilder::internal(from, &self.actor, value).bounce(true).body(body).build()
    }

    /// The actor's wallet holds `others` refusal records under unrelated query
    /// ids (the deepest shape around `key`), as dropped reports would leave.
    pub fn fill_refusals(&mut self, others: u64, key: u64) {
        use chain_block::{BuilderData, HashmapE, HashmapType};
        let actor = self.actor.clone();
        self.net.patch_wallet(&actor, |w| {
            let mut d = HashmapE::with_bit_len(64);
            let value = SliceData::load_cell(cell(|b| coins(b, 1))).unwrap();
            for i in 0..others {
                let mut k = BuilderData::new();
                k.append_u64(key ^ (1u64 << i)).unwrap();
                d.set(SliceData::load_builder(k).unwrap(), &value).unwrap();
            }
            w.refusals = d.data().cloned();
            w.refusals_count = others as u16;
        });
        let wallet = account_hash(&self.wallet());
        self.net.model.refusal_records.retain(|(w, _), _| *w != wallet);
    }

    pub fn refusals(&self) -> i128 {
        self.net.refusals_count(&self.actor)
    }
}
