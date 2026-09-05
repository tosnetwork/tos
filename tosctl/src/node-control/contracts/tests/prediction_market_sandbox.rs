/*
 * Copyright (C) 2025-2026 TOS Network.
 * Licensed under the GNU General Public License v3.0.
 */

//! Production-BOC state-transition tests for PredictionMarket V1.

use chain_block::{
    BuilderData, Cell, Coins, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
    TrComputePhase,
};
use contracts::{
    PredictionLiquidityRoleV1, PredictionMarketContractV1, PredictionMarketInitV1,
    PredictionOraclePolicyV1, PredictionOrderActionV1, PredictionOrderOutcomeV1, PredictionOrderV1,
};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, Treasury, compile_func_with_stdlib};
use tos_vm::stack::StackItem;

fn assert_success(label: &str, result: &SendResult) {
    let description = result.read_primary_description();
    if description.aborted {
        panic!(
            "{label} aborted: compute={:?}, action={:?}",
            description.compute_ph, description.action
        );
    }
}

fn compute_gas_used(result: &SendResult) -> u64 {
    match result.read_primary_description().compute_ph {
        TrComputePhase::Vm(vm) => vm.gas_used.as_u64(),
        TrComputePhase::Skipped(skipped) => {
            panic!("compute phase was skipped: {:?}", skipped.reason)
        }
    }
}

fn always_abort_recipient_code() -> Cell {
    let source = std::env::temp_dir().join("prediction_market_always_abort_recipient.fc");
    std::fs::write(
        &source,
        r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
  throw(777);
}
"#,
    )
    .expect("write aborting recipient source");
    compile_func_with_stdlib(&[source]).expect("compile aborting recipient")
}

const TOS: u64 = 1_000_000_000;
const OPERATION_BUDGET: u64 = TOS;

struct Fixture {
    bc: Blockchain,
    owner: Treasury,
    trader_b: Treasury,
    normal: Treasury,
    appellate: Treasury,
    reserve: Treasury,
    market: MsgAddressInt,
    init: PredictionMarketInitV1,
}

#[derive(Clone, Copy, Debug, Default)]
struct ReferenceAccount {
    free: u64,
    yes: u64,
    no: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct ReferenceMarket {
    accounts: [ReferenceAccount; 2],
    complete_sets: u64,
    locked: u64,
    fill_count: u64,
    order_records: u32,
}

impl ReferenceMarket {
    fn split(&mut self, owner: usize, quantity: u64, lot_value: u64) -> bool {
        let Some(amount) = quantity.checked_mul(lot_value) else {
            return false;
        };
        if self.accounts[owner].free < amount {
            return false;
        }
        self.accounts[owner].free = self.accounts[owner].free.checked_sub(amount).unwrap();
        self.accounts[owner].yes = self.accounts[owner].yes.checked_add(quantity).unwrap();
        self.accounts[owner].no = self.accounts[owner].no.checked_add(quantity).unwrap();
        self.complete_sets = self.complete_sets.checked_add(quantity).unwrap();
        self.locked = self.locked.checked_add(amount).unwrap();
        true
    }

    fn merge(&mut self, owner: usize, quantity: u64, lot_value: u64) -> bool {
        let Some(amount) = quantity.checked_mul(lot_value) else {
            return false;
        };
        if self.accounts[owner].yes < quantity || self.accounts[owner].no < quantity {
            return false;
        }
        self.accounts[owner].yes = self.accounts[owner].yes.checked_sub(quantity).unwrap();
        self.accounts[owner].no = self.accounts[owner].no.checked_sub(quantity).unwrap();
        self.accounts[owner].free = self.accounts[owner].free.checked_add(amount).unwrap();
        self.complete_sets = self.complete_sets.checked_sub(quantity).unwrap();
        self.locked = self.locked.checked_sub(amount).unwrap();
        true
    }

    fn complementary_buy(
        &mut self,
        yes_owner: usize,
        no_owner: usize,
        quantity: u64,
        lot_value: u64,
        yes_price_tick: u16,
    ) -> bool {
        let unit = lot_value.checked_div(10_000).unwrap();
        let Some(notional) = quantity.checked_mul(lot_value) else {
            return false;
        };
        let Some(yes_value) = quantity
            .checked_mul(unit)
            .and_then(|value| value.checked_mul(u64::from(yes_price_tick)))
        else {
            return false;
        };
        let no_value = notional.checked_sub(yes_value).unwrap();
        if self.accounts[yes_owner].free < yes_value || self.accounts[no_owner].free < no_value {
            return false;
        }
        self.accounts[yes_owner].free =
            self.accounts[yes_owner].free.checked_sub(yes_value).unwrap();
        self.accounts[no_owner].free = self.accounts[no_owner].free.checked_sub(no_value).unwrap();
        self.accounts[yes_owner].yes = self.accounts[yes_owner].yes.checked_add(quantity).unwrap();
        self.accounts[no_owner].no = self.accounts[no_owner].no.checked_add(quantity).unwrap();
        self.complete_sets = self.complete_sets.checked_add(quantity).unwrap();
        self.locked = self.locked.checked_add(notional).unwrap();
        self.record_fill();
        true
    }

    fn transfer_yes(
        &mut self,
        seller: usize,
        buyer: usize,
        quantity: u64,
        lot_value: u64,
        yes_price_tick: u16,
    ) -> bool {
        let unit = lot_value.checked_div(10_000).unwrap();
        let Some(value) = quantity
            .checked_mul(unit)
            .and_then(|amount| amount.checked_mul(u64::from(yes_price_tick)))
        else {
            return false;
        };
        if self.accounts[seller].yes < quantity || self.accounts[buyer].free < value {
            return false;
        }
        self.accounts[seller].yes = self.accounts[seller].yes.checked_sub(quantity).unwrap();
        self.accounts[buyer].yes = self.accounts[buyer].yes.checked_add(quantity).unwrap();
        self.accounts[seller].free = self.accounts[seller].free.checked_add(value).unwrap();
        self.accounts[buyer].free = self.accounts[buyer].free.checked_sub(value).unwrap();
        self.record_fill();
        true
    }

    fn complementary_sell(
        &mut self,
        yes_owner: usize,
        no_owner: usize,
        quantity: u64,
        lot_value: u64,
        yes_price_tick: u16,
    ) -> bool {
        let unit = lot_value.checked_div(10_000).unwrap();
        let Some(notional) = quantity.checked_mul(lot_value) else {
            return false;
        };
        let Some(yes_value) = quantity
            .checked_mul(unit)
            .and_then(|value| value.checked_mul(u64::from(yes_price_tick)))
        else {
            return false;
        };
        let no_value = notional.checked_sub(yes_value).unwrap();
        if self.accounts[yes_owner].yes < quantity || self.accounts[no_owner].no < quantity {
            return false;
        }
        self.accounts[yes_owner].yes = self.accounts[yes_owner].yes.checked_sub(quantity).unwrap();
        self.accounts[no_owner].no = self.accounts[no_owner].no.checked_sub(quantity).unwrap();
        self.accounts[yes_owner].free =
            self.accounts[yes_owner].free.checked_add(yes_value).unwrap();
        self.accounts[no_owner].free = self.accounts[no_owner].free.checked_add(no_value).unwrap();
        self.complete_sets = self.complete_sets.checked_sub(quantity).unwrap();
        self.locked = self.locked.checked_sub(notional).unwrap();
        self.record_fill();
        true
    }

    fn record_fill(&mut self) {
        self.fill_count = self.fill_count.checked_add(1).unwrap();
        self.order_records = self.order_records.checked_add(2).unwrap();
    }

    fn assert_matches(&self, fixture: &Fixture, owners: [&MsgAddressInt; 2]) {
        let accounting = fixture.accounting();
        let total_free = self.accounts[0].free.checked_add(self.accounts[1].free).unwrap();
        let cleanup = 2_u64
            .checked_mul(fixture.init.account_cleanup_bounty)
            .and_then(|value| {
                u64::from(self.order_records)
                    .checked_mul(fixture.init.order_cleanup_bounty)
                    .and_then(|orders| value.checked_add(orders))
            })
            .unwrap();
        assert_eq!(accounting[0], 2, "participant count drifted");
        assert_eq!(accounting[1], i128::from(self.order_records), "order records drifted");
        assert_eq!(accounting[2], i128::from(self.fill_count), "fill count drifted");
        assert_eq!(accounting[3], i128::from(self.complete_sets), "complete sets drifted");
        assert_eq!(accounting[4], i128::from(total_free), "total free drifted");
        assert_eq!(accounting[5], i128::from(self.locked), "locked backing drifted");
        assert_eq!(accounting[10], i128::from(cleanup), "cleanup liability drifted");
        let mut total_yes = 0_u64;
        let mut total_no = 0_u64;
        for (index, owner) in owners.into_iter().enumerate() {
            let chain = fixture.account(owner);
            assert_eq!(chain[0], i128::from(self.accounts[index].free));
            assert_eq!(chain[1], i128::from(self.accounts[index].yes));
            assert_eq!(chain[2], i128::from(self.accounts[index].no));
            total_yes = total_yes.checked_add(self.accounts[index].yes).unwrap();
            total_no = total_no.checked_add(self.accounts[index].no).unwrap();
        }
        assert_eq!(total_yes, self.complete_sets, "YES supply no longer equals Q");
        assert_eq!(total_no, self.complete_sets, "NO supply no longer equals Q");
        let liabilities = total_free
            .checked_add(self.locked)
            .and_then(|value| value.checked_add(cleanup))
            .unwrap();
        let physical = fixture
            .bc
            .get_account(&fixture.market)
            .unwrap()
            .balance()
            .unwrap()
            .coins
            .as_u64()
            .unwrap();
        assert!(
            physical >= liabilities.checked_add(fixture.init.operating_reserve_floor).unwrap(),
            "physical balance fell below liabilities plus reserve"
        );
    }
}

impl Fixture {
    fn new() -> Self {
        Self::new_with(|_| {})
    }

    fn new_with(configure: impl FnOnce(&mut PredictionMarketInitV1)) -> Self {
        Self::new_with_global_version(14, configure)
    }

    fn new_with_global_version(
        global_version: u32,
        configure: impl FnOnce(&mut PredictionMarketInitV1),
    ) -> Self {
        let mut bc = Blockchain::with_global_version(global_version).expect("blockchain");
        bc.set_workchain(-1);
        let treasury_balance = 25_000_u64.checked_mul(TOS).unwrap();
        let owner = bc.treasury("prediction-owner", treasury_balance).expect("owner");
        let trader_b = bc.treasury("prediction-trader-b", treasury_balance).expect("trader b");
        let normal = bc.treasury("normal-reporter", 100 * TOS).expect("normal reporter");
        let appellate = bc.treasury("appellate-reporter", 100 * TOS).expect("appellate reporter");
        let reserve = bc.treasury("prediction-reserve", 100 * TOS).expect("reserve");
        let now = u64::from(bc.now());
        let mut init = PredictionMarketInitV1 {
            global_id: 42,
            workchain_id: -1,
            deployment_salt: [0x11; 32],
            rules_hash: [0x22; 32],
            metadata_hash: [0x33; 32],
            reserve_recipient: reserve.address().clone(),
            trade_close: now + 1_000,
            resolve_not_before: now + 1_100,
            oracle_vote_deadline: now + 1_300,
            challenge_period: 120,
            appeal_review_delay: 60,
            appeal_period: 180,
            claim_deadline: now + 2_000,
            lot_value: TOS,
            min_price_tick: 100,
            min_fill_lots: 1,
            max_order_lots: 100,
            max_locked_collateral: 100 * TOS,
            max_account_free_balance: 50 * TOS,
            max_total_free_balance: 100 * TOS,
            max_total_liability: 300 * TOS,
            max_participants: 8,
            max_orders_per_participant: 128,
            max_live_order_records: 256,
            participant_entry_fee: TOS / 1_000,
            account_cleanup_bounty: TOS / 1_000,
            order_entry_fee: TOS / 1_000,
            order_cleanup_bounty: TOS / 1_000,
            operating_reserve_floor: TOS,
            terminal_tombstone_reserve: TOS / 10,
            challenge_bond: TOS / 10,
            challenge_processing_fee: TOS / 100,
            normal_oracle_policy: PredictionOraclePolicyV1 {
                threshold: 1,
                reporters: vec![normal.address().clone()],
            },
            appellate_oracle_policy: PredictionOraclePolicyV1 {
                threshold: 1,
                reporters: vec![appellate.address().clone()],
            },
        };
        configure(&mut init);
        let market = PredictionMarketContractV1::calculate_address(&init).expect("market address");
        let deploy = MessageBuilder::internal(owner.address(), &market, 2 * TOS)
            .bounce(false)
            .state_init(PredictionMarketContractV1::build_state_init(&init).expect("state init"))
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, owner, trader_b, normal, appellate, reserve, market, init }
    }

    fn send(&mut self, sender: &MsgAddressInt, value: u64, body: Cell) -> SendResult {
        let message =
            MessageBuilder::internal(sender, &self.market, value).bounce(true).body(body).build();
        self.bc.send_message(message).expect("send")
    }

    fn accounting(&self) -> Vec<i128> {
        let result = self
            .bc
            .run_get_method(&self.market, "get_prediction_accounting", vec![])
            .expect("accounting getter");
        result.expect_success();
        (0..11).map(|index| result.int_at(index)).collect()
    }

    fn account(&self, owner: &MsgAddressInt) -> Vec<i128> {
        let cell = owner.write_to_new_cell().unwrap().into_cell().unwrap();
        let owner = SliceData::load_cell(cell).unwrap();
        let result = self
            .bc
            .run_get_method(&self.market, "get_prediction_account", vec![StackItem::Slice(owner)])
            .expect("account getter");
        result.expect_success();
        (4..10).map(|index| result.int_at(index)).collect()
    }

    fn phase(&self) -> (u8, u8, u8, [u8; 32], [u8; 32], [u8; 32], u64) {
        let result =
            self.bc.run_get_method(&self.market, "get_market_phase", vec![]).expect("phase getter");
        result.expect_success();
        let hash_at = |index: usize| -> [u8; 32] {
            result.stack[index].as_integer().unwrap().as_u256().unwrap().try_into().unwrap()
        };
        (
            result.int_at(0) as u8,
            result.int_at(1) as u8,
            result.int_at(2) as u8,
            hash_at(3),
            hash_at(4),
            hash_at(5),
            result.int_at(6) as u64,
        )
    }

    fn resolution_contexts(&self) -> (Option<Cell>, Option<Cell>) {
        let result = self
            .bc
            .run_get_method(&self.market, "get_resolution_contexts", vec![])
            .expect("resolution contexts getter");
        result.expect_success();
        assert_eq!(result.stack.len(), 4);
        (
            (result.int_at(0) != 0).then(|| result.cell_at(1)),
            (result.int_at(2) != 0).then(|| result.cell_at(3)),
        )
    }

    fn activate(&mut self) {
        let owner = self.owner.address().clone();
        let result = self.send(
            &owner,
            self.init.operating_reserve_floor + OPERATION_BUDGET,
            PredictionMarketContractV1::activate(1).unwrap(),
        );
        assert_success("activate", &result);
    }

    fn register(&mut self, owner: &MsgAddressInt, key: &SigningKey, query_id: u64) {
        let credited = 10 * TOS;
        let value = credited
            + self.init.participant_entry_fee
            + self.init.account_cleanup_bounty
            + OPERATION_BUDGET;
        let result = self.send(
            owner,
            value,
            PredictionMarketContractV1::register_and_deposit(
                query_id,
                credited,
                key.verifying_key().to_bytes(),
            )
            .unwrap(),
        );
        assert_success("register", &result);
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_order(
        &self,
        owner: &MsgAddressInt,
        key: &SigningKey,
        nonce: u64,
        action: PredictionOrderActionV1,
        outcome: PredictionOrderOutcomeV1,
        role: PredictionLiquidityRoleV1,
        price: u16,
        quantity: u64,
    ) -> Cell {
        let order = PredictionOrderV1 {
            global_id: self.init.global_id,
            workchain_id: self.init.workchain_id,
            market_address: self.market.clone(),
            market_config_hash: PredictionMarketContractV1::market_config_hash(&self.init).unwrap(),
            owner_address: owner.clone(),
            key_epoch: 0,
            nonce,
            salt: [nonce as u8 + 1; 32],
            action,
            outcome,
            liquidity_role: role,
            quantity_lots: quantity,
            min_fill_lots: 1,
            allow_partial: true,
            limit_price_tick: price,
            valid_after: u64::from(self.bc.now()),
            valid_until: self.init.trade_close,
            optional_counterparty: None,
        };
        let digest = PredictionMarketContractV1::order_digest(&order).unwrap();
        let signature = key.sign(&digest).to_bytes();
        PredictionMarketContractV1::build_signed_order(
            &order,
            key.verifying_key().to_bytes(),
            signature,
        )
        .unwrap()
    }
}

#[test]
fn source_compiles_to_frozen_prediction_market_code() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../crypto/smartcont/prediction-market-code.fc");
    let compiled = compile_func_with_stdlib(&[source]).expect("compile PredictionMarket source");
    assert_eq!(
        compiled.repr_hash(),
        PredictionMarketContractV1::code().expect("frozen code").repr_hash(),
        "frozen PredictionMarket BOC must be regenerated after every FunC change"
    );
}

#[test]
fn global_version_gate_rejects_v13_and_admits_v14_v15_activation() {
    let mut v13 = Fixture::new_with_global_version(13, |_| {});
    let owner = v13.owner.address().clone();
    v13.send(
        &owner,
        v13.init.operating_reserve_floor + OPERATION_BUDGET,
        PredictionMarketContractV1::activate(1).unwrap(),
    )
    .expect_exit_code(2404);

    for version in [14, 15] {
        let mut fixture = Fixture::new_with_global_version(version, |_| {});
        fixture.activate();
        assert_eq!(fixture.phase().0, 0, "v{version} activation must retain the trading phase");
    }
}

#[test]
fn malformed_state_init_data_cannot_activate_the_production_contract() {
    let template = Fixture::new();
    let code = PredictionMarketContractV1::code().unwrap();
    let valid_data = PredictionMarketContractV1::build_data(&template.init).unwrap();
    let mut bad_magic_builder = BuilderData::from_cell(&valid_data).unwrap();
    let mut bad_magic = bad_magic_builder.data().to_vec();
    bad_magic[0] ^= 0x80;
    bad_magic_builder.replace_data(bad_magic, valid_data.bit_length());
    let bad_magic = bad_magic_builder.into_cell().unwrap();
    let mut truncated_builder = BuilderData::from_cell(&valid_data).unwrap();
    truncated_builder.trunc(16).unwrap();
    let truncated = truncated_builder.into_cell().unwrap();

    for (label, data) in
        [("empty", Cell::default()), ("truncated", truncated), ("bad magic", bad_magic)]
    {
        let mut bc = Blockchain::with_global_version(14).unwrap();
        bc.set_workchain(-1);
        let owner = bc.treasury(&format!("malformed-init-{label}"), 25_000 * TOS).unwrap();
        let state_init = StateInit::with_code_and_data(code.clone(), data);
        let state = state_init.write_to_new_cell().unwrap().into_cell().unwrap();
        let market = MsgAddressInt::with_params(-1, state.hash(0)).unwrap();
        let deploy = MessageBuilder::internal(owner.address(), &market, 2 * TOS)
            .bounce(true)
            .state_init(state_init)
            .body(PredictionMarketContractV1::activate(1).unwrap())
            .build();
        let result = bc.send_message(deploy).unwrap();
        result.expect_aborted();
        let state = bc.run_get_method(&market, "get_prediction_state", vec![]).unwrap();
        assert_ne!(
            state.exit_code, 0,
            "{label} StateInit must not become a parseable active market state"
        );
    }
}

#[test]
fn prepopulated_state_init_runtime_cannot_activate_the_production_contract() {
    let template = Fixture::new();
    let valid_data = PredictionMarketContractV1::build_data(&template.init).unwrap();
    let mut builder = BuilderData::from_cell(&valid_data).unwrap();
    let mut bytes = builder.data().to_vec();
    // Root layout is magic:uint32, version:uint16, activated:1,
    // activated_at:uint64. Set the low bit of activated_at without changing
    // config, accounting, resolution, or dictionary references.
    bytes[14] |= 0x80;
    builder.replace_data(bytes, valid_data.bit_length());
    let prepopulated_data = builder.into_cell().unwrap();
    let mut decoded = SliceData::load_cell(prepopulated_data.clone()).unwrap();
    decoded.get_next_u32().unwrap();
    decoded.get_next_u16().unwrap();
    decoded.get_next_bit().unwrap();
    assert_eq!(decoded.get_next_u64().unwrap(), 1, "test mutation must set activated_at");

    let mut bc = Blockchain::with_global_version(14).unwrap();
    bc.set_workchain(-1);
    let owner = bc.treasury("prepopulated-init-owner", 25_000 * TOS).unwrap();
    let state_init = StateInit::with_code_and_data(
        PredictionMarketContractV1::code().unwrap(),
        prepopulated_data,
    );
    let state = state_init.write_to_new_cell().unwrap().into_cell().unwrap();
    let market = MsgAddressInt::with_params(-1, state.hash(0)).unwrap();
    let result = bc
        .send_message(
            MessageBuilder::internal(owner.address(), &market, 2 * TOS)
                .bounce(true)
                .state_init(state_init)
                .body(PredictionMarketContractV1::activate(1).unwrap())
                .build(),
        )
        .unwrap();
    result.expect_aborted();
    let state = bc.run_get_method(&market, "get_prediction_state", vec![]).unwrap();
    state.expect_success();
    assert_eq!(state.int_at(0), 0, "pre-populated runtime must not activate the market");
    assert_eq!(state.int_at(1), 1, "failed activation must not rewrite the supplied runtime");
}

#[test]
fn prepopulated_state_init_liability_cannot_activate_the_production_contract() {
    let template = Fixture::new();
    let valid_data = PredictionMarketContractV1::build_data(&template.init).unwrap();
    let mut liabilities = BuilderData::new();
    liabilities.append_u32(0x504d_4c31).unwrap();
    for _ in 0..7 {
        Coins::new(0).write_to(&mut liabilities).unwrap();
    }
    let mut accounting = BuilderData::new();
    accounting
        .append_u32(0x504d_4131)
        .unwrap()
        .append_u32(1)
        .unwrap() // participant_count
        .append_u32(0)
        .unwrap()
        .append_u64(0)
        .unwrap()
        .append_u64(0)
        .unwrap()
        .checked_append_reference(liabilities.into_cell().unwrap())
        .unwrap();
    let mut root = BuilderData::from_cell(&valid_data).unwrap();
    root.replace_reference_cell(1, accounting.into_cell().unwrap());
    let prepopulated_data = root.into_cell().unwrap();

    let mut bc = Blockchain::with_global_version(14).unwrap();
    bc.set_workchain(-1);
    let owner = bc.treasury("prepopulated-liability-owner", 25_000 * TOS).unwrap();
    let state_init = StateInit::with_code_and_data(
        PredictionMarketContractV1::code().unwrap(),
        prepopulated_data,
    );
    let state = state_init.write_to_new_cell().unwrap().into_cell().unwrap();
    let market = MsgAddressInt::with_params(-1, state.hash(0)).unwrap();
    let result = bc
        .send_message(
            MessageBuilder::internal(owner.address(), &market, 2 * TOS)
                .bounce(true)
                .state_init(state_init)
                .body(PredictionMarketContractV1::activate(1).unwrap())
                .build(),
        )
        .unwrap();
    result.expect_aborted();
    let accounting = bc.run_get_method(&market, "get_prediction_accounting", vec![]).unwrap();
    accounting.expect_success();
    assert_eq!(accounting.int_at(0), 1, "failed activation must not normalize seeded liabilities");
    let state = bc.run_get_method(&market, "get_prediction_state", vec![]).unwrap();
    state.expect_success();
    assert_eq!(state.int_at(0), 0, "seeded liability must not activate the market");
}

#[test]
fn zero_oracle_threshold_in_a_structurally_valid_config_cannot_activate() {
    let template = Fixture::new();
    let valid_data = PredictionMarketContractV1::build_data(&template.init).unwrap();

    // Preserve the canonical reporter dictionary and every surrounding cell;
    // mutate only normal_policy.threshold. This bypasses the Rust-side builder
    // validation and proves the production contract rejects the economic
    // invariant itself while parsing a structurally valid StateInit DAG.
    let config = valid_data.reference(0).unwrap();
    let policies = config.reference(3).unwrap();
    let normal_policy = policies.reference(0).unwrap();
    let mut normal_builder = BuilderData::from_cell(&normal_policy).unwrap();
    let mut normal_data = normal_builder.data().to_vec();
    assert_eq!(normal_data[4], template.init.normal_oracle_policy.threshold);
    normal_data[4] = 0;
    normal_builder.replace_data(normal_data, normal_policy.bit_length());

    let mut policies_builder = BuilderData::from_cell(&policies).unwrap();
    policies_builder.replace_reference_cell(0, normal_builder.into_cell().unwrap());
    let mut config_builder = BuilderData::from_cell(&config).unwrap();
    config_builder.replace_reference_cell(3, policies_builder.into_cell().unwrap());
    let mut root_builder = BuilderData::from_cell(&valid_data).unwrap();
    root_builder.replace_reference_cell(0, config_builder.into_cell().unwrap());
    let invalid_data = root_builder.into_cell().unwrap();

    let mut bc = Blockchain::with_global_version(14).unwrap();
    bc.set_workchain(-1);
    let owner = bc.treasury("zero-threshold-owner", 25_000 * TOS).unwrap();
    let state_init =
        StateInit::with_code_and_data(PredictionMarketContractV1::code().unwrap(), invalid_data);
    let state = state_init.write_to_new_cell().unwrap().into_cell().unwrap();
    let market = MsgAddressInt::with_params(-1, state.hash(0)).unwrap();
    let result = bc
        .send_message(
            MessageBuilder::internal(owner.address(), &market, 2 * TOS)
                .bounce(true)
                .state_init(state_init)
                .body(PredictionMarketContractV1::activate(1).unwrap())
                .build(),
        )
        .unwrap();
    result.expect_aborted();
    let state = bc.run_get_method(&market, "get_prediction_state", vec![]).unwrap();
    state.expect_success();
    assert_eq!(state.int_at(0), 0, "zero threshold must not activate the market");
}

#[test]
fn typed_reserve_top_up_is_exact_bounceable_and_state_neutral() {
    let mut f = Fixture::new();
    let owner = f.owner.address().clone();
    let before = f.bc.get_account(&f.market).unwrap();
    let before_data_hash = before.get_data_hash().unwrap();
    let before_balance = before.balance().unwrap().coins.as_u64().unwrap();

    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::top_up_reserve(77).unwrap())
        .expect_success()
        .expect_out_msgs(0);

    let after = f.bc.get_account(&f.market).unwrap();
    assert_eq!(after.get_data_hash().unwrap(), before_data_hash, "top-up must not mutate state");
    assert!(
        after.balance().unwrap().coins.as_u64().unwrap() > before_balance,
        "the value left after compute fees must remain in the market reserve"
    );

    f.send(&owner, OPERATION_BUDGET - 1, PredictionMarketContractV1::top_up_reserve(78).unwrap())
        .expect_exit_code(2412);

    let non_bounce = MessageBuilder::internal(&owner, &f.market, OPERATION_BUDGET)
        .bounce(false)
        .body(PredictionMarketContractV1::top_up_reserve(79).unwrap())
        .build();
    f.bc.send_message(non_bounce).expect("send non-bounce top-up").expect_exit_code(2405);
}

#[test]
fn bounceable_state_init_message_can_deploy_and_activate_atomically() {
    let mut bc = Blockchain::with_global_version(14).expect("v14 blockchain");
    bc.set_workchain(-1);
    let owner = bc.treasury("atomic-deploy-owner", 100 * TOS).expect("owner");
    let normal = bc.treasury("atomic-deploy-normal", 10 * TOS).expect("normal");
    let appellate = bc.treasury("atomic-deploy-appellate", 10 * TOS).expect("appellate");
    let reserve = bc.treasury("atomic-deploy-reserve", 10 * TOS).expect("reserve");
    let now = u64::from(bc.now());
    let init = PredictionMarketInitV1 {
        global_id: 42,
        workchain_id: -1,
        deployment_salt: [0x91; 32],
        rules_hash: [0x92; 32],
        metadata_hash: [0x93; 32],
        reserve_recipient: reserve.address().clone(),
        trade_close: now + 1_000,
        resolve_not_before: now + 1_100,
        oracle_vote_deadline: now + 1_300,
        challenge_period: 120,
        appeal_review_delay: 60,
        appeal_period: 180,
        claim_deadline: now + 2_000,
        lot_value: TOS,
        min_price_tick: 100,
        min_fill_lots: 1,
        max_order_lots: 10,
        max_locked_collateral: 10 * TOS,
        max_account_free_balance: 10 * TOS,
        max_total_free_balance: 10 * TOS,
        max_total_liability: 30 * TOS,
        max_participants: 2,
        max_orders_per_participant: 2,
        max_live_order_records: 4,
        participant_entry_fee: TOS / 1_000,
        account_cleanup_bounty: TOS / 1_000,
        order_entry_fee: TOS / 1_000,
        order_cleanup_bounty: TOS / 1_000,
        operating_reserve_floor: TOS,
        terminal_tombstone_reserve: TOS / 10,
        challenge_bond: TOS / 10,
        challenge_processing_fee: TOS / 100,
        normal_oracle_policy: PredictionOraclePolicyV1 {
            threshold: 1,
            reporters: vec![normal.address().clone()],
        },
        appellate_oracle_policy: PredictionOraclePolicyV1 {
            threshold: 1,
            reporters: vec![appellate.address().clone()],
        },
    };
    let market = PredictionMarketContractV1::calculate_address(&init).unwrap();
    let deploy = MessageBuilder::internal(owner.address(), &market, 2 * TOS)
        .bounce(true)
        .state_init(PredictionMarketContractV1::build_state_init(&init).unwrap())
        .body(PredictionMarketContractV1::activate(7).unwrap())
        .build();
    bc.send_message(deploy).unwrap().expect_success();
    let state = bc.run_get_method(&market, "get_prediction_state", vec![]).unwrap();
    state.expect_success();
    assert_eq!(state.int_at(0), 1);
    assert_eq!(state.int_at(2), 0);
}

#[test]
fn activate_register_split_merge_and_withdraw_preserve_accounting() {
    let mut f = Fixture::new();
    let pre =
        f.bc.run_get_method(&f.market, "get_prediction_state", vec![])
            .expect("state getter before activation");
    assert_eq!(pre.exit_code, 0, "initial state must be parseable");
    let owner = f.owner.address().clone();
    let result = f.send(
        &owner,
        f.init.operating_reserve_floor + OPERATION_BUDGET,
        PredictionMarketContractV1::activate(1).unwrap(),
    );
    assert_success("activate", &result);

    let credited = 5 * TOS;
    let key = SigningKey::from_bytes(&[0x51; 32]).verifying_key().to_bytes();
    let register_value =
        credited + f.init.participant_entry_fee + f.init.account_cleanup_bounty + OPERATION_BUDGET;
    f.send(
        &owner,
        register_value,
        PredictionMarketContractV1::register_and_deposit(2, credited, key).unwrap(),
    )
    .expect_success();
    assert_eq!(f.accounting(), vec![1, 0, 0, 0, credited as i128, 0, 0, 0, 0, 0, 1_000_000]);

    let result = f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::split(3, 2).unwrap());
    assert_success("split", &result);
    assert_eq!(f.accounting()[3..6], [2, 3 * TOS as i128, 2 * TOS as i128]);

    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::merge(4, 1).unwrap())
        .expect_success();
    assert_eq!(f.accounting()[3..6], [1, 4 * TOS as i128, TOS as i128]);

    let before = f.bc.get_account(&owner).unwrap().balance().unwrap().coins.as_u64().unwrap();
    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::withdraw(5, TOS).unwrap())
        .expect_success()
        .expect_out_msgs(1);
    assert_eq!(f.accounting()[4], 3 * TOS as i128);
    let after = f.bc.get_account(&owner).unwrap().balance().unwrap().coins.as_u64().unwrap();
    assert!(after > before, "strict payout must reach the owner treasury");
}

#[test]
fn maximum_free_withdrawal_survives_real_storage_rent_collection() {
    let mut f = Fixture::new_with(|init| {
        // Keep the withdrawal window open while the executor advances far enough
        // to collect a material, nonzero storage fee from the market account.
        init.claim_deadline = init.trade_close + 100 * 24 * 60 * 60;
        init.operating_reserve_floor = 100 * TOS;
    });
    f.activate();
    let owner = f.owner.address().clone();
    let key = SigningKey::from_bytes(&[0x5a; 32]);
    f.register(&owner, &key, 2);
    // Storage rent is paid from physical operating funds, not participant
    // liabilities. Fund the selected horizon explicitly before advancing time.
    f.send(&owner, 50 * TOS, PredictionMarketContractV1::top_up_reserve(3).unwrap())
        .expect_success();

    let withdrawable = f.account(&owner)[0] as u64;
    assert!(withdrawable > 0, "fixture must create a positive free balance");
    f.bc.set_now(f.bc.now() + 30 * 24 * 60 * 60);

    let owner_before = f.bc.get_account(&owner).unwrap().balance().unwrap().coins.as_u64().unwrap();
    let result = f.send(
        &owner,
        OPERATION_BUDGET,
        PredictionMarketContractV1::withdraw(4, withdrawable).unwrap(),
    );
    assert_success("maximum free withdrawal after rent", &result);
    result.expect_out_msgs(1);
    let description = result.read_primary_description();
    let storage = description
        .storage_ph
        .as_ref()
        .expect("ordinary market transaction must have a storage phase");
    assert!(
        storage.storage_fees_collected.as_u128() > 0,
        "the delayed withdrawal must collect actual market storage rent"
    );
    assert_eq!(f.account(&owner)[0], 0, "the complete recorded free balance was not withdrawn");
    let owner_after = f.bc.get_account(&owner).unwrap().balance().unwrap().coins.as_u64().unwrap();
    assert!(owner_after > owner_before, "strict payout must still reach the owner after rent");
}

#[test]
fn no_bounce_withdrawal_credits_an_aborting_recipient_without_a_market_bounce() {
    let mut f = Fixture::new();
    f.activate();
    let owner = f.owner.address().clone();
    let key = SigningKey::from_bytes(&[0x5b; 32]);
    f.register(&owner, &key, 2);

    let mut recipient = f.bc.get_account(&owner).cloned().expect("owner account");
    assert!(recipient.set_code(always_abort_recipient_code()), "owner must remain active");
    f.bc.set_account(owner.clone(), recipient);

    let amount = TOS;
    let free_before = f.account(&owner)[0] as u64;
    let recipient_before =
        f.bc.get_account(&owner).unwrap().balance().unwrap().coins.as_u64().unwrap();
    let result =
        f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::withdraw(3, amount).unwrap());
    result.expect_success().expect_out_msgs(1);
    let recipient_transactions = result.transactions_for(&owner);
    assert_eq!(
        recipient_transactions.len(),
        1,
        "withdrawal must create exactly one recipient delivery"
    );
    let recipient_description = match recipient_transactions[0].read_description().unwrap() {
        chain_block::TransactionDescr::Ordinary(description) => description,
        other => panic!("expected ordinary recipient transaction, got {other:?}"),
    };
    assert!(recipient_description.aborted, "recipient probe must abort its compute phase");
    assert_eq!(
        result.transactions_for(&f.market).len(),
        1,
        "a non-bounce payout must not create a late bounce back to the market"
    );
    assert_eq!(
        f.account(&owner)[0] as u64,
        free_before - amount,
        "aborting recipient must not restore free balance"
    );
    let recipient_after =
        f.bc.get_account(&owner).unwrap().balance().unwrap().coins.as_u64().unwrap();
    assert!(
        recipient_after > recipient_before,
        "non-bounce payout did not credit the recipient account"
    );
}

#[test]
fn participant_cap_rejects_a_new_account_without_mutating_accounting() {
    let mut f = Fixture::new_with(|init| init.max_participants = 2);
    f.activate();
    let owner = f.owner.address().clone();
    let trader = f.trader_b.address().clone();
    let owner_key = SigningKey::from_bytes(&[0x51; 32]);
    let trader_key = SigningKey::from_bytes(&[0x52; 32]);
    f.register(&owner, &owner_key, 2);
    f.register(&trader, &trader_key, 3);
    let before = f.accounting();
    let extra = f.bc.treasury("prediction-third-participant", 25_000 * TOS).expect("third trader");
    let result = f.send(
        extra.address(),
        10 * TOS + f.init.participant_entry_fee + f.init.account_cleanup_bounty + OPERATION_BUDGET,
        PredictionMarketContractV1::register_and_deposit(
            4,
            10 * TOS,
            SigningKey::from_bytes(&[0x53; 32]).verifying_key().to_bytes(),
        )
        .unwrap(),
    );
    assert!(result.read_primary_description().aborted, "participant cap admitted a third account");
    assert_eq!(f.accounting(), before, "failed participant admission mutated accounting");
}

#[test]
fn owner_order_and_global_live_order_caps_fail_closed() {
    fn matched_buy_pair(
        fixture: &mut Fixture,
        owner: &MsgAddressInt,
        trader: &MsgAddressInt,
        owner_key: &SigningKey,
        trader_key: &SigningKey,
        nonce: u64,
    ) -> SendResult {
        let yes = fixture.signed_order(
            owner,
            owner_key,
            nonce,
            PredictionOrderActionV1::Buy,
            PredictionOrderOutcomeV1::Yes,
            PredictionLiquidityRoleV1::Maker,
            6_000,
            1,
        );
        let no = fixture.signed_order(
            trader,
            trader_key,
            nonce,
            PredictionOrderActionV1::Buy,
            PredictionOrderOutcomeV1::No,
            PredictionLiquidityRoleV1::Taker,
            4_000,
            1,
        );
        fixture.send(
            owner,
            2 * TOS,
            PredictionMarketContractV1::match_pair(nonce + 10, 1, yes, no).unwrap(),
        )
    }

    let mut per_owner = Fixture::new_with(|init| {
        init.max_orders_per_participant = 2;
        init.max_live_order_records = 8;
    });
    per_owner.activate();
    let owner = per_owner.owner.address().clone();
    let trader = per_owner.trader_b.address().clone();
    let owner_key = SigningKey::from_bytes(&[0x54; 32]);
    let trader_key = SigningKey::from_bytes(&[0x55; 32]);
    per_owner.register(&owner, &owner_key, 2);
    per_owner.register(&trader, &trader_key, 3);
    assert_success(
        "first owner order",
        &matched_buy_pair(&mut per_owner, &owner, &trader, &owner_key, &trader_key, 1),
    );
    assert_success(
        "second owner order",
        &matched_buy_pair(&mut per_owner, &owner, &trader, &owner_key, &trader_key, 2),
    );
    let before = per_owner.accounting();
    let rejected = matched_buy_pair(&mut per_owner, &owner, &trader, &owner_key, &trader_key, 3);
    assert!(
        rejected.read_primary_description().aborted,
        "per-owner order cap admitted a third live order"
    );
    assert_eq!(
        per_owner.accounting(),
        before,
        "failed per-owner order admission mutated accounting"
    );

    let mut global = Fixture::new_with(|init| {
        init.max_orders_per_participant = 8;
        init.max_live_order_records = 4;
    });
    global.activate();
    let owner = global.owner.address().clone();
    let trader = global.trader_b.address().clone();
    let owner_key = SigningKey::from_bytes(&[0x56; 32]);
    let trader_key = SigningKey::from_bytes(&[0x57; 32]);
    global.register(&owner, &owner_key, 2);
    global.register(&trader, &trader_key, 3);
    assert_success(
        "first global order",
        &matched_buy_pair(&mut global, &owner, &trader, &owner_key, &trader_key, 1),
    );
    assert_success(
        "second global order",
        &matched_buy_pair(&mut global, &owner, &trader, &owner_key, &trader_key, 2),
    );
    let before = global.accounting();
    let rejected = matched_buy_pair(&mut global, &owner, &trader, &owner_key, &trader_key, 3);
    assert!(
        rejected.read_primary_description().aborted,
        "global live-order cap admitted excess records"
    );
    assert_eq!(global.accounting(), before, "failed global order admission mutated accounting");
}

#[test]
fn all_three_match_classes_conserve_collateral_on_the_production_boc() {
    let mut f = Fixture::new();
    f.activate();
    let a = f.owner.address().clone();
    let b = f.trader_b.address().clone();
    let key_a = SigningKey::from_bytes(&[0x61; 32]);
    let key_b = SigningKey::from_bytes(&[0x62; 32]);
    f.register(&a, &key_a, 2);
    f.register(&b, &key_b, 3);

    let buy_yes = f.signed_order(
        &a,
        &key_a,
        1,
        PredictionOrderActionV1::Buy,
        PredictionOrderOutcomeV1::Yes,
        PredictionLiquidityRoleV1::Maker,
        6_000,
        4,
    );
    let buy_no = f.signed_order(
        &b,
        &key_b,
        1,
        PredictionOrderActionV1::Buy,
        PredictionOrderOutcomeV1::No,
        PredictionLiquidityRoleV1::Taker,
        4_000,
        4,
    );
    let result =
        f.send(&a, 2 * TOS, PredictionMarketContractV1::match_pair(4, 2, buy_yes, buy_no).unwrap());
    assert_success("complementary buy", &result);
    let owner_cell = a.write_to_new_cell().unwrap().into_cell().unwrap();
    let owner_slice = SliceData::load_cell(owner_cell).unwrap();
    let bound_order =
        f.bc.run_get_method(
            &f.market,
            "get_prediction_order",
            vec![StackItem::Slice(owner_slice.clone()), StackItem::int(0), StackItem::int(1)],
        )
        .expect("bound order getter");
    bound_order.expect_success();
    assert_eq!(bound_order.int_at(0), 1);
    assert_eq!(bound_order.int_at(2), 4);
    assert_eq!(bound_order.int_at(3), 2);
    assert_eq!(bound_order.int_at(5), 0);
    let unused_order =
        f.bc.run_get_method(
            &f.market,
            "get_prediction_order",
            vec![StackItem::Slice(owner_slice), StackItem::int(0), StackItem::int(99)],
        )
        .expect("unused order getter");
    unused_order.expect_success();
    assert_eq!(unused_order.int_at(0), 0);
    assert_eq!(f.accounting()[0..6], [2, 2, 1, 2, 18 * TOS as i128, 2 * TOS as i128]);
    assert_eq!(&f.account(&a)[1..3], &[2, 0]);
    assert_eq!(&f.account(&b)[1..3], &[0, 2]);

    let sell_yes = f.signed_order(
        &a,
        &key_a,
        2,
        PredictionOrderActionV1::Sell,
        PredictionOrderOutcomeV1::Yes,
        PredictionLiquidityRoleV1::Maker,
        7_000,
        1,
    );
    let buy_yes = f.signed_order(
        &b,
        &key_b,
        2,
        PredictionOrderActionV1::Buy,
        PredictionOrderOutcomeV1::Yes,
        PredictionLiquidityRoleV1::Taker,
        7_000,
        1,
    );
    let result = f.send(
        &b,
        2 * TOS,
        PredictionMarketContractV1::match_pair(5, 1, sell_yes, buy_yes).unwrap(),
    );
    assert_success("same-side transfer", &result);
    assert_eq!(f.accounting()[3..6], [2, 18 * TOS as i128, 2 * TOS as i128]);
    assert_eq!(&f.account(&a)[1..3], &[1, 0]);
    assert_eq!(&f.account(&b)[1..3], &[1, 2]);

    let sell_yes = f.signed_order(
        &a,
        &key_a,
        3,
        PredictionOrderActionV1::Sell,
        PredictionOrderOutcomeV1::Yes,
        PredictionLiquidityRoleV1::Maker,
        5_000,
        1,
    );
    let sell_no = f.signed_order(
        &b,
        &key_b,
        3,
        PredictionOrderActionV1::Sell,
        PredictionOrderOutcomeV1::No,
        PredictionLiquidityRoleV1::Taker,
        5_000,
        1,
    );
    let result = f.send(
        &a,
        2 * TOS,
        PredictionMarketContractV1::match_pair(6, 1, sell_yes, sell_no).unwrap(),
    );
    assert_success("complementary sell", &result);
    assert_eq!(f.accounting()[0..6], [2, 6, 3, 1, 19 * TOS as i128, TOS as i128]);
    assert_eq!(&f.account(&a)[1..3], &[0, 0]);
    assert_eq!(&f.account(&b)[1..3], &[1, 1]);

    f.bc.set_now(f.init.trade_close as u32);
    f.send(
        &a,
        OPERATION_BUDGET,
        PredictionMarketContractV1::prune_owner_orders(7, &a, false).unwrap(),
    )
    .expect_success();
    f.send(
        &b,
        OPERATION_BUDGET,
        PredictionMarketContractV1::prune_owner_orders(8, &b, true).unwrap(),
    )
    .expect_success()
    .expect_out_msgs(1);
    assert_eq!(f.accounting()[1], 0);
    assert_eq!(f.account(&a)[3..6], [0, TOS as i128 / 1_000, 0]);
    assert_eq!(f.account(&b)[3..6], [0, TOS as i128 / 1_000, 0]);
}

#[test]
fn deterministic_random_sequences_match_an_independent_conservation_model() {
    let mut f = Fixture::new();
    f.activate();
    let owners = [f.owner.address().clone(), f.trader_b.address().clone()];
    let keys = [SigningKey::from_bytes(&[0x41; 32]), SigningKey::from_bytes(&[0x42; 32])];
    f.register(&owners[0], &keys[0], 2);
    f.register(&owners[1], &keys[1], 3);
    let mut model = ReferenceMarket {
        accounts: [
            ReferenceAccount { free: 10 * TOS, ..Default::default() },
            ReferenceAccount { free: 10 * TOS, ..Default::default() },
        ],
        ..Default::default()
    };
    for (index, owner) in owners.iter().enumerate() {
        assert!(model.split(index, 3, f.init.lot_value));
        f.send(
            owner,
            OPERATION_BUDGET,
            PredictionMarketContractV1::split(10 + index as u64, 3).unwrap(),
        )
        .expect_success();
    }
    model.assert_matches(&f, [&owners[0], &owners[1]]);

    let mut seed = 0x8f3d_9a21_4c77_b105_u64;
    let mut nonce = 10_u64;
    let mut exercised = 0_u8;
    for step in 0_u64..50 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let quantity = 1 + ((seed >> 33) % 2);
        let first = usize::from(((seed >> 17) & 1) != 0);
        let second = 1 - first;
        let price = 2_500_u16 + u16::try_from((seed >> 29) % 5_001).unwrap();
        let query_id = 1_000_u64.checked_add(step).unwrap();
        match step % 5 {
            0 if model.split(first, quantity, f.init.lot_value) => {
                f.send(
                    &owners[first],
                    OPERATION_BUDGET,
                    PredictionMarketContractV1::split(query_id, quantity).unwrap(),
                )
                .expect_success();
                exercised |= 1;
            }
            1 if model.merge(first, quantity, f.init.lot_value) => {
                f.send(
                    &owners[first],
                    OPERATION_BUDGET,
                    PredictionMarketContractV1::merge(query_id, quantity).unwrap(),
                )
                .expect_success();
                exercised |= 2;
            }
            2 if model.complementary_buy(first, second, quantity, f.init.lot_value, price) => {
                let yes = f.signed_order(
                    &owners[first],
                    &keys[first],
                    nonce,
                    PredictionOrderActionV1::Buy,
                    PredictionOrderOutcomeV1::Yes,
                    PredictionLiquidityRoleV1::Maker,
                    price,
                    quantity,
                );
                let no = f.signed_order(
                    &owners[second],
                    &keys[second],
                    nonce.checked_add(1).unwrap(),
                    PredictionOrderActionV1::Buy,
                    PredictionOrderOutcomeV1::No,
                    PredictionLiquidityRoleV1::Taker,
                    10_000_u16.checked_sub(price).unwrap(),
                    quantity,
                );
                nonce = nonce.checked_add(2).unwrap();
                f.send(
                    &owners[first],
                    2 * TOS,
                    PredictionMarketContractV1::match_pair(query_id, quantity, yes, no).unwrap(),
                )
                .expect_success();
                exercised |= 4;
            }
            3 if model.transfer_yes(first, second, quantity, f.init.lot_value, price) => {
                let sell = f.signed_order(
                    &owners[first],
                    &keys[first],
                    nonce,
                    PredictionOrderActionV1::Sell,
                    PredictionOrderOutcomeV1::Yes,
                    PredictionLiquidityRoleV1::Maker,
                    price,
                    quantity,
                );
                let buy = f.signed_order(
                    &owners[second],
                    &keys[second],
                    nonce.checked_add(1).unwrap(),
                    PredictionOrderActionV1::Buy,
                    PredictionOrderOutcomeV1::Yes,
                    PredictionLiquidityRoleV1::Taker,
                    price,
                    quantity,
                );
                nonce = nonce.checked_add(2).unwrap();
                f.send(
                    &owners[second],
                    2 * TOS,
                    PredictionMarketContractV1::match_pair(query_id, quantity, sell, buy).unwrap(),
                )
                .expect_success();
                exercised |= 8;
            }
            4 if model.complementary_sell(first, second, quantity, f.init.lot_value, price) => {
                let yes = f.signed_order(
                    &owners[first],
                    &keys[first],
                    nonce,
                    PredictionOrderActionV1::Sell,
                    PredictionOrderOutcomeV1::Yes,
                    PredictionLiquidityRoleV1::Maker,
                    price,
                    quantity,
                );
                let no = f.signed_order(
                    &owners[second],
                    &keys[second],
                    nonce.checked_add(1).unwrap(),
                    PredictionOrderActionV1::Sell,
                    PredictionOrderOutcomeV1::No,
                    PredictionLiquidityRoleV1::Taker,
                    10_000_u16.checked_sub(price).unwrap(),
                    quantity,
                );
                nonce = nonce.checked_add(2).unwrap();
                f.send(
                    &owners[first],
                    2 * TOS,
                    PredictionMarketContractV1::match_pair(query_id, quantity, yes, no).unwrap(),
                )
                .expect_success();
                exercised |= 16;
            }
            _ => {}
        }
        model.assert_matches(&f, [&owners[0], &owners[1]]);
    }
    assert_eq!(exercised, 31, "the deterministic sequence missed an operation class");

    // Finish the same randomized state through a production resolution, then
    // claim in the reverse participant order and withdraw every remaining free
    // balance.  The pre-final Q invariant deliberately no longer applies here:
    // the terminal invariant is remaining payout plus claimed payout.
    let keeper = f.trader_b.address().clone();
    let normal = f.normal.address().clone();
    f.bc.set_now(f.init.resolve_not_before as u32);
    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(2_000).unwrap())
        .expect_success();
    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(2_001).unwrap())
        .expect_success();
    let normal_context = f.phase().3;
    f.send(
        &normal,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(
            2_002,
            0,
            normal_context,
            0,
            [0xd1; 32],
            u64::from(f.bc.now()),
            f.init.oracle_vote_deadline,
        )
        .unwrap(),
    )
    .expect_success();
    let finalization_deadline = f.phase().6;
    f.bc.set_now(finalization_deadline as u32);
    f.send(
        &keeper,
        OPERATION_BUDGET,
        PredictionMarketContractV1::finalize_uncontested(2_003).unwrap(),
    )
    .expect_success();

    let final_backing = model.complete_sets.checked_mul(f.init.lot_value).unwrap();
    let accounting = f.accounting();
    assert_eq!(accounting[5], 0, "finalization must clear locked backing");
    assert_eq!(accounting[6], final_backing as i128, "final backing diverged from the model");
    assert_eq!(
        accounting[7], final_backing as i128,
        "all final backing must begin as payout liability"
    );
    assert_eq!(accounting[8], 0, "no claim may be recorded before a claim");

    let mut cumulative_claimed = 0_u64;
    for index in [1_usize, 0] {
        let payout = model.accounts[index].yes.checked_mul(f.init.lot_value).unwrap();
        f.send(
            &keeper,
            OPERATION_BUDGET,
            PredictionMarketContractV1::claim(2_010 + index as u64, &owners[index]).unwrap(),
        )
        .expect_success();
        model.accounts[index].free = model.accounts[index].free.checked_add(payout).unwrap();
        model.accounts[index].yes = 0;
        model.accounts[index].no = 0;
        cumulative_claimed = cumulative_claimed.checked_add(payout).unwrap();
        let accounting = f.accounting();
        assert_eq!(
            accounting[7] as u64 + cumulative_claimed,
            final_backing,
            "remaining payout plus cumulative claims must equal final backing"
        );
        assert_eq!(f.account(&owners[index])[0] as u64, model.accounts[index].free);
    }
    assert_eq!(f.accounting()[7], 0, "all payout liability must be exhausted after both claims");
    assert_eq!(f.accounting()[8], final_backing as i128);

    for index in [0_usize, 1] {
        let amount = model.accounts[index].free;
        if amount > 0 {
            f.send(
                &owners[index],
                OPERATION_BUDGET,
                PredictionMarketContractV1::withdraw(2_020 + index as u64, amount).unwrap(),
            )
            .expect_success();
        }
        model.accounts[index].free = 0;
        assert_eq!(f.account(&owners[index])[0], 0, "withdraw must exhaust modeled free balance");
    }
    assert_eq!(f.accounting()[4], 0, "all participant free liability must be withdrawn");
}

fn run_partitioned_fill(parts: u64) -> ([i128; 3], [i128; 3], [i128; 4]) {
    assert!(parts > 0 && 10_000_u64.checked_rem(parts) == Some(0));
    let mut f = Fixture::new_with(|init| {
        init.lot_value = 10_000;
        init.max_order_lots = 10_000;
        init.max_locked_collateral = TOS;
        init.max_account_free_balance = TOS;
        init.max_total_free_balance = 2_u64.checked_mul(TOS).unwrap();
        init.max_total_liability = 5_u64.checked_mul(TOS).unwrap();
    });
    f.activate();
    let owners = [f.owner.address().clone(), f.trader_b.address().clone()];
    let keys = [SigningKey::from_bytes(&[0x31; 32]), SigningKey::from_bytes(&[0x32; 32])];
    let credited = 200_000_000_u64;
    for (index, owner) in owners.iter().enumerate() {
        let value = credited
            .checked_add(f.init.participant_entry_fee)
            .and_then(|amount| amount.checked_add(f.init.account_cleanup_bounty))
            .and_then(|amount| amount.checked_add(OPERATION_BUDGET))
            .unwrap();
        f.send(
            owner,
            value,
            PredictionMarketContractV1::register_and_deposit(
                20_u64.checked_add(index as u64).unwrap(),
                credited,
                keys[index].verifying_key().to_bytes(),
            )
            .unwrap(),
        )
        .expect_success();
    }
    let buy_yes = f.signed_order(
        &owners[0],
        &keys[0],
        1,
        PredictionOrderActionV1::Buy,
        PredictionOrderOutcomeV1::Yes,
        PredictionLiquidityRoleV1::Maker,
        6_000,
        10_000,
    );
    let buy_no = f.signed_order(
        &owners[1],
        &keys[1],
        1,
        PredictionOrderActionV1::Buy,
        PredictionOrderOutcomeV1::No,
        PredictionLiquidityRoleV1::Taker,
        4_000,
        10_000,
    );
    let chunk = 10_000_u64.checked_div(parts).unwrap();
    for index in 0..parts {
        f.send(
            &owners[0],
            2_u64.checked_mul(TOS).unwrap(),
            PredictionMarketContractV1::match_pair(
                100_u64.checked_add(index).unwrap(),
                chunk,
                buy_yes.clone(),
                buy_no.clone(),
            )
            .unwrap(),
        )
        .expect_success();
    }
    let accounting = f.accounting();
    assert_eq!(accounting[0], 2);
    assert_eq!(accounting[1], 2);
    assert_eq!(accounting[2], i128::from(parts));
    assert_eq!(accounting[3], 10_000);
    assert_eq!(accounting[4], 300_000_000);
    assert_eq!(accounting[5], 100_000_000);
    assert_eq!(accounting[10], 4_000_000);
    let left = f.account(&owners[0]);
    let right = f.account(&owners[1]);
    let left = [left[0], left[1], left[2]];
    let right = [right[0], right[1], right[2]];
    assert_eq!(left, [140_000_000, 10_000, 0]);
    assert_eq!(right, [160_000_000, 0, 10_000]);
    (left, right, [accounting[3], accounting[4], accounting[5], accounting[10]])
}

#[test]
#[ignore = "release-scale production-BOC gate; executes 10,011 real match transactions"]
fn one_ten_and_ten_thousand_partial_fills_are_economically_identical() {
    let single = run_partitioned_fill(1);
    let ten = run_partitioned_fill(10);
    let ten_thousand = run_partitioned_fill(10_000);
    assert_eq!(single, ten);
    assert_eq!(single, ten_thousand);
}

#[test]
fn closed_empty_account_releases_all_cleanup_credit_without_a_tombstone() {
    let mut f = Fixture::new();
    f.activate();
    let owner = f.owner.address().clone();
    let keeper = f.trader_b.address().clone();
    let key = SigningKey::from_bytes(&[0x70; 32]);
    f.register(&owner, &key, 2);
    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::withdraw(3, 10 * TOS).unwrap())
        .expect_success();
    f.bc.set_now(f.init.trade_close as u32);
    f.send(
        &keeper,
        OPERATION_BUDGET,
        PredictionMarketContractV1::close_empty_account(4, &owner, true).unwrap(),
    )
    .expect_success()
    .expect_out_msgs(1);
    assert_eq!(f.accounting()[0], 0);
    assert_eq!(f.accounting()[10], 0);
}

#[test]
fn trading_key_and_nonce_floor_freeze_at_trade_close() {
    let mut f = Fixture::new();
    f.activate();
    let owner = f.owner.address().clone();
    let key = SigningKey::from_bytes(&[0x75; 32]);
    f.register(&owner, &key, 2);
    f.bc.set_now(f.init.trade_close as u32);
    let replacement = SigningKey::from_bytes(&[0x76; 32]);
    f.send(
        &owner,
        OPERATION_BUDGET,
        PredictionMarketContractV1::set_trading_key(3, replacement.verifying_key().to_bytes())
            .unwrap(),
    )
    .expect_exit_code(2406);
    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::raise_nonce_floor(4, 1).unwrap())
        .expect_exit_code(2406);
}

#[test]
fn resolution_context_getter_uses_unambiguous_absence_before_a_round_opens() {
    let f = Fixture::new();
    let (current, review_base) = f.resolution_contexts();
    assert!(current.is_none());
    assert!(review_base.is_none());
}

#[test]
fn challenged_normal_result_is_overturned_by_the_frozen_appellate_oracle() {
    let mut f = Fixture::new();
    f.activate();
    let owner = f.owner.address().clone();
    let challenger = f.trader_b.address().clone();
    let normal = f.normal.address().clone();
    let appellate = f.appellate.address().clone();
    let key = SigningKey::from_bytes(&[0x71; 32]);
    f.register(&owner, &key, 2);
    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::split(3, 2).unwrap())
        .expect_success();

    f.bc.set_now(f.init.resolve_not_before as u32);
    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(4).unwrap())
        .expect_success();
    assert_eq!(f.phase().0, 1);
    assert_eq!(f.phase().3, [0; 32], "phase entry must not also open a round nonce");
    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(40).unwrap())
        .expect_success();
    let (status, _, _, normal_context, _, _, _) = f.phase();
    assert_eq!(status, 1);
    assert_ne!(normal_context, [0; 32]);
    let (current, review_base) = f.resolution_contexts();
    assert_eq!(*current.as_ref().unwrap().repr_hash().as_array(), normal_context);
    assert!(review_base.is_none());
    let result = f.send(
        &normal,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(
            5,
            0,
            normal_context,
            0,
            [0x81; 32],
            u64::from(f.bc.now()),
            f.init.oracle_vote_deadline,
        )
        .unwrap(),
    );
    assert_success("normal report", &result);
    eprintln!("normal report gas: {}", compute_gas_used(&result));
    let (status, _, _, _, _, proposal_hash, _) = f.phase();
    assert_eq!(status, 2);
    assert_ne!(proposal_hash, [0; 32]);

    f.send(
        &challenger,
        OPERATION_BUDGET + f.init.challenge_bond + f.init.challenge_processing_fee,
        PredictionMarketContractV1::challenge_result(6, proposal_hash, 1, [0x82; 32]).unwrap(),
    )
    .expect_success();
    let (status, reason, _, context, base, _, _) = f.phase();
    assert_eq!((status, reason), (3, 1));
    assert_eq!(context, [0; 32], "challenge entry must not open the appeal round");
    assert_ne!(base, [0; 32]);
    let (current, review_base) = f.resolution_contexts();
    assert!(current.is_none());
    assert_eq!(*review_base.as_ref().unwrap().repr_hash().as_array(), base);

    f.bc.set_now((f.init.resolve_not_before + f.init.appeal_review_delay) as u32);
    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(7).unwrap())
        .expect_success();
    let (_, _, _, appeal_context, _, _, _) = f.phase();
    assert_ne!(appeal_context, [0; 32]);
    let (current, review_base) = f.resolution_contexts();
    assert_eq!(*current.as_ref().unwrap().repr_hash().as_array(), appeal_context);
    assert_eq!(*review_base.as_ref().unwrap().repr_hash().as_array(), base);
    let result = f.send(
        &appellate,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(
            8,
            1,
            appeal_context,
            1,
            [0x83; 32],
            u64::from(f.bc.now()),
            f.init.resolve_not_before + f.init.appeal_period,
        )
        .unwrap(),
    );
    assert_success("appellate report", &result);
    eprintln!("appellate report gas: {}", compute_gas_used(&result));
    let (status, _, final_outcome, _, base_after, _, _) = f.phase();
    assert_eq!((status, final_outcome), (4, 1));
    assert_eq!(base_after, base);
    assert_eq!(f.accounting()[5..10], [0, 2 * TOS as i128, 2 * TOS as i128, 0, (TOS / 10) as i128]);

    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::claim(9, &owner).unwrap())
        .expect_success();
    assert_eq!(f.accounting()[4], 10 * TOS as i128);
    assert_eq!(f.accounting()[7], 0);

    let result = f.send(
        &f.trader_b.address().clone(),
        OPERATION_BUDGET,
        PredictionMarketContractV1::withdraw_challenge_bond(10).unwrap(),
    );
    assert_success("challenge bond withdrawal", &result);
    assert_eq!(f.accounting()[9], 0);

    f.bc.set_now(f.init.claim_deadline as u32);
    let result = f.send(
        &challenger,
        OPERATION_BUDGET,
        PredictionMarketContractV1::force_close_account(11, &owner, true).unwrap(),
    );
    result.expect_success().expect_out_msgs(2);
    let tx = result.first_transaction().unwrap();
    let mut owner_message_value = 0;
    tx.iterate_out_msgs(|message| {
        if message.dst() == Some(owner.clone()) {
            owner_message_value = message.int_header().unwrap().value.coins.as_u64().unwrap();
        }
        Ok(true)
    })
    .unwrap();
    assert_eq!(owner_message_value, 10 * TOS);
    assert_eq!(f.accounting()[0], 0);
    assert_eq!(f.accounting()[4], 0);
    assert_eq!(f.accounting()[7], 0);
    assert_eq!(f.accounting()[10], 0);

    f.send(
        &challenger,
        OPERATION_BUDGET,
        PredictionMarketContractV1::compact_terminal(12).unwrap(),
    )
    .expect_success();
    assert_eq!(f.phase().0, 5);
    assert_eq!(f.accounting()[3], 0);

    let reserve = f.reserve.address().clone();
    f.send(
        &challenger,
        OPERATION_BUDGET,
        PredictionMarketContractV1::withdraw_terminal_surplus(13, TOS).unwrap(),
    )
    .expect_exit_code(2407);
    let result = f.send(
        &reserve,
        OPERATION_BUDGET,
        PredictionMarketContractV1::withdraw_terminal_surplus(14, TOS).unwrap(),
    );
    result.expect_success().expect_out_msgs(1);
    let tx = result.first_transaction().unwrap();
    let mut reserve_message_value = 0;
    tx.iterate_out_msgs(|message| {
        if message.dst() == Some(reserve.clone()) {
            reserve_message_value = message.int_header().unwrap().value.coins.as_u64().unwrap();
        }
        Ok(true)
    })
    .unwrap();
    assert_eq!(reserve_message_value, TOS);
}

#[test]
fn uncontested_normal_quorum_finalizes_only_at_the_frozen_deadline() {
    let mut f = Fixture::new();
    f.activate();
    let owner = f.owner.address().clone();
    let normal = f.normal.address().clone();
    let outsider = f.trader_b.address().clone();
    let key = SigningKey::from_bytes(&[0x72; 32]);
    f.register(&owner, &key, 2);
    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::split(3, 1).unwrap())
        .expect_success();

    f.bc.set_now(f.init.resolve_not_before as u32);
    f.send(&outsider, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(4).unwrap())
        .expect_success();
    assert_eq!(f.phase().3, [0; 32], "phase entry must be an independent transition");
    f.send(&outsider, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(40).unwrap())
        .expect_success();
    let context = f.phase().3;

    f.send(
        &outsider,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(
            5,
            0,
            context,
            0,
            [0x91; 32],
            u64::from(f.bc.now()),
            f.init.oracle_vote_deadline,
        )
        .unwrap(),
    )
    .expect_exit_code(2428);
    assert_eq!(f.phase().0, 1, "an unauthorized sender cannot create a proposal");

    f.send(
        &normal,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(
            6,
            0,
            [0x99; 32],
            0,
            [0x91; 32],
            u64::from(f.bc.now()),
            f.init.oracle_vote_deadline,
        )
        .unwrap(),
    )
    .expect_exit_code(2427);
    assert_eq!(f.phase().0, 1, "a report cannot be replayed into another round context");

    f.send(
        &normal,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(
            7,
            0,
            context,
            0,
            [0x91; 32],
            u64::from(f.bc.now()),
            f.init.oracle_vote_deadline,
        )
        .unwrap(),
    )
    .expect_success();
    let deadline = f.phase().6;
    f.bc.set_now((deadline - 1) as u32);
    f.send(
        &outsider,
        OPERATION_BUDGET,
        PredictionMarketContractV1::finalize_uncontested(8).unwrap(),
    )
    .expect_exit_code(2406);
    assert_eq!(f.phase().0, 2);

    f.bc.set_now(deadline as u32);
    f.send(
        &outsider,
        OPERATION_BUDGET,
        PredictionMarketContractV1::finalize_uncontested(9).unwrap(),
    )
    .expect_success();
    let (status, reason, outcome, _, _, _, _) = f.phase();
    assert_eq!((status, reason, outcome), (4, 0, 0));
    assert_eq!(f.accounting()[5..8], [0, TOS as i128, TOS as i128]);
}

#[test]
fn normal_reporter_window_closes_at_the_frozen_deadline() {
    // Each case has its own production contract because a threshold-one
    // report at deadline-1 changes state to PROPOSED. The exact deadline and
    // later cases must remain REPORTING so that their rejection proves the
    // report gate itself, not a later phase's unrelated invariant.
    for (offset, accepted) in [(-1_i64, true), (0, false), (1, false)] {
        let mut f = Fixture::new();
        f.activate();
        let reporter = f.normal.address().clone();
        let keeper = f.trader_b.address().clone();
        let now = f.init.resolve_not_before as u32;
        f.bc.set_now(now);
        f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(1).unwrap())
            .expect_success();
        f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(2).unwrap())
            .expect_success();
        let context = f.phase().3;
        let deadline = f.init.oracle_vote_deadline;
        let report_at = u64::try_from(i128::from(deadline) + i128::from(offset)).unwrap();
        f.bc.set_now(report_at as u32);
        // Keep this statement intrinsically valid at every tested instant.
        // The contract must therefore reach its phase/deadline gate rather
        // than reject it earlier as malformed.
        let body = PredictionMarketContractV1::report_result(
            3,
            0,
            context,
            0,
            [0xb1; 32],
            report_at,
            report_at + 1,
        )
        .unwrap();
        let result = f.send(&reporter, OPERATION_BUDGET, body);
        if accepted {
            result.expect_success();
            assert_eq!(f.phase().0, 2, "deadline-1 report must create a proposal");
        } else {
            result.expect_exit_code(2425);
            assert_eq!(f.phase().0, 1, "late report must not change the reporting state");
        }
    }
}

#[test]
fn appellate_reporter_window_opens_after_delay_and_closes_at_deadline() {
    for (offset, accepted) in [(-1_i64, true), (0, false), (1, false)] {
        let mut f = Fixture::new();
        f.activate();
        let normal = f.normal.address().clone();
        let appellate = f.appellate.address().clone();
        let challenger = f.trader_b.address().clone();
        f.bc.set_now(f.init.resolve_not_before as u32);
        f.send(
            &challenger,
            OPERATION_BUDGET,
            PredictionMarketContractV1::advance_phase(1).unwrap(),
        )
        .expect_success();
        f.send(
            &challenger,
            OPERATION_BUDGET,
            PredictionMarketContractV1::advance_phase(2).unwrap(),
        )
        .expect_success();
        let normal_context = f.phase().3;
        let report_at = u64::from(f.bc.now());
        f.send(
            &normal,
            OPERATION_BUDGET,
            PredictionMarketContractV1::report_result(
                3,
                0,
                normal_context,
                0,
                [0xc1; 32],
                report_at,
                f.init.oracle_vote_deadline,
            )
            .unwrap(),
        )
        .expect_success();
        let proposal = f.phase().5;
        f.send(
            &challenger,
            OPERATION_BUDGET + f.init.challenge_bond + f.init.challenge_processing_fee,
            PredictionMarketContractV1::challenge_result(4, proposal, 1, [0xc2; 32]).unwrap(),
        )
        .expect_success();
        let review_base = f.phase().4;
        assert_ne!(review_base, [0; 32]);
        assert_eq!(f.phase().3, [0; 32], "challenge must not open the appeal nonce early");

        let vote_not_before = f.init.resolve_not_before + f.init.appeal_review_delay;
        f.bc.set_now((vote_not_before - 1) as u32);
        f.send(
            &challenger,
            OPERATION_BUDGET,
            PredictionMarketContractV1::report_result(
                5,
                1,
                review_base,
                1,
                [0xc3; 32],
                vote_not_before - 1,
                vote_not_before,
            )
            .unwrap(),
        )
        .expect_exit_code(2426);

        f.bc.set_now(vote_not_before as u32);
        f.send(
            &challenger,
            OPERATION_BUDGET,
            PredictionMarketContractV1::advance_phase(6).unwrap(),
        )
        .expect_success();
        let appeal_context = f.phase().3;
        assert_ne!(appeal_context, [0; 32], "review delay expiry must open the appeal nonce");
        let deadline = f.phase().6;
        let vote_at = u64::try_from(i128::from(deadline) + i128::from(offset)).unwrap();
        f.bc.set_now(vote_at as u32);
        let body = PredictionMarketContractV1::report_result(
            7,
            1,
            appeal_context,
            1,
            [0xc4; 32],
            vote_at,
            vote_at + 1,
        )
        .unwrap();
        let result = f.send(&appellate, OPERATION_BUDGET, body);
        if accepted {
            result.expect_success();
            assert_eq!(f.phase().0, 4, "deadline-1 appeal report must finalize");
        } else {
            result.expect_exit_code(2425);
            assert_eq!(f.phase().0, 3, "late appeal report must preserve review state");
        }
    }
}

#[test]
fn normal_oracle_requires_exact_threshold_without_duplicate_counting() {
    let mut f = Fixture::new_with(|init| {
        init.normal_oracle_policy.threshold = 2;
        init.normal_oracle_policy.reporters.push(init.reserve_recipient.clone());
    });
    f.activate();
    let first = f.normal.address().clone();
    let second = f.reserve.address().clone();
    let keeper = f.trader_b.address().clone();
    f.bc.set_now(f.init.resolve_not_before as u32);
    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(1).unwrap())
        .expect_success();
    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(2).unwrap())
        .expect_success();
    let context = f.phase().3;
    let now = u64::from(f.bc.now());
    let deadline = f.init.oracle_vote_deadline;
    let report = |query_id| {
        PredictionMarketContractV1::report_result(
            query_id, 0, context, 0, [0xd1; 32], now, deadline,
        )
        .unwrap()
    };

    f.send(&first, OPERATION_BUDGET, report(3)).expect_success();
    assert_eq!(f.phase().0, 1, "M-1 reports must not create a proposal");
    f.send(&first, OPERATION_BUDGET, report(4)).expect_success();
    assert_eq!(f.phase().0, 1, "duplicate reporter vote must be idempotent");
    f.send(
        &first,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(5, 0, context, 1, [0xd2; 32], now, deadline)
            .unwrap(),
    )
    .expect_exit_code(2429);
    assert_eq!(f.phase().0, 1, "equivocation must not create a proposal");
    f.send(&second, OPERATION_BUDGET, report(6)).expect_success();
    assert_eq!(f.phase().0, 2, "exactly M independent reporters must create a proposal");
}

#[test]
fn appellate_oracle_requires_exact_threshold_without_duplicate_counting() {
    let mut f = Fixture::new_with(|init| {
        init.appellate_oracle_policy.threshold = 2;
        init.appellate_oracle_policy.reporters.push(init.reserve_recipient.clone());
    });
    f.activate();
    let normal = f.normal.address().clone();
    let first = f.appellate.address().clone();
    let second = f.reserve.address().clone();
    let challenger = f.trader_b.address().clone();
    f.bc.set_now(f.init.resolve_not_before as u32);
    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(1).unwrap())
        .expect_success();
    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(2).unwrap())
        .expect_success();
    let normal_context = f.phase().3;
    let normal_now = u64::from(f.bc.now());
    f.send(
        &normal,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(
            3,
            0,
            normal_context,
            0,
            [0xe1; 32],
            normal_now,
            f.init.oracle_vote_deadline,
        )
        .unwrap(),
    )
    .expect_success();
    f.send(
        &challenger,
        OPERATION_BUDGET + f.init.challenge_bond + f.init.challenge_processing_fee,
        PredictionMarketContractV1::challenge_result(4, f.phase().5, 1, [0xe2; 32]).unwrap(),
    )
    .expect_success();
    f.bc.set_now((f.init.resolve_not_before + f.init.appeal_review_delay) as u32);
    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(5).unwrap())
        .expect_success();
    let context = f.phase().3;
    let now = u64::from(f.bc.now());
    let deadline = f.phase().6;
    let report = |query_id| {
        PredictionMarketContractV1::report_result(
            query_id, 1, context, 1, [0xe3; 32], now, deadline,
        )
        .unwrap()
    };

    f.send(&first, OPERATION_BUDGET, report(6)).expect_success();
    assert_eq!(f.phase().0, 3, "M-1 appellate votes must not finalize");
    f.send(&first, OPERATION_BUDGET, report(7)).expect_success();
    assert_eq!(f.phase().0, 3, "duplicate appellate vote must be idempotent");
    f.send(
        &first,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(8, 1, context, 2, [0xe4; 32], now, deadline)
            .unwrap(),
    )
    .expect_exit_code(2429);
    assert_eq!(f.phase().0, 3, "appellate equivocation must not finalize");
    f.send(&second, OPERATION_BUDGET, report(9)).expect_success();
    assert_eq!(f.phase().0, 4, "exactly M appellate reporters must finalize");
}

#[test]
fn factual_invalid_from_normal_quorum_pays_each_complete_set_half() {
    let mut f = Fixture::new();
    f.activate();
    let owner = f.owner.address().clone();
    let keeper = f.trader_b.address().clone();
    let normal = f.normal.address().clone();
    let key = SigningKey::from_bytes(&[0x74; 32]);
    f.register(&owner, &key, 2);
    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::split(3, 1).unwrap())
        .expect_success();

    f.bc.set_now(f.init.resolve_not_before as u32);
    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(4).unwrap())
        .expect_success();
    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(5).unwrap())
        .expect_success();
    let context = f.phase().3;
    f.send(
        &normal,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(
            6,
            0,
            context,
            2,
            [0xa1; 32],
            u64::from(f.bc.now()),
            f.init.oracle_vote_deadline,
        )
        .unwrap(),
    )
    .expect_success();
    let deadline = f.phase().6;
    f.bc.set_now(deadline as u32);
    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::finalize_uncontested(7).unwrap())
        .expect_success();
    let (status, reason, outcome, _, _, _, _) = f.phase();
    assert_eq!(
        (status, reason, outcome),
        (4, 0, 2),
        "a normal factual INVALID is distinct from a protocol timeout"
    );

    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::claim(8, &owner).unwrap())
        .expect_success();
    assert_eq!(f.accounting()[4], 10 * TOS as i128, "INVALID must pay a full set exactly once");
    assert_eq!(f.accounting()[7], 0, "claim must exhaust the finalized payout liability");
}

#[test]
fn every_outcome_exhausts_final_backing_under_different_claim_orders() {
    for (outcome, claim_order) in [(0_u8, [1_usize, 0]), (1, [0, 1]), (2, [1, 0])] {
        let mut f = Fixture::new();
        f.activate();
        let owners = [f.owner.address().clone(), f.trader_b.address().clone()];
        let keys = [
            SigningKey::from_bytes(&[0x80 + outcome; 32]),
            SigningKey::from_bytes(&[0x90 + outcome; 32]),
        ];
        let normal = f.normal.address().clone();
        f.register(&owners[0], &keys[0], 2);
        f.register(&owners[1], &keys[1], 3);
        f.send(&owners[0], OPERATION_BUDGET, PredictionMarketContractV1::split(4, 3).unwrap())
            .expect_success();
        f.send(&owners[1], OPERATION_BUDGET, PredictionMarketContractV1::split(5, 2).unwrap())
            .expect_success();

        // Move one YES lot only. The two accounts now have asymmetric YES/NO
        // positions, so all three outcomes exercise different individual payouts.
        let sell_yes = f.signed_order(
            &owners[0],
            &keys[0],
            1,
            PredictionOrderActionV1::Sell,
            PredictionOrderOutcomeV1::Yes,
            PredictionLiquidityRoleV1::Maker,
            5_000,
            1,
        );
        let buy_yes = f.signed_order(
            &owners[1],
            &keys[1],
            1,
            PredictionOrderActionV1::Buy,
            PredictionOrderOutcomeV1::Yes,
            PredictionLiquidityRoleV1::Taker,
            5_000,
            1,
        );
        f.send(
            &owners[1],
            2 * TOS,
            PredictionMarketContractV1::match_pair(6, 1, sell_yes, buy_yes).unwrap(),
        )
        .expect_success();

        f.bc.set_now(f.init.resolve_not_before as u32);
        f.send(&owners[0], OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(7).unwrap())
            .expect_success();
        f.send(&owners[0], OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(8).unwrap())
            .expect_success();
        let context = f.phase().3;
        f.send(
            &normal,
            OPERATION_BUDGET,
            PredictionMarketContractV1::report_result(
                9,
                0,
                context,
                outcome,
                [0xb0 + outcome; 32],
                u64::from(f.bc.now()),
                f.init.oracle_vote_deadline,
            )
            .unwrap(),
        )
        .expect_success();
        let finalization_deadline = f.phase().6;
        f.bc.set_now(finalization_deadline as u32);
        f.send(
            &owners[0],
            OPERATION_BUDGET,
            PredictionMarketContractV1::finalize_uncontested(10).unwrap(),
        )
        .expect_success();

        let final_backing = 5 * TOS;
        assert_eq!(f.accounting()[6], final_backing as i128, "outcome {outcome}: final backing");
        let mut claimed = 0_u64;
        for index in claim_order {
            let account_before = f.account(&owners[index]);
            let expected_payout = match outcome {
                0 => (account_before[1] as u64).checked_mul(TOS).unwrap(),
                1 => (account_before[2] as u64).checked_mul(TOS).unwrap(),
                2 => (account_before[1] as u64 + account_before[2] as u64)
                    .checked_mul(TOS / 2)
                    .unwrap(),
                _ => unreachable!(),
            };
            f.send(
                &owners[1 - index],
                OPERATION_BUDGET,
                PredictionMarketContractV1::claim(20 + index as u64, &owners[index]).unwrap(),
            )
            .expect_success();
            let account_after = f.account(&owners[index]);
            assert_eq!(
                account_after[0] as u64 - account_before[0] as u64,
                expected_payout,
                "outcome {outcome}: claim payout diverged for participant {index}"
            );
            claimed = claimed.checked_add(expected_payout).unwrap();
            let accounting = f.accounting();
            assert_eq!(
                accounting[7] as u64 + claimed,
                final_backing,
                "outcome {outcome}: remaining plus claimed payout diverged"
            );
        }
        assert_eq!(claimed, final_backing, "outcome {outcome}: total payout must equal backing");
        assert_eq!(f.accounting()[7], 0, "outcome {outcome}: payout liability remains");
    }
}

#[test]
fn appellate_quorum_can_uphold_the_challenged_normal_result() {
    let mut f = Fixture::new();
    f.activate();
    let owner = f.owner.address().clone();
    let challenger = f.trader_b.address().clone();
    let normal = f.normal.address().clone();
    let appellate = f.appellate.address().clone();
    let key = SigningKey::from_bytes(&[0x75; 32]);
    f.register(&owner, &key, 2);
    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::split(3, 1).unwrap())
        .expect_success();

    f.bc.set_now(f.init.resolve_not_before as u32);
    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(4).unwrap())
        .expect_success();
    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(5).unwrap())
        .expect_success();
    let normal_context = f.phase().3;
    f.send(
        &normal,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(
            6,
            0,
            normal_context,
            0,
            [0xa2; 32],
            u64::from(f.bc.now()),
            f.init.oracle_vote_deadline,
        )
        .unwrap(),
    )
    .expect_success();
    let proposal_hash = f.phase().5;
    f.send(
        &challenger,
        OPERATION_BUDGET + f.init.challenge_bond + f.init.challenge_processing_fee,
        PredictionMarketContractV1::challenge_result(7, proposal_hash, 1, [0xa3; 32]).unwrap(),
    )
    .expect_success();

    f.bc.set_now((f.init.resolve_not_before + f.init.appeal_review_delay) as u32);
    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(8).unwrap())
        .expect_success();
    let appeal_context = f.phase().3;
    f.send(
        &appellate,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(
            9,
            1,
            appeal_context,
            0,
            [0xa4; 32],
            u64::from(f.bc.now()),
            f.init.resolve_not_before + f.init.appeal_period,
        )
        .unwrap(),
    )
    .expect_success();
    let (status, reason, outcome, _, _, _, _) = f.phase();
    assert_eq!((status, reason, outcome), (4, 1, 0));
}

#[test]
fn challenged_proposal_appellate_timeout_keeps_normal_result_not_invalid() {
    let mut f = Fixture::new();
    f.activate();
    let owner = f.owner.address().clone();
    let challenger = f.trader_b.address().clone();
    let normal = f.normal.address().clone();
    let key = SigningKey::from_bytes(&[0x76; 32]);
    f.register(&owner, &key, 2);
    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::split(3, 1).unwrap())
        .expect_success();

    f.bc.set_now(f.init.resolve_not_before as u32);
    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(4).unwrap())
        .expect_success();
    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(5).unwrap())
        .expect_success();
    let normal_context = f.phase().3;
    f.send(
        &normal,
        OPERATION_BUDGET,
        PredictionMarketContractV1::report_result(
            6,
            0,
            normal_context,
            0,
            [0xa5; 32],
            u64::from(f.bc.now()),
            f.init.oracle_vote_deadline,
        )
        .unwrap(),
    )
    .expect_success();
    let proposal_hash = f.phase().5;
    f.send(
        &challenger,
        OPERATION_BUDGET + f.init.challenge_bond + f.init.challenge_processing_fee,
        PredictionMarketContractV1::challenge_result(7, proposal_hash, 1, [0xa6; 32]).unwrap(),
    )
    .expect_success();
    let review_base = f.phase().4;
    let deadline = f.phase().6;

    f.bc.set_now((f.init.resolve_not_before + f.init.appeal_review_delay) as u32);
    f.send(&challenger, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(8).unwrap())
        .expect_success();
    f.bc.set_now(deadline as u32);
    f.send(
        &challenger,
        OPERATION_BUDGET,
        PredictionMarketContractV1::finalize_review_timeout(9, review_base).unwrap(),
    )
    .expect_success();
    let (status, reason, outcome, _, _, _, _) = f.phase();
    assert_eq!(
        (status, reason, outcome),
        (4, 1, 0),
        "a challenged normal proposal remains authoritative when appellate quorum times out"
    );
}

#[test]
fn both_frozen_oracle_rounds_timing_out_is_the_only_timeout_that_yields_invalid() {
    let mut f = Fixture::new();
    f.activate();
    let owner = f.owner.address().clone();
    let keeper = f.trader_b.address().clone();
    let key = SigningKey::from_bytes(&[0x73; 32]);
    f.register(&owner, &key, 2);
    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::split(3, 1).unwrap())
        .expect_success();

    f.bc.set_now(f.init.oracle_vote_deadline as u32);
    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(4).unwrap())
        .expect_success();
    assert_eq!(f.phase().0, 1, "late keeper call advances only one phase");
    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(40).unwrap())
        .expect_success();
    let (status, reason, _, context, base, _, deadline) = f.phase();
    assert_eq!((status, reason), (3, 0));
    assert_eq!(context, [0; 32]);
    assert_ne!(base, [0; 32]);
    assert_eq!(deadline, f.init.oracle_vote_deadline + f.init.appeal_period);

    f.bc.set_now((f.init.oracle_vote_deadline + f.init.appeal_review_delay) as u32);
    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(5).unwrap())
        .expect_success();
    assert_ne!(f.phase().3, [0; 32]);

    f.bc.set_now(deadline as u32);
    f.send(
        &keeper,
        OPERATION_BUDGET,
        PredictionMarketContractV1::finalize_review_timeout(6, [0x55; 32]).unwrap(),
    )
    .expect_exit_code(2427);
    assert_eq!(f.phase().0, 3);
    f.send(
        &keeper,
        OPERATION_BUDGET,
        PredictionMarketContractV1::finalize_review_timeout(7, base).unwrap(),
    )
    .expect_success();
    let (status, reason, outcome, _, _, _, _) = f.phase();
    assert_eq!((status, reason, outcome), (4, 0, 2));

    f.send(&keeper, OPERATION_BUDGET, PredictionMarketContractV1::claim(8, &owner).unwrap())
        .expect_success();
    assert_eq!(f.accounting()[7], 0);
    assert_eq!(f.account(&owner)[0], 10 * TOS as i128);
}
