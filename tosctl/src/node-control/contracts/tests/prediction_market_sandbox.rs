/*
 * Copyright (C) 2025-2026 TOS Network.
 * Licensed under the GNU General Public License v3.0.
 */

//! Production-BOC state-transition tests for PredictionMarket V1.

use chain_block::{Cell, MsgAddressInt, Serializable, SliceData, TrComputePhase};
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

impl Fixture {
    fn new() -> Self {
        let mut bc = Blockchain::with_global_version(14).expect("v14 blockchain");
        bc.set_workchain(-1);
        let owner = bc.treasury("prediction-owner", 1_000 * TOS).expect("owner");
        let trader_b = bc.treasury("prediction-trader-b", 1_000 * TOS).expect("trader b");
        let normal = bc.treasury("normal-reporter", 100 * TOS).expect("normal reporter");
        let appellate = bc.treasury("appellate-reporter", 100 * TOS).expect("appellate reporter");
        let reserve = bc.treasury("prediction-reserve", 100 * TOS).expect("reserve");
        let now = u64::from(bc.now());
        let init = PredictionMarketInitV1 {
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
            max_orders_per_participant: 8,
            max_live_order_records: 16,
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
    let (status, _, _, normal_context, _, _, _) = f.phase();
    assert_eq!(status, 1);
    assert_ne!(normal_context, [0; 32]);
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

    f.bc.set_now((f.init.resolve_not_before + f.init.appeal_review_delay) as u32);
    f.send(&owner, OPERATION_BUDGET, PredictionMarketContractV1::advance_phase(7).unwrap())
        .expect_success();
    let (_, _, _, appeal_context, _, _, _) = f.phase();
    assert_ne!(appeal_context, [0; 32]);
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
    let reserve_before =
        f.bc.get_account(&reserve).unwrap().balance().unwrap().coins.as_u64().unwrap();
    let result = f.send(
        &challenger,
        OPERATION_BUDGET,
        PredictionMarketContractV1::withdraw_terminal_surplus(13, TOS).unwrap(),
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
    let reserve_after =
        f.bc.get_account(&reserve).unwrap().balance().unwrap().coins.as_u64().unwrap();
    assert!(reserve_after > reserve_before);
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
