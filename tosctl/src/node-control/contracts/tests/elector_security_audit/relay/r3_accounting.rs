//! Explicit debt and paid retry controls. Every hop uses the native action phase.
use super::*;

pub(super) fn fund(f: &mut Fixture, amount: u64, permission: u64) {
    let request = funding_request(f, amount, permission);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "explicit root-authorized operating deposit");
    assert_eq!(out.len(), 1, "deposit change must return to the actual sender");
    assert_eq!(out[0].dst().as_ref(), Some(f.operator.address()));
}

fn funding_request(f: &Fixture, amount: u64, permission: u64) -> Message {
    funding_request_with_policy(f, amount, permission, 20 * TOS, f.chain.blockchain.now() + 86_400)
}

fn funding_request_with_policy(
    f: &Fixture,
    amount: u64,
    permission: u64,
    cap: u64,
    expires: u32,
) -> Message {
    let payload = contracts::validator_controller::operating_funding_payload(
        &contracts::validator_controller::OperatingFunding {
            payer: f.operator.address(),
            deposit: u128::from(amount),
            allowance: u128::from(permission),
            per_request_limit: u128::from(cap),
            storage_floor: u128::from(10 * TOS),
            expires_at: expires,
        },
    )
    .expect("production operating payload");
    operating_request(f, "fund-operations", payload)
}

fn operating_request(f: &Fixture, command: &str, payload: chain_block::Cell) -> Message {
    let state = f
        .chain
        .blockchain
        .run_get_method(&f.validator.address, "controller_state", vec![])
        .expect("controller state");
    let body = run_controller_tool(&[
        command.into(),
        seed_file_for(&f.validator.root).to_string_lossy().into_owned(),
        global_id(&f.chain).to_string(),
        hex::encode(f.validator.id().as_slice()),
        state.stack[0].as_integer().expect("epoch").to_string(),
        f.validator.stored_nonce(&f.chain).to_string(),
        (f.chain.blockchain.now() + 600).to_string(),
        base64_encode(&chain_block::write_boc(&payload).expect("funding payload BOC")),
    ]);
    f.operator.build_message(&f.validator.address, 100 * TOS, true, Some(body))
}

pub(super) fn funds(f: &Fixture) -> u128 {
    let result = f
        .chain
        .blockchain
        .run_get_method(&f.validator.address, "operating_state", vec![])
        .expect("operating ledger");
    assert_eq!(result.exit_code, 0);
    result.stack[0].as_integer().expect("funds").to_string().parse().expect("amount")
}

pub(super) fn first_grant(f: &Fixture) -> u128 {
    u128::from(80 * TOS).checked_sub(funds(f)).expect("first reserved grant")
}

#[test]
fn sponsorship_requires_separate_explicit_funds_and_permission() {
    for case in
        ["default", "ordinary-credit", "funds-only", "permission-only", "expired", "cap", "both"]
    {
        let mut f = Fixture::unfunded(case);
        match case {
            "ordinary-credit" => {
                let transfer =
                    f.operator.build_message(&f.validator.address, 500 * TOS, false, None);
                let (tx, _) = step(&mut f.chain, transfer);
                successful(&tx, "ordinary credit");
                assert_eq!(funds(&f), 0, "balance alone is not an operating deposit");
            }
            "funds-only" => fund(&mut f, 80 * TOS, 0),
            "permission-only" => fund(&mut f, 0, 60 * TOS),
            "both" => fund(&mut f, 80 * TOS, 60 * TOS),
            "expired" | "cap" => {
                let request = funding_request_with_policy(
                    &f,
                    80 * TOS,
                    60 * TOS,
                    if case == "cap" { 1 } else { 20 * TOS },
                    f.chain.blockchain.now() + if case == "expired" { 0 } else { 86_400 },
                );
                let (tx, _) = step(&mut f.chain, request);
                successful(&tx, "explicit restrictive sponsorship policy");
            }
            _ => assert_eq!(funds(&f), 0),
        }
        let before = funds(&f);
        let order = f.order(1, f.election, 10_002 * TOS);
        let (tx, out) = step(&mut f.chain, order);
        successful(&tx, "funded pool inlet");
        let request = only_to(out, &f.validator.address);
        let (tx, out) = step(&mut f.chain, request);
        if case == "both" {
            successful(&tx, "explicitly funded and authorized request");
            assert!(f.pending().is_some());
            assert!(funds(&f) < before, "one finite operating grant is reserved");
        } else {
            assert!(
                tx.read_description().expect("description").is_aborted(),
                "R3: {case} cannot authorize sponsorship"
            );
            assert!(f.pending().is_none());
            assert_eq!(funds(&f), before);
            let bounced = only_to(out, &f.pool);
            assert!(bounced.is_bounced());
            let (tx, _) = step(&mut f.chain, bounced);
            successful(&tx, "rejected request returns through pool");
            assert_eq!(f.pool_state(), 0);
        }
    }
}

#[test]
fn operating_deposits_bind_sender_nonce_expiry_and_preserve_existing_debt() {
    let mut f = Fixture::unfunded("r3-deposit-authorization");
    let request = funding_request(&f, 80 * TOS, 60 * TOS);
    let stranger =
        f.chain.blockchain.treasury("unbound-operations-sender", 1_000 * TOS).expect("stranger");
    let copied = stranger.build_message(
        &f.validator.address,
        100 * TOS,
        true,
        Some(request.body().expect("body").clone().into_cell().expect("cell")),
    );
    let (tx, _) = step(&mut f.chain, copied);
    assert!(tx.read_description().expect("description").is_aborted(), "sender binding must reject");
    assert_eq!(funds(&f), 0);
    let (tx, _) = step(&mut f.chain, request.clone());
    successful(&tx, "original authorized deposit");
    assert_eq!(funds(&f), u128::from(80 * TOS));
    let (tx, _) = step(&mut f.chain, request);
    assert!(
        tx.read_description().expect("description").is_aborted(),
        "nonce prevents a second credit"
    );
    assert_eq!(funds(&f), u128::from(80 * TOS));
    let expired = funding_request(&f, TOS, TOS);
    f.chain.blockchain.set_now(f.chain.blockchain.now() + 601);
    let (tx, _) = step(&mut f.chain, expired);
    assert!(tx.read_description().expect("description").is_aborted(), "expired root authority");
    assert_eq!(funds(&f), u128::from(80 * TOS));
    let at = f.election;
    let stake = begin(&mut f, 1, at);
    let (tx, out) = step(&mut f.chain, stake);
    successful(&tx, "real elector result");
    let result = only_to(out, &f.validator.address);
    let (tx, out) = step(&mut f.chain, result);
    successful(&tx, "record accepted debt");
    let kick = only_to(out, &f.validator.address);
    let ready = f.pending();
    fund(&mut f, 0, 0);
    assert_eq!(f.pending(), ready, "disabling sponsorship must preserve existing debt");
    let (tx, out) = step(&mut f.chain, kick);
    successful(&tx, "already accepted grant remains usable");
    let payment = only_to(out, &f.pool);
    let (tx, out) = step(&mut f.chain, payment);
    successful(&tx, "settle despite zero new permission");
    let ack = only_to(out, &f.validator.address);
    let (tx, _) = step(&mut f.chain, ack);
    successful(&tx, "retire existing obligation");
    assert!(f.pending().is_none());
}

#[test]
fn current_fee_change_goes_to_inlet_and_retry_payers_not_principal_owner() {
    let mut returned = Vec::new();
    for budget in [20 * TOS, 40 * TOS] {
        let mut f = Fixture::new("r3-distinct-fee-payer");
        let mut order = f.order(1, f.election, 10_002 * TOS);
        order.int_header_mut().expect("header").value.coins = Coins::new(budget);
        let (tx, out) = step(&mut f.chain, order);
        successful(&tx, "pool returns inlet change");
        let inlet_change = value(&only_to(out.clone(), f.operator.address()));
        let relay = only_to(out, &f.validator.address);
        let before = balance_of(&f.chain, &f.validator.address);
        let (tx, out) = step(&mut f.chain, relay);
        successful(&tx, "controller returns relay change");
        let relay_change = value(&only_to(out.clone(), f.operator.address()));
        assert_eq!(
            balance_of(&f.chain, &f.validator.address),
            before,
            "inlet fee budget is not retained across transactions"
        );
        returned.push(inlet_change + relay_change);
        let stake = only_to(out, &f.chain.elector);
        let (tx, out) = step(&mut f.chain, stake);
        successful(&tx, "elector accepts stake");
        let receipt = only_to(out, &f.validator.address);
        let debt = value(&receipt);
        let (tx, out) = step(&mut f.chain, receipt);
        successful(&tx, "READY; automatic kick retained by test scheduler");
        let late_kick = only_to(out, &f.validator.address);
        let caller =
            f.chain.blockchain.treasury("third-party-retry-payer", 1_000 * TOS).expect("caller");
        let body = retry(&f, DOMAIN | 1).body().expect("retry").clone().into_cell().expect("body");
        let message = caller.build_message(&f.validator.address, 20 * TOS, true, Some(body));
        let (tx, out) = step(&mut f.chain, message);
        successful(&tx, "third party funds settlement");
        assert!(value(&only_to(out.clone(), caller.address())) > 0);
        assert!(
            out.iter().all(|m| m.dst().as_ref() != Some(f.operator.address())),
            "retry change belongs to the actual caller"
        );
        let payment = only_to(out, &f.pool);
        let before = balance_of(&f.chain, &f.pool);
        let (tx, out) = step(&mut f.chain, payment);
        successful(&tx, "pool separates business value and callback fees");
        assert_eq!(
            balance_of(&f.chain, &f.pool),
            before + debt,
            "callback budget must not enter pool principal or rewards"
        );
        assert!(value(&only_to(out.clone(), caller.address())) > 0);
        let ack = only_to(out, &f.validator.address);
        let (tx, out) = step(&mut f.chain, ack);
        successful(&tx, "ACK change follows the same caller");
        assert!(value(&only_to(out, caller.address())) > 0);
        let before = balance_of(&f.chain, &f.validator.address);
        let (tx, out) = step(&mut f.chain, late_kick);
        successful(&tx, "late automatic wakeup refunds its original sponsor");
        assert!(value(&only_to(out, f.operator.address())) > 0);
        assert_eq!(
            balance_of(&f.chain, &f.validator.address),
            before,
            "late self-kick cannot strand an earlier payer's fees"
        );
        assert!(f.pending().is_none());
    }
    assert_eq!(
        returned[1] - returned[0],
        u128::from(20 * TOS),
        "extra inlet budget returns in that transaction, never as later business value"
    );
}

#[test]
fn explicit_debt_does_not_sweep_aborted_nonbounce_credit() {
    for ready in [false, true] {
        let mut f = Fixture::new("r3-aborted-credit");
        let at = f.election;
        let stake = begin(&mut f, 1, at);
        let (tx, out) = step(&mut f.chain, stake);
        successful(&tx, "elector outcome");
        let reply = only_to(out, &f.validator.address);
        let business = value(&reply);
        let mut held_reply = Some(reply);
        let mut kick = None;
        if ready {
            let (tx, out) = step(&mut f.chain, held_reply.take().expect("reply"));
            successful(&tx, "record debt");
            kick = Some(only_to(out, &f.validator.address));
        }
        let before = balance_of(&f.chain, &f.validator.address);
        let pending = f.pending();
        let unknown = f.operator.build_message(
            &f.validator.address,
            500 * TOS,
            false,
            Some(
                BuilderData::with_raw(0xdeadbeefu32.to_be_bytes().to_vec(), 32)
                    .expect("unknown body")
                    .into_cell()
                    .expect("body"),
            ),
        );
        let (tx, out) = step(&mut f.chain, unknown);
        assert!(
            tx.read_description().expect("description").is_aborted(),
            "original failure premise"
        );
        assert!(out.is_empty());
        assert!(balance_of(&f.chain, &f.validator.address) > before + u128::from(490 * TOS));
        let unrelated = balance_of(&f.chain, &f.validator.address) - before;
        assert_eq!(f.pending(), pending, "failed message did not classify its credit");
        if let Some(reply) = held_reply {
            let (tx, out) = step(&mut f.chain, reply);
            successful(&tx, "record actual result");
            kick = Some(only_to(out, &f.validator.address));
        }
        let (tx, out) = step(&mut f.chain, kick.expect("one automatic attempt"));
        successful(&tx, "exact debt payment");
        let payment = only_to(out, &f.pool);
        let mut body = payment.body().expect("body").clone();
        body.get_next_u32().expect("op");
        body.get_next_u64().expect("query");
        body.get_next_bits(256).expect("hash");
        next_coins(&mut body);
        next_coins(&mut body);
        body.get_next_u32().expect("reason");
        body.get_next_bit().expect("success");
        let reported = next_coins(&mut body);
        let callback = next_coins(&mut body);
        assert_eq!(reported, business);
        assert_eq!(
            value(&payment),
            business + callback,
            "R3: owner payment is actual debt plus classified callback budget, never surplus"
        );
        let (tx, out) = step(&mut f.chain, payment);
        successful(&tx, "pool accounting");
        let ack = only_to(out, &f.validator.address);
        let (tx, _) = step(&mut f.chain, ack);
        successful(&tx, "cleanup");
        assert!(f.pending().is_none());
        assert_eq!(
            balance_of(&f.chain, &f.validator.address),
            before + unrelated - if ready { business } else { first_grant(&f) },
            "R3: the transaction floor protects unrelated cash from every fee refund"
        );
    }
}

#[test]
fn preaccounting_abort_bounces_then_retries_actual_cash_once() {
    let mut f = Fixture::new("r3-return-bounce-recovery");
    // Keep unrelated elector assets available: an invalid resend must fail
    // because of the return phase, never accidentally because cash is absent.
    let donation = f.operator.build_message(&f.chain.elector, 30_000 * TOS, false, None);
    let (tx, _) = step(&mut f.chain, donation);
    successful(&tx, "unrelated elector treasury funds");
    let at = f.election.checked_add(1).expect("wrong round");
    let stake = begin(&mut f, 1, at);
    let (tx, out) = step(&mut f.chain, stake);
    successful(&tx, "elector records and sends actual refund");
    let refund = only_to(out, &f.validator.address);
    assert!(refund.int_header().expect("header").bounce);
    let first_value = value(&refund);
    assert!(first_value > u128::from(9_900 * TOS));
    let waiting = f.pending();
    // A paid retry while the original payment is in flight cannot duplicate it.
    let request = retry(&f, DOMAIN | 1);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "request repair while first payment is in flight");
    let request = only_to(out, &f.chain.elector);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "in-flight retry returns only caller fees");
    assert!(
        out.iter().all(|m| m.dst().as_ref() != Some(&f.validator.address)),
        "in-flight retry must not repeat business payment"
    );
    let prices = raw_parameter(&f.chain, 20).expect("gas profile");
    let mut restricted = f.chain.blockchain.config_params().gas_prices(true).expect("prices");
    restricted.gas_limit = 1_000;
    set_contract_parameter(
        &mut f.chain,
        20,
        restricted.write_to_new_cell().expect("prices").into_cell().expect("cell"),
    );
    let (tx, out) = step(&mut f.chain, refund);
    assert!(tx.read_description().expect("description").is_aborted());
    match tx.read_description().expect("description") {
        TransactionDescr::Ordinary(d) => match d.compute_ph {
            TrComputePhase::Vm(vm) => assert_eq!(vm.exit_code, -14),
            _ => panic!("actual OOG required"),
        },
        _ => panic!("ordinary transaction"),
    }
    assert_eq!(f.pending(), waiting);
    let bounced = only_to(out, &f.chain.elector);
    assert!(bounced.int_header().expect("header").bounced);
    let bounced_value = value(&bounced);
    assert!(bounced_value < first_value);
    set_contract_parameter(&mut f.chain, 20, prices);
    let (tx, out) = step(&mut f.chain, bounced);
    successful(&tx, "elector restores only actual bounced cash");
    assert!(out.is_empty());
    let request = retry(&f, DOMAIN | 1);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "caller funds recovery");
    let request = only_to(out, &f.chain.elector);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "elector retries returned funds");
    let repaired = only_to(out, &f.validator.address);
    let (tx, out) = step(&mut f.chain, repaired);
    successful(&tx, "controller accounts recovered cash");
    let ack = only_to(out.clone(), &f.chain.elector);
    let kick = only_to(out, &f.validator.address);
    let (tx, _) = step(&mut f.chain, ack);
    successful(&tx, "elector records delivered tombstone");
    let (tx, out) = step(&mut f.chain, kick);
    successful(&tx, "pay recovered debt");
    let payment = only_to(out, &f.pool);
    let mut body = payment.body().expect("body").clone();
    body.get_next_u32().expect("op");
    body.get_next_u64().expect("query");
    body.get_next_bits(256).expect("hash");
    next_coins(&mut body);
    next_coins(&mut body);
    body.get_next_u32().expect("reason");
    body.get_next_bit().expect("success");
    assert_eq!(next_coins(&mut body), bounced_value, "gross is never fabricated after a bounce");
    let callback = next_coins(&mut body);
    assert_eq!(value(&payment), bounced_value + callback);
    let (tx, out) = step(&mut f.chain, payment);
    successful(&tx, "pool finishes failed election with operator-paid loss");
    assert_eq!(f.pool_state(), 0);
    let pool_ack = only_to(out, &f.validator.address);
    let request = retry(&f, DOMAIN | 1);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "PAID repair before lost cleanup ACK");
    let repeat = only_to(out, &f.pool);
    assert_eq!(value(&repeat), callback, "repeated result never repeats principal");
    let (tx, _) = step(&mut f.chain, pool_ack);
    successful(&tx, "clear completed request");
    assert!(f.pending().is_none());
}

#[test]
fn delayed_control_fees_return_after_a_later_query_without_changing_its_debt() {
    let mut f = Fixture::new("r3-delayed-controls");
    let at = f.election + 1;
    let stake = begin(&mut f, 1, at);
    let request = retry(&f, DOMAIN | 1);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "fund old return repair");
    let late_repair = only_to(out, &f.chain.elector);
    let (tx, out) = step(&mut f.chain, stake);
    successful(&tx, "first refusal");
    let result = only_to(out, &f.validator.address);
    let (tx, out) = step(&mut f.chain, result);
    successful(&tx, "READY before third-party retry");
    let late_kick = only_to(out.clone(), &f.validator.address);
    let late_delivery_ack = only_to(out, &f.chain.elector);
    let request = retry(&f, DOMAIN | 1);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "settle ahead of automatic wakeup");
    let payment = only_to(out, &f.pool);
    let (tx, out) = step(&mut f.chain, payment);
    successful(&tx, "pool settles first refusal");
    let ack = only_to(out, &f.validator.address);
    let late_pool_ack = ack.clone();
    let (tx, _) = step(&mut f.chain, ack);
    successful(&tx, "first controller cleanup");
    let second = begin(&mut f, 2, at);
    let waiting = f.pending();
    let (tx, out) = step(&mut f.chain, second);
    successful(&tx, "next query implicitly acknowledges the old delivery");
    let second_result = only_to(out, &f.validator.address);
    let elector_data = f
        .chain
        .blockchain
        .get_account(&f.chain.elector)
        .expect("elector")
        .get_data()
        .expect("data");
    for (label, message) in [
        ("old automatic wakeup", late_kick),
        ("old pool ACK", late_pool_ack),
        ("old delivery ACK", late_delivery_ack),
        ("old return retry", late_repair),
    ] {
        let recipient = message.dst().expect("recipient");
        let before = balance_of(&f.chain, &recipient);
        let (tx, out) = step(&mut f.chain, message);
        successful(&tx, label);
        assert!(
            value(&only_to(out, f.operator.address())) > 0,
            "late control fees return to their payer"
        );
        assert_eq!(
            balance_of(&f.chain, &recipient),
            before,
            "late controls cannot retain fees or release existing assets"
        );
        assert_eq!(f.pending(), waiting, "later request remains WAIT");
        assert_eq!(
            f.chain
                .blockchain
                .get_account(&f.chain.elector)
                .expect("elector")
                .get_data()
                .expect("data"),
            elector_data
        );
    }
    finish_reply(&mut f, second_result, 0);
}

#[test]
fn single_pool_keeps_only_business_value_and_returns_third_party_callback_change() {
    let mut f = Fixture::new("r3-single-payer");
    let owner =
        f.chain.blockchain.treasury("single-principal-owner", 100_000 * TOS).expect("owner");
    f.pool = deploy_single_nominator(
        &mut f.chain,
        owner.address(),
        f.operator.address(),
        &f.validator.address,
        40_000 * TOS,
    );
    let order = f.order(1, f.election, 10_002 * TOS);
    let (tx, out) = step(&mut f.chain, order);
    successful(&tx, "single pool caller-funded inlet");
    assert!(value(&only_to(out.clone(), f.operator.address())) > 0);
    let request = only_to(out, &f.validator.address);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "single pool stake relay");
    let stake = only_to(out, &f.chain.elector);
    let (tx, out) = step(&mut f.chain, stake);
    successful(&tx, "single pool stake accepted");
    let result = only_to(out, &f.validator.address);
    let debt = value(&result);
    let (tx, out) = step(&mut f.chain, result);
    successful(&tx, "record single pool debt");
    let late_kick = only_to(out, &f.validator.address);
    let caller = f.chain.blockchain.treasury("single-repair-payer", 1_000 * TOS).expect("payer");
    let body = retry(&f, DOMAIN | 1).body().expect("body").clone().into_cell().expect("cell");
    let message = caller.build_message(&f.validator.address, 20 * TOS, true, Some(body));
    let (tx, out) = step(&mut f.chain, message);
    successful(&tx, "third party pays single pool callback");
    let payment = only_to(out, &f.pool);
    let before = balance_of(&f.chain, &f.pool);
    let (tx, out) = step(&mut f.chain, payment);
    successful(&tx, "single pool classifies callback budget");
    assert_eq!(
        balance_of(&f.chain, &f.pool),
        before + debt,
        "single pool retains only actual business debt"
    );
    assert!(value(&only_to(out.clone(), caller.address())) > 0);
    let ack = only_to(out, &f.validator.address);
    let (tx, out) = step(&mut f.chain, ack);
    successful(&tx, "single pool cleanup");
    assert!(value(&only_to(out, caller.address())) > 0);
    let (tx, out) = step(&mut f.chain, late_kick);
    successful(&tx, "single late wakeup");
    assert!(value(&only_to(out, f.operator.address())) > 0);
    assert!(f.pending().is_none());
}

fn abort_result_and_deliver_native_bounce(f: &mut Fixture, result: Message) -> u128 {
    let original = raw_parameter(&f.chain, 20).expect("gas prices");
    let mut prices = f.chain.blockchain.config_params().gas_prices(true).expect("prices");
    prices.gas_limit = 1_000;
    set_contract_parameter(
        &mut f.chain,
        20,
        prices.write_to_new_cell().expect("prices").into_cell().expect("cell"),
    );
    let waiting = f.pending();
    let (tx, out) = step(&mut f.chain, result);
    match tx.read_description().expect("description") {
        TransactionDescr::Ordinary(d) => match d.compute_ph {
            TrComputePhase::Vm(vm) => assert_eq!(vm.exit_code, -14, "real pre-accounting OOG"),
            _ => panic!("VM required"),
        },
        _ => panic!("ordinary transaction required"),
    }
    assert_eq!(f.pending(), waiting);
    let bounced = only_to(out, &f.chain.elector);
    assert!(bounced.is_bounced());
    let actual = value(&bounced);
    set_contract_parameter(&mut f.chain, 20, original);
    let (tx, out) = step(&mut f.chain, bounced);
    successful(&tx, "elector records actual second bounce");
    assert!(out.is_empty());
    actual
}

#[test]
fn a_second_bounce_preserves_previous_payer_credit_and_acknowledged_returns_never_repay() {
    let mut f = Fixture::new("r3-repeated-return-bounce");
    let at = f.election + 1;
    let stake = begin(&mut f, 1, at);
    let (tx, out) = step(&mut f.chain, stake);
    successful(&tx, "initial refusal");
    let first = only_to(out, &f.validator.address);
    let debt = abort_result_and_deliver_native_bounce(&mut f, first);
    let request = retry(&f, DOMAIN | 1);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "first payer funds retry");
    let request = only_to(out, &f.chain.elector);
    let replay = request.clone();
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "first paid redelivery");
    let delivery = only_to(out, &f.validator.address);
    let returned = abort_result_and_deliver_native_bounce(&mut f, delivery);
    assert!(returned > debt, "the second bounce includes unspent retry fees");
    let caller = f.chain.blockchain.treasury("second-return-payer", 1_000 * TOS).expect("caller");
    let body = retry(&f, DOMAIN | 1).body().expect("body").clone().into_cell().expect("cell");
    let request = caller.build_message(&f.validator.address, 20 * TOS, true, Some(body));
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "second payer funds recovery");
    let request = only_to(out, &f.chain.elector);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "refund old payer credit separately");
    assert_eq!(
        out.iter().find(|m| m.dst().as_ref() == Some(f.operator.address())).map(value),
        Some(returned - debt),
        "returned retry fees belong to the previous payer"
    );
    assert!(value(&only_to(out.clone(), caller.address())) > 0);
    let result = only_to(out, &f.validator.address);
    let (tx, out) = step(&mut f.chain, result);
    successful(&tx, "record the unchanged business debt");
    let ack = only_to(out.clone(), &f.chain.elector);
    let kick = only_to(out, &f.validator.address);
    let (tx, _) = step(&mut f.chain, ack);
    successful(&tx, "acknowledge return");
    let (tx, out) = step(&mut f.chain, replay);
    successful(&tx, "replayed paid retry refunds only its own inbound fees");
    assert!(
        out.iter().all(|m| m.dst().as_ref() != Some(&f.validator.address)),
        "an acknowledged return cannot pay principal again"
    );
    let (tx, out) = step(&mut f.chain, kick);
    successful(&tx, "settle after repeated native bounces");
    let payment = only_to(out, &f.pool);
    let before = balance_of(&f.chain, &f.pool);
    let (tx, out) = step(&mut f.chain, payment);
    successful(&tx, "final pool receipt");
    assert_eq!(balance_of(&f.chain, &f.pool), before + debt);
    assert!(value(&only_to(out.clone(), caller.address())) > 0);
    let ack = only_to(out, &f.validator.address);
    let (tx, _) = step(&mut f.chain, ack);
    successful(&tx, "final cleanup");
    assert!(f.pending().is_none());
}

#[test]
fn operating_withdrawal_is_explicit_bounded_and_cannot_touch_pending_debt() {
    fn request(f: &Fixture, amount: u128) -> Message {
        operating_request(
            f,
            "withdraw-operations",
            contracts::validator_controller::operating_withdrawal_payload(
                f.operator.address(),
                amount,
            )
            .expect("withdrawal payload"),
        )
    }
    let mut f = Fixture::new("r3-operating-withdrawal");
    let original = request(&f, u128::from(10 * TOS));
    let stranger =
        f.chain.blockchain.treasury("withdrawal-stranger", 1_000 * TOS).expect("stranger");
    let copied = stranger.build_message(
        &f.validator.address,
        100 * TOS,
        true,
        Some(original.body().expect("body").clone().into_cell().expect("cell")),
    );
    let (tx, _) = step(&mut f.chain, copied);
    assert!(tx.read_description().expect("description").is_aborted(), "withdrawal sender binding");
    let before = balance_of(&f.chain, &f.validator.address);
    let (tx, out) = step(&mut f.chain, original.clone());
    successful(&tx, "withdraw unreserved operating funds");
    assert_eq!(funds(&f), u128::from(70 * TOS), "withdrawal debits operating ledger");
    assert_eq!(balance_of(&f.chain, &f.validator.address), before - u128::from(10 * TOS));
    assert!(value(&only_to(out, f.operator.address())) > u128::from(100 * TOS));
    let (tx, _) = step(&mut f.chain, original);
    assert!(tx.read_description().expect("description").is_aborted(), "withdrawal cannot replay");
    let too_much = request(&f, u128::from(71 * TOS));
    let (tx, _) = step(&mut f.chain, too_much);
    assert!(
        tx.read_description().expect("description").is_aborted(),
        "unclassified assets are not operating funds"
    );
    let at = f.election + 1;
    let stake = begin(&mut f, 1, at);
    let (tx, out) = step(&mut f.chain, stake);
    successful(&tx, "refusal pending settlement");
    let result = only_to(out, &f.validator.address);
    let pending = f.pending();
    let remaining = funds(&f);
    let withdrawal = request(&f, remaining);
    let (tx, _) = step(&mut f.chain, withdrawal);
    assert!(
        tx.read_description().expect("description").is_aborted(),
        "pending debt blocks withdrawal"
    );
    assert_eq!(f.pending(), pending);
    assert_eq!(funds(&f), remaining);
    finish_reply(&mut f, result, 0);
    let withdrawal = request(&f, remaining);
    let (tx, _) = step(&mut f.chain, withdrawal);
    successful(&tx, "release remaining operating funds after cleanup");
    assert_eq!(funds(&f), 0);
}
