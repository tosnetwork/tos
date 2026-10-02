//! Explicit debt and paid retry controls. Every hop uses the native action phase.
use super::*;

const RETRY_FEES: u32 = 0x50517834;

fn retry_flight(f: &Fixture) -> Option<chain_block::Cell> {
    let result = f
        .chain
        .blockchain
        .run_get_method(&f.validator.address, "relay_retry_fees", vec![])
        .expect("retry flight");
    assert_eq!(result.exit_code, 0);
    result.stack[0].as_cell().ok().cloned()
}

fn wait_budget(f: &Fixture) -> u64 {
    let result = f
        .chain
        .blockchain
        .run_get_method(&f.validator.address, "relay_retry_value", vec![])
        .expect("current retry budget");
    assert_eq!(result.exit_code, 0);
    result.stack[0].as_integer().expect("budget").to_string().parse().expect("coins")
}

// Deliver the independent terminal fee receipt as its own real transaction.
// Business messages stay queued, and caller refunds remain visible to assertions.
fn settle_retry_fees(f: &mut Fixture, messages: Vec<Message>) -> Vec<Message> {
    let mut remaining = Vec::new();
    for message in messages {
        if op(&message) == RETRY_FEES {
            assert_eq!(message.dst().as_ref(), Some(&f.validator.address));
            let (tx, refunds) = step(&mut f.chain, message);
            successful(&tx, "settle this retry flight's actual fees");
            remaining.extend(refunds);
        } else {
            remaining.push(message);
        }
    }
    remaining
}

fn pool_capital(f: &Fixture) -> u128 {
    let result =
        f.chain.blockchain.run_get_method(&f.pool, "get_pool_data", vec![]).expect("pool data");
    assert_eq!(result.exit_code, 0);
    result.stack[3].as_integer().expect("validator amount").to_string().parse().expect("coins")
}

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
    let out = settle_retry_fees(&mut f, out);
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
    let out = settle_retry_fees(&mut f, out);
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
        let out = settle_retry_fees(&mut f, out);
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
    let out = settle_retry_fees(&mut f, out);
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
    let out = settle_retry_fees(&mut f, out);
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
    let out = settle_retry_fees(&mut f, out);
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

#[test]
fn review_underfunded_wait_retry_is_refused_before_forwarding_and_exact_budget_completes() {
    let mut f = Fixture::new("review-wait-threshold");
    let at = f.election + 1;
    let stake = begin(&mut f, 1, at);
    let (tx, out) = step(&mut f.chain, stake);
    successful(&tx, "elector emits original refusal");
    let refund = only_to(out, &f.validator.address);
    abort_result_and_deliver_native_bounce(&mut f, refund);
    let pending = f.pending();
    let caller = f.chain.blockchain.treasury("review-budget-payer", 1_000 * TOS).expect("caller");
    let body = retry(&f, DOMAIN | 1).body().expect("body").clone().into_cell().expect("body cell");
    let budget = wait_budget(&f);
    assert!(budget > 3 * TOS);
    for amount in [3 * TOS, budget - 1] {
        let before = balance_of(&f.chain, &f.validator.address);
        let request = caller.build_message(&f.validator.address, amount, true, Some(body.clone()));
        let (tx, out) = step(&mut f.chain, request);
        assert!(
            tx.read_description().expect("description").is_aborted(),
            "R3 review: insufficient WAIT budget must be refused at the controller"
        );
        assert_eq!(f.pending(), pending);
        assert!(retry_flight(&f).is_none());
        assert_eq!(balance_of(&f.chain, &f.validator.address), before);
        let bounced = only_to(out, caller.address());
        assert!(bounced.is_bounced());
        assert!(value(&bounced) > 0, "rejected inlet returns actual remaining caller cash");
    }
    let request = caller.build_message(&f.validator.address, budget, true, Some(body));
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "exact WAIT threshold forwards the complete downstream budget");
    assert!(retry_flight(&f).is_some());
    let repair = only_to(out, &f.chain.elector);
    let (tx, out) = step(&mut f.chain, repair);
    successful(&tx, "exact controller threshold must also satisfy elector");
    let out = settle_retry_fees(&mut f, out);
    assert!(
        value(&only_to(out.clone(), caller.address())) > 0,
        "terminal retry fees go to the actual caller"
    );
    assert!(retry_flight(&f).is_none());
    let reply = only_to(out, &f.validator.address);
    finish_reply(&mut f, reply, 0);
}

#[test]
fn review_controller_retry_action_failure_returns_current_payer_funds() {
    let mut f = Fixture::new("review-controller-retry-action");
    let at = f.election + 1;
    let stake = begin(&mut f, 1, at);
    let (tx, out) = step(&mut f.chain, stake);
    successful(&tx, "initial refusal");
    let refund = only_to(out, &f.validator.address);
    abort_result_and_deliver_native_bounce(&mut f, refund);
    let pending = f.pending();
    let protected = balance_of(&f.chain, &f.validator.address);
    let caller =
        f.chain.blockchain.treasury("review-controller-action-payer", 1_000 * TOS).expect("caller");
    let body = retry(&f, DOMAIN | 1).body().expect("body").clone().into_cell().expect("cell");
    f.chain
        .blockchain
        .set_size_limits_config(chain_block::SizeLimitsConfig {
            max_msg_cells: 0,
            ..chain_block::SizeLimitsConfig::default()
        })
        .expect("action limit");
    let request = caller.build_message(&f.validator.address, 20 * TOS, true, Some(body.clone()));
    let (tx, out) = step(&mut f.chain, request);
    action_failure(&tx);
    assert!(
        out.iter()
            .any(|m| m.is_bounced() && m.dst().as_ref() == Some(caller.address()) && value(m) > 0),
        "controller retry action failure must bounce current payer funds"
    );
    assert_eq!(f.pending(), pending, "failed forwarding preserves business debt");
    assert!(retry_flight(&f).is_none(), "failed forwarding rolls back fee ownership");
    assert_eq!(
        balance_of(&f.chain, &f.validator.address),
        protected,
        "failed forwarding preserves unrelated assets"
    );
    f.chain
        .blockchain
        .set_size_limits_config(chain_block::SizeLimitsConfig::default())
        .expect("restore action limit");
    let request = caller.build_message(&f.validator.address, 20 * TOS, true, Some(body));
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "retry after action repair");
    let repair = only_to(out, &f.chain.elector);
    let (tx, out) = step(&mut f.chain, repair);
    successful(&tx, "elector redelivery after repaired controller action");
    let out = settle_retry_fees(&mut f, out);
    let reply = only_to(out, &f.validator.address);
    finish_reply(&mut f, reply, 0);
}

#[test]
fn review_wait_retry_native_compute_and_action_bounces_refund_only_the_bound_caller() {
    for failure in ["compute", "action"] {
        let mut f = Fixture::new(failure);
        let at = f.election + 1;
        let stake = begin(&mut f, 1, at);
        let (tx, out) = step(&mut f.chain, stake);
        successful(&tx, "initial refusal");
        let refund = only_to(out, &f.validator.address);
        abort_result_and_deliver_native_bounce(&mut f, refund);
        let pending = f.pending();
        let before = balance_of(&f.chain, &f.validator.address);
        let caller =
            f.chain.blockchain.treasury("review-bounce-payer", 1_000 * TOS).expect("caller");
        let other =
            f.chain.blockchain.treasury("review-other-payer", 1_000 * TOS).expect("other caller");
        let body = retry(&f, DOMAIN | 1).body().expect("body").clone().into_cell().expect("cell");
        let request =
            caller.build_message(&f.validator.address, 20 * TOS, true, Some(body.clone()));
        let (tx, out) = step(&mut f.chain, request);
        successful(&tx, "valid paid WAIT repair");
        let repair = only_to(out, &f.chain.elector);
        let flight = retry_flight(&f);
        let mut fields = SliceData::load_cell(flight.clone().expect("flight")).expect("fields");
        let query = fields.get_next_u64().expect("query");
        let token = fields.get_next_bits(160).expect("token");
        let mut forged = BuilderData::new();
        forged.append_u32(RETRY_FEES).expect("op");
        forged.append_u64(query).expect("query");
        forged.append_raw(&token, 160).expect("token");
        let fake = other.build_message(
            &f.validator.address,
            TOS,
            true,
            Some(forged.into_cell().expect("body")),
        );
        let (tx, out) = step(&mut f.chain, fake);
        successful(&tx, "untrusted terminal receipt cannot settle a fee flight");
        assert!(out.is_empty(), "only the pinned elector may settle retry fees");
        assert_eq!(retry_flight(&f), flight, "terminal receipt sender binding");
        let protected = balance_of(&f.chain, &f.validator.address);
        assert!(protected >= before);
        let competing =
            other.build_message(&f.validator.address, 20 * TOS, true, Some(body.clone()));
        let (tx, out) = step(&mut f.chain, competing);
        assert!(
            tx.read_description().expect("description").is_aborted(),
            "one flight cannot overwrite another payer"
        );
        assert!(only_to(out, other.address()).is_bounced());
        assert_eq!(retry_flight(&f), flight);
        let prices = raw_parameter(&f.chain, 20).expect("prices");
        let special = raw_parameter(&f.chain, 31).expect("special accounts");
        if failure == "compute" {
            let mut restricted = f.chain.blockchain.config_params().gas_prices(true).expect("gas");
            restricted.gas_limit = 1_000;
            restricted.special_gas_limit = 1_000;
            set_contract_parameter(
                &mut f.chain,
                20,
                restricted.write_to_new_cell().expect("prices").into_cell().expect("cell"),
            );
        } else {
            // The Rust native executor exempts special accounts from message-size
            // limits. Temporarily remove that exemption to exercise an actual
            // elector action failure; do not count a compute refusal as one.
            let mut ordinary = BuilderData::new();
            ordinary.append_bit_zero().expect("empty special-account dictionary");
            set_contract_parameter(&mut f.chain, 31, ordinary.into_cell().expect("cell"));
            f.chain
                .blockchain
                .set_size_limits_config(chain_block::SizeLimitsConfig {
                    max_msg_cells: 0,
                    ..chain_block::SizeLimitsConfig::default()
                })
                .expect("action limit");
        }
        let (tx, out) = step(&mut f.chain, repair);
        if failure == "compute" {
            assert!(tx.read_description().expect("description").is_aborted());
            match tx.read_description().expect("description") {
                TransactionDescr::Ordinary(d) => match d.compute_ph {
                    TrComputePhase::Vm(vm) => assert_eq!(vm.exit_code, -14),
                    _ => panic!("native OOG"),
                },
                _ => panic!("ordinary transaction"),
            }
        } else {
            action_failure(&tx);
        }
        assert!(
            out.iter().any(|m| m.is_bounced()),
            "native elector failure must bounce the paid retry"
        );
        let bounce = only_to(out, &f.validator.address);
        assert!(bounce.is_bounced());
        let duplicate = bounce.clone();
        set_contract_parameter(&mut f.chain, 20, prices);
        set_contract_parameter(&mut f.chain, 31, special);
        f.chain
            .blockchain
            .set_size_limits_config(chain_block::SizeLimitsConfig::default())
            .expect("restore action limit");
        let (tx, out) = step(&mut f.chain, bounce);
        successful(&tx, "native retry bounce is classified by its exact flight");
        assert!(
            out.iter().any(|m| m.dst().as_ref() == Some(caller.address()) && value(m) > 0),
            "R3 review: native retry bounce must refund its bound caller"
        );
        assert_eq!(f.pending(), pending, "fee failure cannot change business debt");
        assert!(retry_flight(&f).is_none(), "settled retry fees clear their ownership record");
        assert_eq!(
            balance_of(&f.chain, &f.validator.address),
            protected,
            "retry bounce cannot retain current fees or spend unrelated assets"
        );
        let request = other.build_message(&f.validator.address, 20 * TOS, true, Some(body));
        let (tx, out) = step(&mut f.chain, request);
        successful(&tx, "second caller starts a distinct fee flight");
        let repair = only_to(out, &f.chain.elector);
        let next = retry_flight(&f);
        assert_ne!(next, flight);
        let (tx, out) = step(&mut f.chain, duplicate);
        successful(&tx, "late duplicate cannot settle a later flight");
        assert!(out.is_empty(), "duplicate bounce cannot refund twice or pay the latest caller");
        assert_eq!(retry_flight(&f), next, "flight identity rejects a stale bounce");
        let (tx, out) = step(&mut f.chain, repair);
        successful(&tx, "normal repair after the first failure");
        let out = settle_retry_fees(&mut f, out);
        assert!(value(&only_to(out.clone(), other.address())) > 0);
        let result = only_to(out, &f.validator.address);
        finish_reply(&mut f, result, 0);
    }
}

fn reduced_success_payment(f: &mut Fixture) -> (Message, u128) {
    let at = f.election;
    let stake = begin(f, 1, at);
    let (tx, out) = step(&mut f.chain, stake);
    successful(&tx, "elector accepts the real stake");
    let result = only_to(out, &f.validator.address);
    assert_eq!(op(&result), 0x50516f32);
    let gross = value(&result);
    let recovered = abort_result_and_deliver_native_bounce(f, result);
    assert!(recovered < gross);
    let request = retry(f, DOMAIN | 1);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "fund successful confirmation recovery");
    let repair = only_to(out, &f.chain.elector);
    let (tx, out) = step(&mut f.chain, repair);
    successful(&tx, "redeliver successful confirmation");
    let out = settle_retry_fees(f, out);
    let (tx, out) = step(&mut f.chain, only_to(out, &f.validator.address));
    successful(&tx, "record actual reduced confirmation");
    let (tx, out) = step(&mut f.chain, only_to(out, &f.validator.address));
    successful(&tx, "pay actual reduced confirmation");
    (only_to(out, &f.pool), gross - recovered)
}

fn pool_nominators(f: &Fixture) -> chain_block::HashmapE {
    let account = f.chain.blockchain.get_account(&f.pool).expect("pool");
    let mut data = SliceData::load_cell(account.get_data().expect("data")).expect("slice");
    data.get_next_byte().expect("state");
    data.get_next_u16().expect("count");
    next_coins(&mut data);
    next_coins(&mut data);
    data.checked_drain_reference().expect("config");
    next_dictionary(&mut data, 256)
}

fn deposit_review_nominator(f: &mut Fixture) {
    f.chain.blockchain.set_workchain(0);
    let nominator =
        f.chain.blockchain.treasury("review-nominator", 50_000 * TOS).expect("nominator");
    f.chain.blockchain.set_workchain(-1);
    let mut body = BuilderData::new();
    body.append_u32(0).expect("text");
    body.append_u8(b'd').expect("deposit");
    let message =
        nominator.build_message(&f.pool, 4_902 * TOS, true, Some(body.into_cell().expect("body")));
    let (tx, _) = step(&mut f.chain, message);
    successful(&tx, "real nominator principal before transport loss");
    f.nominator = Some(nominator);
}

#[test]
fn review_successful_confirmation_bounce_accounts_for_validator_loss() {
    let mut f = Fixture::new("review-success-bounce-loss");
    deposit_review_nominator(&mut f);
    let nominators = pool_nominators(&f);
    let before = pool_capital(&f);
    let (payment, loss) = reduced_success_payment(&mut f);
    let (tx, out) = step(&mut f.chain, payment);
    successful(&tx, "pool accepts successful but reduced return");
    assert_eq!(f.pool_state(), 2);
    let ack = only_to(out, &f.validator.address);
    assert_eq!(
        pool_capital(&f),
        before - loss,
        "R3 review: success-path transport loss must be reflected in validator capital"
    );
    assert_eq!(pool_nominators(&f), nominators, "transport loss cannot be charged to nominators");
    let request = retry(&f, DOMAIN | 1);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "repeat paid receipt before cleanup");
    let payment = only_to(out, &f.pool);
    let (tx, _) = step(&mut f.chain, payment);
    successful(&tx, "pool repairs receipt acknowledgment only");
    assert_eq!(
        pool_capital(&f),
        before - loss,
        "repeated successful receipt cannot charge loss twice"
    );
    assert_eq!(pool_nominators(&f), nominators);
    let (tx, _) = step(&mut f.chain, ack);
    successful(&tx, "cleanup");
}

#[test]
fn review_insufficient_validator_capital_waits_for_explicit_topup_then_records_loss_once() {
    let mut f = Fixture::new("review-low-validator-capital");
    deposit_review_nominator(&mut f);
    let nominators = pool_nominators(&f);
    let (payment, loss) = reduced_success_payment(&mut f);
    assert!(loss > 0);
    // A pre-existing undercapitalized ledger is a boundary fixture, not a
    // claim that this profile can burn 5,100 TOS in a single confirmation.
    let mut account = f.chain.blockchain.get_account(&f.pool).expect("pool").clone();
    let mut fields = SliceData::load_cell(account.get_data().expect("data")).expect("slice");
    let mut data = BuilderData::new();
    data.append_u8(fields.get_next_byte().expect("state")).expect("state");
    data.append_u16(fields.get_next_u16().expect("count")).expect("count");
    Coins::new(next_coins(&mut fields) as u64).write_to(&mut data).expect("sent");
    next_coins(&mut fields);
    Coins::new((loss - 1) as u64).write_to(&mut data).expect("capital below loss");
    data.checked_append_references_and_data(&fields).expect("unchanged claims");
    let original = data.into_cell().expect("data");
    account.set_data(original.clone());
    f.chain.blockchain.set_account(f.pool.clone(), account);
    let (tx, out) = step(&mut f.chain, payment);
    successful(
        &tx,
        "insufficient capital refunds current callback fees without committing receipt",
    );
    assert!(
        out.iter().any(|m| m.dst().as_ref() == Some(f.operator.address()) && value(m) > 0),
        "insufficient capital must return current caller fees"
    );
    assert!(
        out.iter().all(|m| m.dst().as_ref() != Some(&f.validator.address)),
        "no accounting ACK before validator topup"
    );
    assert_eq!(f.pool_state(), 1);
    assert_eq!(
        f.chain.blockchain.get_account(&f.pool).expect("pool").get_data().expect("data"),
        original
    );
    assert_eq!(pool_nominators(&f), nominators);
    let mut deposit = BuilderData::new();
    deposit.append_u32(4).expect("validator deposit");
    deposit.append_u64(0).expect("query");
    let message =
        f.operator.build_message(&f.pool, 3 * TOS, true, Some(deposit.into_cell().expect("body")));
    let (tx, _) = step(&mut f.chain, message);
    successful(&tx, "explicit validator topup while result accounting is pending");
    let funded = pool_capital(&f);
    assert!(funded >= loss);
    let request = retry(&f, DOMAIN | 1);
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "PAID receipt retry after validator topup");
    let (tx, out) = step(&mut f.chain, only_to(out, &f.pool));
    successful(&tx, "topup allows original loss accounting");
    assert_eq!(f.pool_state(), 2);
    assert_eq!(pool_capital(&f), funded - loss, "topup covers the recorded loss exactly once");
    assert_eq!(
        pool_nominators(&f),
        nominators,
        "undercapitalized recovery preserves all nominator claims"
    );
    let (tx, _) = step(&mut f.chain, only_to(out, &f.validator.address));
    successful(&tx, "clear original debt after repaired accounting");
    assert!(f.pending().is_none());
}

#[test]
fn review_delayed_native_retry_bounce_keeps_its_payer_after_business_cleanup_and_a_later_query() {
    let mut f = Fixture::new("review-delayed-retry-bounce");
    let at = f.election + 1;
    let stake = begin(&mut f, 1, at);
    let (tx, out) = step(&mut f.chain, stake);
    successful(&tx, "elector records first refusal");
    let original_result = only_to(out, &f.validator.address);
    let caller = f.chain.blockchain.treasury("review-old-fee-payer", 1_000 * TOS).expect("caller");
    let body = retry(&f, DOMAIN | 1).body().expect("body").clone().into_cell().expect("cell");
    let request = caller.build_message(&f.validator.address, 20 * TOS, true, Some(body));
    let (tx, out) = step(&mut f.chain, request);
    successful(&tx, "paid retry while original result is in flight");
    let repair = only_to(out, &f.chain.elector);
    let old_flight = retry_flight(&f);
    let prices = raw_parameter(&f.chain, 20).expect("prices");
    let mut restricted = f.chain.blockchain.config_params().gas_prices(true).expect("gas");
    restricted.special_gas_limit = 1_000;
    set_contract_parameter(
        &mut f.chain,
        20,
        restricted.write_to_new_cell().expect("prices").into_cell().expect("cell"),
    );
    let (tx, out) = step(&mut f.chain, repair);
    assert!(tx.read_description().expect("description").is_aborted());
    let late_bounce = only_to(out, &f.validator.address);
    assert!(late_bounce.is_bounced());
    set_contract_parameter(&mut f.chain, 20, prices);
    finish_reply(&mut f, original_result, 0);
    assert_eq!(
        retry_flight(&f),
        old_flight,
        "business cleanup must preserve another message's fee ownership"
    );
    let second = begin(&mut f, 2, at);
    let waiting = f.pending();
    let (tx, out) = step(&mut f.chain, late_bounce);
    successful(&tx, "late native bounce settles the old independent fee flight");
    assert!(
        value(&only_to(out, caller.address())) > 0,
        "late native retry fees must return to the original payer"
    );
    assert!(retry_flight(&f).is_none());
    assert_eq!(f.pending(), waiting, "late bounce cannot modify a later business debt");
    let (tx, out) = step(&mut f.chain, second);
    successful(&tx, "second business request");
    let result = only_to(out, &f.validator.address);
    finish_reply(&mut f, result, 0);
}
