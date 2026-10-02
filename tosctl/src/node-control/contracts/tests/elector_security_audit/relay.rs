//! Asynchronous receipts and funds, using one native transaction at a time.
mod r3_accounting;
mod r3_r4;
use super::*;
use chain_block::{Coins, Message, TrComputePhase, Transaction, TransactionDescr};
use contracts::nominator::{NewStakeParams, new_stake_with_witness};
use tos_sandbox::{MessageBuilder, Treasury};

const RELAY: u32 = 0x50517232;
const RESULT: u32 = 0x50516232;
const RETRY: u32 = 0x50516632;
const ACK: u32 = 0x50516132;
const DOMAIN: u64 = 1 << 63;

struct Fixture {
    chain: Chain,
    validator: RootedValidator,
    operator: Treasury,
    pool: MsgAddressInt,
    election: u32,
    nominator: Option<Treasury>,
}
impl Fixture {
    fn new(label: &str) -> Self {
        let mut fixture = Self::unfunded(label);
        r3_accounting::fund(&mut fixture, 80 * TOS, 60 * TOS);
        fixture
    }
    fn unfunded(label: &str) -> Self {
        let (mut chain, _, election) = open_election(label, 200_000 * TOS);
        raise_to_post_quantum_version(&mut chain);
        if std::env::var_os("R3_FEE_TRACE").is_some() {
            for parameter in [20, 24] {
                let config = raw_parameter(&chain, parameter).expect("fee configuration");
                println!(
                    "R3_FEE_CONFIG parameter={parameter} boc={}",
                    hex::encode(chain_block::write_boc(&config).expect("public configuration BOC"))
                );
            }
        }
        let validator = deploy_rooted_validator(&mut chain, 0x52);
        admit_code_of(&mut chain, &validator.address);
        let operator = chain.blockchain.treasury(label, 100_000 * TOS).expect("operator");
        let pool = deploy_multi_nominator(&mut chain, operator.address(), &validator.address);
        Self { chain, validator, operator, pool, election, nominator: None }
    }
    fn order(&self, query: u64, at: u32, forwarded: u64) -> Message {
        let owner = chain_block::UInt256::from_slice(&self.pool.address().get_bytestring(0));
        let preimage = pq_stake_preimage_for(
            global_id(&self.chain),
            at,
            0x10000,
            &self.validator.id(),
            &owner,
            1,
            &self.validator.consensus.key_id(),
            &self.validator.consensus.adnl,
        );
        let signature = self.validator.consensus.sign(&preimage);
        let (code, data) = self.validator.birth.as_ref().expect("immutable birth witness");
        let mut birth = BuilderData::new();
        birth.append_raw(code.repr_hash().as_slice(), 256).expect("code hash");
        birth.append_u16(code.repr_depth()).expect("code depth");
        birth.append_raw(data.repr_hash().as_slice(), 256).expect("data hash");
        birth.append_u16(data.repr_depth()).expect("data depth");
        let witness = birth.into_cell().expect("birth witness");
        let body = new_stake_with_witness(
            &NewStakeParams {
                query_id: query,
                stake_amount: forwarded,
                validator_pubkey: &self.validator.consensus.public_key,
                stake_at: at,
                max_factor: 0x10000,
                adnl_addr: &self.validator.consensus.adnl,
                signature: &signature,
            },
            Some(&witness),
        )
        .expect("production order");
        self.operator.build_message(&self.pool, 20 * TOS, true, Some(body))
    }
    fn pool_state(&self) -> u8 {
        let result = self
            .chain
            .blockchain
            .run_get_method(&self.pool, "get_pool_data", vec![])
            .expect("pool getter");
        assert_eq!(result.exit_code, 0);
        result.stack[0].as_integer().expect("state").to_string().parse().expect("u8")
    }
    fn pending(&self) -> Option<chain_block::Cell> {
        let result = self
            .chain
            .blockchain
            .run_get_method(&self.validator.address, "relay_pending", vec![])
            .expect("pending getter");
        assert_eq!(result.exit_code, 0);
        result.stack[0].as_cell().ok().cloned()
    }
}

fn value(message: &Message) -> u128 {
    message.int_header().expect("internal").value.coins.as_u128()
}
fn op(message: &Message) -> u32 {
    message.body().expect("body").clone().get_next_u32().expect("opcode")
}
fn successful(transaction: &Transaction, label: &str) {
    assert!(
        !transaction.read_description().expect("description").is_aborted(),
        "{label}: {:?}",
        transaction.read_description()
    );
}
fn action_failure(transaction: &Transaction) {
    match transaction.read_description().expect("description") {
        TransactionDescr::Ordinary(d) => {
            assert!(
                matches!(d.compute_ph, TrComputePhase::Vm(ref vm) if vm.success),
                "compute must actually succeed"
            );
            let action = d.action.expect("real action phase");
            assert!(!action.success, "a compute-only refusal cannot prove action rollback");
            assert_ne!(action.result_code, 0);
            assert!(d.aborted);
        }
        _ => panic!("ordinary action"),
    }
}
fn step(chain: &mut Chain, message: Message) -> (Transaction, Vec<Message>) {
    let destination = message.dst().expect("destination");
    let before = balance_of(chain, &destination);
    let inbound = value(&message);
    let inbound_op = message.body().and_then(|b| b.clone().get_next_u32().ok()).unwrap_or(0);
    let (_, transaction, outbound) =
        chain.blockchain.execute_one(message).expect("native transaction/action phase");
    let after = balance_of(chain, &destination);
    let transferred: u128 = outbound
        .iter()
        .map(|m| value(m) + m.int_header().expect("internal").fwd_fee.as_u128())
        .sum();
    assert_eq!(
        before + inbound,
        after + transaction.total_fees().coins.as_u128() + transferred,
        "real transaction principal, balance and fees must reconcile"
    );
    if std::env::var_os("R3_FEE_TRACE").is_some() {
        if let TransactionDescr::Ordinary(ref d) =
            transaction.read_description().expect("description")
        {
            if let TrComputePhase::Vm(ref vm) = d.compute_ph {
                println!(
                    "R3_FEE op={inbound_op:08x} gas={} inbound={inbound} fees={} outbound={} aborted={}",
                    vm.gas_used,
                    transaction.total_fees().coins.as_u128(),
                    transferred,
                    d.aborted
                );
            }
        }
    }
    (transaction, outbound)
}
fn only_to(messages: Vec<Message>, destination: &MsgAddressInt) -> Message {
    let mut selected: Vec<_> =
        messages.into_iter().filter(|m| m.dst().as_ref() == Some(destination)).collect();
    assert_eq!(selected.len(), 1, "one real outbound message to {destination}");
    selected.remove(0)
}

#[test]
fn the_three_real_contracts_close_the_stake_receipt_and_return_unused_budget() {
    let mut fixture = Fixture::new("bound-relay-success");
    let capital = balance_of(&fixture.chain, &fixture.validator.address);
    let order = fixture.order(1, fixture.election, 10_002 * TOS);
    let (pool_tx, pool_out) = step(&mut fixture.chain, order);
    successful(&pool_tx, "pool inlet");
    assert_eq!(fixture.pool_state(), 1);
    let relay = only_to(pool_out, &fixture.validator.address);
    assert_eq!(op(&relay), RELAY);
    let (relay_tx, relay_out) = step(&mut fixture.chain, relay);
    successful(&relay_tx, "controller forwarding");
    if let TransactionDescr::Ordinary(d) = relay_tx.read_description().expect("description") {
        if let TrComputePhase::Vm(vm) = d.compute_ph {
            println!("caller-funded controller verification gas={}", vm.gas_used);
            assert!(vm.gas_used < 200_000, "relay gas envelope");
        } else {
            panic!("real controller VM must execute");
        }
    }
    assert!(fixture.pending().is_some(), "controller must retain the real creditor");
    let stake = only_to(relay_out, &fixture.chain.elector);
    assert_eq!(value(&stake), u128::from(10_002 * TOS), "forwarded principal is exact");
    let (elector_tx, elector_out) = step(&mut fixture.chain, stake);
    successful(&elector_tx, "elector acceptance");
    let receipt = only_to(elector_out, &fixture.validator.address);
    let (receipt_tx, receipt_out) = step(&mut fixture.chain, receipt);
    successful(&receipt_tx, "controller stores result before payment");
    let kick = only_to(receipt_out, &fixture.validator.address);
    assert_eq!(op(&kick), RETRY);
    let (payment_tx, payment_out) = step(&mut fixture.chain, kick);
    successful(&payment_tx, "controller payment action");
    let payment = only_to(payment_out, &fixture.pool);
    assert_eq!(op(&payment), RESULT);
    assert!(
        !payment.int_header().expect("header").bounce,
        "principal must not bounce on recipient abort"
    );
    assert!(value(&payment) > u128::from(TOS), "unused caller budget returns to its owner");
    let (settle_tx, settle_out) = step(&mut fixture.chain, payment);
    successful(&settle_tx, "pool consumes bound receipt");
    assert_eq!(fixture.pool_state(), 2, "pool must finish its pending business transition");
    let ack = only_to(settle_out, &fixture.validator.address);
    assert_eq!(op(&ack), ACK);
    let (ack_tx, _) = step(&mut fixture.chain, ack);
    successful(&ack_tx, "owner acknowledgment");
    assert!(fixture.pending().is_none(), "completed relay must not leak a pending slot");
    assert_eq!(
        balance_of(&fixture.chain, &fixture.validator.address),
        capital - r3_accounting::first_grant(&fixture),
        "only the explicit operator grant leaves controller capital"
    );
    let (members, _) = pq_book(&fixture.chain);
    let member = members
        .get(fixture.validator.address.address().clone())
        .expect("member")
        .expect("registered");
    assert_eq!(next_coins(&mut member.clone()), u128::from(10_001 * TOS));
}

fn begin(fixture: &mut Fixture, query: u64, at: u32) -> Message {
    let order = fixture.order(query, at, 10_002 * TOS);
    let (pool_tx, out) = step(&mut fixture.chain, order);
    successful(&pool_tx, "pool order");
    let relay = only_to(out, &fixture.validator.address);
    let (controller_tx, out) = step(&mut fixture.chain, relay);
    successful(&controller_tx, "bound relay");
    only_to(out, &fixture.chain.elector)
}
fn finish_reply(fixture: &mut Fixture, receipt: Message, expected_state: u8) {
    let (tx, out) = step(&mut fixture.chain, receipt);
    successful(&tx, "record reply");
    for ack in out
        .iter()
        .filter(|m| m.dst().as_ref() == Some(&fixture.chain.elector))
        .cloned()
        .collect::<Vec<_>>()
    {
        let (tx, _) = step(&mut fixture.chain, ack);
        successful(&tx, "elector delivery acknowledgment");
    }
    let kick = only_to(out, &fixture.validator.address);
    let (tx, out) = step(&mut fixture.chain, kick);
    successful(&tx, "pay recorded result");
    let payment = only_to(out, &fixture.pool);
    let (tx, out) = step(&mut fixture.chain, payment);
    successful(&tx, "pool callback");
    assert_eq!(fixture.pool_state(), expected_state);
    let ack = only_to(out, &fixture.validator.address);
    let (tx, _) = step(&mut fixture.chain, ack);
    successful(&tx, "acknowledgment");
    assert!(fixture.pending().is_none());
}
fn retry(fixture: &Fixture, query: u64) -> Message {
    let mut body = BuilderData::new();
    body.append_u32(RETRY).expect("opcode");
    body.append_u64(query).expect("query");
    fixture.operator.build_message(
        &fixture.validator.address,
        20 * TOS,
        true,
        Some(body.into_cell().expect("body")),
    )
}

fn pool_command(fixture: &Fixture, operation: u32) -> Message {
    let mut body = BuilderData::new();
    body.append_u32(operation).expect("operation");
    body.append_u64(99).expect("query");
    fixture.operator.build_message(
        &fixture.pool,
        20 * TOS,
        true,
        Some(body.into_cell().expect("command")),
    )
}

fn replace_body_reference(message: &mut Message, index: usize, replacement: chain_block::Cell) {
    let mut body =
        BuilderData::from_cell(&message.body().expect("body").clone().into_cell().expect("cell"))
            .expect("body builder");
    body.replace_reference_cell(index, replacement);
    message.set_body(SliceData::load_cell(body.into_cell().expect("changed body")).expect("slice"));
}

fn controller_authorization(
    fixture: &Fixture,
    kind: u8,
    payload: chain_block::Cell,
    successor: Option<&PqValidator>,
) -> Message {
    let state = fixture
        .chain
        .blockchain
        .run_get_method(&fixture.validator.address, "controller_state", vec![])
        .expect("authority state");
    assert_eq!(state.exit_code, 0);
    let epoch: u64 =
        state.stack[0].as_integer().expect("epoch").to_string().parse().expect("epoch");
    let nonce: u64 =
        state.stack[1].as_integer().expect("nonce").to_string().parse().expect("nonce");
    let until = fixture.chain.blockchain.now() + 600;
    let preimage = controller_preimage(
        global_id(&fixture.chain),
        &fixture.validator.id(),
        epoch,
        nonce,
        until,
        kind,
        &payload,
    );
    let signature = fixture.validator.root.sign_under(&preimage, CONTROLLER_CONTEXT);
    let mut body = BuilderData::new();
    body.append_u32(CONTROLLER_OP).expect("operation");
    body.append_u64(1).expect("query");
    body.append_i32(global_id(&fixture.chain)).expect("network");
    body.append_u64(epoch).expect("epoch");
    body.append_u64(nonce).expect("nonce");
    body.append_u32(until).expect("until");
    body.append_u8(kind).expect("kind");
    body.checked_append_reference(payload).expect("payload");
    body.checked_append_reference(stored_bytes(&signature)).expect("signature");
    if let Some(successor) = successor {
        body.append_bit_one().expect("co-signature");
        body.checked_append_reference(stored_bytes(
            &successor.sign_under(&preimage, CONTROLLER_CONTEXT),
        ))
        .expect("proof");
    } else {
        body.append_bit_zero().expect("no co-signature");
    }
    fixture.operator.build_message(
        &fixture.validator.address,
        100 * TOS,
        true,
        Some(body.into_cell().expect("authorization")),
    )
}

fn root_send(fixture: &Fixture, destination: &MsgAddressInt, body: chain_block::Cell) -> Message {
    let mut outgoing = BuilderData::new();
    outgoing.append_bits(0x18, 6).expect("relaxed header");
    destination.write_to(&mut outgoing).expect("destination");
    Coins::new(1_000 * TOS).write_to(&mut outgoing).expect("value");
    outgoing.append_bits(0, 1 + 4 + 4).expect("currency header");
    outgoing.append_u64(0).expect("logical time");
    outgoing.append_u32(0).expect("timestamp");
    outgoing.append_bit_zero().expect("no state init");
    outgoing.append_bit_one().expect("referenced body");
    outgoing.checked_append_reference(body).expect("body");
    let mut payload = BuilderData::new();
    payload.append_u8(1).expect("mode");
    payload
        .checked_append_reference(outgoing.into_cell().expect("wire message"))
        .expect("outgoing");
    controller_authorization(fixture, 1, payload.into_cell().expect("send payload"), None)
}

#[test]
fn malformed_or_underfunded_real_requests_refund_without_occupying_the_controller() {
    for scenario in [
        "bad-signature",
        "short-signature",
        "missing-signature-chain",
        "gas-limit",
        "elector-config",
        "malformed-witness",
    ] {
        let mut fixture = Fixture::new(scenario);
        let before = balance_of(&fixture.chain, &fixture.pool);
        let mut order = fixture.order(1, fixture.election, 10_002 * TOS);
        if scenario == "bad-signature" {
            replace_body_reference(&mut order, 1, stored_bytes(&vec![0x5a; 2420]));
        }
        if scenario == "short-signature" {
            replace_body_reference(&mut order, 1, stored_bytes(&vec![0x5a; 2419]));
        }
        if scenario == "missing-signature-chain" {
            replace_body_reference(&mut order, 1, chain_block::Cell::default());
        }
        if scenario == "malformed-witness" {
            replace_body_reference(&mut order, 2, chain_block::Cell::default());
        }
        let (tx, out) = step(&mut fixture.chain, order);
        successful(&tx, "pool preserves exact relay before fault");
        assert_eq!(fixture.pool_state(), 1);
        let original_gas = raw_parameter(&fixture.chain, 20).expect("masterchain gas");
        let original_elector = raw_parameter(&fixture.chain, 1).expect("elector identity");
        if scenario == "gas-limit" {
            let mut gas =
                fixture.chain.blockchain.config_params().gas_prices(true).expect("prices");
            gas.gas_limit = 1_000;
            set_contract_parameter(
                &mut fixture.chain,
                20,
                gas.write_to_new_cell().expect("gas").into_cell().expect("gas"),
            );
        }
        if scenario == "elector-config" {
            let mut bad = BuilderData::new();
            bad.append_raw(&[0; 32], 256).expect("no elector");
            set_contract_parameter(&mut fixture.chain, 1, bad.into_cell().expect("bad config"));
        }
        let relay = only_to(out, &fixture.validator.address);
        let (tx, out) = step(&mut fixture.chain, relay);
        set_contract_parameter(&mut fixture.chain, 20, original_gas);
        set_contract_parameter(&mut fixture.chain, 1, original_elector);
        if scenario == "malformed-witness" {
            successful(&tx, "canonical signature can reach elector witness check");
            let stake = only_to(out, &fixture.chain.elector);
            let (tx, out) = step(&mut fixture.chain, stake);
            assert!(tx.read_description().expect("description").is_aborted());
            let receipt = only_to(out, &fixture.validator.address);
            finish_reply(&mut fixture, receipt, 0);
        } else {
            assert!(
                tx.read_description().expect("description").is_aborted(),
                "{scenario}: actual controller must refuse"
            );
            assert!(fixture.pending().is_none(), "invalid request must not occupy pending");
            let bounce = only_to(out, &fixture.pool);
            assert!(bounce.is_bounced());
            let (tx, _) = step(&mut fixture.chain, bounce);
            successful(&tx, "exact front bounce clears original pool request");
        }
        assert_eq!(
            fixture.pool_state(),
            0,
            "{scenario}: failed route must automatically restore idle state"
        );
        assert!(fixture.pending().is_none());
        assert!(
            balance_of(&fixture.chain, &fixture.pool) > before - u128::from(TOS),
            "{scenario}: operator bears the bounded refusal loss"
        );
    }
}

#[test]
fn pool_receipts_bind_actual_controller_query_hash_and_exact_forwarded_amount() {
    let mut fixture = Fixture::new("receipt-binding");
    let at = fixture.election;
    let stake = begin(&mut fixture, 1, at);
    let (_, out) = step(&mut fixture.chain, stake);
    let receipt = only_to(out, &fixture.validator.address);
    let (_, out) = step(&mut fixture.chain, receipt);
    let kick = only_to(out, &fixture.validator.address);
    let (_, out) = step(&mut fixture.chain, kick);
    let payment = only_to(out, &fixture.pool);
    let original_data = fixture
        .chain
        .blockchain
        .get_account(&fixture.pool)
        .expect("pool")
        .get_data()
        .expect("data");
    let attacker =
        fixture.chain.blockchain.treasury("copied-receipt-sender", 100 * TOS).expect("attacker");
    for field in ["source", "query", "hash", "forwarded", "accepted"] {
        let mut bs = payment.body().expect("body").clone();
        let tag = bs.get_next_u32().expect("tag");
        let query = bs.get_next_u64().expect("query");
        let mut hash = bs.get_next_bits(256).expect("hash");
        if field == "hash" {
            hash[0] ^= 1;
        }
        let forwarded = next_coins(&mut bs);
        let accepted = next_coins(&mut bs);
        let reason = bs.get_next_u32().expect("reason");
        let success = bs.get_next_bit().expect("success");
        let mut body = BuilderData::new();
        body.append_u32(tag).expect("tag");
        body.append_u64(query + u64::from(field == "query")).expect("query");
        body.append_raw(&hash, 256).expect("hash");
        Coins::new((forwarded + u128::from(field == "forwarded")) as u64)
            .write_to(&mut body)
            .expect("amount");
        Coins::new((accepted + u128::from(field == "accepted" || field == "forwarded")) as u64)
            .write_to(&mut body)
            .expect("amount");
        body.append_u32(reason).expect("reason");
        body.append_bit_bool(success).expect("success");
        body.checked_append_references_and_data(&bs).expect("unchanged accounting suffix");
        let source =
            if field == "source" { attacker.address() } else { &fixture.validator.address };
        let forged = MessageBuilder::internal(source, &fixture.pool, TOS)
            .bounce(false)
            .body(body.into_cell().expect("forged receipt"))
            .build();
        let _ = step(&mut fixture.chain, forged);
        assert_eq!(fixture.pool_state(), 1, "unbound {field} receipt cannot consume pending");
        assert_eq!(
            fixture
                .chain
                .blockchain
                .get_account(&fixture.pool)
                .expect("pool")
                .get_data()
                .expect("data"),
            original_data,
            "unbound {field} receipt cannot alter business storage"
        );
    }
    let (tx, out) = step(&mut fixture.chain, payment);
    successful(&tx, "original receipt remains available");
    assert_eq!(fixture.pool_state(), 2);
    let (tx, _) = step(&mut fixture.chain, only_to(out, &fixture.validator.address));
    successful(&tx, "original cleanup");
}

#[test]
fn authority_and_elector_changes_keep_the_original_in_flight_creditor() {
    let mut fixture = Fixture::new("pending-authority-changes");
    let at = fixture.election;
    let stake = begin(&mut fixture, 1, at);
    let original = fixture.pending().expect("pending");
    let send = root_send(&fixture, fixture.operator.address(), chain_block::Cell::default());
    let (tx, _) = step(&mut fixture.chain, send);
    assert!(
        tx.read_description().expect("description").is_aborted(),
        "root send must not spend pending third-party funds"
    );
    assert_eq!(fixture.pending().expect("root send refusal retains creditor"), original);
    let next_root = PqValidator::new(0x74);
    let mut payload = BuilderData::new();
    payload.checked_append_reference(stored_bytes(&next_root.public_key)).expect("new root");
    let rotate = controller_authorization(
        &fixture,
        2,
        payload.into_cell().expect("rotation"),
        Some(&next_root),
    );
    let (tx, _) = step(&mut fixture.chain, rotate);
    successful(&tx, "actual root rotation while pending");
    fixture.validator.root = next_root;
    assert_eq!(fixture.pending().expect("rotation retains creditor"), original);
    let next_key = PqValidator::new(0x75);
    let mut payload = BuilderData::new();
    payload.append_u16(1).expect("algorithm");
    payload.checked_append_reference(stored_bytes(&next_key.public_key)).expect("new consensus");
    let bind = controller_authorization(
        &fixture,
        3,
        payload.into_cell().expect("consensus bind"),
        Some(&next_key),
    );
    let (tx, _) = step(&mut fixture.chain, bind);
    successful(&tx, "actual consensus change while pending");
    assert_eq!(fixture.pending().expect("consensus change retains creditor"), original);
    // The old request reaches its pinned elector even if the configuration now names another.
    let old_elector = fixture.chain.elector.clone();
    let mut config = BuilderData::new();
    config.append_raw(&[0x29; 32], 256).expect("replacement elector");
    set_contract_parameter(&mut fixture.chain, 1, config.into_cell().expect("config"));
    let (tx, out) = step(&mut fixture.chain, stake);
    successful(&tx, "original elector processes old request");
    let receipt = only_to(out, &fixture.validator.address);
    finish_reply(&mut fixture, receipt, 2);
    assert_eq!(fixture.chain.elector, old_elector);
}

fn root_place(
    chain: &mut Chain,
    validator: &mut RootedValidator,
    election: u32,
    query: u64,
    amount: u64,
) {
    let signature = validator.consensus.sign(&pq_stake_preimage_for(
        global_id(chain),
        election,
        0x10000,
        &validator.id(),
        &validator.id(),
        1,
        &validator.consensus.key_id(),
        &validator.consensus.adnl,
    ));
    let witness = birth_witness(chain, &validator.address);
    let body =
        pq_stake_body(query, &validator.consensus, election, 0x10000, &signature, Some(witness));
    let result = validator.send_to_elector(chain, amount, body);
    result.expect_success();
    assert!(replies(&result).contains(&STAKE_ACCEPTED), "actual root-owned stake must be admitted");
}

fn rotate_elected_round(chain: &mut Chain, election: u32) {
    assert!(tick_at_close(chain, election, "native relay round").next_set_installed);
    chain.blockchain.set_config(configuration_from_contract(chain)).expect("adopt elected set");
    let takes_over =
        chain.blockchain.config_params().next_validator_set().expect("next set").utime_since();
    chain.blockchain.set_now(takes_over);
    chain
        .blockchain
        .tick_tock(&chain.config_contract, TransactionTickTock::Tock)
        .expect("real config rotation")
        .expect_success();
    chain.blockchain.set_config(configuration_from_contract(chain)).expect("adopt rotated set");
    for _ in 0..4 {
        if elector_purse_and_active_set(chain).1 == election {
            break;
        }
        tick(chain);
    }
    assert_eq!(elector_purse_and_active_set(chain).1, election, "the set must actually serve");
}

/// A served pool round, followed by a second genuinely elected and activated set.
/// No frozen book, credit or pool change counter is injected.
fn served_and_unfrozen_pool(label: &str) -> (Fixture, Vec<RootedValidator>) {
    served_with_receipt(label, false)
}
fn served_with_receipt(label: &str, retain_receipt: bool) -> (Fixture, Vec<RootedValidator>) {
    let mut fixture = Fixture::new(label);
    fixture.chain.blockchain.set_workchain(0);
    let nominator = fixture
        .chain
        .blockchain
        .treasury("served-relay-nominator", 50_000 * TOS)
        .expect("nominator");
    fixture.chain.blockchain.set_workchain(-1);
    let mut deposit = BuilderData::new();
    deposit.append_u32(0).expect("text");
    deposit.append_u8(b'd').expect("deposit");
    let message = nominator.build_message(
        &fixture.pool,
        4_902 * TOS,
        true,
        Some(deposit.into_cell().expect("body")),
    );
    let (tx, _) = step(&mut fixture.chain, message);
    successful(&tx, "actual nominator deposit");
    fixture.nominator = Some(nominator);
    if retain_receipt {
        let owner = fixture.operator.address().clone();
        credit_fixture(&mut fixture.chain, &owner, 50 * TOS, false);
        let request = recover_message(&owner, &fixture.chain.elector, 0x47657432, DOMAIN | 1);
        let (tx, _) = step(&mut fixture.chain, request);
        successful(&tx, "outstanding paid receipt before election writes");
    }
    let at = fixture.election;
    let stake = begin(&mut fixture, 1, at);
    let (tx, out) = step(&mut fixture.chain, stake);
    successful(&tx, "pooled inlet");
    let receipt = only_to(out, &fixture.validator.address);
    finish_reply(&mut fixture, receipt, 2);
    let mut first = Vec::new();
    for i in 0..3 {
        let mut validator = deploy_rooted_validator(&mut fixture.chain, 0x55 + i);
        root_place(&mut fixture.chain, &mut validator, at, 1, 10_002 * TOS);
        if i == 0 {
            root_place(&mut fixture.chain, &mut validator, at, 2, 1_001 * TOS);
        }
        first.push(validator);
    }
    let purse_before = elector_purse_and_active_set(&fixture.chain).0;
    let funding = fixture.operator.build_message(&fixture.chain.elector, 8_000 * TOS, false, None);
    let (tx, _) = step(&mut fixture.chain, funding);
    successful(&tx, "actual reward purse funding");
    assert_eq!(
        elector_purse_and_active_set(&fixture.chain).0,
        purse_before + u128::from(8_000 * TOS)
    );
    rotate_elected_round(&mut fixture.chain, at);
    let command = pool_command(&fixture, 6);
    fixture.chain.blockchain.send_message(command).expect("first pool set change").expect_success();
    let until = fixture
        .chain
        .blockchain
        .config_params()
        .validator_set()
        .expect("current set")
        .utime_until();
    fixture.chain.blockchain.set_now(until - fixture.chain.elect_begin_before);
    tick(&mut fixture.chain);
    let next = active_election_id(&fixture.chain) as u32;
    assert!(next > at, "the chain must open a later election");
    let mut second = Vec::new();
    for i in 0..4 {
        let mut validator = deploy_rooted_validator(&mut fixture.chain, 0x60 + i);
        root_place(&mut fixture.chain, &mut validator, next, 1, 10_002 * TOS);
        second.push(validator);
    }
    rotate_elected_round(&mut fixture.chain, next);
    let command = pool_command(&fixture, 6);
    fixture
        .chain
        .blockchain
        .send_message(command)
        .expect("second pool set change")
        .expect_success();
    let held = fixture
        .chain
        .blockchain
        .config_params()
        .elector_params()
        .expect("election parameters")
        .stake_held_for;
    fixture.chain.blockchain.set_now(fixture.chain.blockchain.now() + held + 61);
    for _ in 0..8 {
        if !has_past_election(&fixture.chain, at) {
            break;
        }
        tick(&mut fixture.chain);
    }
    assert!(!has_past_election(&fixture.chain, at), "served pool round must really unfreeze");
    assert_eq!(fixture.pool_state(), 2);
    (fixture, first)
}

#[test]
fn root_owned_stake_top_up_and_recovery_finish_without_an_orphan_controller_balance() {
    let (mut fixture, mut first) = served_and_unfrozen_pool("root-owned-complete-cycle");
    let validator = &mut first[0];
    let owner: [u8; 32] = validator.address.address().get_bytestring(0).try_into().expect("owner");
    let credit = owed(&fixture.chain, &owner);
    assert!(
        credit >= u128::from(11_001 * TOS),
        "first stake plus top-up must survive the served round"
    );
    let before = balance_of(&fixture.chain, &validator.address);
    let body = contracts::nominator::recover_stake(3).expect("production recovery body");
    let result = validator.send_to_elector(&mut fixture.chain, TOS, body);
    result.expect_success();
    assert!(
        replies(&result).contains(&0xf96f7324),
        "actual elector recovery reply must reach actual controller"
    );
    assert_eq!(owed(&fixture.chain, &owner), 0);
    let after = balance_of(&fixture.chain, &validator.address);
    assert!(
        after >= before + credit && after < before + credit + u128::from(100 * TOS),
        "the owner receives its principal and served reward; only caller funds minus real fees are additional"
    );
    let result = validator.send_to_elector(
        &mut fixture.chain,
        TOS,
        contracts::nominator::recover_stake(3).expect("repeat"),
    );
    result.expect_success();
    assert!(
        replies(&result).contains(&0xfffffffe),
        "a duplicate recover must not pay principal twice"
    );
    assert!(balance_of(&fixture.chain, &validator.address) < after + u128::from(100 * TOS));
}

#[test]
fn a_served_pool_recovers_its_real_credit_and_lost_ack_never_reallocates_rewards() {
    let (mut fixture, _) = served_and_unfrozen_pool("complete-pooled-cycle");
    let owner: [u8; 32] = fixture.pool.address().get_bytestring(0).try_into().expect("owner");
    let credit = owed(&fixture.chain, &owner);
    assert!(credit >= u128::from(10_001 * TOS), "principal and served bonuses must belong to pool");
    let before = balance_of(&fixture.chain, &fixture.pool);
    let mut replacement = BuilderData::new();
    replacement.append_raw(&[0x29; 32], 256).expect("replacement elector");
    set_contract_parameter(&mut fixture.chain, 1, replacement.into_cell().expect("config"));
    let command = pool_command(&fixture, 0x47657424);
    let (tx, out) = step(&mut fixture.chain, command);
    successful(&tx, "pool recovery request");
    let request = out.into_iter().find(|message| op(message) == 0x47657432).expect("recovery");
    assert_eq!(
        request.dst().as_ref(),
        Some(&fixture.chain.elector),
        "mature recovery must use original stake elector"
    );
    assert_eq!(op(&request), 0x47657432);
    let (tx, out) = step(&mut fixture.chain, request);
    successful(&tx, "delete credit and pay its real owner");
    assert_eq!(owed(&fixture.chain, &owner), 0, "credits must be consumed once");
    let payment = only_to(out, &fixture.pool);
    assert!(!payment.int_header().expect("header").bounce);
    assert!(value(&payment) >= credit, "caller funds cover payment fees");
    let duplicate = payment.clone();
    let (tx, out) = step(&mut fixture.chain, payment);
    successful(&tx, "pool recovery settlement");
    assert_eq!(fixture.pool_state(), 0, "normal recovery must finish pool state");
    assert!(balance_of(&fixture.chain, &fixture.pool) > before + credit);
    let lost_ack = only_to(out, &fixture.chain.elector);
    assert_eq!(op(&lost_ack), 0x47656132);
    // A retry asks for the paid receipt, not for a second principal payment.
    let command = pool_command(&fixture, 0x47657424);
    let (tx, out) = step(&mut fixture.chain, command);
    successful(&tx, "public recovery acknowledgment repair");
    let request = only_to(out, &fixture.chain.elector);
    let (tx, out) = step(&mut fixture.chain, request);
    successful(&tx, "paid recovery receipt retry");
    let repeat = only_to(out, &fixture.pool);
    assert!(
        value(&repeat) < u128::from(20 * TOS),
        "recovery retry cannot contain the paid principal"
    );
    let (tx, out) = step(&mut fixture.chain, repeat);
    successful(&tx, "pool deduplicates recovery");
    assert!(out.is_empty(), "confirmed cleanup must not loop acknowledgments");
    let after_cleanup = fixture
        .chain
        .blockchain
        .get_account(&fixture.pool)
        .expect("pool")
        .get_data()
        .expect("data");
    let (tx, _) = step(&mut fixture.chain, lost_ack);
    successful(&tx, "late duplicate recovery acknowledgment");
    // A copied old payload with a small new value must not run accounting again.
    let replay = MessageBuilder::internal(&fixture.chain.elector, &fixture.pool, TOS)
        .bounce(false)
        .body(duplicate.body().expect("body").clone().into_cell().expect("body cell"))
        .build();
    let (tx, _) = step(&mut fixture.chain, replay);
    assert!(
        tx.read_description().expect("description").is_aborted(),
        "forgotten old-elector callback must not regain authority after cleanup"
    );
    assert_eq!(
        fixture
            .chain
            .blockchain
            .get_account(&fixture.pool)
            .expect("pool")
            .get_data()
            .expect("data"),
        after_cleanup
    );
    assert_eq!(owed(&fixture.chain, &owner), 0);
}

#[test]
fn an_unrelated_real_elector_refusal_cannot_consume_a_pools_pending_query() {
    let mut fixture = Fixture::new("unrelated-refusal");
    let order = fixture.order(1, fixture.election, 10_002 * TOS);
    let (_, out) = step(&mut fixture.chain, order);
    assert_eq!(fixture.pool_state(), 1);
    let before = fixture
        .chain
        .blockchain
        .get_account(&fixture.pool)
        .expect("pool")
        .get_data()
        .expect("data");
    let attacker =
        fixture.chain.blockchain.treasury("unrelated-attacker", 100_000 * TOS).expect("attacker");
    let owner = chain_block::UInt256::from_slice(&fixture.pool.address().get_bytestring(0));
    let at = fixture.election;
    let refused = pq_stake_relayed(
        &mut fixture.chain,
        &attacker,
        &PqValidator::new(0x54),
        at + 1,
        DOMAIN | 1,
        2 * TOS,
        &owner,
        &owner,
    );
    assert!(
        replies(&refused).contains(&STAKE_RETURNED),
        "the instrument must obtain the real unrelated elector error"
    );
    assert_eq!(fixture.pool_state(), 1, "unrelated elector refusal must not consume pending");
    assert_eq!(
        fixture
            .chain
            .blockchain
            .get_account(&fixture.pool)
            .expect("pool")
            .get_data()
            .expect("data"),
        before
    );
    let relay = only_to(out, &fixture.validator.address);
    let (tx, out) = step(&mut fixture.chain, relay);
    successful(&tx, "original relay still succeeds");
    let stake = only_to(out, &fixture.chain.elector);
    let (tx, out) = step(&mut fixture.chain, stake);
    successful(&tx, "original elector request");
    let receipt = only_to(out, &fixture.validator.address);
    finish_reply(&mut fixture, receipt, 2);
}

#[test]
fn a_real_refusal_returns_the_principal_without_root_intervention() {
    for scenario in ["wrong-election", "closed", "no-election", "retired"] {
        let mut fixture = Fixture::new(scenario);
        let capital = balance_of(&fixture.chain, &fixture.validator.address);
        let before = balance_of(&fixture.chain, &fixture.pool);
        let at = if scenario == "wrong-election" { fixture.election + 1 } else { fixture.election };
        let stake = begin(&mut fixture, 1, at);
        if scenario == "closed" {
            fixture.chain.blockchain.set_now(fixture.election - fixture.chain.elect_end_before);
        }
        if scenario == "retired" {
            set_contract_parameter(&mut fixture.chain, 47, controller_policy(0));
        }
        if scenario == "no-election" {
            let mut account = fixture
                .chain
                .blockchain
                .get_account(&fixture.chain.elector)
                .expect("elector")
                .clone();
            let mut root = SliceData::load_cell(account.get_data().expect("data")).expect("slice");
            next_dictionary(&mut root, 32);
            let mut data = BuilderData::new();
            data.append_bit_zero().expect("no active election");
            data.checked_append_references_and_data(&root).expect("all other claims");
            account.set_data(data.into_cell().expect("data"));
            fixture.chain.blockchain.set_account(fixture.chain.elector.clone(), account);
        }
        let (tx, out) = step(&mut fixture.chain, stake);
        if scenario == "retired" {
            assert!(tx.read_description().expect("description").is_aborted());
        } else {
            successful(&tx, "real business refusal");
        }
        let receipt = only_to(out, &fixture.validator.address);
        assert_eq!(op(&receipt), if scenario == "retired" { 0xffffffff } else { 0x50516532 });
        finish_reply(&mut fixture, receipt, 0);
        let after = balance_of(&fixture.chain, &fixture.validator.address);
        let reserved = capital - r3_accounting::first_grant(&fixture);
        assert!(
            after <= reserved && reserved - after < u128::from(TOS),
            "{scenario}: only the operating grant and bounded elapsed rent leave capital"
        );
        assert!(
            balance_of(&fixture.chain, &fixture.pool) > before - u128::from(TOS),
            "{scenario}: refusal costs are bounded and charged to the operator contribution"
        );
        let owner: [u8; 32] = fixture.pool.address().get_bytestring(0).try_into().expect("owner");
        assert_eq!(owed(&fixture.chain, &owner), 0, "refusal must not also create a credit");
    }
}

#[test]
fn an_elector_compute_abort_is_a_recorded_and_automatic_owner_refund() {
    let mut fixture = Fixture::new("elector-compute-abort");
    let capital = balance_of(&fixture.chain, &fixture.validator.address);
    let before = balance_of(&fixture.chain, &fixture.pool);
    let at = fixture.election;
    let stake = begin(&mut fixture, 1, at);
    // Remove only the active PQ books, retaining its declared principal. The
    // real parser now refuses the unsupported state rather than fabricating owners.
    let mut account =
        fixture.chain.blockchain.get_account(&fixture.chain.elector).expect("elector").clone();
    let mut root = SliceData::load_cell(account.get_data().expect("data")).expect("root");
    let active = next_dictionary(&mut root, 32);
    let mut fields =
        SliceData::load_cell(HashmapType::data(&active).expect("active").clone()).expect("active");
    let mut truncated = BuilderData::new();
    truncated.append_u32(fields.get_next_u32().expect("at")).expect("at");
    truncated.append_u32(fields.get_next_u32().expect("close")).expect("close");
    Coins::new(next_coins(&mut fields) as u64).write_to(&mut truncated).expect("minimum");
    Coins::new(next_coins(&mut fields) as u64).write_to(&mut truncated).expect("principal");
    truncated.append_bit_zero().expect("failed");
    truncated.append_bit_zero().expect("finished");
    let mut data = BuilderData::new();
    data.append_bit_one().expect("active");
    data.checked_append_reference(truncated.into_cell().expect("unsupported old state"))
        .expect("active ref");
    data.checked_append_references_and_data(&root).expect("other claims");
    account.set_data(data.into_cell().expect("root"));
    fixture.chain.blockchain.set_account(fixture.chain.elector.clone(), account);
    let (tx, out) = step(&mut fixture.chain, stake);
    match tx.read_description().expect("description") {
        TransactionDescr::Ordinary(d) => match d.compute_ph {
            TrComputePhase::Vm(vm) => assert_eq!(vm.exit_code, 65),
            _ => panic!("parser was not executed"),
        },
        _ => panic!("ordinary transaction"),
    }
    let bounce = only_to(out, &fixture.validator.address);
    assert!(bounce.is_bounced(), "the real VM abort must generate a real bounce");
    let (tx, out) = step(&mut fixture.chain, bounce);
    successful(&tx, "record actual bounce debt");
    let kick = only_to(out, &fixture.validator.address);
    let (tx, out) = step(&mut fixture.chain, kick);
    successful(&tx, "automatic debt payment");
    let (tx, out) = step(&mut fixture.chain, only_to(out, &fixture.pool));
    successful(&tx, "owner refund callback");
    assert_eq!(fixture.pool_state(), 0, "automatic refund must finish the original pending");
    let (tx, _) = step(&mut fixture.chain, only_to(out, &fixture.validator.address));
    successful(&tx, "refund ack");
    assert!(fixture.pending().is_none());
    assert_eq!(
        balance_of(&fixture.chain, &fixture.validator.address),
        capital - r3_accounting::first_grant(&fixture)
    );
    assert!(balance_of(&fixture.chain, &fixture.pool) > before - u128::from(TOS));
}

#[test]
fn a_paid_receipt_can_be_retried_after_recipient_abort_without_repaying_principal() {
    let mut fixture = Fixture::new("recipient-abort");
    let at = fixture.election + 1;
    let stake = begin(&mut fixture, 1, at);
    let (_, out) = step(&mut fixture.chain, stake);
    let (_, out) = step(&mut fixture.chain, only_to(out, &fixture.validator.address));
    let (_, out) = step(&mut fixture.chain, only_to(out, &fixture.validator.address));
    let payment = only_to(out, &fixture.pool);
    assert!(!payment.int_header().expect("header").bounce);
    let first_payment = value(&payment);
    assert!(
        first_payment > u128::from(10_000 * TOS),
        "real refund principal must leave the controller"
    );
    let prices = raw_parameter(&fixture.chain, 20).expect("original gas profile");
    let mut restricted = fixture.chain.blockchain.config_params().gas_prices(true).expect("prices");
    restricted.gas_limit = 1_000;
    set_contract_parameter(
        &mut fixture.chain,
        20,
        restricted.write_to_new_cell().expect("gas").into_cell().expect("gas"),
    );
    let before = balance_of(&fixture.chain, &fixture.pool);
    let (tx, out) = step(&mut fixture.chain, payment);
    assert!(
        tx.read_description().expect("description").is_aborted(),
        "receiver must actually abort"
    );
    match tx.read_description().expect("description") {
        TransactionDescr::Ordinary(d) => match d.compute_ph {
            TrComputePhase::Vm(vm) => {
                assert_eq!(vm.exit_code, -14, "actual unmodified pool callback must run out of gas")
            }
            _ => panic!("recipient must execute the real VM"),
        },
        _ => panic!("ordinary receiver transaction"),
    }
    assert!(out.is_empty(), "non-bounce principal cannot return to the controller");
    assert!(
        balance_of(&fixture.chain, &fixture.pool) > before + u128::from(9_900 * TOS),
        "principal belongs to the receiver despite abort"
    );
    set_contract_parameter(&mut fixture.chain, 20, prices);
    let request = retry(&fixture, DOMAIN | 1);
    let (tx, out) = step(&mut fixture.chain, request);
    successful(&tx, "public receipt retry");
    let repeat = only_to(out, &fixture.pool);
    assert!(
        value(&repeat) < u128::from(20 * TOS),
        "PAID receipt retry must never contain the old principal"
    );
    let (tx, out) = step(&mut fixture.chain, repeat);
    successful(&tx, "business retry after actual abort");
    assert_eq!(fixture.pool_state(), 0);
    let (tx, _) = step(&mut fixture.chain, only_to(out, &fixture.validator.address));
    successful(&tx, "retry cleanup");
    assert!(fixture.pending().is_none());
    assert!(first_payment > u128::from(10_000 * TOS));
}

#[test]
fn a_real_controller_payment_action_failure_keeps_ready_debt_for_public_retry() {
    let mut fixture = Fixture::new("payment-action-rollback");
    let at = fixture.election;
    let stake = begin(&mut fixture, 1, at);
    let (_, out) = step(&mut fixture.chain, stake);
    let receipt = only_to(out, &fixture.validator.address);
    let (tx, _) = step(&mut fixture.chain, receipt);
    successful(&tx, "record refund before payment");
    let ready = fixture.pending().expect("READY debt");
    // Tighten the native outbound-message limit after READY. Compute still
    // succeeds, but the mandatory principal action cannot be emitted.
    fixture
        .chain
        .blockchain
        .set_size_limits_config(chain_block::SizeLimitsConfig {
            max_msg_cells: 0,
            ..chain_block::SizeLimitsConfig::default()
        })
        .expect("tighten action limit");
    let request = retry(&fixture, DOMAIN | 1);
    let (tx, _) = step(&mut fixture.chain, request);
    assert_eq!(
        fixture.pending().expect("debt after action failure"),
        ready,
        "failed payment action must retain READY, not publish PAID"
    );
    action_failure(&tx);
    assert_eq!(fixture.pool_state(), 1);
    fixture
        .chain
        .blockchain
        .set_size_limits_config(chain_block::SizeLimitsConfig::default())
        .expect("restore action limit");
    let mut request = retry(&fixture, DOMAIN | 1);
    request.int_header_mut().expect("header").value.coins = Coins::new(40 * TOS);
    let (tx, out) = step(&mut fixture.chain, request);
    successful(&tx, "fund rent and retry original debt");
    let (tx, out) = step(&mut fixture.chain, only_to(out, &fixture.pool));
    successful(&tx, "owner gets original debt");
    assert_eq!(fixture.pool_state(), 2);
    let (tx, _) = step(&mut fixture.chain, only_to(out, &fixture.validator.address));
    successful(&tx, "cleanup retried debt");
    assert!(fixture.pending().is_none());
}

#[test]
fn recovery_payment_action_failure_preserves_credit_and_the_same_query_can_retry() {
    let (mut fixture, _) = served_and_unfrozen_pool("recovery-action-rollback");
    let owner: [u8; 32] = fixture.pool.address().get_bytestring(0).try_into().expect("owner");
    let credit = owed(&fixture.chain, &owner);
    assert!(
        credit > u128::from(10_001 * TOS),
        "served cycle must contain a real reward, not only principal"
    );
    let command = pool_command(&fixture, 0x47657424);
    let (tx, out) = step(&mut fixture.chain, command);
    successful(&tx, "prepare recover");
    let request = only_to(out, &fixture.chain.elector);
    let original_prices = raw_parameter(&fixture.chain, 24).expect("masterchain forwarding prices");
    let original_specials = raw_parameter(&fixture.chain, 31).expect("fundamental contracts");
    let mut empty = BuilderData::new();
    empty.append_bit_zero().expect("no fundamental fee exemption");
    set_contract_parameter(&mut fixture.chain, 31, empty.into_cell().expect("test fee profile"));
    let mut prices = fixture.chain.blockchain.config_params().fwd_prices(true).expect("prices");
    prices.lump_price = 100_000 * TOS;
    set_contract_parameter(
        &mut fixture.chain,
        24,
        prices.write_to_new_cell().expect("price cell").into_cell().expect("prices"),
    );
    let (tx, _) = step(&mut fixture.chain, request);
    assert_eq!(owed(&fixture.chain, &owner), credit, "failed recover action cannot delete credit");
    action_failure(&tx);
    assert_eq!(fixture.pool_state(), 2);
    set_contract_parameter(&mut fixture.chain, 24, original_prices);
    set_contract_parameter(&mut fixture.chain, 31, original_specials);
    let command = pool_command(&fixture, 0x47657424);
    let (tx, out) = step(&mut fixture.chain, command);
    successful(&tx, "resend pending recover");
    let request = only_to(out, &fixture.chain.elector);
    let (tx, out) = step(&mut fixture.chain, request);
    successful(&tx, "retry pays actual credit");
    assert_eq!(owed(&fixture.chain, &owner), 0);
    let (tx, out) = step(&mut fixture.chain, only_to(out, &fixture.pool));
    successful(&tx, "recovery business settlement");
    assert_eq!(fixture.pool_state(), 0);
    let ack = only_to(out, &fixture.chain.elector);
    let (tx, _) = step(&mut fixture.chain, ack);
    successful(&tx, "recovery acknowledgment");
}

#[test]
fn recovery_recipient_abort_retains_money_and_fee_only_retry_finishes_accounting() {
    let (mut fixture, _) = served_and_unfrozen_pool("recovery-recipient-abort");
    let owner: [u8; 32] = fixture.pool.address().get_bytestring(0).try_into().expect("owner");
    let credit = owed(&fixture.chain, &owner);
    let command = pool_command(&fixture, 0x47657424);
    let (_, out) = step(&mut fixture.chain, command);
    let request = only_to(out, &fixture.chain.elector);
    let (tx, out) = step(&mut fixture.chain, request);
    successful(&tx, "recover payment action");
    let payment = only_to(out, &fixture.pool);
    let mut account = fixture.chain.blockchain.get_account(&fixture.pool).expect("pool").clone();
    let code = account.get_code().expect("actual code");
    let temporary = tempfile::tempdir().expect("receiver fixture");
    let source = temporary.path().join("abort.fc");
    std::fs::write(
        &source,
        "() recv_internal(int value, cell message, slice body) impure { throw(199); }\n",
    )
    .expect("source");
    account.set_code(
        tos_sandbox::compile_func_with_stdlib(&[source]).expect("native receiver fixture"),
    );
    fixture.chain.blockchain.set_account(fixture.pool.clone(), account);
    let before = balance_of(&fixture.chain, &fixture.pool);
    let (tx, out) = step(&mut fixture.chain, payment);
    assert!(tx.read_description().expect("description").is_aborted());
    assert!(out.is_empty(), "non-bounce recovery stays in the owner even on receiver abort");
    assert!(balance_of(&fixture.chain, &fixture.pool) >= before + credit);
    assert_eq!(owed(&fixture.chain, &owner), 0);
    let mut account = fixture.chain.blockchain.get_account(&fixture.pool).expect("pool").clone();
    account.set_code(code);
    fixture.chain.blockchain.set_account(fixture.pool.clone(), account);
    let command = pool_command(&fixture, 0x47657424);
    let (tx, out) = step(&mut fixture.chain, command);
    successful(&tx, "public retry of unfinished pool accounting");
    let request = only_to(out, &fixture.chain.elector);
    let (tx, out) = step(&mut fixture.chain, request);
    successful(&tx, "elector sends only paid receipt");
    let repeat = only_to(out, &fixture.pool);
    assert!(
        value(&repeat) < u128::from(20 * TOS),
        "receipt retry never repays the original recovery principal"
    );
    let (tx, out) = step(&mut fixture.chain, repeat);
    successful(&tx, "pool finishes original recovery accounting");
    assert_eq!(fixture.pool_state(), 0);
    let ack = only_to(out, &fixture.chain.elector);
    let (tx, _) = step(&mut fixture.chain, ack);
    successful(&tx, "clean paid recovery record");
}

fn ack_body(query: u64, hash: &[u8]) -> chain_block::Cell {
    let mut body = BuilderData::new();
    body.append_u32(ACK).expect("ack");
    body.append_u64(query).expect("query");
    body.append_raw(hash, 256).expect("hash");
    body.into_cell().expect("ack body")
}

#[test]
fn controller_results_bind_elector_query_commitment_amount_and_wait_phase() {
    let mut fixture = Fixture::new("controller-result-binding");
    let at = fixture.election;
    let stake = begin(&mut fixture, 1, at);
    let (_, out) = step(&mut fixture.chain, stake);
    let receipt = only_to(out, &fixture.validator.address);
    let waiting = fixture.pending().expect("WAIT");
    for field in ["source", "query", "hash", "received", "accepted"] {
        let mut cs = receipt.body().expect("receipt").clone();
        let tag = cs.get_next_u32().expect("op");
        let q = cs.get_next_u64().expect("query");
        let commitment = cs.get_next_bits(160).expect("bounce commitment");
        let reason = cs.get_next_u32().expect("reason");
        let accepted = next_coins(&mut cs);
        let received = next_coins(&mut cs);
        let mut hash = cs.get_next_bits(256).expect("hash");
        if field == "hash" {
            hash[0] ^= 1;
        }
        let mut body = BuilderData::new();
        body.append_u32(tag).expect("op");
        body.append_u64(q + u64::from(field == "query")).expect("q");
        body.append_raw(&commitment, 160).expect("commitment");
        body.append_u32(reason).expect("reason");
        Coins::new((accepted + u128::from(field == "accepted")) as u64)
            .write_to(&mut body)
            .expect("accepted");
        Coins::new((received + u128::from(field == "received")) as u64)
            .write_to(&mut body)
            .expect("received");
        body.append_raw(&hash, 256).expect("hash");
        body.checked_append_references_and_data(&cs).expect("unchanged fee suffix");
        let source =
            if field == "source" { fixture.operator.address() } else { &fixture.chain.elector };
        let message = MessageBuilder::internal(source, &fixture.validator.address, TOS)
            .bounce(false)
            .body(body.into_cell().expect("body"))
            .build();
        let _ = step(&mut fixture.chain, message);
        assert_eq!(
            fixture.pending().expect("unbound result retains debt"),
            waiting,
            "controller unbound {field}"
        );
    }
    let (_, out) = step(&mut fixture.chain, receipt.clone());
    let ready = fixture.pending().expect("READY");
    let (_, repeated) = step(&mut fixture.chain, receipt);
    assert!(repeated.iter().all(|m| m.is_bounced()), "late result cannot restart READY payment");
    assert_eq!(fixture.pending().expect("duplicate result"), ready);
    let kick = only_to(out, &fixture.validator.address);
    let (_, out) = step(&mut fixture.chain, kick);
    let payment = only_to(out, &fixture.pool);
    let (_, out) = step(&mut fixture.chain, payment);
    let ack = only_to(out, &fixture.validator.address);
    let (_, _) = step(&mut fixture.chain, ack);
    assert!(fixture.pending().is_none());
}

#[test]
fn bounces_and_acknowledgments_cannot_change_the_wrong_or_unpaid_request() {
    let mut fixture = Fixture::new("bounce-and-ack-binding");
    let at = fixture.election;
    let stake = begin(&mut fixture, 1, at);
    let waiting = fixture.pending().expect("WAIT");
    let mut original = stake.body().expect("body").clone();
    let prefix = original.get_next_bits(256).expect("full bounce prefix");
    for field in ["source", "prefix"] {
        let mut changed = prefix.clone();
        if field == "prefix" {
            changed[31] ^= 1;
        }
        let mut body = BuilderData::new();
        body.append_u32(u32::MAX).expect("bounce marker");
        body.append_raw(&changed, 256).expect("prefix");
        let source =
            if field == "source" { fixture.operator.address() } else { &fixture.chain.elector };
        let mut message = MessageBuilder::internal(source, &fixture.validator.address, TOS)
            .bounce(false)
            .body(body.into_cell().expect("bounce"))
            .build();
        message.int_header_mut().expect("header").bounced = true;
        let _ = step(&mut fixture.chain, message);
        assert_eq!(
            fixture.pending().expect("wrong bounce retains WAIT"),
            waiting,
            "unbound bounce {field}"
        );
    }
    let (_, out) = step(&mut fixture.chain, stake);
    let receipt = only_to(out, &fixture.validator.address);
    let mut cs = receipt.body().expect("body").clone();
    cs.get_next_u32().expect("op");
    let q = cs.get_next_u64().expect("query");
    cs.get_next_u32().expect("reason");
    next_coins(&mut cs);
    next_coins(&mut cs);
    let hash = cs.get_next_bits(256).expect("hash");
    for phase in ["WAIT", "READY"] {
        let before = fixture.pending().expect("pending");
        let message = MessageBuilder::internal(&fixture.pool, &fixture.validator.address, TOS)
            .body(ack_body(q, &hash))
            .build();
        let _ = step(&mut fixture.chain, message);
        assert_eq!(
            fixture.pending().expect("premature ack retains claim"),
            before,
            "premature {phase} ACK"
        );
        if phase == "WAIT" {
            let _ = step(&mut fixture.chain, receipt.clone());
        }
    }
    let request = retry(&fixture, q);
    let (_, out) = step(&mut fixture.chain, request);
    let payment = only_to(out, &fixture.pool);
    let paid = fixture.pending().expect("PAID");
    for field in ["source", "query", "hash"] {
        let mut changed = hash.clone();
        if field == "hash" {
            changed[0] ^= 1;
        }
        let source = if field == "source" { fixture.operator.address() } else { &fixture.pool };
        let message = MessageBuilder::internal(source, &fixture.validator.address, TOS)
            .body(ack_body(q + u64::from(field == "query"), &changed))
            .build();
        let _ = step(&mut fixture.chain, message);
        assert_eq!(
            fixture.pending().expect("unbound ack retains PAID"),
            paid,
            "unbound ACK {field}"
        );
    }
    let (_, out) = step(&mut fixture.chain, payment);
    let (_, _) = step(&mut fixture.chain, only_to(out, &fixture.validator.address));
    assert!(fixture.pending().is_none());
}

#[test]
fn one_pending_slot_and_monotonic_query_prevent_replay_and_storage_growth() {
    let mut fixture = Fixture::new("single-flight-bound");
    let order = fixture.order(1, fixture.election + 1, 10_002 * TOS);
    let (_, out) = step(&mut fixture.chain, order);
    let relay = only_to(out, &fixture.validator.address);
    let old_relay = relay.clone();
    let (_, out) = step(&mut fixture.chain, relay);
    let waiting = fixture.pending().expect("WAIT");
    let storage = fixture
        .chain
        .blockchain
        .get_account(&fixture.validator.address)
        .expect("controller")
        .get_data()
        .expect("data");
    let mut competing = old_relay.clone();
    let mut cs = competing.body().expect("body").clone();
    let operation = cs.get_next_u32().expect("op");
    cs.get_next_u64().expect("query");
    let mut body = BuilderData::new();
    body.append_u32(operation).expect("op");
    body.append_u64(DOMAIN | 2).expect("next query");
    body.checked_append_references_and_data(&cs).expect("same valid owner and signature");
    competing.set_body(SliceData::load_cell(body.into_cell().expect("body")).expect("body"));
    let (tx, _) = step(&mut fixture.chain, competing);
    assert!(tx.read_description().expect("description").is_aborted());
    assert_eq!(
        fixture.pending().expect("one slot"),
        waiting,
        "a second valid request cannot replace the creditor"
    );
    assert_eq!(
        fixture
            .chain
            .blockchain
            .get_account(&fixture.validator.address)
            .expect("controller")
            .get_data()
            .expect("data"),
        storage
    );
    let stake = only_to(out, &fixture.chain.elector);
    let (_, out) = step(&mut fixture.chain, stake);
    let receipt = only_to(out, &fixture.validator.address);
    let old_receipt = receipt.clone();
    finish_reply(&mut fixture, receipt, 0);
    let (tx, _) = step(&mut fixture.chain, old_relay);
    assert!(
        tx.read_description().expect("description").is_aborted(),
        "accepted query cannot replay"
    );
    assert!(fixture.pending().is_none());
    let at = fixture.election;
    let current = begin(&mut fixture, 2, at);
    let latest = fixture.pending().expect("new WAIT");
    let _ = step(&mut fixture.chain, old_receipt);
    assert_eq!(fixture.pending().expect("late old receipt"), latest);
    let (_, out) = step(&mut fixture.chain, current);
    let receipt = only_to(out, &fixture.validator.address);
    finish_reply(&mut fixture, receipt, 2);
    let account =
        fixture.chain.blockchain.get_account(&fixture.validator.address).expect("controller");
    println!(
        "relay controller live cells={} bits={}",
        account.storage_info().expect("storage").used().cells(),
        account.storage_info().expect("storage").used().bits()
    );
    assert!(
        account.storage_info().expect("storage").used().cells() < 256,
        "bounded controller storage"
    );
}

#[test]
fn root_cannot_forge_reserved_callbacks_even_without_a_pending_request() {
    let mut fixture = Fixture::new("root-reserved-namespace");
    for (operation, query) in [
        (RESULT, 1),
        (RELAY, 1),
        (ACK, 1),
        (0x50517433, 1),
        (0x50516133, 1),
        (0x50517833, 1),
        (0x47657424, DOMAIN | 1),
    ] {
        let mut body = BuilderData::new();
        body.append_u32(operation).expect("operation");
        body.append_u64(query).expect("query");
        let send = root_send(&fixture, &fixture.pool, body.into_cell().expect("body"));
        let (tx, _) = step(&mut fixture.chain, send);
        match tx.read_description().expect("description") {
            TransactionDescr::Ordinary(d) => match d.compute_ph {
                TrComputePhase::Vm(vm) => assert_eq!(vm.exit_code, 97, "root callback namespace"),
                _ => panic!("VM must run"),
            },
            _ => panic!("ordinary transaction"),
        }
        assert!(fixture.pending().is_none());
    }
}

fn credit_fixture(chain: &mut Chain, owner: &MsgAddressInt, amount: u64, drained: bool) {
    let mut account = chain.blockchain.get_account(&chain.elector).expect("elector").clone();
    let mut cs = SliceData::load_cell(account.get_data().expect("data")).expect("data");
    let elect = next_dictionary(&mut cs, 32);
    let mut credits = next_dictionary(&mut cs, 256);
    let key = owner.address().clone();
    let mut value = BuilderData::new();
    Coins::new(amount).write_to(&mut value).expect("credit");
    credits.set_builder(key, &value).expect("credit fixture");
    let mut root = BuilderData::new();
    if drained {
        root.append_bit_zero().expect("no election");
    } else {
        dictionary(&mut root, &elect);
    }
    dictionary(&mut root, &credits);
    if drained {
        next_dictionary(&mut cs, 32);
        root.append_bit_zero().expect("no frozen book");
        Coins::new(0).write_to(&mut root).expect("purse");
        next_coins(&mut cs);
        cs.get_next_u32().expect("active id");
        cs.get_next_bits(256).expect("hash");
        root.append_u32(0).expect("active id");
        root.append_raw(&[0; 32], 256).expect("active hash");
    }
    root.checked_append_references_and_data(&cs).expect("remaining fields and recovery receipts");
    account.set_data(root.into_cell().expect("data"));
    chain.blockchain.set_account(chain.elector.clone(), account);
}
fn recover_message(
    owner: &MsgAddressInt,
    elector: &MsgAddressInt,
    operation: u32,
    query: u64,
) -> Message {
    let mut body = BuilderData::new();
    body.append_u32(operation).expect("op");
    body.append_u64(query).expect("query");
    MessageBuilder::internal(owner, elector, 20 * TOS).body(body.into_cell().expect("body")).build()
}

#[test]
fn recovery_tombstones_protect_later_credits_and_outstanding_receipts_block_upgrade() {
    let mut fixture = Fixture::new("paid-recovery-replay");
    let owner = fixture.operator.address().clone();
    credit_fixture(&mut fixture.chain, &owner, 50 * TOS, true);
    let message = recover_message(&owner, &fixture.chain.elector, 0x47657432, DOMAIN | 1);
    let (tx, out) = step(&mut fixture.chain, message);
    successful(&tx, "real paid recovery");
    let payment = only_to(out, &owner);
    assert!(value(&payment) >= u128::from(50 * TOS));
    let readiness = fixture
        .chain
        .blockchain
        .run_get_method(&fixture.chain.elector, "upgrade_ready", vec![])
        .expect("getter");
    assert_eq!(readiness.exit_code, 0);
    assert_eq!(
        readiness.stack[0].as_integer().expect("ready").to_string(),
        "0",
        "only outstanding recovery blocks upgrade"
    );
    let message = recover_message(&owner, &fixture.chain.elector, 0x47657432, DOMAIN | 1);
    let (_, out) = step(&mut fixture.chain, message);
    assert!(
        value(&only_to(out, &owner)) <= u128::from(20 * TOS),
        "paid recovery repeats only caller fees"
    );
    let message = recover_message(&owner, &fixture.chain.elector, 0x47656132, DOMAIN | 1);
    let _ = step(&mut fixture.chain, message);
    let ready = fixture
        .chain
        .blockchain
        .run_get_method(&fixture.chain.elector, "upgrade_ready", vec![])
        .expect("getter");
    assert_ne!(ready.stack[0].as_integer().expect("ready").to_string(), "0");
    credit_fixture(&mut fixture.chain, &owner, 70 * TOS, false);
    let state = fixture
        .chain
        .blockchain
        .get_account(&fixture.chain.elector)
        .expect("elector")
        .get_data()
        .expect("data");
    let message = recover_message(&owner, &fixture.chain.elector, 0x47657432, DOMAIN | 1);
    let (_, out) = step(&mut fixture.chain, message);
    assert!(out.is_empty(), "acknowledged old recovery cannot consume a later credit");
    assert_eq!(
        fixture
            .chain
            .blockchain
            .get_account(&fixture.chain.elector)
            .expect("elector")
            .get_data()
            .expect("data"),
        state
    );
    let message = recover_message(&owner, &fixture.chain.elector, 0x47657432, DOMAIN | 2);
    let (tx, out) = step(&mut fixture.chain, message);
    successful(&tx, "later distinct recovery");
    assert!(value(&only_to(out, &owner)) >= u128::from(70 * TOS));
    fn metadata(chain: &Chain) -> chain_block::Cell {
        let mut cs = SliceData::load_cell(
            chain
                .blockchain
                .get_account(&chain.elector)
                .expect("elector")
                .get_data()
                .expect("data"),
        )
        .expect("data");
        next_dictionary(&mut cs, 32);
        next_dictionary(&mut cs, 256);
        next_dictionary(&mut cs, 32);
        next_coins(&mut cs);
        cs.get_next_u32().expect("active");
        cs.get_next_bits(256).expect("hash");
        assert!(cs.get_next_bit().expect("receipt book must survive normal writes"));
        cs.checked_drain_reference().expect("receipt book")
    }
    let receipt_book = metadata(&fixture.chain);
    for _ in 0..16 {
        let message = recover_message(&owner, &fixture.chain.elector, 0x47657432, DOMAIN | 2);
        let _ = step(&mut fixture.chain, message);
        assert_eq!(
            metadata(&fixture.chain),
            receipt_book,
            "paid retries cannot grow the receipt book"
        );
    }
    tick(&mut fixture.chain);
    let cancellation = active_election_id(&fixture.chain) as u32;
    assert_ne!(cancellation, 0, "real writer control needs an announced election");
    fixture.chain.blockchain.set_now(cancellation);
    tick(&mut fixture.chain);
    assert_eq!(
        metadata(&fixture.chain),
        receipt_book,
        "normal tick must preserve outstanding recovery metadata"
    );
}

#[test]
fn the_single_pool_checks_the_same_bound_receipt_and_retries_a_paid_refund() {
    let mut fixture = Fixture::new("single-bound-relay");
    fixture.pool = deploy_single_nominator(
        &mut fixture.chain,
        fixture.operator.address(),
        fixture.operator.address(),
        &fixture.validator.address,
        20_000 * TOS,
    );
    let at = fixture.election + 1;
    let stake = begin(&mut fixture, 1, at);
    let (_, out) = step(&mut fixture.chain, stake);
    let (_, out) = step(&mut fixture.chain, only_to(out, &fixture.validator.address));
    let (_, out) = step(&mut fixture.chain, only_to(out, &fixture.validator.address));
    let payment = only_to(out, &fixture.pool);
    let before = fixture
        .chain
        .blockchain
        .get_account(&fixture.pool)
        .expect("single pool")
        .get_data()
        .expect("data");
    let mut cs = payment.body().expect("body").clone();
    cs.get_next_u32().expect("op");
    let q = cs.get_next_u64().expect("query");
    let mut hash = cs.get_next_bits(256).expect("hash");
    hash[0] ^= 1;
    let mut forged = BuilderData::new();
    forged.append_u32(RESULT).expect("op");
    forged.append_u64(q).expect("query");
    forged.append_raw(&hash, 256).expect("hash");
    forged.checked_append_references_and_data(&cs).expect("amounts");
    let message = MessageBuilder::internal(&fixture.validator.address, &fixture.pool, TOS)
        .bounce(false)
        .body(forged.into_cell().expect("body"))
        .build();
    let _ = step(&mut fixture.chain, message);
    assert_eq!(
        fixture
            .chain
            .blockchain
            .get_account(&fixture.pool)
            .expect("single")
            .get_data()
            .expect("data"),
        before,
        "single pool unbound receipt"
    );
    let (_, out) = step(&mut fixture.chain, payment);
    let ack = only_to(out, &fixture.validator.address);
    let settled = fixture
        .chain
        .blockchain
        .get_account(&fixture.pool)
        .expect("single")
        .get_data()
        .expect("data");
    let request = retry(&fixture, q);
    let (_, out) = step(&mut fixture.chain, request);
    let repeat = only_to(out, &fixture.pool);
    assert!(value(&repeat) < u128::from(20 * TOS));
    let (_, _) = step(&mut fixture.chain, repeat);
    assert_eq!(
        fixture
            .chain
            .blockchain
            .get_account(&fixture.pool)
            .expect("single")
            .get_data()
            .expect("data"),
        settled
    );
    let (_, _) = step(&mut fixture.chain, ack);
    assert!(fixture.pending().is_none());
}

#[test]
fn the_official_upgrade_proposal_carries_the_native_installation_hook() {
    let root = std::path::PathBuf::from(std::env::var("TOS_ROOT").expect("root"));
    let directory = tempfile::tempdir().expect("proposal fixture");
    let artifact = directory.path().join("proposal.boc");
    let output = std::process::Command::new(root.join("build/crypto/fift"))
        .env(
            "FIFTPATH",
            format!(
                "{}:{}",
                root.join("crypto/fift/lib").display(),
                root.join("crypto/smartcont").display()
            ),
        )
        .arg("-s")
        .arg(root.join("crypto/smartcont/create-elector-upgrade-proposal.fif"))
        .arg("-s")
        .arg(root.join("build/crypto/smartcont/auto/elector-code.fif"))
        .arg(&artifact)
        .output()
        .expect("real proposal tool");
    assert!(
        output.status.success(),
        "official Fift tool: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let boc = std::fs::read(artifact).expect("generated proposal");
    let mut cs =
        SliceData::load_cell(chain_block::read_single_root_boc(&boc).expect("BOC")).expect("slice");
    assert_eq!(cs.get_next_u32().expect("operation"), 0x6e565052);
    cs.get_next_u64().expect("query");
    cs.get_next_u32().expect("expires");
    let mut proposal =
        SliceData::load_cell(cs.checked_drain_reference().expect("proposal")).expect("proposal");
    assert_eq!(proposal.get_next_byte().expect("tag"), 0xf3);
    assert_eq!(proposal.get_next_i32().expect("parameter"), -1001);
    assert!(proposal.get_next_bit().expect("value"));
    let value = proposal.checked_drain_reference().expect("code parameter");
    let mut parameter = SliceData::load_cell(value).expect("parameter");
    assert!(
        parameter.get_next_bit().expect("official installation hook must be present"),
        "official installation hook must be present"
    );
    let generated = parameter.checked_drain_reference().expect("code");
    let mut chain = launch();
    let actual =
        chain.blockchain.get_account(&chain.elector).expect("elector").get_code().expect("code");
    assert_eq!(
        generated, actual,
        "proposal must carry the exact generated code tested by the sandbox"
    );
    let result = code_upgrade(&mut chain, generated, true);
    result.expect_success();
    assert_eq!(reply(&result).0, 0xce436f64);
}

fn receipt_metadata(chain: &Chain) -> chain_block::Cell {
    let mut cs = SliceData::load_cell(
        chain.blockchain.get_account(&chain.elector).expect("elector").get_data().expect("data"),
    )
    .expect("data");
    next_dictionary(&mut cs, 32);
    next_dictionary(&mut cs, 256);
    next_dictionary(&mut cs, 32);
    next_coins(&mut cs);
    cs.get_next_u32().expect("active");
    cs.get_next_bits(256).expect("hash");
    assert!(cs.get_next_bit().expect("outstanding receipt book after unfreeze"));
    cs.checked_drain_reference().expect("receipt book")
}

#[test]
fn paid_recovery_metadata_survives_real_selection_configuration_rotation_and_unfreeze() {
    let (fixture, _) = served_with_receipt("receipt-book-through-round", true);
    let mut cs = SliceData::load_cell(receipt_metadata(&fixture.chain)).expect("receipt book");
    assert_eq!(cs.get_next_u32().expect("tag"), 0x52435632);
    assert_eq!(
        cs.get_next_u32().expect("outstanding"),
        1,
        "outstanding receipt must survive election writes"
    );
}

#[test]
fn a_real_nominator_gets_its_principal_and_reward_after_the_complete_served_cycle() {
    let (mut fixture, _) = served_and_unfrozen_pool("nominator-principal-and-reward");
    let owner: [u8; 32] = fixture.pool.address().get_bytestring(0).try_into().expect("pool");
    let credit = owed(&fixture.chain, &owner);
    assert!(
        credit > u128::from(10_001 * TOS),
        "served cycle must contain a real reward, not only principal"
    );
    let command = pool_command(&fixture, 0x47657424);
    fixture.chain.blockchain.send_message(command).expect("recover cascade").expect_success();
    assert_eq!(fixture.pool_state(), 0);
    let mut data = SliceData::load_cell(
        fixture
            .chain
            .blockchain
            .get_account(&fixture.pool)
            .expect("pool")
            .get_data()
            .expect("data"),
    )
    .expect("pool");
    data.get_next_byte().expect("state");
    data.get_next_u16().expect("count");
    assert_eq!(next_coins(&mut data), 0, "sent amount cleared once");
    let validator = next_coins(&mut data);
    data.checked_drain_reference().expect("config");
    let nominators = next_dictionary(&mut data, 256);
    let nominator = fixture.nominator.as_ref().expect("real funded nominator");
    let mut entry =
        nominators.get(nominator.address().address().clone()).expect("lookup").expect("principal");
    let amount = next_coins(&mut entry);
    assert_eq!(next_coins(&mut entry), 0);
    assert!(amount >= u128::from(4_901 * TOS));
    assert_eq!(
        amount + validator,
        credit,
        "pool business principal plus partitioned reward equals gross credit"
    );
    let address = nominator.address().clone();
    let before = balance_of(&fixture.chain, &address);
    let mut body = BuilderData::new();
    body.append_u32(0).expect("text");
    body.append_u8(b'w').expect("withdraw");
    let message = MessageBuilder::internal(&address, &fixture.pool, 2 * TOS)
        .body(body.into_cell().expect("body"))
        .build();
    let (tx, out) = step(&mut fixture.chain, message);
    successful(&tx, "real nominator withdrawal");
    assert!(out.iter().all(|m| m.dst().as_ref() == Some(&address)));
    let received: u128 = out.iter().map(value).sum();
    assert!(
        received >= amount,
        "nominator principal and reward actually leave the pool after actual forwarding fees"
    );
    for payment in out {
        let (tx, _) = step(&mut fixture.chain, payment);
        successful(&tx, "real nominator receives principal or fee excess");
    }
    assert!(balance_of(&fixture.chain, &address) >= before + amount);
}

#[test]
fn recovery_receipt_storage_is_one_tombstone_per_owner_and_repeated_rounds_do_not_grow_it() {
    let mut fixture = Fixture::new("recovery-owner-storage");
    // Synthetic prior-round credits isolate dictionary cost; real payment actions
    // still require real collateral, supplied by this sandbox treasury transfer.
    let funding = fixture.operator.build_message(&fixture.chain.elector, 20_000 * TOS, false, None);
    let (tx, _) = step(&mut fixture.chain, funding);
    successful(&tx, "collateral for the resource-only prior-credit fixture");
    let mut maximum_gas = 0;
    for index in 0..256 {
        let owner = fixture
            .chain
            .blockchain
            .treasury(&format!("recovery-owner-{index}"), 100 * TOS)
            .expect("owner");
        credit_fixture(&mut fixture.chain, owner.address(), 50 * TOS, true);
        let message =
            recover_message(owner.address(), &fixture.chain.elector, 0x47657432, DOMAIN | 1);
        let (tx, out) = step(&mut fixture.chain, message);
        successful(&tx, "actual recovery with growing owner book");
        if let TransactionDescr::Ordinary(d) = tx.read_description().expect("description") {
            if let TrComputePhase::Vm(vm) = d.compute_ph {
                maximum_gas = maximum_gas.max(vm.gas_used.as_u64());
            } else {
                panic!("actual VM must run");
            }
        }
        let payment = only_to(out, owner.address());
        let (tx, _) = step(&mut fixture.chain, payment);
        successful(&tx, "actual recovery recipient");
        let ack = recover_message(owner.address(), &fixture.chain.elector, 0x47656132, DOMAIN | 1);
        let (tx, _) = step(&mut fixture.chain, ack);
        successful(&tx, "clear amount but retain replay tombstone");
    }
    let mut metadata = SliceData::load_cell(receipt_metadata(&fixture.chain)).expect("book");
    assert_eq!(metadata.get_next_u32().expect("tag"), 0x52435632);
    assert_eq!(metadata.get_next_u32().expect("outstanding"), 0);
    let receipts = next_dictionary(&mut metadata, 256);
    assert_eq!(
        receipts.len().expect("entries"),
        256,
        "one replay tombstone per actual distinct creditor"
    );
    assert_eq!(metadata.remaining_bits(), 0, "no extra record bits");
    assert_eq!(metadata.remaining_references(), 0, "no extra record references");
    assert!(maximum_gas < 50_000, "bounded point operations must not scan all creditors");
    let before = receipt_metadata(&fixture.chain);
    let owner =
        fixture.chain.blockchain.treasury("recovery-owner-255", 100 * TOS).expect("same owner");
    for query in 2..18 {
        credit_fixture(&mut fixture.chain, owner.address(), 50 * TOS, true);
        let message =
            recover_message(owner.address(), &fixture.chain.elector, 0x47657432, DOMAIN | query);
        let (tx, out) = step(&mut fixture.chain, message);
        successful(&tx, "later recovery replaces owner record");
        let (tx, _) = step(&mut fixture.chain, only_to(out, owner.address()));
        successful(&tx, "later payment");
        let ack =
            recover_message(owner.address(), &fixture.chain.elector, 0x47656132, DOMAIN | query);
        let (tx, _) = step(&mut fixture.chain, ack);
        successful(&tx, "later cleanup");
    }
    let after = receipt_metadata(&fixture.chain);
    let before_size = before.count_cells(4096).expect("bounded cells");
    let after_size = after.count_cells(4096).expect("bounded cells");
    assert_eq!(
        after_size, before_size,
        "new rounds must replace a tombstone, never append history"
    );
    println!(
        "recovery book owners=256 cells={after_size} maximum payment gas={maximum_gas}; distinct-owner growth remains explicit"
    );
}

#[test]
fn recovery_ack_survives_accepted_and_rejected_later_stakes() {
    for reject in [false, true] {
        let (mut fixture, _) = served_and_unfrozen_pool("cross-round-lost-recovery-ack");
        let command = pool_command(&fixture, 0x47657424);
        let (_, out) = step(&mut fixture.chain, command);
        let request = only_to(out, &fixture.chain.elector);
        let (_, out) = step(&mut fixture.chain, request);
        let payment = only_to(out, &fixture.pool);
        let duplicate = payment.clone();
        let (tx, out) = step(&mut fixture.chain, payment);
        successful(&tx, "first recovery settlement");
        assert_eq!(fixture.pool_state(), 0);
        assert_eq!(op(&only_to(out, &fixture.chain.elector)), 0x47656132);
        // Deliberately omit delivery of the pool's ACK. Do not inject an owner message.
        let until =
            fixture.chain.blockchain.config_params().validator_set().expect("set").utime_until();
        fixture.chain.blockchain.set_now(
            (until - fixture.chain.elect_begin_before).max(fixture.chain.blockchain.now() + 1),
        );
        tick(&mut fixture.chain);
        let next = active_election_id(&fixture.chain) as u32;
        assert!(next > fixture.election);
        r3_accounting::fund(&mut fixture, 0, 60 * TOS);
        let stake = begin(&mut fixture, 2, next + u32::from(reject));
        let (tx, out) = step(&mut fixture.chain, stake);
        successful(&tx, "later real elector result");
        let reply = only_to(out, &fixture.validator.address);
        finish_reply(&mut fixture, reply, if reject { 0 } else { 2 });
        let saved = fixture
            .chain
            .blockchain
            .get_account(&fixture.pool)
            .expect("pool")
            .get_data()
            .expect("data");
        for (source, query) in [
            (fixture.operator.address().clone(), DOMAIN | 1),
            (fixture.chain.elector.clone(), DOMAIN | 2),
        ] {
            let mut body = BuilderData::new();
            body.append_u32(0x47656133).expect("op");
            body.append_u64(query).expect("query");
            let message = MessageBuilder::internal(&source, &fixture.pool, TOS)
                .bounce(false)
                .body(body.into_cell().expect("body"))
                .build();
            let _ = step(&mut fixture.chain, message);
            assert_eq!(
                fixture
                    .chain
                    .blockchain
                    .get_account(&fixture.pool)
                    .expect("pool")
                    .get_data()
                    .expect("data"),
                saved,
                "unbound recovery confirmation cannot erase repair metadata"
            );
        }
        let command = pool_command(&fixture, 8);
        let (tx, out) = step(&mut fixture.chain, command);
        successful(&tx, "old recovery ACK remains repairable after later stake result");
        let ack = only_to(out, &fixture.chain.elector);
        let mut body = ack.body().expect("ack").clone();
        assert_eq!(body.get_next_u32().expect("op"), 0x47656132);
        assert_eq!(body.get_next_u64().expect("old query"), DOMAIN | 1);
        let (tx, out) = step(&mut fixture.chain, ack.clone());
        successful(&tx, "old receipt cleared by real owner ACK");
        // Lose the first confirmation too; the repeated ACK must still get a reply.
        assert_eq!(op(&only_to(out, &fixture.pool)), 0x47656133);
        let (tx, out) = step(&mut fixture.chain, ack);
        successful(&tx, "idempotent ACK confirmation");
        let confirmation = only_to(out, &fixture.pool);
        let (tx, _) = step(&mut fixture.chain, confirmation);
        successful(&tx, "pool durably clears only confirmed repair metadata");
        let before = fixture
            .chain
            .blockchain
            .get_account(&fixture.pool)
            .expect("pool")
            .get_data()
            .expect("data");
        let (tx, _) = step(&mut fixture.chain, duplicate);
        successful(&tx, "late old recovery cannot distribute twice");
        assert_eq!(
            fixture
                .chain
                .blockchain
                .get_account(&fixture.pool)
                .expect("pool")
                .get_data()
                .expect("data"),
            before
        );
        if reject {
            r3_accounting::fund(&mut fixture, 0, 60 * TOS);
            let stake = begin(&mut fixture, 3, next);
            let (tx, out) = step(&mut fixture.chain, stake);
            successful(&tx, "new stake after refused round");
            let receipt = only_to(out, &fixture.validator.address);
            finish_reply(&mut fixture, receipt, 2);
        }
        for i in 0..3 {
            let mut validator = deploy_rooted_validator(&mut fixture.chain, 0x20 + i);
            root_place(&mut fixture.chain, &mut validator, next, 1, 10_002 * TOS);
        }
        rotate_elected_round(&mut fixture.chain, next);
        let command = pool_command(&fixture, 6);
        fixture.chain.blockchain.send_message(command).expect("pool set update").expect_success();
        let until =
            fixture.chain.blockchain.config_params().validator_set().expect("set").utime_until();
        fixture.chain.blockchain.set_now(
            (until - fixture.chain.elect_begin_before).max(fixture.chain.blockchain.now() + 1),
        );
        tick(&mut fixture.chain);
        let later = active_election_id(&fixture.chain) as u32;
        for i in 0..4 {
            let mut validator = deploy_rooted_validator(&mut fixture.chain, 0x24 + i);
            root_place(&mut fixture.chain, &mut validator, later, 1, 10_002 * TOS);
        }
        rotate_elected_round(&mut fixture.chain, later);
        let command = pool_command(&fixture, 6);
        fixture
            .chain
            .blockchain
            .send_message(command)
            .expect("pool second update")
            .expect_success();
        let held = fixture
            .chain
            .blockchain
            .config_params()
            .elector_params()
            .expect("params")
            .stake_held_for;
        fixture.chain.blockchain.set_now(fixture.chain.blockchain.now() + held + 61);
        for _ in 0..8 {
            if !has_past_election(&fixture.chain, next) {
                break;
            }
            tick(&mut fixture.chain);
        }
        assert!(!has_past_election(&fixture.chain, next));
        let owner: [u8; 32] = fixture.pool.address().get_bytestring(0).try_into().expect("owner");
        assert!(owed(&fixture.chain, &owner) >= u128::from(10_001 * TOS));
        let command = pool_command(&fixture, 0x47657424);
        fixture
            .chain
            .blockchain
            .send_message(command)
            .expect("new principal recovery cascade")
            .expect_success();
        assert_eq!(fixture.pool_state(), 0);
        assert_eq!(owed(&fixture.chain, &owner), 0);
        let mut root = SliceData::load_cell(
            fixture
                .chain
                .blockchain
                .get_account(&fixture.chain.elector)
                .expect("elector")
                .get_data()
                .expect("data"),
        )
        .expect("slice");
        next_dictionary(&mut root, 32);
        next_dictionary(&mut root, 256);
        next_dictionary(&mut root, 32);
        next_coins(&mut root);
        root.get_next_u32().expect("active");
        root.get_next_hash().expect("hash");
        let book = root.checked_drain_reference().expect("receipt book");
        let mut book = SliceData::load_cell(book).expect("book");
        book.get_next_u32().expect("metadata tag");
        assert_eq!(book.get_next_u32().expect("outstanding"), 0);
    }
}

#[test]
fn relay_query_allocation_refuses_large_jumps_without_burning_the_next_id() {
    let mut fixture = Fixture::new("bounded-relay-query-allocation");
    let order = fixture.order(1, fixture.election + 1, 10_002 * TOS);
    let (tx, out) = step(&mut fixture.chain, order);
    successful(&tx, "valid signed pool request");
    let relay = only_to(out, &fixture.validator.address);
    let original = fixture
        .chain
        .blockchain
        .get_account(&fixture.validator.address)
        .expect("controller")
        .get_data()
        .expect("data");
    for query in [u64::MAX, u64::MAX - 1, DOMAIN | 1_000_000, DOMAIN | 2] {
        let mut attempted = relay.clone();
        let mut body = attempted.body().expect("body").clone();
        let operation = body.get_next_u32().expect("op");
        body.get_next_u64().expect("query");
        let mut changed = BuilderData::new();
        changed.append_u32(operation).expect("op");
        changed.append_u64(query).expect("query");
        changed
            .checked_append_references_and_data(&body)
            .expect("same valid signature and commitment");
        attempted.set_body(SliceData::load_cell(changed.into_cell().expect("body")).expect("body"));
        let (tx, _) = step(&mut fixture.chain, attempted);
        assert!(
            tx.read_description().expect("description").is_aborted(),
            "nonconsecutive valid-signature query must be refused"
        );
        assert_eq!(
            fixture
                .chain
                .blockchain
                .get_account(&fixture.validator.address)
                .expect("controller")
                .get_data()
                .expect("data"),
            original
        );
    }
    let (tx, out) = step(&mut fixture.chain, relay);
    successful(&tx, "next allocated query still works");
    let request = only_to(out, &fixture.chain.elector);
    let (tx, out) = step(&mut fixture.chain, request);
    successful(&tx, "business refusal");
    let receipt = only_to(out, &fixture.validator.address);
    finish_reply(&mut fixture, receipt, 0);
    let next = fixture
        .chain
        .blockchain
        .run_get_method(&fixture.validator.address, "next_relay_query", vec![])
        .expect("next query");
    assert_eq!(next.exit_code, 0);
    assert_eq!(next.stack[0].as_integer().expect("query").to_string(), (DOMAIN | 2).to_string());
    let next_root = PqValidator::new(0x74);
    let mut payload = BuilderData::new();
    payload.checked_append_reference(stored_bytes(&next_root.public_key)).expect("root");
    let message = controller_authorization(
        &fixture,
        2,
        payload.into_cell().expect("payload"),
        Some(&next_root),
    );
    let (tx, _) = step(&mut fixture.chain, message);
    successful(&tx, "root rotation after cleanup");
    fixture.validator.root = next_root;
    let next_key = PqValidator::new(0x75);
    let mut payload = BuilderData::new();
    payload.append_u16(1).expect("algorithm");
    payload.checked_append_reference(stored_bytes(&next_key.public_key)).expect("consensus");
    let message = controller_authorization(
        &fixture,
        3,
        payload.into_cell().expect("payload"),
        Some(&next_key),
    );
    let (tx, _) = step(&mut fixture.chain, message);
    successful(&tx, "consensus rotation after cleanup");
    fixture.validator.consensus = next_key;
    let next = fixture
        .chain
        .blockchain
        .run_get_method(&fixture.validator.address, "next_relay_query", vec![])
        .expect("getter after rotation");
    assert_eq!(next.stack[0].as_integer().expect("query").to_string(), (DOMAIN | 2).to_string());
    let at = fixture.election;
    r3_accounting::fund(&mut fixture, 0, 60 * TOS);
    let stake = begin(&mut fixture, 2, at);
    let (tx, out) = step(&mut fixture.chain, stake);
    successful(&tx, "rotated next request");
    let receipt = only_to(out, &fixture.validator.address);
    finish_reply(&mut fixture, receipt, 2);
}

#[test]
fn single_pool_reuses_the_authoritative_query_after_a_real_controller_bounce() {
    let mut fixture = Fixture::new("single-query-bounce-recovery");
    fixture.pool = deploy_single_nominator(
        &mut fixture.chain,
        fixture.operator.address(),
        fixture.operator.address(),
        &fixture.validator.address,
        20_000 * TOS,
    );
    let order = fixture.order(u64::MAX, fixture.election, 10_002 * TOS);
    let (tx, out) = step(&mut fixture.chain, order);
    successful(&tx, "signed out-of-sequence single-pool order");
    let relay = only_to(out, &fixture.validator.address);
    let (tx, out) = step(&mut fixture.chain, relay);
    assert!(tx.read_description().expect("description").is_aborted());
    let bounce = only_to(out, &fixture.pool);
    assert!(bounce.is_bounced());
    let (tx, _) = step(&mut fixture.chain, bounce);
    successful(&tx, "actual controller refusal bounce");
    assert!(fixture.pending().is_none());
    let at = fixture.election;
    r3_accounting::fund(&mut fixture, 0, 60 * TOS);
    let stake = begin(&mut fixture, 1, at);
    let (tx, out) = step(&mut fixture.chain, stake);
    successful(&tx, "allocated next single-pool stake");
    let receipt = only_to(out, &fixture.validator.address);
    let (_, out) = step(&mut fixture.chain, receipt);
    let message = only_to(out, &fixture.validator.address);
    let (_, out) = step(&mut fixture.chain, message);
    let payment = only_to(out, &fixture.pool);
    let (tx, out) = step(&mut fixture.chain, payment);
    successful(&tx, "single pool accepts bound success");
    let ack = only_to(out, &fixture.validator.address);
    let (tx, _) = step(&mut fixture.chain, ack);
    successful(&tx, "single pool cleanup");
    assert!(fixture.pending().is_none());
}

#[test]
fn single_pool_bounce_preserves_a_previous_unacknowledged_result() {
    let mut fixture = Fixture::new("single-previous-result-after-bounce");
    fixture.pool = deploy_single_nominator(
        &mut fixture.chain,
        fixture.operator.address(),
        fixture.operator.address(),
        &fixture.validator.address,
        20_000 * TOS,
    );
    let at = fixture.election + 1;
    r3_accounting::fund(&mut fixture, 0, 60 * TOS);
    let stake = begin(&mut fixture, 1, at);
    let (_, out) = step(&mut fixture.chain, stake);
    let receipt = only_to(out, &fixture.validator.address);
    let (_, out) = step(&mut fixture.chain, receipt);
    let kick = only_to(out, &fixture.validator.address);
    let (_, out) = step(&mut fixture.chain, kick);
    let payment = only_to(out, &fixture.pool);
    let (tx, out) = step(&mut fixture.chain, payment);
    successful(&tx, "first single-pool business result");
    assert_eq!(op(&only_to(out, &fixture.validator.address)), ACK); // Lost deliberately.
    let paid = fixture
        .chain
        .blockchain
        .get_account(&fixture.pool)
        .expect("pool")
        .get_data()
        .expect("data");
    let order = fixture.order(2, fixture.election, 10_002 * TOS);
    let (tx, out) = step(&mut fixture.chain, order);
    successful(&tx, "new order while prior ACK was lost");
    let relay = only_to(out, &fixture.validator.address);
    let (tx, out) = step(&mut fixture.chain, relay);
    assert!(tx.read_description().expect("description").is_aborted());
    let bounce = only_to(out, &fixture.pool);
    assert!(bounce.is_bounced());
    let (tx, _) = step(&mut fixture.chain, bounce);
    successful(&tx, "refused attempt restores prior result");
    assert_eq!(
        fixture
            .chain
            .blockchain
            .get_account(&fixture.pool)
            .expect("pool")
            .get_data()
            .expect("data"),
        paid,
        "real bounce must retain the previous ACK repair record"
    );
    let request = retry(&fixture, DOMAIN | 1);
    let (tx, out) = step(&mut fixture.chain, request);
    successful(&tx, "old paid receipt retry");
    let repeat = only_to(out, &fixture.pool);
    assert!(value(&repeat) < u128::from(20 * TOS));
    let (tx, out) = step(&mut fixture.chain, repeat);
    successful(&tx, "pool repairs previous ACK");
    let ack = only_to(out, &fixture.validator.address);
    let (tx, _) = step(&mut fixture.chain, ack);
    successful(&tx, "controller clears old paid slot");
    assert!(fixture.pending().is_none());
    let at = fixture.election;
    r3_accounting::fund(&mut fixture, 0, 60 * TOS);
    let stake = begin(&mut fixture, 2, at);
    let (tx, _) = step(&mut fixture.chain, stake);
    successful(&tx, "normal next allocation after repair");
}
