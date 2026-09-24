/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The liquid-staking controller, run rather than read.
//!
//! Of the three pooled-staking contracts this is the one whose failure was not a missed
//! round. It keeps a state machine, and in `SENT_STAKE_REQUEST` it recognises exactly two
//! answers: the stake was taken, or the stake was refused. Anything else sets `halted?`,
//! which is a permanent stop only a governor can lift -- and the elector's unknown-query
//! tag is neither, so the first stake this contract sent halted it for good.
//!
//! It stakes through a Validator Controller now. That account is the one the elector takes
//! a stake from, and it answers this contract in the two words this contract knows. The
//! test that recorded the halt is inverted below.

use chain_block::{
    Account, BuilderData, Cell, Coins, ConfigParams, IBitstring, MsgAddressInt, Serializable,
    ShardStateUnsplit, StateInit, TransactionTickTock,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func, generate_zerostate_state};

const TOS: u64 = 1_000_000_000;

const NEW_STAKE: u32 = 0x4e73_744b;
/// `PQrl`: what this contract asks a Validator Controller to relay.
const RELAY_STAKE: u32 = 0x5051_726c;
const UNKNOWN_QUERY: u32 = 0xffff_ffff;
const NEW_STAKE_OK: u32 = 0xf374_484c;
const NEW_STAKE_ERROR: u32 = 0xee6f_454c;

/// `PQsl`: naming the Validator Controller a stake travels through.
const SET_VALIDATOR_CONTROLLER: u32 = 0x5051_736c;
const TOP_UP: u32 = 0xd372_158c;

const STATE_REST: u8 = 0;
const STATE_SENT_STAKE_REQUEST: u8 = 2;

const ERROR_NO_VALIDATOR_CONTROLLER: i32 = 0xfc00;

fn repo_root() -> std::path::PathBuf {
    std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root above the contracts crate")
            .to_path_buf()
    })
}

fn zerostate() -> ShardStateUnsplit {
    generate_zerostate_state(repo_root().join("crypto/smartcont/gen-zerostate.fif"))
        .expect("zerostate generation needs build/crypto/create-state and the fift libraries")
}

fn configuration(state: &ShardStateUnsplit) -> ConfigParams {
    state
        .read_custom()
        .expect("masterchain extra")
        .expect("the zerostate is a masterchain state")
        .config()
        .clone()
}

fn account(state: &ShardStateUnsplit, address: &MsgAddressInt) -> Account {
    state
        .read_accounts()
        .expect("accounts")
        .account(&address.address())
        .expect("account lookup")
        .unwrap_or_else(|| panic!("the zerostate deploys nothing at {address}"))
        .read_account()
        .expect("account")
}

fn masterchain(id: chain_block::AccountId) -> MsgAddressInt {
    MsgAddressInt::with_standart(None, -1, id).expect("masterchain address")
}

/// The controller carries its own stdlib beside its includes, so it is compiled with
/// that one: a contract built against other definitions is another contract.
fn controller_code() -> Cell {
    compile_func(&[repo_root().join("crypto/smartcont/liquid-staking/controller.func")])
        .expect("the liquid-staking controller compiles")
}

/// The initial storage the pool writes, taken from the pool's own source.
///
/// Building it here instead would make this suite agree with itself: the layout that
/// matters is the one `address_calculations.func` writes, and a field missing there is a
/// field the controller underflows on at its first message. So the probe compiles that
/// file and is asked for the cell.
fn pool_written_controller_data(statics: Cell) -> Cell {
    let probe = std::env::temp_dir().join(format!(
        "tos_liquid_init_probe-{}-{:?}.fc",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(
        &probe,
        r#"
global cell controller_code;
cell probe_controller_init_data(cell static_data) method_id {
  return controller_init_data(static_data);
}
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
}
"#,
    )
    .expect("probe source");
    let code = compile_func(&[
        repo_root().join("crypto/smartcont/liquid-staking/stdlib.func"),
        repo_root().join("crypto/smartcont/liquid-staking/types.func"),
        repo_root().join("crypto/smartcont/liquid-staking/address_calculations.func"),
        probe,
    ])
    .expect("the pool's address calculations and their probe compile");

    let mut chain = Blockchain::new().expect("a chain for the probe");
    chain.set_workchain(-1);
    let address = masterchain(chain_block::AccountId::from([0x77u8; 32]));
    let init = StateInit::with_code_and_data(code, Cell::default());
    let deployment = MessageBuilder::internal(&address, &address, 1_000 * TOS)
        .bounce(false)
        .state_init(init)
        .body(Cell::default())
        .build();
    chain.set_account(
        address.clone(),
        Account::from_message(&deployment).expect("the probe account"),
    );
    let result = chain
        .run_get_method(
            &address,
            "probe_controller_init_data",
            vec![tos_vm::stack::StackItem::Cell(statics)],
        )
        .expect("the probe answers");
    assert_eq!(result.exit_code, 0, "probe_controller_init_data failed");
    result.stack.last().expect("a cell").as_cell().expect("a cell").clone()
}

/// A controller at rest, approved, owing nothing. The static half lives behind two
/// references, which is how the contract reads it back.
/// The half of a controller's storage the pool builds and the controller never writes.
fn controller_statics(
    validator: &MsgAddressInt,
    pool: &MsgAddressInt,
    governor: &MsgAddressInt,
) -> Cell {
    let mut roles = BuilderData::new();
    governor.write_to(&mut roles).expect("approver");
    governor.write_to(&mut roles).expect("halter");

    let mut statics = BuilderData::new();
    statics.append_u32(0).expect("controller id");
    validator.write_to(&mut statics).expect("validator");
    pool.write_to(&mut statics).expect("pool");
    governor.write_to(&mut statics).expect("governor");
    statics
        .checked_append_reference(roles.into_cell().expect("roles cell"))
        .expect("roles reference");
    statics.into_cell().expect("statics cell")
}

fn controller_data(
    validator: &MsgAddressInt,
    pool: &MsgAddressInt,
    governor: &MsgAddressInt,
    validator_controller: &MsgAddressInt,
) -> Cell {
    let none = BuilderData::new();
    let statics = controller_statics(validator, pool, governor);

    let mut data = BuilderData::new();
    data.append_u8(STATE_REST).expect("state");
    data.append_bit_zero().expect("not halted");
    data.append_bit_one().expect("approved");
    Coins::new(0).write_to(&mut data).expect("stake amount sent");
    data.append_bits(0, 48).expect("stake at");
    data.append_raw(&[0u8; 32], 256).expect("saved validator set hash");
    data.append_u8(0).expect("validator set changes count");
    data.append_bits(0, 48).expect("validator set change time");
    data.append_bits(0, 48).expect("stake held for");
    Coins::new(0).write_to(&mut data).expect("borrowed amount");
    data.append_bits(0, 48).expect("borrowing time");
    data.append_bits(0, 2).expect("no sudoer");
    data.append_bits(0, 48).expect("sudoer set at");
    data.append_bits(0, 24).expect("max expected interest");
    // Named after deployment, not built into the address: the pool that deploys a
    // controller does not know which account its validator stakes through.
    validator_controller.write_to(&mut data).expect("validator controller");
    data.checked_append_reference(statics).expect("statics reference");
    let _ = none;
    data.into_cell().expect("controller data")
}

struct Staking {
    chain: Blockchain,
    elector: MsgAddressInt,
    controller: MsgAddressInt,
    validator: MsgAddressInt,
    validator_controller: MsgAddressInt,
}

fn launch(balance: u64) -> Staking {
    launch_with(balance, true)
}

/// A controller as the pool deploys one: no Validator Controller named yet.
fn launch_unnamed(balance: u64) -> Staking {
    launch_with(balance, false)
}

fn launch_with(balance: u64, named: bool) -> Staking {
    let state = zerostate();
    let config = configuration(&state);
    let elector = masterchain(config.elector_address().expect("elector address"));
    let config_contract = masterchain(config.config_address().expect("configuration address"));
    let current = config.validator_set().expect("the zerostate elects a validator set");
    let params = config.elector_params().expect("elector parameters");
    let elector_account = account(&state, &elector);
    let config_account = account(&state, &config_contract);

    let mut chain = Blockchain::with_config(config).expect("sandbox with the real config");
    chain.set_workchain(-1);
    chain.set_account(elector.clone(), elector_account);
    chain.set_account(config_contract, config_account);

    chain.set_now(current.utime_until() - params.elections_start_before);
    chain.tick_tock(&elector, TransactionTickTock::Tick).expect("tick runs").expect_success();

    let validator = chain.treasury("ls-validator", 100_000 * TOS).expect("the validator wallet");
    let validator_address = validator.address().clone();
    let pool = chain.treasury("ls-pool", 10_000 * TOS).expect("the pool");
    let pool_address = pool.address().clone();
    let governor = chain.treasury("ls-governor", 10_000 * TOS).expect("the governor");
    let governor_address = governor.address().clone();

    // The account that stands in the election. A real one is a deployed Validator
    // Controller; what this suite judges is that the stake is sent there and nowhere
    // else, so an address is enough.
    let validator_controller =
        chain.treasury("ls-validator-controller", 10_000 * TOS).expect("a validator controller");
    let validator_controller_address = validator_controller.address().clone();

    let init = StateInit::with_code_and_data(
        controller_code(),
        if named {
            controller_data(
                &validator_address,
                &pool_address,
                &governor_address,
                &validator_controller_address,
            )
        } else {
            // Not written here: what the pool's own source lays down when it deploys one.
            pool_written_controller_data(controller_statics(
                &validator_address,
                &pool_address,
                &governor_address,
            ))
        },
    );
    let controller = MsgAddressInt::with_params(
        -1,
        init.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("controller address");

    // Placed rather than deployed by message: the controller reads an operation before
    // anything else, so it has no empty-body deploy path.
    let deployment = MessageBuilder::internal(&validator_address, &controller, balance)
        .bounce(false)
        .state_init(init)
        .body(Cell::default())
        .build();
    chain.set_account(
        controller.clone(),
        Account::from_message(&deployment).expect("an account from the deployment"),
    );

    Staking {
        chain,
        elector,
        controller,
        validator: validator_address,
        validator_controller: validator_controller_address,
    }
}

/// The order: stake this much, on these terms. The payload is built into the body rather
/// than into a cell of its own, because the contract reads it as a continuation of the
/// same slice and a reference does not survive being appended as bits.
fn stake_order(query_id: u64, value: u64, election: u32) -> Cell {
    let mut key = BuilderData::new();
    key.append_u32(1312).expect("declared length");
    key.checked_append_reference(Cell::default()).expect("the key's bytes");
    let mut signature = BuilderData::new();
    signature.append_u32(2420).expect("declared length");
    signature.checked_append_reference(Cell::default()).expect("the signature's bytes");

    let mut body = BuilderData::new();
    body.append_u32(NEW_STAKE).expect("operation");
    body.append_u64(query_id).expect("query id");
    Coins::new(value).write_to(&mut body).expect("value");
    body.append_u32(election).expect("election");
    body.append_u32(0x10000).expect("max factor");
    body.append_raw(&[0xa5; 32], 256).expect("adnl address");
    body.append_u16(1).expect("algorithm");
    body.checked_append_reference(key.into_cell().expect("key cell")).expect("the key");
    body.checked_append_reference(signature.into_cell().expect("signature cell"))
        .expect("the signature");
    body.append_bit_zero().expect("no birth witness");
    body.into_cell().expect("stake order")
}

impl Staking {
    fn election(&self) -> u32 {
        let result = self
            .chain
            .run_get_method(&self.elector, "active_election_id", vec![])
            .expect("the elector answers");
        assert_eq!(result.exit_code, 0, "active_election_id failed");
        result
            .stack
            .last()
            .expect("a value")
            .as_integer()
            .expect("an integer")
            .to_string()
            .parse()
            .expect("an election id")
    }

    /// The two fields these tests judge: where the state machine is, and whether it has
    /// stopped.
    fn state(&self) -> (u8, bool) {
        let result = self
            .chain
            .run_get_method(&self.controller, "get_validator_controller_data", vec![])
            .expect("the controller answers");
        assert_eq!(result.exit_code, 0, "get_validator_controller_data failed");
        let state: u8 =
            result.stack[0].as_integer().expect("state").to_string().parse().expect("a state");
        let halted = result.stack[1].as_integer().expect("halted").to_string() != "0";
        (state, halted)
    }

    fn order(&mut self, query_id: u64, value: u64, election: u32) -> tos_sandbox::SendResult {
        let order = stake_order(query_id, value, election);
        let sender = self.validator.clone();
        let target = self.controller.clone();
        self.chain
            .send_message(MessageBuilder::internal(&sender, &target, 2 * TOS).body(order).build())
            .expect("the order is delivered")
    }

    /// Name the account a stake is to travel through.
    fn name_controller(
        &mut self,
        from: &MsgAddressInt,
        named: &MsgAddressInt,
    ) -> tos_sandbox::SendResult {
        let mut body = BuilderData::new();
        body.append_u32(SET_VALIDATOR_CONTROLLER).expect("operation");
        body.append_u64(1).expect("query id");
        named.write_to(&mut body).expect("the named account");
        let target = self.controller.clone();
        self.chain
            .send_message(
                MessageBuilder::internal(from, &target, TOS)
                    .body(body.into_cell().expect("a naming"))
                    .build(),
            )
            .expect("the naming is delivered")
    }
}

/// What the contract itself made of a message, rather than what its answer looked like.
fn exit_code(result: &tos_sandbox::SendResult) -> i32 {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    match transaction.read_description().expect("a description").compute_phase_ref() {
        Some(chain_block::TrComputePhase::Vm(vm)) => vm.exit_code,
        _ => panic!("the message was not executed"),
    }
}

/// Where the first message the contract sent went, what it asked for, and what it carried.
fn sent(result: &tos_sandbox::SendResult) -> Option<(MsgAddressInt, u32, u128)> {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    let mut out = None;
    transaction
        .iterate_out_msgs(|message| {
            if out.is_none() {
                if let Some(body) = message.body() {
                    let mut body = body.clone();
                    if let Ok(tag) = body.get_next_u32() {
                        let value = message.get_value().map(|v| v.coins.as_u128()).unwrap_or(0);
                        out = Some((message.dst().expect("a destination"), tag, value));
                    }
                }
            }
            Ok(true)
        })
        .expect("out messages");
    out
}

/// Every reply tag anyone sent during the cascade.
fn reply_tags(result: &tos_sandbox::SendResult) -> Vec<u32> {
    let mut tags = Vec::new();
    for (_, transaction) in &result.transactions {
        transaction
            .iterate_out_msgs(|message| {
                if let Some(body) = message.body() {
                    let mut body = body.clone();
                    if let Ok(tag) = body.get_next_u32() {
                        tags.push(tag);
                    }
                }
                Ok(true)
            })
            .expect("out messages");
    }
    tags
}

#[test]
fn the_controller_starts_at_rest_and_running() {
    let staking = launch(100_000 * TOS);
    assert_eq!(staking.state(), (STATE_REST, false), "a fresh controller is not at rest");
    assert_ne!(staking.election(), 0, "the fixture needs an open election");
}

/// Only the validator may spend this controller's funds on a stake. Without this the
/// test below could be passing against a contract that never ran.
#[test]
fn only_the_validator_can_order_a_stake() {
    let mut staking = launch(100_000 * TOS);
    let election = staking.election();
    let stranger = staking.chain.treasury("ls-stranger", 10_000 * TOS).expect("another wallet");
    let sender = stranger.address().clone();
    let target = staking.controller.clone();
    let order = stake_order(1, 60_000 * TOS, election);
    let result = staking
        .chain
        .send_message(MessageBuilder::internal(&sender, &target, 2 * TOS).body(order).build())
        .expect("delivered");
    assert!(
        result.transactions.iter().any(|(_, transaction)| transaction
            .read_description()
            .expect("description")
            .is_aborted()),
        "a stranger's order was carried out"
    );
    assert_eq!(staking.state(), (STATE_REST, false), "a refused order moved the controller");
}

/// The stake goes to the Validator Controller, and the contract records that it is out.
///
/// This test was written the other way round. The stake went to the elector, which does
/// not know that operation and answered with its unknown-query tag; this contract, in
/// `SENT_STAKE_REQUEST` and recognising only "taken" and "refused", concluded that
/// something it could not account for had happened and halted itself permanently. That is
/// what the first stake used to do.
#[test]
fn a_stake_goes_to_the_validator_controller_and_the_contract_keeps_running() {
    let mut staking = launch(100_000 * TOS);
    let election = staking.election();
    let target = staking.validator_controller.clone();

    let result = staking.order(1, 60_000 * TOS, election);

    let (to, tag, value) = sent(&result).expect("the controller sent nothing on");
    assert_eq!(tag, RELAY_STAKE, "the contract did not ask for a stake to be relayed");
    assert_eq!(to, target, "the stake went somewhere that is not the validator controller");
    assert!(value > u128::from(50_000 * TOS), "the stake carried {value} rather than the money");

    // It is waiting for an answer, and it is still running.
    let (state, halted) = staking.state();
    assert_eq!(state, STATE_SENT_STAKE_REQUEST, "the contract did not record the stake it sent");
    assert!(!halted, "the contract halted itself on a stake it successfully sent");

    // And the elector was not asked anything: it takes a stake from a controller only.
    let (_, _, went_to_elector) = (0, 0, reply_tags(&result).contains(&NEW_STAKE));
    assert!(!went_to_elector, "the classical stake operation is still being sent");
}

/// A stake the Validator Controller refuses comes back, and this contract goes to rest.
///
/// Without recognising the bounce it waits in `SENT_STAKE_REQUEST` for an answer that has
/// already arrived, and the next round's order is refused for the state it is in.
#[test]
fn a_bounced_relay_returns_the_contract_to_rest() {
    let mut staking = launch(100_000 * TOS);
    let election = staking.election();
    staking.order(1, 60_000 * TOS, election);
    assert_eq!(staking.state().0, STATE_SENT_STAKE_REQUEST, "the stake was not sent");

    let mut body = BuilderData::new();
    body.append_u32(0xffff_ffff).expect("the bounced prefix");
    body.append_u32(RELAY_STAKE).expect("the operation that bounced");
    body.append_u64(1).expect("query id");
    let from = staking.validator_controller.clone();
    let target = staking.controller.clone();
    // Marked bounced, which is the bit the contract reads to tell one from an ordinary
    // message; the builder has no word for it.
    let mut bounce = MessageBuilder::internal(&from, &target, TOS)
        .body(body.into_cell().expect("a bounce"))
        .build();
    bounce.int_header_mut().expect("an internal message").bounced = true;
    staking.chain.send_message(bounce).expect("the bounce is delivered").expect_success();

    assert_eq!(
        staking.state(),
        (STATE_REST, false),
        "the contract is still waiting for a stake that came back"
    );
}

/// What the pool actually deploys, and what it can do before it is told anything.
///
/// A controller's initial storage is written by the pool, which deploys one for whichever
/// validator asks and cannot know that validator's Validator Controller. So the account
/// starts without one. The first thing this test asserts is that such an account can be
/// read at all: a field the pool does not write is a field the contract underflows on, and
/// every later message would fail before reaching any of its own checks.
#[test]
fn a_controller_the_pool_deployed_has_nowhere_to_stake_until_the_validator_says() {
    let mut staking = launch_unnamed(100_000 * TOS);
    let election = staking.election();

    // Readable, which is the part the pool's layout decides.
    let (state, halted) = staking.state();
    assert_eq!(state, STATE_REST, "a freshly deployed controller is not at rest");
    assert!(!halted, "a freshly deployed controller is halted");

    // And writeable: an ordinary message writes the storage back, empty field and all. A
    // layout that only survives being read is one that fails on the first message that
    // saves.
    let mut top_up = BuilderData::new();
    top_up.append_u32(TOP_UP).expect("operation");
    top_up.append_u64(1).expect("query id");
    let from = staking.validator.clone();
    let target = staking.controller.clone();
    let funded = staking
        .chain
        .send_message(
            MessageBuilder::internal(&from, &target, 10 * TOS)
                .body(top_up.into_cell().expect("a top-up"))
                .build(),
        )
        .expect("the top-up is delivered");
    assert_eq!(exit_code(&funded), 0, "a controller with no name set could not be topped up");
    assert_eq!(staking.state(), (STATE_REST, false), "the saved storage no longer reads back");

    // And it will not stake, because it has nowhere to stake to.
    let refused = staking.order(1, 60_000 * TOS, election);
    assert_eq!(
        exit_code(&refused),
        ERROR_NO_VALIDATOR_CONTROLLER,
        "a controller with no validator controller sent a stake somewhere"
    );
    assert_eq!(staking.state().0, STATE_REST, "a refused stake moved the controller");

    // A stranger cannot name it either.
    let named = staking.validator_controller.clone();
    let stranger = staking.chain.treasury("ls-stranger", 10_000 * TOS).expect("a stranger");
    let stranger_address = stranger.address().clone();
    let result = staking.name_controller(&stranger_address, &named);
    assert_ne!(exit_code(&result), 0, "a stranger named the account a stake goes to");

    // The validator does, and then the stake goes where it was told.
    let validator = staking.validator.clone();
    let result = staking.name_controller(&validator, &named);
    assert_eq!(exit_code(&result), 0, "the validator could not name its own controller");

    let result = staking.order(2, 60_000 * TOS, election);
    let (to, tag, _) = sent(&result).expect("the controller sent nothing on");
    assert_eq!(tag, RELAY_STAKE, "the contract did not ask for a stake to be relayed");
    assert_eq!(to, named, "the stake went somewhere other than the named controller");
    assert_eq!(staking.state().0, STATE_SENT_STAKE_REQUEST, "the stake was not recorded");
}

/// A name may not move while an answer is still coming back to it.
#[test]
fn the_account_a_stake_went_through_cannot_be_renamed_under_it() {
    let mut staking = launch(100_000 * TOS);
    let election = staking.election();
    staking.order(1, 60_000 * TOS, election);
    assert_eq!(staking.state().0, STATE_SENT_STAKE_REQUEST, "the stake was not sent");

    let validator = staking.validator.clone();
    let other = staking.chain.treasury("ls-other-controller", 10_000 * TOS).expect("another");
    let other_address = other.address().clone();
    let result = staking.name_controller(&validator, &other_address);
    assert_ne!(exit_code(&result), 0, "the name moved while a stake was out");
}

/// Terms that are not the shape of a stake are refused, and nothing is sent.
#[test]
fn terms_that_are_not_a_stake_are_refused_before_anything_is_sent() {
    let mut staking = launch(100_000 * TOS);
    let election = staking.election();

    let mut body = BuilderData::new();
    body.append_u32(NEW_STAKE).expect("operation");
    body.append_u64(1).expect("query id");
    Coins::new(60_000 * TOS).write_to(&mut body).expect("value");
    body.append_u32(election).expect("election");
    body.append_u32(0x10000).expect("max factor");
    // And then it stops.

    let sender = staking.validator.clone();
    let target = staking.controller.clone();
    let result = staking
        .chain
        .send_message(
            MessageBuilder::internal(&sender, &target, 2 * TOS)
                .body(body.into_cell().expect("a truncated order"))
                .build(),
        )
        .expect("delivered");
    assert!(sent(&result).is_none(), "a stake with no terms was relayed anyway");
    assert_eq!(staking.state(), (STATE_REST, false), "a refused order moved the contract");
}

/// The retired liquid-controller Fift command wrote Validator.fif's classical
/// body: a raw Ed25519 key before the election terms and a 64-byte signature
/// reference. The compiled controller must reject the complete old body before
/// sending `RELAY_STAKE`; a truncated-body control alone cannot establish that.
#[test]
fn classical_liquid_controller_order_is_refused_before_controller_relay() {
    let mut staking = launch(100_000 * TOS);
    let election = staking.election();
    let mut body = BuilderData::new();
    body.append_u32(NEW_STAKE).expect("operation");
    body.append_u64(7).expect("query id");
    Coins::new(60_000 * TOS).write_to(&mut body).expect("stake amount");
    body.append_raw(&[0x11; 32], 256).expect("classical public key");
    body.append_u32(election).expect("election");
    body.append_u32(0x10000).expect("max factor");
    body.append_raw(&[0xa5; 32], 256).expect("adnl address");
    let mut signature = BuilderData::new();
    signature.append_raw(&[0x33; 64], 512).expect("Ed25519 signature");
    body.checked_append_reference(signature.into_cell().expect("signature cell"))
        .expect("classical signature reference");

    let sender = staking.validator.clone();
    let target = staking.controller.clone();
    let result = staking
        .chain
        .send_message(
            MessageBuilder::internal(&sender, &target, 2 * TOS)
                .body(body.into_cell().expect("complete classical stake order"))
                .build(),
        )
        .expect("delivered");
    let transaction = &result.transactions.first().expect("controller transaction").1;
    assert!(
        transaction.read_description().expect("description").is_aborted(),
        "the PQ-shaped controller accepted a classical Ed25519 stake body",
    );
    assert!(
        !reply_tags(&result).contains(&RELAY_STAKE),
        "the liquid controller relayed a classical Ed25519 stake body",
    );
    assert_eq!(staking.state(), (STATE_REST, false), "a rejected order moved the controller");
}

/// Told the stake was taken, the contract says so; told it was refused, it goes back to
/// rest and can try again. Those are the two answers it knows, and the Validator
/// Controller is between it and the elector precisely so that it gets one of them.
#[test]
fn the_two_answers_it_knows_move_it_on_rather_than_halting_it() {
    for (answer, expected_state) in [(NEW_STAKE_OK, 3u8), (NEW_STAKE_ERROR, STATE_REST)] {
        let mut staking = launch(100_000 * TOS);
        let election = staking.election();
        staking.order(1, 60_000 * TOS, election);
        assert_eq!(staking.state().0, STATE_SENT_STAKE_REQUEST, "the stake was not sent");

        let mut body = BuilderData::new();
        body.append_u32(answer).expect("the answer");
        body.append_u64(1).expect("query id");
        let elector = staking.elector.clone();
        let target = staking.controller.clone();
        staking
            .chain
            .send_message(
                MessageBuilder::internal(&elector, &target, TOS)
                    .body(body.into_cell().expect("an answer"))
                    .build(),
            )
            .expect("the answer is delivered");

        let (state, halted) = staking.state();
        assert!(!halted, "an answer it knows halted it: {answer:08x}");
        assert_eq!(state, expected_state, "an answer it knows left it in the wrong state");
    }
}
