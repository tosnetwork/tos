/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The single-nominator pool, run rather than read.
//!
//! Three roles: a cold owner holds the funds, a validator wallet may spend them on a stake
//! and on nothing else, and a controller is the account that stands in the election. The
//! elector takes a stake from a controller and from nowhere else, so this contract sends
//! its stake there rather than straight on.
//!
//! The test that used to be here asserted the opposite -- that a stake reached the elector
//! and was answered with the unknown-query tag, leaving the round silently missed. It is
//! inverted below, which is what it was written for.

use chain_block::{
    Account, BuilderData, Cell, Coins, ConfigParams, IBitstring, MsgAddressInt, Serializable,
    ShardStateUnsplit, StateInit, TransactionTickTock,
};
use contracts::nominator::{NewStakeParams, new_stake};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib, generate_zerostate_state};

const TOS: u64 = 1_000_000_000;

const NEW_STAKE: u32 = 0x4e73_744b;
const RELAY_STAKE: u32 = 0x5051_726c;
const RECOVER_STAKE: u32 = 0x4765_7424;
const WITHDRAW: u32 = 0x1000;
const UNKNOWN_QUERY: u32 = 0xffff_ffff;
const NEW_STAKE_OK: u32 = 0xf374_484c;
const NEW_STAKE_ERROR: u32 = 0xee6f_454c;

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

fn nominator_code() -> Cell {
    compile_func_with_stdlib(&[
        repo_root().join("crypto/smartcont/single-nominator-pool/single-nominator-code.fc")
    ])
    .expect("the single-nominator contract compiles")
}

/// Its whole storage: who owns the money, who may stake it, and through whom.
fn nominator_data(
    owner: &MsgAddressInt,
    validator: &MsgAddressInt,
    controller: &MsgAddressInt,
) -> Cell {
    let mut data = BuilderData::new();
    owner.write_to(&mut data).expect("owner address");
    validator.write_to(&mut data).expect("validator address");
    controller.write_to(&mut data).expect("controller address");
    data.into_cell().expect("nominator data")
}

struct Pooled {
    chain: Blockchain,
    elector: MsgAddressInt,
    nominator: MsgAddressInt,
    owner: MsgAddressInt,
    validator: MsgAddressInt,
    controller: MsgAddressInt,
}

fn launch(balance: u64) -> Pooled {
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

    let owner = chain.treasury("cold-owner", 100_000 * TOS).expect("the owner wallet");
    let owner_address = owner.address().clone();
    let validator = chain.treasury("validator-wallet", 100_000 * TOS).expect("the hot wallet");
    let validator_address = validator.address().clone();

    // The controller the stake goes through. A real one is a deployed Validator
    // Controller; what this suite judges is that the stake is sent there and nowhere
    // else, so an address is enough.
    let controller = chain.treasury("validator-controller", 10_000 * TOS).expect("a controller");
    let controller_address = controller.address().clone();

    let init = StateInit::with_code_and_data(
        nominator_code(),
        nominator_data(&owner_address, &validator_address, &controller_address),
    );
    let nominator = MsgAddressInt::with_params(
        -1,
        init.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("nominator address");

    // This contract does have an empty-body path, so it is deployed the way an operator
    // deploys it rather than placed.
    chain
        .send_message(
            MessageBuilder::internal(&owner_address, &nominator, balance)
                .bounce(false)
                .state_init(init)
                .body(Cell::default())
                .build(),
        )
        .expect("the nominator deploys")
        .expect_success();

    Pooled {
        chain,
        elector,
        nominator,
        owner: owner_address,
        validator: validator_address,
        controller: controller_address,
    }
}

/// Exercise the production Rust builder against the compiled pool contract's
/// `check_new_stake_msg`, not a second hand-built encoding of its fields. This
/// proves that the contract accepts the body; it cannot detect a transposition
/// of adjacent fixed-width fields the contract parses but does not interpret.
/// The builder's unit test round-trips field *values* in pool-parser order to
/// guard that semantic property.
fn stake_order(query_id: u64, amount: u64, election: u32) -> Cell {
    new_stake(&NewStakeParams {
        query_id,
        stake_amount: amount,
        validator_pubkey: &[0x11; 1312],
        stake_at: election,
        max_factor: 0x10000,
        adnl_addr: &[0xa5; 32],
        signature: &[0x33; 2420],
    })
    .expect("PQ stake order for the pool parser")
}

fn simple_order(op: u32, query_id: u64) -> Cell {
    let mut body = BuilderData::new();
    body.append_u32(op).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.into_cell().expect("order")
}

fn withdraw_order(query_id: u64, amount: u64) -> Cell {
    let mut body = BuilderData::new();
    body.append_u32(WITHDRAW).expect("operation");
    body.append_u64(query_id).expect("query id");
    Coins::new(amount).write_to(&mut body).expect("amount");
    body.into_cell().expect("withdraw order")
}

impl Pooled {
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

    fn balance(&self, address: &MsgAddressInt) -> u64 {
        self.chain
            .get_account(address)
            .and_then(|account| account.balance().and_then(|balance| balance.coins.as_u64()))
            .unwrap_or(0)
    }

    fn from(&mut self, sender: &MsgAddressInt, body: Cell, value: u64) -> tos_sandbox::SendResult {
        let target = self.nominator.clone();
        self.chain
            .send_message(MessageBuilder::internal(sender, &target, value).body(body).build())
            .expect("the order is delivered")
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

/// What the elector itself did, separated from what came back.
///
/// A tag alone cannot tell a refusal from a bounce: a throw inside the elector returns a
/// bounced message whose first word is also `0xffffffff`, so a test that only looked for
/// that tag would report "the elector refused politely" when the elector had in fact
/// aborted. Teaching the elector the classical opcode again survived exactly that.
fn elector_verdict(result: &tos_sandbox::SendResult, elector: &MsgAddressInt) -> (bool, Vec<u32>) {
    let mut aborted = false;
    let mut tags = Vec::new();
    let mut ran = false;
    for (address, transaction) in &result.transactions {
        if address != elector {
            continue;
        }
        ran = true;
        aborted |= transaction.read_description().expect("description").is_aborted();
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
    assert!(ran, "the elector was never reached");
    (aborted, tags)
}

#[test]
fn the_nominator_deploys_and_reports_its_three_roles() {
    let pooled = launch(20_000 * TOS);
    let result = pooled
        .chain
        .run_get_method(&pooled.nominator, "get_roles", vec![])
        .expect("the nominator answers");
    assert_eq!(result.exit_code, 0, "get_roles failed");
    assert_eq!(result.stack.len(), 3, "a single nominator has exactly three roles");
}

/// The role separation this contract exists for, and the proof that the harness reaches
/// real behaviour: the owner may take the money home, and the validator may not.
#[test]
fn the_owner_takes_the_money_home_and_the_validator_cannot() {
    let mut pooled = launch(20_000 * TOS);
    let before = pooled.balance(&pooled.owner.clone());

    pooled.from(&pooled.owner.clone(), withdraw_order(1, 5_000 * TOS), TOS).expect_success();
    let after = pooled.balance(&pooled.owner.clone());
    assert!(after > before + 4_000 * TOS, "the owner did not get the funds back");

    // The same order from the validator does nothing at all: the contract reaches no
    // branch for it, so it neither sends nor throws.
    let held = pooled.balance(&pooled.nominator.clone());
    let result = pooled.from(&pooled.validator.clone(), withdraw_order(2, 5_000 * TOS), TOS);
    assert!(reply_tags(&result).is_empty(), "the validator moved funds it is not allowed to move");
    assert!(
        pooled.balance(&pooled.nominator.clone()) >= held,
        "the validator's withdrawal took money out"
    );
}

/// A stake goes to the controller, carrying the money and the terms unchanged.
///
/// This test was written the other way round: it asserted that the stake reached the
/// elector, which answered with its unknown-query tag, and that the round was therefore
/// missed in silence. That is what the elector does with a stake from anywhere but a
/// controller, and it is why this contract could not stake at all.
#[test]
fn a_stake_goes_to_the_controller_carrying_the_money_and_the_terms() {
    let mut pooled = launch(20_000 * TOS);
    let election = pooled.election();
    let controller = pooled.controller.clone();

    let result =
        pooled.from(&pooled.validator.clone(), stake_order(1, 1_000 * TOS, election), 2 * TOS);

    let (to, tag, value) = sent(&result).expect("the nominator sent nothing on");
    assert_eq!(tag, RELAY_STAKE, "the nominator did not send a stake to relay");
    assert_eq!(to, controller, "the stake went somewhere that is not the controller");
    assert!(value > u128::from(900 * TOS), "the stake carried {value} rather than the money");

    // And nothing went to the elector, which would refuse it.
    assert!(
        !reply_tags(&result).contains(&NEW_STAKE),
        "the classical stake operation is still being sent"
    );
}

/// Terms that are not the shape of a stake are refused, and nothing is sent.
///
/// This contract reads neither the key nor the signature -- the controller compares the
/// key and the elector verifies the signature -- but it does check that what it is
/// forwarding has a stake's shape. Without that it would relay anything an operator
/// typed, and the refusal would arrive two contracts later.
#[test]
fn terms_that_are_not_a_stake_are_refused_before_anything_is_sent() {
    let mut pooled = launch(20_000 * TOS);
    let election = pooled.election();

    let mut body = BuilderData::new();
    body.append_u32(NEW_STAKE).expect("operation");
    body.append_u64(1).expect("query id");
    Coins::new(1_000 * TOS).write_to(&mut body).expect("stake amount");
    body.append_u32(election).expect("election");
    body.append_u32(0x10000).expect("max factor");
    // And then it stops: no transport address, no key, no signature.

    let result = pooled.from(
        &pooled.validator.clone(),
        body.into_cell().expect("a truncated order"),
        2 * TOS,
    );
    assert!(sent(&result).is_none(), "a stake with no terms was relayed anyway");
}

/// The retired single-pool Fift tool wrote Validator.fif's Ed25519 layout:
/// a raw 256-bit key before the election terms and one 64-byte signature ref.
/// A syntactically complete classical order must not be relayed as a PQ stake.
#[test]
fn classical_single_nominator_order_is_refused_before_controller_relay() {
    let mut pooled = launch(20_000 * TOS);
    let election = pooled.election();
    let mut body = BuilderData::new();
    body.append_u32(NEW_STAKE).expect("operation");
    body.append_u64(7).expect("query id");
    Coins::new(1_000 * TOS).write_to(&mut body).expect("stake amount");
    body.append_raw(&[0x11; 32], 256).expect("classical public key");
    body.append_u32(election).expect("election");
    body.append_u32(0x10000).expect("max factor");
    body.append_raw(&[0xa5; 32], 256).expect("adnl address");
    let mut signature = BuilderData::new();
    signature.append_raw(&[0x33; 64], 512).expect("Ed25519 signature");
    body.checked_append_reference(signature.into_cell().expect("signature cell"))
        .expect("classical signature reference");

    let result = pooled.from(
        &pooled.validator.clone(),
        body.into_cell().expect("complete classical stake order"),
        2 * TOS,
    );
    let pool_transaction = &result.transactions.first().expect("pool transaction").1;
    assert!(
        pool_transaction.read_description().expect("description").is_aborted(),
        "the PQ pool accepted a classical Ed25519 stake body",
    );
    assert!(
        !reply_tags(&result).contains(&RELAY_STAKE),
        "the PQ pool relayed a classical Ed25519 stake body to the controller",
    );
}

/// Only the validator may spend the owner's money on a stake, and a stake spends only
/// what it was told to.
#[test]
fn a_stake_spends_what_it_was_told_to_and_only_the_validator_may_order_one() {
    let mut pooled = launch(20_000 * TOS);
    let election = pooled.election();
    let before = pooled.balance(&pooled.nominator.clone());

    pooled.from(&pooled.validator.clone(), stake_order(1, 1_000 * TOS, election), 2 * TOS);
    let after = pooled.balance(&pooled.nominator.clone());
    let spent = before - after;
    assert!(spent >= 1_000 * TOS, "the stake sent {spent} rather than the amount ordered");
    assert!(spent < 1_100 * TOS, "the stake sent {spent}, which is more than it was told to");

    // The owner's own wallet cannot order one: that role holds the funds and does not
    // decide when they stand in an election.
    let refused =
        pooled.from(&pooled.owner.clone(), stake_order(2, 1_000 * TOS, election), 2 * TOS);
    assert!(sent(&refused).is_none(), "the owner ordered a stake");
}

/// Recovering a stake still reaches the elector, because that operation was not removed.
/// Only the way in is gone, which is what makes the failure a missed round rather than
/// stranded capital.
#[test]
fn recovering_a_stake_still_reaches_the_elector() {
    let mut pooled = launch(20_000 * TOS);
    let result = pooled.from(&pooled.validator.clone(), simple_order(RECOVER_STAKE, 1), 2 * TOS);
    let tags = reply_tags(&result);
    assert!(tags.contains(&RECOVER_STAKE), "the nominator did not ask the elector for its stake");
    let elector = pooled.elector.clone();
    let (_, answered) = elector_verdict(&result, &elector);
    assert!(
        !answered.contains(&UNKNOWN_QUERY),
        "the elector no longer knows how to return a stake: {answered:02x?}"
    );
}
