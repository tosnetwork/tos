/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The nominator pool, run rather than read.
//!
//! The pool forwards its validator's stake terms to the elector unchanged, so the elector
//! sees the pool as the sender: the stake is signed for the pool's address and registered
//! under it. The pool tracks the stake through the elector's answer -- out while it waits,
//! staked once accepted, idle again once refused -- so these tests follow the whole round
//! trip against the real elector.

use chain_block::{
    Account, BuilderData, Cell, Coins, ConfigParams, IBitstring, MsgAddressInt, Serializable,
    ShardStateUnsplit, StateInit, TransactionTickTock,
};
use contracts::nominator::{NewStakeParams, new_stake};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func, generate_zerostate_state};

const TOS: u64 = 1_000_000_000;

/// The pool's own operation for "send a stake to the elector", which is also the operation
/// it forwards.
const NEW_STAKE: u32 = 0x4e73_744b;
/// The only refusal the pool understands.
const NEW_STAKE_ERROR: u32 = 0xee6f_454c;
/// The elector's acceptance.
const NEW_STAKE_OK: u32 = 0xf374_484c;
/// `return_stake` reason 1: the signature did not verify.
const REASON_BAD_SIGNATURE: u32 = 1;
const ELECTION_CONTEXT: &[u8] = b"TOS-VALIDATOR-ELECTION-v1";
const ADNL: [u8; 32] = [0xa5; 32];

/// `new_stake` from somebody who is not the configured validator.
const ERROR_NOT_THE_VALIDATOR: i32 = 78;
/// `new_stake` while a stake is already out.
const ERROR_NOT_IDLE: i32 = 79;

fn repo_root() -> std::path::PathBuf {
    std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root above the contracts crate")
            .to_path_buf()
    })
}

/// The zerostate is generated rather than fixtured, so the elector and the configuration
/// these tests run against are the ones the chain would launch with.
fn zerostate() -> ShardStateUnsplit {
    generate_zerostate_state(
        repo_root().join("test/tostester/tests/tostester/genesis-with-test-auth.fif"),
    )
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

/// The pool carries its own stdlib, so it is compiled with that one rather than with the
/// tree's: a contract compiled against different definitions is a different contract.
fn pool_code() -> Cell {
    let dir = repo_root().join("crypto/smartcont/nominator-pool");
    compile_func(&[dir.join("stdlib.fc"), dir.join("pool.fc")]).expect("the pool compiles")
}

/// The ML-DSA-44 key tool from `crypto/pq/tools`, which is how a test signs: signing is
/// deliberately absent from the node's libraries.
fn key_tool() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("PQ_KEY_TOOL") {
        return std::path::PathBuf::from(path);
    }
    for candidate in ["build-pq-key/tos-pq-key", "build/tos-pq-key"] {
        let path = repo_root().join(candidate);
        if path.exists() {
            return path;
        }
    }
    panic!(
        "the ML-DSA-44 key tool is needed: build it with `cmake -S crypto/pq/tools -B \
         build-pq-key && cmake --build build-pq-key`, or point PQ_KEY_TOOL at it"
    );
}

fn run_key_tool(args: &[&str]) -> Vec<String> {
    let out =
        std::process::Command::new(key_tool()).args(args).output().expect("the key tool runs");
    assert!(out.status.success(), "the key tool failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).lines().map(|line| line.trim().to_string()).collect()
}

/// A consensus key of the pool's validator, generated once per process.
struct ConsensusKey {
    file: std::path::PathBuf,
    public_key: Vec<u8>,
}

fn consensus_key() -> &'static ConsensusKey {
    static KEY: std::sync::OnceLock<ConsensusKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let dir = tempfile::tempdir().expect("a scratch directory").keep();
        let file = dir.join("nominator-pool-validator.key");
        run_key_tool(&["keygen", file.to_str().expect("path")]);
        let public_key =
            hex::decode(&run_key_tool(&["public", file.to_str().expect("path")])[0]).expect("hex");
        assert_eq!(public_key.len(), 1312, "an ML-DSA-44 public key");
        ConsensusKey { file, public_key }
    })
}

/// `state = 0`, no nominators, no withdrawals: a pool that has been funded by its
/// validator and has never staked.
fn pool_data(validator: &chain_block::AccountId, validator_amount: u64) -> Cell {
    let mut config = BuilderData::new();
    config.append_raw(&validator.get_bytestring(0), 256).expect("validator address");
    config.append_u16(4_000).expect("reward share");
    config.append_u16(40).expect("max nominators");
    Coins::new(200 * TOS).write_to(&mut config).expect("min validator stake");
    Coins::new(10 * TOS).write_to(&mut config).expect("min nominator stake");

    let mut data = BuilderData::new();
    data.append_u8(0).expect("state");
    data.append_u16(0).expect("nominators count");
    Coins::new(0).write_to(&mut data).expect("stake amount sent");
    Coins::new(validator_amount).write_to(&mut data).expect("validator amount");
    data.checked_append_reference(config.into_cell().expect("config cell")).expect("config");
    data.append_bit_zero().expect("no nominators");
    data.append_bit_zero().expect("no withdraw requests");
    data.append_u32(0).expect("stake at");
    data.append_raw(&[0u8; 32], 256).expect("saved validator set hash");
    data.append_u8(0).expect("validator set changes count");
    data.append_u32(0).expect("validator set change time");
    data.append_u32(0).expect("stake held for");
    data.append_bit_zero().expect("no config proposal votings");
    data.into_cell().expect("pool data")
}

struct Pooled {
    chain: Blockchain,
    elector: MsgAddressInt,
    pool: MsgAddressInt,
    validator: MsgAddressInt,
}

/// A funded pool on a chain carrying the real elector, with an election open.
fn launch(validator_amount: u64, pool_balance: u64) -> Pooled {
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

    // An open election, reached the way the chain reaches it.
    chain.set_now(current.utime_until() - params.elections_start_before);
    chain.tick_tock(&elector, TransactionTickTock::Tick).expect("tick runs").expect_success();

    // The validator's own masterchain wallet, which is what the pool takes orders from.
    let validator = chain.treasury("pool-validator", 100_000 * TOS).expect("the validator wallet");

    let init = StateInit::with_code_and_data(
        pool_code(),
        pool_data(&validator.address().address(), validator_amount),
    );
    let pool = MsgAddressInt::with_params(
        -1,
        init.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("pool address");
    // Placed rather than deployed by message. The pool's entry point reads an operation
    // from the body before it does anything else, so it has no empty-body deploy path,
    // and driving one through some other operation would start these tests from a state
    // no operator would deploy into.
    let deployment = MessageBuilder::internal(validator.address(), &pool, pool_balance)
        .bounce(false)
        .state_init(init)
        .body(Cell::default())
        .build();
    chain.set_account(
        pool.clone(),
        Account::from_message(&deployment).expect("an account from the deployment"),
    );

    Pooled { chain, elector, pool, validator: validator.address().clone() }
}

/// The order an operator gives the pool: stake this much, on these terms, signed for
/// `signed_for` -- the pool itself, for a stake the elector should take.
///
/// Use the production builder for the exact PQ body the multi-nominator pool's
/// `check_new_stake_msg` parses and forwards unchanged. The deliberately truncated
/// negative order below remains hand-built so it can be malformed.
fn stake_order(
    chain: &Blockchain,
    signed_for: &MsgAddressInt,
    query_id: u64,
    value: u64,
    election: u32,
) -> Cell {
    let global_id = match chain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("the chain states no network id, so nothing can sign for it"),
    };
    let src_addr = chain_block::UInt256::from_slice(&signed_for.address().get_bytestring(0));
    let preimage = chain_block::pq_elector::stake_preimage(
        global_id,
        election,
        0x10000,
        &src_addr,
        &chain_block::UInt256::from(ADNL),
    );
    let key = consensus_key();
    let signature = hex::decode(
        &run_key_tool(&[
            "sign",
            key.file.to_str().expect("path"),
            &hex::encode(preimage),
            &hex::encode(ELECTION_CONTEXT),
        ])[0],
    )
    .expect("hex");
    new_stake(&NewStakeParams {
        query_id,
        stake_amount: value,
        validator_pubkey: &key.public_key,
        stake_at: election,
        max_factor: 0x10000,
        adnl_addr: &ADNL,
        signature: &signature,
    })
    .expect("production PQ stake order for multi-nominator pool")
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

    /// The pool's own view of itself. Only the fields these tests judge.
    fn state(&self) -> (u8, u128) {
        let result = self
            .chain
            .run_get_method(&self.pool, "get_pool_data", vec![])
            .expect("the pool answers");
        assert_eq!(result.exit_code, 0, "get_pool_data failed");
        let state = result.stack[0].as_integer().expect("state").to_string().parse().expect("u8");
        let sent = result.stack[2]
            .as_integer()
            .expect("stake amount sent")
            .to_string()
            .parse()
            .expect("u128");
        (state, sent)
    }

    /// Order a stake signed for the pool, or for `signed_for` when it is given.
    fn order_signed_for(
        &mut self,
        signed_for: &MsgAddressInt,
        query_id: u64,
        value: u64,
        election: u32,
    ) -> tos_sandbox::SendResult {
        let order = stake_order(&self.chain, signed_for, query_id, value, election);
        self.chain
            .send_message(
                MessageBuilder::internal(&self.validator, &self.pool, 20 * TOS).body(order).build(),
            )
            .expect("the order is delivered")
    }

    fn order(&mut self, query_id: u64, value: u64, election: u32) -> tos_sandbox::SendResult {
        let order = stake_order(&self.chain, &self.pool, query_id, value, election);
        self.chain
            .send_message(
                MessageBuilder::internal(&self.validator, &self.pool, 20 * TOS).body(order).build(),
            )
            .expect("the order is delivered")
    }
}

/// Where the first message the pool sent went, what it asked for, and what it carried.
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
fn the_pool_deploys_idle_and_reports_what_it_was_configured_with() {
    let pooled = launch(10_000 * TOS, 30_000 * TOS);
    let (state, sent) = pooled.state();
    assert_eq!(state, 0, "a fresh pool is not idle");
    assert_eq!(sent, 0, "a fresh pool has a stake out");
    assert_ne!(pooled.election(), 0, "the fixture needs an open election");
}

/// The harness drives the real contract: an order from anybody else is refused by the
/// rule that says only the validator commands this pool. Without this the tests below
/// could be passing against a contract that never ran.
#[test]
fn only_the_configured_validator_can_order_a_stake() {
    let mut pooled = launch(10_000 * TOS, 30_000 * TOS);
    let election = pooled.election();
    let stranger = pooled.chain.treasury("stranger", 10_000 * TOS).expect("another wallet");
    let order = stake_order(&pooled.chain, &pooled.pool, 1, 11_000 * TOS, election);
    pooled
        .chain
        .send_message(
            MessageBuilder::internal(stranger.address(), &pooled.pool, 20 * TOS)
                .body(order)
                .build(),
        )
        .expect("delivered")
        .expect_exit_code(ERROR_NOT_THE_VALIDATOR);
    assert_eq!(pooled.state().0, 0, "a refused order moved the pool anyway");
}

/// The pool's stake reaches the elector, which takes it from the pool, and the pool
/// records the stake as placed and will not place another until this one is done.
#[test]
fn a_pools_stake_reaches_the_elector_and_the_pool_records_it() {
    let mut pooled = launch(10_000 * TOS, 30_000 * TOS);
    let election = pooled.election();
    let staked = 11_000 * TOS;
    let elector = pooled.elector.clone();

    let result = pooled.order(1, staked, election);

    let (to, tag, value) = sent(&result).expect("the pool sent nothing on");
    assert_eq!(tag, NEW_STAKE, "the pool did not send a stake");
    assert_eq!(to, elector, "the stake went somewhere that is not the elector");
    assert_eq!(value, u128::from(staked), "the stake carried {value} rather than the money");
    let (aborted, answered) = elector_verdict(&result, &elector);
    assert!(!aborted, "the elector aborted on the pool's stake");
    assert!(
        answered.contains(&NEW_STAKE_OK),
        "the elector did not take the stake: {answered:02x?}"
    );

    // Accepted, the pool records it as placed, at the amount the elector keeps.
    let (state, sent_amount) = pooled.state();
    assert_eq!(state, 2, "the pool did not record the stake the elector accepted");
    assert_eq!(sent_amount, u128::from(staked - TOS), "the pool recorded the wrong amount");

    let again = stake_order(&pooled.chain, &pooled.pool, 2, staked, election);
    pooled
        .chain
        .send_message(
            MessageBuilder::internal(&pooled.validator, &pooled.pool, 20 * TOS).body(again).build(),
        )
        .expect("delivered")
        .expect_exit_code(ERROR_NOT_IDLE);
}

/// A stake the elector refuses comes back, and the pool stops waiting for it.
///
/// Signed for an account other than the pool, the stake is refused for its signature and
/// the money returned. The pool has to recognise that answer, or it sits believing a
/// stake is out and refuses every later order until the validator set has changed three
/// times.
#[test]
fn a_refused_stake_lets_the_pool_try_again() {
    let mut pooled = launch(10_000 * TOS, 30_000 * TOS);
    let election = pooled.election();
    let elector = pooled.elector.clone();
    let validator = pooled.validator.clone();

    let result = pooled.order_signed_for(&validator, 1, 11_000 * TOS, election);
    let mut reason = None;
    for transaction in result.transactions_for(&elector) {
        transaction
            .iterate_out_msgs(|message| {
                let mut body = message.body().expect("a reply").clone();
                if body.get_next_u32().ok() == Some(NEW_STAKE_ERROR) {
                    body.get_next_u64().expect("query id");
                    reason = body.get_next_u32().ok();
                }
                Ok(true)
            })
            .expect("out messages");
    }
    assert_eq!(reason, Some(REASON_BAD_SIGNATURE), "the elector did not refuse the stake");
    assert_eq!(pooled.state().0, 0, "the pool is still waiting for a stake that came back");

    // And it will take another order, which the elector accepts.
    let again = pooled.order(2, 11_000 * TOS, election);
    assert!(sent(&again).is_some(), "the pool would not place another stake");
    assert_eq!(pooled.state().0, 2, "the second stake was not recorded as placed");
}

/// Terms that are not the shape of a stake are refused, and nothing is sent.
#[test]
fn terms_that_are_not_a_stake_are_refused_before_anything_is_sent() {
    let mut pooled = launch(10_000 * TOS, 30_000 * TOS);
    let election = pooled.election();

    let mut body = BuilderData::new();
    body.append_u32(NEW_STAKE).expect("operation");
    body.append_u64(1).expect("query id");
    Coins::new(1_000 * TOS).write_to(&mut body).expect("value");
    body.append_u32(election).expect("election");
    body.append_u32(0x10000).expect("max factor");
    // And then it stops.

    let result = pooled
        .chain
        .send_message(
            MessageBuilder::internal(&pooled.validator, &pooled.pool, 20 * TOS)
                .body(body.into_cell().expect("a truncated order"))
                .build(),
        )
        .expect("delivered");
    assert!(sent(&result).is_none(), "a stake with no terms was forwarded anyway");
    assert_eq!(pooled.state().0, 0, "a refused order moved the pool anyway");
}

/// A stake spends what it was told to spend, and no more: the pool forwards exactly the
/// principal it was ordered to, and pays the forwarding fee separately.
#[test]
fn a_stake_spends_the_amount_it_was_ordered_to() {
    let mut pooled = launch(10_000 * TOS, 30_000 * TOS);
    let election = pooled.election();
    let pool = pooled.pool.clone();

    let result = pooled.order(1, 11_000 * TOS, election);
    let (_, transaction) = result.transactions.first().expect("the pool's transaction");
    let mut forwarded = Vec::new();
    transaction
        .iterate_out_msgs(|message| {
            forwarded.push(message.get_value().expect("a value").coins.as_u128());
            Ok(true)
        })
        .expect("out messages");
    assert_eq!(forwarded, vec![u128::from(11_000 * TOS)], "the pool forwarded something else");
    assert_eq!(result.transactions[0].0, pool, "the first transaction is not the pool's");
}
