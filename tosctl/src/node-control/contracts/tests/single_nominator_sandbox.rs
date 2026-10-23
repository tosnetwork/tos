/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The single-nominator pool, run rather than read.
//!
//! Two roles: a cold owner holds the funds, and a validator wallet may spend them on a
//! stake and on nothing else. The pool forwards the stake terms to the elector unchanged,
//! so the elector sees the pool as the sender: the stake is signed for the pool's address
//! and registered under it, and everything the election owes comes back to the pool.

use chain_block::{
    Account, BuilderData, Cell, Coins, ConfigParams, Deserializable, IBitstring, MsgAddressInt,
    Serializable, ShardStateUnsplit, SliceData, StateInit, TransactionTickTock,
};
use contracts::nominator::{NewStakeParams, new_stake};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib, generate_zerostate_state};

const TOS: u64 = 1_000_000_000;

const NEW_STAKE: u32 = 0x4e73_744b;
const RECOVER_STAKE: u32 = 0x4765_7424;
const WITHDRAW: u32 = 0x1000;
const UNKNOWN_QUERY: u32 = 0xffff_ffff;
const NEW_STAKE_OK: u32 = 0xf374_484c;
const NEW_STAKE_ERROR: u32 = 0xee6f_454c;
/// `return_stake` reason 1: the signature did not verify.
const REASON_BAD_SIGNATURE: u32 = 1;
const ELECTION_CONTEXT: &[u8] = b"TOS-VALIDATOR-ELECTION-v1";

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

fn nominator_code() -> Cell {
    compile_func_with_stdlib(&[
        repo_root().join("crypto/smartcont/single-nominator-pool/single-nominator-code.fc")
    ])
    .expect("the single-nominator contract compiles")
}

/// Its whole storage: who owns the money, and who may stake it.
fn nominator_data(owner: &MsgAddressInt, validator: &MsgAddressInt) -> Cell {
    let mut data = BuilderData::new();
    owner.write_to(&mut data).expect("owner address");
    validator.write_to(&mut data).expect("validator address");
    data.into_cell().expect("nominator data")
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
        let file = dir.join("single-nominator-validator.key");
        run_key_tool(&["keygen", file.to_str().expect("path")]);
        let public_key =
            hex::decode(&run_key_tool(&["public", file.to_str().expect("path")])[0]).expect("hex");
        assert_eq!(public_key.len(), 1312, "an ML-DSA-44 public key");
        ConsensusKey { file, public_key }
    })
}

struct Pooled {
    chain: Blockchain,
    elector: MsgAddressInt,
    nominator: MsgAddressInt,
    owner: MsgAddressInt,
    validator: MsgAddressInt,
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

    let init = StateInit::with_code_and_data(
        nominator_code(),
        nominator_data(&owner_address, &validator_address),
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

    Pooled { chain, elector, nominator, owner: owner_address, validator: validator_address }
}

const ADNL: [u8; 32] = [0xa5; 32];

/// The order the validator wallet gives the pool, from the production Rust builder: the
/// same body the pool's `check_new_stake_msg` parses and forwards unchanged.
///
/// The stake is signed for `signed_for`, which for a stake the elector should take is the
/// pool itself: the pool is the account the elector sees send it.
fn stake_order(
    pooled: &Pooled,
    signed_for: &MsgAddressInt,
    query_id: u64,
    amount: u64,
    election: u32,
) -> Cell {
    let global_id = match pooled.chain.config_params().config(19).expect("parameter 19") {
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
        stake_amount: amount,
        validator_pubkey: &key.public_key,
        stake_at: election,
        max_factor: 0x10000,
        adnl_addr: &ADNL,
        signature: &signature,
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

/// The open election's member registered under an address, as `(stake, key_id)`.
///
/// The record is `stake time max_factor key_id adnl_addr algorithm_id ^public_key`, keyed
/// by the account that sent the stake.
fn member(pooled: &Pooled, address: &MsgAddressInt) -> Option<(u128, [u8; 32])> {
    let data = pooled.chain.get_account(&pooled.elector)?.get_data()?;
    let mut storage = SliceData::load_cell(data).expect("storage");
    let elect = storage.get_next_bit().expect("an election flag");
    if !elect {
        return None;
    }
    let mut election =
        SliceData::load_cell(storage.checked_drain_reference().expect("the election"))
            .expect("the election");
    election.get_next_u32().expect("elect_at");
    election.get_next_u32().expect("elect_close");
    Coins::construct_from(&mut election).expect("min_stake");
    Coins::construct_from(&mut election).expect("total_stake");
    let members = if election.get_next_bit().expect("members presence") {
        Some(election.checked_drain_reference().expect("the members"))
    } else {
        None
    };
    let members = chain_block::HashmapE::with_hashmap(256, members);
    let mut record = members.get(address.address().clone()).expect("lookup")?;
    let stake = Coins::construct_from(&mut record).expect("stake").as_u128();
    record.get_next_u32().expect("time");
    record.get_next_u32().expect("max_factor");
    let key_id = record.get_next_bits(256).expect("key_id").try_into().expect("32 bytes");
    Some((stake, key_id))
}

#[test]
fn the_nominator_deploys_and_reports_its_two_roles() {
    let pooled = launch(20_000 * TOS);
    let result = pooled
        .chain
        .run_get_method(&pooled.nominator, "get_roles", vec![])
        .expect("the nominator answers");
    assert_eq!(result.exit_code, 0, "get_roles failed");
    assert_eq!(result.stack.len(), 2, "a single nominator has exactly two roles");
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

/// A stake goes to the elector carrying the money and the terms unchanged, and the elector
/// registers the pool: the account that sent it, and the one the stake was signed for.
#[test]
fn a_stake_reaches_the_elector_and_registers_the_pool() {
    let mut pooled = launch(20_000 * TOS);
    let election = pooled.election();
    let elector = pooled.elector.clone();
    let nominator = pooled.nominator.clone();

    let order = stake_order(&pooled, &nominator, 1, 11_000 * TOS, election);
    let result = pooled.from(&pooled.validator.clone(), order, 20 * TOS);

    let (to, tag, value) = sent(&result).expect("the nominator sent nothing on");
    assert_eq!(tag, NEW_STAKE, "the nominator did not send a stake");
    assert_eq!(to, elector, "the stake went somewhere that is not the elector");
    assert!(value >= u128::from(11_000 * TOS), "the stake carried {value} rather than the money");

    let (aborted, answered) = elector_verdict(&result, &elector);
    assert!(!aborted, "the elector aborted on the pool's stake");
    assert!(
        answered.contains(&NEW_STAKE_OK),
        "the elector did not take the stake: {answered:02x?}"
    );
    let (stake, key_id) = member(&pooled, &nominator).expect("the pool is not a member");
    assert_eq!(
        key_id,
        chain_block::derive_consensus_key_id(1, &consensus_key().public_key).inner(),
        "the pool is registered with another key"
    );
    assert!(stake >= u128::from(11_000 * TOS - TOS), "the pool is registered with {stake}");
    assert!(
        member(&pooled, &pooled.validator.clone()).is_none(),
        "the wallet that ordered the stake became a member"
    );
}

/// A stake signed for an account other than the pool authorises nothing: the elector
/// rebuilds the signed bytes with the pool's address, refuses the stake, and the money
/// goes back to the pool.
#[test]
fn a_stake_signed_for_another_account_comes_back_to_the_pool() {
    let mut pooled = launch(20_000 * TOS);
    let election = pooled.election();
    let elector = pooled.elector.clone();
    let nominator = pooled.nominator.clone();
    let before = pooled.balance(&nominator);

    let order = stake_order(&pooled, &pooled.validator.clone(), 1, 11_000 * TOS, election);
    let result = pooled.from(&pooled.validator.clone(), order, 20 * TOS);

    let (aborted, answered) = elector_verdict(&result, &elector);
    assert!(!aborted, "the elector aborted rather than refusing");
    assert!(answered.contains(&NEW_STAKE_ERROR), "the elector took the stake: {answered:02x?}");
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
    assert_eq!(reason, Some(REASON_BAD_SIGNATURE), "refused for another reason");
    assert!(member(&pooled, &nominator).is_none(), "the refused stake registered the pool");
    assert!(
        pooled.balance(&nominator) + TOS > before,
        "the refused stake did not come back to the pool"
    );
}

/// Terms that are not the shape of a stake are refused, and nothing is sent.
///
/// This contract reads neither the key nor the signature -- the elector verifies the
/// signature -- but it does check that what it is forwarding has a stake's shape. Without
/// that it would forward anything an operator typed, and the refusal would arrive from
/// the elector instead.
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
        20 * TOS,
    );
    assert!(sent(&result).is_none(), "a stake with no terms was forwarded anyway");
}

/// The retired single-pool Fift tool wrote Validator.fif's Ed25519 layout:
/// a raw 256-bit key before the election terms and one 64-byte signature ref.
/// A syntactically complete classical order must not be forwarded as a PQ stake.
#[test]
fn classical_single_nominator_order_is_refused_before_it_reaches_the_elector() {
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
        20 * TOS,
    );
    let pool_transaction = &result.transactions.first().expect("pool transaction").1;
    assert!(
        pool_transaction.read_description().expect("description").is_aborted(),
        "the PQ pool accepted a classical Ed25519 stake body",
    );
    assert!(
        !reply_tags(&result).contains(&NEW_STAKE),
        "the PQ pool forwarded a classical Ed25519 stake body to the elector",
    );
}

/// Only the validator may spend the owner's money on a stake, and a stake spends only
/// what it was told to.
#[test]
fn a_stake_spends_what_it_was_told_to_and_only_the_validator_may_order_one() {
    let mut pooled = launch(20_000 * TOS);
    let election = pooled.election();
    let nominator = pooled.nominator.clone();
    let before = pooled.balance(&nominator);

    let order = stake_order(&pooled, &nominator, 1, 11_000 * TOS, election);
    let result = pooled.from(&pooled.validator.clone(), order, 20 * TOS);
    assert!(
        elector_verdict(&result, &pooled.elector.clone()).1.contains(&NEW_STAKE_OK),
        "the fixture needs a stake the elector keeps"
    );
    // What left is the stake; what came back is the elector's one-TOS confirmation.
    let spent = before - pooled.balance(&nominator);
    assert!(spent >= 10_980 * TOS, "the stake sent {spent} rather than the amount ordered");
    assert!(spent < 11_100 * TOS, "the stake sent {spent}, which is more than it was told to");

    // The owner's own wallet cannot order one: that role holds the funds and does not
    // decide when they stand in an election.
    let order = stake_order(&pooled, &nominator, 2, 1_000 * TOS, election);
    let refused = pooled.from(&pooled.owner.clone(), order, 20 * TOS);
    assert!(sent(&refused).is_none(), "the owner ordered a stake");
}

/// Recovering a stake reaches the elector, which knows the operation and answers it.
#[test]
fn recovering_a_stake_still_reaches_the_elector() {
    let mut pooled = launch(20_000 * TOS);
    let result = pooled.from(&pooled.validator.clone(), simple_order(RECOVER_STAKE, 1), 20 * TOS);
    let tags = reply_tags(&result);
    assert!(tags.contains(&RECOVER_STAKE), "the nominator did not ask the elector for its stake");
    let elector = pooled.elector.clone();
    let (_, answered) = elector_verdict(&result, &elector);
    assert!(
        !answered.contains(&UNKNOWN_QUERY),
        "the elector no longer knows how to return a stake: {answered:02x?}"
    );
}
