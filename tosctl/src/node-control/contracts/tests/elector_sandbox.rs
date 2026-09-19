/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Behavioural coverage for the elector, which had none.
//!
//! Until now the elector was covered by a compile-and-compare-the-hash check and by Fift
//! assertions on the bytes of the messages sent to it. Nothing executed it, so every claim
//! about what it does with a stake, an election or a validator set was a claim about code
//! nobody had run. The post-quantum work changes the elector's storage, its authorisation
//! and the descriptors it emits, and none of that can be proved against a contract with no
//! behavioural baseline.
//!
//! These tests run the real contract, from the real zerostate, under the real transaction
//! executor. The elector's state machine advances on tick transactions rather than on
//! messages, so it is driven the way the chain drives it.

use chain_block::{Account, ConfigParams, MsgAddressInt, ShardStateUnsplit, TransactionTickTock};
use tos_sandbox::{Blockchain, generate_zerostate_state};

/// The zerostate is generated rather than fixtured, so these tests run against the
/// contracts and the configuration the chain would actually launch with.
fn zerostate() -> ShardStateUnsplit {
    let root = std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root above the contracts crate")
            .to_path_buf()
    });
    generate_zerostate_state(root.join("crypto/smartcont/gen-zerostate.fif"))
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

struct Chain {
    blockchain: Blockchain,
    elector: MsgAddressInt,
    config_contract: MsgAddressInt,
    validators_until: u32,
    elect_begin_before: u32,
    elect_end_before: u32,
}

/// The two system contracts, loaded from the zerostate into a chain that carries the same
/// configuration they were deployed with.
fn launch() -> Chain {
    let state = zerostate();
    let config = configuration(&state);
    let elector = masterchain(config.elector_address().expect("elector address"));
    let config_contract = masterchain(config.config_address().expect("configuration address"));
    let current = config.validator_set().expect("the zerostate elects a validator set");
    let params = config.elector_params().expect("elector parameters");

    let elector_account = account(&state, &elector);
    let config_account = account(&state, &config_contract);

    let mut blockchain = Blockchain::with_config(config).expect("sandbox with the real config");
    blockchain.set_workchain(-1);
    blockchain.set_account(elector.clone(), elector_account);
    blockchain.set_account(config_contract.clone(), config_account);

    Chain {
        blockchain,
        elector,
        config_contract,
        validators_until: current.utime_until(),
        elect_begin_before: params.elections_start_before,
        elect_end_before: params.elections_end_before,
    }
}

fn active_election_id(chain: &Chain) -> i64 {
    let result = chain
        .blockchain
        .run_get_method(&chain.elector, "active_election_id", vec![])
        .expect("the elector answers its own get-method");
    assert_eq!(result.exit_code, 0, "active_election_id failed: {}", result.exit_code);
    result
        .stack
        .last()
        .expect("a return value")
        .as_integer()
        .expect("an integer")
        .to_string()
        .parse::<i64>()
        .expect("an election id")
}

#[test]
fn the_zerostate_starts_with_no_election_open() {
    let chain = launch();
    assert_eq!(active_election_id(&chain), 0, "genesis must not have an election already open");
    assert!(chain.blockchain.get_account(&chain.config_contract).is_some());
}

#[test]
fn a_tick_before_the_window_does_not_open_an_election() {
    let mut chain = launch();
    // One second before the window: the contract reads the clock, not the tick.
    let before = chain.validators_until - chain.elect_begin_before - 1;
    chain.blockchain.set_now(before);
    // The tick has to have run the contract. Without this, a tick the executor refused
    // would look exactly like a contract that correctly declined to open an election.
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success()
        .expect_exit_code(0);
    assert_eq!(
        active_election_id(&chain),
        0,
        "an election opened before the window the configuration defines"
    );
}

#[test]
fn a_tick_inside_the_window_opens_an_election() {
    let mut chain = launch();
    let opens = chain.validators_until - chain.elect_begin_before;
    chain.blockchain.set_now(opens);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success()
        .expect_exit_code(0);
    let election = active_election_id(&chain);
    assert_ne!(election, 0, "the window opened and no election did");
    assert_eq!(
        election as u32, chain.validators_until,
        "an election is identified by when the set it elects takes over"
    );
}

// ---------------------------------------------------------------------------
// Staking
//
// A stake is an internal message carrying a signature over fields the contract
// rebuilds for itself, including the sender's address. The signature is what makes a
// registration belong to a key; the sender's address in the preimage is what stops the
// same signed request being replayed from somewhere else.
// ---------------------------------------------------------------------------

/// The elector's own tags, so a reply is read rather than guessed at.
const STAKE_ACCEPTED: u32 = 0xf374484c;
const STAKE_RETURNED: u32 = 0xee6f454c;
const NEW_STAKE: u32 = 0x4e73744b;
/// `return_stake` reason 1: the signature did not verify.
const REASON_BAD_SIGNATURE: u32 = 1;
const REASON_WRONG_ELECTION: u32 = 3;
const ELECT_REQUEST: u32 = 0x654c5074;

const TOS: u64 = 1_000_000_000;

/// The tag and reason of the first reply the elector sent back. A refusal carries the
/// reason it refused for, and a test that only read the tag would report every refusal as
/// the one it was looking for.
fn reply(result: &tos_sandbox::SendResult) -> (u32, u32) {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    let mut answer = None;
    transaction
        .iterate_out_msgs(|message| {
            if answer.is_none() {
                if let Some(body) = message.body() {
                    let mut body = body.clone();
                    let tag = body.get_next_u32().expect("a reply tag");
                    let _query = body.get_next_u64().expect("a query id");
                    answer = Some((tag, body.get_next_u32().unwrap_or(0)));
                }
            }
            Ok(true)
        })
        .expect("out messages");
    answer.expect("the elector always answers a stake")
}

/// An open election, plus a funded masterchain account to stake from.
fn open_election(name: &str, balance: u64) -> (Chain, tos_sandbox::Treasury, u32) {
    let mut chain = launch();
    let opens = chain.validators_until - chain.elect_begin_before;
    chain.blockchain.set_now(opens);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    let election = active_election_id(&chain) as u32;
    assert_ne!(election, 0, "the fixture needs an open election");
    let treasury = chain.blockchain.treasury(name, balance).expect("a funded sender");
    (chain, treasury, election)
}

/// The running total the open election carries. It decides whether the election has
/// enough stake to close and how small a further stake may be, so it must never exceed
/// what the members actually placed.
fn declared_total_stake(chain: &Chain) -> u128 {
    let result = chain
        .blockchain
        .run_get_method(&chain.elector, "participant_list_extended", vec![])
        .expect("the elector answers");
    assert_eq!(result.exit_code, 0, "participant_list_extended failed");
    assert_eq!(result.stack.len(), 7, "the election summary changed shape");
    result.stack[3].as_integer().expect("an integer").to_string().parse().expect("a running total")
}

/// `return_stake` reason 4: a key already staked from a different address.
const REASON_ANOTHER_ADDRESS: u32 = 4;

// ---------------------------------------------------------------------------
// Closing an election
//
// The elector computes a validator set, sends it to the configuration contract, and
// forgets the election only once it sees that set installed. Three separate things, and
// the third is the one that makes the elector's state depend on authoritative state
// rather than on its own success at sending a message.
// ---------------------------------------------------------------------------

/// The configuration contract's answers to a proposed validator set.
const VALIDATOR_SET_INSTALLED: u32 = 0xee764f4b;
const VALIDATOR_SET_REFUSED: u32 = 0xee764f6f;

/// The configuration a block would be built with, taken from the configuration contract's
/// own storage. Its data is `cfg_dict:^Cell seqno:uint32 public_key:uint256 votes:^Cell`,
/// and the chain's parameters are that first reference.
fn configuration_from_contract(chain: &Chain) -> ConfigParams {
    use chain_block::HashmapE;
    let account = chain
        .blockchain
        .get_account(&chain.config_contract)
        .expect("the configuration contract is deployed");
    let data = account.get_data().expect("the configuration contract has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let parameters = slice.checked_drain_reference().expect("the parameter dictionary");
    ConfigParams {
        config_addr: chain.config_contract.address().clone(),
        config_params: HashmapE::with_hashmap(32, Some(parameters)),
    }
}

fn parameter_present(config: &ConfigParams, index: u32) -> bool {
    config.config_present(index).expect("parameter lookup")
}

/// Everything a reply from either contract carries, by the address that sent it, so a
/// cascade can be read rather than guessed at.
fn replies(result: &tos_sandbox::SendResult) -> Vec<u32> {
    let mut tags = Vec::new();
    for (_, transaction) in &result.transactions {
        transaction
            .iterate_out_msgs(|message| {
                if let Some(body) = message.body() {
                    if let Ok(tag) = body.clone().get_next_u32() {
                        tags.push(tag);
                    }
                }
                Ok(true)
            })
            .expect("out messages");
    }
    tags
}

/// An election with enough validators and enough total stake to succeed: the
/// configuration requires four participants and forty thousand TOS between them.
fn elect_four() -> (Chain, u32, Vec<PqValidator>) {
    let (mut chain, treasury, election) = open_election("validator-set-a", 200_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let mut validators = Vec::new();
    for index in 0..4u8 {
        let validator = PqValidator::new(0x40 + index);
        let account = chain
            .blockchain
            .treasury(&format!("validator-set-{index}"), 40_000 * TOS)
            .expect("a funded account");
        let result =
            pq_stake(&mut chain, &account, &validator, election, 10 + index as u64, 11_000 * TOS);
        assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "validator {index} could not stake");
        validators.push(validator);
    }
    let _ = treasury;
    (chain, election, validators)
}

/// The answer the elector gives a query it does not recognise.
const UNKNOWN_QUERY: u32 = 0xffffffff;

/// A stake in the shape the classical operation took, signed correctly over the terms it
/// used to be checked against. Built here rather than by a shared helper: nothing in the
/// contract reads this encoding any more, and a helper would suggest something still
/// produces it.
fn legacy_stake_body(
    query_id: u64,
    election: u32,
    source: &chain_block::AccountId,
) -> chain_block::Cell {
    use chain_block::IBitstring;
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);
    let adnl = [0xa5u8; 32];
    let max_factor = 0x10000u32;

    let mut preimage = Vec::with_capacity(76);
    preimage.extend_from_slice(&ELECT_REQUEST.to_be_bytes());
    preimage.extend_from_slice(&election.to_be_bytes());
    preimage.extend_from_slice(&max_factor.to_be_bytes());
    preimage.extend_from_slice(&source.get_bytestring(0));
    preimage.extend_from_slice(&adnl);
    let signature: [u8; 64] = ed25519_dalek::Signer::sign(&key, &preimage).to_bytes();

    let mut signature_cell = chain_block::BuilderData::new();
    signature_cell.append_raw(&signature, 512).expect("signature bits");
    let mut body = chain_block::BuilderData::new();
    body.append_u32(NEW_STAKE).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.append_raw(&key.verifying_key().to_bytes(), 256).expect("public key");
    body.append_u32(election).expect("election");
    body.append_u32(max_factor).expect("max factor");
    body.append_raw(&adnl, 256).expect("adnl address");
    body.checked_append_reference(signature_cell.into_cell().expect("signature cell"))
        .expect("signature reference");
    body.into_cell().expect("stake body")
}

/// What the first reply carried back, in nanotomis.
fn returned_value(result: &tos_sandbox::SendResult) -> u128 {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    let mut value = None;
    transaction
        .iterate_out_msgs(|message| {
            if value.is_none() {
                value = message.get_value().map(|v| v.coins.as_u128());
            }
            Ok(true)
        })
        .expect("out messages");
    value.expect("the elector answers, and its answer carries what it did not keep")
}

/// A correctly signed stake in the operation the chain used before validator authority
/// was post-quantum buys nothing: the elector does not know that opcode, so it is
/// answered as an unknown query and the money it carried goes back.
///
/// This is the test that fails if the operation is ever restored. It asserts the absence
/// of an effect and not merely an error, because an error that still registered a member
/// would look the same from the reply alone.
#[test]
fn the_legacy_stake_operation_has_no_authority_and_returns_the_money() {
    let (mut chain, treasury, election) = open_election("legacy-stake-op", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let sent = 11_000 * TOS;

    let result = chain
        .blockchain
        .send_message(treasury.build_message(
            &chain.elector,
            sent,
            true,
            Some(legacy_stake_body(1, election, &treasury.address().address())),
        ))
        .expect("the message is delivered");

    let (tag, _) = reply(&result);
    assert_eq!(tag, UNKNOWN_QUERY, "the elector still recognises the classical stake operation");

    // Nothing was kept: the refusal carries the stake back rather than stranding it.
    let returned = returned_value(&result);
    assert!(
        returned > u128::from(sent) * 9 / 10,
        "a refused legacy stake returned only {returned} of {sent} nanotomis"
    );

    // And nothing was recorded. The election is exactly as it was before the message.
    assert_eq!(
        declared_total_stake(&chain),
        0,
        "a classical stake moved the election's running total"
    );
    let list = chain
        .blockchain
        .run_get_method(&chain.elector, "participant_list", vec![])
        .expect("the elector answers");
    assert_eq!(list.exit_code, 0, "participant_list failed");
    // An empty FunC list is null on the stack; a registered member would make it a pair.
    assert!(
        matches!(list.stack.last().expect("a list"), tos_vm::stack::StackItem::None),
        "a classical stake registered a member"
    );
}

#[test]
fn a_closed_election_sends_its_set_to_the_configuration_contract() {
    let (mut chain, election, validators) = elect_four();
    assert!(!parameter_present(chain.blockchain.config_params(), 36), "nothing is elected yet");

    // The election closes before the set it elects takes over, by the margin the
    // configuration states.
    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    let result =
        chain.blockchain.tick_tock(&chain.elector, TransactionTickTock::Tick).expect("tick runs");
    result.expect_success();

    let tags = replies(&result);
    assert!(
        tags.contains(&VALIDATOR_SET_INSTALLED),
        "the configuration contract did not accept the elected set: {tags:02x?}"
    );
    assert!(!tags.contains(&VALIDATOR_SET_REFUSED), "the configuration contract refused the set");

    let installed = configuration_from_contract(&chain);
    assert!(
        parameter_present(&installed, 36),
        "the configuration contract answered yes without storing the next validator set"
    );
    let next = installed.next_validator_set().expect("the stored set parses");
    assert_eq!(next.list().len(), validators.len(), "every staking validator should be elected");
}

#[test]
fn the_election_is_forgotten_only_once_the_set_is_installed() {
    let (mut chain, election, _validators) = elect_four();
    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();

    // The set is in the configuration contract's storage, but the chain has not adopted
    // it yet, and the elector reads the chain.
    //
    // The tick above conducted the election and stopped there, so it never reached the
    // question this test is about. A second tick does, and it must find the elected set
    // absent from the chain and keep the election. Without this tick the test would pass
    // whatever the elector decides when it does look.
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    assert_ne!(
        active_election_id(&chain),
        0,
        "the elector forgot an election whose set the chain had not adopted"
    );

    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts what the configuration contract installed");
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();

    assert_eq!(
        active_election_id(&chain),
        0,
        "the elector kept an election whose set is installed"
    );
}

// ---------------------------------------------------------------------------
// What the elector keeps, and for how long
// ---------------------------------------------------------------------------

/// `HashmapE n X` is a bit saying whether anything is stored, and a reference to the tree
/// if there is. Read that way rather than through a helper, so the field order below is
/// the contract's storage layout and not an approximation of it.
fn next_dictionary(slice: &mut chain_block::SliceData, bit_len: usize) -> chain_block::HashmapE {
    let present = slice.get_next_bit().expect("the presence bit of a dictionary");
    let root = if present {
        Some(slice.checked_drain_reference().expect("the tree of a non-empty dictionary"))
    } else {
        None
    };
    chain_block::HashmapE::with_hashmap(bit_len, root)
}

/// The elector's storage: `elect credits past_elections tomis active_id active_hash`.
fn past_elections(chain: &Chain) -> chain_block::HashmapE {
    let account = chain.blockchain.get_account(&chain.elector).expect("the elector is deployed");
    let data = account.get_data().expect("the elector has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let _current = next_dictionary(&mut slice, 32);
    let _credits = next_dictionary(&mut slice, 256);
    next_dictionary(&mut slice, 32)
}

#[test]
fn a_finished_election_is_kept_without_any_key_material() {
    let (mut chain, election, validators) = elect_four();
    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts the installed set");
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    assert_eq!(active_election_id(&chain), 0, "the election should be finished by now");

    let past = past_elections(&chain);
    let record = past
        .get(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(election.to_be_bytes().to_vec(), 32)
                    .expect("election key"),
            )
            .expect("key slice"),
        )
        .expect("lookup")
        .unwrap_or_else(|| panic!("no record for the election that just finished"));

    // unfreeze_at:uint32 stake_held:uint32 vset_hash:uint256 frozen:HashmapE total:Tomis
    // bonuses:Tomis complaints:HashmapE
    let mut fields = record;
    let _unfreeze_at = fields.get_next_u32().expect("unfreeze time");
    let _stake_held = fields.get_next_u32().expect("hold time");
    let _vset_hash = fields.get_next_bits(256).expect("the set this election produced");
    let frozen = next_dictionary(&mut fields, 256);

    let mut counted = 0;
    chain_block::HashmapType::iterate_slices(&frozen, |_key, value| {
        // A frozen stake is an address, a weight, an amount and a flag. Nothing here
        // refers to another cell, and a consensus key does not fit in one, so this is
        // what says the elector is not keeping key material after the fact.
        assert_eq!(
            value.remaining_references(),
            0,
            "a frozen stake carries a reference, which is where a key would hide"
        );
        counted += 1;
        Ok(true)
    })
    .expect("frozen stakes");
    assert_eq!(counted, validators.len(), "every elected validator should be frozen");
}

// ---------------------------------------------------------------------------
// Rotation
//
// The configuration contract moves the next set into place on a tock, and keeps the set
// it replaced. Three validator sets exist at once during this, which is the shape any
// sizing of these accounts has to account for.
// ---------------------------------------------------------------------------

/// Elect a set, install it, and let the chain adopt it. Returns the moment the elected
/// set takes over.
fn elect_and_install() -> (Chain, u32) {
    let (mut chain, election, _validators) = elect_four();
    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts the installed set");
    let next =
        chain.blockchain.config_params().next_validator_set().expect("the next set is installed");
    (chain, next.utime_since())
}

#[test]
fn the_next_set_replaces_the_current_one_and_the_current_becomes_the_previous() {
    let (mut chain, takes_over) = elect_and_install();
    let before = chain.blockchain.config_params().clone();
    let replaced = before.validator_set().expect("a current set").utime_since();
    let arriving = before.next_validator_set().expect("a next set").utime_since();
    assert_ne!(replaced, arriving, "the fixture needs two distinguishable sets");

    // Before the moment it takes over, a tock must leave the sets alone.
    chain.blockchain.set_now(takes_over - 1);
    chain
        .blockchain
        .tick_tock(&chain.config_contract, TransactionTickTock::Tock)
        .expect("tock runs")
        .expect_success();
    let early = configuration_from_contract(&chain);
    assert!(parameter_present(&early, 36), "the next set was consumed before its time");
    assert_eq!(
        early.validator_set().expect("a current set").utime_since(),
        replaced,
        "the current set changed before the next one was due"
    );

    chain.blockchain.set_now(takes_over);
    chain
        .blockchain
        .tick_tock(&chain.config_contract, TransactionTickTock::Tock)
        .expect("tock runs")
        .expect_success();

    let after = configuration_from_contract(&chain);
    assert!(!parameter_present(&after, 36), "the next set is still there after taking over");
    assert_eq!(
        after.validator_set().expect("a current set").utime_since(),
        arriving,
        "the elected set did not become the current one"
    );
    assert_eq!(
        after.prev_validator_set().expect("a previous set").utime_since(),
        replaced,
        "the set that was replaced was not kept as the previous one"
    );
}

// ---------------------------------------------------------------------------
// Configuration votes
//
// A validator votes by signing, and the configuration contract verifies that signature
// against the descriptor at the index the vote names. The elected set from the tests
// above is what makes this testable: these are keys this test holds.
// ---------------------------------------------------------------------------

const NEW_PROPOSAL: u32 = 0x6e565052;
const PROPOSAL_ACCEPTED: u32 = 0xee565052;
/// The operation and the signed-domain tag of a post-quantum configuration vote.
const PQ_CONFIG_VOTE_OP: u32 = 0x5051766f;
const PQ_CONFIG_VOTE_SIGN_TAG: u32 = 0x5051564f;
/// `send_confirmation(.., res + 0xd6745240)` with status 2: the vote was registered.
const VOTE_REGISTERED: u32 = 0xd6745240 + 2;
/// `throw_unless(34, pq_check_mldsa44(..))`.
const ERROR_BAD_VOTE_SIGNATURE: i32 = 34;
/// `throw_unless(47, msg_value >= pq::verification_value(-1))`.
const ERROR_VOTE_UNDERFUNDED: i32 = 47;
/// What a vote must carry to pay for the verification it asks for, with room to spare.
const VOTE_VALUE: u64 = 10 * TOS;

/// A set elected by this test, rotated into place, so the current validators are keys the
/// test holds and can sign with.
fn elect_install_and_rotate() -> (Chain, Vec<PqValidator>, u32) {
    let (mut chain, election, validators) = elect_four();
    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts the installed set");
    let takes_over = chain
        .blockchain
        .config_params()
        .next_validator_set()
        .expect("the next set is installed")
        .utime_since();
    chain.blockchain.set_now(takes_over);
    chain
        .blockchain
        .tick_tock(&chain.config_contract, TransactionTickTock::Tock)
        .expect("tock runs")
        .expect_success();
    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts the rotated set");
    (chain, validators, election)
}

/// `cfg_proposal#f3 param_id:int32 param_value:(Maybe ^Cell) if_hash_equal:(Maybe uint256)`
fn proposal_cell(param_id: i32, value: chain_block::Cell) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut proposal = chain_block::BuilderData::new();
    proposal.append_u8(0xf3).expect("tag");
    proposal.append_i32(param_id).expect("parameter");
    proposal.append_bit_one().expect("a value is present");
    proposal.checked_append_reference(value).expect("value");
    proposal.append_bit_zero().expect("no expected current value");
    proposal.into_cell().expect("proposal")
}

/// The cell a configuration parameter holds, as the contract stores it.
fn raw_parameter(chain: &Chain, index: i32) -> Option<chain_block::Cell> {
    use chain_block::IBitstring;
    let mut key = chain_block::BuilderData::new();
    key.append_i32(index).expect("the parameter index");
    configuration_from_contract(chain)
        .config_params
        .get(chain_block::SliceData::load_builder(key).expect("a key slice"))
        .expect("lookup")
        .and_then(|slice| slice.reference_opt(0))
}

/// Whether a parameter is one the configuration marks critical. A proposal for one has
/// to say so, and the contract refuses it outright if it does not, so the fixture asks
/// the chain rather than carrying its own list.
fn is_critical(chain: &Chain, param_id: i32) -> bool {
    use chain_block::IBitstring;
    let mut key = chain_block::BuilderData::new();
    key.append_i32(10).expect("the parameter index");
    let critical = chain
        .blockchain
        .config_params()
        .config_params
        .get(chain_block::SliceData::load_builder(key).expect("a key slice"))
        .expect("lookup");
    let root = match critical {
        Some(slice) => slice.reference(0).expect("the list is stored behind a reference"),
        None => return false,
    };
    let dict = chain_block::HashmapE::with_hashmap(32, Some(root));
    let mut wanted = chain_block::BuilderData::new();
    wanted.append_i32(param_id).expect("the parameter");
    dict.get(chain_block::SliceData::load_builder(wanted).expect("a key slice"))
        .expect("lookup")
        .is_some()
}

/// The index of a validator in the current set, found by the consensus key it holds,
/// because a vote names an index and the contract reads the descriptor stored at it.
fn index_of(chain: &Chain, validator: &PqValidator) -> u16 {
    let wanted = validator.key_id();
    let set = chain.blockchain.config_params().validator_set().expect("a current set");
    for (index, descriptor) in set.list().iter().enumerate() {
        if descriptor.consensus_key_id().expect("a key identity") == wanted {
            return index as u16;
        }
    }
    panic!("the validator is not in the current set");
}

/// The stable identity the set records at an index. The contract reads it from the same
/// place, so a test that built it from the sender instead would still pass if the
/// contract started trusting the message.
fn validator_id_at(chain: &Chain, idx: u16) -> [u8; 32] {
    let set = chain.blockchain.config_params().validator_set().expect("a current set");
    let descriptor = set.list().get(idx as usize).expect("a descriptor at that index");
    descriptor.validator_id().expect("a validator identity").as_slice()[..32]
        .try_into()
        .expect("an identity is 32 bytes")
}

/// The hash of the current validator set, which every vote signs over so that a
/// signature cannot be replayed once the set has changed.
fn current_set_id(chain: &Chain) -> [u8; 32] {
    use chain_block::{GetRepresentationHash, IBitstring};
    let mut key = chain_block::BuilderData::new();
    key.append_u32(34).expect("the parameter index");
    let stored = chain
        .blockchain
        .config_params()
        .config_params
        .get(chain_block::SliceData::load_builder(key).expect("a key slice"))
        .expect("lookup")
        .expect("the chain has a current validator set");
    let cell = stored.reference(0).expect("the parameter value is stored behind a reference");
    cell.hash(0).as_slice()[..32].try_into().expect("a hash is 32 bytes")
}

fn vote_body(
    query_id: u64,
    signature: &[u8],
    idx: u16,
    proposal_hash: &[u8; 32],
) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut body = chain_block::BuilderData::new();
    body.append_u32(PQ_CONFIG_VOTE_OP).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.append_u16(idx).expect("index");
    body.append_raw(proposal_hash, 256).expect("proposal");
    body.checked_append_reference(stored_bytes(signature)).expect("signature");
    body.into_cell().expect("vote body")
}

/// Exactly the bytes the contract verifies. Built here from the set rather than from the
/// sender, because the contract reads the validator identity from the set too: a
/// preimage assembled from what the message claims would agree with a contract that had
/// stopped checking.
fn vote_preimage(chain: &Chain, idx: u16, proposal_hash: &[u8; 32]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(106);
    preimage.extend_from_slice(&PQ_CONFIG_VOTE_SIGN_TAG.to_be_bytes());
    preimage.extend_from_slice(&global_id(chain).to_be_bytes());
    preimage.extend_from_slice(&current_set_id(chain));
    preimage.extend_from_slice(&validator_id_at(chain, idx));
    preimage.extend_from_slice(&idx.to_be_bytes());
    preimage.extend_from_slice(proposal_hash);
    assert_eq!(preimage.len(), 106, "the signed preimage changed shape");
    preimage
}

/// The network identity every signature is bound to.
fn global_id(chain: &Chain) -> i32 {
    match chain.blockchain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("the chain states no network id, so nothing can sign for it"),
    }
}

/// Register a proposal and return its hash, which is how every vote refers to it.
fn propose(chain: &mut Chain, param_id: i32, value: u32) -> [u8; 32] {
    propose_cell(chain, param_id, proposal_value(value), 1)
}

/// The payload `propose` wraps, so a caller with a whole parameter value can use the
/// same path.
fn proposal_value(value: u32) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut payload = chain_block::BuilderData::new();
    payload.append_u32(value).expect("proposed value");
    payload.into_cell().expect("value cell")
}

/// Register a proposal carrying an arbitrary parameter value.
fn propose_cell(
    chain: &mut Chain,
    param_id: i32,
    value: chain_block::Cell,
    query_id: u64,
) -> [u8; 32] {
    use chain_block::{GetRepresentationHash, IBitstring};
    let proposal = proposal_cell(param_id, value);
    let hash: [u8; 32] =
        proposal.hash(0).as_slice()[..32].try_into().expect("a proposal hash is 32 bytes");

    let mut body = chain_block::BuilderData::new();
    body.append_u32(NEW_PROPOSAL).expect("operation");
    body.append_u64(query_id).expect("query id");
    // Absolute times are converted to a duration by the contract, and the configuration
    // requires a proposal to be stored for at least a million seconds.
    body.append_u32(chain.blockchain.now() + 2_000_000).expect("expiry");
    body.checked_append_reference(proposal).expect("proposal");
    // A proposal for a critical parameter that does not declare itself critical is
    // refused before anyone votes on it.
    if is_critical(chain, param_id) {
        body.append_bit_one().expect("a critical parameter");
    } else {
        body.append_bit_zero().expect("not a critical parameter");
    }

    let proposer = chain.blockchain.treasury("proposer", 1_000 * TOS).expect("a funded account");
    let result = chain
        .blockchain
        .send_message(proposer.build_message(
            &chain.config_contract,
            100 * TOS,
            true,
            Some(body.into_cell().expect("proposal body")),
        ))
        .expect("the proposal is delivered");
    let tags = replies(&result);
    assert!(
        tags.contains(&PROPOSAL_ACCEPTED),
        "the configuration contract refused the proposal: {tags:02x?}"
    );
    hash
}

#[test]
fn a_validator_votes_for_a_proposal_with_the_key_in_the_current_set() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let proposal = propose(&mut chain, 42, 0xabcd);

    let voter = &validators[0];
    let idx = index_of(&chain, voter);
    let signature = voter.sign_under(&vote_preimage(&chain, idx, &proposal), CONFIG_VOTE_CONTEXT);
    let sender = chain.blockchain.treasury("vote-relay", 100 * TOS).expect("a funded account");
    let result = chain
        .blockchain
        .send_message(sender.build_message(
            &chain.config_contract,
            VOTE_VALUE,
            true,
            Some(vote_body(2, &signature, idx, &proposal)),
        ))
        .expect("the vote is delivered");
    result.expect_success();

    let tags = replies(&result);
    assert!(tags.contains(&VOTE_REGISTERED), "the vote was not registered: {tags:02x?}");
}

#[test]
fn a_vote_signed_by_a_key_that_is_not_at_that_index_is_refused() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let proposal = propose(&mut chain, 42, 0xabcd);

    let voter = &validators[0];
    let other = &validators[1];
    let idx = index_of(&chain, voter);
    assert_ne!(idx, index_of(&chain, other), "the two validators share an index");
    // A signature that is valid, over the right proposal and the right index, made by a
    // validator who is not the one at that index.
    let signature = other.sign_under(&vote_preimage(&chain, idx, &proposal), CONFIG_VOTE_CONTEXT);

    let sender = chain.blockchain.treasury("vote-relay", 100 * TOS).expect("a funded account");
    chain
        .blockchain
        .send_message(sender.build_message(
            &chain.config_contract,
            VOTE_VALUE,
            true,
            Some(vote_body(3, &signature, idx, &proposal)),
        ))
        .expect("the vote is delivered")
        .expect_aborted()
        .expect_exit_code(ERROR_BAD_VOTE_SIGNATURE);
}

// ---------------------------------------------------------------------------
// The unilateral administrator
//
// A single key, held off-chain, can change any configuration parameter and replace the
// configuration and elector code, through an external message. The post-quantum design
// removes this rather than converting it, so what it can do today is recorded here.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// What no longer has authority
//
// Two paths used to change this chain without a vote of the current validators: a
// validator vote arriving as an external message, and an action signed by a single
// administrator key. Both are gone, and these tests are what fails if either returns.
//
// Each asserts that nothing changed, not merely that something threw. A path that
// errored after registering a vote or installing a parameter would look identical from
// the answer alone.
// ---------------------------------------------------------------------------

/// The configuration contract accepts no external message at all, so a validator has no
/// way to vote except by the internal path that pays for its own verification.
#[test]
fn an_external_validator_vote_has_no_authorization_path() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let proposal = propose(&mut chain, 43, 0x1234);
    let voter = &validators[2];
    let idx = index_of(&chain, voter);

    // Signed by a validator that really is at that index, over the bytes the internal
    // path verifies. Only the absence of an external authorisation path can refuse it.
    let signature = voter.sign_under(&vote_preimage(&chain, idx, &proposal), CONFIG_VOTE_CONTEXT);

    use chain_block::IBitstring;
    let mut body = chain_block::BuilderData::new();
    body.append_u16(idx).expect("index");
    body.append_raw(&proposal, 256).expect("proposal");
    body.checked_append_reference(stored_bytes(&signature)).expect("signature");

    let before = proposal_voters(&chain, &proposal);
    let refused = chain.blockchain.send_message(
        tos_sandbox::MessageBuilder::external(&chain.config_contract)
            .body(body.into_cell().expect("external vote body"))
            .build(),
    );
    assert!(refused.is_err(), "the configuration contract accepted an external validator vote");

    assert_eq!(proposal_voters(&chain, &proposal), before, "an external message registered a vote");
}

/// No key, held by anyone, can change a configuration parameter on its own. The action
/// the administrator used is not merely unsigned now: the contract has no external
/// handler that would reach it.
#[test]
fn no_key_alone_can_change_a_configuration_parameter() {
    let (mut chain, _validators, _election) = elect_install_and_rotate();
    let parameter = 77i32;
    assert!(
        !parameter_present(&configuration_from_contract(&chain), parameter as u32),
        "the fixture needs a parameter that is not already set"
    );

    // The message the administrator path took, signed by a key of the sender's choosing.
    // There is no stored key to compare it against any more, which is the point.
    let admin = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);
    use chain_block::IBitstring;
    let mut value = chain_block::BuilderData::new();
    value.append_u32(0xc0ffee).expect("a value");
    let mut signed = chain_block::BuilderData::new();
    signed.append_u32(0x43665021).expect("the action that changed a parameter");
    signed.append_u32(0).expect("sequence number");
    signed.append_u32(chain.blockchain.now() + 600).expect("valid until");
    signed.append_i32(parameter).expect("parameter");
    signed.checked_append_reference(value.into_cell().expect("value")).expect("value");
    let signed_cell = signed.into_cell().expect("the signed part");

    let digest = signed_cell.hash(0);
    let signature: [u8; 64] = ed25519_dalek::Signer::sign(&admin, digest.as_slice()).to_bytes();

    let mut body = chain_block::BuilderData::new();
    body.append_raw(&signature, 512).expect("signature");
    body.checked_append_references_and_data(
        &chain_block::SliceData::load_cell(signed_cell).expect("the signed part"),
    )
    .expect("the signed part follows the signature");

    let refused = chain.blockchain.send_message(
        tos_sandbox::MessageBuilder::external(&chain.config_contract)
            .body(body.into_cell().expect("administrator message"))
            .build(),
    );
    assert!(refused.is_err(), "the configuration contract accepted an administrator message");

    assert!(
        !parameter_present(&configuration_from_contract(&chain), parameter as u32),
        "a single key changed a configuration parameter"
    );
}

/// The indices that have voted for a proposal, read from the contract's own storage, so
/// a refusal that still recorded a vote is visible.
fn proposal_voters(chain: &Chain, proposal_hash: &[u8; 32]) -> Vec<u16> {
    let account = chain
        .blockchain
        .get_account(&chain.config_contract)
        .expect("the configuration contract is deployed");
    let data = account.get_data().expect("storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    slice.checked_drain_reference().expect("the parameter dictionary");
    let votes = next_dictionary(&mut slice, 256);
    let status = votes.get(
        chain_block::SliceData::load_builder(
            chain_block::BuilderData::with_raw(proposal_hash.to_vec(), 256).expect("a key"),
        )
        .expect("a key slice"),
    );
    let mut status = match status.expect("lookup") {
        Some(s) => s,
        None => return Vec::new(),
    };
    // cfg_proposal_status#ce expires:uint32 proposal:^ConfigProposal is_critical:Bool
    //   voters:(HashmapE 16 True) ...
    assert_eq!(status.get_next_byte().expect("the status tag"), 0xce, "not a proposal status");
    status.get_next_u32().expect("expiry");
    status.checked_drain_reference().expect("the proposal");
    status.get_next_bit().expect("critical");
    let voters = next_dictionary(&mut status, 16);
    let mut indices = Vec::new();
    chain_block::HashmapType::iterate_slices(&voters, |mut key, _| {
        indices.push(key.get_next_u16()?);
        Ok(true)
    })
    .expect("the voters");
    indices.sort_unstable();
    indices
}

/// Make an accepted proposal reachable within one round of voting.
///
/// The chain launches asking an ordinary proposal to win two rounds, and a round turns
/// over only when the validator set does. That is a property of the voting policy, which
/// is configuration and not authority, so a test about what an accepted proposal may
/// install sets it to one round rather than running two elections to reach the same
/// call. The rule under test is unaffected by how many rounds preceded it.
fn require_one_winning_round(chain: &mut Chain) {
    use chain_block::IBitstring;
    // ConfigVotingSetup: cfg_vote_setup#91 normal_params:^ConfigProposalSetup
    //   critical_params:^ConfigProposalSetup
    // ConfigProposalSetup: #36 min_tot_rounds:uint8 max_tot_rounds:uint8 min_wins:uint8
    //   max_losses:uint8 min_store_sec:uint32 max_store_sec:uint32 bit_price:uint32
    //   cell_price:uint32
    let setup = |min_rounds: u8, min_wins: u8, bit_price: u32, cell_price: u32| {
        let mut b = chain_block::BuilderData::new();
        b.append_u8(0x36).expect("tag");
        b.append_u8(min_rounds).expect("min rounds");
        b.append_u8(3).expect("max rounds");
        b.append_u8(min_wins).expect("min wins");
        b.append_u8(2).expect("max losses");
        b.append_u32(1_000_000).expect("min store");
        b.append_u32(10_000_000).expect("max store");
        b.append_u32(bit_price).expect("bit price");
        b.append_u32(cell_price).expect("cell price");
        b.into_cell().expect("a proposal setup")
    };
    let mut value = chain_block::BuilderData::new();
    value.append_u8(0x91).expect("tag");
    value.checked_append_reference(setup(1, 1, 1, 500)).expect("ordinary proposals");
    value.checked_append_reference(setup(1, 1, 2, 1000)).expect("critical proposals");

    set_contract_parameter(chain, 11, value.into_cell().expect("a voting setup"));
}

/// What became of a proposal the validators voted on.
#[derive(Debug, PartialEq, Eq)]
struct Governed {
    /// The proposal was decided: enough weight voted for it that the contract took it up
    /// and removed it from the pending votes. Without this, "not installed" would also
    /// be the answer for a proposal nobody finished voting on.
    decided: bool,
    /// The parameter is in the configuration afterwards.
    installed: bool,
}

/// Propose a parameter value and have the current validators vote on it.
///
/// This is the only way a configuration parameter changes now, so it is also the fixture
/// every test that needs a parameter installed has to go through.
///
/// A proposal the contract refuses to install is not an error: it is decided and
/// returned unchanged, and the vote that carried it succeeds. So the answer is what
/// happened to the configuration, not an exit code -- an exit code would read the same
/// for a rule that refused the value and for a proposal that never carried.
fn govern_install(
    chain: &mut Chain,
    validators: &[PqValidator],
    param_id: i32,
    value: chain_block::Cell,
    query_base: u64,
) -> Governed {
    let keys: Vec<&PqValidator> = validators.iter().collect();
    govern_install_with(chain, &keys, param_id, value, query_base)
}

fn govern_install_with(
    chain: &mut Chain,
    validators: &[&PqValidator],
    param_id: i32,
    value: chain_block::Cell,
    query_base: u64,
) -> Governed {
    let proposal = propose_cell(chain, param_id, value, query_base);
    let sender =
        chain.blockchain.treasury(&format!("govern-{query_base}"), 500 * TOS).expect("an account");
    let mut decided = false;
    for (round, voter) in validators.iter().enumerate() {
        let idx = index_of(chain, voter);
        let signature =
            voter.sign_under(&vote_preimage(chain, idx, &proposal), CONFIG_VOTE_CONTEXT);
        let result = chain
            .blockchain
            .send_message(sender.build_message(
                &chain.config_contract,
                VOTE_VALUE,
                true,
                Some(vote_body(query_base + round as u64, &signature, idx, &proposal)),
            ))
            .expect("the vote is delivered");
        assert_eq!(exit_code_of(&result), 0, "a validator's vote was refused");
        // The contract drops a proposal's status once it has decided it, so the vote it
        // was recorded in disappearing is how a decision is visible from outside.
        if proposal_voters(chain, &proposal).is_empty() {
            decided = true;
            break;
        }
    }
    let installed = parameter_present(&configuration_from_contract(chain), param_id as u32);
    Governed { decided, installed }
}

// ---------------------------------------------------------------------------
// The rules the cutover rests on
//
// Each of these covers something that fails silently: a vote paid for by the chain, a
// set the node cannot read installed anyway, an administrator voted in, an election that
// looks ready on stake it cannot use. None of them announces itself when it stops
// holding, so each has a test that goes red when the rule is removed.
// ---------------------------------------------------------------------------

/// A vote brings the price of the verification it asks for.
///
/// Anyone can send one. Without this, an unauthorised sender could make every
/// masterchain block pay fifty thousand gas per message, for as many messages as it
/// cared to send, and the signatures would never have to be valid.
#[test]
fn a_vote_costs_what_the_verification_it_asks_for_costs() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let proposal = propose(&mut chain, 42, 0xfeed);
    let voter = &validators[0];
    let idx = index_of(&chain, voter);
    let signature = voter.sign_under(&vote_preimage(&chain, idx, &proposal), CONFIG_VOTE_CONTEXT);
    let sender = chain.blockchain.treasury("underfunded-relay", 100 * TOS).expect("an account");

    // Correctly signed by the validator at that index, so only the funding rule can
    // refuse it.
    chain
        .blockchain
        .send_message(sender.build_message(
            &chain.config_contract,
            TOS / 100,
            true,
            Some(vote_body(7, &signature, idx, &proposal)),
        ))
        .expect("the vote is delivered")
        .expect_aborted()
        .expect_exit_code(ERROR_VOTE_UNDERFUNDED);
    assert!(proposal_voters(&chain, &proposal).is_empty(), "an underfunded vote was registered");

    // The same vote, carrying enough, is counted.
    let result = chain
        .blockchain
        .send_message(sender.build_message(
            &chain.config_contract,
            VOTE_VALUE,
            true,
            Some(vote_body(8, &signature, idx, &proposal)),
        ))
        .expect("the vote is delivered");
    assert_eq!(exit_code_of(&result), 0, "a funded vote was refused");
    assert_eq!(proposal_voters(&chain, &proposal), vec![idx], "a funded vote was not registered");
}

/// A set that breaks any rule the node applies is refused before it can become
/// ConfigParam 36.
///
/// The configuration contract installs what the election sends it, and the node refuses
/// to start from a set it cannot read. A set that passes here and fails there is a set
/// that halts the chain at the moment it takes over, which is the one moment nothing can
/// be done about it.
#[test]
fn a_set_the_node_would_refuse_is_refused_before_it_is_installed() {
    let (mut chain, _election, validators) = elect_four();

    fn offer(chain: &mut Chain, set: chain_block::Cell, query: u64) -> Vec<u32> {
        let result = chain
            .blockchain
            .send_message(
                tos_sandbox::MessageBuilder::internal(
                    &chain.elector.clone(),
                    &chain.config_contract.clone(),
                    10 * TOS,
                )
                .body(set_next_validators_body(query, set))
                .build(),
            )
            .expect("the message is delivered");
        replies(&result)
    }

    // The control. Without it every refusal below could be the fixture's own doing.
    let honest = validator_set_cell(&chain, &validators, Flaw::None);
    let tags = offer(&mut chain, honest, 1);
    assert!(
        tags.contains(&VALIDATOR_SET_INSTALLED),
        "the fixture's own set was refused: {tags:02x?}"
    );

    for (query, flaw, what) in [
        (2, Flaw::DuplicateValidator, "naming one validator twice"),
        (3, Flaw::DuplicateKey, "holding one consensus key twice"),
        (4, Flaw::WeightSumDisagrees, "stating a total weight its descriptors do not sum to"),
        (5, Flaw::CountDisagrees, "stating a count its list does not hold"),
    ] {
        let set = validator_set_cell(&chain, &validators, flaw);
        let tags = offer(&mut chain, set, query);
        assert!(tags.contains(&VALIDATOR_SET_REFUSED), "a set {what} was installed: {tags:02x?}");
        assert!(
            !tags.contains(&VALIDATOR_SET_INSTALLED),
            "a set {what} was both refused and installed: {tags:02x?}"
        );
    }
}

/// `0x4e565354`: the elector asking the configuration contract to install a set.
fn set_next_validators_body(query_id: u64, vset: chain_block::Cell) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut body = chain_block::BuilderData::new();
    body.append_u32(0x4e565354).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.checked_append_reference(vset).expect("the set");
    body.into_cell().expect("a set-next-validators body")
}

/// One way a validator set can be wrong. Each breaks exactly one rule, so a set refused
/// for `DuplicateValidator` cannot have been refused for holding a repeated key.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flaw {
    /// Nothing wrong: the fixture's own control.
    None,
    /// Two descriptors naming one account, each with its own consensus key, so one
    /// validator's weight would be counted twice.
    DuplicateValidator,
    /// Two accounts holding one consensus key, which the node cannot tell apart.
    DuplicateKey,
    /// The header's total weight is not the weight the descriptors carry.
    WeightSumDisagrees,
    /// The header states a count the list does not hold.
    CountDisagrees,
}

/// A validator set carrying the given validators, with one stated flaw.
fn validator_set_cell(chain: &Chain, validators: &[PqValidator], flaw: Flaw) -> chain_block::Cell {
    use chain_block::IBitstring;
    let since = chain.blockchain.now() + 1000;
    let mut list = chain_block::HashmapE::with_bit_len(16);
    let mut total_weight = 0u64;
    for (index, validator) in validators.iter().enumerate() {
        let weight = 1u64 << 40;

        // The account this descriptor names, and the key it holds. Only the stated flaw
        // makes either of them repeat.
        let mut identity = [0u8; 32];
        identity[31] = (index + 1) as u8;
        if flaw == Flaw::DuplicateValidator && index == 1 {
            identity[31] = 1;
        }
        let key = if flaw == Flaw::DuplicateKey && index == 1 {
            &validators[0].public_key
        } else {
            &validator.public_key
        };

        let mut descr = chain_block::BuilderData::new();
        descr.append_u8(0xb3).expect("tag");
        descr.append_raw(&identity, 256).expect("validator identity");
        descr.append_u16(1).expect("algorithm");
        descr
            .append_raw(chain_block::derive_consensus_key_id(1, key).as_slice(), 256)
            .expect("key identity");
        descr.checked_append_reference(stored_bytes(key)).expect("the key");
        descr.append_u64(weight).expect("weight");
        descr.append_raw(&validator.adnl, 256).expect("transport identity");

        let mut key_bits = chain_block::BuilderData::new();
        key_bits.append_u16(index as u16).expect("the index");
        list.set_builder(
            chain_block::SliceData::load_builder(key_bits).expect("a key slice"),
            &descr,
        )
        .expect("the descriptor is stored");
        total_weight += weight;
    }

    let stated_total = match flaw {
        Flaw::CountDisagrees => validators.len() as u16 + 1,
        _ => validators.len() as u16,
    };
    let stated_weight = match flaw {
        Flaw::WeightSumDisagrees => total_weight + 1,
        _ => total_weight,
    };

    let mut set = chain_block::BuilderData::new();
    set.append_u8(0x12).expect("validators_ext#12");
    set.append_u32(since).expect("utime_since");
    set.append_u32(since + 100_000).expect("utime_until");
    set.append_u16(stated_total).expect("total");
    set.append_u16(validators.len() as u16).expect("main");
    set.append_u64(stated_weight).expect("total weight");
    set.append_bit_one().expect("a non-empty list");
    set.checked_append_reference(
        chain_block::HashmapType::data(&list).expect("a non-empty list").clone(),
    )
    .expect("the list");
    set.into_cell().expect("a validator set")
}

/// Governance may change what the chain does. It may not vote itself something that can
/// then change the chain without it.
#[test]
fn governance_cannot_vote_itself_an_administrator() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    require_one_winning_round(&mut chain);

    use chain_block::IBitstring;
    let mut key = chain_block::BuilderData::new();
    key.append_raw(&[0x5au8; 32], 256).expect("an administrator key");

    let outcome =
        govern_install(&mut chain, &validators, -999, key.into_cell().expect("a key"), 300);
    assert!(outcome.decided, "the fixture needs a proposal the validators actually carried");
    assert!(
        !outcome.installed,
        "the validators voted an administrator in, so nothing stops governance ending itself"
    );
}

/// Stake behind a controller profile the configuration has retired cannot make an
/// election look ready.
///
/// The money is still there and still refundable, and the running total still counts it.
/// What decides whether an election may close is the stake it can stand behind, so a
/// profile withdrawn after its stake arrived must take that stake out of the decision.
#[test]
fn a_retired_profile_cannot_make_an_election_look_ready() {
    let (mut chain, treasury, election) = open_election("readiness-retired", 200_000 * TOS);
    raise_to_post_quantum_version(&mut chain);

    // Enough stake, from enough members, that the election would close.
    let mut accounts = Vec::new();
    for index in 0..4u8 {
        let account = chain
            .blockchain
            .treasury(&format!("readiness-{index}"), 40_000 * TOS)
            .expect("a funded account");
        let result = pq_stake(
            &mut chain,
            &account,
            &PqValidator::new(0x60 + index),
            election,
            10 + index as u64,
            11_000 * TOS,
        );
        assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "validator {index} could not stake");
        accounts.push(account);
    }
    let _ = treasury;
    let placed = declared_total_stake(&chain);
    assert!(placed > 40_000 * TOS as u128, "the fixture needs enough stake to close on");

    // Retire the profile every one of them was admitted under.
    set_contract_parameter(&mut chain, 47, controller_policy(1));

    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();

    assert!(
        !parameter_present(&configuration_from_contract(&chain), 36),
        "an election closed on stake behind a profile the configuration had retired"
    );
    // The money is untouched: retiring a profile withdraws authority, not deposits.
    assert_eq!(
        declared_total_stake(&chain),
        placed,
        "retiring a profile took the stake that had been placed"
    );

    // And the election is postponed, not failed. The difference is the whole point of
    // judging readiness on the stake the election can stand behind: an election that
    // was marked failed would not retry until new stake arrived, so putting the profile
    // back would leave it stuck for a reason the configuration had already undone.
    admit_sender_code(&mut chain, &accounts[0]);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    assert!(
        parameter_present(&configuration_from_contract(&chain), 36),
        "re-admitting the profile did not revive the election, so it had been given up on"
    );
}

// ---------------------------------------------------------------------------
// The cutover, end to end
//
// Every rule above is tested where it lives. This is the one run that puts them in a
// row: a controller whose authority is post-quantum places a stake, the election that
// selects it emits post-quantum descriptors, the configuration contract validates and
// installs them, and the set that results is the only thing that can govern the chain
// afterwards.
//
// It exists because the parts can each be right while the whole does not compose -- an
// identity that changes shape between the book and the descriptor, a set hash the vote
// is bound to that is not the one installed. Nothing here uses a fixture that writes a
// validator set or a configuration parameter directly.
// ---------------------------------------------------------------------------

/// A validator controller deployed into the elector's own chain, holding a
/// post-quantum root key.
struct RootedValidator {
    address: MsgAddressInt,
    root: PqValidator,
    consensus: PqValidator,
}

/// The domain a controller root signs under, distinct from the election domain so that
/// a signature made for one can never be replayed as the other.
const CONTROLLER_CONTEXT: &[u8] = b"TOS-VALIDATOR-CONTROLLER-v1";
const CONTROLLER_OP: u32 = 0x50516361;
const CONTROLLER_SIGN_TAG: u32 = 0x50514341;
const CONTROLLER_KIND_SEND: u8 = 1;

fn controller_code() -> chain_block::Cell {
    let root = std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root above the contracts crate")
            .to_path_buf()
    });
    tos_sandbox::compile_func_with_stdlib(&[
        root.join("crypto/smartcont/validator-controller-v1.fc")
    ])
    .expect("the controller compiles")
}

/// Deploy a controller, its authority rooted in a key only this test holds.
fn deploy_rooted_validator(chain: &mut Chain, index: u8) -> RootedValidator {
    use chain_block::{GetRepresentationHash, IBitstring, Serializable};
    let root = PqValidator::new(0x80 + index);
    let consensus = PqValidator::new(0x90 + index);

    let mut data = chain_block::BuilderData::new();
    data.append_u64(0).expect("epoch");
    data.append_u64(0).expect("nonce");
    data.checked_append_reference(stored_bytes(&root.public_key)).expect("root key");
    let state = chain_block::StateInit::with_code_and_data(
        controller_code(),
        data.into_cell().expect("controller data"),
    );
    let address = MsgAddressInt::with_params(
        -1,
        state.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("address");

    let funder = chain
        .blockchain
        .treasury(&format!("controller-funder-{index}"), 100_000 * TOS)
        .expect("a funded account");
    chain
        .blockchain
        .send_message(
            tos_sandbox::MessageBuilder::internal(funder.address(), &address, 40_000 * TOS)
                .bounce(false)
                .state_init(state)
                .body(chain_block::Cell::default())
                .build(),
        )
        .expect("the controller is deployed")
        .expect_success();

    RootedValidator { address, root, consensus }
}

/// The 93 bytes a controller root signs to authorise one action.
fn controller_preimage(
    global_id: i32,
    controller: &chain_block::UInt256,
    epoch: u64,
    nonce: u64,
    valid_until: u32,
    kind: u8,
    payload: &chain_block::Cell,
) -> Vec<u8> {
    use chain_block::GetRepresentationHash;
    let mut preimage = Vec::with_capacity(93);
    preimage.extend_from_slice(&CONTROLLER_SIGN_TAG.to_be_bytes());
    preimage.extend_from_slice(&global_id.to_be_bytes());
    preimage.extend_from_slice(controller.as_slice());
    preimage.extend_from_slice(&epoch.to_be_bytes());
    preimage.extend_from_slice(&nonce.to_be_bytes());
    preimage.extend_from_slice(&valid_until.to_be_bytes());
    preimage.push(kind);
    preimage.extend_from_slice(payload.hash(0).as_slice());
    assert_eq!(preimage.len(), 93, "the controller preimage changed shape");
    preimage
}

impl RootedValidator {
    fn id(&self) -> chain_block::UInt256 {
        chain_block::UInt256::from_slice(&self.address.address().get_bytestring(0))
    }

    /// The nonce the controller will accept next.
    fn stored_nonce(&self, chain: &Chain) -> u64 {
        let result = chain
            .blockchain
            .run_get_method(&self.address, "controller_state", vec![])
            .expect("the controller answers");
        assert_eq!(result.exit_code, 0, "controller_state failed");
        result.stack[1].as_integer().expect("a nonce").to_string().parse().expect("a nonce")
    }

    /// Have the controller send a body to the elector, authorised by its root key.
    ///
    /// This is what makes the run an authority test rather than a message test: the
    /// stake arrives from an account whose right to place it is a post-quantum
    /// signature, and the elector reads the sender as the validator identity.
    fn send_to_elector(
        &mut self,
        chain: &mut Chain,
        value: u64,
        body: chain_block::Cell,
    ) -> tos_sandbox::SendResult {
        use chain_block::{IBitstring, Serializable};
        let global_id = global_id(chain);

        // The message is built the way a contract builds one to send: no source, because
        // the sender is filled in by the chain, and the body behind a reference. A body
        // written into the header instead overflows the cell the send instruction has to
        // build, which is a failure in the compute phase and reads like a broken
        // contract rather than a message that does not fit.
        let mut message = chain_block::BuilderData::new();
        message.append_bits(0x18, 6).expect("int_msg_info, bounceable, no source");
        message.append_bits(0b100, 3).expect("addr_std, no anycast");
        message.append_i8(-1).expect("the masterchain");
        message
            .append_raw(&chain.elector.address().get_bytestring(0), 256)
            .expect("the elector's address");
        chain_block::Coins::new(value).write_to(&mut message).expect("the value it carries");
        // other:ExtraCurrencyCollection (empty), ihr_fee and fwd_fee (zero Grams).
        message.append_bits(0, 1 + 4 + 4).expect("no other currencies and no fees");
        message.append_u64(0).expect("created_lt, filled in by the chain");
        message.append_u32(0).expect("created_at, filled in by the chain");
        message.append_bit_zero().expect("no state init");
        message.append_bit_one().expect("the body is a reference");
        message.checked_append_reference(body).expect("the body");

        let mut payload = chain_block::BuilderData::new();
        payload.append_u8(3).expect("mode");
        payload
            .checked_append_reference(message.into_cell().expect("an outbound message"))
            .expect("the message");
        let payload = payload.into_cell().expect("a send payload");

        // Read the nonce the controller actually holds rather than counting sends. A
        // refused action leaves the nonce where it was, so a counter kept out here goes
        // out of step with the contract the first time one is refused.
        let nonce = self.stored_nonce(chain);
        let valid_until = chain.blockchain.now() + 600;
        let signature = self.root.sign_under(
            &controller_preimage(
                global_id,
                &self.id(),
                0,
                nonce,
                valid_until,
                CONTROLLER_KIND_SEND,
                &payload,
            ),
            CONTROLLER_CONTEXT,
        );

        let mut authorisation = chain_block::BuilderData::new();
        authorisation.append_u32(CONTROLLER_OP).expect("operation");
        authorisation.append_u64(1).expect("query id");
        authorisation.append_i32(global_id).expect("network");
        authorisation.append_u64(0).expect("epoch");
        authorisation.append_u64(nonce).expect("nonce");
        authorisation.append_u32(valid_until).expect("expiry");
        authorisation.append_u8(CONTROLLER_KIND_SEND).expect("kind");
        authorisation.checked_append_reference(payload).expect("payload");
        authorisation.checked_append_reference(stored_bytes(&signature)).expect("signature");
        authorisation.append_bit_zero().expect("no cosignature");

        let relayer = chain
            .blockchain
            .treasury(&format!("relayer-{}", hex::encode(&self.id().as_slice()[..4])), 10_000 * TOS)
            .expect("a relayer");
        chain
            .blockchain
            .send_message(relayer.build_message(
                &self.address,
                100 * TOS,
                true,
                Some(authorisation.into_cell().expect("an authorisation")),
            ))
            .expect("the authorisation is delivered")
    }
}
/// The index of a validator in the current set, by the consensus key it holds.
fn index_of_pq(chain: &Chain, consensus: &PqValidator) -> u16 {
    index_of(chain, consensus)
}

/// Admit the code an account was deployed with, and nothing else.
fn admit_code_of(chain: &mut Chain, address: &MsgAddressInt) {
    use chain_block::{GetRepresentationHash, IBitstring};
    let account = chain.blockchain.get_account(address).expect("the account exists");
    let code_hash = account.state_init().expect("a state init").code().expect("code").repr_hash();

    let mut dict = chain_block::HashmapE::with_bit_len(256);
    dict.set(
        chain_block::SliceData::load_builder(
            chain_block::BuilderData::with_raw(code_hash.as_slice().to_vec(), 256).expect("a key"),
        )
        .expect("a key slice"),
        &chain_block::SliceData::default(),
    )
    .expect("insert");
    let mut value = chain_block::BuilderData::new();
    value.append_bit_one().expect("a non-empty policy");
    value
        .checked_append_reference(
            chain_block::HashmapType::data(&dict).expect("a non-empty dictionary").clone(),
        )
        .expect("the codes");
    set_contract_parameter(chain, 47, value.into_cell().expect("a controller policy"));
}

/// `govern_install`, for validators whose consensus keys are held by controllers.
fn govern_install_pq(
    chain: &mut Chain,
    validators: &[RootedValidator],
    param_id: i32,
    value: chain_block::Cell,
    query_base: u64,
) -> Governed {
    let keys: Vec<&PqValidator> = validators.iter().map(|v| &v.consensus).collect();
    govern_install_with(chain, &keys, param_id, value, query_base)
}

/// A contract cannot forward a proof of its own birth code.
///
/// The first stake is supposed to carry a pruned proof of the sender's state init, and
/// the sender is supposed to be the controller, because the elector reads the validator
/// identity from the message source. Those two requirements are in conflict: an outbound
/// message a contract builds may not carry a cell of level greater than zero, and a
/// pruned branch has level one.
///
/// Nothing caught this before because every test that carries a proof sends it from a
/// sandbox treasury, whose messages are injected rather than sent by a contract, so the
/// rule was never reached. This test sends the same body the same way twice, changing
/// only whether the proof's children are pruned, and pins both answers.
#[test]
fn a_contract_cannot_send_a_message_carrying_a_pruned_proof() {
    use chain_block::IBitstring;
    let (mut chain, _treasury, election) = open_election("pruned-proof-limit", 200_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let mut validator = deploy_rooted_validator(&mut chain, 9);
    admit_code_of(&mut chain, &validator.address);

    let preimage = pq_stake_preimage(
        global_id(&chain),
        election,
        0x10000,
        &validator.id(),
        &validator.consensus.key_id(),
        &validator.consensus.adnl,
    );
    let signature = validator.consensus.sign(&preimage);
    let proof = proof_of_birth_code(&chain, &validator.address.clone());
    assert_eq!(proof.level(), 1, "a state-init proof is a level-one cell");

    // The same bits and the same number of children, every child ordinary. If the two
    // answers differ, the difference is the level and not the size.
    let mut twin = chain_block::BuilderData::with_raw(proof.data().to_vec(), proof.bit_length())
        .expect("the proof's own bits");
    for _ in 0..proof.references_count() {
        let mut ordinary = chain_block::BuilderData::new();
        ordinary.append_raw(&[0u8; 32], 256).expect("filler");
        twin.checked_append_reference(ordinary.into_cell().expect("a child")).expect("a child");
    }
    let twin = twin.into_cell().expect("a twin of the proof");
    assert_eq!(twin.level(), 0, "the twin is here to be the ordinary one");

    let send = |chain: &mut Chain, validator: &mut RootedValidator, carried, query| {
        let body = pq_stake_body(
            query,
            &validator.consensus,
            election,
            0x10000,
            &signature,
            Some(carried),
        );
        let result = validator.send_to_elector(chain, 11_000 * TOS, body);
        let (_, transaction) = result.transactions.first().expect("a transaction");
        match transaction.read_description().expect("description") {
            chain_block::TransactionDescr::Ordinary(descr) => match descr.compute_ph {
                chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
                _ => panic!("the controller did not run"),
            },
            _ => panic!("not an ordinary transaction"),
        }
    };

    assert_eq!(
        send(&mut chain, &mut validator, twin, 1),
        0,
        "a controller cannot send a stake at all, so this test measures nothing"
    );
    assert_eq!(
        send(&mut chain, &mut validator, proof.clone(), 2),
        8,
        "a controller can now forward a pruned proof, and the registration path that was \
         blocked on this should be reconsidered"
    );

    // Not the size and not the depth of the message: a body carrying nothing but the
    // proof, two cells deep against the twenty-one of a stake, is refused the same way.
    let mut alone = chain_block::BuilderData::new();
    alone.append_u32(1).expect("something to read as an operation");
    alone.checked_append_reference(proof).expect("the proof alone");
    let alone = alone.into_cell().expect("a body carrying only the proof");
    assert!(alone.repr_depth() < 5, "the small case has to be small");
    let result = validator.send_to_elector(&mut chain, TOS, alone);
    let (_, transaction) = result.transactions.first().expect("a transaction");
    let exit = match transaction.read_description().expect("description") {
        chain_block::TransactionDescr::Ordinary(descr) => match descr.compute_ph {
            chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
            _ => panic!("the controller did not run"),
        },
        _ => panic!("not an ordinary transaction"),
    };
    assert_eq!(exit, 8, "the small case was allowed, so size is part of the rule after all");
}

/// A controller policy holding `count` distinct code hashes.
fn controller_policy(count: usize) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut dict = chain_block::HashmapE::with_bit_len(256);
    for index in 0..count {
        let mut key = [0u8; 32];
        key[31] = index as u8;
        dict.set(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(key.to_vec(), 256).expect("a key"),
            )
            .expect("a key slice"),
            &chain_block::SliceData::default(),
        )
        .expect("insert");
    }
    let mut value = chain_block::BuilderData::new();
    match chain_block::HashmapType::data(&dict) {
        Some(root) => {
            value.append_bit_one().expect("a non-empty policy");
            value.checked_append_reference(root.clone()).expect("the codes");
        }
        None => {
            value.append_bit_zero().expect("an empty policy");
        }
    }
    value.into_cell().expect("a controller policy")
}

/// The ceiling on admitted controller codes is part of the parameter, not a note about it.
///
/// A hashmap carries no cardinality, so a bound that lives only in prose is a bound that
/// is never reached by anything. This is the configuration contract refusing the ninth.
#[test]
fn the_controller_policy_cannot_grow_past_its_ceiling() {
    use chain_block::GetRepresentationHash;
    let (mut chain, validators, _election) = elect_install_and_rotate();
    require_one_winning_round(&mut chain);

    // The fixture already put a policy in place to admit its own senders, so being
    // present proves nothing here. What each vote is judged on is the value stored
    // afterwards.
    let before = raw_parameter(&chain, 47).expect("the fixture installs a policy");

    // Eight is the ceiling, and a vote of the validators installs it.
    let eight = controller_policy(8);
    assert!(
        govern_install(&mut chain, &validators, 47, eight.clone(), 100).decided,
        "the fixture needs a proposal the validators actually carried"
    );
    assert_eq!(
        raw_parameter(&chain, 47),
        Some(eight.clone()),
        "a policy at the ceiling was refused"
    );
    assert_ne!(raw_parameter(&chain, 47), Some(before), "the fixture proved nothing");

    // The ninth is refused by the rule, not by the vote: the validators carried the
    // proposal and the contract still declined to install what it asked for.
    assert!(
        govern_install(&mut chain, &validators, 47, controller_policy(9), 200).decided,
        "the fixture needs a proposal the validators actually carried"
    );
    assert_eq!(
        raw_parameter(&chain, 47),
        Some(eight),
        "a ninth controller code was admitted, so the ceiling is prose"
    );
}

/// The compute-phase exit code of the first transaction a message produced.
fn exit_code_of(result: &tos_sandbox::SendResult) -> i32 {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    match transaction.read_description().expect("description") {
        chain_block::TransactionDescr::Ordinary(descr) => match descr.compute_ph {
            chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
            other => panic!("the compute phase did not run: {other:?}"),
        },
        other => panic!("not an ordinary transaction: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Complaints
//
// A validator of the current set votes, by signature, to punish a validator of a past
// one. The same authority as a configuration vote, in the other contract, and the same
// conversion ahead of it.
// ---------------------------------------------------------------------------

const NEW_COMPLAINT: u32 = 0x52674370;
const COMPLAINT_VOTE: u32 = 0x5051636f;
const COMPLAINT_VOTE_SIGN_TAG: u32 = 0x5051434f;
const COMPLAINT_ACCEPTED: u32 = 0xf2676350;
/// `send_message_back(.., res + 0xd6745240, ..)`: 1 is a vote counted and not yet
/// decisive, 2 is the vote that carries the complaint and applies the fine.
const COMPLAINT_VOTE_COUNTED: u32 = 0xd6745240 + 1;
const COMPLAINT_CARRIED: u32 = 0xd6745240 + 2;

/// `validator_complaint#bc validator_pubkey:uint256 description:^ComplaintDescr
/// created_at:uint32 severity:uint8 reward_addr:uint256 paid:Tomis suggested_fine:Tomis
/// suggested_fine_part:uint32`
///
/// The elector rewrites the reward address, the creation time and the amount paid before
/// storing it, so the hash a vote refers to is not the hash of what was sent. The test
/// reads that hash out of the contract's own storage rather than recomputing it.
fn complaint_body(query_id: u64, election: u32, accused: &[u8; 32]) -> chain_block::Cell {
    // `accused` is a validator identity: the account the elector saw place the stake.
    use chain_block::IBitstring;
    let mut description = chain_block::BuilderData::new();
    description.append_u32(0).expect("an empty description");

    let mut body = chain_block::BuilderData::new();
    body.append_u32(NEW_COMPLAINT).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.append_u32(election).expect("the election complained about");
    body.append_i8(0xbcu8 as i8).expect("complaint tag");
    body.append_raw(accused, 256).expect("the accused validator");
    body.checked_append_reference(description.into_cell().expect("description"))
        .expect("description");
    body.append_u32(0).expect("created at, rewritten by the contract");
    body.append_u8(1).expect("severity");
    body.append_raw(&[0u8; 32], 256).expect("reward address, rewritten by the contract");
    body.append_bits(0, 4).expect("paid, rewritten by the contract");
    // The fine has to exceed what the complaint costs to file, or the elector refuses it
    // as not worth hearing, and it has to stay within the stake it would be taken from.
    body.append_bits(8, 4).expect("the length of the suggested fine");
    body.append_u64(500 * TOS).expect("suggested fine");
    body.append_u32(0).expect("suggested fine part");
    body.into_cell().expect("complaint body")
}

/// The hashes of the complaints the elector is holding for an election, which is how a
/// vote names the one it is for.
///
/// `unfreeze_at:uint32 stake_held:uint32 vset_hash:uint256 frozen:HashmapE total:Tomis
/// bonuses:Tomis complaints:HashmapE`, read in that order because the dictionary is at
/// the end of it.
fn complaint_hashes(chain: &Chain, election: u32) -> Vec<[u8; 32]> {
    let past = past_elections(chain);
    let key = chain_block::SliceData::load_builder(
        chain_block::BuilderData::with_raw(election.to_be_bytes().to_vec(), 32).expect("key"),
    )
    .expect("key slice");
    let mut record = past.get(key).expect("lookup").expect("a record for that election");
    record.get_next_u32().expect("unfreeze time");
    record.get_next_u32().expect("hold time");
    record.get_next_bits(256).expect("the set this election produced");
    next_dictionary(&mut record, 256);
    for _ in 0..2 {
        // An amount is a length in bytes followed by that many bytes, and a zero amount
        // is a length of zero followed by nothing.
        let bytes = record.get_next_int(4).expect("the length of an amount") as usize;
        if bytes > 0 {
            record.get_next_bits(bytes * 8).expect("an amount");
        }
    }
    let complaints = next_dictionary(&mut record, 256);

    let mut hashes = Vec::new();
    chain_block::HashmapType::iterate_slices(&complaints, |key, _value| {
        let bytes = key.get_bytestring(0);
        hashes.push(bytes[..32].try_into().expect("a complaint hash is 32 bytes"));
        Ok(true)
    })
    .expect("complaints");
    hashes
}

/// What a past election still holds frozen for a validator, which is what a fine is taken
/// from.
fn frozen_stake(chain: &Chain, election: u32, validator: &[u8; 32]) -> u128 {
    let past = past_elections(chain);
    let key = chain_block::SliceData::load_builder(
        chain_block::BuilderData::with_raw(election.to_be_bytes().to_vec(), 32).expect("key"),
    )
    .expect("key slice");
    let mut record = past.get(key).expect("lookup").expect("a record for that election");
    record.get_next_u32().expect("unfreeze time");
    record.get_next_u32().expect("hold time");
    record.get_next_bits(256).expect("the set this election produced");
    let frozen = next_dictionary(&mut record, 256);
    let entry = frozen
        .get(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(validator.to_vec(), 256).expect("key"),
            )
            .expect("key slice"),
        )
        .expect("lookup")
        .expect("the validator is frozen in that election");
    let mut entry = entry;
    entry.get_next_bits(256).expect("controller");
    entry.get_next_u64().expect("weight");
    let bytes = entry.get_next_int(4).expect("the length of the stake") as usize;
    if bytes == 0 {
        return 0;
    }
    let mut stake: u128 = 0;
    for byte in entry.get_next_bits(bytes * 8).expect("the stake") {
        stake = (stake << 8) | byte as u128;
    }
    stake
}

/// Exactly the bytes the elector verifies for a complaint vote.
fn complaint_vote_preimage(
    chain: &Chain,
    idx: u16,
    election: u32,
    complaint: &[u8; 32],
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(110);
    preimage.extend_from_slice(&COMPLAINT_VOTE_SIGN_TAG.to_be_bytes());
    preimage.extend_from_slice(&global_id(chain).to_be_bytes());
    preimage.extend_from_slice(&current_set_id(chain));
    preimage.extend_from_slice(&validator_id_at(chain, idx));
    preimage.extend_from_slice(&idx.to_be_bytes());
    preimage.extend_from_slice(&election.to_be_bytes());
    preimage.extend_from_slice(complaint);
    assert_eq!(preimage.len(), 110, "the signed preimage changed shape");
    preimage
}

fn complaint_vote_body(
    query_id: u64,
    signature: &[u8],
    idx: u16,
    election: u32,
    complaint: &[u8; 32],
) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut body = chain_block::BuilderData::new();
    body.append_u32(COMPLAINT_VOTE).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.append_u16(idx).expect("index");
    body.append_u32(election).expect("election");
    body.append_raw(complaint, 256).expect("complaint");
    body.checked_append_reference(stored_bytes(signature)).expect("signature");
    body.into_cell().expect("complaint vote body")
}

#[test]
fn a_validator_votes_to_punish_a_validator_of_a_past_election() {
    let (mut chain, validators, election) = elect_install_and_rotate();
    let accused = validator_id_at(&chain, index_of(&chain, &validators[3]));
    let complainant =
        chain.blockchain.treasury("complainant", 1_000 * TOS).expect("a funded account");

    let result = chain
        .blockchain
        .send_message(complainant.build_message(
            &chain.elector,
            300 * TOS,
            true,
            Some(complaint_body(1, election, &accused)),
        ))
        .expect("the complaint is delivered");
    let tags = replies(&result);
    assert!(tags.contains(&COMPLAINT_ACCEPTED), "the elector refused the complaint: {tags:02x?}");

    let hashes = complaint_hashes(&chain, election);
    assert_eq!(hashes.len(), 1, "exactly one complaint should be registered");
    let complaint = hashes[0];

    let before = frozen_stake(&chain, election, &accused);
    assert_ne!(before, 0, "the accused should have a frozen stake to be fined from");

    // One vote is counted and decides nothing; the complaint carries once enough weight
    // has voted for it. Both answers are checked, because a contract that accepted the
    // first vote as decisive would be a very different contract.
    let sender = chain.blockchain.treasury("complaint-relay", 100 * TOS).expect("an account");
    let mut carried = false;
    for (round, voter) in validators.iter().take(3).enumerate() {
        let idx = index_of(&chain, voter);
        let signature = voter.sign(&complaint_vote_preimage(&chain, idx, election, &complaint));

        let result = chain
            .blockchain
            .send_message(sender.build_message(
                &chain.elector,
                VOTE_VALUE,
                true,
                Some(complaint_vote_body(10 + round as u64, &signature, idx, election, &complaint)),
            ))
            .expect("the vote is delivered");
        result.expect_success();
        let tags = replies(&result);
        if round == 0 {
            assert!(
                tags.contains(&COMPLAINT_VOTE_COUNTED),
                "the first vote was not counted, or decided on its own: {tags:02x?}"
            );
            assert_eq!(
                frozen_stake(&chain, election, &accused),
                before,
                "a fine was taken before the complaint carried"
            );
        }
        carried |= tags.contains(&COMPLAINT_CARRIED);
    }

    assert!(carried, "three of four validators voted and the complaint did not carry");
    let after = frozen_stake(&chain, election, &accused);
    assert_eq!(
        before - after,
        (500 * TOS) as u128,
        "the fine the complaint asked for was not taken from the frozen stake"
    );
}

#[test]
fn a_complaint_vote_signed_by_another_validator_is_refused() {
    let (mut chain, validators, election) = elect_install_and_rotate();
    let accused = validator_id_at(&chain, index_of(&chain, &validators[3]));
    let complainant =
        chain.blockchain.treasury("complainant-b", 1_000 * TOS).expect("a funded account");
    let result = chain
        .blockchain
        .send_message(complainant.build_message(
            &chain.elector,
            300 * TOS,
            true,
            Some(complaint_body(1, election, &accused)),
        ))
        .expect("the complaint is delivered");
    assert!(replies(&result).contains(&COMPLAINT_ACCEPTED), "the complaint was refused");
    let complaint = complaint_hashes(&chain, election)[0];

    let voter = &validators[0];
    let other = &validators[1];
    let idx = index_of(&chain, voter);
    assert_ne!(idx, index_of(&chain, other), "the two validators share an index");
    // Valid, over the right complaint and the right index, by the wrong validator.
    let signature = other.sign(&complaint_vote_preimage(&chain, idx, election, &complaint));

    let sender = chain.blockchain.treasury("complaint-relay-b", 100 * TOS).expect("an account");
    chain
        .blockchain
        .send_message(sender.build_message(
            &chain.elector,
            VOTE_VALUE,
            true,
            Some(complaint_vote_body(20, &signature, idx, election, &complaint)),
        ))
        .expect("the vote is delivered")
        .expect_aborted()
        .expect_exit_code(ERROR_BAD_VOTE_SIGNATURE);
}

// ---------------------------------------------------------------------------
// Post-quantum staking
//
// A separate operation, never a reinterpretation of the classical one. The request
// carries a key and a signature; the contract supplies both identities itself -- the
// validator is the account that sent the message, and the key identity is derived from
// the key presented -- so a request cannot name one validator while carrying another's
// key.
// ---------------------------------------------------------------------------

const PQ_STAKE_OP: u32 = 0x5051_7374;
const PQ_STAKE_SIGN_TAG: u32 = 0x5051_5354;
const ELECTION_CONTEXT: &[u8] = b"TOS-VALIDATOR-ELECTION-v1";
/// A different authorisation's context, used to show a signature cannot cross between them.
const CONFIG_VOTE_CONTEXT: &[u8] = b"TOS-VALIDATOR-CONFIG-VOTE-v1";
const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;
/// `return_stake` reason 7: no transport address was stated.
/// No election is taking stakes: none is open, it is finished, or it has closed.
/// The library refuses a suite it does not admit, before anything reads the key.
const ERROR_UNADMITTED_ALGORITHM: i32 = 61;
const REASON_NO_ELECTION: u32 = 0;
const REASON_BELOW_MINIMUM: u32 = 5;
const REASON_FACTOR_BELOW_ONE: u32 = 6;
const REASON_NO_ADNL: u32 = 7;

/// The key tool from `crypto/pq/tools`. Signing is deliberately absent from the node's
/// libraries, so a test that needs a signature shells out to the tool operators use.
fn key_tool() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("PQ_KEY_TOOL") {
        return std::path::PathBuf::from(path);
    }
    let root = std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root")
            .to_path_buf()
    });
    for candidate in ["build-pq-key/tos-pq-key", "build/tos-pq-key"] {
        let path = root.join(candidate);
        if path.exists() {
            return path;
        }
    }
    panic!(
        "the ML-DSA-44 key tool is needed for post-quantum staking: build it with \
         `cmake -S crypto/pq/tools -B build-pq-key && cmake --build build-pq-key`, \
         or point PQ_KEY_TOOL at it"
    );
}

fn run_key_tool(args: &[&str]) -> Vec<String> {
    let out =
        std::process::Command::new(key_tool()).args(args).output().expect("the key tool runs");
    assert!(out.status.success(), "the key tool failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).lines().map(|line| line.trim().to_string()).collect()
}

/// A post-quantum validator: a key of its own, and the transport address it claims.
struct PqValidator {
    key_file: std::path::PathBuf,
    public_key: Vec<u8>,
    adnl: [u8; 32],
}

impl PqValidator {
    fn new(index: u8) -> Self {
        let key_file = std::env::temp_dir().join(format!("tos-pq-elector-test-{index}.key"));
        if !key_file.exists() {
            let mine = key_file.with_extension(format!("{}.tmp", std::process::id()));
            run_key_tool(&["keygen", mine.to_str().expect("path")]);
            // Losing the race is fine: whoever won wrote a key, and this one is discarded.
            match std::fs::hard_link(&mine, &key_file) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("the key could not be put in place: {e}"),
            }
            let _ = std::fs::remove_file(&mine);
        }
        let public_key =
            hex::decode(&run_key_tool(&["public", key_file.to_str().expect("path")])[0])
                .expect("hex");
        assert_eq!(public_key.len(), MLDSA44_PUBLIC_KEY_BYTES);
        PqValidator { key_file, public_key, adnl: [0xd0 ^ index; 32] }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign_under(message, ELECTION_CONTEXT)
    }

    fn sign_under(&self, message: &[u8], context: &[u8]) -> Vec<u8> {
        let signature = hex::decode(
            &run_key_tool(&[
                "sign",
                self.key_file.to_str().expect("path"),
                &hex::encode(message),
                &hex::encode(context),
            ])[0],
        )
        .expect("hex");
        assert_eq!(signature.len(), 2420);
        signature
    }

    fn key_id(&self) -> chain_block::UInt256 {
        chain_block::derive_consensus_key_id(1, &self.public_key)
    }
}

fn stored_bytes(bytes: &[u8]) -> chain_block::Cell {
    chain_block::pq_bytes::pack_pq_bytes(bytes, chain_block::pq_bytes::PQ_BYTES_HARD_MAX)
        .expect("bytes of admitted length")
}

/// The 114 bytes a stake request signs, built here independently of the contract.
fn pq_stake_preimage(
    global_id: i32,
    stake_at: u32,
    max_factor: u32,
    validator_id: &chain_block::UInt256,
    key_id: &chain_block::UInt256,
    adnl: &[u8; 32],
) -> Vec<u8> {
    pq_stake_preimage_for(global_id, stake_at, max_factor, validator_id, 1, key_id, adnl)
}

/// The same bytes with the suite stated explicitly, so a signature can be made over a
/// suite other than the one the request carries.
#[allow(clippy::too_many_arguments)]
fn pq_stake_preimage_for(
    global_id: i32,
    stake_at: u32,
    max_factor: u32,
    validator_id: &chain_block::UInt256,
    algorithm_id: u16,
    key_id: &chain_block::UInt256,
    adnl: &[u8; 32],
) -> Vec<u8> {
    chain_block::pq_elector::stake_preimage(
        global_id,
        stake_at,
        max_factor,
        validator_id,
        algorithm_id,
        key_id,
        &chain_block::UInt256::from(*adnl),
    )
}

/// A proof of what a sender was deployed as: the state init's own bits, with a pruned
/// branch in place of each child.
fn controller_proof(chain: &Chain, who: &tos_sandbox::Treasury) -> chain_block::Cell {
    proof_of_birth_code(chain, who.address())
}

fn proof_of_birth_code(chain: &Chain, address: &MsgAddressInt) -> chain_block::Cell {
    use chain_block::{GetRepresentationHash, IBitstring, Serializable};
    let account = chain.blockchain.get_account(address).expect("the sender exists");
    let state_init = account.state_init().expect("the sender was deployed with a state init");
    let root = state_init.write_to_new_cell().expect("state init").into_cell().expect("cell");
    let mut partial = chain_block::BuilderData::with_raw(root.data().to_vec(), root.bit_length())
        .expect("the root's own bits");
    for index in 0..root.references_count() {
        let child = root.reference(index).expect("a child");
        let mut branch = chain_block::BuilderData::new();
        branch.set_type(chain_block::CellType::PrunedBranch);
        branch.append_u8(u8::from(chain_block::CellType::PrunedBranch)).expect("the type byte");
        branch.append_u8(1).expect("one stored hash, at merkle depth zero");
        branch.append_raw(child.repr_hash().as_slice(), 256).expect("the pruned hash");
        branch.append_u16(child.repr_depth()).expect("the pruned depth");
        partial
            .checked_append_reference(branch.into_cell().expect("a pruned branch"))
            .expect("a pruned child");
    }
    partial.into_cell().expect("a controller proof")
}

/// The code every sandbox account is deployed with, which is what the fixture admits.
///
/// One admitted code and many accounts is the shape of the real rule; the controller
/// contract's own behaviour is exercised in its own file, not here.
/// Put a configuration parameter into the configuration contract's own dictionary, and
/// let the chain adopt it.
///
/// Setting it only on the blockchain is not enough. Every rotation refreshes the chain's
/// configuration from this contract, so a parameter that lives only in the chain's view
/// disappears the moment a validator set takes over -- and a post-quantum instruction
/// whose global version went back to fourteen fails as an unknown opcode, which reads
/// like a broken contract rather than a lost parameter.
fn set_contract_parameter(chain: &mut Chain, index: i32, value: chain_block::Cell) {
    use chain_block::IBitstring;
    let mut account = chain
        .blockchain
        .get_account(&chain.config_contract)
        .expect("the configuration contract is deployed")
        .clone();
    let data = account.get_data().expect("storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let parameters = slice.checked_drain_reference().expect("the parameter dictionary");

    let mut dict = chain_block::HashmapE::with_hashmap(32, Some(parameters));
    let mut key = chain_block::BuilderData::new();
    key.append_i32(index).expect("the parameter index");
    let mut stored = chain_block::BuilderData::new();
    stored.checked_append_reference(value).expect("the parameter value");
    dict.set_builder(chain_block::SliceData::load_builder(key).expect("a key slice"), &stored)
        .expect("the parameter is stored");

    let mut rebuilt = chain_block::BuilderData::new();
    rebuilt
        .checked_append_reference(
            chain_block::HashmapType::data(&dict).expect("a non-empty dictionary").clone(),
        )
        .expect("parameters");
    rebuilt.checked_append_references_and_data(&slice).expect("the votes");
    account.set_data(rebuilt.into_cell().expect("storage"));
    chain.blockchain.set_account(chain.config_contract.clone(), account);

    chain
        .blockchain
        .set_config(configuration_from_contract(chain))
        .expect("the chain adopts the parameter");
}

fn admit_sender_code(chain: &mut Chain, who: &tos_sandbox::Treasury) {
    use chain_block::{GetRepresentationHash, IBitstring};
    let account = chain.blockchain.get_account(who.address()).expect("the sender exists");
    let state_init = account.state_init().expect("a state init");
    let code_hash = state_init.code().expect("code").repr_hash();

    let mut dict = chain_block::HashmapE::with_bit_len(256);
    dict.set(
        chain_block::SliceData::load_builder(
            chain_block::BuilderData::with_raw(code_hash.as_slice().to_vec(), 256).expect("a key"),
        )
        .expect("a key slice"),
        &chain_block::SliceData::default(),
    )
    .expect("insert");
    let mut value = chain_block::BuilderData::new();
    value.append_bit_one().expect("a non-empty policy");
    value
        .checked_append_reference(
            chain_block::HashmapType::data(&dict).expect("a non-empty dictionary").clone(),
        )
        .expect("the codes");

    set_contract_parameter(chain, 47, value.into_cell().expect("a controller policy"));
}

fn pq_stake_body(
    query_id: u64,
    validator: &PqValidator,
    stake_at: u32,
    max_factor: u32,
    signature: &[u8],
    proof: Option<chain_block::Cell>,
) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut body = chain_block::BuilderData::new();
    body.append_u32(PQ_STAKE_OP).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.append_u16(1).expect("algorithm");
    body.checked_append_reference(stored_bytes(&validator.public_key)).expect("public key");
    body.append_u32(stake_at).expect("election");
    body.append_u32(max_factor).expect("max factor");
    body.append_raw(&validator.adnl, 256).expect("adnl address");
    body.checked_append_reference(stored_bytes(signature)).expect("signature");
    match proof {
        Some(cell) => {
            body.append_bit_one().expect("a proof is present");
            body.checked_append_reference(cell).expect("the controller proof");
        }
        None => {
            body.append_bit_zero().expect("no proof");
        }
    }
    body.into_cell().expect("stake body")
}

/// The post-quantum instruction is gated on global version 16, and the zerostate declares
/// 14. Raising it here is what N3 assumes and the activation gate will make true; the
/// classical tests above stay on the zerostate's version, which is what keeps them
/// evidence about the chain as it is.
fn raise_to_post_quantum_version(chain: &mut Chain) {
    let mut config = chain.blockchain.config_params().clone();
    let version = match config.config(8).expect("parameter 8") {
        Some(chain_block::ConfigParamEnum::ConfigParam8(v)) => v.global_version,
        _ => panic!("the chain states no global version"),
    };
    assert!(version.version < 16, "the fixture is raising a version that is already there");
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParam8(chain_block::ConfigParam8 {
            global_version: chain_block::GlobalVersion { version: 16, ..version },
        }))
        .expect("set the global version");
    let raised = config
        .config_params
        .get(
            chain_block::SliceData::load_builder({
                use chain_block::IBitstring;
                let mut key = chain_block::BuilderData::new();
                key.append_i32(8).expect("the parameter index");
                key
            })
            .expect("a key slice"),
        )
        .expect("lookup")
        .expect("the version was just set")
        .reference(0)
        .expect("the parameter value is stored behind a reference");
    set_contract_parameter(chain, 8, raised);

    // A post-quantum stake is admitted only from an account born with a controller code
    // the configuration admits. Every sandbox account shares one code, so admitting it
    // admits the senders these tests use -- one code, many accounts, which is the shape
    // of the real rule. What a real controller does with that authority is exercised in
    // `validator_controller_sandbox.rs`.
    let probe = chain.blockchain.treasury("controller-policy-probe", TOS).expect("an account");
    admit_sender_code(chain, &probe);
}

/// Send a post-quantum stake, signing for whichever sender is named.
fn pq_stake_from(
    chain: &mut Chain,
    from: &tos_sandbox::Treasury,
    signed_for: &tos_sandbox::Treasury,
    validator: &PqValidator,
    election: u32,
    query_id: u64,
    value: u64,
) -> tos_sandbox::SendResult {
    pq_stake_with_max_factor(chain, from, signed_for, validator, election, query_id, value, 0x10000)
}

/// The same stake, signed and sent with a stated maximum stake factor, so a request that
/// is well formed apart from that factor can be built.
#[allow(clippy::too_many_arguments)]
fn pq_stake_with_max_factor(
    chain: &mut Chain,
    from: &tos_sandbox::Treasury,
    signed_for: &tos_sandbox::Treasury,
    validator: &PqValidator,
    election: u32,
    query_id: u64,
    value: u64,
    max_factor: u32,
) -> tos_sandbox::SendResult {
    let global_id = match chain.blockchain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("the chain states no network id, so nothing can sign for it"),
    };
    let validator_id =
        chain_block::UInt256::from_slice(&signed_for.address().address().get_bytestring(0));
    let preimage = pq_stake_preimage(
        global_id,
        election,
        max_factor,
        &validator_id,
        &validator.key_id(),
        &validator.adnl,
    );
    let signature = validator.sign(&preimage);
    // A first registration proves what its sender was deployed as; a controller the book
    // already knows is re-checked against the policy instead.
    let proof = Some(controller_proof(chain, from));
    chain
        .blockchain
        .send_message(from.build_message(
            &chain.elector,
            value,
            true,
            Some(pq_stake_body(query_id, validator, election, max_factor, &signature, proof)),
        ))
        .expect("the stake is delivered")
}

fn pq_stake(
    chain: &mut Chain,
    from: &tos_sandbox::Treasury,
    validator: &PqValidator,
    election: u32,
    query_id: u64,
    value: u64,
) -> tos_sandbox::SendResult {
    let sender = from.clone();
    pq_stake_from(chain, from, &sender, validator, election, query_id, value)
}

/// The election's post-quantum book: members by controller, and the reverse index.
fn pq_book(chain: &Chain) -> (chain_block::HashmapE, chain_block::HashmapE) {
    let account = chain.blockchain.get_account(&chain.elector).expect("the elector is deployed");
    let data = account.get_data().expect("the elector has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let elect = next_dictionary(&mut slice, 32);
    let root = chain_block::HashmapType::data(&elect).expect("an active election").clone();
    let mut es = chain_block::SliceData::load_cell(root).expect("the election");
    es.get_next_u32().expect("elect_at");
    es.get_next_u32().expect("elect_close");
    for _ in 0..2 {
        let bytes = es.get_next_int(4).expect("an amount length") as usize;
        if bytes > 0 {
            es.get_next_bits(bytes * 8).expect("an amount");
        }
    }
    es.get_next_bit().expect("failed");
    es.get_next_bit().expect("finished");
    let members = next_dictionary(&mut es, 256);
    let key_owner = next_dictionary(&mut es, 256);
    (members, key_owner)
}

/// What a post-quantum controller has placed, according to its own member record.
fn pq_stake_of(chain: &Chain, controller: &tos_sandbox::Treasury) -> u128 {
    let (members, _) = pq_book(chain);
    let mut record = members
        .get(controller.address().address().clone())
        .expect("lookup")
        .expect("the controller is registered");
    let bytes = record.get_next_int(4).expect("a stake length") as usize;
    let mut stake = 0u128;
    if bytes > 0 {
        for byte in record.get_next_bits(bytes * 8).expect("a stake") {
            stake = (stake << 8) | u128::from(byte);
        }
    }
    stake
}

fn pq_member_key_id(
    chain: &Chain,
    controller: &tos_sandbox::Treasury,
) -> Option<chain_block::UInt256> {
    let (members, _) = pq_book(chain);
    let record = members.get(controller.address().address().clone()).expect("lookup")?;
    let mut record = record;
    let bytes = record.get_next_int(4).expect("stake length") as usize;
    if bytes > 0 {
        record.get_next_bits(bytes * 8).expect("stake");
    }
    record.get_next_u32().expect("registered at");
    record.get_next_u32().expect("max factor");
    record.get_next_u16().expect("algorithm");
    Some(chain_block::UInt256::from_slice(&record.get_next_bits(256).expect("key id")))
}

fn pq_key_holder(chain: &Chain, key_id: &chain_block::UInt256) -> Option<chain_block::UInt256> {
    let (_, key_owner) = pq_book(chain);
    let owner = key_owner
        .get(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(key_id.as_slice().to_vec(), 256).expect("key"),
            )
            .expect("key slice"),
        )
        .expect("lookup")?;
    let mut owner = owner;
    Some(chain_block::UInt256::from_slice(&owner.get_next_bits(256).expect("an owner")))
}

#[test]
fn a_signed_post_quantum_stake_registers_the_sender_as_the_validator() {
    let (mut chain, treasury, election) = open_election("pq-validator-a", 40_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(0);

    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    for (_, tx) in &result.transactions {
        eprintln!("tx: {:?}", tx.read_description().expect("description"));
    }
    result.expect_exit_code(0);
    assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "a correctly signed stake was refused");

    let controller =
        chain_block::UInt256::from_slice(&treasury.address().address().get_bytestring(0));
    assert_eq!(
        pq_member_key_id(&chain, &treasury),
        Some(validator.key_id()),
        "the member record does not hold the key that was registered"
    );
    assert_eq!(
        pq_key_holder(&chain, &validator.key_id()),
        Some(controller),
        "the key was not claimed by the account that sent the stake"
    );
}

/// What the compute phase of the first transaction spent.
fn compute_gas(result: &tos_sandbox::SendResult) -> u64 {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    match transaction.read_description().expect("description") {
        chain_block::TransactionDescr::Ordinary(descr) => match descr.compute_ph {
            chain_block::TrComputePhase::Vm(vm) => vm.gas_used.as_u64(),
            other => panic!("the compute phase did not run: {other:?}"),
        },
        other => panic!("not an ordinary transaction: {other:?}"),
    }
}

#[test]
fn a_post_quantum_stake_signed_by_another_key_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-validator-b", 40_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(1);
    let impostor = PqValidator::new(2);

    // The request carries the validator's key, and a signature by a key that is not it.
    let global_id = match chain.blockchain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("no network id"),
    };
    let validator_id =
        chain_block::UInt256::from_slice(&treasury.address().address().get_bytestring(0));
    let preimage = pq_stake_preimage(
        global_id,
        election,
        0x10000,
        &validator_id,
        &validator.key_id(),
        &validator.adnl,
    );
    let signature = impostor.sign(&preimage);
    let proof = controller_proof(&chain, &treasury);
    let result = chain
        .blockchain
        .send_message(treasury.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(pq_stake_body(1, &validator, election, 0x10000, &signature, Some(proof))),
        ))
        .expect("the stake is delivered");

    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_BAD_SIGNATURE),
        "a stake signed by another key was accepted, or refused for another reason"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "a refused stake was registered anyway");
}

#[test]
fn a_post_quantum_stake_signed_for_another_sender_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-validator-c", 40_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let elsewhere = chain.blockchain.treasury("pq-validator-c-elsewhere", TOS).expect("an account");
    let validator = PqValidator::new(3);

    // Signed correctly, by the right key, for a different sender. The validator identity
    // is the account the elector sees, so this signature authorises nothing here.
    let result =
        pq_stake_from(&mut chain, &treasury, &elsewhere, &validator, election, 1, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_BAD_SIGNATURE),
        "a stake signed for another sender was accepted"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None);
}

#[test]
fn a_key_already_registered_by_another_controller_is_returned() {
    let (mut chain, first, election) = open_election("pq-validator-d", 40_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let second =
        chain.blockchain.treasury("pq-validator-d-second", 40_000 * TOS).expect("an account");
    let validator = PqValidator::new(4);

    assert_eq!(
        reply(&pq_stake(&mut chain, &first, &validator, election, 1, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0)
    );
    // The second controller signs correctly for itself, with the same consensus key. Only
    // the rule that a key belongs to one controller can refuse this.
    let result = pq_stake(&mut chain, &second, &validator, election, 2, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_ANOTHER_ADDRESS),
        "two controllers registered the same consensus key"
    );
    assert_eq!(
        pq_key_holder(&chain, &validator.key_id()),
        Some(chain_block::UInt256::from_slice(&first.address().address().get_bytestring(0))),
        "the refused registration moved the key"
    );
}

/// A key released by a rotation is registrable by the controller that was refused it.
///
/// The book and its reverse index are two halves of one fact, and the half that decides
/// admission is the index. Removing a key from it on rotation is only meaningful if the
/// removal is what a later registration sees; an index that merely looked empty to a
/// getter, while the member record still spoke for the key, would leave the key
/// permanently unusable by anyone.
#[test]
fn a_key_released_by_a_rotation_is_registrable_by_the_controller_it_was_refused_to() {
    let (mut chain, first, election) = open_election("pq-release", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let second = chain.blockchain.treasury("pq-release-second", 60_000 * TOS).expect("an account");
    let contested = PqValidator::new(12);
    let rotated = PqValidator::new(13);

    assert_eq!(
        reply(&pq_stake(&mut chain, &first, &contested, election, 1, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "the first controller could not register the contested key"
    );
    assert_eq!(
        reply(&pq_stake(&mut chain, &second, &contested, election, 2, 11_000 * TOS)),
        (STAKE_RETURNED, REASON_ANOTHER_ADDRESS),
        "the second controller took a key that was already held"
    );

    assert_eq!(
        reply(&pq_stake(&mut chain, &first, &rotated, election, 3, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "the holder could not rotate away from the contested key"
    );
    assert_eq!(
        reply(&pq_stake(&mut chain, &second, &contested, election, 4, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "the released key stayed unusable by anyone"
    );

    let first_id = chain_block::UInt256::from_slice(&first.address().address().get_bytestring(0));
    let second_id = chain_block::UInt256::from_slice(&second.address().address().get_bytestring(0));
    assert_eq!(pq_member_key_id(&chain, &first), Some(rotated.key_id()));
    assert_eq!(pq_member_key_id(&chain, &second), Some(contested.key_id()));
    assert_eq!(pq_key_holder(&chain, &rotated.key_id()), Some(first_id));
    assert_eq!(
        pq_key_holder(&chain, &contested.key_id()),
        Some(second_id),
        "the index and the member records disagree about who holds the contested key"
    );
}

#[test]
fn a_controller_rotates_its_key_and_releases_the_one_it_held() {
    let (mut chain, treasury, election) = open_election("pq-validator-e", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let held = PqValidator::new(5);
    let rotated = PqValidator::new(6);

    let first = pq_stake(&mut chain, &treasury, &held, election, 1, 11_000 * TOS);
    assert_eq!(reply(&first), (STAKE_ACCEPTED, 0));
    let registration_gas = compute_gas(&first);

    let second = pq_stake(&mut chain, &treasury, &rotated, election, 2, 11_000 * TOS);
    assert_eq!(
        reply(&second),
        (STAKE_ACCEPTED, 0),
        "a rotation by the registered controller was refused"
    );
    let rotation_gas = compute_gas(&second);

    assert_eq!(
        pq_member_key_id(&chain, &treasury),
        Some(rotated.key_id()),
        "the member record still holds the key it rotated away from"
    );
    assert_eq!(
        pq_key_holder(&chain, &held.key_id()),
        None,
        "the released key is still claimed, so nobody can ever register it"
    );
    assert_eq!(
        pq_key_holder(&chain, &rotated.key_id()),
        Some(chain_block::UInt256::from_slice(&treasury.address().address().get_bytestring(0)))
    );

    // The deferred measurements: a whole stake transaction, and a rotation, which does
    // the same work plus the removal from the reverse index.
    eprintln!("post-quantum stake: {registration_gas} gas; rotation: {rotation_gas} gas");
    // The elector is a special account, allowed seventy million gas by the zerostate's
    // masterchain prices. The point of the figure is how far under that it is.
    assert!(
        rotation_gas < 1_000_000,
        "a rotation costs {rotation_gas} gas, over what an ordinary transaction may spend"
    );
    assert!(
        rotation_gas >= registration_gas,
        "a rotation does strictly more work than a registration but cost less"
    );
}

/// Rewrite the open election with `book_fields` of the post-quantum book still present,
/// each of them an empty dictionary.
///
/// Zero is the storage an upgrade leaves behind: the configuration contract may replace
/// the elector's code while an election is open, and the upgrade hook sets the new code
/// without migrating a single cell, so the first thing the new code reads is an election
/// the old code wrote. One is a shape no version has ever written, and is here to show
/// that the election is read as one of the two shapes that exist and never as something
/// in between.
fn rewrite_election_with_book_fields(chain: &mut Chain, book_fields: usize) {
    use chain_block::IBitstring;
    let mut account =
        chain.blockchain.get_account(&chain.elector).expect("the elector is deployed").clone();
    let data = account.get_data().expect("the elector has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let elect = next_dictionary(&mut slice, 32);
    let root = chain_block::HashmapType::data(&elect).expect("an active election").clone();
    let mut es = chain_block::SliceData::load_cell(root).expect("the election");

    let mut legacy = chain_block::BuilderData::new();
    legacy.append_u32(es.get_next_u32().expect("elect_at")).expect("elect_at");
    legacy.append_u32(es.get_next_u32().expect("elect_close")).expect("elect_close");
    for _ in 0..2 {
        let bytes = es.get_next_int(4).expect("an amount length") as usize;
        legacy.append_bits(bytes, 4).expect("an amount length");
        if bytes > 0 {
            let amount = es.get_next_bits(bytes * 8).expect("an amount");
            legacy.append_raw(&amount, bytes * 8).expect("an amount");
        }
    }
    for field in ["failed", "finished"] {
        if es.get_next_bit().expect(field) {
            legacy.append_bit_one().expect(field);
        } else {
            legacy.append_bit_zero().expect(field);
        }
    }
    for _ in 0..book_fields {
        legacy.append_bit_zero().expect("an empty book dictionary");
    }

    let mut rebuilt = chain_block::BuilderData::new();
    rebuilt.append_bit_one().expect("an active election");
    rebuilt
        .checked_append_reference(legacy.into_cell().expect("the election"))
        .expect("the election");
    rebuilt.checked_append_references_and_data(&slice).expect("the rest of the storage");
    account.set_data(rebuilt.into_cell().expect("storage"));
    chain.blockchain.set_account(chain.elector.clone(), account);
}

#[test]
fn an_election_opened_before_the_upgrade_is_read_and_written_again() {
    let (mut chain, treasury, election) = open_election("legacy-elect", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let opening =
        pq_stake(&mut chain, &treasury, &PqValidator::new(0xf1), election, 1, 11_000 * TOS);
    assert_eq!(reply(&opening), (STAKE_ACCEPTED, 0), "the fixture needs a member");
    let placed = declared_total_stake(&chain);
    assert_ne!(placed, 0, "the fixture needs a running total to read back");
    rewrite_election_with_book_fields(&mut chain, 0);

    // Every entry point reads the election first, so an unreadable one stops the elector
    // altogether: no stake is accepted and no election ever closes.
    assert_eq!(
        declared_total_stake(&chain),
        placed,
        "an election opened by the previous code could not be read back"
    );

    let validator = PqValidator::new(9);
    let result = pq_stake(&mut chain, &treasury, &validator, election, 2, 12_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_ACCEPTED, 0),
        "the elector stopped working on the storage an upgrade leaves behind"
    );
    assert_eq!(
        pq_member_key_id(&chain, &treasury),
        Some(validator.key_id()),
        "the book was not created for an election that was opened without one"
    );
}

/// A stake for an election that is not the open one, refused for a reason that is
/// decided without looking at the key or the signature.
///
/// Anyone can send such a message, and the elector pays for what it does with it out of
/// the masterchain block's gas. Verifying a post-quantum signature is an order of
/// magnitude more expensive than everything else this contract does, so if it happened
/// before the cheap refusals, every one of those messages would cost the chain a
/// verification it never needed.
#[test]
fn a_stake_refused_without_its_key_does_not_pay_for_a_verification() {
    let (mut chain, treasury, election) = open_election("pq-refusal-cost", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(11);

    let refused = pq_stake(&mut chain, &treasury, &validator, election + 1, 1, 11_000 * TOS);
    assert_eq!(
        reply(&refused),
        (STAKE_RETURNED, REASON_WRONG_ELECTION),
        "the fixture must be refused for its election and nothing else"
    );
    let refusal = compute_gas(&refused);

    let accepted = pq_stake(&mut chain, &treasury, &validator, election, 2, 11_000 * TOS);
    assert_eq!(
        reply(&accepted),
        (STAKE_ACCEPTED, 0),
        "the fixture needs a registration to compare"
    );
    let registration = compute_gas(&accepted);

    assert!(
        refusal * 4 < registration,
        "refusing a stake for its election costs {refusal} gas against {registration} for a \
         registration, so the verification is being paid for before the refusal"
    );
}

#[test]
fn half_a_post_quantum_book_is_refused_rather_than_read_as_empty() {
    let (mut chain, treasury, election) = open_election("legacy-partial", 40_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let opening =
        pq_stake(&mut chain, &treasury, &PqValidator::new(0xf3), election, 1, 11_000 * TOS);
    assert_eq!(reply(&opening), (STAKE_ACCEPTED, 0), "the fixture needs a member");

    // Neither version of the elector ever wrote one dictionary of the book. Reading such
    // an election as though the book were absent would hide the half that is there, so it
    // must throw instead: the two shapes that exist are the only ones accepted.
    rewrite_election_with_book_fields(&mut chain, 1);
    let result = chain
        .blockchain
        .run_get_method(&chain.elector, "participant_list_extended", vec![])
        .expect("the elector answers");
    assert_ne!(
        result.exit_code, 0,
        "an election in a shape no version ever wrote was read as a valid one"
    );
}

#[test]
fn a_post_quantum_top_up_adds_only_the_money_it_brings_to_the_election_total() {
    let (mut chain, treasury, election) = open_election("pq-validator-g", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(8);

    let first = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    assert_eq!(reply(&first), (STAKE_ACCEPTED, 0), "the first stake was refused");
    assert_eq!(
        declared_total_stake(&chain),
        pq_stake_of(&chain, &treasury),
        "a single registration already disagrees with what the member holds"
    );

    let second = pq_stake(&mut chain, &treasury, &validator, election, 2, 12_000 * TOS);
    assert_eq!(reply(&second), (STAKE_ACCEPTED, 0), "topping up an own stake was refused");
    assert_eq!(
        pq_stake_of(&chain, &treasury),
        (23_000 * TOS - 2 * TOS) as u128,
        "two stakes from one controller must accumulate, less the two confirmations"
    );

    // The election closes on this running total, so counting a top-up twice lets an
    // election reach the minimum total stake on money nobody placed, and raises the
    // floor under which a later stake from anyone else is refused as too small.
    assert_eq!(
        declared_total_stake(&chain),
        pq_stake_of(&chain, &treasury),
        "the election counts more stake than its only member placed"
    );
}

/// The refusals that the cheap checks are responsible for, now that they run before the
/// verification. A reordering that made one of them unreachable would leave a request the
/// contract intends to refuse being refused by something else, or not at all.
#[test]
fn a_stake_stating_a_factor_below_one_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-factor", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(14);

    let result = pq_stake_with_max_factor(
        &mut chain,
        &treasury,
        &treasury,
        &validator,
        election,
        1,
        11_000 * TOS,
        0x10000 - 1,
    );
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_FACTOR_BELOW_ONE),
        "a validator asked to be weighted below the stake it placed"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");
}

#[test]
fn a_stake_below_the_minimum_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-minimum", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(15);

    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 2 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_BELOW_MINIMUM),
        "a stake under the minimum was registered"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");
}

/// The window between an election's closing time and the tick that conducts it.
///
/// Nothing runs the elector on a schedule of its own: it is ticked, and the tick that
/// finds `now() >= elect_close` is what conducts the election and marks it finished.
/// Admitting a stake, or a rotation, for as long as that tick has not landed would make
/// membership depend on scheduling rather than on the election's own boundary.
/// Every distinct cell in a tree, and the bits they hold.
fn tree_size(root: &chain_block::Cell) -> (usize, usize) {
    fn walk(
        cell: &chain_block::Cell,
        seen: &mut std::collections::HashSet<chain_block::UInt256>,
        bits: &mut usize,
    ) {
        if !seen.insert(cell.repr_hash()) {
            return;
        }
        *bits += cell.bit_length();
        for index in 0..cell.references_count() {
            walk(&cell.reference(index).expect("a reference"), seen, bits);
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut bits = 0;
    walk(root, &mut seen, &mut bits);
    (seen.len(), bits)
}

/// What a stake actually costs to carry, measured on the request the contract now reads.
///
/// The design was sized against an estimate of this message before the request had its
/// final shape. The figures below are the shape that shipped, so a change to the carrier
/// has to be re-approved rather than absorbed.
#[test]
fn a_stake_request_is_the_size_the_design_was_sized_for() {
    let validator = PqValidator::new(23);
    let bare = pq_stake_body(1, &validator, 1_789_434_000, 0x10000, &vec![0u8; 2420], None);
    assert_eq!(
        tree_size(&bare),
        (34, 30_353),
        "a stake carrying no controller proof changed shape"
    );
}

/// The weight factor a member registered with, as its own record holds it.
fn pq_member_max_factor(chain: &Chain, controller: &tos_sandbox::Treasury) -> u32 {
    let (members, _) = pq_book(chain);
    let mut record = members
        .get(controller.address().address().clone())
        .expect("lookup")
        .expect("the controller is registered");
    let bytes = record.get_next_int(4).expect("a stake length") as usize;
    if bytes > 0 {
        record.get_next_bits(bytes * 8).expect("a stake");
    }
    record.get_next_u32().expect("registered at");
    record.get_next_u32().expect("max factor")
}

/// A stake states the weight factor it wants, and that statement is both what the
/// signature covers and what the book records.
///
/// Signing a field is not the same as committing the request's value of it: a contract
/// that built its preimage from a constant would still refuse every signature made over a
/// different one, and every negative case would pass. Only a request carrying a value
/// other than the default can tell the two apart.
#[test]
fn a_stake_registers_the_weight_factor_it_asked_for() {
    let (mut chain, treasury, election) = open_election("pq-factor-kept", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(19);
    let asked = 0x2_5000;

    let result = pq_stake_with_max_factor(
        &mut chain,
        &treasury,
        &treasury,
        &validator,
        election,
        1,
        11_000 * TOS,
        asked,
    );
    assert_eq!(
        reply(&result),
        (STAKE_ACCEPTED, 0),
        "a stake asking for a weight factor other than the default was refused"
    );
    assert_eq!(
        pq_member_max_factor(&chain, &treasury),
        asked,
        "the book recorded a weight factor the request did not ask for"
    );
}

/// The fields the preimage commits to, so that what is signed can be made to differ from
/// what is sent while everything else stays valid.
#[derive(Clone)]
struct SignedFields {
    global_id: i32,
    stake_at: u32,
    max_factor: u32,
    algorithm_id: u16,
    adnl: [u8; 32],
    key_id: chain_block::UInt256,
}

/// Send a well-formed stake whose signature was made over `signed` and under `context`.
///
/// The request itself is always the valid one, so the contract reaches the verification
/// with nothing else to object to, and each case isolates one field of the preimage.
fn pq_stake_signed_over(
    chain: &mut Chain,
    from: &tos_sandbox::Treasury,
    validator: &PqValidator,
    election: u32,
    signed: &SignedFields,
    context: &[u8],
) -> tos_sandbox::SendResult {
    let validator_id =
        chain_block::UInt256::from_slice(&from.address().address().get_bytestring(0));
    let preimage = pq_stake_preimage_for(
        signed.global_id,
        signed.stake_at,
        signed.max_factor,
        &validator_id,
        signed.algorithm_id,
        &signed.key_id,
        &signed.adnl,
    );
    let signature = validator.sign_under(&preimage, context);
    chain
        .blockchain
        .send_message(from.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(pq_stake_body(
                1,
                validator,
                election,
                0x10000,
                &signature,
                Some(controller_proof(chain, from)),
            )),
        ))
        .expect("the stake is delivered")
}

/// Each field of the preimage, changed on its own, must cost the signature its validity.
///
/// The request is valid in every case; only what was signed differs. A field the contract
/// reads from the request but leaves out of the bytes it verifies would be a field an
/// authorised signature does not actually authorise, and this is the test that says which
/// fields those bytes cover.
#[test]
fn every_signed_field_of_a_stake_is_covered_by_its_signature() {
    let (mut chain, treasury, election) = open_election("pq-binding", 200_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(17);
    let other = PqValidator::new(18);

    let global_id = match chain.blockchain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("the chain states no network id"),
    };
    let honest = SignedFields {
        global_id,
        stake_at: election,
        max_factor: 0x10000,
        algorithm_id: 1,
        adnl: validator.adnl,
        key_id: validator.key_id(),
    };

    // The fixture has to be able to succeed, or every case below would pass for nothing.
    let accepted = pq_stake_signed_over(
        &mut chain,
        &treasury,
        &validator,
        election,
        &honest,
        ELECTION_CONTEXT,
    );
    assert_eq!(reply(&accepted), (STAKE_ACCEPTED, 0), "the honest fixture was refused");

    let cases: Vec<(&str, SignedFields, &[u8])> = vec![
        (
            "another network",
            SignedFields { global_id: global_id ^ 1, ..honest.clone() },
            ELECTION_CONTEXT,
        ),
        (
            "another election",
            SignedFields { stake_at: election - 1, ..honest.clone() },
            ELECTION_CONTEXT,
        ),
        (
            "another weight factor",
            SignedFields { max_factor: 0x20000, ..honest.clone() },
            ELECTION_CONTEXT,
        ),
        (
            "another transport address",
            SignedFields { adnl: [0x5e; 32], ..honest.clone() },
            ELECTION_CONTEXT,
        ),
        (
            "another key",
            SignedFields { key_id: other.key_id(), ..honest.clone() },
            ELECTION_CONTEXT,
        ),
        // While one suite is admitted this case cannot tell a preimage that commits the
        // request's suite from one that commits the constant 1, because they are the same
        // value. What distinguishes them is a request carrying a second admitted suite,
        // which is the positive case to add on the day there is one.
        ("another suite", SignedFields { algorithm_id: 7, ..honest.clone() }, ELECTION_CONTEXT),
        ("another purpose", honest.clone(), CONFIG_VOTE_CONTEXT),
    ];

    for (what, signed, context) in cases {
        let result =
            pq_stake_signed_over(&mut chain, &treasury, &validator, election, &signed, context);
        assert_eq!(
            reply(&result),
            (STAKE_RETURNED, REASON_BAD_SIGNATURE),
            "a stake signed for {what} was accepted, so that field is not covered"
        );
    }
}

/// A rotation that is refused leaves the controller exactly as it was.
///
/// The refusal happens between reading the book and writing it, so the question is
/// whether anything was released on the way to it: a controller left holding neither its
/// old key nor the new one would be a validator nobody can reach, and a key released
/// without being replaced is one another controller may take.
#[test]
fn a_refused_rotation_leaves_both_controllers_as_they_were() {
    let (mut chain, mine, election) = open_election("pq-atomic", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let theirs = chain.blockchain.treasury("pq-atomic-other", 60_000 * TOS).expect("an account");
    let held = PqValidator::new(20);
    let wanted = PqValidator::new(21);

    assert_eq!(
        reply(&pq_stake(&mut chain, &mine, &held, election, 1, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0)
    );
    assert_eq!(
        reply(&pq_stake(&mut chain, &theirs, &wanted, election, 2, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0)
    );
    let total_before = declared_total_stake(&chain);

    // A rotation to a key the other controller holds. It cannot be granted.
    assert_eq!(
        reply(&pq_stake(&mut chain, &mine, &wanted, election, 3, 11_000 * TOS)),
        (STAKE_RETURNED, REASON_ANOTHER_ADDRESS),
        "a controller rotated onto a key another one holds"
    );

    let mine_id = chain_block::UInt256::from_slice(&mine.address().address().get_bytestring(0));
    let theirs_id = chain_block::UInt256::from_slice(&theirs.address().address().get_bytestring(0));
    assert_eq!(
        pq_member_key_id(&chain, &mine),
        Some(held.key_id()),
        "the refused rotation moved the controller off the key it held"
    );
    assert_eq!(
        pq_key_holder(&chain, &held.key_id()),
        Some(mine_id),
        "the refused rotation released the key it was rotating away from"
    );
    assert_eq!(
        pq_key_holder(&chain, &wanted.key_id()),
        Some(theirs_id),
        "the refused rotation took the key from the controller that holds it"
    );
    assert_eq!(
        declared_total_stake(&chain),
        total_before,
        "the refused rotation was counted into the election total"
    );
}

/// A request naming a suite the contract does not admit is refused before it is read as
/// a key.
///
/// One suite is admitted, and a second would be a protocol change rather than a
/// configuration value. The guard that says so has to be reachable from a request, or it
/// is a claim about a constant instead of a rule about what arrives.
#[test]
fn a_stake_naming_an_unadmitted_suite_is_refused() {
    use chain_block::IBitstring;
    let (mut chain, treasury, election) = open_election("pq-suite", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(24);

    let mut body = chain_block::BuilderData::new();
    body.append_u32(PQ_STAKE_OP).expect("operation");
    body.append_u64(1).expect("query id");
    body.append_u16(7).expect("a suite that is not admitted");
    body.checked_append_reference(stored_bytes(&validator.public_key)).expect("public key");
    body.append_u32(election).expect("election");
    body.append_u32(0x10000).expect("max factor");
    body.append_raw(&validator.adnl, 256).expect("adnl address");
    body.checked_append_reference(stored_bytes(&vec![0u8; 2420])).expect("signature");
    body.append_bit_one().expect("a proof is present");
    body.checked_append_reference(controller_proof(&chain, &treasury))
        .expect("the controller proof");

    let result = chain
        .blockchain
        .send_message(treasury.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(body.into_cell().expect("stake body")),
        ))
        .expect("the stake is delivered");
    result.expect_exit_code(ERROR_UNADMITTED_ALGORITHM);
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");
}

#[test]
fn a_stake_after_the_election_closes_is_returned_before_the_tick_conducts_it() {
    let (mut chain, treasury, election) = open_election("pq-after-close", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(16);

    chain.blockchain.set_now(election - chain.elect_end_before);
    // Deliberately no tick: the election is closed by the clock and not yet by its state.
    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_NO_ELECTION),
        "a stake was admitted to an election that may already be conducted"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");
}

/// Reasons the elector refuses a stake over the controller it came from.
const REASON_PROOF_MISSING: u32 = 8;
const REASON_PROOF_MISMATCH: u32 = 9;
const REASON_CODE_NOT_ADMITTED: u32 = 10;
const REASON_NO_POLICY: u32 = 11;
const REASON_CODE_RETIRED: u32 = 12;

/// Replace the admitted controller codes with `codes`, or remove the policy entirely.
fn set_policy(chain: &mut Chain, codes: &[chain_block::UInt256]) {
    use chain_block::IBitstring;
    let mut config = chain.blockchain.config_params().clone();
    let mut value = chain_block::BuilderData::new();
    let mut dict = chain_block::HashmapE::with_bit_len(256);
    for code in codes {
        dict.set(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(code.as_slice().to_vec(), 256).expect("a key"),
            )
            .expect("a key slice"),
            &chain_block::SliceData::default(),
        )
        .expect("insert");
    }
    match chain_block::HashmapType::data(&dict) {
        Some(root) => {
            value.append_bit_one().expect("a non-empty policy");
            value.checked_append_reference(root.clone()).expect("the codes");
        }
        None => {
            value.append_bit_zero().expect("an empty policy");
        }
    }
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParamAny(
            47,
            value.into_cell().expect("a controller policy"),
        ))
        .expect("the policy is installed");
    chain.blockchain.set_config(config).expect("the configuration is replaced");
}

/// The code an account was deployed with.
fn sender_code_hash(chain: &Chain, who: &tos_sandbox::Treasury) -> chain_block::UInt256 {
    use chain_block::GetRepresentationHash;
    let account = chain.blockchain.get_account(who.address()).expect("the sender exists");
    account.state_init().expect("a state init").code().expect("code").repr_hash()
}

/// An account whose birth code nothing admits cannot obtain validator authority, however
/// correct everything else about its request is.
#[test]
fn a_stake_from_an_unadmitted_controller_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-unadmitted", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(25);

    // A policy that admits some other code: the sender's is well formed and unlisted.
    set_policy(&mut chain, &[chain_block::UInt256::from_slice(&[0x11; 32])]);
    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_CODE_NOT_ADMITTED),
        "an account nothing admits obtained validator authority"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");

    // No policy at all admits nobody, rather than everybody.
    let mut config = chain.blockchain.config_params().clone();
    config
        .config_params
        .remove(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(47u32.to_be_bytes().to_vec(), 32)
                    .expect("a key"),
            )
            .expect("a key slice"),
        )
        .expect("remove the policy");
    chain.blockchain.set_config(config).expect("the configuration is replaced");
    let result = pq_stake(&mut chain, &treasury, &validator, election, 2, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_NO_POLICY),
        "with no policy installed the elector admitted a controller"
    );
}

/// A proof that does not reconstruct the sender's own address proves nothing about it.
#[test]
fn a_stake_carrying_another_accounts_proof_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-foreign-proof", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let other = chain.blockchain.treasury("pq-foreign-proof-other", TOS).expect("an account");
    let validator = PqValidator::new(26);

    let global_id = match chain.blockchain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("the chain states no network id"),
    };
    let validator_id =
        chain_block::UInt256::from_slice(&treasury.address().address().get_bytestring(0));
    let preimage = pq_stake_preimage(
        global_id,
        election,
        0x10000,
        &validator_id,
        &validator.key_id(),
        &validator.adnl,
    );
    let signature = validator.sign(&preimage);
    let foreign = controller_proof(&chain, &other);
    let result = chain
        .blockchain
        .send_message(treasury.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(pq_stake_body(1, &validator, election, 0x10000, &signature, Some(foreign))),
        ))
        .expect("the stake is delivered");
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_PROOF_MISMATCH),
        "a proof of another account admitted this one"
    );

    // And a first registration with no proof at all says so, rather than being admitted.
    let bare = chain
        .blockchain
        .send_message(treasury.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(pq_stake_body(2, &validator, election, 0x10000, &signature, None)),
        ))
        .expect("the stake is delivered");
    assert_eq!(
        reply(&bare),
        (STAKE_RETURNED, REASON_PROOF_MISSING),
        "a first registration without a proof was admitted"
    );
}

/// An account with a controller code of its own, which the sandbox's shared treasury code
/// cannot provide: every treasury is born from the same code.
///
/// The account is never deployed. The elector cannot read a sender's state in any case;
/// what it needs is a message from that address and a proof of what the address commits
/// to, and the fixture can produce both.
fn account_with_code(seed: u8) -> (MsgAddressInt, chain_block::Cell, chain_block::UInt256) {
    use chain_block::{GetRepresentationHash, IBitstring, Serializable};
    let mut code = chain_block::BuilderData::new();
    code.append_raw(&vec![seed; 32], 256).expect("code bits");
    let code = code.into_cell().expect("a code cell");
    let mut data = chain_block::BuilderData::new();
    data.append_u32(seed as u32).expect("data");
    let state = chain_block::StateInit::with_code_and_data(
        code.clone(),
        data.into_cell().expect("a data cell"),
    );
    let root = state.write_to_new_cell().expect("state init").into_cell().expect("cell");
    let address = MsgAddressInt::with_params(-1, root.hash(0)).expect("address");

    let mut partial = chain_block::BuilderData::with_raw(root.data().to_vec(), root.bit_length())
        .expect("the root's own bits");
    for index in 0..root.references_count() {
        let child = root.reference(index).expect("a child");
        let mut branch = chain_block::BuilderData::new();
        branch.set_type(chain_block::CellType::PrunedBranch);
        branch.append_u8(u8::from(chain_block::CellType::PrunedBranch)).expect("the type byte");
        branch.append_u8(1).expect("one stored hash");
        branch.append_raw(child.repr_hash().as_slice(), 256).expect("the pruned hash");
        branch.append_u16(child.repr_depth()).expect("the pruned depth");
        partial
            .checked_append_reference(branch.into_cell().expect("a pruned branch"))
            .expect("a pruned child");
    }
    (address, partial.into_cell().expect("a proof"), code.repr_hash())
}

/// Send a stake from an address the fixture names, with the proof that address commits to.
fn pq_stake_as(
    chain: &mut Chain,
    sender: &MsgAddressInt,
    proof: chain_block::Cell,
    validator: &PqValidator,
    election: u32,
    query_id: u64,
    value: u64,
) -> tos_sandbox::SendResult {
    let global_id = match chain.blockchain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("the chain states no network id"),
    };
    let validator_id = chain_block::UInt256::from_slice(&sender.address().get_bytestring(0));
    let preimage = pq_stake_preimage(
        global_id,
        election,
        0x10000,
        &validator_id,
        &validator.key_id(),
        &validator.adnl,
    );
    let signature = validator.sign(&preimage);
    chain
        .blockchain
        .send_message(
            tos_sandbox::MessageBuilder::internal(sender, &chain.elector, value)
                .bounce(true)
                .body(pq_stake_body(
                    query_id,
                    validator,
                    election,
                    0x10000,
                    &signature,
                    Some(proof),
                ))
                .build(),
        )
        .expect("the stake is delivered")
}

/// The floor under a stake is measured over the stake the election still counts.
///
/// Retiring a controller code takes the stake behind it out of that measurement, which is
/// what the aggregate exists for: the same small stake is refused as too small while a
/// large retired profile is counted, and clears that floor once it is not.
#[test]
fn a_retired_profile_stops_raising_the_floor_under_everyone_else() {
    let (mut chain, treasury, election) = open_election("pq-effective", 4_000_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let (other, other_proof, other_code) = account_with_code(0x7e);
    let treasury_code = sender_code_hash(&chain, &treasury);
    set_policy(&mut chain, &[treasury_code, other_code.clone()]);

    assert_eq!(
        reply(&pq_stake(
            &mut chain,
            &treasury,
            &PqValidator::new(29),
            election,
            1,
            3_000_000 * TOS
        )),
        (STAKE_ACCEPTED, 0),
        "the fixture needs a large member"
    );

    let small = PqValidator::new(30);
    let refused =
        pq_stake_as(&mut chain, &other, other_proof.clone(), &small, election, 2, 100 * TOS);
    assert_eq!(
        reply(&refused),
        (STAKE_RETURNED, 2),
        "the floor was not measured over the post-quantum stake already placed"
    );

    set_policy(&mut chain, &[other_code]);
    let after = pq_stake_as(&mut chain, &other, other_proof, &small, election, 3, 100 * TOS);
    assert_eq!(
        reply(&after),
        (STAKE_RETURNED, REASON_BELOW_MINIMUM),
        "a retired profile is still counted in the floor it raises"
    );
}

/// Retiring a controller code stops the controllers already using it, not only new ones.
#[test]
fn retiring_a_controller_code_stops_the_members_that_used_it() {
    let (mut chain, treasury, election) = open_election("pq-retire", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(27);
    let rotated = PqValidator::new(28);

    assert_eq!(
        reply(&pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "the fixture needs a registered member"
    );
    let placed = pq_stake_of(&chain, &treasury);

    // The code this member was admitted under is retired.
    set_policy(&mut chain, &[chain_block::UInt256::from_slice(&[0x11; 32])]);

    let topped = pq_stake(&mut chain, &treasury, &validator, election, 2, 12_000 * TOS);
    assert_eq!(
        reply(&topped),
        (STAKE_RETURNED, REASON_CODE_RETIRED),
        "a member whose controller code was retired could still top up"
    );
    let rotation = pq_stake(&mut chain, &treasury, &rotated, election, 3, 12_000 * TOS);
    assert_eq!(
        reply(&rotation),
        (STAKE_RETURNED, REASON_CODE_RETIRED),
        "a member whose controller code was retired could still rotate its key"
    );

    assert_eq!(pq_stake_of(&chain, &treasury), placed, "a refused action changed the member");
    assert_eq!(
        pq_member_key_id(&chain, &treasury),
        Some(validator.key_id()),
        "a refused rotation moved the member off its key"
    );

    // Admitting it again restores what it could do.
    let code = sender_code_hash(&chain, &treasury);
    set_policy(&mut chain, &[code]);
    assert_eq!(
        reply(&pq_stake(&mut chain, &treasury, &validator, election, 4, 12_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "re-admitting the code did not restore the member"
    );
}

#[test]
fn a_post_quantum_stake_without_a_transport_address_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-validator-f", 40_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let mut validator = PqValidator::new(7);
    validator.adnl = [0u8; 32];

    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_NO_ADNL),
        "a validator registered without a transport address, so nothing could reach it"
    );
}
