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

#[path = "elector_security_audit/mod.rs"]
mod security_audit;

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
    generate_zerostate_state(root.join("test/tostester/tests/tostester/genesis-with-test-auth.fif"))
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

fn configuration_parameters_hash(chain: &Chain) -> [u8; 32] {
    let account = chain
        .blockchain
        .get_account(&chain.config_contract)
        .expect("the configuration contract is deployed");
    let data = account.get_data().expect("the configuration contract has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    *slice.checked_drain_reference().expect("the parameter dictionary").repr_hash().as_array()
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
    require_post_quantum_version(&chain);
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

/// A correctly signed stake in the classical Ed25519 shape buys nothing. The operation is
/// the same one a post-quantum stake uses, so the elector reads the body as one: a raw key
/// where the suite and key reference belong, and one reference where two are required.
/// The message cannot be parsed, the transaction aborts, and the bounce carries the money
/// back.
///
/// This is the test that fails if the classical shape is ever accepted again. It asserts
/// the absence of an effect and not merely an error, because an error that still
/// registered a member would look the same from the reply alone.
#[test]
fn the_legacy_stake_operation_has_no_authority_and_returns_the_money() {
    let (mut chain, treasury, election) = open_election("legacy-stake-op", 60_000 * TOS);
    require_post_quantum_version(&chain);
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

    let (_, transaction) = result.transactions.first().expect("a transaction");
    assert!(
        transaction.read_description().expect("description").is_aborted(),
        "the elector parsed a classical stake body as a post-quantum one"
    );
    let mut bounced = false;
    transaction
        .iterate_out_msgs(|message| {
            bounced |= message.int_header().is_some_and(|header| header.bounced);
            Ok(true)
        })
        .expect("out messages");
    assert!(bounced, "the refused classical stake was not bounced back to its sender");

    // Nothing was kept: the bounce carries the stake back rather than stranding it.
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

/// The Elector itself can produce a set with two distinct signing identities but one
/// transport identity: a stake signature binds the claimed ADNL, not ownership of it.
/// The config contract must reject that elected set before it becomes ConfigParam 36.
/// `return_stake` reason 17: the transport address is stated by another member of
/// this election.
const REASON_ADDRESS_STATED_BY_ANOTHER_CANDIDATE: u32 = 17;
/// `return_stake` reason 18: the transport address is held by a validator of the
/// current or next set under another identity.
const REASON_ADDRESS_HELD_BY_ANOTHER_VALIDATOR: u32 = 18;

/// A transport address names one node. A candidate restating another candidate's
/// address is refused at registration, with its money, and the election seats the
/// rest: the refusal that used to happen to the whole set at installation happens
/// to the one candidate instead. The first candidate keeps the address it stated.
#[test]
fn a_stake_restating_another_candidates_address_is_refused_at_registration() {
    let (mut chain, _treasury, election) = open_election("duplicate-adnl-election", 200_000 * TOS);
    require_post_quantum_version(&chain);
    let mut first_adnl = None;
    for index in 0..5u8 {
        let mut validator = PqValidator::new(0x60 + index);
        if index == 0 {
            first_adnl = Some(validator.adnl);
        } else if index == 1 {
            validator.adnl = first_adnl.expect("the first validator has an ADNL");
        }
        let account = chain
            .blockchain
            .treasury(&format!("duplicate-adnl-validator-{index}"), 40_000 * TOS)
            .expect("a funded account");
        let result =
            pq_stake(&mut chain, &account, &validator, election, 30 + index as u64, 11_000 * TOS);
        if index == 1 {
            assert_eq!(
                reply(&result),
                (STAKE_RETURNED, REASON_ADDRESS_STATED_BY_ANOTHER_CANDIDATE),
                "the candidate restating validator 0's address was not refused at registration"
            );
        } else {
            assert_eq!(
                reply(&result),
                (STAKE_ACCEPTED, 0),
                "the Elector refused stake {index}, whose address is its own"
            );
        }
    }

    chain.blockchain.set_now(election - chain.elect_end_before);
    let result =
        chain.blockchain.tick_tock(&chain.elector, TransactionTickTock::Tick).expect("tick runs");
    result.expect_success();
    let tags = replies(&result);
    assert!(
        tags.contains(&VALIDATOR_SET_INSTALLED),
        "the set of the four distinct addresses was not installed: {tags:02x?}"
    );
    assert!(!tags.contains(&VALIDATOR_SET_REFUSED), "the set was refused: {tags:02x?}");
    assert!(
        parameter_present(&configuration_from_contract(&chain), 36),
        "no ConfigParam 36 was stored"
    );
}

/// A validator keeps its address: a member restating its own address on a top-up
/// is accepted, and only another identity stating that address is refused.
#[test]
fn a_member_may_restate_its_own_address_and_nobody_else_may() {
    let (mut chain, _treasury, election) = open_election("own-adnl-election", 200_000 * TOS);
    require_post_quantum_version(&chain);
    let validator = PqValidator::new(0x66);
    let account =
        chain.blockchain.treasury("own-adnl-validator", 60_000 * TOS).expect("a funded account");
    let result = pq_stake(&mut chain, &account, &validator, election, 60, 11_000 * TOS);
    assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "the first stake was refused");
    let result = pq_stake(&mut chain, &account, &validator, election, 61, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_ACCEPTED, 0),
        "a top-up restating the own address was refused"
    );

    let mut squatter = PqValidator::new(0x67);
    squatter.adnl = validator.adnl;
    let other =
        chain.blockchain.treasury("own-adnl-squatter", 40_000 * TOS).expect("a funded account");
    let result = pq_stake(&mut chain, &other, &squatter, election, 62, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_ADDRESS_STATED_BY_ANOTHER_CANDIDATE),
        "another identity stating the member's address was admitted"
    );
}

/// An address a validator of the current set holds is refused to any other
/// identity, so a newcomer cannot unseat an incumbent by restating its address.
#[test]
fn a_stake_restating_an_incumbents_address_is_refused_at_registration() {
    let (mut chain, _treasury, election) = open_election("incumbent-adnl-election", 200_000 * TOS);
    require_post_quantum_version(&chain);
    let incumbent_adnl: [u8; 32] = chain
        .blockchain
        .config_params()
        .validator_set()
        .expect("a current set")
        .list()
        .iter()
        .find_map(|descr| descr.adnl_addr.clone())
        .map(|adnl| *adnl.as_slice())
        .expect("the current set states transport addresses");
    let mut squatter = PqValidator::new(0x68);
    squatter.adnl = incumbent_adnl;
    let account = chain
        .blockchain
        .treasury("incumbent-adnl-squatter", 40_000 * TOS)
        .expect("a funded account");
    let result = pq_stake(&mut chain, &account, &squatter, election, 70, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_ADDRESS_HELD_BY_ANOTHER_VALIDATOR),
        "a newcomer stating an incumbent's address was admitted"
    );
    // The same newcomer with an address of its own is admitted.
    let honest = PqValidator::new(0x69);
    let result = pq_stake(&mut chain, &account, &honest, election, 71, 11_000 * TOS);
    assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "the newcomer's own address was refused");
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
// An election that cannot be conducted
//
// An election the elector cannot conduct -- too little stake, or too few members for a
// set -- is postponed rather than given up. It stays open past its close and past the
// term of the set it was meant to replace, it keeps taking stakes, and the stake already
// placed stays in it: nothing is owed back until a set is seated or the configuration
// refuses one. A stake that arrives after the close is therefore what lets a short
// election recover, so the two are tested together.
// ---------------------------------------------------------------------------

fn tick(chain: &mut Chain) -> tos_sandbox::SendResult {
    let result =
        chain.blockchain.tick_tock(&chain.elector, TransactionTickTock::Tick).expect("tick runs");
    result.expect_success();
    result
}

/// The account a synthetic member stakes from, which is also its validator identity and
/// the account everything the election owes it is credited to.
fn refund_owner(index: u16) -> [u8; 32] {
    let mut owner = [0xEEu8; 32];
    owner[30..32].copy_from_slice(&(index + 1).to_be_bytes());
    owner
}

/// The election's `failed` flag, as the summary getter reports it.
fn election_failed(chain: &Chain) -> bool {
    let summary = chain
        .blockchain
        .run_get_method(&chain.elector, "participant_list_extended", vec![])
        .expect("the elector answers");
    assert_eq!(summary.exit_code, 0, "participant_list_extended failed");
    summary.stack[5].as_integer().expect("the failed flag").to_string() != "0"
}

#[test]
fn a_closed_election_below_the_minimum_keeps_every_stake_until_it_can_be_conducted() {
    let (mut chain, _treasury, election) = open_election("short-election", 200_000 * TOS);
    require_post_quantum_version(&chain);
    // Two members at 11 000 each: below the forty thousand the configuration requires.
    let stake = 11_000 * TOS;
    install_synthetic_book_full(&mut chain, 2, &refund_owner, &|_| stake);
    let placed = declared_total_stake(&chain);

    for (now, at) in [
        (election - chain.elect_end_before, "the close"),
        (election, "the end of the term"),
        (election + 10 * chain.elect_begin_before, "long after the term"),
    ] {
        let seen = tick_at(&mut chain, now, at);
        assert_eq!(seen.open_election, election, "the short election was dropped at {at}");
        assert!(!seen.next_set_installed, "a set was installed from a short election at {at}");
        assert!(!election_failed(&chain), "a short election was marked failed at {at}");
        assert_eq!(declared_total_stake(&chain), placed, "the election's total moved at {at}");
        for index in 0..2 {
            assert_eq!(
                owed(&chain, &refund_owner(index)),
                0,
                "member {index}'s money left a standing election at {at}"
            );
        }
    }
}

/// A selection that runs and seats nobody marks the election failed, and the elector does
/// not try it again on its own: a configuration change alone does not retry it. A new
/// stake does, and the election it completes is seated.
#[test]
fn a_failed_selection_is_retried_once_a_new_stake_arrives() {
    let (mut chain, _treasury, election) = open_election("failed-election", 400_000 * TOS);
    require_post_quantum_version(&chain);
    // Enough money to pass the total, too few members to seat the four the
    // configuration requires: the selection runs and fails.
    let stake = 30_000 * TOS;
    install_synthetic_book_full(&mut chain, 3, &refund_owner, &|_| stake);

    let closed = tick_at_close(&mut chain, election, "the close");
    assert!(!closed.next_set_installed, "three members were seated as a set");
    assert_eq!(closed.open_election, election, "the failed election was dropped");
    assert!(election_failed(&chain), "the fixture must reach a real failed selection");
    for index in 0..3 {
        assert_eq!(owed(&chain, &refund_owner(index)), 0, "money left a failed election");
    }

    // Three members would now be enough, but nothing new was staked.
    set_contract_parameter(&mut chain, 16, validator_count_limits(21, 21, 3));
    let retried = tick_at(&mut chain, election, "after the configuration change");
    assert!(!retried.next_set_installed, "the elector retried a failed selection by itself");
    assert!(election_failed(&chain), "the failed flag cleared without a new stake");

    // A fourth member stakes, which is what reopens the selection.
    let account = chain.blockchain.treasury("failed-election-late", 40_000 * TOS).expect("funds");
    let result = pq_stake(&mut chain, &account, &PqValidator::new(0x7f), election, 1, 30_001 * TOS);
    assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "the late stake was refused");
    assert!(!election_failed(&chain), "a new stake did not clear the failed flag");
    let seated = tick_at(&mut chain, election + 1, "after the new stake");
    assert!(seated.next_set_installed, "the election a new stake completed was not seated");
}

// ---------------------------------------------------------------------------
// The election lifecycle as a whole
//
// Each test above checks one rule where it lives. These follow an election past the tick
// it closed on, for every way it can end:
//
// - liveness: an election that could not be conducted is still open, and still taking
//   stakes, however long it waited;
// - time: each outcome is observed at every boundary, not at one tick;
// - paired assumptions: a late stake is tested together with the short election that
//   needed it;
// - conservation: nothing leaves an election that seated nobody, and a seated one
//   returns each stake exactly once, to the account that put it up;
// - absence: an operator missing whole windows finds the election still waiting.
// ---------------------------------------------------------------------------

/// Every way an election can end.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Outcome {
    /// Nobody staked.
    Empty,
    /// Stake was placed, but less than the configuration's minimum total.
    BelowMinimum,
    /// Enough stake, too few members: the selection runs and seats nobody.
    FailedSelection,
    /// A set is seated. One member staked three times the others, so the selection caps
    /// it and part of its stake comes back at once.
    Seated,
}

const OUTCOMES: [Outcome; 4] =
    [Outcome::Empty, Outcome::BelowMinimum, Outcome::FailedSelection, Outcome::Seated];

/// An open election in the state `outcome` describes, and what each member placed in it.
struct Scenario {
    chain: Chain,
    election: u32,
    placed: Vec<([u8; 32], u128)>,
}

fn scenario(outcome: Outcome) -> Scenario {
    let (mut chain, _treasury, election) =
        open_election(&format!("lifecycle-{outcome:?}"), 400_000 * TOS);
    require_post_quantum_version(&chain);
    let stakes: Vec<u64> = match outcome {
        Outcome::Empty => Vec::new(),
        Outcome::BelowMinimum => vec![11_000 * TOS; 2],
        Outcome::FailedSelection => vec![30_000 * TOS; 3],
        Outcome::Seated => {
            vec![33_000 * TOS, 11_000 * TOS, 11_000 * TOS, 11_000 * TOS, 11_000 * TOS]
        }
    };
    if !stakes.is_empty() {
        install_synthetic_book_full(&mut chain, stakes.len() as u16, &refund_owner, &|index| {
            stakes[index as usize]
        });
    }
    let placed = stakes
        .iter()
        .enumerate()
        .map(|(index, stake)| (refund_owner(index as u16), u128::from(*stake)))
        .collect();
    Scenario { chain, election, placed }
}

/// What the elector and the configuration contract show at one moment.
#[derive(Debug, PartialEq)]
struct Observed {
    at: &'static str,
    open_election: u32,
    next_set_installed: bool,
}

fn observe(chain: &Chain, at: &'static str) -> Observed {
    Observed {
        at,
        open_election: active_election_id(chain) as u32,
        next_set_installed: parameter_present(&configuration_from_contract(chain), 36),
    }
}

/// Tick at the moment `election` closes and record what follows.
fn tick_at_close(chain: &mut Chain, election: u32, at: &'static str) -> Observed {
    let close = election - chain.elect_end_before;
    tick_at(chain, close, at)
}

/// Tick at `now` and record what follows.
fn tick_at(chain: &mut Chain, now: u32, at: &'static str) -> Observed {
    chain.blockchain.set_now(now);
    tick(chain);
    observe(chain, at)
}

/// An amount in the elector's storage: a 4-bit byte count and that many bytes.
fn next_coins(slice: &mut chain_block::SliceData) -> u128 {
    let bytes = slice.get_next_int(4).expect("an amount length") as usize;
    if bytes == 0 {
        return 0;
    }
    slice
        .get_next_bits(bytes * 8)
        .expect("an amount")
        .iter()
        .fold(0u128, |total, byte| (total << 8) | u128::from(*byte))
}

/// The frozen total and the bonuses a past election holds.
fn past_totals(chain: &Chain, election: u32) -> (u128, u128) {
    let key = chain_block::SliceData::load_builder(
        chain_block::BuilderData::with_raw(election.to_be_bytes().to_vec(), 32).expect("key"),
    )
    .expect("key slice");
    let mut record =
        past_elections(chain).get(key).expect("lookup").expect("a record for that election");
    record.get_next_u32().expect("unfreeze time");
    record.get_next_u32().expect("hold time");
    record.get_next_bits(256).expect("the set this election produced");
    let _frozen = next_dictionary(&mut record, 256);
    let total = next_coins(&mut record);
    let bonuses = next_coins(&mut record);
    (total, bonuses)
}

/// Time and conservation, together: every outcome is followed across each boundary. One
/// that seats a set returns each stake exactly once to the account that put it up -- the
/// unused part at once, the frozen part with its share of the bonuses once the stake is
/// released. One that seats nobody stays open, and nothing leaves it however long it
/// waits.
#[test]
fn every_outcome_holds_each_stake_until_a_set_is_seated_and_then_returns_it_once() {
    for outcome in OUTCOMES {
        let Scenario { mut chain, election, placed } = scenario(outcome);
        let close = election - chain.elect_end_before;
        let placed_total: u128 = placed.iter().map(|(_, stake)| stake).sum();
        let before = tick_at(&mut chain, close - 1, "before the close");
        assert_eq!(
            before,
            Observed { at: "before the close", open_election: election, next_set_installed: false },
            "{outcome:?}"
        );
        let closed = tick_at(&mut chain, close, "at the close");
        assert_eq!(closed.open_election, election, "{outcome:?}: the election ended at its close");
        assert_eq!(closed.next_set_installed, outcome == Outcome::Seated, "{outcome:?}");

        if outcome == Outcome::Seated {
            chain
                .blockchain
                .set_config(configuration_from_contract(&chain))
                .expect("the chain adopts the installed set");
            let forgotten = tick_at(&mut chain, close + 1, "after the set is installed");
            assert_eq!(forgotten.open_election, 0, "the election outlived its installed set");
            let (frozen, bonuses) = past_totals(&chain, election);
            let unused: Vec<u128> = placed.iter().map(|(owner, _)| owed(&chain, owner)).collect();
            assert!(unused.iter().any(|part| *part > 0), "nothing was left over to follow");
            assert_eq!(
                frozen + unused.iter().sum::<u128>(),
                placed_total,
                "the frozen stake and the unused part do not add up to what was placed"
            );
            let release = chain.blockchain.now() + 10 * 365 * 24 * 3600;
            tick_at(&mut chain, release, "after the stake is released");
            // Exactly: the unused part, the frozen part, and the frozen part's share of the
            // bonuses -- the same floor division the elector uses -- and nothing else.
            for (index, ((owner, stake), unused)) in placed.iter().zip(&unused).enumerate() {
                let held = stake - unused;
                let expected = stake + bonuses * held / frozen;
                assert_eq!(
                    owed(&chain, owner),
                    expected,
                    "Seated: member {index} placed {stake}, {held} of it held, with {bonuses} \
                     in bonuses over {frozen} held in all"
                );
            }
            continue;
        }

        // Nothing may leave an election that is still standing, at any boundary.
        for (now, at) in [
            (election - 1, "the last second of the term"),
            (election, "the end of the term"),
            (election + 10 * chain.elect_begin_before, "long after the term"),
        ] {
            let seen = tick_at(&mut chain, now, at);
            assert_eq!(
                seen,
                Observed { at, open_election: election, next_set_installed: false },
                "{outcome:?}"
            );
            for (index, (owner, _)) in placed.iter().enumerate() {
                assert_eq!(
                    owed(&chain, owner),
                    0,
                    "{outcome:?}: member {index}'s money left a standing election at {at}"
                );
            }
        }
    }
}

/// Paired assumptions: a short election is held open, and the stake that arrives after
/// its close is what completes it. Without the late stake the election waits; with it the
/// next tick seats a set, and the members that staked in time are elected with the rest.
#[test]
fn a_late_stake_completes_a_short_election() {
    let (mut chain, _treasury, election) = open_election("late-stake", 400_000 * TOS);
    require_post_quantum_version(&chain);
    let close = election - chain.elect_end_before;

    let validators: Vec<PqValidator> =
        (0..4u8).map(|index| PqValidator::new(0x70 + index)).collect();
    let accounts: Vec<tos_sandbox::Treasury> = (0..4)
        .map(|index| {
            chain
                .blockchain
                .treasury(&format!("late-stake-{index}"), 60_000 * TOS)
                .expect("a funded account")
        })
        .collect();

    // Two members in time: short of the minimum.
    for index in 0..2 {
        let result = pq_stake(
            &mut chain,
            &accounts[index],
            &validators[index],
            election,
            30 + index as u64,
            11_000 * TOS,
        );
        assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "member {index} could not stake");
    }

    // The close passes and the election waits for more.
    let waited = tick_at(&mut chain, close + 1, "after the close");
    assert_eq!(waited.open_election, election, "the short election was dropped");
    assert!(!waited.next_set_installed, "a short election was seated");

    // Two more arrive late, after the term the election was meant to follow has ended.
    chain.blockchain.set_now(election + 1);
    for index in 2..4 {
        let result = pq_stake(
            &mut chain,
            &accounts[index],
            &validators[index],
            election,
            40 + index as u64,
            11_000 * TOS,
        );
        assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "the late member {index} was refused");
    }
    let seated = tick_at(&mut chain, election + 2, "after the late stakes");
    assert!(seated.next_set_installed, "the election the late stakes completed seated no set");
    let installed =
        configuration_from_contract(&chain).next_validator_set().expect("the stored set parses");
    assert_eq!(installed.list().len(), 4, "the members that staked in time were left out");
}

/// Absence: the operator misses three whole terms. The empty election waits through all
/// of them, and when the operator returns, staking into it seats a set.
#[test]
fn an_absent_operator_finds_the_election_still_waiting() {
    let (mut chain, _treasury, election) = open_election("absent-operator", 400_000 * TOS);
    require_post_quantum_version(&chain);
    let term = chain.elect_begin_before;
    for window in 0..3u32 {
        let now = election + window * term;
        let seen = tick_at(&mut chain, now, "a missed window");
        assert_eq!(seen.open_election, election, "window {window}: the election was dropped");
        assert!(!seen.next_set_installed, "window {window}: a set came from nobody");
    }

    // The operator is back.
    for index in 0..4u8 {
        let account = chain
            .blockchain
            .treasury(&format!("absent-operator-{index}"), 40_000 * TOS)
            .expect("a funded account");
        let result = pq_stake(
            &mut chain,
            &account,
            &PqValidator::new(0x78 + index),
            election,
            50 + u64::from(index),
            11_000 * TOS,
        );
        assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "member {index} could not stake");
    }
    let now = chain.blockchain.now() + 1;
    let closed = tick_at(&mut chain, now, "the operator's return");
    assert!(closed.next_set_installed, "the returning operator's election seated no set");
}

/// The elector's own accounts after the election record: credits, past elections, its
/// purse of nobody's money, and the set it treats as active.
fn elector_purse_and_active_set(chain: &Chain) -> (u128, u32) {
    let account = chain.blockchain.get_account(&chain.elector).expect("the elector is deployed");
    let data = account.get_data().expect("the elector has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let _election = next_dictionary(&mut slice, 32);
    let _credits = next_dictionary(&mut slice, 256);
    let _past = next_dictionary(&mut slice, 32);
    let purse = next_coins(&mut slice);
    let active = slice.get_next_u32().expect("the active set id");
    (purse, active)
}

/// What a past election holds frozen, by the account each stake goes back to.
fn frozen_by_owner(chain: &Chain, election: u32) -> std::collections::BTreeMap<[u8; 32], u128> {
    let key = chain_block::SliceData::load_builder(
        chain_block::BuilderData::with_raw(election.to_be_bytes().to_vec(), 32).expect("key"),
    )
    .expect("key slice");
    let mut record =
        past_elections(chain).get(key).expect("lookup").expect("a record for that election");
    record.get_next_u32().expect("unfreeze time");
    record.get_next_u32().expect("hold time");
    record.get_next_bits(256).expect("the set this election produced");
    let frozen = next_dictionary(&mut record, 256);
    let mut owners = std::collections::BTreeMap::new();
    chain_block::HashmapType::iterate_slices(&frozen, |_key, mut value| {
        let owner: [u8; 32] =
            value.get_next_bits(256).expect("the owner").try_into().expect("32 bytes");
        value.get_next_u64().expect("weight");
        let stake = next_coins(&mut value);
        let banned = value.get_next_bit().expect("the banned flag");
        assert!(!banned, "nobody was punished in this round");
        *owners.entry(owner).or_insert(0) += stake;
        Ok(true)
    })
    .expect("frozen stakes");
    owners
}

/// Configuration parameter 17: `min_stake max_stake min_total_stake:Tomis max_stake_factor:uint32`.
fn stake_limits(min: u64, max: u64, min_total: u64, factor: u32) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut value = chain_block::BuilderData::new();
    for amount in [min, max, min_total] {
        chain_block::Serializable::write_to(&chain_block::Coins::new(amount), &mut value)
            .expect("an amount");
    }
    value.append_u32(factor).expect("the factor");
    value.into_cell().expect("stake limits")
}

fn has_past_election(chain: &Chain, election: u32) -> bool {
    let key = chain_block::SliceData::load_builder(
        chain_block::BuilderData::with_raw(election.to_be_bytes().to_vec(), 32).expect("key"),
    )
    .expect("key slice");
    past_elections(chain).get(key).expect("lookup").is_some()
}

/// Bonuses, end to end: a set that serves is paid from two sources -- an eighth of the
/// elector's purse when it takes office, and the validator fees sent from the zero
/// address while it is active -- and when it leaves office and its stakes are released,
/// each owner receives its unused part, its frozen stake and its share of the bonuses in
/// proportion to that stake. What the floor division leaves over goes back to the purse,
/// so not one nanotomi is created or lost.
#[test]
fn a_served_sets_bonuses_reach_its_stakers_in_proportion_and_nowhere_else() {
    let (mut chain, _treasury, election) = open_election("bonus-round", 400_000 * TOS);
    require_post_quantum_version(&chain);
    let address_of = |account: &tos_sandbox::Treasury| -> [u8; 32] {
        account.address().address().get_bytestring(0).try_into().expect("an address")
    };
    // Unequal stakes, so a share in proportion differs from an equal split.
    let stakes = [20_000 * TOS, 11_000 * TOS, 13_000 * TOS, 11_000 * TOS];
    let mut owners = Vec::new();
    for (index, stake) in stakes.iter().enumerate() {
        let account = chain
            .blockchain
            .treasury(&format!("bonus-round-{index}"), 40_000 * TOS)
            .expect("a funded account");
        // A factor of three lets a larger stake count up to three times the smallest,
        // so the members freeze different amounts.
        let result = pq_stake_with_max_factor(
            &mut chain,
            &account,
            &account,
            &PqValidator::new(0x58 + index as u8),
            election,
            60 + index as u64,
            *stake,
            3 * 0x10000,
        );
        assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "member {index} could not stake");
        owners.push(address_of(&account));
    }
    let placed = declared_total_stake(&chain);
    // The launch configuration caps every stake at the smallest (a factor of one), which
    // would freeze equal amounts. Allow three, as the members asked for.
    set_contract_parameter(
        &mut chain,
        17,
        stake_limits(10_000 * TOS, 10_000_000 * TOS, 40_000 * TOS, 3 * 0x10000),
    );

    // Elect, install, and rotate the set into office.
    let closed = tick_at_close(&mut chain, election, "the close");
    assert!(closed.next_set_installed, "the election seated no set");
    let unused: Vec<u128> = owners.iter().map(|owner| owed(&chain, owner)).collect();
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
    // Fill the purse with nobody's money: an ordinary account's plain transfer.
    let donor = chain.blockchain.treasury("bonus-donor", 20_000 * TOS).expect("a funded account");
    let (purse_before, active_before) = elector_purse_and_active_set(&chain);
    assert_ne!(active_before, election, "the set was active before it took office");
    chain
        .blockchain
        .send_message(
            tos_sandbox::MessageBuilder::internal(donor.address(), &chain.elector, 8_000 * TOS)
                .build(),
        )
        .expect("the transfer is delivered")
        .expect_success();
    let (purse, active) = elector_purse_and_active_set(&chain);
    assert_eq!(purse, purse_before + 8_000 * TOS as u128, "a plain transfer missed the purse");
    assert_ne!(active, election, "a plain transfer activated the set");
    assert_eq!(past_totals(&chain, election).1, 0, "bonuses before the set took office");

    // The elector sees the set in office: it forgets the election and makes the set
    // active, and taking office moves an eighth of the purse to the set's bonuses.
    for _ in 0..4 {
        if elector_purse_and_active_set(&chain).1 == election {
            break;
        }
        tick(&mut chain);
    }
    assert_eq!(active_election_id(&chain), 0, "the election was not forgotten once installed");
    let (purse_in_office, active) = elector_purse_and_active_set(&chain);
    assert_eq!(active, election, "the elector does not treat the rotated set as active");
    let (_, bonuses) = past_totals(&chain, election);
    assert_eq!(bonuses, purse >> 3, "taking office did not move an eighth of the purse");
    assert_eq!(purse_in_office, purse - (purse >> 3), "the purse lost more than an eighth");

    // Validator fees from the zero address go straight to the active set's bonuses.
    let fees = 777 * TOS + 3;
    let zero = masterchain(chain_block::AccountId::from([0u8; 32]));
    chain
        .blockchain
        .send_message(tos_sandbox::MessageBuilder::internal(&zero, &chain.elector, fees).build())
        .expect("the fees are delivered")
        .expect_success();
    let (frozen_total, bonuses) = past_totals(&chain, election);
    assert_eq!(bonuses, (purse >> 3) + u128::from(fees), "the fees missed the bonuses");
    let (purse_with_fees, _) = elector_purse_and_active_set(&chain);
    assert_eq!(purse_with_fees, purse_in_office, "the fees went to the purse, not the set");

    let frozen = frozen_by_owner(&chain, election);
    assert_eq!(frozen.values().sum::<u128>(), frozen_total, "the frozen total disagrees");
    assert_eq!(
        frozen_total + unused.iter().sum::<u128>(),
        placed,
        "the frozen stake and the unused part do not add up to what the election held"
    );
    assert!(
        frozen.values().collect::<std::collections::BTreeSet<_>>().len() > 1,
        "every member froze the same amount, so a proportional share looks like an equal one"
    );

    // The set leaves office: the configuration names a different current set.
    let previous = raw_parameter(&chain, 32).expect("the previous set is kept");
    set_contract_parameter(&mut chain, 34, previous);
    // The elector does one thing per tick, and announcing an election comes first.
    for _ in 0..4 {
        if elector_purse_and_active_set(&chain).1 != election {
            break;
        }
        tick(&mut chain);
    }
    let (_, active) = elector_purse_and_active_set(&chain);
    assert_ne!(active, election, "the set is still active after leaving office");

    // Past the hold, the stakes are released -- one past election per tick.
    let release = chain.blockchain.now() + 10 * 365 * 24 * 3600;
    chain.blockchain.set_now(release);
    let (purse_before_release, _) = elector_purse_and_active_set(&chain);
    for _ in 0..8 {
        if !has_past_election(&chain, election) {
            break;
        }
        tick(&mut chain);
    }
    assert!(!has_past_election(&chain, election), "the stakes were never released");

    let mut paid_bonuses = 0u128;
    for (index, owner) in owners.iter().enumerate() {
        let held = frozen.get(owner).copied().unwrap_or(0);
        let share = bonuses * held / frozen_total;
        paid_bonuses += share;
        assert_eq!(
            owed(&chain, owner),
            unused[index] + held + share,
            "member {index}: {held} held of {frozen_total}, with {bonuses} in bonuses"
        );
    }
    assert!(paid_bonuses > 0, "no bonus was paid, so the share was never tested");
    let (purse_after_release, _) = elector_purse_and_active_set(&chain);
    assert_eq!(
        purse_after_release,
        purse_before_release + (bonuses - paid_bonuses),
        "the bonus left over by the division did not go back to the purse"
    );
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
fn proposal_cell(chain: &Chain, param_id: i32, value: chain_block::Cell) -> chain_block::Cell {
    use chain_block::{GetRepresentationHash, IBitstring};
    let mut proposal = chain_block::BuilderData::new();
    proposal.append_u8(0xf3).expect("tag");
    proposal.append_i32(param_id).expect("parameter");
    proposal.append_bit_one().expect("a value is present");
    proposal.checked_append_reference(value).expect("value");
    if let Some(current) = raw_parameter(chain, param_id) {
        proposal.append_bit_one().expect("an expected current value is present");
        proposal.append_raw(current.repr_hash().as_slice(), 256).expect("current value hash");
    } else {
        proposal.append_bit_zero().expect("no expected current value");
    }
    proposal.into_cell().expect("proposal")
}

/// The cell a configuration parameter holds, as the contract stores it.
fn raw_parameter(chain: &Chain, index: i32) -> Option<chain_block::Cell> {
    parameter_from_config(&configuration_from_contract(chain), index)
}

fn parameter_from_config(config: &ConfigParams, index: i32) -> Option<chain_block::Cell> {
    use chain_block::IBitstring;
    let mut key = chain_block::BuilderData::new();
    key.append_i32(index).expect("the parameter index");
    config
        .config_params
        .get(chain_block::SliceData::load_builder(key).expect("a key slice"))
        .expect("lookup")
        .and_then(|slice| slice.reference_opt(0))
}

/// The VM's configuration view for the next message, as opposed to the
/// configuration contract's stored dictionary.
fn vm_parameter(chain: &Chain, index: i32) -> Option<chain_block::Cell> {
    parameter_from_config(chain.blockchain.config_params(), index)
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
    let proposal = proposal_cell(chain, param_id, value);
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

    // A whole PQ validator set is much larger than the small scalar proposals this
    // fixture originally carried. Fund the storage price for the largest launch-sized
    // proposal so a cap refusal cannot be confused with an underfunded proposal.
    let proposer = chain.blockchain.treasury("proposer", 20_000 * TOS).expect("a funded account");
    let result = chain
        .blockchain
        .send_message(proposer.build_message(
            &chain.config_contract,
            10_000 * TOS,
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
    use chain_block::{GetRepresentationHash, Serializable};
    let z01_capture = matches!(query_base, 0x1600 | 0x1601 | 0x2800 | 0x2801 | 0x3700 | 0x3701);
    let z01_dir = std::env::var_os("Z01_GOVERNANCE_TX_DIR").map(std::path::PathBuf::from);
    if z01_capture {
        if let Some(dir) = &z01_dir {
            std::fs::create_dir_all(dir).expect("Z01 raw transaction directory");
            let raw = chain_block::write_boc(&proposal_cell(chain, param_id, value.clone()))
                .expect("Z01 proposal BOC");
            std::fs::write(dir.join(format!("proposal-{query_base:04x}.boc")), raw)
                .expect("save Z01 proposal BOC");
        }
    }
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
        if z01_capture {
            for (tx_index, (_, transaction)) in result.transactions.iter().enumerate() {
                if let Some(dir) = &z01_dir {
                    let raw = chain_block::write_boc(
                        &transaction.serialize().expect("Z01 transaction cell"),
                    )
                    .expect("Z01 transaction BOC");
                    std::fs::write(
                        dir.join(format!("vote-{query_base:04x}-{round}-{tx_index}.boc")),
                        raw,
                    )
                    .expect("save Z01 transaction BOC");
                }
                eprintln!(
                    "z01_governance_vote param={param_id} query={} account={} lt={} tx_hash={} first_tx_compute_exit={}",
                    query_base + round as u64,
                    hex::encode(transaction.account_id().get_bytestring(0)),
                    transaction.logical_time(),
                    hex::encode(transaction.hash().expect("transaction hash").as_slice()),
                    exit_code_of(&result),
                );
            }
        }
        assert_eq!(exit_code_of(&result), 0, "a validator's vote was refused");
        // The contract drops a proposal's status once it has decided it, so the vote it
        // was recorded in disappearing is how a decision is visible from outside.
        if proposal_voters(chain, &proposal).is_empty() {
            decided = true;
            break;
        }
    }
    // Sandbox transactions do not automatically refresh their VM config from the
    // configuration contract. Model the next masterchain block before a later
    // proposal reads config_param(current), or its conditional hash is stale.
    chain
        .blockchain
        .set_config(configuration_from_contract(chain))
        .expect("the chain adopts a governed configuration change");
    let installed = parameter_present(&configuration_from_contract(chain), param_id as u32);
    Governed { decided, installed }
}

fn validator_count_limits(maximum: u16, main: u16, minimum: u16) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut value = chain_block::BuilderData::new();
    value.append_u16(maximum).expect("max validators");
    value.append_u16(main).expect("max main validators");
    value.append_u16(minimum).expect("min validators");
    value.into_cell().expect("validator-count limits")
}

fn catchain_limits(shard_validators: u32) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut value = chain_block::BuilderData::new();
    value.append_u8(0xc2).expect("catchain config tag");
    value.append_u8(1).expect("flags plus shuffle bit");
    value.append_u32(250).expect("masterchain lifetime");
    value.append_u32(250).expect("shard lifetime");
    value.append_u32(1000).expect("validator lifetime");
    value.append_u32(shard_validators).expect("shard validator count");
    value.into_cell().expect("catchain limits")
}

#[test]
fn governance_accepts_the_launch_boundary_and_refuses_every_ceiling_above_it() {
    fn governed_change(param: i32, value: chain_block::Cell, query: u64) -> (Governed, bool) {
        use chain_block::GetRepresentationHash;
        let (mut chain, validators, _election) = elect_install_and_rotate();
        require_one_winning_round(&mut chain);
        if param == 28 {
            assert_eq!(
                raw_parameter(&chain, 28),
                Some(catchain_limits(21)),
                "the Genesis Param28 fixture changed"
            );
            // Genesis already has the exact 21 boundary. Start each governance
            // proposal at a valid 20 so acceptance must change the stored cell.
            set_contract_parameter(&mut chain, 28, catchain_limits(20));
            chain
                .blockchain
                .set_config(configuration_from_contract(&chain))
                .expect("the VM adopts the Param28 test baseline");
        }
        let before = configuration_parameters_hash(&chain);
        let raw_dir = std::env::var_os("Z01_GOVERNANCE_TX_DIR").map(std::path::PathBuf::from);
        if let (Some(dir), Some(cell)) = (&raw_dir, raw_parameter(&chain, param)) {
            std::fs::create_dir_all(dir).expect("Z01 raw config directory");
            std::fs::write(
                dir.join(format!("config-before-{query:04x}.boc")),
                chain_block::write_boc(&cell).expect("Z01 before config BOC"),
            )
            .expect("save Z01 before config BOC");
        }
        let value_hash = value.repr_hash();
        let expected = value.clone();
        let outcome = govern_install(&mut chain, &validators, param, value, query);
        let after = configuration_parameters_hash(&chain);
        let actual = raw_parameter(&chain, param);
        if let (Some(dir), Some(cell)) = (&raw_dir, &actual) {
            std::fs::write(
                dir.join(format!("config-after-{query:04x}.boc")),
                chain_block::write_boc(cell).expect("Z01 after config BOC"),
            )
            .expect("save Z01 after config BOC");
        }
        if query == 0x2800 {
            assert_eq!(
                actual,
                Some(expected),
                "governance did not store the exact Param28=21 cell"
            );
        } else if query == 0x2801 {
            assert_eq!(
                actual,
                Some(catchain_limits(20)),
                "governance changed Param28 after the 22 proposal"
            );
        }
        eprintln!(
            "z01_governance param={param} query={query} value_hash={} actual_hash={} before={} after={} decided={} installed={}",
            hex::encode(value_hash.as_slice()),
            hex::encode(
                actual
                    .as_ref()
                    .map(|cell| cell.repr_hash().as_slice().to_vec())
                    .unwrap_or_default()
            ),
            hex::encode(before),
            hex::encode(after),
            outcome.decided,
            outcome.installed,
        );
        let changed = after != before;
        (outcome, changed)
    }

    let (valid_counts, valid_counts_changed) =
        governed_change(16, validator_count_limits(21, 21, 3), 0x1600);
    assert!(
        valid_counts.decided && valid_counts_changed,
        "the exact Param16 launch boundary was refused"
    );
    let (invalid_counts, invalid_counts_changed) =
        governed_change(16, validator_count_limits(22, 21, 3), 0x1601);
    assert!(
        invalid_counts.decided && !invalid_counts_changed,
        "governance installed ConfigParam16.max_validators=22"
    );

    let (valid_catchain, valid_catchain_changed) = governed_change(28, catchain_limits(21), 0x2800);
    assert!(
        valid_catchain.decided && valid_catchain_changed,
        "the exact Param28 shard committee launch boundary was refused"
    );
    let (invalid_catchain, invalid_catchain_changed) =
        governed_change(28, catchain_limits(22), 0x2801);
    assert!(
        invalid_catchain.decided && !invalid_catchain_changed,
        "governance installed ConfigParam28.shard_validators_num=22"
    );

    let valid_set = synthetic_set(1_000_000, 21);
    let (valid_live_set, valid_live_set_changed) = governed_change(37, valid_set, 0x3700);
    assert!(
        valid_live_set.decided && valid_live_set_changed,
        "governance refused a 21-validator ConfigParam37"
    );
    let invalid_set = synthetic_set(1_000_000, 22);
    let (invalid_live_set, invalid_live_set_changed) = governed_change(37, invalid_set, 0x3701);
    assert!(
        invalid_live_set.decided && !invalid_live_set_changed,
        "governance installed a 22-validator ConfigParam37"
    );
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
/// masterchain block pay for a post-quantum verification per message, for as many messages as it
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
            TOS / 2_000,
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

    // Equality is allowed by the node. This control catches an off-by-one
    // rejection while the over-cap negative below catches a missing bound.
    let at_cap = validator_set_cell(&chain, &validators, Flaw::WeightAtProtocolCap);
    let tags = offer(&mut chain, at_cap, 8);
    assert!(
        tags.contains(&VALIDATOR_SET_INSTALLED),
        "a set at UINT64_MAX/3 was refused: {tags:02x?}"
    );

    for (query, flaw, what) in [
        (2, Flaw::DuplicateValidator, "naming one validator twice"),
        (3, Flaw::DuplicateKey, "holding one consensus key twice"),
        (4, Flaw::WeightSumDisagrees, "stating a total weight its descriptors do not sum to"),
        (5, Flaw::CountDisagrees, "stating a count its list does not hold"),
        (6, Flaw::WeightOverProtocolCap, "exceeding the validator-weight protocol cap"),
        (7, Flaw::DuplicateAdnl, "assigning one ADNL identity to two validators"),
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

/// Governance uses install_param, not the Elector's set_next_validators branch.
/// A set rejected on the latter path must not become authoritative by a vote.
#[test]
fn a_governed_next_set_obeys_the_node_descriptor_rules() {
    let (mut honest_chain, honest_validators, _election) = elect_install_and_rotate();
    require_one_winning_round(&mut honest_chain);
    let honest = validator_set_cell(&honest_chain, &honest_validators, Flaw::None);
    let control = govern_install(&mut honest_chain, &honest_validators, 36, honest, 800);
    assert_eq!(
        control,
        Governed { decided: true, installed: true },
        "the honest governed set was not installed"
    );

    for (flaw, name, query) in [
        (Flaw::DuplicateAdnl, "duplicate-ADNL", 900),
        (Flaw::WeightOverProtocolCap, "overweight", 1000),
    ] {
        let (mut bad_chain, bad_validators, _election) = elect_install_and_rotate();
        require_one_winning_round(&mut bad_chain);
        let invalid = validator_set_cell(&bad_chain, &bad_validators, flaw);
        let result = govern_install(&mut bad_chain, &bad_validators, 36, invalid, query);
        assert_eq!(
            result,
            Governed { decided: true, installed: false },
            "a governed {name} set reached ConfigParam 36"
        );
    }
}

/// The C++ node decoder reads this same BOC table. Keep both contract entry points
/// on those exact bytes, rather than building a second set of near-identical flaws.
/// Each BOC carries four members and a future interval, so the honest row reaches
/// both installation paths under the unchanged launch ConfigParam 16. Without that
/// positive control every malformed row could be refused for an unrelated fixture rule.
fn node_validator_set_cases() -> Vec<(&'static str, bool, chain_block::Cell)> {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test/pq-native/validator-set-cases.txt"
    ));
    source
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next().expect("case name");
            let expected = match fields.next().expect("node verdict") {
                "accept" => true,
                "reject" => false,
                other => panic!("unknown node verdict for {name}: {other}"),
            };
            let boc = fields.next().expect("validator-set BOC");
            assert!(fields.next().is_none(), "extra fields in node vector {name}");
            let cell = chain_block::read_single_root_boc(hex::decode(boc).expect("hex BOC"))
                .unwrap_or_else(|error| panic!("invalid node vector {name}: {error}"));
            (name, expected, cell)
        })
        .collect()
}

#[test]
fn node_validator_set_vectors_match_the_elector_install_path() {
    let cases = node_validator_set_cases();
    assert_eq!(cases.len(), 22, "the node's validator-set vector inventory changed");
    assert!(cases.iter().any(|(name, accepts, _)| *name == "valid" && *accepts));
    for (index, (name, node_accepts, set)) in cases.into_iter().enumerate() {
        // Each verdict starts without ConfigParam 36, so a rejection cannot be
        // attributed to a previous row having installed a next set.
        let mut chain = launch();
        let result = chain
            .blockchain
            .send_message(
                tos_sandbox::MessageBuilder::internal(
                    &chain.elector.clone(),
                    &chain.config_contract.clone(),
                    10 * TOS,
                )
                .body(set_next_validators_body(1000 + index as u64, set))
                .build(),
            )
            .expect("the Elector's set-next message is delivered");
        let tags = replies(&result);
        let expected = if node_accepts { VALIDATOR_SET_INSTALLED } else { VALIDATOR_SET_REFUSED };
        assert!(tags.contains(&expected), "Elector install of node vector {name}: {tags:02x?}");
        assert_eq!(
            tags.contains(&VALIDATOR_SET_INSTALLED),
            node_accepts,
            "Elector install disagrees with node decoder for {name}: {tags:02x?}"
        );
        assert_eq!(
            parameter_present(&configuration_from_contract(&chain), 36),
            node_accepts,
            "Elector storage disagrees with node decoder for {name}"
        );
    }
}

#[test]
fn node_validator_set_vectors_match_the_governance_install_path() {
    let cases = node_validator_set_cases();
    assert_eq!(cases.len(), 22, "the node's validator-set vector inventory changed");
    for (index, (name, node_accepts, set)) in cases.into_iter().enumerate() {
        let (mut chain, validators, _election) = elect_install_and_rotate();
        require_one_winning_round(&mut chain);
        let result = govern_install(&mut chain, &validators, 36, set, 2000 + index as u64 * 10);
        assert!(result.decided, "governance did not decide node vector {name}");
        assert_eq!(
            result.installed, node_accepts,
            "governance install disagrees with node decoder for {name}: {result:?}"
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
    /// Two distinct validators with distinct keys but the same transport identity.
    DuplicateAdnl,
    /// The largest total weight the node accepts; an accepted boundary control.
    WeightAtProtocolCap,
    /// The node caps total weight at UINT64_MAX/3 to keep quorum arithmetic safe.
    WeightOverProtocolCap,
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
        let weight = match flaw {
            Flaw::WeightAtProtocolCap => {
                if index == 0 {
                    u64::MAX / 3 - (validators.len() as u64 - 1)
                } else {
                    1
                }
            }
            Flaw::WeightOverProtocolCap => 1u64 << 61,
            _ => 1u64 << 40,
        };

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
        let adnl = if flaw == Flaw::DuplicateAdnl && index == 1 {
            &validators[0].adnl
        } else {
            &validator.adnl
        };
        descr.append_raw(adnl, 256).expect("transport identity");

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

// ---------------------------------------------------------------------------
// Staking through a pool, and the cutover end to end
//
// Every rule above is tested where it lives. These put them in a row: an account whose
// stake is signed with a post-quantum key -- a wallet directly, or a pool forwarding its
// money -- is registered under its own address, the election that selects it emits
// post-quantum descriptors naming that address, the configuration contract validates and
// installs them, and the set that results is the only thing that can govern the chain
// afterwards.
//
// They exist because the parts can each be right while the whole does not compose -- an
// identity that changes shape between the member book and the descriptor, a set hash the
// vote is bound to that is not the one installed. Nothing here uses a fixture that writes
// a validator set or a configuration parameter directly.
// ---------------------------------------------------------------------------

/// A single-nominator pool, deployed and funded: `owner` holds the money and `validator`
/// may spend it on a stake.
///
/// The real contract, compiled from its own source: what is being proved is that a pool's
/// money reaches an election, and a stand-in for the pool would prove nothing about the
/// pool.
fn deploy_single_nominator(
    chain: &mut Chain,
    owner: &MsgAddressInt,
    validator: &MsgAddressInt,
    balance: u64,
) -> MsgAddressInt {
    use chain_block::{GetRepresentationHash, Serializable};
    let code = tos_sandbox::compile_func_with_stdlib(&[
        repo_root().join("crypto/smartcont/single-nominator-pool/single-nominator-code.fc")
    ])
    .expect("the single-nominator contract compiles");

    let mut data = chain_block::BuilderData::new();
    owner.write_to(&mut data).expect("owner address");
    validator.write_to(&mut data).expect("validator address");

    let state = chain_block::StateInit::with_code_and_data(
        code,
        data.into_cell().expect("the pool's storage"),
    );
    let address = MsgAddressInt::with_params(
        -1,
        state.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("the pool's address");
    let funder = chain.blockchain.treasury("pool-funder", 200_000 * TOS).expect("funding");
    chain
        .blockchain
        .send_message(
            tos_sandbox::MessageBuilder::internal(funder.address(), &address, balance)
                .bounce(false)
                .state_init(state)
                .body(chain_block::Cell::default())
                .build(),
        )
        .expect("the pool deploys")
        .expect_success();
    address
}

/// The multi-nominator contract used by the lifecycle script, with its real storage
/// layout and the same 5,100 TOS validator contribution, taking orders from `operator`.
fn deploy_multi_nominator(chain: &mut Chain, operator: &MsgAddressInt) -> MsgAddressInt {
    use chain_block::{Coins, IBitstring, Serializable};
    let dir = repo_root().join("crypto/smartcont/nominator-pool");
    let code = tos_sandbox::compile_func(&[dir.join("stdlib.fc"), dir.join("pool.fc")])
        .expect("the multi-nominator pool compiles");

    let mut config = chain_block::BuilderData::new();
    config.append_raw(&operator.address().get_bytestring(0), 256).expect("operator");
    config.append_u16(4_000).expect("reward share");
    config.append_u16(40).expect("maximum nominators");
    Coins::new(5_000 * TOS).write_to(&mut config).expect("minimum validator stake");
    Coins::new(100 * TOS).write_to(&mut config).expect("minimum nominator stake");

    let mut data = chain_block::BuilderData::new();
    data.append_u8(0).expect("idle");
    data.append_u16(0).expect("no nominators");
    Coins::new(0).write_to(&mut data).expect("no sent stake");
    Coins::new(5_100 * TOS).write_to(&mut data).expect("validator contribution");
    data.checked_append_reference(config.into_cell().expect("pool config")).expect("config");
    data.append_bit_zero().expect("no nominators dictionary");
    data.append_bit_zero().expect("no withdraw requests");
    data.append_u32(0).expect("no stake election");
    data.append_raw(&[0; 32], 256).expect("no saved set hash");
    data.append_u8(0).expect("no set changes");
    data.append_u32(0).expect("no set change time");
    data.append_u32(0).expect("no stake hold period");
    data.append_bit_zero().expect("no proposal votes");

    let state =
        chain_block::StateInit::with_code_and_data(code, data.into_cell().expect("pool data"));
    let address = MsgAddressInt::with_params(
        -1,
        state.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("multi-nominator address");
    let funder = chain.blockchain.treasury("multi-pool-funder", 100_000 * TOS).expect("funder");
    let deployment =
        tos_sandbox::MessageBuilder::internal(funder.address(), &address, 13_120 * TOS)
            .bounce(false)
            .state_init(state)
            .body(chain_block::Cell::default())
            .build();
    chain.blockchain.set_account(
        address.clone(),
        Account::from_message(&deployment).expect("the pool deployment account"),
    );
    address
}

/// The order a pool's validator wallet sends it, built by the production pool builder and
/// signed for the pool: the pool is the account the elector sees send the stake.
fn pool_stake_order(
    chain: &Chain,
    pool: &MsgAddressInt,
    key: &PqValidator,
    election: u32,
    stake_amount: u64,
) -> chain_block::Cell {
    let pool_id = chain_block::UInt256::from_slice(&pool.address().get_bytestring(0));
    let signature =
        key.sign(&pq_stake_preimage(global_id(chain), election, 0x10000, &pool_id, &key.adnl));
    contracts::nominator::new_stake(&contracts::nominator::NewStakeParams {
        query_id: 1,
        stake_amount,
        validator_pubkey: &key.public_key,
        stake_at: election,
        max_factor: 0x10000,
        adnl_addr: &key.adnl,
        signature: &signature,
    })
    .expect("production pool stake order")
}

/// A single-nominator pool's money reaches an election under the pool's own address, and
/// comes back to the pool.
///
/// The pool forwards the stake terms unchanged, so the elector sees the pool as the
/// sender: the member, the validator identity in the elected set, and the account
/// everything is repaid to are all the pool. The validator wallet that ordered the stake
/// put no money up and is owed nothing.
#[test]
fn a_single_nominator_pools_stake_reaches_the_election_under_the_pool_address() {
    let (mut chain, _treasury, election) = open_election("pool-e2e", 200_000 * TOS);
    require_post_quantum_version(&chain);

    let owner = chain.blockchain.treasury("pool-e2e-owner", 100_000 * TOS).expect("an owner");
    let operator = chain.blockchain.treasury("pool-e2e-operator", 100_000 * TOS).expect("a wallet");
    let pool =
        deploy_single_nominator(&mut chain, owner.address(), operator.address(), 40_000 * TOS);
    let key = PqValidator::new(0x20);

    let order = pool_stake_order(&chain, &pool, &key, election, 11_000 * TOS);
    let result = chain
        .blockchain
        .send_message(operator.build_message(&pool, 20 * TOS, true, Some(order)))
        .expect("the order is delivered");
    result.expect_success();
    assert!(
        replies(&result).contains(&STAKE_ACCEPTED),
        "the pool's stake never reached the election: {:02x?}",
        replies(&result)
    );
    assert_eq!(pq_member_key_id_at(&chain, &pool), Some(key.key_id()), "the pool is not a member");
    assert_eq!(
        pq_member_key_id_at(&chain, operator.address()),
        None,
        "the wallet that ordered the stake became a member"
    );

    // Three more stake directly from their own wallets, so the election can conduct.
    let mut validators = vec![key];
    for index in 1..4u8 {
        let wallet = chain
            .blockchain
            .treasury(&format!("pool-e2e-peer-{index}"), 40_000 * TOS)
            .expect("a wallet");
        let peer = PqValidator::new(0x20 + index);
        let placed =
            pq_stake(&mut chain, &wallet, &peer, election, 20 + u64::from(index), 11_000 * TOS);
        assert_eq!(reply(&placed), (STAKE_ACCEPTED, 0), "peer {index} could not stake");
        validators.push(peer);
    }

    // The set names the pool.
    let closed = tick_at_close(&mut chain, election, "the close");
    assert!(closed.next_set_installed, "the election seated no set");
    let pool_id = chain_block::UInt256::from_slice(&pool.address().get_bytestring(0));
    let next = configuration_from_contract(&chain).next_validator_set().expect("the next set");
    assert!(
        next.list().iter().any(|descriptor| {
            descriptor.validator_id().expect("an identity") == pool_id
                && descriptor.consensus_key_id().expect("a key identity") == validators[0].key_id()
        }),
        "the elected set does not name the pool with the key it staked"
    );

    // Run the round to its end, and the money goes home to the pool.
    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts the installed set");
    tick(&mut chain);
    chain.blockchain.set_now(chain.blockchain.now() + 10 * 365 * 24 * 3600);
    tick(&mut chain);

    let pool_bytes: [u8; 32] = pool.address().get_bytestring(0).try_into().expect("an address");
    let operator_bytes: [u8; 32] =
        operator.address().address().get_bytestring(0).try_into().expect("an address");
    assert!(owed(&chain, &pool_bytes) > 0, "the pool was not repaid what it staked");
    assert_eq!(
        owed(&chain, &operator_bytes),
        0,
        "the ordering wallet was repaid money it never put up"
    );
}

/// What a multi-nominator pool's first stake did, across the pool and the elector.
///
/// The pool's idle state alone cannot say whether its stake bounced or the elector
/// returned it, so the transfer, the elector's outcome and its exact reply are all kept.
struct MultiNominatorStakeProbe {
    pool_to_elector: Option<u128>,
    elector_aborted: Option<bool>,
    elector_reply: Option<(u32, u32)>,
    pool_state: u8,
    pool_registered: bool,
    registered_stake: Option<u128>,
}

fn multi_nominator_first_stake_probe(stake_amount: u64) -> MultiNominatorStakeProbe {
    let (mut chain, _treasury, election) = open_election("multi-pool-first-stake", 200_000 * TOS);
    require_post_quantum_version(&chain);
    let operator = chain.blockchain.treasury("multi-pool-operator", 100_000 * TOS).expect("wallet");
    let pool = deploy_multi_nominator(&mut chain, operator.address());
    let key = PqValidator::new(0x31);

    let order = pool_stake_order(&chain, &pool, &key, election, stake_amount);
    let result = chain
        .blockchain
        .send_message(operator.build_message(&pool, TOS + TOS / 5, true, Some(order)))
        .expect("order delivered");
    result.expect_success();

    let mut sent = Vec::new();
    for transaction in result.transactions_for(&pool) {
        transaction
            .iterate_out_msgs(|message| {
                if message.dst() == Some(chain.elector.clone()) {
                    sent.push(
                        message.get_value().expect("internal transfer value").coins.as_u128(),
                    );
                }
                Ok(true)
            })
            .expect("out messages");
    }
    assert!(sent.len() <= 1, "more than one transfer from the pool to the elector: {sent:?}");
    let elector_aborted = result.transactions_for(&chain.elector).first().map(|transaction| {
        transaction.read_description().expect("Elector description").is_aborted()
    });
    let mut elector_reply = None;
    for transaction in result.transactions_for(&chain.elector) {
        transaction
            .iterate_out_msgs(|message| {
                if message.dst() == Some(pool.clone()) {
                    let mut body = message.body().expect("Elector reply body").clone();
                    let tag = body.get_next_u32().expect("reply opcode");
                    body.get_next_u64().expect("reply query id");
                    elector_reply = Some((tag, body.get_next_u32().unwrap_or(0)));
                }
                Ok(true)
            })
            .expect("Elector out messages");
    }
    let state =
        chain.blockchain.run_get_method(&pool, "get_pool_data", vec![]).expect("the pool answers");
    assert_eq!(state.exit_code, 0, "get_pool_data failed");
    let pool_state: u8 = state.stack[0]
        .as_integer()
        .expect("pool state")
        .to_string()
        .parse()
        .expect("numeric pool state");
    let pool_registered = pq_member_key_id_at(&chain, &pool).is_some();
    let registered_stake = pq_member_at(&chain, &pool).map(|member| member.stake);
    eprintln!(
        "multi-pool stake order={stake_amount}: pool_to_elector={:?} \
         elector_aborted={elector_aborted:?} elector_reply={elector_reply:?} \
         pool_state={pool_state} pool_registered={pool_registered}",
        sent.first()
    );

    MultiNominatorStakeProbe {
        pool_to_elector: sent.pop(),
        elector_aborted,
        elector_reply,
        pool_state,
        pool_registered,
        registered_stake,
    }
}

/// The pool forwards exactly the value it was ordered to, and the elector keeps one TOS
/// of it for the confirmation: an order of exactly the minimum stake is a stake one TOS
/// short, refused for that reason, and the pool is idle again.
#[test]
fn a_multi_nominator_first_stake_exposes_the_exact_refusal() {
    let probe = multi_nominator_first_stake_probe(10_000 * TOS);
    assert_eq!(probe.pool_to_elector, Some(u128::from(10_000 * TOS)));
    assert_eq!(probe.elector_aborted, Some(false));
    assert_eq!(probe.elector_reply, Some((STAKE_RETURNED, REASON_BELOW_MINIMUM)));
    assert_eq!(probe.pool_state, 0, "the pool still waits for a stake the elector returned");
    assert!(!probe.pool_registered);
}

#[test]
fn a_multi_nominator_first_stake_with_the_confirmation_allowance_is_accepted() {
    let probe = multi_nominator_first_stake_probe(10_001 * TOS);
    assert_eq!(probe.pool_to_elector, Some(u128::from(10_001 * TOS)));
    assert_eq!(probe.elector_aborted, Some(false));
    assert_eq!(probe.elector_reply, Some((STAKE_ACCEPTED, 0)));
    assert_eq!(probe.pool_state, 2, "the pool did not record the accepted stake");
    assert!(probe.pool_registered, "the elector did not register the pool");
    assert_eq!(probe.registered_stake, Some(u128::from(10_000 * TOS)));
}

#[test]
fn post_quantum_authority_holds_from_the_stake_to_the_governed_change() {
    let (mut chain, _treasury, election) = open_election("cutover-e2e", 200_000 * TOS);
    require_post_quantum_version(&chain);

    // --- each validator stakes from its own wallet, signing for that wallet ----------
    let mut wallets = Vec::new();
    let mut validators = Vec::new();
    for index in 0..4u8 {
        let wallet = chain
            .blockchain
            .treasury(&format!("cutover-wallet-{index}"), 40_000 * TOS)
            .expect("a funded wallet");
        let validator = PqValidator::new(0x80 + index);
        let result = pq_stake(
            &mut chain,
            &wallet,
            &validator,
            election,
            10 + u64::from(index),
            11_000 * TOS,
        );
        result.expect_success();
        assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "wallet {index} could not place a stake");
        wallets.push(wallet);
        validators.push(validator);
    }

    // --- the election selects them, and the configuration contract installs them ----
    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    let result =
        chain.blockchain.tick_tock(&chain.elector, TransactionTickTock::Tick).expect("tick runs");
    result.expect_success();
    assert!(
        replies(&result).contains(&VALIDATOR_SET_INSTALLED),
        "the configuration contract refused the elected set: {:02x?}",
        replies(&result)
    );
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

    // The set is post-quantum, and it names the wallets that staked, with their keys.
    let set = chain.blockchain.config_params().validator_set().expect("a current set");
    assert_eq!(set.list().len(), 4, "every wallet should have been elected");
    for descriptor in set.list() {
        assert!(descriptor.pq_key().is_some(), "the elected set carries a classical descriptor");
        let id = descriptor.validator_id().expect("an identity");
        let key_id = descriptor.consensus_key_id().expect("a key identity");
        assert!(
            wallets.iter().zip(&validators).any(|(wallet, validator)| {
                chain_block::UInt256::from_slice(&wallet.address().address().get_bytestring(0))
                    == id
                    && validator.key_id() == key_id
            }),
            "the set names an identity or a key no wallet staked with"
        );
    }

    // --- only the current set can govern --------------------------------------------
    let proposal = propose(&mut chain, 42, 0xc0de);
    let relay = chain.blockchain.treasury("cutover-relay", 1_000 * TOS).expect("an account");

    let voter = &validators[0];
    let idx = index_of(&chain, voter);
    let signature = voter.sign_under(&vote_preimage(&chain, idx, &proposal), CONFIG_VOTE_CONTEXT);
    let result = chain
        .blockchain
        .send_message(relay.build_message(
            &chain.config_contract,
            VOTE_VALUE,
            true,
            Some(vote_body(1, &signature, idx, &proposal)),
        ))
        .expect("the vote is delivered");
    assert_eq!(exit_code_of(&result), 0, "a validator of the current set could not vote");
    assert_eq!(proposal_voters(&chain, &proposal), vec![idx], "the vote was not counted");

    // Another validator's signature at that index is refused, and counts for nobody.
    let stolen =
        validators[1].sign_under(&vote_preimage(&chain, idx, &proposal), CONFIG_VOTE_CONTEXT);
    chain
        .blockchain
        .send_message(relay.build_message(
            &chain.config_contract,
            VOTE_VALUE,
            true,
            Some(vote_body(2, &stolen, idx, &proposal)),
        ))
        .expect("the vote is delivered")
        .expect_aborted()
        .expect_exit_code(ERROR_BAD_VOTE_SIGNATURE);
    assert_eq!(
        proposal_voters(&chain, &proposal),
        vec![idx],
        "a vote signed by the wrong validator changed who had voted"
    );

    // And nothing arrives from outside the chain.
    assert!(
        chain
            .blockchain
            .send_message(
                tos_sandbox::MessageBuilder::external(&chain.config_contract)
                    .body(vote_body(3, &signature, idx, &proposal))
                    .build(),
            )
            .is_err(),
        "the configuration contract accepted an external message"
    );
    assert_eq!(
        proposal_voters(&chain, &proposal),
        vec![idx],
        "an external message changed who had voted"
    );

    // --- the same, for a complaint against a validator of the closed election --------
    let accused = validator_id_at(&chain, index_of(&chain, &validators[3]));
    let complainant =
        chain.blockchain.treasury("cutover-complainant", 10_000 * TOS).expect("an account");
    let filed = chain
        .blockchain
        .send_message(complainant.build_message(
            &chain.elector,
            300 * TOS,
            true,
            Some(complaint_body(1, election, &accused)),
        ))
        .expect("the complaint is delivered");
    assert!(replies(&filed).contains(&COMPLAINT_ACCEPTED), "the elector refused the complaint");
    let complaint = complaint_hashes(&chain, election)[0];

    let counted = chain
        .blockchain
        .send_message(relay.build_message(
            &chain.elector,
            VOTE_VALUE,
            true,
            Some(complaint_vote_body(
                10,
                &validators[0].sign_under(
                    &complaint_vote_preimage(&chain, idx, election, &complaint),
                    ELECTION_CONTEXT,
                ),
                idx,
                election,
                &complaint,
            )),
        ))
        .expect("the vote is delivered");
    assert_eq!(exit_code_of(&counted), 0, "a validator of the current set could not vote");
    assert_eq!(
        complaint_voters(&chain, election, &complaint),
        vec![idx],
        "the complaint vote was not counted"
    );

    // Signed by a validator that is not the one at that index.
    let stolen_complaint = validators[1]
        .sign_under(&complaint_vote_preimage(&chain, idx, election, &complaint), ELECTION_CONTEXT);
    chain
        .blockchain
        .send_message(relay.build_message(
            &chain.elector,
            VOTE_VALUE,
            true,
            Some(complaint_vote_body(11, &stolen_complaint, idx, election, &complaint)),
        ))
        .expect("the vote is delivered")
        .expect_aborted()
        .expect_exit_code(ERROR_BAD_VOTE_SIGNATURE);
    assert_eq!(
        complaint_voters(&chain, election, &complaint),
        vec![idx],
        "a complaint vote signed by the wrong validator changed who had voted"
    );

    // The classical complaint vote operation: the elector does not know it, so the
    // message is answered as an unknown query and nothing is recorded.
    use chain_block::IBitstring;
    let mut legacy = chain_block::BuilderData::new();
    legacy.append_u32(0x5674_4370).expect("the operation that used to carry a complaint vote");
    legacy.append_u64(12).expect("query id");
    legacy.append_raw(&[0u8; 64], 512).expect("an Ed25519 signature");
    legacy.append_u32(0x5674_4350).expect("the tag it used to sign under");
    legacy.append_u16(idx).expect("index");
    legacy.append_u32(election).expect("election");
    legacy.append_raw(&complaint, 256).expect("complaint");
    let refused = chain
        .blockchain
        .send_message(relay.build_message(
            &chain.elector,
            VOTE_VALUE,
            true,
            Some(legacy.into_cell().expect("a legacy complaint vote")),
        ))
        .expect("the message is delivered");
    refused.expect_success();
    assert_eq!(
        reply(&refused).0,
        UNKNOWN_QUERY,
        "the elector still recognises the classical complaint vote"
    );
    assert_eq!(
        complaint_voters(&chain, election, &complaint),
        vec![idx],
        "an Ed25519 complaint vote changed who had voted"
    );

    // --- a governed change still goes through ---------------------------------------
    require_one_winning_round(&mut chain);
    let value = proposal_value(0xc0de_0001);
    let governed = govern_install(&mut chain, &validators, 42, value.clone(), 400);
    assert!(governed.decided, "the validators did not carry the proposal");
    assert_eq!(
        raw_parameter(&chain, 42),
        Some(value),
        "a change the current validators voted for was not made"
    );

    // --- and no key can make one on its own ------------------------------------------
    assert!(
        !govern_install(&mut chain, &validators, -999, stored_bytes(&[0x5a; 32]), 500).installed,
        "the validators voted an administrator in"
    );
}

// ---------------------------------------------------------------------------
// What a vote must bring, and what an invalid one cannot take
//
// Both vote paths verify an ML-DSA-44 signature, whose cost cannot be made cheaper by
// being wrong: an invalid signature is found only by performing the verification.
// Anyone may send a vote, so the sender has to pay for it before it happens, and a sender
// who keeps sending invalid ones must not be able to spend the contract's own balance
// doing it.
//
// The minimum is found by searching for it rather than by recomputing the contract's
// rule here. A test that derives the boundary the same way the contract does would agree
// with a contract that had stopped applying it, and the number that matters to an
// operator is the whole transaction's cost, not the gate constant alone.
// ---------------------------------------------------------------------------

/// The balance an account holds, in nanotomis.
fn balance_of(chain: &Chain, address: &MsgAddressInt) -> u128 {
    chain
        .blockchain
        .get_account(address)
        .expect("the account is deployed")
        .balance()
        .expect("an active account has a balance")
        .coins
        .as_u128()
}

/// The smallest value for which `send` succeeds, by bisection over [low, high].
///
/// `high` must succeed and `low` must fail, and both are checked: a search whose ends
/// are both on the same side would return an endpoint and look like an answer.
fn smallest_value_that_works(
    chain: &mut Chain,
    low: u64,
    high: u64,
    mut send: impl FnMut(&mut Chain, u64, u64) -> bool,
) -> u64 {
    let mut query = 1_000u64;
    assert!(!send(chain, low, query), "the bottom of the search already works");
    query += 1;
    assert!(send(chain, high, query), "the top of the search does not work");
    let (mut low, mut high) = (low, high);
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        query += 1;
        if send(chain, mid, query) {
            high = mid;
        } else {
            low = mid;
        }
    }
    high
}

/// What a configuration vote must carry to be counted.
#[test]
fn the_minimum_value_a_configuration_vote_must_carry() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let relay = chain.blockchain.treasury("min-config-relay", 100_000 * TOS).expect("an account");

    // A fresh proposal for each attempt, so a vote that succeeded cannot make a later
    // attempt fail for having already voted -- which would read as a funding refusal.
    let voter_index = index_of(&chain, &validators[0]);
    let mut attempt = |chain: &mut Chain, value: u64, query: u64| -> bool {
        let proposal = propose(chain, 42, 0x1000 + query as u32);
        let signature = validators[0]
            .sign_under(&vote_preimage(chain, voter_index, &proposal), CONFIG_VOTE_CONTEXT);
        let result = chain
            .blockchain
            .send_message(relay.build_message(
                &chain.config_contract,
                value,
                true,
                Some(vote_body(query, &signature, voter_index, &proposal)),
            ))
            .expect("the vote is delivered");
        exit_code_of(&result) == 0 && proposal_voters(chain, &proposal) == vec![voter_index]
    };

    let minimum = smallest_value_that_works(&mut chain, TOS / 20_000, TOS / 20, &mut attempt);

    // Two-sided, because a one-sided bound passes when the cost collapses as readily as
    // when it is right, and a verification that stopped happening would do exactly that.
    // A verification is priced as the Ed25519 check, 4,000 gas, which at the configured
    // masterchain gas price is about 0.002 TOS, so a vote counted far below that had none
    // paid for.
    assert!(
        minimum > TOS / 1_000,
        "a configuration vote is counted for {minimum} nanotomis, too little to have paid \
         for an ML-DSA-44 verification"
    );
    assert!(
        minimum <= TOS / 50,
        "a configuration vote now costs {minimum} nanotomis, far more than the \
         verification it asks for"
    );
}

/// An underfunded vote is refused having done almost none of the work it asked for.
///
/// This is the cheapest message an unauthorised sender can repeat without limit: it
/// carries far less than a verification costs, and its signature is wrong, so nothing
/// about it is worth the verification it would take to find that out.
///
/// What is measured is the work, not a balance. The configuration contract's balance
/// does not move for any of these messages -- not for a refusal, and not for a vote that
/// is counted -- so an assertion about it would hold whatever the contract did. The
/// protection that exists is that the refusal happens before the verification, and that
/// is visible in gas.
#[test]
fn an_underfunded_configuration_vote_is_refused_before_the_verification() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let proposal = propose(&mut chain, 42, 0xbeef);
    let idx = index_of(&chain, &validators[0]);
    // Valid in every respect except who signed it, so each message is refused only after
    // the verification has been paid for and performed.
    let stolen =
        validators[1].sign_under(&vote_preimage(&chain, idx, &proposal), CONFIG_VOTE_CONTEXT);
    let relay = chain.blockchain.treasury("drain-relay", 1_000_000 * TOS).expect("an account");
    // Well under what a verification costs, which the minimum-value test measures.
    let too_little = TOS / 2_000;

    // What the same message costs when it is funded and the verification does happen.
    // Measured rather than assumed, so the comparison below follows the contract.
    let verified = chain
        .blockchain
        .send_message(relay.build_message(
            &chain.config_contract,
            VOTE_VALUE,
            true,
            Some(vote_body(499, &stolen, idx, &proposal)),
        ))
        .expect("the vote is delivered");
    assert_eq!(exit_code_of(&verified), ERROR_BAD_VOTE_SIGNATURE, "the fixture needs a refusal");
    let cost_of_verifying = compute_gas(&verified);

    let balance = balance_of(&chain, &chain.config_contract);
    let mut refusal = 0u64;
    for round in 0..16u64 {
        let result = chain
            .blockchain
            .send_message(relay.build_message(
                &chain.config_contract,
                too_little,
                true,
                Some(vote_body(500 + round, &stolen, idx, &proposal)),
            ))
            .expect("the vote is delivered");
        result.expect_aborted().expect_exit_code(ERROR_VOTE_UNDERFUNDED);
        refusal = compute_gas(&result);
    }

    assert!(
        refusal * 8 < cost_of_verifying,
        "refusing an underfunded vote costs {refusal} gas against {cost_of_verifying} for \
         one that is verified, so the verification is happening before the refusal"
    );
    assert!(refusal > 0, "the refusal cost nothing, so the contract never ran");
    assert_eq!(
        balance_of(&chain, &chain.config_contract),
        balance,
        "the balance moved, so it is worth asserting on after all"
    );
    assert!(proposal_voters(&chain, &proposal).is_empty(), "an invalid vote was registered");
}

/// The indices that have voted on a complaint, read from the elector's own storage.
fn complaint_voters(chain: &Chain, election: u32, complaint: &[u8; 32]) -> Vec<u16> {
    let account = chain.blockchain.get_account(&chain.elector).expect("the elector is deployed");
    let data = account.get_data().expect("the elector has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    next_dictionary(&mut slice, 32); // the active election
    next_dictionary(&mut slice, 256); // credits
    let past = next_dictionary(&mut slice, 32);
    let mut record = past
        .get(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(election.to_be_bytes().to_vec(), 32)
                    .expect("a key"),
            )
            .expect("a key slice"),
        )
        .expect("lookup")
        .expect("the election is remembered");
    record.get_next_u32().expect("unfreeze at");
    record.get_next_u32().expect("stake held");
    record.get_next_bits(256).expect("the set hash");
    next_dictionary(&mut record, 256); // the frozen stakes
    for _ in 0..2 {
        let bytes = record.get_next_int(4).expect("an amount length") as usize;
        if bytes > 0 {
            record.get_next_bits(bytes * 8).expect("an amount");
        }
    }
    let complaints = next_dictionary(&mut record, 256);
    let status = complaints.get(
        chain_block::SliceData::load_builder(
            chain_block::BuilderData::with_raw(complaint.to_vec(), 256).expect("a key"),
        )
        .expect("a key slice"),
    );
    let mut status = match status.expect("lookup") {
        Some(s) => s,
        None => return Vec::new(),
    };
    assert_eq!(status.get_next_byte().expect("the status tag"), 0x2d, "not a complaint status");
    status.checked_drain_reference().expect("the complaint");
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

// ---------------------------------------------------------------------------
// What the cutover costs at the sizes the chain is configured for
//
// The PQ launch configuration admits at most 21 validators. Measure the four-member
// fixture and that actual ceiling; 100/400-member elections are invalid inputs, not
// performance targets. Separate refusal tests pin the 22-member boundary.
//
// The sets here are synthesised rather than elected, because what is being measured is
// the contract's work over a set of a given size and not the election that produced it.
// Each descriptor is distinct in both identities, as an elected one would be.
// ---------------------------------------------------------------------------

/// A validator set of `count` descriptors, each with its own identity and its own key.
fn synthetic_set(now: u32, count: u16) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut list = chain_block::HashmapE::with_bit_len(16);
    let weight = 1u64 << 40;
    for index in 0..count {
        // A key of the admitted length, differing between descriptors, so each derives
        // its own key identity the way an elected one does.
        let mut key = vec![0x5au8; MLDSA44_PUBLIC_KEY_BYTES];
        key[0..2].copy_from_slice(&index.to_be_bytes());
        let mut identity = [0u8; 32];
        identity[30..32].copy_from_slice(&(index + 1).to_be_bytes());
        let mut adnl = [0u8; 32];
        adnl[0..2].copy_from_slice(&index.to_be_bytes());
        adnl[31] = 1;

        let mut descr = chain_block::BuilderData::new();
        descr.append_u8(0xb3).expect("tag");
        descr.append_raw(&identity, 256).expect("validator identity");
        descr.append_u16(1).expect("algorithm");
        descr
            .append_raw(chain_block::derive_consensus_key_id(1, &key).as_slice(), 256)
            .expect("key identity");
        descr.checked_append_reference(stored_bytes(&key)).expect("the key");
        descr.append_u64(weight).expect("weight");
        descr.append_raw(&adnl, 256).expect("transport identity");

        let mut at = chain_block::BuilderData::new();
        at.append_u16(index).expect("the index");
        list.set_builder(chain_block::SliceData::load_builder(at).expect("a key slice"), &descr)
            .expect("the descriptor is stored");
    }

    let since = now + 1000;
    let mut set = chain_block::BuilderData::new();
    set.append_u8(0x12).expect("validators_ext#12");
    set.append_u32(since).expect("utime_since");
    set.append_u32(since + 100_000).expect("utime_until");
    set.append_u16(count).expect("total");
    set.append_u16(count).expect("main");
    set.append_u64(weight * u64::from(count)).expect("total weight");
    set.append_bit_one().expect("a non-empty list");
    set.checked_append_reference(
        chain_block::HashmapType::data(&list).expect("a non-empty list").clone(),
    )
    .expect("the list");
    set.into_cell().expect("a validator set")
}

/// What the configuration contract spends checking a set before it installs it,
/// at every representative size the enforced launch range can actually reach.
///
/// This runs once per elected set, over every descriptor, and it is the only thing
/// standing between an election and a Config36 the node would refuse to start from.
#[test]
fn the_pre_install_check_is_measured_at_the_enforced_launch_sizes() {
    let (mut chain, _treasury, _election) = open_election("preinstall-scale", 200_000 * TOS);
    require_post_quantum_version(&chain);
    raise_validator_ceiling(&mut chain, 21);

    let mut measured = Vec::new();
    for (query, count) in [(1u64, 4u16), (2, 12), (3, 21)] {
        let set = synthetic_set(chain.blockchain.now(), count);
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
        let tags = replies(&result);
        assert!(
            tags.contains(&VALIDATOR_SET_INSTALLED),
            "a set of {count} was refused: {tags:02x?}"
        );
        measured.push((count, compute_gas(&result)));
    }

    for (count, gas) in &measured {
        eprintln!("pre-install check, {count} validators: {gas} gas");
    }

    // The elector and the configuration contract are special accounts, allowed seventy
    // million gas by the masterchain prices the zerostate sets. The largest set the
    // configuration permits has to fit in that with room to spare, or an election that
    // succeeds produces a set nothing can install.
    let (largest, cost) = measured.last().expect("a measurement");
    assert!(
        *cost < 20_000_000,
        "checking {largest} validators costs {cost} gas, too close to what a masterchain \
         transaction may spend"
    );

    // And the cost has to follow the count: a check that stopped looking at every
    // descriptor would flatten here, and nothing else would say so.
    let (small, small_gas) = measured[0];
    assert!(
        *cost > small_gas,
        "checking {largest} validators costs {cost} gas against {small_gas} for {small}, so \
         the check is not running over every descriptor"
    );

    let oversized = synthetic_set(chain.blockchain.now(), 22);
    let refused = chain
        .blockchain
        .send_message(
            tos_sandbox::MessageBuilder::internal(
                &chain.elector.clone(),
                &chain.config_contract.clone(),
                10 * TOS,
            )
            .body(set_next_validators_body(4, oversized))
            .build(),
        )
        .expect("the oversized set message is delivered");
    let tags = replies(&refused);
    assert!(
        tags.contains(&VALIDATOR_SET_REFUSED) && !tags.contains(&VALIDATOR_SET_INSTALLED),
        "a 22-validator set crossed the enforced launch cap: {tags:02x?}"
    );
}

/// Select a validator ceiling within the compiled launch cap for a focused fixture.
fn raise_validator_ceiling(chain: &mut Chain, max: u16) {
    use chain_block::IBitstring;
    let mut value = chain_block::BuilderData::new();
    value.append_u16(max).expect("max validators");
    value.append_u16(max).expect("max main validators");
    value.append_u16(1).expect("min validators");
    set_contract_parameter(chain, 16, value.into_cell().expect("a validator count"));
}

/// The account a synthetic member is registered under when a test does not choose one.
fn synthetic_id(index: u16) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[30..32].copy_from_slice(&(index + 1).to_be_bytes());
    id
}

/// Put a book of `count` members into the open election, each staking `stake_each`.
///
/// Written into storage rather than staked for, because what the measurements are about
/// is selection over a book. Placing even 21 signed stakes would mostly measure the
/// fixture rather than the contract. Every member is distinct in its address, its key and
/// its transport address, as a staked one would be.
fn install_synthetic_book(chain: &mut Chain, count: u16, stake_each: u64) {
    install_synthetic_book_full(chain, count, &synthetic_id, &|_| stake_each)
}

/// The same, with each member's address and stake chosen. Equal stakes are capped at the
/// smallest and leave nothing over, so a book where they differ is the only one where the
/// unused part of a stake exists at all.
///
/// The record is the one `process_new_stake` writes -- `stake time max_factor key_id
/// adnl_addr algorithm_id ^public_key` -- under the member's address, and the running
/// total is set to what the book holds, as the stakes that built it would have left it.
fn install_synthetic_book_full(
    chain: &mut Chain,
    count: u16,
    id_of: &dyn Fn(u16) -> [u8; 32],
    stake_of: &dyn Fn(u16) -> u64,
) {
    use chain_block::{IBitstring, Serializable};
    let mut members = chain_block::HashmapE::with_bit_len(256);
    let mut total = 0u64;
    for index in 0..count {
        let mut key = vec![0x5au8; MLDSA44_PUBLIC_KEY_BYTES];
        key[0..2].copy_from_slice(&index.to_be_bytes());
        let key_id = chain_block::derive_consensus_key_id(1, &key);
        let mut adnl = [0u8; 32];
        adnl[0..2].copy_from_slice(&index.to_be_bytes());
        adnl[31] = 1;

        let mut record = chain_block::BuilderData::new();
        chain_block::Coins::new(stake_of(index)).write_to(&mut record).expect("the stake");
        record.append_u32(chain.blockchain.now()).expect("registered at");
        record.append_u32(0x10000).expect("max factor");
        record.append_raw(key_id.as_slice(), 256).expect("key identity");
        record.append_raw(&adnl, 256).expect("transport identity");
        record.append_u16(1).expect("algorithm");
        record.checked_append_reference(stored_bytes(&key)).expect("the key");

        let id_key = chain_block::SliceData::load_builder(
            chain_block::BuilderData::with_raw(id_of(index).to_vec(), 256).expect("a key"),
        )
        .expect("a key slice");
        members.set_builder(id_key, &record).expect("the member is stored");
        total = total.checked_add(stake_of(index)).expect("a fixture total");
    }

    // Rewrite the open election with this book, keeping its times and its minimum.
    let mut account =
        chain.blockchain.get_account(&chain.elector).expect("the elector is deployed").clone();
    let data = account.get_data().expect("the elector has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let elect = next_dictionary(&mut slice, 32);
    let root = chain_block::HashmapType::data(&elect).expect("an active election").clone();
    let mut es = chain_block::SliceData::load_cell(root).expect("the election");

    let mut rebuilt = chain_block::BuilderData::new();
    rebuilt.append_u32(es.get_next_u32().expect("elect_at")).expect("elect_at");
    rebuilt.append_u32(es.get_next_u32().expect("elect_close")).expect("elect_close");
    let minimum = u64::try_from(next_coins(&mut es)).expect("a minimum stake");
    chain_block::Coins::new(minimum).write_to(&mut rebuilt).expect("the minimum stake");
    chain_block::Coins::new(total).write_to(&mut rebuilt).expect("the running total");
    match chain_block::HashmapType::data(&members) {
        Some(cell) => {
            rebuilt.append_bit_one().expect("a non-empty book");
            rebuilt.checked_append_reference(cell.clone()).expect("the book");
        }
        None => {
            rebuilt.append_bit_zero().expect("an empty book");
        }
    }
    rebuilt.append_bit_zero().expect("not failed");
    rebuilt.append_bit_zero().expect("not finished");

    let mut storage = chain_block::BuilderData::new();
    storage.append_bit_one().expect("an active election");
    storage
        .checked_append_reference(rebuilt.into_cell().expect("the election"))
        .expect("the election");
    storage.checked_append_references_and_data(&slice).expect("the rest of the storage");
    account.set_data(storage.into_cell().expect("storage"));
    chain.blockchain.set_account(chain.elector.clone(), account);
    assert_eq!(declared_total_stake(chain), u128::from(total), "the book's total was not kept");
}

/// What an election costs at the sizes the chain allows, from the book to the set the
/// configuration contract installs.
#[test]
fn an_election_is_measured_at_the_sizes_the_chain_allows() {
    let mut measured = Vec::new();
    for count in [4u16, 21] {
        let (mut chain, _treasury, election) =
            open_election(&format!("election-scale-{count}"), 200_000 * TOS);
        require_post_quantum_version(&chain);
        raise_validator_ceiling(&mut chain, 21);
        install_synthetic_book(&mut chain, count, 11_000 * TOS);

        chain.blockchain.set_now(election - chain.elect_end_before);
        let result = chain
            .blockchain
            .tick_tock(&chain.elector, TransactionTickTock::Tick)
            .expect("tick runs");
        result.expect_success();
        let tags = replies(&result);
        assert!(
            tags.contains(&VALIDATOR_SET_INSTALLED),
            "an election of {count} did not produce a set the configuration installed: \
             {tags:02x?}"
        );
        let installed = configuration_from_contract(&chain)
            .next_validator_set()
            .expect("the stored set parses");
        assert_eq!(installed.list().len(), count as usize, "not every member was elected");
        measured.push((count, tick_gas(&result)));
    }

    for (count, gas) in &measured {
        eprintln!("election and set production, {count} members: {gas} gas");
    }

    let (largest, cost) = measured.last().expect("a measurement");
    assert!(
        *cost < 50_000_000,
        "electing {largest} members costs {cost} gas, too close to what a masterchain \
         transaction may spend"
    );
    let (small, small_gas) = measured[0];
    assert!(
        cost > &small_gas,
        "electing {largest} members costs {cost} gas against {small_gas} for {small}, so the \
         measurement did not retain the member-dependent selection cost"
    );
}

/// What the elector owes an account, in nanotomis.
fn owed(chain: &Chain, account: &[u8; 32]) -> u128 {
    // The get-method takes the address as a 256-bit unsigned integer. Built from the
    // bytes rather than from a hexadecimal string: `big_int` strips an `0x` prefix and
    // then parses what is left in decimal, which reads most addresses as a different
    // number and the rest as an error.
    let argument = tos_vm::stack::StackItem::integer(
        tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(account),
    );
    let result = chain
        .blockchain
        .run_get_method(&chain.elector, "compute_returned_stake", vec![argument])
        .expect("the elector answers");
    assert_eq!(result.exit_code, 0, "compute_returned_stake failed");
    result
        .stack
        .last()
        .expect("a value")
        .as_integer()
        .expect("an integer")
        .to_string()
        .parse()
        .expect("an amount")
}

/// The whole round, from the election to the stake coming back.
///
/// Two things only this test can see. The part of a stake the selection does not take is
/// credited straight away, which needs members who staked different amounts -- equal
/// stakes are all capped at the smallest and leave nothing over. And the part it does
/// take is held in the frozen record until the round ends, and returned to the account
/// that record names, which needs the round to actually end.
#[test]
fn the_stake_and_its_unused_part_both_come_back_to_the_member() {
    let (mut chain, _treasury, election) = open_election("member-round", 400_000 * TOS);
    require_post_quantum_version(&chain);
    raise_validator_ceiling(&mut chain, 21);

    // One member stakes three times what the others do, so the selection caps it and the
    // rest is left over.
    let members = 21u16;
    let base = 11_000 * TOS;
    let stake_of = |index: u16| if index == 0 { 3 * base } else { base };
    install_synthetic_book_full(&mut chain, members, &refund_owner, &stake_of);
    let rich = refund_owner(0);

    chain.blockchain.set_now(election - chain.elect_end_before);
    let result =
        chain.blockchain.tick_tock(&chain.elector, TransactionTickTock::Tick).expect("tick runs");
    result.expect_success();
    assert!(replies(&result).contains(&VALIDATOR_SET_INSTALLED), "the election did not run");

    // The part the selection did not take is already owed, and it is exactly the part
    // above what the capped stake froze.
    let left_over = owed(&chain, &rich);
    assert_eq!(left_over, u128::from(2 * base), "the surplus over the cap was not credited");
    let frozen = frozen_by_owner(&chain, election);
    assert_eq!(frozen.get(&rich).copied(), Some(u128::from(base)), "the capped stake moved");
    for index in 1..members {
        assert_eq!(owed(&chain, &refund_owner(index)), 0, "member {index} was credited a surplus");
    }

    // Finish the round and let the held stake come back.
    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts the installed set");
    tick(&mut chain);
    assert_eq!(active_election_id(&chain), 0, "the election should be finished by now");

    // Past the point the stake is held to, and one more tick to release it.
    chain.blockchain.set_now(chain.blockchain.now() + 10 * 365 * 24 * 3600);
    tick(&mut chain);

    assert_eq!(
        owed(&chain, &rich),
        u128::from(3 * base),
        "the held stake did not come back to the member on top of the unused part"
    );
}

/// A stake the contract itself recorded, rather than one a test wrote into the book.
///
/// The test above puts members into the election directly, which exercises what the
/// elector does with a record but not what it writes into one. Here every stake is real,
/// and the round is driven to its end, so what the held stakes come back to is the
/// account each member record and frozen entry names.
#[test]
fn a_real_stake_is_repaid_to_the_account_that_sent_it() {
    let (mut chain, treasury, election) = open_election("recorded-owner", 200_000 * TOS);
    require_post_quantum_version(&chain);
    let _ = treasury;

    let mut senders = Vec::new();
    for index in 0..4u8 {
        let validator = PqValidator::new(0x60 + index);
        let account = chain
            .blockchain
            .treasury(&format!("recorded-owner-{index}"), 40_000 * TOS)
            .expect("a funded account");
        let result = pq_stake(
            &mut chain,
            &account,
            &validator,
            election,
            20 + u64::from(index),
            11_000 * TOS,
        );
        assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "validator {index} could not stake");
        let bytes: [u8; 32] =
            account.address().address().get_bytestring(0).try_into().expect("an address");
        senders.push(bytes);
    }

    // Conduct the election, finish the round, and let the held stakes come back.
    chain.blockchain.set_now(election - chain.elect_end_before);
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
    chain.blockchain.set_now(chain.blockchain.now() + 10 * 365 * 24 * 3600);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();

    for (index, sender) in senders.iter().enumerate() {
        assert!(
            owed(&chain, sender) > 0,
            "member {index}: the elector owes the account that staked nothing, so the record \
             kept something else"
        );
    }
}

// ---------------------------------------------------------------------------
// Votes the node itself produced
//
// Everything above builds a vote in the test and checks the contract accepts it, which
// proves the contract and proves nothing about the node. These run the node's own
// producer -- its custodied seed file, its preimage, its signer, its wire -- and require
// the real contract to count what comes out.
//
// The producer is reached through `tos-pq-vote`, which is the same calls the node makes,
// exposed to a command line. It signs votes and stake authorisations and nothing else.
// ---------------------------------------------------------------------------

/// The node-side vote producer, built from the repository.
fn vote_tool() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("PQ_VOTE_TOOL") {
        return std::path::PathBuf::from(path);
    }
    let root = repo_root();
    for candidate in ["build/crypto/tos-pq-vote", "build/tos-pq-vote"] {
        let path = root.join(candidate);
        if path.exists() {
            return path;
        }
    }
    panic!(
        "the node's vote producer is needed: build it with `ninja -C build tos-pq-vote`, or \
         point PQ_VOTE_TOOL at it"
    );
}

fn repo_root() -> std::path::PathBuf {
    std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root above the contracts crate")
            .to_path_buf()
    })
}

/// Provision a validator's consensus seed the way an operator does: into a directory
/// only this process can write.
///
/// The keys these tests sign with live in the shared temporary directory, which anyone
/// can write to, and the node refuses to load a key from such a place -- a directory
/// anyone can write is a directory anyone can put a key in. Copying it here is the same
/// step an operator takes when moving a seed onto a validator host, and it is what makes
/// the node's own loader the thing under test rather than something to be worked around.
fn seed_file_for(validator: &PqValidator) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let home = std::env::temp_dir().join(format!("tos-node-custody-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("a private directory for the seed");
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
        .expect("only this process may write it");
    let seed = home.join(validator.key_file.file_name().expect("the seed has a name"));
    // Concurrent native-tool tests may provision the same fixture. Publish a
    // complete file atomically so no reader observes a truncation in progress.
    let temporary = tempfile::NamedTempFile::new_in(&home).expect("private staging file");
    std::fs::copy(&validator.key_file, temporary.path()).expect("the test seed is provisioned");
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o600))
        .expect("owner-only, as the node insists");
    temporary.persist(&seed).expect("publish complete test seed");
    seed
}

/// A stake authorisation, produced by the node's own producer from its custodied seed.
///
/// The test names the terms and the tool builds the preimage and signs it, as the node's
/// creator does. Nothing about a validator set is passed in, because the node signs its
/// first stake before it is in one.
fn run_stake_tool(
    consensus: &PqValidator,
    global_id: i32,
    src_addr: &chain_block::UInt256,
    election: u32,
    max_factor: u32,
) -> Vec<u8> {
    let out = std::process::Command::new(vote_tool())
        .args([
            "stake".to_string(),
            seed_file_for(consensus).to_str().expect("path").to_string(),
            global_id.to_string(),
            hex::encode(src_addr.as_slice()),
            election.to_string(),
            max_factor.to_string(),
            hex::encode(consensus.adnl),
        ])
        .output()
        .expect("the stake producer runs");
    assert!(
        out.status.success(),
        "the node could not authorise a stake: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let signature = hex::decode(String::from_utf8_lossy(&out.stdout).trim()).expect("hex");
    assert_eq!(signature.len(), 2420, "the node produced a signature of the wrong length");
    signature
}

fn run_vote_tool(arguments: &[String]) -> chain_block::Cell {
    let out = std::process::Command::new(vote_tool())
        .args(arguments)
        .output()
        .expect("the vote producer runs");
    assert!(
        out.status.success(),
        "the node could not produce a vote: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let encoded = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let bytes = base64_decode(&encoded);
    chain_block::read_single_root_boc(bytes).expect("the vote is a single cell")
}

fn base64_decode(text: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' {
            break;
        }
        let value = TABLE.iter().position(|c| *c == byte).expect("base64") as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

/// A configuration vote the node produced, counted by the contract.
#[test]
fn a_vote_the_node_produced_is_counted() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let proposal = propose(&mut chain, 42, 0x0de0);
    let voter = &validators[0];
    let idx = index_of(&chain, voter);

    let body = run_vote_tool(&[
        "config".to_string(),
        seed_file_for(voter).to_string_lossy().into_owned(),
        global_id(&chain).to_string(),
        hex::encode(current_set_id(&chain)),
        hex::encode(validator_id_at(&chain, idx)),
        idx.to_string(),
        hex::encode(proposal),
    ]);

    let relay = chain.blockchain.treasury("node-vote-relay", 1_000 * TOS).expect("an account");
    let result = chain
        .blockchain
        .send_message(relay.build_message(&chain.config_contract, VOTE_VALUE, true, Some(body)))
        .expect("the vote is delivered");
    assert_eq!(exit_code_of(&result), 0, "the contract refused a vote the node produced");
    assert_eq!(
        proposal_voters(&chain, &proposal),
        vec![idx],
        "a vote the node produced was not counted"
    );
}

/// A complaint vote the node produced, counted by the elector.
#[test]
fn a_complaint_vote_the_node_produced_is_counted() {
    let (mut chain, validators, election) = elect_install_and_rotate();
    let accused = validator_id_at(&chain, index_of(&chain, &validators[3]));
    let complainant =
        chain.blockchain.treasury("node-complainant", 10_000 * TOS).expect("an account");
    let filed = chain
        .blockchain
        .send_message(complainant.build_message(
            &chain.elector,
            300 * TOS,
            true,
            Some(complaint_body(1, election, &accused)),
        ))
        .expect("the complaint is delivered");
    assert!(replies(&filed).contains(&COMPLAINT_ACCEPTED), "the elector refused the complaint");
    let complaint = complaint_hashes(&chain, election)[0];

    let voter = &validators[0];
    let idx = index_of(&chain, voter);
    let body = run_vote_tool(&[
        "complaint".to_string(),
        seed_file_for(voter).to_string_lossy().into_owned(),
        global_id(&chain).to_string(),
        hex::encode(current_set_id(&chain)),
        hex::encode(validator_id_at(&chain, idx)),
        idx.to_string(),
        election.to_string(),
        hex::encode(complaint),
    ]);

    let relay = chain.blockchain.treasury("node-complaint-relay", 1_000 * TOS).expect("an account");
    let result = chain
        .blockchain
        .send_message(relay.build_message(&chain.elector, VOTE_VALUE, true, Some(body)))
        .expect("the vote is delivered");
    assert_eq!(exit_code_of(&result), 0, "the elector refused a vote the node produced");
    assert_eq!(
        complaint_voters(&chain, election, &complaint),
        vec![idx],
        "a complaint vote the node produced was not counted"
    );
}

/// A node holding the wrong key produces no authority.
///
/// The producer will sign whatever fields it is given -- it is a signer, not a judge --
/// so what refuses this is the contract, which reads the key from the descriptor at the
/// index the vote names. A node that had been given somebody else's seed, or whose own
/// key had been rotated out of the set, gets no vote counted and nothing else happens.
#[test]
fn a_vote_the_node_produced_with_another_validators_key_is_refused() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let proposal = propose(&mut chain, 42, 0x0de1);
    let idx = index_of(&chain, &validators[0]);

    // Everything names the validator at that index; only the seed is somebody else's.
    let body = run_vote_tool(&[
        "config".to_string(),
        seed_file_for(&validators[1]).to_string_lossy().into_owned(),
        global_id(&chain).to_string(),
        hex::encode(current_set_id(&chain)),
        hex::encode(validator_id_at(&chain, idx)),
        idx.to_string(),
        hex::encode(proposal),
    ]);

    let relay = chain.blockchain.treasury("wrong-key-relay", 1_000 * TOS).expect("an account");
    chain
        .blockchain
        .send_message(relay.build_message(&chain.config_contract, VOTE_VALUE, true, Some(body)))
        .expect("the vote is delivered")
        .expect_aborted()
        .expect_exit_code(ERROR_BAD_VOTE_SIGNATURE);
    assert!(
        proposal_voters(&chain, &proposal).is_empty(),
        "a vote signed with another validator's key was counted"
    );
}

/// A node that is not in the current set has nothing to sign for.
///
/// The set the election installed names four members. A key that belongs to none of
/// them cannot be at any index, so there is no vote it could produce that the contract
/// would take.
#[test]
fn a_key_that_is_not_in_the_set_can_produce_no_vote() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let outsider = PqValidator::new(0x5f);
    assert!(
        !validators.iter().any(|v| v.key_id() == outsider.key_id()),
        "the fixture needs a key the set does not hold"
    );
    let set = chain.blockchain.config_params().validator_set().expect("a current set");
    for descriptor in set.list() {
        assert_ne!(
            descriptor.consensus_key_id().expect("a key identity"),
            outsider.key_id(),
            "the outsider is in the set, so this test measures nothing"
        );
    }

    let proposal = propose(&mut chain, 42, 0x0de2);
    let relay = chain.blockchain.treasury("outsider-relay", 1_000 * TOS).expect("an account");
    // Every index the set has, tried with the outsider's key.
    for idx in 0..set.list().len() as u16 {
        let body = run_vote_tool(&[
            "config".to_string(),
            seed_file_for(&outsider).to_string_lossy().into_owned(),
            global_id(&chain).to_string(),
            hex::encode(current_set_id(&chain)),
            hex::encode(validator_id_at(&chain, idx)),
            idx.to_string(),
            hex::encode(proposal),
        ]);
        chain
            .blockchain
            .send_message(relay.build_message(&chain.config_contract, VOTE_VALUE, true, Some(body)))
            .expect("the vote is delivered")
            .expect_aborted()
            .expect_exit_code(ERROR_BAD_VOTE_SIGNATURE);
    }
    assert!(
        proposal_voters(&chain, &proposal).is_empty(),
        "a key the set does not hold got a vote counted at some index"
    );
}

/// A governed change is what the next transaction's VM reads, not only what the
/// configuration contract stores. A later proposal binds itself to the current value's
/// hash, which the contract reads through `config_param`, so the two have to agree.
#[test]
fn a_governed_parameter_is_the_value_the_vm_reads_next() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    require_one_winning_round(&mut chain);
    let value = proposal_value(0x0042_0042);
    assert!(govern_install(&mut chain, &validators, 42, value.clone(), 100).decided);
    assert_eq!(raw_parameter(&chain, 42), Some(value));
    let stored = raw_parameter(&chain, 42).expect("contract stores updated Param 42");
    let active = vm_parameter(&chain, 42).expect("VM exposes updated Param 42");
    assert_eq!(
        stored.repr_hash(),
        active.repr_hash(),
        "proposal current hash came from contract storage but VM config_param(42) differs"
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
    description.append_u64(query_id).expect("what distinguishes one complaint from another");

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

/// `complaint_prices#1a deposit:Tomis bit_price:Tomis cell_price:Tomis`, the cell
/// ConfigParam 13 holds.
fn complaint_prices_cell(deposit: u64, bit_price: u64, cell_price: u64) -> chain_block::Cell {
    use chain_block::{Coins, IBitstring, Serializable};
    let mut cell = chain_block::BuilderData::new();
    cell.append_u8(0x1a).expect("complaint prices tag");
    for price in [deposit, bit_price, cell_price] {
        Coins::new(price).write_to(&mut cell).expect("a price");
    }
    cell.into_cell().expect("complaint prices")
}

fn set_complaint_prices(chain: &mut Chain, cell: chain_block::Cell) {
    let mut config = chain.blockchain.config_params().clone();
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParam13(chain_block::ConfigParam13 {
            cell,
        }))
        .expect("ConfigParam 13");
    chain.blockchain.set_config(config).expect("the chain adopts the complaint prices");
}

/// The cheapest punishment ConfigParam 40 defines: ordinary severity, short
/// interval, 62.5 TOS plus 1/256 of the stake.
const MILDEST_FLAT_FINE: u64 = 62_500_000_000;
const MILDEST_FINE_PART: u32 = 1 << 24;
/// 64 full cells, 65,472 bits: about the size of a proof carrying three
/// ML-DSA-44 signatures (2,420 bytes each).
const PROOF_CELLS: usize = 64;

/// A complaint asking for the mildest fine, carrying a proof of `PROOF_CELLS` cells.
fn mildest_tier_complaint_body(
    query_id: u64,
    election: u32,
    accused: &[u8; 32],
) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut proof: Option<chain_block::Cell> = None;
    for index in 0..PROOF_CELLS {
        let mut cell = chain_block::BuilderData::new();
        let mut bytes = [0u8; 127];
        bytes[0] = index as u8;
        cell.append_raw(&bytes, 1016).expect("proof bytes");
        cell.append_bits(0x55, 7).expect("proof tail bits");
        if let Some(next) = proof.take() {
            cell.checked_append_reference(next).expect("proof chain");
        }
        proof = Some(cell.into_cell().expect("proof cell"));
    }
    let mut description = chain_block::BuilderData::new();
    description.append_u64(query_id).expect("what distinguishes one complaint from another");
    description.checked_append_reference(proof.expect("a non-empty proof")).expect("the proof");

    let mut body = chain_block::BuilderData::new();
    body.append_u32(NEW_COMPLAINT).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.append_u32(election).expect("the election complained about");
    body.append_i8(0xbcu8 as i8).expect("complaint tag");
    body.append_raw(accused, 256).expect("the accused validator");
    body.checked_append_reference(description.into_cell().expect("description"))
        .expect("description");
    body.append_u32(0).expect("created at, rewritten by the contract");
    body.append_u8(0).expect("ordinary severity");
    body.append_raw(&[0u8; 32], 256).expect("reward address, rewritten by the contract");
    body.append_bits(0, 4).expect("paid, rewritten by the contract");
    body.append_bits(8, 4).expect("the length of the suggested fine");
    body.append_u64(MILDEST_FLAT_FINE).expect("suggested fine");
    body.append_u32(MILDEST_FINE_PART).expect("suggested fine part");
    body.into_cell().expect("complaint body")
}

/// The genesis complaint deposit decides whether the mildest misbehaviour is worth
/// reporting at all.
///
/// The elector charges `deposit + ((bits + 1024) * bit_price + (cells + 2) *
/// cell_price) * seconds until the stake unfreezes` and refuses a complaint whose fine
/// does not exceed that charge (reply 8). The validators here hold 10,000 to 11,000 TOS,
/// so the mildest fine is 101.5625 to 105.47 TOS. The proof alone costs about 10 TOS
/// over the 98,304 s a just-rotated stake stays frozen: about 67,300 bits and 66 cells
/// give 101,300 nanotos a second. With a 100 TOS deposit that is about 110 TOS and the
/// complaint is refused; with the genesis 1 TOS deposit it is about 11 TOS and accepted.
#[test]
fn the_genesis_complaint_deposit_lets_the_mildest_fine_be_reported() {
    let (mut chain, validators, election) = elect_install_and_rotate();
    let genesis_prices = parameter_from_config(chain.blockchain.config_params(), 13)
        .expect("genesis sets ConfigParam 13");
    assert_eq!(
        genesis_prices,
        complaint_prices_cell(TOS, 1, 500),
        "genesis complaint prices are not 1 TOS / 1 / 500"
    );

    let accused = validator_id_at(&chain, index_of(&chain, &validators[3]));
    let complainant =
        chain.blockchain.treasury("mild-complainant", 10_000 * TOS).expect("an account");
    // Enough value that the elector's other check, paid + 1 TOS <= value, never decides.
    let value = 300 * TOS;

    set_complaint_prices(&mut chain, complaint_prices_cell(100 * TOS, 1, 500));
    let refused = chain
        .blockchain
        .send_message(complainant.build_message(
            &chain.elector,
            value,
            true,
            Some(mildest_tier_complaint_body(1, election, &accused)),
        ))
        .expect("the complaint is delivered");
    assert!(
        replies(&refused).contains(&(COMPLAINT_ACCEPTED + 8)),
        "under a 100 TOS deposit the mildest fine should not cover the complaint's charge"
    );
    assert!(complaint_hashes(&chain, election).is_empty(), "a refused complaint was stored");

    set_complaint_prices(&mut chain, genesis_prices);
    let filed = chain
        .blockchain
        .send_message(complainant.build_message(
            &chain.elector,
            value,
            true,
            Some(mildest_tier_complaint_body(1, election, &accused)),
        ))
        .expect("the complaint is delivered");
    assert!(
        replies(&filed).contains(&COMPLAINT_ACCEPTED),
        "the genesis complaint prices refused a mildest-tier complaint"
    );
    assert_eq!(complaint_hashes(&chain, election).len(), 1, "the complaint was not stored");
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
    entry.get_next_bits(256).expect("the account the stake returns to");
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

/// An underfunded complaint vote is refused before the verification it asks for.
///
/// Anyone may send a complaint vote naming an index of the current set, and the elector's
/// gas does not depend on the value a message carries, so without the gate a stream of
/// cheap, wrongly signed votes would each buy a full ML-DSA verification. The work is
/// measured in gas, as for configuration votes.
#[test]
fn an_underfunded_complaint_vote_is_refused_before_the_verification() {
    let (mut chain, validators, election) = elect_install_and_rotate();
    let accused = validator_id_at(&chain, index_of(&chain, &validators[3]));
    let complainant =
        chain.blockchain.treasury("complainant-c", 1_000 * TOS).expect("a funded account");
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
    let idx = index_of(&chain, &validators[0]);
    // Valid in every respect except who signed it.
    let stolen = validators[1].sign(&complaint_vote_preimage(&chain, idx, election, &complaint));
    let relay = chain.blockchain.treasury("complaint-drain", 1_000_000 * TOS).expect("an account");
    let too_little = TOS / 2_000;

    let verified = chain
        .blockchain
        .send_message(relay.build_message(
            &chain.elector,
            VOTE_VALUE,
            true,
            Some(complaint_vote_body(499, &stolen, idx, election, &complaint)),
        ))
        .expect("the vote is delivered");
    assert_eq!(exit_code_of(&verified), ERROR_BAD_VOTE_SIGNATURE, "the fixture needs a refusal");
    let cost_of_verifying = compute_gas(&verified);

    let mut refusal = 0u64;
    for round in 0..16u64 {
        let result = chain
            .blockchain
            .send_message(relay.build_message(
                &chain.elector,
                too_little,
                true,
                Some(complaint_vote_body(500 + round, &stolen, idx, election, &complaint)),
            ))
            .expect("the vote is delivered");
        result.expect_aborted().expect_exit_code(ERROR_VOTE_UNDERFUNDED);
        refusal = compute_gas(&result);
    }
    assert!(
        refusal * 8 < cost_of_verifying,
        "refusing an underfunded complaint vote costs {refusal} gas against \
         {cost_of_verifying} for one that is verified, so the verification happens first"
    );
    assert!(refusal > 0, "the refusal cost nothing, so the contract never ran");
    assert!(
        complaint_voters(&chain, election, &complaint).is_empty(),
        "an invalid complaint vote was registered"
    );
}

// ---------------------------------------------------------------------------
// Post-quantum staking
//
// The stake operation keeps its classical shape with the key and the signature
// replaced: an ML-DSA-44 key and signature travel as references. The contract supplies
// both identities itself -- the member is the account that sent the message, and the key
// identity is derived from the key presented -- and the signature covers the sender's
// address, so a request signed for one account authorises nothing when another sends it.
// ---------------------------------------------------------------------------

const ELECTION_CONTEXT: &[u8] = b"TOS-VALIDATOR-ELECTION-v1";
/// A different authorisation's context, used to show a signature cannot cross between them.
const CONFIG_VOTE_CONTEXT: &[u8] = b"TOS-VALIDATOR-CONFIG-VOTE-v1";
const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;
/// The library refuses a suite it does not admit, before anything reads the key.
const ERROR_UNADMITTED_ALGORITHM: i32 = 61;
/// `return_stake` reason 2: the stake is under 1/4096 of what the election already holds.
const REASON_TOO_SMALL_FOR_THE_TOTAL: u32 = 2;
/// `return_stake` reason 5: the stake is under the configured minimum.
const REASON_BELOW_MINIMUM: u32 = 5;
/// `return_stake` reason 6: the weight factor asked for is below one.
const REASON_FACTOR_BELOW_ONE: u32 = 6;
/// `return_stake` reason 7: no transport address was stated.
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
            // The scratch name has to be unique per call, not per process. These tests run
            // on threads of one process, so a process id names the same file for all of
            // them: two validators built at once had one thread removing the file the other
            // was still linking, or generating over it while the other read it. The shared
            // published name is deliberate -- generating an ML-DSA key is slow and the tests
            // only need it to be the same key -- and it is safe because it comes into
            // existence by linking a file the generator has already finished writing, so it
            // never exists half-written.
            static SCRATCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let scratch = SCRATCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mine = key_file.with_extension(format!("{}.{scratch}.tmp", std::process::id()));
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
        // Distinct per index, and never a uniform byte pattern: the sandbox genesis set
        // states uniform addresses, and a candidate restating one of those is refused.
        let mut adnl = [0xd0 ^ index; 32];
        adnl[0] = 0xad;
        PqValidator { key_file, public_key, adnl }
    }

    /// A validator whose key is derived from a fixed public seed, so every machine derives
    /// the same key. `new` generates a random key per machine, which is enough for a test
    /// that only needs some key, but not for output that is compared byte for byte.
    fn from_seed(index: u8, seed: [u8; 32]) -> Self {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        static SCRATCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let scratch = SCRATCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let key_file = std::env::temp_dir()
            .join(format!("tos-pq-seeded-{}-{scratch}.key", std::process::id()));
        // The key tool reads only an owner-only regular file.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_file)
            .expect("a private seed file");
        file.write_all(&seed).expect("write the seed");
        drop(file);
        let public_key =
            hex::decode(&run_key_tool(&["public", key_file.to_str().expect("path")])[0])
                .expect("hex");
        assert_eq!(public_key.len(), MLDSA44_PUBLIC_KEY_BYTES);
        let mut adnl = [0xd0 ^ index; 32];
        adnl[0] = 0xad;
        PqValidator { key_file, public_key, adnl }
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

/// The 80 bytes a stake request signs, built here independently of the contract by the
/// node's own Rust mirror. `src_addr` is the account the stake is signed for; the elector
/// rebuilds these bytes with the address of the account that actually sent it.
fn pq_stake_preimage(
    global_id: i32,
    stake_at: u32,
    max_factor: u32,
    src_addr: &chain_block::UInt256,
    adnl: &[u8; 32],
) -> Vec<u8> {
    let preimage = chain_block::pq_elector::stake_preimage(
        global_id,
        stake_at,
        max_factor,
        src_addr,
        &chain_block::UInt256::from(*adnl),
    );
    assert_eq!(preimage.len(), 80, "the signed preimage changed shape");
    preimage
}

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

/// A stake body as a wallet sends it straight to the elector, from the production builder:
/// the stake is the message value, so the body carries no amount.
fn pq_stake_body(
    query_id: u64,
    validator: &PqValidator,
    stake_at: u32,
    max_factor: u32,
    signature: &[u8],
) -> chain_block::Cell {
    contracts::nominator::elector_new_stake(&contracts::nominator::NewStakeParams {
        query_id,
        stake_amount: 0,
        validator_pubkey: &validator.public_key,
        stake_at,
        max_factor,
        adnl_addr: &validator.adnl,
        signature,
    })
    .expect("a well-formed stake body")
}

/// The post-quantum instruction is gated on global version 16. The canonical zerostate
/// declares a version at or above it, so these tests run at the version the chain launches
/// with. A zerostate that drops below 16 fails here, not in every stake that follows.
fn require_post_quantum_version(chain: &Chain) {
    let config = chain.blockchain.config_params().clone();
    let version = match config.config(8).expect("parameter 8") {
        Some(chain_block::ConfigParamEnum::ConfigParam8(v)) => v.global_version,
        _ => panic!("the chain states no global version"),
    };
    assert!(
        version.version >= 16,
        "the zerostate declares global version {}, below the post-quantum instruction's 16",
        version.version
    );
}

/// Send a post-quantum stake from `from`, signed for whichever account `signed_for` is.
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
    let src_addr =
        chain_block::UInt256::from_slice(&signed_for.address().address().get_bytestring(0));
    let preimage =
        pq_stake_preimage(global_id(chain), election, max_factor, &src_addr, &validator.adnl);
    let signature = validator.sign(&preimage);
    chain
        .blockchain
        .send_message(from.build_message(
            &chain.elector,
            value,
            true,
            Some(pq_stake_body(query_id, validator, election, max_factor, &signature)),
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

/// Where the elector's first answer went, what it said, and what it carried.
fn answered(result: &tos_sandbox::SendResult) -> (MsgAddressInt, u32, u32, u128) {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    let mut answer = None;
    transaction
        .iterate_out_msgs(|message| {
            if answer.is_none() {
                let destination = message.dst().expect("a destination");
                let value = message.get_value().map(|v| v.coins.as_u128()).unwrap_or(0);
                let mut body = message.body().expect("a body").clone();
                let tag = body.get_next_u32().expect("a reply tag");
                body.get_next_u64().expect("a query id");
                let reason = body.get_next_u32().unwrap_or(0);
                answer = Some((destination, tag, reason, value));
            }
            Ok(true)
        })
        .expect("out messages");
    answer.expect("the elector always answers a stake")
}

/// The open election's members, keyed by the account each staked from.
fn pq_book(chain: &Chain) -> chain_block::HashmapE {
    let account = chain.blockchain.get_account(&chain.elector).expect("the elector is deployed");
    let data = account.get_data().expect("the elector has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let elect = next_dictionary(&mut slice, 32);
    let root = chain_block::HashmapType::data(&elect).expect("an active election").clone();
    let mut es = chain_block::SliceData::load_cell(root).expect("the election");
    // elect_at elect_close min_stake total_stake members failed finished
    es.get_next_u32().expect("elect_at");
    es.get_next_u32().expect("elect_close");
    next_coins(&mut es);
    next_coins(&mut es);
    let members = next_dictionary(&mut es, 256);
    es.get_next_bit().expect("failed");
    es.get_next_bit().expect("finished");
    assert_eq!(
        (es.remaining_bits(), es.remaining_references()),
        (0, 0),
        "the election record changed shape"
    );
    members
}

/// A member record: `stake time max_factor key_id adnl_addr algorithm_id ^public_key`.
struct Member {
    stake: u128,
    max_factor: u32,
    key_id: chain_block::UInt256,
    adnl: [u8; 32],
}

fn read_member(mut record: chain_block::SliceData) -> Member {
    let stake = next_coins(&mut record);
    record.get_next_u32().expect("registered at");
    let max_factor = record.get_next_u32().expect("max factor");
    let key_id = chain_block::UInt256::from_slice(&record.get_next_bits(256).expect("key id"));
    let adnl = record.get_next_bits(256).expect("adnl").try_into().expect("32 bytes");
    assert_eq!(record.get_next_u16().expect("algorithm"), 1, "a member holds another suite");
    record.checked_drain_reference().expect("the public key");
    assert_eq!(
        (record.remaining_bits(), record.remaining_references()),
        (0, 0),
        "the member record changed shape"
    );
    Member { stake, max_factor, key_id, adnl }
}

/// The member registered under an address, if there is one.
fn pq_member_at(chain: &Chain, address: &MsgAddressInt) -> Option<Member> {
    pq_book(chain).get(address.address().clone()).expect("lookup").map(read_member)
}

/// What a member has placed, according to its own record.
fn pq_stake_of(chain: &Chain, member: &tos_sandbox::Treasury) -> u128 {
    pq_member_at(chain, member.address()).expect("the account is registered").stake
}

fn pq_member_key_id(chain: &Chain, member: &tos_sandbox::Treasury) -> Option<chain_block::UInt256> {
    pq_member_key_id_at(chain, member.address())
}

/// The same, for a member that is a deployed contract rather than a treasury.
fn pq_member_key_id_at(chain: &Chain, address: &MsgAddressInt) -> Option<chain_block::UInt256> {
    pq_member_at(chain, address).map(|member| member.key_id)
}

/// The members holding a key, by address. The election keeps no index of its own, so
/// this is read from every member record, which is what the contract itself walks.
fn pq_key_holders(chain: &Chain, key_id: &chain_block::UInt256) -> Vec<chain_block::UInt256> {
    let mut holders = Vec::new();
    chain_block::HashmapType::iterate_slices(&pq_book(chain), |key, value| {
        if read_member(value).key_id == *key_id {
            holders.push(chain_block::UInt256::from_slice(&key.get_bytestring(0)));
        }
        Ok(true)
    })
    .expect("the members");
    holders
}

/// The one member holding a key, or none.
fn pq_key_holder(chain: &Chain, key_id: &chain_block::UInt256) -> Option<chain_block::UInt256> {
    let mut holders = pq_key_holders(chain, key_id);
    assert!(holders.len() <= 1, "two members hold one key: {holders:?}");
    holders.pop()
}

/// A wallet stakes directly, and the elector registers it under its own address: the
/// member, the key it presented, the transport address it stated, and the stake it sent
/// less the one TOS the confirmation costs.
#[test]
fn a_wallet_stakes_directly_and_is_registered_under_its_own_address() {
    let (mut chain, treasury, election) = open_election("pq-validator-a", 40_000 * TOS);
    require_post_quantum_version(&chain);
    let validator = PqValidator::new(0);

    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    result.expect_exit_code(0);
    assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "a correctly signed stake was refused");
    let (to, _, _, _) = answered(&result);
    assert_eq!(&to, treasury.address(), "the confirmation went somewhere other than the sender");

    let wallet = chain_block::UInt256::from_slice(&treasury.address().address().get_bytestring(0));
    let member = pq_member_at(&chain, treasury.address()).expect("the wallet is not a member");
    assert_eq!(member.key_id, validator.key_id(), "the member record holds another key");
    assert_eq!(member.adnl, validator.adnl, "the member record holds another transport address");
    assert_eq!(member.stake, u128::from(11_000 * TOS - TOS), "the member holds another stake");
    assert_eq!(
        pq_key_holder(&chain, &validator.key_id()),
        Some(wallet),
        "the key was not registered to the account that sent the stake"
    );
    assert_eq!(
        chain_block::HashmapType::len(&pq_book(&chain)).expect("member count"),
        1,
        "a second member appeared"
    );
}

/// What the compute phase of the first transaction spent.
/// The gas a tick or tock transaction spent. The elector's state machine advances on
/// these rather than on messages, so an election is measured here and not in `compute_gas`.
fn tick_gas(result: &tos_sandbox::SendResult) -> u64 {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    match transaction.read_description().expect("description") {
        chain_block::TransactionDescr::TickTock(descr) => match descr.compute_ph {
            chain_block::TrComputePhase::Vm(vm) => vm.gas_used.as_u64(),
            other => panic!("the compute phase did not run: {other:?}"),
        },
        other => panic!("not a tick-tock transaction: {other:?}"),
    }
}

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
    require_post_quantum_version(&chain);
    let validator = PqValidator::new(1);
    let impostor = PqValidator::new(2);

    // The request carries the validator's key, and a signature by a key that is not it.
    let src_addr =
        chain_block::UInt256::from_slice(&treasury.address().address().get_bytestring(0));
    let preimage =
        pq_stake_preimage(global_id(&chain), election, 0x10000, &src_addr, &validator.adnl);
    let signature = impostor.sign(&preimage);
    let result = chain
        .blockchain
        .send_message(treasury.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(pq_stake_body(1, &validator, election, 0x10000, &signature)),
        ))
        .expect("the stake is delivered");

    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_BAD_SIGNATURE),
        "a stake signed by another key was accepted, or refused for another reason"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "a refused stake was registered anyway");
}

/// A signature made for one account authorises nothing when another sends it.
///
/// Signed correctly, by the right key, for a different sender. The elector rebuilds the
/// preimage with the address it sees, so the bytes it verifies are not the bytes that were
/// signed, and the stake goes back -- with its money -- to the account that sent it.
#[test]
fn a_post_quantum_stake_signed_for_another_sender_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-validator-c", 40_000 * TOS);
    require_post_quantum_version(&chain);
    let elsewhere = chain.blockchain.treasury("pq-validator-c-elsewhere", TOS).expect("an account");
    let validator = PqValidator::new(3);

    let result =
        pq_stake_from(&mut chain, &treasury, &elsewhere, &validator, election, 1, 11_000 * TOS);
    let (to, tag, reason, carried) = answered(&result);
    assert_eq!(
        (tag, reason),
        (STAKE_RETURNED, REASON_BAD_SIGNATURE),
        "a stake signed for another sender was accepted"
    );
    assert_eq!(&to, treasury.address(), "the refusal went somewhere other than the sender");
    assert!(carried > u128::from(10_000 * TOS), "the refusal did not carry the money back");
    assert_eq!(pq_member_key_id(&chain, &treasury), None);
    assert_eq!(pq_member_key_id(&chain, &elsewhere), None, "the named account became a member");
    assert_eq!(declared_total_stake(&chain), 0, "a refused stake moved the election's total");
}

/// A consensus key belongs to one member. A second account staking with a key another
/// member already registered is refused, whatever it signs, and the key stays where it is.
#[test]
fn a_key_already_registered_by_another_member_is_returned() {
    let (mut chain, first, election) = open_election("pq-validator-d", 40_000 * TOS);
    require_post_quantum_version(&chain);
    let second =
        chain.blockchain.treasury("pq-validator-d-second", 40_000 * TOS).expect("an account");
    let validator = PqValidator::new(4);

    assert_eq!(
        reply(&pq_stake(&mut chain, &first, &validator, election, 1, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0)
    );
    let total_before = declared_total_stake(&chain);
    // The second account signs correctly for itself, with the same consensus key. Only the
    // rule that a key belongs to one member can refuse this.
    let result = pq_stake(&mut chain, &second, &validator, election, 2, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_ANOTHER_ADDRESS),
        "two members registered the same consensus key"
    );
    assert_eq!(
        pq_key_holder(&chain, &validator.key_id()),
        Some(chain_block::UInt256::from_slice(&first.address().address().get_bytestring(0))),
        "the refused registration moved the key"
    );
    assert_eq!(pq_member_key_id(&chain, &second), None, "the refused account became a member");
    assert_eq!(declared_total_stake(&chain), total_before, "the refusal moved the total");
}

/// A key a member stops using is registrable by the account that was refused it.
///
/// The election keeps no separate record of who holds a key: a member's own record is the
/// claim. So a member restating its stake with another key gives the first one up, and the
/// account that was refused it may now take it.
#[test]
fn a_key_released_by_a_rotation_is_registrable_by_the_member_it_was_refused_to() {
    let (mut chain, first, election) = open_election("pq-release", 60_000 * TOS);
    require_post_quantum_version(&chain);
    let second = chain.blockchain.treasury("pq-release-second", 60_000 * TOS).expect("an account");
    let contested = PqValidator::new(12);
    let rotated = PqValidator::new(13);

    assert_eq!(
        reply(&pq_stake(&mut chain, &first, &contested, election, 1, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "the first member could not register the contested key"
    );
    assert_eq!(
        reply(&pq_stake(&mut chain, &second, &contested, election, 2, 11_000 * TOS)),
        (STAKE_RETURNED, REASON_ANOTHER_ADDRESS),
        "the second account took a key that was already held"
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
        "the member records disagree about who holds the contested key"
    );
}

#[test]
fn a_member_rotates_its_key_and_releases_the_one_it_held() {
    let (mut chain, treasury, election) = open_election("pq-validator-e", 60_000 * TOS);
    require_post_quantum_version(&chain);
    let held = PqValidator::new(5);
    let rotated = PqValidator::new(6);

    let first = pq_stake(&mut chain, &treasury, &held, election, 1, 11_000 * TOS);
    assert_eq!(reply(&first), (STAKE_ACCEPTED, 0));
    let registration_gas = compute_gas(&first);

    let second = pq_stake(&mut chain, &treasury, &rotated, election, 2, 11_000 * TOS);
    assert_eq!(
        reply(&second),
        (STAKE_ACCEPTED, 0),
        "a rotation by the registered member was refused"
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
    assert_eq!(
        pq_stake_of(&chain, &treasury),
        u128::from(22_000 * TOS - 2 * TOS),
        "a rotation did not keep the stake already placed"
    );

    // A whole stake transaction, and a rotation, which does the same work against a book
    // that already holds the member.
    eprintln!("post-quantum stake: {registration_gas} gas; rotation: {rotation_gas} gas");
    // The elector is a special account, allowed seventy million gas by the zerostate's
    // masterchain prices. The point of the figure is how far under that it is.
    for (what, gas) in [("a registration", registration_gas), ("a rotation", rotation_gas)] {
        assert!(
            gas < 1_000_000,
            "{what} costs {gas} gas, over what an ordinary transaction may spend"
        );
    }
}

#[test]
fn a_post_quantum_top_up_adds_only_the_money_it_brings_to_the_election_total() {
    let (mut chain, treasury, election) = open_election("pq-validator-g", 60_000 * TOS);
    require_post_quantum_version(&chain);
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
        "two stakes from one member must accumulate, less the two confirmations"
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

#[test]
fn a_stake_stating_a_factor_below_one_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-factor", 60_000 * TOS);
    require_post_quantum_version(&chain);
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
    require_post_quantum_version(&chain);
    let validator = PqValidator::new(15);

    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 2 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_BELOW_MINIMUM),
        "a stake under the minimum was registered"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");
}

/// A stake under 1/4096 of what the election already holds is refused for that, before
/// the minimum is looked at: the same small stake into an election holding little is
/// refused only as under the minimum.
#[test]
fn a_stake_too_small_for_the_election_total_is_returned() {
    let (mut chain, large, election) = open_election("pq-floor", 4_000_000 * TOS);
    require_post_quantum_version(&chain);
    let small = chain.blockchain.treasury("pq-floor-small", 1_000 * TOS).expect("an account");
    let key = PqValidator::new(30);

    // An empty election: 100 TOS is refused only as under the minimum.
    let alone = pq_stake(&mut chain, &small, &key, election, 1, 100 * TOS);
    assert_eq!(reply(&alone), (STAKE_RETURNED, REASON_BELOW_MINIMUM), "the control moved");

    assert_eq!(
        reply(&pq_stake(&mut chain, &large, &PqValidator::new(29), election, 2, 3_000_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "the fixture needs a large member"
    );
    // 99 TOS against roughly three million held is under 1/4096 of the total.
    let refused = pq_stake(&mut chain, &small, &key, election, 3, 100 * TOS);
    assert_eq!(
        reply(&refused),
        (STAKE_RETURNED, REASON_TOO_SMALL_FOR_THE_TOTAL),
        "the floor was not measured over the stake already placed"
    );
    assert_eq!(pq_member_key_id(&chain, &small), None, "the refused stake registered anyway");
}

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
/// The request is the classical one with the key and the signature replaced: op, query,
/// suite, the key as a reference, election, factor, transport address, and the signature
/// as a reference. The figures below are that shape, so a change to the carrier has to be
/// re-approved rather than absorbed.
#[test]
fn a_stake_request_is_the_size_the_design_was_sized_for() {
    let validator = PqValidator::new(23);
    let body = pq_stake_body(1, &validator, 1_789_434_000, 0x10000, &vec![0u8; 2420]);
    // The body cell: op u32, query u64, suite u16, election u32, factor u32, adnl u256.
    assert_eq!(body.bit_length(), 32 + 64 + 16 + 32 + 32 + 256, "the stake body changed shape");
    assert_eq!(body.references_count(), 2, "the key and the signature are the only references");
    assert_eq!(tree_size(&body), (34, 30_352), "a stake request changed shape");
}

/// The weight factor a member registered with, as its own record holds it.
fn pq_member_max_factor(chain: &Chain, member: &tos_sandbox::Treasury) -> u32 {
    pq_member_at(chain, member.address()).expect("the account is registered").max_factor
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
    require_post_quantum_version(&chain);
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
    adnl: [u8; 32],
    /// The account the authorisation was issued for. `None` means the sender.
    src_addr: Option<chain_block::UInt256>,
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
    let sender = chain_block::UInt256::from_slice(&from.address().address().get_bytestring(0));
    let preimage = pq_stake_preimage(
        signed.global_id,
        signed.stake_at,
        signed.max_factor,
        signed.src_addr.as_ref().unwrap_or(&sender),
        &signed.adnl,
    );
    let signature = validator.sign_under(&preimage, context);
    chain
        .blockchain
        .send_message(from.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(pq_stake_body(1, validator, election, 0x10000, &signature)),
        ))
        .expect("the stake is delivered")
}

/// Each field of the preimage, changed on its own, must cost the signature its validity.
///
/// The request is valid in every case; only what was signed differs. A field the contract
/// reads from the request but leaves out of the bytes it verifies would be a field an
/// authorised signature does not actually authorise, and this is the test that says which
/// fields those bytes cover. The key is not among them: it is what the signature is
/// verified against, so a signature by any other key fails on its own.
#[test]
fn every_signed_field_of_a_stake_is_covered_by_its_signature() {
    let (mut chain, treasury, election) = open_election("pq-binding", 200_000 * TOS);
    require_post_quantum_version(&chain);
    let validator = PqValidator::new(17);

    let honest = SignedFields {
        global_id: global_id(&chain),
        stake_at: election,
        max_factor: 0x10000,
        adnl: validator.adnl,
        src_addr: None,
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
            SignedFields { global_id: honest.global_id ^ 1, ..honest.clone() },
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
        // An authorisation issued for one account, presented by another. This is what
        // stops a validator's permission to stand in an election being taken to an
        // account it was not issued for.
        (
            "another sender",
            SignedFields {
                src_addr: Some(chain_block::UInt256::from_slice(&[0x9f; 32])),
                ..honest.clone()
            },
            ELECTION_CONTEXT,
        ),
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

/// A rotation that is refused leaves the member exactly as it was.
///
/// A member left holding neither its old key nor the new one would be a validator nobody
/// can reach, and a key released without being replaced is one another account may take.
#[test]
fn a_refused_rotation_leaves_both_members_as_they_were() {
    let (mut chain, mine, election) = open_election("pq-atomic", 60_000 * TOS);
    require_post_quantum_version(&chain);
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
    let stake_before = pq_stake_of(&chain, &mine);

    // A rotation to a key the other member holds. It cannot be granted.
    assert_eq!(
        reply(&pq_stake(&mut chain, &mine, &wanted, election, 3, 11_000 * TOS)),
        (STAKE_RETURNED, REASON_ANOTHER_ADDRESS),
        "a member rotated onto a key another one holds"
    );

    let mine_id = chain_block::UInt256::from_slice(&mine.address().address().get_bytestring(0));
    let theirs_id = chain_block::UInt256::from_slice(&theirs.address().address().get_bytestring(0));
    assert_eq!(
        pq_member_key_id(&chain, &mine),
        Some(held.key_id()),
        "the refused rotation moved the member off the key it held"
    );
    assert_eq!(pq_stake_of(&chain, &mine), stake_before, "the refused rotation moved the stake");
    assert_eq!(
        pq_key_holder(&chain, &held.key_id()),
        Some(mine_id),
        "the refused rotation released the key it was rotating away from"
    );
    assert_eq!(
        pq_key_holder(&chain, &wanted.key_id()),
        Some(theirs_id),
        "the refused rotation took the key from the member that holds it"
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
    require_post_quantum_version(&chain);
    let validator = PqValidator::new(24);

    let mut body = chain_block::BuilderData::new();
    body.append_u32(NEW_STAKE).expect("operation");
    body.append_u64(1).expect("query id");
    body.append_u16(7).expect("a suite that is not admitted");
    body.checked_append_reference(stored_bytes(&validator.public_key)).expect("public key");
    body.append_u32(election).expect("election");
    body.append_u32(0x10000).expect("max factor");
    body.append_raw(&validator.adnl, 256).expect("adnl address");
    body.checked_append_reference(stored_bytes(&vec![0u8; 2420])).expect("signature");

    let result = chain
        .blockchain
        .send_message(treasury.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(body.into_cell().expect("stake body")),
        ))
        .expect("the stake is delivered");
    result.expect_aborted().expect_exit_code(ERROR_UNADMITTED_ALGORITHM);
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");
}

#[test]
fn a_post_quantum_stake_without_a_transport_address_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-validator-f", 40_000 * TOS);
    require_post_quantum_version(&chain);
    let mut validator = PqValidator::new(7);
    validator.adnl = [0u8; 32];

    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_NO_ADNL),
        "a validator registered without a transport address, so nothing could reach it"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");
}

// ---------------------------------------------------------------------------
// The sequence an operator actually runs
//
// Everything above proves the contracts. This proves the path: the node's own tool,
// built from this repository, signs each stake from a custodied seed for the wallet that
// sends it, and the real contracts are required to accept what it emits -- from a key in
// no set to a governed change that only the elected set could make. A test that builds
// the signature itself proves the contract reads that shape; it does not prove the tool
// writes it.
// ---------------------------------------------------------------------------

#[test]
fn the_node_tools_carry_a_validator_from_a_fresh_key_to_a_governed_change() {
    let (mut chain, _treasury, election) = open_election("operator-sequence", 200_000 * TOS);
    require_post_quantum_version(&chain);

    // --- each wallet stakes with a signature the node's tool made for it -------------
    let mut validators = Vec::new();
    for index in 0..4u8 {
        let wallet = chain
            .blockchain
            .treasury(&format!("operator-wallet-{index}"), 40_000 * TOS)
            .expect("a funded wallet");
        let consensus = PqValidator::new(0x90 + index);
        let src_addr =
            chain_block::UInt256::from_slice(&wallet.address().address().get_bytestring(0));
        let signature = run_stake_tool(&consensus, global_id(&chain), &src_addr, election, 0x10000);
        let body = pq_stake_body(20 + u64::from(index), &consensus, election, 0x10000, &signature);
        let result = chain
            .blockchain
            .send_message(wallet.build_message(&chain.elector, 11_000 * TOS, true, Some(body)))
            .expect("the stake is delivered");
        assert_eq!(
            reply(&result),
            (STAKE_ACCEPTED, 0),
            "the elector refused a stake the node's tool signed"
        );
        validators.push((wallet, consensus));
    }

    // The tool signs for the account it is told to; signed for another, it authorises
    // nothing.
    let stray = chain.blockchain.treasury("operator-stray", 40_000 * TOS).expect("a wallet");
    let elsewhere = chain_block::UInt256::from_slice(&[0x9f; 32]);
    let spare = PqValidator::new(0x9f);
    let signature = run_stake_tool(&spare, global_id(&chain), &elsewhere, election, 0x10000);
    let refused = chain
        .blockchain
        .send_message(stray.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(pq_stake_body(30, &spare, election, 0x10000, &signature)),
        ))
        .expect("the stake is delivered");
    assert_eq!(
        reply(&refused),
        (STAKE_RETURNED, REASON_BAD_SIGNATURE),
        "a stake the tool signed for another account was accepted"
    );

    // --- the election selects them and the configuration contract installs them ------
    let closed = tick_at_close(&mut chain, election, "the close");
    assert!(closed.next_set_installed, "the configuration contract refused the elected set");
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

    let set = chain.blockchain.config_params().validator_set().expect("a current set");
    assert_eq!(set.list().len(), 4, "every wallet should have been elected");
    for descriptor in set.list() {
        assert!(descriptor.pq_key().is_some(), "the elected set carries a classical descriptor");
        assert!(
            validators.iter().any(|(wallet, _)| {
                chain_block::UInt256::from_slice(&wallet.address().address().get_bytestring(0))
                    == descriptor.validator_id().expect("an identity")
            }),
            "the set names an identity no wallet has"
        );
    }

    // --- the node's own tool votes, and the vote is counted -------------------------
    let proposal = propose(&mut chain, 42, 0xbeef);
    let relay = chain.blockchain.treasury("operator-relay", 1_000 * TOS).expect("an account");
    let (_, voter) = &validators[0];
    let idx = index_of(&chain, voter);

    let vote = run_vote_tool(&[
        "config".to_string(),
        seed_file_for(voter).to_str().expect("path").to_string(),
        global_id(&chain).to_string(),
        hex::encode(current_set_id(&chain)),
        hex::encode(validator_id_at(&chain, idx)),
        idx.to_string(),
        hex::encode(proposal),
    ]);
    let result = chain
        .blockchain
        .send_message(relay.build_message(&chain.config_contract, VOTE_VALUE, true, Some(vote)))
        .expect("the vote is delivered");
    assert_eq!(exit_code_of(&result), 0, "the node's own vote was refused");
    assert_eq!(proposal_voters(&chain, &proposal), vec![idx], "the node's vote was not counted");

    // A body signed for another ConfigParam 34 cell must not count on this chain. The
    // signer receives a deliberately different set hash; the contract independently
    // hashes the actual cell it holds.
    let mut other_set_id = current_set_id(&chain);
    other_set_id[0] ^= 1;
    let wrong_set_vote = run_vote_tool(&[
        "config".to_string(),
        seed_file_for(voter).to_str().expect("path").to_string(),
        global_id(&chain).to_string(),
        hex::encode(other_set_id),
        hex::encode(validator_id_at(&chain, idx)),
        idx.to_string(),
        hex::encode(proposal),
    ]);
    chain
        .blockchain
        .send_message(relay.build_message(
            &chain.config_contract,
            VOTE_VALUE,
            true,
            Some(wrong_set_vote),
        ))
        .expect("the wrong-set vote is delivered")
        .expect_aborted()
        .expect_exit_code(ERROR_BAD_VOTE_SIGNATURE);
    assert_eq!(proposal_voters(&chain, &proposal), vec![idx], "a wrong-set vote was counted");

    // --- and complains about a validator of the closed election ---------------------
    let accused = validator_id_at(&chain, index_of(&chain, &validators[3].1));
    let complainant =
        chain.blockchain.treasury("operator-complainant", 10_000 * TOS).expect("an account");
    let filed = chain
        .blockchain
        .send_message(complainant.build_message(
            &chain.elector,
            300 * TOS,
            true,
            Some(complaint_body(1, election, &accused)),
        ))
        .expect("the complaint is delivered");
    assert!(replies(&filed).contains(&COMPLAINT_ACCEPTED), "the elector refused the complaint");
    let complaint = complaint_hashes(&chain, election)[0];

    let complaint_vote = run_vote_tool(&[
        "complaint".to_string(),
        seed_file_for(voter).to_str().expect("path").to_string(),
        global_id(&chain).to_string(),
        hex::encode(current_set_id(&chain)),
        hex::encode(validator_id_at(&chain, idx)),
        idx.to_string(),
        election.to_string(),
        hex::encode(complaint),
    ]);
    let counted = chain
        .blockchain
        .send_message(relay.build_message(&chain.elector, VOTE_VALUE, true, Some(complaint_vote)))
        .expect("the complaint vote is delivered");
    counted.expect_success();
    assert_eq!(
        complaint_voters(&chain, election, &complaint),
        vec![idx],
        "the node's complaint vote was not counted"
    );

    // --- and no administrator appeared anywhere along the way -----------------------
    //
    // The unilateral path was deleted rather than disabled, so what is checked is that
    // the message it took has nowhere to arrive: the configuration contract has no
    // external handler, and the parameter stays unset.
    use chain_block::IBitstring;
    let parameter = 78i32;
    assert!(
        !parameter_present(&configuration_from_contract(&chain), parameter as u32),
        "the fixture needs a parameter that is not already set"
    );
    let admin = ed25519_dalek::SigningKey::from_bytes(&[0x7c; 32]);
    let mut value = chain_block::BuilderData::new();
    value.append_u32(0xc0ffee).expect("a value");
    let mut signed = chain_block::BuilderData::new();
    signed.append_u32(0x43665021).expect("the action that changed a parameter");
    signed.append_u32(0).expect("sequence number");
    signed.append_u32(chain.blockchain.now() + 600).expect("valid until");
    signed.append_i32(parameter).expect("parameter");
    signed.checked_append_reference(value.into_cell().expect("value")).expect("value");
    let signed_cell = signed.into_cell().expect("the signed part");
    let signature: [u8; 64] =
        ed25519_dalek::Signer::sign(&admin, signed_cell.hash(0).as_slice()).to_bytes();
    let mut body = chain_block::BuilderData::new();
    body.append_raw(&signature, 512).expect("signature");
    body.checked_append_references_and_data(
        &chain_block::SliceData::load_cell(signed_cell).expect("the signed part"),
    )
    .expect("the signed part follows the signature");
    assert!(
        chain
            .blockchain
            .send_message(
                tos_sandbox::MessageBuilder::external(&chain.config_contract)
                    .body(body.into_cell().expect("administrator message"))
                    .build(),
            )
            .is_err(),
        "an administrator message was accepted after the whole sequence"
    );
    assert!(
        !parameter_present(&configuration_from_contract(&chain), parameter as u32),
        "a single key changed a parameter after the whole sequence"
    );
}

// ---------------------------------------------------------------------------
// Configuration proposals as `tosctl vote offer create` builds them
//
// The body and the price come from the same builder the command uses. The price is
// checked three ways: against the contract's own `proposal_storage_price`, against
// what the contract actually keeps, and by underpaying by one nanotomi.
// ---------------------------------------------------------------------------

fn voting_setup(chain: &Chain, critical: bool) -> chain_block::ConfigProposalSetup {
    match chain.blockchain.config_params().config(11).expect("param 11").expect("present") {
        chain_block::ConfigParamEnum::ConfigParam11(setup) => {
            if critical { setup.read_critical_params() } else { setup.read_normal_params() }
                .expect("the voting setup")
        }
        other => panic!("ConfigParam 11 is {other:?}"),
    }
}

fn contract_storage_price(chain: &Chain, critical: bool, ttl: u32, bits: u64, refs: u64) -> u128 {
    use tos_vm::stack::StackItem;
    let result = chain
        .blockchain
        .run_get_method(
            &chain.config_contract,
            "proposal_storage_price",
            vec![
                StackItem::int(if critical { -1 } else { 0 }),
                StackItem::int(i64::from(ttl)),
                StackItem::int(bits as i64),
                StackItem::int(refs as i64),
            ],
        )
        .expect("the configuration contract answers");
    assert_eq!(result.exit_code, 0, "proposal_storage_price failed");
    result
        .stack
        .last()
        .expect("a price")
        .as_integer()
        .expect("an integer")
        .to_string()
        .parse()
        .expect("a non-negative price")
}

#[test]
fn a_proposal_built_for_the_cli_is_registered_at_the_price_it_computes() {
    use contracts::config_contract::messages::proposal;
    let mut chain = launch();
    let param_id = 42;
    assert!(!is_critical(&chain, param_id), "the fixture expects an ordinary parameter");
    let setup = voting_setup(&chain, false);
    let ttl = setup.min_store_sec.checked_add(3_600).expect("a lifetime");

    let mut value = chain_block::BuilderData::new();
    chain_block::IBitstring::append_u32(&mut value, 0xabcd).expect("value");
    chain_block::IBitstring::append_u64(&mut value, 0x1234).expect("value");
    let value = value.into_cell().expect("value cell");
    let (price, stored) = proposal::storage_price(&setup, Some(&value), ttl).expect("a price");
    assert_eq!(stored, ttl.min(setup.max_store_sec));
    let (_, bits, refs) = proposal::value_size(Some(&value)).expect("size");
    assert_eq!(
        contract_storage_price(&chain, false, ttl, bits, refs),
        price,
        "the local price differs from the contract's own"
    );

    let cell = proposal::proposal_cell(param_id, Some(value), None).expect("proposal");
    let body = proposal::new_proposal_body(7, ttl, cell, false).expect("body");
    let proposer =
        chain.blockchain.treasury("cli-proposer", 20_000 * TOS).expect("a funded account");

    // One nanotomi short of the price plus the contract's minimum surplus is refused.
    let short = u64::try_from(price + proposal::MIN_VALUE_ABOVE_PRICE - 1).expect("a value");
    let before = balance_of(&chain, &chain.config_contract);
    let result = chain
        .blockchain
        .send_message(proposer.build_message(
            &chain.config_contract,
            short,
            true,
            Some(body.clone()),
        ))
        .expect("delivered");
    let tags = replies(&result);
    assert!(!tags.contains(&proposal::PROPOSAL_ACCEPTED), "an underpaid proposal was registered");
    assert!(tags.contains(&0xf061_7924), "expected the need-more-money answer: {tags:02x?}");
    assert_eq!(balance_of(&chain, &chain.config_contract), before, "a refusal kept value");

    let enough = u64::try_from(price + proposal::MIN_VALUE_ABOVE_PRICE).expect("a value");
    let result = chain
        .blockchain
        .send_message(proposer.build_message(&chain.config_contract, enough, true, Some(body)))
        .expect("delivered");
    let tags = replies(&result);
    assert!(tags.contains(&proposal::PROPOSAL_ACCEPTED), "refused: {tags:02x?}");
    assert_eq!(
        balance_of(&chain, &chain.config_contract) - before,
        price,
        "the contract kept something other than the computed price"
    );
}

#[test]
fn a_critical_parameter_needs_the_critical_flag_and_a_mandatory_one_its_current_hash() {
    use contracts::config_contract::messages::proposal;
    let mut chain = launch();
    // Whichever present parameter the launch configuration lists first as critical.
    let critical_ids = match chain.blockchain.config_params().config(10).expect("param 10") {
        Some(chain_block::ConfigParamEnum::ConfigParam10(value)) => {
            let mut ids = Vec::new();
            value
                .critical_params
                .iterate_keys(|id: i32| {
                    ids.push(id);
                    Ok(true)
                })
                .expect("the critical list");
            ids
        }
        other => panic!("ConfigParam 10 is {other:?}"),
    };
    let param_id = critical_ids
        .into_iter()
        .find(|id| raw_parameter(&chain, *id).is_some())
        .expect("a present critical parameter");
    assert!(is_critical(&chain, param_id), "the fixture expects a critical parameter");
    let value = raw_parameter(&chain, param_id).expect("the current voting setup");
    let setup = voting_setup(&chain, true);
    let ttl = setup.min_store_sec.checked_add(3_600).expect("a lifetime");
    let (price, _) = proposal::storage_price(&setup, Some(&value), ttl).expect("a price");
    let value_to_send =
        u64::try_from(price + proposal::MIN_VALUE_ABOVE_PRICE + u128::from(TOS)).expect("a value");
    let proposer = chain.blockchain.treasury("cli-proposer", 100_000 * TOS).expect("funded");

    // A proposal for a mandatory parameter must name the value it replaces, or it is
    // refused as an attempt to null it; binding to the current hash satisfies both rules.
    let mut current = [0u8; 32];
    current.copy_from_slice(value.repr_hash().as_slice());
    let unbound = proposal::proposal_cell(param_id, Some(value.clone()), None).expect("proposal");
    let result = chain
        .blockchain
        .send_message(proposer.build_message(
            &chain.config_contract,
            value_to_send,
            true,
            Some(proposal::new_proposal_body(10, ttl, unbound, true).expect("body")),
        ))
        .expect("delivered");
    assert!(replies(&result).contains(&0xcd50_6e6c), "{:02x?}", replies(&result));

    let cell =
        proposal::proposal_cell(param_id, Some(value.clone()), Some(current)).expect("proposal");
    let plain = proposal::new_proposal_body(8, ttl, cell.clone(), false).expect("body");
    let result = chain
        .blockchain
        .send_message(proposer.build_message(
            &chain.config_contract,
            value_to_send,
            true,
            Some(plain),
        ))
        .expect("delivered");
    assert!(replies(&result).contains(&0xc372_6954), "{:02x?}", replies(&result));

    let critical = proposal::new_proposal_body(9, ttl, cell, true).expect("body");
    let result = chain
        .blockchain
        .send_message(proposer.build_message(
            &chain.config_contract,
            value_to_send,
            true,
            Some(critical),
        ))
        .expect("delivered");
    assert!(replies(&result).contains(&proposal::PROPOSAL_ACCEPTED), "{:02x?}", replies(&result));
}

// ---------------------------------------------------------------------------
// How long a proposal lives: the launch ConfigParam 11 lifecycle
//
// The canonical genesis votes with normal 2/6/2/5 and critical 4/7/3/5
// (min_tot_rounds max_tot_rounds min_wins max_losses). The contract stores
// max_tot_rounds when the proposal is registered, in a round that already takes votes,
// decrements it on every later validator-set change and removes the proposal only once
// it goes negative; a round without a winning vote counts as a loss, and the proposal is
// removed only when losses exceed max_losses. So an ordinary proposal has seven voting
// rounds and a critical one eight, and with these values the loss cap and the round cap
// end a proposal on the same transition. These tests run that lifecycle against the
// launch voting setup, with a round turned over by a change of the current validator set.
// ---------------------------------------------------------------------------

/// The launch voting setup, read from the zero state rather than restated.
fn launch_rounds(chain: &Chain, critical: bool) -> (u8, u8, u8, u8) {
    let setup = voting_setup(chain, critical);
    (setup.min_tot_rounds, setup.max_tot_rounds, setup.min_wins, setup.max_losses)
}

/// Register a proposal for parameter 42 with the critical flag as given. Parameter 42 is
/// not critical, so a critical vote on it is permitted and installs normally.
fn propose_for_rounds(chain: &mut Chain, critical: bool, value: u32, query_id: u64) -> [u8; 32] {
    use chain_block::GetRepresentationHash;
    use contracts::config_contract::messages::proposal;
    assert!(!is_critical(chain, 42), "the fixture expects an ordinary parameter");
    let cell = proposal::proposal_cell(42, Some(proposal_value(value)), None).expect("proposal");
    let hash: [u8; 32] = cell.hash(0).as_slice()[..32].try_into().expect("a 32-byte hash");
    // Within both setups' store limits: at least 5,000,000 s, at most 10,000,000 s.
    let body = proposal::new_proposal_body(query_id, 6_000_000, cell, critical).expect("body");
    let proposer =
        chain.blockchain.treasury("rounds-proposer", 20_000 * TOS).expect("a funded account");
    let result = chain
        .blockchain
        .send_message(proposer.build_message(
            &chain.config_contract,
            10_000 * TOS,
            true,
            Some(body),
        ))
        .expect("the proposal is delivered");
    let tags = replies(&result);
    assert!(tags.contains(&PROPOSAL_ACCEPTED), "the proposal was refused: {tags:02x?}");
    hash
}

/// `rounds_remaining wins losses` of a pending proposal, or None once it is gone.
fn proposal_counters(chain: &Chain, proposal_hash: &[u8; 32]) -> Option<(u8, u8, u8)> {
    let account =
        chain.blockchain.get_account(&chain.config_contract).expect("the contract is deployed");
    let mut slice =
        chain_block::SliceData::load_cell(account.get_data().expect("storage")).expect("storage");
    slice.checked_drain_reference().expect("the parameter dictionary");
    let votes = next_dictionary(&mut slice, 256);
    let key = chain_block::SliceData::load_builder(
        chain_block::BuilderData::with_raw(proposal_hash.to_vec(), 256).expect("a key"),
    )
    .expect("a key slice");
    let mut status = votes.get(key).expect("lookup")?;
    // cfg_proposal_status#ce expires:uint32 proposal:^ConfigProposal is_critical:Bool
    //   voters:(HashmapE 16 True) remaining_weight:int64 validator_set_id:uint256
    //   rounds_remaining:uint8 wins:uint8 losses:uint8
    assert_eq!(status.get_next_byte().expect("tag"), 0xce, "not a proposal status");
    status.get_next_u32().expect("expiry");
    status.checked_drain_reference().expect("the proposal");
    status.get_next_bit().expect("critical");
    next_dictionary(&mut status, 16);
    status.get_next_u64().expect("remaining weight");
    status.get_next_bits(256).expect("validator set id");
    Some((
        status.get_next_byte().expect("rounds remaining"),
        status.get_next_byte().expect("wins"),
        status.get_next_byte().expect("losses"),
    ))
}

/// Turn the voting round over: the current validator set changes identity (its
/// `utime_since` moves by a second) while its validators and keys stay the same, which
/// is exactly what the contract compares when it decides a new round has begun.
fn turn_round(chain: &mut Chain) {
    use chain_block::IBitstring;
    let mut key = chain_block::BuilderData::new();
    key.append_u32(34).expect("the parameter index");
    let stored = configuration_from_contract(chain)
        .config_params
        .get(chain_block::SliceData::load_builder(key).expect("a key slice"))
        .expect("lookup")
        .expect("a current validator set");
    let mut set =
        chain_block::SliceData::load_cell(stored.reference(0).expect("the set")).expect("set");
    let tag = set.get_next_byte().expect("tag");
    let since = set.get_next_u32().expect("utime_since");
    let mut next = chain_block::BuilderData::new();
    next.append_u8(tag).expect("tag");
    next.append_u32(since + 1).expect("utime_since");
    next.checked_append_references_and_data(&set).expect("the rest of the set");
    set_contract_parameter(chain, 34, next.into_cell().expect("the next set"));
}

/// One validator votes: not enough weight to win the round, but the vote makes the
/// contract apply any pending round change. Returns the status code it answered with.
fn touch_round(
    chain: &mut Chain,
    voter: &PqValidator,
    proposal_hash: &[u8; 32],
    query_id: u64,
) -> i64 {
    let idx = index_of(chain, voter);
    let signature =
        voter.sign_under(&vote_preimage(chain, idx, proposal_hash), CONFIG_VOTE_CONTEXT);
    let sender = chain.blockchain.treasury("round-voter", 100 * TOS).expect("an account");
    let result = chain
        .blockchain
        .send_message(sender.build_message(
            &chain.config_contract,
            VOTE_VALUE,
            true,
            Some(vote_body(query_id, &signature, idx, proposal_hash)),
        ))
        .expect("the vote is delivered");
    assert_eq!(exit_code_of(&result), 0, "the vote was refused");
    let answers: Vec<u32> = replies(&result)
        .into_iter()
        .filter(|tag| tag.wrapping_sub(0xd674_5240).wrapping_add(8) < 16)
        .collect();
    assert_eq!(answers.len(), 1, "expected one vote confirmation: {answers:02x?}");
    i64::from(answers[0]) - 0xd674_5240
}

/// Every validator votes, which is enough weight to win the round. Returns the status
/// code of the last vote cast; voting stops once the proposal is decided.
fn win_round(
    chain: &mut Chain,
    validators: &[PqValidator],
    proposal_hash: &[u8; 32],
    query_base: u64,
) -> i64 {
    let mut status = 0;
    for (n, voter) in validators.iter().enumerate() {
        status = touch_round(chain, voter, proposal_hash, query_base + n as u64);
        if proposal_counters(chain, proposal_hash).is_none() {
            break;
        }
    }
    status
}

const VOTE_COUNTED: i64 = 2;
const VOTE_DISCARDED: i64 = -1;
const ACCEPTED_ORDINARY: i64 = 6;
const ACCEPTED_CRITICAL: i64 = 7;

fn installed_42(chain: &Chain) -> bool {
    parameter_present(&configuration_from_contract(chain), 42)
}

#[test]
fn an_ordinary_proposal_is_accepted_in_its_seventh_round() {
    let (mut chain, validators, _) = elect_install_and_rotate();
    assert_eq!(launch_rounds(&chain, false), (2, 6, 2, 5), "the launch ordinary setup moved");
    let p = propose_for_rounds(&mut chain, false, 0x0701, 0x7000);
    assert_eq!(proposal_counters(&chain, &p), Some((6, 0, 0)));

    // Round 1: win.
    assert_eq!(win_round(&mut chain, &validators, &p, 0x7010), VOTE_COUNTED);
    // Rounds 2..6: lost, each touched by one vote that cannot win.
    for round in 2..=6u64 {
        turn_round(&mut chain);
        assert_eq!(touch_round(&mut chain, &validators[0], &p, 0x7000 + round * 16), VOTE_COUNTED);
    }
    // Round 7: no rounds remain, five losses, one win; this round still takes votes.
    turn_round(&mut chain);
    assert_eq!(win_round(&mut chain, &validators, &p, 0x7070), ACCEPTED_ORDINARY);
    assert_eq!(proposal_counters(&chain, &p), None, "the accepted proposal is still pending");
    assert!(installed_42(&chain), "the proposal accepted in round 7 was not installed");
}

#[test]
fn a_critical_proposal_is_accepted_in_its_eighth_round() {
    let (mut chain, validators, _) = elect_install_and_rotate();
    assert_eq!(launch_rounds(&chain, true), (4, 7, 3, 5), "the launch critical setup moved");
    let p = propose_for_rounds(&mut chain, true, 0x0801, 0x8000);
    assert_eq!(proposal_counters(&chain, &p), Some((7, 0, 0)));

    // Rounds 1 and 2: win.
    assert_eq!(win_round(&mut chain, &validators, &p, 0x8010), VOTE_COUNTED);
    turn_round(&mut chain);
    assert_eq!(win_round(&mut chain, &validators, &p, 0x8020), VOTE_COUNTED);
    // Rounds 3..7: lost.
    for round in 3..=7u64 {
        turn_round(&mut chain);
        assert_eq!(touch_round(&mut chain, &validators[0], &p, 0x8000 + round * 16), VOTE_COUNTED);
    }
    // Round 8: no rounds remain, five losses, two wins; the third win accepts it.
    turn_round(&mut chain);
    assert_eq!(win_round(&mut chain, &validators, &p, 0x8080), ACCEPTED_CRITICAL);
    assert_eq!(proposal_counters(&chain, &p), None, "the accepted proposal is still pending");
    assert!(installed_42(&chain), "the proposal accepted in round 8 was not installed");
}

#[test]
fn a_proposal_is_removed_on_the_transition_after_its_last_round() {
    let (mut chain, validators, _) = elect_install_and_rotate();
    let p = propose_for_rounds(&mut chain, true, 0x0901, 0x9000);
    // Rounds 1 and 2 won, rounds 3..7 lost, round 8 entered and lost too.
    assert_eq!(win_round(&mut chain, &validators, &p, 0x9010), VOTE_COUNTED);
    turn_round(&mut chain);
    assert_eq!(win_round(&mut chain, &validators, &p, 0x9020), VOTE_COUNTED);
    for round in 3..=8u64 {
        turn_round(&mut chain);
        assert_eq!(touch_round(&mut chain, &validators[0], &p, 0x9000 + round * 16), VOTE_COUNTED);
    }
    assert_eq!(proposal_counters(&chain, &p), Some((0, 2, 5)), "round 8 is the last one");
    // The next transition ends it: no round remains and the sixth loss is recorded.
    turn_round(&mut chain);
    assert_eq!(touch_round(&mut chain, &validators[0], &p, 0x9090), VOTE_DISCARDED);
    assert_eq!(proposal_counters(&chain, &p), None, "the proposal outlived its last round");
    assert!(!installed_42(&chain), "a removed proposal was installed");
}

#[test]
fn five_lost_rounds_keep_a_proposal_and_the_sixth_removes_it() {
    let (mut chain, validators, _) = elect_install_and_rotate();
    let p = propose_for_rounds(&mut chain, false, 0x0a01, 0xa000);
    // Round 1 lost (one vote only), then rounds 2..6 lost: five losses at round 6.
    assert_eq!(touch_round(&mut chain, &validators[0], &p, 0xa010), VOTE_COUNTED);
    for round in 2..=6u64 {
        turn_round(&mut chain);
        assert_eq!(touch_round(&mut chain, &validators[0], &p, 0xa000 + round * 16), VOTE_COUNTED);
    }
    assert_eq!(proposal_counters(&chain, &p), Some((1, 0, 5)), "five losses are still live");
    // Round 6 lost as well: the sixth loss removes it, with one round still remaining.
    turn_round(&mut chain);
    assert_eq!(touch_round(&mut chain, &validators[0], &p, 0xa070), VOTE_DISCARDED);
    assert_eq!(proposal_counters(&chain, &p), None, "a sixth loss did not remove the proposal");
}

/// With the launch values the round cap and the loss cap end a proposal on the same
/// transition, so neither is observable alone through them (loosening only the round cap
/// changes no outcome). This test lifts the loss cap to 255 to hold the round cap on its
/// own: an ordinary proposal still lives in round 7 and is gone on the next transition.
#[test]
fn the_round_cap_alone_ends_a_proposal_after_its_seventh_round() {
    use chain_block::IBitstring;
    let (mut chain, validators, _) = elect_install_and_rotate();
    let setup = |min_rounds: u8, max_rounds: u8, min_wins: u8, min_store: u32, max_store: u32| {
        let mut b = chain_block::BuilderData::new();
        b.append_u8(0x36).expect("tag");
        for value in [min_rounds, max_rounds, min_wins, 255] {
            b.append_u8(value).expect("rounds");
        }
        for value in [min_store, max_store, 1, 500] {
            b.append_u32(value).expect("store and price");
        }
        b.into_cell().expect("a proposal setup")
    };
    let mut value = chain_block::BuilderData::new();
    value.append_u8(0x91).expect("tag");
    value.checked_append_reference(setup(2, 6, 2, 1_000_000, 10_000_000)).expect("ordinary");
    value.checked_append_reference(setup(4, 7, 3, 5_000_000, 20_000_000)).expect("critical");
    set_contract_parameter(&mut chain, 11, value.into_cell().expect("a voting setup"));

    let p = propose_for_rounds(&mut chain, false, 0x0b01, 0xb000);
    assert_eq!(touch_round(&mut chain, &validators[0], &p, 0xb010), VOTE_COUNTED);
    for round in 2..=7u64 {
        turn_round(&mut chain);
        assert_eq!(touch_round(&mut chain, &validators[0], &p, 0xb000 + round * 16), VOTE_COUNTED);
    }
    assert_eq!(proposal_counters(&chain, &p), Some((0, 0, 6)), "round 7 is still live");
    turn_round(&mut chain);
    assert_eq!(touch_round(&mut chain, &validators[0], &p, 0xb080), VOTE_DISCARDED);
    assert_eq!(proposal_counters(&chain, &p), None, "the proposal outlived max_tot_rounds");
}

// ---------------------------------------------------------------------------
// Get-method fixtures for the VM crate
//
// The VM crate tests its get-method runner against the Elector, but cannot build a
// zerostate. It reads two Elector accounts this test produces from the real zerostate:
// one as deployed, with no election open, and one holding a single accepted stake. They
// are checked byte for byte here, so a change to the Elector or the zerostate that is
// not carried into the fixtures fails here rather than leaving the VM tests exercising
// an Elector this repository no longer deploys. Set TOS_REGENERATE_FIXTURES=1 to rewrite
// them.
// ---------------------------------------------------------------------------

/// Where the VM crate reads the fixtures from.
fn vm_getter_fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vm/src/tests/data").join(name)
}

fn elector_account_boc(chain: &Chain) -> Vec<u8> {
    use chain_block::Serializable;
    chain
        .blockchain
        .get_account(&chain.elector)
        .expect("the Elector account")
        .write_to_bytes()
        .expect("the Elector account serializes")
}

fn check_vm_getter_fixture(name: &str, generated: &[u8]) {
    let path = vm_getter_fixture(name);
    if std::env::var_os("TOS_REGENERATE_FIXTURES").is_some() {
        std::fs::write(&path, generated).expect("write the fixture");
        return;
    }
    let committed = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("{} is missing ({e}); regenerate it", path.display()));
    assert!(
        committed == generated,
        "{} no longer matches the Elector this repository deploys; rerun with \
         TOS_REGENERATE_FIXTURES=1",
        path.display()
    );
}

#[test]
fn vm_getter_fixtures_match_the_deployed_elector() {
    let chain = launch();
    assert_eq!(active_election_id(&chain), 0, "the deployed Elector has an election open");
    check_vm_getter_fixture("elector-zerostate.boc", &elector_account_boc(&chain));

    let (mut chain, _treasury, election) = open_election("vm-getter-fixture", 200_000 * TOS);
    require_post_quantum_version(&chain);
    let account =
        chain.blockchain.treasury("vm-getter-fixture-validator", 40_000 * TOS).expect("an account");
    // PUBLIC TEST ONLY seed: the fixture must not depend on a key generated per machine.
    let validator = PqValidator::from_seed(0x70, [0x70; 32]);
    let result = pq_stake(&mut chain, &account, &validator, election, 70, 11_000 * TOS);
    assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "the fixture stake was refused");
    check_vm_getter_fixture("elector-one-stake.boc", &elector_account_boc(&chain));
}
