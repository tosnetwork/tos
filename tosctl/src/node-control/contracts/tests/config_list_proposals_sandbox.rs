/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! `list_proposals` of the configuration contract the chain launches with
//! (crypto/smartcont/config-code.fc, taken from a generated zerostate), rendered as the
//! node's `runGetMethodStd` serves it and read back by the decoder `tosctl` uses.
//!
//! The proposals are written into the contract's vote dictionary directly, in the
//! layout `unpack_proposal_status` reads. The contract's own getter unpacks them, so a
//! layout it does not accept fails the getter rather than agreeing with this file.
//! Voting itself is not exercised here: a vote needs an ML-DSA-44 validator signature.

use chain_block::{
    Account, BuilderData, Cell, ConfigParams, HashmapE, HashmapType, IBitstring, MsgAddressInt,
    ShardStateUnsplit, SliceData,
};
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use contracts::config_contract::{ConfigProposal, ProposalAnswer, ProposalRead, proposal_state};
use contracts::{
    ConfigContractImpl, ConfigContractWrapper, DefaultChainProvider, contract_provider_from,
};
use tos_sandbox::{Blockchain, generate_zerostate_state};
use tos_vm::stack::{StackItem, integer::IntegerData};

mod served;
use served::{Reply, ServedNode};

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

struct Chain {
    blockchain: Blockchain,
    config: MsgAddressInt,
}

/// The configuration contract as the zerostate deploys it, on a chain with its config.
fn launch() -> Chain {
    let state = zerostate();
    let params: ConfigParams = state
        .read_custom()
        .expect("masterchain extra")
        .expect("the zerostate is a masterchain state")
        .config()
        .clone();
    let config = MsgAddressInt::with_standart(
        None,
        -1,
        params.config_address().expect("configuration address"),
    )
    .expect("masterchain address");
    let account: Account = state
        .read_accounts()
        .expect("accounts")
        .account(config.address())
        .expect("account lookup")
        .expect("the zerostate deploys the configuration contract")
        .read_account()
        .expect("account");
    let mut blockchain = Blockchain::with_config(params).expect("sandbox with the real config");
    blockchain.set_workchain(-1);
    blockchain.set_account(config.clone(), account);
    Chain { blockchain, config }
}

/// One registered proposal, as `cfg_proposal_status#ce` stores it.
#[derive(Clone)]
struct Stored {
    hash: [u8; 32],
    expires: u32,
    critical: bool,
    param_id: i32,
    value: Option<Cell>,
    value_hash: Option<[u8; 32]>,
    voters: Vec<u16>,
    weight_remaining: i64,
    vset_id: [u8; 32],
    rounds_remaining: u8,
    wins: u8,
    losses: u8,
}

fn build(fill: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut builder = BuilderData::new();
    fill(&mut builder);
    builder.into_cell().expect("cell")
}

fn key(bytes: &[u8], bits: usize) -> SliceData {
    SliceData::from_raw(bytes.to_vec(), bits)
}

impl Stored {
    fn status(&self) -> SliceData {
        let proposal = build(|p| {
            p.append_u8(0xf3).unwrap();
            p.append_i32(self.param_id).unwrap();
            match &self.value {
                Some(value) => {
                    p.append_bit_one().unwrap();
                    p.checked_append_reference(value.clone()).unwrap();
                }
                None => {
                    p.append_bit_zero().unwrap();
                }
            }
            match &self.value_hash {
                Some(hash) => {
                    p.append_bit_one().unwrap();
                    p.append_raw(hash, 256).unwrap();
                }
                None => {
                    p.append_bit_zero().unwrap();
                }
            }
        });
        let mut voters = HashmapE::with_bit_len(16);
        for voter in &self.voters {
            let stamp = SliceData::load_cell(build(|v| {
                v.append_u32(1).unwrap();
            }))
            .unwrap();
            voters.set(key(&voter.to_be_bytes(), 16), &stamp).unwrap();
        }
        SliceData::load_cell(build(|s| {
            s.append_u8(0xce).unwrap();
            s.append_u32(self.expires).unwrap();
            s.checked_append_reference(proposal).unwrap();
            if self.critical {
                s.append_bit_one().unwrap();
            } else {
                s.append_bit_zero().unwrap();
            }
            match voters.data() {
                Some(root) => {
                    s.append_bit_one().unwrap();
                    s.checked_append_reference(root.clone()).unwrap();
                }
                None => {
                    s.append_bit_zero().unwrap();
                }
            }
            s.append_i64(self.weight_remaining).unwrap();
            s.append_raw(&self.vset_id, 256).unwrap();
            s.append_u8(self.rounds_remaining).unwrap();
            s.append_u8(self.wins).unwrap();
            s.append_u8(self.losses).unwrap();
        }))
        .unwrap()
    }

    fn unvoted(hash: [u8; 32], param_id: i32) -> Self {
        Self {
            hash,
            expires: 1_900_000_000,
            critical: false,
            param_id,
            value: None,
            value_hash: None,
            voters: vec![],
            weight_remaining: 1 << 40,
            vset_id: [0x5a; 32],
            rounds_remaining: 3,
            wins: 0,
            losses: 0,
        }
    }
}

/// Replaces the contract's vote dictionary with `proposals`, keeping its parameters.
fn register(chain: &mut Chain, proposals: &[Stored]) {
    let mut account =
        chain.blockchain.get_account(&chain.config).expect("configuration contract").clone();
    let data = account.get_data().expect("storage");
    let mut slice = SliceData::load_cell(data).expect("storage");
    let parameters = slice.checked_drain_reference().expect("the parameter dictionary");
    let mut votes = HashmapE::with_bit_len(256);
    for proposal in proposals {
        votes.set(key(&proposal.hash, 256), &proposal.status()).unwrap();
    }
    let rebuilt = build(|d| {
        d.checked_append_reference(parameters).unwrap();
        match votes.data() {
            Some(root) => {
                d.append_bit_one().unwrap();
                d.checked_append_reference(root.clone()).unwrap();
            }
            None => {
                d.append_bit_zero().unwrap();
            }
        }
    });
    account.set_data(rebuilt);
    chain.blockchain.set_account(chain.config.clone(), account);
}

const SEQNO: u32 = 777;

/// A getter of the contract run in the sandbox, as the node would serve its result.
fn getter_result(chain: &Chain, method: &str, args: Vec<StackItem>) -> serde_json::Value {
    let result = chain.blockchain.run_get_method(&chain.config, method, args).expect("getter runs");
    result.expect_success();
    served::run_result(&result.stack, served::block_json(SEQNO))
}

fn get_proposal_result(chain: &Chain, hash: [u8; 32]) -> serde_json::Value {
    getter_result(
        chain,
        "get_proposal",
        vec![StackItem::integer(IntegerData::from_unsigned_bytes_be(hash))],
    )
}

/// The contract's stored account, as BOCs.
fn account_bocs(chain: &Chain) -> (Vec<u8>, Vec<u8>) {
    let account = chain.blockchain.get_account(&chain.config).expect("configuration contract");
    let code = account.get_code().expect("code");
    let data = account.get_data().expect("data");
    (
        chain_block::write_boc(&code).expect("code boc"),
        chain_block::write_boc(&data).expect("data boc"),
    )
}

/// What a node answers: the getters' results as the sandbox computes them for this
/// state (or a replacement), and the stored account, all at one block.
struct Answers {
    list: Reply,
    get: std::collections::HashMap<String, Reply>,
    account: Reply,
}

impl Answers {
    fn of(chain: &Chain, hashes: &[[u8; 32]]) -> Self {
        let (code, data) = account_bocs(chain);
        Self {
            list: Reply::ok(getter_result(chain, "list_proposals", vec![])),
            get: hashes
                .iter()
                .map(|hash| (hex::encode(hash), Reply::ok(get_proposal_result(chain, *hash))))
                .collect(),
            account: Reply::ok(served::account_result(&code, &data, served::block_json(SEQNO))),
        }
    }
}

/// The hash `get_proposal` was asked for, from the request's `["num", "0x..."]`.
fn requested_hash(params: &serde_json::Value) -> String {
    params["stack"][0][1].as_str().unwrap_or_default().trim_start_matches("0x").to_ascii_lowercase()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

/// A node serving `answers`, and the configuration wrapper over the real client
/// and provider stack talking to it.
async fn serve(answers: Answers) -> (ServedNode, ConfigContractImpl) {
    let Answers { list, get, account } = answers;
    let node = ServedNode::start(move |method, params| match method {
        "getMasterchainInfo" => served::masterchain_info(SEQNO),
        "runGetMethodStd" | "getAddressInformation" if params["seqno"] != SEQNO => {
            Reply::raw(500, "{}")
        }
        "runGetMethodStd" if params["method"] == "list_proposals" => list.clone(),
        "runGetMethodStd" => {
            get.get(&requested_hash(params)).cloned().unwrap_or_else(|| Reply::raw(500, "{}"))
        }
        "getAddressInformation" => account.clone(),
        _ => Reply::raw(404, "{}"),
    })
    .await;
    let client =
        std::sync::Arc::new(ClientJsonRpc::connect(node.url.clone(), None).expect("client"));
    let provider = std::sync::Arc::new(DefaultChainProvider::new(client));
    (node, ConfigContractImpl::new(contract_provider_from(provider)))
}

/// `list_proposals` read through `ConfigContractImpl`, the path every caller
/// (`vote offer ls`, `vote offer cast`, the voting service) goes through: over HTTP
/// to a node serving the sandbox's own answers, on the bounded worker.
fn decoded(chain: &Chain) -> Vec<ConfigProposal> {
    let answers = Answers::of(chain, &[]);
    runtime().block_on(async {
        let (_node, wrapper) = serve(answers).await;
        wrapper
            .list_proposals()
            .await
            .unwrap_or_else(|error| panic!("the served proposal list decodes: {error:#}"))
    })
}

/// The same state read from the stored account alone.
fn from_state(chain: &Chain, read: ProposalRead) -> anyhow::Result<ProposalAnswer> {
    let (code, data) = account_bocs(chain);
    proposal_state::decode_state(&code, &data, read)
}

fn state_list(chain: &Chain) -> Vec<ConfigProposal> {
    match from_state(chain, ProposalRead::List).expect("the stored state decodes") {
        ProposalAnswer::List(list) => list,
        _ => panic!("a list read answered something else"),
    }
}

/// Every field of two decodings agrees.
fn assert_same(left: &ConfigProposal, right: &ConfigProposal) {
    assert_eq!(left.hash, right.hash);
    assert_eq!(left.expires, right.expires);
    assert_eq!(left.is_critical, right.is_critical);
    assert_eq!(left.param.id, right.param.id);
    assert_eq!(
        left.param.cell.as_ref().map(|cell| cell.repr_hash()),
        right.param.cell.as_ref().map(|cell| cell.repr_hash())
    );
    assert_eq!(left.param.hash, right.param.hash);
    assert_eq!(left.vset_id, right.vset_id);
    assert_eq!(left.voters, right.voters);
    assert_eq!(left.weight_remaining, right.weight_remaining);
    assert_eq!(left.rounds_remaining, right.rounds_remaining);
    assert_eq!(left.wins, right.wins, "wins");
    assert_eq!(left.losses, right.losses, "losses");
}

fn assert_matches(decoded: &ConfigProposal, stored: &Stored) {
    assert_eq!(decoded.hash, stored.hash);
    assert_eq!(decoded.expires, stored.expires);
    assert_eq!(decoded.is_critical, stored.critical);
    assert_eq!(decoded.param.id, stored.param_id);
    assert_eq!(
        decoded.param.cell.as_ref().map(|cell| cell.repr_hash()),
        stored.value.as_ref().map(|cell| cell.repr_hash())
    );
    assert_eq!(decoded.param.hash, stored.value_hash);
    assert_eq!(decoded.vset_id, stored.vset_id);
    assert_eq!(decoded.voters, stored.voters);
    assert_eq!(decoded.weight_remaining, stored.weight_remaining);
    assert_eq!(decoded.rounds_remaining, stored.rounds_remaining);
    assert_eq!(decoded.wins, stored.wins, "wins");
    assert_eq!(decoded.losses, stored.losses, "losses");
}

fn hash_ending(last: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[31] = last;
    hash
}

#[test]
fn genesis_registers_no_proposal() {
    let chain = launch();
    let served = getter_result(&chain, "list_proposals", vec![]).to_string();
    assert!(served.contains(
        r#""stack":[{"@type":"tvm.stackEntryList","list":{"@type":"tvm.list","elements":[]}}]"#
    ));
    assert!(decoded(&chain).is_empty());
    assert!(state_list(&chain).is_empty());
}

/// The code the zerostate deploys is the one whose storage the large-state path
/// interprets.
#[test]
fn the_supported_code_is_the_genesis_code() {
    let chain = launch();
    let (code, _) = account_bocs(&chain);
    let hash = chain_block::read_single_root_boc(&code).expect("code").repr_hash();
    assert!(proposal_state::SUPPORTED_CONFIG_CODE_HASHES.contains(&hash.inner()));
    let fixture = include_bytes!("fixtures/list_proposals/config-code.boc");
    assert_eq!(code, fixture.to_vec(), "the code fixture is the genesis code");
}

#[test]
fn one_unvoted_proposal_decodes_field_by_field() {
    let mut chain = launch();
    let stored = Stored::unvoted([0x47; 32], 1000);
    register(&mut chain, std::slice::from_ref(&stored));
    let proposals = decoded(&chain);
    assert_eq!(proposals.len(), 1);
    assert_matches(&proposals[0], &stored);
    assert_matches(&state_list(&chain)[0], &stored);
}

fn varied() -> Vec<Stored> {
    let mut high = [0xff; 32];
    high[31] = 0xfe;
    let mut middle = [0u8; 32];
    middle[0] = 0x80;
    let value = build(|v| {
        v.append_u32(0xdead_beef).unwrap();
    });
    let empty_value = build(|_| {});
    vec![
        Stored {
            hash: middle,
            expires: 1_800_000_123,
            critical: true,
            param_id: -999,
            value: Some(value),
            value_hash: Some([0x3c; 32]),
            voters: (0..21).collect(),
            weight_remaining: -77,
            vset_id: [0xa5; 32],
            rounds_remaining: 5,
            wins: 7,
            losses: 2,
        },
        Stored::unvoted(high, 31),
        Stored { losses: 1, ..Stored::unvoted(hash_ending(1), 100) },
        Stored { value_hash: Some([0; 32]), ..Stored::unvoted(hash_ending(2), 101) },
        Stored { value_hash: Some([0xff; 32]), ..Stored::unvoted(hash_ending(3), 102) },
        Stored { value: Some(empty_value), ..Stored::unvoted(hash_ending(4), 103) },
        Stored { weight_remaining: i64::MIN, ..Stored::unvoted(hash_ending(5), i32::MIN) },
        Stored { weight_remaining: i64::MAX, ..Stored::unvoted(hash_ending(6), i32::MAX) },
        Stored { voters: vec![0, 65_535], ..Stored::unvoted(hash_ending(7), 104) },
    ]
}

/// Proposals registered out of hash order, carrying values and none, a bound hash
/// absent, zero and maximal, 21 voters, the extremes of int64 weight and int32 id,
/// and unequal wins and losses: the getter returns them in ascending hash order,
/// and the stored account decodes to exactly the same, field by field.
#[test]
fn several_proposals_decode_in_ascending_order_and_match_the_stored_state() {
    let mut chain = launch();
    let stored = varied();
    register(&mut chain, &stored);
    let mut expected = stored.clone();
    expected.sort_by_key(|stored| stored.hash);
    let proposals = decoded(&chain);
    assert_eq!(proposals.len(), expected.len());
    for (decoded, stored) in proposals.iter().zip(&expected) {
        assert_matches(decoded, stored);
    }
    let state = state_list(&chain);
    assert_eq!(state.len(), proposals.len());
    for (from_state, from_getter) in state.iter().zip(&proposals) {
        assert_same(from_state, from_getter);
    }
}

/// `list_proposals` starts its downward walk strictly below 2^256 - 1, so it never
/// lists a proposal stored under that hash; `get_proposal` returns it. Both paths
/// keep both rules.
#[test]
fn the_maximum_hash_is_omitted_by_the_list_and_returned_by_get_proposal() {
    let mut chain = launch();
    let stored = vec![Stored::unvoted(hash_ending(2), 1), Stored::unvoted([0xff; 32], 2)];
    register(&mut chain, &stored);
    let proposals = decoded(&chain);
    assert_eq!(proposals.len(), 1);
    assert_matches(&proposals[0], &stored[0]);
    assert_eq!(state_list(&chain).len(), 1);

    let answers = Answers::of(&chain, &[[0xff; 32], [0x99; 32]]);
    let (one, absent) = runtime().block_on(async {
        let (_node, wrapper) = serve(answers).await;
        (
            wrapper.get_proposal([0xff; 32]).await.expect("present"),
            wrapper.get_proposal([0x99; 32]).await.expect("absent"),
        )
    });
    assert_matches(&one.expect("get_proposal returns the maximum hash"), &stored[1]);
    assert!(absent.is_none());
    let Ok(ProposalAnswer::One(Some(state))) = from_state(&chain, ProposalRead::One([0xff; 32]))
    else {
        panic!("the stored state returns the maximum hash for one read");
    };
    assert_matches(&state, &stored[1]);
    assert!(matches!(
        from_state(&chain, ProposalRead::One([0x99; 32])),
        Ok(ProposalAnswer::One(None))
    ));
    assert!(matches!(
        from_state(&chain, ProposalRead::Expiry([0xff; 32])),
        Ok(ProposalAnswer::Expiry(Some(1_900_000_000)))
    ));
}

/// A value of `cells` distinct cells of 1023 bits, as a balanced binary tree.
fn bulky_value(cells: u32) -> Cell {
    fn subtree(first: u32, count: u32) -> Cell {
        build(|c| {
            let mut bytes = [0u8; 128];
            bytes[..4].copy_from_slice(&first.to_be_bytes());
            c.append_raw(&bytes, 1023).unwrap();
            let rest = count - 1;
            let left = rest / 2;
            if left > 0 {
                c.checked_append_reference(subtree(first + 1, left)).unwrap();
            }
            if rest - left > 0 {
                c.checked_append_reference(subtree(first + 1 + left, rest - left)).unwrap();
            }
        })
    }
    subtree(0, cells)
}

/// Eight proposals for different parameters sharing one value of 1000 cells (the
/// contract stores at most 1024): the getter
/// serializes the value once per proposal, so its answer exceeds the transport
/// limit, while the stored account holds the shared cells once and stays within it.
/// The list is read whole from the stored account at the same block.
#[test]
fn a_list_too_large_for_the_getter_is_read_whole_from_the_stored_state() {
    let mut chain = launch();
    let value = bulky_value(1000);
    let stored: Vec<Stored> = (0..8u8)
        .map(|index| Stored {
            value: Some(value.clone()),
            ..Stored::unvoted(hash_ending(index + 1), 2000 + i32::from(index))
        })
        .collect();
    register(&mut chain, &stored);
    let answers = Answers::of(&chain, &[]);
    let limit = contracts::config_contract::proposal_transport::MAX_RESPONSE_BYTES;
    let getter_bytes = answers.list.body.len();
    let account_bytes = answers.account.body.len();
    assert!(getter_bytes > limit, "the getter answer is only {getter_bytes} bytes");
    assert!(account_bytes < limit, "the account answer is {account_bytes} bytes");
    let (calls, proposals) = runtime().block_on(async {
        let (node, wrapper) = serve(answers).await;
        let proposals = wrapper.list_proposals().await.expect("read from state");
        (node.calls(), proposals)
    });
    assert_eq!(calls, vec!["getMasterchainInfo", "runGetMethodStd", "getAddressInformation"]);
    assert_eq!(proposals.len(), 8);
    for (decoded, stored) in proposals.iter().zip(&stored) {
        assert_matches(decoded, stored);
    }
}

/// `count` small proposals with distinct hashes.
fn many(count: u32) -> Vec<Stored> {
    (0..count)
        .map(|index| {
            let mut hash = [0x5a; 32];
            hash[..4].copy_from_slice(&index.to_be_bytes());
            Stored::unvoted(hash, 1000 + index as i32)
        })
        .collect()
}

/// The node's get-method gas limit (`liteServer`'s `client_method_gas_limit`).
const NODE_GET_METHOD_GAS: i64 = 300_000;

/// The production path when the getter exceeds its gas: the node serves exit 13
/// with an answer far below the byte limit, and the list is read from the stored
/// account at the same block. It matches the getter run with ample gas, entry for
/// entry.
#[test]
fn a_getter_out_of_gas_is_read_whole_from_the_stored_state() {
    let mut chain = launch();
    register(&mut chain, &many(200));
    let starved = chain
        .blockchain
        .run_get_method_with_gas(&chain.config, "list_proposals", vec![], NODE_GET_METHOD_GAS)
        .expect("runs");
    assert_eq!(starved.exit_code, 13, "200 proposals fit the node's gas limit");
    let served = served::run_result_with_exit(&starved.stack, 13, served::block_json(SEQNO));
    let oracle = chain
        .blockchain
        .run_get_method_with_gas(&chain.config, "list_proposals", vec![], 100_000_000)
        .expect("runs");
    oracle.expect_success();
    let oracle_answers = Answers {
        list: Reply::ok(served::run_result(&oracle.stack, served::block_json(SEQNO))),
        ..Answers::of(&chain, &[])
    };
    let oracle_list = runtime().block_on(async {
        let (_node, wrapper) = serve(oracle_answers).await;
        wrapper.list_proposals().await.expect("the oracle decodes")
    });

    let answers = Answers { list: Reply::ok(served), ..Answers::of(&chain, &[]) };
    assert!(answers.list.body.len() < 1 << 20);
    let (calls, proposals) = runtime().block_on(async {
        let (node, wrapper) = serve(answers).await;
        let proposals = wrapper.list_proposals().await.expect("read from state");
        (node.calls(), proposals)
    });
    assert_eq!(calls, vec!["getMasterchainInfo", "runGetMethodStd", "getAddressInformation"]);
    assert_eq!(proposals.len(), 200);
    assert_eq!(oracle_list.len(), 200);
    for (from_state, from_oracle) in proposals.iter().zip(&oracle_list) {
        assert_same(from_state, from_oracle);
    }
}

/// Exit 13 sends only a list read to stored state, and only at the checkpoint:
/// `get_proposal` exit 13, other exits, and exit 13 from another block are errors.
#[test]
fn exit_13_falls_back_for_the_list_only() {
    let mut chain = launch();
    register(&mut chain, &[Stored::unvoted([0x47; 32], 1000)]);
    let exit = |code: i32, seqno: u32| {
        Reply::ok(served::run_result_with_exit(&[], code, served::block_json(seqno)))
    };
    for (case, list) in [
        ("exit 11", exit(11, SEQNO)),
        ("exit 1", exit(1, SEQNO)),
        ("exit 13 from another block", exit(13, SEQNO - 1)),
    ] {
        let answers = Answers { list, ..Answers::of(&chain, &[]) };
        let (calls, result) = runtime().block_on(async {
            let (node, wrapper) = serve(answers).await;
            let result = wrapper.list_proposals().await;
            (node.calls(), result.map(|list| list.len()))
        });
        assert!(result.is_err(), "{case} was accepted");
        assert!(!calls.contains(&"getAddressInformation".to_string()), "{case} fell back");
    }
    let mut answers = Answers::of(&chain, &[]);
    answers.get.insert(hex::encode([0x47; 32]), exit(13, SEQNO));
    let (calls, result) = runtime().block_on(async {
        let (node, wrapper) = serve(answers).await;
        let result = wrapper.get_proposal([0x47; 32]).await;
        (node.calls(), result.map(|proposal| proposal.is_some()))
    });
    assert!(result.is_err_and(|e| format!("{e:#}").contains("exited with code 13")));
    assert!(!calls.contains(&"getAddressInformation".to_string()));
}

/// The contract's getter, at the node's get-method gas limit (`liteServer`'s
/// `client_method_gas_limit`, 300 000), runs out of gas on a long list of small
/// proposals while its answer is still far below the byte limit.
#[test]
fn the_getter_runs_out_of_gas_long_before_the_byte_limit() {
    let run = |count: u32| {
        let mut chain = launch();
        register(&mut chain, &many(count));
        let result = chain
            .blockchain
            .run_get_method_with_gas(&chain.config, "list_proposals", vec![], NODE_GET_METHOD_GAS)
            .expect("runs");
        (result.exit_code, result.gas_used)
    };
    let (fits, gas) = run(100);
    assert_eq!(fits, 0, "100 proposals: {gas} gas");
    let (out_of_gas, _) = run(150);
    assert_eq!(out_of_gas, 13, "150 proposals ran within the node's gas limit");
}

/// Only an oversized getter answer falls back. A malformed or refused answer, an
/// answer from another block, a decoder failure, or an oversized `get_proposal`
/// answer is an error, and the account is never read.
#[test]
fn nothing_but_an_oversized_list_falls_back() {
    let mut chain = launch();
    register(&mut chain, &[Stored::unvoted([0x47; 32], 1000)]);
    let good = Answers::of(&chain, &[]).list.body;
    let other_block = good.replace(&format!("\"seqno\":{SEQNO}"), "\"seqno\":776");
    let bad_entry = good.replacen("\"number\":\"1900000000\"", "\"number\":\"-1900000000\"", 1);
    assert_ne!(other_block, good);
    assert_ne!(bad_entry, good);
    for (case, list) in [
        ("malformed JSON", Reply::raw(200, "{\"ok\":true,")),
        (
            "an error envelope",
            Reply::raw(
                500,
                r#"{"ok":false,"jsonrpc":"2.0","id":"@@ID@@","error":"exit code 11","code":500}"#,
            ),
        ),
        ("another block", Reply::raw(200, other_block)),
        ("a decoder failure", Reply::raw(200, bad_entry)),
    ] {
        let answers = Answers { list, ..Answers::of(&chain, &[]) };
        let (calls, result) = runtime().block_on(async {
            let (node, wrapper) = serve(answers).await;
            let result = wrapper.list_proposals().await;
            (node.calls(), result.map(|list| list.len()))
        });
        assert!(result.is_err(), "{case} was accepted");
        assert!(!calls.contains(&"getAddressInformation".to_string()), "{case} fell back");
    }

    let too_large = Reply::raw(
        200,
        " ".repeat(contracts::config_contract::proposal_transport::MAX_RESPONSE_BYTES + 1),
    );
    let mut answers = Answers::of(&chain, &[]);
    answers.get.insert(hex::encode([0x47; 32]), too_large);
    let (calls, result) = runtime().block_on(async {
        let (node, wrapper) = serve(answers).await;
        let result = wrapper.get_proposal([0x47; 32]).await;
        (node.calls(), result.map(|proposal| proposal.is_some()))
    });
    assert!(result.is_err_and(|e| format!("{e:#}").contains("get_proposal answer exceeds")));
    assert!(!calls.contains(&"getAddressInformation".to_string()));
}

/// The fallback reads the account at the checkpoint and only under supported code.
#[test]
fn the_fallback_refuses_another_block_and_unsupported_code() {
    let mut chain = launch();
    register(&mut chain, &[Stored::unvoted([0x47; 32], 1000)]);
    let (code, data) = account_bocs(&chain);
    let too_large = || {
        Reply::raw(
            200,
            " ".repeat(contracts::config_contract::proposal_transport::MAX_RESPONSE_BYTES + 1),
        )
    };
    let other_code = chain_block::write_boc(&build(|c| {
        c.append_u32(1).unwrap();
    }))
    .unwrap();
    for (case, account, expected) in [
        (
            "another block",
            Reply::ok(served::account_result(&code, &data, served::block_json(SEQNO - 1))),
            "another block",
        ),
        (
            "unsupported code",
            Reply::ok(served::account_result(&other_code, &data, served::block_json(SEQNO))),
            "unsupported code",
        ),
    ] {
        let exit13 = Reply::ok(served::run_result_with_exit(&[], 13, served::block_json(SEQNO)));
        for (trigger, list) in [("too large", too_large()), ("exit 13", exit13)] {
            let answers = Answers { list, account: account.clone(), get: Default::default() };
            let result = runtime().block_on(async {
                let (_node, wrapper) = serve(answers).await;
                wrapper.list_proposals().await.map(|list| list.len())
            });
            let error =
                result.err().unwrap_or_else(|| panic!("{case} after {trigger} was accepted"));
            assert!(format!("{error:#}").contains(expected), "{case} after {trigger}: {error:#}");
        }
    }
}

/// The stored-record decoder refuses every layout `unpack_proposal` would not read.
#[test]
fn malformed_stored_records_are_refused() {
    let chain = launch();
    let (code, _) = account_bocs(&chain);
    let decode = |data: Cell| {
        proposal_state::decode_state(
            &code,
            &chain_block::write_boc(&data).unwrap(),
            ProposalRead::List,
        )
    };
    let data_with = |status: SliceData| {
        let mut votes = HashmapE::with_bit_len(256);
        votes.set(key(&[0x47; 32], 256), &status).unwrap();
        build(|d| {
            d.checked_append_reference(Cell::default()).unwrap();
            d.append_bit_one().unwrap();
            d.checked_append_reference(votes.data().cloned().unwrap()).unwrap();
        })
    };
    let good = Stored::unvoted([0x47; 32], 1000);
    assert!(decode(data_with(good.status())).is_ok(), "the unmodified record decodes");

    // A status rebuilt from the good one's bits with one change.
    let status_bits = |edit: &dyn Fn(&mut Vec<u8>, &mut usize)| {
        let status = good.status();
        let mut bytes = status.get_bytestring(0);
        let mut bits = status.remaining_bits();
        edit(&mut bytes, &mut bits);
        let cell = build(|s| {
            s.append_raw(&bytes, bits).unwrap();
            for index in 0..status.remaining_references() {
                s.checked_append_reference(status.reference(index).unwrap()).unwrap();
            }
        });
        SliceData::load_cell(cell).unwrap()
    };
    let proposal_with = |fill: &dyn Fn(&mut BuilderData)| {
        let proposal = build(|p| fill(p));
        SliceData::load_cell(build(|s| {
            s.append_u8(0xce).unwrap();
            s.append_u32(1).unwrap();
            s.checked_append_reference(proposal).unwrap();
            s.append_bit_zero().unwrap();
            s.append_bit_zero().unwrap();
            s.append_i64(1).unwrap();
            s.append_raw(&[0u8; 32], 256).unwrap();
            s.append_u8(3).unwrap();
            s.append_u8(0).unwrap();
            s.append_u8(0).unwrap();
        }))
        .unwrap()
    };
    let cases: Vec<(&str, Cell)> = vec![
        ("wrong status tag", data_with(status_bits(&|bytes, _| bytes[0] = 0xcf))),
        ("truncated status", data_with(status_bits(&|_, bits| *bits -= 8))),
        (
            "extra status bits",
            data_with(status_bits(&|bytes, bits| {
                bytes.push(0);
                *bits += 1;
            })),
        ),
        (
            "wrong proposal tag",
            data_with(proposal_with(&|p| {
                p.append_u8(0xf4).unwrap();
                p.append_i32(1).unwrap();
                p.append_bit_zero().unwrap();
                p.append_bit_zero().unwrap();
            })),
        ),
        (
            "extra proposal bits",
            data_with(proposal_with(&|p| {
                p.append_u8(0xf3).unwrap();
                p.append_i32(1).unwrap();
                p.append_bit_zero().unwrap();
                p.append_bit_zero().unwrap();
                p.append_bit_zero().unwrap();
            })),
        ),
        (
            "extra proposal reference",
            data_with(proposal_with(&|p| {
                p.append_u8(0xf3).unwrap();
                p.append_i32(1).unwrap();
                p.append_bit_zero().unwrap();
                p.append_bit_zero().unwrap();
                p.checked_append_reference(Cell::default()).unwrap();
            })),
        ),
        (
            "truncated value hash",
            data_with(proposal_with(&|p| {
                p.append_u8(0xf3).unwrap();
                p.append_i32(1).unwrap();
                p.append_bit_zero().unwrap();
                p.append_bit_one().unwrap();
                p.append_raw(&[0u8; 31], 248).unwrap();
            })),
        ),
        (
            "root without the vote dictionary",
            build(|d| {
                d.checked_append_reference(Cell::default()).unwrap();
            }),
        ),
        (
            "root with extra bits",
            build(|d| {
                d.checked_append_reference(Cell::default()).unwrap();
                d.append_bit_zero().unwrap();
                d.append_bit_zero().unwrap();
            }),
        ),
        (
            "root without parameters",
            build(|d| {
                d.append_bit_zero().unwrap();
            }),
        ),
    ];
    for (case, data) in cases {
        let result = decode(data);
        assert!(result.is_err(), "{case} was accepted");
    }
    let other_code = chain_block::write_boc(&build(|c| {
        c.append_u32(1).unwrap();
    }))
    .unwrap();
    let data = chain_block::write_boc(&data_with(good.status())).unwrap();
    assert!(
        proposal_state::decode_state(&other_code, &data, ProposalRead::List)
            .is_err_and(|e| e.to_string().contains("unsupported code"))
    );
}
