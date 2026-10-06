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
use contracts::{ConfigContractImpl, ConfigContractWrapper, config_contract::ConfigProposal};
use tos_sandbox::{Blockchain, generate_zerostate_state};

mod served;

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

/// The contract's own `list_proposals`, as the node would serve it over JSON-RPC.
fn served_list(chain: &Chain) -> String {
    let result = chain
        .blockchain
        .run_get_method(&chain.config, "list_proposals", vec![])
        .expect("list_proposals runs");
    result.expect_success();
    served::served_response(&result.stack)
}

/// Serves one recorded `runGetMethodStd` response to the configuration wrapper.
struct ServedResponse(String);

#[async_trait::async_trait]
impl contracts::ContractProvider for ServedResponse {
    async fn get_method(
        &self,
        _address: String,
        method: &str,
        _stack: Vec<tl_api::tos::tvm::StackEntry>,
    ) -> anyhow::Result<common::tvm_stack_parser::TvmStackParser> {
        anyhow::ensure!(method == "list_proposals", "unexpected getter {method}");
        Ok(served::read_response(&self.0))
    }

    async fn balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
        Ok(0)
    }
}

/// The served list read by `ConfigContractImpl::list_proposals`, the path every
/// caller (`vote offer ls`, `vote offer cast`, the voting service) goes through.
fn decoded(chain: &Chain) -> Vec<ConfigProposal> {
    let wrapper = ConfigContractImpl::new(std::sync::Arc::new(ServedResponse(served_list(chain))));
    let runtime = tokio::runtime::Builder::new_current_thread().build().expect("a runtime");
    runtime
        .block_on(wrapper.list_proposals())
        .unwrap_or_else(|error| panic!("the served proposal list decodes: {error:#}"))
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
    let response = served_list(&chain);
    assert!(response.contains(
        r#""stack":[{"@type":"tvm.stackEntryList","list":{"@type":"tvm.list","elements":[]}}]"#
    ));
    assert!(decoded(&chain).is_empty());
}

#[test]
fn one_unvoted_proposal_decodes_field_by_field() {
    let mut chain = launch();
    let stored = Stored::unvoted([0x47; 32], 1000);
    register(&mut chain, std::slice::from_ref(&stored));
    let proposals = decoded(&chain);
    assert_eq!(proposals.len(), 1);
    assert_matches(&proposals[0], &stored);
}

/// Three proposals registered out of hash order, one carrying a value, a bound hash,
/// the launch cap's 21 voters and unequal wins and losses. The getter returns them in
/// ascending hash order, whatever order they were stored in.
#[test]
fn several_proposals_one_voted_decode_in_ascending_order() {
    let mut chain = launch();
    let mut high = [0xff; 32];
    high[31] = 0xfe;
    let mut middle = [0u8; 32];
    middle[0] = 0x80;
    let value = build(|v| {
        v.append_u32(0xdead_beef).unwrap();
    });
    let voted = Stored {
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
    };
    let stored = vec![
        Stored::unvoted(high, 31),
        voted.clone(),
        Stored { losses: 1, ..Stored::unvoted(hash_ending(1), 100) },
    ];
    register(&mut chain, &stored);
    let proposals = decoded(&chain);
    assert_eq!(proposals.len(), 3);
    assert_matches(&proposals[0], &stored[2]);
    assert_matches(&proposals[1], &voted);
    assert_matches(&proposals[2], &stored[0]);
}

/// The getter starts its downward walk strictly below 2^256 - 1, so a proposal stored
/// under that hash is never listed. This is the contract's own boundary, recorded so a
/// change to it is noticed; the decoder accepts that hash (see its unit tests).
#[test]
fn the_getter_never_lists_the_maximum_hash() {
    let mut chain = launch();
    let stored = vec![Stored::unvoted(hash_ending(2), 1), Stored::unvoted([0xff; 32], 2)];
    register(&mut chain, &stored);
    let proposals = decoded(&chain);
    assert_eq!(proposals.len(), 1);
    assert_matches(&proposals[0], &stored[0]);
}
