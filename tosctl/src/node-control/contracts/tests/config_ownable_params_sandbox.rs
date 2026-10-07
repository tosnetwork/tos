/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The configuration contract with owner-settable custom parameters
//! (crypto/smartcont/config-with-ownable-params.fc) as real transactions, with a
//! validator key anyone can sign for in the current validator set. A vote signed under
//! such a key is refused before its signature is checked -- before acceptance for an
//! external vote -- so a forger cannot cast that validator's weight; and a proposal to
//! appoint such a key as the configuration master key is refused when registered.

use chain_block::{
    BuilderData, Cell, ConfigParamEnum, HashmapE, HashmapType, IBitstring, MsgAddressInt,
    Serializable, SliceData, StateInit,
};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, compile_func_with_stdlib};
use tos_vm::stack::{StackItem, integer::IntegerData};

mod served;
mod weak_ed25519;

use served::as_served;

const TOS: u64 = 1_000_000_000;
const ERR_WEAK_VALIDATOR_KEY: i32 = 45;
const EXTERNAL_GAS_CREDIT: i64 = 10_000;

const TAG_VOTE: u32 = 0x566f_7465;
const SIGN_TAG_VOTE: u32 = 0x566f_7445;
const TAG_NEW_PROPOSAL: u32 = 0x6e56_5052;
const ANSWER_PROPOSAL_ACCEPTED: u32 = 0xee56_5052;
const ANSWER_BAD_VALUE: u32 = 0xc261_6456;

/// Index 0 of the validator set holds the key under test; index 1 a strong key.
const WEAK_INDEX: u16 = 0;
const STRONG_INDEX: u16 = 1;

fn smartcont(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../crypto/smartcont").join(name)
}

fn source() -> String {
    std::fs::read_to_string(smartcont("config-with-ownable-params.fc")).expect("source")
}

/// Compiles `source` as the contract, next to the weak-key helper it includes.
fn compile(source: &str) -> Cell {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("config-with-ownable-params.fc"), source).expect("write");
    std::fs::copy(smartcont("strong-ed25519-key.fc"), dir.path().join("strong-ed25519-key.fc"))
        .expect("copy helper");
    compile_func_with_stdlib(&[dir.path().join("config-with-ownable-params.fc")]).expect("compile")
}

const VOTE_GUARD: &str = "    require_strong_validator_key(val_pubkey);\n";
const INTERNAL_VOTE_GUARD: &str = "    require_strong_validator_key(val_pubkey);\n    throw_unless(34, check_data_signature(msg_body,";
const EXTERNAL_VOTE_GUARD: &str = "    require_strong_validator_key(val_pubkey);\n    throw_unless(34, check_data_signature(in_msg,";
const MASTER_KEY_GUARD: &str = "      if (weak_ed25519_key?(key_cs.preload_uint(256))) {\n        hash = -0xc2616456;  ;; bad value\n      }\n";

/// The source with the named guards taken out.
fn without(guards: &[&str]) -> String {
    let mut source = source();
    for guard in guards {
        assert_eq!(source.matches(guard).count(), 1, "guard moved: {guard}");
        let replacement = guard.strip_prefix(VOTE_GUARD).unwrap_or("");
        source = source.replace(guard, replacement);
    }
    source
}

fn unguarded_source() -> String {
    let source = without(&[INTERNAL_VOTE_GUARD, EXTERNAL_VOTE_GUARD, MASTER_KEY_GUARD]);
    assert!(!source.contains("    require_strong_validator_key("), "a guard was left in");
    source
}

/// The source with the external vote's acceptance replaced by a throw whose exit code is
/// the gas consumed so far. The probe lifts its own gas limit first, so a path over the
/// external credit still reports its cost (over-estimated by that one instruction).
fn probe_source(source: &str) -> String {
    // The vote's acceptance; the commented-out master-key path repeats the line after.
    let accept = "val_pubkey));\n    accept_message();\n";
    assert_eq!(source.matches(accept).count(), 1);
    let probe = source.replace(accept, "val_pubkey));\n    throw(gas_consumed());\n");
    let entry = "() recv_external(slice in_msg) impure {\n";
    assert_eq!(probe.matches(entry).count(), 1);
    let probe = probe.replace(entry, &format!("{entry}  set_gas_limit(1000000);\n"));
    format!("int gas_consumed() asm \"GASCONSUMED\";\n{probe}")
}

fn cell(build: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    build(&mut b);
    b.into_cell().expect("cell")
}

fn key_slice(bits: &[u8], len: usize) -> SliceData {
    SliceData::load_builder(BuilderData::with_raw(bits.to_vec(), len).unwrap()).unwrap()
}

/// validators_ext#12 with one validator#53 entry per key, weight 1 each.
fn validator_set(keys: &[[u8; 32]], now: u32) -> Cell {
    let mut list = HashmapE::with_bit_len(16);
    for (index, key) in keys.iter().enumerate() {
        let descr = SliceData::load_cell(cell(|d| {
            d.append_u8(0x53).unwrap();
            d.append_u32(0x8e81_278a).unwrap();
            d.append_u256(key).unwrap();
            d.append_u64(1).unwrap();
        }))
        .unwrap();
        list.set(key_slice(&(index as u16).to_be_bytes(), 16), &descr).unwrap();
    }
    cell(|v| {
        v.append_u8(0x12).unwrap();
        v.append_u32(now - 100).unwrap();
        v.append_u32(now + 100_000).unwrap();
        v.append_u16(keys.len() as u16).unwrap();
        v.append_u16(keys.len() as u16).unwrap();
        v.append_u64(keys.len() as u64).unwrap();
        v.append_bit_one().unwrap();
        v.checked_append_reference(list.data().cloned().expect("validators")).unwrap();
    })
}

/// cfg_vote_setup#91 with the same cfg_vote_cfg#36 for normal and critical proposals:
/// stored for 1 s to 10^6 s, at a nominal storage price.
fn voting_setup() -> Cell {
    let setup = || {
        cell(|c| {
            c.append_u8(0x36).unwrap();
            for value in [1u8, 10, 1, 3] {
                c.append_u8(value).unwrap();
            }
            for value in [1u32, 1_000_000, 1, 500] {
                c.append_u32(value).unwrap();
            }
        })
    };
    cell(|v| {
        v.append_u8(0x91).unwrap();
        v.checked_append_reference(setup()).unwrap();
        v.checked_append_reference(setup()).unwrap();
    })
}

/// A pending proposal for param 100, created for `vset` and still short of votes.
fn vote_dict(phash: [u8; 32], vset: &Cell, now: u32) -> Cell {
    let proposal = cell(|p| {
        p.append_u8(0xf3).unwrap();
        p.append_i32(100).unwrap();
        p.append_bit_zero().unwrap();
        p.append_bit_zero().unwrap();
    });
    let status = SliceData::load_cell(cell(|s| {
        s.append_u8(0xce).unwrap();
        s.append_u32(now + 100_000).unwrap();
        s.checked_append_reference(proposal).unwrap();
        s.append_bit_zero().unwrap();
        s.append_bit_zero().unwrap();
        s.append_i64(1 << 40).unwrap();
        s.append_u256(vset.hash(0).as_slice()).unwrap();
        s.append_u8(3).unwrap();
        s.append_u8(0).unwrap();
        s.append_u8(0).unwrap();
    }))
    .unwrap();
    let mut votes = HashmapE::with_bit_len(256);
    votes.set(key_slice(&phash, 256), &status).unwrap();
    votes.data().cloned().expect("one proposal")
}

const PHASH: [u8; 32] = [0x70; 32];

struct Config {
    bc: Blockchain,
    address: MsgAddressInt,
}

impl Config {
    /// Deploys the contract on the masterchain over a validator set whose index 0 is
    /// `validator_key`, with one pending proposal, PHASH.
    fn deploy(code: Cell, validator_key: &[u8; 32], strong: &SigningKey) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let now = bc.now();
        let vset = validator_set(&[*validator_key, strong.verifying_key().to_bytes()], now);
        let mut params = bc.config_params().clone();
        params.set_config(ConfigParamEnum::ConfigParamAny(34, vset.clone())).expect("param 34");
        params.set_config(ConfigParamEnum::ConfigParamAny(11, voting_setup())).expect("param 11");
        // A configuration the sandbox rebuilds needs the fundamental-contract list.
        if params.config(31).expect("param 31").is_none() {
            params
                .set_config(ConfigParamEnum::ConfigParam31(chain_block::ConfigParam31 {
                    fundamental_smc_addr: chain_block::FundamentalSmcAddresses::default(),
                }))
                .expect("the fundamental contracts are listed");
        }
        bc.set_config(params).expect("the chain adopts the validator set");
        let cfg_dict = bc.config_params().config_params.data().cloned().expect("config dict");
        let data = cell(|d| {
            d.checked_append_reference(cfg_dict).unwrap();
            d.append_u32(0).unwrap();
            d.append_u256(&[0; 32]).unwrap();
            d.append_bit_one().unwrap();
            d.checked_append_reference(vote_dict(PHASH, &vset, now)).unwrap();
        });
        let funder = bc.treasury("funder", 1_000 * TOS).expect("funder");
        let init = StateInit::with_code_and_data(code, data);
        let hash = init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let address = MsgAddressInt::with_params(-1, hash).unwrap();
        let deploy = MessageBuilder::internal(funder.address(), &address, 100 * TOS)
            .bounce(false)
            .state_init(init)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, address }
    }

    fn send_external(&mut self, body: Cell) -> Result<SendResult, String> {
        let message = MessageBuilder::external(&self.address)
            .body_slice(SliceData::load_cell(body).unwrap())
            .build();
        self.bc.send_message(message).map_err(|error| error.to_string())
    }

    fn seqno(&self) -> i128 {
        self.bc.run_get_method(&self.address, "seqno", vec![]).expect("seqno").int_at(0)
    }

    fn balance(&self) -> u128 {
        self.bc
            .get_account(&self.address)
            .expect("account")
            .balance()
            .expect("balance")
            .coins
            .as_u128()
    }

    fn data_hash(&self) -> chain_block::UInt256 {
        self.bc.get_account(&self.address).expect("account").get_data().expect("data").hash(0)
    }

    /// Whether validator `index` is recorded as having voted for PHASH.
    fn voted(&self, index: u16) -> bool {
        let phash = StackItem::integer(IntegerData::from_unsigned_bytes_be(PHASH));
        let result = self
            .bc
            .run_get_method(&self.address, "get_proposal", vec![phash])
            .expect("get_proposal");
        result.expect_success();
        let proposal = result.stack.last().expect("proposal").as_tuple().expect("tuple").to_vec();
        let mut voters = proposal[4].clone();
        while !voters.is_null() {
            let pair = voters.as_tuple().expect("cons").to_vec();
            if pair[0] == StackItem::int(i64::from(index)) {
                return true;
            }
            voters = pair[1].clone();
        }
        false
    }

    /// An internal message from a masterchain sender; returns the result and the answer
    /// tag the contract sent back, if any.
    fn send_internal(&mut self, body: Cell) -> (SendResult, Option<u32>) {
        let sender = self.bc.treasury("masterchain-sender", 1_000 * TOS).expect("sender");
        let message =
            MessageBuilder::internal(sender.address(), &self.address, 100 * TOS).body(body).build();
        let result = self.bc.send_message(message).expect("internal");
        let answer = result.transactions_for(sender.address()).into_iter().find_map(|tr| {
            let inbound = tr.read_in_msg().ok()??;
            let mut body = inbound.body()?.clone();
            body.get_next_u32().ok()
        });
        (result, answer)
    }
}

/// action seqno valid_until idx phash: the bytes an external vote's signature covers.
fn external_vote_part(seqno: u32, valid_until: u32, index: u16, phash: [u8; 32]) -> Vec<u8> {
    let mut part = Vec::with_capacity(46);
    part.extend(TAG_VOTE.to_be_bytes());
    part.extend(seqno.to_be_bytes());
    part.extend(valid_until.to_be_bytes());
    part.extend(index.to_be_bytes());
    part.extend(phash);
    part
}

fn with_signature(signature: [u8; 64], part: &[u8]) -> Cell {
    cell(|m| {
        m.append_raw(&signature, 512).unwrap();
        m.append_raw(part, part.len() * 8).unwrap();
    })
}

/// An external vote for PHASH carrying a signature forged for `key`, found by trying
/// valid_until values.
fn forged_external_vote(config: &Config, key: &[u8; 32], seqno: u32) -> Cell {
    let now = config.bc.now();
    (0..4_096u32)
        .find_map(|offset| {
            let part = external_vote_part(seqno, now + 3_600 + offset, WEAK_INDEX, PHASH);
            weak_ed25519::forge(key, &part).map(|forged| with_signature(forged, &part))
        })
        .expect("a forgeable external vote")
}

/// sign_tag idx phash: the bytes an internal vote's signature covers.
fn internal_vote_part(index: u16, phash: [u8; 32]) -> Vec<u8> {
    let mut part = Vec::with_capacity(38);
    part.extend(SIGN_TAG_VOTE.to_be_bytes());
    part.extend(index.to_be_bytes());
    part.extend(phash);
    part
}

fn internal_vote(query_id: u64, signature: [u8; 64], part: &[u8]) -> Cell {
    cell(|m| {
        m.append_u32(TAG_VOTE).unwrap();
        m.append_u64(query_id).unwrap();
        m.append_raw(&signature, 512).unwrap();
        m.append_raw(part, part.len() * 8).unwrap();
    })
}

/// An internal vote for PHASH (or a nearby hash, when PHASH itself admits no forgery)
/// forged for `key`; the vote counts only when it names PHASH.
fn forged_internal_vote(key: &[u8; 32]) -> Option<Cell> {
    let part = internal_vote_part(WEAK_INDEX, PHASH);
    weak_ed25519::forge(key, &part).map(|forged| internal_vote(1, forged, &part))
}

fn strong_validator() -> SigningKey {
    SigningKey::from_bytes(&[0x5a; 32])
}

/// Every weak key a vote for PHASH can be forged for, internally or externally.
fn forgeable_weak_keys() -> Vec<[u8; 32]> {
    let keys: Vec<[u8; 32]> = weak_ed25519::weak_keys()
        .into_iter()
        .filter(|key| {
            (0..64u32).any(|offset| {
                weak_ed25519::forge(key, &external_vote_part(0, 1 << 20 | offset, 0, PHASH))
                    .is_some()
            })
        })
        .collect();
    let aliases = weak_ed25519::sign_bit_aliases();
    assert!(keys.contains(&aliases[0]) && keys.contains(&aliases[1]), "aliases not forgeable");
    assert!(keys.len() >= 10, "only {} forgeable weak keys", keys.len());
    keys
}

/// Without the guards, a forged vote under a weak validator key is accepted and counted
/// as that validator's vote, over an external and over an internal message.
#[test]
fn without_the_guards_a_forged_vote_is_counted() {
    let code = compile(&unguarded_source());
    for weak in weak_ed25519::sign_bit_aliases() {
        let mut config = Config::deploy(code.clone(), &weak, &strong_validator());
        let vote = forged_external_vote(&config, &weak, 0);
        config.send_external(vote).expect("the unguarded contract accepts").expect_success();
        assert_eq!(config.seqno(), 1);
        assert!(config.voted(WEAK_INDEX), "the forged external vote was not counted");
    }
    // The identity alias forges for every message, so the internal vote needs no search.
    let weak = weak_ed25519::sign_bit_aliases()[0];
    let mut config = Config::deploy(code, &weak, &strong_validator());
    let vote = forged_internal_vote(&weak).expect("the identity alias forges for anything");
    let (result, answer) = config.send_internal(vote);
    result.expect_success();
    assert_eq!(answer, Some(0xd674_5242), "the forged internal vote was registered (status 2)");
    assert!(config.voted(WEAK_INDEX));
}

/// Every forgeable weak key as a current validator's key: forged external votes are
/// refused with exit 45 before acceptance -- no transaction, no fee, no state change --
/// three times each; a forged internal vote fails with exit 45 and counts nothing.
#[test]
fn forged_votes_under_a_weak_validator_key_are_refused() {
    let code = compile(&source());
    let mut internal_refusals = 0;
    for weak in forgeable_weak_keys() {
        let mut config = Config::deploy(code.clone(), &weak, &strong_validator());
        let balance = config.balance();
        let data = config.data_hash();
        for _ in 0..3 {
            let vote = forged_external_vote(&config, &weak, 0);
            let error = match config.send_external(vote) {
                Ok(_) => panic!("{}: accepted", hex::encode(weak)),
                Err(error) => error,
            };
            assert!(
                error.contains(&format!("exit code: {ERR_WEAK_VALIDATOR_KEY}")),
                "{}: {error}",
                hex::encode(weak)
            );
        }
        assert_eq!(config.balance(), balance, "a refused external vote cost the contract");
        assert_eq!(config.data_hash(), data, "a refused external vote changed state");
        if let Some(vote) = forged_internal_vote(&weak) {
            let (result, answer) = config.send_internal(vote);
            result.expect_exit_code(ERR_WEAK_VALIDATOR_KEY);
            assert_eq!(answer, None, "{}: answered a refused vote", hex::encode(weak));
            assert_eq!(config.data_hash(), data, "a refused internal vote changed state");
            internal_refusals += 1;
        }
        assert!(!config.voted(WEAK_INDEX));
    }
    assert!(internal_refusals >= 2, "only {internal_refusals} internal forgeries tried");
}

/// The strong validator's votes still count, over both message kinds, including a key
/// whose first byte sends it through the full check.
#[test]
fn strong_validators_still_vote() {
    let code = compile(&source());
    for first in [0x00u8, 0x01, 0x26, 0xc7, 0xec, 0xff, 0x42] {
        let strong = strong_key_starting_with(first, 0x61);
        let weak = weak_ed25519::sign_bit_aliases()[1];
        let mut config = Config::deploy(code.clone(), &weak, &strong);
        let part = external_vote_part(0, config.bc.now() + 3_600, STRONG_INDEX, PHASH);
        let vote = with_signature(strong.sign(&part).to_bytes(), &part);
        config.send_external(vote).expect("strong external vote").expect_success();
        assert!(config.voted(STRONG_INDEX), "first byte {first:#04x}");

        let mut config = Config::deploy(code.clone(), &weak, &strong);
        let part = internal_vote_part(STRONG_INDEX, PHASH);
        let (result, answer) =
            config.send_internal(internal_vote(7, strong.sign(&part).to_bytes(), &part));
        result.expect_success();
        assert_eq!(answer, Some(0xd674_5242));
        assert!(config.voted(STRONG_INDEX));
    }
}

/// A new-proposal message appointing `key` as the configuration master key.
fn master_key_proposal(key: &[u8; 32]) -> Cell {
    let proposal = cell(|p| {
        p.append_u8(0xf3).unwrap();
        p.append_i32(-999).unwrap();
        p.append_bit_one().unwrap();
        p.checked_append_reference(cell(|v| {
            v.append_u256(key).unwrap();
        }))
        .unwrap();
        p.append_bit_zero().unwrap();
    });
    cell(|m| {
        m.append_u32(TAG_NEW_PROPOSAL).unwrap();
        m.append_u64(5).unwrap();
        m.append_u32(86_400).unwrap();
        m.checked_append_reference(proposal).unwrap();
        m.append_bit_one().unwrap();
    })
}

/// A proposal to appoint a weak master key is answered "bad value" and not stored, for
/// every weak encoding; a strong key's proposal is registered.
#[test]
fn a_weak_master_key_is_never_proposed() {
    let code = compile(&source());
    let mut config =
        Config::deploy(code, &strong_validator().verifying_key().to_bytes(), &strong_validator());
    let data = config.data_hash();
    for weak in weak_ed25519::weak_keys() {
        let (result, answer) = config.send_internal(master_key_proposal(&weak));
        result.expect_success();
        assert_eq!(answer, Some(ANSWER_BAD_VALUE), "{}", hex::encode(weak));
        assert_eq!(config.data_hash(), data, "a refused proposal was stored");
    }
    for first in [0x00u8, 0x01, 0xec, 0x42] {
        let key = strong_key_starting_with(first, 0x71).verifying_key().to_bytes();
        let (result, answer) = config.send_internal(master_key_proposal(&key));
        result.expect_success();
        assert_eq!(answer, Some(ANSWER_PROPOSAL_ACCEPTED), "first byte {first:#04x}");
    }
}

/// Each guard on its own is what refuses.
#[test]
fn each_guard_is_load_bearing() {
    let weak = weak_ed25519::sign_bit_aliases()[0];

    let mut config =
        Config::deploy(compile(&without(&[EXTERNAL_VOTE_GUARD])), &weak, &strong_validator());
    let vote = forged_external_vote(&config, &weak, 0);
    config.send_external(vote).expect("external guard removed").expect_success();

    let mut config =
        Config::deploy(compile(&without(&[INTERNAL_VOTE_GUARD])), &weak, &strong_validator());
    let (result, _) = config.send_internal(forged_internal_vote(&weak).expect("forgery"));
    result.expect_success();
    assert!(config.voted(WEAK_INDEX));

    let mut config = Config::deploy(
        compile(&without(&[MASTER_KEY_GUARD])),
        &strong_validator().verifying_key().to_bytes(),
        &strong_validator(),
    );
    let (_, answer) = config.send_internal(master_key_proposal(&weak));
    assert_eq!(answer, Some(ANSWER_PROPOSAL_ACCEPTED), "master-key guard removed");
}

/// A signing key whose public key starts with `first`.
fn strong_key_starting_with(first: u8, salt: u8) -> SigningKey {
    (0u32..)
        .map(|n| {
            let mut seed = [salt; 32];
            seed[..4].copy_from_slice(&n.to_le_bytes());
            SigningKey::from_bytes(&seed)
        })
        .find(|key| key.verifying_key().to_bytes()[0] == first)
        .expect("a key with that first byte")
}

/// Pre-acceptance gas of an external vote under a validator key whose first byte
/// enters the full check, against the same build without the guards.
#[test]
fn the_guard_fits_the_external_gas_credit() {
    let guarded = compile(&probe_source(&source()));
    let unguarded = compile(&probe_source(&unguarded_source()));
    let mut worst = 0i64;
    let mut worst_overhead = 0i64;
    for first in [0x00u8, 0x01, 0x26, 0xc7, 0xec, 0xff, 0x42] {
        let validator = strong_key_starting_with(first, 0x81);
        let gas = |code: &Cell| {
            let mut config = Config::deploy(code.clone(), &[0x99; 32], &validator);
            let part = external_vote_part(0, config.bc.now() + 3_600, STRONG_INDEX, PHASH);
            let vote = with_signature(validator.sign(&part).to_bytes(), &part);
            let result = config.send_external(vote).expect("the probe pays for itself");
            match result.read_primary_description().compute_ph {
                chain_block::TrComputePhase::Vm(vm) => i64::from(vm.exit_code),
                chain_block::TrComputePhase::Skipped(skipped) => {
                    panic!("compute skipped: {:?}", skipped.reason)
                }
            }
        };
        let (with, without) = (gas(&guarded), gas(&unguarded));
        eprintln!("first byte {first:#04x}: {without} -> {with} gas before acceptance");
        worst = worst.max(with);
        worst_overhead = worst_overhead.max(with - without);
    }
    eprintln!("worst {worst}, worst guard overhead {worst_overhead}");
    assert!(worst_overhead <= 1_050, "the guard adds {worst_overhead} gas");
    assert!(worst * 10 <= EXTERNAL_GAS_CREDIT * 9, "{worst} leaves under 10% of the credit");
}

/// The configuration contract's own `get_proposal`, rendered as the node serves it
/// and read back by the decoders `tosctl` uses.
fn served_proposal(config: &Config, phash: [u8; 32]) -> common::tvm_stack_parser::TvmStackParser {
    let key = StackItem::integer(IntegerData::from_unsigned_bytes_be(phash));
    let result = config.bc.run_get_method(&config.address, "get_proposal", vec![key]).expect("run");
    result.expect_success();
    // The node serializes the stack top first; the provider reverses it.
    let served: Vec<serde_json::Value> = result.stack.iter().rev().map(as_served).collect();
    let entries: Vec<chain_rpc_client::v2::stack::RPCStackEntry> =
        serde_json::from_value(serde_json::Value::Array(served)).expect("served entries");
    contracts::chain_provider::stack_from_rpc(entries)
}

#[test]
fn the_real_get_proposal_decodes_absent_unvoted_and_voted() {
    use contracts::config_contract::{decode_proposal, decode_proposal_expiry};
    let strong = strong_validator();
    let weak = weak_ed25519::sign_bit_aliases()[1];
    let mut config = Config::deploy(compile(&source()), &weak, &strong);
    let expires = config.bc.now() + 100_000;

    let absent = served_proposal(&config, [0x71; 32]);
    assert_eq!(decode_proposal_expiry(&absent).expect("absent"), None);
    assert!(decode_proposal([0x71; 32], &absent).expect("absent").is_none());

    let unvoted = served_proposal(&config, PHASH);
    assert_eq!(decode_proposal_expiry(&unvoted).expect("present"), Some(expires));
    let proposal = decode_proposal(PHASH, &unvoted).expect("present").expect("a proposal");
    assert_eq!(proposal.expires, expires);
    assert_eq!(proposal.param.id, 100);
    assert!(proposal.voters.is_empty());

    let part = internal_vote_part(STRONG_INDEX, PHASH);
    let (result, _) = config.send_internal(internal_vote(7, strong.sign(&part).to_bytes(), &part));
    result.expect_success();
    let voted = served_proposal(&config, PHASH);
    assert_eq!(decode_proposal_expiry(&voted).expect("voted"), Some(expires));
    let proposal = decode_proposal(PHASH, &voted).expect("voted").expect("a proposal");
    assert_eq!(proposal.voters, vec![STRONG_INDEX]);
}
