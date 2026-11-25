/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The bridge oracle multisigs (coin bridge, both networks, and token bridge).
//!
//! What a quorum may make them send: only a bounceable vote, in send mode 0
//! to 3, of at most MAX_VOTE_VALUE and with no StateInit, to a masterchain
//! bridge listed in the multisig's own StateInit. Each guard has its own exit
//! code and its own test below, which a quorum query violating exactly that
//! guard turns red when the guard is removed (scripts/coin-bridge-mutations.py
//! and scripts/token-bridge-mutations.py remove each one).
//!
//! The owner keys: create_init_state will not build an owner set that holds a
//! key anyone can sign for, and check_query_signatures will not count a stored
//! one as root. The signature-counting paths of a live query are driven by
//! crosschain/*/tvm/tests/weak-owner-key.js.
//!
//! The coin bridge end to end: a migration voted to the old bridge, which the
//! configuration no longer names, completes the 0xf00d loop, and a reward
//! sweep pays the address the vote names, never the multisig.

use std::path::{Path, PathBuf};

use base64::Engine;
use chain_block::{
    BuilderData, Cell, ConfigParamEnum, Deserializable, IBitstring, Message, MsgAddressInt,
    Serializable, SliceData, StateInit, TrComputePhase, Transaction, TransactionDescr,
};
use tos_sandbox::{Blockchain, GetMethodResult, MessageBuilder, Treasury, compile_func};
use tos_vm::stack::StackItem;

#[path = "fixtures/current_network.rs"]
mod current_network;
#[path = "bridge_multisig/query.rs"]
mod query;
mod weak_ed25519;

use query::*;

const ERR_WEAK_OWNER: i32 = 45;
const BRIDGE_A: [u8; 32] = [0xa1; 32];
const BRIDGE_B: [u8; 32] = [0xb2; 32];

fn chain() -> Blockchain {
    Blockchain::with_global_version_and_base_workchain(current_network::global_version())
        .expect("a chain")
}

fn code_of(variant: &Variant) -> Cell {
    compile_func(&variant.sources).unwrap_or_else(|e| panic!("{}: compile: {e}", variant.name))
}

/// Whether the transaction aborted, and the exit code of its compute phase.
fn outcome(tx: &Transaction) -> (bool, Option<i32>) {
    match tx.read_description().expect("a description") {
        TransactionDescr::Ordinary(d) => match &d.compute_ph {
            TrComputePhase::Vm(vm) => (d.aborted, Some(vm.exit_code)),
            TrComputePhase::Skipped(_) => (d.aborted, None),
        },
        other => panic!("not an ordinary transaction: {other:?}"),
    }
}

fn succeeded(tx: &Transaction, what: &str) {
    let (aborted, exit) = outcome(tx);
    assert!(!aborted, "{what}: the transaction failed with exit code {exit:?}");
}

/// A deployed multisig on the masterchain, and a relayer that delivers its
/// queries the way anyone may: by an internal message.
struct Multisig {
    bc: Blockchain,
    address: MsgAddressInt,
    relayer: Treasury,
    keys: [ed25519_dalek::SigningKey; 2],
    next_query: u32,
}

impl Multisig {
    fn deploy_in(
        mut bc: Blockchain,
        code: &Cell,
        owners: &[[u8; 32]],
        allowed: &[[u8; 32]],
    ) -> Self {
        let init = state_init(code, owners, 2, allowed);
        let address = address_of(&init, -1);
        let funder = bc.treasury("multisig-funder", 100_000 * TOS).expect("funder");
        let deploy = MessageBuilder::internal(funder.address(), &address, 1_000 * TOS)
            .bounce(false)
            .state_init(init)
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        let relayer = bc.treasury("multisig-relayer", 1_000 * TOS).expect("relayer");
        Multisig { bc, address, relayer, keys: owner_keys(), next_query: 1 }
    }

    /// The test multisig: both test keys own it, k = 2, and it may vote to
    /// BRIDGE_A and BRIDGE_B.
    fn for_guards(variant: &Variant) -> Self {
        let owners = public_keys(&owner_keys());
        Self::deploy_in(chain(), &code_of(variant), &owners, &[BRIDGE_A, BRIDGE_B])
    }

    fn query(&mut self, mode: u8, vote: &Vote) -> (u64, Message) {
        let id = query_id(self.bc.now(), self.next_query);
        self.next_query += 1;
        let body = quorum_query(&self.keys, id, mode, vote.cell());
        let relay = MessageBuilder::internal(self.relayer.address(), &self.address, TOS)
            .bounce(true)
            .body(body)
            .build();
        (id, relay)
    }

    /// Delivers a quorum query and returns the multisig's own transaction and
    /// what it sends, undelivered.
    fn propose(&mut self, mode: u8, vote: &Vote) -> (u64, Transaction, Vec<Message>) {
        let (id, relay) = self.query(mode, vote);
        let (_, tx, outs) = self.bc.execute_one(relay).expect("the executor runs");
        (id, tx, outs)
    }

    fn data_hash(&self) -> Option<chain_block::UInt256> {
        self.bc.get_account(&self.address).and_then(|a| a.get_data_hash())
    }

    fn get(&self, method: &str, args: Vec<StackItem>) -> GetMethodResult {
        self.bc.run_get_method(&self.address, method, args).expect("the get-method runs")
    }
}

/// A quorum query that violates one guard is refused with that guard's exit
/// code, before anything is recorded or sent.
fn assert_refused(variant: &Variant, mode: u8, vote: &Vote, code: i32, what: &str) {
    assert_refused_with(variant, mode, vote, &[code], what);
}

/// The same, for a message the VM itself may refuse to parse before the
/// guard is reached: any of `codes`.
fn assert_refused_with(variant: &Variant, mode: u8, vote: &Vote, codes: &[i32], what: &str) {
    let mut multisig = Multisig::for_guards(variant);
    let before = multisig.data_hash();
    let (id, tx, outs) = multisig.propose(mode, vote);
    let (aborted, exit) = outcome(&tx);
    let expected: Vec<String> = codes.iter().map(i32::to_string).collect();
    assert!(
        aborted && exit.is_some_and(|e| codes.contains(&e)),
        "{}: {what}: expected exit code {}, got {exit:?}",
        variant.name,
        expected.join(" or ")
    );
    assert_eq!(multisig.data_hash(), before, "{}: {what}: the query was recorded", variant.name);
    assert!(
        outs.iter().all(|m| m.dst_ref() == Some(multisig.relayer.address())),
        "{}: {what}: something other than the bounce left the multisig",
        variant.name
    );
    let state = multisig.get("processed?", vec![StackItem::int(id as i64)]);
    assert_eq!(state.int_at(0), 0, "{}: {what}: the query is not processed", variant.name);
}

fn max_vote_value(variant: &Variant) -> u64 {
    u64::try_from(variant.declared("MAX_VOTE_VALUE")).expect("MAX_VOTE_VALUE fits in u64")
}

// ---------------------------------------------------------------------------
// One test per guard
// ---------------------------------------------------------------------------

#[test]
fn guard_destination_outside_the_allowlist_is_refused() {
    for variant in variants() {
        let vote = Vote::to(&basechain(BRIDGE_A));
        assert_refused(&variant, 1, &vote, ERR_DESTINATION, "a listed hash on the basechain");
        let vote = Vote::to(&masterchain([0xc3; 32]));
        assert_refused(&variant, 1, &vote, ERR_DESTINATION, "an unlisted bridge");
        // A listed hash on the masterchain, spelled any way but addr_std
        // without anycast.
        let vote = Vote::raw_destination(|b| {
            b.append_bits(0b10, 2).unwrap(); // addr_std
            b.append_bit_one().unwrap(); // anycast
            b.append_bits(1, 5).unwrap(); // depth 1
            b.append_bit_one().unwrap(); // rewrite_pfx
            b.append_bits(0xff, 8).unwrap(); // workchain -1
            b.append_raw(&BRIDGE_A, 256).unwrap();
        });
        // At the current global version the VM itself refuses anycast and
        // addr_var addresses in LDMSGADDR (exit code 9); a version that
        // parsed them would meet the guard instead.
        let codes = [ERR_DESTINATION, 9];
        assert_refused_with(&variant, 1, &vote, &codes, "an anycast address");
        let vote = Vote::raw_destination(|b| {
            b.append_bits(0b11, 2).unwrap(); // addr_var
            b.append_bit_zero().unwrap(); // no anycast
            b.append_bits(256, 9).unwrap(); // addr_len
            b.append_i32(-1).unwrap();
            b.append_raw(&BRIDGE_A, 256).unwrap();
        });
        assert_refused_with(&variant, 1, &vote, &codes, "an addr_var address");
        // Exactly as long as addr_std on the masterchain, so only its kind differs.
        let vote = Vote::raw_destination(|b| {
            b.append_bits(0b11, 2).unwrap(); // addr_var
            b.append_bit_zero().unwrap(); // no anycast
            b.append_bits(223, 9).unwrap(); // addr_len
            b.append_i32(-1).unwrap();
            b.append_raw(&BRIDGE_A, 223).unwrap();
        });
        let what = "an addr_var of addr_std's length";
        assert_refused_with(&variant, 1, &vote, &codes, what);
    }
}

#[test]
fn guard_non_bounceable_vote_is_refused() {
    for variant in variants() {
        let vote = Vote { bounce: false, ..Vote::to(&masterchain(BRIDGE_A)) };
        assert_refused(&variant, 1, &vote, ERR_NOT_BOUNCEABLE, "a non-bounceable vote");
        let vote = Vote { bounced: true, ..Vote::to(&masterchain(BRIDGE_A)) };
        assert_refused(&variant, 1, &vote, ERR_NOT_BOUNCEABLE, "a message marked bounced");
        // ext_out_msg_info$11 with a standard source: its first four bits
        // carry a set third bit, where an internal message's bounce flag is.
        let src = masterchain(BRIDGE_A);
        let raw = cell(|b| {
            b.append_bits(0b11, 2).unwrap(); // ext_out_msg_info
            src.write_to(b).unwrap();
            b.append_bits(0, 2).unwrap(); // dest: addr_none
            b.append_u64(0).unwrap();
            b.append_u32(0).unwrap();
            b.append_bit_zero().unwrap(); // no StateInit
            b.append_bit_zero().unwrap(); // body in place, empty
        });
        let vote = Vote { raw: Some(raw), ..Vote::to(&src) };
        assert_refused(&variant, 1, &vote, ERR_NOT_BOUNCEABLE, "an external message");
    }
}

#[test]
fn guard_send_mode_above_three_is_refused() {
    for variant in variants() {
        let vote = Vote::to(&masterchain(BRIDGE_A));
        for mode in [4, 16, 32, 64, 128, 128 + 32, 64 + 1, 16 + 1] {
            assert_refused(&variant, mode, &vote, ERR_SEND_MODE, &format!("send mode {mode}"));
        }
    }
}

#[test]
fn guard_value_above_max_vote_value_is_refused() {
    for variant in variants() {
        let max = max_vote_value(&variant);
        let vote = Vote { value: max + 1, ..Vote::to(&masterchain(BRIDGE_A)) };
        assert_refused(&variant, 1, &vote, ERR_VALUE, "MAX_VOTE_VALUE + 1");
        let vote = Vote { extra_currency: true, ..Vote::to(&masterchain(BRIDGE_A)) };
        assert_refused(&variant, 1, &vote, ERR_VALUE, "an extra currency");
    }
}

#[test]
fn guard_state_init_is_refused() {
    for variant in variants() {
        let code = BuilderData::new().into_cell().expect("a cell");
        let init = StateInit::with_code_and_data(code, Cell::default());
        let vote = Vote { state_init: Some(init), ..Vote::to(&masterchain(BRIDGE_A)) };
        assert_refused(&variant, 1, &vote, ERR_STATE_INIT, "a vote carrying a StateInit");
    }
}

// ---------------------------------------------------------------------------
// What the guards admit
// ---------------------------------------------------------------------------

/// Every allowlisted bridge, every admitted send mode, at the largest admitted
/// value: the query executes and sends exactly one bounceable vote to the
/// bridge, besides the relayer's change.
#[test]
fn an_allowlisted_bounceable_vote_executes_with_one_message_to_the_bridge() {
    for variant in variants() {
        let name = variant.name;
        let max = max_vote_value(&variant);
        let mut multisig = Multisig::for_guards(&variant);
        for bridge in [BRIDGE_A, BRIDGE_B] {
            for mode in 0..4u8 {
                let dest = masterchain(bridge);
                let vote = Vote { value: max, ..Vote::to(&dest) };
                let (id, tx, outs) = multisig.propose(mode, &vote);
                succeeded(&tx, &format!("{name}: mode {mode}"));
                let votes: Vec<&Message> =
                    outs.iter().filter(|m| m.dst_ref() == Some(&dest)).collect();
                assert_eq!(votes.len(), 1, "{name}: mode {mode}: one vote to the bridge");
                assert_eq!(outs.len(), 2, "{name}: the vote and the relayer's change");
                let header = votes[0].int_header().expect("an internal vote");
                assert!(header.bounce, "{name}: the vote is bounceable");
                assert!(votes[0].state_init().is_none(), "{name}: no StateInit");
                let value = header.value.coins.as_u128();
                if mode & 1 == 1 {
                    assert_eq!(value, u128::from(max), "{name}: mode {mode} carries the value");
                } else {
                    assert!(value > 0 && value < u128::from(max), "{name}: mode {mode}: {value}");
                }
                let state = multisig.get("processed?", vec![StackItem::int(id as i64)]);
                assert_eq!(state.int_at(0), -1, "{name}: the query is processed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The initial data
// ---------------------------------------------------------------------------

fn create_init_state(
    multisig: &Multisig,
    owners: &[[u8; 32]],
    allowed: Option<Cell>,
) -> GetMethodResult {
    multisig.get(
        "create_init_state",
        vec![
            StackItem::int(i64::from(WALLET_ID)),
            StackItem::int(owners.len() as i64),
            StackItem::int(2),
            StackItem::cell(owner_dict(owners)),
            allowed.map(StackItem::cell).unwrap_or(StackItem::None),
        ],
    )
}

#[test]
fn create_init_state_refuses_every_weak_owner_key() {
    let strong = public_keys(&owner_keys());
    let allowed = allowlist(&[BRIDGE_A]);
    for variant in variants() {
        let multisig = Multisig::for_guards(&variant);
        let build =
            |owners: &[[u8; 32]]| create_init_state(&multisig, owners, allowed.clone()).exit_code;
        assert_eq!(build(&strong), 0, "{}: strong owners build", variant.name);
        for (i, weak) in weak_ed25519::weak_keys().into_iter().enumerate() {
            assert_eq!(
                build(&[strong[0], strong[1], weak]),
                ERR_WEAK_OWNER,
                "{}: weak key {i} accepted into an owner set",
                variant.name
            );
        }
    }
}

/// The allowlist is the one the initial data was built with, lock_until is 0,
/// and an empty allowlist builds nothing.
#[test]
fn create_init_state_fixes_the_allowlist_and_refuses_an_empty_one() {
    let owners = public_keys(&owner_keys());
    for variant in variants() {
        let name = variant.name;
        let multisig = Multisig::for_guards(&variant);
        let built = create_init_state(&multisig, &owners, allowlist(&[BRIDGE_A, BRIDGE_B]));
        built.expect_success();
        assert_eq!(
            built.cell_at(0).repr_hash(),
            wallet_data(&owners, 2, &[BRIDGE_A, BRIDGE_B]).repr_hash(),
            "{name}: the initial data"
        );
        assert_eq!(
            create_init_state(&multisig, &owners, None).exit_code,
            ERR_EMPTY_ALLOWLIST,
            "{name}: an empty allowlist"
        );
        let listed = multisig.get("get_allowed_bridges", vec![]);
        listed.expect_success();
        assert_eq!(
            Some(listed.cell_at(0).repr_hash()),
            allowlist(&[BRIDGE_A, BRIDGE_B]).map(|c| c.repr_hash()),
            "{name}: get_allowed_bridges"
        );
        assert_eq!(multisig.get("get_lock_timeout", vec![]).int_at(0), 0, "{name}");
    }
}

/// What the deployment check in SECURITY.md is for. A hand-built StateInit
/// can start with a pending query that never passed check_proposed_query: a
/// mode-128 transfer anywhere, already approved by k - 1 owners. One more
/// approval executes it, and get_allowed_bridges still shows the honest
/// list. The address gives it away, since it is not the one
/// create_init_state (and new-multisig.fif) compute for the same owners and
/// bridges, and get_messages_unsigned shows the pending query.
#[test]
fn a_preseeded_pending_query_is_caught_by_the_deployment_check() {
    let keys = owner_keys();
    let owners = public_keys(&keys);
    let thief = masterchain([0xdd; 32]);
    for variant in variants() {
        let name = variant.name;
        let code = code_of(&variant);
        let mut bc = chain();
        let id = query_id(bc.now(), 99);
        let theft = Vote { bounce: false, ..Vote::to(&thief) }.cell();
        let mut pending = chain_block::HashmapE::with_bit_len(64);
        let key =
            SliceData::load_builder(BuilderData::with_raw(id.to_be_bytes().to_vec(), 64).unwrap())
                .unwrap();
        let entry = cell(|b| {
            b.append_bit_one().unwrap(); // not yet executed
            b.append_u8(0).unwrap(); // created by owner 0
            b.append_u8(1).unwrap(); // one approval: k - 1
            b.append_bits(0b01, 2).unwrap(); // owner 0's bit, n = 2
            b.append_u8(128).unwrap(); // the whole balance
            b.checked_append_reference(theft.clone()).unwrap();
        });
        pending.set(key, &SliceData::load_cell(entry).unwrap()).unwrap();
        let pending = chain_block::HashmapType::data(&pending).cloned();
        // Owner 0 is counted as the creator of one pending query, as the
        // contract itself would have counted it.
        let owner_set = owner_dict_with_floods(&owners, &[1, 0]);
        let data = wallet_data_with_pending(&owner_set, 2, 2, &[BRIDGE_A], pending);
        let rigged = StateInit::with_code_and_data(code.clone(), data);
        let address = address_of(&rigged, -1);
        let funder = bc.treasury("rigged-funder", 10_000 * TOS).expect("funder");
        let deploy = MessageBuilder::internal(funder.address(), &address, 1_000 * TOS)
            .bounce(false)
            .state_init(rigged)
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        let relayer = bc.treasury("rigged-relayer", 1_000 * TOS).expect("relayer");
        let multisig = Multisig { bc, address, relayer, keys: owner_keys(), next_query: 1 };

        // What the check compares.
        let honest = address_of(&state_init(&code, &owners, 2, &[BRIDGE_A]), -1);
        assert_ne!(multisig.address, honest, "{name}: the rigged StateInit has another address");
        let listed = multisig.get("get_allowed_bridges", vec![]);
        assert_eq!(
            Some(listed.cell_at(0).repr_hash()),
            allowlist(&[BRIDGE_A]).map(|c| c.repr_hash()),
            "{name}: the allowlist alone looks honest"
        );
        let unsigned = multisig.get("get_messages_unsigned", vec![]);
        unsigned.expect_success();
        assert!(
            !matches!(unsigned.stack.first(), Some(StackItem::None) | None),
            "{name}: get_messages_unsigned shows the pending query"
        );

        // Why it matters: one approval sends the planted message.
        let mut multisig = multisig;
        let body = root_query(&keys[1], 1, id, 128, theft);
        let relay = MessageBuilder::internal(multisig.relayer.address(), &multisig.address, TOS)
            .bounce(true)
            .body(body)
            .build();
        let (_, tx, outs) = multisig.bc.execute_one(relay).expect("the executor runs");
        succeeded(&tx, &format!("{name}: the planted query executes"));
        assert!(outs.iter().any(|m| m.dst_ref() == Some(&thief)), "{name}: and pays out");
    }
}

/// The cell a root signs in a query with no co-signatures; only its hash matters here.
fn signed_root(root: u8) -> Cell {
    cell(|b| {
        b.append_u8(root).unwrap();
        b.append_bit_zero().unwrap();
        b.append_u32(WALLET_ID).unwrap();
        b.append_u64(7).unwrap();
    })
}

fn signed_query(signature: [u8; 64], signed: &Cell) -> Cell {
    let rest = SliceData::load_cell(signed.clone()).unwrap();
    cell(|b| {
        b.append_raw(&signature, 512).unwrap();
        b.append_builder(&rest.as_builder().unwrap()).unwrap();
    })
}

#[test]
fn check_query_signatures_refuses_a_forged_weak_root() {
    use ed25519_dalek::Signer;
    let keys = owner_keys();
    let [identity_alias, order2_alias] = weak_ed25519::sign_bit_aliases();
    let owners = [
        keys[0].verifying_key().to_bytes(),
        keys[1].verifying_key().to_bytes(),
        identity_alias,
        order2_alias,
    ];
    for variant in variants() {
        // A hand-built StateInit, as anyone can deploy: create_init_state refuses these owners.
        let multisig = Multisig::deploy_in(chain(), &code_of(&variant), &owners, &[BRIDGE_A]);
        let check =
            |body: Cell| multisig.get("check_query_signatures", vec![StackItem::cell(body)]);
        let signed = signed_root(2);
        let forged = weak_ed25519::forge(&identity_alias, signed.hash(0).as_slice())
            .expect("the identity alias admits a forgery for every message");
        let refused = check(signed_query(forged, &signed));
        assert_eq!(refused.exit_code, ERR_WEAK_OWNER, "{}", variant.name);

        let signed = signed_root(0);
        let signature = keys[0].sign(signed.hash(0).as_slice()).to_bytes();
        let result = check(signed_query(signature, &signed));
        result.expect_success();
        assert_eq!(result.int_at(0), 1, "{}: one valid signature", variant.name);
    }
}

// ---------------------------------------------------------------------------
// new-multisig.fif
// ---------------------------------------------------------------------------

/// A toolchain binary: the environment's override, else this checkout's build.
fn tool(env: &str, name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(env) {
        return PathBuf::from(path);
    }
    let local = repo_root().join("build/crypto").join(name);
    if local.exists() {
        return local;
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).expect("HOME or a tool override");
    home.join("tos/build/crypto").join(name)
}

/// CRC-16/XMODEM, the checksum Fift's `parse-pubkey` expects.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for byte in data {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// A public key as the scripts read it: tag 0x3ee6, the key and its CRC-16.
fn pubkey_text(key: &[u8; 32]) -> String {
    let mut bytes = vec![0x3e, 0xe6];
    bytes.extend_from_slice(key);
    let crc = crc16(&bytes);
    bytes.extend_from_slice(&crc.to_be_bytes());
    base64::engine::general_purpose::URL_SAFE.encode(bytes)
}

struct Stage {
    dir: tempfile::TempDir,
}

impl Stage {
    /// The variant's sources and script, with its code compiled to the
    /// `multisig-code.fif` the script includes.
    fn new(variant: &Variant, owners: &[[u8; 32]]) -> Self {
        let dir = tempfile::tempdir().expect("a stage");
        for entry in std::fs::read_dir(&variant.dir).expect("the variant's sources") {
            let path = entry.expect("an entry").path();
            if path.extension().is_some_and(|e| e == "fc" || e == "fif") {
                let name = path.file_name().expect("a file name");
                std::fs::copy(&path, dir.path().join(name)).expect("staged");
            }
        }
        let names: Vec<String> = variant
            .sources
            .iter()
            .map(|s| s.file_name().expect("a file name").to_string_lossy().into_owned())
            .collect();
        let out = std::process::Command::new(tool("FUNC_PATH", "func"))
            .current_dir(dir.path())
            .args(["-SPA", "-o", "multisig-code.fif"])
            .args(&names)
            .output()
            .expect("func runs");
        assert!(
            out.status.success(),
            "{}: func: {}",
            variant.name,
            String::from_utf8_lossy(&out.stderr)
        );
        let keys: String = owners.iter().map(|k| pubkey_text(k) + "\n").collect();
        std::fs::write(dir.path().join("keys.txt"), keys).expect("the keys file");
        Stage { dir }
    }

    fn run(&self, bridges: &[&str]) -> std::process::Output {
        let lib = repo_root().join("crypto/fift/lib");
        let includes = format!("{}:{}", lib.display(), self.dir.path().display());
        let wallet_id = WALLET_ID.to_string();
        let mut args = vec![
            "-I",
            &includes,
            "-s",
            "new-multisig.fif",
            "-1",
            &wallet_id,
            "ms",
            "2",
            "keys.txt",
        ];
        args.extend_from_slice(bridges);
        std::process::Command::new(tool("FIFT_PATH", "fift"))
            .current_dir(self.dir.path())
            .args(&args)
            .output()
            .expect("fift runs")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

fn raw(hash: &[u8; 32], workchain: i8) -> String {
    format!("{workchain}:{}", hex::encode(hash))
}

/// The script builds the data create_init_state builds for its bridge list,
/// at the address that StateInit deploys to, and its creation message brings
/// up a multisig that executes a vote. It refuses an empty list, a basechain
/// bridge and a bridge named twice.
#[test]
fn new_multisig_fif_builds_the_allowlisted_state_init() {
    let owners = public_keys(&owner_keys());
    for variant in variants() {
        let name = variant.name;
        let stage = Stage::new(&variant, &owners);
        let out = stage.run(&[&raw(&BRIDGE_A, -1), &raw(&BRIDGE_B, -1)]);
        assert!(
            out.status.success(),
            "{name}: new-multisig.fif: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let boc = std::fs::read(stage.path("ms-create.boc")).expect("the creation query");
        let root = chain_block::read_single_root_boc(boc).expect("a boc");
        let create = Message::construct_from_cell(root).expect("a message");
        let init = create.state_init().expect("a StateInit").clone();
        assert_eq!(
            init.code.as_ref().map(|c| c.repr_hash()),
            Some(code_of(&variant).repr_hash()),
            "{name}: the script deploys this build"
        );
        assert_eq!(
            init.data.as_ref().map(|c| c.repr_hash()),
            Some(wallet_data(&owners, 2, &[BRIDGE_A, BRIDGE_B]).repr_hash()),
            "{name}: the allowlisted data, lock_until 0"
        );
        let address = address_of(&init, -1);
        assert_eq!(create.dst().as_ref(), Some(&address), "{name}: the creation address");

        let mut bc = chain();
        let funder = bc.treasury("script-funder", 10_000 * TOS).expect("funder");
        let fund =
            MessageBuilder::internal(funder.address(), &address, 1_000 * TOS).bounce(false).build();
        // Funds the address before it has any code: the transaction has no
        // state to run, and the coins stay there.
        bc.send_message(fund).expect("fund");
        bc.send_message(create).expect("create").expect_success();
        let relayer = bc.treasury("script-relayer", 1_000 * TOS).expect("relayer");
        let mut multisig = Multisig { bc, address, relayer, keys: owner_keys(), next_query: 1 };
        let (_, tx, outs) = multisig.propose(1, &Vote::to(&masterchain(BRIDGE_B)));
        succeeded(&tx, &format!("{name}: a vote through the scripted multisig"));
        assert!(outs.iter().any(|m| m.dst_ref() == Some(&masterchain(BRIDGE_B))), "{name}");

        for (bridges, what) in [
            (vec![], "no bridge"),
            (vec![raw(&BRIDGE_A, 0)], "a basechain bridge"),
            (vec![raw(&BRIDGE_A, -1), raw(&BRIDGE_A, -1)], "a bridge named twice"),
        ] {
            let _ = std::fs::remove_file(stage.path("ms-create.boc"));
            let bridges: Vec<&str> = bridges.iter().map(String::as_str).collect();
            let out = stage.run(&bridges);
            assert!(!out.status.success(), "{name}: the script accepted {what}");
            assert!(!Path::new(&stage.path("ms-create.boc")).exists(), "{name}: {what}");
        }
    }
}

// ---------------------------------------------------------------------------
// The coin bridge end to end
// ---------------------------------------------------------------------------

const NETWORKS: [&str; 2] = ["ethereum", "bsc"];

fn coin_param(network: &str) -> u32 {
    if network == "ethereum" { 71 } else { 72 }
}

fn coin_bridge_code(network: &'static str) -> Cell {
    let dir = crosschain(&format!("coin-bridge/tvm/{network}"));
    let sources: Vec<PathBuf> =
        ["stdlib.fc", "text_utils.fc", "message_utils.fc", "bridge-config.fc", "bridge_code.fc"]
            .iter()
            .map(|s| dir.join(s))
            .collect();
    compile_func(&sources).unwrap_or_else(|e| panic!("{network} bridge: {e}"))
}

/// state_flags total_locked collector fees, with a 0.5 TOS flat reward, a
/// 0.2 TOS network fee and no percentage.
fn coin_bridge_data(total_locked: u128, collector: u8) -> Cell {
    let collector = basechain([collector; 32]);
    cell(|b| {
        b.append_u8(0).unwrap();
        coins(b, total_locked);
        collector.write_to(b).unwrap();
        coins(b, u128::from(TOS / 2));
        coins(b, u128::from(TOS / 5));
        b.append_bits(0, 14).unwrap();
    })
}

/// ConfigParam 71 or 72: the bridge it names and the oracle multisig.
fn configure_coin(
    bc: &mut Blockchain,
    network: &str,
    bridge: &MsgAddressInt,
    oracles: &MsgAddressInt,
) {
    let param = cell(|b| {
        b.append_raw(&hash_of(bridge), 256).unwrap();
        b.append_raw(&hash_of(oracles), 256).unwrap();
        b.append_bit_zero().unwrap(); // oracle keys, unused here
    });
    let mut config = bc.config_params().clone();
    config
        .set_config(ConfigParamEnum::ConfigParamAny(coin_param(network), param))
        .expect("the bridge param");
    // A configuration the chain adopts lists its fundamental contracts.
    if config.config(31).expect("param 31").is_none() {
        config
            .set_config(ConfigParamEnum::ConfigParam31(chain_block::ConfigParam31 {
                fundamental_smc_addr: chain_block::FundamentalSmcAddresses::default(),
            }))
            .expect("the fundamental contracts are listed");
    }
    bc.set_config(config).expect("the chain adopts it");
}

fn deploy_coin_bridge(bc: &mut Blockchain, init: StateInit, value: u64) -> MsgAddressInt {
    let address = address_of(&init, -1);
    let funder = bc.treasury("bridge-funder", 1_000_000 * TOS).expect("funder");
    // An operation the bridge does not act on, so the deployment changes nothing.
    let deploy = MessageBuilder::internal(funder.address(), &address, value)
        .bounce(false)
        .state_init(init)
        .body(cell(|b| {
            b.append_u32(5).unwrap();
            b.append_u64(0).unwrap();
        }))
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();
    address
}

fn total_locked(bc: &Blockchain, bridge: &MsgAddressInt) -> i128 {
    let data = bc.run_get_method(bridge, "get_bridge_data", vec![]).expect("get_bridge_data");
    data.expect_success();
    data.int_at(1)
}

fn balance(bc: &Blockchain, addr: &MsgAddressInt) -> u128 {
    bc.get_account(addr).and_then(|a| a.balance().cloned()).map(|b| b.coins.as_u128()).unwrap_or(0)
}

fn coin_vote(operation: u8, data: impl FnOnce(&mut BuilderData)) -> Cell {
    cell(|b| {
        b.append_u32(4).unwrap(); // execute_voting
        b.append_u8(operation).unwrap();
        data(b);
    })
}

/// Two coin bridges, the old one holding the locked coins and the new one
/// the configuration names, and an oracle multisig allowed to vote to both.
struct CoinNet {
    multisig: Multisig,
    old: MsgAddressInt,
    new: MsgAddressInt,
}

fn coin_net(network: &'static str, locked: u128, surplus: u64) -> CoinNet {
    let mut bc = chain();
    let code = coin_bridge_code(network);
    let old_init = StateInit::with_code_and_data(code.clone(), coin_bridge_data(locked, 0x11));
    let new_init = StateInit::with_code_and_data(code, coin_bridge_data(0, 0x22));
    let old = address_of(&old_init, -1);
    let new = address_of(&new_init, -1);
    let ms_variant = coin_variant(network);
    let ms_code = code_of(&ms_variant);
    let owners = public_keys(&owner_keys());
    let allowed = [hash_of(&old), hash_of(&new)];
    let ms = address_of(&state_init(&ms_code, &owners, 2, &allowed), -1);
    configure_coin(&mut bc, network, &new, &ms);
    let locked_u64 = u64::try_from(locked).expect("a test amount");
    deploy_coin_bridge(&mut bc, old_init, locked_u64 + surplus);
    deploy_coin_bridge(&mut bc, new_init, 200 * TOS);
    let multisig = Multisig::deploy_in(bc, &ms_code, &owners, &allowed);
    assert_eq!(multisig.address, ms);
    CoinNet { multisig, old, new }
}

/// Migration is voted to the old bridge, which ConfigParam 71/72 no longer
/// names: the multisig dispatches it because its allowlist lists the old
/// bridge, the old bridge sends total_locked to the configured new bridge
/// with 0xf00d, and the new bridge locks it.
#[test]
fn coin_migrate_vote_to_the_old_bridge_completes_the_f00d_loop() {
    for network in NETWORKS {
        let locked = u128::from(50 * TOS);
        let mut net = coin_net(network, locked, 200 * TOS);
        let vote = Vote { body: Some(coin_vote(4, |_| {})), ..Vote::to(&net.old) };
        let (_, relay) = net.multisig.query(1, &vote);
        let result = net.multisig.bc.send_message(relay).expect("the cascade runs");
        for (who, addr) in [
            ("multisig", &net.multisig.address),
            ("old bridge", &net.old),
            ("new bridge", &net.new),
        ] {
            let txs = result.transactions_for(addr);
            assert_eq!(txs.len(), 1, "{network}: one {who} transaction");
            succeeded(txs[0], &format!("{network}: {who}"));
        }
        let bc = &net.multisig.bc;
        assert_eq!(total_locked(bc, &net.old), 0, "{network}: the old bridge backs nothing");
        assert_eq!(
            total_locked(bc, &net.new) as u128,
            locked,
            "{network}: the new bridge locked it"
        );
        assert!(balance(bc, &net.new) >= locked, "{network}: and holds it");
    }
}

/// get_reward pays the address the vote names. The multisig that relayed the
/// vote receives nothing back from the bridge, and the locked coins and the
/// storage reserve stay.
#[test]
fn coin_get_reward_pays_the_voted_address_never_the_multisig() {
    for network in NETWORKS {
        let locked = u128::from(50 * TOS);
        let surplus = 140 * TOS; // 100 TOS storage reserve and 40 TOS of rewards
        let mut net = coin_net(network, locked, surplus);
        let reward = net.multisig.bc.treasury("reward-collector", TOS).expect("a collector");
        let reward_address = reward.address().clone();
        let before = balance(&net.multisig.bc, &reward_address);
        let body = coin_vote(5, |b| reward_address.write_to(b).unwrap());
        let vote = Vote { body: Some(body), ..Vote::to(&net.old) };
        let (_, relay) = net.multisig.query(1, &vote);
        let result = net.multisig.bc.send_message(relay).expect("the cascade runs");
        let bridge_txs = result.transactions_for(&net.old);
        assert_eq!(bridge_txs.len(), 1, "{network}: one bridge transaction");
        succeeded(bridge_txs[0], &format!("{network}: get_reward"));
        assert_eq!(
            result.transactions_for(&net.multisig.address).len(),
            1,
            "{network}: nothing came back to the multisig"
        );
        let bc = &net.multisig.bc;
        let paid = balance(bc, &reward_address) - before;
        assert!(paid > u128::from(39 * TOS), "{network}: the collector got the sweep: {paid}");
        assert_eq!(total_locked(bc, &net.old) as u128, locked, "{network}: locked coins stay");
        let reserve = locked + u128::from(100 * TOS);
        assert!(balance(bc, &net.old) >= reserve, "{network}: and the storage reserve");
    }
}

/// get_reward refuses a reward address it cannot pay safely: the zero
/// account on either chain, and any workchain but the basechain and the
/// masterchain (exit code 308). Nothing leaves the bridge.
#[test]
fn coin_get_reward_refuses_a_reward_address_it_cannot_pay() {
    for network in NETWORKS {
        let locked = u128::from(50 * TOS);
        let mut net = coin_net(network, locked, 140 * TOS);
        for (wc, hash) in [(0, [0u8; 32]), (-1, [0u8; 32]), (5, [0x66; 32])] {
            let reward = MsgAddressInt::with_params(wc, chain_block::UInt256::from(hash))
                .expect("an address");
            let body = coin_vote(5, |b| reward.write_to(b).unwrap());
            let vote = Vote { body: Some(body), ..Vote::to(&net.old) };
            let before = balance(&net.multisig.bc, &net.old);
            let (_, relay) = net.multisig.query(1, &vote);
            let result = net.multisig.bc.send_message(relay).expect("the cascade runs");
            let txs = result.transactions_for(&net.old);
            assert!(!txs.is_empty(), "{network}: the vote reached the bridge");
            let (aborted, exit) = outcome(txs[0]);
            assert!(
                aborted && exit == Some(308),
                "{network}: {reward}: expected exit code 308, got {exit:?}"
            );
            assert!(
                result.transactions_for(&reward).is_empty(),
                "{network}: {reward}: nothing was paid"
            );
            let after = balance(&net.multisig.bc, &net.old);
            assert!(after + u128::from(TOS / 10) >= before, "{network}: no sweep: {after}");
            assert_eq!(total_locked(&net.multisig.bc, &net.old) as u128, locked, "{network}");
        }
    }
}

/// Nothing may follow the reward address in the vote: end_parse refuses it
/// (exit code 9) and nothing is paid.
#[test]
fn coin_get_reward_refuses_trailing_vote_data() {
    for network in NETWORKS {
        let mut net = coin_net(network, u128::from(50 * TOS), 140 * TOS);
        let reward = basechain([0x77; 32]);
        let body = coin_vote(5, |b| {
            reward.write_to(b).unwrap();
            b.append_u8(1).unwrap();
        });
        let vote = Vote { body: Some(body), ..Vote::to(&net.old) };
        let (_, relay) = net.multisig.query(1, &vote);
        let result = net.multisig.bc.send_message(relay).expect("the cascade runs");
        let txs = result.transactions_for(&net.old);
        assert!(!txs.is_empty(), "{network}: the vote reached the bridge");
        let (aborted, exit) = outcome(txs[0]);
        assert!(aborted && exit == Some(9), "{network}: expected exit code 9, got {exit:?}");
        assert!(result.transactions_for(&reward).is_empty(), "{network}: nothing was paid");
    }
}

/// Every coin vote the oracles send executes on a quarter of MAX_VOTE_VALUE,
/// sent through the multisig in mode 1, and its fees stay within that quarter.
#[test]
fn max_vote_value_covers_every_coin_vote_with_margin() {
    for network in NETWORKS {
        let max = max_vote_value(&coin_variant(network));
        let mut net = coin_net(network, u128::from(50 * TOS), 200 * TOS);
        let collector = basechain([0x33; 32]);
        let votes: Vec<(&str, Cell)> = vec![
            (
                "swap",
                coin_vote(0, |b| {
                    b.append_raw(&[0x55; 32], 256).unwrap(); // ext_chain_hash
                    b.append_bits(1, 16).unwrap(); // internal_index
                    b.append_bits(0, 8).unwrap(); // workchain
                    b.append_raw(&[0x44; 32], 256).unwrap(); // recipient
                    b.append_u64(5 * TOS).unwrap();
                }),
            ),
            (
                "state flags",
                coin_vote(3, |b| {
                    b.append_u8(0).unwrap();
                }),
            ),
            (
                "fees",
                coin_vote(6, |b| {
                    coins(b, u128::from(TOS / 2));
                    coins(b, u128::from(TOS / 5));
                    b.append_bits(0, 14).unwrap();
                }),
            ),
            ("collector", coin_vote(7, |b| collector.write_to(b).unwrap())),
            ("reward", coin_vote(5, |b| collector.write_to(b).unwrap())),
            ("migrate", coin_vote(4, |_| {})),
        ];
        for (what, body) in votes {
            let vote = Vote { value: max / 4, body: Some(body), ..Vote::to(&net.old) };
            let (_, relay) = net.multisig.query(1, &vote);
            let result = net.multisig.bc.send_message(relay).expect("the cascade runs");
            let txs = result.transactions_for(&net.old);
            assert!(!txs.is_empty(), "{network}: {what}: the vote reached the bridge");
            succeeded(txs[0], &format!("{network}: {what} on a quarter of MAX_VOTE_VALUE"));
            let fees = txs[0].total_fees().coins.as_u128();
            eprintln!("{network}: {what}: the bridge's fees {fees}, MAX_VOTE_VALUE {max}");
            assert!(fees * 4 <= u128::from(max), "{network}: {what} cost {fees}");
        }
    }
}
