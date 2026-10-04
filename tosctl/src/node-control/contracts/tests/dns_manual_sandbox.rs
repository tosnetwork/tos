/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The owner-controlled DNS resolver (crypto/smartcont/dns-manual-code.fc) as real
//! transactions, with an owner key anyone can sign for. A weak stored key is refused
//! before its signature is checked, and an owner-signed key change (OSet) to a weak key
//! is refused before acceptance, so neither costs the contract anything, changes
//! nothing, nor leaves a replayable message behind. Strong owners keep full control.

use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, compile_func_with_stdlib};
use tos_vm::stack::integer::IntegerData;

mod weak_ed25519;

const TOS: u64 = 1_000_000_000;
const CONTRACT_ID: u32 = 0x444e_5301;
const ERR_WEAK_OWNER_KEY: i32 = 46;
const EXTERNAL_GAS_CREDIT: i64 = 10_000;

const OP_TSET: u64 = 31;
const OP_OSET: u64 = 51;

fn smartcont(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../crypto/smartcont").join(name)
}

fn source() -> String {
    std::fs::read_to_string(smartcont("dns-manual-code.fc")).expect("source")
}

/// Compiles `source` as dns-manual-code.fc next to the weak-key helper it includes.
fn compile(source: &str) -> Cell {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("dns-manual-code.fc"), source).expect("write source");
    std::fs::copy(smartcont("strong-ed25519-key.fc"), dir.path().join("strong-ed25519-key.fc"))
        .expect("copy helper");
    compile_func_with_stdlib(&[dir.path().join("dns-manual-code.fc")]).expect("compile")
}

const STORED_KEY_GUARD: &str = "  require_strong_key(public_key);\n";
const NEW_KEY_GUARD: &str =
    "  if (op == 51) {\n    require_strong_key(in_msg.skip_bits(6).preload_uint(256));\n  }\n";

/// The source with one or both guards taken out.
fn without(guards: &[&str]) -> String {
    let mut source = source();
    for guard in guards {
        assert_eq!(source.matches(guard).count(), 1, "guard moved: {guard}");
        source = source.replace(guard, "");
    }
    source
}

fn unguarded_source() -> String {
    let source = without(&[STORED_KEY_GUARD, NEW_KEY_GUARD]);
    assert!(!source.contains("  require_strong_key("), "a guard was left in");
    source
}

/// The source with acceptance replaced by a throw whose exit code is the gas consumed
/// so far. The probe lifts its own gas limit first, so a path over the external credit
/// still reports its cost (over-estimated by that one instruction).
fn probe_source(source: &str) -> String {
    let accept = "  accept_message(); ;; message is signed by owner, sanity not guaranteed yet";
    assert_eq!(source.matches(accept).count(), 1);
    let probe = source.replace(accept, "  throw(gas_consumed());");
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

fn initial_data(owner: &[u8; 32]) -> Cell {
    cell(|d| {
        d.append_u32(CONTRACT_ID).unwrap();
        d.append_u64(0).unwrap();
        d.append_u256(owner).unwrap();
        d.append_bit_zero().unwrap();
        d.append_bit_zero().unwrap();
    })
}

/// An operation list: OSet to `key`.
fn oset(key: &[u8; 32]) -> Cell {
    cell(|o| {
        o.append_bits(OP_OSET as usize, 6).unwrap();
        o.append_u256(key).unwrap();
    })
}

/// An operation list: TSet replacing the whole domain table with `table`.
fn tset(table: Cell) -> Cell {
    cell(|o| {
        o.append_bits(OP_TSET as usize, 6).unwrap();
        o.append_bit_one().unwrap();
        o.checked_append_reference(table).unwrap();
    })
}

/// The part the owner signs: contract id, query id, then the operations.
fn signed_part(query_id: u64, ops: &Cell) -> Cell {
    let ops = SliceData::load_cell(ops.clone()).unwrap();
    cell(|m| {
        m.append_u32(CONTRACT_ID).unwrap();
        m.append_u64(query_id).unwrap();
        m.append_builder(&ops.as_builder().unwrap()).unwrap();
    })
}

fn external_body(signature: [u8; 64], signed: &Cell) -> Cell {
    let rest = SliceData::load_cell(signed.clone()).unwrap();
    cell(|m| {
        m.append_raw(&signature, 512).unwrap();
        m.append_builder(&rest.as_builder().unwrap()).unwrap();
    })
}

fn sign(key: &SigningKey, signed: &Cell) -> [u8; 64] {
    key.sign(signed.hash(0).as_slice()).to_bytes()
}

struct Resolver {
    bc: Blockchain,
    address: MsgAddressInt,
    next_query: u64,
}

impl Resolver {
    fn deploy(code: Cell, owner: &[u8; 32]) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        let funder = bc.treasury("funder", 1_000 * TOS).expect("funder");
        let init = StateInit::with_code_and_data(code, initial_data(owner));
        let hash = init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let address = MsgAddressInt::with_params(0, hash).unwrap();
        let deploy = MessageBuilder::internal(funder.address(), &address, 10 * TOS)
            .bounce(false)
            .state_init(init)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, address, next_query: 1 }
    }

    /// A fresh query id that stays valid for two hours.
    fn query_id(&mut self) -> u64 {
        self.next_query += 1;
        ((u64::from(self.bc.now()) + 7_200) << 32) | self.next_query
    }

    fn send(&mut self, body: Cell) -> Result<SendResult, String> {
        let message = MessageBuilder::external(&self.address)
            .body_slice(SliceData::load_cell(body).unwrap())
            .build();
        self.bc.send_message(message).map_err(|error| error.to_string())
    }

    /// A message the owner signed with `key`.
    fn signed(&mut self, key: &SigningKey, ops: &Cell) -> Cell {
        let signed = signed_part(self.query_id(), ops);
        external_body(sign(key, &signed), &signed)
    }

    /// A message carrying a signature forged for the weak key `owner`, found by trying
    /// fresh query ids.
    fn forged(&mut self, owner: &[u8; 32], ops: &Cell) -> Cell {
        for _ in 0..4_096 {
            let signed = signed_part(self.query_id(), ops);
            if let Some(forged) = weak_ed25519::forge(owner, signed.hash(0).as_slice()) {
                return external_body(forged, &signed);
            }
        }
        panic!("no forgery found for {}", hex::encode(owner));
    }

    fn owner_is(&self, key: &[u8; 32]) -> bool {
        let result = self
            .bc
            .run_get_method(&self.address, "get_public_key", vec![])
            .expect("get_public_key");
        result.expect_success();
        let stored = result.stack.last().expect("key").as_integer().expect("int").clone();
        stored == IntegerData::from_unsigned_bytes_be(key)
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
}

fn forgeable_weak_keys() -> Vec<[u8; 32]> {
    let probe = signed_part(1 << 40, &tset(Cell::default())).hash(0);
    let keys: Vec<[u8; 32]> = weak_ed25519::weak_keys()
        .into_iter()
        .filter(|key| {
            (0..64u8).any(|i| {
                let mut message = probe.as_slice().to_vec();
                message[0] = i;
                weak_ed25519::forge(key, &message).is_some()
            })
        })
        .collect();
    let aliases = weak_ed25519::sign_bit_aliases();
    assert!(keys.contains(&aliases[0]) && keys.contains(&aliases[1]), "aliases not forgeable");
    assert!(keys.len() >= 10, "only {} forgeable weak keys", keys.len());
    keys
}

fn attacker() -> SigningKey {
    SigningKey::from_bytes(&[0x66; 32])
}

/// Without the guards, a resolver whose stored owner key is weak belongs to anyone: a
/// forged OSet hands it to the forger, and a forged TSet replaces its whole table.
#[test]
fn without_the_guards_a_forged_owner_signature_takes_the_resolver() {
    let code = compile(&unguarded_source());
    for weak in weak_ed25519::sign_bit_aliases() {
        let mut resolver = Resolver::deploy(code.clone(), &weak);
        let data = resolver.data_hash();
        let forged = resolver.forged(&weak, &tset(Cell::default()));
        resolver.send(forged).expect("the unguarded resolver accepts").expect_success();
        assert_ne!(resolver.data_hash(), data, "the forged TSet changed nothing");

        let thief = attacker().verifying_key().to_bytes();
        let forged = resolver.forged(&weak, &oset(&thief));
        resolver.send(forged).expect("the unguarded resolver accepts").expect_success();
        assert!(resolver.owner_is(&thief), "the forger owns the resolver");
    }
}

/// Without the new-key guard, the owner can hand the resolver to a weak key, after which
/// anyone forges for it.
#[test]
fn without_the_guards_an_owner_can_rotate_to_a_key_anyone_signs_for() {
    let code = compile(&unguarded_source());
    let owner = SigningKey::from_bytes(&[0x21; 32]);
    for weak in weak_ed25519::sign_bit_aliases() {
        let mut resolver = Resolver::deploy(code.clone(), &owner.verifying_key().to_bytes());
        let rotate = resolver.signed(&owner, &oset(&weak));
        resolver.send(rotate).expect("rotation accepted").expect_success();
        assert!(resolver.owner_is(&weak));
        let forged = resolver.forged(&weak, &tset(Cell::default()));
        resolver.send(forged).expect("forgery accepted").expect_success();
    }
}

/// Every forgeable weak key as the stored owner: forged TSet and OSet messages are
/// refused with exit 46 before acceptance -- no transaction, no fee taken, no state
/// change -- three times each.
#[test]
fn forged_signatures_under_a_weak_owner_are_refused_before_acceptance() {
    let code = compile(&source());
    let thief = attacker().verifying_key().to_bytes();
    let mut refusals = 0;
    for weak in forgeable_weak_keys() {
        let mut resolver = Resolver::deploy(code.clone(), &weak);
        let balance = resolver.balance();
        let data = resolver.data_hash();
        for _ in 0..3 {
            for ops in [tset(Cell::default()), oset(&thief)] {
                let forged = resolver.forged(&weak, &ops);
                let error = match resolver.send(forged) {
                    Ok(_) => panic!("{}: accepted", hex::encode(weak)),
                    Err(error) => error,
                };
                assert!(
                    error.contains(&format!("exit code: {ERR_WEAK_OWNER_KEY}")),
                    "{}: {error}",
                    hex::encode(weak)
                );
                refusals += 1;
            }
        }
        assert_eq!(resolver.balance(), balance, "a refusal cost the resolver");
        assert_eq!(resolver.data_hash(), data, "a refusal changed state");
        assert!(resolver.owner_is(&weak));
    }
    assert!(refusals >= 2 * 3 * 10);
}

/// An owner-signed OSet to any weak key is refused with exit 46 before acceptance. The
/// very same signed message, resent, is refused again at no cost: a refusal after
/// acceptance would have rolled back the stored query id and left it replayable at the
/// resolver's expense.
#[test]
fn an_owner_cannot_rotate_to_a_weak_key() {
    let code = compile(&source());
    let owner = SigningKey::from_bytes(&[0x22; 32]);
    let mut resolver = Resolver::deploy(code, &owner.verifying_key().to_bytes());
    let balance = resolver.balance();
    let data = resolver.data_hash();
    for weak in weak_ed25519::weak_keys() {
        let rotate = resolver.signed(&owner, &oset(&weak));
        for _ in 0..3 {
            let error = resolver.send(rotate.clone()).err().unwrap_or_default();
            assert!(
                error.contains(&format!("exit code: {ERR_WEAK_OWNER_KEY}")),
                "{}: {error}",
                hex::encode(weak)
            );
        }
    }
    assert_eq!(resolver.balance(), balance, "a refused rotation cost the resolver");
    assert_eq!(resolver.data_hash(), data, "a refused rotation changed state");
    assert!(resolver.owner_is(&owner.verifying_key().to_bytes()));
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

/// A table cell to install with TSet.
fn table(tag: u32) -> Cell {
    cell(|t| {
        t.append_u32(tag).unwrap();
    })
}

/// Strong owners, including keys whose first byte sends them through the full check,
/// replace the table, hand the resolver on, and lose control once they have.
#[test]
fn strong_owners_keep_full_control() {
    let code = compile(&source());
    for first in [0x00u8, 0x01, 0x26, 0xc7, 0xec, 0xff, 0x42] {
        let owner = strong_key_starting_with(first, 0x31);
        let next = strong_key_starting_with(first, 0x32);
        let mut resolver = Resolver::deploy(code.clone(), &owner.verifying_key().to_bytes());

        let data = resolver.data_hash();
        let set = resolver.signed(&owner, &tset(table(1)));
        resolver.send(set).expect("TSet").expect_success();
        assert_ne!(resolver.data_hash(), data, "first byte {first:#04x}: table unchanged");

        let rotate = resolver.signed(&owner, &oset(&next.verifying_key().to_bytes()));
        resolver.send(rotate).expect("OSet").expect_success();
        assert!(resolver.owner_is(&next.verifying_key().to_bytes()));

        let stale = resolver.signed(&owner, &tset(table(2)));
        let error = resolver.send(stale).err().unwrap_or_default();
        assert!(error.contains("exit code: 35"), "the old owner still signs: {error}");
        let clear = resolver.signed(&next, &tset(table(3)));
        resolver.send(clear).expect("TSet by the new owner").expect_success();
    }
}

fn pre_acceptance_gas(source: &str, owner: &SigningKey, next: &[u8; 32]) -> Vec<i64> {
    let mut resolver =
        Resolver::deploy(compile(&probe_source(source)), &owner.verifying_key().to_bytes());
    [oset(next), tset(table(1))]
        .iter()
        .map(|ops| {
            let body = resolver.signed(owner, ops);
            let result = resolver.send(body).expect("the probe pays for itself");
            match result.read_primary_description().compute_ph {
                chain_block::TrComputePhase::Vm(vm) => i64::from(vm.exit_code),
                chain_block::TrComputePhase::Skipped(skipped) => {
                    panic!("compute skipped: {:?}", skipped.reason)
                }
            }
        })
        .collect()
}

/// Pre-acceptance gas of an OSet and a TSet under stored and new keys whose first byte
/// enters the full check, against the same build without the guards.
#[test]
fn the_guards_fit_the_external_gas_credit() {
    let guarded = source();
    let unguarded = unguarded_source();
    let mut worst = 0i64;
    let mut worst_overhead = 0i64;
    for first in [0x00u8, 0x01, 0x26, 0xc7, 0xec, 0xff, 0x42] {
        let owner = strong_key_starting_with(first, 0x41);
        let next = strong_key_starting_with(first, 0x42).verifying_key().to_bytes();
        let with = pre_acceptance_gas(&guarded, &owner, &next);
        let without = pre_acceptance_gas(&unguarded, &owner, &next);
        for (shape, (with, without)) in with.iter().zip(&without).enumerate() {
            eprintln!(
                "first byte {first:#04x} shape {shape}: {without} -> {with} gas before acceptance"
            );
            worst = worst.max(*with);
            worst_overhead = worst_overhead.max(with - without);
        }
    }
    eprintln!("worst {worst}, worst guard overhead {worst_overhead}");
    // About 300 gas for each key the prefilter clears and 1,050 for each it cannot; an
    // OSet checks two keys.
    assert!(worst_overhead <= 2_100, "the guards add {worst_overhead} gas");
    assert!(worst * 10 <= EXTERNAL_GAS_CREDIT * 9, "{worst} leaves under 10% of the credit");
}

/// Each guard on its own is what refuses: with only the stored-key guard removed a
/// forgery under a weak stored key gets through, and with only the new-key guard
/// removed an OSet to a weak key does.
#[test]
fn each_guard_is_load_bearing() {
    let weak = weak_ed25519::sign_bit_aliases()[1];

    let mut resolver = Resolver::deploy(compile(&without(&[STORED_KEY_GUARD])), &weak);
    let forged = resolver.forged(&weak, &tset(Cell::default()));
    resolver.send(forged).expect("stored-key guard removed").expect_success();

    let owner = SigningKey::from_bytes(&[0x23; 32]);
    let mut resolver =
        Resolver::deploy(compile(&without(&[NEW_KEY_GUARD])), &owner.verifying_key().to_bytes());
    let rotate = resolver.signed(&owner, &oset(&weak));
    resolver.send(rotate).expect("new-key guard removed").expect_success();
    assert!(resolver.owner_is(&weak));
}
