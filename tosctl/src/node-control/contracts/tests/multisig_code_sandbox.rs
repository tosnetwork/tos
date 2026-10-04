/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The k-of-n external-message multisig (crypto/smartcont/multisig-code.fc) as real
//! transactions: owner keys anyone can sign for are refused when the initial data is
//! built, and a weak key that reaches storage anyway -- through a hand-built StateInit,
//! which makes a misconfigured wallet rather than an operational one -- neither signs as
//! root nor counts as a co-signer.

use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, compile_func_with_stdlib};
use tos_vm::stack::StackItem;

mod weak_ed25519;

const TOS: u64 = 1_000_000_000;
const WALLET_ID: u32 = 0x5157_0001;
const ERR_WEAK_OWNER: i32 = 45;

fn smartcont(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../crypto/smartcont").join(name)
}

fn cell(build: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    build(&mut b);
    b.into_cell().expect("cell")
}

fn append_maybe_ref(b: &mut BuilderData, value: Option<Cell>) {
    match value {
        Some(cell) => {
            b.append_bit_one().unwrap();
            b.checked_append_reference(cell).unwrap();
        }
        None => {
            b.append_bit_zero().unwrap();
        }
    }
}

/// owner index -> public_key:uint256 flood:uint8, as the contract stores it.
fn owner_dict(keys: &[[u8; 32]]) -> Cell {
    let mut dict = chain_block::HashmapE::with_bit_len(8);
    for (index, key) in keys.iter().enumerate() {
        let index =
            SliceData::load_builder(BuilderData::with_raw(vec![index as u8], 8).unwrap()).unwrap();
        let value = SliceData::load_cell(cell(|b| {
            b.append_u256(key).unwrap();
            b.append_u8(0).unwrap();
        }))
        .unwrap();
        dict.set(index, &value).unwrap();
    }
    chain_block::HashmapType::data(&dict).cloned().expect("non-empty owner set")
}

fn wallet_data(owners: &[[u8; 32]], k: u8) -> Cell {
    cell(|b| {
        b.append_u32(WALLET_ID).unwrap();
        b.append_u8(owners.len() as u8).unwrap();
        b.append_u8(k).unwrap();
        b.append_u64(0).unwrap();
        append_maybe_ref(b, Some(owner_dict(owners)));
        append_maybe_ref(b, None);
    })
}

/// The part every co-signer signs: wallet_id, query_id, and no outbound messages.
fn query_body(query_id: u64) -> Cell {
    cell(|b| {
        b.append_u32(WALLET_ID).unwrap();
        b.append_u64(query_id).unwrap();
    })
}

/// A linked list of co-signatures: signature(512) index(8) next(maybe ref).
fn co_signatures(entries: &[(u8, [u8; 64])]) -> Option<Cell> {
    let mut next: Option<Cell> = None;
    for (index, signature) in entries.iter().rev() {
        let link = next.take();
        next = Some(cell(|b| {
            b.append_raw(signature, 512).unwrap();
            b.append_u8(*index).unwrap();
            append_maybe_ref(b, link);
        }));
    }
    next
}

/// The cell the root signs: root index, co-signatures, then the query body.
fn signed_root(root: u8, co: Option<Cell>, query_id: u64) -> Cell {
    let body = SliceData::load_cell(query_body(query_id)).unwrap();
    cell(|b| {
        b.append_u8(root).unwrap();
        append_maybe_ref(b, co);
        b.append_builder(&body.as_builder().unwrap()).unwrap();
    })
}

fn query(root_signature: [u8; 64], signed: &Cell) -> Cell {
    let rest = SliceData::load_cell(signed.clone()).unwrap();
    cell(|b| {
        b.append_raw(&root_signature, 512).unwrap();
        b.append_builder(&rest.as_builder().unwrap()).unwrap();
    })
}

fn sign(key: &SigningKey, message: &Cell) -> [u8; 64] {
    key.sign(message.hash(0).as_slice()).to_bytes()
}

struct Wallet {
    bc: Blockchain,
    address: MsgAddressInt,
    keys: Vec<SigningKey>,
}

impl Wallet {
    /// Deploys a wallet over the given owner keys straight from a StateInit, the way
    /// anyone can deploy one without calling create_init_state.
    fn deploy(owners: &[[u8; 32]], k: u8, keys: Vec<SigningKey>) -> Self {
        let code = compile_func_with_stdlib(&[smartcont("multisig-code.fc")]).expect("compile");
        Self::deploy_with_code(owners, k, keys, code)
    }

    fn deploy_with_code(owners: &[[u8; 32]], k: u8, keys: Vec<SigningKey>, code: Cell) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        let init = StateInit::with_code_and_data(code, wallet_data(owners, k));
        let hash = init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let address = MsgAddressInt::with_params(0, hash).unwrap();
        let funder = bc.treasury("funder", 1_000 * TOS).expect("funder");
        let fund =
            MessageBuilder::internal(funder.address(), &address, 100 * TOS).bounce(false).build();
        bc.send_message(fund).expect("fund");
        let init_message = MessageBuilder::external(&address).state_init(init).build();
        bc.send_message(init_message).expect("init").expect_success();
        Self { bc, address, keys }
    }

    fn send(&mut self, body: Cell) -> Result<SendResult, String> {
        let message = MessageBuilder::external(&self.address)
            .body_slice(SliceData::load_cell(body).unwrap())
            .build();
        self.bc.send_message(message).map_err(|error| error.to_string())
    }

    /// Sends an external the wallet must refuse before accepting it; returns why.
    fn refused(&mut self, body: Cell) -> String {
        match self.send(body) {
            Ok(_) => panic!("the external was accepted"),
            Err(error) => error,
        }
    }

    fn query_id(&self, offset: u64) -> u64 {
        ((u64::from(self.bc.now()) + 7_200) << 32) | offset
    }

    /// (state, signer mask): (-1, 0) executed, (0, mask) pending with these signers,
    /// (0, 0) never seen.
    fn query_state(&self, query_id: u64) -> (i128, i128) {
        let result = self
            .bc
            .run_get_method(&self.address, "get_query_state", vec![StackItem::int(query_id as i64)])
            .expect("get_query_state");
        result.expect_success();
        (result.int_at(0), result.int_at(1))
    }

    fn processed(&self, query_id: u64) -> i128 {
        self.bc
            .run_get_method(&self.address, "processed?", vec![StackItem::int(query_id as i64)])
            .expect("processed?")
            .expect_success()
            .int_at(0)
    }
}

fn exit_code(result: &SendResult) -> i32 {
    match result.read_primary_description().compute_ph {
        chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
        chain_block::TrComputePhase::Skipped(skipped) => {
            panic!("compute skipped: {:?}", skipped.reason)
        }
    }
}

fn gas_used(result: &SendResult) -> u64 {
    match result.read_primary_description().compute_ph {
        chain_block::TrComputePhase::Vm(vm) => vm.gas_used.as_u64(),
        chain_block::TrComputePhase::Skipped(skipped) => {
            panic!("compute skipped: {:?}", skipped.reason)
        }
    }
}

fn strong_keys(count: u8) -> Vec<SigningKey> {
    (0..count).map(|i| SigningKey::from_bytes(&[0x40 + i; 32])).collect()
}

fn public(keys: &[SigningKey]) -> Vec<[u8; 32]> {
    keys.iter().map(|key| key.verifying_key().to_bytes()).collect()
}

/// The order-2 torsion key: canonical, on the curve, and forgeable for about half of
/// all messages.
fn forgeable_weak_key() -> [u8; 32] {
    let key = weak_ed25519::weak_keys()[4];
    assert_eq!(key[0], 0xec, "the order-2 point (y = -1)");
    key
}

/// Building the initial data through the contract refuses every weak owner key, next
/// to strong keys that would otherwise make a valid 2-of-3.
#[test]
fn create_init_state_refuses_every_weak_owner_key() {
    let keys = strong_keys(2);
    let wallet = Wallet::deploy(&public(&keys), 2, keys.clone());
    let build = |owners: &[[u8; 32]]| {
        wallet
            .bc
            .run_get_method(
                &wallet.address,
                "create_init_state",
                vec![
                    StackItem::int(i64::from(WALLET_ID)),
                    StackItem::int(owners.len() as i64),
                    StackItem::int(2),
                    StackItem::cell(owner_dict(owners)),
                ],
            )
            .expect("create_init_state")
    };
    let strong = public(&keys);
    assert_eq!(build(&[strong[0], strong[1]]).exit_code, 0, "strong owners build");
    for (i, weak) in weak_ed25519::weak_keys().into_iter().enumerate() {
        assert_eq!(
            build(&[strong[0], strong[1], weak]).exit_code,
            ERR_WEAK_OWNER,
            "weak key {i} accepted into an owner set"
        );
    }
}

/// A weak key stored by a hand-built StateInit cannot open a query as root: the external
/// is refused with exit 45 before acceptance, even with a signature forged for it.
#[test]
fn a_stored_weak_owner_cannot_sign_as_root() {
    let mut forged_count = 0;
    for (i, weak) in weak_ed25519::weak_keys().into_iter().enumerate() {
        let keys = strong_keys(2);
        let mut owners = public(&keys);
        owners.push(weak);
        let mut wallet = Wallet::deploy(&owners, 2, keys);
        let forgery = (1..=64).find_map(|offset| {
            let query_id = wallet.query_id(offset);
            let signed = signed_root(2, None, query_id);
            weak_ed25519::forge(&weak, signed.hash(0).as_slice())
                .map(|forged| (query_id, signed, forged))
        });
        match forgery {
            Some((query_id, signed, forged)) => {
                forged_count += 1;
                let error = wallet.refused(query(forged, &signed));
                assert!(
                    error.contains(&format!("exit code: {ERR_WEAK_OWNER}")),
                    "key {i}: {error}"
                );
                assert_eq!(wallet.query_state(query_id), (0, 0), "key {i}: a query was recorded");
            }
            None => {
                let signed = signed_root(2, None, wallet.query_id(100));
                let error = wallet.refused(query([0u8; 64], &signed));
                assert!(
                    error.contains(&format!("exit code: {ERR_WEAK_OWNER}")),
                    "key {i}: {error}"
                );
            }
        }
    }
    // Every torsion encoding and both sign-bit aliases decode, so all ten are forgeable.
    assert!(forged_count >= 10, "only {forged_count} weak keys were forgeable");

    // A strong root opens a query on such a wallet: the refusal is the weak key's.
    let keys = strong_keys(2);
    let mut owners = public(&keys);
    owners.push(forgeable_weak_key());
    let mut wallet = Wallet::deploy(&owners, 2, keys);
    let query_id = wallet.query_id(100);
    let signed = signed_root(0, None, query_id);
    let root_signature = sign(&wallet.keys[0], &signed);
    wallet.send(query(root_signature, &signed)).expect("strong root").expect_success();
    assert_eq!(wallet.query_state(query_id), (0, 1), "strong root's query is pending");
}

/// A 2-of-3 whose third owner is weak: one strong signature is a pending query, and the
/// weak owner's forged co-signature does not complete it.
#[test]
fn a_stored_weak_owner_does_not_count_toward_k() {
    let keys = strong_keys(2);
    let weak = forgeable_weak_key();
    let mut owners = public(&keys);
    owners.push(weak);
    let mut wallet = Wallet::deploy(&owners, 2, keys);

    // Positive control: root 0 with co-signer 1 executes the query.
    let query_id = wallet.query_id(1);
    let co = co_signatures(&[(1, sign(&wallet.keys[1], &query_body(query_id)))]);
    let signed = signed_root(0, co, query_id);
    let root_signature = sign(&wallet.keys[0], &signed);
    let result = wallet.send(query(root_signature, &signed)).expect("strong pair");
    assert_eq!(exit_code(&result), 0);
    assert_eq!(wallet.processed(query_id), -1, "two strong owners reach k");

    // Root 0 with the weak owner's forged co-signature.
    let (query_id, forged) = (2..=64)
        .find_map(|offset| {
            let query_id = wallet.query_id(offset);
            weak_ed25519::forge(&weak, query_body(query_id).hash(0).as_slice())
                .map(|forged| (query_id, forged))
        })
        .expect("a forgeable query id");
    let co = co_signatures(&[(2, forged)]);
    let signed = signed_root(0, co, query_id);
    let root_signature = sign(&wallet.keys[0], &signed);
    let result = wallet.send(query(root_signature, &signed)).expect("accepted for the root");
    assert_eq!(exit_code(&result), ERR_WEAK_OWNER, "the weak co-signature must be refused");
    assert_eq!(
        wallet.query_state(query_id),
        (0, 1),
        "the query must stay pending on the root alone"
    );
}

/// The off-chain check of a query's signatures refuses a weak root too.
#[test]
fn check_query_signatures_refuses_a_weak_root() {
    let keys = strong_keys(2);
    let weak = forgeable_weak_key();
    let mut owners = public(&keys);
    owners.push(weak);
    let wallet = Wallet::deploy(&owners, 2, keys);
    let (signed, forged) = (1..=64)
        .find_map(|offset| {
            let signed = signed_root(2, None, wallet.query_id(offset));
            weak_ed25519::forge(&weak, signed.hash(0).as_slice()).map(|forged| (signed, forged))
        })
        .expect("a forgeable query id");
    let check = |body: Cell| {
        wallet
            .bc
            .run_get_method(&wallet.address, "check_query_signatures", vec![StackItem::cell(body)])
            .expect("check_query_signatures")
    };
    assert_eq!(check(query(forged, &signed)).exit_code, ERR_WEAK_OWNER);
    let strong = signed_root(0, None, wallet.query_id(100));
    let strong_signature = sign(&wallet.keys[0], &strong);
    let result = check(query(strong_signature, &strong));
    result.expect_success();
    assert_eq!(result.int_at(0), 1, "one valid signature");
}

/// Gas for the widest bundle the allowance is sized for: a root and 24 co-signers in
/// one message, each paying a weak-key check before its signature check.
#[test]
fn root_and_twenty_four_co_signers_fit_the_allowance() {
    const ALLOWANCE: u64 = 150_000;
    let keys = strong_keys(25);
    let owners = public(&keys);
    let mut wallet = Wallet::deploy(&owners, 25, keys);
    let query_id = wallet.query_id(1);
    let body = query_body(query_id);
    let entries: Vec<(u8, [u8; 64])> =
        (1..25u8).map(|i| (i, sign(&wallet.keys[usize::from(i)], &body))).collect();
    let signed = signed_root(0, co_signatures(&entries), query_id);
    let root_signature = sign(&wallet.keys[0], &signed);
    let result = wallet.send(query(root_signature, &signed)).expect("bundle");
    let gas = gas_used(&result);
    eprintln!("root + 24 co-signers: gas {gas} of allowance {ALLOWANCE}");
    assert_eq!(exit_code(&result), 0);
    assert!(gas < ALLOWANCE);
    assert_eq!(wallet.processed(query_id), -1, "25 of 25 executed");
}

/// The identity and the order-2 point spelled with the sign bit set pass a y range check.
/// Stored as owners, neither opens a query with a forged root signature nor completes one
/// with a forged co-signature, while the two real owners still reach k.
#[test]
fn sign_bit_alias_owners_neither_sign_nor_count() {
    let keys = strong_keys(2);
    let aliases = weak_ed25519::sign_bit_aliases();
    let mut owners = public(&keys);
    owners.extend(aliases);
    let mut wallet = Wallet::deploy(&owners, 2, keys);
    let mut offset = 1u64;
    let mut fresh_query = |wallet: &Wallet| {
        offset += 1;
        wallet.query_id(offset)
    };
    for (index, alias) in [(2u8, aliases[0]), (3u8, aliases[1])] {
        let (query_id, signed, forged) = std::iter::repeat_with(|| fresh_query(&wallet))
            .take(64)
            .find_map(|query_id| {
                let signed = signed_root(index, None, query_id);
                weak_ed25519::forge(&alias, signed.hash(0).as_slice())
                    .map(|forged| (query_id, signed, forged))
            })
            .expect("a forgeable query id");
        let error = wallet.refused(query(forged, &signed));
        assert!(error.contains(&format!("exit code: {ERR_WEAK_OWNER}")), "alias {index}: {error}");
        assert_eq!(wallet.query_state(query_id), (0, 0), "alias {index} opened a query");

        let (query_id, forged) = std::iter::repeat_with(|| fresh_query(&wallet))
            .take(64)
            .find_map(|query_id| {
                weak_ed25519::forge(&alias, query_body(query_id).hash(0).as_slice())
                    .map(|forged| (query_id, forged))
            })
            .expect("a forgeable query id");
        let signed = signed_root(0, co_signatures(&[(index, forged)]), query_id);
        let root_signature = sign(&wallet.keys[0], &signed);
        let result = wallet.send(query(root_signature, &signed)).expect("accepted for the root");
        assert_eq!(exit_code(&result), ERR_WEAK_OWNER, "alias {index} co-signed");
        assert_eq!(wallet.query_state(query_id), (0, 1), "alias {index} counted toward k");
    }

    let query_id = fresh_query(&wallet);
    let co = co_signatures(&[(1, sign(&wallet.keys[1], &query_body(query_id)))]);
    let signed = signed_root(0, co, query_id);
    let root_signature = sign(&wallet.keys[0], &signed);
    let result = wallet.send(query(root_signature, &signed)).expect("strong pair");
    assert_eq!(exit_code(&result), 0);
    assert_eq!(wallet.processed(query_id), -1, "two real owners reach k");
}

/// wallet_id, query_id, then one (mode, message) pair per action: the query part every
/// signer signs, with outbound messages.
fn query_body_with(query_id: u64, messages: &[Cell]) -> Cell {
    cell(|b| {
        b.append_u32(WALLET_ID).unwrap();
        b.append_u64(query_id).unwrap();
        for message in messages {
            b.append_u8(3).unwrap();
            b.checked_append_reference(message.clone()).unwrap();
        }
    })
}

fn signed_root_with(root: u8, body: &Cell) -> Cell {
    let body = SliceData::load_cell(body.clone()).unwrap();
    cell(|b| {
        b.append_u8(root).unwrap();
        append_maybe_ref(b, None);
        b.append_builder(&body.as_builder().unwrap()).unwrap();
    })
}

/// Three outbound messages of 400 bits with a 200-bit body each: seven cells and 1824
/// bits after the query id, inside the 8-cell, 2048-bit limit the contract checks
/// before acceptance.
fn widest_actions() -> Vec<Cell> {
    (0..3u8)
        .map(|i| {
            let body = cell(|b| {
                b.append_raw(&[0xa0 + i; 25], 200).unwrap();
            });
            cell(|b| {
                b.append_raw(&[0x50 + i; 50], 400).unwrap();
                b.checked_append_reference(body).unwrap();
            })
        })
        .collect()
}

/// A signing key whose public key starts with `first`: the prefilter cannot clear it, so
/// its root check runs the full comparison.
fn strong_key_starting_with(first: u8) -> SigningKey {
    (0u32..)
        .map(|n| {
            let mut seed = [0x5au8; 32];
            seed[..4].copy_from_slice(&n.to_le_bytes());
            SigningKey::from_bytes(&seed)
        })
        .find(|key| key.verifying_key().to_bytes()[0] == first)
        .expect("a key with that first byte")
}

/// The source with its acceptance replaced, for roots 1 and up, by a throw whose exit
/// code is the gas consumed so far: the cost of the whole pre-acceptance path. The
/// added test runs before the throw, so the figure is an over-estimate.
fn pre_acceptance_probe_code() -> Cell {
    let source = std::fs::read_to_string(smartcont("multisig-code.fc")).expect("source");
    // The one place the external message is accepted.
    let accept = "  set_gas_limit(";
    assert_eq!(source.matches(accept).count(), 1);
    let probe =
        source.replace(accept, "  if (root_i >= 1) { throw(gas_consumed()); }\n  set_gas_limit(");
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("multisig-code.fc"),
        format!("int gas_consumed() asm \"GASCONSUMED\";\n{probe}"),
    )
    .expect("write probe");
    std::fs::copy(smartcont("strong-ed25519-key.fc"), dir.path().join("strong-ed25519-key.fc"))
        .expect("copy helper");
    compile_func_with_stdlib(&[dir.path().join("multisig-code.fc")]).expect("compile probe")
}

impl Wallet {
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

/// A funded hand-built wallet whose owners include every weak key a signature can be
/// forged for. Repeated forged root queries from each of them are refused before
/// acceptance: no transaction, no state change, and no fee taken from the wallet. Two
/// real owners then still open a query.
#[test]
fn forged_weak_roots_are_refused_before_acceptance_at_no_cost() {
    let keys = strong_keys(2);
    let probe_message = query_body(1).hash(0);
    let weak: Vec<[u8; 32]> = weak_ed25519::weak_keys()
        .into_iter()
        .filter(|key| {
            (0..64u8).any(|i| {
                let mut message = probe_message.as_slice().to_vec();
                message[0] = i;
                weak_ed25519::forge(key, &message).is_some()
            })
        })
        .collect();
    let aliases = weak_ed25519::sign_bit_aliases();
    assert!(weak.contains(&aliases[0]) && weak.contains(&aliases[1]));
    assert!(weak.len() >= 10, "only {} forgeable weak keys", weak.len());

    let mut owners = public(&keys);
    owners.extend(&weak);
    let mut wallet = Wallet::deploy(&owners, 2, keys);
    let balance = wallet.balance();
    let data = wallet.data_hash();
    let mut offset = 1u64;
    let mut refusals = 0;
    for (i, key) in weak.iter().enumerate() {
        let root = 2 + i as u8;
        for _ in 0..3 {
            let (signed, forged) = loop {
                offset += 1;
                let signed = signed_root(root, None, wallet.query_id(offset));
                if let Some(forged) = weak_ed25519::forge(key, signed.hash(0).as_slice()) {
                    break (signed, forged);
                }
            };
            let error = wallet.refused(query(forged, &signed));
            assert!(
                error.contains(&format!("exit code: {ERR_WEAK_OWNER}")),
                "root {root}: {error}"
            );
            refusals += 1;
        }
    }
    assert_eq!(refusals, 3 * weak.len());
    assert_eq!(wallet.balance(), balance, "a refused forged root cost the wallet");
    assert_eq!(wallet.data_hash(), data, "a refused forged root changed state");

    let query_id = wallet.query_id(10_000);
    let signed = signed_root(0, None, query_id);
    let root_signature = sign(&wallet.keys[0], &signed);
    wallet.send(query(root_signature, &signed)).expect("strong root").expect_success();
    assert_eq!(wallet.query_state(query_id), (0, 1), "a real owner still opens a query");
}

/// A signing key the prefilter clears: its first byte starts no weak encoding.
fn strong_key_cleared(n: u8) -> SigningKey {
    (0u32..)
        .map(|i| {
            let mut seed = [0x33u8; 32];
            seed[0] = n;
            seed[1..5].copy_from_slice(&i.to_le_bytes());
            SigningKey::from_bytes(&seed)
        })
        .find(|key| {
            let first = key.verifying_key().to_bytes()[0];
            first > 0x01 && first != 0x26 && first != 0xc7 && first < 0xec
        })
        .expect("a cleared key")
}

/// Pre-acceptance gas (from the probe build) of every owner after the first acting as
/// root, opening a fresh query or joining one of the pending queries owner 0 has filled
/// its flood quota with, all carrying `actions`. Err when a step could not run.
fn probe_roots(keys: &[SigningKey], actions: &[Cell], join: bool) -> Vec<Result<i64, String>> {
    let owners: Vec<[u8; 32]> = keys.iter().map(|key| key.verifying_key().to_bytes()).collect();
    let mut wallet =
        Wallet::deploy_with_code(&owners, 3, keys.to_vec(), pre_acceptance_probe_code());
    let ids: Vec<u64> = (1..=10).map(|i| wallet.query_id(i)).collect();
    for &query_id in &ids {
        let signed = signed_root_with(0, &query_body_with(query_id, actions));
        let root_signature = sign(&wallet.keys[0], &signed);
        if let Err(error) = wallet.send(query(root_signature, &signed)) {
            return vec![Err(format!("owner 0 cannot open the query: {error}")); keys.len() - 1];
        }
    }
    (1..keys.len())
        .map(|root| {
            let query_id =
                if join { ids[root % ids.len()] } else { wallet.query_id(100 + root as u64) };
            let signed = signed_root_with(root as u8, &query_body_with(query_id, actions));
            let root_signature = sign(&wallet.keys[root], &signed);
            match wallet.send(query(root_signature, &signed)) {
                Ok(_) => Err("the probe accepted".into()),
                Err(error) => error
                    .rsplit("exit code: ")
                    .next()
                    .and_then(|tail| tail.trim().parse::<i64>().ok())
                    .ok_or(error),
            }
        })
        .collect()
}

/// `count` outbound messages of `bytes` bytes each, every one a single cell.
fn actions_of(count: usize, bytes: usize) -> Vec<Cell> {
    (0..count)
        .map(|i| {
            cell(|b| {
                b.append_raw(&vec![0x50 + i as u8; bytes], bytes * 8).unwrap();
            })
        })
        .collect()
}

/// Every first byte the prefilter cannot clear, as a strong key, after one it clears.
fn root_keys() -> Vec<SigningKey> {
    let mut keys = vec![strong_key_cleared(0), strong_key_cleared(1)];
    for first in [0x00, 0x01, 0x26, 0xc7, 0xec, 0xf7] {
        keys.push(strong_key_starting_with(first));
    }
    keys
}

/// The pre-acceptance cost of every kind of root, from a probe build that stops right
/// before acceptance: a key the prefilter clears, and strong keys it cannot clear (first
/// bytes 0x00, 0x01, 0x26, 0xc7, 0xec, 0xf7) that run the full weak-key comparison,
/// opening a query or joining a pending one, with no outbound message and with the
/// largest message this test found the contract taking before the change (two 127-byte
/// messages; three no longer fit the credit either before or after it). Every case must
/// stay 10% under the external gas credit, and the full comparison must cost a bounded
/// amount over a cleared key. The same requests are then sent to the real build, which
/// must accept every one.
#[test]
fn full_check_strong_roots_fit_the_pre_acceptance_path() {
    const CREDIT: i64 = 10_000;
    const FULL_CHECK_BUDGET: i64 = 800;
    let keys = root_keys();
    for (count, bytes) in [(0, 0), (2, 127)] {
        let actions = actions_of(count, bytes);
        for join in [false, true] {
            let path = if join { "join" } else { "open" };
            let gas: Vec<i64> = probe_roots(&keys, &actions, join)
                .into_iter()
                .enumerate()
                .map(|(i, used)| used.unwrap_or_else(|e| panic!("root {}: {e}", i + 1)))
                .collect();
            let cleared = gas[0];
            for (i, used) in gas.iter().enumerate() {
                let root = i + 1;
                let first = keys[root].verifying_key().to_bytes()[0];
                eprintln!(
                    "{count}x{bytes} {path}: root first byte {first:#04x} gas {used} of {CREDIT}"
                );
                assert!(
                    used * 10 <= CREDIT * 9,
                    "root {root}: {used} leaves under 10% of the credit"
                );
                assert!(
                    used - cleared <= FULL_CHECK_BUDGET,
                    "root {root}: full check cost {}",
                    used - cleared
                );
            }

            // The real build accepts each of these roots on the same path.
            let owners: Vec<[u8; 32]> =
                keys.iter().map(|key| key.verifying_key().to_bytes()).collect();
            let mut wallet = Wallet::deploy(&owners, 3, keys.clone());
            let ids: Vec<u64> = (1..=10).map(|i| wallet.query_id(i)).collect();
            for &query_id in &ids {
                let signed = signed_root_with(0, &query_body_with(query_id, &actions));
                let root_signature = sign(&wallet.keys[0], &signed);
                wallet.send(query(root_signature, &signed)).expect("pending").expect_success();
            }
            for root in 1..keys.len() {
                let query_id =
                    if join { ids[root % ids.len()] } else { wallet.query_id(100 + root as u64) };
                let signed = signed_root_with(root as u8, &query_body_with(query_id, &actions));
                let root_signature = sign(&wallet.keys[root], &signed);
                let result = wallet.send(query(root_signature, &signed)).expect("accepted");
                assert_eq!(exit_code(&result), 0, "{path} root {root}");
                let (_, mask) = wallet.query_state(query_id);
                assert_ne!(mask & (1 << root), 0, "{path} root {root} did not sign");
            }
        }
    }
}

/// Joining a pending query with a request that differs from the stored one -- in its own
/// bits, in a referenced message, or in the number of references -- is refused with exit
/// 36 before acceptance; the identical request joins.
#[test]
fn joining_with_a_different_message_is_refused_before_acceptance() {
    let keys = vec![strong_key_cleared(0), strong_key_cleared(1)];
    let owners: Vec<[u8; 32]> = keys.iter().map(|key| key.verifying_key().to_bytes()).collect();
    let mut wallet = Wallet::deploy(&owners, 3, keys);
    let stored = actions_of(2, 40);
    let query_id = wallet.query_id(1);
    let signed = signed_root_with(0, &query_body_with(query_id, &stored));
    let root_signature = sign(&wallet.keys[0], &signed);
    wallet.send(query(root_signature, &signed)).expect("pending").expect_success();

    let other_bits = actions_of(2, 41);
    let other_ref = {
        let mut messages = stored.clone();
        messages[1] = actions_of(1, 40).remove(0);
        messages
    };
    // The request's own bits: the stored messages under another send mode.
    let other_mode = cell(|b| {
        b.append_u32(WALLET_ID).unwrap();
        b.append_u64(query_id).unwrap();
        for message in &stored {
            b.append_u8(2).unwrap();
            b.checked_append_reference(message.clone()).unwrap();
        }
    });
    // Identical bits, one more reference.
    let extra_ref = cell(|b| {
        b.append_u32(WALLET_ID).unwrap();
        b.append_u64(query_id).unwrap();
        for message in &stored {
            b.append_u8(3).unwrap();
            b.checked_append_reference(message.clone()).unwrap();
        }
        b.checked_append_reference(stored[0].clone()).unwrap();
    });
    for (label, body) in [
        ("send mode", other_mode),
        ("a message's bits", query_body_with(query_id, &other_bits)),
        ("a reference", query_body_with(query_id, &other_ref)),
        ("reference count", extra_ref),
    ] {
        let signed = signed_root_with(1, &body);
        let root_signature = sign(&wallet.keys[1], &signed);
        let error = wallet.refused(query(root_signature, &signed));
        assert!(error.contains("exit code: 36"), "{label}: {error}");
    }
    let signed = signed_root_with(1, &query_body_with(query_id, &stored));
    let root_signature = sign(&wallet.keys[1], &signed);
    wallet.send(query(root_signature, &signed)).expect("join").expect_success();
    assert_eq!(wallet.query_state(query_id), (0, 0b11));
}

/// The size check before acceptance: eight cells and 2048 bits after the query id pass,
/// a ninth cell or a 2049th bit is refused with exit 40, and so is a cell reached twice,
/// which the walk counts once per path.
#[test]
fn request_size_limits_are_enforced_before_acceptance() {
    let keys = vec![strong_key_cleared(0)];
    let owners: Vec<[u8; 32]> = keys.iter().map(|key| key.verifying_key().to_bytes()).collect();
    let mut wallet = Wallet::deploy(&owners, 2, keys);
    // `cells` cells in a chain, each holding `bits` data bits.
    let chain = |cells: usize, bits: usize| -> Cell {
        let mut next: Option<Cell> = None;
        for _ in 0..cells {
            let link = next.take();
            next = Some(cell(|b| {
                b.append_raw(&[0x77; 128], bits).unwrap();
                if let Some(link) = link {
                    b.checked_append_reference(link).unwrap();
                }
            }));
        }
        next.expect("at least one cell")
    };
    let mut offset = 0u64;
    let mut send = |wallet: &mut Wallet, message: Cell| {
        offset += 1;
        let signed = signed_root_with(0, &query_body_with(wallet.query_id(offset), &[message]));
        let root_signature = sign(&wallet.keys[0], &signed);
        wallet.send(query(root_signature, &signed))
    };
    // The query body cell itself is the first of the counted cells.
    send(&mut wallet, chain(7, 8)).expect("eight cells").expect_success();
    let error = match send(&mut wallet, chain(8, 8)) {
        Ok(_) => panic!("nine cells accepted"),
        Err(error) => error,
    };
    assert!(error.contains("exit code: 40"), "nine cells: {error}");
    // 8 bits of send mode plus two cells of 1020 bits is 2048; one bit more is over.
    send(&mut wallet, chain(2, 1020)).expect("2048 bits").expect_success();
    let error = match send(
        &mut wallet,
        cell(|b| {
            b.append_raw(&[0x77; 128], 1021).unwrap();
            b.checked_append_reference(chain(1, 1020)).unwrap();
        }),
    ) {
        Ok(_) => panic!("2049 bits accepted"),
        Err(error) => error,
    };
    assert!(error.contains("exit code: 40"), "2049 bits: {error}");
    // One leaf reached through four references is four cells, not one: 1 + 1 + 4 = 6
    // passes, and three such fan-outs (1 + 1 + 3 + 12 = 17) are refused.
    let leaf = chain(1, 8);
    let fan = cell(|b| {
        for _ in 0..4 {
            b.checked_append_reference(leaf.clone()).unwrap();
        }
    });
    send(&mut wallet, fan.clone()).expect("six counted cells").expect_success();
    let wide = cell(|b| {
        for _ in 0..3 {
            b.checked_append_reference(fan.clone()).unwrap();
        }
    });
    let error = match send(&mut wallet, wide) {
        Ok(_) => panic!("a shared subtree was counted once"),
        Err(error) => error,
    };
    assert!(error.contains("exit code: 40"), "shared subtree: {error}");
    // Three distinct cells, each referring four times to the next: 21 counted cells
    // under the request. The walk stops once the limit is passed, so this is a size
    // refusal; a walk over every path would exhaust the external credit first.
    let mut dag = chain(1, 8);
    for _ in 0..2 {
        let below = dag.clone();
        dag = cell(|b| {
            for _ in 0..4 {
                b.checked_append_reference(below.clone()).unwrap();
            }
        });
    }
    let error = match send(&mut wallet, dag) {
        Ok(_) => panic!("a tree of shared cells was accepted"),
        Err(error) => error,
    };
    assert!(error.contains("exit code: 40"), "tree of shared cells: {error}");
}
