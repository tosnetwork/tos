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
        let mut bc = Blockchain::new().expect("blockchain");
        let code = compile_func_with_stdlib(&[smartcont("multisig-code.fc")]).expect("compile");
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

/// A weak key stored by a hand-built StateInit cannot open a query as root. The root is
/// checked right after acceptance (before it, the external gas credit has no room), so a
/// forged root signature is accepted, refused with exit 45, and rolled back: nothing is
/// recorded. A key the verifier cannot be fooled under fails its signature check first.
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
                let result = wallet.send(query(forged, &signed)).expect("accepted for the check");
                assert_eq!(exit_code(&result), ERR_WEAK_OWNER, "key {i}: forged root counted");
                assert_eq!(wallet.query_state(query_id), (0, 0), "key {i}: a query was recorded");
            }
            None => {
                let signed = signed_root(2, None, wallet.query_id(100));
                let error = wallet.refused(query([0u8; 64], &signed));
                assert!(error.contains("exit code: 32"), "key {i}: {error}");
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
        let result = wallet.send(query(forged, &signed)).expect("accepted for the check");
        assert_eq!(exit_code(&result), ERR_WEAK_OWNER, "alias {index} signed as root");
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
