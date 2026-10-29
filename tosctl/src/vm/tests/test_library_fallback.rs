// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
use chain_block::{
    sha256_digest, BuilderData, Cell, CellType, ExceptionCode, HashmapE, IBitstring,
};
use tos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, Engine},
    stack::{
        continuation::{ContinuationData, ContinuationType},
        integer::IntegerData,
        savelist::SaveList,
        Stack, StackItem,
    },
};

fn target() -> Cell {
    BuilderData::with_raw(b"hello library".to_vec(), 104).unwrap().into_cell().unwrap()
}

fn collection(kind: &str) -> HashmapE {
    let target = target();
    let mut dictionary = HashmapE::with_bit_len(256);
    match kind {
        "good" => {
            dictionary.setref(target.repr_hash().into(), target).unwrap();
        }
        "wrong-hash" => {
            dictionary.setref(target.repr_hash().into(), Cell::default()).unwrap();
        }
        "missing-ref" => {
            let mut value = BuilderData::new();
            value.append_bit_one().unwrap();
            dictionary.set_builder(target.repr_hash().into(), &value).unwrap();
        }
        "malformed" => {
            let root = BuilderData::with_raw(vec![0], 1).unwrap().into_cell().unwrap();
            return HashmapE::with_hashmap(256, Some(root));
        }
        _ => panic!("unknown fixture"),
    }
    dictionary
}

fn engine(kinds: &[&str]) -> Engine {
    let mut reference = BuilderData::with_raw(vec![2], 8).unwrap();
    reference.append_raw(target().repr_hash().as_slice(), 256).unwrap();
    reference.set_type(CellType::LibraryReference);
    let mut code = BuilderData::with_raw(vec![0x88, 0xf9, 0x03], 24).unwrap();
    code.checked_append_reference(reference.into_cell().unwrap()).unwrap();
    let mut controls = SaveList::new();
    controls.put(7, StackItem::tuple(vec![])).unwrap();
    controls
        .put(3, StackItem::continuation(ContinuationData::with_type(ContinuationType::Quit(11))))
        .unwrap();
    let mut engine = Engine::with_capabilities(0)
        .setup_checked(
            code.into_cell().unwrap(),
            controls,
            Stack::new(),
            Gas::test_with_limit(1_000_000),
            kinds.iter().map(|kind| collection(kind)).collect(),
        )
        .unwrap();
    engine.set_block_version(16);
    engine
}

fn succeeds(kinds: &[&str]) {
    let mut engine = engine(kinds);
    assert_eq!(engine.execute().expect("later usable collection must be reached"), 0);
    assert_eq!(engine.gas_used(), 150, "dictionary lookup must be uncharged");
    assert_eq!(engine.stack().depth(), 1);
    assert_eq!(
        engine.stack().get(0).unwrap(),
        &StackItem::integer(IntegerData::from_unsigned_bytes_be(sha256_digest(b"hello library")))
    );
}

#[test]
fn wrong_library_hash_does_not_shadow_later_valid_collection() {
    succeeds(&["wrong-hash", "good"]);
}

#[test]
fn missing_library_reference_does_not_shadow_later_valid_collection() {
    succeeds(&["missing-ref", "good"]);
}

#[test]
fn malformed_dictionary_does_not_shadow_later_valid_collection() {
    succeeds(&["malformed", "good"]);
}

#[test]
fn first_usable_library_wins_over_later_invalid_collections() {
    succeeds(&["good", "wrong-hash", "missing-ref", "malformed"]);
}

#[test]
fn all_unusable_libraries_keep_missing_library_exit_and_gas() {
    let mut engine = engine(&["wrong-hash", "missing-ref", "malformed"]);
    let error = engine.execute().expect_err("no usable library exists");
    assert_eq!(tvm_exception_code(&error), Some(ExceptionCode::CellUnderflow));
    assert_eq!(engine.gas_used(), 194);
    assert_eq!(engine.stack().get(0).unwrap(), &StackItem::int(0));
}
