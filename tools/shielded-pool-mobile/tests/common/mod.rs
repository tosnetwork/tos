// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::unwrap_used)]
use chain_block::{
    read_single_root_boc, write_boc, Deserializable, Serializable, Transaction, UInt256,
};
use serde_json::{json, Value};
pub fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../shielded-pool-circuit/fixtures/pool-history-development.json"
    ))
    .unwrap()
}
// The sandbox produces real transaction bodies/state updates but leaves each
// prev_trans field at zero. Link copies explicitly for this unit test; these
// copies are not claimed as published chain history or proof evidence.
pub fn linked_fixture() -> Value {
    let mut fixture = fixture();
    let mut previous_hash = UInt256::default();
    let mut previous_lt = 0;
    for entry in fixture["transactions"].as_array_mut().unwrap() {
        let bytes = hex::decode(entry["boc"].as_str().unwrap()).unwrap();
        let mut tx =
            Transaction::construct_from_cell(read_single_root_boc(&bytes).unwrap()).unwrap();
        tx.set_prev_trans_hash(previous_hash);
        tx.set_prev_trans_lt(previous_lt);
        let root = tx.serialize().unwrap();
        previous_hash = root.repr_hash();
        previous_lt = tx.logical_time();
        entry["boc"] = json!(hex::encode(write_boc(&root).unwrap()));
        entry["hash"] = json!(hex::encode(previous_hash.as_slice()));
    }
    fixture
}
