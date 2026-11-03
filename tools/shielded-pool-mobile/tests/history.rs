// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::unwrap_used)]
mod common;
use base64::{engine::general_purpose::STANDARD, Engine};
use chain_block::{
    read_single_root_boc, write_boc, Deserializable, Serializable, Transaction, UInt256,
};
use common::{fixture, linked_fixture};
use serde_json::{json, Value};
use shielded_pool_mobile::{history::decode_transaction, Error, MAX_REQUEST_BYTES};

fn request(entry: &Value, pool: &str) -> Value {
    let bytes = hex::decode(entry["boc"].as_str().unwrap()).unwrap();
    let root = read_single_root_boc(&bytes).unwrap();
    let tx = Transaction::construct_from_cell(root).unwrap();
    json!({"version":1,"boc":STANDARD.encode(bytes),"expected_hash":entry["hash"],
        "expected_lt":entry["lt"].as_u64().unwrap().to_string(),"account_id":&pool[2..],
        "post_state_hash":hex::encode(tx.read_state_update().unwrap().new_hash.as_slice()),
        "maximum_time":tx.now().to_string()})
}
fn decode(request: &Value) -> Result<Value, Error> {
    let bytes = decode_transaction(&serde_json::to_vec(request).unwrap())?;
    Ok(serde_json::from_slice(&bytes).unwrap())
}

#[test]
fn real_sandbox_transactions_decode_all_event_types() {
    let fixture = fixture();
    for entry in fixture["transactions"].as_array().unwrap() {
        let decoded = decode(&request(entry, fixture["pool_address"].as_str().unwrap())).unwrap();
        assert_eq!(decoded["event"]["kind"], entry["kind"]);
    }
}

#[test]
fn linked_sandbox_copies_bind_every_previous_transaction() {
    let fixture = linked_fixture();
    let entries = fixture["transactions"].as_array().unwrap();
    let pool = fixture["pool_address"].as_str().unwrap();
    let mut next = request(entries.last().unwrap(), pool);
    for entry in entries.iter().rev() {
        next["boc"] = json!(STANDARD.encode(hex::decode(entry["boc"].as_str().unwrap()).unwrap()));
        let step = decode(&next).unwrap();
        assert_eq!(step["hash"], entry["hash"]);
        assert_eq!(step["event"]["kind"], entry["kind"]);
        next["expected_hash"] = step["previous_hash"].clone();
        next["expected_lt"] = step["previous_lt"].clone();
        next["post_state_hash"] = step["pre_state_hash"].clone();
        next["maximum_time"] = step["time"].clone();
        assert!(step.get("verified").is_none());
    }
    assert_eq!(next["expected_lt"], "0");
    assert_eq!(next["expected_hash"], "00".repeat(32));
}

#[test]
fn wrong_hash_lt_account_state_and_time_are_each_rejected() {
    let fixture = fixture();
    let entry = &fixture["transactions"].as_array().unwrap()[8];
    let baseline = request(entry, fixture["pool_address"].as_str().unwrap());
    assert!(decode(&baseline).is_ok());
    for (field, wrong) in [
        ("expected_hash", "11".repeat(32)),
        ("expected_lt", "1".into()),
        ("account_id", "11".repeat(32)),
        ("post_state_hash", "11".repeat(32)),
        ("maximum_time", "0".into()),
    ] {
        let mut changed = baseline.clone();
        changed[field] = json!(wrong);
        assert_eq!(decode(&changed), Err(Error::InvalidInput), "{field}");
    }
    let mut changed = baseline.clone();
    changed["expected_lt"] = json!("02000000013");
    assert_eq!(decode(&changed), Err(Error::InvalidInput));
    changed = baseline;
    changed["extra"] = json!(true);
    assert_eq!(decode(&changed), Err(Error::InvalidInput));
    assert_eq!(decode_transaction(&vec![0; MAX_REQUEST_BYTES + 1]), Err(Error::Limit));
}

#[test]
fn skipping_a_linked_transaction_is_rejected() {
    let fixture = linked_fixture();
    let entries = fixture["transactions"].as_array().unwrap();
    let latest = request(&entries[8], fixture["pool_address"].as_str().unwrap());
    let step = decode(&latest).unwrap();
    let mut skipped = request(&entries[6], fixture["pool_address"].as_str().unwrap());
    skipped["expected_hash"] = step["previous_hash"].clone();
    skipped["expected_lt"] = step["previous_lt"].clone();
    skipped["post_state_hash"] = step["pre_state_hash"].clone();
    skipped["maximum_time"] = step["time"].clone();
    assert_eq!(decode(&skipped), Err(Error::InvalidInput));
}

#[test]
fn inconsistent_and_non_descending_previous_links_are_rejected() {
    let fixture = fixture();
    let entry = &fixture["transactions"][8];
    let bytes = hex::decode(entry["boc"].as_str().unwrap()).unwrap();
    let tx = Transaction::construct_from_cell(read_single_root_boc(&bytes).unwrap()).unwrap();
    for (lt, hash) in [
        (tx.logical_time(), UInt256::from([1; 32])),
        (0, UInt256::from([1; 32])),
        (1, UInt256::default()),
    ] {
        let mut changed = tx.clone();
        changed.set_prev_trans_lt(lt);
        changed.set_prev_trans_hash(hash);
        let root = changed.serialize().unwrap();
        let mut entry = entry.clone();
        entry["boc"] = json!(hex::encode(write_boc(&root).unwrap()));
        entry["hash"] = json!(hex::encode(root.repr_hash().as_slice()));
        let request = request(&entry, fixture["pool_address"].as_str().unwrap());
        assert_eq!(decode(&request), Err(Error::InvalidInput));
    }
}

#[test]
fn history_c_abi_copies_a_checked_response_and_rejects_null() {
    use shielded_pool_mobile::{
        tos_shielded_history_transaction, tos_shielded_response_data, tos_shielded_response_free,
        tos_shielded_response_size, tos_shielded_response_status,
    };
    let fixture = fixture();
    let request = serde_json::to_vec(&request(
        &fixture["transactions"][8],
        fixture["pool_address"].as_str().unwrap(),
    ))
    .unwrap();
    unsafe {
        let response = tos_shielded_history_transaction(request.as_ptr(), request.len());
        assert_eq!(tos_shielded_response_status(response), 0);
        let copied = std::slice::from_raw_parts(
            tos_shielded_response_data(response),
            tos_shielded_response_size(response),
        )
        .to_vec();
        tos_shielded_response_free(response);
        let decoded: Value = serde_json::from_slice(&copied).unwrap();
        assert_eq!(decoded["event"]["kind"], "transact");
        let response = tos_shielded_history_transaction(std::ptr::null(), 1);
        assert_ne!(tos_shielded_response_status(response), 0);
        assert_eq!(tos_shielded_response_size(response), 0);
        tos_shielded_response_free(response);
    }
}
