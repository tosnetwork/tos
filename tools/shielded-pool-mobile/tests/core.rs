// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
// A failed fixture or assertion must fail the test process.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use shielded_pool_circuit::{
    field::{fr_to_be, Fr, MODULUS_BE},
    notes, wire,
};
use shielded_pool_mobile::{
    issue_descriptor, scan_batch, Error, MAX_NULLIFIERS, MAX_OUTPUTS, MAX_REQUEST_BYTES,
};
use shielded_pool_wallet::{
    delivery::{self, Kind, Plaintext},
    descriptor::Descriptor,
    keys::PoolInstance,
};

const SEED: [u8; 32] = [0x42; 32];
fn field(value: Fr) -> String {
    hex::encode(fr_to_be(&value))
}
fn request(outputs: Vec<Value>, nullifiers: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({"version":1,"execution_domain":field(Fr::from(7u64)),
        "outputs":outputs,"published_nullifiers":nullifiers}))
    .unwrap()
}
fn output(amount: u128, index: u64) -> (Value, String) {
    let instance = PoolInstance::new(&SEED, Fr::from(7u64));
    let plaintext = Plaintext {
        slot: 0,
        kind: Kind::Ordinary,
        amount,
        note_secret: Fr::from(123u64),
        owner_nf_key_hash: instance.owner_nf_key_hash(index).unwrap(),
        note_key_index: index,
        pq_auth_key_hash: instance.pq_auth_key_hash(index).unwrap(),
    };
    let payload = delivery::seal(
        &instance.mlkem_encapsulation_key().unwrap(),
        instance.execution_domain(),
        &plaintext,
    )
    .unwrap();
    let data_hash = wire::output_data_hash(&payload);
    let owner = notes::owner_commitment(
        plaintext.owner_nf_key_hash,
        plaintext.pq_auth_key_hash,
        plaintext.note_secret,
    );
    let body = notes::note_body_commitment(owner, Fr::from(amount), data_hash);
    let nullifier = notes::nullifier(body, instance.owner_nf_key(index).unwrap());
    (
        json!({"slot":0,"output_data":STANDARD.encode(payload),"output_data_hash":field(data_hash),
        "note_body":field(body),"recovered":null,"leaf_index":"9"}),
        field(nullifier),
    )
}

#[test]
fn descriptor_uses_existing_crypto_and_full_unsigned_index() {
    let domain = fr_to_be(&Fr::from(7u64));
    let bytes = issue_descriptor(&SEED, &domain, u64::MAX).unwrap();
    let descriptor = Descriptor::from_bytes(&bytes).unwrap();
    assert_eq!(descriptor.note_key_index, u64::MAX);
    descriptor.require_domain(Fr::from(7u64)).unwrap();
    assert_eq!(issue_descriptor(&SEED, &MODULUS_BE, 0), Err(Error::InvalidInput));
}

#[test]
fn decrypts_real_payload_and_reconciles_spent_nullifiers() {
    let (output, nullifier) = output(1_234_567_890, 7);
    let result = scan_batch(&SEED, &request(vec![output.clone()], vec![])).unwrap();
    let result: Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(result["batch_unspent_balance"], "1234567890");
    assert_eq!(result["next_note_key_index"], "8");
    assert_eq!(result["notes"][0]["leaf_index"], "9");
    assert_eq!(result["notes"][0]["nullifier"], nullifier);
    assert_eq!(result["notes"][0]["spent"], false);
    let spent = scan_batch(&SEED, &request(vec![output], vec![json!(nullifier)])).unwrap();
    let spent: Value = serde_json::from_slice(&spent).unwrap();
    assert_eq!(spent["batch_unspent_balance"], "0");
    assert_eq!(spent["notes"][0]["spent"], true);
}

#[test]
fn duplicate_note_is_counted_once_and_another_seed_cannot_read_it() {
    let (output, _) = output(99, 1);
    let input = request(vec![output.clone(), output], vec![]);
    let result = scan_batch(&SEED, &input).unwrap();
    let result: Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(result["batch_unspent_balance"], "99");
    let other = scan_batch(&[0x43; 32], &input).unwrap();
    let other: Value = serde_json::from_slice(&other).unwrap();
    assert_eq!(other["notes"], json!([]));
    assert_eq!(other["batch_unspent_balance"], "0");
}

#[test]
fn authenticated_note_body_mismatch_is_not_balance() {
    let (mut output, _) = output(99, 1);
    output["note_body"] = json!(field(Fr::from(0u64)));
    let result = scan_batch(&SEED, &request(vec![output], vec![])).unwrap();
    let result: Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(result["batch_unspent_balance"], "0");
    assert_eq!(result["diagnostics_count"], 1);
}

#[test]
fn limits_are_enforced_and_invalid_data_does_not_become_empty_balance() {
    assert_eq!(scan_batch(&SEED, b"{}"), Err(Error::InvalidInput));
    assert_eq!(scan_batch(&SEED, &vec![b' '; MAX_REQUEST_BYTES + 1]), Err(Error::Limit));
    let (output, _) = output(99, 1);
    assert_eq!(
        scan_batch(&SEED, &request(vec![output.clone(); MAX_OUTPUTS + 1], vec![])),
        Err(Error::Limit)
    );
    let nf = json!(field(Fr::from(1u64)));
    assert_eq!(
        scan_batch(&SEED, &request(vec![], vec![nf.clone(); MAX_NULLIFIERS + 1])),
        Err(Error::Limit)
    );
    assert_eq!(scan_batch(&SEED, &request(vec![], vec![nf.clone(), nf])), Err(Error::InvalidInput));
    for change in [
        json!({"leaf_index":"09"}),
        json!({"output_data":"not-base64"}),
        json!({"slot":3}),
        json!({"recovered":"-1"}),
        json!({"output_data_hash":hex::encode(MODULUS_BE)}),
    ] {
        let mut changed = output.clone();
        for (key, value) in change.as_object().unwrap() {
            changed[key] = value.clone();
        }
        assert_eq!(scan_batch(&SEED, &request(vec![changed], vec![])), Err(Error::InvalidInput));
    }
}

#[test]
fn ffi_owns_and_releases_response_and_checks_lengths_before_reading() {
    use shielded_pool_mobile::*;
    unsafe {
        let domain = fr_to_be(&Fr::from(7u64));
        let response = tos_shielded_descriptor(SEED.as_ptr(), 32, domain.as_ptr(), 32, 1);
        assert_eq!(tos_shielded_response_status(response), 0);
        assert_eq!(tos_shielded_response_size(response), 2573);
        let bytes = std::slice::from_raw_parts(tos_shielded_response_data(response), 2573);
        assert_eq!(Descriptor::from_bytes(bytes).unwrap().note_key_index, 1);
        tos_shielded_response_free(response);
        let bad = tos_shielded_scan(SEED.as_ptr(), 31, std::ptr::null(), usize::MAX);
        assert_eq!(tos_shielded_response_status(bad), 1);
        assert_eq!(tos_shielded_response_size(bad), 0);
        tos_shielded_response_free(bad);
        tos_shielded_response_free(std::ptr::null_mut());
    }
}
