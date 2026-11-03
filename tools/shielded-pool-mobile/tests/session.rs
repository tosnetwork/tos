// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::unwrap_used)]
mod common;
use base64::{engine::general_purpose::STANDARD, Engine};
use chain_block::{read_single_root_boc, write_boc, Deserializable, Serializable, Transaction};
use serde_json::{json, Value};
use shielded_pool_mobile::{
    replay_ffi::*, tos_shielded_response_data, tos_shielded_response_free,
    tos_shielded_response_size, tos_shielded_response_status, TosShieldedResponse,
};

struct Session(*mut TosShieldedReplay);
impl Drop for Session {
    fn drop(&mut self) {
        unsafe { tos_shielded_replay_free(self.0) }
    }
}
fn create(request: &Value) -> Session {
    let bytes = serde_json::to_vec(request).unwrap();
    let p = unsafe { tos_shielded_replay_create(bytes.as_ptr(), bytes.len()) };
    assert!(!p.is_null());
    Session(p)
}
fn read(response: *mut TosShieldedResponse) -> Result<Value, i32> {
    struct Owned(*mut TosShieldedResponse);
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe { tos_shielded_response_free(self.0) }
        }
    }
    let response = Owned(response);
    unsafe {
        let status = tos_shielded_response_status(response.0);
        if status != 0 {
            assert_eq!(tos_shielded_response_size(response.0), 0);
            return Err(status);
        }
        let bytes = std::slice::from_raw_parts(
            tos_shielded_response_data(response.0),
            tos_shielded_response_size(response.0),
        );
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}
fn fixture_request(f: &Value) -> Value {
    let txs = f["transactions"].as_array().unwrap();
    let e = txs.last().unwrap();
    let t = Transaction::construct_from_cell(
        read_single_root_boc(hex::decode(e["boc"].as_str().unwrap()).unwrap()).unwrap(),
    )
    .unwrap();
    let pool = hex::decode(f["account_data"].as_str().unwrap()).unwrap();
    let gas = hex::decode(f["gas_prices_param21"].as_str().unwrap()).unwrap();
    json!({"version":1,"global_id":3,"account_id":&f["pool_address"].as_str().unwrap()[2..],
        "last_hash":e["hash"],"last_lt":t.logical_time().to_string(),"account_root":hex::encode(t.read_state_update().unwrap().new_hash.as_slice()),"shard_time":t.now().to_string(),
        "pool_state_boc":STANDARD.encode(&pool),"pool_data_hash":hex::encode(read_single_root_boc(pool).unwrap().repr_hash().as_slice()),
        "gas_boc":STANDARD.encode(&gas),"gas_hash":hex::encode(read_single_root_boc(gas).unwrap().repr_hash().as_slice())})
}
fn push_all(session: &Session, f: &Value) {
    for e in f["transactions"].as_array().unwrap() {
        let bytes = hex::decode(e["boc"].as_str().unwrap()).unwrap();
        assert_eq!(unsafe { tos_shielded_replay_push(session.0, bytes.as_ptr(), bytes.len()) }, 0);
    }
}

#[test]
fn full_session_lifecycle_requires_finish_and_bounds_scan_pages() {
    let f = common::linked_fixture();
    let session = create(&fixture_request(&f));
    assert!(unsafe { read(tos_shielded_replay_info(session.0)) }.is_err());
    let seed = [0x42; 32];
    assert!(unsafe { read(tos_shielded_replay_scan(session.0, seed.as_ptr(), 32, 0, 1)) }.is_err());
    push_all(&session, &f);
    assert_eq!(unsafe { tos_shielded_replay_finish(session.0) }, 0);
    let info = unsafe { read(tos_shielded_replay_info(session.0)) }.unwrap();
    let total = info["total_outputs"].as_str().unwrap().parse::<usize>().unwrap();
    assert!(total > 0);
    let page =
        unsafe { read(tos_shielded_replay_scan(session.0, seed.as_ptr(), 32, 0, total)) }.unwrap();
    assert_eq!(page["total_outputs"], total.to_string());
    assert_eq!(page["output_count"], total.to_string());
    assert!(page.get("verified").is_none());
    for (offset, count) in [(usize::MAX, 1), (0, 513), (total, 1), (0, 0)] {
        assert!(unsafe {
            read(tos_shielded_replay_scan(session.0, seed.as_ptr(), 32, offset, count))
        }
        .is_err());
    }
    assert!(unsafe { read(tos_shielded_replay_info(session.0)) }.is_ok());
    assert_ne!(unsafe { tos_shielded_replay_push(session.0, std::ptr::null(), 0) }, 0);
    assert!(unsafe { read(tos_shielded_replay_info(session.0)) }.is_err());
    assert_ne!(unsafe { tos_shielded_replay_finish(session.0) }, 0);
}

#[test]
fn rejected_creation_and_premature_finish_return_no_ledger() {
    let f = common::linked_fixture();
    let baseline = fixture_request(&f);
    for key in ["gas_hash", "pool_data_hash"] {
        let mut r = baseline.clone();
        r[key] = json!("11".repeat(32));
        let bytes = serde_json::to_vec(&r).unwrap();
        assert!(unsafe { tos_shielded_replay_create(bytes.as_ptr(), bytes.len()) }.is_null());
    }
    let session = create(&baseline);
    assert_ne!(unsafe { tos_shielded_replay_finish(session.0) }, 0);
    assert!(unsafe { read(tos_shielded_replay_info(session.0)) }.is_err());
    let bytes = hex::decode(f["transactions"][0]["boc"].as_str().unwrap()).unwrap();
    assert_ne!(unsafe { tos_shielded_replay_push(session.0, bytes.as_ptr(), bytes.len()) }, 0);
    unsafe {
        assert!(tos_shielded_replay_create(std::ptr::null(), 0).is_null());
        assert_ne!(tos_shielded_replay_finish(std::ptr::null_mut()), 0);
        tos_shielded_replay_free(std::ptr::null_mut());
    }
}

// Synthetic unit transaction/state, not a chain proof. Its note uses the actual
// wallet ML-KEM/AEAD implementation so success cannot be an always-empty scan.
#[test]
fn completed_ledger_scan_decrypts_a_real_owned_note() {
    use chain_block::{BuilderData, IBitstring, SliceData, UInt256};
    use shielded_pool_circuit::{
        field::{fr_to_be, Fr},
        notes, wire,
    };
    use shielded_pool_codec::{store_coins, DepositBody, PoolState, STATE_MAGIC, STATE_VERSION};
    use shielded_pool_wallet::{
        delivery::{self, Kind, Plaintext},
        keys::PoolInstance,
        ledger::{Event, Ledger},
    };
    let f = common::fixture();
    let account: [u8; 32] =
        hex::decode(&f["pool_address"].as_str().unwrap()[2..]).unwrap().try_into().unwrap();
    let seed = [0x42; 32];
    let keys = PoolInstance::new(&seed, wire::execution_domain(3, &account));
    let index = 7;
    let plain = Plaintext {
        slot: 0,
        kind: Kind::Ordinary,
        amount: 1_000_000_000,
        note_secret: Fr::from(123u64),
        owner_nf_key_hash: keys.owner_nf_key_hash(index).unwrap(),
        note_key_index: index,
        pq_auth_key_hash: keys.pq_auth_key_hash(index).unwrap(),
    };
    let payload =
        delivery::seal(&keys.mlkem_encapsulation_key().unwrap(), keys.execution_domain(), &plain)
            .unwrap();
    let owner =
        notes::owner_commitment(plain.owner_nf_key_hash, plain.pq_auth_key_hash, plain.note_secret);
    let body = DepositBody {
        query_id: 0,
        amount: plain.amount,
        owner_commitment: fr_to_be(&owner),
        output_data: payload.clone(),
    }
    .build()
    .unwrap();
    let mut tx = Transaction::construct_from_cell(
        read_single_root_boc(hex::decode(f["transactions"][1]["boc"].as_str().unwrap()).unwrap())
            .unwrap(),
    )
    .unwrap();
    tx.set_prev_trans_lt(0);
    tx.set_prev_trans_hash(UInt256::default());
    let mut message = tx.read_in_msg().unwrap().unwrap();
    message.set_body(SliceData::load_cell(body).unwrap());
    tx.write_in_msg(Some(&message)).unwrap();
    let root = tx.serialize().unwrap();
    let mut ledger = Ledger::genesis();
    ledger
        .apply(
            &Event::Deposit { amount: plain.amount, owner_commitment: owner, output_data: payload },
            0,
        )
        .unwrap();
    let c = ledger.checkpoint();
    let genesis = read_single_root_boc(include_bytes!(
        "../../../artifacts/shielded-pool/deployments/epoch4-v16/data.boc"
    ))
    .unwrap();
    let state = PoolState::parse(&genesis).unwrap();
    let mut b = BuilderData::new();
    b.append_u32(STATE_MAGIC).unwrap();
    b.append_u16(STATE_VERSION).unwrap();
    b.append_raw(&fr_to_be(&c.commitment_root), 256).unwrap();
    b.append_u64(c.commitment_next_index).unwrap();
    b.append_u32(0).unwrap();
    b.append_raw(&fr_to_be(&c.nullifier_root), 256).unwrap();
    b.append_u64(c.nullifier_next_index).unwrap();
    b.append_u32(state.last_anchor_epoch).unwrap();
    store_coins(&mut b, c.native_liability).unwrap();
    store_coins(&mut b, state.reserve_floor).unwrap();
    for i in 0..4 {
        b.checked_append_reference(genesis.reference(i).unwrap()).unwrap();
    }
    let state_root = b.into_cell().unwrap();
    let mut request = fixture_request(&common::linked_fixture());
    request["last_hash"] = json!(hex::encode(root.repr_hash().as_slice()));
    request["last_lt"] = json!(tx.logical_time().to_string());
    request["account_root"] =
        json!(hex::encode(tx.read_state_update().unwrap().new_hash.as_slice()));
    request["shard_time"] = json!(tx.now().to_string());
    request["pool_state_boc"] = json!(STANDARD.encode(write_boc(&state_root).unwrap()));
    request["pool_data_hash"] = json!(hex::encode(state_root.repr_hash().as_slice()));
    let session = create(&request);
    let boc = write_boc(&root).unwrap();
    assert_eq!(unsafe { tos_shielded_replay_push(session.0, boc.as_ptr(), boc.len()) }, 0);
    assert_eq!(unsafe { tos_shielded_replay_finish(session.0) }, 0);
    let page =
        unsafe { read(tos_shielded_replay_scan(session.0, seed.as_ptr(), 32, 0, 1)) }.unwrap();
    assert_eq!(page["scan"]["batch_unspent_balance"], "1000000000");
    assert_eq!(page["scan"]["notes"][0]["leaf_index"], "0");
    assert_eq!(page["scan"]["next_note_key_index"], "8");
}

#[test]
fn receive_binding_is_checked_when_creating_a_replay() {
    let f = common::linked_fixture();
    let mut request = fixture_request(&f);
    let data = hex::decode(f["account_data"].as_str().unwrap()).unwrap();
    let config =
        shielded_pool_codec::PoolState::parse(&read_single_root_boc(data).unwrap()).unwrap().config;
    let mut binding = [1; 228];
    binding[..4].copy_from_slice(&3i32.to_be_bytes());
    hex::decode_to_slice(request["account_id"].as_str().unwrap(), &mut binding[4..36]).unwrap();
    binding[132..164].copy_from_slice(&config.profile_hash);
    binding[164..196].copy_from_slice(&config.poseidon_manifest_hash);
    binding[196..228].copy_from_slice(&config.groth16_vk_hash);
    request["receive_binding"] = json!(hex::encode(binding));
    let _valid = create(&request);
    for offset in [0, 4, 132, 164, 196] {
        let mut invalid = binding;
        invalid[offset] ^= 1;
        request["receive_binding"] = json!(hex::encode(invalid));
        let bytes = serde_json::to_vec(&request).unwrap();
        assert!(unsafe { tos_shielded_replay_create(bytes.as_ptr(), bytes.len()) }.is_null());
    }
}
