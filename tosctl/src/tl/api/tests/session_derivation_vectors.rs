// The node and tooling must agree on both layers of session identity: the
// commitment to the governing configuration and the TL group hash. This is
// the same checked-in vector consumed by the C++ production helper's gate.
use chain_block::{read_single_root_boc, sha256_digest, UInt256};
use tl_api::tos::engine::validator::validator::groupmember::GroupMemberPQ;
use tl_api::tos::validator::group::GroupNew;
use tl_api::IntoBoxed;

fn u256(value: &str) -> UInt256 {
    let bytes = hex::decode(value).expect("hex field");
    assert_eq!(bytes.len(), 32);
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    UInt256::from(array)
}

#[test]
fn session_derivation_matches_cpp() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test/pq-native/validator-session-derivation-vectors.tsv"
    );
    let text = std::fs::read_to_string(path).expect("shared session derivation vector");
    let mut lines = text.lines();
    let header = lines.next().expect("header");
    assert_eq!(header.split('\t').count(), 15, "vector header shape");
    let fields: Vec<&str> = lines.next().expect("one vector row").split('\t').collect();
    assert_eq!(fields.len(), 15, "vector row shape");
    assert!(lines.next().is_none(), "exactly one fixed vector is expected");

    let global_id: i32 = fields[0].parse().unwrap();
    let param29_hash = u256(fields[1]);
    let selected_cell = read_single_root_boc(hex::decode(fields[2]).unwrap()).unwrap();
    assert_eq!(selected_cell.repr_hash(), u256(fields[3]));

    let mut config_preimage = b"TOS-VALIDATOR-SESSION-CONFIG-v1".to_vec();
    config_preimage.extend_from_slice(&global_id.to_le_bytes());
    config_preimage.extend_from_slice(param29_hash.as_slice());
    config_preimage.extend_from_slice(selected_cell.repr_hash().as_slice());
    let session_config_hash = UInt256::from(sha256_digest(&config_preimage));
    assert_eq!(session_config_hash, u256(fields[13]));

    let member = GroupMemberPQ {
        validator_id: u256(fields[9]),
        key_id: u256(fields[10]),
        adnl: u256(fields[11]),
        weight: fields[12].parse().unwrap(),
    }
    .into_boxed();
    let shard = fields[5].parse::<u64>().unwrap();
    let group = GroupNew {
        workchain: fields[4].parse().unwrap(),
        shard: i64::from_le_bytes(shard.to_le_bytes()),
        vertical_seqno: fields[6].parse().unwrap(),
        last_key_block_seqno: fields[7].parse().unwrap(),
        catchain_seqno: fields[8].parse().unwrap(),
        config_hash: session_config_hash,
        members: vec![member],
    }
    .into_boxed();
    let bytes = tl_api::serialize_boxed(&group).unwrap();
    assert_eq!(UInt256::from(sha256_digest(&bytes)), u256(fields[14]));
}
