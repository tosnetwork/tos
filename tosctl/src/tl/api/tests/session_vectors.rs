// A consensus session id is computed independently by the node and by this crate, so
// agreeing on the schema is not enough: the bytes have to match. These vectors are
// produced authoritatively by the C++ side and record the member encoding, the whole
// serialized group and the resulting id, so a drift in any of the three is caught here
// rather than by two nodes failing to join the same session.
use chain_block::{sha256_digest, UInt256};
use tl_api::tos::engine::validator::validator::groupmember::{GroupMember, GroupMemberPQ};
use tl_api::tos::engine::validator::GroupMember as BoxedMember;
use tl_api::tos::validator::group::GroupNew;
use tl_api::IntoBoxed;

fn u256(hex_str: &str) -> UInt256 {
    let mut a = [0u8; 32];
    a.copy_from_slice(&hex::decode(hex_str).unwrap());
    UInt256::from(a)
}

#[test]
fn session_vectors_match_cpp() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test/pq-native/validator-session-vectors.txt"
    );
    let text = std::fs::read_to_string(path).expect("shared session vectors");

    // The fixture is produced from one validator whose fields are fixed here; only the
    // identities differ between cases, which is what the vectors are meant to pin down.
    let adnl = u256(&"c0".repeat(32));
    let weight = 5i64;

    let mut sessions = std::collections::HashMap::new();
    let mut checked = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(f.len(), 5, "bad vector line");
        let (name, ctor) = (f[0], u32::from_str_radix(f[1], 16).unwrap());
        let (member_hex, group_hex, session_hex) = (f[2], f[3], f[4]);

        let member: BoxedMember = match name {
            "classical" => GroupMember {
                // the identity a classical member commits to is derived from its key, and
                // the C++ side derives it before the member is built
                public_key_hash: u256(&member_hex[8..72]),
                adnl: adnl.clone(),
                weight,
            }
            .into_boxed(),
            "pq-a-key1" => GroupMemberPQ {
                validator_id: u256(&"a0".repeat(32)),
                key_id: u256(&"b0".repeat(32)),
                adnl: adnl.clone(),
                weight,
            }
            .into_boxed(),
            "pq-a-key2" => GroupMemberPQ {
                validator_id: u256(&"a0".repeat(32)),
                key_id: u256(&"b1".repeat(32)),
                adnl: adnl.clone(),
                weight,
            }
            .into_boxed(),
            other => panic!("unknown vector {other}"),
        };

        let member_bytes = tl_api::serialize_boxed(&member).unwrap();
        assert_eq!(hex::encode(&member_bytes), member_hex, "member bytes for {name}");
        assert_eq!(
            u32::from_le_bytes(member_bytes[..4].try_into().unwrap()),
            ctor,
            "constructor id for {name}"
        );

        let group = GroupNew {
            workchain: 0,
            shard: i64::from_le_bytes(0x8000_0000_0000_0000u64.to_le_bytes()),
            vertical_seqno: 0,
            last_key_block_seqno: 0,
            catchain_seqno: 1,
            config_hash: UInt256::default(),
            members: vec![member],
        }
        .into_boxed();
        let group_bytes = tl_api::serialize_boxed(&group).unwrap();
        assert_eq!(hex::encode(&group_bytes), group_hex, "group bytes for {name}");

        let session_id = sha256_digest(&group_bytes);
        assert_eq!(hex::encode(session_id), session_hex, "session id for {name}");

        sessions.insert(name.to_string(), session_hex.to_string());
        checked += 1;
    }
    assert!(checked >= 3, "expected the full vector set, saw {checked}");

    // Rotating only the key must move the session, which is the property the whole
    // identity split exists to give us.
    assert_ne!(sessions["pq-a-key1"], sessions["pq-a-key2"]);
    assert_ne!(sessions["classical"], sessions["pq-a-key1"]);
}
