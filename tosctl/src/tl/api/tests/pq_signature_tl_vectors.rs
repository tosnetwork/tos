use tl_api::pq_signature_set::{validate_lite, validate_node};
use tl_api::tos::{lite_server, tos_node, Bool};
use tl_api::{serialize_boxed, Deserializer};

fn fields(line: &str) -> Vec<&str> {
    line.split('\t').collect()
}

fn parse_node(bytes: &[u8]) -> anyhow::Result<tos_node::SignatureSet> {
    let mut remaining = bytes;
    let value = Deserializer::new(&mut remaining).read_boxed()?;
    anyhow::ensure!(remaining.is_empty(), "trailing bytes");
    Ok(value)
}

fn parse_lite(bytes: &[u8]) -> anyhow::Result<lite_server::SignatureSet> {
    let mut remaining = bytes;
    let value = Deserializer::new(&mut remaining).read_boxed()?;
    anyhow::ensure!(remaining.is_empty(), "trailing bytes");
    Ok(value)
}

#[test]
fn pq_signature_tl_vectors_match_cpp() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test/pq-native/pq-signature-tl-vectors.txt"
    );
    let text = std::fs::read_to_string(fixture).expect("shared PQ signature TL vectors");
    let rows: Vec<_> =
        text.lines().filter(|line| !line.is_empty() && !line.starts_with('#')).collect();
    assert_eq!(rows.len(), 6, "RUST_TL_VECTOR_ROW_COUNT");

    for line in rows {
        let f = fields(line);
        assert_eq!(f.len(), 14, "RUST_TL_VECTOR_BAD_COLUMNS case={}", f[0]);
        let name = f[0];
        let accept = f[1] == "accept";
        let reason = f[2];
        let carrier = f[3];
        let role = f[4];
        let cc_seqno: i32 = f[5].parse::<u32>().unwrap() as i32;
        let validator_set_hash: i32 = f[6].parse::<u32>().unwrap() as i32;
        let validator_id = hex::decode(f[7]).unwrap();
        let algorithm_id: i32 = f[8].parse().unwrap();
        let signature = hex::decode(f[9]).unwrap();
        let session_id = hex::decode(f[10]).unwrap();
        let slot: i32 = f[11].parse::<u32>().unwrap() as i32;
        let candidate = hex::decode(f[12]).unwrap();
        let wire = hex::decode(f[13]).unwrap();

        if carrier == "node" {
            let value = parse_node(&wire)
                .unwrap_or_else(|error| panic!("RUST_TL_VECTOR_NODE_PARSE case={name}: {error}"));
            let checked = validate_node(&value);
            if !accept {
                assert_eq!(checked, Err(reason), "RUST_TL_VECTOR_REASON_MISMATCH case={name}");
                continue;
            }
            checked.unwrap();
            assert_eq!(
                serialize_boxed(&value).unwrap(),
                wire,
                "RUST_TL_VECTOR_WIRE_MISMATCH case={name}"
            );
            let tos_node::SignatureSet::TosNode_SignatureSet_SimplexPq(value) = value else {
                panic!("RUST_TL_VECTOR_VARIANT case={name}")
            };
            assert_eq!(
                value.final_,
                if role == "final" { Bool::BoolTrue } else { Bool::BoolFalse },
                "RUST_TL_VECTOR_ROLE_MISMATCH case={name}"
            );
            assert_eq!(value.cc_seqno, cc_seqno);
            assert_eq!(value.validator_set_hash, validator_set_hash);
            assert_eq!(value.signatures.len(), 1);
            assert_eq!(&value.signatures[0].validator_id.as_slice()[..], validator_id);
            assert_eq!(
                value.signatures[0].algorithm_id, algorithm_id,
                "RUST_TL_VECTOR_ALGORITHM_MISMATCH case={name}"
            );
            assert_eq!(value.signatures[0].signature, signature);
            assert_eq!(&value.session_id.as_slice()[..], session_id);
            assert_eq!(value.slot, slot);
            assert_eq!(serialize_boxed(&value.candidate).unwrap(), candidate);
            continue;
        }

        let parsed = parse_lite(&wire);
        if reason == "wrong_constructor" {
            assert!(
                parsed.is_err(),
                "RUST_TL_VECTOR_UNEXPECTED_ACCEPT case={name} expected={reason}"
            );
            continue;
        }
        let value =
            parsed.unwrap_or_else(|error| panic!("RUST_TL_VECTOR_LITE_PARSE case={name}: {error}"));
        let checked = validate_lite(&value);
        if !accept {
            assert_eq!(checked, Err(reason), "RUST_TL_VECTOR_REASON_MISMATCH case={name}");
            continue;
        }
        checked.unwrap();
        assert_eq!(
            serialize_boxed(&value).unwrap(),
            wire,
            "RUST_TL_VECTOR_WIRE_MISMATCH case={name}"
        );
        let lite_server::SignatureSet::LiteServer_SignatureSet_SimplexPq(value) = value else {
            panic!("RUST_TL_VECTOR_VARIANT case={name}")
        };
        assert_eq!(role, "final");
        assert_eq!(value.cc_seqno, cc_seqno);
        assert_eq!(value.validator_set_hash, validator_set_hash);
        assert_eq!(value.signatures.len(), 1);
        assert_eq!(&value.signatures[0].validator_id.as_slice()[..], validator_id);
        assert_eq!(value.signatures[0].algorithm_id, algorithm_id);
        assert_eq!(value.signatures[0].signature, signature);
        assert_eq!(&value.session_id.as_slice()[..], session_id);
        assert_eq!(value.slot, slot, "RUST_TL_VECTOR_SLOT_MISMATCH case={name}");
        assert_eq!(value.candidate, candidate);
    }
}
