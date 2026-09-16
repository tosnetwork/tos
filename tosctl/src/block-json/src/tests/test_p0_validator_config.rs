use crate::{parse_config_with_mandatory_params, serialize_config_param};
use chain_block::*;
use serde_json::{Map, Value};

fn fixture(index: u32, kind: u8) -> ConfigParams {
    let mut member = ValidatorDescr::with_params(
        SigPubKey::from_bytes(&[11; 32]).expect("fixture-key"),
        7,
        if kind == 0 { None } else { Some(UInt256::with_array([12; 32])) },
    );
    if kind == 2 {
        member.mc_seq_no_since = 123;
    }
    if kind == 3 {
        member.auth_binding = Some(ValidatorAuthBinding {
            identity: UInt256::with_array([1; 32]),
            stake_id: UInt256::with_array([2; 32]),
        });
    }
    let set = ValidatorSet::new(100, 200, 1, vec![member]).expect("fixture-set");
    let mut config = ConfigParams::default();
    let param = match index {
        32 => ConfigParamEnum::ConfigParam32(ConfigParam32 { prev_validators: set }),
        33 => ConfigParamEnum::ConfigParam33(ConfigParam33 { prev_temp_validators: set }),
        34 => ConfigParamEnum::ConfigParam34(ConfigParam34 { cur_validators: set }),
        35 => ConfigParamEnum::ConfigParam35(ConfigParam35 { cur_temp_validators: set }),
        36 => ConfigParamEnum::ConfigParam36(ConfigParam36 { next_validators: set }),
        37 => ConfigParamEnum::ConfigParam37(ConfigParam37 { next_temp_validators: set }),
        _ => panic!("fixture-index"),
    };
    config.set_config(param).expect("fixture-config");
    config
}
fn json(config: &ConfigParams, index: u32) -> Map<String, Value> {
    serde_json::from_str(&serialize_config_param(config, index).expect("serialize-config"))
        .expect("fixture-json")
}
#[test]
fn json_native_roundtrip() {
    for index in 32..=37 {
        for kind in 0..4 {
            let config = fixture(index, kind);
            let raw = json(&config, index);
            if kind == 3 {
                assert!(
                    raw[&format!("p{index}")]["list"][0].get("auth_binding").is_some(),
                    "json-binding-export"
                );
            }
            if kind == 2 {
                assert_eq!(
                    raw[&format!("p{index}")]["list"][0]["mc_seq_no_since"],
                    123,
                    "json-sequence-export"
                );
            }
            let restored =
                parse_config_with_mandatory_params(&raw, &[index]).expect("parse-native-json");
            assert_eq!(
                restored
                    .config_cell_slice(index)
                    .expect("restored")
                    .cell()
                    .expect("fixture-cell")
                    .repr_hash(),
                config
                    .config_cell_slice(index)
                    .expect("original")
                    .cell()
                    .expect("fixture-cell")
                    .repr_hash(),
                "json-native-roundtrip"
            );
        }
    }
}
#[test]
fn json_binding_refuses_lossy_inputs() {
    let source = json(&fixture(34, 3), 34);
    for (label, field, value) in [
        ("json-missing-adnl", "adnl_addr", Value::Null),
        ("json-sequence-conflict", "mc_seq_no_since", Value::from(1)),
        ("json-null-binding", "auth_binding", Value::Null),
        ("json-missing-stake", "auth_binding", serde_json::json!({"identity":"01".repeat(32)})),
        (
            "json-zero-identity",
            "auth_binding",
            serde_json::json!({"identity":"00".repeat(32),"stake_id":"02".repeat(32)}),
        ),
        (
            "json-uppercase-binding",
            "auth_binding",
            serde_json::json!({"identity":"AB".repeat(32),"stake_id":"02".repeat(32)}),
        ),
        (
            "json-binding-tail",
            "auth_binding",
            serde_json::json!({"identity":"01".repeat(32),"stake_id":"02".repeat(32),"extra":1}),
        ),
    ] {
        let mut candidate = source.clone();
        candidate.get_mut("p34").expect("fixture")["list"][0][field] = value;
        assert!(parse_config_with_mandatory_params(&candidate, &[34]).is_err(), "{label}");
    }
    let duplicated = format!(
        "{{\"identity\":\"{}\",\"identity\":\"{}\",\"stake_id\":\"{}\"}}",
        "01".repeat(32),
        "02".repeat(32),
        "03".repeat(32)
    );
    assert!(
        serde_json::from_str::<ValidatorAuthBinding>(&duplicated).is_err(),
        "json-duplicate-binding-field"
    );
}

#[test]
fn json_binding_count_boundaries() {
    let source = json(&fixture(34, 3), 34);
    for (count, claimed, accepted, label) in [
        (400, 400, true, "json-count-boundary"),
        (401, 401, false, "json-committee-ceiling"),
        (1, 2, false, "json-count-binding"),
    ] {
        let mut candidate = source.clone();
        let member = candidate["p34"]["list"][0].clone();
        candidate.get_mut("p34").expect("fixture")["list"] = Value::Array(vec![member; count]);
        candidate.get_mut("p34").expect("fixture")["total"] = Value::from(claimed);
        assert_eq!(
            parse_config_with_mandatory_params(&candidate, &[34]).is_ok(),
            accepted,
            "{label}"
        );
    }
}
