use crate::config_params::{parse_config_param_34, parse_config_param_36};
use chain_block::{Deserializable, Serializable, ValidatorSet};
use serde_json::{Value, json};
pub fn fixture() -> Value {
    json!({"p34":{"utime_since":100,"utime_until":200,"total":1,"main":1,"list":[{
        "public_key":"0b".repeat(32),"weight_dec":"7","adnl_addr":"0c".repeat(32),
        "auth_binding":{"identity":"01".repeat(32),"stake_id":"02".repeat(32)}
    }]}})
}
#[test]
fn p0_control_config_preserves_native_binding() {
    let source = fixture();
    for key in ["p34", "p36"] {
        let raw = serde_json::to_vec(&json!({key:source["p34"]})).expect("fixture-json");
        let parsed =
            if key == "p34" { parse_config_param_34(&raw) } else { parse_config_param_36(&raw) }
                .expect("parse-p0-config");
        let restored =
            ValidatorSet::construct_from_full_cell(parsed.serialize().expect("native-serialize"))
                .expect("native-decode");
        assert!(restored.list()[0].auth_binding.is_some(), "control-binding");
        let binding = restored.list()[0].auth_binding.as_ref().expect("control-binding");
        assert_eq!(binding.identity.as_slice(), &[1; 32], "control-identity");
        assert_eq!(binding.stake_id.as_slice(), &[2; 32], "control-stake");
        assert_eq!(restored.total_weight(), 7, "control-weight");
    }
}
#[test]
fn p0_control_config_refuses_binding_downgrade() {
    for (label, field, value) in [
        ("control-missing-adnl", "adnl_addr", Value::Null),
        ("control-sequence-conflict", "mc_seq_no_since", Value::from(1)),
        ("control-null-binding", "auth_binding", Value::Null),
        (
            "control-zero-binding",
            "auth_binding",
            json!({"identity":"00".repeat(32),"stake_id":"02".repeat(32)}),
        ),
        (
            "control-uppercase-binding",
            "auth_binding",
            json!({"identity":"AB".repeat(32),"stake_id":"02".repeat(32)}),
        ),
        (
            "control-binding-tail",
            "auth_binding",
            json!({"identity":"01".repeat(32),"stake_id":"02".repeat(32),"extra":1}),
        ),
        (
            "control-malformed-binding",
            "auth_binding",
            json!({"identity":"01","stake_id":"02".repeat(32)}),
        ),
    ] {
        let mut source = fixture();
        source["p34"]["list"][0][field] = value;
        let raw = serde_json::to_vec(&source).expect("fixture-json");
        assert!(parse_config_param_34(&raw).is_err(), "{label}");
    }
    let mut source = fixture();
    source["p34"]["list"][0].as_object_mut().expect("fixture-entry").remove("auth_binding");
    source["p34"]["list"][0]["mc_seq_no_since"] = Value::from(123);
    let parsed = parse_config_param_34(&serde_json::to_vec(&source).expect("fixture-json"))
        .expect("legacy-extension");
    assert!(parsed.list()[0].auth_binding.is_none(), "legacy-no-binding");
    assert_eq!(parsed.list()[0].mc_seq_no_since, 123, "control-sequence-preserved");
}

#[test]
fn p0_control_config_numeric_bounds() {
    for (field, value) in [
        ("utime_since", (1u64 << 32) + 100),
        ("utime_until", (1u64 << 32) + 200),
        ("main", (1u64 << 16) + 1),
        ("total", (1u64 << 16) + 1),
        ("total", 2),
    ] {
        let mut source = fixture();
        source["p34"][field] = Value::from(value);
        assert!(
            parse_config_param_34(&serde_json::to_vec(&source).expect("fixture-json")).is_err(),
            "control-number-{field}"
        );
    }
    let mut source = fixture();
    let entry = source["p34"]["list"][0].clone();
    source["p34"]["list"] = Value::Array(vec![entry; 401]);
    source["p34"]["total"] = Value::from(401);
    assert!(
        parse_config_param_34(&serde_json::to_vec(&source).expect("fixture-json")).is_err(),
        "control-committee-ceiling"
    );
}

#[test]
fn p0_control_config_unique_json() {
    let source = serde_json::to_string(&fixture()).expect("fixture-json");
    for key in ["identity", "auth_binding", "p34"] {
        let marker = format!("\"{key}\":");
        let duplicate = format!("\"{key}\":null,{marker}");
        let raw = source.replacen(&marker, &duplicate, 1);
        assert_ne!(raw, source, "fixture-duplicate");
        assert_eq!(
            serde_json::from_str::<Value>(&raw).expect("permissive-json-fixture"),
            fixture(),
            "fixture-duplicate-value"
        );
        assert!(parse_config_param_34(raw.as_bytes()).is_err(), "control-duplicate-json");
    }
    let raw = source.replacen("\"identity\":", r#""\u0069dentity":null,"identity":"#, 1);
    assert_ne!(raw, source, "fixture-escaped");
    assert_eq!(
        serde_json::from_str::<Value>(&raw).expect("permissive-json-fixture"),
        fixture(),
        "fixture-escaped-value"
    );
    assert!(parse_config_param_34(raw.as_bytes()).is_err(), "control-escaped-duplicate-json");
    let mut oversized = source.clone();
    oversized.push_str(&" ".repeat(4_194_304));
    assert!(parse_config_param_34(oversized.as_bytes()).is_err(), "control-json-byte-limit");
    let mut large = fixture();
    large["padding"] = Value::Array(vec![Value::Null; 200_000]);
    assert!(
        parse_config_param_34(&serde_json::to_vec(&large).expect("fixture-json")).is_err(),
        "control-json-value-limit"
    );
    assert!(
        parse_config_param_34(format!("{source}{{}}").as_bytes()).is_err(),
        "control-json-trailing"
    );
}
