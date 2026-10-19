use tos_health_core::{
    consensus_v2::Consensus,
    native::{canonical_hash, parse_native, NativeEnvelopeV2, NativeRecord},
};

const BODY: &str = include_str!("fixtures/native-core.prom");
fn fixture() -> serde_json::Value {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/native-core.json")).unwrap();
    value["source_version"] = "native-core-v2".into();
    value["coverage"]["sampling_policy"] = "native-core-v2-concurrent-bounded".into();
    value["payload"]["consensus"] =
        serde_json::from_str(include_str!("fixtures/consensus-v2.synthetic.json")).unwrap();
    value["quality"]["instrumentation_complete"] = false.into();
    rehash(&mut value);
    value
}
fn rehash(value: &mut serde_json::Value) {
    value["content_hash"] = canonical_hash(&value["payload"]).unwrap().into();
}
fn validate(value: &serde_json::Value) -> Result<(), String> {
    let native: NativeEnvelopeV2 =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    native.paired("v1", &"a".repeat(64), "1", &native.process_epoch, BODY)
}
#[test]
fn exact_v2_and_v1_coexist_without_fallback() {
    let value = fixture();
    validate(&value).unwrap();
    assert!(matches!(
        parse_native(&serde_json::to_vec(&value).unwrap()).unwrap(),
        NativeRecord::V2(_)
    ));
    let legacy = include_bytes!("fixtures/native-core.json");
    assert!(matches!(parse_native(legacy).unwrap(), NativeRecord::V1(_)));
    let mut wrong = value.clone();
    wrong["source_version"] = "native-core-v1".into();
    assert!(parse_native(&serde_json::to_vec(&wrong).unwrap()).is_err());
    let mut wrong = value;
    wrong["payload"].as_object_mut().unwrap().remove("consensus");
    assert!(parse_native(&serde_json::to_vec(&wrong).unwrap()).is_err());
    assert!(parse_native(&vec![b' '; 262_145]).is_err());
}
#[test]
fn unknown_phase_replay_and_integer_overflow_refuse() {
    let mut value = fixture();
    value["payload"]["consensus"]["actions"][1]["replay"]["signed_record"]["phases"]["signed"] =
        "1".into();
    rehash(&mut value);
    assert!(validate(&value).is_err());
    let mut value = fixture();
    value["payload"]["consensus"]["sessions"]["started"] = "18446744073709551616".into();
    rehash(&mut value);
    assert!(validate(&value).is_err());
    let mut value = fixture();
    value["payload"]["consensus"]["sessions"]["started"] = "01".into();
    rehash(&mut value);
    assert!(validate(&value).is_err());
    let mut value = fixture();
    value["payload"]["consensus"]["actions"][0]["unexpected"] = true.into();
    rehash(&mut value);
    assert!(validate(&value).is_err());
}
#[test]
fn incomplete_capability_and_context_mismatch_refuse() {
    let mut value = fixture();
    value["payload"]["consensus"]["actions"][0]["accounting_complete"] = false.into();
    rehash(&mut value);
    assert!(validate(&value).is_err());
    let mut value = fixture();
    value["payload"]["consensus"]["capabilities"]["vote_assigned"]["enabled"] = true.into();
    rehash(&mut value);
    assert!(validate(&value).is_err());
    let mut value = fixture();
    value["payload"]["consensus"]["contexts"] = serde_json::json!([{
        "network_id":"a".repeat(64),"scope":{"scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808"},
        "session_id":"b".repeat(64),"current_slot":1,"last_finalized_slot":0,
        "lifecycle":"active","stop_started_monotonic_ns":null
    }]);
    rehash(&mut value);
    validate(&value).unwrap();
    value["payload"]["consensus"]["contexts"][0]["scope"]["shard"] = "1".into();
    rehash(&mut value);
    assert!(validate(&value).is_err());
    value["payload"]["consensus"]["contexts"][0]["scope"]["shard"] = "9223372036854775808".into();
    value["payload"]["consensus"]["contexts"][0]["network_id"] = "c".repeat(64).into();
    rehash(&mut value);
    assert!(validate(&value).is_err());
}
#[test]
fn pair_hash_generation_and_eof_refuse() {
    let mut value = fixture();
    value["payload"]["consensus"]["post_terminal_progress"] = "1".into();
    rehash(&mut value);
    assert!(validate(&value).is_err());
    let value = fixture();
    let typed: NativeEnvelopeV2 = serde_json::from_value(value).unwrap();
    assert!(typed.paired("v1", &"a".repeat(64), "2", &typed.process_epoch, BODY).is_err());
    assert!(typed
        .paired("v1", &"a".repeat(64), "1", &typed.process_epoch, BODY.trim_end())
        .is_err());
    assert!(typed.paired("v1", &"b".repeat(64), "1", &typed.process_epoch, BODY).is_err());
}
#[test]
fn synthetic_consensus_shape_is_exact() {
    let value: Consensus =
        serde_json::from_str(include_str!("fixtures/consensus-v2.synthetic.json")).unwrap();
    value.validate(&"a".repeat(64)).unwrap();
}
#[test]
fn duplicate_raw_keys_refuse_before_hash_or_value_normalization() {
    let bytes = serde_json::to_string(&fixture()).unwrap();
    let phases =
        bytes.replacen("\"requested\":\"0\"", "\"requested\":\"0\",\"requested\":\"0\"", 1);
    assert_ne!(phases, bytes);
    assert!(parse_native(phases.as_bytes()).is_err());
    let capabilities =
        bytes.replacen("\"vote_assigned\":{", "\"vote_assigned\":{},\"vote_assigned\":{", 1);
    assert_ne!(capabilities, bytes);
    assert!(parse_native(capabilities.as_bytes()).is_err());
    let version = bytes.replacen(
        "\"source_version\":\"native-core-v2\"",
        "\"source_version\":\"native-core-v1\",\"source_version\":\"native-core-v2\"",
        1,
    );
    assert_ne!(version, bytes);
    assert!(parse_native(version.as_bytes()).is_err());
}
#[test]
fn overall_quality_may_degrade_but_cannot_promote_incomplete_components() {
    let mut value = fixture();
    value["payload"]["consensus"]["sessions"]["stopped"] = "0".into();
    value["payload"]["consensus"]["incomplete_reasons"] = serde_json::json!([]);
    value["payload"]["consensus"]["instrumentation_complete"] = true.into();
    value["payload"]["consensus"]["capabilities"]["session_lifecycle"]["supported"] = true.into();
    value["payload"]["consensus"]["capabilities"]["session_lifecycle"]["reason"] =
        serde_json::Value::Null;
    rehash(&mut value);
    validate(&value).unwrap(); // separate publication/registry degradation remains truthful
    value["quality"]["instrumentation_complete"] = true.into();
    validate(&value).unwrap();
    for field in ["producer_dropped", "relay_dropped", "parse_errors"] {
        let mut degraded = value.clone();
        degraded["quality"][field] = "1".into();
        assert!(validate(&degraded).is_err(), "complete source hid {field}");
    }
    let mut shed = value.clone();
    shed["quality"]["shed_reason"] = "source_budget".into();
    assert!(validate(&shed).is_err());
    value["payload"]["consensus"]["instrumentation_complete"] = false.into();
    value["payload"]["consensus"]["incomplete_reasons"] = serde_json::json!(["observation_gap"]);
    rehash(&mut value);
    assert!(validate(&value).is_err());
}

#[test]
fn disabled_null_and_inventory_overflow_are_not_complete() {
    let mut value = fixture();
    value["payload"]["consensus"] = serde_json::Value::Null;
    rehash(&mut value);
    validate(&value).unwrap();
    value["quality"]["instrumentation_complete"] = true.into();
    assert!(validate(&value).is_err());

    let mut value = fixture();
    value["payload"]["consensus"]["actions"].as_array_mut().unwrap().swap(0, 1);
    rehash(&mut value);
    assert!(validate(&value).is_err());
    let mut value = fixture();
    value["payload"]["consensus"]["actions"].as_array_mut().unwrap().pop();
    rehash(&mut value);
    assert!(validate(&value).is_err());

    let mut value = fixture();
    let context = serde_json::json!({
        "network_id":"a".repeat(64),"scope":{"scope_id":null,"workchain":0,"shard":"1"},
        "session_id":"b".repeat(64),"current_slot":null,"last_finalized_slot":null,
        "lifecycle":"active","stop_started_monotonic_ns":null
    });
    value["payload"]["consensus"]["contexts"] = serde_json::Value::Array(
        (0..9)
            .map(|i| {
                let mut item = context.clone();
                item["session_id"] = format!("{i:064x}").into();
                item
            })
            .collect(),
    );
    rehash(&mut value);
    assert!(validate(&value).is_err());
}

#[test]
fn unapproved_scope_and_post_terminal_progress_cannot_stay_green() {
    let mut value = fixture();
    value["payload"]["consensus"]["contexts"] = serde_json::json!([{
        "network_id":"a".repeat(64),"scope":{"scope_id":null,"workchain":0,"shard":"1"},
        "session_id":"b".repeat(64),"current_slot":1,"last_finalized_slot":null,
        "lifecycle":"active","stop_started_monotonic_ns":null
    }]);
    rehash(&mut value);
    assert!(validate(&value).is_err());
    value["payload"]["consensus"]["incomplete_reasons"] =
        serde_json::json!(["scope_unapproved", "session_lifecycle_unverified"]);
    value["payload"]["consensus"]["capabilities"]["typed_consensus_progress"]["reason"] =
        "scope_unapproved".into();
    rehash(&mut value);
    validate(&value).unwrap();

    let mut value = fixture();
    value["payload"]["consensus"]["post_terminal_progress"] = "1".into();
    value["payload"]["consensus"]["incomplete_reasons"] =
        serde_json::json!(["observation_gap", "session_lifecycle_unverified"]);
    rehash(&mut value);
    assert!(validate(&value).is_err());
    value["payload"]["consensus"]["actions"][0]["accounting_complete"] = false.into();
    value["payload"]["consensus"]["actions"][0]["incomplete_reasons"] =
        serde_json::json!(["observation_gap"]);
    rehash(&mut value);
    validate(&value).unwrap();
}

#[test]
fn shard_scope_is_coverage_not_an_integrity_defect() {
    let shard_context = serde_json::json!([{
        "network_id":"a".repeat(64),"scope":{"scope_id":null,"workchain":0,"shard":"1"},
        "session_id":"b".repeat(64),"current_slot":1,"last_finalized_slot":null,
        "lifecycle":"active","stop_started_monotonic_ns":null
    }]);
    // Current publisher: the capability names the reason, the envelope's coverage
    // names the field, the incomplete reasons carry nothing about scope.
    let mut value = fixture();
    value["payload"]["consensus"]["contexts"] = shard_context.clone();
    value["payload"]["consensus"]["capabilities"]["typed_consensus_progress"]["reason"] =
        "scope_unapproved".into();
    value["coverage"]["missing_fields"] = serde_json::json!(["shard_consensus_progress"]);
    rehash(&mut value);
    validate(&value).unwrap();
    // The field without a shard session is a lie.
    let mut lying = fixture();
    lying["coverage"]["missing_fields"] = serde_json::json!(["shard_consensus_progress"]);
    rehash(&mut lying);
    assert!(validate(&lying).is_err());
    // A shard session with neither the field nor the legacy reason is uncovered.
    let mut uncovered = fixture();
    uncovered["payload"]["consensus"]["contexts"] = shard_context;
    uncovered["payload"]["consensus"]["capabilities"]["typed_consensus_progress"]["reason"] =
        "scope_unapproved".into();
    rehash(&mut uncovered);
    assert!(validate(&uncovered).is_err());
}
