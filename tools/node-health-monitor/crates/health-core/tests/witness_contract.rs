use serde_json::{json, Value};
use tos_health_core::witness::{compare, Compared, Plan, Source, USABLE_AGE_MS};

fn plan() -> Value {
    json!({"schema_version":1,"profile":"c05_development_cache_only",
        "revision":"a".repeat(64),"observer_id":"observer_1","observer_epoch":"boot-1",
        "network_id":"b".repeat(64),"genesis":"c".repeat(64),
        "clock_skew_allowance_ms":5000,
        "endpoints":[{"endpoint_id":"cache_1","fixed_url":"https://cache.example.test/witness",
            "failure_domain":"zone_a","kind":"approved_cache_only_https","current_source_epoch":"upstream-1"},
            {"endpoint_id":"cache_2","fixed_url":"https://other.example.test/witness",
            "failure_domain":"zone_b","kind":"approved_cache_only_https","current_source_epoch":"upstream-2"}],
        "targets":[{"target_id":"validator_1","node_id":"validator_1","role":"normal",
            "valid_from":"2026-09-29T00:00:00Z","valid_until":"2026-09-30T00:00:00Z",
            "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
            "endpoint_ids":["cache_1"]},
            {"target_id":"validator_2","node_id":"validator_2","role":"probe_only",
            "valid_from":"2026-09-29T00:00:00Z","valid_until":"2026-09-30T00:00:00Z",
            "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
            "endpoint_ids":["cache_2"]}]})
}
fn source() -> Value {
    json!({"schema_version":1,"endpoint_id":"cache_1","source_epoch":"upstream-1",
        "generation":"7","network_id":"b".repeat(64),"genesis":"c".repeat(64),
        "observed_at":null,"source_age_ms":null,"clock_quality":"unknown","coverage":"partial",
        "rows":[{"target_id":"validator_1","observed_at":null,"source_age_ms":"46000",
            "anchor":{"kind":"block","network_id":"b".repeat(64),"genesis":"c".repeat(64),
                "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808","seqno":99,
                "root_hash":"d".repeat(64),"file_hash":"e".repeat(64),"point":"reported_finalized"},
            "network_observation":"observed","reported_certificate_membership":"not_checked",
            "reported_proof":"reported_valid","private_vote_visibility":"unavailable",
            "coverage":"partial","missing_fields":["private_vote"]}]})
}
fn decode(value: &Value, plan: &Plan) -> Result<Source, &'static str> {
    Source::decode(&serde_json::to_vec(value).unwrap(), plan, "cache_1")
}

#[test]
fn strict_source_preserves_stale_and_unknown_age_without_proof_promotion() {
    let plan = Plan::decode(&serde_json::to_vec(&plan()).unwrap()).unwrap();
    let admitted = decode(&source(), &plan).unwrap();
    assert!(admitted.rows[0].source_age_ms.unwrap().0 > USABLE_AGE_MS);
    assert!(admitted.source_age_ms.is_none());
    assert!(admitted.observed_at.is_none());
    let anchor = admitted.rows[0].anchor.as_ref().unwrap();
    assert_eq!(compare(anchor, anchor), Compared::Same);
    let mut differing = source();
    differing["rows"][0]["anchor"]["root_hash"] = json!("f".repeat(64));
    let differing = decode(&differing, &plan).unwrap();
    assert_eq!(
        compare(anchor, differing.rows[0].anchor.as_ref().unwrap()),
        Compared::ObservedDisagreement
    );
    assert!(serde_json::to_string(&admitted).unwrap().contains("reported_valid"));
    assert!(!serde_json::to_string(&admitted).unwrap().contains("locally_verified"));
}

#[test]
fn strict_source_refuses_unapproved_target_context_and_extra_fields() {
    let plan = Plan::decode(&serde_json::to_vec(&plan()).unwrap()).unwrap();
    let mut bad = source();
    bad["rows"][0]["target_id"] = json!("validator_2");
    assert!(decode(&bad, &plan).is_err());
    let mut bad = source();
    bad["rows"][0]["anchor"]["genesis"] = json!("f".repeat(64));
    assert!(decode(&bad, &plan).is_err());
    let mut bad = source();
    bad["rows"][0]["anchor"]["locally_verified"] = json!(true);
    assert!(decode(&bad, &plan).is_err());
    let mut bad = source();
    bad["rows"][0]["reported_proof"] = json!("locally_verified");
    assert!(decode(&bad, &plan).is_err());
    let mut bad = source();
    bad["generation"] = json!("01");
    assert!(decode(&bad, &plan).is_err());
    let mut bad = source();
    bad["source_age_ms"] = json!("18446744073709551616");
    assert!(decode(&bad, &plan).is_err());
    let mut bad = source();
    bad["rows"][0]["missing_fields"] = json!(["proof", "clock"]);
    assert!(decode(&bad, &plan).is_err());
    let mut bad = source();
    bad["rows"][0]["source_age_ms"] = Value::Null;
    assert!(decode(&bad, &plan).is_ok());
    let mut bad = source();
    bad["coverage"] = json!("complete");
    assert!(decode(&bad, &plan).is_err());
    let mut bad = source();
    bad["rows"][0]["coverage"] = json!("complete");
    bad["rows"][0]["missing_fields"] = json!([]);
    bad["coverage"] = json!("complete");
    assert!(decode(&bad, &plan).is_err());
    bad["rows"][0]["private_vote_visibility"] = json!("observed");
    assert!(decode(&bad, &plan).is_ok());
    let mut bad = source();
    bad["rows"][0]["missing_fields"] = json!(["proof"]);
    assert!(decode(&bad, &plan).is_err());
}

#[test]
fn strict_plan_refuses_dynamic_and_unreferenced_endpoints() {
    let mut bad = plan();
    bad["endpoints"][0].as_object_mut().unwrap().remove("current_source_epoch");
    assert!(Plan::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = plan();
    bad["endpoints"][0]["current_source_epoch"] = json!("");
    assert!(Plan::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = plan();
    bad["endpoints"][0]["fixed_url"] = json!("https://cache.example.test/witness?target=other");
    assert!(Plan::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = plan();
    bad["targets"][0]["endpoint_ids"] = json!(["cache_2"]);
    assert!(Plan::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = plan();
    bad["targets"][0]["valid_until"] = bad["targets"][0]["valid_from"].clone();
    assert!(Plan::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = plan();
    bad["endpoints"][0]["fixed_url"] = json!("https:///witness");
    assert!(Plan::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = plan();
    bad["endpoints"][1]["fixed_url"] = json!("https://CACHE.EXAMPLE.TEST:443/witness");
    assert!(Plan::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = plan();
    bad["targets"][0]["shard"] = json!("0");
    assert!(Plan::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = plan();
    bad["targets"][1]["scope_id"] = json!("other_scope");
    bad["targets"][1]["shard"] = json!("0");
    bad["targets"][1]["workchain"] = json!(0);
    assert!(Plan::decode(&serde_json::to_vec(&bad).unwrap()).is_ok());
    bad["targets"][1]["scope_id"] = json!("masterchain");
    assert!(Plan::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    bad["targets"][1]["scope_id"] = json!("foo");
    bad["targets"][1]["workchain"] = json!(-1);
    assert!(Plan::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
}

#[test]
fn plan_and_source_cardinality_and_body_caps_are_literal() {
    let mut too_many_targets = plan();
    let seed = too_many_targets["targets"][0].clone();
    for number in 3..=33 {
        let mut target = seed.clone();
        target["target_id"] = json!(format!("validator_{number}"));
        target["node_id"] = json!(format!("validator_{number}"));
        too_many_targets["targets"].as_array_mut().unwrap().push(target);
    }
    assert_eq!(too_many_targets["targets"].as_array().unwrap().len(), 33);
    assert!(Plan::decode(&serde_json::to_vec(&too_many_targets).unwrap()).is_err());
    let mut too_many_refs = plan();
    let seed = too_many_refs["endpoints"][0].clone();
    for number in 3..=4 {
        let mut endpoint = seed.clone();
        endpoint["endpoint_id"] = json!(format!("cache_{number}"));
        endpoint["fixed_url"] = json!(format!("https://cache{number}.example.test/witness"));
        too_many_refs["endpoints"].as_array_mut().unwrap().push(endpoint);
    }
    too_many_refs["targets"][0]["endpoint_ids"] =
        json!(["cache_1", "cache_3", "cache_4", "cache_2"]);
    assert!(Plan::decode(&serde_json::to_vec(&too_many_refs).unwrap()).is_err());
    let plan = Plan::decode(&serde_json::to_vec(&plan()).unwrap()).unwrap();
    let mut bytes = serde_json::to_vec(&source()).unwrap();
    bytes.resize(16_385, b' ');
    assert_eq!(
        Source::decode(&bytes, &plan, "cache_1").err(),
        Some("witness source body overflow")
    );
}

#[test]
fn unknown_candidate_is_not_a_positive_comparison() {
    let plan = Plan::decode(&serde_json::to_vec(&plan()).unwrap()).unwrap();
    let mut value = source();
    value["rows"][0]["anchor"] = json!({"kind":"consensus","network_id":"b".repeat(64),
        "genesis":"c".repeat(64),"scope_id":"masterchain","workchain":-1,
        "shard":"9223372036854775808","session_id":"d".repeat(64),
        "slot":9,"candidate_id":null,"phase":"reported_candidate"});
    let one = decode(&value, &plan).unwrap();
    let one_anchor = one.rows[0].anchor.as_ref().unwrap();
    assert_eq!(compare(one_anchor, one_anchor), Compared::Incomparable);
    value["rows"][0]["anchor"]["candidate_id"] = json!("e".repeat(64));
    let two = decode(&value, &plan).unwrap();
    assert_eq!(compare(one_anchor, two.rows[0].anchor.as_ref().unwrap()), Compared::Incomparable);
    value["rows"][0]["anchor"]["shard"] = json!("0");
    assert!(decode(&value, &plan).is_err());
}

#[test]
fn comparison_requires_exact_context_and_never_upgrades_reported_finality() {
    let plan = Plan::decode(&serde_json::to_vec(&plan()).unwrap()).unwrap();
    let first = decode(&source(), &plan).unwrap();
    let anchor = first.rows[0].anchor.as_ref().unwrap();
    let mut wrong_height = source();
    wrong_height["rows"][0]["anchor"]["seqno"] = json!(100);
    assert_eq!(
        compare(anchor, decode(&wrong_height, &plan).unwrap().rows[0].anchor.as_ref().unwrap()),
        Compared::Incomparable,
        "highest reported height is not canonical truth"
    );
    let mut wrong_point = source();
    wrong_point["rows"][0]["anchor"]["point"] = json!("reported_applied");
    assert_eq!(
        compare(anchor, decode(&wrong_point, &plan).unwrap().rows[0].anchor.as_ref().unwrap()),
        Compared::Incomparable,
        "different block points cannot be compared"
    );
    let mut other_genesis = source();
    other_genesis["rows"][0]["anchor"]["genesis"] = json!("f".repeat(64));
    assert!(
        decode(&other_genesis, &plan).is_err(),
        "wrong genesis is not an approved source context"
    );
    let mut reported_quorum = source();
    reported_quorum["rows"][0]["quorum"] = json!("valid_without_this_node");
    assert!(
        decode(&reported_quorum, &plan).is_err(),
        "raw quorum is not a local proof or member fact"
    );

    let mut candidate = source();
    candidate["rows"][0]["anchor"] = json!({"kind":"consensus","network_id":"b".repeat(64),
        "genesis":"c".repeat(64),"scope_id":"masterchain","workchain":-1,
        "shard":"9223372036854775808","session_id":"d".repeat(64),
        "slot":9,"candidate_id":"e".repeat(64),"phase":"reported_candidate"});
    let first_candidate = decode(&candidate, &plan).unwrap();
    let candidate_anchor = first_candidate.rows[0].anchor.as_ref().unwrap();
    candidate["rows"][0]["anchor"]["candidate_id"] = json!("f".repeat(64));
    let disagreement = decode(&candidate, &plan).unwrap();
    assert_eq!(
        compare(candidate_anchor, disagreement.rows[0].anchor.as_ref().unwrap()),
        Compared::ObservedDisagreement,
        "unfinalized difference is only an observed disagreement"
    );
    candidate["rows"][0]["anchor"]["session_id"] = json!("a".repeat(64));
    let other_session = decode(&candidate, &plan).unwrap();
    assert_eq!(
        compare(candidate_anchor, other_session.rows[0].anchor.as_ref().unwrap()),
        Compared::Incomparable,
        "same slot across sessions is not the same event"
    );
    assert_eq!(compare(anchor, candidate_anchor), Compared::Incomparable);
}
