use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tos_health_core::witness::Plan;
use tos_health_services::witness::{
    qualify_row_from_wire, router, CacheResponse, RelativeAge, RemoteClock, RoleAtObserverReceipt,
    WitnessCache,
};
use tower::ServiceExt;

fn plan() -> Plan {
    let value = json!({"schema_version":1,"profile":"c05_development_cache_only",
        "revision":"a".repeat(64),"observer_id":"observer_1","observer_epoch":"observer-1",
        "network_id":"b".repeat(64),"genesis":"c".repeat(64),"clock_skew_allowance_ms":5000,
        "endpoints":[{"endpoint_id":"cache_1","fixed_url":"https://cache.example.test/witness",
            "failure_domain":"zone_a","kind":"approved_cache_only_https","current_source_epoch":"source-1"}],
        "targets":[{"target_id":"validator_1","node_id":"validator_1","role":"normal",
            "valid_from":"2026-09-29T00:00:00Z","valid_until":"2026-09-30T00:00:00Z",
            "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
            "endpoint_ids":["cache_1"]}]});
    Plan::decode(&serde_json::to_vec(&value).unwrap()).unwrap()
}
fn source() -> Vec<u8> {
    serde_json::to_vec(&json!({"schema_version":1,"endpoint_id":"cache_1",
        "source_epoch":"source-1","generation":"1","network_id":"b".repeat(64),
        "genesis":"c".repeat(64),"observed_at":null,"source_age_ms":null,
        "clock_quality":"unknown","coverage":"partial",
        "rows":[{"target_id":"validator_1","observed_at":null,"source_age_ms":"46000",
            "anchor":{"kind":"block","network_id":"b".repeat(64),"genesis":"c".repeat(64),
                "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
                "seqno":99,"root_hash":"d".repeat(64),"file_hash":"e".repeat(64),
                "point":"reported_finalized"},"network_observation":"observed",
            "reported_certificate_membership":"not_checked","reported_proof":"reported_valid",
            "private_vote_visibility":"unavailable","coverage":"partial",
            "missing_fields":["private_vote"]}]}))
    .unwrap()
}
async fn get(cache: WitnessCache, path: &str, authorized: bool) -> (StatusCode, Value) {
    let mut request = Request::builder().uri(path).method("GET");
    if authorized {
        request = request.header("authorization", "Bearer abcdefghijklmnopqrstuvwxyz0123456789");
    }
    let response = router(cache).oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value =
        if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
    (status, value)
}

#[tokio::test]
async fn actual_read_handler_is_cache_only_and_duplicate_cannot_renew() {
    let cache =
        WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    let path = "/v1/witness/cache/cache_1";
    assert_eq!(get(cache.clone(), path, false).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(get(cache.clone(), path, true).await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        get(cache.clone(), "/v1/witness/cache/cache_1?force=true", true).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(cache.clone(), "/v1/witness/cache/not_planned", true).await.0,
        StatusCode::NOT_FOUND
    );
    let body_request = Request::builder()
        .uri(path)
        .method("GET")
        .header("authorization", "Bearer abcdefghijklmnopqrstuvwxyz0123456789")
        .body(Body::from("force_refresh=true"))
        .unwrap();
    assert_eq!(
        router(cache.clone()).oneshot(body_request).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let raw = source();
    assert!(cache.admit("cache_1", &raw, 120).unwrap());
    let (status, first) = get(cache.clone(), path, true).await;
    assert_eq!(status, StatusCode::OK);
    CacheResponse::decode(&serde_json::to_vec(&first).unwrap(), &plan(), "cache_1").unwrap();
    assert_eq!(first["receipt"]["source_json"], String::from_utf8(raw.clone()).unwrap());
    assert_eq!(first["receipt"]["request_duration_ms"], "120");
    assert_eq!(first["receipt"]["observer_epoch"], "observer-1");
    assert_eq!(first["row_ages"][0]["fresh_relative_age"], false);
    assert!(
        first["row_ages"][0]["effective_age_ms"].as_str().unwrap().parse::<u64>().unwrap()
            >= 46_120
    );
    assert!(!cache.admit("cache_1", &raw, 200).unwrap());
    let (status, second) = get(cache.clone(), path, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["receipt"], first["receipt"]);
    assert_eq!(second["row_ages"][0]["fresh_relative_age"], false);
    assert!(
        second["observer_elapsed_ms"].as_str().unwrap().parse::<u64>().unwrap()
            >= first["observer_elapsed_ms"].as_str().unwrap().parse::<u64>().unwrap()
    );
    let mut changed: Value = serde_json::from_slice(&raw).unwrap();
    changed["rows"][0]["anchor"]["root_hash"] = json!("f".repeat(64));
    assert!(cache.admit("cache_1", &serde_json::to_vec(&changed).unwrap(), 120).is_err());
    assert_eq!(get(cache, path, true).await.0, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn new_generation_of_same_old_row_does_not_renew_age_or_receipt() {
    let cache =
        WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    let path = "/v1/witness/cache/cache_1";
    cache.admit("cache_1", &source(), 120).unwrap();
    let (_, first) = get(cache.clone(), path, true).await;
    let mut newer: Value = serde_json::from_slice(&source()).unwrap();
    newer["generation"] = json!("2");
    newer["rows"][0]["source_age_ms"] = json!("0");
    cache.admit("cache_1", &serde_json::to_vec(&newer).unwrap(), 10).unwrap();
    let (_, second) = get(cache.clone(), path, true).await;
    assert_eq!(second["receipt"]["generation"], "2");
    assert_eq!(
        second["row_ages"][0]["first_received_at"],
        first["row_ages"][0]["first_received_at"]
    );
    assert_eq!(second["row_ages"][0]["source_age_at_first_receipt_ms"], "46120");
    assert_eq!(second["row_ages"][0]["fresh_relative_age"], false);
    let mut absent = newer.clone();
    absent["generation"] = json!("3");
    absent["rows"] = json!([]);
    cache.admit("cache_1", &serde_json::to_vec(&absent).unwrap(), 10).unwrap();
    let mut returned = newer;
    returned["generation"] = json!("4");
    cache.admit("cache_1", &serde_json::to_vec(&returned).unwrap(), 10).unwrap();
    let (_, again) = get(cache, path, true).await;
    assert_eq!(
        again["row_ages"][0]["first_received_at"],
        first["row_ages"][0]["first_received_at"]
    );
    assert_eq!(again["row_ages"][0]["fresh_relative_age"], false);
}

#[tokio::test]
async fn same_row_newer_reported_age_only_raises_lower_bound() {
    let cache =
        WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    let mut initial: Value = serde_json::from_slice(&source()).unwrap();
    initial["rows"][0]["source_age_ms"] = json!("1000");
    cache.admit("cache_1", &serde_json::to_vec(&initial).unwrap(), 100).unwrap();
    let mut later = initial;
    later["generation"] = json!("2");
    later["rows"][0]["source_age_ms"] = json!("100000");
    cache.admit("cache_1", &serde_json::to_vec(&later).unwrap(), 100).unwrap();
    let (_, response) = get(cache, "/v1/witness/cache/cache_1", true).await;
    assert!(
        response["row_ages"][0]["effective_age_ms"].as_str().unwrap().parse::<u64>().unwrap()
            >= 100100
    );
    assert_eq!(response["row_ages"][0]["fresh_relative_age"], false);
}

#[tokio::test]
async fn same_row_newer_unknown_or_overflow_age_cannot_inherit_freshness() {
    for replacement in [Value::Null, json!("18446744073709551615")] {
        let cache =
            WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
        let mut initial: Value = serde_json::from_slice(&source()).unwrap();
        initial["rows"][0]["source_age_ms"] = json!("1000");
        cache.admit("cache_1", &serde_json::to_vec(&initial).unwrap(), 100).unwrap();
        let mut later = initial;
        later["generation"] = json!("2");
        later["rows"][0]["source_age_ms"] = replacement;
        cache.admit("cache_1", &serde_json::to_vec(&later).unwrap(), 100).unwrap();
        let (_, response) = get(cache, "/v1/witness/cache/cache_1", true).await;
        assert!(response["row_ages"][0]["effective_age_ms"].is_null());
        assert_eq!(response["row_ages"][0]["fresh_relative_age"], false);
    }
}

#[tokio::test]
async fn originally_unknown_row_remains_unknown_after_newer_finite_report() {
    let cache =
        WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    let mut initial: Value = serde_json::from_slice(&source()).unwrap();
    initial["rows"][0]["source_age_ms"] = Value::Null;
    cache.admit("cache_1", &serde_json::to_vec(&initial).unwrap(), 100).unwrap();
    let mut later = initial;
    later["generation"] = json!("2");
    later["rows"][0]["source_age_ms"] = json!("10");
    cache.admit("cache_1", &serde_json::to_vec(&later).unwrap(), 100).unwrap();
    let (_, response) = get(cache, "/v1/witness/cache/cache_1", true).await;
    assert!(response["row_ages"][0]["effective_age_ms"].is_null());
    assert_eq!(response["row_ages"][0]["fresh_relative_age"], false);
    CacheResponse::decode(&serde_json::to_vec(&response).unwrap(), &plan(), "cache_1").unwrap();
}

#[tokio::test]
async fn cache_retains_at_most_four_generations_without_revival() {
    let cache =
        WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    for generation in 1..=5 {
        let mut value: Value = serde_json::from_slice(&source()).unwrap();
        value["generation"] = json!(generation.to_string());
        cache.admit("cache_1", &serde_json::to_vec(&value).unwrap(), 10).unwrap();
        assert!(cache.retained_generations("cache_1").unwrap().len() <= 4);
    }
    assert_eq!(cache.retained_generations("cache_1").unwrap(), vec![2, 3, 4, 5]);
    let (_, latest) = get(cache.clone(), "/v1/witness/cache/cache_1", true).await;
    assert_eq!(latest["receipt"]["generation"], "5");
    let mut retired: Value = serde_json::from_slice(&source()).unwrap();
    retired["generation"] = json!("1");
    assert!(cache.admit("cache_1", &serde_json::to_vec(&retired).unwrap(), 10).is_err());
    assert_eq!(cache.retained_generations("cache_1").unwrap(), vec![2, 3, 4, 5]);
}

#[test]
fn owned_capacity_not_only_length_is_charged_at_startup() {
    let mut token = Vec::with_capacity(4 * 1024 * 1024);
    token.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz0123456789");
    assert!(WitnessCache::new(plan(), token).is_err());
    let mut oversized_plan = plan();
    oversized_plan.endpoints.reserve_exact(100_000);
    assert!(WitnessCache::new(oversized_plan, b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec())
        .is_err());
    for field in ["kind", "current_source_epoch"] {
        let mut oversized_plan = plan();
        let endpoint = &mut oversized_plan.endpoints[0];
        let text =
            if field == "kind" { &mut endpoint.kind } else { &mut endpoint.current_source_epoch };
        text.reserve_exact(4 * 1024 * 1024);
        assert!(
            WitnessCache::new(oversized_plan, b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec())
                .is_err(),
            "owned endpoint {field} capacity must be charged"
        );
    }
}

#[tokio::test]
async fn four_read_permits_live_until_cached_response_bodies_drain() {
    let cache =
        WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    cache.admit("cache_1", &source(), 10).unwrap();
    let app = router(cache);
    let request = || {
        Request::builder()
            .uri("/v1/witness/cache/cache_1")
            .header("authorization", "Bearer abcdefghijklmnopqrstuvwxyz0123456789")
            .body(Body::empty())
            .unwrap()
    };
    let mut held = Vec::new();
    for _ in 0..4 {
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        held.push(response);
    }
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    held.pop();
    assert_eq!(app.oneshot(request()).await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn canonical_duplicate_ignores_raw_whitespace_and_escaped_response_overflow_keeps_old() {
    let cache =
        WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    let path = "/v1/witness/cache/cache_1";
    let raw = source();
    cache.admit("cache_1", &raw, 10).unwrap();
    let (_, first) = get(cache.clone(), path, true).await;
    let mut whitespace = raw.clone();
    whitespace.extend_from_slice(b"\n\n");
    assert!(!cache.admit("cache_1", &whitespace, 20).unwrap());
    let (_, duplicate) = get(cache.clone(), path, true).await;
    assert_eq!(duplicate["receipt"], first["receipt"]);
    let mut next: Value = serde_json::from_slice(&raw).unwrap();
    next["generation"] = json!("2");
    next["rows"] = json!([]);
    let mut padded = serde_json::to_vec(&next).unwrap();
    assert!(padded.len() < 16_384);
    padded.resize(16_384, b'\n');
    assert!(cache.admit("cache_1", &padded, 10).is_err());
    let (_, still_old) = get(cache, path, true).await;
    assert_eq!(still_old["receipt"], first["receipt"]);
}

#[tokio::test]
async fn malformed_or_late_source_never_materializes_on_handler() {
    let cache =
        WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    let path = "/v1/witness/cache/cache_1";
    assert!(cache.admit("cache_1", &source(), 3001).is_err());
    let mut bad: Value = serde_json::from_slice(&source()).unwrap();
    bad["rows"][0]["target_id"] = json!("other");
    assert!(cache.admit("cache_1", &serde_json::to_vec(&bad).unwrap(), 100).is_err());
    assert_eq!(get(cache, path, true).await.0, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn retained_ingest_decoder_refuses_identity_age_and_proof_laundering() {
    let cache =
        WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    cache.admit("cache_1", &source(), 100).unwrap();
    let (_, valid) = get(cache, "/v1/witness/cache/cache_1", true).await;
    let check = |value: &Value| {
        CacheResponse::decode(&serde_json::to_vec(value).unwrap(), &plan(), "cache_1")
    };
    assert!(check(&valid).is_ok());
    let mut bad = valid.clone();
    bad["receipt"]["source_hash"] = json!("f".repeat(64));
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad["receipt"]["source_json"] = json!("{}");
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad["row_ages"][0]["fresh_relative_age"] = json!(true);
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad["row_ages"][0]["effective_age_ms"] = json!("0");
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad["row_ages"][0]["source_age_at_first_receipt_ms"] = json!("0");
    bad["row_ages"][0]["effective_age_ms"] = json!("0");
    bad["row_ages"][0]["fresh_relative_age"] = json!(true);
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad["row_ages"][0].as_object_mut().unwrap().remove("effective_age_ms");
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad["row_ages"][0].as_object_mut().unwrap().remove("source_age_at_first_receipt_ms");
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad["receipt"]["first_received_at"] = json!("2026-09-29T00:00:00+00:00");
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad["row_ages"][0]["first_received_at"] = json!("2026-09-29T00:00:00+00:00");
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad["receipt"]["verified_finality"] = json!(true);
    assert!(check(&bad).is_err());
    let overflow_cache =
        WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    let mut overflow: Value = serde_json::from_slice(&source()).unwrap();
    overflow["rows"][0]["source_age_ms"] = json!("18446744073709551615");
    overflow_cache.admit("cache_1", &serde_json::to_vec(&overflow).unwrap(), 100).unwrap();
    let (_, unknown) = get(overflow_cache, "/v1/witness/cache/cache_1", true).await;
    assert!(unknown["row_ages"][0]["effective_age_ms"].is_null());
    assert!(check(&unknown).is_ok());
}

#[tokio::test]
async fn actual_cache_wire_qualifies_future_clock_role_and_five_separate_dimensions() {
    let future = (chrono::Utc::now() + chrono::Duration::seconds(60))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut reported: Value = serde_json::from_slice(&source()).unwrap();
    reported["clock_quality"] = json!("valid");
    reported["observed_at"] = json!(future);
    reported["rows"][0]["observed_at"] = reported["observed_at"].clone();
    reported["rows"][0]["source_age_ms"] = json!("0");
    let raw = serde_json::to_vec(&reported).unwrap();
    let cache = WitnessCache::new_synthetic_valid_clock_fixture(
        plan(),
        b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
    )
    .unwrap();
    cache.admit("cache_1", &raw, 50).unwrap();
    let (_, wire) = get(cache, "/v1/witness/cache/cache_1", true).await;
    let bytes = serde_json::to_vec(&wire).unwrap();
    let qualified =
        qualify_row_from_wire(&bytes, &plan(), "cache_1", "validator_1", Some(100)).unwrap();
    assert_eq!(qualified.relative_age, RelativeAge::Fresh);
    assert_eq!(qualified.remote_clock, RemoteClock::Future);
    assert_eq!(qualified.role_at_observer_receipt, RoleAtObserverReceipt::Normal);
    assert_eq!(qualified.local_action, "unknown");
    assert_eq!(qualified.local_persistence, "unknown");
    assert!(!qualified.verified_finality && !qualified.node_fault_from_witness_alone);
    assert_eq!(serde_json::to_value(&qualified).unwrap()["reported_proof"], "reported_valid");
    assert_eq!(serde_json::to_value(&qualified).unwrap()["private_vote_visibility"], "unavailable");
    assert_eq!(
        qualify_row_from_wire(&bytes, &plan(), "cache_1", "validator_1", None)
            .unwrap()
            .relative_age,
        RelativeAge::Unknown,
        "unmeasured collector/M elapsed cannot become verified fresh"
    );
    assert_eq!(
        qualify_row_from_wire(&bytes, &plan(), "cache_1", "validator_1", Some(46_000))
            .unwrap()
            .relative_age,
        RelativeAge::Stale
    );

    for (role, expected) in [
        ("probe_only", RoleAtObserverReceipt::ProbeOnly),
        ("non_voting", RoleAtObserverReceipt::NonVoting),
    ] {
        let mut value = serde_json::to_value(plan()).unwrap();
        value["targets"][0]["role"] = json!(role);
        let alternate = Plan::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            qualify_row_from_wire(&bytes, &alternate, "cache_1", "validator_1", Some(100)).is_err(),
            "same revision cannot splice a receipt into a different role plan"
        );
        let alternate_cache = WitnessCache::new_synthetic_valid_clock_fixture(
            alternate.clone(),
            b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
        )
        .unwrap();
        alternate_cache.admit("cache_1", &raw, 50).unwrap();
        let (_, alternate_wire) = get(alternate_cache, "/v1/witness/cache/cache_1", true).await;
        let status = qualify_row_from_wire(
            &serde_json::to_vec(&alternate_wire).unwrap(),
            &alternate,
            "cache_1",
            "validator_1",
            Some(100),
        )
        .unwrap();
        assert_eq!(status.role_at_observer_receipt, expected);
        assert!(!status.node_fault_from_witness_alone);
    }
    let mut outside = serde_json::to_value(plan()).unwrap();
    outside["targets"][0]["valid_until"] = json!("2026-09-29T00:00:01Z");
    let outside = Plan::decode(&serde_json::to_vec(&outside).unwrap()).unwrap();
    let outside_cache = WitnessCache::new_synthetic_valid_clock_fixture(
        outside.clone(),
        b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
    )
    .unwrap();
    outside_cache.admit("cache_1", &raw, 50).unwrap();
    let (_, outside_wire) = get(outside_cache, "/v1/witness/cache/cache_1", true).await;
    assert_eq!(
        qualify_row_from_wire(
            &serde_json::to_vec(&outside_wire).unwrap(),
            &outside,
            "cache_1",
            "validator_1",
            Some(100)
        )
        .unwrap()
        .role_at_observer_receipt,
        RoleAtObserverReceipt::OutsideWindow
    );
    let unknown_clock =
        WitnessCache::new(plan(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    unknown_clock.admit("cache_1", &raw, 50).unwrap();
    let (_, unknown_wire) = get(unknown_clock, "/v1/witness/cache/cache_1", true).await;
    let unknown = qualify_row_from_wire(
        &serde_json::to_vec(&unknown_wire).unwrap(),
        &plan(),
        "cache_1",
        "validator_1",
        Some(100),
    )
    .unwrap();
    assert_eq!(
        unknown.relative_age,
        RelativeAge::Fresh,
        "independently measured relative age survives unknown wall clock"
    );
    assert_eq!(unknown.remote_clock, RemoteClock::Unknown);
    assert_eq!(unknown.role_at_observer_receipt, RoleAtObserverReceipt::Unknown);
}

#[tokio::test]
async fn republished_old_row_keeps_first_role_window_and_clock_context() {
    let from = (chrono::Utc::now() + chrono::Duration::seconds(2))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let until = (chrono::Utc::now() + chrono::Duration::seconds(60))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut value = serde_json::to_value(plan()).unwrap();
    value["targets"][0]["valid_from"] = json!(from);
    value["targets"][0]["valid_until"] = json!(until);
    let plan = Plan::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
    let cache = WitnessCache::new_synthetic_valid_clock_fixture(
        plan.clone(),
        b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
    )
    .unwrap();
    let mut original: Value = serde_json::from_slice(&source()).unwrap();
    original["rows"][0]["source_age_ms"] = json!("0");
    cache.admit("cache_1", &serde_json::to_vec(&original).unwrap(), 10).unwrap();
    let (_, first) = get(cache.clone(), "/v1/witness/cache/cache_1", true).await;
    assert_eq!(first["row_ages"][0]["first_received_at"], first["receipt"]["first_received_at"]);
    tokio::time::sleep(std::time::Duration::from_millis(2200)).await;
    original["generation"] = json!("2");
    cache.admit("cache_1", &serde_json::to_vec(&original).unwrap(), 10).unwrap();
    let (_, newer) = get(cache, "/v1/witness/cache/cache_1", true).await;
    assert_ne!(newer["receipt"]["first_received_at"], first["receipt"]["first_received_at"]);
    assert_eq!(
        newer["row_ages"][0]["first_received_at"],
        first["row_ages"][0]["first_received_at"]
    );
    let qualified = qualify_row_from_wire(
        &serde_json::to_vec(&newer).unwrap(),
        &plan,
        "cache_1",
        "validator_1",
        Some(10),
    )
    .unwrap();
    assert_eq!(
        qualified.role_at_observer_receipt,
        RoleAtObserverReceipt::OutsideWindow,
        "new endpoint generation cannot rewrite an old row's original role context"
    );
    assert_eq!(qualified.relative_age, RelativeAge::Fresh);

    let unknown_cache =
        WitnessCache::new(plan.clone(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    original["generation"] = json!("1");
    unknown_cache.admit("cache_1", &serde_json::to_vec(&original).unwrap(), 10).unwrap();
    original["generation"] = json!("2");
    unknown_cache.admit("cache_1", &serde_json::to_vec(&original).unwrap(), 10).unwrap();
    let (_, mut unknown_wire) = get(unknown_cache, "/v1/witness/cache/cache_1", true).await;
    unknown_wire["receipt"]["observer_clock_quality"] = json!("valid");
    let still_unknown = qualify_row_from_wire(
        &serde_json::to_vec(&unknown_wire).unwrap(),
        &plan,
        "cache_1",
        "validator_1",
        Some(10),
    )
    .unwrap();
    assert_eq!(
        still_unknown.role_at_observer_receipt,
        RoleAtObserverReceipt::Unknown,
        "later endpoint clock quality cannot upgrade an old row's unknown first clock"
    );
}
