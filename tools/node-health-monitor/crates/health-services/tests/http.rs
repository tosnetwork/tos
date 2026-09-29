use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc};
use tos_health_core::{
    evidence::Evidence,
    query::{Grant, TOOLS},
    query_output::ToolEnvelope,
    source::{Availability, Coverage, SourceQuality},
};
use tos_health_services::{
    edge::{router as edge_router, sample_process, EdgeState},
    observability::{router as query_router, ObservabilityState},
    Inventory,
};
use tower::ServiceExt;
fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|v| (*v).into()).collect()
}
fn state() -> ObservabilityState {
    ObservabilityState::new(
        Inventory { network_id: "a".repeat(64), nodes: set(&["v1"]), scopes: set(&["node"]) },
        vec![b'o'; 32],
        vec![b'i'; 32],
        vec![b'a'; 32],
    )
    .expect("service fixture")
}
fn quality(at: i64, sequence: u64) -> SourceQuality {
    SourceQuality {
        availability: Availability::Available,
        coverage: Coverage::Complete,
        observed_at_ms: Some(at),
        last_success_at_ms: Some(at),
        clock_valid: true,
        process_epoch: "process-1".into(),
        source_sequence: sequence.to_string(),
    }
}
fn record(at: i64, sequence: u64, source_id: &str, payload: Value) -> Evidence {
    Evidence {
        node_id: "v1".into(),
        scope_id: "node".into(),
        source_id: source_id.into(),
        source_record_id: format!("record-{sequence}"),
        process_epoch: "process-1".into(),
        observed_at_ms: at,
        received_at_ms: at,
        quality: quality(at, sequence),
        payload,
        redacted: true,
    }
}
fn contract(mut payload: Value, evidence_kind: &str) -> Value {
    let object = payload.as_object_mut().expect("contract fixture object");
    object.insert("source_version".into(), json!("synthetic-actor-v1"));
    object.insert("evidence_kind".into(), json!(evidence_kind));
    object.insert(
        "contract_quality".into(),
        json!({"instrumentation_complete":true,"producer_dropped":"0","relay_dropped":"0","parse_errors":"0","shed_reason":null}),
    );
    object.insert(
        "contract_coverage".into(),
        json!({"status":"complete","missing_fields":[],"gaps":[],"sampling_policy":"isolated synthetic actor"}),
    );
    payload
}
fn request(path: &str, token: char, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token.to_string().repeat(32)))
        .body(Body::from(body.to_string()))
        .expect("request")
}
async fn json_body(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&bytes).expect("json body")
}
#[tokio::test]
async fn edge_reads_are_cached_and_authenticated() {
    let state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    let app = edge_router(state.clone());
    let unauth = app
        .clone()
        .oneshot(Request::builder().uri("/v1/edge/heartbeat").body(Body::empty()).expect("request"))
        .await
        .expect("route");
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    let cold = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/edge/snapshot")
                .header("authorization", format!("Bearer {}", "e".repeat(32)))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route");
    assert_eq!(cold.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(state.cache.lock().expect("lock").is_none());
    let sample = sample_process(
        "v1",
        std::fs::read_link("/proc/self")
            .expect("proc namespace")
            .to_string_lossy()
            .parse::<u32>()
            .expect("proc pid"),
        1,
    )
    .expect("real proc sample");
    *state.cache.lock().expect("lock") = Some(sample);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/edge/snapshot")
                .header("authorization", format!("Bearer {}", "e".repeat(32)))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(state.native.lock().expect("native lock").read().is_none());
}
#[tokio::test]
async fn edge_rejects_refresh_and_enforces_burst() {
    let state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    let app = edge_router(state);
    for i in 0..5 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/edge/heartbeat")
                    .header("authorization", format!("Bearer {}", "e".repeat(32)))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route");
        assert_eq!(
            response.status(),
            if i < 4 { StatusCode::OK } else { StatusCode::TOO_MANY_REQUESTS }
        );
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/edge/snapshot?force_refresh=true")
                .header("authorization", format!("Bearer {}", "e".repeat(32)))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[tokio::test]
async fn edge_heartbeat_and_capabilities_emit_bounded_typed_wire() {
    use tos_health_core::edge_snapshot::{EdgeCapabilities, EdgeHeartbeat};
    let state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    let app = edge_router(state);
    let heartbeat = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/edge/heartbeat")
                .header("authorization", format!("Bearer {}", "e".repeat(32)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(heartbeat.into_body(), 4096).await.unwrap();
    if let Ok(directory) = std::env::var("NHM_CONTRACT_OUTPUT_DIR") {
        std::fs::write(std::path::Path::new(&directory).join("edge-heartbeat.json"), &bytes)
            .unwrap();
    }
    let heartbeat: EdgeHeartbeat = serde_json::from_slice(&bytes).unwrap();
    heartbeat.validate("v1").unwrap();
    assert_eq!(heartbeat.guard, "guarded");
    assert!(heartbeat.validator_epoch.is_none());

    let capabilities = app
        .oneshot(
            Request::builder()
                .uri("/v1/edge/capabilities")
                .header("authorization", format!("Bearer {}", "e".repeat(32)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(capabilities.into_body(), 32_768).await.unwrap();
    if let Ok(directory) = std::env::var("NHM_CONTRACT_OUTPUT_DIR") {
        std::fs::write(std::path::Path::new(&directory).join("edge-capabilities.json"), &bytes)
            .unwrap();
    }
    let capabilities: EdgeCapabilities = serde_json::from_slice(&bytes).unwrap();
    capabilities.validate("v1").unwrap();
    let stats = capabilities
        .capabilities
        .iter()
        .find(|capability| capability.name == "validator_stats")
        .unwrap();
    assert!(!stats.value.supported && !stats.value.enabled && !stats.value.contract_valid);
}
#[tokio::test]
async fn edge_router_reserves_burst_token_for_approved_heartbeat() {
    let state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    let app = edge_router(state);
    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/edge/capabilities")
                    .header("authorization", format!("Bearer {}", "e".repeat(32)))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route");
        assert_eq!(response.status(), StatusCode::OK);
    }
    let refused = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/edge/capabilities")
                .header("authorization", format!("Bearer {}", "e".repeat(32)))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route");
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    let heartbeat = app
        .oneshot(
            Request::builder()
                .uri("/v1/edge/heartbeat")
                .header("authorization", format!("Bearer {}", "e".repeat(32)))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route");
    assert_eq!(heartbeat.status(), StatusCode::OK);
}
#[tokio::test]
async fn service_identities_do_not_cross_roles() {
    let app = query_router(state());
    let grant = json!({"node_ids":["v1"],"scope_ids":["node"],"start":"2026-09-01T00:00:00Z","end":"2026-09-01T00:01:00Z"});
    for token in ['i', 'a'] {
        let response = app
            .clone()
            .oneshot(request("/v1/control/grants", token, grant.clone()))
            .await
            .expect("route");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = app.oneshot(request("/v1/control/grants", 'o', grant)).await.expect("route");
    assert_eq!(response.status(), StatusCode::OK);
}
#[tokio::test]
async fn grant_query_and_revocation_round_trip() {
    let state = state();
    let app = query_router(state.clone());
    let grant = json!({"node_ids":["v1"],"scope_ids":["node"],"start":"2026-09-01T00:00:00Z","end":"2026-09-01T00:01:00Z"});
    let g = json_body(
        app.clone().oneshot(request("/v1/control/grants", 'o', grant)).await.expect("route"),
    )
    .await;
    let run = g["run_id"].as_str().expect("run");
    let token = g["run_token"].as_str().expect("token");
    let mut req = request("/v1/query/capabilities", 'a', json!({"run_id":run}));
    req.headers_mut().insert("x-tos-run-token", token.parse().expect("header"));
    let response = app.clone().oneshot(req).await.expect("route");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["data"]["contract_version"], "R4-v1");
    assert_eq!(body["data"]["query_mode"], "cache_only");
    assert_eq!(body["data"]["node_capabilities"][0]["node_id"], "v1");
    let response = app
        .clone()
        .oneshot(request(&format!("/v1/control/grants/{run}/revoke"), 'o', json!({})))
        .await
        .expect("route");
    assert_eq!(response.status(), StatusCode::OK);
    let mut req = request("/v1/query/capabilities", 'a', json!({"run_id":run}));
    req.headers_mut().insert("x-tos-run-token", token.parse().expect("header"));
    assert_eq!(app.oneshot(req).await.expect("route").status(), StatusCode::UNAUTHORIZED);
    assert_eq!(state.data.lock().expect("lock").store.watermark(), 0);
}
#[tokio::test]
async fn ingest_checks_bound_identity() {
    let app = query_router(state());
    let sample = sample_process(
        "v2",
        std::fs::read_link("/proc/self")
            .expect("proc namespace")
            .to_string_lossy()
            .parse::<u32>()
            .expect("proc pid"),
        1,
    )
    .expect("sample");
    let response = app.oneshot(request("/v1/ingest", 'i', json!(sample))).await.expect("route");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
#[tokio::test]
async fn oversized_requests_fail_before_handler() {
    let app = query_router(state());
    let response = app
        .oneshot(request("/v1/control/grants", 'o', json!({"padding":"x".repeat(17_000)})))
        .await
        .expect("route");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
#[test]
fn direct_listener_must_be_local() {
    assert!(tos_health_services::loopback("127.0.0.1:9011").is_ok());
    assert!(tos_health_services::loopback("0.0.0.0:9011").is_err());
    assert!(tos_health_services::loopback("[::]:9011").is_err());
}
#[test]
fn private_token_validation_and_randomness() {
    let a = tos_health_services::random_token().expect("random");
    let b = tos_health_services::random_token().expect("random");
    assert_ne!(a, b);
    let encoded = tos_health_services::hex(&a);
    assert_eq!(tos_health_services::decode_token(&encoded), Some(a));
    assert!(tos_health_services::decode_token("invalid").is_none());
    assert!(tos_health_services::authorized(
        Some(&format!("Bearer {}", "a".repeat(32))),
        &[b'a'; 32]
    ));
    assert!(!tos_health_services::authorized(
        Some(&format!("Bearer {}", "b".repeat(32))),
        &[b'a'; 32]
    ));
}
#[test]
fn inventory_and_secret_domains_are_enforced() {
    let mut inventory =
        Inventory { network_id: "a".repeat(64), nodes: set(&["v1"]), scopes: set(&["node"]) };
    assert!(inventory.validate().is_ok());
    inventory.nodes = set(&["../escape"]);
    assert!(inventory.validate().is_err());
    inventory.nodes = set(&["v1"]);
    inventory.network_id = "not-a-genesis-hash".into();
    assert!(inventory.validate().is_err());
    inventory.network_id = "a".repeat(63);
    assert!(inventory.validate().is_err());
    let state = state();
    assert!(!Arc::ptr_eq(&state.operator_token, &state.service_token));
}
#[tokio::test]
async fn query_rejections_are_not_http_success() {
    let state = state();
    let app = query_router(state);
    let now = chrono::Utc::now();
    let start =
        (now - chrono::Duration::seconds(60)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let end = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let grant = json_body(
        app.clone()
            .oneshot(request(
                "/v1/control/grants",
                'o',
                json!({"node_ids":["v1"],"scope_ids":["node"],"start":start,"end":end}),
            ))
            .await
            .unwrap(),
    )
    .await;
    let run = grant["run_id"].as_str().unwrap();
    let token = grant["run_token"].as_str().unwrap();
    for (path, input, expected) in [
        ("capabilities", json!({"run_id":run,"force_refresh":true}), StatusCode::BAD_REQUEST),
        (
            "node-snapshot",
            json!({"run_id":run,"node_id":"v1","as_of":end,"max_age_seconds":30,"components":["process"]}),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "node-snapshot",
            json!({"run_id":run,"node_id":"other","as_of":end,"max_age_seconds":30,"components":["process"]}),
            StatusCode::FORBIDDEN,
        ),
        (
            "node-snapshot",
            json!({"run_id":run,"node_id":"v1","as_of":end,"max_age_seconds":4294967296u64,"components":["process"]}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut req = request(&format!("/v1/query/{path}"), 'a', input);
        req.headers_mut().insert("x-tos-run-token", token.parse().unwrap());
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(json_body(response).await["status"], "error");
    }
    let mut cross_run = request(
        "/v1/query/capabilities",
        'a',
        json!({"run_id":"00000000-0000-4000-8000-000000000099"}),
    );
    cross_run.headers_mut().insert("x-tos-run-token", token.parse().unwrap());
    assert_eq!(app.oneshot(cross_run).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn all_six_success_handlers_emit_runtime_dtos() {
    let mut state = state();
    Arc::get_mut(&mut state.metrics).unwrap().insert("rss_bytes".into());
    let run = "00000000-0000-4000-8000-000000000001";
    let token = [7u8; 32];
    let start =
        chrono::DateTime::parse_from_rfc3339("2026-09-29T00:00:00Z").unwrap().timestamp_millis();
    let end = start + 60_000;
    let reference = format!("blk_{}", "b".repeat(16));
    {
        let mut data = state.data.lock().unwrap();
        let fixtures = [
            record(
                start + 1_000,
                1,
                "collector",
                contract(
                    json!({"component":"process","contract_payload":{"kind":"process","pid":4242,"rss_bytes":"1048576","anon_bytes":"524288","file_bytes":"524288","swap_bytes":"0","cpu_user_ticks":"100","cpu_system_ticks":"50"}}),
                    "observation",
                ),
            ),
            record(
                start + 2_000,
                2,
                "collector",
                contract(
                    json!({"metric_id":"rss_bytes","metric":{"semantic_type":"gauge","population":"isolated samples","reset_count":"0","labels":[]},"contract_payload":{"kind":"scalar","metric_id":"rss_bytes","value":42.0,"unit":"bytes"}}),
                    "observation",
                ),
            ),
            record(
                start + 3_000,
                3,
                "collector",
                contract(
                    json!({"kind":"warning","event":{"kind":"warning","stage":null,"reason":"synthetic","correlation_id":null,"excerpt":"synthetic warning"},"contract_payload":{"kind":"diagnostic_fixture","record_type":1,"payload":"0102"}}),
                    "event",
                ),
            ),
            record(
                start + 4_000,
                4,
                "operator_change",
                contract(
                    json!({"kind":"config","change":{"kind":"config","completed":null,"actor_alias":"operator","before":{"mode":"old"},"after":{"mode":"new"},"reason":"synthetic","trusted_origin":true},"contract_payload":{"kind":"diagnostic_fixture","record_type":1,"payload":"0102"}}),
                    "change",
                ),
            ),
            record(
                start + 5_000,
                5,
                "collector",
                contract(
                    json!({"reference_id":reference,"contract_payload":{"kind":"block","network_id":"a".repeat(64),"scope_id":"node","workchain":-1,"shard":"9223372036854775808","seqno":1,"root_hash":"b".repeat(64),"file_hash":"c".repeat(64),"point":"observed"}}),
                    "observation",
                ),
            ),
        ];
        for fixture in fixtures {
            data.store.insert(fixture).unwrap();
        }
        let mut grant = Grant::new(
            run.into(),
            "aura".into(),
            "a".repeat(64),
            &token,
            set(&["v1"]),
            set(&["node"]),
            start,
            end,
            0,
            data.store.watermark(),
        )
        .unwrap();
        grant.references.insert(reference.clone());
        data.grants.insert(run.into(), grant);
    }
    let app = query_router(state);
    let at = "2026-09-29T00:00:30Z";
    let cases = [
        ("capabilities", json!({"run_id":run})),
        (
            "node-snapshot",
            json!({"run_id":run,"node_id":"v1","as_of":at,"max_age_seconds":30,"components":["process"]}),
        ),
        (
            "metric-window",
            json!({"run_id":run,"node_ids":["v1"],"metric_ids":["rss_bytes"],"scope_id":"node","start":"2026-09-29T00:00:00Z","end":"2026-09-29T00:01:00Z","step_seconds":15,"mode":"series","max_points_per_series":4}),
        ),
        (
            "event-window",
            json!({"run_id":run,"node_ids":["v1"],"scope_id":"node","start":"2026-09-29T00:00:00Z","end":"2026-09-29T00:01:00Z","sources":["collector"],"kinds":["warning"],"correlation_id":"","contains":"","limit":10,"cursor":""}),
        ),
        (
            "change-history",
            json!({"run_id":run,"node_ids":["v1"],"start":"2026-09-29T00:00:00Z","end":"2026-09-29T00:01:00Z","kinds":["config"],"limit":10,"cursor":""}),
        ),
        (
            "block-evidence",
            json!({"run_id":run,"node_ids":["v1"],"reference_id":reference,"ancestor_depth":0,"max_events":10}),
        ),
    ];
    let output_dir = std::env::var_os("NHM_CONTRACT_OUTPUT_DIR").map(std::path::PathBuf::from);
    for ((path, input), contract_name) in cases.into_iter().zip(TOOLS) {
        let mut req = request(&format!("/v1/query/{path}"), 'a', input);
        req.headers_mut()
            .insert("x-tos-run-token", tos_health_services::hex(&token).parse().unwrap());
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let body = json_body(response).await;
        assert_eq!(body["status"], "ok", "{path}: {body}");
        let _: ToolEnvelope = serde_json::from_value(body.clone()).expect("concrete output DTO");
        for evidence in body["evidence"].as_array().unwrap() {
            let expected =
                format!("{:x}", Sha256::digest(serde_json::to_vec(&evidence["payload"]).unwrap()));
            assert_eq!(evidence["content_hash"], expected, "{path}");
        }
        if let Some(dir) = &output_dir {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(
                dir.join(format!("{contract_name}.json")),
                serde_json::to_vec_pretty(&body).unwrap(),
            )
            .unwrap();
        }
    }
}

async fn metric_response(records: Vec<Evidence>) -> (StatusCode, Value) {
    metric_response_for(records, &["rss_bytes"]).await
}

async fn metric_response_for(records: Vec<Evidence>, metric_ids: &[&str]) -> (StatusCode, Value) {
    let mut state = state();
    for metric_id in metric_ids {
        Arc::get_mut(&mut state.metrics).unwrap().insert((*metric_id).into());
    }
    let run = "00000000-0000-4000-8000-000000000002";
    let token = [8u8; 32];
    let start =
        chrono::DateTime::parse_from_rfc3339("2026-09-29T00:00:00Z").unwrap().timestamp_millis();
    {
        let mut data = state.data.lock().unwrap();
        for record in records {
            data.store.insert(record).unwrap();
        }
        let grant = Grant::new(
            run.into(),
            "aura".into(),
            "a".repeat(64),
            &token,
            set(&["v1"]),
            set(&["node"]),
            start,
            start + 60_000,
            0,
            data.store.watermark(),
        )
        .unwrap();
        data.grants.insert(run.into(), grant);
    }
    let input = json!({"run_id":run,"node_ids":["v1"],"metric_ids":metric_ids,"scope_id":"node","start":"2026-09-29T00:00:00Z","end":"2026-09-29T00:01:00Z","step_seconds":15,"mode":"series","max_points_per_series":4});
    let mut req = request("/v1/query/metric-window", 'a', input);
    req.headers_mut().insert("x-tos-run-token", tos_health_services::hex(&token).parse().unwrap());
    let response = query_router(state).oneshot(req).await.unwrap();
    let status = response.status();
    (status, json_body(response).await)
}

fn metric_payload(unit: &str) -> Value {
    metric_payload_named("rss_bytes", unit)
}

fn metric_payload_named(metric_id: &str, unit: &str) -> Value {
    contract(
        json!({"metric_id":metric_id,"metric":{"semantic_type":"gauge","population":"isolated samples","reset_count":"0","labels":[]},"contract_payload":{"kind":"scalar","metric_id":metric_id,"value":42.0,"unit":unit}}),
        "observation",
    )
}

#[tokio::test]
async fn runtime_output_reflects_unknown_quality_and_rejects_conflicts() {
    let start =
        chrono::DateTime::parse_from_rfc3339("2026-09-29T00:00:00Z").unwrap().timestamp_millis();
    let mut invalid_clock = record(start + 1_000, 1, "collector", metric_payload("bytes"));
    invalid_clock.quality.clock_valid = false;
    let (status, body) = metric_response(vec![invalid_clock]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "partial");
    assert_eq!(body["data"]["series"][0]["clock"], "invalid");
    assert_eq!(body["missing_evidence"][0]["source_id"], "collector");

    let mut partial = record(start + 1_000, 1, "collector", metric_payload("bytes"));
    partial.quality.coverage = Coverage::Partial;
    partial.payload["contract_coverage"]["status"] = json!("partial");
    partial.payload["contract_coverage"]["missing_fields"] = json!(["reset_source"]);
    let (status, body) = metric_response(vec![partial]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "partial");
    assert_eq!(body["coverage"]["status"], "partial");
    assert_eq!(body["data"]["series"][0]["coverage"]["status"], "partial");
    assert_eq!(body["missing_evidence"][0]["source_id"], "collector");

    let one = record(start + 1_000, 1, "collector", metric_payload("bytes"));
    let two = record(start + 2_000, 2, "collector", metric_payload("seconds"));
    let (status, body) = metric_response(vec![one, two]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "SCHEMA_MISMATCH");

    let one = record(start + 1_000, 1, "collector", metric_payload("bytes"));
    let mut two = record(start + 2_000, 2, "collector", metric_payload("bytes"));
    two.process_epoch = "process-2".into();
    two.quality.process_epoch = "process-2".into();
    let (status, body) = metric_response(vec![one, two]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "SCHEMA_MISMATCH");

    let mut extra = record(start + 1_000, 1, "collector", metric_payload("bytes"));
    extra.payload["contract_payload"]["unexpected"] = json!(true);
    let (status, body) = metric_response(vec![extra]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "SCHEMA_MISMATCH");

    let one = record(start + 1_000, 1, "collector", metric_payload("bytes"));
    let mut two = record(start + 2_000, 2, "collector", metric_payload("bytes"));
    two.payload["metric"]["labels"] = json!([{"name":"role","value":"other"}]);
    let (status, body) = metric_response(vec![one, two]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "SCHEMA_MISMATCH");

    let mut one = record(start + 1_000, 1, "collector", metric_payload("bytes"));
    one.quality.coverage = Coverage::Partial;
    one.payload["contract_coverage"]["status"] = json!("partial");
    one.payload["contract_coverage"]["gaps"] = json!(["first-sample-gap"]);
    let mut two = record(start + 2_000, 2, "collector", metric_payload("bytes"));
    two.quality.coverage = Coverage::Partial;
    two.payload["contract_coverage"]["status"] = json!("partial");
    let (status, body) = metric_response(vec![one, two]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["series"][0]["coverage"]["gaps"], json!(["first-sample-gap"]));

    let mut derived = record(start + 1_000, 1, "collector", metric_payload("bytes"));
    derived.payload["evidence_kind"] = json!("derived");
    let (status, body) = metric_response(vec![derived]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "CAPABILITY_UNSUPPORTED");

    let mut unknown = record(start + 1_000, 1, "collector", metric_payload("bytes"));
    unknown.quality.coverage = Coverage::Unknown;
    unknown.payload["contract_coverage"]["status"] = json!("unknown");
    unknown.payload["contract_coverage"]["missing_fields"] = json!(["source_sample"]);
    let (status, body) = metric_response(vec![unknown]).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "unavailable");
    assert!(body["data"].is_null());
    assert_eq!(body["error"]["code"], "SOURCE_UNAVAILABLE");
    assert_eq!(body["missing_evidence"][0]["source_id"], "collector");
}

fn coverage_values(prefix: &str, start: usize, count: usize) -> Value {
    Value::Array((start..start + count).map(|index| json!(format!("{prefix}-{index}"))).collect())
}

#[tokio::test]
async fn runtime_coverage_aggregation_is_bounded_and_schema_ready() {
    let start =
        chrono::DateTime::parse_from_rfc3339("2026-09-29T00:00:00Z").unwrap().timestamp_millis();
    let make = |sequence: u64,
                missing_start: usize,
                missing_count: usize,
                gap_start: usize,
                gap_count: usize| {
        let mut item = record(
            start + i64::try_from(sequence).unwrap() * 1_000,
            sequence,
            "collector",
            metric_payload("bytes"),
        );
        item.quality.coverage = Coverage::Partial;
        item.payload["contract_coverage"]["status"] = json!("partial");
        item.payload["contract_coverage"]["missing_fields"] =
            coverage_values("field", missing_start, missing_count);
        item.payload["contract_coverage"]["gaps"] = coverage_values("gap", gap_start, gap_count);
        item
    };

    let (status, body) =
        metric_response(vec![make(1, 0, 32, 0, 16), make(2, 32, 32, 16, 16)]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "partial");
    assert_eq!(body["coverage"]["missing_fields"].as_array().unwrap().len(), 64);
    assert_eq!(body["coverage"]["gaps"].as_array().unwrap().len(), 32);
    assert_eq!(
        body["data"]["series"][0]["coverage"]["missing_fields"].as_array().unwrap().len(),
        64
    );
    assert_eq!(body["data"]["series"][0]["coverage"]["gaps"].as_array().unwrap().len(), 32);
    let _: ToolEnvelope =
        serde_json::from_value(body.clone()).expect("bounded concrete output DTO");
    if let Some(dir) = std::env::var_os("NHM_CONTRACT_OUTPUT_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            std::path::PathBuf::from(dir).join("tos_get_metric_window.boundary.json"),
            serde_json::to_vec_pretty(&body).unwrap(),
        )
        .unwrap();
    }

    let (status, body) = metric_response(vec![make(1, 0, 32, 0, 16), make(2, 0, 32, 0, 16)]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["coverage"]["missing_fields"].as_array().unwrap().len(), 32);
    assert_eq!(body["coverage"]["gaps"].as_array().unwrap().len(), 16);

    let (status, body) = metric_response(vec![make(1, 0, 32, 0, 1), make(2, 32, 33, 1, 1)]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "SCHEMA_MISMATCH");

    let (status, body) = metric_response(vec![make(1, 0, 1, 0, 16), make(2, 1, 1, 16, 17)]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "SCHEMA_MISMATCH");

    let response_item = |sequence: u64,
                         metric_id: &str,
                         missing_start: usize,
                         missing_count: usize,
                         gap_start: usize,
                         gap_count: usize| {
        let mut item = record(
            start + i64::try_from(sequence).unwrap() * 1_000,
            sequence,
            "collector",
            metric_payload_named(metric_id, "count"),
        );
        item.quality.coverage = Coverage::Partial;
        item.payload["contract_coverage"]["status"] = json!("partial");
        item.payload["contract_coverage"]["missing_fields"] =
            coverage_values("response-field", missing_start, missing_count);
        item.payload["contract_coverage"]["gaps"] =
            coverage_values("response-gap", gap_start, gap_count);
        item
    };
    let (status, body) = metric_response_for(
        vec![
            response_item(1, "rss_bytes", 0, 33, 0, 1),
            response_item(2, "cpu_ticks", 33, 33, 1, 1),
        ],
        &["rss_bytes", "cpu_ticks"],
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "SCHEMA_MISMATCH");

    let (status, body) = metric_response_for(
        vec![
            response_item(1, "rss_bytes", 0, 1, 0, 17),
            response_item(2, "cpu_ticks", 1, 1, 17, 17),
        ],
        &["rss_bytes", "cpu_ticks"],
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "SCHEMA_MISMATCH");
}
