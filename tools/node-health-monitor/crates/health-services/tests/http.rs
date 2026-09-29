use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::{collections::BTreeSet, sync::Arc};
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
        Inventory { network_id: "genesis".into(), nodes: set(&["v1"]), scopes: set(&["node"]) },
        vec![b'o'; 32],
        vec![b'i'; 32],
        vec![b'a'; 32],
    )
    .expect("service fixture")
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["source_record_id"], "1");
    assert_eq!(body["quality"]["coverage"], "partial");
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
    assert_eq!(json_body(response).await["data"]["tools"].as_array().expect("tools").len(), 6);
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
        Inventory { network_id: "genesis".into(), nodes: set(&["v1"]), scopes: set(&["node"]) };
    assert!(inventory.validate().is_ok());
    inventory.nodes = set(&["../escape"]);
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
    ] {
        let mut req = request(&format!("/v1/query/{path}"), 'a', input);
        req.headers_mut().insert("x-tos-run-token", token.parse().unwrap());
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(json_body(response).await["status"], "error");
    }
}
