use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tos_health_core::{
    evidence::Evidence,
    source::{Availability, Coverage, SourceQuality},
};
use tos_health_services::{
    edge::{router, EdgeState},
    native_cache::{NativeCache, NativeSampler},
};
use tower::ServiceExt;
fn process() -> Evidence {
    let now = chrono::Utc::now().timestamp_millis();
    Evidence {
        node_id: "v1".into(),
        scope_id: "node".into(),
        source_id: "collector".into(),
        source_record_id: "1".into(),
        process_epoch: "boot:1:1".into(),
        observed_at_ms: now,
        received_at_ms: now,
        quality: SourceQuality {
            availability: Availability::Available,
            coverage: Coverage::Complete,
            observed_at_ms: Some(now),
            last_success_at_ms: Some(now),
            clock_valid: true,
            process_epoch: "boot:1:1".into(),
            source_sequence: "1".into(),
        },
        payload: serde_json::json!({"component":"process"}),
        redacted: true,
    }
}
fn req(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {}", "e".repeat(32)))
        .body(Body::empty())
        .unwrap()
}
#[tokio::test]
async fn thousand_cache_reads_never_call_native() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let fake=Router::new().route("/metrics",get(move||{let c=c.clone();async move{c.fetch_add(1,Ordering::SeqCst);format!("tos_exporter_snapshot_generation 1\ntos_exporter_snapshot_completed_timestamp_seconds {}\nvalue 7\n# EOF\n",chrono::Utc::now().timestamp_millis() as f64/1000.)}}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, fake).await.unwrap() });
    let state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    *state.cache.lock().unwrap() = Some(process());
    let mut sampler = NativeSampler::new(address, state.clone()).unwrap();
    assert!(sampler.collect().await.unwrap());
    assert!(sampler.collect().await.is_err());
    let app = router(state);
    let mut success = 0;
    for _ in 0..1000 {
        let response = app.clone().oneshot(req("/metrics")).await.unwrap();
        if response.status() == StatusCode::OK {
            success += 1;
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }
    assert!(success >= 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.abort();
}
#[tokio::test]
async fn cold_metrics_and_query_rejected_without_sampler() {
    let state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    let app = router(state);
    assert_eq!(
        app.clone().oneshot(req("/metrics")).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        app.oneshot(req("/metrics?force_refresh=true")).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}
#[test]
fn duplicate_native_sample_keeps_original_age() {
    let mut cache = NativeCache::default();
    let body = "value 1\n# EOF\n".to_string();
    assert!(cache.publish("p", 1, body.clone(), 30_001, 0).unwrap());
    assert!(!cache.publish("p", 1, body, 0, 0).unwrap());
    assert!(cache.read().is_none());
}
#[test]
fn native_conflict_cannot_recover_in_same_epoch() {
    let mut c = NativeCache::default();
    c.publish("p", 1, "value 1\n# EOF\n".into(), 0, 0).unwrap();
    assert!(c.publish("p", 1, "value 2\n# EOF\n".into(), 0, 0).is_err());
    c.publish("p", 2, "value 3\n# EOF\n".into(), 0, 0).unwrap();
    assert!(c.read().is_none());
    c.publish("p2", 1, "value 3\n# EOF\n".into(), 0, 0).unwrap();
    assert!(c.read().is_some());
}
#[test]
fn native_bounds_and_loopback_are_enforced() {
    let mut c = NativeCache::default();
    assert!(c.publish("p", 1, "x".repeat(2_097_153), 0, 0).is_err());
    assert!(c.publish("p", 1, "value 1\n".into(), 0, 0).is_err());
    assert!(NativeSampler::new(
        "192.0.2.1:8080".parse().unwrap(),
        EdgeState::new("v1".into(), vec![b'e'; 32])
    )
    .is_err());
}

#[tokio::test]
async fn metrics_route_refuses_stale_conflicted_and_restarted_cache() {
    let stale = EdgeState::new("v1".into(), vec![b'e'; 32]);
    let body = "value 1\n# EOF\n".to_string();
    stale.native.lock().unwrap().publish("p", 1, body.clone(), 30_001, 0).unwrap();
    assert!(!stale.native.lock().unwrap().publish("p", 1, body, 0, 0).unwrap());
    assert_eq!(
        router(stale).oneshot(req("/metrics")).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let conflicted = EdgeState::new("v1".into(), vec![b'e'; 32]);
    conflicted.native.lock().unwrap().publish("p", 1, "value 1\n# EOF\n".into(), 0, 0).unwrap();
    assert!(conflicted
        .native
        .lock()
        .unwrap()
        .publish("p", 1, "value 2\n# EOF\n".into(), 0, 0)
        .is_err());
    assert_eq!(
        router(conflicted).oneshot(req("/metrics")).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let restarted = EdgeState::new("v1".into(), vec![b'e'; 32]);
    assert_eq!(
        router(restarted).oneshot(req("/metrics")).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
