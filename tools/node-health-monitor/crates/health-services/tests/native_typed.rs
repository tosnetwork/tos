use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tos_health_core::{
    edge_snapshot::EdgeSnapshot,
    native::{canonical_hash, NativeEnvelope},
};
use tos_health_services::{
    edge::{r4_snapshot, sample_process, EdgeState},
    native_cache::{NativeCache, NativeSampler},
};
fn fixture() -> NativeEnvelope {
    let mut value: NativeEnvelope =
        serde_json::from_str(include_str!("../../health-core/tests/fixtures/native-core.json"))
            .unwrap();
    value.source_age_ms = Some(0);
    value
}
const BODY: &str = include_str!("../../health-core/tests/fixtures/native-core.prom");
async fn fake(
    mismatch: bool,
) -> (NativeSampler, EdgeState, Arc<AtomicUsize>, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    use axum::{routing::get, Json, Router};
    let value = fixture();
    let epoch = value.process_epoch.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let reads = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let read = reads.clone();
    let app = Router::new()
        .route(
            "/metrics",
            get(move || {
                let count = count.clone();
                let epoch = epoch.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    (
                        [
                            ("x-tos-snapshot-generation", "1".to_string()),
                            ("x-tos-process-epoch", epoch),
                        ],
                        BODY,
                    )
                }
            }),
        )
        .route(
            "/health-snapshot",
            get(move || {
                let read = read.clone();
                let mut value = value.clone();
                async move {
                    read.fetch_add(1, Ordering::SeqCst);
                    if mismatch {
                        value.generation.0 = 2;
                        value.payload.generation.0 = 2;
                        value.content_hash = canonical_hash(&value.payload).unwrap();
                    }
                    Json(value)
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    let pid = std::fs::read_link("/proc/self").unwrap().to_str().unwrap().parse().unwrap();
    *state.cache.lock().unwrap() = Some(sample_process("v1", pid, 1).unwrap());
    let sampler =
        NativeSampler::new(addr, state.clone()).unwrap().with_network("a".repeat(64)).unwrap();
    (sampler, state, calls, reads, task)
}
#[tokio::test]
async fn typed_cache_duplicate_age_and_conflict_are_sticky() {
    let mut cache = NativeCache::default();
    let mut value = fixture();
    value.source_age_ms = Some(30_000);
    assert!(cache.publish_typed(value.clone(), BODY.into(), 1).is_err());
    value.source_age_ms = Some(29_980);
    assert!(cache.publish_typed(value.clone(), BODY.into(), 0).unwrap());
    tokio::time::sleep(Duration::from_millis(25)).await;
    value.source_age_ms = Some(0);
    assert!(!cache.publish_typed(value.clone(), BODY.into(), 0).unwrap());
    assert!(cache.read_typed().is_none());
    let mut cache = NativeCache::default();
    assert!(cache.publish_typed(value.clone(), BODY.into(), 0).unwrap());
    value.coverage.missing_fields.push("extra".into());
    assert!(cache.publish_typed(value.clone(), BODY.into(), 0).is_err());
    value.generation.0 = 2;
    value.payload.generation.0 = 2;
    value.content_hash = canonical_hash(&value.payload).unwrap();
    let _ = cache.publish_typed(value, BODY.into(), 0);
    assert!(cache.read_typed().is_none());
}
#[tokio::test]
async fn typed_sampler_and_edge_read_only_cache() {
    use tower::ServiceExt;
    let (mut sampler, state, calls, reads, task) = fake(false).await;
    assert!(sampler.collect().await.unwrap());
    let response = tos_health_services::edge::router(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/edge/snapshot")
                .header("authorization", format!("Bearer {}", "e".repeat(32)))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let bytes = axum::body::to_bytes(response.into_body(), 262_144).await.unwrap();
    let snapshot: EdgeSnapshot = serde_json::from_slice(&bytes).unwrap();
    assert!(snapshot.native().is_some());
    assert_eq!(snapshot.sources.len(), 2);
    snapshot.validate("v1", &"a".repeat(64)).unwrap();
    assert!(snapshot.validate("v2", &"a".repeat(64)).is_err());
    assert!(snapshot.validate("v1", &"b".repeat(64)).is_err());
    let mut duplicate = snapshot.clone();
    duplicate.sources.push(snapshot.sources[0].clone());
    assert!(duplicate.validate("v1", &"a".repeat(64)).is_err());
    for _ in 0..1000 {
        let _: EdgeSnapshot = serde_json::from_value(r4_snapshot(&state).unwrap()).unwrap();
    }
    assert!(sampler.collect().await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    task.abort();
}
#[tokio::test]
async fn mismatched_pair_has_no_retry_and_no_publication() {
    let (mut sampler, state, calls, reads, task) = fake(true).await;
    assert!(sampler.collect().await.unwrap_err().contains("generation mismatch"));
    assert!(sampler.collect().await.is_err());
    assert!(state.native.lock().unwrap().read_typed().is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    task.abort();
}
#[test]
fn native_adapter_does_not_turn_missing_pq_into_zero() {
    let mut value = fixture();
    value.payload.pq_sign.as_mut().unwrap().failed.0 = 9_007_199_254_740_993;
    value.content_hash = canonical_hash(&value.payload).unwrap();
    let frame = tos_health_services::manager_poll::native_frame(value.clone(), 17).unwrap();
    assert!(frame.complete);
    assert_eq!(frame.facts[0].value.0, 9_007_199_254_740_993);
    assert_eq!(frame.request_duration_ms.0, 17);
    value.payload.pq_sign = None;
    value.payload.pq_verify = None;
    value.quality.instrumentation_complete = false;
    value.content_hash = canonical_hash(&value.payload).unwrap();
    let frame = tos_health_services::manager_poll::native_frame(value, 0).unwrap();
    assert!(!frame.complete);
    assert!(frame.facts.is_empty());
}
#[tokio::test]
async fn r4_collector_preserves_source_identity_and_immutable_payload() {
    use tos_health_services::collector::{decode_records, evidence_identity};
    let (mut sampler, state, _, _, task) = fake(false).await;
    sampler.collect().await.unwrap();
    let mut legacy = state.cache.lock().unwrap().clone().unwrap();
    assert!(decode_records(&serde_json::to_vec(&legacy).unwrap(), "v1", None).is_ok());
    legacy.source_id = "unbounded-source".into();
    assert!(decode_records(&serde_json::to_vec(&legacy).unwrap(), "v1", None).is_err());
    let mut snapshot = r4_snapshot(&state).unwrap();
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    let records = decode_records(&bytes, "v1", Some(&"a".repeat(64))).unwrap();
    assert_eq!(records.len(), 2);
    assert!(decode_records(&bytes, "v2", Some(&"a".repeat(64))).is_err());
    let native = records.iter().find(|v| v.source_id == "native_core").unwrap();
    assert_eq!(native.payload["source"]["payload"]["pq_sign"]["succeeded"], "9007199254740993");
    assert!(native.payload["source"]["source_age_ms"].is_null());
    let id = evidence_identity(native).unwrap();
    let mut changed = native.clone();
    changed.received_at_ms += 1;
    assert_eq!(id, evidence_identity(&changed).unwrap());
    changed.payload["component"] = "changed".into();
    assert_ne!(id, evidence_identity(&changed).unwrap());
    snapshot["sources"][1]["source_age_ms"] = 100.into();
    snapshot["sources"][1]["received_at"] = "2026-09-29T05:00:00Z".into();
    let records =
        decode_records(&serde_json::to_vec(&snapshot).unwrap(), "v1", Some(&"a".repeat(64)))
            .unwrap();
    let native = records.iter().find(|v| v.source_id == "native_core").unwrap();
    assert_eq!(id, evidence_identity(native).unwrap());
    task.abort();
}
