use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tos_health_core::{
    edge_snapshot::EdgeSnapshot,
    native::{canonical_hash, NativeEnvelope, NativeEnvelopeV2, NativeRecord},
};
use tos_health_services::{
    edge::{r4_snapshot, sample_process, EdgeState},
    native_cache::{verified_binding, NativeCache, NativeSampler},
};
fn fixture() -> NativeEnvelope {
    let mut value: NativeEnvelope =
        serde_json::from_str(include_str!("../../health-core/tests/fixtures/native-core.json"))
            .unwrap();
    value.source_age_ms = Some(0);
    value
}
fn fixture_v2() -> NativeEnvelopeV2 {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../health-core/tests/fixtures/native-core.json"))
            .unwrap();
    value["source_version"] = "native-core-v2".into();
    value["coverage"]["sampling_policy"] = "native-core-v2-concurrent-bounded".into();
    value["payload"]["consensus"] = serde_json::from_str(include_str!(
        "../../health-core/tests/fixtures/consensus-v2.synthetic.json"
    ))
    .unwrap();
    value["quality"]["instrumentation_complete"] = false.into();
    value["content_hash"] = canonical_hash(&value["payload"]).unwrap().into();
    serde_json::from_value(value).unwrap()
}
#[test]
fn scheduler_skips_a_tick_missed_by_a_slow_source() {
    let started = std::time::Instant::now();
    let scheduled = started + Duration::from_secs(15);
    let completed = started + Duration::from_millis(31_500);
    let next = tos_health_services::native_cache::next_due_after_completion(scheduled, completed);
    assert_eq!(next.duration_since(completed), Duration::from_secs(15));
    assert!(next > scheduled + Duration::from_secs(15));
}
const BODY: &str = include_str!("../../health-core/tests/fixtures/native-core.prom");
async fn fake(
    mismatch: bool,
) -> (NativeSampler, EdgeState, Arc<AtomicUsize>, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    use axum::{routing::get, Json, Router};
    let state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    let pid = std::fs::read_link("/proc/self").unwrap().to_str().unwrap().parse().unwrap();
    let process = sample_process("v1", pid, 1).unwrap();
    let mut value = fixture();
    value.process_epoch = "f".repeat(32);
    value.source_epoch = value.process_epoch.clone();
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
    *state.cache.lock().unwrap() = Some(process);
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
    if let Ok(directory) = std::env::var("NHM_CONTRACT_OUTPUT_DIR") {
        std::fs::write(std::path::Path::new(&directory).join("edge-snapshot.json"), &bytes)
            .unwrap();
    }
    let snapshot: EdgeSnapshot = serde_json::from_slice(&bytes).unwrap();
    assert!(snapshot.native().is_some());
    assert_eq!(snapshot.sources.len(), 2);
    snapshot.validate("v1", &"a".repeat(64)).unwrap();
    assert_eq!(snapshot.native_process_binding.native_epoch, "f".repeat(32));
    assert_ne!(
        snapshot.native_process_binding.native_epoch,
        snapshot.native_process_binding.process_epoch
    );
    let mut wrong_pid = snapshot.clone();
    wrong_pid.native_process_binding.pid += 1;
    assert!(wrong_pid.validate("v1", &"a".repeat(64)).is_err());
    let mut wrong_listener = snapshot.clone();
    wrong_listener.native_process_binding.listener_addr = "0.0.0.0:1".into();
    assert!(wrong_listener.validate("v1", &"a".repeat(64)).is_err());
    let mut missing_binding: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    missing_binding.as_object_mut().unwrap().remove("native_process_binding");
    assert!(serde_json::from_value::<EdgeSnapshot>(missing_binding).is_err());
    assert!(snapshot.validate("v2", &"a".repeat(64)).is_err());
    assert!(snapshot.validate("v1", &"b".repeat(64)).is_err());
    let mut duplicate = snapshot.clone();
    duplicate.sources.push(snapshot.sources[0].clone());
    assert!(duplicate.validate("v1", &"a".repeat(64)).is_err());
    let mut mixed = snapshot.clone();
    let native = mixed.sources.iter_mut().find_map(|source| match source {
        tos_health_core::edge_snapshot::EdgeSource::Native(value) => Some(value),
        _ => None,
    });
    let native = native.unwrap();
    native.process_epoch = "0".repeat(32);
    native.source_epoch = native.process_epoch.clone();
    assert_eq!(
        mixed.validate("v1", &"a".repeat(64)).unwrap_err(),
        "native process binding mismatch"
    );
    for _ in 0..1000 {
        let _: EdgeSnapshot = serde_json::from_value(r4_snapshot(&state).unwrap()).unwrap();
    }
    assert!(sampler.collect().await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    task.abort();
}
#[test]
fn native_binding_requires_the_configured_process_owned_listener() {
    let pid = std::process::id();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let binding = verified_binding(pid, addr, &"e".repeat(32)).unwrap();
    assert_eq!(binding.pid, pid);
    assert_eq!(binding.listener_addr, addr.to_string());
    assert!(verified_binding(0, addr, &"e".repeat(32)).is_err());
    assert!(verified_binding(1, addr, &"e".repeat(32)).is_err());
    drop(listener);
    assert!(verified_binding(pid, addr, &"e".repeat(32)).is_err());
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
#[tokio::test]
async fn snapshot_route_refuses_conflicted_and_restarted_typed_cache() {
    use tower::ServiceExt;
    let (mut sampler, state, _, _, task) = fake(false).await;
    sampler.collect().await.unwrap();
    let mut stale_native = state.native.lock().unwrap().read_typed().unwrap();
    stale_native.source_age_ms = Some(29_980);
    let stale = EdgeState::new("v1".into(), vec![b'e'; 32]);
    *stale.cache.lock().unwrap() = state.cache.lock().unwrap().clone();
    stale.native.lock().unwrap().network = Some("a".repeat(64));
    assert!(stale.native.lock().unwrap().publish_typed(stale_native, BODY.into(), 0).unwrap());
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(stale.cache.lock().unwrap().as_ref().unwrap().quality.usable(
        chrono::Utc::now().timestamp_millis(),
        30_000,
        false
    ));
    assert!(stale.native.lock().unwrap().read_typed().is_none());
    let mut conflict = state.native.lock().unwrap().read_typed().unwrap();
    conflict.coverage.missing_fields.push("same_generation_conflict".into());
    assert!(state.native.lock().unwrap().publish_typed(conflict, BODY.into(), 0).is_err());
    let request = || {
        axum::http::Request::builder()
            .uri("/v1/edge/snapshot")
            .header("authorization", format!("Bearer {}", "e".repeat(32)))
            .body(axum::body::Body::empty())
            .unwrap()
    };
    assert_eq!(
        tos_health_services::edge::router(stale).oneshot(request()).await.unwrap().status(),
        503
    );
    assert_eq!(
        tos_health_services::edge::router(state).oneshot(request()).await.unwrap().status(),
        503
    );
    let restarted = EdgeState::new("v1".into(), vec![b'e'; 32]);
    assert_eq!(
        tos_health_services::edge::router(restarted).oneshot(request()).await.unwrap().status(),
        503
    );
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
    for availability in ["unknown", "error", "unsupported"] {
        let mut unavailable = snapshot.clone();
        unavailable["sources"][0]["availability"] = availability.into();
        unavailable["sources"][0]["observed_at"] = serde_json::Value::Null;
        assert!(decode_records(
            &serde_json::to_vec(&unavailable).unwrap(),
            "v1",
            Some(&"a".repeat(64))
        )
        .is_err());
    }
    let mut unknown_coverage = snapshot.clone();
    unknown_coverage["sources"][0]["coverage"]["status"] = "unknown".into();
    assert!(decode_records(
        &serde_json::to_vec(&unknown_coverage).unwrap(),
        "v1",
        Some(&"a".repeat(64))
    )
    .is_err());
    task.abort();
}

#[tokio::test]
async fn v2_edge_route_and_collector_keep_incomplete_consensus_typed() {
    use tos_health_services::collector::decode_records;
    use tower::ServiceExt;
    let state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    let pid = std::fs::read_link("/proc/self").unwrap().to_str().unwrap().parse().unwrap();
    let process = sample_process("v1", pid, 1).unwrap();
    let mut value = fixture_v2();
    value.process_epoch = "f".repeat(32);
    value.source_epoch = value.process_epoch.clone();
    *state.cache.lock().unwrap() = Some(process);
    state.native.lock().unwrap().network = Some("a".repeat(64));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let binding = tos_health_services::native_cache::verified_binding(
        pid,
        listener.local_addr().unwrap(),
        &value.process_epoch,
    )
    .unwrap();
    assert!(state
        .native
        .lock()
        .unwrap()
        .publish_record_with_binding(NativeRecord::V2(value), BODY.into(), 0, Some(binding))
        .unwrap());
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
    if let Ok(directory) = std::env::var("NHM_CONTRACT_OUTPUT_DIR") {
        std::fs::write(std::path::Path::new(&directory).join("edge-snapshot-v2.json"), &bytes)
            .unwrap();
    }
    let snapshot: EdgeSnapshot = serde_json::from_slice(&bytes).unwrap();
    snapshot.validate("v1", &"a".repeat(64)).unwrap();
    assert!(snapshot.native().is_none());
    let native = snapshot.native_v2().unwrap();
    assert!(!native.quality.instrumentation_complete);
    assert!(native.payload.consensus.as_ref().unwrap().sessions.stopped.is_none());
    let archived = decode_records(&bytes, "v1", Some(&"a".repeat(64))).unwrap();
    let record = archived.iter().find(|v| v.source_id == "native_core").unwrap();
    assert_eq!(record.payload["source"]["source_version"], "native-core-v2");
    assert_eq!(
        record.payload["source"]["payload"]["consensus"]["sessions"]["stopped"],
        serde_json::Value::Null
    );
    let frame = tos_health_services::manager_poll::native_frame_v2(native.clone(), 0).unwrap();
    assert!(!frame.complete);
    assert_eq!(frame.facts.len(), 1); // existing PQ only; no invented C04 rule fact
}

#[test]
fn v2_cache_epoch_switch_retires_old_pair_without_counter_merge() {
    let mut cache = NativeCache::default();
    let original = fixture_v2();
    assert!(cache.publish_record(NativeRecord::V2(original.clone()), BODY.into(), 0).unwrap());
    let mut next = original.clone();
    next.process_epoch = "1".repeat(32);
    next.source_epoch = next.process_epoch.clone();
    assert!(cache.publish_record(NativeRecord::V2(next), BODY.into(), 0).unwrap());
    assert_eq!(cache.read_record().unwrap().process_epoch(), "1".repeat(32));
    assert!(cache.publish_record(NativeRecord::V2(original), BODY.into(), 0).is_err());
    assert_eq!(cache.read_record().unwrap().process_epoch(), "1".repeat(32));
}
