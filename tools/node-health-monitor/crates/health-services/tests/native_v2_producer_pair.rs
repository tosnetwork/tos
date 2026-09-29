//! Cross-language C04 test. Run explicitly with NHM_C04_PAIR_DIR pointing to
//! an indexed isolated native publisher fixture, never a live business node.
use std::path::Path;
use tos_health_core::edge_snapshot::EdgeSnapshot;
use tos_health_core::native::{canonical_hash, parse_native, NativeEnvelopeV2, NativeRecord};
use tos_health_services::{
    collector::decode_records,
    edge::{r4_snapshot, sample_process, EdgeState},
    native_cache::{verified_binding, NativeCache},
};
use tower::ServiceExt;

fn changed(mut value: serde_json::Value) -> NativeEnvelopeV2 {
    value["content_hash"] = canonical_hash(&value["payload"]).unwrap().into();
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
#[ignore = "requires indexed native C++ publisher pair; run with NHM_C04_PAIR_DIR"]
async fn actual_cpp_publisher_pairs_and_negatives() {
    let directory = std::env::var("NHM_C04_PAIR_DIR").expect("set indexed native pair directory");
    let directory = Path::new(&directory);
    let mut cache = NativeCache::default();
    let mut first = None;
    let mut last = None;
    for generation in 1..=3u64 {
        let bytes = std::fs::read(directory.join(format!("success-{generation}.json"))).unwrap();
        let body =
            std::fs::read_to_string(directory.join(format!("success-{generation}.prom"))).unwrap();
        let record = parse_native(&bytes).unwrap();
        let NativeRecord::V2(value) = &record else { panic!("native producer did not emit v2") };
        assert_eq!(value.generation.0, generation);
        assert_eq!(value.payload.consensus.as_ref().unwrap().actions.len(), 4);
        record
            .paired("v1", &"a".repeat(64), &generation.to_string(), &value.process_epoch, &body)
            .unwrap();
        assert!(cache.publish_record(record.clone(), body.clone(), 0).unwrap());
        assert_eq!(cache.read_record().unwrap().generation().0, generation);
        last = Some((record.clone(), body.clone()));
        if generation == 1 {
            first = Some((bytes, body, value.clone()));
        }
    }
    // The native producer may add replay/failure/post-terminal witnesses to
    // this directory. Every .prom pair is admitted through the same strict
    // decoder, without assuming these cases share a monotonic cache sequence.
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|v| v.to_str()) != Some("prom") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap();
        if matches!(name, "success-1" | "success-2" | "success-3") {
            continue;
        }
        let bytes = std::fs::read(path.with_extension("json")).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let record = parse_native(&bytes).unwrap();
        let NativeRecord::V2(value) = &record else { panic!("non-v2 native pair: {name}") };
        record
            .paired(
                &value.node_id,
                &value.payload.network_id,
                &value.generation.0.to_string(),
                &value.process_epoch,
                &body,
            )
            .unwrap();
    }
    let (last_record, last_body) = last.unwrap();
    let state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    let pid = std::fs::read_link("/proc/self").unwrap().to_str().unwrap().parse().unwrap();
    let process = sample_process("v1", pid, 1).unwrap();
    *state.cache.lock().unwrap() = Some(process);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let binding =
        verified_binding(pid, listener.local_addr().unwrap(), last_record.process_epoch()).unwrap();
    state.native.lock().unwrap().network = Some("a".repeat(64));
    assert!(state
        .native
        .lock()
        .unwrap()
        .publish_record_with_binding(last_record, last_body, 0, Some(binding))
        .unwrap());
    let snapshot_value = r4_snapshot(&state).unwrap();
    let response = tos_health_services::edge::router(state)
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
    let route_bytes = axum::body::to_bytes(response.into_body(), 262_144).await.unwrap();
    let route_value: serde_json::Value = serde_json::from_slice(&route_bytes).unwrap();
    let direct: EdgeSnapshot = serde_json::from_value(snapshot_value).unwrap();
    let routed: EdgeSnapshot = serde_json::from_value(route_value).unwrap();
    direct.validate("v1", &"a".repeat(64)).unwrap();
    routed.validate("v1", &"a".repeat(64)).unwrap();
    let direct_native = direct.native_v2().unwrap();
    let routed_native = routed.native_v2().unwrap();
    assert_eq!(routed_native.generation, direct_native.generation);
    assert_eq!(routed_native.content_hash, direct_native.content_hash);
    assert!(routed_native.source_age_ms.unwrap() >= direct_native.source_age_ms.unwrap());
    if let Ok(output_dir) = std::env::var("NHM_C04_OUTPUT_DIR") {
        std::fs::write(Path::new(&output_dir).join("edge-snapshot-producer-v2.json"), &route_bytes)
            .unwrap();
    }
    let snapshot = routed;
    snapshot.validate("v1", &"a".repeat(64)).unwrap();
    assert_eq!(snapshot.native_v2().unwrap().generation.0, 3);
    let records = decode_records(&route_bytes, "v1", Some(&"a".repeat(64))).unwrap();
    assert!(records.iter().any(|record| record.source_id == "native_core"));
    let (bytes, body, value) = first.unwrap();
    assert!(value.paired("v1", &"a".repeat(64), "2", &value.process_epoch, &body).is_err());
    assert!(value
        .paired("v1", &"a".repeat(64), "1", &value.process_epoch, body.trim_end())
        .is_err());
    let mut wrong_body = body.clone().into_bytes();
    wrong_body[0] = b'!';
    let wrong_body = String::from_utf8(wrong_body).unwrap();
    assert!(value.paired("v1", &"a".repeat(64), "1", &value.process_epoch, &wrong_body).is_err());

    let mut raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    raw["payload"]["consensus"]["actions"][1]["replay"]["signed_record"]["phases"]["signed"] =
        "1".into();
    assert!(changed(raw).validate().is_err());
    let mut raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    raw["payload"]["consensus"]["sessions"]["started"] = "18446744073709551616".into();
    assert!(parse_native(&serde_json::to_vec(&raw).unwrap()).is_err());
    let mut raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    raw["payload"]["consensus"]["contexts"][0]["scope"]["shard"] = "1".into();
    assert!(changed(raw).validate().is_err());
    let mut raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    raw["payload"]["consensus"]["actions"].as_array_mut().unwrap().swap(0, 1);
    assert!(changed(raw).validate().is_err());
    let mut raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    raw["quality"]["instrumentation_complete"] = true.into();
    assert!(serde_json::from_value::<NativeEnvelopeV2>(raw).unwrap().validate().is_err());
}
