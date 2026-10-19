use tos_health_core::edge_snapshot::{CgroupEnvelope, EdgeSnapshot, EdgeSource, ProcessEnvelope};
use tos_health_core::native::{canonical_hash, NativeEnvelope};

fn fixture() -> NativeEnvelope {
    serde_json::from_str(include_str!("fixtures/native-core.json")).expect("native fixture")
}
#[test]
fn exact_pairing_rejects_changed_generation_and_content() {
    let value = fixture();
    let body = include_str!("fixtures/native-core.prom");
    let pair = |v: &NativeEnvelope, generation: &str, body: &str| {
        v.paired("v1", &"a".repeat(64), generation, &v.process_epoch, body)
    };
    assert!(pair(&value, "1", body).is_ok());
    assert_eq!(
        value.payload.pq_sign.as_ref().expect("PQ enabled").succeeded.0,
        9_007_199_254_740_993
    );
    assert!(pair(&value, "2", body).is_err());
    assert!(pair(&value, "01", body).is_err());
    assert!(value.paired("v2", &"a".repeat(64), "1", &value.process_epoch, body).is_err());
    assert!(value.paired("v1", &"b".repeat(64), "1", &value.process_epoch, body).is_err());
    assert!(value.paired("v1", &"a".repeat(64), "1", "other", body).is_err());
    assert!(pair(&value, "1", &body.replace("fixture_calls 1", "fixture_calls 2")).is_err());
    assert!(pair(
        &value,
        "1",
        &body.replace(
            "exporter_snapshot_collection_skipped_total 0",
            "exporter_snapshot_collection_skipped_total 1"
        )
    )
    .is_err());
    let mut changed = value.clone();
    changed.payload.pq_sign.as_mut().expect("PQ enabled").failed.0 = 7;
    assert!(changed.validate().is_err());
    changed.content_hash = canonical_hash(&changed.payload).expect("hash");
    assert!(changed.validate().is_ok());
}
#[test]
fn required_nullable_and_unknown_fields_are_enforced() {
    let mut value = serde_json::to_value(fixture()).expect("serialize");
    value["payload"]["pq_sign"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<NativeEnvelope>(value.clone()).is_ok());
    value["payload"].as_object_mut().expect("payload").remove("pq_sign");
    assert!(serde_json::from_value::<NativeEnvelope>(value).is_err());
    let mut unknown = serde_json::to_value(fixture()).expect("serialize");
    unknown["payload"]["force_refresh"] = true.into();
    assert!(serde_json::from_value::<NativeEnvelope>(unknown).is_err());
}
#[test]
fn age_and_quality_cannot_be_fabricated() {
    let mut value = fixture();
    value.source_age_ms = Some(30_000);
    assert!(value.validate().is_ok());
    value.source_age_ms = Some(30_001);
    assert!(value.validate().is_err());
    value.source_age_ms = None;
    assert!(value.validate().is_err());
    value.source_age_ms = Some(0);
    value.quality.instrumentation_complete = false;
    assert!(value.validate().is_err());
}
#[test]
fn immutable_identity_excludes_only_receipt_and_age() {
    let mut value = fixture();
    let original = value.immutable_hash().expect("hash");
    value.source_age_ms = Some(123);
    value.received_at = Some("2026-09-29T05:00:00Z".into());
    assert_eq!(original, value.immutable_hash().expect("hash"));
    value.coverage.missing_fields.push("new_gap".into());
    assert_ne!(original, value.immutable_hash().expect("hash"));
}

#[test]
fn edge_wire_requires_bound_process_native_and_cgroup_epochs() {
    let mut process: ProcessEnvelope =
        serde_json::from_str(include_str!("fixtures/process-source.json")).unwrap();
    let mut cgroup: CgroupEnvelope =
        serde_json::from_str(include_str!("fixtures/host-cgroup.json")).unwrap();
    let process_epoch = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:4242:123";
    process.process_epoch = process_epoch.into();
    cgroup.process_epoch = process_epoch.into();
    let native = fixture();
    let snapshot = EdgeSnapshot {
        schema_version: 1,
        status: "partial".into(),
        sources: vec![
            EdgeSource::Process(process),
            EdgeSource::Native(native.clone()),
            EdgeSource::Cgroup(cgroup),
        ],
        anchors: vec![],
        native_process_binding: tos_health_core::edge_snapshot::NativeProcessBinding {
            kind: "native_process_binding".into(),
            process_epoch: process_epoch.into(),
            native_epoch: native.process_epoch,
            pid: 4242,
            start_ticks: tos_health_core::wire::U64(123),
            exe_identity_sha256: "b".repeat(64),
            listener_inode: tos_health_core::wire::U64(1),
            listener_addr: "127.0.0.1:1234".into(),
            checked_at: "2026-09-29T00:00:00Z".into(),
        },
    };
    snapshot.validate("v1", &"a".repeat(64)).unwrap();
    let mut copied_old = snapshot.clone();
    let native = copied_old.sources.iter_mut().find_map(|source| match source {
        EdgeSource::Native(value) => Some(value),
        _ => None,
    });
    let native = native.unwrap();
    native.process_epoch = "0".repeat(32);
    native.source_epoch = native.process_epoch.clone();
    assert_eq!(
        copied_old.validate("v1", &"a".repeat(64)).unwrap_err(),
        "native process binding mismatch"
    );
}
