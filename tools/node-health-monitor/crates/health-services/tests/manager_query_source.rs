use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::atomic::Ordering};
use tos_health_core::{
    edge_snapshot::{ProcessEnvelope, ProcessPayload},
    evidence::{Evidence, EvidenceStore},
    native::{canonical_hash, Coverage as NativeCoverage, Quality, SourceEnvelope},
    query::{Grant, QueryService, TOOLS},
    source::{Availability, Coverage, SourceQuality},
    wire::U64,
};
use tos_health_services::{
    durable::{DurableEvidence, EvidenceDb},
    fixed_package::freeze_process_package,
    manager_query_source::{project_process, read_process_projection},
    observability::{control_router, import_manager, router as query_router, ObservabilityState},
    query_ledger::QueryLedger,
    random_token, Inventory,
};
use tower::ServiceExt;

async fn body(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn durable_projection_requires_exact_retained_parent_on_insert_and_reopen() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-parent-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let manager_path = directory.join("manager.sqlite");
    let ledger_path = directory.join("query.sqlite");
    let mut manager = EvidenceDb::open(&manager_path, 4 * 1024 * 1024).unwrap();
    manager.bind_network(&"a".repeat(64)).unwrap();
    manager.insert(row("edge-epoch-1")).unwrap();
    let (_, records) = read_process_projection(&manager_path, &"a".repeat(64)).unwrap();
    let (origin, projection) = &records[0];
    let mut ledger = QueryLedger::open(&ledger_path).unwrap();
    let mut store = EvidenceStore::new(80_000);
    assert!(ledger.insert_evidence(&mut store, projection.clone()).unwrap_err().contains("parent"));
    let mut altered = projection.clone();
    altered.payload["contract_payload"]["rss_bytes"] = serde_json::json!("8192");
    assert!(ledger.insert_projection(&mut store, origin, altered).unwrap_err().contains("differs"));
    let projected_id = ledger.insert_projection(&mut store, origin, projection.clone()).unwrap();
    assert_eq!(
        ledger.insert_projection(&mut store, origin, projection.clone()).unwrap(),
        projected_id
    );
    drop(ledger);
    let ledger = QueryLedger::open(&ledger_path).unwrap();
    assert_eq!(ledger.load_evidence(80_000).unwrap().watermark(), 1);
    drop(ledger);
    rusqlite::Connection::open(&ledger_path)
        .unwrap()
        .execute("UPDATE query_origins SET body='{}'", [])
        .unwrap();
    let ledger = QueryLedger::open(&ledger_path).unwrap();
    assert!(ledger.load_evidence(80_000).is_err());
    drop(ledger);
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}

fn row(epoch: &str) -> DurableEvidence {
    let at = "2026-09-29T00:00:01.000Z";
    let timestamp = chrono::DateTime::parse_from_rfc3339(at).unwrap().timestamp_millis();
    let payload = ProcessPayload {
        kind: "process".into(),
        pid: 4242,
        rss_bytes: Some(U64(4096)),
        anon_bytes: None,
        file_bytes: None,
        swap_bytes: None,
        cpu_user_ticks: Some(U64(7)),
        cpu_system_ticks: Some(U64(3)),
    };
    let source: ProcessEnvelope = SourceEnvelope {
        schema_version: 1,
        source_id: "process".into(),
        node_id: "v1".into(),
        scope_id: "node".into(),
        process_epoch: "boot:4242:100".into(),
        source_epoch: epoch.into(),
        source_version: "proc-v1".into(),
        generation: U64(1),
        availability: "available".into(),
        observed_at: Some(at.into()),
        last_success_at: Some(at.into()),
        received_at: None,
        source_age_ms: None,
        clock_quality: "valid".into(),
        coverage: NativeCoverage {
            status: "partial".into(),
            missing_fields: vec!["host_pressure".into()],
            gaps: vec![],
            sampling_policy: "fixed_15s".into(),
        },
        content_hash: canonical_hash(&payload).unwrap(),
        payload,
        quality: Quality {
            instrumentation_complete: false,
            producer_dropped: U64(0),
            relay_dropped: U64(0),
            parse_errors: U64(0),
            shed_reason: None,
        },
    };
    DurableEvidence {
        source_epoch: epoch.into(),
        record: Evidence {
            node_id: "v1".into(),
            scope_id: "node".into(),
            source_id: "process".into(),
            source_record_id: format!("{epoch}:1"),
            process_epoch: "boot:4242:100".into(),
            observed_at_ms: timestamp,
            received_at_ms: timestamp + 1000,
            quality: SourceQuality {
                availability: Availability::Available,
                coverage: Coverage::Partial,
                observed_at_ms: Some(timestamp),
                last_success_at_ms: Some(timestamp),
                clock_valid: true,
                process_epoch: "boot:4242:100".into(),
                source_sequence: "1".into(),
            },
            payload: serde_json::json!({"component":"process","source":source}),
            redacted: true,
        },
    }
}

#[test]
fn real_m_writer_process_row_projects_with_parent_and_fixed_query_watermark() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("manager.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&path, 4 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    let original = manager.insert(row("edge-epoch-1")).unwrap();
    let (m_watermark, records) = read_process_projection(&path, &network).unwrap();
    assert_eq!(m_watermark, original.store_seq.0);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1.payload["parent_evidence_ids"][0], original.evidence_id);
    assert_eq!(records[0].1.payload["contract_payload"]["rss_bytes"], "4096");
    assert_eq!(records[0].1.payload["contract_coverage"]["status"], "partial");
    let mut query_store = EvidenceStore::new(80_000);
    query_store.insert(records[0].1.clone()).unwrap();
    let token = [7u8; 32];
    let mut grant = Grant::new(
        "00000000-0000-4000-8000-000000000001".into(),
        "aura".into(),
        network.clone(),
        &token,
        BTreeSet::from(["v1".into()]),
        BTreeSet::from(["node".into()]),
        1790640000000,
        1790640060000,
        0,
        query_store.watermark(),
    )
    .unwrap();
    let metrics = BTreeSet::new();
    let run = grant.run_id.clone();
    let response = QueryService { store: &query_store, metrics: &metrics }.call(
        &mut grant,
        "aura",
        &token,
        1,
        TOOLS[1],
        serde_json::json!({"run_id":run,"node_id":"v1","as_of":"2026-09-29T00:00:02Z","max_age_seconds":30,"components":["process"]}),
    );
    assert_eq!(response["status"], "partial", "{response}");
    assert_eq!(response["evidence"][0]["kind"], "derived");
    assert_eq!(response["evidence"][0]["parent_evidence_ids"][0], original.evidence_id);
    assert_eq!(response["evidence"][0]["derivation_version"], "m-observation-projection-v1");
    assert_eq!(response["data"]["components"][0]["value"]["rss_bytes"], "4096");
    assert_eq!(response["coverage"]["status"], "partial");

    let mut changed = row("edge-epoch-1");
    changed.record.payload["source"]["payload"]["rss_bytes"] = serde_json::json!("8192");
    assert_eq!(manager.insert(changed).unwrap_err(), "SOURCE_CONFLICT");
    assert!(read_process_projection(&path, &network).unwrap().1.is_empty());
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn projection_refuses_wrong_origin_hash_and_unknown_source_fields() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-negative-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let mut manager = EvidenceDb::open(&directory.join("manager.sqlite"), 4 * 1024 * 1024).unwrap();
    manager.bind_network(&"a".repeat(64)).unwrap();
    let saved = manager.insert(row("edge-epoch-1")).unwrap();
    let mut wrong_hash = saved.clone();
    wrong_hash.evidence_id = "b".repeat(64);
    assert!(project_process(&wrong_hash).unwrap_err().contains("hash"));
    let mut db_row = row("edge-epoch-2");
    db_row.record.payload["source"]["unexpected"] = serde_json::json!(true);
    let changed = manager.insert(db_row).unwrap();
    assert!(project_process(&changed).unwrap_err().contains("unknown field"));
    let mut clock_unknown = row("edge-epoch-3");
    clock_unknown.record.payload["source"]["clock_quality"] = serde_json::json!("unknown");
    clock_unknown.record.quality.clock_valid = false;
    let unknown = manager.insert(clock_unknown).unwrap();
    assert!(project_process(&unknown).unwrap_err().contains("unavailable"));
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn unsupported_diagnostic_population_does_not_consume_process_scan_or_quarantine_cap() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-separated-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("manager.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&path, 16 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    let tx = conn.transaction().unwrap();
    {
        let mut insert = tx.prepare(
            "INSERT INTO observations(node,scope,process_epoch,source_epoch,source,source_record,content_hash,body)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        ).unwrap();
        for sequence in 1..=4097 {
            let mut diagnostic = row("d1");
            diagnostic.record.source_id = "consensus_diagnostic".into();
            diagnostic.record.source_record_id = sequence.to_string();
            diagnostic.record.payload = serde_json::json!({"component":"diagnostic","event":{"kind":"consensus_action_phase"}});
            let mut canonical = diagnostic.clone();
            canonical.record.received_at_ms = 0;
            let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&canonical).unwrap()));
            let body = serde_json::to_string(&diagnostic).unwrap();
            assert!(body.len() < 32_768);
            insert
                .execute(rusqlite::params![
                    diagnostic.record.node_id,
                    diagnostic.record.scope_id,
                    diagnostic.record.process_epoch,
                    diagnostic.source_epoch,
                    diagnostic.record.source_id,
                    diagnostic.record.source_record_id,
                    digest,
                    body,
                ])
                .unwrap();
        }
    }
    tx.commit().unwrap();
    let process = manager.insert(row("edge-epoch-1")).unwrap();
    let (watermark, records, quarantined) =
        tos_health_services::manager_query_source::read_process_projection_state(&path, &network)
            .unwrap();
    assert_eq!(watermark, 4098);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0.evidence_id, process.evidence_id);
    assert!(quarantined.is_empty());
    conn.execute(
        "INSERT INTO quarantined(node,scope,process_epoch,source_epoch,source) VALUES(?1,?2,?3,?4,?5)",
        rusqlite::params!["v1", "node", "boot:4242:100", "d1", "consensus_diagnostic"],
    ).unwrap();
    let (_, records, quarantined) =
        tos_health_services::manager_query_source::read_process_projection_state(&path, &network)
            .unwrap();
    assert_eq!(records.len(), 1);
    assert!(quarantined.is_empty());
    drop(conn);
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn broker_grant_imports_actual_m_row_once_and_routes_derived_snapshot() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-route-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let manager_path = directory.join("manager.sqlite");
    let ledger_path = directory.join("query.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&manager_path, 4 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    let mut unsupported = row("edge-epoch-0");
    unsupported.record.source_id = "host_cgroup".into();
    unsupported.record.payload["component"] = serde_json::json!("host");
    manager.insert(unsupported).unwrap();
    let origin = manager.insert(row("edge-epoch-1")).unwrap();
    assert_eq!(origin.store_seq.0, 2);
    let inventory = Inventory {
        network_id: network,
        nodes: BTreeSet::from(["v1".into()]),
        scopes: BTreeSet::from(["node".into()]),
    };
    let state =
        ObservabilityState::new(inventory.clone(), vec![b'o'; 32], vec![b'i'; 32], vec![b'a'; 32])
            .unwrap()
            .with_query_ledger(&ledger_path)
            .unwrap()
            .with_manager_evidence(manager_path.clone())
            .unwrap();
    let grant_request = Request::builder()
        .method("POST")
        .uri("/v1/control/grants")
        .header("authorization", format!("Bearer {}", "o".repeat(32)))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"node_ids":["v1"],"scope_ids":["node"],"start":"2026-09-29T00:00:00Z","end":"2026-09-29T00:01:00Z"}).to_string()))
        .unwrap();
    let grant_response = control_router(state.clone()).oneshot(grant_request).await.unwrap();
    assert_eq!(grant_response.status(), StatusCode::OK);
    let granted = body(grant_response).await;
    let run = granted["run_id"].as_str().unwrap();
    let token = granted["run_token"].as_str().unwrap();
    let package = freeze_process_package(&state, run).unwrap();
    let package_json: serde_json::Value = serde_json::from_slice(&package.bytes).unwrap();
    assert_eq!(package_json["status"], "partial");
    assert_eq!(package_json["source_profile"], "development_process_only");
    assert_eq!(package_json["query_watermark"], "1");
    assert_eq!(package_json["manager_watermark"], origin.store_seq.0.to_string());
    assert_eq!(package_json["process"][0]["parent_evidence_id"], origin.evidence_id);
    assert_eq!(package_json["process"][0]["value"]["rss_bytes"], "4096");
    assert_eq!(package_json["missing_process"].as_array().unwrap().len(), 0);
    assert_eq!(package.sha256, format!("{:x}", Sha256::digest(&package.bytes)));
    assert_eq!(
        state
            .query_ledger
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .load_active_package(run, tos_health_services::query_ledger::boot_millis().unwrap())
            .unwrap(),
        Some((package.sha256.clone(), package.bytes.clone()))
    );
    let request = Request::builder()
        .method("POST")
        .uri("/v1/query/node-snapshot")
        .header("authorization", format!("Bearer {}", "a".repeat(32)))
        .header("x-tos-run-token", token)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"run_id":run,"node_id":"v1","as_of":"2026-09-29T00:00:02Z","max_age_seconds":30,"components":["process"]}).to_string()))
        .unwrap();
    let response = query_router(state.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let output = body(response).await;
    assert_eq!(output["status"], "partial");
    assert_eq!(output["evidence"][0]["parent_evidence_ids"][0], origin.evidence_id);
    assert_eq!(output["evidence"][0]["kind"], "derived");
    assert_eq!(output["data"]["components"][0]["value"]["rss_bytes"], "4096");
    let query_w = state.data.lock().unwrap().store.watermark();
    assert_eq!(query_w, 1);
    assert_eq!(state.data.lock().unwrap().grants[run].manager_watermark, Some(origin.store_seq.0));
    // An unrelated direct cache row arrives after the grant fixed W. It must
    // neither enter nor change the already-frozen M-derived package.
    let mut late_direct = row("late-direct").record;
    late_direct.source_record_id = "late-direct:1".into();
    late_direct.payload = serde_json::json!({"kind":"unavailable","reason":"synthetic late row"});
    {
        let mut data = state.data.lock().unwrap();
        state
            .query_ledger
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .insert_evidence(&mut data.store, late_direct)
            .unwrap();
    }
    assert_eq!(state.data.lock().unwrap().store.watermark(), 2);
    assert_eq!(freeze_process_package(&state, run).unwrap().sha256, package.sha256);
    let late_origin = manager.insert(row("edge-epoch-2")).unwrap();
    assert_eq!(import_manager(&state).unwrap().0, late_origin.store_seq.0);
    assert_eq!(state.data.lock().unwrap().store.watermark(), 3);
    assert_eq!(freeze_process_package(&state, run).unwrap().sha256, package.sha256);
    let capabilities = Request::builder()
        .method("POST")
        .uri("/v1/query/capabilities")
        .header("authorization", format!("Bearer {}", "a".repeat(32)))
        .header("x-tos-run-token", token)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"run_id":run}).to_string()))
        .unwrap();
    let capability_response = query_router(state.clone()).oneshot(capabilities).await.unwrap();
    assert_eq!(capability_response.status(), StatusCode::OK);
    assert_eq!(body(capability_response).await["data"]["watermark"], "1");
    drop(state);
    let restored =
        ObservabilityState::new(inventory, vec![b'o'; 32], vec![b'i'; 32], vec![b'a'; 32])
            .unwrap()
            .with_query_ledger(&ledger_path)
            .unwrap()
            .with_manager_evidence(manager_path)
            .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/v1/query/node-snapshot")
        .header("authorization", format!("Bearer {}", "a".repeat(32)))
        .header("x-tos-run-token", token)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"run_id":run,"node_id":"v1","as_of":"2026-09-29T00:00:02Z","max_age_seconds":30,"components":["process"]}).to_string()))
        .unwrap();
    let restarted = query_router(restored.clone()).oneshot(request).await.unwrap();
    assert_eq!(restarted.status(), StatusCode::OK);
    assert_eq!(body(restarted).await["evidence"][0]["parent_evidence_ids"][0], origin.evidence_id);
    let restored_package = freeze_process_package(&restored, run).unwrap();
    assert_eq!(restored_package.bytes, package.bytes);
    assert_eq!(restored_package.sha256, package.sha256);
    // The next bounded broker refresh sees M's later source quarantine and
    // durably revokes this fixed-W run. No query handler reads M to decide it.
    let mut conflict = row("edge-epoch-1");
    conflict.record.payload["source"]["payload"]["rss_bytes"] = serde_json::json!("8192");
    assert_eq!(manager.insert(conflict).unwrap_err(), "SOURCE_CONFLICT");
    assert!(import_manager(&restored).unwrap_err().contains("quarantined"));
    assert!(restored.data.lock().unwrap().manager_conflicted);
    assert!(freeze_process_package(&restored, run).is_err());
    assert!(restored
        .query_ledger
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .load_active_package(run, tos_health_services::query_ledger::boot_millis().unwrap())
        .unwrap()
        .is_none());
    let refused = Request::builder()
        .method("POST")
        .uri("/v1/query/node-snapshot")
        .header("authorization", format!("Bearer {}", "a".repeat(32)))
        .header("x-tos-run-token", token)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"run_id":run,"node_id":"v1","as_of":"2026-09-29T00:00:02Z","max_age_seconds":30,"components":["process"]}).to_string()))
        .unwrap();
    assert_eq!(
        query_router(restored.clone()).oneshot(refused).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let next_grant = Request::builder()
        .method("POST")
        .uri("/v1/control/grants")
        .header("authorization", format!("Bearer {}", "o".repeat(32)))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"node_ids":["v1"],"scope_ids":["node"],"start":"2026-09-29T00:00:00Z","end":"2026-09-29T00:01:00Z"}).to_string()))
        .unwrap();
    assert_eq!(
        control_router(restored.clone()).oneshot(next_grant).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(QueryLedger::open(&ledger_path).unwrap().inspect(run).unwrap().unwrap()["revoked"]
        .as_bool()
        .unwrap());
    drop(restored);
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn thousand_real_query_requests_do_not_read_manager_archive() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-storm-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let manager_path = directory.join("manager.sqlite");
    let ledger_path = directory.join("query.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&manager_path, 4 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    manager.insert(row("edge-epoch-1")).unwrap();
    let state = ObservabilityState::new(
        Inventory {
            network_id: network,
            nodes: BTreeSet::from(["v1".into()]),
            scopes: BTreeSet::from(["node".into()]),
        },
        vec![b'o'; 32],
        vec![b'i'; 32],
        vec![b'a'; 32],
    )
    .unwrap()
    .with_query_ledger(&ledger_path)
    .unwrap()
    .with_manager_evidence(manager_path)
    .unwrap();
    let grant = control_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/control/grants")
                .header("authorization", format!("Bearer {}", "o".repeat(32)))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"node_ids":["v1"],"scope_ids":["node"],
                    "start":"2026-09-29T00:00:00Z","end":"2026-09-29T00:01:00Z"})
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(grant.status(), StatusCode::OK);
    let granted = body(grant).await;
    let run = granted["run_id"].as_str().unwrap();
    let token = granted["run_token"].as_str().unwrap();
    let before = state.manager_projection_reads.load(Ordering::Relaxed);
    assert_eq!(before, 2, "startup and grant each perform one bounded broker import");
    let mut accepted = 0;
    let mut refused = 0;
    for _ in 0..1000 {
        let response = query_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/query/node-snapshot")
                    .header("authorization", format!("Bearer {}", "a".repeat(32)))
                    .header("x-tos-run-token", token)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"run_id":run,"node_id":"v1",
                        "as_of":"2026-09-29T00:00:02Z","max_age_seconds":30,
                        "components":["process"]})
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        match response.status() {
            StatusCode::OK => accepted += 1,
            StatusCode::TOO_MANY_REQUESTS => refused += 1,
            other => panic!("unexpected storm status: {other}"),
        }
    }
    assert_eq!((accepted, refused), (16, 984));
    assert_eq!(state.manager_projection_reads.load(Ordering::Relaxed), before);
    import_manager(&state).unwrap();
    assert_eq!(state.manager_projection_reads.load(Ordering::Relaxed), before + 1);
    drop(state);
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn fixed_package_marks_unmaterialized_process_missing_without_promoting_direct_cache() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-fixed-package-missing-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let manager_path = directory.join("manager.sqlite");
    let ledger_path = directory.join("query.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&manager_path, 4 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    let state = ObservabilityState::new(
        Inventory {
            network_id: network,
            nodes: BTreeSet::from(["v1".into()]),
            scopes: BTreeSet::from(["node".into()]),
        },
        vec![b'o'; 32],
        vec![b'i'; 32],
        vec![b'a'; 32],
    )
    .unwrap()
    .with_query_ledger(&ledger_path)
    .unwrap()
    .with_manager_evidence(manager_path)
    .unwrap();
    {
        let mut data = state.data.lock().unwrap();
        state
            .query_ledger
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .insert_evidence(&mut data.store, row("untrusted-direct").record)
            .unwrap();
    }
    let grant = control_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/control/grants")
                .header("authorization", format!("Bearer {}", "o".repeat(32)))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"node_ids":["v1"],"scope_ids":["node"],
                    "start":"2026-09-29T00:00:00Z","end":"2026-09-29T00:01:00Z"})
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(grant.status(), StatusCode::OK);
    let granted = body(grant).await;
    let frozen = freeze_process_package(&state, granted["run_id"].as_str().unwrap()).unwrap();
    let package: serde_json::Value = serde_json::from_slice(&frozen.bytes).unwrap();
    assert_eq!(package["query_watermark"], "1");
    assert_eq!(package["manager_watermark"], "0");
    assert_eq!(package["status"], "partial");
    assert!(package["process"].as_array().unwrap().is_empty());
    assert_eq!(package["missing_process"][0]["node_id"], "v1");
    drop(state);
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn broker_parent_index_overflow_latches_refusal_without_deadlocking_ledger() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-index-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let manager_path = directory.join("manager.sqlite");
    let ledger_path = directory.join("query.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&manager_path, 4 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    let inventory = Inventory {
        network_id: network,
        nodes: BTreeSet::from(["v1".into()]),
        scopes: BTreeSet::from(["node".into()]),
    };
    let state = ObservabilityState::new(inventory, vec![b'o'; 32], vec![b'i'; 32], vec![b'a'; 32])
        .unwrap()
        .with_query_ledger(&ledger_path)
        .unwrap()
        .with_manager_evidence(manager_path)
        .unwrap();
    rusqlite::Connection::open(&ledger_path)
        .unwrap()
        .execute_batch(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4097)
             INSERT INTO query_origins(origin_id,manager_seq,body)
             SELECT printf('%064x',x),x,X'7b7d' FROM n",
        )
        .unwrap();
    let checked = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::task::spawn_blocking({
            let state = state.clone();
            move || import_manager(&state)
        }),
    )
    .await
    .expect("ledger error path must not retain its guard")
    .unwrap();
    assert!(checked.unwrap_err().contains("overflow"));
    assert!(state.data.lock().unwrap().manager_conflicted);
    drop(state);
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}
