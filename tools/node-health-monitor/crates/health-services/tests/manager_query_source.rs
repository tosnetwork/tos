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
    manager_query_source::{
        project_process, read_process_projection, read_process_projection_page,
    },
    observability::{control_router, import_manager, router as query_router, ObservabilityState},
    query_ledger::{ManagerCursor, QueryLedger},
    random_token, Inventory,
};
use tower::ServiceExt;

/// Opt-in local cost witness. M is opened read-only; only a disposable Q ledger
/// is written. It is not a performance acceptance threshold or an AURA call.
#[tokio::test]
#[ignore = "requires explicit read-only local M path and network"]
async fn live_read_only_projection_cost_witness() {
    let manager_path = std::path::PathBuf::from(std::env::var("NHM_C09_READONLY_M_DB").unwrap());
    let network = std::env::var("NHM_C09_NETWORK").unwrap();
    let directory = std::env::temp_dir().join(format!(
        "nhm-c09-projection-cost-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let ledger_path = directory.join("query.sqlite");
    let inventory = Inventory {
        network_id: network,
        nodes: BTreeSet::from([
            "validator1".into(),
            "validator2".into(),
            "validator3".into(),
            "validator4".into(),
            "observer5".into(),
            "observer6".into(),
        ]),
        scopes: BTreeSet::from(["node".into()]),
    };
    let started = std::time::Instant::now();
    let state = ObservabilityState::new(inventory, vec![b'o'; 32], vec![b'i'; 32], vec![b'a'; 32])
        .unwrap()
        .with_query_ledger(&ledger_path)
        .unwrap()
        .with_manager_evidence(manager_path)
        .unwrap();
    println!("initial_page_ms={}", started.elapsed().as_millis());
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/control/grants")
            .header("authorization", format!("Bearer {}", "o".repeat(32)))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"node_ids":["validator1"],"scope_ids":["node"],
                    "start":"2026-09-29T00:00:00Z","end":"2026-09-29T00:01:00Z"})
                .to_string(),
            ))
            .unwrap()
    };
    let denied = control_router(state.clone()).oneshot(request()).await.unwrap();
    assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!state.data.lock().unwrap().manager_conflicted);
    println!("grant_during_catchup=503");
    // Startup imports one page; the refused grant attempts exactly one more.
    let mut pages = 2;
    while !state.data.lock().unwrap().manager_caught_up && pages < 32 {
        let started = std::time::Instant::now();
        let (watermark, count) = import_manager(&state).unwrap();
        pages += 1;
        println!(
            "page={pages} rows={count} global_m_seq={watermark} elapsed_ms={}",
            started.elapsed().as_millis()
        );
    }
    assert!(state.data.lock().unwrap().manager_caught_up);
    let caught_up_ms = started.elapsed().as_millis();
    let granted = control_router(state.clone()).oneshot(request()).await.unwrap();
    assert_eq!(granted.status(), StatusCode::OK);
    let granted = body(granted).await;
    let run = granted["run_id"].as_str().unwrap();
    let revoked = control_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/control/grants/{run}/revoke"))
                .header("authorization", format!("Bearer {}", "o".repeat(32)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::OK);
    println!("caught_up_ms={caught_up_ms} grant_after_catchup=200 revoked=200");
    let started = std::time::Instant::now();
    let (watermark, count) = import_manager(&state).unwrap();
    println!(
        "steady_rows={count} global_m_seq={watermark} elapsed_ms={}",
        started.elapsed().as_millis()
    );
    drop(state);
    std::fs::remove_dir_all(directory).unwrap();
}

async fn body(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn persisted_cursor_rejects_malformed_identity_and_unwitnessed_anchor() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-cursor-validation-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("query.sqlite");
    let mut ledger = QueryLedger::open(&path).unwrap();
    let mut cursor =
        ManagerCursor { network: "a".repeat(64), device: 1, inode: 1, watermark: 0, anchor: None };
    ledger.commit_manager_cursor(None, &cursor, None).unwrap();
    assert_eq!(ledger.manager_cursor().unwrap(), Some(cursor.clone()));
    let previous = ledger.manager_cursor().unwrap().unwrap();
    cursor.watermark = 4;
    cursor.anchor = Some((4, "b".repeat(64)));
    assert!(ledger
        .commit_manager_cursor(Some(&previous), &cursor, None)
        .unwrap_err()
        .contains("no retained source row"));
    let sql = rusqlite::Connection::open(&path).unwrap();
    sql.execute("UPDATE query_manager_cursor SET network='bad' WHERE singleton=1", []).unwrap();
    assert!(ledger.manager_cursor().unwrap_err().contains("invalid persisted"));
    sql.execute(
        "UPDATE query_manager_cursor SET network=?1,watermark=3 WHERE singleton=1",
        ["a".repeat(64)],
    )
    .unwrap();
    assert!(ledger.manager_cursor().unwrap_err().contains("invalid persisted"));
    sql.execute(
        "UPDATE query_manager_cursor SET network=?1,anchor_seq=4,anchor_hash=?2 WHERE singleton=1",
        rusqlite::params!["a".repeat(64), "b".repeat(64)],
    )
    .unwrap();
    assert!(ledger.manager_cursor().unwrap_err().contains("invalid persisted"));
    sql.execute(
        "UPDATE query_manager_cursor SET anchor_seq=3,anchor_hash='bad' WHERE singleton=1",
        [],
    )
    .unwrap();
    assert!(ledger.manager_cursor().unwrap_err().contains("invalid persisted"));
    drop(sql);
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn diagnostic_only_boundary_is_anchored_and_tampered_cursor_refuses_startup() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-global-boundary-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let manager_path = directory.join("manager.sqlite");
    let ledger_path = directory.join("query.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&manager_path, 4 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    let sql = rusqlite::Connection::open(&manager_path).unwrap();
    sql.execute(
        "INSERT INTO observations(node,scope,process_epoch,source_epoch,source,source_record,content_hash,body)
         VALUES('v1','node','boot:4242:100','diag','diagnostic','diag:1',?1,'{}')",
        ["d".repeat(64)],
    )
    .unwrap();
    drop(sql);
    let page = read_process_projection_page(&manager_path, &network, None, &[]).unwrap();
    assert!(page.records.is_empty());
    assert!(page.caught_up);
    assert_eq!(page.cursor.watermark, 1);
    assert_eq!(page.cursor.anchor, Some((1, "d".repeat(64))));
    assert_eq!(page.boundary_witness, page.cursor.anchor);
    let mut ledger = QueryLedger::open(&ledger_path).unwrap();
    ledger.commit_manager_cursor(None, &page.cursor, page.boundary_witness.as_ref()).unwrap();
    assert_eq!(ledger.manager_cursor().unwrap(), Some(page.cursor.clone()));
    assert!(
        read_process_projection_page(&manager_path, &network, Some(&page.cursor), &[])
            .unwrap()
            .caught_up
    );
    drop(ledger);
    // SQL CHECK permits a paired NULL anchor. The application must still
    // refuse this nonzero watermark before it can issue any query grant.
    let sql = rusqlite::Connection::open(&ledger_path).unwrap();
    sql.execute(
        "UPDATE query_manager_cursor SET anchor_seq=NULL,anchor_hash=NULL WHERE singleton=1",
        [],
    )
    .unwrap();
    drop(sql);
    let inventory = Inventory {
        network_id: network,
        nodes: BTreeSet::from(["v1".into()]),
        scopes: BTreeSet::from(["node".into()]),
    };
    let state = ObservabilityState::new(inventory, vec![b'o'; 32], vec![b'i'; 32], vec![b'a'; 32])
        .unwrap()
        .with_query_ledger(&ledger_path)
        .unwrap();
    assert!(state
        .with_manager_evidence(manager_path.clone())
        .err()
        .unwrap()
        .contains("invalid persisted M projection cursor"));
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn private_projection_health_exposes_lag_and_conflict_without_grant_or_import() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-health-{}-{}",
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
    .with_manager_evidence(manager_path.clone())
    .unwrap();
    let probe = |token: &str| {
        Request::builder()
            .uri("/v1/control/projection-health")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        control_router(state.clone()).oneshot(probe(&"o".repeat(32))).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        query_router(state.clone()).oneshot(probe(&"a".repeat(32))).await.unwrap().status(),
        StatusCode::NOT_FOUND,
        "projection health must not be on the TCP query router"
    );
    let initial = control_router(state.clone()).oneshot(probe(&"a".repeat(32))).await.unwrap();
    assert_eq!(initial.status(), StatusCode::OK);
    let initial = body(initial).await;
    assert_eq!(initial["projection_status"], "caught_up");
    assert_eq!(initial["manager_conflicted"], false);
    assert_eq!(initial["cursor_global_m_seq"], "1");
    assert_eq!(initial["source_global_m_seq"], "1");
    assert_eq!(initial["lag_global_m_seq"], "0");
    manager.insert(row("edge-epoch-2")).unwrap();
    let lagged = control_router(state.clone()).oneshot(probe(&"a".repeat(32))).await.unwrap();
    assert_eq!(lagged.status(), StatusCode::OK);
    let lagged = body(lagged).await;
    assert_eq!(lagged["projection_status"], "lagging");
    assert_eq!(lagged["lag_global_m_seq"], "1");
    assert_eq!(state.manager_projection_reads.load(Ordering::Relaxed), 1);
    let conn = rusqlite::Connection::open(&manager_path).unwrap();
    conn.execute("UPDATE observations SET body='{}' WHERE store_seq=1", []).unwrap();
    assert!(import_manager(&state).unwrap_err().contains("parent changed"));
    let failed = control_router(state.clone()).oneshot(probe(&"a".repeat(32))).await.unwrap();
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    let failed = body(failed).await;
    assert_eq!(failed["projection_status"], "conflict");
    assert_eq!(failed["manager_conflicted"], true);
    drop(state);
    drop(conn);
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
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
fn incremental_projection_pages_4097_history_and_sparse_global_sequence() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-pages-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("manager.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&path, 64 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    drop(manager);
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    let tx = conn.transaction().unwrap();
    for index in 1..=4097 {
        let epoch = format!("epoch-{index}");
        let value = row(&epoch);
        let mut canonical = value.clone();
        canonical.record.received_at_ms = 0;
        let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&canonical).unwrap()));
        let evidence = &value.record;
        tx.execute(
            "INSERT INTO observations(node,scope,process_epoch,source_epoch,source,source_record,content_hash,body)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![evidence.node_id,evidence.scope_id,evidence.process_epoch,
                value.source_epoch,evidence.source_id,evidence.source_record_id,digest,
                serde_json::to_string(&value).unwrap()],
        ).unwrap();
    }
    // A non-process sequence must advance the global high-water only after
    // the final process page has actually caught up.
    tx.execute(
        "INSERT INTO observations(node,scope,process_epoch,source_epoch,source,source_record,content_hash,body)
         VALUES('v1','node','boot:4242:100','diag','diagnostic','diag:1',?1,'{}')",
        ["d".repeat(64)],
    ).unwrap();
    tx.commit().unwrap();
    drop(conn);
    let mut previous = None;
    let mut pages = 0usize;
    let mut imported = 0usize;
    loop {
        let page = read_process_projection_page(&path, &network, previous.as_ref(), &[]).unwrap();
        assert!(page.records.len() <= 256);
        assert!(
            page.cursor.watermark
                > previous
                    .as_ref()
                    .map_or(0, |cursor: &tos_health_services::query_ledger::ManagerCursor| cursor
                        .watermark)
        );
        pages += 1;
        imported += page.records.len();
        if page.caught_up {
            assert_eq!(page.cursor.watermark, 4098);
            assert_eq!(page.cursor.anchor.as_ref().unwrap().0, 4098);
            assert_eq!(page.boundary_witness, page.cursor.anchor);
            break;
        }
        previous = Some(page.cursor);
    }
    assert_eq!(pages, 17);
    assert_eq!(imported, 4097);
    drop(previous);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn partial_projection_restart_replays_cursor_and_refuses_uncaught_grant() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-catchup-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let manager_path = directory.join("manager.sqlite");
    let ledger_path = directory.join("query.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&manager_path, 64 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    for index in 1..=513 {
        manager.insert(row(&format!("epoch-{index}"))).unwrap();
    }
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
    assert!(!state.data.lock().unwrap().manager_caught_up);
    assert_eq!(
        state
            .query_ledger
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .manager_cursor()
            .unwrap()
            .unwrap()
            .watermark,
        256
    );
    drop(state);
    let restored =
        ObservabilityState::new(inventory, vec![b'o'; 32], vec![b'i'; 32], vec![b'a'; 32])
            .unwrap()
            .with_query_ledger(&ledger_path)
            .unwrap()
            .with_manager_evidence(manager_path)
            .unwrap();
    assert_eq!(
        restored
            .query_ledger
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .manager_cursor()
            .unwrap()
            .unwrap()
            .watermark,
        512
    );
    let request = || {
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
            .unwrap()
    };
    // Introduce one more page before grant creation; the route may consume
    // only a single bounded page and must not issue a grant while behind.
    for index in 514..=769 {
        manager.insert(row(&format!("epoch-{index}"))).unwrap();
    }
    let refused = control_router(restored.clone()).oneshot(request()).await.unwrap();
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!restored.data.lock().unwrap().manager_conflicted);
    assert!(!restored.data.lock().unwrap().manager_caught_up);
    assert_eq!(import_manager(&restored).unwrap().0, 769);
    assert!(restored.data.lock().unwrap().manager_caught_up);
    let granted = control_router(restored.clone()).oneshot(request()).await.unwrap();
    assert_eq!(granted.status(), StatusCode::OK);
    drop(restored);
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn durable_parent_before_cursor_replays_exactly_once_after_restart() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-crash-window-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let manager_path = directory.join("manager.sqlite");
    let ledger_path = directory.join("query.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&manager_path, 4 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    let first = manager.insert(row("edge-epoch-1")).unwrap();
    let second = manager.insert(row("edge-epoch-2")).unwrap();
    let (_, records) = read_process_projection(&manager_path, &network).unwrap();
    let mut ledger = QueryLedger::open(&ledger_path).unwrap();
    let mut store = EvidenceStore::new(8 * 1024 * 1024);
    ledger.insert_projection(&mut store, &records[0].0, records[0].1.clone()).unwrap();
    assert!(
        ledger.manager_cursor().unwrap().is_none(),
        "cursor must not advance with first parent"
    );
    drop(ledger);
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
    let data = state.data.lock().unwrap();
    assert_eq!(data.store.watermark(), 2, "replay must deduplicate the committed first parent");
    drop(data);
    let ledger = state.query_ledger.as_ref().unwrap().lock().unwrap();
    assert_eq!(ledger.manager_cursor().unwrap().unwrap().watermark, second.store_seq.0);
    let retained = ledger.retained_origin_rows().unwrap();
    assert_eq!(retained.len(), 2);
    assert!(retained.iter().any(|origin| origin.evidence_id == first.evidence_id));
    drop(ledger);
    drop(state);
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn cursor_refuses_missing_or_rewritten_retained_parent_and_invalid_middle_row() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-source-rollback-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("manager.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&path, 4 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    let first = manager.insert(row("edge-epoch-1")).unwrap();
    let page = read_process_projection_page(&path, &network, None, &[]).unwrap();
    assert_eq!(page.cursor.watermark, first.store_seq.0);
    let retained = vec![first.clone()];
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("UPDATE observations SET body='{}' WHERE store_seq=?1", [first.store_seq.0])
        .unwrap();
    assert!(read_process_projection_page(&path, &network, Some(&page.cursor), &retained)
        .unwrap_err()
        .contains("parent changed"));
    conn.execute(
        "UPDATE observations SET body=?1,node='wrong-node' WHERE store_seq=?2",
        rusqlite::params![serde_json::to_string(&first.evidence).unwrap(), first.store_seq.0],
    )
    .unwrap();
    assert!(
        read_process_projection_page(&path, &network, Some(&page.cursor), &retained)
            .unwrap_err()
            .contains("parent changed"),
        "mutable tuple must not bypass quarantine identity"
    );
    conn.execute("DELETE FROM observations WHERE store_seq=?1", [first.store_seq.0]).unwrap();
    assert!(read_process_projection_page(&path, &network, Some(&page.cursor), &retained)
        .unwrap_err()
        .contains("anchor changed"));
    drop(conn);
    drop(manager);
    let mut manager = EvidenceDb::open(&path, 4 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    let second = manager.insert(row("edge-epoch-2")).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("UPDATE observations SET body='{}' WHERE store_seq=?1", [second.store_seq.0])
        .unwrap();
    assert!(read_process_projection_page(&path, &network, None, &[])
        .unwrap_err()
        .contains("missing field"));
    drop(conn);
    drop(manager);
    let replacement = directory.join("replacement.sqlite");
    let mut other = EvidenceDb::open(&replacement, 4 * 1024 * 1024).unwrap();
    other.bind_network(&network).unwrap();
    let copied = other.insert(row("edge-epoch-1")).unwrap();
    assert_eq!(copied.evidence_id, first.evidence_id);
    assert_eq!(copied.store_seq.0, first.store_seq.0);
    drop(other);
    std::fs::rename(&replacement, &path).unwrap();
    assert!(read_process_projection_page(&path, &network, Some(&page.cursor), &retained)
        .unwrap_err()
        .contains("database identity changed"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn non_anchor_retained_parent_body_change_is_refused_by_sequence_lookup() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-non-anchor-parent-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("manager.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&path, 4 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    let first = manager.insert(row("edge-epoch-1")).unwrap();
    let last = manager.insert(row("edge-epoch-2")).unwrap();
    let page = read_process_projection_page(&path, &network, None, &[]).unwrap();
    assert_eq!(page.cursor.anchor.as_ref().unwrap().0, last.store_seq.0);
    assert_ne!(first.store_seq.0, last.store_seq.0);
    let retained = vec![first.clone(), last];
    let sql = rusqlite::Connection::open(&path).unwrap();
    sql.execute("UPDATE observations SET body='{}' WHERE store_seq=?1", [first.store_seq.0])
        .unwrap();
    assert!(read_process_projection_page(&path, &network, Some(&page.cursor), &retained)
        .unwrap_err()
        .contains("parent changed"));
    drop(sql);
    drop(manager);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn projection_or_cursor_commit_failure_revokes_old_grant_and_replays_on_restart() {
    for mode in ["projection_insert", "cursor_commit"] {
        let directory = std::env::temp_dir().join(format!(
            "nhm-m-query-failure-{mode}-{}-{}",
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
        let inventory = Inventory {
            network_id: network,
            nodes: BTreeSet::from(["v1".into()]),
            scopes: BTreeSet::from(["node".into()]),
        };
        let state = ObservabilityState::new(
            inventory.clone(),
            vec![b'o'; 32],
            vec![b'i'; 32],
            vec![b'a'; 32],
        )
        .unwrap()
        .with_query_ledger(&ledger_path)
        .unwrap()
        .with_manager_evidence(manager_path.clone())
        .unwrap();
        let response = control_router(state.clone())
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
        assert_eq!(response.status(), StatusCode::OK);
        let grant = body(response).await;
        manager.insert(row("edge-epoch-2")).unwrap();
        manager.insert(row("edge-epoch-3")).unwrap();
        let conn = rusqlite::Connection::open(&ledger_path).unwrap();
        match mode {
            "projection_insert" => conn
                .execute_batch(
                    "CREATE TRIGGER c09_inject BEFORE INSERT ON query_evidence
                 WHEN NEW.store_seq=3 BEGIN SELECT RAISE(FAIL,'injected projection commit'); END;",
                )
                .unwrap(),
            "cursor_commit" => conn
                .execute_batch(
                    "CREATE TRIGGER c09_inject BEFORE UPDATE ON query_manager_cursor
                 BEGIN SELECT RAISE(FAIL,'injected cursor commit'); END;",
                )
                .unwrap(),
            _ => unreachable!(),
        }
        assert!(import_manager(&state).unwrap_err().contains("injected"));
        assert!(state.data.lock().unwrap().manager_conflicted);
        if mode == "projection_insert" {
            // The third row failed inside one page transaction. Neither the
            // first new row nor the in-memory candidate may escape it.
            assert_eq!(state.data.lock().unwrap().store.watermark(), 1);
            assert_eq!(
                QueryLedger::open(&ledger_path)
                    .unwrap()
                    .load_evidence(8 * 1024 * 1024)
                    .unwrap()
                    .watermark(),
                1
            );
        }
        assert_eq!(
            state
                .query_ledger
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .manager_cursor()
                .unwrap()
                .unwrap()
                .watermark,
            1
        );
        let refused = query_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/query/capabilities")
                    .header("authorization", format!("Bearer {}", "a".repeat(32)))
                    .header("x-tos-run-token", grant["run_token"].as_str().unwrap())
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({"run_id":grant["run_id"]}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(state);
        conn.execute_batch("DROP TRIGGER c09_inject").unwrap();
        drop(conn);
        let restored =
            ObservabilityState::new(inventory, vec![b'o'; 32], vec![b'i'; 32], vec![b'a'; 32])
                .unwrap()
                .with_query_ledger(&ledger_path)
                .unwrap()
                .with_manager_evidence(manager_path)
                .unwrap();
        assert_eq!(
            restored
                .query_ledger
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .manager_cursor()
                .unwrap()
                .unwrap()
                .watermark,
            3
        );
        assert_eq!(
            restored.data.lock().unwrap().store.watermark(),
            3,
            "committed parents must replay without another query row"
        );
        assert!(
            restored.data.lock().unwrap().grants.is_empty(),
            "revoked grant must not renew across restart"
        );
        drop(restored);
        drop(manager);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[tokio::test]
async fn pre_cursor_ledger_with_active_grant_catches_up_over_4096_history() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-m-query-migrate-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let manager_path = directory.join("manager.sqlite");
    let ledger_path = directory.join("query.sqlite");
    let network = "a".repeat(64);
    let mut manager = EvidenceDb::open(&manager_path, 64 * 1024 * 1024).unwrap();
    manager.bind_network(&network).unwrap();
    manager.insert(row("epoch-1")).unwrap();
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
    let request = || {
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
            .unwrap()
    };
    let issued = control_router(state.clone()).oneshot(request()).await.unwrap();
    assert_eq!(issued.status(), StatusCode::OK);
    let grant = body(issued).await;
    drop(state);
    drop(manager);
    let mut conn = rusqlite::Connection::open(&manager_path).unwrap();
    let tx = conn.transaction().unwrap();
    for index in 2..=4097 {
        let value = row(&format!("epoch-{index}"));
        let mut canonical = value.clone();
        canonical.record.received_at_ms = 0;
        let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&canonical).unwrap()));
        let evidence = &value.record;
        tx.execute(
            "INSERT INTO observations(node,scope,process_epoch,source_epoch,source,source_record,content_hash,body)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![evidence.node_id,evidence.scope_id,evidence.process_epoch,
                value.source_epoch,evidence.source_id,evidence.source_record_id,digest,
                serde_json::to_string(&value).unwrap()],
        ).unwrap();
    }
    tx.commit().unwrap();
    drop(conn);
    let restored =
        ObservabilityState::new(inventory, vec![b'o'; 32], vec![b'i'; 32], vec![b'a'; 32])
            .unwrap()
            .with_query_ledger(&ledger_path)
            .unwrap()
            .with_manager_evidence(manager_path.clone())
            .unwrap();
    assert!(!restored.data.lock().unwrap().manager_caught_up);
    let denied = control_router(restored.clone()).oneshot(request()).await.unwrap();
    assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!restored.data.lock().unwrap().manager_conflicted);
    let cursor_after_two_pages = restored
        .query_ledger
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .manager_cursor()
        .unwrap()
        .unwrap()
        .watermark;
    assert_eq!(cursor_after_two_pages, 513);
    let old = query_router(restored.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/query/node-snapshot")
                .header("authorization", format!("Bearer {}", "a".repeat(32)))
                .header("x-tos-run-token", grant["run_token"].as_str().unwrap())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"run_id":grant["run_id"],"node_id":"v1",
            "as_of":"2026-09-29T00:00:02Z","max_age_seconds":30,"components":["process"]})
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(old.status(), StatusCode::OK, "fixed old W remains usable during catch-up");
    let mut paused_for_grant = false;
    for _ in 0..32 {
        let cursor = restored
            .query_ledger
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .manager_cursor()
            .unwrap()
            .unwrap()
            .watermark;
        if cursor == 4097 {
            break;
        }
        match import_manager(&restored) {
            Ok(_) => {}
            Err(error) if error == "active grant evidence retention" => {
                paused_for_grant = true;
                assert!(!restored.data.lock().unwrap().manager_conflicted);
                break;
            }
            Err(error) => panic!("unexpected migration failure: {error}"),
        }
    }
    assert!(paused_for_grant, "the fixed W must reach an actual eviction boundary");
    let paused_cursor = restored
        .query_ledger
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .manager_cursor()
        .unwrap()
        .unwrap()
        .watermark;
    let old_at_capacity = query_router(restored.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/query/capabilities")
                .header("authorization", format!("Bearer {}", "a".repeat(32)))
                .header("x-tos-run-token", grant["run_token"].as_str().unwrap())
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"run_id":grant["run_id"]}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(old_at_capacity.status(), StatusCode::OK);
    assert_eq!(
        control_router(restored.clone()).oneshot(request()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        restored
            .query_ledger
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .manager_cursor()
            .unwrap()
            .unwrap()
            .watermark,
        paused_cursor,
        "bounded refusal cannot advance the M cursor"
    );
    {
        let revoked = control_router(restored.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/control/grants/{}/revoke", grant["run_id"].as_str().unwrap()))
                    .header("authorization", format!("Bearer {}", "o".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::OK);
        for _ in 0..32 {
            let cursor = restored
                .query_ledger
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .manager_cursor()
                .unwrap()
                .unwrap()
                .watermark;
            if cursor == 4097 {
                break;
            }
            import_manager(&restored).unwrap();
        }
    }
    assert_eq!(
        restored
            .query_ledger
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .manager_cursor()
            .unwrap()
            .unwrap()
            .watermark,
        4097
    );
    assert!(restored.data.lock().unwrap().manager_caught_up);
    assert!(!restored.data.lock().unwrap().manager_conflicted);
    // The global cursor is not a count of process rows. Once 4097 historical
    // parents are consumed, a single new M record must import without a
    // from-the-beginning scan and a new grant must freeze its exact snapshot W.
    let value = row("epoch-4098");
    let mut canonical = value.clone();
    canonical.record.received_at_ms = 0;
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&canonical).unwrap()));
    let evidence = &value.record;
    let conn = rusqlite::Connection::open(&manager_path).unwrap();
    conn.execute(
        "INSERT INTO observations(node,scope,process_epoch,source_epoch,source,source_record,content_hash,body)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        rusqlite::params![evidence.node_id,evidence.scope_id,evidence.process_epoch,
            value.source_epoch,evidence.source_id,evidence.source_record_id,digest,
            serde_json::to_string(&value).unwrap()],
    )
    .unwrap();
    drop(conn);
    assert_eq!(import_manager(&restored).unwrap(), (4098, 1));
    assert!(restored.data.lock().unwrap().manager_caught_up);
    let fresh = control_router(restored.clone()).oneshot(request()).await.unwrap();
    assert_eq!(fresh.status(), StatusCode::OK);
    let granted = body(fresh).await;
    let run = granted["run_id"].as_str().unwrap();
    assert_eq!(restored.data.lock().unwrap().grants[run].manager_watermark, Some(4098));
    drop(restored);
    std::fs::remove_dir_all(directory).unwrap();
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
    // A fresh grant is needed because the storm correctly exhausted the
    // first one. Exercise cache miss, bounded unknown ancestry, and a
    // forbidden refresh argument while M remains unchanged.
    let second_grant = control_router(state.clone())
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
    assert_eq!(second_grant.status(), StatusCode::OK);
    let second = body(second_grant).await;
    let second_run = second["run_id"].as_str().unwrap();
    let second_token = second["run_token"].as_str().unwrap();
    let after_second_grant = state.manager_projection_reads.load(Ordering::Relaxed);
    assert_eq!(after_second_grant, before + 1);
    let controls = [
        (
            "/v1/query/node-snapshot",
            serde_json::json!({"run_id":second_run,"node_id":"v1",
                "as_of":"2026-09-29T00:00:02Z","max_age_seconds":30,
                "components":["chain"]}),
            StatusCode::SERVICE_UNAVAILABLE,
            "CACHE_MISS",
        ),
        (
            "/v1/query/block-evidence",
            serde_json::json!({"run_id":second_run,"node_ids":["v1"],
                "reference_id":"blk_0123456789abcdef","ancestor_depth":4,"max_events":10}),
            StatusCode::NOT_FOUND,
            "UNKNOWN_REFERENCE",
        ),
        (
            "/v1/query/capabilities",
            serde_json::json!({"run_id":second_run,"force_refresh":true}),
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
        ),
    ];
    for (uri, input, status, code) in controls {
        let response = query_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("authorization", format!("Bearer {}", "a".repeat(32)))
                    .header("x-tos-run-token", second_token)
                    .header("content-type", "application/json")
                    .body(Body::from(input.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{uri}");
        assert_eq!(body(response).await["error"]["code"], code, "{uri}");
        assert_eq!(state.manager_projection_reads.load(Ordering::Relaxed), after_second_grant);
    }
    import_manager(&state).unwrap();
    assert_eq!(state.manager_projection_reads.load(Ordering::Relaxed), after_second_grant + 1);
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
