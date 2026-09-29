use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    process::{Child, Command},
    time::Duration,
};
use tos_health_core::rules::FactFrame;
use tos_health_services::manager::{deliver_once_at, Manager, ManagerConfig, ReceiverConfig};
use tower::ServiceExt;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "health-manager-{}",
            tos_health_services::hex(&tos_health_services::random_token().unwrap())
        ));
        std::fs::create_dir(&dir).unwrap();
        for (name, value) in [("ingest", "a".repeat(32)), ("read", "b".repeat(32))] {
            std::fs::write(dir.join(name), value).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
        }
        Self(dir)
    }
    fn config(&self) -> ManagerConfig {
        serde_json::from_value(json!({
            "inventory":{"schema_version":1,"revision":"runtime-test","network_id":"a".repeat(64),"targets":[{
                "node":"v1","scope":"node","sources":[{"id":"edge_probe","ttl_ms":"45000","facts":["reachable"]}],
                "rules":[{"id":"target_unreachable","source":"edge_probe","threshold":"0","pending_ms":"0","recovery_ms":"60000","minimum_bad_samples":1,"severity":"critical"}]
            }]},
            "control_db":self.0.join("control.db"),"evidence_db":self.0.join("evidence.db"),"control_quota_bytes":"1048576","evidence_quota_bytes":"1048576","listen":"127.0.0.1:0",
            "ingest_token_file":self.0.join("ingest"),"read_token_file":self.0.join("read"),"receiver":null
        })).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn frame(value: u64) -> FactFrame {
    serde_json::from_value(json!({"schema_version":1,"network_id":"a".repeat(64),"node_id":"v1","scope_id":"node","source_id":"edge_probe","process_epoch":"p1","source_epoch":"s1","generation":"1","source_age_ms":"0","request_duration_ms":"0","observed_at":"2026-09-29T00:00:00Z","clock_valid":true,"complete":true,"facts":[{"id":"reachable","value":value.to_string()}]})).unwrap()
}
async fn state(manager: &Manager, wanted: &str) -> Value {
    for _ in 0..140 {
        if let Ok(s) = manager.snapshot() {
            if s["incidents"][0]["state"]["state"] == wanted {
                return s;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("state {wanted} not observed: {:?}", manager.snapshot());
}
#[tokio::test]
async fn full_evidence_writer_queue_refuses_without_receipt_or_green() {
    let fixture = Fixture::new();
    let manager = Manager::start(&fixture.config()).unwrap();
    let lock = rusqlite::Connection::open(fixture.0.join("evidence.db")).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..96 {
        let manager = manager.clone();
        tasks.spawn(async move { manager.ingest(frame(0)).await });
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    let before = manager.snapshot().unwrap_or(json!({"status":"unknown"}));
    assert_ne!(before["incidents"][0]["state"]["state"], "closed_recovered");
    lock.execute_batch("ROLLBACK").unwrap();
    let mut refused = 0;
    while let Some(result) = tasks.join_next().await {
        if matches!(result.unwrap(), Err(ref error) if error == "evidence queue unavailable") {
            refused += 1;
        }
    }
    assert!(refused > 0, "bounded writer queue was not saturated");
    assert!(manager
        .pending()
        .await
        .unwrap()
        .iter()
        .all(|(_, _, body)| !body.contains("closed_recovered")));
}
#[tokio::test]
async fn conflict_quarantines_live_rule_and_receipt_controls_outbox() {
    let fixture = Fixture::new();
    let manager = Manager::start(&fixture.config()).unwrap();
    let mut old = frame(0);
    old.process_epoch = "old-process".into();
    manager.ingest(old).await.unwrap();
    let committed_id = manager.ingest(frame(0)).await.unwrap();
    let control = rusqlite::Connection::open(fixture.0.join("control.db")).unwrap();
    let reference: (String, i64) = control.query_row(
        "SELECT evidence_id,store_seq FROM source_state WHERE node='v1' AND scope='node' AND source='edge_probe'",
        [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!(reference.0, committed_id);
    assert_eq!(reference.1, 2);
    state(&manager, "open").await;
    assert_eq!(manager.pending().await.unwrap().len(), 1);
    let app=Router::new().route("/wrong",post(||async { Json(json!({"accepted":true,"idempotency_key":"wrong","payload_hash":"wrong"})) }))
        .route("/ok",post(|Json(v):Json<Value>| async move {
            assert_eq!(v["network_id"], "a".repeat(64));
            assert_eq!(v["incident"]["rule_key"]["node"], "v1");
            assert_eq!(v["idempotency_key"].as_str().unwrap().len(), 64);
            Json(json!({"accepted":true,"idempotency_key":v["idempotency_key"],"payload_hash":v["payload_hash"]})) }));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let mut receiver = ReceiverConfig {
        url: format!("http://{addr}/wrong"),
        ca_file: PathBuf::new(),
        identity_file: PathBuf::new(),
        token_file: PathBuf::new(),
        alias: "test".into(),
    };
    let client =
        reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(1)).build().unwrap();
    assert!(deliver_once_at(&manager, &client, &receiver, "test", 1).await.is_err());
    assert_eq!(manager.pending().await.unwrap().len(), 1);
    let retry: (String, String, i64, i64) = control
        .query_row("SELECT receiver_alias,payload_hash,attempts,next_due_ms FROM outbox", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap();
    assert_eq!(retry.0, "test");
    assert_eq!(retry.1.len(), 64);
    assert_eq!((retry.2, retry.3), (1, 15_001));
    assert_eq!(
        manager
            .begin_attempt(manager.pending().await.unwrap()[0].0, "other", 15_001)
            .await
            .unwrap_err(),
        "receiver alias mismatch or attempt not due"
    );
    receiver.url = format!("http://{addr}/ok");
    assert_eq!(manager.due(14_999).await.unwrap().len(), 0);
    assert_eq!(deliver_once_at(&manager, &client, &receiver, "test", 15_001).await.unwrap(), 1);
    assert!(manager.pending().await.unwrap().is_empty());
    assert_eq!(manager.ingest(frame(1)).await.unwrap_err(), "SOURCE_CONFLICT");
    let mut old_conflict = frame(1);
    old_conflict.process_epoch = "old-process".into();
    assert_eq!(manager.ingest(old_conflict).await.unwrap_err(), "SOURCE_CONFLICT");
    let s = state(&manager, "suspended_unknown").await;
    assert_eq!(s["incidents"][0]["state"]["severity"], "critical");
    assert_eq!(s["incidents"][0]["input"], "unknown");
    assert!(manager
        .metrics()
        .unwrap()
        .contains("rule=\"target_unreachable\",severity=\"critical\"} 1"));
    server.abort();
}

#[tokio::test]
async fn source_reference_write_failure_cannot_publish_green() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let manager = Manager::start(&config).unwrap();
    let control = rusqlite::Connection::open(&config.control_db).unwrap();
    control.execute_batch("CREATE TRIGGER fail_source BEFORE INSERT ON source_state BEGIN SELECT RAISE(ABORT,'source disk failure'); END;").unwrap();
    assert!(manager.ingest(frame(1)).await.is_err());
    assert!(manager.snapshot().is_err());
    let evidence =
        tos_health_services::durable::EvidenceDb::open(&config.evidence_db, 1_048_576).unwrap();
    assert_eq!(evidence.watermark().unwrap(), 1); // immutable evidence committed first
    let references: i64 =
        control.query_row("SELECT count(*) FROM source_state", [], |r| r.get(0)).unwrap();
    assert_eq!(references, 0);
    for _ in 0..120 {
        if let Ok(state) = manager.snapshot() {
            assert_eq!(state["incidents"][0]["input"], "unknown");
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("rule evaluation did not publish a fail-closed unknown round");
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn remote_state(client: &reqwest::Client, url: &str, wanted: &str) -> Value {
    for _ in 0..140 {
        if let Ok(r) =
            client.get(format!("{url}/v1/manager/state")).bearer_auth("b".repeat(32)).send().await
        {
            if let Ok(s) = r.json::<Value>().await {
                if s["incidents"][0]["state"]["state"] == wanted {
                    return s;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("process state {wanted} not observed");
}
#[tokio::test]
async fn killed_process_reopens_active_incident_as_unknown() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    config.listen = port.local_addr().unwrap().to_string();
    drop(port);
    let path = fixture.0.join("config.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let start =
        || Process(Command::new(env!("CARGO_BIN_EXE_health-state")).arg(&path).spawn().unwrap());
    let process = start();
    let url = format!("http://{}", config.listen);
    let client =
        reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(1)).build().unwrap();
    remote_state(&client, &url, "clear").await;
    assert_eq!(
        client
            .post(format!("{url}/v1/manager/facts"))
            .bearer_auth("b".repeat(32))
            .json(&frame(0))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert!(client
        .post(format!("{url}/v1/manager/facts"))
        .bearer_auth("a".repeat(32))
        .json(&frame(0))
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let before = remote_state(&client, &url, "open").await;
    drop(process);
    let _restarted = start();
    let after = remote_state(&client, &url, "suspended_unknown").await;
    assert_ne!(before["monitor_epoch"], after["monitor_epoch"]);
    assert_eq!(
        before["incidents"][0]["state"]["episode"],
        after["incidents"][0]["state"]["episode"]
    );
    assert_eq!(after["incidents"][0]["state"]["severity"], "critical");
    let conn = rusqlite::Connection::open(&config.control_db).unwrap();
    let pending: i64 =
        conn.query_row("SELECT count(*) FROM outbox WHERE delivered=0", [], |r| r.get(0)).unwrap();
    assert!(pending >= 1);
}
#[test]
fn database_aliases_cannot_defeat_isolation() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    std::fs::write(&config.control_db, []).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&config.control_db, &config.evidence_db).unwrap();
    #[cfg(not(unix))]
    {
        config.evidence_db = config.control_db.clone();
    }
    assert!(
        matches!(Manager::start(&config),Err(e) if e=="control and evidence must be separate databases")
    );
    std::fs::remove_file(&config.evidence_db).unwrap();
    std::fs::hard_link(&config.control_db, &config.evidence_db).unwrap();
    assert!(
        matches!(Manager::start(&config),Err(e) if e=="control and evidence must be separate databases")
    );
    config.evidence_db = fixture.0.join("different.db");
    let manager = Manager::start(&config).unwrap();
    drop(manager);
    config.inventory.network_id = "b".repeat(64);
    config.inventory.revision = "another-network".into();
    assert!(matches!(Manager::start(&config), Err(e) if e == "database network mismatch"));
}
#[test]
fn pending_c04_c05_rule_inputs_cannot_be_enabled_on_manager() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.inventory.targets[0].sources.push(tos_health_core::rules::SourceSpec {
        id: "future_native".into(),
        ttl_ms: tos_health_core::wire::U64(30_000),
        facts: vec![tos_health_core::rules::FactId::QueueOldestMs],
    });
    config.inventory.targets[0].rules.push(tos_health_core::rules::RuleSpec {
        id: "queue_stall".into(),
        source: "future_native".into(),
        threshold: tos_health_core::wire::U64(10),
        pending_ms: tos_health_core::wire::U64(0),
        recovery_ms: tos_health_core::wire::U64(60_000),
        minimum_bad_samples: 1,
        severity: "critical".into(),
    });
    assert_eq!(Manager::start(&config).err().unwrap(), "rule adapter unavailable: queue_stall");
}

#[test]
fn queued_observation_cannot_be_rejuvenated() {
    use tos_health_core::wire::U64;
    use tos_health_services::manager::with_queue_age;
    let mut original = frame(1);
    original.request_duration_ms = U64(7);
    let digest = original.digest().unwrap();
    let aged = with_queue_age(original, Duration::from_millis(13)).unwrap();
    assert_eq!(aged.request_duration_ms.0, 20);
    assert_eq!(aged.digest().unwrap(), digest);
    let mut overflow = frame(1);
    overflow.request_duration_ms = U64(u64::MAX);
    assert!(with_queue_age(overflow, Duration::from_millis(1)).is_err());
}

fn synthetic_bound_snapshot() -> Value {
    let native: Value =
        serde_json::from_str(include_str!("../../health-core/tests/fixtures/native-core.json"))
            .unwrap();
    let mut process: Value =
        serde_json::from_str(include_str!("../../health-core/tests/fixtures/process-source.json"))
            .unwrap();
    let process_epoch = "00000000-0000-4000-8000-000000000001:4242:123";
    process["process_epoch"] = process_epoch.into();
    json!({"schema_version":1,"status":"partial","sources":[native,process],"anchors":[],
        "native_process_binding":{"kind":"native_process_binding","process_epoch":process_epoch,
        "native_epoch":"fa86123d3210887c36045ec1ec657bfc","pid":4242,"start_ticks":"123",
        "exe_identity_sha256":"d".repeat(64),"listener_inode":"456",
        "listener_addr":"127.0.0.1:9000","checked_at":"2026-09-29T00:00:00Z"}})
}

#[tokio::test]
async fn typed_snapshot_archive_commits_exact_refs_without_creating_healthy_facts() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    let fixture = Fixture::new();
    let config = fixture.config();
    let manager = Manager::start(&config).unwrap();
    let snapshot = synthetic_bound_snapshot();
    let app = tos_health_services::manager::router(manager.clone());
    let request = |body: &Value| {
        Request::builder()
            .method("POST")
            .uri("/v1/manager/snapshot-evidence")
            .header("authorization", format!("Bearer {}", "a".repeat(32)))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    };
    let first = app.clone().oneshot(request(&snapshot)).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(first.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["evidence"].as_array().unwrap().len(), 2);
    assert_eq!(body["evidence"][0]["store_seq"], "1");
    assert_eq!(body["evidence"][1]["store_seq"], "2");
    let again = app.clone().oneshot(request(&snapshot)).await.unwrap();
    let repeated: Value =
        serde_json::from_slice(&to_bytes(again.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(repeated["evidence"], body["evidence"]);
    let mut unavailable = snapshot.clone();
    unavailable["sources"][0]["availability"] = "unknown".into();
    unavailable["sources"][0]["observed_at"] = Value::Null;
    assert_eq!(
        app.oneshot(request(&unavailable)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let db =
        tos_health_services::durable::EvidenceDb::open(&config.evidence_db, 1_048_576).unwrap();
    assert_eq!(db.watermark().unwrap(), 2);
    assert_eq!(db.page("v1", "node", 2, 0, 10).unwrap().len(), 2);
    assert!(
        manager.snapshot().is_err()
            || manager.snapshot().unwrap()["incidents"][0]["input"] == "unknown"
    );

    let mut padded = serde_json::to_vec(&snapshot).unwrap();
    padded.extend(std::iter::repeat_n(b' ', 20_000));
    let accepted = Request::builder()
        .method("POST")
        .uri("/v1/manager/snapshot-evidence")
        .header("authorization", format!("Bearer {}", "a".repeat(32)))
        .body(Body::from(padded.clone()))
        .unwrap();
    assert_eq!(
        tos_health_services::manager::router(manager.clone())
            .oneshot(accepted)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    padded.resize(262_145, b' ');
    let oversized = Request::builder()
        .method("POST")
        .uri("/v1/manager/snapshot-evidence")
        .header("authorization", format!("Bearer {}", "a".repeat(32)))
        .body(Body::from(padded))
        .unwrap();
    assert_eq!(
        tos_health_services::manager::router(manager.clone())
            .oneshot(oversized)
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut large_fact = serde_json::to_vec(&frame(0)).unwrap();
    large_fact.extend(std::iter::repeat_n(b' ', 16_385));
    let fact_request = Request::builder()
        .method("POST")
        .uri("/v1/manager/facts")
        .header("authorization", format!("Bearer {}", "a".repeat(32)))
        .header("content-type", "application/json")
        .body(Body::from(large_fact))
        .unwrap();
    assert_eq!(
        tos_health_services::manager::router(manager).oneshot(fact_request).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn partial_archive_failure_has_no_receipt_and_replay_preserves_committed_record() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    let fixture = Fixture::new();
    let config = fixture.config();
    let manager = Manager::start(&config).unwrap();
    let mut snapshot = synthetic_bound_snapshot();
    let records = tos_health_services::collector::decode_records(
        &serde_json::to_vec(&snapshot).unwrap(),
        "v1",
        Some(&"a".repeat(64)),
    )
    .unwrap();
    let seed = records.into_iter().find(|r| r.source_id == "process").unwrap();
    let mut db =
        tos_health_services::durable::EvidenceDb::open(&config.evidence_db, 1_048_576).unwrap();
    db.insert(tos_health_services::durable::DurableEvidence {
        source_epoch: "edge-fixture-1".into(),
        record: seed,
    })
    .unwrap();
    drop(db);
    snapshot["sources"][1]["coverage"]["missing_fields"][0] = "changed_fixture_coverage".into();
    let app = tos_health_services::manager::router(manager);
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/manager/snapshot-evidence")
            .header("authorization", format!("Bearer {}", "a".repeat(32)))
            .body(Body::from(serde_json::to_vec(&snapshot).unwrap()))
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let connection = rusqlite::Connection::open(&config.evidence_db).unwrap();
    let (seq, received): (i64, i64) = connection.query_row(
        "SELECT store_seq, json_extract(body,'$.record.received_at_ms') FROM observations WHERE source='native_core'",
        [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(seq, 2);
    assert_eq!(app.oneshot(request()).await.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
    let (again_seq, again_received): (i64, i64) = connection.query_row(
        "SELECT store_seq, json_extract(body,'$.record.received_at_ms') FROM observations WHERE source='native_core'",
        [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!((again_seq, again_received), (seq, received));
    let count: i64 =
        connection.query_row("SELECT count(*) FROM observations", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 2);
}
