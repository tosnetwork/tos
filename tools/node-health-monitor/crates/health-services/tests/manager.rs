use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    process::{Child, Command},
    time::Duration,
};
use tos_health_core::rules::FactFrame;
use tos_health_services::manager::{deliver_once, Manager, ManagerConfig, ReceiverConfig};
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
                "node":"v1","scope":"node","sources":[{"id":"probe","ttl_ms":"45000","facts":["reachable"]}],
                "rules":[{"id":"target_unreachable","source":"probe","threshold":"0","pending_ms":"0","recovery_ms":"60000","minimum_bad_samples":1,"severity":"critical"}]
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
    serde_json::from_value(json!({"schema_version":1,"network_id":"a".repeat(64),"node_id":"v1","scope_id":"node","source_id":"probe","process_epoch":"p1","source_epoch":"s1","generation":"1","source_age_ms":"0","request_duration_ms":"0","observed_at":"2026-09-29T00:00:00Z","clock_valid":true,"complete":true,"facts":[{"id":"reachable","value":value.to_string()}]})).unwrap()
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
async fn conflict_quarantines_live_rule_and_receipt_controls_outbox() {
    let fixture = Fixture::new();
    let manager = Manager::start(&fixture.config()).unwrap();
    let mut old = frame(0);
    old.process_epoch = "old-process".into();
    manager.ingest(old).await.unwrap();
    manager.ingest(frame(0)).await.unwrap();
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
    assert!(deliver_once(&manager, &client, &receiver, "test").await.is_err());
    assert_eq!(manager.pending().await.unwrap().len(), 1);
    receiver.url = format!("http://{addr}/ok");
    assert_eq!(deliver_once(&manager, &client, &receiver, "test").await.unwrap(), 1);
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
