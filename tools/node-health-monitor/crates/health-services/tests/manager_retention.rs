//! Retention and operator facts as the manager publishes them.
use serde_json::{json, Value};
use std::{path::PathBuf, time::Duration};
use tos_health_core::rules::FactFrame;
use tos_health_services::manager::{Manager, ManagerConfig};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "health-manager-retention-{}",
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
    fn config(&self, extra: Value) -> ManagerConfig {
        let mut value = json!({
            "inventory":{"schema_version":1,"revision":"runtime-test","network_id":"a".repeat(64),"targets":[{
                "node":"v1","scope":"node","sources":[{"id":"edge_probe","ttl_ms":"45000","facts":["reachable"]}],
                "rules":[{"id":"target_unreachable","source":"edge_probe","threshold":"0","pending_ms":"0","recovery_ms":"60000","minimum_bad_samples":1,"severity":"critical"}]
            }]},
            "control_db":self.0.join("control.db"),"evidence_db":self.0.join("evidence.db"),"control_quota_bytes":"1048576","evidence_quota_bytes":"1048576","listen":"127.0.0.1:0",
            "ingest_token_file":self.0.join("ingest"),"read_token_file":self.0.join("read"),"receiver":null
        });
        for (key, item) in extra.as_object().unwrap() {
            value[key] = item.clone();
        }
        serde_json::from_value(value).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn frame() -> FactFrame {
    serde_json::from_value(json!({"schema_version":1,"network_id":"a".repeat(64),"node_id":"v1","scope_id":"node","source_id":"edge_probe","process_epoch":"p1","source_epoch":"s1","generation":"1","source_age_ms":"0","request_duration_ms":"0","observed_at":"2026-09-29T00:00:00Z","clock_valid":true,"complete":true,"facts":[{"id":"reachable","value":"1"}]})).unwrap()
}

#[test]
fn retention_keys_are_optional_and_bounded() {
    let fixture = Fixture::new();
    let unbounded = fixture.config(json!({}));
    assert!(unbounded.evidence_retention_ms.is_none());
    assert!(!unbounded.retention_policy().configured());
    for (key, value) in [
        ("evidence_retention_ms", "3599999"),
        ("evidence_retention_ms", "7776000001"),
        ("witness_retention_ms", "0"),
        ("witness_retention_ms", "7776000001"),
    ] {
        let config = fixture.config(json!({key: value}));
        let error = Manager::start(&config).err().expect("out-of-range retention accepted");
        assert!(error.starts_with(key), "{key}={value}: {error}");
    }
    let bounded = fixture
        .config(json!({"evidence_retention_ms":"3600000","witness_retention_ms":"7776000000"}));
    assert_eq!(bounded.retention_policy().evidence_retention_ms, Some(3_600_000));
    assert_eq!(bounded.retention_policy().witness_retention_ms, Some(7_776_000_000));
}

#[tokio::test]
async fn state_and_metrics_carry_retention_inventory_quarantine_and_delivery_facts() {
    let fixture = Fixture::new();
    let manager =
        Manager::start(&fixture.config(json!({"evidence_retention_ms":"86400000"}))).unwrap();
    manager.ingest(frame()).await.unwrap();
    let mut state = None;
    for _ in 0..200 {
        if let Ok(value) = manager.snapshot() {
            if value["retention"]["passes"] == "1" {
                state = Some(value);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let state = state.expect("first retention pass not published");
    assert_eq!(state["schema_version"], 1);
    assert_eq!(state["incidents"][0]["key"]["rule"], "target_unreachable");
    let retention = &state["retention"];
    assert_eq!(retention["configured"], true);
    assert_eq!(retention["evidence_retention_ms"], "86400000");
    assert_eq!(retention["witness_retention_ms"], Value::Null);
    assert_eq!(retention["period_ms"], "300000");
    assert_eq!(retention["floor_ms"], "7200000");
    assert_eq!(retention["observations_deleted_total"], "0");
    assert_eq!(retention["last_pass_complete"], true);
    assert_eq!(retention["last_pass_error"], Value::Null);
    assert!(retention["last_pass_age_ms"].as_str().unwrap().parse::<u64>().unwrap() < 60_000);
    assert_eq!(state["inventory"]["revision"], "runtime-test");
    assert_eq!(state["inventory"]["targets"][0]["node"], "v1");
    assert_eq!(state["inventory"]["targets"][0]["rules"], json!(["target_unreachable"]));
    assert_eq!(state["quarantined_sources"], json!([]));
    assert_eq!(state["notification"]["receiver_configured"], false);
    assert_eq!(state["notification"]["last_delivery_at_ms"], Value::Null);
    let metrics = manager.metrics().unwrap();
    assert!(metrics.ends_with("# EOF\n"));
    assert_eq!(metrics.matches("# EOF").count(), 1);
    assert!(metrics.contains("tos_health_evidence_retention_configured 1\n"));
    assert!(metrics.contains("tos_health_evidence_retention_passes_total 1\n"));
    assert!(metrics.contains("tos_health_evaluation_sequence{"));
    // A conflicting epoch is published as a quarantined source.
    let mut conflict = frame();
    conflict.facts[0].value = tos_health_core::wire::U64(0);
    assert_eq!(manager.ingest(conflict).await.unwrap_err(), "SOURCE_CONFLICT");
    let state = manager.snapshot().unwrap();
    assert_eq!(state["quarantined_sources"][0]["source"], "edge_probe");
    assert_eq!(state["quarantined_sources"][0]["epochs"][0]["process_epoch"], "p1");
}

#[tokio::test]
async fn unconfigured_retention_is_reported_as_such() {
    let fixture = Fixture::new();
    let manager = Manager::start(&fixture.config(json!({}))).unwrap();
    let mut state = None;
    for _ in 0..100 {
        if let Ok(value) = manager.snapshot() {
            state = Some(value);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let state = state.unwrap();
    assert_eq!(state["retention"]["configured"], false);
    assert_eq!(state["retention"]["passes"], "0");
    assert_eq!(state["retention"]["last_pass_at_ms"], Value::Null);
    assert!(manager.metrics().unwrap().contains("tos_health_evidence_retention_configured 0\n"));
}
