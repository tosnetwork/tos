use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::path::PathBuf;
use tos_health_core::witness::Plan;
use tos_health_services::{
    manager::{Manager, ManagerConfig},
    witness::{router as witness_router, WitnessCache},
};
use tower::ServiceExt;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "witness-archive-{}",
            tos_health_services::hex(&tos_health_services::random_token().unwrap())
        ));
        std::fs::create_dir(&path).unwrap();
        for (name, value) in [("ingest", "a".repeat(32)), ("read", "b".repeat(32))] {
            std::fs::write(path.join(name), value).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
        }
        Self(path)
    }
    fn plan(&self) -> Plan {
        let value = json!({"schema_version":1,"profile":"c05_development_cache_only",
            "revision":"a".repeat(64),"observer_id":"observer_1","observer_epoch":"observer-1",
            "network_id":"a".repeat(64),"genesis":"c".repeat(64),"clock_skew_allowance_ms":5000,
            "endpoints":[{"endpoint_id":"cache_1","fixed_url":"https://cache.example.test/witness",
                "failure_domain":"zone_a","kind":"approved_cache_only_https"}],
            "targets":[{"target_id":"validator_1","node_id":"v1","role":"normal",
                "valid_from":"2026-09-29T00:00:00Z","valid_until":"2026-09-30T00:00:00Z",
                "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
                "endpoint_ids":["cache_1"]}]});
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(self.0.join("plan.json"), &bytes).unwrap();
        Plan::decode(&bytes).unwrap()
    }
    fn config(&self) -> ManagerConfig {
        serde_json::from_value(json!({
            "inventory":{"schema_version":1,"revision":"runtime-test","network_id":"a".repeat(64),
                "targets":[{"node":"v1","scope":"node",
                    "sources":[{"id":"edge_probe","ttl_ms":"45000","facts":["reachable"]}],
                    "rules":[{"id":"target_unreachable","source":"edge_probe","threshold":"0",
                        "pending_ms":"0","recovery_ms":"60000","minimum_bad_samples":1,"severity":"critical"}]},
                    {"node":"v1","scope":"masterchain",
                    "sources":[{"id":"edge_probe","ttl_ms":"45000","facts":["reachable"]}],
                    "rules":[{"id":"target_unreachable","source":"edge_probe","threshold":"0",
                        "pending_ms":"0","recovery_ms":"60000","minimum_bad_samples":1,"severity":"critical"}]}]},
            "control_db":self.0.join("control.db"),"evidence_db":self.0.join("evidence.db"),
            "control_quota_bytes":"1048576","evidence_quota_bytes":"1048576","listen":"127.0.0.1:0",
            "ingest_token_file":self.0.join("ingest"),"read_token_file":self.0.join("read"),
            "receiver":null,"witness_plan_file":self.0.join("plan.json")
        })).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn source(root: char) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"schema_version":1,"endpoint_id":"cache_1","source_epoch":"source-1",
        "generation":"1","network_id":"a".repeat(64),"genesis":"c".repeat(64),
        "observed_at":null,"source_age_ms":null,"clock_quality":"unknown","coverage":"partial",
        "rows":[{"target_id":"validator_1","observed_at":null,"source_age_ms":"46000",
            "anchor":{"kind":"block","network_id":"a".repeat(64),"genesis":"c".repeat(64),
                "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
                "seqno":9,"root_hash":root.to_string().repeat(64),"file_hash":"e".repeat(64),
                "point":"reported_finalized"},"network_observation":"observed",
            "reported_certificate_membership":"not_checked","reported_proof":"reported_valid",
            "private_vote_visibility":"unavailable","coverage":"partial",
            "missing_fields":["private_vote"]}]}),
    )
    .unwrap()
}
fn changed_source(root: char, generation: &str, epoch: &str) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(&source(root)).unwrap();
    value["generation"] = json!(generation);
    value["source_epoch"] = json!(epoch);
    serde_json::to_vec(&value).unwrap()
}
async fn cached(plan: Plan, raw: &[u8]) -> Vec<u8> {
    let cache = WitnessCache::new(plan, b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    cache.admit("cache_1", raw, 100).unwrap();
    let request = Request::builder()
        .uri("/v1/witness/cache/cache_1")
        .header("authorization", "Bearer abcdefghijklmnopqrstuvwxyz0123456789")
        .body(Body::empty())
        .unwrap();
    let response = witness_router(cache).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await.unwrap().to_bytes().to_vec()
}
async fn post(manager: Manager, bytes: Vec<u8>) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/manager/witness-evidence/cache_1")
        .header("authorization", format!("Bearer {}", "a".repeat(32)))
        .header("content-type", "application/json")
        .body(Body::from(bytes))
        .unwrap();
    let response = tos_health_services::manager::router(manager).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value =
        if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
    (status, value)
}

#[tokio::test]
async fn actual_observer_cache_to_manager_retained_archive_dedups_without_rule_fact() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let manager = Manager::start(&fixture.config()).unwrap();
    let body = cached(plan.clone(), &source('d')).await;
    let (status, first) = post(manager.clone(), body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["accepted"], true);
    assert_eq!(first["namespace"], "witness_archive_v1");
    assert!(first["archive_seq"].as_str().unwrap().parse::<u64>().unwrap() > 0);
    assert!(first.get("store_seq").is_none());
    assert!(first["evidence_id"].as_str().is_some_and(tos_health_core::wire::hash));
    let (status, repeated) = post(manager.clone(), body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(repeated, first);
    let stored: i64 = rusqlite::Connection::open(fixture.0.join("evidence.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM witness_observations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored, 1);
    let ordinary_rows: i64 = rusqlite::Connection::open(fixture.0.join("evidence.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM observations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(ordinary_rows, 0, "witness archive must not mint a rule fact");
    let conflicting = cached(plan, &source('f')).await;
    assert_eq!(post(manager.clone(), conflicting).await.0, StatusCode::CONFLICT);
    let quarantined: i64 = rusqlite::Connection::open(fixture.0.join("evidence.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM witness_quarantined", [], |row| row.get(0))
        .unwrap();
    assert_eq!(quarantined, 1);
}

#[tokio::test]
async fn historical_dedup_and_conflict_quarantine_survive_manager_restart() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let first = cached(plan.clone(), &source('d')).await;
    let first_value: Value = serde_json::from_slice(&first).unwrap();
    let newer = cached(plan.clone(), &changed_source('e', "2", "source-1")).await;
    let original_receipt = {
        let manager = Manager::start(&fixture.config()).unwrap();
        let (status, original) = post(manager.clone(), first.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(post(manager, newer.clone()).await.0, StatusCode::OK);
        original
    };
    let restored = Manager::start(&fixture.config()).unwrap();
    let mut aged_duplicate = first_value.clone();
    aged_duplicate["observer_elapsed_ms"] = json!("1000");
    let previous_age =
        aged_duplicate["row_ages"][0]["effective_age_ms"].as_str().unwrap().parse::<u64>().unwrap();
    aged_duplicate["row_ages"][0]["effective_age_ms"] = json!((previous_age + 1000).to_string());
    let (status, repeated) =
        post(restored.clone(), serde_json::to_vec(&aged_duplicate).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(repeated, original_receipt, "historical duplicate must return its original receipt");
    let retained: String = rusqlite::Connection::open(fixture.0.join("evidence.db"))
        .unwrap()
        .query_row("SELECT body FROM witness_observations WHERE generation='1'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&retained).unwrap(),
        first_value,
        "an aged duplicate may not overwrite the original archived body"
    );
    assert_eq!(post(restored.clone(), newer).await.0, StatusCode::OK);
    let conflict = cached(plan, &changed_source('f', "1", "source-1")).await;
    assert_eq!(post(restored, conflict).await.0, StatusCode::CONFLICT);
    let reopened = Manager::start(&fixture.config()).unwrap();
    assert_eq!(
        post(reopened, first).await.0,
        StatusCode::CONFLICT,
        "quarantine must persist across restart and cannot renew a former archive row"
    );
    let connection = rusqlite::Connection::open(fixture.0.join("evidence.db")).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM witness_observations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn witness_archive_quota_refusal_has_no_success_ack_or_partial_row() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let mut config = fixture.config();
    config.evidence_quota_bytes = tos_health_core::wire::U64(262_144);
    let manager = Manager::start(&config).unwrap();
    let mut accepted = 0;
    let mut refused = false;
    for generation in 1..=256 {
        let body =
            cached(plan.clone(), &changed_source('d', &generation.to_string(), "source-1")).await;
        let (status, receipt) = post(manager.clone(), body.clone()).await;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert_eq!(receipt, Value::Null, "quota refusal cannot claim accepted archive receipt");
            let reason = manager.archive_witness("cache_1", &body).await.err().unwrap();
            assert!(
                reason.contains("quota") || reason.contains("full"),
                "refusal must be storage capacity, got: {reason}"
            );
            refused = true;
            break;
        }
        assert_eq!(status, StatusCode::OK);
        assert_eq!(receipt["accepted"], true);
        accepted += 1;
    }
    assert!(refused, "bounded archive must refuse before unbounded history");
    let rows: i64 = rusqlite::Connection::open(fixture.0.join("evidence.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM witness_observations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, accepted, "refused generation must not commit a row");
}

#[test]
fn manager_refuses_oversized_or_uninventoried_witness_plan_before_activation() {
    let fixture = Fixture::new();
    fixture.plan();
    let mut oversized = std::fs::read(fixture.0.join("plan.json")).unwrap();
    oversized.resize(16_385, b' ');
    std::fs::write(fixture.0.join("plan.json"), oversized).unwrap();
    assert_eq!(Manager::start(&fixture.config()).err().unwrap(), "witness plan body overflow");
    let uninventoried = Fixture::new();
    uninventoried.plan();
    let mut config = uninventoried.config();
    config.inventory.targets.retain(|target| target.scope == "node");
    assert_eq!(Manager::start(&config).err().unwrap(), "witness target outside manager inventory");
}
