//! Bounded evidence retention against real SQLite files.
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::path::PathBuf;
use tos_health_core::{
    edge_snapshot::{ProcessEnvelope, ProcessPayload},
    evidence::Evidence,
    health_state::State,
    native::{canonical_hash, Coverage as NativeCoverage, Quality, SourceEnvelope},
    source::{Availability, Coverage, SourceQuality},
    wire::U64,
    witness::Plan,
};
use tos_health_services::{
    durable::{is_capacity_error, ControlDb, DurableEvidence, Evaluation, EvidenceDb, RuleKey},
    manager_query_source::read_process_projection_page,
    retention::{RetentionPolicy, RETAINED_ROWS_PER_SOURCE, RETENTION_MIN_MS},
    witness::{router as witness_router, CacheResponse, WitnessCache},
};
use tower::ServiceExt;

const HOUR: i64 = 3_600_000;
const DAY: i64 = 24 * HOUR;
const NETWORK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "health-retention-{}",
            tos_health_services::hex(&tos_health_services::random_token().unwrap())
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn policy(evidence_ms: u64) -> RetentionPolicy {
    RetentionPolicy { evidence_retention_ms: Some(evidence_ms), witness_retention_ms: None }
}
fn record(source: &str, generation: u64, received_at_ms: i64) -> DurableEvidence {
    DurableEvidence {
        source_epoch: "source-1".into(),
        record: Evidence {
            node_id: "v1".into(),
            scope_id: "node".into(),
            source_id: source.into(),
            source_record_id: generation.to_string(),
            process_epoch: "process-1".into(),
            observed_at_ms: received_at_ms - 5,
            received_at_ms,
            quality: SourceQuality {
                availability: Availability::Available,
                coverage: Coverage::Complete,
                observed_at_ms: Some(received_at_ms - 5),
                last_success_at_ms: Some(received_at_ms - 5),
                clock_valid: true,
                process_epoch: "process-1".into(),
                source_sequence: generation.to_string(),
            },
            payload: json!({"generation":generation.to_string(),"value":"1"}),
            redacted: true,
        },
    }
}
fn process_row(generation: u64, received_at_ms: i64) -> DurableEvidence {
    let at = "2026-09-29T00:00:01.000Z";
    let timestamp = chrono::DateTime::parse_from_rfc3339(at).unwrap().timestamp_millis();
    let payload = ProcessPayload {
        kind: "process".into(),
        pid: 4242,
        rss_bytes: Some(U64(4096 + generation)),
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
        source_epoch: "epoch-1".into(),
        source_version: "proc-v1".into(),
        generation: U64(generation),
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
        source_epoch: "epoch-1".into(),
        record: Evidence {
            node_id: "v1".into(),
            scope_id: "node".into(),
            source_id: "process".into(),
            source_record_id: format!("epoch-1:{generation}"),
            process_epoch: "boot:4242:100".into(),
            observed_at_ms: timestamp,
            received_at_ms,
            quality: SourceQuality {
                availability: Availability::Available,
                coverage: Coverage::Partial,
                observed_at_ms: Some(timestamp),
                last_success_at_ms: Some(timestamp),
                clock_valid: true,
                process_epoch: "boot:4242:100".into(),
                source_sequence: generation.to_string(),
            },
            payload: json!({"component":"process","source":source}),
            redacted: true,
        },
    }
}
fn generations(path: &std::path::Path, source: &str) -> Vec<String> {
    let conn = rusqlite::Connection::open(path).unwrap();
    let mut query = conn
        .prepare("SELECT source_record FROM observations WHERE source=?1 ORDER BY store_seq")
        .unwrap();
    query.query_map([source], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
}
fn table_count(path: &std::path::Path, table: &str) -> i64 {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).unwrap()
}

#[test]
fn old_rows_go_young_rows_stay_and_a_replay_is_refused_as_expired() {
    let t = Temp::new();
    let path = t.0.join("evidence.db");
    let mut db = EvidenceDb::open(&path, 4_194_304).unwrap();
    db.bind_network(NETWORK).unwrap();
    let now = now_ms();
    for generation in 1..=20 {
        db.insert(record("native_facts", generation, now - 3 * DAY)).unwrap();
    }
    for generation in 21..=30 {
        db.insert(record("native_facts", generation, now - 60_000)).unwrap();
    }
    let watermark = db.watermark().unwrap();
    let pass = db.retain(&policy(DAY as u64), now).unwrap();
    assert_eq!(pass.observations_deleted, 20);
    assert!(pass.complete);
    assert_eq!(pass.observations_rows, 10);
    assert_eq!(pass.unsealable_kept, 0);
    assert_eq!(pass.oldest_retained_received_at_ms, Some(now - 60_000));
    let kept = generations(&path, "native_facts");
    assert_eq!(kept, (21..=30).map(|g| g.to_string()).collect::<Vec<_>>());
    // A replay of deleted evidence cannot mint a fresh sequence number.
    assert_eq!(db.insert(record("native_facts", 5, now)).unwrap_err(), "EVIDENCE_EXPIRED");
    assert_eq!(db.insert(record("native_facts", 20, now)).unwrap_err(), "EVIDENCE_EXPIRED");
    // Sequence numbers are never reused and a genuinely new generation is admitted.
    assert_eq!(db.watermark().unwrap(), watermark);
    let next = db.insert(record("native_facts", 31, now)).unwrap();
    assert_eq!(next.store_seq.0, watermark + 1);
    // A duplicate of a retained row still returns the original receipt.
    let mut same = record("native_facts", 25, now - 60_000);
    same.record.received_at_ms = now;
    let same = db.insert(same).unwrap();
    assert_eq!(same.evidence.record.received_at_ms, now - 60_000);
    // Another source epoch is a different identity and is not sealed.
    let mut other_epoch = record("native_facts", 5, now);
    other_epoch.source_epoch = "source-2".into();
    db.insert(other_epoch).unwrap();
    drop(db);
    // The seal survives a reopen.
    let mut db = EvidenceDb::open(&path, 4_194_304).unwrap();
    assert_eq!(db.insert(record("native_facts", 1, now)).unwrap_err(), "EVIDENCE_EXPIRED");
}

#[test]
fn two_hour_floor_overrides_a_shorter_configured_retention() {
    let t = Temp::new();
    let path = t.0.join("evidence.db");
    let mut db = EvidenceDb::open(&path, 4_194_304).unwrap();
    let now = now_ms();
    for generation in 1..=10 {
        db.insert(record("edge_probe", generation, now - 3 * HOUR)).unwrap();
    }
    for generation in 11..=20 {
        db.insert(record("edge_probe", generation, now - 90 * 60_000)).unwrap();
    }
    for generation in 21..=30 {
        db.insert(record("edge_probe", generation, now - 60_000)).unwrap();
    }
    let pass = db.retain(&policy(RETENTION_MIN_MS), now).unwrap();
    assert_eq!(pass.observations_deleted, 10, "only rows older than the floor may go");
    let kept = generations(&path, "edge_probe");
    assert_eq!(kept.len(), 20);
    assert_eq!(kept[0], "11");
}

#[test]
fn newest_rows_per_source_survive_any_age() {
    let t = Temp::new();
    let path = t.0.join("evidence.db");
    let mut db = EvidenceDb::open(&path, 4_194_304).unwrap();
    let now = now_ms();
    for generation in 1..=12 {
        db.insert(record("native_chain", generation, now - 30 * DAY)).unwrap();
    }
    for generation in 1..=5 {
        db.insert(record("native_gauges", generation, now - 30 * DAY)).unwrap();
    }
    let mut other_scope = record("native_chain", 1, now - 30 * DAY);
    other_scope.record.scope_id = "masterchain".into();
    db.insert(other_scope).unwrap();
    let pass = db.retain(&policy(DAY as u64), now).unwrap();
    assert_eq!(pass.observations_deleted, 12 - u64::from(RETAINED_ROWS_PER_SOURCE));
    assert_eq!(
        generations(&path, "native_chain"),
        vec!["5", "6", "7", "8", "9", "10", "11", "12", "1"],
        "the eight newest of (v1,node,native_chain) plus the separate masterchain row"
    );
    assert_eq!(generations(&path, "native_gauges").len(), 5);
    // A second pass finds nothing else to do and remains complete.
    let again = db.retain(&policy(DAY as u64), now).unwrap();
    assert_eq!(again.observations_deleted, 0);
    assert!(again.complete);
}

#[test]
fn quarantine_and_identity_tables_are_untouched_by_a_full_pass() {
    let t = Temp::new();
    let path = t.0.join("evidence.db");
    let mut db = EvidenceDb::open(&path, 4_194_304).unwrap();
    db.bind_network(NETWORK).unwrap();
    let now = now_ms();
    for generation in 1..=10 {
        db.insert(record("diagnostic", generation, now - 3 * DAY)).unwrap();
    }
    let mut conflict = record("diagnostic", 3, now - 3 * DAY);
    conflict.record.payload["value"] = "2".into();
    assert_eq!(db.insert(conflict).unwrap_err(), "SOURCE_CONFLICT");
    assert_eq!(table_count(&path, "quarantined"), 1);
    let pass = db.retain(&policy(DAY as u64), now).unwrap();
    assert_eq!(pass.observations_deleted, 2);
    assert_eq!(table_count(&path, "quarantined"), 1, "quarantine is a control fact, not evidence");
    assert_eq!(table_count(&path, "database_identity"), 1);
    assert_eq!(db.insert(record("diagnostic", 11, now)).unwrap_err(), "SOURCE_CONFLICT");
    drop(db);
    assert_eq!(EvidenceDb::open(&path, 4_194_304).unwrap().watermark().unwrap(), 10);
}

#[test]
fn an_open_incident_in_the_control_database_survives_evidence_retention() {
    let t = Temp::new();
    let evidence_path = t.0.join("evidence.db");
    let mut evidence = EvidenceDb::open(&evidence_path, 4_194_304).unwrap();
    let mut control = ControlDb::open(&t.0.join("control.db"), 1_048_576, 16, 32).unwrap();
    let now = now_ms();
    for generation in 1..=10 {
        evidence.insert(record("native_facts", generation, now - 3 * DAY)).unwrap();
    }
    let key =
        RuleKey { node: "v1".into(), scope: "node".into(), rule: "pq_signing_failure".into() };
    control
        .evaluate(
            &key,
            Evaluation::Bad { severity: "critical".into() },
            0,
            &["native_facts".into()],
            60_000,
        )
        .unwrap();
    assert_eq!(control.state(&key).unwrap().unwrap().state, State::Open);
    let pass = evidence.retain(&policy(DAY as u64), now).unwrap();
    assert_eq!(pass.observations_deleted, 2);
    let state = control.state(&key).unwrap().unwrap();
    assert_eq!(state.state, State::Open);
    assert!(state.active());
    assert_eq!(control.pending().unwrap().len(), 1);
    assert_eq!(control.sequence().unwrap(), 1);
    assert_eq!(table_count(&t.0.join("control.db"), "incidents"), 1);
}

#[test]
fn a_pass_while_the_quota_is_full_frees_space_for_the_next_insert() {
    let t = Temp::new();
    let path = t.0.join("evidence.db");
    let mut db = EvidenceDb::open(&path, 1_048_576).unwrap();
    let now = now_ms();
    let mut refused = None;
    for generation in 1..400 {
        let mut row = record("native_core", generation, now - 3 * DAY);
        row.record.payload["excerpt"] = "a".repeat(8_000).into();
        if let Err(error) = db.insert(row) {
            refused = Some(error);
            break;
        }
    }
    let refused = refused.expect("quota was never reached");
    assert!(is_capacity_error(&refused), "{refused}");
    assert!(!is_capacity_error("SOURCE_CONFLICT"));
    assert!(!is_capacity_error("EVIDENCE_EXPIRED"));
    let pass = db.retain(&policy(DAY as u64), now).unwrap();
    assert!(pass.observations_deleted > 0);
    assert_eq!(pass.observations_rows, u64::from(RETAINED_ROWS_PER_SOURCE));
    let mut fresh = record("native_core", 500, now);
    fresh.record.payload["excerpt"] = "b".repeat(8_000).into();
    db.insert(fresh).unwrap();
}

#[test]
fn a_parent_the_query_service_retained_within_the_floor_is_never_deleted() {
    let t = Temp::new();
    let path = t.0.join("evidence.db");
    let mut db = EvidenceDb::open(&path, 4_194_304).unwrap();
    db.bind_network(NETWORK).unwrap();
    let now = now_ms();
    let mut rows = Vec::new();
    for generation in 1..=12 {
        rows.push(db.insert(process_row(generation, now - 90 * 60_000)).unwrap());
    }
    let first = read_process_projection_page(&path, NETWORK, None, &[]).unwrap();
    assert_eq!(first.records.len(), 12);
    let retained: Vec<_> = first.records.iter().map(|(row, _)| row.clone()).collect();
    assert_eq!(retained.len(), rows.len());
    let pass = db.retain(&policy(RETENTION_MIN_MS), now).unwrap();
    assert_eq!(pass.observations_deleted, 0, "rows younger than the floor are not eligible");
    let again = read_process_projection_page(&path, NETWORK, Some(&first.cursor), &retained)
        .expect("retained parents must still be present");
    assert!(again.records.is_empty());
    assert!(again.quarantined_retained.is_empty());
    // Once the parents age past both the floor and the configured window they
    // may go, and a projection that still names them reports it explicitly.
    let later = now + 3 * HOUR;
    let pass = db.retain(&policy(RETENTION_MIN_MS), later).unwrap();
    assert_eq!(pass.observations_deleted, 12 - u64::from(RETAINED_ROWS_PER_SOURCE));
    assert_eq!(
        read_process_projection_page(&path, NETWORK, Some(&first.cursor), &retained).unwrap_err(),
        "retained M parent missing"
    );
}

#[test]
fn unconfigured_policy_and_unsealable_records_delete_nothing() {
    let t = Temp::new();
    let path = t.0.join("evidence.db");
    let mut db = EvidenceDb::open(&path, 4_194_304).unwrap();
    let now = now_ms();
    for generation in 1..=10 {
        db.insert(record("edge_probe", generation, now - 3 * DAY)).unwrap();
    }
    let pass = db.retain(&RetentionPolicy::default(), now).unwrap();
    assert_eq!(pass.observations_deleted, 0);
    assert!(pass.complete);
    assert_eq!(pass.observations_rows, 10);
    for tag in ["alpha", "beta", "gamma"] {
        let mut row = record("host_notes", 1, now - 3 * DAY);
        row.record.source_record_id = format!("note:{tag}");
        db.insert(row).unwrap();
    }
    for generation in 1..=8 {
        db.insert(record("host_notes", generation + 100, now - 60_000)).unwrap();
    }
    let pass = db.retain(&policy(DAY as u64), now).unwrap();
    assert_eq!(pass.observations_deleted, 2);
    assert_eq!(pass.unsealable_kept, 3, "records without a canonical generation stay");
    assert_eq!(generations(&path, "host_notes").len(), 11);
    assert!(RetentionPolicy { evidence_retention_ms: Some(1), ..Default::default() }
        .validate()
        .is_err());
    assert!(db
        .retain(&RetentionPolicy { evidence_retention_ms: Some(1), ..Default::default() }, now)
        .is_err());
}

fn plan(dir: &std::path::Path) -> Plan {
    let value = json!({"schema_version":1,"profile":"c05_development_cache_only",
        "revision":"a".repeat(64),"observer_id":"observer_1","observer_epoch":"observer-1",
        "network_id":"a".repeat(64),"genesis":"c".repeat(64),"clock_skew_allowance_ms":5000,
        "endpoints":[{"endpoint_id":"cache_1","fixed_url":"https://cache.example.test/witness",
            "failure_domain":"zone_a","kind":"approved_cache_only_https","current_source_epoch":"source-1"}],
        "targets":[{"target_id":"validator_1","node_id":"v1","role":"normal",
            "valid_from":"2026-09-29T00:00:00Z","valid_until":"2026-09-30T00:00:00Z",
            "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
            "endpoint_ids":["cache_1"]}]});
    let bytes = serde_json::to_vec(&value).unwrap();
    std::fs::write(dir.join("plan.json"), &bytes).unwrap();
    Plan::decode(&bytes).unwrap()
}
fn witness_source(generation: u64) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"schema_version":1,"endpoint_id":"cache_1","source_epoch":"source-1",
        "generation":generation.to_string(),"network_id":"a".repeat(64),"genesis":"c".repeat(64),
        "observed_at":null,"source_age_ms":null,"clock_quality":"unknown","coverage":"partial",
        "rows":[{"target_id":"validator_1","observed_at":null,"source_age_ms":"46000",
            "anchor":{"kind":"block","network_id":"a".repeat(64),"genesis":"c".repeat(64),
                "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
                "seqno":generation,"root_hash":"d".repeat(64),"file_hash":"e".repeat(64),
                "point":"reported_finalized"},"network_observation":"observed",
            "reported_certificate_membership":"not_checked","reported_proof":"reported_valid",
            "private_vote_visibility":"unavailable","coverage":"partial",
            "missing_fields":["private_vote"]}]}),
    )
    .unwrap()
}
async fn cached(plan: Plan, raw: &[u8]) -> CacheResponse {
    let cache =
        WitnessCache::new(plan.clone(), b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()).unwrap();
    cache.admit("cache_1", raw, 100).unwrap();
    let request = Request::builder()
        .uri("/v1/witness/cache/cache_1")
        .header("authorization", "Bearer abcdefghijklmnopqrstuvwxyz0123456789")
        .body(Body::empty())
        .unwrap();
    let response = witness_router(cache).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes().to_vec();
    CacheResponse::decode(&bytes, &plan, "cache_1").unwrap().0
}

#[tokio::test]
async fn witness_archive_retention_keeps_newest_rows_and_seals_replays() {
    let t = Temp::new();
    let path = t.0.join("evidence.db");
    let plan = plan(&t.0);
    let mut db = EvidenceDb::open(&path, 4_194_304).unwrap();
    db.activate_witness_current(&plan).unwrap();
    for generation in 1..=12 {
        let response = cached(plan.clone(), &witness_source(generation)).await;
        db.insert_witness(response, &plan).unwrap();
    }
    let conflicting: Value = serde_json::from_slice(&witness_source(3)).unwrap();
    let mut conflicting = conflicting;
    conflicting["rows"][0]["anchor"]["root_hash"] = json!("f".repeat(64));
    let conflicting = cached(plan.clone(), &serde_json::to_vec(&conflicting).unwrap()).await;
    assert_eq!(db.insert_witness(conflicting, &plan).unwrap_err(), "WITNESS_SOURCE_CONFLICT");
    assert_eq!(table_count(&path, "witness_quarantined"), 1);
    let activation_before: (String, i64) = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT plan_hash,quarantined FROM witness_current_activation WHERE endpoint='cache_1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let evidence_only = policy(DAY as u64);
    let untouched = db.retain(&evidence_only, now_ms() + 3 * DAY).unwrap();
    assert_eq!(untouched.witness_deleted, 0, "witness retention is its own key");
    let witness_policy =
        RetentionPolicy { evidence_retention_ms: None, witness_retention_ms: Some(DAY as u64) };
    let pass = db.retain(&witness_policy, now_ms() + 3 * DAY).unwrap();
    assert_eq!(pass.witness_deleted, 12 - u64::from(RETAINED_ROWS_PER_SOURCE));
    assert_eq!(pass.witness_rows, u64::from(RETAINED_ROWS_PER_SOURCE));
    assert!(pass.complete);
    assert_eq!(table_count(&path, "witness_quarantined"), 1);
    let activation_after: (String, i64) = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT plan_hash,quarantined FROM witness_current_activation WHERE endpoint='cache_1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(activation_before, activation_after);
    // The quarantined source epoch refuses everything; a fresh epoch that
    // replays a sealed generation is refused as expired, a newer one is kept.
    let replay = cached(plan.clone(), &witness_source(2)).await;
    assert_eq!(db.insert_witness(replay, &plan).unwrap_err(), "WITNESS_SOURCE_CONFLICT");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("DELETE FROM witness_quarantined", []).unwrap();
    drop(conn);
    let replay = cached(plan.clone(), &witness_source(2)).await;
    assert_eq!(db.insert_witness(replay, &plan).unwrap_err(), "EVIDENCE_EXPIRED");
    let newer = cached(plan.clone(), &witness_source(13)).await;
    db.insert_witness(newer, &plan).unwrap();
    assert_eq!(table_count(&path, "witness_observations"), 9);
    let unbounded = db.retain(&witness_policy, now_ms()).unwrap();
    assert_eq!(unbounded.witness_deleted, 0, "rows received just now are inside the floor");
}

#[test]
fn writer_schedule_recovers_once_after_a_capacity_refusal() {
    use std::sync::{Arc, Mutex};
    use tos_health_services::retention::{RetentionSchedule, RetentionStatus};
    let t = Temp::new();
    let path = t.0.join("evidence.db");
    let mut db = EvidenceDb::open(&path, 1_048_576).unwrap();
    let now = now_ms();
    let mut refused = None;
    for generation in 1..400 {
        let mut row = record("native_core", generation, now - 3 * DAY);
        row.record.payload["excerpt"] = "a".repeat(8_000).into();
        if let Err(error) = db.insert(row) {
            refused = Some(error);
            break;
        }
    }
    let refused = refused.expect("quota was never reached");
    let policy = policy(RETENTION_MIN_MS);
    let status = Arc::new(Mutex::new(RetentionStatus::new(&policy)));
    let mut schedule = RetentionSchedule::new(policy);
    assert!(!schedule.recover(&mut db, &status, "SOURCE_CONFLICT"), "content refusals never prune");
    assert_eq!(status.lock().unwrap().passes, 0);
    assert!(schedule.recover(&mut db, &status, &refused));
    let snapshot = status.lock().unwrap().clone();
    assert_eq!(snapshot.passes, 1);
    assert!(snapshot.observations_deleted_total > 0);
    assert!(snapshot.last_pass_at_ms.is_some());
    let mut fresh = record("native_core", 900, now);
    fresh.record.payload["excerpt"] = "b".repeat(8_000).into();
    db.insert(fresh).unwrap();
    assert!(!schedule.recover(&mut db, &status, &refused), "recovery passes are spaced");
    assert_eq!(status.lock().unwrap().passes, 1);
    let unconfigured = RetentionPolicy::default();
    let mut idle = RetentionSchedule::new(unconfigured);
    let idle_status = Arc::new(Mutex::new(RetentionStatus::new(&unconfigured)));
    assert!(!idle.recover(&mut db, &idle_status, &refused));
    assert!(idle.until_next() > std::time::Duration::from_secs(600));
    let json = status.lock().unwrap().json(now);
    assert_eq!(json["configured"], true);
    assert_eq!(json["passes"], "1");
    assert_eq!(json["evidence_retention_ms"], RETENTION_MIN_MS.to_string());
    assert!(status
        .lock()
        .unwrap()
        .metrics(now)
        .contains("tos_health_evidence_retention_passes_total 1\n"));
}
