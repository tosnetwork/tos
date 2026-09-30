use std::{collections::BTreeMap, path::PathBuf};
use tos_health_core::{
    evidence::Evidence,
    health_state::{Sample, State},
    source::{Availability, Coverage, SourceQuality},
    wire::U64,
};
use tos_health_services::durable::*;
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "health-db-{}",
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
fn record(id: u64) -> DurableEvidence {
    DurableEvidence {
        source_epoch: "source-1".into(),
        record: Evidence {
            node_id: "v1".into(),
            scope_id: "node".into(),
            source_id: "native".into(),
            source_record_id: id.to_string(),
            process_epoch: "process-1".into(),
            observed_at_ms: 0,
            received_at_ms: 1,
            quality: SourceQuality {
                availability: Availability::Available,
                coverage: Coverage::Complete,
                observed_at_ms: Some(0),
                last_success_at_ms: Some(0),
                clock_valid: true,
                process_epoch: "process-1".into(),
                source_sequence: id.to_string(),
            },
            payload: serde_json::json!({"generation":id.to_string(),"rss_bytes":"9007199254740993"}),
            redacted: true,
        },
    }
}
fn key() -> RuleKey {
    RuleKey { node: "v1".into(), scope: "node".into(), rule: "storage_ack_failure".into() }
}
fn good(g: u64) -> Evaluation {
    Evaluation::Good {
        samples: BTreeMap::from([(
            "native".into(),
            Sample { process_epoch: "p".into(), source_epoch: "s".into(), generation: U64(g) },
        )]),
    }
}
fn bad() -> Evaluation {
    Evaluation::Bad { severity: "critical".into() }
}
#[test]
fn immutable_sequence_survives_restart_and_late_arrival() {
    let t = Temp::new();
    let path = t.0.join("evidence.db");
    let mut db = EvidenceDb::open(&path, 1_048_576).unwrap();
    let first = db.insert(record(1)).unwrap();
    let w = db.watermark().unwrap();
    let mut duplicate = record(1);
    duplicate.record.received_at_ms = 99;
    let same = db.insert(duplicate).unwrap();
    assert_eq!(same.store_seq, first.store_seq);
    assert_eq!(same.evidence.record.received_at_ms, 1);
    db.insert(record(2)).unwrap();
    let rows = db.page("v1", "node", w, 0, 100).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].evidence.record.payload["rss_bytes"], "9007199254740993");
    drop(db);
    let mut db = EvidenceDb::open(&path, 1_048_576).unwrap();
    assert_eq!(db.watermark().unwrap(), 2);
    assert_eq!(db.insert(record(3)).unwrap().store_seq.0, 3);
    assert_eq!(db.page("v1", "node", w, 0, 100).unwrap().len(), 1);
    db.checkpoint().unwrap();
}
#[test]
fn conflict_is_persistent_and_scope_is_identity() {
    let t = Temp::new();
    let p = t.0.join("evidence.db");
    let mut db = EvidenceDb::open(&p, 1_048_576).unwrap();
    db.insert(record(1)).unwrap();
    let mut other = record(1);
    other.record.scope_id = "masterchain".into();
    db.insert(other).unwrap();
    let mut conflict = record(1);
    conflict.record.payload["rss_bytes"] = "7".into();
    assert_eq!(db.insert(conflict).unwrap_err(), "SOURCE_CONFLICT");
    drop(db);
    let mut db = EvidenceDb::open(&p, 1_048_576).unwrap();
    assert_eq!(db.insert(record(2)).unwrap_err(), "SOURCE_CONFLICT");
    assert!(db.page("v1", "node", db.watermark().unwrap(), 0, 100).unwrap().is_empty());
    let mut fresh = record(2);
    fresh.source_epoch = "source-2".into();
    db.insert(fresh).unwrap();
}
#[test]
fn incident_and_outbox_commit_together() {
    let t = Temp::new();
    let mut db = ControlDb::open(&t.0.join("control.db"), 1_048_576, 16, 1).unwrap();
    let k = key();
    let req = vec!["native".into()];
    db.evaluate(&k, bad(), 0, &req, 60_000).unwrap();
    assert_eq!(db.sequence().unwrap(), 1);
    assert_eq!(db.pending().unwrap().len(), 1);
    assert_eq!(
        db.evaluate(&k, Evaluation::Unknown, 30_000, &req, 60_000).unwrap_err(),
        "outbox capacity exceeded"
    );
    assert_eq!(db.state(&k).unwrap().unwrap().state, State::Open);
    assert_eq!(db.sequence().unwrap(), 1);
    let id = db.pending().unwrap()[0].0;
    db.delivered(id).unwrap();
    db.evaluate(&k, Evaluation::Unknown, 30_000, &req, 60_000).unwrap();
    assert_eq!(db.state(&k).unwrap().unwrap().state, State::SuspendedUnknown);
}
#[test]
fn legacy_pending_outbox_migrates_without_ack_and_retry_metadata_is_durable() {
    let t = Temp::new();
    let path = t.0.join("control.db");
    let old = rusqlite::Connection::open(&path).unwrap();
    old.execute_batch("CREATE TABLE outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,key TEXT NOT NULL UNIQUE,body TEXT NOT NULL,delivered INTEGER NOT NULL DEFAULT 0);
        INSERT INTO outbox(key,body) VALUES('old-key','{\"event\":1}');").unwrap();
    drop(old);
    let mut db = ControlDb::open(&path, 1_048_576, 16, 32).unwrap();
    let row = db.pending().unwrap().pop().unwrap();
    assert_eq!((row.1.as_str(), row.2.as_str()), ("old-key", "{\"event\":1}"));
    assert_eq!(db.due(1).unwrap().len(), 1);
    let hash = db.begin_attempt(row.0, "approved", 1).unwrap();
    assert_eq!(hash.len(), 64);
    assert!(db.due(15_000).unwrap().is_empty());
    assert_eq!(
        db.begin_attempt(row.0, "other", 15_001).unwrap_err(),
        "receiver alias mismatch or attempt not due"
    );
    drop(db);
    let mut db = ControlDb::open(&path, 1_048_576, 16, 32).unwrap();
    assert_eq!(db.pending().unwrap().len(), 1);
    assert_eq!(db.begin_attempt(row.0, "approved", 15_001).unwrap(), hash);
    assert!(db.due(45_000).unwrap().is_empty());
    assert_eq!(db.begin_attempt(row.0, "approved", 45_001).unwrap(), hash);
    assert!(db.due(105_000).unwrap().is_empty());
    assert_eq!(db.begin_attempt(row.0, "approved", 105_001).unwrap(), hash);
}
#[test]
fn restart_does_not_resolve_or_continue_old_hold() {
    let t = Temp::new();
    let p = t.0.join("control.db");
    let k = key();
    let req = vec!["native".into()];
    let mut db = ControlDb::open(&p, 1_048_576, 16, 32).unwrap();
    db.evaluate(&k, bad(), 0, &req, 60_000).unwrap();
    db.evaluate(&k, good(2), 100_000, &req, 60_000).unwrap();
    drop(db);
    let mut db = ControlDb::open(&p, 1_048_576, 16, 32).unwrap();
    let s = db.state(&k).unwrap().unwrap();
    assert_eq!(s.state, State::SuspendedUnknown);
    assert_eq!(s.severity, "critical");
    assert_eq!(db.evaluate(&k, good(3), 1, &req, 60_000).unwrap().state, State::Recovering);
    assert_eq!(db.evaluate(&k, good(3), 90_000, &req, 60_000).unwrap().state, State::Recovering);
    assert_eq!(
        db.evaluate(&k, good(4), 90_001, &req, 60_000).unwrap().state,
        State::ClosedRecovered
    );
    assert_eq!(db.evaluate(&k, bad(), 100_000, &req, 60_000).unwrap().episode.0, 2);
}
#[test]
fn evidence_disk_limit_does_not_consume_control_capacity() {
    let t = Temp::new();
    let mut e = EvidenceDb::open(&t.0.join("evidence.db"), 262_144).unwrap();
    let mut c = ControlDb::open(&t.0.join("control.db"), 1_048_576, 16, 32).unwrap();
    let mut full = false;
    for id in 1..100 {
        let mut r = record(id);
        r.record.payload["excerpt"] = "a".repeat(16000).into();
        if e.insert(r).is_err() {
            full = true;
            break;
        }
    }
    assert!(full);
    assert!(c.evaluate(&key(), bad(), 0, &["native".into()], 60_000).unwrap().active());
    assert_eq!(c.pending().unwrap().len(), 1);
}
#[test]
fn future_schema_and_invalid_page_are_rejected() {
    let t = Temp::new();
    let p = t.0.join("future.db");
    let conn = rusqlite::Connection::open(&p).unwrap();
    conn.pragma_update(None, "user_version", 3).unwrap();
    drop(conn);
    assert!(EvidenceDb::open(&p, 1_048_576).is_err());
    let e = EvidenceDb::open(&t.0.join("e.db"), 1_048_576).unwrap();
    assert!(e.page("v1", "node", u64::MAX, 0, 100).is_err());
    assert!(e.page("v1", "node", 1, 2, 100).is_err());
    assert!(e.page("v1", "node", 1, 0, 101).is_err());
}
#[test]
fn whole_round_rolls_back_when_any_outbox_change_fails() {
    let t = Temp::new();
    let mut db = ControlDb::open(&t.0.join("control.db"), 1_048_576, 16, 1).unwrap();
    let k = key();
    let other = RuleKey { rule: "queue_stall".into(), ..k.clone() };
    let updates = vec![
        ControlUpdate {
            key: k.clone(),
            signal: bad(),
            required: vec!["native".into()],
            hold: 60_000,
        },
        ControlUpdate {
            key: other.clone(),
            signal: bad(),
            required: vec!["native".into()],
            hold: 60_000,
        },
    ];
    assert!(db.evaluate_round(updates, 0).is_err());
    assert!(db.state(&k).unwrap().is_none());
    assert!(db.state(&other).unwrap().is_none());
    assert!(db.pending().unwrap().is_empty());
    assert_eq!(db.sequence().unwrap(), 0);
}
#[test]
fn immutable_inventory_revision_is_enforced() {
    let t = Temp::new();
    let mut db = ControlDb::open(&t.0.join("control.db"), 1_048_576, 16, 32).unwrap();
    db.bind_inventory("r1", "one").unwrap();
    db.bind_inventory("r1", "one").unwrap();
    for n in 2..=64 {
        db.bind_inventory(&format!("r{n}"), "one").unwrap();
    }
    db.bind_inventory("r1", "one").unwrap();
    assert!(db.bind_inventory("r65", "one").is_err());
    assert_eq!(db.bind_inventory("r1", "two").unwrap_err(), "inventory revision conflict");
}

#[test]
fn ordered_episode_timeline_is_persisted_and_outboxed() {
    let t = Temp::new();
    let path = t.0.join("control.db");
    let k = key();
    let required = vec!["native".into()];
    let mut db = ControlDb::open(&path, 1_048_576, 16, 32).unwrap();
    let opened = db.evaluate(&k, bad(), 0, &required, 60_000).unwrap();
    assert_eq!((opened.state, opened.episode.0), (State::Open, 1));
    let unknown = db.evaluate(&k, Evaluation::Unknown, 30_000, &required, 60_000).unwrap();
    assert_eq!(unknown.state, State::SuspendedUnknown);
    assert_eq!(unknown.severity, "critical");
    assert_eq!(
        db.evaluate(&k, good(2), 100_000, &required, 60_000).unwrap().state,
        State::Recovering
    );
    assert_eq!(
        db.evaluate(&k, good(2), 170_000, &required, 60_000).unwrap().state,
        State::Recovering
    );
    assert_eq!(
        db.evaluate(&k, good(3), 180_000, &required, 60_000).unwrap().state,
        State::ClosedRecovered
    );
    assert_eq!(db.evaluate(&k, bad(), 185_000, &required, 60_000).unwrap().episode.0, 2);
    assert_eq!(db.sequence().unwrap(), 6);
    let outbox = db.pending().unwrap();
    assert_eq!(outbox.len(), 5); // repeat generation did not emit a transition
    assert!(outbox.iter().any(|(_, _, body)| body.contains("closed_recovered")));
    drop(db);
    let mut restored = ControlDb::open(&path, 1_048_576, 16, 32).unwrap();
    let incident = restored.state(&k).unwrap().unwrap();
    assert_eq!((incident.state, incident.episode.0), (State::SuspendedUnknown, 2));
    assert_eq!(incident.severity, "critical");
    assert_eq!(restored.pending().unwrap().len(), 5);
    assert_eq!(restored.sequence().unwrap(), 6);
    assert_eq!(
        restored.evaluate(&k, good(4), 1, &required, 60_000).unwrap().state,
        State::Recovering
    );
}

#[test]
fn outbox_capacity_failure_cannot_advance_recovery_or_sequence() {
    let t = Temp::new();
    let k = key();
    let required = vec!["native".into()];
    let mut db = ControlDb::open(&t.0.join("control.db"), 1_048_576, 16, 2).unwrap();
    db.evaluate(&k, bad(), 0, &required, 60_000).unwrap();
    db.evaluate(&k, Evaluation::Unknown, 30_000, &required, 60_000).unwrap();
    assert_eq!(
        db.evaluate(&k, good(2), 100_000, &required, 60_000).unwrap_err(),
        "outbox capacity exceeded"
    );
    assert_eq!(db.state(&k).unwrap().unwrap().state, State::SuspendedUnknown);
    assert_eq!(db.sequence().unwrap(), 2);
    assert_eq!(db.pending().unwrap().len(), 2);
}

#[test]
fn both_databases_verify_wal_full_and_passive_checkpoint_is_bounded_by_reader() {
    let t = Temp::new();
    let evidence_path = t.0.join("evidence.db");
    let control_path = t.0.join("control.db");
    let mut evidence = EvidenceDb::open(&evidence_path, 1_048_576).unwrap();
    let mut control = ControlDb::open(&control_path, 1_048_576, 16, 32).unwrap();
    for path in [&evidence_path, &control_path] {
        let connection = rusqlite::Connection::open(path).unwrap();
        let mode: String =
            connection.pragma_query_value(None, "journal_mode", |r| r.get(0)).unwrap();
        let sync: i64 = connection.pragma_query_value(None, "synchronous", |r| r.get(0)).unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(sync, 2);
    }
    evidence.insert(record(1)).unwrap();
    let reader = rusqlite::Connection::open(&evidence_path).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let _: i64 = reader.query_row("SELECT count(*) FROM observations", [], |r| r.get(0)).unwrap();
    evidence.insert(record(2)).unwrap();
    let started = std::time::Instant::now();
    let (_busy, log, checkpointed) = evidence.checkpoint().unwrap();
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
    assert!(log >= checkpointed);
    reader.execute_batch("ROLLBACK").unwrap();
    control.evaluate(&key(), bad(), 0, &["native".into()], 60_000).unwrap();
    assert!(control.state(&key()).unwrap().unwrap().active());
    assert_eq!(control.sequence().unwrap(), 1);
}
