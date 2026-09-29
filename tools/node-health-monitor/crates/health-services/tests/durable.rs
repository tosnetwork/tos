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
    conn.pragma_update(None, "user_version", 2).unwrap();
    drop(conn);
    assert!(EvidenceDb::open(&p, 1_048_576).is_err());
    let e = EvidenceDb::open(&t.0.join("e.db"), 1_048_576).unwrap();
    assert!(e.page("v1", "node", u64::MAX, 0, 100).is_err());
    assert!(e.page("v1", "node", 1, 2, 100).is_err());
    assert!(e.page("v1", "node", 1, 0, 101).is_err());
}
