use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::PathBuf};
use tos_health_core::{
    evidence::{Evidence, EvidenceStore},
    query::{Grant, QueryService, TOOLS},
    source::{Availability, Coverage, SourceQuality},
};
use tos_health_services::{
    query_ledger::{Attempt, QueryLedger},
    random_token,
};

const BOOT_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOOT_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn temporary() -> (PathBuf, PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "nhm-query-ledger-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&path).unwrap();
    (path.join("ledger.sqlite"), path)
}

fn grant(token: &[u8; 32]) -> Grant {
    Grant::new(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        "aura".into(),
        "a".repeat(64),
        token,
        BTreeSet::from(["v1".into()]),
        BTreeSet::from(["node".into()]),
        1_000,
        2_000,
        100,
        17,
    )
    .unwrap()
}

#[test]
fn terminal_payload_compaction_is_atomic_and_seals_replay() {
    let (file, directory) = temporary();
    let clock_now = tos_health_services::query_ledger::boot_millis().unwrap();
    let old_expiry = clock_now.checked_sub(1).unwrap();
    let mut old = grant(&[0x79; 32]);
    old.expires_monotonic_ms = old_expiry;
    let mut current = grant(&[0x7a; 32]);
    current.run_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into();
    current.expires_monotonic_ms = clock_now.checked_add(200_000).unwrap();
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    ledger.create(&old, 100).unwrap();
    ledger.claim_mcp(&old.run_id, 101).unwrap();
    ledger.create(&current, 100).unwrap();
    assert_eq!(ledger.compact_terminal(old_expiry - 1, 16).unwrap(), 0);
    assert!(ledger.compact_terminal(old_expiry, 17).is_err());
    drop(ledger);

    // Fixture rows exercise the same foreign-key and AUTOINCREMENT tables as
    // real calls, including an injected failure midway through the transaction.
    let db = rusqlite::Connection::open(&file).unwrap();
    db.execute("INSERT INTO query_attempts(run_id,tool,result_code,returned_bytes) VALUES(?1,'test','ok',1)", [&old.run_id]).unwrap();
    let first_seq: i64 =
        db.query_row("SELECT max(attempt_seq) FROM query_attempts", [], |row| row.get(0)).unwrap();
    db.execute("INSERT INTO query_packages(run_id,boot_id,package_sha256,body,fixed_at_ms) VALUES(?1,?2,?3,X'01',101)",
        rusqlite::params![old.run_id, format!("{BOOT_A}|test-time-namespace"), "a".repeat(64)]).unwrap();
    db.execute_batch(
        "CREATE TRIGGER deny_package_delete BEFORE DELETE ON query_packages
        BEGIN SELECT RAISE(FAIL,'injected failure'); END;",
    )
    .unwrap();
    drop(db);
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    assert!(ledger.compact_terminal(old_expiry, 16).unwrap_err().contains("injected failure"));
    assert!(ledger.load_active(&current.run_id, old_expiry).unwrap().is_some());
    assert!(ledger.inspect(&old.run_id).unwrap().unwrap()["terminal_payload_compacted"].is_null());
    assert_eq!(ledger.attempt_count(&old.run_id).unwrap(), 1);
    drop(ledger);
    let db = rusqlite::Connection::open(&file).unwrap();
    db.execute_batch("DROP TRIGGER deny_package_delete").unwrap();
    drop(db);
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    assert_eq!(ledger.compact_terminal(old_expiry, 16).unwrap(), 1);
    assert_eq!(ledger.compact_terminal(old_expiry, 16).unwrap(), 0);
    assert_eq!(ledger.attempt_count(&old.run_id).unwrap(), 0);
    assert_eq!(ledger.mcp_usage(&old.run_id).unwrap(), None);
    assert!(ledger.load_active_package(&old.run_id, old_expiry).unwrap().is_none());
    assert_eq!(ledger.inspect(&old.run_id).unwrap().unwrap()["terminal_payload_compacted"], true);
    assert!(ledger.revoke(&old.run_id).unwrap());
    assert!(ledger.create(&old, 100).is_err(), "sealed run ID must not be recreated");
    assert!(ledger.load_active(&current.run_id, old_expiry).unwrap().is_some());
    drop(ledger);
    let db = rusqlite::Connection::open(&file).unwrap();
    db.execute("INSERT INTO query_attempts(run_id,tool,result_code,returned_bytes) VALUES(?1,'test','ok',1)", [&current.run_id]).unwrap();
    let next_seq: i64 =
        db.query_row("SELECT max(attempt_seq) FROM query_attempts", [], |row| row.get(0)).unwrap();
    assert!(next_seq > first_seq, "attempt sequence must never reset after deletion");
    drop(db);
    let restored = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    assert_eq!(restored.inspect(&old.run_id).unwrap().unwrap()["terminal_payload_compacted"], true);
    drop(restored);
    // Under another boot every resident grant of boot A is unusable (each
    // lookup binds boot_id), so compaction reclaims it whatever its expiry
    // says in A's clock, and its run id stays sealed.
    let mut foreign_clock = QueryLedger::open_for_boot(&file, BOOT_B).unwrap();
    assert_eq!(foreign_clock.compact_terminal(old_expiry, 16).unwrap(), 1);
    let sealed = foreign_clock.inspect(&current.run_id).unwrap().unwrap();
    assert_eq!(sealed["terminal_payload_compacted"], true);
    assert_eq!(sealed["clock_domain_current"], false);
    assert!(foreign_clock.create(&current, 100).is_err(), "sealed run ID must not be recreated");
    drop(foreign_clock);
    std::fs::remove_dir_all(directory).unwrap();
}

/// Seal rows as a long uptime leaves them: run id kept, payload compacted.
fn insert_seals(file: &PathBuf, domain: &str, prefix: &str, count: u32, expires_ms: i64) {
    let mut db = rusqlite::Connection::open(file).unwrap();
    let tx = db.transaction().unwrap();
    {
        let mut insert = tx
            .prepare(
                "INSERT INTO query_grants(run_id,boot_id,expires_ms,revoked,body) VALUES(?1,?2,?3,1,X'')",
            )
            .unwrap();
        for index in 0..count {
            insert
                .execute(rusqlite::params![
                    format!("{prefix}{index:07x}-0000-4000-8000-000000000000"),
                    domain,
                    expires_ms
                ])
                .unwrap();
        }
    }
    tx.commit().unwrap();
}

#[test]
fn compacted_seals_do_not_count_against_the_resident_grant_bound() {
    let (file, directory) = temporary();
    let domain = format!("{BOOT_A}|test-time-namespace");
    drop(QueryLedger::open_for_boot(&file, BOOT_A).unwrap());
    insert_seals(&file, &domain, "a", 4096, 1);
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    ledger
        .create(&grant(&[0x11; 32]), 100)
        .expect("4096 payload-free seals must not refuse a grant");
    assert!(ledger.load_active(&grant(&[0x11; 32]).run_id, 100).unwrap().is_some());
    drop(ledger);
    // The same number of resident rows still does.
    let db = rusqlite::Connection::open(&file).unwrap();
    db.execute("UPDATE query_grants SET body=X'01' WHERE length(body)=0", []).unwrap();
    drop(db);
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    let mut another = grant(&[0x12; 32]);
    another.run_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into();
    assert_eq!(ledger.create(&another, 100).unwrap_err(), "query grant ledger full");
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn compaction_sweeps_seals_older_than_the_history_window_and_keeps_younger_ones() {
    use tos_health_services::query_ledger::TERMINAL_SEAL_HISTORY_MS;
    let (file, directory) = temporary();
    let domain = format!("{BOOT_A}|test-time-namespace");
    let foreign = format!("{BOOT_B}|test-time-namespace");
    drop(QueryLedger::open_for_boot(&file, BOOT_A).unwrap());
    let cutoff = tos_health_services::query_ledger::boot_millis().unwrap();
    let window_edge = i64::try_from(cutoff).unwrap() - TERMINAL_SEAL_HISTORY_MS;
    insert_seals(&file, &domain, "0", 300, window_edge);
    insert_seals(&file, &domain, "1", 3, window_edge + 1);
    insert_seals(&file, &foreign, "2", 3, window_edge - 5);
    let count = |sql: &str| -> i64 {
        rusqlite::Connection::open(&file).unwrap().query_row(sql, [], |row| row.get(0)).unwrap()
    };
    assert_eq!(count("SELECT COUNT(*) FROM query_grants"), 306);
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    assert_eq!(ledger.compact_terminal(cutoff, 16).unwrap(), 0, "no resident run to compact");
    assert_eq!(
        count("SELECT COUNT(*) FROM query_grants WHERE run_id LIKE '0%'"),
        300 - 256,
        "one call sweeps a bounded batch of seals past the window"
    );
    assert_eq!(ledger.compact_terminal(cutoff, 16).unwrap(), 0);
    assert_eq!(count("SELECT COUNT(*) FROM query_grants WHERE run_id LIKE '0%'"), 0);
    assert_eq!(count("SELECT COUNT(*) FROM query_grants WHERE run_id LIKE '1%'"), 3);
    assert_eq!(count("SELECT COUNT(*) FROM query_grants WHERE run_id LIKE '2%'"), 3);
    let young = ledger.inspect("10000000-0000-4000-8000-000000000000").unwrap().unwrap();
    assert_eq!(young["terminal_payload_compacted"], true);
    assert!(ledger.inspect("00000000-0000-4000-8000-000000000000").unwrap().is_none());
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn mcp_binding_call_and_wire_budgets_survive_restart() {
    let (file, directory) = temporary();
    let g = grant(&[0x51; 32]);
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    ledger.create(&g, 100).unwrap();
    ledger.claim_mcp(&g.run_id, 101).unwrap();
    assert!(ledger.claim_mcp(&g.run_id, 101).is_err());
    for _ in 0..16 {
        ledger.reserve_mcp_call(&g.run_id, 102).unwrap();
    }
    assert!(ledger.reserve_mcp_call(&g.run_id, 102).is_err());
    ledger.charge_mcp_wire(&g.run_id, 131_071, 102).unwrap();
    assert!(ledger.charge_mcp_wire(&g.run_id, 2, 102).is_err());
    assert_eq!(ledger.mcp_usage(&g.run_id).unwrap(), Some((16, 131_071)));
    drop(ledger);
    let mut restored = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    assert!(restored.reserve_mcp_call(&g.run_id, 103).is_err());
    restored.charge_mcp_wire(&g.run_id, 1, 103).unwrap();
    assert!(restored.charge_mcp_wire(&g.run_id, 1, 103).is_err());
    assert_eq!(restored.mcp_usage(&g.run_id).unwrap(), Some((16, 131_072)));
    let mut deadline_grant = grant(&[0x52; 32]);
    deadline_grant.run_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into();
    restored.create(&deadline_grant, 100).unwrap();
    restored.claim_mcp(&deadline_grant.run_id, 101).unwrap();
    restored.reserve_mcp_call(&deadline_grant.run_id, 180_100).unwrap();
    restored.charge_mcp_wire(&deadline_grant.run_id, 1, 180_100).unwrap();
    assert!(restored.reserve_mcp_call(&deadline_grant.run_id, 180_101).is_err());
    assert!(restored.charge_mcp_wire(&deadline_grant.run_id, 1, 180_101).is_err());
    assert_eq!(restored.mcp_usage(&deadline_grant.run_id).unwrap(), Some((1, 1)));
    drop(restored);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn legacy_mcp_binding_cannot_reset_unknown_spent_budget() {
    let (file, directory) = temporary();
    let ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    drop(ledger);
    let db = rusqlite::Connection::open(&file).unwrap();
    db.execute_batch(
        "DROP TABLE query_mcp_bindings;
         CREATE TABLE query_mcp_bindings (
           run_id TEXT PRIMARY KEY, boot_id TEXT NOT NULL, bound_at_ms INTEGER NOT NULL
         );
         INSERT INTO query_mcp_bindings VALUES ('old-run', 'old-boot', 1);",
    )
    .unwrap();
    drop(db);
    assert!(QueryLedger::open_for_boot(&file, BOOT_A)
        .err()
        .unwrap()
        .contains("unknown spent budget"));
    let db = rusqlite::Connection::open(&file).unwrap();
    db.execute("DELETE FROM query_mcp_bindings", []).unwrap();
    drop(db);
    assert!(QueryLedger::open_for_boot(&file, BOOT_A).is_ok());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn fixed_broker_package_is_single_write_and_integrity_checked_after_restart() {
    let (file, directory) = temporary();
    let mut g = grant(&[0x63; 32]);
    g.manager_watermark = Some(3);
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    ledger.create(&g, 100).unwrap();
    let body = serde_json::json!({"schema_version":1,"source_profile":"development_process_only",
        "status":"partial","run_id":g.run_id,"network_id":g.network_id,
        "query_watermark":g.watermark.to_string(),"manager_watermark":"3",
        "process":[],"missing_process":[{"node_id":"v1","scope_id":"node"}]})
    .to_string()
    .into_bytes();
    let mut missing: serde_json::Value = serde_json::from_slice(&body).unwrap();
    missing["missing_process"] = serde_json::json!([]);
    assert!(ledger.save_package(&g.run_id, &serde_json::to_vec(&missing).unwrap(), 101).is_err());
    let mut foreign_scope: serde_json::Value = serde_json::from_slice(&body).unwrap();
    foreign_scope["missing_process"][0]["scope_id"] = serde_json::json!("other");
    assert!(ledger
        .save_package(&g.run_id, &serde_json::to_vec(&foreign_scope).unwrap(), 101)
        .is_err());
    let mut extra: serde_json::Value = serde_json::from_slice(&body).unwrap();
    extra["unapproved"] = serde_json::json!(true);
    assert!(ledger.save_package(&g.run_id, &serde_json::to_vec(&extra).unwrap(), 101).is_err());
    let mut malformed_process: serde_json::Value = serde_json::from_slice(&body).unwrap();
    malformed_process["missing_process"] = serde_json::json!([]);
    malformed_process["process"] = serde_json::json!([{
        "node_id":"v1","scope_id":"node","evidence_id":"a".repeat(64),
        "parent_evidence_id":"b".repeat(64),"query_sequence":"17",
        "manager_sequence":"1","observed_at_ms":"+1500","process_epoch":"p",
        "value":{"kind":"process","pid":9,"rss_bytes":null,"anon_bytes":null,
            "file_bytes":null,"swap_bytes":null,"cpu_user_ticks":null,"cpu_system_ticks":null}
    }]);
    assert!(ledger
        .save_package(&g.run_id, &serde_json::to_vec(&malformed_process).unwrap(), 101)
        .is_err());
    malformed_process["process"][0]["observed_at_ms"] = serde_json::json!("1500");
    malformed_process["process"][0]["value"]["pid"] = serde_json::json!(0);
    assert!(ledger
        .save_package(&g.run_id, &serde_json::to_vec(&malformed_process).unwrap(), 101)
        .is_err());
    let digest = ledger.save_package(&g.run_id, &body, 101).unwrap();
    assert_eq!(ledger.save_package(&g.run_id, &body, 102).unwrap(), digest);
    assert!(ledger.save_package(&g.run_id, b"changed", 102).is_err());
    assert!(ledger.save_package(&g.run_id, &[b'x'; 16_385], 102).is_err());
    drop(ledger);
    let ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    assert_eq!(ledger.load_active_package(&g.run_id, 103).unwrap(), Some((digest, body.clone())));
    drop(ledger);
    assert!(QueryLedger::open_for_boot(&file, BOOT_B)
        .unwrap()
        .load_active_package(&g.run_id, 103)
        .unwrap()
        .is_none());
    let db = rusqlite::Connection::open(&file).unwrap();
    db.execute("UPDATE query_packages SET body=X'7b7d' WHERE run_id=?1", [&g.run_id]).unwrap();
    drop(db);
    let integrity_error = QueryLedger::open_for_boot(&file, BOOT_A)
        .unwrap()
        .load_active_package(&g.run_id, 103)
        .err()
        .unwrap();
    assert!(integrity_error.contains("integrity"), "{integrity_error}");
    let mut foreign: serde_json::Value = serde_json::from_slice(&body).unwrap();
    foreign["run_id"] = serde_json::json!("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    let foreign_bytes = serde_json::to_vec(&foreign).unwrap();
    let foreign_digest = format!("{:x}", Sha256::digest(&foreign_bytes));
    let db = rusqlite::Connection::open(&file).unwrap();
    db.execute(
        "UPDATE query_packages SET body=?1,package_sha256=?2 WHERE run_id=?3",
        rusqlite::params![foreign_bytes, foreign_digest, g.run_id],
    )
    .unwrap();
    drop(db);
    assert!(QueryLedger::open_for_boot(&file, BOOT_A)
        .unwrap()
        .load_active_package(&g.run_id, 103)
        .err()
        .unwrap()
        .contains("binding"));
    let mut altered_partition: serde_json::Value = serde_json::from_slice(&body).unwrap();
    altered_partition["missing_process"][0]["scope_id"] = serde_json::json!("other");
    let altered_bytes = serde_json::to_vec(&altered_partition).unwrap();
    let altered_digest = format!("{:x}", Sha256::digest(&altered_bytes));
    let db = rusqlite::Connection::open(&file).unwrap();
    db.execute(
        "UPDATE query_packages SET body=?1,package_sha256=?2 WHERE run_id=?3",
        rusqlite::params![altered_bytes, altered_digest, g.run_id],
    )
    .unwrap();
    drop(db);
    assert!(QueryLedger::open_for_boot(&file, BOOT_A)
        .unwrap()
        .load_active_package(&g.run_id, 103)
        .err()
        .unwrap()
        .contains("missing-process"));
    std::fs::remove_dir_all(directory).unwrap();
}

fn evidence(sequence: u64) -> Evidence {
    let observed = 1_700_000_000_000;
    Evidence {
        node_id: "v1".into(),
        scope_id: "node".into(),
        source_id: "native_core".into(),
        source_record_id: format!("record-{sequence}"),
        process_epoch: "process-1".into(),
        observed_at_ms: observed,
        received_at_ms: observed,
        quality: SourceQuality {
            availability: Availability::Available,
            coverage: Coverage::Partial,
            observed_at_ms: Some(observed),
            last_success_at_ms: Some(observed),
            clock_valid: true,
            process_epoch: "process-1".into(),
            source_sequence: sequence.to_string(),
        },
        payload: serde_json::json!({"kind":"unavailable","reason":"synthetic capacity fixture"}),
        redacted: true,
    }
}

fn event(sequence: u64) -> Evidence {
    let at = 1_700_000_000_000 + sequence as i64 * 1000;
    let mut row = evidence(sequence);
    row.source_id = "collector".into();
    row.observed_at_ms = at;
    row.received_at_ms = at;
    row.quality.observed_at_ms = Some(at);
    row.quality.last_success_at_ms = Some(at);
    row.quality.coverage = Coverage::Complete;
    row.payload = serde_json::json!({
        "kind":"warning",
        "event":{"kind":"warning","stage":null,"reason":"synthetic","correlation_id":null,"excerpt":"synthetic"},
        "source_version":"synthetic-ledger-test-v1",
        "evidence_kind":"event",
        "contract_quality":{"instrumentation_complete":true,"producer_dropped":"0","relay_dropped":"0","parse_errors":"0","shed_reason":null},
        "contract_coverage":{"status":"complete","missing_fields":[],"gaps":[],"sampling_policy":"isolated synthetic ledger test"},
        "contract_payload":{"kind":"diagnostic_fixture","record_type":1,"payload":"0102"}
    });
    row
}

#[test]
fn event_cursor_survives_ledger_restart_without_later_rows() {
    let (file, directory) = temporary();
    let token = [0x67; 32];
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    let mut store = EvidenceStore::new(80_000);
    for sequence in 1..=3 {
        ledger.insert_evidence(&mut store, event(sequence)).unwrap();
    }
    let mut grant = Grant::new(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        "aura".into(),
        "a".repeat(64),
        &token,
        BTreeSet::from(["v1".into()]),
        BTreeSet::from(["node".into()]),
        1_700_000_000_000,
        1_700_000_060_000,
        100,
        store.watermark(),
    )
    .unwrap();
    ledger.create(&grant, 100).unwrap();
    ledger.insert_evidence(&mut store, event(4)).unwrap();
    let mut query = serde_json::json!({"run_id":grant.run_id,"node_ids":["v1"],"scope_id":"node","start":"2023-11-14T22:13:20Z","end":"2023-11-14T22:14:20Z","sources":["collector"],"kinds":["warning"],"correlation_id":"","contains":"","limit":1,"cursor":""});
    let metrics = BTreeSet::new();
    let first = QueryService { store: &store, metrics: &metrics }.call(
        &mut grant,
        "aura",
        &token,
        101,
        TOOLS[3],
        query.clone(),
    );
    assert_eq!(first["status"], "ok", "{first}");
    let cursor = first["pagination"]["next_cursor"].as_str().unwrap().to_owned();
    let bytes = serde_json::to_vec(&first).unwrap().len();
    ledger
        .advance(&grant, 101, Attempt { tool: TOOLS[3], result_code: "ok", returned_bytes: bytes })
        .unwrap();
    drop(ledger);
    let ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    let restored_store = ledger.load_evidence(80_000).unwrap();
    let mut restored_grant = ledger.load_active(&grant.run_id, 102).unwrap().unwrap();
    query["cursor"] = serde_json::json!(cursor);
    let second = QueryService { store: &restored_store, metrics: &metrics }.call(
        &mut restored_grant,
        "aura",
        &token,
        102,
        TOOLS[3],
        query,
    );
    assert_eq!(second["status"], "ok", "{second}");
    assert_eq!(second["data"]["events"][0]["source_record_id"], "record-2");
    assert_eq!(second["pagination"]["truncated"], true);
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn active_watermark_prevents_eviction_across_restart_until_revoked() {
    let (file, directory) = temporary();
    let mut ledger = QueryLedger::open_for_context(&file, BOOT_A, "test-time-namespace").unwrap();
    let mut store = EvidenceStore::new(4096);
    ledger.insert_evidence(&mut store, evidence(1)).unwrap();
    let now = tos_health_services::query_ledger::boot_millis().unwrap();
    let g = Grant::new(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        "aura".into(),
        "a".repeat(64),
        &[0x77; 32],
        BTreeSet::from(["v1".into()]),
        BTreeSet::from(["node".into()]),
        1_000,
        2_000,
        now,
        store.watermark(),
    )
    .unwrap();
    ledger.create(&g, now).unwrap();
    assert!(ledger.insert_evidence(&mut store, evidence(2)).unwrap_err().contains("retention"));
    assert_eq!(store.watermark(), 1);
    assert_eq!(ledger.load_evidence(4096).unwrap().watermark(), 1);
    drop(ledger);
    let mut ledger = QueryLedger::open_for_context(&file, BOOT_A, "test-time-namespace").unwrap();
    let mut restored = ledger.load_evidence(4096).unwrap();
    assert_eq!(ledger.load_active_all(now).unwrap().len(), 1);
    assert!(ledger.insert_evidence(&mut restored, evidence(2)).unwrap_err().contains("retention"));
    assert!(ledger.revoke(&g.run_id).unwrap());
    ledger.insert_evidence(&mut restored, evidence(2)).unwrap();
    assert_eq!(restored.watermark(), 2);
    assert_eq!(restored.entries().count(), 1);
    assert_eq!(ledger.load_evidence(4096).unwrap().entries().count(), 1);
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn durable_grant_restarts_without_raw_token_or_budget_replay() {
    let (file, directory) = temporary();
    let token = [0x34; 32];
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    let mut g = grant(&token);
    ledger.create(&g, 100).unwrap();
    let disk = std::fs::read(&file).unwrap();
    assert!(!disk.windows(token.len()).any(|slice| slice == token));
    let run = g.run_id.clone();
    let result = QueryService { store: &EvidenceStore::new(8192), metrics: &BTreeSet::new() }.call(
        &mut g,
        "aura",
        &token,
        101,
        TOOLS[0],
        serde_json::json!({"run_id":run}),
    );
    assert!(result["error"].is_null());
    let actual_bytes = serde_json::to_vec(&result).unwrap().len();
    assert_eq!(g.returned_bytes(), actual_bytes);
    assert!(ledger
        .advance(&g, 101, Attempt { tool: TOOLS[0], result_code: "ok", returned_bytes: 1_000 })
        .is_err());
    ledger
        .advance(
            &g,
            101,
            Attempt { tool: TOOLS[0], result_code: "ok", returned_bytes: actual_bytes },
        )
        .unwrap();
    assert_eq!(ledger.attempt_count(&g.run_id).unwrap(), 1);
    assert!(ledger
        .advance(
            &g,
            101,
            Attempt { tool: TOOLS[0], result_code: "ok", returned_bytes: actual_bytes }
        )
        .is_err());
    drop(ledger);
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    let restored = ledger.load_active(&g.run_id, 102).unwrap().unwrap();
    assert_eq!(restored.calls(), 1);
    assert!(restored.authenticate("aura", &token, 102).is_ok());
    let mut swapped = restored.clone();
    swapped.nodes.insert("v2".into());
    assert!(ledger
        .advance(&swapped, 102, Attempt { tool: TOOLS[0], result_code: "ok", returned_bytes: 1 })
        .is_err());
    assert!(ledger.revoke(&g.run_id).unwrap());
    assert!(ledger.load_active(&g.run_id, 102).unwrap().is_none());
    drop(ledger);
    assert!(QueryLedger::open_for_boot(&file, BOOT_B)
        .unwrap()
        .load_active(&g.run_id, 102)
        .unwrap()
        .is_none());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn query_ledger_rejects_aliasing_private_file_and_expiry() {
    let (file, directory) = temporary();
    let token = [0x55; 32];
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    assert!(ledger.create(&grant(&token), 201_000).is_err());
    ledger.create(&grant(&token), 100).unwrap();
    assert!(ledger.load_active(&grant(&token).run_id, 200_100).unwrap().is_none());
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}

fn count_sql(file: &PathBuf, sql: &str) -> i64 {
    rusqlite::Connection::open(file).unwrap().query_row(sql, [], |row| row.get(0)).unwrap()
}

#[test]
fn a_grant_from_a_previous_boot_is_compacted_and_its_run_id_stays_sealed() {
    let (file, directory) = temporary();
    let clock = tos_health_services::query_ledger::boot_millis().unwrap();
    let mut g = grant(&[0x61; 32]);
    g.expires_monotonic_ms = clock + 180_000;
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    ledger.create(&g, clock).unwrap();
    drop(ledger);
    // The reviewer's probe: reopen under another boot and compact.
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_B).unwrap();
    assert_eq!(ledger.compact_terminal(clock, 16).unwrap(), 1);
    assert_eq!(count_sql(&file, "SELECT COUNT(*) FROM query_grants WHERE length(body)>0"), 0);
    assert_eq!(count_sql(&file, "SELECT COUNT(*) FROM query_grants"), 1, "the seal stays");
    assert!(
        count_sql(&file, "SELECT compacted_unix_ms FROM query_grants") > 0,
        "a foreign seal carries its wall-clock compaction instant"
    );
    assert!(ledger.create(&g, clock).is_err(), "sealed run ID must not be recreated");
    assert_eq!(ledger.compact_terminal(clock, 16).unwrap(), 0);
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn resident_grants_of_other_boots_release_the_resident_bound_through_compaction() {
    let (file, directory) = temporary();
    let foreign = format!("{BOOT_B}|test-time-namespace");
    drop(QueryLedger::open_for_boot(&file, BOOT_A).unwrap());
    // 4096 payload-carrying rows of another boot, never expired in that boot.
    let mut db = rusqlite::Connection::open(&file).unwrap();
    let tx = db.transaction().unwrap();
    {
        let mut insert = tx
            .prepare(
                "INSERT INTO query_grants(run_id,boot_id,expires_ms,revoked,body) VALUES(?1,?2,?3,0,X'01')",
            )
            .unwrap();
        for index in 0..4096 {
            insert
                .execute(rusqlite::params![
                    format!("f{index:07x}-0000-4000-8000-000000000000"),
                    foreign,
                    i64::MAX / 2
                ])
                .unwrap();
        }
    }
    tx.commit().unwrap();
    drop(db);
    let clock = tos_health_services::query_ledger::boot_millis().unwrap();
    let mut fresh = grant(&[0x62; 32]);
    fresh.expires_monotonic_ms = clock + 180_000;
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    assert_eq!(ledger.create(&fresh, clock).unwrap_err(), "query grant ledger full");
    let mut compacted = 0usize;
    for _ in 0..512 {
        let n = ledger.compact_terminal(clock, 16).unwrap();
        compacted += n;
        if n == 0 {
            break;
        }
    }
    assert_eq!(compacted, 4096, "every foreign resident row is reclaimed, sixteen per call");
    assert_eq!(count_sql(&file, "SELECT COUNT(*) FROM query_grants WHERE length(body)>0"), 0);
    ledger.create(&fresh, clock).expect("released bound admits a new grant");
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn foreign_seals_age_out_by_wall_clock_while_young_and_unstamped_ones_stay() {
    use tos_health_services::query_ledger::TERMINAL_SEAL_HISTORY_MS;
    let (file, directory) = temporary();
    let foreign = format!("{BOOT_B}|test-time-namespace");
    drop(QueryLedger::open_for_boot(&file, BOOT_A).unwrap());
    let unix_now = i64::try_from(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
    )
    .unwrap();
    let db = rusqlite::Connection::open(&file).unwrap();
    let seal = |run: &str, stamp: Option<i64>| {
        db.execute(
            "INSERT INTO query_grants(run_id,boot_id,expires_ms,revoked,body,compacted_unix_ms) VALUES(?1,?2,1,1,X'',?3)",
            rusqlite::params![run, foreign, stamp],
        )
        .unwrap();
    };
    for index in 0..3 {
        seal(
            &format!("0{index:07x}-0000-4000-8000-000000000000"),
            Some(unix_now - TERMINAL_SEAL_HISTORY_MS - 60_000),
        );
        seal(&format!("1{index:07x}-0000-4000-8000-000000000000"), Some(unix_now - 60_000));
        // Compacted by an earlier build under its own boot: no stamp yet.
        seal(&format!("2{index:07x}-0000-4000-8000-000000000000"), None);
    }
    drop(db);
    let clock = tos_health_services::query_ledger::boot_millis().unwrap();
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    assert_eq!(ledger.compact_terminal(clock, 16).unwrap(), 0, "seals carry no payload to compact");
    assert_eq!(
        count_sql(&file, "SELECT COUNT(*) FROM query_grants WHERE run_id LIKE '0%'"),
        0,
        "aged out"
    );
    assert_eq!(
        count_sql(&file, "SELECT COUNT(*) FROM query_grants WHERE run_id LIKE '1%'"),
        3,
        "young"
    );
    assert_eq!(
        count_sql(&file, "SELECT COUNT(*) FROM query_grants WHERE run_id LIKE '2%'"),
        3,
        "kept"
    );
    assert_eq!(
        count_sql(&file, "SELECT COUNT(*) FROM query_grants WHERE run_id LIKE '2%' AND compacted_unix_ms IS NULL"),
        0,
        "an unstamped foreign seal is stamped now so it ages from this point"
    );
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}

/// Schema-faithful derived rows bound to one M parent, as a projection pass
/// leaves them, without building a full M database here.
fn bind_derived_rows(file: &PathBuf, origin: &str, derived: &[&str]) {
    let db = rusqlite::Connection::open(file).unwrap();
    db.execute(
        "INSERT INTO query_origins(origin_id,manager_seq,body) VALUES(?1,1,X'01')",
        [origin],
    )
    .unwrap();
    for (index, id) in derived.iter().enumerate() {
        db.execute(
            "INSERT INTO query_evidence(store_seq,evidence_id,body) VALUES(?1,?2,X'01')",
            rusqlite::params![i64::try_from(index + 1).unwrap(), id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO query_projection_origin(query_evidence_id,origin_id) VALUES(?1,?2)",
            rusqlite::params![id, origin],
        )
        .unwrap();
    }
}

#[test]
fn expired_parents_are_deferred_while_a_grant_of_this_boot_is_active() {
    let (file, directory) = temporary();
    let clock = tos_health_services::query_ledger::boot_millis().unwrap();
    let mut ledger = QueryLedger::open_for_boot(&file, BOOT_A).unwrap();
    let origin = "e".repeat(64);
    let derived = ["1".repeat(64), "2".repeat(64)];
    bind_derived_rows(&file, &origin, &[&derived[0], &derived[1]]);
    let mut g = grant(&[0x63; 32]);
    g.expires_monotonic_ms = clock + 180_000;
    ledger.create(&g, clock).unwrap();
    // Active grant: nothing moves, the parent is reported back as deferred.
    let outcome = ledger.evict_expired_origins(std::slice::from_ref(&origin), clock).unwrap();
    assert!(outcome.evicted.is_empty());
    assert_eq!(outcome.deferred, vec![origin.clone()]);
    assert_eq!(count_sql(&file, "SELECT COUNT(*) FROM query_evidence"), 2);
    assert_eq!(
        count_sql(&file, "SELECT COUNT(*) FROM query_origins"),
        1,
        "the parent stays retained"
    );
    // Past the grant's expiry the same call evicts.
    let outcome =
        ledger.evict_expired_origins(std::slice::from_ref(&origin), clock + 180_001).unwrap();
    assert!(outcome.deferred.is_empty());
    let mut evicted = outcome.evicted.clone();
    evicted.sort();
    assert_eq!(evicted, derived.to_vec());
    assert_eq!(count_sql(&file, "SELECT COUNT(*) FROM query_evidence"), 0);
    assert_eq!(count_sql(&file, "SELECT COUNT(*) FROM query_origins"), 0);
    // A revoked grant pins nothing either.
    assert!(ledger.revoke(&g.run_id).unwrap());
    bind_derived_rows(&file, &"f".repeat(64), &[&"3".repeat(64)]);
    let mut other = grant(&[0x64; 32]);
    other.run_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd".into();
    other.expires_monotonic_ms = clock + 180_000;
    ledger.create(&other, clock).unwrap();
    assert!(ledger.revoke(&other.run_id).unwrap());
    let outcome = ledger.evict_expired_origins(&["f".repeat(64)], clock).unwrap();
    assert_eq!(outcome.evicted, vec!["3".repeat(64)]);
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn a_long_reader_pins_the_wal_and_writes_are_refused_as_backpressure_until_it_lets_go() {
    // SEC-07: `wal_autocheckpoint` bounds the WAL only while no reader holds
    // frames. With a reader open the file grows without limit; the ledger
    // must refuse further writes at its mark, change nothing committed, and
    // resume once the reader is gone, without deleting anything to make room.
    let (file, directory) = temporary();
    let mark: u64 = 256 * 1024;
    let mut ledger =
        QueryLedger::open_for_boot(&file, BOOT_A).unwrap().with_wal_high_water(mark).unwrap();
    let mut store = EvidenceStore::new(32 * 1024 * 1024);
    for sequence in 1..=4 {
        ledger.insert_evidence(&mut store, evidence(sequence)).unwrap();
    }
    let clock = tos_health_services::query_ledger::boot_millis().unwrap();
    let mut pinned = grant(&[0x71; 32]);
    pinned.expires_monotonic_ms = clock + 180_000;
    ledger.create(&pinned, clock).unwrap();
    let baseline = ledger.disk_usage().unwrap();
    assert!(!baseline.backpressure && baseline.backpressure_refusals == 0);
    // A second connection holds a read snapshot: checkpoints cannot reset the WAL.
    let reader = rusqlite::Connection::open(&file).unwrap();
    reader.execute_batch("BEGIN; SELECT COUNT(*) FROM query_grants;").unwrap();
    let mut refused = None;
    let mut written = 0u32;
    for sequence in 5..5000 {
        match ledger.insert_evidence(&mut store, evidence(sequence)) {
            Ok(_) => written += 1,
            Err(error) => {
                refused = Some(error);
                break;
            }
        }
    }
    let error = refused.expect("the WAL gate must refuse before five thousand rows");
    assert!(error.contains("disk_backpressure"), "{error}");
    assert!(written > 0, "the gate must not fire before the mark");
    let usage = ledger.disk_usage().unwrap();
    assert!(usage.backpressure, "{usage:?}");
    assert_eq!(usage.backpressure_refusals, 1);
    assert!(usage.wal_bytes > mark, "{usage:?}");
    assert!(
        usage.checkpoint_pinned >= 1,
        "the passive checkpoint saw the reader's pinned frames: {usage:?}"
    );
    // Nothing committed moves while refused: evidence rows, watermark,
    // grants, cursor table and seals are exactly as before the refusal.
    let evidence_rows = count_sql(&file, "SELECT COUNT(*) FROM query_evidence");
    let grants = count_sql(&file, "SELECT COUNT(*) FROM query_grants");
    let watermark = store.watermark();
    let sequence_on_disk =
        count_sql(&file, "SELECT sequence FROM query_evidence_meta WHERE singleton=1");
    assert!(ledger
        .insert_evidence(&mut store, evidence(9_000))
        .unwrap_err()
        .contains("disk_backpressure"));
    let mut another = grant(&[0x72; 32]);
    another.run_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into();
    another.expires_monotonic_ms = clock + 180_000;
    assert!(ledger.create(&another, clock).unwrap_err().contains("disk_backpressure"));
    assert!(ledger.compact_terminal(clock, 16).unwrap_err().contains("disk_backpressure"));
    assert_eq!(count_sql(&file, "SELECT COUNT(*) FROM query_evidence"), evidence_rows);
    assert_eq!(count_sql(&file, "SELECT COUNT(*) FROM query_grants"), grants);
    assert_eq!(store.watermark(), watermark);
    assert_eq!(
        count_sql(&file, "SELECT sequence FROM query_evidence_meta WHERE singleton=1"),
        sequence_on_disk
    );
    assert!(
        ledger.load_active(&pinned.run_id, clock).unwrap().is_some(),
        "the pinned grant is untouched"
    );
    assert_eq!(ledger.disk_usage().unwrap().backpressure_refusals, 4);
    // Revocation is never gated: a conflict must still be able to revoke.
    assert!(ledger.revoke(&another.run_id).is_ok());
    // The reader lets go: the gate's own passive checkpoint backs every
    // frame, the next write resets the WAL and journal_size_limit shrinks it.
    reader.execute_batch("COMMIT").unwrap();
    drop(reader);
    ledger.insert_evidence(&mut store, evidence(9_000)).unwrap();
    ledger.insert_evidence(&mut store, evidence(9_001)).unwrap();
    let recovered = ledger.disk_usage().unwrap();
    assert!(!recovered.backpressure, "{recovered:?}");
    assert!(recovered.wal_bytes <= mark, "the WAL file shrinks after the reset: {recovered:?}");
    ledger.create(&another, clock).unwrap();
    assert_eq!(count_sql(&file, "SELECT COUNT(*) FROM query_grants"), grants + 1);
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn moving_readers_cannot_accumulate_checkpointed_wal_above_the_water_mark() {
    let (file, directory) = temporary();
    let mark = 256 * 1024;
    let mut ledger =
        QueryLedger::open_for_boot(&file, BOOT_A).unwrap().with_wal_high_water(mark).unwrap();
    let mut store = EvidenceStore::new(32 * 1024 * 1024);
    ledger.insert_evidence(&mut store, evidence(1)).unwrap();
    let readers =
        [rusqlite::Connection::open(&file).unwrap(), rusqlite::Connection::open(&file).unwrap()];
    readers[0]
        .execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE); BEGIN; SELECT COUNT(*) FROM query_evidence;",
        )
        .unwrap();
    let mut current = 0;
    let mut sequence = 1;
    let mut refused = false;
    for _ in 0..40 {
        for _ in 0..4 {
            sequence += 1;
            let before = store.watermark();
            let started = std::time::Instant::now();
            match ledger.insert_evidence(&mut store, evidence(sequence)) {
                Ok(_) => (),
                Err(error) => {
                    assert!(error.contains("disk_backpressure"), "{error}");
                    assert_eq!(store.watermark(), before);
                    assert!(
                        started.elapsed() < std::time::Duration::from_millis(100),
                        "reader reset must not wait"
                    );
                    refused = true;
                    break;
                }
            }
        }
        if refused {
            break;
        }
        let next = 1 - current;
        readers[next].execute_batch("BEGIN; SELECT COUNT(*) FROM query_evidence;").unwrap();
        readers[current].execute_batch("COMMIT").unwrap();
        current = next;
    }
    assert!(refused, "checkpointed WAL prefixes must still count against the physical water mark");
    let held = ledger.disk_usage().unwrap();
    assert!(held.backpressure && held.wal_bytes > mark);
    readers[current].execute_batch("COMMIT").unwrap();
    drop(readers);
    ledger.insert_evidence(&mut store, evidence(sequence)).unwrap();
    let recovered = ledger.disk_usage().unwrap();
    assert!(!recovered.backpressure && recovered.wal_bytes < mark, "{recovered:?}");
    drop(ledger);
    std::fs::remove_dir_all(directory).unwrap();
}
