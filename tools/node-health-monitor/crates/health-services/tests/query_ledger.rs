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
