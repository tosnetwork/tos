use std::{collections::BTreeSet, path::PathBuf};
use tos_health_core::{
    evidence::EvidenceStore,
    query::{Grant, QueryService, TOOLS},
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
