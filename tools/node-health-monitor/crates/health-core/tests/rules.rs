use tos_health_core::{observer::EpochDeadman, rules::*, wire::U64};
fn inventory(rule: &str, fact: FactId) -> RuleInventory {
    RuleInventory {
        schema_version: 1,
        revision: "test-1".into(),
        network_id: "a".repeat(64),
        targets: vec![Target {
            node: "v1".into(),
            scope: "node".into(),
            sources: vec![SourceSpec {
                id: "probe".into(),
                ttl_ms: U64(45_000),
                facts: vec![fact],
            }],
            rules: vec![RuleSpec {
                id: rule.into(),
                source: "probe".into(),
                threshold: U64(10),
                pending_ms: U64(0),
                recovery_ms: U64(60_000),
                minimum_bad_samples: 1,
                severity: "critical".into(),
            }],
        }],
    }
}
fn frame(fact: FactId, value: u64, g: u64) -> FactFrame {
    FactFrame {
        schema_version: 1,
        network_id: "a".repeat(64),
        node_id: "v1".into(),
        scope_id: "node".into(),
        source_id: "probe".into(),
        process_epoch: "p".into(),
        source_epoch: "s".into(),
        generation: U64(g),
        source_age_ms: U64(0),
        request_duration_ms: U64(0),
        observed_at: "2026-09-29T00:00:00Z".into(),
        clock_valid: true,
        complete: true,
        facts: vec![Fact { id: fact, value: U64(value) }],
    }
}
#[test]
fn missing_and_conflicting_sources_are_unknown() {
    let mut e = RuleEngine::new(inventory("target_unreachable", FactId::Reachable), 0).unwrap();
    assert_eq!(e.evaluate(0)[0].signal, Signal::Unknown);
    e.ingest(frame(FactId::Reachable, 1, 1), 0).unwrap();
    assert_eq!(e.evaluate(0)[0].signal, Signal::Good);
    assert!(e.ingest(frame(FactId::Reachable, 0, 1), 1).is_err());
    assert_eq!(e.evaluate(1)[0].signal, Signal::Unknown);
}
#[test]
fn cache_duplicates_do_not_renew_rule_quality() {
    let mut e = RuleEngine::new(inventory("target_unreachable", FactId::Reachable), 0).unwrap();
    let f = frame(FactId::Reachable, 1, 1);
    e.ingest(f.clone(), 0).unwrap();
    assert!(!e.ingest(f, 44_000).unwrap());
    assert_eq!(e.evaluate(45_001)[0].signal, Signal::Unknown);
}
#[test]
fn counter_rule_needs_baseline_and_does_not_recount() {
    let mut e =
        RuleEngine::new(inventory("pq_signing_failure", FactId::PqSigningFailures), 0).unwrap();
    e.ingest(frame(FactId::PqSigningFailures, 50, 1), 0).unwrap();
    assert_eq!(e.evaluate(0)[0].signal, Signal::Unknown);
    e.ingest(frame(FactId::PqSigningFailures, 51, 2), 5).unwrap();
    assert_eq!(e.evaluate(5)[0].signal, Signal::Bad);
    assert_eq!(e.evaluate(6)[0].signal, Signal::Bad);
    e.ingest(frame(FactId::PqSigningFailures, 51, 3), 10).unwrap();
    assert_eq!(e.evaluate(10)[0].signal, Signal::Good);
    let mut reset = frame(FactId::PqSigningFailures, 999, 4);
    reset.source_epoch = "s2".into();
    e.ingest(reset, 15).unwrap();
    assert_eq!(e.evaluate(15)[0].signal, Signal::Unknown);
}
#[test]
fn bad_hold_and_distinct_samples_are_both_required() {
    let mut i = inventory("rocksdb_write_stopped", FactId::RocksdbWriteStopped);
    i.targets[0].rules[0].pending_ms = U64(10);
    i.targets[0].rules[0].minimum_bad_samples = 2;
    let mut e = RuleEngine::new(i, 0).unwrap();
    e.ingest(frame(FactId::RocksdbWriteStopped, 1, 1), 0).unwrap();
    assert_eq!(e.evaluate(0)[0].signal, Signal::Unknown);
    assert_eq!(e.evaluate(30)[0].signal, Signal::Unknown);
    e.ingest(frame(FactId::RocksdbWriteStopped, 1, 2), 35).unwrap();
    assert_eq!(e.evaluate(35)[0].signal, Signal::Bad);
}
#[test]
fn telemetry_inventory_detects_never_seen_source() {
    let mut i = inventory("telemetry_unavailable", FactId::Reachable);
    i.targets[0].rules[0].source = "inventory".into();
    i.targets[0].rules[0].pending_ms = U64(45_000);
    let mut e = RuleEngine::new(i, 0).unwrap();
    assert_eq!(e.evaluate(0)[0].signal, Signal::Unknown);
    assert_eq!(e.evaluate(45_000)[0].signal, Signal::Bad);
    e.ingest(frame(FactId::Reachable, 1, 1), 45_001).unwrap();
    let r = e.evaluate(45_001);
    assert_eq!(r[0].signal, Signal::Good);
    assert_eq!(r[0].samples.len(), 1);
}
#[test]
fn facts_cannot_escape_catalog_or_network() {
    let mut e = RuleEngine::new(inventory("target_unreachable", FactId::Reachable), 0).unwrap();
    let mut f = frame(FactId::Reachable, 1, 1);
    f.network_id = "b".repeat(64);
    assert!(e.ingest(f, 0).is_err());
    assert!(e.ingest(frame(FactId::PqSigningFailures, 1, 1), 0).is_err());
    assert!(e.ingest(frame(FactId::Reachable, 2, 1), 0).is_err());
    let mut empty = frame(FactId::Reachable, 1, 1);
    empty.facts.clear();
    assert!(e.ingest(empty, 0).is_err());
}
#[test]
fn retired_heartbeat_and_repeats_cannot_extend_deadlines() {
    let mut p = EpochDeadman::new(0, 45_000).unwrap();
    assert!(p.receive(0, "p1", 100).unwrap());
    assert!(p.receive(10, "p2", 1).unwrap());
    assert!(p.receive(20, "p1", 101).is_err());
    assert!(!p.receive(44_000, "p2", 1).unwrap());
    assert!(p.unavailable(45_010));
    let mut pipeline = EpochDeadman::new(0, 100_000).unwrap();
    pipeline.receive(0, "m", 1).unwrap();
    assert!(!pipeline.receive(90_000, "m", 1).unwrap());
    assert!(pipeline.unavailable(100_000));
}
#[test]
fn scalar_rules_use_only_their_frozen_facts() {
    for (rule, fact, value) in [
        ("initialization_stalled", FactId::InitializationPendingMs, 11),
        ("local_chain_stalled", FactId::ChainProgressAgeMs, 11),
        ("applied_served_gap", FactId::AppliedServedGap, 11),
        ("key_block_stale", FactId::KeyBlockAgeMs, 11),
        ("storage_space_low", FactId::DiskUsedPermille, 11),
        ("state_gc_lag", FactId::StateGcLagBlocks, 11),
        ("local_action_overdue", FactId::ActionOldestMs, 11),
        ("queue_stall", FactId::QueueOldestMs, 11),
        ("session_stop_pending", FactId::SessionStopPendingMs, 11),
        ("memory_growth_unexplained", FactId::UnexplainedMemoryBytes, 11),
        ("quic_pressure", FactId::QuicBacklogBytes, 11),
        ("observer_disagreement", FactId::ObserverDisagreement, 1),
        ("monitoring_unavailable", FactId::MonitorAvailable, 0),
        ("ai_unavailable", FactId::AiAvailable, 0),
    ] {
        let mut e = RuleEngine::new(inventory(rule, fact), 0).unwrap();
        e.ingest(frame(fact, value, 1), 0).unwrap();
        assert_eq!(e.evaluate(0)[0].signal, Signal::Bad, "{rule}");
    }
}

#[test]
fn rules_per_target_bound_follows_the_catalog() {
    // Every rule id the engine defines must fit one target at once.
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../../contracts/rule-manifest.json")).unwrap();
    let catalog = manifest["rules"].as_array().unwrap().len();
    assert_eq!(
        tos_health_core::rules::MAX_RULES_PER_TARGET,
        catalog,
        "bound must track the 22-rule catalog"
    );
}
