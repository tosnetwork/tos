use std::collections::BTreeMap;
use tos_health_core::{contracts::*, freshness::Freshness, health_state::*, wire::*};
#[test]
fn exact_uint64() {
    let v: U64 = serde_json::from_str("\"18446744073709551615\"").unwrap();
    assert_eq!(v.0, u64::MAX);
    assert_eq!(serde_json::to_string(&v).unwrap(), "\"18446744073709551615\"");
    for s in [
        "9007199254740993",
        "true",
        "1.0",
        "\"18446744073709551616\"",
        "\"01\"",
        "\"-1\"",
        "\"１\"",
        "\"\"",
    ] {
        assert!(serde_json::from_str::<U64>(s).is_err(), "{s}");
    }
}
#[test]
fn ipc_frozen_bytes() {
    let bytes = fixture_record().encode().unwrap();
    let frozen = include_str!("../../../tests/fixtures/diagnostic-v1.hex").trim();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, frozen);
    assert_eq!(DiagnosticRecord::decode(&bytes).unwrap(), fixture_record());
}
#[test]
fn ipc_rejects_malformed_header() {
    let bytes = fixture_record().encode().unwrap();
    for (offset, value) in
        [(0, 0), (4, 2), (6, 63), (8, 65), (10, 2), (12, 8), (48, 1), (56, 3), (58, 2), (60, 1)]
    {
        let mut b = bytes.clone();
        b[offset] = value;
        assert!(DiagnosticRecord::decode(&b).is_err(), "offset {offset}");
    }
    assert!(DiagnosticRecord::decode(&bytes[..63]).is_err());
    assert!(DiagnosticRecord::decode(&vec![0; 513]).is_err());
}
#[test]
fn freshness_same_generation_does_not_renew() {
    let mut f = Freshness::default();
    let h = "a".repeat(64);
    assert!(f.observe("p", "s", 1, &h, 0, 0, 2).unwrap());
    assert!(!f.observe("p", "s", 1, &h, 29, 0, 0).unwrap());
    assert!(!f.usable(29, 30));
    assert_eq!(f.distinct, 1);
}
#[test]
fn freshness_conflict_quarantines_epoch() {
    let mut f = Freshness::default();
    f.observe("p", "s", 1, &"a".repeat(64), 0, 0, 0).unwrap();
    assert_eq!(f.observe("p", "s", 1, &"b".repeat(64), 1, 0, 0), Err("SOURCE_CONFLICT"));
    f.observe("p", "s", 2, &"c".repeat(64), 2, 0, 0).unwrap();
    assert!(!f.usable(2, 30));
    f.observe("p", "s2", 1, &"a".repeat(64), 3, 0, 0).unwrap();
    assert!(f.usable(3, 30));
    assert!(f.observe("p", "s", 3, &"a".repeat(64), 4, 0, 0).is_err());
}
#[test]
fn freshness_regression_and_overflow() {
    let mut f = Freshness::default();
    f.observe("p", "s", 9, &"a".repeat(64), 1, 0, 0).unwrap();
    assert!(!f.observe("p", "s", 8, &"b".repeat(64), 29, 0, 0).unwrap());
    assert!(!f.usable(32, 30));
    assert!(f.observe("p", "s", 10, &"a".repeat(64), 32, u64::MAX, 1).is_err());
}
fn samples(epoch: &str, gen: u64) -> BTreeMap<String, Sample> {
    BTreeMap::from([(
        "native".into(),
        Sample { process_epoch: "p".into(), source_epoch: epoch.into(), generation: U64(gen) },
    )])
}
fn good(i: &mut HealthState, t: u64, e: &str, g: u64) {
    i.good(t, &["native".into()], samples(e, g), 60_000, 2).unwrap();
}
#[test]
fn recovery_requires_distinct_good_and_hold() {
    let mut i = HealthState::default();
    i.bad("critical").unwrap();
    i.unknown();
    assert_eq!(i.state, State::SuspendedUnknown);
    assert_eq!(i.severity, "critical");
    good(&mut i, 100_000, "s", 2);
    good(&mut i, 170_000, "s", 2);
    assert!(i.active());
    good(&mut i, 180_000, "s", 3);
    assert_eq!(i.state, State::ClosedRecovered);
    i.bad("critical").unwrap();
    assert_eq!(i.episode.0, 2);
}
#[test]
fn unknown_epoch_and_restart_reset_recovery() {
    let mut i = HealthState::default();
    i.bad("warning").unwrap();
    good(&mut i, 10_000, "s", 2);
    i.unknown();
    good(&mut i, 80_000, "s", 3);
    assert!(i.active());
    good(&mut i, 140_000, "s2", 9);
    assert!(i.active());
    i.acknowledge();
    assert!(i.active());
    i.after_restart();
    good(&mut i, 1, "s2", 10);
    assert!(i.active());
    good(&mut i, 60_001, "s2", 11);
    assert!(!i.active());
}
#[test]
fn multi_source_recovery_requires_every_source() {
    let mut i = HealthState::default();
    i.bad("critical").unwrap();
    let required = vec!["native".into(), "host".into()];
    i.good(0, &required, samples("s", 1), 60, 2).unwrap();
    assert_eq!(i.state, State::SuspendedUnknown);
    let mut s = samples("s", 2);
    s.insert(
        "host".into(),
        Sample { process_epoch: "p".into(), source_epoch: "s".into(), generation: U64(1) },
    );
    i.good(10, &required, s.clone(), 60, 2).unwrap();
    s.get_mut("native").unwrap().generation = U64(3);
    i.good(80, &required, s.clone(), 60, 2).unwrap();
    assert!(i.active());
    s.get_mut("host").unwrap().generation = U64(2);
    i.good(90, &required, s, 60, 2).unwrap();
    assert!(!i.active());
}
#[test]
fn bad_after_unknown_preserves_episode() {
    let mut i = HealthState::default();
    i.bad("critical").unwrap();
    i.unknown();
    i.bad("critical").unwrap();
    assert_eq!(i.episode.0, 1);
}
#[test]
fn sparse_histograms_count_all_series() {
    let mut f = MetricFamily {
        name: "stage".into(),
        semantic_type: "histogram".into(),
        label_names: vec!["action".into()],
        allowed_tuples: (0..4).map(|i| vec![i.to_string()]).collect(),
        finite_buckets: (1..=12).map(f64::from).collect(),
        bytes_per_tuple: 128,
    };
    assert_eq!(metric_capacity(&[f.clone()]).unwrap(), (60, 512));
    f.allowed_tuples = (0..137).map(|i| vec![i.to_string()]).collect();
    assert_eq!(metric_capacity(&[f]), Err("core capacity exceeded"));
}
#[test]
fn vote_trace_and_normal_return_are_not_success() {
    for action in ["notarize_vote", "finalize_vote", "skip_vote"] {
        let mut v = VoteStages::new(action, false).unwrap();
        assert!(!v.enqueued());
        v.advance(1).unwrap();
        v.fail().unwrap();
        assert!(!v.enqueued());
        assert!(v.fail().is_err());
    }
}
#[test]
fn vote_order_and_replay_are_preserved() {
    assert!(VoteStages::new("proposal", false).is_err());
    let mut v = VoteStages::new("skip_vote", false).unwrap();
    assert!(v.advance(2).is_err());
    for n in 1..=5 {
        v.advance(n).unwrap();
        assert_eq!(v.enqueued(), n == 5);
    }
    let mut r = VoteStages::new("notarize_vote", true).unwrap();
    for n in 1..5 {
        r.advance(n).unwrap();
    }
    assert!(r.advance(5).is_err());
    assert!(!r.enqueued());
}
fn batch() -> serde_json::Value {
    serde_json::json!({"schema_version":1,"node_id":"v1","edge_epoch":"e","process_epoch":"p","source_id":"diagnostic_fixture","batch_id":"a".repeat(64),"records":[{"sequence":"9","monotonic_ns":"10","observed_at":null,"record_type":1,"payload":"0102"}],"quality":{"dropped":"0","gaps":false}})
}
#[test]
fn diagnostic_limits_are_independent() {
    let mut b = batch();
    assert!(DiagnosticBatch::decode(&serde_json::to_vec(&b).unwrap()).is_ok());
    b["records"][0]["payload"] = serde_json::json!("00".repeat(65_537));
    let wire = serde_json::to_vec(&b).unwrap();
    assert!(wire.len() < 262_144);
    assert_eq!(DiagnosticBatch::decode(&wire).unwrap_err(), "decoded payload limit");
    let mut wire = serde_json::to_vec(&batch()).unwrap();
    wire.resize(262_145, b' ');
    assert_eq!(DiagnosticBatch::decode(&wire).unwrap_err(), "JSON body limit");
    let mut b = batch();
    b["records"][0]["unknown"] = true.into();
    assert!(DiagnosticBatch::decode(&serde_json::to_vec(&b).unwrap()).is_err());
}
#[test]
fn production_placeholders_and_claims_do_not_pass() {
    let production = include_str!("../../../config/production.example.yaml");
    let mut config: DeploymentConfig = serde_json::from_str(production).unwrap();
    config.validate().unwrap();
    assert!(config.production_blockers().contains(&"performance"));
    assert!(config.production_blockers().contains(&"contiguous_work"));
    config.network_id = Some("a".repeat(64));
    config.binary_digest = Some("a".repeat(64));
    config.performance_digest = Some("a".repeat(64));
    config.mtls_digest = Some("a".repeat(64));
    config.receiver_digest = Some("a".repeat(64));
    config.effective_resource_digest = Some("a".repeat(64));
    config.failure_domains =
        Some(FailureDomains { validator: "v".into(), monitor: "m".into(), watchdog: "o".into() });
    config.max_contiguous_monitor_work_us = Some(U64(1000));
    assert_eq!(config.production_blockers(), vec!["runtime_acceptance_not_verified"]);
    let mut value: serde_json::Value = serde_json::from_str(production).unwrap();
    value["force"] = true.into();
    assert!(serde_json::from_value::<DeploymentConfig>(value).is_err());
}
#[test]
fn block_shard_is_unsigned_and_hashes_are_canonical() {
    use tos_health_core::observer::*;
    let mut b = BlockIdentity {
        genesis: "a".repeat(64),
        workchain: -1,
        shard: "18446744073709551615".into(),
        seqno: 5,
        root_hash: "b".repeat(64),
        file_hash: "c".repeat(64),
    };
    assert!(b.valid());
    b.shard = "-9223372036854775808".into();
    assert!(!b.valid());
    b.shard = "01".into();
    assert!(!b.valid());
    b.shard = "0".into();
    b.root_hash = "A".repeat(64);
    assert!(!b.valid());
}
