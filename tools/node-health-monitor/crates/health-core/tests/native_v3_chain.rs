use tos_health_core::native::{canonical_hash, parse_native, NativeRecord};

fn fixture() -> serde_json::Value {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/native-core.json")).unwrap();
    value["source_version"] = "native-core-v3".into();
    value["coverage"]["sampling_policy"] = "native-core-v3-chain-partial".into();
    value["coverage"]["missing_fields"] =
        serde_json::json!(["local_duties", "queue_state", "storage_state"]);
    value["payload"]["consensus"] =
        serde_json::from_str(include_str!("fixtures/consensus-v2.synthetic.json")).unwrap();
    let block = |point: &str, seqno| {
        serde_json::json!({
            "file_hash": "1".repeat(64), "kind": "block", "network_id": "a".repeat(64),
            "point": point, "root_hash": "2".repeat(64), "scope_id": "masterchain",
            "seqno": seqno, "shard": "9223372036854775808", "workchain": -1
        })
    };
    value["payload"]["chain"] = serde_json::json!({
        "applied": block("applied", 17), "served": block("served", 16),
        "applied_advanced_unix_seconds": "1790668064",
        "observed_unix_seconds": "1790668065"
    });
    value["quality"]["instrumentation_complete"] = false.into();
    rehash(&mut value);
    value
}
fn rehash(value: &mut serde_json::Value) {
    value["content_hash"] = canonical_hash(&value["payload"]).unwrap().into();
}
fn accepts(value: &serde_json::Value) -> bool {
    let bytes = serde_json::to_vec(value).unwrap();
    let Ok(NativeRecord::V3(v)) = parse_native(&bytes) else { return false };
    v.validate().is_ok()
}
#[test]
fn exact_chain_identity_and_event_time_fail_closed() {
    let value = fixture();
    assert!(accepts(&value));
    for (path, replacement) in [
        ("point", serde_json::json!("finalized")),
        ("scope_id", serde_json::json!("shard")),
        ("network_id", serde_json::json!("b".repeat(64))),
        ("root_hash", serde_json::json!("g".repeat(64))),
        ("shard", serde_json::json!("1")),
    ] {
        let mut wrong = value.clone();
        wrong["payload"]["chain"]["applied"][path] = replacement;
        rehash(&mut wrong);
        assert!(!accepts(&wrong), "accepted wrong {path}");
    }
    let mut future = value.clone();
    future["payload"]["chain"]["observed_unix_seconds"] = "1790668068".into();
    rehash(&mut future);
    assert!(!accepts(&future));
    let mut stale = value.clone();
    stale["payload"]["chain"]["applied_advanced_unix_seconds"] = "1790668030".into();
    rehash(&mut stale);
    assert!(!accepts(&stale));
    let mut unknown = value.clone();
    unknown["payload"]["chain"]["applied_advanced_unix_seconds"] = "0".into();
    rehash(&mut unknown);
    assert!(!accepts(&unknown));
    let mut reversed = value.clone();
    reversed["payload"]["chain"]["served"]["seqno"] = 18.into();
    rehash(&mut reversed);
    assert!(!accepts(&reversed));
    let mut marked_missing = value.clone();
    marked_missing["coverage"]["missing_fields"] = serde_json::json!(["chain_anchors"]);
    assert!(!accepts(&marked_missing));
}

#[test]
fn key_block_anchor_is_optional_bounded_and_yields_an_age_fact() {
    use tos_health_core::native_facts::key_block_age_ms;
    let parse = |value: &serde_json::Value| parse_native(&serde_json::to_vec(value).unwrap());
    // Publishers before the key block anchor: accepted, no fact, never zero.
    let value = fixture();
    assert!(accepts(&value));
    assert_eq!(key_block_age_ms(&parse(&value).unwrap()), None);
    // A null key block (none resolved yet) is accepted and yields no fact.
    let mut none = value.clone();
    none["payload"]["chain"]["key_block"] = serde_json::Value::Null;
    rehash(&mut none);
    assert!(accepts(&none));
    assert_eq!(key_block_age_ms(&parse(&none).unwrap()), None);
    // A key block 65 s before the observation: age 65,000 ms.
    let mut keyed = value.clone();
    keyed["payload"]["chain"]["key_block"] =
        serde_json::json!({"seqno": 12, "unix_seconds": "1790668000"});
    rehash(&mut keyed);
    assert!(accepts(&keyed));
    assert_eq!(key_block_age_ms(&parse(&keyed).unwrap()), Some(65_000));
    // The zero state as the last key block is a truthful, large age.
    let mut genesis = value.clone();
    genesis["payload"]["chain"]["key_block"] =
        serde_json::json!({"seqno": 0, "unix_seconds": "1790600000"});
    rehash(&mut genesis);
    assert!(accepts(&genesis));
    assert_eq!(key_block_age_ms(&parse(&genesis).unwrap()), Some(68_065_000));
    // Malformed: a clock of zero, a clock after the observation, a seqno past the applied block.
    for (field, bad) in [
        ("unix_seconds", serde_json::json!("0")),
        ("unix_seconds", serde_json::json!("1790668066")),
        ("seqno", serde_json::json!(18)),
    ] {
        let mut wrong = keyed.clone();
        wrong["payload"]["chain"]["key_block"][field] = bad;
        rehash(&mut wrong);
        assert!(!accepts(&wrong), "{field}");
    }
    // Unknown fields inside the anchor are refused.
    let mut extra = keyed.clone();
    extra["payload"]["chain"]["key_block"]["root_hash"] = "3".repeat(64).into();
    rehash(&mut extra);
    assert!(!accepts(&extra));
}

fn node_state_value() -> serde_json::Value {
    serde_json::json!({
        "duties": {"leader_windows": {"assigned": "12", "started": "9", "superseded": "1", "suppressed_behind": "1"}, "member": true},
        "observed_unix_seconds": "1790668064",
        "queues": [
            {"depth": 3, "oldest_age_ms": "4500", "queue": "block_data_waiters"},
            {"depth": 0, "oldest_age_ms": "0", "queue": "shard_client_waiters"},
            {"depth": 1, "oldest_age_ms": "120000", "queue": "state_waiters"}
        ],
        "storage": {"db_free_bytes": "250000000000", "db_total_bytes": "1000000000000", "gc_seqno": 5, "persistent_state_seqno": 3}
    })
}

#[test]
fn node_state_is_optional_covered_and_yields_duty_queue_and_storage_facts() {
    use tos_health_core::native_facts::{duty_facts, queue_facts, storage_facts};
    use tos_health_core::rules::FactId;
    let parse = |value: &serde_json::Value| parse_native(&serde_json::to_vec(value).unwrap());
    let get = |facts: &[tos_health_core::rules::Fact], id: FactId| {
        facts.iter().find(|f| f.id == id).map(|f| f.value.0)
    };
    // Older publisher: no section, coverage still names the three fields, no facts.
    let value = fixture();
    assert!(accepts(&value));
    let record = parse(&value).unwrap();
    assert!(duty_facts(&record).is_none());
    assert!(queue_facts(&record).is_none());
    assert!(storage_facts(&record).is_none());
    // Null section (manager has not published yet): accepted, same coverage.
    let mut none = value.clone();
    none["payload"]["node_state"] = serde_json::Value::Null;
    rehash(&mut none);
    assert!(accepts(&none));
    // Full section: coverage becomes complete and the facts follow.
    let mut full = value.clone();
    full["payload"]["node_state"] = node_state_value();
    full["coverage"]["missing_fields"] = serde_json::json!([]);
    full["coverage"]["status"] = "complete".into();
    rehash(&mut full);
    assert!(accepts(&full));
    let record = parse(&full).unwrap();
    let duties = duty_facts(&record).unwrap();
    assert_eq!(get(&duties, FactId::DutyMember), Some(1));
    assert_eq!(get(&duties, FactId::DutyWindowsMissed), Some(1)); // 12 - 9 - 1 - 1
    let queues = queue_facts(&record).unwrap();
    assert_eq!(get(&queues, FactId::QueueDepth), Some(4));
    assert_eq!(get(&queues, FactId::QueueOldestMs), Some(120_000));
    let storage = storage_facts(&record).unwrap();
    assert_eq!(get(&storage, FactId::DiskUsedPermille), Some(750));
    assert_eq!(get(&storage, FactId::StateGcLagBlocks), Some(12)); // applied 17 - gc 5
                                                                   // A present section still marked missing, or a complete status with a
                                                                   // non-empty missing list, is a lying envelope.
    let mut lying = full.clone();
    lying["coverage"]["missing_fields"] =
        serde_json::json!(["local_duties", "queue_state", "storage_state"]);
    lying["coverage"]["status"] = "partial".into();
    assert!(!accepts(&lying));
    let mut half = full.clone();
    half["coverage"]["missing_fields"] = serde_json::json!(["queue_state"]);
    half["coverage"]["status"] = "complete".into();
    assert!(!accepts(&half));
    // Stale section, free space above total, a duplicate queue name, and more
    // ended windows than assigned are all refused.
    for (path, bad) in [
        ("observed_unix_seconds", serde_json::json!("1790668000")),
        (
            "storage",
            serde_json::json!({"db_free_bytes": "2", "db_total_bytes": "1", "gc_seqno": 5, "persistent_state_seqno": 3}),
        ),
        (
            "queues",
            serde_json::json!([{"depth": 1, "oldest_age_ms": "1", "queue": "a"}, {"depth": 1, "oldest_age_ms": "1", "queue": "a"}]),
        ),
        (
            "duties",
            serde_json::json!({"leader_windows": {"assigned": "1", "started": "1", "superseded": "1", "suppressed_behind": "0"}, "member": false}),
        ),
    ] {
        let mut wrong = full.clone();
        wrong["payload"]["node_state"][path] = bad;
        rehash(&mut wrong);
        assert!(!accepts(&wrong), "{path}");
    }
    // An unknown key inside the section is refused.
    let mut extra = full.clone();
    extra["payload"]["node_state"]["fd_count"] = 5.into();
    rehash(&mut extra);
    assert!(!accepts(&extra));
}
