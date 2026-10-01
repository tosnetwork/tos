//! The deterministic rule engine driven by facts derived from real native
//! samples: a healthy validator stays good; a stalled chain, a local signing
//! failure and an unusable vote journal each open the intended rule.
use tos_health_core::{
    consensus_v2::Action,
    native::{parse_native, NativeRecord},
    native_facts::{derive, NativeFactState, CATALOG},
    rules::*,
    wire::U64,
};

const NET: &str = "b7fba4bda348db54717b7930da7b874289d88642a4d3990fb41d03e0cb006004";

fn fixture() -> NativeRecord {
    let path = format!(
        "{}/tests/fixtures/native-core-v2.validator1.live.json",
        env!("CARGO_MANIFEST_DIR")
    );
    parse_native(&std::fs::read(path).expect("fixture")).expect("valid record")
}
fn rule(id: &str, threshold: u64, pending_ms: u64, minimum_bad_samples: u32) -> RuleSpec {
    RuleSpec {
        id: id.into(),
        source: "native_core".into(),
        threshold: U64(threshold),
        pending_ms: U64(pending_ms),
        recovery_ms: U64(60_000),
        minimum_bad_samples,
        severity: "critical".into(),
    }
}
fn inventory() -> RuleInventory {
    RuleInventory {
        schema_version: 1,
        revision: "native-facts-test-1".into(),
        network_id: NET.into(),
        targets: vec![Target {
            node: "validator1".into(),
            scope: "node".into(),
            sources: vec![SourceSpec {
                id: "native_core".into(),
                ttl_ms: U64(60_000),
                facts: CATALOG.to_vec(),
            }],
            rules: vec![
                rule("local_chain_stalled", 90_000, 30_000, 2),
                rule("pq_signing_failure", 0, 0, 1),
                rule("local_action_failure", 0, 0, 1),
                rule("storage_ack_failure", 0, 0, 1),
                rule("local_action_overdue", 10_000, 30_000, 2),
                rule("session_stop_pending", 120_000, 30_000, 2),
            ],
        }],
    }
}
fn frame(
    record: &NativeRecord,
    observed_ms: u64,
    generation: u64,
    state: &mut NativeFactState,
) -> FactFrame {
    let derived = derive(record, observed_ms, state).unwrap();
    FactFrame {
        schema_version: 1,
        network_id: NET.into(),
        node_id: "validator1".into(),
        scope_id: "node".into(),
        source_id: "native_core".into(),
        process_epoch: record.process_epoch().into(),
        source_epoch: record.process_epoch().into(),
        generation: U64(generation),
        source_age_ms: U64(0),
        request_duration_ms: U64(0),
        observed_at: "2026-09-30T00:00:00Z".into(),
        clock_valid: true,
        complete: derived.complete,
        facts: derived.facts,
    }
}
fn signals(engine: &mut RuleEngine, now: u64) -> Vec<(String, Signal)> {
    engine.evaluate(now).into_iter().map(|r| (r.rule, r.signal)).collect()
}
fn signal(list: &[(String, Signal)], id: &str) -> Signal {
    list.iter().find(|(r, _)| r == id).map(|(_, s)| *s).expect("rule present")
}
fn advance(record: &mut NativeRecord) {
    if let NativeRecord::V2(v) = record {
        for c in &mut v.payload.consensus.as_mut().unwrap().contexts {
            if let Some(s) = c.last_finalized_slot.as_mut() {
                *s += 1;
            }
        }
    }
}
fn finalize_live(record: &mut NativeRecord) -> &mut tos_health_core::consensus_v2::Live {
    let NativeRecord::V2(v) = record else { panic!() };
    match &mut v.payload.consensus.as_mut().unwrap().actions[2] {
        Action::FinalizeVote { live, .. } => live,
        _ => panic!("finalize row"),
    }
}

#[test]
fn healthy_validator_sample_evaluates_every_native_rule_good() {
    let mut engine = RuleEngine::new(inventory(), 0).unwrap();
    let mut state = NativeFactState::default();
    let mut record = fixture();
    // Two consecutive advancing samples 15 s apart; the engine evaluates
    // after every sample as the running service does.
    engine.ingest(frame(&record, 0, 1, &mut state), 0).unwrap();
    signals(&mut engine, 0);
    advance(&mut record);
    engine.ingest(frame(&record, 15_000, 2, &mut state), 15_000).unwrap();
    let out = signals(&mut engine, 15_000);
    for id in [
        "local_chain_stalled",
        "pq_signing_failure",
        "local_action_failure",
        "storage_ack_failure",
        "local_action_overdue",
        "session_stop_pending",
    ] {
        assert_eq!(signal(&out, id), Signal::Good, "{id}");
    }
}

#[test]
fn finalized_slot_stall_opens_local_chain_stalled_after_pending() {
    let mut engine = RuleEngine::new(inventory(), 0).unwrap();
    let mut state = NativeFactState::default();
    let record = fixture();
    let mut now = 0;
    let mut generation = 0;
    // Same finalized slot for 120 s: age exceeds the 90 s threshold at t=105 s.
    while now <= 150_000 {
        generation += 1;
        engine.ingest(frame(&record, now, generation, &mut state), now).unwrap();
        let s = signal(&signals(&mut engine, now), "local_chain_stalled");
        if now < 105_000 {
            assert_eq!(s, Signal::Good, "t={now}");
        } else if now >= 135_000 {
            // threshold crossed at 105 s, pending 30 s and two bad samples.
            assert_eq!(s, Signal::Bad, "t={now}");
        }
        now += 15_000;
    }
    // Progress resumes: the rule returns to good on the next distinct sample.
    let mut advanced = record.clone();
    advance(&mut advanced);
    generation += 1;
    engine.ingest(frame(&advanced, now, generation, &mut state), now).unwrap();
    assert_eq!(signal(&signals(&mut engine, now), "local_chain_stalled"), Signal::Good);
}

#[test]
fn signing_backend_failure_increase_opens_local_action_failure() {
    let mut engine = RuleEngine::new(inventory(), 0).unwrap();
    let mut state = NativeFactState::default();
    let mut record = fixture();
    engine.ingest(frame(&record, 0, 1, &mut state), 0).unwrap();
    signals(&mut engine, 0);
    advance(&mut record);
    engine.ingest(frame(&record, 15_000, 2, &mut state), 15_000).unwrap();
    assert_eq!(signal(&signals(&mut engine, 15_000), "local_action_failure"), Signal::Good);
    advance(&mut record);
    finalize_live(&mut record).failures.insert("sign_backend".into(), U64(1));
    engine.ingest(frame(&record, 30_000, 3, &mut state), 30_000).unwrap();
    let out = signals(&mut engine, 30_000);
    assert_eq!(signal(&out, "local_action_failure"), Signal::Bad);
    // A legitimate refusal never counts.
    assert_eq!(signal(&out, "storage_ack_failure"), Signal::Good);
    advance(&mut record);
    finalize_live(&mut record).failures.insert("superseded".into(), U64(500));
    engine.ingest(frame(&record, 45_000, 4, &mut state), 45_000).unwrap();
    assert_eq!(signal(&signals(&mut engine, 45_000), "local_action_failure"), Signal::Good);
}

#[test]
fn unusable_vote_journal_opens_storage_ack_failure_immediately() {
    let mut engine = RuleEngine::new(inventory(), 0).unwrap();
    let mut state = NativeFactState::default();
    let mut record = fixture();
    engine.ingest(frame(&record, 0, 1, &mut state), 0).unwrap();
    signals(&mut engine, 0);
    advance(&mut record);
    if let NativeRecord::V2(v) = &mut record {
        let cap = v
            .payload
            .consensus
            .as_mut()
            .unwrap()
            .capabilities
            .get_mut("storage_commit_ack")
            .unwrap();
        cap.supported = false;
        cap.enabled = false;
        cap.reason = Some("observation_incomplete".into());
    }
    // Votes were requested since the previous sample and none was committed.
    let live = finalize_live(&mut record);
    let requested = live.phases.get("requested").unwrap().0;
    live.phases.insert("requested".into(), U64(requested + 3));
    engine.ingest(frame(&record, 15_000, 2, &mut state), 15_000).unwrap();
    assert_eq!(signal(&signals(&mut engine, 15_000), "storage_ack_failure"), Signal::Bad);
}

#[test]
fn incomplete_sample_leaves_native_rules_unknown_instead_of_good() {
    let mut engine = RuleEngine::new(inventory(), 0).unwrap();
    let mut state = NativeFactState::default();
    let mut record = fixture();
    if let NativeRecord::V2(v) = &mut record {
        v.quality.relay_dropped = U64(3);
    }
    engine.ingest(frame(&record, 0, 1, &mut state), 0).unwrap();
    let out = signals(&mut engine, 0);
    for (_, s) in &out {
        assert_eq!(*s, Signal::Unknown);
    }
}
