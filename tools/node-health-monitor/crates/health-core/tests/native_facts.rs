//! Native fact derivation against real validator1/observer5 loopback samples.
use tos_health_core::{
    native::{parse_native, NativeRecord},
    native_facts::{derive, NativeFactState, CATALOG},
    rules::FactId,
    wire::U64,
};

fn fixture(name: &str) -> NativeRecord {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    parse_native(&std::fs::read(path).expect("fixture")).expect("valid native record")
}
fn value(facts: &[tos_health_core::rules::Fact], id: FactId) -> Option<u64> {
    facts.iter().find(|f| f.id == id).map(|f| f.value.0)
}
fn consensus_mut(record: &mut NativeRecord) -> &mut tos_health_core::consensus_v2::Consensus {
    match record {
        NativeRecord::V2(v) => v.payload.consensus.as_mut().expect("consensus"),
        _ => panic!("v2 fixture expected"),
    }
}

#[test]
fn real_validator_sample_yields_every_catalog_fact() {
    let record = fixture("native-core-v2.validator1.live.json");
    let mut state = NativeFactState::default();
    let derived = derive(&record, 1_000_000, &mut state).expect("derive");
    assert!(derived.complete, "missing: {:?}", derived.missing);
    assert_eq!(derived.facts.len(), CATALOG.len());
    for id in CATALOG {
        assert!(value(&derived.facts, id).is_some(), "{id:?} absent");
    }
    // The live validator had no local failures and no pending work.
    assert_eq!(value(&derived.facts, FactId::ActionFailures), Some(0));
    assert_eq!(value(&derived.facts, FactId::StorageAckFailures), Some(0));
    assert_eq!(value(&derived.facts, FactId::StorageUsable), Some(1));
    // The live sample carried one in-flight vote a few tens of ms old.
    let oldest = value(&derived.facts, FactId::ActionOldestMs).unwrap();
    assert!(oldest > 0 && oldest < 1_000, "oldest pending {oldest} ms");
    assert_eq!(value(&derived.facts, FactId::SessionStopPendingMs), Some(0));
    assert_eq!(value(&derived.facts, FactId::ChainProgressAgeMs), Some(0));
    // Legitimate refusals (duplicate_or_stale) are present in the sample but
    // must not be counted as failures.
    let refusals: u64 = consensus_refusals(&record);
    assert!(refusals > 0, "fixture should carry duplicate_or_stale refusals");
}
fn consensus_refusals(record: &NativeRecord) -> u64 {
    let NativeRecord::V2(v) = record else { panic!() };
    let c = v.payload.consensus.as_ref().unwrap();
    c.actions
        .iter()
        .filter_map(|a| match a {
            tos_health_core::consensus_v2::Action::NotarizeVote { live, .. } => {
                live.failures.get("duplicate_or_stale").map(|v| v.0)
            }
            _ => None,
        })
        .sum()
}

#[test]
fn finalized_slot_stall_ages_across_samples_and_resets_on_advance() {
    let record = fixture("native-core-v2.validator1.live.json");
    let mut state = NativeFactState::default();
    let first = derive(&record, 10_000, &mut state).unwrap();
    assert_eq!(value(&first.facts, FactId::ChainProgressAgeMs), Some(0));
    let same = derive(&record, 70_000, &mut state).unwrap();
    assert_eq!(value(&same.facts, FactId::ChainProgressAgeMs), Some(60_000));
    let mut advanced = record.clone();
    for c in &mut consensus_mut(&mut advanced).contexts {
        if let Some(slot) = c.last_finalized_slot.as_mut() {
            *slot += 1;
        }
    }
    let after = derive(&advanced, 85_000, &mut state).unwrap();
    assert_eq!(value(&after.facts, FactId::ChainProgressAgeMs), Some(0));
    // A slot that goes backwards is not progress.
    let regressed = derive(&record, 100_000, &mut state).unwrap();
    assert_eq!(value(&regressed.facts, FactId::ChainProgressAgeMs), Some(15_000));
}

#[test]
fn epoch_change_resets_state() {
    let record = fixture("native-core-v2.validator1.live.json");
    let mut state = NativeFactState::default();
    derive(&record, 10_000, &mut state).unwrap();
    derive(&record, 70_000, &mut state).unwrap();
    let mut restarted = record.clone();
    if let NativeRecord::V2(v) = &mut restarted {
        v.process_epoch = "restarted-epoch".into();
    }
    let fresh = derive(&restarted, 80_000, &mut state).unwrap();
    assert_eq!(value(&fresh.facts, FactId::ChainProgressAgeMs), Some(0));
    assert_eq!(state.process_epoch, "restarted-epoch");
}

#[test]
fn local_failures_and_storage_counters_sum_only_execution_failures() {
    let mut record = fixture("native-core-v2.validator1.live.json");
    {
        let c = consensus_mut(&mut record);
        for a in &mut c.actions {
            if let tos_health_core::consensus_v2::Action::FinalizeVote { live, .. } = a {
                live.failures.insert("sign_backend".into(), U64(2));
                live.failures.insert("signed_storage".into(), U64(3));
                live.failures.insert("superseded".into(), U64(40));
                live.failures.insert("finality_behind".into(), U64(7));
            }
        }
    }
    let derived = derive(&record, 1, &mut NativeFactState::default()).unwrap();
    assert_eq!(value(&derived.facts, FactId::ActionFailures), Some(5));
    assert_eq!(value(&derived.facts, FactId::StorageAckFailures), Some(3));
}

#[test]
fn pending_age_and_stop_pending_are_reported() {
    let mut record = fixture("native-core-v2.validator1.live.json");
    {
        let c = consensus_mut(&mut record);
        if let tos_health_core::consensus_v2::Action::NotarizeVote { live, .. } = &mut c.actions[1]
        {
            live.pending = U64(2);
            live.oldest_age_ns = Some(U64(4_500_000_000));
        }
        c.sessions.stopping = U64(1);
    }
    let mut state = NativeFactState::default();
    let first = derive(&record, 1_000, &mut state).unwrap();
    assert_eq!(value(&first.facts, FactId::ActionOldestMs), Some(4_500));
    assert_eq!(value(&first.facts, FactId::SessionStopPendingMs), Some(0));
    let later = derive(&record, 31_000, &mut state).unwrap();
    assert_eq!(value(&later.facts, FactId::SessionStopPendingMs), Some(30_000));
    consensus_mut(&mut record).sessions.stopping = U64(0);
    let done = derive(&record, 32_000, &mut state).unwrap();
    assert_eq!(value(&done.facts, FactId::SessionStopPendingMs), Some(0));
}

#[test]
fn storage_unusable_when_votes_requested_without_any_commit_ack() {
    let mut record = fixture("native-core-v2.validator1.live.json");
    {
        let c = consensus_mut(&mut record);
        let cap = c.capabilities.get_mut("storage_commit_ack").unwrap();
        cap.supported = false;
        cap.enabled = false;
        cap.reason = Some("observation_incomplete".into());
    }
    let derived = derive(&record, 1, &mut NativeFactState::default()).unwrap();
    assert_eq!(value(&derived.facts, FactId::StorageUsable), Some(0));
}

#[test]
fn observer_without_sessions_is_incomplete_not_zero() {
    let record = fixture("native-core-v2.observer5.live.json");
    let derived = derive(&record, 1, &mut NativeFactState::default()).unwrap();
    assert!(!derived.complete);
    assert!(derived.missing.contains(&"no_masterchain_progress_source"));
    assert_eq!(value(&derived.facts, FactId::ChainProgressAgeMs), None);
    // Counters that do exist are still reported for the remaining rules.
    assert_eq!(value(&derived.facts, FactId::PqSigningFailures), Some(0));
    assert_eq!(value(&derived.facts, FactId::ActionFailures), Some(0));
}

#[test]
fn dropped_or_saturated_counters_are_not_complete() {
    let mut record = fixture("native-core-v2.validator1.live.json");
    if let NativeRecord::V2(v) = &mut record {
        v.quality.producer_dropped = U64(1);
    }
    let derived = derive(&record, 1, &mut NativeFactState::default()).unwrap();
    assert!(!derived.complete);
    let mut record = fixture("native-core-v2.validator1.live.json");
    consensus_mut(&mut record)
        .incomplete_reasons
        .insert(0, tos_health_core::consensus_v2::IncompleteReason::CounterSaturation);
    let derived = derive(&record, 1, &mut NativeFactState::default()).unwrap();
    assert!(!derived.complete);
    // Capability gaps alone (scope/lifecycle, present in the live sample) keep
    // the counters complete.
    let live = fixture("native-core-v2.validator1.live.json");
    assert!(derive(&live, 1, &mut NativeFactState::default()).unwrap().complete);
}
