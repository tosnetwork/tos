//! Secondary fact frames of the native poll: fixed gauge parsing and frame identity.
use sha2::{Digest, Sha256};
use tos_health_core::{
    native::{canonical_hash, parse_native, NativeEnvelope, NativeRecord},
    native_facts::NativeFactState,
    rules::FactId,
    wire::U64,
};
use tos_health_services::manager_poll::{
    native_fact_frame, paired_gauge_facts, quic_backlog_bytes, secondary_frame, stagger_ms,
    storage_write_stopped,
};

const METRICS: &str = "# TYPE tos_quic_summary_unsent_bytes gauge\n\
tos_quic_summary_unsent_bytes 1024\n\
tos_quic_summary_unacked_bytes 2048\n\
tos_quic_summary_conns 12\n\
tos_quic_summary_mean_rtt 173540.08\n";

#[test]
fn quic_backlog_is_the_sum_of_two_exact_gauges_or_absent() {
    assert_eq!(quic_backlog_bytes(METRICS), Some(3072));
    assert_eq!(quic_backlog_bytes("tos_quic_summary_unsent_bytes 5\n"), None);
    assert_eq!(
        quic_backlog_bytes("tos_quic_summary_unsent_bytes x\ntos_quic_summary_unacked_bytes 1\n"),
        None
    );
    assert_eq!(
        quic_backlog_bytes("tos_quic_summary_unsent_bytes -1\ntos_quic_summary_unacked_bytes 0\n"),
        None
    );
    assert_eq!(
        quic_backlog_bytes(
            "tos_quic_summary_unsent_bytes_total 9\ntos_quic_summary_unacked_bytes 1\n"
        ),
        None
    );
    assert_eq!(quic_backlog_bytes(""), None);
}

#[test]
fn secondary_frames_keep_the_native_identity_and_carry_one_fact() {
    let path = format!(
        "{}/../health-core/tests/fixtures/native-core-v2.validator1.live.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let record = parse_native(&std::fs::read(path).unwrap()).unwrap();
    let mut state = NativeFactState::default();
    let native = native_fact_frame(&record, 3, &mut state, "run-a").unwrap();
    assert_eq!(native.facts.len(), 8);
    assert_eq!(native.source_id, "native_facts");
    assert!(native.source_epoch.ends_with(":facts-v2:run-a"));
    assert!(native.source_epoch.len() <= 128);
    // A second deriver run over the same archived generation is a new source
    // epoch, so it can never conflict with the first run's frames.
    let again = native_fact_frame(&record, 3, &mut NativeFactState::default(), "run-b").unwrap();
    assert_eq!(again.process_epoch, native.process_epoch);
    assert_eq!(again.generation, native.generation);
    assert_ne!(again.source_epoch, native.source_epoch);
    let run = tos_health_services::manager_poll::derivation_run_id();
    assert!(run.len() <= 32 && run.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    let diagnostic = secondary_frame(&native, "diagnostic", FactId::DiagnosticDrops, 0);
    assert_eq!(diagnostic.source_id, "diagnostic");
    assert_eq!(diagnostic.process_epoch, native.process_epoch);
    assert_eq!(diagnostic.generation, native.generation);
    assert_eq!(diagnostic.facts.len(), 1);
    assert!(diagnostic.complete);
    assert_eq!(diagnostic.facts[0].id, FactId::DiagnosticDrops);
    diagnostic.validate().unwrap();
}

#[test]
fn stagger_offsets_are_deterministic_and_spread_the_local_nodes() {
    let nodes = ["validator1", "validator2", "validator3", "validator4", "observer5", "observer6"];
    let offsets: Vec<u64> = nodes.iter().map(|n| stagger_ms(n)).collect();
    assert!(offsets.iter().all(|o| *o < 12_000));
    assert_eq!(offsets, nodes.iter().map(|n| stagger_ms(n)).collect::<Vec<_>>());
    let mut sorted = offsets.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert!(sorted.len() >= 5, "offsets collide: {offsets:?}");
}

#[test]
fn storage_write_stopped_is_a_strict_zero_or_one_gauge_or_absent() {
    assert_eq!(storage_write_stopped("tos_health_storage_write_stopped 0\n"), Some(0));
    assert_eq!(storage_write_stopped("tos_health_storage_write_stopped 1\n"), Some(1));
    assert_eq!(storage_write_stopped("tos_health_storage_write_stopped 2\n"), None);
    assert_eq!(storage_write_stopped("tos_health_storage_write_stopped_total 5\n"), None);
    assert_eq!(storage_write_stopped(METRICS), None);
}

/// A native record whose payload commits to exactly `body`.
fn committed_to(body: &str) -> NativeRecord {
    let mut value: NativeEnvelope =
        serde_json::from_str(include_str!("../../health-core/tests/fixtures/native-core.json"))
            .unwrap();
    value.payload.openmetrics_hash = format!("{:x}", Sha256::digest(body.as_bytes()));
    value.payload.bytes = u32::try_from(body.len()).unwrap();
    value.content_hash = canonical_hash(&value.payload).unwrap();
    NativeRecord::V1(value)
}

#[test]
fn gauges_are_read_only_from_the_body_the_record_committed_to() {
    let sampled = format!("{METRICS}tos_health_storage_write_stopped 0\n# EOF\n");
    let record = committed_to(&sampled);
    let facts = paired_gauge_facts(&record, sampled.as_bytes()).unwrap();
    assert_eq!(facts.len(), 2);
    assert_eq!(facts[0].id, FactId::QuicBacklogBytes);
    assert_eq!(facts[0].value, U64(3072));
    assert_eq!(facts[1].id, FactId::RocksdbWriteStopped);
    assert_eq!(facts[1].value, U64(0));

    // The edge completed a newer generation between the snapshot and the
    // metrics request: its body must not travel under the sampled generation.
    let newer = sampled.replace("unsent_bytes 1024", "unsent_bytes 4096");
    assert_ne!(quic_backlog_bytes(&newer), quic_backlog_bytes(&sampled));
    let refused = paired_gauge_facts(&record, newer.as_bytes()).unwrap_err();
    assert!(refused.contains("pairing mismatch"), "{refused}");

    let mut invalid = sampled.into_bytes();
    invalid[0] = 0xff;
    assert_eq!(paired_gauge_facts(&record, &invalid).unwrap_err(), "edge metrics body not UTF-8");
}

#[test]
fn a_paired_body_without_catalog_gauges_yields_no_fact() {
    let body = include_str!("../../health-core/tests/fixtures/native-core.prom");
    let record =
        parse_native(include_bytes!("../../health-core/tests/fixtures/native-core.json")).unwrap();
    assert!(paired_gauge_facts(&record, body.as_bytes()).unwrap().is_empty());
}
