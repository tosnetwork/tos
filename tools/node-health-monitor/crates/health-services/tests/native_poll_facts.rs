//! Secondary fact frames of the native poll: fixed gauge parsing and frame identity.
use tos_health_core::{native::parse_native, native_facts::NativeFactState, rules::FactId};
use tos_health_services::manager_poll::{
    native_fact_frame, quic_backlog_bytes, secondary_frame, stagger_ms, storage_write_stopped,
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
