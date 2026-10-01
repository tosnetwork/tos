use serde_json::{json, Value};
use std::collections::BTreeSet;
use tos_health_core::{
    broker::*, duty::*, evidence::*, guard::*, incident::*, observer::*, query::*, source::*,
};
fn quality(at: i64) -> SourceQuality {
    SourceQuality {
        availability: Availability::Available,
        coverage: Coverage::Complete,
        observed_at_ms: Some(at),
        last_success_at_ms: Some(at),
        clock_valid: true,
        process_epoch: "boot:12:400".into(),
        source_sequence: "1".into(),
    }
}
fn evidence(at: i64) -> Evidence {
    Evidence {
        node_id: "v1".into(),
        scope_id: "node".into(),
        source_id: "collector".into(),
        source_record_id: format!("sample-{at}"),
        process_epoch: "boot:12:400".into(),
        observed_at_ms: at,
        received_at_ms: at,
        quality: quality(at),
        payload: json!({
            "component":"process",
            "source_version":"synthetic-core-v1",
            "evidence_kind":"observation",
            "contract_quality":{"instrumentation_complete":true,"producer_dropped":"0","relay_dropped":"0","parse_errors":"0","shed_reason":null},
            "contract_coverage":{"status":"complete","missing_fields":[],"gaps":[],"sampling_policy":"synthetic unit fixture"},
            "contract_payload":{"kind":"process","pid":12,"rss_bytes":"18446744073709551615","anon_bytes":null,"file_bytes":null,"swap_bytes":null,"cpu_user_ticks":null,"cpu_system_ticks":null}
        }),
        redacted: true,
    }
}
fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|v| (*v).into()).collect()
}
fn grant(store: &EvidenceStore) -> Grant {
    Grant::new(
        "00000000-0000-4000-8000-000000000001".into(),
        "aura".into(),
        "a".repeat(64),
        &[7; 32],
        names(&["v1"]),
        names(&["node"]),
        0,
        60_000,
        0,
        store.watermark(),
    )
    .expect("valid grant fixture")
}
fn caps(run: &str) -> Value {
    json!({"run_id":run})
}
fn code(value: &Value) -> &str {
    value["error"]["code"].as_str().expect("specific error code")
}

#[test]
fn freshness_is_original_observation_not_poll_time() {
    let mut q = quality(1000);
    q.last_success_at_ms = Some(90_000);
    assert!(!q.usable(90_000, 30_000, true));
    q = quality(1000);
    assert!(q.usable(1500, 1000, true));
    assert!(!q.usable(999, 1000, true));
}
#[test]
fn absence_never_becomes_zero() {
    for a in [
        Availability::Disabled,
        Availability::Unsupported,
        Availability::Unauthorized,
        Availability::Error,
        Availability::Unknown,
    ] {
        let mut q = quality(1000);
        q.availability = a;
        assert!(!q.usable(1000, 30_000, false));
    }
}
#[test]
fn partial_cannot_prove_complete_duties() {
    let mut q = quality(1000);
    q.coverage = Coverage::Partial;
    assert!(!q.usable(1000, 30_000, true));
    assert!(q.usable(1000, 30_000, false));
}
#[test]
fn timeout_does_not_release_actual_work() {
    let mut s = SourceGate::new(15_000, 2000).expect("gate");
    assert_eq!(s.start(0), Admission::Started(1));
    assert!(s.expired(3000));
    assert_eq!(s.start(20_000), Admission::Busy);
    assert_eq!(s.complete(2, 20_000), Err("wrong work token"));
    assert!(s.inflight());
    assert_eq!(s.complete(1, 20_000), Ok(false));
    assert_eq!(s.start(20_001), Admission::Started(2));
}
#[test]
fn scheduler_skips_missed_ticks() {
    let mut s = SourceGate::new(15_000, 2000).expect("gate");
    assert_eq!(s.start(100_000), Admission::Started(1));
    assert_eq!(s.complete(1, 100_001), Ok(true));
    assert_eq!(s.start(100_002), Admission::NotDue);
    assert_eq!(s.start(115_000), Admission::Started(2));
}
#[test]
fn scheduler_rejects_overflow() {
    let mut s = SourceGate::new(15_000, 2000).expect("gate");
    assert_eq!(s.start(u64::MAX - 1), Admission::Exhausted);
    assert!(!s.inflight());
}
fn signals(now: u64) -> Signals {
    Signals {
        sampled_ms: now,
        valid: true,
        pressure: false,
        business_degraded: false,
        oom_or_reserve_exhausted: false,
    }
}
#[test]
fn guard_requires_continuous_recovery() {
    let mut g = Guard::default();
    assert_eq!(g.update(0, signals(0)), GuardState::Recovering);
    for now in (5_000..300_000).step_by(5_000) {
        g.update(now, signals(now));
    }
    assert_eq!(g.update(300_000, signals(300_000)), GuardState::Normal);
    let mut s = signals(300_001);
    s.oom_or_reserve_exhausted = true;
    assert_eq!(g.update(300_001, s), GuardState::Emergency);
    assert!(!g.allow_diagnostics());
    assert_eq!(g.update(300_002, signals(300_002)), GuardState::Recovering);
    let mut bad = signals(500_000);
    bad.valid = false;
    assert_eq!(g.update(500_000, bad), GuardState::Guarded);
    assert_eq!(g.update(500_001, signals(500_001)), GuardState::Recovering);
    for now in (505_001..800_000).step_by(5_000) {
        g.update(now, signals(now));
    }
    assert_eq!(g.update(800_000, signals(800_000)), GuardState::Recovering);
    assert_eq!(g.update(800_001, signals(800_001)), GuardState::Normal);
}
#[test]
fn stale_guard_signals_shed_work() {
    let mut g = Guard::default();
    g.update(0, signals(0));
    g.update(300_000, signals(300_000));
    assert_eq!(g.update(316_000, signals(300_000)), GuardState::Guarded);
}
#[test]
fn duties_deduplicate_retry_and_late_completion() {
    let mut d = DutyLedger::new(3);
    assert!(d.assign("round1:vote", 10, Some(20)));
    assert!(!d.assign("round1:vote", 11, Some(20)));
    assert!(d.start("round1:vote", 12));
    assert!(!d.start("round1:vote", 13));
    d.tick(21);
    d.tick(22);
    assert_eq!(d.overdue_total, 1);
    assert!(d.finish("round1:vote", Outcome::CompletedLate, false));
    assert!(!d.finish("round1:vote", Outcome::Failed, false));
    assert_eq!(d.pending(), 0);
    assert_eq!(d.closed_cohort(0, 20), Some((0, 1)));
}
#[test]
fn duties_do_not_hide_pending_or_incomplete_population() {
    let mut d = DutyLedger::new(1);
    d.assign("a", 10, Some(20));
    assert_eq!(d.closed_cohort(0, 20), None);
    assert!(!d.assign("b", 10, Some(20)));
    d.finish("a", Outcome::CompletedOnTime, false);
    assert_eq!(d.closed_cohort(0, 20), None);
    assert!(!d.complete);
}
#[test]
fn not_required_needs_protocol_evidence() {
    let mut d = DutyLedger::new(1);
    d.assign("a", 10, Some(20));
    assert!(!d.finish("a", Outcome::NotRequired, false));
    assert_eq!(d.pending(), 1);
    assert!(d.finish("a", Outcome::NotRequired, true));
}
fn block() -> BlockIdentity {
    BlockIdentity {
        genesis: "a".repeat(64),
        workchain: -1,
        shard: "9223372036854775808".into(),
        seqno: 8,
        root_hash: "b".repeat(64),
        file_hash: "c".repeat(64),
    }
}
#[test]
fn block_comparison_requires_full_identity() {
    let a = block();
    let mut b = a.clone();
    assert_eq!(compare(&a, &b), Comparison::Same);
    b.file_hash = "d".repeat(64);
    assert_eq!(compare(&a, &b), Comparison::ObservedBlockDisagreement);
    b.seqno = 9;
    assert_eq!(compare(&a, &b), Comparison::Incomparable);
    b.seqno = 8;
    b.genesis = "e".repeat(64);
    assert_eq!(compare(&a, &b), Comparison::Incomparable);
}
#[test]
fn repeated_deadman_does_not_keep_monitor_alive() {
    let mut d = Deadman::new(0);
    assert!(d.receive(1000, 1));
    assert!(!d.receive(40_000, 1));
    assert!(!d.unavailable(45_000));
    assert!(d.unavailable(46_000));
}
#[test]
fn missing_source_does_not_recover_incident() {
    let mut i = Incident::default();
    i.observe(Severity::Critical, true);
    i.observe(Severity::Healthy, false);
    assert!(i.active);
    assert_eq!(i.severity, Severity::Unknown);
    assert_eq!(i.last_known, Severity::Critical);
    i.observe(Severity::Healthy, true);
    assert!(!i.active);
}
#[test]
fn cancellation_keeps_model_resource_exclusive() {
    let mut b = Broker::default();
    assert_eq!(b.enqueue("one", 0), Enqueue::Queued);
    assert_eq!(b.enqueue("two", 0), Enqueue::Queued);
    assert!(b.start(1).is_some());
    assert!(b.cancel());
    assert!(b.start(2).is_none());
    assert!(!b.confirm_stopped("wrong"));
    assert!(b.start(3).is_none());
    assert!(b.confirm_stopped("one"));
    assert_eq!(b.start(4).expect("next").incident, "two");
}
#[test]
fn broker_expires_backlog_and_bounds_queue() {
    let mut b = Broker::default();
    for i in 0..32 {
        assert_eq!(b.enqueue(&format!("i{i}"), 0), Enqueue::Queued);
    }
    assert_eq!(b.enqueue("overflow", 0), Enqueue::Full);
    assert!(b.start(300_000).is_none());
}
#[test]
fn evidence_is_immutable_deduplicated_and_bounded() {
    let mut s = EvidenceStore::new(8000);
    let e = evidence(1000);
    let id = s.insert(e.clone()).expect("insert");
    assert_eq!(s.insert(e.clone()), Ok(id));
    assert_eq!(s.watermark(), 1);
    let mut different = e;
    different.payload = json!({"rss_bytes":"0"});
    assert_eq!(s.insert(different), Err("immutable evidence conflict"));
    for t in 2..100 {
        s.insert(evidence(t)).expect("bounded insertion");
        assert!(s.resident_bytes() <= 8000);
    }
    assert!(s.entries().count() < 99);
}
#[test]
fn query_authentication_and_run_are_independent() {
    let s = EvidenceStore::new(8000);
    let mut g = grant(&s);
    let metrics = BTreeSet::new();
    let q = QueryService { store: &s, metrics: &metrics };
    let run = g.run_id.clone();
    assert_eq!(code(&q.call(&mut g, "aura", &[8; 32], 1, TOOLS[0], caps(&run))), "UNAUTHENTICATED");
    assert_eq!(
        code(&q.call(&mut g, "other", &[7; 32], 1, TOOLS[0], caps(&run))),
        "UNAUTHENTICATED"
    );
    assert_eq!(code(&q.call(&mut g, "aura", &[7; 32], 1, TOOLS[0], caps("other"))), "OUT_OF_SCOPE");
    assert_eq!(q.call(&mut g, "aura", &[7; 32], 1, TOOLS[0], caps(&run))["status"], "ok");
}
#[test]
fn unknown_fields_and_force_refresh_are_rejected() {
    let s = EvidenceStore::new(8000);
    let mut g = grant(&s);
    let metrics = BTreeSet::new();
    let q = QueryService { store: &s, metrics: &metrics };
    let input = json!({"run_id":g.run_id,"force_refresh":true});
    assert_eq!(code(&q.call(&mut g, "aura", &[7; 32], 1, TOOLS[0], input)), "INVALID_ARGUMENT");
}
#[test]
fn failed_calls_consume_budget() {
    let s = EvidenceStore::new(8000);
    let mut g = grant(&s);
    let metrics = BTreeSet::new();
    let q = QueryService { store: &s, metrics: &metrics };
    let run = g.run_id.clone();
    for _ in 0..16 {
        assert_eq!(
            code(&q.call(&mut g, "aura", &[7; 32], 1, "not_a_tool", caps(&run))),
            "INVALID_ARGUMENT"
        );
    }
    assert_eq!(
        code(&q.call(&mut g, "aura", &[7; 32], 1, TOOLS[0], caps(&run))),
        "RUN_BUDGET_EXHAUSTED"
    );
}
#[test]
fn grants_expire_and_revoke() {
    let s = EvidenceStore::new(8000);
    let mut g = grant(&s);
    assert_eq!(g.authenticate("aura", &[7; 32], 200_000), Err("RUN_TOKEN_EXPIRED"));
    g.revoke();
    assert_eq!(g.authenticate("aura", &[7; 32], 1), Err("UNAUTHENTICATED"));
}
#[test]
fn snapshot_does_not_return_future_ingestion_or_another_node() {
    let mut s = EvidenceStore::new(80_000);
    s.insert(evidence(1000)).expect("old");
    let mut g = grant(&s);
    s.insert(evidence(2000)).expect("new");
    let metrics = BTreeSet::new();
    let q = QueryService { store: &s, metrics: &metrics };
    let input = json!({"run_id":g.run_id,"node_id":"v1","as_of":"1970-01-01T00:00:03Z","max_age_seconds":10,"components":["process"]});
    let result = q.call(&mut g, "aura", &[7; 32], 1, TOOLS[1], input.clone());
    assert_eq!(result["status"], "ok");
    assert_eq!(result["data"]["components"][0]["kind"], "process");
    assert_eq!(result["data"]["components"][0]["value"]["rss_bytes"], "18446744073709551615");
    assert_eq!(result["evidence"][0]["observed_at"], "1970-01-01T00:00:01.000Z");
    let mut denied = input;
    denied["node_id"] = json!("v2");
    assert_eq!(code(&q.call(&mut g, "aura", &[7; 32], 1, TOOLS[1], denied)), "OUT_OF_SCOPE");
}
#[test]
fn cache_miss_does_not_create_evidence() {
    let s = EvidenceStore::new(8000);
    let mut g = grant(&s);
    let metrics = BTreeSet::new();
    let q = QueryService { store: &s, metrics: &metrics };
    let input = json!({"run_id":g.run_id,"node_id":"v1","as_of":"1970-01-01T00:00:03Z","max_age_seconds":10,"components":["process"]});
    assert_eq!(code(&q.call(&mut g, "aura", &[7; 32], 1, TOOLS[1], input)), "CACHE_MISS");
    assert_eq!(s.watermark(), 0);
}

#[test]
fn event_cursor_is_stable_at_grant_watermark_and_bound_to_filters() {
    let mut store = EvidenceStore::new(80_000);
    for at in [3000, 1000, 2000] {
        let mut row = evidence(at);
        row.payload["evidence_kind"] = json!("event");
        row.payload["kind"] = json!("warning");
        row.payload["event"] = json!({"kind":"warning","stage":null,"reason":"synthetic","correlation_id":null,"excerpt":"synthetic"});
        row.payload["contract_payload"] =
            json!({"kind":"diagnostic_fixture","record_type":1,"payload":"0102"});
        store.insert(row).expect("event fixture");
    }
    let mut grant = grant(&store);
    let mut later = evidence(4000);
    later.payload["evidence_kind"] = json!("event");
    later.payload["kind"] = json!("warning");
    later.payload["event"] = json!({"kind":"warning","stage":null,"reason":"synthetic","correlation_id":null,"excerpt":"late"});
    later.payload["contract_payload"] =
        json!({"kind":"diagnostic_fixture","record_type":1,"payload":"0102"});
    store.insert(later).expect("later than W");
    let metrics = BTreeSet::new();
    let service = QueryService { store: &store, metrics: &metrics };
    let mut request = json!({"run_id":grant.run_id,"node_ids":["v1"],"scope_id":"node","start":"1970-01-01T00:00:00Z","end":"1970-01-01T00:01:00Z","sources":["collector"],"kinds":["warning"],"correlation_id":"","contains":"","limit":1,"cursor":""});
    let mut returned = Vec::new();
    for page in 0..3 {
        let reply = service.call(&mut grant, "aura", &[7; 32], 1 + page, TOOLS[3], request.clone());
        assert_eq!(reply["status"], "ok", "{reply}");
        assert_eq!(reply["data"]["events"].as_array().unwrap().len(), 1);
        returned.push(reply["evidence"][0]["source_record_id"].as_str().unwrap().to_owned());
        let next = reply["pagination"]["next_cursor"].as_str();
        assert_eq!(reply["pagination"]["truncated"], page < 2);
        assert_eq!(reply["pagination"]["scan_complete"], page == 2);
        if page == 0 {
            let mut changed = request.clone();
            changed["contains"] = json!("different");
            changed["cursor"] = json!(next.unwrap());
            assert_eq!(
                code(&service.call(&mut grant, "aura", &[7; 32], 1, TOOLS[3], changed)),
                "CURSOR_MISMATCH"
            );
            let mut tampered = request.clone();
            let mut cursor = next.unwrap().to_owned();
            let replacement = if cursor.ends_with('0') { "1" } else { "0" };
            cursor.replace_range(cursor.len() - 1.., replacement);
            tampered["cursor"] = json!(cursor);
            assert_eq!(
                code(&service.call(&mut grant, "aura", &[7; 32], 1, TOOLS[3], tampered)),
                "CURSOR_MISMATCH"
            );
            let mut other_run = grant.clone();
            other_run.run_id = "00000000-0000-4000-8000-000000000002".into();
            let mut replay = request.clone();
            replay["run_id"] = json!(other_run.run_id);
            replay["cursor"] = json!(next.unwrap());
            assert_eq!(
                code(&service.call(&mut other_run, "aura", &[7; 32], 1, TOOLS[3], replay)),
                "CURSOR_MISMATCH"
            );
            let mut other_principal = grant.clone();
            other_principal.principal = "other".into();
            let mut replay = request.clone();
            replay["cursor"] = json!(next.unwrap());
            assert_eq!(
                code(&service.call(&mut other_principal, "other", &[7; 32], 1, TOOLS[3], replay)),
                "CURSOR_MISMATCH"
            );
            let change = json!({"run_id":grant.run_id,"node_ids":["v1"],"start":"1970-01-01T00:00:00Z","end":"1970-01-01T00:01:00Z","kinds":["config"],"limit":1,"cursor":next.unwrap()});
            assert_eq!(
                code(&service.call(&mut grant, "aura", &[7; 32], 1, TOOLS[4], change)),
                "CURSOR_MISMATCH"
            );
        }
        if let Some(next) = next {
            request["cursor"] = json!(next);
        }
    }
    assert_eq!(returned, ["sample-3000", "sample-1000", "sample-2000"]);
    assert!(!returned.contains(&"sample-4000".to_owned()));
}

#[test]
fn change_history_uses_the_same_stable_cursor_without_time_sorting() {
    let mut store = EvidenceStore::new(80_000);
    for (at, id) in [(3000, "first"), (1000, "second")] {
        let mut row = evidence(at);
        row.source_id = "operator_change".into();
        row.source_record_id = id.into();
        row.payload["evidence_kind"] = json!("change");
        row.payload["kind"] = json!("config");
        row.payload["change"] = json!({"kind":"config","completed":null,"actor_alias":"operator","before":{"mode":"old"},"after":{"mode":"new"},"reason":"synthetic","trusted_origin":true});
        row.payload["contract_payload"] =
            json!({"kind":"diagnostic_fixture","record_type":1,"payload":"0102"});
        store.insert(row).unwrap();
    }
    let mut grant = grant(&store);
    let metrics = BTreeSet::new();
    let service = QueryService { store: &store, metrics: &metrics };
    let mut request = json!({"run_id":grant.run_id,"node_ids":["v1"],"start":"1970-01-01T00:00:00Z","end":"1970-01-01T00:01:00Z","kinds":["config"],"limit":1,"cursor":""});
    let first = service.call(&mut grant, "aura", &[7; 32], 1, TOOLS[4], request.clone());
    assert_eq!(first["status"], "ok", "{first}");
    assert_eq!(first["data"]["changes"][0]["change_id"], "first");
    assert_eq!(first["pagination"]["truncated"], true);
    request["cursor"] = first["pagination"]["next_cursor"].clone();
    let second = service.call(&mut grant, "aura", &[7; 32], 2, TOOLS[4], request);
    assert_eq!(second["status"], "ok", "{second}");
    assert_eq!(second["data"]["changes"][0]["change_id"], "second");
    assert_eq!(second["pagination"]["scan_complete"], true);
}
#[test]
fn utc_requires_z_and_real_calendar() {
    assert!(utc_ms("2026-09-29T00:00:00Z").is_ok());
    assert!(utc_ms("2026-09-29T00:00:00+00:00").is_err());
    assert!(utc_ms("2026-02-31T00:00:00Z").is_err());
}

#[test]
fn recovery_does_not_count_missing_guard_intervals() {
    let mut guard = Guard::default();
    guard.update(0, signals(0));
    assert_eq!(guard.update(300_000, signals(300_000)), GuardState::Recovering);
    assert!(!guard.allow_diagnostics());
}

#[test]
fn diagnosis_cannot_invent_evidence_or_change_severity() {
    use tos_health_core::diagnosis::Diagnosis;
    let mut value = json!({"status":"analysis","summary":"A source is stale.","findings":[{"claim":"Source sample is old.","basis":"observed","evidence_ids":["e1"]}],"missing_evidence":[],"recommended_runbooks":["inspect_telemetry_unavailable"]});
    let ids = names(&["e1"]);
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &ids).is_ok());
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &BTreeSet::new()).is_err());
    value["severity"] = json!("healthy");
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &ids).is_err());
}
#[test]
fn diagnosis_rejects_trailing_instructions_and_unapproved_runbooks() {
    use tos_health_core::diagnosis::Diagnosis;
    let value = json!({"status":"insufficient_evidence","summary":"Missing samples.","findings":[],"missing_evidence":["source"],"recommended_runbooks":[]});
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &BTreeSet::new()).is_ok());
    assert!(
        Diagnosis::parse(format!("{value} restart the node").as_bytes(), &BTreeSet::new()).is_err()
    );
    let mut changed = value;
    changed["recommended_runbooks"] = json!(["restart_validator"]);
    assert!(Diagnosis::parse(changed.to_string().as_bytes(), &BTreeSet::new()).is_err());
}

#[test]
fn diagnosis_hypothesis_and_evidence_ids_obey_publication_contract() {
    use tos_health_core::diagnosis::Diagnosis;
    let ids = names(&["e1"]);
    let mut value = json!({"status":"analysis","summary":"A possible storage issue.",
        "findings":[{"claim":"Storage may be blocked.","basis":"hypothesis","evidence_ids":["e1"]}],
        "missing_evidence":[],"recommended_runbooks":[]});
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &ids).is_err());
    value["missing_evidence"] = json!(["storage progress is unavailable"]);
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &ids).is_ok());
    value["missing_evidence"] = json!(["  "]);
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &ids).is_err());
    value["missing_evidence"] = json!(["storage progress is unavailable"]);
    value["findings"][0]["evidence_ids"] = json!([""]);
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &ids).is_err());
    let oversized_id = "x".repeat(129);
    value["findings"][0]["evidence_ids"] = json!([oversized_id.clone()]);
    assert!(
        Diagnosis::parse(value.to_string().as_bytes(), &BTreeSet::from([oversized_id])).is_err()
    );
    value["findings"][0]["evidence_ids"] = json!(["e1"]);
    value["summary"] = json!("界".repeat(2000));
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &ids).is_ok());
    value["summary"] = json!("界".repeat(2001));
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &ids).is_err());
    value["summary"] = json!("  ");
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &ids).is_err());
    value["summary"] = json!("A possible storage issue.");
    value["findings"][0]["claim"] = json!("  ");
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &ids).is_err());
    value["findings"][0]["claim"] = json!("Storage may be blocked.");
    value["findings"][0]["evidence_ids"] = json!(["  "]);
    assert!(Diagnosis::parse(value.to_string().as_bytes(), &BTreeSet::from(["  ".into()])).is_err());
}

#[test]
fn repeated_relay_receipt_keeps_original_evidence_identity() {
    let mut store = EvidenceStore::new(80_000);
    let record = evidence(1000);
    let id = store.insert(record.clone()).expect("first");
    let mut retransmitted = record;
    retransmitted.received_at_ms = 10_000;
    assert_eq!(store.insert(retransmitted), Ok(id));
    assert_eq!(store.watermark(), 1);
    assert_eq!(store.entries().next().expect("record").record.received_at_ms, 1000);
}

#[test]
fn unapproved_profile_cannot_pass_declaration_checks() {
    use tos_health_core::config::{production_doctor, ProductionEvidence, ResourceProfile};
    let profile: ResourceProfile =
        serde_json::from_str(include_str!("../../../config/resource-profile.json"))
            .expect("profile");
    let evidence: ProductionEvidence =
        serde_json::from_str(include_str!("../../../config/acceptance-evidence.json"))
            .expect("evidence");
    assert!(profile.validate().is_ok());
    let missing = production_doctor(&profile, &evidence);
    assert!(missing.contains(&"contiguous_work_budget"));
    assert!(missing.contains(&"independent_watchdog"));
    assert!(missing.contains(&"validator_core"));
    assert!(missing.contains(&"zero_upstream"));
}
#[test]
fn profile_arithmetic_cannot_overflow_into_validity() {
    use tos_health_core::config::ResourceProfile;
    let mut profile: ResourceProfile =
        serde_json::from_str(include_str!("../../../config/resource-profile.json"))
            .expect("profile");
    profile.records = u64::MAX;
    assert!(profile.validate().is_err());
    profile.records = 4096;
    profile.http_timeout_ms = profile.source_budget_ms;
    assert!(profile.validate().is_err());
}


#[test]
fn evidence_charges_the_decoded_footprint_and_bounds_nodes() {
    use tos_health_core::evidence::{value_footprint, value_nodes, MAX_PAYLOAD_NODES};
    // 7000 zeros serialize to ~14 KB but cost 7000 Values once decoded.
    let zeros = json!(vec![0u8; 7000]);
    assert!(value_footprint(&zeros) > 7000 * 32);
    assert_eq!(value_nodes(&zeros), 7001);
    let mut e = evidence(1);
    e.payload = zeros;
    let mut s = EvidenceStore::new(8 * 1024 * 1024);
    assert_eq!(s.insert(e.clone()), Err("evidence payload node limit"));
    // Within the node bound the resident charge follows the footprint, not the text.
    let mut small = evidence(2);
    small.payload = json!(vec![0u8; 2000]);
    let text = serde_json::to_vec(&small).unwrap().len();
    s.insert(small).unwrap();
    assert!(s.resident_bytes() > text + 2048, "{} vs {}", s.resident_bytes(), text);
    assert!(value_nodes(&json!({"a": [1, 2, {"b": "c"}]})) == 6 && MAX_PAYLOAD_NODES == 4096);
    // Removal by id frees the charge and the identity.
    let id = s.insert(evidence(3)).unwrap();
    let before = s.resident_bytes();
    assert!(s.remove(&id));
    assert!(s.resident_bytes() < before);
    assert!(!s.remove(&id));
    assert_eq!(s.insert(evidence(3)).unwrap(), id);
}
