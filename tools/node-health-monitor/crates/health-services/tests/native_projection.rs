//! Native consensus rows archived by M are projected into the query cache and
//! served as real `consensus`/`chain`/`storage` components, catalog metric
//! windows and a read-only health verdict copy. Fixture: one real validator1
//! native-core-v2 sample from the loopback publisher; v3 rows are derived from
//! it with synthetic chain anchors and recomputed content hashes.
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::PathBuf};
use tos_health_core::{
    evidence::Evidence,
    native::canonical_hash,
    query_output::ToolEnvelope,
    source::{Availability, Coverage, SourceQuality},
};
use tos_health_services::{
    durable::{ControlDb, DurableEvidence, Evaluation, EvidenceDb, RuleKey},
    manager_query_source::{project_origin, read_process_projection},
    observability::{control_router, router as query_router, ObservabilityState},
    random_token, Inventory,
};
use tower::ServiceExt;

const FIXTURE: &str = include_str!("fixtures/native_core_v2_validator1.json");
const NETWORK: &str = "b7fba4bda348db54717b7930da7b874289d88642a4d3990fb41d03e0cb006004";
const NODE: &str = "validator1";
const T0: &str = "2026-09-30T09:40:38Z";

fn ms(at: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(at).unwrap().timestamp_millis()
}
fn rfc(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
fn temp(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nhm-native-{tag}-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

/// Archive-shaped native row exactly as the edge/collector path stores it:
/// relay age and receipt are null, `component` is `consensus`.
fn native_row(
    generation: u64,
    observed_ms: i64,
    mutate: impl FnOnce(&mut Value),
) -> DurableEvidence {
    let mut source: Value = serde_json::from_str(FIXTURE).unwrap();
    let at = rfc(observed_ms);
    source["generation"] = json!(generation.to_string());
    source["payload"]["generation"] = json!(generation.to_string());
    source["observed_at"] = json!(at);
    source["last_success_at"] = json!(at);
    source["source_age_ms"] = Value::Null;
    source["received_at"] = Value::Null;
    mutate(&mut source);
    source["content_hash"] = json!(canonical_hash(&source["payload"]).unwrap());
    let epoch = source["process_epoch"].as_str().unwrap().to_owned();
    DurableEvidence {
        source_epoch: epoch.clone(),
        record: Evidence {
            node_id: NODE.into(),
            scope_id: "node".into(),
            source_id: "native_core".into(),
            source_record_id: format!("{epoch}:{generation}"),
            process_epoch: epoch.clone(),
            observed_at_ms: observed_ms,
            received_at_ms: observed_ms + 500,
            quality: SourceQuality {
                availability: Availability::Available,
                coverage: Coverage::Partial,
                observed_at_ms: Some(observed_ms),
                last_success_at_ms: Some(observed_ms),
                clock_valid: true,
                process_epoch: epoch,
                source_sequence: generation.to_string(),
            },
            payload: json!({"component":"consensus","source":source}),
            redacted: true,
        },
    }
}

/// Turn the v2 sample into a v3 sample with chain anchors observed at the
/// sample time and applied five seconds earlier.
fn to_v3(source: &mut Value, observed_ms: i64, applied_seqno: u32, served_seqno: u32) {
    let seconds = observed_ms / 1000;
    source["source_version"] = json!("native-core-v3");
    source["coverage"]["sampling_policy"] = json!("native-core-v3-chain-partial");
    let missing: Vec<Value> = source["coverage"]["missing_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|field| field.as_str() != Some("chain_anchors"))
        .cloned()
        .collect();
    source["coverage"]["missing_fields"] = Value::Array(missing);
    let anchor = |point: &str, seqno: u32| {
        json!({"kind":"block","network_id":NETWORK,"point":point,"scope_id":"masterchain",
            "workchain":-1,"shard":"9223372036854775808","seqno":seqno,
            "root_hash":format!("a{}", "b".repeat(63)),"file_hash":format!("c{}", "d".repeat(63))})
    };
    source["payload"]["chain"] = json!({
        "applied":anchor("applied", applied_seqno),
        "served":anchor("served", served_seqno),
        "applied_advanced_unix_seconds":(seconds - 5).to_string(),
        "observed_unix_seconds":seconds.to_string(),
    });
}

/// A collector fact frame also uses the native_core source id but carries no
/// `component`; it must be skipped by the projection, never mis-projected.
fn fact_frame_row(generation: u64, observed_ms: i64) -> DurableEvidence {
    let epoch = "f72a52b2f44cc45ff59cd6d8ceeeee0c";
    DurableEvidence {
        source_epoch: epoch.into(),
        record: Evidence {
            node_id: NODE.into(),
            scope_id: "node".into(),
            source_id: "native_core".into(),
            source_record_id: generation.to_string(),
            process_epoch: epoch.into(),
            observed_at_ms: observed_ms,
            received_at_ms: observed_ms + 1,
            quality: SourceQuality {
                availability: Availability::Available,
                coverage: Coverage::Partial,
                observed_at_ms: Some(observed_ms),
                last_success_at_ms: Some(observed_ms),
                clock_valid: true,
                process_epoch: epoch.into(),
                source_sequence: generation.to_string(),
            },
            payload: json!({"schema_version":1,"network_id":NETWORK,"node_id":NODE,"scope_id":"node",
                "source_id":"native_core","facts":[{"id":"pq_signing_failures","value":"0"}]}),
            redacted: true,
        },
    }
}

fn inventory() -> Inventory {
    Inventory {
        network_id: NETWORK.into(),
        nodes: BTreeSet::from([NODE.into()]),
        scopes: BTreeSet::from(["node".into(), "masterchain".into()]),
    }
}

fn request(path: &str, token: char, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token.to_string().repeat(32)))
        .body(Body::from(body.to_string()))
        .unwrap()
}
async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
async fn grant(state: &ObservabilityState, start_ms: i64, end_ms: i64) -> (String, String) {
    let response = control_router(state.clone())
        .oneshot(request(
            "/v1/control/grants",
            'o',
            json!({"node_ids":[NODE],"scope_ids":["node","masterchain"],
                "start":rfc(start_ms),"end":rfc(end_ms)}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let issued = body(response).await;
    (issued["run_id"].as_str().unwrap().into(), issued["run_token"].as_str().unwrap().into())
}
async fn query(
    state: &ObservabilityState,
    tool: &str,
    token: &str,
    input: Value,
) -> (StatusCode, Value) {
    let mut req = request(&format!("/v1/query/{tool}"), 'a', input);
    req.headers_mut().insert("x-tos-run-token", token.parse().unwrap());
    let response = query_router(state.clone()).oneshot(req).await.unwrap();
    let status = response.status();
    (status, body(response).await)
}

/// Three archived native samples (v2, v2, v3) plus one fact frame row.
fn seed_manager(path: &std::path::Path) -> Vec<tos_health_services::durable::EvidenceRow> {
    let mut manager = EvidenceDb::open(path, 64 * 1024 * 1024).unwrap();
    manager.bind_network(NETWORK).unwrap();
    let t0 = ms(T0);
    let mut rows = Vec::new();
    manager.insert(fact_frame_row(1, t0 - 5_000)).unwrap();
    rows.push(manager.insert(native_row(3620, t0, |_| {})).unwrap());
    rows.push(
        manager
            .insert(native_row(3621, t0 + 15_000, |source| {
                let notarize = &mut source["payload"]["consensus"]["actions"][1]["live"];
                notarize["outcomes"]["enqueued"] = json!("332896");
                notarize["phases"]["broadcast_enqueued"] = json!("332896");
                source["payload"]["consensus"]["contexts"][0]["last_finalized_slot"] =
                    json!(153142);
                source["payload"]["consensus"]["contexts"][0]["current_slot"] = json!(153143);
            }))
            .unwrap(),
    );
    rows.push(
        manager
            .insert(native_row(3622, t0 + 30_000, |source| {
                let notarize = &mut source["payload"]["consensus"]["actions"][1]["live"];
                notarize["outcomes"]["enqueued"] = json!("332896");
                notarize["phases"]["broadcast_enqueued"] = json!("332896");
                source["payload"]["consensus"]["contexts"][0]["last_finalized_slot"] =
                    json!(153142);
                source["payload"]["consensus"]["contexts"][0]["current_slot"] = json!(153143);
                to_v3(source, t0 + 30_000, 153142, 153140);
            }))
            .unwrap(),
    );
    rows
}

#[test]
fn native_rows_project_deterministically_and_skip_fact_frames() {
    let directory = temp("project");
    let path = directory.join("manager.sqlite");
    let originals = seed_manager(&path);
    let (watermark, records) = read_process_projection(&path, NETWORK).unwrap();
    assert_eq!(watermark, 4, "fact frame row occupies M sequence 1");
    assert_eq!(records.len(), 3, "fact frame row must not be projected");
    for ((origin, projected), expected) in records.iter().zip(&originals) {
        assert_eq!(origin.evidence_id, expected.evidence_id);
        assert_eq!(projected.payload["parent_evidence_ids"][0], expected.evidence_id);
        assert_eq!(projected.payload["evidence_kind"], "derived");
        assert_eq!(projected.payload["contract_payload"]["kind"], "native_consensus");
        assert_eq!(projected.payload["storage_payload"]["kind"], "storage_state");
        assert_eq!(projected.payload["storage_payload"]["storage_commit_ack"]["enabled"], true);
        assert_eq!(
            projected.payload["storage_payload"]["durable_finality_reason"],
            "hardware_power_loss_not_proven"
        );
        // Query charge must exceed the retained parent so the 8 MiB parent
        // retention can never fill before the resident cache evicts.
        let parent = serde_json::to_vec(origin).unwrap().len();
        let charge = serde_json::to_vec(projected).unwrap().len() + 2048;
        assert!(parent <= 34_816 && parent < charge, "parent={parent} charge={charge}");
        // The projection is a pure function of its parent.
        let again = project_origin(origin).unwrap().unwrap();
        assert_eq!(serde_json::to_vec(&again).unwrap(), serde_json::to_vec(projected).unwrap());
    }
    assert!(records[0].1.payload["chain_payload"].is_null());
    assert_eq!(records[2].1.payload["chain_payload"]["kind"], "chain_anchors");
    assert_eq!(records[2].1.payload["chain_payload"]["applied"]["seqno"], 153142);
    assert_eq!(records[2].1.payload["chain_payload"]["served_gap"], "2");
    assert_eq!(records[2].1.payload["chain_payload"]["applied_age_seconds"], "5");
    // A tampered parent body is refused rather than re-projected.
    let mut tampered = originals[0].clone();
    tampered.evidence.record.payload["source"]["payload"]["pq_sign"]["failed"] = json!("7");
    assert!(project_origin(&tampered).unwrap_err().contains("hash mismatch"));
    let mut relabelled = originals[0].clone();
    relabelled.evidence.record.source_id = "process".into();
    assert!(project_origin(&relabelled).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn snapshot_serves_consensus_chain_storage_and_catalog_metrics_from_native_rows() {
    let directory = temp("serve");
    let manager_path = directory.join("manager.sqlite");
    let originals = seed_manager(&manager_path);
    let state =
        ObservabilityState::new(inventory(), vec![b'o'; 32], vec![b'i'; 32], vec![b'a'; 32])
            .unwrap()
            .with_query_ledger(&directory.join("query.sqlite"))
            .unwrap()
            .with_manager_evidence(manager_path.clone())
            .unwrap();
    let t0 = ms(T0);
    // A verdict copy stamped hours ago is visible under W but no longer
    // fresh against the response clock: it must be reported missing rather
    // than presented as the current verdict.
    {
        let stale = tos_health_services::manager_query_source::verdict_evidence(
            7,
            &tos_health_services::manager_query_source::NodeVerdicts {
                node_id: NODE.into(),
                verdicts: vec![],
            },
            t0,
        );
        let mut data = state.data.lock().unwrap();
        state
            .query_ledger
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .insert_evidence(&mut data.store, stale)
            .unwrap();
    }
    let (run, token) = grant(&state, t0 - 60_000, t0 + 60_000).await;
    let as_of = rfc(t0 + 35_000);
    let (status, snapshot) = query(
        &state,
        "node-snapshot",
        &token,
        json!({"run_id":run,"node_id":NODE,"as_of":as_of,"max_age_seconds":60,
            "components":["consensus","chain","storage"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{snapshot}");
    assert_eq!(snapshot["status"], "partial");
    let _: ToolEnvelope = serde_json::from_value(snapshot.clone()).expect("typed envelope");
    let components = snapshot["data"]["components"].as_array().unwrap();
    assert_eq!(components.len(), 3);
    let consensus = &components[0];
    assert_eq!(consensus["kind"], "consensus");
    assert_eq!(consensus["sources"], json!(["native_core"]));
    assert_eq!(consensus["value"]["kind"], "native_consensus");
    assert_eq!(consensus["value"]["source_version"], "native-core-v3");
    assert_eq!(consensus["value"]["generation"], "3622");
    assert_eq!(consensus["value"]["sessions"]["active"], "4");
    assert_eq!(consensus["value"]["sessions"]["stopped"], Value::Null);
    assert_eq!(consensus["value"]["contexts"].as_array().unwrap().len(), 4);
    assert_eq!(consensus["value"]["contexts"][0]["last_finalized_slot"], 153142);
    assert_eq!(consensus["value"]["contexts"][0]["lifecycle"], "active");
    assert_eq!(consensus["value"]["actions"][1]["action"], "notarize_vote");
    assert!(consensus["value"]["actions"][1]["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "enqueued" && c["count"] == "332896"));
    assert!(consensus["value"]["actions"][2]["failures"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "duplicate_or_stale" && c["count"] == "1069"));
    assert_eq!(consensus["value"]["pq_sign"]["succeeded"], "749287");
    assert_eq!(
        consensus["value"]["incomplete_reasons"],
        json!(["scope_unapproved", "session_lifecycle_unverified"])
    );
    // The only verdict copy is hours old: it is reported missing, not shown.
    assert!(consensus["health"].is_null());
    assert!(snapshot["missing_evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["source_id"] == "health_state"));
    let chain = &components[1];
    assert_eq!(chain["kind"], "chain");
    assert_eq!(chain["value"]["kind"], "chain_anchors");
    assert_eq!(chain["value"]["applied"]["seqno"], 153142);
    assert_eq!(chain["value"]["served"]["seqno"], 153140);
    assert_eq!(chain["value"]["served_gap"], "2");
    let storage = &components[2];
    assert_eq!(storage["value"]["kind"], "storage_state");
    assert_eq!(storage["value"]["storage_commit_ack"]["supported"], true);
    assert_eq!(storage["value"]["intent_storage_failures"], "0");
    // All three components cite the same delivered derived row with its M parent.
    assert_eq!(snapshot["evidence"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["evidence"][0]["kind"], "derived");
    assert_eq!(snapshot["evidence"][0]["parent_evidence_ids"][0], originals[2].evidence_id);
    if let Some(dir) = std::env::var_os("NHM_CONTRACT_OUTPUT_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            PathBuf::from(dir).join("tos_get_node_snapshot.native.json"),
            serde_json::to_vec_pretty(&snapshot).unwrap(),
        )
        .unwrap();
    }
    // A v2-only window has no chain anchors: explicit miss, no fabricated anchor.
    let (status, miss) = query(
        &state,
        "node-snapshot",
        &token,
        json!({"run_id":run,"node_id":NODE,"as_of":rfc(t0 + 20_000),"max_age_seconds":30,
            "components":["chain"]}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(miss["error"]["code"], "CACHE_MISS");
    assert_eq!(miss["error"]["retryable"], false);

    let window = |metrics: Value, max_points: u32| {
        json!({"run_id":run,"node_ids":[NODE],"metric_ids":metrics,"scope_id":"node",
            "start":rfc(t0 - 60_000),"end":rfc(t0 + 60_000),"step_seconds":15,
            "mode":"series","max_points_per_series":max_points})
    };
    let (status, metrics) = query(
        &state,
        "metric-window",
        &token,
        window(
            json!([
                "native_consensus_last_finalized_slot",
                "native_notarize_vote_enqueued_delta",
                "native_chain_applied_seqno"
            ]),
            10,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{metrics}");
    let _: ToolEnvelope = serde_json::from_value(metrics.clone()).expect("typed metric envelope");
    let series = metrics["data"]["series"].as_array().unwrap();
    assert_eq!(series.len(), 3);
    let by_id = |id: &str| series.iter().find(|s| s["metric_id"] == id).unwrap();
    let gauge = by_id("native_consensus_last_finalized_slot");
    assert_eq!(gauge["semantic_type"], "gauge");
    assert_eq!(gauge["unit"], "slots");
    let values: Vec<_> =
        gauge["points"].as_array().unwrap().iter().map(|p| p["value"].clone()).collect();
    assert_eq!(values, json!([153141.0, 153142.0, 153142.0]).as_array().unwrap().clone());
    assert_eq!(gauge["source_evidence_ids"].as_array().unwrap().len(), 3);
    assert_eq!(gauge["coverage"]["status"], "complete");
    let delta = by_id("native_notarize_vote_enqueued_delta");
    assert_eq!(delta["semantic_type"], "counter");
    let values: Vec<_> =
        delta["points"].as_array().unwrap().iter().map(|p| p["value"].clone()).collect();
    assert_eq!(values, json!([10.0, 0.0]).as_array().unwrap().clone());
    assert_eq!(delta["coverage"]["status"], "partial");
    assert!(delta["coverage"]["gaps"][0].as_str().unwrap().starts_with("no prior sample before"));
    assert_eq!(delta["reset_count"], "0");
    let chain_gauge = by_id("native_chain_applied_seqno");
    let values: Vec<_> =
        chain_gauge["points"].as_array().unwrap().iter().map(|p| p["value"].clone()).collect();
    assert_eq!(values, json!([null, null, 153142.0]).as_array().unwrap().clone());
    assert_eq!(chain_gauge["coverage"]["missing_fields"], json!(["native_chain_applied_seqno"]));
    // Only the newest contributing sample is delivered as citable evidence.
    assert_eq!(metrics["evidence"].as_array().unwrap().len(), 1);
    assert_eq!(metrics["evidence"][0]["parent_evidence_ids"][0], originals[2].evidence_id);
    let (status, limited) = query(
        &state,
        "metric-window",
        &token,
        window(json!(["native_consensus_last_finalized_slot"]), 2),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{limited}");
    assert_eq!(
        limited["error"]["code"], "SERIES_LIMIT",
        "smaller max_points is an explicit overflow"
    );
    let (status, unknown) =
        query(&state, "metric-window", &token, window(json!(["not_in_catalog"]), 10)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(unknown["error"]["code"], "UNKNOWN_METRIC");
    let (status, summary) = query(
        &state,
        "metric-window",
        &token,
        json!({"run_id":run,"node_ids":[NODE],"metric_ids":["native_sessions_active"],"scope_id":"node",
            "start":rfc(t0 - 60_000),"end":rfc(t0 + 60_000),"step_seconds":15,
            "mode":"summary","max_points_per_series":10}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(summary["error"]["code"], "CAPABILITY_UNSUPPORTED");
    assert_eq!(
        state.manager_projection_reads.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "startup and grant read M once each; no query read M"
    );
    drop(state);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn health_verdict_copy_attaches_to_consensus_component_read_only() {
    let directory = temp("verdict");
    let manager_path = directory.join("manager.sqlite");
    seed_manager(&manager_path);
    let control_path = directory.join("control.sqlite");
    let mut control = ControlDb::open(&control_path, 1024 * 1024, 100, 100).unwrap();
    control.bind_network(NETWORK).unwrap();
    let key = |rule: &str, scope: &str| RuleKey {
        node: NODE.into(),
        scope: scope.into(),
        rule: rule.into(),
    };
    control
        .evaluate(
            &key("chain_progress", "masterchain"),
            Evaluation::Bad { severity: "critical".into() },
            1_000,
            &[],
            0,
        )
        .unwrap();
    control.evaluate(&key("pq_signing", "node"), Evaluation::Unknown, 1_000, &[], 0).unwrap();
    let sequence = control.sequence().unwrap();
    drop(control);
    let wrong_network = directory.join("wrong.sqlite");
    let mut wrong = ControlDb::open(&wrong_network, 1024 * 1024, 100, 100).unwrap();
    wrong.bind_network(&"e".repeat(64)).unwrap();
    drop(wrong);
    let base = || {
        ObservabilityState::new(inventory(), vec![b'o'; 32], vec![b'i'; 32], vec![b'a'; 32])
            .unwrap()
            .with_query_ledger(&directory.join(format!(
                "query-{}.sqlite",
                tos_health_services::hex(&random_token().unwrap())
            )))
            .unwrap()
            .with_manager_evidence(manager_path.clone())
            .unwrap()
    };
    match base().with_manager_control(wrong_network) {
        Err(error) => assert!(error.contains("network"), "{error}"),
        Ok(_) => panic!("control database of another network was accepted"),
    }
    let state = base().with_manager_control(control_path.clone()).unwrap();
    let t0 = ms(T0);
    let (run, token) = grant(&state, t0 - 60_000, t0 + 60_000).await;
    // The verdict row is stamped with the query layer's own read time; the
    // snapshot as_of must therefore be "now"-relative, unlike native samples.
    let now = chrono::Utc::now().timestamp_millis();
    let (run_now, token_now) = grant(&state, now - 3_000_000, now - 1_000).await;
    let (status, snapshot) = query(
        &state,
        "node-snapshot",
        &token_now,
        json!({"run_id":run_now,"node_id":NODE,"as_of":rfc(now - 1_000),"max_age_seconds":180,
            "components":["process"]}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{snapshot}");
    assert_eq!(
        snapshot["error"]["code"], "CACHE_MISS",
        "no process rows; health is not a component"
    );
    // Verdict evidence itself is visible through the event-free query path:
    // it is attached to the consensus component when that sample is usable.
    let (status, consensus) = query(
        &state,
        "node-snapshot",
        &token,
        json!({"run_id":run,"node_id":NODE,"as_of":rfc(t0 + 35_000),"max_age_seconds":60,
            "components":["consensus"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{consensus}");
    // The native sample is historical while the verdict copy was read at
    // grant time: the verdict is fresh against the response clock and is
    // attached with its own evidence id, stamped with the read time.
    let health = &consensus["data"]["components"][0]["health"];
    assert_eq!(health["since_basis"], "query_import", "{consensus}");
    assert_eq!(health["rules_evaluated"], 2);
    assert_eq!(health["active_incidents"].as_array().unwrap().len(), 1);
    assert_eq!(health["active_incidents"][0]["rule"], "chain_progress");
    assert_eq!(health["active_incidents"][0]["severity"], "critical");
    assert_eq!(health["active_incidents"][0]["state"], "open");
    assert!(consensus["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["evidence_id"] == health["evidence_id"] && e["source_id"] == "health_state"));
    assert!(consensus["missing_evidence"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["source_id"] != "health_state"));
    // Read the verdict row directly from the fixed cache to check its copy.
    let data = state.data.lock().unwrap();
    let verdict = data
        .store
        .entries()
        .find(|e| e.record.source_id == "health_state")
        .expect("verdict copy row");
    assert_eq!(verdict.record.process_epoch, "m-control");
    assert_eq!(verdict.record.quality.source_sequence, sequence.to_string());
    let payload = &verdict.record.payload["contract_payload"];
    assert_eq!(payload["kind"], "health_verdicts");
    assert_eq!(payload["evaluation_sequence"], sequence.to_string());
    let verdicts = payload["verdicts"].as_array().unwrap();
    assert_eq!(verdicts.len(), 2);
    let chain = verdicts.iter().find(|v| v["rule"] == "chain_progress").unwrap();
    assert_eq!(chain["state"], "open");
    assert_eq!(chain["severity"], "critical");
    assert_eq!(chain["active"], true);
    assert_eq!(chain["scope_id"], "masterchain");
    let pq = verdicts.iter().find(|v| v["rule"] == "pq_signing").unwrap();
    assert_eq!(pq["state"], "clear");
    assert_eq!(pq["active"], false);
    let verdict_rows =
        data.store.entries().filter(|e| e.record.source_id == "health_state").count();
    assert_eq!(verdict_rows, 1, "unchanged sequence within two minutes is not re-copied");
    assert!(data.verdict_import_error.is_none());
    drop(data);
    // The control database is never opened for write by the query layer.
    let reopened = ControlDb::open(&control_path, 1024 * 1024, 100, 100).unwrap();
    assert_eq!(reopened.sequence().unwrap(), sequence);
    assert_eq!(reopened.all_states().unwrap().len(), 2);
    drop(reopened);
    drop(state);
    std::fs::remove_dir_all(directory).unwrap();
}

/// A verdict row and a fresh native sample together attach the verdict to the
/// consensus component; the model sees both ids as citable evidence.
#[tokio::test]
async fn fresh_native_sample_and_verdict_share_one_snapshot() {
    let directory = temp("fresh");
    let manager_path = directory.join("manager.sqlite");
    let now = chrono::Utc::now().timestamp_millis();
    let observed = now - 20_000;
    {
        let mut manager = EvidenceDb::open(&manager_path, 64 * 1024 * 1024).unwrap();
        manager.bind_network(NETWORK).unwrap();
        manager.insert(native_row(9001, observed, |_| {})).unwrap();
    }
    let control_path = directory.join("control.sqlite");
    let mut control = ControlDb::open(&control_path, 1024 * 1024, 100, 100).unwrap();
    control.bind_network(NETWORK).unwrap();
    control
        .evaluate(
            &RuleKey { node: NODE.into(), scope: "node".into(), rule: "pq_signing".into() },
            Evaluation::Bad { severity: "warning".into() },
            1_000,
            &[],
            0,
        )
        .unwrap();
    drop(control);
    let state =
        ObservabilityState::new(inventory(), vec![b'o'; 32], vec![b'i'; 32], vec![b'a'; 32])
            .unwrap()
            .with_query_ledger(&directory.join("query.sqlite"))
            .unwrap()
            .with_manager_evidence(manager_path)
            .unwrap()
            .with_manager_control(control_path)
            .unwrap();
    // The verdict copy was stamped during startup, so a millisecond `now`
    // taken afterwards bounds both the grant window and the snapshot as_of.
    let now = chrono::Utc::now().timestamp_millis();
    let as_of = chrono::DateTime::from_timestamp_millis(now)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let (run, token) = grant(&state, now - 600_000, now).await;
    let (status, snapshot) = query(
        &state,
        "node-snapshot",
        &token,
        json!({"run_id":run,"node_id":NODE,"as_of":as_of,"max_age_seconds":120,
            "components":["consensus"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{snapshot}");
    let _: ToolEnvelope = serde_json::from_value(snapshot.clone()).expect("typed envelope");
    let health = &snapshot["data"]["components"][0]["health"];
    assert_eq!(health["since_basis"], "query_import");
    assert_eq!(health["rules_evaluated"], 1);
    assert_eq!(health["active_incidents"][0]["rule"], "pq_signing");
    assert_eq!(health["active_incidents"][0]["severity"], "warning");
    let evidence = snapshot["evidence"].as_array().unwrap();
    assert_eq!(evidence.len(), 2);
    assert!(evidence.iter().any(|e| e["evidence_id"] == health["evidence_id"]
        && e["payload"]["kind"] == "health_verdicts"
        && e["kind"] == "observation"
        && e["source_id"] == "health_state"));
    assert!(snapshot["missing_evidence"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["source_id"] != "health_state"));
    if let Some(dir) = std::env::var_os("NHM_CONTRACT_OUTPUT_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            PathBuf::from(dir).join("tos_get_node_snapshot.verdict.json"),
            serde_json::to_vec_pretty(&snapshot).unwrap(),
        )
        .unwrap();
    }
    drop(state);
    std::fs::remove_dir_all(directory).unwrap();
}
