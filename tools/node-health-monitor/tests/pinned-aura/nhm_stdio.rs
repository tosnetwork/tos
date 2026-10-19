// Include this test from pinned AURA 1000f119's `crates/aura/tests`.
// It uses AURA's real McpManager and the NHM process/adapter binaries.

use aura::{
    config::{McpConfig, McpServerConfig},
    mcp::McpManager,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

#[cfg(target_os = "linux")]
fn adapter_pids(credential: &Path) -> Vec<u32> {
    let marker = credential.as_os_str().as_encoded_bytes();
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/cmdline"))
                .ok()
                .is_some_and(|command| command.split(|byte| *byte == 0).any(|arg| arg == marker))
        })
        .collect()
}

fn deterministic_fixture_judgment(event_result: &Value, block_result: &Value) -> Value {
    let events = event_result["data"]["events"].as_array();
    let delivered = event_result["evidence"].as_array();
    let event = events.and_then(|rows| rows.first());
    let id = event.and_then(|row| row["evidence_id"].as_str());
    let matched = event_result["status"] == "ok"
        && event.is_some_and(|row| {
            row["source_id"] == "collector"
                && row["kind"] == "warning"
                && row["reason"] == "synthetic_rss_pressure"
        })
        && id.is_some_and(|id| {
            delivered.is_some_and(|rows| rows.iter().any(|row| row["evidence_id"] == id))
        });
    let missing_block = block_result["status"] == "error";
    if matched {
        json!({"status":"analysis","summary":"An isolated synthetic collector warning reports memory pressure; this is not a live-node diagnosis.",
            "findings":[{"claim":"A synthetic collector warning was observed.","basis":"observed","evidence_ids":[id.unwrap()]}],
            "missing_evidence":if missing_block {vec!["Block evidence is unavailable; no consensus or proof conclusion is made."]} else {vec![]},
            "recommended_runbooks":["inspect_storage_pressure"]})
    } else {
        json!({"status":"insufficient_evidence","summary":"No delivered synthetic warning supports an abnormality claim.",
            "findings":[],"missing_evidence":["Collector warning evidence is unavailable or unverified."],
            "recommended_runbooks":[]})
    }
}

struct OwnedProcess(Child);
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn grant(path: &Path, start: &str, end: &str) -> Value {
    let mut stream = UnixStream::connect(path).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let body = json!({"node_ids":["v1"],"scope_ids":["node"],"start":start,"end":end}).to_string();
    write!(stream,
        "POST /v1/control/grants HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        "o".repeat(32), body.len(), body,
    ).unwrap();
    stream.flush().unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"), "grant route refused");
    let split = response.windows(4).position(|part| part == b"\r\n\r\n").unwrap() + 4;
    serde_json::from_slice(&response[split..]).unwrap()
}

#[tokio::test]
async fn pinned_aura_calls_six_nhm_tools_over_private_unix_adapter() {
    let service_bin = std::env::var("NHM_OBSERVABILITY_BIN").expect("pinned NHM service path");
    let adapter_bin = std::env::var("NHM_AURA_STDIO_BIN").expect("pinned NHM adapter path");
    let directory = std::env::temp_dir().join(format!("nhm-pinned-aura-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let inventory = directory.join("inventory.json");
    std::fs::write(
        &inventory,
        json!({"network_id":"a".repeat(64),"nodes":["v1"],"scopes":["node"]}).to_string(),
    )
    .unwrap();
    let now = chrono::Utc::now();
    let observed = (now - chrono::Duration::seconds(30)).timestamp_millis();
    let cache = directory.join("cache.jsonl");
    let process = json!({
        "node_id":"v1","scope_id":"node","source_id":"collector",
        "source_record_id":"synthetic-process-1","process_epoch":"process-1",
        "observed_at_ms":observed,"received_at_ms":observed,"redacted":true,
        "quality":{"availability":"available","coverage":"complete",
            "observed_at_ms":observed,"last_success_at_ms":observed,
            "clock_valid":true,"process_epoch":"process-1","source_sequence":"1"},
        "payload":{"component":"process","evidence_kind":"observation",
            "source_version":"synthetic-local-v1",
            "contract_quality":{"instrumentation_complete":true,"producer_dropped":"0",
                "relay_dropped":"0","parse_errors":"0","shed_reason":null},
            "contract_coverage":{"status":"complete","missing_fields":[],"gaps":[],
                "sampling_policy":"isolated synthetic fixture"},
            "contract_payload":{"kind":"process","pid":111,"rss_bytes":"8589934592",
                "anon_bytes":"8589934592","file_bytes":"0","swap_bytes":"0",
                "cpu_user_ticks":"100","cpu_system_ticks":"50"}}
    });
    let warning = json!({
        "node_id":"v1","scope_id":"node","source_id":"collector",
        "source_record_id":"synthetic-warning-1","process_epoch":"process-1",
        "observed_at_ms":observed+1,"received_at_ms":observed+1,"redacted":true,
        "quality":{"availability":"available","coverage":"complete",
            "observed_at_ms":observed+1,"last_success_at_ms":observed+1,
            "clock_valid":true,"process_epoch":"process-1","source_sequence":"2"},
        "payload":{"kind":"warning","evidence_kind":"event","source_version":"synthetic-local-v1",
            "event":{"kind":"warning","stage":null,"reason":"synthetic_rss_pressure",
                "correlation_id":null,"excerpt":"isolated synthetic collector warning"},
            "contract_quality":{"instrumentation_complete":true,"producer_dropped":"0",
                "relay_dropped":"0","parse_errors":"0","shed_reason":null},
            "contract_coverage":{"status":"complete","missing_fields":[],"gaps":[],
                "sampling_policy":"isolated synthetic fixture"},
            "contract_payload":{"kind":"diagnostic_fixture","record_type":1,"payload":"0102"}}
    });
    std::fs::write(&cache, format!("{process}\n{warning}\n")).unwrap();
    for (name, value) in [("operator", 'o'), ("ingest", 'i'), ("service", 'a')] {
        let path = directory.join(name);
        std::fs::write(&path, value.to_string().repeat(32)).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let control = directory.join("control.sock");
    let mcp = directory.join("mcp.sock");
    let _service = OwnedProcess(
        Command::new(service_bin)
            .arg(&inventory)
            .arg("127.0.0.1:0")
            .arg(directory.join("operator"))
            .arg(directory.join("ingest"))
            .arg(directory.join("service"))
            .arg(directory.join("query.sqlite"))
            .arg(&control)
            .arg(&cache)
            .arg("-")
            .arg(&mcp)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if control.exists() && mcp.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(control.exists() && mcp.exists());
    let start =
        (now - chrono::Duration::seconds(60)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let end = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let issued = grant(&control, &start, &end);
    let run = issued["run_id"].as_str().unwrap();
    let credential = directory.join("adapter-credential.json");
    std::fs::write(
        &credential,
        json!({"run_id":run,"run_token":issued["run_token"],"service_token":"a".repeat(32)})
            .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();

    let config = McpConfig {
        sanitize_schemas: false,
        servers: [(
            "nhm".to_owned(),
            McpServerConfig::Stdio {
                cmd: vec![adapter_bin],
                args: vec![
                    mcp.to_string_lossy().into_owned(),
                    credential.to_string_lossy().into_owned(),
                ],
                env: HashMap::new(),
                description: Some("isolated private NHM evidence".to_owned()),
                scratchpad: HashMap::new(),
            },
        )]
        .into_iter()
        .collect(),
    };
    let manager =
        tokio::time::timeout(Duration::from_secs(15), McpManager::initialize_from_config(&config))
            .await
            .unwrap()
            .unwrap();
    let mut names = manager.get_available_tool_names();
    names.sort();
    let mut expected: Vec<String> = [
        "tos_get_capabilities",
        "tos_get_node_snapshot",
        "tos_get_metric_window",
        "tos_get_event_window",
        "tos_get_change_history",
        "tos_get_block_evidence",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    expected.sort();
    assert_eq!(
        names, expected,
        "AURA did not discover six exact NHM tools: {:?}",
        manager.server_info
    );
    assert_eq!(manager.stdio_clients.len(), 1);
    assert!(!credential.exists(), "AURA adapter retained the one-use credential file");
    #[cfg(target_os = "linux")]
    let adapter_pid = {
        let pids = adapter_pids(&credential);
        assert_eq!(pids.len(), 1, "AURA did not own exactly one adapter child");
        pids[0]
    };

    let calls = [
        ("tos_get_capabilities", json!({"run_id":run})),
        (
            "tos_get_node_snapshot",
            json!({"run_id":run,"node_id":"v1","as_of":end,"max_age_seconds":60,"components":["process"]}),
        ),
        (
            "tos_get_metric_window",
            json!({"run_id":run,"node_ids":["v1"],"metric_ids":["rss_bytes"],"scope_id":"node","start":start,"end":end,"step_seconds":15,"mode":"raw","max_points_per_series":10}),
        ),
        (
            "tos_get_event_window",
            json!({"run_id":run,"node_ids":["v1"],"scope_id":"node","start":start,"end":end,"sources":["collector"],"kinds":["warning"],"correlation_id":"","contains":"","limit":10,"cursor":""}),
        ),
        (
            "tos_get_change_history",
            json!({"run_id":run,"node_ids":["v1"],"start":start,"end":end,"kinds":["config"],"limit":10,"cursor":""}),
        ),
        (
            "tos_get_block_evidence",
            json!({"run_id":run,"node_ids":["v1"],"reference_id":"blk_0123456789abcdef","ancestor_depth":0,"max_events":10}),
        ),
    ];
    let mut event_result = None;
    let mut block_result = None;
    for (name, arguments) in calls {
        let result = tokio::time::timeout(
            Duration::from_secs(6),
            manager.execute_fallback_tool(name, &arguments.to_string()),
        )
        .await
        .unwrap()
        .unwrap();
        let content = result.strip_prefix("Tool returned an error: ").unwrap_or(&result);
        let envelope: Value = serde_json::from_str(content)
            .unwrap_or_else(|_| panic!("{name}: non-JSON AURA result"));
        assert_eq!(envelope["run_id"], run, "{name}: AURA result escaped the granted run");
        assert_eq!(envelope["schema_version"], 1, "{name}: unexpected NHM wire");
        assert!(!result.contains(issued["run_token"].as_str().unwrap()));
        if name == "tos_get_node_snapshot" {
            assert_eq!(envelope["status"], "ok", "AURA did not read the retained process fixture");
            assert!(content.contains("8589934592"), "AURA snapshot lost the fixture's RSS value");
        }
        if name == "tos_get_event_window" {
            event_result = Some(envelope.clone());
        }
        if name == "tos_get_block_evidence" {
            block_result = Some(envelope.clone());
        }
        println!("AURA_NHM_TOOL {name} {}", envelope["status"]);
    }
    let event_result = event_result.unwrap();
    let block_result = block_result.unwrap();
    let diagnosis = deterministic_fixture_judgment(&event_result, &block_result);
    assert_eq!(diagnosis["status"], "analysis");
    let warning_id = event_result["data"]["events"][0]["evidence_id"].as_str().unwrap();
    assert_eq!(diagnosis["findings"][0]["evidence_ids"][0], warning_id);
    assert!(diagnosis["missing_evidence"][0].as_str().unwrap().contains("Block evidence"));
    let missing_control =
        deterministic_fixture_judgment(&json!({"status":"unavailable"}), &block_result);
    assert_eq!(missing_control["status"], "insufficient_evidence");
    assert!(missing_control["findings"].as_array().unwrap().is_empty());
    println!("AURA_NHM_DETERMINISTIC_FIXTURE analysis=1 unknown_control=insufficient_evidence");
    // Use AURA's actual cancellation/close API while it still owns the
    // adapter. No tool is in flight here; the separate slow-body control
    // exercises adapter cancellation of an in-flight transport request.
    let cancelled =
        manager.cancel_and_close_all("nhm-fixture-request", "isolated test cancellation").await;
    assert_eq!(cancelled, 0, "an unexpected tool remained in flight");
    #[cfg(target_os = "linux")]
    {
        for _ in 0..100 {
            if !std::path::Path::new(&format!("/proc/{adapter_pid}")).exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !std::path::Path::new(&format!("/proc/{adapter_pid}")).exists(),
            "AURA cancellation did not reap the adapter child"
        );
    }
    println!("AURA_NHM_CANCEL cancelled_inflight=0 child_reaped=1");
    drop(manager);
    drop(_service);
    std::fs::remove_dir_all(directory).unwrap();
}
