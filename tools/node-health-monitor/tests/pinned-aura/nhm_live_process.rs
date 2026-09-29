// Include from the pinned AURA 1000f119 test tree. This opt-in C09 host test
// reads the already-running M evidence DB; it never changes business nodes.

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

struct OwnedProcess(Child);
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn live_grant(path: &Path, start: &str, end: &str, nodes: &[&str]) -> Value {
    let mut stream = UnixStream::connect(path).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let body = json!({"node_ids":nodes,"scope_ids":["node"],"start":start,"end":end}).to_string();
    write!(stream,
        "POST /v1/control/grants HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        "o".repeat(32), body.len(), body).unwrap();
    stream.flush().unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"), "live grant refused");
    let split = response.windows(4).position(|part| part == b"\r\n\r\n").unwrap() + 4;
    serde_json::from_slice(&response[split..]).unwrap()
}

#[tokio::test]
async fn pinned_aura_reads_six_real_m_process_sources_without_model() {
    let db = std::env::var("NHM_C09_LIVE_M_EVIDENCE_DB").expect("explicit C09 live M DB");
    let service_bin = std::env::var("NHM_OBSERVABILITY_BIN").expect("pinned NHM service");
    let adapter_bin = std::env::var("NHM_AURA_STDIO_BIN").expect("pinned adapter");
    let directory = std::env::temp_dir().join(format!("nhm-c09-aura-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let nodes = ["validator1", "validator2", "validator3", "validator4", "observer5", "observer6"];
    let inventory = directory.join("inventory.json");
    std::fs::write(&inventory, json!({"network_id":"b7fba4bda348db54717b7930da7b874289d88642a4d3990fb41d03e0cb006004","nodes":nodes,"scopes":["node"]}).to_string()).unwrap();
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
            .arg("-")
            .arg(&db)
            .arg(&mcp)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if control.exists() && mcp.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(control.exists() && mcp.exists(), "query service refused live M projection");
    let now = chrono::Utc::now();
    let start =
        (now - chrono::Duration::minutes(4)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let end = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    // A grant deliberately caps node identities at four. Six nodes require
    // two independently authorized runs; the test must not relax that bound.
    for (index, group) in [nodes[..4].as_ref(), nodes[4..].as_ref()].into_iter().enumerate() {
        let issued = live_grant(&control, &start, &end, group);
        let run = issued["run_id"].as_str().unwrap();
        let credential = directory.join(format!("adapter-credential-{index}.json"));
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
                    cmd: vec![adapter_bin.clone()],
                    args: vec![
                        mcp.to_string_lossy().into_owned(),
                        credential.to_string_lossy().into_owned(),
                    ],
                    env: HashMap::new(),
                    description: Some("C09 real M process sources".into()),
                    scratchpad: HashMap::new(),
                },
            )]
            .into_iter()
            .collect(),
        };
        let manager = tokio::time::timeout(
            Duration::from_secs(15),
            McpManager::initialize_from_config(&config),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!credential.exists(), "one-use credential remained on disk");
        let mut available = manager.get_available_tool_names();
        available.sort();
        assert_eq!(available.len(), 6, "pinned AURA did not discover six NHM tools");
        for node in group {
            let arguments = json!({"run_id":run,"node_id":node,"as_of":end,"max_age_seconds":180,"components":["process"]});
            let result = tokio::time::timeout(
                Duration::from_secs(6),
                manager.execute_fallback_tool("tos_get_node_snapshot", &arguments.to_string()),
            )
            .await
            .unwrap()
            .unwrap();
            let content = result.strip_prefix("Tool returned an error: ").unwrap_or(&result);
            let envelope: Value =
                serde_json::from_str(content).expect("AURA did not return a typed NHM envelope");
            assert_eq!(envelope["run_id"], run);
            assert_ne!(envelope["status"], "error", "{node}: process projection unavailable");
            assert!(
                envelope["evidence"].as_array().is_some_and(|rows| !rows.is_empty()),
                "{node}: AURA received no retained M evidence reference"
            );
            assert!(content.contains(node), "{node}: delivered result lacks node identity");
            assert!(!content.contains(issued["run_token"].as_str().unwrap()));
            println!("AURA_C09_REAL_PROCESS {node} {}", envelope["status"]);
        }
        if index == 0 {
            // A live process row says nothing about consensus. Its absence is
            // an explicit unknown, not a fabricated healthy/abnormal verdict.
            let unknown = json!({"run_id":run,"node_id":"validator1","as_of":end,"max_age_seconds":180,"components":["consensus"]});
            let result = manager
                .execute_fallback_tool("tos_get_node_snapshot", &unknown.to_string())
                .await
                .unwrap();
            let content = result.strip_prefix("Tool returned an error: ").unwrap_or(&result);
            let envelope: Value = serde_json::from_str(content).unwrap();
            assert_eq!(envelope["status"], "error");
            assert_eq!(envelope["error"]["code"], "CACHE_MISS");
            assert_eq!(envelope["coverage"]["status"], "unknown");
            assert!(envelope["evidence"].as_array().is_some_and(Vec::is_empty));
            println!("AURA_C09_REAL_UNKNOWN consensus=error");
        } else {
            // The second run has only observer5/6; it cannot borrow the
            // first run's validator scope despite sharing the same socket.
            let denied = json!({"run_id":run,"node_id":"validator1","as_of":end,"max_age_seconds":180,"components":["process"]});
            let result = manager
                .execute_fallback_tool("tos_get_node_snapshot", &denied.to_string())
                .await
                .unwrap();
            let content = result.strip_prefix("Tool returned an error: ").unwrap_or(&result);
            let envelope: Value = serde_json::from_str(content).unwrap();
            assert_eq!(envelope["status"], "error");
            assert_eq!(envelope["error"]["code"], "OUT_OF_SCOPE");
            println!("AURA_C09_REAL_SCOPE cross_run=error");
        }
        let cancelled =
            manager.cancel_and_close_all("nhm-c09-readonly", "bounded C09 test done").await;
        assert_eq!(cancelled, 0);
        drop(manager);
    }
    drop(_service);
    std::fs::remove_dir_all(directory).unwrap();
}
