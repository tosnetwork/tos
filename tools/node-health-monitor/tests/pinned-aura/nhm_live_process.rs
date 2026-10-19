// Include from the pinned AURA 1000f119 test tree. This opt-in C09 host test
// reads the already-running M evidence DB; it never changes business nodes.

use aura::{
    config::{McpConfig, McpServerConfig},
    mcp::McpManager,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

fn sha256_file(path: &Path) -> String {
    let mut file = std::fs::File::open(path).unwrap();
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    hex::encode(digest.finalize())
}

fn m_process_parent(db: &str, parent_id: &str, node: &str) -> Value {
    // Host-only, read-only lookup by the original M evidence ID. Pinned AURA
    // does not depend on SQLite, so use the Python standard library here.
    const LOOKUP: &str = r#"import json, sqlite3, sys
db, evidence_id, node = sys.argv[1:]
conn = sqlite3.connect('file:' + db + '?mode=ro', uri=True)
row = conn.execute('SELECT body FROM observations WHERE content_hash=? AND node=? AND source=? LIMIT 1', (evidence_id, node, 'process')).fetchone()
if row is None:
    sys.exit(2)
record = json.loads(row[0])['record']
source = record['payload']['source']
print(json.dumps({'node_id': record['node_id'], 'process_epoch': record['process_epoch'], 'process_payload': source['payload'], 'observed_at_ms': record['observed_at_ms']}))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(LOOKUP)
        .arg(db)
        .arg(parent_id)
        .arg(node)
        .output()
        .unwrap();
    assert!(output.status.success(), "missing original M process evidence for {node}");
    serde_json::from_slice(&output.stdout).unwrap()
}

struct OwnedProcess(Child);
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct PrivateDirectory(PathBuf);
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn private_token(path: &Path) -> String {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    assert!(metadata.file_type().is_file(), "credential is not a regular file");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600, "credential permissions");
    let token = String::from_utf8(std::fs::read(path).unwrap()).unwrap();
    let token = token.trim_end_matches(['\r', '\n']);
    assert!(token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()));
    token.to_owned()
}

fn revoke_grant(path: &Path, operator_token: &str, run: &str) -> bool {
    let Ok(mut stream) = UnixStream::connect(path) else { return false };
    if stream.set_read_timeout(Some(Duration::from_secs(5))).is_err() {
        return false;
    }
    if stream.set_write_timeout(Some(Duration::from_secs(5))).is_err() {
        return false;
    }
    if write!(
        stream,
        "POST /v1/control/grants/{run}/revoke HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {operator_token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .and_then(|_| stream.flush())
    .is_err()
    {
        return false;
    }
    let mut response = Vec::new();
    (&mut stream).take(4096).read_to_end(&mut response).is_ok()
        && response.starts_with(b"HTTP/1.1 200")
        && response.windows(b"\"revoked\":true".len()).any(|part| part == b"\"revoked\":true")
}

struct GrantLease<'a> {
    socket: &'a Path,
    operator_token: &'a str,
    run: String,
    revoked: bool,
}
impl GrantLease<'_> {
    fn revoke(&mut self) {
        assert!(revoke_grant(self.socket, self.operator_token, &self.run));
        self.revoked = true;
    }
}
impl Drop for GrantLease<'_> {
    fn drop(&mut self) {
        if !self.revoked {
            let _ = revoke_grant(self.socket, self.operator_token, &self.run);
        }
    }
}

fn live_grant(path: &Path, operator_token: &str, start: &str, end: &str, nodes: &[&str]) -> Value {
    let mut stream = UnixStream::connect(path).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let body = json!({"node_ids":nodes,"scope_ids":["node"],"start":start,"end":end}).to_string();
    write!(stream,
        "POST /v1/control/grants HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        operator_token, body.len(), body).unwrap();
    stream.flush().unwrap();
    let mut response = Vec::new();
    (&mut stream).take(4096).read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"), "live grant refused");
    let split = response.windows(4).position(|part| part == b"\r\n\r\n").unwrap() + 4;
    serde_json::from_slice(&response[split..]).unwrap()
}

#[tokio::test]
async fn pinned_aura_reads_six_real_m_process_sources_without_model() {
    let db = std::env::var("NHM_C09_LIVE_M_EVIDENCE_DB").expect("explicit C09 live M DB");
    let manifest_path = std::env::var("NHM_C09_DEPLOYMENT_MANIFEST").expect("live manifest");
    let expected_manifest =
        std::env::var("NHM_C09_EXPECTED_MANIFEST_SHA256").expect("manifest digest");
    let manager_pid = std::env::var("NHM_C09_MANAGER_PID").expect("running M PID");
    assert_eq!(sha256_file(Path::new(&manifest_path)), expected_manifest);
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    assert_eq!(
        manifest["component_source_commits"]["health-state"],
        "aa583894420af2665c95768a3e5248f41f61c18e"
    );
    let manager_exe = format!("/proc/{manager_pid}/exe");
    let manager_sha = sha256_file(Path::new(&manager_exe));
    assert_eq!(manifest["binary_sha256"]["health-state"], manager_sha);
    let manager_fd = format!("/proc/{manager_pid}/fd");
    assert!(
        std::fs::read_dir(manager_fd).unwrap().any(|entry| {
            entry
                .ok()
                .and_then(|entry| std::fs::read_link(entry.path()).ok())
                .is_some_and(|path| path == Path::new(&db))
        }),
        "running M does not own the queried evidence database"
    );
    println!("C09_RUNTIME_BINDING pid={manager_pid} health_state_sha256={manager_sha} manifest_sha256={expected_manifest}");
    let adapter_bin = std::env::var("NHM_AURA_STDIO_BIN").expect("pinned adapter");
    let directory = std::env::temp_dir().join(format!("nhm-c09-aura-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _private_directory = PrivateDirectory(directory.clone());
    let nodes = ["validator1", "validator2", "validator3", "validator4", "observer5", "observer6"];
    assert_eq!(
        manifest["nodes"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        nodes.into_iter().collect(),
    );
    let broker_control = std::env::var("NHM_C09_BROKER_CONTROL_SOCKET").ok();
    let (control, mcp, operator_token, service_token, owned_service) = if let Some(control) =
        broker_control
    {
        let mcp =
            PathBuf::from(std::env::var("NHM_C09_BROKER_MCP_SOCKET").expect("broker MCP socket"));
        let control = PathBuf::from(control);
        let broker_pid = std::env::var("NHM_C09_BROKER_PID").expect("running broker PID");
        let broker_sha = sha256_file(Path::new(&format!("/proc/{broker_pid}/exe")));
        assert_eq!(manifest["binary_sha256"]["tos-observability"], broker_sha);
        let cmdline = std::fs::read(format!("/proc/{broker_pid}/cmdline")).unwrap();
        for expected in [&control, &mcp, Path::new(&db)] {
            assert!(
                cmdline
                    .split(|byte| *byte == 0)
                    .any(|argument| argument == expected.as_os_str().as_encoded_bytes()),
                "broker does not own expected socket or M evidence path"
            );
        }
        assert!(control.exists() && mcp.exists(), "live broker sockets unavailable");
        let operator_token = private_token(Path::new(
            &std::env::var("NHM_C09_BROKER_OPERATOR_TOKEN_FILE")
                .expect("broker operator token path"),
        ));
        let service_token = private_token(Path::new(
            &std::env::var("NHM_C09_BROKER_SERVICE_TOKEN_FILE").expect("broker service token path"),
        ));
        println!("C09_AURA_TARGET live_broker pid={broker_pid} exe_sha256={broker_sha}");
        (control, mcp, operator_token, service_token, None)
    } else {
        let service_bin = std::env::var("NHM_OBSERVABILITY_BIN").expect("pinned NHM service");
        let inventory = directory.join("inventory.json");
        std::fs::write(
            &inventory,
            json!({"network_id":manifest["network_id"],"nodes":nodes,"scopes":["node"]})
                .to_string(),
        )
        .unwrap();
        for (name, value) in [("operator", 'o'), ("ingest", 'i'), ("service", 'a')] {
            let path = directory.join(name);
            std::fs::write(&path, value.to_string().repeat(32)).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let control = directory.join("control.sock");
        let mcp = directory.join("mcp.sock");
        let mut service = OwnedProcess(
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
        for _ in 0..500 {
            if control.exists() && mcp.exists() {
                break;
            }
            assert!(
                service.0.try_wait().unwrap().is_none(),
                "query service exited before readiness"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(control.exists() && mcp.exists(), "query service refused live M projection");
        (control, mcp, "o".repeat(32), "a".repeat(32), Some(service))
    };
    let now = chrono::Utc::now();
    let start =
        (now - chrono::Duration::minutes(4)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let end = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    // A grant deliberately caps node identities at four. Six nodes require
    // two independently authorized runs; the test must not relax that bound.
    for (index, group) in [nodes[..4].as_ref(), nodes[4..].as_ref()].into_iter().enumerate() {
        let issued = live_grant(&control, &operator_token, &start, &end, group);
        let run = issued["run_id"].as_str().unwrap().to_owned();
        let mut grant_lease = GrantLease {
            socket: &control,
            operator_token: &operator_token,
            run: run.clone(),
            revoked: false,
        };
        let credential = directory.join(format!("adapter-credential-{index}.json"));
        std::fs::write(
            &credential,
            json!({"run_id":run,"run_token":issued["run_token"],"service_token":service_token})
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
            assert!(
                matches!(envelope["status"].as_str(), Some("ok" | "partial")),
                "{node}: process projection unavailable: {envelope}"
            );
            assert_eq!(envelope["data"]["node_id"], *node);
            let components = envelope["data"]["components"].as_array().unwrap();
            assert_eq!(components.len(), 1, "{node}: unexpected component count");
            let component = &components[0];
            assert_eq!(component["kind"], "process");
            assert_eq!(component["sources"], json!(["process"]));
            assert_eq!(component["value"]["kind"], "process");
            let pid = component["value"]["pid"].as_u64().expect("actual process PID missing");
            assert!(pid > 0);
            assert_eq!(pid, manifest["nodes"][*node]["pid"].as_u64().unwrap());
            let evidence = envelope["evidence"].as_array().unwrap();
            assert_eq!(evidence.len(), 1, "{node}: expected one retained process evidence");
            let source = &evidence[0];
            assert_eq!(source["node_id"], *node);
            assert_eq!(source["source_id"], "process");
            assert_eq!(source["kind"], "derived");
            assert_eq!(source["source_version"], "m-observation-projection-v1");
            assert_eq!(source["derivation_version"], "m-observation-projection-v1");
            assert_eq!(source["clock_quality"], "valid");
            assert_eq!(source["redacted"], true);
            assert_eq!(source["payload"], component["value"]);
            assert_eq!(source["process_epoch"], envelope["data"]["process_epoch"]);
            let parents = source["parent_evidence_ids"].as_array().unwrap();
            assert_eq!(parents.len(), 1, "{node}: missing original M parent");
            let parent_id = parents[0].as_str().unwrap();
            assert_eq!(source["source_record_id"], format!("m-{parent_id}"));
            let original = m_process_parent(&db, parent_id, node);
            assert_eq!(original["node_id"], *node);
            assert_eq!(original["process_payload"], component["value"]);
            assert_eq!(original["process_epoch"], source["process_epoch"]);
            let observed = chrono::DateTime::from_timestamp_millis(
                original["observed_at_ms"].as_i64().unwrap(),
            )
            .unwrap();
            assert_eq!(
                source["observed_at"],
                observed.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            );
            let age_seconds = now.signed_duration_since(observed).num_seconds();
            assert!((0..=180).contains(&age_seconds), "{node}: process parent age invalid");
            assert!(!content.contains(issued["run_token"].as_str().unwrap()));
            println!(
                "AURA_C09_REAL_PROCESS {node} {} pid={pid} parent={parent_id}",
                envelope["status"]
            );
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
            assert!(envelope["data"].is_null());
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
        grant_lease.revoke();
        println!("C09_GRANT_REVOKED group={index}");
    }
    drop(owned_service);
    std::fs::remove_dir_all(directory).unwrap();
}
