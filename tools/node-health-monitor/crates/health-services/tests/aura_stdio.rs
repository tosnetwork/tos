#![cfg(feature = "mcp")]

use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, client::conn::http1, Request};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::{os::unix::fs::PermissionsExt, path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{ChildStdin, ChildStdout, Command},
};
use tos_health_core::{query::TOOLS, query_output::ToolEnvelope};

async fn wait_for_socket(path: &Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("isolated NHM Unix socket did not appear");
}

async fn control_grant(path: &Path, start: &str, end: &str) -> Value {
    let stream = tokio::net::UnixStream::connect(path).await.unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.unwrap();
    let task = tokio::spawn(connection);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/control/grants")
        .header("host", "localhost")
        .header("authorization", format!("Bearer {}", "o".repeat(32)))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(
            json!({"node_ids":["v1"],"scope_ids":["node"],"start":start,"end":end}).to_string(),
        )))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert!(response.status().is_success(), "grant: {}", response.status());
    let value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    drop(sender);
    task.abort();
    value
}

async fn rpc(
    stdin: &mut ChildStdin,
    output: &mut Lines<BufReader<ChildStdout>>,
    request: Value,
) -> Value {
    stdin.write_all(request.to_string().as_bytes()).await.unwrap();
    stdin.write_all(b"\n").await.unwrap();
    stdin.flush().await.unwrap();
    let line = tokio::time::timeout(Duration::from_secs(5), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str(&line).unwrap()
}

#[tokio::test]
async fn stdio_adapter_uses_actual_private_unix_mcp_for_six_tools() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-aura-stdio-{}-{}",
        std::process::id(),
        tos_health_services::hex(&tos_health_services::random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let inventory = directory.join("inventory.json");
    std::fs::write(
        &inventory,
        json!({"network_id":"a".repeat(64),"nodes":["v1"],"scopes":["node"]}).to_string(),
    )
    .unwrap();
    for (name, value) in [("operator", 'o'), ("ingest", 'i'), ("service", 'a')] {
        let path = directory.join(name);
        std::fs::write(&path, value.to_string().repeat(32)).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let control = directory.join("control.sock");
    let mcp = directory.join("mcp.sock");
    let mut service = Command::new(env!("CARGO_BIN_EXE_tos-observability"))
        .arg(&inventory)
        .arg("127.0.0.1:0")
        .arg(directory.join("operator"))
        .arg(directory.join("ingest"))
        .arg(directory.join("service"))
        .arg(directory.join("query.sqlite"))
        .arg(&control)
        .arg("-")
        .arg("-")
        .arg(&mcp)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for_socket(&control).await;
    wait_for_socket(&mcp).await;
    assert!(service.try_wait().unwrap().is_none());

    let now = chrono::Utc::now();
    let start =
        (now - chrono::Duration::seconds(60)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let end = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let grant = control_grant(&control, &start, &end).await;
    let run = grant["run_id"].as_str().unwrap();
    let credential = directory.join("adapter-credential.json");
    std::fs::write(
        &credential,
        json!({"run_id":run,"run_token":grant["run_token"],"service_token":"a".repeat(32)})
            .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o644)).unwrap();
    let refused = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&mcp)
        .arg(&credential)
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(!refused.status.success(), "world-readable credential file was admitted");
    assert!(refused.stdout.is_empty(), "credential refusal reached model-visible stdout");
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut adapter = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&mcp)
        .arg(&credential)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = adapter.stdin.take().unwrap();
    let mut output = BufReader::new(adapter.stdout.take().unwrap()).lines();
    let initialized = rpc(
        &mut stdin,
        &mut output,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"isolated-aura-transport-check","version":"1"}}}),
    )
    .await;
    assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let listed = rpc(
        &mut stdin,
        &mut output,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    )
    .await;
    let names: Vec<_> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, TOOLS);
    assert!(!listed.to_string().contains(grant["run_token"].as_str().unwrap()));

    let inputs = [
        json!({"run_id":run}),
        json!({"run_id":run,"node_id":"v1","as_of":end,"max_age_seconds":60,"components":["process"]}),
        json!({"run_id":run,"node_ids":["v1"],"metric_ids":["rss_bytes"],"scope_id":"node","start":start,"end":end,"step_seconds":15,"mode":"raw","max_points_per_series":10}),
        json!({"run_id":run,"node_ids":["v1"],"scope_id":"node","start":start,"end":end,"sources":["collector"],"kinds":["warning"],"correlation_id":"","contains":"","limit":10,"cursor":""}),
        json!({"run_id":run,"node_ids":["v1"],"start":start,"end":end,"kinds":["config"],"limit":10,"cursor":""}),
        json!({"run_id":run,"node_ids":["v1"],"reference_id":"blk_0123456789abcdef","ancestor_depth":0,"max_events":10}),
    ];
    for (index, (name, arguments)) in TOOLS.into_iter().zip(inputs).enumerate() {
        let result = rpc(
            &mut stdin,
            &mut output,
            json!({"jsonrpc":"2.0","id":index + 3,"method":"tools/call","params":{
                "name":name,"arguments":arguments}}),
        )
        .await;
        assert_eq!(result["id"], index + 3, "{name}: {result}");
        let text = result["result"]["content"][0]["text"].as_str().unwrap();
        let _: ToolEnvelope = serde_json::from_str(text).unwrap();
        assert!(!result.to_string().contains(grant["run_token"].as_str().unwrap()));
    }
    drop(stdin);
    assert!(tokio::time::timeout(Duration::from_secs(5), adapter.wait())
        .await
        .unwrap()
        .unwrap()
        .success());
    let mut replay = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&mcp)
        .arg(&credential)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    replay.stdin.take().unwrap().write_all(
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"replay\",\"version\":\"1\"}}\n",
    ).await.unwrap();
    let replay_output = tokio::time::timeout(Duration::from_secs(5), replay.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(!replay_output.status.success(), "second connection reclaimed a single-use grant");
    assert!(replay_output.stdout.is_empty(), "replayed grant returned model-visible data");
    service.kill().await.unwrap();
    service.wait().await.unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
