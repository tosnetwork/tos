#![cfg(feature = "mcp")]

use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body as HttpBody, Bytes, Frame},
    client::conn::http1,
    server::conn::http1 as server_http1,
    service::service_fn,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    future::Future,
    os::unix::fs::PermissionsExt,
    path::Path,
    pin::Pin,
    process::Stdio,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines},
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

async fn wait_for_handoff_consumption(path: &Path, child: &mut tokio::process::Child) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            assert!(child.try_wait().unwrap().is_none(), "adapter exited before consuming handoff");
            if !path.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("adapter did not consume one-use handoff within two seconds");
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
async fn dead_unix_connection_exits_with_stdin_still_open() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-aura-dead-{}-{}",
        std::process::id(),
        tos_health_services::hex(&tos_health_services::random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.join("mcp.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let (disconnect, disconnected) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(|_request: Request<hyper::body::Incoming>| async {
            Ok::<_, Infallible>(
                Response::builder()
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"mock","version":"1"}}}"#)))
                    .unwrap(),
            )
        });
        let connection =
            server_http1::Builder::new().serve_connection(TokioIo::new(stream), service);
        tokio::select! {
            _ = connection => {},
            _ = disconnected => {},
        }
    });
    let credential = directory.join("credential.json");
    std::fs::write(
        &credential,
        json!({"run_id":"01234567-89ab-4cde-8f01-23456789abcd",
            "run_token":"b".repeat(64),"service_token":"a".repeat(32)})
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut adapter = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&socket)
        .arg(&credential)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for_handoff_consumption(&credential, &mut adapter).await;
    let mut stdin = adapter.stdin.take().unwrap();
    let mut output = BufReader::new(adapter.stdout.take().unwrap()).lines();
    let mut stderr = adapter.stderr.take().unwrap();
    let init = rpc(
        &mut stdin,
        &mut output,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"dead-connection-control","version":"1"}}}),
    )
    .await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    let started = tokio::time::Instant::now();
    disconnect.send(()).unwrap();
    server.await.unwrap();
    // The stdin writer is deliberately retained throughout the wait. The
    // adapter must observe its Unix task's death, not wait for stdin EOF.
    let status =
        tokio::time::timeout(Duration::from_secs(3), adapter.wait()).await.unwrap().unwrap();
    assert!(!status.success());
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(output.next_line().await.unwrap().is_none(), "dead transport emitted a tool result");
    let mut diagnostic = Vec::new();
    stderr.read_to_end(&mut diagnostic).await.unwrap();
    assert_eq!(diagnostic, b"NHM AURA stdio transport refused\n");
    drop(stdin);
    std::fs::remove_dir_all(directory).unwrap();
}

struct SlowBody {
    delay: Pin<Box<tokio::time::Sleep>>,
    complete: bool,
    dropped: Arc<AtomicBool>,
}
impl SlowBody {
    fn new(dropped: Arc<AtomicBool>) -> Self {
        Self {
            delay: Box::pin(tokio::time::sleep(Duration::from_secs(10))),
            complete: false,
            dropped,
        }
    }
}
impl Drop for SlowBody {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}
impl HttpBody for SlowBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.complete {
            return Poll::Ready(None);
        }
        if self.delay.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }
        self.complete = true;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#,
        )))))
    }
}

async fn mock_refusal(sse: bool) {
    let directory = std::env::temp_dir().join(format!(
        "nhm-aura-mock-{}-{}",
        std::process::id(),
        tos_health_services::hex(&tos_health_services::random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.join("mcp.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let dropped = Arc::new(AtomicBool::new(false));
    let producer_dropped = dropped.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
            let calls = calls.clone();
            let producer_dropped = producer_dropped.clone();
            async move {
                assert_eq!(request.headers()["accept"], "application/json, text/event-stream");
                let index = calls.fetch_add(1, Ordering::SeqCst);
                let response = if index == 0 {
                    Response::builder()
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"mock","version":"1"}}}"#)))
                        .unwrap()
                } else if sse {
                    Response::builder()
                        .header("content-type", "text/event-stream")
                        .body(axum::body::Body::from(Bytes::from_static(
                            b"event: message\ndata: {}\n\n",
                        )))
                        .unwrap()
                } else {
                    Response::builder()
                        .header("content-type", "application/json")
                        .body(axum::body::Body::new(SlowBody::new(producer_dropped)))
                        .unwrap()
                };
                Ok::<_, Infallible>(response)
            }
        });
        let _ = server_http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
    });
    let credential = directory.join("credential.json");
    std::fs::write(
        &credential,
        json!({
            "run_id":"01234567-89ab-4cde-8f01-23456789abcd",
            "run_token":"b".repeat(64),
            "service_token":"a".repeat(32)
        })
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut adapter = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&socket)
        .arg(&credential)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for_handoff_consumption(&credential, &mut adapter).await;
    let mut stdin = adapter.stdin.take().unwrap();
    let mut output = BufReader::new(adapter.stdout.take().unwrap()).lines();
    let init = rpc(
        &mut stdin,
        &mut output,
        json!({"jsonrpc":"2.0","id":1,
        "method":"initialize","params":{"protocolVersion":"2025-06-18",
        "capabilities":{},"clientInfo":{"name":"mock","version":"1"}}}),
    )
    .await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(!credential.exists(), "mock handoff remained on disk");
    // Queue a third request before the second response. The adapter must not
    // forward it after an SSE refusal or the complete five-second deadline.
    stdin.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\",\"params\":{}}\n").await.unwrap();
    stdin.flush().await.unwrap();
    let start = tokio::time::Instant::now();
    let status =
        tokio::time::timeout(Duration::from_secs(7), adapter.wait()).await.unwrap().unwrap();
    assert!(!status.success(), "unsupported/slow response was accepted");
    assert!(start.elapsed() < Duration::from_secs(7), "tool deadline became whole-run deadline");
    assert_eq!(count.load(Ordering::SeqCst), 2, "a second tool call was forwarded after failure");
    if !sse {
        for _ in 0..50 {
            if dropped.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            dropped.load(Ordering::SeqCst),
            "slow response producer survived client termination"
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(1), output.next_line())
            .await
            .unwrap()
            .unwrap()
            .is_none(),
        "refusal produced a model-visible partial result"
    );
    server.abort();
    let _ = server.await;
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn sse_response_is_refused_without_forwarding_next_call() {
    mock_refusal(true).await;
}

#[tokio::test]
async fn tool_deadline_covers_complete_body_and_stops_next_call() {
    mock_refusal(false).await;
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
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(refused.stderr, b"NHM AURA stdio transport refused\n");
    eprintln!("NHM_AURA_REFUSAL exit=1 stderr=generic_only");
    assert!(!credential.exists(), "refused credential handoff remained on disk");
    let target = directory.join("target-credential.json");
    std::fs::write(
        &target,
        json!({"run_id":run,"run_token":grant["run_token"],
        "service_token":"a".repeat(32)})
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, &credential).unwrap();
    let linked = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&mcp)
        .arg(&credential)
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(!linked.status.success() && linked.stdout.is_empty());
    assert!(!credential.exists() && target.exists(), "symlink refusal touched target");
    std::fs::hard_link(&target, &credential).unwrap();
    let linked = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&mcp)
        .arg(&credential)
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(!linked.status.success() && linked.stdout.is_empty());
    assert!(!credential.exists() && target.exists(), "hardlink refusal touched target");
    std::fs::write(&credential, b"{invalid-json").unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let malformed = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&mcp)
        .arg(&credential)
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(!malformed.status.success() && malformed.stdout.is_empty());
    assert!(!credential.exists(), "malformed handoff remained on disk");
    std::fs::write(
        &credential,
        json!({"run_id":run,"run_token":grant["run_token"],
        "service_token":"a".repeat(32)})
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let no_socket = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(directory.join("missing.sock"))
        .arg(&credential)
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(!no_socket.status.success(), "missing Unix socket was admitted");
    assert!(no_socket.stdout.is_empty());
    assert!(!credential.exists(), "transport refusal retained credential handoff");
    std::fs::write(
        &credential,
        json!({"run_id":run,"run_token":grant["run_token"],
        "service_token":"a".repeat(32)})
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut adapter = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&mcp)
        .arg(&credential)
        .env("NHM_AURA_TRACE_PROTOCOL", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for_handoff_consumption(&credential, &mut adapter).await;
    let mut stdin = adapter.stdin.take().unwrap();
    let mut output = BufReader::new(adapter.stdout.take().unwrap()).lines();
    let mut stderr = adapter.stderr.take().unwrap();
    let initialized = rpc(
        &mut stdin,
        &mut output,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-03-26","capabilities":{},
            "clientInfo":{"name":"isolated-aura-transport-check","version":"1"}}}),
    )
    .await;
    assert_eq!(initialized["result"]["protocolVersion"], "2025-03-26");
    assert!(!credential.exists(), "connected adapter retained credential handoff");
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
    let adapter_status =
        tokio::time::timeout(Duration::from_secs(5), adapter.wait()).await.unwrap().unwrap();
    assert_eq!(adapter_status.code(), Some(0));
    eprintln!("NHM_AURA_EXIT exit=0");
    let mut diagnostic = Vec::new();
    stderr.read_to_end(&mut diagnostic).await.unwrap();
    assert_eq!(diagnostic, b"NHM_AURA_INIT version=2025-03-26 status=200 content_type=json\n");
    eprintln!("{}", String::from_utf8(diagnostic).unwrap().trim_end());
    std::fs::write(
        &credential,
        json!({"run_id":run,"run_token":grant["run_token"],
        "service_token":"a".repeat(32)})
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
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
    assert!(!credential.exists(), "replayed handoff remained on disk");
    service.kill().await.unwrap();
    service.wait().await.unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
