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
use tos_health_core::{
    edge_snapshot::{ProcessEnvelope, ProcessPayload},
    evidence::Evidence,
    native::{canonical_hash, Coverage as NativeCoverage, Quality, SourceEnvelope},
    query::TOOLS,
    query_output::ToolEnvelope,
    source::{Availability, Coverage, SourceQuality},
    wire::U64,
};
use tos_health_services::durable::{DurableEvidence, EvidenceDb};

/// One archived process observation for node `v1`, observed at a fixed
/// instant so a grant window around that instant returns it as evidence.
const ROW_OBSERVED_AT: &str = "2026-09-29T00:00:01.000Z";
fn process_row(epoch: &str) -> DurableEvidence {
    let timestamp =
        chrono::DateTime::parse_from_rfc3339(ROW_OBSERVED_AT).unwrap().timestamp_millis();
    let payload = ProcessPayload {
        kind: "process".into(),
        pid: 4242,
        rss_bytes: Some(U64(4096)),
        anon_bytes: None,
        file_bytes: None,
        swap_bytes: None,
        cpu_user_ticks: Some(U64(7)),
        cpu_system_ticks: Some(U64(3)),
    };
    let source: ProcessEnvelope = SourceEnvelope {
        schema_version: 1,
        source_id: "process".into(),
        node_id: "v1".into(),
        scope_id: "node".into(),
        process_epoch: "boot:4242:100".into(),
        source_epoch: epoch.into(),
        source_version: "proc-v1".into(),
        generation: U64(1),
        availability: "available".into(),
        observed_at: Some(ROW_OBSERVED_AT.into()),
        last_success_at: Some(ROW_OBSERVED_AT.into()),
        received_at: None,
        source_age_ms: None,
        clock_quality: "valid".into(),
        coverage: NativeCoverage {
            status: "partial".into(),
            missing_fields: vec!["host_pressure".into()],
            gaps: vec![],
            sampling_policy: "fixed_15s".into(),
        },
        content_hash: canonical_hash(&payload).unwrap(),
        payload,
        quality: Quality {
            instrumentation_complete: false,
            producer_dropped: U64(0),
            relay_dropped: U64(0),
            parse_errors: U64(0),
            shed_reason: None,
        },
    };
    DurableEvidence {
        source_epoch: epoch.into(),
        record: Evidence {
            node_id: "v1".into(),
            scope_id: "node".into(),
            source_id: "process".into(),
            source_record_id: format!("{epoch}:1"),
            process_epoch: "boot:4242:100".into(),
            observed_at_ms: timestamp,
            received_at_ms: timestamp + 1000,
            quality: SourceQuality {
                availability: Availability::Available,
                coverage: Coverage::Partial,
                observed_at_ms: Some(timestamp),
                last_success_at_ms: Some(timestamp),
                clock_valid: true,
                process_epoch: "boot:4242:100".into(),
                source_sequence: "1".into(),
            },
            payload: json!({"component":"process","source":source}),
            redacted: true,
        },
    }
}

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
    let requests = Arc::new(AtomicUsize::new(0));
    let served = requests.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(move |_request: Request<hyper::body::Incoming>| {
            let served = served.clone();
            async move {
                served.fetch_add(1, Ordering::SeqCst);
                Ok::<_, Infallible>(
                Response::builder()
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"mock","version":"1"}}}"#)))
                    .unwrap(),
                )
            }
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
    // Even if this write races with the adapter's prompt exit, no second
    // tools/list frame may cross the dead connection or reach model stdout.
    if stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n")
        .await
        .is_ok()
    {
        let _ = stdin.flush().await;
    }
    // The stdin writer is deliberately retained throughout the wait. The
    // adapter must observe its Unix task's death, not wait for stdin EOF.
    let status =
        tokio::time::timeout(Duration::from_secs(3), adapter.wait()).await.unwrap().unwrap();
    assert!(!status.success());
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(requests.load(Ordering::SeqCst), 1, "second tool request reached dead server");
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

#[tokio::test]
async fn stdio_adapter_writes_an_evidence_log_bound_to_the_run() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-aura-log-{}-{}",
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
    // M holds one archived process row for v1; Q imports it at start, so the
    // node-snapshot tool returns real evidence for the log to bind.
    let manager = directory.join("manager.sqlite");
    {
        let mut db = EvidenceDb::open(&manager, 4 * 1024 * 1024).unwrap();
        db.bind_network(&"a".repeat(64)).unwrap();
        db.insert(process_row("edge-epoch-log")).unwrap();
    }
    let mut service = Command::new(env!("CARGO_BIN_EXE_tos-observability"))
        .arg(&inventory)
        .arg("127.0.0.1:0")
        .arg(directory.join("operator"))
        .arg(directory.join("ingest"))
        .arg(directory.join("service"))
        .arg(directory.join("query.sqlite"))
        .arg(&control)
        .arg("-")
        .arg(&manager)
        .arg(&mcp)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for_socket(&control).await;
    wait_for_socket(&mcp).await;
    // The grant window surrounds the archived row's observation instant.
    let start = "2026-09-29T00:00:00.000Z".to_owned();
    let end = "2026-09-29T00:01:00.000Z".to_owned();
    let credential = directory.join("credential.json");
    let write_credential = |grant: &Value| {
        std::fs::write(
            &credential,
            json!({"run_id":grant["run_id"],"run_token":grant["run_token"],
            "service_token":"a".repeat(32)})
            .to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    // A log path that already exists is refused before the handoff is consumed.
    let stale = directory.join("stale.jsonl");
    std::fs::write(&stale, b"left over\n").unwrap();
    let grant = control_grant(&control, &start, &end).await;
    write_credential(&grant);
    let refused = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&mcp)
        .arg(&credential)
        .arg(&stale)
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(!refused.status.success(), "a pre-existing evidence log was accepted");
    assert!(refused.stdout.is_empty());
    assert_eq!(std::fs::read(&stale).unwrap(), b"left over\n", "stale log was touched");
    assert!(credential.exists(), "a refused log must not consume the one-use handoff");
    std::fs::remove_file(&credential).unwrap();
    // The real run: six calls, one log line each, ids equal to what stdio returned.
    let grant = control_grant(&control, &start, &end).await;
    let run = grant["run_id"].as_str().unwrap().to_owned();
    write_credential(&grant);
    let log = directory.join("evidence.jsonl");
    let mut adapter = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&mcp)
        .arg(&credential)
        .arg(&log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for_handoff_consumption(&credential, &mut adapter).await;
    let mut stdin = adapter.stdin.take().unwrap();
    let mut output = BufReader::new(adapter.stdout.take().unwrap()).lines();
    let initialized = rpc(
        &mut stdin,
        &mut output,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"evidence-log-check","version":"1"}}}),
    )
    .await;
    assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let inputs = [
        json!({"run_id":run}),
        json!({"run_id":run,"node_id":"v1","as_of":end,"max_age_seconds":120,"components":["process"]}),
        json!({"run_id":run,"node_ids":["v1"],"metric_ids":["rss_bytes"],"scope_id":"node","start":start,"end":end,"step_seconds":15,"mode":"raw","max_points_per_series":10}),
        json!({"run_id":run,"node_ids":["v1"],"scope_id":"node","start":start,"end":end,"sources":["collector"],"kinds":["warning"],"correlation_id":"","contains":"","limit":10,"cursor":""}),
        json!({"run_id":run,"node_ids":["v1"],"start":start,"end":end,"kinds":["config"],"limit":10,"cursor":""}),
        json!({"run_id":run,"node_ids":["v1"],"reference_id":"blk_0123456789abcdef","ancestor_depth":0,"max_events":10}),
    ];
    let mut returned: Vec<(String, Vec<String>, String)> = Vec::new();
    for (index, (name, arguments)) in TOOLS.into_iter().zip(inputs).enumerate() {
        let result = rpc(
            &mut stdin,
            &mut output,
            json!({"jsonrpc":"2.0","id":index + 2,"method":"tools/call","params":{
                "name":name,"arguments":arguments}}),
        )
        .await;
        let text = result["result"]["content"][0]["text"].as_str().unwrap();
        let envelope: ToolEnvelope = serde_json::from_str(text).unwrap();
        let ids = envelope.evidence.iter().map(|item| item.evidence_id.clone()).collect();
        returned.push((name.to_owned(), ids, envelope.request_id));
    }
    drop(stdin);
    let status =
        tokio::time::timeout(Duration::from_secs(5), adapter.wait()).await.unwrap().unwrap();
    assert_eq!(status.code(), Some(0));
    let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "evidence log mode {mode:o}");
    let lines: Vec<Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), TOOLS.len(), "one log line per tool call");
    assert!(
        lines
            .iter()
            .any(|line| line["error"] == false && !line["evidence"].as_array().unwrap().is_empty()),
        "at least one successful call must have logged evidence"
    );
    for ((name, ids, request_id), line) in returned.iter().zip(&lines) {
        assert_eq!(line["tool"], *name);
        assert_eq!(line["request_id"], *request_id);
        let logged: Vec<String> = line["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["evidence_id"].as_str().unwrap().to_owned())
            .collect();
        if line["error"] == true {
            // A tool that answered with an error envelope is counted, with no
            // evidence attributed to it.
            assert!(logged.is_empty(), "{name}: error call logged evidence");
            continue;
        }
        assert_eq!(&logged, ids, "{name}: logged ids differ from the returned ids");
        for item in line["evidence"].as_array().unwrap() {
            assert_eq!(item["node_id"], "v1");
            assert!(item["content_hash"].as_str().is_some_and(|hash| hash.len() == 64));
            assert!(item.get("payload").is_none(), "payload must not reach the log");
        }
    }
    let serialized = std::fs::read_to_string(&log).unwrap();
    assert!(!serialized.contains(grant["run_token"].as_str().unwrap()));
    assert!(!serialized.contains(&"a".repeat(32)), "service token reached the log");
    service.kill().await.unwrap();
    service.wait().await.unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

/// Real clients open with frames the private endpoint does not serve: a
/// `server/discover` probe with an id, notifications for roots, and an
/// `initialize` naming a protocol version newer than the endpoint's. The
/// adapter must answer the probe with method-not-found, drop the notification,
/// forward the handshake with a version the endpoint serves, and keep the
/// session alive for the tools. Before this it exited on the first frame.
#[tokio::test]
async fn stdio_adapter_survives_client_probes_and_negotiates_a_served_version() {
    // Short name: the Unix socket path below must stay under the AF_UNIX limit.
    let directory = std::env::temp_dir().join(format!(
        "nhm-neg-{}-{}",
        std::process::id(),
        &tos_health_services::hex(&tos_health_services::random_token().unwrap())[..16]
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
    let credential = directory.join("credential.json");
    std::fs::write(
        &credential,
        json!({"run_id":run,"run_token":grant["run_token"],"service_token":"a".repeat(32)})
            .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut adapter = Command::new(env!("CARGO_BIN_EXE_tos-nhm-aura-stdio"))
        .arg(&mcp)
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
    // A probe the endpoint does not serve is answered locally, not fatal.
    let probe = rpc(
        &mut stdin,
        &mut output,
        json!({"jsonrpc":"2.0","id":"server-discover-probe-1","method":"server/discover","params":{}}),
    )
    .await;
    assert_eq!(probe["id"], "server-discover-probe-1");
    assert_eq!(probe["error"]["code"], -32601);
    // An unknown notification is dropped silently.
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/roots/list_changed\"}\n")
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    // A newer protocol version is negotiated down to one the endpoint serves.
    let initialized = rpc(
        &mut stdin,
        &mut output,
        json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{"roots":{"listChanged":true}},
            "clientInfo":{"name":"claude-code","version":"2.1"}}}),
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
    // An unknown tool is refused locally with invalid params; the session continues.
    let unknown = rpc(
        &mut stdin,
        &mut output,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"tos_delete_everything","arguments":{}}}),
    )
    .await;
    assert_eq!(unknown["error"]["code"], -32602);
    let listed_again = rpc(
        &mut stdin,
        &mut output,
        json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}),
    )
    .await;
    assert_eq!(listed_again["result"]["tools"].as_array().unwrap().len(), TOOLS.len());
    drop(stdin);
    let status =
        tokio::time::timeout(Duration::from_secs(10), adapter.wait()).await.unwrap().unwrap();
    assert!(status.success(), "adapter did not exit cleanly after stdin closed");
    service.kill().await.unwrap();
    let _ = std::fs::remove_dir_all(&directory);
}
