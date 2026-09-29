use axum::{body::Body, Router};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};
use tower::ServiceExt;

#[cfg(feature = "mcp")]
async fn serve_mcp(
    listener: tokio::net::UnixListener,
    state: tos_health_services::observability::ObservabilityState,
) -> Result<(), std::io::Error> {
    use http_body_util::{BodyExt, Full};
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager,
        tower::{StreamableHttpServerConfig, StreamableHttpService},
    };
    use subtle::ConstantTimeEq;
    type Service =
        StreamableHttpService<tos_health_services::mcp_bridge::McpBridge, LocalSessionManager>;
    let mut config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(["localhost", "127.0.0.1", "[::1]"])
        .enforce_origin_validation();
    config.legacy_session_mode = false;
    config.json_response = true;
    config.max_request_body_bytes = 16_384;
    let connections = Arc::new(tokio::sync::Semaphore::new(8));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let state = state.clone();
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // A connection owns exactly one durable grant claim. No model
            // argument can select or rebind that claim; reconnect fails closed.
            let binding = Arc::new(std::sync::Mutex::new(None::<(String, [u8; 32], Service)>));
            let transport = service_fn(move |request: hyper::Request<Incoming>| {
                let binding = binding.clone();
                let state = state.clone();
                let config = config.clone();
                async move {
                    let refuse = || {
                        hyper::Response::builder()
                            .status(hyper::StatusCode::UNAUTHORIZED)
                            .body(Full::new(axum::body::Bytes::new()).boxed())
                            .expect("fixed refusal response")
                    };
                    let header = |name| request.headers().get(name).and_then(|v| v.to_str().ok());
                    let service_header = header("authorization");
                    if !tos_health_services::authorized(service_header, &state.service_token)
                        || !matches!(header("host"), Some("localhost" | "127.0.0.1" | "[::1]"))
                        || header("origin").is_some()
                    {
                        return Ok::<_, std::convert::Infallible>(refuse());
                    }
                    let service = {
                        let mut bound = binding.lock().expect("MCP connection binding");
                        match bound.as_ref() {
                            Some((run, token, service)) => {
                                if header("x-tos-run-id").is_some_and(|value| value != run)
                                    || header("x-tos-run-token").is_some_and(|value| {
                                        tos_health_services::decode_token(value).is_none_or(
                                            |provided| provided.ct_eq(token).unwrap_u8() == 0,
                                        )
                                    })
                                {
                                    None
                                } else {
                                    Some((run.clone(), service.clone()))
                                }
                            }
                            None => {
                                let run = header("x-tos-run-id").unwrap_or_default();
                                let token_text = header("x-tos-run-token").unwrap_or_default();
                                match tos_health_services::mcp_bridge::McpBridge::admit(
                                    state.clone(),
                                    service_header,
                                    run,
                                    token_text,
                                ) {
                                    Ok(bridge) => {
                                        let token = tos_health_services::decode_token(token_text)
                                            .expect("admitted token");
                                        let service = StreamableHttpService::new(
                                            move || Ok(bridge.clone()),
                                            LocalSessionManager::default().into(),
                                            config,
                                        );
                                        *bound = Some((run.to_owned(), token, service.clone()));
                                        Some((run.to_owned(), service))
                                    }
                                    Err(_) => None,
                                }
                            }
                        }
                    };
                    let Some((run, service)) = service else { return Ok(refuse()) };
                    let response = service.oneshot(request).await?;
                    // Buffer the complete SDK body before sending any bytes. The
                    // transport wrapper is counted too, and an oversized/failed
                    // response cannot leak a partial uncharged result.
                    let (parts, body) = response.into_parts();
                    let Ok(collected) = http_body_util::Limited::new(body, 131_072).collect().await
                    else {
                        return Ok(hyper::Response::builder()
                            .status(hyper::StatusCode::PAYLOAD_TOO_LARGE)
                            .body(Full::new(axum::body::Bytes::new()).boxed())
                            .expect("fixed MCP size refusal"));
                    };
                    let bytes = collected.to_bytes();
                    let charged = state.query_ledger.as_ref().is_some_and(|ledger| {
                        ledger
                            .lock()
                            .expect("query ledger")
                            .charge_mcp_wire(&run, bytes.len())
                            .is_ok()
                    });
                    if !charged {
                        return Ok(hyper::Response::builder()
                            .status(hyper::StatusCode::TOO_MANY_REQUESTS)
                            .body(Full::new(axum::body::Bytes::new()).boxed())
                            .expect("fixed MCP budget refusal"));
                    }
                    Ok(hyper::Response::from_parts(parts, Full::new(bytes).boxed()))
                }
            });
            let _ = tokio::time::timeout(
                Duration::from_secs(200),
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(TokioIo::new(stream), transport),
            )
            .await;
        });
    }
}

async fn refresh_manager(
    state: tos_health_services::observability::ObservabilityState,
) -> Result<(), String> {
    let mut ticks = tokio::time::interval(Duration::from_secs(15));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Startup performs the first bounded import before either listener opens.
    ticks.tick().await;
    loop {
        ticks.tick().await;
        let state = state.clone();
        tokio::task::spawn_blocking(move || {
            let _ = tos_health_services::observability::import_manager(&state);
        })
        .await
        .map_err(|error| error.to_string())?;
    }
}

async fn serve_control(
    listener: tokio::net::UnixListener,
    app: Router,
    connections: Arc<tokio::sync::Semaphore>,
) -> Result<(), std::io::Error> {
    loop {
        let (stream, _) = listener.accept().await?;
        // Admission precedes the task spawn. The owned permit survives until
        // Hyper has finished this one non-keepalive connection, including
        // response transmission. Idle/header/body readers have a finite cap.
        let Ok(connection_permit) = connections.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let service = service_fn(move |request: hyper::Request<Incoming>| {
                let app = app.clone();
                async move { app.oneshot(request.map(Body::new)).await }
            });
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(stream), service),
            )
            .await;
        });
    }
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let max_args = if cfg!(feature = "mcp") { 11 } else { 10 };
    if !(8..=max_args).contains(&args.len()) {
        return Err("usage: tos-observability INVENTORY_JSON LOOPBACK_LISTEN OPERATOR_TOKEN INGEST_TOKEN SERVICE_TOKEN PRIVATE_QUERY_LEDGER_DB PRIVATE_CONTROL_SOCKET [CACHE_JSONL_OR_DASH] [MANAGER_EVIDENCE_DB] [PRIVATE_MCP_SOCKET_WITH_MCP_FEATURE]".into());
    }
    let raw = std::fs::read(&args[1])?;
    if raw.len() > 262_144 {
        return Err("inventory too large".into());
    }
    let inventory = serde_json::from_slice(&raw)?;
    let mut state = tos_health_services::observability::ObservabilityState::new(
        inventory,
        tos_health_services::secret(std::path::Path::new(&args[3]))?,
        tos_health_services::secret(std::path::Path::new(&args[4]))?,
        tos_health_services::secret(std::path::Path::new(&args[5]))?,
    )?
    .with_query_ledger(std::path::Path::new(&args[6]))?;
    if let Some(path) = args.get(9) {
        state = state.with_manager_evidence(path.into())?;
    }
    if let Some(path) = args.get(8).filter(|path| path.as_str() != "-") {
        tos_health_services::observability::import_cache(&state, path.into())?;
    }
    let socket_path = Path::new(&args[7]);
    let parent = socket_path.parent().ok_or("control socket must have a private parent")?;
    let parent_meta = std::fs::symlink_metadata(parent)?;
    if !parent_meta.is_dir() || parent_meta.permissions().mode() & 0o077 != 0 {
        return Err("control socket parent must be a private directory".into());
    }
    #[cfg(feature = "mcp")]
    let mcp_listener = if let Some(path) = args.get(10) {
        let path = Path::new(path);
        let parent = path.parent().ok_or("MCP socket must have a private parent")?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 || path == socket_path {
            return Err("MCP socket must differ from control and have a private parent".into());
        }
        let listener = tokio::net::UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Some(listener)
    } else {
        None
    };
    let control = tokio::net::UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    let listener = tokio::net::TcpListener::bind(tos_health_services::loopback(&args[2])?).await?;
    let tcp = axum::serve(listener, tos_health_services::observability::router(state.clone()));
    let refresh = state.manager_evidence_db.as_ref().map(|_| refresh_manager(state.clone()));
    let unix = serve_control(
        control,
        tos_health_services::observability::control_router(state.clone()),
        Arc::new(tokio::sync::Semaphore::new(8)),
    );
    #[cfg(feature = "mcp")]
    let mcp = async {
        match mcp_listener {
            Some(listener) => serve_mcp(listener, state.clone()).await?,
            None => std::future::pending().await,
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    #[cfg(not(feature = "mcp"))]
    let mcp = std::future::pending::<Result<(), Box<dyn std::error::Error>>>();
    tokio::select! {
        result = tcp => result?,
        result = unix => result?,
        result = mcp => result?,
        result = async { match refresh { Some(task) => task.await, None => std::future::pending().await } } => result?,
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn socket() -> (std::path::PathBuf, tokio::net::UnixListener) {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path =
            std::env::temp_dir().join(format!("nhm-control-{}-{nanos}.sock", std::process::id()));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        (path, listener)
    }
    async fn wait_permits(limit: &tokio::sync::Semaphore, expected: usize, timeout: Duration) {
        tokio::time::timeout(timeout, async {
            while limit.available_permits() != expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn eight_idle_control_connections_are_bounded_and_expire() {
        let (path, listener) = socket();
        let limit = Arc::new(tokio::sync::Semaphore::new(8));
        let app = Router::new().route("/ok", get(|| async { "ok" }));
        let task = tokio::spawn(serve_control(listener, app, limit.clone()));
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(tokio::net::UnixStream::connect(&path).await.unwrap());
        }
        wait_permits(&limit, 0, Duration::from_secs(2)).await;
        let mut ninth = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), ninth.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        wait_permits(&limit, 8, Duration::from_secs(6)).await;
        let mut accepted = tokio::net::UnixStream::connect(&path).await.unwrap();
        accepted.write_all(b"GET /ok HTTP/1.1\r\nHost: local\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), accepted.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        task.abort();
        drop(held);
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn control_permit_covers_the_slow_request_until_connection_finishes() {
        let (path, listener) = socket();
        let limit = Arc::new(tokio::sync::Semaphore::new(1));
        let app = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                "done"
            }),
        );
        let task = tokio::spawn(serve_control(listener, app, limit.clone()));
        let mut first = tokio::net::UnixStream::connect(&path).await.unwrap();
        first.write_all(b"GET /slow HTTP/1.1\r\nHost: local\r\n\r\n").await.unwrap();
        wait_permits(&limit, 0, Duration::from_secs(2)).await;
        let mut second = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), second.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), first.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        wait_permits(&limit, 1, Duration::from_secs(2)).await;
        task.abort();
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(feature = "mcp")]
    #[tokio::test]
    async fn mcp_unix_connection_binds_one_durable_grant_and_rejects_replay() {
        use axum::{body::Body, http::Request};
        use http_body_util::{BodyExt, Full};
        use serde_json::{json, Value};
        use std::collections::BTreeSet;
        use tos_health_services::{
            observability::{control_router, ObservabilityState},
            Inventory,
        };

        let directory = std::env::temp_dir().join(format!(
            "nhm-mcp-unix-{}-{}",
            std::process::id(),
            tos_health_services::hex(&tos_health_services::random_token().unwrap())
        ));
        std::fs::create_dir(&directory).unwrap();
        let state = ObservabilityState::new(
            Inventory {
                network_id: "a".repeat(64),
                nodes: BTreeSet::from(["v1".into()]),
                scopes: BTreeSet::from(["node".into()]),
            },
            vec![b'o'; 32],
            vec![b'i'; 32],
            vec![b'a'; 32],
        )
        .unwrap()
        .with_query_ledger(&directory.join("query.sqlite"))
        .unwrap();
        let grant = control_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/control/grants")
                    .header("authorization", format!("Bearer {}", "o".repeat(32)))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"node_ids":["v1"],"scope_ids":["node"],
                "start":"2026-09-01T00:00:00Z","end":"2026-09-01T00:01:00Z"})
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(grant.status().is_success());
        let grant: Value =
            serde_json::from_slice(&axum::body::to_bytes(grant.into_body(), 4096).await.unwrap())
                .unwrap();
        let run = grant["run_id"].as_str().unwrap();
        let token = grant["run_token"].as_str().unwrap();
        let path = directory.join("mcp.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(serve_mcp(listener, state.clone()));

        let request = |id: u32, method: &str, params: Value, token_header: Option<&str>| {
            let mut builder = hyper::Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "localhost")
                .header("authorization", format!("Bearer {}", "a".repeat(32)))
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .header("mcp-protocol-version", "2025-06-18");
            if let Some(token_header) = token_header {
                builder =
                    builder.header("x-tos-run-id", run).header("x-tos-run-token", token_header);
            }
            builder
                .body(Full::new(axum::body::Bytes::from(
                    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string(),
                )))
                .unwrap()
        };
        let connect = || async {
            let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
            let (sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            (sender, task)
        };
        let init = || {
            json!({"protocolVersion":"2025-06-18","capabilities":{},
                             "clientInfo":{"name":"bounded-test","version":"1"}})
        };
        let (mut wrong, wrong_task) = connect().await;
        let refused = wrong
            .send_request(request(1, "initialize", init(), Some(&"0".repeat(64))))
            .await
            .unwrap();
        assert_eq!(refused.status(), hyper::StatusCode::UNAUTHORIZED);
        drop(wrong);
        wrong_task.abort();

        let (mut client, client_task) = connect().await;
        let initialized =
            client.send_request(request(2, "initialize", init(), Some(token))).await.unwrap();
        assert!(initialized.status().is_success(), "{}", initialized.status());
        let init_bytes = initialized.into_body().collect().await.unwrap().to_bytes();
        let listed = client.send_request(request(3, "tools/list", json!({}), None)).await.unwrap();
        assert!(listed.status().is_success(), "{}", listed.status());
        let list_bytes = listed.into_body().collect().await.unwrap().to_bytes();
        let listed: Value = serde_json::from_slice(&list_bytes).unwrap();
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 6);
        let called = client
            .send_request(request(
                4,
                "tools/call",
                json!({
                    "name":"tos_get_capabilities","arguments":{"run_id":run}
                }),
                None,
            ))
            .await
            .unwrap();
        assert!(called.status().is_success(), "{}", called.status());
        let call_bytes = called.into_body().collect().await.unwrap().to_bytes();
        let called: Value = serde_json::from_slice(&call_bytes).unwrap();
        assert_eq!(called["result"]["isError"], false, "{called}");
        assert!(!called.to_string().contains(token));
        assert_eq!(
            state.query_ledger.as_ref().unwrap().lock().unwrap().mcp_usage(run).unwrap(),
            Some((1, (init_bytes.len() + list_bytes.len() + call_bytes.len()) as u64))
        );

        let (mut replay, replay_task) = connect().await;
        let refused =
            replay.send_request(request(5, "initialize", init(), Some(token))).await.unwrap();
        assert_eq!(refused.status(), hyper::StatusCode::UNAUTHORIZED);
        drop(replay);
        replay_task.abort();
        drop(client);
        client_task.abort();
        server.abort();
        drop(state);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
