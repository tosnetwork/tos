use super::{IngressConfig, Peer, Role};
use axum::{routing::get, Router};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
#[allow(dead_code)]
#[path = "ingress_tls.rs"]
mod tls;
use tls::{client_with_timeout, fingerprint, fixture, idle_tls};
const WAIT: Duration = Duration::from_secs(60);
struct AbortTask<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for AbortTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
#[tokio::test]
async fn seven_slow_regular_requests_leave_classified_heartbeat_capacity() {
    regular_capacity(None, false).await;
}

#[tokio::test]
async fn configured_regular_requests_reserve_heartbeat_and_release_permits() {
    regular_capacity(Some(9), false).await;
}

#[tokio::test]
async fn configured_regular_permits_release_on_client_disconnect() {
    regular_capacity(Some(2), true).await;
}

async fn regular_capacity(configured_limit: Option<usize>, disconnect_first: bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let t = fixture();
    let limit = configured_limit.unwrap_or(7);
    let slow_calls = Arc::new(AtomicUsize::new(0));
    let count = slow_calls.clone();
    let large = format!("{}# EOF\n", "x".repeat(2_097_146));
    assert_eq!(large.len(), 2_097_152);
    let edge = Router::new()
        .route(
            "/metrics",
            get(move || {
                let count = count.clone();
                let large = large.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    large
                }
            }),
        )
        .route("/v1/edge/heartbeat", get(|| async { "ok" }));
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = up.local_addr().unwrap();
    let upstream_task =
        AbortTask(tokio::spawn(async move { axum::serve(up, edge).await.unwrap() }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    // Accepted sockets inherit this bound, so the full response cannot fit in
    // the kernel send queue while the client deliberately stops reading.
    use std::os::fd::AsRawFd;
    let send_buffer: libc::c_int = 16_384;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&send_buffer as *const libc::c_int).cast(),
                std::mem::size_of_val(&send_buffer).try_into().unwrap(),
            )
        },
        0
    );
    let address = listener.local_addr().unwrap();
    let config = IngressConfig {
        listen: address,
        witness_endpoints: vec![],
        regular_request_limit: configured_limit.unwrap_or(7),
        rate_per_second: 64,
        burst: 256,
        server_name: "localhost".into(),
        upstream,
        cert_file: t.0.join("server.pem"),
        key_file: t.0.join("server.key"),
        ca_file: t.0.join("ca.pem"),
        peers: vec![
            Peer {
                alias: "reader".into(),
                certificate_sha256: fingerprint(&t.0, "client"),
                role: Role::EdgeReader,
            },
            Peer {
                alias: "watchdog".into(),
                certificate_sha256: fingerprint(&t.0, "watchdog"),
                role: Role::EdgeWatchdog,
            },
        ],
    };
    // Exercise serde's omitted-field default, not just a hand-written literal.
    let mut json = serde_json::to_value(&config).unwrap();
    if configured_limit.is_none() {
        json.as_object_mut().unwrap().remove("regular_request_limit");
    }
    let config: IngressConfig = serde_json::from_value(json).unwrap();
    assert_eq!(config.regular_request_limit, limit, "default/configured regular limit");
    let server = AbortTask(tokio::spawn(super::serve_with_deadlines(
        config,
        listener,
        super::Deadlines {
            tls: WAIT,
            headers: WAIT,
            upstream: WAIT,
            connection: Duration::from_secs(180),
        },
    )));
    let mut setup = tokio::task::JoinSet::new();
    for _ in 0..limit {
        let dir = t.0.clone();
        setup.spawn(async move {
            let mut stream = idle_tls(&dir, address, "client").await;
            stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut first = [0];
            tokio::time::timeout(WAIT, stream.read_exact(&mut first))
                .await
                .expect("response did not become ready")
                .unwrap();
            assert_eq!(first, [b'H']);
            stream
        });
    }
    let mut pending = Vec::new();
    tokio::time::timeout(WAIT, async {
        while let Some(result) = setup.join_next().await {
            pending.push(result.unwrap());
        }
    })
    .await
    .expect("concurrent setup did not finish");
    assert_eq!(slow_calls.load(Ordering::SeqCst), limit);

    let heartbeat = format!("https://localhost:{}/v1/edge/heartbeat", address.port());
    let metrics = format!("https://localhost:{}/metrics", address.port());
    let reader = client_with_timeout(&t.0, Some("client"), WAIT);
    assert_eq!(
        reader
            .get(&metrics)
            .header("authorization", format!("Bearer {}", "e".repeat(32)))
            .send()
            .await
            .unwrap()
            .status(),
        429,
        "limit+1 ordinary request bypassed the classified reserve"
    );
    assert_eq!(slow_calls.load(Ordering::SeqCst), limit);
    assert_eq!(
        reader
            .get(&heartbeat)
            .header("authorization", format!("Bearer {}", "e".repeat(32)))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "classified EdgeReader heartbeat"
    );

    // Untouched clients remain blocked on output until every admission assertion finishes.
    let released = pending.pop().unwrap();
    if disconnect_first {
        drop(released);
    } else {
        drain_complete(released).await;
    }
    tokio::time::timeout(WAIT, async {
        loop {
            let response = reader.get(&metrics).send().await.unwrap();
            let status = response.status();
            let bytes = response.bytes().await.unwrap();
            if status == 200 {
                assert_eq!(bytes.len(), 2_097_152);
                break;
            }
            assert_eq!(status, 429, "unexpected release response");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("released connection did not release permits");
    assert_eq!(slow_calls.load(Ordering::SeqCst), limit + 1);
    assert_eq!(
        client_with_timeout(&t.0, Some("watchdog"), WAIT)
            .get(&heartbeat)
            .header("authorization", format!("Bearer {}", "e".repeat(32)))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "classified EdgeWatchdog heartbeat"
    );
    for stream in pending {
        drain_complete(stream).await;
    }
    drop(server);
    drop(upstream_task);
}

async fn drain_complete(mut stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>) {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut bytes))
        .await
        .expect("response drain did not finish")
        .unwrap();
    assert!(bytes.starts_with(b"TTP/1.1 200"), "untouched connection did not stay live");
    let split = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    assert_eq!(bytes[split + 4..].len(), 2_097_152, "response expired before drain completed");
    assert!(bytes.ends_with(b"# EOF\n"));
}
