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
impl<T> AbortTask<T> {
    async fn stop(&mut self) {
        self.0.abort();
        assert!(tokio::time::timeout(WAIT, &mut self.0)
            .await
            .expect("server task did not stop")
            .is_err());
    }
}
impl<T> Drop for AbortTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
#[tokio::test]
async fn regular_capacity_is_event_driven() {
    regular_capacity(None, false).await;
    regular_capacity(Some(9), false).await;
    regular_capacity(Some(2), true).await;
}

async fn regular_capacity(configured_limit: Option<usize>, disconnect_first: bool) {
    let t = fixture();
    let limit = configured_limit.unwrap_or(7);
    let slow_calls = Arc::new(AtomicUsize::new(0));
    let count = slow_calls.clone();
    let payload = format!("{}# EOF\n", "x".repeat(1_018));
    assert_eq!(payload.len(), 1_024);
    let edge = Router::new()
        .route(
            "/metrics",
            get(move || {
                let count = count.clone();
                let payload = payload.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    payload
                }
            }),
        )
        .route("/v1/edge/heartbeat", get(|| async { "ok" }));
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = up.local_addr().unwrap();
    let mut upstream_task =
        AbortTask(tokio::spawn(async move { axum::serve(up, edge).await.unwrap() }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
    let hooks = Instrumentation((0..=limit + 4).map(|_| Arc::new(Gate::new())).collect());
    let guards: Vec<_> = hooks.0.iter().map(|gate| GateGuard(gate.clone())).collect();
    let mut server = AbortTask(tokio::spawn(super::serve_with_deadlines(
        config,
        listener,
        super::Deadlines {
            tls: WAIT,
            headers: WAIT,
            upstream: WAIT,
            connection: Duration::from_secs(180),
        },
        Some(hooks.clone()),
    )));
    let mut setup = tokio::task::JoinSet::new();
    for id in 0..limit {
        let dir = t.0.clone();
        let gate = hooks.0[id].clone();
        setup.spawn(async move { (held_request(&dir, address, id, &gate).await, gate) });
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
    checked_reply(
        &reader,
        &metrics,
        limit + 1,
        &hooks,
        429,
        "limit+1 ordinary request bypassed the classified reserve",
    )
    .await;
    assert_eq!(slow_calls.load(Ordering::SeqCst), limit);
    checked_reply(&reader, &heartbeat, limit + 2, &hooks, 200, "classified EdgeReader heartbeat")
        .await;

    // Untouched clients remain blocked on output until every admission assertion finishes.
    let (released, gate) = pending.pop().unwrap();
    if disconnect_first {
        drop(released);
        gate.wait_done().await;
        assert!(
            !gate.opened.load(Ordering::SeqCst),
            "disconnect completed only after opening output"
        );
    } else {
        gate.open();
        drain_complete(released).await;
        gate.wait_done().await;
    }
    assert!(
        pending
            .iter()
            .all(|(_, gate)| !gate.opened.load(Ordering::SeqCst)
                && !gate.done.load(Ordering::SeqCst)),
        "untouched connections stopped being blocked"
    );
    let replacement_gate = hooks.0[limit].clone();
    let replacement = held_request(&t.0, address, limit, &replacement_gate).await;
    pending.push((replacement, replacement_gate));
    checked_reply(
        &reader,
        &metrics,
        limit + 3,
        &hooks,
        429,
        "replacement plus untouched connections did not saturate the regular slots",
    )
    .await;
    assert_eq!(slow_calls.load(Ordering::SeqCst), limit + 1);
    checked_reply(
        &client_with_timeout(&t.0, Some("watchdog"), WAIT),
        &heartbeat,
        limit + 4,
        &hooks,
        200,
        "classified EdgeWatchdog heartbeat",
    )
    .await;
    let mut drains = tokio::task::JoinSet::new();
    for (stream, gate) in pending {
        gate.open();
        drains.spawn(async move {
            drain_complete(stream).await;
            gate.wait_done().await;
        });
    }
    tokio::time::timeout(WAIT, async {
        while let Some(result) = drains.join_next().await {
            result.unwrap();
        }
    })
    .await
    .expect("concurrent drains did not finish");
    drop(guards);
    server.stop().await;
    upstream_task.stop().await;
}

async fn checked_reply(
    client: &reqwest::Client,
    url: &str,
    id: usize,
    hooks: &Instrumentation,
    expected: u16,
    message: &str,
) {
    let response = client.get(url).header("x-test-completion", id).send().await.unwrap();
    assert_eq!(response.status().as_u16(), expected, "{message}");
    response.bytes().await.unwrap();
    // Even an empty body can arrive before the connection task drops its
    // total slot. Observe that Drop before issuing the next capacity probe.
    hooks.0[id].wait_done().await;
}

async fn held_request(
    dir: &std::path::Path,
    address: std::net::SocketAddr,
    id: usize,
    gate: &Gate,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(WAIT, async {
        let mut stream = idle_tls(dir, address, "client").await;
        stream.write_all(format!("GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nx-test-gate: {id}\r\n\r\n").as_bytes()).await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 4096, "response headers exceeded the test bound");
            header.push(stream.read_u8().await.unwrap());
        }
        assert!(header.starts_with(b"HTTP/1.1 200"), "released connection did not release permits: {}", String::from_utf8_lossy(&header));
        gate.wait_blocked().await;
        stream
    }).await.expect("response did not become ready")
}

async fn drain_complete(mut stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>) {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut bytes))
        .await
        .expect("response drain did not finish")
        .unwrap();
    assert_eq!(bytes.len(), 1_024, "response expired before drain completed");
    assert_eq!(bytes, format!("{}# EOF\n", "x".repeat(1_018)).as_bytes());
}

#[derive(Clone)]
pub(super) struct Instrumentation(Vec<Arc<Gate>>);
impl Instrumentation {
    pub(super) fn for_request(
        &self,
        request: &hyper::Request<hyper::body::Incoming>,
    ) -> Option<(Arc<Gate>, bool)> {
        let (id, hold) = match request.headers().get("x-test-gate") {
            Some(id) => (id, true),
            None => (request.headers().get("x-test-completion")?, false),
        };
        let id: usize = id.to_str().ok()?.parse().ok()?;
        self.0.get(id).cloned().map(|gate| (gate, hold))
    }
}

pub(super) struct Gate {
    opened: std::sync::atomic::AtomicBool,
    blocked: std::sync::atomic::AtomicBool,
    done: std::sync::atomic::AtomicBool,
    events: tokio::sync::Notify,
    open_tx: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    open_rx: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}
impl Gate {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            opened: false.into(),
            blocked: false.into(),
            done: false.into(),
            events: tokio::sync::Notify::new(),
            open_tx: std::sync::Mutex::new(Some(tx)),
            open_rx: std::sync::Mutex::new(Some(rx)),
        }
    }
    fn open(&self) {
        self.opened.store(true, Ordering::SeqCst);
        if let Some(tx) = self.open_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }
    async fn wait_flag(&self, flag: &std::sync::atomic::AtomicBool, message: &str) {
        tokio::time::timeout(WAIT, async {
            loop {
                let event = self.events.notified();
                tokio::pin!(event);
                event.as_mut().enable();
                if flag.load(Ordering::SeqCst) {
                    break;
                }
                event.await;
            }
        })
        .await
        .expect(message);
    }
    async fn wait_blocked(&self) {
        self.wait_flag(&self.blocked, "response gate was not reached").await;
    }
    async fn wait_done(&self) {
        self.wait_flag(&self.done, "connection teardown did not finish").await;
    }
}
struct GateGuard(Arc<Gate>);
impl Drop for GateGuard {
    fn drop(&mut self) {
        self.0.open();
    }
}

// Declared before the connection permit so its Drop reports teardown only
// after the HTTP future, TLS stream and both permit-owning scopes are gone.
#[derive(Default)]
pub(super) struct Completion {
    pub(super) gate: Arc<std::sync::Mutex<Option<Arc<Gate>>>>,
}
impl Drop for Completion {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.lock().unwrap().take() {
            gate.done.store(true, Ordering::SeqCst);
            gate.events.notify_waiters();
        }
    }
}

struct GatedBody {
    bytes: hyper::body::Bytes,
    prefix_sent: bool,
    rx: tokio::sync::oneshot::Receiver<()>,
    gate: Arc<Gate>,
}
impl hyper::body::Body for GatedBody {
    type Data = hyper::body::Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::{future::Future, task::Poll};
        if self.bytes.is_empty() {
            return Poll::Ready(None);
        }
        if !self.prefix_sent {
            self.prefix_sent = true;
            let prefix = self.bytes.split_to(1);
            return Poll::Ready(Some(Ok(hyper::body::Frame::data(prefix))));
        }
        self.gate.blocked.store(true, Ordering::SeqCst);
        self.gate.events.notify_waiters();
        if std::pin::Pin::new(&mut self.rx).poll(cx).is_pending() {
            return Poll::Pending;
        }
        Poll::Ready(Some(Ok(hyper::body::Frame::data(std::mem::take(&mut self.bytes)))))
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.bytes.len().try_into().unwrap())
    }
}
pub(super) async fn gate_response(
    answer: Result<hyper::Response<axum::body::Body>, std::convert::Infallible>,
    gate: Arc<Gate>,
) -> Result<hyper::Response<axum::body::Body>, std::convert::Infallible> {
    let (parts, body) = answer.unwrap().into_parts();
    let bytes = axum::body::to_bytes(body, 1024).await.unwrap();
    let rx = gate.open_rx.lock().unwrap().take().unwrap();
    Ok(hyper::Response::from_parts(
        parts,
        axum::body::Body::new(GatedBody { bytes, prefix_sent: false, rx, gate }),
    ))
}
