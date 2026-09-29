//! Fixed-route mTLS ingress. No URL, method, DNS or credential passthrough selection.
use axum::body::Body;
use hyper::{body::Incoming, service::service_fn, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    },
    TlsAcceptor,
};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub alias: String,
    pub certificate_sha256: String,
    pub role: Role,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    EdgeReader,
    EdgeWatchdog,
    ManagerIngest,
    ManagerReader,
    PipelineSender,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressConfig {
    pub listen: SocketAddr,
    pub server_name: String,
    pub upstream: SocketAddr,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub ca_file: PathBuf,
    pub peers: Vec<Peer>,
}
struct Bucket {
    at: Instant,
    tokens: u32,
}
impl Bucket {
    fn new() -> Self {
        Self { at: Instant::now(), tokens: 4 }
    }
    fn take(&mut self, reserve: bool) -> bool {
        let elapsed = self.at.elapsed().as_secs();
        if elapsed > 0 {
            self.tokens = self.tokens.saturating_add(elapsed.min(4) as u32).min(4);
            self.at += Duration::from_secs(elapsed);
        }
        if self.tokens <= u32::from(reserve) {
            return false;
        }
        self.tokens -= 1;
        true
    }
}
struct Limits {
    global: Bucket,
    peers: BTreeMap<String, Bucket>,
}
fn bounded_file(path: &Path) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > 262_144 {
        return Err("certificate file size".into());
    }
    std::fs::read(path).map_err(|e| e.to_string())
}
fn route(role: Role, method: &hyper::Method, path: &str) -> Option<usize> {
    if method == hyper::Method::GET {
        match (role, path) {
            (Role::EdgeReader | Role::EdgeWatchdog, "/v1/edge/heartbeat") => Some(4096),
            (Role::EdgeReader, "/v1/edge/capabilities") => Some(32768),
            (Role::EdgeReader, "/v1/edge/snapshot") => Some(262144),
            (Role::EdgeReader | Role::ManagerReader, "/metrics") => Some(2097152),
            (Role::ManagerReader, "/v1/manager/state") => Some(2097152),
            (Role::ManagerReader, "/v1/monitor/heartbeat") => Some(4096),
            _ => None,
        }
    } else if method == hyper::Method::POST {
        match (role, path) {
            (Role::ManagerIngest, "/v1/manager/facts") => Some(4096),
            (Role::PipelineSender, "/v1/watchdog/pipeline") => Some(4096),
            _ => None,
        }
    } else {
        None
    }
}
fn response(code: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = code;
    response
}
async fn proxy(
    request: Request<Incoming>,
    peer: Peer,
    config: Arc<IngressConfig>,
    client: reqwest::Client,
    limits: Arc<Mutex<Limits>>,
    regular_connections: Arc<tokio::sync::Semaphore>,
    connection_regular: Arc<Mutex<Option<tokio::sync::OwnedSemaphorePermit>>>,
) -> Result<Response<Body>, Infallible> {
    let path = request.uri().path().to_owned();
    if request.uri().query().is_some() || request.headers().contains_key("origin") {
        return Ok(response(StatusCode::BAD_REQUEST));
    }
    let host = request.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
    if host != config.server_name
        && host.split_once(':').map(|v| v.0) != Some(config.server_name.as_str())
    {
        return Ok(response(StatusCode::BAD_REQUEST));
    }
    let Some(max_response) = route(peer.role, request.method(), &path) else {
        return Ok(response(StatusCode::FORBIDDEN));
    };
    let heartbeat = path == "/v1/edge/heartbeat" || path == "/v1/monitor/heartbeat";
    let regular_connection = if heartbeat {
        None
    } else {
        match regular_connections.try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => return Ok(response(StatusCode::TOO_MANY_REQUESTS)),
        }
    };
    if let Some(permit) = regular_connection {
        let Ok(mut slot) = connection_regular.lock() else {
            return Ok(response(StatusCode::SERVICE_UNAVAILABLE));
        };
        if slot.is_some() {
            return Ok(response(StatusCode::TOO_MANY_REQUESTS));
        }
        *slot = Some(permit);
    }
    {
        let Ok(mut budget) = limits.lock() else {
            return Ok(response(StatusCode::SERVICE_UNAVAILABLE));
        };
        if !budget.global.take(!heartbeat)
            || !budget.peers.get_mut(&peer.alias).is_some_and(|b| b.take(false))
        {
            return Ok(response(StatusCode::TOO_MANY_REQUESTS));
        }
    }
    let method = request.method().clone();
    let authorization = request.headers().get("authorization").cloned();
    let max_input = if peer.role == Role::PipelineSender { 262144 } else { 16384 };
    let body = match tokio::time::timeout(
        Duration::from_secs(3),
        axum::body::to_bytes(Body::new(request.into_body()), max_input),
    )
    .await
    {
        Ok(Ok(b)) => b,
        _ => return Ok(response(StatusCode::PAYLOAD_TOO_LARGE)),
    };
    if method == hyper::Method::GET && !body.is_empty() {
        return Ok(response(StatusCode::BAD_REQUEST));
    }
    let mut upstream = client
        .request(method, format!("http://{}{}", config.upstream, path))
        .header("content-type", "application/json")
        .body(body);
    if let Some(value) = authorization {
        upstream = upstream.header("authorization", value);
    }
    let mut result = match upstream.send().await {
        Ok(r) => r,
        Err(_) => return Ok(response(StatusCode::BAD_GATEWAY)),
    };
    let status = result.status();
    let content_type = result.headers().get("content-type").cloned();
    if result.content_length().is_some_and(|n| n > max_response as u64) {
        return Ok(response(StatusCode::BAD_GATEWAY));
    }
    let mut bytes = Vec::new();
    loop {
        match result.chunk().await {
            Ok(Some(chunk)) => {
                if bytes.len().saturating_add(chunk.len()) > max_response {
                    return Ok(response(StatusCode::BAD_GATEWAY));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return Ok(response(StatusCode::BAD_GATEWAY)),
        }
    }
    let mut out = Response::new(Body::from(bytes));
    *out.status_mut() = status;
    if let Some(value) = content_type {
        out.headers_mut().insert(hyper::header::CONTENT_TYPE, value);
    }
    Ok(out)
}
pub async fn serve(config: IngressConfig, listener: tokio::net::TcpListener) -> Result<(), String> {
    if !config.upstream.ip().is_loopback()
        || config.upstream.port() == 0
        || config.peers.is_empty()
        || config.peers.len() > 32
        || config.server_name.is_empty()
        || config.server_name.len() > 253
        || !config.server_name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err("invalid ingress configuration".into());
    }
    let mut peers = BTreeMap::new();
    let mut buckets = BTreeMap::new();
    for peer in &config.peers {
        if !crate::alias(&peer.alias)
            || !tos_health_core::wire::hash(&peer.certificate_sha256)
            || peers.insert(peer.certificate_sha256.clone(), peer.clone()).is_some()
            || buckets.insert(peer.alias.clone(), Bucket::new()).is_some()
        {
            return Err("invalid peer ACL".into());
        }
    }
    let cert = bounded_file(&config.cert_file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::symlink_metadata(&config.key_file).map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
            return Err("private key must be an owner-only regular file".into());
        }
    }
    let key = bounded_file(&config.key_file)?;
    let ca = bounded_file(&config.ca_file)?;
    let certs = CertificateDer::pem_slice_iter(&cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let private = PrivateKeyDer::from_pem_slice(&key).map_err(|e| e.to_string())?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&ca) {
        roots.add(cert.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .map_err(|e| e.to_string())?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, private)
        .map_err(|e| e.to_string())?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .pool_max_idle_per_host(1)
        .build()
        .map_err(|e| e.to_string())?;
    let limits = Arc::new(Mutex::new(Limits { global: Bucket::new(), peers: buckets }));
    let config = Arc::new(config);
    let peers = Arc::new(peers);
    let slots = Arc::new(tokio::sync::Semaphore::new(8));
    // One of the eight classified request lifetimes is reserved for either
    // approved heartbeat path. TLS handshakes remain under the total-eight cap.
    let regular_connections = Arc::new(tokio::sync::Semaphore::new(7));
    loop {
        let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let (acceptor, peers, config, client, limits, regular_connections) = (
            acceptor.clone(),
            peers.clone(),
            config.clone(),
            client.clone(),
            limits.clone(),
            regular_connections.clone(),
        );
        tokio::spawn(async move {
            let _permit = permit;
            let tls =
                match tokio::time::timeout(Duration::from_secs(3), acceptor.accept(stream)).await {
                    Ok(Ok(tls)) => tls,
                    _ => return,
                };
            let Some(cert) = tls.get_ref().1.peer_certificates().and_then(|chain| chain.first())
            else {
                return;
            };
            let digest = format!("{:x}", Sha256::digest(cert.as_ref()));
            let Some(peer) = peers.get(&digest).cloned() else {
                return;
            };
            // keep_alive is disabled, so this connection-owned slot retains a
            // classified ordinary-request permit through TLS response drain.
            let connection_regular = Arc::new(Mutex::new(None));
            let service = service_fn(move |request| {
                proxy(
                    request,
                    peer.clone(),
                    config.clone(),
                    client.clone(),
                    limits.clone(),
                    regular_connections.clone(),
                    connection_regular.clone(),
                )
            });
            let mut http = hyper::server::conn::http1::Builder::new();
            http.keep_alive(false)
                .max_buf_size(32768)
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(3));
            let _ = tokio::time::timeout(
                Duration::from_secs(8),
                http.serve_connection(hyper_util::rt::TokioIo::new(tls), service),
            )
            .await;
        });
    }
}
