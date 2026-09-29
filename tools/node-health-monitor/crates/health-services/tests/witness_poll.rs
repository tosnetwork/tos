use axum::body::Bytes;
use http_body_util::Full;
use hyper::{service::service_fn, Response};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::{
    convert::Infallible,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_rustls::rustls::{
    self,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
};
use tos_health_core::witness::Plan;
use tos_health_services::witness::{next_fixed_due_ms, poll_round, WitnessCache, WitnessClient};

#[test]
fn fixed_schedule_skips_missed_tick_without_immediate_catch_up() {
    assert_eq!(next_fixed_due_ms(0), Ok(15_000));
    assert_eq!(next_fixed_due_ms(14_999), Ok(15_000));
    assert_eq!(next_fixed_due_ms(15_000), Ok(30_000));
    assert_eq!(next_fixed_due_ms(16_500), Ok(30_000));
    assert_eq!(next_fixed_due_ms(46_000), Ok(60_000));
    assert!(next_fixed_due_ms(u64::MAX).is_err());
}

struct TlsFiles(PathBuf);
impl Drop for TlsFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn files() -> TlsFiles {
    let dir = std::env::temp_dir().join(format!(
        "witness-tls-{}",
        tos_health_services::hex(&tos_health_services::random_token().unwrap())
    ));
    std::fs::create_dir(&dir).unwrap();
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            "server.key",
            "-out",
            "server.pem",
            "-subj",
            "/CN=localhost",
            "-days",
            "1",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
        ])
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    TlsFiles(dir)
}
fn client(dir: &Path) -> WitnessClient {
    let mut identity = std::fs::read(dir.join("server.pem")).unwrap();
    identity.extend(std::fs::read(dir.join("server.key")).unwrap());
    std::fs::write(dir.join("client.pem"), identity).unwrap();
    WitnessClient::new(&dir.join("server.pem"), &dir.join("client.pem")).unwrap()
}
async fn server(
    dir: &Path,
    body: Vec<u8>,
    delay: Duration,
    hits: Arc<AtomicUsize>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let certs = CertificateDer::pem_slice_iter(&std::fs::read(dir.join("server.pem")).unwrap())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(&std::fs::read(dir.join("server.key")).unwrap()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let body = body.clone();
            let hits = hits.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(socket).await else {
                    return;
                };
                let service = service_fn(move |_| {
                    let body = body.clone();
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(delay).await;
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (port, task)
}
fn plan(url: &str) -> Plan {
    let value = json!({"schema_version":1,"profile":"c05_development_cache_only",
        "revision":"a".repeat(64),"observer_id":"observer_1","observer_epoch":"observer-1",
        "network_id":"b".repeat(64),"genesis":"c".repeat(64),"clock_skew_allowance_ms":5000,
        "endpoints":[{"endpoint_id":"cache_1","fixed_url":url,"failure_domain":"zone_a",
            "kind":"approved_cache_only_https"}],
        "targets":[{"target_id":"validator_1","node_id":"validator_1","role":"normal",
            "valid_from":"2026-09-29T00:00:00Z","valid_until":"2026-09-30T00:00:00Z",
            "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
            "endpoint_ids":["cache_1"]},
            {"target_id":"validator_2","node_id":"validator_2","role":"probe_only",
            "valid_from":"2026-09-29T00:00:00Z","valid_until":"2026-09-30T00:00:00Z",
            "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
            "endpoint_ids":["cache_1"]}]});
    Plan::decode(&serde_json::to_vec(&value).unwrap()).unwrap()
}
fn five_endpoint_plan(port: u16) -> Plan {
    let mut value =
        serde_json::to_value(plan(&format!("https://localhost:{port}/witness1"))).unwrap();
    let first = value["endpoints"][0].clone();
    for number in 2..=5 {
        let mut endpoint = first.clone();
        endpoint["endpoint_id"] = json!(format!("cache_{number}"));
        endpoint["fixed_url"] = json!(format!("https://localhost:{port}/witness{number}"));
        value["endpoints"].as_array_mut().unwrap().push(endpoint);
    }
    value["targets"][0]["endpoint_ids"] = json!(["cache_1", "cache_2", "cache_3"]);
    value["targets"][1]["endpoint_ids"] = json!(["cache_4", "cache_5"]);
    Plan::decode(&serde_json::to_vec(&value).unwrap()).unwrap()
}
fn body() -> Vec<u8> {
    let row = |target: &str| {
        json!({"target_id":target,"observed_at":null,"source_age_ms":"1000",
        "anchor":null,"network_observation":"not_observed_in_window",
        "reported_certificate_membership":"not_checked","reported_proof":"not_checked",
        "private_vote_visibility":"unavailable","coverage":"partial",
        "missing_fields":["private_vote"]})
    };
    serde_json::to_vec(&json!({"schema_version":1,"endpoint_id":"cache_1",
        "source_epoch":"source-1","generation":"1","network_id":"b".repeat(64),
        "genesis":"c".repeat(64),"observed_at":null,"source_age_ms":"1000",
        "clock_quality":"unknown","coverage":"partial","rows":[row("validator_1"),row("validator_2")]})).unwrap()
}
#[tokio::test]
async fn one_actual_https_get_serves_two_planned_targets_per_round() {
    let files = files();
    let hits = Arc::new(AtomicUsize::new(0));
    let (port, task) = server(&files.0, body(), Duration::ZERO, hits.clone()).await;
    let cache = WitnessCache::new(
        plan(&format!("https://localhost:{port}/witness")),
        b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
    )
    .unwrap();
    let first = poll_round(cache.clone(), &client(&files.0)).await.unwrap();
    assert_eq!((first.attempted, first.admitted), (1, 1));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let cached = cache.cached("cache_1").unwrap().unwrap();
    assert_eq!(cached.2.len(), 2);
    let second = poll_round(cache, &client(&files.0)).await.unwrap();
    assert_eq!((second.attempted, second.duplicate), (1, 1));
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    task.abort();
}
#[tokio::test]
async fn local_timeout_quarantines_late_remote_work_without_retry() {
    let files = files();
    let hits = Arc::new(AtomicUsize::new(0));
    let (port, task) = server(&files.0, body(), Duration::from_millis(3400), hits.clone()).await;
    let cache = WitnessCache::new(
        plan(&format!("https://localhost:{port}/witness")),
        b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
    )
    .unwrap();
    let first = poll_round(cache.clone(), &client(&files.0)).await.unwrap();
    assert_eq!((first.attempted, first.timed_out_or_uncertain), (1, 1));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(cache.cached("cache_1").is_err());
    let second = poll_round(cache, &client(&files.0)).await.unwrap();
    assert_eq!(second.attempted, 0);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn cancelled_round_then_new_round_never_exceeds_four_local_requests() {
    let files = files();
    let hits = Arc::new(AtomicUsize::new(0));
    let (port, server_task) =
        server(&files.0, body(), Duration::from_millis(1500), hits.clone()).await;
    let cache = WitnessCache::new(
        five_endpoint_plan(port),
        b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
    )
    .unwrap();
    let first_cache = cache.clone();
    let first_client = client(&files.0);
    let first = tokio::spawn(async move { poll_round(first_cache, &first_client).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while hits.load(Ordering::SeqCst) < 4 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(cache.local_requests_inflight(), 4);
    first.abort();
    let _ = first.await;
    let next_cache = cache.clone();
    let next_client = client(&files.0);
    let second = tokio::spawn(async move { poll_round(next_cache, &next_client).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(cache.local_requests_inflight() <= 4);
    let result = second.await.unwrap();
    assert_eq!(result.attempted + result.skipped_local_busy, 1);
    assert_eq!(hits.load(Ordering::SeqCst), 4 + result.attempted);
    assert_eq!(cache.local_requests_inflight(), 0);
    server_task.abort();
}
