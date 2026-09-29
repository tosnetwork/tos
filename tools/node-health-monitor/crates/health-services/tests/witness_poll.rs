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
use tos_health_services::witness::{
    next_fixed_due_ms, poll_round, run_fixed, WitnessCache, WitnessClient,
};

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
struct ProcessGuard(std::process::Child);
impl std::ops::Deref for ProcessGuard {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for ProcessGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
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

#[tokio::test]
async fn development_owner_keeps_independent_watchdog_alive_when_source_is_invalid() {
    let files = files();
    let hits = Arc::new(AtomicUsize::new(0));
    let (port, source_task) =
        server(&files.0, b"invalid closed source JSON".to_vec(), Duration::ZERO, hits.clone())
            .await;
    let cache = WitnessCache::new(
        plan(&format!("https://localhost:{port}/witness")),
        b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
    )
    .unwrap();
    let task = tokio::spawn(run_fixed(cache.clone(), client(&files.0)));
    tokio::time::timeout(Duration::from_secs(2), async {
        while hits.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!task.is_finished(), "bad source is isolated, not an O notification-task exit");
    assert!(cache.cached("cache_1").unwrap().is_none(), "invalid source cannot materialize");
    let watchdog = tos_health_services::watchdog::WatchdogState::new_with_epoch(
        "monitor1".into(),
        "observer1".into(),
        "observer-1".into(),
        vec![b'a'; 32],
    )
    .unwrap();
    assert_eq!(watchdog.completed_tick().unwrap(), 1);
    watchdog.notice_result(false).unwrap();
    assert_eq!(
        watchdog.completed_tick().unwrap(),
        2,
        "O heartbeat remains independent of witness source and notice transport"
    );
    task.abort();
    let _ = task.await;
    source_task.abort();
}

async fn runtime_server(
    dir: &Path,
    source_hits: Arc<AtomicUsize>,
    notice_hits: Arc<AtomicUsize>,
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
            let source_hits = source_hits.clone();
            let notice_hits = notice_hits.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(socket).await else {
                    return;
                };
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let source_hits = source_hits.clone();
                    let notice_hits = notice_hits.clone();
                    async move {
                        let (status, body) = match request.uri().path() {
                            "/witness" => {
                                source_hits.fetch_add(1, Ordering::SeqCst);
                                (hyper::StatusCode::OK, b"invalid source JSON".to_vec())
                            }
                            "/monitor" => (hyper::StatusCode::SERVICE_UNAVAILABLE, Vec::new()),
                            "/notice" => {
                                notice_hits.fetch_add(1, Ordering::SeqCst);
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                (hyper::StatusCode::SERVICE_UNAVAILABLE, Vec::new())
                            }
                            _ => (hyper::StatusCode::NOT_FOUND, Vec::new()),
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
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

#[tokio::test]
async fn actual_development_process_serves_heartbeat_with_bad_source_and_failed_delayed_notice() {
    use std::os::unix::fs::PermissionsExt;
    let files = files();
    let _ = client(&files.0); // also materializes the isolated test identity PEM.
    let source_hits = Arc::new(AtomicUsize::new(0));
    let notice_hits = Arc::new(AtomicUsize::new(0));
    let (tls_port, server_task) =
        runtime_server(&files.0, source_hits.clone(), notice_hits.clone()).await;
    let unused_port = || {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let pipeline_port = unused_port();
    let cache_port = unused_port();
    let fixed = plan(&format!("https://localhost:{tls_port}/witness"));
    std::fs::write(files.0.join("plan.json"), serde_json::to_vec(&fixed).unwrap()).unwrap();
    for (name, value) in [("pipeline.token", "p".repeat(32)), ("cache.token", "c".repeat(32))] {
        let path = files.0.join(name);
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config = json!({
        "monitor_url":format!("https://localhost:{tls_port}/monitor"),
        "receiver_url":format!("https://localhost:{tls_port}/notice"),
        "ca_file":files.0.join("server.pem"),"identity_file":files.0.join("client.pem"),
        "monitor_token_file":files.0.join("pipeline.token"),
        "receiver_token_file":files.0.join("pipeline.token"),
        "observer_id":"observer_1","monitor_id":"monitor_1",
        "pipeline_listen":format!("127.0.0.1:{pipeline_port}"),
        "pipeline_token_file":files.0.join("pipeline.token"),
        "witness_development":{"development_only":true,
            "plan_file":files.0.join("plan.json"),
            "cache_listen":format!("127.0.0.1:{cache_port}"),
            "read_token_file":files.0.join("cache.token"),
            "source_ca_file":files.0.join("server.pem"),
            "source_identity_file":files.0.join("client.pem")}
    });
    std::fs::write(files.0.join("runtime.json"), serde_json::to_vec(&config).unwrap()).unwrap();
    let child_log = files.0.join("child.stderr");
    let mut child = ProcessGuard(
        Command::new(env!("CARGO_BIN_EXE_health-watchdog"))
            .arg(files.0.join("runtime.json"))
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&child_log).unwrap()))
            .spawn()
            .unwrap(),
    );
    let observer =
        reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(1)).build().unwrap();
    let heartbeat = format!("http://127.0.0.1:{pipeline_port}/v1/watchdog/heartbeat");
    let cached = format!("http://127.0.0.1:{cache_port}/v1/witness/cache/cache_1");
    let outcome = tokio::time::timeout(Duration::from_secs(55), async {
        loop {
            if let Ok(response) = observer.get(&heartbeat).bearer_auth("p".repeat(32)).send().await
            {
                if response.status().is_success() {
                    break;
                }
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "development O exited before readiness: {}",
                std::fs::read_to_string(&child_log).unwrap_or_default()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let initial: serde_json::Value = observer
            .get(&heartbeat)
            .bearer_auth("p".repeat(32))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(initial["observer_epoch"], "observer-1");
        let unavailable = observer.get(&cached).bearer_auth("c".repeat(32)).send().await.unwrap();
        assert_eq!(unavailable.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        while notice_hits.load(Ordering::SeqCst) == 0 {
            assert!(child.try_wait().unwrap().is_none(), "O exited during invalid source rounds");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            source_hits.load(Ordering::SeqCst) >= 3,
            "invalid witness source was polled in earlier fixed rounds before delayed notice"
        );
        let during: serde_json::Value = observer
            .get(&heartbeat)
            .bearer_auth("p".repeat(32))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(during["observer_epoch"], "observer-1");
        assert!(child.try_wait().unwrap().is_none(), "slow notice must not kill O");
        loop {
            let later: serde_json::Value = observer
                .get(&heartbeat)
                .bearer_auth("p".repeat(32))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if later["notification_transport"] == "delivery_failed" {
                assert!(
                    later["sequence"].as_str().unwrap().parse::<u64>().unwrap()
                        > initial["sequence"].as_str().unwrap().parse::<u64>().unwrap()
                );
                assert!(child.try_wait().unwrap().is_none());
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    drop(child);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let reachable = observer
                .get(&heartbeat)
                .bearer_auth("p".repeat(32))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success());
            if !reachable {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("independent test client detects missing O heartbeat after process stop");
    server_task.abort();
    outcome.expect("bounded actual O runtime/notice witness");
}
