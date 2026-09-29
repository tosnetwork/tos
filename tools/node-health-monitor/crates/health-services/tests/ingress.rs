use axum::{routing::get, Router};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tos_health_services::ingress::{IngressConfig, Peer, Role};
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn openssl(dir: &Path, args: &[&str]) {
    assert!(
        Command::new("openssl")
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "openssl {args:?}"
    );
}
fn fixture() -> Temp {
    let p = std::env::temp_dir().join(format!(
        "health-tls-{}",
        tos_health_services::hex(&tos_health_services::random_token().unwrap())
    ));
    std::fs::create_dir(&p).unwrap();
    let t = Temp(p);
    openssl(
        &t.0,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-subj",
            "/CN=health-ca",
            "-days",
            "1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    );
    for name in ["server", "client", "watchdog"] {
        openssl(
            &t.0,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN={name}"),
            ],
        );
    }
    std::fs::write(
        t.0.join("server.ext"),
        "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
    )
    .unwrap();
    std::fs::write(
        t.0.join("client.ext"),
        "extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
    )
    .unwrap();
    std::fs::write(
        t.0.join("watchdog.ext"),
        "extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
    )
    .unwrap();
    for (name, csr, days, serial) in [
        ("server", "server", "1", "1"),
        ("client", "client", "1", "2"),
        ("expired", "client", "-1", "3"),
        ("unapproved", "client", "1", "4"),
        ("watchdog", "watchdog", "1", "5"),
    ] {
        openssl(
            &t.0,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{csr}.csr"),
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                serial,
                "-days",
                days,
                "-extfile",
                &format!("{csr}.ext"),
                "-out",
                &format!("{name}.pem"),
            ],
        );
    }
    t
}
fn fingerprint(dir: &Path, name: &str) -> String {
    let r = Command::new("openssl")
        .args(["x509", "-in", &format!("{name}.pem"), "-outform", "DER"])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(r.status.success());
    format!("{:x}", Sha256::digest(r.stdout))
}
fn client(dir: &Path, name: Option<&str>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(dir.join("ca.pem")).unwrap()).unwrap(),
        );
    if let Some(name) = name {
        let mut pem = std::fs::read(dir.join(format!("{name}.pem"))).unwrap();
        let key = if dir.join(format!("{name}.key")).is_file() { name } else { "client" };
        pem.extend(std::fs::read(dir.join(format!("{key}.key"))).unwrap());
        builder = builder.identity(reqwest::Identity::from_pem(&pem).unwrap());
    }
    builder.build().unwrap()
}
async fn idle_tls(
    dir: &Path,
    address: std::net::SocketAddr,
    name: &str,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    use tokio_rustls::rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    };
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&std::fs::read(dir.join("ca.pem")).unwrap()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let certs =
        CertificateDer::pem_slice_iter(&std::fs::read(dir.join(format!("{name}.pem"))).unwrap())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(&std::fs::read(dir.join(format!("{name}.key"))).unwrap())
            .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(1024).unwrap();
    let stream = socket.connect(address).await.unwrap();
    connector.connect(ServerName::try_from("localhost".to_owned()).unwrap(), stream).await.unwrap()
}
#[tokio::test]
async fn mtls_acl_rejects_missing_expired_and_unapproved_before_upstream() {
    let t = fixture();
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                "value 1\n# EOF\n"
            }
        }),
    );
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = up.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move { axum::serve(up, app).await.unwrap() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = IngressConfig {
        listen: address,
        server_name: "localhost".into(),
        upstream,
        cert_file: t.0.join("server.pem"),
        key_file: t.0.join("server.key"),
        ca_file: t.0.join("ca.pem"),
        peers: vec![
            Peer {
                alias: "monitor".into(),
                certificate_sha256: fingerprint(&t.0, "client"),
                role: Role::EdgeReader,
            },
            Peer {
                alias: "expired".into(),
                certificate_sha256: fingerprint(&t.0, "expired"),
                role: Role::EdgeReader,
            },
        ],
    };
    // Prove the same unapproved leaf can authenticate when explicitly authorized.
    // Otherwise any earlier TLS failure could masquerade as an ACL rejection.
    let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_address = control_listener.local_addr().unwrap();
    let mut control_config = config.clone();
    control_config.listen = control_address;
    control_config.peers = vec![Peer {
        alias: "control".into(),
        certificate_sha256: fingerprint(&t.0, "unapproved"),
        role: Role::EdgeReader,
    }];
    let control_server =
        tokio::spawn(tos_health_services::ingress::serve(control_config, control_listener));
    assert_eq!(
        client(&t.0, Some("unapproved"))
            .get(format!("https://localhost:{}/metrics", control_address.port()))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    control_server.abort();
    let server = tokio::spawn(tos_health_services::ingress::serve(config, listener));
    let base = format!("https://localhost:{}", address.port());
    let valid = client(&t.0, Some("client"));
    assert_eq!(valid.get(format!("{base}/metrics")).send().await.unwrap().status(), 200);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    for name in [None, Some("expired"), Some("unapproved")] {
        assert!(
            client(&t.0, name).get(format!("{base}/metrics")).send().await.is_err(),
            "{name:?}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        valid.get(format!("{base}/metrics?force_refresh=true")).send().await.unwrap().status(),
        400
    );
    assert_eq!(
        valid.post(format!("{base}/v1/manager/facts")).body("{}").send().await.unwrap().status(),
        403
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    server.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn eight_idle_authenticated_readers_are_bounded_then_release() {
    let t = fixture();
    let app = Router::new().route("/v1/edge/heartbeat", get(|| async { "ok" }));
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = up.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move { axum::serve(up, app).await.unwrap() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = IngressConfig {
        listen: address,
        server_name: "localhost".into(),
        upstream,
        cert_file: t.0.join("server.pem"),
        key_file: t.0.join("server.key"),
        ca_file: t.0.join("ca.pem"),
        peers: vec![Peer {
            alias: "reader".into(),
            certificate_sha256: fingerprint(&t.0, "client"),
            role: Role::EdgeReader,
        }],
    };
    let server = tokio::spawn(tos_health_services::ingress::serve(config, listener));
    let mut idle = Vec::new();
    for _ in 0..8 {
        idle.push(idle_tls(&t.0, address, "client").await);
    }
    let base = format!("https://localhost:{}/v1/edge/heartbeat", address.port());
    let started = std::time::Instant::now();
    assert!(client(&t.0, Some("client")).get(&base).send().await.is_err());
    assert!(started.elapsed() < Duration::from_secs(3), "ninth connection was not rejected");

    // TLS handshakes and HTTP header reads each have their own three-second bound.
    // These sockets completed TLS, so the header bound releases all eight slots.
    tokio::time::sleep(Duration::from_millis(3_200)).await;
    assert_eq!(client(&t.0, Some("client")).get(&base).send().await.unwrap().status(), 200);
    drop(idle);
    server.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn seven_slow_regular_requests_leave_classified_heartbeat_capacity() {
    use axum::middleware;
    use tokio::io::AsyncWriteExt;
    let t = fixture();
    let slow_calls = Arc::new(AtomicUsize::new(0));
    let count = slow_calls.clone();
    let edge_state = tos_health_services::edge::EdgeState::new("v1".into(), vec![b'e'; 32]);
    let large = format!("{}# EOF\n", "x".repeat(2_097_146));
    assert_eq!(large.len(), 2_097_152);
    edge_state.native.lock().unwrap().publish("process", 1, large, 0, 0).unwrap();
    let edge = tos_health_services::edge::router(edge_state).layer(middleware::from_fn(
        move |request: axum::extract::Request, next: middleware::Next| {
            let count = count.clone();
            async move {
                if request.uri().path() == "/metrics" {
                    count.fetch_add(1, Ordering::SeqCst);
                }
                next.run(request).await
            }
        },
    ));
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = up.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move { axum::serve(up, edge).await.unwrap() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = IngressConfig {
        listen: address,
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
    let server = tokio::spawn(tos_health_services::ingress::serve(config, listener));
    let mut pending = Vec::new();
    for index in 0..7 {
        let mut stream = idle_tls(&t.0, address, "client").await;
        stream
            .write_all(
                format!(
                    "GET /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
                    "e".repeat(32)
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        pending.push(stream);
        if index != 6 {
            tokio::time::sleep(Duration::from_millis(1_100)).await;
        }
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while slow_calls.load(Ordering::SeqCst) != 7 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(pending.len(), 7);

    let heartbeat = format!("https://localhost:{}/v1/edge/heartbeat", address.port());
    let metrics = format!("https://localhost:{}/metrics", address.port());
    let reader = client(&t.0, Some("client"));
    assert_eq!(
        reader
            .get(&metrics)
            .header("authorization", format!("Bearer {}", "e".repeat(32)))
            .send()
            .await
            .unwrap()
            .status(),
        429,
        "eighth ordinary request bypassed the classified reserve"
    );
    assert_eq!(slow_calls.load(Ordering::SeqCst), 7);
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

    // Releasing one draining connection makes an ordinary request reach the
    // upstream immediately, proving the prior 429 was not the rate bucket.
    drop(pending.pop());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let control = reader
        .get(&metrics)
        .header("authorization", format!("Bearer {}", "e".repeat(32)))
        .send()
        .await
        .unwrap();
    assert_eq!(control.status(), 200);
    assert_eq!(control.bytes().await.unwrap().len(), 2_097_152);
    assert_eq!(slow_calls.load(Ordering::SeqCst), 8);
    assert_eq!(
        client(&t.0, Some("watchdog"))
            .get(&heartbeat)
            .header("authorization", format!("Bearer {}", "e".repeat(32)))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "classified EdgeWatchdog heartbeat"
    );
    drop(pending);
    server.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn scheduled_probe_uses_mtls_and_never_claims_consensus_health() {
    use axum::{routing::post, Json};
    use serde_json::{json, Value};
    use tos_health_services::manager_poll::{run, ProbeConfig};
    let t = fixture();
    let wrong = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = wrong.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Value>(4);
    let app = Router::new()
        .route("/v1/edge/heartbeat", get(move || {
            let flag=flag.clone(); async move {Json(json!({
                "schema_version":1,"node_id":if flag.load(Ordering::SeqCst){"other"}else{"v1"},
                "edge_epoch":"edge-1","state":"available","guard":"guarded","validator_epoch":null,
                "sources":[{"source_id":"process","age_ms":null,"usable":false}]
            }))}
        }))
        .route("/v1/manager/facts",post(move |Json(value):Json<Value>| { let tx=tx.clone(); async move {tx.try_send(value).unwrap(); Json(json!({"accepted":true}))} }));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = socket.local_addr().unwrap();
    let app_task = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let edge_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge_addr = edge_socket.local_addr().unwrap();
    let manager_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let manager_addr = manager_socket.local_addr().unwrap();
    let config = IngressConfig {
        listen: edge_addr,
        server_name: "localhost".into(),
        upstream,
        cert_file: t.0.join("server.pem"),
        key_file: t.0.join("server.key"),
        ca_file: t.0.join("ca.pem"),
        peers: vec![Peer {
            alias: "probe".into(),
            certificate_sha256: fingerprint(&t.0, "client"),
            role: Role::EdgeReader,
        }],
    };
    let mut manager_config = config.clone();
    manager_config.listen = manager_addr;
    manager_config.peers[0].role = Role::ManagerIngest;
    let edge_task = tokio::spawn(tos_health_services::ingress::serve(config, edge_socket));
    let manager_task =
        tokio::spawn(tos_health_services::ingress::serve(manager_config, manager_socket));
    let mut identity = std::fs::read(t.0.join("client.pem")).unwrap();
    identity.extend(std::fs::read(t.0.join("client.key")).unwrap());
    std::fs::write(t.0.join("identity.pem"), identity).unwrap();
    for (name, value) in [("edge.token", "e".repeat(32)), ("manager.token", "m".repeat(32))] {
        std::fs::write(t.0.join(name), value).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(t.0.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
    }
    let mut receiver = tos_health_services::manager::ReceiverConfig {
        url: "https://localhost/receipt".into(),
        ca_file: t.0.join("ca.pem"),
        identity_file: t.0.join("identity.pem"),
        token_file: t.0.join("manager.token"),
        alias: "test".into(),
    };
    assert!(tos_health_services::manager::prepare_receiver(&receiver).is_ok());
    receiver.url = "http://localhost/receipt".into();
    assert!(
        matches!(tos_health_services::manager::prepare_receiver(&receiver), Err(e) if e == "invalid receiver endpoint")
    );
    for mismatch in [false, true] {
        wrong.store(mismatch, Ordering::SeqCst);
        let probe = ProbeConfig {
            network_id: "a".repeat(64),
            node_id: "v1".into(),
            scope_id: "node".into(),
            edge_url: format!("https://localhost:{}/v1/edge/heartbeat", edge_addr.port()),
            manager_url: format!("https://localhost:{}/v1/manager/facts", manager_addr.port()),
            ca_file: t.0.join("ca.pem"),
            identity_file: t.0.join("identity.pem"),
            edge_token_file: t.0.join("edge.token"),
            manager_token_file: t.0.join("manager.token"),
        };
        let task = tokio::spawn(run(probe));
        let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        task.abort();
        assert_eq!(frame["complete"], !mismatch);
        assert_eq!(frame["source_id"], "edge_probe");
        assert_eq!(frame["generation"], "1");
        assert_eq!(frame["facts"], json!([{"id":"reachable","value":"1"}]));
    }
    assert!(rx.try_recv().is_err());
    edge_task.abort();
    manager_task.abort();
    app_task.abort();
}

#[tokio::test]
async fn scheduled_native_poll_checks_inventory_over_mtls() {
    use axum::{routing::post, Json};
    use serde_json::{json, Value};
    use tos_health_services::manager_poll::{run_native as run, ProbeConfig};
    let t = fixture();
    let wrong = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = wrong.clone();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = calls.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Value>(4);
    let native: Value =
        serde_json::from_str(include_str!("../../health-core/tests/fixtures/native-core.json"))
            .unwrap();
    let epoch = native["process_epoch"].as_str().unwrap();
    let process_payload = json!({
        "kind":"process","pid":4242,"rss_bytes":"1048576","anon_bytes":"524288",
        "file_bytes":"524288","swap_bytes":"0","cpu_user_ticks":"100","cpu_system_ticks":"50"
    });
    let process = json!({
        "schema_version":1,"source_id":"process","node_id":"v1","scope_id":"node",
        "process_epoch":epoch,"source_epoch":"edge-test-1","source_version":"proc-v1",
        "generation":"1","availability":"available","observed_at":"2026-09-29T00:00:00Z",
        "last_success_at":"2026-09-29T00:00:00Z","received_at":null,"source_age_ms":0,
        "clock_quality":"valid","coverage":{"status":"partial","missing_fields":["host_pressure"],
        "gaps":[],"sampling_policy":"fixed_15s"},
        "content_hash":tos_health_core::native::canonical_hash(&process_payload).unwrap(),
        "payload":process_payload,"quality":{"instrumentation_complete":false,"producer_dropped":"0",
        "relay_dropped":"0","parse_errors":"0","shed_reason":null}
    });
    let app = Router::new()
        .route("/v1/edge/snapshot", get(move || {
            let flag=flag.clone(); let count=count.clone(); let process=process.clone(); async move {
                count.fetch_add(1, Ordering::SeqCst);
                let mut value:Value=serde_json::from_str(include_str!("../../health-core/tests/fixtures/native-core.json")).unwrap();
                value["node_id"]=if flag.load(Ordering::SeqCst){"other"}else{"v1"}.into();
                value["source_age_ms"]=0.into();
                Json(json!({"schema_version":1,"status":"partial","sources":[process,value],"anchors":[]}))
            }
        }))
        .route("/v1/manager/facts",post(move |Json(value):Json<Value>| { let tx=tx.clone(); async move {tx.try_send(value).unwrap(); Json(json!({"accepted":true}))} }));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = socket.local_addr().unwrap();
    let app_task = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let edge_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge_addr = edge_socket.local_addr().unwrap();
    let manager_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let manager_addr = manager_socket.local_addr().unwrap();
    let config = IngressConfig {
        listen: edge_addr,
        server_name: "localhost".into(),
        upstream,
        cert_file: t.0.join("server.pem"),
        key_file: t.0.join("server.key"),
        ca_file: t.0.join("ca.pem"),
        peers: vec![Peer {
            alias: "probe".into(),
            certificate_sha256: fingerprint(&t.0, "client"),
            role: Role::EdgeReader,
        }],
    };
    let mut manager_config = config.clone();
    manager_config.listen = manager_addr;
    manager_config.peers[0].role = Role::ManagerIngest;
    let edge_task = tokio::spawn(tos_health_services::ingress::serve(config, edge_socket));
    let manager_task =
        tokio::spawn(tos_health_services::ingress::serve(manager_config, manager_socket));
    let mut identity = std::fs::read(t.0.join("client.pem")).unwrap();
    identity.extend(std::fs::read(t.0.join("client.key")).unwrap());
    std::fs::write(t.0.join("identity.pem"), identity).unwrap();
    for (name, value) in [("edge.token", "e".repeat(32)), ("manager.token", "m".repeat(32))] {
        std::fs::write(t.0.join(name), value).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(t.0.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
    }
    for mismatch in [false, true] {
        wrong.store(mismatch, Ordering::SeqCst);
        let before = calls.load(Ordering::SeqCst);
        let probe = ProbeConfig {
            network_id: "a".repeat(64),
            node_id: "v1".into(),
            scope_id: "node".into(),
            edge_url: format!("https://localhost:{}/v1/edge/snapshot", edge_addr.port()),
            manager_url: format!("https://localhost:{}/v1/manager/facts", manager_addr.port()),
            ca_file: t.0.join("ca.pem"),
            identity_file: t.0.join("identity.pem"),
            edge_token_file: t.0.join("edge.token"),
            manager_token_file: t.0.join("manager.token"),
        };
        let task = tokio::spawn(run(probe));
        if mismatch {
            assert!(
                tokio::time::timeout(Duration::from_millis(700), rx.recv()).await.is_err(),
                "wrong inventory reached ingest"
            );
        } else {
            let frame =
                tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
            assert_eq!(frame["complete"], true);
            assert_eq!(frame["source_id"], "native_core");
            assert_eq!(frame["generation"], "1");
            assert_eq!(frame["facts"], json!([{"id":"pq_signing_failures","value":"0"}]));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before + 1,
            "poll must reach source even when rejected"
        );
        task.abort();
    }
    assert!(rx.try_recv().is_err());
    edge_task.abort();
    manager_task.abort();
    app_task.abort();
}
