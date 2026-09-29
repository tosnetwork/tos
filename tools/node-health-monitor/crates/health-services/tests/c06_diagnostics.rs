use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::PermissionsExt, path::PathBuf, process::Command, sync::Arc, time::Duration,
};
use tos_health_services::{
    diagnostic_ipc::Mapping,
    diagnostic_relay::{self, Config, Stats},
    diagnostic_transport::Destination,
    ingress::{IngressConfig, Peer, Role},
    manager::{Manager, ManagerConfig},
};
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> Fixture {
    let path = std::env::temp_dir().join(format!(
        "nhm-d-{}",
        &tos_health_services::hex(&tos_health_services::random_token().unwrap())[..16]
    ));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let commands = vec![vec![
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
        "/CN=nhm-ca",
        "-days",
        "1",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    ]];
    for args in commands {
        assert!(Command::new("openssl")
            .args(args)
            .current_dir(&path)
            .output()
            .unwrap()
            .status
            .success());
    }
    for name in ["server", "client"] {
        assert!(Command::new("openssl")
            .args([
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
                &format!("/CN={name}")
            ])
            .current_dir(&path)
            .output()
            .unwrap()
            .status
            .success());
        let ext = if name == "server" {
            "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
        } else {
            "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n"
        };
        std::fs::write(path.join(format!("{name}.ext")), ext).unwrap();
        assert!(Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                if name == "server" { "1" } else { "2" },
                "-days",
                "1",
                "-extfile",
                &format!("{name}.ext"),
                "-out",
                &format!("{name}.pem")
            ])
            .current_dir(&path)
            .output()
            .unwrap()
            .status
            .success());
    }
    let mut identity = std::fs::read(path.join("client.pem")).unwrap();
    identity.extend(std::fs::read(path.join("client.key")).unwrap());
    std::fs::write(path.join("identity.pem"), identity).unwrap();
    std::fs::set_permissions(path.join("identity.pem"), std::fs::Permissions::from_mode(0o600))
        .unwrap();
    for (name, value) in [("ingest", 'a'), ("read", 'b'), ("diagnostic", 'c')] {
        let file = path.join(name);
        std::fs::write(&file, value.to_string().repeat(32)).unwrap();
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    Fixture(path)
}
fn manager_config(f: &Fixture) -> ManagerConfig {
    serde_json::from_value(json!({"inventory":{"schema_version":1,"revision":"c06-local","network_id":"a".repeat(64),"targets":[{"node":"v1","scope":"node","sources":[{"id":"edge_probe","ttl_ms":"45000","facts":["reachable"]}],"rules":[{"id":"target_unreachable","source":"edge_probe","threshold":"0","pending_ms":"0","recovery_ms":"60000","minimum_bad_samples":1,"severity":"critical"}]}]},
        "control_db":f.0.join("control.db"),"evidence_db":f.0.join("evidence.db"),"control_quota_bytes":"1048576","evidence_quota_bytes":"16777216","listen":"127.0.0.1:0",
        "ingest_token_file":f.0.join("ingest"),"read_token_file":f.0.join("read"),"receiver":null,"diagnostic":{"token_file":f.0.join("diagnostic"),"nodes":["v1"]}})).unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_native_ipc_relay_mtls_manager_transaction_chain() {
    let f = fixture();
    let config = manager_config(&f);
    let manager = Manager::start(&config).unwrap();
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = up.local_addr().unwrap();
    let app = tos_health_services::manager::router(manager.clone());
    let serving = tokio::spawn(async move { axum::serve(up, app).await.unwrap() });
    let tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tls.local_addr().unwrap();
    let der = Command::new("openssl")
        .args(["x509", "-in", "client.pem", "-outform", "DER"])
        .current_dir(&f.0)
        .output()
        .unwrap();
    assert!(der.status.success());
    let ingress = IngressConfig {
        listen: address,
        server_name: "localhost".into(),
        upstream,
        cert_file: f.0.join("server.pem"),
        key_file: f.0.join("server.key"),
        ca_file: f.0.join("ca.pem"),
        witness_endpoints: vec![],
        peers: vec![Peer {
            alias: "diagnostic_edge".into(),
            certificate_sha256: format!("{:x}", Sha256::digest(der.stdout)),
            role: Role::DiagnosticSender,
        }],
    };
    let ingress_task = tokio::spawn(tos_health_services::ingress::serve(ingress, tls));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).ancestors().nth(4).unwrap().to_path_buf();
    let bridge = f.0.join("native-bridge");
    let compile = Command::new("g++")
        .args(["-std=c++20", "-O2", "-pthread", "-I"])
        .arg(&root)
        .arg(root.join("tools/node-health-monitor/tests/native/diagnostic-bridge.cpp"))
        .arg("-o")
        .arg(&bridge)
        .output()
        .unwrap();
    assert!(compile.status.success(), "{}", String::from_utf8_lossy(&compile.stderr));
    // Spawn the native process before creating its fixed credential allowlist.
    // The private path may be absent; its pump connects only after approved bind.
    eprintln!("C06 native_bridge_sha256={:x}", Sha256::digest(std::fs::read(&bridge).unwrap()));
    let socket = f.0.join("diagnostic.sock");
    let epoch = "23".repeat(16);
    let mut native = Command::new(&bridge)
        .arg(&socket)
        .arg(std::process::id().to_string())
        .arg(&epoch)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let relay_config = Config {
        mapping: Mapping {
            socket_path: socket,
            node_id: "v1".into(),
            native_pid: native.id() as i32,
            native_uid: unsafe { libc::getuid() },
            native_gid: unsafe { libc::getgid() },
            process_epoch: epoch,
        },
        destination: Destination {
            origin: format!("https://localhost:{}/", address.port()),
            ca_file: f.0.join("ca.pem"),
            identity_file: f.0.join("identity.pem"),
            token_file: f.0.join("diagnostic"),
        },
    };
    let stats = Arc::new(Stats::default());
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let relay = tokio::spawn(diagnostic_relay::run(relay_config, stats.clone(), stopping));
    tokio::time::timeout(Duration::from_secs(2), async {
        while !stats.running.load(std::sync::atomic::Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    {
        use std::io::Write;
        native.stdin.take().unwrap().write_all(b"go\n").unwrap();
    }
    let native_result = tokio::task::spawn_blocking(move || native.wait().unwrap()).await.unwrap();
    assert!(native_result.success());
    tokio::time::timeout(Duration::from_secs(8), async {
        while stats.accepted.load(std::sync::atomic::Ordering::Relaxed) != 10 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("real native records must be ACKed through TLS into M");
    let db = rusqlite::Connection::open(&config.evidence_db).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM observations WHERE source='consensus_diagnostic'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        10
    );
    assert_eq!(stats.rejected.load(std::sync::atomic::Ordering::Relaxed), 0);
    let approved =
        tos_health_services::client(&f.0.join("ca.pem"), &f.0.join("identity.pem")).unwrap();
    let forbidden = approved
        .post(format!("https://localhost:{}/v1/manager/facts", address.port()))
        .bearer_auth("a".repeat(32))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        forbidden.status(),
        reqwest::StatusCode::FORBIDDEN,
        "diagnostic role must not inherit facts ingress"
    );
    stop.send(true).unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(1), relay).await.unwrap().unwrap().is_ok());
    ingress_task.abort();
    serving.abort();
    drop(manager);
    drop(db);
}
fn batch() -> tos_health_core::contracts::DiagnosticBatch {
    use tos_health_core::{
        contracts::{DiagnosticBatch, DiagnosticItem, DiagnosticQuality},
        wire::U64,
    };
    let mut value = DiagnosticBatch {
        schema_version: 1,
        node_id: "v1".into(),
        edge_epoch: "edge_a".into(),
        process_epoch: "23".repeat(16),
        source_id: "consensus_diagnostic".into(),
        batch_id: "0".repeat(64),
        records: vec![DiagnosticItem {
            sequence: U64(1),
            monotonic_ns: U64(10),
            observed_at: None,
            record_type: 1,
            payload: "01000300".into(),
        }],
        quality: DiagnosticQuality { dropped: U64(0), gaps: true },
    };
    value.batch_id = value.content_id().unwrap();
    value
}
#[tokio::test]
async fn actual_manager_http_refusals_and_conflict_survive_reopen() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let f = fixture();
    let config = manager_config(&f);
    let manager = Manager::start(&config).unwrap();
    let app = tos_health_services::manager::router(manager.clone());
    let request = |token: char, body: Vec<u8>| {
        Request::post("/v1/ingest/diagnostic-batches")
            .header("authorization", format!("Bearer {}", token.to_string().repeat(32)))
            .body(Body::from(body))
            .unwrap()
    };
    let original = batch();
    let bytes = serde_json::to_vec(&original).unwrap();
    assert_eq!(
        app.clone().oneshot(request('a', bytes.clone())).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone().oneshot(request('c', vec![b' '; 262145])).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut malformed = serde_json::to_value(&original).unwrap();
    malformed["records"][0]["sequence"] = json!("01");
    assert_eq!(
        app.clone()
            .oneshot(request('c', serde_json::to_vec(&malformed).unwrap()))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut missing = serde_json::to_value(&original).unwrap();
    missing["records"][0].as_object_mut().unwrap().remove("observed_at");
    assert_eq!(
        app.clone()
            .oneshot(request('c', serde_json::to_vec(&missing).unwrap()))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let response = app.clone().oneshot(request('c', bytes.clone())).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let ack: tos_health_services::diagnostic_ingest::Ack =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(ack.batch_id, original.batch_id);
    assert_eq!(ack.accepted_through_sequence.0, 1);
    assert_eq!(ack.duplicate_count.0, 0);
    let response = app.clone().oneshot(request('c', bytes)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let ack: tos_health_services::diagnostic_ingest::Ack =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(ack.duplicate_count.0, 1);
    let mut conflicting = original.clone();
    conflicting.records[0].payload = "02000300".into();
    conflicting.batch_id = conflicting.content_id().unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request('c', serde_json::to_vec(&conflicting).unwrap()))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    drop(app);
    drop(manager);
    // A new owner reopens persistent quarantine; the original content is no
    // longer ACKed after a conflicting immutable identity was observed.
    let reopened = Manager::start(&config).unwrap();
    let app = tos_health_services::manager::router(reopened.clone());
    assert_eq!(
        app.oneshot(request('c', serde_json::to_vec(&original).unwrap())).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    let database = rusqlite::Connection::open(&config.evidence_db).unwrap();
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM observations", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        1
    );
    database.execute_batch("CREATE TRIGGER hold_first_fact BEFORE INSERT ON observations WHEN NEW.source='edge_probe' AND NEW.source_record='1' BEGIN SELECT (WITH RECURSIVE delay(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM delay WHERE n<40000000) SELECT max(n) FROM delay);END;").unwrap();
    let (ready, mut waiting) = tokio::sync::mpsc::channel(32);
    let mut queued = Vec::new();
    for sequence in 1..=32u64 {
        let manager = reopened.clone();
        let ready = ready.clone();
        queued.push(tokio::spawn(async move {
            let frame=serde_json::from_value(json!({"schema_version":1,"network_id":"a".repeat(64),"node_id":"v1","scope_id":"node","source_id":"edge_probe","process_epoch":"p1","source_epoch":"s1","generation":sequence.to_string(),"source_age_ms":"0","request_duration_ms":"0","observed_at":"2026-09-29T00:00:00Z","clock_valid":true,"complete":true,"facts":[{"id":"reachable","value":"1"}]})).unwrap();
            ready.send(()).await.unwrap();let _=manager.ingest(frame).await;
        }));
    }
    drop(ready);
    for _ in 0..32 {
        waiting.recv().await.unwrap();
    }
    let mut fresh = original.clone();
    fresh.process_epoch = "24".repeat(16);
    fresh.batch_id = fresh.content_id().unwrap();
    let app = tos_health_services::manager::router(reopened.clone());
    let started = std::time::Instant::now();
    let timed_out = app.oneshot(request('c', serde_json::to_vec(&fresh).unwrap())).await.unwrap();
    eprintln!(
        "C06 caller_deadline elapsed_ms={} status={} budget={}",
        started.elapsed().as_millis(),
        timed_out.status(),
        reopened.diagnostic_status()
    );
    assert!(started.elapsed() >= Duration::from_secs(2), "503 must come from the writer deadline");
    assert_eq!(timed_out.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        reopened.diagnostic_status()["budget"]["owned_batches"],
        "1",
        "caller timeout must retain the queued diagnostic lease"
    );
    assert_ne!(reopened.diagnostic_status()["budget"]["owned_bytes"], "0");
    assert!(reopened.snapshot().is_ok(), "control cache remains readable during evidence pressure");
    for task in queued {
        task.await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(55), async {
        while reopened.diagnostic_status()["budget"]["owned_batches"] != "0" {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(database.query_row("SELECT count(*) FROM observations WHERE source='consensus_diagnostic' AND source_epoch=?1",[&fresh.process_epoch],|r|r.get::<_,u64>(0)).unwrap(),1,"queued D transaction must commit after its caller deadline");
    database.execute_batch("DROP TRIGGER hold_first_fact;").unwrap();
}

struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn unused_address() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}
fn bridge_line(reader: &mut std::io::BufReader<std::process::ChildStdout>) -> String {
    use std::{io::BufRead, os::fd::AsRawFd};
    let mut poll =
        libc::pollfd { fd: reader.get_ref().as_raw_fd(), events: libc::POLLIN, revents: 0 };
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1, "native fixture output deadline");
    let mut line = String::new();
    assert!(reader.read_line(&mut line).unwrap() > 0);
    line.trim().into()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_manager_death_then_edge_shutdown_preserves_native_core_progress() {
    use std::io::{BufReader, Write};
    let f = fixture();
    let mut config = manager_config(&f);
    let upstream = unused_address();
    config.listen = upstream.to_string();
    let config_file = f.0.join("manager.json");
    std::fs::write(&config_file, serde_json::to_vec(&config).unwrap()).unwrap();
    for (name, path) in [
        ("health-state", env!("CARGO_BIN_EXE_health-state")),
        ("health-edge", env!("CARGO_BIN_EXE_health-edge")),
    ] {
        eprintln!(
            "C06 child_binary={name} sha256={:x}",
            Sha256::digest(std::fs::read(path).unwrap())
        );
    }
    let mut manager = OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_health-state"))
            .arg(config_file)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tls.local_addr().unwrap();
    let der = Command::new("openssl")
        .args(["x509", "-in", "client.pem", "-outform", "DER"])
        .current_dir(&f.0)
        .output()
        .unwrap();
    assert!(der.status.success());
    let ingress_task = tokio::spawn(tos_health_services::ingress::serve(
        IngressConfig {
            listen: address,
            server_name: "localhost".into(),
            upstream,
            cert_file: f.0.join("server.pem"),
            key_file: f.0.join("server.key"),
            ca_file: f.0.join("ca.pem"),
            witness_endpoints: vec![],
            peers: vec![Peer {
                alias: "diagnostic_edge".into(),
                certificate_sha256: format!("{:x}", Sha256::digest(der.stdout)),
                role: Role::DiagnosticSender,
            }],
        },
        tls,
    ));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).ancestors().nth(4).unwrap().to_path_buf();
    let bridge = f.0.join("native-bridge");
    let compile = Command::new("g++")
        .args(["-std=c++20", "-O2", "-pthread", "-I"])
        .arg(&root)
        .arg(root.join("tools/node-health-monitor/tests/native/diagnostic-bridge.cpp"))
        .arg("-o")
        .arg(&bridge)
        .output()
        .unwrap();
    assert!(compile.status.success(), "{}", String::from_utf8_lossy(&compile.stderr));
    eprintln!("C06 native_bridge_sha256={:x}", Sha256::digest(std::fs::read(&bridge).unwrap()));
    let socket = f.0.join("diagnostic.sock");
    let epoch = "23".repeat(16);
    let mut native = OwnedChild(
        Command::new(bridge)
            .arg(&socket)
            .arg("0")
            .arg(&epoch)
            .arg("lifecycle")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let diagnostic = Config {
        mapping: Mapping {
            socket_path: socket.clone(),
            node_id: "v1".into(),
            native_pid: native.0.id() as i32,
            native_uid: unsafe { libc::getuid() },
            native_gid: unsafe { libc::getgid() },
            process_epoch: epoch,
        },
        destination: Destination {
            origin: format!("https://localhost:{}/", address.port()),
            ca_file: f.0.join("ca.pem"),
            identity_file: f.0.join("identity.pem"),
            token_file: f.0.join("diagnostic"),
        },
    };
    let relay_file = f.0.join("relay.json");
    std::fs::write(&relay_file, serde_json::to_vec(&diagnostic).unwrap()).unwrap();
    std::fs::set_permissions(&relay_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let edge_address = unused_address();
    let mut edge = OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_health-edge"))
            .arg("v1")
            .arg(native.0.id().to_string())
            .arg(edge_address.to_string())
            .arg(f.0.join("read"))
            .env("TOS_HEALTH_DIAGNOSTIC_CONFIG", relay_file)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let http = reqwest::Client::builder().timeout(Duration::from_secs(1)).build().unwrap();
    let url = format!("http://{edge_address}/v1/edge/diagnostics");
    let status = || http.get(&url).bearer_auth("b".repeat(32)).send();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(response) = status().await {
                if response.status().is_success()
                    && response.json::<serde_json::Value>().await.unwrap()["running"] == true
                {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let mut output = BufReader::new(native.0.stdout.take().unwrap());
    let input = native.0.stdin.as_mut().unwrap();
    writeln!(input, "{}", edge.0.id()).unwrap();
    assert_eq!(bridge_line(&mut output), "ready");
    writeln!(input, "emit").unwrap();
    let first = bridge_line(&mut output);
    eprintln!("C06 native_first signed/inflight/sent/dropped={first}");
    assert!(first.starts_with("100 0 "), "actual CORE Signed and inflight: {first}");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let value = status().await.unwrap().json::<serde_json::Value>().await.unwrap();
            if value["accepted"] == "300" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
    })
    .await
    .unwrap();
    manager.0.kill().unwrap();
    let dead = manager.0.wait().unwrap();
    eprintln!("C06 manager_pid={} terminated={dead}", manager.0.id());
    assert!(!dead.success(), "actual owned M process must die");
    writeln!(input, "emit").unwrap();
    let second = bridge_line(&mut output);
    eprintln!("C06 native_after_manager_death signed/inflight/sent/dropped={second}");
    assert!(second.starts_with("200 0 "), "CORE progresses after M death: {second}");
    tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            let value = status().await.unwrap().json::<serde_json::Value>().await.unwrap();
            assert_eq!(value["accepted"], "300", "dead M cannot ACK new records");
            if value["expired"] == "300" {
                assert_eq!(value["gaps"], true);
                break;
            }
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
    })
    .await
    .expect("pending flight must expire at original receive age");
    assert!(
        http.get(format!("http://{edge_address}/v1/edge/heartbeat"))
            .bearer_auth("b".repeat(32))
            .send()
            .await
            .unwrap()
            .status()
            .is_success(),
        "actual edge CORE endpoint survives diagnostic M outage"
    );
    let stopping = std::time::Instant::now();
    assert_eq!(unsafe { libc::kill(edge.0.id() as i32, libc::SIGINT) }, 0);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(exit) = edge.0.try_wait().unwrap() {
                assert!(exit.success());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(stopping.elapsed() < Duration::from_secs(2));
    assert!(!socket.exists(), "graceful relay exit removes only its own socket");
    writeln!(input, "emit").unwrap();
    let third = bridge_line(&mut output);
    eprintln!(
        "C06 native_after_edge_exit signed/inflight/sent/dropped={third}; edge_stop_ms={}",
        stopping.elapsed().as_millis()
    );
    let values = third.split_whitespace().map(|v| v.parse::<u64>().unwrap()).collect::<Vec<_>>();
    assert_eq!(values[0], 300);
    assert_eq!(values[1], 0);
    assert!(values[3] > 0, "dead edge causes diagnostic drop while CORE advances");
    writeln!(input, "stop").unwrap();
    let native_exit = native.0.wait().unwrap();
    eprintln!("C06 native_pid={} EOF/terminal={native_exit}", native.0.id());
    assert!(native_exit.success());
    ingress_task.abort();
}
