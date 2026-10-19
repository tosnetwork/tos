//! Exercise each scheduled sender's actual manager POST and stderr wiring.
use http_body_util::Full;
use hyper::{body::Bytes, service::service_fn, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    os::unix::fs::PermissionsExt,
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
use tos_health_core::{
    evidence::Evidence,
    native::canonical_hash,
    source::{Availability, Coverage, SourceQuality},
};
use tos_health_services::durable::{DurableEvidence, EvidenceDb};

struct Files(PathBuf);
impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn files() -> Files {
    let dir = std::env::temp_dir().join(format!(
        "nhm-sender-{}",
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
    let mut identity = std::fs::read(dir.join("server.pem")).unwrap();
    identity.extend(std::fs::read(dir.join("server.key")).unwrap());
    for (name, bytes) in [
        ("identity.pem", identity),
        ("edge-token", vec![b'e'; 32]),
        ("manager-token", vec![b'm'; 32]),
    ] {
        std::fs::write(dir.join(name), bytes).unwrap();
        std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    Files(dir)
}

fn snapshot() -> Value {
    let mut native: Value =
        serde_json::from_str(include_str!("fixtures/native_core_v2_validator1.json")).unwrap();
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    native["observed_at"] = now.clone().into();
    native["last_success_at"] = now.clone().into();
    native["source_age_ms"] = 0.into();
    let epoch = "00000000-0000-4000-8000-000000000001:4242:100";
    let payload = json!({"kind":"process","pid":4242,"rss_bytes":"4096","anon_bytes":null,"file_bytes":null,"swap_bytes":null,"cpu_user_ticks":"0","cpu_system_ticks":"0"});
    let process = json!({"schema_version":1,"source_id":"process","node_id":"validator1","scope_id":"node","process_epoch":epoch,"source_epoch":"process-source","source_version":"proc-v1","generation":"1","availability":"available","observed_at":now,"last_success_at":now,"received_at":null,"source_age_ms":0,"clock_quality":"valid","coverage":{"status":"partial","missing_fields":[],"gaps":[],"sampling_policy":"fixed_15s"},"content_hash":canonical_hash(&payload).unwrap(),"payload":payload,"quality":{"instrumentation_complete":false,"producer_dropped":"0","relay_dropped":"0","parse_errors":"0","shed_reason":null}});
    let value = json!({"schema_version":1,"status":"partial","sources":[native.clone(),process],"anchors":[],"native_process_binding":{"kind":"native_process_binding","process_epoch":epoch,"native_epoch":native["process_epoch"],"pid":4242,"start_ticks":"100","exe_identity_sha256":"a".repeat(64),"listener_inode":"1","listener_addr":"127.0.0.1:9000","checked_at":now}});
    let parsed: tos_health_core::edge_snapshot::EdgeSnapshot =
        serde_json::from_value(value.clone()).unwrap();
    parsed.validate("validator1", native["payload"]["network_id"].as_str().unwrap()).unwrap();
    value
}

async fn server(
    dir: &Path,
    snapshot: Value,
    status: u16,
    hits: Arc<AtomicUsize>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let certs = CertificateDer::pem_slice_iter(&std::fs::read(dir.join("server.pem")).unwrap())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(&std::fs::read(dir.join("server.key")).unwrap()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
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
            let snapshot = snapshot.clone();
            let hits = hits.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(socket).await else { return };
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let snapshot = snapshot.clone();
                    let hits = hits.clone();
                    async move {
                        let (status,body)=match request.uri().path() {
                        "/v1/manager/facts"=>{assert_eq!(request.method(),hyper::Method::POST);hits.fetch_add(1,Ordering::SeqCst);(status,b"private response body".to_vec())},
                        "/v1/edge/heartbeat"=>(200,json!({"schema_version":1,"node_id":"validator1","edge_epoch":"edge1","state":"available","guard":"normal","validator_epoch":null,"sources":[]}).to_string().into_bytes()),
                        "/v1/edge/snapshot"=>(200,snapshot.to_string().into_bytes()),
                        "/metrics"=>(200,vec![]),
                        _=>(404,vec![]),
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

fn populate_witness(path: &Path, network: &str) {
    let now = chrono::Utc::now().timestamp_millis();
    let mut db = EvidenceDb::open(path, 4 * 1024 * 1024).unwrap();
    db.bind_network(network).unwrap();
    for node in ["validator1", "observer1"] {
        db.insert(DurableEvidence {source_epoch:"epoch".into(),record:Evidence {node_id:node.into(),scope_id:"node".into(),source_id:"native_core".into(),source_record_id:"epoch:1".into(),process_epoch:"epoch".into(),observed_at_ms:now,received_at_ms:now,quality:SourceQuality {availability:Availability::Available,coverage:Coverage::Partial,observed_at_ms:Some(now),last_success_at_ms:Some(now),clock_valid:true,process_epoch:"epoch".into(),source_sequence:"1".into()},redacted:true,payload:json!({"component":"consensus","source":{"payload":{"network_id":network,"chain":{"applied":{"seqno":1,"root_hash":"a".repeat(64)}}}}})}}).unwrap();
    }
}

async fn check_sender(binary: &str, kind: &str, status: u16) {
    let files = files();
    let snapshot = snapshot();
    let network = snapshot["sources"][0]["payload"]["network_id"].as_str().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let (port, server) = server(&files.0, snapshot.clone(), status, hits.clone()).await;
    let mut config = json!({"network_id":network,"node_id":"validator1","scope_id":"node","edge_url":format!("https://localhost:{port}/v1/edge/heartbeat"),"manager_url":format!("https://localhost:{port}/v1/manager/facts"),"ca_file":files.0.join("server.pem"),"identity_file":files.0.join("identity.pem"),"edge_token_file":files.0.join("edge-token"),"manager_token_file":files.0.join("manager-token")});
    if kind == "native poll" {
        config["edge_url"] = format!("https://localhost:{port}/v1/edge/snapshot").into();
    }
    if kind == "witness compare" {
        populate_witness(&files.0.join("evidence.sqlite"), network);
        config = json!({"network_id":network,"evidence_db":files.0.join("evidence.sqlite"),"manager_url":format!("https://localhost:{port}/v1/manager/facts"),"ca_file":files.0.join("server.pem"),"identity_file":files.0.join("identity.pem"),"manager_token_file":files.0.join("manager-token"),"validators":["validator1"],"observers":["observer1"],"lag_blocks":1});
    }
    std::fs::write(files.0.join("config.json"), config.to_string()).unwrap();
    let log = files.0.join("stderr.log");
    let mut child = Child(
        Command::new(binary)
            .arg(files.0.join("config.json"))
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&log).unwrap()))
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let output = std::fs::read_to_string(&log).unwrap();
            if output.contains(&format!("{kind}: manager delivery:")) {
                assert!(output.contains(&format!("http_status={status}")), "{output}");
                assert!(!output.contains("private response body"));
                assert!(!output.contains(&"m".repeat(32)));
                assert!(hits.load(Ordering::SeqCst) > 0);
                assert_eq!(output.matches("manager delivery:").count(), 1);
                break;
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "sender exited before reporting: {output}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{kind} did not report a manager failure: {}",
            std::fs::read_to_string(&log).unwrap()
        )
    });
    drop(child);
    server.abort();
}

#[tokio::test]
async fn probe_process_reports_manager_refusal() {
    check_sender(env!("CARGO_BIN_EXE_health-probe"), "probe", 429).await;
}
#[tokio::test]
async fn native_process_reports_manager_refusal() {
    check_sender(env!("CARGO_BIN_EXE_health-native-poll"), "native poll", 503).await;
}
#[tokio::test]
async fn witness_process_reports_manager_refusal() {
    check_sender(env!("CARGO_BIN_EXE_health-witness-compare"), "witness compare", 503).await;
}
