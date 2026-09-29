use axum::{
    routing::{get, post},
    Router,
};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::PermissionsExt,
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

#[tokio::test]
async fn fixed_development_witness_routes_keep_peer_and_header_bounds() {
    use axum::{body::Bytes, http::HeaderMap, Json};
    use serde_json::json;
    let t = fixture();
    let (tx, mut rx) = tokio::sync::mpsc::channel(2);
    let app = Router::new()
        .route(
            "/v1/manager/witness-evidence/cache_1",
            post(move |headers: HeaderMap, body: Bytes| {
                let tx = tx.clone();
                async move {
                    tx.send((headers, body.len())).await.unwrap();
                    Json(json!({"accepted":true}))
                }
            }),
        )
        .route("/v1/witness/cache/cache_1", get(|| async { "cached" }));
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = up.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move { axum::serve(up, app).await.unwrap() });
    let m_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let m_addr = m_listener.local_addr().unwrap();
    let o_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let o_addr = o_listener.local_addr().unwrap();
    let config = IngressConfig {
        listen: m_addr,
        witness_endpoints: vec!["cache_1".into()],
        server_name: "localhost".into(),
        upstream,
        cert_file: t.0.join("server.pem"),
        key_file: t.0.join("server.key"),
        ca_file: t.0.join("ca.pem"),
        peers: vec![Peer {
            alias: "collector".into(),
            certificate_sha256: fingerprint(&t.0, "client"),
            role: Role::ManagerIngest,
        }],
    };
    let mut o_config = config.clone();
    o_config.listen = o_addr;
    o_config.peers[0].role = Role::WitnessReader;
    let m_server = tokio::spawn(tos_health_services::ingress::serve(config, m_listener));
    let o_server = tokio::spawn(tos_health_services::ingress::serve(o_config, o_listener));
    let approved = client(&t.0, Some("client"));
    let m_url = format!("https://localhost:{}/v1/manager/witness-evidence/cache_1", m_addr.port());
    let o_url = format!("https://localhost:{}/v1/witness/cache/cache_1", o_addr.port());
    let body = vec![b'x'; 32_768];
    let stamp = tos_health_services::transit::Stamp::capture().unwrap();
    let response = stamp
        .add_headers(approved.post(&m_url), &body, &"a".repeat(32))
        .header("x-unapproved-header", "must-not-forward")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let (forwarded, size) = rx.recv().await.unwrap();
    assert_eq!(size, 32_768);
    assert_eq!(forwarded["x-nhm-witness-clock-v1"], "1");
    assert_eq!(forwarded["x-nhm-witness-current-auth"], "a".repeat(32));
    assert!(!forwarded.contains_key("x-unapproved-header"));
    let invalid = stamp
        .add_headers(approved.post(&m_url), b"historical", &"a".repeat(32))
        .header("x-nhm-witness-start-ns", "1")
        .body("historical")
        .send()
        .await
        .unwrap();
    assert_eq!(
        invalid.status(),
        reqwest::StatusCode::OK,
        "bad current metadata must not revoke historical delivery"
    );
    let (forwarded, _) = rx.recv().await.unwrap();
    assert!(
        !forwarded.contains_key("x-nhm-witness-start-ns"),
        "duplicate current header must not become a singleton"
    );
    assert_eq!(approved.get(&o_url).send().await.unwrap().status(), reqwest::StatusCode::OK);
    assert_eq!(
        approved.post(&o_url).send().await.unwrap().status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        approved.get(format!("{o_url}?force=1")).send().await.unwrap().status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    assert!(rx.try_recv().is_err());
    m_server.abort();
    o_server.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn actual_collector_observer_tls_ingress_manager_current_chain_is_dev_only() {
    use serde_json::{json, Value};
    use tos_health_services::{
        collector::{CollectorConfig, WitnessCollectorConfig},
        manager::{Manager, ManagerConfig},
        witness::WitnessCache,
    };
    let t = fixture();
    let o_up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let o_up_addr = o_up.local_addr().unwrap();
    let m_up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let m_up_addr = m_up.local_addr().unwrap();
    let o_tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let o_tls_addr = o_tls.local_addr().unwrap();
    let m_tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let m_tls_addr = m_tls.local_addr().unwrap();
    let network = "a".repeat(64);
    let genesis = "c".repeat(64);
    let plan_value = json!({"schema_version":1,"profile":"c05_development_cache_only",
        "revision":"a".repeat(64),"observer_id":"observer_1","observer_epoch":"observer-1",
        "network_id":network,"genesis":genesis,"clock_skew_allowance_ms":5000,
        "endpoints":[{"endpoint_id":"cache_1","fixed_url":format!("https://localhost:{}/source",o_tls_addr.port()),
            "failure_domain":"zone_a","kind":"approved_cache_only_https","current_source_epoch":"source-1"}],
        "targets":[{"target_id":"validator_1","node_id":"v1","role":"normal",
            "valid_from":"2026-09-29T00:00:00Z","valid_until":"2026-09-30T00:00:00Z",
            "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
            "endpoint_ids":["cache_1"]}]});
    let plan_bytes = serde_json::to_vec(&plan_value).unwrap();
    std::fs::write(t.0.join("plan.json"), &plan_bytes).unwrap();
    let plan = tos_health_core::witness::Plan::decode(&plan_bytes).unwrap();
    let observer_token = "o".repeat(32);
    let cache = WitnessCache::new(plan, observer_token.as_bytes().to_vec()).unwrap();
    let source = serde_json::to_vec(&json!({"schema_version":1,"endpoint_id":"cache_1",
        "source_epoch":"source-1","generation":"1","network_id":network,"genesis":genesis,
        "observed_at":null,"source_age_ms":null,"clock_quality":"unknown","coverage":"partial",
        "rows":[{"target_id":"validator_1","observed_at":null,"source_age_ms":"46000",
            "anchor":null,"network_observation":"unavailable","reported_certificate_membership":"not_checked",
            "reported_proof":"not_checked","private_vote_visibility":"unavailable",
            "coverage":"partial","missing_fields":["private_vote"]}]})).unwrap();
    cache.admit("cache_1", &source, 10).unwrap();
    let o_task = tokio::spawn(async move {
        axum::serve(o_up, tos_health_services::witness::router(cache)).await.unwrap()
    });
    let ingest_token = "i".repeat(32);
    let read_token = "r".repeat(32);
    let current_token = "c".repeat(32);
    for (name, value) in [
        ("observer.token", observer_token),
        ("ingest.token", ingest_token.clone()),
        ("read.token", read_token.clone()),
        ("current.token", current_token),
    ] {
        std::fs::write(t.0.join(name), value).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(t.0.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
    }
    let mut identity = std::fs::read(t.0.join("client.pem")).unwrap();
    identity.extend(std::fs::read(t.0.join("client.key")).unwrap());
    std::fs::write(t.0.join("identity.pem"), identity).unwrap();
    let mut ingest_identity = std::fs::read(t.0.join("watchdog.pem")).unwrap();
    ingest_identity.extend(std::fs::read(t.0.join("watchdog.key")).unwrap());
    std::fs::write(t.0.join("ingest-identity.pem"), ingest_identity).unwrap();
    let manager_config: ManagerConfig = serde_json::from_value(json!({
        "inventory":{"schema_version":1,"revision":"runtime-test","network_id":network,
            "targets":[{"node":"v1","scope":"masterchain","sources":[{"id":"edge_probe","ttl_ms":"45000","facts":["reachable"]}],
                "rules":[{"id":"target_unreachable","source":"edge_probe","threshold":"0","pending_ms":"0",
                    "recovery_ms":"60000","minimum_bad_samples":1,"severity":"critical"}]}]},
        "control_db":t.0.join("control.db"),"evidence_db":t.0.join("evidence.db"),
        "control_quota_bytes":"1048576","evidence_quota_bytes":"1048576","listen":"127.0.0.1:0",
        "ingest_token_file":t.0.join("ingest.token"),"read_token_file":t.0.join("read.token"),
        "receiver":null,"witness_plan_file":t.0.join("plan.json"),
        "witness_current_token_file":t.0.join("current.token"),"witness_current_trusted_same_host":true
    })).unwrap();
    let manager = Manager::start(&manager_config).unwrap();
    let m_task = tokio::spawn(async move {
        axum::serve(m_up, tos_health_services::manager::router(manager)).await.unwrap()
    });
    let peer = fingerprint(&t.0, "client");
    let make_ingress = |listen, upstream, role| IngressConfig {
        listen,
        upstream,
        server_name: "localhost".into(),
        cert_file: t.0.join("server.pem"),
        key_file: t.0.join("server.key"),
        ca_file: t.0.join("ca.pem"),
        peers: vec![Peer { alias: "collector".into(), certificate_sha256: peer.clone(), role }],
        witness_endpoints: vec!["cache_1".into()],
    };
    let o_ingress = tokio::spawn(tos_health_services::ingress::serve(
        make_ingress(o_tls_addr, o_up_addr, Role::WitnessReader),
        o_tls,
    ));
    let mut m_config = make_ingress(m_tls_addr, m_up_addr, Role::ManagerIngest);
    m_config.peers[0].certificate_sha256 = fingerprint(&t.0, "watchdog");
    let m_ingress = tokio::spawn(tos_health_services::ingress::serve(m_config, m_tls));
    let collector = CollectorConfig {
        node_id: "v1".into(),
        network_id: Some(network),
        edge_url: format!("https://localhost:{}/v1/edge/snapshot", o_tls_addr.port()),
        ingest_url: format!("https://localhost:{}/v1/manager/snapshot-evidence", m_tls_addr.port()),
        ca_file: t.0.join("ca.pem"),
        identity_file: t.0.join("identity.pem"),
        ingest_identity_file: Some(t.0.join("ingest-identity.pem")),
        edge_token_file: t.0.join("observer.token"),
        ingest_token_file: t.0.join("ingest.token"),
        witness: Some(WitnessCollectorConfig {
            plan_file: t.0.join("plan.json"),
            observer_base_url: format!("https://localhost:{}/", o_tls_addr.port()),
            observer_token_file: t.0.join("observer.token"),
            current_token_file: Some(t.0.join("current.token")),
            trusted_same_host: true,
        }),
    };
    let collector_task = tokio::spawn(tos_health_services::collector::run(collector));
    let reader = reqwest::Client::new();
    let current_url = format!("http://{m_up_addr}/v1/manager/witness-current/cache_1");
    let mut observed = None;
    for _ in 0..60 {
        if let Ok(reply) = reader.get(&current_url).bearer_auth(&read_token).send().await {
            if reply.status().is_success() {
                let value: Value = reply.json().await.unwrap();
                observed = Some(value);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let value =
        observed.expect("actual fixed collector must reach O and M through two mTLS ingresses");
    assert_eq!(value["status"], "unknown", "synthetic stale/clock-unknown source cannot qualify");
    assert_eq!(value["production_usable"], false);
    assert!(
        value["collector_to_m_ms"].as_str().is_some(),
        "real collector transit stamp survived ingress"
    );
    assert_eq!(value["rows"][0]["qualification"]["verified_finality"], false);
    let archived: i64 = rusqlite::Connection::open(t.0.join("evidence.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM witness_observations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(archived, 1, "historical archive committed separately");
    collector_task.abort();
    // A second real mTLS O-cache read and M-ingress POST with the wrong
    // current credential must still ACK the historical duplicate while
    // invalidating the matching volatile current view.
    let approved = client(&t.0, Some("client"));
    let approved_ingest = client(&t.0, Some("watchdog"));
    let cached = approved
        .get(format!("https://localhost:{}/v1/witness/cache/cache_1", o_tls_addr.port()))
        .bearer_auth("o".repeat(32))
        .send()
        .await
        .unwrap();
    assert_eq!(cached.status(), reqwest::StatusCode::OK);
    let body = cached.bytes().await.unwrap();
    let cached_body = body.clone();
    let stamp = tos_health_services::transit::Stamp::capture().unwrap();
    let delivered = stamp
        .add_headers(
            approved_ingest
                .post(format!(
                    "https://localhost:{}/v1/manager/witness-evidence/cache_1",
                    m_tls_addr.port()
                ))
                .bearer_auth("i".repeat(32))
                .header("content-type", "application/json"),
            &body,
            &"x".repeat(32),
        )
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(delivered.status(), reqwest::StatusCode::OK);
    assert_eq!(
        reader.get(&current_url).bearer_auth(&read_token).send().await.unwrap().status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "wrong current token through TLS cannot retain old current view"
    );
    for (header, replacement, expected) in [
        (
            "x-nhm-witness-boot-id",
            "00000000-0000-0000-0000-000000000000".to_owned(),
            reqwest::StatusCode::OK,
        ),
        ("x-nhm-witness-time-ns", "time:[999999]".to_owned(), reqwest::StatusCode::OK),
        ("x-nhm-witness-start-ns", u64::MAX.to_string(), reqwest::StatusCode::OK),
        ("x-nhm-witness-body-sha256", "0".repeat(64), reqwest::StatusCode::SERVICE_UNAVAILABLE),
    ] {
        // Keep the configured 1/s ingress rate; these are distinct M
        // deliveries of the same immutable O cache body, not extra O polls.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let body = cached_body.clone();
        let stamp = tos_health_services::transit::Stamp::capture().unwrap();
        let mut request = stamp
            .add_headers(
                approved_ingest
                    .post(format!(
                        "https://localhost:{}/v1/manager/witness-evidence/cache_1",
                        m_tls_addr.port()
                    ))
                    .bearer_auth("i".repeat(32))
                    .header("content-type", "application/json"),
                &body,
                &"c".repeat(32),
            )
            .body(body)
            .build()
            .unwrap();
        request.headers_mut().insert(
            reqwest::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            reqwest::header::HeaderValue::from_str(&replacement).unwrap(),
        );
        assert_eq!(
            approved_ingest.execute(request).await.unwrap().status(),
            reqwest::StatusCode::OK,
            "{header} cannot revoke historical ACK"
        );
        let current_reply = reader.get(&current_url).bearer_auth(&read_token).send().await.unwrap();
        assert_eq!(current_reply.status(), expected, "{header} current availability");
        if expected == reqwest::StatusCode::OK {
            let value: Value = current_reply.json().await.unwrap();
            assert_eq!(value["status"], "unknown", "{header} cannot renew current");
        }
    }
    let archived_after: i64 = rusqlite::Connection::open(t.0.join("evidence.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM witness_observations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(archived_after, 1, "invalid current metadata does not mint historical duplicate");
    o_ingress.abort();
    m_ingress.abort();
    m_task.abort();
    o_task.abort();
}

#[tokio::test]
async fn split_collector_identities_archive_validated_process_without_probe_relabel() {
    use axum::Json;
    use serde_json::{json, Value};
    use tos_health_services::{
        collector::CollectorConfig,
        manager::{Manager, ManagerConfig},
    };

    let t = fixture();
    for (name, value) in [
        ("edge.token", "e".repeat(32)),
        ("ingest.token", "i".repeat(32)),
        ("read.token", "r".repeat(32)),
    ] {
        std::fs::write(t.0.join(name), value).unwrap();
        std::fs::set_permissions(t.0.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    for (name, cert) in [("reader-identity.pem", "client"), ("ingest-identity.pem", "watchdog")] {
        let mut identity = std::fs::read(t.0.join(format!("{cert}.pem"))).unwrap();
        identity.extend(std::fs::read(t.0.join(format!("{cert}.key"))).unwrap());
        std::fs::write(t.0.join(name), identity).unwrap();
        std::fs::set_permissions(t.0.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut native: Value =
        serde_json::from_str(include_str!("../../health-core/tests/fixtures/native-core.json"))
            .unwrap();
    let mut process: Value =
        serde_json::from_str(include_str!("../../health-core/tests/fixtures/process-source.json"))
            .unwrap();
    let process_epoch = "00000000-0000-4000-8000-000000000001:4242:123";
    process["process_epoch"] = process_epoch.into();
    let network = "a".repeat(64);
    let snapshot = json!({"schema_version":1,"status":"partial","sources":[native.take(),process],"anchors":[],
        "native_process_binding":{"kind":"native_process_binding","process_epoch":process_epoch,
            "native_epoch":"fa86123d3210887c36045ec1ec657bfc","pid":4242,"start_ticks":"123",
            "exe_identity_sha256":"d".repeat(64),"listener_inode":"456",
            "listener_addr":"127.0.0.1:9000","checked_at":"2026-09-29T00:00:00Z"}});
    let edge_up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge_up_addr = edge_up.local_addr().unwrap();
    let edge_task = tokio::spawn(async move {
        axum::serve(
            edge_up,
            Router::new().route(
                "/v1/edge/snapshot",
                get(move || {
                    let snapshot = snapshot.clone();
                    async move { Json(snapshot) }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let manager_config: ManagerConfig = serde_json::from_value(json!({
        "inventory":{"schema_version":1,"revision":"split-identity-test","network_id":network,
            "targets":[{"node":"v1","scope":"node","sources":[{"id":"edge_probe","ttl_ms":"45000","facts":["reachable"]}],
                "rules":[{"id":"target_unreachable","source":"edge_probe","threshold":"0","pending_ms":"0",
                    "recovery_ms":"60000","minimum_bad_samples":1,"severity":"critical"}]}]},
        "control_db":t.0.join("control.db"),"evidence_db":t.0.join("evidence.db"),
        "control_quota_bytes":"1048576","evidence_quota_bytes":"1048576","listen":"127.0.0.1:0",
        "ingest_token_file":t.0.join("ingest.token"),"read_token_file":t.0.join("read.token"),"receiver":null
    })).unwrap();
    let manager = Manager::start(&manager_config).unwrap();
    let manager_up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let manager_up_addr = manager_up.local_addr().unwrap();
    let manager_task = tokio::spawn(async move {
        axum::serve(manager_up, tos_health_services::manager::router(manager)).await.unwrap();
    });
    let edge_tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge_tls_addr = edge_tls.local_addr().unwrap();
    let manager_tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let manager_tls_addr = manager_tls.local_addr().unwrap();
    let ingress = |listen, upstream, role, cert| IngressConfig {
        listen,
        upstream,
        server_name: "localhost".into(),
        cert_file: t.0.join("server.pem"),
        key_file: t.0.join("server.key"),
        ca_file: t.0.join("ca.pem"),
        witness_endpoints: vec![],
        peers: vec![Peer {
            alias: "collector".into(),
            certificate_sha256: fingerprint(&t.0, cert),
            role,
        }],
    };
    let edge_ingress = tokio::spawn(tos_health_services::ingress::serve(
        ingress(edge_tls_addr, edge_up_addr, Role::EdgeReader, "client"),
        edge_tls,
    ));
    let manager_ingress = tokio::spawn(tos_health_services::ingress::serve(
        ingress(manager_tls_addr, manager_up_addr, Role::ManagerIngest, "watchdog"),
        manager_tls,
    ));
    let config = CollectorConfig {
        node_id: "v1".into(),
        network_id: Some("a".repeat(64)),
        edge_url: format!("https://localhost:{}/v1/edge/snapshot", edge_tls_addr.port()),
        ingest_url: format!(
            "https://localhost:{}/v1/manager/snapshot-evidence",
            manager_tls_addr.port()
        ),
        ca_file: t.0.join("ca.pem"),
        identity_file: t.0.join("reader-identity.pem"),
        ingest_identity_file: None,
        edge_token_file: t.0.join("edge.token"),
        ingest_token_file: t.0.join("ingest.token"),
        witness: None,
    };
    let denied = tokio::spawn(tos_health_services::collector::run(config));
    tokio::time::sleep(Duration::from_millis(700)).await;
    denied.abort();
    let _ = denied.await;
    let count = || -> i64 {
        rusqlite::Connection::open(t.0.join("evidence.db"))
            .unwrap()
            .query_row("SELECT COUNT(*) FROM observations WHERE source='process'", [], |row| {
                row.get(0)
            })
            .unwrap()
    };
    assert_eq!(count(), 0, "Edge reader certificate was admitted as M writer");
    let config = CollectorConfig {
        ingest_identity_file: Some(t.0.join("ingest-identity.pem")),
        node_id: "v1".into(),
        network_id: Some("a".repeat(64)),
        edge_url: format!("https://localhost:{}/v1/edge/snapshot", edge_tls_addr.port()),
        ingest_url: format!(
            "https://localhost:{}/v1/manager/snapshot-evidence",
            manager_tls_addr.port()
        ),
        ca_file: t.0.join("ca.pem"),
        identity_file: t.0.join("reader-identity.pem"),
        edge_token_file: t.0.join("edge.token"),
        ingest_token_file: t.0.join("ingest.token"),
        witness: None,
    };
    let accepted = tokio::spawn(tos_health_services::collector::run(config));
    for _ in 0..100 {
        if count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(count(), 1, "split mTLS collector did not archive process");
    let (_, projected) = tos_health_services::manager_query_source::read_process_projection(
        &t.0.join("evidence.db"),
        &"a".repeat(64),
    )
    .unwrap();
    assert_eq!(projected.len(), 1, "M archive did not preserve a queryable process origin");
    let edge_probe_count: i64 = rusqlite::Connection::open(t.0.join("evidence.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM observations WHERE source='edge_probe'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(edge_probe_count, 0, "snapshot was mislabeled as reachability");
    accepted.abort();
    edge_ingress.abort();
    manager_ingress.abort();
    edge_task.abort();
    manager_task.abort();
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
        witness_endpoints: vec![],
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
        witness_endpoints: vec![],
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
        witness_endpoints: vec![],
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
        witness_endpoints: vec![],
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
    let native_epoch = native["process_epoch"].as_str().unwrap();
    let epoch = "00000000-0000-4000-8000-000000000001:4242:123";
    let binding = json!({
        "kind":"native_process_binding","process_epoch":epoch,"native_epoch":native_epoch,
        "pid":4242,"start_ticks":"123","exe_identity_sha256":"d".repeat(64),
        "listener_inode":"456","listener_addr":"127.0.0.1:9000",
        "checked_at":"2026-09-29T00:00:00Z"
    });
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
            let flag=flag.clone(); let count=count.clone(); let process=process.clone(); let binding=binding.clone(); async move {
                count.fetch_add(1, Ordering::SeqCst);
                let mut value:Value=serde_json::from_str(include_str!("../../health-core/tests/fixtures/native-core.json")).unwrap();
                value["node_id"]=if flag.load(Ordering::SeqCst){"other"}else{"v1"}.into();
                value["source_age_ms"]=0.into();
                Json(json!({"schema_version":1,"status":"partial","sources":[process,value],"anchors":[],"native_process_binding":binding}))
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
        witness_endpoints: vec![],
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
