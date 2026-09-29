use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
use tos_health_core::evidence::Evidence;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    pub node_id: String,
    #[serde(default)]
    pub network_id: Option<String>,
    pub edge_url: String,
    pub ingest_url: String,
    pub ca_file: PathBuf,
    pub identity_file: PathBuf,
    pub edge_token_file: PathBuf,
    pub ingest_token_file: PathBuf,
    #[serde(default)]
    pub witness: Option<WitnessCollectorConfig>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessCollectorConfig {
    pub plan_file: PathBuf,
    pub observer_base_url: String,
    pub observer_token_file: PathBuf,
}
impl CollectorConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.validate_static()?;
        self.witness_plan().map(|_| ())
    }
    fn validate_static(&self) -> Result<(), String> {
        if !crate::alias(&self.node_id)
            || self.network_id.as_ref().is_none_or(|v| !tos_health_core::wire::hash(v))
        {
            return Err("invalid node alias".into());
        }
        for (value, path) in [
            (&self.edge_url, "/v1/edge/snapshot"),
            (&self.ingest_url, "/v1/manager/snapshot-evidence"),
        ] {
            let url = reqwest::Url::parse(value).map_err(|e| e.to_string())?;
            if url.scheme() != "https"
                || url.path() != path
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err("only fixed credential-free HTTPS endpoints are allowed".into());
            }
        }
        if let Some(witness) = &self.witness {
            let url = reqwest::Url::parse(&witness.observer_base_url).map_err(|e| e.to_string())?;
            if url.scheme() != "https"
                || url.path() != "/"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || witness.observer_base_url != url.as_str()
            {
                return Err("invalid fixed observer cache base".into());
            }
        }
        Ok(())
    }
    fn witness_plan(&self) -> Result<Option<tos_health_core::witness::Plan>, String> {
        if let Some(witness) = &self.witness {
            let plan = tos_health_core::witness::Plan::read_file(&witness.plan_file)?;
            if self.network_id.as_deref() != Some(plan.network_id.as_str()) {
                return Err("witness plan network mismatch".into());
            }
            return Ok(Some(plan));
        }
        Ok(None)
    }
}
pub async fn run(config: CollectorConfig) -> Result<(), String> {
    config.validate_static()?;
    let frozen_witness_plan = config.witness_plan()?;
    if let (Some(witness), Some(plan)) = (&config.witness, frozen_witness_plan) {
        let client = crate::client(&config.ca_file, &config.identity_file)?;
        let observer_token = String::from_utf8(crate::secret(&witness.observer_token_file)?)
            .map_err(|e| e.to_string())?;
        let ingest_token = String::from_utf8(crate::secret(&config.ingest_token_file)?)
            .map_err(|e| e.to_string())?;
        let base = witness.observer_base_url.clone();
        let ingest = config.ingest_url.clone();
        tokio::spawn(async move {
            if let Err(error) =
                run_witness(client, plan, base, ingest, observer_token, ingest_token).await
            {
                eprintln!("witness retained collector stopped: {error}");
            }
        });
    }
    let client = crate::client(&config.ca_file, &config.identity_file)?;
    let edge_token =
        String::from_utf8(crate::secret(&config.edge_token_file)?).map_err(|e| e.to_string())?;
    let ingest_token =
        String::from_utf8(crate::secret(&config.ingest_token_file)?).map_err(|e| e.to_string())?;
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_identity = std::collections::BTreeMap::new();
    loop {
        interval.tick().await;
        let response = match client.get(&config.edge_url).bearer_auth(&edge_token).send().await {
            Ok(r) => r,
            Err(_) => {
                eprintln!("edge unavailable");
                continue;
            }
        };
        let bytes = match crate::bounded_body(response, 262_144).await {
            Ok(b) => b,
            Err(_) => {
                eprintln!("invalid edge response");
                continue;
            }
        };
        let records = match decode_records(&bytes, &config.node_id, config.network_id.as_deref()) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("invalid edge identity or schema");
                continue;
            }
        };
        let identities = records
            .iter()
            .map(|record| Ok((record.source_id.clone(), evidence_identity(record)?)))
            .collect::<Result<Vec<_>, String>>()?;
        if identities.iter().all(|(source, id)| last_identity.get(source) == Some(id)) {
            continue;
        }
        let sent = client
            .post(&config.ingest_url)
            .bearer_auth(&ingest_token)
            .header("content-type", "application/json")
            .body(bytes)
            .send()
            .await;
        let accepted = match sent {
            Ok(response) => crate::bounded_body(response, 4096)
                .await
                .ok()
                .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
                .is_some_and(|receipt| {
                    receipt["accepted"] == true
                        && receipt["evidence"].as_array().is_some_and(|rows| {
                            rows.len() == records.len()
                                && rows.iter().all(|row| {
                                    row["evidence_id"]
                                        .as_str()
                                        .is_some_and(tos_health_core::wire::hash)
                                        && row["store_seq"].as_str().is_some_and(|seq| {
                                            tos_health_core::wire::exact_u64(seq).is_ok()
                                        })
                                })
                        })
                }),
            Err(_) => false,
        };
        if accepted {
            last_identity.extend(identities);
        } else {
            eprintln!("snapshot evidence ingest unavailable; no backlog retained");
        }
    }
}

/// M reads only O's fixed retained routes. This never constructs a target RPC.
async fn run_witness(
    client: reqwest::Client,
    plan: tos_health_core::witness::Plan,
    observer_base_url: String,
    ingest_url: String,
    observer_token: String,
    ingest_token: String,
) -> Result<(), String> {
    plan.validate().map_err(str::to_owned)?;
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_identity = std::collections::BTreeMap::new();
    loop {
        interval.tick().await;
        poll_witness_once(
            &client,
            &plan,
            &observer_base_url,
            &ingest_url,
            &observer_token,
            &ingest_token,
            &mut last_identity,
        )
        .await?;
    }
}

type WitnessIdentity = (String, String, u64, String);
async fn poll_witness_once(
    client: &reqwest::Client,
    plan: &tos_health_core::witness::Plan,
    observer_base_url: &str,
    ingest_url: &str,
    observer_token: &str,
    ingest_token: &str,
    last_identity: &mut std::collections::BTreeMap<String, WitnessIdentity>,
) -> Result<(), String> {
    for endpoint in &plan.endpoints {
        let url = format!("{}v1/witness/cache/{}", observer_base_url, endpoint.endpoint_id);
        let response = match client.get(&url).bearer_auth(&observer_token).send().await {
            Ok(response) if response.status().is_success() => response,
            _ => {
                eprintln!("observer witness cache unavailable endpoint={}", endpoint.endpoint_id);
                continue;
            }
        };
        let body = match crate::bounded_body(response, 32_768).await {
            Ok(body) => body,
            Err(_) => {
                eprintln!("observer witness cache body refused endpoint={}", endpoint.endpoint_id);
                continue;
            }
        };
        let (receipt, _) =
            match crate::witness::CacheResponse::decode(&body, &plan, &endpoint.endpoint_id) {
                Ok(value) => value,
                Err(_) => {
                    eprintln!("observer witness cache invalid endpoint={}", endpoint.endpoint_id);
                    continue;
                }
            };
        let identity = (
            receipt.receipt.observer_epoch.clone(),
            receipt.receipt.source_epoch.clone(),
            receipt.receipt.generation.0,
            receipt.receipt.source_hash.clone(),
        );
        if last_identity.get(&endpoint.endpoint_id) == Some(&identity) {
            continue;
        }
        let destination = format!(
            "{}/witness-evidence/{}",
            ingest_url.trim_end_matches("/snapshot-evidence"),
            endpoint.endpoint_id
        );
        let expected_id =
            crate::witness::archive_evidence_id(&receipt.receipt).map_err(str::to_owned)?;
        let accepted = match client
            .post(&destination)
            .bearer_auth(&ingest_token)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => crate::bounded_body(response, 4096)
                .await
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .is_some_and(|value| {
                    value["accepted"] == true
                        && value["namespace"] == "witness_archive_v1"
                        && value["evidence_id"] == expected_id
                        && value["archive_seq"].as_str().is_some_and(|s| {
                            tos_health_core::wire::exact_u64(s).is_ok_and(|v| v > 0)
                        })
                }),
            _ => false,
        };
        if accepted {
            last_identity.insert(endpoint.endpoint_id.clone(), identity);
        } else {
            eprintln!("witness archive unavailable endpoint={}", endpoint.endpoint_id);
        }
    }
    Ok(())
}

pub fn decode_records(
    bytes: &[u8],
    node: &str,
    network: Option<&str>,
) -> Result<Vec<Evidence>, String> {
    use tos_health_core::edge_snapshot::{EdgeSnapshot, EdgeSource};
    if bytes.len() > 262_144 {
        return Err("edge body limit".into());
    }
    let Some(network) = network else {
        let record: Evidence = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if record.node_id != node || record.scope_id != "node" || record.source_id != "collector" {
            return Err("edge identity mismatch".into());
        }
        return Ok(vec![record]);
    };
    let snapshot: EdgeSnapshot = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    snapshot.validate(node, network)?;
    snapshot
        .sources
        .into_iter()
        .map(|source| match source {
            EdgeSource::Native(v) => evidence(v, "consensus"),
            EdgeSource::NativeV2(v) => evidence(v, "consensus"),
            EdgeSource::Process(v) => evidence(v, "process"),
            EdgeSource::Cgroup(v) => evidence(v, "host"),
        })
        .collect()
}

#[cfg(test)]
mod witness_tests {
    use super::*;
    use axum::{
        body::{Body, Bytes},
        http::Request,
    };
    use http_body_util::{BodyExt, Full};
    use hyper::{service::service_fn, Response};
    use hyper_util::rt::TokioIo;
    use serde_json::json;
    use std::{
        convert::Infallible,
        process::{Command, Stdio},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };
    use tokio_rustls::rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn wrong_archive_ack_cannot_suppress_next_real_collector_post() {
        let dir = std::env::temp_dir()
            .join(format!("witness-collector-{}", crate::hex(&crate::random_token().unwrap())));
        std::fs::create_dir(&dir).unwrap();
        let certificate = Command::new("openssl")
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
        assert!(certificate.success());
        let mut identity = std::fs::read(dir.join("server.pem")).unwrap();
        identity.extend(std::fs::read(dir.join("server.key")).unwrap());
        std::fs::write(dir.join("client.pem"), identity).unwrap();
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
        let plan = tos_health_core::witness::Plan::decode(&serde_json::to_vec(&json!({
            "schema_version":1,"profile":"c05_development_cache_only","revision":"a".repeat(64),
            "observer_id":"observer_1","observer_epoch":"observer-1","network_id":"b".repeat(64),
            "genesis":"c".repeat(64),"clock_skew_allowance_ms":5000,
            "endpoints":[{"endpoint_id":"cache_1","fixed_url":format!("https://localhost:{port}/source"),
                "failure_domain":"zone_a","kind":"approved_cache_only_https"}],
            "targets":[{"target_id":"validator_1","node_id":"validator_1","role":"normal",
                "valid_from":"2026-09-29T00:00:00Z","valid_until":"2026-09-30T00:00:00Z",
                "scope_id":"masterchain","workchain":-1,"shard":"9223372036854775808",
                "endpoint_ids":["cache_1"]}]
        })).unwrap()).unwrap();
        let source = serde_json::to_vec(&json!({"schema_version":1,"endpoint_id":"cache_1",
            "source_epoch":"source-1","generation":"1","network_id":"b".repeat(64),
            "genesis":"c".repeat(64),"observed_at":null,"source_age_ms":null,
            "clock_quality":"unknown","coverage":"partial","rows":[{"target_id":"validator_1",
                "observed_at":null,"source_age_ms":null,"anchor":null,
                "network_observation":"unavailable","reported_certificate_membership":"not_checked",
                "reported_proof":"not_checked","private_vote_visibility":"unavailable",
                "coverage":"partial","missing_fields":["private_vote"]}]}))
        .unwrap();
        let token = "abcdefghijklmnopqrstuvwxyz0123456789";
        let cache =
            crate::witness::WitnessCache::new(plan.clone(), token.as_bytes().to_vec()).unwrap();
        cache.admit("cache_1", &source, 20).unwrap();
        let request = Request::builder()
            .uri("/v1/witness/cache/cache_1")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let response = crate::witness::router(cache).oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let cached = response.into_body().collect().await.unwrap().to_bytes();
        let decoded = crate::witness::CacheResponse::decode(&cached, &plan, "cache_1").unwrap().0;
        let expected = crate::witness::archive_evidence_id(&decoded.receipt).unwrap();
        let gets = Arc::new(AtomicUsize::new(0));
        let posts = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let gets = gets.clone();
            let posts = posts.clone();
            async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let cached = cached.clone();
                    let expected = expected.clone();
                    let gets = gets.clone();
                    let posts = posts.clone();
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(socket).await else {
                            return;
                        };
                        let service = service_fn(
                            move |request: hyper::Request<hyper::body::Incoming>| {
                                let cached = cached.clone();
                                let expected = expected.clone();
                                let gets = gets.clone();
                                let posts = posts.clone();
                                async move {
                                    let bytes = if request.uri().path()
                                        == "/v1/witness/cache/cache_1"
                                    {
                                        gets.fetch_add(1, Ordering::SeqCst);
                                        cached.to_vec()
                                    } else if request.uri().path()
                                        == "/v1/manager/witness-evidence/cache_1"
                                    {
                                        let nth = posts.fetch_add(1, Ordering::SeqCst);
                                        serde_json::to_vec(&json!({"accepted":true,"namespace":"witness_archive_v1",
                                    "archive_seq":"1","evidence_id":if nth == 0 { "f".repeat(64) } else { expected }})).unwrap()
                                    } else {
                                        Vec::new()
                                    };
                                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                                        bytes,
                                    ))))
                                }
                            },
                        );
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                    });
                }
            }
        });
        let client = crate::client(&dir.join("server.pem"), &dir.join("client.pem")).unwrap();
        let mut last_identity = std::collections::BTreeMap::new();
        let base = format!("https://localhost:{port}/");
        let ingest = format!("https://localhost:{port}/v1/manager/snapshot-evidence");
        poll_witness_once(&client, &plan, &base, &ingest, token, token, &mut last_identity)
            .await
            .unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert!(last_identity.is_empty(), "wrong ACK must not advance collector identity");
        poll_witness_once(&client, &plan, &base, &ingest, token, token, &mut last_identity)
            .await
            .unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 2);
        assert_eq!(last_identity.len(), 1);
        poll_witness_once(&client, &plan, &base, &ingest, token, token, &mut last_identity)
            .await
            .unwrap();
        assert_eq!(gets.load(Ordering::SeqCst), 3);
        assert_eq!(
            posts.load(Ordering::SeqCst),
            2,
            "valid original ACK deduplicates the immutable source"
        );
        task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
fn evidence<T: serde::Serialize>(
    mut source: tos_health_core::native::SourceEnvelope<T>,
    component: &str,
) -> Result<Evidence, String> {
    use tos_health_core::source::{Availability, Coverage, SourceQuality};
    // The current EdgeSnapshot contract admits only usable, timestamped
    // sources. An unavailable source has no historical observation time in
    // Evidence v1, so refuse it; absence remains unknown in the rule inventory.
    // Never recast an unavailable or unknown source as an available record.
    if source.availability != "available" {
        return Err("unavailable source is not an observation".into());
    }
    let coverage = match source.coverage.status.as_str() {
        "complete" => Coverage::Complete,
        "partial" => Coverage::Partial,
        _ => return Err("unknown source coverage".into()),
    };
    let observed = tos_health_core::query::utc_ms(
        source.observed_at.as_deref().ok_or("missing observation time")?,
    )
    .map_err(str::to_owned)?;
    let success = tos_health_core::query::utc_ms(
        source.last_success_at.as_deref().ok_or("missing success time")?,
    )
    .map_err(str::to_owned)?;
    // Relay age and receipt are not part of the original immutable evidence.
    // This historical copy is not eligible as a live native sample.
    source.source_age_ms = None;
    source.received_at = None;
    Ok(Evidence {
        node_id: source.node_id.clone(),
        scope_id: source.scope_id.clone(),
        source_id: source.source_id.clone(),
        source_record_id: format!("{}:{}", source.source_epoch, source.generation.0),
        process_epoch: source.process_epoch.clone(),
        observed_at_ms: observed,
        received_at_ms: chrono::Utc::now().timestamp_millis(),
        quality: SourceQuality {
            availability: Availability::Available,
            coverage,
            observed_at_ms: Some(observed),
            last_success_at_ms: Some(success),
            clock_valid: source.clock_quality == "valid",
            process_epoch: source.process_epoch.clone(),
            source_sequence: source.generation.0.to_string(),
        },
        payload: serde_json::json!({"component":component,"source":source}),
        redacted: true,
    })
}

pub fn evidence_identity(record: &Evidence) -> Result<(String, String, String), String> {
    let mut immutable = record.clone();
    immutable.received_at_ms = 0;
    Ok((
        record.process_epoch.clone(),
        record.source_record_id.clone(),
        tos_health_core::native::canonical_hash(&immutable)?,
    ))
}
