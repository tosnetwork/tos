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
}
impl CollectorConfig {
    pub fn validate(&self) -> Result<(), String> {
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
        Ok(())
    }
}
pub async fn run(config: CollectorConfig) -> Result<(), String> {
    config.validate()?;
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
            EdgeSource::Process(v) => evidence(v, "process"),
            EdgeSource::Cgroup(v) => evidence(v, "host"),
        })
        .collect()
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
