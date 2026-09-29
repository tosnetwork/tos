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
            || self.network_id.as_ref().is_some_and(|v| !tos_health_core::wire::hash(v))
        {
            return Err("invalid node alias".into());
        }
        for value in [&self.edge_url, &self.ingest_url] {
            let url = reqwest::Url::parse(value).map_err(|e| e.to_string())?;
            if url.scheme() != "https"
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
        for record in records {
            let identity = evidence_identity(&record)?;
            if last_identity.get(&record.source_id) == Some(&identity) {
                continue;
            }
            match client
                .post(&config.ingest_url)
                .bearer_auth(&ingest_token)
                .json(&record)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    let _ = crate::bounded_body(response, 4096).await;
                    last_identity.insert(record.source_id, identity);
                }
                _ => eprintln!("ingest unavailable; no backlog retained"),
            }
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
        })
        .collect()
}
fn evidence<T: serde::Serialize>(
    mut source: tos_health_core::native::SourceEnvelope<T>,
    component: &str,
) -> Result<Evidence, String> {
    use tos_health_core::source::{Availability, Coverage, SourceQuality};
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
            coverage: Coverage::Partial,
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
