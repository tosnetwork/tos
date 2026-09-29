use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
use tos_health_core::evidence::Evidence;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    pub node_id: String,
    pub edge_url: String,
    pub ingest_url: String,
    pub ca_file: PathBuf,
    pub identity_file: PathBuf,
    pub edge_token_file: PathBuf,
    pub ingest_token_file: PathBuf,
}
impl CollectorConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !crate::alias(&self.node_id) {
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
    let mut last_identity = None;
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
        let record: Evidence = match serde_json::from_slice(&bytes) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("invalid edge schema");
                continue;
            }
        };
        if record.node_id != config.node_id || record.scope_id != "node" {
            eprintln!("edge identity mismatch");
            continue;
        }
        let identity = (record.process_epoch.clone(), record.source_record_id.clone());
        if last_identity.as_ref() == Some(&identity) {
            continue;
        }
        match client.post(&config.ingest_url).bearer_auth(&ingest_token).json(&record).send().await
        {
            Ok(response) if response.status().is_success() => {
                let _ = crate::bounded_body(response, 4096).await;
                last_identity = Some(identity);
            }
            _ => eprintln!("ingest unavailable; no backlog retained"),
        }
    }
}
