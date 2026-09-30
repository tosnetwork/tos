//! External-chain witness: does a node's own chain view agree with the
//! independent observers'? The node reports its applied masterchain anchors
//! (seqno + root/file hash) through the native v3 snapshot; observers do the
//! same. A node is in disagreement when it holds a different root hash for a
//! seqno an observer also holds (fork), or when its applied head lags every
//! fresh observer head by more than the allowed distance (isolation). A node
//! that is ahead of the observers is not in disagreement: observers may lag.
//!
//! Inputs come from M's archived native rows, read only; nothing here
//! contacts a node, an edge or a model.
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use tos_health_core::{
    rules::{Fact, FactFrame, FactId},
    wire::U64,
};

/// Source id of the witness fact frames; separate from every archived source.
pub const WITNESS_SOURCE: &str = "witness";
/// Version of the comparison; part of the frame's source epoch.
pub const COMPARE_VERSION: u32 = 1;
/// Samples older than this take no part in a comparison.
pub const FRESH_MS: u64 = 120_000;
/// Rows read per node per pass; anchors change at most once per 15 s.
const ROWS_PER_NODE: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorSample {
    pub observed_ms: u64,
    pub seqno: u32,
    pub root_hash: String,
    pub process_epoch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disagreement {
    pub value: u64,
    pub reason: Option<String>,
    /// Observers with at least one fresh anchor.
    pub witnesses: usize,
}

/// Compare one node's recent anchors against the observers'. `None` means no
/// judgement can be made: the node has no fresh anchor or no observer does.
pub fn compare(
    node: &[AnchorSample],
    observers: &BTreeMap<String, Vec<AnchorSample>>,
    now_ms: u64,
    lag_blocks: u32,
) -> Option<Disagreement> {
    let fresh = |s: &&AnchorSample| now_ms.saturating_sub(s.observed_ms) <= FRESH_MS;
    let node_head = node.iter().filter(fresh).max_by_key(|s| s.seqno)?;
    let mut witnesses = 0usize;
    let mut best_observer_head: Option<u32> = None;
    let mut fork: Option<String> = None;
    for (name, samples) in observers {
        let Some(head) = samples.iter().filter(fresh).max_by_key(|s| s.seqno) else {
            continue;
        };
        witnesses = witnesses.saturating_add(1);
        best_observer_head = Some(best_observer_head.map_or(head.seqno, |h| h.max(head.seqno)));
        // Fork: the same seqno with a different root hash in any pair of samples.
        for mine in node {
            if let Some(theirs) = samples.iter().find(|s| s.seqno == mine.seqno) {
                if theirs.root_hash != mine.root_hash && fork.is_none() {
                    fork = Some(format!("fork_at_{}_vs_{name}", mine.seqno));
                }
            }
        }
    }
    let observer_head = best_observer_head?;
    if let Some(reason) = fork {
        return Some(Disagreement { value: 1, reason: Some(reason), witnesses });
    }
    if observer_head.saturating_sub(node_head.seqno) > lag_blocks {
        return Some(Disagreement {
            value: 1,
            reason: Some(format!(
                "behind_observers_by_{}",
                observer_head.saturating_sub(node_head.seqno)
            )),
            witnesses,
        });
    }
    Some(Disagreement { value: 0, reason: None, witnesses })
}

/// Latest archived v3 anchors per node from M's evidence database (read only).
pub fn read_anchors(
    path: &Path,
    network_id: &str,
    nodes: &[String],
) -> Result<BTreeMap<String, Vec<AnchorSample>>, String> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;
    conn.busy_timeout(Duration::from_millis(500)).map_err(|e| e.to_string())?;
    let mut out = BTreeMap::new();
    for node in nodes {
        let mut statement = conn
            .prepare(
                "SELECT process_epoch, body FROM observations WHERE node=?1 AND scope='node' \
                 AND source='native_core' ORDER BY store_seq DESC LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![node, ROWS_PER_NODE as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        let mut samples = Vec::new();
        for row in rows {
            let (epoch, body) = row.map_err(|e| e.to_string())?;
            if body.len() > 32_768 {
                continue;
            }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else { continue };
            let record = &value["record"];
            // Only archived snapshots carry a `source` payload; fact frames do not.
            let Some(source) = record["payload"].get("source") else { continue };
            if source["payload"]["network_id"].as_str() != Some(network_id) {
                continue;
            }
            let chain = &source["payload"]["chain"];
            let (Some(seqno), Some(root), Some(observed_ms)) = (
                chain["applied"]["seqno"].as_u64(),
                chain["applied"]["root_hash"].as_str(),
                record["observed_at_ms"].as_u64(),
            ) else {
                continue;
            };
            let Ok(seqno) = u32::try_from(seqno) else { continue };
            samples.push(AnchorSample {
                observed_ms,
                seqno,
                root_hash: root.to_owned(),
                process_epoch: epoch,
            });
        }
        out.insert(node.clone(), samples);
    }
    Ok(out)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessConfig {
    pub network_id: String,
    pub evidence_db: PathBuf,
    pub manager_url: String,
    pub ca_file: PathBuf,
    pub identity_file: PathBuf,
    pub manager_token_file: PathBuf,
    pub validators: Vec<String>,
    pub observers: Vec<String>,
    /// Blocks a node may lag the freshest observer head before it disagrees.
    pub lag_blocks: u32,
}

/// One witness frame for a node, bound to the node's current native epoch.
pub fn frame(
    config: &WitnessConfig,
    node: &str,
    epoch: &str,
    generation: u64,
    now_ms: u64,
    value: u64,
) -> FactFrame {
    FactFrame {
        schema_version: 1,
        network_id: config.network_id.clone(),
        node_id: node.to_owned(),
        scope_id: "node".into(),
        source_id: WITNESS_SOURCE.into(),
        process_epoch: epoch.to_owned(),
        source_epoch: format!("{epoch}:witness-v{COMPARE_VERSION}"),
        generation: U64(generation),
        source_age_ms: U64(0),
        request_duration_ms: U64(0),
        observed_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            i64::try_from(now_ms).unwrap_or(0),
        )
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        clock_valid: true,
        complete: true,
        facts: vec![Fact { id: FactId::ObserverDisagreement, value: U64(value) }],
    }
}

pub async fn run(config: WitnessConfig) -> Result<(), String> {
    if !tos_health_core::wire::hash(&config.network_id)
        || config.validators.is_empty()
        || config.observers.is_empty()
        || config.lag_blocks == 0
        || !config.validators.iter().chain(&config.observers).all(|n| crate::alias(n))
    {
        return Err("invalid witness compare configuration".into());
    }
    let client = crate::client(&config.ca_file, &config.identity_file)?;
    let token =
        String::from_utf8(crate::secret(&config.manager_token_file)?).map_err(|e| e.to_string())?;
    let mut generation = 0u64;
    let mut timer = tokio::time::interval(Duration::from_secs(15));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let all: Vec<String> = config.validators.iter().chain(&config.observers).cloned().collect();
    loop {
        timer.tick().await;
        let anchors = match read_anchors(&config.evidence_db, &config.network_id, &all) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("witness compare: evidence read failed: {e}");
                continue;
            }
        };
        let now_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
        generation = generation.checked_add(1).ok_or("witness generation exhausted")?;
        for node in &all {
            // Observers are compared against the other observers only.
            let others: BTreeMap<String, Vec<AnchorSample>> = config
                .observers
                .iter()
                .filter(|o| *o != node)
                .filter_map(|o| anchors.get(o).map(|s| (o.clone(), s.clone())))
                .collect();
            let Some(samples) = anchors.get(node) else { continue };
            let Some(epoch) = samples.first().map(|s| s.process_epoch.clone()) else { continue };
            let Some(result) = compare(samples, &others, now_ms, config.lag_blocks) else {
                eprintln!("witness compare: {node}: no fresh anchor pair, no fact posted");
                continue;
            };
            if let Some(reason) = &result.reason {
                eprintln!(
                    "witness compare: {node}: disagreement ({reason}, {} witnesses)",
                    result.witnesses
                );
            }
            let f = frame(&config, node, &epoch, generation, now_ms, result.value);
            match client.post(&config.manager_url).bearer_auth(&token).json(&f).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    eprintln!("witness compare: manager refused {node}: {}", response.status())
                }
                Err(e) => eprintln!("witness compare: manager request failed: {e}"),
            }
        }
    }
}
