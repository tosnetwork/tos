//! Local monitoring-host storage. Control transactions never share the evidence database.
use crate::witness::{CacheResponse, RelativeAge, RowQualification};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, Instant},
};
use tos_health_core::{
    evidence::{Evidence, EvidenceStore},
    health_state::{HealthState, Sample},
    rules::FactFrame,
    wire::U64,
    witness::{canonical_plan_hash, Plan},
};

type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn open(path: &Path, max_bytes: u64) -> Result<Connection> {
    if max_bytes < 262_144 {
        return Err("database quota too small".into());
    }
    let conn = Connection::open(path).map_err(err)?;
    conn.busy_timeout(Duration::from_millis(100)).map_err(err)?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).map_err(err)?;
    if version > 1 {
        return Err("unsupported database schema".into());
    }
    conn.pragma_update(None, "journal_mode", "WAL").map_err(err)?;
    conn.pragma_update(None, "synchronous", "FULL").map_err(err)?;
    conn.pragma_update(None, "wal_autocheckpoint", 64).map_err(err)?;
    let mode: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0)).map_err(err)?;
    let sync: i64 = conn.pragma_query_value(None, "synchronous", |r| r.get(0)).map_err(err)?;
    if mode != "wal" || sync != 2 {
        return Err("WAL/FULL not effective".into());
    }
    let page: u64 = conn.pragma_query_value(None, "page_size", |r| r.get(0)).map_err(err)?;
    let pages = max_bytes / page;
    let effective: u64 =
        conn.pragma_update_and_check(None, "max_page_count", pages, |r| r.get(0)).map_err(err)?;
    if effective > pages {
        return Err("database exceeds configured quota".into());
    }
    conn.pragma_update(None, "user_version", 1).map_err(err)?;
    Ok(conn)
}
fn bind_network(conn: &mut Connection, network: &str) -> Result<()> {
    if !tos_health_core::wire::hash(network) {
        return Err("invalid database network".into());
    }
    let tx = conn.transaction().map_err(err)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS database_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),network TEXT NOT NULL)").map_err(err)?;
    tx.execute("INSERT OR IGNORE INTO database_identity VALUES(1,?1)", [network]).map_err(err)?;
    let stored: String = tx
        .query_row("SELECT network FROM database_identity WHERE singleton=1", [], |r| r.get(0))
        .map_err(err)?;
    if stored != network {
        return Err("database network mismatch".into());
    }
    tx.commit().map_err(err)
}
fn wal_budget(path: &Path, quota: u64) -> Result<()> {
    let wal = std::ffi::OsString::from(format!("{}-wal", path.display()));
    match std::fs::metadata(wal) {
        Ok(m) if m.len() > quota => Err("WAL quota exceeded".into()),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(err(e)),
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableEvidence {
    pub source_epoch: String,
    pub record: Evidence,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRow {
    pub store_seq: U64,
    pub evidence_id: String,
    pub evidence: DurableEvidence,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessArchiveRow {
    pub namespace: String,
    pub archive_seq: U64,
    pub evidence_id: String,
    pub response: CacheResponse,
}
fn witness_immutable_metadata_hash(response: &CacheResponse) -> Result<String> {
    let receipt = &response.receipt;
    let immutable_rows: Vec<_> = response
        .row_ages
        .iter()
        .map(|age| {
            (
                &age.target_id,
                &age.first_received_at,
                age.observer_clock_quality_at_first_receipt,
                age.source_age_at_first_receipt_ms,
            )
        })
        .collect();
    let metadata = serde_json::to_vec(&(
        &receipt.observer_id,
        &receipt.observer_epoch,
        &receipt.plan_revision,
        &receipt.plan_hash,
        &receipt.endpoint_id,
        &receipt.source_epoch,
        receipt.generation,
        &receipt.source_hash,
        receipt.observer_clock_quality,
        &receipt.first_received_at,
        receipt.request_duration_ms,
        immutable_rows,
    ))
    .map_err(err)?;
    Ok(format!("{:x}", Sha256::digest(&metadata)))
}
pub struct EvidenceDb {
    conn: Connection,
    path: std::path::PathBuf,
    quota: u64,
    current_tracks: BTreeMap<String, CurrentTrack>,
}
struct CurrentTrack {
    generation: u64,
    source_hash: String,
    first_received: Instant,
    first_extra_ms: Option<u64>,
    age_class: BTreeMap<String, RelativeAge>,
    first_age_floor_ms: BTreeMap<String, Option<u64>>,
}
type CurrentActivationRow =
    (String, String, String, Option<String>, Option<String>, Option<String>, i64);
impl EvidenceDb {
    pub fn bind_network(&mut self, network: &str) -> Result<()> {
        bind_network(&mut self.conn, network)
    }
    pub fn open(path: &Path, quota: u64) -> Result<Self> {
        let conn = open(path, quota)?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS observations (
            store_seq INTEGER PRIMARY KEY AUTOINCREMENT,
            node TEXT NOT NULL, scope TEXT NOT NULL, process_epoch TEXT NOT NULL,
            source_epoch TEXT NOT NULL, source TEXT NOT NULL, source_record TEXT NOT NULL,
            content_hash TEXT NOT NULL, body TEXT NOT NULL,
            UNIQUE(node,scope,process_epoch,source_epoch,source,source_record));
            CREATE INDEX IF NOT EXISTS observation_scope ON observations(node,scope,store_seq);
            CREATE TABLE IF NOT EXISTS quarantined(node TEXT,scope TEXT,process_epoch TEXT,source_epoch TEXT,source TEXT,
            PRIMARY KEY(node,scope,process_epoch,source_epoch,source));
            CREATE TABLE IF NOT EXISTS witness_observations (
            store_seq INTEGER PRIMARY KEY AUTOINCREMENT,
            observer_epoch TEXT NOT NULL,endpoint TEXT NOT NULL,source_epoch TEXT NOT NULL,
            generation TEXT NOT NULL,source_hash TEXT NOT NULL,metadata_hash TEXT NOT NULL,
            evidence_id TEXT NOT NULL,body TEXT NOT NULL,
            UNIQUE(observer_epoch,endpoint,source_epoch,generation));
            CREATE INDEX IF NOT EXISTS witness_endpoint_seq ON witness_observations(endpoint,store_seq);
            CREATE TABLE IF NOT EXISTS witness_quarantined (
            observer_epoch TEXT NOT NULL,endpoint TEXT NOT NULL,source_epoch TEXT NOT NULL,
            PRIMARY KEY(observer_epoch,endpoint,source_epoch));
            CREATE TABLE IF NOT EXISTS witness_current_activation (
            endpoint TEXT PRIMARY KEY,plan_revision TEXT NOT NULL,plan_hash TEXT NOT NULL,observer_epoch TEXT NOT NULL,
            source_epoch TEXT NOT NULL,highest_generation TEXT,source_hash TEXT,metadata_hash TEXT,
            quarantined INTEGER NOT NULL DEFAULT 0);").map_err(err)?;
        Ok(Self { conn, path: path.into(), quota, current_tracks: BTreeMap::new() })
    }
    /// Activate the explicit startup plan's current source epochs. Historical
    /// witness rows and their independent quarantine are not changed.
    /// Same-activation reopening preserves high-water and quarantine; a new
    /// plan revision is the only reset path. Retired entries still consume the
    /// global 16-entry bound, so repeated revisions cannot grow this index.
    pub fn activate_witness_current(&mut self, plan: &Plan) -> Result<()> {
        plan.validate().map_err(str::to_owned)?;
        wal_budget(&self.path, self.quota)?;
        let plan_hash = canonical_plan_hash(plan).map_err(str::to_owned)?;
        let tx = self.conn.transaction().map_err(err)?;
        let reused_revision: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM witness_current_activation WHERE plan_revision=?1 AND plan_hash<>?2)",
                params![plan.revision, plan_hash],
                |row| row.get(0),
            )
            .map_err(err)?;
        if reused_revision {
            return Err("witness current activation changed without new revision".into());
        }
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM witness_current_activation", [], |row| row.get(0))
            .map_err(err)?;
        let mut additions = 0i64;
        for endpoint in &plan.endpoints {
            let prior: Option<(String, String, String, String)> = tx
                .query_row(
                    "SELECT plan_revision,plan_hash,observer_epoch,source_epoch FROM witness_current_activation WHERE endpoint=?1",
                    params![endpoint.endpoint_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(err)?;
            match prior {
                Some((revision, hash, observer, source))
                    if revision == plan.revision
                        && hash == plan_hash
                        && observer == plan.observer_epoch
                        && source == endpoint.current_source_epoch => {}
                Some((revision, _, _, _)) if revision == plan.revision => {
                    return Err("witness current activation changed without new revision".into());
                }
                Some(_) => {
                    tx.execute(
                        "UPDATE witness_current_activation SET plan_revision=?2,plan_hash=?3,observer_epoch=?4,source_epoch=?5,
                         highest_generation=NULL,source_hash=NULL,metadata_hash=NULL,quarantined=0 WHERE endpoint=?1",
                        params![endpoint.endpoint_id, plan.revision, plan_hash, plan.observer_epoch, endpoint.current_source_epoch],
                    )
                    .map_err(err)?;
                }
                None => {
                    additions += 1;
                    tx.execute(
                        "INSERT INTO witness_current_activation(endpoint,plan_revision,plan_hash,observer_epoch,source_epoch)
                         VALUES(?1,?2,?3,?4,?5)",
                        params![endpoint.endpoint_id, plan.revision, plan_hash, plan.observer_epoch, endpoint.current_source_epoch],
                    )
                    .map_err(err)?;
                }
            }
        }
        if count + additions > 16 {
            return Err("witness current activation index full".into());
        }
        tx.commit().map_err(err)
    }
    /// Separate development current-order gate. It is never called by the
    /// historical archive route, never enters `observations`, and its rows
    /// cannot feed rules until the caller supplies a complete measured age.
    pub fn review_witness_current(
        &mut self,
        response: &CacheResponse,
        plan: &Plan,
        measured_extra_ms: Option<u64>,
    ) -> Result<Vec<RowQualification>> {
        wal_budget(&self.path, self.quota)?;
        let endpoint = &response.receipt.endpoint_id;
        let body = serde_json::to_vec(response).map_err(err)?;
        let (validated, source) =
            CacheResponse::decode(&body, plan, endpoint).map_err(str::to_owned)?;
        let plan_hash = canonical_plan_hash(plan).map_err(str::to_owned)?;
        let approved_epoch = plan
            .endpoints
            .iter()
            .find(|candidate| candidate.endpoint_id == *endpoint)
            .ok_or("unapproved current endpoint")?
            .current_source_epoch
            .as_str();
        if source.source_epoch != approved_epoch {
            return Err("WITNESS_CURRENT_EPOCH_UNAPPROVED".into());
        }
        let metadata_hash = witness_immutable_metadata_hash(&validated)?;
        let qualify = |extra| -> Result<Vec<RowQualification>> {
            source
                .rows
                .iter()
                .map(|row| {
                    crate::witness::qualify_validated_row(
                        &validated,
                        &source,
                        plan,
                        &row.target_id,
                        extra,
                    )
                    .map_err(str::to_owned)
                })
                .collect()
        };
        let tx = self.conn.transaction().map_err(err)?;
        let prior: Option<CurrentActivationRow> = tx
            .query_row(
                "SELECT plan_hash,observer_epoch,source_epoch,highest_generation,source_hash,metadata_hash,quarantined
                 FROM witness_current_activation WHERE endpoint=?1",
                params![endpoint],
                |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?))
                },
            )
            .optional()
            .map_err(err)?;
        let Some((active_hash, observer, active_source, high, old_hash, old_metadata, quarantined)) =
            prior
        else {
            return Err("WITNESS_CURRENT_NOT_ACTIVATED".into());
        };
        if active_hash != plan_hash
            || observer != validated.receipt.observer_epoch
            || active_source != source.source_epoch
        {
            return Err("WITNESS_CURRENT_NOT_ACTIVATED".into());
        }
        if quarantined != 0 {
            return Err("WITNESS_CURRENT_CONFLICT".into());
        }
        if let Some(previous) = high {
            let previous = tos_health_core::wire::exact_u64(&previous).map_err(str::to_owned)?;
            if source.generation.0 < previous {
                return Err("WITNESS_CURRENT_REGRESSION".into());
            }
            if source.generation.0 == previous {
                if old_hash.as_deref() != Some(validated.receipt.source_hash.as_str())
                    || old_metadata.as_deref() != Some(metadata_hash.as_str())
                {
                    tx.execute(
                        "UPDATE witness_current_activation SET quarantined=1 WHERE endpoint=?1",
                        params![endpoint],
                    )
                    .map_err(err)?;
                    tx.commit().map_err(err)?;
                    self.current_tracks.remove(endpoint);
                    return Err("WITNESS_CURRENT_CONFLICT".into());
                }
                let active = self.current_tracks.get(endpoint).filter(|track| {
                    track.generation == source.generation.0
                        && track.source_hash == validated.receipt.source_hash
                });
                let extra = active.and_then(|track| {
                    let elapsed: u64 =
                        track.first_received.elapsed().as_millis().try_into().ok()?;
                    Some(track.first_extra_ms?.checked_add(elapsed)?.max(measured_extra_ms?))
                });
                let mut qualified = qualify(extra)?;
                if let Some(track) = self.current_tracks.get_mut(endpoint) {
                    let elapsed: Option<u64> =
                        track.first_received.elapsed().as_millis().try_into().ok();
                    for row in &mut qualified {
                        let original_floor = track
                            .first_age_floor_ms
                            .get(&row.target_id)
                            .copied()
                            .flatten()
                            .zip(elapsed)
                            .and_then(|(age, elapsed)| age.checked_add(elapsed));
                        match original_floor {
                            Some(age) if age > tos_health_core::witness::USABLE_AGE_MS => {
                                row.relative_age = RelativeAge::Stale;
                            }
                            None => row.relative_age = RelativeAge::Unknown,
                            Some(_) => {}
                        }
                        match track.age_class.get(&row.target_id) {
                            Some(RelativeAge::Stale) => row.relative_age = RelativeAge::Stale,
                            Some(RelativeAge::Unknown) => row.relative_age = RelativeAge::Unknown,
                            _ => {}
                        }
                        track.age_class.insert(row.target_id.clone(), row.relative_age);
                    }
                }
                return Ok(qualified);
            }
        }
        let qualified = qualify(measured_extra_ms)?;
        tx.execute(
            "UPDATE witness_current_activation SET highest_generation=?2,source_hash=?3,metadata_hash=?4 WHERE endpoint=?1",
            params![endpoint, source.generation.0.to_string(), validated.receipt.source_hash, metadata_hash],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        self.current_tracks.insert(
            endpoint.clone(),
            CurrentTrack {
                generation: source.generation.0,
                source_hash: validated.receipt.source_hash.clone(),
                first_received: Instant::now(),
                first_extra_ms: measured_extra_ms,
                age_class: qualified
                    .iter()
                    .map(|row| (row.target_id.clone(), row.relative_age))
                    .collect(),
                first_age_floor_ms: validated
                    .row_ages
                    .iter()
                    .map(|age| {
                        (
                            age.target_id.clone(),
                            age.effective_age_ms
                                .map(|value| value.0)
                                .zip(measured_extra_ms)
                                .and_then(|(age, extra)| age.checked_add(extra)),
                        )
                    })
                    .collect(),
            },
        );
        Ok(qualified)
    }
    pub fn insert(&mut self, value: DurableEvidence) -> Result<EvidenceRow> {
        wal_budget(&self.path, self.quota)?;
        if value.source_epoch.is_empty() || value.source_epoch.len() > 128 {
            return Err("invalid source epoch".into());
        }
        // Reuse the bounded metadata checks; temporary validation never changes the database.
        EvidenceStore::new(65_536).insert(value.record.clone()).map_err(err)?;
        let mut canonical = value.clone();
        canonical.record.received_at_ms = 0;
        let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&canonical).map_err(err)?));
        let body = serde_json::to_string(&value).map_err(err)?;
        if body.len() > 32768 {
            return Err("evidence size limit".into());
        }
        let e = &value.record;
        let tx = self.conn.transaction().map_err(err)?;
        let quarantined:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM quarantined WHERE node=?1 AND scope=?2 AND process_epoch=?3 AND source_epoch=?4 AND source=?5)",params![e.node_id,e.scope_id,e.process_epoch,value.source_epoch,e.source_id],|r|r.get(0)).map_err(err)?;
        if quarantined {
            return Err("SOURCE_CONFLICT".into());
        }
        let prior:Option<(i64,String,String)>=tx.query_row("SELECT store_seq,content_hash,body FROM observations WHERE node=?1 AND scope=?2 AND process_epoch=?3 AND source_epoch=?4 AND source=?5 AND source_record=?6",params![e.node_id,e.scope_id,e.process_epoch,value.source_epoch,e.source_id,e.source_record_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(err)?;
        if let Some((seq, hash, stored)) = prior {
            if hash != digest {
                tx.execute(
                    "INSERT OR IGNORE INTO quarantined VALUES (?1,?2,?3,?4,?5)",
                    params![
                        e.node_id,
                        e.scope_id,
                        e.process_epoch,
                        value.source_epoch,
                        e.source_id
                    ],
                )
                .map_err(err)?;
                tx.commit().map_err(err)?;
                return Err("SOURCE_CONFLICT".into());
            }
            return Ok(EvidenceRow {
                store_seq: U64(u64::try_from(seq).map_err(err)?),
                evidence_id: hash,
                evidence: serde_json::from_str(&stored).map_err(err)?,
            });
        }
        tx.execute("INSERT INTO observations(node,scope,process_epoch,source_epoch,source,source_record,content_hash,body) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![e.node_id,e.scope_id,e.process_epoch,value.source_epoch,e.source_id,e.source_record_id,digest,body]).map_err(err)?;
        let seq = tx.last_insert_rowid();
        tx.commit().map_err(err)?;
        Ok(EvidenceRow {
            store_seq: U64(u64::try_from(seq).map_err(err)?),
            evidence_id: digest,
            evidence: value,
        })
    }
    pub fn insert_witness(
        &mut self,
        response: CacheResponse,
        plan: &Plan,
    ) -> Result<WitnessArchiveRow> {
        wal_budget(&self.path, self.quota)?;
        let body = serde_json::to_vec(&response).map_err(err)?;
        let endpoint = &response.receipt.endpoint_id;
        let _source = CacheResponse::decode(&body, plan, endpoint).map_err(str::to_owned)?;
        if body.len() > 32_768 {
            return Err("witness archive size limit".into());
        }
        let receipt = &response.receipt;
        let current_plan_hash = canonical_plan_hash(plan).map_err(str::to_owned)?;
        let metadata_hash = witness_immutable_metadata_hash(&response)?;
        let evidence_id = crate::witness::archive_evidence_id(receipt).map_err(str::to_owned)?;
        let body_text = String::from_utf8(body).map_err(err)?;
        let tx = self.conn.transaction().map_err(err)?;
        let quarantined: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM witness_quarantined
            WHERE observer_epoch=?1 AND endpoint=?2 AND source_epoch=?3)",
                params![receipt.observer_epoch, endpoint, receipt.source_epoch],
                |r| r.get(0),
            )
            .map_err(err)?;
        if quarantined {
            return Err("WITNESS_SOURCE_CONFLICT".into());
        }
        let prior: Option<(i64, String, String, String)> = tx
            .query_row(
                "SELECT store_seq,source_hash,metadata_hash,body FROM witness_observations
             WHERE observer_epoch=?1 AND endpoint=?2 AND source_epoch=?3 AND generation=?4",
                params![
                    receipt.observer_epoch,
                    endpoint,
                    receipt.source_epoch,
                    receipt.generation.0.to_string()
                ],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(err)?;
        if let Some((seq, hash, prior_metadata, stored)) = prior {
            if hash != receipt.source_hash || prior_metadata != metadata_hash {
                tx.execute(
                    "INSERT OR IGNORE INTO witness_quarantined VALUES(?1,?2,?3)",
                    params![receipt.observer_epoch, endpoint, receipt.source_epoch],
                )
                .map_err(err)?;
                let current_quarantined = tx
                    .execute(
                        "UPDATE witness_current_activation SET quarantined=1
                         WHERE endpoint=?1 AND plan_hash=?2 AND observer_epoch=?3 AND source_epoch=?4",
                        params![endpoint, current_plan_hash, receipt.observer_epoch, receipt.source_epoch],
                    )
                    .map_err(err)?;
                tx.commit().map_err(err)?;
                if current_quarantined != 0 {
                    self.current_tracks.remove(endpoint);
                }
                return Err("WITNESS_SOURCE_CONFLICT".into());
            }
            return Ok(WitnessArchiveRow {
                namespace: "witness_archive_v1".into(),
                archive_seq: U64(u64::try_from(seq).map_err(err)?),
                evidence_id,
                response: serde_json::from_str(&stored).map_err(err)?,
            });
        }
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM witness_observations", [], |r| r.get(0))
            .map_err(err)?;
        if count >= 4096 {
            return Err("witness archive capacity".into());
        }
        tx.execute("INSERT INTO witness_observations(observer_epoch,endpoint,source_epoch,generation,source_hash,metadata_hash,evidence_id,body)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![receipt.observer_epoch, endpoint, receipt.source_epoch, receipt.generation.0.to_string(),
                receipt.source_hash, metadata_hash, evidence_id, body_text]).map_err(err)?;
        let seq = tx.last_insert_rowid();
        tx.commit().map_err(err)?;
        Ok(WitnessArchiveRow {
            namespace: "witness_archive_v1".into(),
            archive_seq: U64(u64::try_from(seq).map_err(err)?),
            evidence_id,
            response,
        })
    }
    pub fn watermark(&self) -> Result<u64> {
        let v: Option<i64> = self
            .conn
            .query_row("SELECT seq FROM sqlite_sequence WHERE name='observations'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(err)?;
        u64::try_from(v.unwrap_or(0)).map_err(err)
    }
    /// Indexed, fixed-watermark page; caller owns grant authorization and cursor binding.
    pub fn page(
        &self,
        node: &str,
        scope: &str,
        watermark: u64,
        after: u64,
        limit: u32,
    ) -> Result<Vec<EvidenceRow>> {
        if !(1..=100).contains(&limit) || watermark > i64::MAX as u64 || after > watermark {
            return Err("invalid page".into());
        }
        let reader = Connection::open_with_flags(
            &self.path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(err)?;
        reader.busy_timeout(Duration::from_millis(100)).map_err(err)?;
        let mut query=reader.prepare("SELECT store_seq,content_hash,body FROM observations WHERE node=?1 AND scope=?2 AND store_seq>?3 AND store_seq<=?4 AND NOT EXISTS(SELECT 1 FROM quarantined q WHERE q.node=observations.node AND q.scope=observations.scope AND q.process_epoch=observations.process_epoch AND q.source_epoch=observations.source_epoch AND q.source=observations.source) ORDER BY store_seq LIMIT ?5").map_err(err)?;
        let rows = query
            .query_map(params![node, scope, after as i64, watermark as i64, limit], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
            })
            .map_err(err)?;
        let (mut output, mut bytes) = (Vec::new(), 0usize);
        for row in rows {
            let (seq, id, body) = row.map_err(err)?;
            bytes = bytes.checked_add(body.len()).ok_or("scan overflow")?;
            if bytes > 8 * 1024 * 1024 {
                return Err("QUERY_TIMEOUT".into());
            }
            output.push(EvidenceRow {
                store_seq: U64(u64::try_from(seq).map_err(err)?),
                evidence_id: id,
                evidence: serde_json::from_str(&body).map_err(err)?,
            });
        }
        Ok(output)
    }
    pub fn checkpoint(&self) -> Result<(i64, i64, i64)> {
        self.conn
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .map_err(err)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleKey {
    pub node: String,
    pub scope: String,
    pub rule: String,
}
impl RuleKey {
    fn valid(&self) -> bool {
        [&self.node, &self.scope, &self.rule].iter().all(|s| tos_health_core::wire::alias(s))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "signal", rename_all = "snake_case", deny_unknown_fields)]
pub enum Evaluation {
    Bad { severity: String },
    Unknown,
    Good { samples: BTreeMap<String, Sample> },
}
pub struct ControlUpdate {
    pub key: RuleKey,
    pub signal: Evaluation,
    pub required: Vec<String>,
    pub hold: u64,
}
pub struct ControlDb {
    conn: Connection,
    path: std::path::PathBuf,
    quota: u64,
    max_incidents: u32,
    max_outbox: u32,
}
impl ControlDb {
    pub fn bind_network(&mut self, network: &str) -> Result<()> {
        bind_network(&mut self.conn, network)
    }
    pub fn open(path: &Path, quota: u64, max_incidents: u32, max_outbox: u32) -> Result<Self> {
        if max_incidents == 0 || max_outbox == 0 || max_incidents > 10000 || max_outbox > 10000 {
            return Err("invalid control capacity".into());
        }
        let conn = open(path, quota)?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS incidents(node TEXT,scope TEXT,rule TEXT,body TEXT NOT NULL,PRIMARY KEY(node,scope,rule));
        CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,key TEXT NOT NULL UNIQUE,body TEXT NOT NULL,delivered INTEGER NOT NULL DEFAULT 0,
            receiver_alias TEXT NOT NULL DEFAULT '',payload_hash TEXT NOT NULL DEFAULT '',attempts INTEGER NOT NULL DEFAULT 0,next_due_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS source_state(node TEXT NOT NULL,scope TEXT NOT NULL,source TEXT NOT NULL,
            process_epoch TEXT NOT NULL,source_epoch TEXT NOT NULL,generation TEXT NOT NULL,
            content_hash TEXT NOT NULL,evidence_id TEXT NOT NULL,store_seq INTEGER NOT NULL,
            clock_valid INTEGER NOT NULL,complete INTEGER NOT NULL,
            PRIMARY KEY(node,scope,source));
        CREATE TABLE IF NOT EXISTS evaluation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),sequence INTEGER NOT NULL);
        INSERT OR IGNORE INTO evaluation VALUES(1,0);").map_err(err)?;
        // C02 databases may carry pending rows. Add metadata without deleting or
        // acknowledging those rows; first delivery binds their approved alias.
        let columns = {
            let mut stmt = conn.prepare("PRAGMA table_info(outbox)").map_err(err)?;
            let found = stmt
                .query_map([], |r| r.get::<_, String>(1))
                .map_err(err)?
                .collect::<std::result::Result<std::collections::BTreeSet<_>, _>>()
                .map_err(err)?;
            found
        };
        for (name, definition) in [
            ("receiver_alias", "TEXT NOT NULL DEFAULT ''"),
            ("payload_hash", "TEXT NOT NULL DEFAULT ''"),
            ("attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("next_due_ms", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            if !columns.contains(name) {
                conn.execute_batch(&format!("ALTER TABLE outbox ADD COLUMN {name} {definition}"))
                    .map_err(err)?;
            }
        }
        let mut db = Self { conn, path: path.into(), quota, max_incidents, max_outbox };
        db.restore_unknown()?;
        Ok(db)
    }
    fn restore_unknown(&mut self) -> Result<()> {
        let tx = self.conn.transaction().map_err(err)?;
        let rows = {
            let mut stmt = tx
                .prepare("SELECT node,scope,rule,body FROM incidents LIMIT 10001")
                .map_err(err)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })
                .map_err(err)?;
            rows.collect::<std::result::Result<Vec<_>, _>>().map_err(err)?
        };
        if rows.len() > self.max_incidents as usize {
            return Err("incident capacity exceeded".into());
        }
        for (node, scope, rule, body) in rows {
            let mut state: HealthState = serde_json::from_str(&body).map_err(err)?;
            state.after_restart();
            tx.execute(
                "UPDATE incidents SET body=?4 WHERE node=?1 AND scope=?2 AND rule=?3",
                params![node, scope, rule, serde_json::to_string(&state).map_err(err)?],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)
    }
    pub fn state(&self, key: &RuleKey) -> Result<Option<HealthState>> {
        let body: Option<String> = self
            .conn
            .query_row(
                "SELECT body FROM incidents WHERE node=?1 AND scope=?2 AND rule=?3",
                params![key.node, key.scope, key.rule],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        body.map(|b| serde_json::from_str(&b).map_err(err)).transpose()
    }
    /// References are written only after the evidence writer has committed the
    /// immutable row. This is a bounded latest-state index, not history.
    pub fn record_source_ref(&mut self, frame: &FactFrame, row: &EvidenceRow) -> Result<()> {
        if !tos_health_core::wire::hash(&row.evidence_id)
            || row.store_seq.0 == 0
            || row.store_seq.0 > i64::MAX as u64
            || frame.node_id != row.evidence.record.node_id
            || frame.scope_id != row.evidence.record.scope_id
            || frame.source_id != row.evidence.record.source_id
            || frame.process_epoch != row.evidence.record.process_epoch
            || frame.source_epoch != row.evidence.source_epoch
            || frame.generation.0.to_string() != row.evidence.record.source_record_id
        {
            return Err("evidence reference mismatch".into());
        }
        wal_budget(&self.path, self.quota)?;
        let tx = self.conn.transaction().map_err(err)?;
        tx.execute("INSERT INTO source_state(node,scope,source,process_epoch,source_epoch,generation,content_hash,evidence_id,store_seq,clock_valid,complete)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
            ON CONFLICT(node,scope,source) DO UPDATE SET process_epoch=excluded.process_epoch,
            source_epoch=excluded.source_epoch,generation=excluded.generation,content_hash=excluded.content_hash,
            evidence_id=excluded.evidence_id,store_seq=excluded.store_seq,
            clock_valid=excluded.clock_valid,complete=excluded.complete",
            params![frame.node_id,frame.scope_id,frame.source_id,frame.process_epoch,
                frame.source_epoch,frame.generation.0.to_string(),frame.digest().map_err(err)?,
                row.evidence_id,row.store_seq.0 as i64,frame.clock_valid,frame.complete]).map_err(err)?;
        tx.commit().map_err(err)
    }
    pub fn evaluate(
        &mut self,
        key: &RuleKey,
        signal: Evaluation,
        now: u64,
        required: &[String],
        hold: u64,
    ) -> Result<HealthState> {
        let mut results = self.evaluate_round(
            vec![ControlUpdate { key: key.clone(), signal, required: required.to_vec(), hold }],
            now,
        )?;
        results.pop().map(|(_, state)| state).ok_or_else(|| "empty evaluation".into())
    }
    /// The published sequence advances only when every rule and its outbox changes commit.
    pub fn evaluate_round(
        &mut self,
        updates: Vec<ControlUpdate>,
        now: u64,
    ) -> Result<Vec<(RuleKey, HealthState)>> {
        if updates.is_empty() || updates.len() > 2304 {
            return Err("invalid evaluation size".into());
        }
        let mut keys = std::collections::BTreeSet::new();
        for update in &updates {
            if !update.key.valid()
                || !keys.insert((&update.key.node, &update.key.scope, &update.key.rule))
            {
                return Err("invalid or duplicate rule key".into());
            }
        }
        wal_budget(&self.path, self.quota)?;
        let tx = self.conn.transaction().map_err(err)?;
        let sequence: i64 = tx
            .query_row("SELECT sequence FROM evaluation WHERE singleton=1", [], |r| r.get(0))
            .map_err(err)?;
        let sequence = sequence.checked_add(1).ok_or("evaluation sequence exhausted")?;
        let mut results = Vec::new();
        for update in updates {
            let ControlUpdate { key, signal, required, hold } = update;
            let old: Option<String> = tx
                .query_row(
                    "SELECT body FROM incidents WHERE node=?1 AND scope=?2 AND rule=?3",
                    params![key.node, key.scope, key.rule],
                    |r| r.get(0),
                )
                .optional()
                .map_err(err)?;
            if old.is_none() {
                let n: u32 = tx
                    .query_row("SELECT count(*) FROM incidents", [], |r| r.get(0))
                    .map_err(err)?;
                if n >= self.max_incidents {
                    return Err("incident capacity exceeded".into());
                }
            }
            let mut state = match old {
                Some(b) => serde_json::from_str::<HealthState>(&b).map_err(err)?,
                None => HealthState::default(),
            };
            let before = state.state;
            let severity_before = state.severity.clone();
            match signal {
                Evaluation::Bad { severity } => state.bad(&severity).map_err(err)?,
                Evaluation::Unknown => state.unknown(),
                Evaluation::Good { samples } => {
                    state.good(now, &required, samples, hold, 2).map_err(err)?
                }
            }
            let body = serde_json::to_string(&state).map_err(err)?;
            if state.state != before || state.severity != severity_before {
                let n: u32 =
                    tx.query_row("SELECT count(*) FROM outbox", [], |r| r.get(0)).map_err(err)?;
                if n >= self.max_outbox {
                    return Err("outbox capacity exceeded".into());
                }
                let id = format!(
                    "{}:{}:{}:{}:{}",
                    key.node, key.scope, key.rule, state.episode.0, sequence
                );
                let event = serde_json::to_string(
                    &serde_json::json!({"schema_version":1,"rule_key":key,"health_state":state}),
                )
                .map_err(err)?;
                let hash = format!("{:x}", Sha256::digest(event.as_bytes()));
                tx.execute(
                    "INSERT INTO outbox(key,body,payload_hash) VALUES(?1,?2,?3)",
                    params![id, event, hash],
                )
                .map_err(err)?;
            }
            tx.execute("INSERT INTO incidents VALUES(?1,?2,?3,?4) ON CONFLICT(node,scope,rule) DO UPDATE SET body=excluded.body",params![key.node,key.scope,key.rule,body]).map_err(err)?;
            results.push((key, state));
        }
        tx.execute("UPDATE evaluation SET sequence=?1 WHERE singleton=1", [sequence])
            .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(results)
    }
    pub fn bind_inventory(&mut self, revision: &str, body: &str) -> Result<()> {
        if revision.is_empty() || revision.len() > 128 || body.len() > 262_144 {
            return Err("invalid inventory".into());
        }
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS inventory(revision TEXT PRIMARY KEY,body TEXT NOT NULL)").map_err(err)?;
        let old: Option<String> = self
            .conn
            .query_row("SELECT body FROM inventory WHERE revision=?1", [revision], |r| r.get(0))
            .optional()
            .map_err(err)?;
        if let Some(old) = old {
            if old != body {
                return Err("inventory revision conflict".into());
            }
            return Ok(());
        }
        let count: u32 =
            self.conn.query_row("SELECT count(*) FROM inventory", [], |r| r.get(0)).map_err(err)?;
        if count >= 64 {
            return Err("inventory history limit".into());
        }
        self.conn
            .execute("INSERT OR IGNORE INTO inventory VALUES(?1,?2)", params![revision, body])
            .map_err(err)?;
        Ok(())
    }
    pub fn all_states(&self) -> Result<Vec<(RuleKey, HealthState)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT node,scope,rule,body FROM incidents ORDER BY node,scope,rule LIMIT 10001",
            )
            .map_err(err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(err)?;
        let mut out = Vec::new();
        for row in rows {
            let (node, scope, rule, body) = row.map_err(err)?;
            if out.len() >= self.max_incidents as usize {
                return Err("incident capacity exceeded".into());
            }
            out.push((RuleKey { node, scope, rule }, serde_json::from_str(&body).map_err(err)?));
        }
        Ok(out)
    }
    pub fn sequence(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT sequence FROM evaluation WHERE singleton=1", [], |r| r.get(0))
            .map_err(err)?;
        u64::try_from(n).map_err(err)
    }
    pub fn pending(&self) -> Result<Vec<(i64, String, String)>> {
        let mut q = self
            .conn
            .prepare("SELECT id,key,body FROM outbox WHERE delivered=0 ORDER BY id LIMIT 100")
            .map_err(err)?;
        let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(err)
    }
    pub fn due(&self, now_ms: i64) -> Result<Vec<(i64, String, String)>> {
        let mut q = self.conn.prepare(
            "SELECT id,key,body FROM outbox WHERE delivered=0 AND next_due_ms<=?1 ORDER BY id LIMIT 100",
        ).map_err(err)?;
        let rows = q
            .query_map([now_ms], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?;
        Ok(rows)
    }
    /// Bind the approved receiver before transmission and persist bounded
    /// retry spacing even if the process dies after sending but before receipt.
    pub fn begin_attempt(&mut self, id: i64, alias: &str, now_ms: i64) -> Result<String> {
        if !crate::alias(alias) || now_ms < 0 {
            return Err("invalid receiver attempt".into());
        }
        wal_budget(&self.path, self.quota)?;
        let tx = self.conn.transaction().map_err(err)?;
        let row: Option<(String, String, String, i64, i64)> = tx.query_row(
            "SELECT receiver_alias,payload_hash,body,attempts,next_due_ms FROM outbox WHERE id=?1",
            [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).optional().map_err(err)?;
        let (bound, mut hash, body, attempts, due) = row.ok_or("outbox row missing")?;
        if (!bound.is_empty() && bound != alias) || due > now_ms {
            return Err("receiver alias mismatch or attempt not due".into());
        }
        let actual = format!("{:x}", Sha256::digest(body.as_bytes()));
        if !hash.is_empty() && hash != actual {
            return Err("outbox payload hash mismatch".into());
        }
        hash = actual;
        let next_attempts = attempts.checked_add(1).ok_or("outbox attempt count exhausted")?;
        let retry_ms = match next_attempts {
            1 => 15_000,
            2 => 30_000,
            _ => 60_000,
        };
        let next_due = now_ms.checked_add(retry_ms).ok_or("outbox retry time exhausted")?;
        tx.execute("UPDATE outbox SET receiver_alias=?2,payload_hash=?3,attempts=?4,next_due_ms=?5 WHERE id=?1",
            params![id,alias,hash,next_attempts,next_due]).map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(hash)
    }
    /// Call only after an independently authenticated delivery receipt.
    pub fn delivered(&mut self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM outbox WHERE id=?1", [id]).map_err(err)?;
        Ok(())
    }
}
