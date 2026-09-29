//! Local monitoring-host storage. Control transactions never share the evidence database.
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, time::Duration};
use tos_health_core::{
    evidence::{Evidence, EvidenceStore},
    health_state::{HealthState, Sample},
    wire::U64,
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
pub struct EvidenceDb {
    conn: Connection,
    path: std::path::PathBuf,
    quota: u64,
}
impl EvidenceDb {
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
            PRIMARY KEY(node,scope,process_epoch,source_epoch,source));").map_err(err)?;
        Ok(Self { conn, path: path.into(), quota })
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
pub struct ControlDb {
    conn: Connection,
    path: std::path::PathBuf,
    quota: u64,
    max_incidents: u32,
    max_outbox: u32,
}
impl ControlDb {
    pub fn open(path: &Path, quota: u64, max_incidents: u32, max_outbox: u32) -> Result<Self> {
        if max_incidents == 0 || max_outbox == 0 || max_incidents > 10000 || max_outbox > 10000 {
            return Err("invalid control capacity".into());
        }
        let conn = open(path, quota)?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS incidents(node TEXT,scope TEXT,rule TEXT,body TEXT NOT NULL,PRIMARY KEY(node,scope,rule));
        CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,key TEXT NOT NULL UNIQUE,body TEXT NOT NULL,delivered INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS evaluation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),sequence INTEGER NOT NULL);
        INSERT OR IGNORE INTO evaluation VALUES(1,0);").map_err(err)?;
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
    pub fn evaluate(
        &mut self,
        key: &RuleKey,
        signal: Evaluation,
        now: u64,
        required: &[String],
        hold: u64,
    ) -> Result<HealthState> {
        if !key.valid() {
            return Err("invalid rule key".into());
        }
        wal_budget(&self.path, self.quota)?;
        let tx = self.conn.transaction().map_err(err)?;
        let old: Option<String> = tx
            .query_row(
                "SELECT body FROM incidents WHERE node=?1 AND scope=?2 AND rule=?3",
                params![key.node, key.scope, key.rule],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if old.is_none() {
            let n: u32 =
                tx.query_row("SELECT count(*) FROM incidents", [], |r| r.get(0)).map_err(err)?;
            if n >= self.max_incidents {
                return Err("incident capacity exceeded".into());
            }
        }
        let mut state = match old {
            Some(b) => serde_json::from_str::<HealthState>(&b).map_err(err)?,
            None => HealthState::default(),
        };
        let before = state.state;
        match signal {
            Evaluation::Bad { severity } => state.bad(&severity).map_err(err)?,
            Evaluation::Unknown => state.unknown(),
            Evaluation::Good { samples } => {
                state.good(now, required, samples, hold, 2).map_err(err)?
            }
        }
        let sequence: i64 = tx
            .query_row("SELECT sequence FROM evaluation WHERE singleton=1", [], |r| r.get(0))
            .map_err(err)?;
        let sequence = sequence.checked_add(1).ok_or("evaluation sequence exhausted")?;
        let body = serde_json::to_string(&state).map_err(err)?;
        if state.state != before {
            let n: u32 =
                tx.query_row("SELECT count(*) FROM outbox", [], |r| r.get(0)).map_err(err)?;
            if n >= self.max_outbox {
                return Err("outbox capacity exceeded".into());
            }
            let id =
                format!("{}:{}:{}:{}:{}", key.node, key.scope, key.rule, state.episode.0, sequence);
            tx.execute("INSERT INTO outbox(key,body) VALUES(?1,?2)", params![id, body])
                .map_err(err)?;
        }
        tx.execute("INSERT INTO incidents VALUES(?1,?2,?3,?4) ON CONFLICT(node,scope,rule) DO UPDATE SET body=excluded.body",params![key.node,key.scope,key.rule,body]).map_err(err)?;
        tx.execute("UPDATE evaluation SET sequence=?1 WHERE singleton=1", [sequence])
            .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(state)
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
    /// Call only after an independently authenticated delivery receipt.
    pub fn delivered(&mut self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM outbox WHERE id=?1", [id]).map_err(err)?;
        Ok(())
    }
}
