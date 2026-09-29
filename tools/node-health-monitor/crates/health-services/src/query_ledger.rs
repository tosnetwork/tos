//! Durable, fail-closed query grant accounting. No raw run token is stored.
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use tos_health_core::evidence::{Evidence, EvidenceStore, StoredEvidence};
use tos_health_core::query::Grant;

pub struct QueryLedger {
    conn: Connection,
    clock_domain: String,
}

/// Linux BOOTTIME includes suspend and keeps the same origin across process
/// restarts in one time namespace. Instant::elapsed would renew old grants.
pub fn boot_millis() -> Result<u64, String> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0
        || ts.tv_sec < 0
        || ts.tv_nsec < 0
        || ts.tv_nsec >= 1_000_000_000
    {
        return Err("CLOCK_BOOTTIME unavailable".into());
    }
    let seconds = u64::try_from(ts.tv_sec).map_err(failure)?;
    let nanos = u64::try_from(ts.tv_nsec).map_err(failure)?;
    seconds
        .checked_mul(1000)
        .and_then(|ms| ms.checked_add(nanos / 1_000_000))
        .ok_or_else(|| "CLOCK_BOOTTIME overflow".into())
}

#[derive(Debug, Clone)]
pub struct Attempt<'a> {
    pub tool: &'a str,
    pub result_code: &'a str,
    /// Actual bytes returned to the caller, including any MCP duplicate forms.
    pub returned_bytes: usize,
}

fn failure(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn encoded(grant: &Grant) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(grant).map_err(failure)?;
    if body.len() > 32_768 {
        return Err("grant ledger row too large".into());
    }
    Ok(body)
}

impl QueryLedger {
    pub fn open(path: &Path) -> Result<Self, String> {
        let boot_id =
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(failure)?;
        let namespace = std::fs::read_link("/proc/self/ns/time").map_err(failure)?;
        Self::open_for_context(path, boot_id.trim(), &namespace.to_string_lossy())
    }

    /// The boot identity is explicit here so restart and boot-rotation tests
    /// exercise the same path without changing the host's clock.
    pub fn open_for_boot(path: &Path, boot_id: &str) -> Result<Self, String> {
        Self::open_for_context(path, boot_id, "test-time-namespace")
    }

    pub fn open_for_context(path: &Path, boot_id: &str, namespace: &str) -> Result<Self, String> {
        if boot_id.len() != 36 || !boot_id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
            return Err("invalid boot identity".into());
        }
        if namespace.is_empty() || namespace.len() > 96 {
            return Err("invalid time namespace".into());
        }
        match std::fs::symlink_metadata(path) {
            Ok(meta) if !meta.is_file() || meta.mode() & 0o077 != 0 => {
                return Err("query ledger must be a private regular file".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(failure)?;
            }
            Err(error) => return Err(failure(error)),
        }
        let conn = Connection::open(path).map_err(failure)?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(failure)?;
        conn.pragma_update(None, "synchronous", "FULL").map_err(failure)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(failure)?;
        conn.pragma_update(None, "temp_store", "MEMORY").map_err(failure)?;
        let mode: String =
            conn.pragma_query_value(None, "journal_mode", |row| row.get(0)).map_err(failure)?;
        let synchronous: i64 =
            conn.pragma_query_value(None, "synchronous", |row| row.get(0)).map_err(failure)?;
        if !mode.eq_ignore_ascii_case("wal") || synchronous != 2 {
            return Err("query ledger WAL/FULL unavailable".into());
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS query_grants (
                run_id TEXT PRIMARY KEY,
                boot_id TEXT NOT NULL,
                expires_ms INTEGER NOT NULL,
                revoked INTEGER NOT NULL CHECK (revoked IN (0,1)),
                body BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS query_attempts (
                attempt_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES query_grants(run_id),
                tool TEXT NOT NULL,
                result_code TEXT NOT NULL,
                returned_bytes INTEGER NOT NULL CHECK (returned_bytes >= 0)
            );
            CREATE INDEX IF NOT EXISTS query_grants_live
                ON query_grants(boot_id,revoked,expires_ms);
            CREATE TABLE IF NOT EXISTS query_evidence_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                sequence INTEGER NOT NULL CHECK(sequence >= 0)
            );
            INSERT OR IGNORE INTO query_evidence_meta(singleton,sequence) VALUES(1,0);
            CREATE TABLE IF NOT EXISTS query_evidence (
                store_seq INTEGER PRIMARY KEY CHECK(store_seq > 0),
                evidence_id TEXT NOT NULL UNIQUE,
                body BLOB NOT NULL
            );",
        )
        .map_err(failure)?;
        Ok(Self { conn, clock_domain: format!("{boot_id}|{namespace}") })
    }

    pub fn create(&mut self, grant: &Grant, now_ms: u64) -> Result<(), String> {
        if grant.revoked() || grant.expires_monotonic_ms() <= now_ms {
            return Err("inactive grant".into());
        }
        let body = encoded(grant)?;
        let expires = i64::try_from(grant.expires_monotonic_ms()).map_err(failure)?;
        let now = i64::try_from(now_ms).map_err(failure)?;
        let tx =
            self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(failure)?;
        let active: i64 = tx.query_row(
            "SELECT COUNT(*) FROM query_grants WHERE boot_id=?1 AND revoked=0 AND expires_ms>?2",
            params![self.clock_domain, now], |row| row.get(0),
        ).map_err(failure)?;
        let total: i64 = tx
            .query_row("SELECT COUNT(*) FROM query_grants", [], |row| row.get(0))
            .map_err(failure)?;
        if active >= 32 || total >= 4096 {
            return Err("query grant ledger full".into());
        }
        tx.execute(
            "INSERT INTO query_grants(run_id,boot_id,expires_ms,revoked,body) VALUES(?1,?2,?3,0,?4)",
            params![grant.run_id, self.clock_domain, expires, body],
        ).map_err(failure)?;
        tx.commit().map_err(failure)
    }

    pub fn load_active(&self, run_id: &str, now_ms: u64) -> Result<Option<Grant>, String> {
        let now = i64::try_from(now_ms).map_err(failure)?;
        let body: Option<Vec<u8>> = self.conn.query_row(
            "SELECT body FROM query_grants WHERE run_id=?1 AND boot_id=?2 AND revoked=0 AND expires_ms>?3",
            params![run_id, self.clock_domain, now], |row| row.get(0),
        ).optional().map_err(failure)?;
        body.map(|bytes| serde_json::from_slice(&bytes).map_err(failure)).transpose()
    }

    pub fn load_active_all(&self, now_ms: u64) -> Result<Vec<Grant>, String> {
        let now = i64::try_from(now_ms).map_err(failure)?;
        let mut query = self.conn.prepare(
            "SELECT body FROM query_grants WHERE boot_id=?1 AND revoked=0 AND expires_ms>?2 LIMIT 33"
        ).map_err(failure)?;
        let rows = query
            .query_map(params![self.clock_domain, now], |row| row.get::<_, Vec<u8>>(0))
            .map_err(failure)?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(serde_json::from_slice(&row.map_err(failure)?).map_err(failure)?);
        }
        if grants.len() > 32 {
            return Err("active grant ledger overflow".into());
        }
        Ok(grants)
    }

    pub fn load_evidence(&self, max_bytes: usize) -> Result<EvidenceStore, String> {
        let sequence: i64 = self
            .conn
            .query_row("SELECT sequence FROM query_evidence_meta WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .map_err(failure)?;
        let mut query = self
            .conn
            .prepare("SELECT body FROM query_evidence ORDER BY store_seq")
            .map_err(failure)?;
        let rows = query.query_map([], |row| row.get::<_, Vec<u8>>(0)).map_err(failure)?;
        let mut entries = Vec::new();
        let mut total = 0usize;
        for row in rows {
            let body = row.map_err(failure)?;
            total = total.checked_add(body.len()).ok_or("evidence restore size overflow")?;
            if body.len() > 34_816 || total > max_bytes || entries.len() >= 4096 {
                return Err("evidence restore exceeds resident cap".into());
            }
            entries.push(serde_json::from_slice::<StoredEvidence>(&body).map_err(failure)?);
        }
        EvidenceStore::restore(max_bytes, u64::try_from(sequence).map_err(failure)?, entries)
            .map_err(str::to_owned)
    }

    /// Persist before publishing to memory/HTTP. The candidate is bounded by
    /// EvidenceStore and replaces the live store only after SQLite FULL commit.
    pub fn insert_evidence(
        &mut self,
        store: &mut EvidenceStore,
        record: Evidence,
    ) -> Result<String, String> {
        let mut candidate = store.clone();
        let previous = store.watermark();
        let id = candidate.insert(record).map_err(str::to_owned)?;
        if candidate.watermark() == previous {
            return Ok(id);
        }
        // A grant pins its fixed W for the complete run. If bounded insertion
        // would evict a record at or before any active W, refuse the new
        // source row rather than turn a stable cursor into a later miss.
        let pinned_w = self
            .load_active_all(boot_millis()?)?
            .iter()
            .map(|grant| grant.watermark)
            .max()
            .unwrap_or(0);
        if let Some(oldest) = store.entries().next() {
            if oldest.watermark <= pinned_w
                && candidate.entries().next().is_none_or(|next| next.watermark > oldest.watermark)
            {
                return Err("active grant evidence retention".into());
            }
        }
        let entry = candidate.entries().last().ok_or("missing inserted evidence")?;
        if entry.watermark != candidate.watermark() || entry.evidence_id != id {
            return Err("evidence insertion mismatch".into());
        }
        let body = serde_json::to_vec(entry).map_err(failure)?;
        let first_live =
            candidate.entries().next().map(|item| item.watermark).unwrap_or(candidate.watermark());
        let tx =
            self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(failure)?;
        let disk_sequence: i64 = tx
            .query_row("SELECT sequence FROM query_evidence_meta WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .map_err(failure)?;
        if u64::try_from(disk_sequence).map_err(failure)? > previous {
            return Err("evidence watermark conflict".into());
        }
        tx.execute(
            "INSERT INTO query_evidence(store_seq,evidence_id,body) VALUES(?1,?2,?3)",
            params![i64::try_from(candidate.watermark()).map_err(failure)?, id, body],
        )
        .map_err(failure)?;
        tx.execute(
            "DELETE FROM query_evidence WHERE store_seq<?1",
            [i64::try_from(first_live).map_err(failure)?],
        )
        .map_err(failure)?;
        tx.execute(
            "UPDATE query_evidence_meta SET sequence=?1 WHERE singleton=1",
            [i64::try_from(candidate.watermark()).map_err(failure)?],
        )
        .map_err(failure)?;
        tx.commit().map_err(failure)?;
        *store = candidate;
        Ok(id)
    }

    /// Commit the complete post-call snapshot and one attempt before releasing
    /// a response. Rollback rejects binding swaps and budget counter replay.
    pub fn advance(
        &mut self,
        grant: &Grant,
        now_ms: u64,
        attempt: Attempt<'_>,
    ) -> Result<(), String> {
        if !tos_health_core::query::TOOLS.contains(&attempt.tool)
            || attempt.result_code.len() > 64
            || attempt.returned_bytes > 32_768
            || grant.revoked()
            || now_ms >= grant.expires_monotonic_ms()
        {
            return Err("invalid query attempt".into());
        }
        let body = encoded(grant)?;
        let returned_bytes = i64::try_from(attempt.returned_bytes).map_err(failure)?;
        let tx =
            self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(failure)?;
        let previous: Vec<u8> = tx
            .query_row(
                "SELECT body FROM query_grants WHERE run_id=?1 AND boot_id=?2",
                params![grant.run_id, self.clock_domain],
                |row| row.get(0),
            )
            .map_err(failure)?;
        let previous: Grant = serde_json::from_slice(&previous).map_err(failure)?;
        if !grant.progress_follows(&previous)
            || grant.calls() != previous.calls() + 1
            || grant.returned_bytes().checked_sub(previous.returned_bytes())
                != Some(attempt.returned_bytes)
        {
            return Err("query grant replay or binding change".into());
        }
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM query_attempts", [], |row| row.get(0))
            .map_err(failure)?;
        if count >= 65_536 {
            return Err("query attempt ledger full".into());
        }
        tx.execute(
            "UPDATE query_grants SET body=?2,revoked=?3 WHERE run_id=?1",
            params![grant.run_id, body, grant.revoked()],
        )
        .map_err(failure)?;
        tx.execute("INSERT INTO query_attempts(run_id,tool,result_code,returned_bytes) VALUES(?1,?2,?3,?4)",
            params![grant.run_id, attempt.tool, attempt.result_code, returned_bytes]).map_err(failure)?;
        tx.commit().map_err(failure)
    }

    pub fn revoke(&mut self, run_id: &str) -> Result<bool, String> {
        let tx =
            self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(failure)?;
        let previous: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM query_grants WHERE run_id=?1 AND boot_id=?2",
                params![run_id, self.clock_domain],
                |row| row.get(0),
            )
            .optional()
            .map_err(failure)?;
        let Some(previous) = previous else { return Ok(false) };
        let mut grant: Grant = serde_json::from_slice(&previous).map_err(failure)?;
        grant.revoke();
        tx.execute(
            "UPDATE query_grants SET body=?2,revoked=1 WHERE run_id=?1",
            params![run_id, encoded(&grant)?],
        )
        .map_err(failure)?;
        tx.commit().map_err(failure)?;
        Ok(true)
    }

    pub fn attempt_count(&self, run_id: &str) -> Result<u64, String> {
        self.conn
            .query_row("SELECT COUNT(*) FROM query_attempts WHERE run_id=?1", [run_id], |row| {
                row.get(0)
            })
            .map_err(failure)
    }

    /// Redacted operator ledger view; never serialize Grant itself to an API.
    pub fn inspect(&self, run_id: &str) -> Result<Option<serde_json::Value>, String> {
        let row: Option<(String, i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT boot_id,revoked,body FROM query_grants WHERE run_id=?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(failure)?;
        let Some((clock_domain, revoked, body)) = row else { return Ok(None) };
        let grant: Grant = serde_json::from_slice(&body).map_err(failure)?;
        Ok(Some(serde_json::json!({
            "run_id":grant.run_id,
            "principal":grant.principal,
            "network_id":grant.network_id,
            "node_ids":grant.nodes,
            "scope_ids":grant.scopes,
            "watermark":grant.watermark.to_string(),
            "calls":grant.calls(),
            "returned_bytes":grant.returned_bytes(),
            "attempts":self.attempt_count(run_id)?,
            "revoked":revoked != 0 || grant.revoked(),
            "clock_domain_current":clock_domain == self.clock_domain,
        })))
    }
}
