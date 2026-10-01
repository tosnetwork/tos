//! Durable, fail-closed query grant accounting. No raw run token is stored.
use crate::durable::EvidenceRow;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
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

/// Hard SQLite page quota for the ledger file (256 MiB).
pub const LEDGER_QUOTA_BYTES: u64 = 256 * 1024 * 1024;
/// WAL frames between passive checkpoints; keeps the WAL file small.
pub const WAL_AUTOCHECKPOINT_PAGES: i64 = 64;
/// Resident grants (non-empty body) the ledger may hold at once.
const MAX_RESIDENT_GRANTS: i64 = 4096;
/// Compacted run-id seals younger than this stay as anti-replay history.
pub const TERMINAL_SEAL_HISTORY_MS: i64 = 30 * 86_400_000;
/// Expired seals removed per compaction call; bounds one transaction.
const TERMINAL_SEAL_SWEEP_LIMIT: i64 = 256;

/// Last fully imported M snapshot. The anchor detects replacement or rewrite
/// of the append-only source across QueryService restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerCursor {
    pub network: String,
    pub device: u64,
    pub inode: u64,
    pub watermark: u64,
    pub anchor: Option<(u64, String)>,
}
type CursorSqlRow = (String, String, String, i64, Option<i64>, Option<String>);

fn validate_manager_cursor(cursor: &ManagerCursor) -> Result<(), String> {
    if !tos_health_core::wire::hash(&cursor.network)
        || (cursor.watermark == 0) != cursor.anchor.is_none()
        || cursor.anchor.as_ref().is_some_and(|(seq, hash)| {
            *seq != cursor.watermark || !tos_health_core::wire::hash(hash)
        })
    {
        return Err("invalid persisted M projection cursor".into());
    }
    // A nonzero global boundary anchors the exact last M observation, which
    // may be non-process. An older valid process hash cannot justify a later W.
    Ok(())
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

/// Only SQLite's typed BUSY/LOCKED/FULL write failures may pause an
/// import without treating its already-verified fixed-W parents as changed.
/// Trigger/constraint errors and all non-SQLite failures remain untagged.
#[derive(Debug)]
pub enum ProjectionWriteError {
    RecoverableSqlite(String),
    Capacity(&'static str),
    Refused(String),
}

impl ProjectionWriteError {
    pub fn is_proven_recoverable(&self) -> bool {
        matches!(self, Self::RecoverableSqlite(_) | Self::Capacity(_))
    }
}

impl std::fmt::Display for ProjectionWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::RecoverableSqlite(message) | Self::Refused(message) => message.as_str(),
            Self::Capacity(message) => message,
        };
        formatter.write_str(message)
    }
}

impl From<String> for ProjectionWriteError {
    fn from(message: String) -> Self {
        Self::Refused(message)
    }
}

impl From<&str> for ProjectionWriteError {
    fn from(message: &str) -> Self {
        Self::Refused(message.to_owned())
    }
}

fn projection_sql_failure(error: rusqlite::Error) -> ProjectionWriteError {
    if let rusqlite::Error::SqliteFailure(details, _) = &error {
        if matches!(
            details.code,
            rusqlite::ErrorCode::DatabaseBusy
                | rusqlite::ErrorCode::DatabaseLocked
                | rusqlite::ErrorCode::DiskFull
        ) {
            return ProjectionWriteError::RecoverableSqlite(error.to_string());
        }
    }
    ProjectionWriteError::Refused(error.to_string())
}

fn encoded(grant: &Grant) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(grant).map_err(failure)?;
    if body.len() > 32_768 {
        return Err("grant ledger row too large".into());
    }
    Ok(body)
}

fn validate_package_binding(body: &[u8], grant: &Grant) -> Result<(), String> {
    crate::fixed_package::validate_package_binding(body, grant)
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
        // The ledger is bounded the same way as the evidence database: a hard
        // page quota and a small WAL so an unchecked writer cannot fill the disk.
        let page: u64 =
            conn.pragma_query_value(None, "page_size", |row| row.get(0)).map_err(failure)?;
        if page == 0 {
            return Err("query ledger page size unavailable".into());
        }
        let pages = LEDGER_QUOTA_BYTES / page;
        let effective: u64 = conn
            .pragma_update_and_check(None, "max_page_count", pages, |row| row.get(0))
            .map_err(failure)?;
        if effective > pages {
            return Err("query ledger exceeds configured quota".into());
        }
        conn.pragma_update(None, "wal_autocheckpoint", WAL_AUTOCHECKPOINT_PAGES)
            .map_err(failure)?;
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
            CREATE INDEX IF NOT EXISTS query_attempts_run ON query_attempts(run_id);
            CREATE TABLE IF NOT EXISTS query_mcp_bindings (
                run_id TEXT PRIMARY KEY REFERENCES query_grants(run_id),
                boot_id TEXT NOT NULL,
                bound_at_ms INTEGER NOT NULL CHECK (bound_at_ms >= 0),
                call_count INTEGER NOT NULL DEFAULT 0 CHECK (call_count BETWEEN 0 AND 16),
                wire_bytes INTEGER NOT NULL DEFAULT 0 CHECK (wire_bytes BETWEEN 0 AND 131072)
            );
            CREATE TABLE IF NOT EXISTS query_packages (
                run_id TEXT PRIMARY KEY REFERENCES query_grants(run_id),
                boot_id TEXT NOT NULL,
                package_sha256 TEXT NOT NULL,
                body BLOB NOT NULL CHECK(length(body)<=16384),
                fixed_at_ms INTEGER NOT NULL CHECK(fixed_at_ms>=0)
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
            );
            CREATE TABLE IF NOT EXISTS query_origins (
                origin_id TEXT PRIMARY KEY,
                manager_seq INTEGER NOT NULL CHECK(manager_seq > 0),
                body BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS query_projection_origin (
                query_evidence_id TEXT PRIMARY KEY,
                origin_id TEXT NOT NULL REFERENCES query_origins(origin_id)
            );
            CREATE TABLE IF NOT EXISTS query_manager_cursor (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                network TEXT NOT NULL,
                device TEXT NOT NULL,
                inode TEXT NOT NULL,
                watermark INTEGER NOT NULL CHECK(watermark >= 0),
                anchor_seq INTEGER,
                anchor_hash TEXT,
                CHECK((anchor_seq IS NULL) = (anchor_hash IS NULL))
            );",
        )
        .map_err(failure)?;
        // The earlier opt-in MCP checkpoint created bindings without these
        // counters. Never reset an already-bound grant's spent budget during
        // migration; require a fresh ledger/explicit grant instead.
        let mut columns = conn.prepare("PRAGMA table_info(query_mcp_bindings)").map_err(failure)?;
        let names: Vec<String> = columns
            .query_map([], |row| row.get(1))
            .map_err(failure)?
            .collect::<Result<_, _>>()
            .map_err(failure)?;
        drop(columns);
        if !names.iter().any(|name| name == "call_count")
            || !names.iter().any(|name| name == "wire_bytes")
        {
            let bound: i64 = conn
                .query_row("SELECT COUNT(*) FROM query_mcp_bindings", [], |row| row.get(0))
                .map_err(failure)?;
            if bound != 0 {
                return Err("legacy MCP bindings have unknown spent budget".into());
            }
            if !names.iter().any(|name| name == "call_count") {
                conn.execute_batch("ALTER TABLE query_mcp_bindings ADD COLUMN call_count INTEGER NOT NULL DEFAULT 0 CHECK(call_count BETWEEN 0 AND 16)")
                    .map_err(failure)?;
            }
            if !names.iter().any(|name| name == "wire_bytes") {
                conn.execute_batch("ALTER TABLE query_mcp_bindings ADD COLUMN wire_bytes INTEGER NOT NULL DEFAULT 0 CHECK(wire_bytes BETWEEN 0 AND 131072)")
                    .map_err(failure)?;
            }
        }
        Ok(Self { conn, clock_domain: format!("{boot_id}|{namespace}") })
    }

    pub fn manager_cursor(&self) -> Result<Option<ManagerCursor>, String> {
        self.conn.query_row(
            "SELECT network,device,inode,watermark,anchor_seq,anchor_hash FROM query_manager_cursor WHERE singleton=1",
            [],
            |row| {
                let network: String = row.get(0)?;
                let device: String = row.get(1)?;
                let inode: String = row.get(2)?;
                let watermark: i64 = row.get(3)?;
                let anchor_seq: Option<i64> = row.get(4)?;
                let anchor_hash: Option<String> = row.get(5)?;
                Ok((network,device,inode,watermark,anchor_seq,anchor_hash))
            },
        ).optional().map_err(failure)?.map(|(network,device,inode,watermark,anchor_seq,anchor_hash)| {
            let anchor = match (anchor_seq, anchor_hash) {
                (Some(seq), Some(hash)) => Some((u64::try_from(seq).map_err(failure)?,hash)),
                (None, None) => None,
                _ => return Err("M cursor anchor incomplete".into()),
            };
            let cursor = ManagerCursor {
                network,
                device: device.parse().map_err(failure)?,
                inode: inode.parse().map_err(failure)?,
                watermark: u64::try_from(watermark).map_err(failure)?,
                anchor,
            };
            validate_manager_cursor(&cursor)?;
            Ok(cursor)
        }).transpose()
    }

    /// Projection rows are individually durable and idempotent. Advance this
    /// cursor only after every row in the page has committed; replay after a
    /// crash may repeat a page but must never skip an uncommitted M parent.
    pub fn commit_manager_cursor(
        &mut self,
        previous: Option<&ManagerCursor>,
        next: &ManagerCursor,
        boundary_witness: Option<&(u64, String)>,
    ) -> Result<(), ProjectionWriteError> {
        validate_manager_cursor(next)?;
        if previous.is_some_and(|old| {
            old.network != next.network
                || old.device != next.device
                || old.inode != next.inode
                || old.watermark > next.watermark
                || old.anchor.as_ref().is_some_and(|(seq, hash)| {
                    next.anchor.as_ref().is_none_or(|(new_seq, new_hash)| {
                        new_seq < seq || (new_seq == seq && new_hash != hash)
                    })
                })
        }) {
            return Err("invalid M projection cursor advancement".into());
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(projection_sql_failure)?;
        let actual: Option<CursorSqlRow> = tx.query_row(
            "SELECT network,device,inode,watermark,anchor_seq,anchor_hash FROM query_manager_cursor WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        ).optional().map_err(projection_sql_failure)?;
        let expected = previous
            .map(|old| -> Result<_, String> {
                Ok((
                    old.network.clone(),
                    old.device.to_string(),
                    old.inode.to_string(),
                    i64::try_from(old.watermark).map_err(failure)?,
                    old.anchor
                        .as_ref()
                        .map(|(seq, _)| i64::try_from(*seq).map_err(failure))
                        .transpose()?,
                    old.anchor.as_ref().map(|(_, hash)| hash.clone()),
                ))
            })
            .transpose()?;
        if actual != expected {
            return Err("M projection cursor changed concurrently".into());
        }
        if let Some((seq, hash)) = next
            .anchor
            .as_ref()
            .filter(|anchor| previous.and_then(|old| old.anchor.as_ref()) != Some(*anchor))
        {
            // A changed anchor needs either a projected process origin
            // retained in Q or the exact global M boundary witnessed by the
            // page reader in the same source snapshot. The latter may be a
            // diagnostic row; it is never promoted to a process origin.
            let witnessed: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM query_origins WHERE origin_id=?1 AND manager_seq=?2)",
                    params![hash, i64::try_from(*seq).map_err(failure)?],
                    |row| row.get(0),
                )
                .map_err(projection_sql_failure)?;
            let witnessed_boundary = boundary_witness.is_some_and(|boundary| {
                boundary == &(next.watermark, hash.clone()) && *seq == next.watermark
            });
            if !witnessed && !witnessed_boundary {
                return Err("M cursor anchor has no retained source row".into());
            }
        }
        tx.execute(
            "INSERT INTO query_manager_cursor(singleton,network,device,inode,watermark,anchor_seq,anchor_hash)
             VALUES(1,?1,?2,?3,?4,?5,?6)
             ON CONFLICT(singleton) DO UPDATE SET network=excluded.network,device=excluded.device,
             inode=excluded.inode,watermark=excluded.watermark,anchor_seq=excluded.anchor_seq,
             anchor_hash=excluded.anchor_hash",
            params![next.network,next.device.to_string(),next.inode.to_string(),
                i64::try_from(next.watermark).map_err(failure)?,
                next.anchor.as_ref().map(|(seq,_)| i64::try_from(*seq).map_err(failure)).transpose()?,
                next.anchor.as_ref().map(|(_,hash)| hash)],
        ).map_err(projection_sql_failure)?;
        tx.commit().map_err(projection_sql_failure)
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
        // Only resident grants count toward the lifetime bound. Compacted
        // seals keep their run id for replay protection but hold no payload,
        // so they must not refuse new grants forever.
        let resident: i64 = tx
            .query_row("SELECT COUNT(*) FROM query_grants WHERE length(body)>0", [], |row| {
                row.get(0)
            })
            .map_err(failure)?;
        if active >= 32 || resident >= MAX_RESIDENT_GRANTS {
            return Err("query grant ledger full".into());
        }
        tx.execute(
            "INSERT INTO query_grants(run_id,boot_id,expires_ms,revoked,body) VALUES(?1,?2,?3,0,?4)",
            params![grant.run_id, self.clock_domain, expires, body],
        ).map_err(failure)?;
        tx.commit().map_err(failure)
    }

    /// One MCP transport binding per grant, durably single-use even after a
    /// service restart. A broken connection fails closed; the broker must
    /// revoke and issue a fresh grant before opening another MCP session.
    pub fn claim_mcp(&mut self, run_id: &str, now_ms: u64) -> Result<(), String> {
        let now = i64::try_from(now_ms).map_err(failure)?;
        let tx =
            self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(failure)?;
        let active: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM query_grants WHERE run_id=?1 AND boot_id=?2 AND revoked=0 AND expires_ms>?3",
                params![run_id, self.clock_domain, now],
                |row| row.get(0),
            )
            .optional()
            .map_err(failure)?;
        if active.is_none() {
            return Err("MCP grant inactive".into());
        }
        tx.execute(
            "INSERT INTO query_mcp_bindings(run_id,boot_id,bound_at_ms,call_count,wire_bytes) VALUES(?1,?2,?3,0,0)",
            params![run_id, self.clock_domain, now],
        )
        .map_err(|_| "MCP grant already bound".to_owned())?;
        tx.commit().map_err(failure)
    }

    /// The MCP handler reserves an attempt before invoking the shared HTTP
    /// query handler. This counts tool-level failures and survives a crash;
    /// the separate QueryService ledger can only be more restrictive.
    pub fn reserve_mcp_call(&mut self, run_id: &str, now_ms: u64) -> Result<(), String> {
        let now = i64::try_from(now_ms).map_err(failure)?;
        let tx =
            self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(failure)?;
        let changed = tx
            .execute(
                "UPDATE query_mcp_bindings SET call_count=call_count+1
             WHERE run_id=?1 AND boot_id=?2 AND call_count<16
               AND bound_at_ms<=?3 AND ?3-bound_at_ms<180000
             AND EXISTS(SELECT 1 FROM query_grants g WHERE g.run_id=query_mcp_bindings.run_id
               AND g.boot_id=?2 AND g.revoked=0 AND g.expires_ms>?3)",
                params![run_id, self.clock_domain, now],
            )
            .map_err(failure)?;
        if changed != 1 {
            return Err("MCP call budget or grant unavailable".into());
        }
        tx.commit().map_err(failure)
    }

    /// Count exact MCP HTTP response bytes, including JSON-RPC wrapper and
    /// any duplicated representation, before releasing them to the client.
    /// A rejected response is not delivered even if its underlying query
    /// attempt has already committed; that is conservative rather than replay.
    pub fn charge_mcp_wire(
        &mut self,
        run_id: &str,
        bytes: usize,
        now_ms: u64,
    ) -> Result<(), String> {
        let bytes = i64::try_from(bytes).map_err(failure)?;
        let now = i64::try_from(now_ms).map_err(failure)?;
        if bytes > 131_072 {
            return Err("MCP wire response exceeds run budget".into());
        }
        let tx =
            self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(failure)?;
        let changed = tx
            .execute(
                "UPDATE query_mcp_bindings SET wire_bytes=wire_bytes+?2
             WHERE run_id=?1 AND boot_id=?3 AND wire_bytes<=131072-?2
               AND bound_at_ms<=?4 AND ?4-bound_at_ms<180000
               AND EXISTS(SELECT 1 FROM query_grants g WHERE g.run_id=query_mcp_bindings.run_id
                 AND g.boot_id=?3 AND g.revoked=0 AND g.expires_ms>?4)",
                params![run_id, bytes, self.clock_domain, now],
            )
            .map_err(failure)?;
        if changed != 1 {
            return Err("MCP wire budget unavailable".into());
        }
        tx.commit().map_err(failure)
    }

    pub fn mcp_usage(&self, run_id: &str) -> Result<Option<(u32, u64)>, String> {
        self.conn.query_row(
            "SELECT call_count,wire_bytes FROM query_mcp_bindings WHERE run_id=?1 AND boot_id=?2",
            params![run_id, self.clock_domain],
            |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u64>(1)?)),
        ).optional().map_err(failure)
    }

    /// Store a prevalidated, fixed-W broker package once. A later regeneration
    /// must produce exact same bytes; neither a model nor an MCP client can
    /// call this internal ledger method through a query route.
    pub fn save_package(
        &mut self,
        run_id: &str,
        body: &[u8],
        now_ms: u64,
    ) -> Result<String, String> {
        if body.is_empty() || body.len() > 16_384 {
            return Err("broker package exceeds 16 KiB".into());
        }
        let now = i64::try_from(now_ms).map_err(failure)?;
        let digest = format!("{:x}", Sha256::digest(body));
        let tx =
            self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(failure)?;
        let active: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM query_grants WHERE run_id=?1 AND boot_id=?2 AND revoked=0 AND expires_ms>?3",
                params![run_id, self.clock_domain, now],
                |row| row.get(0),
            )
            .optional()
            .map_err(failure)?;
        let grant: Grant = serde_json::from_slice(&active.ok_or("broker package grant inactive")?)
            .map_err(failure)?;
        validate_package_binding(body, &grant)?;
        let existing: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT package_sha256,body FROM query_packages WHERE run_id=?1 AND boot_id=?2",
                params![run_id, self.clock_domain],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(failure)?;
        if let Some((old_digest, old_body)) = existing {
            if old_digest != digest || old_body != body {
                return Err("broker package immutable conflict".into());
            }
            tx.commit().map_err(failure)?;
            return Ok(digest);
        }
        let used: i64 = tx
            .query_row("SELECT COALESCE(SUM(length(body)),0) FROM query_packages", [], |row| {
                row.get(0)
            })
            .map_err(failure)?;
        if used
            .checked_add(i64::try_from(body.len()).map_err(failure)?)
            .is_none_or(|total| total > 8 * 1024 * 1024)
        {
            return Err("broker package ledger full".into());
        }
        tx.execute(
            "INSERT INTO query_packages(run_id,boot_id,package_sha256,body,fixed_at_ms) VALUES(?1,?2,?3,?4,?5)",
            params![run_id, self.clock_domain, digest, body, now],
        )
        .map_err(failure)?;
        tx.commit().map_err(failure)?;
        Ok(digest)
    }

    pub fn load_active_package(
        &self,
        run_id: &str,
        now_ms: u64,
    ) -> Result<Option<(String, Vec<u8>)>, String> {
        let now = i64::try_from(now_ms).map_err(failure)?;
        let stored: Option<(String, Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT p.package_sha256,p.body,g.body FROM query_packages p
                 JOIN query_grants g ON g.run_id=p.run_id
                 WHERE p.run_id=?1 AND p.boot_id=?2 AND g.boot_id=?2
                   AND g.revoked=0 AND g.expires_ms>?3",
                params![run_id, self.clock_domain, now],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(failure)?;
        if let Some((digest, bytes, grant_bytes)) = stored {
            if bytes.is_empty()
                || bytes.len() > 16_384
                || digest != format!("{:x}", Sha256::digest(&bytes))
            {
                return Err("broker package integrity mismatch".into());
            }
            let grant: Grant = serde_json::from_slice(&grant_bytes).map_err(failure)?;
            validate_package_binding(&bytes, &grant)?;
            return Ok(Some((digest, bytes)));
        }
        Ok(None)
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
        for entry in &entries {
            if entry.record.payload.get("evidence_kind").and_then(serde_json::Value::as_str)
                == Some("derived")
            {
                let binding: Option<(String, i64, Vec<u8>)> = self.conn.query_row(
                    "SELECT o.origin_id,o.manager_seq,o.body FROM query_origins o JOIN query_projection_origin p ON p.origin_id=o.origin_id WHERE p.query_evidence_id=?1",
                    [&entry.evidence_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
                ).optional().map_err(failure)?;
                let (origin_id, manager_seq, body) =
                    binding.ok_or("derived query evidence has no retained M parent")?;
                let origin: EvidenceRow = serde_json::from_slice(&body).map_err(failure)?;
                if origin.evidence_id != origin_id
                    || i64::try_from(origin.store_seq.0).map_err(failure)? != manager_seq
                {
                    return Err("retained M parent index mismatch".into());
                }
                let reproduced = crate::manager_query_source::project_process(&origin)?
                    .ok_or("derived M parent is not process")?;
                if serde_json::to_vec(&reproduced).map_err(failure)?
                    != serde_json::to_vec(&entry.record).map_err(failure)?
                {
                    return Err("derived query evidence does not match M parent".into());
                }
            }
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
        if record.payload.get("evidence_kind").and_then(serde_json::Value::as_str)
            == Some("derived")
        {
            return Err("derived evidence requires retained parent".into());
        }
        self.insert_bound(store, record, None)
    }

    pub fn insert_projection(
        &mut self,
        store: &mut EvidenceStore,
        origin: &EvidenceRow,
        record: Evidence,
    ) -> Result<String, String> {
        let reproduced = crate::manager_query_source::project_process(origin)?
            .ok_or("M origin has no supported projection")?;
        if serde_json::to_vec(&record).map_err(failure)?
            != serde_json::to_vec(&reproduced).map_err(failure)?
        {
            return Err("projection differs from original M evidence".into());
        }
        self.insert_bound(store, record, Some(origin))
    }

    /// Commit one bounded M page with one in-memory copy and one FULL SQLite
    /// transaction. The cursor is committed separately, after this returns;
    /// a crash between the two replays the exact, idempotent parent bindings.
    pub fn insert_projection_page(
        &mut self,
        store: &mut EvidenceStore,
        page: &[(EvidenceRow, Evidence)],
    ) -> Result<(), ProjectionWriteError> {
        if page.len() > 256 {
            return Err("M projection page too large".into());
        }
        if page.is_empty() {
            return Ok(());
        }
        let previous = store.watermark();
        let mut candidate = store.clone();
        let pinned_w = self
            .load_active_all(boot_millis()?)?
            .iter()
            .map(|grant| grant.watermark)
            .max()
            .unwrap_or(0);
        let mut staged: Vec<(EvidenceRow, StoredEvidence)> = Vec::with_capacity(page.len());
        for (origin, record) in page {
            let reproduced = crate::manager_query_source::project_process(origin)
                .map_err(|error| format!("M projection integrity: {error}"))?
                .ok_or("M origin has no supported projection")?;
            if serde_json::to_vec(record).map_err(failure)?
                != serde_json::to_vec(&reproduced).map_err(failure)?
            {
                return Err("projection differs from original M evidence".into());
            }
            let before = candidate.watermark();
            let oldest = candidate.entries().next().map(|entry| entry.watermark);
            let id = candidate.insert(record.clone()).map_err(str::to_owned)?;
            if candidate.watermark() == before {
                let retained = if let Some((prior, _)) =
                    staged.iter().rev().find(|(_, entry)| entry.evidence_id == id)
                {
                    Some(serde_json::to_vec(prior).map_err(failure)?)
                } else {
                    self.conn
                        .query_row(
                            "SELECT o.body FROM query_origins o JOIN query_projection_origin p ON p.origin_id=o.origin_id WHERE p.query_evidence_id=?1",
                            [&id],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(projection_sql_failure)?
                };
                if retained.as_deref()
                    != Some(serde_json::to_vec(origin).map_err(failure)?.as_slice())
                {
                    return Err("duplicate projection parent missing or changed".into());
                }
                continue;
            }
            if oldest.is_some_and(|watermark| {
                watermark <= pinned_w
                    && candidate.entries().next().is_none_or(|next| next.watermark > watermark)
            }) {
                return Err(ProjectionWriteError::Capacity("active grant evidence retention"));
            }
            let entry = candidate.entries().last().ok_or("missing inserted evidence")?;
            if entry.watermark != candidate.watermark() || entry.evidence_id != id {
                return Err("evidence insertion mismatch".into());
            }
            staged.push((origin.clone(), entry.clone()));
        }
        let first_live = candidate
            .entries()
            .next()
            .map(|entry| entry.watermark)
            .unwrap_or(candidate.watermark());
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(projection_sql_failure)?;
        let disk_sequence: i64 = tx
            .query_row("SELECT sequence FROM query_evidence_meta WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .map_err(projection_sql_failure)?;
        if u64::try_from(disk_sequence).map_err(failure)? > previous {
            return Err("evidence watermark conflict".into());
        }
        tx.execute(
            "DELETE FROM query_evidence WHERE store_seq<?1",
            [i64::try_from(first_live).map_err(failure)?],
        )
        .map_err(projection_sql_failure)?;
        tx.execute("DELETE FROM query_projection_origin WHERE query_evidence_id NOT IN (SELECT evidence_id FROM query_evidence)", [])
            .map_err(projection_sql_failure)?;
        tx.execute("DELETE FROM query_origins WHERE origin_id NOT IN (SELECT origin_id FROM query_projection_origin)", [])
            .map_err(projection_sql_failure)?;
        // Drop evicted rows before adding this page. The transaction still
        // rolls back as one unit, while the temporary Q index never needs a
        // second page's worth of retained bodies.
        for (_, entry) in &staged {
            if entry.watermark >= first_live {
                tx.execute(
                    "INSERT INTO query_evidence(store_seq,evidence_id,body) VALUES(?1,?2,?3)",
                    params![
                        i64::try_from(entry.watermark).map_err(failure)?,
                        entry.evidence_id,
                        serde_json::to_vec(entry).map_err(failure)?
                    ],
                )
                .map_err(projection_sql_failure)?;
            }
        }
        let (mut count, mut bytes): (i64, i64) = tx
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(length(body)),0) FROM query_origins",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(projection_sql_failure)?;
        for (origin, entry) in &staged {
            if entry.watermark < first_live {
                continue;
            }
            let parent = serde_json::to_vec(origin).map_err(failure)?;
            if parent.len() > 34_816 {
                return Err("M parent too large".into());
            }
            let existing: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT manager_seq,body FROM query_origins WHERE origin_id=?1",
                    [&origin.evidence_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(projection_sql_failure)?;
            if let Some((seq, body)) = existing {
                if u64::try_from(seq).map_err(failure)? != origin.store_seq.0 || body != parent {
                    return Err("M parent identity conflict".into());
                }
            } else {
                let size = i64::try_from(parent.len()).map_err(failure)?;
                if count >= 4096 || bytes.checked_add(size).is_none_or(|sum| sum > 8 * 1024 * 1024)
                {
                    return Err(ProjectionWriteError::Capacity("M parent retention full"));
                }
                tx.execute(
                    "INSERT INTO query_origins(origin_id,manager_seq,body) VALUES(?1,?2,?3)",
                    params![
                        origin.evidence_id,
                        i64::try_from(origin.store_seq.0).map_err(failure)?,
                        parent
                    ],
                )
                .map_err(projection_sql_failure)?;
                count += 1;
                bytes += size;
            }
            tx.execute(
                "INSERT INTO query_projection_origin(query_evidence_id,origin_id) VALUES(?1,?2)",
                params![entry.evidence_id, origin.evidence_id],
            )
            .map_err(projection_sql_failure)?;
        }
        tx.execute(
            "UPDATE query_evidence_meta SET sequence=?1 WHERE singleton=1",
            [i64::try_from(candidate.watermark()).map_err(failure)?],
        )
        .map_err(projection_sql_failure)?;
        tx.commit().map_err(projection_sql_failure)?;
        *store = candidate;
        Ok(())
    }

    /// Only original rows still backing a resident derived query row matter.
    /// Their full immutable bodies permit exact M revalidation even when no
    /// new observation follows a quarantine or source-file replacement.
    pub fn retained_origin_rows(&self) -> Result<Vec<EvidenceRow>, String> {
        let (count, total): (i64, i64) = self
            .conn
            .query_row(
                "SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM query_origins",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(failure)?;
        if count > 4096 || total > 8 * 1024 * 1024 {
            return Err("retained M parent index overflow".into());
        }
        let mut query =
            self.conn.prepare("SELECT body FROM query_origins LIMIT 4097").map_err(failure)?;
        let rows = query.query_map([], |row| row.get::<_, Vec<u8>>(0)).map_err(failure)?;
        let mut origins = Vec::new();
        let mut bytes = 0usize;
        for row in rows {
            let body = row.map_err(failure)?;
            bytes = bytes.checked_add(body.len()).ok_or("retained M parent size overflow")?;
            if origins.len() >= 4096 || bytes > 8 * 1024 * 1024 {
                return Err("retained M parent index overflow".into());
            }
            origins.push(serde_json::from_slice::<EvidenceRow>(&body).map_err(failure)?);
        }
        Ok(origins)
    }

    /// Drop the derived query rows whose M parent was expired by M's sealed
    /// age retention, together with their parent bindings and the parents
    /// themselves, in one transaction. Returns the evicted query evidence ids
    /// so the caller can remove the same rows from the resident store. The
    /// evidence sequence is never rewound; an evicted watermark is a gap.
    pub fn evict_expired_origins(&mut self, origins: &[String]) -> Result<Vec<String>, String> {
        if origins.len() > 4096 {
            return Err("expired M parent set exceeds retained bound".into());
        }
        if origins.is_empty() {
            return Ok(Vec::new());
        }
        if origins.iter().any(|origin| !tos_health_core::wire::hash(origin)) {
            return Err("expired M parent id malformed".into());
        }
        let tx =
            self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(failure)?;
        let mut evicted = Vec::new();
        for origin in origins {
            let dependants: Vec<String> = {
                let mut query = tx
                    .prepare(
                        "SELECT query_evidence_id FROM query_projection_origin
                         WHERE origin_id=?1 ORDER BY query_evidence_id LIMIT 4097",
                    )
                    .map_err(failure)?;
                let rows = query
                    .query_map([origin], |row| row.get::<_, String>(0))
                    .map_err(failure)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(failure)?;
                rows
            };
            if dependants.len() > 4096 {
                return Err("expired M parent has too many dependants".into());
            }
            for evidence_id in &dependants {
                tx.execute("DELETE FROM query_evidence WHERE evidence_id=?1", [evidence_id])
                    .map_err(failure)?;
            }
            tx.execute("DELETE FROM query_projection_origin WHERE origin_id=?1", [origin])
                .map_err(failure)?;
            let still_bound: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM query_projection_origin WHERE origin_id=?1)",
                    [origin],
                    |row| row.get(0),
                )
                .map_err(failure)?;
            if still_bound {
                return Err("expired M parent still bound after eviction".into());
            }
            tx.execute("DELETE FROM query_origins WHERE origin_id=?1", [origin])
                .map_err(failure)?;
            evicted.extend(dependants);
        }
        tx.commit().map_err(failure)?;
        Ok(evicted)
    }

    fn insert_bound(
        &mut self,
        store: &mut EvidenceStore,
        record: Evidence,
        origin: Option<&EvidenceRow>,
    ) -> Result<String, String> {
        let mut candidate = store.clone();
        let previous = store.watermark();
        let id = candidate.insert(record).map_err(str::to_owned)?;
        if candidate.watermark() == previous {
            if let Some(origin) = origin {
                let retained: Option<Vec<u8>> = self.conn.query_row(
                    "SELECT o.body FROM query_origins o JOIN query_projection_origin p ON p.origin_id=o.origin_id WHERE p.query_evidence_id=?1",
                    [&id], |row| row.get(0),
                ).optional().map_err(failure)?;
                if retained.as_deref()
                    != Some(serde_json::to_vec(origin).map_err(failure)?.as_slice())
                {
                    return Err("duplicate projection parent missing or changed".into());
                }
            }
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
        tx.execute("DELETE FROM query_projection_origin WHERE query_evidence_id NOT IN (SELECT evidence_id FROM query_evidence)", [])
            .map_err(failure)?;
        tx.execute("DELETE FROM query_origins WHERE origin_id NOT IN (SELECT origin_id FROM query_projection_origin)", [])
            .map_err(failure)?;
        if let Some(origin) = origin {
            let parent = serde_json::to_vec(origin).map_err(failure)?;
            if parent.len() > 34_816 {
                return Err("M parent too large".into());
            }
            let existing: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT manager_seq,body FROM query_origins WHERE origin_id=?1",
                    [&origin.evidence_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(failure)?;
            if let Some((seq, body)) = existing {
                if u64::try_from(seq).map_err(failure)? != origin.store_seq.0 || body != parent {
                    return Err("M parent identity conflict".into());
                }
            } else {
                let (count, bytes): (i64, i64) = tx
                    .query_row(
                        "SELECT COUNT(*), COALESCE(SUM(length(body)),0) FROM query_origins",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(failure)?;
                if count >= 4096
                    || bytes
                        .checked_add(i64::try_from(parent.len()).map_err(failure)?)
                        .is_none_or(|sum| sum > 8 * 1024 * 1024)
                {
                    return Err("M parent retention full".into());
                }
                tx.execute(
                    "INSERT INTO query_origins(origin_id,manager_seq,body) VALUES(?1,?2,?3)",
                    params![
                        origin.evidence_id,
                        i64::try_from(origin.store_seq.0).map_err(failure)?,
                        parent
                    ],
                )
                .map_err(failure)?;
            }
            tx.execute(
                "INSERT INTO query_projection_origin(query_evidence_id,origin_id) VALUES(?1,?2)",
                params![id, origin.evidence_id],
            )
            .map_err(failure)?;
        }
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
        let previous: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT revoked,body FROM query_grants WHERE run_id=?1 AND boot_id=?2",
                params![run_id, self.clock_domain],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(failure)?;
        let Some((revoked, previous)) = previous else { return Ok(false) };
        // A compacted terminal row is the permanent run-ID replay seal.
        if previous.is_empty() {
            return if revoked == 1 { Ok(true) } else { Err("invalid terminal grant seal".into()) };
        }
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

    /// Reclaim the payload of expired runs. The grant row and its unique run
    /// ID remain as a replay seal for `TERMINAL_SEAL_HISTORY_MS` past the
    /// cutoff; older seals of this boot are then dropped so the table stays
    /// bounded. `cutoff_ms` is an explicit policy input, never inferred from
    /// a wall clock or another boot's monotonic origin. Each call compacts at
    /// most 16 runs and sweeps a bounded number of seals in one FULL
    /// transaction. The returned count is the number of runs compacted.
    pub fn compact_terminal(&mut self, cutoff_ms: u64, limit: usize) -> Result<usize, String> {
        if limit == 0 || limit > 16 {
            return Err("terminal compaction limit must be 1..16".into());
        }
        if cutoff_ms > boot_millis()? {
            return Err("terminal compaction cutoff is in the future".into());
        }
        let cutoff = i64::try_from(cutoff_ms).map_err(failure)?;
        let tx =
            self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(failure)?;
        let runs: Vec<String> = {
            let mut query = tx
                .prepare(
                    "SELECT run_id FROM query_grants
                 WHERE boot_id=?1 AND expires_ms<=?2 AND length(body)>0
                 ORDER BY expires_ms,run_id LIMIT ?3",
                )
                .map_err(failure)?;
            let rows = query
                .query_map(
                    params![self.clock_domain, cutoff, i64::try_from(limit).map_err(failure)?],
                    |row| row.get(0),
                )
                .map_err(failure)?
                .collect::<Result<_, _>>()
                .map_err(failure)?;
            rows
        };
        for run in &runs {
            let attempts: i64 = tx
                .query_row("SELECT COUNT(*) FROM query_attempts WHERE run_id=?1", [run], |row| {
                    row.get(0)
                })
                .map_err(failure)?;
            if attempts > 16 {
                return Err("terminal run attempt count exceeds budget".into());
            }
            tx.execute("DELETE FROM query_attempts WHERE run_id=?1", [run]).map_err(failure)?;
            tx.execute("DELETE FROM query_mcp_bindings WHERE run_id=?1", [run]).map_err(failure)?;
            tx.execute("DELETE FROM query_packages WHERE run_id=?1", [run]).map_err(failure)?;
            let changed = tx
                .execute(
                    "UPDATE query_grants SET revoked=1,body=X''
                 WHERE run_id=?1 AND boot_id=?2 AND expires_ms<=?3 AND length(body)>0",
                    params![run, self.clock_domain, cutoff],
                )
                .map_err(failure)?;
            if changed != 1 {
                return Err("terminal compaction grant changed".into());
            }
        }
        // Seals of this boot that expired more than the history window before
        // the cutoff carry no payload and no dependants; drop a bounded batch.
        let seal_cutoff = cutoff
            .checked_sub(TERMINAL_SEAL_HISTORY_MS)
            .ok_or("terminal seal history cutoff underflow")?;
        tx.execute(
            "DELETE FROM query_grants WHERE run_id IN (
                 SELECT run_id FROM query_grants
                 WHERE boot_id=?1 AND length(body)=0 AND expires_ms<=?2
                   AND NOT EXISTS(SELECT 1 FROM query_attempts a WHERE a.run_id=query_grants.run_id)
                   AND NOT EXISTS(SELECT 1 FROM query_mcp_bindings b WHERE b.run_id=query_grants.run_id)
                   AND NOT EXISTS(SELECT 1 FROM query_packages p WHERE p.run_id=query_grants.run_id)
                 ORDER BY expires_ms,run_id LIMIT ?3)",
            params![self.clock_domain, seal_cutoff, TERMINAL_SEAL_SWEEP_LIMIT],
        )
        .map_err(failure)?;
        tx.commit().map_err(failure)?;
        Ok(runs.len())
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
        if body.is_empty() {
            if revoked != 1 {
                return Err("invalid terminal grant seal".into());
            }
            return Ok(Some(serde_json::json!({
                "run_id":run_id,
                "revoked":true,
                "terminal_payload_compacted":true,
                "clock_domain_current":clock_domain == self.clock_domain,
            })));
        }
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

#[cfg(test)]
mod storage_bound_tests {
    use super::{QueryLedger, LEDGER_QUOTA_BYTES, WAL_AUTOCHECKPOINT_PAGES};

    #[test]
    fn open_applies_page_quota_and_wal_autocheckpoint_on_its_own_connection() {
        let directory = std::env::temp_dir().join(format!(
            "nhm-query-ledger-bounds-{}-{}",
            std::process::id(),
            crate::hex(&crate::random_token().unwrap())
        ));
        std::fs::create_dir(&directory).unwrap();
        let ledger = QueryLedger::open_for_boot(
            &directory.join("ledger.sqlite"),
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
        .unwrap();
        let page: u64 =
            ledger.conn.pragma_query_value(None, "page_size", |row| row.get(0)).unwrap();
        let max_pages: u64 =
            ledger.conn.pragma_query_value(None, "max_page_count", |row| row.get(0)).unwrap();
        let autocheckpoint: i64 =
            ledger.conn.pragma_query_value(None, "wal_autocheckpoint", |row| row.get(0)).unwrap();
        assert_eq!(page, 4096, "default page size assumed by the quota arithmetic");
        assert_eq!(max_pages, LEDGER_QUOTA_BYTES / page);
        assert_eq!(max_pages, 65_536);
        assert_eq!(autocheckpoint, WAL_AUTOCHECKPOINT_PAGES);
        drop(ledger);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(test)]
mod projection_error_tests {
    use super::{projection_sql_failure, ProjectionWriteError};

    #[test]
    fn sqlite_full_is_typed_recoverable_but_io_and_matching_text_are_not() {
        let full = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            None,
        );
        assert!(projection_sql_failure(full).is_proven_recoverable());
        for code in [rusqlite::ffi::SQLITE_IOERR_DATA, rusqlite::ffi::SQLITE_IOERR_CORRUPTFS] {
            let io = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            assert!(!projection_sql_failure(io).is_proven_recoverable());
        }
        assert!(!ProjectionWriteError::Refused("Q_SQLITE_RETRYABLE: database is locked".into())
            .is_proven_recoverable());
        assert!(!ProjectionWriteError::Refused("M parent retention full".into())
            .is_proven_recoverable());
    }
}
