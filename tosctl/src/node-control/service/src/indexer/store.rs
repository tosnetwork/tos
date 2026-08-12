/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! SQLite-backed storage for the chain-wide contract indexer.
//!
//! Two tables: `indexer_meta` (one `checkpoint:<shard_key>` entry per shard
//! being scanned, so a restart resumes each shard where it left off rather
//! than starting over -- shard block seqnos advance independently of the
//! masterchain's; one `blockhash:<shard_key>` entry alongside it, so a reorg
//! at or before the checkpoint can be detected -- see `indexer_task`'s
//! reorg-rewind logic; and a `schema_version` entry, checked on every open)
//! and `indexed_contracts` (one row per address the indexer has ever seen).
//! Every account the indexer encounters gets a row -- including ones that
//! turn out not to be one of the four known contract types
//! (`kind = "unclassified"`) -- so a plain wallet or Agent Account that
//! transacts frequently is code-hash-checked once, not on every subsequent
//! sighting.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};

/// Bumped whenever `init_schema`'s table/column layout changes in a way that
/// isn't purely additive (`CREATE ... IF NOT EXISTS` alone can't detect a
/// changed column set on an existing file).
const CURRENT_SCHEMA_VERSION: i64 = 3;

/// `MIGRATIONS[i]` transforms a database at schema version `i + 1` into
/// version `i + 2` (e.g. `MIGRATIONS[0]` migrates v1 -> v2). Adding an
/// entry here plus bumping [`CURRENT_SCHEMA_VERSION`] is the intended way
/// to evolve the schema, rather than editing `init_schema`'s
/// `CREATE TABLE` in place (which `IF NOT EXISTS` would silently no-op
/// against an existing file).
const MIGRATIONS: &[fn(&Connection) -> rusqlite::Result<()>] = &[
    |conn| {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS service_request_lifecycle (
                service_address TEXT NOT NULL,
                request_id TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                dto_json TEXT NOT NULL,
                PRIMARY KEY(service_address, request_id)
            );
            CREATE INDEX IF NOT EXISTS idx_service_request_status
                ON service_request_lifecycle(service_address, status);",
        )
    },
    |conn| conn.execute_batch(POIW_SETTLEMENT_SCHEMA),
];

/// v3: settlement events for the PoIW shadow-scoring data plane. One row
/// per observed settlement (a Task Escrow reaching `settled`, or a
/// Service Actor request answered within its deadline), keyed so
/// re-observation is idempotent. `seqno` is the block in which the
/// transition was *observed* by the scan -- an upper bound on, not
/// necessarily equal to, the block that executed it.
const POIW_SETTLEMENT_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS poiw_settlement_events (
        address TEXT NOT NULL,
        request_id TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL,
        earner TEXT NOT NULL,
        payer TEXT NOT NULL,
        amount INTEGER NOT NULL,
        attested INTEGER NOT NULL,
        seqno INTEGER NOT NULL,
        observed_at INTEGER NOT NULL,
        PRIMARY KEY(address, request_id)
    );
    CREATE INDEX IF NOT EXISTS idx_poiw_settlement_seqno
        ON poiw_settlement_events(seqno);";

/// One indexed account: either a recognized contract (`kind` is one of
/// `task_escrow`/`dispute`/`service_actor`/`capability_registry`) or
/// `unclassified` (seen on-chain, code hash didn't match any known contract).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedRecord {
    pub address: String,
    pub kind: String,
    pub creator: Option<String>,
    pub counterparty: Option<String>,
    pub status: Option<String>,
    pub deadline: Option<u64>,
    pub last_seqno: u32,
    pub updated_at: u64,
    pub dto_json: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRequestRecord {
    pub service_address: String,
    pub request_id: u64,
    pub status: String,
    pub updated_at: u64,
    pub dto_json: String,
}

/// One observed settlement, recorded for the PoIW shadow-scoring data
/// plane. `request_id` is empty for Task Escrow settlements and the
/// request number for Service Actor responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoiwSettlementRecord {
    pub address: String,
    pub request_id: String,
    pub kind: String,
    pub earner: String,
    pub payer: String,
    pub amount: u64,
    pub attested: bool,
    pub seqno: u32,
    pub observed_at: u64,
}

/// Filters accepted by [`IndexerStore::list`]. All fields are optional
/// (`None` = no filter on that column).
#[derive(Clone, Debug, Default)]
pub struct ListFilters<'a> {
    pub creator: Option<&'a str>,
    pub status: Option<&'a str>,
    pub deadline_after: Option<u64>,
    pub deadline_before: Option<u64>,
}

pub struct IndexerStore {
    conn: Mutex<Connection>,
}

impl IndexerStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        Self::init_schema(&conn)?;
        Self::ensure_schema_version(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// In-memory store, for tests.
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        Self::ensure_schema_version(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn init_schema(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS indexer_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS indexed_contracts (
                address TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                creator TEXT,
                counterparty TEXT,
                status TEXT,
                deadline INTEGER,
                last_seqno INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                dto_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_indexed_contracts_kind
                ON indexed_contracts(kind);
            CREATE TABLE IF NOT EXISTS service_request_lifecycle (
                service_address TEXT NOT NULL,
                request_id TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                dto_json TEXT NOT NULL,
                PRIMARY KEY(service_address, request_id)
            );
            CREATE INDEX IF NOT EXISTS idx_service_request_status
                ON service_request_lifecycle(service_address, status);",
        )?;
        conn.execute_batch(POIW_SETTLEMENT_SCHEMA)?;
        Ok(())
    }

    /// Records [`CURRENT_SCHEMA_VERSION`] on a fresh database, or runs any
    /// pending [`MIGRATIONS`] to bring an older one forward. A version newer
    /// than this binary supports fails outright -- an older binary opening a
    /// database written by a future one is never safe to silently proceed
    /// with. Each migration step updates the stored version immediately
    /// after it succeeds, so a failure partway through a multi-step chain
    /// leaves the database at the last version that was actually reached,
    /// not silently marked as fully migrated.
    fn ensure_schema_version(conn: &Connection) -> anyhow::Result<()> {
        Self::ensure_schema_version_against(conn, CURRENT_SCHEMA_VERSION, MIGRATIONS)
    }

    /// The actual logic, with `current`/`migrations` as parameters rather
    /// than reading the module constants directly, so tests can exercise
    /// the "old version with a missing migration step" branch without
    /// needing a real second schema version to exist yet.
    fn ensure_schema_version_against(
        conn: &Connection,
        current: i64,
        migrations: &[fn(&Connection) -> rusqlite::Result<()>],
    ) -> anyhow::Result<()> {
        let existing: Option<String> = conn
            .query_row("SELECT value FROM indexer_meta WHERE key = 'schema_version'", [], |row| {
                row.get(0)
            })
            .optional()?;
        let mut version = match existing.as_deref().map(str::parse::<i64>) {
            None => {
                // Fresh database: `init_schema` just created the current
                // layout directly, so it's already at the current version.
                conn.execute(
                    "INSERT INTO indexer_meta (key, value) VALUES ('schema_version', ?1)",
                    params![current.to_string()],
                )?;
                return Ok(());
            }
            Some(Ok(v)) => v,
            Some(Err(_)) => anyhow::bail!("indexer database has a corrupt schema_version value"),
        };
        if version < 1 {
            anyhow::bail!("indexer database has an invalid schema_version {version}");
        }
        if version > current {
            anyhow::bail!(
                "indexer database schema version {version} is newer than this binary supports \
                 ({current}) -- upgrade tosctl"
            );
        }
        while version < current {
            let migration = migrations.get((version - 1) as usize).ok_or_else(|| {
                anyhow::anyhow!(
                    "indexer database schema version {version} has no migration path to \
                     {current} -- delete the indexer database file to rebuild from genesis, \
                     or pin the binary version that wrote it"
                )
            })?;
            migration(conn)?;
            version += 1;
            conn.execute(
                "UPDATE indexer_meta SET value = ?1 WHERE key = 'schema_version'",
                params![version.to_string()],
            )?;
        }
        Ok(())
    }

    /// Last seqno fully scanned for the given shard key (e.g.
    /// `"-1:-9223372036854775808"` for the masterchain, or
    /// `"0:9223372036854775808"` for workchain 0's shard). `0` means "never
    /// scanned" -- the caller starts from seqno 1 (genesis). Shard block
    /// seqnos advance independently of the masterchain's, so each shard is
    /// checkpointed separately.
    /// A missing checkpoint (never scanned) and a corrupt one (unparseable
    /// stored value) both fall back to `0` -- the safe behavior in both
    /// cases is "rescan this shard from genesis" -- but the two are
    /// distinguished in the log, since a corrupt value on an
    /// already-populated database is worth an operator's attention (a full
    /// rescan is redundant work, not silent data loss, so this is a
    /// deliberate fail-safe rather than a fail-closed).
    pub fn checkpoint(&self, shard_key: &str) -> anyhow::Result<u32> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM indexer_meta WHERE key = ?1",
                params![format!("checkpoint:{shard_key}")],
                |row| row.get(0),
            )
            .optional()?;
        match value {
            None => Ok(0),
            Some(v) => match v.parse() {
                Ok(seqno) => Ok(seqno),
                Err(_) => {
                    tracing::warn!(
                        target: "indexer",
                        shard = %shard_key,
                        raw_value = %v,
                        "corrupt checkpoint value, falling back to a full rescan from genesis",
                    );
                    Ok(0)
                }
            },
        }
    }

    pub fn set_checkpoint(&self, shard_key: &str, seqno: u32) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.execute(
            "INSERT INTO indexer_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![format!("checkpoint:{shard_key}"), seqno.to_string()],
        )?;
        Ok(())
    }

    /// The block hash last recorded at this shard's checkpoint seqno, used
    /// to detect a reorg: if the chain later reports a *different* hash at
    /// that same seqno, the block the indexer already scanned was
    /// reorganized out from under it.
    pub fn checkpoint_block_hash(&self, shard_key: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.query_row(
            "SELECT value FROM indexer_meta WHERE key = ?1",
            params![format!("blockhash:{shard_key}")],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn set_checkpoint_block_hash(
        &self,
        shard_key: &str,
        block_hash: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.execute(
            "INSERT INTO indexer_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![format!("blockhash:{shard_key}"), block_hash],
        )?;
        Ok(())
    }

    /// `true` if this address has already been seen (classified or not),
    /// i.e. it does not need a fresh code-hash lookup.
    pub fn is_known(&self, address: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM indexed_contracts WHERE address = ?1",
                params![address],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Returns the stored `kind` for an already-known address, if any.
    pub fn kind_of(&self, address: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let kind: Option<String> = conn
            .query_row(
                "SELECT kind FROM indexed_contracts WHERE address = ?1",
                params![address],
                |row| row.get(0),
            )
            .optional()?;
        Ok(kind)
    }

    pub fn upsert(&self, record: &IndexedRecord) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.execute(
            "INSERT INTO indexed_contracts
                (address, kind, creator, counterparty, status, deadline, last_seqno, updated_at, dto_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(address) DO UPDATE SET
                kind = excluded.kind,
                creator = excluded.creator,
                counterparty = excluded.counterparty,
                status = excluded.status,
                deadline = excluded.deadline,
                last_seqno = excluded.last_seqno,
                updated_at = excluded.updated_at,
                dto_json = excluded.dto_json",
            params![
                record.address,
                record.kind,
                record.creator,
                record.counterparty,
                record.status,
                record.deadline,
                record.last_seqno,
                record.updated_at,
                record.dto_json,
            ],
        )?;
        Ok(())
    }

    pub fn get(&self, address: &str) -> anyhow::Result<Option<IndexedRecord>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.query_row(
            "SELECT address, kind, creator, counterparty, status, deadline, last_seqno, updated_at, dto_json
             FROM indexed_contracts WHERE address = ?1",
            params![address],
            row_to_record,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Lists records of a given `kind` matching `filters`, sorted by address
    /// for stable pagination, returning `(page, total_matching)`.
    pub fn list(
        &self,
        kind: &str,
        filters: &ListFilters<'_>,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<(Vec<IndexedRecord>, usize)> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");

        let mut where_clauses = vec!["kind = ?1".to_owned()];
        let mut bind: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(kind.to_owned())];

        if let Some(creator) = filters.creator {
            bind.push(Box::new(creator.to_owned()));
            where_clauses.push(format!("creator = ?{}", bind.len()));
        }
        if let Some(status) = filters.status {
            bind.push(Box::new(status.to_owned()));
            where_clauses.push(format!("status = ?{}", bind.len()));
        }
        if let Some(after) = filters.deadline_after {
            bind.push(Box::new(after as i64));
            where_clauses.push(format!("deadline > ?{}", bind.len()));
        }
        if let Some(before) = filters.deadline_before {
            bind.push(Box::new(before as i64));
            where_clauses.push(format!("deadline < ?{}", bind.len()));
        }
        let where_sql = where_clauses.join(" AND ");

        let total: usize = conn.query_row(
            &format!("SELECT COUNT(*) FROM indexed_contracts WHERE {where_sql}"),
            rusqlite::params_from_iter(bind.iter().map(|b| b.as_ref())),
            |row| row.get::<_, i64>(0),
        )? as usize;

        bind.push(Box::new(limit as i64));
        let limit_idx = bind.len();
        bind.push(Box::new(offset as i64));
        let offset_idx = bind.len();

        let sql = format!(
            "SELECT address, kind, creator, counterparty, status, deadline, last_seqno, updated_at, dto_json
             FROM indexed_contracts WHERE {where_sql}
             ORDER BY address LIMIT ?{limit_idx} OFFSET ?{offset_idx}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bind.iter().map(|b| b.as_ref())), row_to_record)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok((rows, total))
    }

    /// Records one settlement event. First observation wins (`INSERT OR
    /// IGNORE`): a settlement is a terminal, once-only transition, so a
    /// re-scan or a later re-observation of the same settled contract
    /// must not move the event to a different seqno.
    pub fn record_poiw_settlement(&self, record: &PoiwSettlementRecord) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO poiw_settlement_events
                (address, request_id, kind, earner, payer, amount, attested, seqno, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record.address,
                record.request_id,
                record.kind,
                record.earner,
                record.payer,
                record.amount as i64,
                record.attested as i64,
                record.seqno,
                record.observed_at as i64,
            ],
        )?;
        Ok(())
    }

    /// Lists settlement events with `from_seqno <= seqno <= to_seqno`,
    /// ordered by `(seqno, address, request_id)` for stable pagination,
    /// returning `(page, total_matching)`.
    pub fn list_poiw_settlements(
        &self,
        from_seqno: u32,
        to_seqno: u32,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<(Vec<PoiwSettlementRecord>, usize)> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let total: usize = conn.query_row(
            "SELECT COUNT(*) FROM poiw_settlement_events WHERE seqno >= ?1 AND seqno <= ?2",
            params![from_seqno, to_seqno],
            |row| row.get::<_, i64>(0),
        )? as usize;
        let mut stmt = conn.prepare(
            "SELECT address, request_id, kind, earner, payer, amount, attested, seqno, observed_at
             FROM poiw_settlement_events WHERE seqno >= ?1 AND seqno <= ?2
             ORDER BY seqno, address, request_id LIMIT ?3 OFFSET ?4",
        )?;
        let rows = stmt
            .query_map(params![from_seqno, to_seqno, limit as i64, offset as i64], |row| {
                Ok(PoiwSettlementRecord {
                    address: row.get(0)?,
                    request_id: row.get(1)?,
                    kind: row.get(2)?,
                    earner: row.get(3)?,
                    payer: row.get(4)?,
                    amount: row.get::<_, i64>(5)? as u64,
                    attested: row.get::<_, i64>(6)? != 0,
                    seqno: row.get(7)?,
                    observed_at: row.get::<_, i64>(8)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok((rows, total))
    }

    pub fn upsert_service_request(&self, record: &ServiceRequestRecord) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.execute(
            "INSERT INTO service_request_lifecycle
                (service_address, request_id, status, updated_at, dto_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(service_address, request_id) DO UPDATE SET
                status = excluded.status, updated_at = excluded.updated_at,
                dto_json = excluded.dto_json",
            params![
                record.service_address,
                record.request_id.to_string(),
                record.status,
                record.updated_at as i64,
                record.dto_json
            ],
        )?;
        Ok(())
    }

    pub fn service_request(
        &self,
        service_address: &str,
        request_id: u64,
    ) -> anyhow::Result<Option<ServiceRequestRecord>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.query_row(
            "SELECT service_address, request_id, status, updated_at, dto_json
             FROM service_request_lifecycle WHERE service_address = ?1 AND request_id = ?2",
            params![service_address, request_id.to_string()],
            |row| {
                Ok(ServiceRequestRecord {
                    service_address: row.get(0)?,
                    request_id: row.get::<_, String>(1)?.parse().map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                    status: row.get(2)?,
                    updated_at: row.get::<_, i64>(3)? as u64,
                    dto_json: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    /// Returns the highest ID ever indexed plus only non-terminal rows that
    /// still need an on-chain refresh. IDs are TEXT to preserve all uint64
    /// values, so compute the maximum after lossless Rust parsing.
    pub fn service_requests_for_refresh(
        &self,
        service_address: &str,
    ) -> anyhow::Result<(Option<u64>, Vec<ServiceRequestRecord>)> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT service_address, request_id, status, updated_at, dto_json
             FROM service_request_lifecycle WHERE service_address = ?1",
        )?;
        let rows = stmt
            .query_map(params![service_address], |row| {
                let raw: String = row.get(1)?;
                let request_id = raw.parse().map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(ServiceRequestRecord {
                    service_address: row.get(0)?,
                    request_id,
                    status: row.get(2)?,
                    updated_at: row.get::<_, i64>(3)? as u64,
                    dto_json: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let max_id = rows.iter().map(|r| r.request_id).max();
        let active = rows
            .into_iter()
            .filter(|r| matches!(r.status.as_str(), "pending" | "refundable"))
            .collect();
        Ok((max_id, active))
    }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<IndexedRecord> {
    Ok(IndexedRecord {
        address: row.get(0)?,
        kind: row.get(1)?,
        creator: row.get(2)?,
        counterparty: row.get(3)?,
        status: row.get(4)?,
        deadline: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
        last_seqno: row.get(6)?,
        updated_at: row.get(7)?,
        dto_json: row.get(8)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        address: &str,
        kind: &str,
        creator: &str,
        status: &str,
        deadline: u64,
    ) -> IndexedRecord {
        IndexedRecord {
            address: address.to_owned(),
            kind: kind.to_owned(),
            creator: Some(creator.to_owned()),
            counterparty: None,
            status: Some(status.to_owned()),
            deadline: Some(deadline),
            last_seqno: 1,
            updated_at: 1000,
            dto_json: "{}".to_owned(),
        }
    }

    #[test]
    fn checkpoint_defaults_to_zero_and_round_trips() {
        let store = IndexerStore::open_in_memory().unwrap();
        assert_eq!(store.checkpoint("-1:-9223372036854775808").unwrap(), 0);
        store.set_checkpoint("-1:-9223372036854775808", 42).unwrap();
        assert_eq!(store.checkpoint("-1:-9223372036854775808").unwrap(), 42);
        store.set_checkpoint("-1:-9223372036854775808", 43).unwrap();
        assert_eq!(store.checkpoint("-1:-9223372036854775808").unwrap(), 43);
    }

    #[test]
    fn a_corrupt_checkpoint_value_falls_back_to_zero_rather_than_erroring() {
        let store = IndexerStore::open_in_memory().unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO indexer_meta (key, value) VALUES ('checkpoint:0:1', 'not-a-number')",
                [],
            )
            .unwrap();
        }
        assert_eq!(
            store.checkpoint("0:1").unwrap(),
            0,
            "corrupt data must trigger a safe rescan, not a panic/error"
        );
    }

    #[test]
    fn checkpoints_are_independent_per_shard_key() {
        let store = IndexerStore::open_in_memory().unwrap();
        store.set_checkpoint("-1:-9223372036854775808", 10).unwrap();
        store.set_checkpoint("0:9223372036854775808", 7).unwrap();
        assert_eq!(store.checkpoint("-1:-9223372036854775808").unwrap(), 10);
        assert_eq!(store.checkpoint("0:9223372036854775808").unwrap(), 7);
    }

    #[test]
    fn checkpoint_block_hash_defaults_to_none_and_round_trips() {
        let store = IndexerStore::open_in_memory().unwrap();
        assert_eq!(store.checkpoint_block_hash("-1:-9223372036854775808").unwrap(), None);
        store.set_checkpoint_block_hash("-1:-9223372036854775808", "hash-a").unwrap();
        assert_eq!(
            store.checkpoint_block_hash("-1:-9223372036854775808").unwrap(),
            Some("hash-a".to_owned())
        );
        store.set_checkpoint_block_hash("-1:-9223372036854775808", "hash-b").unwrap();
        assert_eq!(
            store.checkpoint_block_hash("-1:-9223372036854775808").unwrap(),
            Some("hash-b".to_owned())
        );
    }

    #[test]
    fn fresh_database_records_current_schema_version() {
        let store = IndexerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        let version: String = conn
            .query_row("SELECT value FROM indexer_meta WHERE key = 'schema_version'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION.to_string());
    }

    #[test]
    fn reopening_a_database_with_a_newer_schema_version_fails_loudly() {
        let conn = Connection::open_in_memory().unwrap();
        IndexerStore::init_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO indexer_meta (key, value) VALUES ('schema_version', ?1)",
            params![(CURRENT_SCHEMA_VERSION + 1).to_string()],
        )
        .unwrap();
        let err = IndexerStore::ensure_schema_version(&conn).unwrap_err();
        assert!(err.to_string().contains("newer than this binary supports"), "{err}");
    }

    #[test]
    fn reopening_a_database_with_an_invalid_schema_version_fails_loudly() {
        let conn = Connection::open_in_memory().unwrap();
        IndexerStore::init_schema(&conn).unwrap();
        conn.execute("INSERT INTO indexer_meta (key, value) VALUES ('schema_version', '0')", [])
            .unwrap();
        let err = IndexerStore::ensure_schema_version(&conn).unwrap_err();
        assert!(err.to_string().contains("invalid schema_version"), "{err}");
    }

    #[test]
    fn an_old_version_with_no_migration_step_available_fails_loudly() {
        // CURRENT_SCHEMA_VERSION is 1 with no real migrations yet, so this
        // exercises the "missing migration" branch against an injected
        // higher target version rather than waiting for a real v2 to exist.
        let conn = Connection::open_in_memory().unwrap();
        IndexerStore::init_schema(&conn).unwrap();
        conn.execute("INSERT INTO indexer_meta (key, value) VALUES ('schema_version', '1')", [])
            .unwrap();
        let err = IndexerStore::ensure_schema_version_against(&conn, 3, &[]).unwrap_err();
        assert!(err.to_string().contains("no migration path"), "{err}");
    }

    #[test]
    fn migrations_run_in_order_and_update_the_stored_version_after_each_step() {
        let conn = Connection::open_in_memory().unwrap();
        IndexerStore::init_schema(&conn).unwrap();
        conn.execute("INSERT INTO indexer_meta (key, value) VALUES ('schema_version', '1')", [])
            .unwrap();
        conn.execute("INSERT INTO indexer_meta (key, value) VALUES ('migration_log', '')", [])
            .unwrap();

        fn append_log(conn: &Connection, step: &str) {
            conn.execute(
                "UPDATE indexer_meta SET value = value || ?1 WHERE key = 'migration_log'",
                params![step],
            )
            .unwrap();
        }
        fn migrate_to_v2(conn: &Connection) -> rusqlite::Result<()> {
            append_log(conn, "1->2;");
            Ok(())
        }
        fn migrate_to_v3(conn: &Connection) -> rusqlite::Result<()> {
            append_log(conn, "2->3;");
            Ok(())
        }

        IndexerStore::ensure_schema_version_against(&conn, 3, &[migrate_to_v2, migrate_to_v3])
            .unwrap();

        let version: String = conn
            .query_row("SELECT value FROM indexer_meta WHERE key = 'schema_version'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, "3");
        let log: String = conn
            .query_row("SELECT value FROM indexer_meta WHERE key = 'migration_log'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(log, "1->2;2->3;", "migrations must run in order, once each");
    }

    #[test]
    fn a_failing_migration_leaves_the_version_at_the_last_successfully_reached_step() {
        let conn = Connection::open_in_memory().unwrap();
        IndexerStore::init_schema(&conn).unwrap();
        conn.execute("INSERT INTO indexer_meta (key, value) VALUES ('schema_version', '1')", [])
            .unwrap();

        fn migrate_ok(_conn: &Connection) -> rusqlite::Result<()> {
            Ok(())
        }
        fn migrate_fails(_conn: &Connection) -> rusqlite::Result<()> {
            Err(rusqlite::Error::SqliteSingleThreadedMode)
        }

        let result =
            IndexerStore::ensure_schema_version_against(&conn, 3, &[migrate_ok, migrate_fails]);
        assert!(result.is_err());

        let version: String = conn
            .query_row("SELECT value FROM indexer_meta WHERE key = 'schema_version'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, "2", "the successful first step must be durably recorded");
    }

    #[test]
    fn unknown_address_is_not_known() {
        let store = IndexerStore::open_in_memory().unwrap();
        assert!(!store.is_known("0:aaaa").unwrap());
        assert_eq!(store.get("0:aaaa").unwrap(), None);
    }

    #[test]
    fn upsert_then_get_round_trips_and_is_known() {
        let store = IndexerStore::open_in_memory().unwrap();
        let rec = record("0:aaaa", "task_escrow", "0:creator", "open", 100);
        store.upsert(&rec).unwrap();
        assert!(store.is_known("0:aaaa").unwrap());
        assert_eq!(store.kind_of("0:aaaa").unwrap(), Some("task_escrow".to_owned()));
        assert_eq!(store.get("0:aaaa").unwrap(), Some(rec));
    }

    #[test]
    fn upsert_overwrites_existing_row() {
        let store = IndexerStore::open_in_memory().unwrap();
        store.upsert(&record("0:aaaa", "task_escrow", "0:creator", "open", 100)).unwrap();
        let updated = record("0:aaaa", "task_escrow", "0:creator", "settled", 100);
        store.upsert(&updated).unwrap();
        assert_eq!(store.get("0:aaaa").unwrap(), Some(updated));
    }

    #[test]
    fn service_request_lifecycle_round_trips_full_u64_ids_and_transitions() {
        let store = IndexerStore::open_in_memory().unwrap();
        let mut rec = ServiceRequestRecord {
            service_address: "-1:service".into(),
            request_id: u64::MAX,
            status: "pending".into(),
            updated_at: 10,
            dto_json: r#"{"status":"pending"}"#.into(),
        };
        store.upsert_service_request(&rec).unwrap();
        assert_eq!(store.service_request("-1:service", u64::MAX).unwrap(), Some(rec.clone()));
        rec.status = "responded".into();
        rec.updated_at = 11;
        rec.dto_json = r#"{"status":"responded"}"#.into();
        store.upsert_service_request(&rec).unwrap();
        assert_eq!(store.service_request("-1:service", u64::MAX).unwrap(), Some(rec));
    }

    #[test]
    fn list_filters_by_kind_creator_status_and_deadline_range() {
        let store = IndexerStore::open_in_memory().unwrap();
        store.upsert(&record("0:a", "task_escrow", "0:creator1", "open", 100)).unwrap();
        store.upsert(&record("0:b", "task_escrow", "0:creator1", "settled", 200)).unwrap();
        store.upsert(&record("0:c", "task_escrow", "0:creator2", "open", 300)).unwrap();
        store.upsert(&record("0:d", "dispute", "0:creator1", "open", 400)).unwrap();

        let (rows, total) = store.list("task_escrow", &ListFilters::default(), 0, 10).unwrap();
        assert_eq!(total, 3);
        assert_eq!(rows.len(), 3);

        let filters = ListFilters { creator: Some("0:creator1"), ..Default::default() };
        let (rows, total) = store.list("task_escrow", &filters, 0, 10).unwrap();
        assert_eq!(total, 2);
        assert_eq!(rows.iter().map(|r| r.address.as_str()).collect::<Vec<_>>(), vec!["0:a", "0:b"]);

        let filters = ListFilters { status: Some("open"), ..Default::default() };
        let (rows, _) = store.list("task_escrow", &filters, 0, 10).unwrap();
        assert_eq!(rows.iter().map(|r| r.address.as_str()).collect::<Vec<_>>(), vec!["0:a", "0:c"]);

        let filters = ListFilters {
            deadline_after: Some(150),
            deadline_before: Some(350),
            ..Default::default()
        };
        let (rows, _) = store.list("task_escrow", &filters, 0, 10).unwrap();
        assert_eq!(rows.iter().map(|r| r.address.as_str()).collect::<Vec<_>>(), vec!["0:b", "0:c"]);
    }

    #[test]
    fn list_paginates_with_offset_and_limit() {
        let store = IndexerStore::open_in_memory().unwrap();
        for i in 0..5 {
            store
                .upsert(&record(&format!("0:{i}"), "task_escrow", "0:creator", "open", 100))
                .unwrap();
        }
        let (rows, total) = store.list("task_escrow", &ListFilters::default(), 1, 2).unwrap();
        assert_eq!(total, 5);
        assert_eq!(rows.iter().map(|r| r.address.as_str()).collect::<Vec<_>>(), vec!["0:1", "0:2"]);
    }

    #[test]
    fn unclassified_kind_is_stored_and_listed_separately() {
        let store = IndexerStore::open_in_memory().unwrap();
        let rec = IndexedRecord {
            address: "0:wallet".to_owned(),
            kind: "unclassified".to_owned(),
            creator: None,
            counterparty: None,
            status: None,
            deadline: None,
            last_seqno: 1,
            updated_at: 1,
            dto_json: "{}".to_owned(),
        };
        store.upsert(&rec).unwrap();
        assert_eq!(store.kind_of("0:wallet").unwrap(), Some("unclassified".to_owned()));
        let (rows, total) = store.list("task_escrow", &ListFilters::default(), 0, 10).unwrap();
        assert_eq!(total, 0);
        assert!(rows.is_empty());
    }

    fn settlement(
        address: &str,
        request_id: &str,
        seqno: u32,
        amount: u64,
    ) -> PoiwSettlementRecord {
        PoiwSettlementRecord {
            address: address.to_owned(),
            request_id: request_id.to_owned(),
            kind: "task_escrow".to_owned(),
            earner: "0:agent".to_owned(),
            payer: "0:creator".to_owned(),
            amount,
            attested: false,
            seqno,
            observed_at: 1_000,
        }
    }

    #[test]
    fn poiw_settlement_first_observation_wins() {
        let store = IndexerStore::open_in_memory().unwrap();
        let mut event = settlement("0:task", "", 7, 500);
        event.attested = true;
        store.record_poiw_settlement(&event).unwrap();

        // A settlement is terminal; a replayed observation at a later
        // seqno (e.g. after a rescan) must not move or change the event.
        let mut replay = event.clone();
        replay.seqno = 9;
        replay.amount = 999;
        store.record_poiw_settlement(&replay).unwrap();

        let (rows, total) = store.list_poiw_settlements(0, u32::MAX, 0, 10).unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows, vec![event]);
    }

    #[test]
    fn poiw_settlements_filter_by_seqno_range_and_paginate() {
        let store = IndexerStore::open_in_memory().unwrap();
        for i in 1..=5u32 {
            store.record_poiw_settlement(&settlement(&format!("0:t{i}"), "", i, i.into())).unwrap();
        }
        let (rows, total) = store.list_poiw_settlements(2, 4, 0, 10).unwrap();
        assert_eq!(total, 3);
        assert_eq!(rows.iter().map(|r| r.seqno).collect::<Vec<_>>(), vec![2, 3, 4]);

        let (page, page_total) = store.list_poiw_settlements(2, 4, 1, 1).unwrap();
        assert_eq!(page_total, 3);
        assert_eq!(page.iter().map(|r| r.seqno).collect::<Vec<_>>(), vec![3]);

        let (empty, none) = store.list_poiw_settlements(6, u32::MAX, 0, 10).unwrap();
        assert_eq!(none, 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn poiw_settlements_key_on_address_and_request_id() {
        let store = IndexerStore::open_in_memory().unwrap();
        // One service actor answering two requests yields two distinct
        // events; the same request re-observed stays one event.
        store.record_poiw_settlement(&settlement("0:svc", "0", 3, 10)).unwrap();
        store.record_poiw_settlement(&settlement("0:svc", "1", 4, 20)).unwrap();
        store.record_poiw_settlement(&settlement("0:svc", "1", 8, 20)).unwrap();
        let (rows, total) = store.list_poiw_settlements(0, u32::MAX, 0, 10).unwrap();
        assert_eq!(total, 2);
        assert_eq!(
            rows.iter().map(|r| (r.request_id.as_str(), r.seqno)).collect::<Vec<_>>(),
            vec![("0", 3), ("1", 4)]
        );
    }
}
