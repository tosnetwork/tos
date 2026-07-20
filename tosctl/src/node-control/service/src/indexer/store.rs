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
/// changed column set on an existing file). There is no migration path
/// implemented yet -- [`IndexerStore::open`] fails loudly on a mismatch
/// rather than silently misinterpreting old data, which is the honest
/// behavior until a real migration is written.
const CURRENT_SCHEMA_VERSION: i64 = 1;

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
                ON indexed_contracts(kind);",
        )?;
        Ok(())
    }

    /// Records [`CURRENT_SCHEMA_VERSION`] on a fresh database, or verifies an
    /// existing one matches. A mismatch fails the open outright: an older
    /// version means this binary doesn't know how to migrate it forward yet,
    /// and a newer version means an older binary opened a database written
    /// by a future one -- neither is safe to silently proceed with.
    fn ensure_schema_version(conn: &Connection) -> anyhow::Result<()> {
        let existing: Option<String> = conn
            .query_row(
                "SELECT value FROM indexer_meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match existing.as_deref().map(str::parse::<i64>) {
            None => {
                conn.execute(
                    "INSERT INTO indexer_meta (key, value) VALUES ('schema_version', ?1)",
                    params![CURRENT_SCHEMA_VERSION.to_string()],
                )?;
                Ok(())
            }
            Some(Ok(v)) if v == CURRENT_SCHEMA_VERSION => Ok(()),
            Some(Ok(v)) if v < CURRENT_SCHEMA_VERSION => Err(anyhow::anyhow!(
                "indexer database schema version {v} is older than {CURRENT_SCHEMA_VERSION} \
                 and no migration path is implemented yet -- delete the indexer database file \
                 to rebuild from genesis, or pin the binary version that wrote it"
            )),
            Some(Ok(v)) => Err(anyhow::anyhow!(
                "indexer database schema version {v} is newer than this binary supports \
                 ({CURRENT_SCHEMA_VERSION}) -- upgrade tosctl"
            )),
            Some(Err(_)) => Err(anyhow::anyhow!("indexer database has a corrupt schema_version value")),
        }
    }

    /// Last seqno fully scanned for the given shard key (e.g.
    /// `"-1:-9223372036854775808"` for the masterchain, or
    /// `"0:9223372036854775808"` for workchain 0's shard). `0` means "never
    /// scanned" -- the caller starts from seqno 1 (genesis). Shard block
    /// seqnos advance independently of the masterchain's, so each shard is
    /// checkpointed separately.
    pub fn checkpoint(&self, shard_key: &str) -> anyhow::Result<u32> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM indexer_meta WHERE key = ?1",
                params![format!("checkpoint:{shard_key}")],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.and_then(|v| v.parse().ok()).unwrap_or(0))
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

    pub fn set_checkpoint_block_hash(&self, shard_key: &str, block_hash: &str) -> anyhow::Result<()> {
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

    fn record(address: &str, kind: &str, creator: &str, status: &str, deadline: u64) -> IndexedRecord {
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
            .query_row("SELECT value FROM indexer_meta WHERE key = 'schema_version'", [], |r| r.get(0))
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
    fn reopening_a_database_with_an_older_schema_version_fails_loudly() {
        let conn = Connection::open_in_memory().unwrap();
        IndexerStore::init_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO indexer_meta (key, value) VALUES ('schema_version', '0')",
            [],
        )
        .unwrap();
        let err = IndexerStore::ensure_schema_version(&conn).unwrap_err();
        assert!(err.to_string().contains("no migration path is implemented"), "{err}");
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

        let filters = ListFilters { deadline_after: Some(150), deadline_before: Some(350), ..Default::default() };
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
}
