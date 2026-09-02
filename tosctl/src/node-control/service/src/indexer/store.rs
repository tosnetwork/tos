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
//! `indexer_meta` stores one `checkpoint:<shard_key>` entry per shard
//! being scanned, so a restart resumes each shard where it left off rather
//! than starting over -- shard block seqnos advance independently of the
//! masterchain's; one `blockhash:<shard_key>` entry alongside it, so a reorg
//! at or before the checkpoint can be detected -- see `indexer_task`'s
//! reorg-rewind logic; and a `schema_version` entry, checked on every open)
//! while the remaining tables store classified contracts, service
//! lifecycle evidence, and explorer block/transaction identities.
//! Every account the indexer encounters gets a row -- including ones that
//! turn out not to be one of the known contract types
//! (`kind = "unclassified"`) -- so a plain wallet that
//! transacts frequently is code-hash-checked once, not on every subsequent
//! sighting.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};

/// Bumped whenever `init_schema`'s table/column layout changes in a way that
/// isn't purely additive (`CREATE ... IF NOT EXISTS` alone can't detect a
/// changed column set on an existing file).
const CURRENT_SCHEMA_VERSION: i64 = 9;
/// pool.fc state 0: the stake is in the pool rather than with the Elector.
const POOL_STATE_IDLE: i64 = 0;

/// What one depositor put into one pool and what it has paid them.
#[derive(Debug, Clone, PartialEq)]
pub struct NominatorLedgerRecord {
    pub pool_address: String,
    pub nominator_address: String,
    pub deposited_total: u64,
    pub rewarded_total: u64,
    /// Changes no previous observation could account for. Kept separate so a
    /// gap in coverage is visible rather than counted as earnings.
    pub unattributed_total: u64,
    pub last_amount: u64,
    pub last_pending: u64,
    pub first_seen_at: u64,
    pub updated_at: u64,
}

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
    // Keep the retired v2 -> v3 slot so later positional migrations retain
    // their original schema-version mapping on existing databases.
    |_conn| Ok(()),
    |conn| {
        conn.execute_batch(EXPLORER_SCHEMA)?;
        // v4 adds historical block/transaction identities and learns the
        // Agent Account code hash. Existing checkpoints predate both, so a
        // one-time genesis replay is required to make the new index complete.
        conn.execute(
            "DELETE FROM indexer_meta WHERE key LIKE 'checkpoint:%' OR key LIKE 'blockhash:%'",
            [],
        )?;
        conn.execute("DELETE FROM indexed_contracts WHERE kind = 'unclassified'", [])?;
        Ok(())
    },
    |conn| {
        conn.execute_batch(
            "ALTER TABLE explorer_blocks
                 ADD COLUMN observed_mc_seqno INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE explorer_transactions ADD COLUMN fee TEXT;
             ALTER TABLE explorer_transactions ADD COLUMN in_msg_hash TEXT;
             DELETE FROM explorer_transactions;
             DELETE FROM explorer_blocks;
             DELETE FROM indexed_contracts;
             DELETE FROM service_request_lifecycle;
             DELETE FROM indexer_meta
                 WHERE key LIKE 'checkpoint:%' OR key LIKE 'blockhash:%';",
        )
    },
    |conn| conn.execute_batch(NOMINATOR_LEDGER_SCHEMA),
    |conn| conn.execute_batch(DNS_HISTORY_SCHEMA),
    migrate_dns_checkpoint_hashes,
    // v9 adds ordering indexes so the hot explorer list sorts are
    // index-served instead of sorting the whole table per request. The
    // network-wide transaction feed's ORDER BY was changed at the same time
    // from `COALESCE(b.gen_utime, 0) DESC` (an expression over a join, which
    // no index can serve) to `t.seqno DESC` -- an observable ordering change
    // only where shards interleave (blocks at the same seqno in different
    // shards now group by seqno rather than by block time) and for
    // transactions whose block row is missing (previously forced last via
    // gen_utime 0, now ordered by their own seqno). Within any single shard
    // chain the order is unchanged.
    |conn| conn.execute_batch(EXPLORER_ORDER_INDEX_SCHEMA),
];

fn migrate_dns_checkpoint_hashes(conn: &Connection) -> rusqlite::Result<()> {
    let mut columns = conn.prepare("PRAGMA table_info(dns_domain_history)")?;
    let names =
        columns.query_map([], |row| row.get::<_, String>(1))?.collect::<Result<Vec<_>, _>>()?;
    if !names.iter().any(|name| name == "root_hash") {
        conn.execute("ALTER TABLE dns_domain_history ADD COLUMN root_hash TEXT", [])?;
    }
    if !names.iter().any(|name| name == "file_hash") {
        conn.execute("ALTER TABLE dns_domain_history ADD COLUMN file_hash TEXT", [])?;
    }
    // Older rows were only height-bound and cannot be upgraded honestly.
    conn.execute("DELETE FROM dns_domain_history", [])?;
    Ok(())
}

const DNS_HISTORY_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS dns_domain_history (
        address TEXT NOT NULL,
        account_seqno INTEGER NOT NULL,
        observed_mc_seqno INTEGER NOT NULL,
        observed_at INTEGER NOT NULL,
        dto_json TEXT NOT NULL,
        root_hash TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        PRIMARY KEY(address, observed_mc_seqno)
    );
    CREATE INDEX IF NOT EXISTS idx_dns_domain_history_checkpoint
        ON dns_domain_history(observed_mc_seqno, address);";

/// What a depositor put into a pool and what the pool paid them.
///
/// The contract's ledger records only what someone is owed right now, which
/// answers "what am I holding" but not "what did this earn me" -- the two
/// differ by the deposits that got them there, and nothing on chain records
/// those against an address. Reconstructing them afterwards is not possible
/// either: a withdrawal deletes the entry outright.
///
/// So the attribution is done while it is still visible, one row per depositor
/// per pool, by comparing each observation against the last. Deltas that
/// cannot be attributed -- a gap in observation across a distribution, for
/// instance -- are accumulated separately rather than folded into rewards,
/// because a number that quietly absorbs what it could not explain is worse
/// than one that admits the gap.
const NOMINATOR_LEDGER_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS nominator_ledger (
        pool_address TEXT NOT NULL,
        nominator_address TEXT NOT NULL,
        deposited_total INTEGER NOT NULL DEFAULT 0,
        rewarded_total INTEGER NOT NULL DEFAULT 0,
        unattributed_total INTEGER NOT NULL DEFAULT 0,
        last_amount INTEGER NOT NULL DEFAULT 0,
        last_pending INTEGER NOT NULL DEFAULT 0,
        last_pool_state INTEGER NOT NULL DEFAULT 0,
        first_seen_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY(pool_address, nominator_address)
    );
    CREATE INDEX IF NOT EXISTS idx_nominator_ledger_address
        ON nominator_ledger(nominator_address);";

/// v4: the minimal durable, chain-wide index a read-only explorer needs.
///
/// The node remains authoritative for full block/transaction bodies.  These
/// tables deliberately store only deterministic identities and locations so
/// an explorer can resolve a transaction hash, paginate account history and
/// find a block by either hash without duplicating the node archive.
const EXPLORER_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS explorer_blocks (
        workchain INTEGER NOT NULL,
        shard INTEGER NOT NULL,
        seqno INTEGER NOT NULL,
        root_hash TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        gen_utime INTEGER NOT NULL,
        indexed_at INTEGER NOT NULL,
        observed_mc_seqno INTEGER NOT NULL,
        PRIMARY KEY(workchain, shard, seqno)
    );
    CREATE INDEX IF NOT EXISTS idx_explorer_blocks_root_hash
        ON explorer_blocks(root_hash);
    CREATE INDEX IF NOT EXISTS idx_explorer_blocks_file_hash
        ON explorer_blocks(file_hash);
    CREATE TABLE IF NOT EXISTS explorer_transactions (
        hash TEXT PRIMARY KEY,
        account TEXT NOT NULL,
        lt TEXT NOT NULL,
        workchain INTEGER NOT NULL,
        shard INTEGER NOT NULL,
        seqno INTEGER NOT NULL,
        fee TEXT,
        in_msg_hash TEXT,
        indexed_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_explorer_transactions_account
        ON explorer_transactions(account, seqno DESC, indexed_at DESC);
    CREATE INDEX IF NOT EXISTS idx_explorer_transactions_block
        ON explorer_transactions(workchain, shard, seqno);
    CREATE INDEX IF NOT EXISTS idx_explorer_transactions_recent
        ON explorer_transactions(seqno DESC, indexed_at DESC);";

/// v9: indexes matching the explorer list queries' ORDER BY clauses exactly,
/// so those sorts are served by an index walk instead of materialising and
/// sorting every row on each request.
const EXPLORER_ORDER_INDEX_SCHEMA: &str = "CREATE INDEX IF NOT EXISTS idx_explorer_blocks_gen_utime
        ON explorer_blocks(gen_utime DESC, seqno DESC, workchain, shard);
    CREATE INDEX IF NOT EXISTS idx_explorer_transactions_order
        ON explorer_transactions(seqno DESC, length(lt) DESC, lt DESC, hash);";

/// One indexed account: either a recognized contract (`kind` is one of the
/// public explorer contract kinds, including Agent Account) or
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplorerBlockRecord {
    pub workchain: i32,
    pub shard: i64,
    pub seqno: u32,
    pub root_hash: String,
    pub file_hash: String,
    pub gen_utime: u32,
    /// Number of transactions indexed for this block. This is derived from
    /// the transaction table when records are read, so it cannot drift from
    /// the indexed identities.
    pub tx_count: usize,
    pub indexed_at: u64,
    /// Masterchain block whose shard topology referenced this exact block.
    /// For masterchain blocks this equals `seqno`.
    pub observed_mc_seqno: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplorerTransactionRecord {
    pub hash: String,
    pub account: String,
    pub lt: u64,
    pub workchain: i32,
    pub shard: i64,
    pub seqno: u32,
    pub gen_utime: u32,
    pub fee: Option<String>,
    pub in_msg_hash: Option<String>,
    pub indexed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexerCheckpoint {
    pub shard_key: String,
    pub seqno: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplorerIndexStats {
    pub blocks: usize,
    pub transactions: usize,
    pub contracts: usize,
    pub latest_indexed_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsDomainHistoryRecord {
    pub address: String,
    pub account_seqno: u32,
    pub observed_mc_seqno: u32,
    pub observed_at: u64,
    pub dto_json: String,
    pub root_hash: Option<String>,
    pub file_hash: Option<String>,
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
        conn.execute_batch(EXPLORER_SCHEMA)?;
        conn.execute_batch(EXPLORER_ORDER_INDEX_SCHEMA)?;
        conn.execute_batch(NOMINATOR_LEDGER_SCHEMA)?;
        conn.execute_batch(DNS_HISTORY_SCHEMA)?;
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

    /// Returns every valid shard checkpoint in deterministic shard-key
    /// order. Corrupt values are omitted (and separately warned about by
    /// [`Self::checkpoint`]) rather than being exposed as made-up progress.
    pub fn checkpoints(&self) -> anyhow::Result<Vec<IndexerCheckpoint>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT substr(key, 12), value FROM indexer_meta
             WHERE key LIKE 'checkpoint:%' ORDER BY key",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let shard_key: String = row.get(0)?;
                let raw: String = row.get(1)?;
                Ok((shard_key, raw))
            })?
            .filter_map(|row| match row {
                Ok((shard_key, raw)) => {
                    raw.parse::<u32>().ok().map(|seqno| Ok(IndexerCheckpoint { shard_key, seqno }))
                }
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Atomically records a block identity and every transaction short-ID
    /// returned for it. Replaying the same block is idempotent.
    pub fn index_explorer_block(
        &self,
        block: &ExplorerBlockRecord,
        transactions: &[ExplorerTransactionRecord],
    ) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().expect("indexer store lock poisoned");
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO explorer_blocks
                (workchain, shard, seqno, root_hash, file_hash, gen_utime, indexed_at,
                 observed_mc_seqno)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(workchain, shard, seqno) DO UPDATE SET
                root_hash = excluded.root_hash,
                file_hash = excluded.file_hash,
                gen_utime = excluded.gen_utime,
                indexed_at = excluded.indexed_at,
                observed_mc_seqno = excluded.observed_mc_seqno",
            params![
                block.workchain,
                block.shard,
                block.seqno,
                block.root_hash,
                block.file_hash,
                block.gen_utime,
                block.indexed_at as i64,
                block.observed_mc_seqno,
            ],
        )?;
        // Replacing a block after a reorg must also remove transaction
        // identities that existed only in the old version of that block.
        tx.execute(
            "DELETE FROM explorer_transactions
             WHERE workchain = ?1 AND shard = ?2 AND seqno = ?3",
            params![block.workchain, block.shard, block.seqno],
        )?;
        {
            let mut statement = tx.prepare(
                "INSERT INTO explorer_transactions
                    (hash, account, lt, workchain, shard, seqno, fee, in_msg_hash, indexed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(hash) DO UPDATE SET
                    account = excluded.account,
                    lt = excluded.lt,
                    workchain = excluded.workchain,
                    shard = excluded.shard,
                    seqno = excluded.seqno,
                    fee = excluded.fee,
                    in_msg_hash = excluded.in_msg_hash,
                    indexed_at = excluded.indexed_at",
            )?;
            for record in transactions {
                statement.execute(params![
                    record.hash,
                    record.account,
                    record.lt.to_string(),
                    record.workchain,
                    record.shard,
                    record.seqno,
                    record.fee,
                    record.in_msg_hash,
                    record.indexed_at as i64,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Removes explorer identities from a reorganized suffix. Contract
    /// state is refreshed by the normal re-scan; transaction/block search
    /// must additionally forget identities that no longer exist.
    pub fn rewind_explorer(
        &self,
        workchain: i32,
        shard: i64,
        from_seqno: u32,
    ) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().expect("indexer store lock poisoned");
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM explorer_transactions
             WHERE workchain = ?1 AND shard = ?2 AND seqno >= ?3",
            params![workchain, shard, from_seqno],
        )?;
        tx.execute(
            "DELETE FROM explorer_blocks
             WHERE workchain = ?1 AND shard = ?2 AND seqno >= ?3",
            params![workchain, shard, from_seqno],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Removes every shard block that was made canonical by a masterchain
    /// suffix. This is the topology-aware counterpart to a masterchain
    /// reorg rewind and removes retired split/merge branches as well.
    pub fn rewind_masterchain_observations(&self, from_mc_seqno: u32) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().expect("indexer store lock poisoned");
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM explorer_transactions WHERE EXISTS (
                SELECT 1 FROM explorer_blocks b
                WHERE b.workchain = explorer_transactions.workchain
                  AND b.shard = explorer_transactions.shard
                  AND b.seqno = explorer_transactions.seqno
                  AND b.observed_mc_seqno >= ?1
             )",
            params![from_mc_seqno],
        )?;
        tx.execute(
            "DELETE FROM explorer_blocks WHERE observed_mc_seqno >= ?1",
            params![from_mc_seqno],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Clears all chain-derived state after a confirmed masterchain reorg.
    /// A full replay is intentionally conservative: contract snapshots and
    /// lifecycle evidence may also have originated on a retired branch and
    /// cannot be repaired safely from a short explorer-only rewind.
    /// The highest new-request id ever scanned for a service, kept as one
    /// meta row per service. Ids probed and found absent are deliberately
    /// NOT stored as lifecycle rows -- a contract reporting a fabricated
    /// counter would otherwise grow the table by one batch of dead rows per
    /// visit -- so the scan position must survive on its own.
    pub fn service_scan_high_water(&self, service_address: &str) -> anyhow::Result<Option<u64>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM indexer_meta WHERE key = ?1",
                params![format!("svc-scan:{service_address}")],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.and_then(|v| v.parse().ok()))
    }

    pub fn set_service_scan_high_water(
        &self,
        service_address: &str,
        high_water: u64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO indexer_meta (key, value) VALUES (?1, ?2)",
            params![format!("svc-scan:{service_address}"), high_water.to_string()],
        )?;
        Ok(())
    }

    pub fn reset_canonical_index(&self) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().expect("indexer store lock poisoned");
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM explorer_transactions", [])?;
        tx.execute("DELETE FROM explorer_blocks", [])?;
        tx.execute("DELETE FROM indexed_contracts", [])?;
        tx.execute("DELETE FROM service_request_lifecycle", [])?;
        tx.execute("DELETE FROM dns_domain_history", [])?;
        tx.execute(
            "DELETE FROM indexer_meta
             WHERE key LIKE 'checkpoint:%' OR key LIKE 'blockhash:%' OR key LIKE 'svc-scan:%'",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_dns_domain_history(&self, record: &DnsDomainHistoryRecord) -> anyhow::Result<()> {
        anyhow::ensure!(
            record.root_hash.as_ref().is_some_and(|hash| !hash.is_empty())
                && record.file_hash.as_ref().is_some_and(|hash| !hash.is_empty()),
            "DNS history requires a full masterchain checkpoint"
        );
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.execute(
            "INSERT INTO dns_domain_history(address,account_seqno,observed_mc_seqno,observed_at,dto_json,root_hash,file_hash)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(address,observed_mc_seqno) DO UPDATE SET
               account_seqno=excluded.account_seqno,observed_at=excluded.observed_at,
               dto_json=excluded.dto_json,root_hash=excluded.root_hash,file_hash=excluded.file_hash",
            params![record.address, record.account_seqno, record.observed_mc_seqno, record.observed_at, record.dto_json, record.root_hash, record.file_hash],
        )?;
        Ok(())
    }

    pub fn dns_domain_history(
        &self,
        after_mc_seqno: u32,
        after_address: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<DnsDomainHistoryRecord>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let mut statement = conn.prepare(
            "SELECT h.address,h.account_seqno,h.observed_mc_seqno,h.observed_at,h.dto_json,
                    h.root_hash,h.file_hash
             FROM dns_domain_history h
             WHERE h.observed_mc_seqno>?1
                OR (h.observed_mc_seqno=?1 AND h.address>?2)
             ORDER BY h.observed_mc_seqno,h.address LIMIT ?3",
        )?;
        let rows = statement.query_map(params![after_mc_seqno, after_address, limit], |row| {
            Ok(DnsDomainHistoryRecord {
                address: row.get(0)?,
                account_seqno: row.get(1)?,
                observed_mc_seqno: row.get(2)?,
                observed_at: row.get::<_, i64>(3)? as u64,
                dto_json: row.get(4)?,
                root_hash: row.get(5)?,
                file_hash: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn masterchain_block(&self, seqno: u32) -> anyhow::Result<Option<ExplorerBlockRecord>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.query_row(
            "SELECT b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash, b.gen_utime,
                    (SELECT COUNT(*) FROM explorer_transactions t
                     WHERE t.workchain=b.workchain AND t.shard=b.shard AND t.seqno=b.seqno),
                    b.indexed_at, b.observed_mc_seqno
             FROM explorer_blocks b WHERE b.workchain=-1 AND b.seqno=?1",
            params![seqno],
            row_to_explorer_block,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn explorer_block_root(
        &self,
        workchain: i32,
        shard: i64,
        seqno: u32,
    ) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.query_row(
            "SELECT root_hash FROM explorer_blocks
             WHERE workchain = ?1 AND shard = ?2 AND seqno = ?3",
            params![workchain, shard, seqno],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn explorer_transaction(
        &self,
        hash: &str,
    ) -> anyhow::Result<Option<ExplorerTransactionRecord>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.query_row(
            "SELECT t.hash, t.account, t.lt, t.workchain, t.shard, t.seqno,
                    COALESCE(b.gen_utime, 0), t.indexed_at, t.fee, t.in_msg_hash
             FROM explorer_transactions t
             LEFT JOIN explorer_blocks b
               ON b.workchain = t.workchain AND b.shard = t.shard AND b.seqno = t.seqno
             WHERE t.hash = ?1",
            params![hash],
            row_to_explorer_transaction,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn explorer_block_by_hash(
        &self,
        hash: &str,
    ) -> anyhow::Result<Option<ExplorerBlockRecord>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        conn.query_row(
            "SELECT b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash, b.gen_utime,
                    (SELECT COUNT(*) FROM explorer_transactions t
                     WHERE t.workchain = b.workchain AND t.shard = b.shard AND t.seqno = b.seqno),
                    b.indexed_at, b.observed_mc_seqno
             FROM explorer_blocks b WHERE b.root_hash = ?1 OR b.file_hash = ?1 LIMIT 1",
            params![hash],
            row_to_explorer_block,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Lists every indexed block newest-first across all observed shards.
    /// The transaction count is computed from the same durable index so the
    /// explorer never needs one node RPC round-trip per table row.
    pub fn list_explorer_blocks(
        &self,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<(Vec<ExplorerBlockRecord>, usize)> {
        let offset = i64::try_from(offset)?;
        let limit = i64::try_from(limit)?;
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let total = conn
            .query_row("SELECT COUNT(*) FROM explorer_blocks", [], |row| row.get::<_, i64>(0))?
            as usize;
        // The ORDER BY matches `idx_explorer_blocks_gen_utime` exactly so the
        // sort is an index walk, not a full-table sort per request.
        let mut stmt = conn.prepare(
            "SELECT b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash, b.gen_utime,
                    (SELECT COUNT(*) FROM explorer_transactions t
                     WHERE t.workchain = b.workchain AND t.shard = b.shard AND t.seqno = b.seqno),
                    b.indexed_at, b.observed_mc_seqno
             FROM explorer_blocks b
             ORDER BY b.gen_utime DESC, b.seqno DESC, b.workchain, b.shard
             LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt
            .query_map(params![limit, offset], row_to_explorer_block)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok((rows, total))
    }

    /// Lists indexed transaction identities newest-first. `account = None`
    /// yields the network-wide feed; an address yields its complete indexed
    /// history. The returned total is computed before pagination.
    pub fn list_explorer_transactions(
        &self,
        account: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<(Vec<ExplorerTransactionRecord>, usize)> {
        let offset = i64::try_from(offset)?;
        let limit = i64::try_from(limit)?;
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let (where_sql, account_param) =
            if account.is_some() { (" WHERE account = ?1", account) } else { ("", None) };
        let total: usize = if let Some(account) = account_param {
            conn.query_row(
                "SELECT COUNT(*) FROM explorer_transactions WHERE account = ?1",
                params![account],
                |row| row.get::<_, i64>(0),
            )? as usize
        } else {
            conn.query_row("SELECT COUNT(*) FROM explorer_transactions", [], |row| {
                row.get::<_, i64>(0)
            })? as usize
        };
        // Sorted on the transaction's own columns (matching
        // `idx_explorer_transactions_order` exactly for the network-wide
        // feed, and the `account` index's `seqno DESC` prefix for account
        // history) rather than the joined block's `gen_utime`, which no index
        // can serve. Observable ordering difference versus the older
        // gen_utime sort: same-seqno blocks in different shards group by
        // seqno instead of block time, and a transaction whose block row is
        // missing sorts by its own seqno instead of being forced last.
        let sql = format!(
            "SELECT t.hash, t.account, t.lt, t.workchain, t.shard, t.seqno,
                    COALESCE(b.gen_utime, 0), t.indexed_at, t.fee, t.in_msg_hash
             FROM explorer_transactions t
             LEFT JOIN explorer_blocks b
               ON b.workchain = t.workchain AND b.shard = t.shard AND b.seqno = t.seqno{where_sql}
             ORDER BY t.seqno DESC, length(t.lt) DESC, t.lt DESC, t.hash
             LIMIT ?{} OFFSET ?{}",
            if account.is_some() { 2 } else { 1 },
            if account.is_some() { 3 } else { 2 },
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = if let Some(account) = account {
            stmt.query_map(params![account, limit, offset], row_to_explorer_transaction)?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            stmt.query_map(params![limit, offset], row_to_explorer_transaction)?
                .collect::<Result<Vec<_>, _>>()?
        };
        Ok((rows, total))
    }

    /// Lists transaction identities belonging to one exact block. Logical
    /// times are decimal strings in SQLite so ordering uses length first to
    /// preserve unsigned 64-bit numeric order without integer overflow.
    pub fn list_explorer_block_transactions(
        &self,
        workchain: i32,
        shard: i64,
        seqno: u32,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<(Vec<ExplorerTransactionRecord>, usize)> {
        let offset = i64::try_from(offset)?;
        let limit = i64::try_from(limit)?;
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let total = conn.query_row(
            "SELECT COUNT(*) FROM explorer_transactions
             WHERE workchain = ?1 AND shard = ?2 AND seqno = ?3",
            params![workchain, shard, seqno],
            |row| row.get::<_, i64>(0),
        )? as usize;
        let mut stmt = conn.prepare(
            "SELECT t.hash, t.account, t.lt, t.workchain, t.shard, t.seqno,
                    COALESCE(b.gen_utime, 0), t.indexed_at, t.fee, t.in_msg_hash
             FROM explorer_transactions t
             LEFT JOIN explorer_blocks b
               ON b.workchain = t.workchain AND b.shard = t.shard AND b.seqno = t.seqno
             WHERE t.workchain = ?1 AND t.shard = ?2 AND t.seqno = ?3
             ORDER BY length(t.lt) DESC, t.lt DESC, t.hash
             LIMIT ?4 OFFSET ?5",
        )?;
        let rows = stmt
            .query_map(
                params![workchain, shard, seqno, limit, offset],
                row_to_explorer_transaction,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok((rows, total))
    }

    pub fn explorer_stats(&self) -> anyhow::Result<ExplorerIndexStats> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let blocks = conn
            .query_row("SELECT COUNT(*) FROM explorer_blocks", [], |row| row.get::<_, i64>(0))?
            as usize;
        let transactions =
            conn.query_row("SELECT COUNT(*) FROM explorer_transactions", [], |row| {
                row.get::<_, i64>(0)
            })? as usize;
        let contracts = conn.query_row(
            "SELECT COUNT(*) FROM indexed_contracts WHERE kind != 'unclassified'",
            [],
            |row| row.get::<_, i64>(0),
        )? as usize;
        let latest_indexed_at: Option<i64> =
            conn.query_row("SELECT MAX(indexed_at) FROM explorer_blocks", [], |row| row.get(0))?;
        Ok(ExplorerIndexStats {
            blocks,
            transactions,
            contracts,
            latest_indexed_at: latest_indexed_at.map(|value| value as u64),
        })
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
        let offset = i64::try_from(offset)?;
        let limit = i64::try_from(limit)?;
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

        bind.push(Box::new(limit));
        let limit_idx = bind.len();
        bind.push(Box::new(offset));
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

    /// One depositor's standing in one pool, as attributed so far.
    pub fn nominator_ledger_entries(
        &self,
        nominator_address: &str,
    ) -> anyhow::Result<Vec<NominatorLedgerRecord>> {
        let conn = self.conn.lock().expect("indexer store lock poisoned");
        let mut statement = conn.prepare(
            "SELECT pool_address, nominator_address, deposited_total, rewarded_total,
                    unattributed_total, last_amount, last_pending, first_seen_at, updated_at
             FROM nominator_ledger
             WHERE nominator_address = ?1
             ORDER BY pool_address",
        )?;
        let rows = statement.query_map(params![nominator_address], |row| {
            Ok(NominatorLedgerRecord {
                pool_address: row.get(0)?,
                nominator_address: row.get(1)?,
                deposited_total: row.get::<_, i64>(2)? as u64,
                rewarded_total: row.get::<_, i64>(3)? as u64,
                unattributed_total: row.get::<_, i64>(4)? as u64,
                last_amount: row.get::<_, i64>(5)? as u64,
                last_pending: row.get::<_, i64>(6)? as u64,
                first_seen_at: row.get::<_, i64>(7)? as u64,
                updated_at: row.get::<_, i64>(8)? as u64,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Fold one observation of a pool's depositors into the ledger.
    ///
    /// Attribution follows pool.fc's own rules for where a change can come
    /// from: while the pool is idle a deposit lands directly in `amount`;
    /// while it is staked a deposit lands in `pending_deposit`; and a
    /// distribution moves the pending amount plus the round's reward into
    /// `amount` and clears pending. Anything the previous observation cannot
    /// account for is recorded as unattributed instead of being called a
    /// reward.
    pub fn observe_nominator_positions(
        &self,
        pool_address: &str,
        pool_state: i32,
        observed_at: u64,
        positions: &[(String, u64, u64)],
    ) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().expect("indexer store lock poisoned");
        let tx = conn.transaction()?;
        for (nominator, amount, pending) in positions {
            let previous: Option<(i64, i64, i64)> = tx
                .query_row(
                    "SELECT last_amount, last_pending, last_pool_state
                     FROM nominator_ledger
                     WHERE pool_address = ?1 AND nominator_address = ?2",
                    params![pool_address, nominator],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;

            let (mut deposited, mut rewarded, mut unattributed) = (0i64, 0i64, 0i64);
            match previous {
                None => {
                    // First sight of this depositor. Everything they hold was
                    // put there before anyone was watching, so it is a
                    // deposit only in the sense that it is not a reward this
                    // ledger observed.
                    deposited = (*amount as i64).saturating_add(*pending as i64);
                }
                Some((last_amount, last_pending, last_state)) => {
                    // Chain-controlled values: keep the delta math saturating
                    // so a hostile or corrupt observation cannot overflow.
                    let amount_delta = (*amount as i64).saturating_sub(last_amount);
                    let pending_delta = (*pending as i64).saturating_sub(last_pending);
                    let distribution_happened = last_state != POOL_STATE_IDLE
                        && i64::from(pool_state) == POOL_STATE_IDLE
                        && *pending == 0;

                    if distribution_happened {
                        // amount grew by the pending deposit plus this
                        // round's share of the reward.
                        let reward = amount_delta.saturating_sub(last_pending);
                        if reward >= 0 {
                            rewarded = reward;
                        } else {
                            // A loss round, or an observation gap that hid a
                            // withdrawal. Either way it is not a reward.
                            unattributed = reward;
                        }
                    } else if pending_delta > 0 {
                        deposited = pending_delta;
                        if amount_delta != 0 {
                            unattributed = amount_delta;
                        }
                    } else if amount_delta > 0 && last_state == POOL_STATE_IDLE {
                        deposited = amount_delta;
                    } else if amount_delta != 0 || pending_delta != 0 {
                        unattributed = amount_delta.saturating_add(pending_delta);
                    }
                }
            }

            tx.execute(
                "INSERT INTO nominator_ledger
                    (pool_address, nominator_address, deposited_total, rewarded_total,
                     unattributed_total, last_amount, last_pending, last_pool_state,
                     first_seen_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
                 ON CONFLICT(pool_address, nominator_address) DO UPDATE SET
                    deposited_total = deposited_total + ?3,
                    rewarded_total = rewarded_total + ?4,
                    unattributed_total = unattributed_total + ?5,
                    last_amount = excluded.last_amount,
                    last_pending = excluded.last_pending,
                    last_pool_state = excluded.last_pool_state,
                    updated_at = excluded.updated_at",
                params![
                    pool_address,
                    nominator,
                    deposited.max(0),
                    rewarded.max(0),
                    unattributed.unsigned_abs() as i64,
                    *amount as i64,
                    *pending as i64,
                    pool_state,
                    observed_at as i64,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
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
    ) -> anyhow::Result<(Option<u64>, u64, Vec<ServiceRequestRecord>)> {
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
        let max_row_id = rows.iter().map(|r| r.request_id).max();
        drop(stmt);
        drop(conn);
        let scan_high_water = self.service_scan_high_water(service_address)?;
        let max_id = match (max_row_id, scan_high_water) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        let stored = rows.len() as u64;
        let active = rows
            .into_iter()
            .filter(|r| matches!(r.status.as_str(), "pending" | "refundable"))
            .collect();
        Ok((max_id, stored, active))
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

fn row_to_explorer_block(row: &rusqlite::Row<'_>) -> rusqlite::Result<ExplorerBlockRecord> {
    Ok(ExplorerBlockRecord {
        workchain: row.get(0)?,
        shard: row.get(1)?,
        seqno: row.get(2)?,
        root_hash: row.get(3)?,
        file_hash: row.get(4)?,
        gen_utime: row.get(5)?,
        tx_count: row.get::<_, i64>(6)? as usize,
        indexed_at: row.get::<_, i64>(7)? as u64,
        observed_mc_seqno: row.get(8)?,
    })
}

fn row_to_explorer_transaction(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ExplorerTransactionRecord> {
    let raw_lt: String = row.get(2)?;
    let lt = raw_lt.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(ExplorerTransactionRecord {
        hash: row.get(0)?,
        account: row.get(1)?,
        lt,
        workchain: row.get(3)?,
        shard: row.get(4)?,
        seqno: row.get(5)?,
        gen_utime: row.get(6)?,
        fee: row.get(8)?,
        in_msg_hash: row.get(9)?,
        indexed_at: row.get::<_, i64>(7)? as u64,
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
    fn dns_checkpoint_migration_discards_height_only_history() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE dns_domain_history (
                address TEXT NOT NULL, account_seqno INTEGER NOT NULL,
                observed_mc_seqno INTEGER NOT NULL, observed_at INTEGER NOT NULL,
                dto_json TEXT NOT NULL, PRIMARY KEY(address, observed_mc_seqno)
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO dns_domain_history
             (address,account_seqno,observed_mc_seqno,observed_at,dto_json)
             VALUES('0:old',1,7,8,'{}')",
            [],
        )
        .unwrap();
        migrate_dns_checkpoint_hashes(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM dns_domain_history", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let columns = conn
            .prepare("PRAGMA table_info(dns_domain_history)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(columns.iter().any(|name| name == "root_hash"));
        assert!(columns.iter().any(|name| name == "file_hash"));
    }

    #[test]
    fn ordering_index_migration_applies_from_the_previous_version() {
        let conn = Connection::open_in_memory().unwrap();
        IndexerStore::init_schema(&conn).unwrap();
        // Simulate a database written at the previous schema version, before
        // the ordering indexes existed.
        conn.execute_batch(
            "DROP INDEX IF EXISTS idx_explorer_blocks_gen_utime;
             DROP INDEX IF EXISTS idx_explorer_transactions_order;",
        )
        .unwrap();
        conn.execute("INSERT INTO indexer_meta (key, value) VALUES ('schema_version', '8')", [])
            .unwrap();

        IndexerStore::ensure_schema_version(&conn).unwrap();

        let version: String = conn
            .query_row("SELECT value FROM indexer_meta WHERE key = 'schema_version'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION.to_string());
        for index in ["idx_explorer_blocks_gen_utime", "idx_explorer_transactions_order"] {
            let found: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                    params![index],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(found, 1, "migration must create {index}");
        }
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

    fn explorer_block(seqno: u32) -> ExplorerBlockRecord {
        ExplorerBlockRecord {
            workchain: -1,
            shard: i64::MIN,
            seqno,
            root_hash: format!("root-{seqno}"),
            file_hash: format!("file-{seqno}"),
            gen_utime: 1_700_000_000 + seqno,
            tx_count: 1,
            indexed_at: 1_000 + u64::from(seqno),
            observed_mc_seqno: seqno,
        }
    }

    fn explorer_transaction(
        hash: &str,
        account: &str,
        lt: u64,
        seqno: u32,
    ) -> ExplorerTransactionRecord {
        ExplorerTransactionRecord {
            hash: hash.to_owned(),
            account: account.to_owned(),
            lt,
            workchain: -1,
            shard: i64::MIN,
            seqno,
            gen_utime: 1_700_000_000 + seqno,
            fee: Some("1000".to_owned()),
            in_msg_hash: Some(format!("msg-{hash}")),
            indexed_at: 1_000 + u64::from(seqno),
        }
    }

    #[test]
    fn explorer_index_resolves_hashes_and_preserves_full_u64_logical_time() {
        let store = IndexerStore::open_in_memory().unwrap();
        let block = explorer_block(7);
        let transaction = explorer_transaction("tx-seven", "-1:account", u64::MAX, 7);
        store.index_explorer_block(&block, std::slice::from_ref(&transaction)).unwrap();

        assert_eq!(store.explorer_block_by_hash("root-7").unwrap(), Some(block.clone()));
        assert_eq!(store.explorer_block_by_hash("file-7").unwrap(), Some(block));
        assert_eq!(store.explorer_transaction("tx-seven").unwrap(), Some(transaction));
        assert_eq!(
            store.explorer_stats().unwrap(),
            ExplorerIndexStats {
                blocks: 1,
                transactions: 1,
                contracts: 0,
                latest_indexed_at: Some(1_007),
            }
        );
    }

    #[test]
    fn dns_history_is_checkpoint_bound_and_removed_by_reorg_reset() {
        let store = IndexerStore::open_in_memory().expect("store");
        assert!(
            store
                .record_dns_domain_history(&DnsDomainHistoryRecord {
                    address: "0:unbound".to_owned(),
                    account_seqno: 1,
                    observed_mc_seqno: 7,
                    observed_at: 1_700_000_000,
                    dto_json: "{}".to_owned(),
                    root_hash: None,
                    file_hash: None,
                })
                .is_err()
        );
        store
            .index_explorer_block(
                &ExplorerBlockRecord {
                    workchain: -1,
                    shard: i64::MIN,
                    seqno: 7,
                    root_hash: "root-seven".to_owned(),
                    file_hash: "file-seven".to_owned(),
                    gen_utime: 1_700_000_000,
                    tx_count: 0,
                    indexed_at: 1_700_000_001,
                    observed_mc_seqno: 7,
                },
                &[],
            )
            .expect("block");
        store
            .record_dns_domain_history(&DnsDomainHistoryRecord {
                address: "0:domain".to_owned(),
                account_seqno: 3,
                observed_mc_seqno: 7,
                observed_at: 1_700_000_000,
                dto_json: r#"{"name":"alice.tos"}"#.to_owned(),
                root_hash: Some("root-seven".to_owned()),
                file_hash: Some("file-seven".to_owned()),
            })
            .expect("DNS history");
        let rows = store.dns_domain_history(0, "", 10).expect("read DNS history");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].root_hash.as_deref(), Some("root-seven"));
        assert_eq!(rows[0].file_hash.as_deref(), Some("file-seven"));
        store.reset_canonical_index().expect("reorg reset");
        assert!(store.dns_domain_history(0, "", 10).expect("history after reset").is_empty());
    }

    #[test]
    fn replacing_a_block_removes_retired_transactions_and_preserves_rich_fields() {
        let store = IndexerStore::open_in_memory().unwrap();
        let original = explorer_transaction("tx-retired", "-1:alice", 10, 7);
        store.index_explorer_block(&explorer_block(7), &[original]).unwrap();

        let mut replacement_block = explorer_block(7);
        replacement_block.root_hash = "root-7-reorganized".into();
        replacement_block.observed_mc_seqno = 9;
        let mut replacement = explorer_transaction("tx-canonical", "-1:bob", 11, 7);
        replacement.fee = Some("424242".into());
        replacement.in_msg_hash = Some("message-canonical".into());
        store.index_explorer_block(&replacement_block, std::slice::from_ref(&replacement)).unwrap();

        assert_eq!(store.explorer_transaction("tx-retired").unwrap(), None);
        assert_eq!(store.explorer_transaction("tx-canonical").unwrap(), Some(replacement));
        assert_eq!(
            store.explorer_block_by_hash("root-7-reorganized").unwrap(),
            Some(replacement_block)
        );
        assert_eq!(store.explorer_stats().unwrap().transactions, 1);
    }

    #[test]
    fn explorer_transaction_lists_are_newest_first_filtered_and_paginated() {
        let store = IndexerStore::open_in_memory().unwrap();
        store
            .index_explorer_block(
                &explorer_block(1),
                &[explorer_transaction("tx-a", "-1:alice", 10, 1)],
            )
            .unwrap();
        store
            .index_explorer_block(
                &explorer_block(2),
                &[
                    explorer_transaction("tx-b", "-1:bob", 20, 2),
                    explorer_transaction("tx-c", "-1:alice", 30, 2),
                ],
            )
            .unwrap();

        let (all, total) = store.list_explorer_transactions(None, 0, 2).unwrap();
        assert_eq!(total, 3);
        assert_eq!(
            all.iter().map(|row| row.hash.as_str()).collect::<Vec<_>>(),
            vec!["tx-c", "tx-b"]
        );
        let (alice, alice_total) =
            store.list_explorer_transactions(Some("-1:alice"), 0, 10).unwrap();
        assert_eq!(alice_total, 2);
        assert_eq!(
            alice.iter().map(|row| row.hash.as_str()).collect::<Vec<_>>(),
            vec!["tx-c", "tx-a"]
        );

        let (blocks, block_total) = store.list_explorer_blocks(0, 1).unwrap();
        assert_eq!(block_total, 2);
        assert_eq!(blocks[0].seqno, 2);
        assert_eq!(blocks[0].tx_count, 2);

        let (block_transactions, block_transaction_total) =
            store.list_explorer_block_transactions(-1, i64::MIN, 2, 0, 10).unwrap();
        assert_eq!(block_transaction_total, 2);
        assert_eq!(block_transactions.iter().map(|row| row.lt).collect::<Vec<_>>(), vec![30, 20]);
    }

    #[test]
    fn explorer_rewind_removes_only_the_reorganized_suffix() {
        let store = IndexerStore::open_in_memory().unwrap();
        for seqno in 1..=3 {
            store
                .index_explorer_block(
                    &explorer_block(seqno),
                    &[explorer_transaction(
                        &format!("tx-{seqno}"),
                        "-1:account",
                        u64::from(seqno),
                        seqno,
                    )],
                )
                .unwrap();
        }
        store.rewind_explorer(-1, i64::MIN, 2).unwrap();

        assert!(store.explorer_block_by_hash("root-1").unwrap().is_some());
        assert!(store.explorer_transaction("tx-1").unwrap().is_some());
        assert!(store.explorer_block_by_hash("root-2").unwrap().is_none());
        assert!(store.explorer_transaction("tx-3").unwrap().is_none());
        assert_eq!(store.explorer_stats().unwrap().blocks, 1);
    }
}

#[cfg(test)]
mod nominator_ledger_tests {
    use super::IndexerStore;

    const POOL: &str = "-1:aaaa";
    const ALICE: &str = "0:1111";
    const IDLE: i32 = 0;
    const STAKED: i32 = 2;

    fn only(store: &IndexerStore, who: &str) -> super::NominatorLedgerRecord {
        let mut rows = store.nominator_ledger_entries(who).unwrap();
        assert_eq!(rows.len(), 1, "expected one position for {who}");
        rows.remove(0)
    }

    #[test]
    fn a_first_sighting_is_not_treated_as_earnings() {
        // Whatever a depositor already holds when the indexer first sees them
        // was put there before anyone was watching. Calling it a reward would
        // invent profit out of a cold start.
        let store = IndexerStore::open_in_memory().unwrap();
        store.observe_nominator_positions(POOL, IDLE, 100, &[(ALICE.into(), 2_000, 0)]).unwrap();

        let entry = only(&store, ALICE);
        assert_eq!(entry.deposited_total, 2_000);
        assert_eq!(entry.rewarded_total, 0);
        assert_eq!(entry.unattributed_total, 0);
    }

    #[test]
    fn a_deposit_while_idle_lands_in_the_principal() {
        let store = IndexerStore::open_in_memory().unwrap();
        store.observe_nominator_positions(POOL, IDLE, 100, &[(ALICE.into(), 2_000, 0)]).unwrap();
        store.observe_nominator_positions(POOL, IDLE, 200, &[(ALICE.into(), 3_500, 0)]).unwrap();

        let entry = only(&store, ALICE);
        assert_eq!(entry.deposited_total, 3_500, "2000 seen plus 1500 deposited");
        assert_eq!(entry.rewarded_total, 0);
    }

    #[test]
    fn a_deposit_while_staked_lands_in_pending() {
        let store = IndexerStore::open_in_memory().unwrap();
        store.observe_nominator_positions(POOL, STAKED, 100, &[(ALICE.into(), 2_000, 0)]).unwrap();
        store
            .observe_nominator_positions(POOL, STAKED, 200, &[(ALICE.into(), 2_000, 500)])
            .unwrap();

        let entry = only(&store, ALICE);
        assert_eq!(entry.deposited_total, 2_500);
        assert_eq!(entry.rewarded_total, 0);
    }

    #[test]
    fn a_distribution_separates_the_reward_from_the_pending_deposit() {
        // pool.fc folds pending into the principal and adds the round's share
        // in the same step, so the reward is the growth beyond what was
        // already pending -- not the whole delta.
        let store = IndexerStore::open_in_memory().unwrap();
        store
            .observe_nominator_positions(POOL, STAKED, 100, &[(ALICE.into(), 2_000, 500)])
            .unwrap();
        store.observe_nominator_positions(POOL, IDLE, 200, &[(ALICE.into(), 2_600, 0)]).unwrap();

        let entry = only(&store, ALICE);
        assert_eq!(entry.rewarded_total, 100, "2600 - 2000 - 500 pending");
        assert_eq!(entry.deposited_total, 2_500, "2000 seen plus 500 pending");
        assert_eq!(entry.unattributed_total, 0);
    }

    #[test]
    fn a_losing_round_is_not_recorded_as_a_reward() {
        let store = IndexerStore::open_in_memory().unwrap();
        store.observe_nominator_positions(POOL, STAKED, 100, &[(ALICE.into(), 2_000, 0)]).unwrap();
        store.observe_nominator_positions(POOL, IDLE, 200, &[(ALICE.into(), 1_800, 0)]).unwrap();

        let entry = only(&store, ALICE);
        assert_eq!(entry.rewarded_total, 0);
        assert_eq!(entry.unattributed_total, 200, "the shortfall is stated, not hidden");
    }

    #[test]
    fn a_change_no_previous_observation_explains_is_kept_apart() {
        // The principal shrank while the pool was idle, which no rule accounts
        // for -- an unobserved withdrawal and redeposit, most likely. It must
        // not quietly reduce or inflate the earnings figure.
        let store = IndexerStore::open_in_memory().unwrap();
        store.observe_nominator_positions(POOL, IDLE, 100, &[(ALICE.into(), 2_000, 0)]).unwrap();
        store.observe_nominator_positions(POOL, IDLE, 200, &[(ALICE.into(), 1_500, 0)]).unwrap();

        let entry = only(&store, ALICE);
        assert_eq!(entry.rewarded_total, 0);
        assert_eq!(entry.deposited_total, 2_000);
        assert_eq!(entry.unattributed_total, 500);
    }

    #[test]
    fn rewards_accumulate_across_rounds() {
        let store = IndexerStore::open_in_memory().unwrap();
        let mut principal = 1_000u64;
        store.observe_nominator_positions(POOL, IDLE, 0, &[(ALICE.into(), principal, 0)]).unwrap();
        for round in 1..=3u64 {
            store
                .observe_nominator_positions(
                    POOL,
                    STAKED,
                    round * 10,
                    &[(ALICE.into(), principal, 0)],
                )
                .unwrap();
            principal += 50;
            store
                .observe_nominator_positions(
                    POOL,
                    IDLE,
                    round * 10 + 5,
                    &[(ALICE.into(), principal, 0)],
                )
                .unwrap();
        }

        let entry = only(&store, ALICE);
        assert_eq!(entry.rewarded_total, 150);
        assert_eq!(entry.deposited_total, 1_000);
        assert_eq!(entry.unattributed_total, 0);
        assert_eq!(entry.last_amount, 1_150);
    }

    #[test]
    fn positions_are_tracked_per_pool() {
        let store = IndexerStore::open_in_memory().unwrap();
        store.observe_nominator_positions(POOL, IDLE, 100, &[(ALICE.into(), 2_000, 0)]).unwrap();
        store.observe_nominator_positions("-1:bbbb", IDLE, 100, &[(ALICE.into(), 700, 0)]).unwrap();

        let rows = store.nominator_ledger_entries(ALICE).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows.iter().map(|r| r.deposited_total).sum::<u64>(), 2_700);
    }
}
