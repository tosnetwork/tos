/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Canonical provenance for the nominator ledger.
//!
//! The ledger's lifetime totals are only meaningful if every observation
//! that produced them came from the canonical chain, read at an exact
//! masterchain block, starting from genesis. This module keeps the ledger's
//! validity state next to the totals, binds each row to the checkpoint of its
//! last observation, and decides -- in one place -- when the totals may be
//! served at all.

use std::collections::HashSet;

use contracts::MasterchainCheckpoint;
use rusqlite::{Connection, OptionalExtension, params};

use super::{IndexerStore, NominatorLedgerRecord, POOL_STATE_IDLE};

/// Whether the ledger's totals can be trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerStatus {
    /// Replayed from genesis over canonical history and caught up once.
    Valid,
    /// The totals have no canonical provenance; nothing may be served.
    RebuildRequired,
    /// Replaying from genesis; totals are incomplete until caught up.
    Rebuilding,
}

impl LedgerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::RebuildRequired => "rebuild_required",
            Self::Rebuilding => "rebuilding",
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "valid" => Ok(Self::Valid),
            "rebuild_required" => Ok(Self::RebuildRequired),
            "rebuilding" => Ok(Self::Rebuilding),
            other => anyhow::bail!("unknown nominator ledger status {other}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NominatorLedgerState {
    pub status: LedgerStatus,
    /// The published masterchain block every observation up to which the
    /// totals include.
    pub as_of: Option<MasterchainCheckpoint>,
}

/// Whether the ledger may be served, and if not, a stable reason code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerAvailability {
    Available {
        as_of: MasterchainCheckpoint,
        /// The published index had reached the chain tip seen at the last tick.
        caught_up: bool,
    },
    Unavailable {
        code: &'static str,
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct NominatorLedgerReport {
    pub availability: LedgerAvailability,
    pub entries: Vec<NominatorLedgerRecord>,
}

/// Lifetime attribution is complete only for a valid ledger with nothing
/// unexplained and no observation interval that hid more than one change.
pub fn attribution_complete(ledger_valid: bool, record: &NominatorLedgerRecord) -> bool {
    ledger_valid && record.unattributed_total == 0 && record.coverage_gap_count == 0
}

pub(super) const NOMINATOR_LEDGER_STATE_SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS nominator_ledger_state (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        status TEXT NOT NULL CHECK(status IN ('valid', 'rebuild_required', 'rebuilding')),
        as_of_mc_seqno INTEGER,
        as_of_mc_root_hash TEXT,
        as_of_mc_file_hash TEXT
    );
    INSERT OR IGNORE INTO nominator_ledger_state (id, status) VALUES (1, 'rebuild_required');";

/// Columns v11 adds to `nominator_ledger`, for databases created earlier.
const PROVENANCE_COLUMNS: &[(&str, &str)] = &[
    ("last_mc_seqno", "INTEGER"),
    ("last_mc_root_hash", "TEXT"),
    ("last_mc_file_hash", "TEXT"),
    ("coverage_gap_count", "INTEGER NOT NULL DEFAULT 0"),
];

/// v11 ledger migration: a v10 ledger has no canonical provenance, so it is
/// marked for a genesis replay and cannot be served until that completes.
pub(super) fn migrate_nominator_ledger(conn: &Connection) -> rusqlite::Result<()> {
    let names = {
        let mut columns = conn.prepare("PRAGMA table_info(nominator_ledger)")?;
        columns.query_map([], |row| row.get::<_, String>(1))?.collect::<Result<Vec<_>, _>>()?
    };
    for (column, definition) in PROVENANCE_COLUMNS {
        if !names.iter().any(|name| name == column) {
            conn.execute(
                &format!("ALTER TABLE nominator_ledger ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
    }
    conn.execute_batch(NOMINATOR_LEDGER_STATE_SCHEMA)?;
    mark_rebuild_required(conn)?;
    Ok(())
}

/// Totals become unavailable at once; the replay itself happens later.
pub(super) fn mark_rebuild_required(conn: &Connection) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE nominator_ledger_state SET status = 'rebuild_required',
            as_of_mc_seqno = NULL, as_of_mc_root_hash = NULL, as_of_mc_file_hash = NULL
         WHERE id = 1",
        [],
    )
}

fn read_state(conn: &Connection) -> anyhow::Result<NominatorLedgerState> {
    let (status, seqno, root_hash, file_hash): (
        String,
        Option<u32>,
        Option<String>,
        Option<String>,
    ) = conn.query_row(
        "SELECT status, as_of_mc_seqno, as_of_mc_root_hash, as_of_mc_file_hash
             FROM nominator_ledger_state WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let as_of = match (seqno, root_hash, file_hash) {
        (Some(seqno), Some(root_hash), Some(file_hash)) => {
            Some(MasterchainCheckpoint { seqno, root_hash, file_hash })
        }
        _ => None,
    };
    Ok(NominatorLedgerState { status: LedgerStatus::parse(&status)?, as_of })
}

fn stored_amount(value: u64) -> anyhow::Result<i64> {
    i64::try_from(value).map_err(|_| anyhow::anyhow!("amount {value} exceeds the ledger's range"))
}

fn loaded_amount(value: i64) -> anyhow::Result<u64> {
    u64::try_from(value).map_err(|_| anyhow::anyhow!("ledger holds a negative amount {value}"))
}

fn add_total(total: u64, delta: i128) -> anyhow::Result<u64> {
    let delta = u64::try_from(delta)
        .map_err(|_| anyhow::anyhow!("ledger delta {delta} is out of range"))?;
    total.checked_add(delta).ok_or_else(|| anyhow::anyhow!("ledger total overflowed"))
}

/// The attributable deltas of one depositor between two observations,
/// following pool.fc's rules for where a change can come from: while idle a
/// deposit lands in `amount`; while staked it lands in `pending_deposit`; a
/// distribution moves pending plus the round's reward into `amount`.
/// Returns `(deposited, rewarded, unattributed)`, all non-negative.
fn attribute(
    previous: Option<(u64, u64, i64)>,
    amount: u64,
    pending: u64,
    pool_state: i64,
) -> (i128, i128, i128) {
    let Some((last_amount, last_pending, last_state)) = previous else {
        // First sight: everything held was put there before this ledger saw
        // it, so it is a deposit, never a reward.
        return (i128::from(amount) + i128::from(pending), 0, 0);
    };
    let amount_delta = i128::from(amount) - i128::from(last_amount);
    let pending_delta = i128::from(pending) - i128::from(last_pending);
    let distribution_happened =
        last_state != POOL_STATE_IDLE && pool_state == POOL_STATE_IDLE && pending == 0;
    if distribution_happened {
        let reward = amount_delta - i128::from(last_pending);
        if reward >= 0 { (0, reward, 0) } else { (0, 0, -reward) }
    } else if pending_delta > 0 {
        (pending_delta, 0, amount_delta.abs())
    } else if amount_delta > 0 && last_state == POOL_STATE_IDLE {
        (amount_delta, 0, 0)
    } else {
        (0, 0, (amount_delta + pending_delta).abs())
    }
}

impl IndexerStore {
    pub fn nominator_ledger_state(&self) -> anyhow::Result<NominatorLedgerState> {
        let conn = self.lock()?;
        read_state(&conn)
    }

    /// Starts a genesis replay of a ledger marked for rebuild: the old rows,
    /// which have no canonical provenance, are dropped. The canonical index
    /// must itself be at genesis, or the replay would not start there.
    /// Returns whether a rebuild was started.
    pub fn begin_nominator_ledger_rebuild(&self) -> anyhow::Result<bool> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        if read_state(&tx)?.status != LedgerStatus::RebuildRequired {
            return Ok(false);
        }
        anyhow::ensure!(
            super::read_canonical_state(&tx)?.is_none(),
            "a nominator ledger rebuild must replay from genesis"
        );
        tx.execute("DELETE FROM nominator_ledger", [])?;
        tx.execute(
            "UPDATE nominator_ledger_state SET status = 'rebuilding',
                as_of_mc_seqno = NULL, as_of_mc_root_hash = NULL, as_of_mc_file_hash = NULL
             WHERE id = 1",
            [],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Folds one checkpoint-pinned pool snapshot into the ledger.
    ///
    /// `touch_count` is how many transactions touched the pool since its
    /// previous observation. With more than one, a single end-of-interval
    /// snapshot cannot attribute each change, so the interval is recorded as
    /// a coverage gap instead of being silently explained. Nominators that
    /// left the pool's dictionary are zeroed with their lifetime totals kept,
    /// so a later deposit is measured from zero.
    pub fn observe_nominator_snapshot(
        &self,
        pool_address: &str,
        pool_state: i32,
        observed_at: u64,
        positions: &[(String, u64, u64)],
        checkpoint: &MasterchainCheckpoint,
        touch_count: u32,
    ) -> anyhow::Result<()> {
        let pool_state = i64::from(pool_state);
        let observed_at = stored_amount(observed_at)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        anyhow::ensure!(
            read_state(&tx)?.status != LedgerStatus::RebuildRequired,
            "the nominator ledger must be rebuilt before it accepts observations"
        );
        let published = super::read_canonical_state(&tx)?
            .ok_or_else(|| anyhow::anyhow!("ledger observations need a published checkpoint"))?;
        anyhow::ensure!(
            checkpoint.seqno < published.seqno || *checkpoint == published,
            "pool snapshot at masterchain {} is not a published checkpoint",
            checkpoint.seqno
        );
        let latest: Option<u32> = tx.query_row(
            "SELECT MAX(last_mc_seqno) FROM nominator_ledger WHERE pool_address = ?1",
            params![pool_address],
            |row| row.get(0),
        )?;
        if latest.is_some_and(|latest| latest >= checkpoint.seqno) {
            // Already folded in (a retry after an interrupted refresh).
            return Ok(());
        }
        let coverage_gap = touch_count > 1;
        let gap_increment = u64::from(coverage_gap);

        let mut seen = HashSet::new();
        for (nominator, amount, pending) in positions {
            anyhow::ensure!(seen.insert(nominator.as_str()), "snapshot lists {nominator} twice");
            let previous: Option<(i64, i64, i64, i64, i64, i64, i64)> = tx
                .query_row(
                    "SELECT last_amount, last_pending, last_pool_state, deposited_total,
                            rewarded_total, unattributed_total, coverage_gap_count
                     FROM nominator_ledger WHERE pool_address = ?1 AND nominator_address = ?2",
                    params![pool_address, nominator],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .optional()?;
            let (last, totals) = match previous {
                Some((amount, pending, state, deposited, rewarded, unattributed, gaps)) => (
                    Some((loaded_amount(amount)?, loaded_amount(pending)?, state)),
                    (
                        loaded_amount(deposited)?,
                        loaded_amount(rewarded)?,
                        loaded_amount(unattributed)?,
                        loaded_amount(gaps)?,
                    ),
                ),
                None => (None, (0, 0, 0, 0)),
            };
            let (deposited, rewarded, unattributed) =
                attribute(last, *amount, *pending, pool_state);
            let deposited_total = add_total(totals.0, deposited)?;
            let rewarded_total = add_total(totals.1, rewarded)?;
            let unattributed_total = add_total(totals.2, unattributed)?;
            let gap_total = totals
                .3
                .checked_add(gap_increment)
                .ok_or_else(|| anyhow::anyhow!("coverage gap counter overflowed"))?;
            tx.execute(
                "INSERT INTO nominator_ledger
                    (pool_address, nominator_address, deposited_total, rewarded_total,
                     unattributed_total, last_amount, last_pending, last_pool_state,
                     first_seen_at, updated_at, last_mc_seqno, last_mc_root_hash,
                     last_mc_file_hash, coverage_gap_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(pool_address, nominator_address) DO UPDATE SET
                    deposited_total = excluded.deposited_total,
                    rewarded_total = excluded.rewarded_total,
                    unattributed_total = excluded.unattributed_total,
                    last_amount = excluded.last_amount,
                    last_pending = excluded.last_pending,
                    last_pool_state = excluded.last_pool_state,
                    updated_at = excluded.updated_at,
                    last_mc_seqno = excluded.last_mc_seqno,
                    last_mc_root_hash = excluded.last_mc_root_hash,
                    last_mc_file_hash = excluded.last_mc_file_hash,
                    coverage_gap_count = excluded.coverage_gap_count",
                params![
                    pool_address,
                    nominator,
                    stored_amount(deposited_total)?,
                    stored_amount(rewarded_total)?,
                    stored_amount(unattributed_total)?,
                    stored_amount(*amount)?,
                    stored_amount(*pending)?,
                    pool_state,
                    observed_at,
                    checkpoint.seqno,
                    checkpoint.root_hash,
                    checkpoint.file_hash,
                    stored_amount(gap_total)?,
                ],
            )?;
        }

        // Depositors absent from the snapshot have left the pool: zero what
        // they hold now, keep what they put in and earned.
        let absent: Vec<String> = {
            let mut statement = tx.prepare(
                "SELECT nominator_address FROM nominator_ledger WHERE pool_address = ?1",
            )?;
            let rows = statement.query_map(params![pool_address], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|nominator| !seen.contains(nominator.as_str()))
                .collect()
        };
        for nominator in absent {
            tx.execute(
                "UPDATE nominator_ledger SET last_amount = 0, last_pending = 0,
                    last_pool_state = ?3, updated_at = ?4, last_mc_seqno = ?5,
                    last_mc_root_hash = ?6, last_mc_file_hash = ?7,
                    coverage_gap_count = coverage_gap_count + ?8
                 WHERE pool_address = ?1 AND nominator_address = ?2",
                params![
                    pool_address,
                    nominator,
                    pool_state,
                    observed_at,
                    checkpoint.seqno,
                    checkpoint.root_hash,
                    checkpoint.file_hash,
                    stored_amount(gap_increment)?,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Advances the ledger's `as_of` to the published checkpoint once no
    /// published touch that could affect a pool is still waiting to be
    /// refreshed, and marks a rebuilding ledger valid once that happens with
    /// the index caught up to the chain tip. Returns the resulting state.
    pub fn settle_nominator_ledger(&self) -> anyhow::Result<NominatorLedgerState> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let state = read_state(&tx)?;
        let Some(published) = super::read_canonical_state(&tx)? else {
            return Ok(state);
        };
        if state.status == LedgerStatus::RebuildRequired {
            return Ok(state);
        }
        let blocking: i64 = tx.query_row(
            "SELECT COUNT(*) FROM indexer_address_refresh r
             LEFT JOIN indexed_contracts c ON c.address = r.address
             WHERE c.kind IS NULL OR c.kind IN ('unclassified', 'contract.pool.nominator')",
            [],
            |row| row.get(0),
        )?;
        if blocking > 0 {
            return Ok(state);
        }
        tx.execute(
            "UPDATE nominator_ledger_state SET as_of_mc_seqno = ?1, as_of_mc_root_hash = ?2,
                as_of_mc_file_hash = ?3 WHERE id = 1",
            params![published.seqno, published.root_hash, published.file_hash],
        )?;
        let tip = super::canonical::read_remote_mc_tip(&tx)?;
        if state.status == LedgerStatus::Rebuilding && tip.is_some_and(|tip| published.seqno >= tip)
        {
            tx.execute("UPDATE nominator_ledger_state SET status = 'valid' WHERE id = 1", [])?;
        }
        let settled = read_state(&tx)?;
        tx.commit()?;
        Ok(settled)
    }

    /// One depositor's positions together with whether they may be served.
    pub fn nominator_ledger_report(
        &self,
        nominator_address: &str,
    ) -> anyhow::Result<NominatorLedgerReport> {
        let conn = self.lock()?;
        let state = read_state(&conn)?;
        let published = super::read_canonical_state(&conn)?;
        let tip = super::canonical::read_remote_mc_tip(&conn)?;
        let entries = super::read_ledger_entries(&conn, nominator_address)?;
        let availability = match (state.status, state.as_of, published) {
            (LedgerStatus::RebuildRequired, _, _) => LedgerAvailability::Unavailable {
                code: "nominator_ledger_rebuild_required",
                reason: "the nominator ledger lacks canonical provenance and awaits a replay"
                    .to_owned(),
            },
            (LedgerStatus::Rebuilding, _, _) => LedgerAvailability::Unavailable {
                code: "nominator_ledger_rebuilding",
                reason: "the nominator ledger is replaying canonical history from genesis"
                    .to_owned(),
            },
            (LedgerStatus::Valid, Some(as_of), Some(published)) if as_of == published => {
                if entries
                    .iter()
                    .any(|entry| entry.last_mc_seqno.is_none_or(|seqno| seqno > published.seqno))
                {
                    LedgerAvailability::Unavailable {
                        code: "nominator_ledger_not_canonical",
                        reason: "a ledger row is not bound to published history".to_owned(),
                    }
                } else if tip.is_some_and(|tip| published.seqno >= tip) {
                    LedgerAvailability::Available { caught_up: true, as_of }
                } else {
                    // Clients may ignore freshness fields, so amounts from an index
                    // that trails the chain are never served as a success.
                    LedgerAvailability::Unavailable {
                        code: "nominator_ledger_behind_chain",
                        reason: format!(
                            "the index has published masterchain {} and the chain is further ahead",
                            published.seqno
                        ),
                    }
                }
            }
            (LedgerStatus::Valid, Some(as_of), Some(published))
                if as_of.seqno < published.seqno =>
            {
                LedgerAvailability::Unavailable {
                    code: "nominator_ledger_behind_index",
                    reason: format!(
                        "pool observations up to masterchain {} are still being folded in",
                        published.seqno
                    ),
                }
            }
            (LedgerStatus::Valid, _, _) => LedgerAvailability::Unavailable {
                code: "nominator_ledger_not_canonical",
                reason: "the ledger anchor is not the published canonical checkpoint".to_owned(),
            },
        };
        Ok(NominatorLedgerReport { availability, entries })
    }

    /// Forces a state, for tests that exercise serving rules directly.
    #[cfg(test)]
    pub(crate) fn set_nominator_ledger_state_for_tests(
        &self,
        status: LedgerStatus,
        as_of: Option<&MasterchainCheckpoint>,
    ) -> anyhow::Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE nominator_ledger_state SET status = ?1, as_of_mc_seqno = ?2,
                as_of_mc_root_hash = ?3, as_of_mc_file_hash = ?4 WHERE id = 1",
            params![
                status.as_str(),
                as_of.map(|c| c.seqno),
                as_of.map(|c| c.root_hash.clone()),
                as_of.map(|c| c.file_hash.clone())
            ],
        )?;
        Ok(())
    }
}
