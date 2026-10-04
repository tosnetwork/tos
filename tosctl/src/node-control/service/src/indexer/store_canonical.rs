/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Durable canonical-traversal state for the explorer indexer.
//!
//! One masterchain height is assembled as a *batch* anchored to its full
//! block identity. The batch walks proof-derived parent edges back from the
//! shard heads the masterchain block references until every branch reaches
//! the previous height's exact shard heads (the *frontier*) or a zerostate.
//! Every step is one SQLite transaction, so a crash at any point resumes the
//! same batch without skipping a parent or scanning a descendant before its
//! ancestors. Rows written by a batch are hidden behind the published
//! watermark until the whole height is published in one transaction.

use contracts::MasterchainCheckpoint;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{BlockFullId, ExplorerBlockRecord, ExplorerTransactionRecord, IndexerStore};

/// Where a pending masterchain batch stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchPhase {
    /// The masterchain block itself has not been scanned yet.
    ScanMaster,
    /// The shard heads referenced by the masterchain block are not recorded yet.
    SeedShards,
    /// Shard ancestry is being expanded and scanned.
    Traverse,
}

impl BatchPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::ScanMaster => "scan_master",
            Self::SeedShards => "seed_shards",
            Self::Traverse => "traverse",
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "scan_master" => Ok(Self::ScanMaster),
            "seed_shards" => Ok(Self::SeedShards),
            "traverse" => Ok(Self::Traverse),
            other => anyhow::bail!("unknown pending batch phase {other}"),
        }
    }
}

/// The single masterchain height currently being assembled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingBatch {
    pub anchor: MasterchainCheckpoint,
    pub phase: BatchPhase,
}

/// The next unit of shard-ancestry work in a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShardStep {
    /// Every parent is at the frontier or indexed: scan this exact block.
    Scan(BlockFullId),
    /// Decide whether this block is at the frontier, or fetch its parents.
    Resolve(BlockFullId),
    /// Nothing left: the batch can be published.
    Done,
}

/// Which exact block a scan result belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScannedTarget {
    Master,
    Shard(BlockFullId),
}

/// Transactions an address had in one scanned block. The count, not merely
/// the fact of a touch, is what later tells whether one end-of-interval
/// snapshot can explain everything that happened to the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressTouch {
    pub address: String,
    pub count: u32,
    pub block_seqno: u32,
    pub gen_utime: u32,
}

/// An address touched by published history, waiting to be refreshed at the
/// exact published masterchain block that made it canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressRefresh {
    pub address: String,
    /// Transactions since the address was last successfully refreshed.
    pub touch_count: u32,
    pub last_block_seqno: u32,
    pub last_gen_utime: u32,
    pub checkpoint: MasterchainCheckpoint,
    pub attempts: u32,
}

/// Whether two shard prefixes of the same workchain cover any common range.
pub fn shards_intersect(a: i64, b: i64) -> bool {
    let (a, b) = (a as u64, b as u64);
    let (low_a, low_b) = (a & a.wrapping_neg(), b & b.wrapping_neg());
    if low_a == 0 || low_b == 0 {
        return false;
    }
    let low = low_a.max(low_b);
    // Bits above the coarser shard's tag bit name its prefix.
    let prefix_mask = !((low << 1).wrapping_sub(1));
    (a ^ b) & prefix_mask == 0
}

const WORK_DISCOVERED: &str = "discovered";
const WORK_PARENTS_EXPANDED: &str = "parents_expanded";
const WORK_INDEXED: &str = "indexed";
const WORK_FRONTIER: &str = "frontier";

fn read_batch(conn: &Connection) -> anyhow::Result<Option<PendingBatch>> {
    let row: Option<(u32, String, String, String)> = conn
        .query_row(
            "SELECT mc_seqno, mc_root_hash, mc_file_hash, phase FROM indexer_master_batch
             WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    row.map(|(seqno, root_hash, file_hash, phase)| {
        Ok(PendingBatch {
            anchor: MasterchainCheckpoint { seqno, root_hash, file_hash },
            phase: BatchPhase::parse(&phase)?,
        })
    })
    .transpose()
}

fn require_batch(conn: &Connection, batch_seqno: u32) -> anyhow::Result<PendingBatch> {
    let batch =
        read_batch(conn)?.ok_or_else(|| anyhow::anyhow!("no pending masterchain batch is open"))?;
    anyhow::ensure!(
        batch.anchor.seqno == batch_seqno,
        "pending batch is for masterchain {} not {batch_seqno}",
        batch.anchor.seqno
    );
    Ok(batch)
}

fn set_phase(conn: &Connection, phase: BatchPhase) -> rusqlite::Result<usize> {
    conn.execute("UPDATE indexer_master_batch SET phase = ?1 WHERE id = 1", params![phase.as_str()])
}

fn work_row(
    conn: &Connection,
    batch_seqno: u32,
    workchain: i32,
    shard: i64,
    seqno: u32,
) -> anyhow::Result<Option<(BlockFullId, String, u32)>> {
    conn.query_row(
        "SELECT root_hash, file_hash, state, pending_parents FROM indexer_shard_work
         WHERE batch_mc_seqno = ?1 AND workchain = ?2 AND shard = ?3 AND seqno = ?4",
        params![batch_seqno, workchain, shard, seqno],
        |row| {
            Ok((
                BlockFullId {
                    workchain,
                    shard,
                    seqno,
                    root_hash: row.get(0)?,
                    file_hash: row.get(1)?,
                },
                row.get(2)?,
                row.get(3)?,
            ))
        },
    )
    .optional()
    .map_err(Into::into)
}

/// A settled row (frontier or indexed) no longer blocks its children.
fn release_children(
    tx: &Transaction<'_>,
    batch_seqno: u32,
    id: &BlockFullId,
) -> anyhow::Result<()> {
    tx.execute(
        "UPDATE indexer_shard_work SET pending_parents = pending_parents - 1
         WHERE batch_mc_seqno = ?1 AND pending_parents > 0
           AND (workchain, shard, seqno) IN (
             SELECT e.child_workchain, e.child_shard, e.child_seqno FROM indexer_shard_edge e
             WHERE e.batch_mc_seqno = ?1
               AND e.parent_workchain = ?2 AND e.parent_shard = ?3 AND e.parent_seqno = ?4)",
        params![batch_seqno, id.workchain, id.shard, id.seqno],
    )?;
    Ok(())
}

fn read_frontier(conn: &Connection, workchain: i32) -> anyhow::Result<Vec<BlockFullId>> {
    let mut statement = conn.prepare(
        "SELECT shard, seqno, root_hash, file_hash FROM canonical_shard_frontier
         WHERE workchain = ?1",
    )?;
    let rows = statement.query_map(params![workchain], |row| {
        Ok(BlockFullId {
            workchain,
            shard: row.get(0)?,
            seqno: row.get(1)?,
            root_hash: row.get(2)?,
            file_hash: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Removes every row written by an unpublished batch. Only one batch can be
/// pending, so everything above the published watermark belongs to it.
fn delete_hidden_rows(tx: &Transaction<'_>) -> anyhow::Result<()> {
    let published = super::read_canonical_state(tx)?.map_or(0, |state| state.seqno);
    tx.execute(
        "DELETE FROM explorer_transactions WHERE EXISTS (
            SELECT 1 FROM explorer_blocks b
            WHERE b.workchain = explorer_transactions.workchain
              AND b.shard = explorer_transactions.shard
              AND b.seqno = explorer_transactions.seqno
              AND b.observed_mc_seqno > ?1)",
        params![published],
    )?;
    tx.execute("DELETE FROM explorer_blocks WHERE observed_mc_seqno > ?1", params![published])?;
    Ok(())
}

fn clear_batch_metadata(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute_batch(
        "DELETE FROM indexer_shard_edge;
         DELETE FROM indexer_shard_work;
         DELETE FROM indexer_touched_address;
         DELETE FROM indexer_master_batch;",
    )
}

impl IndexerStore {
    pub fn pending_batch(&self) -> anyhow::Result<Option<PendingBatch>> {
        let conn = self.lock()?;
        read_batch(&conn)
    }

    /// Opens the batch for the next unpublished masterchain height.
    pub fn begin_batch(&self, anchor: &MasterchainCheckpoint) -> anyhow::Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        anyhow::ensure!(read_batch(&tx)?.is_none(), "a masterchain batch is already pending");
        let published = super::read_canonical_state(&tx)?.map_or(0, |state| state.seqno);
        anyhow::ensure!(
            anchor.seqno == published.saturating_add(1),
            "masterchain batch {} does not follow published height {published}",
            anchor.seqno
        );
        // Stale work from an interrupted, already-discarded batch must never
        // be merged into a new one.
        clear_batch_metadata(&tx)?;
        delete_hidden_rows(&tx)?;
        tx.execute(
            "INSERT INTO indexer_master_batch (id, mc_seqno, mc_root_hash, mc_file_hash, phase)
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                anchor.seqno,
                anchor.root_hash,
                anchor.file_hash,
                BatchPhase::ScanMaster.as_str()
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Drops the pending batch and every hidden row it wrote. Used when the
    /// anchor it was built for is no longer the chain's block at that height.
    pub fn discard_pending_batch(&self) -> anyhow::Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        delete_hidden_rows(&tx)?;
        clear_batch_metadata(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// Records the shard heads the batch's masterchain block references.
    pub fn seed_batch_heads(&self, batch_seqno: u32, heads: &[BlockFullId]) -> anyhow::Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let batch = require_batch(&tx, batch_seqno)?;
        anyhow::ensure!(
            batch.phase == BatchPhase::SeedShards,
            "shard heads can only be seeded once, after the masterchain block"
        );
        for (index, head) in heads.iter().enumerate() {
            anyhow::ensure!(head.workchain != -1, "a shard head cannot be a masterchain block");
            anyhow::ensure!(head.shard != 0, "shard head carries an invalid shard prefix");
            for other in &heads[..index] {
                anyhow::ensure!(
                    other.workchain != head.workchain || !shards_intersect(other.shard, head.shard),
                    "masterchain block references overlapping shard heads {}:{} and {}:{}",
                    other.workchain,
                    other.shard,
                    head.workchain,
                    head.shard
                );
            }
            tx.execute(
                "INSERT INTO indexer_shard_work
                    (batch_mc_seqno, workchain, shard, seqno, root_hash, file_hash, state,
                     is_head, pending_parents)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 0)",
                params![
                    batch_seqno,
                    head.workchain,
                    head.shard,
                    head.seqno,
                    head.root_hash,
                    head.file_hash,
                    WORK_DISCOVERED
                ],
            )?;
        }
        set_phase(&tx, BatchPhase::Traverse)?;
        tx.commit()?;
        Ok(())
    }

    /// Chooses the next shard work item: scanning a block whose ancestors
    /// are settled comes first, so descendants never precede ancestors.
    pub fn next_shard_step(&self, batch_seqno: u32) -> anyhow::Result<ShardStep> {
        let conn = self.lock()?;
        require_batch(&conn, batch_seqno)?;
        let pick =
            |state: &str, pending_only: bool, order: &str| -> anyhow::Result<Option<BlockFullId>> {
                let sql = format!(
                    "SELECT workchain, shard, seqno, root_hash, file_hash FROM indexer_shard_work
                 WHERE batch_mc_seqno = ?1 AND state = ?2 {}
                 ORDER BY seqno {order}, workchain, shard LIMIT 1",
                    if pending_only { "AND pending_parents = 0" } else { "" }
                );
                conn.query_row(&sql, params![batch_seqno, state], |row| {
                    Ok(BlockFullId {
                        workchain: row.get(0)?,
                        shard: row.get(1)?,
                        seqno: row.get(2)?,
                        root_hash: row.get(3)?,
                        file_hash: row.get(4)?,
                    })
                })
                .optional()
                .map_err(Into::into)
            };
        if let Some(id) = pick(WORK_PARENTS_EXPANDED, true, "ASC")? {
            return Ok(ShardStep::Scan(id));
        }
        if let Some(id) = pick(WORK_DISCOVERED, false, "DESC")? {
            return Ok(ShardStep::Resolve(id));
        }
        let blocked: i64 = conn.query_row(
            "SELECT COUNT(*) FROM indexer_shard_work WHERE batch_mc_seqno = ?1 AND state = ?2",
            params![batch_seqno, WORK_PARENTS_EXPANDED],
            |row| row.get(0),
        )?;
        anyhow::ensure!(blocked == 0, "{blocked} shard blocks wait on parents that never settle");
        Ok(ShardStep::Done)
    }

    /// Settles a discovered block that needs no scan: an exact match of the
    /// previous height's frontier, or a zerostate below an empty frontier.
    /// Any other block at or below an overlapping frontier entry means the
    /// ancestry disagrees with published history, and is refused.
    pub fn resolve_at_frontier(&self, batch_seqno: u32, id: &BlockFullId) -> anyhow::Result<bool> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        require_batch(&tx, batch_seqno)?;
        let (stored, state, _) = work_row(&tx, batch_seqno, id.workchain, id.shard, id.seqno)?
            .ok_or_else(|| anyhow::anyhow!("shard block {id:?} is not part of the batch"))?;
        anyhow::ensure!(
            stored == *id && state == WORK_DISCOVERED,
            "shard block {id:?} is not open"
        );
        let frontier = read_frontier(&tx, id.workchain)?;
        let exact_frontier = frontier.iter().any(|entry| entry == id);
        if exact_frontier {
            tx.execute(
                "UPDATE indexer_shard_work SET state = ?5
                 WHERE batch_mc_seqno = ?1 AND workchain = ?2 AND shard = ?3 AND seqno = ?4",
                params![batch_seqno, id.workchain, id.shard, id.seqno, WORK_FRONTIER],
            )?;
            release_children(&tx, batch_seqno, id)?;
            tx.commit()?;
            return Ok(true);
        }
        if let Some(entry) = frontier
            .iter()
            .find(|entry| shards_intersect(entry.shard, id.shard) && entry.seqno >= id.seqno)
        {
            if entry.same_coordinate(id) {
                anyhow::bail!(
                    "shard block {}:{}:{} has hash {} but the published frontier holds {}",
                    id.workchain,
                    id.shard,
                    id.seqno,
                    id.root_hash,
                    entry.root_hash
                );
            }
            anyhow::bail!(
                "shard ancestry reached {}:{}:{} without passing the published frontier {}:{}:{}",
                id.workchain,
                id.shard,
                id.seqno,
                entry.workchain,
                entry.shard,
                entry.seqno
            );
        }
        if id.seqno == 0 {
            tx.execute(
                "UPDATE indexer_shard_work SET state = ?5
                 WHERE batch_mc_seqno = ?1 AND workchain = ?2 AND shard = ?3 AND seqno = ?4",
                params![batch_seqno, id.workchain, id.shard, id.seqno, WORK_FRONTIER],
            )?;
            release_children(&tx, batch_seqno, id)?;
            tx.commit()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Durably records a block's proof-derived parents and the edges to
    /// them. A parent already in the batch must carry the same hashes: the
    /// same coordinate with a different hash is conflicting evidence.
    pub fn record_parents(
        &self,
        batch_seqno: u32,
        child: &BlockFullId,
        parents: &[BlockFullId],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !parents.is_empty() && parents.len() <= 2,
            "a shard block has one or two parents, not {}",
            parents.len()
        );
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        require_batch(&tx, batch_seqno)?;
        let (stored, state, _) =
            work_row(&tx, batch_seqno, child.workchain, child.shard, child.seqno)?
                .ok_or_else(|| anyhow::anyhow!("shard block {child:?} is not part of the batch"))?;
        anyhow::ensure!(
            stored == *child && state == WORK_DISCOVERED,
            "shard block {child:?} is not awaiting its parents"
        );
        let mut unsettled = 0u32;
        for parent in parents {
            anyhow::ensure!(
                parent.workchain == child.workchain && parent.seqno < child.seqno,
                "shard block {}:{}:{} names an invalid parent {}:{}:{}",
                child.workchain,
                child.shard,
                child.seqno,
                parent.workchain,
                parent.shard,
                parent.seqno
            );
            match work_row(&tx, batch_seqno, parent.workchain, parent.shard, parent.seqno)? {
                Some((existing, existing_state, _)) => {
                    anyhow::ensure!(
                        existing == *parent,
                        "shard block {}:{}:{} is reported with hash {} and {}",
                        parent.workchain,
                        parent.shard,
                        parent.seqno,
                        existing.root_hash,
                        parent.root_hash
                    );
                    if existing_state != WORK_FRONTIER && existing_state != WORK_INDEXED {
                        unsettled = unsettled.saturating_add(1);
                    }
                }
                None => {
                    tx.execute(
                        "INSERT INTO indexer_shard_work
                            (batch_mc_seqno, workchain, shard, seqno, root_hash, file_hash,
                             state, is_head, pending_parents)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0)",
                        params![
                            batch_seqno,
                            parent.workchain,
                            parent.shard,
                            parent.seqno,
                            parent.root_hash,
                            parent.file_hash,
                            WORK_DISCOVERED
                        ],
                    )?;
                    unsettled = unsettled.saturating_add(1);
                }
            }
            tx.execute(
                "INSERT INTO indexer_shard_edge
                    (batch_mc_seqno, child_workchain, child_shard, child_seqno, child_root_hash,
                     child_file_hash, parent_workchain, parent_shard, parent_seqno,
                     parent_root_hash, parent_file_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    batch_seqno,
                    child.workchain,
                    child.shard,
                    child.seqno,
                    child.root_hash,
                    child.file_hash,
                    parent.workchain,
                    parent.shard,
                    parent.seqno,
                    parent.root_hash,
                    parent.file_hash
                ],
            )?;
        }
        tx.execute(
            "UPDATE indexer_shard_work SET state = ?5, pending_parents = ?6
             WHERE batch_mc_seqno = ?1 AND workchain = ?2 AND shard = ?3 AND seqno = ?4",
            params![
                batch_seqno,
                child.workchain,
                child.shard,
                child.seqno,
                WORK_PARENTS_EXPANDED,
                unsettled
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Atomically stores one scanned block of the pending batch -- its hidden
    /// explorer rows, its per-address touch counts, and the work transition
    /// that says it is done -- so a crash either redoes the whole block or
    /// none of it.
    pub fn commit_scanned_block(
        &self,
        batch_seqno: u32,
        target: &ScannedTarget,
        block: &ExplorerBlockRecord,
        transactions: &[ExplorerTransactionRecord],
        touches: &[AddressTouch],
    ) -> anyhow::Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let batch = require_batch(&tx, batch_seqno)?;
        anyhow::ensure!(
            block.observed_mc_seqno == batch_seqno,
            "a scanned block must be observed at its batch height"
        );
        let scanned = BlockFullId {
            workchain: block.workchain,
            shard: block.shard,
            seqno: block.seqno,
            root_hash: block.root_hash.clone(),
            file_hash: block.file_hash.clone(),
        };
        match target {
            ScannedTarget::Master => {
                anyhow::ensure!(
                    batch.phase == BatchPhase::ScanMaster,
                    "the masterchain block of this batch was already scanned"
                );
                anyhow::ensure!(
                    scanned.workchain == -1
                        && scanned.seqno == batch.anchor.seqno
                        && scanned.root_hash == batch.anchor.root_hash
                        && scanned.file_hash == batch.anchor.file_hash,
                    "scanned masterchain block differs from the batch anchor"
                );
                set_phase(&tx, BatchPhase::SeedShards)?;
            }
            ScannedTarget::Shard(id) => {
                anyhow::ensure!(scanned == *id, "scanned shard block differs from its work item");
                let (stored, state, pending) =
                    work_row(&tx, batch_seqno, id.workchain, id.shard, id.seqno)?
                        .ok_or_else(|| anyhow::anyhow!("shard block {id:?} is not in the batch"))?;
                anyhow::ensure!(
                    stored == *id && state == WORK_PARENTS_EXPANDED && pending == 0,
                    "shard block {id:?} cannot be scanned before its parents settle"
                );
                tx.execute(
                    "UPDATE indexer_shard_work SET state = ?5
                     WHERE batch_mc_seqno = ?1 AND workchain = ?2 AND shard = ?3 AND seqno = ?4",
                    params![batch_seqno, id.workchain, id.shard, id.seqno, WORK_INDEXED],
                )?;
                release_children(&tx, batch_seqno, id)?;
            }
        }
        write_hidden_block(&tx, block, transactions)?;
        for touch in touches {
            tx.execute(
                "INSERT INTO indexer_touched_address
                    (batch_mc_seqno, address, touch_count, last_block_seqno, last_gen_utime)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(batch_mc_seqno, address) DO UPDATE SET
                    touch_count = touch_count + excluded.touch_count,
                    last_block_seqno = MAX(last_block_seqno, excluded.last_block_seqno),
                    last_gen_utime = MAX(last_gen_utime, excluded.last_gen_utime)",
                params![
                    batch_seqno,
                    touch.address,
                    touch.count,
                    touch.block_seqno,
                    touch.gen_utime
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Publishes the pending batch in one transaction: the watermark, the
    /// new frontier, the compatibility checkpoints and the touched-address
    /// hand-off all move together, then the batch's metadata is cleared.
    pub fn publish_batch(
        &self,
        master_shard: i64,
        anchor: &MasterchainCheckpoint,
    ) -> anyhow::Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let batch = require_batch(&tx, anchor.seqno)?;
        anyhow::ensure!(batch.anchor == *anchor, "pending batch anchor changed before publish");
        anyhow::ensure!(batch.phase == BatchPhase::Traverse, "pending batch is not assembled");
        let open: i64 = tx.query_row(
            "SELECT COUNT(*) FROM indexer_shard_work
             WHERE batch_mc_seqno = ?1 AND state NOT IN (?2, ?3)",
            params![anchor.seqno, WORK_FRONTIER, WORK_INDEXED],
            |row| row.get(0),
        )?;
        anyhow::ensure!(open == 0, "{open} shard blocks of the batch are still unsettled");
        let published = super::read_canonical_state(&tx)?.map_or(0, |state| state.seqno);
        anyhow::ensure!(
            anchor.seqno == published.saturating_add(1),
            "masterchain height {} cannot be published after {published}",
            anchor.seqno
        );
        let heads = {
            let mut statement = tx.prepare(
                "SELECT workchain, shard, seqno, root_hash, file_hash FROM indexer_shard_work
                 WHERE batch_mc_seqno = ?1 AND is_head = 1",
            )?;
            let rows = statement.query_map(params![anchor.seqno], |row| {
                Ok(BlockFullId {
                    workchain: row.get(0)?,
                    shard: row.get(1)?,
                    seqno: row.get(2)?,
                    root_hash: row.get(3)?,
                    file_hash: row.get(4)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        super::write_publication(&tx, master_shard, anchor, &heads)?;
        tx.execute("DELETE FROM canonical_shard_frontier", [])?;
        for head in &heads {
            tx.execute(
                "INSERT INTO canonical_shard_frontier
                    (workchain, shard, seqno, root_hash, file_hash, published_mc_seqno)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    head.workchain,
                    head.shard,
                    head.seqno,
                    head.root_hash,
                    head.file_hash,
                    anchor.seqno
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO indexer_address_refresh
                (address, touch_count, last_block_seqno, last_gen_utime,
                 mc_seqno, mc_root_hash, mc_file_hash, attempts)
             SELECT address, touch_count, last_block_seqno, last_gen_utime, ?1, ?2, ?3, 0
             FROM indexer_touched_address WHERE batch_mc_seqno = ?1
             ON CONFLICT(address, mc_seqno) DO UPDATE SET
                touch_count = excluded.touch_count,
                last_block_seqno = excluded.last_block_seqno,
                last_gen_utime = excluded.last_gen_utime,
                mc_root_hash = excluded.mc_root_hash,
                mc_file_hash = excluded.mc_file_hash,
                attempts = 0",
            params![anchor.seqno, anchor.root_hash, anchor.file_hash],
        )?;
        clear_batch_metadata(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// The published shard heads ancestry traversal stops at.
    pub fn canonical_shard_frontier(&self) -> anyhow::Result<Vec<BlockFullId>> {
        let conn = self.lock()?;
        let mut statement = conn.prepare(
            "SELECT workchain, shard, seqno, root_hash, file_hash FROM canonical_shard_frontier
             ORDER BY workchain, shard",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(BlockFullId {
                workchain: row.get(0)?,
                shard: row.get(1)?,
                seqno: row.get(2)?,
                root_hash: row.get(3)?,
                file_hash: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Shard work rows of the pending batch by state, for progress reporting.
    pub fn pending_work_counts(&self) -> anyhow::Result<Vec<(String, u64)>> {
        let conn = self.lock()?;
        let mut statement = conn.prepare(
            "SELECT state, COUNT(*) FROM indexer_shard_work GROUP BY state ORDER BY state",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0)))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Published addresses awaiting a refresh: for each address only its
    /// lowest pending height, since later heights wait for it anyway.
    ///
    /// Rows that have never failed come first, oldest checkpoint first. Rows
    /// that have failed get a fixed share of `limit`, fewest attempts first,
    /// and any room the fresh rows leave. Rows that keep failing therefore
    /// cannot fill the window and stop fresh work behind them, and they are
    /// still retried every pass.
    pub fn address_refresh_queue(&self, limit: usize) -> anyhow::Result<Vec<AddressRefresh>> {
        // A window too small to split leaves failed rows to whatever room
        // fresh rows do not take.
        let retry_share = limit / ADDRESS_REFRESH_RETRY_SHARE_DIVISOR;
        let fresh_limit = limit.saturating_sub(retry_share);
        let conn = self.lock()?;
        let mut queue =
            read_address_refresh_heads(&conn, "attempts = 0", "mc_seqno, address", fresh_limit)?;
        let fresh_read = queue.len();
        queue.extend(read_address_refresh_heads(
            &conn,
            "attempts > 0",
            "attempts, mc_seqno, address",
            limit.saturating_sub(fresh_read),
        )?);
        // Fresh rows the share held back fill whatever the retries left.
        let room = limit.saturating_sub(queue.len());
        if room > 0 && fresh_read == fresh_limit {
            queue.extend(read_address_refresh_heads_after(&conn, fresh_read, room)?);
        }
        Ok(queue)
    }

    /// The lowest queued height of one address, if any: the next height a
    /// drain of that address must observe.
    pub fn next_address_refresh(&self, address: &str) -> anyhow::Result<Option<AddressRefresh>> {
        let conn = self.lock()?;
        let mut statement = conn.prepare(
            "SELECT address, touch_count, last_block_seqno, last_gen_utime,
                    mc_seqno, mc_root_hash, mc_file_hash, attempts
             FROM indexer_address_refresh WHERE address = ?1
             ORDER BY mc_seqno ASC LIMIT 1",
        )?;
        Ok(statement.query_row(params![address], address_refresh_row).optional()?)
    }

    /// The highest queued height of one address, if any.
    pub fn latest_address_refresh(&self, address: &str) -> anyhow::Result<Option<AddressRefresh>> {
        let conn = self.lock()?;
        let mut statement = conn.prepare(
            "SELECT address, touch_count, last_block_seqno, last_gen_utime,
                    mc_seqno, mc_root_hash, mc_file_hash, attempts
             FROM indexer_address_refresh WHERE address = ?1
             ORDER BY mc_seqno DESC LIMIT 1",
        )?;
        Ok(statement.query_row(params![address], address_refresh_row).optional()?)
    }

    /// Removes the queued heights of one address up to and including
    /// `through`: they are covered by a visit at height `through`.
    pub fn complete_address_refresh_through(
        &self,
        address: &str,
        through: u32,
    ) -> anyhow::Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM indexer_address_refresh WHERE address = ?1 AND mc_seqno <= ?2",
            params![address, through],
        )?;
        Ok(())
    }

    /// Removes the refresh row for one address at one published height. Rows
    /// of later heights for the same address stay queued: each published
    /// height is observed at its own checkpoint, never folded into another.
    pub fn complete_address_refresh(&self, refresh: &AddressRefresh) -> anyhow::Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM indexer_address_refresh WHERE address = ?1 AND mc_seqno = ?2",
            params![refresh.address, refresh.checkpoint.seqno],
        )?;
        Ok(())
    }
}

/// One in this many places of a refresh pass is held for rows that failed before.
const ADDRESS_REFRESH_RETRY_SHARE_DIVISOR: usize = 8;

// A row is its address's head when no lower height of the address is
// queued; the primary key answers that per row, so a scan in schedule order
// stops after `limit` heads.
const ADDRESS_REFRESH_HEAD: &str = "SELECT address, touch_count, last_block_seqno, last_gen_utime,
        mc_seqno, mc_root_hash, mc_file_hash, attempts
     FROM indexer_address_refresh AS r INDEXED BY idx_address_refresh_schedule
     WHERE NOT EXISTS (SELECT 1 FROM indexer_address_refresh AS lower
                       WHERE lower.address = r.address AND lower.mc_seqno < r.mc_seqno)";

fn read_address_refresh_heads(
    conn: &Connection,
    filter: &str,
    order: &str,
    limit: usize,
) -> anyhow::Result<Vec<AddressRefresh>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let limit = i64::try_from(limit)?;
    let mut statement =
        conn.prepare(&format!("{ADDRESS_REFRESH_HEAD} AND {filter} ORDER BY {order} LIMIT ?1"))?;
    let rows = statement.query_map(params![limit], address_refresh_row)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Fresh head rows past the first `skip`, in the same order as the first read.
fn read_address_refresh_heads_after(
    conn: &Connection,
    skip: usize,
    limit: usize,
) -> anyhow::Result<Vec<AddressRefresh>> {
    let skip = i64::try_from(skip)?;
    let limit = i64::try_from(limit)?;
    let mut statement = conn.prepare(&format!(
        "{ADDRESS_REFRESH_HEAD} AND attempts = 0 ORDER BY mc_seqno, address LIMIT ?1 OFFSET ?2"
    ))?;
    let rows = statement.query_map(params![limit, skip], address_refresh_row)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn address_refresh_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AddressRefresh> {
    Ok(AddressRefresh {
        address: row.get(0)?,
        touch_count: row.get(1)?,
        last_block_seqno: row.get(2)?,
        last_gen_utime: row.get(3)?,
        checkpoint: MasterchainCheckpoint {
            seqno: row.get(4)?,
            root_hash: row.get(5)?,
            file_hash: row.get(6)?,
        },
        attempts: row.get(7)?,
    })
}

impl IndexerStore {
    /// Queues one refresh row directly, for tests of the queue and its drain.
    #[cfg(test)]
    pub(crate) fn queue_address_refresh_for_test(
        &self,
        address: &str,
        mc_seqno: u32,
        attempts: u32,
    ) -> anyhow::Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO indexer_address_refresh
                (address, touch_count, last_block_seqno, last_gen_utime,
                 mc_seqno, mc_root_hash, mc_file_hash, attempts)
             VALUES (?1, 1, ?2, 1, ?2, ?3, ?4, ?5)",
            params![
                address,
                mc_seqno,
                format!("{mc_seqno:064x}"),
                format!("{:064x}", u64::from(mc_seqno) + 1_000),
                attempts
            ],
        )?;
        Ok(())
    }

    /// Every queued height of one address with its attempts, lowest first,
    /// for tests of the drain.
    #[cfg(test)]
    pub(crate) fn queued_heights_for_test(&self, address: &str) -> anyhow::Result<Vec<(u32, u32)>> {
        let conn = self.lock()?;
        let mut statement = conn.prepare(
            "SELECT mc_seqno, attempts FROM indexer_address_refresh WHERE address = ?1
             ORDER BY mc_seqno",
        )?;
        let rows = statement.query_map(params![address], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Keeps a refresh row for another attempt.
    pub fn defer_address_refresh(&self, refresh: &AddressRefresh) -> anyhow::Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE indexer_address_refresh SET attempts = attempts + 1
             WHERE address = ?1 AND mc_seqno = ?2",
            params![refresh.address, refresh.checkpoint.seqno],
        )?;
        Ok(())
    }

    /// Highest masterchain seqno the chain reported at the last tick.
    pub fn set_remote_mc_tip(&self, seqno: u32) -> anyhow::Result<()> {
        let conn = self.lock()?;
        super::upsert_meta(&conn, "remote_mc_tip", &seqno.to_string())?;
        Ok(())
    }

    pub fn remote_mc_tip(&self) -> anyhow::Result<Option<u32>> {
        let conn = self.lock()?;
        read_remote_mc_tip(&conn)
    }
}

pub(super) fn read_remote_mc_tip(conn: &Connection) -> anyhow::Result<Option<u32>> {
    let value: Option<String> = conn
        .query_row("SELECT value FROM indexer_meta WHERE key = 'remote_mc_tip'", [], |row| {
            row.get(0)
        })
        .optional()?;
    Ok(value.and_then(|value| value.parse().ok()))
}

/// Writes a block of the pending batch. It must never replace a published
/// row: the frontier check keeps traversal above published history, and this
/// refuses outright if that ever fails.
fn write_hidden_block(
    tx: &Transaction<'_>,
    block: &ExplorerBlockRecord,
    transactions: &[ExplorerTransactionRecord],
) -> anyhow::Result<()> {
    let published = super::read_canonical_state(tx)?.map_or(0, |state| state.seqno);
    let existing: Option<u32> = tx
        .query_row(
            "SELECT observed_mc_seqno FROM explorer_blocks
             WHERE workchain = ?1 AND shard = ?2 AND seqno = ?3",
            params![block.workchain, block.shard, block.seqno],
            |row| row.get(0),
        )
        .optional()?;
    anyhow::ensure!(
        existing.is_none_or(|observed| observed > published),
        "pending block {}:{}:{} would replace a published block",
        block.workchain,
        block.shard,
        block.seqno
    );
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
            i64::try_from(block.indexed_at)?,
            block.observed_mc_seqno,
        ],
    )?;
    tx.execute(
        "DELETE FROM explorer_transactions WHERE workchain = ?1 AND shard = ?2 AND seqno = ?3",
        params![block.workchain, block.shard, block.seqno],
    )?;
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
            indexed_at = excluded.indexed_at
         WHERE NOT EXISTS (
            SELECT 1 FROM explorer_blocks b
            WHERE b.workchain = explorer_transactions.workchain
              AND b.shard = explorer_transactions.shard
              AND b.seqno = explorer_transactions.seqno
              AND b.observed_mc_seqno <= ?10)",
    )?;
    for record in transactions {
        let changed = statement.execute(params![
            record.hash,
            record.account,
            record.lt.to_string(),
            record.workchain,
            record.shard,
            record.seqno,
            record.fee,
            record.in_msg_hash,
            i64::try_from(record.indexed_at)?,
            published,
        ])?;
        anyhow::ensure!(
            changed == 1,
            "pending transaction {} would move a published transaction",
            record.hash
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(tag: u32) -> String {
        format!("{tag:064x}")
    }

    fn anchor(seqno: u32) -> MasterchainCheckpoint {
        MasterchainCheckpoint { seqno, root_hash: hash(seqno), file_hash: hash(seqno + 1_000) }
    }

    fn block(workchain: i32, shard: i64, seqno: u32, tag: u32) -> BlockFullId {
        BlockFullId { workchain, shard, seqno, root_hash: hash(tag), file_hash: hash(tag + 7) }
    }

    fn record(id: &BlockFullId, observed_mc_seqno: u32) -> ExplorerBlockRecord {
        ExplorerBlockRecord {
            workchain: id.workchain,
            shard: id.shard,
            seqno: id.seqno,
            root_hash: id.root_hash.clone(),
            file_hash: id.file_hash.clone(),
            gen_utime: 1,
            tx_count: 0,
            indexed_at: 1,
            observed_mc_seqno,
        }
    }

    fn master(seqno: u32) -> BlockFullId {
        BlockFullId {
            workchain: -1,
            shard: i64::MIN,
            seqno,
            root_hash: anchor(seqno).root_hash,
            file_hash: anchor(seqno).file_hash,
        }
    }

    /// Opens a batch and scans its masterchain block, leaving it at SeedShards.
    fn open_batch(store: &IndexerStore, seqno: u32) {
        store.begin_batch(&anchor(seqno)).unwrap();
        store
            .commit_scanned_block(
                seqno,
                &ScannedTarget::Master,
                &record(&master(seqno), seqno),
                &[],
                &[],
            )
            .unwrap();
    }

    fn scan(store: &IndexerStore, batch: u32, id: &BlockFullId) -> anyhow::Result<()> {
        store.commit_scanned_block(
            batch,
            &ScannedTarget::Shard(id.clone()),
            &record(id, batch),
            &[],
            &[],
        )
    }

    #[test]
    fn shard_prefixes_intersect_only_when_one_contains_the_other() {
        let root = i64::MIN;
        let left = 0x4000_0000_0000_0000_i64;
        let right = 0xC000_0000_0000_0000_u64 as i64;
        assert!(shards_intersect(root, left));
        assert!(shards_intersect(right, root));
        assert!(shards_intersect(left, left));
        assert!(!shards_intersect(left, right));
        assert!(!shards_intersect(0, root), "a zero prefix is not a shard");
    }

    #[test]
    fn a_height_is_assembled_and_published_with_its_frontier_in_one_step() {
        let store = IndexerStore::open_in_memory().unwrap();
        assert!(store.begin_batch(&anchor(2)).is_err(), "heights are published in order");
        open_batch(&store, 1);
        let head = block(0, i64::MIN, 2, 20);
        let parent = block(0, i64::MIN, 1, 10);
        let genesis = block(0, i64::MIN, 0, 0);
        store.seed_batch_heads(1, std::slice::from_ref(&head)).unwrap();

        assert_eq!(store.next_shard_step(1).unwrap(), ShardStep::Resolve(head.clone()));
        assert!(!store.resolve_at_frontier(1, &head).unwrap());
        store.record_parents(1, &head, std::slice::from_ref(&parent)).unwrap();
        assert!(
            scan(&store, 1, &head).is_err(),
            "a block is never scanned before its parents settle"
        );
        assert!(
            store.publish_batch(i64::MIN, &anchor(1)).is_err(),
            "unsettled work blocks publish"
        );
        assert_eq!(store.next_shard_step(1).unwrap(), ShardStep::Resolve(parent.clone()));
        assert!(!store.resolve_at_frontier(1, &parent).unwrap());
        store.record_parents(1, &parent, std::slice::from_ref(&genesis)).unwrap();
        assert!(
            store.resolve_at_frontier(1, &genesis).unwrap(),
            "zerostate below an empty frontier"
        );
        assert_eq!(store.next_shard_step(1).unwrap(), ShardStep::Scan(parent.clone()));
        scan(&store, 1, &parent).unwrap();
        assert_eq!(store.next_shard_step(1).unwrap(), ShardStep::Scan(head.clone()));
        scan(&store, 1, &head).unwrap();
        assert_eq!(store.next_shard_step(1).unwrap(), ShardStep::Done);
        assert_eq!(store.explorer_stats().unwrap().blocks, 0, "hidden until published");

        store.publish_batch(i64::MIN, &anchor(1)).unwrap();
        assert_eq!(store.canonical_state().unwrap(), Some(anchor(1)));
        assert_eq!(store.canonical_shard_frontier().unwrap(), vec![head]);
        assert_eq!(store.explorer_stats().unwrap().blocks, 3);
        assert_eq!(store.pending_batch().unwrap(), None);
        assert!(store.pending_work_counts().unwrap().is_empty(), "batch metadata is cleared");
        assert_eq!(store.checkpoint("-1:-9223372036854775808").unwrap(), 1);
        assert_eq!(store.checkpoint("0:-9223372036854775808").unwrap(), 2);
    }

    #[test]
    fn the_same_coordinate_with_another_hash_is_refused() {
        let store = IndexerStore::open_in_memory().unwrap();
        open_batch(&store, 1);
        let left = block(0, 0x4000_0000_0000_0000, 5, 50);
        let right = block(0, 0xC000_0000_0000_0000_u64 as i64, 5, 51);
        store.seed_batch_heads(1, &[left.clone(), right.clone()]).unwrap();
        let parent = block(0, i64::MIN, 4, 40);
        let forged = block(0, i64::MIN, 4, 41);
        store.record_parents(1, &right, std::slice::from_ref(&parent)).unwrap();
        let error = store.record_parents(1, &left, std::slice::from_ref(&forged)).unwrap_err();
        assert!(error.to_string().contains("is reported with hash"), "{error}");
    }

    #[test]
    fn overlapping_shard_heads_are_refused() {
        let store = IndexerStore::open_in_memory().unwrap();
        open_batch(&store, 1);
        let error = store
            .seed_batch_heads(1, &[block(0, i64::MIN, 3, 1), block(0, 0x4000_0000_0000_0000, 3, 2)])
            .unwrap_err();
        assert!(error.to_string().contains("overlapping"), "{error}");
    }

    #[test]
    fn traversal_below_the_frontier_without_matching_it_is_refused() {
        let store = IndexerStore::open_in_memory().unwrap();
        open_batch(&store, 1);
        let published_head = block(0, i64::MIN, 3, 30);
        store.seed_batch_heads(1, std::slice::from_ref(&published_head)).unwrap();
        store.record_parents(1, &published_head, &[block(0, i64::MIN, 0, 0)]).unwrap();
        assert!(store.resolve_at_frontier(1, &block(0, i64::MIN, 0, 0)).unwrap());
        scan(&store, 1, &published_head).unwrap();
        store.publish_batch(i64::MIN, &anchor(1)).unwrap();

        open_batch(&store, 2);
        let head = block(0, i64::MIN, 4, 40);
        store.seed_batch_heads(2, std::slice::from_ref(&head)).unwrap();
        // Same coordinate as the published head, different hash.
        let impostor = block(0, i64::MIN, 3, 31);
        store.record_parents(2, &head, std::slice::from_ref(&impostor)).unwrap();
        let error = store.resolve_at_frontier(2, &impostor).unwrap_err();
        assert!(error.to_string().contains("published frontier holds"), "{error}");
        // The exact published head settles without a scan.
        let store = IndexerStore::open_in_memory().unwrap();
        open_batch(&store, 1);
        store.seed_batch_heads(1, std::slice::from_ref(&published_head)).unwrap();
        store.record_parents(1, &published_head, &[block(0, i64::MIN, 0, 0)]).unwrap();
        assert!(store.resolve_at_frontier(1, &block(0, i64::MIN, 0, 0)).unwrap());
        scan(&store, 1, &published_head).unwrap();
        store.publish_batch(i64::MIN, &anchor(1)).unwrap();
        open_batch(&store, 2);
        store.seed_batch_heads(2, std::slice::from_ref(&head)).unwrap();
        store.record_parents(2, &head, std::slice::from_ref(&published_head)).unwrap();
        assert!(store.resolve_at_frontier(2, &published_head).unwrap());
        assert_eq!(store.next_shard_step(2).unwrap(), ShardStep::Scan(head));
    }

    #[test]
    fn discarding_a_batch_removes_every_hidden_row_it_wrote() {
        let store = IndexerStore::open_in_memory().unwrap();
        open_batch(&store, 1);
        store.seed_batch_heads(1, &[]).unwrap();
        store.publish_batch(i64::MIN, &anchor(1)).unwrap();
        open_batch(&store, 2);
        let head = block(0, i64::MIN, 1, 11);
        store.seed_batch_heads(2, std::slice::from_ref(&head)).unwrap();
        store.record_parents(2, &head, &[block(0, i64::MIN, 0, 0)]).unwrap();
        assert!(store.resolve_at_frontier(2, &block(0, i64::MIN, 0, 0)).unwrap());
        store
            .commit_scanned_block(
                2,
                &ScannedTarget::Shard(head.clone()),
                &record(&head, 2),
                &[ExplorerTransactionRecord {
                    hash: "tx-fork".into(),
                    account: "0:aa".into(),
                    lt: 1,
                    workchain: 0,
                    shard: i64::MIN,
                    seqno: 1,
                    gen_utime: 1,
                    fee: None,
                    in_msg_hash: None,
                    indexed_at: 1,
                }],
                &[AddressTouch { address: "0:aa".into(), count: 1, block_seqno: 1, gen_utime: 1 }],
            )
            .unwrap();
        assert!(store.explorer_block_root(0, i64::MIN, 1).unwrap().is_some());
        store.discard_pending_batch().unwrap();
        assert!(store.explorer_block_root(0, i64::MIN, 1).unwrap().is_none());
        assert!(store.explorer_block_root(-1, i64::MIN, 2).unwrap().is_none());
        assert!(store.explorer_block_root(-1, i64::MIN, 1).unwrap().is_some(), "published stays");
        assert_eq!(store.pending_batch().unwrap(), None);
        let conn = store.conn.lock().unwrap();
        let leftovers: i64 = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM explorer_transactions)
                      + (SELECT COUNT(*) FROM indexer_touched_address)
                      + (SELECT COUNT(*) FROM indexer_shard_work)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn the_frontier_survives_any_retention_prune() {
        let store = IndexerStore::open_in_memory().unwrap();
        open_batch(&store, 1);
        let head = block(0, i64::MIN, 0, 0);
        store.seed_batch_heads(1, std::slice::from_ref(&head)).unwrap();
        assert!(store.resolve_at_frontier(1, &head).unwrap());
        store.publish_batch(i64::MIN, &anchor(1)).unwrap();
        store.prune_history(u32::MAX).unwrap();
        assert_eq!(store.explorer_stats().unwrap().blocks, 0);
        assert_eq!(store.canonical_shard_frontier().unwrap(), vec![head]);
        assert_eq!(store.canonical_state().unwrap(), Some(anchor(1)));
    }

    #[test]
    fn a_pending_block_can_never_replace_a_published_one() {
        let store = IndexerStore::open_in_memory().unwrap();
        open_batch(&store, 1);
        store.seed_batch_heads(1, &[]).unwrap();
        store.publish_batch(i64::MIN, &anchor(1)).unwrap();
        store.begin_batch(&anchor(2)).unwrap();
        // A masterchain row claiming the published block's coordinate.
        let mut colliding = record(&master(2), 2);
        colliding.seqno = 1;
        let error = store
            .commit_scanned_block(2, &ScannedTarget::Master, &colliding, &[], &[])
            .unwrap_err();
        assert!(error.to_string().contains("differs from the batch anchor"), "{error}");
    }

    fn queue_refresh(store: &IndexerStore, address: &str, mc_seqno: u32, attempts: u32) {
        store.queue_address_refresh_for_test(address, mc_seqno, attempts).unwrap();
    }

    fn queued(store: &IndexerStore, limit: usize) -> Vec<(String, u32)> {
        store
            .address_refresh_queue(limit)
            .unwrap()
            .into_iter()
            .map(|refresh| (refresh.address, refresh.checkpoint.seqno))
            .collect()
    }

    #[test]
    fn rows_that_keep_failing_cannot_hold_back_fresh_work() {
        let store = IndexerStore::open_in_memory().unwrap();
        // A full window of rows that failed before, all at older heights.
        for n in 0..4096 {
            queue_refresh(&store, &format!("0:poison{n:05}"), 10 + n, 1);
        }
        queue_refresh(&store, "0:honest", 9_000, 0);
        let queue = queued(&store, 4096);
        assert_eq!(queue.len(), 4096);
        assert!(queue.contains(&("0:honest".to_owned(), 9_000)), "fresh work is reached");
    }

    #[test]
    fn one_failing_address_takes_one_place_however_many_heights_it_has() {
        let store = IndexerStore::open_in_memory().unwrap();
        for height in 0..4096 {
            queue_refresh(&store, "0:poison", 10 + height, 1);
        }
        queue_refresh(&store, "0:honest", 9_000, 0);
        let queue = queued(&store, 4096);
        assert_eq!(queue, vec![("0:honest".to_owned(), 9_000), ("0:poison".to_owned(), 10)]);
    }

    #[test]
    fn rows_that_failed_keep_their_share_under_fresh_load() {
        let store = IndexerStore::open_in_memory().unwrap();
        for n in 0..500 {
            queue_refresh(&store, &format!("0:fresh{n:05}"), 100 + n, 0);
        }
        for n in 0..10 {
            queue_refresh(&store, &format!("0:retry{n:05}"), 1 + n, 3);
        }
        let queue = queued(&store, 80);
        assert_eq!(queue.len(), 80);
        let retried = queue.iter().filter(|(address, _)| address.starts_with("0:retry")).count();
        assert_eq!(retried, 10, "every failed row is retried within the share");
    }

    #[test]
    fn fresh_rows_fill_room_the_retries_leave() {
        let store = IndexerStore::open_in_memory().unwrap();
        for n in 0..200 {
            queue_refresh(&store, &format!("0:fresh{n:05}"), 100 + n, 0);
        }
        queue_refresh(&store, "0:retry", 1, 1);
        let queue = queued(&store, 100);
        assert_eq!(queue.len(), 100);
        assert_eq!(queue.iter().filter(|(address, _)| address == "0:retry").count(), 1);
        // The fresh rows are the 99 oldest, with none read twice.
        let fresh: Vec<_> =
            queue.iter().filter(|(address, _)| address.starts_with("0:fresh")).collect();
        assert_eq!(fresh.len(), 99);
        let mut heights: Vec<u32> = fresh.iter().map(|(_, height)| *height).collect();
        heights.sort_unstable();
        heights.dedup();
        assert_eq!(heights, (100..199).collect::<Vec<u32>>());
    }

    #[test]
    fn an_address_is_offered_at_its_lowest_height_only() {
        let store = IndexerStore::open_in_memory().unwrap();
        queue_refresh(&store, "0:pool", 7, 0);
        queue_refresh(&store, "0:pool", 5, 0);
        assert_eq!(queued(&store, 10), vec![("0:pool".to_owned(), 5)]);
        store.complete_address_refresh_through("0:pool", 7).unwrap();
        assert!(queued(&store, 10).is_empty());
    }

    #[test]
    fn a_window_too_small_to_split_serves_fresh_rows_first() {
        let store = IndexerStore::open_in_memory().unwrap();
        queue_refresh(&store, "0:retry", 1, 2);
        for n in 0..3 {
            queue_refresh(&store, &format!("0:fresh{n}"), 10 + n, 0);
        }
        // Below eight places there is no reserved share: fresh rows first,
        // and the failed row takes the place they leave.
        let queue = queued(&store, 4);
        assert_eq!(queue.len(), 4);
        assert_eq!(queue[3], ("0:retry".to_owned(), 1));
        assert_eq!(queued(&store, 1), vec![("0:fresh0".to_owned(), 10)]);
    }

    /// Cost of one queue read on a large queue. Run on demand:
    /// `cargo test -p service --lib refresh_queue_cost -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn refresh_queue_cost_on_a_large_queue() {
        let store = IndexerStore::open_in_memory().unwrap();
        // 100,000 addresses with three heights each, a tenth of them failing,
        // plus one address whose failed head holds 50,000 fresh heights back.
        {
            let conn = store.lock().unwrap();
            conn.execute_batch("BEGIN").unwrap();
            for n in 0..100_000u32 {
                for height in 0..3u32 {
                    conn.execute(
                        "INSERT INTO indexer_address_refresh
                            (address, touch_count, last_block_seqno, last_gen_utime,
                             mc_seqno, mc_root_hash, mc_file_hash, attempts)
                         VALUES (?1, 1, ?2, 1, ?2, ?3, ?3, ?4)",
                        params![
                            format!("0:{n:08}"),
                            n + height * 200_000,
                            hash(n),
                            u32::from(n % 10 == 0)
                        ],
                    )
                    .unwrap();
                }
            }
            for height in 0..50_000u32 {
                conn.execute(
                    "INSERT INTO indexer_address_refresh
                        (address, touch_count, last_block_seqno, last_gen_utime,
                         mc_seqno, mc_root_hash, mc_file_hash, attempts)
                     VALUES ('0:poison', 1, ?1, 1, ?1, ?2, ?2, ?3)",
                    // Its head failed; the later heights are fresh rows that
                    // every read has to step past, the scan's worst case.
                    params![height, hash(height), u32::from(height == 0)],
                )
                .unwrap();
            }
            conn.execute_batch("COMMIT").unwrap();
        }
        for _ in 0..3 {
            let started = std::time::Instant::now();
            let queue = store.address_refresh_queue(4096).unwrap();
            println!(
                "REFRESH_QUEUE_COST rows=350000 returned={} elapsed_ms={}",
                queue.len(),
                started.elapsed().as_millis()
            );
        }
    }
}
