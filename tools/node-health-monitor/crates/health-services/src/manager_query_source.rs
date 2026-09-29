//! Read-only, bounded M observation projection for the query process.
//! Only the exact archived process envelope is implemented. Unsupported
//! source classes are not silently recast as a complete query component.
use crate::durable::{DurableEvidence, EvidenceRow};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, os::unix::fs::MetadataExt, path::Path};
use tos_health_core::{
    edge_snapshot::{ProcessEnvelope, ProcessPayload},
    evidence::Evidence,
    native::canonical_hash,
    query::utc_ms,
    source::{Availability, Coverage},
    wire::U64,
};

const MAX_ROWS: usize = 4096;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const PAGE_ROWS: usize = 256;
const VERSION: &str = "m-observation-projection-v1";
pub type ProjectionScan = (u64, Vec<(EvidenceRow, Evidence)>, std::collections::BTreeSet<String>);
type RetainedSqlRow = (String, String, String, String, String, String, String, String, i64);

#[derive(Debug)]
pub struct ProjectionPage {
    pub cursor: crate::query_ledger::ManagerCursor,
    pub records: Vec<(EvidenceRow, Evidence)>,
    pub quarantined_retained: BTreeSet<String>,
    pub caught_up: bool,
}

fn failure(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub fn project_process(row: &EvidenceRow) -> Result<Option<Evidence>, String> {
    if row.store_seq.0 == 0 || !tos_health_core::wire::hash(&row.evidence_id) {
        return Err("invalid M evidence identity".into());
    }
    let mut original = row.evidence.clone();
    original.record.received_at_ms = 0;
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&original).map_err(failure)?));
    if digest != row.evidence_id {
        return Err("M evidence hash mismatch".into());
    }
    let record = &row.evidence.record;
    if record.payload.get("component").and_then(serde_json::Value::as_str) != Some("process") {
        return Ok(None);
    }
    let source: ProcessEnvelope = serde_json::from_value(
        record.payload.get("source").ok_or("missing archived process source")?.clone(),
    )
    .map_err(failure)?;
    if source.availability != "available"
        || source.clock_quality != "valid"
        || source.observed_at.is_none()
        || source.last_success_at.is_none()
        || !record.quality.clock_valid
        || record.quality.observed_at_ms.is_none()
    {
        return Err(
            "M process source unavailable: source clock, time or availability unknown".into()
        );
    }
    let observed = utc_ms(source.observed_at.as_deref().ok_or("missing source observed_at")?)
        .map_err(str::to_owned)?;
    let success = utc_ms(source.last_success_at.as_deref().ok_or("missing source success_at")?)
        .map_err(str::to_owned)?;
    if source.schema_version != 1
        || source.source_id != "process"
        || source.source_version != "proc-v1"
        || source.payload.kind != "process"
        || source.payload.pid == 0
        || source.generation.0 == 0
        || source.availability != "available"
        || source.clock_quality != "valid"
        || source.coverage.status != "partial"
        || source.coverage.sampling_policy != "fixed_15s"
        || !source.coverage.gaps.is_empty()
        || source.coverage.missing_fields.len() > 64
        || source.coverage.missing_fields.iter().any(|field| field.len() > 96)
        || source.node_id != record.node_id
        || source.scope_id != record.scope_id
        || source.process_epoch != record.process_epoch
        || source.source_epoch != row.evidence.source_epoch
        || record.source_id != source.source_id
        || record.source_record_id != format!("{}:{}", source.source_epoch, source.generation.0)
        || record.observed_at_ms != observed
        || record.quality.observed_at_ms != Some(observed)
        || record.quality.last_success_at_ms != Some(success)
        || record.quality.process_epoch != source.process_epoch
        || record.quality.source_sequence != source.generation.0.to_string()
        || record.quality.availability != Availability::Available
        || record.quality.coverage != Coverage::Partial
        || !record.quality.clock_valid
        || !record.redacted
        || source.received_at.is_some()
        || canonical_hash(&source.payload)? != source.content_hash
    {
        return Err("archived process source mismatch".into());
    }
    let payload: ProcessPayload = source.payload;
    let query_payload = serde_json::json!({
        "component":"process",
        "source_version":VERSION,
        "origin_source_version":source.source_version,
        "origin_store_seq":U64(row.store_seq.0),
        "evidence_kind":"derived",
        "parent_evidence_ids":[row.evidence_id],
        "derivation_version":VERSION,
        "contract_quality":source.quality,
        "contract_coverage":source.coverage,
        "contract_payload":payload,
    });
    let mut projected = record.clone();
    projected.source_record_id = format!("m-{}", row.evidence_id);
    projected.payload = query_payload;
    Ok(Some(projected))
}

/// One read transaction fixes M's original observation watermark and excludes
/// quarantine. Query-memory W is separate and only advances after its own
/// durable import; the caller must not mistake the two sequence namespaces.
pub fn read_process_projection(
    path: &Path,
    network: &str,
) -> Result<(u64, Vec<(EvidenceRow, Evidence)>), String> {
    let (watermark, records, _) = read_process_projection_state(path, network)?;
    Ok((watermark, records))
}

/// One bounded incremental page from a single read transaction. The previous
/// cursor is persisted in QueryLedger, not inferred from the in-memory store:
/// evicted query rows must not cause old M history to be scanned again.
pub fn read_process_projection_page(
    path: &Path,
    network: &str,
    previous: Option<&crate::query_ledger::ManagerCursor>,
    retained: &[EvidenceRow],
) -> Result<ProjectionPage, String> {
    if !tos_health_core::wire::hash(network) || retained.len() > MAX_ROWS {
        return Err("invalid M projection source or retained set".into());
    }
    let meta = std::fs::symlink_metadata(path).map_err(failure)?;
    if !meta.file_type().is_file() {
        return Err("M evidence path is not a regular file".into());
    }
    if previous.is_some_and(|old| {
        old.network != network || old.device != meta.dev() || old.inode != meta.ino()
    }) {
        return Err("M projection database identity changed".into());
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(failure)?;
    conn.busy_timeout(std::time::Duration::from_millis(100)).map_err(failure)?;
    conn.execute_batch("PRAGMA query_only=ON; BEGIN TRANSACTION").map_err(failure)?;
    let bound: String = conn
        .query_row("SELECT network FROM database_identity WHERE singleton=1", [], |row| row.get(0))
        .map_err(failure)?;
    if bound != network {
        return Err("M evidence network mismatch".into());
    }
    let watermark: Option<i64> = conn
        .query_row("SELECT seq FROM sqlite_sequence WHERE name='observations'", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(failure)?;
    let watermark = u64::try_from(watermark.unwrap_or(0)).map_err(failure)?;
    let after = previous.map_or(0, |old| old.watermark);
    if watermark < after {
        return Err("M projection watermark regressed".into());
    }
    if let Some((seq, expected)) = previous.and_then(|old| old.anchor.as_ref()) {
        let actual: Option<String> = conn
            .query_row(
                "SELECT content_hash FROM observations WHERE store_seq=?1 AND source='process'",
                [i64::try_from(*seq).map_err(failure)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(failure)?;
        if actual.as_deref() != Some(expected) {
            return Err("M projection anchor changed".into());
        }
    }
    // A late quarantine or replacement may target a row older than `after`.
    // Revalidate exact retained parent seq/hash/body in this same M snapshot.
    let mut quarantined_retained = BTreeSet::new();
    let mut parent = conn
        .prepare(
            "SELECT o.content_hash,o.body,o.node,o.scope,o.process_epoch,
             o.source_epoch,o.source,o.source_record,
             EXISTS(SELECT 1 FROM quarantined q
             WHERE q.node=o.node AND q.scope=o.scope AND q.process_epoch=o.process_epoch
             AND q.source_epoch=o.source_epoch AND q.source=o.source)
             FROM observations o WHERE o.store_seq=?1 AND o.source='process'",
        )
        .map_err(failure)?;
    for origin in retained {
        if origin.store_seq.0 == 0 || origin.store_seq.0 > watermark {
            return Err("retained M parent sequence outside snapshot".into());
        }
        let actual: Option<RetainedSqlRow> = parent
            .query_row([i64::try_from(origin.store_seq.0).map_err(failure)?], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            })
            .optional()
            .map_err(failure)?;
        let (
            id,
            body,
            node,
            scope,
            process_epoch,
            source_epoch,
            source,
            source_record,
            quarantined,
        ) = actual.ok_or("retained M parent missing")?;
        let original = &origin.evidence.record;
        if id != origin.evidence_id
            || body.as_bytes() != serde_json::to_vec(&origin.evidence).map_err(failure)?
            || node != original.node_id
            || scope != original.scope_id
            || process_epoch != original.process_epoch
            || source_epoch != origin.evidence.source_epoch
            || source != original.source_id
            || source_record != original.source_record_id
        {
            return Err("retained M parent changed".into());
        }
        if quarantined != 0 {
            quarantined_retained.insert(id);
        }
    }
    drop(parent);
    let mut query = conn
        .prepare(
            "SELECT store_seq,content_hash,length(CAST(body AS BLOB)),
         CASE WHEN length(CAST(body AS BLOB))<=32768 THEN body ELSE NULL END
         FROM observations WHERE store_seq>?1 AND store_seq<=?2 AND source='process'
         AND NOT EXISTS(SELECT 1 FROM quarantined q WHERE q.node=observations.node
         AND q.scope=observations.scope AND q.process_epoch=observations.process_epoch
         AND q.source_epoch=observations.source_epoch AND q.source=observations.source)
         ORDER BY store_seq LIMIT ?3",
        )
        .map_err(failure)?;
    let rows = query
        .query_map(
            params![
                i64::try_from(after).map_err(failure)?,
                i64::try_from(watermark).map_err(failure)?,
                (PAGE_ROWS + 1) as i64
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .map_err(failure)?;
    let mut records = Vec::new();
    let mut bytes = 0usize;
    let mut last = after;
    let mut anchor = previous.and_then(|old| old.anchor.clone());
    let mut caught_up = true;
    for (count, row) in rows.enumerate() {
        if count == PAGE_ROWS {
            caught_up = false;
            break;
        }
        let (seq, id, length, body) = row.map_err(failure)?;
        let length = usize::try_from(length).map_err(failure)?;
        bytes = bytes.checked_add(length).ok_or("M scan overflow")?;
        if bytes > MAX_BYTES || length > 32_768 {
            return Err("M projection page bound exceeded".into());
        }
        let row = EvidenceRow {
            store_seq: U64(u64::try_from(seq).map_err(failure)?),
            evidence_id: id,
            evidence: serde_json::from_str::<DurableEvidence>(
                &body.ok_or("M projection body unavailable")?,
            )
            .map_err(failure)?,
        };
        last = row.store_seq.0;
        anchor = Some((last, row.evidence_id.clone()));
        let projected = project_process(&row)?.ok_or("M process row payload not process")?;
        records.push((row, projected));
    }
    drop(query);
    let end_meta = std::fs::symlink_metadata(path).map_err(failure)?;
    if end_meta.dev() != meta.dev() || end_meta.ino() != meta.ino() {
        return Err("M projection database replaced during read".into());
    }
    Ok(ProjectionPage {
        cursor: crate::query_ledger::ManagerCursor {
            network: network.to_owned(),
            device: meta.dev(),
            inode: meta.ino(),
            watermark: if caught_up { watermark } else { last },
            anchor,
        },
        records,
        quarantined_retained,
        caught_up,
    })
}

/// The third value is a bounded set of M original IDs whose source tuple is
/// quarantined. It is read in the same SQLite snapshot as the projection.
pub fn read_process_projection_state(path: &Path, network: &str) -> Result<ProjectionScan, String> {
    if !tos_health_core::wire::hash(network) {
        return Err("invalid M network".into());
    }
    let meta = std::fs::symlink_metadata(path).map_err(failure)?;
    if !meta.file_type().is_file() {
        return Err("M evidence path is not a regular file".into());
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(failure)?;
    conn.busy_timeout(std::time::Duration::from_millis(100)).map_err(failure)?;
    conn.execute_batch("PRAGMA query_only=ON; BEGIN TRANSACTION").map_err(failure)?;
    let bound: String = conn
        .query_row("SELECT network FROM database_identity WHERE singleton=1", [], |row| row.get(0))
        .map_err(failure)?;
    if bound != network {
        return Err("M evidence network mismatch".into());
    }
    let watermark: Option<i64> = conn
        .query_row("SELECT seq FROM sqlite_sequence WHERE name='observations'", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(failure)?;
    let watermark = u64::try_from(watermark.unwrap_or(0)).map_err(failure)?;
    let mut query = conn
        .prepare(
            "SELECT store_seq,content_hash,length(CAST(body AS BLOB)),
             CASE WHEN length(CAST(body AS BLOB))<=32768 THEN body ELSE NULL END
             FROM observations WHERE store_seq<=?1 AND source='process'
             AND NOT EXISTS(SELECT 1 FROM quarantined q WHERE q.node=observations.node
             AND q.scope=observations.scope AND q.process_epoch=observations.process_epoch
             AND q.source_epoch=observations.source_epoch AND q.source=observations.source)
             ORDER BY store_seq LIMIT ?2",
        )
        .map_err(failure)?;
    let rows = query
        .query_map(
            params![i64::try_from(watermark).map_err(failure)?, MAX_ROWS as i64 + 1],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .map_err(failure)?;
    let mut projected = Vec::new();
    let mut count = 0usize;
    let mut bytes = 0usize;
    for row in rows {
        let (seq, id, length, body) = row.map_err(failure)?;
        count += 1;
        let length = usize::try_from(length).map_err(failure)?;
        bytes = bytes.checked_add(length).ok_or("M scan overflow")?;
        if count > MAX_ROWS || bytes > MAX_BYTES || length > 32_768 {
            return Err("M projection scan bound exceeded".into());
        }
        let body = body.ok_or("M projection body unavailable")?;
        let row = EvidenceRow {
            store_seq: U64(u64::try_from(seq).map_err(failure)?),
            evidence_id: id,
            evidence: serde_json::from_str::<DurableEvidence>(&body).map_err(failure)?,
        };
        if let Some(record) = project_process(&row)? {
            projected.push((row, record));
        }
    }
    let mut quarantined = std::collections::BTreeSet::new();
    let mut query = conn
        .prepare(
            "SELECT o.content_hash FROM observations o JOIN quarantined q
         ON q.node=o.node AND q.scope=o.scope AND q.process_epoch=o.process_epoch
         AND q.source_epoch=o.source_epoch AND q.source=o.source
             WHERE o.store_seq<=?1 AND o.source='process'
             ORDER BY o.store_seq LIMIT ?2",
        )
        .map_err(failure)?;
    let rows = query
        .query_map(
            params![i64::try_from(watermark).map_err(failure)?, MAX_ROWS as i64 + 1],
            |row| row.get::<_, String>(0),
        )
        .map_err(failure)?;
    let mut count = 0usize;
    for row in rows {
        count += 1;
        if count > MAX_ROWS {
            return Err("M quarantine scan bound exceeded".into());
        }
        quarantined.insert(row.map_err(failure)?);
    }
    Ok((watermark, projected, quarantined))
}
