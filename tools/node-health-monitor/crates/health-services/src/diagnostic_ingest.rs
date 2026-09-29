//! Batch transaction on the existing evidence owner's connection.
use crate::durable::DurableEvidence;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tos_health_core::{
    contracts::DiagnosticBatch,
    evidence::{Evidence, EvidenceStore},
    source::{Availability, Coverage, SourceQuality},
    wire::U64,
};
const MAX_RECORDS: usize = 128;
const MAX_BODY: usize = 262144;
const ROW_BYTES: usize = 24576;
const PREDECODE_BYTES: u32 = 4 * 1024 * 1024;
const TOTAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_BATCHES: usize = 32;
const FIXED_BYTES: usize = 132 * 1024;
const fn maximum_batch_bytes() -> usize {
    let rows = match MAX_RECORDS.checked_mul(ROW_BYTES) {
        Some(value) => value,
        None => panic!("diagnostic bound overflow"),
    };
    let raw = match rows.checked_add(MAX_BODY) {
        Some(value) => value,
        None => panic!("diagnostic bound overflow"),
    };
    match raw.checked_add(FIXED_BYTES) {
        Some(value) => value,
        None => panic!("diagnostic bound overflow"),
    }
}
const MAX_BATCH_BYTES: usize = maximum_batch_bytes();
const _: () = assert!(MAX_BATCH_BYTES <= PREDECODE_BYTES as usize);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub batch_id: String,
    pub accepted_through_sequence: U64,
    pub duplicate_count: U64,
}
pub(crate) fn insert(conn: &mut Connection, batch: &DiagnosticBatch) -> Result<Ack, String> {
    batch.validate().map_err(str::to_owned)?;
    if batch.source_id != "consensus_diagnostic"
        || batch.process_epoch.len() != 32
        || !batch.process_epoch.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || batch.content_id().map_err(str::to_owned)? != batch.batch_id
    {
        return Err("DIAGNOSTIC_INVALID".into());
    }
    // Defend this boundary independently of the HTTP parser.
    let wire = serde_json::to_vec(batch).map_err(|e| e.to_string())?;
    if wire.capacity() > 65536
        || batch_owned(batch) > 65536
        || wire.capacity() + batch_owned(batch) > 96 * 1024
    {
        return Err("DIAGNOSTIC_OWNERSHIP".into());
    }
    DiagnosticBatch::decode(&wire).map_err(str::to_owned)?;
    let mut rows = Vec::with_capacity(batch.records.len());
    let now = chrono::Utc::now().timestamp_millis();
    for item in &batch.records {
        let observed = item
            .observed_at
            .as_deref()
            .map(tos_health_core::query::utc_ms)
            .transpose()
            .map_err(str::to_owned)?;
        let value = DurableEvidence {
            // A relay restart does not change the native source identity.
            source_epoch: batch.process_epoch.clone(),
            record: Evidence {
                node_id: batch.node_id.clone(),
                scope_id: "node".into(),
                source_id: batch.source_id.clone(),
                source_record_id: item.sequence.0.to_string(),
                process_epoch: batch.process_epoch.clone(),
                observed_at_ms: observed.unwrap_or(0),
                received_at_ms: now,
                quality: SourceQuality {
                    availability: Availability::Available,
                    coverage: Coverage::Partial,
                    observed_at_ms: observed,
                    last_success_at_ms: observed,
                    clock_valid: false,
                    process_epoch: batch.process_epoch.clone(),
                    source_sequence: item.sequence.0.to_string(),
                },
                redacted: true,
                payload: serde_json::json!({"source_version":"diagnostic_catalog_8_v1","evidence_kind":"event",
                    "contract_quality":{"instrumentation_complete":false,"producer_dropped":null,"relay_dropped":null,"parse_errors":null,"shed_reason":"sampled_unanchored_diagnostic_counters_not_attached"},
                    "contract_coverage":{"status":"partial","missing_fields":["valid_clock","source_record_counters","consensus_anchor"],"gaps":["diagnostic_delivery_not_complete"],"sampling_policy":"fixed_configured_producer_sampler_policy_not_attached_to_record"},
                    "event":{"kind":"consensus_action_phase","stage":null,"reason":null,"correlation_id":null,"excerpt":"Unanchored scalar action phase; no consensus or durability proof."},
                    "contract_payload":{"kind":"diagnostic_phase","record_type":item.record_type,"payload":item.payload,"monotonic_ns":item.monotonic_ns}}),
            },
        };
        #[cfg(test)]
        eprintln!(
            "diagnostic row scalar/value owned upper bound {}",
            row_owned(&value, &String::new(), &String::new())
        );
        if row_owned(&value, &String::new(), &String::new()) > 16384 {
            return Err("DIAGNOSTIC_OWNERSHIP".into());
        }
        let mut canonical = value.clone();
        canonical.record.received_at_ms = 0;
        let encoded = serde_json::to_vec(&canonical).map_err(|e| e.to_string())?;
        if encoded.capacity() > 16384 {
            return Err("DIAGNOSTIC_OWNERSHIP".into());
        }
        // EvidenceStore validates through two overlapping record clones and
        // two encode buffers. The enclosing DurableEvidence encoding bounds
        // the shorter record encodings under the same pinned serde allocator.
        let scalar = row_owned(&value, &String::new(), &String::new());
        let validation_scratch = 2 * scalar + 2 * encoded.capacity() + 4096;
        let available_scratch = FIXED_BYTES - 96 * 1024 + ROW_BYTES - scalar;
        if validation_scratch > available_scratch {
            return Err("DIAGNOSTIC_OWNERSHIP".into());
        }
        let digest = format!("{:x}", Sha256::digest(&encoded));
        drop(encoded);
        drop(canonical);
        EvidenceStore::new(65536).insert(value.record.clone()).map_err(str::to_owned)?;
        let body = serde_json::to_string(&value).map_err(|e| e.to_string())?;
        if body.len() > 8192 {
            return Err("DIAGNOSTIC_OWNERSHIP".into());
        }
        #[cfg(test)]
        eprintln!(
            "diagnostic row body capacity {} total owned upper bound {}",
            body.capacity(),
            row_owned(&value, &digest, &body)
        );
        if row_owned(&value, &digest, &body) > ROW_BYTES {
            return Err("DIAGNOSTIC_OWNERSHIP".into());
        }
        rows.push((value, digest, body));
    }
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let quarantined:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM quarantined WHERE node=?1 AND scope='node' AND process_epoch=?2 AND source_epoch=?2 AND source=?3)",
        params![batch.node_id,batch.process_epoch,batch.source_id],|r| r.get(0)).map_err(|e| e.to_string())?;
    if quarantined {
        return Err("SOURCE_CONFLICT".into());
    }
    let mut duplicates = 0u64;
    let mut insert_flags = Vec::with_capacity(rows.len());
    // Preflight the whole batch before any observation is inserted. A conflict
    // commits only quarantine; no prefix of this batch can escape rollback.
    for (value, digest, _) in &rows {
        let prior:Option<String>=tx.query_row("SELECT content_hash FROM observations WHERE node=?1 AND scope='node' AND process_epoch=?2 AND source_epoch=?2 AND source=?3 AND source_record=?4",
            params![batch.node_id,batch.process_epoch,batch.source_id,value.record.source_record_id],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
        if let Some(hash) = prior {
            if hash != *digest {
                tx.execute(
                    "INSERT OR IGNORE INTO quarantined VALUES(?1,'node',?2,?2,?3)",
                    params![batch.node_id, batch.process_epoch, batch.source_id],
                )
                .map_err(|e| e.to_string())?;
                tx.commit().map_err(|e| e.to_string())?;
                return Err("SOURCE_CONFLICT".into());
            }
            duplicates = duplicates.checked_add(1).ok_or("duplicate overflow")?;
            insert_flags.push(false);
        } else {
            insert_flags.push(true);
        }
    }
    for ((value, digest, body), insert) in rows.iter().zip(insert_flags) {
        if insert {
            tx.execute("INSERT INTO observations(node,scope,process_epoch,source_epoch,source,source_record,content_hash,body) VALUES(?1,'node',?2,?2,?3,?4,?5,?6)",
                params![batch.node_id,batch.process_epoch,batch.source_id,value.record.source_record_id,digest,body]).map_err(|e|e.to_string())?;
        }
    }
    let last = batch.records.last().ok_or("empty diagnostic batch")?.sequence;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(Ack {
        batch_id: batch.batch_id.clone(),
        accepted_through_sequence: last,
        duplicate_count: U64(duplicates),
    })
}
fn batch_owned(batch: &DiagnosticBatch) -> usize {
    std::mem::size_of::<DiagnosticBatch>()
        + batch.node_id.capacity()
        + batch.edge_epoch.capacity()
        + batch.process_epoch.capacity()
        + batch.source_id.capacity()
        + batch.batch_id.capacity()
        + batch.records.capacity()
            * std::mem::size_of::<tos_health_core::contracts::DiagnosticItem>()
        + batch
            .records
            .iter()
            .map(|item| {
                item.payload.capacity() + item.observed_at.as_ref().map_or(0, String::capacity)
            })
            .sum::<usize>()
}
fn value_owned(value: &serde_json::Value) -> usize {
    std::mem::size_of::<serde_json::Value>()
        + match value {
            serde_json::Value::String(text) => text.capacity(),
            serde_json::Value::Array(items) => {
                items.capacity() * std::mem::size_of::<serde_json::Value>()
                    + items.iter().map(value_owned).sum::<usize>()
            }
            // Fixed objects use the default BTreeMap representation; 512/entry
            // bounds node slots/allocator bookkeeping in addition to owned keys.
            serde_json::Value::Object(items) => items
                .iter()
                .map(|(key, item)| 512 + key.capacity() + value_owned(item))
                .sum::<usize>(),
            _ => 0,
        }
}
fn row_owned(row: &DurableEvidence, hash: &String, body: &String) -> usize {
    let record = &row.record;
    std::mem::size_of::<(DurableEvidence, String, String)>()
        + row.source_epoch.capacity()
        + record.node_id.capacity()
        + record.scope_id.capacity()
        + record.source_id.capacity()
        + record.source_record_id.capacity()
        + record.process_epoch.capacity()
        + record.quality.process_epoch.capacity()
        + record.quality.source_sequence.capacity()
        + value_owned(&record.payload)
        + hash.capacity()
        + body.capacity()
        + 512
}

/// Independent diagnostic ownership; these permits accompany queued commands
/// until the writer finishes, even if the caller has already timed out.
pub struct Budget {
    slots: std::sync::Arc<tokio::sync::Semaphore>,
    bytes: std::sync::Arc<tokio::sync::Semaphore>,
}
pub struct Lease {
    _slot: tokio::sync::OwnedSemaphorePermit,
    _bytes: tokio::sync::OwnedSemaphorePermit,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            slots: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_BATCHES)),
            bytes: std::sync::Arc::new(tokio::sync::Semaphore::new(TOTAL_BYTES)),
        }
    }
}
impl Budget {
    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({"max_batches":MAX_BATCHES,"max_owned_bytes":TOTAL_BYTES.to_string(),"predecode_bytes":PREDECODE_BYTES.to_string(),
            "owned_batches":MAX_BATCHES.saturating_sub(self.slots.available_permits()).to_string(),"owned_bytes":TOTAL_BYTES.saturating_sub(self.bytes.available_permits()).to_string()})
    }
    /// Called before the HTTP body is collected or deserialized. Four MiB
    /// covers the full maximum batch and bounded raw/parser scratch overlap.
    pub fn acquire_request(&self) -> Result<Lease, String> {
        let slot = self.slots.clone().try_acquire_owned().map_err(|_| "DIAGNOSTIC_BUSY")?;
        let bytes = self
            .bytes
            .clone()
            .try_acquire_many_owned(PREDECODE_BYTES)
            .map_err(|_| "DIAGNOSTIC_BUSY")?;
        Ok(Lease { _slot: slot, _bytes: bytes })
    }
}
impl Lease {
    pub fn narrow(&mut self, body: usize, batch: &DiagnosticBatch) -> Result<(), String> {
        // Actual raw Vec capacity is charged separately. The 132KiB scratch
        // reserve covers batch + wire capacities <=96KiB combined and
        // 36KiB temporary scratch. The row being constructed is charged its
        // full24KiB before persistence. insert preflights the overlapping
        // EvidenceStore clones + encodes +4KiB indices against that scratch
        // plus the unoccupied part of the current row reservation.
        // row_owned binds every persisted row to its24KiB ceiling, including
        // Value tree nodes, vector slots, String capacities and allocator charge.
        if body > MAX_BODY
            || batch_owned(batch) > 65536
            || batch.records.is_empty()
            || batch.records.len() > MAX_RECORDS
        {
            return Err("DIAGNOSTIC_OWNERSHIP".into());
        }
        let charge = body
            .checked_add(FIXED_BYTES)
            .and_then(|n| n.checked_add(batch.records.len().checked_mul(ROW_BYTES)?))
            .ok_or("diagnostic ownership overflow")?;
        let spare = self._bytes.num_permits().checked_sub(charge).ok_or("DIAGNOSTIC_OWNERSHIP")?;
        if spare > 0 {
            drop(self._bytes.split(spare).ok_or("diagnostic lease split")?);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn database() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE observations(store_seq INTEGER PRIMARY KEY AUTOINCREMENT,node TEXT,scope TEXT,process_epoch TEXT,source_epoch TEXT,source TEXT,source_record TEXT,content_hash TEXT,body TEXT,UNIQUE(node,scope,process_epoch,source_epoch,source,source_record));CREATE TABLE quarantined(node TEXT,scope TEXT,process_epoch TEXT,source_epoch TEXT,source TEXT,PRIMARY KEY(node,scope,process_epoch,source_epoch,source));").unwrap();
        conn
    }
    fn batch(sequences: &[u64]) -> DiagnosticBatch {
        use tos_health_core::contracts::{DiagnosticItem, DiagnosticQuality};
        let mut batch = DiagnosticBatch {
            schema_version: 1,
            node_id: "node_a".into(),
            edge_epoch: "edge_a".into(),
            process_epoch: "a".repeat(32),
            source_id: "consensus_diagnostic".into(),
            batch_id: "0".repeat(64),
            records: sequences
                .iter()
                .map(|seq| DiagnosticItem {
                    sequence: U64(*seq),
                    monotonic_ns: U64(*seq),
                    observed_at: Some("2026-09-29T00:00:00Z".into()),
                    record_type: 1,
                    payload: "01000300".into(),
                })
                .collect(),
            quality: DiagnosticQuality { dropped: U64(0), gaps: false },
        };
        batch.batch_id = batch.content_id().unwrap();
        batch
    }
    #[test]
    fn late_sequence_across_batches_is_not_a_replay_and_edge_restart_is_idempotent() {
        let mut db = database();
        let high = batch(&[10]);
        let low = batch(&[0]);
        assert_eq!(insert(&mut db, &high).unwrap().accepted_through_sequence.0, 10);
        assert_eq!(insert(&mut db, &low).unwrap().accepted_through_sequence.0, 0);
        let mut restart = low.clone();
        restart.edge_epoch = "edge_b".into();
        restart.batch_id = restart.content_id().unwrap();
        assert_eq!(insert(&mut db, &restart).unwrap().duplicate_count.0, 1);
        assert_eq!(
            db.query_row("SELECT count(*) FROM observations", [], |r| r.get::<_, u64>(0)).unwrap(),
            2
        );
        let body: String = db
            .query_row("SELECT body FROM observations WHERE source_record='0'", [], |r| r.get(0))
            .unwrap();
        let stored: DurableEvidence = serde_json::from_str(&body).unwrap();
        assert!(!stored.record.quality.clock_valid);
        let mut unknown = batch(&[30]);
        unknown.records[0].observed_at = None;
        unknown.batch_id = unknown.content_id().unwrap();
        insert(&mut db, &unknown).unwrap();
        let body: String = db
            .query_row("SELECT body FROM observations WHERE source_record='30'", [], |r| r.get(0))
            .unwrap();
        let stored: DurableEvidence = serde_json::from_str(&body).unwrap();
        assert_eq!(stored.record.quality.observed_at_ms, None);
        let mut store = EvidenceStore::new(65536);
        let id = store.insert(stored.record.clone()).unwrap();
        let grant = tos_health_core::query::Grant::new(
            "00000000-0000-4000-8000-000000000001".into(),
            "diagnostic-test".into(),
            "a".repeat(64),
            &[7; 32],
            std::collections::BTreeSet::from(["node_a".into()]),
            std::collections::BTreeSet::from(["node".into()]),
            0,
            3600000,
            0,
            1,
        )
        .unwrap();
        let output = tos_health_core::query_output::success(
            "tos_get_event_window",
            &serde_json::json!({"run_id":grant.run_id,"limit":100,"cursor":""}),
            &grant,
            0,
            0,
            &[id],
            &store,
            &std::collections::BTreeSet::new(),
            tos_health_core::query_output::PaginationDto {
                next_cursor: None,
                truncated: false,
                scan_complete: true,
            },
        )
        .unwrap();
        assert!(
            output["evidence"][0]["observed_at"].is_null()
                && output["data"]["events"][0]["observed_at"].is_null()
        );
        assert_eq!(output["evidence"][0]["clock_quality"], "uncertain");
        for field in ["producer_dropped", "relay_dropped", "parse_errors"] {
            assert!(output["evidence"][0]["quality"][field].is_null());
        }
        assert_eq!(output["evidence"][0]["quality"]["instrumentation_complete"], false);
        let mut known = stored.record;
        for field in ["producer_dropped", "relay_dropped", "parse_errors"] {
            known.payload["contract_quality"][field] = serde_json::json!("0");
        }
        let mut store = EvidenceStore::new(65536);
        let id = store.insert(known).unwrap();
        let output = tos_health_core::query_output::success(
            "tos_get_event_window",
            &serde_json::json!({"run_id":grant.run_id,"limit":100,"cursor":""}),
            &grant,
            0,
            0,
            &[id],
            &store,
            &std::collections::BTreeSet::new(),
            tos_health_core::query_output::PaginationDto {
                next_cursor: None,
                truncated: false,
                scan_complete: true,
            },
        )
        .unwrap();
        assert_eq!(output["evidence"][0]["quality"]["producer_dropped"], "0");
    }
    #[test]
    fn conflict_quarantines_without_committing_an_earlier_new_record() {
        let mut db = database();
        insert(&mut db, &batch(&[2])).unwrap();
        let mut conflicting = batch(&[1, 2]);
        conflicting.records[1].payload = "02000300".into();
        conflicting.batch_id = conflicting.content_id().unwrap();
        assert_eq!(insert(&mut db, &conflicting).unwrap_err(), "SOURCE_CONFLICT");
        assert_eq!(
            db.query_row("SELECT count(*) FROM observations", [], |r| r.get::<_, u64>(0)).unwrap(),
            1
        );
        assert_eq!(insert(&mut db, &batch(&[3])).unwrap_err(), "SOURCE_CONFLICT");
        let mut fresh = batch(&[2]);
        fresh.process_epoch = "b".repeat(32);
        fresh.batch_id = fresh.content_id().unwrap();
        assert!(insert(&mut db, &fresh).is_ok());
    }
    #[test]
    fn actual_mid_transaction_failure_rolls_back_and_never_returns_ack() {
        let mut db = database();
        db.execute_batch("CREATE TRIGGER fail_second BEFORE INSERT ON observations WHEN NEW.source_record='2' BEGIN SELECT RAISE(ABORT,'forced_second_row_failure');END;").unwrap();
        assert!(insert(&mut db, &batch(&[1, 2]))
            .unwrap_err()
            .contains("forced_second_row_failure"));
        assert_eq!(
            db.query_row("SELECT count(*) FROM observations", [], |r| r.get::<_, u64>(0)).unwrap(),
            0
        );
        db.execute_batch("DROP TRIGGER fail_second;").unwrap();
        assert!(insert(&mut db, &batch(&[1, 2])).is_ok());
        let budget = Budget::default();
        let mut leases = Vec::new();
        while let Ok(mut lease) = budget.acquire_request() {
            lease.narrow(1024, &batch(&[1])).unwrap();
            leases.push(lease);
        }
        assert!(!leases.is_empty() && leases.len() <= MAX_BATCHES);
        assert_eq!(budget.acquire_request().err().unwrap(), "DIAGNOSTIC_BUSY");
        assert!(budget.bytes.available_permits() > 0);
        drop(leases);
        assert_eq!(budget.slots.available_permits(), 32);
        assert_eq!(budget.bytes.available_permits(), 8 * 1024 * 1024);
        let first = budget.acquire_request().unwrap();
        let second = budget.acquire_request().unwrap();
        assert_eq!(budget.acquire_request().err().unwrap(), "DIAGNOSTIC_BUSY");
        drop(first);
        drop(second);
        let mut maximum = batch(&(u64::MAX - 127..=u64::MAX).collect::<Vec<_>>());
        maximum.node_id = "n".repeat(64);
        maximum.edge_epoch = "e".repeat(128);
        for item in &mut maximum.records {
            item.monotonic_ns = U64(u64::MAX);
            item.observed_at = Some("2026-09-29T00:00:00.123456789Z".into());
        }
        maximum.batch_id = maximum.content_id().unwrap();
        assert!(batch_owned(&maximum) <= 65536);
        let mut maximum_body = serde_json::to_vec(&maximum).unwrap();
        maximum_body.resize(MAX_BODY, b' ');
        assert_eq!(maximum_body.capacity(), MAX_BODY);
        let maximum = DiagnosticBatch::decode(&maximum_body).unwrap();
        let mut maximum_db = database();
        assert_eq!(
            insert(&mut maximum_db, &maximum).unwrap().accepted_through_sequence.0,
            u64::MAX
        );
        assert!(maximum_batch_bytes() <= PREDECODE_BYTES as usize);
        let mut lease = budget.acquire_request().unwrap();
        assert!(lease.narrow(262144, &maximum).is_ok());
        let directory = std::env::temp_dir()
            .join(format!("nhm-c06-quota-{}", &crate::hex(&crate::random_token().unwrap())[..16]));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("evidence.db");
        let mut bounded = crate::durable::EvidenceDb::open(&path, 262144).unwrap();
        let mut accepted = 0u64;
        for number in 0..32 {
            let sequences = (number * 16..number * 16 + 16).collect::<Vec<_>>();
            match bounded.insert_diagnostic(&batch(&sequences)) {
                Ok(_) => {
                    accepted += 16;
                    Connection::open(&path)
                        .unwrap()
                        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                        .unwrap();
                }
                Err(error) => {
                    assert!(
                        error.contains("database or disk is full"),
                        "wrong quota failure: {error}"
                    );
                    break;
                }
            }
        }
        assert!(accepted > 0 && accepted < 512, "finite SQLite page quota must trip");
        let count = Connection::open(&path)
            .unwrap()
            .query_row("SELECT count(*) FROM observations", [], |r| r.get::<_, u64>(0))
            .unwrap();
        assert_eq!(count, accepted, "failed batch must have no committed prefix");
        drop(bounded);
        let path = directory.join("wal.db");
        let mut wal = crate::durable::EvidenceDb::open(&path, 1048576).unwrap();
        wal.insert_diagnostic(&batch(&[0])).unwrap();
        let wal_path = std::path::PathBuf::from(format!("{}-wal", path.display()));
        let file = std::fs::OpenOptions::new().write(true).open(&wal_path).unwrap();
        let original = file.metadata().unwrap().len();
        file.set_len(1048577).unwrap();
        assert_eq!(wal.insert_diagnostic(&batch(&[1])).unwrap_err(), "WAL quota exceeded");
        file.set_len(original).unwrap();
        drop(file);
        assert!(wal.insert_diagnostic(&batch(&[1])).is_ok());
        drop(wal);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
