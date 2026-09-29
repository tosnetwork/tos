use crate::source::SourceQuality;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub node_id: String,
    pub scope_id: String,
    pub source_id: String,
    pub source_record_id: String,
    pub process_epoch: String,
    pub observed_at_ms: i64,
    pub received_at_ms: i64,
    pub quality: SourceQuality,
    pub payload: serde_json::Value,
    pub redacted: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct StoredEvidence {
    pub evidence_id: String,
    pub watermark: u64,
    pub record: Evidence,
}
#[derive(Debug)]
pub struct EvidenceStore {
    records: VecDeque<(StoredEvidence, usize)>,
    identities: BTreeMap<(String, String, String, String), String>,
    bytes: usize,
    max_bytes: usize,
    sequence: u64,
}
impl EvidenceStore {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            records: VecDeque::new(),
            identities: BTreeMap::new(),
            bytes: 0,
            max_bytes,
            sequence: 0,
        }
    }
    pub fn insert(&mut self, record: Evidence) -> Result<String, &'static str> {
        if !record.redacted
            || record.process_epoch != record.quality.process_epoch
            || record.quality.observed_at_ms != Some(record.observed_at_ms)
            || [
                &record.node_id,
                &record.scope_id,
                &record.source_id,
                &record.source_record_id,
                &record.process_epoch,
            ]
            .iter()
            .any(|v| v.is_empty() || v.len() > 256)
        {
            return Err("invalid evidence metadata");
        }
        let bytes = serde_json::to_vec(&record).map_err(|_| "serialization failed")?;
        if bytes.len() > 32_768 || bytes.len() > self.max_bytes {
            return Err("evidence size limit");
        }
        let mut canonical = record.clone();
        // Relay receipt time is not the identity of an original source record.
        canonical.received_at_ms = 0;
        let canonical_bytes = serde_json::to_vec(&canonical).map_err(|_| "serialization failed")?;
        let digest = format!("{:x}", Sha256::digest(&canonical_bytes));
        let key = (
            record.node_id.clone(),
            record.process_epoch.clone(),
            record.source_id.clone(),
            record.source_record_id.clone(),
        );
        if let Some(existing) = self.identities.get(&key) {
            return if *existing == digest {
                Ok(existing.clone())
            } else {
                Err("immutable evidence conflict")
            };
        }
        let Some(next) = self.sequence.checked_add(1) else {
            return Err("watermark exhausted");
        };
        // Include conservative per-record index/allocator overhead in the bound.
        let size = bytes.len().checked_add(2048).ok_or("size overflow")?;
        if size > self.max_bytes {
            return Err("evidence resident limit");
        }
        while self.bytes > self.max_bytes - size {
            self.evict_one();
        }
        self.sequence = next;
        self.bytes += size;
        self.identities.insert(key, digest.clone());
        self.records.push_back((
            StoredEvidence { evidence_id: digest.clone(), watermark: next, record },
            size,
        ));
        Ok(digest)
    }
    fn evict_one(&mut self) {
        if let Some((entry, bytes)) = self.records.pop_front() {
            let e = entry.record;
            self.identities.remove(&(e.node_id, e.process_epoch, e.source_id, e.source_record_id));
            self.bytes -= bytes;
        }
    }
    pub fn expire_before(&mut self, received_ms: i64) {
        // Insertion order is independent of the source wall clock.
        let expired: Vec<_> = self
            .records
            .iter()
            .filter(|(e, _)| e.record.received_at_ms < received_ms)
            .map(|(e, _)| e.evidence_id.clone())
            .collect();
        for id in expired {
            if let Some(pos) = self.records.iter().position(|(e, _)| e.evidence_id == id) {
                if let Some((entry, size)) = self.records.remove(pos) {
                    let e = entry.record;
                    self.identities.remove(&(
                        e.node_id,
                        e.process_epoch,
                        e.source_id,
                        e.source_record_id,
                    ));
                    self.bytes -= size;
                }
            }
        }
    }
    pub fn watermark(&self) -> u64 {
        self.sequence
    }
    pub fn entries(&self) -> impl Iterator<Item = &StoredEvidence> {
        self.records.iter().map(|(entry, _)| entry)
    }
    pub fn resident_bytes(&self) -> usize {
        self.bytes
    }
}
