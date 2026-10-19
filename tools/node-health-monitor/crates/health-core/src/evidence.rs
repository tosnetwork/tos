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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredEvidence {
    pub evidence_id: String,
    pub watermark: u64,
    pub record: Evidence,
}
#[derive(Debug, Clone)]
pub struct EvidenceStore {
    records: VecDeque<(StoredEvidence, usize)>,
    identities: BTreeMap<(String, String, String, String), String>,
    bytes: usize,
    max_bytes: usize,
    sequence: u64,
}
/// Upper bound on decoded payload nodes per evidence record.
pub const MAX_PAYLOAD_NODES: usize = 4096;
/// Inline size of one decoded JSON value (an array slot or a map value).
const VALUE_BYTES: usize = std::mem::size_of::<serde_json::Value>();
/// Inline size of an owned string handle (pointer, capacity, length).
const STRING_HEAD_BYTES: usize = std::mem::size_of::<String>();
/// One ordered-map node holds up to eleven entries; nodes other than the
/// root are at least half full, so entries are charged in half-node units.
const MAP_NODE_BYTES: usize = 11 * (STRING_HEAD_BYTES + VALUE_BYTES) + 12 * 8 + 16;
const MAP_ENTRIES_PER_CHARGED_NODE: usize = 6;
/// Largest resident charge one record can carry: every node a one-entry
/// map on its own node, plus the wire bound and the per-record overhead. A
/// validation probe must allow at least this much or it refuses legitimate
/// records; a decoded record is routinely eight times its wire size.
pub const MAX_RECORD_RESIDENT_BYTES: usize =
    MAX_PAYLOAD_NODES * (MAP_NODE_BYTES + VALUE_BYTES) + 32_768 + 2048;

/// Number of `serde_json::Value` nodes in a tree (scalars included).
pub fn value_nodes(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(items) => {
            1 + items.iter().map(value_nodes).fold(0usize, |a, b| a.saturating_add(b))
        }
        serde_json::Value::Object(map) => {
            1 + map.values().map(value_nodes).fold(0usize, |a, b| a.saturating_add(b))
        }
        _ => 1,
    }
}

/// Heap bytes owned by a decoded value, not counting the value's own inline
/// slot: a string's allocated capacity, an array's allocated slots (used or
/// not) plus what those slots own, a map's nodes plus its keys' capacities
/// and what its values own. Capacities, not lengths: a deserializer grows a
/// vector by doubling, so a 3000-element array commonly holds 4096 slots.
fn heap_footprint(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => 0,
        serde_json::Value::String(text) => text.capacity(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(heap_footprint)
            .fold(items.capacity().saturating_mul(VALUE_BYTES), |a, b| a.saturating_add(b)),
        serde_json::Value::Object(map) => {
            let nodes = map.len().div_ceil(MAP_ENTRIES_PER_CHARGED_NODE).max(1);
            map.iter().fold(nodes.saturating_mul(MAP_NODE_BYTES), |acc, (key, item)| {
                acc.saturating_add(key.capacity()).saturating_add(heap_footprint(item))
            })
        }
    }
}

/// Resident-heap estimate of a decoded `serde_json::Value` as it is actually
/// allocated: the value's own slot plus everything it owns, by capacity.
pub fn value_footprint(value: &serde_json::Value) -> usize {
    VALUE_BYTES.saturating_add(heap_footprint(value))
}

/// Release the slack a deserializer leaves behind, so the charged capacity
/// and the kept allocation are the same number.
pub fn shrink_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.shrink_to_fit(),
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                shrink_value(item);
            }
            items.shrink_to_fit();
        }
        serde_json::Value::Object(map) => {
            for item in map.values_mut() {
                shrink_value(item);
            }
        }
        _ => {}
    }
}

/// Everything a stored record owns on the heap: its identity strings by
/// capacity and its payload tree by capacity.
pub fn record_footprint(record: &Evidence) -> usize {
    [
        &record.node_id,
        &record.scope_id,
        &record.source_id,
        &record.source_record_id,
        &record.process_epoch,
        &record.quality.process_epoch,
        &record.quality.source_sequence,
    ]
    .iter()
    .map(|text| text.capacity())
    .fold(value_footprint(&record.payload), |a, b| a.saturating_add(b))
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
    pub fn restore(
        max_bytes: usize,
        sequence: u64,
        entries: impl IntoIterator<Item = StoredEvidence>,
    ) -> Result<Self, &'static str> {
        let mut store = Self::new(max_bytes);
        for entry in entries {
            if entry.watermark == 0
                || entry.watermark <= store.sequence
                || entry.watermark > sequence
            {
                return Err("invalid restored watermark");
            }
            store.sequence = entry.watermark - 1;
            // Rows written under an earlier resident charge may no longer fit
            // or may exceed the node bound; replay evicts the oldest or skips
            // the row rather than refusing to start, and the watermark stays
            // continuous. Identity and sequence are still exact.
            match store.insert(entry.record) {
                Ok(id) if id == entry.evidence_id && store.sequence == entry.watermark => {}
                Ok(_) => return Err("invalid restored evidence"),
                Err("evidence payload node limit") => store.sequence = entry.watermark,
                Err(error) => return Err(error),
            }
        }
        store.sequence = sequence;
        Ok(store)
    }
    pub fn insert(&mut self, mut record: Evidence) -> Result<String, &'static str> {
        if !record.redacted
            || record.process_epoch != record.quality.process_epoch
            || !(record.quality.observed_at_ms == Some(record.observed_at_ms)
                || (record.quality.observed_at_ms.is_none()
                    && !record.quality.clock_valid
                    && record.observed_at_ms == 0))
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
        // The payload stays resident as a decoded tree, not as its JSON text:
        // a short scalar costs a whole Value, so the resident charge is the
        // larger of the two, and a tree of many tiny nodes is refused outright.
        if value_nodes(&record.payload) > MAX_PAYLOAD_NODES {
            return Err("evidence payload node limit");
        }
        // Keep exactly what is charged: drop deserializer slack first, then
        // charge the record's real capacities (strings, array slots, map
        // nodes), never its lengths.
        shrink_value(&mut record.payload);
        for text in [
            &mut record.node_id,
            &mut record.scope_id,
            &mut record.source_id,
            &mut record.source_record_id,
            &mut record.process_epoch,
            &mut record.quality.process_epoch,
            &mut record.quality.source_sequence,
        ] {
            text.shrink_to_fit();
        }
        let footprint = record_footprint(&record);
        // Relay receipt time is not the identity of an original source record.
        // Serialize with it zeroed in place instead of cloning the whole tree:
        // the transient peak is then the two encodings, each under 32 KiB.
        let received_at_ms = record.received_at_ms;
        record.received_at_ms = 0;
        let canonical_bytes = serde_json::to_vec(&record).map_err(|_| "serialization failed")?;
        record.received_at_ms = received_at_ms;
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
        let size = bytes.len().max(footprint).checked_add(2048).ok_or("size overflow")?;
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
    /// Remove one stored record by evidence id (an expired projection parent);
    /// the watermark is never reused.
    pub fn remove(&mut self, evidence_id: &str) -> bool {
        let Some(index) = self.records.iter().position(|(e, _)| e.evidence_id == evidence_id)
        else {
            return false;
        };
        if let Some((entry, bytes)) = self.records.remove(index) {
            let e = entry.record;
            self.identities.remove(&(e.node_id, e.process_epoch, e.source_id, e.source_record_id));
            self.bytes = self.bytes.saturating_sub(bytes);
            return true;
        }
        false
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
    /// After restart, no new record may enter an earlier run's fixed W even
    /// when the old evidence cache is unavailable. This is fail-closed, not a
    /// substitute for durable evidence restoration.
    pub fn advance_watermark_floor(&mut self, floor: u64) -> Result<(), &'static str> {
        if !self.records.is_empty() {
            return Err("watermark floor requires an empty store");
        }
        self.sequence = self.sequence.max(floor);
        Ok(())
    }
    pub fn entries(&self) -> impl Iterator<Item = &StoredEvidence> {
        self.records.iter().map(|(entry, _)| entry)
    }
    pub fn resident_bytes(&self) -> usize {
        self.bytes
    }
}
