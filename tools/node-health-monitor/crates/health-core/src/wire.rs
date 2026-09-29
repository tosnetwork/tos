//! Exact wire scalars and the fixed diagnostic datagram contract.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct U64(pub u64);
impl Serialize for U64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for U64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        exact_u64(&value).map(Self).map_err(serde::de::Error::custom)
    }
}
pub fn exact_u64(value: &str) -> Result<u64, &'static str> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("canonical ASCII decimal string required");
    }
    value.parse().map_err(|_| "u64 overflow")
}
pub fn hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
pub fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticRecord {
    pub record_type: u16,
    pub source_catalog_id: u32,
    pub epoch: [u8; 16],
    pub sequence: u64,
    pub monotonic_ns: u64,
    pub wall_unix_ns: Option<u64>,
    pub payload: Vec<u8>,
}
impl DiagnosticRecord {
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        if !diagnostic_payload(self.source_catalog_id, self.record_type, &self.payload) {
            return Err("unknown catalog or payload");
        }
        let mut out = vec![0u8; 64 + self.payload.len()];
        out[..4].copy_from_slice(b"THD1");
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        out[6..8].copy_from_slice(&64u16.to_le_bytes());
        let total = out.len() as u16;
        out[8..10].copy_from_slice(&total.to_le_bytes());
        out[10..12].copy_from_slice(&self.record_type.to_le_bytes());
        out[12..16].copy_from_slice(&self.source_catalog_id.to_le_bytes());
        out[16..32].copy_from_slice(&self.epoch);
        out[32..40].copy_from_slice(&self.sequence.to_le_bytes());
        out[40..48].copy_from_slice(&self.monotonic_ns.to_le_bytes());
        out[48..56].copy_from_slice(&self.wall_unix_ns.unwrap_or(0).to_le_bytes());
        out[56..58].copy_from_slice(&(self.payload.len() as u16).to_le_bytes());
        out[58..60].copy_from_slice(&u16::from(self.wall_unix_ns.is_some()).to_le_bytes());
        out[64..].copy_from_slice(&self.payload);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 64 || bytes.len() > 512 || &bytes[..4] != b"THD1" {
            return Err("invalid frame");
        }
        let u16_at = |p| u16::from_le_bytes([bytes[p], bytes[p + 1]]);
        let u32_at = |p| u32::from_le_bytes([bytes[p], bytes[p + 1], bytes[p + 2], bytes[p + 3]]);
        let u64_at = |p| {
            u64::from_le_bytes([
                bytes[p],
                bytes[p + 1],
                bytes[p + 2],
                bytes[p + 3],
                bytes[p + 4],
                bytes[p + 5],
                bytes[p + 6],
                bytes[p + 7],
            ])
        };
        let flags = u16_at(58);
        if u16_at(4) != 1
            || u16_at(6) != 64
            || usize::from(u16_at(8)) != bytes.len()
            || usize::from(u16_at(56)) + 64 != bytes.len()
            || u32_at(60) != 0
            || flags & !1 != 0
            || (flags == 0 && u64_at(48) != 0)
        {
            return Err("invalid header");
        }
        if !diagnostic_payload(u32_at(12), u16_at(10), &bytes[64..]) {
            return Err("unknown catalog or payload");
        }
        let mut epoch = [0; 16];
        epoch.copy_from_slice(&bytes[16..32]);
        Ok(Self {
            record_type: u16_at(10),
            source_catalog_id: u32_at(12),
            epoch,
            sequence: u64_at(32),
            monotonic_ns: u64_at(40),
            wall_unix_ns: if flags == 1 { Some(u64_at(48)) } else { None },
            payload: bytes[64..].to_vec(),
        })
    }
}
pub fn diagnostic_payload(catalog: u32, record_type: u16, payload: &[u8]) -> bool {
    record_type == 1 && match catalog {
        7 => payload.len() == 2,
        8 => payload.len() == 4 && payload[0] < 4 && payload[1] < 3 && payload[2] < 22 && payload[3] == 0,
        _ => false,
    }
}
