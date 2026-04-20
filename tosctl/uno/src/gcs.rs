//! Golomb-Coded Set decoder for per-block compact filters (§2.8.1).
//!
//! Parameters pinned by the design doc:
//!   - `P = 15` (Golomb-Rice quotient bits)
//!   - `M = 2^16 = 65536` (tag universe — matches `filter_tag` width)
//!   - No secondary hash: operates directly on u16 tags.
//!
//! Wire format:
//!
//! | Field   | Encoding                                                         |
//! |---------|------------------------------------------------------------------|
//! | `N`     | varint (LEB128) — number of tags                                 |
//! | entries | for each i ≥ 1, Δᵢ = tagᵢ - tagᵢ₋₁ - 1 encoded Golomb-Rice        |
//! |         | (quotient `q = Δᵢ >> P` in unary; remainder `r = Δᵢ & ((1<<P)-1)` |
//! |         | in `P` bits)                                                     |
//! | padding | zero-bits to byte-align                                          |
//!
//! Matches `uno/core/block-filter.cpp` byte-for-byte (per §2.8.1 spec).

use anyhow::{anyhow, Result};

const GCS_P: u32 = 15;
const GCS_P_MASK: u32 = (1u32 << GCS_P) - 1;

/// Bit-level reader over a byte slice.
struct BitReader<'a> {
    bytes: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit_pos: 0 }
    }

    /// Read one bit (MSB-first within a byte). Returns `None` at EOF.
    fn read_bit(&mut self) -> Option<bool> {
        let byte_idx = self.bit_pos >> 3;
        if byte_idx >= self.bytes.len() {
            return None;
        }
        let bit_in_byte = 7 - (self.bit_pos & 7);
        let b = (self.bytes[byte_idx] >> bit_in_byte) & 1;
        self.bit_pos += 1;
        Some(b == 1)
    }

    /// Read `n` bits (n ≤ 32), MSB-first.
    fn read_bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | (self.read_bit()? as u32);
        }
        Some(v)
    }

    /// Decode a LEB128 varint.
    fn read_varint(&mut self) -> Option<u64> {
        // Align to byte boundary first (varint is byte-oriented).
        if self.bit_pos & 7 != 0 {
            // Skip to next byte.
            self.bit_pos = (self.bit_pos + 7) & !7;
        }
        let mut v: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte_idx = self.bit_pos >> 3;
            if byte_idx >= self.bytes.len() {
                return None;
            }
            let b = self.bytes[byte_idx];
            self.bit_pos += 8;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
            shift += 7;
            if shift >= 64 { return None; }
        }
    }
}

/// Decode a block filter into the ordered list of `filter_tag` u16 values.
pub fn decode(bytes: &[u8]) -> Result<Vec<u16>> {
    let mut r = BitReader::new(bytes);
    let n = r.read_varint().ok_or_else(|| anyhow!("gcs: varint N truncated"))? as usize;

    let mut out = Vec::with_capacity(n);
    let mut last: u32 = 0;  // u32 to cover the "tagᵢ₋₁ doesn't exist yet" convention (-1)
    let mut first = true;
    for i in 0..n {
        // Unary quotient.
        let mut q: u32 = 0;
        loop {
            let bit = r.read_bit().ok_or_else(|| anyhow!("gcs: unary q truncated at i={i}"))?;
            if !bit { break; }
            q += 1;
            if q > 16 {
                return Err(anyhow!("gcs: quotient overflow at i={i}"));
            }
        }
        let rem = r.read_bits(GCS_P).ok_or_else(|| anyhow!("gcs: remainder truncated at i={i}"))?;
        let delta = ((q << GCS_P) | rem) as u32;
        let tag = if first {
            first = false;
            // First tag: tag₀ = Δ₀
            delta
        } else {
            last + delta + 1
        };
        if tag > 0xffff {
            return Err(anyhow!("gcs: decoded tag {tag} > 16-bit range"));
        }
        out.push(tag as u16);
        last = tag;
    }
    Ok(out)
}

/// Encoder — included for round-trip tests and for a future `send` path
/// that would re-build filters from assembled output sets.
pub fn encode(tags: &[u16]) -> Vec<u8> {
    let mut sorted: Vec<u16> = tags.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut bw = BitWriter::new();
    // varint N
    let mut n = sorted.len() as u64;
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            bw.write_byte(byte);
            break;
        } else {
            bw.write_byte(byte | 0x80);
        }
    }

    let mut last: i32 = -1;
    for &tag in &sorted {
        let delta: u32 = if last < 0 {
            tag as u32
        } else {
            (tag as i32 - last - 1) as u32
        };
        let q = delta >> GCS_P;
        let r = delta & GCS_P_MASK;
        for _ in 0..q { bw.write_bit(true); }
        bw.write_bit(false);
        bw.write_bits(r, GCS_P);
        last = tag as i32;
    }
    bw.finish()
}

struct BitWriter {
    bytes: Vec<u8>,
    cur: u8,
    n: u32,
    byte_aligned: bool,
}

impl BitWriter {
    fn new() -> Self {
        Self { bytes: Vec::new(), cur: 0, n: 0, byte_aligned: true }
    }

    fn write_byte(&mut self, b: u8) {
        assert!(self.byte_aligned, "write_byte called on non-aligned stream");
        self.bytes.push(b);
    }

    fn write_bit(&mut self, bit: bool) {
        self.byte_aligned = false;
        self.cur = (self.cur << 1) | (bit as u8);
        self.n += 1;
        if self.n == 8 {
            self.bytes.push(self.cur);
            self.cur = 0;
            self.n = 0;
            self.byte_aligned = true;
        }
    }

    fn write_bits(&mut self, v: u32, nbits: u32) {
        for i in (0..nbits).rev() {
            self.write_bit(((v >> i) & 1) == 1);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.cur <<= 8 - self.n;
            self.bytes.push(self.cur);
        }
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        let enc = encode(&[]);
        let dec = decode(&enc).unwrap();
        assert_eq!(dec, Vec::<u16>::new());
    }

    #[test]
    fn roundtrip_small_set() {
        let tags = vec![7u16, 42, 1000, 30000, 65535];
        let enc = encode(&tags);
        let dec = decode(&enc).unwrap();
        assert_eq!(dec, tags);
    }

    #[test]
    fn roundtrip_deduplicates_and_sorts() {
        let tags = vec![50u16, 10, 50, 10, 20];
        let enc = encode(&tags);
        let dec = decode(&enc).unwrap();
        assert_eq!(dec, vec![10, 20, 50]);
    }

    #[test]
    fn roundtrip_dense_block() {
        // Simulate a block with 60 tags (≈ 30 TPS × 2 outputs).
        let mut tags: Vec<u16> = (0..60).map(|i| (i * 997) as u16).collect();
        tags.sort_unstable();
        tags.dedup();
        let enc = encode(&tags);
        let dec = decode(&enc).unwrap();
        assert_eq!(dec, tags);
    }
}
