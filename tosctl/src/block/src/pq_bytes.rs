/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
//! Canonical bounded-bytes -> cell tree (PQBytes), the exact counterpart of
//! crypto/pq/pq-bytes.cpp. ML-DSA-44 public keys (1312 B) and signatures (2420 B)
//! exceed the 127-byte cell payload, so they are stored as a greedy 127-byte snake:
//! the root cell holds the u32 length, data cells are full except the last. A given
//! byte string encodes to exactly one tree; unpack rejects oversize and any
//! non-canonical tree. Cross-language parity is locked by the shared vector fixture
//! test/pq-mldsa44/pq-bytes-vectors.txt (generated authoritatively by the C++ side).

use crate::{fail, BuilderData, Cell, IBitstring, Result, SliceData};

pub const PQ_BYTES_CHUNK: usize = 127;

/// Absolute structural ceiling, enforced independently of the caller's `max_bytes`
/// and before any allocation or traversal, so the effective bound is always
/// `min(max_bytes, PQ_BYTES_HARD_MAX)`. Mirrors `pq_bytes_hard_max` in
/// crypto/pq/pq-bytes.h; the two must stay equal.
pub const PQ_BYTES_HARD_MAX: usize = 8192;

pub fn pack_pq_bytes(data: &[u8], max_bytes: usize) -> Result<Cell> {
    let len = data.len();
    // Both bounds apply: the caller's limit and the absolute ceiling. Never just the caller's.
    if len > max_bytes || len > PQ_BYTES_HARD_MAX || max_bytes > 0xffff_ffff {
        fail!("pq-bytes: oversize")
    }
    let mut next: Option<Cell> = None;
    if len > 0 {
        let nchunks = len.div_ceil(PQ_BYTES_CHUNK);
        for i in (0..nchunks).rev() {
            let off = i * PQ_BYTES_CHUNK;
            let n = core::cmp::min(PQ_BYTES_CHUNK, len - off);
            let mut b = BuilderData::new();
            b.append_raw(&data[off..off + n], n * 8)?;
            if let Some(c) = next.take() {
                b.checked_append_reference(c)?;
            }
            next = Some(b.into_cell()?);
        }
    }
    let mut root = BuilderData::new();
    root.append_bits(len, 32)?;
    if let Some(c) = next {
        root.checked_append_reference(c)?;
    }
    root.into_cell()
}

pub fn unpack_pq_bytes(root: &Cell, max_bytes: usize) -> Result<Vec<u8>> {
    let mut cs = SliceData::load_cell_ref(root)?;
    if cs.remaining_bits() != 32 {
        fail!("pq-bytes: root bits")
    }
    // The declared length is attacker-controlled: bound it against BOTH the caller limit
    // and the absolute ceiling before allocating or walking a single cell.
    let len = cs.get_next_int(32)? as usize;
    if len > max_bytes || len > PQ_BYTES_HARD_MAX {
        fail!("pq-bytes: oversize")
    }
    if len == 0 {
        if cs.remaining_references() != 0 {
            fail!("pq-bytes: empty with ref")
        }
        return Ok(Vec::new());
    }
    if cs.remaining_references() != 1 {
        fail!("pq-bytes: root ref")
    }
    let mut out: Vec<u8> = Vec::with_capacity(len);
    let mut cur = cs.checked_drain_reference()?;
    loop {
        let mut dc = SliceData::load_cell(cur)?;
        let n = core::cmp::min(PQ_BYTES_CHUNK, len - out.len());
        if dc.remaining_bits() != n * 8 {
            fail!("pq-bytes: chunk bits")
        }
        out.extend_from_slice(&dc.get_next_bytes(n)?);
        if out.len() == len {
            if dc.remaining_references() != 0 {
                fail!("pq-bytes: trailing ref")
            }
            break;
        }
        if dc.remaining_references() != 1 {
            fail!("pq-bytes: chunk ref")
        }
        cur = dc.checked_drain_reference()?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read_single_root_boc;

    #[test]
    fn shared_vectors_match_cpp() {
        let path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../../test/pq-mldsa44/pq-bytes-vectors.txt");
        let text = std::fs::read_to_string(path).expect("shared vector fixture");
        let mut count = 0;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split(' ').collect();
            assert_eq!(parts.len(), 3, "bad fixture line");
            let input = hex::decode(parts[0]).unwrap();
            let root_hex = parts[1];
            let boc = hex::decode(parts[2]).unwrap();

            // The C++-produced BOC decodes to a cell with the recorded hash, and unpacks
            // to the input -> Rust decode agrees with the C++ encoding.
            let cell = read_single_root_boc(&boc).unwrap();
            assert_eq!(cell.repr_hash().as_hex_string(), root_hex);
            assert_eq!(unpack_pq_bytes(&cell, 2420).unwrap(), input);
            // Rust encode of the same input yields the identical cell -> byte-exact parity.
            let packed = pack_pq_bytes(&input, 2420).unwrap();
            assert_eq!(packed.repr_hash().as_hex_string(), root_hex);
            count += 1;
        }
        assert!(count >= 8, "expected the full vector set");
    }

    // Build an arbitrary (possibly malformed) tree so each canonicality rule can be
    // attacked individually. A rule that no test can break is not an enforced rule.
    fn data_cell(bytes: &[u8], refs: Vec<Cell>) -> Cell {
        let mut b = BuilderData::new();
        b.append_raw(bytes, bytes.len() * 8).unwrap();
        for r in refs {
            b.checked_append_reference(r).unwrap();
        }
        b.into_cell().unwrap()
    }

    fn root_cell(len: usize, bits: usize, refs: Vec<Cell>) -> Cell {
        let mut b = BuilderData::new();
        b.append_bits(len, bits).unwrap();
        for r in refs {
            b.checked_append_reference(r).unwrap();
        }
        b.into_cell().unwrap()
    }

    // A well-formed snake of arbitrary length, mirroring pack_pq_bytes but without the
    // ceiling check, so the ceiling can be attacked with an otherwise canonical tree.
    fn snake(len: usize) -> Cell {
        let mut next: Option<Cell> = None;
        if len > 0 {
            let nchunks = len.div_ceil(PQ_BYTES_CHUNK);
            for i in (0..nchunks).rev() {
                let off = i * PQ_BYTES_CHUNK;
                let n = core::cmp::min(PQ_BYTES_CHUNK, len - off);
                let mut b = BuilderData::new();
                b.append_raw(&vec![5u8; n], n * 8).unwrap();
                if let Some(c) = next.take() {
                    b.checked_append_reference(c).unwrap();
                }
                next = Some(b.into_cell().unwrap());
            }
        }
        root_cell(len, 32, next.into_iter().collect())
    }

    #[test]
    fn oversize_and_canonical_negatives() {
        // caller limit
        assert!(pack_pq_bytes(&vec![0u8; 2421], 2420).is_err());
        let p = pack_pq_bytes(&vec![7u8; 2420], 2420).unwrap();
        assert!(unpack_pq_bytes(&p, 1312).is_err());

        // absolute ceiling: a permissive caller limit must NOT unlock it
        assert!(pack_pq_bytes(&vec![0u8; PQ_BYTES_HARD_MAX + 1], 0xffff_ffff).is_err());
        assert!(pack_pq_bytes(&vec![0u8; PQ_BYTES_HARD_MAX], 0xffff_ffff).is_ok());
        // Otherwise perfectly canonical snakes, so the ONLY thing that can reject them
        // is the ceiling itself (built by hand because pack refuses to exceed it).
        assert!(unpack_pq_bytes(&snake(PQ_BYTES_HARD_MAX), 0xffff_ffff).is_ok());
        assert!(unpack_pq_bytes(&snake(PQ_BYTES_HARD_MAX + 1), 0xffff_ffff).is_err());
        // a 4 GiB declaration is refused by the same length gate, before any allocation
        assert!(unpack_pq_bytes(&root_cell(0xffff_ffff, 32, vec![]), 0xffff_ffff).is_err());

        // root bit-width: 31 and 33 are both non-canonical
        assert!(unpack_pq_bytes(&root_cell(0, 31, vec![]), 2420).is_err());
        assert!(unpack_pq_bytes(&root_cell(0, 33, vec![]), 2420).is_err());

        // zero length must carry no ref
        assert!(
            unpack_pq_bytes(&root_cell(0, 32, vec![data_cell(&[1u8; 1], vec![])]), 2420).is_err()
        );
        assert!(unpack_pq_bytes(&root_cell(0, 32, vec![]), 2420).unwrap().is_empty());

        // root ref count must be exactly 1 when len > 0
        assert!(unpack_pq_bytes(&root_cell(10, 32, vec![]), 2420).is_err());
        let two =
            root_cell(10, 32, vec![data_cell(&[1u8; 10], vec![]), data_cell(&[1u8; 10], vec![])]);
        assert!(unpack_pq_bytes(&two, 2420).is_err());

        // middle cell must have exactly 1 ref (0 and 2 both rejected)
        let mid0 = root_cell(200, 32, vec![data_cell(&[1u8; 127], vec![])]);
        assert!(unpack_pq_bytes(&mid0, 2420).is_err());
        let tail = data_cell(&[1u8; 73], vec![]);
        let mid2 =
            root_cell(200, 32, vec![data_cell(&[1u8; 127], vec![tail.clone(), tail.clone()])]);
        assert!(unpack_pq_bytes(&mid2, 2420).is_err());

        // final cell must carry no trailing ref
        let trailing = root_cell(127, 32, vec![data_cell(&[1u8; 127], vec![tail.clone()])]);
        assert!(unpack_pq_bytes(&trailing, 2420).is_err());

        // non-full middle chunk (100 instead of 127)
        let short_mid =
            root_cell(227, 32, vec![data_cell(&[1u8; 100], vec![data_cell(&[1u8; 127], vec![])])]);
        assert!(unpack_pq_bytes(&short_mid, 2420).is_err());

        // declared length > actual bytes, and < actual bytes
        let over = root_cell(300, 32, vec![data_cell(&[1u8; 127], vec![tail.clone()])]);
        assert!(unpack_pq_bytes(&over, 2420).is_err());
        let under = root_cell(100, 32, vec![data_cell(&[1u8; 127], vec![])]);
        assert!(unpack_pq_bytes(&under, 2420).is_err());

        // final chunk longer than the remaining declared bytes
        let long_final =
            root_cell(130, 32, vec![data_cell(&[1u8; 127], vec![data_cell(&[1u8; 10], vec![])])]);
        assert!(unpack_pq_bytes(&long_final, 2420).is_err());

        // non-byte-aligned payload: 100 bits where 12 whole bytes are required
        let mut odd = BuilderData::new();
        odd.append_raw(&[0u8; 13], 100).unwrap(); // 100 bits: not a whole number of bytes
        let odd = root_cell(12, 32, vec![odd.into_cell().unwrap()]);
        assert!(unpack_pq_bytes(&odd, 2420).is_err());
    }
}
