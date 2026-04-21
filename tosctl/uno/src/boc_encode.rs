//! BoC-encoding of a `Transfer` — byte-compatible with the daemon's
//! `uno/core/transaction.cpp::encode_transfer` + `decode_transfer_bytes`.
//!
//! # Why this module exists (V1-3b)
//!
//! `transfer::encode_transfer_wire` produces a flat self-contained byte
//! layout (varint length prefix + inline blobs). The TOS daemon's
//! `uno_sendTransfer` RPC entry point feeds raw body bytes through
//! `vm::std_boc_deserialize` and walks a Cell tree. The flat layout is
//! NOT a BoC, so the flat-encoded Transfer is rejected by the daemon
//! before any validation runs.
//!
//! `encode_transfer_boc` here emits a genuine TOS BoC whose Cell-tree
//! shape matches `uno/core/transaction.cpp::encode_transfer` exactly:
//!
//! ```text
//!   root cell (448 bits inline, 3 refs)
//!     inline: version | scheme_id | chain_id | anchor | expiry | fee | sc | oc
//!     ref[0] → spends_root  (empty inline, `sc` refs)
//!                each → per_spend cell: 127 B head + 1 ref → 1 B cont
//!     ref[1] → outputs_root (empty inline, `oc` refs)
//!                each → per_output cell:
//!                         127 B head of 146 B inline
//!                         ref[0] → 19 B continuation (inline, 0 refs)
//!                         ref[1] → enc_ciphertext chunk chain
//!                         ref[2] → mlkem_ct chunk chain
//!     ref[2] → zk_proof chunk chain
//! ```
//!
//! Chunk chains follow the CellString convention:
//!   - Up to 127 bytes inline per cell.
//!   - Trailing 1 bit: `1` = more chunks (1st ref is the next cell);
//!     `0` = terminal chunk, no ref.
//!
//! This module is the authoritative wallet-side encoder post-V1-3b.
//! `transfer::encode_transfer_wire` is retained for unit-testing the
//! flat layout and for the legacy offline `send_roundtrip` integration
//! test, but `send.rs`'s submission path routes through
//! `encode_transfer_boc` so the daemon actually accepts it.

use anyhow::{anyhow, Result};
use chain_block::boc::{BocFlags, BocWriter};
use chain_block::cell::{BuilderData, Cell, IBitstring, MAX_DEPTH};

use crate::transfer::{
    Transfer, MAX_OUTPUT_COUNT, MAX_SPEND_COUNT, MIN_OUTPUT_COUNT, MIN_SPEND_COUNT,
    OUT_CIPHERTEXT_BYTES,
};

// Mirror of `uno/core/transaction.cpp:72` `kChunkBytes`.
const CHUNK_BYTES: usize = 127;
// Mirror of `uno/core/transaction.cpp` `kItemInlineHeadBytes`. The per-spend
// and per-output cells inline up to 127 bytes, with the remainder in a
// single continuation ref.
const ITEM_INLINE_HEAD_BYTES: usize = 127;

/// Per-spend inline payload: nullifier(32) || rk(32) || spend_auth_sig(64).
/// Matches `uno/core/transaction.h` `kSpendInlineBytes = 128`.
const SPEND_INLINE_BYTES: usize = 32 + 32 + 64;
/// Per-output inline payload (excluding enc_ct / mlkem_ct refs):
/// cm(32) || epk(32) || filter_tag(2 BE) || out_ciphertext(80).
/// Matches `uno/core/transaction.h` `kOutputInlineBytes = 146`.
const OUTPUT_INLINE_BYTES: usize = 32 + 32 + 2 + OUT_CIPHERTEXT_BYTES;

// ---------------------------------------------------------------------------
// Chunk-chain helpers
// ---------------------------------------------------------------------------

/// Build a chunk-chain BoC Cell tree from a byte blob. Mirrors
/// `uno/core/transaction.cpp::store_bytes_as_chunk_chain`.
///
/// Returns `Ok(None)` for an empty input (matches the C++ helper's
/// "bytes.empty() -> {}" behavior). Non-empty inputs always produce a
/// non-null Cell.
fn store_bytes_as_chunk_chain(bytes: &[u8]) -> Result<Option<Cell>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let total = bytes.len();
    let n_chunks = (total + CHUNK_BYTES - 1) / CHUNK_BYTES;

    // Build the chain back-to-front: terminal chunk first, then prepend.
    let mut next: Option<Cell> = None;
    for i in (0..n_chunks).rev() {
        let start = i * CHUNK_BYTES;
        let end = core::cmp::min(start + CHUNK_BYTES, total);
        let chunk = &bytes[start..end];

        let mut cb = BuilderData::default();
        // Inline bytes (8 bits × chunk.len()).
        cb.append_raw(chunk, chunk.len() * 8)?;
        // has_next bit.
        if let Some(n) = next.take() {
            cb.append_bit_one()?;
            cb.checked_append_reference(n)?;
        } else {
            cb.append_bit_zero()?;
        }
        next = Some(cb.finalize(chain_block::cell::MAX_DEPTH)?);
    }
    Ok(next)
}

/// Build a "head + continuation" cell pair for a fixed-length inline
/// payload. Mirrors
/// `uno/core/transaction.cpp::append_item_head_and_continuation`.
///
/// Returns a `BuilderData` pre-populated with the inline head (up to
/// 127 B) and — if `bytes.len() > 127` — with a continuation ref as
/// its first ref. Caller can append additional refs (e.g. enc_ct,
/// mlkem_ct) and finalize.
fn item_head_and_continuation(bytes: &[u8]) -> Result<BuilderData> {
    let head = core::cmp::min(bytes.len(), ITEM_INLINE_HEAD_BYTES);
    let mut item = BuilderData::default();
    item.append_raw(&bytes[..head], head * 8)?;
    if head < bytes.len() {
        let tail = &bytes[head..];
        let mut cont = BuilderData::default();
        cont.append_raw(tail, tail.len() * 8)?;
        item.checked_append_reference(cont.finalize(chain_block::cell::MAX_DEPTH)?)?;
    }
    Ok(item)
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Encode a `Transfer` into a TOS BoC byte string that the daemon's
/// `uno/core/transaction.cpp::decode_transfer_bytes` will parse.
///
/// # Errors
///
/// - `spend_count` or `output_count` out of [MIN..=MAX] range
/// - `out_ciphertext.len() != 80`
/// - `enc_ciphertext` / `mlkem_ct` / `zk_proof` empty — the daemon
///   rejects `null` refs, so an empty ciphertext (hypothetically
///   legal but untypical) must still carry at least one chunk cell
///   with the terminal-bit set.
pub fn encode_transfer_boc(tx: &Transfer) -> Result<Vec<u8>> {
    if tx.spends.is_empty()
        || tx.spends.len() > MAX_SPEND_COUNT as usize
        || (tx.spends.len() as u8) < MIN_SPEND_COUNT
    {
        return Err(anyhow!(
            "encode_transfer_boc: spend_count {} out of [{},{}]",
            tx.spends.len(),
            MIN_SPEND_COUNT,
            MAX_SPEND_COUNT
        ));
    }
    if tx.outputs.is_empty()
        || tx.outputs.len() > MAX_OUTPUT_COUNT as usize
        || (tx.outputs.len() as u8) < MIN_OUTPUT_COUNT
    {
        return Err(anyhow!(
            "encode_transfer_boc: output_count {} out of [{},{}]",
            tx.outputs.len(),
            MIN_OUTPUT_COUNT,
            MAX_OUTPUT_COUNT
        ));
    }
    if tx.zk_proof.is_empty() {
        return Err(anyhow!(
            "encode_transfer_boc: zk_proof must be non-empty (chunk chain requires ≥ 1 cell)"
        ));
    }
    for (i, o) in tx.outputs.iter().enumerate() {
        if o.enc_ciphertext.is_empty() {
            return Err(anyhow!(
                "encode_transfer_boc: output[{}].enc_ciphertext is empty",
                i
            ));
        }
        if o.mlkem_ct.is_empty() {
            return Err(anyhow!(
                "encode_transfer_boc: output[{}].mlkem_ct is empty",
                i
            ));
        }
        if o.out_ciphertext.len() != OUT_CIPHERTEXT_BYTES {
            return Err(anyhow!(
                "encode_transfer_boc: output[{}].out_ciphertext len {} != {}",
                i,
                o.out_ciphertext.len(),
                OUT_CIPHERTEXT_BYTES
            ));
        }
    }

    // -- spends_root: empty inline + sc refs --
    let mut spends_root = BuilderData::default();
    for s in &tx.spends {
        let mut inline = [0u8; SPEND_INLINE_BYTES];
        inline[0..32].copy_from_slice(&s.nullifier);
        inline[32..64].copy_from_slice(&s.rk);
        inline[64..128].copy_from_slice(&s.spend_auth_sig);
        let item = item_head_and_continuation(&inline)?;
        spends_root.checked_append_reference(item.finalize(chain_block::cell::MAX_DEPTH)?)?;
    }
    let spends_root_cell = spends_root.finalize(chain_block::cell::MAX_DEPTH)?;

    // -- outputs_root: empty inline + oc refs --
    let mut outputs_root = BuilderData::default();
    for o in &tx.outputs {
        let mut inline = [0u8; OUTPUT_INLINE_BYTES];
        inline[0..32].copy_from_slice(&o.cm);
        inline[32..64].copy_from_slice(&o.epk);
        // filter_tag is BE u16.
        inline[64] = (o.filter_tag >> 8) as u8;
        inline[65] = (o.filter_tag & 0xFF) as u8;
        inline[66..66 + OUT_CIPHERTEXT_BYTES].copy_from_slice(&o.out_ciphertext);

        // per_output cell: 127 B head + 3 refs (cont, enc_ct, mlkem_ct).
        // item_head_and_continuation handles head + (optional) cont ref;
        // we append enc_ct + mlkem_ct refs afterwards.
        let mut item = item_head_and_continuation(&inline)?;
        let enc_chain = store_bytes_as_chunk_chain(&o.enc_ciphertext)?
            .ok_or_else(|| anyhow!("enc_ciphertext is unexpectedly empty"))?;
        let mlkem_chain = store_bytes_as_chunk_chain(&o.mlkem_ct)?
            .ok_or_else(|| anyhow!("mlkem_ct is unexpectedly empty"))?;
        item.checked_append_reference(enc_chain)?;
        item.checked_append_reference(mlkem_chain)?;
        outputs_root.checked_append_reference(item.finalize(chain_block::cell::MAX_DEPTH)?)?;
    }
    let outputs_root_cell = outputs_root.finalize(chain_block::cell::MAX_DEPTH)?;

    // -- zk_proof chunk chain --
    let zk_proof_cell = store_bytes_as_chunk_chain(&tx.zk_proof)?
        .ok_or_else(|| anyhow!("zk_proof is unexpectedly empty"))?;

    // -- root cell: 448-bit header + 3 refs --
    let mut root = BuilderData::default();
    root.append_u8(tx.version)?;
    root.append_u8(tx.scheme_id)?;
    root.append_u32(tx.chain_id)?;
    root.append_raw(&tx.anchor, 32 * 8)?;
    root.append_u64(tx.expiry_block)?;
    root.append_u64(tx.fee)?;
    root.append_u8(tx.spends.len() as u8)?;
    root.append_u8(tx.outputs.len() as u8)?;
    root.checked_append_reference(spends_root_cell)?;
    root.checked_append_reference(outputs_root_cell)?;
    root.checked_append_reference(zk_proof_cell)?;

    let root_cell = root.finalize(MAX_DEPTH)?;

    // v1 zk_proof chunk chain is ~7,400 cells deep at worst-case 4/4
    // shape; this exceeds chain_block's `MAX_SAFE_DEPTH = 2048` default.
    // Use BocWriter::with_params directly to pin a higher depth cap that
    // matches the daemon's kChunkChainMaxChunks ceiling (8192 post-V1).
    fn no_abort() -> bool {
        false
    }
    let writer = BocWriter::with_params(
        [root_cell],
        MAX_DEPTH,
        BocFlags::None,
        &no_abort,
    )?;
    let mut buf = Vec::new();
    writer.write(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::{
        OutputDescription, SpendDescription, Transfer, SCHEME_ID_V1, TRANSFER_VERSION,
    };

    /// Sample Transfer whose fields exercise every shape variant our
    /// encoder cares about: 1-spend / 2-output, non-zero anchors, non-
    /// empty variable-length blobs (enc_ct 580 B, mlkem_ct 1088 B,
    /// zk_proof 520 KB — typical v1 sizes).
    fn sample_transfer(n_spends: usize, n_outputs: usize) -> Transfer {
        let mut spends = Vec::with_capacity(n_spends);
        for i in 0..n_spends {
            let mut spend = SpendDescription {
                nullifier: [0u8; 32],
                rk: [0u8; 32],
                spend_auth_sig: [0u8; 64],
            };
            spend.nullifier[0] = i as u8;
            spend.rk[0] = (i + 0x10) as u8;
            spend.spend_auth_sig[0] = (i + 0x20) as u8;
            spends.push(spend);
        }
        let mut outputs = Vec::with_capacity(n_outputs);
        for j in 0..n_outputs {
            let mut output = OutputDescription {
                cm: [0u8; 32],
                epk: [0u8; 32],
                filter_tag: 0x4200 | (j as u16),
                enc_ciphertext: vec![0u8; 579], // realistic: 580 B - tag
                mlkem_ct: vec![0u8; 1088],      // ML-KEM-768 ct
                out_ciphertext: [0u8; 80],
            };
            output.cm[0] = (j + 0x30) as u8;
            output.epk[0] = (j + 0x40) as u8;
            for b in output.enc_ciphertext.iter_mut().take(4) {
                *b = 0xEE;
            }
            for b in output.mlkem_ct.iter_mut().take(4) {
                *b = 0xAA;
            }
            output.out_ciphertext[0] = (j + 0x50) as u8;
            outputs.push(output);
        }

        Transfer {
            version: TRANSFER_VERSION,
            scheme_id: SCHEME_ID_V1,
            chain_id: 0xCAFE_BABE,
            anchor: {
                let mut a = [0u8; 32];
                a[0] = 0xA0;
                a[31] = 0x0A;
                a
            },
            expiry_block: 0x1234_5678_9ABC_DEF0,
            fee: 100_000,
            spends,
            outputs,
            zk_proof: {
                // 520 KB of deterministic filler.
                let mut v = vec![0u8; 520 * 1024];
                for (i, b) in v.iter_mut().enumerate() {
                    *b = (i & 0xFF) as u8;
                }
                v
            },
        }
    }

    #[test]
    fn boc_encode_round_trips_through_chain_block_reader() {
        use chain_block::boc::BocReader;
        use std::io::Cursor;

        let tx = sample_transfer(1, 2);
        let bytes = encode_transfer_boc(&tx).expect("encode");
        let mut cursor = Cursor::new(bytes.clone());
        let parsed = BocReader::new()
            .set_max_cell_depth(MAX_DEPTH)
            .read(&mut cursor)
            .expect("read_boc");

        // Single root.
        assert_eq!(parsed.roots.len(), 1, "one root cell");
        let root = &parsed.roots[0];

        // Root inline is 448 bits (header).
        assert_eq!(
            root.bit_length(),
            56 * 8,
            "root inline must be 56 bytes = 448 bits"
        );
        assert_eq!(root.references_count(), 3, "root must have 3 refs");
    }

    #[test]
    fn boc_encode_shape_dispatch_all_envelopes() {
        // Sweep the 1..=4 × 1..=4 envelope. Every shape must encode
        // without panic and produce at least the 448-bit header + 3 refs.
        use chain_block::boc::BocReader;
        use std::io::Cursor;

        for n_s in 1..=4 {
            for n_o in 1..=4 {
                let tx = sample_transfer(n_s, n_o);
                let bytes = encode_transfer_boc(&tx)
                    .unwrap_or_else(|e| panic!("{n_s}/{n_o} encode: {e}"));
                let mut cursor = std::io::Cursor::new(bytes);
                let parsed = BocReader::new()
                    .set_max_cell_depth(MAX_DEPTH)
                    .read(&mut cursor)
                    .unwrap_or_else(|e| panic!("{n_s}/{n_o} read_boc: {e}"));
                assert_eq!(parsed.roots.len(), 1);
                let root = &parsed.roots[0];
                assert_eq!(root.references_count(), 3);

                // spends_root should have `n_s` refs; outputs_root `n_o`.
                let spends_root = root.reference(0).expect("spends_root");
                assert_eq!(
                    spends_root.references_count(),
                    n_s,
                    "{n_s}/{n_o} spends_root ref count"
                );
                let outputs_root = root.reference(1).expect("outputs_root");
                assert_eq!(
                    outputs_root.references_count(),
                    n_o,
                    "{n_s}/{n_o} outputs_root ref count"
                );
                // zk_proof chunk chain's first cell is at ref[2]; it has
                // 127 B inline + 1 has-next bit = 1017 bits, and either
                // 0 or 1 refs depending on payload size.
                let zk_root = root.reference(2).expect("zk_proof");
                assert_eq!(
                    zk_root.bit_length(),
                    127 * 8 + 1,
                    "zk_proof first cell: 127 B + 1 has_next bit"
                );
            }
        }
    }

    #[test]
    fn boc_encode_rejects_out_of_range_shapes() {
        let mut tx = sample_transfer(1, 1);
        tx.spends.clear();
        assert!(encode_transfer_boc(&tx).is_err(), "0 spends must reject");

        let mut tx = sample_transfer(1, 1);
        tx.outputs.clear();
        assert!(encode_transfer_boc(&tx).is_err(), "0 outputs must reject");

        // Build a 5-spend Transfer manually — over the 4 cap.
        let mut tx = sample_transfer(4, 1);
        let copy = tx.spends[0].clone();
        tx.spends.push(copy);
        assert!(encode_transfer_boc(&tx).is_err(), "5 spends must reject");
    }

    #[test]
    fn boc_encode_rejects_empty_zk_proof() {
        let mut tx = sample_transfer(1, 1);
        tx.zk_proof.clear();
        assert!(encode_transfer_boc(&tx).is_err());
    }

    #[test]
    fn boc_encode_rejects_empty_enc_or_mlkem() {
        let mut tx = sample_transfer(1, 1);
        tx.outputs[0].enc_ciphertext.clear();
        assert!(encode_transfer_boc(&tx).is_err());

        let mut tx = sample_transfer(1, 1);
        tx.outputs[0].mlkem_ct.clear();
        assert!(encode_transfer_boc(&tx).is_err());
    }

    #[test]
    fn boc_encode_chunk_chain_terminates_with_has_next_zero() {
        use chain_block::boc::BocReader;
        use std::io::Cursor;

        let tx = sample_transfer(1, 1);
        let bytes = encode_transfer_boc(&tx).expect("encode");
        let mut cursor = Cursor::new(bytes.clone());
        let parsed = BocReader::new()
            .set_max_cell_depth(MAX_DEPTH)
            .read(&mut cursor)
            .expect("read_boc");
        let root = &parsed.roots[0];

        // Walk the zk_proof chunk chain to the tail — verify every
        // intermediate cell has 127 B inline + 1 has_next bit + 1 ref,
        // and the terminal cell has its has_next bit cleared + 0 refs.
        let mut cell = root.reference(2).expect("zk_proof root").clone();
        let mut depth = 0usize;
        loop {
            depth += 1;
            let bits = cell.bit_length();
            let refs = cell.references_count();

            // Payload bytes = (bits - 1) / 8. Must be ≤ 127.
            assert!(
                bits >= 1 && (bits - 1) % 8 == 0,
                "chunk cell has 8k+1 bits; got {bits}"
            );
            let payload_bytes = (bits - 1) / 8;
            assert!(payload_bytes <= 127, "chunk payload ≤ 127 B");

            if refs == 0 {
                // Terminal chunk — has_next bit should be 0.
                break;
            } else {
                assert_eq!(refs, 1, "non-terminal chunk has exactly 1 ref");
                cell = cell.reference(0).unwrap().clone();
            }
            assert!(depth < 10_000, "chunk chain too long, likely bug");
        }
        // 520 KB / 127 = ~4,096 chunks; assert we walked roughly that.
        assert!(depth > 1000 && depth < 5000, "depth ~ 4,100 expected; got {depth}");
    }
}
