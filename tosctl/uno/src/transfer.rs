//! Rust-side mirror of the `Transfer` wire format (§4.1).
//!
//! This module is the sender-side counterpart to `wire.rs` (which only parses
//! `OutputDescription` for the scan path). It supplies:
//!
//! - `SpendDescription` / `OutputDescription` / `Transfer` structs,
//! - note-commitment computation (`compute_note_commitment`, §3.2),
//! - the canonical `tx_hash` formula (§4.1),
//! - a flat-bytes serialization consumed by the P.6 foundation `send` path
//!   (see `src/send.rs`).
//!
//! # Scope and parity caveat
//!
//! This module provides the flat self-contained byte layout for
//! `encode_transfer_wire` / `decode_transfer_wire`. It is used by the
//! offline `tests/send_roundtrip.rs` to exercise the end-to-end send
//! pipeline through a tosctl-uno-internal codec pair, and its
//! `canonical_tx_hash` formula mirrors the consensus-bound preimage
//! the daemon signs over.
//!
//! **Daemon-compatible path (V1-3b, landed)**: production submission
//! (`send::run_send`) routes through `crate::boc_encode::encode_transfer_boc`
//! instead of the flat encoder below. That emitter produces TOS BoC
//! bytes whose Cell tree matches `uno/core/transaction.cpp::encode_transfer`
//! exactly; the daemon's `std_boc_deserialize`-based
//! `decode_transfer_bytes` parses them cleanly. The flat encoder here
//! is NOT daemon-compatible (flat layout vs Cell tree); it exists only
//! so the offline plumbing test can round-trip without depending on
//! the daemon's BoC reader.
//!
//! The flat `canonical_tx_hash` below uses `BLAKE3(enc_ct_bytes)` as
//! the "cell hash" proxy, which is NOT bit-identical to
//! `uno/core/transaction.cpp::canonical_tx_hash` (which uses the TOS
//! cell-root hash). The production path recomputes the canonical
//! tx_hash via BoC cell-root hashing once BoC encoding is complete;
//! offline tests still verify structural properties via the flat path.
//!
//! Inline layout of `encode_transfer_wire` (flat bytes, self-contained):
//!
//! | Offset            | Len | Field                             |
//! |-------------------|-----|-----------------------------------|
//! | 0                 | 1   | version (=1)                      |
//! | 1                 | 1   | scheme_id (=0x01)                 |
//! | 2                 | 4   | chain_id (BE u32)                 |
//! | 6                 | 32  | anchor                            |
//! | 38                | 8   | expiry_block (BE u64)             |
//! | 46                | 8   | fee (BE u64)                      |
//! | 54                | 1   | spend_count                       |
//! | 55                | 1   | output_count                      |
//! | 56                | *   | spends × 128 B inline             |
//! | …                 | *   | outputs × (32+32+2+LEN+LEN+80) B  |
//! | …                 | *   | LEN-prefix zk_proof blob (varint) |
//!
//! `enc_ciphertext` and `mlkem_ct` are serialized inline with a LEB128
//! length prefix rather than as cell refs. This matches what `scan.rs`
//! already accepts for `OutputDescription` (see `wire.rs`) — the receive
//! side is the ground truth for P.6.

use anyhow::{anyhow, Result};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

use crate::poseidon2;
use crate::sizes::DIGEST;

// Goldilocks p used for canonical wrapped-load of limbs.
const P_GL: u64 = <Goldilocks as p3_field::PrimeField64>::ORDER_U64;

// ---------------------------------------------------------------------------
// Constants from the design doc §4.1 / §4.2
// ---------------------------------------------------------------------------

/// Protocol version.
pub const TRANSFER_VERSION: u8 = 1;
/// `scheme_id = 0x01` — v1 Plonky3 / Goldilocks / Poseidon2.
pub const SCHEME_ID_V1: u8 = 0x01;
/// Inline header size (version..output_count).
pub const TRANSFER_HEADER_BYTES: usize = 1 + 1 + 4 + 32 + 8 + 8 + 1 + 1;
/// Inline per-spend size: nullifier(32) + rk(32) + sig(64).
pub const SPEND_INLINE_BYTES: usize = 32 + 32 + 64;
/// Inline per-output size (excluding the two variable-length blobs):
/// cm(32) + epk(32) + filter_tag(2) + out_ciphertext(80) = 146.
pub const OUTPUT_INLINE_BYTES: usize = 32 + 32 + 2 + 80;
/// `out_ciphertext` is a fixed 80-byte AEAD blob recoverable with `ovk`.
pub const OUT_CIPHERTEXT_BYTES: usize = 80;
/// Minimum / maximum transfer shape (§4.1).
pub const MIN_SPEND_COUNT: u8 = 1;
pub const MAX_SPEND_COUNT: u8 = 4;
pub const MIN_OUTPUT_COUNT: u8 = 1;
pub const MAX_OUTPUT_COUNT: u8 = 4;

/// Anchor lookback window: §4.3 step 1.5 says valid anchor must appear in
/// the last 100 roots. Expiry convention for wallets: `current + 32`.
pub const DEFAULT_EXPIRY_DELTA_BLOCKS: u64 = 32;

/// Canonical STARK proof blob size used for the scaffold-stub zk_proof.
/// 43 bytes is arbitrary — it just needs to be (a) recognizable as a stub,
/// (b) non-zero-length so encoder/decoder round-trip exercises the ref
/// path. Real proofs are 40–100 KB per §4.1.
pub const STUB_PROOF_BYTES: usize = 43;

// ---------------------------------------------------------------------------
// Wire structs
// ---------------------------------------------------------------------------

/// A single spend. `spend_auth_sig` is the 64-byte Schnorr-on-Ristretto255
/// signature of `tx_hash` under the fresh per-spend `rsk`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendDescription {
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub spend_auth_sig: [u8; 64],
}

/// A single output. `enc_ciphertext` / `mlkem_ct` are variable-length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputDescription {
    pub cm: [u8; 32],
    pub epk: [u8; 32],
    pub filter_tag: u16,
    pub enc_ciphertext: Vec<u8>,
    pub mlkem_ct: Vec<u8>,
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_BYTES],
}

/// A v1 Transfer. Shape bounds: `1 ≤ spends.len() ≤ 4` and
/// `1 ≤ outputs.len() ≤ 4`. `zk_proof` is the Plonky3 STARK proof blob;
/// the scaffold-stub value is `vec![0u8; STUB_PROOF_BYTES]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub version: u8,
    pub scheme_id: u8,
    pub chain_id: u32,
    pub anchor: [u8; 32],
    pub expiry_block: u64,
    pub fee: u64,
    pub spends: Vec<SpendDescription>,
    pub outputs: Vec<OutputDescription>,
    pub zk_proof: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Note commitment (§3.2)
// ---------------------------------------------------------------------------

/// Inputs to `compute_note_commitment`. Mirrors C++
/// `uno_workchain::NoteCommitmentInputs`.
#[derive(Clone, Debug)]
pub struct NoteCommitmentInputs<'a> {
    pub d: &'a [u8; 11],
    pub pk_d_bytes: &'a [u8; 32],
    pub ivk_commitment: &'a [u8; 32],
    pub value: u64,
    /// `rcm = Poseidon2("uno-rcm-v1", rseed)` — 32 canonical bytes.
    pub rcm: &'a [u8; 32],
}

/// `rcm = Poseidon2("uno-rcm-v1", rseed)` (§3.1).
pub fn compute_rcm(rseed: &[u8; 32]) -> [u8; 32] {
    poseidon2::hash_tagged_bytes(b"uno-rcm-v1", rseed)
}

/// `cm = Poseidon2("uno-cm-v1", d, pk_d.bytes, ivk_commitment, value, rcm)`
/// (§3.2).
///
/// Input packing matches C++ `uno_workchain::compute_note_commitment`:
///   - d (11 B) → 2 fes (LE u64 of 8-byte halves, zero-padded).
///   - pk_d.bytes (32 B) → 4 fes (each limb is 8 bytes LE u64, wrapped-load).
///   - ivk_commitment (32 B) → 4 fes (same packing).
///   - value (u64) → 1 fe.
///   - rcm (32 B) → 4 fes (same packing).
/// Total: 15 fes → one width-16 Poseidon2 permutation.
pub fn compute_note_commitment(input: &NoteCommitmentInputs<'_>) -> [u8; DIGEST] {
    let mut fes: Vec<Goldilocks> = Vec::with_capacity(15);

    // d (11 B) — pad to 16 B, split into two 8-byte LE u64 limbs, wrapped.
    let mut padded = [0u8; 16];
    padded[..11].copy_from_slice(input.d);
    fes.extend(poseidon2::bytes_to_fes_wrapped(&padded));

    // pk_d.bytes → 4 fes
    fes.extend(poseidon2::bytes_to_fes_wrapped(input.pk_d_bytes));
    // ivk_commitment → 4 fes
    fes.extend(poseidon2::bytes_to_fes_wrapped(input.ivk_commitment));
    // value → 1 fe
    fes.push(Goldilocks::from_u64(wrap_u64(input.value)));
    // rcm → 4 fes
    fes.extend(poseidon2::bytes_to_fes_wrapped(input.rcm));

    debug_assert_eq!(fes.len(), 15);
    poseidon2::hash_tagged(b"uno-cm-v1", &fes)
}

fn wrap_u64(v: u64) -> u64 {
    if v >= P_GL { v - P_GL } else { v }
}

// ---------------------------------------------------------------------------
// Canonical tx_hash (§4.1)
// ---------------------------------------------------------------------------

/// Compute the canonical `tx_hash` per §4.1.
///
/// Layout (all integers **big-endian**, matching `uno/core/transaction.cpp`):
///
/// ```text
/// BLAKE3(
///   version(1) || scheme_id(1) || chain_id(4) || anchor(32) ||
///   expiry_block(8) || fee(8) || spend_count(1) || output_count(1) ||
///   for each spend: nullifier(32) || rk(32)                 // NOT sig
///   for each output:
///     cm(32) || epk(32) || filter_tag(2) ||
///     cell_hash(enc_ciphertext) || cell_hash(mlkem_ct) || out_ciphertext(80)
/// )
/// ```
///
/// `cell_hash(x)` is approximated as `BLAKE3(x)` for this scaffold (see
/// module docstring). The real chain parity point is M-P2.
pub fn canonical_tx_hash(tx: &Transfer) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(
        TRANSFER_HEADER_BYTES
            + tx.spends.len() * 64
            + tx.outputs.len() * (32 + 32 + 2 + 32 + 32 + 80),
    );
    buf.push(tx.version);
    buf.push(tx.scheme_id);
    buf.extend_from_slice(&tx.chain_id.to_be_bytes());
    buf.extend_from_slice(&tx.anchor);
    buf.extend_from_slice(&tx.expiry_block.to_be_bytes());
    buf.extend_from_slice(&tx.fee.to_be_bytes());
    buf.push(tx.spends.len() as u8);
    buf.push(tx.outputs.len() as u8);
    for s in &tx.spends {
        buf.extend_from_slice(&s.nullifier);
        buf.extend_from_slice(&s.rk);
        // spend_auth_sig intentionally excluded per §4.1.
    }
    for o in &tx.outputs {
        buf.extend_from_slice(&o.cm);
        buf.extend_from_slice(&o.epk);
        buf.extend_from_slice(&o.filter_tag.to_be_bytes());
        buf.extend_from_slice(&blake3_32(&o.enc_ciphertext));
        buf.extend_from_slice(&blake3_32(&o.mlkem_ct));
        buf.extend_from_slice(&o.out_ciphertext);
    }
    blake3_32(&buf)
}

fn blake3_32(data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(data);
    *h.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Flat wire encode / decode (for `uno_sendTransfer`)
// ---------------------------------------------------------------------------

/// Encode a Transfer to the flat wire format documented at the top of this
/// module. Round-trippable with `decode_transfer_wire`.
pub fn encode_transfer_wire(tx: &Transfer) -> Result<Vec<u8>> {
    if tx.spends.is_empty() || tx.spends.len() > MAX_SPEND_COUNT as usize {
        return Err(anyhow!(
            "encode_transfer_wire: spend_count {} out of [{},{}]",
            tx.spends.len(), MIN_SPEND_COUNT, MAX_SPEND_COUNT));
    }
    if tx.outputs.is_empty() || tx.outputs.len() > MAX_OUTPUT_COUNT as usize {
        return Err(anyhow!(
            "encode_transfer_wire: output_count {} out of [{},{}]",
            tx.outputs.len(), MIN_OUTPUT_COUNT, MAX_OUTPUT_COUNT));
    }

    let mut out = Vec::new();
    out.push(tx.version);
    out.push(tx.scheme_id);
    out.extend_from_slice(&tx.chain_id.to_be_bytes());
    out.extend_from_slice(&tx.anchor);
    out.extend_from_slice(&tx.expiry_block.to_be_bytes());
    out.extend_from_slice(&tx.fee.to_be_bytes());
    out.push(tx.spends.len() as u8);
    out.push(tx.outputs.len() as u8);

    for s in &tx.spends {
        out.extend_from_slice(&s.nullifier);
        out.extend_from_slice(&s.rk);
        out.extend_from_slice(&s.spend_auth_sig);
    }
    for o in &tx.outputs {
        out.extend_from_slice(&o.cm);
        out.extend_from_slice(&o.epk);
        out.extend_from_slice(&o.filter_tag.to_be_bytes());
        write_varint(&mut out, o.enc_ciphertext.len() as u64);
        out.extend_from_slice(&o.enc_ciphertext);
        write_varint(&mut out, o.mlkem_ct.len() as u64);
        out.extend_from_slice(&o.mlkem_ct);
        out.extend_from_slice(&o.out_ciphertext);
    }
    write_varint(&mut out, tx.zk_proof.len() as u64);
    out.extend_from_slice(&tx.zk_proof);
    Ok(out)
}

/// Reverse of `encode_transfer_wire` — used by tests to verify well-formedness.
pub fn decode_transfer_wire(bytes: &[u8]) -> Result<Transfer> {
    let mut r = Reader::new(bytes);
    let version = r.read_u8()?;
    let scheme_id = r.read_u8()?;
    let chain_id = r.read_be_u32()?;
    let anchor = r.read_fixed::<32>()?;
    let expiry_block = r.read_be_u64()?;
    let fee = r.read_be_u64()?;
    let spend_count = r.read_u8()?;
    let output_count = r.read_u8()?;
    if !(MIN_SPEND_COUNT..=MAX_SPEND_COUNT).contains(&spend_count) {
        return Err(anyhow!("decode: spend_count {spend_count} out of range"));
    }
    if !(MIN_OUTPUT_COUNT..=MAX_OUTPUT_COUNT).contains(&output_count) {
        return Err(anyhow!("decode: output_count {output_count} out of range"));
    }
    let mut spends = Vec::with_capacity(spend_count as usize);
    for _ in 0..spend_count {
        let nullifier = r.read_fixed::<32>()?;
        let rk = r.read_fixed::<32>()?;
        let spend_auth_sig = r.read_fixed::<64>()?;
        spends.push(SpendDescription { nullifier, rk, spend_auth_sig });
    }
    let mut outputs = Vec::with_capacity(output_count as usize);
    for _ in 0..output_count {
        let cm = r.read_fixed::<32>()?;
        let epk = r.read_fixed::<32>()?;
        let filter_tag = r.read_be_u16()?;
        let enc_ciphertext = r.read_varint_blob()?;
        let mlkem_ct = r.read_varint_blob()?;
        let out_ciphertext = r.read_fixed::<OUT_CIPHERTEXT_BYTES>()?;
        outputs.push(OutputDescription {
            cm, epk, filter_tag, enc_ciphertext, mlkem_ct, out_ciphertext,
        });
    }
    let zk_proof = r.read_varint_blob()?;
    if r.remaining() != 0 {
        return Err(anyhow!("decode: trailing {} bytes after zk_proof", r.remaining()));
    }
    Ok(Transfer {
        version, scheme_id, chain_id, anchor, expiry_block, fee,
        spends, outputs, zk_proof,
    })
}

// ---------------------------------------------------------------------------
// Small wire reader/writer helpers
// ---------------------------------------------------------------------------

struct Reader<'a> { buf: &'a [u8], pos: usize }

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }
    fn remaining(&self) -> usize { self.buf.len() - self.pos }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.remaining() < N {
            return Err(anyhow!("decode: truncated at offset {}", self.pos));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }
    fn read_u8(&mut self) -> Result<u8> { Ok(self.read_fixed::<1>()?[0]) }
    fn read_be_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read_fixed::<2>()?))
    }
    fn read_be_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read_fixed::<4>()?))
    }
    fn read_be_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.read_fixed::<8>()?))
    }
    fn read_varint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            if self.pos >= self.buf.len() {
                return Err(anyhow!("decode: varint truncated"));
            }
            let b = self.buf[self.pos]; self.pos += 1;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 { return Ok(v); }
            shift += 7;
            if shift >= 64 { return Err(anyhow!("decode: varint overflow")); }
        }
    }
    fn read_varint_blob(&mut self) -> Result<Vec<u8>> {
        let n = self.read_varint()? as usize;
        if self.remaining() < n {
            return Err(anyhow!("decode: varint-blob truncated (want {n})"));
        }
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 { out.push(byte); return; }
        out.push(byte | 0x80);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_transfer() -> Transfer {
        Transfer {
            version: TRANSFER_VERSION,
            scheme_id: SCHEME_ID_V1,
            chain_id: 0x0000_0002,
            anchor: [0x11u8; 32],
            expiry_block: 1_000_000,
            fee: 1_000,
            spends: vec![SpendDescription {
                nullifier: [0x22u8; 32],
                rk: [0x33u8; 32],
                spend_auth_sig: [0x44u8; 64],
            }],
            outputs: vec![OutputDescription {
                cm: [0x55u8; 32],
                epk: [0x66u8; 32],
                filter_tag: 0x1234,
                enc_ciphertext: vec![0x77u8; 580],
                mlkem_ct: vec![0x88u8; crate::sizes::MLKEM768_CT],
                out_ciphertext: [0x99u8; OUT_CIPHERTEXT_BYTES],
            }],
            zk_proof: vec![0u8; STUB_PROOF_BYTES],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let tx = mk_transfer();
        let enc = encode_transfer_wire(&tx).unwrap();
        let dec = decode_transfer_wire(&enc).unwrap();
        assert_eq!(tx, dec);
    }

    #[test]
    fn tx_hash_excludes_signature_and_zk_proof() {
        let tx = mk_transfer();
        let h1 = canonical_tx_hash(&tx);
        // Mutate the sig. tx_hash must NOT change.
        let mut tx2 = tx.clone();
        tx2.spends[0].spend_auth_sig[0] ^= 1;
        assert_eq!(h1, canonical_tx_hash(&tx2), "sig mutation must not affect tx_hash");
        // Mutate the zk_proof. tx_hash must NOT change.
        let mut tx3 = tx.clone();
        tx3.zk_proof[0] ^= 1;
        assert_eq!(h1, canonical_tx_hash(&tx3), "zk_proof mutation must not affect tx_hash");
        // Mutate nullifier. tx_hash MUST change.
        let mut tx4 = tx.clone();
        tx4.spends[0].nullifier[0] ^= 1;
        assert_ne!(h1, canonical_tx_hash(&tx4), "nullifier mutation must affect tx_hash");
    }

    #[test]
    fn note_commitment_is_deterministic_and_binds_all_inputs() {
        let d = [0x01u8; 11];
        let pk_d = [0x02u8; 32];
        let ivk_cm = [0x03u8; 32];
        let rcm = [0x04u8; 32];
        let cm_a = compute_note_commitment(&NoteCommitmentInputs {
            d: &d, pk_d_bytes: &pk_d, ivk_commitment: &ivk_cm, value: 10, rcm: &rcm,
        });
        let cm_b = compute_note_commitment(&NoteCommitmentInputs {
            d: &d, pk_d_bytes: &pk_d, ivk_commitment: &ivk_cm, value: 10, rcm: &rcm,
        });
        assert_eq!(cm_a, cm_b);

        // Changing each input changes the commitment.
        let cm_value = compute_note_commitment(&NoteCommitmentInputs {
            d: &d, pk_d_bytes: &pk_d, ivk_commitment: &ivk_cm, value: 11, rcm: &rcm,
        });
        assert_ne!(cm_a, cm_value);
        let d2 = [0x99u8; 11];
        let cm_d = compute_note_commitment(&NoteCommitmentInputs {
            d: &d2, pk_d_bytes: &pk_d, ivk_commitment: &ivk_cm, value: 10, rcm: &rcm,
        });
        assert_ne!(cm_a, cm_d);
    }

    #[test]
    fn rcm_is_tagged_hash_of_rseed() {
        let rseed = [0xabu8; 32];
        let a = compute_rcm(&rseed);
        let b = compute_rcm(&rseed);
        assert_eq!(a, b);
        assert_eq!(a, poseidon2::hash_tagged_bytes(b"uno-rcm-v1", &rseed));
    }

    #[test]
    fn constants_match_doc() {
        assert_eq!(TRANSFER_HEADER_BYTES, 56);
        assert_eq!(SPEND_INLINE_BYTES, 128);
        assert_eq!(OUTPUT_INLINE_BYTES, 146);
    }

    #[test]
    fn empty_shapes_rejected() {
        let mut tx = mk_transfer();
        tx.spends.clear();
        assert!(encode_transfer_wire(&tx).is_err());
    }
}
