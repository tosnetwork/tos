//! Minimal wire-format parser for scan-time use.
//!
//! This crate consumes `OutputDescription` records that `uno_getOutputsAtBlock`
//! (§9.1) returns. The RPC returns **raw wire bytes** (per §9 handler
//! contract); we only need to unpack the fields the receiver needs for
//! compact-filter matching + hybrid-KEM trial-decrypt.
//!
//! `OutputDescription` fields (§4.1):
//!
//! | Field           | Type     | On-wire                                |
//! |-----------------|----------|----------------------------------------|
//! | `cm`            | bits256  | 32 B inline                            |
//! | `epk`           | bits256  | 32 B inline                            |
//! | `filter_tag`    | bits16   | 2 B inline (little-endian u16)         |
//! | `enc_ciphertext`| ^Cell    | length-prefixed (varint) byte blob     |
//! | `mlkem_ct`      | ^Cell    | length-prefixed (varint) byte blob     |
//! | `out_ciphertext`| bytes[80]| 80 B inline                            |
//!
//! The doc encodes `^Cell` via TL-B as a pointer to a separate cell. The
//! JSON-RPC layer (A6, `uno/rpc/handlers.cpp`) flattens cell chains into
//! length-prefixed byte blobs when exporting raw output records; this parser
//! matches that post-flattening convention. If the RPC layer later changes
//! to return full BoC blobs, the parser would need to grow a BoC reader —
//! marked as a TODO.

use anyhow::{anyhow, Result};

use crate::sizes::{DIGEST, RISTRETTO_POINT};

/// Minimal receiver-side view of an `OutputDescription`.
#[derive(Clone, Debug)]
pub struct OutputDescription {
    pub cm: [u8; DIGEST],
    pub epk: [u8; RISTRETTO_POINT],
    pub filter_tag: u16,
    pub enc_ciphertext: Vec<u8>,
    pub mlkem_ct: Vec<u8>,
    /// 80-byte AEAD blob recoverable with `ovk` (audit path). Unused by the
    /// default `ivk` scan; carried for completeness.
    pub out_ciphertext: [u8; 80],
}

/// Parse an `OutputDescription` from the flattened wire layout.
///
/// If the layout doesn't match, returns an error; partial parses are not
/// produced.
pub fn parse_output(bytes: &[u8]) -> Result<OutputDescription> {
    let mut r = Reader::new(bytes);
    let cm = r.read_fixed::<DIGEST>()?;
    let epk = r.read_fixed::<RISTRETTO_POINT>()?;
    let filter_tag = r.read_u16_le()?;
    let enc_ciphertext = r.read_varint_blob()?;
    let mlkem_ct = r.read_varint_blob()?;
    let out_ciphertext = r.read_fixed::<80>()?;
    if r.remaining() != 0 {
        return Err(anyhow!(
            "trailing {} bytes after OutputDescription",
            r.remaining()
        ));
    }
    Ok(OutputDescription {
        cm,
        epk,
        filter_tag,
        enc_ciphertext,
        mlkem_ct,
        out_ciphertext,
    })
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.remaining() < N {
            return Err(anyhow!(
                "truncated: want {N} bytes, have {}",
                self.remaining()
            ));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_u16_le(&mut self) -> Result<u16> {
        let b = self.read_fixed::<2>()?;
        Ok(u16::from_le_bytes(b))
    }

    /// LEB128 varint length prefix followed by that many bytes.
    fn read_varint_blob(&mut self) -> Result<Vec<u8>> {
        let n = self.read_varint()? as usize;
        if self.remaining() < n {
            return Err(anyhow!(
                "varint-blob truncated: want {n}, have {}",
                self.remaining()
            ));
        }
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }

    fn read_varint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            if self.pos >= self.buf.len() {
                return Err(anyhow!("varint truncated"));
            }
            let b = self.buf[self.pos];
            self.pos += 1;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
            if shift >= 64 {
                return Err(anyhow!("varint overflow"));
            }
        }
    }
}

/// Encode an `OutputDescription` back to the flattened layout. Used by tests.
pub fn encode_output(o: &OutputDescription) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(32 + 32 + 2 + o.enc_ciphertext.len() + o.mlkem_ct.len() + 80 + 8);
    out.extend_from_slice(&o.cm);
    out.extend_from_slice(&o.epk);
    out.extend_from_slice(&o.filter_tag.to_le_bytes());
    write_varint(&mut out, o.enc_ciphertext.len() as u64);
    out.extend_from_slice(&o.enc_ciphertext);
    write_varint(&mut out, o.mlkem_ct.len() as u64);
    out.extend_from_slice(&o.mlkem_ct);
    out.extend_from_slice(&o.out_ciphertext);
    out
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let o = OutputDescription {
            cm: [1u8; 32],
            epk: [2u8; 32],
            filter_tag: 0x1234,
            enc_ciphertext: vec![3u8; 580],
            mlkem_ct: vec![4u8; crate::sizes::MLKEM768_CT],
            out_ciphertext: [5u8; 80],
        };
        let enc = encode_output(&o);
        let dec = parse_output(&enc).unwrap();
        assert_eq!(dec.cm, o.cm);
        assert_eq!(dec.epk, o.epk);
        assert_eq!(dec.filter_tag, o.filter_tag);
        assert_eq!(dec.enc_ciphertext, o.enc_ciphertext);
        assert_eq!(dec.mlkem_ct, o.mlkem_ct);
        assert_eq!(dec.out_ciphertext, o.out_ciphertext);
    }
}
