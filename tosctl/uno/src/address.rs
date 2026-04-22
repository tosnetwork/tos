//! Diversified-address construction (§2.6).
//!
//! ```text
//!   d              : 11 bytes (user-chosen or random)
//!   g_d            = HashToRistretto("uno-diversifier-v1" || d)
//!   pk_d           = ivk · g_d
//!   ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)
//!   Address        = (d, compress(pk_d), ivk_commitment, pk_mlkem)
//! ```
//!
//! Wire layout, 1259 bytes total:
//!
//! | Offset | Len  | Field            |
//! |--------|------|------------------|
//! | 0      | 11   | `d`              |
//! | 11     | 32   | `compress(pk_d)` |
//! | 43     | 32   | `ivk_commitment` |
//! | 75     | 1184 | `pk_mlkem`       |
//!
//! # String encoding (wallet-UX, off-spec)
//!
//! The design doc (§2.6) only fixes the byte layout; the string form is left
//! to wallet conventions. We use a short-prefix + Base58 + BLAKE3-4B checksum
//! scheme:
//!
//! ```text
//!   bytes_with_checksum = addr_bytes || BLAKE3(addr_bytes)[..4]
//!   hrp = "uno1" (testnet) | "unos" (mainnet)
//!   Address::to_string() = hrp || base58_encode(bytes_with_checksum)
//! ```
//!
//! Base58 is the Bitcoin alphabet, implemented inline (no extra dep). The
//! 4-byte BLAKE3 checksum catches most single-character transcription
//! errors. This choice is **off-spec** — design doc §2.6 does not mandate a
//! string format — and is documented here so a future wallet team can
//! migrate to a chain-wide convention (e.g. Bech32m) without ambiguity.

use anyhow::{anyhow, Result};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::keygen::{self, FullViewingKey};
use crate::sizes::{ADDRESS, DIVERSIFIER, IVK_COMMITMENT, MLKEM768_PK, RISTRETTO_POINT};
use crate::tags;

// ---------------------------------------------------------------------------
// HashToRistretto
// ---------------------------------------------------------------------------

/// `g_d = HashToRistretto("uno-diversifier-v1" || d)`.
///
/// Implementation: absorb tag + d into a BLAKE2b-512 that produces 64 bytes
/// of uniform output, then map via `RistrettoPoint::from_uniform_bytes`
/// (which is the `crypto_core_ristretto255_from_hash` routine libsodium
/// exposes to the A3 C++ code). This matches the §2.6 footnote binding.
pub fn derive_diversified_base_point(diversifier_11: &[u8]) -> Result<RistrettoPoint> {
    if diversifier_11.len() != DIVERSIFIER {
        return Err(anyhow!(
            "diversifier must be 11 bytes, got {}",
            diversifier_11.len()
        ));
    }
    let uniform_64 = keygen::blake2b_512(&[tags::UNO_DIVERSIFIER_V1, diversifier_11]);
    Ok(RistrettoPoint::from_uniform_bytes(&uniform_64))
}

// ---------------------------------------------------------------------------
// Address struct
// ---------------------------------------------------------------------------

/// Wire-level Uno Address. 1259 bytes on the wire (§2.6).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Address {
    /// Diversifier `d`.
    #[serde(with = "hex::serde")]
    pub d: [u8; DIVERSIFIER],

    /// Compressed `pk_d = ivk · g_d` on Ristretto255.
    #[serde(with = "hex::serde")]
    pub pk_d: [u8; RISTRETTO_POINT],

    /// `Poseidon2("uno-ivk-cm-v1", ivk, d)`.
    #[serde(with = "hex::serde")]
    pub ivk_commitment: [u8; IVK_COMMITMENT],

    /// ML-KEM-768 public key.
    #[serde(with = "hex::serde")]
    pub pk_mlkem: Vec<u8>,
}

impl Address {
    /// Build from the wallet FVK and a chosen 11-byte diversifier.
    pub fn build(fvk: &FullViewingKey, diversifier_11: &[u8]) -> Result<Self> {
        if diversifier_11.len() != DIVERSIFIER {
            return Err(anyhow!(
                "diversifier must be 11 bytes, got {}",
                diversifier_11.len()
            ));
        }
        let mut d = [0u8; DIVERSIFIER];
        d.copy_from_slice(diversifier_11);

        let g_d = derive_diversified_base_point(&d)?;
        let pk_d_point = fvk.ivk_scalar() * g_d;
        let pk_d = pk_d_point.compress().to_bytes();

        let ivk_cm = keygen::ivk_commitment(&fvk.ivk.0, &d)?;

        Ok(Address {
            d,
            pk_d,
            ivk_commitment: ivk_cm,
            pk_mlkem: fvk.pk_mlkem.clone(),
        })
    }

    /// Build with a freshly-randomized diversifier. Uses `rand::thread_rng`;
    /// output differs per call.
    pub fn build_random(fvk: &FullViewingKey) -> Result<Self> {
        let mut d = [0u8; DIVERSIFIER];
        rand::thread_rng().fill_bytes(&mut d);
        Address::build(fvk, &d)
    }

    /// Serialize to the 1259-byte wire layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ADDRESS);
        out.extend_from_slice(&self.d);
        out.extend_from_slice(&self.pk_d);
        out.extend_from_slice(&self.ivk_commitment);
        out.extend_from_slice(&self.pk_mlkem);
        debug_assert_eq!(out.len(), ADDRESS);
        out
    }

    /// Parse the 1259-byte wire layout. Validates pk_d is a canonical
    /// Ristretto255 compressed point; does NOT validate `pk_mlkem` (its
    /// well-formedness is only checked by `ML-KEM-768.Encap`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ADDRESS {
            return Err(anyhow!(
                "address must be {ADDRESS} bytes, got {}",
                bytes.len()
            ));
        }
        let mut d = [0u8; DIVERSIFIER];
        d.copy_from_slice(&bytes[0..11]);

        let mut pk_d = [0u8; RISTRETTO_POINT];
        pk_d.copy_from_slice(&bytes[11..43]);
        // Validate pk_d by decompressing.
        let _ = CompressedRistretto::from_slice(&pk_d)
            .map_err(|_| anyhow!("pk_d slice wrong length"))?
            .decompress()
            .ok_or_else(|| anyhow!("pk_d is not a valid Ristretto255 compressed point"))?;

        let mut ivk_cm = [0u8; IVK_COMMITMENT];
        ivk_cm.copy_from_slice(&bytes[43..75]);

        let pk_mlkem = bytes[75..].to_vec();
        if pk_mlkem.len() != MLKEM768_PK {
            return Err(anyhow!("pk_mlkem must be {MLKEM768_PK} bytes"));
        }

        Ok(Address {
            d,
            pk_d,
            ivk_commitment: ivk_cm,
            pk_mlkem,
        })
    }

    /// Encode to the string form `<hrp><base58(addr_bytes || checksum)>`.
    /// The checksum is `BLAKE3(addr_bytes)[..4]`. `hrp` is usually "uno1"
    /// (testnet) or "unos" (mainnet); callers choose.
    pub fn to_string_with_hrp(&self, hrp: &str) -> String {
        let raw = self.to_bytes();
        let mut cksum = [0u8; 4];
        cksum.copy_from_slice(&blake3_hash(&raw)[..4]);

        let mut payload = Vec::with_capacity(raw.len() + 4);
        payload.extend_from_slice(&raw);
        payload.extend_from_slice(&cksum);

        let mut s = String::from(hrp);
        s.push_str(&base58_encode(&payload));
        s
    }

    /// Parse the string form. Accepts either HRP; the caller can verify the
    /// expected HRP afterwards from the returned tuple.
    pub fn from_string(s: &str) -> Result<(Self, String)> {
        if s.len() < 4 {
            return Err(anyhow!("address string too short"));
        }
        let (hrp, rest) = s.split_at(4);
        if hrp != "uno1" && hrp != "unos" {
            return Err(anyhow!(
                "unknown address HRP {hrp:?}; expected uno1 (testnet) or unos (mainnet)"
            ));
        }
        let decoded = base58_decode(rest)?;
        if decoded.len() < 5 {
            return Err(anyhow!("address payload shorter than checksum"));
        }
        let body_len = decoded.len() - 4;
        let body = &decoded[..body_len];
        let cksum = &decoded[body_len..];
        let expected = &blake3_hash(body)[..4];
        if cksum != expected {
            return Err(anyhow!("address checksum mismatch"));
        }
        let addr = Address::from_bytes(body)?;
        Ok((addr, hrp.to_string()))
    }
}

// ---------------------------------------------------------------------------
// BLAKE3 + Base58 helpers — kept here (not in lib root) because this is the
// only module that uses them.
// ---------------------------------------------------------------------------

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(data);
    let d = h.finalize();
    *d.as_bytes()
}

// Bitcoin Base58 alphabet. Kept local to avoid a one-method dependency.
const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(input: &[u8]) -> String {
    // Count leading zeros.
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut n: Vec<u8> = input[zeros..].to_vec();
    let mut out_rev: Vec<u8> = Vec::new();

    while !n.is_empty() {
        let mut rem: u32 = 0;
        let mut new_n: Vec<u8> = Vec::with_capacity(n.len());
        let mut started = false;
        for &b in &n {
            let acc = rem * 256 + b as u32;
            let q = (acc / 58) as u8;
            rem = acc % 58;
            if started || q != 0 {
                started = true;
                new_n.push(q);
            }
        }
        out_rev.push(B58[rem as usize]);
        n = new_n;
    }

    let mut s = String::with_capacity(zeros + out_rev.len());
    for _ in 0..zeros {
        s.push('1');
    }
    for b in out_rev.iter().rev() {
        s.push(*b as char);
    }
    s
}

fn base58_decode(input: &str) -> Result<Vec<u8>> {
    let mut n: Vec<u8> = Vec::new();
    let zeros = input.chars().take_while(|&c| c == '1').count();

    for c in input.chars() {
        let digit = B58
            .iter()
            .position(|&b| b == c as u8)
            .ok_or_else(|| anyhow!("invalid base58 char {c:?}"))? as u32;
        // n = n * 58 + digit
        let mut carry = digit;
        for byte in n.iter_mut().rev() {
            let acc = *byte as u32 * 58 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            n.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = Vec::with_capacity(zeros + n.len());
    for _ in 0..zeros {
        out.push(0);
    }
    out.extend_from_slice(&n);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::derive_fvk;

    fn fixed_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        for i in 0..32 {
            s[i] = i as u8;
        }
        s
    }

    #[test]
    fn address_wire_is_1259_bytes() {
        let fvk = derive_fvk(&fixed_seed()).unwrap();
        let d = [0x42u8; 11];
        let a = Address::build(&fvk, &d).unwrap();
        let bytes = a.to_bytes();
        assert_eq!(bytes.len(), ADDRESS);
        assert_eq!(bytes.len(), 1259);

        // Round-trip through the wire parser.
        let b = Address::from_bytes(&bytes).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn ivk_commitment_matches_independent_recompute() {
        // Integration test (commit #6): derive keys → derive address → verify
        // address.ivk_commitment == Poseidon2("uno-ivk-cm-v1", ivk, d).
        let fvk = derive_fvk(&fixed_seed()).unwrap();
        let d = [0x99u8; 11];
        let a = Address::build(&fvk, &d).unwrap();
        let recomputed = keygen::ivk_commitment(&fvk.ivk.0, &d).unwrap();
        assert_eq!(a.ivk_commitment, recomputed);
    }

    #[test]
    fn address_string_roundtrip() {
        let fvk = derive_fvk(&fixed_seed()).unwrap();
        let d = [0x33u8; 11];
        let a = Address::build(&fvk, &d).unwrap();
        let s = a.to_string_with_hrp("uno1");
        assert!(s.starts_with("uno1"));
        let (b, hrp) = Address::from_string(&s).unwrap();
        assert_eq!(hrp, "uno1");
        assert_eq!(a, b);
    }

    #[test]
    fn address_string_rejects_bad_checksum() {
        let fvk = derive_fvk(&fixed_seed()).unwrap();
        let a = Address::build(&fvk, &[0; 11]).unwrap();
        let mut s = a.to_string_with_hrp("uno1");
        // Flip a character; round-trip must reject.
        // (Replace the last char with a different valid B58 char.)
        let last = s.pop().unwrap();
        let replacement = if last == '2' { '3' } else { '2' };
        s.push(replacement);
        assert!(Address::from_string(&s).is_err());
    }

    #[test]
    fn diversified_base_point_is_deterministic() {
        let d = [0x01u8; 11];
        let a = derive_diversified_base_point(&d).unwrap();
        let b = derive_diversified_base_point(&d).unwrap();
        assert_eq!(a.compress().to_bytes(), b.compress().to_bytes());
    }

    #[test]
    fn different_diversifiers_produce_different_pk_d() {
        let fvk = derive_fvk(&fixed_seed()).unwrap();
        let a = Address::build(&fvk, &[1u8; 11]).unwrap();
        let b = Address::build(&fvk, &[2u8; 11]).unwrap();
        assert_ne!(a.pk_d, b.pk_d);
        assert_ne!(a.ivk_commitment, b.ivk_commitment);
        assert_eq!(
            a.pk_mlkem, b.pk_mlkem,
            "pk_mlkem is shared across diversifiers"
        );
    }

    #[test]
    fn base58_roundtrip() {
        let samples: &[&[u8]] = &[
            &[],
            &[0],
            &[0, 0, 0x12],
            &[0xff; 16],
            &[0x01, 0x02, 0x03, 0x04, 0x05],
        ];
        for s in samples {
            let enc = base58_encode(s);
            let dec = base58_decode(&enc).unwrap();
            assert_eq!(dec, *s, "roundtrip failed for {:?}", s);
        }
    }
}
