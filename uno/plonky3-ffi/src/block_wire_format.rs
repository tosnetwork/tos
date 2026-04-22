//! `UnoBlockExtra` — v2 wire format for UNO aggregated-block proofs.
//! Implements §2.1 of `doc/uno-aggregation-design.md`.
//!
//! ⚠️ **v2 research path (frozen).** Per the v1 pivot in
//! `doc/uno-aggregation-design.md` §-1 (2026-04-21), UNO v1 ships
//! WITHOUT block-level aggregation; this wire-format container is
//! NOT used on the v1 critical path. The code stays in-tree so the
//! v1 Transfer wire format (which keeps `zk_proof: ^Cell`) can carry
//! a defensible "future aggregation will slot here" story, and so
//! v2 activation requires no additional wire-codec work.
//!
//! # Layout (on the wire, little-endian, canonical)
//!
//! ```text
//! UnoBlockExtra :=
//!   aggregator_scheme_id : u8      // crypto-agility tag (0x01 for v1 launch)
//!   aggregator_version   : u8      // format revision (1 at launch)
//!   n_transfers          : u16     // 0..=BLOCK_TX_CAP
//!   tx_pi_merkle_root    : [u8; 32]  // BLAKE3 Merkle root over per-Tx PI hashes
//!   aggregated_proof_len : u32     // byte length of the following proof blob
//!   aggregated_proof     : [u8; aggregated_proof_len]
//! ```
//!
//! **Framing size (fixed)**: 1 + 1 + 2 + 32 + 4 = **40 bytes** + the
//! variable-length proof payload. The proof payload itself is
//! `postcard`-encoded `p3_uni_stark::Proof<…>` (produced by
//! `crate::aggregator::prove_block`); this module treats it as an
//! opaque byte slice so the wire layer is stable across FRI-parameter
//! tuning and future migrations (e.g. WHIR).
//!
//! # Why this layer is tiny
//!
//! The aggregated proof itself is currently 400-800 KB (§A4
//! measurements). Adding framing overhead of 40 bytes is noise. The
//! point of this module is **not** to compress the proof further — it's
//! to lock down the header fields that bind the proof to the block
//! (scheme_id, n_transfers, tx_pi_merkle_root) in a canonical,
//! versioned, parser-friendly form.
//!
//! # Versioning strategy
//!
//! - `aggregator_scheme_id` changes on crypto-family migration (FRI →
//!   WHIR, STARK → recursive, etc.). Validators reject unknown ids at
//!   the wire layer, BEFORE invoking any verifier.
//! - `aggregator_version` changes on backward-incompatible framing
//!   tweaks within the same scheme_id. Upgrade path: validators
//!   support N and N-1 simultaneously during a hardfork window.
//!
//! # What this module does NOT do
//!
//! - Cryptographic verification of the proof. That's `aggregator::
//!   verify_block`.
//! - Validator block-consistency checks (e.g. tx_pi_merkle_root
//!   matches the Transfer list). That lives in the consensus layer.
//! - FFI exports. Phase A6 wires C++ consumers.

use crate::aggregator::{AggregatedProof, BLOCK_TX_CAP};

/// Current `aggregator_scheme_id`. Bumped on crypto-family migration.
pub const UNO_AGGREGATOR_SCHEME_ID_V1: u8 = 0x01;

/// Current `aggregator_version`. Bumped on framing-incompatible
/// changes within the same scheme_id.
pub const UNO_AGGREGATOR_VERSION_V1: u8 = 0x01;

/// Fixed framing overhead (bytes BEFORE the variable-length proof).
/// 1 + 1 + 2 + 32 + 4 = 40.
pub const UNO_BLOCK_EXTRA_HEADER_BYTES: usize = 40;

/// Hard cap on `aggregated_proof_len`. 16 MB is orders above our
/// measured 400-800 KB envelope and above any plausible future WHIR
/// proof size — rejects adversarial inputs before allocating.
pub const UNO_BLOCK_EXTRA_MAX_PROOF_BYTES: u32 = 16 * 1024 * 1024;

/// Block-level wire-format container for the aggregated proof.
///
/// Owned form. Use [`encode`] / [`decode`] for the canonical byte
/// representation. This type deliberately avoids `serde` derives — the
/// wire format is hand-rolled and canonical, and we don't want
/// postcard varint behaviors or field reordering to matter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnoBlockExtra {
    /// Crypto-agility tag. Must equal [`UNO_AGGREGATOR_SCHEME_ID_V1`]
    /// for v1 launch.
    pub aggregator_scheme_id: u8,
    /// Framing revision. Must equal [`UNO_AGGREGATOR_VERSION_V1`].
    pub aggregator_version: u8,
    /// Number of Transfers aggregated in this block. 0..=BLOCK_TX_CAP.
    pub n_transfers: u16,
    /// BLAKE3 Merkle root over per-Tx PI hashes (inclusion order).
    /// Binds the aggregated proof to the Transfer list.
    pub tx_pi_merkle_root: [u8; 32],
    /// Canonical aggregated proof bytes (postcard-encoded
    /// `p3_uni_stark::Proof` today; treated as opaque here).
    pub aggregated_proof: Vec<u8>,
}

/// Errors surfaced by [`decode`]. Every variant is "reject this block
/// at the wire layer before invoking the verifier".
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Input shorter than the fixed 40-byte header.
    ShortHeader { got: usize },
    /// `aggregator_scheme_id` is not in the accepted set.
    UnknownSchemeId { got: u8 },
    /// `aggregator_version` is not in the accepted set for the given
    /// scheme_id. (v1 launch only accepts version 1.)
    UnknownVersion { scheme_id: u8, got: u8 },
    /// `n_transfers` exceeds `BLOCK_TX_CAP`.
    TooManyTransfers { got: u16, cap: u16 },
    /// `aggregated_proof_len` field claims more bytes than the policy
    /// cap (hardens against OOM at decode time).
    ProofTooLarge { got: u32, cap: u32 },
    /// Declared `aggregated_proof_len` doesn't match remaining input
    /// bytes.
    ProofLengthMismatch { declared: u32, remaining: usize },
}

impl UnoBlockExtra {
    /// Construct a v1 wire header wrapping the given aggregated proof.
    ///
    /// # Panics
    /// - if `n_transfers > BLOCK_TX_CAP` (caller should clamp).
    /// - if `proof.bytes.len() > UNO_BLOCK_EXTRA_MAX_PROOF_BYTES`.
    pub fn v1(n_transfers: u16, tx_pi_merkle_root: [u8; 32], proof: AggregatedProof) -> Self {
        assert!(
            n_transfers as usize <= BLOCK_TX_CAP,
            "UnoBlockExtra::v1: n_transfers {n_transfers} > BLOCK_TX_CAP {BLOCK_TX_CAP}"
        );
        assert!(
            proof.bytes.len() <= UNO_BLOCK_EXTRA_MAX_PROOF_BYTES as usize,
            "UnoBlockExtra::v1: proof bytes {} > cap {}",
            proof.bytes.len(),
            UNO_BLOCK_EXTRA_MAX_PROOF_BYTES,
        );
        Self {
            aggregator_scheme_id: UNO_AGGREGATOR_SCHEME_ID_V1,
            aggregator_version: UNO_AGGREGATOR_VERSION_V1,
            n_transfers,
            tx_pi_merkle_root,
            aggregated_proof: proof.bytes,
        }
    }

    /// Total encoded size (header + proof). Exact; no extra padding.
    pub fn encoded_len(&self) -> usize {
        UNO_BLOCK_EXTRA_HEADER_BYTES + self.aggregated_proof.len()
    }
}

/// Canonical encode. Produces exactly `encoded_len()` bytes.
pub fn encode(extra: &UnoBlockExtra) -> Vec<u8> {
    let mut out = Vec::with_capacity(extra.encoded_len());
    out.push(extra.aggregator_scheme_id);
    out.push(extra.aggregator_version);
    out.extend_from_slice(&extra.n_transfers.to_le_bytes());
    out.extend_from_slice(&extra.tx_pi_merkle_root);
    // Proof length — u32 LE. We already assert at construction time
    // that the length fits; use `as u32` unconditionally here.
    let proof_len = extra.aggregated_proof.len() as u32;
    out.extend_from_slice(&proof_len.to_le_bytes());
    out.extend_from_slice(&extra.aggregated_proof);
    debug_assert_eq!(out.len(), extra.encoded_len());
    out
}

/// Canonical decode. Rejects unknown scheme_id / version, malformed
/// length fields, and truncated inputs BEFORE allocating the proof
/// buffer.
pub fn decode(bytes: &[u8]) -> Result<UnoBlockExtra, DecodeError> {
    if bytes.len() < UNO_BLOCK_EXTRA_HEADER_BYTES {
        return Err(DecodeError::ShortHeader { got: bytes.len() });
    }

    let aggregator_scheme_id = bytes[0];
    let aggregator_version = bytes[1];

    // Accept only v1 scheme + v1 framing at launch. Future scheme_ids
    // land by extending this match arm; historical ones stay forever.
    match aggregator_scheme_id {
        UNO_AGGREGATOR_SCHEME_ID_V1 => {
            if aggregator_version != UNO_AGGREGATOR_VERSION_V1 {
                return Err(DecodeError::UnknownVersion {
                    scheme_id: aggregator_scheme_id,
                    got: aggregator_version,
                });
            }
        }
        unknown => {
            return Err(DecodeError::UnknownSchemeId { got: unknown });
        }
    }

    let n_transfers = u16::from_le_bytes([bytes[2], bytes[3]]);
    if n_transfers as usize > BLOCK_TX_CAP {
        return Err(DecodeError::TooManyTransfers {
            got: n_transfers,
            cap: BLOCK_TX_CAP as u16,
        });
    }

    let mut tx_pi_merkle_root = [0u8; 32];
    tx_pi_merkle_root.copy_from_slice(&bytes[4..36]);

    let proof_len = u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
    if proof_len > UNO_BLOCK_EXTRA_MAX_PROOF_BYTES {
        return Err(DecodeError::ProofTooLarge {
            got: proof_len,
            cap: UNO_BLOCK_EXTRA_MAX_PROOF_BYTES,
        });
    }

    let remaining = bytes.len() - UNO_BLOCK_EXTRA_HEADER_BYTES;
    if proof_len as usize != remaining {
        return Err(DecodeError::ProofLengthMismatch {
            declared: proof_len,
            remaining,
        });
    }

    let aggregated_proof = bytes[UNO_BLOCK_EXTRA_HEADER_BYTES..].to_vec();

    Ok(UnoBlockExtra {
        aggregator_scheme_id,
        aggregator_version,
        n_transfers,
        tx_pi_merkle_root,
        aggregated_proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_proof_bytes(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    #[test]
    fn encode_then_decode_round_trip() {
        let proof = AggregatedProof {
            bytes: sample_proof_bytes(0x41, 128),
        };
        let root = [0x5a; 32];
        let extra = UnoBlockExtra::v1(3, root, proof.clone());
        assert_eq!(extra.encoded_len(), UNO_BLOCK_EXTRA_HEADER_BYTES + 128);

        let encoded = encode(&extra);
        assert_eq!(encoded.len(), extra.encoded_len());
        let decoded = decode(&encoded).expect("round-trip");
        assert_eq!(decoded, extra);
    }

    #[test]
    fn encode_layout_is_byte_exact() {
        // Use a legal n_transfers (≤ BLOCK_TX_CAP = 4 at v1).
        let extra = UnoBlockExtra::v1(
            3,
            [0xaa; 32],
            AggregatedProof {
                bytes: vec![0xde, 0xad, 0xbe, 0xef],
            },
        );
        let encoded = encode(&extra);
        assert_eq!(encoded[0], UNO_AGGREGATOR_SCHEME_ID_V1);
        assert_eq!(encoded[1], UNO_AGGREGATOR_VERSION_V1);
        // n_transfers = 3, little-endian.
        assert_eq!(&encoded[2..4], &[3, 0]);
        assert_eq!(&encoded[4..36], &[0xaa; 32]);
        // proof length = 4, LE.
        assert_eq!(&encoded[36..40], &[4, 0, 0, 0]);
        assert_eq!(&encoded[40..], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_empty_proof() {
        let extra = UnoBlockExtra::v1(0, [0; 32], AggregatedProof { bytes: vec![] });
        let encoded = encode(&extra);
        assert_eq!(encoded.len(), UNO_BLOCK_EXTRA_HEADER_BYTES);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.aggregated_proof.len(), 0);
        assert_eq!(decoded.n_transfers, 0);
    }

    #[test]
    fn decode_rejects_short_header() {
        let short = vec![0u8; UNO_BLOCK_EXTRA_HEADER_BYTES - 1];
        let err = decode(&short).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ShortHeader {
                got: UNO_BLOCK_EXTRA_HEADER_BYTES - 1,
            }
        );
    }

    #[test]
    fn decode_rejects_unknown_scheme_id() {
        let mut bytes = encode(&UnoBlockExtra::v1(
            1,
            [0; 32],
            AggregatedProof {
                bytes: vec![1, 2, 3],
            },
        ));
        bytes[0] = 0x99; // unknown scheme
        let err = decode(&bytes).unwrap_err();
        assert_eq!(err, DecodeError::UnknownSchemeId { got: 0x99 });
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut bytes = encode(&UnoBlockExtra::v1(
            1,
            [0; 32],
            AggregatedProof {
                bytes: vec![1, 2, 3],
            },
        ));
        bytes[1] = 0x02; // unknown version for v1 scheme
        let err = decode(&bytes).unwrap_err();
        assert_eq!(
            err,
            DecodeError::UnknownVersion {
                scheme_id: UNO_AGGREGATOR_SCHEME_ID_V1,
                got: 0x02,
            }
        );
    }

    #[test]
    fn decode_rejects_too_many_transfers() {
        // Forge n_transfers = BLOCK_TX_CAP + 1.
        let mut bytes = encode(&UnoBlockExtra::v1(
            1,
            [0; 32],
            AggregatedProof {
                bytes: vec![1, 2, 3],
            },
        ));
        let bad = (BLOCK_TX_CAP as u16) + 1;
        bytes[2..4].copy_from_slice(&bad.to_le_bytes());
        let err = decode(&bytes).unwrap_err();
        assert_eq!(
            err,
            DecodeError::TooManyTransfers {
                got: bad,
                cap: BLOCK_TX_CAP as u16,
            }
        );
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        let extra = UnoBlockExtra::v1(
            1,
            [0; 32],
            AggregatedProof {
                bytes: vec![1, 2, 3, 4, 5],
            },
        );
        let mut encoded = encode(&extra);
        // Corrupt declared length: claim 10 instead of 5.
        encoded[36..40].copy_from_slice(&10u32.to_le_bytes());
        let err = decode(&encoded).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ProofLengthMismatch {
                declared: 10,
                remaining: 5,
            }
        );
    }

    #[test]
    fn decode_rejects_proof_too_large() {
        let mut bytes = vec![0u8; UNO_BLOCK_EXTRA_HEADER_BYTES];
        bytes[0] = UNO_AGGREGATOR_SCHEME_ID_V1;
        bytes[1] = UNO_AGGREGATOR_VERSION_V1;
        // n_transfers = 0, tx_pi_merkle_root = 0.
        // proof length = cap + 1.
        let bad_len = UNO_BLOCK_EXTRA_MAX_PROOF_BYTES + 1;
        bytes[36..40].copy_from_slice(&bad_len.to_le_bytes());
        let err = decode(&bytes).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ProofTooLarge {
                got: bad_len,
                cap: UNO_BLOCK_EXTRA_MAX_PROOF_BYTES,
            }
        );
    }

    /// Wire-format stability guard: if any of these offsets changes,
    /// the on-chain wire format has drifted and every validator needs
    /// the new code. A scheme_id bump is the correct response.
    #[test]
    fn wire_layout_is_pinned_v1() {
        assert_eq!(UNO_BLOCK_EXTRA_HEADER_BYTES, 40);
        assert_eq!(UNO_AGGREGATOR_SCHEME_ID_V1, 0x01);
        assert_eq!(UNO_AGGREGATOR_VERSION_V1, 0x01);
        assert_eq!(UNO_BLOCK_EXTRA_MAX_PROOF_BYTES, 16 * 1024 * 1024);
    }

    /// Realistic-scale round-trip: 512 KB proof (close to our measured
    /// §A4 4-Tx aggregated proof size).
    #[test]
    fn round_trip_512kb_proof() {
        let proof = AggregatedProof {
            bytes: (0..512 * 1024u32).map(|i| i as u8).collect(),
        };
        let extra = UnoBlockExtra::v1(4, [0x7e; 32], proof);
        let encoded = encode(&extra);
        assert_eq!(encoded.len(), UNO_BLOCK_EXTRA_HEADER_BYTES + 512 * 1024);
        let decoded = decode(&encoded).expect("512 KB round-trip");
        assert_eq!(decoded, extra);
    }
}
