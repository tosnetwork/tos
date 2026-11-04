// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! The relay request and the structural checks both ends make on it. The
//! wallet runs [`Candidate::check`] on what it is about to submit; the
//! provider runs the same on what it received, then its own custody checks.
use crate::wire;
use anyhow::{ensure, Result};
use ark_ff::PrimeField;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chain_block::{BocReader, Cell, CellType, Coins, Deserializable, SliceData};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shielded_pool_circuit::field::{is_canonical, Fr};

pub const REQUEST_TAG: &[u8] = b"TOS-BR1-REQUEST\0";
/// The most bytes a transact body may have, and its base64 length.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
pub const MAX_BODY_BASE64: usize = 349528;
/// The most bytes a standalone request wire may have.
pub const MAX_REQUEST_WIRE_BYTES: usize = 2 * MAX_BODY_BYTES;
/// The most bytes of one API request or response body carrying a request.
pub const MAX_WIRE_BYTES: usize = 2 * MAX_BODY_BYTES + 4096;
/// The Shield transact operation.
pub const TRANSACT_OP: u32 = 0x53485002;
/// A sealed output payload's exact length.
pub const OUTPUT_PAYLOAD_BYTES: usize = 1233;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub release: String,
    pub intent: String,
    pub body_b64: String,
    pub body_sha256: String,
    pub nullifiers: [String; 2],
    pub quote_hash: String,
    pub fee_note_body: String,
    pub fee_slot: u8,
    pub fee_note_index: u64,
    pub valid_until: u32,
    pub funding_cap: u64,
}

impl Request {
    /// A request from its exact wire bytes: at most 512 KiB, an object with
    /// exactly the eleven members, no duplicate member, no float.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = wire::parse_object(bytes, MAX_REQUEST_WIRE_BYTES)?;
        let request: Self = serde_json::from_value(value)?;
        request.validate()?;
        Ok(request)
    }

    /// The field rules the reference `Request` enforces on construction:
    /// digests are digests, scalars are canonical field elements, the two
    /// nullifiers differ, the slot is one of three, the expiry is positive,
    /// the cap is within the signed 64-bit range, and the body is canonical
    /// base64 of at most 256 KiB whose digest is `body_sha256`. Returns the
    /// decoded body bytes.
    pub fn validate(&self) -> Result<Vec<u8>> {
        for s in [&self.release, &self.body_sha256, &self.quote_hash] {
            wire::digest_str(s)?;
        }
        for s in [&self.intent, &self.fee_note_body, &self.nullifiers[0], &self.nullifiers[1]] {
            scalar(s)?;
        }
        ensure!(self.nullifiers[0] != self.nullifiers[1], "duplicate nullifier");
        ensure!(self.fee_slot < 3, "fee slot out of range");
        ensure!(self.valid_until >= 1, "expiry out of range");
        ensure!(
            self.funding_cap >= 1 && self.funding_cap < (1u64 << 63),
            "funding cap out of range"
        );
        ensure!(self.body_b64.len() <= MAX_BODY_BASE64, "body base64 bound");
        let bytes = STANDARD.decode(&self.body_b64)?;
        ensure!(
            !bytes.is_empty()
                && bytes.len() <= MAX_BODY_BYTES
                && STANDARD.encode(&bytes) == self.body_b64
                && wire::hash(&bytes) == self.body_sha256,
            "exact body bytes"
        );
        Ok(bytes)
    }

    /// The exact bytes the request is identified by and sent as.
    pub fn wire(&self) -> Result<Vec<u8>> {
        wire::canonical(&serde_json::to_value(self)?)
    }

    /// The request identity: the tagged hash of its wire bytes.
    pub fn identity(&self) -> Result<String> {
        Ok(identity_of(&self.wire()?))
    }
}

pub fn identity_of(wire_bytes: &[u8]) -> String {
    let mut bytes = REQUEST_TAG.to_vec();
    bytes.extend_from_slice(wire_bytes);
    wire::hash(&bytes)
}

/// A single-root BOC of ordinary level-zero cells within the protocol's
/// bounds, with nothing after it.
pub fn ordinary_boc(bytes: &[u8]) -> Result<Cell> {
    ensure!(!bytes.is_empty() && bytes.len() <= 512 * 1024, "BOC byte bound");
    let mut reader = BocReader::new().set_max_cell_depth(256);
    let mut source = std::io::Cursor::new(bytes);
    let cell = reader.read(&mut source)?.withdraw_single_root()?;
    ensure!(source.position() == u64::try_from(bytes.len())?, "trailing BOC bytes");
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![cell.clone()];
    while let Some(c) = stack.pop() {
        if !seen.insert(c.repr_hash()) {
            continue;
        }
        ensure!(
            seen.len() <= 8192 && c.cell_type() == CellType::Ordinary && c.level() == 0,
            "BOC cells/type bound"
        );
        for i in 0..c.references_count() {
            stack.push(c.reference(i)?);
        }
    }
    Ok(cell)
}

/// A canonical field element from its hex digest.
pub fn scalar(s: &str) -> Result<Fr> {
    wire::digest_str(s)?;
    let raw: [u8; 32] = hex::decode(s)?.try_into().map_err(|_| anyhow::anyhow!("scalar width"))?;
    ensure!(is_canonical(&raw), "noncanonical field");
    Ok(Fr::from_be_bytes_mod_order(&raw))
}

/// A request that passed every structural check: its typed form, its
/// identity, the decoded body, and the fee slot's payload and note body.
pub struct Candidate {
    pub request: Request,
    pub identity: String,
    pub body: Cell,
    pub fee_payload: Vec<u8>,
    pub fee_body: Fr,
}

impl Candidate {
    /// Every check of a request that needs no custody: release scope, slot,
    /// a positive cap, distinct canonical nullifiers, exact body bytes and
    /// digest, the transact shape, the wire's intent, expiry, nullifiers and
    /// fee note, the payout shape, the fee payload at the fee slot, and the
    /// quote binding (slot, index, expiry, digest). `terms` are the quote's
    /// authenticated terms. The caller bounds `funding_cap` against its own
    /// policy and checks the fee output's derivation.
    pub fn check(value: &Value, scope: &str, terms: &Value) -> Result<Self> {
        let request: Request = serde_json::from_value(value.clone())?;
        ensure!(
            request.release == scope && request.fee_slot < 3 && request.funding_cap > 0,
            "request release/budget/slot"
        );
        let bytes = request.validate()?;
        let body = ordinary_boc(&bytes)?;
        let mut s = SliceData::load_cell(body.clone())?;
        ensure!(s.get_next_u32()? == TRANSACT_OP, "Shield transact required");
        let query = s.get_next_u64()?;
        let _anchor_kind = s.get_next_int(8)?;
        let _anchor_id = s.get_next_u32()?;
        ensure!(s.get_next_u32()? == request.valid_until, "wire expiry mismatch");
        let withdrawal = !Coins::construct_from(&mut s)?.is_zero();
        let has_pool_fee = !Coins::construct_from(&mut s)?.is_zero();
        ensure!(withdrawal == has_pool_fee, "withdrawal fee shape");
        let recipient_tag = s.get_next_int(2)?;
        if withdrawal {
            ensure!(
                recipient_tag == 2 && s.get_next_int(1)? == 0 && s.get_next_int(8)? == 0,
                "withdrawal requires a standard workchain-0 recipient"
            );
            s.get_next_bytes(32)?;
        } else {
            ensure!(recipient_tag == 0, "private transfer recipient");
        }
        ensure!(
            hex::encode(s.get_next_bytes(32)?) == request.intent
                && query == u64::from_str_radix(&request.intent[48..], 16)?,
            "wire intent/query mismatch"
        );
        ensure!(s.remaining_bits() == 0 && s.remaining_references() == 4, "transact root shape");
        let proof = s.checked_drain_reference()?;
        let output = s.checked_drain_reference()?;
        let mut proof = SliceData::load_cell(proof)?;
        ensure!(
            proof.remaining_bits() == 768 && proof.remaining_references() == 2,
            "proof bundle shape"
        );
        let _root = proof.get_next_bytes(32)?;
        for expected in &request.nullifiers {
            ensure!(hex::encode(proof.get_next_bytes(32)?) == *expected, "wire nullifier mismatch");
        }
        let mut notes = SliceData::load_cell(proof.checked_drain_reference()?)?;
        ensure!(
            notes.remaining_bits() == 768 && notes.remaining_references() == 0,
            "note bodies shape"
        );
        let mut fee_note = Vec::new();
        for slot in 0..3 {
            let n = notes.get_next_bytes(32)?;
            if slot == request.fee_slot {
                fee_note = n;
            }
        }
        ensure!(hex::encode(&fee_note) == request.fee_note_body, "fee note slot mismatch");
        let mut output = SliceData::load_cell(output)?;
        ensure!(
            output.remaining_bits() == 256 && output.remaining_references() == 4,
            "output bundle shape"
        );
        let mut fee_payload = Vec::new();
        for slot in 0..3 {
            let c = output.checked_drain_reference()?;
            if slot == request.fee_slot {
                fee_payload = br1_bond_codec::chain_bytes(&c, OUTPUT_PAYLOAD_BYTES)?;
            }
        }
        if withdrawal {
            br1_bond_codec::chain_bytes(&output.checked_drain_reference()?, OUTPUT_PAYLOAD_BYTES)?;
        }
        ensure!(
            terms["slot"] == request.fee_slot
                && terms["note_index"] == request.fee_note_index
                && terms["valid_until"]
                    .as_u64()
                    .is_some_and(|expiry| u64::from(request.valid_until) <= expiry),
            "candidate quote binding"
        );
        ensure!(crate::quote::identity(terms)? == request.quote_hash, "quote digest mismatch");
        let fee_body = scalar(&request.fee_note_body)?;
        Ok(Self {
            request,
            identity: identity_of(&wire::canonical(value)?),
            body,
            fee_payload,
            fee_body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identity_is_the_tagged_hash_of_the_canonical_wire() -> Result<()> {
        let request = Request {
            release: "0a".repeat(32),
            intent: "0b".repeat(32),
            body_b64: STANDARD.encode(b"body"),
            body_sha256: wire::hash(b"body"),
            nullifiers: ["0c".repeat(32), "0d".repeat(32)],
            quote_hash: "0e".repeat(32),
            fee_note_body: "0f".repeat(32),
            fee_slot: 2,
            fee_note_index: 5,
            valid_until: 1_700_000_300,
            funding_cap: 250_000_000,
        };
        let wire_bytes = request.wire()?;
        assert!(wire_bytes.starts_with(br#"{"body_b64":"#));
        let mut tagged = REQUEST_TAG.to_vec();
        tagged.extend_from_slice(&wire_bytes);
        assert_eq!(request.identity()?, wire::hash(&tagged));
        let back = Request::parse(&wire_bytes)?;
        assert_eq!(back, request);
        let mut dup = wire_bytes.clone();
        dup.truncate(dup.len() - 1);
        dup.extend_from_slice(br#","fee_slot":2}"#);
        assert!(Request::parse(&dup).is_err());
        assert!(Request::parse(&vec![b' '; MAX_REQUEST_WIRE_BYTES + 1]).is_err());
        let mut extra: Value = serde_json::from_slice(&wire_bytes)?;
        extra["extra"] = json!(1);
        assert!(serde_json::from_value::<Request>(extra).is_err());
        Ok(())
    }

    #[test]
    fn a_body_that_is_not_a_transact_is_refused_by_name() {
        let body = STANDARD.encode(b"not a boc");
        let value = json!({
            "release": "0a".repeat(32), "intent": "0b".repeat(32), "body_b64": body,
            "body_sha256": wire::hash(b"not a boc"), "nullifiers": ["0c".repeat(32), "0d".repeat(32)],
            "quote_hash": "0e".repeat(32), "fee_note_body": "0f".repeat(32), "fee_slot": 2,
            "fee_note_index": 5, "valid_until": 1_700_000_300u64, "funding_cap": 250_000_000u64,
        });
        let terms = json!({"slot": 2, "note_index": 5, "valid_until": 1_700_000_300u64});
        assert!(Candidate::check(&value, &"0a".repeat(32), &terms).is_err());
        let mut dup = value.clone();
        dup["nullifiers"] = json!(["0c".repeat(32), "0c".repeat(32)]);
        assert!(matches!(
            Candidate::check(&dup, &"0a".repeat(32), &terms),
            Err(error) if error.to_string() == "duplicate nullifier"
        ));
        let mut scope = value.clone();
        scope["release"] = json!("0b".repeat(32));
        assert!(matches!(
            Candidate::check(&scope, &"0a".repeat(32), &terms),
            Err(error) if error.to_string() == "request release/budget/slot"
        ));
    }

    #[test]
    fn boc_bounds() {
        assert!(ordinary_boc(b"").is_err());
        assert!(ordinary_boc(&[0u8; 600 * 1024]).is_err());
        assert!(scalar(&"ff".repeat(32)).is_err());
        assert!(scalar(&"00".repeat(32)).is_err());
        assert!(scalar(&"01".repeat(32)).is_ok());
    }
}
