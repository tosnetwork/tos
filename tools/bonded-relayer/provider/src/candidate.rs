// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
use crate::{config::Config, identity::Identity, protocol};
use anyhow::{ensure, Result};
use ark_ff::PrimeField;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chain_block::{BocReader, Cell, CellType, Coins, Deserializable, SliceData};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shielded_pool_circuit::field::{is_canonical, Fr};

#[derive(Deserialize, Serialize)]
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
pub struct Candidate {
    pub request: Request,
    pub identity: String,
    pub body: Cell,
    pub fee_payload: Vec<u8>,
    pub fee_body: Fr,
}
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
fn scalar(s: &str) -> Result<Fr> {
    protocol::digest(&Value::String(s.into()))?;
    let raw: [u8; 32] = hex::decode(s)?.try_into().map_err(|_| anyhow::anyhow!("scalar width"))?;
    ensure!(is_canonical(&raw), "noncanonical field");
    Ok(Fr::from_be_bytes_mod_order(&raw))
}
impl Candidate {
    pub fn parse(
        value: &Value,
        config: &Config,
        identity: &Identity,
        terms: &Value,
    ) -> Result<Self> {
        let request: Request = serde_json::from_value(value.clone())?;
        ensure!(
            request.release == config.release.scope()?
                && request.fee_slot < 3
                && request.funding_cap > 0
                && request.funding_cap <= config.funding_cap,
            "request release/budget/slot"
        );
        ensure!(request.nullifiers[0] != request.nullifiers[1], "duplicate nullifier");
        for s in [
            &request.intent,
            &request.fee_note_body,
            &request.nullifiers[0],
            &request.nullifiers[1],
        ] {
            scalar(s)?;
        }
        ensure!(request.body_b64.len() <= 349528, "body base64 bound");
        let bytes = STANDARD.decode(&request.body_b64)?;
        ensure!(
            !bytes.is_empty()
                && bytes.len() <= 256 * 1024
                && STANDARD.encode(&bytes) == request.body_b64
                && protocol::hash(&bytes) == request.body_sha256,
            "exact body bytes"
        );
        let body = ordinary_boc(&bytes)?;
        let mut s = SliceData::load_cell(body.clone())?;
        ensure!(s.get_next_u32()? == 0x53485002, "Shield transact required");
        let query = s.get_next_u64()?;
        let _anchor_kind = s.get_next_int(8)?;
        let _anchor_id = s.get_next_u32()?;
        ensure!(s.get_next_u32()? == request.valid_until, "wire expiry mismatch");
        ensure!(
            Coins::construct_from(&mut s)?.is_zero() && Coins::construct_from(&mut s)?.is_zero(),
            "local provider supports private transfers only"
        );
        ensure!(s.get_next_int(2)? == 0, "private transfer recipient");
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
                fee_payload = node_contracts::relayer_bond::chain_bytes(&c, 1233)?;
            }
        }
        ensure!(
            terms["slot"] == request.fee_slot
                && terms["note_index"] == request.fee_note_index
                && terms["valid_until"]
                    .as_u64()
                    .is_some_and(|expiry| u64::from(request.valid_until) <= expiry),
            "candidate quote binding"
        );
        let mut q = b"TOS-BR1-QUOTE\0".to_vec();
        q.extend(protocol::canonical(terms)?);
        ensure!(protocol::hash(&q) == request.quote_hash, "quote digest mismatch");
        let fee_body = scalar(&request.fee_note_body)?;
        let fee_terms = shielded_pool_wallet::relayer_fee::FeeTerms {
            execution_domain: identity.recipient().execution_domain(),
            slot: request.fee_slot,
            amount: u128::from(config.fee),
            note_key_index: request.fee_note_index,
        };
        shielded_pool_wallet::relayer_fee::preflight_fee_output(
            identity.recipient(),
            &fee_terms,
            &fee_payload,
            fee_body,
        )?;
        let mut wire = b"TOS-BR1-REQUEST\0".to_vec();
        wire.extend(protocol::canonical(value)?);
        Ok(Self { request, identity: protocol::hash(&wire), body, fee_payload, fee_body })
    }
}
