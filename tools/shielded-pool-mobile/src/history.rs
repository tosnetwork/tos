// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Decode one history link against caller-supplied authenticated expectations.
//! The initial expectations must come from an account proof; subsequent ones
//! come from the previous fields of the already bound newer transaction.
use base64::{engine::general_purpose::STANDARD, Engine};
use chain_block::{CellType, Deserializable, Transaction};
use serde::Deserialize;
use serde_json::{json, Value};
use shielded_pool_codec::{classify, PoolTransaction};
use zeroize::Zeroizing;

use crate::{decimal, pool::read_cell, Error, Result, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    boc: String,
    expected_hash: String,
    expected_lt: String,
    account_id: String,
    post_state_hash: String,
    maximum_time: String,
}

fn hash(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(Error::InvalidInput);
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| Error::InvalidInput)?;
    Ok(bytes)
}

fn field(bytes: &[u8; 32]) -> Result<String> {
    shielded_pool_circuit::field::fr_from_be(bytes).map_err(|_| Error::InvalidInput)?;
    Ok(hex::encode(bytes))
}

fn event(transaction: &Transaction) -> Result<Value> {
    Ok(match classify(transaction).map_err(|_| Error::InvalidInput)? {
        PoolTransaction::NoStateChange(reason) => {
            json!({"kind": "no-state-change", "reason": reason})
        }
        PoolTransaction::Deposit(body) => json!({
            "kind": "deposit", "amount": body.amount.to_string(),
            "owner_commitment": field(&body.owner_commitment)?,
            "output_data": STANDARD.encode(body.output_data),
        }),
        PoolTransaction::Bounce { original_body_hash, sender, value } => json!({
            "kind": "bounce", "original_body_hash": hex::encode(original_body_hash),
            "sender": sender.to_string(), "value": value.to_string(),
        }),
        PoolTransaction::Transact { body, payout } => json!({
            "kind": "transact", "intent_digest": field(&body.intent_digest)?,
            "nullifiers": [field(&body.nullifiers[0])?, field(&body.nullifiers[1])?],
            "note_bodies": [field(&body.note_bodies[0])?, field(&body.note_bodies[1])?, field(&body.note_bodies[2])?],
            "payloads": body.payloads.iter().map(|v| STANDARD.encode(v)).collect::<Vec<_>>(),
            "public_amount_out": body.public_amount_out.to_string(),
            "withdrawal_fee": body.withdrawal_fee.to_string(),
            "recovery_owner_commitment": field(&body.recovery_owner_commitment)?,
            "recovery_payload": body.recovery_payload.as_ref().map(|v| STANDARD.encode(v)),
            "payout": payout.map(|p| json!({"recipient": p.recipient.to_string(),
                "value": p.value.to_string(), "body_hash": hex::encode(p.body_hash)})),
        }),
    })
}

pub fn decode_transaction(request: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if request.len() > MAX_REQUEST_BYTES {
        return Err(Error::Limit);
    }
    let request: Request = serde_json::from_slice(request).map_err(|_| Error::InvalidInput)?;
    if request.version != 1 || request.boc.len() > MAX_REQUEST_BYTES {
        return Err(Error::InvalidInput);
    }
    let expected_hash = hash(&request.expected_hash)?;
    let account_id = hash(&request.account_id)?;
    let post_state_hash = hash(&request.post_state_hash)?;
    let expected_lt: u64 = decimal(&request.expected_lt)?;
    let maximum_time: u32 = decimal(&request.maximum_time)?;
    if expected_lt == 0 || expected_hash == [0; 32] {
        return Err(Error::InvalidInput);
    }
    let bytes = STANDARD.decode(&request.boc).map_err(|_| Error::InvalidInput)?;
    if STANDARD.encode(&bytes) != request.boc {
        return Err(Error::InvalidInput);
    }
    let root = read_cell(&bytes)?;
    if root.cell_type() != CellType::Ordinary
        || root.level() != 0
        || root.repr_hash().as_array() != &expected_hash
    {
        return Err(Error::InvalidInput);
    }
    let transaction = Transaction::construct_from_cell(root).map_err(|_| Error::InvalidInput)?;
    let update = transaction.read_state_update().map_err(|_| Error::InvalidInput)?;
    if transaction.logical_time() != expected_lt
        || transaction.account_id() != &chain_block::SliceData::from_raw(account_id.to_vec(), 256)
        || transaction.now() > maximum_time
        || update.new_hash.as_array() != &post_state_hash
    {
        return Err(Error::InvalidInput);
    }
    let previous_lt = transaction.prev_trans_lt();
    let previous_hash = transaction.prev_trans_hash();
    if previous_lt >= expected_lt || (previous_lt == 0) != (previous_hash.as_array() == &[0; 32]) {
        return Err(Error::InvalidInput);
    }
    let output = json!({"version": 1, "hash": hex::encode(expected_hash),
        "logical_time": expected_lt.to_string(), "account_id": hex::encode(account_id),
        "time": transaction.now().to_string(), "previous_lt": previous_lt.to_string(),
        "previous_hash": hex::encode(previous_hash.as_slice()),
        "pre_state_hash": hex::encode(update.old_hash.as_slice()),
        "post_state_hash": hex::encode(update.new_hash.as_slice()), "event": event(&transaction)?});
    let bytes = Zeroizing::new(serde_json::to_vec(&output).map_err(|_| Error::InvalidInput)?);
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::Limit);
    }
    Ok(bytes)
}
