// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Bounded cell decoding only. A decoded state is not an authenticated state.
use base64::{engine::general_purpose::STANDARD, Engine};
use chain_block::{BocReader, Cell};
use serde::Serialize;
use shielded_pool_circuit::field::fr_from_be;
use shielded_pool_codec::{AnchorEntry, PoolState};
use std::io::Cursor;
use zeroize::Zeroizing;

use crate::{Error, Result, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};

pub const MAX_BOC_CELLS: usize = 32768;
pub const MAX_BOC_DEPTH: u16 = 128;

pub(crate) fn read_cell(bytes: &[u8]) -> Result<Cell> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(Error::Limit);
    }
    if bytes.len() < 6 || bytes[..4] != [0xb5, 0xee, 0x9c, 0x72] {
        return Err(Error::InvalidInput);
    }
    // Proof-extracted state and transaction cells use the generic BOC encoding.
    // Inspect cardinality before the reader can allocate any cell tables.
    let width = usize::from(bytes[4] & 7);
    if !(1..=4).contains(&width)
        || !(1..=8).contains(&bytes[5])
        || bytes.len() < 6 + 3 * width + usize::from(bytes[5])
    {
        return Err(Error::InvalidInput);
    }
    let integer =
        |start| bytes[start..start + width].iter().fold(0u64, |n, b| (n << 8) | u64::from(*b));
    let cells = integer(6);
    if cells > MAX_BOC_CELLS as u64 {
        return Err(Error::Limit);
    }
    if cells == 0 || integer(6 + width) != 1 || integer(6 + 2 * width) != 0 {
        return Err(Error::InvalidInput);
    }
    let total_start = 6 + 3 * width;
    let total_end = total_start + usize::from(bytes[5]);
    let declared_total =
        bytes[total_start..total_end].iter().fold(0u64, |n, b| (n << 8) | u64::from(*b));
    // The underlying reader narrows this field to usize. Check the full wire
    // width first so a 32-bit target cannot accept a wrapped data size.
    if declared_total > bytes.len() as u64 {
        return Err(Error::Limit);
    }
    let mut input = Cursor::new(bytes);
    let root = BocReader::new()
        .set_max_cell_depth(MAX_BOC_DEPTH)
        .read(&mut input)
        .and_then(|boc| boc.withdraw_single_root())
        .map_err(|_| Error::InvalidInput)?;
    if input.position() != bytes.len() as u64 {
        return Err(Error::InvalidInput);
    }
    Ok(root)
}

#[derive(Serialize)]
struct Anchor {
    slot: u16,
    id: String,
    root: String,
}
fn anchors(entries: &[AnchorEntry]) -> Result<Vec<Anchor>> {
    entries
        .iter()
        .map(|entry| {
            fr_from_be(&entry.root).map_err(|_| Error::InvalidInput)?;
            Ok(Anchor { slot: entry.slot, id: entry.id.to_string(), root: hex::encode(entry.root) })
        })
        .collect()
}
#[derive(Serialize)]
struct State {
    version: u8,
    data_hash: String,
    commitment_root: String,
    commitment_next_index: String,
    reserved_recovery_leaves: String,
    nullifier_root: String,
    nullifier_next_index: String,
    last_anchor_epoch: String,
    native_liability: String,
    reserve_floor: String,
    profile_hash: String,
    poseidon_manifest_hash: String,
    groth16_vk_hash: String,
    withdrawal_fee: String,
    denominations: Vec<String>,
    verifying_key: String,
    recent_anchors: Vec<Anchor>,
    epoch_anchors: Vec<Anchor>,
}

pub fn decode_pool_state(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let root = read_cell(bytes)?;
    let pool = PoolState::parse(&root).map_err(|_| Error::InvalidInput)?;
    fr_from_be(&pool.commitment_root).map_err(|_| Error::InvalidInput)?;
    fr_from_be(&pool.nullifier_root).map_err(|_| Error::InvalidInput)?;
    let state = State {
        version: 1,
        data_hash: hex::encode(root.repr_hash().as_slice()),
        commitment_root: hex::encode(pool.commitment_root),
        commitment_next_index: pool.commitment_next_index.to_string(),
        reserved_recovery_leaves: pool.reserved_recovery_leaves.to_string(),
        nullifier_root: hex::encode(pool.nullifier_root),
        nullifier_next_index: pool.nullifier_next_index.to_string(),
        last_anchor_epoch: pool.last_anchor_epoch.to_string(),
        native_liability: pool.native_liability.to_string(),
        reserve_floor: pool.reserve_floor.to_string(),
        profile_hash: hex::encode(pool.config.profile_hash),
        poseidon_manifest_hash: hex::encode(pool.config.poseidon_manifest_hash),
        groth16_vk_hash: hex::encode(pool.config.groth16_vk_hash),
        withdrawal_fee: pool.config.withdrawal_fee.to_string(),
        denominations: pool.config.denominations.iter().map(ToString::to_string).collect(),
        verifying_key: STANDARD.encode(&pool.verifying_key),
        recent_anchors: anchors(&pool.anchors.recent)?,
        epoch_anchors: anchors(&pool.anchors.epoch)?,
    };
    let output = Zeroizing::new(serde_json::to_vec(&state).map_err(|_| Error::InvalidInput)?);
    if output.len() > MAX_RESPONSE_BYTES {
        return Err(Error::Limit);
    }
    Ok(output)
}
