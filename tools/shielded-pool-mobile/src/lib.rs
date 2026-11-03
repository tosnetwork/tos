// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Bounded native wallet operations for mobile callers. The caller owns
//! proof verification, durable index allocation, encrypted storage and transport.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use shielded_pool_circuit::{
    field::{fr_from_be, fr_to_be, Fr},
    notes,
};
use shielded_pool_wallet::{
    delivery::OUTPUT_DATA_BYTES,
    descriptor::Descriptor,
    import::ChainSlot,
    keys::PoolInstance,
    scan::{self, ObservedOutput},
};
use std::{
    collections::BTreeSet,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub mod history;
pub mod pool;
pub mod replay;
pub mod replay_ffi;

pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_OUTPUTS: usize = 512;
pub const MAX_NULLIFIERS: usize = 8192;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    Crypto,
    Limit,
}
type Result<T> = std::result::Result<T, Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanRequest {
    version: u8,
    execution_domain: String,
    outputs: Vec<Output>,
    published_nullifiers: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    slot: u8,
    output_data: String,
    output_data_hash: String,
    note_body: String,
    recovered: Option<String>,
    leaf_index: Option<String>,
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
struct ScanResult {
    version: u8,
    // This is a batch result, never a claim of a complete/fresh wallet balance.
    batch_unspent_balance: String,
    next_note_key_index: String,
    diagnostics_count: usize,
    notes: Vec<Note>,
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
struct Note {
    note_key_index: String,
    amount: String,
    note_secret: String,
    owner_commitment: String,
    note_body: String,
    output_data_hash: String,
    nullifier: String,
    spendable: bool,
    spent: bool,
    leaf_index: Option<String>,
}

fn word(text: &str) -> Result<Fr> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(Error::InvalidInput);
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| Error::InvalidInput)?;
    fr_from_be(&bytes).map_err(|_| Error::InvalidInput)
}

fn decimal<T: std::str::FromStr>(text: &str) -> Result<T> {
    if text.is_empty()
        || text.len() > 39
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::InvalidInput);
    }
    text.parse().map_err(|_| Error::InvalidInput)
}

pub fn issue_descriptor(seed: &[u8; 32], domain: &[u8; 32], index: u64) -> Result<Vec<u8>> {
    let domain = fr_from_be(domain).map_err(|_| Error::InvalidInput)?;
    let instance = PoolInstance::new(seed, domain);
    Descriptor::issue(&instance, index).map(|d| d.to_bytes()).map_err(|_| Error::Crypto)
}

pub fn scan_batch(seed: &[u8; 32], request: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if request.len() > MAX_REQUEST_BYTES {
        return Err(Error::Limit);
    }
    let request: ScanRequest = serde_json::from_slice(request).map_err(|_| Error::InvalidInput)?;
    if request.version != 1 {
        return Err(Error::InvalidInput);
    }
    if request.outputs.len() > MAX_OUTPUTS || request.published_nullifiers.len() > MAX_NULLIFIERS {
        return Err(Error::Limit);
    }
    let instance = PoolInstance::new(seed, word(&request.execution_domain)?);
    let mut outputs = Vec::with_capacity(request.outputs.len());
    for item in request.outputs {
        if item.slot > 2 || item.output_data.len() != OUTPUT_DATA_BYTES.div_ceil(3) * 4 {
            return Err(Error::InvalidInput);
        }
        let data = STANDARD.decode(&item.output_data).map_err(|_| Error::InvalidInput)?;
        if data.len() != OUTPUT_DATA_BYTES || STANDARD.encode(&data) != item.output_data {
            return Err(Error::InvalidInput);
        }
        let observed = ObservedOutput {
            slot: item.slot,
            output_data: data,
            chain: ChainSlot {
                output_data_hash: word(&item.output_data_hash)?,
                note_body: word(&item.note_body)?,
                recovered: item.recovered.as_deref().map(decimal).transpose()?,
            },
        };
        outputs.push((observed, item.leaf_index.as_deref().map(decimal).transpose()?));
    }
    let mut published = BTreeSet::new();
    for item in request.published_nullifiers {
        if !published.insert(word(&item)?) {
            return Err(Error::InvalidInput);
        }
    }
    let result = recover_notes(&instance, &outputs, &published)?;
    let response = Zeroizing::new(serde_json::to_vec(&result).map_err(|_| Error::InvalidInput)?);
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(Error::Limit);
    }
    Ok(response)
}

fn recover_notes(
    instance: &PoolInstance,
    outputs: &[(ObservedOutput, Option<u64>)],
    published: &BTreeSet<Fr>,
) -> Result<ScanResult> {
    if outputs.len() > MAX_OUTPUTS {
        return Err(Error::Limit);
    }
    let mut recovered = scan::recover_indexed(instance, outputs).map_err(|_| Error::Crypto)?;
    recovered.reconcile_spent(instance, published).map_err(|_| Error::Crypto)?;
    let balance = recovered
        .spendable_notes()
        .try_fold(0u128, |sum, note| sum.checked_add(note.amount).ok_or(Error::Limit))?;
    let mut result = ScanResult {
        version: 1,
        batch_unspent_balance: balance.to_string(),
        next_note_key_index: recovered.next_note_key_index.to_string(),
        diagnostics_count: recovered.diagnostics.len(),
        notes: Vec::with_capacity(recovered.notes.len()),
    };
    for (index, note) in recovered.notes.iter().enumerate() {
        let owner_key = instance.owner_nf_key(note.note_key_index).map_err(|_| Error::Crypto)?;
        result.notes.push(Note {
            note_key_index: note.note_key_index.to_string(),
            amount: note.amount.to_string(),
            note_secret: hex::encode(fr_to_be(&note.note_secret)),
            owner_commitment: hex::encode(fr_to_be(&note.owner_commitment)),
            note_body: hex::encode(fr_to_be(&note.note_body)),
            output_data_hash: hex::encode(fr_to_be(&note.output_data_hash)),
            nullifier: hex::encode(fr_to_be(&notes::nullifier(note.note_body, owner_key))),
            spendable: note.spendable,
            spent: note.spent,
            leaf_index: recovered.leaves.get(index).copied().flatten().map(|v| v.to_string()),
        });
    }
    Ok(result)
}

/// Opaque allocation; no mobile caller may construct or mutate it.
pub struct TosShieldedResponse {
    status: i32,
    bytes: Zeroizing<Vec<u8>>,
}

fn response(call: impl FnOnce() -> Result<Zeroizing<Vec<u8>>>) -> *mut TosShieldedResponse {
    let (status, bytes) = match catch_unwind(AssertUnwindSafe(call)) {
        Ok(Ok(bytes)) => (0, bytes),
        Ok(Err(_)) => (1, Zeroizing::new(Vec::new())),
        Err(_) => (2, Zeroizing::new(Vec::new())),
    };
    Box::into_raw(Box::new(TosShieldedResponse { status, bytes }))
}

/// # Safety
/// Non-null pointers must identify live allocations of the stated length.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_descriptor(
    seed: *const u8,
    seed_len: usize,
    domain: *const u8,
    domain_len: usize,
    index: u64,
) -> *mut TosShieldedResponse {
    response(|| {
        if seed.is_null() || seed_len != 32 || domain.is_null() || domain_len != 32 {
            return Err(Error::InvalidInput);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(unsafe { slice::from_raw_parts(seed, 32) });
        let mut domain_bytes = [0u8; 32];
        domain_bytes.copy_from_slice(unsafe { slice::from_raw_parts(domain, 32) });
        issue_descriptor(&key, &domain_bytes, index).map(Zeroizing::new)
    })
}

/// # Safety
/// Non-null pointers must identify live allocations of the stated length.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_scan(
    seed: *const u8,
    seed_len: usize,
    request: *const u8,
    request_len: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if seed.is_null() || seed_len != 32 || request.is_null() || request_len > MAX_REQUEST_BYTES
        {
            return Err(Error::InvalidInput);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(unsafe { slice::from_raw_parts(seed, 32) });
        scan_batch(&key, unsafe { slice::from_raw_parts(request, request_len) })
    })
}

/// # Safety
/// A non-null response must be a live handle from this library.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_response_status(response: *const TosShieldedResponse) -> i32 {
    if response.is_null() {
        1
    } else {
        unsafe { (*response).status }
    }
}
/// # Safety
/// A non-null response must be a live handle from this library.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_response_data(
    response: *const TosShieldedResponse,
) -> *const u8 {
    if response.is_null() {
        ptr::null()
    } else {
        unsafe { (*response).bytes.as_ptr() }
    }
}
/// # Safety
/// A non-null response must be a live handle from this library.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_response_size(response: *const TosShieldedResponse) -> usize {
    if response.is_null() {
        0
    } else {
        unsafe { (*response).bytes.len() }
    }
}
/// # Safety
/// A non-null response must be a live handle from this library, freed once.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_response_free(response: *mut TosShieldedResponse) {
    if !response.is_null() {
        drop(unsafe { Box::from_raw(response) });
    }
}

/// Decode one proof-extracted state cell. This does not verify a chain proof.
/// # Safety
/// A non-null input must identify a live allocation of the stated length.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_pool_state(
    data: *const u8,
    length: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if data.is_null() || length > MAX_REQUEST_BYTES {
            return Err(Error::InvalidInput);
        }
        pool::decode_pool_state(unsafe { slice::from_raw_parts(data, length) })
    })
}

/// Decode one transaction against expectations bound to the account proof or a newer link.
/// # Safety
/// Non-null pointers must identify live allocations of the stated length.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_history_transaction(
    request: *const u8,
    length: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if request.is_null() || length > MAX_REQUEST_BYTES {
            return Err(Error::InvalidInput);
        }
        history::decode_transaction(unsafe { slice::from_raw_parts(request, length) })
    })
}
