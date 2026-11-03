// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Owned replay session. Initial hashes and head metadata must come from one
//! verified observation; this adapter does not authenticate caller expectations.
use crate::{
    decimal,
    history::hash,
    pool::read_cell,
    recover_notes,
    replay::{Head, Replay},
    response, Error, Result, ScanResult, TosShieldedResponse, MAX_OUTPUTS, MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chain_block::ConfigParamEnum;
use serde::{Deserialize, Serialize};
use shielded_pool_circuit::{field::Fr, wire};
use shielded_pool_codec::{compute_fee, PoolState, BOUNCE_GAS_CEILING};
use shielded_pool_wallet::{keys::PoolInstance, ledger::Ledger};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    global_id: i32,
    account_id: String,
    last_hash: String,
    last_lt: String,
    account_root: String,
    shard_time: String,
    pool_state_boc: String,
    pool_data_hash: String,
    gas_boc: String,
    gas_hash: String,
}

enum State {
    Building(Box<Replay>),
    Ready(Box<Ledger>),
    Failed,
}
/// Opaque and single-owner. All calls, including free, must be serialized by the caller.
pub struct TosShieldedReplay {
    state: State,
    domain: Fr,
}

fn bound_cell(encoded: &str, expected: &str) -> Result<chain_block::Cell> {
    let bytes = STANDARD.decode(encoded).map_err(|_| Error::InvalidInput)?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(Error::InvalidInput);
    }
    let root = read_cell(&bytes)?;
    if root.cell_type() != chain_block::CellType::Ordinary || root.level() != 0 {
        return Err(Error::InvalidInput);
    }
    if root.repr_hash().as_array() != &hash(expected)? {
        return Err(Error::InvalidInput);
    }
    Ok(root)
}

impl TosShieldedReplay {
    fn create(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Error::Limit);
        }
        let r: Request = serde_json::from_slice(bytes).map_err(|_| Error::InvalidInput)?;
        if r.version != 1 {
            return Err(Error::InvalidInput);
        }
        let head = Head {
            account_id: hash(&r.account_id)?,
            last_hash: hash(&r.last_hash)?,
            last_lt: decimal(&r.last_lt)?,
            account_root: hash(&r.account_root)?,
            shard_time: decimal(&r.shard_time)?,
        };
        let state = PoolState::parse(&bound_cell(&r.pool_state_boc, &r.pool_data_hash)?)
            .map_err(|_| Error::InvalidInput)?;
        let gas = bound_cell(&r.gas_boc, &r.gas_hash)?;
        let ConfigParamEnum::ConfigParam21(prices) =
            ConfigParamEnum::construct_from_cell_and_number(gas, 21)
                .map_err(|_| Error::InvalidInput)?
        else {
            return Err(Error::InvalidInput);
        };
        let charge = compute_fee(&prices, BOUNCE_GAS_CEILING).map_err(|_| Error::InvalidInput)?;
        let domain = wire::execution_domain(r.global_id, &head.account_id);
        Ok(Self { state: State::Building(Box::new(Replay::new(head, &state, charge)?)), domain })
    }

    fn scan(&self, seed: &[u8; 32], offset: usize, count: usize) -> Result<Zeroizing<Vec<u8>>> {
        let State::Ready(ledger) = &self.state else {
            return Err(Error::InvalidInput);
        };
        let end = offset.checked_add(count).ok_or(Error::Limit)?;
        if count == 0
            || count > MAX_OUTPUTS
            || offset > ledger.outputs().len()
            || end > ledger.outputs().len()
        {
            return Err(Error::InvalidInput);
        }
        let instance = PoolInstance::new(seed, self.domain);
        let outputs = ledger.outputs()[offset..end]
            .iter()
            .map(|o| (o.observed.clone(), o.leaf))
            .collect::<Vec<_>>();
        let page = Page {
            version: 1,
            output_offset: offset.to_string(),
            output_count: count.to_string(),
            total_outputs: ledger.outputs().len().to_string(),
            scan: recover_notes(&instance, &outputs, ledger.published_nullifiers())?,
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&page).map_err(|_| Error::InvalidInput)?);
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
struct Page {
    version: u8,
    output_offset: String,
    output_count: String,
    total_outputs: String,
    scan: ScanResult,
}

/// # Safety
/// Non-null pointers identify live allocations of the stated length.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_create(
    request: *const u8,
    length: usize,
) -> *mut TosShieldedReplay {
    if request.is_null() || length > MAX_REQUEST_BYTES {
        return ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        TosShieldedReplay::create(unsafe { slice::from_raw_parts(request, length) })
    })) {
        Ok(Ok(session)) => Box::into_raw(Box::new(session)),
        _ => ptr::null_mut(),
    }
}

unsafe fn mutate(
    session: *mut TosShieldedReplay,
    operation: impl FnOnce(State) -> Result<State>,
) -> i32 {
    if session.is_null() {
        return 1;
    }
    let owner = unsafe { &mut *session };
    // Poison before entering any operation that can reject, mutate or unwind.
    let previous = std::mem::replace(&mut owner.state, State::Failed);
    match catch_unwind(AssertUnwindSafe(|| operation(previous))) {
        Ok(Ok(next)) => {
            owner.state = next;
            0
        }
        Ok(Err(_)) => 1,
        Err(_) => 2,
    }
}

/// # Safety
/// Session is live, exclusively owned and not concurrently used. BOC pointer is live for length.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_push(
    session: *mut TosShieldedReplay,
    boc: *const u8,
    length: usize,
) -> i32 {
    unsafe {
        mutate(session, |old| {
            if boc.is_null() || length > MAX_REQUEST_BYTES {
                return Err(Error::InvalidInput);
            }
            let State::Building(mut replay) = old else {
                return Err(Error::InvalidInput);
            };
            replay.push(slice::from_raw_parts(boc, length))?;
            Ok(State::Building(replay))
        })
    }
}

/// # Safety
/// Session is live, exclusively owned and not concurrently used.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_finish(session: *mut TosShieldedReplay) -> i32 {
    unsafe {
        mutate(session, |old| {
            let State::Building(replay) = old else {
                return Err(Error::InvalidInput);
            };
            Ok(State::Ready(Box::new(replay.finish()?)))
        })
    }
}

/// # Safety
/// Session is live and not concurrently mutated/freed.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_info(
    session: *const TosShieldedReplay,
) -> *mut TosShieldedResponse {
    response(|| {
        if session.is_null() {
            return Err(Error::InvalidInput);
        }
        let State::Ready(ledger) = &unsafe { &*session }.state else {
            return Err(Error::InvalidInput);
        };
        let checkpoint = ledger.checkpoint();
        serde_json::to_vec(&serde_json::json!({"version":1,"total_outputs":ledger.outputs().len().to_string(),
            "commitment_root":hex::encode(shielded_pool_circuit::field::fr_to_be(&checkpoint.commitment_root)),
            "commitment_next_index":checkpoint.commitment_next_index.to_string(),
            "nullifier_root":hex::encode(shielded_pool_circuit::field::fr_to_be(&checkpoint.nullifier_root)),
            "nullifier_next_index":checkpoint.nullifier_next_index.to_string(),
            "reserved_recovery_leaves":checkpoint.reserved_recovery_leaves.to_string(),
            "native_liability":checkpoint.native_liability.to_string()}))
            .map(Zeroizing::new).map_err(|_|Error::InvalidInput)
    })
}

/// # Safety
/// Session is live and not concurrently mutated/freed. Seed pointer is live for seed_length.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_scan(
    session: *const TosShieldedReplay,
    seed: *const u8,
    seed_length: usize,
    offset: usize,
    count: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if session.is_null() || seed.is_null() || seed_length != 32 {
            return Err(Error::InvalidInput);
        }
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(unsafe { slice::from_raw_parts(seed, 32) });
        unsafe { &*session }.scan(&key, offset, count)
    })
}

/// # Safety
/// Non-null session is a live allocation from this library, freed exactly once without concurrent calls.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_free(session: *mut TosShieldedReplay) {
    if !session.is_null() {
        drop(unsafe { Box::from_raw(session) });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use shielded_pool_circuit::{notes, wire};
    use shielded_pool_wallet::{
        delivery::{self, Kind, Plaintext},
        ledger::{Event, Transact},
    };

    #[test]
    fn completed_scan_uses_the_full_published_nullifier_set() {
        // Synthetic ledger unit test, not transaction/proof execution evidence.
        let domain = Fr::from(7u64);
        let seed = [0x42; 32];
        let keys = PoolInstance::new(&seed, domain);
        let plain = Plaintext {
            slot: 0,
            kind: Kind::Ordinary,
            amount: 1000,
            note_secret: Fr::from(123u64),
            note_key_index: 7,
            owner_nf_key_hash: keys.owner_nf_key_hash(7).unwrap(),
            pq_auth_key_hash: keys.pq_auth_key_hash(7).unwrap(),
        };
        let payload =
            delivery::seal(&keys.mlkem_encapsulation_key().unwrap(), domain, &plain).unwrap();
        let owner = notes::owner_commitment(
            plain.owner_nf_key_hash,
            plain.pq_auth_key_hash,
            plain.note_secret,
        );
        let body = notes::note_body_commitment(
            owner,
            Fr::from(plain.amount),
            wire::output_data_hash(&payload),
        );
        let nullifier = notes::nullifier(body, keys.owner_nf_key(7).unwrap());
        let mut ledger = Ledger::genesis();
        ledger
            .apply(
                &Event::Deposit { amount: 1000, owner_commitment: owner, output_data: payload },
                0,
            )
            .unwrap();
        let before = TosShieldedReplay { state: State::Ready(Box::new(ledger.clone())), domain };
        let page: serde_json::Value =
            serde_json::from_slice(&before.scan(&seed, 0, 1).unwrap()).unwrap();
        assert_eq!(page["scan"]["batch_unspent_balance"], "1000");
        ledger
            .apply(
                &Event::Transact(Box::new(Transact {
                    intent_digest: Fr::from(77u64),
                    nullifiers: [nullifier, Fr::from(999u64)],
                    note_bodies: [Fr::from(11u64), Fr::from(12u64), Fr::from(13u64)],
                    payloads: std::array::from_fn(|_| vec![0; delivery::OUTPUT_DATA_BYTES]),
                    public_amount_out: 0,
                    withdrawal_fee: 0,
                    recovery_owner_commitment: Fr::from(0u64),
                    recovery_payload: None,
                    payout: None,
                })),
                0,
            )
            .unwrap();
        let after = TosShieldedReplay { state: State::Ready(Box::new(ledger)), domain };
        let page: serde_json::Value =
            serde_json::from_slice(&after.scan(&seed, 0, 1).unwrap()).unwrap();
        assert_eq!(page["scan"]["batch_unspent_balance"], "0");
        assert_eq!(page["scan"]["notes"][0]["spent"], true);
    }

    #[test]
    fn contained_mutator_panic_leaves_the_owner_failed() {
        // Deliberate test-only unwind through the same FFI ownership boundary.
        let mut owner = TosShieldedReplay {
            state: State::Ready(Box::new(Ledger::genesis())),
            domain: Fr::from(7u64),
        };
        let result = unsafe {
            mutate(&mut owner, |_old| std::panic::resume_unwind(Box::new("injected test unwind")))
        };
        assert_eq!(result, 2);
        assert!(matches!(owner.state, State::Failed));
        assert_eq!(unsafe { tos_shielded_replay_finish(&mut owner) }, 1);
    }
}
