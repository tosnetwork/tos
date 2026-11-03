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
    receive_binding: Option<String>,
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
    receive_binding: Option<[u8; 228]>,
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
        let receive_binding = r
            .receive_binding
            .map(|encoded| {
                let mut bytes = [0; 228];
                hex::decode_to_slice(encoded, &mut bytes).map_err(|_| Error::InvalidInput)?;
                if bytes[..4] != r.global_id.to_be_bytes()
                    || bytes[4..36] != head.account_id
                    || bytes[132..164] != state.config.profile_hash
                    || bytes[164..196] != state.config.poseidon_manifest_hash
                    || bytes[196..228] != state.config.groth16_vk_hash
                {
                    return Err(Error::InvalidInput);
                }
                Ok(bytes)
            })
            .transpose()?;
        Ok(Self {
            state: State::Building(Box::new(Replay::new(head, &state, charge)?)),
            domain,
            receive_binding,
        })
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

/// Issue a descriptor only after committing its index in the canonical store.
///
/// # Safety
/// The session must be live and serialized. All input pointers must be valid
/// for their lengths. The caller authenticates freshness, the original master,
/// and the binding against the same observation used to create the replay.
#[cfg(unix)]
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_receive(
    session: *const TosShieldedReplay,
    seed: *const u8,
    seed_length: usize,
    root: *const u8,
    root_length: usize,
    binding: *const u8,
    binding_length: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if session.is_null()
            || seed.is_null()
            || root.is_null()
            || binding.is_null()
            || seed_length != 32
            || !(1..=4096).contains(&root_length)
            || binding_length != 228
        {
            return Err(Error::InvalidInput);
        }
        let owner = unsafe { &*session };
        let State::Ready(ledger) = &owner.state else {
            return Err(Error::InvalidInput);
        };
        let root = std::str::from_utf8(unsafe { slice::from_raw_parts(root, root_length) })
            .map_err(|_| Error::InvalidInput)?;
        if root.as_bytes().contains(&0) || !std::path::Path::new(root).is_absolute() {
            return Err(Error::InvalidInput);
        }
        let bytes = unsafe { slice::from_raw_parts(binding, binding_length) };
        if owner.receive_binding.as_ref().map(|value| value.as_slice()) != Some(bytes) {
            return Err(Error::InvalidInput);
        }
        let field = |offset| -> Result<[u8; 32]> {
            bytes[offset..offset + 32].try_into().map_err(|_| Error::InvalidInput)
        };
        let binding = crate::sealed::Binding {
            global_id: i32::from_be_bytes(bytes[..4].try_into().map_err(|_| Error::InvalidInput)?),
            pool_account: field(4)?,
            genesis_root: field(36)?,
            genesis_file: field(68)?,
            code_hash: field(100)?,
            profile_hash: field(132)?,
            manifest_hash: field(164)?,
            verifying_key_hash: field(196)?,
        };
        if wire::execution_domain(binding.global_id, &binding.pool_account) != owner.domain {
            return Err(Error::InvalidInput);
        }
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(unsafe { slice::from_raw_parts(seed, 32) });
        let recovered = crate::wallet::recover_complete(
            ledger.outputs(),
            ledger.published_nullifiers(),
            &key,
            owner.domain,
        )?;
        if !recovered.0.diagnostics.is_empty() {
            return Err(Error::InvalidInput);
        }
        let next = match recovered.0.notes.iter().map(|note| note.note_key_index).max() {
            Some(index) => index.checked_add(1).ok_or(Error::Limit)?,
            None => 0,
        };
        let mut store = crate::store::StateStore::open_wallet(
            std::path::Path::new(root),
            crate::sealed::RecordCipher::derive(&key, binding),
        )
        .map_err(|_| Error::InvalidInput)?;
        let indices = store.reserve_indices(Some(next), 1).map_err(|_| Error::InvalidInput)?;
        let index = indices.first().copied().ok_or(Error::InvalidInput)?;
        crate::issue_descriptor(&key, &shielded_pool_circuit::field::fr_to_be(&owner.domain), index)
            .map(Zeroizing::new)
    })
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

/// Complete global scan, not a sum of independent page balances.
/// # Safety
/// Session is live and serialized; seed points to seed_length readable bytes.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_summary(
    session: *const TosShieldedReplay,
    seed: *const u8,
    seed_length: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if session.is_null() || seed.is_null() || seed_length != 32 {
            return Err(Error::InvalidInput);
        }
        let State::Ready(ledger) = &unsafe { &*session }.state else {
            return Err(Error::InvalidInput);
        };
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(unsafe { slice::from_raw_parts(seed, 32) });
        crate::wallet::summary(ledger, &key, unsafe { &*session }.domain)
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
        let before = TosShieldedReplay {
            state: State::Ready(Box::new(ledger.clone())),
            domain,
            receive_binding: None,
        };
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
        let after = TosShieldedReplay {
            state: State::Ready(Box::new(ledger)),
            domain,
            receive_binding: None,
        };
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
            receive_binding: None,
        };
        let result = unsafe {
            mutate(&mut owner, |_old| std::panic::resume_unwind(Box::new("injected test unwind")))
        };
        assert_eq!(result, 2);
        assert!(matches!(owner.state, State::Failed));
        assert_eq!(unsafe { tos_shielded_replay_finish(&mut owner) }, 1);
    }
    fn summary_json(owner: &TosShieldedReplay, seed: &[u8; 32]) -> serde_json::Value {
        let raw = unsafe { tos_shielded_replay_summary(owner, seed.as_ptr(), seed.len()) };
        assert!(!raw.is_null());
        let response = unsafe { Box::from_raw(raw) };
        assert_eq!(response.status, 0);
        serde_json::from_slice(&response.bytes).unwrap()
    }
    #[test]
    fn complete_summary_deduplicates_across_pages_and_keeps_same_index_distinct_notes() {
        // Real ML-KEM payloads on a synthetic ledger: no VM/proof execution claim.
        let seed = [42; 32];
        let domain = Fr::from(7u64);
        let keys = PoolInstance::new(&seed, domain);
        let make = |secret| {
            let plain = Plaintext {
                slot: 0,
                kind: Kind::Ordinary,
                amount: 1000,
                note_secret: Fr::from(secret),
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
                Fr::from(1000u64),
                wire::output_data_hash(&payload),
            );
            (Event::Deposit { amount: 1000, owner_commitment: owner, output_data: payload }, body)
        };
        let (event, body) = make(123u64);
        let mut ledger = Ledger::genesis();
        for _ in 0..513 {
            ledger.apply(&event, 0).unwrap();
        }
        let (second, _) = make(124u64);
        ledger.apply(&second, 0).unwrap();
        let before = TosShieldedReplay {
            state: State::Ready(Box::new(ledger.clone())),
            domain,
            receive_binding: None,
        };
        let page_a: serde_json::Value =
            serde_json::from_slice(&before.scan(&seed, 0, 512).unwrap()).unwrap();
        let page_b: serde_json::Value =
            serde_json::from_slice(&before.scan(&seed, 512, 2).unwrap()).unwrap();
        assert_eq!(page_a["scan"]["batch_unspent_balance"], "1000");
        assert_eq!(page_b["scan"]["batch_unspent_balance"], "2000");
        let summary = summary_json(&before, &seed);
        assert_eq!(summary["unspent_balance"], "2000");
        assert_eq!(summary["owned_outputs"], "514");
        assert_eq!(summary["unique_unspent_notes"], "2");
        assert_eq!(summary["duplicate_outputs"], "512");
        assert_eq!(summary["reused_indices_count"], "1");
        assert_eq!(summary["scan_next_index"], "8");
        let summary_keys: std::collections::BTreeSet<_> =
            summary.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            summary_keys,
            [
                "version",
                "total_outputs",
                "owned_outputs",
                "unique_unspent_notes",
                "duplicate_outputs",
                "reused_indices_count",
                "diagnostics_count",
                "unspent_balance",
                "scan_next_index"
            ]
            .into_iter()
            .collect()
        );
        let nullifier = notes::nullifier(body, keys.owner_nf_key(7).unwrap());
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
        let after = TosShieldedReplay {
            state: State::Ready(Box::new(ledger)),
            domain,
            receive_binding: None,
        };
        let summary = summary_json(&after, &seed);
        assert_eq!(summary["unspent_balance"], "1000");
        assert_eq!(summary["unique_unspent_notes"], "1");
        assert_eq!(summary["scan_next_index"], "8");
    }
    #[test]
    fn summary_requires_ready_and_exact_seed_and_allows_authentic_empty_ledger() {
        let seed = [42; 32];
        let domain = Fr::from(7u64);
        let mut owner = TosShieldedReplay { state: State::Failed, domain, receive_binding: None };
        for (session, key, length) in [
            (&owner as *const _, seed.as_ptr(), 32),
            (ptr::null(), seed.as_ptr(), 32),
            (&owner as *const _, ptr::null(), 32),
            (&owner as *const _, seed.as_ptr(), 31),
        ] {
            let raw = unsafe { tos_shielded_replay_summary(session, key, length) };
            let response = unsafe { Box::from_raw(raw) };
            assert_eq!(response.status, 1);
            assert!(response.bytes.is_empty());
        }
        owner.state = State::Ready(Box::new(Ledger::genesis()));
        let summary = summary_json(&owner, &seed);
        assert_eq!(summary["unspent_balance"], "0");
        assert_eq!(summary["total_outputs"], "0");
    }
    #[cfg(unix)]
    #[test]
    fn receive_reserves_before_return_and_survives_replay_restart() {
        use std::os::unix::fs::DirBuilderExt;
        let root = std::env::temp_dir().join(format!("tos-receive-{}", rand::random::<u64>()));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let path = root.to_str().unwrap().as_bytes();
        let key = [42; 32];
        let mut binding = [1; 228];
        binding[..4].copy_from_slice(&3i32.to_be_bytes());
        let receive = |owner: &TosShieldedReplay, binding: &[u8]| unsafe {
            Box::from_raw(tos_shielded_replay_receive(
                owner,
                key.as_ptr(),
                key.len(),
                path.as_ptr(),
                path.len(),
                binding.as_ptr(),
                binding.len(),
            ))
        };
        let domain = wire::execution_domain(3, &[1; 32]);
        let failed =
            TosShieldedReplay { state: State::Failed, domain, receive_binding: Some(binding) };
        assert_eq!(receive(&failed, &binding).status, 1);
        let make_ready = || TosShieldedReplay {
            state: State::Ready(Box::new(Ledger::genesis())),
            domain,
            receive_binding: Some(binding),
        };
        let mut other_pool = binding;
        other_pool[4] = 2;
        assert_eq!(receive(&make_ready(), &other_pool).status, 1);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        for index in [0, 1] {
            let result = receive(&make_ready(), &binding);
            assert_eq!(result.status, 0);
            let descriptor =
                shielded_pool_wallet::descriptor::Descriptor::from_bytes(&result.bytes).unwrap();
            assert_eq!(descriptor.note_key_index, index);
        }
        let keys = PoolInstance::new(&key, domain);
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
        let commitment = notes::owner_commitment(
            plain.owner_nf_key_hash,
            plain.pq_auth_key_hash,
            plain.note_secret,
        );
        let mut ledger = Ledger::genesis();
        ledger
            .apply(
                &Event::Deposit {
                    amount: plain.amount,
                    owner_commitment: commitment,
                    output_data: payload,
                },
                0,
            )
            .unwrap();
        let observed = TosShieldedReplay {
            state: State::Ready(Box::new(ledger)),
            domain,
            receive_binding: Some(binding),
        };
        for (owner, expected) in [(&observed, 8), (&make_ready(), 9)] {
            let result = receive(owner, &binding);
            assert_eq!(result.status, 0);
            let descriptor =
                shielded_pool_wallet::descriptor::Descriptor::from_bytes(&result.bytes).unwrap();
            assert_eq!(descriptor.note_key_index, expected);
        }
        let mut wrong_genesis = binding;
        wrong_genesis[36] ^= 1;
        let refused = receive(&make_ready(), &wrong_genesis);
        assert_eq!(refused.status, 1);
        assert!(refused.bytes.is_empty());
        let mut upgraded = binding;
        upgraded[100] = 2;
        let refused = receive(&make_ready(), &upgraded);
        assert_eq!(refused.status, 1);
        assert!(refused.bytes.is_empty());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    }
}
