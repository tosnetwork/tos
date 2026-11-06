/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! What a Native Registry authorization would cost with ML-DSA-44 controllers,
//! measured before any registry contract is designed around them.
//!
//! The registry authorizes an action by walking its stored policy and the
//! submitted signatures in lockstep; a registration additionally needs a
//! possession signature from every controller of the installed policy and must
//! validate the policy it installs. The probe performs exactly that work with
//! ML-DSA-44: for N controllers it verifies N signatures over one 32-byte action
//! hash under a fixed context, against N stored 1312-byte keys, in one internal
//! message, so the per-transaction signature counter (the first ten checks free,
//! then 4,000 gas each) and the cell-load pricing apply as they would on chain.
//! The `hash_keys` variant also derives every key id from its key bytes, which a
//! registration must do to validate the policy it installs.
//!
//! The numbers are a lower bound for a real registry path: the real contract
//! adds its own parsing, state writes and outgoing messages.

use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit, TrComputePhase,
    TransactionDescr,
};
use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 16;
const CONTEXT: &[u8] = b"TOS-NATIVE-REGISTRY-PQ-PROBE";
const CHUNK_BYTES: usize = 127;

const PROBE: &str = r#"
;; data: n:uint8 ^policy
;; policy entry: key_id:uint256 weight:uint32 ^key [^next]
;; body: op:uint32 hash_keys:uint8 ^message ^signatures
;; signature entry: key_id:uint256 ^signature [^next]
() recv_internal(int msg_value, cell in_msg_full, slice in_msg) impure {
  slice full = in_msg_full.begin_parse();
  if (full~load_uint(4) & 1) { return (); }
  if (in_msg.slice_bits() < 40) { return (); }
  in_msg~load_uint(32);
  int hash_keys = in_msg~load_uint(8);
  cell message = in_msg~load_ref();
  cell signatures = in_msg~load_ref();
  in_msg.end_parse();
  slice ds = get_data().begin_parse();
  int n = ds~load_uint(8);
  cell policy = ds~load_ref();
  cell context = begin_cell().store_slice("TOS-NATIVE-REGISTRY-PQ-PROBE").end_cell();
  slice p = policy.begin_parse();
  slice s = signatures.begin_parse();
  int i = 0;
  int total = 0;
  while (i < n) {
    int key_id = p~load_uint(256);
    int weight = p~load_uint(32);
    cell key = p~load_ref();
    int signed_id = s~load_uint(256);
    cell signature = s~load_ref();
    throw_unless(50, signed_id == key_id);
    if (hash_keys) {
      throw_unless(51, key.snake_string_hash() == key_id);
    }
    throw_unless(52, pq_check_mldsa44(message, context, signature, key));
    total += weight;
    i += 1;
    if (i < n) {
      p = p~load_ref().begin_parse();
      s = s~load_ref().begin_parse();
    }
  }
  throw_unless(53, total == n);
}
"#;

fn byte_chain(bytes: &[u8]) -> Cell {
    let mut next: Option<Cell> = None;
    for chunk in bytes.chunks(CHUNK_BYTES).collect::<Vec<_>>().iter().rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(chunk, chunk.len() * 8).expect("chunk");
        if let Some(reference) = next.take() {
            builder.checked_append_reference(reference).expect("link");
        }
        next = Some(builder.into_cell().expect("cell"));
    }
    next.expect("a non-empty chain")
}

fn key_id(public: &[u8]) -> [u8; 32] {
    chain_block::sha256_digest(public)
}

struct Controller {
    public: Vec<u8>,
    secret: ml_dsa_44::PrivateKey,
}

fn controllers(n: usize) -> Vec<Controller> {
    (0..n)
        .map(|_| {
            let (public, secret) = ml_dsa_44::try_keygen().expect("keygen");
            Controller { public: public.into_bytes().to_vec(), secret }
        })
        .collect()
}

fn linked(entries: Vec<BuilderData>) -> Cell {
    let mut next: Option<Cell> = None;
    for mut entry in entries.into_iter().rev() {
        if let Some(link) = next.take() {
            entry.checked_append_reference(link).expect("link");
        }
        next = Some(entry.into_cell().expect("entry"));
    }
    next.expect("at least one entry")
}

fn policy(set: &[Controller]) -> Cell {
    linked(
        set.iter()
            .map(|c| {
                let mut b = BuilderData::new();
                b.append_raw(&key_id(&c.public), 256).expect("id");
                b.append_u32(1).expect("weight");
                b.checked_append_reference(byte_chain(&c.public)).expect("key");
                b
            })
            .collect(),
    )
}

fn signatures(set: &[Controller], message: &[u8]) -> Cell {
    linked(
        set.iter()
            .map(|c| {
                let signature = c.secret.try_sign(message, CONTEXT).expect("sign");
                let mut b = BuilderData::new();
                b.append_raw(&key_id(&c.public), 256).expect("id");
                b.checked_append_reference(byte_chain(&signature)).expect("signature");
                b
            })
            .collect(),
    )
}

#[derive(Debug)]
struct Measured {
    controllers: usize,
    hash_keys: bool,
    gas_used: u64,
    gas_limit: u64,
    exit: i32,
    aborted: bool,
    body_cells: usize,
    body_bytes: usize,
    /// The exact inputs, so another executor can run the same transaction.
    code_boc: String,
    data_boc: String,
    body_boc: String,
    address: String,
}

fn b64(cell: &Cell) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(chain_block::write_boc(cell).expect("boc"))
}

fn count_cells(cell: &Cell, seen: &mut std::collections::HashSet<Vec<u8>>) -> (usize, usize) {
    if !seen.insert(cell.repr_hash().as_slice().to_vec()) {
        return (0, 0);
    }
    let mut cells = 1;
    let mut bytes = cell.bit_length().div_ceil(8);
    for i in 0..cell.references_count() {
        let (c, b) = count_cells(&cell.reference(i).expect("reference"), seen);
        cells += c;
        bytes += b;
    }
    (cells, bytes)
}

fn measure(code: &Cell, n: usize, hash_keys: bool) -> Measured {
    let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
        .expect("v16 chain with basechain 0");
    bc.set_workchain(0);
    let payer = bc.treasury("pq-registry-gas-payer", 1_000 * TOS).expect("payer");
    let set = controllers(n);
    let mut data = BuilderData::new();
    data.append_u8(u8::try_from(n).expect("n")).expect("n");
    data.checked_append_reference(policy(&set)).expect("policy");
    let data = data.into_cell().expect("data");
    let data_boc = b64(&data);
    let init = StateInit::with_code_and_data(code.clone(), data);
    let address = MsgAddressInt::with_params(
        0,
        init.write_to_new_cell().expect("init").into_cell().expect("init").repr_hash(),
    )
    .expect("address");
    bc.send_message(
        MessageBuilder::internal(payer.address(), &address, 10 * TOS)
            .bounce(false)
            .state_init(init)
            .body(Cell::default())
            .build(),
    )
    .expect("deploy")
    .expect_success();

    let action_hash = chain_block::sha256_digest(format!("action-{n}").as_bytes());
    let mut body = BuilderData::new();
    body.append_u32(0x5051_5052).expect("op");
    body.append_u8(u8::from(hash_keys)).expect("mode");
    body.checked_append_reference(byte_chain(&action_hash)).expect("message");
    body.checked_append_reference(signatures(&set, &action_hash)).expect("signatures");
    let body = body.into_cell().expect("body");
    let (body_cells, body_bytes) = count_cells(&body, &mut Default::default());
    let body_boc = b64(&body);

    let result = bc
        .send_message(MessageBuilder::internal(payer.address(), &address, 10 * TOS).body(body).build())
        .expect("submit");
    let transaction = result.transactions_for(&address).into_iter().last().expect("transaction");
    let TransactionDescr::Ordinary(description) =
        transaction.read_description().expect("description")
    else {
        panic!("ordinary transaction expected")
    };
    let TrComputePhase::Vm(vm) = description.compute_ph else {
        panic!("compute phase skipped")
    };
    Measured {
        controllers: n,
        hash_keys,
        gas_used: vm.gas_used.as_u64(),
        gas_limit: vm.gas_limit.as_u64(),
        exit: vm.exit_code,
        aborted: description.aborted,
        body_cells,
        body_bytes,
        code_boc: b64(code),
        data_boc,
        body_boc,
        address: address.to_string(),
    }
}

/// Prints one row per controller count. Set PQ_REGISTRY_GAS_OUT=<path> to write
/// the rows as JSON.
#[test]
fn registry_shaped_mldsa44_authorization_gas() {
    let dir = tempfile::tempdir().expect("probe dir");
    let path = dir.path().join("pq_registry_gas_probe.fc");
    let pq = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont/pq.fc");
    std::fs::write(&path, PROBE).expect("probe source");
    let code = compile_func_with_stdlib(&[std::path::PathBuf::from(pq), path])
        .expect("the probe compiles with PQ.fif");
    let mut rows = Vec::new();
    for n in [1usize, 2, 5, 10, 11, 12, 16, 20] {
        for hash_keys in [false, true] {
            let m = measure(&code, n, hash_keys);
            println!(
                "controllers={:>2} hash_keys={:<5} gas_used={:>8} gas_limit={:>8} exit={} aborted={} body_cells={} body_bytes={}",
                m.controllers, m.hash_keys, m.gas_used, m.gas_limit, m.exit, m.aborted, m.body_cells, m.body_bytes
            );
            rows.push(serde_json::json!({
                "controllers": m.controllers,
                "hash_keys": m.hash_keys,
                "gas_used": m.gas_used,
                "gas_limit": m.gas_limit,
                "exit_code": m.exit,
                "aborted": m.aborted,
                "body_cells": m.body_cells,
                "body_bytes": m.body_bytes,
                "code_boc": m.code_boc,
                "data_boc": m.data_boc,
                "body_boc": m.body_boc,
                "address": m.address,
            }));
            if m.gas_used < m.gas_limit {
                assert!(!m.aborted && m.exit == 0, "a valid authorization failed: {m:?}");
            }
        }
    }
    if let Ok(out) = std::env::var("PQ_REGISTRY_GAS_OUT") {
        std::fs::write(out, serde_json::to_string_pretty(&rows).expect("json")).expect("write");
    }
}
