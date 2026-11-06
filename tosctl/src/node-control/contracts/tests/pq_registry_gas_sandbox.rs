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

// ---------------------------------------------------------------------------
// Lifecycle paths with the real key codec, and their serialized message sizes.
//
// The first probe hashed raw chains; a registry validates stored keys through
// pq::stored_key and derives ids with pq::key_id, and walks some policies more
// than once. This probe does exactly that work per path, and builds each path's
// whole message to measure its serialized BOC size.

const LIFECYCLE_PROBE: &str = r#"
;; body: op:uint32 ^message ^pairs ^keys
;; pair:  ^stored_key ^stored_signature [^next]   -- one verification each
;; key:   walks:uint8 ^stored_key [^next]          -- pq::key_id `walks` times each
() recv_internal(int msg_value, cell in_msg_full, slice in_msg) impure {
  slice full = in_msg_full.begin_parse();
  if (full~load_uint(4) & 1) { return (); }
  if (in_msg.slice_bits() < 32) { return (); }
  in_msg~load_uint(32);
  ;; optimized: the native instruction checks operand lengths and canonical chains, so
  ;; keys and signatures are read without the FunC chain walk, and a key id is one
  ;; SHA256C over the domain, the suite and the chain.
  int optimized = in_msg~load_uint(8);
  cell message = in_msg~load_ref();
  cell pairs = in_msg~load_ref();
  cell keys = in_msg~load_ref();
  in_msg.end_parse();
  cell context = begin_cell().store_slice("TOS-NATIVE-REGISTRY-v2").end_cell();
  slice p = pairs.begin_parse();
  int more = -1;
  while (more) {
    cell key = null();
    cell signature = null();
    if (optimized) {
      slice ks = p~load_ref().begin_parse(); ks~skip_bits(32); key = ks~load_ref();
      slice ss = p~load_ref().begin_parse(); ss~skip_bits(32); signature = ss~load_ref();
    } else {
      (_, key) = pq::stored_key(1, p~load_ref());
      signature = pq::stored_signature(1, p~load_ref());
    }
    throw_unless(52, pq_check_mldsa44(message, context, signature, key));
    if (p.slice_refs() > 0) { p = p~load_ref().begin_parse(); } else { more = 0; }
  }
  slice k = keys.begin_parse();
  int acc = 0;
  more = -1;
  while (more) {
    int walks = k~load_uint(8);
    cell stored = k~load_ref();
    if (optimized) {
      slice cs = stored.begin_parse(); cs~skip_bits(32); cell chain = cs~load_ref();
      repeat (walks) {
        acc ^= begin_cell().store_slice("TOS-PQ-CONSENSUS-KEY-v1").store_uint(256, 16)
          .store_ref(chain).end_cell().snake_string_hash();
      }
    } else {
      repeat (walks) { acc ^= pq::key_id(1, stored); }
    }
    if (k.slice_refs() > 0) { k = k~load_ref().begin_parse(); } else { more = 0; }
  }
  throw_if(53, acc == -1);
}
"#;

fn stored(bytes: &[u8]) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(u32::try_from(bytes.len()).expect("length")).expect("length");
    b.checked_append_reference(byte_chain(bytes)).expect("chain");
    b.into_cell().expect("stored")
}

struct Pq {
    stored_key: Cell,
    key_id: [u8; 32],
    secret: ml_dsa_44::PrivateKey,
}

fn pq_set(n: usize) -> Vec<Pq> {
    (0..n)
        .map(|_| {
            let (public, secret) = ml_dsa_44::try_keygen().expect("keygen");
            let bytes = public.into_bytes();
            let mut preimage = b"TOS-PQ-CONSENSUS-KEY-v1".to_vec();
            preimage.extend_from_slice(&[1, 0]);
            preimage.extend_from_slice(&bytes);
            Pq { stored_key: stored(&bytes), key_id: chain_block::sha256_digest(&preimage), secret }
        })
        .collect()
}

fn pq_sign(c: &Pq, message: &[u8]) -> Cell {
    stored(&c.secret.try_sign(message, b"TOS-NATIVE-REGISTRY-v2").expect("sign"))
}

/// V2 policy: header, then controllers key_id weight purposes recovery ^stored_key [^next].
fn v2_policy(set: &[Pq]) -> Cell {
    let entries = set
        .iter()
        .map(|c| {
            let mut b = BuilderData::new();
            b.append_raw(&c.key_id, 256).expect("id");
            b.append_u32(1).expect("weight");
            b.append_u16(15).expect("purposes");
            b.append_bit_one().expect("recovery");
            b.checked_append_reference(c.stored_key.clone()).expect("key");
            b
        })
        .collect();
    let mut root = BuilderData::new();
    root.append_u32(0x4e56_5031).expect("magic");
    root.append_u16(2).expect("schema");
    root.append_u32(u32::try_from(set.len()).expect("n")).expect("threshold");
    root.append_u32(1).expect("recovery threshold");
    root.append_u64(86_400).expect("timelock");
    root.append_u8(u8::try_from(set.len()).expect("n")).expect("count");
    root.checked_append_reference(linked(entries)).expect("controllers");
    root.into_cell().expect("policy")
}

/// V2 signature set: count:uint8 ^entry, entry = key_id ^stored_signature [^next].
fn v2_signatures(set: &[Pq], message: &[u8]) -> Cell {
    let mut root = BuilderData::new();
    root.append_u8(u8::try_from(set.len()).expect("n")).expect("count");
    if !set.is_empty() {
        let entries = set
            .iter()
            .map(|c| {
                let mut b = BuilderData::new();
                b.append_raw(&c.key_id, 256).expect("id");
                b.checked_append_reference(pq_sign(c, message)).expect("signature");
                b
            })
            .collect();
        root.checked_append_reference(linked(entries)).expect("entries");
    }
    root.into_cell().expect("signature set")
}

/// One registry submission as a wallet would carry it: the action (with its payload),
/// both signature sets, optionally a StateInit with the release code, inside an internal
/// message, inside a wallet external message signed with ML-DSA-44.
fn wallet_external(action_payload: Cell, authority: Cell, counterparty: Cell, with_code: bool) -> Cell {
    let mut action = BuilderData::new();
    action.append_u32(0x4e56_4131).expect("magic");
    action.append_u16(2).expect("schema");
    action.append_raw(&[0x5a; 2 + 16 + 96], (2 + 16 + 96) * 8).expect("header fields");
    let mut domain = BuilderData::new();
    domain.append_raw(&[0x11; 96], 96 * 8).expect("domain");
    let mut code_hash = BuilderData::new();
    code_hash.append_raw(&[0x44; 32], 256).expect("code hash");
    domain.checked_append_reference(code_hash.into_cell().expect("cell")).expect("ref");
    action.checked_append_reference(domain.into_cell().expect("domain")).expect("ref");
    action.checked_append_reference(action_payload).expect("payload");
    let mut body = BuilderData::new();
    body.append_u32(0x4e56_0001).expect("op");
    body.append_u64(1).expect("query");
    body.checked_append_reference(action.into_cell().expect("action")).expect("action");
    body.checked_append_reference(authority).expect("authority");
    body.checked_append_reference(counterparty).expect("counterparty");
    let body = body.into_cell().expect("body");

    let wallet = pq_set(1);
    let destination =
        MsgAddressInt::with_params(0, chain_block::UInt256::from([0x33; 32])).expect("destination");
    let mut builder = MessageBuilder::internal(&destination, &destination, TOS).bounce(!with_code).body(body);
    if with_code {
        // The current registry release stands in for the size of a V2 code cell tree.
        let encoded: String = include_str!(
            "../../../../../crypto/smartcont/tos-service-native-registry-v1.boc.base64"
        )
        .split_whitespace()
        .collect();
        let code = chain_block::read_single_root_boc(
            chain_block::base64_decode(&encoded).expect("base64"),
        )
        .expect("release code");
        builder = builder.state_init(StateInit::with_code_and_data(code, Cell::default()));
    }
    let internal = builder.build().serialize().expect("internal message");
    let mut signed = BuilderData::new();
    signed.append_u32(0x2a).expect("subwallet");
    signed.append_u32(1_800_000_000).expect("valid until");
    signed.append_u32(7).expect("seqno");
    signed.append_u8(3).expect("mode");
    signed.checked_append_reference(internal).expect("message");
    let signed = signed.into_cell().expect("signed");
    let mut external = BuilderData::new();
    external.append_raw(&[0x88; 80], 80 * 8).expect("ext_in header and destination");
    external.checked_append_reference(pq_sign(&wallet[0], signed.repr_hash().as_slice())).expect("sig");
    external.checked_append_reference(signed).expect("signed");
    external.into_cell().expect("external")
}

fn boc_len(cell: &Cell) -> usize {
    chain_block::write_boc(cell).expect("boc").len()
}

#[derive(Clone, Copy)]
enum Path {
    Registration,
    PolicyUpdate,
    RecoveryInitiation,
    TransferLeg,
}

/// (pairs to verify, key walks, serialized external message bytes) for one path at width n.
fn lifecycle_case(path: Path, n: usize, optimized: bool) -> (Cell, usize) {
    let old = pq_set(n);
    let new = pq_set(n);
    let message = chain_block::sha256_digest(format!("lifecycle-{n}").as_bytes());
    let none = v2_signatures(&[], &message);
    let mut pairs = Vec::new();
    let mut keys = Vec::new();
    let pair = |c: &Pq, pairs: &mut Vec<BuilderData>| {
        let mut b = BuilderData::new();
        b.checked_append_reference(c.stored_key.clone()).expect("key");
        b.checked_append_reference(pq_sign(c, &message)).expect("signature");
        pairs.push(b);
    };
    let key = |c: &Pq, walks: u8, keys: &mut Vec<BuilderData>| {
        let mut b = BuilderData::new();
        b.append_u8(walks).expect("walks");
        b.checked_append_reference(c.stored_key.clone()).expect("key");
        keys.push(b);
    };
    let size = match path {
        Path::Registration => {
            // Possession by every new controller; the installed policy validated once.
            new.iter().for_each(|c| pair(c, &mut pairs));
            new.iter().for_each(|c| key(c, 1, &mut keys));
            let mut payload = BuilderData::new();
            payload.append_raw(&[0x6f; 32], 256).expect("object nonce");
            payload.checked_append_reference(v2_policy(&new)).expect("policy");
            boc_len(&wallet_external(
                payload.into_cell().expect("payload"),
                v2_signatures(&new, &message),
                none,
                true,
            ))
        }
        Path::PolicyUpdate | Path::RecoveryInitiation => {
            // Old controllers authorize, every new controller proves possession; the
            // stored policy and the installed one are validated (twice each for
            // recovery initiation, as the current contract does).
            // Optimized: stored ids are trusted after installation, so only the
            // installed policy is derived, once.
            let (old_walks, new_walks) = if optimized {
                (0, 1)
            } else if matches!(path, Path::RecoveryInitiation) {
                (2, 2)
            } else {
                (1, 2)
            };
            old.iter().for_each(|c| pair(c, &mut pairs));
            new.iter().for_each(|c| pair(c, &mut pairs));
            old.iter().for_each(|c| key(c, old_walks, &mut keys));
            new.iter().for_each(|c| key(c, new_walks, &mut keys));
            let mut payload = BuilderData::new();
            if matches!(path, Path::RecoveryInitiation) {
                payload.append_u64(1_800_000_000).expect("execute after");
            }
            payload.checked_append_reference(v2_policy(&new)).expect("policy");
            boc_len(&wallet_external(
                payload.into_cell().expect("payload"),
                v2_signatures(&old, &message),
                v2_signatures(&new, &message),
                false,
            ))
        }
        Path::TransferLeg => {
            // One Agent's transaction: its own threshold signatures, its policy once. The
            // submitted message carries both owners' signature sets.
            old.iter().for_each(|c| pair(c, &mut pairs));
            old.iter().for_each(|c| key(c, u8::from(!optimized), &mut keys));
            let mut payload = BuilderData::new();
            payload.append_raw(&[0x4a; 64], 512).expect("owners");
            boc_len(&wallet_external(
                payload.into_cell().expect("payload"),
                v2_signatures(&old, &message),
                v2_signatures(&new, &message),
                false,
            ))
        }
    };
    let mut body = BuilderData::new();
    body.append_u32(0x5051_5053).expect("op");
    body.append_u8(u8::from(optimized)).expect("mode");
    body.checked_append_reference(byte_chain(&message)).expect("message");
    body.checked_append_reference(linked(pairs)).expect("pairs");
    body.checked_append_reference(linked(keys)).expect("keys");
    (body.into_cell().expect("body"), size)
}

/// Prints gas and serialized size per path and width. PQ_REGISTRY_LIFECYCLE_OUT=<path>
/// writes JSON (including the probe inputs for the C++ emulator).
#[test]
fn registry_lifecycle_paths_with_the_real_key_codec() {
    let dir = tempfile::tempdir().expect("probe dir");
    let path = dir.path().join("pq_registry_lifecycle_probe.fc");
    let smartcont = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont");
    std::fs::write(&path, LIFECYCLE_PROBE).expect("probe source");
    let code = compile_func_with_stdlib(&[
        std::path::PathBuf::from(format!("{smartcont}/pq.fc")),
        std::path::PathBuf::from(format!("{smartcont}/pq-bytes.fc")),
        path,
    ])
    .expect("the lifecycle probe compiles with pq-bytes.fc");
    let mut rows = Vec::new();
    for (n, optimized) in [4usize, 6, 8, 10, 12, 16].into_iter().flat_map(|n| [(n, false), (n, true)]) {
        for (name, p) in [
            ("registration", Path::Registration),
            ("policy-update", Path::PolicyUpdate),
            ("recovery-initiation", Path::RecoveryInitiation),
            ("transfer-leg", Path::TransferLeg),
        ] {
            let (body, external_bytes) = lifecycle_case(p, n, optimized);
            let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
                .expect("chain");
            bc.set_workchain(0);
            let payer = bc.treasury("lifecycle-payer", 1_000 * TOS).expect("payer");
            let init = StateInit::with_code_and_data(code.clone(), Cell::default());
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
            let result = bc
                .send_message(
                    MessageBuilder::internal(payer.address(), &address, 10 * TOS).body(body.clone()).build(),
                )
                .expect("submit");
            let transaction = result.transactions_for(&address).into_iter().last().expect("tx");
            let TransactionDescr::Ordinary(description) =
                transaction.read_description().expect("description")
            else {
                panic!("ordinary")
            };
            let TrComputePhase::Vm(vm) = description.compute_ph else { panic!("compute") };
            println!(
                "{name:<20} n={n:>2} optimized={optimized:<5} gas={:>8} exit={} external_bytes={external_bytes:>6} fits_65535={}",
                vm.gas_used.as_u64(),
                vm.exit_code,
                external_bytes <= 65_535
            );
            rows.push(serde_json::json!({
                "path": name, "controllers": n, "optimized": optimized, "gas_used": vm.gas_used.as_u64(),
                "exit_code": vm.exit_code, "aborted": description.aborted,
                "external_bytes": external_bytes, "fits_max_ext_msg_size": external_bytes <= 65_535,
                "code_boc": b64(&code), "data_boc": b64(&Cell::default()), "body_boc": b64(&body),
                "address": address.to_string(),
            }));
        }
    }
    if let Ok(out) = std::env::var("PQ_REGISTRY_LIFECYCLE_OUT") {
        std::fs::write(out, serde_json::to_string_pretty(&rows).expect("json")).expect("write");
    }
}
