/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! What a Service Actor attestation would cost with an ML-DSA-44 attestor,
//! measured before the contract is designed around it.
//!
//! The Service Actor snapshots the attestor key into every pending request at
//! `call` and checks the attestor's signature over a response domain hash at
//! `respond`. The probe keeps the same shape -- a `HashmapE 64` of pending
//! requests, each snapshotting the attestor key material in force at `call` --
//! in three variants:
//!
//! * `ed25519`: today's contract, a 256-bit key inline, `CHKSIGNU` over the
//!   domain hash.
//! * `stored-key`: the 1,312-byte ML-DSA-44 key as a stored cell
//!   (`len:uint32 ^chain`) snapshotted by reference; `respond` carries the
//!   stored signature.
//! * `key-id`: only the 32-byte key id snapshotted; `respond` carries the
//!   stored key and the stored signature, and the probe derives the key id
//!   from the key `PQCHECKSIG_MLDSA44` accepted.
//!
//! For each it measures `call` and `respond` gas, the `respond` body size, and
//! the account's storage with 1, 10 and 50 pending requests, before and after a
//! key rotation. The real contract adds its own accounting and messages on top
//! of the probe's work, identically in every variant.

use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit, TrComputePhase,
    TransactionDescr,
};
use ed25519_dalek::Signer as _;
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer as _};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 16;
const CONTEXT: &[u8] = b"TOS-SERVICE-ACTOR-RESPOND";
const CHUNK_BYTES: usize = 127;

const PROBE: &str = r#"
;; data: mode:uint8 next_id:uint64 ^key_material pending:(HashmapE 64 ^entry)
;;   mode 0 ed25519:     key_material = [pubkey:uint256]
;;   mode 1 stored-key:  key_material = [^stored_key]
;;   mode 2 key-id:      key_material = [key_id:uint256]
;; entry: request_hash:uint256 terms_hash:uint256 has_attestor:uint1 + snapshot
;;   mode 0: pubkey:uint256   mode 1: ^stored_key   mode 2: key_id:uint256
;; call    op=1: request_hash:uint256
;; respond op=2: request_id:uint64 response_hash:uint256 + proof
;;   mode 0: signature:bits512   mode 1: ^stored_signature
;;   mode 2: ^stored_key ^stored_signature
;; rotate  op=3: ^key_material

cell stored_chain(cell stored, int expected) inline {
  slice s = stored.pq::parse_ordinary();
  throw_unless(60, s~load_uint(32) == expected);
  cell chain = s~load_ref();
  s.end_parse();
  return chain;
}

int verified_key_id(cell chain) inline {
  return begin_cell().store_slice("TOS-PQ-CONSENSUS-KEY-v1")
    .store_uint(0x0100, 16).store_ref(chain).end_cell().snake_string_hash();
}

() save(int mode, int next_id, cell key_material, cell pending) impure inline {
  set_data(begin_cell().store_uint(mode, 8).store_uint(next_id, 64)
    .store_ref(key_material).store_dict(pending).end_cell());
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg) impure {
  slice full = in_msg_full.begin_parse();
  if (full~load_uint(4) & 1) { return (); }
  if (in_msg.slice_bits() < 32) { return (); }
  int op = in_msg~load_uint(32);
  slice ds = get_data().begin_parse();
  int mode = ds~load_uint(8);
  int next_id = ds~load_uint(64);
  cell key_material = ds~load_ref();
  cell pending = ds~load_dict();
  ds.end_parse();

  if (op == 1) {
    int request_hash = in_msg~load_uint(256);
    in_msg.end_parse();
    slice km = key_material.begin_parse();
    builder entry = begin_cell().store_uint(request_hash, 256).store_uint(0, 256)
      .store_uint(1, 1);
    if (mode == 1) {
      entry = entry.store_ref(km~load_ref());
    } else {
      entry = entry.store_uint(km~load_uint(256), 256);
    }
    pending~udict_set_ref(64, next_id, entry.end_cell());
    save(mode, next_id + 1, key_material, pending);
    return ();
  }

  if (op == 2) {
    int request_id = in_msg~load_uint(64);
    int response_hash = in_msg~load_uint(256);
    (cell entry_cell, int found) = pending.udict_get_ref?(64, request_id);
    throw_unless(61, found);
    slice entry = entry_cell.begin_parse();
    int request_hash = entry~load_uint(256);
    entry~load_uint(256);
    throw_unless(62, entry~load_uint(1));
    int domain_hash = begin_cell().store_uint(0x53525032, 32).store_uint(request_id, 64)
      .store_uint(request_hash, 256).store_uint(response_hash, 256).end_cell().cell_hash();
    if (mode == 0) {
      int pubkey = entry~load_uint(256);
      slice signature = in_msg~load_bits(512);
      in_msg.end_parse();
      throw_unless(63, check_signature(domain_hash, signature, pubkey));
    } else {
      cell message = begin_cell().store_uint(domain_hash, 256).end_cell();
      cell context = begin_cell().store_slice("TOS-SERVICE-ACTOR-RESPOND").end_cell();
      cell key = null();
      if (mode == 1) {
        key = stored_chain(entry~load_ref(), 1312);
      } else {
        int key_id = entry~load_uint(256);
        key = stored_chain(in_msg~load_ref(), 1312);
        cell signature = stored_chain(in_msg~load_ref(), 2420);
        in_msg.end_parse();
        throw_unless(64, pq_check_mldsa44(message, context, signature, key));
        throw_unless(65, verified_key_id(key) == key_id);
        (pending, _) = pending.udict_delete?(64, request_id);
        save(mode, next_id, key_material, pending);
        return ();
      }
      cell signature = stored_chain(in_msg~load_ref(), 2420);
      in_msg.end_parse();
      throw_unless(64, pq_check_mldsa44(message, context, signature, key));
    }
    (pending, _) = pending.udict_delete?(64, request_id);
    save(mode, next_id, key_material, pending);
    return ();
  }

  if (op == 3) {
    cell next = in_msg~load_ref();
    in_msg.end_parse();
    save(mode, next_id, next, pending);
    return ();
  }
  throw(0xffff);
}
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    Ed25519,
    StoredKey,
    KeyId,
}

impl Variant {
    fn mode(self) -> u8 {
        match self {
            Self::Ed25519 => 0,
            Self::StoredKey => 1,
            Self::KeyId => 2,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::StoredKey => "stored-key",
            Self::KeyId => "key-id",
        }
    }
}

fn byte_chain(bytes: &[u8]) -> Cell {
    let mut next: Option<Cell> = None;
    for chunk in bytes.chunks(CHUNK_BYTES).rev() {
        let mut b = BuilderData::new();
        b.append_raw(chunk, chunk.len() * 8).expect("chunk");
        if let Some(link) = next.take() {
            b.checked_append_reference(link).expect("link");
        }
        next = Some(b.into_cell().expect("cell"));
    }
    next.expect("non-empty")
}

fn stored(bytes: &[u8]) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(u32::try_from(bytes.len()).expect("length")).expect("length");
    b.checked_append_reference(byte_chain(bytes)).expect("chain");
    b.into_cell().expect("stored")
}

fn key_id(public: &[u8]) -> [u8; 32] {
    let mut preimage = b"TOS-PQ-CONSENSUS-KEY-v1".to_vec();
    preimage.extend_from_slice(&[1, 0]);
    preimage.extend_from_slice(public);
    chain_block::sha256_digest(&preimage)
}

/// One attestor of either suite, from a fixed seed.
struct Attestor {
    ed: ed25519_dalek::SigningKey,
    pq_public: Vec<u8>,
    pq_secret: ml_dsa_44::PrivateKey,
}

impl Attestor {
    fn new(seed: u8) -> Self {
        let (public, secret) = ml_dsa_44::KG::keygen_from_seed(&[seed; 32]);
        Self {
            ed: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            pq_public: public.into_bytes().to_vec(),
            pq_secret: secret,
        }
    }

    fn key_material(&self, variant: Variant) -> Cell {
        let mut b = BuilderData::new();
        match variant {
            Variant::Ed25519 => {
                b.append_raw(&self.ed.verifying_key().to_bytes(), 256).expect("key");
            }
            Variant::StoredKey => {
                b.checked_append_reference(stored(&self.pq_public)).expect("key");
            }
            Variant::KeyId => {
                b.append_raw(&key_id(&self.pq_public), 256).expect("key id");
            }
        }
        b.into_cell().expect("key material")
    }

    fn proof(&self, variant: Variant, domain_hash: &[u8; 32], body: &mut BuilderData) {
        match variant {
            Variant::Ed25519 => {
                body.append_raw(&self.ed.sign(domain_hash).to_bytes(), 512).expect("signature");
            }
            Variant::StoredKey | Variant::KeyId => {
                let signature = self
                    .pq_secret
                    .try_sign_with_seed(&[0; 32], domain_hash, CONTEXT)
                    .expect("ML-DSA-44 signing");
                if variant == Variant::KeyId {
                    body.checked_append_reference(stored(&self.pq_public)).expect("key");
                }
                body.checked_append_reference(stored(&signature)).expect("signature");
            }
        }
    }
}

fn domain_hash(request_id: u64, request_hash: &[u8; 32], response_hash: &[u8; 32]) -> [u8; 32] {
    let mut b = BuilderData::new();
    b.append_u32(0x5352_5032).expect("tag");
    b.append_u64(request_id).expect("id");
    b.append_raw(request_hash, 256).expect("request");
    b.append_raw(response_hash, 256).expect("response");
    *b.into_cell().expect("domain").repr_hash().as_array()
}

struct Probe {
    bc: Blockchain,
    payer: tos_sandbox::Treasury,
    address: MsgAddressInt,
}

#[derive(Clone, Copy, Debug)]
struct Gas {
    used: u64,
    exit: i32,
    aborted: bool,
}

impl Probe {
    fn deploy(code: &Cell, variant: Variant, attestor: &Attestor) -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
            .expect("v16 chain with basechain 0");
        bc.set_workchain(0);
        let payer = bc.treasury("pq-service-actor-gas-payer", 10_000 * TOS).expect("payer");
        let mut data = BuilderData::new();
        data.append_u8(variant.mode()).expect("mode");
        data.append_u64(0).expect("next id");
        data.checked_append_reference(attestor.key_material(variant)).expect("key material");
        data.append_bit_zero().expect("empty pending");
        let init = StateInit::with_code_and_data(code.clone(), data.into_cell().expect("data"));
        let address = MsgAddressInt::with_params(
            0,
            init.write_to_new_cell().expect("init").into_cell().expect("init").repr_hash(),
        )
        .expect("address");
        bc.send_message(
            MessageBuilder::internal(payer.address(), &address, 100 * TOS)
                .bounce(false)
                .state_init(init)
                .body(Cell::default())
                .build(),
        )
        .expect("deploy")
        .expect_success();
        Self { bc, payer, address }
    }

    fn send(&mut self, body: Cell) -> Gas {
        use chain_block::{HashmapType, ShardAccount, UInt256, base64_encode, write_boc};
        let message =
            MessageBuilder::internal(self.payer.address(), &self.address, TOS).body(body).build();
        // With PQ_SERVICE_ACTOR_TRACE_DIR set, every transaction is recorded in
        // the format scripts/replay-token-bridge-trace.py replays through the
        // native (C++) transaction engine.
        let boc = |cell: Cell| base64_encode(write_boc(&cell).expect("boc"));
        let trace = std::env::var_os("PQ_SERVICE_ACTOR_TRACE_DIR").map(|dir| {
            let before = ShardAccount::with_params(
                self.bc.get_account(&self.address).expect("account"),
                UInt256::default(),
                0,
            )
            .expect("shard account");
            (
                dir,
                boc(HashmapType::data(&self.bc.config_params().config_params)
                    .expect("config")
                    .clone()),
                boc(before.serialize().expect("before")),
                boc(message.serialize().expect("message")),
            )
        });
        let result = self.bc.send_message(message).expect("send");
        if let Some((dir, config, before, message)) = trace {
            let transaction =
                result.transactions_for(&self.address).into_iter().last().expect("transaction");
            let after = ShardAccount::with_params(
                self.bc.get_account(&self.address).expect("account"),
                UInt256::default(),
                0,
            )
            .expect("shard account");
            let record = serde_json::json!({"unixtime": transaction.now(),
                "lt": transaction.logical_time().to_string(), "config": config,
                "shard_account": before, "message": message,
                "rust_transaction": boc(transaction.serialize().expect("transaction")),
                "shard_account_after": boc(after.serialize().expect("after"))});
            let dir = std::path::PathBuf::from(dir);
            std::fs::create_dir_all(&dir).expect("trace dir");
            static RECORD: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let index = RECORD.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::fs::write(
                dir.join(format!("{index:05}.json")),
                serde_json::to_string(&record).expect("json"),
            )
            .expect("trace record");
        }
        let transaction =
            result.transactions_for(&self.address).into_iter().last().expect("transaction");
        let TransactionDescr::Ordinary(description) =
            transaction.read_description().expect("description")
        else {
            panic!("ordinary transaction expected")
        };
        let TrComputePhase::Vm(vm) = description.compute_ph else {
            panic!("compute phase skipped")
        };
        Gas { used: vm.gas_used.as_u64(), exit: vm.exit_code, aborted: description.aborted }
    }

    fn call(&mut self, request: u64) -> Gas {
        let mut body = BuilderData::new();
        body.append_u32(1).expect("op");
        body.append_raw(&request_hash(request), 256).expect("request");
        self.send(body.into_cell().expect("call"))
    }

    fn respond(&mut self, variant: Variant, attestor: &Attestor, request: u64) -> (Gas, usize) {
        let response_hash = chain_block::sha256_digest(format!("response-{request}").as_bytes());
        let domain = domain_hash(request, &request_hash(request), &response_hash);
        let mut body = BuilderData::new();
        body.append_u32(2).expect("op");
        body.append_u64(request).expect("id");
        body.append_raw(&response_hash, 256).expect("response");
        attestor.proof(variant, &domain, &mut body);
        let body = body.into_cell().expect("respond");
        let bytes = chain_block::write_boc(&body).expect("boc").len();
        (self.send(body), bytes)
    }

    fn rotate(&mut self, variant: Variant, next: &Attestor) -> Gas {
        let mut body = BuilderData::new();
        body.append_u32(3).expect("op");
        body.checked_append_reference(next.key_material(variant)).expect("key material");
        self.send(body.into_cell().expect("rotate"))
    }

    fn storage(&self) -> (u64, u64) {
        let account = self.bc.get_account(&self.address).expect("account");
        let used = account.storage_info().expect("storage info").used();
        (used.cells(), used.bits())
    }
}

fn request_hash(request: u64) -> [u8; 32] {
    chain_block::sha256_digest(format!("request-{request}").as_bytes())
}

fn probe_code() -> Cell {
    let dir = tempfile::tempdir().expect("probe dir");
    let path = dir.path().join("pq_service_actor_gas_probe.fc");
    std::fs::write(&path, PROBE).expect("probe source");
    let crypto = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont");
    compile_func_with_stdlib(&[
        std::path::PathBuf::from(format!("{crypto}/pq.fc")),
        std::path::PathBuf::from(format!("{crypto}/pq-bytes.fc")),
        path,
    ])
    .expect("the probe compiles with PQ.fif")
}

/// One row per variant. Set PQ_SERVICE_ACTOR_GAS_OUT=<path> to write them as JSON.
#[test]
fn service_actor_shaped_attestation_cost() {
    let code = probe_code();
    let mut rows = Vec::new();
    for variant in [Variant::Ed25519, Variant::StoredKey, Variant::KeyId] {
        let first = Attestor::new(0x41);
        let second = Attestor::new(0x42);
        let mut probe = Probe::deploy(&code, variant, &first);
        let base = probe.storage();

        let mut call_gas = Vec::new();
        let mut storage = serde_json::Map::new();
        for request in 0..50u64 {
            let gas = probe.call(request);
            assert!(!gas.aborted && gas.exit == 0, "{} call {request}: {gas:?}", variant.name());
            call_gas.push(gas.used);
            if matches!(request + 1, 1 | 10 | 50) {
                let (cells, bits) = probe.storage();
                storage.insert(
                    format!("pending_{}", request + 1),
                    serde_json::json!({"cells": cells, "bits": bits,
                        "delta_cells": cells - base.0, "delta_bits": bits - base.1}),
                );
            }
        }
        // Rotate, then 10 more requests under the new key: the old snapshots
        // keep the old key alive alongside the new one.
        let rotate_gas = probe.rotate(variant, &second);
        assert!(!rotate_gas.aborted && rotate_gas.exit == 0, "{} rotate", variant.name());
        for request in 50..60u64 {
            let gas = probe.call(request);
            assert!(!gas.aborted && gas.exit == 0, "{} call {request}", variant.name());
        }
        let (cells, bits) = probe.storage();
        storage.insert(
            "after_rotation_60".into(),
            serde_json::json!({"cells": cells, "bits": bits,
                "delta_cells": cells - base.0, "delta_bits": bits - base.1}),
        );

        // Respond to one request under each key.
        let (respond_old, body_bytes) = probe.respond(variant, &first, 0);
        assert!(!respond_old.aborted && respond_old.exit == 0, "{} respond", variant.name());
        let (respond_new, _) = probe.respond(variant, &second, 55);
        assert!(!respond_new.aborted && respond_new.exit == 0, "{} respond", variant.name());
        // A response signed by the other key is refused.
        let (wrong, _) = probe.respond(variant, &second, 1);
        assert!(wrong.aborted, "{} accepted the wrong attestor: {wrong:?}", variant.name());

        let call_first = call_gas[0];
        let call_last = call_gas[call_gas.len() - 1];
        println!(
            "{:<10} call gas first={call_first} 50th={call_last} | respond gas {} (old key) {} \
             (new key) | respond body {body_bytes} B | rotate gas {} | storage {:?}",
            variant.name(),
            respond_old.used,
            respond_new.used,
            rotate_gas.used,
            storage
        );
        rows.push(serde_json::json!({
            "variant": variant.name(),
            "call_gas_first": call_first,
            "call_gas_50th": call_last,
            "respond_gas_old_key": respond_old.used,
            "respond_gas_new_key": respond_new.used,
            "respond_wrong_key_exit": wrong.exit,
            "respond_body_boc_bytes": body_bytes,
            "rotate_gas": rotate_gas.used,
            "storage_base": {"cells": base.0, "bits": base.1},
            "storage": storage,
        }));
    }
    if let Ok(out) = std::env::var("PQ_SERVICE_ACTOR_GAS_OUT") {
        std::fs::write(out, serde_json::to_string_pretty(&rows).expect("json")).expect("write");
    }
}
