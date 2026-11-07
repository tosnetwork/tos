/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! What Task Escrow, Proof Attestation and Dispute attestations would cost with
//! an ML-DSA-44 attestor, measured before those contracts are changed.
//!
//! Each of the three verifies exactly one attestor signature per authorizing
//! operation, over a domain hash built with `signing-domain.fc` (tag, global
//! id, workchain, this contract's address) followed by the operation's fields,
//! against a key held in its state. The probe performs exactly those four
//! operations with their real preimages:
//!
//! * Task Escrow `settle` ("TSE2": result_hash, payout) and `resolve` ("TRE2":
//!   result_hash, dispute_hash, payout);
//! * Proof Attestation `attest` ("PAT3": key_epoch, sequence, attested_hash);
//! * Dispute `rule` ("DRU3": ruling, split_bps, ruling_hash);
//!
//! once with today's inline 256-bit Ed25519 key and `CHKSIGNU`, and once with
//! the stored ML-DSA-44 key (`len:uint32 ^chain`) and `PQCHECKSIG_MLDSA44`, plus
//! a key rotation. The real contracts add their own state handling and payouts
//! on top, identically in both modes; the difference between the modes is the
//! cost of the change.

use chain_block::{
    BuilderData, Cell, Coins, IBitstring, MsgAddressInt, Serializable, StateInit, TrComputePhase,
    TransactionDescr,
};
use ed25519_dalek::Signer as _;
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer as _};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 16;
const CONTEXT: &[u8] = b"TOS-SERVICE-ATTESTOR-PROBE";
const CHUNK_BYTES: usize = 127;

const PROBE: &str = r#"
;; data: mode:uint8 ^key_material
;;   mode 0: key_material = [pubkey:uint256]   mode 1: key_material = [^stored_key]
;; op 1 settle:  payout:Coins + proof; result_hash from state          (TSE2)
;; op 2 resolve: payout:Coins + proof; result_hash, dispute_hash from state (TRE2)
;; (as in Task Escrow: the hashes are stored; the message carries the payout)
;; op 3 attest:  key_epoch:uint32 sequence:uint64 attested_hash:uint256 + proof (PAT3)
;; op 4 rule:    ruling:uint8 split_bps:uint16 ruling_hash:uint256 + proof (DRU3)
;; op 5 rotate:  ^key_material
;; proof: mode 0 signature:bits512   mode 1 ^stored_signature

cell stored_chain(cell stored, int expected) inline {
  slice s = stored.pq::parse_ordinary();
  throw_unless(60, s~load_uint(32) == expected);
  cell chain = s~load_ref();
  s.end_parse();
  return chain;
}

() check(int mode, cell key_material, int domain_hash, slice body) impure inline {
  slice km = key_material.begin_parse();
  if (mode == 0) {
    slice signature = body~load_bits(512);
    body.end_parse();
    throw_unless(61, check_signature(domain_hash, signature, km~load_uint(256)));
  } else {
    cell key = stored_chain(km~load_ref(), 1312);
    cell signature = stored_chain(body~load_ref(), 2420);
    body.end_parse();
    cell message = begin_cell().store_uint(domain_hash, 256).end_cell();
    cell context = begin_cell().store_slice("TOS-SERVICE-ATTESTOR-PROBE").end_cell();
    throw_unless(62, pq_check_mldsa44(message, context, signature, key));
  }
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg) impure {
  slice full = in_msg_full.begin_parse();
  if (full~load_uint(4) & 1) { return (); }
  if (in_msg.slice_bits() < 32) { return (); }
  int op = in_msg~load_uint(32);
  slice ds = get_data().begin_parse();
  int mode = ds~load_uint(8);
  cell key_material = ds~load_ref();
  ds.end_parse();
  if (op == 5) {
    cell next = in_msg~load_ref();
    in_msg.end_parse();
    set_data(begin_cell().store_uint(mode, 8).store_ref(next).end_cell());
    return ();
  }
  int domain_hash = 0;
  int result_hash = 0x1111111111111111111111111111111111111111111111111111111111111111;
  int dispute_hash = 0x2222222222222222222222222222222222222222222222222222222222222222;
  if (op == 1) {
    int payout = in_msg~load_coins();
    domain_hash = cell_hash(begin_signing_domain(0x54534532)
      .store_uint(result_hash, 256).store_coins(payout).end_cell());
  } elseif (op == 2) {
    int payout = in_msg~load_coins();
    domain_hash = cell_hash(begin_signing_domain(0x54524532)
      .store_uint(result_hash, 256).store_uint(dispute_hash, 256).store_coins(payout).end_cell());
  } elseif (op == 3) {
    int key_epoch = in_msg~load_uint(32);
    int sequence = in_msg~load_uint(64);
    int attested_hash = in_msg~load_uint(256);
    domain_hash = cell_hash(begin_signing_domain(0x50415433)
      .store_uint(key_epoch, 32).store_uint(sequence, 64).store_uint(attested_hash, 256).end_cell());
  } elseif (op == 4) {
    int ruling = in_msg~load_uint(8);
    int split_bps = in_msg~load_uint(16);
    int ruling_hash = in_msg~load_uint(256);
    domain_hash = cell_hash(begin_signing_domain(0x44525533)
      .store_uint(ruling, 8).store_uint(split_bps, 16).store_uint(ruling_hash, 256).end_cell());
  } else {
    throw(0xffff);
  }
  check(mode, key_material, domain_hash, in_msg);
}
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Ed25519,
    MlDsa44,
}

impl Mode {
    fn code(self) -> u8 {
        match self {
            Self::Ed25519 => 0,
            Self::MlDsa44 => 1,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa44 => "ml-dsa-44",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Settle,
    Resolve,
    Attest,
    Rule,
}

impl Op {
    fn all() -> [Op; 4] {
        [Op::Settle, Op::Resolve, Op::Attest, Op::Rule]
    }
    fn code(self) -> u32 {
        match self {
            Op::Settle => 1,
            Op::Resolve => 2,
            Op::Attest => 3,
            Op::Rule => 4,
        }
    }
    fn tag(self) -> u32 {
        match self {
            Op::Settle => 0x5453_4532,
            Op::Resolve => 0x5452_4532,
            Op::Attest => 0x5041_5433,
            Op::Rule => 0x4452_5533,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Op::Settle => "task-escrow settle",
            Op::Resolve => "task-escrow resolve",
            Op::Attest => "proof-attestation attest",
            Op::Rule => "dispute rule",
        }
    }
    /// The fields the operation's message carries: Task Escrow keeps the
    /// result and dispute hashes in state and sends only the payout.
    fn message_fields(self, b: &mut BuilderData) {
        match self {
            Op::Settle => Coins::new(3 * TOS).write_to(b).expect("payout"),
            Op::Resolve => Coins::new(2 * TOS).write_to(b).expect("payout"),
            Op::Attest | Op::Rule => self.fields(b),
        }
    }

    /// The operation's fields, as they follow the signing-domain prefix.
    fn fields(self, b: &mut BuilderData) {
        match self {
            Op::Settle => {
                b.append_raw(&[0x11; 32], 256).expect("result");
                Coins::new(3 * TOS).write_to(b).expect("payout");
            }
            Op::Resolve => {
                b.append_raw(&[0x11; 32], 256).expect("result");
                b.append_raw(&[0x22; 32], 256).expect("dispute");
                Coins::new(2 * TOS).write_to(b).expect("payout");
            }
            Op::Attest => {
                b.append_u32(1).expect("epoch");
                b.append_u64(7).expect("sequence");
                b.append_raw(&[0x33; 32], 256).expect("hash");
            }
            Op::Rule => {
                b.append_u8(2).expect("ruling");
                b.append_u16(5_000).expect("split");
                b.append_raw(&[0x44; 32], 256).expect("ruling hash");
            }
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

    fn key_material(&self, mode: Mode) -> Cell {
        let mut b = BuilderData::new();
        match mode {
            Mode::Ed25519 => {
                b.append_raw(&self.ed.verifying_key().to_bytes(), 256).expect("key");
            }
            Mode::MlDsa44 => {
                b.checked_append_reference(stored(&self.pq_public)).expect("key");
            }
        }
        b.into_cell().expect("key material")
    }

    fn proof(&self, mode: Mode, domain_hash: &[u8; 32], body: &mut BuilderData) {
        match mode {
            Mode::Ed25519 => {
                body.append_raw(&self.ed.sign(domain_hash).to_bytes(), 512).expect("signature");
            }
            Mode::MlDsa44 => {
                let signature = self
                    .pq_secret
                    .try_sign_with_seed(&[0; 32], domain_hash, CONTEXT)
                    .expect("ML-DSA-44 signing");
                body.checked_append_reference(stored(&signature)).expect("signature");
            }
        }
    }
}

fn sandbox_global_id(bc: &Blockchain) -> i32 {
    match bc.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        other => panic!("parameter 19 is not the global id: {other:?}"),
    }
}

#[derive(Clone, Copy, Debug)]
struct Gas {
    used: u64,
    exit: i32,
    aborted: bool,
}

struct Probe {
    bc: Blockchain,
    payer: tos_sandbox::Treasury,
    address: MsgAddressInt,
}

impl Probe {
    fn deploy(code: &Cell, mode: Mode, attestor: &Attestor) -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
            .expect("v16 chain with basechain 0");
        bc.set_workchain(0);
        let payer = bc.treasury("pq-attestor-gas-payer", 1_000 * TOS).expect("payer");
        let mut data = BuilderData::new();
        data.append_u8(mode.code()).expect("mode");
        data.checked_append_reference(attestor.key_material(mode)).expect("key material");
        let init = StateInit::with_code_and_data(code.clone(), data.into_cell().expect("data"));
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
        Self { bc, payer, address }
    }

    fn domain_hash(&self, op: Op) -> [u8; 32] {
        let mut b = BuilderData::new();
        b.append_u32(op.tag()).expect("tag");
        b.append_i32(sandbox_global_id(&self.bc)).expect("global id");
        b.append_i8(0).expect("workchain");
        b.append_raw(self.address.address().storage(), 256).expect("address");
        op.fields(&mut b);
        *b.into_cell().expect("domain").repr_hash().as_array()
    }

    fn send(&mut self, body: Cell) -> Gas {
        use chain_block::{HashmapType, ShardAccount, UInt256, base64_encode, write_boc};
        let message =
            MessageBuilder::internal(self.payer.address(), &self.address, TOS).body(body).build();
        // With PQ_ATTESTOR_TRACE_DIR set, every transaction is recorded for replay
        // in the native (C++) engine (scripts/replay-token-bridge-trace.py).
        let boc = |cell: Cell| base64_encode(write_boc(&cell).expect("boc"));
        let trace = std::env::var_os("PQ_ATTESTOR_TRACE_DIR").map(|dir| {
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
        let transaction =
            result.transactions_for(&self.address).into_iter().last().expect("transaction");
        if let Some((dir, config, before, message)) = trace {
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

    fn operate(&mut self, mode: Mode, op: Op, attestor: &Attestor) -> (Gas, usize) {
        let domain = self.domain_hash(op);
        let mut body = BuilderData::new();
        body.append_u32(op.code()).expect("op");
        op.message_fields(&mut body);
        attestor.proof(mode, &domain, &mut body);
        let body = body.into_cell().expect("body");
        let bytes = chain_block::write_boc(&body).expect("boc").len();
        (self.send(body), bytes)
    }

    fn rotate(&mut self, mode: Mode, next: &Attestor) -> Gas {
        let mut body = BuilderData::new();
        body.append_u32(5).expect("op");
        body.checked_append_reference(next.key_material(mode)).expect("key material");
        self.send(body.into_cell().expect("rotate"))
    }

    fn storage(&self) -> (u64, u64) {
        let account = self.bc.get_account(&self.address).expect("account");
        let used = account.storage_info().expect("storage info").used();
        (used.cells(), used.bits())
    }
}

fn probe_code() -> Cell {
    let dir = tempfile::tempdir().expect("probe dir");
    let path = dir.path().join("pq_attestor_gas_probe.fc");
    std::fs::write(&path, PROBE).expect("probe source");
    let crypto = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont");
    compile_func_with_stdlib(&[
        std::path::PathBuf::from(format!("{crypto}/signing-domain.fc")),
        std::path::PathBuf::from(format!("{crypto}/pq.fc")),
        std::path::PathBuf::from(format!("{crypto}/pq-bytes.fc")),
        path,
    ])
    .expect("the probe compiles with PQ.fif")
}

/// One row per (mode, operation). Set PQ_ATTESTOR_GAS_OUT=<path> to write JSON.
#[test]
fn single_attestor_operations_cost() {
    let code = probe_code();
    let mut rows = Vec::new();
    for mode in [Mode::Ed25519, Mode::MlDsa44] {
        let attestor = Attestor::new(0x51);
        let other = Attestor::new(0x52);
        let mut probe = Probe::deploy(&code, mode, &attestor);
        let storage = probe.storage();
        for op in Op::all() {
            let (gas, body_bytes) = probe.operate(mode, op, &attestor);
            assert!(!gas.aborted && gas.exit == 0, "{} {}: {gas:?}", mode.name(), op.name());
            let (wrong, _) = probe.operate(mode, op, &other);
            assert!(wrong.aborted, "{} {} accepted another key: {wrong:?}", mode.name(), op.name());
            println!(
                "{:<10} {:<26} gas {:>6} | body {:>5} B | wrong key exit {}",
                mode.name(),
                op.name(),
                gas.used,
                body_bytes,
                wrong.exit
            );
            rows.push(serde_json::json!({"mode": mode.name(), "operation": op.name(),
                "gas": gas.used, "body_boc_bytes": body_bytes, "wrong_key_exit": wrong.exit,
                "storage_cells": storage.0, "storage_bits": storage.1}));
        }
        let rotate = probe.rotate(mode, &other);
        assert!(!rotate.aborted && rotate.exit == 0, "{} rotate", mode.name());
        let (after, _) = probe.operate(mode, Op::Attest, &other);
        assert!(!after.aborted && after.exit == 0, "{} after rotation", mode.name());
        println!(
            "{:<10} rotate gas {} | account storage {} cells / {} bits",
            mode.name(),
            rotate.used,
            storage.0,
            storage.1
        );
        rows.push(serde_json::json!({"mode": mode.name(), "operation": "rotate key",
            "gas": rotate.used, "storage_cells": storage.0, "storage_bits": storage.1}));
    }
    if let Ok(out) = std::env::var("PQ_ATTESTOR_GAS_OUT") {
        std::fs::write(out, serde_json::to_string_pretty(&rows).expect("json")).expect("write");
    }
}
