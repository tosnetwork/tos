/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sections 15.3, 15.4 and 16.3: authenticating a bounced payout and turning
//! it back into a note.
//!
//! **What this suite does not do.** Section 15.3 requires the recovery handler
//! to be tested against a real outbound -> failure -> protocol-generated bounce
//! round trip, and says plainly that a helper which fabricates `bounced=true`
//! is not sufficient evidence. That round trip has to start with the pool
//! sending a payout, and a payout is step 16 of section 16.2 -- after the
//! proof. This branch has no proof that verifies, so the pool cannot be made
//! to send one, and the round trip cannot be completed through it.
//!
//! What is done instead, and what it is worth: the bounce **body** used below
//! is genuinely protocol-generated. A sender built from the pool's own payout
//! library sends a real section 15.2 message, a real destination refuses it,
//! and the executor produces a real rich bounce; the suite then delivers that
//! bounce's own body to the pool. The envelope, the original body and the
//! value are the chain's, not the test's. The delivery is arranged, and that
//! is the part section 15.3 is not satisfied by. It will be satisfied when a
//! proof exists and not before.

use chain_block::{
    BuilderData, Cell, CommonMsgInfo, CurrencyCollection, IBitstring, InternalMessageHeader,
    Message, MsgAddressInt, Serializable, SliceData, StateInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, compile_func_with_stdlib};
use tos_vm::stack::StackItem;
use tos_vm::stack::integer::IntegerData;

mod shielded_pool_library;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
const MAGIC: u32 = 0x5350_5631;
const VERSION: u16 = 1;
const EPOCH_NONE: u32 = 0xffff_ffff;
const RESERVE_FLOOR: u64 = 5 * TOS;
const DEPTH: usize = 12;
const CONFIG_WITHDRAWAL_FEE: u64 = 50_000_000;

type Field = [u8; 32];

fn small(value: u64) -> Field {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn dec(bytes: &Field) -> String {
    let mut digits = vec![0u8];
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let value = u32::from(*digit) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

fn int(value: &Field) -> StackItem {
    StackItem::int(IntegerData::from_str_radix(&dec(value), 10).expect("a field element"))
}

fn store_coins(builder: &mut BuilderData, amount: u128) {
    let bytes = amount.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let length = bytes.len() - first;
    builder.append_bits(length, 4).expect("coin length");
    if length > 0 {
        builder.append_raw(&bytes[first..], length * 8).expect("coin bytes");
    }
}

fn byte_chain(bytes: &[u8]) -> Cell {
    let mut chunks: Vec<&[u8]> = bytes.chunks(127).collect();
    let mut cell = Cell::default();
    let mut first = true;
    while let Some(chunk) = chunks.pop() {
        let mut builder = BuilderData::new();
        builder.append_raw(chunk, chunk.len() * 8).expect("chunk");
        if !first {
            builder.checked_append_reference(cell).expect("chain");
        }
        first = false;
        cell = builder.into_cell().expect("a chain cell");
    }
    cell
}

fn payload(seed: u8) -> Vec<u8> {
    (0..1233u32).map(|i| (i as u8) ^ seed).collect()
}

fn std_address(account: &Field) -> SliceData {
    let mut builder = BuilderData::new();
    builder.append_bits(2, 2).unwrap();
    builder.append_bit_zero().unwrap();
    builder.append_i8(0).unwrap();
    builder.append_raw(account, 256).unwrap();
    SliceData::load_builder(builder).expect("an address slice")
}

fn account_of(addr: &MsgAddressInt) -> Field {
    let bytes = addr.address().get_bytestring(0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

// --- the library probe ---------------------------------------------------

const PROBE: &str = r#"
cell p_original(slice body) method_id { return recovery_original_body(body); }
(int, int, int, int, int) p_payout(cell original) method_id {
  (int query_id, int digest, int template_hash, int recipient_hash, int owner, cell data) =
    recovery_parse_payout(original);
  return (query_id, digest, template_hash, recipient_hash, owner);
}
int p_authentic(slice sender, int query_id, int digest, int template_hash,
                int recipient_hash, int owner, cell data) method_id {
  recovery_require_authentic(sender, query_id, digest, template_hash, recipient_hash,
                             owner, data);
  return 1;
}
int p_note(int owner, int amount, cell data) method_id {
  return recovery_note_body(owner, amount, data);
}
int p_recipient_hash(slice address) method_id { return public_recipient_hash(address); }
int p_template_hash(int owner, cell data) method_id {
  return recovery_template_hash(owner, output_data_hash(data));
}
cell p_record(int digest, int template_hash, int recipient_hash, int owner, cell data)
    method_id {
  return payout_record(digest, template_hash, recipient_hash, owner, data);
}
cell p_body(int digest, cell record) method_id { return payout_body(digest, record); }
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

/// A sender that builds a real section 15.2 payout out of the pool's own
/// library and sends it bouncable, so the bounce that comes back is the
/// chain's work rather than the test's.
const SENDER: &str = r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
  slice header = in_msg_full.begin_parse();
  int flags = header~load_uint(4);
  if (flags & 1) {
    return ();
  }
  if (in_msg_body.slice_empty?()) {
    return ();
  }
  slice recipient = in_msg_body~load_msg_addr();
  int amount = in_msg_body~load_coins();
  ;; Four field elements are 1024 bits and a cell holds 1023, so the caller
  ;; hands them over in the same two-cell shape the record itself uses.
  slice fields = in_msg_body~load_ref().begin_parse();
  int digest = fields~load_uint(256);
  int template_hash = fields~load_uint(256);
  int recipient_hash = fields~load_uint(256);
  slice tail = fields~load_ref().begin_parse();
  int owner = tail~load_uint(256);
  cell data = tail~load_ref();
  cell record = payout_record(digest, template_hash, recipient_hash, owner, data);
  send_raw_message(payout_message(recipient, amount, payout_body(digest, record)), 1);
}
() recv_external(slice in_msg) impure { }
"#;

/// A destination that refuses everything but its own deployment.
const REFUSER: &str = r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
  slice header = in_msg_full.begin_parse();
  int flags = header~load_uint(4);
  if (flags & 1) {
    return ();
  }
  if (in_msg_body.slice_empty?()) {
    return ();
  }
  throw(701);
}
() recv_external(slice in_msg) impure { }
"#;

fn library() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont/shielded")
}

fn deploy_source(bc: &mut Blockchain, name: &str, source: &str, extra: &[&str]) -> MsgAddressInt {
    // A directory of this call's own. These probes are written from several tests at
    // once, and a shared path is truncated under a concurrent `func` reading it.
    let probe_dir = tempfile::tempdir().expect("a directory for the probe");
    let path = probe_dir.path().join(format!("tos_shielded_{name}.fc"));
    std::fs::write(&path, source).expect("write probe");
    let mut sources: Vec<std::path::PathBuf> =
        extra.iter().map(|f| format!("{}/{f}", library()).into()).collect();
    sources.push(path);
    let code = compile_func_with_stdlib(&sources).expect("compile (needs build/crypto/func)");
    let si = StateInit::with_code_and_data(code, Cell::default());
    let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    let addr = MsgAddressInt::with_params(0, hash).unwrap();
    let payer = bc.treasury(name, 100_000 * TOS).expect("treasury");
    bc.send_message(
        MessageBuilder::internal(payer.address(), &addr, 1_000 * TOS)
            .bounce(false)
            .state_init(si)
            .body(Cell::default())
            .build(),
    )
    .expect("deploy")
    .expect_success();
    addr
}

struct Probe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl Probe {
    fn deploy() -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
            .expect("blockchain at version 17");
        bc.set_workchain(0);
        let addr = deploy_source(
            &mut bc,
            "recovery_probe",
            PROBE,
            &[
                "domains.fc",
                "empty-roots.fc",
                "notes.fc",
                "auth.fc",
                "payload.fc",
                "domain.fc",
                "payout.fc",
                "recovery.fc",
            ],
        );
        Self { bc, addr }
    }

    fn call(&self, method: &str, args: Vec<StackItem>) -> Result<Vec<StackItem>, i32> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, args)
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        if result.exit_code != 0 {
            return Err(result.exit_code);
        }
        Ok(result.stack)
    }

    fn cell(&self, method: &str, args: Vec<StackItem>) -> Cell {
        let stack = self.call(method, args).unwrap_or_else(|code| panic!("{method} exited {code}"));
        stack.last().expect("a result").as_cell().expect("a cell").clone()
    }

    fn int_of(&self, method: &str, args: Vec<StackItem>) -> String {
        let stack = self.call(method, args).unwrap_or_else(|code| panic!("{method} exited {code}"));
        stack.last().expect("a result").as_integer().expect("an integer").to_string()
    }
}

/// One real round trip: a sender built from the payout library pays a
/// destination that refuses, and the protocol bounces the payment back.
/// Returns the bounce the chain produced and the address it came from.
fn real_bounce(
    bc: &mut Blockchain,
    digest: &Field,
    template_hash: &str,
    recipient_hash: &str,
    owner: &Field,
    data: &Cell,
    amount: u64,
) -> (Message, MsgAddressInt) {
    let sender = deploy_source(bc, "recovery_sender", SENDER, &["payout.fc"]);
    let refuser = deploy_source(bc, "recovery_refuser", REFUSER, &[]);

    // A get-method hands a field element back as a decimal string; the wire
    // wants its 32 big-endian bytes.
    let to_field = |text: &str| -> Field {
        let value = IntegerData::from_str_radix(text, 10).expect("a field element");
        let hex = format!("{:0>64}", value.to_str_radix(16));
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex");
        }
        out
    };

    let mut tail = BuilderData::new();
    tail.append_raw(owner, 256).unwrap();
    tail.checked_append_reference(data.clone()).unwrap();
    let mut fields = BuilderData::new();
    fields.append_raw(digest, 256).unwrap();
    fields.append_raw(&to_field(template_hash), 256).unwrap();
    fields.append_raw(&to_field(recipient_hash), 256).unwrap();
    fields.checked_append_reference(tail.into_cell().unwrap()).unwrap();

    let mut instruction = BuilderData::new();
    let address = std_address(&account_of(&refuser));
    instruction.append_raw(&address.get_bytestring(0), address.remaining_bits()).unwrap();
    store_coins(&mut instruction, u128::from(amount));
    instruction.checked_append_reference(fields.into_cell().unwrap()).unwrap();

    let payer = bc.treasury("relay", 100_000 * TOS).expect("treasury");
    let result: SendResult = bc
        .send_message(
            MessageBuilder::internal(payer.address(), &sender, 50 * TOS)
                .bounce(true)
                .body(instruction.into_cell().unwrap())
                .build(),
        )
        .expect("send");

    for (_, tx) in &result.transactions {
        if let Ok(Some(msg)) = tx.read_in_msg() {
            if let CommonMsgInfo::IntMsgInfo(info) = msg.header() {
                if info.bounced {
                    return (msg.clone(), refuser.clone());
                }
            }
        }
    }
    panic!("the round trip produced no bounce");
}

// --- the pool ------------------------------------------------------------

fn config_store() -> Cell {
    let mut chain = BuilderData::new();
    store_coins(&mut chain, u128::from(TOS));
    let mut builder = BuilderData::new();
    builder.append_raw(&[0x11; 32], 256).unwrap();
    builder.append_raw(&[0x22; 32], 256).unwrap();
    builder.append_raw(&[0x33; 32], 256).unwrap();
    store_coins(&mut builder, u128::from(CONFIG_WITHDRAWAL_FEE));
    builder.append_u8(1).unwrap();
    builder.checked_append_reference(chain.into_cell().unwrap()).unwrap();
    builder.into_cell().expect("a config store")
}

fn vk_store() -> Cell {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../tools/shielded-pool-circuit/fixtures/groth16-development.json"
    );
    let text = std::fs::read_to_string(path).expect("the development fixture");
    let fixture: serde_json::Value = serde_json::from_str(&text).expect("the fixture is JSON");
    let hex = fixture["verifying_key"]["hex"].as_str().expect("the verifying key");
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();
    byte_chain(&bytes)
}

fn empty_ring_holder() -> Cell {
    let mut builder = BuilderData::new();
    builder.append_bit_zero().unwrap();
    builder.into_cell().unwrap()
}

fn genesis_state(liability: u64) -> Cell {
    let empty_root = chain_block::poseidon2_kat::EMPTY_ROOTS[DEPTH];
    let mut builder = BuilderData::new();
    builder.append_u32(MAGIC).unwrap();
    builder.append_u16(VERSION).unwrap();
    builder.append_raw(&empty_root, 256).unwrap();
    builder.append_u64(0).unwrap();
    builder.append_raw(&[0x5a; 32], 256).unwrap();
    builder.append_u64(1).unwrap();
    builder.append_u32(EPOCH_NONE).unwrap();
    store_coins(&mut builder, u128::from(liability));
    store_coins(&mut builder, u128::from(RESERVE_FLOOR));
    builder.checked_append_reference(shielded_pool_library::frontier_holder()).unwrap();
    let mut anchors = BuilderData::new();
    anchors.checked_append_reference(empty_ring_holder()).unwrap();
    anchors.checked_append_reference(empty_ring_holder()).unwrap();
    builder.checked_append_reference(anchors.into_cell().unwrap()).unwrap();
    builder.checked_append_reference(config_store()).unwrap();
    builder.checked_append_reference(vk_store()).unwrap();
    builder.into_cell().expect("the genesis state")
}

struct Pool {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl Pool {
    fn deploy(bc: Blockchain, liability: u64) -> Self {
        let mut bc = bc;
        bc.set_workchain(0);
        let payer = bc.treasury("pool_funder", 100_000 * TOS).expect("treasury");
        let code = compile_func_with_stdlib(&shielded_pool_library::pool_sources())
            .expect("compile the pool (needs build/crypto/func)");
        let si = StateInit::with_code_and_data(code, genesis_state(liability));
        let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let addr = MsgAddressInt::with_params(0, hash).unwrap();
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 200 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )
        .expect("deploy")
        .expect_success();
        Self { bc, addr }
    }

    fn get(&self, method: &str) -> String {
        let result = self
            .bc
            .run_get_method(&self.addr, method, vec![])
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        assert_eq!(result.exit_code, 0, "{method} exited {}", result.exit_code);
        result.stack.last().expect("a result").as_integer().expect("integer").to_string()
    }

    fn snapshot(&self) -> Vec<String> {
        ["commitment_root", "commitment_next_index", "native_liability", "reserve_floor"]
            .iter()
            .map(|m| self.get(m))
            .collect()
    }

    /// Delivers a bounce body to the pool as if it had come from `src`. The
    /// body is the chain's; this arranges the delivery, which is the part
    /// section 15.3 does not accept as evidence.
    fn deliver_bounce(&mut self, src: &MsgAddressInt, body: SliceData, value: u64) -> i32 {
        let mut header = InternalMessageHeader::with_addresses(
            src.clone(),
            self.addr.clone(),
            CurrencyCollection::with_coins(value),
        );
        header.bounce = false;
        header.bounced = true;
        header.ihr_disabled = true;
        let mut msg = Message::with_int_header(header);
        msg.set_body(body);
        let result = self.bc.send_message(msg).expect("deliver the bounce");
        match result.read_primary_description().compute_ph {
            chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
            chain_block::TrComputePhase::Skipped(s) => panic!("compute skipped: {:?}", s.reason),
        }
    }
}

// --- the library ---------------------------------------------------------

/// The envelope is read for exactly what the recovery needs out of it and
/// nothing else: a bounce is not made more authentic by why it happened.
#[test]
fn only_the_new_bounce_envelope_is_read() {
    let probe = Probe::deploy();

    let mut not_envelope = BuilderData::new();
    not_envelope.append_u32(0xffff_ffff).unwrap();
    not_envelope.checked_append_reference(Cell::default()).unwrap();
    assert_eq!(
        probe.call(
            "p_original",
            vec![StackItem::Slice(SliceData::load_builder(not_envelope).expect("a body"))],
        ),
        Err(264),
        "the legacy bounce tag was read as the new envelope"
    );

    let mut no_ref = BuilderData::new();
    no_ref.append_u32(0xffff_fffe).unwrap();
    assert_eq!(
        probe.call(
            "p_original",
            vec![StackItem::Slice(SliceData::load_builder(no_ref).expect("a body"))],
        ),
        Err(264),
        "an envelope carrying no original body was accepted"
    );

    // With a reference, so that only the length guard can refuse it: without
    // one the missing-reference guard would catch it first and the length
    // guard would never be the thing under test.
    let mut short = BuilderData::new();
    short.append_u16(0xffff).unwrap();
    short.checked_append_reference(Cell::default()).unwrap();
    assert_eq!(
        probe.call(
            "p_original",
            vec![StackItem::Slice(SliceData::load_builder(short).expect("a body"))],
        ),
        Err(264),
        "a body too short to hold a tag was read as one"
    );
}

/// Section 15.2's shape, read back. The bits-only bounce form is excluded by
/// this and not by a flag: it carries the payout's bits without its
/// references, so the record is not there to find.
#[test]
fn only_the_frozen_payout_shape_is_a_payout() {
    let probe = Probe::deploy();
    let data = byte_chain(&payload(4));
    let digest = small(0x0102_0304_0506_0708);
    let record = probe.cell(
        "p_record",
        vec![
            int(&digest),
            int(&small(0xaaa)),
            int(&small(0xbbb)),
            int(&small(0xccc)),
            StackItem::cell(data.clone()),
        ],
    );
    let body = probe.cell("p_body", vec![int(&digest), StackItem::cell(record)]);
    let stack = probe.call("p_payout", vec![StackItem::cell(body)]).expect("a payout");
    let values: Vec<String> =
        stack.iter().map(|i| i.as_integer().expect("integer").to_string()).collect();
    assert_eq!(values[0], "72623859790382856", "the query id is not the low half of the digest");
    assert_eq!(values[1], dec(&digest), "the intent digest was not read back");
    assert_eq!(values[2], dec(&small(0xaaa)), "the template hash was not read back");
    assert_eq!(values[3], dec(&small(0xbbb)), "the recipient hash was not read back");
    assert_eq!(values[4], dec(&small(0xccc)), "the owner commitment was not read back");

    // What the bits-only bounce form leaves: the payout's bits, no references.
    let mut bits_only = BuilderData::new();
    bits_only.append_u32(0).unwrap();
    bits_only.append_u64(1).unwrap();
    assert_eq!(
        probe.call("p_payout", vec![StackItem::cell(bits_only.into_cell().unwrap())]),
        Err(265),
        "a payout body without its record was accepted"
    );
}

/// Each half of the frozen shape, wrong on its own. A guard that no test can
/// reach is a guard nobody maintains, so every one of them gets a body that
/// only it can refuse.
#[test]
fn every_frozen_shape_is_refused_when_it_is_not_that_shape() {
    let probe = Probe::deploy();
    let data = byte_chain(&payload(1));

    /// `extra_*` add one bit past the frozen width; `*_refs` drop the
    /// reference the shape requires.
    struct Shape {
        op: u32,
        extra_root_bit: bool,
        extra_record_bit: bool,
        record_tail: bool,
        extra_tail_bit: bool,
        tail_payload: bool,
    }
    let build = |shape: &Shape| -> Cell {
        let mut tail = BuilderData::new();
        tail.append_raw(&small(0xccc), 256).unwrap();
        if shape.extra_tail_bit {
            tail.append_bit_one().unwrap();
        }
        if shape.tail_payload {
            tail.checked_append_reference(data.clone()).unwrap();
        }
        let mut record = BuilderData::new();
        record.append_raw(&small(1), 256).unwrap();
        record.append_raw(&small(2), 256).unwrap();
        record.append_raw(&small(3), 256).unwrap();
        if shape.extra_record_bit {
            record.append_bit_one().unwrap();
        }
        if shape.record_tail {
            record.checked_append_reference(tail.into_cell().unwrap()).unwrap();
        }
        let mut root = BuilderData::new();
        root.append_u32(shape.op).unwrap();
        root.append_u64(1).unwrap();
        if shape.extra_root_bit {
            root.append_bit_one().unwrap();
        }
        root.checked_append_reference(record.into_cell().unwrap()).unwrap();
        root.into_cell().expect("a payout body")
    };
    let frozen = Shape {
        op: 0,
        extra_root_bit: false,
        extra_record_bit: false,
        record_tail: true,
        extra_tail_bit: false,
        tail_payload: true,
    };
    assert!(
        probe.call("p_payout", vec![StackItem::cell(build(&frozen))]).is_ok(),
        "the frozen shape itself was refused"
    );

    let cases: Vec<(&str, Shape)> = vec![
        ("an operation other than zero", Shape { op: 1, ..frozen }),
        ("a bit past the root's width", Shape { extra_root_bit: true, ..frozen }),
        ("a bit past the record's width", Shape { extra_record_bit: true, ..frozen }),
        ("a record with no tail", Shape { record_tail: false, ..frozen }),
        ("a bit past the tail's width", Shape { extra_tail_bit: true, ..frozen }),
        ("a tail with no payload", Shape { tail_payload: false, ..frozen }),
    ];
    for (what, shape) in cases {
        assert_eq!(
            probe.call("p_payout", vec![StackItem::cell(build(&shape))]),
            Err(265),
            "{what} was read as a payout"
        );
    }
}

/// Section 15.3 checks 4 through 7. Every value in the record is either
/// recomputed from something outside it or used to recompute something that
/// is compared against it, so a record cannot vouch for itself.
#[test]
fn a_record_cannot_vouch_for_itself() {
    let probe = Probe::deploy();
    let data = byte_chain(&payload(6));
    let owner = small(0x5eed);
    let sender = small(0x4242);
    let digest = small(0x0102_0304_0506_0708);
    let recipient_hash =
        probe.int_of("p_recipient_hash", vec![StackItem::Slice(std_address(&sender))]);
    let template_hash =
        probe.int_of("p_template_hash", vec![int(&owner), StackItem::cell(data.clone())]);

    let authentic = |query: u64, tmpl: &str, recip: &str, owner_c: &Field, d: &Cell| {
        probe.call(
            "p_authentic",
            vec![
                StackItem::Slice(std_address(&sender)),
                StackItem::int(IntegerData::from_str_radix(&query.to_string(), 10).unwrap()),
                int(&digest),
                StackItem::int(IntegerData::from_str_radix(tmpl, 10).unwrap()),
                StackItem::int(IntegerData::from_str_radix(recip, 10).unwrap()),
                int(owner_c),
                StackItem::cell(d.clone()),
            ],
        )
    };

    let query = 0x0102_0304_0506_0708u64;
    assert!(
        authentic(query, &template_hash, &recipient_hash, &owner, &data).is_ok(),
        "a record consistent with everything outside it was refused"
    );

    assert_eq!(
        authentic(query + 1, &template_hash, &recipient_hash, &owner, &data),
        Err(266),
        "a query id that names another intent was accepted"
    );

    // The check that makes the record unusable by anyone else: the recipient
    // hash is recomputed from the address the bounce actually came from.
    let elsewhere =
        probe.int_of("p_recipient_hash", vec![StackItem::Slice(std_address(&small(0x4243)))]);
    assert_eq!(
        authentic(query, &template_hash, &elsewhere, &owner, &data),
        Err(267),
        "a record was accepted from an address it was not addressed to"
    );

    // And the template hash is recomputed from the payload that arrived, so
    // neither the owner commitment nor the payload can be swapped.
    assert_eq!(
        authentic(query, &template_hash, &recipient_hash, &small(0x5eee), &data),
        Err(268),
        "a record with another owner commitment was accepted"
    );
    assert_eq!(
        authentic(query, &template_hash, &recipient_hash, &owner, &byte_chain(&payload(7))),
        Err(268),
        "a record with another payload was accepted"
    );
}

/// Section 15.4: the note is for what came back, not for what went out.
#[test]
fn the_note_is_built_for_the_amount_that_actually_returned() {
    let probe = Probe::deploy();
    let data = byte_chain(&payload(8));
    let owner = small(0x1234);
    let note = |amount: u64| {
        probe.int_of(
            "p_note",
            vec![
                int(&owner),
                StackItem::int(IntegerData::from_str_radix(&amount.to_string(), 10).unwrap()),
                StackItem::cell(data.clone()),
            ],
        )
    };
    assert_ne!(
        note(1_000_000_000),
        note(999_999_999),
        "a note for one nanotos less is the same note"
    );
    assert_ne!(
        note(1_000_000_000),
        probe.int_of(
            "p_note",
            vec![
                int(&small(0x1235)),
                StackItem::int(IntegerData::from_u32(1_000_000_000)),
                StackItem::cell(data.clone()),
            ],
        ),
        "the owner commitment does not reach the note"
    );
}

// --- the handler ---------------------------------------------------------

/// A bounce the chain really produced, carrying a record that really checks
/// out, becomes a note. The pool owes what came back and nothing more.
#[test]
fn a_bounced_payout_becomes_a_note_for_what_came_back() {
    let probe = Probe::deploy();
    let data = byte_chain(&payload(2));
    let owner = small(0xbeef);
    let digest = small(0x0102_0304_0506_0708);
    let template_hash =
        probe.int_of("p_template_hash", vec![int(&owner), StackItem::cell(data.clone())]);

    let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
        .expect("blockchain at version 17");
    bc.set_workchain(0);
    // The record has to name the address the bounce will come from, which is
    // the refuser's, so it is deployed on a throwaway chain first just to
    // learn it. Code determines the address, so the one that matters later is
    // the same address.
    let mut scratch = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
        .expect("blockchain at version 17");
    scratch.set_workchain(0);
    let refuser = deploy_source(&mut scratch, "recovery_refuser", REFUSER, &[]);
    let recipient_hash = probe
        .int_of("p_recipient_hash", vec![StackItem::Slice(std_address(&account_of(&refuser)))]);

    let (bounce, from) =
        real_bounce(&mut bc, &digest, &template_hash, &recipient_hash, &owner, &data, 9 * TOS);
    assert_eq!(from.to_string(), refuser.to_string(), "the bounce came from somewhere else");
    let returned = match bounce.header() {
        CommonMsgInfo::IntMsgInfo(info) => info.value.coins.as_u128() as u64,
        _ => panic!("not an internal message"),
    };
    assert!(returned > 0 && returned < 9 * TOS, "the bounce returned {returned} of 9 TOS");

    let mut pool = Pool::deploy(bc, 9 * TOS);
    let before = pool.snapshot();
    let body = bounce.body().expect("the bounce has a body").clone();
    assert_eq!(pool.deliver_bounce(&from, body, returned), 0, "the recovery was refused");

    let after = pool.snapshot();
    assert_ne!(after[0], before[0], "the recovery minted no note");
    assert_eq!(after[1], "1", "the recovery did not take exactly one leaf");

    // Section 15.4: what came back **less what putting it back costs**. The
    // charge is asked of the contract rather than recomputed here, because a
    // second copy of a fee formula is a second thing to keep in step with the
    // chain's prices.
    let charge = pool.get("recovery_charge").parse::<u64>().expect("the quoted charge");
    assert!(charge > 0, "the contract quotes a recovery charge of nothing");
    assert!(returned > charge, "this bounce is below the charge and would mint nothing");
    assert_eq!(
        after[2].parse::<u64>().expect("liability"),
        before[2].parse::<u64>().expect("liability") + returned - charge,
        "the pool took back {returned} rather than that less the {charge} the recovery costs"
    );
    eprintln!(
        "a 9 TOS payout bounced back {returned} and minted {}: the recovery charged itself \
         {charge}",
        returned - charge
    );
}

/// Everything the authentication refuses, refused at the pool rather than in
/// a get-method: the record is the chain's, only the address it is presented
/// from is not the one it names.
#[test]
fn a_bounce_from_the_wrong_address_recovers_nothing() {
    let probe = Probe::deploy();
    let data = byte_chain(&payload(2));
    let owner = small(0xbeef);
    let digest = small(0x0102_0304_0506_0708);
    let template_hash =
        probe.int_of("p_template_hash", vec![int(&owner), StackItem::cell(data.clone())]);

    let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
        .expect("blockchain at version 17");
    bc.set_workchain(0);
    let mut scratch = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
        .expect("blockchain at version 17");
    scratch.set_workchain(0);
    let refuser = deploy_source(&mut scratch, "recovery_refuser", REFUSER, &[]);
    let recipient_hash = probe
        .int_of("p_recipient_hash", vec![StackItem::Slice(std_address(&account_of(&refuser)))]);

    let (bounce, _) =
        real_bounce(&mut bc, &digest, &template_hash, &recipient_hash, &owner, &data, 9 * TOS);

    let mut pool = Pool::deploy(bc, 9 * TOS);
    let before = pool.snapshot();
    let body = bounce.body().expect("the bounce has a body").clone();
    let elsewhere =
        MsgAddressInt::with_params(0, SliceData::from_raw(vec![0x77u8; 32], 256)).unwrap();
    assert_eq!(
        pool.deliver_bounce(&elsewhere, body, 5 * TOS),
        267,
        "a record was recovered from an address it does not name"
    );
    assert_eq!(pool.snapshot(), before, "a refused recovery moved the state");
}

/// Money arriving as a bounce with nothing to recover is reserve. The pool
/// does not refuse it and does not mint for it.
#[test]
fn a_bounce_that_is_not_a_payout_is_reserve() {
    let bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
        .expect("blockchain at version 17");
    let mut pool = Pool::deploy(bc, 0);
    let before = pool.snapshot();
    let from = MsgAddressInt::with_params(0, SliceData::from_raw(vec![0x11u8; 32], 256)).unwrap();

    assert_eq!(
        pool.deliver_bounce(&from, SliceData::default(), 3 * TOS),
        0,
        "an empty bounce was refused"
    );
    let mut legacy = BuilderData::new();
    legacy.append_u32(0xffff_ffff).unwrap();
    legacy.append_raw(&[0u8; 32], 256).unwrap();
    assert_eq!(
        pool.deliver_bounce(
            &from,
            SliceData::load_builder(legacy).expect("a legacy bounce"),
            3 * TOS
        ),
        0,
        "a legacy truncated bounce was refused"
    );
    assert_eq!(pool.snapshot(), before, "a bounce with nothing to recover moved the state");
}
