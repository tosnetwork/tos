/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Can this executor produce the bounce the profile's section 15.3 demands?
//!
//! Section 15.3 is explicit that a sandbox helper which fabricates
//! `bounced=true` is not evidence, and that recovery has to be tested against
//! a real outbound -> failure -> protocol-generated bounce round trip. Before
//! any recovery handler is written, that capability is worth establishing on
//! its own, because if the executor cannot do it the handler cannot be tested
//! and knowing that early is worth more than the handler.
//!
//! Nothing in this file is part of the pool. It is a probe: a minimal sender
//! that forwards one bouncable message, and a look at what comes back.

use chain_block::{
    BuilderData, Cell, CommonMsgInfo, Deserializable, IBitstring, Message, MsgAddressInt,
    Serializable,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};

const ACTIVE_VERSION: u32 = 18;
const TOS: u64 = 1_000_000_000;

/// A sender with nothing in it but the action under test: forward one
/// bouncable internal message to the address in the body, carrying the rich
/// bounce flags section 15.2 asks for, and record a bounce when one returns.
///
/// `extra_flags` is the field this chain put where `ihr_fee` used to be. Bit 0
/// asks for the new bounce format and bit 1 for the full original body, so the
/// profile's "rich-bounce extra flags 3" is this field set to 3. The probe
/// takes it from the body so both forms can be compared.
const SENDER: &str = r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
  slice header = in_msg_full.begin_parse();
  int flags = header~load_uint(4);
  if (flags & 1) {
    ;; A bounce came back. Record that it did, and how much returned.
    set_data(begin_cell().store_uint(1, 1).store_coins(msg_value).end_cell());
    return ();
  }
  ;; Its own deployment carries no body; there is nothing to forward.
  if (in_msg_body.slice_empty?()) {
    return ();
  }
  slice dest = in_msg_body~load_msg_addr();
  int amount = in_msg_body~load_coins();
  int extra_flags = in_msg_body~load_uint(8);
  cell payload = in_msg_body~load_ref();
  cell msg = begin_cell()
    .store_uint(0x18, 6)      ;; int_msg_info, ihr disabled, bounce = 1
    .store_slice(dest)
    .store_coins(amount)
    .store_uint(0, 1)         ;; no extra currencies
    .store_coins(extra_flags) ;; bit 0 new bounce format, bit 1 full body
    .store_coins(0)           ;; forward fee, filled in by the action phase
    .store_uint(0, 64 + 32)   ;; created_lt and created_at
    .store_uint(0, 1)         ;; no state init
    .store_uint(1, 1)         ;; the body is in a reference
    .store_ref(payload)
    .end_cell();
  send_raw_message(msg, 1);
}

;; 1 once a bounce has come back, 0 before.
int bounced() method_id {
  slice s = get_data().begin_parse();
  if (s.slice_bits() == 0) {
    return 0;
  }
  return s~load_uint(1);
}

;; How much value the bounce brought back.
int returned() method_id {
  slice s = get_data().begin_parse();
  if (s.slice_bits() == 0) {
    return 0;
  }
  s~load_uint(1);
  return s~load_coins();
}
"#;

/// A destination that refuses everything, so the message it is sent fails in
/// the compute phase and the protocol bounces it.
const REFUSER: &str = r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
  slice header = in_msg_full.begin_parse();
  int flags = header~load_uint(4);
  if (flags & 1) {
    return ();
  }
  ;; Its own deployment carries no body and must not fail, or there would be
  ;; nothing here to send to. Everything else is refused.
  if (in_msg_body.slice_empty?()) {
    return ();
  }
  throw(701);
}
"#;

fn deploy(bc: &mut Blockchain, source: &str, name: &str) -> MsgAddressInt {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join(format!("{name}.fc"));
    std::fs::write(&path, source).expect("write the source");
    let code = compile_func_with_stdlib(&[&path]).expect("compile (needs build/crypto/func)");
    let si = chain_block::StateInit::with_code_and_data(code, Cell::default());
    let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    let addr = MsgAddressInt::with_params(0, hash).unwrap();
    let payer = bc.treasury(name, 100_000 * TOS).expect("treasury");
    bc.send_message(
        MessageBuilder::internal(payer.address(), &addr, 100 * TOS)
            .bounce(false)
            .state_init(si)
            .body(Cell::default())
            .build(),
    )
    .expect("deploy")
    .expect_success();
    addr
}

fn get(bc: &Blockchain, addr: &MsgAddressInt, method: &str) -> String {
    let result =
        bc.run_get_method(addr, method, vec![]).unwrap_or_else(|e| panic!("{method}: {e}"));
    assert_eq!(result.exit_code, 0, "{method} exited {}", result.exit_code);
    result.stack.last().expect("a result").as_integer().expect("integer").to_string()
}

/// Was the returned message produced by the protocol, or by the test?
fn bounced_messages(result: &tos_sandbox::SendResult) -> Vec<Message> {
    let mut found = Vec::new();
    for (_, tx) in &result.transactions {
        if let Ok(Some(msg)) = tx.read_in_msg() {
            if let CommonMsgInfo::IntMsgInfo(info) = msg.header() {
                if info.bounced {
                    found.push(msg.clone());
                }
            }
        }
    }
    found
}

/// One round trip: the sender forwards a bouncable message carrying `flags`,
/// the destination refuses it, and the protocol bounces it back. Returns the
/// bounced message and the whole result.
fn round_trip(flags: u8) -> (Blockchain, MsgAddressInt, Message, tos_sandbox::SendResult) {
    let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
        .expect("blockchain at version 17");
    bc.set_workchain(0);
    let sender = deploy(&mut bc, SENDER, "sender");
    let refuser = deploy(&mut bc, REFUSER, "refuser");

    assert_eq!(get(&bc, &sender, "bounced"), "0", "the sender starts with no bounce");

    // A payload with a reference of its own, which is the part a body-bits-only
    // bounce cannot carry and the recovery record depends on.
    let mut tail = BuilderData::new();
    tail.append_raw(&[0xcd; 32], 256).unwrap();
    let mut payload = BuilderData::new();
    payload.append_u32(0).unwrap();
    payload.append_u64(0x0102_0304_0506_0708).unwrap();
    payload.append_raw(&[0xab; 32], 256).unwrap();
    payload.checked_append_reference(tail.into_cell().unwrap()).expect("tail");

    let mut instruction = BuilderData::new();
    append_std_address(&mut instruction, &refuser);
    store_coins(&mut instruction, 5 * u128::from(TOS));
    instruction.append_u8(flags).unwrap();
    instruction.checked_append_reference(payload.into_cell().unwrap()).expect("payload");

    let payer = bc.treasury("caller", 100_000 * TOS).expect("treasury");
    let result = bc
        .send_message(
            MessageBuilder::internal(payer.address(), &sender, 20 * TOS)
                .bounce(true)
                .body(instruction.into_cell().unwrap())
                .build(),
        )
        .expect("send");

    // Three transactions: the caller's message into the sender, the sender's
    // message into the refuser, and the bounce back into the sender.
    assert!(
        result.transaction_count() >= 3,
        "the round trip did not happen: {} transactions",
        result.transaction_count()
    );

    let bounced = bounced_messages(&result);
    assert_eq!(bounced.len(), 1, "expected exactly one bounced message, got {}", bounced.len());
    let info = match bounced[0].header() {
        CommonMsgInfo::IntMsgInfo(info) => info.clone(),
        other => panic!("a bounce that is not an internal message: {other:?}"),
    };
    assert_eq!(
        info.src_ref().map(std::string::ToString::to_string),
        Some(refuser.to_string()),
        "the bounce did not come from the address that failed"
    );
    assert_eq!(info.dst.to_string(), sender.to_string(), "the bounce did not return to the sender");
    assert_eq!(get(&bc, &sender, "bounced"), "1", "the sender never saw the bounce");

    let msg = bounced[0].clone();
    (bc, sender, msg, result)
}

/// The bounce exists, it comes back to the sender, and it brings value with it.
#[test]
fn this_executor_produces_a_real_bounce_and_the_sender_receives_it() {
    let (bc, sender, _, _) = round_trip(3);
    let returned: u128 = get(&bc, &sender, "returned").parse().expect("returned value");
    assert!(returned > 0, "the bounce brought nothing back");
    assert!(
        returned < 5 * u128::from(TOS),
        "the bounce returned {returned}, no less than what was sent; fees were not charged"
    );
    eprintln!("bounce returned {returned} of {} sent", 5 * u128::from(TOS));
}

/// The layout the section 16.3 parser will be written against, pinned here so
/// a change to it breaks a test with a name rather than a handler in the
/// field. `new_bounce_body#fffffffe original_body:^Cell original_info:^[...]
/// bounced_by_phase:uint8 exit_code:int32 compute_phase:(Maybe [...])`.
#[test]
fn the_rich_bounce_body_has_the_shape_the_recovery_handler_will_parse() {
    let (_, _, msg, _) = round_trip(3);
    let mut body = msg.body().expect("the bounce has no body").clone();

    assert_eq!(body.get_next_u32().expect("tag"), 0xffff_fffe, "not the new bounce body tag");
    let original = body.checked_drain_reference().expect("original_body");
    let info = body.checked_drain_reference().expect("original_info");
    let phase = body.get_next_byte().expect("bounced_by_phase");
    let exit = body.get_next_u32().expect("exit_code") as i32;
    let has_compute = body.get_next_bit().expect("compute_phase maybe");
    assert_eq!(phase, 1, "the destination failed in compute, not in phase {phase}");
    assert_eq!(exit, 701, "the bounce does not carry the exit code the destination threw");
    assert!(has_compute, "a compute phase that ran reported no compute info");
    let gas = body.get_next_u32().expect("gas_used");
    let steps = body.get_next_u32().expect("vm_steps");
    assert!(gas > 0 && steps > 0, "the destination ran but reported {gas} gas in {steps} steps");
    assert_eq!(body.remaining_bits(), 0, "trailing bits after the bounce body");
    assert_eq!(body.remaining_references(), 0, "trailing references after the bounce body");

    // The original body arrives whole, references and all.
    let mut carried = chain_block::SliceData::load_cell(original).expect("original body");
    assert_eq!(carried.get_next_u32().expect("op"), 0, "the original body was not carried");
    assert_eq!(carried.get_next_u64().expect("query id"), 0x0102_0304_0506_0708);
    assert_eq!(
        carried.remaining_references(),
        1,
        "the full-body bounce dropped the original body's reference"
    );

    // And so does the value that was sent, which recovery needs in order to
    // mint back no more than actually returned.
    let mut original_info = chain_block::SliceData::load_cell(info).expect("original info");
    let value = chain_block::CurrencyCollection::construct_from(&mut original_info)
        .expect("the original value");
    assert_eq!(
        value.coins.to_string(),
        (5 * u128::from(TOS)).to_string(),
        "the original value was not carried"
    );
}

/// Without bit 1 the bounce carries the body's bits and drops its references,
/// so the recovery record would arrive headless. This is what section 15.3's
/// "not a legacy or truncated body" has to exclude, and it is a real form this
/// executor produces, not a hypothetical one.
#[test]
fn a_bounce_without_the_full_body_flag_drops_the_original_references() {
    let (_, _, msg, _) = round_trip(1);
    let mut body = msg.body().expect("the bounce has no body").clone();
    assert_eq!(body.get_next_u32().expect("tag"), 0xffff_fffe, "not the new bounce body tag");
    let original = body.checked_drain_reference().expect("original_body");
    let carried = chain_block::SliceData::load_cell(original).expect("original body");
    assert_eq!(
        carried.remaining_references(),
        0,
        "the bits-only bounce carried a reference after all"
    );
}

/// `addr_std$10 anycast:nothing workchain_id:int8 address:bits256`, the one
/// shape `load_msg_addr` reads back and the only one this probe sends to.
fn append_std_address(builder: &mut BuilderData, addr: &MsgAddressInt) {
    builder.append_bits(2, 2).unwrap();
    builder.append_bit_zero().unwrap();
    builder.append_i8(addr.workchain_id() as i8).unwrap();
    builder.append_raw(&addr.address().get_bytestring(0), 256).unwrap();
}

fn store_coins(builder: &mut BuilderData, amount: u128) {
    let bytes = amount.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let len = bytes.len() - first;
    builder.append_bits(len, 4).unwrap();
    if len > 0 {
        builder.append_raw(&bytes[first..], len * 8).unwrap();
    }
}
