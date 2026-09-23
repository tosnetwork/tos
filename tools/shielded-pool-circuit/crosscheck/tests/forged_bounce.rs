/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 19 gate 16: an ordinary message cannot become the bounce path.
//!
//! The recovery handler is the one place the pool mints a note without a
//! proof. What it trusts instead is the bounce itself: the record travelled
//! out with the payout, and the address it names is checked against the
//! address the message came from -- which a sender cannot choose.
//!
//! That leaves exactly one attacker the authentication cannot stop: the
//! address the payout was actually sent to. The record names them, so check 5
//! passes for them and for nobody else. What stops that attacker is not in
//! this contract at all. It is one line in the action phase, which clears the
//! bounced flag on every message a contract proposes, so no contract can send
//! a message that arrives looking like a bounce.
//!
//! That line is `int_header.bounced = false` in
//! `tosctl/src/executor/src/transaction_executor.rs`, and `info.bounced =
//! false` in `crypto/block/transaction.cpp`. A dependency on somebody else's
//! invariant is the kind that goes unnoticed when it moves, so this test
//! states it, exercises it, and -- because a negative test that passes for
//! the wrong reason proves nothing -- shows the same record minting when the
//! flag is set by other means.

use chain_block::{BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::wire;
use shielded_pool_circuit_crosscheck::pool::{be, Pool, DENOMINATION};
use shielded_pool_circuit_crosscheck::wire::byte_chain;
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;

/// What the pool returns for a message whose first 32 bits are none of its
/// three operations.
const NOT_AN_OPERATION: i32 = 201;

/// Section 15.3's envelope tag.
const ENVELOPE: u32 = 0xffff_fffe;

/// A contract that proposes an outbound message with the bounced bit set.
///
/// The four header bits are tag, ihr_disabled, bounce, bounced, so 0b0101 is
/// a message that claims to be a bounce and asks not to be bounced itself.
/// Nothing here is unusual except that one bit: this is the ordinary
/// `send_raw_message` any contract can call.
const FORGER: &str = r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
  if (in_msg_body.slice_empty?()) { return (); }
  slice target = in_msg_body~load_msg_addr();
  int amount = in_msg_body~load_coins();
  cell payload = in_msg_body~load_ref();
  cell message = begin_cell()
    .store_uint(5, 4)        ;; tag 0, ihr_disabled 1, bounce 0, bounced 1
    .store_uint(0, 2)        ;; src: addr_none, which the system replaces
    .store_slice(target)
    .store_coins(amount)
    .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1)
    .store_uint(1, 1)        ;; the body travels in a reference
    .store_ref(payload)
    .end_cell();
  send_raw_message(message, 0);
}
() recv_external(slice in_msg) impure { }
"#;

fn cell(builder: BuilderData) -> Cell {
    builder.into_cell().expect("a cell")
}

fn account_of(addr: &MsgAddressInt) -> [u8; 32] {
    let bytes = addr.address().get_bytestring(0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn deploy_forger(bc: &mut Blockchain) -> MsgAddressInt {
    // A directory of this call's own. These probes are written from several tests at
    // once, and a shared path is truncated under a concurrent `func` reading it.
    let probe_dir = tempfile::tempdir().expect("a directory for the probe");
    let path = probe_dir.path().join("tos_shielded_bounce_forger.fc");
    std::fs::write(&path, FORGER).expect("write the forger");
    let stdlib = shielded_pool_circuit_crosscheck::stdlib_path();
    let code = compile_func(&[stdlib, path]).expect("compile the forger");
    let si = StateInit::with_code_and_data(code, Cell::default());
    let hash = si.write_to_new_cell().and_then(|b| b.into_cell()).expect("state init").hash(0);
    let addr = MsgAddressInt::with_params(0, hash).expect("address");
    let payer = bc.treasury("forger_funder", 1_000 * TOS).expect("treasury");
    bc.send_message(
        MessageBuilder::internal(payer.address(), &addr, 50 * TOS)
            .bounce(false)
            .state_init(si)
            .body(Cell::default())
            .build(),
    )
    .expect("deploy")
    .expect_success();
    addr
}

/// Section 15.2's payout body, wrapped in section 15.3's envelope.
///
/// Every field is chosen so the record authenticates when it arrives from
/// `claimant`: the query id is the digest's low 64 bits, the recipient hash is
/// that address, and the template hash is the one the payload produces. If
/// the pool ever reads this as a bounce it will mint.
fn authentic_looking_envelope(claimant: &MsgAddressInt) -> (Cell, Fr) {
    let owner_commitment = Fr::from(0x5eed_1234u64);
    let recovery_payload: Vec<u8> = (0..wire::OUTPUT_DATA_BYTES as u32)
        .map(|index| (index as u8) ^ 0x3c)
        .collect();
    let template_hash = wire::recovery_template_hash(
        owner_commitment,
        wire::output_data_hash(&recovery_payload),
    );
    let recipient_hash = wire::public_recipient_hash(&account_of(claimant));

    // The digest is arbitrary: nothing on this path proves anything about it.
    // What the contract checks is that the query id repeats its low 64 bits.
    let intent_digest = Fr::from(0x0123_4567_89ab_cdefu64);
    let digest_bytes = be(intent_digest);
    let query_id = u64::from_be_bytes(digest_bytes[24..].try_into().expect("eight bytes"));

    let mut tail = BuilderData::new();
    tail.append_raw(&be(owner_commitment), 256).expect("owner");
    tail.checked_append_reference(byte_chain(&recovery_payload).expect("payload")).expect("data");

    let mut record = BuilderData::new();
    record.append_raw(&digest_bytes, 256).expect("digest");
    record.append_raw(&be(template_hash), 256).expect("template");
    record.append_raw(&be(recipient_hash), 256).expect("recipient");
    record.checked_append_reference(cell(tail)).expect("tail");

    let mut original = BuilderData::new();
    original.append_u32(0).expect("the payout's op");
    original.append_u64(query_id).expect("query id");
    original.checked_append_reference(cell(record)).expect("record");

    let mut envelope = BuilderData::new();
    envelope.append_u32(ENVELOPE).expect("the envelope tag");
    envelope.checked_append_reference(cell(original)).expect("original body");
    (cell(envelope), owner_commitment)
}

/// A pool holding one deposit, so a mint would be visible in the liability.
fn pool_with_a_deposit() -> Pool {
    let mut pool = Pool::deploy().expect("deploy the pool");
    let payload: Vec<u8> =
        (0..wire::OUTPUT_DATA_BYTES as u32).map(|index| (index as u8) ^ 0x11).collect();
    pool.send(
        DENOMINATION + COMPUTE_FEE,
        Pool::deposit_body(DENOMINATION, Fr::from(0x1111u64), byte_chain(&payload).expect("chain"))
            .expect("deposit body"),
    )
    .expect("deposit")
    .expect_success();
    pool
}

fn liability(pool: &Pool) -> u128 {
    pool.get("native_liability").expect("liability").parse().expect("a number")
}

#[test]
fn a_contract_cannot_send_the_pool_a_message_that_arrives_bounced() {
    let mut pool = pool_with_a_deposit();
    let forger = deploy_forger(&mut pool.bc);
    let (envelope, _) = authentic_looking_envelope(&forger);

    let before = liability(&pool);
    let root_before = pool.get("commitment_root").expect("root");

    // Ask the forger to send it. The value is far above the dust threshold a
    // recovery needs, so nothing here fails for want of money.
    let mut instruction = BuilderData::new();
    let mut target = BuilderData::new();
    target.append_bits(2, 2).expect("addr_std");
    target.append_bit_zero().expect("no anycast");
    target.append_i8(0).expect("workchain");
    target.append_raw(&pool.account().expect("the pool account"), 256).expect("account");
    instruction.append_builder(&target).expect("target");
    shielded_pool_circuit_crosscheck::pool::store_coins(&mut instruction, u128::from(2 * TOS))
        .expect("amount");
    instruction.checked_append_reference(envelope.clone()).expect("payload");

    let payer = pool.bc.treasury("forger_relay", 1_000 * TOS).expect("treasury");
    let result = pool
        .bc
        .send_message(
            MessageBuilder::internal(payer.address(), &forger, 20 * TOS)
                .bounce(false)
                .body(cell(instruction))
                .build(),
        )
        .expect("ask the forger to send");

    // What the pool actually received. This is the assertion the whole gate
    // rests on: the bit the forger set is not the bit that arrived.
    let mut seen = None;
    for (addr, tx) in &result.transactions {
        if addr.to_string() != pool.addr.to_string() {
            continue;
        }
        let msg = tx.read_in_msg().expect("in msg").expect("an inbound message");
        if let chain_block::CommonMsgInfo::IntMsgInfo(info) = msg.header() {
            seen = Some(info.bounced);
        }
    }
    let bounced = seen.expect("the forger's message never reached the pool");
    assert!(
        !bounced,
        "the forged message arrived at the pool with the bounced bit still set, so the action \
         phase no longer clears it and the recovery path is reachable by any contract"
    );

    // And so the pool read it as an ordinary message, whose first 32 bits are
    // the envelope tag and therefore not one of its three operations.
    let exit = result
        .transactions
        .iter()
        .find(|(addr, _)| addr.to_string() == pool.addr.to_string())
        .and_then(|(_, tx)| match tx.read_description().ok()? {
            chain_block::TransactionDescr::Ordinary(d) => match d.compute_ph {
                chain_block::TrComputePhase::Vm(vm) => Some(vm.exit_code),
                chain_block::TrComputePhase::Skipped(_) => None,
            },
            _ => None,
        })
        .expect("the pool's transaction");
    assert_eq!(
        exit, NOT_AN_OPERATION,
        "the pool did something other than refuse the forged message as an unknown operation"
    );

    assert_eq!(liability(&pool), before, "the forged bounce minted a note");
    assert_eq!(
        pool.get("commitment_root").expect("root"),
        root_before,
        "the forged bounce moved the commitment tree"
    );
}

/// The same record, delivered with the bit set by other means, does mint.
///
/// Without this the test above would pass just as well if the record were
/// malformed, if the value were too small, or if the pool refused every
/// bounce for some unrelated reason. It is not evidence for the gate -- the
/// gate says so itself -- it is what makes the test above evidence.
#[test]
fn the_same_record_mints_when_the_bit_is_not_the_senders_to_set() {
    let mut pool = pool_with_a_deposit();
    let forger = deploy_forger(&mut pool.bc);
    let (envelope, _) = authentic_looking_envelope(&forger);

    let before = liability(&pool);
    let (exit, _) = pool
        .deliver_synthetic_bounce(&forger, envelope, 2 * TOS)
        .expect("deliver the synthetic bounce");
    assert_eq!(
        exit, 0,
        "the record the forger could not deliver would not have been accepted anyway (exit \
         {exit}), so the test above shows nothing about who may set the bounced bit"
    );
    assert!(
        liability(&pool) > before,
        "the synthetic bounce was accepted but minted nothing"
    );
}

/// And a record naming somebody else is refused even then, which is the half
/// of the authentication that does live in this contract.
#[test]
fn a_record_naming_another_address_is_refused_from_any_sender() {
    let mut pool = pool_with_a_deposit();
    let forger = deploy_forger(&mut pool.bc);
    let elsewhere = MsgAddressInt::with_params(
        0,
        chain_block::SliceData::from_raw(vec![0x77u8; 32], 256),
    )
    .expect("another address");
    let (envelope, _) = authentic_looking_envelope(&elsewhere);

    let before = liability(&pool);
    let (exit, _) = pool
        .deliver_synthetic_bounce(&forger, envelope, 2 * TOS)
        .expect("deliver the synthetic bounce");
    assert_eq!(exit, 267, "a record was recovered from an address it does not name");
    assert_eq!(liability(&pool), before, "a refused recovery minted anyway");
}
