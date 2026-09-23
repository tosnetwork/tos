/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sections 15.2 and 14.2: the withdrawal payout message and the rule that the
//! fee has to cover it.
//!
//! Step 16 of section 16.2 sits after the proof, and this branch has no proof
//! that verifies, so the payout cannot yet be reached through the pool. That
//! makes this suite the evidence for it rather than a supplement to it, and it
//! is written accordingly: the message is not merely built and inspected, it is
//! sent, and the fee the contract computed is compared against the fee the
//! action phase actually charged.

use chain_block::{
    BuilderData, Cell, CommonMsgInfo, Deserializable, IBitstring, MsgAddressInt, Serializable,
    SliceData, StateInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;
use tos_vm::stack::integer::IntegerData;

mod shielded_pool_library;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
/// Section 3: the canonical outer payload is exactly this many bytes.
const PAYLOAD_BYTES: usize = 1233;

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

/// The 1233-byte canonical payload as a chain of cells: 127 bytes each until
/// the last, which carries what is left.
fn byte_chain(bytes: &[u8]) -> Cell {
    let mut chunks: Vec<&[u8]> = bytes.chunks(127).collect();
    let mut cell = Cell::default();
    while let Some(chunk) = chunks.pop() {
        let mut builder = BuilderData::new();
        builder.append_raw(chunk, chunk.len() * 8).expect("chunk");
        if cell != Cell::default() {
            builder.checked_append_reference(cell).expect("chain");
        }
        cell = builder.into_cell().expect("a chain cell");
    }
    cell
}

fn payload(seed: u8) -> Vec<u8> {
    (0..PAYLOAD_BYTES as u32).map(|i| (i as u8) ^ seed).collect()
}

/// `addr_std$10 anycast:nothing workchain_id:int8 address:bits256`.
fn std_address(account: &Field) -> SliceData {
    let mut builder = BuilderData::new();
    builder.append_bits(2, 2).unwrap();
    builder.append_bit_zero().unwrap();
    builder.append_i8(0).unwrap();
    builder.append_raw(account, 256).unwrap();
    SliceData::load_builder(builder).expect("an address slice")
}

fn addr_none() -> SliceData {
    let mut builder = BuilderData::new();
    builder.append_bits(0, 2).unwrap();
    SliceData::load_builder(builder).expect("addr_none")
}

const PROBE: &str = r#"
cell p_record(int digest, int template_hash, int recipient_hash, int owner, cell data)
    method_id {
  return payout_record(digest, template_hash, recipient_hash, owner, data);
}
cell p_body(int digest, cell record) method_id {
  return payout_body(digest, record);
}
cell p_message(slice recipient, int amount, cell body) method_id {
  return payout_message(recipient, amount, body);
}
int p_forward_fee(cell body) method_id {
  return payout_forward_fee(body);
}
int p_solvent(int fee, int config_fee, cell body) method_id {
  payout_require_solvent(fee, config_fee, body);
  return 1;
}
int p_new_liability(int liability, int amount, int fee) method_id {
  return payout_new_liability(liability, amount, fee);
}
int p_query_id(int digest) method_id { return payout_query_id(digest); }
;; What a whole bounded recovery costs to run, so the suite can require the
;; solvency boundary to be the sum rather than merely large enough.
int p_bounce_compute_fee(int ceiling) method_id { return get_compute_fee(0, ceiling); }

;; The payout body's size, as `payout_forward_fee` measures it. A forward fee
;; can be reproduced by more than one (bits, cells) pair, so deriving what the
;; fee would be under a different ConfigParam 25 from the fee alone is a guess
;; between them. This is the measurement that makes it arithmetic.
(int, int) p_body_size(cell body) method_id {
  (int cells, int bits, _) = compute_data_size(body, 1024);
  return (cells, bits);
}

;; `get_forward_fee` at prices the caller names rather than the chain's, so a
;; deployment's fee can be judged against a price the chain is not charging
;; today -- including one it charged yesterday.
int p_forward_fee_at(int lump, int per_bit, int per_cell, int bits, int cells) method_id {
  return lump + muldivc(per_bit * bits + per_cell * cells, 1, 65536);
}

;; Sends the payout for real, so the fee the action phase charges can be read
;; back and compared against the one the contract computed. The body names the
;; recipient and the amount; everything else the library builds.
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
  int digest = in_msg_body~load_uint(256);
  cell data = in_msg_body~load_ref();
  cell record = payout_record(digest, 0, 0, 0, data);
  cell body = payout_body(digest, record);
  send_raw_message(payout_message(recipient, amount, body), 17);
}
() recv_external(slice in_msg) impure { }
"#;

struct Probe {
    bc: Blockchain,
    addr: MsgAddressInt,
    payer: tos_sandbox::Treasury,
}

impl Probe {
    fn deploy() -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
            .expect("blockchain at version 17");
        bc.set_workchain(0);
        let payer = bc.treasury("deployer", 100_000 * TOS).expect("treasury");
        let library = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont/shielded");
        let probe_path = std::env::temp_dir().join("tos_shielded_payout_probe.fc");
        std::fs::write(&probe_path, PROBE).expect("write probe");
        let code = compile_func_with_stdlib(&[format!("{library}/payout.fc").into(), probe_path])
            .expect("compile the shielded library (needs build/crypto/func)");
        let si = StateInit::with_code_and_data(code, Cell::default());
        let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let addr = MsgAddressInt::with_params(0, hash).unwrap();
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 1_000 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )
        .expect("deploy")
        .expect_success();
        Self { bc, addr, payer }
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

    fn int(&self, method: &str, args: Vec<StackItem>) -> i128 {
        let stack = self.call(method, args).unwrap_or_else(|code| panic!("{method} exited {code}"));
        stack
            .last()
            .expect("a result")
            .as_integer()
            .expect("an integer")
            .to_string()
            .parse()
            .expect("a number")
    }
}

fn record_of(probe: &Probe, digest: &Field, data: &Cell) -> Cell {
    probe.cell(
        "p_record",
        vec![
            int(digest),
            int(&small(0xaaa)),
            int(&small(0xbbb)),
            int(&small(0xccc)),
            StackItem::cell(data.clone()),
        ],
    )
}

/// Section 15.2 fixes where the record splits: three field elements and a
/// reference in the root, one field element and the payload in the tail. It is
/// split exactly there because four field elements are 1024 bits and a cell
/// holds 1023.
#[test]
fn the_record_has_the_shape_section_15_2_fixes() {
    let probe = Probe::deploy();
    let data = byte_chain(&payload(3));
    let digest = small(0x1234_5678);
    let record = record_of(&probe, &digest, &data);

    let mut root = SliceData::load_cell(record).expect("the record root");
    assert_eq!(root.remaining_bits(), 768, "the record root is not three field elements");
    assert_eq!(root.remaining_references(), 1, "the record root does not carry exactly one tail");
    assert_eq!(root.get_next_bits(256).expect("digest"), digest.to_vec());
    assert_eq!(root.get_next_bits(256).expect("template"), small(0xaaa).to_vec());
    assert_eq!(root.get_next_bits(256).expect("recipient"), small(0xbbb).to_vec());

    let mut tail =
        SliceData::load_cell(root.checked_drain_reference().expect("tail")).expect("the tail");
    assert_eq!(tail.remaining_bits(), 256, "the tail is not one field element");
    assert_eq!(tail.remaining_references(), 1, "the tail does not carry exactly one payload");
    assert_eq!(tail.get_next_bits(256).expect("owner"), small(0xccc).to_vec());
    assert_eq!(
        tail.checked_drain_reference().expect("payload"),
        data,
        "the tail carries a payload the caller did not give it"
    );
}

/// The reply is tied to its intent by the low 64 bits of the digest, which is
/// what section 15.3 step 4 recomputes rather than trusts.
#[test]
fn the_query_id_is_the_low_half_of_the_intent_digest() {
    let probe = Probe::deploy();
    // A digest whose high bits are not zero, so taking the whole thing instead
    // of the low half would give a different answer.
    let mut digest = [0x77u8; 32];
    digest[24..].copy_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(
        probe.int("p_query_id", vec![int(&digest)]),
        0x0102_0304_0506_0708,
        "the query id is not the low 64 bits of the digest"
    );

    let body = probe.cell("p_body", vec![int(&digest), StackItem::cell(Cell::default())]);
    let mut slice = SliceData::load_cell(body).expect("the body");
    assert_eq!(slice.get_next_u32().expect("op"), 0, "the outbound operation is not zero");
    assert_eq!(
        slice.get_next_u64().expect("query id"),
        0x0102_0304_0506_0708,
        "the body's query id is not the one the record is tied to"
    );
    assert_eq!(slice.remaining_bits(), 0, "trailing bits in the outbound body");
    assert_eq!(slice.remaining_references(), 1, "the body does not carry exactly the record");
}

/// The message is bouncable and asks for the rich bounce with the full
/// original body. Without those two bits the recovery record would arrive
/// truncated or not at all, and section 16.3 would have nothing to work from.
#[test]
fn the_message_is_bouncable_and_asks_for_the_full_original_body() {
    let probe = Probe::deploy();
    let data = byte_chain(&payload(5));
    let digest = small(0x99);
    let record = record_of(&probe, &digest, &data);
    let body = probe.cell("p_body", vec![int(&digest), StackItem::cell(record)]);
    let recipient = small(0x4242);
    let message = probe.cell(
        "p_message",
        vec![
            StackItem::Slice(std_address(&recipient)),
            StackItem::int(IntegerData::from_u32(7_000_000)),
            StackItem::cell(body),
        ],
    );

    let mut slice = SliceData::load_cell(message).expect("the message");
    assert_eq!(slice.get_next_bit().expect("tag"), false, "not an internal message");
    assert_eq!(slice.get_next_bit().expect("ihr"), true, "instant hypercube routing is not off");
    assert_eq!(slice.get_next_bit().expect("bounce"), true, "the payout is not bouncable");
    assert_eq!(slice.get_next_bit().expect("bounced"), false, "the payout claims to be a bounce");
    // src is addr_none in a message a contract builds; the system fills it in.
    assert_eq!(slice.get_next_bits(2).expect("src"), vec![0]);
    assert_eq!(
        slice.get_next_bits(3 + 8 + 256).expect("dest"),
        std_address(&recipient).get_bytestring(0),
        "the payout is addressed to somebody else"
    );
    let value = chain_block::Coins::construct_from(&mut slice).expect("value");
    assert_eq!(value.as_u128(), 7_000_000, "the payout carries a different amount");
    assert_eq!(slice.get_next_bit().expect("extra currencies"), false);
    let flags = chain_block::Coins::construct_from(&mut slice).expect("extra flags");
    assert_eq!(
        flags.as_u128(),
        3,
        "the payout does not ask for the new bounce format with the full original body"
    );
}

/// A payout with nowhere to go is not a payout.
#[test]
fn a_payout_to_nobody_is_refused() {
    let probe = Probe::deploy();
    assert_eq!(
        probe.call(
            "p_message",
            vec![
                StackItem::Slice(addr_none()),
                StackItem::int(IntegerData::from_u32(1)),
                StackItem::cell(Cell::default()),
            ],
        ),
        Err(245),
        "a payout to addr_none was built"
    );
}

/// Section 14.2. The fee is fixed at deployment and the chain's prices are
/// not, so the check is on the deployment: if the configured fee has stopped
/// covering the message, withdrawals fail closed.
///
/// **The floor is the forward fee and nothing else**, and this test exists to
/// say so. It used to include a whole bounded recovery's compute, and that
/// term was the dangerous one: an immutable fee had to stay ahead of a
/// *compute* price the chain can govern upwards, so a large enough rise would
/// brick every withdrawal permanently. Section 15.4 charges the recovery to
/// the money being recovered instead, at the prices live when the bounce
/// arrives, and what is left here prices bytes rather than work.
#[test]
fn the_fee_must_cover_the_message_and_not_the_recovery() {
    let probe = Probe::deploy();
    let data = byte_chain(&payload(7));
    let digest = small(0x31337);
    let record = record_of(&probe, &digest, &data);
    let body = probe.cell("p_body", vec![int(&digest), StackItem::cell(record)]);
    // The frozen bounce ceiling, read out of the contract rather than copied:
    // it is no longer part of the floor, and it is priced below only so the
    // test can say how much was taken out of it. A copy here would go stale
    // the next time the ceiling is re-derived, and say nothing when it did.
    let ceiling = u32::try_from(shielded_pool_library::gas_ceiling("bounce_gas_ceiling"))
        .expect("the bounce ceiling fits a uint32");

    let forward = probe.int("p_forward_fee", vec![StackItem::cell(body.clone())]);
    assert!(forward > 0, "the forward fee of a real message is zero");
    eprintln!("payout forward fee: {forward}");

    let solvent = |fee: i128, config_fee: i128| {
        probe.call(
            "p_solvent",
            vec![
                StackItem::int(IntegerData::from_str_radix(&fee.to_string(), 10).unwrap()),
                StackItem::int(IntegerData::from_str_radix(&config_fee.to_string(), 10).unwrap()),
                StackItem::cell(body.clone()),
            ],
        )
    };

    // The fee on the wire is not the fee the configuration fixed. The pair is
    // synthetic and only has to differ; what it checks is that the contract
    // compares them rather than trusting the wire.
    assert_eq!(solvent(20_000_000, 20_000_001), Err(242), "a fee the config did not fix passed");

    // The smallest fee that covers the message, found rather than assumed: the
    // fee one nanotos below it must fail, which is what makes it the boundary
    // and not just a number that happens to work.
    let (mut low, mut high) = (0i128, 10_000_000_000i128);
    assert!(solvent(high, high).is_ok(), "no fee in range was ever enough");
    while low + 1 < high {
        let mid = low + (high - low) / 2;
        if solvent(mid, mid).is_ok() {
            high = mid;
        } else {
            low = mid;
        }
    }
    let enough = high;
    assert_eq!(solvent(low, low), Err(243), "the fee one below the boundary was accepted");

    // The boundary is the forward fee, exactly. A rule that added a term back
    // would still have a boundary, and a test that only required the boundary
    // to be positive would not notice.
    let recovery =
        probe.int("p_bounce_compute_fee", vec![StackItem::int(IntegerData::from_u32(ceiling))]);
    assert_eq!(
        enough, forward,
        "the boundary is {enough} and the message's forward fee is {forward}; something other \
         than forwarding is in the floor"
    );

    // And the term that used to be there is real and large, so the equality
    // above is a statement about the rule rather than about a quantity that
    // happens to be near zero. This is the whole of the change: at a gas price
    // {recovery} times dearer the old floor would have overtaken an immutable
    // fee, and this one would not have moved at all.
    assert!(
        recovery > 0,
        "a bounded recovery's compute costs nothing, so dropping it from the floor proves \
         nothing"
    );
    assert!(
        enough < forward + recovery,
        "the floor is still the old sum: {enough} against {forward} + {recovery}"
    );
    eprintln!(
        "the smallest solvent fee is {enough}, the forward fee exactly; the {recovery} a \
         bounded recovery at a {ceiling} gas ceiling would cost is charged to the bounce, \
         not pre-paid by every withdrawal"
    );
}

/// How far the configured fee is from the cliff, measured rather than argued.
///
/// `config.withdrawal_fee` is written into the genesis store and can never
/// change, while the check that enforces it reads the chain's **live**
/// forwarding prices. So if ConfigParam 25 is ever governed past what the fee
/// affords, every withdrawal fails at exit 243 permanently while deposits and
/// transfers carry on. Money goes in and cannot come out, and there is no
/// admin to fix it.
///
/// The fee is therefore not sized against today's price. It is sized against
/// the highest price the chain could plausibly reach, and the only
/// non-hypothetical reference for that is a price **this chain itself
/// charged**: until `3c7f4036d` its three forwarding prices were each exactly
/// six times today's.
///
/// Both halves of that are measured here rather than inferred. A forward fee
/// can be reproduced by more than one `(bits, cells)` pair, so working out
/// what the same message would cost under different prices from the fee alone
/// is a guess between them; `p_body_size` removes the guess.
#[test]
fn the_configured_fee_clears_the_price_this_chain_used_to_charge() {
    let probe = Probe::deploy();
    let data = byte_chain(&payload(7));
    let digest = small(0x31337);
    let record = record_of(&probe, &digest, &data);
    let body = probe.cell("p_body", vec![int(&digest), StackItem::cell(record)]);

    // Today's ConfigParam 25, and the values this chain charged before the
    // alignment. Read from `crypto/smartcont/gen-zerostate.fif`; the ratio is
    // asserted rather than trusted.
    const TODAY: (i128, i128, i128) = (66_667, 4_369_067, 436_906_667);
    const BEFORE_ALIGNMENT: (i128, i128, i128) = (400_000, 26_214_400, 2_621_440_000);
    // The zerostate says the old prices "were each exactly six times these".
    // Each is short by two: the alignment divided by six and rounded **up**,
    // and 400,000 / 6 is 66,666.67. The relationship that is exact is the one
    // the alignment performed, so that is the one asserted.
    for (before, today) in [
        (BEFORE_ALIGNMENT.0, TODAY.0),
        (BEFORE_ALIGNMENT.1, TODAY.1),
        (BEFORE_ALIGNMENT.2, TODAY.2),
    ] {
        assert_eq!(
            today,
            (before + 5) / 6,
            "today's price is not the pre-alignment one divided by six, rounded up"
        );
    }

    let size = probe.call("p_body_size", vec![StackItem::cell(body.clone())])
        .expect("the body's size");
    assert_eq!(size.len(), 2, "p_body_size returned {} values", size.len());
    let number = |item: &StackItem| -> i128 {
        item.as_integer().expect("an integer").to_string().parse().expect("a number")
    };
    let cells = number(&size[0]);
    let bits = number(&size[1]);

    let at = |(lump, bit, cell): (i128, i128, i128)| {
        probe.int(
            "p_forward_fee_at",
            vec![
                StackItem::int(IntegerData::from_str_radix(&lump.to_string(), 10).unwrap()),
                StackItem::int(IntegerData::from_str_radix(&bit.to_string(), 10).unwrap()),
                StackItem::int(IntegerData::from_str_radix(&cell.to_string(), 10).unwrap()),
                StackItem::int(IntegerData::from_str_radix(&bits.to_string(), 10).unwrap()),
                StackItem::int(IntegerData::from_str_radix(&cells.to_string(), 10).unwrap()),
            ],
        )
    };

    // The reconstruction has to reproduce what the chain actually charges, or
    // the figure for the other price is arithmetic about the wrong message.
    let live = probe.int("p_forward_fee", vec![StackItem::cell(body.clone())]);
    assert_eq!(
        at(TODAY),
        live,
        "the reconstruction gives {} where the chain charges {live}",
        at(TODAY)
    );

    let restoration = at(BEFORE_ALIGNMENT);
    let configured = shielded_pool_library::configured_withdrawal_fee();
    eprintln!(
        "the payout body is {bits} bits in {cells} cells; it forwards for {live} today and \
         would for {restoration} at the prices this chain charged before {}",
        "3c7f4036d"
    );
    eprintln!(
        "the configured fee {configured} is {:.1}x today's floor and {:.2}x the floor at \
         those prices",
        configured as f64 / live as f64,
        configured as f64 / restoration as f64
    );

    // The property that matters: restoring the price the chain itself charged
    // must not brick withdrawals. Everything above that is margin.
    assert!(
        configured > restoration,
        "the configured fee {configured} does not clear the {restoration} floor at the \
         forwarding prices this chain charged until {}, so restoring them would brick every \
         withdrawal permanently",
        "3c7f4036d"
    );
}

/// The arithmetic of step 16, including the case that would let a pool pay out
/// more than it owes.
#[test]
fn a_payout_never_discharges_more_liability_than_there_is() {
    let probe = Probe::deploy();
    let liability = |l: u32, amount: u32, fee: u32| {
        probe.call(
            "p_new_liability",
            vec![
                StackItem::int(IntegerData::from_u32(l)),
                StackItem::int(IntegerData::from_u32(amount)),
                StackItem::int(IntegerData::from_u32(fee)),
            ],
        )
    };

    assert_eq!(
        probe.int(
            "p_new_liability",
            vec![
                StackItem::int(IntegerData::from_u32(1_000_000)),
                StackItem::int(IntegerData::from_u32(700_000)),
                StackItem::int(IntegerData::from_u32(50_000)),
            ],
        ),
        250_000,
        "the fee leaves with the payout, and both come out of liability"
    );

    // Exactly enough is enough.
    assert_eq!(liability(750_000, 700_000, 50_000).map(|_| ()), Ok(()));
    // One short is not.
    assert_eq!(
        liability(749_999, 700_000, 50_000),
        Err(244),
        "a payout discharged liability the pool did not have"
    );
    assert_eq!(liability(0, 1, 0), Err(244), "a pool owing nothing paid something out");
}

/// The one that cannot be argued with: send the message and read back what the
/// action phase charged to forward it. A fee the contract computes and never
/// compares against the real one is a number, not a check.
#[test]
fn the_computed_forward_fee_is_the_fee_the_chain_charges() {
    let mut probe = Probe::deploy();
    let data = byte_chain(&payload(11));
    let digest = small(0xfeed_face);
    let record = record_of(&probe, &digest, &data);
    let body = probe.cell("p_body", vec![int(&digest), StackItem::cell(record)]);
    let computed = probe.int("p_forward_fee", vec![StackItem::cell(body)]);

    let recipient = small(0x1357);
    let mut instruction = BuilderData::new();
    let address = std_address(&recipient);
    instruction
        .append_raw(&address.get_bytestring(0), address.remaining_bits())
        .expect("recipient");
    store_coins(&mut instruction, 9 * u128::from(TOS));
    instruction.append_raw(&digest, 256).unwrap();
    instruction.checked_append_reference(data).expect("payload");

    let payer = probe.payer.address();
    let result = probe
        .bc
        .send_message(
            MessageBuilder::internal(payer, &probe.addr, 50 * TOS)
                .bounce(true)
                .body(instruction.into_cell().unwrap())
                .build(),
        )
        .expect("send");

    // What the pool pays is the action phase's own total, not the number the
    // message carries onward: a message keeps only the part that has not been
    // collected yet, and section 14.2's fee has to cover what the pool pays.
    let mut charged = None;
    let mut carried = None;
    for (_, tx) in &result.transactions {
        if let Ok(chain_block::TransactionDescr::Ordinary(d)) = tx.read_description() {
            if let Some(action) = d.action.as_ref() {
                if action.total_fwd_fees().as_u128() > 0 {
                    charged = Some(action.total_fwd_fees().as_u128());
                }
            }
        }
        let _ = tx.iterate_out_msgs(|msg| {
            if let CommonMsgInfo::IntMsgInfo(info) = msg.header() {
                if !info.bounced {
                    carried = Some(info.fwd_fee.as_u128());
                }
            }
            Ok(true)
        });
    }
    let charged = charged.expect("the payout was never sent");
    let carried = carried.expect("the payout carried no forward fee");
    eprintln!("forward fee: computed {computed}, charged {charged}, carried onward {carried}");
    assert_eq!(
        charged, computed as u128,
        "the contract's forward fee is not the one the chain charged the pool"
    );
    assert!(
        carried < charged,
        "the message carried {carried} of a {charged} fee; nothing was collected at this hop"
    );
}

/// Coins are a VarUInteger 16: four bits of byte length, then the bytes.
fn store_coins(builder: &mut BuilderData, amount: u128) {
    let bytes = amount.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let length = bytes.len() - first;
    builder.append_bits(length, 4).expect("coin length");
    if length > 0 {
        builder.append_raw(&bytes[first..], length * 8).expect("coin bytes");
    }
}
