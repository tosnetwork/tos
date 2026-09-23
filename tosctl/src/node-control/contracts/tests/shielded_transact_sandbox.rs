/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The transact message and its public inputs: sections 12.2, 13.3 and 10.
//!
//! Eight of the eighteen public inputs are not on the wire. The three payload
//! hashes, the two public-key hashes, the recipient hash, the execution domain
//! and the recovery template hash are computed by the contract from the bytes
//! that actually arrived, and this file's second test is the one that matters:
//! change a byte of a payload or a key and the corresponding input has to move.
//! A sender that could supply those values could make the proof commit to one
//! thing and the chain record another.
//!
//! The rest is section 19 gate 19: every shape the profile freezes, refused
//! when it is not that shape, each with its own code so a failure says which
//! rule it broke.

use sha2::{Digest, Sha256};

use chain_block::poseidon2::permute;
use chain_block::poseidon2_kat::DOMAINS;
use chain_block::{BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
const PK_BYTES: usize = 1312;
const SIG_BYTES: usize = 2420;
const PAYLOAD_BYTES: usize = 1233;

type Field = [u8; 32];
const ZERO: Field = [0u8; 32];

fn modulus() -> Field {
    from_dec("52435875175126190479447740508185965837690552500527637822603658699938581184513")
}

fn reduce(digest: [u8; 32]) -> Field {
    let m = modulus();
    let mut value = digest;
    while value[..] >= m[..] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for index in (0..32).rev() {
            let mut diff = value[index] as i16 - m[index] as i16 - borrow;
            borrow = if diff < 0 {
                diff += 256;
                1
            } else {
                0
            };
            out[index] = diff as u8;
        }
        value = out;
    }
    value
}

fn domain(label: &str) -> Field {
    DOMAINS.iter().find(|(name, _)| *name == label).expect("a domain label").1
}

fn h7(domain: Field, args: [Field; 7]) -> Field {
    let mut state = [[0u8; 32]; 8];
    state[0] = domain;
    state[1..].copy_from_slice(&args);
    permute(&state)[0]
}

fn tagged_hash(tag: &[u8], body: &[u8]) -> Field {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(body);
    reduce(hasher.finalize().into())
}

fn output_data_hash(bytes: &[u8]) -> Field {
    tagged_hash(b"TOS-SHIELDED-OUTPUT-DATA-v1", bytes)
}

fn pq_auth_key_hash(bytes: &[u8]) -> Field {
    tagged_hash(b"TOS-SHIELDED-MLDSA44-PK-v1", bytes)
}

fn recipient_hash(account: &Field) -> Field {
    tagged_hash(b"TOS-SHIELDED-RECIPIENT-v1", account)
}

fn execution_domain(global_id: i32, pool: &Field) -> Field {
    let mut body = Vec::new();
    body.extend_from_slice(&global_id.to_be_bytes());
    body.push(0);
    body.extend_from_slice(pool);
    body.extend_from_slice(&1u16.to_be_bytes());
    tagged_hash(b"TOS-SHIELDED-EXEC-v1", &body)
}

fn recovery_template_hash(owner: Field, data_hash: Field) -> Field {
    h7(domain("RECOVERY-TEMPLATE"), [owner, data_hash, ZERO, ZERO, ZERO, ZERO, ZERO])
}

// ---------------------------------------------------------------------------

fn dec(bytes: &Field) -> String {
    let mut digits = vec![0u8];
    for &byte in bytes {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            let value = (*digit as u32) * 256 + carry;
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

fn from_dec(text: &str) -> Field {
    let mut out = [0u8; 32];
    for ch in text.bytes() {
        let mut carry = (ch - b'0') as u32;
        for byte in out.iter_mut().rev() {
            let value = (*byte as u32) * 10 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        assert_eq!(carry, 0, "value does not fit in 256 bits: {text}");
    }
    out
}

fn small(value: u64) -> Field {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
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

/// A canonical byte chain: full 127-byte cells with one reference each, and a
/// non-empty tail with none.
fn byte_chain(bytes: &[u8]) -> Cell {
    let pieces: Vec<&[u8]> = bytes.chunks(127).collect();
    let mut chain: Option<Cell> = None;
    for piece in pieces.iter().rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(piece, piece.len() * 8).expect("a chunk");
        if let Some(next) = chain {
            builder.checked_append_reference(next).expect("a chain reference");
        }
        chain = Some(builder.into_cell().expect("a chain cell"));
    }
    chain.expect("a chain")
}

fn bytes_of(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 31 + seed as u32) % 251) as u8).collect()
}

/// Section 13.3: A and C in the root, B behind its only reference.
fn groth16_proof(seed: u8) -> Cell {
    let a_and_c = bytes_of(96, seed);
    let b = bytes_of(96, seed ^ 0x55);
    let mut b_cell = BuilderData::new();
    b_cell.append_raw(&b, 768).expect("B");
    let mut root = BuilderData::new();
    root.append_raw(&a_and_c, 768).expect("A and C");
    root.checked_append_reference(b_cell.into_cell().expect("B cell")).expect("B reference");
    root.into_cell().expect("a proof")
}

fn field_cell(values: &[Field]) -> Cell {
    let mut builder = BuilderData::new();
    for value in values {
        builder.append_raw(value, 256).expect("a field element");
    }
    builder.into_cell().expect("a field cell")
}

fn refs_only(cells: &[Cell]) -> Cell {
    let mut builder = BuilderData::new();
    for cell in cells {
        builder.checked_append_reference(cell.clone()).expect("a reference");
    }
    builder.into_cell().expect("a bundle")
}

/// Everything a transact message carries, so a test can change exactly one
/// thing and leave the rest alone.
#[derive(Clone)]
struct Message {
    anchor_kind: u8,
    anchor_id: u32,
    valid_until: u32,
    public_amount_out: u64,
    withdrawal_fee: u64,
    recipient: Option<Field>,
    intent_digest: Field,
    anchor_root: Field,
    nullifiers: [Field; 2],
    note_bodies: [Field; 3],
    payloads: [Vec<u8>; 3],
    public_keys: [Vec<u8>; 2],
    signatures: [Vec<u8>; 2],
    recovery_owner: Field,
    recovery_payload: Option<Vec<u8>>,
    witnesses: [Cell; 2],
}

impl Message {
    fn transfer() -> Self {
        let digest = small(0x0123_4567_89ab_cdef);
        Message {
            anchor_kind: 0,
            anchor_id: 0,
            valid_until: 1_700_000_000,
            public_amount_out: 0,
            withdrawal_fee: 0,
            recipient: None,
            intent_digest: digest,
            anchor_root: small(11),
            nullifiers: [small(21), small(22)],
            note_bodies: [small(31), small(32), small(33)],
            payloads: [
                bytes_of(PAYLOAD_BYTES, 1),
                bytes_of(PAYLOAD_BYTES, 2),
                bytes_of(PAYLOAD_BYTES, 3),
            ],
            public_keys: [bytes_of(PK_BYTES, 4), bytes_of(PK_BYTES, 5)],
            signatures: [bytes_of(SIG_BYTES, 6), bytes_of(SIG_BYTES, 7)],
            recovery_owner: ZERO,
            recovery_payload: None,
            witnesses: [byte_chain(&bytes_of(64, 8)), byte_chain(&bytes_of(64, 9))],
        }
    }

    fn withdrawal() -> Self {
        let mut message = Message::transfer();
        message.public_amount_out = 10 * TOS;
        message.withdrawal_fee = 50_000_000;
        message.recipient = Some(small(0xdead_beef));
        message.recovery_owner = small(44);
        message.recovery_payload = Some(bytes_of(PAYLOAD_BYTES, 10));
        message
    }

    fn proof_bundle(&self) -> Cell {
        let mut builder = BuilderData::new();
        builder.append_raw(&self.anchor_root, 256).unwrap();
        builder.append_raw(&self.nullifiers[0], 256).unwrap();
        builder.append_raw(&self.nullifiers[1], 256).unwrap();
        builder.checked_append_reference(field_cell(&self.note_bodies)).unwrap();
        builder.checked_append_reference(groth16_proof(12)).unwrap();
        builder.into_cell().expect("a proof bundle")
    }

    fn output_bundle(&self) -> Cell {
        let mut builder = BuilderData::new();
        builder.append_raw(&self.recovery_owner, 256).unwrap();
        for payload in &self.payloads {
            builder.checked_append_reference(byte_chain(payload)).unwrap();
        }
        let recovery = match &self.recovery_payload {
            Some(bytes) => byte_chain(bytes),
            None => Cell::default(),
        };
        builder.checked_append_reference(recovery).unwrap();
        builder.into_cell().expect("an output bundle")
    }

    fn auth_bundle(&self) -> Cell {
        refs_only(&[
            byte_chain(&self.public_keys[0]),
            byte_chain(&self.signatures[0]),
            byte_chain(&self.public_keys[1]),
            byte_chain(&self.signatures[1]),
        ])
    }

    fn body(&self) -> Cell {
        self.body_with(self.proof_bundle(), self.output_bundle(), self.auth_bundle())
    }

    fn body_with(&self, proof: Cell, output: Cell, auth: Cell) -> Cell {
        self.body_with_all(proof, output, auth, refs_only(&self.witnesses))
    }

    fn body_with_all(&self, proof: Cell, output: Cell, auth: Cell, witnesses: Cell) -> Cell {
        let mut builder = BuilderData::new();
        builder
            .append_u64(u64::from_be_bytes(self.intent_digest[24..].try_into().unwrap()))
            .unwrap();
        builder.append_u8(self.anchor_kind).unwrap();
        builder.append_u32(self.anchor_id).unwrap();
        builder.append_u32(self.valid_until).unwrap();
        store_coins(&mut builder, self.public_amount_out as u128);
        store_coins(&mut builder, self.withdrawal_fee as u128);
        match &self.recipient {
            None => {
                builder.append_bits(0, 2).unwrap();
            }
            Some(account) => {
                builder.append_bits(2, 2).unwrap();
                builder.append_bit_zero().unwrap();
                builder.append_i8(0).unwrap();
                builder.append_raw(account, 256).unwrap();
            }
        }
        builder.append_raw(&self.intent_digest, 256).unwrap();
        builder.checked_append_reference(proof).unwrap();
        builder.checked_append_reference(output).unwrap();
        builder.checked_append_reference(auth).unwrap();
        builder.checked_append_reference(witnesses).unwrap();
        builder.into_cell().expect("a transact body")
    }

    /// Section 10's eighteen, in the frozen order.
    fn expected(&self, global_id: i32, pool: &Field) -> Vec<Field> {
        vec![
            self.anchor_root,
            self.nullifiers[0],
            self.nullifiers[1],
            self.note_bodies[0],
            self.note_bodies[1],
            self.note_bodies[2],
            output_data_hash(&self.payloads[0]),
            output_data_hash(&self.payloads[1]),
            output_data_hash(&self.payloads[2]),
            pq_auth_key_hash(&self.public_keys[0]),
            pq_auth_key_hash(&self.public_keys[1]),
            small(self.public_amount_out),
            small(self.withdrawal_fee),
            match &self.recipient {
                None => ZERO,
                Some(account) => recipient_hash(account),
            },
            small(self.valid_until as u64),
            execution_domain(global_id, pool),
            match &self.recovery_payload {
                None => ZERO,
                Some(bytes) => recovery_template_hash(self.recovery_owner, output_data_hash(bytes)),
            },
            self.intent_digest,
        ]
    }
}

const PROBE: &str = r#"
int p_input(cell body_cell, int index) method_id {
  slice body = body_cell.begin_parse();
  tuple inputs = transact_public_inputs(body);
  return public_input_at(inputs, index);
}
int p_count(cell body_cell) method_id {
  slice body = body_cell.begin_parse();
  tuple inputs = transact_public_inputs(body);
  return public_input_length(inputs);
}
int p_global_id() method_id { return global_id(); }
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

struct Probe {
    bc: Blockchain,
    addr: MsgAddressInt,
    account: Field,
}

impl Probe {
    fn deploy() -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
            .expect("blockchain at version 17");
        let payer = bc.treasury("deployer", 1_000 * TOS).expect("treasury");
        let library = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont/shielded");
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir().expect("a directory for the probe");
        let probe_path = probe_dir.path().join("tos_shielded_transact_probe.fc");
        std::fs::write(&probe_path, PROBE).expect("write probe");
        let code = compile_func_with_stdlib(&[
            std::path::PathBuf::from(format!("{library}/domains.fc")),
            std::path::PathBuf::from(format!("{library}/empty-roots.fc")),
            std::path::PathBuf::from(format!("{library}/notes.fc")),
            std::path::PathBuf::from(format!("{library}/auth.fc")),
            std::path::PathBuf::from(format!("{library}/payload.fc")),
            std::path::PathBuf::from(format!("{library}/domain.fc")),
            std::path::PathBuf::from(format!("{library}/transact.fc")),
            probe_path,
        ])
        .expect("compile the shielded library (needs build/crypto/func)");
        let mut data = BuilderData::new();
        data.append_u32(0).unwrap();
        let si = StateInit::with_code_and_data(code, data.into_cell().unwrap());
        let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let mut account = [0u8; 32];
        account.copy_from_slice(hash.as_slice());
        let addr = MsgAddressInt::with_params(0, hash).unwrap();
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 2 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )
        .expect("deploy")
        .expect_success();
        Self { bc, addr, account }
    }

    fn global_id(&self) -> i32 {
        let result = self.bc.run_get_method(&self.addr, "p_global_id", vec![]).expect("run");
        result.stack.last().unwrap().as_integer().unwrap().to_string().parse().expect("i32")
    }

    fn input(&self, body: &Cell, index: usize) -> Result<Field, i32> {
        let result = self
            .bc
            .run_get_method(
                &self.addr,
                "p_input",
                vec![StackItem::Cell(body.clone()), StackItem::int(index as i64)],
            )
            .expect("p_input should run");
        if result.exit_code != 0 {
            return Err(result.exit_code);
        }
        let text = result.stack.last().unwrap().as_integer().unwrap().to_string();
        let value = from_dec(&text);
        assert_eq!(dec(&value), text, "the decimal round trip is not exact");
        Ok(value)
    }

    fn all(&self, body: &Cell) -> Result<Vec<Field>, i32> {
        let count = match self.bc.run_get_method(
            &self.addr,
            "p_count",
            vec![StackItem::Cell(body.clone())],
        ) {
            Ok(result) if result.exit_code == 0 => result
                .stack
                .last()
                .unwrap()
                .as_integer()
                .unwrap()
                .to_string()
                .parse::<usize>()
                .expect("a count"),
            Ok(result) => return Err(result.exit_code),
            Err(error) => panic!("p_count: {error}"),
        };
        (0..count).map(|index| self.input(body, index)).collect()
    }

    fn exit(&self, body: &Cell) -> i32 {
        self.all(body).err().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------

#[test]
fn the_eighteen_public_inputs_are_the_frozen_order() {
    let probe = Probe::deploy();
    let global_id = probe.global_id();

    for (what, message) in
        [("transfer", Message::transfer()), ("withdrawal", Message::withdrawal())]
    {
        let body = message.body();
        let produced = probe.all(&body).unwrap_or_else(|code| panic!("{what}: exit {code}"));
        let expected = message.expected(global_id, &probe.account);
        assert_eq!(produced.len(), 18, "{what}: the vector is not eighteen long");
        for (index, (got, want)) in produced.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got, want, "{what}: public input {index} is not what section 10 says");
        }
        // The derived ones really are full-width values, not truncated zeros.
        for index in [6usize, 9, 15] {
            assert!(dec(&produced[index]).len() > 70, "{what}: input {index} looks truncated");
        }
    }

    // A transfer's recipient hash and recovery template hash are zero by
    // definition, and a withdrawal's are not.
    let transfer = probe.all(&Message::transfer().body()).expect("transfer");
    let withdrawal = probe.all(&Message::withdrawal().body()).expect("withdrawal");
    assert_eq!(transfer[13], ZERO, "a transfer carries a recipient hash");
    assert_eq!(transfer[16], ZERO, "a transfer carries a recovery template");
    assert_ne!(withdrawal[13], ZERO, "a withdrawal has no recipient hash");
    assert_ne!(withdrawal[16], ZERO, "a withdrawal has no recovery template");
}

#[test]
fn the_eight_derived_inputs_come_from_the_bytes_that_arrived() {
    let probe = Probe::deploy();
    let base = Message::withdrawal();
    let reference = probe.all(&base.body()).expect("the base message");

    // One byte of each payload, one byte of each key, and the recovery
    // payload: if any of these could be supplied instead of derived, the proof
    // could commit to one payload while the chain recorded another.
    let cases: Vec<(&str, usize, Box<dyn Fn(&mut Message)>)> = vec![
        ("payload 0", 6, Box::new(|m: &mut Message| m.payloads[0][0] ^= 1)),
        ("payload 1", 7, Box::new(|m: &mut Message| m.payloads[1][600] ^= 1)),
        ("payload 2", 8, Box::new(|m: &mut Message| m.payloads[2][PAYLOAD_BYTES - 1] ^= 1)),
        ("public key 0", 9, Box::new(|m: &mut Message| m.public_keys[0][0] ^= 1)),
        ("public key 1", 10, Box::new(|m: &mut Message| m.public_keys[1][PK_BYTES - 1] ^= 1)),
        ("recipient", 13, Box::new(|m: &mut Message| m.recipient = Some(small(1)))),
        (
            "recovery payload",
            16,
            Box::new(|m: &mut Message| {
                if let Some(bytes) = m.recovery_payload.as_mut() {
                    bytes[0] ^= 1;
                }
            }),
        ),
        ("recovery owner", 16, Box::new(|m: &mut Message| m.recovery_owner = small(45))),
    ];

    for (what, index, mutate) in cases {
        let mut changed = base.clone();
        mutate(&mut changed);
        let produced =
            probe.all(&changed.body()).unwrap_or_else(|code| panic!("{what}: exit {code}"));
        assert_ne!(
            produced[index], reference[index],
            "changing {what} did not move public input {index}, so it is not derived from it"
        );
        // And nothing else moved: a derived input must depend on its own input
        // and not on the shape of the message.
        for other in 0..18 {
            if other != index {
                assert_eq!(
                    produced[other], reference[other],
                    "changing {what} also moved public input {other}"
                );
            }
        }
    }
}

#[test]
fn every_frozen_shape_is_refused_when_it_is_not_that_shape() {
    let probe = Probe::deploy();
    let base = Message::withdrawal();
    assert_eq!(probe.exit(&base.body()), 0, "the canonical message was refused");

    // The root: four references, nothing left over.
    let mut trailing = BuilderData::new();
    let canonical = base.body();
    let mut source = chain_block::SliceData::load_cell_ref(&canonical).unwrap();
    let bits = source.remaining_bits();
    trailing.append_raw(&source.get_next_bytes(bits / 8).unwrap(), (bits / 8) * 8).unwrap();
    trailing.append_bits(0, bits % 8).unwrap();
    trailing.append_bit_zero().unwrap();
    for _ in 0..4 {
        trailing.checked_append_reference(source.checked_drain_reference().unwrap()).unwrap();
    }
    assert_eq!(probe.exit(&trailing.into_cell().unwrap()), 230, "a trailing bit was accepted");

    let three_refs = {
        let mut builder = BuilderData::new();
        let mut source = chain_block::SliceData::load_cell_ref(&canonical).unwrap();
        let bits = source.remaining_bits();
        builder.append_raw(&source.get_next_bytes(bits / 8).unwrap(), (bits / 8) * 8).unwrap();
        builder.append_bits(0, bits % 8).unwrap();
        for _ in 0..3 {
            builder.checked_append_reference(source.checked_drain_reference().unwrap()).unwrap();
        }
        builder.into_cell().unwrap()
    };
    assert_eq!(probe.exit(&three_refs), 230, "three references were accepted");

    // The proof bundle: 768 bits and two references.
    let short_proof = {
        let mut builder = BuilderData::new();
        builder.append_raw(&base.anchor_root, 256).unwrap();
        builder.append_raw(&base.nullifiers[0], 256).unwrap();
        builder.checked_append_reference(field_cell(&base.note_bodies)).unwrap();
        builder.checked_append_reference(groth16_proof(12)).unwrap();
        builder.into_cell().unwrap()
    };
    assert_eq!(
        probe.exit(&base.body_with(short_proof, base.output_bundle(), base.auth_bundle())),
        231,
        "a 512-bit proof bundle was accepted"
    );

    // The note bodies: exactly three field elements and nothing else. Four
    // would not fit a cell at all -- 1024 bits against a 1023-bit limit -- so
    // the cases are two bodies, and three with something hanging off them.
    let bad_bodies = |bodies: Cell| {
        let mut builder = BuilderData::new();
        builder.append_raw(&base.anchor_root, 256).unwrap();
        builder.append_raw(&base.nullifiers[0], 256).unwrap();
        builder.append_raw(&base.nullifiers[1], 256).unwrap();
        builder.checked_append_reference(bodies).unwrap();
        builder.checked_append_reference(groth16_proof(12)).unwrap();
        builder.into_cell().unwrap()
    };
    let two = field_cell(&[base.note_bodies[0], base.note_bodies[1]]);
    assert_eq!(
        probe.exit(&base.body_with(bad_bodies(two), base.output_bundle(), base.auth_bundle())),
        232,
        "two note bodies were accepted"
    );
    let with_ref = {
        let mut builder = BuilderData::new();
        for body in &base.note_bodies {
            builder.append_raw(body, 256).unwrap();
        }
        builder.checked_append_reference(Cell::default()).unwrap();
        builder.into_cell().unwrap()
    };
    assert_eq!(
        probe.exit(&base.body_with(bad_bodies(with_ref), base.output_bundle(), base.auth_bundle())),
        232,
        "a note-bodies cell with a reference was accepted"
    );

    // The Groth16 proof: A and C in the root, B behind its only reference.
    let wide_proof = {
        let mut root = BuilderData::new();
        root.append_raw(&bytes_of(97, 12), 776).unwrap();
        let mut b = BuilderData::new();
        b.append_raw(&bytes_of(96, 13), 768).unwrap();
        root.checked_append_reference(b.into_cell().unwrap()).unwrap();
        root.into_cell().unwrap()
    };
    let with_wide = {
        let mut builder = BuilderData::new();
        builder.append_raw(&base.anchor_root, 256).unwrap();
        builder.append_raw(&base.nullifiers[0], 256).unwrap();
        builder.append_raw(&base.nullifiers[1], 256).unwrap();
        builder.checked_append_reference(field_cell(&base.note_bodies)).unwrap();
        builder.checked_append_reference(wide_proof).unwrap();
        builder.into_cell().unwrap()
    };
    assert_eq!(
        probe.exit(&base.body_with(with_wide, base.output_bundle(), base.auth_bundle())),
        241,
        "a 776-bit proof root was accepted"
    );

    let heavy_b = {
        let mut root = BuilderData::new();
        root.append_raw(&bytes_of(96, 12), 768).unwrap();
        let mut b = BuilderData::new();
        b.append_raw(&bytes_of(96, 13), 768).unwrap();
        b.checked_append_reference(Cell::default()).unwrap();
        root.checked_append_reference(b.into_cell().unwrap()).unwrap();
        root.into_cell().unwrap()
    };
    let with_heavy = {
        let mut builder = BuilderData::new();
        builder.append_raw(&base.anchor_root, 256).unwrap();
        builder.append_raw(&base.nullifiers[0], 256).unwrap();
        builder.append_raw(&base.nullifiers[1], 256).unwrap();
        builder.checked_append_reference(field_cell(&base.note_bodies)).unwrap();
        builder.checked_append_reference(heavy_b).unwrap();
        builder.into_cell().unwrap()
    };
    assert_eq!(
        probe.exit(&base.body_with(with_heavy, base.output_bundle(), base.auth_bundle())),
        241,
        "a B cell carrying a reference was accepted"
    );

    // The output bundle: 256 bits and four references.
    let three_payloads = {
        let mut builder = BuilderData::new();
        builder.append_raw(&base.recovery_owner, 256).unwrap();
        for payload in &base.payloads {
            builder.checked_append_reference(byte_chain(payload)).unwrap();
        }
        builder.into_cell().unwrap()
    };
    assert_eq!(
        probe.exit(&base.body_with(base.proof_bundle(), three_payloads, base.auth_bundle())),
        233,
        "an output bundle without recovery data was accepted"
    );

    // The auth bundle: no data, four references.
    let three_auth = refs_only(&[
        byte_chain(&base.public_keys[0]),
        byte_chain(&base.signatures[0]),
        byte_chain(&base.public_keys[1]),
    ]);
    assert_eq!(
        probe.exit(&base.body_with(base.proof_bundle(), base.output_bundle(), three_auth)),
        234,
        "an auth bundle with one signature was accepted"
    );

    // The witness bundle: no data, two references.
    let one_witness = base.body_with_all(
        base.proof_bundle(),
        base.output_bundle(),
        base.auth_bundle(),
        refs_only(&[base.witnesses[0].clone()]),
    );
    assert_eq!(probe.exit(&one_witness), 235, "a witness bundle with one witness was accepted");

    let witnesses_with_data = {
        let mut builder = BuilderData::new();
        builder.append_bit_zero().unwrap();
        for witness in &base.witnesses {
            builder.checked_append_reference(witness.clone()).unwrap();
        }
        builder.into_cell().unwrap()
    };
    assert_eq!(
        probe.exit(&base.body_with_all(
            base.proof_bundle(),
            base.output_bundle(),
            base.auth_bundle(),
            witnesses_with_data
        )),
        235,
        "a witness bundle carrying data was accepted"
    );
}

#[test]
fn a_field_element_on_the_wire_must_already_be_canonical() {
    let probe = Probe::deploy();
    let base = Message::withdrawal();
    let m = modulus();

    let mut at_modulus = base.clone();
    at_modulus.anchor_root = m;
    assert_eq!(probe.exit(&at_modulus.body()), 236, "the modulus was accepted as an anchor root");

    let mut over = base.clone();
    over.nullifiers[1] = [0xff; 32];
    assert_eq!(probe.exit(&over.body()), 236, "2^256-1 was accepted as a nullifier");

    let mut body_over = base.clone();
    body_over.note_bodies[2] = m;
    assert_eq!(probe.exit(&body_over.body()), 236, "the modulus was accepted as a note body");

    // And the largest legal value is legal.
    let mut largest = base.clone();
    let mut below = m;
    below[31] -= 1;
    largest.anchor_root = below;
    assert_eq!(probe.exit(&largest.body()), 0, "the largest field element was refused");
}

#[test]
fn the_query_id_and_the_mode_have_to_agree_with_the_rest() {
    let probe = Probe::deploy();

    // The query id is the digest's low sixty-four bits and nothing else.
    let base = Message::transfer();
    let mut builder = BuilderData::new();
    builder.append_u64(1).unwrap();
    builder.append_u8(base.anchor_kind).unwrap();
    builder.append_u32(base.anchor_id).unwrap();
    builder.append_u32(base.valid_until).unwrap();
    store_coins(&mut builder, 0);
    store_coins(&mut builder, 0);
    builder.append_bits(0, 2).unwrap();
    builder.append_raw(&base.intent_digest, 256).unwrap();
    builder.checked_append_reference(base.proof_bundle()).unwrap();
    builder.checked_append_reference(base.output_bundle()).unwrap();
    builder.checked_append_reference(base.auth_bundle()).unwrap();
    builder.checked_append_reference(refs_only(&base.witnesses)).unwrap();
    assert_eq!(probe.exit(&builder.into_cell().unwrap()), 237, "a free-form query id was accepted");

    // A transfer that names a recipient. Setting an amount without one is not
    // this case: that is a withdrawal with nowhere to go, and it is refused as
    // such below.
    let mut addressed_transfer = Message::transfer();
    addressed_transfer.recipient = Some(small(1));
    assert_eq!(probe.exit(&addressed_transfer.body()), 239, "a transfer named a recipient");

    let mut paying_transfer = Message::transfer();
    paying_transfer.public_amount_out = TOS;
    assert_eq!(
        probe.exit(&paying_transfer.body()),
        238,
        "an amount with no recipient was not refused as a withdrawal with nowhere to go"
    );

    let mut anonymous_withdrawal = Message::withdrawal();
    anonymous_withdrawal.recipient = None;
    assert_eq!(probe.exit(&anonymous_withdrawal.body()), 238, "a withdrawal had nowhere to go");

    // A transfer carrying recovery material.
    let mut transfer_with_owner = Message::transfer();
    transfer_with_owner.recovery_owner = small(44);
    assert_eq!(
        probe.exit(&transfer_with_owner.body()),
        240,
        "a transfer pre-authorised a recovery"
    );

    let mut transfer_with_payload = Message::transfer();
    transfer_with_payload.recovery_payload = Some(bytes_of(PAYLOAD_BYTES, 10));
    assert_eq!(probe.exit(&transfer_with_payload.body()), 240, "a transfer carried recovery data");
}
