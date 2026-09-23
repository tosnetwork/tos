/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Section 9 of the V1 implementation profile, run in the VM: the transaction
//! intent digest, the ML-DSA-44 authorization of that digest, and the 4.1
//! `pq_auth_key_hash` rule that binds a public key to the note that key spends.
//!
//! The chain ships an ML-DSA-44 *verifier* only, so every signature here is
//! produced by a pinned test-only signer. The first thing the suite does is
//! prove that signer interoperates with this repository's own verifier in both
//! directions: the repository's OpenSSL fixture signatures verify under the
//! signer, and the signer's signatures verify under `PQCHECKSIG_MLDSA44` inside
//! the sandbox VM. Nothing else in the file is worth anything until that holds.
//!
//! What this cannot establish: that the digest the contract computes is the one
//! the circuit will constrain. The FunC and the reference below were both
//! written from section 9, so a misreading would be reproduced in both. The
//! cross-check that settles it is the circuit, which does not exist yet.

use chain_block::poseidon2::permute;
use chain_block::poseidon2_kat::DOMAINS;
use chain_block::{
    BuilderData, Cell, CellType, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
};
use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer, Verifier};
use sha2::{Digest, Sha256};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;
use tos_vm::stack::integer::IntegerData;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;

/// 9.4: the context is exactly these 28 ASCII bytes.
const CONTEXT: &[u8] = b"TOS-SHIELDED-POOL-MLDSA44-v1";
/// 4.1: the domain-separating prefix of the public-key hash.
const KEY_HASH_PREFIX: &[u8] = b"TOS-SHIELDED-MLDSA44-PK-v1";

const PUBLIC_KEY_BYTES: usize = 1312;
const SIGNATURE_BYTES: usize = 2420;
/// The canonical chunk size crypto/vm/pqops.cpp enforces on a byte chain.
const CHUNK_BYTES: usize = 127;

type Field = [u8; 32];

const ZERO: Field = [0u8; 32];

// ---------------------------------------------------------------------------
// Reference: sections 4.1 and 9 written out directly.

fn domain(label: &str) -> Field {
    DOMAINS
        .iter()
        .find(|(name, _)| *name == label)
        .unwrap_or_else(|| panic!("unknown domain label {label}"))
        .1
}

fn h7(domain: Field, args: [Field; 7]) -> Field {
    let mut state = [[0u8; 32]; 8];
    state[0] = domain;
    state[1..].copy_from_slice(&args);
    permute(&state)[0]
}

/// The BLS12-381 scalar field modulus of section 1.1.
fn field_modulus() -> Field {
    from_dec("52435875175126190479447740508185965837690552500527637822603658699938581184513")
}

fn less_than(a: &Field, b: &Field) -> bool {
    for index in 0..32 {
        if a[index] != b[index] {
            return a[index] < b[index];
        }
    }
    false
}

fn subtract(a: &Field, b: &Field) -> Field {
    let mut out = [0u8; 32];
    let mut borrow = 0i32;
    for index in (0..32).rev() {
        let value = a[index] as i32 - b[index] as i32 - borrow;
        if value < 0 {
            out[index] = (value + 256) as u8;
            borrow = 1;
        } else {
            out[index] = value as u8;
            borrow = 0;
        }
    }
    assert_eq!(borrow, 0, "subtraction underflowed");
    out
}

/// A 256-bit digest brought into the field. SHA256 output is below 2^256 and
/// the modulus is above 2^254, so at most two subtractions are ever needed;
/// the loop asserts that rather than assuming it.
fn reduce_to_field(digest: Field) -> Field {
    let modulus = field_modulus();
    let mut value = digest;
    let mut rounds = 0;
    while !less_than(&value, &modulus) {
        value = subtract(&value, &modulus);
        rounds += 1;
        assert!(rounds <= 2, "a SHA256 digest needed more than two reductions");
    }
    value
}

/// 4.1: uint256_be(SHA256("TOS-SHIELDED-MLDSA44-PK-v1" || pk_bytes)) mod r.
fn reference_key_hash(public_key: &[u8]) -> Field {
    let mut hasher = Sha256::new();
    hasher.update(KEY_HASH_PREFIX);
    hasher.update(public_key);
    let digest: Field = hasher.finalize().into();
    reduce_to_field(digest)
}

/// 9.2.
fn reference_recovery_template_hash(owner_commitment: Field, data_hash: Field) -> Field {
    h7(domain("RECOVERY-TEMPLATE"), [owner_commitment, data_hash, ZERO, ZERO, ZERO, ZERO, ZERO])
}

/// 9.3, in the order the profile writes the arguments.
#[derive(Clone, Copy)]
struct Core {
    execution_domain: Field,
    nf0: Field,
    nf1: Field,
    public_amount_out: Field,
    withdrawal_fee: Field,
    public_recipient_hash: Field,
    recovery_template_hash: Field,
}

impl Core {
    fn fields(&self) -> [Field; 7] {
        [
            self.execution_domain,
            self.nf0,
            self.nf1,
            self.public_amount_out,
            self.withdrawal_fee,
            self.public_recipient_hash,
            self.recovery_template_hash,
        ]
    }

    fn hash(&self) -> Field {
        h7(domain("INTENT-CORE"), self.fields())
    }
}

/// 9.3, in the order the profile writes the arguments.
#[derive(Clone, Copy)]
struct Outputs {
    note_body_0: Field,
    note_body_1: Field,
    note_body_2: Field,
    pq_auth_key_hash_0: Field,
    pq_auth_key_hash_1: Field,
    intent_nonce: Field,
    valid_until: Field,
}

impl Outputs {
    fn fields(&self) -> [Field; 7] {
        [
            self.note_body_0,
            self.note_body_1,
            self.note_body_2,
            self.pq_auth_key_hash_0,
            self.pq_auth_key_hash_1,
            self.intent_nonce,
            self.valid_until,
        ]
    }

    fn hash(&self) -> Field {
        h7(domain("INTENT-OUTPUTS"), self.fields())
    }
}

/// 9.3.
fn reference_intent_digest(core: Field, outputs: Field) -> Field {
    h7(domain("INTENT-FINAL"), [core, outputs, ZERO, ZERO, ZERO, ZERO, ZERO])
}

// ---------------------------------------------------------------------------
// 256-bit values travel as decimal strings; they are never parsed as i64.

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

// ---------------------------------------------------------------------------
// Canonical operand byte chains, built the way crypto/vm/pqops.cpp reads them:
// full 127-byte cells each carrying one reference, then a non-empty final cell.

fn byte_chain(bytes: &[u8]) -> Cell {
    if bytes.is_empty() {
        // pqops.cpp allows an empty payload only as the sole root of a chain.
        return chain_with_chunks(&[&[]]);
    }
    chain_with_chunks(&bytes.chunks(CHUNK_BYTES).collect::<Vec<_>>())
}

fn chain_with_chunks(chunks: &[&[u8]]) -> Cell {
    assert!(!chunks.is_empty(), "a byte chain needs at least one cell");
    let mut next: Option<Cell> = None;
    for chunk in chunks.iter().rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(chunk, chunk.len() * 8).expect("chunk bits");
        if let Some(reference) = next.take() {
            builder.checked_append_reference(reference).expect("chain reference");
        }
        next = Some(builder.into_cell().expect("chain cell"));
    }
    next.expect("a chain cell")
}

/// (payload bits, reference count) for every cell of a chain, from the root.
fn chain_shape(root: &Cell) -> Vec<(usize, usize)> {
    let mut shape = Vec::new();
    let mut cell = root.clone();
    loop {
        let refs = cell.references_count();
        shape.push((cell.bit_length(), refs));
        assert!(refs <= 1, "a byte chain cell carries more than one reference");
        if refs == 0 {
            return shape;
        }
        let next = cell.reference(0).expect("chain reference").clone();
        cell = next;
    }
}

/// A pruned-branch cell: type byte, level mask, one hash, one depth. Its level
/// is above zero, which is what lifts the level of any ordinary cell that
/// references it.
fn pruned_branch(seed: u8) -> Cell {
    let mut builder = BuilderData::new();
    builder.set_type(CellType::PrunedBranch);
    builder.append_u8(u8::from(CellType::PrunedBranch)).expect("type byte");
    builder.append_u8(1).expect("level mask");
    builder.append_raw(&[seed; 32], 256).expect("hash");
    builder.append_u16(0).expect("depth");
    builder.into_cell().expect("pruned branch cell")
}

/// A special cell the VM will still load, so the "ordinary cell only" rule has
/// something it can actually refuse. A pruned branch does not serve: the VM
/// refuses to load one at all, with its own pruned-cell exception, before any
/// contract code sees it.
fn merkle_proof_cell(inner: Cell) -> Cell {
    let mut builder = BuilderData::new();
    builder.set_type(CellType::MerkleProof);
    builder.append_u8(u8::from(CellType::MerkleProof)).expect("type byte");
    builder.append_raw(inner.hash(0).as_slice(), 256).expect("hash");
    builder.append_u16(inner.depth(0)).expect("depth");
    builder.checked_append_reference(inner).expect("proof reference");
    builder.into_cell().expect("merkle proof cell")
}

// ---------------------------------------------------------------------------
// The test-only signer.

struct Key {
    public_bytes: [u8; PUBLIC_KEY_BYTES],
    secret: ml_dsa_44::PrivateKey,
}

impl Key {
    fn generate() -> Self {
        let (public, secret) = ml_dsa_44::try_keygen().expect("ML-DSA-44 key generation");
        Self { public_bytes: public.into_bytes(), secret }
    }

    fn sign(&self, message: &[u8], context: &[u8]) -> [u8; SIGNATURE_BYTES] {
        self.secret.try_sign(message, context).expect("ML-DSA-44 signing")
    }

    /// A signature over the intent digest under the fixed section 9.4 context.
    fn authorize(&self, digest: &Field) -> [u8; SIGNATURE_BYTES] {
        self.sign(digest, CONTEXT)
    }

    fn key_cell(&self) -> Cell {
        byte_chain(&self.public_bytes)
    }

    fn key_hash(&self) -> Field {
        reference_key_hash(&self.public_bytes)
    }
}

// ---------------------------------------------------------------------------

const PROBE: &str = r#"
int p_key_hash(cell public_key) method_id { return pq_auth_key_hash(public_key); }
int p_pq_verify(cell message, cell context, cell signature, cell public_key) method_id {
  return pq_verify_mldsa44(message, context, signature, public_key);
}
int p_verify(cell public_key, cell signature, int digest) method_id {
  return verify_intent_signature(public_key, signature, digest);
}
(int, int) p_authorize(cell pk0, cell sig0, cell pk1, cell sig1, int digest) method_id {
  return authorize_intent(pk0, sig0, pk1, sig1, digest);
}
int p_intent_core(int a, int b, int c, int d, int e, int f, int g) method_id {
  return intent_core(a, b, c, d, e, f, g);
}
int p_intent_outputs(int a, int b, int c, int d, int e, int f, int g) method_id {
  return intent_outputs(a, b, c, d, e, f, g);
}
int p_intent_digest(int core, int outputs) method_id {
  return transaction_intent_digest(core, outputs);
}
int p_recovery_template(int a, int b) method_id { return recovery_template_hash(a, b); }
int p_check_chain(cell chain, int total_bytes) method_id {
  check_pq_byte_chain(chain, total_bytes);
  return 0;
}
cell p_context() method_id { return intent_signature_context(); }
cell p_message(int digest) method_id { return intent_message(digest); }
int p_check_validity(int valid_until, int now_seconds) method_id {
  check_intent_validity(valid_until, now_seconds);
  return 0;
}
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

struct Probe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl Probe {
    fn deploy() -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
            .expect("blockchain at version 17");
        let payer = bc.treasury("deployer", 1_000 * TOS).expect("treasury");
        // The library under test is this worktree's, found from the manifest
        // rather than from TOS_ROOT: TOS_ROOT points at the built toolchain,
        // which may be another checkout, and compiling that checkout's FunC
        // here would make every mutation appear to survive.
        let library = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont/shielded");
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir().expect("a directory for the probe");
        let probe_path = probe_dir.path().join("tos_shielded_auth_probe.fc");
        std::fs::write(&probe_path, PROBE).expect("write probe");
        let code = compile_func_with_stdlib(&[
            format!("{library}/domains.fc").into(),
            format!("{library}/notes.fc").into(),
            format!("{library}/auth.fc").into(),
            probe_path,
        ])
        .expect("compile the shielded library (needs build/crypto/func)");
        let mut data = BuilderData::new();
        data.append_u32(0).expect("initial data");
        let si = StateInit::with_code_and_data(code, data.into_cell().expect("data cell"));
        let addr_hash =
            si.write_to_new_cell().expect("state init").into_cell().expect("cell").hash(0);
        let addr = MsgAddressInt::with_params(0, addr_hash).expect("address");
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 2 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )
        .expect("deploy")
        .expect_success();
        Self { bc, addr }
    }

    fn field_arg(value: &Field) -> StackItem {
        StackItem::integer(
            IntegerData::from_str_radix(&dec(value), 10).expect("argument as integer"),
        )
    }

    fn field_args(values: &[Field]) -> Vec<StackItem> {
        values.iter().map(Self::field_arg).collect()
    }

    fn run(&self, method: &str, args: Vec<StackItem>) -> tos_sandbox::GetMethodResult {
        self.bc.run_get_method(&self.addr, method, args).unwrap_or_else(|e| panic!("{method}: {e}"))
    }

    fn exit_code(&self, method: &str, args: Vec<StackItem>) -> i32 {
        self.run(method, args).exit_code
    }

    fn field_from(result: &tos_sandbox::GetMethodResult, method: &str) -> Field {
        let text = result
            .stack
            .last()
            .expect("a result")
            .as_integer()
            .unwrap_or_else(|_| panic!("{method}: non-integer"))
            .to_string();
        let value = from_dec(&text);
        // The round trip is the guard, not the length: a 256-bit result that
        // was truncated on the way back would not come back to the same string.
        assert_eq!(dec(&value), text, "{method}: the decimal round trip is not exact");
        value
    }

    fn call_field(&self, method: &str, args: &[Field]) -> Field {
        let result = self.run(method, Self::field_args(args));
        assert_eq!(result.exit_code, 0, "{method} exited {}", result.exit_code);
        Self::field_from(&result, method)
    }

    fn key_hash(&self, key: &Cell) -> Field {
        let result = self.run("p_key_hash", vec![StackItem::Cell(key.clone())]);
        assert_eq!(result.exit_code, 0, "p_key_hash exited {}", result.exit_code);
        Self::field_from(&result, "p_key_hash")
    }

    fn key_hash_exit_code(&self, key: &Cell) -> i32 {
        self.exit_code("p_key_hash", vec![StackItem::Cell(key.clone())])
    }

    /// The raw opcode, so the repository's own fixtures can be replayed on
    /// chain exactly as they were produced.
    fn pq_verify(&self, message: &[u8], context: &[u8], signature: &[u8], key: &[u8]) -> bool {
        let args = vec![
            StackItem::Cell(byte_chain(message)),
            StackItem::Cell(byte_chain(context)),
            StackItem::Cell(byte_chain(signature)),
            StackItem::Cell(byte_chain(key)),
        ];
        let result = self.run("p_pq_verify", args);
        assert_eq!(result.exit_code, 0, "p_pq_verify exited {}", result.exit_code);
        !result.stack.last().expect("a result").as_integer().expect("bool").is_zero()
    }

    fn verify(&self, key: &Cell, signature: &Cell, digest: &Field) -> bool {
        let args = vec![
            StackItem::Cell(key.clone()),
            StackItem::Cell(signature.clone()),
            Self::field_arg(digest),
        ];
        let result = self.run("p_verify", args);
        assert_eq!(result.exit_code, 0, "p_verify exited {}", result.exit_code);
        !result.stack.last().expect("a result").as_integer().expect("bool").is_zero()
    }

    fn authorize_args(
        key_0: &Cell,
        signature_0: &Cell,
        key_1: &Cell,
        signature_1: &Cell,
        digest: &Field,
    ) -> Vec<StackItem> {
        vec![
            StackItem::Cell(key_0.clone()),
            StackItem::Cell(signature_0.clone()),
            StackItem::Cell(key_1.clone()),
            StackItem::Cell(signature_1.clone()),
            Self::field_arg(digest),
        ]
    }

    /// The two `pq_auth_key_hash` values the contract hands to public inputs
    /// 9 and 10, or the throw code if authorization failed.
    fn authorize(
        &self,
        key_0: &Cell,
        signature_0: &Cell,
        key_1: &Cell,
        signature_1: &Cell,
        digest: &Field,
    ) -> Result<(Field, Field), i32> {
        let result = self.run(
            "p_authorize",
            Self::authorize_args(key_0, signature_0, key_1, signature_1, digest),
        );
        if result.exit_code != 0 {
            return Err(result.exit_code);
        }
        assert_eq!(result.stack.len(), 2, "p_authorize must return two key hashes");
        let first = from_dec(&result.stack[0].as_integer().expect("hash 0").to_string());
        let second = from_dec(&result.stack[1].as_integer().expect("hash 1").to_string());
        Ok((first, second))
    }

    fn cell_result(&self, method: &str, args: Vec<StackItem>) -> Cell {
        let result = self.run(method, args);
        assert_eq!(result.exit_code, 0, "{method} exited {}", result.exit_code);
        result.stack.last().expect("a result").as_cell().expect("a cell").clone()
    }
}

fn cell_bytes(cell: &Cell) -> Vec<u8> {
    let bits = cell.bit_length();
    assert_eq!(bits % 8, 0, "the cell does not hold whole bytes");
    let mut slice = SliceData::load_cell_ref(cell).expect("slice");
    (0..bits / 8).map(|_| slice.get_next_byte().expect("byte")).collect()
}

// ---------------------------------------------------------------------------

/// Gate zero for everything else in this file. The signer is only useful if the
/// chain's own verifier accepts what it produces, and if it accepts what the
/// chain's own fixtures contain.
#[test]
fn the_test_signer_interoperates_with_this_chains_verifier() {
    assert_eq!(CONTEXT.len(), 28, "the section 9.4 context is not 28 bytes");

    let fixtures =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../test/pq-mldsa44/fixtures.json");
    let text = std::fs::read_to_string(fixtures).expect("the repository's ML-DSA fixtures");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("fixtures json");
    let fixture_key =
        hex::decode(doc["publicKeyHex"].as_str().expect("fixture key")).expect("key hex");
    assert_eq!(fixture_key.len(), PUBLIC_KEY_BYTES);
    let parsed =
        ml_dsa_44::PublicKey::try_from_bytes(fixture_key.clone().try_into().expect("1312 bytes"))
            .expect("the signer parses the chain's fixture public key");

    let probe = Probe::deploy();
    let cases = doc["cases"].as_array().expect("fixture cases");
    assert!(!cases.is_empty(), "there are no fixture cases to replay");
    for case in cases {
        let id = case["id"].as_str().expect("case id");
        let repeated = |key: &str| -> Option<Vec<u8>> {
            case.get(key).map(|r| {
                vec![
                    r["byte"].as_u64().expect("byte") as u8;
                    r["count"].as_u64().expect("count") as usize
                ]
            })
        };
        let message = repeated("messageRepeat").unwrap_or_else(|| {
            hex::decode(case["messageHex"].as_str().expect("message")).expect("message hex")
        });
        let context = repeated("contextRepeat").unwrap_or_else(|| {
            hex::decode(case["contextHex"].as_str().expect("context")).expect("context hex")
        });
        let signature: [u8; SIGNATURE_BYTES] =
            hex::decode(case["signatureHex"].as_str().expect("signature"))
                .expect("signature hex")
                .try_into()
                .expect("2420 bytes");
        // Verify direction: the signer agrees with the fixtures the chain ships.
        assert!(parsed.verify(&message, &signature, &context), "{id}: the signer rejected it");
        // And the chain's own verifier still accepts them, inside the VM.
        assert!(
            probe.pq_verify(&message, &context, &signature, &fixture_key),
            "{id}: PQCHECKSIG_MLDSA44 rejected the repository's own fixture"
        );
    }

    // Sign direction: what the signer produces is accepted on chain.
    let key = Key::generate();
    let digest = reduce_to_field([0x5au8; 32]);
    let signature = key.authorize(&digest);
    assert!(
        probe.pq_verify(&digest, CONTEXT, &signature, &key.public_bytes),
        "PQCHECKSIG_MLDSA44 rejected a signature from the test signer"
    );
    // And a signature that should not verify does not, so the check above is
    // not simply a verifier that answers true.
    let other = Key::generate();
    assert!(
        !probe.pq_verify(&digest, CONTEXT, &signature, &other.public_bytes),
        "PQCHECKSIG_MLDSA44 accepted a signature under the wrong public key"
    );
    assert!(
        !probe.pq_verify(&digest, b"TOS-SHIELDED-POOL-MLDSA44-v2", &signature, &key.public_bytes),
        "PQCHECKSIG_MLDSA44 accepted a signature under a different context"
    );
}

/// 4.1, over the actual canonical byte chain rather than a pre-hashed input.
#[test]
fn the_public_key_hash_is_the_sha256_rule_over_the_whole_key() {
    let probe = Probe::deploy();
    let key = Key::generate();
    let expected = reference_key_hash(&key.public_bytes);

    assert_eq!(
        probe.key_hash(&key.key_cell()),
        expected,
        "the contract's pq_auth_key_hash is not the section 4.1 rule"
    );
    assert!(dec(&expected).len() > 70, "the key hash is not a full-width field element");
    assert!(less_than(&expected, &field_modulus()), "the key hash is not in the field");

    // The whole key reaches the hash: flipping any one byte moves it.
    for position in [0usize, 1, 126, 127, 1269, 1270, 1311] {
        let mut altered = key.public_bytes;
        altered[position] ^= 0x01;
        assert_ne!(
            probe.key_hash(&byte_chain(&altered)),
            expected,
            "byte {position} of the public key does not reach the hash"
        );
    }

    // A second key gives a second hash; the rule is not a constant.
    let other = Key::generate();
    assert_ne!(probe.key_hash(&other.key_cell()), expected, "two keys hashed to one value");
    assert_eq!(probe.key_hash(&other.key_cell()), other.key_hash());

    // The prefix is part of the preimage: hashing the key alone is a different
    // value, and the contract must not produce it.
    let unprefixed: Field = Sha256::digest(key.public_bytes).into();
    assert_ne!(
        probe.key_hash(&key.key_cell()),
        reduce_to_field(unprefixed),
        "the domain prefix is missing from the preimage"
    );

    // The reduction is not decoration. About half of all keys hash above the
    // modulus, so search for one and require the contract to bring it into the
    // field rather than hand back the raw digest.
    let overflowing = (0..64)
        .map(|_| Key::generate())
        .find(|candidate| {
            let mut hasher = Sha256::new();
            hasher.update(KEY_HASH_PREFIX);
            hasher.update(candidate.public_bytes);
            let digest: Field = hasher.finalize().into();
            !less_than(&digest, &field_modulus())
        })
        .expect("no key in 64 hashed above the modulus, which is implausible");
    let mut hasher = Sha256::new();
    hasher.update(KEY_HASH_PREFIX);
    hasher.update(overflowing.public_bytes);
    let raw: Field = hasher.finalize().into();
    let reduced = reduce_to_field(raw);
    assert_ne!(raw, reduced, "the search did not find an overflowing digest");
    assert_eq!(
        probe.key_hash(&overflowing.key_cell()),
        reduced,
        "a digest above the modulus was not reduced into the field"
    );
}

/// The chain layout rules of crypto/vm/pqops.cpp, enforced in FunC rather than
/// left to the verifier: a key that is not laid out canonically is refused.
#[test]
fn a_noncanonical_public_key_chain_is_refused() {
    let probe = Probe::deploy();
    let key = Key::generate();
    let bytes = key.public_bytes.to_vec();
    assert_eq!(probe.key_hash_exit_code(&byte_chain(&bytes)), 0, "the canonical chain was refused");

    // The forced layout for 1312 bytes: ten full cells and a 42-byte tail.
    assert_eq!(
        chain_shape(&byte_chain(&bytes)),
        {
            let mut shape = vec![(CHUNK_BYTES * 8, 1); 10];
            shape.push((42 * 8, 0));
            shape
        },
        "the canonical 1312-byte chain is not ten full cells and a 42-byte tail"
    );

    // A short intermediate cell: the same 1312 bytes, split 126 / 127 / ...
    let mut short_first: Vec<&[u8]> = vec![&bytes[0..126]];
    let mut offset = 126;
    while offset < bytes.len() {
        let end = (offset + CHUNK_BYTES).min(bytes.len());
        short_first.push(&bytes[offset..end]);
        offset = end;
    }
    assert_eq!(
        probe.key_hash_exit_code(&chain_with_chunks(&short_first)),
        133,
        "a short intermediate cell was hashed anyway"
    );

    // A wrong total length, one byte short and one byte long.
    assert_eq!(
        probe.key_hash_exit_code(&byte_chain(&bytes[..PUBLIC_KEY_BYTES - 1])),
        133,
        "a 1311-byte key was accepted"
    );
    let mut too_long = bytes.clone();
    too_long.push(0);
    assert_eq!(
        probe.key_hash_exit_code(&byte_chain(&too_long)),
        133,
        "a 1313-byte key was accepted"
    );

    // A chain that stops before the key does. The cell that should carry the
    // next reference does not, so the reference rule is what refuses it.
    let truncated: Vec<&[u8]> = bytes[..CHUNK_BYTES * 9].chunks(CHUNK_BYTES).collect();
    assert_eq!(
        probe.key_hash_exit_code(&chain_with_chunks(&truncated)),
        134,
        "a chain that ended early was accepted"
    );

    // No chain at all.
    assert_eq!(
        probe.exit_code("p_key_hash", vec![StackItem::None]),
        130,
        "a null cell was accepted as a key chain"
    );

    // An empty final cell, which pqops.cpp allows only for an empty string.
    let mut with_empty_tail: Vec<&[u8]> = bytes.chunks(CHUNK_BYTES).collect();
    with_empty_tail.push(&[]);
    assert_eq!(
        probe.key_hash_exit_code(&chain_with_chunks(&with_empty_tail)),
        134,
        "an empty final cell was accepted"
    );

    // An extra reference hanging off the tail.
    let canonical_chunks: Vec<&[u8]> = bytes.chunks(CHUNK_BYTES).collect();
    let tail_with_reference = {
        let mut builder = BuilderData::new();
        builder.append_raw(canonical_chunks[10], 42 * 8).expect("tail bits");
        builder.checked_append_reference(byte_chain(&[0u8; 8])).expect("extra reference");
        let tail = builder.into_cell().expect("tail cell");
        let mut next = tail;
        for chunk in canonical_chunks[..10].iter().rev() {
            let mut builder = BuilderData::new();
            builder.append_raw(chunk, chunk.len() * 8).expect("chunk bits");
            builder.checked_append_reference(next).expect("chain reference");
            next = builder.into_cell().expect("chain cell");
        }
        next
    };
    assert_eq!(
        probe.key_hash_exit_code(&tail_with_reference),
        134,
        "a tail carrying an extra reference was accepted"
    );

    // A special cell as the root of the chain.
    let special_root = merkle_proof_cell(byte_chain(&bytes));
    assert_eq!(special_root.cell_type(), CellType::MerkleProof, "the fixture is not special");
    assert_eq!(
        probe.key_hash_exit_code(&special_root),
        131,
        "a special cell was accepted as a key chain"
    );

    // A special cell inside the chain, which also lifts the root's level above
    // zero; the level rule is what catches it at the root.
    let special_tail = {
        let mut next = pruned_branch(0x22);
        for chunk in canonical_chunks[..10].iter().rev() {
            let mut builder = BuilderData::new();
            builder.append_raw(chunk, chunk.len() * 8).expect("chunk bits");
            builder.checked_append_reference(next).expect("chain reference");
            next = builder.into_cell().expect("chain cell");
        }
        next
    };
    assert_ne!(special_tail.level(), 0, "the fixture does not actually raise the level");
    assert_eq!(
        probe.key_hash_exit_code(&special_tail),
        132,
        "a chain whose level is above zero was accepted"
    );
}

/// 9.3: the digest is one value that commits to every listed field, in order,
/// with the padding included.
#[test]
fn the_intent_digest_binds_every_field_it_is_specified_to_bind() {
    let probe = Probe::deploy();

    let core = Core {
        execution_domain: small(0x746f73),
        nf0: small(101),
        nf1: small(202),
        public_amount_out: small(7 * TOS),
        withdrawal_fee: small(TOS / 20),
        public_recipient_hash: small(303),
        recovery_template_hash: reference_recovery_template_hash(small(11), small(12)),
    };
    let outputs = Outputs {
        note_body_0: small(404),
        note_body_1: small(505),
        note_body_2: small(606),
        pq_auth_key_hash_0: small(707),
        pq_auth_key_hash_1: small(808),
        intent_nonce: small(909),
        valid_until: small(1_700_000_000),
    };

    assert_eq!(
        probe.call_field("p_recovery_template", &[small(11), small(12)]),
        core.recovery_template_hash,
        "the recovery template hash is not the section 9.2 rule"
    );
    assert_eq!(
        probe.call_field("p_intent_core", &core.fields()),
        core.hash(),
        "intent_core is not the section 9.3 rule"
    );
    assert_eq!(
        probe.call_field("p_intent_outputs", &outputs.fields()),
        outputs.hash(),
        "intent_outputs is not the section 9.3 rule"
    );
    let digest = reference_intent_digest(core.hash(), outputs.hash());
    assert_eq!(
        probe.call_field("p_intent_digest", &[core.hash(), outputs.hash()]),
        digest,
        "transaction_intent_digest is not the section 9.3 rule"
    );
    assert!(dec(&digest).len() > 70, "the digest is not a full-width field element");

    // Every named argument alone has to move the digest.
    let core_names = [
        "execution_domain",
        "nf0",
        "nf1",
        "public_amount_out",
        "withdrawal_fee",
        "public_recipient_hash",
        "recovery_template_hash",
    ];
    for (slot, name) in core_names.iter().enumerate() {
        let mut fields = core.fields();
        fields[slot] = small(0xfeed_0000 + slot as u64);
        let moved = probe.call_field("p_intent_core", &fields);
        assert_ne!(moved, core.hash(), "intent_core ignores {name}");
        assert_ne!(
            probe.call_field("p_intent_digest", &[moved, outputs.hash()]),
            digest,
            "the digest does not move when {name} changes"
        );
    }
    let output_names = [
        "note_body_0",
        "note_body_1",
        "note_body_2",
        "pq_auth_key_hash_0",
        "pq_auth_key_hash_1",
        "intent_nonce",
        "valid_until",
    ];
    for (slot, name) in output_names.iter().enumerate() {
        let mut fields = outputs.fields();
        fields[slot] = small(0xbeef_0000 + slot as u64);
        let moved = probe.call_field("p_intent_outputs", &fields);
        assert_ne!(moved, outputs.hash(), "intent_outputs ignores {name}");
        assert_ne!(
            probe.call_field("p_intent_digest", &[core.hash(), moved]),
            digest,
            "the digest does not move when {name} changes"
        );
    }

    // The argument order is part of the definition: swapping a pair changes it.
    let mut swapped = core.fields();
    swapped.swap(1, 2);
    assert_ne!(
        probe.call_field("p_intent_core", &swapped),
        core.hash(),
        "intent_core does not depend on the order of nf0 and nf1"
    );
    let mut swapped = outputs.fields();
    swapped.swap(3, 4);
    assert_ne!(
        probe.call_field("p_intent_outputs", &swapped),
        outputs.hash(),
        "intent_outputs does not depend on the order of the two key hashes"
    );
    assert_ne!(
        probe.call_field("p_intent_digest", &[outputs.hash(), core.hash()]),
        digest,
        "the digest does not depend on which half comes first"
    );

    // The zero padding of INTENT-FINAL is part of the definition, not slack.
    assert_ne!(
        h7(domain("INTENT-FINAL"), [core.hash(), outputs.hash(), small(1), ZERO, ZERO, ZERO, ZERO]),
        digest,
        "a padding lane does not reach the output"
    );

    // The three domains separate the structures.
    let same = [small(1), small(2), ZERO, ZERO, ZERO, ZERO, ZERO];
    let mut produced = vec![
        h7(domain("INTENT-CORE"), same),
        h7(domain("INTENT-OUTPUTS"), same),
        h7(domain("INTENT-FINAL"), same),
        h7(domain("RECOVERY-TEMPLATE"), same),
    ];
    produced.sort();
    produced.dedup();
    assert_eq!(produced.len(), 4, "two intent domains agree on the same inputs");
}

/// 9.4: the signed bytes are the digest's 32 big-endian bytes under the fixed
/// 28-byte context, and nothing else.
#[test]
fn the_signed_bytes_are_the_digest_under_the_fixed_context() {
    let probe = Probe::deploy();

    let context = probe.cell_result("p_context", vec![]);
    assert_eq!(context.bit_length(), CONTEXT.len() * 8, "the context is not 28 bytes");
    assert_eq!(context.references_count(), 0, "the context is not a single cell");
    assert_eq!(cell_bytes(&context), CONTEXT, "the context is not the section 9.4 string");

    let digest = reduce_to_field([0x31u8; 32]);
    let message = probe.cell_result("p_message", vec![Probe::field_arg(&digest)]);
    assert_eq!(message.bit_length(), 256, "the message is not 32 bytes");
    assert_eq!(message.references_count(), 0, "the message is not a single cell");
    assert_eq!(
        cell_bytes(&message),
        digest.to_vec(),
        "the message is not the raw big-endian digest"
    );

    // A digest outside the field is not a field element and is refused rather
    // than truncated into 256 bits.
    assert_eq!(
        probe.exit_code("p_message", vec![Probe::field_arg(&field_modulus())]),
        136,
        "the modulus was accepted as a digest"
    );

    // The signature has to be over that exact message and context.
    let key = Key::generate();
    let good = key.authorize(&digest);
    assert!(probe.verify(&key.key_cell(), &byte_chain(&good), &digest), "a good signature failed");

    let other_digest = reduce_to_field([0x32u8; 32]);
    let wrong_message = key.authorize(&other_digest);
    assert!(
        !probe.verify(&key.key_cell(), &byte_chain(&wrong_message), &digest),
        "a signature over a different digest was accepted"
    );
    let wrong_context = key.sign(&digest, b"TOS-SHIELDED-POOL-MLDSA44-v2");
    assert!(
        !probe.verify(&key.key_cell(), &byte_chain(&wrong_context), &digest),
        "a signature under a different context was accepted"
    );
    let no_context = key.sign(&digest, b"");
    assert!(
        !probe.verify(&key.key_cell(), &byte_chain(&no_context), &digest),
        "a signature with an empty context was accepted"
    );

    // And the signature chain itself has to be the canonical 2420 bytes.
    assert_eq!(
        chain_shape(&byte_chain(&good)),
        {
            let mut shape = vec![(CHUNK_BYTES * 8, 1); 19];
            shape.push((7 * 8, 0));
            shape
        },
        "the canonical 2420-byte chain is not nineteen full cells and a 7-byte tail"
    );
    let args = vec![
        StackItem::Cell(key.key_cell()),
        StackItem::Cell(byte_chain(&good[..SIGNATURE_BYTES - 1])),
        Probe::field_arg(&digest),
    ];
    assert_eq!(probe.exit_code("p_verify", args), 133, "a 2419-byte signature was accepted");
    let mut short_first: Vec<&[u8]> = vec![&good[0..1]];
    let mut offset = 1usize;
    while offset < good.len() {
        let end = (offset + CHUNK_BYTES).min(good.len());
        short_first.push(&good[offset..end]);
        offset = end;
    }
    let args = vec![
        StackItem::Cell(key.key_cell()),
        StackItem::Cell(chain_with_chunks(&short_first)),
        Probe::field_arg(&digest),
    ];
    assert_eq!(
        probe.exit_code("p_verify", args),
        133,
        "a non-canonically split signature was accepted"
    );

    // The chain walker refuses an operand length that is not a positive number
    // of bytes, rather than treating it as an empty operand.
    assert_eq!(
        probe.exit_code(
            "p_check_chain",
            vec![StackItem::Cell(byte_chain(&good)), Probe::field_arg(&ZERO)],
        ),
        135,
        "a zero-byte operand length was accepted"
    );
    assert_eq!(
        probe.exit_code(
            "p_check_chain",
            vec![
                StackItem::Cell(byte_chain(&good)),
                Probe::field_arg(&small(SIGNATURE_BYTES as u64)),
            ],
        ),
        0,
        "the canonical signature chain was refused"
    );
}

/// Section 19 gate 6. An attacker who holds a perfectly valid keypair and signs
/// the very same digest still cannot authorize the transaction: the hash the
/// contract derives from their key is not the one the note and public inputs
/// 9 and 10 demand, and mixing their material with the honest material fails.
#[test]
fn an_attackers_own_valid_keypair_cannot_authorize_the_transaction() {
    let probe = Probe::deploy();
    let key_0 = Key::generate();
    let key_1 = Key::generate();
    let attacker = Key::generate();

    let core = Core {
        execution_domain: small(0x746f73),
        nf0: small(0xaaaa),
        nf1: small(0xbbbb),
        public_amount_out: ZERO,
        withdrawal_fee: ZERO,
        public_recipient_hash: ZERO,
        recovery_template_hash: ZERO,
    };
    let outputs = Outputs {
        note_body_0: small(1),
        note_body_1: small(2),
        note_body_2: small(3),
        pq_auth_key_hash_0: key_0.key_hash(),
        pq_auth_key_hash_1: key_1.key_hash(),
        intent_nonce: small(0xc0ffee),
        valid_until: small(1_700_000_000),
    };
    let digest = reference_intent_digest(core.hash(), outputs.hash());

    let signature_0 = byte_chain(&key_0.authorize(&digest));
    let signature_1 = byte_chain(&key_1.authorize(&digest));
    let attacker_signature = byte_chain(&attacker.authorize(&digest));

    // The honest bundle authorizes and yields exactly the two hashes that the
    // public input vector carries.
    assert_eq!(
        probe.authorize(&key_0.key_cell(), &signature_0, &key_1.key_cell(), &signature_1, &digest),
        Ok((key_0.key_hash(), key_1.key_hash())),
        "the honest authorization did not produce the two bound key hashes"
    );

    // The attacker's pair is genuinely valid over the same digest, so the
    // substitution below is not defeated by a bad signature.
    assert!(
        probe.verify(&attacker.key_cell(), &attacker_signature, &digest),
        "the attacker's own signature is not valid, so this test proves nothing"
    );

    // Swapping in the attacker's whole pair verifies, but produces a key hash
    // that is not the one bound into the note: it cannot satisfy the circuit.
    let substituted = probe
        .authorize(
            &attacker.key_cell(),
            &attacker_signature,
            &key_1.key_cell(),
            &signature_1,
            &digest,
        )
        .expect("a valid pair verifies");
    assert_ne!(substituted.0, key_0.key_hash(), "the attacker's key produced the honest key hash");
    assert_eq!(substituted.0, attacker.key_hash());
    assert_ne!(
        outputs.pq_auth_key_hash_0, substituted.0,
        "public input 9 would still match after substitution"
    );

    // Swapping in either half alone is refused outright.
    assert_eq!(
        probe.authorize(
            &key_0.key_cell(),
            &attacker_signature,
            &key_1.key_cell(),
            &signature_1,
            &digest
        ),
        Err(137),
        "an attacker's signature under the honest key was accepted in slot 0"
    );
    assert_eq!(
        probe.authorize(
            &attacker.key_cell(),
            &signature_0,
            &key_1.key_cell(),
            &signature_1,
            &digest
        ),
        Err(137),
        "the honest signature under an attacker's key was accepted in slot 0"
    );
    assert_eq!(
        probe.authorize(
            &key_0.key_cell(),
            &signature_0,
            &key_1.key_cell(),
            &attacker_signature,
            &digest
        ),
        Err(138),
        "an attacker's signature under the honest key was accepted in slot 1"
    );
    assert_eq!(
        probe.authorize(
            &key_0.key_cell(),
            &signature_0,
            &attacker.key_cell(),
            &signature_1,
            &digest
        ),
        Err(138),
        "the honest signature under an attacker's key was accepted in slot 1"
    );

    // Replaying the bundle against a different digest fails at slot 0.
    let other_digest = reference_intent_digest(core.hash(), small(5));
    assert_ne!(other_digest, digest);
    assert_eq!(
        probe.authorize(
            &key_0.key_cell(),
            &signature_0,
            &key_1.key_cell(),
            &signature_1,
            &other_digest
        ),
        Err(137),
        "a signature bundle authorized a different digest"
    );

    // Both slots are checked, not just the first: a bundle whose second slot is
    // signed under the wrong context is refused even though slot 0 is perfect.
    let bad_context = byte_chain(&key_1.sign(&digest, b"TOS-SHIELDED-POOL-MLDSA44-v2"));
    assert_eq!(
        probe.authorize(&key_0.key_cell(), &signature_0, &key_1.key_cell(), &bad_context, &digest),
        Err(138),
        "slot 1 was not verified"
    );
}

/// Section 19 gate 8. A phantom input slot carries a fresh throwaway key and a
/// real signature, so the wire is byte-for-byte the same shape as a slot
/// holding a real note's key.
#[test]
fn the_wire_carries_two_full_keys_and_two_signatures_either_way() {
    let probe = Probe::deploy();

    // Two real inputs.
    let real_0 = Key::generate();
    let real_1 = Key::generate();
    // One real input; slot 1 is phantom and the wallet generated a throwaway.
    let single_real = Key::generate();
    let throwaway = Key::generate();

    let digest = reduce_to_field([0x77u8; 32]);

    let bundles: [(&str, [&Key; 2]); 2] = [
        ("two real inputs", [&real_0, &real_1]),
        ("one real input and a phantom slot", [&single_real, &throwaway]),
    ];

    let mut encodings = Vec::new();
    for (label, keys) in bundles {
        let key_cells = [keys[0].key_cell(), keys[1].key_cell()];
        let signatures =
            [byte_chain(&keys[0].authorize(&digest)), byte_chain(&keys[1].authorize(&digest))];

        // Both slots authorize, phantom or not.
        assert_eq!(
            probe.authorize(&key_cells[0], &signatures[0], &key_cells[1], &signatures[1], &digest),
            Ok((keys[0].key_hash(), keys[1].key_hash())),
            "{label}: the bundle did not authorize"
        );

        let mut shape = Vec::new();
        for slot in 0..2 {
            assert_eq!(keys[slot].public_bytes.len(), PUBLIC_KEY_BYTES, "{label}: key {slot}");
            shape.push(chain_shape(&key_cells[slot]));
            shape.push(chain_shape(&signatures[slot]));
        }
        // Eleven cells of key and twenty of signature, in both slots.
        assert_eq!(shape[0].len(), 11, "{label}: key 0 is not eleven cells");
        assert_eq!(shape[1].len(), 20, "{label}: signature 0 is not twenty cells");
        assert_eq!(shape[0], shape[2], "{label}: the two keys are shaped differently");
        assert_eq!(shape[1], shape[3], "{label}: the two signatures are shaped differently");
        let key_bytes: usize = shape[0].iter().map(|(bits, _)| bits / 8).sum();
        let signature_bytes: usize = shape[1].iter().map(|(bits, _)| bits / 8).sum();
        assert_eq!(key_bytes, PUBLIC_KEY_BYTES, "{label}: the key is not 1312 bytes on the wire");
        assert_eq!(
            signature_bytes, SIGNATURE_BYTES,
            "{label}: the signature is not 2420 bytes on the wire"
        );
        encodings.push(shape);
    }

    assert_eq!(
        encodings[0], encodings[1],
        "the one-real and two-real cases are distinguishable from the encoding alone"
    );

    // The throwaway key is a different key, so the equality above is about the
    // shape and not about having accidentally reused one key everywhere.
    assert_ne!(single_real.key_hash(), throwaway.key_hash());
    assert_ne!(real_0.key_hash(), real_1.key_hash());
}

/// 9.3: `now <= valid_until <= now + 3600`, on a uint32 field.
#[test]
fn valid_until_must_be_now_or_within_the_hour() {
    let probe = Probe::deploy();
    let now = 1_700_000_000u64;
    let check = |valid_until: u64| {
        probe.exit_code(
            "p_check_validity",
            vec![Probe::field_arg(&small(valid_until)), Probe::field_arg(&small(now))],
        )
    };

    assert_eq!(check(now), 0, "valid_until equal to now was refused");
    assert_eq!(check(now + 1), 0, "a second into the future was refused");
    assert_eq!(check(now + 3600), 0, "the far edge of the window was refused");
    assert_eq!(check(now + 3601), 141, "a second past the window was accepted");
    assert_eq!(check(now - 1), 140, "a valid_until in the past was accepted");
    assert_eq!(
        probe.exit_code(
            "p_check_validity",
            vec![Probe::field_arg(&small(4_294_967_296)), Probe::field_arg(&small(now))],
        ),
        139,
        "a valid_until outside uint32 was accepted"
    );
}
