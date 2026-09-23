/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The pool contract's transact handler, section 16.2.
//!
//! Section 16.2 is an order, not a set: the funding rule comes before the gas
//! ceiling, the ceiling before any hashing, the anchor before the witnesses,
//! the witnesses before the signatures, and all of them before the proof. This
//! file drives a message that is correct up to a chosen step and requires the
//! failure to carry that step's own code, which is the only way to show the
//! order is the one the profile fixes rather than whatever the code happened
//! to do first.
//!
//! **What is not established here.** The handler has never accepted a
//! transact. Reaching step 17 needs a Groth16 proof over the exact eighteen
//! public inputs, eight of which the contract derives from the payloads, the
//! keys and its own address -- so the proof can only be made after the pool is
//! deployed and its execution domain is known. The furthest a test can get
//! today is step 12, failing at 262 with everything before it satisfied, and
//! that is what the last test asserts. Section 19 gate 11 is therefore shown
//! for the failing paths and not for a successful one.

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer};

use chain_block::poseidon2::permute;
use chain_block::poseidon2_kat::{DOMAINS, EMPTY_ROOTS};
use chain_block::{BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, compile_func_with_stdlib};

use std::collections::BTreeMap;

mod shielded_pool_library;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
const DEPTH: usize = 12;
const ARITY: u64 = 7;
const CAPACITY: u64 = 1 << 32;
const PATH_FIELDS: usize = DEPTH * 6;

const MAGIC: u32 = 0x5350_5631;
const VERSION: u16 = 1;
const EPOCH_NONE: u32 = 0xffff_ffff;
const OP_TRANSACT: u32 = 0x5348_5002;
const RESERVE_FLOOR: u64 = 5 * TOS;
/// Section 14.1, frozen by the production rule
/// C = max(10,000, round_up_10,000(ceil(B * 5 / 4))). A sender funds the
/// ceiling, not what the path will use.
///
/// `B` is a derived upper bound, not a measured maximum. The dearest state a
/// pool can *reach* is full anchor rings on the youngest tree that can have
/// them -- full rings make a transact dearer and a higher leaf index makes it
/// slightly cheaper, so it is at neither end of a pool's life -- but the
/// dearest state a transact can be *in* is not reachable at all, and that is
/// what the ceiling has to cover. `gas_ceiling_bound.rs` derives it by walking
/// each variable call's whole domain and adding the spans.
///
/// Read out of the contract, never written down here. A ceiling copied into a
/// test is a number this file can check against itself while the deployed
/// contract says something else entirely.
fn transact_gas_ceiling() -> i64 {
    shielded_pool_library::gas_ceiling("transact_gas_ceiling")
}
/// The upper bound `gas_ceiling_bound.rs` derives for a withdrawal, which is
/// the dearer of the two transact modes. It is not a measurement: no
/// transaction anybody can build sits at the dearest denomination, the
/// dearest anchor kind, full rings, a turning epoch, the leaf index whose
/// base-seven digits are all zero and the more expensive nullifier order at
/// once. The bound adds each of those spans to one real withdrawal.
const TRANSACT_DERIVED_BOUND_GAS: i64 = 1_204_845;
/// The basechain compute fee for `gas`, priced as ConfigParam21 prices it: a
/// flat 667 for the first hundred gas, then 436,907 per 65,536 gas with the
/// division rounded up.
///
/// This was `gas * NANOTOS_PER_GAS` with NANOTOS_PER_GAS = 400 while the
/// price was 26,214,400, which divides by 65,536 exactly. Neither of the two
/// prices since does, so a flat multiplier is no longer the same arithmetic
/// the VM does, and the tests now do the VM's.
const fn compute_fee(gas: u64) -> u64 {
    const FLAT_LIMIT: u64 = 100;
    const FLAT_PRICE: u64 = 667;
    const GAS_PRICE: u64 = 436_907;
    if gas <= FLAT_LIMIT {
        FLAT_PRICE
    } else {
        FLAT_PRICE + ((gas - FLAT_LIMIT) * GAS_PRICE).div_ceil(65_536)
    }
}
/// What a transact has to fund: the ceiling the contract declares, priced by
/// the same arithmetic the VM uses.
fn transact_fee() -> u64 {
    compute_fee(transact_gas_ceiling() as u64)
}

type Field = [u8; 32];
const ZERO: Field = [0u8; 32];

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

fn small(value: u64) -> Field {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
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

fn imt_node(children: [Field; 7]) -> Field {
    h7(domain("IMT-NODE"), children)
}

/// Section 7: `H7("IMT-LEAF", value, next_index, next_value, 0,0,0,0)`.
fn imt_leaf_hash(leaf: &Leaf) -> Field {
    h7(
        domain("IMT-LEAF"),
        [leaf.value, small(leaf.next_index as u64), leaf.next_value, ZERO, ZERO, ZERO, ZERO],
    )
}

/// Section 7.0: `IMT_EMPTY[0] = 0`, then seven copies under IMT-NODE.
fn empty_ladder() -> Vec<Field> {
    let mut out = vec![ZERO];
    for level in 0..DEPTH {
        out.push(imt_node([out[level]; 7]));
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Leaf {
    value: Field,
    next_index: u32,
    next_value: Field,
}

impl Leaf {
    fn sentinel() -> Self {
        Leaf { value: ZERO, next_index: 0, next_value: ZERO }
    }
}

/// A whole IMT as a map from leaf index to leaf tuple. Nothing here folds a
/// path or carries a frontier: every root is rebuilt from every allocated leaf.
#[derive(Clone, Default)]
struct RefTree {
    leaves: BTreeMap<u64, Leaf>,
}

impl RefTree {
    /// Node values level by level, sparsely: `levels[l][i]` is the node at
    /// level `l`, index `i`. A missing entry is that level's empty root.
    fn levels(&self) -> Vec<BTreeMap<u64, Field>> {
        let empty = empty_ladder();
        let mut levels: Vec<BTreeMap<u64, Field>> = Vec::with_capacity(DEPTH + 1);
        levels
            .push(self.leaves.iter().map(|(index, leaf)| (*index, imt_leaf_hash(leaf))).collect());
        for level in 0..DEPTH {
            let current = &levels[level];
            let mut parents: BTreeMap<u64, Field> = BTreeMap::new();
            for index in current.keys() {
                parents.insert(index / ARITY, ZERO);
            }
            let mut next: BTreeMap<u64, Field> = BTreeMap::new();
            for parent in parents.keys() {
                let mut children = [empty[level]; 7];
                for (position, slot) in children.iter_mut().enumerate() {
                    if let Some(value) = current.get(&(parent * ARITY + position as u64)) {
                        *slot = *value;
                    }
                }
                next.insert(*parent, imt_node(children));
            }
            levels.push(next);
        }
        levels
    }

    fn root(&self) -> Field {
        let empty = empty_ladder();
        self.levels()[DEPTH].get(&0).copied().unwrap_or(empty[DEPTH])
    }

    /// Section 7.2: twelve levels, leaf to root, six siblings per level in
    /// ascending child position with the path digit skipped.
    fn path(&self, index: u64) -> Vec<Field> {
        let empty = empty_ladder();
        let levels = self.levels();
        let mut out = Vec::with_capacity(PATH_FIELDS);
        let mut stride = 1u64;
        for (level, nodes) in levels.iter().take(DEPTH).enumerate() {
            let at_level = index / stride;
            let digit = at_level % ARITY;
            let base = (at_level / ARITY) * ARITY;
            for position in 0..ARITY {
                if position == digit {
                    continue;
                }
                out.push(nodes.get(&(base + position)).copied().unwrap_or(empty[level]));
            }
            stride *= ARITY;
        }
        assert_eq!(out.len(), PATH_FIELDS, "a path is not 72 fields");
        out
    }
}

/// The contract's two persistent nullifier fields, with the tree behind them.
#[derive(Clone)]
struct RefState {
    tree: RefTree,
    next_index: u64,
}

/// Everything the caller supplies for one insertion, before encoding.
#[derive(Clone)]
struct Witness {
    low_index: u32,
    low_value: Field,
    low_next_index: u32,
    low_next_value: Field,
    low_path: Vec<Field>,
    append_path: Vec<Field>,
}

impl RefState {
    /// Section 7.0: leaf 0 holds the head sentinel and the next index starts at 1.
    fn genesis() -> Self {
        let mut tree = RefTree::default();
        tree.leaves.insert(0, Leaf::sentinel());
        RefState { tree, next_index: 1 }
    }

    fn root(&self) -> Field {
        self.tree.root()
    }

    /// The allocated leaf with the greatest value strictly below `nf`.
    fn predecessor(&self, nf: &Field) -> (u64, Leaf) {
        let mut best: Option<(u64, Leaf)> = None;
        for (index, leaf) in self.tree.leaves.iter() {
            if leaf.value < *nf && best.is_none_or(|(_, chosen)| leaf.value > chosen.value) {
                best = Some((*index, *leaf));
            }
        }
        best.unwrap_or_else(|| panic!("no predecessor for {}", dec(nf)))
    }

    /// The witness of 7.1, plus the intermediate root of step 5 and the final
    /// root of step 7, all built by rebuilding trees rather than folding paths.
    fn witness_for(&self, nf: &Field) -> (Witness, Field, Field, RefTree) {
        let (low_index, low) = self.predecessor(nf);
        let new_index = self.next_index;
        assert!(new_index < CAPACITY, "the reference tree is exhausted");

        let low_path = self.tree.path(low_index);

        let mut after_update = self.tree.clone();
        after_update.leaves.insert(
            low_index,
            Leaf { value: low.value, next_index: new_index as u32, next_value: *nf },
        );
        let root1 = after_update.root();
        let append_path = after_update.path(new_index);

        let mut after_insert = after_update.clone();
        after_insert.leaves.insert(
            new_index,
            Leaf { value: *nf, next_index: low.next_index, next_value: low.next_value },
        );
        let root2 = after_insert.root();

        let witness = Witness {
            low_index: u32::try_from(low_index).expect("low index is a uint32"),
            low_value: low.value,
            low_next_index: low.next_index,
            low_next_value: low.next_value,
            low_path,
            append_path,
        };
        (witness, root1, root2, after_insert)
    }

    fn apply(&mut self, tree: RefTree) {
        self.tree = tree;
        self.next_index += 1;
    }
}

// ---------------------------------------------------------------------------
// Section 7.2 encoding, with the deliberate deviations the decoder must reject.

#[derive(Clone, Copy, Default)]
struct PathTweak {
    /// Extra data bits appended to the given path cell.
    trailing_bits: Option<(usize, usize)>,
    /// An extra reference appended to the given path cell.
    extra_ref: Option<usize>,
}

fn encode_path(fields: &[Field]) -> Cell {
    encode_path_tweaked(fields, PathTweak::default())
}

/// A canonical linked chain of level-zero cells, three fields each, built from
/// the last cell backwards so every non-final cell carries exactly one ref.
fn encode_path_tweaked(fields: &[Field], tweak: PathTweak) -> Cell {
    assert_eq!(fields.len() % 3, 0, "a path cell holds exactly three fields");
    let cells = fields.len() / 3;
    assert!(cells > 0, "a path needs at least one cell");
    let mut chain: Option<Cell> = None;
    for index in (0..cells).rev() {
        let mut builder = BuilderData::new();
        for offset in 0..3 {
            builder.append_raw(&fields[index * 3 + offset], 256).expect("a path field");
        }
        if let Some((cell, bits)) = tweak.trailing_bits {
            if cell == index {
                builder.append_bits(0, bits).expect("trailing bits");
            }
        }
        if let Some(next) = chain {
            builder.checked_append_reference(next).expect("the chain reference");
        }
        if tweak.extra_ref == Some(index) {
            builder.checked_append_reference(Cell::default()).expect("an extra reference");
        }
        chain = Some(builder.into_cell().expect("a path cell"));
    }
    chain.expect("a path chain")
}

#[derive(Clone, Copy, Default)]
struct WitnessTweak {
    trailing_bits: usize,
    extra_ref: bool,
}

fn encode_witness(witness: &Witness) -> Cell {
    encode_witness_parts(
        witness,
        encode_path(&witness.low_path),
        encode_path(&witness.append_path),
        WitnessTweak::default(),
    )
}

/// The witness root of 7.2: 32 + 256 + 32 + 256 data bits and two references.
fn encode_witness_parts(
    witness: &Witness,
    low_path: Cell,
    append_path: Cell,
    tweak: WitnessTweak,
) -> Cell {
    let mut builder = BuilderData::new();
    builder.append_u32(witness.low_index).expect("low index");
    builder.append_raw(&witness.low_value, 256).expect("low value");
    builder.append_u32(witness.low_next_index).expect("low next index");
    builder.append_raw(&witness.low_next_value, 256).expect("low next value");
    if tweak.trailing_bits > 0 {
        builder.append_bits(0, tweak.trailing_bits).expect("trailing bits");
    }
    builder.checked_append_reference(low_path).expect("low path ref");
    builder.checked_append_reference(append_path).expect("append path ref");
    if tweak.extra_ref {
        builder.checked_append_reference(Cell::default()).expect("an extra reference");
    }
    builder.into_cell().expect("a witness root")
}

// ---------------------------------------------------------------------------
// The message, and the contract that receives it.

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

fn payload(seed: u8) -> Vec<u8> {
    (0..1233u32).map(|i| (i as u8) ^ seed).collect()
}

fn refs_only(cells: &[Cell]) -> Cell {
    let mut builder = BuilderData::new();
    for cell in cells {
        builder.checked_append_reference(cell.clone()).expect("a reference");
    }
    builder.into_cell().expect("a bundle")
}

/// A real proof, from the circuit tool's development fixture. It decodes as
/// three curve points and proves a different statement, which is what makes it
/// useful here: arbitrary bytes are refused by blst while it is still reading
/// them, and the test would then never learn whether the handler reached the
/// equation at all.
fn groth16_proof() -> Cell {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../tools/shielded-pool-circuit/fixtures/groth16-development.json"
    );
    let text = std::fs::read_to_string(path).expect("the development fixture");
    let fixture: serde_json::Value = serde_json::from_str(&text).expect("the fixture is JSON");
    let proof = &fixture["vectors"][0]["proof"];
    let hex = |key: &str| -> Vec<u8> {
        let text = proof[key].as_str().expect("a proof component");
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect()
    };
    let mut b = BuilderData::new();
    b.append_raw(&hex("b_hex"), 768).unwrap();
    let mut root = BuilderData::new();
    root.append_raw(&hex("a_hex"), 384).unwrap();
    root.append_raw(&hex("c_hex"), 384).unwrap();
    root.checked_append_reference(b.into_cell().unwrap()).unwrap();
    root.into_cell().unwrap()
}

/// A test-only ML-DSA-44 signer. The chain ships a verifier only; this exists
/// so the suite can reach step 11 with signatures the chain accepts, and its
/// interoperability with this chain's verifier is proved by the authorization
/// suite rather than assumed here.
struct Key {
    public_bytes: [u8; 1312],
    secret: ml_dsa_44::PrivateKey,
}

impl Key {
    fn generate() -> Self {
        let (public, secret) = ml_dsa_44::try_keygen().expect("ML-DSA-44 key generation");
        Key { public_bytes: public.into_bytes(), secret }
    }

    /// Section 9.4: the digest's raw bytes under the fixed context.
    fn authorize(&self, digest: &Field) -> [u8; 2420] {
        self.secret.try_sign(digest, b"TOS-SHIELDED-POOL-MLDSA44-v1").expect("ML-DSA-44 signing")
    }
}

/// One transact message, with every piece reachable so a test can break
/// exactly one rule and leave the others intact.
struct Transact {
    valid_until: u32,
    anchor_kind: u8,
    anchor_id: u32,
    anchor_root: Field,
    nullifiers: [Field; 2],
    witnesses: [Cell; 2],
    note_bodies: [Field; 3],
    intent_digest: Field,
    keys: [Cell; 2],
    signatures: [Cell; 2],
    public_amount_out: u64,
    withdrawal_fee: u64,
    /// `None` is `addr_none`, which is the only recipient a transfer may name.
    recipient: Option<Field>,
    recovery_owner_commitment: Field,
    recovery_data: Cell,
}

impl Transact {
    fn body(&self) -> Cell {
        let mut proof = BuilderData::new();
        proof.append_raw(&self.anchor_root, 256).unwrap();
        proof.append_raw(&self.nullifiers[0], 256).unwrap();
        proof.append_raw(&self.nullifiers[1], 256).unwrap();
        let mut bodies = BuilderData::new();
        for body in &self.note_bodies {
            bodies.append_raw(body, 256).unwrap();
        }
        proof.checked_append_reference(bodies.into_cell().unwrap()).unwrap();
        proof.checked_append_reference(groth16_proof()).unwrap();

        let mut output = BuilderData::new();
        output.append_raw(&self.recovery_owner_commitment, 256).unwrap();
        for seed in 0..3u8 {
            output.checked_append_reference(byte_chain(&payload(seed))).unwrap();
        }
        output.checked_append_reference(self.recovery_data.clone()).unwrap();

        let auth = refs_only(&[
            self.keys[0].clone(),
            self.signatures[0].clone(),
            self.keys[1].clone(),
            self.signatures[1].clone(),
        ]);

        let mut builder = BuilderData::new();
        builder.append_u32(OP_TRANSACT).unwrap();
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
        builder.checked_append_reference(proof.into_cell().unwrap()).unwrap();
        builder.checked_append_reference(output.into_cell().unwrap()).unwrap();
        builder.checked_append_reference(auth).unwrap();
        builder.checked_append_reference(refs_only(&self.witnesses)).unwrap();
        builder.into_cell().expect("a transact body")
    }
}

fn empty_ring_holder() -> Cell {
    let mut builder = BuilderData::new();
    builder.append_bit_zero().unwrap();
    builder.into_cell().unwrap()
}

fn config_store() -> Cell {
    let mut chain = BuilderData::new();
    store_coins(&mut chain, TOS as u128);
    let mut builder = BuilderData::new();
    builder.append_raw(&[0x11; 32], 256).unwrap();
    builder.append_raw(&[0x22; 32], 256).unwrap();
    builder.append_raw(&[0x33; 32], 256).unwrap();
    store_coins(&mut builder, CONFIG_WITHDRAWAL_FEE as u128);
    builder.append_u8(1).unwrap();
    builder.checked_append_reference(chain.into_cell().unwrap()).unwrap();
    builder.into_cell().expect("a config store")
}

/// The development verifying key, so that the Groth16 step fails on the
/// equation rather than on reading a point. Arbitrary bytes are refused by
/// blst while it is still decoding them, and the test would then never learn
/// whether the handler reached the equation at all.
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

fn genesis_state(nullifier_root: Field) -> Cell {
    let mut builder = BuilderData::new();
    builder.append_u32(MAGIC).unwrap();
    builder.append_u16(VERSION).unwrap();
    builder.append_raw(&EMPTY_ROOTS[DEPTH], 256).unwrap();
    builder.append_u64(0).unwrap();
    builder.append_raw(&nullifier_root, 256).unwrap();
    builder.append_u64(1).unwrap();
    builder.append_u32(EPOCH_NONE).unwrap();
    store_coins(&mut builder, 0);
    store_coins(&mut builder, RESERVE_FLOOR as u128);
    builder.checked_append_reference(shielded_pool_library::frontier_holder()).unwrap();
    builder
        .checked_append_reference(refs_only(&[empty_ring_holder(), empty_ring_holder()]))
        .unwrap();
    builder.checked_append_reference(config_store()).unwrap();
    builder.checked_append_reference(vk_store()).unwrap();
    builder.into_cell().expect("the genesis state")
}

/// The configured withdrawal fee and the one configured denomination, which
/// the genesis state above fixes. A withdrawal that does not match both is
/// refused before it reaches the proof.
///
/// The fee is above the boundary the payout suite measures -- 205,313,600 at
/// the profile's 500,000 gas bounce ceiling and this chain's gas price -- so a
/// withdrawal configured this way could actually pay out. A smaller fee would
/// fail section 14.2's solvency check at step 16, which is after the proof and
/// therefore out of this suite's reach; configuring it below the boundary
/// would leave that unsaid rather than untrue.
const CONFIG_WITHDRAWAL_FEE: u64 = 50_000_000;
const DENOMINATION: u64 = TOS;

/// Turn a well-formed transfer into a well-formed withdrawal: an amount the
/// configuration admits, the fee it fixes, a recipient, and the recovery
/// material a withdrawal has to pre-authorise.
fn withdrawing(mut message: Transact, recipient: Field) -> Transact {
    message.public_amount_out = DENOMINATION;
    message.withdrawal_fee = CONFIG_WITHDRAWAL_FEE;
    message.recipient = Some(recipient);
    message.recovery_owner_commitment = small(0x5eed);
    message.recovery_data = byte_chain(&payload(9));
    message
}

struct Pool {
    bc: Blockchain,
    addr: MsgAddressInt,
    payer: tos_sandbox::Treasury,
}

impl Pool {
    fn deploy(nullifier_root: Field) -> Self {
        Self::deploy_with_gas_limit(nullifier_root, None)
    }

    /// `limit` replaces the network's per-transaction gas ceiling. This chain
    /// grants 30,000,000, so the only use left for this is the opposite of
    /// what it was built for: starving a transaction on a network configured
    /// like TON's basechain, to show what the contract's own ceiling is
    /// protecting against.
    fn deploy_with_gas_limit(nullifier_root: Field, limit: Option<u64>) -> Self {
        let mut bc = match limit {
            None => Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
                .expect("blockchain at version 17"),
            Some(limit) => {
                let base =
                    tos_executor::BlockchainConfig::default_with_global_version(ACTIVE_VERSION)
                        .expect("a configuration");
                let mut raw = base.raw_config().clone();
                let mut prices = raw.gas_prices(false).expect("basechain gas prices");
                prices.gas_limit = limit;
                prices.block_gas_limit = limit.max(prices.block_gas_limit);
                raw.set_config(chain_block::ConfigParamEnum::ConfigParam21(prices))
                    .expect("raise the gas limit");
                // Rebuilding a configuration from its raw parameters needs this
                // one, which the default builder supplies separately.
                raw.set_config(chain_block::ConfigParamEnum::ConfigParam31(
                    chain_block::ConfigParam31::default(),
                ))
                .expect("fundamental addresses");
                let mut bc = Blockchain::with_config(raw).expect("blockchain");
                bc.set_workchain(0);
                bc
            }
        };
        bc.set_workchain(0);
        let payer = bc.treasury("relay", 100_000 * TOS).expect("treasury");
        let code = compile_func_with_stdlib(&shielded_pool_library::pool_sources())
            .expect("compile the pool (needs build/crypto/func)");
        let si = StateInit::with_code_and_data(code, genesis_state(nullifier_root));
        let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let addr = MsgAddressInt::with_params(0, hash).unwrap();
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 20 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )
        .expect("deploy")
        .expect_success();
        Self { bc, addr, payer }
    }

    fn get(&self, method: &str) -> String {
        let result = self
            .bc
            .run_get_method(&self.addr, method, vec![])
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        assert_eq!(result.exit_code, 0, "{method} exited {}", result.exit_code);
        result.stack.last().expect("a result").as_integer().expect("integer").to_string()
    }

    /// Everything a successful transact would change, so a failure can be
    /// required to change none of it.
    fn snapshot(&self) -> Vec<String> {
        [
            "commitment_root",
            "commitment_next_index",
            "nullifier_root",
            "nullifier_next_index",
            "native_liability",
            "reserve_floor",
        ]
        .iter()
        .map(|method| self.get(method))
        .collect()
    }

    fn send(&mut self, value: u64, body: Cell) -> SendResult {
        let msg = MessageBuilder::internal(self.payer.address(), &self.addr, value)
            .bounce(true)
            .body(body)
            .build();
        self.bc.send_message(msg).expect("send")
    }

    fn exit_of(&mut self, value: u64, body: Cell) -> i32 {
        self.run(value, body).0
    }

    /// The exit code and the gas it took to get there.
    fn run(&mut self, value: u64, body: Cell) -> (i32, i64) {
        let result = self.send(value, body);
        match result.read_primary_description().compute_ph {
            chain_block::TrComputePhase::Vm(vm) => {
                (vm.exit_code, vm.gas_used.to_string().parse().expect("gas used"))
            }
            chain_block::TrComputePhase::Skipped(s) => panic!("compute skipped: {:?}", s.reason),
        }
    }
}

/// A transact that is correct in every respect this branch can make correct:
/// a valid anchor, two witnesses against the genesis nullifier tree, two real
/// signatures over the digest, and a proof that cannot be real.
fn well_formed(state: &RefState, keys: &[Key; 2], digest: Field) -> Transact {
    let nf0 = small(101);
    let nf1 = small(202);
    // The second witness is against the tree the first insertion leaves, which
    // is what section 16.2 step 10 means by "sequentially".
    let mut after_first = state.clone();
    let (witness_0, _, _, tree_after_first) = after_first.witness_for(&nf0);
    after_first.apply(tree_after_first);
    let (witness_1, _, _, _) = after_first.witness_for(&nf1);
    Transact {
        valid_until: 0,
        anchor_kind: 0,
        anchor_id: 0,
        anchor_root: EMPTY_ROOTS[DEPTH],
        nullifiers: [nf0, nf1],
        witnesses: [encode_witness(&witness_0), encode_witness(&witness_1)],
        note_bodies: [small(301), small(302), small(303)],
        intent_digest: digest,
        keys: [byte_chain(&keys[0].public_bytes), byte_chain(&keys[1].public_bytes)],
        signatures: [
            byte_chain(&keys[0].authorize(&digest)),
            byte_chain(&keys[1].authorize(&digest)),
        ],
        public_amount_out: 0,
        withdrawal_fee: 0,
        recipient: None,
        recovery_owner_commitment: ZERO,
        recovery_data: Cell::default(),
    }
}

// ---------------------------------------------------------------------------

/// Section 16.2 is an order. Each case breaks one rule and requires the
/// failure to carry that rule's own code: if the handler did the work in a
/// different order, an earlier rule's code would come back instead.
#[test]
fn each_step_fails_with_its_own_code_and_in_its_own_place() {
    let state = RefState::genesis();
    let keys = [Key::generate(), Key::generate()];
    let digest = small(0x1234_5678_9abc_def0);
    let mut pool = Pool::deploy(state.root());
    let now = pool.bc.now();

    let good = || {
        let mut message = well_formed(&state, &keys, digest);
        message.valid_until = now + 60;
        message
    };

    // Step 2: funding, before anything else. Even a message whose every other
    // field is wrong must fail here first.
    let mut broken = good();
    broken.anchor_root = small(1);
    broken.nullifiers[0] = small(1);
    assert_eq!(
        pool.exit_of(transact_fee() - 1, broken.body()),
        203,
        "an underfunded message was judged on its contents"
    );

    // Step 5, the withdrawal half: an amount the configuration does not admit
    // is refused, and so is a fee that is not the one the configuration fixed.
    // Both are checked before any expensive work.
    let mut odd_amount = withdrawing(good(), small(0x11));
    odd_amount.public_amount_out = DENOMINATION + 1;
    assert_eq!(
        pool.exit_of(transact_fee(), odd_amount.body()),
        202,
        "an amount outside the denomination list was paid out"
    );
    let mut wrong_fee = withdrawing(good(), small(0x11));
    wrong_fee.withdrawal_fee = CONFIG_WITHDRAWAL_FEE - 1;
    assert_ne!(
        pool.exit_of(transact_fee(), wrong_fee.body()),
        0,
        "a fee other than the configured one was accepted"
    );

    // An amount with nobody to send it to, and a recipient with nothing to
    // send: neither is a withdrawal this contract will start.
    let mut unaddressed = withdrawing(good(), small(0x11));
    unaddressed.recipient = None;
    assert_eq!(
        pool.exit_of(transact_fee(), unaddressed.body()),
        238,
        "a withdrawal with no recipient was accepted"
    );
    let mut addressed_transfer = good();
    addressed_transfer.recipient = Some(small(0x11));
    assert_eq!(
        pool.exit_of(transact_fee(), addressed_transfer.body()),
        239,
        "a transfer that named a recipient was accepted"
    );

    // Step 5: the intent's hour.
    let mut stale = good();
    stale.valid_until = now - 1;
    assert_eq!(pool.exit_of(transact_fee(), stale.body()), 140, "a stale intent was accepted");
    let mut far = good();
    far.valid_until = now + 3601;
    assert_eq!(
        pool.exit_of(transact_fee(), far.body()),
        141,
        "an intent beyond the hour was accepted"
    );

    // Step 9: the anchor. A root this pool never held is not an anchor, even
    // though everything after it would have been fine.
    let mut forged_anchor = good();
    forged_anchor.anchor_root = small(7);
    assert_eq!(
        pool.exit_of(transact_fee(), forged_anchor.body()),
        152,
        "a root the pool never held was accepted as the current anchor"
    );
    let mut wrong_kind = good();
    wrong_kind.anchor_kind = 3;
    assert_eq!(
        pool.exit_of(transact_fee(), wrong_kind.body()),
        151,
        "an unknown anchor kind passed"
    );
    let mut recent = good();
    recent.anchor_kind = 1;
    assert_eq!(
        pool.exit_of(transact_fee(), recent.body()),
        153,
        "an empty recent slot was accepted"
    );

    // Step 10: the witnesses, before the signatures. A witness for the wrong
    // nullifier must fail as a witness and not as a signature.
    let mut swapped = good();
    swapped.witnesses.swap(0, 1);
    let exit = pool.exit_of(transact_fee(), swapped.body());
    assert!(
        (100..=129).contains(&exit),
        "a mismatched witness failed with {exit}, which is not the nullifier tree's"
    );

    // Step 11: the signatures, before the proof. A signature over another
    // digest must fail as a signature and not as a proof.
    let mut misauthorized = good();
    let other = small(999);
    misauthorized.signatures[1] = byte_chain(&keys[1].authorize(&other));
    assert_eq!(
        pool.exit_of(transact_fee(), misauthorized.body()),
        138,
        "a signature over another digest was accepted"
    );
    // An attacker's own valid key pair passes step 11 -- the signatures verify,
    // because they are that attacker's -- and is stopped later, where the
    // proof binds the key hashes the note committed to. On this network the
    // path runs out of gas before it gets there, which the measurement test
    // below explains; what matters here is that step 11 is not where it is
    // caught, so the signature check is not doing work the proof must do.
    let mut impostor = good();
    let attacker = Key::generate();
    impostor.keys[0] = byte_chain(&attacker.public_bytes);
    impostor.signatures[0] = byte_chain(&attacker.authorize(&digest));
    let exit = pool.exit_of(transact_fee(), impostor.body());
    assert!(
        exit != 137 && exit != 138,
        "an attacker's own key pair was refused as a bad signature ({exit}), which it is not"
    );
}

/// Section 19 gate 11, for every path that fails: a throw at any step leaves
/// the state exactly as it was. There is no COMMIT in the handler, so the
/// successful return is the only commit boundary.
#[test]
fn a_failure_at_any_step_changes_nothing() {
    let state = RefState::genesis();
    let keys = [Key::generate(), Key::generate()];
    let digest = small(0x5555_6666_7777_8888);
    let mut pool = Pool::deploy(state.root());
    let now = pool.bc.now();
    let before = pool.snapshot();

    let good = || {
        let mut message = well_formed(&state, &keys, digest);
        message.valid_until = now + 60;
        message
    };

    let mut cases: Vec<(&str, Cell, u64)> = Vec::new();
    cases.push(("underfunded", good().body(), transact_fee() - 1));
    let mut withdrawing = good();
    withdrawing.public_amount_out = TOS;
    cases.push(("a withdrawal", withdrawing.body(), transact_fee()));
    let mut stale = good();
    stale.valid_until = now - 1;
    cases.push(("a stale intent", stale.body(), transact_fee()));
    let mut forged = good();
    forged.anchor_root = small(7);
    cases.push(("a forged anchor", forged.body(), transact_fee()));
    let mut swapped = good();
    swapped.witnesses.swap(0, 1);
    cases.push(("mismatched witnesses", swapped.body(), transact_fee()));
    let mut misauthorized = good();
    misauthorized.signatures[0] = byte_chain(&keys[0].authorize(&small(1)));
    cases.push(("a wrong signature", misauthorized.body(), transact_fee()));

    for (what, body, value) in cases {
        let exit = pool.exit_of(value, body);
        assert_ne!(exit, 0, "{what}: the message was accepted");
        assert_eq!(pool.snapshot(), before, "{what}: a failed transact left the state changed");
    }
}

/// The proof is the last thing standing between a well-formed message and the
/// pool's money, so it gets a test of its own rather than a line in the list
/// above: on the default network the path runs out of gas long before the
/// pairing, and a message that dies of gas says nothing about whether the
/// proof was ever checked.
#[test]
fn a_proof_that_does_not_verify_stops_the_transaction() {
    let state = RefState::genesis();
    let keys = [Key::generate(), Key::generate()];
    let digest = small(0x1234_5678_9abc_def0);
    let mut pool = Pool::deploy(state.root());
    let now = pool.bc.now();
    let before = pool.snapshot();

    // Everything before the proof is in order: funding, window, anchor,
    // witnesses and signatures all pass. Only the proof does not verify.
    let mut message = well_formed(&state, &keys, digest);
    message.valid_until = now + 60;
    assert_eq!(
        pool.exit_of(transact_fee() * 8, message.body()),
        262,
        "a message with an unverifiable proof was not stopped by the proof"
    );
    assert_eq!(pool.snapshot(), before, "a proof that did not verify still moved the state");
}

/// A withdrawal gets as far as a transfer does. Every check that only a
/// withdrawal faces -- the denomination, the configured fee, the recipient,
/// the pre-authorised recovery material -- is behind it by the time the proof
/// is reached, so reaching the proof is what says the withdrawal half of the
/// handler accepts a well-formed withdrawal.
///
/// It cannot go further than that here. Step 16 is after step 12, and this
/// branch has no proof that verifies, so the payout itself has no end-to-end
/// test. What it has is a library suite of its own and this: the handler
/// admits a withdrawal to the point where only the proof stands in the way.
#[test]
fn a_well_formed_withdrawal_reaches_the_proof_like_a_transfer_does() {
    let state = RefState::genesis();
    let keys = [Key::generate(), Key::generate()];
    let digest = small(0x7777_8888_9999_aaaa);
    let mut pool = Pool::deploy(state.root());
    let now = pool.bc.now();
    let before = pool.snapshot();

    let mut message = withdrawing(well_formed(&state, &keys, digest), small(0x4242));
    message.valid_until = now + 60;

    let (exit, used) = pool.run(transact_fee() * 8, message.body());
    assert_eq!(exit, 262, "a well-formed withdrawal was stopped before the proof");
    assert_eq!(pool.snapshot(), before, "a withdrawal that failed at the proof moved the state");
    eprintln!("a withdrawal, up to and including the proof: {used} gas");
}

/// Where the gas goes. A message that fails at step N has paid for steps 1
/// through N, so the cost of each step is the difference between two failures
/// -- no instrumentation, no estimate, and nothing the contract does not
/// really do. The ceiling question below is a question about which of these
/// numbers can be made smaller, so it needs them.
#[test]
fn what_a_transact_spends_and_where() {
    let state = RefState::genesis();
    let keys = [Key::generate(), Key::generate()];
    let digest = small(0x2222_3333_4444_5555);
    let mut pool = Pool::deploy(state.root());
    let now = pool.bc.now();
    let value = transact_fee() * 8;

    let good = || {
        let mut message = well_formed(&state, &keys, digest);
        message.valid_until = now + 60;
        message
    };

    // Each message is correct up to the step named and wrong at it, so the
    // gas it burned is the cost of everything before that step.
    let mut stale = good();
    stale.valid_until = now - 1;
    let mut forged = good();
    forged.anchor_root = small(7);
    // Wrong from the start: the first insertion rejects it.
    let mut swapped = good();
    swapped.witnesses.swap(0, 1);
    // Right for the first insertion and wrong for the second: the second
    // witness agrees with the tree as it was, not with the tree the first
    // insertion left. So this one pays for a whole insertion first.
    let mut stale_second = good();
    let (witness_1, _, _, _) = state.clone().witness_for(&small(202));
    stale_second.witnesses[1] = encode_witness(&witness_1);
    let mut misauthorized = good();
    misauthorized.signatures[0] = byte_chain(&keys[0].authorize(&small(1)));

    let stages: Vec<(&str, Cell)> = vec![
        ("parse and the validity window", stale.body()),
        ("+ the anchor", forged.body()),
        ("+ the first insertion, rejected at its witness", swapped.body()),
        ("+ one whole insertion, the second rejected", stale_second.body()),
        ("+ both insertions and the first authorization", misauthorized.body()),
        ("+ the second authorization and the proof", good().body()),
    ];

    let mut previous = 0i64;
    let mut reached_proof = 0i64;
    for (what, body) in stages {
        let (exit, used) = pool.run(value, body);
        assert_ne!(exit, 0, "{what}: the message was accepted");
        assert!(
            used > previous,
            "{what}: cost {used} gas, no more than the step before it ({previous})"
        );
        eprintln!("{used:>9}  (+{:>8})  {what}", used - previous);
        previous = used;
        reached_proof = used;
    }

    // The total is what the suite reports elsewhere; this test's claim is the
    // shape of the breakdown, not the total.
    //
    // It used to assert this was above a million, because it was. At global
    // version 18 the two insertions stopped walking their paths in FunC and
    // the whole path to the proof came to 825,393 -- under the 1,000,000 a
    // TON basechain grants a transaction, which is the figure the gas budget
    // work spent a day being wrong about. The bound is kept, pointing the
    // other way, so that losing the saving is loud.
    assert!(
        reached_proof < 1_000_000,
        "the path to the proof costs {reached_proof} gas, back above the million a TON \
         basechain grants; POSEIDON2_PATH7 brought it to 825,393 and something has undone that"
    );
}

/// What a transact costs, measured rather than estimated, against the two
/// limits that actually bound it.
///
/// This test used to assert that the path did not fit "the network", having
/// measured it against the executor's default table -- which carried TON's
/// basechain limit of 1,000,000 while this chain's zero state grants
/// 30,000,000. The claim was false for this chain by a factor of twenty-seven.
/// `chain_gas_envelope_sandbox.rs` now generates the zero state and holds the
/// two tables together, and what is left to say here is what the path costs
/// and how much room it has.
#[test]
fn a_transact_fits_its_ceiling_and_the_gas_this_chain_grants() {
    // Section 14.1. Unlike the network limit, this one the contract sets on
    // itself, and it is the binding one: it is far below what the chain
    // grants, which is the point of having it.
    let ceiling = transact_gas_ceiling();
    /// ConfigParam 21 of this chain's zero state.
    const BASECHAIN_GAS_LIMIT: i64 = 30_000_000;

    let state = RefState::genesis();
    let keys = [Key::generate(), Key::generate()];
    let digest = small(0x0f0f_0f0f_0f0f_0f0f);
    let mut pool = Pool::deploy(state.root());
    let now = pool.bc.now();
    let mut message = well_formed(&state, &keys, digest);
    message.valid_until = now + 60;

    let (exit, used) = pool.run(transact_fee() * 8, message.body());
    assert_eq!(exit, 262, "the message did not reach the proof on an ordinary network");
    eprintln!(
        "a transact, up to and including the proof: {used} gas          ({}% of the ceiling, {}% of what the chain grants)",
        used * 100 / ceiling,
        used * 100 / BASECHAIN_GAS_LIMIT
    );

    assert!(
        used < ceiling,
        "the path uses {used} gas and no longer fits the profile's own ceiling of          {ceiling}"
    );
    assert!(
        used < BASECHAIN_GAS_LIMIT,
        "the path uses {used} gas and no longer fits what this chain grants a transaction"
    );

    // Section 14's deployment invariant, in full:
    //
    //     MEASURED_MAX_VALID_GAS < operation_gas_ceiling <= workchain gas_limit
    //
    // Both halves matter and for opposite reasons. A ceiling above what the
    // chain grants buys nothing, because SETGASLIMIT cannot raise a
    // transaction above the network's own limit. A ceiling below what the path
    // needs stops the path. The transact ceiling is the binding one here: it
    // is far below what the chain grants, which is the point of having it.
    assert!(
        ceiling <= BASECHAIN_GAS_LIMIT,
        "the contract's ceiling is above what the chain grants, so it can never take effect"
    );

    // And the middle term is the one the production rule gives, applied to the
    // derived bound rather than to a measurement:
    //
    //     C = max(10,000, round_up_10,000(ceil(M * 5 / 4)))
    //
    // `TRANSACT_DERIVED_BOUND_GAS` carried that measurement and nothing read
    // it -- a number written down, never compared to anything, free to drift
    // away from both the contract and the measurement it came from. The
    // crosscheck crate holds the same rule against a pool it has aged, which
    // is where the measurement is taken; this holds it against the contract,
    // which is what a reader of this file can see.
    let by_rule = |measured: i64| -> i64 {
        let with_headroom = (measured * 5 + 3) / 4;
        10_000.max((with_headroom + 9_999) / 10_000 * 10_000)
    };
    assert_eq!(
        ceiling,
        by_rule(TRANSACT_DERIVED_BOUND_GAS),
        "the transact ceiling is {ceiling}, not the {} the production rule gives for a \
         derived bound of {TRANSACT_DERIVED_BOUND_GAS}",
        by_rule(TRANSACT_DERIVED_BOUND_GAS)
    );

    // And a network that grants less than the path needs stops it, which is
    // what the ceiling is protecting against on a chain configured otherwise.
    //
    // This used to starve the path at 1,000,000. It no longer starves there:
    // since global version 18 the whole path to the proof is 825,393, so the
    // figure has to be one that is actually short of it.
    let mut starved = Pool::deploy_with_gas_limit(RefState::genesis().root(), Some(500_000));
    let now = starved.bc.now();
    let mut same = well_formed(&RefState::genesis(), &keys, digest);
    same.valid_until = now + 60;
    assert_eq!(
        starved.exit_of(transact_fee() * 8, same.body()),
        -14,
        "a network granting 500,000 gas ran the whole path after all"
    );
}
