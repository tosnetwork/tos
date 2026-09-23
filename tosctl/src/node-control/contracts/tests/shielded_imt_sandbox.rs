/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Section 7 of the V1 implementation profile, run in the VM: the nullifier
//! indexed Merkle tree, its empty-subtree ladder and genesis root, the eight
//! numbered steps of the non-membership/insertion contract, and the canonical
//! witness cell encoding of 7.2.
//!
//! The check worth the most here is the one that is not a restatement. The
//! contract folds a 72-element path into a root, which is an incremental
//! computation over a witness the caller supplied. The reference below never
//! folds a path: it keeps a plain map from leaf index to leaf tuple and rebuilds
//! every level of the tree from every allocated leaf. The two agree at every
//! step or the test fails, so a path that happens to fold to a plausible root
//! cannot pass unnoticed.
//!
//! What this cannot establish: that these are the semantics the circuit will
//! enforce. The FunC and the reference below were both written from section 7,
//! so a misreading of that section would be reproduced in both, and the
//! agreement above would not detect it. Only the circuit (WP-C), which does not
//! exist yet, settles that. Nor does anything here establish gas cost: these are
//! get-methods, not a transaction against the pool contract.
//!
//! This file deliberately derives the FunC library path from CARGO_MANIFEST_DIR
//! rather than from TOS_ROOT. TOS_ROOT points at whichever checkout owns the
//! built compiler, which is not necessarily the checkout that owns this test.

use std::collections::BTreeMap;

use chain_block::poseidon2::permute;
use chain_block::poseidon2_kat::{DOMAINS, EMPTY_ROOTS};
use chain_block::{
    BuilderData, Cell, CellType, IBitstring, MsgAddressInt, Serializable, StateInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;
use tos_vm::stack::integer::IntegerData;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
const DEPTH: usize = 12;
const ARITY: u64 = 7;
const PATH_FIELDS: usize = DEPTH * 6;
const PATH_CELLS: usize = 24;
/// The first leaf index that may not be allocated: section 7's logical maximum.
const CAPACITY: u64 = 1 << 32;
const FIELD_MODULUS_DEC: &str =
    "52435875175126190479447740508185965837690552500527637822603658699938581184513";

type Field = [u8; 32];
const ZERO: Field = [0u8; 32];

// ---------------------------------------------------------------------------
// Decimal transport. A 256-bit value never becomes an i64 anywhere in this file.

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
        assert!(ch.is_ascii_digit(), "not a decimal integer: {text}");
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

fn field_modulus() -> Field {
    from_dec(FIELD_MODULUS_DEC)
}

// ---------------------------------------------------------------------------
// Reference: section 7 written out directly, over a plain map of leaves.

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

/// The two exotic cells worth trying. A pruned branch is refused by the VM
/// before any contract code runs, with its own exception; a Merkle proof is one
/// the VM will still load, so it reaches `begin_parse` and is refused there.
/// Both are fail-closed, and the pair covers both sides of that boundary.
#[derive(Clone, Copy, Debug)]
enum Exotic {
    PrunedBranch,
    MerkleProof,
}

fn pruned_branch() -> Cell {
    let mut builder = BuilderData::new();
    builder.set_type(CellType::PrunedBranch);
    builder.append_u8(u8::from(CellType::PrunedBranch)).expect("type byte");
    builder.append_u8(1).expect("level mask");
    builder.append_raw(&[0xab; 32], 256).expect("hash");
    builder.append_u16(0).expect("depth");
    builder.into_cell().expect("pruned branch cell")
}

fn merkle_proof_cell(inner: Cell) -> Cell {
    let mut builder = BuilderData::new();
    builder.set_type(CellType::MerkleProof);
    builder.append_u8(u8::from(CellType::MerkleProof)).expect("type byte");
    builder.append_raw(inner.hash(0).as_slice(), 256).expect("hash");
    builder.append_u16(inner.depth(0)).expect("depth");
    builder.checked_append_reference(inner).expect("proof reference");
    builder.into_cell().expect("merkle proof cell")
}

fn exotic_cell(kind: Exotic, inner: Cell) -> Cell {
    match kind {
        Exotic::PrunedBranch => pruned_branch(),
        Exotic::MerkleProof => merkle_proof_cell(inner),
    }
}

/// The path chain from `from` onwards, built the canonical way.
fn path_tail(fields: &[Field], from: usize) -> Option<Cell> {
    let cells = fields.len() / 3;
    let mut chain: Option<Cell> = None;
    for index in (from..cells).rev() {
        let mut builder = BuilderData::new();
        for offset in 0..3 {
            builder.append_raw(&fields[index * 3 + offset], 256).expect("a path field");
        }
        if let Some(next) = chain {
            builder.checked_append_reference(next).expect("the chain reference");
        }
        chain = Some(builder.into_cell().expect("a path cell"));
    }
    chain
}

/// The same chain with the cell at `position` replaced by an exotic one, which
/// takes over the rest of the chain as its own reference where it can.
fn path_with_exotic(fields: &[Field], position: usize, kind: Exotic) -> Cell {
    let tail = path_tail(fields, position + 1).unwrap_or_default();
    let mut chain = exotic_cell(kind, tail);
    for index in (0..position).rev() {
        let mut builder = BuilderData::new();
        for offset in 0..3 {
            builder.append_raw(&fields[index * 3 + offset], 256).expect("a path field");
        }
        builder.checked_append_reference(chain).expect("the chain reference");
        chain = builder.into_cell().expect("a path cell");
    }
    chain
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

const PROBE: &str = r#"
int p_unallocated() method_id { return imt_unallocated_leaf(); }
int p_empty(int level) method_id { return imt_empty_at(level); }
int p_genesis() method_id { return imt_genesis_root(); }
int p_leaf(int value, int next_index, int next_value) method_id {
  return imt_leaf_hash(value, next_index, next_value);
}
int p_require_allocated(int leaf) method_id {
  return imt_require_allocated_leaf_hash(leaf);
}
int p_node(int c0, int c1, int c2, int c3, int c4, int c5, int c6) method_id {
  return imt_node(c0, c1, c2, c3, c4, c5, c6);
}
int p_root(cell path, int index, int leaf) method_id {
  return imt_root_from_path(path, index, leaf);
}
(int, int) p_insert(int root, int next_index, int nf, cell witness) method_id {
  return imt_insert(root, next_index, nf, witness);
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
        // The library belongs to the checkout that owns this test file, which
        // is not necessarily the checkout TOS_ROOT points at.
        let library = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont/shielded");
        let probe_path = std::env::temp_dir().join("tos_shielded_imt_probe.fc");
        std::fs::write(&probe_path, PROBE).expect("write probe");
        let code = compile_func_with_stdlib(&[
            format!("{library}/domains.fc").into(),
            format!("{library}/notes.fc").into(),
            format!("{library}/imt.fc").into(),
            probe_path,
        ])
        .expect("compile the shielded library (needs build/crypto/func)");
        let mut data = BuilderData::new();
        data.append_u32(0).expect("probe data");
        let si = StateInit::with_code_and_data(code, data.into_cell().expect("probe data cell"));
        let addr_hash = si
            .write_to_new_cell()
            .expect("state init cell")
            .into_cell()
            .expect("state init cell")
            .hash(0);
        let addr = MsgAddressInt::with_params(0, addr_hash).expect("probe address");
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

    fn counter_arg(value: u64) -> StackItem {
        StackItem::integer(
            IntegerData::from_str_radix(&value.to_string(), 10).expect("counter as integer"),
        )
    }

    fn call_field(&self, method: &str, args: Vec<StackItem>) -> Field {
        let result = self
            .bc
            .run_get_method(&self.addr, method, args)
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        assert_eq!(result.exit_code, 0, "{method} exited {}", result.exit_code);
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

    fn fields(&self, method: &str, args: &[Field]) -> Field {
        self.call_field(method, args.iter().map(Self::field_arg).collect())
    }

    fn empty_at(&self, level: u64) -> Field {
        self.call_field("p_empty", vec![Self::counter_arg(level)])
    }

    fn root_from_path(&self, path: &Cell, index: u64, leaf: &Field) -> Field {
        self.call_field(
            "p_root",
            vec![StackItem::Cell(path.clone()), Self::counter_arg(index), Self::field_arg(leaf)],
        )
    }

    fn root_from_path_exit(&self, path: &Cell, index: &str, leaf: &Field) -> i32 {
        let args = vec![
            StackItem::Cell(path.clone()),
            StackItem::integer(IntegerData::from_str_radix(index, 10).expect("index")),
            Self::field_arg(leaf),
        ];
        self.bc.run_get_method(&self.addr, "p_root", args).expect("p_root should run").exit_code
    }

    fn insert_args(root: &Field, next_index: u64, nf: &Field, witness: &Cell) -> Vec<StackItem> {
        vec![
            Self::field_arg(root),
            Self::counter_arg(next_index),
            Self::field_arg(nf),
            StackItem::Cell(witness.clone()),
        ]
    }

    /// Returns the new nullifier root and the new next index.
    fn insert(&self, root: &Field, next_index: u64, nf: &Field, witness: &Cell) -> (Field, u64) {
        let result = self
            .bc
            .run_get_method(
                &self.addr,
                "p_insert",
                Self::insert_args(root, next_index, nf, witness),
            )
            .expect("p_insert should run");
        assert_eq!(result.exit_code, 0, "p_insert exited {}", result.exit_code);
        assert_eq!(result.stack.len(), 2, "p_insert must return a root and a next index");
        let text = result.stack[0].as_integer().expect("the new root is an integer").to_string();
        let new_root = from_dec(&text);
        assert_eq!(dec(&new_root), text, "p_insert: the root round trip is not exact");
        let counter =
            result.stack[1].as_integer().expect("the next index is an integer").to_string();
        let next = counter.parse::<u64>().expect("the next index is a uint64");
        (new_root, next)
    }

    /// The sentinel guard, called directly. Returns the exit code and, when it
    /// let the value through, the value it returned.
    fn require_allocated(&self, leaf: &Field) -> (i32, Option<Field>) {
        let result = self
            .bc
            .run_get_method(&self.addr, "p_require_allocated", vec![Self::field_arg(leaf)])
            .expect("p_require_allocated should run");
        if result.exit_code != 0 {
            return (result.exit_code, None);
        }
        let text = result
            .stack
            .last()
            .expect("a result")
            .as_integer()
            .expect("the result is an integer")
            .to_string();
        (0, Some(from_dec(&text)))
    }

    fn insert_exit(&self, root: &Field, next_index: u64, nf: &Field, witness: &Cell) -> i32 {
        self.bc
            .run_get_method(
                &self.addr,
                "p_insert",
                Self::insert_args(root, next_index, nf, witness),
            )
            .expect("p_insert should run")
            .exit_code
    }
}

/// One full insertion checked end to end: the contract's roots and counter
/// against a tree rebuilt from every leaf, then the reference state advanced.
fn insert_and_check(probe: &Probe, state: &mut RefState, nf: &Field, what: &str) {
    let before = state.root();
    let (witness, root1, root2, after) = state.witness_for(nf);
    let cell = encode_witness(&witness);

    // Step 5's intermediate root, folded by the contract from the same path the
    // reference built, against the reference's rebuilt tree.
    let updated_low = Leaf {
        value: witness.low_value,
        next_index: u32::try_from(state.next_index).expect("the new index is a uint32"),
        next_value: *nf,
    };
    assert_eq!(
        probe.root_from_path(
            &encode_path(&witness.low_path),
            witness.low_index as u64,
            &imt_leaf_hash(&updated_low),
        ),
        root1,
        "{what}: the contract's step 5 root disagrees with the rebuilt tree"
    );

    let (new_root, new_next) = probe.insert(&before, state.next_index, nf, &cell);
    assert_eq!(new_root, root2, "{what}: the contract's new root disagrees with the rebuilt tree");
    assert_eq!(new_next, state.next_index + 1, "{what}: the next index did not advance by one");
    assert_ne!(new_root, before, "{what}: the root did not move");
    state.apply(after);
    assert_eq!(state.root(), new_root, "{what}: the reference and the contract diverged");
}

// ---------------------------------------------------------------------------

#[test]
fn the_empty_ladder_and_the_genesis_root_are_what_the_permutation_produces() {
    let probe = Probe::deploy();
    let empty = empty_ladder();
    assert_eq!(empty.len(), DEPTH + 1, "the ladder is not thirteen entries");
    assert_eq!(empty[0], ZERO, "an unallocated leaf must hash to field zero");
    assert_eq!(probe.call_field("p_unallocated", vec![]), ZERO, "the contract's empty leaf moved");

    for (level, value) in empty.iter().enumerate() {
        assert_eq!(
            probe.empty_at(level as u64),
            *value,
            "the contract's IMT_EMPTY[{level}] disagrees with the permutation"
        );
    }
    for level in 1..empty.len() {
        assert_ne!(empty[level], empty[level - 1], "two IMT levels share an empty root");
        // The commitment ladder is a different domain, so it must be a
        // different ladder. Reusing it here would be a silent forgery surface.
        assert_ne!(
            empty[level], EMPTY_ROOTS[level],
            "IMT_EMPTY[{level}] equals the COMMIT-NODE ladder at the same level"
        );
    }

    // The node hash itself, under its own domain.
    let children = [small(1), small(2), small(3), small(4), small(5), small(6), small(7)];
    assert_eq!(probe.fields("p_node", &children), imt_node(children), "imt_node disagrees");
    assert_ne!(
        imt_node(children),
        h7(domain("COMMIT-NODE"), children),
        "the IMT and commitment node domains collide"
    );

    // Section 7.0: the genesis root is the head sentinel at leaf 0 of the
    // otherwise empty tree, which the reference builds without any path.
    let genesis = RefState::genesis();
    let expected = genesis.root();
    assert_eq!(probe.call_field("p_genesis", vec![]), expected, "the genesis root disagrees");
    assert_ne!(expected, empty[DEPTH], "the genesis root is the empty root");
    assert_ne!(expected, ZERO, "the genesis root is zero");
    assert_eq!(genesis.next_index, 1, "the next index does not start at 1");
}

#[test]
fn an_allocated_leaf_matches_the_profile_and_binds_every_argument() {
    let probe = Probe::deploy();

    let sentinel = Leaf::sentinel();
    let sentinel_hash = probe.fields("p_leaf", &[ZERO, ZERO, ZERO]);
    assert_eq!(sentinel_hash, imt_leaf_hash(&sentinel), "the sentinel leaf hash disagrees");
    // Section 7.0: an allocated leaf must never collide with an unallocated one.
    assert_ne!(sentinel_hash, ZERO, "the head sentinel hashed to the unallocated leaf");
    assert!(dec(&sentinel_hash).len() > 70, "the leaf hash is not a full-width field element");

    let leaf = Leaf { value: small(1234), next_index: 9, next_value: small(99_999) };
    let hash =
        probe.fields("p_leaf", &[leaf.value, small(leaf.next_index as u64), leaf.next_value]);
    assert_eq!(hash, imt_leaf_hash(&leaf), "the leaf hash disagrees with the profile");
    assert_ne!(hash, ZERO, "an allocated leaf hashed to the unallocated leaf");

    // Every element of the tuple has to reach the output.
    for slot in 0..3 {
        let mut args = [leaf.value, small(leaf.next_index as u64), leaf.next_value];
        args[slot] = small(7);
        assert_ne!(
            probe.fields("p_leaf", &args),
            hash,
            "the leaf hash ignores tuple element {slot}"
        );
    }
    // The zero padding is part of the definition, not slack.
    assert_ne!(
        h7(domain("IMT-LEAF"), [leaf.value, small(9), leaf.next_value, ZERO, ZERO, ZERO, ZERO]),
        h7(domain("IMT-LEAF"), [leaf.value, small(9), leaf.next_value, small(1), ZERO, ZERO, ZERO]),
        "a padding lane does not reach the output"
    );
    // And the leaf and node domains must not be interchangeable.
    assert_ne!(
        imt_leaf_hash(&leaf),
        imt_node([leaf.value, small(9), leaf.next_value, ZERO, ZERO, ZERO, ZERO]),
        "the IMT leaf and node domains collide"
    );
}

#[test]
fn two_sequential_nullifiers_both_insert_and_match_the_rebuilt_tree() {
    let probe = Probe::deploy();
    let mut state = RefState::genesis();
    assert_eq!(probe.call_field("p_genesis", vec![]), state.root(), "genesis disagrees");

    // Section 7.1: nf0 then nf1, the second witness taken against the root that
    // the first insertion produced.
    let nf0 = from_dec("500000000000000000000000000000000000000000000000000000000000000000");
    let nf1 = from_dec("900000000000000000000000000000000000000000000000000000000000000000");
    insert_and_check(&probe, &mut state, &nf0, "nf0");
    assert_eq!(state.next_index, 2, "the first insertion did not take index 1");
    insert_and_check(&probe, &mut state, &nf1, "nf1");
    assert_eq!(state.next_index, 3, "the second insertion did not take index 2");

    // A third nullifier that lands between them exercises the branch where the
    // low leaf already has a successor, which the two above never reach.
    let between = from_dec("700000000000000000000000000000000000000000000000000000000000000000");
    let (witness, _, _, _) = state.witness_for(&between);
    assert_ne!(witness.low_next_index, 0, "the predecessor should already have a successor");
    insert_and_check(&probe, &mut state, &between, "between");

    // And a fourth below all of them, whose predecessor is the head sentinel.
    let smallest = from_dec("7");
    let (witness, _, _, _) = state.witness_for(&smallest);
    assert_eq!(witness.low_index, 0, "the smallest nullifier should follow the head sentinel");
    insert_and_check(&probe, &mut state, &smallest, "smallest");

    assert_eq!(state.next_index, 5, "four insertions did not advance the counter four times");
    assert_eq!(state.tree.leaves.len(), 5, "the reference tree lost a leaf");
}

#[test]
fn a_zero_nullifier_is_refused_by_the_head_sentinel() {
    let probe = Probe::deploy();
    let state = RefState::genesis();

    // The sentinel holds value 0 at leaf 0, so step 2's low_value < nf cannot
    // be satisfied for nf = 0 by any leaf. That is what reserves zero.
    let (witness, _, _, _) = state.witness_for(&small(1));
    let cell = encode_witness(&witness);
    assert_eq!(
        probe.insert_exit(&state.root(), state.next_index, &ZERO, &cell),
        116,
        "a zero nullifier was not refused by the ordering rule"
    );
    // The same witness with a non-zero nullifier is accepted, so the rejection
    // above is the nullifier's doing and not the witness's.
    assert_eq!(probe.insert_exit(&state.root(), state.next_index, &small(1), &cell), 0);
}

#[test]
fn a_bad_successor_tuple_is_refused() {
    let probe = Probe::deploy();
    let mut state = RefState::genesis();
    let nf0 = from_dec("500000000000000000000000000000000000000000000000000000000000000000");
    insert_and_check(&probe, &mut state, &nf0, "nf0");

    // Step 3, the bracket: a nullifier at or above the low leaf's successor is
    // not proven absent.
    let above = from_dec("600000000000000000000000000000000000000000000000000000000000000000");
    let (witness, _, _, _) = state.witness_for(&above);
    assert_eq!(witness.low_index, 1, "the predecessor of the larger value should be nf0");
    let mut forged = witness.clone();
    forged.low_next_value = small(1);
    // Membership fails first, because the low leaf hash binds the whole tuple.
    // The forged successor value keeps low_next_index at 0, so this is the
    // membership proof rejecting it and not the allocated-index rule.
    assert_eq!(
        probe.insert_exit(&state.root(), state.next_index, &above, &encode_witness(&forged)),
        115,
        "a forged successor tuple was not caught by the membership proof"
    );

    // A tree whose leaf 0 claims no successor while carrying a successor value
    // is exactly what step 3's first disjunct refuses. It has to be built by
    // hand: a correct insertion can never produce it.
    let mut malformed = RefTree::default();
    malformed.leaves.insert(0, Leaf { value: ZERO, next_index: 0, next_value: small(10) });
    let broken = RefState { tree: malformed, next_index: 1 };
    let (witness, _, _, _) = broken.witness_for(&small(5));
    assert_eq!(witness.low_next_index, 0);
    assert_eq!(witness.low_next_value, small(10));
    assert_eq!(
        probe.insert_exit(&broken.root(), broken.next_index, &small(5), &encode_witness(&witness)),
        117,
        "a tail leaf carrying a successor value was accepted"
    );

    // And the other side of step 3: a real successor that does not bracket.
    let mut bracketed = RefTree::default();
    bracketed.leaves.insert(0, Leaf { value: ZERO, next_index: 1, next_value: small(10) });
    bracketed.leaves.insert(1, Leaf { value: small(10), next_index: 0, next_value: ZERO });
    let two = RefState { tree: bracketed, next_index: 2 };
    let (witness, _, _, _) = two.witness_for(&small(4));
    assert_eq!(witness.low_index, 0, "the predecessor of 4 should be the sentinel");
    let nf_at_successor = small(10);
    let mut same = witness.clone();
    same.low_path = two.tree.path(0);
    assert_eq!(
        probe.insert_exit(&two.root(), two.next_index, &nf_at_successor, &encode_witness(&same)),
        117,
        "a nullifier equal to the low leaf's successor was accepted"
    );

    // Step 2: a low leaf that does not precede the nullifier.
    let (witness, _, _, _) = two.witness_for(&small(4));
    let mut not_below = witness.clone();
    not_below.low_index = 1;
    not_below.low_value = small(10);
    not_below.low_next_index = 0;
    not_below.low_next_value = ZERO;
    not_below.low_path = two.tree.path(1);
    assert_eq!(
        probe.insert_exit(&two.root(), two.next_index, &small(4), &encode_witness(&not_below)),
        116,
        "a low leaf above the nullifier was accepted"
    );
}

#[test]
fn a_non_empty_append_slot_is_refused() {
    let probe = Probe::deploy();
    let mut state = RefState::genesis();

    // A single tampered sibling in the append path: the fold no longer proves
    // the slot empty under the step 5 root.
    let nf = from_dec("500000000000000000000000000000000000000000000000000000000000000000");
    let (witness, _, _, _) = state.witness_for(&nf);
    let mut tampered = witness.clone();
    tampered.append_path[0] = small(1);
    assert_eq!(
        probe.insert_exit(&state.root(), state.next_index, &nf, &encode_witness(&tampered)),
        120,
        "an append path with a tampered sibling was accepted"
    );
    assert_eq!(
        probe.insert_exit(&state.root(), state.next_index, &nf, &encode_witness(&witness)),
        0,
        "the untampered witness should still be accepted"
    );

    // And the slot itself already allocated: two nullifiers inserted, then an
    // insertion whose counter lags behind the tree, so the append slot is leaf 2.
    let big_a = from_dec("500000000000000000000000000000000000000000000000000000000000000000");
    let big_b = from_dec("900000000000000000000000000000000000000000000000000000000000000000");
    insert_and_check(&probe, &mut state, &big_a, "big_a");
    insert_and_check(&probe, &mut state, &big_b, "big_b");
    assert_eq!(state.next_index, 3, "two insertions should leave the counter at 3");

    let lagging = RefState { tree: state.tree.clone(), next_index: 2 };
    let smaller = small(11);
    let (witness, _, _, _) = lagging.witness_for(&smaller);
    assert_eq!(witness.low_index, 0, "the predecessor of the small value should be the sentinel");
    assert_eq!(
        probe.insert_exit(&state.root(), 2, &smaller, &encode_witness(&witness)),
        120,
        "an append into an already allocated leaf was accepted"
    );
}

#[test]
fn duplicate_and_reordered_witnesses_fail() {
    let probe = Probe::deploy();
    let mut state = RefState::genesis();
    let nf0 = from_dec("500000000000000000000000000000000000000000000000000000000000000000");
    let nf1 = from_dec("900000000000000000000000000000000000000000000000000000000000000000");

    let genesis_root = state.root();
    let (witness0, _, _, _) = state.witness_for(&nf0);
    let cell0 = encode_witness(&witness0);
    insert_and_check(&probe, &mut state, &nf0, "nf0");

    // The same witness replayed against the root it already moved: the low leaf
    // tuple it proves is no longer in the tree.
    assert_eq!(
        probe.insert_exit(&state.root(), state.next_index, &nf0, &cell0),
        115,
        "a replayed witness was accepted"
    );

    // A freshly built, entirely correct witness for a nullifier that is already
    // in the tree is refused by the bracket instead: its predecessor now points
    // straight at it.
    let (fresh, _, _, _) = state.witness_for(&nf0);
    assert_eq!(fresh.low_index, 0, "the sentinel should still precede nf0");
    assert_eq!(fresh.low_next_value, nf0, "the sentinel should point at nf0");
    assert_eq!(
        probe.insert_exit(&state.root(), state.next_index, &nf0, &encode_witness(&fresh)),
        117,
        "a nullifier already in the tree was accepted a second time"
    );

    // Reordering: nf1's witness is taken against the post-nf0 root and names
    // leaf 1 as its low leaf. Applied first, at genesis, leaf 1 is not yet
    // allocated, and 7.2 refuses a witness that names an unallocated leaf.
    let (witness1, _, _, _) = state.witness_for(&nf1);
    assert_eq!(witness1.low_index, 1, "nf1's predecessor should be nf0 at leaf 1");
    assert_eq!(
        probe.insert_exit(&genesis_root, 1, &nf1, &encode_witness(&witness1)),
        113,
        "the second witness was accepted before the first insertion"
    );
}

#[test]
fn a_witness_that_names_an_unallocated_leaf_is_refused() {
    let probe = Probe::deploy();
    let state = RefState::genesis();
    let nf = small(5);

    // low_index at the next index is not yet allocated.
    let (witness, _, _, _) = state.witness_for(&nf);
    let mut future = witness.clone();
    future.low_index = 1;
    assert_eq!(
        probe.insert_exit(&state.root(), state.next_index, &nf, &encode_witness(&future)),
        113,
        "a low index at or above the next index was accepted"
    );

    // low_next_index pointing past the allocated range. Without the 7.2 check
    // this witness is otherwise valid, so the check is the only thing refusing it.
    let mut malformed = RefTree::default();
    malformed.leaves.insert(0, Leaf { value: ZERO, next_index: 9, next_value: small(100) });
    let broken = RefState { tree: malformed, next_index: 1 };
    let (witness, _, _, _) = broken.witness_for(&small(50));
    assert_eq!(witness.low_next_index, 9);
    assert_eq!(
        probe.insert_exit(&broken.root(), broken.next_index, &small(50), &encode_witness(&witness)),
        114,
        "a successor index at or above the next index was accepted"
    );
}

#[test]
fn the_witness_encoding_is_rejected_unless_it_is_canonical() {
    let probe = Probe::deploy();
    let state = RefState::genesis();
    let nf = small(5);
    let (witness, _, _, _) = state.witness_for(&nf);
    let root = state.root();
    let next = state.next_index;
    let canonical = encode_witness(&witness);
    assert_eq!(probe.insert_exit(&root, next, &nf, &canonical), 0, "the canonical witness failed");

    let case = |cell: Cell| probe.insert_exit(&root, next, &nf, &cell);

    // The codes below are the VM's, not this contract's. Until global version
    // 18 the path walk was a FunC loop that threw 102 to 105 for a malformed
    // cell and 103 for a field at or above the modulus; POSEIDON2_PATH7 does
    // the same refusals and throws what the VM throws. Every caller in the
    // pool compares the returned root and rejects on inequality, so nothing
    // distinguishes them -- but the change is real and this is where it is
    // recorded.
    const CELL_UNDERFLOW: i32 = 9;
    const RANGE_CHECK: i32 = 5;

    // Fewer or more than twenty-four path cells.
    let short = encode_witness_parts(
        &witness,
        encode_path(&witness.low_path[..PATH_FIELDS - 3]),
        encode_path(&witness.append_path),
        WitnessTweak::default(),
    );
    assert_eq!(case(short), CELL_UNDERFLOW, "a twenty-three cell path was accepted");
    let mut long_fields = witness.low_path.clone();
    long_fields.extend_from_slice(&[ZERO, ZERO, ZERO]);
    let long = encode_witness_parts(
        &witness,
        encode_path(&long_fields),
        encode_path(&witness.append_path),
        WitnessTweak::default(),
    );
    assert_eq!(case(long), CELL_UNDERFLOW, "a twenty-five cell path was accepted");

    // A path field at or above the modulus.
    let mut over = witness.clone();
    over.low_path[5] = field_modulus();
    assert_eq!(case(encode_witness(&over)), RANGE_CHECK, "a non-canonical path field was accepted");

    // Trailing bits in a path cell, on the first cell and on the last.
    for cell_index in [0usize, PATH_CELLS - 1] {
        let tweaked = encode_witness_parts(
            &witness,
            encode_path_tweaked(
                &witness.low_path,
                PathTweak { trailing_bits: Some((cell_index, 1)), extra_ref: None },
            ),
            encode_path(&witness.append_path),
            WitnessTweak::default(),
        );
        assert_eq!(case(tweaked), CELL_UNDERFLOW, "a path cell with a trailing bit was accepted");
    }

    // An extra reference, on a non-final cell and on the final one.
    let extra_middle = encode_witness_parts(
        &witness,
        encode_path_tweaked(
            &witness.low_path,
            PathTweak { trailing_bits: None, extra_ref: Some(0) },
        ),
        encode_path(&witness.append_path),
        WitnessTweak::default(),
    );
    assert_eq!(case(extra_middle), CELL_UNDERFLOW, "a path cell with two references was accepted");
    let extra_final = encode_witness_parts(
        &witness,
        encode_path_tweaked(
            &witness.low_path,
            PathTweak { trailing_bits: None, extra_ref: Some(PATH_CELLS - 1) },
        ),
        encode_path(&witness.append_path),
        WitnessTweak::default(),
    );
    assert_eq!(
        case(extra_final),
        CELL_UNDERFLOW,
        "a final path cell with a reference was accepted"
    );

    // The same rules on the append path, so neither reference is decoded loosely.
    let bad_append = encode_witness_parts(
        &witness,
        encode_path(&witness.low_path),
        encode_path(&witness.append_path[..PATH_FIELDS - 3]),
        WitnessTweak::default(),
    );
    assert_eq!(case(bad_append), CELL_UNDERFLOW, "a short append path was accepted");

    // Trailing bits and an extra reference on the witness root.
    let root_bits = encode_witness_parts(
        &witness,
        encode_path(&witness.low_path),
        encode_path(&witness.append_path),
        WitnessTweak { trailing_bits: 1, extra_ref: false },
    );
    assert_eq!(case(root_bits), 108, "a witness root with a trailing bit was accepted");
    let root_ref = encode_witness_parts(
        &witness,
        encode_path(&witness.low_path),
        encode_path(&witness.append_path),
        WitnessTweak { trailing_bits: 0, extra_ref: true },
    );
    assert_eq!(case(root_ref), 109, "a witness root with three references was accepted");

    // A non-canonical low value in the witness root.
    let mut over_low = witness.clone();
    over_low.low_value = field_modulus();
    assert_eq!(case(encode_witness(&over_low)), 110, "a non-canonical low value was accepted");
    let mut over_next = witness.clone();
    over_next.low_next_value = field_modulus();
    assert_eq!(
        case(encode_witness(&over_next)),
        111,
        "a non-canonical successor value was accepted"
    );

    // A non-canonical nullifier.
    assert_eq!(
        probe.insert_exit(&root, next, &field_modulus(), &canonical),
        112,
        "a nullifier at the modulus was accepted"
    );
}

#[test]
fn the_sibling_order_is_the_one_the_profile_froze() {
    let probe = Probe::deploy();

    // A tree with one leaf in every child position under one parent, so that a
    // reordering of the six siblings cannot be hidden by equal values.
    let mut tree = RefTree::default();
    for index in 0..ARITY {
        tree.leaves
            .insert(index, Leaf { value: small(1000 + index), next_index: 0, next_value: ZERO });
    }
    let root = tree.root();
    for index in 0..ARITY {
        let leaf = tree.leaves.get(&index).copied().expect("a leaf");
        let path = encode_path(&tree.path(index));
        assert_eq!(
            probe.root_from_path(&path, index, &imt_leaf_hash(&leaf)),
            root,
            "folding leaf {index}'s path does not give the rebuilt root"
        );
        // Swapping the two siblings that bracket the digit must change the root.
        let mut swapped = tree.path(index);
        swapped.swap(0, 1);
        assert_ne!(
            probe.root_from_path(&encode_path(&swapped), index, &imt_leaf_hash(&leaf)),
            root,
            "swapping two siblings at leaf {index} left the root unchanged"
        );
        // So must folding the same path at the wrong leaf index.
        let other = (index + 1) % ARITY;
        assert_ne!(
            probe.root_from_path(&path, other, &imt_leaf_hash(&leaf)),
            root,
            "leaf {index}'s path folded at index {other} still gave the root"
        );
    }

    // An unallocated leaf folds to the same root as the tree without it.
    let mut sparse = RefTree::default();
    sparse.leaves.insert(0, Leaf::sentinel());
    let sparse_root = sparse.root();
    assert_eq!(
        probe.root_from_path(&encode_path(&sparse.path(3)), 3, &ZERO),
        sparse_root,
        "an unallocated leaf does not fold to the tree's root"
    );
}

/// Section 7.0's zero-leaf sentinel, hit directly. The permutation never
/// produces zero for an allocated leaf, so this guard is unreachable through
/// `imt_leaf_hash` and no mutation of that path could kill it -- which is why
/// it is a function of its own, called here with the one value that fires it.
#[test]
fn an_allocated_leaf_hash_of_zero_is_refused_by_the_sentinel() {
    let probe = Probe::deploy();

    let (exit, returned) = probe.require_allocated(&ZERO);
    assert_eq!(exit, 121, "field zero was accepted as an allocated leaf hash");
    assert!(returned.is_none(), "a refused value still came back");

    // And it is a guard, not a filter: everything else passes through unchanged.
    for value in [small(1), small(2), domain("IMT-LEAF"), imt_leaf_hash(&Leaf::sentinel())] {
        let (exit, returned) = probe.require_allocated(&value);
        assert_eq!(exit, 0, "a non-zero leaf hash was refused");
        assert_eq!(returned, Some(value), "the value was not returned unchanged");
    }
}

/// Section 7.2 requires ordinary cells. This module deliberately does not
/// reimplement "is this exotic": `begin_parse` is the real VM boundary, and a
/// second cell-type check here would be a second set of cell semantics.
///
/// So the evidence is not "delete our guard and watch a test go red" -- there
/// is no guard of ours to delete. It is that an exotic witness executed in a
/// real TVM fails closed *before* this module's own field parsing, which is
/// what the exit code proves: anything in 100..=122 is one of ours and would
/// mean the cell got that far. If the VM's special-cell semantics ever change,
/// this is the test that goes red first.
#[test]
fn an_exotic_cell_anywhere_in_the_witness_fails_closed_in_the_vm() {
    let probe = Probe::deploy();
    let state = RefState::genesis();
    let nf = small(5);
    let (witness, _, _, _) = state.witness_for(&nf);
    let root = state.root();
    let next = state.next_index;
    assert_eq!(
        probe.insert_exit(&root, next, &nf, &encode_witness(&witness)),
        0,
        "the canonical witness must pass, or nothing below means anything"
    );

    let cells = PATH_FIELDS / 3;
    let positions = [("first", 0usize), ("middle", cells / 2), ("last", cells - 1)];
    let mut cases: Vec<(String, Cell)> = Vec::new();
    for kind in [Exotic::PrunedBranch, Exotic::MerkleProof] {
        cases
            .push((format!("witness root, {kind:?}"), exotic_cell(kind, encode_witness(&witness))));
        for (where_, position) in positions {
            cases.push((
                format!("low_path {where_} cell, {kind:?}"),
                encode_witness_parts(
                    &witness,
                    path_with_exotic(&witness.low_path, position, kind),
                    encode_path(&witness.append_path),
                    WitnessTweak::default(),
                ),
            ));
            cases.push((
                format!("append_path {where_} cell, {kind:?}"),
                encode_witness_parts(
                    &witness,
                    encode_path(&witness.low_path),
                    path_with_exotic(&witness.append_path, position, kind),
                    WitnessTweak::default(),
                ),
            ));
        }
    }
    assert_eq!(cases.len(), 14, "the exotic case list shrank");

    for (what, cell) in cases {
        let exit = probe.insert_exit(&root, next, &nf, &cell);
        assert_ne!(exit, 0, "{what}: an exotic witness was accepted");
        assert!(
            !(100..=122).contains(&exit),
            "{what}: exit {exit} is one of this module's own codes, so the cell reached \
             field parsing; the VM was supposed to refuse it first"
        );
    }
}

#[test]
fn the_capacity_boundary_is_exactly_two_to_the_thirty_two() {
    let probe = Probe::deploy();
    let state = RefState::genesis();

    // The last representable index still inserts. The reference tree is sparse,
    // so a leaf at 2^32 - 1 costs nothing to build, and its path digits exercise
    // the full width of the index decomposition.
    let last = CAPACITY - 1;
    let lagging = RefState { tree: state.tree.clone(), next_index: last };
    let nf = small(42);
    let (witness, _, root2, _) = lagging.witness_for(&nf);
    let (new_root, new_next) = probe.insert(&lagging.root(), last, &nf, &encode_witness(&witness));
    assert_eq!(new_root, root2, "the last index produced the wrong root");
    assert_eq!(new_next, CAPACITY, "the counter did not reach the exhausted sentinel");

    // And one more is refused, because the counter is now the sentinel.
    let exhausted = RefState { tree: state.tree.clone(), next_index: CAPACITY };
    let (witness, _, _, _) =
        RefState { tree: state.tree.clone(), next_index: last }.witness_for(&small(43));
    assert_eq!(
        probe.insert_exit(&exhausted.root(), CAPACITY, &small(43), &encode_witness(&witness)),
        118,
        "an exhausted tree accepted another insertion"
    );

    // The fold refuses an out-of-range leaf index on its own.
    let path = encode_path(&state.tree.path(0));
    assert_eq!(probe.root_from_path_exit(&path, "4294967296", &ZERO), 107, "2^32 was folded");
    assert_eq!(probe.root_from_path_exit(&path, "-1", &ZERO), 106, "a negative index was folded");
    assert_eq!(probe.root_from_path_exit(&path, "4294967295", &ZERO), 0, "2^32-1 was refused");
}
