/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sections 4 and 5 of the V1 implementation profile, run in the VM: the note
//! commitments and nullifiers, and the 7-ary depth-12 commitment tree with its
//! canonical frontier store.
//!
//! Two of the checks here are worth more than the rest. The frontier is an
//! incremental algorithm; the test also rebuilds the whole tree from every leaf
//! and requires the two to agree, which is a genuinely different computation
//! rather than the same one written twice. And the empty-subtree ladder is
//! generated rather than recomputed on chain, so the test recomputes it from
//! the permutation and requires the generated table to match.
//!
//! What this cannot establish: that these formulas are the ones the circuit
//! will enforce. The FunC here and the reference below were both written from
//! section 4, so a misreading of the profile would be reproduced in both. The
//! cross-check that settles it is the circuit (WP-C), which does not exist yet.

use chain_block::poseidon2::permute;
use chain_block::poseidon2_kat::{DOMAINS, EMPTY_ROOTS};
use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;
use tos_vm::stack::integer::IntegerData;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
const DEPTH: usize = 12;
const ARITY: usize = 7;

type Field = [u8; 32];

// ---------------------------------------------------------------------------
// Reference: section 4 and section 5 written out directly.

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

fn small(value: u64) -> Field {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

const ZERO: Field = [0u8; 32];

fn owner_commitment(
    owner_nf_key_hash: Field,
    pq_auth_key_hash: Field,
    note_secret: Field,
) -> Field {
    h7(
        domain("OWNER-COMMITMENT"),
        [owner_nf_key_hash, pq_auth_key_hash, note_secret, ZERO, ZERO, ZERO, ZERO],
    )
}

fn note_body_commitment(owner: Field, amount: Field, output_data_hash: Field) -> Field {
    h7(domain("NOTE-BODY"), [owner, amount, output_data_hash, ZERO, ZERO, ZERO, ZERO])
}

fn note_commitment(body: Field, leaf_index: Field) -> Field {
    h7(domain("NOTE-COMMITMENT"), [body, leaf_index, ZERO, ZERO, ZERO, ZERO, ZERO])
}

fn nullifier(body: Field, owner_nf_key: Field) -> Field {
    h7(domain("NULLIFIER"), [body, owner_nf_key, ZERO, ZERO, ZERO, ZERO, ZERO])
}

fn phantom_nullifier(intent_nonce: Field, input_slot: Field, pq_auth_key_hash: Field) -> Field {
    h7(
        domain("PHANTOM-NULLIFIER"),
        [intent_nonce, input_slot, pq_auth_key_hash, ZERO, ZERO, ZERO, ZERO],
    )
}

fn commit_node(children: [Field; 7]) -> Field {
    h7(domain("COMMIT-NODE"), children)
}

/// EMPTY_ROOT[0] = 0, EMPTY_ROOT[level+1] = COMMIT-NODE of seven copies.
fn recomputed_empty_roots() -> Vec<Field> {
    let mut out = vec![ZERO];
    for level in 0..DEPTH {
        out.push(commit_node([out[level]; 7]));
    }
    out
}

/// The whole tree from every leaf, level by level. This shares the hash with
/// the frontier and nothing else: it never looks at a stored frontier slot and
/// never depends on the order the leaves arrived in.
fn naive_root(leaves: &[Field], empty: &[Field]) -> Field {
    let mut level_nodes = leaves.to_vec();
    for level in 0..DEPTH {
        while level_nodes.len() % ARITY != 0 {
            level_nodes.push(empty[level]);
        }
        let mut next = Vec::with_capacity(level_nodes.len() / ARITY);
        for group in level_nodes.chunks(ARITY) {
            let mut children = [ZERO; 7];
            children.copy_from_slice(group);
            next.push(commit_node(children));
        }
        if next.is_empty() {
            next.push(empty[level + 1]);
        }
        level_nodes = next;
    }
    assert_eq!(level_nodes.len(), 1, "the tree did not reduce to a single root");
    level_nodes[0]
}

/// The frontier as section 5.1 describes it: twelve levels of seven slots,
/// every slot always present. The contract's cell encoding is not part of the
/// reference -- `read_frontier` is what turns one into the other.
type ReferenceFrontier = [[Field; ARITY]; DEPTH];

/// The incremental algorithm of section 5.1, over a plain array.
fn reference_append(
    frontier: &mut ReferenceFrontier,
    index: u64,
    leaf: Field,
    empty: &[Field],
) -> Field {
    let mut carry = leaf;
    let mut stride = 1u64;
    for level in 0..DEPTH {
        let digit = ((index / stride) % ARITY as u64) as usize;
        let mut children = [empty[level]; 7];
        children[..digit].copy_from_slice(&frontier[level][..digit]);
        children[digit] = carry;
        // Positions above the digit keep the level's empty root, and the
        // whole level is rewritten: what sits in the store above the digit is
        // never read, but it is part of the state hash.
        frontier[level] = children;
        carry = commit_node(children);
        stride *= ARITY as u64;
    }
    carry
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

const PROBE: &str = r#"
int p_owner_commitment(int a, int b, int c) method_id { return owner_commitment(a, b, c); }
int p_note_body(int a, int b, int c) method_id { return note_body_commitment(a, b, c); }
int p_note_commitment(int a, int b) method_id { return note_commitment(a, b); }
int p_nullifier(int a, int b) method_id { return nullifier(a, b); }
int p_phantom(int a, int b, int c) method_id { return phantom_nullifier(a, b, c); }
int p_reduce(int d) method_id { return reduce_to_field(d); }
int p_empty_root(int level) method_id { return empty_root_at(level); }
int p_commit_node(int c0, int c1, int c2, int c3, int c4, int c5, int c6) method_id {
  return commit_node(c0, c1, c2, c3, c4, c5, c6);
}
cell p_frontier_genesis() method_id { return frontier_genesis(); }
(cell, int) p_append(cell frontier, int index, int leaf) method_id {
  return frontier_append(frontier, index, leaf);
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
        // Derived from this crate's own location, never from TOS_ROOT: that
        // variable points at the checkout holding the compiler, which in a
        // worktree is a different tree, and this suite would then silently
        // test another checkout's FunC instead of its own.
        let library = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont/shielded");
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir().expect("a directory for the probe");
        let probe_path = probe_dir.path().join("tos_shielded_notes_probe.fc");
        std::fs::write(&probe_path, PROBE).expect("write probe");
        let code = compile_func_with_stdlib(&[
            format!("{library}/domains.fc").into(),
            format!("{library}/empty-roots.fc").into(),
            format!("{library}/notes.fc").into(),
            format!("{library}/tree.fc").into(),
            probe_path,
        ])
        .expect("compile the shielded library (needs build/crypto/func)");
        let mut data = BuilderData::new();
        data.append_u32(0).unwrap();
        let si = StateInit::with_code_and_data(code, data.into_cell().unwrap());
        let addr_hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let addr = MsgAddressInt::with_params(0, addr_hash).unwrap();
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

    fn field_args(values: &[Field]) -> Vec<StackItem> {
        values
            .iter()
            .map(|value| {
                StackItem::integer(
                    IntegerData::from_str_radix(&dec(value), 10).expect("argument as integer"),
                )
            })
            .collect()
    }

    fn call_field(&self, method: &str, args: &[Field]) -> Field {
        let result = self
            .bc
            .run_get_method(&self.addr, method, Self::field_args(args))
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

    /// The store section 13.2 deploys a pool with, which is where a sequence
    /// of appends starts.
    fn frontier_genesis(&self) -> Cell {
        let result = self
            .bc
            .run_get_method(&self.addr, "p_frontier_genesis", vec![])
            .expect("p_frontier_genesis should run");
        assert_eq!(result.exit_code, 0, "p_frontier_genesis exited {}", result.exit_code);
        result.stack.last().expect("a store").as_cell().expect("a cell").clone()
    }

    /// Returns the updated frontier store and the new root.
    fn append(&self, frontier: Cell, index: u64, leaf: Field) -> (Cell, Field) {
        let mut args = vec![StackItem::Cell(frontier)];
        args.push(StackItem::int(index as i64));
        args.extend(Self::field_args(&[leaf]));
        let result =
            self.bc.run_get_method(&self.addr, "p_append", args).expect("p_append should run");
        assert_eq!(result.exit_code, 0, "p_append exited {}", result.exit_code);
        assert_eq!(result.stack.len(), 2, "p_append must return a store and a root");
        let root = from_dec(&result.stack[1].as_integer().expect("root is an integer").to_string());
        let store = result.stack[0].as_cell().expect("a store cell").clone();
        (store, root)
    }

    fn append_exit_code(&self, index_bits: &str, leaf: Field) -> i32 {
        let args = vec![
            StackItem::Cell(self.frontier_genesis()),
            StackItem::integer(IntegerData::from_str_radix(index_bits, 10).expect("index")),
            Self::field_args(&[leaf]).remove(0),
        ];
        self.bc.run_get_method(&self.addr, "p_append", args).expect("p_append should run").exit_code
    }
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

/// Every slot of the store, with the §13.1 encoding checked rather than
/// assumed: twelve level nodes in order, each three cells holding 3 + 3 + 1
/// field elements, the last level carrying no successor.
fn read_frontier(store: &Cell) -> ReferenceFrontier {
    let mut out = [[ZERO; ARITY]; DEPTH];
    let mut node = Some(store.clone());
    for (level, slots) in out.iter_mut().enumerate() {
        let last = level == DEPTH - 1;
        let cell = node.take().expect("a level node");
        let mut a = SliceData::load_cell(cell).expect("load a level node");
        assert_eq!(a.remaining_bits(), 768, "level {level} does not hold three field elements");
        assert_eq!(
            a.remaining_references(),
            if last { 1 } else { 2 },
            "level {level} does not have the references section 13.1 fixes"
        );
        for slot in slots.iter_mut().take(3) {
            *slot = read_field(&mut a);
        }
        let second = a.checked_drain_reference().expect("the second cell");
        if !last {
            node = Some(a.checked_drain_reference().expect("the next level"));
        }

        let mut b = SliceData::load_cell(second).expect("load the second cell");
        assert_eq!(b.remaining_bits(), 768, "level {level}'s second cell is not three elements");
        assert_eq!(b.remaining_references(), 1, "level {level}'s second cell is not one reference");
        for slot in slots.iter_mut().skip(3).take(3) {
            *slot = read_field(&mut b);
        }

        let mut c = SliceData::load_cell(b.checked_drain_reference().expect("the third cell"))
            .expect("load the third cell");
        assert_eq!(c.remaining_bits(), 256, "level {level}'s third cell is not one element");
        assert_eq!(c.remaining_references(), 0, "level {level}'s third cell carries a reference");
        slots[6] = read_field(&mut c);
    }
    assert!(node.is_none(), "the chain does not end at level {}", DEPTH - 1);
    out
}

fn read_field(slice: &mut SliceData) -> Field {
    let mut bytes = [0u8; 32];
    for byte in bytes.iter_mut() {
        *byte = slice.get_next_byte().expect("a slot byte");
    }
    bytes
}

// ---------------------------------------------------------------------------

#[test]
fn the_generated_empty_root_ladder_is_what_the_permutation_produces() {
    let recomputed = recomputed_empty_roots();
    assert_eq!(recomputed.len(), EMPTY_ROOTS.len(), "the ladder changed length");
    for (level, value) in recomputed.iter().enumerate() {
        assert_eq!(
            *value, EMPTY_ROOTS[level],
            "EMPTY_ROOT[{level}] in the generated table is not what the permutation gives"
        );
    }
    assert_eq!(recomputed[0], ZERO, "the empty leaf must be field zero");
    for level in 1..recomputed.len() {
        assert_ne!(recomputed[level], recomputed[level - 1], "two levels share an empty root");
    }

    let probe = Probe::deploy();
    for (level, value) in recomputed.iter().enumerate() {
        assert_eq!(
            probe.call_field("p_empty_root", &[small(level as u64)]),
            *value,
            "the contract's EMPTY_ROOT[{level}] disagrees"
        );
    }
}

#[test]
fn each_commitment_matches_the_profile_and_binds_every_argument() {
    let probe = Probe::deploy();
    let a = small(11);
    let b = small(22);
    let c = small(33);

    let owner = owner_commitment(a, b, c);
    assert_eq!(probe.call_field("p_owner_commitment", &[a, b, c]), owner);
    // These really are 256-bit values, so the comparisons above are not
    // comparing two truncated zeros.
    assert!(dec(&owner).len() > 70, "the commitment is not a full-width field element");
    let body = note_body_commitment(owner, small(5 * TOS), small(77));
    assert_eq!(probe.call_field("p_note_body", &[owner, small(5 * TOS), small(77)]), body);
    assert_eq!(
        probe.call_field("p_note_commitment", &[body, small(3)]),
        note_commitment(body, small(3))
    );
    assert_eq!(probe.call_field("p_nullifier", &[body, a]), nullifier(body, a));
    assert_eq!(
        probe.call_field("p_phantom", &[small(9), small(1), b]),
        phantom_nullifier(small(9), small(1), b)
    );

    // Every argument has to reach the output, or the commitment is not binding.
    for slot in 0..3 {
        let mut args = [a, b, c];
        args[slot] = small(99);
        assert_ne!(
            probe.call_field("p_owner_commitment", &args),
            owner,
            "owner commitment ignores argument {slot}"
        );
    }
    assert_ne!(
        note_body_commitment(owner, small(5 * TOS), small(77)),
        note_body_commitment(owner, small(5 * TOS + 1), small(77)),
        "the amount is not bound into the note body"
    );
    assert_ne!(
        note_commitment(body, small(3)),
        note_commitment(body, small(4)),
        "the leaf index is not bound into the note commitment"
    );

    // The domains separate the structures: the same three values under four
    // different labels must not collide.
    let same = [a, b, c, ZERO, ZERO, ZERO, ZERO];
    let mut produced = vec![
        h7(domain("OWNER-COMMITMENT"), same),
        h7(domain("NOTE-BODY"), same),
        h7(domain("PHANTOM-NULLIFIER"), same),
        h7(domain("COMMIT-NODE"), same),
    ];
    produced.sort();
    produced.dedup();
    assert_eq!(produced.len(), 4, "two domains produced the same value for the same inputs");

    // The zero padding is part of the definition, not slack.
    assert_ne!(
        h7(domain("NOTE-COMMITMENT"), [body, small(3), ZERO, ZERO, ZERO, ZERO, ZERO]),
        h7(domain("NOTE-COMMITMENT"), [body, small(3), small(1), ZERO, ZERO, ZERO, ZERO]),
        "a padding lane does not reach the output"
    );
}

#[test]
fn hashing_into_the_field_is_a_reduction_and_only_a_reduction() {
    let probe = Probe::deploy();
    let modulus =
        from_dec("52435875175126190479447740508185965837690552500527637822603658699938581184513");
    assert_eq!(probe.call_field("p_reduce", &[small(7)]), small(7), "a small value moved");
    assert_eq!(
        probe.call_field("p_reduce", &[modulus]),
        ZERO,
        "the modulus did not reduce to zero"
    );
    let mut above = modulus;
    above[31] += 4; // the modulus ends in 0x01
    assert_eq!(probe.call_field("p_reduce", &[above]), small(4), "reduction is not modular");
}

#[test]
fn the_frontier_agrees_with_rebuilding_the_whole_tree() {
    let probe = Probe::deploy();
    let empty = recomputed_empty_roots();

    // The empty tree's root is the ladder's top, before anything is appended.
    assert_eq!(naive_root(&[], &empty), empty[DEPTH], "an empty tree is not the empty root");

    let mut store = probe.frontier_genesis();
    let mut reference_frontier: ReferenceFrontier = [[ZERO; ARITY]; DEPTH];
    assert_eq!(
        read_frontier(&store),
        reference_frontier,
        "the store a pool is deployed with is not twelve levels of zeros"
    );
    let mut leaves: Vec<Field> = Vec::new();

    // Fifty leaves crosses the first group boundary at 7 and the second at 49.
    for index in 0..50u64 {
        let leaf = note_commitment(small(1000 + index), small(index));
        let (next_store, contract_root) = probe.append(store.clone(), index, leaf);
        let reference_root = reference_append(&mut reference_frontier, index, leaf, &empty);
        leaves.push(leaf);

        assert_eq!(
            contract_root, reference_root,
            "at leaf {index} the contract and the incremental reference disagree"
        );
        assert_eq!(
            contract_root,
            naive_root(&leaves, &empty),
            "at leaf {index} the frontier disagrees with rebuilding the tree from every leaf"
        );
        assert_ne!(contract_root, empty[DEPTH], "the root did not move off the empty root");

        // The store stays canonical and stays in agreement with the reference.
        let stored = read_frontier(&next_store);
        assert_eq!(
            stored, reference_frontier,
            "at leaf {index} the stored frontier is not the reference frontier"
        );
        store = next_store;
    }

    // Order independence is not claimed by the profile and is not true of the
    // frontier: what is claimed is that the root after n appends is the tree of
    // those n leaves, which is what the check above asserts at every step.
    assert_eq!(leaves.len(), 50);
}

/// A zero slot is stored like any other value.
///
/// This test used to assert the opposite. Under the dictionary the store was
/// canonical only if it omitted every zero, and a zero leaf -- which is the
/// empty leaf, and so a legal thing to append -- was the one path that
/// reached the rule. The level chain has no encoding for an absent slot, so
/// the rule is gone, and what has to be shown instead is that the append does
/// not invent one: the store still has the fixed shape, and the zero is in it.
#[test]
fn a_zero_valued_slot_is_stored_like_any_other() {
    let probe = Probe::deploy();
    let empty = recomputed_empty_roots();

    let (store, root) = probe.append(probe.frontier_genesis(), 0, ZERO);
    assert_eq!(
        root, empty[DEPTH],
        "a zero leaf is the empty leaf, so the root must still be the empty root"
    );
    // `read_frontier` checks the shape of every cell on the way through, so
    // reaching this line is itself the assertion that the zero did not change
    // the encoding.
    let stored = read_frontier(&store);
    assert_eq!(stored[0][0], ZERO, "the zero carry did not survive into slot (0, 0)");
    // Every level above the leaf carries a real value, so the store is not
    // simply the zeros it was deployed with.
    for level in 1..DEPTH {
        assert_ne!(
            stored[level][0], ZERO,
            "level {level} slot 0 is still zero, so nothing was carried upwards"
        );
    }

    // And a later non-zero append at the same slot must overwrite it.
    let (store, root) = probe.append(store, 0, small(5));
    assert_ne!(root, empty[DEPTH], "overwriting the zero leaf did not change the root");
    assert_eq!(
        read_frontier(&store)[0][0],
        small(5),
        "the slot did not take the value that was written over the zero"
    );
}

#[test]
fn the_capacity_sentinel_is_refused() {
    let probe = Probe::deploy();
    let leaf = small(1);
    assert_eq!(probe.append_exit_code("4294967296", leaf), 92, "2^32 was accepted as an index");
    assert_eq!(
        probe.append_exit_code("4294967295", leaf),
        0,
        "the last representable index was refused"
    );
    assert_eq!(probe.append_exit_code("-1", leaf), 91, "a negative index was accepted");
}
