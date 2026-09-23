/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Runs an indexed Merkle tree inside the VM, to check claims that until now were only
//! modelled on a development machine: that a dictionary costs exactly `2n - 1` cells, that
//! recomputing each affected node once beats walking every leaf's path, and that a single
//! insert touches exactly the tree depth.
//!
//! The hash here is a PLACEHOLDER (`cell_hash`, SHA-256 over a cell). The design calls for
//! Poseidon2, which has no instruction yet. Nothing measured here depends on which hash is
//! used: the counts are structural. What this does NOT cover is gas per transfer, which is
//! the placeholder hash's price and not the real one.

use chain_block::{Cell, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{Blockchain, GetMethodResult, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;

const TOS: u64 = 1_000_000_000;
/// Tree depth used by the probe: 32 leaves. Small enough to run, big enough that a
/// "recompute each affected node once" pass is distinguishable from "walk every path".
const DEPTH: i64 = 5;

fn probe_code() -> Cell {
    // A directory of this call's own. These probes are written from several tests at
    // once, and a shared path is truncated under a concurrent `func` reading it.
    let src_dir = tempfile::tempdir().expect("a directory for the probe");
    let src = src_dir.path().join("tos_imt_probe.fc");
    std::fs::write(&src, PROBE_SRC).expect("write probe source");
    compile_func_with_stdlib(&[src]).expect("compile the IMT probe (needs build/crypto/func)")
}

const PROBE_SRC: &str = r#"
int depth() asm "5 PUSHINT";
int key_bits() asm "32 PUSHINT";
int leaves() asm "32 PUSHINT";

global int calls;
global cell nodes;

int h2(int a, int b) inline {
  calls = calls + 1;
  return cell_hash(begin_cell().store_uint(a, 256).store_uint(b, 256).end_cell());
}

int node_at(int id) inline {
  (slice s, int ok) = nodes.udict_get?(key_bits(), id);
  if (ok == 0) { return 0; }
  return s~load_uint(256);
}

() put_node(int id, int v) impure inline {
  nodes~udict_set(key_bits(), id, begin_cell().store_uint(v, 256).end_cell().begin_parse());
}

;; Value stored at leaf j. Any deterministic function will do; the tree does not
;; care what the values are, only that they differ.
int leaf_value(int j, int salt) inline {
  return (j + 1) * 1000003 + salt;
}

;; Recompute one leaf's path to the root: exactly `depth` hashes.
() write_leaf_walking(int j, int v) impure {
  int id = (1 << depth()) + j;
  put_node(id, v);
  while (id > 1) {
    int sib = id ^ 1;
    int left = ((id & 1) == 0) ? node_at(id) : node_at(sib);
    int right = ((id & 1) == 0) ? node_at(sib) : node_at(id);
    id = id / 2;
    put_node(id, h2(left, right));
  }
}

;; Insert `count` leaves spaced `stride` apart, walking each path. Returns (root, hashes).
(int, int) walk_insert(int count, int stride, int salt) method_id {
  calls = 0;
  nodes = new_dict();
  int i = 0;
  while (i < count) {
    int j = (i * stride) % leaves();
    write_leaf_walking(j, leaf_value(j, salt));
    i = i + 1;
  }
  return (node_at(1), calls);
}

;; The same leaves, but each affected internal node recomputed ONCE, level by level.
(int, int) batch_insert(int count, int stride, int salt) method_id {
  calls = 0;
  nodes = new_dict();

  cell touched = new_dict();
  int i = 0;
  while (i < count) {
    int j = (i * stride) % leaves();
    int id = (1 << depth()) + j;
    put_node(id, leaf_value(j, salt));
    touched~udict_set(key_bits(), id / 2,
                      begin_cell().store_uint(1, 1).end_cell().begin_parse());
    i = i + 1;
  }

  int level = depth() - 1;
  while (level >= 0) {
    cell next = new_dict();
    int id = -1;
    int more = -1;
    do {
      (id, slice ignored, more) = touched.udict_get_next?(key_bits(), id);
      if (more) {
        put_node(id, h2(node_at(id * 2), node_at(id * 2 + 1)));
        if (id > 1) {
          next~udict_set(key_bits(), id / 2,
                         begin_cell().store_uint(1, 1).end_cell().begin_parse());
        }
      }
    } until (~ more);
    touched = next;
    level = level - 1;
  }
  return (node_at(1), calls);
}

;; The nullifier set is keyed by the nullifier itself: a 256-bit key. The 32-bit
;; keys used for tree node ids are a different shape, so both are measured.
(int, int) dict_size_256key(int n) method_id {
  cell d = new_dict();
  int i = 0;
  while (i < n) {
    int k = cell_hash(begin_cell().store_uint(i, 32).end_cell());   ;; scattered keys
    d~udict_set(256, k, begin_cell().store_uint(1, 1).end_cell().begin_parse());
    i = i + 1;
  }
  (int cells, int bits, int refs) = compute_data_size(d, 1000000);
  return (cells, bits);
}

;; Cells and bits a dictionary of `n` 256-bit entries actually occupies.
(int, int) dict_size(int n) method_id {
  cell d = new_dict();
  int i = 0;
  while (i < n) {
    d~udict_set(key_bits(), i, begin_cell().store_uint(i + 1, 256).end_cell().begin_parse());
    i = i + 1;
  }
  (int cells, int bits, int refs) = compute_data_size(d, 1000000);
  return (cells, bits);
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
}
"#;

struct Probe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl Probe {
    fn deploy() -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let deployer = bc.treasury("imt-deployer", 1_000 * TOS).expect("deployer");
        let si = StateInit::with_code_and_data(probe_code(), Cell::default());
        let addr_hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let addr = MsgAddressInt::with_params(-1, addr_hash).unwrap();
        let deploy = MessageBuilder::internal(deployer.address(), &addr, 2 * TOS)
            .bounce(false)
            .state_init(si)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, addr }
    }

    /// Results as decimal strings. A root is a 256-bit value and does not fit in an
    /// i64; parsing it into one collapses every root to the same sentinel, which makes
    /// "the root changed" untestable. Keep the full value and let callers narrow.
    fn call(&self, method: &str, args: Vec<i64>) -> (Vec<String>, i64) {
        let items: Vec<StackItem> = args.into_iter().map(StackItem::int).collect();
        let res: GetMethodResult = self
            .bc
            .run_get_method(&self.addr, method, items)
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        res.expect_success();
        let vals = res
            .stack
            .iter()
            .map(|i| {
                i.as_integer()
                    .unwrap_or_else(|_| panic!("{method}: non-integer result"))
                    .to_string()
            })
            .collect();
        (vals, res.gas_used as i64)
    }

    fn small(v: &str, what: &str) -> i64 {
        v.parse::<i64>().unwrap_or_else(|_| panic!("{what} does not fit in i64: {v}"))
    }

    /// (root as a full 256-bit decimal string, hash calls, gas).
    fn walk(&self, count: i64, stride: i64, salt: i64) -> (String, i64, i64) {
        let (v, gas) = self.call("walk_insert", vec![count, stride, salt]);
        (v[v.len() - 2].clone(), Self::small(&v[v.len() - 1], "hash calls"), gas)
    }

    fn batch(&self, count: i64, stride: i64, salt: i64) -> (String, i64, i64) {
        let (v, gas) = self.call("batch_insert", vec![count, stride, salt]);
        (v[v.len() - 2].clone(), Self::small(&v[v.len() - 1], "hash calls"), gas)
    }
}

/// The four checks that must pass before any count from this probe means anything:
/// a write must change the root, the same writes must give the same root, a different
/// leaf must give a different root, and one insert must cost exactly the depth.
#[test]
fn the_tree_behaves_like_a_tree_before_any_count_is_believed() {
    let p = Probe::deploy();

    let (root_one, calls_one, _) = p.walk(1, 1, 0);
    assert_eq!(calls_one, DEPTH, "one insert must hash exactly the depth");

    let (root_two, _, _) = p.walk(2, 1, 0);
    assert_ne!(root_one, root_two, "a second write must change the root");

    let (root_again, _, _) = p.walk(2, 1, 0);
    assert_eq!(root_two, root_again, "the same writes must give the same root");

    let (root_other, _, _) = p.walk(2, 1, 7);
    assert_ne!(root_two, root_other, "a different leaf value must change the root");

    println!("instrument self-check passed: 1 insert = {calls_one} hashes (depth {DEPTH})");
}

/// The claim taken from the development-machine model: a dictionary of n entries is
/// exactly `2n - 1` cells, which is what turns the 65,536-cell account limit into a
/// hard ceiling of 32,768 nullifiers.
#[test]
fn a_dictionary_costs_exactly_two_cells_per_entry_minus_one() {
    let p = Probe::deploy();
    println!("\n n      cells   expected(2n-1)   bits");
    // 256 exhausts the get-method gas allowance (exit 13); the formula is what is
    // under test, not how many entries one get-method can build.
    for n in [1i64, 2, 4, 8, 16, 32, 64, 128] {
        let (v, _) = p.call("dict_size", vec![n]);
        let cells = Probe::small(&v[v.len() - 2], "cells");
        let bits = Probe::small(&v[v.len() - 1], "bits");
        println!("{n:4}   {cells:6}   {:12}   {bits:6}", 2 * n - 1);
        assert_eq!(cells, 2 * n - 1, "dictionary of {n} entries should be 2n-1 cells");
    }

    // The nullifier set is keyed by the nullifier: a 256-bit, pseudorandom key. That is
    // a different trie shape from the 32-bit node ids above, and it is the one the
    // 32,768 ceiling is actually derived from.
    println!("\n 256-bit keys (the shape the nullifier set really has)");
    println!(" n      cells   expected(2n-1)   bits");
    for n in [1i64, 2, 4, 8, 16, 32, 64] {
        let (v, _) = p.call("dict_size_256key", vec![n]);
        let cells = Probe::small(&v[v.len() - 2], "cells");
        let bits = Probe::small(&v[v.len() - 1], "bits");
        println!("{n:4}   {cells:6}   {:12}   {bits:6}", 2 * n - 1);
        assert_eq!(cells, 2 * n - 1, "256-bit-key dictionary of {n} entries should be 2n-1 cells");
    }
    let per_entry = 2;
    let cap_cells = 65_536i64;
    println!(
        "=> account limit {cap_cells} cells / {per_entry} per entry = {} nullifiers",
        cap_cells / per_entry
    );
}

/// The saving credited to "recompute each affected node once" instead of walking every
/// leaf's path. The development-machine model counted permutations only and called this
/// free. In the VM it is not free: the bookkeeping needed to remember which nodes were
/// touched is itself dictionary work, and for two scattered leaves it costs more gas than
/// the single hash it saves. The exact counts are asserted so that a change in either
/// direction fails here rather than being absorbed silently.
#[test]
fn batching_saves_hashes_but_its_bookkeeping_is_not_free() {
    let p = Probe::deploy();
    println!("\n leaves  stride   walk   batch   saved   walk gas   batch gas");
    let mut rows = Vec::new();
    for (count, stride, label) in
        [(2i64, 1i64, "adjacent"), (2, 16, "far apart"), (4, 8, "scattered"), (8, 4, "scattered")]
    {
        let (rw, cw, gw) = p.walk(count, stride, 0);
        let (rb, cb, gb) = p.batch(count, stride, 0);
        assert_eq!(rw, rb, "batched and walked roots must agree ({label})");
        assert!(rw.len() > 8, "root looks truncated, the comparison above proves nothing: {rw}");
        let saved = 100.0 * (1.0 - cb as f64 / cw as f64);
        println!(
            "{count:6}  {stride:6}   {cw:4}   {cb:5}   {saved:4.0}%   {gw:8}   {gb:9}   {label}"
        );
        rows.push((count, stride, cw, cb, gw, gb));
    }

    // Two adjacent leaves share their whole path above the first split, so batching
    // halves the hashing.
    let (_, _, cw, cb, _, _) = rows[0];
    assert_eq!((cw, cb), (10, 5), "adjacent leaves: batching should halve the hashes");

    // Two leaves far apart share only the root, which is the realistic case: a nullifier
    // decides its own leaf index and nullifiers are pseudorandom. Batching then saves one
    // hash out of ten -- and the bookkeeping costs more gas than that hash is worth.
    let (_, _, cw, cb, gw, gb) = rows[1];
    assert_eq!((cw, cb), (10, 9), "scattered leaves: batching should save exactly one hash");
    assert!(
        gb > gw,
        "the bookkeeping overhead this test exists to document has disappeared: \
         batch {gb} gas vs walk {gw} gas. Re-measure before trusting the 'batching is \
         free' claim again."
    );

    // The saving does grow once enough leaves share subtrees.
    let (_, _, cw8, cb8, gw8, gb8) = rows[3];
    assert_eq!((cw8, cb8), (40, 23), "eight leaves: 40 hashes walked, 23 batched (43%)");
    assert!(gb8 < gw8, "eight leaves: batching should win on gas too ({gb8} vs {gw8})");
}
