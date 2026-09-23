/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! What one commitment-tree append costs as the tree fills up.
//!
//! `frontier_append` hashes a fixed twelve nodes whatever the index. What
//! changes with the index is the store work around the hashing, and how it
//! changes depends on the container: the level chain the contract uses now
//! reads and rebuilds all seven slots of every level whatever the digits are,
//! so its cost is flat, while the HashmapE it replaced touched `digit + 1`
//! slots per level and so grew with the leaf index.
//!
//! This probe calls the function directly so both shapes can be measured
//! without minting two billion notes: `fill` builds the store a pool at
//! `index` would hold and `append_gas` reports what appending there costs.
//! The `dict_*` family is the old container, kept here in full and no longer
//! referenced by the contract, because the argument for the change was a
//! comparison and a comparison with one side deleted cannot be rerun.

use chain_block::{Cell, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};
use tos_vm::stack::integer::IntegerData;
use tos_vm::stack::StackItem;

use crate::{library_dir, stdlib_path, CrossCheckError, Result, ACTIVE_VERSION, TOS};

const PROBE: &str = r#"
;; --- the store the contract uses -------------------------------------------

;; The frontier a pool that has appended `index` leaves would hold: at every
;; level the slots up to that level's digit carry values and the rest carry
;; that level's empty root, which is what an append leaves behind. The values
;; are arbitrary -- a 256-bit slot costs what it costs whatever is in it --
;; but they are laid out this way so the store is one a real pool can be in.
cell f_fill(int index) method_id {
  cell chain = null();
  int level = tree_depth() - 1;
  while (level >= 0) {
    int stride = 1;
    int i = 0;
    while (i < level) { stride = stride * tree_arity(); i = i + 1; }
    int digit = (index / stride) % tree_arity();
    int empty = empty_root_at(level);
    tuple v = empty_tuple();
    int slot = 0;
    while (slot < tree_arity()) {
      v = v.tpush(slot <= digit ? 0x51ed0000 + (level * 7) + slot : empty);
      slot = slot + 1;
    }
    chain = frontier_level_build(v, chain, level == (tree_depth() - 1));
    level = level - 1;
  }
  return chain;
}

;; The store a pool is deployed with, for the tests that start at genesis.
cell f_genesis() method_id {
  return frontier_genesis();
}

;; The same shape as `f_fill`, with every slot zero. It is the same number of
;; cells and the same number of bits as a filled store, so the only thing it
;; can cost differently is what the VM charges for loading a cell it has
;; already loaded: all twelve levels' tail cells are byte-identical here and
;; distinct in a filled store.
cell f_fill_zeros(int index) method_id {
  tuple zeros = empty_tuple();
  int slot = 0;
  while (slot < tree_arity()) { zeros = zeros.tpush(0); slot = slot + 1; }
  cell chain = null();
  int level = tree_depth() - 1;
  while (level >= 0) {
    chain = frontier_level_build(zeros, chain, level == (tree_depth() - 1));
    level = level - 1;
  }
  return chain;
}

;; The measured call. The returned root is discarded by the caller, but it is
;; returned rather than dropped so no part of the append can be eliminated.
(cell, int) f_append(cell frontier, int index, int leaf) method_id {
  return frontier_append(frontier, index, leaf);
}

;; The digit sum, which is what decided how many slots the dictionary read.
int f_digit_sum(int index) method_id {
  int total = 0;
  int stride = 1;
  int level = 0;
  while (level < tree_depth()) {
    total = total + ((index / stride) % tree_arity());
    stride = stride * tree_arity();
    level = level + 1;
  }
  return total;
}

;; --- the container that was replaced ---------------------------------------
;; A HashmapE 7 keyed by `level * 7 + position`, 0..83, absence meaning field
;; zero. This is the store the contract carried until 2026-09-21, reproduced
;; here verbatim so the two can still be measured against each other.

int d_key(int level, int position) inline {
  return (level * tree_arity()) + position;
}

int d_get(cell frontier, int level, int position) inline {
  (slice value, int found) = frontier.udict_get?(7, d_key(level, position));
  if (~ found) { return 0; }
  return value~load_uint(256);
}

cell d_set(cell frontier, int level, int position, int value) inline {
  int key = d_key(level, position);
  if (value == 0) {
    (cell updated, int removed) = frontier.udict_delete?(7, key);
    return updated;
  }
  return frontier.udict_set_builder(7, key, begin_cell().store_uint(value, 256));
}

(cell, int) d_append_impl(cell frontier, int index, int leaf) impure {
  int carry = leaf;
  int stride = 1;
  int level = 0;
  while (level < tree_depth()) {
    int digit = (index / stride) % tree_arity();
    frontier = d_set(frontier, level, digit, carry);
    int empty = empty_root_at(level);
    int c0 = digit >= 0 ? d_get(frontier, level, 0) : empty;
    int c1 = digit >= 1 ? d_get(frontier, level, 1) : empty;
    int c2 = digit >= 2 ? d_get(frontier, level, 2) : empty;
    int c3 = digit >= 3 ? d_get(frontier, level, 3) : empty;
    int c4 = digit >= 4 ? d_get(frontier, level, 4) : empty;
    int c5 = digit >= 5 ? d_get(frontier, level, 5) : empty;
    int c6 = digit >= 6 ? d_get(frontier, level, 6) : empty;
    carry = commit_node(c0, c1, c2, c3, c4, c5, c6);
    stride = stride * tree_arity();
    level = level + 1;
  }
  return (frontier, carry);
}

(cell, int) d_append(cell frontier, int index, int leaf) method_id {
  return d_append_impl(frontier, index, leaf);
}

cell d_fill(int index) method_id {
  cell frontier = new_dict();
  int stride = 1;
  int level = 0;
  while (level < tree_depth()) {
    int digit = (index / stride) % tree_arity();
    int position = 0;
    while (position <= digit) {
      frontier = d_set(frontier, level, position, 0x51ed0000 + (level * 7) + position);
      position = position + 1;
    }
    stride = stride * tree_arity();
    level = level + 1;
  }
  return frontier;
}

int d_reads(cell frontier, int rounds) method_id {
  int acc = 0;
  int i = 0;
  while (i < rounds) {
    acc = acc + d_get(frontier, i % tree_depth(), i % tree_arity());
    i = i + 1;
  }
  return acc;
}

cell d_writes(cell frontier, int rounds) method_id {
  int i = 0;
  while (i < rounds) {
    frontier = d_set(frontier, i % tree_depth(), i % tree_arity(), 0x1234 + i);
    i = i + 1;
  }
  return frontier;
}

;; --- what a dense container costs to read ----------------------------------
;; The same eighty-four values as a flat chain of cells, three to a cell, read
;; by walking rather than by key.

cell f_flat_build() method_id {
  cell chain = begin_cell().end_cell();
  int i = 0;
  while (i < 28) {
    chain = begin_cell()
      .store_uint(0x1234 + i * 3, 256)
      .store_uint(0x1235 + i * 3, 256)
      .store_uint(0x1236 + i * 3, 256)
      .store_ref(chain)
      .end_cell();
    i = i + 1;
  }
  return chain;
}

int f_flat_reads(cell chain, int rounds) method_id {
  int acc = 0;
  int i = 0;
  while (i < rounds) {
    slice s = chain.begin_parse();
    acc = acc + s~load_uint(256);
    i = i + 1;
  }
  return acc;
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

pub struct FrontierProbe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl FrontierProbe {
    pub fn deploy() -> Result<Self> {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
        bc.set_workchain(0);
        let payer = bc.treasury("frontier_deployer", 1_000 * TOS)?;
        let library = library_dir();
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir()
            .map_err(|error| CrossCheckError::Sandbox(format!("probe directory: {error}")))?;
        let probe_path = probe_dir.path().join("tos_shielded_frontier_probe.fc");
        std::fs::write(&probe_path, PROBE)
            .map_err(|error| CrossCheckError::Sandbox(format!("write probe: {error}")))?;
        let code = compile_func(&[
            stdlib_path(),
            library.join("domains.fc"),
            library.join("empty-roots.fc"),
            library.join("notes.fc"),
            library.join("tree.fc"),
            probe_path,
        ])?;
        let si = StateInit::with_code_and_data(code, Cell::default());
        let addr_hash = si
            .write_to_new_cell()
            .and_then(|builder| builder.into_cell())
            .map_err(|error| CrossCheckError::Sandbox(format!("state init: {error}")))?
            .hash(0);
        let addr = MsgAddressInt::with_params(0, addr_hash)
            .map_err(|error| CrossCheckError::Sandbox(format!("address: {error}")))?;
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 2 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )?
        .expect_success();
        Ok(Self { bc, addr })
    }

    fn integer(value: &str) -> Result<StackItem> {
        IntegerData::from_str_radix(value, 10)
            .map(StackItem::integer)
            .map_err(|error| CrossCheckError::Fixture(format!("{value}: {error}")))
    }

    fn call(&self, method: &str, args: Vec<StackItem>) -> Result<(Vec<StackItem>, i64)> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, args)
            .map_err(|error| CrossCheckError::Vm(format!("{method}: {error}")))?;
        if result.exit_code != 0 {
            return Err(CrossCheckError::Vm(format!("{method} exited {}", result.exit_code)));
        }
        Ok((result.stack, result.gas_used))
    }

    fn cell_of(stack: &[StackItem], what: &str) -> Result<Cell> {
        stack
            .last()
            .ok_or_else(|| CrossCheckError::Vm(format!("no {what}")))?
            .as_cell()
            .map(Clone::clone)
            .map_err(|error| CrossCheckError::Vm(format!("{what}: {error}")))
    }

    /// The frontier store of a pool holding `index` notes.
    pub fn fill(&self, index: u64) -> Result<Cell> {
        let (stack, _) = self.call("f_fill", vec![Self::integer(&index.to_string())?])?;
        Self::cell_of(&stack, "frontier")
    }

    /// The store section 13.2 deploys a pool with.
    pub fn genesis(&self) -> Result<Cell> {
        let (stack, _) = self.call("f_genesis", vec![])?;
        Self::cell_of(&stack, "genesis frontier")
    }

    /// The digit sum of `index` in base seven. It no longer decides what an
    /// append costs -- that is the point of the change -- but it is what the
    /// dictionary's cost was proportional to, so the tests that assert the
    /// cost no longer follows it need it.
    pub fn digit_sum(&self, index: u64) -> Result<u64> {
        let (stack, _) = self.call("f_digit_sum", vec![Self::integer(&index.to_string())?])?;
        let top = stack.last().ok_or_else(|| CrossCheckError::Vm("no sum".to_string()))?;
        top.as_integer()
            .map_err(|error| CrossCheckError::Vm(format!("sum: {error}")))?
            .to_string()
            .parse()
            .map_err(|error| CrossCheckError::Vm(format!("sum: {error}")))
    }

    /// The gas one append at `index` costs against that pool's frontier.
    pub fn append_gas(&self, index: u64) -> Result<i64> {
        let frontier = self.fill(index)?;
        let (_, gas) = self.call(
            "f_append",
            vec![
                StackItem::cell(frontier),
                Self::integer(&index.to_string())?,
                Self::integer("12345678901234567890")?,
            ],
        )?;
        Ok(gas)
    }

    /// The first append a deployed pool ever does, against the store the
    /// contract deploys with rather than one the probe built.
    pub fn genesis_append_gas(&self) -> Result<i64> {
        let frontier = self.genesis()?;
        self.append_against(frontier, 0)
    }

    /// The same append against a store of the same shape whose every slot is
    /// zero. It isolates one thing: what the VM charges for re-loading a cell
    /// it has already loaded in this transaction.
    pub fn zeroed_append_gas(&self, index: u64) -> Result<i64> {
        let (stack, _) = self.call("f_fill_zeros", vec![Self::integer(&index.to_string())?])?;
        let frontier = Self::cell_of(&stack, "zeroed frontier")?;
        self.append_against(frontier, index)
    }

    fn append_against(&self, frontier: Cell, index: u64) -> Result<i64> {
        let (_, gas) = self.call(
            "f_append",
            vec![
                StackItem::cell(frontier),
                Self::integer(&index.to_string())?,
                Self::integer("12345678901234567890")?,
            ],
        )?;
        Ok(gas)
    }

    /// The dictionary store for a pool at `index`.
    pub fn dict_fill(&self, index: u64) -> Result<Cell> {
        let (stack, _) = self.call("d_fill", vec![Self::integer(&index.to_string())?])?;
        Self::cell_of(&stack, "dictionary frontier")
    }

    /// The same append, against the container that was replaced.
    pub fn dict_append_gas(&self, index: u64) -> Result<i64> {
        let frontier = self.dict_fill(index)?;
        let (_, gas) = self.call(
            "d_append",
            vec![
                StackItem::cell(frontier),
                Self::integer(&index.to_string())?,
                Self::integer("12345678901234567890")?,
            ],
        )?;
        Ok(gas)
    }

    /// The gas `rounds` dictionary reads cost against a frontier of that age.
    pub fn dict_read_gas(&self, index: u64, rounds: u64) -> Result<i64> {
        let frontier = self.dict_fill(index)?;
        let (_, gas) = self.call(
            "d_reads",
            vec![StackItem::cell(frontier), Self::integer(&rounds.to_string())?],
        )?;
        Ok(gas)
    }

    /// The same for writes.
    pub fn dict_write_gas(&self, index: u64, rounds: u64) -> Result<i64> {
        let frontier = self.dict_fill(index)?;
        let (_, gas) = self.call(
            "d_writes",
            vec![StackItem::cell(frontier), Self::integer(&rounds.to_string())?],
        )?;
        Ok(gas)
    }

    /// What the same values cost to read from a flat cell chain.
    pub fn flat_read_gas(&self, rounds: u64) -> Result<i64> {
        let (stack, _) = self.call("f_flat_build", vec![])?;
        let chain = Self::cell_of(&stack, "chain")?;
        let (_, gas) = self.call(
            "f_flat_reads",
            vec![StackItem::cell(chain), Self::integer(&rounds.to_string())?],
        )?;
        Ok(gas)
    }
}
