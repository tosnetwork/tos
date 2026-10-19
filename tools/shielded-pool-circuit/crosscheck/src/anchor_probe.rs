/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! What the anchor rings cost once they are no longer empty.
//!
//! Section 6 keeps two rings, 4,096 recent roots and 2,880 epoch
//! checkpoints. At genesis both are empty dictionaries, so the write a
//! transaction makes lands in a dictionary with no nodes and the read a
//! transaction makes is skipped entirely when it proves against the current
//! root. Neither stays true for a pool that has been running: the rings fill
//! within an hour of traffic and stay full for the pool's life.
//!
//! This probe fills the rings to an arbitrary occupancy and reports what the
//! preserve and the check then cost.

use chain_block::{Cell, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};
use tos_vm::stack::integer::IntegerData;
use tos_vm::stack::StackItem;

use crate::{library_dir, stdlib_path, CrossCheckError, Result, ACTIVE_VERSION, TOS};

const PROBE: &str = r#"
;; An anchor store whose recent ring holds `recent_count` entries and whose
;; epoch ring holds `epoch_count`. The roots are arbitrary; only occupancy
;; changes what a dictionary operation costs.
cell a_empty() method_id { return anchors_empty(); }

;; Filling a ring costs far more than a get-method may spend, so it is done a
;; chunk at a time and the store is carried back in. Nothing here is measured.
cell a_fill_recent(cell anchors, int from, int to) method_id {
  (cell recent, cell epoch_dict) = anchors_parse(anchors);
  while (from < to) {
    recent = recent.udict_set_builder(anchor_key_bits(), from % recent_root_slots(),
                                      anchor_entry_build(from, 0x5eed0000 + from));
    from = from + 1;
  }
  return anchors_build(recent, epoch_dict);
}

cell a_fill_epoch(cell anchors, int from, int to) method_id {
  (cell recent, cell epoch_dict) = anchors_parse(anchors);
  while (from < to) {
    epoch_dict = epoch_dict.udict_set_builder(anchor_key_bits(), from % anchor_epoch_slots(),
                                              anchor_entry_build(from, 0x5eed0000 + from));
    from = from + 1;
  }
  return anchors_build(recent, epoch_dict);
}

;; The measured write: what a handler does once per mutation.
(cell, int) a_preserve(cell anchors, int next_index, int root, int now_seconds,
                       int last_epoch) method_id {
  return anchors_preserve(anchors, next_index, root, now_seconds, last_epoch);
}

;; The measured read, for a proof against a recent root rather than the
;; current one. It returns a constant so nothing about the call can be
;; eliminated.
int a_check_recent(cell anchors, int id, int root, int commitment_root, int now_seconds)
    method_id {
  anchor_require_valid(anchors, anchor_recent(), id, root, commitment_root, now_seconds);
  return 1;
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

/// The recent ring's slot count, and the epoch ring's.
pub const RECENT_SLOTS: u64 = 4096;
pub const EPOCH_SLOTS: u64 = 2880;

pub struct AnchorProbe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl AnchorProbe {
    pub fn deploy() -> Result<Self> {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
        bc.set_workchain(0);
        let payer = bc.treasury("anchor_deployer", 1_000 * TOS)?;
        let library = library_dir();
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir()
            .map_err(|error| CrossCheckError::Sandbox(format!("probe directory: {error}")))?;
        let probe_path = probe_dir.path().join("tos_shielded_anchor_probe.fc");
        std::fs::write(&probe_path, PROBE)
            .map_err(|error| CrossCheckError::Sandbox(format!("write probe: {error}")))?;
        let code = compile_func(&[stdlib_path(), library.join("anchors.fc"), probe_path])?;
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

    fn integer(value: u64) -> Result<StackItem> {
        IntegerData::from_str_radix(&value.to_string(), 10)
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

    /// One filling step, small enough to fit a get-method's gas.
    const CHUNK: u64 = 64;

    fn store(&self, method: &str, args: Vec<StackItem>) -> Result<Cell> {
        let (stack, _) = self.call(method, args)?;
        let top = stack.last().ok_or_else(|| CrossCheckError::Vm("no store".to_string()))?;
        top.as_cell()
            .map(Clone::clone)
            .map_err(|error| CrossCheckError::Vm(format!("store: {error}")))
    }

    /// An anchor store with the given occupancy in each ring.
    pub fn fill(&self, recent: u64, epoch: u64) -> Result<Cell> {
        let mut anchors = self.store("a_empty", vec![])?;
        for (method, count) in [("a_fill_recent", recent), ("a_fill_epoch", epoch)] {
            let mut from = 0;
            while from < count {
                let to = (from + Self::CHUNK).min(count);
                anchors = self.store(
                    method,
                    vec![StackItem::cell(anchors), Self::integer(from)?, Self::integer(to)?],
                )?;
                from = to;
            }
        }
        Ok(anchors)
    }

    /// The same store with more entries in the recent ring, rather than a
    /// fresh one built from empty.
    ///
    /// A sweep over every occupancy a ring can reach is quadratic if each
    /// point rebuilds its ring and linear if each point extends the last.
    /// The occupancies a pool passes through are consecutive, so extending
    /// is also the more faithful of the two.
    pub fn extend_recent(&self, anchors: Cell, from: u64, to: u64) -> Result<Cell> {
        self.extend("a_fill_recent", anchors, from, to)
    }

    /// The same, for the epoch ring.
    pub fn extend_epoch(&self, anchors: Cell, from: u64, to: u64) -> Result<Cell> {
        self.extend("a_fill_epoch", anchors, from, to)
    }

    fn extend(&self, method: &str, anchors: Cell, from: u64, to: u64) -> Result<Cell> {
        let mut store = anchors;
        let mut at = from;
        while at < to {
            let next = (at + Self::CHUNK).min(to);
            store = self.store(
                method,
                vec![StackItem::cell(store), Self::integer(at)?, Self::integer(next)?],
            )?;
            at = next;
        }
        Ok(store)
    }

    /// The genesis store: both rings empty.
    pub fn empty(&self) -> Result<Cell> {
        self.store("a_empty", vec![])
    }

    /// What one `anchors_preserve` costs against rings of that occupancy.
    ///
    /// `epoch_advances` decides whether the epoch ring is written too, which
    /// is the more expensive of the two branches and the one a pool takes
    /// once every thirty seconds.
    pub fn preserve_gas(&self, recent: u64, epoch: u64, epoch_advances: bool) -> Result<i64> {
        let anchors = self.fill(recent, epoch)?;
        // An epoch that has already been checkpointed suppresses the second
        // write; one behind the clock does not.
        let now = 1_000_000u64;
        let last_epoch = if epoch_advances { now / 30 - 1 } else { now / 30 };
        let (_, gas) = self.call(
            "a_preserve",
            vec![
                StackItem::cell(anchors),
                Self::integer(12_345)?,
                Self::integer(0x5eed_1234)?,
                Self::integer(now)?,
                Self::integer(last_epoch)?,
            ],
        )?;
        Ok(gas)
    }

    /// What checking a proof against a recent root costs at that occupancy.
    pub fn check_recent_gas(&self, recent: u64, id: u64) -> Result<i64> {
        let anchors = self.fill(recent, 0)?;
        let (_, gas) = self.call(
            "a_check_recent",
            vec![
                StackItem::cell(anchors),
                Self::integer(id)?,
                Self::integer(0x5eed_0000 + id)?,
                Self::integer(0)?,
                Self::integer(1_000_000)?,
            ],
        )?;
        Ok(gas)
    }
}
