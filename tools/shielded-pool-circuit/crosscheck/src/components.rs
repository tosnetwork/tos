/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Every cost in the pool that depends on something other than the code, as
//! a get-method that charges for exactly one of them.
//!
//! A ceiling is a promise that no legal path can exceed it, and no number of
//! whole transactions can make that promise: the space a transaction ranges
//! over is the product of a leaf index, two ring occupancies, an anchor kind,
//! a denomination and two nullifier orders, and a maximum taken over a
//! handful of points in a product space is a sample with a superlative
//! attached to it.
//!
//! What can be exhausted is each factor separately. The handlers are straight
//! lines -- parse, check, insert, append, write -- and each variable call
//! reads only its own arguments, so the whole is the sum of the parts and a
//! bound on the whole is the sum of bounds on the parts. That sum is
//! reachable by no input, which is the point of it: it is an upper bound and
//! it is allowed to be loose. Erring high costs a sender gas they did not
//! use; erring low strands a withdrawal in a contract whose code hash is its
//! address.
//!
//! This probe is the measuring end of that. It exposes the five library
//! functions whose cost moves -- the denomination walk, the anchor check, the
//! anchor write, the tree append and the nullifier insert -- and takes their
//! stores as arguments, so a sweep over four thousand keys fills a ring once
//! rather than four thousand times.

use chain_block::{Cell, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};
use tos_vm::stack::integer::IntegerData;
use tos_vm::stack::StackItem;

use crate::{library_dir, stdlib_path, CrossCheckError, Result, ACTIVE_VERSION, TOS};

/// Each method returns something, so that no call can be optimised away, and
/// each takes its store as an argument rather than building one, so that what
/// is measured is the operation and not the fixture.
const PROBE: &str = r#"
;; Section 12.1's amount check: a walk down the configured list that stops at
;; the first match, so what it costs depends on where in the list the amount
;; sits.
int c_denomination(cell config, int amount) method_id {
  return config_has_denomination(config, amount);
}

;; Section 6.3, all three kinds. ANCHOR_CURRENT does not touch the store;
;; the other two walk a dictionary whose depth is the ring's occupancy.
int c_check(cell anchors, int kind, int id, int root, int commitment_root, int now_seconds)
    method_id {
  anchor_require_valid(anchors, kind, id, root, commitment_root, now_seconds);
  return 1;
}

;; Section 6.1 and 6.2: the write every mutating path makes once.
(cell, int) c_preserve(cell anchors, int next_index, int root, int now_seconds,
                       int last_epoch) method_id {
  return anchors_preserve(anchors, next_index, root, now_seconds, last_epoch);
}

;; Section 5.3's append. Twelve levels, each costing what its base-seven digit
;; costs.
(cell, int) c_append(cell frontier, int index, int leaf) method_id {
  return frontier_append(frontier, index, leaf);
}

;; Section 7.3's insert, which a transact makes twice.
(int, int) c_insert(int root, int next_index, int nf, cell witness) method_id {
  return imt_insert(root, next_index, nf, witness);
}

;; Section 13's state cell, written and read back. Every path does both once.
;; The liability and the floor are Coins, which is a variable-length encoding,
;; so whether a pool holding a thousand nanotos and one holding the supply
;; cost the same to write down is a question and not an assumption.
int c_state_round_trip(int liability, int floor, int index,
                       cell frontier, cell anchors, cell config, cell vk) method_id {
  cell state = state_build(0, index, 0, 1, 0, liability, floor, frontier, anchors, config, vk);
  (_, _, _, _, _, int read_liability, int read_floor, _, _, _, _) = state_parse(state);
  return read_liability + read_floor;
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

pub struct ComponentProbe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl ComponentProbe {
    pub fn deploy() -> Result<Self> {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
        bc.set_workchain(0);
        let payer = bc.treasury("component_deployer", 1_000 * TOS)?;
        let library = library_dir();
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir()
            .map_err(|error| CrossCheckError::Sandbox(format!("probe directory: {error}")))?;
        let probe_path = probe_dir.path().join("tos_shielded_component_probe.fc");
        std::fs::write(&probe_path, PROBE)
            .map_err(|error| CrossCheckError::Sandbox(format!("write probe: {error}")))?;
        // The same sources the pool is built from, in the same order, minus
        // the contract itself. A probe compiled against a different set of
        // library files would be measuring a different library.
        let code = compile_func(&[
            stdlib_path(),
            library.join("domains.fc"),
            library.join("empty-roots.fc"),
            library.join("notes.fc"),
            library.join("tree.fc"),
            library.join("imt.fc"),
            library.join("auth.fc"),
            library.join("payload.fc"),
            library.join("domain.fc"),
            library.join("anchors.fc"),
            library.join("state.fc"),
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

    fn number(value: u64) -> Result<StackItem> {
        Self::integer(&value.to_string())
    }

    /// The gas one call costs, and the exit code it left, so that a caller
    /// can measure a refusal on purpose without the probe deciding for it
    /// that a refusal is a failure.
    fn call(&self, method: &str, args: Vec<StackItem>) -> Result<(Vec<StackItem>, i64, i32)> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, args)
            .map_err(|error| CrossCheckError::Vm(format!("{method}: {error}")))?;
        Ok((result.stack, result.gas_used, result.exit_code))
    }

    /// The gas of a call that has to succeed.
    fn gas(&self, method: &str, args: Vec<StackItem>) -> Result<i64> {
        let (_, gas, exit) = self.call(method, args)?;
        if exit != 0 {
            return Err(CrossCheckError::Vm(format!("{method} exited {exit}")));
        }
        Ok(gas)
    }

    /// What walking the denomination list to `amount` costs, against the
    /// configuration a pool is actually deployed with.
    pub fn denomination_gas(&self, config: &Cell, amount: u64) -> Result<i64> {
        let (stack, gas, exit) = self.call(
            "c_denomination",
            vec![StackItem::cell(config.clone()), Self::number(amount)?],
        )?;
        if exit != 0 {
            return Err(CrossCheckError::Vm(format!("c_denomination exited {exit}")));
        }
        let found = stack
            .last()
            .ok_or_else(|| CrossCheckError::Vm("c_denomination returned nothing".to_string()))?
            .as_integer()
            .map_err(|error| CrossCheckError::Vm(format!("c_denomination: {error}")))?
            .to_string();
        if found == "0" {
            return Err(CrossCheckError::Fixture(format!(
                "{amount} is not in the configured list, so this measures a refusal"
            )));
        }
        Ok(gas)
    }

    /// What checking an anchor of that kind costs.
    #[allow(clippy::too_many_arguments)]
    pub fn check_gas(
        &self,
        anchors: &Cell,
        kind: u64,
        id: u64,
        root: &str,
        commitment_root: &str,
        now_seconds: u64,
    ) -> Result<i64> {
        self.gas(
            "c_check",
            vec![
                StackItem::cell(anchors.clone()),
                Self::number(kind)?,
                Self::number(id)?,
                Self::integer(root)?,
                Self::integer(commitment_root)?,
                Self::number(now_seconds)?,
            ],
        )
    }

    /// What preserving a root into those rings costs.
    pub fn preserve_gas(
        &self,
        anchors: &Cell,
        next_index: u64,
        root: &str,
        now_seconds: u64,
        last_epoch: u64,
    ) -> Result<i64> {
        self.gas(
            "c_preserve",
            vec![
                StackItem::cell(anchors.clone()),
                Self::number(next_index)?,
                Self::integer(root)?,
                Self::number(now_seconds)?,
                Self::number(last_epoch)?,
            ],
        )
    }

    /// What appending a leaf at that index into that store costs.
    pub fn append_gas(&self, frontier: &Cell, index: u64, leaf: &str) -> Result<i64> {
        self.gas(
            "c_append",
            vec![StackItem::cell(frontier.clone()), Self::number(index)?, Self::integer(leaf)?],
        )
    }

    /// What writing the state cell and reading it back costs.
    #[allow(clippy::too_many_arguments)]
    pub fn state_round_trip_gas(
        &self,
        liability: &str,
        floor: &str,
        index: u64,
        frontier: &Cell,
        anchors: &Cell,
        config: &Cell,
        vk: &Cell,
    ) -> Result<i64> {
        self.gas(
            "c_state_round_trip",
            vec![
                Self::integer(liability)?,
                Self::integer(floor)?,
                Self::number(index)?,
                StackItem::cell(frontier.clone()),
                StackItem::cell(anchors.clone()),
                StackItem::cell(config.clone()),
                StackItem::cell(vk.clone()),
            ],
        )
    }

    /// What one nullifier insert costs.
    pub fn insert_gas(
        &self,
        root: &str,
        next_index: u64,
        nullifier: &str,
        witness: &Cell,
    ) -> Result<i64> {
        self.gas(
            "c_insert",
            vec![
                Self::integer(root)?,
                Self::number(next_index)?,
                Self::integer(nullifier)?,
                StackItem::cell(witness.clone()),
            ],
        )
    }
}
