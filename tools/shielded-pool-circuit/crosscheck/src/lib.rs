/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Runs the shielded FunC library inside the VM and compares every section 4
//! and section 5 value against the circuit gadgets.
//!
//! Why this exists: the FunC library and the sandbox reference beside it were
//! written from section 4 by the same hand, so a misreading of the profile
//! would appear in both and neither would catch it. The circuit is a third,
//! independent reading. This crate is where the two meet, and it compares
//! against values the VM actually produced -- not against that reference.
//!
//! Two path rules matter here and are easy to get wrong:
//!
//! * the `.fc` sources are resolved from `CARGO_MANIFEST_DIR`, so the library
//!   under test is always the one in this checkout;
//! * `TOS_ROOT` is used only so the sandbox can find the `func`/`fift`
//!   binaries, which are build outputs and carry no protocol content.

use std::path::PathBuf;

use chain_block::{BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder, SandboxError};
use tos_vm::stack::integer::IntegerData;
use tos_vm::stack::StackItem;

pub(crate) const TOS: u64 = 1_000_000_000;
pub const ACTIVE_VERSION: u32 = 18;

pub mod acceptance;
pub mod anchor_probe;
pub mod ceiling;
pub mod components;
pub mod frontier_probe;
pub mod imt_probe;
pub mod pool;
pub mod stark_sketch_probe;
pub mod transact;
pub mod wire;

/// Anything that stops the cross-check from producing a comparison.
#[derive(Debug)]
pub enum CrossCheckError {
    Sandbox(String),
    Vm(String),
    Fixture(String),
}

impl std::fmt::Display for CrossCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrossCheckError::Sandbox(detail) => write!(f, "sandbox: {detail}"),
            CrossCheckError::Vm(detail) => write!(f, "vm: {detail}"),
            CrossCheckError::Fixture(detail) => write!(f, "fixture: {detail}"),
        }
    }
}

impl std::error::Error for CrossCheckError {}

impl From<SandboxError> for CrossCheckError {
    fn from(error: SandboxError) -> Self {
        CrossCheckError::Sandbox(error.to_string())
    }
}

type Result<T> = std::result::Result<T, CrossCheckError>;

/// The probe exposes the library's own functions as get-methods. It adds no
/// arithmetic of its own: every returned value is what the library computed.
///
/// `p_owner_nf_key_hash` is the one composition here, because section 2.1's
/// hash has no named function in the library. It is still the library's `h7`
/// and the library's generated domain constant.
const PROBE: &str = r#"
int p_owner_nf_key_hash(int k) method_id {
  return h7(domain_owner_nf_hash(), k, 0, 0, 0, 0, 0, 0);
}
int p_owner_commitment(int a, int b, int c) method_id { return owner_commitment(a, b, c); }
int p_note_body(int a, int b, int c) method_id { return note_body_commitment(a, b, c); }
int p_note_commitment(int a, int b) method_id { return note_commitment(a, b); }
int p_nullifier(int a, int b) method_id { return nullifier(a, b); }
int p_phantom(int a, int b, int c) method_id { return phantom_nullifier(a, b, c); }
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

/// A deployed probe contract.
pub struct Probe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

/// The directory holding the shielded FunC library in *this* checkout.
pub fn library_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../crypto/smartcont/shielded")
}

/// `stdlib.fc` from this checkout, not from wherever `TOS_ROOT` points.
pub fn stdlib_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../crypto/smartcont/stdlib.fc")
}

impl Probe {
    /// Compiles the library with the probe and deploys it at global version 17.
    pub fn deploy() -> Result<Self> {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
        let payer = bc.treasury("deployer", 1_000 * TOS)?;

        let library = library_dir();
        // Print the resolved path: the one mistake that would silently void
        // this whole comparison is compiling some other checkout's library.
        println!(
            "shielded FunC library under test: {}",
            library.canonicalize().unwrap_or(library.clone()).display()
        );
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir()
            .map_err(|error| CrossCheckError::Sandbox(format!("probe directory: {error}")))?;
        let probe_path = probe_dir.path().join("tos_shielded_circuit_crosscheck_probe.fc");
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

        let mut data = BuilderData::new();
        data.append_u32(0)
            .map_err(|error| CrossCheckError::Sandbox(format!("state data: {error}")))?;
        let data_cell = data
            .into_cell()
            .map_err(|error| CrossCheckError::Sandbox(format!("state data cell: {error}")))?;
        let si = StateInit::with_code_and_data(code, data_cell);
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

    fn arg(value: &str) -> Result<StackItem> {
        // A 256-bit value must never be parsed as an i64 on the way in.
        let integer = IntegerData::from_str_radix(value, 10)
            .map_err(|error| CrossCheckError::Fixture(format!("{value}: {error}")))?;
        Ok(StackItem::integer(integer))
    }

    /// Calls a get-method returning one field element, as a decimal string.
    ///
    /// The returned string is what the VM produced. It is never widened,
    /// truncated or routed through a machine integer.
    pub fn call_field(&self, method: &str, args: &[&str]) -> Result<String> {
        let mut stack = Vec::with_capacity(args.len());
        for value in args {
            stack.push(Self::arg(value)?);
        }
        let result = self
            .bc
            .run_get_method(&self.addr, method, stack)
            .map_err(|error| CrossCheckError::Vm(format!("{method}: {error}")))?;
        if result.exit_code != 0 {
            return Err(CrossCheckError::Vm(format!("{method} exited {}", result.exit_code)));
        }
        let top = result
            .stack
            .last()
            .ok_or_else(|| CrossCheckError::Vm(format!("{method} returned nothing")))?;
        let integer =
            top.as_integer().map_err(|error| CrossCheckError::Vm(format!("{method}: {error}")))?;
        Ok(integer.to_string())
    }

    /// The store a pool is deployed with, which is where a sequence of
    /// appends starts. It is a built cell rather than an absent one: the
    /// level chain has no encoding for "empty", and an append refuses a store
    /// it cannot read rather than inventing one.
    pub fn frontier_genesis(&self) -> Result<Cell> {
        let result = self
            .bc
            .run_get_method(&self.addr, "p_frontier_genesis", vec![])
            .map_err(|error| CrossCheckError::Vm(format!("p_frontier_genesis: {error}")))?;
        if result.exit_code != 0 {
            return Err(CrossCheckError::Vm(format!(
                "p_frontier_genesis exited {}",
                result.exit_code
            )));
        }
        result
            .stack
            .last()
            .ok_or_else(|| CrossCheckError::Vm("no genesis frontier".to_string()))?
            .as_cell()
            .map(Clone::clone)
            .map_err(|error| CrossCheckError::Vm(format!("genesis frontier: {error}")))
    }

    /// Calls `frontier_append` and returns the new store and the new root.
    pub fn append(&self, frontier: Cell, index: u64, leaf: &str) -> Result<(Cell, String)> {
        let stack =
            vec![StackItem::Cell(frontier), Self::arg(&index.to_string())?, Self::arg(leaf)?];
        let result = self
            .bc
            .run_get_method(&self.addr, "p_append", stack)
            .map_err(|error| CrossCheckError::Vm(format!("p_append: {error}")))?;
        if result.exit_code != 0 {
            return Err(CrossCheckError::Vm(format!("p_append exited {}", result.exit_code)));
        }
        if result.stack.len() != 2 {
            return Err(CrossCheckError::Vm("p_append must return a store and a root".to_string()));
        }
        let root = result.stack[1]
            .as_integer()
            .map_err(|error| CrossCheckError::Vm(format!("p_append root: {error}")))?
            .to_string();
        let store = result.stack[0]
            .as_cell()
            .map(Clone::clone)
            .map_err(|error| CrossCheckError::Vm(format!("p_append store: {error}")))?;
        Ok((store, root))
    }
}

/// Loads the fixture that the circuit crate wrote.
pub fn load_fixture() -> Result<shielded_pool_circuit::fixture::Section45Fixture> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/section45.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|error| CrossCheckError::Fixture(format!("{}: {error}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|error| CrossCheckError::Fixture(format!("{}: {error}", path.display())))
}
