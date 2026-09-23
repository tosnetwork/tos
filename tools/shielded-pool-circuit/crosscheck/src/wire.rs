/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The eight derived public inputs, computed twice and compared.
//!
//! `shielded_pool_circuit::wire` is how a prover computes the public inputs
//! the contract will recompute from bytes. If the two disagree, every proof
//! the prover makes is a proof of a transaction the contract will refuse --
//! and the failure looks like "the proof does not verify", which says nothing
//! about where the disagreement is. So they are compared here, against values
//! the VM actually produced, before anything is proved.

use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};
use tos_vm::stack::integer::IntegerData;
use tos_vm::stack::StackItem;

use crate::{library_dir, stdlib_path, CrossCheckError, Result, ACTIVE_VERSION, TOS};

/// Exposes the derivations the contract performs on bytes. Nothing here
/// computes anything of its own.
const PROBE: &str = r#"
int w_output_data_hash(cell payload) method_id { return output_data_hash(payload); }
int w_pq_auth_key_hash(cell key) method_id { return pq_auth_key_hash(key); }
int w_recipient_hash(slice address) method_id { return public_recipient_hash(address); }
int w_execution_domain() method_id { return execution_domain(); }
int w_recovery_template(int owner, int data_hash) method_id {
  return recovery_template_hash(owner, data_hash);
}
int w_global_id() method_id { return global_id(); }
;; The probe's own account id, so the caller can compute the execution domain
;; from the same address the library used.
int w_self() method_id { return std_account_id(my_address()); }
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

/// A byte string as the canonical chain of cells: 127 bytes each until the
/// last, which carries what is left.
pub fn byte_chain(bytes: &[u8]) -> Result<Cell> {
    let chunks: Vec<&[u8]> = bytes.chunks(127).collect();
    let mut cell: Option<Cell> = None;
    for chunk in chunks.iter().rev() {
        let mut builder = BuilderData::new();
        builder
            .append_raw(chunk, chunk.len() * 8)
            .map_err(|error| CrossCheckError::Sandbox(format!("chunk: {error}")))?;
        if let Some(next) = cell {
            builder
                .checked_append_reference(next)
                .map_err(|error| CrossCheckError::Sandbox(format!("chain: {error}")))?;
        }
        cell = Some(
            builder
                .into_cell()
                .map_err(|error| CrossCheckError::Sandbox(format!("chain cell: {error}")))?,
        );
    }
    cell.ok_or_else(|| CrossCheckError::Fixture("an empty byte chain".to_string()))
}

/// `addr_std$10 anycast:nothing workchain_id:int8 address:bits256`.
fn std_address(account: &[u8; 32]) -> Result<SliceData> {
    let mut builder = BuilderData::new();
    let mut write = |value: usize, bits: usize| -> Result<()> {
        builder
            .append_bits(value, bits)
            .map_err(|error| CrossCheckError::Sandbox(format!("address: {error}")))?;
        Ok(())
    };
    write(2, 2)?;
    write(0, 1)?;
    write(0, 8)?;
    builder
        .append_raw(account, 256)
        .map_err(|error| CrossCheckError::Sandbox(format!("address: {error}")))?;
    SliceData::load_builder(builder)
        .map_err(|error| CrossCheckError::Sandbox(format!("address slice: {error}")))
}

/// A probe carrying the wire derivations.
pub struct WireProbe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl WireProbe {
    pub fn deploy() -> Result<Self> {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
        bc.set_workchain(0);
        let payer = bc.treasury("wire_deployer", 1_000 * TOS)?;
        let library = library_dir();
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir()
            .map_err(|error| CrossCheckError::Sandbox(format!("probe directory: {error}")))?;
        let probe_path = probe_dir.path().join("tos_shielded_wire_crosscheck_probe.fc");
        std::fs::write(&probe_path, PROBE)
            .map_err(|error| CrossCheckError::Sandbox(format!("write probe: {error}")))?;
        let code = compile_func(&[
            stdlib_path(),
            library.join("domains.fc"),
            library.join("empty-roots.fc"),
            library.join("notes.fc"),
            library.join("auth.fc"),
            library.join("payload.fc"),
            library.join("domain.fc"),
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

    fn call(&self, method: &str, args: Vec<StackItem>) -> Result<String> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, args)
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

    pub fn output_data_hash(&self, bytes: &[u8]) -> Result<String> {
        self.call("w_output_data_hash", vec![StackItem::cell(byte_chain(bytes)?)])
    }

    pub fn pq_auth_key_hash(&self, bytes: &[u8]) -> Result<String> {
        self.call("w_pq_auth_key_hash", vec![StackItem::cell(byte_chain(bytes)?)])
    }

    pub fn public_recipient_hash(&self, account: &[u8; 32]) -> Result<String> {
        self.call("w_recipient_hash", vec![StackItem::Slice(std_address(account)?)])
    }

    pub fn execution_domain(&self) -> Result<String> {
        self.call("w_execution_domain", vec![])
    }

    pub fn recovery_template_hash(&self, owner: &str, data_hash: &str) -> Result<String> {
        let arg = |value: &str| -> Result<StackItem> {
            IntegerData::from_str_radix(value, 10)
                .map(StackItem::integer)
                .map_err(|error| CrossCheckError::Fixture(format!("{value}: {error}")))
        };
        self.call("w_recovery_template", vec![arg(owner)?, arg(data_hash)?])
    }

    /// The chain's global id and this probe's own account id, which are the
    /// two things the execution domain is built from.
    pub fn domain_inputs(&self) -> Result<(i32, [u8; 32])> {
        let global: i64 = self
            .call("w_global_id", vec![])?
            .parse()
            .map_err(|error| CrossCheckError::Vm(format!("global id: {error}")))?;
        let account = self.call("w_self", vec![])?;
        let mut bytes = [0u8; 32];
        let value = IntegerData::from_str_radix(&account, 10)
            .map_err(|error| CrossCheckError::Vm(format!("account id: {error}")))?;
        let hex = format!("{:0>64}", value.to_str_radix(16));
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                .map_err(|error| CrossCheckError::Vm(format!("account id: {error}")))?;
        }
        Ok((global as i32, bytes))
    }
}
