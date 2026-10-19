/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! `imt.fc` in the VM, given witnesses the prover's model built.

use ark_ff::{BigInteger, PrimeField};
use chain_block::{BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::imt;
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};
use tos_vm::stack::integer::IntegerData;
use tos_vm::stack::StackItem;

use crate::{library_dir, stdlib_path, CrossCheckError, Result, ACTIVE_VERSION, TOS};

const PROBE: &str = r#"
int i_empty_at(int level) method_id { return imt_empty_at(level); }
int i_genesis_root() method_id { return imt_genesis_root(); }
(int, int) i_insert(int root, int next_index, int nf, cell witness) method_id {
  return imt_insert(root, next_index, nf, witness);
}
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

/// A field element as its 32 big-endian wire bytes.
fn be(value: Fr) -> [u8; 32] {
    let digits = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - digits.len()..].copy_from_slice(&digits);
    out
}

/// Section 7.2: a linked chain of level-zero cells, three fields each, built
/// from the last cell backwards so every non-final cell carries exactly one
/// reference.
fn encode_path(fields: &[Fr]) -> Result<Cell> {
    if !fields.len().is_multiple_of(3) || fields.is_empty() {
        return Err(CrossCheckError::Fixture("a path cell holds exactly three fields".to_string()));
    }
    let cells = fields.len() / 3;
    let mut chain: Option<Cell> = None;
    for index in (0..cells).rev() {
        let mut builder = BuilderData::new();
        for offset in 0..3 {
            builder
                .append_raw(&be(fields[index * 3 + offset]), 256)
                .map_err(|error| CrossCheckError::Sandbox(format!("path field: {error}")))?;
        }
        if let Some(next) = chain {
            builder
                .checked_append_reference(next)
                .map_err(|error| CrossCheckError::Sandbox(format!("path chain: {error}")))?;
        }
        chain = Some(
            builder
                .into_cell()
                .map_err(|error| CrossCheckError::Sandbox(format!("path cell: {error}")))?,
        );
    }
    chain.ok_or_else(|| CrossCheckError::Fixture("an empty path".to_string()))
}

/// Section 7.2's witness root.
pub fn encode_witness(witness: &imt::Witness) -> Result<Cell> {
    let mut builder = BuilderData::new();
    builder
        .append_u32(witness.low_index)
        .map_err(|error| CrossCheckError::Sandbox(format!("low index: {error}")))?;
    builder
        .append_raw(&be(witness.low_value), 256)
        .map_err(|error| CrossCheckError::Sandbox(format!("low value: {error}")))?;
    builder
        .append_u32(witness.low_next_index)
        .map_err(|error| CrossCheckError::Sandbox(format!("low next index: {error}")))?;
    builder
        .append_raw(&be(witness.low_next_value), 256)
        .map_err(|error| CrossCheckError::Sandbox(format!("low next value: {error}")))?;
    builder
        .checked_append_reference(encode_path(&witness.low_path)?)
        .map_err(|error| CrossCheckError::Sandbox(format!("low path: {error}")))?;
    builder
        .checked_append_reference(encode_path(&witness.append_path)?)
        .map_err(|error| CrossCheckError::Sandbox(format!("append path: {error}")))?;
    builder.into_cell().map_err(|error| CrossCheckError::Sandbox(format!("witness: {error}")))
}

pub struct ImtProbe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl ImtProbe {
    pub fn deploy() -> Result<Self> {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
        bc.set_workchain(0);
        let payer = bc.treasury("imt_deployer", 1_000 * TOS)?;
        let library = library_dir();
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir()
            .map_err(|error| CrossCheckError::Sandbox(format!("probe directory: {error}")))?;
        let probe_path = probe_dir.path().join("tos_shielded_imt_crosscheck_probe.fc");
        std::fs::write(&probe_path, PROBE)
            .map_err(|error| CrossCheckError::Sandbox(format!("write probe: {error}")))?;
        let code = compile_func(&[
            stdlib_path(),
            library.join("domains.fc"),
            library.join("empty-roots.fc"),
            library.join("notes.fc"),
            library.join("imt.fc"),
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

    fn call(&self, method: &str, args: Vec<StackItem>) -> Result<Vec<StackItem>> {
        Ok(self.call_with_gas(method, args)?.0)
    }

    fn call_with_gas(&self, method: &str, args: Vec<StackItem>) -> Result<(Vec<StackItem>, i64)> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, args)
            .map_err(|error| CrossCheckError::Vm(format!("{method}: {error}")))?;
        if result.exit_code != 0 {
            return Err(CrossCheckError::Vm(format!("{method} exited {}", result.exit_code)));
        }
        Ok((result.stack, result.gas_used))
    }

    /// The gas one `imt_insert` costs, which is what the nullifier tree
    /// charges a transaction twice.
    pub fn insert_gas(
        &self,
        root: &str,
        next_index: u64,
        nullifier: &str,
        witness: &imt::Witness,
    ) -> Result<i64> {
        let (_, gas) = self.call_with_gas(
            "i_insert",
            vec![
                Self::integer(root)?,
                Self::integer(&next_index.to_string())?,
                Self::integer(nullifier)?,
                StackItem::cell(encode_witness(witness)?),
            ],
        )?;
        Ok(gas)
    }

    pub fn empty_at(&self, level: usize) -> Result<String> {
        let stack = self.call("i_empty_at", vec![Self::integer(&level.to_string())?])?;
        Self::top(&stack)
    }

    pub fn genesis_root(&self) -> Result<String> {
        let stack = self.call("i_genesis_root", vec![])?;
        Self::top(&stack)
    }

    /// `imt_insert`, returning the new root and the new next index.
    pub fn insert(
        &self,
        root: &str,
        next_index: u64,
        nullifier: &str,
        witness: &imt::Witness,
    ) -> Result<(String, u64)> {
        let stack = self.call(
            "i_insert",
            vec![
                Self::integer(root)?,
                Self::integer(&next_index.to_string())?,
                Self::integer(nullifier)?,
                StackItem::cell(encode_witness(witness)?),
            ],
        )?;
        if stack.len() < 2 {
            return Err(CrossCheckError::Vm("i_insert returned fewer than two values".to_string()));
        }
        let next = stack[stack.len() - 1]
            .as_integer()
            .map_err(|error| CrossCheckError::Vm(format!("next index: {error}")))?
            .to_string()
            .parse()
            .map_err(|error| CrossCheckError::Vm(format!("next index: {error}")))?;
        let new_root = stack[stack.len() - 2]
            .as_integer()
            .map_err(|error| CrossCheckError::Vm(format!("root: {error}")))?
            .to_string();
        Ok((new_root, next))
    }

    fn top(stack: &[StackItem]) -> Result<String> {
        let top = stack.last().ok_or_else(|| CrossCheckError::Vm("no result".to_string()))?;
        Ok(top.as_integer().map_err(|error| CrossCheckError::Vm(format!("{error}")))?.to_string())
    }
}
