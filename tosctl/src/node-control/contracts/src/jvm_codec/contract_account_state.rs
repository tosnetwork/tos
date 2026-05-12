/*
 * Rust port of `encode_jvm_contract_account_state` (jvm/core/cell-codec.cpp).
 *
 * Wire layout (JVAC, schema_version=2):
 *
 *   jvm_contract_account#4a564143
 *     schema_version:uint8 (=2)
 *     stdlib_hash:bits256
 *     deployer:bits256
 *     address_commit:bits256
 *     class_bytes:^Cell                 (chunked storage-value form)
 *     storage_root:(Maybe ^Cell)
 *     manifest_root:(Maybe ^Cell)
 *
 * Note: `class_hash` is intentionally NOT on the wire — the C++ decoder
 * recomputes it from `class_bytes` (Round 14).  Callers that need the
 * class hash use `compute_jvm_class_hash` from `address.rs`.
 */
use anyhow::{Context, Result};
use chain_block::{BuilderData, Cell, IBitstring};

use super::address::{JvmAddressCommit, JvmContractId};
use super::storage_value::encode_jvm_storage_value;

pub const JVM_CONTRACT_ACCOUNT_STATE_MAGIC: u32 = 0x4a56_4143; // "JVAC"
pub const JVM_CONTRACT_ACCOUNT_STATE_SCHEMA_VERSION: u8 = 2;

#[derive(Clone, Debug)]
pub struct JvmContractAccountState {
    pub stdlib_hash: [u8; 32],
    pub deployer: JvmContractId,
    pub address_commit: JvmAddressCommit,
    /// Raw class bytes (the Avata `.class` blob).  Encoded into a
    /// chunk-chain cell on `encode_jvm_contract_account_state`.
    pub class_bytes: Vec<u8>,
    /// Optional initial storage trie.  `None` means the account starts
    /// with empty storage — the canonical first-activation shape, since
    /// the dispatch engine rejects non-empty storage_root on first
    /// activation.
    pub storage_root: Option<Cell>,
    /// Required method manifest.  Used to bind the dispatchable method
    /// set into the account address; passing `None` produces a contract
    /// that cannot be called.
    pub manifest_root: Option<Cell>,
}

/// Encode the JVAC cell.  Returns an error on any encoding failure.
pub fn encode_jvm_contract_account_state(
    state: &JvmContractAccountState,
) -> Result<Cell> {
    if state.class_bytes.is_empty() {
        anyhow::bail!(
            "encode_jvm_contract_account_state: class_bytes must not be empty"
        );
    }

    let class_bytes_cell = encode_jvm_storage_value(&state.class_bytes)
        .context("encode_jvm_contract_account_state: class_bytes encode failed")?;

    let mut cb = BuilderData::new();
    cb.append_u32(JVM_CONTRACT_ACCOUNT_STATE_MAGIC)
        .context("JVAC magic append failed")?;
    cb.append_u8(JVM_CONTRACT_ACCOUNT_STATE_SCHEMA_VERSION)
        .context("JVAC schema_version append failed")?;
    cb.append_raw(&state.stdlib_hash, 256)
        .context("JVAC stdlib_hash append failed")?;
    cb.append_raw(&state.deployer, 256)
        .context("JVAC deployer append failed")?;
    cb.append_raw(&state.address_commit, 256)
        .context("JVAC address_commit append failed")?;
    cb.checked_append_reference(class_bytes_cell)
        .context("JVAC class_bytes ref append failed")?;

    append_maybe_ref(&mut cb, state.storage_root.clone())
        .context("JVAC storage_root append failed")?;
    append_maybe_ref(&mut cb, state.manifest_root.clone())
        .context("JVAC manifest_root append failed")?;

    cb.into_cell().context("JVAC finalize failed")
}

fn append_maybe_ref(cb: &mut BuilderData, cell: Option<Cell>) -> Result<()> {
    match cell {
        Some(c) => {
            cb.append_bit_one()?;
            cb.checked_append_reference(c)?;
        }
        None => {
            cb.append_bit_zero()?;
        }
    }
    Ok(())
}
