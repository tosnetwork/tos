/*
 * Rust port of `encode_jvm_call_descriptor` (jvm/core/message-abi.cpp).
 *
 * Wire layout:
 *   jvm_call#4a564932
 *     schema_version:uint8 (=2)
 *     method_id:uint32
 *     args:^Cell
 */
use anyhow::{Context, Result};
use chain_block::{BuilderData, Cell, IBitstring};

use super::args::{encode_jvm_args, JvmArgs};

pub const JVM_CALL_DESCRIPTOR_MAGIC: u32 = 0x4a56_4932; // "JVI2"
pub const JVM_CALL_DESCRIPTOR_SCHEMA_VERSION: u8 = 2;

#[derive(Clone, Debug)]
pub struct JvmCallDescriptor {
    pub method_id: u32,
    pub args: JvmArgs,
}

impl JvmCallDescriptor {
    pub fn new(method_id: u32, args: JvmArgs) -> Self {
        Self { method_id, args }
    }
}

/// Encode a JVM call descriptor as a single cell suitable for an
/// internal-message body.  The args sub-cell is always present; a
/// parameterless call carries an empty `JvmArgs` (count=0).
pub fn encode_jvm_call_descriptor(descriptor: &JvmCallDescriptor) -> Result<Cell> {
    let args_cell = encode_jvm_args(&descriptor.args)
        .context("jvm call descriptor: args encode failed")?;
    let mut cb = BuilderData::new();
    cb.append_u32(JVM_CALL_DESCRIPTOR_MAGIC)
        .context("jvm call descriptor magic append failed")?;
    cb.append_u8(JVM_CALL_DESCRIPTOR_SCHEMA_VERSION)
        .context("jvm call descriptor schema_version append failed")?;
    cb.append_u32(descriptor.method_id)
        .context("jvm call descriptor method_id append failed")?;
    cb.checked_append_reference(args_cell)
        .context("jvm call descriptor args ref append failed")?;
    cb.into_cell()
        .context("jvm call descriptor finalize failed")
}
