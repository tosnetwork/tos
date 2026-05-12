/*
 * Rust port of `encode_jvm_args` (jvm/core/message-abi.cpp).
 *
 * Wire layout:
 *
 *   jvm_args#4a564d41
 *     schema_version:uint8 (=1)
 *     count:uint8
 *     entries:^(JvmArgNode chain)?    -- absent when count == 0
 *
 *   jvm_arg_node
 *     type:uint8
 *     has_next:bit
 *     next:^JvmArgNode?               -- only when has_next == 1
 *     value:^Cell                     -- chunked storage-value encoding
 */
use anyhow::{Context, Result, anyhow};
use chain_block::{BuilderData, Cell, IBitstring};

use super::storage_value::encode_jvm_storage_value;

pub const JVM_ARGS_MAGIC: u32 = 0x4a56_4d41; // "JVMA"
pub const JVM_ARGS_SCHEMA_VERSION: u8 = 1;
pub const JVM_ARGS_MAX_COUNT: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum JvmArgType {
    Bool = 1,
    Int32 = 2,
    Int64 = 3,
    Bytes = 4,
    Address = 5,
    Uint256 = 6,
    Bytes32 = 7,
    Bytes4 = 8,
}

#[derive(Clone, Debug)]
pub struct JvmTypedArg {
    pub arg_type: JvmArgType,
    pub bytes: Vec<u8>,
}

impl JvmTypedArg {
    pub fn new(arg_type: JvmArgType, bytes: Vec<u8>) -> Self {
        Self { arg_type, bytes }
    }

    pub fn bool_(value: bool) -> Self {
        Self::new(JvmArgType::Bool, vec![if value { 1 } else { 0 }])
    }

    pub fn int32(value: i32) -> Self {
        Self::new(JvmArgType::Int32, value.to_be_bytes().to_vec())
    }

    pub fn int64(value: i64) -> Self {
        Self::new(JvmArgType::Int64, value.to_be_bytes().to_vec())
    }

    pub fn bytes32(value: [u8; 32]) -> Self {
        Self::new(JvmArgType::Bytes32, value.to_vec())
    }

    pub fn bytes4(value: [u8; 4]) -> Self {
        Self::new(JvmArgType::Bytes4, value.to_vec())
    }

    pub fn uint256(value: [u8; 32]) -> Self {
        Self::new(JvmArgType::Uint256, value.to_vec())
    }

    pub fn address(workchain: i32, account_id: [u8; 32]) -> Self {
        let mut bytes = Vec::with_capacity(36);
        bytes.extend_from_slice(&workchain.to_be_bytes());
        bytes.extend_from_slice(&account_id);
        Self::new(JvmArgType::Address, bytes)
    }

    pub fn raw_bytes(value: Vec<u8>) -> Self {
        Self::new(JvmArgType::Bytes, value)
    }
}

#[derive(Clone, Debug, Default)]
pub struct JvmArgs {
    pub values: Vec<JvmTypedArg>,
}

impl JvmArgs {
    pub fn new(values: Vec<JvmTypedArg>) -> Self {
        Self { values }
    }
}

/// Encode args into the canonical `jvm_args#4a564d41` cell.  Empty args
/// produce a header-only root cell; non-empty args wrap a back-linked
/// chain in a single child ref.
pub fn encode_jvm_args(args: &JvmArgs) -> Result<Cell> {
    if args.values.len() > JVM_ARGS_MAX_COUNT {
        return Err(anyhow!(
            "jvm args: count {} exceeds {}",
            args.values.len(),
            JVM_ARGS_MAX_COUNT
        ));
    }

    let chain_head = if args.values.is_empty() {
        None
    } else {
        Some(encode_arg_chain(&args.values)?)
    };

    let mut root = BuilderData::new();
    root.append_u32(JVM_ARGS_MAGIC)
        .context("jvm args magic append failed")?;
    root.append_u8(JVM_ARGS_SCHEMA_VERSION)
        .context("jvm args schema_version append failed")?;
    root.append_u8(args.values.len() as u8)
        .context("jvm args count append failed")?;
    if let Some(head) = chain_head {
        root.checked_append_reference(head)
            .context("jvm args chain head ref append failed")?;
    }
    root.into_cell()
        .context("jvm args root finalize failed")
}

fn encode_arg_chain(values: &[JvmTypedArg]) -> Result<Cell> {
    let mut next: Option<Cell> = None;
    for arg in values.iter().rev() {
        let value_cell = encode_jvm_storage_value(&arg.bytes)
            .context("jvm arg value encoding failed")?;
        let mut node = BuilderData::new();
        node.append_u8(arg.arg_type as u8)
            .context("jvm arg type append failed")?;
        match next.take() {
            Some(child) => {
                node.append_bit_one()
                    .context("jvm arg has_next bit failed")?;
                node.checked_append_reference(child)
                    .context("jvm arg next ref append failed")?;
            }
            None => {
                node.append_bit_zero()
                    .context("jvm arg tail bit failed")?;
            }
        }
        node.checked_append_reference(value_cell)
            .context("jvm arg value ref append failed")?;
        next = Some(
            node.into_cell()
                .context("jvm arg node finalize failed")?,
        );
    }
    Ok(next.expect("non-empty values always produce at least one node"))
}
