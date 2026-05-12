/*
 * Rust port of `encode_jvm_deploy_descriptor` (jvm/core/deploy-abi.cpp).
 *
 * Wire layout:
 *   jvm_deploy#4a564d44
 *     schema_version:uint8 (=1)
 *     deployer:bits256
 *     salt:bits256
 *     class_hash:bits256
 *     class_name:^Cell             -- chunk-encoded UTF-8 string
 *     class_bytes:^Cell            -- chunk-encoded class file bytes
 *     init_args:^Cell              -- JvmArgs cell (jvm_codec::args)
 */
use anyhow::{Context, Result};
use chain_block::{BuilderData, Cell, IBitstring};

use super::address::{JvmClassHash, JvmContractId};
use super::storage_value::encode_jvm_storage_value;

pub const JVM_DEPLOY_DESCRIPTOR_MAGIC: u32 = 0x4a56_4d44; // "JVMD"
pub const JVM_DEPLOY_DESCRIPTOR_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug)]
pub struct JvmDeployDescriptor {
    pub deployer: JvmContractId,
    pub salt: [u8; 32],
    pub class_hash: JvmClassHash,
    pub class_name: String,
    pub class_bytes: Vec<u8>,
    pub init_args: Cell,
}

pub fn encode_jvm_deploy_descriptor(d: &JvmDeployDescriptor) -> Result<Cell> {
    let class_name_cell = encode_jvm_storage_value(d.class_name.as_bytes())
        .context("jvm deploy descriptor: class_name encode failed")?;
    let class_bytes_cell = encode_jvm_storage_value(&d.class_bytes)
        .context("jvm deploy descriptor: class_bytes encode failed")?;

    let mut cb = BuilderData::new();
    cb.append_u32(JVM_DEPLOY_DESCRIPTOR_MAGIC)
        .context("jvm deploy magic append failed")?;
    cb.append_u8(JVM_DEPLOY_DESCRIPTOR_SCHEMA_VERSION)
        .context("jvm deploy schema_version append failed")?;
    cb.append_raw(&d.deployer, 256)
        .context("jvm deploy deployer append failed")?;
    cb.append_raw(&d.salt, 256)
        .context("jvm deploy salt append failed")?;
    cb.append_raw(&d.class_hash, 256)
        .context("jvm deploy class_hash append failed")?;
    cb.checked_append_reference(class_name_cell)
        .context("jvm deploy class_name ref append failed")?;
    cb.checked_append_reference(class_bytes_cell)
        .context("jvm deploy class_bytes ref append failed")?;
    cb.checked_append_reference(d.init_args.clone())
        .context("jvm deploy init_args ref append failed")?;
    cb.into_cell()
        .context("jvm deploy descriptor finalize failed")
}
