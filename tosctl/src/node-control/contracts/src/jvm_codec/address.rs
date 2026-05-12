/*
 * Rust port of the wc=3 address derivation formula
 * (jvm/core/deploy-abi.cpp:175-232).
 *
 *   class_hash         = sha256(class_bytes), or all-zero if empty
 *   address_commit     = sha256(deployer || salt || init_args_cell.hash)
 *   manifest_root_hash = manifest_cell.hash, or all-zero if cell is null
 *   address            = sha256("TOS-JVM-CONTRACT-v2"
 *                                || deployer
 *                                || address_commit
 *                                || class_hash
 *                                || manifest_root_hash)
 *
 * All hashes are SHA-256.  The cell hash for `init_args_cell` is the
 * cell's representation hash (level 0), which matches what the C++ side
 * obtains via `td::Ref<vm::Cell>::get_hash()`.
 */
use chain_block::Cell;
use sha2::{Digest, Sha256};

use super::JVM_CONTRACT_ADDRESS_DOMAIN;

pub type JvmContractId = [u8; 32];
pub type JvmAddressCommit = [u8; 32];
pub type JvmClassHash = [u8; 32];
pub type JvmManifestRootHash = [u8; 32];

/// sha256(class_bytes), with all-zero output for empty class_bytes.
pub fn compute_jvm_class_hash(class_bytes: &[u8]) -> JvmClassHash {
    let mut out = [0u8; 32];
    if !class_bytes.is_empty() {
        let digest = Sha256::digest(class_bytes);
        out.copy_from_slice(digest.as_slice());
    }
    out
}

/// sha256(deployer || salt || init_args_cell.hash).
pub fn compute_jvm_address_commit(
    deployer: &JvmContractId,
    salt: &[u8; 32],
    init_args_cell: &Cell,
) -> JvmAddressCommit {
    let mut hasher = Sha256::new();
    hasher.update(deployer);
    hasher.update(salt);
    hasher.update(init_args_cell.repr_hash().as_slice());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// 32-byte representation hash of the manifest cell, or all-zero for
/// the null-cell case (a contract with no callable @ContractEntry
/// methods).
pub fn compute_jvm_manifest_root_hash(
    manifest_cell: Option<&Cell>,
) -> JvmManifestRootHash {
    let mut out = [0u8; 32];
    if let Some(cell) = manifest_cell {
        out.copy_from_slice(cell.repr_hash().as_slice());
    }
    out
}

/// sha256("TOS-JVM-CONTRACT-v2" || deployer || address_commit ||
///        class_hash || manifest_root_hash). Matches
/// `derive_jvm_contract_address_from_state` from the C++ side.
pub fn derive_jvm_contract_address(
    deployer: &JvmContractId,
    address_commit: &JvmAddressCommit,
    class_hash: &JvmClassHash,
    manifest_root_hash: &JvmManifestRootHash,
) -> JvmContractId {
    let mut hasher = Sha256::new();
    hasher.update(JVM_CONTRACT_ADDRESS_DOMAIN.as_bytes());
    hasher.update(deployer);
    hasher.update(address_commit);
    hasher.update(class_hash);
    hasher.update(manifest_root_hash);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}
