/*
 * Rust port of the consensus-side JVM ABI codecs for wc=3.
 *
 * Mirrors:
 *   - `jvm/core/message-abi.{h,cpp}`   — JvmArgs / JvmCallDescriptor
 *   - `jvm/core/deploy-abi.{h,cpp}`    — JvmDeployDescriptor + the
 *                                         deterministic address formula
 *   - `jvm/core/cell-codec.{h,cpp}`    — JvmContractAccountState +
 *                                         StateInit
 *   - `jvm/core/storage-cell-host.cpp` — chunked storage-value cell
 *
 * Byte-stability is consensus-critical: every Rust output cell here
 * must produce a hash byte-identical to what the C++ encoders produce
 * for the same logical input.  The structural tests under
 * `jvm_codec::tests` lock the magic + schema_version + chunking rules
 * the C++ side enforces; parity against the live C++ codec is verified
 * by `cargo test -p contracts jvm_codec` against fixture inputs
 * (extend by adding a fixture, running the C++ test that exposes the
 * expected hash via `crypto/test/test-workchain-execution-registry`,
 * and pasting back the hex digest).
 */
pub mod args;
pub mod address;
pub mod call_descriptor;
pub mod deploy_descriptor;
pub mod state_init;
pub mod storage_value;

pub use address::{
    compute_jvm_address_commit, compute_jvm_class_hash,
    compute_jvm_manifest_root_hash, derive_jvm_contract_address,
    JvmAddressCommit, JvmClassHash, JvmContractId, JvmManifestRootHash,
};
pub use args::{encode_jvm_args, JvmArgType, JvmArgs, JvmTypedArg};
pub use call_descriptor::{
    encode_jvm_call_descriptor, JvmCallDescriptor, JVM_CALL_DESCRIPTOR_MAGIC,
};
pub use deploy_descriptor::{
    encode_jvm_deploy_descriptor, JvmDeployDescriptor,
    JVM_DEPLOY_DESCRIPTOR_MAGIC,
};
pub use state_init::encode_jvm_state_init_cell;
pub use storage_value::encode_jvm_storage_value;

/// Activation marker byte that the host writes into `account.code` for
/// every wc=3 contract. Used by `encode_jvm_state_init_cell`.
pub const JVM_ACTIVATION_CODE_MARKER: u8 = 0x4a;

/// Domain tag for the wc=3 contract address derivation. Must equal the
/// C++ constant in `jvm/core/deploy-abi.cpp:220`.
pub const JVM_CONTRACT_ADDRESS_DOMAIN: &str = "TOS-JVM-CONTRACT-v2";

#[cfg(test)]
mod tests;
