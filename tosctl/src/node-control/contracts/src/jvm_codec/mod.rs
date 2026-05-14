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
 * the C++ side enforces; byte-exact parity against the live C++ codec
 * is locked by `jvm_codec::tests::parity_against_reference_vectors` and
 * the matching C++ test `JvmWorkchainCore::JvmCodecParityVectors` (in
 * `crypto/test/test-workchain-execution-registry.cpp`), both of which
 * assert the same 8 canonical hex hashes committed to
 * `jvm/core/jvm-codec-reference.txt`.
 *
 * To regenerate the reference vectors after an intentional wire-format
 * change:
 *   1. Update both the Rust and C++ encoders.
 *   2. cargo run -p contracts --example jvm_codec_reference \
 *          > jvm/core/jvm-codec-reference.txt
 *   3. Copy the new hex hashes into the `kExpected*` constants in the
 *      C++ test inline expectations.
 *   4. Verify `cargo test -p contracts jvm_codec` and
 *      `./test-workchain-execution-registry` both pass.
 */
pub mod action_create_account;
pub mod args;
pub mod address;
pub mod call_descriptor;
pub mod cli_parse;
pub mod contract_account_state;
pub mod event_registry;
pub mod deploy_descriptor;
pub mod manifest;
pub mod state_init;
pub mod storage_value;

pub use action_create_account::{
    encode_action_create_account, ACTION_CREATE_ACCOUNT_MAGIC,
};
pub use address::{
    compute_jvm_address_commit, compute_jvm_class_hash,
    compute_jvm_manifest_root_hash, derive_jvm_contract_address,
    JvmAddressCommit, JvmClassHash, JvmContractId, JvmManifestRootHash,
};
pub use args::{encode_jvm_args, JvmArgType, JvmArgs, JvmTypedArg};
pub use event_registry::{
    lookup_admitted_event, JvmEventSignature, ADMITTED_EVENT_SIGNATURES,
    DEPLOYER_EVT_DEPLOYED, DEPLOYER_EVT_INITIALIZED, DEPLOYER_EVT_NONCE,
    WALLET_EVT_EXECUTED, WALLET_EVT_INITIALIZED, WALLET_EVT_NONCE,
};
pub use cli_parse::{
    parse_manifest_cell, parse_manifest_json, parse_typed_arg,
    parse_typed_args, parse_workchain_address, ManifestEntrySpec,
};
pub use call_descriptor::{
    encode_jvm_call_descriptor, JvmCallDescriptor, JVM_CALL_DESCRIPTOR_MAGIC,
};
pub use contract_account_state::{
    encode_jvm_contract_account_state, JvmContractAccountState,
    JVM_CONTRACT_ACCOUNT_STATE_MAGIC,
    JVM_CONTRACT_ACCOUNT_STATE_SCHEMA_VERSION,
};
pub use deploy_descriptor::{
    encode_jvm_deploy_descriptor, JvmDeployDescriptor,
    JVM_DEPLOY_DESCRIPTOR_MAGIC,
};
pub use manifest::{
    encode_jvm_method_manifest, JvmMethodManifestEntry,
    JVM_METHOD_MANIFEST_MAGIC, JVM_METHOD_MANIFEST_SCHEMA_VERSION,
    JVM_METHOD_MANIFEST_MAX_ENTRIES,
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
