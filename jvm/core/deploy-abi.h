/*
    JVM Workchain — deployment message ABI codec.

    This fixes the deterministic deploy envelope used by future RPC/admission
    code and consensus deploy handling. It does not load classes yet; it only
    validates and commits to the bytes and init args carried by a deploy body.
*/
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "jvm/core/message-abi.h"
#include "jvm/core/storage-cell-host.h"
#include "td/utils/Status.h"
#include "vm/cells.h"

namespace jvm_workchain {

constexpr std::uint32_t kJvmDeployDescriptorMagic = 0x4a564d44;  // "JVMD"
constexpr std::uint8_t kJvmDeployDescriptorSchemaVersion = 1;
constexpr unsigned kJvmClassHashBytes = 32;
constexpr unsigned kJvmAddressCommitBytes = 32;
constexpr std::size_t kJvmDeployClassNameMaxBytes = 512;
constexpr std::size_t kJvmDeployClassBytesMaxBytes = kJvmStorageValueMaxBytes;

using JvmClassHash = std::array<std::uint8_t, kJvmClassHashBytes>;

// 32-byte commitment that binds a JVAC state cell to its wc=3 account
// address.  `address_commit = sha256(deployer || salt ||
// init_args_cell.hash)`; the account address is
// `sha256("TOS-JVM-CONTRACT-v2" || address_commit || class_hash)`.
// Stored inside JVAC so the engine can verify on every `run_compute`
// that the decoded state actually corresponds to the account address
// it was loaded from.
using JvmAddressCommit = std::array<std::uint8_t, kJvmAddressCommitBytes>;

struct JvmDeployDescriptor {
    std::uint8_t schema_version{kJvmDeployDescriptorSchemaVersion};
    JvmContractId deployer{};
    JvmContractId salt{};
    JvmClassHash class_hash{};
    std::string class_name;
    JvmStorageValue class_bytes;
    td::Ref<vm::Cell> init_args;
};

JvmClassHash compute_jvm_class_hash(const JvmStorageValue& class_bytes);

// `address_commit = sha256(deployer || salt || init_args_cell.hash)`.
// Captures everything about a deploy that does not become part of
// `class_hash`, in a single bits256 word.  The engine stores this inside
// JVAC and verifies on every run.
JvmAddressCommit compute_jvm_address_commit(
    const JvmContractId& deployer, const JvmContractId& salt,
    td::Ref<vm::Cell> init_args);

// Type-tagged 32-byte hash of a `manifest_root` cell ref (zero if null).
// Used in the engine's address-binding gate.  Manifest is immutable
// post-deploy, so the hash binds to the address forever.
using JvmManifestRootHash = std::array<std::uint8_t, 32>;
JvmManifestRootHash compute_jvm_manifest_root_hash(
    td::Ref<vm::Cell> manifest_root);

// Deterministic per-contract wc=3 account address.  Five-input formula
// keeps the address-binding gate cheap to verify on every `run_compute`:
//
//   address_commit     = sha256(deployer || salt || init_args_cell.hash)
//   manifest_root_hash = sha256-cell-hash(manifest_root) or zero if null
//   addr               = sha256("TOS-JVM-CONTRACT-v2"
//                               || deployer
//                               || address_commit
//                               || class_hash
//                               || manifest_root_hash)
//
// `deployer` joins the four other commitments so the engine can
// authenticate the source of the first-activation message
// (`msg.src.addr == state.deployer`) without having to break
// `address_commit`.  Without this binding an attacker who saw a
// victim's pending deploy could copy the StateInit and run their own
// first-call body on the same address (round-14 front-run finding).
//
// `manifest_root_hash` and `class_hash` are immutable per-account
// commitments; redirecting method_id → method dispatch or swapping
// the bytecode under the same address would change the resulting
// address.
//
// Initial `storage_root` is constrained separately: at first activation
// (`WorkchainComputeInput::msg_state_used == true`) the engine rejects
// any non-empty `state.storage_root` AND requires the inbound message
// source to equal `state.deployer` (the round-14 front-run gate).
//
// The output is the 256-bit `tos::StdSmcAddress` part of the StdAddress
// `{workchain=3, addr=...}`.  Because TOS workchain addresses are flat with
// no reserved bits (`tos/tos-types.h:36-46`), the full sha256 output goes
// straight into the address space.
// `manifest_root` MUST be the manifest cell the deployer commits to;
// pass an explicit `td::Ref<vm::Cell>{}` (null) only if the caller has
// validated that the deployed JVAC's manifest_root is also null
// (manifest_root_hash == zero in that case).  No default — making
// callers thread this parameter explicitly is what prevents the
// "default-empty manifest mismatches non-null encoded empty manifest"
// integration bug.
td::Result<JvmContractId> derive_jvm_contract_address(
    const JvmDeployDescriptor& descriptor,
    td::Ref<vm::Cell> manifest_root);

// Reconstruct the same address from a parsed JVAC state, for the
// engine-side address-binding check at `run_compute` time.  Equivalent
// to `derive_jvm_contract_address(descriptor, manifest_root)` whenever
// the JVAC's `(deployer, address_commit, class_hash, manifest_root_hash)`
// match the descriptor's inputs.
JvmContractId derive_jvm_contract_address_from_state(
    const JvmContractId& deployer,
    const JvmAddressCommit& address_commit, const JvmClassHash& class_hash,
    const JvmManifestRootHash& manifest_root_hash);

td::Ref<vm::Cell> encode_jvm_deploy_descriptor(
    const JvmDeployDescriptor& descriptor);

td::Result<JvmDeployDescriptor> parse_jvm_deploy_descriptor(
    td::Ref<vm::CellSlice> body);

td::Result<JvmDeployDescriptor> parse_jvm_deploy_descriptor(vm::CellSlice body);

}  // namespace jvm_workchain
