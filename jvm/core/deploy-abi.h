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

// Deterministic per-contract wc=3 account address.  Two-step formula
// keeps the address-binding gate cheap to verify on every `run_compute`
// (the engine only needs `state.address_commit` and `state.class_hash`,
// not the original deploy descriptor):
//
//   address_commit = sha256(deployer || salt || init_args_cell.hash)
//   addr           = sha256("TOS-JVM-CONTRACT-v2"
//                           || address_commit
//                           || class_hash)
//
// The output is the 256-bit `tos::StdSmcAddress` part of the StdAddress
// `{workchain=3, addr=...}`.  Because TOS workchain addresses are flat with
// no reserved bits (`tos/tos-types.h:36-46`), the full sha256 output goes
// straight into the address space.
td::Result<JvmContractId> derive_jvm_contract_address(
    const JvmDeployDescriptor& descriptor);

// Reconstruct the same address from a parsed JVAC state, for the
// engine-side address-binding check at `run_compute` time.  Equivalent
// to `derive_jvm_contract_address(descriptor)` whenever
// `address_commit == compute_jvm_address_commit(deployer, salt,
// init_args)` and `class_hash == compute_jvm_class_hash(class_bytes)`.
JvmContractId derive_jvm_contract_address_from_state(
    const JvmAddressCommit& address_commit, const JvmClassHash& class_hash);

td::Ref<vm::Cell> encode_jvm_deploy_descriptor(
    const JvmDeployDescriptor& descriptor);

td::Result<JvmDeployDescriptor> parse_jvm_deploy_descriptor(
    td::Ref<vm::CellSlice> body);

td::Result<JvmDeployDescriptor> parse_jvm_deploy_descriptor(vm::CellSlice body);

}  // namespace jvm_workchain
