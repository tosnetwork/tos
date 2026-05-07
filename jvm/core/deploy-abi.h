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
constexpr std::size_t kJvmDeployClassNameMaxBytes = 512;
constexpr std::size_t kJvmDeployClassBytesMaxBytes = kJvmStorageValueMaxBytes;

using JvmClassHash = std::array<std::uint8_t, kJvmClassHashBytes>;

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

// Deterministic v1 contract id:
// sha256("TOS-JVM-CONTRACT-v1" || deployer || class_hash || salt ||
//        init_args_cell_hash)
td::Result<JvmContractId> derive_jvm_contract_id(
    const JvmDeployDescriptor& descriptor);

td::Ref<vm::Cell> encode_jvm_deploy_descriptor(
    const JvmDeployDescriptor& descriptor);

td::Result<JvmDeployDescriptor> parse_jvm_deploy_descriptor(
    td::Ref<vm::CellSlice> body);

td::Result<JvmDeployDescriptor> parse_jvm_deploy_descriptor(vm::CellSlice body);

}  // namespace jvm_workchain
