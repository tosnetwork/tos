/*
    JVM Workchain — contract class manifest codec.

    The v1 executor state keeps persistent storage separate from deploy/class
    metadata. This manifest is the first deterministic class_state_root shape:
    it maps an inbound (contract_id, method_id) pair to the Avata class and
    static method descriptor that the linked runtime resolves before execution.
*/
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "jvm/core/message-abi.h"
#include "td/utils/Status.h"
#include "vm/cells.h"

namespace jvm_workchain {

constexpr std::uint32_t kJvmAvataClassManifestMagic = 0x4a564d4d;  // "JVMM"
constexpr std::uint8_t kJvmAvataClassManifestSchemaVersion = 1;
constexpr std::size_t kJvmAvataManifestMaxEntries = 1024;
constexpr std::size_t kJvmAvataManifestStringMaxBytes = 512;

struct JvmAvataClassManifestEntry {
    JvmContractId contract_id{};
    std::uint32_t method_id{0};
    std::string class_name;
    std::string method_name;
    std::string method_spec;
};

td::Ref<vm::Cell> encode_jvm_avata_class_manifest(
    const std::vector<JvmAvataClassManifestEntry>& entries);

td::Result<std::vector<JvmAvataClassManifestEntry>>
parse_jvm_avata_class_manifest(td::Ref<vm::Cell> root);

td::Result<JvmAvataClassManifestEntry> find_jvm_avata_class_manifest_entry(
    td::Ref<vm::Cell> root,
    const JvmCallDescriptor& call);

}  // namespace jvm_workchain
