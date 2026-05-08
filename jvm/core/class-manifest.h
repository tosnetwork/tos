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

#include "jvm/core/deploy-abi.h"
#include "jvm/core/message-abi.h"
#include "td/utils/Status.h"
#include "vm/cells.h"

namespace jvm_workchain {

struct JvmConfig;

constexpr std::uint32_t kJvmAvataClassManifestMagic = 0x4a564d4d;  // "JVMM"
constexpr std::uint8_t kJvmAvataClassManifestSchemaVersion = 1;
constexpr std::size_t kJvmAvataManifestMaxEntries = 1024;
constexpr std::size_t kJvmAvataManifestStringMaxBytes = 512;
constexpr std::uint32_t kJvmAvataClassStateMagic = 0x4a564d43;  // "JVMC"
constexpr std::uint8_t kJvmAvataClassStateSchemaVersion = 1;
constexpr std::size_t kJvmAvataClassStateMaxClasses = 1024;

struct JvmAvataClassManifestEntry {
    JvmContractId contract_id{};
    std::uint32_t method_id{0};
    std::string class_name;
    std::string method_name;
    std::string method_spec;
};

struct JvmAvataClassDefinition {
    JvmClassHash class_hash{};
    std::string class_name;
    JvmStorageValue class_bytes;
};

struct JvmAvataClassState {
    std::vector<JvmAvataClassManifestEntry> manifest_entries;
    std::vector<JvmAvataClassDefinition> classes;
};

td::Ref<vm::Cell> encode_jvm_avata_class_manifest(
    const std::vector<JvmAvataClassManifestEntry>& entries);

td::Result<std::vector<JvmAvataClassManifestEntry>>
parse_jvm_avata_class_manifest(td::Ref<vm::Cell> root);

td::Result<JvmAvataClassManifestEntry> find_jvm_avata_class_manifest_entry(
    td::Ref<vm::Cell> root,
    const JvmCallDescriptor& call);

td::Ref<vm::Cell> encode_jvm_avata_class_state(
    const JvmAvataClassState& state);

// Accepts both the legacy manifest-only JVMM root and the JVMC class-state
// envelope.  A manifest-only root decodes as a state with no class byte table.
td::Result<JvmAvataClassState> parse_jvm_avata_class_state(
    td::Ref<vm::Cell> root);

td::Result<JvmAvataClassDefinition> find_jvm_avata_class_definition(
    td::Ref<vm::Cell> root,
    const std::string& class_name);

struct JvmDeployInstallResult {
    JvmContractId contract_id{};
    td::Ref<vm::Cell> class_state_root;
};

struct JvmClassStoreLimits {
    std::uint32_t max_class_bytes{0};
    std::uint32_t max_total_class_bytes{0};
};

// Install the class bytes carried by a deploy descriptor into class_state_root.
// The method manifest is intentionally unchanged here; admission/ABI tooling is
// responsible for declaring callable method ids after class verification.
td::Result<JvmDeployInstallResult> install_jvm_deploy_descriptor(
    td::Ref<vm::Cell> previous_class_state_root,
    const JvmDeployDescriptor& descriptor);

td::Result<JvmDeployInstallResult> install_jvm_deploy_descriptor(
    td::Ref<vm::Cell> previous_class_state_root,
    const JvmDeployDescriptor& descriptor,
    const JvmClassStoreLimits& limits);

td::Result<JvmDeployInstallResult> install_jvm_deploy_descriptor(
    td::Ref<vm::Cell> previous_class_state_root,
    const JvmDeployDescriptor& descriptor,
    const JvmConfig& config);

// -------------------------------------------------------------------------
// JVM v2: per-account method manifest.
//
// Under the v2 account-native topology the destination address already names
// the contract, so the manifest entry no longer carries `contract_id`. One
// account holds one class, and the manifest is the list of @ContractEntry
// methods on that class indexed by method_id.
// -------------------------------------------------------------------------

constexpr std::uint32_t kJvmMethodManifestMagic = 0x4a564d32;  // "JVM2"
constexpr std::uint8_t kJvmMethodManifestSchemaVersion = 1;
constexpr std::size_t kJvmMethodManifestMaxEntries = 1024;

struct JvmMethodManifestEntry {
    std::uint32_t method_id{0};
    std::string class_name;
    std::string method_name;
    std::string method_spec;
};

// Layout (linked-list spine, mirrors the v1 manifest encoding so that audit
// tooling can reuse the same string-cell helpers):
//   jvm_method_manifest#4a564d32
//     schema_version:uint8 (=1)
//     count:uint16
//     entries:^(JvmMethodManifestEntryNode chain)?
//   jvm_method_manifest_entry
//     method_id:uint32
//     has_next:bit
//     next:^(JvmMethodManifestEntryNode)?
//     class_name:^StringCell
//     method_name:^StringCell
//     method_spec:^StringCell
td::Ref<vm::Cell> encode_jvm_method_manifest(
    const std::vector<JvmMethodManifestEntry>& entries);

td::Result<std::vector<JvmMethodManifestEntry>> parse_jvm_method_manifest(
    td::Ref<vm::Cell> root);

td::Result<JvmMethodManifestEntry> find_jvm_method_manifest_entry(
    td::Ref<vm::Cell> root,
    std::uint32_t method_id);

}  // namespace jvm_workchain
