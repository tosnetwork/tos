/*
    JVM Workchain — per-account method manifest codec.

    Under the account-native topology each contract is its own wc=3 account,
    so the manifest is per-account (one class per account) and indexed by
    `method_id` only.  Each entry maps an inbound `method_id` to the Avata
    class name + static method descriptor that the linked runtime resolves
    before execution.
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

constexpr std::size_t kJvmAvataManifestStringMaxBytes = 512;

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

// Round 123 MEDIUM fix: cheap count peek used to pre-bound the
// validator-CPU/gas asymmetry that round 122 only partially
// closed.  Reads ONLY the manifest root header (magic, schema,
// count) without walking the chain or decoding any entry strings.
// Lets dispatch reject manifests whose declared size exceeds the
// caller's affordable gas before paying the ~1.5 KiB-per-entry
// string-decode cost.
td::Result<std::uint16_t> peek_jvm_method_manifest_count(
    td::Ref<vm::Cell> root);

// Conservative upper bound on parse_jvm_method_manifest's cost
// per declared entry.  Each entry decodes 3 strings up to
// kJvmAvataManifestStringMaxBytes bytes (= 512) plus a small
// envelope; the +64 covers the per-entry header, four refs, and
// the per-cell decode/copy overhead.  Used as a conservative gas
// proxy in dispatch's first-activation manifest gate.
constexpr std::uint64_t kJvmManifestParseBytesPerEntry =
    3u * kJvmAvataManifestStringMaxBytes + 64u;

td::Result<JvmMethodManifestEntry> find_jvm_method_manifest_entry(
    td::Ref<vm::Cell> root,
    std::uint32_t method_id);

}  // namespace jvm_workchain
