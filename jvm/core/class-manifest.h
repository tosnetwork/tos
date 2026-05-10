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

// Strict upper bound on parse_jvm_method_manifest's cost per
// declared entry.  Per-entry work touches each of the three
// kJvmAvataManifestStringMaxBytes-capped (=512) strings up to
// FOUR times:
//   (1) decode_jvm_storage_value chunk walk + memcpy
//   (2) validate_method_manifest_string inside decode_string_cell
//   (3) validate_method_manifest_entry inside decode_method_
//       manifest_node
//   (4) validate_method_manifest_entries' second pass at the end
// of parse_jvm_method_manifest, which calls validate_method_
// manifest_entry again for every entry plus an O(n log n) sort
// over the method_id list.  3 * 512 * 4 = 6144 bytes; the
// constant is rounded up to a power of two to give a comfortable
// margin for per-cell decode overhead and sort cost.
//
// Round 124 MEDIUM fix: round 123 used 3 * 512 + 64 = 1600
// which only covered (1).  That underestimated actual parse work
// by ~4x, so a 1024-entry manifest combined with an unknown-
// method call (or a malformed manifest that fails at the final
// validate_method_manifest_entries pass) under-billed validator
// CPU by the same ratio.
constexpr std::uint64_t kJvmManifestParseBytesPerEntry = 8192u;

td::Result<JvmMethodManifestEntry> find_jvm_method_manifest_entry(
    td::Ref<vm::Cell> root,
    std::uint32_t method_id);

}  // namespace jvm_workchain
