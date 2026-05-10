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
// declared entry.  Per-entry the parser touches each of the
// three kJvmAvataManifestStringMaxBytes-capped (=512) strings
// the following number of times:
//   (1) decode_jvm_storage_value chunk walk + memcpy →
//       512 bytes WRITE per string
//   (2) std::string copy at decode_string_cell:165 →
//       512 bytes WRITE per string
//   (3) validate_method_manifest_string inside
//       decode_string_cell (NUL scan + UTF-8 scan) →
//       1024 bytes READ per string
//   (4) validate_method_manifest_entry inside
//       decode_method_manifest_node calls validate_method_
//       manifest_string again → 1024 bytes READ per string
//   (5) validate_method_manifest_entries' final pass at the
//       end of parse_jvm_method_manifest calls validate_method_
//       manifest_entry once more → 1024 bytes READ per string
// Total per string = 4096 bytes; per entry (3 strings) = 12288
// bytes.  Plus an O(n log n) method_id sort and dedup linear
// pass at the end.  Rounded up to 16384 (2^14) so the gas proxy
// is a strict upper bound with margin for per-cell decode
// overhead and the sort/dedup epilogue.
//
// Round 125 MEDIUM fix: round 124 used 8192 which still only
// covered (1)+(2)+(3) (~6 KiB) and underestimated the two
// downstream re-validation passes that hit each string twice
// more.  At kJvmMethodManifestMaxEntries=1024 this is the
// difference between 8 MiB and 12 MiB of unbilled validator CPU.
constexpr std::uint64_t kJvmManifestParseBytesPerEntry = 16384u;

td::Result<JvmMethodManifestEntry> find_jvm_method_manifest_entry(
    td::Ref<vm::Cell> root,
    std::uint32_t method_id);

// Round 125 MEDIUM fix: streaming peek of the first entry's
// class_name only.  Used by the JSON-RPC `jvm_getContractState`
// human-readable display path, which previously called
// parse_jvm_method_manifest just to get this one field — turning
// any caller-supplied accountStateBoc into a public, gasless
// O(N * 4 KiB) decode/validate trigger.  This helper walks just
// the manifest root header + the first node and decodes only the
// class_name string ref, with the same string validation
// (decode_string_cell) but without sort/dedup/full chain walk.
// Returns an empty string when count == 0.
td::Result<std::string> peek_jvm_method_manifest_first_class_name(
    td::Ref<vm::Cell> root);

}  // namespace jvm_workchain
