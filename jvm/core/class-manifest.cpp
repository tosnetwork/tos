/*
    JVM Workchain — per-account method manifest codec implementation.
*/
#include "jvm/core/class-manifest.h"

#include <algorithm>
#include <utility>

#include "jvm/core/storage-cell-host.h"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

namespace jvm_workchain {

namespace {

// Reject any byte sequence that is not well-formed UTF-8.  Manifest
// strings are spliced into JSON RPC responses (className / methodName /
// methodSpec) and the JSON spec requires UTF-8: a malformed sequence
// would let an attacker emit a response that strict clients refuse to
// parse — i.e. an RPC-response DoS.  Rather than trying to escape
// malformed bytes downstream, we keep the manifest's wire shape strict
// and reject it at decode time so all consumers see well-formed text.
//
// Rules (RFC 3629):
//   * 0x00..0x7F                                          — 1 byte
//   * 0xC2..0xDF, then 0x80..0xBF                         — 2 bytes
//   * 0xE0,      then 0xA0..0xBF, then 0x80..0xBF         — 3 bytes
//   * 0xE1..0xEC, then 0x80..0xBF, then 0x80..0xBF        — 3 bytes
//   * 0xED,      then 0x80..0x9F, then 0x80..0xBF         — 3 bytes
//                (excludes UTF-16 surrogate halves U+D800..U+DFFF)
//   * 0xEE..0xEF, then 0x80..0xBF, then 0x80..0xBF        — 3 bytes
//   * 0xF0,      then 0x90..0xBF, then 0x80..0xBF, then 0x80..0xBF
//   * 0xF1..0xF3, then 0x80..0xBF (×3)                    — 4 bytes
//   * 0xF4,      then 0x80..0x8F, then 0x80..0xBF (×2)    — 4 bytes
// Anything else (including overlong forms, 0xC0/0xC1, 0xF5+, surrogates)
// is rejected.
bool is_well_formed_utf8(const std::string& value) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(value.data());
    const std::size_t n = value.size();
    std::size_t i = 0;
    while (i < n) {
        std::uint8_t b0 = p[i];
        if (b0 < 0x80u) {
            ++i;
            continue;
        }
        std::uint8_t lo = 0, hi = 0;  // valid range for the FIRST cont byte
        std::size_t extra = 0;
        if (b0 >= 0xC2u && b0 <= 0xDFu) {
            extra = 1; lo = 0x80u; hi = 0xBFu;
        } else if (b0 == 0xE0u) {
            extra = 2; lo = 0xA0u; hi = 0xBFu;
        } else if (b0 >= 0xE1u && b0 <= 0xECu) {
            extra = 2; lo = 0x80u; hi = 0xBFu;
        } else if (b0 == 0xEDu) {
            extra = 2; lo = 0x80u; hi = 0x9Fu;
        } else if (b0 >= 0xEEu && b0 <= 0xEFu) {
            extra = 2; lo = 0x80u; hi = 0xBFu;
        } else if (b0 == 0xF0u) {
            extra = 3; lo = 0x90u; hi = 0xBFu;
        } else if (b0 >= 0xF1u && b0 <= 0xF3u) {
            extra = 3; lo = 0x80u; hi = 0xBFu;
        } else if (b0 == 0xF4u) {
            extra = 3; lo = 0x80u; hi = 0x8Fu;
        } else {
            return false;  // 0x80..0xC1, 0xF5..0xFF: never a valid leader
        }
        if (i + extra >= n) {
            return false;  // truncated sequence
        }
        if (p[i + 1] < lo || p[i + 1] > hi) {
            return false;
        }
        for (std::size_t k = 2; k <= extra; ++k) {
            if (p[i + k] < 0x80u || p[i + k] > 0xBFu) {
                return false;
            }
        }
        i += extra + 1;
    }
    return true;
}

td::Status validate_method_manifest_string(const std::string& value,
                                            const char* field) {
    if (value.empty()) {
        return td::Status::Error(
            PSLICE() << "JVM method manifest " << field << " is empty");
    }
    if (value.size() > kJvmAvataManifestStringMaxBytes) {
        return td::Status::Error(
            PSLICE() << "JVM method manifest " << field << " exceeds size cap");
    }
    if (value.find('\0') != std::string::npos) {
        return td::Status::Error(
            PSLICE() << "JVM method manifest " << field << " contains NUL");
    }
    if (!is_well_formed_utf8(value)) {
        return td::Status::Error(
            PSLICE() << "JVM method manifest " << field
                     << " is not well-formed UTF-8");
    }
    return td::Status::OK();
}

td::Status validate_method_manifest_entry(
    const JvmMethodManifestEntry& entry) {
    TRY_STATUS(validate_method_manifest_string(entry.class_name, "class_name"));
    TRY_STATUS(
        validate_method_manifest_string(entry.method_name, "method_name"));
    TRY_STATUS(
        validate_method_manifest_string(entry.method_spec, "method_spec"));
    return td::Status::OK();
}

td::Status validate_method_manifest_entries(
    const std::vector<JvmMethodManifestEntry>& entries) {
    if (entries.size() > kJvmMethodManifestMaxEntries) {
        return td::Status::Error(
            "JVM method manifest exceeds maximum entry count");
    }
    for (std::size_t i = 0; i < entries.size(); ++i) {
        TRY_STATUS(validate_method_manifest_entry(entries[i]));
    }
    // Round 10: replaced the original O(n^2) nested-loop duplicate
    // scan with an O(n log n) sort + linear pass.  At
    // kJvmMethodManifestMaxEntries == 1024 the old loop did ~525k
    // comparisons per parse; this drops the manifest pre-gas walk
    // cost meaningfully and still rejects the same duplicate inputs.
    // We sort indices instead of entries to avoid copying the
    // potentially-large entry strings.
    std::vector<std::uint32_t> ids;
    ids.reserve(entries.size());
    for (const auto& e : entries) {
        ids.push_back(e.method_id);
    }
    std::sort(ids.begin(), ids.end());
    if (std::adjacent_find(ids.begin(), ids.end()) != ids.end()) {
        return td::Status::Error(
            "JVM method manifest has duplicate method_id");
    }
    return td::Status::OK();
}

td::Ref<vm::Cell> encode_string_cell(const std::string& value) {
    JvmStorageValue bytes(value.begin(), value.end());
    return encode_jvm_storage_value(bytes);
}

td::Result<std::string> decode_string_cell(td::Ref<vm::Cell> cell,
                                           const char* field_name) {
    // Round 75 MEDIUM fix: cap the decoded byte budget at the manifest
    // string limit BEFORE the storage walker copies the chunk chain
    // into the result vector.  Pre-fix, `decode_jvm_storage_value`
    // ran with the default 1 MiB cap, fully walked + copied the chain,
    // and only then `validate_method_manifest_string` rejected at 512
    // bytes — letting an external sender force ~1 MiB of validator
    // work per resolver lookup before dispatch billed admission floor.
    TRY_RESULT(bytes,
               decode_jvm_storage_value(std::move(cell),
                                        kJvmAvataManifestStringMaxBytes));
    std::string value(bytes.begin(), bytes.end());
    TRY_STATUS(validate_method_manifest_string(value, field_name));
    return value;
}

bool fetch_u8(vm::CellSlice& cs, std::uint8_t& out) {
    unsigned v = 0;
    if (!cs.fetch_uint_to(8, v)) {
        return false;
    }
    out = static_cast<std::uint8_t>(v);
    return true;
}

bool fetch_u16(vm::CellSlice& cs, std::uint16_t& out) {
    unsigned v = 0;
    if (!cs.fetch_uint_to(16, v)) {
        return false;
    }
    out = static_cast<std::uint16_t>(v);
    return true;
}

bool fetch_u32(vm::CellSlice& cs, std::uint32_t& out) {
    unsigned long long v = 0;
    if (!cs.fetch_ulong_bool(32, v)) {
        return false;
    }
    out = static_cast<std::uint32_t>(v);
    return true;
}

td::Result<JvmMethodManifestEntry> decode_method_manifest_node(
    td::Ref<vm::Cell> node,
    td::Ref<vm::Cell>& next) {
    next = {};
    if (node.is_null()) {
        return td::Status::Error("JVM method manifest node is null");
    }

    bool special = false;
    auto cs = vm::load_cell_slice_special(node, special);
    if (special) {
        return td::Status::Error("JVM method manifest node is special");
    }

    JvmMethodManifestEntry entry;
    unsigned has_next = 0;
    if (!fetch_u32(cs, entry.method_id) || !cs.fetch_uint_to(1, has_next) ||
        has_next > 1) {
        return td::Status::Error("JVM method manifest node is truncated");
    }
    const unsigned expected_refs = 3 + has_next;
    if (cs.size() != 0 || cs.size_refs() != expected_refs) {
        return td::Status::Error(
            "JVM method manifest node has malformed refs");
    }
    if (has_next != 0) {
        next = cs.fetch_ref();
    }
    auto class_name = cs.fetch_ref();
    auto method_name = cs.fetch_ref();
    auto method_spec = cs.fetch_ref();
    if (!cs.empty_ext()) {
        return td::Status::Error(
            "JVM method manifest node has trailing data");
    }

    TRY_RESULT(decoded_class_name,
               decode_string_cell(std::move(class_name), "class_name"));
    TRY_RESULT(decoded_method_name,
               decode_string_cell(std::move(method_name), "method_name"));
    TRY_RESULT(decoded_method_spec,
               decode_string_cell(std::move(method_spec), "method_spec"));
    entry.class_name = std::move(decoded_class_name);
    entry.method_name = std::move(decoded_method_name);
    entry.method_spec = std::move(decoded_method_spec);
    TRY_STATUS(validate_method_manifest_entry(entry));
    return entry;
}

}  // namespace

td::Ref<vm::Cell> encode_jvm_method_manifest(
    const std::vector<JvmMethodManifestEntry>& entries) {
    if (validate_method_manifest_entries(entries).is_error()) {
        return {};
    }

    // Round 119 MEDIUM fix: wrap encoding in try/catch.  The
    // manifest is built as a linked spine: each entry node refs
    // the next, so chain depth = entries.size().  At
    // kJvmMethodManifestMaxEntries = 1024, root depth is 1025 —
    // above vm::CellTraits::max_depth = 1024 — and
    // CellBuilder::finalize() throws CellWriteError.  Pre-fix
    // jvm_deployContract called this directly and the public RPC
    // dispatch did not catch the exception, making the deploy
    // RPC a DoS vector.  Catch + return null so the caller
    // surfaces a clean error.
    try {
    td::Ref<vm::Cell> next;
    for (std::size_t i = entries.size(); i-- > 0;) {
        auto class_name = encode_string_cell(entries[i].class_name);
        auto method_name = encode_string_cell(entries[i].method_name);
        auto method_spec = encode_string_cell(entries[i].method_spec);
        if (class_name.is_null() || method_name.is_null() ||
            method_spec.is_null()) {
            return {};
        }
        vm::CellBuilder node;
        if (!node.store_ulong_rchk_bool(entries[i].method_id, 32) ||
            !node.store_ulong_rchk_bool(next.not_null() ? 1 : 0, 1)) {
            return {};
        }
        if (next.not_null() && !node.store_ref_bool(std::move(next))) {
            return {};
        }
        if (!node.store_ref_bool(std::move(class_name)) ||
            !node.store_ref_bool(std::move(method_name)) ||
            !node.store_ref_bool(std::move(method_spec))) {
            return {};
        }
        next = node.finalize();
        if (next.is_null()) {
            return {};
        }
    }

    vm::CellBuilder root;
    if (!root.store_ulong_rchk_bool(kJvmMethodManifestMagic, 32) ||
        !root.store_ulong_rchk_bool(kJvmMethodManifestSchemaVersion, 8) ||
        !root.store_ulong_rchk_bool(entries.size(), 16)) {
        return {};
    }
    if (next.not_null() && !root.store_ref_bool(std::move(next))) {
        return {};
    }
    return root.finalize();
    } catch (vm::VmError&) {
        return {};
    } catch (vm::VmVirtError&) {
        return {};
    } catch (...) {
        return {};
    }
}

td::Result<std::uint16_t> peek_jvm_method_manifest_count(
    td::Ref<vm::Cell> root) {
    if (root.is_null()) {
        return td::Status::Error("JVM method manifest root is null");
    }
    bool special = false;
    auto cs = vm::load_cell_slice_special(root, special);
    if (special) {
        return td::Status::Error("JVM method manifest root is special");
    }
    std::uint32_t magic = 0;
    if (!fetch_u32(cs, magic) || magic != kJvmMethodManifestMagic) {
        return td::Status::Error("JVM method manifest root has wrong magic");
    }
    std::uint8_t schema_version = 0;
    if (!fetch_u8(cs, schema_version) ||
        schema_version != kJvmMethodManifestSchemaVersion) {
        return td::Status::Error(
            "JVM method manifest root has unsupported schema");
    }
    std::uint16_t count = 0;
    if (!fetch_u16(cs, count)) {
        return td::Status::Error("JVM method manifest root is truncated");
    }
    if (count > kJvmMethodManifestMaxEntries) {
        return td::Status::Error(
            "JVM method manifest root has too many entries");
    }
    return count;
}

td::Result<std::vector<JvmMethodManifestEntry>> parse_jvm_method_manifest(
    td::Ref<vm::Cell> root) {
    if (root.is_null()) {
        return td::Status::Error("JVM method manifest root is null");
    }
    bool special = false;
    auto cs = vm::load_cell_slice_special(root, special);
    if (special) {
        return td::Status::Error("JVM method manifest root is special");
    }

    std::uint32_t magic = 0;
    if (!fetch_u32(cs, magic) || magic != kJvmMethodManifestMagic) {
        return td::Status::Error("JVM method manifest root has wrong magic");
    }
    std::uint8_t schema_version = 0;
    if (!fetch_u8(cs, schema_version) ||
        schema_version != kJvmMethodManifestSchemaVersion) {
        return td::Status::Error(
            "JVM method manifest root has unsupported schema");
    }
    std::uint16_t count = 0;
    if (!fetch_u16(cs, count)) {
        return td::Status::Error("JVM method manifest root is truncated");
    }
    if (count > kJvmMethodManifestMaxEntries) {
        return td::Status::Error(
            "JVM method manifest root has too many entries");
    }

    const unsigned expected_refs = (count == 0) ? 0u : 1u;
    if (cs.size() != 0 || cs.size_refs() != expected_refs) {
        return td::Status::Error(
            "JVM method manifest root has malformed refs");
    }

    std::vector<JvmMethodManifestEntry> entries;
    if (count == 0) {
        return entries;
    }
    auto next_ref = cs.fetch_ref();
    if (!cs.empty_ext()) {
        return td::Status::Error(
            "JVM method manifest root has trailing data");
    }
    entries.reserve(count);
    for (std::uint16_t i = 0; i < count; ++i) {
        if (next_ref.is_null()) {
            return td::Status::Error(
                "JVM method manifest chain ended early");
        }
        td::Ref<vm::Cell> next_chain;
        TRY_RESULT(decoded,
                   decode_method_manifest_node(std::move(next_ref), next_chain));
        entries.push_back(std::move(decoded));
        next_ref = std::move(next_chain);
    }
    if (next_ref.not_null()) {
        return td::Status::Error("JVM method manifest chain has trailing node");
    }
    TRY_STATUS(validate_method_manifest_entries(entries));
    return entries;
}

td::Result<JvmMethodManifestEntry> find_jvm_method_manifest_entry(
    td::Ref<vm::Cell> root,
    std::uint32_t method_id) {
    // Round 114 MEDIUM fix: streaming lookup.  Pre-fix, this called
    // parse_jvm_method_manifest which decodes EVERY entry's three
    // capped 512-byte strings (class_name / method_name /
    // method_spec) before searching.  At max 1024 entries that's
    // ~1.5 MiB of validator-CPU work, paid only at the admission
    // floor when the dispatch resolver-order mirror (round 79) ran
    // BEFORE arg-byte billing.  An attacker could repeatedly trigger
    // unknown-method_id calls and force the full manifest decode
    // every time.  Walk the chain decoding only the method_id of
    // each entry; decode the matching entry's strings only when
    // found.  Manifest validation (count cap, dedup) was performed
    // at deploy time via parse_jvm_method_manifest in the install
    // path, so trusting the persisted manifest layout here is
    // safe.
    if (root.is_null()) {
        return td::Status::Error("JVM method manifest root is null");
    }
    bool special = false;
    auto cs = vm::load_cell_slice_special(root, special);
    if (special) {
        return td::Status::Error("JVM method manifest root is special");
    }
    std::uint32_t magic = 0;
    if (!fetch_u32(cs, magic) || magic != kJvmMethodManifestMagic) {
        return td::Status::Error("JVM method manifest root has wrong magic");
    }
    std::uint8_t schema_version = 0;
    if (!fetch_u8(cs, schema_version) ||
        schema_version != kJvmMethodManifestSchemaVersion) {
        return td::Status::Error(
            "JVM method manifest root has unsupported schema");
    }
    std::uint16_t count = 0;
    if (!fetch_u16(cs, count)) {
        return td::Status::Error("JVM method manifest root is truncated");
    }
    if (count > kJvmMethodManifestMaxEntries) {
        return td::Status::Error(
            "JVM method manifest root has too many entries");
    }
    const unsigned expected_refs = (count == 0) ? 0u : 1u;
    if (cs.size() != 0 || cs.size_refs() != expected_refs) {
        return td::Status::Error(
            "JVM method manifest root has malformed refs");
    }
    if (count == 0) {
        return td::Status::Error("JVM method manifest has no matching entry");
    }
    auto next_ref = cs.fetch_ref();
    if (!cs.empty_ext()) {
        return td::Status::Error(
            "JVM method manifest root has trailing data");
    }

    for (std::uint16_t i = 0; i < count; ++i) {
        if (next_ref.is_null()) {
            return td::Status::Error(
                "JVM method manifest chain ended early");
        }
        bool node_special = false;
        auto node_cs = vm::load_cell_slice_special(next_ref, node_special);
        if (node_special) {
            return td::Status::Error("JVM method manifest node is special");
        }
        std::uint32_t entry_method_id = 0;
        unsigned has_next = 0;
        if (!fetch_u32(node_cs, entry_method_id) ||
            !node_cs.fetch_uint_to(1, has_next) || has_next > 1) {
            return td::Status::Error(
                "JVM method manifest node is truncated");
        }
        const unsigned node_expected_refs = 3 + has_next;
        if (node_cs.size() != 0 || node_cs.size_refs() != node_expected_refs) {
            return td::Status::Error(
                "JVM method manifest node has malformed refs");
        }
        if (entry_method_id == method_id) {
            // Decode this entry's strings only.
            td::Ref<vm::Cell> unused_next;
            return decode_method_manifest_node(std::move(next_ref),
                                                unused_next);
        }
        // Skip to the next entry without decoding strings.
        td::Ref<vm::Cell> next_chain;
        if (has_next != 0) {
            next_chain = node_cs.fetch_ref();
        }
        next_ref = std::move(next_chain);
    }
    return td::Status::Error("JVM method manifest has no matching entry");
}

}  // namespace jvm_workchain
