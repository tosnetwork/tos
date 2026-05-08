/*
    JVM Workchain — per-account method manifest codec implementation.
*/
#include "jvm/core/class-manifest.h"

#include <utility>

#include "jvm/core/storage-cell-host.h"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

namespace jvm_workchain {

namespace {

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
        for (std::size_t j = 0; j < i; ++j) {
            if (entries[i].method_id == entries[j].method_id) {
                return td::Status::Error(
                    "JVM method manifest has duplicate method_id");
            }
        }
    }
    return td::Status::OK();
}

td::Ref<vm::Cell> encode_string_cell(const std::string& value) {
    JvmStorageValue bytes(value.begin(), value.end());
    return encode_jvm_storage_value(bytes);
}

td::Result<std::string> decode_string_cell(td::Ref<vm::Cell> cell,
                                           const char* field_name) {
    TRY_RESULT(bytes, decode_jvm_storage_value(std::move(cell)));
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
    TRY_RESULT(entries, parse_jvm_method_manifest(std::move(root)));
    for (const auto& entry : entries) {
        if (entry.method_id == method_id) {
            return entry;
        }
    }
    return td::Status::Error("JVM method manifest has no matching entry");
}

}  // namespace jvm_workchain
