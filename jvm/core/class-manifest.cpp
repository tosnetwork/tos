/*
    JVM Workchain — contract class manifest codec implementation.
*/
#include "jvm/core/class-manifest.h"

#include <algorithm>

#include "jvm/core/storage-cell-host.h"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

namespace jvm_workchain {

namespace {

bool is_zero_contract_id(const JvmContractId& contract_id) {
    return std::all_of(contract_id.begin(), contract_id.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

bool same_manifest_key(const JvmAvataClassManifestEntry& left,
                       const JvmAvataClassManifestEntry& right) {
    return left.contract_id == right.contract_id &&
           left.method_id == right.method_id;
}

td::Status validate_manifest_string(const std::string& value,
                                    const char* field_name) {
    if (value.empty()) {
        return td::Status::Error(PSTRING() << "JVM manifest " << field_name
                                           << " is empty");
    }
    if (value.size() > kJvmAvataManifestStringMaxBytes) {
        return td::Status::Error(PSTRING() << "JVM manifest " << field_name
                                           << " is too long");
    }
    if (value.find('\0') != std::string::npos) {
        return td::Status::Error(PSTRING() << "JVM manifest " << field_name
                                           << " contains NUL");
    }
    return td::Status::OK();
}

td::Status validate_manifest_entry(
    const JvmAvataClassManifestEntry& entry) {
    if (is_zero_contract_id(entry.contract_id)) {
        return td::Status::Error("JVM manifest entry has zero contract id");
    }
    TRY_STATUS(validate_manifest_string(entry.class_name, "class_name"));
    TRY_STATUS(validate_manifest_string(entry.method_name, "method_name"));
    TRY_STATUS(validate_manifest_string(entry.method_spec, "method_spec"));
    return td::Status::OK();
}

td::Status validate_manifest_entries(
    const std::vector<JvmAvataClassManifestEntry>& entries) {
    if (entries.size() > kJvmAvataManifestMaxEntries) {
        return td::Status::Error("JVM manifest has too many entries");
    }
    for (std::size_t i = 0; i < entries.size(); ++i) {
        TRY_STATUS(validate_manifest_entry(entries[i]));
        for (std::size_t j = 0; j < i; ++j) {
            if (same_manifest_key(entries[i], entries[j])) {
                return td::Status::Error(
                    "JVM manifest has duplicate contract method id");
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
    TRY_STATUS(validate_manifest_string(value, field_name));
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

td::Result<JvmAvataClassManifestEntry> decode_manifest_node(
    td::Ref<vm::Cell> node,
    td::Ref<vm::Cell>& next) {
    next = {};
    if (node.is_null()) {
        return td::Status::Error("JVM manifest node is null");
    }

    bool special = false;
    auto cs = vm::load_cell_slice_special(node, special);
    if (special) {
        return td::Status::Error("JVM manifest node is special");
    }

    JvmAvataClassManifestEntry entry;
    unsigned has_next = 0;
    if (!cs.fetch_bytes(entry.contract_id.data(),
                        static_cast<unsigned>(entry.contract_id.size())) ||
        !fetch_u32(cs, entry.method_id) ||
        !cs.fetch_uint_to(1, has_next) ||
        has_next > 1) {
        return td::Status::Error("JVM manifest node is truncated");
    }

    const unsigned expected_refs = 3 + has_next;
    if (cs.size() != 0 || cs.size_refs() != expected_refs) {
        return td::Status::Error("JVM manifest node has malformed refs");
    }
    if (has_next != 0) {
        next = cs.fetch_ref();
    }
    auto class_name = cs.fetch_ref();
    auto method_name = cs.fetch_ref();
    auto method_spec = cs.fetch_ref();
    if (!cs.empty_ext()) {
        return td::Status::Error("JVM manifest node has trailing data");
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
    TRY_STATUS(validate_manifest_entry(entry));
    return entry;
}

}  // namespace

td::Ref<vm::Cell> encode_jvm_avata_class_manifest(
    const std::vector<JvmAvataClassManifestEntry>& entries) {
    if (validate_manifest_entries(entries).is_error()) {
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
        if (!node.store_bytes_bool(
                entries[i].contract_id.data(),
                static_cast<unsigned>(entries[i].contract_id.size())) ||
            !node.store_ulong_rchk_bool(entries[i].method_id, 32) ||
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
    if (!root.store_ulong_rchk_bool(kJvmAvataClassManifestMagic, 32) ||
        !root.store_ulong_rchk_bool(kJvmAvataClassManifestSchemaVersion, 8) ||
        !root.store_ulong_rchk_bool(entries.size(), 16)) {
        return {};
    }
    if (next.not_null() && !root.store_ref_bool(std::move(next))) {
        return {};
    }
    return root.finalize();
}

td::Result<std::vector<JvmAvataClassManifestEntry>>
parse_jvm_avata_class_manifest(td::Ref<vm::Cell> root) {
    std::vector<JvmAvataClassManifestEntry> entries;
    if (root.is_null()) {
        return td::Status::Error("JVM class manifest root is null");
    }

    try {
        bool special = false;
        auto cs = vm::load_cell_slice_special(root, special);
        if (special) {
            return td::Status::Error("JVM class manifest root is special");
        }

        std::uint32_t magic = 0;
        std::uint8_t schema = 0;
        std::uint16_t count = 0;
        if (!fetch_u32(cs, magic) ||
            magic != kJvmAvataClassManifestMagic ||
            !fetch_u8(cs, schema) ||
            schema != kJvmAvataClassManifestSchemaVersion ||
            !fetch_u16(cs, count)) {
            return td::Status::Error("JVM class manifest root is malformed");
        }
        if (count > kJvmAvataManifestMaxEntries) {
            return td::Status::Error("JVM class manifest has too many entries");
        }
        if (count == 0) {
            if (!cs.empty_ext()) {
                return td::Status::Error(
                    "JVM class manifest empty root has trailing data");
            }
            return entries;
        }
        if (cs.size() != 0 || cs.size_refs() != 1) {
            return td::Status::Error(
                "JVM class manifest root must carry one entry-list ref");
        }

        auto node = cs.fetch_ref();
        entries.reserve(count);
        for (std::uint16_t i = 0; i < count; ++i) {
            td::Ref<vm::Cell> next;
            TRY_RESULT(entry, decode_manifest_node(std::move(node), next));
            for (const auto& existing : entries) {
                if (same_manifest_key(entry, existing)) {
                    return td::Status::Error(
                        "JVM class manifest has duplicate contract method id");
                }
            }
            entries.push_back(std::move(entry));
            node = std::move(next);
        }
        if (node.not_null()) {
            return td::Status::Error(
                "JVM class manifest has trailing entry nodes");
        }
        return entries;
    } catch (vm::VmError&) {
        return td::Status::Error("JVM class manifest decode hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error(
            "JVM class manifest decode hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM class manifest decode failed");
    }
}

td::Result<JvmAvataClassManifestEntry> find_jvm_avata_class_manifest_entry(
    td::Ref<vm::Cell> root,
    const JvmCallDescriptor& call) {
    TRY_RESULT(entries, parse_jvm_avata_class_manifest(std::move(root)));
    for (const auto& entry : entries) {
        if (entry.contract_id == call.contract_id &&
            entry.method_id == call.method_id) {
            return entry;
        }
    }
    return td::Status::Error("JVM class manifest has no matching entry");
}

}  // namespace jvm_workchain
