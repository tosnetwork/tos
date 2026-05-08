/*
    JVM Workchain — contract class manifest codec implementation.
*/
#include "jvm/core/class-manifest.h"

#include <algorithm>
#include <limits>
#include <utility>

#include "jvm/core/config-param.h"
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

bool same_class_name(const JvmAvataClassDefinition& left,
                     const JvmAvataClassDefinition& right) {
    return left.class_name == right.class_name;
}

bool is_zero_class_hash(const JvmClassHash& class_hash) {
    return std::all_of(class_hash.begin(), class_hash.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

bool is_ascii_alpha(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool is_ascii_digit(char c) {
    return c >= '0' && c <= '9';
}

bool is_java_identifier_start(char c) {
    return is_ascii_alpha(c) || c == '_' || c == '$';
}

bool is_java_identifier_part(char c) {
    return is_java_identifier_start(c) || is_ascii_digit(c);
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

td::Status validate_manifest_class_name(const std::string& value) {
    TRY_STATUS(validate_manifest_string(value, "class_name"));
    bool at_component_start = true;
    for (char c : value) {
        if (c == '/') {
            if (at_component_start) {
                return td::Status::Error(
                    "JVM manifest class_name has empty component");
            }
            at_component_start = true;
            continue;
        }
        if (at_component_start) {
            if (!is_java_identifier_start(c)) {
                return td::Status::Error(
                    "JVM manifest class_name component has invalid start");
            }
            at_component_start = false;
            continue;
        }
        if (!is_java_identifier_part(c)) {
            return td::Status::Error(
                "JVM manifest class_name contains invalid character");
        }
    }
    if (at_component_start) {
        return td::Status::Error(
            "JVM manifest class_name has trailing slash");
    }
    return td::Status::OK();
}

td::Status validate_manifest_method_name(const std::string& value) {
    TRY_STATUS(validate_manifest_string(value, "method_name"));
    if (!is_java_identifier_start(value.front())) {
        return td::Status::Error(
            "JVM manifest method_name has invalid start");
    }
    for (char c : value) {
        if (!is_java_identifier_part(c)) {
            return td::Status::Error(
                "JVM manifest method_name contains invalid character");
        }
    }
    return td::Status::OK();
}

td::Status validate_manifest_entry(
    const JvmAvataClassManifestEntry& entry) {
    if (is_zero_contract_id(entry.contract_id)) {
        return td::Status::Error("JVM manifest entry has zero contract id");
    }
    TRY_STATUS(validate_manifest_class_name(entry.class_name));
    TRY_STATUS(validate_manifest_method_name(entry.method_name));
    TRY_RESULT(arg_types, parse_jvm_method_argument_types(entry.method_spec));
    (void)arg_types;
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

td::Status validate_class_definition(
    const JvmAvataClassDefinition& definition) {
    if (is_zero_class_hash(definition.class_hash)) {
        return td::Status::Error("JVM class state definition has zero hash");
    }
    TRY_STATUS(validate_manifest_class_name(definition.class_name));
    if (definition.class_bytes.empty()) {
        return td::Status::Error("JVM class state definition has empty bytes");
    }
    if (definition.class_bytes.size() > kJvmDeployClassBytesMaxBytes) {
        return td::Status::Error("JVM class state definition bytes are too large");
    }
    if (compute_jvm_class_hash(definition.class_bytes) !=
        definition.class_hash) {
        return td::Status::Error("JVM class state definition hash mismatch");
    }
    return td::Status::OK();
}

td::Status validate_class_definitions(
    const std::vector<JvmAvataClassDefinition>& definitions) {
    if (definitions.size() > kJvmAvataClassStateMaxClasses) {
        return td::Status::Error("JVM class state has too many classes");
    }
    for (std::size_t i = 0; i < definitions.size(); ++i) {
        TRY_STATUS(validate_class_definition(definitions[i]));
        for (std::size_t j = 0; j < i; ++j) {
            if (same_class_name(definitions[i], definitions[j])) {
                return td::Status::Error(
                    "JVM class state has duplicate class name");
            }
        }
    }
    return td::Status::OK();
}

td::Status validate_class_state(const JvmAvataClassState& state) {
    TRY_STATUS(validate_manifest_entries(state.manifest_entries));
    TRY_STATUS(validate_class_definitions(state.classes));
    return td::Status::OK();
}

td::Status validate_class_store_limits(
    const JvmAvataClassState& state,
    const JvmClassStoreLimits& limits) {
    if (limits.max_class_bytes == 0 || limits.max_total_class_bytes == 0) {
        return td::Status::Error("JVM class store limits are invalid");
    }

    std::uint64_t total_class_bytes = 0;
    for (const auto& definition : state.classes) {
        if (definition.class_bytes.size() > limits.max_class_bytes) {
            return td::Status::Error(
                "JVM class state definition exceeds max_class_bytes");
        }
        total_class_bytes += definition.class_bytes.size();
        if (total_class_bytes > limits.max_total_class_bytes) {
            return td::Status::Error(
                "JVM class state exceeds max_total_class_bytes");
        }
    }
    return td::Status::OK();
}

JvmClassStoreLimits default_class_store_limits() {
    JvmClassStoreLimits limits;
    limits.max_class_bytes =
        static_cast<std::uint32_t>(kJvmDeployClassBytesMaxBytes);
    limits.max_total_class_bytes = std::numeric_limits<std::uint32_t>::max();
    return limits;
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

td::Result<JvmAvataClassDefinition> decode_class_definition_node(
    td::Ref<vm::Cell> node,
    td::Ref<vm::Cell>& next) {
    next = {};
    if (node.is_null()) {
        return td::Status::Error("JVM class state node is null");
    }

    bool special = false;
    auto cs = vm::load_cell_slice_special(node, special);
    if (special) {
        return td::Status::Error("JVM class state node is special");
    }

    JvmAvataClassDefinition definition;
    unsigned has_next = 0;
    if (!cs.fetch_bytes(definition.class_hash.data(),
                        static_cast<unsigned>(
                            definition.class_hash.size())) ||
        !cs.fetch_uint_to(1, has_next) ||
        has_next > 1) {
        return td::Status::Error("JVM class state node is truncated");
    }

    const unsigned expected_refs = 2 + has_next;
    if (cs.size() != 0 || cs.size_refs() != expected_refs) {
        return td::Status::Error("JVM class state node has malformed refs");
    }
    if (has_next != 0) {
        next = cs.fetch_ref();
    }
    auto class_name = cs.fetch_ref();
    auto class_bytes = cs.fetch_ref();
    if (!cs.empty_ext()) {
        return td::Status::Error("JVM class state node has trailing data");
    }

    TRY_RESULT(decoded_class_name,
               decode_string_cell(std::move(class_name), "class_name"));
    TRY_RESULT(decoded_class_bytes,
               decode_jvm_storage_value(std::move(class_bytes)));
    definition.class_name = std::move(decoded_class_name);
    definition.class_bytes = std::move(decoded_class_bytes);
    TRY_STATUS(validate_class_definition(definition));
    return definition;
}

td::Ref<vm::Cell> encode_class_definition_list(
    const std::vector<JvmAvataClassDefinition>& definitions) {
    td::Ref<vm::Cell> next;
    for (std::size_t i = definitions.size(); i-- > 0;) {
        auto class_name = encode_string_cell(definitions[i].class_name);
        auto class_bytes = encode_jvm_storage_value(definitions[i].class_bytes);
        if (class_name.is_null() || class_bytes.is_null()) {
            return {};
        }

        vm::CellBuilder node;
        if (!node.store_bytes_bool(
                definitions[i].class_hash.data(),
                static_cast<unsigned>(definitions[i].class_hash.size())) ||
            !node.store_ulong_rchk_bool(next.not_null() ? 1 : 0, 1)) {
            return {};
        }
        if (next.not_null() && !node.store_ref_bool(std::move(next))) {
            return {};
        }
        if (!node.store_ref_bool(std::move(class_name)) ||
            !node.store_ref_bool(std::move(class_bytes))) {
            return {};
        }
        next = node.finalize();
    }
    return next;
}

td::Result<std::uint32_t> read_root_magic(td::Ref<vm::Cell> root,
                                          const char* field_name) {
    if (root.is_null()) {
        return td::Status::Error(PSTRING() << field_name << " is null");
    }
    try {
        bool special = false;
        auto cs = vm::load_cell_slice_special(root, special);
        if (special) {
            return td::Status::Error(PSTRING() << field_name << " is special");
        }
        std::uint32_t magic = 0;
        if (!fetch_u32(cs, magic)) {
            return td::Status::Error(PSTRING()
                                     << field_name << " is truncated");
        }
        return magic;
    } catch (vm::VmError&) {
        return td::Status::Error(PSTRING()
                                 << field_name << " decode hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error(PSTRING()
                                 << field_name
                                 << " decode hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error(PSTRING() << field_name << " decode failed");
    }
}

td::Result<std::vector<JvmAvataClassManifestEntry>> parse_manifest_root(
    td::Ref<vm::Cell> root) {
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

td::Result<JvmAvataClassState> parse_class_state_envelope(
    td::Ref<vm::Cell> root) {
    JvmAvataClassState state;
    if (root.is_null()) {
        return td::Status::Error("JVM class state root is null");
    }

    try {
        bool special = false;
        auto cs = vm::load_cell_slice_special(root, special);
        if (special) {
            return td::Status::Error("JVM class state root is special");
        }

        std::uint32_t magic = 0;
        std::uint8_t schema = 0;
        std::uint16_t class_count = 0;
        if (!fetch_u32(cs, magic) ||
            magic != kJvmAvataClassStateMagic ||
            !fetch_u8(cs, schema) ||
            schema != kJvmAvataClassStateSchemaVersion ||
            !fetch_u16(cs, class_count)) {
            return td::Status::Error("JVM class state root is malformed");
        }
        if (class_count > kJvmAvataClassStateMaxClasses) {
            return td::Status::Error("JVM class state has too many classes");
        }

        const unsigned expected_refs = class_count == 0 ? 1 : 2;
        if (cs.size() != 0 || cs.size_refs() != expected_refs) {
            return td::Status::Error(
                "JVM class state root has malformed refs");
        }

        auto manifest_root = cs.fetch_ref();
        TRY_RESULT(manifest_entries,
                   parse_manifest_root(std::move(manifest_root)));
        state.manifest_entries = std::move(manifest_entries);

        if (class_count == 0) {
            if (!cs.empty_ext()) {
                return td::Status::Error(
                    "JVM class state empty root has trailing data");
            }
            return state;
        }

        auto node = cs.fetch_ref();
        if (!cs.empty_ext()) {
            return td::Status::Error("JVM class state root has trailing data");
        }

        state.classes.reserve(class_count);
        for (std::uint16_t i = 0; i < class_count; ++i) {
            td::Ref<vm::Cell> next;
            TRY_RESULT(definition,
                       decode_class_definition_node(std::move(node), next));
            for (const auto& existing : state.classes) {
                if (same_class_name(definition, existing)) {
                    return td::Status::Error(
                        "JVM class state has duplicate class name");
                }
            }
            state.classes.push_back(std::move(definition));
            node = std::move(next);
        }
        if (node.not_null()) {
            return td::Status::Error(
                "JVM class state has trailing class nodes");
        }
        return state;
    } catch (vm::VmError&) {
        return td::Status::Error("JVM class state decode hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error(
            "JVM class state decode hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM class state decode failed");
    }
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
    TRY_RESULT(magic, read_root_magic(root, "JVM class manifest root"));
    if (magic == kJvmAvataClassManifestMagic) {
        return parse_manifest_root(std::move(root));
    }
    if (magic == kJvmAvataClassStateMagic) {
        TRY_RESULT(state, parse_class_state_envelope(std::move(root)));
        return std::move(state.manifest_entries);
    }
    return td::Status::Error("JVM class manifest root has wrong magic");
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

td::Ref<vm::Cell> encode_jvm_avata_class_state(
    const JvmAvataClassState& state) {
    if (validate_class_state(state).is_error()) {
        return {};
    }

    auto manifest = encode_jvm_avata_class_manifest(state.manifest_entries);
    if (manifest.is_null()) {
        return {};
    }

    td::Ref<vm::Cell> class_list;
    if (!state.classes.empty()) {
        class_list = encode_class_definition_list(state.classes);
        if (class_list.is_null()) {
            return {};
        }
    }

    vm::CellBuilder root;
    if (!root.store_ulong_rchk_bool(kJvmAvataClassStateMagic, 32) ||
        !root.store_ulong_rchk_bool(kJvmAvataClassStateSchemaVersion, 8) ||
        !root.store_ulong_rchk_bool(state.classes.size(), 16) ||
        !root.store_ref_bool(std::move(manifest))) {
        return {};
    }
    if (class_list.not_null() &&
        !root.store_ref_bool(std::move(class_list))) {
        return {};
    }
    return root.finalize();
}

td::Result<JvmAvataClassState> parse_jvm_avata_class_state(
    td::Ref<vm::Cell> root) {
    TRY_RESULT(magic, read_root_magic(root, "JVM class state root"));
    if (magic == kJvmAvataClassManifestMagic) {
        JvmAvataClassState state;
        TRY_RESULT(entries, parse_manifest_root(std::move(root)));
        state.manifest_entries = std::move(entries);
        return state;
    }
    if (magic == kJvmAvataClassStateMagic) {
        return parse_class_state_envelope(std::move(root));
    }
    return td::Status::Error("JVM class state root has wrong magic");
}

td::Result<JvmAvataClassDefinition> find_jvm_avata_class_definition(
    td::Ref<vm::Cell> root,
    const std::string& class_name) {
    TRY_STATUS(validate_manifest_class_name(class_name));
    TRY_RESULT(state, parse_jvm_avata_class_state(std::move(root)));
    for (const auto& definition : state.classes) {
        if (definition.class_name == class_name) {
            return definition;
        }
    }
    return td::Status::Error("JVM class state has no matching class");
}

td::Result<JvmDeployInstallResult> install_jvm_deploy_descriptor(
    td::Ref<vm::Cell> previous_class_state_root,
    const JvmDeployDescriptor& descriptor) {
    return install_jvm_deploy_descriptor(
        std::move(previous_class_state_root),
        descriptor,
        default_class_store_limits());
}

td::Result<JvmDeployInstallResult> install_jvm_deploy_descriptor(
    td::Ref<vm::Cell> previous_class_state_root,
    const JvmDeployDescriptor& descriptor,
    const JvmClassStoreLimits& limits) {
    TRY_RESULT(contract_id, derive_jvm_contract_id(descriptor));

    JvmAvataClassState state;
    if (previous_class_state_root.not_null()) {
        TRY_RESULT(decoded_state,
                   parse_jvm_avata_class_state(
                       std::move(previous_class_state_root)));
        state = std::move(decoded_state);
    }

    JvmAvataClassDefinition definition;
    definition.class_hash = descriptor.class_hash;
    definition.class_name = descriptor.class_name;
    definition.class_bytes = descriptor.class_bytes;
    TRY_STATUS(validate_class_definition(definition));

    bool found = false;
    for (const auto& existing : state.classes) {
        if (existing.class_name != definition.class_name) {
            continue;
        }
        if (existing.class_hash != definition.class_hash ||
            existing.class_bytes != definition.class_bytes) {
            return td::Status::Error(
                "JVM class state already has different bytes for class");
        }
        found = true;
        break;
    }
    if (!found) {
        state.classes.push_back(std::move(definition));
    }
    TRY_STATUS(validate_class_store_limits(state, limits));

    auto class_state_root = encode_jvm_avata_class_state(state);
    if (class_state_root.is_null()) {
        return td::Status::Error("JVM class state encode failed");
    }

    JvmDeployInstallResult result;
    result.contract_id = contract_id;
    result.class_state_root = std::move(class_state_root);
    return result;
}

td::Result<JvmDeployInstallResult> install_jvm_deploy_descriptor(
    td::Ref<vm::Cell> previous_class_state_root,
    const JvmDeployDescriptor& descriptor,
    const JvmConfig& config) {
    JvmClassStoreLimits limits;
    limits.max_class_bytes = config.max_class_bytes;
    limits.max_total_class_bytes = config.max_total_class_bytes;
    return install_jvm_deploy_descriptor(
        std::move(previous_class_state_root), descriptor, limits);
}

// -------------------------------------------------------------------------
// JVM v2: per-account method manifest implementation.
// -------------------------------------------------------------------------

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
