/*
    JVM Workchain — deployment message ABI codec implementation.
*/
#include "jvm/core/deploy-abi.h"

#include <utility>

#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

namespace jvm_workchain {

namespace {

bool is_zero_contract_id(const JvmContractId& value) {
    for (std::uint8_t byte : value) {
        if (byte != 0) {
            return false;
        }
    }
    return true;
}

bool is_zero_class_hash(const JvmClassHash& value) {
    for (std::uint8_t byte : value) {
        if (byte != 0) {
            return false;
        }
    }
    return true;
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

td::Status validate_deploy_class_name(const std::string& value) {
    if (value.empty()) {
        return td::Status::Error("JVM deploy class_name is empty");
    }
    if (value.size() > kJvmDeployClassNameMaxBytes) {
        return td::Status::Error("JVM deploy class_name is too long");
    }
    bool at_component_start = true;
    for (char c : value) {
        if (c == '\0') {
            return td::Status::Error("JVM deploy class_name contains NUL");
        }
        if (c == '/') {
            if (at_component_start) {
                return td::Status::Error(
                    "JVM deploy class_name has empty component");
            }
            at_component_start = true;
            continue;
        }
        if (at_component_start) {
            if (!is_java_identifier_start(c)) {
                return td::Status::Error(
                    "JVM deploy class_name component has invalid start");
            }
            at_component_start = false;
            continue;
        }
        if (!is_java_identifier_part(c)) {
            return td::Status::Error(
                "JVM deploy class_name contains invalid character");
        }
    }
    if (at_component_start) {
        return td::Status::Error("JVM deploy class_name has trailing slash");
    }
    return td::Status::OK();
}

bool validate_plain_cell(td::Ref<vm::Cell> cell) {
    if (cell.is_null()) {
        return false;
    }
    bool special = false;
    (void)vm::load_cell_slice_special(cell, special);
    return !special;
}

td::Status validate_deploy_descriptor(
    const JvmDeployDescriptor& descriptor) {
    if (descriptor.schema_version != kJvmDeployDescriptorSchemaVersion) {
        return td::Status::Error("JVM deploy descriptor has unsupported schema");
    }
    if (is_zero_contract_id(descriptor.deployer)) {
        return td::Status::Error("JVM deploy descriptor has zero deployer");
    }
    if (is_zero_class_hash(descriptor.class_hash)) {
        return td::Status::Error("JVM deploy descriptor has zero class hash");
    }
    TRY_STATUS(validate_deploy_class_name(descriptor.class_name));
    if (descriptor.class_bytes.empty()) {
        return td::Status::Error("JVM deploy descriptor has empty class bytes");
    }
    if (descriptor.class_bytes.size() > kJvmDeployClassBytesMaxBytes) {
        return td::Status::Error("JVM deploy descriptor class bytes are too large");
    }
    if (compute_jvm_class_hash(descriptor.class_bytes) != descriptor.class_hash) {
        return td::Status::Error("JVM deploy descriptor class hash mismatch");
    }
    if (!validate_plain_cell(descriptor.init_args)) {
        return td::Status::Error("JVM deploy descriptor has invalid init args");
    }
    return td::Status::OK();
}

td::Ref<vm::Cell> encode_string_cell(const std::string& value) {
    JvmStorageValue bytes(value.begin(), value.end());
    return encode_jvm_storage_value(bytes);
}

td::Result<std::string> decode_string_cell(td::Ref<vm::Cell> cell) {
    TRY_RESULT(bytes, decode_jvm_storage_value(std::move(cell)));
    std::string value(bytes.begin(), bytes.end());
    TRY_STATUS(validate_deploy_class_name(value));
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

bool fetch_u32(vm::CellSlice& cs, std::uint32_t& out) {
    unsigned long long v = 0;
    if (!cs.fetch_ulong_bool(32, v)) {
        return false;
    }
    out = static_cast<std::uint32_t>(v);
    return true;
}

void append_bytes(std::string& out, const std::uint8_t* bytes,
                  std::size_t size) {
    out.append(reinterpret_cast<const char*>(bytes), size);
}

}  // namespace

JvmClassHash compute_jvm_class_hash(const JvmStorageValue& class_bytes) {
    JvmClassHash out{};
    if (!class_bytes.empty()) {
        td::sha256(td::Slice(reinterpret_cast<const char*>(class_bytes.data()),
                             class_bytes.size()),
                   td::MutableSlice(reinterpret_cast<char*>(out.data()),
                                    out.size()));
    }
    return out;
}

td::Result<JvmContractId> derive_jvm_contract_id(
    const JvmDeployDescriptor& descriptor) {
    TRY_STATUS(validate_deploy_descriptor(descriptor));

    std::string material = "TOS-JVM-CONTRACT-v1";
    append_bytes(material, descriptor.deployer.data(),
                 descriptor.deployer.size());
    append_bytes(material, descriptor.class_hash.data(),
                 descriptor.class_hash.size());
    append_bytes(material, descriptor.salt.data(), descriptor.salt.size());
    auto init_hash = descriptor.init_args->get_hash().as_slice();
    material.append(init_hash.data(), init_hash.size());

    JvmContractId out{};
    td::sha256(td::Slice(material),
               td::MutableSlice(reinterpret_cast<char*>(out.data()),
                                out.size()));
    return out;
}

td::Result<JvmContractId> derive_jvm_contract_address(
    const JvmDeployDescriptor& descriptor) {
    TRY_STATUS(validate_deploy_descriptor(descriptor));

    std::string material = "TOS-JVM-CONTRACT-v2";
    append_bytes(material, descriptor.deployer.data(),
                 descriptor.deployer.size());
    append_bytes(material, descriptor.class_hash.data(),
                 descriptor.class_hash.size());
    append_bytes(material, descriptor.salt.data(), descriptor.salt.size());
    auto init_hash = descriptor.init_args->get_hash().as_slice();
    material.append(init_hash.data(), init_hash.size());

    JvmContractId out{};
    td::sha256(td::Slice(material),
               td::MutableSlice(reinterpret_cast<char*>(out.data()),
                                out.size()));
    return out;
}

td::Ref<vm::Cell> encode_jvm_deploy_descriptor(
    const JvmDeployDescriptor& descriptor) {
    if (validate_deploy_descriptor(descriptor).is_error()) {
        return {};
    }

    auto class_name = encode_string_cell(descriptor.class_name);
    auto class_bytes = encode_jvm_storage_value(descriptor.class_bytes);
    if (class_name.is_null() || class_bytes.is_null()) {
        return {};
    }

    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(kJvmDeployDescriptorMagic, 32) ||
        !cb.store_ulong_rchk_bool(descriptor.schema_version, 8) ||
        !cb.store_bytes_bool(descriptor.deployer.data(),
                             static_cast<unsigned>(
                                 descriptor.deployer.size())) ||
        !cb.store_bytes_bool(descriptor.salt.data(),
                             static_cast<unsigned>(descriptor.salt.size())) ||
        !cb.store_bytes_bool(descriptor.class_hash.data(),
                             static_cast<unsigned>(
                                 descriptor.class_hash.size())) ||
        !cb.store_ref_bool(std::move(class_name)) ||
        !cb.store_ref_bool(std::move(class_bytes)) ||
        !cb.store_ref_bool(descriptor.init_args)) {
        return {};
    }
    return cb.finalize();
}

td::Result<JvmDeployDescriptor> parse_jvm_deploy_descriptor(
    td::Ref<vm::CellSlice> body) {
    if (body.is_null()) {
        return td::Status::Error("JVM deploy descriptor body is missing");
    }
    return parse_jvm_deploy_descriptor(*body);
}

td::Result<JvmDeployDescriptor> parse_jvm_deploy_descriptor(vm::CellSlice body) {
    try {
        JvmDeployDescriptor descriptor;
        std::uint32_t magic = 0;
        if (!fetch_u32(body, magic) || magic != kJvmDeployDescriptorMagic) {
            return td::Status::Error("JVM deploy descriptor has wrong magic");
        }
        if (!fetch_u8(body, descriptor.schema_version) ||
            descriptor.schema_version != kJvmDeployDescriptorSchemaVersion) {
            return td::Status::Error(
                "JVM deploy descriptor has unsupported schema");
        }
        if (!body.fetch_bytes(descriptor.deployer.data(),
                              static_cast<unsigned>(
                                  descriptor.deployer.size())) ||
            !body.fetch_bytes(descriptor.salt.data(),
                              static_cast<unsigned>(
                                  descriptor.salt.size())) ||
            !body.fetch_bytes(descriptor.class_hash.data(),
                              static_cast<unsigned>(
                                  descriptor.class_hash.size()))) {
            return td::Status::Error("JVM deploy descriptor is truncated");
        }
        if (body.size() != 0 || body.size_refs() != 3) {
            return td::Status::Error(
                "JVM deploy descriptor must carry class refs and init args");
        }

        auto class_name = body.fetch_ref();
        auto class_bytes = body.fetch_ref();
        descriptor.init_args = body.fetch_ref();
        if (!body.empty_ext()) {
            return td::Status::Error("JVM deploy descriptor has trailing data");
        }

        TRY_RESULT(decoded_class_name,
                   decode_string_cell(std::move(class_name)));
        TRY_RESULT(decoded_class_bytes,
                   decode_jvm_storage_value(std::move(class_bytes)));
        descriptor.class_name = std::move(decoded_class_name);
        descriptor.class_bytes = std::move(decoded_class_bytes);
        TRY_STATUS(validate_deploy_descriptor(descriptor));
        return descriptor;
    } catch (vm::VmError&) {
        return td::Status::Error("JVM deploy descriptor decode hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error(
            "JVM deploy descriptor decode hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM deploy descriptor decode failed");
    }
}

}  // namespace jvm_workchain
