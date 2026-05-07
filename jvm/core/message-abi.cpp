/*
    JVM Workchain — inbound message ABI codec implementation.
*/
#include "jvm/core/message-abi.h"

#include <algorithm>

#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

namespace jvm_workchain {

namespace {

bool is_zero_contract_id(const JvmContractId& contract_id) {
    return std::all_of(contract_id.begin(), contract_id.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

bool validate_plain_cell(td::Ref<vm::Cell> cell) {
    if (cell.is_null()) {
        return false;
    }
    bool special = false;
    (void)vm::load_cell_slice_special(cell, special);
    return !special;
}

td::Status validate_descriptor(const JvmCallDescriptor& descriptor) {
    if (descriptor.schema_version != kJvmCallDescriptorSchemaVersion) {
        return td::Status::Error("JVM call descriptor has unsupported schema");
    }
    if (is_zero_contract_id(descriptor.contract_id)) {
        return td::Status::Error("JVM call descriptor has zero contract id");
    }
    if (!validate_plain_cell(descriptor.args)) {
        return td::Status::Error("JVM call descriptor has invalid args cell");
    }
    return td::Status::OK();
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

}  // namespace

td::Ref<vm::Cell> encode_jvm_call_descriptor(
    const JvmCallDescriptor& descriptor) {
    if (validate_descriptor(descriptor).is_error()) {
        return {};
    }

    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(kJvmCallDescriptorMagic, 32) ||
        !cb.store_ulong_rchk_bool(descriptor.schema_version, 8) ||
        !cb.store_bytes_bool(descriptor.contract_id.data(),
                             static_cast<unsigned>(
                                 descriptor.contract_id.size())) ||
        !cb.store_ulong_rchk_bool(descriptor.method_id, 32) ||
        !cb.store_ref_bool(descriptor.args)) {
        return {};
    }
    return cb.finalize();
}

td::Result<JvmCallDescriptor> parse_jvm_call_descriptor(
    td::Ref<vm::CellSlice> body) {
    if (body.is_null()) {
        return td::Status::Error("JVM call descriptor body is missing");
    }
    return parse_jvm_call_descriptor(*body);
}

td::Result<JvmCallDescriptor> parse_jvm_call_descriptor(vm::CellSlice body) {
    try {
        JvmCallDescriptor descriptor;
        std::uint32_t magic = 0;
        if (!fetch_u32(body, magic) || magic != kJvmCallDescriptorMagic) {
            return td::Status::Error("JVM call descriptor has wrong magic");
        }
        if (!fetch_u8(body, descriptor.schema_version) ||
            descriptor.schema_version != kJvmCallDescriptorSchemaVersion) {
            return td::Status::Error(
                "JVM call descriptor has unsupported schema");
        }
        if (!body.fetch_bytes(
                descriptor.contract_id.data(),
                static_cast<unsigned>(descriptor.contract_id.size())) ||
            !fetch_u32(body, descriptor.method_id)) {
            return td::Status::Error("JVM call descriptor is truncated");
        }
        if (body.size() != 0 || body.size_refs() != 1) {
            return td::Status::Error(
                "JVM call descriptor must carry exactly one args ref");
        }
        descriptor.args = body.fetch_ref();
        if (!body.empty_ext()) {
            return td::Status::Error("JVM call descriptor has trailing data");
        }
        TRY_STATUS(validate_descriptor(descriptor));
        return descriptor;
    } catch (vm::VmError&) {
        return td::Status::Error("JVM call descriptor decode hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error(
            "JVM call descriptor decode hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM call descriptor decode failed");
    }
}

}  // namespace jvm_workchain
