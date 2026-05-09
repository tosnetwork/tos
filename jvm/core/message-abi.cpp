/*
    JVM Workchain — inbound message ABI codec implementation.
*/
#include "jvm/core/message-abi.h"

#include <algorithm>
#include <utility>

#include "jvm/core/storage-cell-host.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

namespace jvm_workchain {

namespace {

bool validate_plain_cell(td::Ref<vm::Cell> cell) {
    if (cell.is_null()) {
        return false;
    }
    try {
        bool special = false;
        (void)vm::load_cell_slice_special(cell, special);
        return !special;
    } catch (...) {
        return false;
    }
}

td::Status validate_descriptor(const JvmCallDescriptor& descriptor) {
    if (descriptor.schema_version != kJvmCallDescriptorSchemaVersion) {
        return td::Status::Error("JVM call descriptor has unsupported schema");
    }
    if (!validate_plain_cell(descriptor.args)) {
        return td::Status::Error(
            "JVM call descriptor args ref is missing or special");
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

td::Status validate_arg_value(const JvmTypedArg& value) {
    switch (value.type) {
        case JvmArgType::Bool:
            if (value.bytes.size() != 1 ||
                (value.bytes[0] != 0 && value.bytes[0] != 1)) {
                return td::Status::Error("JVM bool arg must be 0 or 1");
            }
            return td::Status::OK();
        case JvmArgType::Int32:
            if (value.bytes.size() != 4) {
                return td::Status::Error("JVM int arg must be 4 bytes");
            }
            return td::Status::OK();
        case JvmArgType::Int64:
            if (value.bytes.size() != 8) {
                return td::Status::Error("JVM long arg must be 8 bytes");
            }
            return td::Status::OK();
        case JvmArgType::Bytes:
            if (value.bytes.size() > kJvmStorageValueMaxBytes) {
                return td::Status::Error("JVM bytes arg is too large");
            }
            return td::Status::OK();
        case JvmArgType::Address:
            if (value.bytes.size() != 36) {
                return td::Status::Error("JVM address arg must be 36 bytes");
            }
            return td::Status::OK();
        case JvmArgType::Uint256:
        case JvmArgType::Bytes32:
            if (value.bytes.size() != 32) {
                return td::Status::Error(
                    "JVM 256-bit arg must be 32 bytes");
            }
            return td::Status::OK();
        case JvmArgType::Bytes4:
            if (value.bytes.size() != 4) {
                return td::Status::Error("JVM bytes4 arg must be 4 bytes");
            }
            return td::Status::OK();
    }
    return td::Status::Error("JVM arg has unsupported type");
}

td::Status validate_args(const JvmArgs& args) {
    if (args.schema_version != kJvmArgsSchemaVersion) {
        return td::Status::Error("JVM args have unsupported schema");
    }
    if (args.values.size() > kJvmArgsMaxCount) {
        return td::Status::Error("JVM args have too many values");
    }
    for (const auto& value : args.values) {
        TRY_STATUS(validate_arg_value(value));
    }
    return td::Status::OK();
}

td::Result<JvmArgType> parse_arg_type(std::uint8_t type) {
    switch (type) {
        case static_cast<std::uint8_t>(JvmArgType::Bool):
            return JvmArgType::Bool;
        case static_cast<std::uint8_t>(JvmArgType::Int32):
            return JvmArgType::Int32;
        case static_cast<std::uint8_t>(JvmArgType::Int64):
            return JvmArgType::Int64;
        case static_cast<std::uint8_t>(JvmArgType::Bytes):
            return JvmArgType::Bytes;
        case static_cast<std::uint8_t>(JvmArgType::Address):
            return JvmArgType::Address;
        case static_cast<std::uint8_t>(JvmArgType::Uint256):
            return JvmArgType::Uint256;
        case static_cast<std::uint8_t>(JvmArgType::Bytes32):
            return JvmArgType::Bytes32;
        case static_cast<std::uint8_t>(JvmArgType::Bytes4):
            return JvmArgType::Bytes4;
        default:
            return td::Status::Error("JVM arg has unknown type");
    }
}

td::Result<JvmTypedArg> decode_arg_node(td::Ref<vm::Cell> node,
                                        td::Ref<vm::Cell>& next) {
    next = {};
    if (node.is_null()) {
        return td::Status::Error("JVM args node is null");
    }

    bool special = false;
    auto cs = vm::load_cell_slice_special(node, special);
    if (special) {
        return td::Status::Error("JVM args node is special");
    }

    std::uint8_t type = 0;
    unsigned has_next = 0;
    if (!fetch_u8(cs, type) || !cs.fetch_uint_to(1, has_next) ||
        has_next > 1) {
        return td::Status::Error("JVM args node is truncated");
    }
    const unsigned expected_refs = 1 + has_next;
    if (cs.size() != 0 || cs.size_refs() != expected_refs) {
        return td::Status::Error("JVM args node has malformed refs");
    }
    if (has_next != 0) {
        next = cs.fetch_ref();
    }
    auto value_ref = cs.fetch_ref();
    if (!cs.empty_ext()) {
        return td::Status::Error("JVM args node has trailing data");
    }

    JvmTypedArg arg;
    TRY_RESULT(arg_type, parse_arg_type(type));
    arg.type = arg_type;
    TRY_RESULT(bytes, decode_jvm_storage_value(std::move(value_ref)));
    arg.bytes = std::move(bytes);
    TRY_STATUS(validate_arg_value(arg));
    return arg;
}

td::Ref<vm::Cell> encode_arg_list(const std::vector<JvmTypedArg>& values) {
    td::Ref<vm::Cell> next;
    for (std::size_t i = values.size(); i-- > 0;) {
        auto value_ref = encode_jvm_storage_value(values[i].bytes);
        if (value_ref.is_null()) {
            return {};
        }
        vm::CellBuilder node;
        if (!node.store_ulong_rchk_bool(
                static_cast<std::uint8_t>(values[i].type), 8) ||
            !node.store_ulong_rchk_bool(next.not_null() ? 1 : 0, 1)) {
            return {};
        }
        if (next.not_null() && !node.store_ref_bool(std::move(next))) {
            return {};
        }
        if (!node.store_ref_bool(std::move(value_ref))) {
            return {};
        }
        next = node.finalize();
    }
    return next;
}

td::Result<JvmArgType> parse_descriptor_argument(
    const std::string& method_spec,
    std::size_t& offset) {
    if (offset >= method_spec.size()) {
        return td::Status::Error("JVM method descriptor ended early");
    }
    const char code = method_spec[offset++];
    switch (code) {
        case 'Z':
            return JvmArgType::Bool;
        case 'I':
            return JvmArgType::Int32;
        case 'J':
            return JvmArgType::Int64;
        case 'L': {
            const auto end = method_spec.find(';', offset);
            if (end == std::string::npos) {
                return td::Status::Error(
                    "JVM method descriptor has unterminated object type");
            }
            const auto name = method_spec.substr(offset, end - offset);
            offset = end + 1;
            if (name == "java/lang/Bytes") {
                return JvmArgType::Bytes;
            }
            if (name == "java/lang/Address") {
                return JvmArgType::Address;
            }
            if (name == "java/lang/Uint256") {
                return JvmArgType::Uint256;
            }
            if (name == "java/lang/Bytes32") {
                return JvmArgType::Bytes32;
            }
            if (name == "java/lang/Bytes4") {
                return JvmArgType::Bytes4;
            }
            return td::Status::Error(
                "JVM method descriptor has unsupported object arg");
        }
        default:
            return td::Status::Error(
                "JVM method descriptor has unsupported arg type");
    }
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

td::Result<JvmCallDescriptor> parse_jvm_call_descriptor(
    vm::CellSlice body) {
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
        if (!fetch_u32(body, descriptor.method_id)) {
            return td::Status::Error("JVM call descriptor is truncated");
        }
        if (body.size() != 0 || body.size_refs() != 1) {
            return td::Status::Error(
                "JVM call descriptor must carry exactly one args ref");
        }
        descriptor.args = body.fetch_ref();
        if (!body.empty_ext()) {
            return td::Status::Error(
                "JVM call descriptor has trailing data");
        }
        TRY_STATUS(validate_descriptor(descriptor));
        return descriptor;
    } catch (vm::VmError&) {
        return td::Status::Error(
            "JVM call descriptor decode hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error(
            "JVM call descriptor decode hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM call descriptor decode failed");
    }
}

td::Ref<vm::Cell> encode_jvm_args(const JvmArgs& args) {
    if (validate_args(args).is_error()) {
        return {};
    }

    td::Ref<vm::Cell> arg_list;
    if (!args.values.empty()) {
        arg_list = encode_arg_list(args.values);
        if (arg_list.is_null()) {
            return {};
        }
    }

    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(kJvmArgsMagic, 32) ||
        !cb.store_ulong_rchk_bool(args.schema_version, 8) ||
        !cb.store_ulong_rchk_bool(args.values.size(), 8)) {
        return {};
    }
    if (arg_list.not_null() && !cb.store_ref_bool(std::move(arg_list))) {
        return {};
    }
    return cb.finalize();
}

td::Result<JvmArgs> parse_jvm_args(td::Ref<vm::Cell> root) {
    JvmArgs args;
    if (root.is_null()) {
        return td::Status::Error("JVM args root is null");
    }

    try {
        bool special = false;
        auto cs = vm::load_cell_slice_special(root, special);
        if (special) {
            return td::Status::Error("JVM args root is special");
        }

        std::uint32_t magic = 0;
        unsigned count = 0;
        if (!fetch_u32(cs, magic) || magic != kJvmArgsMagic ||
            !fetch_u8(cs, args.schema_version) ||
            args.schema_version != kJvmArgsSchemaVersion ||
            !cs.fetch_uint_to(8, count)) {
            return td::Status::Error("JVM args root is malformed");
        }
        if (count > kJvmArgsMaxCount) {
            return td::Status::Error("JVM args have too many values");
        }
        if (count == 0) {
            if (!cs.empty_ext()) {
                return td::Status::Error(
                    "JVM empty args root has trailing data");
            }
            return args;
        }
        if (cs.size() != 0 || cs.size_refs() != 1) {
            return td::Status::Error("JVM args root has malformed refs");
        }

        auto node = cs.fetch_ref();
        args.values.reserve(count);
        for (unsigned i = 0; i < count; ++i) {
            td::Ref<vm::Cell> next;
            TRY_RESULT(arg, decode_arg_node(std::move(node), next));
            args.values.push_back(std::move(arg));
            node = std::move(next);
        }
        if (node.not_null()) {
            return td::Status::Error("JVM args have trailing nodes");
        }
        return args;
    } catch (vm::VmError&) {
        return td::Status::Error("JVM args decode hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error("JVM args decode hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM args decode failed");
    }
}

// Round 65 MEDIUM fix: returns the canonical byte count for
// fixed-width typed args (Bool/Int32/Int64/Address/Uint256/
// Bytes32/Bytes4), or `std::nullopt` for variable-length types
// (Bytes).  Used by `peek_jvm_args_types` to reject non-canonical
// value cells (e.g. an Int32 arg whose value ref is a 1 MiB chunk
// chain) before the full payload decode.
std::optional<std::size_t> jvm_arg_fixed_byte_count(JvmArgType type) {
    switch (type) {
        case JvmArgType::Bool:    return 1;
        case JvmArgType::Int32:   return 4;
        case JvmArgType::Int64:   return 8;
        case JvmArgType::Bytes:   return std::nullopt;
        case JvmArgType::Address: return 36;
        case JvmArgType::Uint256: return 32;
        case JvmArgType::Bytes32: return 32;
        case JvmArgType::Bytes4:  return 4;
    }
    return std::nullopt;
}

td::Result<std::vector<JvmArgType>> peek_jvm_args_types(
    td::Ref<vm::Cell> root) {
    if (root.is_null()) {
        return td::Status::Error("JVM args root is null");
    }

    try {
        bool special = false;
        auto cs = vm::load_cell_slice_special(root, special);
        if (special) {
            return td::Status::Error("JVM args root is special");
        }

        std::uint32_t magic = 0;
        unsigned count = 0;
        std::uint8_t schema_version = 0;
        if (!fetch_u32(cs, magic) || magic != kJvmArgsMagic ||
            !fetch_u8(cs, schema_version) ||
            schema_version != kJvmArgsSchemaVersion ||
            !cs.fetch_uint_to(8, count)) {
            return td::Status::Error("JVM args root is malformed");
        }
        if (count > kJvmArgsMaxCount) {
            return td::Status::Error("JVM args have too many values");
        }
        std::vector<JvmArgType> types;
        if (count == 0) {
            if (!cs.empty_ext()) {
                return td::Status::Error(
                    "JVM empty args root has trailing data");
            }
            return types;
        }
        if (cs.size() != 0 || cs.size_refs() != 1) {
            return td::Status::Error("JVM args root has malformed refs");
        }

        types.reserve(count);
        auto node = cs.fetch_ref();
        for (unsigned i = 0; i < count; ++i) {
            if (node.is_null()) {
                return td::Status::Error("JVM args node is null");
            }
            bool node_special = false;
            auto node_cs = vm::load_cell_slice_special(node, node_special);
            if (node_special) {
                return td::Status::Error("JVM args node is special");
            }
            std::uint8_t type = 0;
            unsigned has_next = 0;
            if (!fetch_u8(node_cs, type) ||
                !node_cs.fetch_uint_to(1, has_next) || has_next > 1) {
                return td::Status::Error("JVM args node is truncated");
            }
            const unsigned expected_refs = 1 + has_next;
            if (node_cs.size() != 0 ||
                node_cs.size_refs() != expected_refs) {
                return td::Status::Error("JVM args node has malformed refs");
            }
            TRY_RESULT(arg_type, parse_arg_type(type));
            types.push_back(arg_type);
            // Advance to next node WITHOUT touching the value ref —
            // that's where the byte payload chain lives.
            td::Ref<vm::Cell> next;
            if (has_next != 0) {
                next = node_cs.fetch_ref();
            }
            // Round 65 MEDIUM fix: peek the value ref's structural
            // size for FIXED-WIDTH typed args (everything except
            // `Bytes`).  Pre-fix the peek skipped the value ref
            // entirely, so an attacker could send an `Int32` arg
            // whose value ref points at a multi-MiB chunk chain;
            // `parse_jvm_args` would memcpy the entire chain, then
            // `validate_arg_value` would reject the wrong byte
            // count, and dispatch billed only the admission floor.
            // For canonical fixed-width values, the value cell is
            // a single cell with `byte_count*8 + 1` bits (the +1 is
            // the trailing has_next=0) and zero refs.  Reject any
            // value cell that doesn't match that shape.
            auto value_ref = node_cs.fetch_ref();
            if (auto fixed = jvm_arg_fixed_byte_count(arg_type);
                fixed.has_value()) {
                if (value_ref.is_null()) {
                    return td::Status::Error(
                        "JVM args fixed-width value ref is null");
                }
                bool value_special = false;
                auto value_cs =
                    vm::load_cell_slice_special(value_ref, value_special);
                if (value_special) {
                    return td::Status::Error(
                        "JVM args fixed-width value cell is special");
                }
                const unsigned expected_bits =
                    static_cast<unsigned>(*fixed) * 8u + 1u;
                if (value_cs.size() != expected_bits ||
                    value_cs.size_refs() != 0) {
                    return td::Status::Error(
                        "JVM args fixed-width value has non-canonical size");
                }
            }
            if (!node_cs.empty_ext()) {
                return td::Status::Error("JVM args node has trailing data");
            }
            node = std::move(next);
        }
        if (node.not_null()) {
            return td::Status::Error("JVM args have trailing nodes");
        }
        return types;
    } catch (vm::VmError&) {
        return td::Status::Error("JVM args peek hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error("JVM args peek hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM args peek failed");
    }
}

td::Result<std::uint64_t> peek_jvm_args_total_bytes(
    td::Ref<vm::Cell> root,
    std::uint64_t* partial_walked_on_error,
    std::uint64_t max_bytes_budget) {
    // Round 68 MEDIUM fix: track the running byte total in a single
    // local; on every error return path, if `partial_walked_on_error`
    // is non-null, write the running count so callers can bill the
    // bytes the real decoder would have already memcpy'd before
    // failing at the same point.
    std::uint64_t total = 0;
    const auto fail = [&](td::Slice msg) -> td::Status {
        if (partial_walked_on_error != nullptr) {
            *partial_walked_on_error = total;
        }
        return td::Status::Error(msg.str());
    };
    if (root.is_null()) {
        return fail("JVM args root is null");
    }

    try {
        bool special = false;
        auto cs = vm::load_cell_slice_special(root, special);
        if (special) {
            return fail("JVM args root is special");
        }
        std::uint32_t magic = 0;
        unsigned count = 0;
        std::uint8_t schema_version = 0;
        if (!fetch_u32(cs, magic) || magic != kJvmArgsMagic ||
            !fetch_u8(cs, schema_version) ||
            schema_version != kJvmArgsSchemaVersion ||
            !cs.fetch_uint_to(8, count)) {
            return fail("JVM args root is malformed");
        }
        if (count > kJvmArgsMaxCount) {
            return fail("JVM args have too many values");
        }
        if (count == 0) {
            return std::uint64_t{0};
        }
        if (cs.size() != 0 || cs.size_refs() != 1) {
            return fail("JVM args root has malformed refs");
        }
        std::uint64_t local_total = 0;
        auto node = cs.fetch_ref();
        for (unsigned i = 0; i < count; ++i) {
            // Re-sync `total` to `local_total` at each loop iteration
            // so the `fail()` helper has the up-to-date partial when
            // it captures it.  We also write back at the end of each
            // arg's chunk walk.
            total = local_total;
            if (node.is_null()) {
                return fail("JVM args node is null");
            }
            bool node_special = false;
            auto node_cs = vm::load_cell_slice_special(node, node_special);
            if (node_special) {
                return fail("JVM args node is special");
            }
            std::uint8_t type = 0;
            unsigned has_next = 0;
            if (!fetch_u8(node_cs, type) ||
                !node_cs.fetch_uint_to(1, has_next) || has_next > 1) {
                return fail("JVM args node is truncated");
            }
            const unsigned expected_refs = 1 + has_next;
            if (node_cs.size() != 0 ||
                node_cs.size_refs() != expected_refs) {
                return fail("JVM args node has malformed refs");
            }
            td::Ref<vm::Cell> next;
            if (has_next != 0) {
                next = node_cs.fetch_ref();
            }
            auto value_ref = node_cs.fetch_ref();
            if (!node_cs.empty_ext()) {
                return fail("JVM args node has trailing data");
            }
            // Round 78 MEDIUM fix: mirror peek_jvm_args_types' cheap
            // gates — validate `parse_arg_type(type)` and, for
            // fixed-width types, require the canonical single-cell
            // value shape (no chunk chain).  Pre-fix the peek walked
            // a multi-MiB chunk chain attached to a fixed-width type
            // (Int32, Address, ...) and reported the entire chain's
            // byte count, so the round-76 pre-walk gate billed
            // attacker payload bytes the resolver+decoder would
            // never memcpy (decode_arg_node does memcpy then
            // validate_arg_value rejects, but the round-64 path
            // through peek_jvm_args_types in
            // decode_linked_invocation_args rejects fixed-width
            // shape mismatches BEFORE reaching parse_jvm_args).
            // For fixed-width types, account exactly the canonical
            // byte count (so over-billing tracks the work the
            // resolver actually performs).
            TRY_RESULT(arg_type, parse_arg_type(type));
            if (auto fixed = jvm_arg_fixed_byte_count(arg_type);
                fixed.has_value()) {
                if (value_ref.is_null()) {
                    return fail(
                        "JVM args fixed-width value ref is null");
                }
                bool value_special = false;
                auto value_cs =
                    vm::load_cell_slice_special(value_ref, value_special);
                if (value_special) {
                    return fail(
                        "JVM args fixed-width value cell is special");
                }
                const unsigned expected_bits =
                    static_cast<unsigned>(*fixed) * 8u + 1u;
                if (value_cs.size() != expected_bits ||
                    value_cs.size_refs() != 0) {
                    return fail(
                        "JVM args fixed-width value has non-canonical size");
                }
                const std::uint64_t fixed_bytes =
                    static_cast<std::uint64_t>(*fixed);
                if (local_total >
                    std::numeric_limits<std::uint64_t>::max() -
                        fixed_bytes) {
                    local_total =
                        std::numeric_limits<std::uint64_t>::max();
                } else {
                    local_total += fixed_bytes;
                }
                total = local_total;
                if (max_bytes_budget != 0 &&
                    local_total > max_bytes_budget) {
                    return fail("JVM args exceed peek byte budget");
                }
                node = std::move(next);
                continue;
            }
            // Variable-length (Bytes) — walk the value's chunk chain
            // summing byte counts only (no byte memcpy).  Mirrors
            // `decode_jvm_storage_value`'s structural walk; bounded
            // by `kJvmStorageValueMaxBytes`.
            //
            // Round 70 MEDIUM fix: track `value_byte_total` for THIS
            // value's chain separately from `local_total` (the
            // cumulative across-args total).  `decode_jvm_storage_value`
            // enforces `kJvmStorageValueMaxBytes` PER decoded value,
            // not across all args — pre-fix the peek capped on
            // cumulative bytes, so two args of 700 KiB summing to
            // 1.4 MiB caused the peek to error at 1 MiB while the
            // real decoder accepted both.  Reset the per-value count
            // at each value chain.
            auto chunk = value_ref;
            bool chain_done = false;
            std::uint64_t value_byte_total = 0;
            for (std::size_t chunks = 0;
                 !chain_done && chunks <=
                     kJvmStorageValueMaxBytes / kJvmStorageValueChunkBytes + 1;
                 ++chunks) {
                // Update `total` continuously so a `fail()` call
                // inside the chunk loop sees the latest count.
                total = local_total;
                if (chunk.is_null()) {
                    return fail("JVM args value chain ended early");
                }
                bool value_special = false;
                auto value_cs =
                    vm::load_cell_slice_special(chunk, value_special);
                if (value_special) {
                    return fail("JVM args value cell is special");
                }
                const unsigned bits = value_cs.size();
                if (bits < 1 || ((bits - 1) % 8) != 0) {
                    return fail("JVM args value cell is not byte-aligned");
                }
                const unsigned byte_count = (bits - 1) / 8;
                // Round 69/70 fix: per-value cap matches
                // `decode_jvm_storage_value` exactly.
                if (value_byte_total + byte_count >
                    kJvmStorageValueMaxBytes) {
                    return fail("JVM args value exceeds maximum size");
                }
                value_byte_total += byte_count;
                if (local_total >
                    std::numeric_limits<std::uint64_t>::max() - byte_count) {
                    local_total = std::numeric_limits<std::uint64_t>::max();
                } else {
                    local_total += byte_count;
                }
                total = local_total;
                // Round 77 LOW fix: bail out as soon as the running
                // byte total crosses the caller-supplied budget.
                // Pre-fix the walker traversed the full chunk chain
                // even when the eventual consensus reject was
                // already inevitable.  `partial_walked_on_error`
                // captures the count at exit; the dispatch /
                // RPC gates use either the success ok() value or
                // this partial, so the early exit reports the same
                // billing total without doing the rest of the walk.
                if (max_bytes_budget != 0 &&
                    local_total > max_bytes_budget) {
                    return fail("JVM args exceed peek byte budget");
                }
                // Skip the byte_count payload bytes without copying.
                if (!value_cs.advance(byte_count * 8u)) {
                    return fail("JVM args value cell payload truncated");
                }
                unsigned has_value_next = 0;
                if (!value_cs.fetch_uint_to(1, has_value_next)
                    || has_value_next > 1) {
                    return fail("JVM args value cell is truncated");
                }
                if (has_value_next == 0) {
                    chain_done = true;
                    break;
                }
                if (value_cs.size() != 0 || value_cs.size_refs() != 1) {
                    return fail("JVM args value continuation missing ref");
                }
                // Round 67 LOW fix: enforce canonical 127-byte
                // non-final chunks, mirroring round-57's
                // `decode_jvm_storage_value` rule.  Pre-fix
                // `peek_jvm_args_total_bytes` would walk a chain
                // of 1-byte continuation cells to the depth bound
                // before the real decoder (which has the same gate)
                // would have rejected on the first cell.
                if (byte_count != kJvmStorageValueChunkBytes) {
                    return fail("JVM args value has non-canonical "
                                 "continuation chunk size");
                }
                chunk = value_cs.fetch_ref();
            }
            if (!chain_done) {
                return fail("JVM args value chain too deep");
            }
            node = std::move(next);
        }
        total = local_total;
        if (node.not_null()) {
            return fail("JVM args have trailing nodes");
        }
        return total;
    } catch (vm::VmError&) {
        return fail("JVM args byte peek hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return fail("JVM args byte peek hit vm::VmVirtError");
    } catch (...) {
        return fail("JVM args byte peek failed");
    }
}

td::Result<std::vector<JvmArgType>> parse_jvm_method_argument_types(
    const std::string& method_spec) {
    if (method_spec.size() < 3 || method_spec[0] != '(') {
        return td::Status::Error("JVM method descriptor is malformed");
    }

    std::vector<JvmArgType> types;
    std::size_t offset = 1;
    while (offset < method_spec.size() && method_spec[offset] != ')') {
        if (types.size() >= kJvmArgsMaxCount) {
            return td::Status::Error("JVM method descriptor has too many args");
        }
        TRY_RESULT(type, parse_descriptor_argument(method_spec, offset));
        types.push_back(type);
    }
    if (offset >= method_spec.size() || method_spec[offset] != ')') {
        return td::Status::Error("JVM method descriptor is missing return");
    }
    ++offset;
    if (offset != method_spec.size() - 1 || method_spec[offset] != 'V') {
        return td::Status::Error(
            "JVM v1 typed ABI supports only void return descriptors");
    }
    return types;
}

td::Status validate_jvm_typed_args_against_spec(
    const std::string& method_spec, const JvmArgs& parsed_args) {
    TRY_RESULT(expected_types, parse_jvm_method_argument_types(method_spec));
    if (parsed_args.values.size() != expected_types.size()) {
        return td::Status::Error("JVM typed args count mismatch");
    }
    for (std::size_t i = 0; i < expected_types.size(); ++i) {
        if (parsed_args.values[i].type != expected_types[i]) {
            return td::Status::Error("JVM typed arg type mismatch");
        }
    }
    return td::Status::OK();
}

td::Status validate_jvm_typed_call_args(const std::string& method_spec,
                                        td::Ref<vm::Cell> args) {
    TRY_RESULT(decoded_args, parse_jvm_args(std::move(args)));
    return validate_jvm_typed_args_against_spec(method_spec, decoded_args);
}

td::Status validate_jvm_static_void_call_args(
    const std::string& method_spec,
    td::Ref<vm::Cell> args) {
    if (method_spec != kJvmStaticVoidMethodSpec) {
        return td::Status::Error(
            "JVM v1 linked runtime supports only static void entry points");
    }
    if (args.is_null()) {
        return td::Status::Error("JVM static void call is missing args cell");
    }

    try {
        bool special = false;
        auto cs = vm::load_cell_slice_special(args, special);
        if (special) {
            return td::Status::Error(
                "JVM static void call args cell is special");
        }
        if (!cs.empty_ext()) {
            return td::Status::Error(
                "JVM static void call requires empty args cell");
        }
        return td::Status::OK();
    } catch (vm::VmError&) {
        return td::Status::Error(
            "JVM static void call args decode hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error(
            "JVM static void call args decode hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM static void call args decode failed");
    }
}

}  // namespace jvm_workchain
