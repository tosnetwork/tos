/*
    JVM Workchain — cell codec implementation.
*/
#include "jvm/core/cell-codec.h"

#include "jvm/core/class-manifest.h"
#include "jvm/core/storage-cell-host.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

namespace jvm_workchain {

namespace {

bool store_maybe_ref(vm::CellBuilder& cb, const td::Ref<vm::Cell>& ref) {
    if (ref.not_null()) {
        return cb.store_ulong_rchk_bool(1, 1) && cb.store_ref_bool(ref);
    }
    return cb.store_ulong_rchk_bool(0, 1);
}

bool fetch_maybe_ref(vm::CellSlice& cs, td::Ref<vm::Cell>& ref) {
    ref = {};
    unsigned has_ref = 0;
    if (!cs.fetch_uint_to(1, has_ref)) {
        return false;
    }
    if (has_ref == 0) {
        return true;
    }
    if (has_ref != 1 || cs.size_refs() == 0) {
        return false;
    }
    return cs.fetch_ref_to(ref);
}

bool validate_optional_class_manifest(td::Ref<vm::Cell> cell) {
    if (cell.is_null()) {
        return true;
    }
    return parse_jvm_avata_class_manifest(std::move(cell)).is_ok();
}

}  // namespace

td::Ref<vm::Cell> encode_jvm_executor_state(const JvmExecutorState& state) {
    if (state.schema_version != kJvmExecutorStateSchemaVersion) {
        return {};
    }

    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(kJvmExecutorStateMagic,
                                  kJvmExecutorStateMagicBits) ||
        !cb.store_ulong_rchk_bool(state.schema_version, 8) ||
        !cb.store_bytes_bool(state.stdlib_hash.data(),
                             static_cast<unsigned>(state.stdlib_hash.size())) ||
        !store_maybe_ref(cb, state.storage_root) ||
        !store_maybe_ref(cb, state.class_state_root)) {
        return {};
    }
    return cb.finalize();
}

bool decode_jvm_executor_state(td::Ref<vm::Cell> cell, JvmExecutorState& out) {
    out = JvmExecutorState{};
    if (cell.is_null()) {
        return false;
    }

    try {
        bool special = false;
        auto cs = vm::load_cell_slice_special(cell, special);
        if (special) {
            return false;
        }

        unsigned long long magic = 0;
        if (!cs.fetch_ulong_bool(kJvmExecutorStateMagicBits, magic) ||
            static_cast<std::uint32_t>(magic) != kJvmExecutorStateMagic) {
            return false;
        }

        unsigned schema_version = 0;
        if (!cs.fetch_uint_to(8, schema_version) ||
            schema_version != kJvmExecutorStateSchemaVersion) {
            return false;
        }
        out.schema_version = static_cast<std::uint8_t>(schema_version);

        if (!cs.fetch_bytes(out.stdlib_hash.data(),
                            static_cast<unsigned>(out.stdlib_hash.size())) ||
            !fetch_maybe_ref(cs, out.storage_root) ||
            !fetch_maybe_ref(cs, out.class_state_root) ||
            !cs.empty_ext()) {
            out = JvmExecutorState{};
            return false;
        }
        if (!validate_jvm_storage_root(out.storage_root) ||
            !validate_optional_class_manifest(out.class_state_root)) {
            out = JvmExecutorState{};
            return false;
        }

        return true;
    } catch (vm::VmError&) {
        out = JvmExecutorState{};
        return false;
    } catch (vm::VmVirtError&) {
        out = JvmExecutorState{};
        return false;
    } catch (...) {
        out = JvmExecutorState{};
        return false;
    }
}

}  // namespace jvm_workchain
