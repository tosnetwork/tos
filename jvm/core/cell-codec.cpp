/*
    JVM Workchain — cell codec implementation.
*/
#include "jvm/core/cell-codec.h"

#include "jvm/core/class-manifest.h"
#include "jvm/core/dispatch-engine.h"  // for kJvmActivationCode
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

namespace {

bool jvm_class_hash_is_zero(const JvmClassHash& h) {
    for (auto b : h) {
        if (b != 0) {
            return false;
        }
    }
    return true;
}

}  // namespace

td::Ref<vm::Cell> encode_jvm_contract_account_state(
    const JvmContractAccountState& state) {
    if (state.schema_version != kJvmContractAccountStateSchemaVersion) {
        return {};
    }
    if (state.class_bytes.is_null() || jvm_class_hash_is_zero(state.class_hash)) {
        return {};
    }

    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(kJvmContractAccountStateMagic,
                                  kJvmContractAccountStateMagicBits) ||
        !cb.store_ulong_rchk_bool(state.schema_version, 8) ||
        !cb.store_bytes_bool(state.stdlib_hash.data(),
                             static_cast<unsigned>(state.stdlib_hash.size())) ||
        !cb.store_bytes_bool(state.class_hash.data(),
                             static_cast<unsigned>(state.class_hash.size())) ||
        !cb.store_ref_bool(state.class_bytes) ||
        !store_maybe_ref(cb, state.storage_root) ||
        !store_maybe_ref(cb, state.manifest_root)) {
        return {};
    }
    return cb.finalize();
}

bool decode_jvm_contract_account_state(td::Ref<vm::Cell> cell,
                                       JvmContractAccountState& out) {
    out = JvmContractAccountState{};
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
        if (!cs.fetch_ulong_bool(kJvmContractAccountStateMagicBits, magic) ||
            static_cast<std::uint32_t>(magic) !=
                kJvmContractAccountStateMagic) {
            return false;
        }

        unsigned schema_version = 0;
        if (!cs.fetch_uint_to(8, schema_version) ||
            schema_version != kJvmContractAccountStateSchemaVersion) {
            return false;
        }
        out.schema_version = static_cast<std::uint8_t>(schema_version);

        if (!cs.fetch_bytes(out.stdlib_hash.data(),
                            static_cast<unsigned>(out.stdlib_hash.size())) ||
            !cs.fetch_bytes(out.class_hash.data(),
                            static_cast<unsigned>(out.class_hash.size())) ||
            cs.size_refs() == 0 ||
            !cs.fetch_ref_to(out.class_bytes) ||
            !fetch_maybe_ref(cs, out.storage_root) ||
            !fetch_maybe_ref(cs, out.manifest_root) ||
            !cs.empty_ext()) {
            out = JvmContractAccountState{};
            return false;
        }
        if (jvm_class_hash_is_zero(out.class_hash) ||
            out.class_bytes.is_null() ||
            !validate_jvm_storage_root(out.storage_root)) {
            out = JvmContractAccountState{};
            return false;
        }
        return true;
    } catch (vm::VmError&) {
        out = JvmContractAccountState{};
        return false;
    } catch (vm::VmVirtError&) {
        out = JvmContractAccountState{};
        return false;
    } catch (...) {
        out = JvmContractAccountState{};
        return false;
    }
}

td::Ref<vm::Cell> encode_jvm_state_init_cell(
    const JvmContractAccountState& state) {
    auto data_cell = encode_jvm_contract_account_state(state);
    if (data_cell.is_null()) {
        return {};
    }
    // Inline the activation marker (single byte 0x4a, 'J') to avoid pulling in
    // dispatch-engine.h.  Mirrors `jvm_activation_code_cell()`.
    vm::CellBuilder code_cb;
    if (!code_cb.store_ulong_rchk_bool(kJvmActivationCode, 8)) {
        return {};
    }
    td::Ref<vm::Cell> code_cell = code_cb.finalize();
    if (code_cell.is_null()) {
        return {};
    }
    // StateInit TLB layout (block.tlb):
    //   _ fixed_prefix_length:(Maybe (## 5))
    //     special:(Maybe TickTock)
    //     code:(Maybe ^Cell)
    //     data:(Maybe ^Cell)
    //     library:(HashmapE 256 SimpleLib)
    //     = StateInit;
    // We emit: no fixed_prefix_length, no special, code=Just ^marker,
    // data=Just ^state, library=empty.
    vm::CellBuilder cb;
    if (!cb.store_long_bool(0, 1)         // fixed_prefix_length: Nothing
        || !cb.store_long_bool(0, 1)      // special: Nothing
        || !cb.store_long_bool(1, 1)      // code: Just
        || !cb.store_ref_bool(code_cell)  // ^code
        || !cb.store_long_bool(1, 1)      // data: Just
        || !cb.store_ref_bool(data_cell)  // ^data
        || !cb.store_long_bool(0, 1)) {   // library: hme_empty$0
        return {};
    }
    return cb.finalize();
}

}  // namespace jvm_workchain
