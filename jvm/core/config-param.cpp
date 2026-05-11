/*
    JVM Workchain — ConfigParam 85 codec.
*/
#include "jvm/core/config-param.h"

#include <algorithm>
#include <limits>

#define AVATA_GAS_SCHEDULE_DEFINE_TABLE
#include <avata/gas_schedule.h>
#undef AVATA_GAS_SCHEDULE_DEFINE_TABLE

#include "block/block-auto.h"
#include "jvm/core/dispatch-engine.h"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

namespace jvm_workchain {

namespace {

constexpr unsigned kGasCostsPerCell = 15;

bool valid_gas_cost(std::uint64_t cost) {
    return cost != 0 && cost != std::numeric_limits<std::uint64_t>::max();
}

td::Ref<vm::Cell> build_gas_table_chain(const std::uint64_t* costs,
                                        unsigned count,
                                        unsigned offset) {
    if (costs == nullptr || offset >= count) {
        return {};
    }

    const unsigned chunk = std::min(kGasCostsPerCell, count - offset);
    td::Ref<vm::Cell> next;
    if (offset + chunk < count) {
        next = build_gas_table_chain(costs, count, offset + chunk);
        if (next.is_null()) {
            return {};
        }
    }

    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(chunk, 8)) {
        return {};
    }
    for (unsigned i = 0; i < chunk; ++i) {
        const std::uint64_t cost = costs[offset + i];
        if (!valid_gas_cost(cost) || !cb.store_ulong_rchk_bool(cost, 64)) {
            return {};
        }
    }
    if (next.not_null() && !cb.store_ref_bool(std::move(next))) {
        return {};
    }
    return cb.finalize();
}

td::Status parse_gas_table_chain(td::Ref<vm::Cell> cell,
                                 std::uint64_t* out,
                                 unsigned expected_count,
                                 const char* label) {
    if (cell.is_null()) {
        return td::Status::Error(PSTRING() << "JVM ConfigParam 85 missing "
                                           << label << " gas table");
    }
    if (out == nullptr || expected_count == 0) {
        return td::Status::Error("JVM ConfigParam 85 parser misuse");
    }

    unsigned offset = 0;
    while (offset < expected_count) {
        auto cs = vm::load_cell_slice(cell);
        unsigned chunk = 0;
        if (!cs.fetch_uint_to(8, chunk) || chunk == 0 ||
            chunk > kGasCostsPerCell) {
            return td::Status::Error(PSTRING()
                                     << "JVM ConfigParam 85 malformed "
                                     << label << " gas chunk");
        }
        if (offset + chunk > expected_count) {
            return td::Status::Error(PSTRING()
                                     << "JVM ConfigParam 85 overlong "
                                     << label << " gas table");
        }
        for (unsigned i = 0; i < chunk; ++i) {
            unsigned long long cost = 0;
            if (!cs.fetch_ulong_bool(64, cost) ||
                !valid_gas_cost(static_cast<std::uint64_t>(cost))) {
                return td::Status::Error(PSTRING()
                                         << "JVM ConfigParam 85 invalid "
                                         << label << " gas cost");
            }
            out[offset + i] = static_cast<std::uint64_t>(cost);
        }
        offset += chunk;

        if (offset < expected_count) {
            if (cs.size() != 0 || cs.size_refs() != 1) {
                return td::Status::Error(PSTRING()
                                         << "JVM ConfigParam 85 truncated "
                                         << label << " gas table");
            }
            cell = cs.fetch_ref();
        } else if (!cs.empty_ext()) {
            return td::Status::Error(PSTRING()
                                     << "JVM ConfigParam 85 trailing data in "
                                     << label << " gas table");
        }
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
    if (!cs.fetch_uint_to(32, v)) {
        return false;
    }
    out = static_cast<std::uint32_t>(v);
    return true;
}

bool fetch_u64(vm::CellSlice& cs, std::uint64_t& out) {
    unsigned long long v = 0;
    if (!cs.fetch_ulong_bool(64, v)) {
        return false;
    }
    out = static_cast<std::uint64_t>(v);
    return true;
}

}  // namespace

td::Ref<vm::Cell> build_jvm_workchain_descr(
    const tos::RootHash& zerostate_root_hash,
    const tos::FileHash& zerostate_file_hash,
    std::uint32_t enabled_since) {
    vm::CellBuilder cb;
    cb.store_long(0xa6, 8);              // workchain#a6
    cb.store_long(enabled_since, 32);
    cb.store_long(0, 8);                 // monitor_min_split
    cb.store_long(0, 8);                 // min_split
    cb.store_long(8, 8);                 // max_split
    cb.store_long(0xe000, 16);           // basic=1, active=1, accept_msgs=1
    cb.store_bits(zerostate_root_hash.as_bitslice());
    cb.store_bits(zerostate_file_hash.as_bitslice());
    cb.store_long(0, 32);                // version
    cb.store_long(0x1, 4);               // wfmt_basic
    cb.store_long(kJvmVmVersion, 32);    // vm_version = "JVM1"
    cb.store_long(0, 64);                // vm_mode is reserved for JVM v1

    auto cell = cb.finalize();
    if (!block::gen::t_WorkchainDescr.validate_ref(cell)) {
        LOG(ERROR) << "jvm-workchain: built WorkchainDescr failed TLB validation";
        return {};
    }
    return cell;
}

td::Ref<vm::Cell> build_jvm_config_cell(const JvmConfig& cfg) {
    if (cfg.schema_version != kJvmConfigSchemaVersion ||
        cfg.class_file_major != 52 ||
        cfg.chain_id == 0 ||
        cfg.gas_price == 0 ||
        cfg.max_gas_per_tx == 0 ||
        cfg.max_class_bytes == 0 ||
        cfg.max_heap_bytes == 0 ||
        cfg.max_storage_cells == 0 ||
        cfg.gas_schedule_version == 0) {
        return {};
    }

    auto opcode_table = build_gas_table_chain(
        cfg.opcode_gas_costs.data(), kJvmOpcodeGasCostCount, 0);
    auto helper_table = build_gas_table_chain(
        cfg.helper_gas_costs.data(), kJvmContractHelperGasCostCount, 0);
    if (opcode_table.is_null() || helper_table.is_null()) {
        return {};
    }

    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(kJvmConfigMagic, kJvmConfigMagicBits) ||
        !cb.store_ulong_rchk_bool(cfg.schema_version, 8) ||
        !cb.store_ulong_rchk_bool(cfg.chain_id, 32) ||
        !cb.store_ulong_rchk_bool(cfg.gas_price, 64) ||
        !cb.store_ulong_rchk_bool(cfg.max_gas_per_tx, 64) ||
        !cb.store_ulong_rchk_bool(cfg.max_class_bytes, 32) ||
        !cb.store_ulong_rchk_bool(cfg.max_heap_bytes, 32) ||
        !cb.store_ulong_rchk_bool(cfg.max_storage_cells, 32) ||
        !cb.store_ulong_rchk_bool(cfg.class_file_major, 16) ||
        !cb.store_ulong_rchk_bool(cfg.gas_schedule_version, 8) ||
        !cb.store_bytes_bool(cfg.stdlib_hash.data(), cfg.stdlib_hash.size()) ||
        !cb.store_ref_bool(std::move(opcode_table)) ||
        !cb.store_ref_bool(std::move(helper_table))) {
        return {};
    }

    return cb.finalize();
}

td::Result<JvmConfig> parse_jvm_config_cell(td::Ref<vm::Cell> cell) {
    if (cell.is_null()) {
        return td::Status::Error("missing JVM ConfigParam 85");
    }

    JvmConfig cfg;
    auto cs = vm::load_cell_slice(cell);
    std::uint32_t magic = 0;
    if (!fetch_u32(cs, magic) || magic != kJvmConfigMagic) {
        return td::Status::Error("JVM ConfigParam 85 has wrong magic");
    }
    if (!fetch_u8(cs, cfg.schema_version) ||
        cfg.schema_version != kJvmConfigSchemaVersion) {
        return td::Status::Error("JVM ConfigParam 85 has unsupported schema");
    }
    if (!fetch_u32(cs, cfg.chain_id) ||
        !fetch_u64(cs, cfg.gas_price) ||
        !fetch_u64(cs, cfg.max_gas_per_tx) ||
        !fetch_u32(cs, cfg.max_class_bytes) ||
        !fetch_u32(cs, cfg.max_heap_bytes) ||
        !fetch_u32(cs, cfg.max_storage_cells) ||
        !fetch_u16(cs, cfg.class_file_major) ||
        !fetch_u8(cs, cfg.gas_schedule_version) ||
        !cs.fetch_bytes(cfg.stdlib_hash.data(), cfg.stdlib_hash.size())) {
        return td::Status::Error("JVM ConfigParam 85 is truncated");
    }
    if (cfg.chain_id == 0 ||
        cfg.gas_price == 0 ||
        cfg.max_gas_per_tx == 0 ||
        cfg.max_class_bytes == 0 ||
        cfg.max_heap_bytes == 0 ||
        cfg.max_storage_cells == 0 ||
        cfg.class_file_major != 52 ||
        cfg.gas_schedule_version == 0) {
        return td::Status::Error("JVM ConfigParam 85 contains invalid limits");
    }
    if (cs.size() != 0 || cs.size_refs() != 2) {
        return td::Status::Error("JVM ConfigParam 85 must carry two gas table refs");
    }

    auto opcode_table = cs.fetch_ref();
    auto helper_table = cs.fetch_ref();
    TRY_STATUS(parse_gas_table_chain(opcode_table,
                                     cfg.opcode_gas_costs.data(),
                                     kJvmOpcodeGasCostCount,
                                     "opcode"));
    TRY_STATUS(parse_gas_table_chain(helper_table,
                                     cfg.helper_gas_costs.data(),
                                     kJvmContractHelperGasCostCount,
                                     "helper"));
    return cfg;
}

JvmConfig JvmConfig::default_activation() noexcept {
    JvmConfig cfg;
    cfg.chain_id = 3;
    cfg.gas_price = 1000;
    cfg.max_gas_per_tx = 1000000;
    cfg.max_class_bytes = 65536;
    cfg.max_heap_bytes = 4194304;
    cfg.max_storage_cells = 65536;
    cfg.class_file_major = 52;
    cfg.gas_schedule_version = 1;
    // stdlib_hash stays zero-initialized until the stdlib archive is locked in

    for (unsigned i = 0; i < kJvmOpcodeGasCostCount; ++i) {
        cfg.opcode_gas_costs[i] = kTosDefaultOpcodeGasCosts[i];
    }

    // Matches DefaultContractHelperGasCosts in machine.cpp
    cfg.helper_gas_costs[0]  = 20;   // STORAGE_LOAD
    cfg.helper_gas_costs[1]  = 100;  // STORAGE_STORE_BASE
    cfg.helper_gas_costs[2]  = 1;    // STORAGE_STORE_BYTE
    cfg.helper_gas_costs[3]  = 50;   // STORAGE_CLEAR
    cfg.helper_gas_costs[4]  = 1;    // ALLOCATION_OBJECT_WORD
    cfg.helper_gas_costs[5]  = 8;    // ALLOCATION_ARRAY_BASE
    cfg.helper_gas_costs[6]  = 1;    // ALLOCATION_ARRAY_ELEMENT
    cfg.helper_gas_costs[7]  = 3;    // ARRAYCOPY_BASE
    cfg.helper_gas_costs[8]  = 1;    // ARRAYCOPY_ELEMENT
    cfg.helper_gas_costs[9]  = 2;    // NATIVE_CALL
    cfg.helper_gas_costs[10] = 50;   // EVENT_BASE
    cfg.helper_gas_costs[11] = 10;   // EVENT_TOPIC
    cfg.helper_gas_costs[12] = 1;    // EVENT_BYTE
    cfg.helper_gas_costs[13] = 1;    // STORAGE_LOAD_BYTE (round 53)

    return cfg;
}

}  // namespace jvm_workchain
