/*
    JVM Workchain — ConfigParam 85 codec.

    ConfigParam 85 carries the consensus parameters for JVM v1, including
    opcode and helper gas schedules.  The runtime still keeps standalone
    defaults for local tests, but validator execution must resolve this cell
    through the workchain registry before any wc=3 transaction is admitted.
*/
#pragma once

#include <array>
#include <cstdint>

#include "td/utils/Status.h"
#include "tos/tos-types.h"
#include "vm/cells.h"

namespace jvm_workchain {

constexpr std::uint32_t kJvmConfigMagic = 0x4a564d43;  // "JVMC"
constexpr unsigned kJvmConfigMagicBits = 32;
constexpr std::uint8_t kJvmConfigSchemaVersion = 1;
constexpr unsigned kJvmOpcodeGasCostCount = 256;
constexpr unsigned kJvmContractHelperGasCostCount = 13;
constexpr unsigned kJvmStdlibHashBytes = 32;

struct JvmConfig {
    std::uint32_t chain_id{0};
    std::uint8_t schema_version{kJvmConfigSchemaVersion};
    std::uint64_t gas_price{0};
    std::uint64_t max_gas_per_tx{0};
    std::uint32_t max_class_bytes{0};
    std::uint32_t max_total_class_bytes{0};
    std::uint32_t max_heap_bytes{0};
    std::uint32_t max_storage_cells{0};
    std::uint16_t class_file_major{52};
    std::uint8_t gas_schedule_version{0};
    std::array<std::uint8_t, kJvmStdlibHashBytes> stdlib_hash{};
    std::array<std::uint64_t, kJvmOpcodeGasCostCount> opcode_gas_costs{};
    std::array<std::uint64_t, kJvmContractHelperGasCostCount> helper_gas_costs{};

    // Returns the canonical v1 activation parameters (wc=3, gas_schedule_version=1).
    // stdlib_hash is zero until the stdlib archive is locked in.
    static JvmConfig default_activation() noexcept;
};

// Build the ConfigParam 12 WorkchainDescr cell for JVM v1.
// The descriptor uses wfmt_basic, vm_version="JVM1", vm_mode=0, and the
// singleton-executor account policy supplied by JvmNativeEngine.
td::Ref<vm::Cell> build_jvm_workchain_descr(
    const tos::RootHash& zerostate_root_hash,
    const tos::FileHash& zerostate_file_hash,
    std::uint32_t enabled_since = 0);

// Build a ConfigParam 85 cell.  Returns null on invalid gas costs or if the
// cell cannot be represented in the configured layout.
td::Ref<vm::Cell> build_jvm_config_cell(const JvmConfig& cfg);

// Parse and validate ConfigParam 85.  Missing cells, wrong magic/version,
// invalid gas costs, and malformed table references are consensus errors.
td::Result<JvmConfig> parse_jvm_config_cell(td::Ref<vm::Cell> cell);

}  // namespace jvm_workchain
