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
// schema_version=2 is the account-native topology wire format.  The
// SingletonExecutor's shared class-store has no analog under per-account
// topology — Cell DB hash dedup handles physical sharing automatically —
// so `max_total_class_bytes` is no longer carried in ConfigParam 85.
constexpr std::uint8_t kJvmConfigSchemaVersion = 2;
constexpr unsigned kJvmOpcodeGasCostCount = 256;
// Round 53 MEDIUM fix: bumped from 13 to 14 to add
// AVATA_CONTRACT_HELPER_STORAGE_LOAD_BYTE.  Pre-fix Storage.load
// charged a single fixed cost regardless of value size, letting a
// contract that had seeded a large slot force validators to decode +
// copy up to 1 MiB per call for ~20 gas.  Now mirrored to
// STORAGE_STORE_BYTE so load and store bill symmetrically per byte.
// IMPORTANT: this changes the ConfigParam-85 wire layout; the
// `JvmConfig::helper_gas_costs` array now serializes 14 entries
// instead of 13.  Pre-launch only, so no migration is needed, but
// existing serialized configs will be invalid.
//
// Phase A (rt.jar gap plan): bumped from 14 to 15 to add
// AVATA_CONTRACT_HELPER_CONTEXT_READ.  Each java.lang.Context getter
// charges one unit so contracts that poll context in a hot loop are
// billed.  Same wire-layout discipline: pre-launch only, no migration.
// Phase B: 15 → 21 to add CRYPTO_SHA256_BASE / SHA256_BYTE /
// SECP256K1_RECOVER / SECP256K1_VERIFY / ED25519_VERIFY /
// BLS12381_VERIFY.
//
// Final TODO closure: 21 → 23 for System.sendMessage's
// MESSAGE_BASE + MESSAGE_BYTE.
// Phase H: 23 → 25 for System.createAccount's
// CREATE_ACCOUNT_BASE + CREATE_ACCOUNT_BYTE.
constexpr unsigned kJvmContractHelperGasCostCount = 25;
constexpr unsigned kJvmStdlibHashBytes = 32;

struct JvmConfig {
    std::uint32_t chain_id{0};
    std::uint8_t schema_version{kJvmConfigSchemaVersion};
    std::uint64_t gas_price{0};
    std::uint64_t max_gas_per_tx{0};
    std::uint32_t max_class_bytes{0};
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

    // Same as default_activation() but with stdlib_hash populated from
    // sha256(stdlib_bytes).  This is the path mainnet genesis tooling
    // takes: the operator points the Fift word at the canonical rt.jar
    // bytes, the helper hashes them, and the resulting hash is locked
    // into ConfigParam 85 so validators reject any node carrying a
    // mismatched stdlib at activation.
    static JvmConfig default_activation_with_stdlib(td::Slice stdlib_bytes) noexcept;
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
