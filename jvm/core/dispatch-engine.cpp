/*
    JVM Workchain — native engine implementation (Phase 2 scaffold).

    JvmNativeEngine implements WorkchainEngine following the same pattern as
    EvmNativeEngine (evm/core/dispatch-engine.cpp) and UnoNativeEngine.

    Phase 2 stub: run_compute returns a NOT_READY result until Phase 4 heap
    serialization (JvmCellCodec) is implemented.  A production binary must
    fail closed if wc=3 is active before real compute is wired.

    Source: TOS-specific integration point.
*/
#include "jvm/core/dispatch-engine.h"

#include "block/workchain-execution-dispatch.h"
#include "td/utils/Status.h"
#include "td/utils/logging.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"

#include <memory>

namespace jvm_workchain {

namespace {

// Singleton executor address: 0x0000...0001, matching doc/jvm-roadmap.md.
tos::StdSmcAddress singleton_executor_address() {
    tos::StdSmcAddress addr;
    addr.set_zero();
    addr.data()[31] = 1;
    return addr;
}

// JVM activation code cell: single byte 0x4a ('J').
td::Ref<vm::Cell> jvm_activation_code_cell() {
    vm::CellBuilder cb;
    cb.store_long(kJvmActivationCode, 8);
    return cb.finalize();
}

struct JvmEngineConfig final : public block::WorkchainEngineConfig {
    // ConfigParam 85 fields (Phase 2 stub: all zero defaults).
    std::uint32_t chain_id{0};
    std::uint8_t  schema_version{0};
    std::uint64_t gas_price{0};
    std::uint64_t max_gas_per_tx{0};
    std::uint32_t max_class_bytes{0};
    std::uint32_t max_total_class_bytes{0};
    std::uint32_t max_heap_bytes{0};
    std::uint32_t max_storage_cells{0};
    std::uint16_t class_file_major{52};
    std::uint8_t  gas_schedule_version{0};
};

block::WorkchainEngineKey jvm_engine_key() {
    // vm_version = 0x4a564d31 ("JVM1"), sign-extended to int64_t via int32_t.
    return block::WorkchainEngineKey{
        block::WorkchainFormat::Basic,
        static_cast<std::int64_t>(static_cast<std::int32_t>(kJvmVmVersion))};
}

class JvmNativeEngine final : public block::WorkchainEngine {
 public:
    block::WorkchainEngineKey engine_key() const override {
        return jvm_engine_key();
    }

    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>>
    validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor& descriptor,
        const block::Config& /*block_transition_config*/) const override {
        if (descriptor.format != block::WorkchainFormat::Basic ||
            static_cast<std::int32_t>(descriptor.vm_version) != kJvmVmVersion) {
            return td::Status::Error("JVM engine received non-JVM descriptor");
        }
        if (descriptor.vm_mode != 0) {
            return td::Status::Error("JVM v1 descriptor requires vm_mode=0");
        }
        // Phase 2 stub: return defaults.  Phase 2+ will parse ConfigParam 85.
        // TODO(Phase 2): parse block_transition_config.get_config_param(kJvmConfigParam)
        // into JvmEngineConfig fields.
        auto cfg = std::make_shared<JvmEngineConfig>();
        std::shared_ptr<const block::WorkchainEngineConfig> result = cfg;
        return result;
    }

    block::AccountExecutionPolicy account_policy(
        const block::WorkchainExecutionDescriptor& /*descriptor*/,
        const block::WorkchainEngineConfig& /*engine_config*/) const override {
        block::AccountExecutionPolicy policy;
        policy.kind = block::AccountExecutionPolicyKind::SingletonExecutor;
        policy.singleton_address = singleton_executor_address();
        policy.accepts_external_inbound = true;
        policy.accepts_internal_inbound = true;
        policy.may_activate_uninitialized_account = true;
        policy.activation_code = jvm_activation_code_cell();
        return policy;
    }

    td::Result<block::WorkchainComputeOutput> run_compute(
        const block::WorkchainComputeInput& /*input*/,
        const block::WorkchainComputeContext& /*context*/) const override {
        // Phase 2 stub: real compute requires Phase 4 heap serialization.
        // Returning an error here causes the validator to skip the transaction,
        // which is the correct fail-closed behavior before the engine is ready.
        // TODO(Phase 4): replace with JvmCellCodec::decode_heap() +
        //   avata_begin_contract_transaction_with_limits() + avata interpreter
        //   + avata_storage_execute_transaction() + JvmCellCodec::encode_heap().
        return td::Status::Error("JVM compute not yet implemented (Phase 2 scaffold)");
    }
};

}  // namespace

void register_jvm_workchain_engine(block::WorkchainExecutionRegistry& registry) {
    registry.register_engine_if_absent(std::make_unique<JvmNativeEngine>());
}

}  // namespace jvm_workchain
