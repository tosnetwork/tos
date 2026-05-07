/*
    JVM Workchain — native engine implementation.

    JvmNativeEngine implements WorkchainEngine following the same pattern as
    EvmNativeEngine (evm/core/dispatch-engine.cpp) and UnoNativeEngine.

    run_compute decodes the canonical JvmExecutorState and delegates actual
    contract invocation to an installed JvmComputeRuntime. A production binary
    without that runtime fails closed if wc=3 is active.

    Source: TOS-specific integration point.
*/
#include "jvm/core/dispatch-engine.h"

#include "block/transaction.h"
#include "block/workchain-execution-dispatch.h"
#include "jvm/core/cell-codec.h"
#include "jvm/core/config-param.h"
#include "jvm/core/message-abi.h"
#include "td/utils/Status.h"
#include "td/utils/logging.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"

#include <memory>
#include <string>

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
    JvmConfig config;
};

bool same_stdlib_hash(const JvmConfig& cfg, const JvmExecutorState& state) {
    return cfg.stdlib_hash == state.stdlib_hash;
}

block::WorkchainComputeOutput skipped_output(int skip_reason,
                                             std::string vm_log,
                                             bool out_of_gas = false) {
    block::WorkchainComputeOutput out;
    out.completed = true;
    out.skip_reason = skip_reason;
    out.out_of_gas = out_of_gas;
    out.gas_fees = td::zero_refint();
    out.vm_log = std::move(vm_log);
    return out;
}

block::WorkchainEngineKey jvm_engine_key() {
    // vm_version = 0x4a564d31 ("JVM1"), sign-extended to int64_t via int32_t.
    return block::WorkchainEngineKey{
        block::WorkchainFormat::Basic,
        static_cast<std::int64_t>(static_cast<std::int32_t>(kJvmVmVersion))};
}

class JvmNativeEngine final : public block::WorkchainEngine {
 public:
    explicit JvmNativeEngine(std::shared_ptr<const JvmComputeRuntime> runtime)
        : runtime_(std::move(runtime)) {
    }

    block::WorkchainEngineKey engine_key() const override {
        return jvm_engine_key();
    }

    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>>
    validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor& descriptor,
        const block::Config& block_transition_config) const override {
        if (descriptor.format != block::WorkchainFormat::Basic ||
            static_cast<std::int32_t>(descriptor.vm_version) != kJvmVmVersion) {
            return td::Status::Error("JVM engine received non-JVM descriptor");
        }
        if (descriptor.vm_mode != 0) {
            return td::Status::Error("JVM v1 descriptor requires vm_mode=0");
        }
        TRY_RESULT(parsed_config,
                   parse_jvm_config_cell(
                       block_transition_config.get_config_param(kJvmConfigParam)));
        auto cfg = std::make_shared<JvmEngineConfig>();
        cfg->config = parsed_config;
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
        const block::WorkchainComputeInput& input,
        const block::WorkchainComputeContext& context) const override {
        auto* cfg = dynamic_cast<const JvmEngineConfig*>(context.engine_config.get());
        if (cfg == nullptr || cfg->config.chain_id == 0) {
            return td::Status::Error("JVM engine missing resolved ConfigParam 85");
        }
        if (input.inbound_body.is_null()) {
            return skipped_output(block::ComputePhase::sk_bad_state,
                                  "JVM inbound body is missing");
        }
        if (parse_jvm_call_descriptor(input.inbound_body).is_error()) {
            return skipped_output(block::ComputePhase::sk_bad_state,
                                  "JVM inbound body is not a valid call descriptor");
        }
        if (input.gas_limit == 0 || input.gas_limit > cfg->config.max_gas_per_tx) {
            return skipped_output(block::ComputePhase::sk_no_gas,
                                  "JVM gas limit is outside ConfigParam 85 bounds",
                                  true);
        }

        JvmExecutorState state;
        if (input.current_data.not_null()) {
            if (!decode_jvm_executor_state(input.current_data, state)) {
                return skipped_output(block::ComputePhase::sk_bad_state,
                                      "JVM executor state cell is malformed");
            }
            if (!same_stdlib_hash(cfg->config, state)) {
                return skipped_output(block::ComputePhase::sk_bad_state,
                                      "JVM executor state stdlib hash does not match ConfigParam 85");
            }
        } else {
            state.schema_version = kJvmExecutorStateSchemaVersion;
            state.stdlib_hash = cfg->config.stdlib_hash;
        }

        if (runtime_ == nullptr) {
            return skipped_output(block::ComputePhase::sk_bad_state,
                                  "JVM Avata interpreter runtime is not installed");
        }

        TRY_RESULT(invocation,
                   runtime_->run_contract(input, context, cfg->config, state));
        return build_jvm_workchain_output(
            cfg->config, state, input.gas_limit, invocation);
    }

 private:
    std::shared_ptr<const JvmComputeRuntime> runtime_;
};

}  // namespace

void register_jvm_workchain_engine(
    block::WorkchainExecutionRegistry& registry,
    std::shared_ptr<const JvmComputeRuntime> runtime) {
    registry.register_engine_if_absent(
        std::make_unique<JvmNativeEngine>(std::move(runtime)));
}

}  // namespace jvm_workchain
