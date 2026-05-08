/*
    JVM Workchain — native engine implementation.

    JvmNativeEngine implements WorkchainEngine following the same pattern as
    EvmNativeEngine (evm/core/dispatch-engine.cpp) and UnoNativeEngine.

    run_compute decodes the canonical per-account JvmContractAccountState
    from `input.current_data` and delegates actual contract invocation to
    an installed JvmComputeRuntime.  A production binary without that
    runtime fails closed if wc=3 is active.

    Source: TOS-specific integration point.
*/
#include "jvm/core/dispatch-engine.h"

#include "block/transaction.h"
#include "block/workchain-execution-dispatch.h"
#include "jvm/core/cell-codec.h"
#include "jvm/core/config-param.h"
#include "jvm/core/deploy-abi.h"
#include "jvm/core/message-abi.h"
#include "td/utils/Status.h"
#include "td/utils/logging.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"

#include <cstring>

#include <memory>
#include <string>

namespace jvm_workchain {

namespace {

// JVM activation code cell: single byte 0x4a ('J').
td::Ref<vm::Cell> jvm_activation_code_cell() {
    vm::CellBuilder cb;
    cb.store_long(kJvmActivationCode, 8);
    return cb.finalize();
}

struct JvmEngineConfig final : public block::WorkchainEngineConfig {
    JvmConfig config;
};

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
        // Account-native topology: each JVM contract is its own wc=3
        // account at a deterministic address derived by
        // `derive_jvm_contract_address`.  The host accepts any address in
        // wc=3 and lets the engine emit `action_create_account` to
        // materialize new contract accounts (host plumbing in
        // crypto/block/transaction.cpp Transaction::try_action_create_account).
        block::AccountExecutionPolicy policy;
        policy.kind = block::AccountExecutionPolicyKind::EngineDefined;
        policy.singleton_address.reset();
        policy.accepts_external_inbound = true;
        policy.accepts_internal_inbound = true;
        policy.may_activate_uninitialized_account = true;
        policy.admits_engine_create_account_actions = true;
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
        if (input.gas_limit == 0 || input.gas_limit > cfg->config.max_gas_per_tx) {
            return skipped_output(block::ComputePhase::sk_no_gas,
                                  "JVM gas limit is outside ConfigParam 85 bounds",
                                  true);
        }
        if (runtime_ == nullptr) {
            return skipped_output(block::ComputePhase::sk_bad_state,
                                  "JVM Avata interpreter runtime is not installed");
        }
        if (parse_jvm_call_descriptor(input.inbound_body).is_error()) {
            return skipped_output(
                block::ComputePhase::sk_bad_state,
                "JVM inbound body is not a valid call descriptor");
        }

        JvmContractAccountState state;
        if (!decode_jvm_contract_account_state(input.current_data, state)) {
            return skipped_output(
                block::ComputePhase::sk_bad_state,
                "JVM contract account state cell is malformed");
        }
        if (state.stdlib_hash != cfg->config.stdlib_hash) {
            return skipped_output(
                block::ComputePhase::sk_bad_state,
                "JVM contract account stdlib hash does not match ConfigParam 85");
        }
        // Address-binding gate: the wc=3 account address must equal
        // `sha256("TOS-JVM-CONTRACT-v2" || state.address_commit ||
        // state.class_hash)`.  Without this check an attacker could deliver
        // any well-formed StateInit to a victim's deterministic but
        // not-yet-active address (the host-side custom-engine branch
        // unpacks `StateInit.data` for every acc_uninit wc=3 transaction
        // and skips `check_in_msg_state_hash` because v2 addresses are
        // derived from the deploy descriptor, not from `hash(StateInit)`).
        // Since the address is `H(domain || address_commit || class_hash)`,
        // the only way to land at a chosen victim address is a sha256
        // pre-image; rejecting any state whose `(address_commit,
        // class_hash)` does not produce `account_addr` therefore prevents
        // the squat.
        const auto expected_addr = derive_jvm_contract_address_from_state(
            state.address_commit, state.class_hash);
        if (std::memcmp(input.account_addr.data(), expected_addr.data(),
                        expected_addr.size()) != 0) {
            return skipped_output(
                block::ComputePhase::sk_bad_state,
                "JVM contract account state does not bind to account address");
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
