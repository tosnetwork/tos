/*
    EVM Workchain dispatch — callback registry implementation.
    Source: TOS-specific integration point.
*/
#include "evm-workchain-dispatch.h"

#include "block/transaction.h"
#include "block/workchain-execution-dispatch.h"
#include "td/utils/Status.h"
#include "vm/cells/CellBuilder.h"

namespace evm_workchain_dispatch {

namespace {

constexpr std::int32_t kEvmVmVersion = 0x45564D;  // "EVM"
constexpr std::uint64_t kLegacyVmMode = 0;

tos::StdSmcAddress singleton_executor_address() {
    tos::StdSmcAddress addr;
    addr.set_zero();
    addr.data()[31] = 1;
    return addr;
}

struct EvmEngineConfig final : public block::WorkchainEngineConfig {
    std::uint64_t chain_id{0};
};

block::WorkchainComputeOutput output_from_compute_phase(
    const block::ComputePhase& cp,
    bool committed) {
    block::WorkchainComputeOutput out;
    out.skip_reason = cp.skip_reason;
    out.completed = true;
    out.accepted = cp.accepted;
    out.committed = committed;
    out.engine_success = cp.success;
    out.msg_state_used = cp.msg_state_used;
    out.account_activated = cp.account_activated;
    out.out_of_gas = cp.out_of_gas;
    out.mode = cp.mode;
    out.exit_code = cp.exit_code;
    out.exit_arg = cp.exit_arg;
    out.vm_steps = cp.vm_steps;
    out.vm_init_state_hash = cp.vm_init_state_hash;
    out.vm_final_state_hash = cp.vm_final_state_hash;
    out.gas_used = cp.gas_used;
    out.gas_fees = cp.gas_fees.not_null() ? cp.gas_fees : td::zero_refint();
    out.new_data = cp.new_data;
    out.action_list = cp.actions;
    out.vm_log = cp.vm_log;
    return out;
}

class EvmDescriptorEngine final : public block::WorkchainEngine {
 public:
    block::WorkchainEngineKey engine_key() const override {
        return {block::WorkchainFormat::Basic, kEvmVmVersion};
    }

    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor& descriptor,
        const block::Config& /*block_transition_config*/) const override {
        if (descriptor.format != block::WorkchainFormat::Basic ||
            descriptor.vm_version != kEvmVmVersion) {
            return td::Status::Error("EVM engine received non-EVM descriptor");
        }
        if (descriptor.vm_mode == kLegacyVmMode) {
            return td::Status::Error("EVM descriptor has legacy vm_mode=0; expected chain id");
        }
        auto cfg = std::make_shared<EvmEngineConfig>();
        cfg->chain_id = descriptor.vm_mode;
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
        policy.activation_code = get_evm_code_marker_cell();
        return policy;
    }

    td::Result<block::WorkchainComputeOutput> run_compute(
        const block::WorkchainComputeInput& input,
        const block::WorkchainComputeContext& context) const override {
        auto* cfg = dynamic_cast<const EvmEngineConfig*>(context.engine_config.get());
        if (cfg == nullptr || cfg->chain_id == 0) {
            return td::Status::Error("EVM engine missing resolved chain id");
        }
        if (!has_evm_compute_handler()) {
            return td::Status::Error("descriptor-selected EVM workchain has no registered compute handler");
        }
        if (input.inbound_body.is_null()) {
            block::WorkchainComputeOutput out;
            out.completed = true;
            out.skip_reason = block::ComputePhase::sk_bad_state;
            return out;
        }
        block::ComputePhase cp{};
        vm::CellSlice body_cs{*input.inbound_body};
        bool ok = invoke_evm_compute(
            cp,
            input.current_data,
            body_cs,
            input.gas_limit,
            cfg->chain_id,
            context.block_seqno,
            context.now,
            context.rand_seed.data(),
            context.parent_block_hash.data());
        if (!ok) {
            return td::Status::Error("EVM compute handler failed");
        }
        return output_from_compute_phase(cp, cp.accepted && cp.new_data.not_null());
    }
};

}  // namespace

static EvmComputeHandler g_handler;

td::Ref<vm::Cell> get_evm_code_marker_cell() {
    static const td::Ref<vm::Cell> kMarker = []() {
        vm::CellBuilder cb;
        cb.store_long(0x45, 8);  // 'E' — EVM activated account marker
        return cb.finalize();
    }();
    return kMarker;
}

void set_evm_compute_handler(EvmComputeHandler handler) {
    g_handler = std::move(handler);
}

bool has_evm_compute_handler() noexcept {
    return static_cast<bool>(g_handler);
}

bool invoke_evm_compute(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> account_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t chain_id,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32]) {
    return g_handler(cp, std::move(account_data), in_msg_body, gas_limit,
                     chain_id, block_seqno, timestamp, rand_seed, parent_block_hash);
}

void register_evm_workchain_engine(block::WorkchainExecutionRegistry& registry) {
    registry.register_engine_if_absent(std::make_unique<EvmDescriptorEngine>());
}

}  // namespace evm_workchain_dispatch
