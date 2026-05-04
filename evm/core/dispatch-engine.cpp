/*
    EVM Workchain — native engine implementation.

    EvmNativeEngine is the descriptor-selected EVM executor that lives in
    evm/core/ so it can call run_evm_compute_phase_snapshot() directly,
    eliminating the g_handler function-pointer indirection used in Phase 1-2.

    Source: TOS-specific integration point (Phase 4 refactor).
*/
#include "evm/core/dispatch-engine.h"

#include "block/transaction.h"
#include "block/workchain-execution-dispatch.h"
#include "evm/core/compute-phase.h"
#include "evm/core/post-accept.h"
#include "td/utils/Status.h"
#include "vm/cells/CellBuilder.h"

namespace evm_workchain {

namespace {

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

td::Ref<vm::Cell> get_evm_code_marker_cell_local() {
    static const td::Ref<vm::Cell> kMarker = []() {
        vm::CellBuilder cb;
        cb.store_long(0x45, 8);  // 'E' — EVM activated account marker
        return cb.finalize();
    }();
    return kMarker;
}

class EvmNativeEngine final : public block::WorkchainEngine {
 public:
    block::WorkchainEngineKey engine_key() const override {
        return block::evm_workchain_engine_key();
    }

    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor& descriptor,
        const block::Config& /*block_transition_config*/) const override {
        if (!block::workchain_engine_key_is_evm(
                block::workchain_engine_key_from_descriptor(descriptor))) {
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
        policy.activation_code = get_evm_code_marker_cell_local();
        return policy;
    }

    td::Result<block::WorkchainComputeOutput> run_compute(
        const block::WorkchainComputeInput& input,
        const block::WorkchainComputeContext& context) const override {
        auto* cfg = dynamic_cast<const EvmEngineConfig*>(context.engine_config.get());
        if (cfg == nullptr || cfg->chain_id == 0) {
            return td::Status::Error("EVM engine missing resolved chain id");
        }
        if (input.inbound_body.is_null()) {
            block::WorkchainComputeOutput out;
            out.completed = true;
            out.skip_reason = block::ComputePhase::sk_bad_state;
            return out;
        }
        block::ComputePhase cp{};
        vm::CellSlice body_cs{*input.inbound_body};
        bool ok = run_evm_compute_phase_snapshot(
            cp,
            input.current_data,
            body_cs,
            input.gas_limit,
            context.block_seqno,
            context.now,
            context.rand_seed.data(),
            context.parent_block_hash.data(),
            cfg->chain_id);
        if (!ok) {
            return td::Status::Error("EVM compute handler failed");
        }
        // Stash captured side effects under the EVM tx_hash; the
        // validator manager publishes them post-BFT-accept via
        // `take_side_effects` + `apply_block_side_effects` from
        // `cleanup_applied_external_messages`. Applying at compute
        // time would pollute the RPC cache with records from
        // candidates that lost BFT.
        if (cp.evm_side_effects) {
            auto tx_hash = cp.evm_side_effects->tx_hash;
            // Audit #4 (2026-04-26): key by accepted-block context plus
            // tx_hash so rejected candidates with the same tx cannot
            // publish stale receipt/log/block records post-accept.
            stash_side_effects(context.block_seqno, context.now,
                               context.rand_seed.data(),
                               context.parent_block_hash.data(),
                               tx_hash,
                               *cp.evm_side_effects);
        }
        return output_from_compute_phase(cp, cp.accepted && cp.new_data.not_null());
    }
};

}  // namespace

void register_evm_workchain_engine(block::WorkchainExecutionRegistry& registry) {
    registry.register_engine_if_absent(std::make_unique<EvmNativeEngine>());
}

}  // namespace evm_workchain
