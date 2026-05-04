/*
    Uno Workchain — native engine implementation.

    Phase 4 refactoring: `UnoNativeEngine` lives here in uno/core/ so it can
    call `uno_run_compute_phase()` directly, eliminating the function-pointer
    indirection that the old `uno_workchain_dispatch` callback bridge required.

    Source: TOS-specific integration point.
*/
#include "uno/core/dispatch-engine.h"
#include "uno/core/init.h"

#include "block/transaction.h"
#include "block/workchain-execution-dispatch.h"
#include "td/utils/Status.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cellslice.h"

namespace uno_workchain {

namespace {

tos::StdSmcAddress singleton_executor_address() {
    tos::StdSmcAddress addr;
    addr.set_zero();
    addr.data()[31] = 1;
    return addr;
}

/// Canonical "Uno activated account" code marker cell.
///
/// A single-byte cell containing 0x55 ('U'). Used as StateInit.code for the
/// descriptor-selected Uno singleton executor account. The UnoShardState
/// itself lives in StateInit.data; the outer code cell only needs to satisfy
/// the "account_active" requirement.
///
/// Returns the same Ref<vm::Cell> on every call (cached singleton). All
/// validators produce the same cell hash, which CellDb will deduplicate.
td::Ref<vm::Cell> get_uno_code_marker_cell() {
    static const td::Ref<vm::Cell> kMarker = []() {
        vm::CellBuilder cb;
        cb.store_long(0x55, 8);  // 'U' — Uno activated account marker
        return cb.finalize();
    }();
    return kMarker;
}

struct UnoEngineConfig final : public block::WorkchainEngineConfig {
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

class UnoNativeEngine final : public block::WorkchainEngine {
 public:
    block::WorkchainEngineKey engine_key() const override {
        return block::uno_workchain_engine_key();
    }

    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor& descriptor,
        const block::Config& /*block_transition_config*/) const override {
        if (!block::workchain_engine_key_is_uno(
                block::workchain_engine_key_from_descriptor(descriptor))) {
            return td::Status::Error("Uno engine received non-Uno descriptor");
        }
        if (descriptor.vm_mode != 0) {
            return td::Status::Error("Uno v1 descriptor requires vm_mode=0");
        }
        // Uno v1 reads chain_id from the process-global g_uno_config set by
        // install_uno_config at startup. vm_mode=0 is reserved for Uno v1, so
        // a future Uno v2 descriptor should encode chain_id in vm_mode and
        // route it through UnoEngineConfig here, matching EvmNativeEngine.
        std::shared_ptr<const block::WorkchainEngineConfig> result =
            std::make_shared<UnoEngineConfig>();
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
        policy.activation_code = get_uno_code_marker_cell();
        return policy;
    }

    td::Result<block::WorkchainComputeOutput> run_compute(
        const block::WorkchainComputeInput& input,
        const block::WorkchainComputeContext& context) const override {
        if (input.inbound_body.is_null()) {
            block::WorkchainComputeOutput out;
            out.completed = true;
            out.skip_reason = block::ComputePhase::sk_bad_state;
            out.gas_fees = td::zero_refint();
            return out;
        }
        block::ComputePhase cp{};
        vm::CellSlice body_cs{*input.inbound_body};
        bool ok = uno_workchain::uno_run_compute_phase(
            cp,
            input.current_data,
            body_cs,
            input.gas_limit,
            context.block_seqno,
            context.now,
            context.rand_seed.data());
        if (!ok) {
            return td::Status::Error("Uno compute phase failed");
        }
        return output_from_compute_phase(cp, cp.success && cp.new_data.not_null());
    }
};

}  // namespace

void register_uno_workchain_engine(block::WorkchainExecutionRegistry& registry) {
    registry.register_engine_if_absent(std::make_unique<UnoNativeEngine>());
}

}  // namespace uno_workchain
